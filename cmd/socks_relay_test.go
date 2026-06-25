package cmd

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/HynoR/uscf/models"
)

func relayTestAdapter(halfOpenIdle time.Duration) *txthinkingAdapter {
	dial := func(ctx context.Context, network, addr string, target socksTarget) (net.Conn, error) {
		return nil, errors.New("dial unused in relay test")
	}
	return newTxthinkingAdapter("", "", systemDNSResolver{}, dial, 0, halfOpenIdle, false, false)
}

// tcpConnPair returns a connected pair of real loopback TCP connections. Unlike
// net.Pipe, real TCP models a clean half-close (CloseWrite → the peer reads EOF)
// distinctly from a hard close/reset (the peer's read errors) — which is exactly
// the distinction relayTCP keys on.
func tcpConnPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type accepted struct {
		conn net.Conn
		err  error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		ch <- accepted{c, err}
	}()

	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	got := <-ch
	if got.err != nil {
		t.Fatalf("accept: %v", got.err)
	}
	return dialed, got.conn
}

// TestRelayTCPHalfOpenBoundReclaimsIdleSurvivor proves the L4 leak bound: after a
// clean half-close, a silent surviving direction is reaped at halfOpenIdle instead
// of pinning its connection (an L4 QUIC stream) for the full idle timeout.
func TestRelayTCPHalfOpenBoundReclaimsIdleSurvivor(t *testing.T) {
	a := relayTestAdapter(150 * time.Millisecond)

	clientConn, clientPeer := tcpConnPair(t)
	upstreamConn, upstreamPeer := tcpConnPair(t)
	defer clientPeer.Close()
	defer upstreamPeer.Close()

	const longIdle = 10 * time.Second
	client := &models.TimeoutConn{Conn: clientConn, IdleTimeout: longIdle}
	upstream := &models.TimeoutConn{Conn: upstreamConn, IdleTimeout: longIdle}

	// The client finished its request: a clean TCP half-close (FIN), so our read of
	// it EOFs cleanly. The upstream stays silent — the half-open state.
	_ = clientPeer.(*net.TCPConn).CloseWrite()

	done := make(chan error, 1)
	go func() { done <- a.relayTCP(client, upstream) }()

	select {
	case <-done:
		// Returned well under longIdle: the half-open bound reclaimed the idle survivor.
	case <-time.After(2 * time.Second):
		t.Fatal("relayTCP did not reclaim an idle half-open flow within 2s — half-open bound not applied")
	}
}

// TestRelayTCPNoBoundKeepsHalfOpenSurvivor confirms a CLEAN half-close keeps the
// surviving direction alive on L3 (halfOpenIdle disabled): a legit slow/long
// response after the client finished its request is not cut short.
func TestRelayTCPNoBoundKeepsHalfOpenSurvivor(t *testing.T) {
	a := relayTestAdapter(0) // disabled (L3)

	clientConn, clientPeer := tcpConnPair(t)
	upstreamConn, upstreamPeer := tcpConnPair(t)
	defer clientPeer.Close()
	defer upstreamPeer.Close()

	client := &models.TimeoutConn{Conn: clientConn, IdleTimeout: 10 * time.Second}
	upstream := &models.TimeoutConn{Conn: upstreamConn, IdleTimeout: 10 * time.Second}

	_ = clientPeer.(*net.TCPConn).CloseWrite() // clean half-close

	done := make(chan error, 1)
	go func() { done <- a.relayTCP(client, upstream) }()

	select {
	case <-done:
		t.Fatal("relayTCP cut a clean half-open survivor on L3; the response side should be kept")
	case <-time.After(400 * time.Millisecond):
		// Expected: still relaying the surviving (response) direction.
	}
}

// TestRelayTCPHardErrorTearsDownBothImmediately is the hang fix: when one direction
// fails HARD (a reset, or the runtime closing the conn after the tunnel dropped),
// relayTCP tears BOTH directions down at once instead of leaving the silent survivor
// blocked until its (minutes-long) idle deadline. This is what makes the downstream
// client get a prompt reset and retry instead of hanging.
func TestRelayTCPHardErrorTearsDownBothImmediately(t *testing.T) {
	a := relayTestAdapter(0) // L3, no half-open bound — the worst case for hangs

	clientConn, clientPeer := tcpConnPair(t)
	upstreamConn, upstreamPeer := tcpConnPair(t)
	defer clientPeer.Close()
	defer upstreamPeer.Close()

	// Both carry a LONG idle timeout: without the hard-error teardown the silent
	// survivor would block ~10s.
	client := &models.TimeoutConn{Conn: clientConn, IdleTimeout: 10 * time.Second}
	upstream := &models.TimeoutConn{Conn: upstreamConn, IdleTimeout: 10 * time.Second}

	done := make(chan error, 1)
	go func() { done <- a.relayTCP(client, upstream) }()

	// Simulates socksRuntime.ResetTrackedConns() closing the stranded client conn
	// after the upstream tunnel died (the upstream side here is silent/dead).
	time.Sleep(50 * time.Millisecond)
	_ = client.Close()

	select {
	case <-done:
		// Prompt teardown of both directions.
	case <-time.After(2 * time.Second):
		t.Fatal("relayTCP did not tear down both directions on a hard error within 2s — stranded flow would hang")
	}
}
