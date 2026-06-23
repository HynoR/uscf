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

// TestRelayTCPHalfOpenBoundReclaimsIdleSurvivor proves the L4 leak fix: once one
// relay direction finishes, a silent surviving direction is reaped at halfOpenIdle
// instead of pinning its connection (an L4 QUIC stream) for the full idle timeout.
func TestRelayTCPHalfOpenBoundReclaimsIdleSurvivor(t *testing.T) {
	a := relayTestAdapter(150 * time.Millisecond)

	clientConn, clientPeer := net.Pipe()
	upstreamConn, upstreamPeer := net.Pipe()
	defer upstreamPeer.Close()

	// Both conns carry a LONG idle timeout, so without the half-open bound the
	// surviving direction would block ~10s.
	const longIdle = 10 * time.Second
	client := &models.TimeoutConn{Conn: clientConn, IdleTimeout: longIdle}
	upstream := &models.TimeoutConn{Conn: upstreamConn, IdleTimeout: longIdle}

	// client -> upstream EOFs immediately (client closed), while upstream -> client
	// stays silent (upstreamPeer open, never writes). That is the half-open state.
	_ = clientPeer.Close()

	done := make(chan error, 1)
	go func() { done <- a.relayTCP(client, upstream) }()

	select {
	case <-done:
		// Returned well under longIdle: the half-open bound reclaimed the idle survivor.
	case <-time.After(2 * time.Second):
		t.Fatal("relayTCP did not reclaim an idle half-open flow within 2s — half-open bound not applied")
	}
}

// TestRelayTCPNoBoundWaitsForBoth confirms that with halfOpenIdle disabled (L3),
// the relay keeps the prior behavior: it does NOT reclaim the idle survivor early
// (it waits for the long idle timeout), so L3's teardown timing is unchanged.
func TestRelayTCPNoBoundWaitsForBoth(t *testing.T) {
	a := relayTestAdapter(0) // disabled

	clientConn, clientPeer := net.Pipe()
	upstreamConn, upstreamPeer := net.Pipe()
	defer upstreamPeer.Close()
	defer upstreamConn.Close()

	client := &models.TimeoutConn{Conn: clientConn, IdleTimeout: 10 * time.Second}
	upstream := &models.TimeoutConn{Conn: upstreamConn, IdleTimeout: 10 * time.Second}
	_ = clientPeer.Close()

	done := make(chan error, 1)
	go func() { done <- a.relayTCP(client, upstream) }()

	select {
	case <-done:
		t.Fatal("relayTCP returned early with halfOpenIdle disabled; L3 timing changed")
	case <-time.After(400 * time.Millisecond):
		// Expected: still waiting on the silent survivor (no early reclaim).
	}
}
