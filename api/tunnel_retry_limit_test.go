package api

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/quic-go/quic-go"
)

type staticBackoff struct {
	delay time.Duration
}

func (b staticBackoff) NextDelay(attempt int) time.Duration {
	return b.delay
}

func (b staticBackoff) Reset() {}

type noopDevice struct{}

func (noopDevice) ReadPacket(buf []byte) (int, error) { return 0, errors.New("not implemented") }
func (noopDevice) WritePacket(pkt []byte) error       { return errors.New("not implemented") }

func TestMaintainTunnelPausesAfterMaxReconnectAttempts(t *testing.T) {
	oldConnectTunnelFunc := connectTunnelFunc
	defer func() { connectTunnelFunc = oldConnectTunnelFunc }()

	var attempts atomic.Int32
	connectTunnelFunc = func(
		ctx context.Context,
		tlsConfig *tls.Config,
		quicConfig *quic.Config,
		connectURI string,
		endpoint net.Addr,
		useHTTP2 bool,
	) (*net.UDPConn, tunnelTransport, *connectip.Conn, *http.Response, error) {
		attempts.Add(1)
		return nil, nil, nil, nil, errors.New("connect failed")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		MaintainTunnel(ctx, ConnectionConfig{
			TLSConfig:            &tls.Config{},
			KeepAlivePeriod:      time.Second,
			InitialPacketSize:    1242,
			Endpoint:             &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443},
			MTU:                  1280,
			MaxReconnectAttempts: 3,
			ReconnectStrategy:    staticBackoff{delay: time.Millisecond},
		}, noopDevice{})
	}()

	waitForAttempts(t, &attempts, 3)
	time.Sleep(80 * time.Millisecond)

	if got := attempts.Load(); got != 3 {
		t.Fatalf("expected retries to stop at 3 attempts, got %d", got)
	}

	select {
	case <-done:
		t.Fatalf("MaintainTunnel should wait for context cancel after retry limit")
	default:
	}

	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("MaintainTunnel did not exit after context cancel")
	}
}

func TestMaintainTunnelUnlimitedRetriesWhenMaxIsZero(t *testing.T) {
	oldConnectTunnelFunc := connectTunnelFunc
	defer func() { connectTunnelFunc = oldConnectTunnelFunc }()

	var attempts atomic.Int32
	connectTunnelFunc = func(
		ctx context.Context,
		tlsConfig *tls.Config,
		quicConfig *quic.Config,
		connectURI string,
		endpoint net.Addr,
		useHTTP2 bool,
	) (*net.UDPConn, tunnelTransport, *connectip.Conn, *http.Response, error) {
		attempts.Add(1)
		return nil, nil, nil, nil, errors.New("connect failed")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		MaintainTunnel(ctx, ConnectionConfig{
			TLSConfig:            &tls.Config{},
			KeepAlivePeriod:      time.Second,
			InitialPacketSize:    1242,
			Endpoint:             &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443},
			MTU:                  1280,
			MaxReconnectAttempts: 0,
			ReconnectStrategy:    staticBackoff{delay: time.Millisecond},
		}, noopDevice{})
	}()

	waitForAttempts(t, &attempts, 5)
	cancel()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("MaintainTunnel did not exit after context cancel")
	}
}

func TestMaintainTunnelLazyReconnectWaitsForDemand(t *testing.T) {
	oldConnectTunnelFunc := connectTunnelFunc
	oldHandleForwardingFn := handleForwardingFn
	defer func() {
		connectTunnelFunc = oldConnectTunnelFunc
		handleForwardingFn = oldHandleForwardingFn
	}()

	var connects atomic.Int32
	connectTunnelFunc = func(
		ctx context.Context,
		tlsConfig *tls.Config,
		quicConfig *quic.Config,
		connectURI string,
		endpoint net.Addr,
		useHTTP2 bool,
	) (*net.UDPConn, tunnelTransport, *connectip.Conn, *http.Response, error) {
		connects.Add(1)
		return nil, nil, nil, &http.Response{StatusCode: http.StatusOK, Status: "200 OK"}, nil
	}
	// Every established connection drops immediately, exercising the
	// established-then-lost path that the lazy gate guards.
	handleForwardingFn = func(ctx context.Context, forwarding *forwardingSupervisor, ipConn *connectip.Conn) error {
		return errors.New("connection dropped")
	}

	demand := make(chan struct{})
	cfg := ConnectionConfig{
		TLSConfig:         &tls.Config{},
		KeepAlivePeriod:   time.Second,
		InitialPacketSize: 1242,
		Endpoint:          &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443},
		MTU:               1280,
		AlwaysReconnect:   false,
		WaitForReconnectDemand: func(ctx context.Context) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-demand:
				return nil
			}
		},
		ReconnectStrategy: staticBackoff{delay: time.Millisecond},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		MaintainTunnel(ctx, cfg, noopDevice{})
	}()

	// First connection is eager.
	waitForAttempts(t, &connects, 1)

	// After it drops, the lazy gate must block: no further connect until demand.
	time.Sleep(60 * time.Millisecond)
	if got := connects.Load(); got != 1 {
		t.Fatalf("expected reconnect to be gated on demand, got %d connects", got)
	}

	// Signalling demand triggers exactly one reconnect.
	demand <- struct{}{}
	waitForAttempts(t, &connects, 2)
	time.Sleep(60 * time.Millisecond)
	if got := connects.Load(); got != 2 {
		t.Fatalf("expected gate to re-engage after second drop, got %d connects", got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("MaintainTunnel did not exit after context cancel")
	}
}

func waitForAttempts(t *testing.T, attempts *atomic.Int32, want int32) {
	t.Helper()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if attempts.Load() >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("connect attempts did not reach %d within timeout, got %d", want, attempts.Load())
}
