package cmd

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// newTestL3UDPTunnel builds an l3UDPTunnel with a no-network start hook so the
// demand/gating logic can be exercised without standing up a real connect-ip
// tunnel. starts counts how many times the lazy start fired.
func newTestL3UDPTunnel() (*l3UDPTunnel, *atomic.Int32) {
	var starts atomic.Int32
	t := &l3UDPTunnel{
		demand:            make(chan struct{}, 1),
		connectionTimeout: time.Second,
		idleTimeout:       time.Second,
	}
	t.start = func() { starts.Add(1) }
	return t, &starts
}

func TestL3UDPTunnelDialWhileDownSignalsDemand(t *testing.T) {
	tunnel, starts := newTestL3UDPTunnel()

	// Down: DialUDP must lazily start, drop (ErrTunnelDisconnected), and leave a
	// demand token so a dormant reconnect loop wakes.
	conn, err := tunnel.DialUDP(context.Background(), "1.1.1.1:53")
	if conn != nil {
		t.Fatalf("expected nil conn while tunnel down, got %v", conn)
	}
	if !errors.Is(err, ErrTunnelDisconnected) {
		t.Fatalf("expected ErrTunnelDisconnected while down, got %v", err)
	}
	if got := starts.Load(); got != 1 {
		t.Fatalf("expected lazy start to fire once, got %d", got)
	}

	// A demand token must be queued (waitForReconnectDemand returns immediately).
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := tunnel.waitForReconnectDemand(ctx); err != nil {
		t.Fatalf("expected a queued demand token, got %v", err)
	}

	// A second dial while still down re-arms demand but does NOT start again.
	if _, err := tunnel.DialUDP(context.Background(), "1.1.1.1:53"); !errors.Is(err, ErrTunnelDisconnected) {
		t.Fatalf("second dial: expected ErrTunnelDisconnected, got %v", err)
	}
	if got := starts.Load(); got != 1 {
		t.Fatalf("start must fire exactly once (startOnce), got %d", got)
	}
}

func TestL3UDPTunnelDemandTrio(t *testing.T) {
	tunnel, _ := newTestL3UDPTunnel()

	// drainDemand on an empty channel is a no-op and must not block.
	tunnel.drainDemand()

	// signalDemand coalesces bursts into a single cap-1 token.
	tunnel.signalDemand()
	tunnel.signalDemand()
	tunnel.signalDemand()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := tunnel.waitForReconnectDemand(ctx); err != nil {
		t.Fatalf("waitForReconnectDemand after signal: %v", err)
	}

	// Token consumed: the channel is empty again, so drainDemand stays a no-op.
	tunnel.drainDemand()

	// With no token, waitForReconnectDemand blocks until ctx cancellation.
	cctx, ccancel := context.WithCancel(context.Background())
	ccancel()
	if err := tunnel.waitForReconnectDemand(cctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled when no demand, got %v", err)
	}
}

func TestL3UDPTunnelDrainClearsDemand(t *testing.T) {
	tunnel, _ := newTestL3UDPTunnel()

	tunnel.signalDemand()
	tunnel.drainDemand()

	// After draining, nothing is queued: waitForReconnectDemand must block (ctx wins).
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := tunnel.waitForReconnectDemand(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded after drain, got %v", err)
	}
}
