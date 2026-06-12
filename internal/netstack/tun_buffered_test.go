package netstack

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func newTestTUN(t *testing.T) (*netTun, *Net) {
	t.Helper()
	addr := netip.MustParseAddr("10.0.0.2")
	dev, tnet, err := CreateNetTUN([]netip.Addr{addr}, nil, 1280)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	nt := dev.(*netTun)
	t.Cleanup(func() { _ = nt.Close() })
	return nt, tnet
}

// TestWriteNotifyDoesNotBlockWithoutReader sends a burst of outbound packets
// through the stack while nobody is calling Read. With the upstream unbuffered
// incomingPacket channel the first send would park the writer forever; the
// buffered channel must absorb the burst.
func TestWriteNotifyDoesNotBlockWithoutReader(t *testing.T) {
	_, tnet := newTestTUN(t)

	conn, err := tnet.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("10.0.0.1:9"))
	if err != nil {
		t.Fatalf("DialUDPAddrPort: %v", err)
	}
	defer conn.Close()

	const packets = 100
	done := make(chan error, 1)
	go func() {
		payload := make([]byte, 512)
		for i := 0; i < packets; i++ {
			if _, err := conn.Write(payload); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("write burst failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("write burst blocked: incomingPacket channel is not buffered")
	}
}

// TestDialContextSmoke guards the fork against drift: Net.DialContext (the
// only Net method uscf uses) must still resolve and dial through the stack.
// HandleLocal keeps the traffic inside the stack, no device pump needed.
func TestDialContextSmoke(t *testing.T) {
	_, tnet := newTestTUN(t)

	ln, err := tnet.ListenTCPAddrPort(netip.MustParseAddrPort("10.0.0.2:8080"))
	if err != nil {
		t.Fatalf("ListenTCPAddrPort: %v", err)
	}
	defer ln.Close()

	accepted := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accepted <- err
			return
		}
		defer c.Close()
		_, err = c.Write([]byte("pong"))
		accepted <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := tnet.DialContext(ctx, "tcp", "10.0.0.2:8080")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("got %q, want %q", buf, "pong")
	}
	if err := <-accepted; err != nil {
		t.Fatalf("accept side: %v", err)
	}
}
