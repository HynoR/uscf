package netstack

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
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

func makeReadBufs(n, size int) ([][]byte, []int) {
	bufs := make([][]byte, n)
	for i := range bufs {
		bufs[i] = make([]byte, size)
	}
	return bufs, make([]int, n)
}

// TestReadDrainsBatch checks that a single Read call returns every packet
// already queued, up to len(bufs).
func TestReadDrainsBatch(t *testing.T) {
	nt, _ := newTestTUN(t)

	const queued = 10
	for i := 0; i < queued; i++ {
		nt.incomingPacket <- buffer.NewViewWithData([]byte{byte(i), 1, 2, 3})
	}

	bufs, sizes := makeReadBufs(batchSize, 1280)
	n, err := nt.Read(bufs, sizes, 0)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != queued {
		t.Fatalf("Read returned %d packets, want %d", n, queued)
	}
	for i := 0; i < n; i++ {
		if sizes[i] != 4 {
			t.Fatalf("packet %d: size %d, want 4", i, sizes[i])
		}
		if bufs[i][0] != byte(i) {
			t.Fatalf("packet %d: first byte %d, want %d (order broken)", i, bufs[i][0], i)
		}
	}
}

// TestReadBlocksForFirstThenNonBlocking checks that Read blocks while the
// queue is empty and returns exactly one packet when only one arrives.
func TestReadBlocksForFirstThenNonBlocking(t *testing.T) {
	nt, _ := newTestTUN(t)

	bufs, sizes := makeReadBufs(batchSize, 1280)
	got := make(chan int, 1)
	go func() {
		n, err := nt.Read(bufs, sizes, 0)
		if err != nil {
			got <- -1
			return
		}
		got <- n
	}()

	select {
	case n := <-got:
		t.Fatalf("Read returned %d before any packet was queued", n)
	case <-time.After(100 * time.Millisecond):
	}

	nt.incomingPacket <- buffer.NewViewWithData([]byte{42})
	select {
	case n := <-got:
		if n != 1 {
			t.Fatalf("Read returned %d packets, want 1", n)
		}
		if sizes[0] != 1 || bufs[0][0] != 42 {
			t.Fatalf("unexpected packet: size %d, byte %d", sizes[0], bufs[0][0])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read did not return after a packet was queued")
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
