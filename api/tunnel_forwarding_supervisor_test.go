package api

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
)

type testForwardingConn struct {
	writePackets chan []byte
	readPackets  chan []byte
	closeCh      chan struct{}
	closed       atomic.Bool
}

func newTestForwardingConn() *testForwardingConn {
	return &testForwardingConn{
		writePackets: make(chan []byte, 16),
		readPackets:  make(chan []byte, 16),
		closeCh:      make(chan struct{}),
	}
}

func (c *testForwardingConn) ReadPacket(buf []byte, allowAny bool) (int, error) {
	select {
	case <-c.closeCh:
		return 0, &connectip.CloseError{}
	case pkt := <-c.readPackets:
		n := copy(buf, pkt)
		return n, nil
	}
}

func (c *testForwardingConn) WritePacket(pkt []byte) ([]byte, error) {
	select {
	case <-c.closeCh:
		return nil, &connectip.CloseError{}
	default:
	}

	cp := append([]byte(nil), pkt...)
	select {
	case <-c.closeCh:
		return nil, &connectip.CloseError{}
	case c.writePackets <- cp:
		return nil, nil
	}
}

func (c *testForwardingConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		close(c.closeCh)
	}
	return nil
}

type testTunnelDevice struct {
	readPackets  chan []byte
	writePackets chan []byte
	closeCh      chan struct{}

	activeReads int32
	maxReads    int32
	closed      atomic.Bool
}

func newTestTunnelDevice() *testTunnelDevice {
	return &testTunnelDevice{
		readPackets:  make(chan []byte, 16),
		writePackets: make(chan []byte, 16),
		closeCh:      make(chan struct{}),
	}
}

func (d *testTunnelDevice) ReadPacket(buf []byte) (int, error) {
	current := atomic.AddInt32(&d.activeReads, 1)
	for {
		max := atomic.LoadInt32(&d.maxReads)
		if current <= max || atomic.CompareAndSwapInt32(&d.maxReads, max, current) {
			break
		}
	}
	defer atomic.AddInt32(&d.activeReads, -1)

	select {
	case <-d.closeCh:
		return 0, errors.New("device closed")
	case pkt := <-d.readPackets:
		n := copy(buf, pkt)
		return n, nil
	}
}

func (d *testTunnelDevice) WritePacket(pkt []byte) error {
	cp := append([]byte(nil), pkt...)
	select {
	case <-d.closeCh:
		return errors.New("device closed")
	case d.writePackets <- cp:
		return nil
	}
}

func (d *testTunnelDevice) Close() {
	if d.closed.CompareAndSwap(false, true) {
		close(d.closeCh)
	}
}

func TestForwardingSupervisorSingleDeviceReaderAcrossSessionSwitches(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	device := newTestTunnelDevice()
	supervisor := newForwardingSupervisor(ctx, device, &TunnelStats{}, NewNetBuffer(2048))
	t.Cleanup(func() {
		device.Close()
		supervisor.Close()
	})

	var prev *forwardSession
	for i := 0; i < 5; i++ {
		conn := newTestForwardingConn()
		session, err := supervisor.attach(conn)
		if err != nil {
			t.Fatalf("attach session %d failed: %v", i, err)
		}

		if prev != nil {
			supervisor.Detach(prev)
			prev.close()
		}

		payload := []byte{byte(0x10 + i)}
		device.readPackets <- payload
		got := waitConnPacket(t, conn.writePackets, time.Second)
		if len(got) != 1 || got[0] != payload[0] {
			t.Fatalf("session %d got unexpected packet: %#v", i, got)
		}
		prev = session
	}

	waitFor(t, time.Second, func() bool {
		return atomic.LoadInt32(&device.maxReads) >= 1
	})

	if max := atomic.LoadInt32(&device.maxReads); max != 1 {
		t.Fatalf("expected exactly one concurrent device reader, got %d", max)
	}
}

func TestForwardingSupervisorDetachStopsOldSessionAndNewSessionWorks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	device := newTestTunnelDevice()
	supervisor := newForwardingSupervisor(ctx, device, &TunnelStats{}, NewNetBuffer(2048))
	t.Cleanup(func() {
		device.Close()
		supervisor.Close()
	})

	oldConn := newTestForwardingConn()
	oldSession, err := supervisor.attach(oldConn)
	if err != nil {
		t.Fatalf("attach old session failed: %v", err)
	}

	device.readPackets <- []byte{0x01}
	_ = waitConnPacket(t, oldConn.writePackets, time.Second)

	newConn := newTestForwardingConn()
	newSession, err := supervisor.attach(newConn)
	if err != nil {
		t.Fatalf("attach new session failed: %v", err)
	}

	supervisor.Detach(oldSession)
	oldSession.close()

	device.readPackets <- []byte{0x02}
	gotNew := waitConnPacket(t, newConn.writePackets, time.Second)
	if len(gotNew) != 1 || gotNew[0] != 0x02 {
		t.Fatalf("new session got unexpected packet: %#v", gotNew)
	}

	select {
	case gotOld := <-oldConn.writePackets:
		t.Fatalf("old session received unexpected packet after detach: %#v", gotOld)
	case <-time.After(200 * time.Millisecond):
	}

	newConn.readPackets <- []byte{0xAA, 0xBB}
	gotTun := waitConnPacket(t, device.writePackets, time.Second)
	if len(gotTun) != 2 || gotTun[0] != 0xAA || gotTun[1] != 0xBB {
		t.Fatalf("device got unexpected packet from new session: %#v", gotTun)
	}

	supervisor.Detach(newSession)
	newSession.close()
}

func waitConnPacket(t *testing.T, ch <-chan []byte, timeout time.Duration) []byte {
	t.Helper()
	select {
	case pkt := <-ch:
		return pkt
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for packet after %s", timeout)
		return nil
	}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}
