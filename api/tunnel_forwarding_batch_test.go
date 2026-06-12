package api

import (
	"context"
	"testing"
	"time"
)

// testBatchTunnelDevice extends testTunnelDevice with the BatchTunnelDevice
// interface, mimicking the forked netstack TUN: block for the first packet,
// then drain whatever is queued without blocking.
type testBatchTunnelDevice struct {
	*testTunnelDevice
	batch int
}

func (d *testBatchTunnelDevice) BatchSize() int { return d.batch }

func (d *testBatchTunnelDevice) ReadPackets(bufs [][]byte, sizes []int) (int, error) {
	n, err := d.ReadPacket(bufs[0])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	count := 1
	for count < len(bufs) {
		select {
		case pkt := <-d.readPackets:
			sizes[count] = copy(bufs[count], pkt)
			count++
		default:
			return count, nil
		}
	}
	return count, nil
}

// TestForwardingSupervisorBatchDeviceForwardsAllPackets checks that the
// supervisor's batched read path loses no packets, preserves order, and still
// routes ICMP responses through the injector goroutine.
func TestForwardingSupervisorBatchDeviceForwardsAllPackets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	base := newTestTunnelDevice()
	device := &testBatchTunnelDevice{testTunnelDevice: base, batch: 8}
	supervisor := newForwardingSupervisor(ctx, device, NewNetBuffer(2048))
	t.Cleanup(func() {
		base.Close()
		supervisor.Close()
	})

	conn := &icmpForwardingConn{
		testForwardingConn: newTestForwardingConn(),
		icmp:               []byte{0xFE},
	}
	session, err := supervisor.attach(conn)
	if err != nil {
		t.Fatalf("attach session failed: %v", err)
	}
	defer func() {
		supervisor.Detach(session)
		session.close()
	}()

	const packets = 12
	for i := 0; i < packets; i++ {
		base.readPackets <- []byte{byte(i), 0xAA}
	}

	for i := 0; i < packets; i++ {
		got := waitConnPacket(t, conn.writePackets, 2*time.Second)
		if len(got) != 2 || got[0] != byte(i) {
			t.Fatalf("packet %d: got %#v, want [%d 0xAA]", i, got, i)
		}
	}

	// Every forwarded packet produced an ICMP response; all must come back
	// through the device without stalling the pump.
	for i := 0; i < packets; i++ {
		if got := waitConnPacket(t, base.writePackets, 2*time.Second); got[0] != 0xFE {
			t.Fatalf("ICMP %d: got %#v, want [0xFE]", i, got)
		}
	}
}
