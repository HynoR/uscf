package api

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	connectip "github.com/Diniboy1123/connect-ip-go"
)

// benchDevice synthesizes packets without channel overhead so the benchmark
// measures the pump itself, not a test harness.
type benchDevice struct {
	pkt []byte
}

func (d *benchDevice) ReadPacket(buf []byte) (int, error) {
	return copy(buf, d.pkt), nil
}

func (d *benchDevice) WritePacket(pkt []byte) error { return nil }

// benchBatchDevice additionally implements BatchTunnelDevice, returning a full
// batch per call like a saturated netstack queue.
type benchBatchDevice struct {
	benchDevice
	batch int
}

func (d *benchBatchDevice) BatchSize() int { return d.batch }

func (d *benchBatchDevice) ReadPackets(bufs [][]byte, sizes []int) (int, error) {
	for i := range bufs {
		sizes[i] = copy(bufs[i], d.pkt)
	}
	return len(bufs), nil
}

// countingConn counts forwarded packets and unblocks the benchmark once the
// target is reached.
type countingConn struct {
	target   int64
	count    int64
	done     chan struct{}
	doneOnce sync.Once
	closeCh  chan struct{}
	closed   sync.Once
}

func newCountingConn(target int64) *countingConn {
	return &countingConn{
		target:  target,
		done:    make(chan struct{}),
		closeCh: make(chan struct{}),
	}
}

func (c *countingConn) WritePacket(pkt []byte) ([]byte, error) {
	if atomic.AddInt64(&c.count, 1) >= c.target {
		c.doneOnce.Do(func() { close(c.done) })
	}
	return nil, nil
}

func (c *countingConn) ReadPacket(buf []byte, allowAny bool) (int, error) {
	<-c.closeCh
	return 0, &connectip.CloseError{}
}

func (c *countingConn) Close() error {
	c.closed.Do(func() { close(c.closeCh) })
	return nil
}

func benchmarkPump(b *testing.B, device TunnelDevice, pktSize int) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn := newCountingConn(int64(b.N))
	supervisor := newForwardingSupervisor(ctx, device, NewNetBuffer(pktSize))
	defer supervisor.Close()

	if _, err := supervisor.attach(conn); err != nil {
		b.Fatalf("attach: %v", err)
	}

	b.SetBytes(int64(pktSize))
	b.ResetTimer()
	<-conn.done
	b.StopTimer()
}

func BenchmarkPumpSinglePacket(b *testing.B) {
	pkt := make([]byte, 1280)
	benchmarkPump(b, &benchDevice{pkt: pkt}, len(pkt))
}

func BenchmarkPumpBatch128(b *testing.B) {
	pkt := make([]byte, 1280)
	benchmarkPump(b, &benchBatchDevice{benchDevice: benchDevice{pkt: pkt}, batch: 128}, len(pkt))
}
