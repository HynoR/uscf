package api

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
)

type forwardingConn interface {
	ReadPacket(buf []byte, allowAny bool) (int, error)
	WritePacket(pkt []byte) ([]byte, error)
	Close() error
}

type forwardSession struct {
	id     uint64
	conn   forwardingConn
	ctx    context.Context
	cancel context.CancelFunc
	errCh  chan error

	closeOnce sync.Once
	errOnce   sync.Once
}

func (s *forwardSession) close() {
	s.closeOnce.Do(func() {
		_ = s.conn.Close()
		s.cancel()
	})
}

// forwardingSupervisor owns a single, long-lived device→IP pump (and ICMP
// injector) for the whole process. Reconnects only swap the active IP
// connection underneath it via attach(); the TUN reader is never torn down.
// This avoids the "stale TUN reader" problem that a per-cycle pump model has
// to paper over with a serializing mutex and a shutdown grace window.
type forwardingSupervisor struct {
	ctx    context.Context
	cancel context.CancelFunc

	device  TunnelDevice
	bufPool *NetBuffer

	mu     sync.RWMutex
	active *forwardSession

	icmpCh chan []byte

	sessionID uint64
	wg        sync.WaitGroup
}

// fallbackBufferSize sizes the packet buffers when no pool is supplied (test
// paths). Sized to a full Ethernet MTU so it can never truncate a tunneled
// packet even with a raised inner MTU.
const fallbackBufferSize = 1500

func newForwardingSupervisor(parentCtx context.Context, device TunnelDevice, bufPool *NetBuffer) *forwardingSupervisor {
	ctx, cancel := context.WithCancel(parentCtx)
	if bufPool == nil {
		bufPool = NewNetBuffer(fallbackBufferSize)
	}
	s := &forwardingSupervisor{
		ctx:     ctx,
		cancel:  cancel,
		device:  device,
		bufPool: bufPool,
		icmpCh:  make(chan []byte, 32),
	}
	s.wg.Add(2)
	go s.runDeviceToIP()
	go s.runICMPInjector()
	return s
}

func (s *forwardingSupervisor) Close() {
	s.cancel()
	s.mu.Lock()
	active := s.active
	s.active = nil
	s.mu.Unlock()
	if active != nil {
		active.close()
	}
	s.wg.Wait()
}

func (s *forwardingSupervisor) AttachConnectIP(ipConn *connectip.Conn) (*forwardSession, error) {
	return s.attach(ipConn)
}

func (s *forwardingSupervisor) attach(conn forwardingConn) (*forwardSession, error) {
	if conn == nil {
		return nil, fmt.Errorf("ip connection is nil")
	}

	sessionCtx, cancel := context.WithCancel(s.ctx)
	session := &forwardSession{
		id:     atomic.AddUint64(&s.sessionID, 1),
		conn:   conn,
		ctx:    sessionCtx,
		cancel: cancel,
		errCh:  make(chan error, 1),
	}

	s.mu.Lock()
	prev := s.active
	s.active = session
	s.mu.Unlock()

	if prev != nil {
		prev.close()
	}

	s.wg.Add(1)
	go s.runIPToDevice(session)

	return session, nil
}

func (s *forwardingSupervisor) Detach(session *forwardSession) {
	if session == nil {
		return
	}

	s.mu.Lock()
	if s.active == session {
		s.active = nil
	}
	s.mu.Unlock()
}

func (s *forwardingSupervisor) activeSession() *forwardSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active
}

func (s *forwardingSupervisor) isActiveSession(session *forwardSession) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active == session
}

func (s *forwardingSupervisor) reportSessionError(session *forwardSession, err error) {
	if session == nil || err == nil {
		return
	}
	session.errOnce.Do(func() {
		select {
		case session.errCh <- err:
		default:
		}
		session.close()
	})
}

func (s *forwardingSupervisor) runDeviceToIP() {
	defer s.wg.Done()

	// Devices that support batched reads (the forked netstack TUN) deliver up
	// to BatchSize packets per call; plain TunnelDevices go through a
	// single-packet shim. The pump owns its read buffers outright: it is the
	// sole reader and every packet is fully consumed by WritePacket before the
	// next read, so the buffers are reused across iterations instead of
	// cycling through the shared pool.
	batch := 1
	var readBatch func(bufs [][]byte, sizes []int) (int, error)
	if dev, ok := s.device.(BatchTunnelDevice); ok && dev.BatchSize() > 1 {
		batch = dev.BatchSize()
		readBatch = dev.ReadPackets
	} else {
		readBatch = func(bufs [][]byte, sizes []int) (int, error) {
			n, err := s.device.ReadPacket(bufs[0])
			if err != nil {
				return 0, err
			}
			sizes[0] = n
			return 1, nil
		}
	}
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, s.bufPool.capacity)
	}
	sizes := make([]int, batch)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		n, err := readBatch(bufs, sizes)
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			if session := s.activeSession(); session != nil {
				s.reportSessionError(session, fmt.Errorf("failed to read from TUN device: %v", err))
			}
			// Device read errors realistically only happen on shutdown; the
			// short pause just guards against a busy-loop if one slips through
			// while the supervisor is still live.
			select {
			case <-s.ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}

		// Drop outbound packets while there is no usable session (no tunnel yet,
		// or the active one is being torn down for a reconnect). Reading and
		// discarding keeps the netstack device drained so it never blocks.
		session := s.activeSession()
		if session == nil || session.ctx.Err() != nil {
			continue
		}

		for i := 0; i < n; i++ {
			icmp, err := session.conn.WritePacket(bufs[i][:sizes[i]])
			if err != nil {
				// Any write error means this IP connection is unusable; signal a
				// reconnect (unless this session was already superseded) and drop
				// the rest of the batch.
				if s.isActiveSession(session) {
					s.reportSessionError(session, fmt.Errorf("error writing to IP connection: %w", err))
				}
				break
			}

			if len(icmp) > 0 {
				// Never inject the ICMP packet from this goroutine: it is the sole
				// reader of the TUN device, and netstack can synchronously emit a
				// retransmission while handling the ICMP error. Even with the
				// fork's buffered packet channel, injecting mid-drain from the
				// reader risks stalling the loop. Hand the packet to a dedicated
				// injector goroutine instead.
				select {
				case s.icmpCh <- icmp:
				default:
					slog.Warn("dropping ICMP packet: injector queue full")
				}
			}
		}
	}
}

// runICMPInjector writes ICMP packets produced by the IP connection (e.g.
// "datagram too large" responses) back into the TUN device. This must happen
// off the runDeviceToIP goroutine; see the comment at the icmpCh send site.
func (s *forwardingSupervisor) runICMPInjector() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		case pkt := <-s.icmpCh:
			if err := s.device.WritePacket(pkt); err != nil {
				slog.Debug("error writing ICMP to TUN device; continuing", "error", err)
			}
		}
	}
}

func (s *forwardingSupervisor) runIPToDevice(session *forwardSession) {
	defer s.wg.Done()

	for {
		select {
		case <-session.ctx.Done():
			return
		default:
		}

		buf := s.bufPool.GetBuf()
		n, err := session.conn.ReadPacket(*buf, true)
		if err != nil {
			s.bufPool.PutBuf(buf)
			if session.ctx.Err() != nil {
				return
			}
			if s.isActiveSession(session) {
				s.reportSessionError(session, fmt.Errorf("error reading from IP connection: %w", err))
			}
			return
		}

		if err := s.device.WritePacket((*buf)[:n]); err != nil {
			s.bufPool.PutBuf(buf)
			s.reportSessionError(session, fmt.Errorf("failed to write to TUN device: %v", err))
			return
		}
		s.bufPool.PutBuf(buf)
	}
}

func handleForwarding(ctx context.Context, supervisor *forwardingSupervisor, ipConn *connectip.Conn) error {
	session, err := supervisor.AttachConnectIP(ipConn)
	if err != nil {
		return err
	}
	defer func() {
		supervisor.Detach(session)
		session.close()
	}()

	select {
	case err := <-session.errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
