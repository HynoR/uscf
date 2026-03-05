package api

import (
	"context"
	"errors"
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

type forwardingSupervisor struct {
	ctx    context.Context
	cancel context.CancelFunc

	device TunnelDevice
	stats  *TunnelStats

	mu     sync.RWMutex
	active *forwardSession

	sessionID uint64
	wg        sync.WaitGroup
}

func newForwardingSupervisor(parentCtx context.Context, device TunnelDevice, stats *TunnelStats) *forwardingSupervisor {
	ctx, cancel := context.WithCancel(parentCtx)
	s := &forwardingSupervisor{
		ctx:    ctx,
		cancel: cancel,
		device: device,
		stats:  stats,
	}
	s.wg.Add(1)
	go s.runDeviceToIP()
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

	errStreak := 0
	var backoff time.Duration
	var lastSessionID uint64

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		buf := packetBufferPool.GetBuf()

		n, err := s.device.ReadPacket(*buf)
		if err != nil {
			packetBufferPool.PutBuf(buf)
			if s.ctx.Err() != nil {
				return
			}

			if session := s.activeSession(); session != nil {
				s.reportSessionError(session, fmt.Errorf("failed to read from TUN device: %v", err))
			}
			if !sleepWithBackoff(s.ctx, &backoff) {
				return
			}
			continue
		}

		s.stats.RecordPacketOut(n)
		session := s.activeSession()
		if session == nil {
			errStreak = 0
			backoff = 0
			lastSessionID = 0
			if cap(*buf) < 2*packetBuffCap {
				packetBufferPool.PutBuf(buf)
			}
			continue
		}

		if session.id != lastSessionID {
			errStreak = 0
			backoff = 0
			lastSessionID = session.id
		}

		icmp, err := session.conn.WritePacket((*buf)[:n])
		if err != nil {
			packetBufferPool.PutBuf(buf)
			if !s.isActiveSession(session) {
				continue
			}
			if errors.As(err, new(*connectip.CloseError)) {
				s.reportSessionError(session, fmt.Errorf("connection closed while writing to IP connection: %v", err))
				continue
			}

			errStreak++
			if errStreak >= forwardingErrStreakThreshold {
				s.reportSessionError(session, fmt.Errorf("too many write errors to IP connection: %w", err))
				continue
			}
			if errStreak == 1 {
				slog.Debug("error writing to IP connection", "error", err, "streak", errStreak)
			}
			if !sleepWithBackoff(s.ctx, &backoff) {
				return
			}
			continue
		}

		errStreak = 0
		backoff = 0
		if cap(*buf) < 2*packetBuffCap {
			packetBufferPool.PutBuf(buf)
		}

		if len(icmp) > 0 {
			if err := s.device.WritePacket(icmp); err != nil {
				if errors.As(err, new(*connectip.CloseError)) {
					if s.isActiveSession(session) {
						s.reportSessionError(session, fmt.Errorf("failed to write ICMP to TUN device: %v", err))
					}
					continue
				}
				slog.Debug("error writing ICMP to TUN device; continuing", "error", err)
				continue
			}
			s.stats.RecordPacketIn(len(icmp))
		}
	}
}

func (s *forwardingSupervisor) runIPToDevice(session *forwardSession) {
	defer s.wg.Done()

	errStreak := 0
	var backoff time.Duration

	for {
		select {
		case <-session.ctx.Done():
			return
		default:
		}

		buf := packetBufferPool.GetBuf()
		n, err := session.conn.ReadPacket(*buf, true)
		if err != nil {
			packetBufferPool.PutBuf(buf)
			if session.ctx.Err() != nil {
				return
			}
			if errors.As(err, new(*connectip.CloseError)) {
				if s.isActiveSession(session) {
					s.reportSessionError(session, fmt.Errorf("connection closed while reading from IP connection: %v", err))
				}
				return
			}

			errStreak++
			if errStreak >= forwardingErrStreakThreshold {
				s.reportSessionError(session, fmt.Errorf("too many read errors from IP connection: %w", err))
				return
			}
			if errStreak == 1 {
				slog.Debug("error reading from IP connection", "error", err, "streak", errStreak)
			}
			if !sleepWithBackoff(session.ctx, &backoff) {
				return
			}
			continue
		}

		errStreak = 0
		backoff = 0

		s.stats.RecordPacketIn(n)
		if err := s.device.WritePacket((*buf)[:n]); err != nil {
			packetBufferPool.PutBuf(buf)
			s.reportSessionError(session, fmt.Errorf("failed to write to TUN device: %v", err))
			return
		}
		if cap(*buf) < 2*packetBuffCap {
			packetBufferPool.PutBuf(buf)
		}
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
