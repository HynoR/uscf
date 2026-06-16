package cmd

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var ErrTunnelDisconnected = errors.New("tunnel disconnected")

// socksDialFunc dials an upstream connection for the given network and address.
type socksDialFunc = func(ctx context.Context, network, addr string) (net.Conn, error)

// socksServer serves a single accepted SOCKS5 client connection. It decouples
// socksRuntime from any concrete SOCKS library so the underlying implementation
// can be swapped behind this interface.
type socksServer interface {
	ServeConn(net.Conn) error
}

// drainHandle wraps a scheduled drain timer. The runtime stores it behind a
// pointer whose identity is set before the timer fires, letting the AfterFunc
// callback compare identity without racing on the timer assignment.
type drainHandle struct {
	timer *time.Timer
}

type socksRuntime struct {
	tunnelUp       atomic.Bool
	verboseLogging atomic.Bool
	restartMu      sync.Mutex
	drainMu        sync.Mutex
	scheduledDrain *drainHandle
	activeConns    sync.Map
	server         atomic.Value // socksServer
	serverFactory  func(dialFunc socksDialFunc) socksServer
	upstreamDial   socksDialFunc
	demand         chan struct{} // cap-1: signals outbound demand while the tunnel is down
}

func newSocksRuntime(
	upstreamDial socksDialFunc,
	serverFactory func(dialFunc socksDialFunc) socksServer,
) *socksRuntime {
	r := &socksRuntime{
		serverFactory: serverFactory,
		upstreamDial:  upstreamDial,
		demand:        make(chan struct{}, 1),
	}
	r.server.Store(r.serverFactory(r.DialContext))
	return r
}

// SignalDemand records that something wants the tunnel while it is down, so a
// lazy (non-always-reconnect) MaintainTunnel loop wakes up and reconnects.
// Non-blocking; the cap-1 channel coalesces bursts into a single token.
func (r *socksRuntime) SignalDemand() {
	select {
	case r.demand <- struct{}{}:
	default:
	}
}

// WaitForReconnectDemand blocks until SignalDemand fires or ctx is cancelled.
// Wired into api.ConnectionConfig.WaitForReconnectDemand.
func (r *socksRuntime) WaitForReconnectDemand(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.demand:
		return nil
	}
}

// drainDemand clears any pending demand token. Called once the tunnel is up so
// demand accumulated during a connect-failure backoff doesn't trigger a
// spurious immediate reconnect after the next idle drop.
func (r *socksRuntime) drainDemand() {
	select {
	case <-r.demand:
	default:
	}
}

func (r *socksRuntime) SetTunnelUp(up bool) {
	r.tunnelUp.Store(up)
}

func (r *socksRuntime) IsTunnelUp() bool {
	return r.tunnelUp.Load()
}

func (r *socksRuntime) SetVerboseLogging(enabled bool) {
	r.verboseLogging.Store(enabled)
}

func (r *socksRuntime) VerboseLoggingEnabled() bool {
	return r.verboseLogging.Load()
}

func (r *socksRuntime) CurrentServer() socksServer {
	loaded := r.server.Load()
	if loaded == nil {
		return nil
	}
	srv, _ := loaded.(socksServer)
	return srv
}

func (r *socksRuntime) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if !r.IsTunnelUp() {
		if r.VerboseLoggingEnabled() {
			slog.Warn("SOCKS dial rejected: tunnel down", "network", network, "target", addr)
		}
		return nil, ErrTunnelDisconnected
	}

	conn, err := r.upstreamDial(ctx, network, addr)
	if err != nil {
		if !r.IsTunnelUp() {
			if r.VerboseLoggingEnabled() {
				slog.Warn("SOCKS dial failed after tunnel down", "network", network, "target", addr, "error", err)
			}
			return nil, ErrTunnelDisconnected
		}
		if r.VerboseLoggingEnabled() {
			slog.Warn("SOCKS upstream dial failed", "network", network, "target", addr, "error", err)
		}
		return nil, err
	}

	if r.VerboseLoggingEnabled() {
		slog.Debug("SOCKS upstream dial succeeded", "network", network, "target", addr)
	}
	return conn, nil
}

func (r *socksRuntime) DropIfDisconnected(conn net.Conn) bool {
	if r.IsTunnelUp() {
		return false
	}

	// A client is trying to use the proxy while the tunnel is down: that is
	// real demand. Wake a lazy MaintainTunnel loop so it reconnects. The
	// connection itself is still dropped (the client retries once the tunnel
	// is back up).
	r.SignalDemand()

	remote := "<unknown>"
	if addr := conn.RemoteAddr(); addr != nil {
		remote = addr.String()
	}
	if r.VerboseLoggingEnabled() {
		slog.Warn("new SOCKS connection rejected while tunnel down", "remote", remote)
	} else {
		slog.Debug("new connection dropped while tunnel disconnected", "remote", remote)
	}
	_ = conn.Close()
	return true
}

func (r *socksRuntime) TrackConn(conn net.Conn) net.Conn {
	managed := &managedConn{
		Conn: conn,
	}
	managed.onClose = func() {
		r.activeConns.Delete(managed)
	}
	r.activeConns.Store(managed, struct{}{})
	return managed
}

func (r *socksRuntime) RestartAndDrain(reason error) {
	r.CancelScheduledDrain()

	r.restartMu.Lock()
	defer r.restartMu.Unlock()
	start := time.Now()

	slog.Debug("drain restart", "reason", reason)
	r.server.Store(r.serverFactory(r.DialContext))

	drained := r.drainActiveConnections()
	slog.Debug(
		"drain complete",
		"count",
		drained,
		"reason",
		reason,
		"duration",
		time.Since(start),
	)
}

func (r *socksRuntime) ScheduleDrain(reason error, grace time.Duration) {
	if grace <= 0 {
		r.RestartAndDrain(reason)
		return
	}

	r.drainMu.Lock()
	if r.scheduledDrain != nil {
		r.drainMu.Unlock()
		return
	}

	// handle's pointer identity is created before the timer so the AfterFunc
	// callback only ever reads this fully-assigned pointer (captured by the
	// closure) instead of a variable still being written by time.AfterFunc.
	// handle.timer is assigned below while still holding drainMu, and is only
	// read again under drainMu (CancelScheduledDrain), so it carries no race.
	handle := &drainHandle{}
	r.scheduledDrain = handle
	handle.timer = time.AfterFunc(grace, func() {
		r.clearScheduledDrain(handle)
		if r.IsTunnelUp() {
			return
		}
		r.RestartAndDrain(reason)
	})
	r.drainMu.Unlock()
}

func (r *socksRuntime) CancelScheduledDrain() bool {
	r.drainMu.Lock()
	handle := r.scheduledDrain
	r.scheduledDrain = nil
	r.drainMu.Unlock()

	if handle == nil {
		return false
	}
	return handle.timer.Stop()
}

func (r *socksRuntime) clearScheduledDrain(handle *drainHandle) {
	r.drainMu.Lock()
	if r.scheduledDrain == handle {
		r.scheduledDrain = nil
	}
	r.drainMu.Unlock()
}

func (r *socksRuntime) drainActiveConnections() int {
	count := 0
	r.activeConns.Range(func(key, _ any) bool {
		conn, ok := key.(net.Conn)
		if !ok {
			return true
		}
		count++
		_ = conn.Close()
		return true
	})
	return count
}

func (r *socksRuntime) activeConnCount() int {
	count := 0
	r.activeConns.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}

type managedConn struct {
	net.Conn
	onClose func()
	once    sync.Once
}

func (c *managedConn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.Conn.Close()
		if c.onClose != nil {
			c.onClose()
		}
	})
	return err
}

// CloseWrite forwards a half-close to the wrapped connection so graceful TCP
// half-close survives the managed wrapper. Returns nil if unsupported.
func (c *managedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
