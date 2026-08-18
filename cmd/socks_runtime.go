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

type socksRuntime struct {
	tunnelUp       atomic.Bool
	verboseLogging atomic.Bool
	activeConns    sync.Map
	server         socksServer
	upstreamDial   socksDialFunc
	demand         chan struct{} // cap-1: signals outbound demand while the tunnel is down
}

func newSocksRuntime(
	upstreamDial socksDialFunc,
	serverFactory func(dialFunc socksDialFunc) socksServer,
) *socksRuntime {
	r := &socksRuntime{
		upstreamDial: upstreamDial,
		demand:       make(chan struct{}, 1),
	}
	// The server is stateless and shared for the runtime's whole life (it holds no
	// per-connection state), so it is built once here and never swapped.
	r.server = serverFactory(r.DialContext)
	// Claim the state file before anything can serve: a previous run killed while
	// up leaves "up" on disk, and a healthcheck must not read that as a live
	// tunnel while this process is still dialing.
	publishTunnelState(false)
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

// SetTunnelUp records whether the upstream is usable. Every transport (L3
// MASQUE, L4 MASQUE, in-process WireGuard, SOCKS-only) drives this, so it is
// also where the healthcheck state file is published — a transport cannot gain
// a data plane without teaching the healthcheck about it.
func (r *socksRuntime) SetTunnelUp(up bool) {
	if r.tunnelUp.Swap(up) != up {
		publishTunnelState(up)
	}
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
	return r.server
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

// ResetTrackedConns closes every tracked downstream connection immediately. It is
// called the moment the tunnel goes down: a MASQUE flow's edge state at Cloudflare
// is destroyed when the tunnel drops, so the flow cannot resume on the next
// connection — even one that reconnects in milliseconds. Closing it turns a silent
// multi-minute hang into a prompt reset the client retries (and the retry succeeds
// once the tunnel is back). New connections cannot be tracked while the tunnel is
// down — the accept loop drops them (DropIfDisconnected) — so this only ever closes
// genuinely-stranded flows.
func (r *socksRuntime) ResetTrackedConns() {
	if n := r.drainActiveConnections(); n > 0 {
		slog.Info("reset stranded SOCKS connections (upstream tunnel dropped)", "count", n)
	}
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

// SetIdleTimeout forwards a re-arming idle-timeout change to the wrapped
// connection (e.g. models.TimeoutConn) so the relay can shorten a half-open
// flow's idle bound through this managed wrapper. No-op if unsupported.
func (c *managedConn) SetIdleTimeout(d time.Duration) {
	if s, ok := c.Conn.(interface{ SetIdleTimeout(time.Duration) }); ok {
		s.SetIdleTimeout(d)
	}
}
