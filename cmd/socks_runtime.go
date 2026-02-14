package cmd

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
	"sync/atomic"

	"github.com/things-go/go-socks5"
)

var ErrTunnelDisconnected = errors.New("tunnel disconnected")

type socksRuntime struct {
	tunnelUp      atomic.Bool
	restartMu     sync.Mutex
	activeConns   sync.Map
	server        atomic.Value // *socks5.Server
	serverFactory func(dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)) *socks5.Server
	upstreamDial  func(ctx context.Context, network, addr string) (net.Conn, error)
}

func newSocksRuntime(
	upstreamDial func(ctx context.Context, network, addr string) (net.Conn, error),
	serverFactory func(dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)) *socks5.Server,
) *socksRuntime {
	r := &socksRuntime{
		serverFactory: serverFactory,
		upstreamDial:  upstreamDial,
	}
	r.server.Store(r.serverFactory(r.DialContext))
	return r
}

func (r *socksRuntime) SetTunnelUp(up bool) {
	r.tunnelUp.Store(up)
}

func (r *socksRuntime) IsTunnelUp() bool {
	return r.tunnelUp.Load()
}

func (r *socksRuntime) CurrentServer() *socks5.Server {
	loaded := r.server.Load()
	if loaded == nil {
		return nil
	}
	srv, _ := loaded.(*socks5.Server)
	return srv
}

func (r *socksRuntime) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if !r.IsTunnelUp() {
		return nil, ErrTunnelDisconnected
	}

	conn, err := r.upstreamDial(ctx, network, addr)
	if err != nil {
		if !r.IsTunnelUp() {
			return nil, ErrTunnelDisconnected
		}
		return nil, err
	}

	return conn, nil
}

func (r *socksRuntime) DropIfDisconnected(conn net.Conn) bool {
	if r.IsTunnelUp() {
		return false
	}

	remote := "<unknown>"
	if addr := conn.RemoteAddr(); addr != nil {
		remote = addr.String()
	}
	log.Printf("new_conn_dropped_while_disconnected: remote=%s", remote)
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
	r.restartMu.Lock()
	defer r.restartMu.Unlock()

	log.Printf("socks_restart: reason=%v", reason)
	r.server.Store(r.serverFactory(r.DialContext))

	drained := r.drainActiveConnections()
	log.Printf("active_conn_drained: count=%d reason=%v", drained, reason)
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
