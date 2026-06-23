package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// L4 (layer-4) proxying tunnels each TCP connection directly as an HTTP/3
// extended-CONNECT request stream over a single shared QUIC connection to
// Cloudflare's MASQUE proxy endpoint. Unlike the connect-ip (L3) path, it never
// runs a userspace TCP/IP stack: a client TCP flow maps 1:1 onto a QUIC stream,
// so congestion- and flow-control are handled natively by QUIC instead of
// gVisor's netstack. This is faster and lighter but TCP-only — there is no
// datagram/UDP path here.
//
// Ported and adapted from Diniboy1123/usque api/l4proxy.go. The DNS resolver is
// intentionally dropped: uscf's SOCKS adapter resolves hostnames to IP literals
// before dialing, which is exactly what the edge CONNECT authority requires.

const (
	defaultL4ConnectTimeout    = 15 * time.Second
	defaultL4ConnectRetryCount = 2
)

// L4ProxyConfig configures a new L4Proxy.
type L4ProxyConfig struct {
	TLSConfig  *tls.Config
	QUICConfig *quic.Config
	// Endpoint is the fallback HTTP/3 UDP endpoint used when EndpointSelector is
	// nil or returns nothing.
	Endpoint *net.UDPAddr
	// EndpointSelector, when set, is consulted on every (re)connect so the proxy
	// can rotate across a custom endpoint pool, mirroring the L3 tunnel's
	// EndpointSelector. It must return a *net.UDPAddr; anything else is ignored
	// in favour of Endpoint.
	EndpointSelector func() net.Addr
	// ConnectTimeout bounds a single CONNECT-stream open attempt.
	ConnectTimeout time.Duration
	// ConnectRetryCount is how many times DialContext retries opening a stream.
	ConnectRetryCount int
}

// L4Proxy opens one HTTP/3 CONNECT stream for each proxied TCP connection,
// multiplexed over a single cached QUIC connection.
type L4Proxy struct {
	tlsConfig         *tls.Config
	quicConfig        *quic.Config
	endpoint          *net.UDPAddr
	endpointSelector  func() net.Addr
	connectTimeout    time.Duration
	connectRetryCount int

	connMu sync.Mutex
	client *l4HTTP3Client
}

type l4HTTP3Client struct {
	udpConn    *net.UDPConn
	quicConn   *quic.Conn
	clientConn *http3.ClientConn
}

// NewL4Proxy creates an L4 proxy dialer from a configuration struct.
func NewL4Proxy(cfg L4ProxyConfig) (*L4Proxy, error) {
	if cfg.TLSConfig == nil {
		return nil, fmt.Errorf("missing TLS config")
	}
	if cfg.Endpoint == nil {
		return nil, fmt.Errorf("missing HTTP/3 UDP endpoint")
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = defaultL4ConnectTimeout
	}
	if cfg.ConnectRetryCount <= 0 {
		cfg.ConnectRetryCount = defaultL4ConnectRetryCount
	}

	return &L4Proxy{
		tlsConfig:         cfg.TLSConfig,
		quicConfig:        cfg.QUICConfig,
		endpoint:          cfg.Endpoint,
		endpointSelector:  cfg.EndpointSelector,
		connectTimeout:    cfg.ConnectTimeout,
		connectRetryCount: cfg.ConnectRetryCount,
	}, nil
}

// Connect eagerly establishes (or validates) the shared QUIC connection. It is
// optional — DialContext establishes lazily — but lets callers fail fast / log a
// "ready" line at startup.
func (p *L4Proxy) Connect(ctx context.Context) error {
	_, err := p.getOrCreateClientConn(ctx)
	return err
}

// Close tears down the shared QUIC connection, if any.
func (p *L4Proxy) Close() error {
	p.connMu.Lock()
	client := p.client
	p.client = nil
	p.connMu.Unlock()
	if client != nil {
		closeL4HTTP3(client.udpConn, client.quicConn)
	}
	return nil
}

// DialContext connects target (an "ip:port" authority) over an L4 MASQUE
// HTTP/3 CONNECT stream and returns it as a net.Conn.
func (p *L4Proxy) DialContext(ctx context.Context, target string) (net.Conn, error) {
	if p == nil || p.tlsConfig == nil {
		return nil, fmt.Errorf("missing TLS config")
	}
	if p.endpoint == nil {
		return nil, fmt.Errorf("missing HTTP/3 UDP endpoint")
	}

	timeout := p.connectTimeout
	if timeout <= 0 {
		timeout = defaultL4ConnectTimeout
	}
	attempts := p.connectRetryCount
	if attempts <= 0 {
		attempts = defaultL4ConnectRetryCount
	}

	var lastErr error
	for range attempts {
		dialCtx, cancel := context.WithTimeout(ctx, timeout)
		conn, err := p.dial(dialCtx, target)
		cancel()
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

func (p *L4Proxy) dial(ctx context.Context, target string) (*l4TCPConn, error) {
	h3Client, err := p.getOrCreateClientConn(ctx)
	if err != nil {
		return nil, err
	}

	stream, err := h3Client.clientConn.OpenRequestStream(ctx)
	if err != nil {
		if !shouldReconnectOnOpenStreamError(ctx, err) {
			return nil, err
		}
		// The cached HTTP/3 connection might be stale (e.g. Cloudflare evicted it
		// after the idle timeout); reconnect once and retry.
		p.closeClientConnIfCurrent(h3Client)
		h3Client, err = p.getOrCreateClientConn(ctx)
		if err != nil {
			return nil, err
		}
		stream, err = h3Client.clientConn.OpenRequestStream(ctx)
		if err != nil {
			if shouldReconnectOnOpenStreamError(ctx, err) {
				p.closeClientConnIfCurrent(h3Client)
			}
			return nil, err
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+target, nil)
	if err != nil {
		closeL4Stream(stream)
		return nil, err
	}
	req.Host = target
	if err := stream.SendRequestHeader(req); err != nil {
		closeL4Stream(stream)
		p.dropConnIfDead(h3Client)
		return nil, err
	}
	response, err := stream.ReadResponse()
	if err != nil {
		closeL4Stream(stream)
		p.dropConnIfDead(h3Client)
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		// A valid non-2xx response means the shared connection is healthy and only
		// this target was rejected: close just the stream, never the connection.
		closeL4Stream(stream)
		return nil, fmt.Errorf("CONNECT %s rejected with status %d", target, response.StatusCode)
	}
	return &l4TCPConn{stream: stream, local: h3Client.udpConn.LocalAddr(), remote: l4Addr(target)}, nil
}

// shouldReconnectOnOpenStreamError reports whether an OpenRequestStream failure
// looks like a stale connection (worth reconnecting) rather than a caller-driven
// cancellation/timeout (which must propagate unchanged).
func shouldReconnectOnOpenStreamError(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if ctx != nil && (errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded)) {
		return false
	}
	return true
}

func (p *L4Proxy) selectEndpoint() *net.UDPAddr {
	if p.endpointSelector != nil {
		if selected := p.endpointSelector(); selected != nil {
			if udp, ok := selected.(*net.UDPAddr); ok && udp != nil {
				return udp
			}
		}
	}
	return p.endpoint
}

func (p *L4Proxy) getOrCreateClientConn(ctx context.Context) (*l4HTTP3Client, error) {
	p.connMu.Lock()
	if p.client != nil {
		client := p.client
		p.connMu.Unlock()
		return client, nil
	}
	p.connMu.Unlock()

	endpoint := p.selectEndpoint()
	udpConn, err := listenUDPForEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	quicConn, err := quic.Dial(ctx, udpConn, endpoint, p.tlsConfig, p.quicConfig)
	if err != nil {
		_ = udpConn.Close()
		return nil, err
	}

	newClient := &l4HTTP3Client{
		udpConn:    udpConn,
		quicConn:   quicConn,
		clientConn: (&http3.Transport{}).NewClientConn(quicConn),
	}

	p.connMu.Lock()
	if p.client != nil {
		// Lost the race: another goroutine created the shared connection first.
		current := p.client
		p.connMu.Unlock()
		closeL4HTTP3(newClient.udpConn, newClient.quicConn)
		return current, nil
	}
	p.client = newClient
	p.connMu.Unlock()
	slog.Debug("l4 proxy established shared QUIC connection", "endpoint", endpoint.String())
	go p.watchClientConn(newClient)

	return newClient, nil
}

// watchClientConn evicts the cached shared connection from the cache as soon as
// its underlying QUIC connection dies — idle eviction by Cloudflare, a server
// close, or a path/keepalive failure detected by quic-go. Without this, a dead
// connection lingers in the cache: OpenRequestStream still succeeds locally, so
// the reconnect-on-open-error path never triggers, and every new dial blocks in
// ReadResponse until its timeout. Proactively dropping the dead connection lets
// the next dial rebuild immediately instead of stalling all flows. The goroutine
// exits when the connection is closed (Done fires) — including on Close() — so it
// does not leak.
func (p *L4Proxy) watchClientConn(client *l4HTTP3Client) {
	if client == nil || client.quicConn == nil {
		return
	}
	<-client.quicConn.Context().Done()
	slog.Debug("l4 proxy shared QUIC connection closed; invalidating cache",
		"cause", context.Cause(client.quicConn.Context()))
	p.closeClientConnIfCurrent(client)
}

// dropConnIfDead invalidates the cached shared connection when its underlying
// QUIC connection has already died. Called on dial-time transport errors
// (SendRequestHeader / ReadResponse) so that the first dial to observe a path
// failure frees every other in-flight and subsequent dial to rebuild, instead of
// each one independently blocking on the same dead connection. A per-target
// rejection (a valid non-2xx HTTP response) never reaches here, so a single bad
// target never tears down the connection shared by all other live flows.
func (p *L4Proxy) dropConnIfDead(client *l4HTTP3Client) {
	if client != nil && client.quicConn != nil && client.quicConn.Context().Err() != nil {
		p.closeClientConnIfCurrent(client)
	}
}

// closeClientConnIfCurrent drops the shared connection only if it is still the
// one the caller observed, so concurrent dials that already reconnected are not
// torn down.
func (p *L4Proxy) closeClientConnIfCurrent(expected *l4HTTP3Client) {
	if expected == nil {
		return
	}

	p.connMu.Lock()
	if p.client != expected {
		p.connMu.Unlock()
		return
	}
	p.client = nil
	p.connMu.Unlock()

	closeL4HTTP3(expected.udpConn, expected.quicConn)
}

func listenUDPForEndpoint(endpoint *net.UDPAddr) (*net.UDPConn, error) {
	if endpoint.IP.To4() == nil {
		return net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6zero})
	}
	return net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
}

func closeL4HTTP3(udpConn *net.UDPConn, quicConn *quic.Conn) {
	if quicConn != nil {
		_ = quicConn.CloseWithError(0, "")
	}
	if udpConn != nil {
		_ = udpConn.Close()
	}
}

// closeL4Stream fully reclaims a dial-time request stream by ending the send
// side AND cancelling the receive side. http3.RequestStream.Close only closes
// the send direction, so without the CancelRead the bidirectional QUIC stream
// is never released on the shared connection — every rejected or failed CONNECT
// would otherwise leak a half-open stream (and its flow-control credit) until
// the whole connection is torn down. Mirrors l4TCPConn.Close. It does NOT touch
// the shared QUIC connection: a per-target rejection (e.g. 502) must not kill
// the connection shared by all other live flows.
func closeL4Stream(stream l4Stream) {
	if stream == nil {
		return
	}
	_ = stream.Close()
	stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
}

// l4TCPConn adapts an HTTP/3 CONNECT request stream to net.Conn, preserving TCP
// half-close semantics (CloseWrite ends our send side; CloseRead cancels recv).
type l4TCPConn struct {
	stream l4Stream
	local  net.Addr
	remote net.Addr
	once   sync.Once
}

type l4Stream interface {
	io.ReadWriteCloser
	CancelRead(quic.StreamErrorCode)
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

func (c *l4TCPConn) Read(b []byte) (int, error) {
	if c.stream == nil {
		return 0, net.ErrClosed
	}
	return c.stream.Read(b)
}

func (c *l4TCPConn) Write(b []byte) (int, error) {
	if c.stream == nil {
		return 0, net.ErrClosed
	}
	return c.stream.Write(b)
}

func (c *l4TCPConn) CloseWrite() error {
	if c.stream == nil {
		return nil
	}
	return c.stream.Close()
}

func (c *l4TCPConn) CloseRead() error {
	if c.stream == nil {
		return nil
	}
	c.stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	return nil
}

func (c *l4TCPConn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.CloseWrite()
		_ = c.CloseRead()
	})
	return err
}

func (c *l4TCPConn) LocalAddr() net.Addr {
	if c.local == nil {
		return l4Addr("l4")
	}
	return c.local
}

func (c *l4TCPConn) RemoteAddr() net.Addr { return c.remote }

func (c *l4TCPConn) SetDeadline(t time.Time) error {
	if c.stream == nil {
		return nil
	}
	return c.stream.SetDeadline(t)
}

func (c *l4TCPConn) SetReadDeadline(t time.Time) error {
	if c.stream == nil {
		return nil
	}
	return c.stream.SetReadDeadline(t)
}

func (c *l4TCPConn) SetWriteDeadline(t time.Time) error {
	if c.stream == nil {
		return nil
	}
	return c.stream.SetWriteDeadline(t)
}

type l4Addr string

func (a l4Addr) Network() string { return "masque-l4-tcp" }
func (a l4Addr) String() string  { return string(a) }
