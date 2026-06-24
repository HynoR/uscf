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
	"sync/atomic"
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
	defaultL4PoolSize          = 1
	// defaultL4MaxInFlightStreams bounds concurrent open CONNECT streams when the
	// caller does not specify one. Sized well above typical peak active concurrency;
	// it is an OOM backstop, not the normal operating limit.
	defaultL4MaxInFlightStreams = 4096
	// defaultL4StreamOpenTimeout bounds a single OpenRequestStream attempt so a
	// saturated connection (peer MAX_STREAMS reached → OpenStreamSync blocks) is
	// detected quickly and the dial can fall through to another pooled connection
	// instead of stalling. It is clamped to the connect timeout.
	defaultL4StreamOpenTimeout = 5 * time.Second
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
	// PoolSize is how many shared QUIC connections to keep. Default 1: a single
	// connection is one stable WARP egress identity. A larger pool does not scale
	// throughput (Cloudflare caps connections per enrollment and each connection is a
	// different egress IP), so it is an opt-in that trades egress-IP stability for
	// per-connection MAX_STREAMS headroom. <=0 uses the default.
	PoolSize int
	// MaxInFlightStreams hard-caps concurrent open CONNECT streams across the whole
	// proxy. When reached, DialContext fails fast with errL4PoolSaturated (the client
	// retries) instead of blocking on the shared connection's MAX_STREAMS — which is
	// what otherwise lets inbound SOCKS connections pile up into an OOM. It also
	// bounds how many dials can be concurrently blocked in OpenRequestStream. <=0 uses
	// the default.
	MaxInFlightStreams int
}

// L4Proxy opens one HTTP/3 CONNECT stream per proxied TCP connection, multiplexed
// over a single shared QUIC connection (PoolSize defaults to 1). The connection is
// one stable WARP egress identity; it auto-reconnects when it dies. The two ways a
// shared connection breaks under load are handled explicitly: half-open streams are
// reclaimed quickly upstream (so the peer keeps raising MAX_STREAMS), and a hard
// in-flight stream cap fast-fails new flows the instant the connection is saturated,
// so a dial never blocks on OpenStreamSync and inbound SOCKS connections cannot pile
// up into an OOM. PoolSize>1 keeps the same machinery across N connections, but at
// the cost of fragmenting the egress IP — it is not the scaling axis (Cloudflare
// caps connections per enrollment).
type L4Proxy struct {
	tlsConfig         *tls.Config
	quicConfig        *quic.Config
	endpoint          *net.UDPAddr
	endpointSelector  func() net.Addr
	connectTimeout    time.Duration
	connectRetryCount int
	streamOpenTimeout time.Duration
	poolSize          int   // immutable; == len(clients). Read locklessly in DialContext.
	maxInFlight       int64 // immutable; hard ceiling on concurrent open streams (0 = unbounded).

	inFlight        atomic.Int64  // currently open CONNECT streams (reserved at dial, released on Close)
	saturations     atomic.Uint64 // cumulative fast-fail rejections (local cap OR CF MAX_STREAMS)
	lastSatLogNs    atomic.Int64  // unix ns of the last saturation warning (rate-limits the log)
	observedCeiling atomic.Int64  // smallest in-flight level seen to block on CF MAX_STREAMS (0 = never)

	connMu  sync.Mutex
	closed  bool             // set by Close; blocks a racing in-flight dial from storing
	clients []*l4HTTP3Client // len == poolSize; nil slots are (re)built lazily
	next    atomic.Uint64    // round-robin cursor over pool slots
}

// errL4ProxyClosed is returned when a dial loses the race with Close.
var errL4ProxyClosed = errors.New("l4 proxy closed")

// errL4PoolSaturated is returned when every pooled connection is at the peer's
// MAX_STREAMS (OpenStreamSync blocked past streamOpenTimeout), so no new stream
// could be opened. It is distinct from an unreachable endpoint: the connections
// are alive, just busy, and recover as in-flight flows free their streams.
var errL4PoolSaturated = errors.New("l4 connection pool saturated (all shared QUIC connections at MAX_STREAMS)")

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
	if cfg.PoolSize <= 0 {
		cfg.PoolSize = defaultL4PoolSize
	}
	if cfg.MaxInFlightStreams <= 0 {
		cfg.MaxInFlightStreams = defaultL4MaxInFlightStreams
	}
	// Bound a single stream-open attempt so a saturated connection is detected fast,
	// and ensure the whole pool can be swept within one connect timeout under
	// saturation (poolSize * streamOpenTimeout <= connectTimeout), with a 1s floor so
	// a momentarily-busy healthy connection is not falsely skipped.
	streamOpenTimeout := defaultL4StreamOpenTimeout
	if perSlot := cfg.ConnectTimeout / time.Duration(cfg.PoolSize); perSlot > 0 && perSlot < streamOpenTimeout {
		streamOpenTimeout = perSlot
	}
	if streamOpenTimeout > cfg.ConnectTimeout {
		streamOpenTimeout = cfg.ConnectTimeout
	}
	if streamOpenTimeout < time.Second {
		streamOpenTimeout = time.Second
	}

	return &L4Proxy{
		tlsConfig:         cfg.TLSConfig,
		quicConfig:        cfg.QUICConfig,
		endpoint:          cfg.Endpoint,
		endpointSelector:  cfg.EndpointSelector,
		connectTimeout:    cfg.ConnectTimeout,
		connectRetryCount: cfg.ConnectRetryCount,
		streamOpenTimeout: streamOpenTimeout,
		poolSize:          cfg.PoolSize,
		maxInFlight:       int64(cfg.MaxInFlightStreams),
		clients:           make([]*l4HTTP3Client, cfg.PoolSize),
	}, nil
}

// Connect eagerly establishes (or validates) the first pooled QUIC connection. It
// is optional — DialContext establishes lazily — but lets callers fail fast / log a
// "ready" line at startup. Remaining pool slots are built lazily on demand.
func (p *L4Proxy) Connect(ctx context.Context) error {
	_, err := p.getOrCreateClientConnAt(ctx, 0)
	return err
}

// Close tears down every pooled QUIC connection. After Close, a dial that was
// in flight (blocked in quic.Dial) is prevented from storing its new connection
// into the pool (see getOrCreateClientConnAt), so nothing leaks past Close.
func (p *L4Proxy) Close() error {
	p.connMu.Lock()
	p.closed = true
	clients := make([]*l4HTTP3Client, len(p.clients))
	copy(clients, p.clients)
	for i := range p.clients {
		p.clients[i] = nil
	}
	p.connMu.Unlock()
	for _, client := range clients {
		if client != nil {
			closeL4HTTP3(client.udpConn, client.quicConn)
		}
	}
	return nil
}

// DialContext connects target (an "ip:port" authority) over an L4 MASQUE HTTP/3
// CONNECT stream and returns it as a net.Conn.
//
// Before doing any work it reserves an in-flight stream slot: if the proxy is
// already at MaxInFlightStreams it returns errL4PoolSaturated immediately, so a
// saturated shared connection sheds load fast (the client retries) instead of
// blocking on OpenStreamSync and letting inbound SOCKS connections accumulate into
// an OOM. The reservation is released here on any dial failure, or when the returned
// conn is closed (l4TCPConn.onClose). It also bounds how many dials may be blocked
// concurrently in OpenRequestStream, since each holds a slot until it returns.
func (p *L4Proxy) DialContext(ctx context.Context, target string) (net.Conn, error) {
	if p == nil || p.tlsConfig == nil {
		return nil, fmt.Errorf("missing TLS config")
	}
	if p.endpoint == nil {
		return nil, fmt.Errorf("missing HTTP/3 UDP endpoint")
	}

	reserved := false
	if p.maxInFlight > 0 {
		if p.inFlight.Add(1) > p.maxInFlight {
			p.inFlight.Add(-1)
			p.recordSaturation()
			return nil, errL4PoolSaturated
		}
		reserved = true
	}

	conn, err := p.dialSweep(ctx, target)
	if err != nil {
		// A saturated shared connection (Cloudflare's MAX_STREAMS reached, surfaced by
		// dialOnSlot as a bounded OpenRequestStream timeout) is counted here too, so the
		// rejection is visible whether the local cap or Cloudflare's ceiling is the
		// binding limit. Record before releasing so the logged in_flight reflects the
		// saturated level.
		if errors.Is(err, errL4PoolSaturated) {
			p.recordSaturation()
		}
		if reserved {
			p.inFlight.Add(-1)
		}
		return nil, err
	}
	if reserved {
		conn.onClose = func() { p.inFlight.Add(-1) }
	}
	return conn, nil
}

// dialSweep sweeps the connection pool (round-robin) within one connect timeout, so
// a saturated (MAX_STREAMS-reached) or transiently failing connection is skipped in
// favour of another pooled connection. With the default PoolSize of 1 it is a single
// attempt on the one shared connection.
func (p *L4Proxy) dialSweep(ctx context.Context, target string) (*l4TCPConn, error) {
	timeout := p.connectTimeout
	if timeout <= 0 {
		timeout = defaultL4ConnectTimeout
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	poolSize := p.poolSize // immutable; avoids a lockless read of the p.clients header
	if poolSize <= 0 {
		poolSize = 1
	}
	// Compute the modulo in uint64 so a wrapped counter never yields a negative
	// (panicking) slice index.
	start := int((p.next.Add(1) - 1) % uint64(poolSize))

	var lastErr error
	for i := 0; i < poolSize; i++ {
		if dialCtx.Err() != nil {
			break
		}
		slot := (start + i) % poolSize
		conn, err := p.dialOnSlot(dialCtx, slot, target)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		// A per-target rejection (valid non-2xx) is deterministic across the pool —
		// retrying other connections would just get the same status, so stop.
		var statusErr *l4StatusError
		if errors.As(err, &statusErr) {
			break
		}
	}

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("l4 dial to %s failed", target)
	}
	return nil, lastErr
}

// recordSaturation counts a fast-fail rejection and warns at most once every 5s so a
// sustained saturation storm cannot flood the log. A persistent stream of these is
// the operator's signal that one enrollment cannot carry the offered concurrency.
func (p *L4Proxy) recordSaturation() {
	n := p.saturations.Add(1)
	now := time.Now().UnixNano()
	last := p.lastSatLogNs.Load()
	if now-last > int64(5*time.Second) && p.lastSatLogNs.CompareAndSwap(last, now) {
		slog.Warn("l4 saturated: rejecting new flows fast (shared QUIC connection at MAX_STREAMS or local cap reached)",
			"in_flight", p.inFlight.Load(), "max_streams", p.maxInFlight, "observed_stream_ceiling", p.observedCeiling.Load(), "rejected_total", n)
	}
}

// noteCeiling records the smallest in-flight level at which the shared connection's
// OpenStreamSync blocked — an empirical estimate of Cloudflare's per-connection
// MAX_STREAMS. It is observational only (it does not change the cap): the value is
// logged once on first observation and surfaced via Stats, so an operator can compare
// the real ceiling against the configured cap and the offered concurrency, and decide
// whether one connection suffices or an overflow path (e.g. L3 spill) is needed.
func (p *L4Proxy) noteCeiling(n int64) {
	if n <= 0 {
		return
	}
	for {
		cur := p.observedCeiling.Load()
		if cur != 0 && cur <= n {
			return
		}
		if p.observedCeiling.CompareAndSwap(cur, n) {
			if cur == 0 {
				slog.Warn("l4 hit Cloudflare's per-connection stream ceiling (OpenStreamSync blocked) — this is the real MAX_STREAMS limit for a single connection",
					"observed_stream_ceiling", n, "configured_max_streams", p.maxInFlight)
			}
			return
		}
	}
}

// Stats reports the current open-stream count, the cumulative number of dials
// fast-failed at saturation, and the empirically observed Cloudflare per-connection
// stream ceiling (0 if never hit), for periodic observability.
func (p *L4Proxy) Stats() (inFlight int64, rejected uint64, observedCeiling int64) {
	return p.inFlight.Load(), p.saturations.Load(), p.observedCeiling.Load()
}

// l4StatusError is a per-target CONNECT rejection (valid non-2xx response). The
// shared connection is healthy; only this target was refused, so a dial must not
// tear the connection down or retry other pool slots.
type l4StatusError struct {
	target string
	status int
}

func (e *l4StatusError) Error() string {
	return fmt.Sprintf("CONNECT %s rejected with status %d", e.target, e.status)
}

// dialOnSlot opens one CONNECT stream on the given pool slot's connection.
func (p *L4Proxy) dialOnSlot(ctx context.Context, slot int, target string) (*l4TCPConn, error) {
	h3Client, err := p.getOrCreateClientConnAt(ctx, slot)
	if err != nil {
		return nil, err
	}

	// Bound the stream open so a saturated connection (peer MAX_STREAMS reached →
	// OpenStreamSync blocks) is detected quickly and the caller falls through to the
	// next pool slot, instead of stalling the whole connect timeout on one slot.
	openCtx, cancelOpen := context.WithTimeout(ctx, p.streamOpenTimeout)
	stream, err := h3Client.clientConn.OpenRequestStream(openCtx)
	cancelOpen()
	if err != nil {
		// A real (non-deadline) open error means the connection is likely stale; drop
		// this slot so it rebuilds.
		if shouldReconnectOnOpenStreamError(ctx, err) {
			p.clearSlotIfCurrent(slot, h3Client)
			return nil, err
		}
		// Our per-slot openCtx fired while the parent ctx is still live: the
		// connection is alive but saturated (MAX_STREAMS). Keep the slot and report
		// saturation distinctly so the sweep can try another slot and the caller
		// isn't told the endpoint is unreachable. Record the in-flight level at which
		// OpenStreamSync blocked as an empirical estimate of Cloudflare's per-connection
		// MAX_STREAMS, so an operator can see the real ceiling.
		if ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded) {
			p.noteCeiling(p.inFlight.Load())
			return nil, errL4PoolSaturated
		}
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+target, nil)
	if err != nil {
		closeL4Stream(stream)
		return nil, err
	}
	req.Host = target
	if err := stream.SendRequestHeader(req); err != nil {
		closeL4Stream(stream)
		p.dropConnIfDead(slot, h3Client)
		return nil, err
	}
	response, err := stream.ReadResponse()
	if err != nil {
		closeL4Stream(stream)
		p.dropConnIfDead(slot, h3Client)
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		// A valid non-2xx response means the connection is healthy and only this
		// target was rejected: close just the stream, never the connection.
		closeL4Stream(stream)
		return nil, &l4StatusError{target: target, status: response.StatusCode}
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

func (p *L4Proxy) getOrCreateClientConnAt(ctx context.Context, slot int) (*l4HTTP3Client, error) {
	p.connMu.Lock()
	if p.closed {
		p.connMu.Unlock()
		return nil, errL4ProxyClosed
	}
	if slot < 0 || slot >= len(p.clients) {
		p.connMu.Unlock()
		return nil, fmt.Errorf("l4 pool slot %d out of range", slot)
	}
	if client := p.clients[slot]; client != nil {
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
	if p.closed {
		// Close ran while we were dialing: do not store (it would leak past Close).
		p.connMu.Unlock()
		closeL4HTTP3(newClient.udpConn, newClient.quicConn)
		return nil, errL4ProxyClosed
	}
	if client := p.clients[slot]; client != nil {
		// Lost the race: another goroutine filled this slot first.
		p.connMu.Unlock()
		closeL4HTTP3(newClient.udpConn, newClient.quicConn)
		return client, nil
	}
	p.clients[slot] = newClient
	p.connMu.Unlock()
	slog.Debug("l4 proxy established pooled QUIC connection", "endpoint", endpoint.String(), "slot", slot)
	go p.watchClientConn(slot, newClient)

	return newClient, nil
}

// watchClientConn evicts a pooled connection from its slot as soon as its
// underlying QUIC connection dies — idle eviction by Cloudflare, a server close, or
// a path/keepalive failure detected by quic-go. Without this, a dead connection
// lingers in its slot: OpenRequestStream still succeeds locally, so the
// reconnect-on-open-error path never triggers, and every dial routed to that slot
// blocks until timeout. Proactively clearing the slot lets the next dial rebuild
// it. The goroutine exits when the connection is closed (Done fires) — including on
// Close() — so it does not leak.
func (p *L4Proxy) watchClientConn(slot int, client *l4HTTP3Client) {
	if client == nil || client.quicConn == nil {
		return
	}
	<-client.quicConn.Context().Done()
	slog.Debug("l4 proxy pooled QUIC connection closed; clearing slot",
		"slot", slot, "cause", context.Cause(client.quicConn.Context()))
	p.clearSlotIfCurrent(slot, client)
}

// dropConnIfDead clears a pooled slot when its connection has already died. Called
// on dial-time transport errors (SendRequestHeader / ReadResponse) so the first
// dial to observe a path failure frees the slot for rebuild instead of every dial
// independently blocking on the same dead connection. A per-target rejection (a
// valid non-2xx response) never reaches here, so a single bad target never tears
// down a connection shared by other live flows.
func (p *L4Proxy) dropConnIfDead(slot int, client *l4HTTP3Client) {
	if client != nil && client.quicConn != nil && client.quicConn.Context().Err() != nil {
		p.clearSlotIfCurrent(slot, client)
	}
}

// clearSlotIfCurrent drops a pooled connection only if the slot still holds the
// one the caller observed, so a concurrent dial that already rebuilt the slot is
// not torn down.
func (p *L4Proxy) clearSlotIfCurrent(slot int, expected *l4HTTP3Client) {
	if expected == nil {
		return
	}

	p.connMu.Lock()
	if slot < 0 || slot >= len(p.clients) || p.clients[slot] != expected {
		p.connMu.Unlock()
		return
	}
	p.clients[slot] = nil
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
	stream  l4Stream
	local   net.Addr
	remote  net.Addr
	once    sync.Once
	onClose func() // releases the proxy's in-flight reservation; runs once on Close
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
		if c.onClose != nil {
			c.onClose()
		}
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
