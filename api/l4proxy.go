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
// extended-CONNECT request stream over a SINGLE shared QUIC connection to
// Cloudflare's MASQUE proxy endpoint. Unlike the connect-ip (L3) path, it never
// runs a userspace TCP/IP stack: a client TCP flow maps 1:1 onto a QUIC stream,
// so congestion- and flow-control are handled natively by QUIC instead of
// gVisor's netstack. This is faster and lighter but TCP-only — there is no
// datagram/UDP path here.
//
// The connection model follows mihomo's validated MASQUE l4proxy
// (github.com/MetaCubeX/mihomo transport/masque/l4proxy.go): the *http3.ClientConn
// is cached and reused for every flow, and is rebuilt ONLY when OpenRequestStream
// fails — which covers a dead connection (Cloudflare idle eviction / path failure)
// and a saturated one (peer MAX_STREAMS reached → OpenStreamSync blocks). Rebuilding
// on demand is the single recovery mechanism; there is deliberately no connection
// pool, no in-flight stream cap, and no proactive health goroutine. Those were
// uscf-specific additions that fragmented the egress IP or, worse, fast-failed dials
// before OpenRequestStream and so prevented the rebuild from ever happening — locking
// the proxy at the cap until a manual restart. Keeping a single connection rebuilt
// lazily is both simpler and the same stable, single egress identity as L3.

const (
	defaultL4ConnectTimeout = 15 * time.Second
	// defaultL4StreamOpenTimeout bounds a single OpenRequestStream attempt so a
	// saturated connection (peer MAX_STREAMS reached → OpenStreamSync blocks) is
	// detected quickly and the connection is rebuilt, instead of the dial hanging for
	// the full connect timeout and inbound flows piling up. It is clamped to the
	// connect timeout with a 1s floor.
	defaultL4StreamOpenTimeout = 5 * time.Second
	// defaultL4MaxConsecutiveConnFailures is the default count threshold for how many
	// CONNECT handshakes may fail in a row — with no Cloudflare response in between —
	// before the shared connection is declared wedged and rebuilt (see noteConnFailure).
	// Configurable via L4ProxyConfig.MaxConsecutiveConnFailures (socks.l4_max_conn_failures)
	// for tuning/experimentation. High enough that a transient blip or an occasional slow/
	// blackholed target (interspersed with successes that reset the run) never trips it.
	// The count alone only recovers promptly under high concurrency (many dials fail inside
	// one connect-timeout window); the elapsed-time trip below bounds recovery under low
	// concurrency, where reaching the count would otherwise take many serial windows.
	defaultL4MaxConsecutiveConnFailures = 50
)

// L4ProxyConfig configures a new L4Proxy.
type L4ProxyConfig struct {
	TLSConfig  *tls.Config
	QUICConfig *quic.Config
	// Endpoint is the fallback HTTP/3 UDP endpoint used when EndpointSelector is
	// nil or returns nothing.
	Endpoint *net.UDPAddr
	// EndpointSelector, when set, is consulted on every (re)connect so the proxy can
	// rotate across a custom endpoint pool, mirroring the L3 tunnel's EndpointSelector.
	// It must return a *net.UDPAddr; anything else is ignored in favour of Endpoint.
	EndpointSelector func() net.Addr
	// ConnectTimeout bounds establishing the shared QUIC connection (and clamps the
	// per-dial stream-open attempt).
	ConnectTimeout time.Duration
	// MaxConsecutiveConnFailures is the count threshold for the wedge detector (see
	// noteConnFailure). <=0 falls back to defaultL4MaxConsecutiveConnFailures.
	MaxConsecutiveConnFailures int
}

// L4Proxy opens one HTTP/3 CONNECT stream per proxied TCP connection over a single
// shared QUIC connection that is cached, reused, and rebuilt on demand. See the
// package-level comment for the rationale (mihomo's model). The zero egress-IP churn
// of one connection matches the L3 tunnel; the cost is that a connection rebuild
// (rare: only on death or MAX_STREAMS saturation) resets the streams it carried.
type L4Proxy struct {
	tlsConfig         *tls.Config
	quicConfig        *quic.Config
	endpoint          *net.UDPAddr
	endpointSelector  func() net.Addr
	connectTimeout    time.Duration
	streamOpenTimeout time.Duration

	// maxConsecutiveFails is the count threshold for the wedge detector (noteConnFailure).
	maxConsecutiveFails int64

	// dialSem is a context-aware single-flight (capacity 1) so concurrent dials that
	// find no cached connection do not each dial a redundant one — the first builds it,
	// the rest reuse the result. Mirrors mihomo's semaphore.Weighted(1) around dial/close.
	dialSem chan struct{}

	mu          sync.Mutex
	closed      bool
	udpConn     *net.UDPConn
	quicConn    *quic.Conn
	clientConn  *http3.ClientConn
	cachedLocal net.Addr // local addr of the current connection's UDP socket (for SOCKS replies)

	inFlight         atomic.Int64  // currently open CONNECT streams (observability only — not a cap)
	reconnects       atomic.Uint64 // cumulative shared-connection rebuilds (self-heal counter)
	consecutiveFails atomic.Int64  // CONNECT handshakes failed in a row with no CF answer; rebuilds when it crosses maxConsecutiveFails
	firstFailNanos   atomic.Int64  // unix-ns of the first un-answered failure in the current run; 0 = no run (drives the elapsed-time wedge trip)
}

// errL4ProxyClosed is returned when a dial loses the race with Close.
var errL4ProxyClosed = errors.New("l4 proxy closed")

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
	streamOpenTimeout := defaultL4StreamOpenTimeout
	if streamOpenTimeout > cfg.ConnectTimeout {
		streamOpenTimeout = cfg.ConnectTimeout
	}
	if streamOpenTimeout < time.Second {
		streamOpenTimeout = time.Second
	}
	maxConsecutiveFails := cfg.MaxConsecutiveConnFailures
	if maxConsecutiveFails <= 0 {
		maxConsecutiveFails = defaultL4MaxConsecutiveConnFailures
	}

	return &L4Proxy{
		tlsConfig:           cfg.TLSConfig,
		quicConfig:          cfg.QUICConfig,
		endpoint:            cfg.Endpoint,
		endpointSelector:    cfg.EndpointSelector,
		connectTimeout:      cfg.ConnectTimeout,
		streamOpenTimeout:   streamOpenTimeout,
		maxConsecutiveFails: int64(maxConsecutiveFails),
		dialSem:             make(chan struct{}, 1),
	}, nil
}

// Connect eagerly establishes (or validates) the shared QUIC connection. It is
// optional — DialContext establishes lazily — but lets callers fail fast / log a
// "ready" line at startup.
func (p *L4Proxy) Connect(ctx context.Context) error {
	_, err := p.dialConn(ctx)
	return err
}

// Close tears down the shared QUIC connection. After Close, a dial that was in flight
// (blocked in quic.Dial) is prevented from storing its new connection.
func (p *L4Proxy) Close() error {
	p.mu.Lock()
	p.closed = true
	udpConn, quicConn := p.udpConn, p.quicConn
	p.udpConn, p.quicConn, p.clientConn, p.cachedLocal = nil, nil, nil, nil
	p.mu.Unlock()
	closeL4HTTP3(udpConn, quicConn)
	return nil
}

// dialConn returns the cached *http3.ClientConn, building it on first use or after a
// closeConn teardown. Concurrent callers that find no cached connection serialize on
// dialSem so only one connection is dialed; the rest reuse it. Mirrors mihomo's dialConn.
func (p *L4Proxy) dialConn(ctx context.Context) (*http3.ClientConn, error) {
	// Fast path: a cached connection already exists.
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, errL4ProxyClosed
	}
	if cc := p.clientConn; cc != nil {
		p.mu.Unlock()
		return cc, nil
	}
	p.mu.Unlock()

	// Single-flight the build (context-aware so a caller can still cancel while waiting).
	select {
	case p.dialSem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-p.dialSem }()

	// Re-check: another goroutine may have built it while we waited on dialSem.
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, errL4ProxyClosed
	}
	if cc := p.clientConn; cc != nil {
		p.mu.Unlock()
		return cc, nil
	}
	p.mu.Unlock()

	endpoint := p.selectEndpoint()
	dialCtx, cancel := context.WithTimeout(ctx, p.connectTimeout)
	defer cancel()

	udpConn, err := listenUDPForEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	quicConn, err := quic.Dial(dialCtx, udpConn, endpoint, p.tlsConfig, p.quicConfig)
	if err != nil {
		_ = udpConn.Close()
		return nil, err
	}
	clientConn := (&http3.Transport{}).NewClientConn(quicConn)

	p.mu.Lock()
	if p.closed {
		// Close ran while we were dialing: do not store (it would leak past Close).
		p.mu.Unlock()
		closeL4HTTP3(udpConn, quicConn)
		return nil, errL4ProxyClosed
	}
	p.udpConn, p.quicConn, p.clientConn = udpConn, quicConn, clientConn
	p.cachedLocal = udpConn.LocalAddr()
	p.mu.Unlock()

	slog.Debug("l4 established shared QUIC connection", "endpoint", endpoint.String())
	return clientConn, nil
}

// closeConn tears down the cached connection IF it is still the one the caller observed
// (so a connection already rebuilt by another goroutine is not torn down), making the
// next dial rebuild. This is the recovery primitive, invoked when OpenRequestStream
// fails. Mirrors mihomo's closeConn.
func (p *L4Proxy) closeConn(stale *http3.ClientConn) {
	p.mu.Lock()
	if p.clientConn == nil || (stale != nil && p.clientConn != stale) {
		p.mu.Unlock()
		return
	}
	udpConn, quicConn := p.udpConn, p.quicConn
	p.udpConn, p.quicConn, p.clientConn, p.cachedLocal = nil, nil, nil, nil
	p.mu.Unlock()

	p.consecutiveFails.Store(0)
	p.firstFailNanos.Store(0)
	p.reconnects.Add(1)
	slog.Debug("l4 tearing down shared QUIC connection; next dial rebuilds")
	closeL4HTTP3(udpConn, quicConn)
}

// noteConnFailure records a CONNECT-handshake failure on the shared connection: a stream
// opened, but Cloudflare delivered no response. A wedged connection stays alive at the
// QUIC layer (keepalive still flows, so OpenRequestStream keeps succeeding and quic-go
// never reports it dead) yet answers nothing — so the rebuild-on-OpenRequestStream-failure
// path never fires and every dial hangs to its deadline. When enough handshakes fail in a
// row with no answer in between, the connection is wedged: tear it down so the next dial
// rebuilds. A single 2xx OR per-target rejection resets the run, so an occasional slow or
// blackholed target among healthy traffic never trips it. Ignored when the caller gave up
// (its ctx was cancelled) or when the failure is on an already-replaced connection.
//
// Two trips, whichever fires first:
//   - count: maxConsecutiveFails failures in a row. This catches a wedge fast under high
//     concurrency, where many dials fail within a single connect-timeout window.
//   - elapsed time: a run of un-answered failures older than 2×connectTimeout. Under low
//     concurrency (1-2 flows) the count alone would need ~maxConsecutiveFails serial
//     connect-timeout windows to trip — minutes to nearly an hour of 假死 — so the timer
//     bounds recovery to ~one window regardless of how few flows drive it.
func (p *L4Proxy) noteConnFailure(clientConn *http3.ClientConn, ctx context.Context) {
	if errors.Is(ctx.Err(), context.Canceled) {
		return
	}
	p.mu.Lock()
	current := p.clientConn == clientConn
	p.mu.Unlock()
	if !current {
		return
	}
	n := p.consecutiveFails.Add(1)
	if n == 1 {
		p.firstFailNanos.Store(time.Now().UnixNano())
	}
	first := p.firstFailNanos.Load()
	wedgedFor := time.Duration(0)
	if first != 0 {
		wedgedFor = time.Since(time.Unix(0, first))
	}
	wedgedTooLong := first != 0 && wedgedFor >= 2*p.connectTimeout
	if n >= p.maxConsecutiveFails || wedgedTooLong {
		slog.Warn("l4 shared connection stopped answering CONNECTs (wedged); forcing a rebuild",
			"consecutive_failures", n, "wedged_for", wedgedFor.Round(time.Second), "trip", tripReason(n >= p.maxConsecutiveFails))
		p.closeConn(clientConn)
	}
}

// tripReason labels which wedge trip fired, for the rebuild log line.
func tripReason(byCount bool) string {
	if byCount {
		return "count"
	}
	return "elapsed"
}

// localAddr returns the cached connection's local UDP address (for SOCKS bound-address
// replies), or nil if there is no current connection.
func (p *L4Proxy) localAddr() net.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cachedLocal
}

// Stats reports the current open-stream count and the cumulative number of shared-
// connection rebuilds (a climbing rebuild count under steady load means the connection
// keeps dying or saturating), for periodic observability.
func (p *L4Proxy) Stats() (inFlight int64, reconnects uint64) {
	return p.inFlight.Load(), p.reconnects.Load()
}

// ConsecutiveFails reports the current run of un-answered CONNECT failures on the shared
// connection (a wedge in progress). It climbs toward MaxConsecutiveFails and resets to 0 on
// any Cloudflare answer or a rebuild, so a non-zero value at observation time means the
// connection is degrading — surfaced by logL4Stats so a wedge is visible before the rebuild.
func (p *L4Proxy) ConsecutiveFails() int64 { return p.consecutiveFails.Load() }

// MaxConsecutiveFails returns the configured count threshold at which a wedge run forces a
// rebuild (socks.l4_max_conn_failures), for sizing the degradation-warning threshold.
func (p *L4Proxy) MaxConsecutiveFails() int64 { return p.maxConsecutiveFails }

// DialContext connects target (an "ip:port" authority) over an L4 MASQUE HTTP/3
// CONNECT stream and returns it as a net.Conn. It follows mihomo's sequence: reuse the
// cached connection, open a request stream, and rebuild the connection if the stream
// could not be opened.
func (p *L4Proxy) DialContext(ctx context.Context, target string) (net.Conn, error) {
	if p == nil || p.tlsConfig == nil {
		return nil, fmt.Errorf("missing TLS config")
	}
	if p.endpoint == nil {
		return nil, fmt.Errorf("missing HTTP/3 UDP endpoint")
	}

	clientConn, err := p.dialConn(ctx)
	if err != nil {
		return nil, err
	}

	// Bound the stream open so a dead or saturated connection is detected quickly.
	openCtx, cancelOpen := context.WithTimeout(ctx, p.streamOpenTimeout)
	stream, err := clientConn.OpenRequestStream(openCtx)
	cancelOpen()
	if err != nil {
		// The recovery primitive: if we could not open a stream, the shared connection
		// is dead or at the peer's MAX_STREAMS. Tear it down so the next dial rebuilds.
		// Skip the teardown ONLY when the CALLER cancelled (its own ctx is done): the
		// connection is fine, the client just gave up, so do not punish other flows. A
		// deadline-expired dial still rebuilds (mihomo always rebuilds on this failure)
		// — using the same predicate as noteConnFailure so the two self-heal gates agree.
		if !errors.Is(ctx.Err(), context.Canceled) {
			p.closeConn(clientConn)
		}
		return nil, err
	}

	// Bound the CONNECT handshake explicitly. On a wedged connection (Cloudflare still
	// terminates QUIC and grants streams, so OpenRequestStream succeeds, but no longer
	// answers CONNECTs) ReadResponse would otherwise hang until the caller's deadline —
	// or forever if it set none. noteConnFailure turns a run of these into a rebuild.
	handshakeDeadline, ok := ctx.Deadline()
	if !ok {
		handshakeDeadline = time.Now().Add(p.connectTimeout)
	}
	_ = stream.SetDeadline(handshakeDeadline)

	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+target, nil)
	if err != nil {
		closeL4Stream(stream)
		return nil, err
	}
	req.Host = target
	if err := stream.SendRequestHeader(req); err != nil {
		closeL4Stream(stream)
		p.noteConnFailure(clientConn, ctx)
		return nil, err
	}
	response, err := stream.ReadResponse()
	if err != nil {
		closeL4Stream(stream)
		p.noteConnFailure(clientConn, ctx)
		return nil, err
	}
	// Cloudflare answered — a 2xx or a per-target rejection alike proves the shared
	// connection is servicing requests, so clear the wedge run and the handshake deadline
	// (the relay re-arms its own deadlines from here on).
	p.consecutiveFails.Store(0)
	p.firstFailNanos.Store(0)
	_ = stream.SetDeadline(time.Time{})
	if response.StatusCode < 200 || response.StatusCode > 299 {
		// A valid non-2xx means the connection is healthy and only this target was
		// rejected: close just the stream, never the connection.
		closeL4Stream(stream)
		return nil, &l4StatusError{target: target, status: response.StatusCode}
	}

	p.inFlight.Add(1)
	conn := &l4TCPConn{stream: stream, local: p.localAddr(), remote: l4Addr(target)}
	conn.onClose = func() { p.inFlight.Add(-1) }
	return conn, nil
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

// l4StatusError is a per-target CONNECT rejection (valid non-2xx response). The shared
// connection is healthy; only this target was refused, so a dial must not tear the
// connection down.
type l4StatusError struct {
	target string
	status int
}

func (e *l4StatusError) Error() string {
	return fmt.Sprintf("CONNECT %s rejected with status %d", e.target, e.status)
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

// closeL4Stream fully reclaims a dial-time request stream by ending the send side AND
// cancelling the receive side. http3.RequestStream.Close only closes the send
// direction, so without the CancelRead the bidirectional QUIC stream is never released
// on the shared connection — every rejected or failed CONNECT would otherwise leak a
// half-open stream (and its flow-control credit) until the whole connection is rebuilt.
// Mirrors l4TCPConn.Close. It does NOT touch the shared connection: a per-target
// rejection (e.g. 502) must not kill the connection shared by all other live flows.
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
	onClose func() // releases the proxy's in-flight gauge; runs once on Close
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
