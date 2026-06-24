package api

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// fakeL4Stream implements l4Stream and records the half-close calls.
type fakeL4Stream struct {
	closed       bool
	readCanceled bool
	cancelCode   quic.StreamErrorCode
}

func (f *fakeL4Stream) Read(p []byte) (int, error)  { return 0, nil }
func (f *fakeL4Stream) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakeL4Stream) Close() error {
	f.closed = true
	return nil
}
func (f *fakeL4Stream) CancelRead(code quic.StreamErrorCode) {
	f.readCanceled = true
	f.cancelCode = code
}
func (f *fakeL4Stream) SetDeadline(t time.Time) error      { return nil }
func (f *fakeL4Stream) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakeL4Stream) SetWriteDeadline(t time.Time) error { return nil }

func TestL4TCPConnHalfClose(t *testing.T) {
	stream := &fakeL4Stream{}
	conn := &l4TCPConn{stream: stream, remote: l4Addr("1.2.3.4:443")}

	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if !stream.closed {
		t.Fatal("CloseWrite should close (end) the send side of the stream")
	}

	if err := conn.CloseRead(); err != nil {
		t.Fatalf("CloseRead: %v", err)
	}
	if !stream.readCanceled {
		t.Fatal("CloseRead should cancel the read side of the stream")
	}
}

func TestL4TCPConnCloseIsIdempotent(t *testing.T) {
	stream := &fakeL4Stream{}
	conn := &l4TCPConn{stream: stream, remote: l4Addr("1.2.3.4:443")}

	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !stream.closed || !stream.readCanceled {
		t.Fatal("Close should both end the send side and cancel the read side")
	}

	// A second Close must not panic and must remain a no-op.
	stream.closed = false
	stream.readCanceled = false
	if err := conn.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if stream.closed || stream.readCanceled {
		t.Fatal("Close must run exactly once")
	}
}

// TestL4TCPConnOnCloseReleasesOnce verifies the in-flight gauge is released exactly
// once even when several teardown paths (relay end + drain) both close the conn, so
// the live-stream counter cannot be double-decremented below zero.
func TestL4TCPConnOnCloseReleasesOnce(t *testing.T) {
	released := 0
	c := &l4TCPConn{onClose: func() { released++ }}

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if released != 1 {
		t.Fatalf("onClose ran %d times, want exactly 1", released)
	}
}

func TestCloseL4StreamResetsBothDirections(t *testing.T) {
	// dial-time error paths must reclaim BOTH halves of the request stream:
	// http3.RequestStream.Close() only ends the send side, so without an explicit
	// CancelRead a rejected CONNECT leaks a half-open stream on the shared QUIC
	// connection.
	stream := &fakeL4Stream{}
	closeL4Stream(stream)
	if !stream.closed {
		t.Fatal("closeL4Stream must end the send side (Close)")
	}
	if !stream.readCanceled {
		t.Fatal("closeL4Stream must cancel the receive side (CancelRead)")
	}

	// Nil-safe.
	closeL4Stream(nil)
}

func TestL4TCPConnNilStream(t *testing.T) {
	conn := &l4TCPConn{}
	if _, err := conn.Read(make([]byte, 4)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read on nil stream: want net.ErrClosed, got %v", err)
	}
	if _, err := conn.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write on nil stream: want net.ErrClosed, got %v", err)
	}
	// LocalAddr falls back to a placeholder when the stream/conn is unset.
	if conn.LocalAddr() == nil {
		t.Fatal("LocalAddr should never be nil")
	}
}

func TestNewL4ProxyValidation(t *testing.T) {
	if _, err := NewL4Proxy(L4ProxyConfig{}); err == nil {
		t.Fatal("expected error when TLS config is missing")
	}
	if _, err := NewL4Proxy(L4ProxyConfig{TLSConfig: &tls.Config{}}); err == nil {
		t.Fatal("expected error when endpoint is missing")
	}

	p, err := NewL4Proxy(L4ProxyConfig{
		TLSConfig: &tls.Config{},
		Endpoint:  &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 443},
	})
	if err != nil {
		t.Fatalf("NewL4Proxy: %v", err)
	}
	// Default connect timeout applied for non-positive value.
	if p.connectTimeout != defaultL4ConnectTimeout {
		t.Fatalf("connectTimeout = %v, want default %v", p.connectTimeout, defaultL4ConnectTimeout)
	}
	// streamOpenTimeout defaults to 5s and is clamped to the (smaller) connect timeout.
	if p.streamOpenTimeout != defaultL4StreamOpenTimeout {
		t.Fatalf("streamOpenTimeout = %v, want %v", p.streamOpenTimeout, defaultL4StreamOpenTimeout)
	}
	p2, err := NewL4Proxy(L4ProxyConfig{
		TLSConfig:      &tls.Config{},
		Endpoint:       &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 443},
		ConnectTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewL4Proxy: %v", err)
	}
	if p2.streamOpenTimeout != 2*time.Second {
		t.Fatalf("streamOpenTimeout = %v, want clamped to 2s", p2.streamOpenTimeout)
	}
}

func TestL4ProxySelectEndpoint(t *testing.T) {
	fallback := &net.UDPAddr{IP: net.IPv4(2, 2, 2, 2), Port: 443}
	p := &L4Proxy{endpoint: fallback}

	// No selector -> fallback.
	if got := p.selectEndpoint(); got != fallback {
		t.Fatalf("no selector: got %v, want fallback", got)
	}

	// Selector returning a UDP addr -> that addr.
	chosen := &net.UDPAddr{IP: net.IPv4(3, 3, 3, 3), Port: 443}
	p.endpointSelector = func() net.Addr { return chosen }
	if got := p.selectEndpoint(); got != chosen {
		t.Fatalf("udp selector: got %v, want chosen", got)
	}

	// Selector returning nil -> fallback.
	p.endpointSelector = func() net.Addr { return nil }
	if got := p.selectEndpoint(); got != fallback {
		t.Fatalf("nil selector: got %v, want fallback", got)
	}

	// Selector returning a non-UDP addr -> fallback (defensive).
	p.endpointSelector = func() net.Addr { return &net.TCPAddr{IP: net.IPv4(4, 4, 4, 4), Port: 443} }
	if got := p.selectEndpoint(); got != fallback {
		t.Fatalf("tcp selector: got %v, want fallback", got)
	}
}

func TestListenUDPForEndpoint(t *testing.T) {
	// The exact family of a wildcard local bind is OS-dependent; assert only that
	// each endpoint family yields a usable UDP socket.
	v4, err := listenUDPForEndpoint(&net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 443})
	if err != nil {
		t.Fatalf("listen v4: %v", err)
	}
	if _, ok := v4.LocalAddr().(*net.UDPAddr); !ok {
		t.Fatalf("v4 local addr is not a *net.UDPAddr: %T", v4.LocalAddr())
	}
	_ = v4.Close()

	v6, err := listenUDPForEndpoint(&net.UDPAddr{IP: net.ParseIP("2606:4700::1111"), Port: 443})
	if err != nil {
		t.Fatalf("listen v6: %v", err)
	}
	if _, ok := v6.LocalAddr().(*net.UDPAddr); !ok {
		t.Fatalf("v6 local addr is not a *net.UDPAddr: %T", v6.LocalAddr())
	}
	_ = v6.Close()
}

func TestL4Addr(t *testing.T) {
	a := l4Addr("9.9.9.9:443")
	if a.Network() != "masque-l4-tcp" {
		t.Fatalf("Network() = %q", a.Network())
	}
	if a.String() != "9.9.9.9:443" {
		t.Fatalf("String() = %q", a.String())
	}
}

func TestL4ProxyCloseIsSafe(t *testing.T) {
	p, err := NewL4Proxy(L4ProxyConfig{
		TLSConfig: &tls.Config{},
		Endpoint:  &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 443},
	})
	if err != nil {
		t.Fatalf("NewL4Proxy: %v", err)
	}
	// Close with no established connection must be a no-op, not a panic.
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestL4ProxyClosedRejectsDial(t *testing.T) {
	p, err := NewL4Proxy(L4ProxyConfig{
		TLSConfig: &tls.Config{},
		Endpoint:  &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 443},
	})
	if err != nil {
		t.Fatalf("NewL4Proxy: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// After Close, building a connection must fail fast with errL4ProxyClosed rather
	// than dialing and storing (which would leak past Close).
	if _, err := p.dialConn(context.Background()); !errors.Is(err, errL4ProxyClosed) {
		t.Fatalf("dialConn after Close = %v, want errL4ProxyClosed", err)
	}
}

func TestL4StatusError(t *testing.T) {
	err := error(&l4StatusError{target: "1.1.1.1:443", status: 502})
	var se *l4StatusError
	if !errors.As(err, &se) {
		t.Fatal("errors.As should match *l4StatusError")
	}
	if se.status != 502 {
		t.Fatalf("status = %d, want 502", se.status)
	}
	if !strings.Contains(err.Error(), "502") || !strings.Contains(err.Error(), "1.1.1.1:443") {
		t.Fatalf("unexpected error string: %q", err.Error())
	}
}

// TestL4ProxyCloseConnRebuildsOnce verifies closeConn is the rebuild primitive: it
// clears the cached connection (so the next dial rebuilds) and bumps the reconnect
// counter, but only when the stale connection it was handed still matches the cache —
// a connection already rebuilt by another goroutine must not be torn down.
func TestL4ProxyCloseConnRebuildsOnce(t *testing.T) {
	p, err := NewL4Proxy(L4ProxyConfig{
		TLSConfig: &tls.Config{},
		Endpoint:  &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 443},
	})
	if err != nil {
		t.Fatalf("NewL4Proxy: %v", err)
	}

	// No cached connection: closeConn is a no-op and must not bump the counter.
	p.closeConn(nil)
	if _, rc := p.Stats(); rc != 0 {
		t.Fatalf("reconnects = %d after no-op closeConn, want 0", rc)
	}

	// Install a fake cached connection (nil conns: closeL4HTTP3 is nil-safe).
	cc := &http3.ClientConn{}
	p.mu.Lock()
	p.clientConn = cc
	p.mu.Unlock()

	// A stale connection that does not match the cache must not clear it.
	other := &http3.ClientConn{}
	p.closeConn(other)
	p.mu.Lock()
	stillCached := p.clientConn == cc
	p.mu.Unlock()
	if !stillCached {
		t.Fatal("closeConn must not tear down a connection that differs from the stale arg")
	}
	if _, rc := p.Stats(); rc != 0 {
		t.Fatalf("reconnects = %d after mismatched closeConn, want 0", rc)
	}

	// Matching stale (and the nil "whatever is current" form) tears it down and rebuilds.
	p.closeConn(cc)
	p.mu.Lock()
	cleared := p.clientConn == nil
	p.mu.Unlock()
	if !cleared {
		t.Fatal("closeConn must clear the cached connection so the next dial rebuilds")
	}
	if _, rc := p.Stats(); rc != 1 {
		t.Fatalf("reconnects = %d after teardown, want 1", rc)
	}
}

func newTestL4Proxy(t *testing.T) *L4Proxy {
	t.Helper()
	p, err := NewL4Proxy(L4ProxyConfig{
		TLSConfig: &tls.Config{},
		Endpoint:  &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 443},
	})
	if err != nil {
		t.Fatalf("NewL4Proxy: %v", err)
	}
	return p
}

// TestL4ProxyRebuildsOnConsecutiveConnFailures proves the wedge detector: a run of
// CONNECT-handshake failures with no intervening Cloudflare answer rebuilds the shared
// connection (the case OpenRequestStream-failure recovery misses), and the run resets
// after the rebuild.
func TestL4ProxyRebuildsOnConsecutiveConnFailures(t *testing.T) {
	p := newTestL4Proxy(t)
	cc := &http3.ClientConn{} // nil conns: closeL4HTTP3 is nil-safe
	p.mu.Lock()
	p.clientConn = cc
	p.mu.Unlock()
	ctx := context.Background()

	// Just under the threshold: no rebuild yet, connection still cached. The loop runs in
	// microseconds, far under 2×connectTimeout, so the elapsed-time trip cannot fire here —
	// this isolates the count trip.
	for i := 0; i < int(p.maxConsecutiveFails)-1; i++ {
		p.noteConnFailure(cc, ctx)
	}
	if _, rc := p.Stats(); rc != 0 {
		t.Fatalf("reconnects = %d below threshold, want 0", rc)
	}
	p.mu.Lock()
	stillCached := p.clientConn == cc
	p.mu.Unlock()
	if !stillCached {
		t.Fatal("connection must survive a sub-threshold failure run")
	}

	// One more crosses the threshold → rebuild, and the run resets.
	p.noteConnFailure(cc, ctx)
	if _, rc := p.Stats(); rc != 1 {
		t.Fatalf("reconnects = %d at threshold, want 1", rc)
	}
	p.mu.Lock()
	cleared := p.clientConn == nil
	p.mu.Unlock()
	if !cleared {
		t.Fatal("wedge rebuild must clear the cached connection")
	}
	if p.consecutiveFails.Load() != 0 {
		t.Fatalf("consecutiveFails = %d after rebuild, want 0 (reset)", p.consecutiveFails.Load())
	}
	if p.firstFailNanos.Load() != 0 {
		t.Fatalf("firstFailNanos = %d after rebuild, want 0 (run reset)", p.firstFailNanos.Load())
	}
}

// TestL4ProxyRebuildsOnWedgeElapsed proves the elapsed-time wedge trip: under low concurrency
// the count threshold alone would need ~maxConsecutiveFails serial connect-timeout windows to
// fire (minutes to ~an hour of 假死), so a no-answer run older than 2×connectTimeout rebuilds
// well before the count is reached.
func TestL4ProxyRebuildsOnWedgeElapsed(t *testing.T) {
	p := newTestL4Proxy(t)
	cc := &http3.ClientConn{}
	p.mu.Lock()
	p.clientConn = cc
	p.mu.Unlock()
	ctx := context.Background()

	// First failure starts the run (stamps firstFailNanos); far below the count threshold.
	p.noteConnFailure(cc, ctx)
	if _, rc := p.Stats(); rc != 0 {
		t.Fatalf("reconnects = %d after one failure, want 0", rc)
	}
	// Back-date the run to older than 2×connectTimeout so the next failure trips on elapsed
	// time, not count.
	p.firstFailNanos.Store(time.Now().Add(-2*p.connectTimeout - time.Second).UnixNano())

	p.noteConnFailure(cc, ctx)
	if got := p.consecutiveFails.Load(); got >= p.maxConsecutiveFails {
		t.Fatalf("elapsed trip should fire BELOW the count threshold; consecutiveFails=%d threshold=%d", got, p.maxConsecutiveFails)
	}
	if _, rc := p.Stats(); rc != 1 {
		t.Fatalf("reconnects = %d, want 1 (elapsed-time wedge trip)", rc)
	}
	p.mu.Lock()
	cleared := p.clientConn == nil
	p.mu.Unlock()
	if !cleared {
		t.Fatal("elapsed wedge trip must clear the cached connection")
	}
	if p.consecutiveFails.Load() != 0 || p.firstFailNanos.Load() != 0 {
		t.Fatalf("run not reset after rebuild: consecutiveFails=%d firstFailNanos=%d", p.consecutiveFails.Load(), p.firstFailNanos.Load())
	}
}

// TestL4ProxyConnFailureIgnoresStaleAndCancelled verifies the two guards: a failure on an
// already-replaced connection must not count (it would otherwise prematurely tear down the
// fresh connection), and a caller-cancelled dial must not count (the client gave up — the
// connection is not at fault).
func TestL4ProxyConnFailureIgnoresStaleAndCancelled(t *testing.T) {
	p := newTestL4Proxy(t)
	cc := &http3.ClientConn{}
	p.mu.Lock()
	p.clientConn = cc
	p.mu.Unlock()

	// Failures attributed to a DIFFERENT (already-replaced) connection are ignored.
	stale := &http3.ClientConn{}
	for i := 0; i < int(p.maxConsecutiveFails)*2; i++ {
		p.noteConnFailure(stale, context.Background())
	}
	if got := p.consecutiveFails.Load(); got != 0 {
		t.Fatalf("stale-connection failures counted (%d); they must be ignored", got)
	}
	if _, rc := p.Stats(); rc != 0 {
		t.Fatalf("stale-connection failures rebuilt (reconnects=%d); they must not", rc)
	}

	// Caller-cancelled dials are ignored.
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < int(p.maxConsecutiveFails)*2; i++ {
		p.noteConnFailure(cc, cancelledCtx)
	}
	if got := p.consecutiveFails.Load(); got != 0 {
		t.Fatalf("caller-cancelled dials counted (%d); they must be ignored", got)
	}
	if _, rc := p.Stats(); rc != 0 {
		t.Fatalf("caller-cancelled dials rebuilt (reconnects=%d); they must not", rc)
	}
}
