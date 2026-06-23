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

func TestShouldReconnectOnOpenStreamError(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	cases := []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		{"nil error", context.Background(), nil, false},
		{"context canceled error", context.Background(), context.Canceled, false},
		{"deadline exceeded error", context.Background(), context.DeadlineExceeded, false},
		{"cancelled ctx", cancelled, errors.New("stream open failed"), false},
		{"generic error", context.Background(), errors.New("PROTOCOL_VIOLATION"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldReconnectOnOpenStreamError(tc.ctx, tc.err); got != tc.want {
				t.Fatalf("shouldReconnectOnOpenStreamError = %v, want %v", got, tc.want)
			}
		})
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
	// Defaults are applied for non-positive timeout / retry count.
	if p.connectTimeout != defaultL4ConnectTimeout {
		t.Fatalf("connectTimeout = %v, want default %v", p.connectTimeout, defaultL4ConnectTimeout)
	}
	if p.connectRetryCount != defaultL4ConnectRetryCount {
		t.Fatalf("connectRetryCount = %d, want default %d", p.connectRetryCount, defaultL4ConnectRetryCount)
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

func TestNewL4ProxyPoolSize(t *testing.T) {
	endpoint := &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 443}

	// Default pool size when unset / non-positive.
	p, err := NewL4Proxy(L4ProxyConfig{TLSConfig: &tls.Config{}, Endpoint: endpoint})
	if err != nil {
		t.Fatalf("NewL4Proxy: %v", err)
	}
	if len(p.clients) != defaultL4PoolSize {
		t.Fatalf("default pool size = %d, want %d", len(p.clients), defaultL4PoolSize)
	}

	// Explicit pool size.
	p2, err := NewL4Proxy(L4ProxyConfig{TLSConfig: &tls.Config{}, Endpoint: endpoint, PoolSize: 5})
	if err != nil {
		t.Fatalf("NewL4Proxy: %v", err)
	}
	if len(p2.clients) != 5 {
		t.Fatalf("pool size = %d, want 5", len(p2.clients))
	}

	// streamOpenTimeout is clamped to the (smaller) connect timeout.
	p3, err := NewL4Proxy(L4ProxyConfig{TLSConfig: &tls.Config{}, Endpoint: endpoint, ConnectTimeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("NewL4Proxy: %v", err)
	}
	if p3.streamOpenTimeout != 2*time.Second {
		t.Fatalf("streamOpenTimeout = %v, want clamped to 2s", p3.streamOpenTimeout)
	}
}

func TestL4ProxyClosedRejectsNewConns(t *testing.T) {
	p, err := NewL4Proxy(L4ProxyConfig{
		TLSConfig: &tls.Config{},
		Endpoint:  &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 443},
		PoolSize:  4,
	})
	if err != nil {
		t.Fatalf("NewL4Proxy: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// After Close, building a connection must fail fast with errL4ProxyClosed rather
	// than dialing and storing into the pool (which would leak past Close).
	if _, err := p.getOrCreateClientConnAt(context.Background(), 0); !errors.Is(err, errL4ProxyClosed) {
		t.Fatalf("getOrCreateClientConnAt after Close = %v, want errL4ProxyClosed", err)
	}
}

func TestL4ProxyClearSlotIfCurrent(t *testing.T) {
	p := &L4Proxy{clients: make([]*l4HTTP3Client, 3)}
	c := &l4HTTP3Client{} // nil conns: closeL4HTTP3 is nil-safe

	p.clients[1] = c
	// Mismatched client must not clear the slot.
	p.clearSlotIfCurrent(1, &l4HTTP3Client{})
	if p.clients[1] != c {
		t.Fatal("clearSlotIfCurrent must not clear on a client mismatch")
	}
	// Matching client clears exactly that slot.
	p.clearSlotIfCurrent(1, c)
	if p.clients[1] != nil {
		t.Fatal("clearSlotIfCurrent must clear the matching slot")
	}
	// Naming the wrong slot for a client must not clear a different slot.
	p.clients[2] = c
	p.clearSlotIfCurrent(0, c)
	if p.clients[2] != c {
		t.Fatal("clearSlotIfCurrent must only touch the named slot")
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

func TestL4ProxyConnHealthHelpersNilSafe(t *testing.T) {
	p := &L4Proxy{clients: make([]*l4HTTP3Client, 2)}
	// Both helpers must tolerate nil clients / nil QUIC connections / out-of-range
	// slots without panicking (they run on dial error paths and as a goroutine).
	p.dropConnIfDead(0, nil)
	p.dropConnIfDead(0, &l4HTTP3Client{})
	p.dropConnIfDead(99, &l4HTTP3Client{}) // out-of-range slot
	p.watchClientConn(0, nil)
	p.watchClientConn(0, &l4HTTP3Client{}) // nil quicConn returns immediately
	p.clearSlotIfCurrent(0, &l4HTTP3Client{})
	for _, c := range p.clients {
		if c != nil {
			t.Fatal("nil-safe helpers must not populate a slot")
		}
	}
}
