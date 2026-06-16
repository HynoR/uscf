package models

import (
	"io"
	"net"
	"testing"
	"time"
)

// TestTimeoutConnCloseWrite verifies the half-close is forwarded to the
// underlying *net.TCPConn even though net.Conn does not expose CloseWrite.
func TestTimeoutConnCloseWrite(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer dialed.Close()

	srv, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer srv.Close()

	tc := &TimeoutConn{Conn: dialed, IdleTimeout: 5 * time.Second}
	const payload = "half-close"
	if _, err := tc.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tc.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	_ = srv.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(srv)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("got %q want %q (CloseWrite should deliver payload then EOF)", string(got), payload)
	}
}

// TestTimeoutConnCloseWriteUnsupported ensures CloseWrite degrades to nil when
// the wrapped connection has no write half (e.g. a net.Pipe).
func TestTimeoutConnCloseWriteUnsupported(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	tc := &TimeoutConn{Conn: c1}
	if err := tc.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite on unsupported conn should be nil, got %v", err)
	}
}
