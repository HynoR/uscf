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

// TestTimeoutConnSetIdleTimeout verifies SetIdleTimeout lowers the effective
// re-arming idle bound for an in-flight connection: a subsequent silent Read times
// out near the new (short) value rather than the construction-time IdleTimeout.
func TestTimeoutConnSetIdleTimeout(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	tc := &TimeoutConn{Conn: c1, IdleTimeout: 10 * time.Second}
	tc.SetIdleTimeout(100 * time.Millisecond)

	start := time.Now()
	_, err := tc.Read(make([]byte, 1))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a timeout error on a silent read after SetIdleTimeout")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("read did not honor the shortened idle timeout: waited %v (want ~100ms)", elapsed)
	}
}

// TestTimeoutConnActiveReadReArms confirms an actively-progressing read is not cut
// by the idle bound: each successful Read re-arms the deadline, so a stream with
// inter-byte gaps below the idle timeout keeps flowing (the property that lets the
// half-open relay bound reclaim only truly idle survivors, never active ones).
func TestTimeoutConnActiveReadReArms(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	tc := &TimeoutConn{Conn: c1, IdleTimeout: 200 * time.Millisecond}

	go func() {
		for i := 0; i < 5; i++ {
			time.Sleep(80 * time.Millisecond) // < idle, so each read re-arms
			if _, err := c2.Write([]byte{byte(i)}); err != nil {
				return
			}
		}
	}()

	buf := make([]byte, 1)
	for i := 0; i < 5; i++ {
		if _, err := tc.Read(buf); err != nil {
			t.Fatalf("active read %d was cut by the idle bound: %v", i, err)
		}
	}
}
