package cmd

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// stubSocksServer is a minimal socksServer used by the runtime tests; each
// factory call returns a fresh instance so restart-rebuild assertions hold.
type stubSocksServer struct {
	dial socksDialFunc
}

func (s *stubSocksServer) ServeConn(conn net.Conn) error {
	return conn.Close()
}

func newRuntimeForTest(upstreamDial socksDialFunc) *socksRuntime {
	return newSocksRuntime(
		upstreamDial,
		func(dialFunc socksDialFunc) socksServer {
			return &stubSocksServer{dial: dialFunc}
		},
	)
}

func TestSocksRuntimeDialContextFastFailWhenDisconnected(t *testing.T) {
	var dialCount int
	runtime := newRuntimeForTest(func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialCount++
		return nil, errors.New("unexpected dial")
	})
	runtime.SetTunnelUp(false)

	_, err := runtime.DialContext(context.Background(), "tcp", "example.com:80")
	if !errors.Is(err, ErrTunnelDisconnected) {
		t.Fatalf("expected ErrTunnelDisconnected, got: %v", err)
	}
	if dialCount != 0 {
		t.Fatalf("expected upstream dial not to be called, got: %d", dialCount)
	}
}

func TestSocksRuntimeDropIfDisconnected(t *testing.T) {
	runtime := newRuntimeForTest(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, nil
	})
	runtime.SetTunnelUp(false)

	client, peer := net.Pipe()
	defer peer.Close()

	dropped := runtime.DropIfDisconnected(client)
	if !dropped {
		t.Fatalf("expected connection to be dropped")
	}

	_ = peer.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1)
	_, err := peer.Read(buf)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected peer EOF after drop, got: %v", err)
	}
}

func TestSocksRuntimeDropIfDisconnectedIsStrictEvenWithVerboseLogging(t *testing.T) {
	runtime := newRuntimeForTest(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, nil
	})
	runtime.SetTunnelUp(false)
	runtime.SetVerboseLogging(true)

	client, peer := net.Pipe()
	defer peer.Close()

	dropped := runtime.DropIfDisconnected(client)
	if !dropped {
		t.Fatalf("expected connection to be dropped when tunnel is down")
	}

	_ = peer.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1)
	_, err := peer.Read(buf)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected peer EOF after strict drop, got: %v", err)
	}
}

func TestSocksRuntimeResetTrackedConnsClosesStrandedFlows(t *testing.T) {
	runtime := newRuntimeForTest(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("not used")
	})

	client1, peer1 := net.Pipe()
	defer peer1.Close()
	client2, peer2 := net.Pipe()
	defer peer2.Close()

	tracked1 := runtime.TrackConn(client1)
	tracked2 := runtime.TrackConn(client2)
	if runtime.activeConnCount() != 2 {
		t.Fatalf("expected 2 tracked connections before reset, got: %d", runtime.activeConnCount())
	}

	// Simulates OnDisconnected: the tunnel dropped, so every stranded flow is reset
	// immediately rather than left to hang until an idle timeout.
	runtime.ResetTrackedConns()

	if runtime.activeConnCount() != 0 {
		t.Fatalf("expected tracked connections to be reset, got: %d", runtime.activeConnCount())
	}

	_ = peer1.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := peer1.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("expected peer1 EOF after reset, got: %v", err)
	}
	_ = peer2.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := peer2.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("expected peer2 EOF after reset, got: %v", err)
	}

	if _, err := tracked1.Write([]byte("x")); err == nil {
		t.Fatalf("expected tracked1 write to fail after reset")
	}
	if _, err := tracked2.Write([]byte("x")); err == nil {
		t.Fatalf("expected tracked2 write to fail after reset")
	}
}
