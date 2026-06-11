package cmd

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/things-go/go-socks5"
)

func newRuntimeForTest(upstreamDial func(ctx context.Context, network, addr string) (net.Conn, error)) *socksRuntime {
	return newSocksRuntime(
		upstreamDial,
		func(dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)) *socks5.Server {
			return socks5.NewServer(socks5.WithDial(dialFunc))
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

func TestSocksRuntimeRestartAndDrainClosesTrackedConnections(t *testing.T) {
	runtime := newRuntimeForTest(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("not used")
	})
	runtime.SetTunnelUp(true)

	oldServer := runtime.CurrentServer()
	if oldServer == nil {
		t.Fatalf("expected initial server to be created")
	}

	client1, peer1 := net.Pipe()
	defer peer1.Close()
	client2, peer2 := net.Pipe()
	defer peer2.Close()

	tracked1 := runtime.TrackConn(client1)
	tracked2 := runtime.TrackConn(client2)
	if runtime.activeConnCount() != 2 {
		t.Fatalf("expected 2 tracked connections before drain, got: %d", runtime.activeConnCount())
	}

	runtime.RestartAndDrain(errors.New("test reconnect"))

	newServer := runtime.CurrentServer()
	if newServer == nil {
		t.Fatalf("expected server after restart")
	}
	if oldServer == newServer {
		t.Fatalf("expected server instance to be rebuilt on restart")
	}
	if runtime.activeConnCount() != 0 {
		t.Fatalf("expected tracked connections to be drained, got: %d", runtime.activeConnCount())
	}

	_ = peer1.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, err := peer1.Read(make([]byte, 1))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected peer1 EOF after drain, got: %v", err)
	}

	_ = peer2.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, err = peer2.Read(make([]byte, 1))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected peer2 EOF after drain, got: %v", err)
	}

	if _, err := tracked1.Write([]byte("x")); err == nil {
		t.Fatalf("expected tracked1 write to fail after drain")
	}
	if _, err := tracked2.Write([]byte("x")); err == nil {
		t.Fatalf("expected tracked2 write to fail after drain")
	}
}

func TestSocksRuntimeScheduleDrainCanBeCancelled(t *testing.T) {
	runtime := newRuntimeForTest(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("not used")
	})
	runtime.SetTunnelUp(false)

	client, peer := net.Pipe()
	defer peer.Close()
	tracked := runtime.TrackConn(client)
	defer tracked.Close()

	runtime.ScheduleDrain(errors.New("temporary disconnect"), 50*time.Millisecond)
	runtime.SetTunnelUp(true)
	if !runtime.CancelScheduledDrain() {
		t.Fatalf("expected scheduled drain to be cancelled")
	}

	time.Sleep(80 * time.Millisecond)
	if runtime.activeConnCount() != 1 {
		t.Fatalf("expected tracked connection to survive cancelled drain, got: %d", runtime.activeConnCount())
	}
}

func TestSocksRuntimeScheduleDrainClosesTrackedConnectionsAfterGrace(t *testing.T) {
	runtime := newRuntimeForTest(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("not used")
	})
	runtime.SetTunnelUp(false)

	client, peer := net.Pipe()
	defer peer.Close()
	tracked := runtime.TrackConn(client)

	runtime.ScheduleDrain(errors.New("persistent disconnect"), 20*time.Millisecond)

	deadline := time.Now().Add(500 * time.Millisecond)
	for runtime.activeConnCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if runtime.activeConnCount() != 0 {
		t.Fatalf("expected scheduled drain to close tracked connections, got: %d", runtime.activeConnCount())
	}

	_ = peer.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, err := peer.Read(make([]byte, 1))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected peer EOF after scheduled drain, got: %v", err)
	}
	if _, err := tracked.Write([]byte("x")); err == nil {
		t.Fatalf("expected tracked write to fail after scheduled drain")
	}
}
