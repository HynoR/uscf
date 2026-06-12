package cmd

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/txthinking/socks5"
)

// startAdapterServer runs a real TCP listener serving connections through the
// txthinking adapter, dialing upstreams directly (no tunnel). Returns the proxy
// address and a stop func.
func startAdapterServer(t *testing.T, username, password string) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	dial := func(ctx context.Context, network, addr string, _ socksTarget) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	adapter := newTxthinkingAdapter(username, password, systemDNSResolver{}, dial, false)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = adapter.ServeConn(conn) }()
		}
	}()

	return ln.Addr().String(), func() { _ = ln.Close() }
}

func startEchoTCP(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func startEchoUDP(t *testing.T) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp echo listen: %v", err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteTo(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().String(), func() { _ = pc.Close() }
}

func roundtrip(t *testing.T, conn net.Conn, payload string) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	got := 0
	for got < len(payload) {
		n, err := conn.Read(buf[got:])
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		got += n
	}
	if string(buf) != payload {
		t.Fatalf("echo mismatch: got %q want %q", string(buf), payload)
	}
}

func TestAdapterTCPConnectNoAuth(t *testing.T) {
	echoAddr, echoStop := startEchoTCP(t)
	defer echoStop()
	proxyAddr, stop := startAdapterServer(t, "", "")
	defer stop()

	client, err := socks5.NewClient(proxyAddr, "", "", 0, 10)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	conn, err := client.Dial("tcp", echoAddr)
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	defer conn.Close()

	roundtrip(t, conn, "hello-no-auth")
}

func TestAdapterTCPConnectAuthSuccess(t *testing.T) {
	echoAddr, echoStop := startEchoTCP(t)
	defer echoStop()
	proxyAddr, stop := startAdapterServer(t, "user", "pass")
	defer stop()

	client, err := socks5.NewClient(proxyAddr, "user", "pass", 0, 10)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	conn, err := client.Dial("tcp", echoAddr)
	if err != nil {
		t.Fatalf("dial with valid auth: %v", err)
	}
	defer conn.Close()

	roundtrip(t, conn, "hello-auth")
}

func TestAdapterTCPConnectAuthRejected(t *testing.T) {
	echoAddr, echoStop := startEchoTCP(t)
	defer echoStop()
	proxyAddr, stop := startAdapterServer(t, "user", "pass")
	defer stop()

	client, err := socks5.NewClient(proxyAddr, "user", "wrong", 0, 10)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if _, err := client.Dial("tcp", echoAddr); err == nil {
		t.Fatalf("expected dial with invalid credentials to fail")
	}
}

func TestAdapterUDPAssociate(t *testing.T) {
	udpEchoAddr, echoStop := startEchoUDP(t)
	defer echoStop()
	proxyAddr, stop := startAdapterServer(t, "", "")
	defer stop()

	client, err := socks5.NewClient(proxyAddr, "", "", 0, 10)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	conn, err := client.Dial("udp", udpEchoAddr)
	if err != nil {
		t.Fatalf("udp associate: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("udp write: %v", err)
	}
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("udp read: %v", err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("udp echo mismatch: got %q want %q", string(buf[:n]), "ping")
	}
}
