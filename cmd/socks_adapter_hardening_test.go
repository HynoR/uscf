package cmd

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// stubDial is a targetDialFunc that never actually dials; used by semaphore tests
// that only exercise slot accounting.
func stubDial(context.Context, string, string, socksTarget) (net.Conn, error) {
	return nil, net.ErrClosed
}

// startReadAllThenRespondTCP accepts a connection, reads until the client
// half-closes its write side (EOF), then echoes everything back. A response is
// only produced AFTER the read EOF, so it can only succeed if TCP half-close is
// propagated through the relay.
func startReadAllThenRespondTCP(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				data, _ := io.ReadAll(c)
				_, _ = c.Write(data)
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// socks5ConnectRaw performs a no-auth SOCKS5 CONNECT handshake over a raw TCP
// connection and returns it, so the test keeps a *net.TCPConn that exposes
// CloseWrite (the high-level txthinking client does not).
func socks5ConnectRaw(t *testing.T, proxyAddr, target string) net.Conn {
	t.Helper()
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("split target: %v", err)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		t.Fatalf("target %s is not IPv4", target)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth).
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	methodResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, methodResp); err != nil {
		t.Fatalf("read method: %v", err)
	}
	if methodResp[0] != 0x05 || methodResp[1] != 0x00 {
		t.Fatalf("unexpected method selection: %v", methodResp)
	}

	// CONNECT request: VER, CMD=1, RSV, ATYP=IPv4, addr, port.
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, ip...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write connect: %v", err)
	}
	// Reply: VER, REP, RSV, ATYP=IPv4(4 bytes)+port(2) = 10 bytes total.
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read connect reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("connect failed, rep=%d", reply[1])
	}
	return conn
}

func TestAdapterTCPHalfClose(t *testing.T) {
	upAddr, stopUp := startReadAllThenRespondTCP(t)
	defer stopUp()
	proxyAddr, stop := startAdapterServer(t, "", "")
	defer stop()

	conn := socks5ConnectRaw(t, proxyAddr, upAddr)
	defer conn.Close()

	cw, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("raw conn %T has no CloseWrite", conn)
	}

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	const payload = "half-close-payload"
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Signal EOF to the upstream while keeping the read side open for the reply.
	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read after half-close: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("half-close echo mismatch: got %q want %q", string(got), payload)
	}
}

func TestUDPAllowSource(t *testing.T) {
	assoc := &udpAssociation{expectedIP: net.IPv4(10, 0, 0, 1)}
	if !assoc.allowSource(&net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5}) {
		t.Fatal("matching source IP should be allowed")
	}
	if assoc.allowSource(&net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 5}) {
		t.Fatal("mismatched source IP must be dropped")
	}

	// Undetermined client IP must not break availability.
	open := &udpAssociation{}
	if !open.allowSource(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4)}) {
		t.Fatal("nil expectedIP should accept any source")
	}
}

func TestUDPSlotSemaphore(t *testing.T) {
	a := newTxthinkingAdapter("", "", systemDNSResolver{}, stubDial, 0, false, false)
	a.udpSem = make(chan struct{}, 2)

	if !a.acquireUDPSlot() || !a.acquireUDPSlot() {
		t.Fatal("first two acquisitions should succeed")
	}
	if a.acquireUDPSlot() {
		t.Fatal("acquisition past the cap must fail")
	}
	a.releaseUDPSlot()
	if !a.acquireUDPSlot() {
		t.Fatal("a slot should be available after release")
	}
}

func TestCountedConnReleasesOnce(t *testing.T) {
	a := newTxthinkingAdapter("", "", systemDNSResolver{}, stubDial, 0, false, false)
	a.udpSem = make(chan struct{}, 1)

	if !a.acquireUDPSlot() {
		t.Fatal("acquire should succeed")
	}
	c1, c2 := net.Pipe()
	defer c2.Close()
	cc := &countedConn{Conn: c1, release: a.releaseUDPSlot}

	_ = cc.Close()
	_ = cc.Close() // must not double-release

	if !a.acquireUDPSlot() {
		t.Fatal("slot should be released exactly once")
	}
	if a.acquireUDPSlot() {
		t.Fatal("double release would have freed an extra slot")
	}
}

// newTestAssociation builds a udpAssociation backed by a real relay UDP socket
// and a real TCP control connection so close() has something concrete to tear
// down.
func newTestAssociation(t *testing.T) (*udpAssociation, func()) {
	t.Helper()
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("control listen: %v", err)
	}
	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("control dial: %v", err)
	}
	srvConn, err := ln.Accept()
	if err != nil {
		t.Fatalf("control accept: %v", err)
	}
	_ = ln.Close()

	assoc := &udpAssociation{
		relay:       relay,
		controlConn: srvConn,
		upstreams:   make(map[string]net.Conn),
		done:        make(chan struct{}),
	}
	cleanup := func() {
		assoc.close()
		_ = dialed.Close()
	}
	return assoc, cleanup
}

func TestUDPAssociationIdleReaper(t *testing.T) {
	assoc, cleanup := newTestAssociation(t)
	defer cleanup()

	assoc.touch()
	go assoc.idleReaper(150 * time.Millisecond)

	select {
	case <-assoc.done:
		// Reclaimed as expected.
	case <-time.After(3 * time.Second):
		t.Fatal("idle association was not reclaimed")
	}

	// The relay socket must be closed by close().
	_ = assoc.relay.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err := assoc.relay.ReadFromUDP(make([]byte, 1)); err == nil {
		t.Fatal("relay socket should be closed after reclaim")
	}
}

func TestUDPAssociationActiveNotReclaimed(t *testing.T) {
	assoc, cleanup := newTestAssociation(t)
	defer cleanup()

	go assoc.idleReaper(150 * time.Millisecond)

	// Keep the association active for longer than the idle timeout.
	for i := 0; i < 10; i++ {
		assoc.touch()
		time.Sleep(40 * time.Millisecond)
	}

	select {
	case <-assoc.done:
		t.Fatal("active association was wrongly reclaimed")
	default:
	}
}
