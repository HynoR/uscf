package cmd

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/HynoR/uscf/api"
	"github.com/txthinking/socks5"
)

// targetDialFunc dials an upstream connection for an already-resolved address,
// while still receiving the original (pre-resolution) target so that routing
// decisions such as bypass_domain / proxy_tcp_port can be made on the host name.
type targetDialFunc func(ctx context.Context, network, addr string, target socksTarget) (net.Conn, error)

// txthinkingAdapter implements socksServer on top of github.com/txthinking/socks5.
//
// txthinking/socks5 is a low-level protocol package: it exposes Negotiate /
// GetRequest helpers but no per-server dial or resolver hooks. This adapter
// re-implements the request dispatch so uscf keeps full control over DNS
// resolution, route policy, the per-runtime tunnel dialer, block_udp_443 and the
// tunnel-down / drain semantics that the accept loop and socksRuntime provide.
type txthinkingAdapter struct {
	// proto carries only the protocol configuration (method + credentials +
	// supported commands) consulted by Negotiate / GetRequest. It holds no
	// per-connection state, so a single instance is safe to share.
	proto *socks5.Server

	resolver api.NameResolver
	dial     targetDialFunc
	bufPool  *api.NetBuffer
	verbose  bool
}

func newTxthinkingAdapter(username, password string, resolver api.NameResolver, dial targetDialFunc, verbose bool) *txthinkingAdapter {
	method := socks5.MethodNone
	if username != "" && password != "" {
		method = socks5.MethodUsernamePassword
	}
	return &txthinkingAdapter{
		proto: &socks5.Server{
			Method:            method,
			UserName:          username,
			Password:          password,
			SupportedCommands: []byte{socks5.CmdConnect, socks5.CmdUDP},
		},
		resolver: resolver,
		dial:     dial,
		bufPool:  api.NewNetBuffer(32 * 1024),
		verbose:  verbose,
	}
}

// ServeConn negotiates auth, reads the request and dispatches it. Mirrors the
// flow that go-socks5's ServeConn previously provided.
func (a *txthinkingAdapter) ServeConn(conn net.Conn) error {
	if err := a.proto.Negotiate(conn); err != nil {
		return err
	}
	req, err := a.proto.GetRequest(conn)
	if err != nil {
		return err
	}

	switch req.Cmd {
	case socks5.CmdConnect:
		return a.handleConnect(conn, req)
	case socks5.CmdUDP:
		return a.handleAssociate(conn, req)
	default:
		// GetRequest already rejected unsupported commands, but stay defensive.
		a.replyError(conn, req, socks5.RepCommandNotSupported)
		return socks5.ErrUnsupportCmd
	}
}

// handleConnect resolves the target, applies route policy via a.dial, replies and
// then pumps bytes in both directions.
func (a *txthinkingAdapter) handleConnect(conn net.Conn, req *socks5.Request) error {
	target := targetFromRequest(req)
	ctx := context.Background()

	dialAddr, err := a.resolveDialAddr(ctx, target)
	if err != nil {
		if a.verbose {
			slog.Warn("SOCKS connect resolve failed", "host", target.Host, "port", target.Port, "error", err)
		}
		a.replyError(conn, req, socks5.RepHostUnreachable)
		return err
	}

	upstream, err := a.dial(ctx, "tcp", dialAddr, target)
	if err != nil {
		if a.verbose {
			slog.Warn("SOCKS connect dial failed", "host", target.Host, "port", target.Port, "target", dialAddr, "error", err)
		}
		a.replyError(conn, req, socks5.RepHostUnreachable)
		return err
	}
	defer upstream.Close()

	if err := a.replyConnectSuccess(conn, upstream); err != nil {
		return err
	}

	return a.relayTCP(conn, upstream)
}

// relayTCP copies bytes between the client and the upstream until either side
// closes, using pooled buffers so models.TimeoutConn deadline bookkeeping runs.
func (a *txthinkingAdapter) relayTCP(client, upstream net.Conn) error {
	errc := make(chan error, 2)
	go func() { errc <- a.copyBuffered(upstream, client) }()
	go func() { errc <- a.copyBuffered(client, upstream) }()

	first := <-errc
	_ = client.Close()
	_ = upstream.Close()
	<-errc
	return first
}

func (a *txthinkingAdapter) copyBuffered(dst, src net.Conn) error {
	buf := a.bufPool.GetBuf()
	defer a.bufPool.PutBuf(buf)
	_, err := io.CopyBuffer(dst, src, *buf)
	return err
}

// resolveDialAddr returns the host:port the dialer should connect to. Domains are
// resolved through the configured resolver (which already routes local vs tunnel
// DNS); IP literals are passed through untouched.
func (a *txthinkingAdapter) resolveDialAddr(ctx context.Context, target socksTarget) (string, error) {
	host := target.Host
	if net.ParseIP(host) == nil {
		_, ip, err := a.resolver.Resolve(ctx, host)
		if err != nil {
			return "", err
		}
		host = ip.String()
	}
	return net.JoinHostPort(host, strconv.Itoa(target.Port)), nil
}

// targetFromRequest extracts the original destination host and port.
func targetFromRequest(req *socks5.Request) socksTarget {
	var host string
	if req.Atyp == socks5.ATYPDomain {
		host = string(req.DstAddr[1:])
	} else {
		host = net.IP(req.DstAddr).String()
	}
	return socksTarget{
		Host: host,
		Port: int(binary.BigEndian.Uint16(req.DstPort)),
	}
}

func (a *txthinkingAdapter) replyConnectSuccess(conn net.Conn, upstream net.Conn) error {
	atyp, addr, port := boundAddress(upstream)
	_, err := socks5.NewReply(socks5.RepSuccess, atyp, addr, port).WriteTo(conn)
	return err
}

func (a *txthinkingAdapter) replyError(conn net.Conn, req *socks5.Request, rep byte) {
	atyp := byte(socks5.ATYPIPv4)
	addr := []byte{0x00, 0x00, 0x00, 0x00}
	if req != nil && req.Atyp == socks5.ATYPIPv6 {
		atyp = socks5.ATYPIPv6
		addr = make([]byte, net.IPv6len)
	}
	_, _ = socks5.NewReply(rep, atyp, addr, []byte{0x00, 0x00}).WriteTo(conn)
}

// boundAddress encodes conn.LocalAddr() into SOCKS reply fields, falling back to
// 0.0.0.0:0 when it cannot be parsed (clients accept the zero address).
func boundAddress(conn net.Conn) (byte, []byte, []byte) {
	if conn != nil {
		if local := conn.LocalAddr(); local != nil {
			if atyp, addr, port, err := socks5.ParseAddress(local.String()); err == nil {
				return atyp, addr, port
			}
		}
	}
	return socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}
}

// handleAssociate implements SOCKS5 UDP ASSOCIATE with a dedicated relay socket
// per association. Upstream UDP datagrams go through a.dial (the per-runtime
// tunnel dialer with block_udp_443 enforcement and tunnel-down gating); the
// association ends when the TCP control connection closes.
func (a *txthinkingAdapter) handleAssociate(conn net.Conn, req *socks5.Request) error {
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: localIP(conn), Port: 0})
	if err != nil {
		a.replyError(conn, req, socks5.RepServerFailure)
		return err
	}
	defer relay.Close()

	atyp, addr, port, err := socks5.ParseAddress(relay.LocalAddr().String())
	if err != nil {
		a.replyError(conn, req, socks5.RepServerFailure)
		return err
	}
	if _, err := socks5.NewReply(socks5.RepSuccess, atyp, addr, port).WriteTo(conn); err != nil {
		return err
	}

	assoc := &udpAssociation{
		adapter:   a,
		relay:     relay,
		upstreams: make(map[string]net.Conn),
	}
	defer assoc.closeAll()

	// The association lives as long as the TCP control connection. When the
	// client closes it (or the runtime drains it on tunnel-down), unblock the
	// read loop below by closing the relay socket.
	go func() {
		_, _ = io.Copy(io.Discard, conn)
		_ = relay.Close()
	}()

	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := relay.ReadFromUDP(buf)
		if err != nil {
			return nil
		}
		d, err := socks5.NewDatagramFromBytes(buf[:n])
		if err != nil || d.Frag != 0x00 {
			continue
		}
		assoc.forwardFromClient(clientAddr, d)
	}
}

// udpAssociation tracks the relay socket, the latest client source address and
// one upstream connection per destination for a single UDP ASSOCIATE.
type udpAssociation struct {
	adapter    *txthinkingAdapter
	relay      *net.UDPConn
	clientAddr atomic.Pointer[net.UDPAddr]

	mu        sync.Mutex
	upstreams map[string]net.Conn
	closed    bool
}

func (assoc *udpAssociation) forwardFromClient(clientAddr *net.UDPAddr, d *socks5.Datagram) {
	assoc.clientAddr.Store(clientAddr)
	dst := d.Address()

	assoc.mu.Lock()
	if assoc.closed {
		assoc.mu.Unlock()
		return
	}
	up, ok := assoc.upstreams[dst]
	assoc.mu.Unlock()
	if ok {
		_, _ = up.Write(d.Data)
		return
	}

	host, portStr, err := net.SplitHostPort(dst)
	if err != nil {
		return
	}
	dstPort, err := strconv.Atoi(portStr)
	if err != nil {
		return
	}
	target := socksTarget{Host: host, Port: dstPort}

	ctx := context.Background()
	dialAddr, err := assoc.adapter.resolveDialAddr(ctx, target)
	if err != nil {
		return
	}

	up, err = assoc.adapter.dial(ctx, "udp", dialAddr, target)
	if err != nil {
		// e.g. block_udp_443 or tunnel down: silently drop, the client retries.
		return
	}

	assoc.mu.Lock()
	if assoc.closed {
		assoc.mu.Unlock()
		_ = up.Close()
		return
	}
	if existing, ok := assoc.upstreams[dst]; ok {
		assoc.mu.Unlock()
		_ = up.Close()
		_, _ = existing.Write(d.Data)
		return
	}
	assoc.upstreams[dst] = up
	assoc.mu.Unlock()

	if _, err := up.Write(d.Data); err != nil {
		assoc.removeUpstream(dst, up)
		return
	}
	go assoc.relayFromUpstream(dst, up)
}

// relayFromUpstream reads upstream responses, re-wraps them with the original
// destination header and sends them back to the client's UDP source address.
func (assoc *udpAssociation) relayFromUpstream(dst string, up net.Conn) {
	defer assoc.removeUpstream(dst, up)

	atyp, addr, port, err := socks5.ParseAddress(dst)
	if err != nil {
		return
	}
	if atyp == socks5.ATYPDomain {
		// NewDatagram re-adds the domain length prefix.
		addr = addr[1:]
	}

	buf := make([]byte, 65535)
	for {
		n, err := up.Read(buf)
		if err != nil {
			return
		}
		clientAddr := assoc.clientAddr.Load()
		if clientAddr == nil {
			continue
		}
		datagram := socks5.NewDatagram(atyp, addr, port, buf[:n])
		if _, err := assoc.relay.WriteToUDP(datagram.Bytes(), clientAddr); err != nil {
			return
		}
	}
}

func (assoc *udpAssociation) removeUpstream(dst string, up net.Conn) {
	assoc.mu.Lock()
	if current, ok := assoc.upstreams[dst]; ok && current == up {
		delete(assoc.upstreams, dst)
	}
	assoc.mu.Unlock()
	_ = up.Close()
}

func (assoc *udpAssociation) closeAll() {
	assoc.mu.Lock()
	assoc.closed = true
	conns := make([]net.Conn, 0, len(assoc.upstreams))
	for dst, up := range assoc.upstreams {
		conns = append(conns, up)
		delete(assoc.upstreams, dst)
	}
	assoc.mu.Unlock()

	for _, up := range conns {
		_ = up.Close()
	}
}

// localIP returns the local IP of the (TCP) control connection so the UDP relay
// socket binds to an address the client can reach. Falls back to the unspecified
// address, which tells the client to reuse the SOCKS server address.
func localIP(conn net.Conn) net.IP {
	if conn == nil {
		return nil
	}
	switch addr := conn.LocalAddr().(type) {
	case *net.TCPAddr:
		return addr.IP
	case *net.UDPAddr:
		return addr.IP
	}
	if host, _, err := net.SplitHostPort(conn.LocalAddr().String()); err == nil {
		return net.ParseIP(host)
	}
	return nil
}
