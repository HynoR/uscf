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
	"time"

	"github.com/HynoR/uscf/api"
	"github.com/txthinking/socks5"
)

// maxConcurrentUDPUpstreams bounds the total number of live upstream UDP
// connections across all associations served by one adapter. Each upstream
// holds a socket, a relay goroutine and a read buffer, so an unbounded count is
// an OOM / file-descriptor exhaustion vector when a client (or an injected
// source) fans datagrams out to many distinct destinations. Datagrams to a new
// destination are dropped once the cap is reached; the client simply retries.
const maxConcurrentUDPUpstreams = 1024

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

	// idleTimeout reclaims a UDP association after this long without any UDP
	// activity. Zero disables the reaper. TCP relays are bounded separately by
	// the per-connection models.TimeoutConn deadlines applied at dial time.
	idleTimeout time.Duration

	// halfOpenIdle, when >0, caps how long a TCP relay's surviving direction may
	// stay idle once the other direction has finished (half-open). It re-arms on
	// activity, so an active/slow-but-streaming survivor is never cut; only a
	// truly idle half-open flow is reaped — at this timeout instead of the full
	// idleTimeout. Set for L4 (where a lingering half-open flow pins a QUIC stream
	// on the shared connection against MAX_STREAMS); 0 disables it (L3 unchanged).
	halfOpenIdle time.Duration

	// udpSem is a counting semaphore bounding live upstream UDP connections to
	// maxConcurrentUDPUpstreams across all associations served by this adapter.
	udpSem chan struct{}
}

func newTxthinkingAdapter(username, password string, resolver api.NameResolver, dial targetDialFunc, idleTimeout, halfOpenIdle time.Duration, verbose bool, tcpOnly bool) *txthinkingAdapter {
	method := socks5.MethodNone
	if username != "" && password != "" {
		method = socks5.MethodUsernamePassword
	}
	// L4 mode tunnels each flow as an HTTP/3 CONNECT stream and has no UDP path,
	// so advertise CONNECT only — GetRequest then rejects UDP ASSOCIATE during
	// negotiation instead of accepting an association whose datagrams all drop.
	supported := []byte{socks5.CmdConnect, socks5.CmdUDP}
	if tcpOnly {
		supported = []byte{socks5.CmdConnect}
	}
	return &txthinkingAdapter{
		proto: &socks5.Server{
			Method:            method,
			UserName:          username,
			Password:          password,
			SupportedCommands: supported,
		},
		resolver:     resolver,
		dial:         dial,
		bufPool:      api.NewNetBuffer(32 * 1024),
		verbose:      verbose,
		idleTimeout:  idleTimeout,
		halfOpenIdle: halfOpenIdle,
		udpSem:       make(chan struct{}, maxConcurrentUDPUpstreams),
	}
}

// acquireUDPSlot reserves one upstream-UDP-connection slot, returning false when
// the adapter is already at maxConcurrentUDPUpstreams.
func (a *txthinkingAdapter) acquireUDPSlot() bool {
	select {
	case a.udpSem <- struct{}{}:
		return true
	default:
		return false
	}
}

// releaseUDPSlot returns one slot. Non-blocking so an accidental double-release
// can never deadlock a relay goroutine; pairing is kept exact by countedConn.
func (a *txthinkingAdapter) releaseUDPSlot() {
	select {
	case <-a.udpSem:
	default:
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

// relayTCP copies bytes in both directions until BOTH halves finish. Each
// direction signals a TCP half-close to its destination when its source EOFs,
// so a peer that closes only its write side (e.g. an HTTP client that finished
// the request but still awaits the response) is not torn down prematurely.
//
// Once the FIRST direction finishes, the flow is half-open. Both ends carry a
// models.TimeoutConn idle deadline (default minutes), but for L4 a half-open flow
// that goes silent would pin its QUIC stream on the shared connection for that
// whole window — and under load those accumulate against the connection's
// MAX_STREAMS until new dials block. So when halfOpenIdle is set, we shorten the
// surviving direction's re-arming idle bound the moment the first half ends. The
// bound re-arms on activity, so a still-active survivor (a slow/long response
// after the client finished its request) keeps transferring and is not cut; only
// a truly idle half-open flow is reaped — in seconds instead of minutes.
func (a *txthinkingAdapter) relayTCP(client, upstream net.Conn) error {
	errc := make(chan error, 2)
	go func() { errc <- a.copyHalf(upstream, client) }() // client -> upstream
	go func() { errc <- a.copyHalf(client, upstream) }() // upstream -> client

	err1 := <-errc
	// io.Copy returns nil on a clean EOF (a graceful TCP half-close), so a non-nil
	// error here means a direction failed HARD — a reset, the upstream tunnel dying
	// under the flow, or an idle-deadline expiry. Tear BOTH conns down immediately
	// so the surviving direction's blocked Read unblocks now, instead of waiting out
	// its (minutes-long) idle deadline. This is what stops a flow from hanging when
	// the WARP tunnel drops mid-request: the client gets a prompt reset and retries
	// (which succeeds on the freshly reconnected tunnel) rather than stalling.
	if err1 != nil {
		_ = client.Close()
		_ = upstream.Close()
		<-errc // the other goroutine is now unblocked; reclaim it (and its buffer)
		return err1
	}

	// Clean half-close: the flow is legitimately half-open (e.g. an HTTP client that
	// finished its request and still awaits the response). Keep the surviving
	// direction; for L4, shorten its idle so a silent half-open does not pin a scarce
	// QUIC stream on the shared connection.
	if a.halfOpenIdle > 0 {
		shortenRelayIdle(client, a.halfOpenIdle)
		shortenRelayIdle(upstream, a.halfOpenIdle)
	}
	err2 := <-errc
	_ = client.Close()
	_ = upstream.Close()
	return err2
}

// shortenRelayIdle lowers a relay connection's re-arming idle bound (so a now
// half-open flow is reclaimed quickly) and immediately re-bounds any in-flight
// blocked Read, so the surviving direction does not have to wait out the old,
// far-future deadline. It re-arms on activity via TimeoutConn, so an active
// survivor is not affected.
func shortenRelayIdle(conn net.Conn, idle time.Duration) {
	if s, ok := conn.(interface{ SetIdleTimeout(time.Duration) }); ok {
		s.SetIdleTimeout(idle)
	}
	_ = conn.SetReadDeadline(time.Now().Add(idle))
}

// copyHalf copies src->dst with a pooled buffer (so models.TimeoutConn deadline
// bookkeeping runs), then half-closes dst's write side so the peer observes a
// clean EOF instead of a reset when only one direction has finished.
func (a *txthinkingAdapter) copyHalf(dst, src net.Conn) error {
	buf := a.bufPool.GetBuf()
	defer a.bufPool.PutBuf(buf)
	_, err := io.CopyBuffer(dst, src, *buf)
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
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
	if a.verbose {
		slog.Debug("UDP ASSOCIATE established", "client", conn.RemoteAddr(), "relay", relay.LocalAddr())
	}

	assoc := &udpAssociation{
		adapter:     a,
		relay:       relay,
		controlConn: conn,
		expectedIP:  clientIP(conn),
		upstreams:   make(map[string]net.Conn),
		done:        make(chan struct{}),
	}
	assoc.touch()
	defer assoc.close()

	// The association lives as long as the TCP control connection. When the
	// client closes it (or the runtime drains it on tunnel-down), tear the
	// association down. Idle-read timeouts on the (deliberately silent) control
	// channel are ignored here: an active UDP flow must not be killed just
	// because no TCP bytes arrived — association idleness is judged from UDP
	// activity by idleReaper instead.
	go func() {
		drainControlConn(conn)
		assoc.close()
	}()

	if a.idleTimeout > 0 {
		go assoc.idleReaper(a.idleTimeout)
	}

	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := relay.ReadFromUDP(buf)
		if err != nil {
			return nil
		}
		// Only relay datagrams whose source IP matches the client that
		// authenticated the TCP control connection. Without this, anything that
		// can reach the relay port could use it as an open UDP relay through the
		// tunnel and could hijack where responses are sent.
		if !assoc.allowSource(clientAddr) {
			if a.verbose {
				slog.Warn("dropping UDP datagram from unauthorized source", "src", clientAddr.String(), "expected_ip", assoc.expectedIP.String())
			}
			continue
		}
		d, err := socks5.NewDatagramFromBytes(buf[:n])
		if err != nil || d.Frag != 0x00 {
			continue
		}
		assoc.touch()
		assoc.forwardFromClient(clientAddr, d)
	}
}

// drainControlConn reads and discards from the UDP-ASSOCIATE TCP control
// connection until it closes, ignoring idle-read timeouts (the control channel
// is silent by design while UDP data flows). Returns on EOF or any non-timeout
// error so the association is torn down when the client really goes away.
func drainControlConn(conn net.Conn) {
	buf := make([]byte, 512)
	for {
		if _, err := conn.Read(buf); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
	}
}

// udpAssociation tracks the relay socket, the controlling TCP connection, the
// latest client source address and one upstream connection per destination for
// a single UDP ASSOCIATE.
type udpAssociation struct {
	adapter     *txthinkingAdapter
	relay       *net.UDPConn
	controlConn net.Conn
	// expectedIP is the IP of the client that opened the TCP control connection.
	// Datagrams from other source IPs are rejected (see allowSource). Nil when
	// the client address could not be determined, in which case all sources are
	// accepted to preserve availability.
	expectedIP   net.IP
	clientAddr   atomic.Pointer[net.UDPAddr]
	lastActivity atomic.Int64 // unix ns of last UDP datagram in either direction

	mu        sync.Mutex
	upstreams map[string]net.Conn
	closed    bool
	done      chan struct{}
}

// touch records UDP activity so idleReaper can tell a live association from a
// stale one.
func (assoc *udpAssociation) touch() {
	assoc.lastActivity.Store(time.Now().UnixNano())
}

// allowSource reports whether a datagram from addr may be relayed: its IP must
// match the client that authenticated the control connection.
func (assoc *udpAssociation) allowSource(addr *net.UDPAddr) bool {
	if assoc.expectedIP == nil || addr == nil {
		return true
	}
	return assoc.expectedIP.Equal(addr.IP)
}

// idleReaper closes the association once no UDP datagram has flowed in either
// direction for idleTimeout, reclaiming the relay socket, upstreams and the
// control connection so a walked-away client cannot pin resources indefinitely.
func (assoc *udpAssociation) idleReaper(idleTimeout time.Duration) {
	interval := idleTimeout / 2
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-assoc.done:
			return
		case <-ticker.C:
			if time.Now().UnixNano()-assoc.lastActivity.Load() > int64(idleTimeout) {
				slog.Debug("reclaiming idle UDP association", "idle_timeout", idleTimeout)
				assoc.close()
				return
			}
		}
	}
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
		if assoc.adapter.verbose {
			slog.Warn("dropping UDP datagram: resolve failed", "dst", dst, "error", err)
		}
		return
	}

	// Bound concurrent upstream UDP connections so a client (or an injected
	// source) fanning out to many destinations cannot exhaust memory/FDs.
	if !assoc.adapter.acquireUDPSlot() {
		if assoc.adapter.verbose {
			slog.Warn("UDP upstream limit reached; dropping datagram", "dst", dst)
		}
		return
	}
	rawUp, err := assoc.adapter.dial(ctx, "udp", dialAddr, target)
	if err != nil {
		// e.g. block_udp_443, tunnel down, or an L4 direct/tunnel dial error: the
		// datagram is dropped and the client retries. Log it (verbose) so a UDP
		// outage is diagnosable instead of silent — the underlying reason
		// (tunnel-down, udp/443 blocked, dial error) is only otherwise visible at
		// the L3 runtime layer, and not at all for L4 direct/tunnel modes.
		if assoc.adapter.verbose {
			slog.Warn("dropping UDP datagram: upstream dial failed", "dst", dst, "target", dialAddr, "error", err)
		}
		assoc.adapter.releaseUDPSlot()
		return
	}
	// countedConn releases the slot exactly once when the upstream is closed,
	// whichever teardown path (discard below, removeUpstream, or close) closes it.
	up = &countedConn{Conn: rawUp, release: assoc.adapter.releaseUDPSlot}

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
	// Per-flow success line (verbose): confirms UDP is actually being proxied to a
	// destination — one line per new (association, dst), not per datagram.
	if assoc.adapter.verbose {
		slog.Debug("UDP proxying flow established", "src", clientAddr, "dst", dst, "first_bytes", len(d.Data))
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
	firstReply := true
	for {
		n, err := up.Read(buf)
		if err != nil {
			return
		}
		clientAddr := assoc.clientAddr.Load()
		if clientAddr == nil {
			continue
		}
		// One line on the first reply (verbose): confirms the upstream actually
		// answered, i.e. UDP is being proxied bidirectionally — not per datagram.
		if firstReply && assoc.adapter.verbose {
			slog.Debug("UDP proxying reply received", "dst", dst, "client", clientAddr, "bytes", n)
			firstReply = false
		}
		assoc.touch()
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

// close tears the association down once: it stops the relay socket (unblocking
// the read loop), closes the TCP control connection (unblocking drainControlConn
// and the idleReaper) and closes every upstream. Idempotent across the read
// loop's defer, the control-conn watcher and the idle reaper.
func (assoc *udpAssociation) close() {
	assoc.mu.Lock()
	if assoc.closed {
		assoc.mu.Unlock()
		return
	}
	assoc.closed = true
	close(assoc.done)
	conns := make([]net.Conn, 0, len(assoc.upstreams))
	for dst, up := range assoc.upstreams {
		conns = append(conns, up)
		delete(assoc.upstreams, dst)
	}
	assoc.mu.Unlock()

	if assoc.relay != nil {
		_ = assoc.relay.Close()
	}
	if assoc.controlConn != nil {
		_ = assoc.controlConn.Close()
	}
	for _, up := range conns {
		_ = up.Close()
	}
}

// countedConn releases a UDP-upstream semaphore slot exactly once, when the
// connection is closed, no matter which teardown path closes it.
type countedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *countedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
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

// clientIP returns the remote IP of the (TCP) control connection: the client
// authorized to drive this UDP association. Used to filter relay datagrams by
// source. Returns nil when it cannot be determined.
func clientIP(conn net.Conn) net.IP {
	if conn == nil {
		return nil
	}
	switch addr := conn.RemoteAddr().(type) {
	case *net.TCPAddr:
		return addr.IP
	case *net.UDPAddr:
		return addr.IP
	}
	if remote := conn.RemoteAddr(); remote != nil {
		if host, _, err := net.SplitHostPort(remote.String()); err == nil {
			return net.ParseIP(host)
		}
	}
	return nil
}
