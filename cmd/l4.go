package cmd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/HynoR/uscf/api"
	"github.com/HynoR/uscf/config"
	"github.com/HynoR/uscf/internal"
	"github.com/HynoR/uscf/models"
	"github.com/quic-go/quic-go"
	"github.com/spf13/cobra"
)

var errL4UDPUnsupported = errors.New("L4 mode is TCP-only; UDP is not supported")

// l4UDPRoute classifies how a UDP dial is handled in L4 mode. The L4 transport
// cannot tunnel UDP (Cloudflare's MASQUE proxy endpoint answers connect-udp with
// 403), so UDP is either refused, sent out directly, or carried over a parallel
// L3 connect-ip tunnel ("mix" mode).
type l4UDPRoute int

const (
	l4UDPReject     l4UDPRoute = iota // refuse the datagram (block mode)
	l4UDPBlocked443                   // refuse: block_udp_443 is on and dst port is 443
	l4UDPDirectOut                    // relay directly, bypassing the tunnel (direct mode)
	l4UDPTunnelOut                    // relay over the parallel L3 connect-ip tunnel (tunnel/mix mode)
)

// classifyL4UDP decides the disposition of an L4-mode UDP dial given socks.l4_udp.
// "block" always refuses. "direct" relays straight out; "tunnel" relays over the
// parallel L3 connect-ip leg. Both "direct" and "tunnel" honor block_udp_443,
// which suppresses UDP/443 (QUIC) so apps fall back to the tunneled TCP path: in
// direct mode that stops QUIC leaking outside WARP, and in tunnel mode it stops
// QUIC-in-QUIC over the L3 leg from throttling bandwidth. block_udp_443 is a
// precondition for forcing HTTP/3 down to HTTP/2, not an optional optimization.
func classifyL4UDP(mode string, blockUDP443 bool, addr string) l4UDPRoute {
	if mode != config.L4UDPDirect && mode != config.L4UDPTunnel {
		return l4UDPReject
	}
	if blockUDP443 {
		if _, port, err := net.SplitHostPort(addr); err == nil && port == "443" {
			return l4UDPBlocked443
		}
	}
	if mode == config.L4UDPTunnel {
		return l4UDPTunnelOut
	}
	return l4UDPDirectOut
}

// dialL4UDP routes a UDP dial in L4 mode according to socks.l4_udp. "direct"
// relays straight out via directDial; "tunnel" carries it over the parallel L3
// connect-ip leg (udpTunnel); a block_udp_443 hit or a non-UDP-capable mode
// returns the matching error so the SOCKS layer drops the datagram. Extracted
// from the dialWithTarget closure so the route→dialer mapping is unit-testable
// without a live tunnel.
func dialL4UDP(ctx context.Context, network, addr string, target socksTarget, mode string, blockUDP443 bool, directDial socksDialFunc, udpTunnel *l3UDPTunnel) (net.Conn, error) {
	switch classifyL4UDP(mode, blockUDP443, addr) {
	case l4UDPDirectOut:
		slog.Debug("l4 udp relayed directly (bypassing tunnel)", "host", target.Host, "port", target.Port, "target", addr)
		return directDial(ctx, network, addr)
	case l4UDPTunnelOut:
		slog.Debug("l4 udp routed over parallel L3 tunnel", "host", target.Host, "port", target.Port, "target", addr)
		return udpTunnel.DialUDP(ctx, addr)
	case l4UDPBlocked443:
		return nil, errUDP443Blocked
	default:
		return nil, errL4UDPUnsupported
	}
}

// setupAndRunL4Proxy runs the SOCKS5 proxy over the L4 (HTTP/3 CONNECT-stream)
// transport. It reuses uscf's SOCKS machinery — auth, route policy, idle
// timeouts, the caching resolver, verbose logging, connection tracking — but
// swaps the L3 connect-ip tunnel for a multiplexed QUIC connection. There is no
// TUN device, no gVisor netstack and no forwarding supervisor: each client TCP
// flow becomes one QUIC stream, so QUIC handles congestion/flow control
// natively. The trade-off is that the mode is TCP-only and DNS is resolved
// locally (there is no in-tunnel resolver path).
func setupAndRunL4Proxy(cmd *cobra.Command, overrides []string, configSaved bool) error {
	if config.AppConfig.Socks.HTTP2 {
		return fmt.Errorf("l4 mode cannot be combined with http2: L4 requires QUIC/HTTP3")
	}

	tlsConfig, err := prepareL4TlsConfig()
	if err != nil {
		return err
	}

	endpoint, endpointSelector, err := selectL4Endpoint()
	if err != nil {
		return err
	}

	connectionTimeout, idleTimeout := getTimeoutSettings(cmd)

	l4Proxy, err := api.NewL4Proxy(api.L4ProxyConfig{
		TLSConfig:          tlsConfig,
		QUICConfig:         l4QUICConfig(config.AppConfig.Socks.KeepalivePeriod.Duration(), config.AppConfig.Socks.InitialPacketSize),
		Endpoint:           endpoint,
		EndpointSelector:   endpointSelector,
		ConnectTimeout:     connectionTimeout,
		PoolSize:           config.AppConfig.Socks.L4PoolSize,
		MaxInFlightStreams: config.AppConfig.Socks.L4MaxStreams,
	})
	if err != nil {
		return fmt.Errorf("failed to create L4 proxy: %w", err)
	}
	defer l4Proxy.Close()

	// Periodically surface the live stream count and cumulative fast-fail rejections
	// so an operator can see how close a single connection runs to its ceiling under
	// load. Stops when the listener closes (runSocksServer returns).
	statsCtx, stopStats := context.WithCancel(context.Background())
	defer stopStats()
	go logL4Stats(statsCtx, l4Proxy)

	// "mix" mode: stand up a parallel, lazy L3 connect-ip tunnel that carries UDP
	// while TCP rides L4. It does not connect until the first UDP datagram, so a
	// mostly-TCP workload pays nothing for it. The TCP path is untouched.
	var udpTunnel *l3UDPTunnel
	if config.AppConfig.Socks.L4UDP == config.L4UDPTunnel {
		slog.Warn("l4_udp=tunnel (experimental mix mode): TCP egresses via L4, UDP via a parallel L3 connect-ip tunnel (real WARP IP); the UDP leg is lazy and stays dormant when idle")
		tunnel, cleanup, terr := startL3UDPTunnel(cmd, connectionTimeout, idleTimeout)
		if terr != nil {
			return fmt.Errorf("failed to start L3 UDP tunnel for mix mode: %w", terr)
		}
		defer cleanup()
		udpTunnel = tunnel
	}

	socksRuntime, runtimeMeta, err := prepareL4SocksRuntime(l4Proxy, udpTunnel, connectionTimeout, idleTimeout)
	if err != nil {
		return err
	}

	// L4 is lazy: the shared QUIC connection is established on first dial and
	// auto-reconnected when stale, so the listener can serve immediately. There
	// is no L3 tunnel lifecycle to gate on, so treat the tunnel as always up.
	socksRuntime.SetTunnelUp(true)

	// Best-effort warm-up so a misconfigured enrollment / unreachable endpoint
	// surfaces at startup instead of on the first client request. A failure is
	// non-fatal: the proxy still serves and retries lazily on demand.
	warmCtx, cancel := context.WithTimeout(context.Background(), connectionTimeout)
	if err := l4Proxy.Connect(warmCtx); err != nil {
		slog.Warn("l4 proxy warm-up failed; will retry on demand", "endpoint", endpoint.String(), "error", err)
	}
	cancel()

	readyInfo := proxyReadyInfo{
		endpoint:          endpoint,
		endpointSelector:  endpointSelector,
		transport:         "l4",
		connectionTimeout: connectionTimeout,
		overrides:         overrides,
		configSaved:       configSaved,
		meta:              runtimeMeta,
	}
	return runSocksServer(socksRuntime, idleTimeout, readyInfo)
}

// prepareL4TlsConfig builds the TLS config for the L4 MASQUE proxy endpoint.
// It reuses the same enrollment (client cert + endpoint key pinning) as the L3
// path but pins the L4 proxy SNI, which is a distinct Cloudflare service from
// the connect-ip tunnel. The configured socks.sni_address (an L3 value) is
// intentionally not used here.
func prepareL4TlsConfig() (*tls.Config, error) {
	privKey, err := config.AppConfig.GetEcPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("Failed to get private key: %v", err)
	}
	peerPubKey, err := config.AppConfig.GetEcEndpointPublicKey()
	if err != nil {
		return nil, fmt.Errorf("Failed to get public key: %v", err)
	}
	cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate cert: %v", err)
	}
	tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, internal.L4ConnectSNI)
	if err != nil {
		return nil, fmt.Errorf("Failed to prepare TLS config: %v", err)
	}
	return tlsConfig, nil
}

// selectL4Endpoint reuses the L3 endpoint selection (same Cloudflare MASQUE
// endpoint IPs and custom endpoint pool) but forces the HTTP/3 UDP path.
func selectL4Endpoint() (*net.UDPAddr, func() net.Addr, error) {
	connectPort := config.AppConfig.Socks.ConnectPort
	useIPv6 := config.AppConfig.Socks.UseIPv6

	endpoint, selector, err := selectMasqueEndpoint(connectPort, useIPv6, false)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to select L4 endpoint: %w", err)
	}
	udp, ok := endpoint.(*net.UDPAddr)
	if !ok {
		return nil, nil, fmt.Errorf("l4 mode requires a UDP endpoint, got %T", endpoint)
	}
	return udp, selector, nil
}

// l4QUICConfig builds the QUIC config for the shared L4 connection. Large
// receive windows let a single connection saturate high-BDP links across many
// multiplexed streams; datagrams are disabled (L4 carries no UDP). Unlike the
// upstream usque config, path-MTU discovery is left enabled (seeded by
// InitialPacketSize) to match uscf's proven L3 default rather than pinning a
// fixed packet size.
func l4QUICConfig(keepalivePeriod time.Duration, initialPacketSize uint16) *quic.Config {
	return &quic.Config{
		EnableDatagrams:                false,
		KeepAlivePeriod:                keepalivePeriod,
		InitialPacketSize:              initialPacketSize,
		InitialConnectionReceiveWindow: 10_000_000,
		MaxConnectionReceiveWindow:     10_000_000,
		InitialStreamReceiveWindow:     1_000_000,
		MaxStreamReceiveWindow:         1_000_000,
		MaxIncomingStreams:             100,
		MaxIncomingUniStreams:          100,
	}
}

// logL4Stats periodically logs the L4 proxy's live stream count and cumulative
// fast-fail rejections. It logs at debug normally and bumps to info on any interval
// where saturation occurred (the actionable case), so an operator sees the ceiling
// being hit without enabling debug. Returns when ctx is cancelled.
func logL4Stats(ctx context.Context, l4Proxy *api.L4Proxy) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	var lastRejected uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			inFlight, rejected, ceiling := l4Proxy.Stats()
			if rejected > lastRejected {
				slog.Info("l4 stream stats", "in_flight", inFlight, "observed_stream_ceiling", ceiling, "rejected_total", rejected, "rejected_interval", rejected-lastRejected)
			} else {
				slog.Debug("l4 stream stats", "in_flight", inFlight, "observed_stream_ceiling", ceiling, "rejected_total", rejected)
			}
			lastRejected = rejected
		}
	}
}

// prepareL4SocksRuntime builds the SOCKS runtime backed by the L4 proxy dialer.
// Mirrors prepareSocksRuntime but: DNS is always local (no in-tunnel resolver),
// the SOCKS server is CONNECT-only (TCP), and the upstream dialer routes through
// the L4 QUIC connection while bypass/proxy-port rules still fall back to a
// direct dial.
func prepareL4SocksRuntime(l4Proxy *api.L4Proxy, udpTunnel *l3UDPTunnel, connectionTimeout, idleTimeout time.Duration) (*socksRuntime, socksRuntimeMeta, error) {
	routePolicy, err := newRoutePolicy(config.AppConfig.Socks.BypassDomain, config.AppConfig.Socks.ProxyTCPPort)
	if err != nil {
		return nil, socksRuntimeMeta{}, err
	}
	bypassMatcher := routePolicy.bypassMatcher
	meta := socksRuntimeMeta{
		l4PoolSize:   config.AppConfig.Socks.L4PoolSize,
		l4MaxStreams: config.AppConfig.Socks.L4MaxStreams,
	}
	if routePolicy.ProxyTCPPortsEnabled() {
		meta.proxyTCPPorts = len(routePolicy.proxyTCPPortList)
	} else if bypassMatcher.Enabled() {
		meta.bypassDomains = len(bypassMatcher.domains)
	}

	if config.AppConfig.Socks.RemoteDNS {
		slog.Warn("remote_dns is ignored in L4 mode; resolving names locally")
	}

	// L4 cannot tunnel UDP. "direct" relays UDP ASSOCIATE straight out (bypassing
	// WARP); "tunnel" relays it over the parallel L3 connect-ip leg; "block"
	// (default) refuses it so apps fall back to TCP.
	udpMode := config.AppConfig.Socks.L4UDP
	udpEnabled := udpMode == config.L4UDPDirect || udpMode == config.L4UDPTunnel
	meta.udpMode = udpMode
	if udpEnabled {
		// block_udp_443 applies to both direct and tunnel UDP egress; surface it.
		meta.blockUDP443 = config.AppConfig.Socks.BlockUDP443
	}
	if udpMode == config.L4UDPDirect {
		slog.Warn("l4_udp=direct: SOCKS UDP ASSOCIATE is relayed directly, bypassing WARP — UDP egresses your real IP (only TCP is tunneled)")
	}
	if udpMode == config.L4UDPTunnel && udpTunnel == nil {
		return nil, socksRuntimeMeta{}, fmt.Errorf("l4_udp=tunnel requires an L3 UDP tunnel, but none was provided")
	}

	// L4 has no in-tunnel DNS path (no netstack), so resolution is always local.
	// The CONNECT authority must be an IP literal, which the SOCKS adapter
	// produces by resolving here before dialing.
	localResolver, err := newLocalDNSResolver()
	if err != nil {
		return nil, socksRuntimeMeta{}, err
	}
	resolver := api.NewCachingResolver(localResolver, 10*time.Minute, 5*time.Second, 4096)
	meta.dnsMode = "local"

	upstreamDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		// UDP never goes through the L4 QUIC connection; direct mode routes it via
		// directDial in dialWithTarget below, so reaching here with UDP is a bug.
		if !strings.HasPrefix(network, "tcp") {
			return nil, errL4UDPUnsupported
		}

		dialCtx, cancel := context.WithTimeout(ctx, connectionTimeout)
		defer cancel()

		conn, err := l4Proxy.DialContext(dialCtx, addr)
		if err != nil {
			return nil, err
		}
		return &models.TimeoutConn{
			Conn:        conn,
			IdleTimeout: idleTimeout,
		}, nil
	}

	directDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialCtx, cancel := context.WithTimeout(ctx, connectionTimeout)
		defer cancel()

		dialer := &net.Dialer{}
		conn, err := dialer.DialContext(dialCtx, network, addr)
		if err != nil {
			return nil, err
		}
		return &models.TimeoutConn{
			Conn:        conn,
			IdleTimeout: idleTimeout,
		}, nil
	}

	username := config.AppConfig.Socks.Username
	password := config.AppConfig.Socks.Password
	verbose := config.AppConfig.Logging.SocksVerbose

	runtime := newSocksRuntime(
		upstreamDial,
		func(dialFunc socksDialFunc) socksServer {
			dialWithTarget := func(ctx context.Context, network, addr string, target socksTarget) (net.Conn, error) {
				if strings.HasPrefix(network, "udp") {
					return dialL4UDP(ctx, network, addr, target, udpMode, config.AppConfig.Socks.BlockUDP443, directDial, udpTunnel)
				}
				if !selectTCPRoute(routePolicy, network, target) {
					slog.Debug("route policy selected direct network", "network", network, "host", target.Host, "port", target.Port, "target", addr)
					return directDial(ctx, network, addr)
				}
				return dialFunc(ctx, network, addr)
			}
			// tcpOnly gates UDP ASSOCIATE at SOCKS negotiation: "direct" and "tunnel"
			// advertise (and then relay) UDP; "block" stays CONNECT-only.
			// halfOpenIdle bounds half-open flows so a finished/idle relay cannot pin
			// its QUIC stream on the shared connection for the full idle timeout.
			return createSocksServer(username, password, resolver, dialWithTarget, idleTimeout, config.AppConfig.Socks.L4HalfOpenTimeout.Duration(), verbose, !udpEnabled)
		},
	)
	runtime.SetVerboseLogging(verbose)

	return runtime, meta, nil
}
