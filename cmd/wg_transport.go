package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/HynoR/uscf/config"
	"github.com/HynoR/uscf/internal/netstack"
	"github.com/HynoR/uscf/wireguard"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/device"
)

const (
	// defaultWGEndpointPort is Cloudflare's standard WireGuard UDP port, used
	// when a registration response yields a host without an explicit port.
	defaultWGEndpointPort     = 2408
	defaultWGRunMTU           = 1280
	defaultWGRunKeepalive     = 25
	defaultWGHandshakeTimeout = 10 * time.Second
)

// teamCGNATPrefix / consumerWARPPrefix are used purely for a human-friendly
// startup log annotating which WARP tier the assigned address belongs to.
var (
	teamCGNATPrefix    = netip.MustParsePrefix("100.64.0.0/10")
	consumerWARPPrefix = netip.MustParsePrefix("172.16.0.0/12")
)

// wgTransportParams bundles the tunable WireGuard data-plane knobs. Zero values
// fall back to the package defaults (MTU 1280, 10s handshake wait), so callers
// only set what they want to override.
type wgTransportParams struct {
	mtu              int           // tunnel MTU (<=0 -> defaultWGRunMTU)
	keepalive        int           // PersistentKeepalive seconds (0 disables)
	listenPort       int           // local UDP bind port (0 = random)
	handshakeTimeout time.Duration // how long to wait for the first handshake (<=0 -> default)
}

// runWireGuardTransport brings up an in-process WireGuard data plane from a
// standalone wg account and serves it through the same SOCKS5 layer as the
// MASQUE transports. It is the shared implementation behind `uscf proxy --wg`:
// the caller is responsible for loading config, gating on --experimental, and
// obtaining a validated account (see ensureWGAccount). Health is self-healed in
// place by superviseWireGuard rather than by tearing the tunnel down and
// reconnecting (see step 7).
func runWireGuardTransport(cmd *cobra.Command, account config.WGAccount, flagOverrides []string, params wgTransportParams) error {
	if params.mtu <= 0 {
		params.mtu = defaultWGRunMTU
	}
	if params.handshakeTimeout <= 0 {
		params.handshakeTimeout = defaultWGHandshakeTimeout
	}

	privKey, err := wireguard.NewKey(account.PrivateKey)
	if err != nil {
		return fmt.Errorf("invalid wg account private key: %w", err)
	}

	// 1. Fetch the source device to learn peer/addresses/endpoint.
	device, err := wgGetSourceDeviceFunc(account.DeviceID, account.AccessToken)
	if err != nil {
		return fmt.Errorf("fetch source device: %w", err)
	}
	profileData, err := buildWGProfileData(account, device)
	if err != nil {
		return err
	}

	// 2. Resolve the endpoint to a literal ip:port (the WG bind cannot resolve
	//    hostnames) and validate the peer — fail fast, surfacing the offending
	//    value to aid diagnosis of opaque registration responses.
	endpoint, err := resolveWGEndpointAddrPort(profileData.Endpoint)
	if err != nil {
		return fmt.Errorf("resolve wg endpoint %q: %w", profileData.Endpoint, err)
	}
	if err := wireguard.ValidatePeer(profileData.PublicKey, endpoint.String()); err != nil {
		return fmt.Errorf("invalid wg peer: %w", err)
	}
	peerKey, err := wireguard.NewKey(profileData.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid wg peer public key: %w", err)
	}

	// 3. Normalize the interface addresses into bare addrs for the netstack TUN.
	localAddresses, addrPrefixes, err := wgRunLocalAddresses(profileData)
	if err != nil {
		return err
	}
	dnsAddrs, err := wgRunDNSAddrs()
	if err != nil {
		return err
	}

	// 4. Build the UAPI config and the netstack TUN, then bring WG up.
	uapiConfig, err := wireguard.BuildUAPIConfig(wireguard.UAPIParams{
		PrivateKey:          privKey,
		PublicKey:           peerKey,
		Endpoint:            endpoint.String(),
		PersistentKeepalive: params.keepalive,
		AllowedIPs:          []string{"0.0.0.0/0", "::/0"},
		ListenPort:          params.listenPort,
	})
	if err != nil {
		return err
	}

	if msg, warn := mtuWarning(params.mtu); warn {
		slog.Warn(msg, "mtu", params.mtu)
	}
	tunDev, tunNet, err := netstack.CreateNetTUN(localAddresses, dnsAddrs, params.mtu)
	if err != nil {
		return fmt.Errorf("create virtual TUN device: %w", err)
	}
	defer tunDev.Close()

	verbose := config.AppConfig.Logging.SocksVerbose
	wgDev, err := StartWireGuardTunnel(tunDev, uapiConfig, verbose)
	if err != nil {
		return err
	}
	defer wgDev.Close()

	logWGRunStartup(addrPrefixes, endpoint, params.mtu, params.keepalive)

	// 5. Wait for the first handshake. Serve anyway on timeout, but loudly — a
	//    later keepalive can still complete it, but a slow/failed first request
	//    is the signal something is wrong with the peer/endpoint/credentials.
	if err := waitForWGHandshake(wgDev, params.handshakeTimeout); err != nil {
		slog.Warn("first wireguard handshake not observed; serving anyway (first request may be slow or fail)", "error", err)
	} else {
		slog.Info("wireguard handshake established")
	}

	// 6. Reuse the shared SOCKS layer and serve immediately.
	connectionTimeout, idleTimeout := getTimeoutSettings(cmd)
	socksRuntime, runtimeMeta, err := prepareSocksRuntime(tunNet, connectionTimeout, idleTimeout)
	if err != nil {
		return err
	}
	socksRuntime.SetTunnelUp(true)

	// 7. Reconnect supervisor (runtime parity with L3/L4 self-heal). wireguard-go
	//    re-handshakes transient blips itself but pins the configured endpoint
	//    forever, so a moved WARP edge wedges the session permanently. The
	//    watchdog heals it IN PLACE — re-pointing the peer endpoint via UAPI — so
	//    the netstack TUN and the SOCKS listener layered on top keep serving
	//    across recovery (no device/TUN teardown). It also gates new SOCKS dials
	//    and drains stale ones during an outage, like the MASQUE transports.
	superCtx, stopSupervisor := context.WithCancel(context.Background())
	supervisorDone := make(chan struct{})
	go func() {
		defer close(supervisorDone)
		superviseWireGuard(superCtx, wgDev, account, peerKey, socksRuntime, params.keepalive)
	}()
	// Stop and join the supervisor before recording the final state: it marks the
	// tunnel up on recovery, so a recovery in flight when the server stops would
	// otherwise leave the healthcheck claiming a tunnel that no longer exists.
	defer func() {
		stopSupervisor()
		<-supervisorDone
		socksRuntime.SetTunnelUp(false)
	}()

	readyInfo := proxyReadyInfo{
		connectionTimeout: connectionTimeout,
		socksOnly:         true,
		overrides:         flagOverrides,
		meta:              runtimeMeta,
	}
	return runSocksServer(socksRuntime, idleTimeout, readyInfo)
}

// wgRunLocalAddresses normalizes the source device's interface addresses and
// returns both the bare addrs (for the netstack TUN) and the prefixes (for
// logging). At least one address family is required.
func wgRunLocalAddresses(profileData *wireguard.ProfileData) ([]netip.Addr, []netip.Prefix, error) {
	var addrs []netip.Addr
	var prefixes []netip.Prefix
	for _, raw := range []string{profileData.Address1, profileData.Address2} {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		prefix, err := wireguard.NormalizeInterfaceAddr(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid interface address: %w", err)
		}
		addrs = append(addrs, prefix.Addr())
		prefixes = append(prefixes, prefix)
	}
	if len(addrs) == 0 {
		return nil, nil, fmt.Errorf("wireguard: source device has no usable interface address")
	}
	return addrs, prefixes, nil
}

// wgRunDNSAddrs parses the DNS servers from the shared socks block, falling back
// to Cloudflare's 1.1.1.1 when none are configured.
func wgRunDNSAddrs() ([]netip.Addr, error) {
	var dnsAddrs []netip.Addr
	for _, dns := range config.AppConfig.Socks.DNS {
		dns = strings.TrimSpace(dns)
		if dns == "" {
			continue
		}
		addr, err := netip.ParseAddr(dns)
		if err != nil {
			return nil, fmt.Errorf("parse DNS server %q: %w", dns, err)
		}
		dnsAddrs = append(dnsAddrs, addr)
	}
	if len(dnsAddrs) == 0 {
		dnsAddrs = append(dnsAddrs, netip.MustParseAddr("1.1.1.1"))
	}
	return dnsAddrs, nil
}

// resolveWGEndpointAddrPort turns a possibly-hostname endpoint into a literal
// ip:port. wireguard-go's default bind parses endpoints with
// netip.ParseAddrPort and never resolves DNS, so we must do it here. A missing
// port defaults to Cloudflare's standard WG port.
func resolveWGEndpointAddrPort(endpoint string) (netip.AddrPort, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return netip.AddrPort{}, fmt.Errorf("empty wireguard endpoint")
	}
	if ap, err := netip.ParseAddrPort(endpoint); err == nil {
		return ap, nil
	}

	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		// No port present: assume the default WG port.
		host = strings.Trim(endpoint, "[]")
		port = strconv.Itoa(defaultWGEndpointPort)
	}
	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve %q: %w", endpoint, err)
	}
	ap := udpAddr.AddrPort()
	if !ap.IsValid() {
		return netip.AddrPort{}, fmt.Errorf("resolved %q to an invalid address", endpoint)
	}
	addr := ap.Addr()
	if addr.Is4In6() {
		ap = netip.AddrPortFrom(addr.Unmap(), ap.Port())
	}
	return ap, nil
}

func logWGRunStartup(prefixes []netip.Prefix, endpoint netip.AddrPort, mtu, keepalive int) {
	addrLabels := make([]string, 0, len(prefixes))
	tier := "unknown"
	for _, p := range prefixes {
		addrLabels = append(addrLabels, p.String())
		switch {
		case p.Addr().Is4() && teamCGNATPrefix.Contains(p.Addr()):
			tier = "team(cgnat)"
		case p.Addr().Is4() && consumerWARPPrefix.Contains(p.Addr()):
			tier = "consumer"
		}
	}
	slog.Info("wireguard run starting",
		"addresses", strings.Join(addrLabels, ","),
		"tier", tier,
		"endpoint", endpoint.String(),
		"mtu", mtu,
		"keepalive", keepalive,
	)
}

const (
	// wgWedgeKeepaliveFactor scales keepalive into the no-receive window that
	// flags a wedged session. WARP runs persistent keepalive on its side, so a
	// healthy peer refreshes rx every keepalive interval; 3× leaves slack for a
	// couple of missed beats before declaring the path dead.
	wgWedgeKeepaliveFactor = 3
	// wgMinWedgeWindow floors the wedge window so a tiny or zero keepalive cannot
	// make the detector hair-trigger.
	wgMinWedgeWindow = 60 * time.Second
	// wgMaxPollInterval caps how often the watchdog inspects the device when the
	// keepalive interval is long or disabled.
	wgMaxPollInterval = 15 * time.Second
	// wgInitialRecoveryBackoff / wgMaxRecoveryBackoff bound the gap between
	// successive re-point attempts while a session stays wedged.
	wgInitialRecoveryBackoff = 2 * time.Second
	wgMaxRecoveryBackoff     = 5 * time.Minute
)

// wgHealth is a snapshot of the single peer's UAPI counters used by the wedge
// detector.
type wgHealth struct {
	tx, rx       uint64
	handshakeSec int64
}

// readWGHealth reads the peer's tx/rx byte counters and last handshake time from
// the device's UAPI. ok is false when the device cannot be queried.
func readWGHealth(dev *device.Device) (wgHealth, bool) {
	cfg, err := dev.IpcGet()
	if err != nil {
		return wgHealth{}, false
	}
	return parseWGHealth(cfg), true
}

// parseWGHealth extracts the single peer's counters from a UAPI "get" payload.
func parseWGHealth(cfg string) wgHealth {
	var h wgHealth
	for _, line := range strings.Split(cfg, "\n") {
		switch {
		case strings.HasPrefix(line, "tx_bytes="):
			h.tx, _ = strconv.ParseUint(strings.TrimPrefix(line, "tx_bytes="), 10, 64)
		case strings.HasPrefix(line, "rx_bytes="):
			h.rx, _ = strconv.ParseUint(strings.TrimPrefix(line, "rx_bytes="), 10, 64)
		case strings.HasPrefix(line, "last_handshake_time_sec="):
			h.handshakeSec, _ = strconv.ParseInt(strings.TrimPrefix(line, "last_handshake_time_sec="), 10, 64)
		}
	}
	return h
}

// wgWedged reports whether a no-receive-progress sample is a wedge: the device
// must be actively sending (evidence the path is being exercised) and the last
// receive progress must be older than the window. A silent/idle tunnel (no tx)
// returns false, so it is never falsely declared dead.
func wgWedged(sent bool, sinceProgress, window time.Duration) bool {
	return sent && sinceProgress >= window
}

func nextWGBackoff(d time.Duration) time.Duration {
	n := d * 2
	if n > wgMaxRecoveryBackoff {
		n = wgMaxRecoveryBackoff
	}
	return n
}

// repointWireGuardEndpoint re-fetches the source device and updates the peer's
// endpoint in place (UAPI update_only), so a moved WARP edge is followed without
// tearing down the device, TUN, or SOCKS listener. It is idempotent: re-pointing
// to the same endpoint is harmless.
func repointWireGuardEndpoint(dev *device.Device, account config.WGAccount, peerKey *wireguard.Key) error {
	src, err := wgGetSourceDeviceFunc(account.DeviceID, account.AccessToken)
	if err != nil {
		return fmt.Errorf("fetch source device: %w", err)
	}
	profileData, err := buildWGProfileData(account, src)
	if err != nil {
		return err
	}
	endpoint, err := resolveWGEndpointAddrPort(profileData.Endpoint)
	if err != nil {
		return fmt.Errorf("resolve endpoint %q: %w", profileData.Endpoint, err)
	}
	upd := fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n", peerKey.HexString(), endpoint.String())
	if err := dev.IpcSet(upd); err != nil {
		return fmt.Errorf("update peer endpoint: %w", err)
	}
	slog.Info("wireguard re-pointed peer endpoint", "endpoint", endpoint.String())
	return nil
}

// superviseWireGuard keeps a single WireGuard session healthy without dropping
// the SOCKS listener. It polls the peer counters and declares the session wedged
// when the device is sending (keepalive or user traffic) but receiving nothing
// for a keepalive-scaled window — a signal robust against a healthy idle tunnel,
// since WARP keepalives keep rx advancing. On a wedge it gates new SOCKS dials
// (SetTunnelUp(false)), schedules a drain of stale connections, and repeatedly
// re-points the peer endpoint (with backoff) until receive traffic resumes,
// mirroring the L3/L4 reconnect behavior. It returns when ctx is cancelled.
func superviseWireGuard(ctx context.Context, dev *device.Device, account config.WGAccount, peerKey *wireguard.Key, runtime *socksRuntime, keepalive int) {
	keepaliveDur := time.Duration(keepalive) * time.Second
	wedgeWindow := time.Duration(wgWedgeKeepaliveFactor) * keepaliveDur
	if wedgeWindow < wgMinWedgeWindow {
		wedgeWindow = wgMinWedgeWindow
	}
	poll := keepaliveDur
	if poll <= 0 || poll > wgMaxPollInterval {
		poll = wgMaxPollInterval
	}

	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	prev, _ := readWGHealth(dev)
	lastProgress := time.Now()
	down := false
	var wedgedAt, lastAttempt time.Time
	backoff := wgInitialRecoveryBackoff

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		cur, ok := readWGHealth(dev)
		if !ok {
			continue
		}
		progressed := cur.rx > prev.rx || cur.handshakeSec > prev.handshakeSec
		sent := cur.tx > prev.tx
		prev = cur

		if progressed {
			lastProgress = time.Now()
			if down {
				down = false
				backoff = wgInitialRecoveryBackoff
				runtime.SetTunnelUp(true)
				slog.Info("wireguard recovered", "down_for", time.Since(wedgedAt).Round(time.Second))
			}
			continue
		}

		// No receive progress. Only treat it as a wedge when we are actually
		// sending — a fully idle tunnel with keepalive disabled yields no signal
		// and must stay up.
		if !wgWedged(sent, time.Since(lastProgress), wedgeWindow) {
			continue
		}

		if !down {
			down = true
			wedgedAt = time.Now()
			runtime.SetTunnelUp(false)
			// The wedged session's flows are dead; reset them now so clients retry
			// instead of hanging while we re-point the endpoint.
			runtime.ResetTrackedConns()
			slog.Warn("wireguard session wedged (sending but no response); recovering",
				"no_rx_for", time.Since(lastProgress).Round(time.Second))
		}

		if time.Since(lastAttempt) < backoff {
			continue
		}
		lastAttempt = time.Now()
		if err := repointWireGuardEndpoint(dev, account, peerKey); err != nil {
			slog.Warn("wireguard recovery: endpoint re-point failed; will retry", "error", err, "backoff", backoff)
		} else {
			// Nudge a packet toward the (possibly new) endpoint so the handshake
			// retries promptly instead of waiting for the next keepalive tick.
			dev.SendKeepalivesToPeersWithCurrentKeypair()
		}
		backoff = nextWGBackoff(backoff)
	}
}
