package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/HynoR/uscf/config"
	"github.com/HynoR/uscf/internal/logging"
	"github.com/HynoR/uscf/internal/netstack"
	"github.com/HynoR/uscf/wireguard"
	"github.com/spf13/cobra"
)

const (
	// defaultWGEndpointPort is Cloudflare's standard WireGuard UDP port, used
	// when a registration response yields a host without an explicit port.
	defaultWGEndpointPort = 2408
	defaultWGRunMTU       = 1280
	defaultWGRunKeepalive = 25
)

// teamCGNATPrefix / consumerWARPPrefix are used purely for a human-friendly
// startup log annotating which WARP tier the assigned address belongs to.
var (
	teamCGNATPrefix    = netip.MustParsePrefix("100.64.0.0/10")
	consumerWARPPrefix = netip.MustParsePrefix("172.16.0.0/12")
)

func newWGRunCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "(experimental) Run an in-process WireGuard tunnel and expose it as a SOCKS5 proxy",
		Long: "EXPERIMENTAL. Brings up an in-process WireGuard data plane from a standalone\n" +
			"wg account and serves it through the same SOCKS5 proxy layer as `uscf proxy`.\n" +
			"This does NOT replace `uscf wg generate` (the stable .conf path) and is fully\n" +
			"isolated from MASQUE: a single process runs exactly one transport.\n\n" +
			"Requires --experimental to acknowledge the experimental status.",
		RunE: runWGRunCmd,
	}

	cmd.Flags().String("wg-account", "wg-account.json", "WireGuard account file")
	cmd.Flags().Bool("experimental", false, "Acknowledge and enable the experimental wg run mode")
	cmd.Flags().Int("mtu", defaultWGRunMTU, "Tunnel MTU for the in-process WireGuard interface")
	cmd.Flags().Int("keepalive", defaultWGRunKeepalive, "PersistentKeepalive seconds for the WG peer (0 disables)")
	cmd.Flags().Int("listen-port", 0, "Local UDP port for the WG bind (0 = random)")
	cmd.Flags().Duration("handshake-timeout", 10*time.Second, "How long to wait for the first WG handshake before serving")

	// Proxy-layer overrides (parity with `socks`/`proxy`): the SOCKS listener
	// reads the shared `socks` config block; these let callers/containers
	// override bind/port/auth without editing config.json.
	cmd.Flags().StringP("bind-address", "b", "", "SOCKS5 bind address (overrides config file)")
	cmd.Flags().StringP("port", "p", "", "SOCKS5 port (overrides config file)")
	cmd.Flags().StringP("username", "u", "", "SOCKS5 username (overrides config file)")
	cmd.Flags().StringP("password", "w", "", "SOCKS5 password (overrides config file)")

	return cmd
}

func runWGRunCmd(cmd *cobra.Command, args []string) error {
	if experimental, _ := cmd.Flags().GetBool("experimental"); !experimental {
		return fmt.Errorf("`uscf wg run` is experimental; re-run with --experimental to enable it (the stable path is `uscf wg generate`)")
	}

	// The `wg` subtree is skipped by the root PersistentPreRunE config loader, so
	// load the shared proxy-layer config (the `socks` block) ourselves. wg run
	// reuses that block by design (locked decision: WG run shares the socks
	// block); only the transport differs.
	if !config.ConfigLoaded {
		configPath, _ := cmd.Flags().GetString("config")
		configPath = config.ResolveConfigPath(configPath)
		if err := config.LoadPublicConfig(configPath); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("load config %q: %w", configPath, err)
			}
			slog.Info("config file not found, using default SOCKS configuration", "path", configPath)
			config.AppConfig = config.Config{
				Socks:   config.GetDefaultSocksConfig(),
				Logging: config.GetDefaultLoggingConfig(),
			}
		}
	}
	config.AppConfig.Logging = logging.Setup(config.AppConfig.Logging)
	_, flagOverrides := applySocksFlagOverrides(cmd, &config.AppConfig)

	accountPath, _ := cmd.Flags().GetString("wg-account")
	mtu, _ := cmd.Flags().GetInt("mtu")
	keepalive, _ := cmd.Flags().GetInt("keepalive")
	listenPort, _ := cmd.Flags().GetInt("listen-port")
	handshakeTimeout, _ := cmd.Flags().GetDuration("handshake-timeout")

	slog.Warn("wg run is EXPERIMENTAL and not for production; `uscf wg generate` remains the stable path")

	// 1. Load + validate the standalone WG account (same source as wg generate).
	account, err := wgLoadAccountFunc(accountPath)
	if err != nil {
		return fmt.Errorf("load wg account: %w", err)
	}
	if err := account.Validate(); err != nil {
		return fmt.Errorf("invalid wg account: %w", err)
	}
	privKey, err := wireguard.NewKey(account.PrivateKey)
	if err != nil {
		return fmt.Errorf("invalid wg account private key: %w", err)
	}

	// 2. Fetch the source device to learn peer/addresses/endpoint.
	device, err := wgGetSourceDeviceFunc(account.DeviceID, account.AccessToken)
	if err != nil {
		return fmt.Errorf("fetch source device: %w", err)
	}
	profileData, err := buildWGProfileData(account, device)
	if err != nil {
		return err
	}

	// 3. Resolve the endpoint to a literal ip:port (the WG bind cannot resolve
	//    hostnames) and validate the peer (item K) — fail fast, surfacing the
	//    offending value to aid diagnosis of opaque registration responses.
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

	// 4. Normalize the interface addresses (item J) into bare addrs for the
	//    netstack TUN.
	localAddresses, addrPrefixes, err := wgRunLocalAddresses(profileData)
	if err != nil {
		return err
	}
	dnsAddrs, err := wgRunDNSAddrs()
	if err != nil {
		return err
	}

	// 5. Build the UAPI config and the netstack TUN, then bring WG up.
	uapiConfig, err := wireguard.BuildUAPIConfig(wireguard.UAPIParams{
		PrivateKey:          privKey,
		PublicKey:           peerKey,
		Endpoint:            endpoint.String(),
		PersistentKeepalive: keepalive,
		AllowedIPs:          []string{"0.0.0.0/0", "::/0"},
		ListenPort:          listenPort,
	})
	if err != nil {
		return err
	}

	if msg, warn := mtuWarning(mtu); warn {
		slog.Warn(msg, "mtu", mtu)
	}
	tunDev, tunNet, err := netstack.CreateNetTUN(localAddresses, dnsAddrs, mtu)
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

	logWGRunStartup(addrPrefixes, endpoint, mtu, keepalive)

	// 6. Wait for the first handshake. PoC behavior: serve anyway on timeout,
	//    but loudly — a missing handshake is the whole point of the smoke test.
	if err := waitForWGHandshake(wgDev, handshakeTimeout); err != nil {
		slog.Warn("first wireguard handshake not observed; serving anyway (first request may be slow or fail)", "error", err)
	} else {
		slog.Info("wireguard handshake established")
	}

	// 7. Reuse the shared SOCKS layer (locked decision: WG run reads the same
	//    `socks` proxy-layer config block as MASQUE). The transport is the only
	//    thing that differs, and the tunnel is single-shot in the PoC: no
	//    MASQUE reconnect supervisor, so we mark the gate up ourselves.
	connectionTimeout, idleTimeout := getTimeoutSettings(cmd)
	socksRuntime, runtimeMeta, err := prepareSocksRuntime(tunNet, connectionTimeout, idleTimeout)
	if err != nil {
		return err
	}
	socksRuntime.SetTunnelUp(true)
	writeTunnelStateSafe(tunnelStateUp)
	defer writeTunnelStateSafe(tunnelStateDown)

	readyInfo := proxyReadyInfo{
		connectionTimeout: connectionTimeout,
		socksOnly:         true,
		overrides:         flagOverrides,
		meta:              runtimeMeta,
	}
	return runSocksServer(socksRuntime, idleTimeout, readyInfo)
}

// wgRunLocalAddresses normalizes the source device's interface addresses (item
// J) and returns both the bare addrs (for the netstack TUN) and the prefixes
// (for logging). At least one address family is required.
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
		return nil, nil, fmt.Errorf("wg run: source device has no usable interface address")
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
