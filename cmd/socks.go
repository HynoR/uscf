package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/HynoR/uscf/config"
	"github.com/HynoR/uscf/internal/logging"
	"github.com/HynoR/uscf/models"
	"github.com/spf13/cobra"
)

var (
	prepareDirectSocksRuntimeFunc = prepareDirectSocksRuntime
	runSocksServerFunc            = runSocksServer
)

var socksCmd = &cobra.Command{
	Use:   "socks",
	Short: "Run a standalone SOCKS5 server without TUN or MASQUE",
	Long:  "Runs a standalone SOCKS5 server that forwards traffic through the host/container network stack without creating a TUN device or MASQUE tunnel.",
	RunE:  runSocksCmd,
}

func init() {
	socksCmd.Flags().StringP("bind-address", "b", "", "Bind address for SOCKS5 proxy (overrides config file)")
	socksCmd.Flags().StringP("port", "p", "", "Port for SOCKS5 proxy (overrides config file)")
	socksCmd.Flags().StringP("username", "u", "", "Username for SOCKS5 proxy authentication (overrides config file)")
	socksCmd.Flags().StringP("password", "w", "", "Password for SOCKS5 proxy authentication (overrides config file)")
	rootCmd.AddCommand(socksCmd)
}

func runSocksCmd(cmd *cobra.Command, args []string) error {
	if !config.ConfigLoaded {
		configPath, err := cmd.Flags().GetString("config")
		if err != nil {
			return fmt.Errorf("failed to get config path: %w", err)
		}
		if configPath == "" {
			configPath = "config.json"
		}

		if err := config.LoadPublicConfig(configPath); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("failed to load public config %q: %w", configPath, err)
			}
			slog.Info("config file not found, using default SOCKS-only configuration", "path", configPath)
			config.AppConfig = config.Config{
				Socks:   config.GetDefaultSocksConfig(),
				Logging: config.GetDefaultLoggingConfig(),
			}
		}
	}
	config.AppConfig.Logging = logging.Setup(config.AppConfig.Logging)

	_, flagOverrides := applySocksFlagOverrides(cmd, &config.AppConfig)

	if ignored := ignoredSocksOnlySettings(config.AppConfig); len(ignored) > 0 {
		slog.Debug("socks ignores tunnel settings", "fields", strings.Join(ignored, ","))
	}

	connectionTimeout, idleTimeout := getTimeoutSettings(cmd)
	runtime, err := prepareDirectSocksRuntimeFunc(connectionTimeout, idleTimeout)
	if err != nil {
		return err
	}

	readyInfo := proxyReadyInfo{
		connectionTimeout: connectionTimeout,
		overrides:         flagOverrides,
		socksOnly:         true,
		meta:              socksRuntimeMeta{dnsMode: "system"},
	}
	return runSocksServerFunc(runtime, idleTimeout, readyInfo)
}

func prepareDirectSocksRuntime(connectionTimeout, idleTimeout time.Duration) (*socksRuntime, error) {
	localResolver := systemDNSResolver{}

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
		directDial,
		func(dialFunc socksDialFunc) socksServer {
			dialWithTarget := func(ctx context.Context, network, addr string, target socksTarget) (net.Conn, error) {
				return dialFunc(ctx, network, addr)
			}
			return createSocksServer(username, password, localResolver, dialWithTarget, idleTimeout, verbose, false)
		},
	)
	runtime.SetTunnelUp(true)
	runtime.SetVerboseLogging(config.AppConfig.Logging.SocksVerbose)

	return runtime, nil
}

// systemDNSResolver resolves names through the host's default resolver. Used by
// SOCKS-only mode, replacing go-socks5's built-in DNSResolver.
type systemDNSResolver struct{}

func (systemDNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", name)
	if err != nil {
		return ctx, nil, err
	}
	if len(ips) == 0 {
		return ctx, nil, fmt.Errorf("no IP found for %q", name)
	}
	return ctx, ips[0], nil
}

func ignoredSocksOnlySettings(cfg config.Config) []string {
	var ignored []string
	defaults := config.GetDefaultSocksConfig()

	add := func(condition bool, name string) {
		if condition {
			ignored = append(ignored, name)
		}
	}

	add(strings.TrimSpace(cfg.PrivateKey) != "", "private_key")
	add(strings.TrimSpace(cfg.EndpointV4) != "", "endpoint_v4")
	add(strings.TrimSpace(cfg.EndpointV6) != "", "endpoint_v6")
	add(strings.TrimSpace(cfg.EndpointPubKey) != "", "endpoint_pub_key")
	add(strings.TrimSpace(cfg.AccountMode) != "", "account_mode")
	add(strings.TrimSpace(cfg.License) != "", "license")
	add(strings.TrimSpace(cfg.ID) != "", "id")
	add(strings.TrimSpace(cfg.AccessToken) != "", "access_token")
	add(strings.TrimSpace(cfg.IPv4) != "", "ipv4")
	add(strings.TrimSpace(cfg.IPv6) != "", "ipv6")

	add(len(cfg.Socks.BypassDomain) > 0, "bypass_domain")
	add(len(cfg.Socks.ProxyTCPPort) > 0, "proxy_tcp_port")
	add(cfg.Socks.RemoteDNS, "remote_dns")
	add(!sameStringSlice(cfg.Socks.DNS, defaults.DNS), "dns")
	add(cfg.Socks.DNSTimeout.Duration() != defaults.DNSTimeout.Duration(), "dns_timeout")
	add(cfg.Socks.BlockUDP443, "block_udp_443")
	add(cfg.Socks.UseIPv6, "use_ipv6")
	add(cfg.Socks.HTTP2, "http2")
	add(cfg.Socks.L4, "l4")
	add(cfg.Socks.NoTunnelIPv4, "no_tunnel_ipv4")
	add(cfg.Socks.NoTunnelIPv6, "no_tunnel_ipv6")
	add(strings.TrimSpace(cfg.Socks.SNIAddress) != "", "sni_address")
	add(cfg.Socks.ConnectPort != defaults.ConnectPort, "connect_port")
	add(cfg.Socks.KeepalivePeriod.Duration() != defaults.KeepalivePeriod.Duration(), "keepalive_period")
	add(cfg.Socks.MTU != defaults.MTU, "mtu")
	add(cfg.Socks.InitialPacketSize != defaults.InitialPacketSize, "initial_packet_size")
	add(cfg.Socks.ReconnectDelay.Duration() != defaults.ReconnectDelay.Duration(), "reconnect_delay")
	add(cfg.Socks.MaxReconnectAttempts != defaults.MaxReconnectAttempts, "max_reconnect_attempts")
	add(cfg.Socks.DrainGrace.Duration() != defaults.DrainGrace.Duration(), "drain_grace")
	add(cfg.Socks.AlwaysReconnect, "always_reconnect")

	sort.Strings(ignored)
	return ignored
}

func sameStringSlice(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
