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
	"github.com/things-go/go-socks5"
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

	applySocksFlagOverrides(cmd, &config.AppConfig)

	if ignored := ignoredSocksOnlySettings(config.AppConfig); len(ignored) > 0 {
		slog.Info("SOCKS-only mode ignores tunnel-specific settings", "fields", strings.Join(ignored, ","))
	}

	connectionTimeout, idleTimeout := getTimeoutSettings(cmd)
	runtime, err := prepareDirectSocksRuntimeFunc(connectionTimeout, idleTimeout)
	if err != nil {
		return err
	}

	slog.Info("starting SOCKS-only mode without TUN or MASQUE")
	return runSocksServerFunc(runtime, idleTimeout)
}

func prepareDirectSocksRuntime(connectionTimeout, idleTimeout time.Duration) (*socksRuntime, error) {
	localResolver := socks5.DNSResolver{}
	slog.Info("SOCKS-only mode uses the system DNS resolver")

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

	runtime := newSocksRuntime(
		directDial,
		func(dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)) *socks5.Server {
			dialWithRequest := func(ctx context.Context, network, addr string, request *socks5.Request) (net.Conn, error) {
				return dialFunc(ctx, network, addr)
			}
			return createSocksServer(username, password, dialFunc, dialWithRequest, localResolver)
		},
	)
	runtime.SetTunnelUp(true)
	runtime.SetVerboseLogging(config.AppConfig.Logging.SocksVerbose)
	if config.AppConfig.Logging.SocksVerbose {
		slog.Info("SOCKS verbose logging enabled")
	}

	return runtime, nil
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
	add(cfg.Socks.NoTunnelIPv4, "no_tunnel_ipv4")
	add(cfg.Socks.NoTunnelIPv6, "no_tunnel_ipv6")
	add(strings.TrimSpace(cfg.Socks.SNIAddress) != "", "sni_address")
	add(cfg.Socks.ConnectPort != defaults.ConnectPort, "connect_port")
	add(cfg.Socks.KeepalivePeriod.Duration() != defaults.KeepalivePeriod.Duration(), "keepalive_period")
	add(cfg.Socks.MTU != defaults.MTU, "mtu")
	add(cfg.Socks.InitialPacketSize != defaults.InitialPacketSize, "initial_packet_size")
	add(cfg.Socks.ReconnectDelay.Duration() != defaults.ReconnectDelay.Duration(), "reconnect_delay")
	add(cfg.Socks.MaxReconnectAttempts != defaults.MaxReconnectAttempts, "max_reconnect_attempts")
	add(cfg.Socks.SelfCheck, "self_check")

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
