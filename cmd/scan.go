package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"math/rand"
	"net"
	"time"

	"github.com/HynoR/uscf/api"
	"github.com/HynoR/uscf/config"
	"github.com/HynoR/uscf/internal"
	"github.com/HynoR/uscf/scanner"
	"github.com/quic-go/quic-go"
	"github.com/spf13/cobra"
)

var (
	scanGenerateCandidatesFn = scanner.GenerateCandidates
	scanEndpointsFn          = scanner.ScanEndpoints
	scanPickHealthyFn        = scanner.PickRandomHealthy
	scanPrepareTLSConfigFn   = prepareTlsConfig
	scanProbeBuilderFn       = buildConnectIPProbe
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan endpoint candidates and update config",
	Long:  "Scan candidate endpoints for IPv4 or IPv6, write one healthy endpoint to config, then exit.",
	RunE:  runScanCmd,
}

func init() {
	scanCmd.Flags().Bool("ipv4", false, "scan IPv4 endpoints and update endpoint_v4")
	scanCmd.Flags().Bool("ipv6", false, "scan IPv6 endpoints and update endpoint_v6")
	scanCmd.Flags().Duration("timeout", scanner.DefaultScanPerIPTimeout, "timeout per endpoint scan")
	rootCmd.AddCommand(scanCmd)
}

func runScanCmd(cmd *cobra.Command, args []string) error {
	useV4, err := cmd.Flags().GetBool("ipv4")
	if err != nil {
		return fmt.Errorf("failed to parse --ipv4: %w", err)
	}
	useV6, err := cmd.Flags().GetBool("ipv6")
	if err != nil {
		return fmt.Errorf("failed to parse --ipv6: %w", err)
	}

	if useV4 == useV6 {
		return fmt.Errorf("must specify exactly one IP family: --ipv4 or --ipv6")
	}

	timeout, err := cmd.Flags().GetDuration("timeout")
	if err != nil {
		return fmt.Errorf("failed to parse --timeout: %w", err)
	}
	if timeout <= 0 {
		return fmt.Errorf("--timeout must be greater than 0")
	}

	configPath, err := cmd.Flags().GetString("config")
	if err != nil {
		return fmt.Errorf("failed to get config path: %w", err)
	}
	if configPath == "" {
		configPath = "config.json"
	}
	if !config.ConfigLoaded {
		return fmt.Errorf("config not loaded, please provide a valid config file with -c")
	}

	family := scanner.IPFamilyV4
	if useV6 {
		family = scanner.IPFamilyV6
	}

	return scanAndUpdateConfig(cmd, configPath, family, timeout)
}

func scanAndUpdateConfig(cmd *cobra.Command, configPath string, family scanner.IPFamily, timeout time.Duration) error {
	if config.AppConfig.Socks.ConnectPort <= 0 || config.AppConfig.Socks.ConnectPort > 65535 {
		return fmt.Errorf("invalid connect_port in config: %d", config.AppConfig.Socks.ConnectPort)
	}

	tlsConf, err := scanPrepareTLSConfigFn(cmd)
	if err != nil {
		return fmt.Errorf("failed to prepare tls config for scan: %w", err)
	}

	cidrs := scanner.DefaultCIDRsForFamily(family)
	candidates, err := scanGenerateCandidatesFn(
		cidrs,
		config.AppConfig.Socks.ConnectPort,
		family,
		scanner.DefaultSamplePerCIDR,
		rand.New(rand.NewSource(time.Now().UnixNano())),
	)
	if err != nil {
		return fmt.Errorf("failed to generate candidates: %w", err)
	}

	probe := scanProbeBuilderFn(tlsConf)
	quicConf := scanDefaultScanQUICConfig(timeout)

	log.Printf("scan: family=%s candidates=%d timeout=%s", family, len(candidates), timeout)
	results := scanEndpointsFn(
		candidates,
		scanner.WithPerIPTimeout(timeout),
		scanner.WithQUIC(true),
		scanner.WithTLSConfig(tlsConf),
		scanner.WithQUICConfig(quicConf),
		scanner.WithProbe(probe),
	)

	selected, err := scanPickHealthyFn(results, rand.New(rand.NewSource(time.Now().UnixNano())))
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	host, _, err := net.SplitHostPort(selected)
	if err != nil {
		return fmt.Errorf("invalid selected endpoint %q: %w", selected, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("selected endpoint is not an IP address: %s", host)
	}

	switch family {
	case scanner.IPFamilyV4:
		if ip.To4() == nil {
			return fmt.Errorf("selected endpoint is not IPv4: %s", host)
		}
		config.AppConfig.EndpointV4 = host
	case scanner.IPFamilyV6:
		if ip.To4() != nil {
			return fmt.Errorf("selected endpoint is not IPv6: %s", host)
		}
		config.AppConfig.EndpointV6 = host
	default:
		return fmt.Errorf("unsupported family: %s", family)
	}

	if err := config.AppConfig.SaveConfig(configPath); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	log.Printf("scan success: selected=%s, family=%s, config=%s", host, family, configPath)
	return nil
}

func scanDefaultScanQUICConfig(timeout time.Duration) *quic.Config {
	initialPacketSize := config.AppConfig.Socks.InitialPacketSize
	if initialPacketSize == 0 {
		initialPacketSize = 1242
	}
	qc := internal.DefaultQuicConfig(0, initialPacketSize)
	qc.KeepAlivePeriod = 0
	qc.HandshakeIdleTimeout = timeout
	qc.MaxIdleTimeout = timeout
	return qc
}

func buildConnectIPProbe(tlsConf *tls.Config) scanner.ProbeFunc {
	return func(ctx context.Context, endpoint string, o scanner.Options) error {
		udpAddr, err := net.ResolveUDPAddr("udp", endpoint)
		if err != nil {
			return fmt.Errorf("resolve endpoint failed: %w", err)
		}

		quicConf := o.QUICConfig
		if quicConf == nil {
			quicConf = scanDefaultScanQUICConfig(o.PerIPTimeout)
		}

		udpConn, tr, ipConn, rsp, err := api.ConnectTunnel(ctx, tlsConf, quicConf, internal.ConnectURI, udpAddr)
		if ipConn != nil {
			defer ipConn.Close()
		}
		if udpConn != nil {
			defer udpConn.Close()
		}
		if tr != nil {
			defer tr.Close()
		}
		if err != nil {
			return err
		}
		if rsp == nil {
			return fmt.Errorf("connect-ip returned nil response")
		}
		if rsp.StatusCode != 200 {
			return fmt.Errorf("tunnel connection failed: %s", rsp.Status)
		}
		return nil
	}
}
