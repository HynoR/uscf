package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/HynoR/uscf/models"

	"github.com/HynoR/uscf/api"
	"github.com/HynoR/uscf/config"
	"github.com/HynoR/uscf/internal"
	"github.com/spf13/cobra"
	"github.com/things-go/go-socks5"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// proxyCmd 命令，结合 socks 和 register 的功能
var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "One-command solution to run SOCKS5 proxy with auto-registration",
	Long:  "Automatically registers if no config exists, then runs a dual-stack SOCKS5 proxy with optional authentication.",
	RunE:  runProxyCmd,
}

var (
	registerAccountFunc = api.Register
	enrollKeyFunc       = api.EnrollKey
	rebindLicenseFunc   = api.RebindLicense
)

func init() {
	// 初始化 proxy 命令的参数

	// 只保留必要的注册相关参数，其他参数已转移到配置文件
	proxyCmd.Flags().String("locale", internal.DefaultLocale, "Locale for registration")
	proxyCmd.Flags().String("model", internal.DefaultModel, "Model for registration")
	proxyCmd.Flags().String("name", "", "Device name for registration")
	proxyCmd.Flags().Bool("accept-tos", true, "Automatically accept Cloudflare TOS")
	proxyCmd.Flags().String("jwt", "", "Team token for registration")
	proxyCmd.Flags().String("license", "", "WARP+ license key to bind to the account")

	// 添加重置SOCKS5配置的标志
	proxyCmd.Flags().Bool("reset-config", false, "Reset SOCKS5 configuration to default values")

	// 添加SOCKS5代理配置的命令行参数
	proxyCmd.Flags().StringP("bind-address", "b", "", "Bind address for SOCKS5 proxy (overrides config file)")
	proxyCmd.Flags().StringP("port", "p", "", "Port for SOCKS5 proxy (overrides config file)")
	proxyCmd.Flags().StringP("username", "u", "", "Username for SOCKS5 proxy authentication (overrides config file)")
	proxyCmd.Flags().StringP("password", "w", "", "Password for SOCKS5 proxy authentication (overrides config file)")

	// 添加提示，说明SOCKS配置已移至配置文件，但可通过命令行参数覆盖
	proxyCmd.Long += "\n\nNote: All SOCKS proxy settings are primarily managed through the config file, but can be overridden with command-line flags."

	// 把 proxyCmd 注册到根命令
	rootCmd.AddCommand(proxyCmd)
}

// runProxyCmd 是 proxyCmd 的执行逻辑
func runProxyCmd(cmd *cobra.Command, args []string) error {
	// 0. 获取配置文件路径
	configPath, err := cmd.Flags().GetString("config")
	if err != nil {
		return fmt.Errorf("failed to get config path: %w", err)
	}
	if configPath == "" {
		configPath = "config.json"
	}
	customLicense, _ := cmd.Flags().GetString("license")
	customLicense = strings.TrimSpace(customLicense)

	// 检查是否需要重置SOCKS5配置
	resetConfig, _ := cmd.Flags().GetBool("reset-config")
	registeredThisRun := false

	// 1. 如有需要，进行自动注册
	if !config.ConfigLoaded {
		if err := handleRegistration(cmd, configPath, customLicense); err != nil {
			return err
		}
		registeredThisRun = true

		// 更新一些需要从内部常量获取的配置值
		config.AppConfig.Socks.SNIAddress = internal.ConnectSNI

		// 保存更新后的配置
		if err := config.AppConfig.SaveConfig(configPath); err != nil {
			slog.Warn("failed to save updated config", "path", configPath, "error", err)
		}
	} else if resetConfig {
		// 如果已加载配置且指定了reset-config标志，则重置SOCKS5配置
		slog.Info("resetting SOCKS5 configuration to defaults")

		// 保存当前的SNI地址，因为它取决于内部常量
		sniAddress := config.AppConfig.Socks.SNIAddress

		// 重置为默认配置
		config.AppConfig.Socks = config.GetDefaultSocksConfig()

		// 恢复SNI地址
		config.AppConfig.Socks.SNIAddress = sniAddress

		// 保存更新后的配置
		if err := config.AppConfig.SaveConfig(configPath); err != nil {
			slog.Warn("failed to save reset config", "path", configPath, "error", err)
			return fmt.Errorf("failed to save reset configuration: %w", err)
		}
		slog.Info("SOCKS5 configuration reset to defaults", "path", configPath)
	}

	// 对已有配置场景，允许用户主动更新 license。
	if config.ConfigLoaded && !registeredThisRun && customLicense != "" {
		if err := applyCustomLicense(configPath, customLicense); err != nil {
			return err
		}
	}

	// 检查并应用命令行参数覆盖配置文件的值
	configChanged := false

	// 检查绑定地址
	if bindAddress, _ := cmd.Flags().GetString("bind-address"); bindAddress != "" {
		slog.Info("overriding bind address from command line", "bind_address", bindAddress)
		config.AppConfig.Socks.BindAddress = bindAddress
		configChanged = true
	}

	// 检查端口
	if port, _ := cmd.Flags().GetString("port"); port != "" {
		slog.Info("overriding port from command line", "port", port)
		config.AppConfig.Socks.Port = port
		configChanged = true
	}

	// 检查用户名
	if username, _ := cmd.Flags().GetString("username"); username != "" {
		slog.Info("overriding username from command line")
		config.AppConfig.Socks.Username = username
		configChanged = true
	}

	// 检查密码
	if password, _ := cmd.Flags().GetString("password"); password != "" {
		slog.Info("overriding password from command line")
		config.AppConfig.Socks.Password = password
		configChanged = true
	}

	// 如果配置有变更，保存到配置文件
	if configChanged {
		slog.Info("saving updated configuration", "path", configPath)
		if err := config.AppConfig.SaveConfig(configPath); err != nil {
			slog.Warn("failed to save updated config", "path", configPath, "error", err)
		}
	}

	// 2. 启动 SOCKS5 代理
	if err := setupAndRunSocksProxy(cmd); err != nil {
		return err
	}

	return nil
}

// handleRegistration 处理自动注册流程
func handleRegistration(cmd *cobra.Command, configPath, customLicense string) error {
	slog.Info("config not loaded, starting automatic registration")

	// 获取注册参数
	deviceName, _ := cmd.Flags().GetString("name")
	locale, _ := cmd.Flags().GetString("locale")
	model, _ := cmd.Flags().GetString("model")
	acceptTos, _ := cmd.Flags().GetBool("accept-tos")
	jwt, _ := cmd.Flags().GetString("jwt")

	slog.Info("registering account", "locale", locale, "model", model)

	// 注册账户
	accountData, err := registerAccountFunc(model, locale, jwt, acceptTos)
	if err != nil {
		return fmt.Errorf("Failed to register: %v", err)
	}

	if customLicense != "" {
		slog.Info("fetching remote account license")
		finalAccount, changed, apiErr, err := rebindLicenseFunc(accountData, customLicense)
		if err != nil {
			if apiErr != nil {
				return fmt.Errorf("Failed to apply license: %v (API errors: %s)", err, apiErr.ErrorsAsString("; "))
			}
			return fmt.Errorf("Failed to apply license: %v", err)
		}
		if changed {
			slog.Info("remote license differs, updating via PUT")
			slog.Info("license update completed")
		} else {
			slog.Info("remote license already matches target")
		}
		accountData.Account.License = finalAccount.License
	}

	// 生成密钥对
	privKey, pubKey, err := internal.GenerateEcKeyPair()
	if err != nil {
		return fmt.Errorf("Failed to generate key pair: %v", err)
	}

	slog.Info("enrolling device key")

	// 注册设备密钥
	updatedAccountData, apiErr, err := enrollKeyFunc(accountData, pubKey, deviceName)
	if err != nil {
		if apiErr != nil {
			return fmt.Errorf("Failed to enroll key: %v (API errors: %s)", err, apiErr.ErrorsAsString("; "))
		}
		return fmt.Errorf("Failed to enroll key: %v", err)
	}

	slog.Info("registration successful, saving config")

	if len(updatedAccountData.Config.Peers) == 0 {
		return fmt.Errorf("Failed to save config: register response has no peers")
	}
	peer := updatedAccountData.Config.Peers[0]

	endpointV4, err := parseEndpointHost(peer.Endpoint.V4)
	if err != nil {
		return fmt.Errorf("Failed to parse IPv4 endpoint: %v", err)
	}
	endpointV6, err := parseEndpointHost(peer.Endpoint.V6)
	if err != nil {
		return fmt.Errorf("Failed to parse IPv6 endpoint: %v", err)
	}

	// 保存配置，使用InitNewConfig创建带有默认值的配置
	config.AppConfig = config.InitNewConfig(
		base64.StdEncoding.EncodeToString(privKey),
		endpointV4,
		endpointV6,
		peer.PublicKey,
		pickAccountLicense(updatedAccountData, accountData, customLicense),
		updatedAccountData.ID,
		accountData.Token,
		updatedAccountData.Config.Interface.Addresses.V4,
		updatedAccountData.Config.Interface.Addresses.V6,
		deviceName,
	)

	err = config.AppConfig.SaveConfig(configPath)
	if err != nil {
		return fmt.Errorf("Failed to save config: %v", err)
	}

	slog.Info("config saved", "path", configPath)

	// 标记配置已加载
	config.ConfigLoaded = true
	return nil
}

func applyCustomLicense(configPath, customLicense string) error {
	if config.AppConfig.ID == "" || config.AppConfig.AccessToken == "" {
		return fmt.Errorf("Failed to apply license: missing id/access_token in config")
	}

	accountData := models.AccountData{
		ID:    config.AppConfig.ID,
		Token: config.AppConfig.AccessToken,
	}

	slog.Info("fetching remote account license")
	finalAccount, changed, apiErr, err := rebindLicenseFunc(accountData, customLicense)
	if err != nil {
		if apiErr != nil {
			return fmt.Errorf("Failed to apply license: %v (API errors: %s)", err, apiErr.ErrorsAsString("; "))
		}
		return fmt.Errorf("Failed to apply license: %v", err)
	}
	if changed {
		slog.Info("remote license differs, updating via PUT")
		slog.Info("license update completed")
		slog.Info("re-enrolling current MASQUE key after license change")
		if err := reenrollCurrentMasqueKey(); err != nil {
			return err
		}
	} else {
		slog.Info("remote license already matches target")
	}

	config.AppConfig.License = finalAccount.License
	if err := config.AppConfig.SaveConfig(configPath); err != nil {
		return fmt.Errorf("Failed to save config after license update: %v", err)
	}
	slog.Info("license updated successfully")

	return nil
}

func reenrollCurrentMasqueKey() error {
	privKey, err := config.AppConfig.GetEcPrivateKey()
	if err != nil {
		return fmt.Errorf("Failed to get private key for re-enroll: %v", err)
	}

	pubKey, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return fmt.Errorf("Failed to marshal public key for re-enroll: %v", err)
	}

	accountData := models.AccountData{
		ID:    config.AppConfig.ID,
		Token: config.AppConfig.AccessToken,
	}

	updatedAccountData, apiErr, err := enrollKeyFunc(accountData, pubKey, config.AppConfig.Registration.DeviceName)
	if err != nil {
		if apiErr != nil {
			return fmt.Errorf("Failed to re-enroll key after license update: %v (API errors: %s)", err, apiErr.ErrorsAsString("; "))
		}
		return fmt.Errorf("Failed to re-enroll key after license update: %v", err)
	}

	if len(updatedAccountData.Config.Peers) == 0 {
		return fmt.Errorf("Failed to re-enroll key after license update: response has no peers")
	}

	peer := updatedAccountData.Config.Peers[0]
	endpointV4, err := parseEndpointHost(peer.Endpoint.V4)
	if err != nil {
		return fmt.Errorf("Failed to parse IPv4 endpoint after re-enroll: %v", err)
	}
	endpointV6, err := parseEndpointHost(peer.Endpoint.V6)
	if err != nil {
		return fmt.Errorf("Failed to parse IPv6 endpoint after re-enroll: %v", err)
	}

	config.AppConfig.EndpointV4 = endpointV4
	config.AppConfig.EndpointV6 = endpointV6
	config.AppConfig.EndpointPubKey = peer.PublicKey
	config.AppConfig.IPv4 = updatedAccountData.Config.Interface.Addresses.V4
	config.AppConfig.IPv6 = updatedAccountData.Config.Interface.Addresses.V6
	if updatedAccountData.ID != "" {
		config.AppConfig.ID = updatedAccountData.ID
	}

	return nil
}

func pickAccountLicense(primary models.AccountData, fallback models.AccountData, customLicense string) string {
	if primary.Account.License != "" {
		return primary.Account.License
	}
	if fallback.Account.License != "" {
		return fallback.Account.License
	}
	return customLicense
}

func parseEndpointHost(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", fmt.Errorf("empty endpoint")
	}

	// Most API responses are host:port or [host]:port.
	if host, _, err := net.SplitHostPort(endpoint); err == nil {
		host = strings.Trim(host, "[]")
		if addr, parseErr := netip.ParseAddr(host); parseErr == nil {
			return addr.String(), nil
		}
		return host, nil
	}

	// Some responses may contain a bare address without port.
	trimmed := strings.Trim(endpoint, "[]")
	if addr, err := netip.ParseAddr(trimmed); err == nil {
		return addr.String(), nil
	}

	// Handle non-bracketed IPv6 with trailing ":port" defensively.
	if strings.Count(endpoint, ":") > 1 {
		lastColon := strings.LastIndex(endpoint, ":")
		if lastColon > 0 && lastColon < len(endpoint)-1 {
			hostPart := endpoint[:lastColon]
			portPart := endpoint[lastColon+1:]
			if _, err := strconv.Atoi(portPart); err == nil {
				if addr, parseErr := netip.ParseAddr(hostPart); parseErr == nil {
					return addr.String(), nil
				}
			}
		}
	}

	return "", fmt.Errorf("unsupported endpoint format: %q", endpoint)
}

func udpAddrFromHost(host string, port int, useIPv6 bool) (*net.UDPAddr, error) {
	normalizedHost, err := parseEndpointHost(host)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(normalizedHost)
	if ip == nil {
		return nil, fmt.Errorf("invalid endpoint IP: %q", normalizedHost)
	}
	if useIPv6 && ip.To4() != nil {
		return nil, fmt.Errorf("expected IPv6 endpoint, got IPv4: %s", normalizedHost)
	}
	if !useIPv6 && ip.To4() == nil {
		return nil, fmt.Errorf("expected IPv4 endpoint, got IPv6: %s", normalizedHost)
	}

	return &net.UDPAddr{IP: ip, Port: port}, nil
}

func buildCustomEndpointPool(customHosts []string, port int, useIPv6 bool) []*net.UDPAddr {
	candidates := make([]*net.UDPAddr, 0, len(customHosts))
	seen := make(map[string]struct{})
	for _, raw := range customHosts {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}

		addr, err := udpAddrFromHost(raw, port, useIPv6)
		if err != nil {
			slog.Warn("ignoring invalid custom endpoint", "endpoint", raw, "error", err)
			continue
		}

		key := addr.IP.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		candidates = append(candidates, addr)
	}

	return candidates
}

func newEndpointSelector(candidates []*net.UDPAddr) func() *net.UDPAddr {
	if len(candidates) == 0 {
		return nil
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var mu sync.Mutex

	return func() *net.UDPAddr {
		mu.Lock()
		idx := rng.Intn(len(candidates))
		selected := candidates[idx]
		mu.Unlock()

		return &net.UDPAddr{
			IP:   append(net.IP(nil), selected.IP...),
			Port: selected.Port,
		}
	}
}

func familyLabel(useIPv6 bool) string {
	if useIPv6 {
		return "ipv6"
	}
	return "ipv4"
}

func normalizeDNSServerAddress(dns string) (string, error) {
	dns = strings.TrimSpace(dns)
	if dns == "" {
		return "", fmt.Errorf("empty DNS server")
	}

	if host, port, err := net.SplitHostPort(dns); err == nil {
		if host == "" {
			return "", fmt.Errorf("missing DNS host in %q", dns)
		}
		portNumber, convErr := strconv.Atoi(port)
		if convErr != nil || portNumber <= 0 || portNumber > 65535 {
			return "", fmt.Errorf("invalid DNS port in %q", dns)
		}
		return net.JoinHostPort(host, port), nil
	}

	trimmed := strings.Trim(dns, "[]")
	if addr, err := netip.ParseAddr(trimmed); err == nil {
		return net.JoinHostPort(addr.String(), "53"), nil
	}

	// Allow domain names without port and default to 53.
	if !strings.Contains(dns, ":") {
		return net.JoinHostPort(dns, "53"), nil
	}

	return "", fmt.Errorf("invalid DNS server address %q", dns)
}

// setupAndRunSocksProxy 设置并运行SOCKS5代理
func setupAndRunSocksProxy(cmd *cobra.Command) error {
	slog.Info("preparing SOCKS5 proxy")

	// 设置最大并发处理能力
	runtime.GOMAXPROCS(runtime.NumCPU())

	// 准备TLS配置
	tlsConfig, err := prepareTlsConfig(cmd)
	if err != nil {
		return err
	}

	// 准备网络配置
	endpoint, endpointSelector, localAddresses, dnsAddrs, err := prepareNetworkConfig(cmd)
	if err != nil {
		return err
	}

	// 获取超时设置
	connectionTimeout, idleTimeout := getTimeoutSettings(cmd)

	// 创建TUN设备
	tunDev, tunNet, err := createTunDevice(localAddresses, dnsAddrs, cmd)
	if err != nil {
		return err
	}
	defer tunDev.Close()

	// 准备SOCKS运行时
	socksRuntime, err := prepareSocksRuntime(tunNet, connectionTimeout, idleTimeout)
	if err != nil {
		return err
	}

	// 配置连接并启动隧道
	readyCh := startTunnel(cmd, tlsConfig, endpoint, endpointSelector, tunDev, tunNet, socksRuntime)

	slog.Info("waiting for MASQUE connection before starting SOCKS5 proxy listener")
	<-readyCh
	slog.Info("MASQUE connection established, starting SOCKS5 proxy listener")

	// 创建并启动SOCKS服务器
	return runSocksServer(socksRuntime, idleTimeout)
}

// prepareTlsConfig 准备TLS配置
func prepareTlsConfig(cmd *cobra.Command) (*tls.Config, error) {
	// 从配置中获取SNI地址
	sni := config.AppConfig.Socks.SNIAddress
	if sni == "" {
		sni = internal.ConnectSNI
	}

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

	tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, sni)
	if err != nil {
		return nil, fmt.Errorf("Failed to prepare TLS config: %v", err)
	}
	return tlsConfig, nil
}

// prepareNetworkConfig 准备网络配置
func prepareNetworkConfig(cmd *cobra.Command) (*net.UDPAddr, func() *net.UDPAddr, []netip.Addr, []netip.Addr, error) {
	// 从配置文件获取连接端口
	connectPort := config.AppConfig.Socks.ConnectPort

	useIPv6 := config.AppConfig.Socks.UseIPv6
	fallbackHost := config.AppConfig.EndpointV4
	customHosts := config.AppConfig.CustomEndpointsV4
	if useIPv6 {
		fallbackHost = config.AppConfig.EndpointV6
		customHosts = config.AppConfig.CustomEndpointsV6
	}

	fallbackEndpoint, err := udpAddrFromHost(fallbackHost, connectPort, useIPv6)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to parse fallback endpoint: %w", err)
	}

	candidateEndpoints := buildCustomEndpointPool(customHosts, connectPort, useIPv6)
	var endpointSelector func() *net.UDPAddr
	if len(candidateEndpoints) > 0 {
		endpointSelector = newEndpointSelector(candidateEndpoints)
		slog.Info("custom endpoint pool enabled", "family", familyLabel(useIPv6), "count", len(candidateEndpoints))
	} else if len(customHosts) > 0 {
		slog.Warn("custom endpoint list configured but no valid entries; using fallback endpoint", "family", familyLabel(useIPv6))
	}

	// 隧道内IP设置
	var localAddresses []netip.Addr
	if !config.AppConfig.Socks.NoTunnelIPv4 {
		v4, err := netip.ParseAddr(config.AppConfig.IPv4)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("Failed to parse IPv4 address: %v", err)
		}
		localAddresses = append(localAddresses, v4)
	}
	if !config.AppConfig.Socks.NoTunnelIPv6 {
		v6, err := netip.ParseAddr(config.AppConfig.IPv6)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("Failed to parse IPv6 address: %v", err)
		}
		localAddresses = append(localAddresses, v6)
	}

	// DNS设置
	var dnsAddrs []netip.Addr
	for _, dns := range config.AppConfig.Socks.DNS {
		addr, err := netip.ParseAddr(dns)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("Failed to parse DNS server: %v", err)
		}
		dnsAddrs = append(dnsAddrs, addr)
	}

	return fallbackEndpoint, endpointSelector, localAddresses, dnsAddrs, nil
}

// getTimeoutSettings 获取超时设置
func getTimeoutSettings(cmd *cobra.Command) (time.Duration, time.Duration) {
	// 直接从配置文件中读取超时设置
	connectionTimeout := config.AppConfig.Socks.ConnectionTimeout.Duration()
	idleTimeout := config.AppConfig.Socks.IdleTimeout.Duration()

	// 确保设置了默认值
	if connectionTimeout == 0 {
		connectionTimeout = 30 * time.Second
	}

	if idleTimeout == 0 {
		idleTimeout = 5 * time.Minute
	}

	return connectionTimeout, idleTimeout
}

// createTunDevice 创建TUN设备
func createTunDevice(localAddresses, dnsAddrs []netip.Addr, cmd *cobra.Command) (tun.Device, *netstack.Net, error) {
	// 从配置中获取MTU
	mtu := config.AppConfig.Socks.MTU
	if mtu != 1280 {
		slog.Warn("MTU is not default 1280; packet loss or other issues may occur", "mtu", mtu)
	}

	tunDev, tunNet, err := netstack.CreateNetTUN(localAddresses, dnsAddrs, mtu)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create virtual TUN device: %v", err)
	}
	return tunDev, tunNet, nil
}

// startTunnel 配置并启动隧道连接
func startTunnel(cmd *cobra.Command, tlsConfig *tls.Config, endpoint *net.UDPAddr, endpointSelector func() *net.UDPAddr, tunDev tun.Device, tunNet *netstack.Net, socksRuntime *socksRuntime) <-chan struct{} {
	readyCh := make(chan struct{})
	var readyOnce sync.Once

	// 从配置文件读取隧道参数
	keepalivePeriod := config.AppConfig.Socks.KeepalivePeriod.Duration()
	initialPacketSize := config.AppConfig.Socks.InitialPacketSize
	mtu := config.AppConfig.Socks.MTU
	reconnectDelay := config.AppConfig.Socks.ReconnectDelay.Duration()
	maxReconnectAttempts := config.AppConfig.Socks.MaxReconnectAttempts

	configTunnel := api.ConnectionConfig{
		TLSConfig:            tlsConfig,
		KeepAlivePeriod:      keepalivePeriod,
		InitialPacketSize:    initialPacketSize,
		Endpoint:             endpoint,
		EndpointSelector:     endpointSelector,
		MTU:                  mtu,
		MaxPacketRate:        8192,
		MaxBurst:             1024,
		MaxReconnectAttempts: maxReconnectAttempts,
		SelfCheckEnabled:     config.AppConfig.Socks.SelfCheck,
		SelfCheckDialFunc:    tunNet.DialContext,
		ReconnectStrategy: &api.ExponentialBackoff{
			InitialDelay: reconnectDelay,
			MaxDelay:     5 * time.Minute,
			Factor:       2.0,
		},
		OnConnected: func() {
			if socksRuntime != nil {
				socksRuntime.SetTunnelUp(true)
			}
			readyOnce.Do(func() {
				close(readyCh)
			})
		},
		OnDisconnected: func(err error) {
			if socksRuntime == nil {
				return
			}
			socksRuntime.SetTunnelUp(false)
			slog.Warn("tunnel down", "error", err)
			socksRuntime.RestartAndDrain(err)
		},
	}

	go api.MaintainTunnel(
		context.Background(),
		configTunnel,
		api.NewNetstackAdapter(tunDev),
	)

	return readyCh
}

// prepareSocksRuntime 创建SOCKS运行时，包括解析器、拨号器和可重建的server工厂
func prepareSocksRuntime(tunNet *netstack.Net, connectionTimeout, idleTimeout time.Duration) (*socksRuntime, error) {
	// 根据配置选择DNS解析器
	var resolver socks5.NameResolver
	if config.AppConfig.Socks.RemoteDNS {
		// 使用TunnelDNSResolver，让DNS通过TUN隧道
		slog.Info("using remote DNS resolver through TUN tunnel")

		// 解析DNS服务器地址
		var dnsAddrs []netip.Addr
		for _, dns := range config.AppConfig.Socks.DNS {
			addr, err := netip.ParseAddr(dns)
			if err != nil {
				return nil, fmt.Errorf("Failed to parse DNS server %s: %v", dns, err)
			}
			dnsAddrs = append(dnsAddrs, addr)
		}

		resolver = api.NewTunnelDNSResolver(tunNet, dnsAddrs, config.AppConfig.Socks.DNSTimeout.Duration())
	} else {
		// 使用本地DNS解析器
		slog.Info("using local DNS resolver")
		dnsTimeout := config.AppConfig.Socks.DNSTimeout.Duration()
		if len(config.AppConfig.Socks.DNS) > 0 {
			dnsServer, err := normalizeDNSServerAddress(config.AppConfig.Socks.DNS[0])
			if err != nil {
				return nil, fmt.Errorf("Failed to parse local DNS server %s: %v", config.AppConfig.Socks.DNS[0], err)
			}
			resolver = api.NewCachingDNSResolver(
				dnsServer,
				dnsTimeout,
			)
		} else {
			resolver = api.NewCachingDNSResolver(
				"8.8.8.8:53",
				dnsTimeout,
			)
		}

	}

	if config.AppConfig.Socks.BlockUDP443 {
		slog.Info("UDP/443 blocking enabled; outbound QUIC/UDP will be rejected")
	}

	// 仅负责实际拨号，不做隧道状态门控；门控由socksRuntime统一处理。
	upstreamDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if config.AppConfig.Socks.BlockUDP443 && strings.HasPrefix(network, "udp") {
			_, port, err := net.SplitHostPort(addr)
			if err == nil && port == "443" {
				return nil, fmt.Errorf("udp/443 blocked by config")
			}
		}

		dialCtx, cancel := context.WithTimeout(ctx, connectionTimeout)
		defer cancel()

		conn, err := tunNet.DialContext(dialCtx, network, addr)
		if err != nil {
			return nil, err
		}

		return &models.TimeoutConn{
			Conn:        conn,
			IdleTimeout: idleTimeout,
		}, nil
	}

	// 从配置中获取身份验证设置
	username := config.AppConfig.Socks.Username
	password := config.AppConfig.Socks.Password

	return newSocksRuntime(
		upstreamDial,
		func(dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)) *socks5.Server {
			return createSocksServer(username, password, dialFunc, resolver)
		},
	), nil
}

// runSocksServer 创建并运行SOCKS5服务器
func runSocksServer(socksRuntime *socksRuntime, idleTimeout time.Duration) error {
	// 从配置中获取网络参数
	bindAddress := config.AppConfig.Socks.BindAddress
	port := config.AppConfig.Socks.Port

	// 启动监听
	slog.Info(
		"SOCKS proxy listening",
		"addr",
		net.JoinHostPort(bindAddress, port),
		"connect_timeout",
		config.AppConfig.Socks.ConnectionTimeout.Duration(),
		"idle_timeout",
		idleTimeout,
	)

	listener, err := net.Listen("tcp", net.JoinHostPort(bindAddress, port))
	if err != nil {
		return fmt.Errorf("Failed to start SOCKS proxy: %v", err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			slog.Warn("failed to accept connection", "error", err)
			continue
		}

		if socksRuntime.DropIfDisconnected(conn) {
			continue
		}

		timeoutConn := &models.TimeoutConn{
			Conn:        conn,
			IdleTimeout: idleTimeout,
		}
		trackedConn := socksRuntime.TrackConn(timeoutConn)
		server := socksRuntime.CurrentServer()
		if server == nil {
			slog.Warn("failed to serve SOCKS connection: server unavailable")
			_ = trackedConn.Close()
			continue
		}

		go func(server *socks5.Server, conn net.Conn) {
			if err := server.ServeConn(conn); err != nil && !errors.Is(err, net.ErrClosed) {
				slog.Debug("failed to serve SOCKS connection", "error", err)
			}
			_ = conn.Close()
		}(server, trackedConn)
	}
}

// createSocksServer 创建SOCKS5服务器
func createSocksServer(username, password string, dialFunc func(ctx context.Context, network, addr string) (net.Conn, error), resolver socks5.NameResolver) *socks5.Server {
	buf := api.NewNetBuffer(32 * 1024) // 32KB buffer
	if buf == nil {
		slog.Error("failed to create buffer pool for SOCKS5")
		return nil
	}

	logger := socks5SlogLogger{}

	if username == "" || password == "" {
		return socks5.NewServer(
			socks5.WithLogger(logger),
			socks5.WithDial(dialFunc),
			socks5.WithResolver(resolver),
			socks5.WithBufferPool(buf),
		)
	} else {

		return socks5.NewServer(
			socks5.WithLogger(logger),
			socks5.WithDial(dialFunc),
			socks5.WithResolver(resolver),
			socks5.WithAuthMethods([]socks5.Authenticator{
				socks5.UserPassAuthenticator{
					Credentials: socks5.StaticCredentials{
						username: password,
					},
				}}),
			socks5.WithBufferPool(buf),
		)
	}
}

type socks5SlogLogger struct{}

func (socks5SlogLogger) Errorf(format string, args ...interface{}) {
	slog.Error(fmt.Sprintf("socks5: "+format, args...))
}
