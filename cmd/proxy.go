package cmd

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"runtime"
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
	Run:   runProxyCmd,
}

func init() {
	// 初始化 proxy 命令的参数

	// 只保留必要的注册相关参数，其他参数已转移到配置文件
	proxyCmd.Flags().String("locale", internal.DefaultLocale, "Locale for registration")
	proxyCmd.Flags().String("model", internal.DefaultModel, "Model for registration")
	proxyCmd.Flags().String("name", "", "Device name for registration")
	proxyCmd.Flags().Bool("accept-tos", true, "Automatically accept Cloudflare TOS")
	proxyCmd.Flags().String("jwt", "", "Team token for registration")

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
func runProxyCmd(cmd *cobra.Command, args []string) {
	// 0. 获取配置文件路径
	configPath, err := cmd.Flags().GetString("config")
	if err != nil {
		cmd.Printf("Failed to get config path: %v\n", err)
		return
	}
	if configPath == "" {
		configPath = "config.json"
	}

	// 检查是否需要重置SOCKS5配置
	resetConfig, _ := cmd.Flags().GetBool("reset-config")

	// 1. 如有需要，进行自动注册
	if !config.ConfigLoaded {
		if err := handleRegistration(cmd, configPath); err != nil {
			cmd.Printf("%v\n", err)
			return
		}

		// 更新一些需要从内部常量获取的配置值
		config.AppConfig.Socks.SNIAddress = internal.ConnectSNI

		// 保存更新后的配置
		if err := config.AppConfig.SaveConfig(configPath); err != nil {
			log.Printf("Warning: Failed to save updated config: %v", err)
		}
	} else if resetConfig {
		// 如果已加载配置且指定了reset-config标志，则重置SOCKS5配置
		log.Println("Resetting SOCKS5 configuration to default values...")

		// 保存当前的SNI地址，因为它取决于内部常量
		sniAddress := config.AppConfig.Socks.SNIAddress

		// 重置为默认配置
		config.AppConfig.Socks = config.GetDefaultSocksConfig()

		// 恢复SNI地址
		config.AppConfig.Socks.SNIAddress = sniAddress

		// 保存更新后的配置
		if err := config.AppConfig.SaveConfig(configPath); err != nil {
			log.Printf("Warning: Failed to save reset config: %v", err)
			cmd.Printf("Failed to save reset configuration: %v\n", err)
			return
		}
		log.Printf("SOCKS5 configuration has been reset to default values in %s", configPath)
	}

	// 检查并应用命令行参数覆盖配置文件的值
	configChanged := false

	// 检查绑定地址
	if bindAddress, _ := cmd.Flags().GetString("bind-address"); bindAddress != "" {
		log.Printf("Overriding bind address from command line: %s", bindAddress)
		config.AppConfig.Socks.BindAddress = bindAddress
		configChanged = true
	}

	// 检查端口
	if port, _ := cmd.Flags().GetString("port"); port != "" {
		log.Printf("Overriding port from command line: %s", port)
		config.AppConfig.Socks.Port = port
		configChanged = true
	}

	// 检查用户名
	if username, _ := cmd.Flags().GetString("username"); username != "" {
		log.Printf("Overriding username from command line")
		config.AppConfig.Socks.Username = username
		configChanged = true
	}

	// 检查密码
	if password, _ := cmd.Flags().GetString("password"); password != "" {
		log.Printf("Overriding password from command line")
		config.AppConfig.Socks.Password = password
		configChanged = true
	}

	// 如果配置有变更，保存到配置文件
	if configChanged {
		log.Printf("Saving updated configuration to %s", configPath)
		if err := config.AppConfig.SaveConfig(configPath); err != nil {
			log.Printf("Warning: Failed to save updated config: %v", err)
		}
	}

	// 2. 启动 SOCKS5 代理
	if err := setupAndRunSocksProxy(cmd); err != nil {
		cmd.Printf("%v\n", err)
		return
	}
}

// handleRegistration 处理自动注册流程
func handleRegistration(cmd *cobra.Command, configPath string) error {
	log.Println("Config not loaded. Starting automatic registration...")

	// 获取注册参数
	deviceName, _ := cmd.Flags().GetString("name")
	locale, _ := cmd.Flags().GetString("locale")
	model, _ := cmd.Flags().GetString("model")
	acceptTos, _ := cmd.Flags().GetBool("accept-tos")
	jwt, _ := cmd.Flags().GetString("jwt")

	log.Printf("Registering with locale %s and model %s", locale, model)

	// 注册账户
	accountData, err := api.Register(model, locale, jwt, acceptTos)
	if err != nil {
		return fmt.Errorf("Failed to register: %v", err)
	}

	// 生成密钥对
	privKey, pubKey, err := internal.GenerateEcKeyPair()
	if err != nil {
		return fmt.Errorf("Failed to generate key pair: %v", err)
	}

	log.Printf("Enrolling device key...")

	// 注册设备密钥
	updatedAccountData, apiErr, err := api.EnrollKey(accountData, pubKey, deviceName)
	if err != nil {
		if apiErr != nil {
			return fmt.Errorf("Failed to enroll key: %v (API errors: %s)", err, apiErr.ErrorsAsString("; "))
		}
		return fmt.Errorf("Failed to enroll key: %v", err)
	}

	log.Printf("Registration successful. Saving config...")

	// 保存配置，使用InitNewConfig创建带有默认值的配置
	config.AppConfig = config.InitNewConfig(
		base64.StdEncoding.EncodeToString(privKey),
		// TODO: proper endpoint parsing in utils
		// strip :0
		updatedAccountData.Config.Peers[0].Endpoint.V4[:len(updatedAccountData.Config.Peers[0].Endpoint.V4)-2],
		// strip [ from beginning and ]:0 from end
		updatedAccountData.Config.Peers[0].Endpoint.V6[1:len(updatedAccountData.Config.Peers[0].Endpoint.V6)-3],
		updatedAccountData.Config.Peers[0].PublicKey,
		updatedAccountData.Account.License,
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

	log.Printf("Config saved to %s", configPath)

	// 标记配置已加载
	config.ConfigLoaded = true
	return nil
}

// setupAndRunSocksProxy 设置并运行SOCKS5代理
func setupAndRunSocksProxy(cmd *cobra.Command) error {
	log.Println("Starting SOCKS5 proxy...")

	// 设置最大并发处理能力
	runtime.GOMAXPROCS(runtime.NumCPU())

	// 准备TLS配置
	tlsConfig, err := prepareTlsConfig(cmd)
	if err != nil {
		return err
	}

	// 准备网络配置
	endpoint, localAddresses, dnsAddrs, err := prepareNetworkConfig(cmd)
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

	// 配置连接并启动隧道
	startTunnel(cmd, tlsConfig, endpoint, tunDev)

	// 创建并启动SOCKS服务器
	return runSocksServer(cmd, tunNet, connectionTimeout, idleTimeout)
}

// prepareTlsConfig 准备TLS配置
func prepareTlsConfig(cmd *cobra.Command) (*tls.Config, error) {
	// 从配置中获取SNI地址
	sni := config.AppConfig.Socks.SNIAddress

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
func prepareNetworkConfig(cmd *cobra.Command) (*net.UDPAddr, []netip.Addr, []netip.Addr, error) {
	// 从配置文件获取连接端口
	connectPort := config.AppConfig.Socks.ConnectPort

	// 确定使用IPv4还是IPv6端点
	var endpoint *net.UDPAddr
	if !config.AppConfig.Socks.UseIPv6 {
		endpoint = &net.UDPAddr{
			IP:   net.ParseIP(config.AppConfig.EndpointV4),
			Port: connectPort,
		}
	} else {
		endpoint = &net.UDPAddr{
			IP:   net.ParseIP(config.AppConfig.EndpointV6),
			Port: connectPort,
		}
	}

	// 隧道内IP设置
	var localAddresses []netip.Addr
	if !config.AppConfig.Socks.NoTunnelIPv4 {
		v4, err := netip.ParseAddr(config.AppConfig.IPv4)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("Failed to parse IPv4 address: %v", err)
		}
		localAddresses = append(localAddresses, v4)
	}
	if !config.AppConfig.Socks.NoTunnelIPv6 {
		v6, err := netip.ParseAddr(config.AppConfig.IPv6)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("Failed to parse IPv6 address: %v", err)
		}
		localAddresses = append(localAddresses, v6)
	}

	// DNS设置
	var dnsAddrs []netip.Addr
	for _, dns := range config.AppConfig.Socks.DNS {
		addr, err := netip.ParseAddr(dns)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("Failed to parse DNS server: %v", err)
		}
		dnsAddrs = append(dnsAddrs, addr)
	}

	return endpoint, localAddresses, dnsAddrs, nil
}

// getTimeoutSettings 获取超时设置
func getTimeoutSettings(cmd *cobra.Command) (time.Duration, time.Duration) {
	// 直接从配置文件中读取超时设置
	connectionTimeout := config.AppConfig.Socks.ConnectionTimeout
	idleTimeout := config.AppConfig.Socks.IdleTimeout

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
		log.Println("Warning: MTU is not the default 1280. This is not supported. Packet loss and other issues may occur.")
	}

	tunDev, tunNet, err := netstack.CreateNetTUN(localAddresses, dnsAddrs, mtu)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create virtual TUN device: %v", err)
	}
	return tunDev, tunNet, nil
}

// startTunnel 配置并启动隧道连接
func startTunnel(cmd *cobra.Command, tlsConfig *tls.Config, endpoint *net.UDPAddr, tunDev tun.Device) {
	// 从配置文件读取隧道参数
	keepalivePeriod := config.AppConfig.Socks.KeepalivePeriod
	initialPacketSize := config.AppConfig.Socks.InitialPacketSize
	mtu := config.AppConfig.Socks.MTU
	reconnectDelay := config.AppConfig.Socks.ReconnectDelay

	configTunnel := api.ConnectionConfig{
		TLSConfig:         tlsConfig,
		KeepAlivePeriod:   keepalivePeriod,
		InitialPacketSize: initialPacketSize,
		Endpoint:          endpoint,
		MTU:               mtu,
		MaxPacketRate:     8192,
		MaxBurst:          1024,
		ReconnectStrategy: &api.ExponentialBackoff{
			InitialDelay: reconnectDelay,
			MaxDelay:     5 * time.Minute,
			Factor:       2.0,
		},
	}

	go api.MaintainTunnel(
		context.Background(),
		configTunnel,
		api.NewNetstackAdapter(tunDev),
	)
}

// runSocksServer 创建并运行SOCKS5服务器
func runSocksServer(cmd *cobra.Command, tunNet *netstack.Net, connectionTimeout, idleTimeout time.Duration) error {
	// 从配置中获取网络参数
	bindAddress := config.AppConfig.Socks.BindAddress
	port := config.AppConfig.Socks.Port

	// 创建本地DNS解析器
	// api.NewCachingDNSResolver需要一个int类型的超时值（秒数）
	dnsTimeout := config.AppConfig.Socks.DNSTimeout
	dnsTimeoutSeconds := int(dnsTimeout.Seconds())
	localResolver := api.NewCachingDNSResolver("", dnsTimeoutSeconds)

	// 添加超时设置的拨号函数
	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
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

	// 创建SOCKS5服务器
	server := createSocksServer(username, password, dialFunc, localResolver)

	// 启动监听
	log.Printf("SOCKS proxy listening on %s:%s with timeouts (connect: %s, idle: %s)",
		bindAddress, port, connectionTimeout, idleTimeout)

	listener, err := net.Listen("tcp", net.JoinHostPort(bindAddress, port))
	if err != nil {
		return fmt.Errorf("Failed to start SOCKS proxy: %v", err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v\n", err)
			continue
		}

		timeoutConn := &models.TimeoutConn{
			Conn:        conn,
			IdleTimeout: idleTimeout,
		}

		go server.ServeConn(timeoutConn)
	}
}

// createSocksServer 创建SOCKS5服务器
func createSocksServer(username, password string, dialFunc func(ctx context.Context, network, addr string) (net.Conn, error), resolver socks5.NameResolver) *socks5.Server {
	if username == "" || password == "" {
		return socks5.NewServer(
			socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
			socks5.WithDial(dialFunc),
			socks5.WithResolver(resolver),
		)
	} else {
		cred := socks5.StaticCredentials{
			username: password,
		}
		authenticator := socks5.UserPassAuthenticator{
			Credentials: cred,
		}
		return socks5.NewServer(
			socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
			socks5.WithDial(dialFunc),
			socks5.WithResolver(resolver),
			socks5.WithAuthMethods([]socks5.Authenticator{authenticator}),
		)
	}
}
