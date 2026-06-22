package config

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Duration 是人类可读的时长类型，在 JSON 中支持字符串（如 "2s"、"5m"）或纳秒数字（向后兼容）。
type Duration time.Duration

// UnmarshalJSON 支持字符串（time.ParseDuration 格式）或纳秒数字。
func (d *Duration) UnmarshalJSON(data []byte) error {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch x := v.(type) {
	case string:
		parsed, err := time.ParseDuration(x)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", x, err)
		}
		*d = Duration(parsed)
		return nil
	case float64:
		*d = Duration(int64(x))
		return nil
	default:
		return fmt.Errorf("duration must be string or number, got %T", v)
	}
}

// MarshalJSON 输出人类可读的字符串（如 "2s"、"5m0s"）。
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// Duration 返回标准库 time.Duration，便于在业务代码中使用。
func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// Config represents the application configuration structure, containing essential details such as keys, endpoints, and access tokens.
type Config struct {
	// 连接信息
	PrivateKey        string   `json:"private_key"`         // Base64-encoded ECDSA private key
	EndpointV4        string   `json:"endpoint_v4"`         // IPv4 address of the endpoint
	EndpointV6        string   `json:"endpoint_v6"`         // IPv6 address of the endpoint
	EndpointH2V4      string   `json:"endpoint_h2_v4"`      // IPv4 address used in HTTP/2 mode
	EndpointH2V6      string   `json:"endpoint_h2_v6"`      // IPv6 address used in HTTP/2 mode
	CustomEndpointsV4 []string `json:"custom_endpoints_v4"` // Optional IPv4 endpoint pool used by runtime
	CustomEndpointsV6 []string `json:"custom_endpoints_v6"` // Optional IPv6 endpoint pool used by runtime
	EndpointPubKey    string   `json:"endpoint_pub_key"`    // PEM-encoded ECDSA public key of the endpoint to verify against
	License           string   `json:"license"`             // Application license key
	ID                string   `json:"id"`                  // Device unique identifier
	AccessToken       string   `json:"access_token"`        // Authentication token for API access
	AccountMode       string   `json:"account_mode"`        // Account mode: free/premium/team
	IPv4              string   `json:"ipv4"`                // Assigned IPv4 address
	IPv6              string   `json:"ipv6"`                // Assigned IPv6 address

	// SOCKS代理配置
	Socks SocksConfig `json:"socks"` // SOCKS5代理相关配置

	// SSH SOCKS5网关配置
	SSHSocks SSHSocksConfig `json:"ssh_socks"` // SSH SOCKS5网关相关配置

	// 注册信息
	Registration RegistrationInfo `json:"registration"` // 注册相关信息

	// 日志配置
	Logging LoggingConfig `json:"logging"` // 日志输出级别和格式
}

// KeyConfig 包含与 Cloudflare/MASQUE 身份强绑定的配置，存储于 key.json。
type KeyConfig struct {
	PrivateKey     string `json:"private_key"`
	EndpointV4     string `json:"endpoint_v4"`
	EndpointV6     string `json:"endpoint_v6"`
	EndpointPubKey string `json:"endpoint_pub_key"`
	AccountMode    string `json:"account_mode"`
	License        string `json:"license"`
	ID             string `json:"id"`
	AccessToken    string `json:"access_token"`
	IPv4           string `json:"ipv4"`
	IPv6           string `json:"ipv6"`
}

// PublicConfig 包含可复用的通用运行配置，存储于 config.json。
type PublicConfig struct {
	EndpointH2V4      string           `json:"endpoint_h2_v4"`
	EndpointH2V6      string           `json:"endpoint_h2_v6"`
	CustomEndpointsV4 []string         `json:"custom_endpoints_v4"`
	CustomEndpointsV6 []string         `json:"custom_endpoints_v6"`
	Socks             SocksConfig      `json:"socks"`
	SSHSocks          SSHSocksConfig   `json:"ssh_socks"`
	Registration      RegistrationInfo `json:"registration"`
	Logging           LoggingConfig    `json:"logging"`
}

// legacyConfig 兼容读取旧版单文件 config.json（包含 key 字段 + 公共字段）。
type legacyConfig struct {
	KeyConfig
	PublicConfig
}

// SocksConfig 包含SOCKS5代理相关的配置
type SocksConfig struct {
	BindAddress          string   `json:"bind_address"`           // 代理绑定的地址
	Port                 string   `json:"port"`                   // 代理监听的端口
	Username             string   `json:"username"`               // 代理认证的用户名
	Password             string   `json:"password"`               // 代理认证的密码
	BypassDomain         []string `json:"bypass_domain"`          // 命中后直连当前网络，不走MASQUE隧道
	ProxyTCPPort         []int    `json:"proxy_tcp_port"`         // 仅这些TCP目标端口走MASQUE隧道，其余直连
	ConnectPort          int      `json:"connect_port"`           // MASQUE连接使用的端口
	DNS                  []string `json:"dns"`                    // 在MASQUE隧道内使用的DNS服务器
	DNSTimeout           Duration `json:"dns_timeout"`            // DNS查询超时时间（超时后尝试下一个服务器）
	RemoteDNS            bool     `json:"remote_dns"`             // 是否使用远程DNS（通过TUN隧道），false则使用本地DNS
	UseIPv6              bool     `json:"use_ipv6"`               // 是否使用IPv6进行MASQUE连接
	HTTP2                bool     `json:"http2"`                  // true=TCP+TLS+HTTP/2; false=QUIC+HTTP/3
	L4                   bool     `json:"l4"`                     // true=L4模式(HTTP/3 CONNECT流, 绕过netstack, 仅TCP); 与http2互斥
	NoTunnelIPv4         bool     `json:"no_tunnel_ipv4"`         // 是否在MASQUE隧道内禁用IPv4
	NoTunnelIPv6         bool     `json:"no_tunnel_ipv6"`         // 是否在MASQUE隧道内禁用IPv6
	BlockUDP443          bool     `json:"block_udp_443"`          // Whether to block outbound UDP/443 (QUIC)
	SNIAddress           string   `json:"sni_address"`            // MASQUE连接使用的SNI地址
	KeepalivePeriod      Duration `json:"keepalive_period"`       // MASQUE连接的心跳周期
	MTU                  int      `json:"mtu"`                    // MASQUE连接的MTU
	InitialPacketSize    uint16   `json:"initial_packet_size"`    // MASQUE连接的初始包大小
	ReconnectDelay       Duration `json:"reconnect_delay"`        // 重连尝试之间的延迟
	MaxReconnectAttempts int      `json:"max_reconnect_attempts"` // 连续连接失败阈值；达到后暂停重连等待人工处理，0表示无限重试
	DrainGrace           Duration `json:"drain_grace"`            // 隧道断开后保留现有SOCKS连接的宽限期，超时仍未恢复则关闭
	ConnectionTimeout    Duration `json:"connection_timeout"`     // 建立连接的超时时间
	IdleTimeout          Duration `json:"idle_timeout"`           // 空闲连接的超时时间
	AlwaysReconnect      bool     `json:"always_reconnect"`       // true=断线后立即重连；false(默认)=隧道空闲被服务端清掉后，等到有出站流量再重连
}

// SSHSocksConfig 包含SSH SOCKS5网关相关的配置
type SSHSocksConfig struct {
	BindAddress       string   `json:"bind_address"`       // 代理绑定的地址
	Port              string   `json:"port"`               // 代理监听的端口
	Username          string   `json:"username"`           // 代理认证的用户名
	Password          string   `json:"password"`           // 代理认证的密码
	HourlyThreshold   int      `json:"hourly_threshold"`   // 每小时同一IP连接次数阈值，超过则锁定/24子网，默认15
	Whitelist         []string `json:"whitelist"`          // 白名单，host或IP，命中后不参与计数器统计
	ConnectionTimeout Duration `json:"connection_timeout"` // 建立连接的超时时间
	IdleTimeout       Duration `json:"idle_timeout"`       // 空闲连接的超时时间
}

// GetDefaultSSHSocksConfig 返回默认的SSH SOCKS5网关配置
func GetDefaultSSHSocksConfig() SSHSocksConfig {
	return SSHSocksConfig{
		BindAddress:       "0.0.0.0",
		Port:              "1080",
		Username:          "",
		Password:          "",
		HourlyThreshold:   15,
		Whitelist:         []string{},
		ConnectionTimeout: Duration(30 * time.Second),
		IdleTimeout:       Duration(5 * time.Minute),
	}
}

// LoggingConfig 包含日志相关的配置
type LoggingConfig struct {
	Level        string `json:"level"`         // 日志级别: debug/info/warn/error
	Format       string `json:"format"`        // 日志格式: text/json
	SocksVerbose bool   `json:"socks_verbose"` // 是否启用SOCKS连接级详细日志
}

// RegistrationInfo 包含注册相关的信息
type RegistrationInfo struct {
	DeviceName string `json:"device_name"` // 注册的设备名称
}

// AppConfig holds the global application configuration.
var AppConfig Config

// ConfigLoaded indicates whether the configuration has been successfully loaded.
var ConfigLoaded bool

const (
	DefaultEndpointH2V4 = "162.159.198.2"
	DefaultEndpointH2V6 = ""
)

// LoadConfig loads the application configuration from a JSON file.
//
// Parameters:
//   - configPath: string - The path to the configuration JSON file.
//
// Returns:
//   - error: An error if the configuration file cannot be loaded or parsed.
func LoadConfig(configPath string) error {
	if strings.TrimSpace(configPath) == "" {
		configPath = "config.json"
	}

	file, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	var legacy legacyConfig
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&legacy); err != nil {
		return fmt.Errorf("failed to decode config file: %w", err)
	}

	AppConfig = Config{
		EndpointH2V4:      legacy.EndpointH2V4,
		EndpointH2V6:      legacy.EndpointH2V6,
		CustomEndpointsV4: append([]string(nil), legacy.CustomEndpointsV4...),
		CustomEndpointsV6: append([]string(nil), legacy.CustomEndpointsV6...),
		Socks:             legacy.Socks,
		SSHSocks:          legacy.SSHSocks,
		Registration:      legacy.Registration,
		Logging:           legacy.Logging,
	}
	applyKeyConfig(&AppConfig, legacy.KeyConfig)

	keyPath := keyConfigPath(configPath)
	keyFile, err := os.Open(keyPath)
	switch {
	case err == nil:
		defer keyFile.Close()
		var keyCfg KeyConfig
		if err := json.NewDecoder(keyFile).Decode(&keyCfg); err != nil {
			return fmt.Errorf("failed to decode key file: %w", err)
		}
		applyKeyConfig(&AppConfig, keyCfg)
	case errors.Is(err, os.ErrNotExist):
		legacyKey := extractKeyConfig(AppConfig)
		if hasAnyKeyField(legacyKey) {
			if err := writeJSONFile(keyPath, legacyKey); err != nil {
				return fmt.Errorf("failed to write key file during migration: %w", err)
			}
			if err := writeJSONFile(configPath, extractPublicConfig(AppConfig)); err != nil {
				return fmt.Errorf("failed to rewrite config file during migration: %w", err)
			}
		}
	default:
		return fmt.Errorf("failed to open key file: %w", err)
	}

	// 如果Socks配置为空，设置默认值
	// 判断Socks配置是否已初始化（通过检查关键字段）
	if AppConfig.Socks.Port == "" && AppConfig.Socks.BindAddress == "" && len(AppConfig.Socks.DNS) == 0 {
		AppConfig.Socks = GetDefaultSocksConfig()
	}
	AppConfig.Socks, err = NormalizeSocksConfig(AppConfig.Socks)
	if err != nil {
		return err
	}

	// 如果SSHSocks配置为空，设置默认值
	if AppConfig.SSHSocks.Port == "" && AppConfig.SSHSocks.BindAddress == "" {
		AppConfig.SSHSocks = GetDefaultSSHSocksConfig()
	}
	AppConfig.SSHSocks = NormalizeSSHSocksConfig(AppConfig.SSHSocks)

	defaultLogging := GetDefaultLoggingConfig()
	if strings.TrimSpace(AppConfig.Logging.Level) == "" {
		AppConfig.Logging.Level = defaultLogging.Level
	}
	if strings.TrimSpace(AppConfig.Logging.Format) == "" {
		AppConfig.Logging.Format = defaultLogging.Format
	}

	ConfigLoaded = true

	return nil
}

// LoadPublicConfig loads only reusable/public runtime settings from config.json.
// It ignores both sibling key.json and any legacy key fields embedded in config.json.
func LoadPublicConfig(configPath string) error {
	if strings.TrimSpace(configPath) == "" {
		configPath = "config.json"
	}

	file, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	var public PublicConfig
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&public); err != nil {
		return fmt.Errorf("failed to decode config file: %w", err)
	}

	AppConfig = Config{
		EndpointH2V4:      public.EndpointH2V4,
		EndpointH2V6:      public.EndpointH2V6,
		CustomEndpointsV4: append([]string(nil), public.CustomEndpointsV4...),
		CustomEndpointsV6: append([]string(nil), public.CustomEndpointsV6...),
		Socks:             public.Socks,
		SSHSocks:          public.SSHSocks,
		Registration:      public.Registration,
		Logging:           public.Logging,
	}

	if AppConfig.Socks.Port == "" && AppConfig.Socks.BindAddress == "" && len(AppConfig.Socks.DNS) == 0 {
		AppConfig.Socks = GetDefaultSocksConfig()
	}
	normalizedSocks, normErr := NormalizeSocksConfig(AppConfig.Socks)
	if normErr != nil {
		return normErr
	}
	AppConfig.Socks = normalizedSocks

	// 如果SSHSocks配置为空，设置默认值
	if AppConfig.SSHSocks.Port == "" && AppConfig.SSHSocks.BindAddress == "" {
		AppConfig.SSHSocks = GetDefaultSSHSocksConfig()
	}
	AppConfig.SSHSocks = NormalizeSSHSocksConfig(AppConfig.SSHSocks)

	defaultLogging := GetDefaultLoggingConfig()
	if strings.TrimSpace(AppConfig.Logging.Level) == "" {
		AppConfig.Logging.Level = defaultLogging.Level
	}
	if strings.TrimSpace(AppConfig.Logging.Format) == "" {
		AppConfig.Logging.Format = defaultLogging.Format
	}

	ConfigLoaded = true
	return nil
}

// GetDefaultSocksConfig 返回默认的SOCKS代理配置
func GetDefaultSocksConfig() SocksConfig {
	return SocksConfig{
		BindAddress:     "127.0.0.1",
		Port:            "1080",
		Username:        "",
		Password:        "",
		BypassDomain:    []string{},
		ProxyTCPPort:    []int{},
		ConnectPort:     443,
		DNS:             []string{"1.1.1.1", "8.8.8.8"},
		DNSTimeout:      Duration(2 * time.Second),
		RemoteDNS:       false,
		UseIPv6:         false,
		NoTunnelIPv4:    false,
		NoTunnelIPv6:    false,
		BlockUDP443:     true,
		HTTP2:           false,
		L4:              false,
		SNIAddress:      "", // 这应当从internal.ConnectSNI读取，但现在我们不修改其他文件
		KeepalivePeriod: Duration(30 * time.Second),
		// MTU is the inner (tunneled) packet size. 1280 is the safe default;
		// values up to ~1400 are supported — oversized packets are clamped back
		// by the connect-ip ICMP packet-too-big response, which always
		// advertises 1280.
		MTU: 1280,
		// InitialPacketSize seeds quic-go's path MTU discovery, which probes
		// upward from here. 1242 is the empirically measured Cloudflare Initial
		// packet size (see RESEARCH.md) and remains the safe floor; 1350 stays
		// below the common ~1400 PPPoE/tunnel cliff while shortening probing.
		InitialPacketSize:    1350,
		ReconnectDelay:       Duration(1 * time.Second),
		MaxReconnectAttempts: 0,
		DrainGrace:           Duration(15 * time.Second),
		ConnectionTimeout:    Duration(30 * time.Second),
		IdleTimeout:          Duration(5 * time.Minute),
		AlwaysReconnect:      false,
	}
}

// GetDefaultLoggingConfig 返回默认日志配置
func GetDefaultLoggingConfig() LoggingConfig {
	return LoggingConfig{
		Level:        "info",
		Format:       "text",
		SocksVerbose: false,
	}
}

// NormalizeSSHSocksConfig 规范化SSH SOCKS5网关配置。
func NormalizeSSHSocksConfig(cfg SSHSocksConfig) SSHSocksConfig {
	normalized := cfg
	defaults := GetDefaultSSHSocksConfig()
	if normalized.HourlyThreshold <= 0 {
		normalized.HourlyThreshold = defaults.HourlyThreshold
	}
	if normalized.Whitelist == nil {
		normalized.Whitelist = []string{}
	}
	if normalized.ConnectionTimeout.Duration() <= 0 {
		normalized.ConnectionTimeout = defaults.ConnectionTimeout
	}
	if normalized.IdleTimeout.Duration() <= 0 {
		normalized.IdleTimeout = defaults.IdleTimeout
	}
	return normalized
}

// NormalizeLoggingConfig 规范化日志配置，并返回无效配置项说明。
func NormalizeLoggingConfig(cfg LoggingConfig) (LoggingConfig, []string) {
	normalized := cfg
	defaults := GetDefaultLoggingConfig()
	var issues []string

	level := strings.ToLower(strings.TrimSpace(cfg.Level))
	switch level {
	case "", "debug", "info", "warn", "error":
		if level == "" {
			level = defaults.Level
		}
	default:
		issues = append(issues, fmt.Sprintf("level=%q -> %q", cfg.Level, defaults.Level))
		level = defaults.Level
	}
	normalized.Level = level

	format := strings.ToLower(strings.TrimSpace(cfg.Format))
	switch format {
	case "", "text", "json":
		if format == "" {
			format = defaults.Format
		}
	default:
		issues = append(issues, fmt.Sprintf("format=%q -> %q", cfg.Format, defaults.Format))
		format = defaults.Format
	}
	normalized.Format = format

	return normalized, issues
}

// NormalizeSocksConfig normalizes SOCKS settings and rejects invalid values.
func NormalizeSocksConfig(cfg SocksConfig) (SocksConfig, error) {
	normalized := cfg
	proxyTCPPorts, err := normalizeProxyTCPPorts(cfg.ProxyTCPPort)
	if err != nil {
		return SocksConfig{}, err
	}
	normalized.ProxyTCPPort = proxyTCPPorts
	if normalized.BypassDomain == nil {
		normalized.BypassDomain = []string{}
	}
	if normalized.ProxyTCPPort == nil {
		normalized.ProxyTCPPort = []int{}
	}
	if normalized.DrainGrace.Duration() <= 0 {
		normalized.DrainGrace = GetDefaultSocksConfig().DrainGrace
	}
	return normalized, nil
}

func normalizeProxyTCPPorts(ports []int) ([]int, error) {
	if len(ports) == 0 {
		return []int{}, nil
	}

	normalized := make([]int, 0, len(ports))
	seen := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid proxy_tcp_port %d: must be between 1 and 65535", port)
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		normalized = append(normalized, port)
	}

	return normalized, nil
}

// SaveConfig writes the current application configuration to a prettified JSON file.
//
// Parameters:
//   - configPath: string - The path to save the configuration JSON file.
//
// Returns:
//   - error: An error if the configuration file cannot be written.
func (*Config) SaveConfig(configPath string) error {
	if strings.TrimSpace(configPath) == "" {
		configPath = "config.json"
	}

	normalized := AppConfig
	var err error
	normalized.Socks, err = NormalizeSocksConfig(normalized.Socks)
	if err != nil {
		return err
	}

	if err := writeJSONFile(configPath, extractPublicConfig(normalized)); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	if err := writeJSONFile(keyConfigPath(configPath), extractKeyConfig(normalized)); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

func keyConfigPath(configPath string) string {
	if strings.TrimSpace(configPath) == "" {
		configPath = "config.json"
	}
	return filepath.Join(filepath.Dir(configPath), "key.json")
}

func extractKeyConfig(cfg Config) KeyConfig {
	return KeyConfig{
		PrivateKey:     cfg.PrivateKey,
		EndpointV4:     cfg.EndpointV4,
		EndpointV6:     cfg.EndpointV6,
		EndpointPubKey: cfg.EndpointPubKey,
		AccountMode:    cfg.AccountMode,
		License:        cfg.License,
		ID:             cfg.ID,
		AccessToken:    cfg.AccessToken,
		IPv4:           cfg.IPv4,
		IPv6:           cfg.IPv6,
	}
}

func extractPublicConfig(cfg Config) PublicConfig {
	return PublicConfig{
		EndpointH2V4:      cfg.EndpointH2V4,
		EndpointH2V6:      cfg.EndpointH2V6,
		CustomEndpointsV4: append([]string(nil), cfg.CustomEndpointsV4...),
		CustomEndpointsV6: append([]string(nil), cfg.CustomEndpointsV6...),
		Socks:             cfg.Socks,
		SSHSocks:          cfg.SSHSocks,
		Registration:      cfg.Registration,
		Logging:           cfg.Logging,
	}
}

func applyKeyConfig(cfg *Config, key KeyConfig) {
	cfg.PrivateKey = key.PrivateKey
	cfg.EndpointV4 = key.EndpointV4
	cfg.EndpointV6 = key.EndpointV6
	cfg.EndpointPubKey = key.EndpointPubKey
	cfg.AccountMode = key.AccountMode
	cfg.License = key.License
	cfg.ID = key.ID
	cfg.AccessToken = key.AccessToken
	cfg.IPv4 = key.IPv4
	cfg.IPv6 = key.IPv6
}

func hasAnyKeyField(key KeyConfig) bool {
	return strings.TrimSpace(key.PrivateKey) != "" ||
		strings.TrimSpace(key.EndpointV4) != "" ||
		strings.TrimSpace(key.EndpointV6) != "" ||
		strings.TrimSpace(key.EndpointPubKey) != "" ||
		strings.TrimSpace(key.AccountMode) != "" ||
		strings.TrimSpace(key.License) != "" ||
		strings.TrimSpace(key.ID) != "" ||
		strings.TrimSpace(key.AccessToken) != "" ||
		strings.TrimSpace(key.IPv4) != "" ||
		strings.TrimSpace(key.IPv6) != ""
}

func writeJSONFile(path string, v interface{}) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file %q: %w", path, err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(v); err != nil {
		return fmt.Errorf("failed to encode json to %q: %w", path, err)
	}

	return nil
}

// InitNewConfig initializes a new configuration with default values.
//
// Parameters:
//   - privateKey: string - Base64-encoded ECDSA private key.
//   - endpointV4: string - IPv4 address of the endpoint.
//   - endpointV6: string - IPv6 address of the endpoint.
//   - endpointPubKey: string - PEM-encoded ECDSA public key of the endpoint.
//   - license: string - Application license key.
//   - id: string - Device unique identifier.
//   - accessToken: string - Authentication token for API access.
//   - accountMode: string - Account mode, one of free/premium/team.
//   - ipv4: string - Assigned IPv4 address.
//   - ipv6: string - Assigned IPv6 address.
//   - deviceName: string - Name of the device (for registration info).
//
// Returns:
//   - The newly initialized Config.
func InitNewConfig(
	privateKey, endpointV4, endpointV6, endpointPubKey,
	license, id, accessToken, accountMode, ipv4, ipv6, deviceName string,
) Config {
	return Config{
		PrivateKey:     privateKey,
		EndpointV4:     endpointV4,
		EndpointV6:     endpointV6,
		EndpointH2V4:   DefaultEndpointH2V4,
		EndpointH2V6:   DefaultEndpointH2V6,
		EndpointPubKey: endpointPubKey,
		License:        license,
		ID:             id,
		AccessToken:    accessToken,
		AccountMode:    accountMode,
		IPv4:           ipv4,
		IPv6:           ipv6,
		Socks:          GetDefaultSocksConfig(),
		Logging:        GetDefaultLoggingConfig(),
		Registration: RegistrationInfo{
			DeviceName: deviceName,
		},
	}
}

// GetEcPrivateKey retrieves the ECDSA private key from the stored Base64-encoded string.
//
// Returns:
//   - *ecdsa.PrivateKey: The parsed ECDSA private key.
//   - error: An error if decoding or parsing the private key fails.
func (*Config) GetEcPrivateKey() (*ecdsa.PrivateKey, error) {
	privKeyB64, err := base64.StdEncoding.DecodeString(AppConfig.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %v", err)
	}

	privKey, err := x509.ParseECPrivateKey(privKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return privKey, nil
}

// GetEcEndpointPublicKey retrieves the ECDSA public key from the stored PEM-encoded string.
//
// Returns:
//   - *ecdsa.PublicKey: The parsed ECDSA public key.
//   - error: An error if decoding or parsing the public key fails.
func (*Config) GetEcEndpointPublicKey() (*ecdsa.PublicKey, error) {
	endpointPubKeyB64, _ := pem.Decode([]byte(AppConfig.EndpointPubKey))
	if endpointPubKeyB64 == nil {
		return nil, fmt.Errorf("failed to decode endpoint public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(endpointPubKeyB64.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	ecPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to assert public key as ECDSA")
	}

	return ecPubKey, nil
}
