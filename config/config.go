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

	"sigs.k8s.io/yaml"
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
	PrivateKey     string `json:"private_key"`      // Base64-encoded ECDSA private key
	EndpointV4     string `json:"endpoint_v4"`      // IPv4 address of the endpoint
	EndpointV6     string `json:"endpoint_v6"`      // IPv6 address of the endpoint
	EndpointH2V4   string `json:"endpoint_h2_v4"`   // IPv4 address used in HTTP/2 mode
	EndpointH2V6   string `json:"endpoint_h2_v6"`   // IPv6 address used in HTTP/2 mode
	EndpointPubKey string `json:"endpoint_pub_key"` // PEM-encoded ECDSA public key of the endpoint to verify against
	License        string `json:"license"`          // Application license key
	ID             string `json:"id"`               // Device unique identifier
	AccessToken    string `json:"access_token"`     // Authentication token for API access
	AccountMode    string `json:"account_mode"`     // Account mode: free/premium/team
	IPv4           string `json:"ipv4"`             // Assigned IPv4 address
	IPv6           string `json:"ipv6"`             // Assigned IPv6 address

	// SOCKS代理配置
	Socks SocksConfig `json:"socks"` // SOCKS5代理相关配置

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
	EndpointH2V4   string `json:"endpoint_h2_v4"`
	EndpointH2V6   string `json:"endpoint_h2_v6"`
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
	Socks        SocksConfig      `json:"socks"`
	Registration RegistrationInfo `json:"registration"`
	Logging      LoggingConfig    `json:"logging"`
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
	WG                   bool     `json:"wg"`                     // true=实验性进程内WireGuard传输(替代MASQUE);需配合 proxy --experimental;与 http2/l4 互斥
	L4UDP                string   `json:"l4_udp"`                 // L4模式下UDP处理: "block"(默认,拒绝UDP ASSOCIATE) | "direct"(本地直连,绕过隧道,UDP以真实出口IP外发) | "tunnel"(mix模式,UDP走并行L3 connect-ip隧道,真实WARP IP出口)
	NoTunnelIPv4         bool     `json:"no_tunnel_ipv4"`         // 是否在MASQUE隧道内禁用IPv4
	NoTunnelIPv6         bool     `json:"no_tunnel_ipv6"`         // 是否在MASQUE隧道内禁用IPv6
	BlockUDP443          bool     `json:"block_udp_443"`          // Whether to block outbound UDP/443 (QUIC)
	SNIAddress           string   `json:"sni_address"`            // MASQUE连接使用的SNI地址
	KeepalivePeriod      Duration `json:"keepalive_period"`       // MASQUE连接(QUIC)的心跳周期,空闲时按此周期发PING防止被idle清掉;仅HTTP/3模式有效;<=0取默认(30s),即漏写也会保活(L3隧道与L4共享连接均依赖它)
	MTU                  int      `json:"mtu"`                    // MASQUE连接的MTU
	InitialPacketSize    uint16   `json:"initial_packet_size"`    // MASQUE连接的初始包大小
	ReconnectDelay       Duration `json:"reconnect_delay"`        // 重连尝试之间的延迟
	MaxReconnectAttempts int      `json:"max_reconnect_attempts"` // 连续连接失败阈值；达到后暂停重连等待人工处理，0表示无限重试
	ConnectionTimeout    Duration `json:"connection_timeout"`     // 建立连接的超时时间(L3/WG;L4用l4_connection_timeout,两套协议互不影响)
	IdleTimeout          Duration `json:"idle_timeout"`           // 空闲连接的超时时间(L3/WG;L4用l4_idle_timeout,两套协议互不影响)
	AlwaysReconnect      bool     `json:"always_reconnect"`       // true=断线后立即重连；false(默认)=隧道空闲被服务端清掉后，等到有出站流量再重连
	L4HalfOpenTimeout    Duration `json:"l4_half_open_timeout"`   // L4模式半开TCP流的空闲上限:一方向结束后另一方向最多空闲多久就回收(随活动重置),避免滞留流占满共享连接的MAX_STREAMS;<=0取默认
	L4ConnectionTimeout  Duration `json:"l4_connection_timeout"`  // L4模式建立连接/打开流的超时(与L3的connection_timeout隔离);<=0取默认
	L4IdleTimeout        Duration `json:"l4_idle_timeout"`        // L4模式空闲流的超时(与L3的idle_timeout隔离)。L4每条空闲流占用稀缺的QUIC MAX_STREAMS额度,故默认显著短于L3;<=0取默认
	L4MaxConnFailures    int      `json:"l4_max_conn_failures"`   // L4模式判定共享连接wedged(QUIC存活但CF停止应答CONNECT)前允许的连续握手失败次数;调低=更快重建但更易因瞬时抖动误判,可用于实验;<=0取默认(50)。另有按时长触发的兜底(2×l4_connection_timeout),低并发下也能及时重建
}

// L4 UDP handling modes (socks.l4_udp). The L4 transport has no UDP path of its
// own — Cloudflare's MASQUE proxy endpoint answers connect-udp with 403 — so UDP
// is either refused, relayed outside the tunnel, or carried over a parallel L3
// connect-ip tunnel ("mix" mode).
const (
	// L4UDPBlock rejects SOCKS UDP ASSOCIATE outright (the default). Apps that can
	// fall back to TCP (e.g. browsers downgrading QUIC to HTTP/2) keep working.
	L4UDPBlock = "block"
	// L4UDPDirect accepts UDP ASSOCIATE but relays datagrams through a direct local
	// socket, bypassing WARP. UDP egresses the host's real IP; only TCP is tunneled.
	L4UDPDirect = "direct"
	// L4UDPTunnel ("mix" mode) accepts UDP ASSOCIATE and relays datagrams through a
	// parallel connect-ip (L3/netstack) tunnel that runs alongside the L4 TCP proxy,
	// so UDP egresses the real WARP IP while TCP keeps L4's per-flow QUIC speed. The
	// L3 leg is lazy (built on the first UDP datagram, sleeps when idle) because mix
	// mode targets workloads that are almost entirely TCP. block_udp_443 still applies
	// (QUIC-in-QUIC over the tunnel would throttle bandwidth — apps fall back to TCP).
	L4UDPTunnel = "tunnel"
)

// DefaultKeepalivePeriod is the QUIC keepalive (heartbeat) period for MASQUE connections.
// NormalizeSocksConfig backfills it field-wise (<=0 -> this default), so a populated socks
// block that simply omits keepalive_period still gets a heartbeat. Without it the L3 tunnel
// and the L4 shared connection would run with keepalive disabled and be idle-evicted by
// Cloudflare/quic-go during quiet periods — and L4 has no reconnect supervisor, so it would
// self-destruct every idle window. usque and mihomo both pin 30s.
const DefaultKeepalivePeriod = 30 * time.Second

// L4 shared-connection scaling and stream-lifetime defaults. L4 multiplexes every
// TCP flow as one QUIC stream over shared QUIC connection(s), so the live-stream
// count is bounded by Cloudflare's per-connection MAX_STREAMS. Robustness comes
// from three independent guards: a short half-open idle keeps a finished flow from
// pinning its stream for the full idle timeout; a hard in-flight stream cap fast-
// fails new flows the instant the connection is saturated (so nothing blocks or
// piles up to OOM); and the connection auto-reconnects when it dies.
const (
	// DefaultL4HalfOpenTimeout bounds how long a half-open L4 TCP relay's surviving
	// direction may stay idle before it is reaped (re-arming on activity), instead
	// of pinning its QUIC stream for the full idle timeout.
	DefaultL4HalfOpenTimeout = 30 * time.Second
	// DefaultL4ConnectionTimeout is L4 mode's connect/stream-open timeout, a SEPARATE
	// knob from the L3 connection_timeout so the two transports tune independently. The
	// reference MASQUE L4 implementations (mihomo, usque) do not pin an explicit dial
	// timeout (they use the caller's context), so this keeps the conventional 30s.
	DefaultL4ConnectionTimeout = 30 * time.Second
	// DefaultL4IdleTimeout is L4 mode's idle-stream timeout, kept SEPARATE from the L3
	// idle_timeout (which stays 5m for the cheap-netstack-conn L3 path). The value is
	// taken from the reference MASQUE L4 implementations rather than reused from L3: usque
	// uses no TCP-stream idle reaper and a 60s data-path (UDP) timeout, and mihomo relies
	// on quic-go's ~30s connection idle plus a 30s keepalive (so a stream lives only as
	// long as the connection). uscf keeps its 30s half-open reaper (l4_half_open_timeout)
	// for the common one-sided case and sets this both-directions-idle baseline to 60s,
	// matching usque's data-path timeout — bounding idle streams against the shared
	// connection's scarce MAX_STREAMS budget. A re-arming activity check means an actively
	// transferring flow is never cut; only a truly idle one is reaped.
	DefaultL4IdleTimeout = 60 * time.Second
	// DefaultL4MaxConnFailures is the default count threshold for the L4 wedge detector
	// (see api.noteConnFailure): how many CONNECT handshakes may fail in a row with no
	// Cloudflare answer before the shared connection is rebuilt. Lowered from an earlier
	// 100 to 50 — combined with the elapsed-time trip (2×l4_connection_timeout) this
	// recovers a wedged connection promptly without re-tripping on a transient blip.
	// Operators can tune l4_max_conn_failures to experiment.
	DefaultL4MaxConnFailures = 50
)

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

	var legacy legacyConfig
	if err := decodeConfigFile(configPath, &legacy); err != nil {
		return err
	}

	AppConfig = Config{
		Socks:        legacy.Socks,
		Registration: legacy.Registration,
		Logging:      legacy.Logging,
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
			if err := writeConfigFile(configPath, extractPublicConfig(AppConfig)); err != nil {
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

	var public PublicConfig
	if err := decodeConfigFile(configPath, &public); err != nil {
		return err
	}

	AppConfig = Config{
		Socks:        public.Socks,
		Registration: public.Registration,
		Logging:      public.Logging,
	}

	if AppConfig.Socks.Port == "" && AppConfig.Socks.BindAddress == "" && len(AppConfig.Socks.DNS) == 0 {
		AppConfig.Socks = GetDefaultSocksConfig()
	}
	normalizedSocks, normErr := NormalizeSocksConfig(AppConfig.Socks)
	if normErr != nil {
		return normErr
	}
	AppConfig.Socks = normalizedSocks

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
		L4UDP:           L4UDPBlock,
		SNIAddress:      "", // 这应当从internal.ConnectSNI读取，但现在我们不修改其他文件
		KeepalivePeriod: Duration(DefaultKeepalivePeriod),
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
		ConnectionTimeout:    Duration(30 * time.Second),
		IdleTimeout:          Duration(5 * time.Minute),
		AlwaysReconnect:      false,
		L4HalfOpenTimeout:    Duration(DefaultL4HalfOpenTimeout),
		L4ConnectionTimeout:  Duration(DefaultL4ConnectionTimeout),
		L4IdleTimeout:        Duration(DefaultL4IdleTimeout),
		L4MaxConnFailures:    DefaultL4MaxConnFailures,
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
	// keepalive_period backfills to its default field-wise (like the timeouts below) so a
	// populated socks block that omits it still gets a QUIC heartbeat. Without this the L3
	// tunnel and the L4 shared connection would run with keepalive disabled and be idle-
	// evicted during quiet periods (L4 has no reconnect supervisor — it would self-destruct
	// every idle window). The lazy mix-mode UDP leg is unaffected: it hardcodes 0 in Go.
	if normalized.KeepalivePeriod.Duration() <= 0 {
		normalized.KeepalivePeriod = Duration(DefaultKeepalivePeriod)
	}
	if normalized.L4HalfOpenTimeout.Duration() <= 0 {
		normalized.L4HalfOpenTimeout = Duration(DefaultL4HalfOpenTimeout)
	}
	if normalized.L4ConnectionTimeout.Duration() <= 0 {
		normalized.L4ConnectionTimeout = Duration(DefaultL4ConnectionTimeout)
	}
	if normalized.L4IdleTimeout.Duration() <= 0 {
		normalized.L4IdleTimeout = Duration(DefaultL4IdleTimeout)
	}
	if normalized.L4MaxConnFailures <= 0 {
		normalized.L4MaxConnFailures = DefaultL4MaxConnFailures
	}
	// Keep the L4 half-open reaper a SHORTENER: a half-open timeout larger than the idle
	// timeout would re-arm the surviving direction LONGER than a fully-open flow, inverting
	// the guard that exists to free a stranded half-open stream's scarce QUIC stream faster.
	if normalized.L4HalfOpenTimeout.Duration() > normalized.L4IdleTimeout.Duration() {
		normalized.L4HalfOpenTimeout = normalized.L4IdleTimeout
	}
	switch strings.ToLower(strings.TrimSpace(normalized.L4UDP)) {
	case "", L4UDPBlock:
		normalized.L4UDP = L4UDPBlock
	case L4UDPDirect:
		normalized.L4UDP = L4UDPDirect
	case L4UDPTunnel:
		normalized.L4UDP = L4UDPTunnel
	default:
		return SocksConfig{}, fmt.Errorf("invalid l4_udp %q: must be %q, %q or %q", cfg.L4UDP, L4UDPBlock, L4UDPDirect, L4UDPTunnel)
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

	if err := writeConfigFile(configPath, extractPublicConfig(normalized)); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	if err := writeJSONFile(keyConfigPath(configPath), extractKeyConfig(normalized)); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

// SavePublicConfig writes only the reusable/public settings (config.yaml) and
// never touches key.json. It is used by transports that carry their own identity
// store outside key.json — notably the experimental WireGuard mode, which uses
// wg-account.json — so enabling them does not create or overwrite a sibling
// key.json with empty MASQUE identity material.
func (*Config) SavePublicConfig(configPath string) error {
	if strings.TrimSpace(configPath) == "" {
		configPath = "config.json"
	}

	normalized := AppConfig
	var err error
	normalized.Socks, err = NormalizeSocksConfig(normalized.Socks)
	if err != nil {
		return err
	}

	if err := writeConfigFile(configPath, extractPublicConfig(normalized)); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
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
		EndpointH2V4:   cfg.EndpointH2V4,
		EndpointH2V6:   cfg.EndpointH2V6,
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
		Socks:        cfg.Socks,
		Registration: cfg.Registration,
		Logging:      cfg.Logging,
	}
}

func applyKeyConfig(cfg *Config, key KeyConfig) {
	cfg.PrivateKey = key.PrivateKey
	cfg.EndpointV4 = key.EndpointV4
	cfg.EndpointV6 = key.EndpointV6
	cfg.EndpointH2V4 = key.EndpointH2V4
	cfg.EndpointH2V6 = key.EndpointH2V6
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

// isYAMLPath reports whether path uses a YAML file extension (.yaml/.yml).
func isYAMLPath(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		return true
	default:
		return false
	}
}

// decodeConfigFile reads a config file and unmarshals it into v. Both YAML and
// JSON inputs are accepted (JSON is a subset of YAML), so a path is decoded the
// same way regardless of extension. The struct's existing `json:` tags and the
// Duration JSON (un)marshalers are reused via sigs.k8s.io/yaml. The returned
// error wraps os.ErrNotExist when the file is missing so callers can detect it.
func decodeConfigFile(path string, v interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to open config file: %w", err)
	}
	if err := yaml.Unmarshal(data, v); err != nil {
		return fmt.Errorf("failed to decode config file: %w", err)
	}
	return nil
}

// writeConfigFile writes v to path, choosing the encoding from the file
// extension: YAML for .yaml/.yml, otherwise prettified JSON (legacy). key.json
// always goes through writeJSONFile directly and is unaffected.
func writeConfigFile(path string, v interface{}) error {
	if !isYAMLPath(path) {
		return writeJSONFile(path, v)
	}
	data, err := yaml.Marshal(v)
	if err != nil {
		return fmt.Errorf("failed to encode yaml to %q: %w", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("failed to write file %q: %w", path, err)
	}
	return nil
}

// Candidate config filenames probed (in order) when no explicit path is given.
var configFileCandidates = []string{"config.yaml", "config.yml", "config.json"}

// ResolveConfigPath decides which config file to use. A non-empty explicit path
// is honored verbatim. Otherwise the current directory is probed for
// config.yaml, config.yml, then a legacy config.json; the first that exists
// wins. When none exist it defaults to config.yaml (the path a fresh config is
// written to).
func ResolveConfigPath(explicit string) string {
	if strings.TrimSpace(explicit) != "" {
		return explicit
	}
	for _, candidate := range configFileCandidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return "config.yaml"
}

// MigrateLegacyJSONConfigPath resolves the config path and, when no explicit
// path is given and only a legacy config.json exists (no YAML sibling),
// transcodes it to config.yaml and renames the original to config.json.bak.
// It returns the path to use afterwards and whether a migration happened.
//
// An explicit path is always honored verbatim and never migrated, so users who
// deliberately point at a .json file keep JSON behavior. key.json is never
// touched here — identity material stays in JSON.
func MigrateLegacyJSONConfigPath(explicit string) (path string, migrated bool, err error) {
	if strings.TrimSpace(explicit) != "" {
		return explicit, false, nil
	}

	// A YAML config already exists — prefer it, nothing to migrate.
	for _, candidate := range []string{"config.yaml", "config.yml"} {
		if _, statErr := os.Stat(candidate); statErr == nil {
			return candidate, false, nil
		}
	}

	const legacyPath = "config.json"
	if _, statErr := os.Stat(legacyPath); statErr != nil {
		// No legacy file either: fresh start, write to config.yaml.
		return "config.yaml", false, nil
	}

	jsonData, readErr := os.ReadFile(legacyPath)
	if readErr != nil {
		return "", false, fmt.Errorf("failed to read legacy config %q: %w", legacyPath, readErr)
	}
	yamlData, convErr := yaml.JSONToYAML(jsonData)
	if convErr != nil {
		return "", false, fmt.Errorf("failed to convert legacy config %q to yaml: %w", legacyPath, convErr)
	}

	const newPath = "config.yaml"
	if writeErr := os.WriteFile(newPath, yamlData, 0o644); writeErr != nil {
		return "", false, fmt.Errorf("failed to write %q during migration: %w", newPath, writeErr)
	}
	if renameErr := os.Rename(legacyPath, legacyPath+".bak"); renameErr != nil {
		return "", false, fmt.Errorf("failed to back up %q during migration: %w", legacyPath, renameErr)
	}
	return newPath, true, nil
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
