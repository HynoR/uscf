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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/HynoR/uscf/models"

	"github.com/HynoR/uscf/api"
	"github.com/HynoR/uscf/config"
	"github.com/HynoR/uscf/internal"
	"github.com/HynoR/uscf/internal/netstack"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/tun"
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

const (
	accountModeFree    = "free"
	accountModePremium = "premium"
	accountModeTeam    = "team"
	maxDeviceNameLen   = 16
)

type startupAction string

const (
	startupUseExisting     startupAction = "use_existing"
	startupRegisterFree    startupAction = "register_free"
	startupRegisterPremium startupAction = "register_premium"
	startupRegisterTeam    startupAction = "register_team"
)

type startupDecision struct {
	Action            startupAction
	EffectiveMode     string
	ShouldPersistMode bool
	ModeWasInvalid    bool
	IgnoredLicense    bool
	IgnoredJWT        bool
}

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
	proxyCmd.Flags().Bool("use-ipv6", false, "Use IPv6 for MASQUE connection (overrides config file)")
	proxyCmd.Flags().Bool("http2", false, "Use HTTP/2 over TCP+TLS instead of HTTP/3 over QUIC (overrides config file)")
	proxyCmd.Flags().Bool("l4", false, "Use L4 mode: tunnel each TCP flow as an HTTP/3 CONNECT stream, bypassing the userspace netstack (faster, TCP-only)")
	proxyCmd.Flags().String("l4-udp", "", "L4 UDP handling: \"block\" (reject UDP ASSOCIATE) or \"direct\" (relay UDP directly, bypassing WARP)")

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
	customJWT, _ := cmd.Flags().GetString("jwt")
	customJWT = strings.TrimSpace(customJWT)
	customJWT, jwtFromFile, jwtResolveErr := resolveJWTFromFlagOrFile(configPath, config.ConfigLoaded, config.AppConfig, customLicense, customJWT)
	if jwtResolveErr != nil {
		slog.Warn("failed to consume jwt from jwt.txt, continuing startup", "path", jwtFilePathFromConfigPath(configPath), "error", jwtResolveErr)
	}
	if jwtFromFile {
		slog.Info("consumed jwt from jwt.txt", "path", jwtFilePathFromConfigPath(configPath))
	}

	// 检查是否需要重置SOCKS5配置
	resetConfig, _ := cmd.Flags().GetBool("reset-config")
	decision, err := decideStartupAction(config.ConfigLoaded, config.AppConfig, customLicense, customJWT)
	if err != nil {
		return err
	}
	if decision.ModeWasInvalid {
		slog.Warn("invalid account_mode in config, falling back to free", "mode", config.AppConfig.AccountMode)
	}
	if decision.IgnoredLicense {
		slog.Info("ignoring --license for existing non-free account mode", "account_mode", decision.EffectiveMode)
	}
	if decision.IgnoredJWT {
		slog.Info("ignoring --jwt for existing non-free account mode", "account_mode", decision.EffectiveMode)
	}

	switch decision.Action {
	case startupUseExisting:
		if config.ConfigLoaded && decision.ShouldPersistMode {
			config.AppConfig.AccountMode = decision.EffectiveMode
			if err := config.AppConfig.SaveConfig(configPath); err != nil {
				slog.Warn("failed to persist inferred account mode", "path", configPath, "error", err)
			}
		}

		if resetConfig && config.ConfigLoaded {
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
	case startupRegisterFree, startupRegisterPremium, startupRegisterTeam:
		registrationMode := decision.EffectiveMode
		if err := handleRegistration(cmd, configPath, registrationMode, customLicense, customJWT); err != nil {
			return err
		}

		// 更新一些需要从内部常量获取的配置值
		config.AppConfig.Socks.SNIAddress = internal.ConnectSNI

		// 保存更新后的配置
		if err := config.AppConfig.SaveConfig(configPath); err != nil {
			slog.Warn("failed to save updated config", "path", configPath, "error", err)
		}
	default:
		return fmt.Errorf("unsupported startup action: %s", decision.Action)
	}

	// 检查并应用命令行参数覆盖配置文件的值
	configChanged, flagOverrides := applySocksFlagOverrides(cmd, &config.AppConfig)

	if configChanged {
		if err := config.AppConfig.SaveConfig(configPath); err != nil {
			slog.Warn("config save failed", "path", configPath, "error", err)
		}
	}

	if err := setupAndRunSocksProxy(cmd, flagOverrides, configChanged); err != nil {
		return err
	}

	return nil
}

func applySocksFlagOverrides(cmd *cobra.Command, cfg *config.Config) (bool, []string) {
	configChanged := false
	var overrides []string

	if bindAddress, _ := cmd.Flags().GetString("bind-address"); bindAddress != "" {
		cfg.Socks.BindAddress = bindAddress
		configChanged = true
		overrides = append(overrides, "bind_address")
	}

	if port, _ := cmd.Flags().GetString("port"); port != "" {
		cfg.Socks.Port = port
		configChanged = true
		overrides = append(overrides, "port")
	}

	if username, _ := cmd.Flags().GetString("username"); username != "" {
		cfg.Socks.Username = username
		configChanged = true
		overrides = append(overrides, "username")
	}

	if password, _ := cmd.Flags().GetString("password"); password != "" {
		cfg.Socks.Password = password
		configChanged = true
		overrides = append(overrides, "password")
	}

	if cmd.Flags().Changed("use-ipv6") {
		useIPv6, _ := cmd.Flags().GetBool("use-ipv6")
		cfg.Socks.UseIPv6 = useIPv6
		configChanged = true
		overrides = append(overrides, "use_ipv6")
	}

	if cmd.Flags().Changed("http2") {
		useHTTP2, _ := cmd.Flags().GetBool("http2")
		cfg.Socks.HTTP2 = useHTTP2
		configChanged = true
		overrides = append(overrides, "http2")
	}

	if cmd.Flags().Changed("l4") {
		useL4, _ := cmd.Flags().GetBool("l4")
		cfg.Socks.L4 = useL4
		configChanged = true
		overrides = append(overrides, "l4")
	}

	if cmd.Flags().Changed("l4-udp") {
		raw, _ := cmd.Flags().GetString("l4-udp")
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case config.L4UDPBlock, config.L4UDPDirect:
			cfg.Socks.L4UDP = strings.ToLower(strings.TrimSpace(raw))
			configChanged = true
			overrides = append(overrides, "l4_udp")
		default:
			slog.Warn("ignoring invalid --l4-udp value; expected \"block\" or \"direct\"", "value", raw)
		}
	}

	return configChanged, overrides
}

func jwtFilePathFromConfigPath(configPath string) string {
	if strings.TrimSpace(configPath) == "" {
		configPath = "config.json"
	}
	return filepath.Join(filepath.Dir(configPath), "jwt.txt")
}

func consumeJWTFromSiblingFile(configPath string) (string, error) {
	jwtPath := jwtFilePathFromConfigPath(configPath)

	raw, err := os.ReadFile(jwtPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("failed to read jwt file %q: %w", jwtPath, err)
	}

	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", nil
	}

	if err := os.WriteFile(jwtPath, []byte(""), 0o600); err != nil {
		return token, fmt.Errorf("failed to clear jwt file %q: %w", jwtPath, err)
	}

	return token, nil
}

func resolveJWTFromFlagOrFile(configPath string, configLoaded bool, cfg config.Config, customLicense, customJWT string) (resolvedJWT string, fromFile bool, warnErr error) {
	customLicense = strings.TrimSpace(customLicense)
	customJWT = strings.TrimSpace(customJWT)

	if customJWT != "" || customLicense != "" {
		return customJWT, false, nil
	}

	decision, err := decideStartupAction(configLoaded, cfg, customLicense, "")
	if err != nil {
		return customJWT, false, err
	}
	if decision.EffectiveMode != accountModeFree {
		return customJWT, false, nil
	}

	fileJWT, consumeErr := consumeJWTFromSiblingFile(configPath)
	if fileJWT == "" {
		return customJWT, false, consumeErr
	}
	if consumeErr != nil {
		return fileJWT, true, consumeErr
	}

	return fileJWT, true, nil
}

func decideStartupAction(configLoaded bool, cfg config.Config, customLicense, customJWT string) (startupDecision, error) {
	customLicense = strings.TrimSpace(customLicense)
	customJWT = strings.TrimSpace(customJWT)

	if customLicense != "" && customJWT != "" {
		return startupDecision{}, fmt.Errorf("cannot use --license and --jwt together")
	}

	if !configLoaded || !isStartupConfigValid(cfg) {
		switch {
		case customLicense != "":
			return startupDecision{
				Action:        startupRegisterPremium,
				EffectiveMode: accountModePremium,
			}, nil
		case customJWT != "":
			return startupDecision{
				Action:        startupRegisterTeam,
				EffectiveMode: accountModeTeam,
			}, nil
		default:
			return startupDecision{
				Action:        startupRegisterFree,
				EffectiveMode: accountModeFree,
			}, nil
		}
	}

	effectiveMode, shouldPersist, modeWasInvalid := resolveAccountMode(cfg, customLicense)
	decision := startupDecision{
		EffectiveMode:     effectiveMode,
		ShouldPersistMode: shouldPersist,
		ModeWasInvalid:    modeWasInvalid,
	}

	switch effectiveMode {
	case accountModePremium:
		decision.Action = startupUseExisting
		decision.IgnoredLicense = customLicense != ""
		decision.IgnoredJWT = customJWT != ""
	case accountModeTeam:
		decision.Action = startupUseExisting
		decision.IgnoredLicense = customLicense != ""
		decision.IgnoredJWT = customJWT != ""
	case accountModeFree:
		switch {
		case customLicense != "":
			decision.Action = startupRegisterPremium
			decision.EffectiveMode = accountModePremium
		case customJWT != "":
			decision.Action = startupRegisterTeam
			decision.EffectiveMode = accountModeTeam
		default:
			decision.Action = startupUseExisting
		}
	default:
		return startupDecision{}, fmt.Errorf("unsupported account mode: %s", effectiveMode)
	}

	return decision, nil
}

func isStartupConfigValid(cfg config.Config) bool {
	return strings.TrimSpace(cfg.ID) != "" && strings.TrimSpace(cfg.AccessToken) != ""
}

func resolveAccountMode(cfg config.Config, customLicense string) (mode string, shouldPersist bool, modeWasInvalid bool) {
	raw := strings.TrimSpace(cfg.AccountMode)
	normalized := strings.ToLower(raw)

	switch normalized {
	case accountModeFree, accountModePremium, accountModeTeam:
		if raw != normalized {
			return normalized, true, false
		}
		return normalized, false, false
	case "":
		if strings.HasPrefix(strings.TrimSpace(cfg.ID), "t.") {
			return accountModeTeam, true, false
		}
		if customLicense != "" && customLicense == strings.TrimSpace(cfg.License) {
			return accountModePremium, true, false
		}
		return accountModeFree, true, false
	default:
		return accountModeFree, true, true
	}
}

func normalizeDeviceName(raw string) string {
	s := strings.TrimSpace(strings.ToLower(raw))
	var b strings.Builder
	prevDash := false

	for _, r := range s {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
			prevDash = false
		case r == '-' || r == '_' || unicode.IsSpace(r):
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
		default:
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}

	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "node"
	}
	if len(out) > maxDeviceNameLen {
		out = strings.Trim(out[:maxDeviceNameLen], "-")
		if out == "" {
			out = "node"
		}
	}
	return out
}

func accountIDSuffix(accountID string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(accountID)) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	cleaned := b.String()
	if cleaned == "" {
		cleaned = "0000"
	}
	if len(cleaned) > 4 {
		cleaned = cleaned[len(cleaned)-4:]
	}
	return cleaned
}

func buildAutoDeviceName(mode, hostname, accountID string) string {
	prefix := "p"
	if mode == accountModeTeam {
		prefix = "t"
	}

	host := normalizeDeviceName(hostname)
	id4 := accountIDSuffix(accountID)

	maxHostLen := maxDeviceNameLen - len(prefix) - 1 - 1 - len(id4)
	if maxHostLen < 1 {
		maxHostLen = 1
	}
	if len(host) > maxHostLen {
		host = strings.Trim(host[:maxHostLen], "-")
		if host == "" {
			host = "n"
		}
	}

	return normalizeDeviceName(fmt.Sprintf("%s-%s-%s", prefix, host, id4))
}

func resolveRegistrationDeviceName(mode, explicitName, accountID string) string {
	if mode != accountModePremium && mode != accountModeTeam {
		return explicitName
	}

	explicit := strings.TrimSpace(explicitName)
	if explicit != "" {
		return normalizeDeviceName(explicit)
	}

	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "node"
	}
	return buildAutoDeviceName(mode, hostname, accountID)
}

// handleRegistration 处理自动注册流程
func handleRegistration(cmd *cobra.Command, configPath, accountMode, customLicense, customJWT string) error {
	slog.Info("starting registration flow", "account_mode", accountMode)

	// 获取注册参数
	explicitDeviceName, _ := cmd.Flags().GetString("name")
	locale, _ := cmd.Flags().GetString("locale")
	model, _ := cmd.Flags().GetString("model")
	acceptTos, _ := cmd.Flags().GetBool("accept-tos")

	slog.Info("registering account", "locale", locale, "model", model)

	registerJWT := ""
	switch accountMode {
	case accountModeFree, accountModePremium:
		registerJWT = ""
	case accountModeTeam:
		registerJWT = customJWT
		if registerJWT == "" {
			return fmt.Errorf("Failed to register: jwt is required for team mode")
		}
	default:
		return fmt.Errorf("Failed to register: unsupported account mode %q", accountMode)
	}

	// 注册账户
	accountData, err := registerAccountFunc(model, locale, registerJWT, acceptTos)
	if err != nil {
		return fmt.Errorf("Failed to register: %v", err)
	}

	deviceName := resolveRegistrationDeviceName(accountMode, explicitDeviceName, accountData.ID)
	if accountMode == accountModePremium || accountMode == accountModeTeam {
		if strings.TrimSpace(explicitDeviceName) == "" {
			slog.Info("auto-generated device name for registration", "device_name", deviceName)
		} else if deviceName != explicitDeviceName {
			slog.Warn("provided --name normalized/truncated for registration", "original", explicitDeviceName, "normalized", deviceName)
		}
	}

	if accountMode == accountModePremium {
		if customLicense == "" {
			return fmt.Errorf("Failed to apply license: license is required for premium mode")
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
		accountMode,
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

func tcpAddrFromHost(host string, port int, useIPv6 bool) (*net.TCPAddr, error) {
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

	return &net.TCPAddr{IP: ip, Port: port}, nil
}

func selectMasqueEndpoint(port int, useIPv6 bool, useHTTP2 bool) (net.Addr, func() net.Addr, error) {
	if useHTTP2 {
		h2Host := strings.TrimSpace(config.AppConfig.EndpointH2V4)
		if useIPv6 {
			h2Host = strings.TrimSpace(config.AppConfig.EndpointH2V6)
			if h2Host == "" {
				return nil, nil, fmt.Errorf("http2 with use_ipv6 requires endpoint_h2_v6")
			}
		} else if h2Host == "" {
			h2Host = config.DefaultEndpointH2V4
		}

		endpoint, err := tcpAddrFromHost(h2Host, port, useIPv6)
		if err != nil {
			return nil, nil, err
		}
		slog.Info("HTTP/2 TCP fallback enabled", "endpoint", endpoint.String(), "family", familyLabel(useIPv6))
		return endpoint, nil, nil
	}

	fallbackHost := config.AppConfig.EndpointV4
	customHosts := config.AppConfig.CustomEndpointsV4
	if useIPv6 {
		fallbackHost = config.AppConfig.EndpointV6
		customHosts = config.AppConfig.CustomEndpointsV6
	}

	fallbackEndpoint, err := udpAddrFromHost(fallbackHost, port, useIPv6)
	if err != nil {
		return nil, nil, err
	}

	candidateEndpoints := buildCustomEndpointPool(customHosts, port, useIPv6)
	if len(candidateEndpoints) > 0 {
		slog.Info("custom endpoint pool enabled", "family", familyLabel(useIPv6), "count", len(candidateEndpoints))
		return fallbackEndpoint, newEndpointSelector(candidateEndpoints), nil
	}
	if len(customHosts) > 0 {
		slog.Warn("custom endpoint list configured but no valid entries; using fallback endpoint", "family", familyLabel(useIPv6))
	}

	return fallbackEndpoint, nil, nil
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

func newEndpointSelector(candidates []*net.UDPAddr) func() net.Addr {
	if len(candidates) == 0 {
		return nil
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var mu sync.Mutex

	return func() net.Addr {
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

func newLocalDNSResolver() (api.NameResolver, error) {
	dnsTimeout := config.AppConfig.Socks.DNSTimeout.Duration()
	dnsServer := "8.8.8.8:53"
	if len(config.AppConfig.Socks.DNS) > 0 {
		var err error
		dnsServer, err = normalizeDNSServerAddress(config.AppConfig.Socks.DNS[0])
		if err != nil {
			return nil, fmt.Errorf("Failed to parse local DNS server %s: %v", config.AppConfig.Socks.DNS[0], err)
		}
	}
	return &api.LocalDNSResolver{
		DNSServer: dnsServer,
		Timeout:   dnsTimeout,
	}, nil
}

type socksRuntimeMeta struct {
	dnsMode       string
	bypassDomains int
	proxyTCPPorts int
	blockUDP443   bool
	udpMode       string // L4 UDP disposition ("block"/"direct"); empty outside L4
}

type proxyReadyInfo struct {
	endpoint          net.Addr
	endpointSelector  func() net.Addr
	useHTTP2          bool
	transport         string // explicit transport label (e.g. "l4"); empty derives from useHTTP2
	connectionTimeout time.Duration
	overrides         []string
	configSaved       bool
	socksOnly         bool
	meta              socksRuntimeMeta
}

// setupAndRunSocksProxy 设置并运行SOCKS5代理
func setupAndRunSocksProxy(cmd *cobra.Command, overrides []string, configSaved bool) error {
	// L4 模式走独立链路：HTTP/3 CONNECT 流，绕过 TUN/netstack/connect-ip。
	if config.AppConfig.Socks.L4 {
		return setupAndRunL4Proxy(cmd, overrides, configSaved)
	}

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

	socksRuntime, runtimeMeta, err := prepareSocksRuntime(tunNet, connectionTimeout, idleTimeout)
	if err != nil {
		return err
	}

	readyCh := startTunnel(cmd, tlsConfig, endpoint, endpointSelector, tunDev, tunNet, socksRuntime)
	<-readyCh

	readyInfo := proxyReadyInfo{
		endpoint:          endpoint,
		endpointSelector:  endpointSelector,
		useHTTP2:          config.AppConfig.Socks.HTTP2,
		connectionTimeout: connectionTimeout,
		overrides:         overrides,
		configSaved:       configSaved,
		meta:              runtimeMeta,
	}
	return runSocksServer(socksRuntime, idleTimeout, readyInfo)
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
func prepareNetworkConfig(cmd *cobra.Command) (net.Addr, func() net.Addr, []netip.Addr, []netip.Addr, error) {
	// 从配置文件获取连接端口
	connectPort := config.AppConfig.Socks.ConnectPort

	useIPv6 := config.AppConfig.Socks.UseIPv6
	useHTTP2 := config.AppConfig.Socks.HTTP2
	fallbackEndpoint, endpointSelector, err := selectMasqueEndpoint(connectPort, useIPv6, useHTTP2)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to parse fallback endpoint: %w", err)
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

// mtuWarning returns a warning for MTU values outside the supported range.
// 1280-1400 is silent: the connect-ip ICMP packet-too-big safety net (which
// always advertises 1280) lets TCP recover if the path turns out smaller.
func mtuWarning(mtu int) (string, bool) {
	switch {
	case mtu < 1280:
		return "MTU below 1280 may break IPv6 and cause path-MTU issues", true
	case mtu > 1400:
		return "MTU above 1400 will likely exceed the QUIC datagram size and be clamped back to 1280 by ICMP packet-too-big", true
	}
	return "", false
}

// createTunDevice 创建TUN设备
func createTunDevice(localAddresses, dnsAddrs []netip.Addr, cmd *cobra.Command) (tun.Device, *netstack.Net, error) {
	// 从配置中获取MTU
	mtu := config.AppConfig.Socks.MTU
	if msg, warn := mtuWarning(mtu); warn {
		slog.Warn(msg, "mtu", mtu)
	}

	tunDev, tunNet, err := netstack.CreateNetTUN(localAddresses, dnsAddrs, mtu)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create virtual TUN device: %v", err)
	}
	return tunDev, tunNet, nil
}

// startTunnel 配置并启动隧道连接
func startTunnel(cmd *cobra.Command, tlsConfig *tls.Config, endpoint net.Addr, endpointSelector func() net.Addr, tunDev tun.Device, tunNet *netstack.Net, socksRuntime *socksRuntime) <-chan struct{} {
	readyCh := make(chan struct{})
	var readyOnce sync.Once
	writeTunnelStateSafe(tunnelStateDown)

	// 从配置文件读取隧道参数
	keepalivePeriod := config.AppConfig.Socks.KeepalivePeriod.Duration()
	initialPacketSize := config.AppConfig.Socks.InitialPacketSize
	mtu := config.AppConfig.Socks.MTU
	reconnectDelay := config.AppConfig.Socks.ReconnectDelay.Duration()
	maxReconnectAttempts := config.AppConfig.Socks.MaxReconnectAttempts
	drainGrace := config.AppConfig.Socks.DrainGrace.Duration()
	reconnectLog := &api.TunnelReconnectLog{Trigger: "backoff"}

	configTunnel := api.ConnectionConfig{
		TLSConfig:              tlsConfig,
		KeepAlivePeriod:        keepalivePeriod,
		InitialPacketSize:      initialPacketSize,
		Endpoint:               endpoint,
		EndpointSelector:       endpointSelector,
		UseHTTP2:               config.AppConfig.Socks.HTTP2,
		MTU:                    mtu,
		MaxReconnectAttempts:   maxReconnectAttempts,
		AlwaysReconnect:        config.AppConfig.Socks.AlwaysReconnect,
		WaitForReconnectDemand: socksRuntime.WaitForReconnectDemand,
		ReconnectLog:           reconnectLog,
		ReconnectStrategy: &api.ExponentialBackoff{
			InitialDelay: reconnectDelay,
			MaxDelay:     5 * time.Minute,
			Factor:       2.0,
		},
		OnConnected: func() {
			if socksRuntime != nil {
				socksRuntime.SetTunnelUp(true)
				socksRuntime.CancelScheduledDrain()
				socksRuntime.drainDemand()
			}
			writeTunnelStateSafe(tunnelStateUp)
			readyOnce.Do(func() {
				close(readyCh)
			})
		},
		OnDisconnected: func(err error) {
			writeTunnelStateSafe(tunnelStateDown)
			if socksRuntime == nil {
				return
			}
			reconnectLog.DisconnectedAt = time.Now()
			socksRuntime.SetTunnelUp(false)
			reason, remote := api.TunnelDisconnectReason(err)
			reconnectMode := "on_demand"
			if config.AppConfig.Socks.AlwaysReconnect {
				reconnectMode = "immediate"
			}
			slog.Warn(
				"disconnected",
				"reason", reason,
				"remote", remote,
				"grace", drainGrace,
				"reconnect", reconnectMode,
			)
			socksRuntime.ScheduleDrain(err, drainGrace)
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
func prepareSocksRuntime(tunNet *netstack.Net, connectionTimeout, idleTimeout time.Duration) (*socksRuntime, socksRuntimeMeta, error) {
	routePolicy, err := newRoutePolicy(config.AppConfig.Socks.BypassDomain, config.AppConfig.Socks.ProxyTCPPort)
	if err != nil {
		return nil, socksRuntimeMeta{}, err
	}
	bypassMatcher := routePolicy.bypassMatcher
	meta := socksRuntimeMeta{
		blockUDP443: config.AppConfig.Socks.BlockUDP443,
	}
	if routePolicy.ProxyTCPPortsEnabled() {
		meta.proxyTCPPorts = len(routePolicy.proxyTCPPortList)
	} else if bypassMatcher.Enabled() {
		meta.bypassDomains = len(bypassMatcher.domains)
	}

	// 根据配置选择DNS解析器
	var resolver api.NameResolver
	if config.AppConfig.Socks.RemoteDNS {
		var dnsAddrs []netip.Addr
		for _, dns := range config.AppConfig.Socks.DNS {
			addr, err := netip.ParseAddr(dns)
			if err != nil {
				return nil, socksRuntimeMeta{}, fmt.Errorf("Failed to parse DNS server %s: %v", dns, err)
			}
			dnsAddrs = append(dnsAddrs, addr)
		}

		tunnelResolver := api.NewTunnelDNSResolver(tunNet, dnsAddrs, config.AppConfig.Socks.DNSTimeout.Duration())
		if bypassMatcher.Enabled() {
			localResolver, err := newLocalDNSResolver()
			if err != nil {
				return nil, socksRuntimeMeta{}, err
			}
			resolver = newBypassAwareResolver(bypassMatcher, localResolver, tunnelResolver)
			meta.dnsMode = "remote+bypass"
		} else {
			resolver = tunnelResolver
			meta.dnsMode = "remote"
		}
	} else {
		localResolver, err := newLocalDNSResolver()
		if err != nil {
			return nil, socksRuntimeMeta{}, err
		}
		resolver = localResolver
		meta.dnsMode = "local"
	}

	// 统一加缓存层，让 local / tunnel / bypass 三条路径都能享受缓存和 singleflight
	resolver = api.NewCachingResolver(resolver, 10*time.Minute, 5*time.Second, 4096)

	// 仅负责实际拨号，不做隧道状态门控；门控由socksRuntime统一处理。
	upstreamDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if config.AppConfig.Socks.BlockUDP443 && strings.HasPrefix(network, "udp") {
			_, port, err := net.SplitHostPort(addr)
			if err == nil && port == "443" {
				return nil, errUDP443Blocked
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

	// 从配置中获取身份验证设置
	username := config.AppConfig.Socks.Username
	password := config.AppConfig.Socks.Password

	verbose := config.AppConfig.Logging.SocksVerbose
	runtime := newSocksRuntime(
		upstreamDial,
		func(dialFunc socksDialFunc) socksServer {
			dialWithTarget := func(ctx context.Context, network, addr string, target socksTarget) (net.Conn, error) {
				if !selectTCPRoute(routePolicy, network, target) {
					slog.Debug("route policy selected direct network", "network", network, "host", target.Host, "port", target.Port, "target", addr)
					return directDial(ctx, network, addr)
				}

				return dialFunc(ctx, network, addr)
			}

			return createSocksServer(username, password, resolver, dialWithTarget, idleTimeout, verbose, false)
		},
	)
	runtime.SetVerboseLogging(config.AppConfig.Logging.SocksVerbose)

	return runtime, meta, nil
}

func proxyTransportLabel(useHTTP2 bool) string {
	if useHTTP2 {
		return "http2"
	}
	return "http3"
}

// resolvedTransportLabel prefers an explicit transport label (e.g. "l4") and
// otherwise derives http2/http3 from the flag.
func resolvedTransportLabel(info proxyReadyInfo) string {
	if info.transport != "" {
		return info.transport
	}
	return proxyTransportLabel(info.useHTTP2)
}

func selectedProxyEndpoint(endpoint net.Addr, selector func() net.Addr) string {
	if selector != nil {
		if selected := selector(); selected != nil {
			return selected.String()
		}
	}
	if endpoint != nil {
		return endpoint.String()
	}
	return ""
}

func logProxyReady(listenerAddr net.Addr, idleTimeout time.Duration, info proxyReadyInfo) {
	attrs := []any{
		"addr", listenerAddr.String(),
		"connect_timeout", info.connectionTimeout,
		"idle_timeout", idleTimeout,
	}
	if info.socksOnly {
		attrs = append(attrs, "mode", "socks", "dns", info.meta.dnsMode)
	} else {
		attrs = append(attrs,
			"endpoint", selectedProxyEndpoint(info.endpoint, info.endpointSelector),
			"transport", resolvedTransportLabel(info),
			"dns", info.meta.dnsMode,
			"tunnel", "up",
		)
	}
	if info.meta.blockUDP443 {
		attrs = append(attrs, "block_udp_443", true)
	}
	if info.meta.udpMode != "" {
		attrs = append(attrs, "l4_udp", info.meta.udpMode)
	}
	if info.meta.bypassDomains > 0 {
		attrs = append(attrs, "bypass_domains", info.meta.bypassDomains)
	}
	if info.meta.proxyTCPPorts > 0 {
		attrs = append(attrs, "proxy_tcp_ports", info.meta.proxyTCPPorts)
	}
	if len(info.overrides) > 0 {
		attrs = append(attrs, "overrides", strings.Join(info.overrides, ","))
	}
	if info.configSaved {
		attrs = append(attrs, "config_saved", true)
	}
	slog.Info("ready", attrs...)
}

// runSocksServer 创建并运行SOCKS5服务器
func runSocksServer(socksRuntime *socksRuntime, idleTimeout time.Duration, readyInfo proxyReadyInfo) error {
	bindAddress := config.AppConfig.Socks.BindAddress
	port := config.AppConfig.Socks.Port

	listener, err := net.Listen("tcp", net.JoinHostPort(bindAddress, port))
	if err != nil {
		return fmt.Errorf("Failed to start SOCKS proxy: %v", err)
	}
	logProxyReady(listener.Addr(), idleTimeout, readyInfo)

	var connSeq atomic.Uint64
	acceptBackoff := 5 * time.Millisecond

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				slog.Info("listener closed")
				return nil
			}
			slog.Warn("failed to accept connection", "error", err)
			time.Sleep(acceptBackoff)
			if acceptBackoff < 1*time.Second {
				acceptBackoff *= 2
			}
			continue
		}
		acceptBackoff = 5 * time.Millisecond
		connID := connSeq.Add(1)
		if socksRuntime.VerboseLoggingEnabled() {
			remote := "<unknown>"
			if addr := conn.RemoteAddr(); addr != nil {
				remote = addr.String()
			}
			slog.Debug("accepted SOCKS connection", "conn_id", connID, "remote", remote)
		}

		if socksRuntime.DropIfDisconnected(conn) {
			if socksRuntime.VerboseLoggingEnabled() {
				slog.Warn("SOCKS connection dropped immediately due to tunnel down", "conn_id", connID)
			}
			continue
		}

		timeoutConn := &models.TimeoutConn{
			Conn:        conn,
			IdleTimeout: idleTimeout,
		}
		trackedConn := socksRuntime.TrackConn(timeoutConn)
		server := socksRuntime.CurrentServer()
		if server == nil {
			slog.Warn("failed to serve SOCKS connection: server unavailable", "conn_id", connID)
			_ = trackedConn.Close()
			continue
		}

		go func(server socksServer, conn net.Conn, id uint64) {
			if err := server.ServeConn(conn); err != nil && !errors.Is(err, net.ErrClosed) {
				if socksRuntime.VerboseLoggingEnabled() {
					slog.Warn("failed to serve SOCKS connection", "conn_id", id, "error", err)
				} else {
					slog.Debug("failed to serve SOCKS connection", "error", err)
				}
			} else if socksRuntime.VerboseLoggingEnabled() {
				slog.Debug("SOCKS connection closed", "conn_id", id)
			}
			_ = conn.Close()
		}(server, trackedConn, connID)
	}
}

// createSocksServer 创建SOCKS5服务器（基于 txthinking/socks5 的自定义 adapter）。
// dialWithTarget 负责在已解析地址上拨号，同时拿到原始 target 以便做路由判定。
func createSocksServer(
	username, password string,
	resolver api.NameResolver,
	dialWithTarget targetDialFunc,
	idleTimeout time.Duration,
	verbose bool,
	tcpOnly bool,
) socksServer {
	return newTxthinkingAdapter(username, password, resolver, dialWithTarget, idleTimeout, verbose, tcpOnly)
}

var errUDP443Blocked = errors.New("udp/443 blocked by config")
