package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestGetDefaultSocksConfig_ProxyTCPPortEmpty(t *testing.T) {
	defaults := GetDefaultSocksConfig()
	if defaults.ProxyTCPPort == nil {
		t.Fatalf("default ProxyTCPPort should be an empty slice, got nil")
	}
	if len(defaults.ProxyTCPPort) != 0 {
		t.Fatalf("default ProxyTCPPort length = %d, want 0", len(defaults.ProxyTCPPort))
	}
}

func TestLoadConfig_NormalizesProxyTCPPort(t *testing.T) {
	backupConfig := AppConfig
	backupLoaded := ConfigLoaded
	t.Cleanup(func() {
		AppConfig = backupConfig
		ConfigLoaded = backupLoaded
	})

	configPath := filepath.Join(t.TempDir(), "config.json")
	content := `{
  "socks": {
    "bind_address": "127.0.0.1",
    "port": "1080",
    "dns": ["1.1.1.1"],
    "proxy_tcp_port": [443, 80, 443, 80]
  }
}`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config.json: %v", err)
	}

	if err := LoadConfig(configPath); err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	want := []int{443, 80}
	if !reflect.DeepEqual(AppConfig.Socks.ProxyTCPPort, want) {
		t.Fatalf("AppConfig.Socks.ProxyTCPPort = %v, want %v", AppConfig.Socks.ProxyTCPPort, want)
	}
}

func TestLoadConfig_RejectsInvalidProxyTCPPort(t *testing.T) {
	backupConfig := AppConfig
	backupLoaded := ConfigLoaded
	t.Cleanup(func() {
		AppConfig = backupConfig
		ConfigLoaded = backupLoaded
	})

	configPath := filepath.Join(t.TempDir(), "config.json")
	content := `{
  "socks": {
    "bind_address": "127.0.0.1",
    "port": "1080",
    "dns": ["1.1.1.1"],
    "proxy_tcp_port": [80, 0, 65536]
  }
}`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config.json: %v", err)
	}

	err := LoadConfig(configPath)
	if err == nil {
		t.Fatalf("expected LoadConfig() to reject invalid proxy_tcp_port")
	}
	if !strings.Contains(err.Error(), "proxy_tcp_port") {
		t.Fatalf("expected proxy_tcp_port error, got %v", err)
	}
}

func TestSaveConfig_RoundTripsProxyTCPPort(t *testing.T) {
	backupConfig := AppConfig
	backupLoaded := ConfigLoaded
	t.Cleanup(func() {
		AppConfig = backupConfig
		ConfigLoaded = backupLoaded
	})

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")

	AppConfig = Config{
		Socks: SocksConfig{
			BindAddress:  "127.0.0.1",
			Port:         "1080",
			DNS:          []string{"1.1.1.1"},
			ProxyTCPPort: []int{80, 443},
		},
		Logging: GetDefaultLoggingConfig(),
	}

	if err := AppConfig.SaveConfig(configPath); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}

	if err := LoadConfig(configPath); err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	want := []int{80, 443}
	if !reflect.DeepEqual(AppConfig.Socks.ProxyTCPPort, want) {
		t.Fatalf("AppConfig.Socks.ProxyTCPPort = %v, want %v", AppConfig.Socks.ProxyTCPPort, want)
	}
}
