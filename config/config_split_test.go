package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfig_DualFileMerge(t *testing.T) {
	backupConfig := AppConfig
	backupLoaded := ConfigLoaded
	t.Cleanup(func() {
		AppConfig = backupConfig
		ConfigLoaded = backupLoaded
	})

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	keyPath := filepath.Join(dir, "key.json")

	publicContent := `{
  "custom_endpoints_v4": ["162.159.1.1"],
  "custom_endpoints_v6": ["2606:4700::1111"],
  "socks": {
    "bind_address": "127.0.0.1",
    "port": "1080",
    "dns": ["1.1.1.1"]
  },
  "logging": {
    "level": "debug",
    "format": "json"
  },
  "registration": {
    "device_name": "node-1"
  }
}`
	keyContent := `{
  "private_key": "PK",
  "endpoint_v4": "162.159.199.1",
  "endpoint_v6": "2606:4700:104::1",
  "endpoint_pub_key": "PUB",
  "account_mode": "team",
  "license": "LICENSE-1",
  "id": "id-1",
  "access_token": "token-1",
  "ipv4": "172.16.0.2",
  "ipv6": "2606:4700:110::2"
}`
	if err := os.WriteFile(configPath, []byte(publicContent), 0o600); err != nil {
		t.Fatalf("write config.json: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyContent), 0o600); err != nil {
		t.Fatalf("write key.json: %v", err)
	}

	if err := LoadConfig(configPath); err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if AppConfig.License != "LICENSE-1" {
		t.Fatalf("AppConfig.License = %q, want %q", AppConfig.License, "LICENSE-1")
	}
	if AppConfig.AccessToken != "token-1" {
		t.Fatalf("AppConfig.AccessToken = %q, want %q", AppConfig.AccessToken, "token-1")
	}
	if AppConfig.Socks.Port != "1080" {
		t.Fatalf("AppConfig.Socks.Port = %q, want %q", AppConfig.Socks.Port, "1080")
	}
	if AppConfig.Logging.Level != "debug" {
		t.Fatalf("AppConfig.Logging.Level = %q, want %q", AppConfig.Logging.Level, "debug")
	}
}

func TestLoadConfig_MigratesLegacySingleFile(t *testing.T) {
	backupConfig := AppConfig
	backupLoaded := ConfigLoaded
	t.Cleanup(func() {
		AppConfig = backupConfig
		ConfigLoaded = backupLoaded
	})

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	keyPath := filepath.Join(dir, "key.json")
	legacy := `{
  "private_key": "PK-OLD",
  "endpoint_v4": "162.159.198.1",
  "endpoint_v6": "2606:4700:103::1",
  "endpoint_pub_key": "PUB-OLD",
  "account_mode": "premium",
  "license": "LICENSE-OLD",
  "id": "legacy-id",
  "access_token": "legacy-token",
  "ipv4": "172.16.0.2",
  "ipv6": "2606:4700:110::2",
  "socks": {
    "bind_address": "0.0.0.0",
    "port": "1081",
    "dns": ["1.1.1.1"]
  },
  "logging": {
    "level": "info",
    "format": "text"
  }
}`
	if err := os.WriteFile(configPath, []byte(legacy), 0o600); err != nil {
		t.Fatalf("write legacy config: %v", err)
	}

	if err := LoadConfig(configPath); err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	keyRaw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("expected key.json after migration: %v", err)
	}
	if !strings.Contains(string(keyRaw), `"license": "LICENSE-OLD"`) {
		t.Fatalf("key.json missing migrated license, content:\n%s", string(keyRaw))
	}

	configRaw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config.json after migration: %v", err)
	}
	if strings.Contains(string(configRaw), `"access_token"`) {
		t.Fatalf("config.json should not keep key fields after migration, content:\n%s", string(configRaw))
	}
	if strings.Contains(string(configRaw), `"license"`) {
		t.Fatalf("config.json should not keep license after migration, content:\n%s", string(configRaw))
	}
}

func TestSaveConfig_WritesPublicAndKeySeparately(t *testing.T) {
	backupConfig := AppConfig
	backupLoaded := ConfigLoaded
	t.Cleanup(func() {
		AppConfig = backupConfig
		ConfigLoaded = backupLoaded
	})

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	keyPath := filepath.Join(dir, "key.json")

	AppConfig = Config{
		PrivateKey:        "PK",
		EndpointV4:        "162.159.199.1",
		EndpointV6:        "2606:4700:104::1",
		EndpointPubKey:    "PUB",
		AccountMode:       "free",
		License:           "LICENSE-1",
		ID:                "id-1",
		AccessToken:       "token-1",
		IPv4:              "172.16.0.2",
		IPv6:              "2606:4700:110::2",
		CustomEndpointsV4: []string{"162.159.1.1"},
		Socks: SocksConfig{
			BindAddress: "127.0.0.1",
			Port:        "1080",
			DNS:         []string{"1.1.1.1"},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
		},
		Registration: RegistrationInfo{
			DeviceName: "node-1",
		},
	}

	if err := AppConfig.SaveConfig(configPath); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}

	configRaw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config.json: %v", err)
	}
	keyRaw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key.json: %v", err)
	}

	if strings.Contains(string(configRaw), `"access_token"`) {
		t.Fatalf("config.json should not contain access_token, content:\n%s", string(configRaw))
	}
	if !strings.Contains(string(configRaw), `"socks"`) {
		t.Fatalf("config.json should contain socks, content:\n%s", string(configRaw))
	}
	if !strings.Contains(string(keyRaw), `"access_token": "token-1"`) {
		t.Fatalf("key.json should contain access_token, content:\n%s", string(keyRaw))
	}
	if strings.Contains(string(keyRaw), `"socks"`) {
		t.Fatalf("key.json should not contain socks, content:\n%s", string(keyRaw))
	}
}

func TestLoadConfig_KeyFileWinsOnConflict(t *testing.T) {
	backupConfig := AppConfig
	backupLoaded := ConfigLoaded
	t.Cleanup(func() {
		AppConfig = backupConfig
		ConfigLoaded = backupLoaded
	})

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	keyPath := filepath.Join(dir, "key.json")

	legacyWithResidue := `{
  "license": "LICENSE-CONFIG",
  "access_token": "token-config",
  "id": "id-config",
  "socks": {
    "bind_address": "127.0.0.1",
    "port": "1080",
    "dns": ["1.1.1.1"]
  }
}`
	keyContent := `{
  "license": "LICENSE-KEY",
  "access_token": "token-key",
  "id": "id-key"
}`
	if err := os.WriteFile(configPath, []byte(legacyWithResidue), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyContent), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	if err := LoadConfig(configPath); err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if AppConfig.License != "LICENSE-KEY" {
		t.Fatalf("AppConfig.License = %q, want %q", AppConfig.License, "LICENSE-KEY")
	}
	if AppConfig.AccessToken != "token-key" {
		t.Fatalf("AppConfig.AccessToken = %q, want %q", AppConfig.AccessToken, "token-key")
	}
	if AppConfig.ID != "id-key" {
		t.Fatalf("AppConfig.ID = %q, want %q", AppConfig.ID, "id-key")
	}
}

func TestSaveConfig_JSONShape(t *testing.T) {
	backupConfig := AppConfig
	t.Cleanup(func() {
		AppConfig = backupConfig
	})

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	keyPath := filepath.Join(dir, "key.json")
	AppConfig = Config{
		License: "L1",
		Socks: SocksConfig{
			BindAddress: "127.0.0.1",
			Port:        "1080",
			DNS:         []string{"1.1.1.1"},
		},
	}
	if err := AppConfig.SaveConfig(configPath); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}

	var publicMap map[string]any
	publicRaw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if err := json.Unmarshal(publicRaw, &publicMap); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	if _, ok := publicMap["license"]; ok {
		t.Fatalf("config.json should not expose license")
	}

	var keyMap map[string]any
	keyRaw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if err := json.Unmarshal(keyRaw, &keyMap); err != nil {
		t.Fatalf("unmarshal key: %v", err)
	}
	if _, ok := keyMap["license"]; !ok {
		t.Fatalf("key.json should contain license")
	}
}
