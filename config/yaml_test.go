package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func restoreGlobals(t *testing.T) {
	t.Helper()
	backupConfig := AppConfig
	backupLoaded := ConfigLoaded
	t.Cleanup(func() {
		AppConfig = backupConfig
		ConfigLoaded = backupLoaded
	})
}

func TestLoadConfig_ReadsYAML(t *testing.T) {
	restoreGlobals(t)

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	keyPath := filepath.Join(dir, "key.json")

	yamlContent := `socks:
  bind_address: 127.0.0.1
  port: "1080"
  dns:
    - 1.1.1.1
  keepalive_period: 45s
  idle_timeout: 90000000000   # 90s as nanoseconds (legacy numeric form)
logging:
  level: debug
  format: json
registration:
  device_name: yaml-node
`
	keyContent := `{"license": "LIC-Y", "access_token": "tok-y"}`
	if err := os.WriteFile(configPath, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyContent), 0o600); err != nil {
		t.Fatalf("write key.json: %v", err)
	}

	if err := LoadConfig(configPath); err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if AppConfig.Socks.Port != "1080" {
		t.Fatalf("Socks.Port = %q, want 1080", AppConfig.Socks.Port)
	}
	if AppConfig.Socks.KeepalivePeriod.Duration() != 45*time.Second {
		t.Fatalf("KeepalivePeriod = %v, want 45s", AppConfig.Socks.KeepalivePeriod.Duration())
	}
	if AppConfig.Socks.IdleTimeout.Duration() != 90*time.Second {
		t.Fatalf("IdleTimeout = %v, want 90s (from numeric nanoseconds)", AppConfig.Socks.IdleTimeout.Duration())
	}
	if AppConfig.Logging.Level != "debug" {
		t.Fatalf("Logging.Level = %q, want debug", AppConfig.Logging.Level)
	}
	if AppConfig.License != "LIC-Y" {
		t.Fatalf("License = %q, want LIC-Y", AppConfig.License)
	}
}

func TestSaveConfig_WritesYAMLAndKeyStaysJSON(t *testing.T) {
	restoreGlobals(t)

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	keyPath := filepath.Join(dir, "key.json")

	AppConfig = Config{
		License:     "LIC-1",
		AccessToken: "tok-1",
		Socks: SocksConfig{
			BindAddress:     "127.0.0.1",
			Port:            "1080",
			DNS:             []string{"1.1.1.1"},
			KeepalivePeriod: Duration(30 * time.Second),
			L4UDP:           L4UDPBlock,
		},
		Logging: LoggingConfig{Level: "info", Format: "text"},
	}

	if err := AppConfig.SaveConfig(configPath); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}

	configRaw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config.yaml: %v", err)
	}
	configStr := string(configRaw)
	// YAML, not JSON: no top-level object braces, snake_case keys present.
	if strings.HasPrefix(strings.TrimSpace(configStr), "{") {
		t.Fatalf("config.yaml looks like JSON:\n%s", configStr)
	}
	if !strings.Contains(configStr, "bind_address: 127.0.0.1") {
		t.Fatalf("config.yaml missing expected YAML key:\n%s", configStr)
	}
	// Duration serializes as a human-readable string, not nanoseconds.
	if !strings.Contains(configStr, "keepalive_period: 30s") {
		t.Fatalf("config.yaml missing human-readable duration:\n%s", configStr)
	}
	// Key material must not leak into the public config.
	if strings.Contains(configStr, "LIC-1") || strings.Contains(configStr, "tok-1") {
		t.Fatalf("config.yaml leaked key material:\n%s", configStr)
	}

	keyRaw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key.json: %v", err)
	}
	keyStr := string(keyRaw)
	// key.json stays JSON.
	if !strings.HasPrefix(strings.TrimSpace(keyStr), "{") {
		t.Fatalf("key.json is not JSON:\n%s", keyStr)
	}
	if !strings.Contains(keyStr, `"license": "LIC-1"`) {
		t.Fatalf("key.json missing license:\n%s", keyStr)
	}
}

func TestSaveThenLoadYAML_RoundTrip(t *testing.T) {
	restoreGlobals(t)

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	AppConfig = Config{
		License: "LIC-RT",
		Socks: SocksConfig{
			BindAddress:     "0.0.0.0",
			Port:            "2080",
			DNS:             []string{"8.8.8.8", "1.1.1.1"},
			KeepalivePeriod: Duration(90 * time.Second),
			IdleTimeout:     Duration(7 * time.Minute),
			L4UDP:           L4UDPDirect,
		},
		Logging: LoggingConfig{Level: "warn", Format: "json"},
	}
	if err := AppConfig.SaveConfig(configPath); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}

	AppConfig = Config{}
	if err := LoadConfig(configPath); err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if AppConfig.Socks.Port != "2080" {
		t.Fatalf("Port = %q, want 2080", AppConfig.Socks.Port)
	}
	if AppConfig.Socks.KeepalivePeriod.Duration() != 90*time.Second {
		t.Fatalf("KeepalivePeriod = %v, want 90s", AppConfig.Socks.KeepalivePeriod.Duration())
	}
	if AppConfig.Socks.IdleTimeout.Duration() != 7*time.Minute {
		t.Fatalf("IdleTimeout = %v, want 7m", AppConfig.Socks.IdleTimeout.Duration())
	}
	if AppConfig.Socks.L4UDP != L4UDPDirect {
		t.Fatalf("L4UDP = %q, want %q", AppConfig.Socks.L4UDP, L4UDPDirect)
	}
	if AppConfig.Logging.Level != "warn" {
		t.Fatalf("Logging.Level = %q, want warn", AppConfig.Logging.Level)
	}
}

func TestResolveConfigPath(t *testing.T) {
	t.Run("explicit honored", func(t *testing.T) {
		if got := ResolveConfigPath("/etc/custom.json"); got != "/etc/custom.json" {
			t.Fatalf("ResolveConfigPath(explicit) = %q", got)
		}
	})

	t.Run("prefers yaml over json", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		if err := os.WriteFile("config.json", []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("config.yaml", []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := ResolveConfigPath(""); got != "config.yaml" {
			t.Fatalf("ResolveConfigPath() = %q, want config.yaml", got)
		}
	})

	t.Run("falls back to json", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		if err := os.WriteFile("config.json", []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := ResolveConfigPath(""); got != "config.json" {
			t.Fatalf("ResolveConfigPath() = %q, want config.json", got)
		}
	})

	t.Run("defaults to yaml when nothing exists", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		if got := ResolveConfigPath(""); got != "config.yaml" {
			t.Fatalf("ResolveConfigPath() = %q, want config.yaml", got)
		}
	})
}

func TestMigrateLegacyJSONConfigPath(t *testing.T) {
	t.Run("explicit not migrated", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		if err := os.WriteFile("config.json", []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		path, migrated, err := MigrateLegacyJSONConfigPath("some/explicit.json")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if migrated || path != "some/explicit.json" {
			t.Fatalf("explicit path got migrated=%v path=%q", migrated, path)
		}
	})

	t.Run("transcodes legacy json to yaml with backup", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		legacy := `{
  "socks": { "bind_address": "127.0.0.1", "port": "1080", "keepalive_period": "30s" },
  "logging": { "level": "debug", "format": "text" }
}`
		if err := os.WriteFile("config.json", []byte(legacy), 0o600); err != nil {
			t.Fatal(err)
		}

		path, migrated, err := MigrateLegacyJSONConfigPath("")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if !migrated || path != "config.yaml" {
			t.Fatalf("migrated=%v path=%q, want true/config.yaml", migrated, path)
		}

		if _, err := os.Stat("config.json.bak"); err != nil {
			t.Fatalf("expected config.json.bak backup: %v", err)
		}
		if _, err := os.Stat("config.json"); !os.IsNotExist(err) {
			t.Fatalf("config.json should have been renamed, stat err = %v", err)
		}
		yamlRaw, err := os.ReadFile("config.yaml")
		if err != nil {
			t.Fatalf("read migrated config.yaml: %v", err)
		}
		if !strings.Contains(string(yamlRaw), "bind_address: 127.0.0.1") {
			t.Fatalf("migrated yaml missing expected content:\n%s", string(yamlRaw))
		}

		// The migrated YAML must load cleanly.
		restoreGlobals(t)
		if err := LoadConfig("config.yaml"); err != nil {
			t.Fatalf("LoadConfig(migrated) error = %v", err)
		}
		if AppConfig.Socks.Port != "1080" {
			t.Fatalf("Port = %q, want 1080", AppConfig.Socks.Port)
		}
	})

	t.Run("no migration when yaml already present", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		if err := os.WriteFile("config.yaml", []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("config.json", []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		path, migrated, err := MigrateLegacyJSONConfigPath("")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if migrated || path != "config.yaml" {
			t.Fatalf("migrated=%v path=%q, want false/config.yaml", migrated, path)
		}
		// Original json must be left untouched (no backup created).
		if _, err := os.Stat("config.json.bak"); !os.IsNotExist(err) {
			t.Fatalf("unexpected backup created: %v", err)
		}
	})

	t.Run("fresh start defaults to yaml", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		path, migrated, err := MigrateLegacyJSONConfigPath("")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if migrated || path != "config.yaml" {
			t.Fatalf("migrated=%v path=%q, want false/config.yaml", migrated, path)
		}
	})
}
