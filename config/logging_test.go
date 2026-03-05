package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfig_DefaultLoggingWhenMissing(t *testing.T) {
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
    "dns": ["1.1.1.1"]
  }
}`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write test config: %v", err)
	}

	if err := LoadConfig(configPath); err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	defaultLogging := GetDefaultLoggingConfig()
	if AppConfig.Logging != defaultLogging {
		t.Fatalf("AppConfig.Logging = %+v, want %+v", AppConfig.Logging, defaultLogging)
	}
}

func TestLoadConfig_UsesProvidedLoggingConfig(t *testing.T) {
	backupConfig := AppConfig
	backupLoaded := ConfigLoaded
	t.Cleanup(func() {
		AppConfig = backupConfig
		ConfigLoaded = backupLoaded
	})

	configPath := filepath.Join(t.TempDir(), "config.json")
	content := `{
  "logging": {
    "level": "debug",
    "format": "json",
    "socks_verbose": true
  }
}`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write test config: %v", err)
	}

	if err := LoadConfig(configPath); err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if AppConfig.Logging.Level != "debug" {
		t.Fatalf("AppConfig.Logging.Level = %q, want %q", AppConfig.Logging.Level, "debug")
	}
	if AppConfig.Logging.Format != "json" {
		t.Fatalf("AppConfig.Logging.Format = %q, want %q", AppConfig.Logging.Format, "json")
	}
	if !AppConfig.Logging.SocksVerbose {
		t.Fatalf("AppConfig.Logging.SocksVerbose = %v, want true", AppConfig.Logging.SocksVerbose)
	}
}

func TestNormalizeLoggingConfig_FallbackForInvalidValues(t *testing.T) {
	normalized, issues := NormalizeLoggingConfig(LoggingConfig{
		Level:  "verbose",
		Format: "yaml",
	})

	if normalized.Level != "info" {
		t.Fatalf("normalized.Level = %q, want %q", normalized.Level, "info")
	}
	if normalized.Format != "text" {
		t.Fatalf("normalized.Format = %q, want %q", normalized.Format, "text")
	}
	if len(issues) == 0 {
		t.Fatalf("issues should not be empty for invalid values")
	}

	joined := strings.Join(issues, ";")
	if !strings.Contains(joined, "level=") {
		t.Fatalf("issues should mention level fallback, got: %q", joined)
	}
	if !strings.Contains(joined, "format=") {
		t.Fatalf("issues should mention format fallback, got: %q", joined)
	}
}
