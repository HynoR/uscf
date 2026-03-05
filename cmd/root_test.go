package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/HynoR/uscf/config"
	"github.com/spf13/cobra"
)

func newRootPreRunCmdForTest(configPath string) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("config", configPath, "")
	return cmd
}

func TestRootPersistentPreRun_ConfigMissingContinues(t *testing.T) {
	backupConfig := config.AppConfig
	backupLoaded := config.ConfigLoaded
	t.Cleanup(func() {
		config.AppConfig = backupConfig
		config.ConfigLoaded = backupLoaded
	})

	configPath := filepath.Join(t.TempDir(), "missing-config.json")
	cmd := newRootPreRunCmdForTest(configPath)

	if err := rootCmd.PersistentPreRunE(cmd, nil); err != nil {
		t.Fatalf("expected nil error when config missing, got %v", err)
	}
}

func TestRootPersistentPreRun_LoadConfigFailureReturnsError(t *testing.T) {
	backupConfig := config.AppConfig
	backupLoaded := config.ConfigLoaded
	t.Cleanup(func() {
		config.AppConfig = backupConfig
		config.ConfigLoaded = backupLoaded
	})

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte("{invalid-json"), 0o600); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}

	cmd := newRootPreRunCmdForTest(configPath)
	if err := rootCmd.PersistentPreRunE(cmd, nil); err == nil {
		t.Fatalf("expected load config error")
	}
}
