package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/HynoR/uscf/config"
	"github.com/HynoR/uscf/internal/logging"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "uscf",
	Short: "USCF Warp CLI",
	Long:  "An unofficial Cloudflare Warp CLI that uses the MASQUE protocol and exposes the tunnel as various different services.",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if shouldSkipConfigLoad(cmd) {
			return nil
		}

		configPath, err := cmd.Flags().GetString("config")
		if err != nil {
			return fmt.Errorf("failed to get config path: %w", err)
		}

		// Prefer config.yaml; one-time upgrade a legacy config.json to YAML when
		// no explicit --config was given. The resolved path is written back to
		// the flag so downstream commands (save, jwt, key.json) reuse it.
		resolved, migrated, err := config.MigrateLegacyJSONConfigPath(configPath)
		if err != nil {
			return fmt.Errorf("failed to migrate legacy config: %w", err)
		}
		if migrated {
			slog.Info("migrated legacy config.json to config.yaml", "backup", "config.json.bak")
		}
		if err := cmd.Flags().Set("config", resolved); err != nil {
			return fmt.Errorf("failed to set resolved config path: %w", err)
		}

		if err := config.LoadConfig(resolved); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				slog.Info("config file not found, continuing without preloaded config", "path", resolved)
				return nil
			}
			return fmt.Errorf("failed to load config %q: %w; delete config and reinitialize", resolved, err)
		}

		config.AppConfig.Logging = logging.Setup(config.AppConfig.Logging)

		return nil
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func shouldSkipConfigLoad(cmd *cobra.Command) bool {
	for current := cmd; current != nil; current = current.Parent() {
		if current.Name() == "wg" || current.Name() == "socks" {
			return true
		}
	}
	return false
}

func init() {
	rootCmd.PersistentFlags().StringP("config", "c", "", "config file (default: config.yaml, falling back to config.json)")
}
