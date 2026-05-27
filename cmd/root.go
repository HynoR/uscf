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

		if configPath != "" {
			if err := config.LoadConfig(configPath); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					slog.Info("config file not found, continuing without preloaded config", "path", configPath)
					return nil
				}
				return fmt.Errorf("failed to load config %q: %w; delete config and reinitialize", configPath, err)
			}

			config.AppConfig.Logging = logging.Setup(config.AppConfig.Logging)
		}

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
	rootCmd.PersistentFlags().StringP("config", "c", "config.json", "config file (default is config.json)")
}
