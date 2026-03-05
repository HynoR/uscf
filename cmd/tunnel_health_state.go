package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

const (
	tunnelStateUp   = "up"
	tunnelStateDown = "down"
)

var tunnelStateFilePath = "/tmp/uscf_tunnel_state"

func writeTunnelStateSafe(state string) {
	if err := writeTunnelState(state); err != nil {
		slog.Warn("failed to update tunnel state file", "path", tunnelStateFilePath, "state", state, "error", err)
	}
}

func writeTunnelState(state string) error {
	state = strings.TrimSpace(strings.ToLower(state))
	if state != tunnelStateUp && state != tunnelStateDown {
		return fmt.Errorf("invalid tunnel state %q", state)
	}

	dir := filepath.Dir(tunnelStateFilePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}

	tmpFile, err := os.CreateTemp(dir, "uscf_tunnel_state_*")
	if err != nil {
		return fmt.Errorf("create temp state file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if _, err := tmpFile.WriteString(state + "\n"); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write state file: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("sync state file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close state file: %w", err)
	}

	if err := os.Rename(tmpPath, tunnelStateFilePath); err != nil {
		return fmt.Errorf("replace state file: %w", err)
	}
	return nil
}
