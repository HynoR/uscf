package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	tunnelStateUp   = "up"
	tunnelStateDown = "down"
)

// The tunnel state file is a container healthcheck hook, not a user-facing
// feature: uscf writes "up"/"down" to it on every tunnel transition and
// healthcheck.sh reads it back to decide whether the SOCKS layer is worth
// probing. It is opt-in through USCF_TUNNEL_STATE_FILE — set by the Dockerfile
// for the images that ship healthcheck.sh — so a plain CLI run writes nothing
// and leaves nothing behind. Never default this to a hardcoded "/tmp/..."
// path: on Windows that resolves to the root of the current drive and creates
// a stray "\tmp" directory there (issue #12).
const tunnelStateEnvVar = "USCF_TUNNEL_STATE_FILE"

// tunnelStateFilePath is empty when the feature is disabled.
var tunnelStateFilePath = strings.TrimSpace(os.Getenv(tunnelStateEnvVar))

// tunnelStateMu serializes writers so the file always reflects the last
// transition. Transitions come from several goroutines at once — the MASQUE
// OnConnected/OnDisconnected callbacks, the WireGuard supervisor, and the
// shutdown path — and without this two racing writes can land in the reverse
// of their causal order and leave a stale value behind.
var tunnelStateMu sync.Mutex

// publishTunnelState mirrors a tunnel up/down transition into the state file.
// Transports never call this directly: socksRuntime.SetTunnelUp is the single
// signal every transport already maintains, so the file cannot drift from the
// gate that actually decides whether SOCKS dials are accepted.
func publishTunnelState(up bool) {
	state := tunnelStateDown
	if up {
		state = tunnelStateUp
	}
	writeTunnelStateSafe(state)
}

func writeTunnelStateSafe(state string) {
	if err := writeTunnelState(state); err != nil {
		slog.Warn("failed to update tunnel state file", "path", tunnelStateFilePath, "state", state, "error", err)
	}
}

// writeTunnelState atomically replaces the state file with state. It is a no-op
// when the feature is disabled, but an invalid state is always a programming
// error and is reported either way.
func writeTunnelState(state string) error {
	state = strings.TrimSpace(strings.ToLower(state))
	if state != tunnelStateUp && state != tunnelStateDown {
		return fmt.Errorf("invalid tunnel state %q", state)
	}

	tunnelStateMu.Lock()
	defer tunnelStateMu.Unlock()

	path := tunnelStateFilePath
	if path == "" {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}

	// A fixed scratch name rather than os.CreateTemp: a crash between write and
	// rename then leaves at most one stale file instead of one per transition.
	// 0o644 keeps the file readable by a healthcheck running as another user.
	tmpPath := path + ".tmp"
	tmpFile, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create temp state file: %w", err)
	}
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

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace state file: %w", err)
	}
	return nil
}
