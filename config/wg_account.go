package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const defaultWGAccountPath = "wg-account.json"

// WGAccount stores the standalone WireGuard account state used by `uscf wg`.
type WGAccount struct {
	DeviceID    string `json:"device_id"`
	AccessToken string `json:"access_token"`
	License     string `json:"license"`
	PrivateKey  string `json:"private_key"`
	DeviceName  string `json:"device_name"`
	Model       string `json:"model"`
}

func normalizeWGAccountPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return defaultWGAccountPath
	}
	return path
}

// Validate checks that the minimum fields required for remote profile generation exist.
func (a WGAccount) Validate() error {
	switch {
	case strings.TrimSpace(a.PrivateKey) == "":
		return fmt.Errorf("missing private_key in wg account")
	case strings.TrimSpace(a.DeviceID) == "":
		return fmt.Errorf("missing device_id in wg account")
	case strings.TrimSpace(a.AccessToken) == "":
		return fmt.Errorf("missing access_token in wg account")
	default:
		return nil
	}
}

// Save writes the WireGuard account to disk with mode 0600.
func (a WGAccount) Save(path string) error {
	if err := a.Validate(); err != nil {
		return err
	}

	path = normalizeWGAccountPath(path)
	raw, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal wg account: %w", err)
	}
	raw = append(raw, '\n')

	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("write wg account: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod wg account: %w", err)
	}
	return nil
}

// LoadWGAccount reads and decodes the standalone WireGuard account file.
func LoadWGAccount(path string) (WGAccount, error) {
	raw, err := os.ReadFile(normalizeWGAccountPath(path))
	if err != nil {
		return WGAccount{}, fmt.Errorf("read wg account: %w", err)
	}

	var account WGAccount
	if err := json.Unmarshal(raw, &account); err != nil {
		return WGAccount{}, fmt.Errorf("decode wg account: %w", err)
	}

	return account, nil
}
