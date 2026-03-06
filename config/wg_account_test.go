package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWGAccountSaveAndLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	accountPath := filepath.Join(dir, "wg-account.json")

	want := WGAccount{
		DeviceID:    "device-1",
		AccessToken: "token-1",
		License:     "license-1",
		PrivateKey:  "private-key-1",
		DeviceName:  "node-1",
		Model:       "PC",
	}

	if err := want.Save(accountPath); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	got, err := LoadWGAccount(accountPath)
	if err != nil {
		t.Fatalf("LoadWGAccount() error = %v", err)
	}

	if got != want {
		t.Fatalf("LoadWGAccount() = %#v, want %#v", got, want)
	}
}

func TestWGAccountValidateRequiresCoreFields(t *testing.T) {
	testCases := []struct {
		name    string
		account WGAccount
		want    string
	}{
		{
			name: "missing private key",
			account: WGAccount{
				DeviceID:    "device-1",
				AccessToken: "token-1",
			},
			want: "private_key",
		},
		{
			name: "missing device id",
			account: WGAccount{
				AccessToken: "token-1",
				PrivateKey:  "private-key-1",
			},
			want: "device_id",
		},
		{
			name: "missing access token",
			account: WGAccount{
				DeviceID:   "device-1",
				PrivateKey: "private-key-1",
			},
			want: "access_token",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.account.Validate()
			if err == nil {
				t.Fatalf("Validate() error = nil, want substring %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestWGAccountSaveTightensExistingFilePermissions(t *testing.T) {
	dir := t.TempDir()
	accountPath := filepath.Join(dir, "wg-account.json")
	if err := os.WriteFile(accountPath, []byte("{}"), 0o644); err != nil {
		t.Fatalf("seed wg-account.json: %v", err)
	}

	account := WGAccount{
		DeviceID:    "device-1",
		AccessToken: "token-1",
		PrivateKey:  "private-key-1",
	}
	if err := account.Save(accountPath); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	info, err := os.Stat(accountPath)
	if err != nil {
		t.Fatalf("stat wg-account.json: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("wg-account.json mode = %#o, want %#o", got, 0o600)
	}
}
