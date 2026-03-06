package wireguard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProfileSaveTightensExistingFilePermissions(t *testing.T) {
	dir := t.TempDir()
	profilePath := filepath.Join(dir, "wg-profile.conf")
	if err := os.WriteFile(profilePath, []byte("stale"), 0o644); err != nil {
		t.Fatalf("seed profile: %v", err)
	}

	profile, err := NewProfile(&ProfileData{
		PrivateKey: "private-key-1",
		Address1:   "172.16.0.2",
		Address2:   "2606:4700:110::2",
		PublicKey:  "peer-public-key",
		Endpoint:   "engage.cloudflareclient.com:2408",
	})
	if err != nil {
		t.Fatalf("NewProfile() error = %v", err)
	}

	if err := profile.Save(profilePath); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	info, err := os.Stat(profilePath)
	if err != nil {
		t.Fatalf("stat profile: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("profile mode = %#o, want %#o", got, 0o600)
	}
}
