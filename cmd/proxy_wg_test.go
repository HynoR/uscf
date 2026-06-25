package cmd

import (
	"os"
	"strings"
	"testing"

	"github.com/HynoR/uscf/config"
	"github.com/HynoR/uscf/models"
	"github.com/spf13/cobra"
)

// newProxyWGCmdForTest builds a cobra command exposing the flags runProxyWGMode
// and wgModeSelected read.
func newProxyWGCmdForTest() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().Bool("wg", false, "")
	cmd.Flags().Bool("experimental", false, "")
	cmd.Flags().String("wg-account", "wg-account.json", "")
	cmd.Flags().Int("wg-keepalive", defaultWGRunKeepalive, "")
	cmd.Flags().String("license", "", "")
	cmd.Flags().String("jwt", "", "")
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("model", "PC", "")
	cmd.Flags().Bool("accept-tos", true, "")
	// flags consumed by applySocksFlagOverrides
	cmd.Flags().String("bind-address", "", "")
	cmd.Flags().String("port", "", "")
	cmd.Flags().String("username", "", "")
	cmd.Flags().String("password", "", "")
	cmd.Flags().Bool("use-ipv6", false, "")
	cmd.Flags().Bool("http2", false, "")
	cmd.Flags().Bool("l4", false, "")
	cmd.Flags().String("l4-udp", "", "")
	return cmd
}

func TestProxyWGModeRequiresExperimental(t *testing.T) {
	cmd := newProxyWGCmdForTest()
	if err := cmd.Flags().Set("wg", "true"); err != nil {
		t.Fatalf("set wg flag: %v", err)
	}
	// --experimental left false.
	err := runProxyWGMode(cmd, "config.yaml")
	if err == nil {
		t.Fatalf("expected an error when --experimental is missing")
	}
	if !strings.Contains(err.Error(), "experimental") {
		t.Fatalf("error = %v, want it to mention experimental", err)
	}
}

func TestWGModeSelected(t *testing.T) {
	backup := config.AppConfig
	t.Cleanup(func() { config.AppConfig = backup })

	t.Run("flag true overrides config", func(t *testing.T) {
		config.AppConfig.Socks.WG = false
		cmd := newProxyWGCmdForTest()
		if err := cmd.Flags().Set("wg", "true"); err != nil {
			t.Fatalf("set wg: %v", err)
		}
		if !wgModeSelected(cmd) {
			t.Fatalf("expected wg selected when --wg=true")
		}
	})

	t.Run("flag false overrides config", func(t *testing.T) {
		config.AppConfig.Socks.WG = true
		cmd := newProxyWGCmdForTest()
		if err := cmd.Flags().Set("wg", "false"); err != nil {
			t.Fatalf("set wg: %v", err)
		}
		if wgModeSelected(cmd) {
			t.Fatalf("expected wg not selected when --wg=false")
		}
	})

	t.Run("unset falls back to config", func(t *testing.T) {
		config.AppConfig.Socks.WG = true
		cmd := newProxyWGCmdForTest()
		if !wgModeSelected(cmd) {
			t.Fatalf("expected wg selected from config when flag unset")
		}
	})
}

func TestRejectConflictingTransport(t *testing.T) {
	backup := config.AppConfig
	t.Cleanup(func() { config.AppConfig = backup })

	config.AppConfig = config.Config{}
	if err := rejectConflictingTransport(); err != nil {
		t.Fatalf("no conflict expected, got %v", err)
	}

	config.AppConfig.Socks.L4 = true
	if err := rejectConflictingTransport(); err == nil || !strings.Contains(err.Error(), "l4") {
		t.Fatalf("expected l4 conflict error, got %v", err)
	}

	config.AppConfig.Socks.L4 = false
	config.AppConfig.Socks.HTTP2 = true
	if err := rejectConflictingTransport(); err == nil || !strings.Contains(err.Error(), "http2") {
		t.Fatalf("expected http2 conflict error, got %v", err)
	}
}

func TestEnsureWGAccountReusesValidAccount(t *testing.T) {
	oldLoad := wgLoadAccountFunc
	oldRegister := wgRegisterDeviceFunc
	t.Cleanup(func() {
		wgLoadAccountFunc = oldLoad
		wgRegisterDeviceFunc = oldRegister
	})

	existing := config.WGAccount{
		PrivateKey:  "priv",
		DeviceID:    "dev-1",
		AccessToken: "tok-1",
	}
	wgLoadAccountFunc = func(path string) (config.WGAccount, error) {
		return existing, nil
	}
	wgRegisterDeviceFunc = func(publicKey, model, jwt string) (models.AccountData, error) {
		t.Fatalf("register must not be called when a valid account already exists")
		return models.AccountData{}, nil
	}

	got, err := ensureWGAccount("wg-account.json", wgRegisterOptions{acceptTOS: true})
	if err != nil {
		t.Fatalf("ensureWGAccount() error = %v", err)
	}
	if got != existing {
		t.Fatalf("ensureWGAccount() = %#v, want %#v", got, existing)
	}
}

func TestEnsureWGAccountRegistersWhenMissing(t *testing.T) {
	oldLoad := wgLoadAccountFunc
	oldRegister := wgRegisterDeviceFunc
	oldSave := wgSaveAccountFunc
	t.Cleanup(func() {
		wgLoadAccountFunc = oldLoad
		wgRegisterDeviceFunc = oldRegister
		wgSaveAccountFunc = oldSave
	})

	wgLoadAccountFunc = func(path string) (config.WGAccount, error) {
		return config.WGAccount{}, os.ErrNotExist
	}
	registered := false
	wgRegisterDeviceFunc = func(publicKey, model, jwt string) (models.AccountData, error) {
		registered = true
		return models.AccountData{ID: "dev-9", Token: "tok-9"}, nil
	}
	var saved config.WGAccount
	wgSaveAccountFunc = func(path string, account config.WGAccount) error {
		saved = account
		return nil
	}

	got, err := ensureWGAccount("wg-account.json", wgRegisterOptions{model: "PC", acceptTOS: true})
	if err != nil {
		t.Fatalf("ensureWGAccount() error = %v", err)
	}
	if !registered {
		t.Fatalf("expected registration when account is missing")
	}
	if got.DeviceID != "dev-9" || got.AccessToken != "tok-9" {
		t.Fatalf("registered account core fields = %#v", got)
	}
	if saved.DeviceID != "dev-9" {
		t.Fatalf("saved account = %#v", saved)
	}
}
