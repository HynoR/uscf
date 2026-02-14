package cmd

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HynoR/uscf/config"
	"github.com/HynoR/uscf/internal"
	"github.com/HynoR/uscf/models"
	"github.com/spf13/cobra"
)

func newRegistrationCmdForTest() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("locale", internal.DefaultLocale, "")
	cmd.Flags().String("model", internal.DefaultModel, "")
	cmd.Flags().Bool("accept-tos", true, "")
	cmd.Flags().String("jwt", "", "")
	return cmd
}

func TestHandleRegistrationLicenseFailureStopsBeforeEnroll(t *testing.T) {
	oldRegister := registerAccountFunc
	oldRebind := rebindLicenseFunc
	oldEnroll := enrollKeyFunc
	oldConfig := config.AppConfig
	oldLoaded := config.ConfigLoaded
	t.Cleanup(func() {
		registerAccountFunc = oldRegister
		rebindLicenseFunc = oldRebind
		enrollKeyFunc = oldEnroll
		config.AppConfig = oldConfig
		config.ConfigLoaded = oldLoaded
	})

	registerAccountFunc = func(model, locale, jwt string, acceptTos bool) (models.AccountData, error) {
		return models.AccountData{
			ID:    "device-id",
			Token: "token",
		}, nil
	}
	rebindLicenseFunc = func(accountData models.AccountData, target string) (models.Account, bool, *models.APIError, error) {
		return models.Account{}, false, &models.APIError{
			Errors: []models.ErrorInfo{{Code: 1000, Message: "invalid license"}},
		}, errors.New("bad request")
	}
	enrollCalled := false
	enrollKeyFunc = func(accountData models.AccountData, pubKey []byte, deviceName string) (models.AccountData, *models.APIError, error) {
		enrollCalled = true
		return models.AccountData{}, nil, nil
	}

	configPath := filepath.Join(t.TempDir(), "config.json")
	err := handleRegistration(newRegistrationCmdForTest(), configPath, "LICENSE")
	if err == nil {
		t.Fatalf("expected error when license bind fails")
	}
	if !strings.Contains(err.Error(), "Failed to apply license") {
		t.Fatalf("unexpected error: %v", err)
	}
	if enrollCalled {
		t.Fatalf("EnrollKey should not be called after license bind failure")
	}
}

func TestApplyCustomLicenseRemoteAlreadySame(t *testing.T) {
	oldRebind := rebindLicenseFunc
	oldConfig := config.AppConfig
	oldLoaded := config.ConfigLoaded
	t.Cleanup(func() {
		rebindLicenseFunc = oldRebind
		config.AppConfig = oldConfig
		config.ConfigLoaded = oldLoaded
	})

	config.AppConfig = config.Config{
		ID:          "device-id",
		AccessToken: "token",
		License:     "OLD-LICENSE",
	}

	rebindLicenseFunc = func(accountData models.AccountData, target string) (models.Account, bool, *models.APIError, error) {
		return models.Account{License: "OLD-LICENSE"}, false, nil, nil
	}

	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := applyCustomLicense(configPath, "OLD-LICENSE"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if config.AppConfig.License != "OLD-LICENSE" {
		t.Fatalf("unexpected license in memory: %q", config.AppConfig.License)
	}
	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("expected config file to be saved: %v", err)
	}
}

func TestApplyCustomLicenseUpdatesConfig(t *testing.T) {
	oldRebind := rebindLicenseFunc
	oldEnroll := enrollKeyFunc
	oldConfig := config.AppConfig
	oldLoaded := config.ConfigLoaded
	t.Cleanup(func() {
		rebindLicenseFunc = oldRebind
		enrollKeyFunc = oldEnroll
		config.AppConfig = oldConfig
		config.ConfigLoaded = oldLoaded
	})

	privKey, _, err := internal.GenerateEcKeyPair()
	if err != nil {
		t.Fatalf("failed to generate test keypair: %v", err)
	}

	config.AppConfig = config.Config{
		ID:          "device-id",
		AccessToken: "token",
		License:     "OLD-LICENSE",
		PrivateKey:  base64.StdEncoding.EncodeToString(privKey),
	}

	rebindLicenseFunc = func(accountData models.AccountData, target string) (models.Account, bool, *models.APIError, error) {
		return models.Account{License: "NEW-LICENSE"}, true, nil, nil
	}
	enrollCalled := false
	enrollKeyFunc = func(accountData models.AccountData, pubKey []byte, deviceName string) (models.AccountData, *models.APIError, error) {
		enrollCalled = true
		updated := models.AccountData{ID: accountData.ID}
		peer := models.Peer{PublicKey: "peer-pub-key"}
		peer.Endpoint.V4 = "162.159.198.1:0"
		peer.Endpoint.V6 = "[2606:4700:103::1]:0"
		updated.Config.Peers = []models.Peer{peer}
		updated.Config.Interface.Addresses.V4 = "172.16.0.2"
		updated.Config.Interface.Addresses.V6 = "2606:4700:110::2"
		return updated, nil, nil
	}

	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := applyCustomLicense(configPath, "NEW-LICENSE"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !enrollCalled {
		t.Fatalf("expected re-enroll call when license changes")
	}

	if config.AppConfig.License != "NEW-LICENSE" {
		t.Fatalf("unexpected in-memory license: %q", config.AppConfig.License)
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read config file: %v", err)
	}
	if !strings.Contains(string(content), `"license": "NEW-LICENSE"`) {
		t.Fatalf("expected updated license in config file, got:\n%s", string(content))
	}
}
