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
	err := handleRegistration(newRegistrationCmdForTest(), configPath, accountModePremium, "LICENSE", "")
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

func TestHandleRegistrationTeamUsesJWTAndSavesMode(t *testing.T) {
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

	var receivedJWT string
	const registerID = "team-9f0c"
	registerAccountFunc = func(model, locale, jwt string, acceptTos bool) (models.AccountData, error) {
		receivedJWT = jwt
		return models.AccountData{
			ID:    registerID,
			Token: "token",
		}, nil
	}
	rebindCalled := false
	rebindLicenseFunc = func(accountData models.AccountData, target string) (models.Account, bool, *models.APIError, error) {
		rebindCalled = true
		return models.Account{}, false, nil, nil
	}
	var enrolledDeviceName string
	enrollKeyFunc = func(accountData models.AccountData, pubKey []byte, deviceName string) (models.AccountData, *models.APIError, error) {
		enrolledDeviceName = deviceName
		updated := models.AccountData{
			ID: accountData.ID,
		}
		peer := models.Peer{PublicKey: "peer-pub-key"}
		peer.Endpoint.V4 = "162.159.198.1:0"
		peer.Endpoint.V6 = "[2606:4700:103::1]:0"
		updated.Config.Peers = []models.Peer{peer}
		updated.Config.Interface.Addresses.V4 = "172.16.0.2"
		updated.Config.Interface.Addresses.V6 = "2606:4700:110::2"
		return updated, nil, nil
	}

	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := handleRegistration(newRegistrationCmdForTest(), configPath, accountModeTeam, "", "JWT-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedJWT != "JWT-1" {
		t.Fatalf("unexpected jwt passed to register: %q", receivedJWT)
	}
	if rebindCalled {
		t.Fatalf("rebind should not be called in team mode registration")
	}
	if config.AppConfig.AccountMode != accountModeTeam {
		t.Fatalf("unexpected account mode: %q", config.AppConfig.AccountMode)
	}
	if enrolledDeviceName == "" {
		t.Fatalf("expected auto-generated device name")
	}
	if len(enrolledDeviceName) > maxDeviceNameLen {
		t.Fatalf("expected len <= %d, got %d (%q)", maxDeviceNameLen, len(enrolledDeviceName), enrolledDeviceName)
	}
	if !strings.HasPrefix(enrolledDeviceName, "t-") {
		t.Fatalf("expected team prefix, got %q", enrolledDeviceName)
	}
	if !strings.HasSuffix(enrolledDeviceName, accountIDSuffix(registerID)) {
		t.Fatalf("expected id suffix %q in %q", accountIDSuffix(registerID), enrolledDeviceName)
	}
}

func TestHandleRegistrationPremiumAutoDeviceNameFromAccountID(t *testing.T) {
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

	const registerID = "premium-a1b2"
	registerAccountFunc = func(model, locale, jwt string, acceptTos bool) (models.AccountData, error) {
		return models.AccountData{
			ID:    registerID,
			Token: "token",
		}, nil
	}
	rebindLicenseFunc = func(accountData models.AccountData, target string) (models.Account, bool, *models.APIError, error) {
		return models.Account{License: "LICENSE-1"}, false, nil, nil
	}
	var enrolledDeviceName string
	enrollKeyFunc = func(accountData models.AccountData, pubKey []byte, deviceName string) (models.AccountData, *models.APIError, error) {
		enrolledDeviceName = deviceName
		updated := models.AccountData{
			ID: accountData.ID,
		}
		peer := models.Peer{PublicKey: "peer-pub-key"}
		peer.Endpoint.V4 = "162.159.198.1:0"
		peer.Endpoint.V6 = "[2606:4700:103::1]:0"
		updated.Config.Peers = []models.Peer{peer}
		updated.Config.Interface.Addresses.V4 = "172.16.0.2"
		updated.Config.Interface.Addresses.V6 = "2606:4700:110::2"
		return updated, nil, nil
	}

	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := handleRegistration(newRegistrationCmdForTest(), configPath, accountModePremium, "LICENSE-1", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if enrolledDeviceName == "" {
		t.Fatalf("expected auto-generated device name")
	}
	if len(enrolledDeviceName) > maxDeviceNameLen {
		t.Fatalf("expected len <= %d, got %d (%q)", maxDeviceNameLen, len(enrolledDeviceName), enrolledDeviceName)
	}
	if !strings.HasPrefix(enrolledDeviceName, "p-") {
		t.Fatalf("expected premium prefix, got %q", enrolledDeviceName)
	}
	if !strings.HasSuffix(enrolledDeviceName, accountIDSuffix(registerID)) {
		t.Fatalf("expected id suffix %q in %q", accountIDSuffix(registerID), enrolledDeviceName)
	}
	if config.AppConfig.Registration.DeviceName != enrolledDeviceName {
		t.Fatalf("expected config device name %q, got %q", enrolledDeviceName, config.AppConfig.Registration.DeviceName)
	}
}

func TestHandleRegistrationPremiumExplicitNameTakesPriority(t *testing.T) {
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
			ID:    "premium-a1b2",
			Token: "token",
		}, nil
	}
	rebindLicenseFunc = func(accountData models.AccountData, target string) (models.Account, bool, *models.APIError, error) {
		return models.Account{License: "LICENSE-1"}, false, nil, nil
	}
	var enrolledDeviceName string
	enrollKeyFunc = func(accountData models.AccountData, pubKey []byte, deviceName string) (models.AccountData, *models.APIError, error) {
		enrolledDeviceName = deviceName
		updated := models.AccountData{
			ID: accountData.ID,
		}
		peer := models.Peer{PublicKey: "peer-pub-key"}
		peer.Endpoint.V4 = "162.159.198.1:0"
		peer.Endpoint.V6 = "[2606:4700:103::1]:0"
		updated.Config.Peers = []models.Peer{peer}
		updated.Config.Interface.Addresses.V4 = "172.16.0.2"
		updated.Config.Interface.Addresses.V6 = "2606:4700:110::2"
		return updated, nil, nil
	}

	cmd := newRegistrationCmdForTest()
	if err := cmd.Flags().Set("name", "My Fancy Device Name"); err != nil {
		t.Fatalf("failed to set name flag: %v", err)
	}
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := handleRegistration(cmd, configPath, accountModePremium, "LICENSE-1", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := normalizeDeviceName("My Fancy Device Name")
	if enrolledDeviceName != want {
		t.Fatalf("expected normalized explicit name %q, got %q", want, enrolledDeviceName)
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

	keyPath := filepath.Join(filepath.Dir(configPath), "key.json")
	content, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("failed to read key file: %v", err)
	}
	if !strings.Contains(string(content), `"license": "NEW-LICENSE"`) {
		t.Fatalf("expected updated license in key file, got:\n%s", string(content))
	}
}
