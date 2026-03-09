package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HynoR/uscf/config"
	"github.com/HynoR/uscf/models"
	"github.com/HynoR/uscf/wireguard"
	"github.com/spf13/cobra"
)

func newWGRegisterCmdForTest() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("wg-account", "wg-account.json", "")
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("model", "PC", "")
	cmd.Flags().String("key", "", "")
	cmd.Flags().String("license", "", "")
	cmd.Flags().String("jwt", "", "")
	cmd.Flags().Bool("accept-tos", false, "")
	return cmd
}

func newWGGenerateCmdForTest() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("wg-account", "wg-account.json", "")
	cmd.Flags().String("profile", "wg-profile.conf", "")
	return cmd
}

func newWGUpdateCmdForTest() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("wg-account", "wg-account.json", "")
	cmd.Flags().String("license", "", "")
	return cmd
}

func TestRunWGRegisterCmdSavesAccountAndUsesDerivedPublicKey(t *testing.T) {
	oldRegister := wgRegisterDeviceFunc
	oldSetName := wgSetDeviceNameFunc
	oldSave := wgSaveAccountFunc
	t.Cleanup(func() {
		wgRegisterDeviceFunc = oldRegister
		wgSetDeviceNameFunc = oldSetName
		wgSaveAccountFunc = oldSave
	})

	privateKey, err := wireguard.NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey() error = %v", err)
	}

	var gotPublicKey string
	wgRegisterDeviceFunc = func(publicKey, model, jwt string) (models.AccountData, error) {
		gotPublicKey = publicKey
		if jwt != "" {
			t.Fatalf("expected empty jwt for free register, got %q", jwt)
		}
		return models.AccountData{
			ID:    "device-1",
			Token: "token-1",
			Account: models.Account{
				License: "license-1",
			},
		}, nil
	}

	var gotRename struct {
		deviceID string
		token    string
		name     string
	}
	wgSetDeviceNameFunc = func(deviceID, accessToken, deviceName string) error {
		gotRename.deviceID = deviceID
		gotRename.token = accessToken
		gotRename.name = deviceName
		return nil
	}

	var savedPath string
	var savedAccount config.WGAccount
	wgSaveAccountFunc = func(path string, account config.WGAccount) error {
		savedPath = path
		savedAccount = account
		return nil
	}

	cmd := newWGRegisterCmdForTest()
	accountPath := filepath.Join(t.TempDir(), "wg-account.json")
	if err := cmd.Flags().Set("wg-account", accountPath); err != nil {
		t.Fatalf("set wg-account flag: %v", err)
	}
	if err := cmd.Flags().Set("key", privateKey.String()); err != nil {
		t.Fatalf("set key flag: %v", err)
	}
	if err := cmd.Flags().Set("name", "my-device"); err != nil {
		t.Fatalf("set name flag: %v", err)
	}
	if err := cmd.Flags().Set("accept-tos", "true"); err != nil {
		t.Fatalf("set accept-tos flag: %v", err)
	}

	if err := runWGRegisterCmd(cmd, nil); err != nil {
		t.Fatalf("runWGRegisterCmd() error = %v", err)
	}

	if gotPublicKey != privateKey.Public().String() {
		t.Fatalf("register public key = %q, want %q", gotPublicKey, privateKey.Public().String())
	}
	if gotRename.deviceID != "device-1" || gotRename.token != "token-1" || gotRename.name != "my-device" {
		t.Fatalf("rename args = %#v", gotRename)
	}
	if savedPath != accountPath {
		t.Fatalf("saved path = %q, want %q", savedPath, accountPath)
	}
	if savedAccount.PrivateKey != privateKey.String() {
		t.Fatalf("saved private key = %q, want %q", savedAccount.PrivateKey, privateKey.String())
	}
	if savedAccount.DeviceID != "device-1" || savedAccount.AccessToken != "token-1" || savedAccount.License != "license-1" {
		t.Fatalf("saved account core fields = %#v", savedAccount)
	}
}

func TestRunWGRegisterCmdReturnsErrorWhenSetDeviceNameFails(t *testing.T) {
	oldRegister := wgRegisterDeviceFunc
	oldSetName := wgSetDeviceNameFunc
	oldSave := wgSaveAccountFunc
	t.Cleanup(func() {
		wgRegisterDeviceFunc = oldRegister
		wgSetDeviceNameFunc = oldSetName
		wgSaveAccountFunc = oldSave
	})

	privateKey, err := wireguard.NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey() error = %v", err)
	}

	wgRegisterDeviceFunc = func(publicKey, model, jwt string) (models.AccountData, error) {
		if jwt != "" {
			t.Fatalf("expected empty jwt for free register, got %q", jwt)
		}
		return models.AccountData{
			ID:    "device-1",
			Token: "token-1",
		}, nil
	}
	wgSetDeviceNameFunc = func(deviceID, accessToken, deviceName string) error {
		return os.ErrPermission
	}
	saveCalled := false
	var savedAccount config.WGAccount
	wgSaveAccountFunc = func(path string, account config.WGAccount) error {
		saveCalled = true
		savedAccount = account
		return nil
	}

	cmd := newWGRegisterCmdForTest()
	if err := cmd.Flags().Set("key", privateKey.String()); err != nil {
		t.Fatalf("set key flag: %v", err)
	}
	if err := cmd.Flags().Set("name", "my-device"); err != nil {
		t.Fatalf("set name flag: %v", err)
	}
	if err := cmd.Flags().Set("accept-tos", "true"); err != nil {
		t.Fatalf("set accept-tos flag: %v", err)
	}

	err = runWGRegisterCmd(cmd, nil)
	if err == nil {
		t.Fatalf("expected error when set device name fails")
	}
	if !strings.Contains(err.Error(), "set device name") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !saveCalled {
		t.Fatalf("wgSaveAccountFunc should still be called on rename failure")
	}
	if savedAccount.DeviceID != "device-1" || savedAccount.AccessToken != "token-1" || savedAccount.PrivateKey != privateKey.String() {
		t.Fatalf("saved account = %#v", savedAccount)
	}
}

func TestRunWGRegisterCmdRebindsLicenseBeforeSave(t *testing.T) {
	oldRegister := wgRegisterDeviceFunc
	oldRebind := wgRebindLicenseFunc
	oldSetName := wgSetDeviceNameFunc
	oldSave := wgSaveAccountFunc
	t.Cleanup(func() {
		wgRegisterDeviceFunc = oldRegister
		wgRebindLicenseFunc = oldRebind
		wgSetDeviceNameFunc = oldSetName
		wgSaveAccountFunc = oldSave
	})

	privateKey, err := wireguard.NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey() error = %v", err)
	}

	wgRegisterDeviceFunc = func(publicKey, model, jwt string) (models.AccountData, error) {
		if jwt != "" {
			t.Fatalf("expected empty jwt for premium register, got %q", jwt)
		}
		return models.AccountData{
			ID:    "device-1",
			Token: "token-1",
			Account: models.Account{
				License: "old-license",
			},
		}, nil
	}

	var gotRebind struct {
		deviceID string
		token    string
		license  string
	}
	wgRebindLicenseFunc = func(accountData models.AccountData, target string) (models.Account, bool, *models.APIError, error) {
		gotRebind.deviceID = accountData.ID
		gotRebind.token = accountData.Token
		gotRebind.license = target
		return models.Account{License: "premium-license"}, true, nil, nil
	}
	wgSetDeviceNameFunc = func(deviceID, accessToken, deviceName string) error { return nil }

	var savedAccount config.WGAccount
	wgSaveAccountFunc = func(path string, account config.WGAccount) error {
		savedAccount = account
		return nil
	}

	cmd := newWGRegisterCmdForTest()
	if err := cmd.Flags().Set("key", privateKey.String()); err != nil {
		t.Fatalf("set key flag: %v", err)
	}
	if err := cmd.Flags().Set("license", "premium-license"); err != nil {
		t.Fatalf("set license flag: %v", err)
	}
	if err := cmd.Flags().Set("accept-tos", "true"); err != nil {
		t.Fatalf("set accept-tos flag: %v", err)
	}

	if err := runWGRegisterCmd(cmd, nil); err != nil {
		t.Fatalf("runWGRegisterCmd() error = %v", err)
	}

	if gotRebind.deviceID != "device-1" || gotRebind.token != "token-1" || gotRebind.license != "premium-license" {
		t.Fatalf("unexpected rebind args: %#v", gotRebind)
	}
	if savedAccount.License != "premium-license" {
		t.Fatalf("saved license = %q, want premium-license", savedAccount.License)
	}
}

func TestRunWGRegisterCmdPassesJWTForTeamRegister(t *testing.T) {
	oldRegister := wgRegisterDeviceFunc
	oldRebind := wgRebindLicenseFunc
	oldSetName := wgSetDeviceNameFunc
	oldSave := wgSaveAccountFunc
	t.Cleanup(func() {
		wgRegisterDeviceFunc = oldRegister
		wgRebindLicenseFunc = oldRebind
		wgSetDeviceNameFunc = oldSetName
		wgSaveAccountFunc = oldSave
	})

	privateKey, err := wireguard.NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey() error = %v", err)
	}

	var gotJWT string
	wgRegisterDeviceFunc = func(publicKey, model, jwt string) (models.AccountData, error) {
		gotJWT = jwt
		return models.AccountData{
			ID:    "team-device-1",
			Token: "team-token-1",
			Account: models.Account{
				License: "team-license",
			},
		}, nil
	}
	wgRebindLicenseFunc = func(accountData models.AccountData, target string) (models.Account, bool, *models.APIError, error) {
		t.Fatalf("wgRebindLicenseFunc should not be called for team register")
		return models.Account{}, false, nil, nil
	}
	wgSetDeviceNameFunc = func(deviceID, accessToken, deviceName string) error { return nil }

	var savedAccount config.WGAccount
	wgSaveAccountFunc = func(path string, account config.WGAccount) error {
		savedAccount = account
		return nil
	}

	cmd := newWGRegisterCmdForTest()
	if err := cmd.Flags().Set("key", privateKey.String()); err != nil {
		t.Fatalf("set key flag: %v", err)
	}
	if err := cmd.Flags().Set("jwt", "team-jwt-1"); err != nil {
		t.Fatalf("set jwt flag: %v", err)
	}
	if err := cmd.Flags().Set("accept-tos", "true"); err != nil {
		t.Fatalf("set accept-tos flag: %v", err)
	}

	if err := runWGRegisterCmd(cmd, nil); err != nil {
		t.Fatalf("runWGRegisterCmd() error = %v", err)
	}

	if gotJWT != "team-jwt-1" {
		t.Fatalf("register jwt = %q, want %q", gotJWT, "team-jwt-1")
	}
	if savedAccount.DeviceID != "team-device-1" || savedAccount.AccessToken != "team-token-1" {
		t.Fatalf("saved account = %#v", savedAccount)
	}
}

func TestRunWGRegisterCmdRejectsLicenseAndJWTTogether(t *testing.T) {
	cmd := newWGRegisterCmdForTest()
	if err := cmd.Flags().Set("license", "license-1"); err != nil {
		t.Fatalf("set license flag: %v", err)
	}
	if err := cmd.Flags().Set("jwt", "jwt-1"); err != nil {
		t.Fatalf("set jwt flag: %v", err)
	}
	if err := cmd.Flags().Set("accept-tos", "true"); err != nil {
		t.Fatalf("set accept-tos flag: %v", err)
	}

	err := runWGRegisterCmd(cmd, nil)
	if err == nil {
		t.Fatalf("expected error when license and jwt are both set")
	}
	if !strings.Contains(err.Error(), "cannot use --license and --jwt together") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunWGGenerateCmdWritesProfileFromRemoteSourceDevice(t *testing.T) {
	oldLoad := wgLoadAccountFunc
	oldSourceDevice := wgGetSourceDeviceFunc
	t.Cleanup(func() {
		wgLoadAccountFunc = oldLoad
		wgGetSourceDeviceFunc = oldSourceDevice
	})

	privateKey, err := wireguard.NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey() error = %v", err)
	}

	wgLoadAccountFunc = func(path string) (config.WGAccount, error) {
		return config.WGAccount{
			DeviceID:    "device-1",
			AccessToken: "token-1",
			PrivateKey:  privateKey.String(),
		}, nil
	}
	wgGetSourceDeviceFunc = func(deviceID, accessToken string) (models.AccountData, error) {
		device := models.AccountData{}
		device.Config.Interface.Addresses.V4 = "172.16.0.2"
		device.Config.Interface.Addresses.V6 = "2606:4700:110::2"
		peer := models.Peer{
			PublicKey: "peer-public-key",
		}
		peer.Endpoint.Host = "engage.cloudflareclient.com:2408"
		device.Config.Peers = []models.Peer{peer}
		return device, nil
	}

	cmd := newWGGenerateCmdForTest()
	profilePath := filepath.Join(t.TempDir(), "wg-profile.conf")
	if err := cmd.Flags().Set("profile", profilePath); err != nil {
		t.Fatalf("set profile flag: %v", err)
	}

	if err := runWGGenerateCmd(cmd, nil); err != nil {
		t.Fatalf("runWGGenerateCmd() error = %v", err)
	}

	raw, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatalf("read profile: %v", err)
	}
	profile := string(raw)
	for _, needle := range []string{
		"PrivateKey = " + privateKey.String(),
		"Address = 172.16.0.2/32, 2606:4700:110::2/128",
		"PublicKey = peer-public-key",
		"Endpoint = engage.cloudflareclient.com:2408",
	} {
		if !strings.Contains(profile, needle) {
			t.Fatalf("profile missing %q:\n%s", needle, profile)
		}
	}
}

func TestRunWGGenerateCmdRejectsMissingPeers(t *testing.T) {
	oldLoad := wgLoadAccountFunc
	oldSourceDevice := wgGetSourceDeviceFunc
	t.Cleanup(func() {
		wgLoadAccountFunc = oldLoad
		wgGetSourceDeviceFunc = oldSourceDevice
	})

	privateKey, err := wireguard.NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey() error = %v", err)
	}

	wgLoadAccountFunc = func(path string) (config.WGAccount, error) {
		return config.WGAccount{
			DeviceID:    "device-1",
			AccessToken: "token-1",
			PrivateKey:  privateKey.String(),
		}, nil
	}
	wgGetSourceDeviceFunc = func(deviceID, accessToken string) (models.AccountData, error) {
		device := models.AccountData{}
		device.Config.Interface.Addresses.V4 = "172.16.0.2"
		device.Config.Interface.Addresses.V6 = "2606:4700:110::2"
		return device, nil
	}

	err = runWGGenerateCmd(newWGGenerateCmdForTest(), nil)
	if err == nil {
		t.Fatalf("expected error for missing peers")
	}
	if !strings.Contains(err.Error(), "no peers") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunWGGenerateCmdRejectsMalformedPrivateKey(t *testing.T) {
	oldLoad := wgLoadAccountFunc
	t.Cleanup(func() {
		wgLoadAccountFunc = oldLoad
	})

	wgLoadAccountFunc = func(path string) (config.WGAccount, error) {
		return config.WGAccount{
			DeviceID:    "device-1",
			AccessToken: "token-1",
			PrivateKey:  "not-base64",
		}, nil
	}

	err := runWGGenerateCmd(newWGGenerateCmdForTest(), nil)
	if err == nil {
		t.Fatalf("expected error for malformed private key")
	}
	if !strings.Contains(err.Error(), "private key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunWGGenerateCmdFallsBackToEndpointAddressAndPort(t *testing.T) {
	oldLoad := wgLoadAccountFunc
	oldSourceDevice := wgGetSourceDeviceFunc
	t.Cleanup(func() {
		wgLoadAccountFunc = oldLoad
		wgGetSourceDeviceFunc = oldSourceDevice
	})

	privateKey, err := wireguard.NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey() error = %v", err)
	}

	wgLoadAccountFunc = func(path string) (config.WGAccount, error) {
		return config.WGAccount{
			DeviceID:    "device-1",
			AccessToken: "token-1",
			PrivateKey:  privateKey.String(),
		}, nil
	}
	wgGetSourceDeviceFunc = func(deviceID, accessToken string) (models.AccountData, error) {
		device := models.AccountData{}
		device.Config.Interface.Addresses.V4 = "172.16.0.2"
		device.Config.Interface.Addresses.V6 = "2606:4700:110::2"
		peer := models.Peer{
			PublicKey: "peer-public-key",
		}
		peer.Endpoint.V4 = "162.159.192.1"
		peer.Endpoint.Ports = []int{2408}
		device.Config.Peers = []models.Peer{peer}
		return device, nil
	}

	cmd := newWGGenerateCmdForTest()
	profilePath := filepath.Join(t.TempDir(), "wg-profile.conf")
	if err := cmd.Flags().Set("profile", profilePath); err != nil {
		t.Fatalf("set profile flag: %v", err)
	}

	if err := runWGGenerateCmd(cmd, nil); err != nil {
		t.Fatalf("runWGGenerateCmd() error = %v", err)
	}

	raw, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatalf("read profile: %v", err)
	}
	if !strings.Contains(string(raw), "Endpoint = 162.159.192.1:2408") {
		t.Fatalf("profile missing fallback endpoint:\n%s", string(raw))
	}
}

func TestRunWGGenerateCmdCombinesHostAndPortList(t *testing.T) {
	oldLoad := wgLoadAccountFunc
	oldSourceDevice := wgGetSourceDeviceFunc
	t.Cleanup(func() {
		wgLoadAccountFunc = oldLoad
		wgGetSourceDeviceFunc = oldSourceDevice
	})

	privateKey, err := wireguard.NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey() error = %v", err)
	}

	wgLoadAccountFunc = func(path string) (config.WGAccount, error) {
		return config.WGAccount{
			DeviceID:    "device-1",
			AccessToken: "token-1",
			PrivateKey:  privateKey.String(),
		}, nil
	}
	wgGetSourceDeviceFunc = func(deviceID, accessToken string) (models.AccountData, error) {
		device := models.AccountData{}
		device.Config.Interface.Addresses.V4 = "172.16.0.2"
		device.Config.Interface.Addresses.V6 = "2606:4700:110::2"
		peer := models.Peer{
			PublicKey: "peer-public-key",
		}
		peer.Endpoint.Host = "engage.cloudflareclient.com"
		peer.Endpoint.Ports = []int{2408}
		device.Config.Peers = []models.Peer{peer}
		return device, nil
	}

	cmd := newWGGenerateCmdForTest()
	profilePath := filepath.Join(t.TempDir(), "wg-profile.conf")
	if err := cmd.Flags().Set("profile", profilePath); err != nil {
		t.Fatalf("set profile flag: %v", err)
	}

	if err := runWGGenerateCmd(cmd, nil); err != nil {
		t.Fatalf("runWGGenerateCmd() error = %v", err)
	}

	raw, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatalf("read profile: %v", err)
	}
	if !strings.Contains(string(raw), "Endpoint = engage.cloudflareclient.com:2408") {
		t.Fatalf("profile missing combined host+port endpoint:\n%s", string(raw))
	}
}

func TestRunWGUpdateCmdRebindsExistingAccountAndPersistsLicense(t *testing.T) {
	oldLoad := wgLoadAccountFunc
	oldRebind := wgRebindLicenseFunc
	oldSave := wgSaveAccountFunc
	t.Cleanup(func() {
		wgLoadAccountFunc = oldLoad
		wgRebindLicenseFunc = oldRebind
		wgSaveAccountFunc = oldSave
	})

	privateKey, err := wireguard.NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey() error = %v", err)
	}

	wgLoadAccountFunc = func(path string) (config.WGAccount, error) {
		return config.WGAccount{
			DeviceID:    "device-1",
			AccessToken: "token-1",
			License:     "old-license",
			PrivateKey:  privateKey.String(),
			DeviceName:  "edge-node",
			Model:       "PC",
		}, nil
	}

	var gotRebind struct {
		deviceID string
		token    string
		license  string
	}
	wgRebindLicenseFunc = func(accountData models.AccountData, target string) (models.Account, bool, *models.APIError, error) {
		gotRebind.deviceID = accountData.ID
		gotRebind.token = accountData.Token
		gotRebind.license = target
		return models.Account{License: "new-license"}, true, nil, nil
	}

	var savedAccount config.WGAccount
	wgSaveAccountFunc = func(path string, account config.WGAccount) error {
		savedAccount = account
		return nil
	}

	cmd := newWGUpdateCmdForTest()
	if err := cmd.Flags().Set("license", "new-license"); err != nil {
		t.Fatalf("set license flag: %v", err)
	}

	if err := runWGUpdateCmd(cmd, nil); err != nil {
		t.Fatalf("runWGUpdateCmd() error = %v", err)
	}

	if gotRebind.deviceID != "device-1" || gotRebind.token != "token-1" || gotRebind.license != "new-license" {
		t.Fatalf("unexpected rebind args: %#v", gotRebind)
	}
	if savedAccount.License != "new-license" || savedAccount.PrivateKey != privateKey.String() || savedAccount.DeviceName != "edge-node" {
		t.Fatalf("saved account = %#v", savedAccount)
	}
}

func TestRunWGUpdateCmdRequiresLicense(t *testing.T) {
	err := runWGUpdateCmd(newWGUpdateCmdForTest(), nil)
	if err == nil {
		t.Fatalf("expected error for missing license")
	}
	if !strings.Contains(err.Error(), "license is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestShouldSkipConfigLoad(t *testing.T) {
	wgCmd := &cobra.Command{Use: "wg"}
	generateCmd := &cobra.Command{Use: "generate"}
	updateCmd := &cobra.Command{Use: "update"}
	wgCmd.AddCommand(generateCmd)
	wgCmd.AddCommand(updateCmd)
	socksCmd := &cobra.Command{Use: "socks"}

	if !shouldSkipConfigLoad(generateCmd) {
		t.Fatalf("expected wg generate to skip config load")
	}
	if !shouldSkipConfigLoad(updateCmd) {
		t.Fatalf("expected wg update to skip config load")
	}
	if !shouldSkipConfigLoad(socksCmd) {
		t.Fatalf("expected socks command to skip MASQUE config preload")
	}
	if shouldSkipConfigLoad(proxyCmd) {
		t.Fatalf("expected proxy command not to skip config load")
	}
}

func TestRootCommandUseMatchesBinaryName(t *testing.T) {
	if rootCmd.Use != "uscf" {
		t.Fatalf("rootCmd.Use = %q, want %q", rootCmd.Use, "uscf")
	}
}
