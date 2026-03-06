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
	cmd.Flags().Bool("accept-tos", false, "")
	return cmd
}

func newWGGenerateCmdForTest() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("wg-account", "wg-account.json", "")
	cmd.Flags().String("profile", "wg-profile.conf", "")
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
	wgRegisterDeviceFunc = func(publicKey, model string) (models.AccountData, error) {
		gotPublicKey = publicKey
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

	wgRegisterDeviceFunc = func(publicKey, model string) (models.AccountData, error) {
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

func TestShouldSkipConfigLoad(t *testing.T) {
	wgCmd := &cobra.Command{Use: "wg"}
	generateCmd := &cobra.Command{Use: "generate"}
	wgCmd.AddCommand(generateCmd)

	if !shouldSkipConfigLoad(generateCmd) {
		t.Fatalf("expected wg generate to skip config load")
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
