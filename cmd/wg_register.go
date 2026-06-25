package cmd

import (
	"fmt"
	"strings"

	"github.com/HynoR/uscf/api"
	"github.com/HynoR/uscf/config"
	"github.com/HynoR/uscf/internal"
	"github.com/HynoR/uscf/models"
	"github.com/HynoR/uscf/wireguard"
	"github.com/spf13/cobra"
)

var (
	wgRegisterDeviceFunc = api.RegisterWireGuardDevice
	wgRebindLicenseFunc  = api.RebindLicense
	wgSetDeviceNameFunc  = api.SetWireGuardDeviceName
	wgSaveAccountFunc    = func(path string, account config.WGAccount) error { return account.Save(path) }
)

func newWGRegisterCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a standalone WireGuard device",
		RunE:  runWGRegisterCmd,
	}

	cmd.Flags().String("wg-account", "wg-account.json", "WireGuard account file")
	cmd.Flags().String("name", "", "Device name displayed in the 1.1.1.1 app")
	cmd.Flags().String("model", internal.DefaultModel, "Device model displayed in the 1.1.1.1 app")
	cmd.Flags().String("key", "", "Existing base64 WireGuard private key (defaults to random)")
	cmd.Flags().String("license", "", "WARP+ license key for premium WireGuard registration")
	cmd.Flags().String("jwt", "", "Team token for WireGuard team registration")
	cmd.Flags().Bool("accept-tos", false, "Accept Cloudflare's Terms of Service non-interactively")

	return cmd
}

// wgRegisterOptions carries the inputs shared by `uscf wg register` and the
// auto-registration performed by `uscf proxy --wg`.
type wgRegisterOptions struct {
	name      string // device name shown in the 1.1.1.1 app (empty = unset)
	model     string // device model
	key       string // existing base64 private key (empty = generate a random one)
	license   string // WARP+ license for premium registration (mutually exclusive with jwt)
	jwt       string // team token for team registration (mutually exclusive with license)
	acceptTOS bool   // when false, prompt interactively before registering
}

func runWGRegisterCmd(cmd *cobra.Command, args []string) error {
	accountPath, _ := cmd.Flags().GetString("wg-account")
	deviceName, _ := cmd.Flags().GetString("name")
	model, _ := cmd.Flags().GetString("model")
	keyValue, _ := cmd.Flags().GetString("key")
	licenseValue, _ := cmd.Flags().GetString("license")
	jwtValue, _ := cmd.Flags().GetString("jwt")
	acceptTOS, _ := cmd.Flags().GetBool("accept-tos")

	if err := ensureWGAcceptedTOS(acceptTOS); err != nil {
		return err
	}

	_, err := registerWGAccount(accountPath, wgRegisterOptions{
		name:      deviceName,
		model:     model,
		key:       keyValue,
		license:   licenseValue,
		jwt:       jwtValue,
		acceptTOS: acceptTOS,
	})
	return err
}

// ensureWGAccount returns a valid WireGuard account from accountPath, registering
// and saving a new one when the file is missing or invalid. It is the auto-setup
// entry point used by `uscf proxy --wg`: an existing valid account is reused
// as-is (no TOS prompt, no network call), while a first run transparently
// registers a device (free by default; premium/team via opts.license/opts.jwt).
func ensureWGAccount(accountPath string, opts wgRegisterOptions) (config.WGAccount, error) {
	if account, err := wgLoadAccountFunc(accountPath); err == nil {
		if account.Validate() == nil {
			return account, nil
		}
	}
	if err := ensureWGAcceptedTOS(opts.acceptTOS); err != nil {
		return config.WGAccount{}, err
	}
	return registerWGAccount(accountPath, opts)
}

// registerWGAccount registers a standalone WireGuard device and saves it to
// accountPath. It is the shared body behind `uscf wg register` and the
// auto-registration in ensureWGAccount; the caller is responsible for TOS
// acceptance before invoking it.
func registerWGAccount(accountPath string, opts wgRegisterOptions) (config.WGAccount, error) {
	license := strings.TrimSpace(opts.license)
	jwt := strings.TrimSpace(opts.jwt)
	if license != "" && jwt != "" {
		return config.WGAccount{}, fmt.Errorf("cannot use --license and --jwt together")
	}

	privateKey, err := loadOrCreateWGPrivateKey(opts.key)
	if err != nil {
		return config.WGAccount{}, err
	}

	accountData, err := wgRegisterDeviceFunc(privateKey.Public().String(), opts.model, jwt)
	if err != nil {
		return config.WGAccount{}, fmt.Errorf("register wireguard device: %w", err)
	}
	if license != "" {
		finalAccount, _, apiErr, err := wgRebindLicenseFunc(accountData, license)
		if err != nil {
			if apiErr != nil {
				return config.WGAccount{}, fmt.Errorf("rebind wireguard license: %w (API errors: %s)", err, apiErr.ErrorsAsString("; "))
			}
			return config.WGAccount{}, fmt.Errorf("rebind wireguard license: %w", err)
		}
		accountData.Account = finalAccount
	}

	account := buildWGAccount(accountData, privateKey.String(), opts.name, opts.model)
	if err := wgSaveAccountFunc(accountPath, account); err != nil {
		return config.WGAccount{}, fmt.Errorf("save wg account: %w", err)
	}

	if strings.TrimSpace(opts.name) != "" {
		if err := wgSetDeviceNameFunc(accountData.ID, accountData.Token, opts.name); err != nil {
			return config.WGAccount{}, fmt.Errorf("set device name: %w (wg account already saved to %s)", err, accountPath)
		}
	}
	return account, nil
}

func ensureWGAcceptedTOS(accepted bool) error {
	if accepted {
		return nil
	}

	fmt.Print("You must accept the Terms of Service (https://www.cloudflare.com/application/terms/) to register. Do you agree? (y/n): ")
	var response string
	if _, err := fmt.Scanln(&response); err != nil {
		return fmt.Errorf("failed to read user input: %w", err)
	}
	if strings.ToLower(strings.TrimSpace(response)) != "y" {
		return fmt.Errorf("user did not accept TOS")
	}
	return nil
}

func loadOrCreateWGPrivateKey(keyValue string) (*wireguard.Key, error) {
	keyValue = strings.TrimSpace(keyValue)
	if keyValue == "" {
		privateKey, err := wireguard.NewPrivateKey()
		if err != nil {
			return nil, fmt.Errorf("generate wireguard private key: %w", err)
		}
		return privateKey, nil
	}

	privateKey, err := wireguard.NewKey(keyValue)
	if err != nil {
		return nil, fmt.Errorf("parse wireguard private key: %w", err)
	}
	return privateKey, nil
}

func buildWGAccount(accountData models.AccountData, privateKey, deviceName, model string) config.WGAccount {
	return config.WGAccount{
		DeviceID:    accountData.ID,
		AccessToken: accountData.Token,
		License:     accountData.Account.License,
		PrivateKey:  privateKey,
		DeviceName:  deviceName,
		Model:       model,
	}
}
