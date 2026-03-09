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

func runWGRegisterCmd(cmd *cobra.Command, args []string) error {
	accountPath, _ := cmd.Flags().GetString("wg-account")
	deviceName, _ := cmd.Flags().GetString("name")
	model, _ := cmd.Flags().GetString("model")
	keyValue, _ := cmd.Flags().GetString("key")
	licenseValue, _ := cmd.Flags().GetString("license")
	jwtValue, _ := cmd.Flags().GetString("jwt")
	acceptTOS, _ := cmd.Flags().GetBool("accept-tos")

	licenseValue = strings.TrimSpace(licenseValue)
	jwtValue = strings.TrimSpace(jwtValue)
	if licenseValue != "" && jwtValue != "" {
		return fmt.Errorf("cannot use --license and --jwt together")
	}

	if err := ensureWGAcceptedTOS(acceptTOS); err != nil {
		return err
	}

	privateKey, err := loadOrCreateWGPrivateKey(keyValue)
	if err != nil {
		return err
	}

	accountData, err := wgRegisterDeviceFunc(privateKey.Public().String(), model, jwtValue)
	if err != nil {
		return fmt.Errorf("register wireguard device: %w", err)
	}
	if licenseValue != "" {
		finalAccount, _, apiErr, err := wgRebindLicenseFunc(accountData, licenseValue)
		if err != nil {
			if apiErr != nil {
				return fmt.Errorf("rebind wireguard license: %w (API errors: %s)", err, apiErr.ErrorsAsString("; "))
			}
			return fmt.Errorf("rebind wireguard license: %w", err)
		}
		accountData.Account = finalAccount
	}

	account := buildWGAccount(accountData, privateKey.String(), deviceName, model)
	if err := wgSaveAccountFunc(accountPath, account); err != nil {
		return fmt.Errorf("save wg account: %w", err)
	}

	if strings.TrimSpace(deviceName) != "" {
		if err := wgSetDeviceNameFunc(accountData.ID, accountData.Token, deviceName); err != nil {
			return fmt.Errorf("set device name: %w (wg account already saved to %s)", err, accountPath)
		}
	}
	return nil
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
