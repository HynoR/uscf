package cmd

import (
	"fmt"
	"strings"

	"github.com/HynoR/uscf/models"
	"github.com/spf13/cobra"
)

func newWGUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update an existing standalone WireGuard account",
		RunE:  runWGUpdateCmd,
	}

	cmd.Flags().String("wg-account", "wg-account.json", "WireGuard account file")
	cmd.Flags().String("license", "", "WARP+ license key to bind to the existing WireGuard account")

	return cmd
}

func runWGUpdateCmd(cmd *cobra.Command, args []string) error {
	accountPath, _ := cmd.Flags().GetString("wg-account")
	licenseValue, _ := cmd.Flags().GetString("license")
	licenseValue = strings.TrimSpace(licenseValue)
	if licenseValue == "" {
		return fmt.Errorf("license is required")
	}

	account, err := wgLoadAccountFunc(accountPath)
	if err != nil {
		return fmt.Errorf("load wg account: %w", err)
	}
	if strings.TrimSpace(account.DeviceID) == "" {
		return fmt.Errorf("invalid wg account: missing device_id in wg account")
	}
	if strings.TrimSpace(account.AccessToken) == "" {
		return fmt.Errorf("invalid wg account: missing access_token in wg account")
	}
	if strings.TrimSpace(account.PrivateKey) == "" {
		return fmt.Errorf("invalid wg account: missing private_key in wg account")
	}

	accountData := models.AccountData{
		ID:    account.DeviceID,
		Token: account.AccessToken,
		Account: models.Account{
			License: account.License,
		},
	}

	finalAccount, _, apiErr, err := wgRebindLicenseFunc(accountData, licenseValue)
	if err != nil {
		if apiErr != nil {
			return fmt.Errorf("rebind wireguard license: %w (API errors: %s)", err, apiErr.ErrorsAsString("; "))
		}
		return fmt.Errorf("rebind wireguard license: %w", err)
	}

	account.License = finalAccount.License
	if err := wgSaveAccountFunc(accountPath, account); err != nil {
		return fmt.Errorf("save wg account: %w", err)
	}

	return nil
}
