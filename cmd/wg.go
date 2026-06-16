package cmd

import "github.com/spf13/cobra"

var wgCmd = &cobra.Command{
	Use:   "wg",
	Short: "Manage standalone WireGuard registration and profile generation",
}

func init() {
	wgCmd.AddCommand(newWGRegisterCmd())
	wgCmd.AddCommand(newWGGenerateCmd())
	wgCmd.AddCommand(newWGUpdateCmd())
	wgCmd.AddCommand(newWGRunCmd())
	rootCmd.AddCommand(wgCmd)
}
