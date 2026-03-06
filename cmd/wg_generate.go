package cmd

import (
	"fmt"
	"net"

	"github.com/HynoR/uscf/api"
	"github.com/HynoR/uscf/config"
	"github.com/HynoR/uscf/models"
	"github.com/HynoR/uscf/wireguard"
	"github.com/spf13/cobra"
)

var (
	wgLoadAccountFunc     = config.LoadWGAccount
	wgGetSourceDeviceFunc = api.GetWireGuardSourceDevice
)

func newWGGenerateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a WireGuard profile from a standalone WireGuard account",
		RunE:  runWGGenerateCmd,
	}

	cmd.Flags().String("wg-account", "wg-account.json", "WireGuard account file")
	cmd.Flags().String("profile", "wg-profile.conf", "WireGuard profile output file")

	return cmd
}

func runWGGenerateCmd(cmd *cobra.Command, args []string) error {
	accountPath, _ := cmd.Flags().GetString("wg-account")
	profilePath, _ := cmd.Flags().GetString("profile")

	account, err := wgLoadAccountFunc(accountPath)
	if err != nil {
		return fmt.Errorf("load wg account: %w", err)
	}
	if err := account.Validate(); err != nil {
		return fmt.Errorf("invalid wg account: %w", err)
	}
	if _, err := wireguard.NewKey(account.PrivateKey); err != nil {
		return fmt.Errorf("invalid wg account private key: %w", err)
	}

	device, err := wgGetSourceDeviceFunc(account.DeviceID, account.AccessToken)
	if err != nil {
		return fmt.Errorf("fetch source device: %w", err)
	}

	profileData, err := buildWGProfileData(account, device)
	if err != nil {
		return err
	}

	profile, err := wireguard.NewProfile(profileData)
	if err != nil {
		return fmt.Errorf("build wireguard profile: %w", err)
	}
	if err := profile.Save(profilePath); err != nil {
		return fmt.Errorf("save wireguard profile: %w", err)
	}
	return nil
}

func buildWGProfileData(account config.WGAccount, device models.AccountData) (*wireguard.ProfileData, error) {
	if len(device.Config.Peers) == 0 {
		return nil, fmt.Errorf("generate wireguard profile: source device has no peers")
	}
	if device.Config.Interface.Addresses.V4 == "" {
		return nil, fmt.Errorf("generate wireguard profile: source device missing IPv4 address")
	}
	if device.Config.Interface.Addresses.V6 == "" {
		return nil, fmt.Errorf("generate wireguard profile: source device missing IPv6 address")
	}

	peer := device.Config.Peers[0]
	if peer.PublicKey == "" {
		return nil, fmt.Errorf("generate wireguard profile: source device missing peer public key")
	}
	endpoint, err := resolveWireGuardEndpoint(peer)
	if err != nil {
		return nil, err
	}
	if endpoint == "" {
		return nil, fmt.Errorf("generate wireguard profile: source device missing peer endpoint")
	}

	return &wireguard.ProfileData{
		PrivateKey: account.PrivateKey,
		Address1:   device.Config.Interface.Addresses.V4,
		Address2:   device.Config.Interface.Addresses.V6,
		PublicKey:  peer.PublicKey,
		Endpoint:   endpoint,
	}, nil
}

func resolveWireGuardEndpoint(peer models.Peer) (string, error) {
	if peer.Endpoint.Host != "" {
		if len(peer.Endpoint.Ports) == 0 {
			return peer.Endpoint.Host, nil
		}
		if _, _, err := net.SplitHostPort(peer.Endpoint.Host); err == nil {
			return peer.Endpoint.Host, nil
		}
		return net.JoinHostPort(peer.Endpoint.Host, fmt.Sprintf("%d", peer.Endpoint.Ports[0])), nil
	}
	if len(peer.Endpoint.Ports) == 0 {
		return "", fmt.Errorf("generate wireguard profile: source device missing peer endpoint")
	}

	port := peer.Endpoint.Ports[0]
	switch {
	case peer.Endpoint.V4 != "":
		return net.JoinHostPort(peer.Endpoint.V4, fmt.Sprintf("%d", port)), nil
	case peer.Endpoint.V6 != "":
		return net.JoinHostPort(peer.Endpoint.V6, fmt.Sprintf("%d", port)), nil
	default:
		return "", fmt.Errorf("generate wireguard profile: source device missing peer endpoint")
	}
}
