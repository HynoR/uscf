package cmd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/HynoR/uscf/config"
	"github.com/HynoR/uscf/internal"
	"github.com/HynoR/uscf/scanner"
	"github.com/spf13/cobra"
)

func TestScanAndUpdateConfigIPv4UpdatesOnlyV4(t *testing.T) {
	origCfg := config.AppConfig
	origLoaded := config.ConfigLoaded
	defer func() {
		config.AppConfig = origCfg
		config.ConfigLoaded = origLoaded
	}()

	restore := mockScanDeps(t)
	defer restore()

	config.ConfigLoaded = true
	config.AppConfig = config.Config{
		EndpointV4: "162.159.198.1",
		EndpointV6: "2606:4700:103::1",
		Socks: config.SocksConfig{
			ConnectPort:       443,
			SNIAddress:        internal.ConnectSNI,
			InitialPacketSize: 1242,
		},
	}

	scanGenerateCandidatesFn = func(cidrs []string, port int, family scanner.IPFamily, samplePerCIDR int, rnd *rand.Rand) ([]string, error) {
		return []string{"9.9.9.9:443"}, nil
	}
	scanEndpointsFn = func(endpoints []string, opts ...scanner.Option) []scanner.Result {
		return []scanner.Result{{Endpoint: "9.9.9.9:443", OK: true}}
	}
	scanPickHealthyFn = func(results []scanner.Result, rnd *rand.Rand) (string, error) {
		return "9.9.9.9:443", nil
	}

	path := filepath.Join(t.TempDir(), "config.json")
	if err := scanAndUpdateConfig(nil, path, scanner.IPFamilyV4, time.Second); err != nil {
		t.Fatalf("scanAndUpdateConfig() error = %v", err)
	}

	if config.AppConfig.EndpointV4 != "9.9.9.9" {
		t.Fatalf("expected endpoint_v4 to be updated, got %s", config.AppConfig.EndpointV4)
	}
	if config.AppConfig.EndpointV6 != "2606:4700:103::1" {
		t.Fatalf("endpoint_v6 should remain unchanged, got %s", config.AppConfig.EndpointV6)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read saved config: %v", err)
	}
	var saved config.Config
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatalf("failed to decode saved config: %v", err)
	}
	if saved.EndpointV4 != "9.9.9.9" {
		t.Fatalf("saved endpoint_v4 mismatch, got %s", saved.EndpointV4)
	}
}

func TestScanAndUpdateConfigIPv6UpdatesOnlyV6(t *testing.T) {
	origCfg := config.AppConfig
	origLoaded := config.ConfigLoaded
	defer func() {
		config.AppConfig = origCfg
		config.ConfigLoaded = origLoaded
	}()

	restore := mockScanDeps(t)
	defer restore()

	config.ConfigLoaded = true
	config.AppConfig = config.Config{
		EndpointV4: "162.159.198.1",
		EndpointV6: "2606:4700:103::1",
		Socks: config.SocksConfig{
			ConnectPort:       443,
			SNIAddress:        internal.ConnectSNI,
			InitialPacketSize: 1242,
		},
	}

	scanGenerateCandidatesFn = func(cidrs []string, port int, family scanner.IPFamily, samplePerCIDR int, rnd *rand.Rand) ([]string, error) {
		return []string{"[2001:db8::2]:443"}, nil
	}
	scanEndpointsFn = func(endpoints []string, opts ...scanner.Option) []scanner.Result {
		return []scanner.Result{{Endpoint: "[2001:db8::2]:443", OK: true}}
	}
	scanPickHealthyFn = func(results []scanner.Result, rnd *rand.Rand) (string, error) {
		return "[2001:db8::2]:443", nil
	}

	path := filepath.Join(t.TempDir(), "config.json")
	if err := scanAndUpdateConfig(nil, path, scanner.IPFamilyV6, time.Second); err != nil {
		t.Fatalf("scanAndUpdateConfig() error = %v", err)
	}

	if config.AppConfig.EndpointV4 != "162.159.198.1" {
		t.Fatalf("endpoint_v4 should remain unchanged, got %s", config.AppConfig.EndpointV4)
	}
	if config.AppConfig.EndpointV6 != "2001:db8::2" {
		t.Fatalf("expected endpoint_v6 to be updated, got %s", config.AppConfig.EndpointV6)
	}
}

func TestScanAndUpdateConfigNoHealthyDoesNotPersist(t *testing.T) {
	origCfg := config.AppConfig
	origLoaded := config.ConfigLoaded
	defer func() {
		config.AppConfig = origCfg
		config.ConfigLoaded = origLoaded
	}()

	restore := mockScanDeps(t)
	defer restore()

	config.ConfigLoaded = true
	config.AppConfig = config.Config{
		EndpointV4: "162.159.198.1",
		EndpointV6: "2606:4700:103::1",
		Socks: config.SocksConfig{
			ConnectPort:       443,
			SNIAddress:        internal.ConnectSNI,
			InitialPacketSize: 1242,
		},
	}

	scanGenerateCandidatesFn = func(cidrs []string, port int, family scanner.IPFamily, samplePerCIDR int, rnd *rand.Rand) ([]string, error) {
		return []string{"9.9.9.9:443"}, nil
	}
	scanEndpointsFn = func(endpoints []string, opts ...scanner.Option) []scanner.Result {
		return []scanner.Result{{Endpoint: "9.9.9.9:443", OK: false, Err: "boom"}}
	}
	scanPickHealthyFn = func(results []scanner.Result, rnd *rand.Rand) (string, error) {
		return "", errors.New("no healthy endpoints")
	}

	path := filepath.Join(t.TempDir(), "config.json")
	err := scanAndUpdateConfig(nil, path, scanner.IPFamilyV4, time.Second)
	if err == nil {
		t.Fatalf("expected error when no healthy endpoint")
	}
	if config.AppConfig.EndpointV4 != "162.159.198.1" {
		t.Fatalf("endpoint_v4 should not change on failure, got %s", config.AppConfig.EndpointV4)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("config file should not be saved on failure")
	}
}

func TestRunScanCmdRequiresExactlyOneFamilyFlag(t *testing.T) {
	origCfg := config.AppConfig
	origLoaded := config.ConfigLoaded
	defer func() {
		config.AppConfig = origCfg
		config.ConfigLoaded = origLoaded
	}()

	config.ConfigLoaded = true
	cmd := newScanTestCommand()
	if err := cmd.Flags().Set("ipv4", "true"); err != nil {
		t.Fatalf("failed to set flag: %v", err)
	}
	if err := cmd.Flags().Set("ipv6", "true"); err != nil {
		t.Fatalf("failed to set flag: %v", err)
	}

	err := runScanCmd(cmd, nil)
	if err == nil {
		t.Fatalf("expected mutual exclusion validation error")
	}
}

func newScanTestCommand() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().Bool("ipv4", false, "")
	cmd.Flags().Bool("ipv6", false, "")
	cmd.Flags().Duration("timeout", scanner.DefaultScanPerIPTimeout, "")
	cmd.Flags().String("config", "config.json", "")
	return cmd
}

func mockScanDeps(t *testing.T) func() {
	t.Helper()

	origGenerate := scanGenerateCandidatesFn
	origScan := scanEndpointsFn
	origPick := scanPickHealthyFn
	origTLS := scanPrepareTLSConfigFn
	origProbeBuilder := scanProbeBuilderFn

	scanPrepareTLSConfigFn = func(cmd *cobra.Command) (*tls.Config, error) {
		return &tls.Config{}, nil
	}
	scanProbeBuilderFn = func(tlsConf *tls.Config) scanner.ProbeFunc {
		return func(ctx context.Context, endpoint string, o scanner.Options) error {
			return nil
		}
	}

	return func() {
		scanGenerateCandidatesFn = origGenerate
		scanEndpointsFn = origScan
		scanPickHealthyFn = origPick
		scanPrepareTLSConfigFn = origTLS
		scanProbeBuilderFn = origProbeBuilder
	}
}
