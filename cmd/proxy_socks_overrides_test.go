package cmd

import (
	"testing"

	"github.com/HynoR/uscf/config"
	"github.com/spf13/cobra"
)

func newSocksOverrideCmdForTest() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("bind-address", "", "")
	cmd.Flags().String("port", "", "")
	cmd.Flags().String("username", "", "")
	cmd.Flags().String("password", "", "")
	cmd.Flags().Bool("use-ipv6", false, "")
	cmd.Flags().Bool("http2", false, "")
	return cmd
}

func TestApplySocksFlagOverridesUseIPv6WhenFlagProvided(t *testing.T) {
	cfg := config.Config{Socks: config.SocksConfig{UseIPv6: false}}
	cmd := newSocksOverrideCmdForTest()
	if err := cmd.Flags().Set("use-ipv6", "true"); err != nil {
		t.Fatalf("failed to set use-ipv6 flag: %v", err)
	}

	changed, _ := applySocksFlagOverrides(cmd, &cfg)
	if !changed {
		t.Fatalf("expected config to be marked changed")
	}
	if !cfg.Socks.UseIPv6 {
		t.Fatalf("expected use_ipv6 to be overridden to true")
	}
}

func TestApplySocksFlagOverridesUseIPv6UnchangedWhenFlagOmitted(t *testing.T) {
	cfg := config.Config{Socks: config.SocksConfig{UseIPv6: true}}
	cmd := newSocksOverrideCmdForTest()

	changed, _ := applySocksFlagOverrides(cmd, &cfg)
	if changed {
		t.Fatalf("expected no config change when use-ipv6 flag is omitted")
	}
	if !cfg.Socks.UseIPv6 {
		t.Fatalf("expected use_ipv6 to keep original value")
	}
}

func TestApplySocksFlagOverridesUseIPv6AllowsFalseWhenExplicitlyProvided(t *testing.T) {
	cfg := config.Config{Socks: config.SocksConfig{UseIPv6: true}}
	cmd := newSocksOverrideCmdForTest()
	if err := cmd.Flags().Set("use-ipv6", "false"); err != nil {
		t.Fatalf("failed to set use-ipv6 flag: %v", err)
	}

	changed, _ := applySocksFlagOverrides(cmd, &cfg)
	if !changed {
		t.Fatalf("expected config to be marked changed")
	}
	if cfg.Socks.UseIPv6 {
		t.Fatalf("expected use_ipv6 to be overridden to false")
	}
}

func TestApplySocksFlagOverridesHTTP2WhenFlagProvided(t *testing.T) {
	cfg := config.Config{Socks: config.SocksConfig{HTTP2: false}}
	cmd := newSocksOverrideCmdForTest()
	if err := cmd.Flags().Set("http2", "true"); err != nil {
		t.Fatalf("failed to set http2 flag: %v", err)
	}

	changed, _ := applySocksFlagOverrides(cmd, &cfg)
	if !changed {
		t.Fatalf("expected config to be marked changed")
	}
	if !cfg.Socks.HTTP2 {
		t.Fatalf("expected http2 to be overridden to true")
	}
}

func TestApplySocksFlagOverridesHTTP2AllowsFalseWhenExplicitlyProvided(t *testing.T) {
	cfg := config.Config{Socks: config.SocksConfig{HTTP2: true}}
	cmd := newSocksOverrideCmdForTest()
	if err := cmd.Flags().Set("http2", "false"); err != nil {
		t.Fatalf("failed to set http2 flag: %v", err)
	}

	changed, _ := applySocksFlagOverrides(cmd, &cfg)
	if !changed {
		t.Fatalf("expected config to be marked changed")
	}
	if cfg.Socks.HTTP2 {
		t.Fatalf("expected http2 to be overridden to false")
	}
}
