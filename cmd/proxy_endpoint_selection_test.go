package cmd

import (
	"net"
	"testing"

	"github.com/HynoR/uscf/config"
)

func TestPrepareNetworkConfigUsesCustomIPv4Pool(t *testing.T) {
	origCfg := config.AppConfig
	defer func() { config.AppConfig = origCfg }()

	config.AppConfig = config.Config{
		EndpointV4:        "162.159.198.1",
		EndpointV6:        "2606:4700:103::1",
		CustomEndpointsV4: []string{"162.159.199.1", "bad-ip", "162.159.199.2"},
		Socks: config.SocksConfig{
			ConnectPort:    443,
			UseIPv6:        false,
			NoTunnelIPv4:   true,
			NoTunnelIPv6:   true,
			DNS:            []string{"1.1.1.1"},
			BlockUDP443:    false,
			SNIAddress:     "",
			BindAddress:    "127.0.0.1",
			Port:           "1080",
			RemoteDNS:      false,
			DNSTimeout:     config.Duration(2),
			ReconnectDelay: config.Duration(1),
		},
	}

	fallback, selector, _, _, err := prepareNetworkConfig(nil)
	if err != nil {
		t.Fatalf("prepareNetworkConfig() error = %v", err)
	}
	if fallback == nil || fallback.IP.String() != "162.159.198.1" {
		t.Fatalf("unexpected fallback endpoint: %+v", fallback)
	}
	if selector == nil {
		t.Fatalf("expected custom selector to be enabled")
	}

	allowed := map[string]struct{}{
		"162.159.199.1": {},
		"162.159.199.2": {},
	}
	for i := 0; i < 20; i++ {
		picked := selector()
		if picked == nil {
			t.Fatalf("selector returned nil")
		}
		if picked.Port != 443 {
			t.Fatalf("unexpected picked port: %d", picked.Port)
		}
		if _, ok := allowed[picked.IP.String()]; !ok {
			t.Fatalf("picked endpoint not in custom pool: %s", picked.IP.String())
		}
	}
}

func TestPrepareNetworkConfigFallsBackWhenCustomInvalid(t *testing.T) {
	origCfg := config.AppConfig
	defer func() { config.AppConfig = origCfg }()

	config.AppConfig = config.Config{
		EndpointV4:        "162.159.198.1",
		EndpointV6:        "2606:4700:103::1",
		CustomEndpointsV4: []string{"bad-ip", "2606:4700:103::1"},
		Socks: config.SocksConfig{
			ConnectPort:  443,
			UseIPv6:      false,
			NoTunnelIPv4: true,
			NoTunnelIPv6: true,
			DNS:          []string{"1.1.1.1"},
		},
	}

	fallback, selector, _, _, err := prepareNetworkConfig(nil)
	if err != nil {
		t.Fatalf("prepareNetworkConfig() error = %v", err)
	}
	if selector != nil {
		t.Fatalf("expected selector to be nil when custom pool has no valid entries")
	}
	if fallback == nil || !fallback.IP.Equal(net.ParseIP("162.159.198.1")) {
		t.Fatalf("unexpected fallback endpoint: %+v", fallback)
	}
}

func TestPrepareNetworkConfigUsesIPv6CustomPool(t *testing.T) {
	origCfg := config.AppConfig
	defer func() { config.AppConfig = origCfg }()

	config.AppConfig = config.Config{
		EndpointV4:        "162.159.198.1",
		EndpointV6:        "2606:4700:103::1",
		CustomEndpointsV4: []string{"162.159.199.1"},
		CustomEndpointsV6: []string{"2606:4700:104::1", "2606:4700:104::2"},
		Socks: config.SocksConfig{
			ConnectPort:  443,
			UseIPv6:      true,
			NoTunnelIPv4: true,
			NoTunnelIPv6: true,
			DNS:          []string{"1.1.1.1"},
		},
	}

	_, selector, _, _, err := prepareNetworkConfig(nil)
	if err != nil {
		t.Fatalf("prepareNetworkConfig() error = %v", err)
	}
	if selector == nil {
		t.Fatalf("expected ipv6 custom selector")
	}

	for i := 0; i < 10; i++ {
		picked := selector()
		if picked == nil {
			t.Fatalf("selector returned nil")
		}
		if picked.IP.To4() != nil {
			t.Fatalf("expected ipv6 endpoint, got %s", picked.IP.String())
		}
	}
}
