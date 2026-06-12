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
	fallbackUDP := mustUDPAddr(t, fallback)
	if fallbackUDP.IP.String() != "162.159.198.1" {
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
		picked := mustUDPAddr(t, selector())
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
	fallbackUDP := mustUDPAddr(t, fallback)
	if !fallbackUDP.IP.Equal(net.ParseIP("162.159.198.1")) {
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
		picked := mustUDPAddr(t, selector())
		if picked.IP.To4() != nil {
			t.Fatalf("expected ipv6 endpoint, got %s", picked.IP.String())
		}
	}
}

func TestPrepareNetworkConfigUsesHTTP2IPv4EndpointDefault(t *testing.T) {
	origCfg := config.AppConfig
	defer func() { config.AppConfig = origCfg }()

	config.AppConfig = config.Config{
		EndpointV4:        "162.159.198.1",
		EndpointV6:        "2606:4700:103::1",
		CustomEndpointsV4: []string{"162.159.199.1"},
		Socks: config.SocksConfig{
			ConnectPort:  443,
			UseIPv6:      false,
			HTTP2:        true,
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
		t.Fatalf("expected HTTP/2 mode not to use H3 custom endpoint selector")
	}
	tcpEndpoint := mustTCPAddr(t, fallback)
	if got := tcpEndpoint.IP.String(); got != config.DefaultEndpointH2V4 {
		t.Fatalf("unexpected HTTP/2 endpoint IP: got %s want %s", got, config.DefaultEndpointH2V4)
	}
	if tcpEndpoint.Port != 443 {
		t.Fatalf("unexpected HTTP/2 endpoint port: %d", tcpEndpoint.Port)
	}
}

func TestPrepareNetworkConfigUsesHTTP2ConfiguredIPv6Endpoint(t *testing.T) {
	origCfg := config.AppConfig
	defer func() { config.AppConfig = origCfg }()

	config.AppConfig = config.Config{
		EndpointH2V6: "2606:4700:103::2",
		Socks: config.SocksConfig{
			ConnectPort:  443,
			UseIPv6:      true,
			HTTP2:        true,
			NoTunnelIPv4: true,
			NoTunnelIPv6: true,
			DNS:          []string{"1.1.1.1"},
		},
	}

	fallback, _, _, _, err := prepareNetworkConfig(nil)
	if err != nil {
		t.Fatalf("prepareNetworkConfig() error = %v", err)
	}
	tcpEndpoint := mustTCPAddr(t, fallback)
	if got := tcpEndpoint.IP.String(); got != "2606:4700:103::2" {
		t.Fatalf("unexpected HTTP/2 IPv6 endpoint IP: %s", got)
	}
}

func TestPrepareNetworkConfigRequiresHTTP2IPv6Endpoint(t *testing.T) {
	origCfg := config.AppConfig
	defer func() { config.AppConfig = origCfg }()

	config.AppConfig = config.Config{
		Socks: config.SocksConfig{
			ConnectPort: 443,
			UseIPv6:     true,
			HTTP2:       true,
			DNS:         []string{"1.1.1.1"},
		},
	}

	_, _, _, _, err := prepareNetworkConfig(nil)
	if err == nil {
		t.Fatalf("expected missing endpoint_h2_v6 error")
	}
}

func mustUDPAddr(t *testing.T, addr net.Addr) *net.UDPAddr {
	t.Helper()
	if addr == nil {
		t.Fatalf("endpoint is nil")
	}
	udp, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected UDP endpoint, got %T", addr)
	}
	return udp
}

func mustTCPAddr(t *testing.T, addr net.Addr) *net.TCPAddr {
	t.Helper()
	if addr == nil {
		t.Fatalf("endpoint is nil")
	}
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("expected TCP endpoint, got %T", addr)
	}
	return tcp
}
