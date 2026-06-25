package cmd

import (
	"net"
	"testing"

	"github.com/HynoR/uscf/config"
)

func TestPrepareNetworkConfigResolvesIPv4Endpoint(t *testing.T) {
	origCfg := config.AppConfig
	defer func() { config.AppConfig = origCfg }()

	config.AppConfig = config.Config{
		EndpointV4: "162.159.198.1",
		EndpointV6: "2606:4700:103::1",
		Socks: config.SocksConfig{
			ConnectPort:  443,
			UseIPv6:      false,
			NoTunnelIPv4: true,
			NoTunnelIPv6: true,
			DNS:          []string{"1.1.1.1"},
		},
	}

	endpoint, _, _, err := prepareNetworkConfig(nil)
	if err != nil {
		t.Fatalf("prepareNetworkConfig() error = %v", err)
	}
	udp := mustUDPAddr(t, endpoint)
	if udp.IP.String() != "162.159.198.1" {
		t.Fatalf("unexpected endpoint: %+v", endpoint)
	}
	if udp.Port != 443 {
		t.Fatalf("unexpected port: %d", udp.Port)
	}
}

func TestPrepareNetworkConfigResolvesIPv6Endpoint(t *testing.T) {
	origCfg := config.AppConfig
	defer func() { config.AppConfig = origCfg }()

	config.AppConfig = config.Config{
		EndpointV4: "162.159.198.1",
		EndpointV6: "2606:4700:103::1",
		Socks: config.SocksConfig{
			ConnectPort:  443,
			UseIPv6:      true,
			NoTunnelIPv4: true,
			NoTunnelIPv6: true,
			DNS:          []string{"1.1.1.1"},
		},
	}

	endpoint, _, _, err := prepareNetworkConfig(nil)
	if err != nil {
		t.Fatalf("prepareNetworkConfig() error = %v", err)
	}
	udp := mustUDPAddr(t, endpoint)
	if udp.IP.To4() != nil {
		t.Fatalf("expected ipv6 endpoint, got %s", udp.IP.String())
	}
}

func TestPrepareNetworkConfigUsesHTTP2IPv4EndpointDefault(t *testing.T) {
	origCfg := config.AppConfig
	defer func() { config.AppConfig = origCfg }()

	config.AppConfig = config.Config{
		EndpointV4: "162.159.198.1",
		EndpointV6: "2606:4700:103::1",
		Socks: config.SocksConfig{
			ConnectPort:  443,
			UseIPv6:      false,
			HTTP2:        true,
			NoTunnelIPv4: true,
			NoTunnelIPv6: true,
			DNS:          []string{"1.1.1.1"},
		},
	}

	endpoint, _, _, err := prepareNetworkConfig(nil)
	if err != nil {
		t.Fatalf("prepareNetworkConfig() error = %v", err)
	}
	tcpEndpoint := mustTCPAddr(t, endpoint)
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

	endpoint, _, _, err := prepareNetworkConfig(nil)
	if err != nil {
		t.Fatalf("prepareNetworkConfig() error = %v", err)
	}
	tcpEndpoint := mustTCPAddr(t, endpoint)
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

	_, _, _, err := prepareNetworkConfig(nil)
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
