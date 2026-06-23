package config

import "testing"

func TestNormalizeSocksConfigL4UDP(t *testing.T) {
	base := GetDefaultSocksConfig()

	valid := []struct {
		in   string
		want string
	}{
		{"", L4UDPBlock},
		{"block", L4UDPBlock},
		{"direct", L4UDPDirect},
		{"DIRECT", L4UDPDirect},
		{"  Direct  ", L4UDPDirect},
	}
	for _, tc := range valid {
		cfg := base
		cfg.L4UDP = tc.in
		got, err := NormalizeSocksConfig(cfg)
		if err != nil {
			t.Fatalf("NormalizeSocksConfig(l4_udp=%q): unexpected error %v", tc.in, err)
		}
		if got.L4UDP != tc.want {
			t.Fatalf("NormalizeSocksConfig(l4_udp=%q).L4UDP = %q, want %q", tc.in, got.L4UDP, tc.want)
		}
	}

	cfg := base
	cfg.L4UDP = "tunnel"
	if _, err := NormalizeSocksConfig(cfg); err == nil {
		t.Fatal("NormalizeSocksConfig(l4_udp=\"tunnel\"): expected error, got nil")
	}
}

func TestDefaultSocksConfigL4UDPIsBlock(t *testing.T) {
	if got := GetDefaultSocksConfig().L4UDP; got != L4UDPBlock {
		t.Fatalf("default L4UDP = %q, want %q", got, L4UDPBlock)
	}
}
