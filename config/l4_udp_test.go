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
		{"tunnel", L4UDPTunnel},
		{"TUNNEL", L4UDPTunnel},
		{"  Tunnel  ", L4UDPTunnel},
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
	cfg.L4UDP = "garbage"
	if _, err := NormalizeSocksConfig(cfg); err == nil {
		t.Fatal("NormalizeSocksConfig(l4_udp=\"garbage\"): expected error, got nil")
	}
}

func TestDefaultSocksConfigL4UDPIsBlock(t *testing.T) {
	if got := GetDefaultSocksConfig().L4UDP; got != L4UDPBlock {
		t.Fatalf("default L4UDP = %q, want %q", got, L4UDPBlock)
	}
}

// TestDefaultSocksConfigL4PoolSizeIsOne pins the pool default to a single connection:
// a stable WARP egress identity. A larger default would fragment the egress IP for no
// real throughput gain (Cloudflare caps connections per enrollment).
func TestDefaultSocksConfigL4PoolSizeIsOne(t *testing.T) {
	if got := GetDefaultSocksConfig().L4PoolSize; got != 1 {
		t.Fatalf("default L4PoolSize = %d, want 1", got)
	}
	if DefaultL4PoolSize != 1 {
		t.Fatalf("DefaultL4PoolSize = %d, want 1", DefaultL4PoolSize)
	}
}

func TestNormalizeSocksConfigL4MaxStreams(t *testing.T) {
	base := GetDefaultSocksConfig()

	if base.L4MaxStreams != DefaultL4MaxStreams {
		t.Fatalf("default L4MaxStreams = %d, want %d", base.L4MaxStreams, DefaultL4MaxStreams)
	}

	cases := []struct {
		name string
		in   int
		want int
	}{
		{"zero -> default", 0, DefaultL4MaxStreams},
		{"negative -> default", -5, DefaultL4MaxStreams},
		{"in range kept", 1000, 1000},
		{"over max clamped", MaxL4MaxStreams + 1, MaxL4MaxStreams},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			cfg.L4MaxStreams = tc.in
			got, err := NormalizeSocksConfig(cfg)
			if err != nil {
				t.Fatalf("NormalizeSocksConfig: %v", err)
			}
			if got.L4MaxStreams != tc.want {
				t.Fatalf("L4MaxStreams = %d, want %d", got.L4MaxStreams, tc.want)
			}
		})
	}
}
