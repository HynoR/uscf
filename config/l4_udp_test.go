package config

import (
	"testing"
	"time"
)

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

// TestNormalizeSocksConfigL4HalfOpenTimeout verifies the half-open reaper bound falls
// back to its default when unset/non-positive and is otherwise preserved.
func TestNormalizeSocksConfigL4HalfOpenTimeout(t *testing.T) {
	base := GetDefaultSocksConfig()
	if base.L4HalfOpenTimeout.Duration() != DefaultL4HalfOpenTimeout {
		t.Fatalf("default L4HalfOpenTimeout = %v, want %v", base.L4HalfOpenTimeout.Duration(), DefaultL4HalfOpenTimeout)
	}

	cfg := base
	cfg.L4HalfOpenTimeout = 0
	got, err := NormalizeSocksConfig(cfg)
	if err != nil {
		t.Fatalf("NormalizeSocksConfig: %v", err)
	}
	if got.L4HalfOpenTimeout.Duration() != DefaultL4HalfOpenTimeout {
		t.Fatalf("zero L4HalfOpenTimeout -> %v, want default %v", got.L4HalfOpenTimeout.Duration(), DefaultL4HalfOpenTimeout)
	}

	cfg.L4HalfOpenTimeout = Duration(90 * time.Second)
	got, err = NormalizeSocksConfig(cfg)
	if err != nil {
		t.Fatalf("NormalizeSocksConfig: %v", err)
	}
	if got.L4HalfOpenTimeout.Duration() != 90*time.Second {
		t.Fatalf("in-range L4HalfOpenTimeout = %v, want 90s", got.L4HalfOpenTimeout.Duration())
	}
}

// TestL4TimeoutsAreIsolatedFromL3 pins the L4-specific connect/idle timeouts and proves
// they are decoupled from the L3 connection_timeout / idle_timeout — tuning one transport
// must never bleed into the other (L4 streams are scarce QUIC streams, L3 flows are cheap
// netstack conns). Defaults follow the reference MASQUE impls (usque's 60s data-path idle).
func TestL4TimeoutsAreIsolatedFromL3(t *testing.T) {
	base := GetDefaultSocksConfig()

	if DefaultL4ConnectionTimeout != 30*time.Second {
		t.Fatalf("DefaultL4ConnectionTimeout = %v, want 30s", DefaultL4ConnectionTimeout)
	}
	if DefaultL4IdleTimeout != 60*time.Second {
		t.Fatalf("DefaultL4IdleTimeout = %v, want 60s (usque data-path timeout)", DefaultL4IdleTimeout)
	}
	if base.L4ConnectionTimeout.Duration() != DefaultL4ConnectionTimeout {
		t.Fatalf("default L4ConnectionTimeout = %v, want %v", base.L4ConnectionTimeout.Duration(), DefaultL4ConnectionTimeout)
	}
	if base.L4IdleTimeout.Duration() != DefaultL4IdleTimeout {
		t.Fatalf("default L4IdleTimeout = %v, want %v", base.L4IdleTimeout.Duration(), DefaultL4IdleTimeout)
	}
	// Isolation: the L4 idle default must NOT equal the (longer) L3 idle default.
	if base.L4IdleTimeout.Duration() == base.IdleTimeout.Duration() {
		t.Fatalf("L4IdleTimeout must differ from L3 IdleTimeout (both %v) — they must be independent", base.IdleTimeout.Duration())
	}

	// Non-positive L4 timeouts fall back to the L4 defaults, NOT to the L3 values.
	cfg := base
	cfg.L4ConnectionTimeout = 0
	cfg.L4IdleTimeout = 0
	cfg.ConnectionTimeout = Duration(99 * time.Second) // distinct L3 values...
	cfg.IdleTimeout = Duration(99 * time.Minute)       // ...that must NOT leak into L4
	got, err := NormalizeSocksConfig(cfg)
	if err != nil {
		t.Fatalf("NormalizeSocksConfig: %v", err)
	}
	if got.L4ConnectionTimeout.Duration() != DefaultL4ConnectionTimeout {
		t.Fatalf("zero L4ConnectionTimeout -> %v, want L4 default %v (not the L3 value)", got.L4ConnectionTimeout.Duration(), DefaultL4ConnectionTimeout)
	}
	if got.L4IdleTimeout.Duration() != DefaultL4IdleTimeout {
		t.Fatalf("zero L4IdleTimeout -> %v, want L4 default %v (not the L3 value)", got.L4IdleTimeout.Duration(), DefaultL4IdleTimeout)
	}
	// And the L3 values are preserved untouched (we must not have overwritten them).
	if got.ConnectionTimeout.Duration() != 99*time.Second || got.IdleTimeout.Duration() != 99*time.Minute {
		t.Fatalf("L3 timeouts mutated: connection=%v idle=%v", got.ConnectionTimeout.Duration(), got.IdleTimeout.Duration())
	}

	// In-range L4 values are preserved.
	cfg = base
	cfg.L4ConnectionTimeout = Duration(12 * time.Second)
	cfg.L4IdleTimeout = Duration(45 * time.Second)
	got, err = NormalizeSocksConfig(cfg)
	if err != nil {
		t.Fatalf("NormalizeSocksConfig: %v", err)
	}
	if got.L4ConnectionTimeout.Duration() != 12*time.Second || got.L4IdleTimeout.Duration() != 45*time.Second {
		t.Fatalf("in-range L4 timeouts mutated: connect=%v idle=%v", got.L4ConnectionTimeout.Duration(), got.L4IdleTimeout.Duration())
	}
}
