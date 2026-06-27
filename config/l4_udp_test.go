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

// TestNormalizeSocksConfigL4PoolSize pins the L4 shard-count clamp: the default is the
// single-connection main line (1), a non-positive size falls back to 1, and an oversized
// one is capped at MaxL4PoolSize — so a misconfig can never fan out past the intended
// blast-radius/egress trade-off.
func TestNormalizeSocksConfigL4PoolSize(t *testing.T) {
	if got := GetDefaultSocksConfig().L4PoolSize; got != DefaultL4PoolSize {
		t.Fatalf("default L4PoolSize = %d, want %d", got, DefaultL4PoolSize)
	}
	if DefaultL4PoolSize != 1 {
		t.Fatalf("DefaultL4PoolSize = %d, want 1 (single-connection main line)", DefaultL4PoolSize)
	}

	base := GetDefaultSocksConfig()
	for _, tc := range []struct{ in, want int }{
		{-5, DefaultL4PoolSize}, {0, DefaultL4PoolSize}, {1, 1}, {2, 2},
		{MaxL4PoolSize, MaxL4PoolSize}, {MaxL4PoolSize + 1, MaxL4PoolSize}, {99, MaxL4PoolSize},
	} {
		cfg := base
		cfg.L4PoolSize = tc.in
		got, err := NormalizeSocksConfig(cfg)
		if err != nil {
			t.Fatalf("NormalizeSocksConfig(l4_pool_size=%d): %v", tc.in, err)
		}
		if got.L4PoolSize != tc.want {
			t.Fatalf("NormalizeSocksConfig(l4_pool_size=%d).L4PoolSize = %d, want %d", tc.in, got.L4PoolSize, tc.want)
		}
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

	// In-range (and <= the 60s idle default, so the half-open<=idle clamp leaves it alone).
	cfg.L4HalfOpenTimeout = Duration(45 * time.Second)
	got, err = NormalizeSocksConfig(cfg)
	if err != nil {
		t.Fatalf("NormalizeSocksConfig: %v", err)
	}
	if got.L4HalfOpenTimeout.Duration() != 45*time.Second {
		t.Fatalf("in-range L4HalfOpenTimeout = %v, want 45s", got.L4HalfOpenTimeout.Duration())
	}
}

// TestNormalizeSocksConfigL4HalfOpenClampedToIdle proves the half-open reaper stays a
// SHORTENER: a half-open timeout larger than the idle timeout is clamped down so it can
// never extend the surviving direction's idle past a fully-open flow.
func TestNormalizeSocksConfigL4HalfOpenClampedToIdle(t *testing.T) {
	base := GetDefaultSocksConfig()
	cfg := base
	cfg.L4IdleTimeout = Duration(60 * time.Second)
	cfg.L4HalfOpenTimeout = Duration(120 * time.Second) // larger than idle -> must clamp
	got, err := NormalizeSocksConfig(cfg)
	if err != nil {
		t.Fatalf("NormalizeSocksConfig: %v", err)
	}
	if got.L4HalfOpenTimeout.Duration() != 60*time.Second {
		t.Fatalf("half-open %v exceeding idle 60s -> %v, want clamped to 60s", 120*time.Second, got.L4HalfOpenTimeout.Duration())
	}

	// Half-open <= idle is preserved untouched.
	cfg = base
	cfg.L4IdleTimeout = Duration(60 * time.Second)
	cfg.L4HalfOpenTimeout = Duration(20 * time.Second)
	got, err = NormalizeSocksConfig(cfg)
	if err != nil {
		t.Fatalf("NormalizeSocksConfig: %v", err)
	}
	if got.L4HalfOpenTimeout.Duration() != 20*time.Second {
		t.Fatalf("half-open 20s below idle 60s -> %v, want preserved 20s", got.L4HalfOpenTimeout.Duration())
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
