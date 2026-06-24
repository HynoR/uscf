package config

import (
	"testing"
	"time"
)

// TestDefaultPacketSizing pins the MTU / initial packet size defaults: the
// inner MTU must stay at the safe 1280 floor, while the QUIC initial packet
// size seeds path MTU discovery above the measured Cloudflare floor of 1242.
func TestDefaultPacketSizing(t *testing.T) {
	defaults := GetDefaultSocksConfig()
	if defaults.MTU != 1280 {
		t.Errorf("default MTU = %d, want 1280", defaults.MTU)
	}
	if defaults.InitialPacketSize != 1350 {
		t.Errorf("default InitialPacketSize = %d, want 1350", defaults.InitialPacketSize)
	}
	if defaults.HTTP2 {
		t.Errorf("default HTTP2 = true, want false")
	}
}

// TestNormalizeSocksConfigKeepalivePeriod verifies keepalive_period backfills to its default
// field-wise — a populated socks block that omits it (so the field is 0) must NOT run with
// keepalive disabled, since both the L3 tunnel and the L4 shared connection depend on it.
func TestNormalizeSocksConfigKeepalivePeriod(t *testing.T) {
	if DefaultKeepalivePeriod != 30*time.Second {
		t.Fatalf("DefaultKeepalivePeriod = %v, want 30s", DefaultKeepalivePeriod)
	}
	if GetDefaultSocksConfig().KeepalivePeriod.Duration() != DefaultKeepalivePeriod {
		t.Fatalf("default KeepalivePeriod = %v, want %v", GetDefaultSocksConfig().KeepalivePeriod.Duration(), DefaultKeepalivePeriod)
	}

	// Unset/non-positive backfills to the default (the L3-keepalive-disabled bug this fixes).
	for _, in := range []time.Duration{0, -5 * time.Second} {
		cfg := GetDefaultSocksConfig()
		cfg.KeepalivePeriod = Duration(in)
		got, err := NormalizeSocksConfig(cfg)
		if err != nil {
			t.Fatalf("NormalizeSocksConfig(keepalive_period=%v): %v", in, err)
		}
		if got.KeepalivePeriod.Duration() != DefaultKeepalivePeriod {
			t.Fatalf("keepalive_period=%v -> %v, want default %v", in, got.KeepalivePeriod.Duration(), DefaultKeepalivePeriod)
		}
	}

	// An explicit positive value is preserved.
	cfg := GetDefaultSocksConfig()
	cfg.KeepalivePeriod = Duration(45 * time.Second)
	got, err := NormalizeSocksConfig(cfg)
	if err != nil {
		t.Fatalf("NormalizeSocksConfig: %v", err)
	}
	if got.KeepalivePeriod.Duration() != 45*time.Second {
		t.Fatalf("in-range keepalive_period = %v, want 45s", got.KeepalivePeriod.Duration())
	}
}
