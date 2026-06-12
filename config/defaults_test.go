package config

import "testing"

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
}
