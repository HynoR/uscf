package cmd

import "testing"

func TestMTUWarning(t *testing.T) {
	tests := []struct {
		mtu  int
		warn bool
	}{
		{1000, true},
		{1279, true},
		{1280, false},
		{1350, false},
		{1400, false},
		{1401, true},
		{1500, true},
	}
	for _, tt := range tests {
		msg, warn := mtuWarning(tt.mtu)
		if warn != tt.warn {
			t.Errorf("mtuWarning(%d): warn = %v, want %v", tt.mtu, warn, tt.warn)
		}
		if warn && msg == "" {
			t.Errorf("mtuWarning(%d): empty message with warn=true", tt.mtu)
		}
	}
}
