package cmd

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/HynoR/uscf/config"
	"github.com/HynoR/uscf/models"
)

func TestParseWGHealth(t *testing.T) {
	payload := strings.Join([]string{
		"private_key=00",
		"public_key=ff",
		"endpoint=1.2.3.4:2408",
		"last_handshake_time_sec=1700000000",
		"last_handshake_time_nsec=12345",
		"tx_bytes=4096",
		"rx_bytes=8192",
		"persistent_keepalive_interval=25",
		"",
	}, "\n")

	h := parseWGHealth(payload)
	if h.tx != 4096 {
		t.Fatalf("tx = %d, want 4096", h.tx)
	}
	if h.rx != 8192 {
		t.Fatalf("rx = %d, want 8192", h.rx)
	}
	if h.handshakeSec != 1700000000 {
		t.Fatalf("handshakeSec = %d, want 1700000000", h.handshakeSec)
	}
}

func TestWGWedged(t *testing.T) {
	const window = 60 * time.Second
	cases := []struct {
		name          string
		sent          bool
		sinceProgress time.Duration
		want          bool
	}{
		{"idle no tx never wedges", false, 5 * time.Minute, false},
		{"sending within window", true, 30 * time.Second, false},
		{"sending past window", true, 75 * time.Second, true},
		{"sending at exact window", true, window, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := wgWedged(tc.sent, tc.sinceProgress, window); got != tc.want {
				t.Fatalf("wgWedged(%v, %v, %v) = %v, want %v", tc.sent, tc.sinceProgress, window, got, tc.want)
			}
		})
	}
}

func TestNextWGBackoff(t *testing.T) {
	if got := nextWGBackoff(2 * time.Second); got != 4*time.Second {
		t.Fatalf("nextWGBackoff(2s) = %v, want 4s", got)
	}
	if got := nextWGBackoff(4 * time.Minute); got != wgMaxRecoveryBackoff {
		t.Fatalf("nextWGBackoff(4m) = %v, want %v (cap)", got, wgMaxRecoveryBackoff)
	}
	if got := nextWGBackoff(wgMaxRecoveryBackoff); got != wgMaxRecoveryBackoff {
		t.Fatalf("nextWGBackoff(cap) = %v, want %v", got, wgMaxRecoveryBackoff)
	}
}

func TestRepointWireGuardEndpointSurfacesFetchError(t *testing.T) {
	old := wgGetSourceDeviceFunc
	t.Cleanup(func() { wgGetSourceDeviceFunc = old })

	wgGetSourceDeviceFunc = func(deviceID, accessToken string) (models.AccountData, error) {
		return models.AccountData{}, errors.New("boom")
	}

	// The source-device fetch fails first, so the nil device is never touched.
	err := repointWireGuardEndpoint(nil, config.WGAccount{DeviceID: "d", AccessToken: "t"}, nil)
	if err == nil || !strings.Contains(err.Error(), "fetch source device") {
		t.Fatalf("want fetch source device error, got %v", err)
	}
}
