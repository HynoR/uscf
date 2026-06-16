package wireguard

import "testing"

func TestNormalizeInterfaceAddr(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		want  string
		isErr bool
	}{
		{"bare ipv4 gets /32", "172.16.0.2", "172.16.0.2/32", false},
		{"bare ipv6 gets /128", "2606:4700:110::2", "2606:4700:110::2/128", false},
		{"team cgnat bare", "100.96.0.5", "100.96.0.5/32", false},
		{"explicit /32 preserved", "172.16.0.2/32", "172.16.0.2/32", false},
		{"explicit /24 keeps host bits", "172.16.0.2/24", "172.16.0.2/24", false},
		{"empty", "", "", true},
		{"garbage", "not-an-ip", "", true},
		{"double suffix rejected", "172.16.0.2/32/32", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeInterfaceAddr(tc.in)
			if tc.isErr {
				if err == nil {
					t.Fatalf("expected error for %q, got %v", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.String() != tc.want {
				t.Fatalf("NormalizeInterfaceAddr(%q) = %q, want %q", tc.in, got.String(), tc.want)
			}
		})
	}
}

func TestValidatePeer(t *testing.T) {
	validKey := mustPubKeyB64(t)

	cases := []struct {
		name     string
		key      string
		endpoint string
		isErr    bool
	}{
		{"valid", validKey, "162.159.192.1:2408", false},
		{"valid hostname endpoint", validKey, "engage.cloudflareclient.com:2408", false},
		{"empty key", "", "1.2.3.4:2408", true},
		{"bad base64 key", "!!!not base64!!!", "1.2.3.4:2408", true},
		{"short key", "AAAA", "1.2.3.4:2408", true},
		{"endpoint without port", validKey, "1.2.3.4", true},
		{"endpoint bad port", validKey, "1.2.3.4:notaport", true},
		{"endpoint port out of range", validKey, "1.2.3.4:70000", true},
		{"empty endpoint", validKey, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePeer(tc.key, tc.endpoint)
			if tc.isErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.isErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func mustPubKeyB64(t *testing.T) string {
	t.Helper()
	priv, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey() error = %v", err)
	}
	return priv.Public().String()
}
