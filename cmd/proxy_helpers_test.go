package cmd

import "testing"

func TestParseEndpointHost(t *testing.T) {
	testCases := []struct {
		name      string
		input     string
		want      string
		shouldErr bool
	}{
		{
			name:  "ipv4 with port",
			input: "162.159.198.1:0",
			want:  "162.159.198.1",
		},
		{
			name:  "ipv6 with bracket and port",
			input: "[2606:4700:103::1]:0",
			want:  "2606:4700:103::1",
		},
		{
			name:  "bare ipv6",
			input: "2606:4700:103::1",
			want:  "2606:4700:103::1",
		},
		{
			name:      "invalid endpoint",
			input:     "invalid-endpoint",
			shouldErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseEndpointHost(tc.input)
			if tc.shouldErr {
				if err == nil {
					t.Fatalf("expected error, got nil (result=%q)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("parseEndpointHost(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestNormalizeDNSServerAddress(t *testing.T) {
	testCases := []struct {
		name      string
		input     string
		want      string
		shouldErr bool
	}{
		{
			name:  "ipv4 without port",
			input: "1.1.1.1",
			want:  "1.1.1.1:53",
		},
		{
			name:  "ipv4 with port",
			input: "1.1.1.1:5353",
			want:  "1.1.1.1:5353",
		},
		{
			name:  "ipv6 without port",
			input: "2606:4700:4700::1111",
			want:  "[2606:4700:4700::1111]:53",
		},
		{
			name:  "ipv6 with port",
			input: "[2606:4700:4700::1111]:5353",
			want:  "[2606:4700:4700::1111]:5353",
		},
		{
			name:  "hostname without port",
			input: "dns.google",
			want:  "dns.google:53",
		},
		{
			name:      "invalid port",
			input:     "1.1.1.1:abc",
			shouldErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeDNSServerAddress(tc.input)
			if tc.shouldErr {
				if err == nil {
					t.Fatalf("expected error, got nil (result=%q)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("normalizeDNSServerAddress(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
