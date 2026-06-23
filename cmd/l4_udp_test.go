package cmd

import "testing"

func TestClassifyL4UDP(t *testing.T) {
	cases := []struct {
		name        string
		directMode  bool
		blockUDP443 bool
		addr        string
		want        l4UDPRoute
	}{
		{"block mode rejects", false, false, "1.1.1.1:53", l4UDPReject},
		{"block mode rejects even 443", false, true, "1.1.1.1:443", l4UDPReject},
		{"direct relays", true, false, "1.1.1.1:53", l4UDPDirectOut},
		{"direct relays 443 when not blocking", true, false, "1.1.1.1:443", l4UDPDirectOut},
		{"direct + block443 suppresses 443", true, true, "1.1.1.1:443", l4UDPBlocked443},
		{"direct + block443 allows non-443", true, true, "1.1.1.1:53", l4UDPDirectOut},
		{"direct + block443 with bad addr relays", true, true, "garbage", l4UDPDirectOut},
		{"direct + block443 ipv6 443", true, true, "[2606:4700:4700::1111]:443", l4UDPBlocked443},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyL4UDP(tc.directMode, tc.blockUDP443, tc.addr); got != tc.want {
				t.Fatalf("classifyL4UDP(%v,%v,%q) = %d, want %d", tc.directMode, tc.blockUDP443, tc.addr, got, tc.want)
			}
		})
	}
}
