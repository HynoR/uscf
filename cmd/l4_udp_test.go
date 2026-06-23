package cmd

import (
	"testing"

	"github.com/HynoR/uscf/config"
)

func TestClassifyL4UDP(t *testing.T) {
	cases := []struct {
		name        string
		mode        string
		blockUDP443 bool
		addr        string
		want        l4UDPRoute
	}{
		{"block mode rejects", config.L4UDPBlock, false, "1.1.1.1:53", l4UDPReject},
		{"block mode rejects even 443", config.L4UDPBlock, true, "1.1.1.1:443", l4UDPReject},
		{"empty mode rejects", "", false, "1.1.1.1:53", l4UDPReject},

		{"direct relays", config.L4UDPDirect, false, "1.1.1.1:53", l4UDPDirectOut},
		{"direct relays 443 when not blocking", config.L4UDPDirect, false, "1.1.1.1:443", l4UDPDirectOut},
		{"direct + block443 suppresses 443", config.L4UDPDirect, true, "1.1.1.1:443", l4UDPBlocked443},
		{"direct + block443 allows non-443", config.L4UDPDirect, true, "1.1.1.1:53", l4UDPDirectOut},
		{"direct + block443 with bad addr relays", config.L4UDPDirect, true, "garbage", l4UDPDirectOut},
		{"direct + block443 ipv6 443", config.L4UDPDirect, true, "[2606:4700:4700::1111]:443", l4UDPBlocked443},

		{"tunnel relays", config.L4UDPTunnel, false, "1.1.1.1:53", l4UDPTunnelOut},
		{"tunnel relays 443 when not blocking", config.L4UDPTunnel, false, "1.1.1.1:443", l4UDPTunnelOut},
		// block_udp_443 is honored in tunnel mode too: QUIC-in-QUIC over the L3 leg
		// would throttle bandwidth, so UDP/443 is suppressed to force a TCP fallback.
		{"tunnel + block443 suppresses 443", config.L4UDPTunnel, true, "1.1.1.1:443", l4UDPBlocked443},
		{"tunnel + block443 allows non-443", config.L4UDPTunnel, true, "1.1.1.1:53", l4UDPTunnelOut},
		{"tunnel + block443 ipv6 443", config.L4UDPTunnel, true, "[2606:4700:4700::1111]:443", l4UDPBlocked443},
		{"tunnel + block443 bad addr relays", config.L4UDPTunnel, true, "garbage", l4UDPTunnelOut},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyL4UDP(tc.mode, tc.blockUDP443, tc.addr); got != tc.want {
				t.Fatalf("classifyL4UDP(%q,%v,%q) = %d, want %d", tc.mode, tc.blockUDP443, tc.addr, got, tc.want)
			}
		})
	}
}
