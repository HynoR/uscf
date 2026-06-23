package cmd

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/HynoR/uscf/config"
)

// errDirectStub marks that dialL4UDP routed to the direct dialer.
var errDirectStub = errors.New("direct-dial-stub")

func stubDirectDial(ctx context.Context, network, addr string) (net.Conn, error) {
	return nil, errDirectStub
}

// TestDialL4UDPRouting asserts the route→dialer mapping in dialL4UDP without a live
// tunnel: a down l3UDPTunnel yields ErrTunnelDisconnected, the direct dialer is hit
// via a sentinel, and block_udp_443 hits return errUDP443Blocked in BOTH direct and
// tunnel modes. This is the dispatch the gated live test would otherwise be the only
// thing to exercise.
func TestDialL4UDPRouting(t *testing.T) {
	// A down tunnel (up defaults false, no-op start) returns ErrTunnelDisconnected.
	tunnel := &l3UDPTunnel{demand: make(chan struct{}, 1), start: func() {}}

	cases := []struct {
		name        string
		mode        string
		addr        string
		blockUDP443 bool
		wantErr     error
	}{
		{"block rejects non-443", config.L4UDPBlock, "1.1.1.1:53", false, errL4UDPUnsupported},
		{"block rejects 443 even with block443", config.L4UDPBlock, "1.1.1.1:443", true, errL4UDPUnsupported},
		{"empty mode rejects", "", "1.1.1.1:53", false, errL4UDPUnsupported},

		{"direct routes to direct dialer", config.L4UDPDirect, "1.1.1.1:53", false, errDirectStub},
		{"direct 443 allowed when not blocking", config.L4UDPDirect, "1.1.1.1:443", false, errDirectStub},
		{"direct 443 blocked", config.L4UDPDirect, "1.1.1.1:443", true, errUDP443Blocked},

		{"tunnel routes to L3 leg (down→sentinel)", config.L4UDPTunnel, "1.1.1.1:53", false, ErrTunnelDisconnected},
		{"tunnel 443 allowed when not blocking (down→sentinel)", config.L4UDPTunnel, "1.1.1.1:443", false, ErrTunnelDisconnected},
		// The key l4_udp=tunnel decision: block_udp_443 is honored, so QUIC-in-QUIC
		// is suppressed and the datagram never reaches the L3 leg.
		{"tunnel 443 blocked", config.L4UDPTunnel, "1.1.1.1:443", true, errUDP443Blocked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := dialL4UDP(context.Background(), "udp", tc.addr, socksTarget{Host: "h", Port: 0}, tc.mode, tc.blockUDP443, stubDirectDial, tunnel)
			if conn != nil {
				t.Fatalf("expected nil conn, got %v", conn)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("dialL4UDP(%q, %q, block443=%v) err = %v, want %v", tc.mode, tc.addr, tc.blockUDP443, err, tc.wantErr)
			}
		})
	}
}

// TestPrepareL4SocksRuntimeTunnelRequiresUDPTunnel guards the nil-deref crash path:
// l4_udp=tunnel with no L3 UDP tunnel must fail fast at setup, not panic on the
// first UDP datagram by dereferencing a nil *l3UDPTunnel in dialL4UDP.
func TestPrepareL4SocksRuntimeTunnelRequiresUDPTunnel(t *testing.T) {
	socks := config.GetDefaultSocksConfig()
	socks.L4 = true
	socks.L4UDP = config.L4UDPTunnel
	socks, err := config.NormalizeSocksConfig(socks)
	if err != nil {
		t.Fatalf("normalize socks: %v", err)
	}

	saved := config.AppConfig.Socks
	t.Cleanup(func() { config.AppConfig.Socks = saved })
	config.AppConfig.Socks = socks

	_, _, err = prepareL4SocksRuntime(nil, nil, 10*time.Second, 30*time.Second)
	if err == nil {
		t.Fatal("expected error when l4_udp=tunnel but udpTunnel is nil")
	}
	if !strings.Contains(err.Error(), "requires an L3 UDP tunnel") {
		t.Fatalf("unexpected error: %v", err)
	}
}
