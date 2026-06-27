package api

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
)

func newTestPool(t *testing.T, size int) *L4Pool {
	t.Helper()
	p, err := NewL4Pool(L4ProxyConfig{
		TLSConfig: &tls.Config{},
		Endpoint:  &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 443},
	}, size)
	if err != nil {
		t.Fatalf("NewL4Pool(size=%d): %v", size, err)
	}
	return p
}

// TestL4PoolSizeClamp proves the shard count is clamped to [1, maxL4PoolShards]: a
// non-positive size falls back to the single-connection main line, and an oversized one
// is capped — a misconfig can never fan out past the intended trade-off.
func TestL4PoolSizeClamp(t *testing.T) {
	for _, tc := range []struct{ in, want int }{
		{-1, 1}, {0, 1}, {1, 1}, {2, 2}, {3, 3}, {4, 3}, {100, 3},
	} {
		p := newTestPool(t, tc.in)
		if p.Size() != tc.want {
			t.Fatalf("NewL4Pool(size=%d).Size() = %d, want %d", tc.in, p.Size(), tc.want)
		}
	}
}

// TestL4PoolSingleShardLabelEmpty verifies a size-1 pool leaves the shard label empty, so
// its logs are byte-for-byte the single-connection main line; a multi-shard pool tags each.
func TestL4PoolSingleShardLabelEmpty(t *testing.T) {
	if got := newTestPool(t, 1).shards[0].label; got != "" {
		t.Fatalf("size-1 shard label = %q, want empty (unchanged single-connection logs)", got)
	}
	p := newTestPool(t, 3)
	for i, want := range []string{"1/3", "2/3", "3/3"} {
		if got := p.shards[i].label; got != want {
			t.Fatalf("shard[%d].label = %q, want %q", i, got, want)
		}
	}
}

// TestL4PoolSingleShardRoutesAllToZero: with one shard, every client IP (and an unknown
// one) routes to shard 0 — identical to the single-connection path.
func TestL4PoolSingleShardRoutesAllToZero(t *testing.T) {
	p := newTestPool(t, 1)
	for _, ip := range []net.IP{nil, net.IPv4(10, 0, 0, 1), net.ParseIP("2606:4700::1")} {
		if p.shardFor(ip) != p.shards[0] {
			t.Fatalf("single-shard pool routed %v off shard 0", ip)
		}
	}
}

// TestL4PoolShardingStableAndSpreads proves the two properties the isolation guarantee
// rests on: a given client IP always maps to the SAME shard (stable across calls, so its
// egress identity is stable), and a population of distinct client IPs spreads across more
// than one shard (so a wedged shard cannot take down every downstream).
func TestL4PoolShardingStableAndSpreads(t *testing.T) {
	p := newTestPool(t, 3)

	// Stability: repeated lookups for the same IP return the same shard.
	ip := net.IPv4(192, 168, 1, 42)
	first := p.shardFor(ip)
	for i := 0; i < 50; i++ {
		if p.shardFor(ip) != first {
			t.Fatal("shardFor must be stable for a fixed client IP")
		}
	}

	// Spread: 30 distinct downstream IPs land on more than one shard.
	seen := map[*L4Proxy]bool{}
	for i := 1; i <= 30; i++ {
		seen[p.shardFor(net.IPv4(192, 168, 1, byte(i)))] = true
	}
	if len(seen) < 2 {
		t.Fatalf("30 distinct client IPs mapped to only %d shard(s); sharding does not isolate", len(seen))
	}

	// A nil/unknown client IP is routed (to shard 0), never a panic.
	if p.shardFor(nil) != p.shards[0] {
		t.Fatal("nil client IP must route to shard 0")
	}
}

// TestWithClientIPRoundTrip checks the context plumbing the SOCKS layer relies on.
func TestWithClientIPRoundTrip(t *testing.T) {
	ip := net.IPv4(203, 0, 113, 7)
	got := clientIPFromContext(WithClientIP(context.Background(), ip))
	if !got.Equal(ip) {
		t.Fatalf("clientIPFromContext = %v, want %v", got, ip)
	}
	// nil ip is a no-op: nothing stored, nothing recovered.
	if recovered := clientIPFromContext(WithClientIP(context.Background(), nil)); recovered != nil {
		t.Fatalf("WithClientIP(nil) stored %v, want no-op", recovered)
	}
	if recovered := clientIPFromContext(context.Background()); recovered != nil {
		t.Fatalf("clientIPFromContext(bare ctx) = %v, want nil", recovered)
	}
}

// TestL4PoolDialContextRoutesByClientIP proves DialContext picks the shard for the ctx's
// client IP: two IPs that hash to different shards reach different shards. Verified at the
// routing layer (shardFor) since a real dial needs a live endpoint.
func TestL4PoolDialContextRoutesByClientIP(t *testing.T) {
	p := newTestPool(t, 3)
	// Find two IPs that map to distinct shards, then assert the ctx-driven route matches.
	a := net.IPv4(198, 51, 100, 1)
	var b net.IP
	for i := 2; i <= 254; i++ {
		cand := net.IPv4(198, 51, 100, byte(i))
		if p.shardFor(cand) != p.shardFor(a) {
			b = cand
			break
		}
	}
	if b == nil {
		t.Skip("no two IPs in the probe range hashed to different shards")
	}
	if p.shardFor(clientIPFromContext(WithClientIP(context.Background(), a))) != p.shardFor(a) {
		t.Fatal("ctx-carried IP a must route to a's shard")
	}
	if p.shardFor(clientIPFromContext(WithClientIP(context.Background(), a))) ==
		p.shardFor(clientIPFromContext(WithClientIP(context.Background(), b))) {
		t.Fatal("IPs on different shards must not collapse to one when routed via ctx")
	}
}

func TestL4PoolCloseAndStatsSafe(t *testing.T) {
	p := newTestPool(t, 3)
	if f, r := p.Stats(); f != 0 || r != 0 {
		t.Fatalf("fresh pool Stats() = (%d,%d), want (0,0)", f, r)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestItoa(t *testing.T) {
	for _, tc := range []struct {
		in   int
		want string
	}{{0, "0"}, {1, "1"}, {9, "9"}, {10, "10"}, {42, "42"}, {100, "100"}} {
		if got := itoa(tc.in); got != tc.want {
			t.Fatalf("itoa(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
