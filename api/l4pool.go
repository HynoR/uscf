package api

import (
	"context"
	"hash/fnv"
	"net"
)

// maxL4PoolShards caps the shard count the pool will build, independent of the config
// layer's clamp (config.MaxL4PoolSize), so a misconfigured caller can never fan out
// beyond the intended blast-radius/egress trade-off. Kept in sync with that constant.
const maxL4PoolShards = 3

// clientIPKey is the context key under which the SOCKS layer stashes the downstream
// client's source IP. Unexported: producers call WithClientIP, the pool reads it
// internally — so the dial signature (shared by L3/L4/direct) never has to change.
type clientIPKey struct{}

// WithClientIP returns ctx carrying the downstream client's source IP so an L4Pool can
// pin the flow to a shard (one of its independent shared QUIC connections). A nil ip is
// a no-op. Harmless for the L3/direct paths, which ignore it.
func WithClientIP(ctx context.Context, ip net.IP) context.Context {
	if ip == nil {
		return ctx
	}
	return context.WithValue(ctx, clientIPKey{}, ip)
}

// clientIPFromContext recovers the downstream client IP a producer stored with
// WithClientIP, or nil if none was set.
func clientIPFromContext(ctx context.Context) net.IP {
	if ctx == nil {
		return nil
	}
	ip, _ := ctx.Value(clientIPKey{}).(net.IP)
	return ip
}

// L4Pool fans L4 (HTTP/3 CONNECT-stream) flows across a small fixed set of independent
// shared QUIC connections — "shards" — to bound the blast radius of one connection
// stalling. Each shard is a complete, self-healing L4Proxy (its own connection, wedge
// detector and lazy rebuild); the pool only decides WHICH shard a flow uses, by hashing
// the downstream client's source IP. So a wedged shard disrupts only the clients hashed
// to it (~1/N of downstreams), not every downstream device.
//
// This is fault ISOLATION, not capacity scaling: a single shared connection already
// carries thousands of concurrent streams comfortably, so the pool is not about load.
// It is opt-in and off by default — size 1 is exactly the single-connection L4Proxy,
// byte-for-byte, so the proven single-connection path stays the main line.
//
// Sharding is a stable hash, deliberately NOT a sticky/least-loaded table: a given
// client IP always maps to the same shard index, and a shard rebuild keeps that index —
// so a client's egress identity is stable across rebuilds, and distinct clients spread
// over at most N egress identities. Shards build lazily (their L4Proxy dials on first
// use) and only shard 0 is warmed, so an idle or single-client proxy still uses one
// connection and only fans out when distinct clients actually arrive.
type L4Pool struct {
	shards []*L4Proxy
}

// NewL4Pool builds a pool of independent L4Proxy shards from one config. size is clamped
// to [1, maxL4PoolShards]; size 1 yields a single shard identical to NewL4Proxy (the
// shard label stays empty, so its logs are unchanged). Each shard dials the same endpoint
// but is an independent QUIC connection that fails and rebuilds on its own.
func NewL4Pool(cfg L4ProxyConfig, size int) (*L4Pool, error) {
	if size < 1 {
		size = 1
	}
	if size > maxL4PoolShards {
		size = maxL4PoolShards
	}
	shards := make([]*L4Proxy, 0, size)
	for i := 0; i < size; i++ {
		shardCfg := cfg
		if size > 1 {
			shardCfg.Label = shardLabel(i, size)
		}
		p, err := NewL4Proxy(shardCfg)
		if err != nil {
			for _, built := range shards {
				_ = built.Close()
			}
			return nil, err
		}
		shards = append(shards, p)
	}
	return &L4Pool{shards: shards}, nil
}

// shardLabel renders a stable, human-readable shard tag for logs, e.g. "1/3".
func shardLabel(i, size int) string {
	return itoa(i+1) + "/" + itoa(size)
}

// itoa avoids pulling strconv for two tiny single-digit-friendly conversions.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}

// shardFor returns the shard a client IP is pinned to: a stable FNV-1a hash of the IP
// modulo the shard count, so the same client always lands on the same shard (and keeps
// it across that shard's rebuilds). A nil/unknown client IP — and the single-shard pool —
// routes to shard 0.
func (p *L4Pool) shardFor(ip net.IP) *L4Proxy {
	if len(p.shards) == 1 || ip == nil {
		return p.shards[0]
	}
	h := fnv.New32a()
	_, _ = h.Write(ip.To16())
	return p.shards[h.Sum32()%uint32(len(p.shards))]
}

// DialContext routes the flow to the shard pinned to the calling client's source IP
// (read from ctx via WithClientIP) and dials over that shard's shared connection.
func (p *L4Pool) DialContext(ctx context.Context, target string) (net.Conn, error) {
	return p.shardFor(clientIPFromContext(ctx)).DialContext(ctx, target)
}

// Connect warms shard 0 only. The other shards build lazily on first use, so an idle or
// single-client proxy keeps a single connection (a single egress identity) and only fans
// out when distinct clients arrive. Mirrors L4Proxy.Connect for the warm-up call site.
func (p *L4Pool) Connect(ctx context.Context) error {
	return p.shards[0].Connect(ctx)
}

// Close tears down every shard.
func (p *L4Pool) Close() error {
	for _, s := range p.shards {
		_ = s.Close()
	}
	return nil
}

// Stats sums the live open-stream count and the cumulative shared-connection rebuilds
// across all shards, for the periodic observability log.
func (p *L4Pool) Stats() (inFlight int64, reconnects uint64) {
	for _, s := range p.shards {
		f, r := s.Stats()
		inFlight += f
		reconnects += r
	}
	return inFlight, reconnects
}

// Size reports the number of shards (1 = the single-connection main line).
func (p *L4Pool) Size() int { return len(p.shards) }
