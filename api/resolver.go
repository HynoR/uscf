package api

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/HynoR/uscf/internal/netstack"
	"golang.org/x/sync/singleflight"
)

// NameResolver matches the socks5.NameResolver interface without importing go-socks5.
type NameResolver interface {
	Resolve(ctx context.Context, name string) (context.Context, net.IP, error)
}

// cacheEntry represents a single DNS cache entry.
type cacheEntry struct {
	ip        net.IP
	expiresAt time.Time
	negative  bool
	err       error
}

// CachingResolver wraps any NameResolver with TTL-based caching,
// singleflight request deduplication, bounded size, and negative caching.
type CachingResolver struct {
	inner       NameResolver
	ttl         time.Duration
	negativeTTL time.Duration
	maxEntries  int

	mu    sync.RWMutex
	cache map[string]*cacheEntry
	sf    singleflight.Group
}

// NewCachingResolver creates a new CachingResolver.
//
// Parameters:
//   - inner: the upstream resolver to wrap.
//   - ttl: positive cache TTL; zero defaults to 10 minutes.
//   - negativeTTL: negative cache TTL; zero defaults to 5 seconds.
//   - maxEntries: max number of cached entries; zero defaults to 4096.
func NewCachingResolver(inner NameResolver, ttl, negativeTTL time.Duration, maxEntries int) *CachingResolver {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if negativeTTL <= 0 {
		negativeTTL = 5 * time.Second
	}
	if maxEntries <= 0 {
		maxEntries = 4096
	}
	return &CachingResolver{
		inner:       inner,
		ttl:         ttl,
		negativeTTL: negativeTTL,
		maxEntries:  maxEntries,
		cache:       make(map[string]*cacheEntry),
	}
}

// Resolve implements NameResolver with caching and singleflight deduplication.
func (r *CachingResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	// 1. Fast-path read from cache.
	r.mu.RLock()
	entry, ok := r.cache[name]
	r.mu.RUnlock()
	if ok && time.Now().Before(entry.expiresAt) {
		if entry.negative {
			return ctx, nil, entry.err
		}
		return ctx, entry.ip, nil
	}

	// 2. singleflight: only one upstream query per name at a time.
	v, err, _ := r.sf.Do(name, func() (interface{}, error) {
		_, ip, resolveErr := r.inner.Resolve(ctx, name)
		now := time.Now()

		r.mu.Lock()
		defer r.mu.Unlock()

		if resolveErr != nil {
			r.cache[name] = &cacheEntry{
				expiresAt: now.Add(r.negativeTTL),
				negative:  true,
				err:       resolveErr,
			}
			return nil, resolveErr
		}

		if len(r.cache) >= r.maxEntries {
			r.evictLocked()
		}
		r.cache[name] = &cacheEntry{
			ip:        ip,
			expiresAt: now.Add(r.ttl),
		}
		return ip, nil
	})

	if err != nil {
		return ctx, nil, err
	}
	return ctx, v.(net.IP), nil
}

// evictLocked removes ~10% of entries, preferring expired ones.
// Caller must hold mu.
func (r *CachingResolver) evictLocked() {
	target := r.maxEntries / 10
	if target < 1 {
		target = 1
	}
	now := time.Now()
	for k, v := range r.cache {
		if now.After(v.expiresAt) {
			delete(r.cache, k)
			target--
			if target <= 0 {
				return
			}
		}
	}
	// If still not enough, evict arbitrary entries.
	for k := range r.cache {
		delete(r.cache, k)
		target--
		if target <= 0 {
			return
		}
	}
}

// ClearCache clears all cached entries.
func (r *CachingResolver) ClearCache() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache = make(map[string]*cacheEntry)
}

// CachingDNSResolver is kept for backward compatibility.
// It wraps a local net.Resolver with CachingResolver.
type CachingDNSResolver struct {
	*CachingResolver
}

// NewCachingDNSResolver creates a new caching DNS resolver using a local DNS server.
// dnsServer: DNS server address, e.g. "8.8.8.8:53"
// timeout: DNS query timeout
func NewCachingDNSResolver(dnsServer string, timeout time.Duration) *CachingDNSResolver {
	if dnsServer == "" {
		dnsServer = "8.8.8.8:53"
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	inner := &LocalDNSResolver{
		DNSServer: dnsServer,
		Timeout:   timeout,
	}
	return &CachingDNSResolver{
		CachingResolver: NewCachingResolver(inner, 10*time.Minute, 5*time.Second, 4096),
	}
}

// LocalDNSResolver performs DNS resolution against a specific UDP DNS server.
type LocalDNSResolver struct {
	DNSServer string
	Timeout   time.Duration
}

func (r *LocalDNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	lookupCtx := ctx
	if r.Timeout > 0 {
		var cancel context.CancelFunc
		lookupCtx, cancel = context.WithTimeout(ctx, r.Timeout)
		defer cancel()
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: r.Timeout}
			return d.DialContext(ctx, "udp", r.DNSServer)
		},
	}

	ips, err := resolver.LookupIP(lookupCtx, "ip", name)
	if err != nil {
		return ctx, nil, err
	}
	if len(ips) == 0 {
		return ctx, nil, net.ErrClosed
	}
	return ctx, ips[0], nil
}

// TunnelDNSResolver implements a DNS resolver that uses the provided DNS servers inside a MASQUE tunnel.
type TunnelDNSResolver struct {
	// tunNet is the network stack for the tunnel you want to use for DNS resolution.
	tunNet *netstack.Net
	// dnsAddrs is the list of DNS servers to use for resolution.
	dnsAddrs []netip.Addr
	// timeout is the timeout for DNS queries on a specific server before trying the next one.
	timeout time.Duration
}

// NewTunnelDNSResolver creates a new TunnelDNSResolver.
func NewTunnelDNSResolver(tunNet *netstack.Net, dnsAddrs []netip.Addr, timeout time.Duration) *TunnelDNSResolver {
	return &TunnelDNSResolver{
		tunNet:   tunNet,
		dnsAddrs: dnsAddrs,
		timeout:  timeout,
	}
}

// Resolve performs a DNS lookup using the provided DNS resolvers.
// It queries all resolvers concurrently and returns the first successful result.
func (r TunnelDNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	if len(r.dnsAddrs) == 0 {
		return ctx, nil, fmt.Errorf("no DNS servers configured")
	}

	lookupCtx := ctx
	var cancel context.CancelFunc
	if r.timeout > 0 {
		lookupCtx, cancel = context.WithTimeout(ctx, r.timeout)
		defer cancel()
	}

	type result struct {
		ip  net.IP
		err error
	}

	resultCh := make(chan result, 1)
	var wg sync.WaitGroup

	for _, dnsAddr := range r.dnsAddrs {
		dnsHost := net.JoinHostPort(dnsAddr.String(), "53")
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			resolver := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					return r.tunNet.DialContext(ctx, "udp", host)
				},
			}
			ips, err := resolver.LookupIP(lookupCtx, "ip", name)
			if err == nil && len(ips) > 0 {
				select {
				case resultCh <- result{ip: ips[0]}:
				default:
				}
			}
		}(dnsHost)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	select {
	case <-lookupCtx.Done():
		return ctx, nil, lookupCtx.Err()
	case res := <-resultCh:
		if res.ip != nil {
			return ctx, res.ip, nil
		}
		// Channel closed with no success.
		return ctx, nil, fmt.Errorf("all DNS servers failed for %s", name)
	}
}
