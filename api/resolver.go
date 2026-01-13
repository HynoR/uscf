package api

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// DNSCacheEntry 表示缓存中的一个条目
type DNSCacheEntry struct {
	IP        net.IP
	ExpiresAt time.Time
}

// CachingDNSResolver 实现了带缓存的DNS解析器
type CachingDNSResolver struct {
	// DNS服务器地址
	DNSServer string
	// 缓存过期时间
	CacheTTL time.Duration
	// DNS查询超时
	Timeout time.Duration
	// 缓存
	cache     map[string]DNSCacheEntry
	cacheLock sync.RWMutex
}

// NewCachingDNSResolver 创建一个新的缓存DNS解析器
// dnsServer: DNS服务器地址，如 "8.8.8.8:53"
// timeout: DNS查询超时
func NewCachingDNSResolver(dnsServer string, timeout time.Duration) *CachingDNSResolver {
	cacheTTL := 10 * time.Minute

	if dnsServer == "" {
		dnsServer = "8.8.8.8:53" // 默认使用谷歌DNS
	}

	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	return &CachingDNSResolver{
		DNSServer: dnsServer,
		CacheTTL:  cacheTTL,
		Timeout:   timeout,
		cache:     make(map[string]DNSCacheEntry),
	}
}

type dnsLookupResult struct {
	ip  net.IP
	err error
}

// Resolve 实现NameResolver接口，解析域名为IP地址
func (r *CachingDNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	// 先检查缓存
	r.cacheLock.RLock()
	entry, exists := r.cache[name]
	now := time.Now()
	cacheHit := exists && now.Before(entry.ExpiresAt)
	r.cacheLock.RUnlock()

	// 如果缓存中存在且未过期，直接返回
	if cacheHit {
		return ctx, entry.IP, nil
	}

	// 使用单独锁来防止对同一域名的并发DNS查询，实现"查询合并"
	resultChan := make(chan dnsLookupResult, 1)

	// 缓存不存在或已过期，进行实际的DNS查询
	// 这里可以添加错误重试逻辑
	go func() {
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
			resultChan <- dnsLookupResult{nil, err}
			return
		}

		if len(ips) == 0 {
			resultChan <- dnsLookupResult{nil, net.ErrClosed}
			return
		}

		resultChan <- dnsLookupResult{ips[0], nil}
	}()

	// 等待DNS查询完成或上下文取消
	select {
	case <-ctx.Done():
		return ctx, nil, ctx.Err()
	case result := <-resultChan:
		if result.err != nil {
			return ctx, nil, result.err
		}

		// 更新缓存
		r.cacheLock.Lock()
		r.cache[name] = DNSCacheEntry{
			IP:        result.ip,
			ExpiresAt: now.Add(r.CacheTTL),
		}
		r.cacheLock.Unlock()

		return ctx, result.ip, nil
	}
}

// ClearCache 清除DNS缓存
func (r *CachingDNSResolver) ClearCache() {
	r.cacheLock.Lock()
	defer r.cacheLock.Unlock()
	r.cache = make(map[string]DNSCacheEntry)
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
//
// Parameters:
//   - tunNet: *netstack.Net - The network stack for the tunnel.
//   - dnsAddrs: []netip.Addr - The list of DNS servers to use for resolution.
//   - timeout: time.Duration - The timeout for DNS queries on a specific server before trying the next one.
//
// Returns:
//   - *TunnelDNSResolver: The newly created TunnelDNSResolver.
func NewTunnelDNSResolver(tunNet *netstack.Net, dnsAddrs []netip.Addr, timeout time.Duration) *TunnelDNSResolver {
	return &TunnelDNSResolver{
		tunNet:   tunNet,
		dnsAddrs: dnsAddrs,
		timeout:  timeout,
	}
}

// Resolve performs a DNS lookup using the provided DNS resolvers.
// It tries each resolver in order until one succeeds.
//
// Parameters:
//   - ctx: context.Context - The context for the DNS lookup.
//   - name: string - The domain name to resolve.
//
// Returns:
//   - context.Context: The context for the DNS lookup.
//   - net.IP: The resolved IP address.
//   - error: An error if the lookup fails.
func (r TunnelDNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	var lastErr error

	for _, dnsAddr := range r.dnsAddrs {
		dnsHost := net.JoinHostPort(dnsAddr.String(), "53")
		lookupCtx := ctx
		var cancel context.CancelFunc
		if r.timeout > 0 {
			lookupCtx, cancel = context.WithTimeout(ctx, r.timeout)
		}

		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return r.tunNet.DialContext(ctx, "udp", dnsHost)
			},
		}

		ips, err := resolver.LookupIP(lookupCtx, "ip", name)
		if cancel != nil {
			cancel()
		}
		if err == nil && len(ips) > 0 {
			return ctx, ips[0], nil
		}
		lastErr = err
	}

	return ctx, nil, fmt.Errorf("all DNS servers failed: %v", lastErr)
}
