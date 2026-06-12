package cmd

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/HynoR/uscf/api"
)

type bypassDomainMatcher struct {
	domains map[string]struct{}
}

func newBypassDomainMatcher(domains []string) *bypassDomainMatcher {
	matcher := &bypassDomainMatcher{
		domains: make(map[string]struct{}, len(domains)),
	}

	for _, raw := range domains {
		normalized := normalizeBypassDomain(raw)
		if normalized == "" {
			continue
		}
		matcher.domains[normalized] = struct{}{}
	}

	return matcher
}

func (m *bypassDomainMatcher) Enabled() bool {
	return m != nil && len(m.domains) > 0
}

func (m *bypassDomainMatcher) Match(host string) bool {
	if !m.Enabled() {
		return false
	}

	normalized := normalizeBypassDomain(host)
	if normalized == "" {
		return false
	}

	if _, err := netip.ParseAddr(normalized); err == nil {
		return false
	}

	if _, ok := m.domains[normalized]; ok {
		return true
	}

	for {
		dot := strings.IndexByte(normalized, '.')
		if dot <= 0 || dot >= len(normalized)-1 {
			return false
		}

		normalized = normalized[dot+1:]
		if _, ok := m.domains[normalized]; ok {
			return true
		}
	}
}

func normalizeBypassDomain(domain string) string {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return ""
	}

	if host, _, err := net.SplitHostPort(domain); err == nil {
		domain = host
	}

	domain = strings.Trim(domain, "[]")
	domain = strings.TrimSuffix(domain, ".")
	for strings.HasSuffix(domain, ".") {
		domain = strings.TrimSuffix(domain, ".")
	}

	if strings.Contains(domain, "/") {
		return ""
	}

	return domain
}

type bypassAwareResolver struct {
	matcher        *bypassDomainMatcher
	localResolver  api.NameResolver
	tunnelResolver api.NameResolver
}

func newBypassAwareResolver(matcher *bypassDomainMatcher, localResolver, tunnelResolver api.NameResolver) api.NameResolver {
	return &bypassAwareResolver{
		matcher:        matcher,
		localResolver:  localResolver,
		tunnelResolver: tunnelResolver,
	}
}

func (r *bypassAwareResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	if r.matcher != nil && r.matcher.Match(name) {
		if r.localResolver == nil {
			return ctx, nil, fmt.Errorf("local resolver is not configured")
		}
		return r.localResolver.Resolve(ctx, name)
	}

	if r.tunnelResolver != nil {
		return r.tunnelResolver.Resolve(ctx, name)
	}
	if r.localResolver != nil {
		return r.localResolver.Resolve(ctx, name)
	}

	return ctx, nil, fmt.Errorf("no resolver is configured")
}
