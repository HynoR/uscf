package cmd

import (
	"context"
	"net"
	"testing"
)

func TestBypassDomainMatcher_MatchExactAndSubdomain(t *testing.T) {
	matcher := newBypassDomainMatcher([]string{"Example.com"})

	if !matcher.Match("example.com") {
		t.Fatalf("expected exact domain to match")
	}
	if !matcher.Match("www.example.com") {
		t.Fatalf("expected subdomain to match")
	}
	if !matcher.Match("WWW.EXAMPLE.COM.") {
		t.Fatalf("expected normalized subdomain to match")
	}
	if matcher.Match("badexample.com") {
		t.Fatalf("unexpected suffix match")
	}
}

func TestBypassDomainMatcher_NormalizationAndDedup(t *testing.T) {
	matcher := newBypassDomainMatcher([]string{" example.com ", "EXAMPLE.COM.", "", "   ", "sub.example.com"})

	if !matcher.Enabled() {
		t.Fatalf("expected matcher to be enabled")
	}
	if got := len(matcher.domains); got != 2 {
		t.Fatalf("expected deduped domain count to be 2, got %d", got)
	}
	if !matcher.Match("a.sub.example.com") {
		t.Fatalf("expected nested subdomain to match")
	}
}

func TestBypassDomainMatcher_NoMatchForIPOrUnrelatedDomain(t *testing.T) {
	matcher := newBypassDomainMatcher([]string{"example.com"})

	if matcher.Match("1.1.1.1") {
		t.Fatalf("expected ipv4 not to match bypass domain")
	}
	if matcher.Match("2001:db8::1") {
		t.Fatalf("expected ipv6 not to match bypass domain")
	}
	if matcher.Match("google.com") {
		t.Fatalf("expected unrelated domain not to match")
	}
}

type fakeResolver struct {
	calls int
	ip    net.IP
	err   error
}

func (r *fakeResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	r.calls++
	return ctx, r.ip, r.err
}

func TestBypassAwareResolver_SelectsLocalForMatchedDomain(t *testing.T) {
	matcher := newBypassDomainMatcher([]string{"example.com"})
	local := &fakeResolver{ip: net.IPv4(1, 1, 1, 1)}
	tunnel := &fakeResolver{ip: net.IPv4(8, 8, 8, 8)}
	resolver := newBypassAwareResolver(matcher, local, tunnel)

	_, ip, err := resolver.Resolve(context.Background(), "www.example.com")
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if !ip.Equal(net.IPv4(1, 1, 1, 1)) {
		t.Fatalf("expected local resolver ip, got %v", ip)
	}
	if local.calls != 1 {
		t.Fatalf("expected local resolver calls=1, got %d", local.calls)
	}
	if tunnel.calls != 0 {
		t.Fatalf("expected tunnel resolver calls=0, got %d", tunnel.calls)
	}
}
