package cmd

import (
	"testing"
)

func TestRoutePolicy_BypassDomainUsesDirectWhenNoProxyTCPPort(t *testing.T) {
	policy, err := newRoutePolicy([]string{"example.com"}, nil)
	if err != nil {
		t.Fatalf("newRoutePolicy() error = %v", err)
	}

	if policy.ShouldUseTunTCP("www.example.com", 443) {
		t.Fatalf("expected matched bypass domain to use direct path")
	}
	if !policy.ShouldUseTunTCP("www.google.com", 443) {
		t.Fatalf("expected non-matching domain to use tun path")
	}
}

func TestRoutePolicy_ProxyTCPPortUsesWhitelist(t *testing.T) {
	policy, err := newRoutePolicy([]string{"example.com"}, []int{80, 443})
	if err != nil {
		t.Fatalf("newRoutePolicy() error = %v", err)
	}

	if !policy.ShouldUseTunTCP("www.example.com", 80) {
		t.Fatalf("expected whitelisted port to use tun path")
	}
	if policy.ShouldUseTunTCP("www.example.com", 992) {
		t.Fatalf("expected non-whitelisted port to use direct path")
	}
}

func TestRoutePolicy_RejectsInvalidProxyTCPPort(t *testing.T) {
	if _, err := newRoutePolicy(nil, []int{0}); err == nil {
		t.Fatalf("expected invalid proxy_tcp_port to be rejected")
	}
}

func TestRoutePolicy_DeduplicatesProxyTCPPort(t *testing.T) {
	policy, err := newRoutePolicy(nil, []int{443, 80, 443})
	if err != nil {
		t.Fatalf("newRoutePolicy() error = %v", err)
	}

	if got := len(policy.proxyTCPPorts); got != 2 {
		t.Fatalf("proxyTCPPorts count = %d, want 2", got)
	}
}

func TestSelectTCPRoute_PrefersRequestPort(t *testing.T) {
	policy, err := newRoutePolicy(nil, []int{80, 443})
	if err != nil {
		t.Fatalf("newRoutePolicy() error = %v", err)
	}

	target := socksTarget{Host: "example.com", Port: 992}

	useTun := selectTCPRoute(policy, "tcp", target)
	if useTun {
		t.Fatalf("expected request destination port to control routing and use direct path")
	}
}

func TestSelectTCPRoute_UDPIsUnaffected(t *testing.T) {
	policy, err := newRoutePolicy(nil, []int{80, 443})
	if err != nil {
		t.Fatalf("newRoutePolicy() error = %v", err)
	}

	target := socksTarget{Host: "example.com", Port: 992}

	useTun := selectTCPRoute(policy, "udp", target)
	if !useTun {
		t.Fatalf("expected udp traffic to remain on tun path")
	}
}
