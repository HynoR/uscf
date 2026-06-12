package cmd

import (
	"strings"

	"github.com/HynoR/uscf/config"
)

// socksTarget is a library-agnostic SOCKS5 request destination used for routing
// decisions. Host is the original requested host (domain or IP literal), before
// DNS resolution, so domain-based rules such as bypass_domain keep working.
type socksTarget struct {
	Host string
	Port int
}

type routePolicy struct {
	bypassMatcher    *bypassDomainMatcher
	proxyTCPPorts    map[int]struct{}
	proxyTCPPortList []int
}

func newRoutePolicy(bypassDomains []string, proxyTCPPorts []int) (*routePolicy, error) {
	normalizedPorts, err := config.NormalizeSocksConfig(config.SocksConfig{
		BypassDomain: bypassDomains,
		ProxyTCPPort: proxyTCPPorts,
	})
	if err != nil {
		return nil, err
	}

	policy := &routePolicy{
		bypassMatcher:    newBypassDomainMatcher(normalizedPorts.BypassDomain),
		proxyTCPPorts:    make(map[int]struct{}, len(normalizedPorts.ProxyTCPPort)),
		proxyTCPPortList: append([]int(nil), normalizedPorts.ProxyTCPPort...),
	}
	for _, port := range normalizedPorts.ProxyTCPPort {
		policy.proxyTCPPorts[port] = struct{}{}
	}

	return policy, nil
}

func (p *routePolicy) ProxyTCPPortsEnabled() bool {
	return p != nil && len(p.proxyTCPPorts) > 0
}

func (p *routePolicy) ShouldUseTunTCP(host string, port int) bool {
	if p == nil {
		return true
	}
	if p.ProxyTCPPortsEnabled() {
		_, ok := p.proxyTCPPorts[port]
		return ok
	}
	return p.bypassMatcher == nil || !p.bypassMatcher.Match(host)
}

func selectTCPRoute(policy *routePolicy, network string, target socksTarget) bool {
	if policy == nil || !strings.HasPrefix(network, "tcp") {
		return true
	}

	if strings.TrimSpace(target.Host) == "" || target.Port <= 0 {
		return true
	}

	return policy.ShouldUseTunTCP(target.Host, target.Port)
}
