package cmd

import (
	"net"
	"strconv"
	"strings"

	"github.com/things-go/go-socks5"

	"github.com/HynoR/uscf/config"
)

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

func selectTCPRoute(policy *routePolicy, network, addr string, request *socks5.Request) bool {
	if policy == nil || !strings.HasPrefix(network, "tcp") {
		return true
	}

	host, port, ok := extractRequestTarget(addr, request)
	if !ok {
		return true
	}

	return policy.ShouldUseTunTCP(host, port)
}

func extractRequestTarget(addr string, request *socks5.Request) (string, int, bool) {
	if request != nil && request.RawDestAddr != nil {
		host := strings.TrimSpace(request.RawDestAddr.FQDN)
		if host == "" && request.RawDestAddr.IP != nil {
			host = request.RawDestAddr.IP.String()
		}
		if host != "" && request.RawDestAddr.Port > 0 {
			return host, request.RawDestAddr.Port, true
		}
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return "", 0, false
	}

	parsedPort, err := strconv.Atoi(port)
	if err != nil {
		return "", 0, false
	}

	return host, parsedPort, true
}
