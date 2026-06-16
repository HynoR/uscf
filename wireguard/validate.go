package wireguard

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// NormalizeInterfaceAddr parses a WireGuard interface address that may or may
// not already carry a prefix length and returns a canonical netip.Prefix.
//
// A bare address gets its family's full-length prefix (/32 for IPv4, /128 for
// IPv6), so callers never blindly append a suffix and produce a doubled
// "1.2.3.4/32/32" (deep-dive item J). An address that already carries a prefix
// is returned verbatim (host bits preserved — interface addresses are not
// masked to their network).
func NormalizeInterfaceAddr(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, fmt.Errorf("empty interface address")
	}
	if strings.Contains(s, "/") {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("parse interface prefix %q: %w", s, err)
		}
		return prefix, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse interface address %q: %w", s, err)
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// ValidatePeer fails fast on a malformed peer public key or endpoint before
// they reach the data plane (deep-dive item K). The public key must be a
// base64-encoded 32-byte WireGuard key; the endpoint must be host:port with a
// numeric port. On error the offending value is surfaced, which doubles as a
// diagnostic aid for opaque registration responses (e.g. Team onboarding).
func ValidatePeer(publicKeyB64, endpoint string) error {
	if err := ValidateKeyB64(publicKeyB64); err != nil {
		return fmt.Errorf("peer public key: %w", err)
	}
	if err := ValidateEndpointHostPort(endpoint); err != nil {
		return fmt.Errorf("peer endpoint: %w", err)
	}
	return nil
}

// ValidateKeyB64 checks that s is a base64-encoded WireGuard key of the correct
// length (32 bytes) without allocating a Key.
func ValidateKeyB64(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("empty key")
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("invalid base64 %q: %w", s, err)
	}
	if len(decoded) != KeyLength {
		return fmt.Errorf("invalid key length %d (want %d)", len(decoded), KeyLength)
	}
	return nil
}

// ValidateEndpointHostPort checks that endpoint is host:port with a non-empty
// host and a numeric port in range. The host may be an IP or a hostname;
// resolution happens later (see the run path's endpoint resolver).
func ValidateEndpointHostPort(endpoint string) error {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return fmt.Errorf("empty endpoint")
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return fmt.Errorf("endpoint %q must be host:port: %w", endpoint, err)
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("endpoint %q missing host", endpoint)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p <= 0 || p > 65535 {
		return fmt.Errorf("endpoint %q has invalid port %q", endpoint, port)
	}
	return nil
}
