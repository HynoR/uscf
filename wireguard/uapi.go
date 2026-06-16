package wireguard

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
)

// HexString returns the lowercase hex encoding of the key.
//
// Account keys are stored base64 (see Key.String), but wireguard-go's UAPI
// "set" format (device.Device.IpcSet) expects keys as lowercase hex. This is
// the base64->hex bridge used when building an in-process WireGuard config.
func (k *Key) HexString() string {
	return hex.EncodeToString(k[:])
}

// UAPIParams describes a single-peer WireGuard interface to be rendered into
// wireguard-go's UAPI "set" text format (see device/uapi.go IpcSetOperation).
//
// It intentionally models only what the in-process WARP tunnel needs: one
// interface key and exactly one peer. Multi-peer configs are out of scope.
type UAPIParams struct {
	PrivateKey          *Key     // interface private key (required)
	PublicKey           *Key     // peer public key (required)
	Endpoint            string   // peer endpoint as ip:port; must be a literal address, not a hostname
	PersistentKeepalive int      // seconds; <=0 omits the line (0 disables keepalive)
	AllowedIPs          []string // peer allowed IPs as CIDRs; empty defaults to full-tunnel
	ListenPort          int      // local UDP bind port; 0 selects a random port
}

// BuildUAPIConfig renders p into the UAPI "set" string accepted by
// device.Device.IpcSet. It is a pure function: every input is validated and the
// offending value is surfaced on error, so a malformed account/registration
// response fails fast rather than producing a silently-broken tunnel.
//
// The endpoint must already be a literal ip:port. wireguard-go's default bind
// (conn.NewDefaultBind -> StdNetBind) parses endpoints with netip.ParseAddrPort
// and does NOT resolve hostnames, so callers must resolve DNS beforehand.
func BuildUAPIConfig(p UAPIParams) (string, error) {
	if p.PrivateKey == nil {
		return "", fmt.Errorf("build uapi: nil private key")
	}
	if p.PublicKey == nil {
		return "", fmt.Errorf("build uapi: nil peer public key")
	}
	ap, err := netip.ParseAddrPort(strings.TrimSpace(p.Endpoint))
	if err != nil {
		return "", fmt.Errorf("build uapi: endpoint %q must be ip:port (hostnames must be resolved first): %w", p.Endpoint, err)
	}
	if p.ListenPort < 0 || p.ListenPort > 65535 {
		return "", fmt.Errorf("build uapi: invalid listen port %d", p.ListenPort)
	}
	if p.PersistentKeepalive < 0 || p.PersistentKeepalive > 65535 {
		return "", fmt.Errorf("build uapi: invalid persistent keepalive %d", p.PersistentKeepalive)
	}

	allowed := p.AllowedIPs
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0", "::/0"}
	}
	prefixes := make([]netip.Prefix, 0, len(allowed))
	for _, cidr := range allowed {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			return "", fmt.Errorf("build uapi: invalid allowed ip %q: %w", cidr, err)
		}
		prefixes = append(prefixes, prefix)
	}

	// Order matters: interface fields, then replace_peers, then the peer block
	// (public_key starts the peer), then its allowed_ips.
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", p.PrivateKey.HexString())
	if p.ListenPort > 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", p.ListenPort)
	}
	b.WriteString("replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", p.PublicKey.HexString())
	fmt.Fprintf(&b, "endpoint=%s\n", ap.String())
	if p.PersistentKeepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", p.PersistentKeepalive)
	}
	b.WriteString("replace_allowed_ips=true\n")
	for _, prefix := range prefixes {
		fmt.Fprintf(&b, "allowed_ip=%s\n", prefix.String())
	}
	return b.String(), nil
}
