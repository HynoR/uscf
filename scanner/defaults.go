package scanner

import "time"

// IPFamily indicates which IP version to scan.
type IPFamily string

const (
	IPFamilyV4 IPFamily = "ipv4"
	IPFamilyV6 IPFamily = "ipv6"
)

const (
	DefaultSamplePerCIDR = 64
)

var (
	DefaultScanPerIPTimeout = 3 * time.Second

	// Placeholder defaults. Replace these with full endpoint CIDRs as needed.
	DefaultIPv4CIDRs = []string{"162.159.198.1/32"}
	DefaultIPv6CIDRs = []string{"2606:4700:103::1/128"}
)

func DefaultCIDRsForFamily(family IPFamily) []string {
	switch family {
	case IPFamilyV4:
		return append([]string(nil), DefaultIPv4CIDRs...)
	case IPFamilyV6:
		return append([]string(nil), DefaultIPv6CIDRs...)
	default:
		return nil
	}
}
