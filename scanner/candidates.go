package scanner

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"net"
	"strconv"
)

const maxSampleAttemptsFactor = 16

// GenerateCandidates builds endpoint candidates from CIDRs by random sampling.
func GenerateCandidates(cidrs []string, port int, family IPFamily, samplePerCIDR int, rnd *rand.Rand) ([]string, error) {
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port: %d", port)
	}
	if family != IPFamilyV4 && family != IPFamilyV6 {
		return nil, fmt.Errorf("unsupported ip family: %q", family)
	}
	if samplePerCIDR <= 0 {
		samplePerCIDR = DefaultSamplePerCIDR
	}
	if rnd == nil {
		rnd = rand.New(rand.NewSource(rand.Int63()))
	}

	out := make([]string, 0)
	seenEndpoints := make(map[string]struct{})

	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}

		if !netMatchesFamily(ipNet, family) {
			continue
		}

		var hosts []string
		switch family {
		case IPFamilyV4:
			hosts = sampleIPv4Hosts(ipNet, samplePerCIDR, rnd)
		case IPFamilyV6:
			hosts = sampleIPv6Hosts(ipNet, samplePerCIDR, rnd)
		}

		for _, host := range hosts {
			ep := net.JoinHostPort(host, strconv.Itoa(port))
			if _, ok := seenEndpoints[ep]; ok {
				continue
			}
			seenEndpoints[ep] = struct{}{}
			out = append(out, ep)
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no candidates generated for family %s", family)
	}

	return out, nil
}

func netMatchesFamily(ipNet *net.IPNet, family IPFamily) bool {
	if ipNet == nil {
		return false
	}
	isV4 := ipNet.IP.To4() != nil
	if family == IPFamilyV4 {
		return isV4
	}
	return !isV4
}

func sampleIPv4Hosts(ipNet *net.IPNet, samplePerCIDR int, rnd *rand.Rand) []string {
	prefix, bits := ipNet.Mask.Size()
	if bits != 32 {
		return nil
	}

	netIP := ipNet.IP.To4()
	if netIP == nil {
		return nil
	}

	hostBits := uint32(32 - prefix)
	var total uint64 = 1
	if hostBits > 0 {
		total = uint64(1) << hostBits
	}
	target := samplePerCIDR
	if uint64(target) > total {
		target = int(total)
	}
	if target <= 0 {
		return nil
	}

	base := binary.BigEndian.Uint32(netIP)
	seenOffsets := make(map[uint32]struct{}, target)
	hosts := make([]string, 0, target)
	maxAttempts := target * maxSampleAttemptsFactor
	if maxAttempts < target {
		maxAttempts = target
	}

	for attempts := 0; len(hosts) < target && attempts < maxAttempts; attempts++ {
		var offset uint32
		if hostBits == 0 {
			offset = 0
		} else {
			offset = rnd.Uint32() & ((1 << hostBits) - 1)
		}
		if _, ok := seenOffsets[offset]; ok {
			continue
		}
		seenOffsets[offset] = struct{}{}

		addr := make(net.IP, 4)
		binary.BigEndian.PutUint32(addr, base+offset)
		hosts = append(hosts, addr.String())
	}

	if len(hosts) < target {
		for off := uint64(0); off < total && len(hosts) < target; off++ {
			offset := uint32(off)
			if _, ok := seenOffsets[offset]; ok {
				continue
			}
			seenOffsets[offset] = struct{}{}
			addr := make(net.IP, 4)
			binary.BigEndian.PutUint32(addr, base+offset)
			hosts = append(hosts, addr.String())
		}
	}

	return hosts
}

func sampleIPv6Hosts(ipNet *net.IPNet, samplePerCIDR int, rnd *rand.Rand) []string {
	prefix, bits := ipNet.Mask.Size()
	if bits != 128 {
		return nil
	}

	netIP := ipNet.IP.To16()
	if netIP == nil {
		return nil
	}

	hostBits := 128 - prefix
	target := samplePerCIDR
	if hostBits == 0 {
		target = 1
	}
	if target <= 0 {
		return nil
	}

	network := make(net.IP, 16)
	copy(network, netIP)
	for i := prefix; i < 128; i++ {
		byteIdx := i / 8
		bit := uint(7 - (i % 8))
		network[byteIdx] &^= 1 << bit
	}

	seen := make(map[string]struct{}, target)
	hosts := make([]string, 0, target)
	maxAttempts := target * maxSampleAttemptsFactor
	if maxAttempts < target {
		maxAttempts = target
	}
	if hostBits > 0 {
		maxPossible := maxIntByHostBits(hostBits)
		if target > maxPossible {
			target = maxPossible
		}
	}

	for attempts := 0; len(hosts) < target && attempts < maxAttempts; attempts++ {
		ip := make(net.IP, 16)
		copy(ip, network)
		if hostBits > 0 {
			for i := prefix; i < 128; i++ {
				if rnd.Intn(2) == 0 {
					continue
				}
				byteIdx := i / 8
				bit := uint(7 - (i % 8))
				ip[byteIdx] |= 1 << bit
			}
		}
		host := ip.String()
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}

	if len(hosts) < target {
		for i := 0; len(hosts) < target && i < target*maxSampleAttemptsFactor; i++ {
			ip := make(net.IP, 16)
			copy(ip, network)
			value := uint64(i)
			for bitPos := 0; bitPos < hostBits && bitPos < 64; bitPos++ {
				if value&(1<<bitPos) == 0 {
					continue
				}
				idx := 127 - bitPos
				byteIdx := idx / 8
				bit := uint(7 - (idx % 8))
				ip[byteIdx] |= 1 << bit
			}
			host := ip.String()
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			hosts = append(hosts, host)
		}
	}

	return hosts
}

func maxIntByHostBits(hostBits int) int {
	if hostBits <= 0 {
		return 1
	}
	if hostBits >= 31 {
		return math.MaxInt32
	}
	return 1 << hostBits
}
