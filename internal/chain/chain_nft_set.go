//go:build linux

package chain

import (
	"fmt"
	"math/big"
	"net"

	"github.com/google/nftables"
)

// cidrToSetElements converts a CIDR string into an interval pair suitable
// for an nftables interval set: [network, broadcast+1).
func cidrToSetElements(cidr string, v6 bool) ([]nftables.SetElement, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	var startIP []byte
	if v6 {
		startIP = ipnet.IP.To16()
	} else {
		startIP = ipnet.IP.To4()
	}
	if startIP == nil {
		return nil, fmt.Errorf("CIDR %q: IP conversion failed", cidr)
	}

	// Compute the exclusive end: broadcast + 1.
	endIP := broadcastPlusOne(startIP, ipnet.Mask)

	return []nftables.SetElement{
		{Key: startIP},
		{Key: endIP, IntervalEnd: true},
	}, nil
}

// cidrsToSetElements converts multiple CIDRs into nftables set elements.
func cidrsToSetElements(cidrs []string, v6 bool) ([]nftables.SetElement, error) {
	var elements []nftables.SetElement
	for _, cidr := range cidrs {
		elems, err := cidrToSetElements(cidr, v6)
		if err != nil {
			return nil, err
		}
		elements = append(elements, elems...)
	}
	return elements, nil
}

// broadcastPlusOne returns the first IP address past the broadcast address
// of the given network.
func broadcastPlusOne(ip net.IP, mask net.IPMask) net.IP {
	// Compute broadcast: IP | ^mask
	broadcast := make(net.IP, len(ip))
	for i := range ip {
		broadcast[i] = ip[i] | ^mask[i]
	}

	// Add 1 using big.Int for correct carry handling.
	n := new(big.Int).SetBytes(broadcast)
	n.Add(n, big.NewInt(1))

	b := n.Bytes()
	result := make(net.IP, len(ip))
	// Right-align into result (big.Int.Bytes may be shorter).
	copy(result[len(result)-len(b):], b)

	return result
}

// setKeyType returns the nftables key type for IPv4 or IPv6 sets.
func setKeyType(v6 bool) (nftables.SetDatatype, uint32) {
	if v6 {
		return nftables.TypeIP6Addr, 16
	}
	return nftables.TypeIPAddr, 4
}

// parseCIDRsFamily determines whether all CIDRs are IPv4 or IPv6 (must be uniform).
func parseCIDRsFamily(cidrs []string) (v6 bool, err error) {
	for i, cidr := range cidrs {
		ip, _, perr := net.ParseCIDR(cidr)
		if perr != nil {
			return false, fmt.Errorf("invalid CIDR %q: %w", cidr, perr)
		}
		isV6 := ip.To4() == nil
		if i == 0 {
			v6 = isV6
		} else if isV6 != v6 {
			return false, fmt.Errorf("mixed IPv4 and IPv6 CIDRs")
		}
	}
	return
}

