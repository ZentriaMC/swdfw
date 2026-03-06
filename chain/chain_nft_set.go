//go:build linux

package chain

import (
	"fmt"
	"math/big"
	"net/netip"

	"github.com/google/nftables"
)

// cidrToSetElements converts a netip.Prefix into an interval pair suitable
// for an nftables interval set: [network, broadcast+1).
func cidrToSetElements(cidr netip.Prefix, v6 bool) ([]nftables.SetElement, error) {
	if !cidr.IsValid() {
		return nil, fmt.Errorf("invalid CIDR %q", cidr)
	}

	masked := cidr.Masked()
	var startIP []byte
	if v6 {
		a := masked.Addr().As16()
		startIP = a[:]
	} else {
		a := masked.Addr().As4()
		startIP = a[:]
	}

	// Compute the exclusive end: broadcast + 1.
	endIP := broadcastPlusOne(cidr)

	return []nftables.SetElement{
		{Key: startIP},
		{Key: endIP, IntervalEnd: true},
	}, nil
}

// cidrsToSetElements converts multiple CIDRs into nftables set elements.
func cidrsToSetElements(cidrs []netip.Prefix, v6 bool) ([]nftables.SetElement, error) {
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
// of the given prefix.
func broadcastPlusOne(prefix netip.Prefix) []byte {
	masked := prefix.Masked()
	byteLen := 4
	if prefix.Addr().Is6() {
		byteLen = 16
	}

	var ipBytes []byte
	if byteLen == 16 {
		a := masked.Addr().As16()
		ipBytes = a[:]
	} else {
		a := masked.Addr().As4()
		ipBytes = a[:]
	}

	mask := prefixToMask(prefix.Bits(), byteLen)

	// Compute broadcast: IP | ^mask
	broadcast := make([]byte, byteLen)
	for i := range ipBytes {
		broadcast[i] = ipBytes[i] | ^mask[i]
	}

	// Add 1 using big.Int for correct carry handling.
	n := new(big.Int).SetBytes(broadcast)
	n.Add(n, big.NewInt(1))

	b := n.Bytes()
	result := make([]byte, byteLen)
	if len(b) <= byteLen {
		// Right-align into result (big.Int.Bytes may be shorter).
		copy(result[byteLen-len(b):], b)
	}
	// else: overflow (e.g. /0 prefix) — result stays all-zeros, which is
	// the correct wrap-around end for an nftables interval covering
	// the entire address space.

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
func parseCIDRsFamily(cidrs []netip.Prefix) (v6 bool, err error) {
	for i, cidr := range cidrs {
		if !cidr.IsValid() {
			return false, fmt.Errorf("invalid CIDR %q", cidr)
		}
		isV6 := cidr.Addr().Is6()
		if i == 0 {
			v6 = isV6
		} else if isV6 != v6 {
			return false, fmt.Errorf("mixed IPv4 and IPv6 CIDRs")
		}
	}
	return
}

