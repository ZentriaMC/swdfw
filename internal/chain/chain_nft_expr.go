//go:build linux

package chain

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/ZentriaMC/swdfw/internal/rule"
)

// nftables reject constants (not always available in x/sys/unix).
const (
	nftRejectICMPXUnreach     uint32 = 2 // NFT_REJECT_ICMPX_UNREACH
	nftRejectICMPXPortUnreach uint8  = 1 // NFT_REJECT_ICMPX_PORT_UNREACH
)

// ruleToExprs converts a rule.Rule into a slice of nftables expressions.
// If sourceSet is non-nil, a Lookup expression is emitted to match the source
// address against the named set.
func ruleToExprs(r rule.Rule, sourceSet *nftables.Set) ([]expr.Any, error) {
	var exprs []expr.Any

	// Match network protocol family (IPv4 vs IPv6) in inet table.
	nfproto := byte(unix.NFPROTO_IPV4)
	if r.IsV6() {
		nfproto = byte(unix.NFPROTO_IPV6)
	}
	exprs = append(exprs,
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{nfproto}},
	)

	// Match source CIDR.
	cidrExprs, err := cidrExprs(r.CIDR, r.IsV6())
	if err != nil {
		return nil, err
	}
	exprs = append(exprs, cidrExprs...)

	// Match source set (if configured).
	if sourceSet != nil {
		var addrOffset, addrLen uint32
		if r.IsV6() {
			addrOffset = 8
			addrLen = 16
		} else {
			addrOffset = 12
			addrLen = 4
		}
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       addrOffset,
				Len:          addrLen,
			},
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        sourceSet.Name,
				SetID:          sourceSet.ID,
			},
		)
	}

	// Match L4 protocol.
	protoName := r.ProtocolName()
	l4Exprs := l4ProtoExprs(protoName, r.IsV6())
	exprs = append(exprs, l4Exprs...)

	// Match destination port (TCP/UDP only).
	if protoName == "tcp" || protoName == "udp" {
		exprs = append(exprs, dstPortExprs(r.Port, r.StartPort, r.EndPort)...)
		exprs = append(exprs, srcPortExprs(r.SourcePort, r.SourceStartPort, r.SourceEndPort)...)
	}

	// Match TCP flags and TCP options (TCP only).
	if protoName == "tcp" {
		exprs = append(exprs, tcpFlagExprs(r.Flags)...)
		exprs = append(exprs, tcpOptExprs(r.Flags)...)
	}

	// Match ICMP type.
	switch r.Protocol {
	case rule.ProtocolICMP:
		if icmpExprs := icmpTypeExprs(r.Flags, rule.ICMPTypeCodes()); icmpExprs != nil {
			exprs = append(exprs, icmpExprs...)
		}
	case rule.ProtocolICMPv6:
		if icmpExprs := icmpTypeExprs(r.Flags, rule.ICMPV6TypeCodes()); icmpExprs != nil {
			exprs = append(exprs, icmpExprs...)
		}
	}

	// Match interfaces.
	if r.SourceInterface != "" {
		exprs = append(exprs, ifnameExprs(expr.MetaKeyIIFNAME, r.SourceInterface)...)
	}
	if r.DestinationInterface != "" {
		exprs = append(exprs, ifnameExprs(expr.MetaKeyOIFNAME, r.DestinationInterface)...)
	}

	// Match MAC source address.
	macExprs, err := macSrcExprs(r.Flags)
	if err != nil {
		return nil, err
	}
	exprs = append(exprs, macExprs...)

	// Verdict.
	verdict, err := verdictExpr(r.Action)
	if err != nil {
		return nil, err
	}
	exprs = append(exprs, verdict)

	return exprs, nil
}

// cidrExprs builds expressions to match a source CIDR.
// Returns nil for /0 masks (matches everything).
func cidrExprs(cidr netip.Prefix, v6 bool) ([]expr.Any, error) {
	if !cidr.IsValid() {
		return nil, fmt.Errorf("invalid CIDR %q", cidr)
	}

	if cidr.Bits() == 0 {
		return nil, nil
	}

	masked := cidr.Masked()
	var addrOffset, addrLen uint32
	var network []byte
	if v6 {
		addrOffset = 8
		addrLen = 16
		a := masked.Addr().As16()
		network = a[:]
	} else {
		addrOffset = 12
		addrLen = 4
		a := masked.Addr().As4()
		network = a[:]
	}

	mask := prefixToMask(cidr.Bits(), int(addrLen))

	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       addrOffset,
			Len:          addrLen,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            addrLen,
			Mask:           mask,
			Xor:            make([]byte, addrLen),
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     network[:addrLen],
		},
	}, nil
}

// prefixToMask builds a subnet mask byte slice from a prefix length.
func prefixToMask(bits, byteLen int) []byte {
	mask := make([]byte, byteLen)
	for i := range mask {
		if bits >= 8 {
			mask[i] = 0xff
			bits -= 8
		} else {
			mask[i] = byte(0xff << (8 - bits))
			bits = 0
		}
	}
	return mask
}

// l4ProtoExprs matches the L4 protocol (TCP, UDP, ICMP).
func l4ProtoExprs(protoName string, v6 bool) []expr.Any {
	var proto byte
	switch protoName {
	case "tcp":
		proto = unix.IPPROTO_TCP
	case "udp":
		proto = unix.IPPROTO_UDP
	case "icmp":
		if v6 {
			proto = unix.IPPROTO_ICMPV6
		} else {
			proto = unix.IPPROTO_ICMP
		}
	default:
		return nil
	}

	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
	}
}

// dstPortExprs matches a destination port or port range.
func dstPortExprs(port, startPort, endPort uint16) []expr.Any {
	return portExprs(2, port, startPort, endPort) // offset 2 = destination port
}

// srcPortExprs matches a source port or port range.
func srcPortExprs(port, startPort, endPort uint16) []expr.Any {
	return portExprs(0, port, startPort, endPort) // offset 0 = source port
}

// portExprs builds expressions for port matching at the given transport header offset.
func portExprs(offset uint32, port, startPort, endPort uint16) []expr.Any {
	if port > 0 {
		return []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       offset,
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     uint16Bytes(port),
			},
		}
	}

	if startPort > 0 {
		return []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       offset,
				Len:          2,
			},
			&expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: uint16Bytes(startPort)},
			&expr.Cmp{Op: expr.CmpOpLte, Register: 1, Data: uint16Bytes(endPort)},
		}
	}

	return nil
}

// ifnameExprs matches an interface name.
func ifnameExprs(key expr.MetaKey, name string) []expr.Any {
	b := make([]byte, len(name)+1) // null-terminated
	copy(b, name)

	return []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: b},
	}
}

// verdictExpr returns the terminal expression for a rule action.
func verdictExpr(action rule.Action) (expr.Any, error) {
	switch action {
	case rule.ActionAllow:
		return &expr.Verdict{Kind: expr.VerdictAccept}, nil
	case rule.ActionBlock:
		return &expr.Reject{
			Type: nftRejectICMPXUnreach,
			Code: nftRejectICMPXPortUnreach,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported action: %s", action)
	}
}

// icmpTypeExprs scans flags for an ICMP type prefix and returns payload+cmp
// expressions matching the ICMP type byte at transport header offset 0.
// A leading '!' on the flag produces a CmpOpNeq (match everything except).
func icmpTypeExprs(flags []string, typeCodes map[string]uint8) []expr.Any {
	for _, flag := range flags {
		clean, negated := rule.ParseFlag(flag)
		if code, ok := typeCodes[clean]; ok {
			op := expr.CmpOpEq
			if negated {
				op = expr.CmpOpNeq
			}
			return []expr.Any{
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseTransportHeader,
					Offset:       0,
					Len:          1,
				},
				&expr.Cmp{
					Op:       op,
					Register: 1,
					Data:     []byte{code},
				},
			}
		}
	}
	return nil
}

// tcpFlagExprs builds expressions to match TCP flags using bitwise AND.
// TCP flags byte is at transport header offset 13, length 1.
func tcpFlagExprs(flags []string) []expr.Any {
	bits := rule.TCPFlagBits()
	var mask uint8
	negated := false

	for _, flag := range flags {
		clean, neg := rule.ParseFlag(flag)
		name, ok := strings.CutPrefix(clean, "tcp:")
		if !ok {
			continue
		}
		b, valid := bits[name]
		if !valid {
			continue
		}
		mask |= b
		if neg {
			negated = true
		}
	}

	if mask == 0 {
		return nil
	}

	op := expr.CmpOpEq
	if negated {
		op = expr.CmpOpNeq
	}

	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       13,
			Len:          1,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            1,
			Mask:           []byte{mask},
			Xor:            []byte{0x00},
		},
		&expr.Cmp{
			Op:       op,
			Register: 1,
			Data:     []byte{mask},
		},
	}
}

// tcpOptExprs builds expressions to check TCP option presence using Exthdr.
func tcpOptExprs(flags []string) []expr.Any {
	for _, flag := range flags {
		clean, negated := rule.ParseFlag(flag)
		optStr, ok := strings.CutPrefix(clean, "tcpopt:")
		if !ok {
			continue
		}
		kind, err := strconv.ParseUint(optStr, 10, 8)
		if err != nil {
			continue
		}

		op := expr.CmpOpEq
		if negated {
			op = expr.CmpOpNeq
		}

		return []expr.Any{
			&expr.Exthdr{
				DestRegister: 1,
				Type:         uint8(kind),
				Op:           expr.ExthdrOpTcpopt,
				Flags:        1, // NFT_EXTHDR_F_PRESENT
			},
			&expr.Cmp{
				Op:       op,
				Register: 1,
				Data:     []byte{1},
			},
		}
	}
	return nil
}

// macSrcExprs builds expressions to match source MAC address.
// Source MAC is at link layer header offset 6, length 6.
func macSrcExprs(flags []string) ([]expr.Any, error) {
	for _, flag := range flags {
		clean, negated := rule.ParseFlag(flag)
		addr, ok := strings.CutPrefix(clean, "mac:")
		if !ok {
			continue
		}
		hw, err := net.ParseMAC(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid MAC address %q: %w", addr, err)
		}

		op := expr.CmpOpEq
		if negated {
			op = expr.CmpOpNeq
		}

		return []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseLLHeader,
				Offset:       6,
				Len:          uint32(len(hw)),
			},
			&expr.Cmp{
				Op:       op,
				Register: 1,
				Data:     hw,
			},
		}, nil
	}
	return nil, nil
}

func uint16Bytes(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}
