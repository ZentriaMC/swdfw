//go:build linux

package chain

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

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
func ruleToExprs(r rule.Rule) ([]expr.Any, error) {
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

	// Match L4 protocol.
	protoName := r.ProtocolName()
	l4Exprs := l4ProtoExprs(protoName, r.IsV6())
	exprs = append(exprs, l4Exprs...)

	// Match destination port (TCP/UDP only).
	if protoName == "tcp" || protoName == "udp" {
		exprs = append(exprs, dstPortExprs(r.Port, r.StartPort, r.EndPort)...)
		exprs = append(exprs, srcPortExprs(r.SourcePort, r.SourceStartPort, r.SourceEndPort)...)
	}

	// Match ICMP type.
	if protoName == "icmp" {
		typeCodes := rule.ICMPTypeCodes()
		if r.IsV6() {
			typeCodes = rule.ICMPV6TypeCodes()
		}
		if icmpExprs := icmpTypeExprs(r.Flags, typeCodes); icmpExprs != nil {
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
func cidrExprs(cidr string, v6 bool) ([]expr.Any, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	ones, _ := ipnet.Mask.Size()
	if ones == 0 {
		return nil, nil
	}

	var addrOffset, addrLen uint32
	var network []byte
	if v6 {
		addrOffset = 8
		addrLen = 16
		network = ipnet.IP.To16()
	} else {
		addrOffset = 12
		addrLen = 4
		network = ipnet.IP.To4()
	}

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
			Mask:           []byte(ipnet.Mask),
			Xor:            make([]byte, addrLen),
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     network[:addrLen],
		},
	}, nil
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
func verdictExpr(action string) (expr.Any, error) {
	switch action {
	case "allow":
		return &expr.Verdict{Kind: expr.VerdictAccept}, nil
	case "block":
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
func icmpTypeExprs(flags []string, typeCodes map[string]uint8) []expr.Any {
	for _, flag := range flags {
		flagLower := strings.ToLower(flag)
		if code, ok := typeCodes[flagLower]; ok {
			return []expr.Any{
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseTransportHeader,
					Offset:       0,
					Len:          1,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{code},
				},
			}
		}
	}
	return nil
}

func uint16Bytes(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}
