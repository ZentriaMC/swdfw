package rule

const (
	icmpPrefix   = "icmp:"
	icmpv6Prefix = "icmpv6:"
	tcpPrefix    = "tcp:"
	macPrefix    = "mac:"
)

var (
	validTCPFlags = map[string]bool{
		"tcp:ack":  true,
		"tcp:all":  true,
		"tcp:fin":  true,
		"tcp:none": true,
		"tcp:psh":  true,
		"tcp:rst":  true,
		"tcp:syn":  true,
		"tcp:urg":  true,
	}
	validICMPTypes = map[string]uint8{
		"icmp:echo-reply":              0,
		"icmp:destination-unreachable": 3,
		"icmp:source-quench":           4,
		"icmp:redirect":                5,
		"icmp:echo-request":            8,
		"icmp:router-advertisement":    9,
		"icmp:router-solicitation":     10,
		"icmp:time-exceeded":           11,
		"icmp:parameter-problem":       12,
		"icmp:timestamp-request":       13,
		"icmp:timestamp-reply":         14,
		"icmp:address-mask-request":    17,
		"icmp:address-mask-reply":      18,
	}
	validICMPV6Types = map[string]uint8{
		"icmpv6:destination-unreachable": 1,
		"icmpv6:packet-too-big":          2,
		"icmpv6:time-exceeded":           3,
		"icmpv6:parameter-problem":       4,
		"icmpv6:echo-request":            128,
		"icmpv6:echo-reply":              129,
		"icmpv6:router-solicitation":     133,
		"icmpv6:router-advertisement":    134,
		"icmpv6:neighbour-solicitation":  135,
		"icmpv6:neighbour-advertisement": 136,
		"icmpv6:redirect":                137,
	}
	validStates = map[string]bool{
		"state:established": true,
		"state:invalid":     true,
		"state:new":         true,
		"state:related":     true,
	}
)

var tcpFlagBits = map[string]uint8{
	"fin":  0x01,
	"syn":  0x02,
	"rst":  0x04,
	"psh":  0x08,
	"ack":  0x10,
	"urg":  0x20,
	"all":  0x3f,
	"none": 0x00,
}

// ICMPTypeCodes returns the ICMP type code map for use by backends.
func ICMPTypeCodes() map[string]uint8 {
	return validICMPTypes
}

// ICMPV6TypeCodes returns the ICMPv6 type code map for use by backends.
func ICMPV6TypeCodes() map[string]uint8 {
	return validICMPV6Types
}

// TCPFlagBits returns the TCP flag name → bit value map for use by backends.
func TCPFlagBits() map[string]uint8 {
	return tcpFlagBits
}
