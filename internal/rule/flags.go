package rule

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
	validICMPTypes = map[string]bool{
		// TODO: iptables -p icmp -h
	}
	validICMPV6Types = map[string]bool{
		// TODO: ip6tables -p icmpv6 -h
	}
	validStates = map[string]bool{
		"state:established": true,
		"state:invalid":     true,
		"state:new":         true,
		"state:related":     true,
	}
)
