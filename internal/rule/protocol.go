package rule

type Protocol byte

const (
	ProtocolIPv4 Protocol = iota
	ProtocolIPv6
)

func (p Protocol) Prog() (v string) {
	switch p {
	case ProtocolIPv4:
		v = "iptables"
	case ProtocolIPv6:
		v = "ip6tables"
	}
	return
}
