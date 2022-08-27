package rule

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
)

var (
	supportedProtocols = map[string]bool{
		"tcp":    true,
		"udp":    true,
		"icmp":   true,
		"tcpv6":  true,
		"udpv6":  true,
		"icmpv6": true,
	}
	supportedActions = map[string]bool{
		"allow": true,
		"block": true,
	}
	supportedDirections = map[string]bool{
		"input":  true,
		"output": true,
	}
)

type Rule struct {
	Protocol  string `json:"protocol"`
	CIDR      string `json:"cidr"` // TODO: type
	Action    string `json:"action"`
	Direction string `json:"direction"`

	StartPort uint16 `json:"start"`
	EndPort   uint16 `json:"end"`
	Port      uint16 `json:"-"`
}

func normalizeValue(what, v, def string, validValues map[string]bool) (normalized string, err error) {
	if v == "" {
		v = def
	}
	normalized = strings.ToLower(v)
	if _, ok := validValues[normalized]; !ok {
		err = fmt.Errorf("unsupported %s: '%s'", what, normalized)
	}
	return
}

func (r *Rule) UnmarshalJSON(b []byte) (err error) {
	type ruleT Rule
	if err = json.Unmarshal(b, (*ruleT)(r)); err != nil {
		return
	}

	err = r.Validate()
	return
}

func (r *Rule) Validate() (err error) {
	if r.Protocol, err = normalizeValue("protocol", r.Protocol, "", supportedProtocols); err != nil {
		return
	}

	if r.Action, err = normalizeValue("action", r.Action, "", supportedActions); err != nil {
		return
	}

	if r.Direction, err = normalizeValue("direction", r.Direction, "input", supportedDirections); err != nil {
		return
	}

	// Validate IP
	var cidr *net.IPNet
	if _, cidr, err = net.ParseCIDR(r.CIDR); err != nil {
		return
	}

	cidrV6 := cidr.IP.To4() == nil
	if r.IsV6() != cidrV6 {
		err = fmt.Errorf("ipv4 in ipv6 (or vice versa) rule")
		return
	}

	if (r.StartPort == r.EndPort) || (r.StartPort != 0 && r.EndPort == 0) {
		r.Port = r.StartPort
	} else if r.StartPort > r.EndPort {
		err = fmt.Errorf("port range end cannot be smaller than start (start=%d, end=%d)", r.StartPort, r.EndPort)
		return
	}

	return
}

func (r *Rule) IsV6() bool {
	return strings.HasSuffix(r.Protocol, "v6")
}

func (r *Rule) ProtocolName() string {
	return strings.TrimSuffix(r.Protocol, "v6")
}

func (r *Rule) Proto() Protocol {
	if r.IsV6() {
		return ProtocolIPv6
	}
	return ProtocolIPv4
}

func (r *Rule) ToRulespec() (s []string, err error) {
	if err = r.Validate(); err != nil {
		return
	}
	s = []string{
		"-s", r.CIDR,
		"-p", r.ProtocolName(),
	}

	if r.Port > 0 {
		s = append(s, "--dport", strconv.Itoa(int(r.Port)))
	} else if r.StartPort > 0 {
		s = append(s, "--dport", fmt.Sprintf("%d:%d", r.StartPort, r.EndPort))
	}

	var target string
	switch r.Action {
	case "allow":
		target = "RETURN"
	case "block":
		target = "REJECT"
	default:
		err = fmt.Errorf("unhandled target '%s'", r.Action)
		return
	}

	s = append(s, "-j", target)

	if target == "REJECT" {
		if r.IsV6() {
			s = append(s, "--reject-with", "icmp6-port-unreachable")
		} else {
			s = append(s, "--reject-with", "icmp-port-unreachable")
		}
	}
	return
}
