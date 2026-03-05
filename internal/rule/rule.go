package rule

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Action represents a firewall rule verdict.
type Action string

const (
	ActionAllow Action = "allow"
	ActionBlock Action = "block"
)

// Direction represents which hook a rule applies to.
type Direction string

const (
	DirectionInput  Direction = "input"
	DirectionOutput Direction = "output"
)

// Protocol represents the L4 protocol (with optional v6 suffix).
type Protocol string

const (
	ProtocolTCP    Protocol = "tcp"
	ProtocolUDP    Protocol = "udp"
	ProtocolICMP   Protocol = "icmp"
	ProtocolTCPv6  Protocol = "tcpv6"
	ProtocolUDPv6  Protocol = "udpv6"
	ProtocolICMPv6 Protocol = "icmpv6"
)

var (
	supportedProtocols = map[string]bool{
		string(ProtocolTCP):    true,
		string(ProtocolUDP):    true,
		string(ProtocolICMP):   true,
		string(ProtocolTCPv6):  true,
		string(ProtocolUDPv6):  true,
		string(ProtocolICMPv6): true,
	}
	supportedActions = map[string]bool{
		string(ActionAllow): true,
		string(ActionBlock): true,
	}
	supportedDirections = map[string]bool{
		string(DirectionInput):  true,
		string(DirectionOutput): true,
	}
)

type Rule struct {
	Protocol  Protocol `json:"protocol"`
	CIDR      netip.Prefix `json:"cidr"`
	Action    Action    `json:"action"`
	Direction Direction `json:"direction"`

	StartPort uint16 `json:"start"`
	EndPort   uint16 `json:"end"`
	Port      uint16 `json:"-"`

	// Only TCP and UDP
	SourceEndPort   uint16 `json:"source_end"`
	SourcePort      uint16 `json:"source_port"`
	SourceStartPort uint16 `json:"source_start"`

	// TODO:
	// --tcp-flags (SYN, ACK etc.) also prefix with !
	// --tcp-option option:<value> also prefix with !
	// --icmp-type (echo-reply, echo-request etc.) also prefix with !
	// --mac-source (mac) also prefix with !
	Flags                []string `json:"flags"`
	SourceInterface      string   `json:"source_interface"`
	DestinationInterface string   `json:"destination_interface"`
	SourceSet            string   `json:"source_set,omitempty"`
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
	{
		var normalized string
		if normalized, err = normalizeValue("protocol", string(r.Protocol), "", supportedProtocols); err != nil {
			return
		}
		r.Protocol = Protocol(normalized)
	}

	{
		var normalized string
		if normalized, err = normalizeValue("action", string(r.Action), "", supportedActions); err != nil {
			return
		}
		r.Action = Action(normalized)
	}

	{
		var normalized string
		if normalized, err = normalizeValue("direction", string(r.Direction), "input", supportedDirections); err != nil {
			return
		}
		r.Direction = Direction(normalized)
	}

	// Deduplicate and validate flags
	collectedFlagsMap := map[string]bool{}
	newFlags := []string{}
	for _, flag := range r.Flags {
		if _, ok := collectedFlagsMap[flag]; !ok {
			collectedFlagsMap[flag] = true
			newFlags = append(newFlags, flag)
		}
	}
	r.Flags = newFlags

	if err = r.validateFlags(); err != nil {
		return
	}

	// Validate IP
	if !r.CIDR.IsValid() {
		err = fmt.Errorf("invalid CIDR %q", r.CIDR)
		return
	}
	r.CIDR = r.CIDR.Masked()

	if r.IsV6() != r.CIDR.Addr().Is6() {
		err = fmt.Errorf("ipv4 in ipv6 (or vice versa) rule")
		return
	}

	if r.ProtocolName() == "icmp" {
		r.StartPort = 0
		r.EndPort = 0
		r.Port = 0
	} else {
		if (r.StartPort == r.EndPort) || (r.StartPort != 0 && r.EndPort == 0) {
			r.Port = r.StartPort
		} else if r.StartPort > r.EndPort {
			err = fmt.Errorf("port range end cannot be smaller than start (start=%d, end=%d)", r.StartPort, r.EndPort)
			return
		}
	}

	return
}

func (r *Rule) IsV6() bool {
	return strings.HasSuffix(string(r.Protocol), "v6")
}

func (r *Rule) ProtocolName() string {
	return strings.TrimSuffix(string(r.Protocol), "v6")
}

func (r *Rule) Family() Family {
	if r.IsV6() {
		return FamilyIPv6
	}
	return FamilyIPv4
}

func (r *Rule) ToRulespec(chainName string) (s []string, err error) {
	if err = r.Validate(); err != nil {
		return
	}
	s = []string{"-s", r.CIDR.String()}

	if r.Protocol != ProtocolICMPv6 {
		s = append(s, "-p", r.ProtocolName())
	} else {
		s = append(s, "-p", string(r.Protocol))
	}

	if r.Port > 0 {
		s = append(s, "--dport", strconv.Itoa(int(r.Port)))
	} else if r.StartPort > 0 {
		s = append(s, "--dport", fmt.Sprintf("%d:%d", r.StartPort, r.EndPort))
	}

	// ICMP type matching.
	switch r.ProtocolName() {
	case "icmp":
		for _, flag := range r.Flags {
			flagLower := strings.ToLower(flag)
			if strings.HasPrefix(flagLower, icmpPrefix) {
				s = append(s, "--icmp-type", strings.TrimPrefix(flagLower, icmpPrefix))
			}
		}
	case "icmpv6":
		for _, flag := range r.Flags {
			flagLower := strings.ToLower(flag)
			if strings.HasPrefix(flagLower, icmpv6Prefix) {
				s = append(s, "--icmpv6-type", strings.TrimPrefix(flagLower, icmpv6Prefix))
			}
		}
	}

	if r.SourceSet != "" {
		s = append(s, "-m", "set", "--match-set", r.SourceSet, "src")
	}

	var target string
	switch r.Action {
	case ActionAllow:
		target = "RETURN"
	case ActionBlock:
		target = "REJECT"
	default:
		err = fmt.Errorf("unhandled target '%s'", r.Action)
		return
	}

	s = append(s, "-j", target)

	// mimic what iptables is doing
	if target == "REJECT" {
		if r.IsV6() {
			s = append(s, "--reject-with", "icmp6-port-unreachable")
		} else {
			s = append(s, "--reject-with", "icmp-port-unreachable")
		}
	}

	s = append(s, "-m", "comment", "--comment", fmt.Sprintf("Autogenerated rule using swdfw from '%s'", chainName))
	return
}
