package rule_test

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/ZentriaMC/swdfw/internal/rule"
)

func TestSimpleRule(t *testing.T) {
	rules := []rule.Rule{
		{
			Protocol: "tcp",
			CIDR:     netip.MustParsePrefix("10.123.0.1/24"),
			Port:     22,
			Action:   "allow",
		},
		{
			Protocol:  "tcp",
			CIDR:      netip.MustParsePrefix("0.0.0.0/0"),
			Action:    "allow",
			StartPort: 1024,
			EndPort:   4096,
		},
		{
			Protocol: "icmp",
			CIDR:     netip.MustParsePrefix("10.124.0.0/24"),
			Action:   "allow",
		},
		{
			Protocol: "icmp",
			CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
			Action:   "block",
		},
		{
			Protocol: "tcp",
			CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
			Action:   "block",
		},
	}

	var strRules []string
	for _, r := range rules {
		rules, err := r.ToRulespec("testchain")
		if err != nil {
			t.Fatalf("failed to create rule: %s", err)
		}
		strRules = append(strRules, strings.Join(rules, " "))
	}

	// TODO: verify generated rules
	fmt.Printf("%s\n", strings.Join(strRules, "\n"))
}

func TestRulesWithFlags(t *testing.T) {
	mptcpRule := rule.Rule{
		Protocol: "tcp",
		CIDR:     netip.MustParsePrefix("10.123.0.1/24"),
		Port:     22,
		Action:   "allow",
		Flags: []string{
			"TCPOPT:30", // Allow MPTCP
		},
	}

	invalidMultiTCPOptRule := rule.Rule{
		Protocol: "tcp",
		CIDR:     netip.MustParsePrefix("10.123.0.1/24"),
		Port:     3066,
		Action:   "block",
		Flags: []string{
			"TCPOPT:30", // Block MPTCP
			"TCPOPT:36", // Block TCP Fast Open
		},
	}

	tcpFlagsInICMPRule := rule.Rule{
		Protocol: "icmp",
		CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
		Port:     4200,
		Action:   "block",
		Flags: []string{
			"TCP:ACK",
		},
	}

	err := mptcpRule.Validate()
	if err != nil {
		t.Error("expected mptcp rule to be valid:", err)
	}

	err = invalidMultiTCPOptRule.Validate()
	if err == nil {
		t.Error("expected rule containing multiple tcp options to be invalid")
	}

	err = tcpFlagsInICMPRule.Validate()
	if err == nil {
		t.Error("expected icmp rule containing tcp flags to be invalid")
	}
}

func TestSourceSetRulespec(t *testing.T) {
	r := rule.Rule{
		Protocol:  "tcp",
		CIDR:      netip.MustParsePrefix("0.0.0.0/0"),
		Port:      80,
		Action:    "allow",
		SourceSet: "trusted-ips",
	}

	spec, err := r.ToRulespec("testchain")
	if err != nil {
		t.Fatalf("ToRulespec: %v", err)
	}

	joined := strings.Join(spec, " ")
	expected := "-m set --match-set trusted-ips src"
	if !strings.Contains(joined, expected) {
		t.Fatalf("expected rulespec to contain %q, got: %s", expected, joined)
	}

	// Verify it appears before the verdict (-j)
	setIdx := strings.Index(joined, "-m set")
	jIdx := strings.Index(joined, "-j")
	if setIdx > jIdx {
		t.Fatalf("expected set match before verdict, set at %d, -j at %d", setIdx, jIdx)
	}
}

func TestNegatedICMPFlags(t *testing.T) {
	// Negated ICMP flag on ICMP rule → valid
	validNeg := rule.Rule{
		Protocol: "icmp",
		CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
		Action:   "allow",
		Flags:    []string{"!icmp:echo-request"},
	}
	if err := validNeg.Validate(); err != nil {
		t.Errorf("expected negated icmp flag to be valid: %v", err)
	}

	// Negated ICMP flag on TCP rule → invalid (wrong protocol)
	negOnTCP := rule.Rule{
		Protocol: "tcp",
		CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
		Port:     80,
		Action:   "allow",
		Flags:    []string{"!icmp:echo-request"},
	}
	if err := negOnTCP.Validate(); err == nil {
		t.Error("expected negated icmp flag on tcp rule to be invalid")
	}

	// Negated + positive in same rule → invalid (multiple ICMP types)
	negPlusPosICMP := rule.Rule{
		Protocol: "icmp",
		CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
		Action:   "allow",
		Flags:    []string{"!icmp:echo-request", "icmp:echo-reply"},
	}
	if err := negPlusPosICMP.Validate(); err == nil {
		t.Error("expected negated + positive icmp types to be invalid")
	}
}

func TestNegatedICMPToRulespec(t *testing.T) {
	r := rule.Rule{
		Protocol: "icmp",
		CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
		Action:   "allow",
		Flags:    []string{"!icmp:echo-request"},
	}

	spec, err := r.ToRulespec("testchain")
	if err != nil {
		t.Fatalf("ToRulespec: %v", err)
	}

	joined := strings.Join(spec, " ")
	expected := "! --icmp-type echo-request"
	if !strings.Contains(joined, expected) {
		t.Fatalf("expected rulespec to contain %q, got: %s", expected, joined)
	}
}

func TestNegatedICMPv6ToRulespec(t *testing.T) {
	r := rule.Rule{
		Protocol: "icmpv6",
		CIDR:     netip.MustParsePrefix("::/0"),
		Action:   "block",
		Flags:    []string{"!icmpv6:echo-request"},
	}

	spec, err := r.ToRulespec("testchain")
	if err != nil {
		t.Fatalf("ToRulespec: %v", err)
	}

	joined := strings.Join(spec, " ")
	expected := "! --icmpv6-type echo-request"
	if !strings.Contains(joined, expected) {
		t.Fatalf("expected rulespec to contain %q, got: %s", expected, joined)
	}
}

func TestTCPFlagsToRulespec(t *testing.T) {
	// Single TCP flag.
	r := rule.Rule{
		Protocol: "tcp",
		CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
		Port:     80,
		Action:   "allow",
		Flags:    []string{"tcp:syn"},
	}
	spec, err := r.ToRulespec("test")
	if err != nil {
		t.Fatalf("ToRulespec: %v", err)
	}
	joined := strings.Join(spec, " ")
	if !strings.Contains(joined, "--tcp-flags SYN SYN") {
		t.Fatalf("expected --tcp-flags SYN SYN, got: %s", joined)
	}

	// Combined TCP flags.
	r2 := rule.Rule{
		Protocol: "tcp",
		CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
		Port:     80,
		Action:   "allow",
		Flags:    []string{"tcp:syn", "tcp:ack"},
	}
	spec2, err := r2.ToRulespec("test")
	if err != nil {
		t.Fatalf("ToRulespec: %v", err)
	}
	joined2 := strings.Join(spec2, " ")
	if !strings.Contains(joined2, "--tcp-flags SYN,ACK SYN,ACK") {
		t.Fatalf("expected --tcp-flags SYN,ACK SYN,ACK, got: %s", joined2)
	}

	// Negated TCP flag.
	r3 := rule.Rule{
		Protocol: "tcp",
		CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
		Port:     80,
		Action:   "allow",
		Flags:    []string{"!tcp:syn"},
	}
	spec3, err := r3.ToRulespec("test")
	if err != nil {
		t.Fatalf("ToRulespec: %v", err)
	}
	joined3 := strings.Join(spec3, " ")
	if !strings.Contains(joined3, "! --tcp-flags SYN SYN") {
		t.Fatalf("expected ! --tcp-flags SYN SYN, got: %s", joined3)
	}

	// TCP flag on ICMP rule → invalid.
	r4 := rule.Rule{
		Protocol: "icmp",
		CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
		Action:   "block",
		Flags:    []string{"tcp:syn"},
	}
	if err := r4.Validate(); err == nil {
		t.Error("expected tcp flag on icmp rule to be invalid")
	}
}

func TestTCPOptionToRulespec(t *testing.T) {
	r := rule.Rule{
		Protocol: "tcp",
		CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
		Port:     80,
		Action:   "allow",
		Flags:    []string{"tcpopt:30"},
	}
	spec, err := r.ToRulespec("test")
	if err != nil {
		t.Fatalf("ToRulespec: %v", err)
	}
	joined := strings.Join(spec, " ")
	if !strings.Contains(joined, "--tcp-option 30") {
		t.Fatalf("expected --tcp-option 30, got: %s", joined)
	}

	// Negated.
	r2 := rule.Rule{
		Protocol: "tcp",
		CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
		Port:     80,
		Action:   "allow",
		Flags:    []string{"!tcpopt:30"},
	}
	spec2, err := r2.ToRulespec("test")
	if err != nil {
		t.Fatalf("ToRulespec: %v", err)
	}
	joined2 := strings.Join(spec2, " ")
	if !strings.Contains(joined2, "! --tcp-option 30") {
		t.Fatalf("expected ! --tcp-option 30, got: %s", joined2)
	}
}

func TestMACSourceToRulespec(t *testing.T) {
	r := rule.Rule{
		Protocol: "tcp",
		CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
		Port:     80,
		Action:   "allow",
		Flags:    []string{"mac:00:11:22:33:44:55"},
	}
	spec, err := r.ToRulespec("test")
	if err != nil {
		t.Fatalf("ToRulespec: %v", err)
	}
	joined := strings.Join(spec, " ")
	if !strings.Contains(joined, "-m mac --mac-source 00:11:22:33:44:55") {
		t.Fatalf("expected -m mac --mac-source 00:11:22:33:44:55, got: %s", joined)
	}

	// Negated.
	r2 := rule.Rule{
		Protocol: "tcp",
		CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
		Port:     80,
		Action:   "allow",
		Flags:    []string{"!mac:00:11:22:33:44:55"},
	}
	spec2, err := r2.ToRulespec("test")
	if err != nil {
		t.Fatalf("ToRulespec: %v", err)
	}
	joined2 := strings.Join(spec2, " ")
	if !strings.Contains(joined2, "-m mac ! --mac-source 00:11:22:33:44:55") {
		t.Fatalf("expected -m mac ! --mac-source 00:11:22:33:44:55, got: %s", joined2)
	}

	// Invalid MAC → validation error.
	r3 := rule.Rule{
		Protocol: "tcp",
		CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
		Port:     80,
		Action:   "allow",
		Flags:    []string{"mac:invalid"},
	}
	if err := r3.Validate(); err == nil {
		t.Error("expected invalid MAC address to fail validation")
	}

	// Multiple MACs → error.
	r4 := rule.Rule{
		Protocol: "tcp",
		CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
		Port:     80,
		Action:   "allow",
		Flags:    []string{"mac:00:11:22:33:44:55", "mac:aa:bb:cc:dd:ee:ff"},
	}
	if err := r4.Validate(); err == nil {
		t.Error("expected multiple MAC sources to fail validation")
	}
}

func TestInterfaceToRulespec(t *testing.T) {
	r := rule.Rule{
		Protocol:             "tcp",
		CIDR:                 netip.MustParsePrefix("0.0.0.0/0"),
		Port:                 80,
		Action:               "allow",
		SourceInterface:      "eth0",
		DestinationInterface: "eth1",
	}
	spec, err := r.ToRulespec("test")
	if err != nil {
		t.Fatalf("ToRulespec: %v", err)
	}
	joined := strings.Join(spec, " ")
	if !strings.Contains(joined, "-i eth0") {
		t.Fatalf("expected -i eth0, got: %s", joined)
	}
	if !strings.Contains(joined, "-o eth1") {
		t.Fatalf("expected -o eth1, got: %s", joined)
	}

	// Verify interfaces appear before verdict (-j)
	iIdx := strings.Index(joined, "-i eth0")
	jIdx := strings.Index(joined, "-j")
	if iIdx > jIdx {
		t.Fatalf("expected -i before -j, -i at %d, -j at %d", iIdx, jIdx)
	}
}

func TestICMPTypeFlags(t *testing.T) {
	// Valid ICMP rule with icmp:echo-request
	validICMP := rule.Rule{
		Protocol: "icmp",
		CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
		Action:   "allow",
		Flags:    []string{"icmp:echo-request"},
	}
	if err := validICMP.Validate(); err != nil {
		t.Errorf("expected icmp rule with echo-request to be valid: %v", err)
	}

	// Valid ICMPv6 rule with icmpv6:echo-request
	validICMPv6 := rule.Rule{
		Protocol: "icmpv6",
		CIDR:     netip.MustParsePrefix("::/0"),
		Action:   "allow",
		Flags:    []string{"icmpv6:echo-request"},
	}
	if err := validICMPv6.Validate(); err != nil {
		t.Errorf("expected icmpv6 rule with echo-request to be valid: %v", err)
	}

	// ICMP type on TCP rule → error
	icmpOnTCP := rule.Rule{
		Protocol: "tcp",
		CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
		Port:     80,
		Action:   "allow",
		Flags:    []string{"icmp:echo-request"},
	}
	if err := icmpOnTCP.Validate(); err == nil {
		t.Error("expected icmp type flag on tcp rule to be invalid")
	}

	// Unknown ICMP type → error
	unknownType := rule.Rule{
		Protocol: "icmp",
		CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
		Action:   "allow",
		Flags:    []string{"icmp:nonexistent"},
	}
	if err := unknownType.Validate(); err == nil {
		t.Error("expected unknown icmp type to be invalid")
	}

	// Multiple ICMP types → error
	multiType := rule.Rule{
		Protocol: "icmp",
		CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
		Action:   "allow",
		Flags:    []string{"icmp:echo-request", "icmp:echo-reply"},
	}
	if err := multiType.Validate(); err == nil {
		t.Error("expected multiple icmp types to be invalid")
	}
}
