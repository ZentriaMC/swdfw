package rule_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ZentriaMC/swdfw/internal/rule"
)

func TestSimpleRule(t *testing.T) {
	rules := []rule.Rule{
		{
			Protocol: "tcp",
			CIDR:     "10.123.0.1/24",
			Port:     22,
			Action:   "allow",
		},
		{
			Protocol:  "tcp",
			CIDR:      "0.0.0.0/0",
			Action:    "allow",
			StartPort: 1024,
			EndPort:   4096,
		},
		{
			Protocol: "icmp",
			CIDR:     "10.124.0.0/24",
			Action:   "allow",
		},
		{
			Protocol: "icmp",
			CIDR:     "0.0.0.0/0",
			Action:   "block",
		},
		{
			Protocol: "tcp",
			CIDR:     "0.0.0.0/0",
			Action:   "block",
		},
	}

	var strRules []string
	for _, r := range rules {
		rules, err := r.ToRulespec()
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
		CIDR:     "10.123.0.1/24",
		Port:     22,
		Action:   "allow",
		Flags: []string{
			"TCPOPT:30", // Allow MPTCP
		},
	}

	invalidMultiTCPOptRule := rule.Rule{
		Protocol: "tcp",
		CIDR:     "10.123.0.1/24",
		Port:     3066,
		Action:   "block",
		Flags: []string{
			"TCPOPT:30", // Block MPTCP
			"TCPOPT:36", // Block TCP Fast Open
		},
	}

	tcpFlagsInICMPRule := rule.Rule{
		Protocol: "icmp",
		CIDR:     "0.0.0.0/0",
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
