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
