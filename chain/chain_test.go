package chain_test

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/ZentriaMC/swdfw/chain"
	"github.com/ZentriaMC/swdfw/rule"
)

func TestChain(t *testing.T) {
	var commands []string
	recorder := chain.Executor(func(ctx context.Context, args ...string) error {
		commands = append(commands, strings.Join(args, " "))
		return nil
	})

	c, err := chain.NewIPTablesManager(
		chain.WithCustomExecutor(recorder),
		chain.WithFamilies(rule.FamilyIPv4),
		chain.WithChecks(false),
	)
	if err != nil {
		t.Fatalf("failed to initialize chainmanager: %s", err)
	}

	defer func() {
		if cerr := c.Close(); cerr != nil {
			t.Logf("failed to close chainmanager: %s", cerr)
		}
	}()

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
			Protocol:  "tcpv6",
			CIDR:      netip.MustParsePrefix("::/0"),
			Action:    "allow",
			StartPort: 1024,
			EndPort:   4096,
		},
		{
			Protocol: "tcp",
			CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
			Action:   "block",
		},
	}

	ctx := context.Background()
	base := "SWDFW-INPUT"
	err = c.AddBaseChain(ctx, base, chain.HookInput, chain.PolicyAccept)
	if err != nil {
		t.Fatalf("failed to install base chain: %s", err)
	}

	err = c.ConfigureChain(ctx, "basicrules", base, "", rules)
	if err != nil {
		t.Fatalf("failed to replace chain: %s", err)
	}

	for _, cmd := range commands {
		fmt.Println(cmd)
	}
}

func TestAddBaseChainPolicyDrop(t *testing.T) {
	var commands []string
	recorder := chain.Executor(func(ctx context.Context, args ...string) error {
		commands = append(commands, strings.Join(args, " "))
		return nil
	})

	c, err := chain.NewIPTablesManager(
		chain.WithCustomExecutor(recorder),
		chain.WithFamilies(rule.FamilyIPv4),
		chain.WithChecks(false),
	)
	if err != nil {
		t.Fatalf("failed to initialize chainmanager: %s", err)
	}
	defer func() { _ = c.Close() }()

	ctx := context.Background()
	if err := c.AddBaseChain(ctx, "SWDFW-INPUT", chain.HookInput, chain.PolicyDrop); err != nil {
		t.Fatalf("AddBaseChain: %v", err)
	}

	foundPolicy := false
	for _, cmd := range commands {
		if strings.Contains(cmd, "-P INPUT DROP") {
			foundPolicy = true
			break
		}
	}
	if !foundPolicy {
		t.Error("expected iptables -P INPUT DROP command")
		for _, cmd := range commands {
			t.Log(cmd)
		}
	}
}

func TestConfigureChainAppendGotoFailure(t *testing.T) {
	var commands []string
	failOnAppend := chain.Executor(func(ctx context.Context, args ...string) error {
		cmd := strings.Join(args, " ")
		commands = append(commands, cmd)
		// Fail when appending a goto to the parent chain (the temp name contains ":").
		if strings.Contains(cmd, "-A SWDFW-INPUT -g ") && strings.Contains(cmd, ":") {
			return fmt.Errorf("simulated append failure")
		}
		return nil
	})

	c, err := chain.NewIPTablesManager(
		chain.WithCustomExecutor(failOnAppend),
		chain.WithFamilies(rule.FamilyIPv4),
		chain.WithChecks(false),
	)
	if err != nil {
		t.Fatalf("failed to initialize chainmanager: %s", err)
	}
	defer func() { _ = c.Close() }()

	ctx := context.Background()
	base := "SWDFW-INPUT"
	if err := c.AddBaseChain(ctx, base, chain.HookInput, chain.PolicyAccept); err != nil {
		t.Fatalf("AddBaseChain: %v", err)
	}

	rules := []rule.Rule{
		{
			Protocol: "tcp",
			CIDR:     netip.MustParsePrefix("10.0.0.0/24"),
			Port:     22,
			Action:   "allow",
		},
	}

	err = c.ConfigureChain(ctx, "myrules", base, "", rules)
	if err == nil {
		t.Fatal("expected error from ConfigureChain when append-goto fails")
	}
	if !strings.Contains(err.Error(), "appending goto") {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the temp chain was cleaned up (flush + delete).
	hasFlushTemp := false
	hasDeleteTemp := false
	for _, cmd := range commands {
		if strings.Contains(cmd, "-F myrules:") {
			hasFlushTemp = true
		}
		if strings.Contains(cmd, "-X myrules:") {
			hasDeleteTemp = true
		}
	}
	if !hasFlushTemp {
		t.Error("expected temp chain to be flushed on failure")
	}
	if !hasDeleteTemp {
		t.Error("expected temp chain to be deleted on failure")
	}

	// Verify the old goto was NOT deleted (no -D for the real chain name).
	for _, cmd := range commands {
		if strings.Contains(cmd, "-D SWDFW-INPUT -g myrules") && !strings.Contains(cmd, "myrules:") {
			t.Error("should not delete old goto when append-goto failed")
		}
	}
}

func TestChainWithSets(t *testing.T) {
	var commands []string
	recorder := chain.Executor(func(ctx context.Context, args ...string) error {
		commands = append(commands, strings.Join(args, " "))
		return nil
	})

	c, err := chain.NewIPTablesManager(
		chain.WithCustomExecutor(recorder),
		chain.WithFamilies(rule.FamilyIPv4),
		chain.WithChecks(false),
	)
	if err != nil {
		t.Fatalf("failed to initialize chainmanager: %s", err)
	}
	defer func() { _ = c.Close() }()

	ctx := context.Background()

	// Type-assert to SetManager.
	sm, ok := c.(chain.SetManager)
	if !ok {
		t.Fatal("ChainManagerIPTables does not implement SetManager")
	}

	// ConfigureSet should produce ipset commands.
	if err := sm.ConfigureSet(ctx, "trusted", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("192.168.1.0/24")}); err != nil {
		t.Fatalf("ConfigureSet: %v", err)
	}

	// Verify atomic swap: create temp, add CIDRs, create real, swap, destroy.
	hasCreateTemp := false
	hasCreateReal := false
	hasSwap := false
	hasDestroy := false
	addCount := 0
	for _, cmd := range commands {
		if strings.Contains(cmd, "ipset create trusted:") {
			hasCreateTemp = true
		}
		if strings.Contains(cmd, "ipset create trusted hash:net") && !strings.Contains(cmd, "trusted:") {
			hasCreateReal = true
		}
		if strings.Contains(cmd, "ipset swap") {
			hasSwap = true
		}
		if strings.Contains(cmd, "ipset destroy trusted:") {
			hasDestroy = true
		}
		if strings.Contains(cmd, "ipset add trusted:") {
			addCount++
		}
	}
	if !hasCreateTemp {
		t.Error("expected ipset create command for temp set")
	}
	if !hasCreateReal {
		t.Error("expected ipset create command for real set")
	}
	if !hasSwap {
		t.Error("expected ipset swap command")
	}
	if !hasDestroy {
		t.Error("expected ipset destroy command for old set")
	}
	if addCount != 2 {
		t.Errorf("expected 2 ipset add commands, got %d", addCount)
	}

	// ConfigureChain with SourceSet rule should produce -m set --match-set.
	commands = nil // reset

	base := "SWDFW-INPUT"
	if err := c.AddBaseChain(ctx, base, chain.HookInput, chain.PolicyAccept); err != nil {
		t.Fatalf("AddBaseChain: %v", err)
	}

	rules := []rule.Rule{
		{
			Protocol:  "tcp",
			CIDR:      netip.MustParsePrefix("0.0.0.0/0"),
			Port:      443,
			Action:    "allow",
			SourceSet: "trusted",
		},
	}

	if err := c.ConfigureChain(ctx, "setrules", base, "", rules); err != nil {
		t.Fatalf("ConfigureChain: %v", err)
	}

	foundMatchSet := false
	for _, cmd := range commands {
		if strings.Contains(cmd, "--match-set trusted src") {
			foundMatchSet = true
			break
		}
	}
	if !foundMatchSet {
		t.Error("expected -m set --match-set in iptables commands")
		for _, cmd := range commands {
			t.Log(cmd)
		}
	}
}
