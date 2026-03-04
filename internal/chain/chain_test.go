package chain_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/ZentriaMC/swdfw/internal/chain"
	"github.com/ZentriaMC/swdfw/internal/rule"
)

func TestChain(t *testing.T) {
	var commands []string
	recorder := chain.Executor(func(ctx context.Context, args ...string) error {
		commands = append(commands, strings.Join(args, " "))
		return nil
	})

	c, err := chain.NewIPTablesManager(
		chain.WithCustomExecutor(recorder),
		chain.WithProtocols(rule.ProtocolIPv4),
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
			Protocol:  "tcpv6",
			CIDR:      "::/0",
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

	ctx := context.Background()
	base := "SWDFW-INPUT"
	err = c.AddBaseChain(ctx, base, chain.HookInput)
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

func TestChainWithSets(t *testing.T) {
	var commands []string
	recorder := chain.Executor(func(ctx context.Context, args ...string) error {
		commands = append(commands, strings.Join(args, " "))
		return nil
	})

	c, err := chain.NewIPTablesManager(
		chain.WithCustomExecutor(recorder),
		chain.WithProtocols(rule.ProtocolIPv4),
		chain.WithChecks(false),
	)
	if err != nil {
		t.Fatalf("failed to initialize chainmanager: %s", err)
	}
	defer c.Close()

	ctx := context.Background()

	// Type-assert to SetManager.
	sm, ok := c.(chain.SetManager)
	if !ok {
		t.Fatal("ChainManagerIPTables does not implement SetManager")
	}

	// ConfigureSet should produce ipset commands.
	if err := sm.ConfigureSet(ctx, "trusted", []string{"10.0.0.0/24", "192.168.1.0/24"}); err != nil {
		t.Fatalf("ConfigureSet: %v", err)
	}

	// Verify ipset create, flush, add commands were recorded.
	hasCreate := false
	hasFlush := false
	addCount := 0
	for _, cmd := range commands {
		if strings.Contains(cmd, "ipset create trusted") {
			hasCreate = true
		}
		if strings.Contains(cmd, "ipset flush trusted") {
			hasFlush = true
		}
		if strings.Contains(cmd, "ipset add trusted") {
			addCount++
		}
	}
	if !hasCreate {
		t.Error("expected ipset create command")
	}
	if !hasFlush {
		t.Error("expected ipset flush command")
	}
	if addCount != 2 {
		t.Errorf("expected 2 ipset add commands, got %d", addCount)
	}

	// ConfigureChain with SourceSet rule should produce -m set --match-set.
	commands = nil // reset

	base := "SWDFW-INPUT"
	if err := c.AddBaseChain(ctx, base, chain.HookInput); err != nil {
		t.Fatalf("AddBaseChain: %v", err)
	}

	rules := []rule.Rule{
		{
			Protocol:  "tcp",
			CIDR:      "0.0.0.0/0",
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
