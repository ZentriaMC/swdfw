package chain_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/ZentriaMC/swdfw/internal/chain"
	"github.com/ZentriaMC/swdfw/internal/cmdchain"
	"github.com/ZentriaMC/swdfw/internal/rule"
)

func TestChain(t *testing.T) {
	sg := cmdchain.NewShellScriptGenerator("#!/bin/sh")
	c, err := chain.NewChainManager(
		chain.WithCustomExecutor(sg.Executor()),
		chain.WithProtocols(rule.ProtocolIPv4),
		chain.VerifyIPTablesPath(false),
	)
	if err != nil {
		t.Fatalf("failed to initialize chainmanager: %s", err)
	}

	defer func() {
		cerr := c.Close()
		if cerr != nil {
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
	err = c.InstallBaseChain(ctx, base, "INPUT")
	if err != nil {
		t.Fatalf("failed to install base chain: %s", err)
	}

	err = c.ConfigureChain(ctx, "basicrules", base, "", rules)
	if err != nil {
		t.Fatalf("failed to replace chain: %s", err)
	}

	script := sg.Script()
	fmt.Println(script)
}
