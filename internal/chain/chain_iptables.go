package chain

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/multierr"

	"github.com/ZentriaMC/swdfw/internal/cmdchain"
	"github.com/ZentriaMC/swdfw/internal/rule"
)

type ChainManagerIPTables struct {
	*chainManagerBase

	iptablesPath       string
	ip6tablesPath      string
	verifyIptablesPath bool
	nftWorkaround      bool
}

func newChainManagerIPTables(base *chainManagerBase) (c *ChainManagerIPTables) {
	c = &ChainManagerIPTables{
		chainManagerBase:   base,
		iptablesPath:       "iptables",
		ip6tablesPath:      "ip6tables",
		verifyIptablesPath: false,
		nftWorkaround:      false,
	}
	return
}

func (c *ChainManagerIPTables) init() (err error) {
	// TODO: c.verifyIptablesPath
	return
}

func (c *ChainManagerIPTables) ConfigureChain(ctx context.Context, name, parentChain, jumpTo string, rules []rule.Rule) (err error) {
	tempName := fmt.Sprintf("%s:%d", name, time.Now().Unix()&0xFFFF)
	if err = c.createChain(ctx, name, tempName, jumpTo, rules); err != nil {
		return
	}

	// Insert new chain jump before old one
	_ = c.runAllProtocols(ctx, "filter", "-I", parentChain, "-g", tempName)

	// Remove old chain references
	_ = c.runAllProtocols(ctx, "filter", "-D", parentChain, "-g", name)

	if err = c.DeleteChain(ctx, name); err != nil {
		err = fmt.Errorf("failed to clean up old rules: %w", err)
		// TODO: not fatal
		return
	}
	err = c.runAllProtocols(ctx, "filter", "-E", tempName, name)
	return
}

func (c *ChainManagerIPTables) InstallBaseChain(ctx context.Context, name, parentChain string) (err error) {
	if err = c.createChainIfNotExists(ctx, "filter", name); err != nil {
		return
	}

	jump := []string{"-j", name}
	for proto := range c.protocols {
		rerr := cmdchain.NewCommandChain(ctx, c.prog(proto)).
			WithExecutor(c.executor).
			WithEnableChecks(c.executeChecks).
			WithCheck("parent-rule-exists", func(cc cmdchain.CommandChain) cmdchain.CommandChain {
				return cc.WithErrInterceptor(IPTablesIsErrNotExist(false)).
					WithNegated(true).
					Args(c.cmdRuleExists(proto, "filter", parentChain, jump...)...)
			}).
			Args(c.iptables(proto, "filter", "-A", parentChain, jump...)...).
			Run()

		err = multierr.Append(err, rerr)
	}

	return
}

func (c *ChainManagerIPTables) DeleteChain(ctx context.Context, name string) (err error) {
	for proto := range c.protocols {
		cch := cmdchain.NewCommandChain(ctx, "chain-delete").
			WithExecutor(c.executor).
			WithEnableChecks(c.executeChecks)

		if c.nftWorkaround {
			cch = cch.WithErrInterceptor(IPTablesIsErrNotExist(false))
		} else {
			cch = cch.WithCheck("chain-check", func(cc cmdchain.CommandChain) cmdchain.CommandChain {
				return c.checkChainExists(cc, proto, "filter", name, true)
			})
		}

		rerr := cch.ArgsGroup(
			func(cc cmdchain.CommandChain) cmdchain.CommandChain {
				return cc.
					WithName("flush-chain").
					Args(c.iptables(proto, "filter", "-F", name)...)
			},
			func(cc cmdchain.CommandChain) cmdchain.CommandChain {
				return cc.
					WithName("delete-chain").
					Args(c.iptables(proto, "filter", "-X", name)...)
			},
		).Run()
		err = multierr.Append(err, rerr)
	}
	return
}

func (c *ChainManagerIPTables) Close() (err error) {
	// no-op
	return
}
