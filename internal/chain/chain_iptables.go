package chain

import (
	"context"
	"fmt"
	"io"
	"time"

	"go.uber.org/multierr"

	"github.com/ZentriaMC/swdfw/internal/cmdchain"
	"github.com/ZentriaMC/swdfw/internal/rule"
)

type ChainManagerIPTables struct {
	chainManagerBase
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
		rerr := cmdchain.NewCommandChain(ctx, proto.Prog()).
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
		rerr := cmdchain.NewCommandChain(ctx, "chain-delete").
			WithExecutor(c.executor).
			WithEnableChecks(c.executeChecks).
			WithCheck("chain-exists", func(cc cmdchain.CommandChain) cmdchain.CommandChain {
				return cc.
					WithOutput(io.Discard, nil).
					WithErrInterceptor(IPTablesIsErrNotExist(true)).
					Args(c.cmdChainExists(proto, "filter", name)...)
			}).
			ArgsGroup(
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
			).
			Run()
		err = multierr.Append(err, rerr)
	}
	return
}

func (c *ChainManagerIPTables) Close() (err error) {
	// no-op
	return
}
