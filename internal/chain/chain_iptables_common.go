package chain

import (
	"context"
	"fmt"
	"io"

	"go.uber.org/multierr"
	"go.uber.org/zap"

	"github.com/ZentriaMC/swdfw/internal/cmdchain"
	"github.com/ZentriaMC/swdfw/internal/rule"
)

func (c *ChainManagerIPTables) iptables(proto rule.Protocol, table, action, chainName string, args ...string) []string {
	return append([]string{proto.Prog(), "--wait", "1", "-t", table, action, chainName}, args...)
}

func (c *ChainManagerIPTables) cmdChainExists(proto rule.Protocol, table string, chain string) []string {
	return c.iptables(proto, table, "-S", chain, "1")
}

func (c *ChainManagerIPTables) cmdRuleExists(proto rule.Protocol, table string, chain string, rulespec ...string) []string {
	return c.iptables(proto, table, "-C", chain, rulespec...)
}

func (c *ChainManagerIPTables) cmdCreateChain(proto rule.Protocol, table string, chain string) []string {
	return c.iptables(proto, table, "-N", chain)
}

func (c *ChainManagerIPTables) runProtocol(ctx context.Context, proto rule.Protocol, table, action, chainName string, args ...string) (err error) {
	return cmdchain.NewCommandChain(ctx, proto.Prog()).
		WithErrInterceptor(IPTablesIsErrAlreadyExist(false)).
		WithExecutor(c.executor).
		WithEnableChecks(c.executeChecks).
		Args(c.iptables(proto, table, action, chainName, args...)...).
		Run()
}

func (c *ChainManagerIPTables) runAllProtocols(ctx context.Context, table, action, chainName string, args ...string) (err error) {
	for proto := range c.protocols {
		perr := c.runProtocol(ctx, proto, table, action, chainName, args...)
		err = multierr.Append(err, perr)
	}
	return
}

func (c *ChainManagerIPTables) createChainIfNotExists(ctx context.Context, table string, chainName string) (err error) {
	for proto := range c.protocols {
		rerr := cmdchain.NewCommandChain(ctx, proto.Prog()).
			WithExecutor(c.executor).
			WithEnableChecks(c.executeChecks).
			WithCheck("chain-check", func(cc cmdchain.CommandChain) cmdchain.CommandChain {
				return cc.WithErrInterceptor(IPTablesIsErrNotExist(false)).
					WithOutput(io.Discard, nil).
					WithNegated(true).
					Args(c.cmdChainExists(proto, table, chainName)...)
			}).
			Args(c.cmdCreateChain(proto, table, chainName)...).
			Run()

		err = multierr.Append(err, rerr)
	}
	return
}

func (c *ChainManagerIPTables) createChain(ctx context.Context, realName, tempName, jumpTo string, rules []rule.Rule) (err error) {
	if err = c.createChainIfNotExists(ctx, "filter", tempName); err != nil {
		err = fmt.Errorf("failed to create a firewall chain: %w", err)
		return
	}

	defer func() {
		if err != nil {
			derr := c.DeleteChain(context.Background(), tempName)
			if derr != nil {
				zap.L().Error("failed to delete chain", zap.Error(err))
			}
		}
	}()

	var rulespec []string
	var rerr error
	for _, rule := range rules {
		proto := rule.Proto()
		if _, ok := c.protocols[proto]; !ok {
			continue
		}

		if rulespec, rerr = rule.ToRulespec(realName); rerr != nil {
			err = multierr.Append(err, rerr)
			continue
		}

		err = multierr.Append(err, c.runProtocol(ctx, proto, "filter", "-A", tempName, rulespec...))
	}

	if jumpTo != "" {
		cerr := c.runAllProtocols(ctx, "filter", "-A", tempName, "-g", jumpTo)
		err = multierr.Append(err, cerr)
	}

	return
}
