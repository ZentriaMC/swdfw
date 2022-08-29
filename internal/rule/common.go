package rule

import (
	"context"

	"go.uber.org/multierr"

	"github.com/ZentriaMC/swdfw/internal/cmdchain"
)

func (c *ChainManagerIPTables) iptables(proto Protocol, table, action, chainName string, args ...string) []string {
	return append([]string{proto.Prog(), "--wait", "1", "-t", table, action, chainName}, args...)
}

func (c *ChainManagerIPTables) cmdChainExists(proto Protocol, table string, chain string) []string {
	return c.iptables(proto, table, "-S", chain, "1")
}

func (c *ChainManagerIPTables) cmdRuleExists(proto Protocol, table string, chain string, rulespec ...string) []string {
	return c.iptables(proto, table, "-C", chain, rulespec...)
}

func (c *ChainManagerIPTables) cmdCreateChain(proto Protocol, table string, chain string) []string {
	return c.iptables(proto, table, "-N", chain)
}

func (c *ChainManagerIPTables) runProtocol(ctx context.Context, proto Protocol, table, action, chainName string, args ...string) (err error) {
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
				// TODO: silence this
				return cc.WithErrInterceptor(IPTablesIsErrNotExist(false)).
					WithNegated(true).
					Args(c.cmdChainExists(proto, table, chainName)...)
			}).
			Args(c.cmdCreateChain(proto, table, chainName)...).
			Run()

		err = multierr.Append(err, rerr)
	}
	return
}
