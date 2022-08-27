package rule

import (
	"context"

	"github.com/ZentriaMC/swdfw/internal/chain"
	"go.uber.org/multierr"
)

func (c *ChainManager) iptables(proto Protocol, table, action, chainName string, args ...string) []string {
	return append([]string{proto.Prog(), "--wait", "1", "-t", table, action, chainName}, args...)
}

func (c *ChainManager) chainExists(proto Protocol, table string, chain string) []string {
	return c.iptables(proto, table, "-S", chain, "1")
}

func (c *ChainManager) ruleExists(proto Protocol, table string, chain string, rulespec ...string) []string {
	return c.iptables(proto, table, "-C", chain, rulespec...)
}

func (c *ChainManager) createChain(proto Protocol, table string, chain string) []string {
	return c.iptables(proto, table, "-N", chain)
}

func (c *ChainManager) runProtocol(ctx context.Context, proto Protocol, table, action, chainName string, args ...string) (err error) {
	return chain.NewCommandChain(ctx, proto.Prog()).
		WithErrInterceptor(IPTablesIsErrAlreadyExist(false)).
		WithExecutor(c.executor).
		WithEnableChecks(c.executeChecks).
		Args(c.iptables(proto, table, action, chainName, args...)...).
		Run()
}

func (c *ChainManager) runAllProtocols(ctx context.Context, table, action, chainName string, args ...string) (err error) {
	for proto := range c.protocols {
		perr := c.runProtocol(ctx, proto, table, action, chainName, args...)
		err = multierr.Append(err, perr)
	}
	return
}

func (c *ChainManager) createChainIfNotExists(ctx context.Context, table string, chainName string) (err error) {
	for proto := range c.protocols {
		rerr := chain.NewCommandChain(ctx, proto.Prog()).
			WithExecutor(c.executor).
			WithEnableChecks(c.executeChecks).
			WithCheck("chain-check", func(cc chain.CommandChain) chain.CommandChain {
				// TODO: silence this
				return cc.WithErrInterceptor(IPTablesIsErrNotExist(false)).
					WithNegated(true).
					Args(c.chainExists(proto, table, chainName)...)
			}).
			Args(c.createChain(proto, table, chainName)...).
			Run()

		err = multierr.Append(err, rerr)
	}
	return
}
