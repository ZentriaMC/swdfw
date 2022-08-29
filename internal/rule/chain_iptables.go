package rule

import (
	"context"
	"fmt"
	"time"

	"github.com/ZentriaMC/swdfw/internal/chain"
	"go.uber.org/multierr"
	"go.uber.org/zap"
)

type ChainManagerIPTables struct {
	chainManagerBase
}

func (c *ChainManagerIPTables) createChain(ctx context.Context, realName, tempName, jumpTo string, rules []Rule) (err error) {
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

func (c *ChainManagerIPTables) DeleteChain(ctx context.Context, name string) (err error) {
	for proto := range c.protocols {
		rerr := chain.NewCommandChain(ctx, "chain-delete").
			WithExecutor(c.executor).
			WithEnableChecks(c.executeChecks).
			WithCheck("chain-exists", func(cc chain.CommandChain) chain.CommandChain {
				// TODO: silence this
				return cc.
					WithErrInterceptor(IPTablesIsErrNotExist(true)).
					Args(c.cmdChainExists(proto, "filter", name)...)
			}).
			ArgsGroup(
				func(cc chain.CommandChain) chain.CommandChain {
					return cc.
						WithName("flush-chain").
						Args(c.iptables(proto, "filter", "-F", name)...)
				},
				func(cc chain.CommandChain) chain.CommandChain {
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

func (c *ChainManagerIPTables) ConfigureChain(ctx context.Context, name, parentChain, jumpTo string, rules []Rule) (err error) {
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
		rerr := chain.NewCommandChain(ctx, proto.Prog()).
			WithExecutor(c.executor).
			WithEnableChecks(c.executeChecks).
			WithCheck("parent-rule-exists", func(cc chain.CommandChain) chain.CommandChain {
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
