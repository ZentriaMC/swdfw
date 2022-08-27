package rule

import (
	"context"
	"fmt"
	"time"

	"github.com/ZentriaMC/swdfw/internal/chain"
	"go.uber.org/multierr"
	"go.uber.org/zap"
)

type ChainManager struct {
	executor      chain.Executor
	executeChecks bool
	protocols     map[Protocol]bool
}

type ChainManagerOpt func(*ChainManager)

func NewChainManager(opts ...ChainManagerOpt) (cm *ChainManager) {
	cm = &ChainManager{
		executor:      chain.DefaultChainExecutor,
		executeChecks: true,
		protocols: map[Protocol]bool{
			ProtocolIPv4: true,
			ProtocolIPv6: true,
		},
	}

	for _, opt := range opts {
		opt(cm)
	}
	return
}

func WithCustomExecutor(executor chain.Executor) ChainManagerOpt {
	return func(cm *ChainManager) {
		cm.executor = executor
	}
}

func WithProtocols(enabledProtocols ...Protocol) ChainManagerOpt {
	return func(cm *ChainManager) {
		// Clear existing values
		for k := range cm.protocols {
			delete(cm.protocols, k)
		}

		for _, enabled := range enabledProtocols {
			cm.protocols[enabled] = true
		}
	}
}

// WithChecks sets if ChainManager should run commands to check for existing rules before creating anything.
// Makes sense to disable when custom executor is not touching state right away
func WithChecks(check bool) ChainManagerOpt {
	return func(cm *ChainManager) {
		cm.executeChecks = check
	}
}

func (c *ChainManager) CreateChain(ctx context.Context, name, jumpTo string, rules []Rule) (err error) {
	if err = c.createChainIfNotExists(ctx, "filter", name); err != nil {
		err = fmt.Errorf("failed to create a firewall chain: %w", err)
		return
	}

	defer func() {
		if err != nil {
			derr := c.DeleteChain(context.Background(), name)
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

		if rulespec, rerr = rule.ToRulespec(); rerr != nil {
			err = multierr.Append(err, rerr)
			continue
		}

		err = multierr.Append(err, c.runProtocol(ctx, proto, "filter", "-A", name, rulespec...))
	}

	if jumpTo != "" {
		cerr := c.runAllProtocols(ctx, "filter", "-A", name, "-g", jumpTo)
		err = multierr.Append(err, cerr)
	}

	return
}

func (c *ChainManager) DeleteChain(ctx context.Context, name string) (err error) {
	for proto := range c.protocols {
		rerr := chain.NewCommandChain(ctx, "chain-delete").
			WithExecutor(c.executor).
			WithEnableChecks(c.executeChecks).
			WithCheck("chain-exists", func(cc chain.CommandChain) chain.CommandChain {
				// TODO: silence this
				return cc.
					WithErrInterceptor(IPTablesIsErrNotExist(true)).
					Args(c.chainExists(proto, "filter", name)...)
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

func (c *ChainManager) ReplaceChain(ctx context.Context, name, parentChain, jumpTo string, rules []Rule) (err error) {
	tempName := fmt.Sprintf("%s-new%d", name, time.Now().UnixMilli())
	if err = c.CreateChain(ctx, tempName, jumpTo, rules); err != nil {
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

func (c *ChainManager) InstallBaseChain(ctx context.Context, name, parentChain string) (err error) {
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
					Args(c.ruleExists(proto, "filter", parentChain, jump...)...)
			}).
			Args(c.iptables(proto, "filter", "-A", parentChain, jump...)...).
			Run()

		err = multierr.Append(err, rerr)
	}

	return
}
