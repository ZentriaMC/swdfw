package chain

import (
	"context"
	"io"

	"github.com/ZentriaMC/swdfw/internal/cmdchain"
	"github.com/ZentriaMC/swdfw/internal/rule"
)

type ChainManager interface {
	io.Closer
	ConfigureChain(ctx context.Context, name, parentChain, jumpTo string, rules []rule.Rule) (err error)
	InstallBaseChain(ctx context.Context, name, parentChain string) (err error)
	DeleteChain(ctx context.Context, name string) (err error)
}

type ChainManagerOpt func(ChainManager)

func NewChainManager(opts ...ChainManagerOpt) (c ChainManager) {
	cm := &ChainManagerIPTables{
		chainManagerBase: chainManagerBase{
			executor:      cmdchain.DefaultChainExecutor,
			executeChecks: true,
			protocols: map[rule.Protocol]bool{
				rule.ProtocolIPv4: true,
				rule.ProtocolIPv6: true,
			},
		},
	}

	for _, opt := range opts {
		opt(cm)
	}
	return cm
}

func WithCustomExecutor(executor cmdchain.Executor) ChainManagerOpt {
	return func(c ChainManager) {
		c.(chainManagerBaseGetter).Mut(func(cm *chainManagerBase) {
			cm.executor = executor
		})
	}
}

func WithProtocols(enabledProtocols ...rule.Protocol) ChainManagerOpt {
	return func(c ChainManager) {
		c.(chainManagerBaseGetter).Mut(func(cm *chainManagerBase) {
			// Clear existing values
			for k := range cm.protocols {
				delete(cm.protocols, k)
			}

			for _, enabled := range enabledProtocols {
				cm.protocols[enabled] = true
			}
		})
	}
}

// WithChecks sets if ChainManager should run commands to check for existing rules before creating anything.
// Makes sense to disable when custom executor is not touching state right away
func WithChecks(check bool) ChainManagerOpt {
	return func(c ChainManager) {
		c.(chainManagerBaseGetter).Mut(func(cm *chainManagerBase) {
			cm.executeChecks = check
		})
	}
}

type chainManagerBase struct {
	executor      cmdchain.Executor
	executeChecks bool
	protocols     map[rule.Protocol]bool
}

type chainManagerBaseGetter interface {
	Mut(f func(*chainManagerBase))
}

func (c *chainManagerBase) Mut(f func(*chainManagerBase)) {
	f(c)
}
