package chain

import (
	"context"
	"io"
	"net/netip"

	"github.com/ZentriaMC/swdfw/rule"
)

// Hook represents a netfilter hook point.
type Hook int

const (
	HookInput Hook = iota
	HookOutput
	HookForward
)

type ChainManager interface {
	io.Closer
	AddBaseChain(ctx context.Context, name string, hook Hook) error
	ConfigureChain(ctx context.Context, name, parentChain, jumpTo string, rules []rule.Rule) (err error)
	DeleteChain(ctx context.Context, name string) (err error)
}

// SetManager manages named IP sets that rules can reference via SourceSet.
type SetManager interface {
	ConfigureSet(ctx context.Context, name string, cidrs []netip.Prefix) error
	DeleteSet(ctx context.Context, name string) error
}

type ChainManagerOpt func(ChainManager)

// NewIPTablesManager creates a ChainManager backed by iptables.
func NewIPTablesManager(opts ...ChainManagerOpt) (ChainManager, error) {
	cm := newChainManagerIPTables(&chainManagerBase{
		executor:      DefaultExecutor,
		executeChecks: true,
		protocols: map[rule.Family]bool{
			rule.FamilyIPv4: true,
			rule.FamilyIPv6: true,
		},
		quirks: map[Quirk]bool{},
	})

	for _, opt := range opts {
		opt(cm)
	}

	err := cm.init()
	return cm, err
}

// NewChainManager creates a ChainManager backed by iptables.
// Deprecated: Use NewIPTablesManager instead.
func NewChainManager(opts ...ChainManagerOpt) (c ChainManager, err error) {
	return NewIPTablesManager(opts...)
}

func WithCustomExecutor(executor Executor) ChainManagerOpt {
	return func(c ChainManager) {
		c.(chainManagerBaseGetter).Mut(func(cm *chainManagerBase) {
			cm.executor = executor
		})
	}
}

func WithFamilies(enabledProtocols ...rule.Family) ChainManagerOpt {
	return func(c ChainManager) {
		c.(chainManagerBaseGetter).Mut(func(cm *chainManagerBase) {
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
func WithChecks(check bool) ChainManagerOpt {
	return func(c ChainManager) {
		c.(chainManagerBaseGetter).Mut(func(cm *chainManagerBase) {
			cm.executeChecks = check
		})
	}
}

type chainManagerBase struct {
	executor      Executor
	executeChecks bool
	protocols     map[rule.Family]bool
	quirks        map[Quirk]bool
}

type chainManagerBaseGetter interface {
	Mut(f func(*chainManagerBase))
}

func (c *chainManagerBase) Mut(f func(*chainManagerBase)) {
	f(c)
}
