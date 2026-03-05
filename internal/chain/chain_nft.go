//go:build linux

package chain

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"

	"github.com/ZentriaMC/swdfw/internal/rule"
)

var hookToNFTables = map[Hook]nftables.ChainHook{
	HookInput:   *nftables.ChainHookInput,
	HookOutput:  *nftables.ChainHookOutput,
	HookForward: *nftables.ChainHookForward,
}

type chainState struct {
	rules       []rule.Rule
	parentChain string
	jumpTo      string
}

type setDef struct {
	cidrs []netip.Prefix
	v6    bool
}

type ChainManagerNFTables struct {
	*chainManagerBase

	tableName string
	conn      *nftables.Conn

	baseChains map[string]Hook
	chains     map[string]chainState
	chainOrder []string
	sets       map[string]setDef
}

// NewNFTablesManager creates a ChainManager backed by nftables via netlink.
func NewNFTablesManager(opts ...ChainManagerOpt) (ChainManager, error) {
	cm := &ChainManagerNFTables{
		chainManagerBase: &chainManagerBase{
			protocols: map[rule.Family]bool{
				rule.FamilyIPv4: true,
				rule.FamilyIPv6: true,
			},
			quirks: map[Quirk]bool{},
		},
		tableName:  "swdfw",
		baseChains: make(map[string]Hook),
		chains:     make(map[string]chainState),
		sets:       make(map[string]setDef),
	}

	for _, opt := range opts {
		opt(cm)
	}

	if cm.conn == nil {
		cm.conn = &nftables.Conn{}
	}

	return cm, nil
}

func (c *ChainManagerNFTables) AddBaseChain(_ context.Context, name string, hook Hook) error {
	if _, ok := hookToNFTables[hook]; !ok {
		return fmt.Errorf("unsupported hook: %d", hook)
	}

	c.baseChains[name] = hook
	return c.apply()
}

func (c *ChainManagerNFTables) ConfigureChain(_ context.Context, name, parentChain, jumpTo string, rules []rule.Rule) error {
	_, existed := c.chains[name]
	c.chains[name] = chainState{
		rules:       rules,
		parentChain: parentChain,
		jumpTo:      jumpTo,
	}

	if !existed {
		c.chainOrder = append(c.chainOrder, name)
	}

	return c.apply()
}

func (c *ChainManagerNFTables) DeleteChain(_ context.Context, name string) error {
	delete(c.baseChains, name)
	delete(c.chains, name)

	filtered := c.chainOrder[:0]
	for _, n := range c.chainOrder {
		if n != name {
			filtered = append(filtered, n)
		}
	}
	c.chainOrder = filtered

	return c.apply()
}

func (c *ChainManagerNFTables) Close() error {
	return nil
}

func (c *ChainManagerNFTables) ConfigureSet(_ context.Context, name string, cidrs []netip.Prefix) error {
	if len(cidrs) == 0 {
		return fmt.Errorf("set %q: at least one CIDR required", name)
	}
	v6, err := parseCIDRsFamily(cidrs)
	if err != nil {
		return fmt.Errorf("set %q: %w", name, err)
	}
	c.sets[name] = setDef{cidrs: cidrs, v6: v6}
	return c.apply()
}

func (c *ChainManagerNFTables) DeleteSet(_ context.Context, name string) error {
	delete(c.sets, name)
	return c.apply()
}

func (c *ChainManagerNFTables) apply() error {
	table := &nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   c.tableName,
	}

	// Atomically replace the table: ensure it exists, delete it (including
	// all chains/rules), then recreate. This is the nftables equivalent of
	// "create table X; delete table X; table X { ... }".
	c.conn.AddTable(table)
	c.conn.DelTable(table)
	table = c.conn.AddTable(table)

	// Create named sets before chains.
	setObjs := make(map[string]*nftables.Set)
	for name, sd := range c.sets {
		keyType, _ := setKeyType(sd.v6)
		s := &nftables.Set{
			Table:        table,
			Name:         name,
			Interval:     true,
			KeyType:      keyType,
			KeyByteOrder: binaryutil.BigEndian,
		}

		elements, err := cidrsToSetElements(sd.cidrs, sd.v6)
		if err != nil {
			return fmt.Errorf("set %q: %w", name, err)
		}

		if err := c.conn.AddSet(s, elements); err != nil {
			return fmt.Errorf("set %q: AddSet failed: %w", name, err)
		}
		setObjs[name] = s
	}

	chainObjs := make(map[string]*nftables.Chain)

	// Create base chains with hooks.
	for name, hook := range c.baseChains {
		nftHook := hookToNFTables[hook]
		policy := nftables.ChainPolicyAccept

		ch := c.conn.AddChain(&nftables.Chain{
			Name:     name,
			Table:    table,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  &nftHook,
			Priority: nftables.ChainPriorityFilter,
			Policy:   &policy,
		})
		chainObjs[name] = ch
	}

	// Create regular chains (no hook).
	for _, name := range c.chainOrder {
		ch := c.conn.AddChain(&nftables.Chain{
			Name:  name,
			Table: table,
		})
		chainObjs[name] = ch
	}

	// Add rules to regular chains.
	for _, name := range c.chainOrder {
		state := c.chains[name]
		ch := chainObjs[name]

		for _, r := range state.rules {
			if _, ok := c.protocols[r.Family()]; !ok {
				continue
			}

			var sourceSet *nftables.Set
			if r.SourceSet != "" {
				sourceSet = setObjs[r.SourceSet]
				if sourceSet == nil {
					return fmt.Errorf("rule in chain %q references unknown set %q", name, r.SourceSet)
				}
			}

			exprs, err := ruleToExprs(r, sourceSet)
			if err != nil {
				return fmt.Errorf("rule conversion failed for chain %q: %w", name, err)
			}

			c.conn.AddRule(&nftables.Rule{
				Table: table,
				Chain: ch,
				Exprs: exprs,
			})
		}

		// Goto to jumpTo chain at end of this chain.
		if state.jumpTo != "" {
			if _, ok := chainObjs[state.jumpTo]; ok {
				c.conn.AddRule(&nftables.Rule{
					Table: table,
					Chain: ch,
					Exprs: []expr.Any{
						&expr.Verdict{
							Kind:  expr.VerdictGoto,
							Chain: state.jumpTo,
						},
					},
				})
			}
		}
	}

	// Add parent→child goto rules (preserving insertion order).
	parentGotos := make(map[string][]string)
	for _, name := range c.chainOrder {
		state := c.chains[name]
		if state.parentChain != "" {
			parentGotos[state.parentChain] = append(parentGotos[state.parentChain], name)
		}
	}
	for parent, children := range parentGotos {
		parentCh := chainObjs[parent]
		if parentCh == nil {
			continue
		}
		for _, child := range children {
			c.conn.AddRule(&nftables.Rule{
				Table: table,
				Chain: parentCh,
				Exprs: []expr.Any{
					&expr.Verdict{
						Kind:  expr.VerdictGoto,
						Chain: child,
					},
				},
			})
		}
	}

	return c.conn.Flush()
}
