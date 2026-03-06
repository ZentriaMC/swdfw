//go:build linux

package chain

import (
	"context"
	"fmt"
	"net/netip"
	"sort"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"

	"github.com/ZentriaMC/swdfw/rule"
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
	autoApply bool

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
		autoApply:  true,
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
	return c.maybeApply()
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

	return c.maybeApply()
}

func (c *ChainManagerNFTables) DeleteChain(_ context.Context, name string) error {
	delete(c.chains, name)

	filtered := c.chainOrder[:0]
	for _, n := range c.chainOrder {
		if n != name {
			filtered = append(filtered, n)
		}
	}
	c.chainOrder = filtered

	return c.maybeApply()
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
	return c.maybeApply()
}

func (c *ChainManagerNFTables) DeleteSet(_ context.Context, name string) error {
	delete(c.sets, name)
	return c.maybeApply()
}

func (c *ChainManagerNFTables) maybeApply() error {
	if !c.autoApply {
		return nil
	}
	return c.apply()
}

// Apply flushes the current in-memory state to the kernel as a single atomic
// netlink batch. When auto-apply is enabled (the default), this is called
// automatically after every mutation. When auto-apply is disabled (see
// WithAutoApply), call Apply once after all mutations are complete.
func (c *ChainManagerNFTables) Apply(_ context.Context) error {
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

	// Create named sets before chains (sorted for deterministic output).
	setNames := make([]string, 0, len(c.sets))
	for name := range c.sets {
		setNames = append(setNames, name)
	}
	sort.Strings(setNames)

	setObjs := make(map[string]*nftables.Set)
	for _, name := range setNames {
		sd := c.sets[name]
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

	// Create base chains with hooks (sorted for deterministic output).
	baseChainNames := make([]string, 0, len(c.baseChains))
	for name := range c.baseChains {
		baseChainNames = append(baseChainNames, name)
	}
	sort.Strings(baseChainNames)

	for _, name := range baseChainNames {
		hook := c.baseChains[name]
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

	// Add parent→child jump rules (preserving insertion order).
	// Jump (not goto) so that unmatched packets return to the parent
	// chain and continue to the next child.
	parentChildren := make(map[string][]string)
	for _, name := range c.chainOrder {
		state := c.chains[name]
		if state.parentChain != "" {
			parentChildren[state.parentChain] = append(parentChildren[state.parentChain], name)
		}
	}
	parentNames := make([]string, 0, len(parentChildren))
	for parent := range parentChildren {
		parentNames = append(parentNames, parent)
	}
	sort.Strings(parentNames)

	for _, parent := range parentNames {
		children := parentChildren[parent]
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
						Kind:  expr.VerdictJump,
						Chain: child,
					},
				},
			})
		}
	}

	return c.conn.Flush()
}
