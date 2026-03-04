package chain

import (
	"context"
	"fmt"

	"go.uber.org/multierr"
	"go.uber.org/zap"

	"github.com/ZentriaMC/swdfw/internal/rule"
)

func (c *ChainManagerIPTables) chainLength(name string, mod int) error {
	const nameLimit = 24

	if l := len(name); l > (nameLimit + mod) {
		return fmt.Errorf("chain name '%s' too long (%d > %d)", name, l, nameLimit+mod)
	}
	return nil
}

func (c *ChainManagerIPTables) prog(proto rule.Protocol) string {
	if proto == rule.ProtocolIPv4 {
		return c.iptablesPath
	}
	return c.ip6tablesPath
}

func (c *ChainManagerIPTables) iptables(proto rule.Protocol, table, action, chainName string, args ...string) []string {
	return append([]string{c.prog(proto), "--wait", "1", "-t", table, action, chainName}, args...)
}

func (c *ChainManagerIPTables) cmdChainExists(proto rule.Protocol, table, chain string) []string {
	return c.iptables(proto, table, "-S", chain, "1")
}

func (c *ChainManagerIPTables) cmdRuleExists(proto rule.Protocol, table, chain string, rulespec ...string) []string {
	return c.iptables(proto, table, "-C", chain, rulespec...)
}

func (c *ChainManagerIPTables) cmdCreateChain(proto rule.Protocol, table, chain string) []string {
	return c.iptables(proto, table, "-N", chain)
}

func (c *ChainManagerIPTables) runCmd(ctx context.Context, args ...string) error {
	return c.executor(ctx, args...)
}

func (c *ChainManagerIPTables) hasQuirk(q Quirk) bool {
	_, ok := c.quirks[q]
	return ok
}

func (c *ChainManagerIPTables) chainExists(ctx context.Context, proto rule.Protocol, table, chain string) (bool, error) {
	err := c.runCmd(ctx, c.cmdChainExists(proto, table, chain)...)
	if err == nil {
		return true, nil
	}
	if isNotExistErr(err) {
		return false, nil
	}
	return false, err
}

func (c *ChainManagerIPTables) ruleExists(ctx context.Context, proto rule.Protocol, table, chain string, rulespec ...string) (bool, error) {
	err := c.runCmd(ctx, c.cmdRuleExists(proto, table, chain, rulespec...)...)
	if err == nil {
		return true, nil
	}
	if isNotExistErr(err) {
		return false, nil
	}
	return false, err
}

func (c *ChainManagerIPTables) runProtocol(ctx context.Context, proto rule.Protocol, table, action, chainName string, args ...string) error {
	err := c.runCmd(ctx, c.iptables(proto, table, action, chainName, args...)...)
	if err != nil && isAlreadyExistErr(err) {
		return nil
	}
	return err
}

func (c *ChainManagerIPTables) runAllProtocols(ctx context.Context, table, action, chainName string, args ...string) error {
	var err error
	for proto := range c.protocols {
		perr := c.runProtocol(ctx, proto, table, action, chainName, args...)
		err = multierr.Append(err, perr)
	}
	return err
}

func (c *ChainManagerIPTables) createChainIfNotExists(ctx context.Context, table, chainName string) error {
	var err error
	for proto := range c.protocols {
		if c.executeChecks && !c.hasQuirk(QuirkIPTablesBrokenChainCheck) {
			exists, cerr := c.chainExists(ctx, proto, table, chainName)
			if cerr != nil {
				err = multierr.Append(err, cerr)
				continue
			}
			if exists {
				continue
			}
		}

		rerr := c.runCmd(ctx, c.cmdCreateChain(proto, table, chainName)...)
		if rerr != nil && isAlreadyExistErr(rerr) {
			continue
		}
		err = multierr.Append(err, rerr)
	}
	return err
}

func (c *ChainManagerIPTables) createChain(ctx context.Context, realName, tempName, jumpTo string, rules []rule.Rule) (err error) {
	// Validate that referenced sets exist and family matches.
	for _, r := range rules {
		if r.SourceSet == "" {
			continue
		}
		si, ok := c.sets[r.SourceSet]
		if !ok {
			return fmt.Errorf("rule references unknown set %q", r.SourceSet)
		}
		if si.v6 != r.IsV6() {
			return fmt.Errorf("set %q family mismatch: set is v6=%v but rule is v6=%v", r.SourceSet, si.v6, r.IsV6())
		}
	}

	if err = c.createChainIfNotExists(ctx, "filter", tempName); err != nil {
		return fmt.Errorf("failed to create a firewall chain: %w", err)
	}

	defer func() {
		if err != nil {
			derr := c.DeleteChain(context.Background(), tempName)
			if derr != nil {
				zap.L().Error("failed to delete chain", zap.Error(derr))
			}
		}
	}()

	var rulespec []string
	var rerr error
	for _, r := range rules {
		proto := r.Proto()
		if _, ok := c.protocols[proto]; !ok {
			continue
		}

		if rulespec, rerr = r.ToRulespec(realName); rerr != nil {
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
