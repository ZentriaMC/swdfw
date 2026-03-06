package chain

import (
	"context"
	"crypto/rand"
	"fmt"

	"errors"
	"go.uber.org/zap"

	"github.com/ZentriaMC/swdfw/rule"
)

const (
	// iptables allows 28 chars (29 with null terminator).
	iptablesMaxChainLen = 28
	// Temp chain suffix: ":%04x" → always 5 chars.
	tempSuffixLen = 5
	// User-facing chain name limit: must leave room for temp suffix.
	chainNameLimit = iptablesMaxChainLen - tempSuffixLen // 23
)

func (c *ChainManagerIPTables) validateChainName(name string) error {
	if l := len(name); l > chainNameLimit {
		return fmt.Errorf("chain name %q too long (%d > %d)", name, l, chainNameLimit)
	}
	return nil
}

// tempChainName generates a temporary chain name with a random 4-hex-char suffix.
// The result is guaranteed to fit within iptablesMaxChainLen.
func tempChainName(name string) (string, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating temp chain name: %w", err)
	}
	return fmt.Sprintf("%s:%x", name, b), nil
}

func (c *ChainManagerIPTables) prog(proto rule.Family) string {
	if proto == rule.FamilyIPv4 {
		return c.iptablesPath
	}
	return c.ip6tablesPath
}

func (c *ChainManagerIPTables) iptables(proto rule.Family, table, action, chainName string, args ...string) []string {
	return append([]string{c.prog(proto), "--wait", "1", "-t", table, action, chainName}, args...)
}

func (c *ChainManagerIPTables) cmdChainExists(proto rule.Family, table, chain string) []string {
	return c.iptables(proto, table, "-S", chain, "1")
}

func (c *ChainManagerIPTables) cmdRuleExists(proto rule.Family, table, chain string, rulespec ...string) []string {
	return c.iptables(proto, table, "-C", chain, rulespec...)
}

func (c *ChainManagerIPTables) cmdCreateChain(proto rule.Family, table, chain string) []string {
	return c.iptables(proto, table, "-N", chain)
}

func (c *ChainManagerIPTables) runCmd(ctx context.Context, args ...string) error {
	return c.executor(ctx, args...)
}

func (c *ChainManagerIPTables) hasQuirk(q Quirk) bool {
	_, ok := c.quirks[q]
	return ok
}

func (c *ChainManagerIPTables) chainExists(ctx context.Context, proto rule.Family, table, chain string) (bool, error) {
	err := c.runCmd(ctx, c.cmdChainExists(proto, table, chain)...)
	if err == nil {
		return true, nil
	}
	if isNotExistErr(err) {
		return false, nil
	}
	return false, err
}

func (c *ChainManagerIPTables) ruleExists(ctx context.Context, proto rule.Family, table, chain string, rulespec ...string) (bool, error) {
	err := c.runCmd(ctx, c.cmdRuleExists(proto, table, chain, rulespec...)...)
	if err == nil {
		return true, nil
	}
	if isNotExistErr(err) {
		return false, nil
	}
	return false, err
}

func (c *ChainManagerIPTables) runProtocol(ctx context.Context, proto rule.Family, table, action, chainName string, args ...string) error {
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
		err = errors.Join(err, perr)
	}
	return err
}

func (c *ChainManagerIPTables) createChainIfNotExists(ctx context.Context, table, chainName string) error {
	var err error
	for proto := range c.protocols {
		if c.executeChecks && !c.hasQuirk(QuirkIPTablesBrokenChainCheck) {
			exists, cerr := c.chainExists(ctx, proto, table, chainName)
			if cerr != nil {
				err = errors.Join(err, cerr)
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
		err = errors.Join(err, rerr)
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
		proto := r.Family()
		if _, ok := c.protocols[proto]; !ok {
			continue
		}

		if rulespec, rerr = r.ToRulespec(realName); rerr != nil {
			err = errors.Join(err, rerr)
			continue
		}

		err = errors.Join(err, c.runProtocol(ctx, proto, "filter", "-A", tempName, rulespec...))
	}

	if jumpTo != "" {
		cerr := c.runAllProtocols(ctx, "filter", "-A", tempName, "-g", jumpTo)
		err = errors.Join(err, cerr)
	}

	return
}
