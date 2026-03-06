package chain

import (
	"context"
	"fmt"
	"net/netip"

	"errors"
	"go.uber.org/zap"

	"github.com/ZentriaMC/swdfw/rule"
)

type setInfo struct {
	v6 bool
}

var hookToIPTablesChain = map[Hook]string{
	HookInput:   "INPUT",
	HookOutput:  "OUTPUT",
	HookForward: "FORWARD",
}

type ChainManagerIPTables struct {
	*chainManagerBase

	iptablesPath  string
	ip6tablesPath string
	sets          map[string]setInfo
}

func newChainManagerIPTables(base *chainManagerBase) *ChainManagerIPTables {
	return &ChainManagerIPTables{
		chainManagerBase: base,
		iptablesPath:     "iptables",
		ip6tablesPath:    "ip6tables",
		sets:             make(map[string]setInfo),
	}
}

func (c *ChainManagerIPTables) init() error {
	return nil
}

func (c *ChainManagerIPTables) ConfigureChain(ctx context.Context, name, parentChain, jumpTo string, rules []rule.Rule) error {
	if err := c.validateChainName(name); err != nil {
		return err
	}

	tempName, err := tempChainName(name)
	if err != nil {
		return err
	}

	if err := c.createChain(ctx, name, tempName, jumpTo, rules); err != nil {
		return err
	}

	// Append new goto to preserve declaration order across chains.
	// During updates the old goto (higher in chain) evaluates briefly
	// until deleted below — acceptable since both chains carry valid rules.
	if err := c.runAllProtocols(ctx, "filter", "-A", parentChain, "-g", tempName); err != nil {
		// New goto failed — clean up temp chain so we don't leak it.
		// The old chain remains active and unmodified.
		_ = c.DeleteChain(ctx, tempName)
		return fmt.Errorf("appending goto to parent chain: %w", err)
	}

	// Remove old chain reference. Non-fatal: both gotos existing briefly is
	// acceptable since both chains carry valid rules.
	if err := c.runAllProtocols(ctx, "filter", "-D", parentChain, "-g", name); err != nil {
		zap.L().Warn("failed to remove old goto from parent", zap.String("chain", name), zap.Error(err))
	}

	if err := c.DeleteChain(ctx, name); err != nil {
		zap.L().Warn("failed to clean up old chain", zap.String("chain", name), zap.Error(err))
	}

	return c.runAllProtocols(ctx, "filter", "-E", tempName, name)
}

func (c *ChainManagerIPTables) AddBaseChain(ctx context.Context, name string, hook Hook) error {
	parentChain, ok := hookToIPTablesChain[hook]
	if !ok {
		return fmt.Errorf("unsupported hook: %d", hook)
	}

	if err := c.validateChainName(name); err != nil {
		return err
	}

	if err := c.createChainIfNotExists(ctx, "filter", name); err != nil {
		return err
	}

	var err error
	jump := []string{"-j", name}
	for proto := range c.protocols {
		if c.executeChecks {
			exists, cerr := c.ruleExists(ctx, proto, "filter", parentChain, jump...)
			if cerr != nil {
				err = errors.Join(err, cerr)
				continue
			}
			if exists {
				continue
			}
		}

		rerr := c.runCmd(ctx, c.iptables(proto, "filter", "-A", parentChain, jump...)...)
		err = errors.Join(err, rerr)
	}

	return err
}

func (c *ChainManagerIPTables) DeleteChain(ctx context.Context, name string) error {
	var err error
	for proto := range c.protocols {
		if c.executeChecks && !c.hasQuirk(QuirkIPTablesBrokenChainCheck) {
			exists, cerr := c.chainExists(ctx, proto, "filter", name)
			if cerr != nil {
				err = errors.Join(err, cerr)
				continue
			}
			if !exists {
				continue
			}
		}

		ferr := c.runCmd(ctx, c.iptables(proto, "filter", "-F", name)...)
		if ferr != nil {
			if c.hasQuirk(QuirkIPTablesBrokenChainCheck) && isNotExistErr(ferr) {
				continue
			}
			err = errors.Join(err, ferr)
			continue
		}

		derr := c.runCmd(ctx, c.iptables(proto, "filter", "-X", name)...)
		if derr != nil {
			if c.hasQuirk(QuirkIPTablesBrokenChainCheck) && isNotExistErr(derr) {
				continue
			}
			err = errors.Join(err, derr)
		}
	}

	return err
}

func (c *ChainManagerIPTables) Close() error {
	return nil
}

const (
	ipsetMaxNameLen = 31
	ipsetNameLimit  = ipsetMaxNameLen - tempSuffixLen // 26
)

func (c *ChainManagerIPTables) ConfigureSet(ctx context.Context, name string, cidrs []netip.Prefix) error {
	if len(name) > ipsetNameLimit {
		return fmt.Errorf("ipset name %q too long (%d > %d)", name, len(name), ipsetNameLimit)
	}
	if len(cidrs) == 0 {
		return fmt.Errorf("set %q: at least one CIDR required", name)
	}

	// Determine family from CIDRs — all must be the same.
	var v6 bool
	for i, cidr := range cidrs {
		if !cidr.IsValid() {
			return fmt.Errorf("set %q: invalid CIDR %q", name, cidr)
		}
		isV6 := cidr.Addr().Is6()
		if i == 0 {
			v6 = isV6
		} else if isV6 != v6 {
			return fmt.Errorf("set %q: mixed IPv4 and IPv6 CIDRs", name)
		}
	}

	family := "inet"
	if v6 {
		family = "inet6"
	}

	// Atomic swap: build a temp set, populate it, then swap with the real one.
	tempName, err := tempChainName(name)
	if err != nil {
		return err
	}

	if err := c.runCmd(ctx, "ipset", "create", tempName, "hash:net", "family", family); err != nil {
		return fmt.Errorf("set %q: create temp failed: %w", name, err)
	}

	// Clean up temp set on failure.
	success := false
	defer func() {
		if !success {
			_ = c.runCmd(ctx, "ipset", "destroy", tempName)
		}
	}()

	for _, cidr := range cidrs {
		if err := c.runCmd(ctx, "ipset", "add", tempName, cidr.String()); err != nil {
			return fmt.Errorf("set %q: add %q failed: %w", name, cidr, err)
		}
	}

	// Ensure the real set exists so swap has a target.
	if err := c.runCmd(ctx, "ipset", "create", name, "hash:net", "family", family, "-exist"); err != nil {
		return fmt.Errorf("set %q: create failed: %w", name, err)
	}

	// Atomic swap.
	if err := c.runCmd(ctx, "ipset", "swap", tempName, name); err != nil {
		return fmt.Errorf("set %q: swap failed: %w", name, err)
	}
	success = true

	// Destroy the old set (now under the temp name).
	if err := c.runCmd(ctx, "ipset", "destroy", tempName); err != nil {
		zap.L().Warn("failed to destroy old ipset", zap.String("set", tempName), zap.Error(err))
	}

	c.sets[name] = setInfo{v6: v6}
	return nil
}

func (c *ChainManagerIPTables) DeleteSet(ctx context.Context, name string) error {
	if err := c.runCmd(ctx, "ipset", "destroy", name); err != nil {
		return fmt.Errorf("set %q: destroy failed: %w", name, err)
	}
	delete(c.sets, name)
	return nil
}
