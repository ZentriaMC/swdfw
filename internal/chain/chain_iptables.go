package chain

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"errors"
	"go.uber.org/zap"

	"github.com/ZentriaMC/swdfw/internal/rule"
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

	iptablesPath       string
	ip6tablesPath      string
	verifyIptablesPath bool
	sets               map[string]setInfo
}

func newChainManagerIPTables(base *chainManagerBase) *ChainManagerIPTables {
	return &ChainManagerIPTables{
		chainManagerBase:   base,
		iptablesPath:       "iptables",
		ip6tablesPath:      "ip6tables",
		verifyIptablesPath: false,
		sets:               make(map[string]setInfo),
	}
}

func (c *ChainManagerIPTables) init() error {
	// TODO: c.verifyIptablesPath
	return nil
}

func (c *ChainManagerIPTables) ConfigureChain(ctx context.Context, name, parentChain, jumpTo string, rules []rule.Rule) error {
	if err := c.chainLength(name, 0); err != nil {
		return err
	}

	tempName := fmt.Sprintf("%s:%d", name, time.Now().Unix()&0xFFFF)
	// Allow for n+6 here because temporary chain will contain unique suffix
	if err := c.chainLength(tempName, 6); err != nil {
		return err
	}

	if err := c.createChain(ctx, name, tempName, jumpTo, rules); err != nil {
		return err
	}

	// Insert new chain jump before old one
	_ = c.runAllProtocols(ctx, "filter", "-I", parentChain, "-g", tempName)

	// Remove old chain references
	_ = c.runAllProtocols(ctx, "filter", "-D", parentChain, "-g", name)

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

	if err := c.chainLength(name, 0); err != nil {
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

func (c *ChainManagerIPTables) ConfigureSet(ctx context.Context, name string, cidrs []netip.Prefix) error {
	if len(name) > 31 {
		return fmt.Errorf("ipset name %q too long (%d > 31)", name, len(name))
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

	if err := c.runCmd(ctx, "ipset", "create", name, "hash:net", "family", family, "-exist"); err != nil {
		return fmt.Errorf("set %q: create failed: %w", name, err)
	}

	if err := c.runCmd(ctx, "ipset", "flush", name); err != nil {
		return fmt.Errorf("set %q: flush failed: %w", name, err)
	}

	for _, cidr := range cidrs {
		if err := c.runCmd(ctx, "ipset", "add", name, cidr.String()); err != nil {
			return fmt.Errorf("set %q: add %q failed: %w", name, cidr, err)
		}
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
