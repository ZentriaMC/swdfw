package chain

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/multierr"

	"github.com/ZentriaMC/swdfw/internal/rule"
)

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
}

func newChainManagerIPTables(base *chainManagerBase) *ChainManagerIPTables {
	return &ChainManagerIPTables{
		chainManagerBase:   base,
		iptablesPath:       "iptables",
		ip6tablesPath:      "ip6tables",
		verifyIptablesPath: false,
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
		// TODO: not fatal
		return fmt.Errorf("failed to clean up old rules: %w", err)
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
				err = multierr.Append(err, cerr)
				continue
			}
			if exists {
				continue
			}
		}

		rerr := c.runCmd(ctx, c.iptables(proto, "filter", "-A", parentChain, jump...)...)
		err = multierr.Append(err, rerr)
	}

	return err
}

func (c *ChainManagerIPTables) DeleteChain(ctx context.Context, name string) error {
	var err error
	for proto := range c.protocols {
		if c.executeChecks && !c.hasQuirk(QuirkIPTablesBrokenChainCheck) {
			exists, cerr := c.chainExists(ctx, proto, "filter", name)
			if cerr != nil {
				err = multierr.Append(err, cerr)
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
			err = multierr.Append(err, ferr)
			continue
		}

		derr := c.runCmd(ctx, c.iptables(proto, "filter", "-X", name)...)
		if derr != nil {
			if c.hasQuirk(QuirkIPTablesBrokenChainCheck) && isNotExistErr(derr) {
				continue
			}
			err = multierr.Append(err, derr)
		}
	}

	return err
}

func (c *ChainManagerIPTables) Close() error {
	return nil
}
