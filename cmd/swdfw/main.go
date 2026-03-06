package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"

	"github.com/ZentriaMC/swdfw/chain"
	"github.com/ZentriaMC/swdfw/rule"
)

func main() {
	var configPath string
	var dryRun bool

	flag.StringVar(&configPath, "config", "", "path to config file (YAML or JSON)")
	flag.StringVar(&configPath, "c", "", "path to config file (shorthand)")
	flag.BoolVar(&dryRun, "dry-run", false, "validate config and print summary without applying")
	flag.Parse()

	if configPath == "" {
		fmt.Fprintln(os.Stderr, "error: -config is required")
		flag.Usage()
		os.Exit(1)
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if err := cfg.validate(); err != nil {
		fmt.Fprintf(os.Stderr, "validation error: %v\n", err)
		os.Exit(1)
	}

	if dryRun {
		printSummary(cfg)
		return
	}

	if err := apply(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printSummary(cfg *Config) {
	backend := cfg.Backend
	if backend == "" {
		backend = "(auto-detect)"
	}
	fmt.Printf("Backend: %s\n", backend)

	if cfg.Table != "" {
		fmt.Printf("Table:   %s\n", cfg.Table)
	}

	if len(cfg.Sets) > 0 {
		fmt.Printf("\nSets:\n")
		for name, cidrs := range cfg.Sets {
			fmt.Printf("  %s: %d entries\n", name, len(cidrs))
		}
	}

	fmt.Printf("\nChains:\n")
	for _, ch := range cfg.Chains {
		if ch.Hook != "" {
			policy := ch.Policy
		if policy == "" {
			policy = "accept"
		}
		fmt.Printf("  %s (base, hook=%s, policy=%s)\n", ch.Name, ch.Hook, policy)
		} else {
			extra := ""
			if ch.JumpTo != "" {
				extra = fmt.Sprintf(", jump_to=%s", ch.JumpTo)
			}
			fmt.Printf("  %s (parent=%s, %d rules%s)\n", ch.Name, ch.Parent, len(ch.Rules), extra)
		}
	}
}

func apply(cfg *Config) error {
	ctx := context.Background()

	cm, err := createBackend(cfg)
	if err != nil {
		return fmt.Errorf("creating backend: %w", err)
	}
	defer func() { _ = cm.Close() }()

	// Configure sets.
	if len(cfg.Sets) > 0 {
		sm, ok := cm.(chain.SetManager)
		if !ok {
			return fmt.Errorf("backend does not support named sets")
		}
		for name, cidrStrs := range cfg.Sets {
			cidrs := make([]netip.Prefix, 0, len(cidrStrs))
			for _, s := range cidrStrs {
				p, err := netip.ParsePrefix(s)
				if err != nil {
					return fmt.Errorf("set %q: %w", name, err)
				}
				cidrs = append(cidrs, p)
			}
			if err := sm.ConfigureSet(ctx, name, cidrs); err != nil {
				return fmt.Errorf("configuring set %q: %w", name, err)
			}
		}
	}

	// Add base chains.
	for _, ch := range cfg.Chains {
		if ch.Hook == "" {
			continue
		}
		if err := cm.AddBaseChain(ctx, ch.Name, parseHook(ch.Hook), parsePolicy(ch.Policy)); err != nil {
			return fmt.Errorf("adding base chain %q: %w", ch.Name, err)
		}
	}

	// Configure rule chains.
	for _, ch := range cfg.Chains {
		if ch.Hook != "" {
			continue
		}
		if err := cm.ConfigureChain(ctx, ch.Name, ch.Parent, ch.JumpTo, ch.Rules); err != nil {
			return fmt.Errorf("configuring chain %q: %w", ch.Name, err)
		}
	}

	// Flush deferred state to kernel (nftables with auto-apply disabled).
	if applier, ok := cm.(chain.Applier); ok {
		if err := applier.Apply(ctx); err != nil {
			return fmt.Errorf("applying rules: %w", err)
		}
	}

	return nil
}

func createBackend(cfg *Config) (chain.ChainManager, error) {
	families := cfg.families()

	var opts []chain.ChainManagerOpt
	if len(families) > 0 {
		fams := make([]rule.Family, len(families))
		copy(fams, families)
		opts = append(opts, chain.WithFamilies(fams...))
	}

	backend := cfg.Backend

	// Auto-detect if not specified.
	if backend == "" {
		if hasNFTables {
			backend = "nftables"
		} else {
			backend = "iptables"
		}
	}

	switch backend {
	case "nftables":
		return newNFTablesManager(tableOrDefault(cfg.Table), opts...)
	case "iptables":
		iptOpts := opts
		if cfg.IPTablesPath != "" {
			iptOpts = append(iptOpts, chain.IPTablesPath(cfg.IPTablesPath))
		}
		if cfg.IP6TablesPath != "" {
			iptOpts = append(iptOpts, chain.IP6TablesPath(cfg.IP6TablesPath))
		}
		return chain.NewIPTablesManager(iptOpts...)
	default:
		return nil, fmt.Errorf("unsupported backend %q", backend)
	}
}

func tableOrDefault(table string) string {
	if table != "" {
		return table
	}
	return "swdfw"
}
