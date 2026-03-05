package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ZentriaMC/swdfw/chain"
	"github.com/ZentriaMC/swdfw/rule"
)

type Config struct {
	Backend       string              `yaml:"backend" json:"backend"`
	Table         string              `yaml:"table" json:"table"`
	Families      []string            `yaml:"families" json:"families"`
	IPTablesPath  string              `yaml:"iptables_path" json:"iptables_path"`
	IP6TablesPath string              `yaml:"ip6tables_path" json:"ip6tables_path"`
	Sets          map[string][]string `yaml:"sets" json:"sets"`
	Chains        []ChainConfig       `yaml:"chains" json:"chains"`
}

type ChainConfig struct {
	Name   string      `yaml:"name" json:"name"`
	Hook   string      `yaml:"hook" json:"hook"`
	Parent string      `yaml:"parent" json:"parent"`
	JumpTo string      `yaml:"jump_to" json:"jump_to"`
	Rules  []rule.Rule `yaml:"rules" json:"rules"`
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("parsing JSON config: %w", err)
		}
	default:
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("parsing YAML config: %w", err)
		}
	}

	return &cfg, nil
}

func (c *Config) validate() error {
	if c.Backend != "" && c.Backend != "nftables" && c.Backend != "iptables" {
		return fmt.Errorf("unsupported backend %q (must be \"nftables\" or \"iptables\")", c.Backend)
	}

	for _, fam := range c.Families {
		switch strings.ToLower(fam) {
		case "ipv4", "ipv6":
		default:
			return fmt.Errorf("unsupported family %q (must be \"ipv4\" or \"ipv6\")", fam)
		}
	}

	// Validate sets: parse all CIDRs.
	for name, cidrs := range c.Sets {
		for _, cidr := range cidrs {
			if _, err := netip.ParsePrefix(cidr); err != nil {
				return fmt.Errorf("set %q: invalid CIDR %q: %w", name, cidr, err)
			}
		}
	}

	// Validate chains.
	baseChains := map[string]bool{}
	for _, ch := range c.Chains {
		if ch.Name == "" {
			return fmt.Errorf("chain missing name")
		}
		if ch.Hook != "" {
			switch strings.ToLower(ch.Hook) {
			case "input", "output", "forward":
			default:
				return fmt.Errorf("chain %q: unsupported hook %q", ch.Name, ch.Hook)
			}
			if ch.Parent != "" {
				return fmt.Errorf("chain %q: base chain (has hook) cannot have parent", ch.Name)
			}
			baseChains[ch.Name] = true
		} else {
			if ch.Parent == "" {
				return fmt.Errorf("chain %q: rule chain must have a parent", ch.Name)
			}
		}
	}

	// Verify parent references.
	for _, ch := range c.Chains {
		if ch.Parent != "" {
			if !baseChains[ch.Parent] {
				return fmt.Errorf("chain %q: parent %q is not a base chain", ch.Name, ch.Parent)
			}
		}
	}

	// Validate rules.
	for _, ch := range c.Chains {
		for i := range ch.Rules {
			if err := ch.Rules[i].Validate(); err != nil {
				return fmt.Errorf("chain %q rule %d: %w", ch.Name, i, err)
			}
		}
	}

	return nil
}

func (c *Config) families() []rule.Family {
	if len(c.Families) == 0 {
		return []rule.Family{rule.FamilyIPv4, rule.FamilyIPv6}
	}
	var fams []rule.Family
	for _, f := range c.Families {
		switch strings.ToLower(f) {
		case "ipv4":
			fams = append(fams, rule.FamilyIPv4)
		case "ipv6":
			fams = append(fams, rule.FamilyIPv6)
		}
	}
	return fams
}

func parseHook(s string) chain.Hook {
	switch strings.ToLower(s) {
	case "output":
		return chain.HookOutput
	case "forward":
		return chain.HookForward
	default:
		return chain.HookInput
	}
}
