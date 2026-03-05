package rule

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// ParseFlag strips an optional leading '!' and lowercases the flag.
// It returns the cleaned value and whether the flag was negated.
func ParseFlag(flag string) (string, bool) {
	negated := strings.HasPrefix(flag, "!")
	clean := flag
	if negated {
		clean = flag[1:]
	}
	return strings.ToLower(clean), negated
}

func (r *Rule) validateFlags() (err error) {
	proto := r.Protocol
	validFlags := []map[string]bool{validStates}
	var validICMP map[string]uint8

	switch proto {
	case "tcp", "tcpv6":
		validFlags = append(validFlags, validTCPFlags, validTCPOpts)
	case "udp", "udpv6":
		// no-op
	case "icmp":
		validICMP = validICMPTypes
	case "icmpv6":
		validICMP = validICMPV6Types
	}

	hasTCPOpt := false
	hasICMPType := false
	hasMACSource := false
	for _, flag := range r.Flags {
		clean, _ := ParseFlag(flag)

		// MAC source flags are valid for all protocols.
		if addr, ok := strings.CutPrefix(clean, macPrefix); ok {
			if _, macErr := net.ParseMAC(addr); macErr != nil {
				err = fmt.Errorf("invalid MAC address in flag '%s': %v", flag, macErr)
				return
			}
			if hasMACSource {
				err = errors.New("cannot specify multiple mac source addresses in a single rule")
				return
			}
			hasMACSource = true
			continue
		}

		if !containsFlag(validFlags, clean) && !containsFlagU8(validICMP, clean) {
			err = fmt.Errorf("unsupported flag '%s' for protocol %s", flag, proto)
			return
		}

		if strings.HasPrefix(clean, tcpOptPrefix) {
			if hasTCPOpt {
				err = errors.New("cannot specify multiple tcp options in a single rule")
				return
			}
			hasTCPOpt = true
		}

		if strings.HasPrefix(clean, icmpPrefix) || strings.HasPrefix(clean, icmpv6Prefix) {
			if hasICMPType {
				err = errors.New("cannot specify multiple icmp types in a single rule")
				return
			}
			hasICMPType = true
		}
	}

	return
}

func containsFlag(flagsList []map[string]bool, flag string) (ok bool) {
	for _, flagSet := range flagsList {
		if _, ok = flagSet[flag]; ok {
			return
		}
	}

	return
}

func containsFlagU8(flagSet map[string]uint8, flag string) (ok bool) {
	if flagSet == nil {
		return
	}
	_, ok = flagSet[flag]
	return
}
