package rule

import (
	"errors"
	"fmt"
	"strings"
)

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
	for _, flag := range r.Flags {
		flagLower := strings.ToLower(flag)
		if !containsFlag(validFlags, flagLower) && !containsFlagU8(validICMP, flagLower) {
			err = fmt.Errorf("unsupported flag '%s' for protocol %s", flag, proto)
			return
		}

		if strings.HasPrefix(flagLower, tcpOptPrefix) {
			if hasTCPOpt {
				err = errors.New("cannot specify multiple tcp options in a single rule")
				return
			}
			hasTCPOpt = true
		}

		if strings.HasPrefix(flagLower, icmpPrefix) || strings.HasPrefix(flagLower, icmpv6Prefix) {
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
