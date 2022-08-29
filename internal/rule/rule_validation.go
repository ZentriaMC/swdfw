package rule

import (
	"errors"
	"fmt"
	"strings"
)

func (r *Rule) validateFlags() (err error) {
	proto := r.Protocol
	validFlags := []map[string]bool{validICMPTypes, validStates}

	switch proto {
	case "tcp", "tcpv6":
		validFlags = append(validFlags, validTCPFlags, validTCPOpts)
	case "udp", "udpv6":
		// no-op
	case "icmp":
		validFlags = append(validFlags, validICMPTypes)
	case "icmpv6":
		validFlags = append(validFlags, validICMPV6Types)
	}

	hasTCPOpt := false
	for _, flag := range r.Flags {
		flagLower := strings.ToLower(flag)
		if !containsFlag(validFlags, flagLower) {
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
