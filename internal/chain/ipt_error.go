package chain

import (
	"errors"
	"strings"

	"github.com/ZentriaMC/swdfw/internal/cmdchain"
)

const (
	msgNoRuleExist  = "Bad rule (does a matching rule exist in that chain?).\n"
	msgNoChainExist = "No chain/target/match by that name.\n"
	msgChainExist   = "Chain already exists.\n"
)

// This interceptor checks if iptables reported missing rule/chain and passes
var IPTablesIsErrNotExist = func(short bool) cmdchain.ErrInterceptor {
	return func(err error) error {
		var cmdErr *cmdchain.ChainExecError
		if !errors.As(err, &cmdErr) || cmdErr.ExitStatus() != 1 {
			return err
		}

		if !strings.Contains(cmdErr.Stderr(), msgNoRuleExist) && !strings.Contains(cmdErr.Stderr(), msgNoChainExist) {
			return err
		}

		if short {
			return cmdchain.ErrShortCircuit
		}
		return nil
	}
}

var IPTablesIsErrAlreadyExist = func(short bool) cmdchain.ErrInterceptor {
	return func(err error) error {
		var cmdErr *cmdchain.ChainExecError
		if !errors.As(err, &cmdErr) || cmdErr.ExitStatus() != 1 {
			return err
		}

		if !strings.Contains(cmdErr.Stderr(), msgChainExist) {
			return err
		}

		if short {
			return cmdchain.ErrShortCircuit
		}
		return nil
	}
}
