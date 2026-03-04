package chain

import (
    "errors"
    "strings"
)

const (
    msgIPTNoRuleExist  = "Bad rule (does a matching rule exist in that chain?).\n"
    msgIPTNoChainExist = "No chain/target/match by that name.\n"
    msgIPTChainExist   = "Chain already exists.\n"
)

func isNotExistErr(err error) bool {
    var execErr *ExecError
    if !errors.As(err, &execErr) || execErr.ExitStatus() != 1 {
        return false
    }
    return strings.Contains(execErr.Stderr(), msgIPTNoRuleExist) || strings.Contains(execErr.Stderr(), msgIPTNoChainExist)
}

func isAlreadyExistErr(err error) bool {
    var execErr *ExecError
    if !errors.As(err, &execErr) || execErr.ExitStatus() != 1 {
        return false
    }
    return strings.Contains(execErr.Stderr(), msgIPTChainExist)
}
