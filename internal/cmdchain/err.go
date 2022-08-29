package cmdchain

import (
	"errors"
	"fmt"
)

type ChainCheckError struct {
	chain CommandChain
	cause error
}

func (e *ChainCheckError) Error() string {
	return fmt.Sprintf("check '%s' failed: %s", e.ChainName(), e.Unwrap())
}

func (e *ChainCheckError) Unwrap() error {
	return e.cause
}

func (e *ChainCheckError) ChainName() string {
	return e.chain.Name()
}

var ErrShortCircuit = errors.New("check short circuited main execution")

type ChainExecError struct {
	Args    []string
	Stderr_ string
	Status  int
}

func (e *ChainExecError) Error() string {
	return fmt.Sprintf("%v: exit=%d: %s", e.Args, e.ExitStatus(), e.Stderr())
}

func (e *ChainExecError) ExitStatus() int {
	return e.Status
}

func (e *ChainExecError) Stderr() string {
	return e.Stderr_
}
