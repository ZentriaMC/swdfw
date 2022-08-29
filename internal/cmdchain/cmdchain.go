package cmdchain

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/multierr"
)

type ChainChildFunc func(CommandChain) CommandChain

type CommandChain interface {
	Name() string
	WithName(name string) CommandChain
	WithEnableChecks(enable bool) CommandChain
	WithNegated(negated bool) CommandChain
	WithSimpleCheck(name string, command ...string) CommandChain
	WithCheck(name string, chain ChainChildFunc) CommandChain
	WithExecutor(executor Executor) CommandChain
	WithErrInterceptor(interceptor ErrInterceptor) CommandChain
	Args(args ...string) CommandChain
	ArgsGroup(children ...ChainChildFunc) CommandChain

	Run() (err error)
	Negated() bool
}

func NewCommandChain(ctx context.Context, name string) CommandChain {
	return &cmdChain{
		ctx:         ctx,
		executor:    DefaultChainExecutor,
		interceptor: DefaultErrInterceptor,
		name:        name,
		doChecks:    true,
	}
}

type cmdChain struct {
	ctx         context.Context
	executor    Executor
	interceptor ErrInterceptor
	name        string
	doChecks    bool
	negated     bool
	checks      []CommandChain

	args     []string
	children []CommandChain
}

func (c *cmdChain) Name() string {
	return c.name
}

func (c *cmdChain) WithName(name string) CommandChain {
	c.name = name
	return c
}

func (c *cmdChain) WithEnableChecks(enable bool) CommandChain {
	c.doChecks = enable
	return c
}

func (c *cmdChain) WithNegated(negated bool) CommandChain {
	c.negated = negated
	return c
}

func (c *cmdChain) WithCheck(name string, chainFunc ChainChildFunc) CommandChain {
	checkChain := chainFunc(
		NewCommandChain(asCheck(c.ctx, c), name).
			WithExecutor(c.executor).
			WithErrInterceptor(c.interceptor),
	)
	c.checks = append(c.checks, checkChain)
	return c
}

func (c *cmdChain) WithSimpleCheck(name string, command ...string) CommandChain {
	return c.WithCheck(name, func(cc CommandChain) CommandChain {
		return cc.Args(command...)
	})
}

func (c *cmdChain) WithExecutor(executor Executor) CommandChain {
	c.executor = executor
	return c
}

func (c *cmdChain) WithErrInterceptor(interceptor ErrInterceptor) CommandChain {
	c.interceptor = interceptor
	return c
}

func (c *cmdChain) Args(args ...string) CommandChain {
	/*
		c.args = make([]string, len(args))
		copy(c.args, args)
	*/
	c.args = args
	return c
}

func (c *cmdChain) ArgsGroup(children ...ChainChildFunc) CommandChain {
	for _, childFunc := range children {
		ctx := context.WithValue(c.ctx, ContextParent, c)
		child := childFunc(NewCommandChain(ctx, fmt.Sprintf("%s-child-%d", c.Name(), len(c.children))).
			WithExecutor(c.executor).
			WithErrInterceptor(c.interceptor))
		c.children = append(c.children, child)
	}
	return c
}

func (c *cmdChain) Run() (err error) {
	if len(c.args) == 0 && len(c.children) == 0 {
		err = fmt.Errorf("command chain '%s' has no args or children set", c.Name())
		return
	}

	ctx := context.WithValue(c.ctx, ContextSelf, c)
	if c.doChecks {
		for _, check := range c.checks {
			err = check.Run()
			if errors.Is(err, ErrShortCircuit) {
				return nil
			}

			if err != nil {
				err = &ChainCheckError{
					chain: check,
					cause: err,
				}
				return
			}
		}
	}

	if len(c.args) > 0 {
		err = c.interceptor(c.executor(ctx, c.args...))
	} else if len(c.children) > 0 {
		for _, child := range c.children {
			cerr := child.Run()
			err = multierr.Append(err, cerr)
		}
	}
	return
}

func (c *cmdChain) Negated() bool {
	return c.negated
}
