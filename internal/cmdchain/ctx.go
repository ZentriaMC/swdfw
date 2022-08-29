package cmdchain

import (
	"context"
	"io"
)

type Context string

const (
	ContextCheck  Context = "cctx:checking"
	ContextParent Context = "cctx:parent"
	ContextSelf   Context = "cctx:self"

	contextStdout Context = "cctx:stdout"
	contextStderr Context = "cctx:stderr"
)

func Checking(ctx context.Context) CommandChain {
	v := ctx.Value(ContextCheck)
	if c, ok := v.(CommandChain); ok {
		return c
	}
	return nil
}

func Self(ctx context.Context) CommandChain {
	return ctx.Value(ContextSelf).(CommandChain)
}

func Parent(ctx context.Context) CommandChain {
	return ctx.Value(ContextParent).(CommandChain)
}

func asCheck(ctx context.Context, to CommandChain) context.Context {
	return context.WithValue(ctx, ContextCheck, to)
}

func withInputOutput(ctx context.Context, stdout, stderr io.Writer) context.Context {
	ctx = context.WithValue(ctx, contextStdout, stdout)
	ctx = context.WithValue(ctx, contextStderr, stderr)
	return ctx
}

func InputOutput(ctx context.Context) (stdout, stderr io.Writer) {
	stdout, _ = ctx.Value(contextStdout).(io.Writer)
	stderr, _ = ctx.Value(contextStderr).(io.Writer)
	return
}
