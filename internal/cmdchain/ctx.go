package cmdchain

import "context"

type Context string

const (
	ContextCheck  Context = "cctx:checking"
	ContextParent Context = "cctx:parent"
	ContextSelf   Context = "cctx:self"
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
