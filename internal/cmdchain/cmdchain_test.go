package cmdchain_test

import (
	"context"
	"os"
	"testing"

	"go.uber.org/zap"

	"github.com/ZentriaMC/swdfw/internal/cmdchain"
)

func TestMain(m *testing.M) {
	os.Exit(testEntrypoint(m))
}

func testEntrypoint(m *testing.M) (exitCode int) {
	logger, err := zap.NewDevelopment(zap.IncreaseLevel(zap.DebugLevel))
	if err != nil {
		panic(err)
	}

	defer func() { _ = logger.Sync() }()
	zap.ReplaceGlobals(logger)

	exitCode = m.Run()
	return
}

func TestSimpleChain(t *testing.T) {
	ctx := context.Background()

	c := cmdchain.NewCommandChain(ctx, "simple").
		WithExecutor(cmdchain.LogNoopChainExecutor).
		Args("sh", "-c", "echo 'hello'")

	err := c.Run()
	if err != nil {
		t.Error("unexpected err:", err)
	}
}

func TestChainWithChecks(t *testing.T) {
	ctx := context.Background()

	c := cmdchain.NewCommandChain(ctx, "simple-with-checks").
		WithExecutor(cmdchain.LogNoopChainExecutor).
		WithSimpleCheck("version-check", "sh", "-ec", `x=1; [ "${x}" -gt "0" ]`).
		Args("sh", "-c", "echo 'checks succeeded'")

	err := c.Run()
	if err != nil {
		t.Error("unexpected err:", err)
	}
}

func TestChainWithChecksDisabled(t *testing.T) {
	ctx := context.Background()
	collected := map[string]bool{}
	var collectingExecutor cmdchain.Executor = func(ctx context.Context, args ...string) error {
		cmd := args[0]
		collected[cmd] = true
		return nil
	}

	c := cmdchain.NewCommandChain(ctx, "simple-with-checks").
		WithExecutor(collectingExecutor).
		WithSimpleCheck("check0", "check0").
		WithEnableChecks(false).
		Args("sh", "-c", "echo 'checks bypassed'")

	err := c.Run()
	if err != nil {
		t.Error("unexpected err:", err)
	}

	if _, ok := collected["check0"]; ok {
		t.Error("check 'check0' was not supposed to be ran")
	}
}
