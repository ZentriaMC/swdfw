package chain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapio"
)

type Executor (func(context.Context, ...string) error)

var (
	DefaultChainExecutor Executor = func(ctx context.Context, command ...string) (err error) {
		var stderr bytes.Buffer
		cmd := exec.CommandContext(ctx, command[0], command[1:]...)
		cmd.Stdout = &zapio.Writer{Log: zap.L().With(zap.String("program", command[0])), Level: zap.DebugLevel}
		cmd.Stderr = &stderr

		defer func() {
			_ = cmd.Stdout.(io.Closer).Close()
		}()

		err = cmd.Run()
		exitCode := cmd.ProcessState.ExitCode()

		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) || exitCode != 0 {
			//exitErr.ExitCode(), //exitErr.Sys().(syscall.WaitStatus).ExitStatus()
			err = &ChainExecError{
				command,
				stderr.String(),
				exitCode,
			}
		}

		return
	}

	LogNoopChainExecutor Executor = func(ctx context.Context, command ...string) (err error) {
		fmt.Println(strings.Join(command, "\t"))
		return
	}
)
