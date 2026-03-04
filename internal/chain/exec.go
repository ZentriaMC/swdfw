package chain

import (
    "bytes"
    "context"
    "errors"
    "fmt"
    "io"
    "os/exec"

    "go.uber.org/zap"
    "go.uber.org/zap/zapio"
)

// Executor runs a command and returns an error.
type Executor func(ctx context.Context, args ...string) error

// DefaultExecutor runs commands via os/exec.
var DefaultExecutor Executor = func(ctx context.Context, command ...string) error {
    var stderr bytes.Buffer
    cmd := exec.CommandContext(ctx, command[0], command[1:]...)
    cmd.Stdout = &zapio.Writer{Log: zap.L().With(zap.String("program", command[0])), Level: zap.DebugLevel}
    cmd.Stderr = &stderr

    defer func() {
        if closer, ok := cmd.Stdout.(io.Closer); ok {
            _ = closer.Close()
        }
    }()

    err := cmd.Run()
    var exitErr *exec.ExitError
    if errors.As(err, &exitErr) || (cmd.ProcessState != nil && cmd.ProcessState.ExitCode() != 0) {
        return &ExecError{
            Args:    command,
            Stderr_: stderr.String(),
            Status:  cmd.ProcessState.ExitCode(),
        }
    }
    return err
}

// ExecError represents a command that exited with non-zero status.
type ExecError struct {
    Args    []string
    Stderr_ string
    Status  int
}

func (e *ExecError) Error() string {
    return fmt.Sprintf("%v: exit=%d: %s", e.Args, e.ExitStatus(), e.Stderr())
}

func (e *ExecError) ExitStatus() int {
    return e.Status
}

func (e *ExecError) Stderr() string {
    return e.Stderr_
}
