package cmdchain

import (
	"context"
	"io"
	"strconv"
	"strings"
)

type ShellScriptGenerator struct {
	shebang    string
	shellLines []string
	stack      []string
}

func NewShellScriptGenerator(shebang string) *ShellScriptGenerator {
	return &ShellScriptGenerator{
		shebang: shebang,
	}
}

func (s *ShellScriptGenerator) Reset() {
	s.shellLines = nil
	s.stack = nil
}

func (s *ShellScriptGenerator) Executor() Executor {
	// TODO: group support
	return func(ctx context.Context, command ...string) error {
		hasCheck := len(s.stack) > 1
		self := Self(ctx)
		parent := Checking(ctx)
		if parent != nil {
			s.stack = append(s.stack, "(")
			if self.Negated() {
				s.stack = append(s.stack, "!")
			}
		}

		if hasCheck {
			s.stack = append(s.stack, "&&")
		}

		for i, e := range command {
			command[i] = strconv.Quote(e)
		}
		s.stack = append(s.stack, strings.Join(command, " "))

		stdout, stderr := InputOutput(ctx)
		if stdout == io.Discard {
			s.stack = append(s.stack, "1>&-")
		}
		if stderr == io.Discard {
			s.stack = append(s.stack, "2>&-")
		}

		if parent == nil {
			if hasCheck {
				s.stack = append(s.stack, ")")
			}
			s.shellLines = append(s.shellLines, strings.Join(s.stack, " "))
			s.stack = nil
		}
		return nil
	}
}

func (s *ShellScriptGenerator) Script() string {
	return strings.Join(append([]string{s.shebang}, s.shellLines...), "\n") + "\n"
}
