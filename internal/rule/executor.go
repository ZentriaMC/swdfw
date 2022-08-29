package rule

import (
	"context"
	"strings"

	"github.com/ZentriaMC/swdfw/internal/chain"
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

func (s *ShellScriptGenerator) Executor() chain.Executor {
	// TODO: group support
	return func(ctx context.Context, command ...string) error {
		hasCheck := len(s.stack) > 1
		self := chain.Self(ctx)
		parent := chain.Checking(ctx)
		if parent != nil {
			s.stack = append(s.stack, "(")
			if self.Negated() {
				s.stack = append(s.stack, "!")
			}
		}

		if hasCheck {
			//s.stack = append(s.stack, "2>&-")
			s.stack = append(s.stack, "&&")
		}

		s.stack = append(s.stack, strings.Join(command, " "))

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
