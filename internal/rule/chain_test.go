package rule_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"go.uber.org/zap"

	"github.com/ZentriaMC/swdfw/internal/chain"
	"github.com/ZentriaMC/swdfw/internal/rule"
)

var (
	dockerPool      *dockertest.Pool
	dockerResources = map[string]*dockertest.Resource{}
)

func TestMain(m *testing.M) {
	os.Exit(testEntrypoint(m))
}

func setupResource(name string) func(r *dockertest.Resource, err error) error {
	return func(r *dockertest.Resource, err error) error {
		if err != nil {
			return fmt.Errorf("failed to set up docker resource '%s': %w", name, err)
		}
		if r == nil {
			panic("nil resource?")
		}
		dockerResources[name] = r
		return nil
	}
}

func testEntrypoint(m *testing.M) (exitCode int) {
	logger, err := zap.NewDevelopment(zap.IncreaseLevel(zap.DebugLevel))
	if err != nil {
		panic(err)
	}

	defer func() { _ = logger.Sync() }()
	zap.ReplaceGlobals(logger)

	if dockerPool, err = dockertest.NewPool(""); err != nil {
		fmt.Println("unable to initialize docker connection, skipping integration tests")
		fmt.Println(err)
		return 0
	}

	defer func() {
		for _, resource := range dockerResources {
			if err := dockerPool.Purge(resource); err != nil {
				fmt.Fprintf(os.Stderr, "failed to purge test resource '%s': %s", resource.Container.Name, err)
			}
		}
	}()

	err = setupResource("iptables")(dockerPool.BuildAndRunWithOptions("../../test/Dockerfile.iptables", &dockertest.RunOptions{
		Name:       fmt.Sprintf("iptables-testing-%d", time.Now().Unix()),
		Privileged: true,
		CapAdd:     []string{"NET_ADMIN"},
		Cmd:        []string{"/bin/sh", "-c", "while sleep 3600; do :; done"},
	}, func(hc *docker.HostConfig) {
		hc.AutoRemove = true
		hc.RestartPolicy = docker.NeverRestart()
	}))
	if err != nil {
		fmt.Println("unable to initialize docker resources, skipping integration tests")
		fmt.Println(err)
		return 0
	}

	exitCode = m.Run()

	return
}

func TestChain(t *testing.T) {
	sg := rule.NewShellScriptGenerator("#!/bin/sh")
	c := rule.NewChainManager(
		rule.WithCustomExecutor(sg.Executor()),
		rule.WithProtocols(rule.ProtocolIPv4),
	)
	rules := []rule.Rule{
		{
			Protocol: "tcp",
			CIDR:     "10.123.0.1/24",
			Port:     22,
			Action:   "allow",
		},
		{
			Protocol:  "tcp",
			CIDR:      "0.0.0.0/0",
			Action:    "allow",
			StartPort: 1024,
			EndPort:   4096,
		},
		{
			Protocol:  "tcpv6",
			CIDR:      "::/0",
			Action:    "allow",
			StartPort: 1024,
			EndPort:   4096,
		},
		{
			Protocol: "tcp",
			CIDR:     "0.0.0.0/0",
			Action:   "block",
		},
	}

	ctx := context.Background()
	base := "SWDFW-OUTPUT"
	err := c.InstallBaseChain(ctx, base, "INPUT")
	if err != nil {
		t.Fatalf("failed to install base chain: %s", err)
	}

	err = c.ReplaceChain(ctx, "basicrules", base, "", rules)
	if err != nil {
		t.Fatalf("failed to replace chain: %s", err)
	}

	script := sg.Script()
	fmt.Println(script)
}

func TestChainDocker(t *testing.T) {
	var dockerExecutor chain.Executor = func(ctx context.Context, command ...string) (err error) {
		var exitCode int
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		err = dockerPool.Retry(func() (err error) {
			defer func() {
				if r := recover(); r != nil {
					if e, ok := r.(error); ok {
						err = e
					} else {
						err = fmt.Errorf("%v", r)
					}
				}
			}()

			stderr.Reset()
			cmd := []string{"/bin/sh", "-xc", strings.Join(command, " ")}
			exitCode, err = dockerResources["iptables"].Exec(cmd, dockertest.ExecOptions{
				StdOut: &stdout,
				StdErr: &stderr,
			})

			if stdout.Len() > 0 {
				fmt.Println(strings.TrimRight(stderr.String(), "\n"))
				fmt.Println(strings.TrimRight(stdout.String(), "\n"))
			}
			return
		})
		if err != nil {
			return
		}

		if exitCode != 0 {
			err = &chain.ChainExecError{
				Args:    command,
				Stderr_: stderr.String(),
				Status:  exitCode,
			}
		}

		return
	}

	c := rule.NewChainManager(
		rule.WithCustomExecutor(dockerExecutor),
		rule.WithProtocols(rule.ProtocolIPv4, rule.ProtocolIPv6),
	)
	rules := []rule.Rule{
		{
			Protocol: "tcp",
			CIDR:     "10.123.0.1/24",
			Port:     22,
			Action:   "allow",
		},
		{
			Protocol:  "tcp",
			CIDR:      "0.0.0.0/0",
			Action:    "allow",
			StartPort: 1024,
			EndPort:   4096,
		},
		{
			Protocol:  "tcpv6",
			CIDR:      "::/0",
			Action:    "allow",
			StartPort: 1024,
			EndPort:   4096,
		},
		{
			Protocol: "tcp",
			CIDR:     "0.0.0.0/0",
			Action:   "block",
		},
		{
			Protocol: "tcpv6",
			CIDR:     "::/0",
			Action:   "block",
		},
	}

	ctx := context.Background()
	base := "SWDFW-OUTPUT"
	err := c.InstallBaseChain(ctx, base, "INPUT")
	if err != nil {
		t.Fatalf("failed to install base chain: %s", err)
	}

	err = c.ReplaceChain(ctx, "basicrules", base, "", rules)
	if err != nil {
		t.Fatalf("failed to replace chain: %s", err)
	}

	err = c.ReplaceChain(ctx, "basicrules", base, "", rules)
	if err != nil {
		t.Fatalf("failed to replace chain: %s", err)
	}

	var collectedRules bytes.Buffer
	_, err = dockerResources["iptables"].Exec([]string{"/bin/sh", "-c", "iptables-save && ip6tables-save"}, dockertest.ExecOptions{
		StdOut: &collectedRules,
	})
	if err != nil {
		t.Fatalf("failed to get rules: %s", err)
	}

	fmt.Println(strings.TrimRight(collectedRules.String(), "\n"))
}
