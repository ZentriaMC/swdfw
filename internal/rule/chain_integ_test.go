package rule_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"go.uber.org/zap"

	"github.com/ZentriaMC/swdfw/internal/cmdchain"
	"github.com/ZentriaMC/swdfw/internal/rule"
)

var (
	hasDocker       = true
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
		Name:   fmt.Sprintf("iptables-testing-%d", time.Now().Unix()),
		CapAdd: []string{"NET_ADMIN"},
		Cmd:    []string{"/bin/sh", "-c", "while sleep 3600; do :; done"},
	}, func(hc *docker.HostConfig) {
		hc.AutoRemove = true
		hc.RestartPolicy = docker.NeverRestart()
	}))
	if err != nil {
		fmt.Println("unable to initialize docker resources, skipping integration tests")
		fmt.Println(err)
		hasDocker = false
		goto runTests
	}

	// Test the container
	_, err = dockerResources["iptables"].Exec([]string{"/bin/sh", "-c", "true"}, dockertest.ExecOptions{})
	if err != nil {
		fmt.Println("unable to initialize docker resources, skipping integration tests")
		fmt.Println(err)
		hasDocker = false
		goto runTests
	}

runTests:
	exitCode = m.Run()

	return
}

func TestChainDocker(t *testing.T) {
	if !hasDocker {
		t.SkipNow()
	}

	var dockerExecutor cmdchain.Executor = func(ctx context.Context, command ...string) (err error) {
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

			stdout.Reset()
			stderr.Reset()

			for i, e := range command {
				command[i] = strconv.Quote(e)
			}
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
			err = &cmdchain.ChainExecError{
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
	inputRules := []rule.Rule{
		{
			Direction: "input",
			Protocol:  "tcp",
			CIDR:      "10.123.0.1/24",
			Port:      22,
			Action:    "allow",
		},
		{
			Direction: "input",
			Protocol:  "tcp",
			CIDR:      "0.0.0.0/0",
			Action:    "allow",
			StartPort: 1024,
			EndPort:   4096,
		},
		{
			Direction: "input",
			Protocol:  "tcpv6",
			CIDR:      "::/0",
			Action:    "allow",
			StartPort: 1024,
			EndPort:   4096,
		},
		{
			Direction: "input",
			Protocol:  "tcp",
			CIDR:      "0.0.0.0/0",
			Action:    "block",
		},
		{
			Direction: "input",
			Protocol:  "tcpv6",
			CIDR:      "::/0",
			Action:    "block",
		},
	}

	outputRules := []rule.Rule{}

	ctx := context.Background()
	baseInput := "SWDFW-INPUT"
	baseOutput := "SWDFW-OUTPUT"
	err := c.InstallBaseChain(ctx, baseInput, "INPUT")
	if err != nil {
		t.Fatalf("failed to install base input chain: %s", err)
	}

	err = c.InstallBaseChain(ctx, baseOutput, "OUTPUT")
	if err != nil {
		t.Fatalf("failed to install base output chain: %s", err)
	}

	err = c.ConfigureChain(ctx, "basicrules-input", baseInput, "", inputRules)
	if err != nil {
		t.Fatalf("failed to replace chain: %s", err)
	}

	err = c.ConfigureChain(ctx, "basicrules-input", baseInput, "", inputRules)
	if err != nil {
		t.Fatalf("failed to replace chain: %s", err)
	}

	err = c.ConfigureChain(ctx, "basicrules-output", baseOutput, "", outputRules)
	if err != nil {
		t.Fatalf("failed to replace chain: %s", err)
	}

	err = c.ConfigureChain(ctx, "basicrules-output", baseOutput, "", outputRules)
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
