package chain_test

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alessio/shellescape"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"go.uber.org/zap"

	"github.com/ZentriaMC/swdfw/chain"
	"github.com/ZentriaMC/swdfw/rule"
)

var (
	hasDocker       = true
	dockerPool      *dockertest.Pool
	dockerResources = map[string]*dockertest.Resource{}

	dockerExecutor chain.Executor = func(ctx context.Context, command ...string) (err error) {
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

			cmd := []string{"/bin/sh", "-xc", shellescape.QuoteCommand(command)}
			exitCode, err = dockerResources["iptables"].Exec(cmd, dockertest.ExecOptions{
				StdOut: &stdout,
				StdErr: &stderr,
			})
			if err != nil {
				fmt.Println("failed to exec:", err)
				return
			}

			fmt.Println(strings.TrimRight(stderr.String(), "\n"))
			if stdout.Len() > 0 {
				fmt.Println(strings.TrimRight(stdout.String(), "\n"))
			}
			return
		})
		if err != nil {
			return
		}

		if exitCode != 0 {
			err = &chain.ExecError{
				Args:    command,
				Stderr_: stderr.String(),
				Status:  exitCode,
			}
		}

		return
	}
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
		goto runTests
	}

	defer func() {
		for _, resource := range dockerResources {
			if err := dockerPool.Purge(resource); err != nil {
				fmt.Fprintf(os.Stderr, "failed to purge test resource '%s': %s", resource.Container.Name, err)
			}
		}
	}()

	err = setupResource("iptables")(dockerPool.BuildAndRunWithOptions("../test/Dockerfile.iptables", &dockertest.RunOptions{
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

	err = setupResource("nftables")(dockerPool.BuildAndRunWithBuildOptions(
		&dockertest.BuildOptions{
			ContextDir: "../",
			Dockerfile: "test/Dockerfile.nftables",
		},
		&dockertest.RunOptions{
			Name:   fmt.Sprintf("nftables-testing-%d", time.Now().Unix()),
			CapAdd: []string{"NET_ADMIN", "SYS_ADMIN"},
			Cmd:    []string{"/bin/sh", "-c", "while sleep 3600; do :; done"},
		},
		func(hc *docker.HostConfig) {
			hc.AutoRemove = true
			hc.RestartPolicy = docker.NeverRestart()
		},
	))
	if err != nil {
		fmt.Println("unable to initialize nftables docker resource, skipping nftables integration tests")
		fmt.Println(err)
		delete(dockerResources, "nftables")
	}

runTests:
	exitCode = m.Run()

	return
}

func TestChainDockerIPTablesLegacy(t *testing.T) {
	if !hasDocker {
		t.SkipNow()
	}

	c, err := chain.NewIPTablesManager(
		chain.WithCustomExecutor(dockerExecutor),
		chain.WithFamilies(rule.FamilyIPv4, rule.FamilyIPv6),
	)
	if err != nil {
		t.Fatalf("failed to initialize chainmanager: %s", err)
	}

	defer func() {
		cerr := c.Close()
		if cerr != nil {
			t.Logf("failed to close chainmanager: %s", cerr)
		}
	}()
	inputRules := []rule.Rule{
		{
			Direction: "input",
			Protocol:  "tcp",
			CIDR:      netip.MustParsePrefix("10.123.0.1/24"),
			Port:      22,
			Action:    "allow",
		},
		{
			Direction: "input",
			Protocol:  "tcp",
			CIDR:      netip.MustParsePrefix("0.0.0.0/0"),
			Action:    "allow",
			StartPort: 1024,
			EndPort:   4096,
		},
		{
			Direction: "input",
			Protocol:  "tcpv6",
			CIDR:      netip.MustParsePrefix("::/0"),
			Action:    "allow",
			StartPort: 1024,
			EndPort:   4096,
		},
		{
			Direction: "input",
			Protocol:  "tcp",
			CIDR:      netip.MustParsePrefix("0.0.0.0/0"),
			Action:    "block",
		},
		{
			Direction: "input",
			Protocol:  "tcpv6",
			CIDR:      netip.MustParsePrefix("::/0"),
			Action:    "block",
		},
	}

	outputRules := []rule.Rule{}

	ctx := context.Background()

	defer func() {
		var collectedRules bytes.Buffer
		_, err := dockerResources["iptables"].Exec([]string{"/bin/sh", "-c", "iptables-save && ip6tables-save"}, dockertest.ExecOptions{
			StdOut: &collectedRules,
		})
		if err != nil {
			t.Fatalf("failed to get rules: %s", err)
		}

		fmt.Println(strings.TrimRight(collectedRules.String(), "\n"))
	}()

	baseInput := "SWDFW-INPUT"
	baseOutput := "SWDFW-OUTPUT"
	err = c.AddBaseChain(ctx, baseInput, chain.HookInput)
	if err != nil {
		t.Fatalf("failed to install base input chain: %s", err)
	}

	err = c.AddBaseChain(ctx, baseOutput, chain.HookOutput)
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
}

func TestIPSetAtomicSwapDocker(t *testing.T) {
	if !hasDocker {
		t.SkipNow()
	}

	c, err := chain.NewIPTablesManager(
		chain.WithCustomExecutor(dockerExecutor),
		chain.WithFamilies(rule.FamilyIPv4),
	)
	if err != nil {
		t.Fatalf("failed to initialize chainmanager: %s", err)
	}
	defer func() { _ = c.Close() }()

	sm := c.(chain.SetManager)
	ctx := context.Background()

	// Create initial set.
	cidrs1 := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("192.168.1.0/24"),
	}
	if err := sm.ConfigureSet(ctx, "e2e-test", cidrs1); err != nil {
		t.Fatalf("ConfigureSet initial: %v", err)
	}

	// Verify initial contents.
	assertIPSetContains(t, "e2e-test", []string{"10.0.0.0/24", "192.168.1.0/24"})

	// Update set with different CIDRs — should atomically swap.
	cidrs2 := []netip.Prefix{
		netip.MustParsePrefix("172.16.0.0/16"),
		netip.MustParsePrefix("10.10.0.0/24"),
		netip.MustParsePrefix("10.20.0.0/24"),
	}
	if err := sm.ConfigureSet(ctx, "e2e-test", cidrs2); err != nil {
		t.Fatalf("ConfigureSet update: %v", err)
	}

	// Verify updated contents — old CIDRs should be gone.
	assertIPSetContains(t, "e2e-test", []string{"172.16.0.0/16", "10.10.0.0/24", "10.20.0.0/24"})
	assertIPSetNotContains(t, "e2e-test", []string{"10.0.0.0/24", "192.168.1.0/24"})

	// Verify no temp sets left behind.
	assertNoTempSets(t, "e2e-test")

	// Wire it into a rule and verify the chain works.
	base := "SWDFW-SETTEST"
	if err := c.AddBaseChain(ctx, base, chain.HookInput); err != nil {
		t.Fatalf("AddBaseChain: %v", err)
	}

	rules := []rule.Rule{
		{
			Protocol:  "tcp",
			CIDR:      netip.MustParsePrefix("0.0.0.0/0"),
			Port:      443,
			Action:    "allow",
			SourceSet: "e2e-test",
		},
	}
	if err := c.ConfigureChain(ctx, "setrules-e2e", base, "", rules); err != nil {
		t.Fatalf("ConfigureChain: %v", err)
	}

	// Verify chain was created with set reference.
	var collectedRules bytes.Buffer
	_, err = dockerResources["iptables"].Exec(
		[]string{"/bin/sh", "-c", "iptables-save"},
		dockertest.ExecOptions{StdOut: &collectedRules},
	)
	if err != nil {
		t.Fatalf("failed to get rules: %v", err)
	}
	if !strings.Contains(collectedRules.String(), "--match-set e2e-test src") {
		t.Fatal("expected --match-set e2e-test src in iptables-save output")
	}

}

func assertIPSetContains(t *testing.T, setName string, expected []string) {
	t.Helper()
	var stdout bytes.Buffer
	_, err := dockerResources["iptables"].Exec(
		[]string{"/bin/sh", "-c", fmt.Sprintf("ipset list %s", setName)},
		dockertest.ExecOptions{StdOut: &stdout},
	)
	if err != nil {
		t.Fatalf("ipset list %s: %v", setName, err)
	}
	output := stdout.String()
	for _, cidr := range expected {
		if !strings.Contains(output, cidr) {
			t.Errorf("expected %q in ipset %s, got:\n%s", cidr, setName, output)
		}
	}
}

func assertIPSetNotContains(t *testing.T, setName string, unexpected []string) {
	t.Helper()
	var stdout bytes.Buffer
	_, err := dockerResources["iptables"].Exec(
		[]string{"/bin/sh", "-c", fmt.Sprintf("ipset list %s", setName)},
		dockertest.ExecOptions{StdOut: &stdout},
	)
	if err != nil {
		t.Fatalf("ipset list %s: %v", setName, err)
	}
	output := stdout.String()
	for _, cidr := range unexpected {
		if strings.Contains(output, cidr) {
			t.Errorf("unexpected %q in ipset %s, got:\n%s", cidr, setName, output)
		}
	}
}

func assertNoTempSets(t *testing.T, baseName string) {
	t.Helper()
	var stdout bytes.Buffer
	_, err := dockerResources["iptables"].Exec(
		[]string{"/bin/sh", "-c", "ipset list -n"},
		dockertest.ExecOptions{StdOut: &stdout},
	)
	if err != nil {
		t.Fatalf("ipset list -n: %v", err)
	}
	for _, line := range strings.Split(stdout.String(), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, baseName+":") {
			t.Errorf("temp set %q still exists after swap", line)
		}
	}
}

func TestChainDockerIPTablesNft(t *testing.T) {
	if !hasDocker {
		t.SkipNow()
	}

	c, err := chain.NewIPTablesManager(
		chain.WithCustomExecutor(dockerExecutor),
		chain.WithFamilies(rule.FamilyIPv4, rule.FamilyIPv6),
		chain.IPTablesPath("iptables-nft"),
		chain.IP6TablesPath("ip6tables-nft"),
		chain.Quirks(chain.QuirkIPTablesBrokenChainCheck),
	)
	if err != nil {
		t.Fatalf("failed to initialize chainmanager: %s", err)
	}

	defer func() {
		cerr := c.Close()
		if cerr != nil {
			t.Logf("failed to close chainmanager: %s", cerr)
		}
	}()
	inputRules := []rule.Rule{
		{
			Direction: "input",
			Protocol:  "tcp",
			CIDR:      netip.MustParsePrefix("10.123.0.1/24"),
			Port:      22,
			Action:    "allow",
		},
		{
			Direction: "input",
			Protocol:  "tcp",
			CIDR:      netip.MustParsePrefix("0.0.0.0/0"),
			Action:    "allow",
			StartPort: 1024,
			EndPort:   4096,
		},
		{
			Direction: "input",
			Protocol:  "tcpv6",
			CIDR:      netip.MustParsePrefix("::/0"),
			Action:    "allow",
			StartPort: 1024,
			EndPort:   4096,
		},
		{
			Direction: "input",
			Protocol:  "tcp",
			CIDR:      netip.MustParsePrefix("0.0.0.0/0"),
			Action:    "block",
		},
		{
			Direction: "input",
			Protocol:  "tcpv6",
			CIDR:      netip.MustParsePrefix("::/0"),
			Action:    "block",
		},
	}

	outputRules := []rule.Rule{}

	ctx := context.Background()

	defer func() {
		var collectedRules bytes.Buffer
		_, err := dockerResources["iptables"].Exec([]string{"/bin/sh", "-c", "iptables-nft-save && ip6tables-nft-save"}, dockertest.ExecOptions{
			StdOut: &collectedRules,
		})
		if err != nil {
			t.Fatalf("failed to get rules: %s", err)
		}

		fmt.Println(strings.TrimRight(collectedRules.String(), "\n"))
	}()

	baseInput := "SWDFWNFT-INPUT"
	baseOutput := "SWDFWNFT-OUTPUT"
	err = c.AddBaseChain(ctx, baseInput, chain.HookInput)
	if err != nil {
		t.Fatalf("failed to install base input chain: %s", err)
	}

	err = c.AddBaseChain(ctx, baseOutput, chain.HookOutput)
	if err != nil {
		t.Fatalf("failed to install base output chain: %s", err)
	}

	err = c.ConfigureChain(ctx, "basicrulesnft-input", baseInput, "", inputRules)
	if err != nil {
		t.Fatalf("failed to replace chain: %s", err)
	}

	err = c.ConfigureChain(ctx, "basicrulesnft-input", baseInput, "", inputRules)
	if err != nil {
		t.Fatalf("failed to replace chain: %s", err)
	}

	err = c.ConfigureChain(ctx, "basicrulesnft-output", baseOutput, "", outputRules)
	if err != nil {
		t.Fatalf("failed to replace chain: %s", err)
	}

	err = c.ConfigureChain(ctx, "basicrulesnft-output", baseOutput, "", outputRules)
	if err != nil {
		t.Fatalf("failed to replace chain: %s", err)
	}
}

func TestChainDockerNFTables(t *testing.T) {
	if !hasDocker {
		t.SkipNow()
	}
	if _, ok := dockerResources["nftables"]; !ok {
		t.Skip("nftables docker resource not available")
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode, err := dockerResources["nftables"].Exec(
		[]string{"/chain.test", "-test.run", "^TestNFTables|^TestRuleToExprs", "-test.v"},
		dockertest.ExecOptions{
			StdOut: &stdout,
			StdErr: &stderr,
		},
	)
	if err != nil {
		t.Fatalf("failed to exec test binary: %s", err)
	}

	t.Logf("stdout:\n%s", stdout.String())
	if stderr.Len() > 0 {
		t.Logf("stderr:\n%s", stderr.String())
	}

	if exitCode != 0 {
		t.Fatalf("test binary exited with code %d", exitCode)
	}
}
