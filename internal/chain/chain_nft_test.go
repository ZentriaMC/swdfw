//go:build linux

package chain

import (
	"context"
	"runtime"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/ZentriaMC/swdfw/internal/rule"
)

// nftTestConn creates an isolated network namespace and returns an nftables
// connection scoped to it. Mirrors upstream nftest.OpenSystemConn.
func nftTestConn(t *testing.T) *nftables.Conn {
	t.Helper()
	runtime.LockOSThread()
	ns, err := netns.New()
	if err != nil {
		runtime.UnlockOSThread()
		t.Skipf("netns.New: %v", err)
	}
	t.Cleanup(func() {
		ns.Close()
		runtime.UnlockOSThread()
	})
	conn, err := nftables.New(nftables.WithNetNSFd(int(ns)))
	if err != nil {
		t.Fatalf("nftables.New: %v", err)
	}
	return conn
}

// --- Expression unit tests (no netlink needed) ---

func TestRuleToExprsTCPAllow(t *testing.T) {
	r := rule.Rule{
		Protocol: "tcp",
		CIDR:     "10.0.0.0/24",
		Port:     80,
		Action:   "allow",
	}

	exprs, err := ruleToExprs(r)
	if err != nil {
		t.Fatalf("ruleToExprs: %v", err)
	}

	// Should start with Meta NFPROTO + Cmp for IPv4
	meta, ok := exprs[0].(*expr.Meta)
	if !ok || meta.Key != expr.MetaKeyNFPROTO {
		t.Fatal("expected Meta NFPROTO as first expr")
	}
	cmp, ok := exprs[1].(*expr.Cmp)
	if !ok || cmp.Data[0] != byte(unix.NFPROTO_IPV4) {
		t.Fatal("expected CmpEq NFPROTO_IPV4")
	}

	// Should contain a CIDR match (Payload + Bitwise + Cmp for /24)
	hasBitwise := false
	for _, e := range exprs {
		if _, ok := e.(*expr.Bitwise); ok {
			hasBitwise = true
		}
	}
	if !hasBitwise {
		t.Fatal("expected Bitwise expression for /24 CIDR")
	}

	// Last expression should be Accept verdict
	last := exprs[len(exprs)-1]
	v, ok := last.(*expr.Verdict)
	if !ok || v.Kind != expr.VerdictAccept {
		t.Fatalf("expected Accept verdict, got %T %+v", last, last)
	}
}

func TestRuleToExprsBlock(t *testing.T) {
	r := rule.Rule{
		Protocol: "tcp",
		CIDR:     "0.0.0.0/0",
		Action:   "block",
	}

	exprs, err := ruleToExprs(r)
	if err != nil {
		t.Fatalf("ruleToExprs: %v", err)
	}

	last := exprs[len(exprs)-1]
	reject, ok := last.(*expr.Reject)
	if !ok {
		t.Fatalf("expected Reject expression, got %T", last)
	}
	if reject.Type != nftRejectICMPXUnreach {
		t.Fatalf("expected reject type %d, got %d", nftRejectICMPXUnreach, reject.Type)
	}
}

func TestRuleToExprsPortRange(t *testing.T) {
	r := rule.Rule{
		Protocol:  "tcp",
		CIDR:      "0.0.0.0/0",
		StartPort: 1024,
		EndPort:   4096,
		Action:    "allow",
	}

	exprs, err := ruleToExprs(r)
	if err != nil {
		t.Fatalf("ruleToExprs: %v", err)
	}

	// Port range should produce Gte + Lte cmp pair
	var hasGte, hasLte bool
	for _, e := range exprs {
		if c, ok := e.(*expr.Cmp); ok {
			if c.Op == expr.CmpOpGte {
				hasGte = true
			}
			if c.Op == expr.CmpOpLte {
				hasLte = true
			}
		}
	}
	if !hasGte || !hasLte {
		t.Fatal("expected CmpOpGte + CmpOpLte pair for port range")
	}
}

func TestRuleToExprsZeroCIDR(t *testing.T) {
	r := rule.Rule{
		Protocol: "tcp",
		CIDR:     "0.0.0.0/0",
		Port:     443,
		Action:   "allow",
	}

	exprs, err := ruleToExprs(r)
	if err != nil {
		t.Fatalf("ruleToExprs: %v", err)
	}

	// /0 should produce no Bitwise expression
	for _, e := range exprs {
		if _, ok := e.(*expr.Bitwise); ok {
			t.Fatal("unexpected Bitwise expression for /0 CIDR")
		}
	}
}

// --- Integration tests (real netlink, isolated namespace) ---

func TestNFTablesAddBaseChain(t *testing.T) {
	conn := nftTestConn(t)
	ctx := context.Background()

	cm, err := NewNFTablesManager(WithNFTConn(conn))
	if err != nil {
		t.Fatalf("NewNFTablesManager: %v", err)
	}

	if err := cm.AddBaseChain(ctx, "test-input", HookInput); err != nil {
		t.Fatalf("AddBaseChain input: %v", err)
	}
	if err := cm.AddBaseChain(ctx, "test-output", HookOutput); err != nil {
		t.Fatalf("AddBaseChain output: %v", err)
	}

	chains, err := conn.ListChains()
	if err != nil {
		t.Fatalf("ListChains: %v", err)
	}

	found := map[string]bool{}
	for _, ch := range chains {
		found[ch.Name] = true
	}
	if !found["test-input"] || !found["test-output"] {
		t.Fatalf("expected chains test-input and test-output, got %v", found)
	}
}

func TestNFTablesConfigureChain(t *testing.T) {
	conn := nftTestConn(t)
	ctx := context.Background()

	cm, err := NewNFTablesManager(WithNFTConn(conn))
	if err != nil {
		t.Fatalf("NewNFTablesManager: %v", err)
	}

	if err := cm.AddBaseChain(ctx, "base-input", HookInput); err != nil {
		t.Fatalf("AddBaseChain: %v", err)
	}

	rules := []rule.Rule{
		{
			Protocol: "tcp",
			CIDR:     "10.0.0.0/24",
			Port:     22,
			Action:   "allow",
		},
		{
			Protocol: "tcp",
			CIDR:     "0.0.0.0/0",
			Action:   "block",
		},
	}

	if err := cm.ConfigureChain(ctx, "my-rules", "base-input", "", rules); err != nil {
		t.Fatalf("ConfigureChain: %v", err)
	}

	chains, err := conn.ListChains()
	if err != nil {
		t.Fatalf("ListChains: %v", err)
	}

	var myChain *nftables.Chain
	for _, ch := range chains {
		if ch.Name == "my-rules" {
			myChain = ch
			break
		}
	}
	if myChain == nil {
		t.Fatal("chain my-rules not found")
	}

	gotRules, err := conn.GetRules(myChain.Table, myChain)
	if err != nil {
		t.Fatalf("GetRules: %v", err)
	}

	// 2 rules in the chain
	if len(gotRules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(gotRules))
	}
}

func TestNFTablesIdempotent(t *testing.T) {
	conn := nftTestConn(t)
	ctx := context.Background()

	cm, err := NewNFTablesManager(WithNFTConn(conn))
	if err != nil {
		t.Fatalf("NewNFTablesManager: %v", err)
	}

	if err := cm.AddBaseChain(ctx, "base-input", HookInput); err != nil {
		t.Fatalf("AddBaseChain: %v", err)
	}

	rules := []rule.Rule{
		{
			Protocol: "tcp",
			CIDR:     "10.0.0.0/24",
			Port:     22,
			Action:   "allow",
		},
	}

	if err := cm.ConfigureChain(ctx, "idem-rules", "base-input", "", rules); err != nil {
		t.Fatalf("ConfigureChain first: %v", err)
	}

	// Apply again — should not duplicate rules.
	if err := cm.ConfigureChain(ctx, "idem-rules", "base-input", "", rules); err != nil {
		t.Fatalf("ConfigureChain second: %v", err)
	}

	chains, err := conn.ListChains()
	if err != nil {
		t.Fatalf("ListChains: %v", err)
	}

	var ch *nftables.Chain
	for _, c := range chains {
		if c.Name == "idem-rules" {
			ch = c
			break
		}
	}
	if ch == nil {
		t.Fatal("chain idem-rules not found")
	}

	gotRules, err := conn.GetRules(ch.Table, ch)
	if err != nil {
		t.Fatalf("GetRules: %v", err)
	}

	if len(gotRules) != 1 {
		t.Fatalf("expected 1 rule after idempotent apply, got %d", len(gotRules))
	}
}

func TestNFTablesDeleteChain(t *testing.T) {
	conn := nftTestConn(t)
	ctx := context.Background()

	cm, err := NewNFTablesManager(WithNFTConn(conn))
	if err != nil {
		t.Fatalf("NewNFTablesManager: %v", err)
	}

	if err := cm.AddBaseChain(ctx, "base-input", HookInput); err != nil {
		t.Fatalf("AddBaseChain: %v", err)
	}

	rules := []rule.Rule{
		{
			Protocol: "tcp",
			CIDR:     "10.0.0.0/24",
			Port:     22,
			Action:   "allow",
		},
	}

	if err := cm.ConfigureChain(ctx, "del-rules", "base-input", "", rules); err != nil {
		t.Fatalf("ConfigureChain: %v", err)
	}

	if err := cm.DeleteChain(ctx, "del-rules"); err != nil {
		t.Fatalf("DeleteChain: %v", err)
	}

	chains, err := conn.ListChains()
	if err != nil {
		t.Fatalf("ListChains: %v", err)
	}

	for _, ch := range chains {
		if ch.Name == "del-rules" {
			t.Fatal("chain del-rules should have been deleted")
		}
	}
}

func TestNFTablesIPv6(t *testing.T) {
	conn := nftTestConn(t)
	ctx := context.Background()

	cm, err := NewNFTablesManager(WithNFTConn(conn))
	if err != nil {
		t.Fatalf("NewNFTablesManager: %v", err)
	}

	if err := cm.AddBaseChain(ctx, "base-input", HookInput); err != nil {
		t.Fatalf("AddBaseChain: %v", err)
	}

	rules := []rule.Rule{
		{
			Protocol:  "tcpv6",
			CIDR:      "::/0",
			Action:    "allow",
			StartPort: 1024,
			EndPort:   4096,
		},
	}

	if err := cm.ConfigureChain(ctx, "v6-rules", "base-input", "", rules); err != nil {
		t.Fatalf("ConfigureChain: %v", err)
	}

	chains, err := conn.ListChains()
	if err != nil {
		t.Fatalf("ListChains: %v", err)
	}

	var ch *nftables.Chain
	for _, c := range chains {
		if c.Name == "v6-rules" {
			ch = c
			break
		}
	}
	if ch == nil {
		t.Fatal("chain v6-rules not found")
	}

	// Verify it's in an inet table
	if ch.Table.Family != nftables.TableFamilyINet {
		t.Fatalf("expected inet table family, got %v", ch.Table.Family)
	}

	gotRules, err := conn.GetRules(ch.Table, ch)
	if err != nil {
		t.Fatalf("GetRules: %v", err)
	}
	if len(gotRules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(gotRules))
	}
}

func TestNFTablesGoto(t *testing.T) {
	conn := nftTestConn(t)
	ctx := context.Background()

	cm, err := NewNFTablesManager(WithNFTConn(conn))
	if err != nil {
		t.Fatalf("NewNFTablesManager: %v", err)
	}

	if err := cm.AddBaseChain(ctx, "base-input", HookInput); err != nil {
		t.Fatalf("AddBaseChain: %v", err)
	}

	// First chain with jumpTo
	rules1 := []rule.Rule{
		{
			Protocol: "tcp",
			CIDR:     "10.0.0.0/24",
			Port:     22,
			Action:   "allow",
		},
	}
	// Target chain
	rules2 := []rule.Rule{
		{
			Protocol: "tcp",
			CIDR:     "0.0.0.0/0",
			Action:   "block",
		},
	}

	if err := cm.ConfigureChain(ctx, "goto-target", "base-input", "", rules2); err != nil {
		t.Fatalf("ConfigureChain target: %v", err)
	}
	if err := cm.ConfigureChain(ctx, "goto-source", "base-input", "goto-target", rules1); err != nil {
		t.Fatalf("ConfigureChain source: %v", err)
	}

	chains, err := conn.ListChains()
	if err != nil {
		t.Fatalf("ListChains: %v", err)
	}

	var srcChain *nftables.Chain
	for _, ch := range chains {
		if ch.Name == "goto-source" {
			srcChain = ch
			break
		}
	}
	if srcChain == nil {
		t.Fatal("chain goto-source not found")
	}

	gotRules, err := conn.GetRules(srcChain.Table, srcChain)
	if err != nil {
		t.Fatalf("GetRules: %v", err)
	}

	// Should have 1 rule + 1 goto verdict = 2 rules
	if len(gotRules) != 2 {
		t.Fatalf("expected 2 rules (1 rule + 1 goto), got %d", len(gotRules))
	}

	// Last rule should contain a goto verdict
	lastRule := gotRules[len(gotRules)-1]
	hasGoto := false
	for _, e := range lastRule.Exprs {
		if v, ok := e.(*expr.Verdict); ok && v.Kind == expr.VerdictGoto && v.Chain == "goto-target" {
			hasGoto = true
		}
	}
	if !hasGoto {
		t.Fatal("expected goto verdict to goto-target in last rule")
	}
}

func TestRuleToExprsICMPType(t *testing.T) {
	r := rule.Rule{
		Protocol: "icmp",
		CIDR:     "0.0.0.0/0",
		Action:   "allow",
		Flags:    []string{"icmp:echo-request"},
	}

	exprs, err := ruleToExprs(r)
	if err != nil {
		t.Fatalf("ruleToExprs: %v", err)
	}

	// Find a Payload expression at transport header offset 0 with Len 1
	// followed by a Cmp with ICMP type code 8 (echo-request).
	foundPayload := false
	foundCmp := false
	for i, e := range exprs {
		p, ok := e.(*expr.Payload)
		if !ok {
			continue
		}
		if p.Base != expr.PayloadBaseTransportHeader || p.Offset != 0 || p.Len != 1 {
			continue
		}
		foundPayload = true
		// Next expression should be the Cmp
		if i+1 < len(exprs) {
			if c, ok := exprs[i+1].(*expr.Cmp); ok {
				if c.Op == expr.CmpOpEq && len(c.Data) == 1 && c.Data[0] == 8 {
					foundCmp = true
				}
			}
		}
	}
	if !foundPayload {
		t.Fatal("expected Payload expression for ICMP type at transport header offset 0")
	}
	if !foundCmp {
		t.Fatal("expected Cmp expression with ICMP type code 8 (echo-request)")
	}

	// Last expression should still be Accept verdict
	last := exprs[len(exprs)-1]
	v, ok := last.(*expr.Verdict)
	if !ok || v.Kind != expr.VerdictAccept {
		t.Fatalf("expected Accept verdict, got %T %+v", last, last)
	}
}

func TestNFTablesCustomTable(t *testing.T) {
	conn := nftTestConn(t)
	ctx := context.Background()

	cm, err := NewNFTablesManager(
		WithNFTConn(conn),
		WithTableName("custom-table"),
	)
	if err != nil {
		t.Fatalf("NewNFTablesManager: %v", err)
	}

	if err := cm.AddBaseChain(ctx, "test-input", HookInput); err != nil {
		t.Fatalf("AddBaseChain: %v", err)
	}

	chains, err := conn.ListChains()
	if err != nil {
		t.Fatalf("ListChains: %v", err)
	}

	found := false
	for _, ch := range chains {
		if ch.Table.Name == "custom-table" && ch.Name == "test-input" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected chain in custom-table")
	}
}
