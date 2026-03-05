//go:build linux

package chain

import (
	"context"
	"net/netip"
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
		CIDR:     netip.MustParsePrefix("10.0.0.0/24"),
		Port:     80,
		Action:   "allow",
	}

	exprs, err := ruleToExprs(r, nil)
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
		CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
		Action:   "block",
	}

	exprs, err := ruleToExprs(r, nil)
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
		CIDR:      netip.MustParsePrefix("0.0.0.0/0"),
		StartPort: 1024,
		EndPort:   4096,
		Action:    "allow",
	}

	exprs, err := ruleToExprs(r, nil)
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
		CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
		Port:     443,
		Action:   "allow",
	}

	exprs, err := ruleToExprs(r, nil)
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
			CIDR:     netip.MustParsePrefix("10.0.0.0/24"),
			Port:     22,
			Action:   "allow",
		},
		{
			Protocol: "tcp",
			CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
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
			CIDR:     netip.MustParsePrefix("10.0.0.0/24"),
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
			CIDR:     netip.MustParsePrefix("10.0.0.0/24"),
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
			CIDR:      netip.MustParsePrefix("::/0"),
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
			CIDR:     netip.MustParsePrefix("10.0.0.0/24"),
			Port:     22,
			Action:   "allow",
		},
	}
	// Target chain
	rules2 := []rule.Rule{
		{
			Protocol: "tcp",
			CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
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
		CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
		Action:   "allow",
		Flags:    []string{"icmp:echo-request"},
	}

	exprs, err := ruleToExprs(r, nil)
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

func TestRuleToExprsICMPTypeNegated(t *testing.T) {
	r := rule.Rule{
		Protocol: "icmp",
		CIDR:     netip.MustParsePrefix("0.0.0.0/0"),
		Action:   "allow",
		Flags:    []string{"!icmp:echo-request"},
	}

	exprs, err := ruleToExprs(r, nil)
	if err != nil {
		t.Fatalf("ruleToExprs: %v", err)
	}

	// Find a Payload at transport header offset 0 with Len 1
	// followed by a CmpOpNeq with ICMP type code 8 (echo-request).
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
		if i+1 < len(exprs) {
			if c, ok := exprs[i+1].(*expr.Cmp); ok {
				if c.Op == expr.CmpOpNeq && len(c.Data) == 1 && c.Data[0] == 8 {
					foundCmp = true
				}
			}
		}
	}
	if !foundPayload {
		t.Fatal("expected Payload expression for ICMP type at transport header offset 0")
	}
	if !foundCmp {
		t.Fatal("expected Cmp expression with CmpOpNeq and ICMP type code 8 (echo-request)")
	}
}

func TestRuleToExprsICMPv6Type(t *testing.T) {
	r := rule.Rule{
		Protocol: "icmpv6",
		CIDR:     netip.MustParsePrefix("::/0"),
		Action:   "allow",
		Flags:    []string{"icmpv6:echo-request"},
	}

	exprs, err := ruleToExprs(r, nil)
	if err != nil {
		t.Fatalf("ruleToExprs: %v", err)
	}

	// ICMPv6 echo-request = type 128.
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
		if i+1 < len(exprs) {
			if c, ok := exprs[i+1].(*expr.Cmp); ok {
				if c.Op == expr.CmpOpEq && len(c.Data) == 1 && c.Data[0] == 128 {
					foundCmp = true
				}
			}
		}
	}
	if !foundPayload {
		t.Fatal("expected Payload expression for ICMPv6 type at transport header offset 0")
	}
	if !foundCmp {
		t.Fatal("expected Cmp expression with ICMPv6 type code 128 (echo-request)")
	}
}

func TestRuleToExprsSourceSet(t *testing.T) {
	r := rule.Rule{
		Protocol:  "tcp",
		CIDR:      netip.MustParsePrefix("0.0.0.0/0"),
		Port:      80,
		Action:    "allow",
		SourceSet: "trusted",
	}

	// Create a fake set for expression generation.
	fakeSet := &nftables.Set{
		Name: "trusted",
		ID:   42,
	}

	exprs, err := ruleToExprs(r, fakeSet)
	if err != nil {
		t.Fatalf("ruleToExprs: %v", err)
	}

	// Should contain a Payload (source addr) + Lookup pair.
	foundPayload := false
	foundLookup := false
	for i, e := range exprs {
		p, ok := e.(*expr.Payload)
		if !ok {
			continue
		}
		// IPv4 source addr: offset 12, len 4
		if p.Base == expr.PayloadBaseNetworkHeader && p.Offset == 12 && p.Len == 4 {
			// Check next expression is Lookup
			if i+1 < len(exprs) {
				if l, ok := exprs[i+1].(*expr.Lookup); ok {
					if l.SetName == "trusted" && l.SourceRegister == 1 {
						foundPayload = true
						foundLookup = true
					}
				}
			}
		}
	}
	if !foundPayload || !foundLookup {
		t.Fatal("expected Payload + Lookup expressions for source set")
	}

	// Last expression should be Accept verdict.
	last := exprs[len(exprs)-1]
	v, ok := last.(*expr.Verdict)
	if !ok || v.Kind != expr.VerdictAccept {
		t.Fatalf("expected Accept verdict, got %T %+v", last, last)
	}
}

func TestNFTablesConfigureSet(t *testing.T) {
	conn := nftTestConn(t)
	ctx := context.Background()

	cm, err := NewNFTablesManager(WithNFTConn(conn))
	if err != nil {
		t.Fatalf("NewNFTablesManager: %v", err)
	}

	// Type-assert to SetManager.
	sm := cm.(SetManager)

	if err := sm.ConfigureSet(ctx, "trusted", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("192.168.1.0/24")}); err != nil {
		t.Fatalf("ConfigureSet: %v", err)
	}

	if err := cm.AddBaseChain(ctx, "base-input", HookInput); err != nil {
		t.Fatalf("AddBaseChain: %v", err)
	}

	rules := []rule.Rule{
		{
			Protocol:  "tcp",
			CIDR:      netip.MustParsePrefix("0.0.0.0/0"),
			Port:      443,
			Action:    "allow",
			SourceSet: "trusted",
		},
	}

	if err := cm.ConfigureChain(ctx, "set-rules", "base-input", "", rules); err != nil {
		t.Fatalf("ConfigureChain: %v", err)
	}

	// Verify the set exists.
	tables, err := conn.ListTables()
	if err != nil {
		t.Fatalf("ListTables: %v", err)
	}
	if len(tables) == 0 {
		t.Fatal("expected at least one table")
	}

	sets, err := conn.GetSets(tables[0])
	if err != nil {
		t.Fatalf("GetSets: %v", err)
	}

	foundSet := false
	for _, s := range sets {
		if s.Name == "trusted" {
			foundSet = true
			break
		}
	}
	if !foundSet {
		t.Fatal("expected set 'trusted' in table")
	}

	// Verify the chain has a rule.
	chains, err := conn.ListChains()
	if err != nil {
		t.Fatalf("ListChains: %v", err)
	}

	var ch *nftables.Chain
	for _, c := range chains {
		if c.Name == "set-rules" {
			ch = c
			break
		}
	}
	if ch == nil {
		t.Fatal("chain set-rules not found")
	}

	gotRules, err := conn.GetRules(ch.Table, ch)
	if err != nil {
		t.Fatalf("GetRules: %v", err)
	}
	if len(gotRules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(gotRules))
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
