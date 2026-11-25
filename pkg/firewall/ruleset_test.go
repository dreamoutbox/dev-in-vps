package firewall_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/dreamoutbox/dev-in-vps/pkg/firewall"
	"github.com/dreamoutbox/dev-in-vps/pkg/types"
)

func mustSpecs(t *testing.T, args ...string) []firewall.Rule {
	t.Helper()
	rules, err := firewall.ParseRuleSpecs(args)
	if err != nil {
		t.Fatalf("ParseRuleSpecs(%v) failed: %v", args, err)
	}
	return rules
}

func mustSources(t *testing.T, args ...string) []string {
	t.Helper()
	sources, err := firewall.ParseSources(args)
	if err != nil {
		t.Fatalf("ParseSources(%v) failed: %v", args, err)
	}
	return sources
}

func TestAllowCreatesNewRulesAndMergesExisting(t *testing.T) {
	current := []firewall.Rule{
		firewall.SSHRule([]string{"0.0.0.0/0", "::/0"}),
		{
			Protocol: types.ProtocolTCP,
			Ports:    firewall.PortRange{From: 5432, To: 5432},
			Sources:  []string{"10.0.0.0/8"},
		},
	}

	next, report := firewall.Allow(
		current,
		mustSpecs(t, "5432", "9000-9010/udp", "icmp"),
		mustSources(t, "10.0.0.0/8", "203.0.113.7"),
	)

	if !report.HasChanges() {
		t.Fatalf("expected report.HasChanges() == true")
	}

	// Verify current was not mutated.
	if len(current) != 2 || len(current[1].Sources) != 1 {
		t.Fatalf("expected current slice not to be mutated, got %+v", current)
	}

	// Verify 5432 merged new source and skipped existing source.
	if len(next) != 4 {
		t.Fatalf("expected 4 rules, got %d: %+v", len(next), next)
	}
	want5432Sources := []string{"10.0.0.0/8", "203.0.113.7/32"}
	if !reflect.DeepEqual(next[1].Sources, want5432Sources) {
		t.Errorf("5432 sources = %v, want %v", next[1].Sources, want5432Sources)
	}
	if next[2].Spec() != "9000-9010/udp" || next[3].Spec() != "icmp" {
		t.Errorf("unexpected appended rules: %+v", next[2:])
	}

	if len(report.Added) != 3 {
		t.Fatalf("expected 3 added entries, got %+v", report.Added)
	}
	if report.Added[0].Rule.Spec() != "5432/tcp" || !reflect.DeepEqual(report.Added[0].Sources, []string{"203.0.113.7/32"}) {
		t.Errorf("unexpected Added[0]: %+v", report.Added[0])
	}
	if len(report.Skipped) != 1 || report.Skipped[0].Rule.Spec() != "5432/tcp" || !reflect.DeepEqual(report.Skipped[0].Sources, []string{"10.0.0.0/8"}) {
		t.Errorf("unexpected Skipped: %+v", report.Skipped)
	}
}

func TestAllowAllAlreadyPresentIsNoOp(t *testing.T) {
	current := []firewall.Rule{
		{
			Protocol: types.ProtocolTCP,
			Ports:    firewall.PortRange{From: 80, To: 80},
			Sources:  []string{"0.0.0.0/0", "::/0"},
		},
	}

	next, report := firewall.Allow(current, mustSpecs(t, "80"), mustSources(t, "any"))
	if report.HasChanges() {
		t.Errorf("expected HasChanges() == false, got true: %+v", report)
	}
	if len(report.Skipped) != 1 || !reflect.DeepEqual(report.Skipped[0].Sources, []string{"0.0.0.0/0", "::/0"}) {
		t.Errorf("expected skipped sources, got %+v", report.Skipped)
	}
	if !reflect.DeepEqual(next, current) {
		t.Errorf("expected unchanged rules, got %+v", next)
	}
}

func TestAllowOverlappingRangeAddsSeparateRule(t *testing.T) {
	current := []firewall.Rule{
		{
			Protocol: types.ProtocolTCP,
			Ports:    firewall.PortRange{From: 9000, To: 9010},
			Sources:  []string{"0.0.0.0/0", "::/0"},
		},
	}

	next, report := firewall.Allow(current, mustSpecs(t, "9005-9020"), mustSources(t, "any"))
	if !report.HasChanges() {
		t.Fatalf("expected HasChanges() == true")
	}
	if len(next) != 2 {
		t.Fatalf("expected 2 separate rules, got %+v", next)
	}
	if next[0].Spec() != "9000-9010/tcp" || next[1].Spec() != "9005-9020/tcp" {
		t.Errorf("expected both ranges preserved separately, got %+v", next)
	}
}

func TestAllowEmptySourcesIsNoOp(t *testing.T) {
	current := []firewall.Rule{firewall.SSHRule([]string{"0.0.0.0/0"})}
	next, report := firewall.Allow(current, mustSpecs(t, "80"), nil)
	if report.HasChanges() {
		t.Errorf("expected no changes when sources is empty, got %+v", report)
	}
	if !reflect.DeepEqual(next, current) {
		t.Errorf("expected unchanged rules, got %+v", next)
	}
}

func TestDenyWholeRule(t *testing.T) {
	current := []firewall.Rule{
		firewall.SSHRule([]string{"0.0.0.0/0", "::/0"}),
		{Protocol: types.ProtocolTCP, Ports: firewall.PortRange{From: 80, To: 80}, Sources: []string{"0.0.0.0/0", "::/0"}},
		{Protocol: types.ProtocolICMP, Sources: []string{"10.0.0.0/8"}},
	}

	next, report, err := firewall.Deny(current, mustSpecs(t, "80", "icmp", "9999"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !report.HasChanges() {
		t.Fatalf("expected HasChanges() == true")
	}
	if len(next) != 1 || next[0].Spec() != "22/tcp" {
		t.Fatalf("expected only 22/tcp remaining, got %+v", next)
	}
	if len(report.Removed) != 2 {
		t.Fatalf("expected 2 removed entries, got %+v", report.Removed)
	}
	if len(report.Skipped) != 1 || report.Skipped[0].Rule.Spec() != "9999/tcp" {
		t.Errorf("expected 9999/tcp skipped, got %+v", report.Skipped)
	}
	// Verify caller slice was not mutated.
	if len(current) != 3 {
		t.Errorf("expected original current slice length 3, got %d", len(current))
	}
}

func TestDenySpecificSourcesPartialAndLastSourceRemovesRule(t *testing.T) {
	current := []firewall.Rule{
		firewall.SSHRule([]string{"0.0.0.0/0", "::/0"}),
		{
			Protocol: types.ProtocolTCP,
			Ports:    firewall.PortRange{From: 8080, To: 8080},
			Sources:  []string{"10.0.0.0/8", "203.0.113.7/32"},
		},
		{
			Protocol: types.ProtocolTCP,
			Ports:    firewall.PortRange{From: 5432, To: 5432},
			Sources:  []string{"203.0.113.7/32"},
		},
	}

	// Partial removal on 8080, full removal (last source) on 5432, plus a missing source.
	next, report, err := firewall.Deny(
		current,
		mustSpecs(t, "8080", "5432"),
		mustSources(t, "203.0.113.7", "198.51.100.1"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !report.HasChanges() {
		t.Fatalf("expected HasChanges() == true")
	}
	if len(next) != 2 {
		t.Fatalf("expected 2 rules remaining (22/tcp and 8080/tcp), got %+v", next)
	}
	if next[1].Spec() != "8080/tcp" || !reflect.DeepEqual(next[1].Sources, []string{"10.0.0.0/8"}) {
		t.Errorf("expected 8080/tcp to retain 10.0.0.0/8 only, got %+v", next[1])
	}
	if len(report.Removed) != 2 {
		t.Fatalf("expected 2 removed entries, got %+v", report.Removed)
	}
	if len(report.Skipped) != 2 {
		t.Fatalf("expected 2 skipped entries for missing source 198.51.100.1/32, got %+v", report.Skipped)
	}
}

func TestDenyCoveredByWiderRangeChangesNothing(t *testing.T) {
	current := []firewall.Rule{
		firewall.SSHRule([]string{"0.0.0.0/0", "::/0"}),
		{
			Protocol: types.ProtocolTCP,
			Ports:    firewall.PortRange{From: 9000, To: 9010},
			Sources:  []string{"0.0.0.0/0", "::/0"},
		},
	}

	// Deny single port inside open range without -s.
	next, report, err := firewall.Deny(current, mustSpecs(t, "9005"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.HasChanges() {
		t.Errorf("expected HasChanges() == false, got true")
	}
	if !reflect.DeepEqual(next, current) {
		t.Errorf("expected rules unchanged, got %+v", next)
	}
	if len(report.CoveredBy) != 1 {
		t.Fatalf("expected 1 CoveredBy entry, got %+v", report.CoveredBy)
	}
	if report.CoveredBy[0].Target.Spec() != "9005/tcp" {
		t.Errorf("expected target 9005/tcp, got %q", report.CoveredBy[0].Target.Spec())
	}
	if len(report.CoveredBy[0].CoveredBy) != 1 || report.CoveredBy[0].CoveredBy[0].Spec() != "9000-9010/tcp" {
		t.Errorf("expected covered by 9000-9010/tcp, got %+v", report.CoveredBy[0].CoveredBy)
	}

	// Different protocol (9005/udp) is NOT covered by 9000-9010/tcp.
	_, udpReport, err := firewall.Deny(current, mustSpecs(t, "9005/udp"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(udpReport.CoveredBy) != 0 {
		t.Errorf("expected no CoveredBy for 9005/udp, got %+v", udpReport.CoveredBy)
	}
	if len(udpReport.Skipped) != 1 || udpReport.Skipped[0].Rule.Spec() != "9005/udp" {
		t.Errorf("expected 9005/udp skipped, got %+v", udpReport.Skipped)
	}

	// Subrange with -s also reports CoveredBy.
	_, subReport, err := firewall.Deny(current, mustSpecs(t, "9002-9008"), mustSources(t, "0.0.0.0/0"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(subReport.CoveredBy) != 1 || subReport.CoveredBy[0].Target.Spec() != "9002-9008/tcp" {
		t.Errorf("expected CoveredBy for 9002-9008/tcp, got %+v", subReport.CoveredBy)
	}
}

func TestSSHProtectionSemantics(t *testing.T) {
	base := []firewall.Rule{
		firewall.SSHRule([]string{"0.0.0.0/0", "::/0"}),
		{Protocol: types.ProtocolTCP, Ports: firewall.PortRange{From: 80, To: 80}, Sources: []string{"0.0.0.0/0", "::/0"}},
		{Protocol: types.ProtocolUDP, Ports: firewall.PortRange{From: 22, To: 22}, Sources: []string{"0.0.0.0/0"}},
		{Protocol: types.ProtocolTCP, Ports: firewall.PortRange{From: 20, To: 25}, Sources: []string{"0.0.0.0/0"}},
	}

	t.Run("deny 22 without -s is refused atomically", func(t *testing.T) {
		next, report, err := firewall.Deny(base, mustSpecs(t, "80", "22"), nil)
		if !errors.Is(err, firewall.ErrSSHRuleProtected) {
			t.Fatalf("expected ErrSSHRuleProtected, got: %v", err)
		}
		if next != nil || report.HasChanges() {
			t.Errorf("expected nil rules and empty report on error, got next=%+v report=%+v", next, report)
		}
	})

	t.Run("deny 22 -s any refused when no other source remains", func(t *testing.T) {
		_, _, err := firewall.Deny(base, mustSpecs(t, "22"), mustSources(t, "any"))
		if !errors.Is(err, firewall.ErrSSHRuleProtected) {
			t.Fatalf("expected ErrSSHRuleProtected, got: %v", err)
		}
	})

	t.Run("allow 22 -s my-ip then deny 22 -s any succeeds", func(t *testing.T) {
		afterAllow, allowReport := firewall.Allow(base, mustSpecs(t, "22"), mustSources(t, "203.0.113.7"))
		if !allowReport.HasChanges() {
			t.Fatalf("expected allow to add 203.0.113.7/32")
		}

		afterDeny, denyReport, err := firewall.Deny(afterAllow, mustSpecs(t, "22"), mustSources(t, "any"))
		if err != nil {
			t.Fatalf("expected restricting SSH to succeed, got: %v", err)
		}
		if !denyReport.HasChanges() {
			t.Fatalf("expected deny to report changes")
		}
		wantSources := []string{"203.0.113.7/32"}
		if !reflect.DeepEqual(afterDeny[0].Sources, wantSources) {
			t.Errorf("expected 22/tcp sources %v, got %v", wantSources, afterDeny[0].Sources)
		}

		// Removing the final remaining SSH source must now be refused.
		_, _, err = firewall.Deny(afterDeny, mustSpecs(t, "22"), mustSources(t, "203.0.113.7"))
		if !errors.Is(err, firewall.ErrSSHRuleProtected) {
			t.Fatalf("expected ErrSSHRuleProtected when removing last SSH source, got: %v", err)
		}
	})

	t.Run("deny 22 -s 0.0.0.0/0 allowed because ::/0 remains", func(t *testing.T) {
		next, report, err := firewall.Deny(base, mustSpecs(t, "22"), mustSources(t, "0.0.0.0/0"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !report.HasChanges() {
			t.Fatalf("expected changes")
		}
		if !reflect.DeepEqual(next[0].Sources, []string{"::/0"}) {
			t.Errorf("expected [::/0] remaining, got %v", next[0].Sources)
		}
	})

	t.Run("deny 22 -s non-present source is skipped without error", func(t *testing.T) {
		next, report, err := firewall.Deny(base, mustSpecs(t, "22"), mustSources(t, "198.51.100.9"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if report.HasChanges() {
			t.Errorf("expected no changes")
		}
		if len(report.Skipped) != 1 || report.Skipped[0].Rule.Spec() != "22/tcp" {
			t.Errorf("expected 22/tcp skipped, got %+v", report.Skipped)
		}
		if !reflect.DeepEqual(next[0].Sources, []string{"0.0.0.0/0", "::/0"}) {
			t.Errorf("expected 22/tcp unchanged, got %v", next[0].Sources)
		}
	})

	t.Run("22/udp and 20-25/tcp are not protected as exact 22/tcp", func(t *testing.T) {
		next, report, err := firewall.Deny(base, mustSpecs(t, "22/udp", "20-25"), nil)
		if err != nil {
			t.Fatalf("expected 22/udp and 20-25/tcp to be removable, got: %v", err)
		}
		if len(report.Removed) != 2 {
			t.Errorf("expected 2 removed, got %+v", report.Removed)
		}
		if len(next) != 2 {
			t.Errorf("expected 2 rules remaining, got %+v", next)
		}
	})
}
