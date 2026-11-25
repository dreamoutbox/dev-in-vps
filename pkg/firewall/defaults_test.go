package firewall_test

import (
	"reflect"
	"testing"

	"github.com/dreamoutbox/dev-in-vps/pkg/firewall"
)

func TestDefaultRuleSpecsAndSources(t *testing.T) {
	specs := firewall.DefaultRuleSpecs()
	wantSpecs := []string{"22", "80", "443", "8080", "8081", "3000", "8000"}
	if !reflect.DeepEqual(specs, wantSpecs) {
		t.Fatalf("DefaultRuleSpecs() = %v, want %v", specs, wantSpecs)
	}
	for _, s := range specs {
		if s == "5432" {
			t.Errorf("5432 must not be in built-in defaults")
		}
	}

	// Mutating returned slice must not affect subsequent calls.
	specs[0] = "9999"
	if firewall.DefaultRuleSpecs()[0] != "22" {
		t.Errorf("DefaultRuleSpecs() returned aliased slice")
	}

	sources := firewall.DefaultSources()
	wantSources := []string{"0.0.0.0/0", "::/0"}
	if !reflect.DeepEqual(sources, wantSources) {
		t.Fatalf("DefaultSources() = %v, want %v", sources, wantSources)
	}
	sources[0] = "10.0.0.0/8"
	if firewall.DefaultSources()[0] != "0.0.0.0/0" {
		t.Errorf("DefaultSources() returned aliased slice")
	}
}

func TestBuildDefaultRulesBuiltin(t *testing.T) {
	rules, err := firewall.BuildDefaultRules(firewall.DefaultRuleSpecs(), firewall.DefaultSources())
	if err != nil {
		t.Fatalf("BuildDefaultRules unexpected error: %v", err)
	}

	wantSpecs := []string{"22/tcp", "80/tcp", "443/tcp", "8080/tcp", "8081/tcp", "3000/tcp", "8000/tcp"}
	if len(rules) != len(wantSpecs) {
		t.Fatalf("expected %d rules, got %d", len(wantSpecs), len(rules))
	}
	for i, want := range wantSpecs {
		if rules[i].Spec() != want {
			t.Errorf("rules[%d].Spec() = %q, want %q", i, rules[i].Spec(), want)
		}
		if !reflect.DeepEqual(rules[i].Sources, []string{"0.0.0.0/0", "::/0"}) {
			t.Errorf("rules[%d].Sources = %v, want [0.0.0.0/0 ::/0]", i, rules[i].Sources)
		}
	}

	// Mutating one rule's sources must not mutate another rule's sources.
	rules[0].Sources[0] = "1.2.3.4/32"
	if rules[1].Sources[0] != "0.0.0.0/0" {
		t.Errorf("expected independent source slices per rule")
	}
}

func TestBuildDefaultRulesEnsuresExactSSH(t *testing.T) {
	t.Run("empty specs produces 22/tcp only", func(t *testing.T) {
		rules, err := firewall.BuildDefaultRules([]string{}, []string{"203.0.113.7"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rules) != 1 || rules[0].Spec() != "22/tcp" {
			t.Fatalf("expected [22/tcp], got %+v", rules)
		}
		if !reflect.DeepEqual(rules[0].Sources, []string{"203.0.113.7/32"}) {
			t.Errorf("unexpected sources: %v", rules[0].Sources)
		}
	})

	t.Run("custom specs without 22 gets 22/tcp added", func(t *testing.T) {
		rules, err := firewall.BuildDefaultRules(
			[]string{"80", "9000-9010/udp", "icmp"},
			[]string{"any"},
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		wantSpecs := []string{"22/tcp", "80/tcp", "9000-9010/udp", "icmp"}
		if len(rules) != len(wantSpecs) {
			t.Fatalf("expected %d rules, got %d: %+v", len(wantSpecs), len(rules), rules)
		}
		for i, want := range wantSpecs {
			if rules[i].Spec() != want {
				t.Errorf("rules[%d].Spec() = %q, want %q", i, rules[i].Spec(), want)
			}
		}
	})

	t.Run("22/udp and 20-25 do not satisfy exact 22/tcp", func(t *testing.T) {
		rules, err := firewall.BuildDefaultRules([]string{"22/udp", "20-25"}, []string{"10.0.0.0/8"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		wantSpecs := []string{"22/tcp", "22/udp", "20-25/tcp"}
		if len(rules) != len(wantSpecs) {
			t.Fatalf("expected %d rules, got %+v", len(wantSpecs), rules)
		}
		for i, want := range wantSpecs {
			if rules[i].Spec() != want {
				t.Errorf("rules[%d].Spec() = %q, want %q", i, rules[i].Spec(), want)
			}
		}
	})

	t.Run("explicit 22/tcp is not duplicated", func(t *testing.T) {
		rules, err := firewall.BuildDefaultRules([]string{"443", "22/TCP", "22"}, []string{"10.0.0.0/8"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		wantSpecs := []string{"443/tcp", "22/tcp"}
		if len(rules) != len(wantSpecs) {
			t.Fatalf("expected %d rules, got %+v", len(wantSpecs), rules)
		}
	})
}

func TestBuildDefaultRulesRejectsInvalidInput(t *testing.T) {
	if _, err := firewall.BuildDefaultRules([]string{"9000/sctp"}, []string{"any"}); err == nil {
		t.Errorf("expected error for invalid spec")
	}
	if _, err := firewall.BuildDefaultRules([]string{"80"}, []string{"10.0.0.1/8"}); err == nil {
		t.Errorf("expected error for invalid source")
	}
	if _, err := firewall.BuildDefaultRules([]string{"80"}, []string{}); err == nil {
		t.Errorf("expected error for empty sources")
	}
}
