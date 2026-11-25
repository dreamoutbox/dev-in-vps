package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/dreamoutbox/dev-in-vps/pkg/config"
	"github.com/dreamoutbox/dev-in-vps/pkg/firewall"
	"github.com/spf13/cobra"
)

func TestResolveFirewallDefaults(t *testing.T) {
	t.Run("old config without firewall block uses built-in defaults", func(t *testing.T) {
		cfg := &config.Config{
			DefaultRegion: "nyc1",
			Firewall:      nil,
		}

		rules, sources, err := resolveFirewallDefaults(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		wantSpecs := []string{"22/tcp", "80/tcp", "443/tcp", "8080/tcp", "8081/tcp", "3000/tcp", "8000/tcp"}
		if len(rules) != len(wantSpecs) {
			t.Fatalf("expected %d rules, got %d: %+v", len(wantSpecs), len(rules), rules)
		}
		for i, want := range wantSpecs {
			if rules[i].Spec() != want {
				t.Errorf("rules[%d].Spec() = %q, want %q", i, rules[i].Spec(), want)
			}
		}
		wantSources := []string{"0.0.0.0/0", "::/0"}
		if !reflect.DeepEqual(sources, wantSources) {
			t.Errorf("sources = %v, want %v", sources, wantSources)
		}
	})

	t.Run("custom block with ranges, UDP, and ICMP resolves correctly", func(t *testing.T) {
		cfg := &config.Config{
			Firewall: &config.FirewallConfig{
				DefaultRules:   []string{"22", "80", "9000-9010/udp", "icmp"},
				DefaultSources: []string{"10.0.0.0/8", "203.0.113.7"},
			},
		}

		rules, sources, err := resolveFirewallDefaults(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		wantSpecs := []string{"22/tcp", "80/tcp", "9000-9010/udp", "icmp"}
		wantSources := []string{"10.0.0.0/8", "203.0.113.7/32"}
		if !reflect.DeepEqual(sources, wantSources) {
			t.Errorf("sources = %v, want %v", sources, wantSources)
		}
		if len(rules) != len(wantSpecs) {
			t.Fatalf("expected %d rules, got %d: %+v", len(wantSpecs), len(rules), rules)
		}
		for i, want := range wantSpecs {
			if rules[i].Spec() != want {
				t.Errorf("rules[%d].Spec() = %q, want %q", i, rules[i].Spec(), want)
			}
			if !reflect.DeepEqual(rules[i].Sources, wantSources) {
				t.Errorf("rules[%d].Sources = %v, want %v", i, rules[i].Sources, wantSources)
			}
		}
	})

	t.Run("config omitting 22 still gets 22/tcp", func(t *testing.T) {
		cfg := &config.Config{
			Firewall: &config.FirewallConfig{
				DefaultRules: []string{"80", "443"},
			},
		}

		rules, sources, err := resolveFirewallDefaults(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		wantSpecs := []string{"22/tcp", "80/tcp", "443/tcp"}
		if len(rules) != len(wantSpecs) {
			t.Fatalf("expected %d rules, got %d: %+v", len(wantSpecs), len(rules), rules)
		}
		for i, want := range wantSpecs {
			if rules[i].Spec() != want {
				t.Errorf("rules[%d].Spec() = %q, want %q", i, rules[i].Spec(), want)
			}
		}
		if !reflect.DeepEqual(sources, firewall.DefaultSources()) {
			t.Errorf("expected built-in default sources, got %v", sources)
		}
	})

	t.Run("explicit empty default_rules resolves to 22/tcp only", func(t *testing.T) {
		cfg := &config.Config{
			Firewall: &config.FirewallConfig{
				DefaultRules: []string{},
			},
		}

		rules, _, err := resolveFirewallDefaults(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rules) != 1 || rules[0].Spec() != "22/tcp" {
			t.Fatalf("expected [22/tcp] only, got %+v", rules)
		}
	})

	t.Run("missing default_rules with custom default_sources uses built-in rules", func(t *testing.T) {
		cfg := &config.Config{
			Firewall: &config.FirewallConfig{
				DefaultSources: []string{"203.0.113.7"},
			},
		}

		rules, sources, err := resolveFirewallDefaults(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rules) != len(firewall.DefaultRuleSpecs()) {
			t.Fatalf("expected %d built-in rules, got %d", len(firewall.DefaultRuleSpecs()), len(rules))
		}
		if !reflect.DeepEqual(sources, []string{"203.0.113.7/32"}) {
			t.Errorf("sources = %v, want [203.0.113.7/32]", sources)
		}
	})

	t.Run("invalid default_rules names config key", func(t *testing.T) {
		cfg := &config.Config{
			Firewall: &config.FirewallConfig{
				DefaultRules: []string{"80", "9000/sctp"},
			},
		}

		_, _, err := resolveFirewallDefaults(cfg)
		if err == nil {
			t.Fatalf("expected error for invalid default_rules, got nil")
		}
		if !strings.Contains(err.Error(), "firewall.default_rules") {
			t.Errorf("expected error to name firewall.default_rules, got: %v", err)
		}
	})

	t.Run("invalid default_sources names config key", func(t *testing.T) {
		cfg := &config.Config{
			Firewall: &config.FirewallConfig{
				DefaultSources: []string{"10.0.0.1/8"},
			},
		}

		_, _, err := resolveFirewallDefaults(cfg)
		if err == nil {
			t.Fatalf("expected error for invalid default_sources, got nil")
		}
		if !strings.Contains(err.Error(), "firewall.default_sources") {
			t.Errorf("expected error to name firewall.default_sources, got: %v", err)
		}
		if !strings.Contains(err.Error(), "10.0.0.0/8") {
			t.Errorf("expected masked CIDR suggestion in error, got: %v", err)
		}
	})

	t.Run("explicit empty default_sources names config key", func(t *testing.T) {
		cfg := &config.Config{
			Firewall: &config.FirewallConfig{
				DefaultSources: []string{},
			},
		}

		_, _, err := resolveFirewallDefaults(cfg)
		if err == nil {
			t.Fatalf("expected error for empty default_sources, got nil")
		}
		if !strings.Contains(err.Error(), "firewall.default_sources") {
			t.Errorf("expected error to name firewall.default_sources, got: %v", err)
		}
	})
}

func TestFreshHomeDirProducesConfigWithFirewallBlock(t *testing.T) {
	tempDir := filepath.Join(t.TempDir(), "fresh-home")
	t.Setenv(config.EnvDevVPSHome, tempDir)
	t.Cleanup(func() { customBaseDir = "" })

	cmd := newRootCmd()
	cmd.AddCommand(&cobra.Command{
		Use: "noop",
		Run: func(c *cobra.Command, args []string) {},
	})
	cmd.SetArgs([]string{"--home-dir", tempDir, "noop"})
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))

	if err := cmd.Execute(); err != nil {
		t.Fatalf("root command failed: %v", err)
	}

	raw, err := os.ReadFile(config.ConfigPath(tempDir))
	if err != nil {
		t.Fatalf("failed to read generated config.json: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("failed to unmarshal config.json: %v", err)
	}

	fwBlock, ok := parsed["firewall"].(map[string]any)
	if !ok {
		t.Fatalf("expected 'firewall' object in config.json, got:\n%s", string(raw))
	}
	if _, ok := fwBlock["default_rules"]; !ok {
		t.Errorf("expected 'default_rules' key in firewall block")
	}
	if _, ok := fwBlock["default_sources"]; !ok {
		t.Errorf("expected 'default_sources' key in firewall block")
	}
}
