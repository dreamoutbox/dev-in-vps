package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dreamoutbox/dev-in-vps/pkg/config"
	"github.com/dreamoutbox/dev-in-vps/pkg/firewall"
	"github.com/dreamoutbox/dev-in-vps/pkg/provider"
	"github.com/dreamoutbox/dev-in-vps/pkg/types"
)

func TestFirewallListCommand(t *testing.T) {
	t.Cleanup(func() {
		customBaseDir = ""
	})

	sampleRules := []firewall.Rule{
		{Protocol: types.ProtocolICMP, Sources: []string{"10.0.0.0/8"}},
		{Protocol: types.ProtocolUDP, Ports: firewall.PortRange{From: 9000, To: 9010}, Sources: []string{"10.0.0.0/8", "2001:db8::/32"}},
		{Protocol: types.ProtocolTCP, Ports: firewall.PortRange{From: 8080, To: 8080}, Sources: []string{"0.0.0.0/0", "::/0"}},
		{Protocol: types.ProtocolTCP, Ports: firewall.PortRange{From: 22, To: 22}, Sources: []string{"203.0.113.7/32"}},
		{Protocol: types.ProtocolUDP, Ports: firewall.PortRange{From: 53, To: 53}, Sources: []string{"0.0.0.0/0"}},
	}

	t.Run("table output sorts TCP then UDP then ICMP and formats columns", func(t *testing.T) {
		tempDir := filepath.Join(t.TempDir(), "fw-list-table")
		if err := config.InitStorage(tempDir); err != nil {
			t.Fatalf("InitStorage failed: %v", err)
		}
		st, _ := config.LoadState(tempDir)
		st.AddServer(config.ServerRecord{
			ID:        "srv-101",
			Name:      "web-box",
			Provider:  types.ProviderDigitalOcean,
			Region:    "nyc1",
			Size:      "s-2vcpu-4gb",
			IPAddress: "203.0.113.10",
			Status:    types.StatusActive,
			CreatedAt: time.Now(),
		})
		_ = config.SaveState(tempDir, st)

		mock := newMockProvider()
		mock.firewalls["srv-101"] = &provider.FirewallInfo{
			ID:           "fw-101",
			Name:         "dev-vps-web-box",
			ServerID:     "srv-101",
			InboundRules: sampleRules,
		}

		oldFactory := providerFactory
		providerFactory = func(cfg *config.Config) (provider.Provider, error) { return mock, nil }
		defer func() { providerFactory = oldFactory }()

		cmd := newRootCmd()
		outBuf := new(bytes.Buffer)
		cmd.SetOut(outBuf)
		cmd.SetErr(new(bytes.Buffer))
		cmd.SetArgs([]string{"--home-dir", tempDir, "firewall", "list", "web-box"})

		if err := cmd.Execute(); err != nil {
			t.Fatalf("firewall list failed: %v", err)
		}

		lines := strings.Split(strings.TrimSpace(outBuf.String()), "\n")
		if len(lines) != 6 {
			t.Fatalf("expected header + 5 rule rows, got %d lines:\n%s", len(lines), outBuf.String())
		}

		// Header columns
		for _, col := range []string{"RULE", "PROTOCOL", "PORTS", "SOURCES"} {
			if !strings.Contains(lines[0], col) {
				t.Errorf("header missing column %q: %s", col, lines[0])
			}
		}

		// Row order: 22/tcp, 8080/tcp, 53/udp, 9000-9010/udp, icmp
		wantRowPrefixes := []string{
			"22/tcp",
			"8080/tcp",
			"53/udp",
			"9000-9010/udp",
			"icmp",
		}
		for i, prefix := range wantRowPrefixes {
			if !strings.HasPrefix(lines[i+1], prefix+" ") {
				t.Errorf("row %d = %q, expected prefix %q", i+1, lines[i+1], prefix)
			}
		}

		// Verify multiple sources comma-joined and ICMP ports rendered as '-'
		if !strings.Contains(lines[4], "10.0.0.0/8, 2001:db8::/32") {
			t.Errorf("expected comma-joined sources in UDP range row: %s", lines[4])
		}
		if !strings.Contains(lines[5], "icmp") || !strings.Contains(lines[5], "-") || !strings.Contains(lines[5], "10.0.0.0/8") {
			t.Errorf("expected ICMP row with '-' ports and source, got: %s", lines[5])
		}
	})

	t.Run("JSON output encodes FirewallInfo with sorted inbound rules", func(t *testing.T) {
		tempDir := filepath.Join(t.TempDir(), "fw-list-json")
		mock := newMockProvider()
		// Not in local state -> exercises fallback to prov.ListServers!
		mock.servers["srv-202"] = &provider.ServerInfo{
			ID:       "srv-202",
			Name:     "remote-only-box",
			Provider: types.ProviderDigitalOcean,
		}
		mock.firewalls["srv-202"] = &provider.FirewallInfo{
			ID:           "fw-202",
			Name:         "dev-vps-remote-only-box",
			ServerID:     "srv-202",
			InboundRules: sampleRules,
		}

		oldFactory := providerFactory
		providerFactory = func(cfg *config.Config) (provider.Provider, error) { return mock, nil }
		defer func() { providerFactory = oldFactory }()

		cmd := newRootCmd()
		outBuf := new(bytes.Buffer)
		cmd.SetOut(outBuf)
		cmd.SetErr(new(bytes.Buffer))
		cmd.SetArgs([]string{"--home-dir", tempDir, "firewall", "list", "remote-only-box", "--json"})

		if err := cmd.Execute(); err != nil {
			t.Fatalf("firewall list --json failed: %v", err)
		}

		var got provider.FirewallInfo
		if err := json.Unmarshal(outBuf.Bytes(), &got); err != nil {
			t.Fatalf("failed to decode JSON output: %v\noutput:\n%s", err, outBuf.String())
		}
		if got.ID != "fw-202" || got.Name != "dev-vps-remote-only-box" || got.ServerID != "srv-202" {
			t.Errorf("unexpected FirewallInfo metadata: %+v", got)
		}
		wantOrder := []string{"22/tcp", "8080/tcp", "53/udp", "9000-9010/udp", "icmp"}
		if len(got.InboundRules) != len(wantOrder) {
			t.Fatalf("expected %d rules, got %d", len(wantOrder), len(got.InboundRules))
		}
		for i, want := range wantOrder {
			if got.InboundRules[i].Spec() != want {
				t.Errorf("JSON InboundRules[%d].Spec() = %q, want %q", i, got.InboundRules[i].Spec(), want)
			}
		}
	})

	t.Run("droplet without firewall prints allow hint", func(t *testing.T) {
		tempDir := filepath.Join(t.TempDir(), "fw-list-missing")
		mock := newMockProvider()
		mock.servers["srv-303"] = &provider.ServerInfo{
			ID:   "srv-303",
			Name: "legacy-box",
		}

		oldFactory := providerFactory
		providerFactory = func(cfg *config.Config) (provider.Provider, error) { return mock, nil }
		defer func() { providerFactory = oldFactory }()

		cmd := newRootCmd()
		outBuf := new(bytes.Buffer)
		cmd.SetOut(outBuf)
		cmd.SetErr(new(bytes.Buffer))
		cmd.SetArgs([]string{"--home-dir", tempDir, "firewall", "list", "legacy-box"})

		if err := cmd.Execute(); err != nil {
			t.Fatalf("expected clean exit with hint when firewall is absent, got: %v", err)
		}
		if !strings.Contains(outBuf.String(), "dev-vps firewall allow legacy-box <rule>") {
			t.Errorf("expected allow hint in output, got: %s", outBuf.String())
		}
	})

	t.Run("unknown droplet returns error", func(t *testing.T) {
		tempDir := filepath.Join(t.TempDir(), "fw-list-unknown")
		mock := newMockProvider()

		oldFactory := providerFactory
		providerFactory = func(cfg *config.Config) (provider.Provider, error) { return mock, nil }
		defer func() { providerFactory = oldFactory }()

		cmd := newRootCmd()
		cmd.SetOut(new(bytes.Buffer))
		cmd.SetErr(new(bytes.Buffer))
		cmd.SetArgs([]string{"--home-dir", tempDir, "firewall", "list", "does-not-exist"})

		err := cmd.Execute()
		if err == nil {
			t.Fatalf("expected error for unknown droplet, got nil")
		}
		if !strings.Contains(err.Error(), "does-not-exist") {
			t.Errorf("expected error to mention droplet name, got: %v", err)
		}
	})
}

func setupFirewallTestEnv(t *testing.T, withFirewall bool, initialRules []firewall.Rule) (string, *mockProvider) {
	t.Helper()
	tempDir := filepath.Join(t.TempDir(), "fw-cmd-home")
	if err := config.InitStorage(tempDir); err != nil {
		t.Fatalf("InitStorage failed: %v", err)
	}
	st, _ := config.LoadState(tempDir)
	st.AddServer(config.ServerRecord{
		ID:        "srv-fw-1",
		Name:      "my-droplet",
		Provider:  types.ProviderDigitalOcean,
		Region:    "nyc1",
		Size:      "s-2vcpu-4gb",
		IPAddress: "203.0.113.10",
		Status:    types.StatusActive,
		CreatedAt: time.Now(),
	})
	_ = config.SaveState(tempDir, st)

	mock := newMockProvider()
	mock.servers["srv-fw-1"] = &provider.ServerInfo{ID: "srv-fw-1", Name: "my-droplet"}
	if withFirewall {
		mock.firewalls["srv-fw-1"] = &provider.FirewallInfo{
			ID:           "fw-1",
			Name:         "dev-vps-my-droplet",
			ServerID:     "srv-fw-1",
			InboundRules: initialRules,
		}
	}

	oldFactory := providerFactory
	providerFactory = func(cfg *config.Config) (provider.Provider, error) { return mock, nil }
	t.Cleanup(func() {
		providerFactory = oldFactory
		customBaseDir = ""
	})

	return tempDir, mock
}

func runFirewallCLI(tempDir string, subArgs ...string) (string, string, error) {
	cmd := newRootCmd()
	outBuf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	cmd.SetOut(outBuf)
	cmd.SetErr(errBuf)
	args := append([]string{"--home-dir", tempDir, "firewall"}, subArgs...)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return outBuf.String(), errBuf.String(), err
}

func TestFirewallAllowCommand(t *testing.T) {
	t.Run("allow 9000 icmp 9001/udp 9100-9110 adds all rules with default sources", func(t *testing.T) {
		tempDir, mock := setupFirewallTestEnv(t, true, []firewall.Rule{
			firewall.SSHRule([]string{"0.0.0.0/0", "::/0"}),
		})

		out, _, err := runFirewallCLI(tempDir, "allow", "my-droplet", "9000", "icmp", "9001/udp", "9100-9110")
		if err != nil {
			t.Fatalf("firewall allow failed: %v", err)
		}

		fw := mock.firewalls["srv-fw-1"]
		if len(fw.InboundRules) != 5 {
			t.Fatalf("expected 5 rules, got %+v", fw.InboundRules)
		}
		for _, want := range []string{"9000/tcp", "9100-9110/tcp", "9001/udp", "icmp"} {
			if !strings.Contains(out, want) {
				t.Errorf("expected %q in output, got:\n%s", want, out)
			}
		}
	})

	t.Run("allow with -s merges new sources into existing rule and reports skipped", func(t *testing.T) {
		tempDir, mock := setupFirewallTestEnv(t, true, []firewall.Rule{
			firewall.SSHRule([]string{"0.0.0.0/0", "::/0"}),
			{Protocol: types.ProtocolTCP, Ports: firewall.PortRange{From: 5432, To: 5432}, Sources: []string{"10.0.0.0/8"}},
		})

		out, _, err := runFirewallCLI(tempDir, "allow", "my-droplet", "5432", "-s", "10.0.0.0/8,203.0.113.7")
		if err != nil {
			t.Fatalf("firewall allow -s failed: %v", err)
		}

		fw := mock.firewalls["srv-fw-1"]
		wantSources := []string{"10.0.0.0/8", "203.0.113.7/32"}
		if !reflect.DeepEqual(fw.InboundRules[1].Sources, wantSources) {
			t.Errorf("5432/tcp sources = %v, want %v", fw.InboundRules[1].Sources, wantSources)
		}
		if !strings.Contains(out, "Added:") || !strings.Contains(out, "203.0.113.7/32") {
			t.Errorf("expected Added line for 203.0.113.7/32, got:\n%s", out)
		}
		if !strings.Contains(out, "Skipped:") || !strings.Contains(out, "10.0.0.0/8") {
			t.Errorf("expected Skipped line for 10.0.0.0/8, got:\n%s", out)
		}
	})

	t.Run("allow creates missing firewall with 22/tcp default sources plus requested rules", func(t *testing.T) {
		tempDir, mock := setupFirewallTestEnv(t, false, nil)

		out, _, err := runFirewallCLI(tempDir, "allow", "my-droplet", "9000", "-s", "203.0.113.7")
		if err != nil {
			t.Fatalf("firewall allow on missing firewall failed: %v", err)
		}

		fw, ok := mock.firewalls["srv-fw-1"]
		if !ok {
			t.Fatalf("expected firewall to be created")
		}
		if fw.Name != "dev-vps-my-droplet" {
			t.Errorf("expected name dev-vps-my-droplet, got %q", fw.Name)
		}
		if len(fw.InboundRules) != 2 {
			t.Fatalf("expected [22/tcp, 9000/tcp], got %+v", fw.InboundRules)
		}
		if fw.InboundRules[0].Spec() != "22/tcp" || !reflect.DeepEqual(fw.InboundRules[0].Sources, []string{"0.0.0.0/0", "::/0"}) {
			t.Errorf("expected 22/tcp with default sources, got %+v", fw.InboundRules[0])
		}
		if fw.InboundRules[1].Spec() != "9000/tcp" || !reflect.DeepEqual(fw.InboundRules[1].Sources, []string{"203.0.113.7/32"}) {
			t.Errorf("expected 9000/tcp with 203.0.113.7/32, got %+v", fw.InboundRules[1])
		}
		if !strings.Contains(out, "Created firewall dev-vps-my-droplet") {
			t.Errorf("expected creation message in output, got:\n%s", out)
		}
		if !strings.Contains(out, "Added:   22/tcp (0.0.0.0/0, ::/0)") || !strings.Contains(out, "Added:   9000/tcp (203.0.113.7/32)") {
			t.Errorf("expected both rules reported as Added, got:\n%s", out)
		}
	})

	t.Run("allow 22 on missing firewall reports added and not no-op", func(t *testing.T) {
		tempDir, mock := setupFirewallTestEnv(t, false, nil)

		out, _, err := runFirewallCLI(tempDir, "allow", "my-droplet", "22")
		if err != nil {
			t.Fatalf("firewall allow 22 on missing firewall failed: %v", err)
		}

		fw, ok := mock.firewalls["srv-fw-1"]
		if !ok || len(fw.InboundRules) != 1 || fw.InboundRules[0].Spec() != "22/tcp" {
			t.Fatalf("expected newly created firewall with 22/tcp, got %+v", fw)
		}
		if !strings.Contains(out, "Created firewall dev-vps-my-droplet") {
			t.Errorf("expected creation message in output, got:\n%s", out)
		}
		if !strings.Contains(out, "Added:   22/tcp (0.0.0.0/0, ::/0)") {
			t.Errorf("expected 22/tcp reported as Added, got:\n%s", out)
		}
		if strings.Contains(out, "No firewall changes applied.") || strings.Contains(out, "Skipped:") {
			t.Errorf("must not print no-op or skipped after creating a new firewall, got:\n%s", out)
		}
	})

	t.Run("no-op allow skips UpdateFirewallRules API call", func(t *testing.T) {
		tempDir, mock := setupFirewallTestEnv(t, true, []firewall.Rule{
			firewall.SSHRule([]string{"0.0.0.0/0", "::/0"}),
			{Protocol: types.ProtocolTCP, Ports: firewall.PortRange{From: 80, To: 80}, Sources: []string{"0.0.0.0/0", "::/0"}},
		})

		out, _, err := runFirewallCLI(tempDir, "allow", "my-droplet", "80")
		if err != nil {
			t.Fatalf("no-op allow failed: %v", err)
		}
		for _, call := range mock.callLog {
			if strings.HasPrefix(call, "UpdateFirewallRules:") {
				t.Errorf("expected no UpdateFirewallRules call on no-op, got calls: %v", mock.callLog)
			}
		}
		if !strings.Contains(out, "No firewall changes applied.") {
			t.Errorf("expected no-change summary, got:\n%s", out)
		}
	})

	t.Run("invalid spec or source makes zero API calls", func(t *testing.T) {
		tempDir, mock := setupFirewallTestEnv(t, true, []firewall.Rule{
			firewall.SSHRule([]string{"0.0.0.0/0", "::/0"}),
		})

		if _, _, err := runFirewallCLI(tempDir, "allow", "my-droplet", "9000/sctp", "9010-9000"); err == nil {
			t.Fatalf("expected error for invalid specs")
		}
		if len(mock.callLog) != 0 {
			t.Errorf("expected zero provider calls on invalid spec, got %v", mock.callLog)
		}

		if _, _, err := runFirewallCLI(tempDir, "allow", "my-droplet", "9000", "-s", "10.0.0.1/8"); err == nil {
			t.Fatalf("expected error for CIDR with host bits")
		}
		if len(mock.callLog) != 0 {
			t.Errorf("expected zero provider calls on invalid source, got %v", mock.callLog)
		}
	})
}

func TestFirewallDenyCommand(t *testing.T) {
	t.Run("deny whole rule removes it completely", func(t *testing.T) {
		tempDir, mock := setupFirewallTestEnv(t, true, []firewall.Rule{
			firewall.SSHRule([]string{"0.0.0.0/0", "::/0"}),
			{Protocol: types.ProtocolTCP, Ports: firewall.PortRange{From: 8080, To: 8080}, Sources: []string{"0.0.0.0/0", "::/0"}},
		})

		out, _, err := runFirewallCLI(tempDir, "deny", "my-droplet", "8080")
		if err != nil {
			t.Fatalf("firewall deny failed: %v", err)
		}
		fw := mock.firewalls["srv-fw-1"]
		if len(fw.InboundRules) != 1 || fw.InboundRules[0].Spec() != "22/tcp" {
			t.Errorf("expected only 22/tcp remaining, got %+v", fw.InboundRules)
		}
		if !strings.Contains(out, "Removed: 8080/tcp") {
			t.Errorf("expected Removed line for 8080/tcp, got:\n%s", out)
		}
	})

	t.Run("deny with -s removes partial sources and removes rule when last source removed", func(t *testing.T) {
		tempDir, mock := setupFirewallTestEnv(t, true, []firewall.Rule{
			firewall.SSHRule([]string{"0.0.0.0/0", "::/0"}),
			{Protocol: types.ProtocolTCP, Ports: firewall.PortRange{From: 8080, To: 8080}, Sources: []string{"10.0.0.0/8", "203.0.113.7/32"}},
			{Protocol: types.ProtocolTCP, Ports: firewall.PortRange{From: 5432, To: 5432}, Sources: []string{"203.0.113.7/32"}},
		})

		_, _, err := runFirewallCLI(tempDir, "deny", "my-droplet", "8080", "5432", "-s", "203.0.113.7")
		if err != nil {
			t.Fatalf("firewall deny -s failed: %v", err)
		}

		fw := mock.firewalls["srv-fw-1"]
		if len(fw.InboundRules) != 2 {
			t.Fatalf("expected 2 rules remaining (22/tcp, 8080/tcp), got %+v", fw.InboundRules)
		}
		if !reflect.DeepEqual(fw.InboundRules[1].Sources, []string{"10.0.0.0/8"}) {
			t.Errorf("8080/tcp sources = %v, want [10.0.0.0/8]", fw.InboundRules[1].Sources)
		}
	})

	t.Run("deny 22 refused and deny 22 -s any refused until another source remains", func(t *testing.T) {
		tempDir, mock := setupFirewallTestEnv(t, true, []firewall.Rule{
			firewall.SSHRule([]string{"0.0.0.0/0", "::/0"}),
		})

		// 1. deny 22 without -s refused
		_, _, err := runFirewallCLI(tempDir, "deny", "my-droplet", "22")
		if !errors.Is(err, firewall.ErrSSHRuleProtected) {
			t.Fatalf("expected ErrSSHRuleProtected for deny 22, got: %v", err)
		}
		if !strings.Contains(err.Error(), "dev-vps firewall allow my-droplet 22 -s") {
			t.Errorf("expected SSH restriction hint in error, got: %v", err)
		}

		// 2. deny 22 -s any refused when it would empty the rule
		_, _, err = runFirewallCLI(tempDir, "deny", "my-droplet", "22", "-s", "any")
		if !errors.Is(err, firewall.ErrSSHRuleProtected) {
			t.Fatalf("expected ErrSSHRuleProtected for deny 22 -s any, got: %v", err)
		}

		// 3. allow 22 -s 203.0.113.7 then deny 22 -s any succeeds
		if _, _, err := runFirewallCLI(tempDir, "allow", "my-droplet", "22", "-s", "203.0.113.7"); err != nil {
			t.Fatalf("allow 22 -s failed: %v", err)
		}
		if _, _, err := runFirewallCLI(tempDir, "deny", "my-droplet", "22", "-s", "any"); err != nil {
			t.Fatalf("deny 22 -s any after adding IP failed: %v", err)
		}

		fw := mock.firewalls["srv-fw-1"]
		if !reflect.DeepEqual(fw.InboundRules[0].Sources, []string{"203.0.113.7/32"}) {
			t.Errorf("expected 22/tcp restricted to [203.0.113.7/32], got %v", fw.InboundRules[0].Sources)
		}
	})

	t.Run("deny 9005 covered by 9000-9010/tcp reports covered-by and skips API update", func(t *testing.T) {
		tempDir, mock := setupFirewallTestEnv(t, true, []firewall.Rule{
			firewall.SSHRule([]string{"0.0.0.0/0", "::/0"}),
			{Protocol: types.ProtocolTCP, Ports: firewall.PortRange{From: 9000, To: 9010}, Sources: []string{"0.0.0.0/0", "::/0"}},
		})

		out, _, err := runFirewallCLI(tempDir, "deny", "my-droplet", "9005")
		if err != nil {
			t.Fatalf("deny 9005 failed: %v", err)
		}
		if !strings.Contains(out, "not open (covered by 9000-9010/tcp)") {
			t.Errorf("expected covered-by message, got:\n%s", out)
		}
		for _, call := range mock.callLog {
			if strings.HasPrefix(call, "UpdateFirewallRules:") {
				t.Errorf("expected zero UpdateFirewallRules calls on covered-by no-op, got %v", mock.callLog)
			}
		}
	})

	t.Run("invalid spec or source on deny makes zero API calls", func(t *testing.T) {
		tempDir, mock := setupFirewallTestEnv(t, true, []firewall.Rule{
			firewall.SSHRule([]string{"0.0.0.0/0", "::/0"}),
		})

		if _, _, err := runFirewallCLI(tempDir, "deny", "my-droplet", "9000/icmp"); err == nil {
			t.Fatalf("expected error for invalid spec 9000/icmp")
		}
		if _, _, err := runFirewallCLI(tempDir, "deny", "my-droplet", "80", "-s", "example.com"); err == nil {
			t.Fatalf("expected error for invalid hostname source")
		}
		if len(mock.callLog) != 0 {
			t.Errorf("expected zero provider calls on invalid deny input, got %v", mock.callLog)
		}
	})

	t.Run("help output documents syntax table, sources, and SSH lockout warning", func(t *testing.T) {
		tempDir, _ := setupFirewallTestEnv(t, false, nil)

		allowHelp, _, err := runFirewallCLI(tempDir, "allow", "--help")
		if err != nil {
			t.Fatalf("allow --help failed: %v", err)
		}
		for _, snippet := range []string{"9000-9010/udp", "icmp", "--source", "0.0.0.0/0"} {
			if !strings.Contains(allowHelp, snippet) {
				t.Errorf("allow --help missing %q", snippet)
			}
		}

		denyHelp, _, err := runFirewallCLI(tempDir, "deny", "--help")
		if err != nil {
			t.Fatalf("deny --help failed: %v", err)
		}
		for _, snippet := range []string{"9000-9010/udp", "icmp", "--source", "lock yourself out"} {
			if !strings.Contains(denyHelp, snippet) {
				t.Errorf("deny --help missing %q", snippet)
			}
		}
	})
}
