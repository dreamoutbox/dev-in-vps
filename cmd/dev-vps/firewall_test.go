package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
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
