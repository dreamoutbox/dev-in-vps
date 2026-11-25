package config_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dreamoutbox/dev-in-vps/pkg/config"
	"github.com/dreamoutbox/dev-in-vps/pkg/firewall"
	"github.com/dreamoutbox/dev-in-vps/pkg/types"
)

func TestInitStorageAndConfig(t *testing.T) {
	tempDir := t.TempDir()

	// Initializing storage should create base, .ssh, auto-setup, init.sh, config.json, and state.json
	if err := config.InitStorage(tempDir); err != nil {
		t.Fatalf("InitStorage failed: %v", err)
	}

	// Verify .ssh directory permissions (0700)
	sshInfo, err := os.Stat(config.SSHDir(tempDir))
	if err != nil {
		t.Fatalf("failed to stat ssh dir: %v", err)
	}
	if perm := sshInfo.Mode().Perm(); perm != 0700 {
		t.Errorf("expected ssh dir perm 0700, got %04o", perm)
	}

	// Verify init.sh exists and has content
	initScript := config.AutoSetupScriptPath(tempDir)
	content, err := os.ReadFile(initScript)
	if err != nil {
		t.Fatalf("failed to read init.sh: %v", err)
	}
	if len(content) == 0 {
		t.Errorf("init.sh is empty")
	}
	if !strings.Contains(string(content), "/dev-vps/startup.log") {
		t.Errorf("expected /dev-vps/startup.log in default init.sh, got: %s", string(content))
	}

	// Verify load config
	cfg, err := config.LoadConfig(tempDir)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg.DefaultProvider != types.ProviderDigitalOcean {
		t.Errorf("expected default provider digitalocean, got %v", cfg.DefaultProvider)
	}

	// Update config and verify persistence
	cfg.DefaultRegion = "sfo3"
	if err := config.SaveConfig(tempDir, cfg); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	reloaded, err := config.LoadConfig(tempDir)
	if err != nil {
		t.Fatalf("LoadConfig after update failed: %v", err)
	}
	if reloaded.DefaultRegion != "sfo3" {
		t.Errorf("expected default region sfo3, got %s", reloaded.DefaultRegion)
	}
}

func TestStateManagement(t *testing.T) {
	tempDir := t.TempDir()
	if err := config.InitStorage(tempDir); err != nil {
		t.Fatalf("InitStorage failed: %v", err)
	}

	st, err := config.LoadState(tempDir)
	if err != nil {
		t.Fatalf("LoadState failed: %v", err)
	}

	rec := config.ServerRecord{
		ID:               "do-12345",
		Name:             "dev-alpha",
		Provider:         types.ProviderDigitalOcean,
		Region:           "nyc1",
		Size:             "s-2vcpu-4gb",
		IPAddress:        "192.0.2.1",
		PrivateIPAddress: "10.132.0.5",
		Status:           types.StatusActive,
		CreatedAt:        time.Now(),
	}

	st.AddServer(rec)
	if err := config.SaveState(tempDir, st); err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	reloaded, err := config.LoadState(tempDir)
	if err != nil {
		t.Fatalf("LoadState failed: %v", err)
	}

	found, ok := reloaded.GetServer("dev-alpha")
	if !ok || found.ID != "do-12345" || found.PrivateIPAddress != "10.132.0.5" {
		t.Errorf("expected to find server by name with private IP, got %+v (ok=%v)", found, ok)
	}

	foundByID, okByID := reloaded.GetServer("do-12345")
	if !okByID || foundByID.Name != "dev-alpha" {
		t.Errorf("expected to find server by ID, got %+v (ok=%v)", foundByID, okByID)
	}

	list := reloaded.ListServers()
	if len(list) != 1 {
		t.Errorf("expected 1 server, got %d", len(list))
	}

	// Remove server
	if !reloaded.RemoveServer("dev-alpha") {
		t.Errorf("expected RemoveServer to return true")
	}
	if len(reloaded.ListServers()) != 0 {
		t.Errorf("expected 0 servers after removal")
	}
}

func TestBaseDirEnvOverride(t *testing.T) {
	custom := filepath.Join(t.TempDir(), "custom-home")
	t.Setenv(config.EnvDevVPSHome, custom)

	if got := config.BaseDir(); got != custom {
		t.Errorf("expected BaseDir() to return %s, got %s", custom, got)
	}
}

func TestValidateAndFixPermissions(t *testing.T) {
	tempDir := t.TempDir()
	if err := config.InitStorage(tempDir); err != nil {
		t.Fatalf("InitStorage failed: %v", err)
	}

	privKey := config.SSHPrivateKeyPath(tempDir)
	if err := os.WriteFile(privKey, []byte("secret"), 0666); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	sshDir := config.SSHDir(tempDir)
	_ = os.Chmod(sshDir, 0755)

	if err := config.ValidateAndFixPermissions(tempDir); err != nil {
		t.Fatalf("ValidateAndFixPermissions failed: %v", err)
	}

	info, _ := os.Stat(sshDir)
	if perm := info.Mode().Perm(); perm != 0700 {
		t.Errorf("expected ssh dir perm 0700, got %04o", perm)
	}

	privInfo, _ := os.Stat(privKey)
	if perm := privInfo.Mode().Perm(); perm != 0600 {
		t.Errorf("expected private key perm 0600, got %04o", perm)
	}
}

func TestEnsureStartupLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty input",
			input:    "   ",
			expected: "",
		},
		{
			name:     "already contains logging redirection",
			input:    "#!/bin/sh\nexec > /dev-vps/startup.log 2>&1\necho hi",
			expected: "#!/bin/sh\nexec > /dev-vps/startup.log 2>&1\necho hi",
		},
		{
			name:     "script with shebang",
			input:    "#!/bin/bash\necho hello",
			expected: "#!/bin/bash\nmkdir -p /dev-vps\nexec > /dev-vps/startup.log 2>&1\necho hello",
		},
		{
			name:     "script without shebang",
			input:    "echo hello",
			expected: "mkdir -p /dev-vps\nexec > /dev-vps/startup.log 2>&1\necho hello",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := config.EnsureStartupLogging(tc.input)
			if got != tc.expected {
				t.Errorf("EnsureStartupLogging() =\n%q\nwant:\n%q", got, tc.expected)
			}
		})
	}
}

func TestFirewallConfigDefaultsAndBackwardCompatibility(t *testing.T) {
	t.Run("fresh storage writes firewall defaults block", func(t *testing.T) {
		tempDir := t.TempDir()
		if err := config.InitStorage(tempDir); err != nil {
			t.Fatalf("InitStorage failed: %v", err)
		}

		cfg, err := config.LoadConfig(tempDir)
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}
		if cfg.Firewall == nil {
			t.Fatalf("expected Firewall block to be populated on fresh install")
		}
		if !reflect.DeepEqual(cfg.Firewall.DefaultRules, firewall.DefaultRuleSpecs()) {
			t.Errorf("DefaultRules = %v, want %v", cfg.Firewall.DefaultRules, firewall.DefaultRuleSpecs())
		}
		if !reflect.DeepEqual(cfg.Firewall.DefaultSources, firewall.DefaultSources()) {
			t.Errorf("DefaultSources = %v, want %v", cfg.Firewall.DefaultSources, firewall.DefaultSources())
		}
	})

	t.Run("old config without firewall block loads cleanly and is not rewritten", func(t *testing.T) {
		tempDir := t.TempDir()
		if err := config.InitStorage(tempDir); err != nil {
			t.Fatalf("InitStorage failed: %v", err)
		}

		legacyJSON := "{\n  \"default_provider\": \"digitalocean\",\n  \"default_region\": \"sgp1\",\n  \"default_size\": \"s-1vcpu-1gb\"\n}\n"
		cfgPath := config.ConfigPath(tempDir)
		if err := os.WriteFile(cfgPath, []byte(legacyJSON), 0600); err != nil {
			t.Fatalf("failed to write legacy config: %v", err)
		}

		// Re-running InitStorage and LoadConfig must not overwrite the legacy file.
		if err := config.InitStorage(tempDir); err != nil {
			t.Fatalf("InitStorage on existing dir failed: %v", err)
		}
		cfg, err := config.LoadConfig(tempDir)
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}
		if cfg.Firewall != nil {
			t.Errorf("expected nil Firewall for legacy config, got %+v", cfg.Firewall)
		}

		afterBytes, err := os.ReadFile(cfgPath)
		if err != nil {
			t.Fatalf("failed to re-read config.json: %v", err)
		}
		if string(afterBytes) != legacyJSON {
			t.Errorf("expected legacy config.json not to be rewritten;\ngot:\n%s\nwant:\n%s", string(afterBytes), legacyJSON)
		}
	})

	t.Run("explicit empty default_rules distinguishes from missing field", func(t *testing.T) {
		tempDir := t.TempDir()
		if err := config.InitStorage(tempDir); err != nil {
			t.Fatalf("InitStorage failed: %v", err)
		}

		rawJSON := `{
  "default_provider": "digitalocean",
  "default_region": "nyc1",
  "default_size": "s-2vcpu-4gb",
  "firewall": {
    "default_rules": []
  }
}`
		if err := os.WriteFile(config.ConfigPath(tempDir), []byte(rawJSON), 0600); err != nil {
			t.Fatalf("failed to write config: %v", err)
		}

		cfg, err := config.LoadConfig(tempDir)
		if err != nil {
			t.Fatalf("LoadConfig failed: %v", err)
		}
		if cfg.Firewall == nil {
			t.Fatalf("expected non-nil Firewall block")
		}
		if cfg.Firewall.DefaultRules == nil || len(cfg.Firewall.DefaultRules) != 0 {
			t.Errorf("expected non-nil empty DefaultRules, got %#v", cfg.Firewall.DefaultRules)
		}
		if cfg.Firewall.DefaultSources != nil {
			t.Errorf("expected nil DefaultSources when omitted, got %#v", cfg.Firewall.DefaultSources)
		}
	})
}
