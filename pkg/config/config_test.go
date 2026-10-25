package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dreamoutbox/dev-in-vps/pkg/config"
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
		ID:        "do-12345",
		Name:      "dev-alpha",
		Provider:  types.ProviderDigitalOcean,
		Region:    "nyc1",
		Size:      "s-2vcpu-4gb",
		IPAddress: "192.0.2.1",
		Status:    types.StatusActive,
		CreatedAt: time.Now(),
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
	if !ok || found.ID != "do-12345" {
		t.Errorf("expected to find server by name, got %+v (ok=%v)", found, ok)
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
