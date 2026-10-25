package config

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/dreamoutbox/dev-in-vps/pkg/types"
)

// Config represents persistent application settings stored in config.json.
type Config struct {
	DefaultProvider   types.ProviderType `json:"default_provider"`
	DefaultRegion     string             `json:"default_region"`
	DefaultSize       string             `json:"default_size"`
	DigitalOceanToken string             `json:"digitalocean_token,omitempty"`
}

// DefaultConfig returns a new Config populated with sensible defaults.
//
// Returns:
//   - *Config: pointer to initialized default config.
//
// Example:
//
//	cfg := config.DefaultConfig()
func DefaultConfig() *Config {
	return &Config{
		DefaultProvider: types.ProviderDigitalOcean,
		DefaultRegion:   "nyc1",
		DefaultSize:     "s-2vcpu-4gb",
	}
}

// defaultInitScriptContent returns the bootstrap shell script body for new installations.
func defaultInitScriptContent() string {
	return `#!/bin/sh
set -eu
echo "dev-vps auto-setup: initializing server..."
`
}

// InitStorage ensures the directory hierarchy and default files exist at base.
//
// Input args:
//   - base: root directory path (if empty, BaseDir() is used).
//
// Returns:
//   - error: non-nil if directory creation or file initialization fails.
//
// Example:
//
//	err := config.InitStorage("")
func InitStorage(base string) error {
	if base == "" {
		base = BaseDir()
	}

	// Create root directory with standard directory permissions (0755).
	if err := os.MkdirAll(base, 0755); err != nil {
		return fmt.Errorf("failed to create base directory %s: %w", base, err)
	}

	// Create SSH directory with strict permissions (0700).
	sshDir := SSHDir(base)
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("failed to create ssh directory %s: %w", sshDir, err)
	}

	// Create auto-setup directory with standard permissions (0755).
	autoSetupDir := AutoSetupDir(base)
	if err := os.MkdirAll(autoSetupDir, 0755); err != nil {
		return fmt.Errorf("failed to create auto-setup directory %s: %w", autoSetupDir, err)
	}

	// Initialize default init.sh if it does not exist yet.
	initScript := AutoSetupScriptPath(base)
	if _, err := os.Stat(initScript); os.IsNotExist(err) {
		if err := os.WriteFile(initScript, []byte(defaultInitScriptContent()), 0755); err != nil {
			return fmt.Errorf("failed to write default init script %s: %w", initScript, err)
		}
	}

	// Initialize default config.json if not present.
	cfgPath := ConfigPath(base)
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		if err := SaveConfig(base, DefaultConfig()); err != nil {
			return fmt.Errorf("failed to write initial config %s: %w", cfgPath, err)
		}
	}

	// Initialize empty state.json if not present.
	statePath := StatePath(base)
	if _, err := os.Stat(statePath); os.IsNotExist(err) {
		emptyState := NewState()
		if err := SaveState(base, emptyState); err != nil {
			return fmt.Errorf("failed to write initial state %s: %w", statePath, err)
		}
	}

	return nil
}

// LoadConfig reads and parses config.json from the base directory.
//
// Input args:
//   - base: root directory path (if empty, BaseDir() is used).
//
// Returns:
//   - *Config: parsed configuration.
//   - error: non-nil if reading or unmarshaling fails.
//
// Example:
//
//	cfg, err := config.LoadConfig("")
func LoadConfig(base string) (*Config, error) {
	path := ConfigPath(base)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

	return &cfg, nil
}

// SaveConfig writes the given Config as formatted JSON to config.json.
//
// Input args:
//   - base: root directory path (if empty, BaseDir() is used).
//   - cfg: configuration to write.
//
// Returns:
//   - error: non-nil if writing or marshaling fails.
//
// Example:
//
//	err := config.SaveConfig("", cfg)
func SaveConfig(base string, cfg *Config) error {
	path := ConfigPath(base)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		return fmt.Errorf("failed to write config file %s: %w", path, err)
	}

	return nil
}
