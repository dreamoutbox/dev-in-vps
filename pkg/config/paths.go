// Package config manages configuration files, server state, and local directories under ~/.dev-vps.
package config

import (
	"os"
	"path/filepath"
)

const (
	// EnvDevVPSHome defines the environment variable overriding the default ~/.dev-vps directory.
	EnvDevVPSHome = "DEV_VPS_HOME"

	// DefaultDirName is the default directory name created inside the user's home directory.
	DefaultDirName = ".dev-vps"

	// ConfigFileName is the JSON configuration file name.
	ConfigFileName = "config.json"

	// StateFileName is the JSON state file name.
	StateFileName = "state.json"

	// SSHDirName is the directory storing managed SSH key pairs.
	SSHDirName = ".ssh"

	// AutoSetupDirName is the directory storing bootstrap setup scripts.
	AutoSetupDirName = "auto-setup"

	// InitScriptName is the default startup shell script name.
	InitScriptName = "init.sh"
)

// BaseDir returns the root storage directory for dev-vps.
// It checks DEV_VPS_HOME environment variable first, defaulting to ~/.dev-vps.
//
// Returns:
//   - string: the absolute or home-relative path of the base directory.
//
// Example:
//
//	dir := config.BaseDir()
func BaseDir() string {
	if custom := os.Getenv(EnvDevVPSHome); custom != "" {
		return custom
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return DefaultDirName
	}
	return filepath.Join(home, DefaultDirName)
}

// ConfigPath returns the path to the config.json file within the specified base directory.
//
// Input args:
//   - base: root directory path (if empty, BaseDir() is used).
//
// Returns:
//   - string: path to config.json.
//
// Example:
//
//	path := config.ConfigPath("")
func ConfigPath(base string) string {
	if base == "" {
		base = BaseDir()
	}
	return filepath.Join(base, ConfigFileName)
}

// StatePath returns the path to the state.json file within the specified base directory.
//
// Input args:
//   - base: root directory path (if empty, BaseDir() is used).
//
// Returns:
//   - string: path to state.json.
//
// Example:
//
//	path := config.StatePath("")
func StatePath(base string) string {
	if base == "" {
		base = BaseDir()
	}
	return filepath.Join(base, StateFileName)
}

// SSHDir returns the path to the .ssh directory within the specified base directory.
//
// Input args:
//   - base: root directory path (if empty, BaseDir() is used).
//
// Returns:
//   - string: path to .ssh directory.
//
// Example:
//
//	dir := config.SSHDir("")
func SSHDir(base string) string {
	if base == "" {
		base = BaseDir()
	}
	return filepath.Join(base, SSHDirName)
}

// SSHPrivateKeyPath returns the path to the private SSH key file within the specified base directory.
//
// Input args:
//   - base: root directory path (if empty, BaseDir() is used).
//
// Returns:
//   - string: path to id_ed25519 private key.
//
// Example:
//
//	keyPath := config.SSHPrivateKeyPath("")
func SSHPrivateKeyPath(base string) string {
	return filepath.Join(SSHDir(base), "id_ed25519")
}

// SSHPublicKeyPath returns the path to the public SSH key file within the specified base directory.
//
// Input args:
//   - base: root directory path (if empty, BaseDir() is used).
//
// Returns:
//   - string: path to id_ed25519.pub public key.
//
// Example:
//
//	pubPath := config.SSHPublicKeyPath("")
func SSHPublicKeyPath(base string) string {
	return filepath.Join(SSHDir(base), "id_ed25519.pub")
}

// AutoSetupDir returns the path to the auto-setup directory within the specified base directory.
//
// Input args:
//   - base: root directory path (if empty, BaseDir() is used).
//
// Returns:
//   - string: path to auto-setup directory.
//
// Example:
//
//	dir := config.AutoSetupDir("")
func AutoSetupDir(base string) string {
	if base == "" {
		base = BaseDir()
	}
	return filepath.Join(base, AutoSetupDirName)
}

// AutoSetupScriptPath returns the path to the init.sh bootstrap script within the specified base directory.
//
// Input args:
//   - base: root directory path (if empty, BaseDir() is used).
//
// Returns:
//   - string: path to init.sh script.
//
// Example:
//
//	script := config.AutoSetupScriptPath("")
func AutoSetupScriptPath(base string) string {
	return filepath.Join(AutoSetupDir(base), InitScriptName)
}
