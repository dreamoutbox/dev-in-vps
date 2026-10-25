package config

import (
	"fmt"
	"os"
)

// ValidateAndFixPermissions checks and corrects file permissions on sensitive files in the storage directory.
// Ensures .ssh directory has 0700 permissions and private key has 0600 permissions.
//
// Input args:
//   - base: root directory path (if empty, BaseDir() is used).
//
// Returns:
//   - error: non-nil if permission adjustment fails.
//
// Example:
//
//	err := config.ValidateAndFixPermissions("")
func ValidateAndFixPermissions(base string) error {
	if base == "" {
		base = BaseDir()
	}

	sshDir := SSHDir(base)
	if info, err := os.Stat(sshDir); err == nil {
		if info.Mode().Perm() != 0700 {
			if chmodErr := os.Chmod(sshDir, 0700); chmodErr != nil {
				return fmt.Errorf("failed to fix ssh directory permissions on %s: %w", sshDir, chmodErr)
			}
		}
	}

	privKey := SSHPrivateKeyPath(base)
	if info, err := os.Stat(privKey); err == nil {
		if info.Mode().Perm() != 0600 {
			if chmodErr := os.Chmod(privKey, 0600); chmodErr != nil {
				return fmt.Errorf("failed to fix private key permissions on %s: %w", privKey, chmodErr)
			}
		}
	}

	initScript := AutoSetupScriptPath(base)
	if info, err := os.Stat(initScript); err == nil {
		// Ensure init.sh is executable (0755)
		if info.Mode().Perm()&0111 == 0 {
			if chmodErr := os.Chmod(initScript, 0755); chmodErr != nil {
				return fmt.Errorf("failed to ensure execute permissions on %s: %w", initScript, chmodErr)
			}
		}
	}

	return nil
}
