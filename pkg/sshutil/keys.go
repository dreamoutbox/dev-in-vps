// Package sshutil provides cryptographic routines for generating and managing SSH keys.
package sshutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/dreamoutbox/dev-in-vps/pkg/config"
	"golang.org/x/crypto/ssh"
)

// GenerateEd25519Key creates a fresh Ed25519 key pair formatted as OpenSSH PEM and authorized_keys.
//
// Returns:
//   - []byte: OpenSSH private key PEM encoded bytes.
//   - string: authorized_keys formatted public key string.
//   - error: non-nil if random entropy or key serialization fails.
//
// Example:
//
//	privPEM, pubAuth, err := sshutil.GenerateEd25519Key()
func GenerateEd25519Key() ([]byte, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate ed25519 key: %w", err)
	}

	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal private key: %w", err)
	}

	privBytes := pem.EncodeToMemory(pemBlock)

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, "", fmt.Errorf("failed to convert public key: %w", err)
	}

	pubBytes := ssh.MarshalAuthorizedKey(sshPub)
	pubStr := strings.TrimSpace(string(pubBytes))

	return privBytes, pubStr, nil
}

// EnsureLocalSSHKey ensures an Ed25519 key pair exists under ~/.dev-vps/.ssh/.
// If either the private or public key is missing, a new key pair is generated.
//
// Input args:
//   - baseDir: root directory path (if empty, config.BaseDir() is used).
//
// Returns:
//   - privPath: absolute path to the private key file.
//   - pubPath: absolute path to the public key file.
//   - pubContent: public key text formatted for authorized_keys.
//   - created: true if a new key pair was generated, false if already present.
//   - error: non-nil if directory creation or file operations fail.
//
// Example:
//
//	priv, pub, content, created, err := sshutil.EnsureLocalSSHKey("")
func EnsureLocalSSHKey(baseDir string) (privPath string, pubPath string, pubContent string, created bool, err error) {
	if baseDir == "" {
		baseDir = config.BaseDir()
	}

	privPath = config.SSHPrivateKeyPath(baseDir)
	pubPath = config.SSHPublicKeyPath(baseDir)

	privExists := false
	pubExists := false

	if _, statErr := os.Stat(privPath); statErr == nil {
		privExists = true
	}
	if _, statErr := os.Stat(pubPath); statErr == nil {
		pubExists = true
	}

	if privExists && pubExists {
		data, readErr := os.ReadFile(pubPath)
		if readErr != nil {
			return privPath, pubPath, "", false, fmt.Errorf("failed to read existing public key %s: %w", pubPath, readErr)
		}
		return privPath, pubPath, strings.TrimSpace(string(data)), false, nil
	}

	// Ensure .ssh directory exists with 0700 permissions
	sshDir := config.SSHDir(baseDir)
	if mkErr := os.MkdirAll(sshDir, 0700); mkErr != nil {
		return privPath, pubPath, "", false, fmt.Errorf("failed to create ssh directory %s: %w", sshDir, mkErr)
	}

	privBytes, pubStr, genErr := GenerateEd25519Key()
	if genErr != nil {
		return privPath, pubPath, "", false, genErr
	}

	if writeErr := os.WriteFile(privPath, privBytes, 0600); writeErr != nil {
		return privPath, pubPath, "", false, fmt.Errorf("failed to write private key %s: %w", privPath, writeErr)
	}

	if writeErr := os.WriteFile(pubPath, []byte(pubStr+"\n"), 0644); writeErr != nil {
		return privPath, pubPath, "", false, fmt.Errorf("failed to write public key %s: %w", pubPath, writeErr)
	}

	return privPath, pubPath, pubStr, true, nil
}
