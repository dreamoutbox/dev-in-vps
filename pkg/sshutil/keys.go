// Package sshutil provides cryptographic routines for generating and managing SSH keys.
package sshutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
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

// copySingleKey reads a file and writes it to dst with the specified file permissions.
//
// Input args:
//   - src: path to the source file to copy.
//   - dst: path to the destination file.
//   - perm: file mode permissions for the written file.
//
// Returns:
//   - error: non-nil if reading, directory creation, or writing fails.
//
// Example:
//
//	err := copySingleKey("~/.dev-vps/.ssh/id_ed25519", "./id_ed25519", 0600)
func copySingleKey(src string, dst string, perm os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("failed to read source file %s: %w", src, err)
	}

	dstDir := filepath.Dir(dst)
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dstDir, err)
	}

	if err := os.WriteFile(dst, data, perm); err != nil {
		return fmt.Errorf("failed to write destination file %s: %w", dst, err)
	}

	if err := os.Chmod(dst, perm); err != nil {
		return fmt.Errorf("failed to set permissions on %s: %w", dst, err)
	}

	return nil
}

// CopyKeyPairFiles copies private and public key files to their target destinations,
// setting 0600 permissions on the private key and 0644 permissions on the public key.
//
// Input args:
//   - srcPrivPath: path to the source private key.
//   - srcPubPath: path to the source public key.
//   - dstPrivPath: path to the destination private key.
//   - dstPubPath: path to the destination public key.
//   - force: if true, existing destination files will be overwritten.
//
// Returns:
//   - error: non-nil if source keys are missing, destinations exist without force, or writing fails.
//
// Example:
//
//	err := sshutil.CopyKeyPairFiles("src/id_ed25519", "src/id_ed25519.pub", "dst/id_ed25519", "dst/id_ed25519.pub", false)
func CopyKeyPairFiles(srcPrivPath, srcPubPath, dstPrivPath, dstPubPath string, force bool) error {
	if _, err := os.Stat(srcPrivPath); err != nil {
		return fmt.Errorf("source private key %s not found: %w", srcPrivPath, err)
	}
	if _, err := os.Stat(srcPubPath); err != nil {
		return fmt.Errorf("source public key %s not found: %w", srcPubPath, err)
	}

	if !force {
		if _, err := os.Stat(dstPrivPath); err == nil {
			return fmt.Errorf("destination file %s already exists (use --force to overwrite)", dstPrivPath)
		}
		if _, err := os.Stat(dstPubPath); err == nil {
			return fmt.Errorf("destination file %s already exists (use --force to overwrite)", dstPubPath)
		}
	}

	if err := copySingleKey(srcPrivPath, dstPrivPath, 0600); err != nil {
		return err
	}

	if err := copySingleKey(srcPubPath, dstPubPath, 0644); err != nil {
		return err
	}

	return nil
}

// CopyKeyPairToDir copies a private and public key pair into a destination directory,
// retaining their existing filenames.
//
// Input args:
//   - srcPrivPath: path to the source private key.
//   - srcPubPath: path to the source public key.
//   - dstDir: destination directory.
//   - force: if true, existing files in dstDir will be overwritten.
//
// Returns:
//   - dstPriv: resulting path to the copied private key.
//   - dstPub: resulting path to the copied public key.
//   - error: non-nil if source keys are missing, files exist without force, or copy fails.
//
// Example:
//
//	priv, pub, err := sshutil.CopyKeyPairToDir("keys/id_ed25519", "keys/id_ed25519.pub", "./backup", false)
func CopyKeyPairToDir(srcPrivPath, srcPubPath, dstDir string, force bool) (string, string, error) {
	dstPrivPath := filepath.Join(dstDir, filepath.Base(srcPrivPath))
	dstPubPath := filepath.Join(dstDir, filepath.Base(srcPubPath))

	if err := CopyKeyPairFiles(srcPrivPath, srcPubPath, dstPrivPath, dstPubPath, force); err != nil {
		return "", "", err
	}

	return dstPrivPath, dstPubPath, nil
}
