package sshutil_test

import (
	"os"
	"strings"
	"testing"

	"github.com/dreamoutbox/dev-in-vps/pkg/sshutil"
	"golang.org/x/crypto/ssh"
)

func TestGenerateEd25519Key(t *testing.T) {
	privBytes, pubStr, err := sshutil.GenerateEd25519Key()
	if err != nil {
		t.Fatalf("GenerateEd25519Key failed: %v", err)
	}

	if !strings.Contains(string(privBytes), "BEGIN OPENSSH PRIVATE KEY") {
		t.Errorf("expected OPENSSH PRIVATE KEY header in private key")
	}

	if !strings.HasPrefix(pubStr, "ssh-ed25519 ") {
		t.Errorf("expected ssh-ed25519 prefix in public key string, got: %s", pubStr)
	}

	// Verify the public key is parseable
	_, _, _, _, err = ssh.ParseAuthorizedKey([]byte(pubStr))
	if err != nil {
		t.Fatalf("failed to parse generated public key: %v", err)
	}
}

func TestEnsureLocalSSHKey(t *testing.T) {
	tempDir := t.TempDir()

	// 1. First run: key should be generated
	privPath, pubPath, pubContent, created, err := sshutil.EnsureLocalSSHKey(tempDir)
	if err != nil {
		t.Fatalf("EnsureLocalSSHKey failed: %v", err)
	}
	if !created {
		t.Errorf("expected created to be true on first invocation")
	}

	// Check file permissions
	privInfo, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("failed to stat private key: %v", err)
	}
	if perm := privInfo.Mode().Perm(); perm != 0600 {
		t.Errorf("expected private key perm 0600, got %04o", perm)
	}

	// 2. Second run: key should be reused, not regenerated
	privPath2, pubPath2, pubContent2, created2, err := sshutil.EnsureLocalSSHKey(tempDir)
	if err != nil {
		t.Fatalf("EnsureLocalSSHKey second run failed: %v", err)
	}
	if created2 {
		t.Errorf("expected created to be false on second invocation")
	}
	if privPath2 != privPath || pubPath2 != pubPath || pubContent2 != pubContent {
		t.Errorf("expected identical key metadata on second invocation")
	}
}
