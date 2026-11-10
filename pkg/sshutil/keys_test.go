package sshutil_test

import (
	"os"
	"path/filepath"
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

func TestCopyKeyPair(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	srcPriv, srcPub, _, _, err := sshutil.EnsureLocalSSHKey(srcDir)
	if err != nil {
		t.Fatalf("failed to prepare source keys: %v", err)
	}

	// 1. Missing source key check
	missingPriv := filepath.Join(srcDir, "nonexistent")
	if _, _, err := sshutil.CopyKeyPairToDir(missingPriv, srcPub, dstDir, false); err == nil {
		t.Errorf("expected error when source private key is missing")
	}

	// 2. Successful copy to directory
	copiedPriv, copiedPub, err := sshutil.CopyKeyPairToDir(srcPriv, srcPub, dstDir, false)
	if err != nil {
		t.Fatalf("CopyKeyPairToDir failed: %v", err)
	}

	privStat, err := os.Stat(copiedPriv)
	if err != nil {
		t.Fatalf("failed to stat copied private key: %v", err)
	}
	if perm := privStat.Mode().Perm(); perm != 0600 {
		t.Errorf("expected private key perm 0600, got %04o", perm)
	}

	pubStat, err := os.Stat(copiedPub)
	if err != nil {
		t.Fatalf("failed to stat copied public key: %v", err)
	}
	if perm := pubStat.Mode().Perm(); perm != 0644 {
		t.Errorf("expected public key perm 0644, got %04o", perm)
	}

	// 3. Overwrite refusal without force
	if _, _, err := sshutil.CopyKeyPairToDir(srcPriv, srcPub, dstDir, false); err == nil {
		t.Errorf("expected error when destination files exist and force is false")
	}

	// 4. Overwrite allowed with force
	if _, _, err := sshutil.CopyKeyPairToDir(srcPriv, srcPub, dstDir, true); err != nil {
		t.Fatalf("expected successful overwrite with force=true, got: %v", err)
	}
}
