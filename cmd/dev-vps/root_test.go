package main

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/dreamoutbox/dev-in-vps/pkg/config"
	"github.com/spf13/cobra"
)

func TestRootCmdExecution(t *testing.T) {
	tempDir := filepath.Join(t.TempDir(), "cli-test-home")

	cmd := newRootCmd()
	// Add a dummy test child command to verify PersistentPreRunE execution
	executed := false
	cmd.AddCommand(&cobra.Command{
		Use: "test-run",
		Run: func(c *cobra.Command, args []string) {
			executed = true
		},
	})

	cmd.SetArgs([]string{"--home-dir", tempDir, "test-run"})
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("root command execution failed: %v", err)
	}

	if !executed {
		t.Fatalf("expected test-run subcommand to execute")
	}

	// Verify storage was initialized during execution
	if _, err := config.LoadConfig(tempDir); err != nil {
		t.Fatalf("expected config to be initialized in tempDir, got: %v", err)
	}
}
