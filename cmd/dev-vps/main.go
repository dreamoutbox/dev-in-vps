package main

import (
	"fmt"
	"os"

	"github.com/dreamoutbox/dev-in-vps/pkg/config"
	"github.com/spf13/cobra"
)

var (
	// customBaseDir allows overriding the ~/.dev-vps directory path via command flag.
	customBaseDir string
)

// newRootCmd builds the root cobra command for the dev-vps CLI.
//
// Returns:
//   - *cobra.Command: root command with global flags and storage initialization.
//
// Example:
//
//	cmd := newRootCmd()
//	_ = cmd.Execute()
func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "dev-vps",
		Short: "Provision and manage high-resource development VPS instances",
		Long:  `dev-vps is a command-line tool to spin up development cloud servers for remote development workloads.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if customBaseDir != "" {
				_ = os.Setenv(config.EnvDevVPSHome, customBaseDir)
			}
			// Automatically ensure ~/.dev-vps directory and default files exist.
			return config.InitStorage(customBaseDir)
		},
	}

	rootCmd.PersistentFlags().StringVar(
		&customBaseDir,
		"home-dir",
		"",
		"custom configuration and state directory (default: ~/.dev-vps)",
	)

	rootCmd.AddCommand(newCreateCmd())
	rootCmd.AddCommand(newSSHCmd())

	return rootCmd
}

func main() {
	rootCmd := newRootCmd()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
