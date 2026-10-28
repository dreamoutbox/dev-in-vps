package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/dreamoutbox/dev-in-vps/pkg/config"
	"github.com/dreamoutbox/dev-in-vps/pkg/sshutil"
	"github.com/dreamoutbox/dev-in-vps/pkg/ui"
	"github.com/spf13/cobra"
)

// sshExecutor executes the system SSH binary.
// Can be replaced in tests to verify arguments without opening a terminal.
var sshExecutor = func(args []string) error {
	sshProc := exec.Command("ssh", args...)
	sshProc.Stdin = os.Stdin
	sshProc.Stdout = os.Stdout
	sshProc.Stderr = os.Stderr
	return sshProc.Run()
}

// newSSHCmd constructs the ssh command group and subcommands.
//
// Returns:
//   - *cobra.Command: ssh command configured with subcommands and flag handling.
//
// Example:
//
//	cmd := newSSHCmd()
func newSSHCmd() *cobra.Command {
	sshCmd := &cobra.Command{
		Use:   "ssh [name-or-id] [command...]",
		Short: "Connect to a running dev VPS instance via SSH or execute a command",
		Long: `Connect directly to a provisioned dev server using the managed SSH key,
or execute a command on the remote server and exit.
If [name-or-id] is omitted and exactly one active server exists, it connects automatically.`,
		DisableFlagParsing: true,
		RunE:               runSSHConnect,
	}

	sshCmd.AddCommand(newSSHCreateCmd())

	return sshCmd
}

// newSSHCreateCmd constructs the 'dev-vps ssh create' subcommand.
//
// Returns:
//   - *cobra.Command: create subcommand for SSH key provisioning.
//
// Example:
//
//	cmd := newSSHCreateCmd()
func newSSHCreateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "create",
		Short: "Generate local SSH key pair and register it with the cloud provider",
		Long: `Generates a new Ed25519 key pair in ~/.dev-vps/.ssh/ if not already present,
and registers the public key with your configured cloud provider using their API.`,
		RunE: runSSHCreate,
	}
}

// runSSHCreate handles generating and synchronizing the SSH key.
//
// Input args:
//   - cmd: the cobra command instance handling execution context and output.
//   - args: command arguments passed to create subcommand (unused).
//
// Returns:
//   - error: non-nil if SSH key generation or provider sync fails.
//
// Example:
//
//	err := runSSHCreate(cmd, []string{})
func runSSHCreate(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

	cfg, err := config.LoadConfig(customBaseDir)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	prov, err := providerFactory(cfg)
	if err != nil {
		return err
	}

	privPath, pubPath, pubContent, created, err := sshutil.EnsureLocalSSHKey(customBaseDir)
	if err != nil {
		return fmt.Errorf("failed to prepare local SSH key: %w", err)
	}

	if created {
		cmd.Printf("Generated new Ed25519 key pair:\n  Private: %s\n  Public:  %s\n", privPath, pubPath)
	} else {
		cmd.Printf("Using existing SSH key:\n  Private: %s\n  Public:  %s\n", privPath, pubPath)
	}

	keyID, err := prov.EnsureSSHKey(ctx, "dev-vps-key", pubContent)
	if err != nil {
		return fmt.Errorf("failed to synchronize SSH key with cloud provider: %w", err)
	}

	cmd.Printf("SSH key registered with %s (Key ID: %s)\n", prov.Type(), keyID)
	return nil
}

// runSSHConnect executes an interactive SSH session or runs a remote command and exits.
//
// Input args:
//   - cmd: the cobra command instance handling execution context and output.
//   - args: positional arguments where args[0] optionally specifies the server name or ID,
//     and subsequent arguments specify the remote command to execute.
//
// Returns:
//   - error: non-nil if server resolution, key verification, or SSH execution fails.
//
// Example:
//
//	// Connect interactively:
//	err := runSSHConnect(cmd, []string{"dev1"})
//
//	// Execute remote command and exit:
//	err := runSSHConnect(cmd, []string{"dev1", "echo", "1"})
func runSSHConnect(cmd *cobra.Command, args []string) error {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		return cmd.Help()
	}

	st, err := config.LoadState(customBaseDir)
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}

	servers := st.ListServers()
	if len(servers) == 0 {
		return fmt.Errorf("no active dev servers found; spin one up with 'dev-vps create'")
	}

	var targetIP string
	var targetName string
	var remoteCmd []string

	if len(args) > 0 {
		rec, found := st.GetServer(args[0])
		if !found {
			return fmt.Errorf("server %q not found in local state", args[0])
		}
		targetIP = rec.IPAddress
		targetName = rec.Name
		remoteCmd = args[1:]
	} else if len(servers) == 1 {
		targetIP = servers[0].IPAddress
		targetName = servers[0].Name
	} else {
		chosenName, pickErr := ui.SelectServer(servers)
		if pickErr != nil {
			return pickErr
		}
		rec, _ := st.GetServer(chosenName)
		targetIP = rec.IPAddress
		targetName = rec.Name
	}

	if targetIP == "" {
		return fmt.Errorf("server %s does not have an assigned public IP yet", targetName)
	}

	privKey := config.SSHPrivateKeyPath(customBaseDir)
	if _, err := os.Stat(privKey); os.IsNotExist(err) {
		return fmt.Errorf("private SSH key not found at %s; run 'dev-vps ssh create' first", privKey)
	}

	if len(remoteCmd) == 0 {
		cmd.Printf("Connecting to %s (%s)...\n", targetName, targetIP)
	}

	sshArgs := []string{
		"-i", privKey,
		"-o", "StrictHostKeyChecking=accept-new",
		fmt.Sprintf("root@%s", targetIP),
	}
	if len(remoteCmd) > 0 {
		sshArgs = append(sshArgs, remoteCmd...)
	}

	err = sshExecutor(sshArgs)
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			cmd.SilenceErrors = true
			return exitErr
		}
		return err
	}
	return nil
}
