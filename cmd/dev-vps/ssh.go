package main

import (
	"context"
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
func newSSHCmd() *cobra.Command {
	sshCmd := &cobra.Command{
		Use:   "ssh [name-or-id]",
		Short: "Connect to a running dev VPS instance via SSH",
		Long: `Connect directly to a provisioned dev server using the managed SSH key.
If [name-or-id] is omitted and exactly one active server exists, it connects automatically.`,
		RunE: runSSHConnect,
	}

	sshCmd.AddCommand(newSSHCreateCmd())

	return sshCmd
}

// newSSHCreateCmd constructs the 'dev-vps ssh create' subcommand.
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

// runSSHConnect executes interactive SSH connection to the target instance.
func runSSHConnect(cmd *cobra.Command, args []string) error {
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

	if len(args) > 0 {
		rec, found := st.GetServer(args[0])
		if !found {
			return fmt.Errorf("server %q not found in local state", args[0])
		}
		targetIP = rec.IPAddress
		targetName = rec.Name
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

	cmd.Printf("Connecting to %s (%s)...\n", targetName, targetIP)

	sshArgs := []string{
		"-i", privKey,
		"-o", "StrictHostKeyChecking=accept-new",
		fmt.Sprintf("root@%s", targetIP),
	}

	return sshExecutor(sshArgs)
}
