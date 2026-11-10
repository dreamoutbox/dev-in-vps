package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	sshCmd.AddCommand(newSSHCopyCmd())
	sshCmd.AddCommand(newSSHImportCmd())

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

// newSSHCopyCmd constructs the 'dev-vps ssh copy' subcommand.
//
// Returns:
//   - *cobra.Command: copy subcommand for exporting the dev-vps SSH key pair.
//
// Example:
//
//	cmd := newSSHCopyCmd()
func newSSHCopyCmd() *cobra.Command {
	var force bool

	copyCmd := &cobra.Command{
		Use:   "copy [destination-path]",
		Short: "Copy managed SSH key pair to the specified directory",
		Long: `Copies the dev-vps SSH key pair (id_ed25519 and id_ed25519.pub) from ~/.dev-vps/.ssh/
to the specified destination directory (defaults to current directory).`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSSHCopy(cmd, args, force)
		},
	}

	copyCmd.Flags().BoolVarP(&force, "force", "f", false, "overwrite destination files if they already exist")

	return copyCmd
}

// runSSHCopy copies the managed dev-vps SSH key pair to a destination directory.
//
// Input args:
//   - cmd: the cobra command instance handling execution context and output.
//   - args: optional arguments where args[0] specifies the destination directory (defaults to ".").
//   - force: whether to overwrite existing destination files.
//
// Returns:
//   - error: non-nil if source keys are missing or copy fails.
//
// Example:
//
//	err := runSSHCopy(cmd, []string{"/tmp/keys"}, false)
func runSSHCopy(cmd *cobra.Command, args []string, force bool) error {
	dstDir := "."
	if len(args) > 0 && args[0] != "" {
		dstDir = args[0]
	}

	srcPriv := config.SSHPrivateKeyPath(customBaseDir)
	srcPub := config.SSHPublicKeyPath(customBaseDir)

	if _, err := os.Stat(srcPriv); os.IsNotExist(err) {
		return fmt.Errorf("private SSH key not found at %s; run 'dev-vps ssh create' first", srcPriv)
	}
	if _, err := os.Stat(srcPub); os.IsNotExist(err) {
		return fmt.Errorf("public SSH key not found at %s; run 'dev-vps ssh create' first", srcPub)
	}

	dstPriv, dstPub, err := sshutil.CopyKeyPairToDir(srcPriv, srcPub, dstDir, force)
	if err != nil {
		return err
	}

	cmd.Printf("Copied SSH key pair to %s:\n  Private: %s\n  Public:  %s\n", dstDir, dstPriv, dstPub)
	return nil
}

// newSSHImportCmd constructs the 'dev-vps ssh import' subcommand.
//
// Returns:
//   - *cobra.Command: import subcommand for adopting an existing SSH key pair.
//
// Example:
//
//	cmd := newSSHImportCmd()
func newSSHImportCmd() *cobra.Command {
	var force bool

	importCmd := &cobra.Command{
		Use:   "import [key-path]",
		Short: "Import existing SSH key pair into dev-vps managed storage",
		Long: `Imports an existing SSH key pair from ~/.ssh/ (default: ~/.ssh/id_ed25519)
or a specified private key path into ~/.dev-vps/.ssh/.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSSHImport(cmd, args, force)
		},
	}

	importCmd.Flags().BoolVarP(&force, "force", "f", false, "overwrite managed key files if they already exist")

	return importCmd
}

// resolveImportKeyPaths determines source private and public key paths from user input.
//
// Input args:
//   - arg: user-supplied key path or empty string for default ~/.ssh/id_ed25519.
//
// Returns:
//   - privPath: determined private key path.
//   - pubPath: determined public key path.
//   - error: non-nil if home directory cannot be resolved.
//
// Example:
//
//	priv, pub, err := resolveImportKeyPaths("~/.ssh/id_ed25519")
func resolveImportKeyPaths(arg string) (string, string, error) {
	if arg == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", "", fmt.Errorf("failed to resolve user home directory: %w", err)
		}
		arg = filepath.Join(home, ".ssh", "id_ed25519")
	}

	if strings.HasPrefix(arg, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", "", fmt.Errorf("failed to resolve user home directory: %w", err)
		}
		arg = filepath.Join(home, arg[2:])
	}

	var privPath, pubPath string
	if strings.HasSuffix(arg, ".pub") {
		pubPath = arg
		privPath = strings.TrimSuffix(arg, ".pub")
	} else {
		privPath = arg
		pubPath = arg + ".pub"
	}

	return privPath, pubPath, nil
}

// runSSHImport handles copying and validating an external SSH key into dev-vps storage.
//
// Input args:
//   - cmd: cobra command instance for output.
//   - args: optional arguments where args[0] specifies the source private key path.
//   - force: whether to overwrite existing dev-vps keys.
//
// Returns:
//   - error: non-nil if validation fails, destination exists without force, or copy fails.
//
// Example:
//
//	err := runSSHImport(cmd, []string{"~/.ssh/id_ed25519"}, false)
func runSSHImport(cmd *cobra.Command, args []string, force bool) error {
	arg := ""
	if len(args) > 0 {
		arg = args[0]
	}

	srcPriv, srcPub, err := resolveImportKeyPaths(arg)
	if err != nil {
		return err
	}

	if err := sshutil.ValidateKeyPair(srcPriv, srcPub); err != nil {
		return fmt.Errorf("failed to validate source SSH key pair: %w", err)
	}

	dstPriv := config.SSHPrivateKeyPath(customBaseDir)
	dstPub := config.SSHPublicKeyPath(customBaseDir)

	if !force {
		if _, err := os.Stat(dstPriv); err == nil {
			return fmt.Errorf("managed SSH key already exists at %s (use --force to overwrite)", dstPriv)
		}
		if _, err := os.Stat(dstPub); err == nil {
			return fmt.Errorf("managed SSH key already exists at %s (use --force to overwrite)", dstPub)
		}
	}

	if err := sshutil.CopyKeyPairFiles(srcPriv, srcPub, dstPriv, dstPub, force); err != nil {
		return fmt.Errorf("failed to import SSH key pair: %w", err)
	}

	cmd.Printf("Imported SSH key pair:\n  Private: %s\n  Public:  %s\n", dstPriv, dstPub)
	cmd.Println("Note: Run 'dev-vps ssh create' to synchronize your imported key with the cloud provider.")
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

	// Silence cobra usage output once arguments and credentials are confirmed valid,
	// ensuring exit statuses from ssh sessions do not trigger usage/help printing.
	cmd.SilenceUsage = true

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
