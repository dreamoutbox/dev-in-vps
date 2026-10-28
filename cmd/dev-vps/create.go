package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dreamoutbox/dev-in-vps/pkg/config"
	"github.com/dreamoutbox/dev-in-vps/pkg/provider"
	"github.com/dreamoutbox/dev-in-vps/pkg/sshutil"
	"github.com/dreamoutbox/dev-in-vps/pkg/types"
	"github.com/dreamoutbox/dev-in-vps/pkg/ui"
	"github.com/spf13/cobra"
)

var (
	createName       string
	createRegion     string
	createSize       string
	createInitScript string
)

// newCreateCmd constructs the 'dev-vps create' command.
func newCreateCmd() *cobra.Command {
	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Spin up a new dev VPS server",
		Long: `Provisions a cloud VPS instance with your chosen region and size specifications.
Prompts interactively for region and size if flags are omitted.
Automatically manages SSH keys and executes ~/.dev-vps/auto-setup/init.sh on initial boot.`,
		RunE: runCreateServer,
	}

	createCmd.Flags().StringVar(&createName, "name", "", "name for the dev server (prompts if omitted)")
	createCmd.Flags().StringVar(&createRegion, "region", "", "datacenter region slug (prompts if omitted)")
	createCmd.Flags().StringVar(&createSize, "size", "", "compute size slug (prompts if omitted)")
	createCmd.Flags().StringVar(&createInitScript, "init-script", "", "custom path to auto-setup bootstrap script")

	return createCmd
}

// runCreateServer handles the end-to-end creation, polling, and local state persistence.
func runCreateServer(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Minute)
	defer cancel()

	cfg, err := config.LoadConfig(customBaseDir)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	prov, err := providerFactory(cfg)
	if err != nil {
		return err
	}

	// 1. Ensure local SSH key and register with cloud provider
	_, _, pubContent, created, err := sshutil.EnsureLocalSSHKey(customBaseDir)
	if err != nil {
		return fmt.Errorf("failed to ensure local SSH key: %w", err)
	}
	if created {
		cmd.Printf("Auto-generated new SSH key pair at ~/.dev-vps/.ssh/\n")
	}

	keyID, err := prov.EnsureSSHKey(ctx, "dev-vps-key", pubContent)
	if err != nil {
		return fmt.Errorf("failed to register SSH key with cloud provider: %w", err)
	}

	// 2. Resolve Region
	selectedRegion := createRegion
	if selectedRegion == "" {
		regions, listErr := prov.ListRegions(ctx)
		if listErr != nil {
			return fmt.Errorf("failed to list regions: %w", listErr)
		}
		var pickErr error
		selectedRegion, pickErr = ui.SelectRegion(regions, cfg.DefaultRegion)
		if pickErr != nil {
			return pickErr
		}
	}

	// 3. Resolve Size
	selectedSize := createSize
	if selectedSize == "" {
		sizes, listErr := prov.ListSizes(ctx, selectedRegion)
		if listErr != nil {
			return fmt.Errorf("failed to list sizes for region %s: %w", selectedRegion, listErr)
		}
		var pickErr error
		selectedSize, pickErr = ui.SelectSize(sizes, cfg.DefaultSize)
		if pickErr != nil {
			return pickErr
		}
	}

	// 4. Resolve Server Name
	serverName := createName
	if serverName == "" {
		defaultName := fmt.Sprintf("dev-%d", time.Now().Unix())
		var promptErr error
		serverName, promptErr = ui.PromptText("Server name:", defaultName)
		if promptErr != nil {
			return promptErr
		}
	}

	// 5. Read init.sh bootstrap script
	initPath := createInitScript
	if initPath == "" {
		initPath = config.AutoSetupScriptPath(customBaseDir)
	}

	var userData string
	if scriptData, readErr := os.ReadFile(initPath); readErr == nil {
		userData = string(scriptData)
	}

	cmd.Printf("Creating %s instance (%s, %s) in %s...\n", serverName, prov.Type(), selectedSize, selectedRegion)

	req := provider.CreateServerRequest{
		Name:     serverName,
		Region:   selectedRegion,
		Size:     selectedSize,
		SSHKeyID: keyID,
		UserData: userData,
	}

	info, err := prov.CreateServer(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to provision server: %w", err)
	}

	cmd.Printf("Server provisioned (ID: %s). Waiting for public IP and active status...\n", info.ID)

	// 6. Poll until IP is assigned and status is active
	activeInfo, err := pollServerActive(ctx, prov, info.ID)
	if err != nil {
		return fmt.Errorf("polling server failed: %w", err)
	}

	// 7. Persist to local state
	st, err := config.LoadState(customBaseDir)
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}

	rec := config.ServerRecord{
		ID:               activeInfo.ID,
		Name:             activeInfo.Name,
		Provider:         activeInfo.Provider,
		Region:           activeInfo.Region,
		Size:             activeInfo.Size,
		IPAddress:        activeInfo.IPAddress,
		PrivateIPAddress: activeInfo.PrivateIPAddress,
		Status:           activeInfo.Status,
		CreatedAt:        activeInfo.CreatedAt,
	}

	st.AddServer(rec)
	if err := config.SaveState(customBaseDir, st); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	var reuseCmd strings.Builder
	reuseCmd.WriteString(fmt.Sprintf("dev-vps create --name %s --region %s --size %s", activeInfo.Name, activeInfo.Region, activeInfo.Size))
	if createInitScript != "" {
		reuseCmd.WriteString(fmt.Sprintf(" --init-script %s", createInitScript))
	}
	if customBaseDir != "" {
		reuseCmd.WriteString(fmt.Sprintf(" --home-dir %s", customBaseDir))
	}

	cmd.Printf("\nDev server created successfully!\n")
	cmd.Printf("  Name:        %s\n", activeInfo.Name)
	cmd.Printf("  Provider:    %s\n", activeInfo.Provider)
	cmd.Printf("  Region:      %s\n", activeInfo.Region)
	cmd.Printf("  Size:        %s\n", activeInfo.Size)
	cmd.Printf("  IP Address:  %s\n", activeInfo.IPAddress)
	if activeInfo.PrivateIPAddress != "" {
		cmd.Printf("  Internal IP: %s\n", activeInfo.PrivateIPAddress)
	}
	cmd.Printf("  Status:      %s\n\n", activeInfo.Status)
	cmd.Printf("Create command for reuse:\n  %s\n\n", reuseCmd.String())
	cmd.Printf("Connect to server:\n  dev-vps ssh %s\n", activeInfo.Name)

	return nil
}

// pollServerActive polls the provider until the instance reaches StatusActive with an IPv4 address.
func pollServerActive(ctx context.Context, prov provider.Provider, serverID string) (*provider.ServerInfo, error) {
	// Check immediately before waiting on ticker
	if info, err := prov.GetServer(ctx, serverID); err == nil && info != nil {
		if info.Status == types.StatusActive && info.IPAddress != "" {
			return info, nil
		}
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			info, err := prov.GetServer(ctx, serverID)
			if err != nil {
				continue
			}
			if info.Status == types.StatusActive && info.IPAddress != "" {
				return info, nil
			}
		}
	}
}
