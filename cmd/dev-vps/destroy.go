package main

import (
	"context"
	"fmt"
	"time"

	"github.com/dreamoutbox/dev-in-vps/pkg/config"
	"github.com/dreamoutbox/dev-in-vps/pkg/ui"
	"github.com/spf13/cobra"
)

var (
	destroyForce bool
)

// newDestroyCmd constructs the 'dev-vps destroy' command.
func newDestroyCmd() *cobra.Command {
	destroyCmd := &cobra.Command{
		Use:     "destroy [name-or-id]",
		Aliases: []string{"rm", "delete"},
		Short:   "Terminate and delete a dev VPS server",
		Long: `Permanently deletes the specified cloud VPS instance using the provider API
and removes its record from local tracking in ~/.dev-vps/state.json.`,
		RunE: runDestroyServer,
	}

	destroyCmd.Flags().BoolVarP(&destroyForce, "force", "y", false, "skip interactive confirmation prompt")

	return destroyCmd
}

// runDestroyServer handles server resolution, confirmation, deletion, and state cleanup.
func runDestroyServer(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
	defer cancel()

	cfg, err := config.LoadConfig(customBaseDir)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	st, err := config.LoadState(customBaseDir)
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}

	var targetName string
	var targetID string

	if len(args) > 0 {
		targetInput := args[0]
		if rec, found := st.GetServer(targetInput); found {
			targetName = rec.Name
			targetID = rec.ID
		} else {
			targetName = targetInput
			targetID = targetInput
		}
	} else {
		servers := st.ListServers()
		if len(servers) == 0 {
			return fmt.Errorf("no active dev servers found to destroy")
		}
		if len(servers) == 1 {
			targetName = servers[0].Name
			targetID = servers[0].ID
		} else {
			chosenName, pickErr := ui.SelectServer(servers)
			if pickErr != nil {
				return pickErr
			}
			rec, _ := st.GetServer(chosenName)
			targetName = rec.Name
			targetID = rec.ID
		}
	}

	// Confirmation check
	if !destroyForce {
		if ui.IsInteractive() {
			confirmed, confirmErr := ui.PromptConfirm(fmt.Sprintf("Are you sure you want to permanently destroy server %s (ID: %s)?", targetName, targetID))
			if confirmErr != nil {
				return confirmErr
			}
			if !confirmed {
				cmd.Println("Server destruction cancelled.")
				return nil
			}
		} else {
			return fmt.Errorf("confirmation required to destroy %s; pass --force or -y in non-interactive environments", targetName)
		}
	}

	prov, err := providerFactory(cfg)
	if err != nil {
		return err
	}

	cmd.Printf("Destroying server %s (ID: %s) on %s...\n", targetName, targetID, prov.Type())

	if err := prov.DeleteServer(ctx, targetID); err != nil {
		return fmt.Errorf("failed to destroy server %s: %w", targetID, err)
	}

	// Clean up local state
	st.RemoveServer(targetName)
	st.RemoveServer(targetID)
	if err := config.SaveState(customBaseDir, st); err != nil {
		return fmt.Errorf("failed to update state after deletion: %w", err)
	}

	cmd.Printf("Server %s successfully destroyed and removed from state.\n", targetName)
	return nil
}
