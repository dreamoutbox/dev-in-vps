package main

import (
	"context"
	"encoding/json"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/dreamoutbox/dev-in-vps/pkg/config"
	"github.com/dreamoutbox/dev-in-vps/pkg/provider"
	"github.com/spf13/cobra"
)

var (
	listJSON bool
)

// newListCmd constructs the 'dev-vps list' command.
func newListCmd() *cobra.Command {
	listCmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List active dev VPS instances",
		Long:    `Displays a tabular or JSON overview of all tracked dev servers.`,
		RunE:    runListServers,
	}

	listCmd.Flags().BoolVar(&listJSON, "json", false, "output results in JSON format")

	return listCmd
}

// runListServers formats and prints tracked servers to standard output.
func runListServers(cmd *cobra.Command, args []string) error {
	st, err := config.LoadState(customBaseDir)
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
	defer cancel()

	remoteServers, fetchErr := fetchRemoteServers(ctx, customBaseDir)
	if fetchErr != nil {
		cmd.PrintErrf("Warning: failed to fetch live servers from provider (%v); displaying cached state\n", fetchErr)
	} else if reconcileState(st, remoteServers) {
		_ = config.SaveState(customBaseDir, st)
	}

	servers := st.ListServers()

	if listJSON {
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetIndent("", "  ")
		return encoder.Encode(servers)
	}

	if len(servers) == 0 {
		cmd.Println("No active dev servers found. Run 'dev-vps create' to spin one up.")
		return nil
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 8, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tPROVIDER\tID\tREGION\tSIZE\tIP ADDRESS\tINTERNAL IP\tSTATUS\tCREATED")

	for _, s := range servers {
		createdStr := s.CreatedAt.Format(time.RFC3339)
		if !s.CreatedAt.IsZero() {
			createdStr = s.CreatedAt.Format("2006-01-02 15:04")
		}
		internalIP := s.PrivateIPAddress
		if internalIP == "" {
			internalIP = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			s.Name,
			s.Provider,
			s.ID,
			s.Region,
			s.Size,
			s.IPAddress,
			internalIP,
			s.Status,
			createdStr,
		)
	}

	return w.Flush()
}

// reconcileState synchronizes local state records with the remote provider's active server list.
// It purges local entries that no longer exist remotely and updates or adds active remote instances.
//
// Input args:
//   - st: local state instance to reconcile.
//   - remoteServers: slice of active servers reported by the provider.
//
// Returns:
//   - bool: true if state was modified and requires saving.
//
// Example:
//
//	changed := reconcileState(st, remoteServers)
func reconcileState(st *config.State, remoteServers []provider.ServerInfo) bool {
	remoteMap := make(map[string]provider.ServerInfo, len(remoteServers))
	for _, r := range remoteServers {
		remoteMap[r.ID] = r
	}

	changed := false

	// Purge local records not present in the remote provider
	for _, local := range st.ListServers() {
		if _, exists := remoteMap[local.ID]; !exists {
			st.RemoveServer(local.Name)
			changed = true
		}
	}

	// Add or update records from provider
	for _, rem := range remoteServers {
		rec := ServerInfoToRecord(rem)
		localRec, exists := st.GetServer(rem.ID)
		if !exists || localRec != rec {
			if exists && localRec.Name != rec.Name {
				st.RemoveServer(localRec.Name)
			}
			st.AddServer(rec)
			changed = true
		}
	}

	return changed
}
