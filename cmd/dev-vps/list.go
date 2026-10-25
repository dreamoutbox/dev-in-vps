package main

import (
	"encoding/json"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/dreamoutbox/dev-in-vps/pkg/config"
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
	fmt.Fprintln(w, "NAME\tPROVIDER\tID\tREGION\tSIZE\tIP ADDRESS\tSTATUS\tCREATED")

	for _, s := range servers {
		createdStr := s.CreatedAt.Format(time.RFC3339)
		if !s.CreatedAt.IsZero() {
			createdStr = s.CreatedAt.Format("2006-01-02 15:04")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			s.Name,
			s.Provider,
			s.ID,
			s.Region,
			s.Size,
			s.IPAddress,
			s.Status,
			createdStr,
		)
	}

	return w.Flush()
}
