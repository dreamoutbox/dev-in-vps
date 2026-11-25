package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/dreamoutbox/dev-in-vps/pkg/config"
	"github.com/dreamoutbox/dev-in-vps/pkg/firewall"
	"github.com/dreamoutbox/dev-in-vps/pkg/provider"
	"github.com/dreamoutbox/dev-in-vps/pkg/types"
	"github.com/spf13/cobra"
)

// newFirewallCmd constructs the 'dev-vps firewall' command group.
//
// Returns:
//   - *cobra.Command: parent command grouping firewall subcommands.
//
// Example:
//
//	rootCmd.AddCommand(newFirewallCmd())
func newFirewallCmd() *cobra.Command {
	fwCmd := &cobra.Command{
		Use:   "firewall",
		Short: "Manage cloud firewall rules for dev VPS instances",
		Long:  `Inspect and update inbound cloud firewall rules attached to dev-vps droplets.`,
	}

	fwCmd.AddCommand(newFirewallListCmd())

	return fwCmd
}

// newFirewallListCmd constructs the 'dev-vps firewall list <droplet_name>' subcommand.
//
// Returns:
//   - *cobra.Command: command that prints a droplet's inbound firewall rules.
//
// Example:
//
//	fwCmd.AddCommand(newFirewallListCmd())
func newFirewallListCmd() *cobra.Command {
	var jsonOutput bool

	listCmd := &cobra.Command{
		Use:     "list <droplet_name>",
		Aliases: []string{"ls"},
		Short:   "List inbound firewall rules for a dev VPS instance",
		Long:    `Displays the inbound rules on a droplet's dev-vps managed cloud firewall as a table or JSON.`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFirewallList(cmd, args[0], jsonOutput)
		},
	}

	listCmd.Flags().BoolVar(&jsonOutput, "json", false, "output results in JSON format")

	return listCmd
}

// runFirewallList resolves the target droplet, fetches its managed firewall, and renders the rules.
func runFirewallList(cmd *cobra.Command, target string, jsonOutput bool) error {
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

	serverID, serverName, err := resolveServerID(ctx, prov, target)
	if err != nil {
		return err
	}

	fwInfo, err := prov.GetFirewall(ctx, serverID)
	if errors.Is(err, provider.ErrFirewallNotFound) {
		if jsonOutput {
			empty := provider.FirewallInfo{
				ServerID:     serverID,
				InboundRules: []firewall.Rule{},
			}
			return writeIndentedJSON(cmd.OutOrStdout(), empty)
		}
		cmd.Printf("No dev-vps firewall found for %s. Run 'dev-vps firewall allow %s <rule>' to create one.\n", serverName, serverName)
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to fetch firewall for %s: %w", serverName, err)
	}

	sortedRules := sortFirewallRules(fwInfo.InboundRules)
	if jsonOutput {
		out := provider.FirewallInfo{
			ID:           fwInfo.ID,
			Name:         fwInfo.Name,
			ServerID:     fwInfo.ServerID,
			InboundRules: sortedRules,
		}
		return writeIndentedJSON(cmd.OutOrStdout(), out)
	}

	return renderFirewallRulesTable(cmd.OutOrStdout(), sortedRules)
}

// resolveServerID resolves a droplet name or ID to its provider server ID and name.
// It checks local state first and falls back to querying the provider's ListServers API.
//
// Input args:
//   - ctx: execution context for fallback API lookup.
//   - prov: cloud provider client.
//   - nameOrID: droplet name or provider ID supplied by the user.
//
// Returns:
//   - string: resolved provider server ID.
//   - string: resolved droplet name.
//   - error: non-nil if the server cannot be found or the fallback API call fails.
//
// Example:
//
//	id, name, err := resolveServerID(ctx, prov, "my-droplet")
func resolveServerID(ctx context.Context, prov provider.Provider, nameOrID string) (string, string, error) {
	if st, err := config.LoadState(customBaseDir); err == nil {
		if rec, found := st.GetServer(nameOrID); found {
			return rec.ID, rec.Name, nil
		}
	}

	servers, err := prov.ListServers(ctx)
	if err != nil {
		return "", "", fmt.Errorf("failed to look up server %q: %w", nameOrID, err)
	}

	for _, s := range servers {
		if s.Name == nameOrID || s.ID == nameOrID {
			return s.ID, s.Name, nil
		}
	}

	return "", "", fmt.Errorf("server %q not found", nameOrID)
}

// renderFirewallRulesTable formats firewall rules into a sorted tabwriter table with
// columns RULE, PROTOCOL, PORTS, and SOURCES.
//
// Input args:
//   - w: output writer (e.g. cmd.OutOrStdout()).
//   - rules: inbound firewall rules to display (input slice is not mutated).
//
// Returns:
//   - error: non-nil if flushing the table fails.
//
// Example:
//
//	err := renderFirewallRulesTable(cmd.OutOrStdout(), fwInfo.InboundRules)
func renderFirewallRulesTable(w io.Writer, rules []firewall.Rule) error {
	sorted := sortFirewallRules(rules)

	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "RULE\tPROTOCOL\tPORTS\tSOURCES")

	for _, r := range sorted {
		ports := r.Ports.String()
		if r.Protocol == types.ProtocolICMP || ports == "" {
			ports = "-"
		}
		sources := strings.Join(r.Sources, ", ")
		if sources == "" {
			sources = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
			r.Spec(),
			r.Protocol.String(),
			ports,
			sources,
		)
	}

	return tw.Flush()
}

// sortFirewallRules returns a copy of rules sorted by protocol (TCP, UDP, ICMP) and
// then by ascending start port and end port.
func sortFirewallRules(rules []firewall.Rule) []firewall.Rule {
	sorted := make([]firewall.Rule, len(rules))
	copy(sorted, rules)

	sort.Slice(sorted, func(i, j int) bool {
		pi := protocolSortOrder(sorted[i].Protocol)
		pj := protocolSortOrder(sorted[j].Protocol)
		if pi != pj {
			return pi < pj
		}
		if sorted[i].Ports.From != sorted[j].Ports.From {
			return sorted[i].Ports.From < sorted[j].Ports.From
		}
		return sorted[i].Ports.To < sorted[j].Ports.To
	})

	return sorted
}

// protocolSortOrder assigns display sort priority: TCP (0), UDP (1), ICMP (2).
func protocolSortOrder(p types.NetworkProtocol) int {
	switch p {
	case types.ProtocolTCP:
		return 0
	case types.ProtocolUDP:
		return 1
	case types.ProtocolICMP:
		return 2
	default:
		return 3
	}
}

// writeIndentedJSON writes v as pretty-printed JSON to w.
func writeIndentedJSON(w io.Writer, v any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(v)
}
