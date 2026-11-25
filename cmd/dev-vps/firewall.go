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

const firewallSyntaxHelp = `Rule spec syntax (case-insensitive):
  9000                   TCP port 9000 (bare port or range defaults to TCP)
  9000/tcp, 9001/udp     single port with explicit protocol
  9000-9010              inclusive TCP port range
  9000-9010/udp          inclusive UDP port range
  icmp                   ICMP (ping)

Accepted --source (-s) values (repeatable or comma-separated):
  203.0.113.7            bare IPv4 or IPv6 address (normalized to /32 or /128)
  10.0.0.0/8             IPv4 or IPv6 CIDR (must not have host bits set)
  any                    expands to 0.0.0.0/0 and ::/0`

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
	fwCmd.AddCommand(newFirewallAllowCmd())
	fwCmd.AddCommand(newFirewallDenyCmd())

	return fwCmd
}

// newFirewallAllowCmd constructs the 'dev-vps firewall allow <droplet_name> <rule...>' command.
//
// Returns:
//   - *cobra.Command: command that opens or adds sources to inbound firewall rules.
//
// Example:
//
//	fwCmd.AddCommand(newFirewallAllowCmd())
func newFirewallAllowCmd() *cobra.Command {
	var rawSources []string

	allowCmd := &cobra.Command{
		Use:   "allow <droplet_name> <rule...>",
		Short: "Allow inbound firewall rules on a dev VPS instance",
		Long: `Opens one or more inbound firewall rules on a droplet's dev-vps firewall.
If a rule with the same protocol and port range already exists, the sources are merged into it.
If --source is omitted, firewall.default_sources from config (or 0.0.0.0/0, ::/0) is used.
If the droplet has no dev-vps firewall yet, one is created with 22/tcp plus the requested rules.

` + firewallSyntaxHelp + `

Examples:
  dev-vps firewall allow my-droplet 9000 icmp 9001/udp 9100-9110
  dev-vps firewall allow my-droplet 5432 --source 203.0.113.7
  dev-vps firewall allow my-droplet 9000-9010/udp icmp -s 10.0.0.0/8,2001:db8::/32`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFirewallAllow(cmd, args[0], args[1:], rawSources, cmd.Flags().Changed("source"))
		},
	}

	allowCmd.Flags().StringSliceVarP(&rawSources, "source", "s", nil, "source IP, CIDR, or 'any' (repeatable or comma-separated)")

	return allowCmd
}

// newFirewallDenyCmd constructs the 'dev-vps firewall deny <droplet_name> <rule...>' command.
//
// Returns:
//   - *cobra.Command: command that removes inbound firewall rules or specific sources.
//
// Example:
//
//	fwCmd.AddCommand(newFirewallDenyCmd())
func newFirewallDenyCmd() *cobra.Command {
	var rawSources []string

	denyCmd := &cobra.Command{
		Use:   "deny <droplet_name> <rule...>",
		Short: "Deny inbound firewall rules or sources on a dev VPS instance",
		Long: `Removes inbound firewall rules or specific sources from a droplet's dev-vps firewall.
Without --source, the entire matching rule is removed.
With --source, only those sources are removed (and the rule is removed if no sources remain).
Ranges match exactly; overlapping ranges are never split.

SSH protection (22/tcp):
  - 'deny <droplet> 22' without --source is refused.
  - 'deny <droplet> 22 -s <sources>' is allowed only if at least one source remains.
  - To restrict SSH to your IP:
      dev-vps firewall allow my-droplet 22 -s <your-ip>
      dev-vps firewall deny my-droplet 22 -s any
  - Warning: verify <your-ip> matches your actual public IP before removing broad sources,
    or you can lock yourself out of SSH access.

` + firewallSyntaxHelp + `

Examples:
  dev-vps firewall deny my-droplet 9000 icmp
  dev-vps firewall deny my-droplet 5432 --source 203.0.113.7
  dev-vps firewall deny my-droplet 22 -s any`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFirewallDeny(cmd, args[0], args[1:], rawSources, cmd.Flags().Changed("source"))
		},
	}

	denyCmd.Flags().StringSliceVarP(&rawSources, "source", "s", nil, "source IP, CIDR, or 'any' to remove (repeatable or comma-separated)")

	return denyCmd
}

// runFirewallAllow validates inputs, merges requested rules/sources, and persists changes.
func runFirewallAllow(cmd *cobra.Command, target string, rawSpecs []string, rawSources []string, sourceFlagSet bool) error {
	specs, err := firewall.ParseRuleSpecs(rawSpecs)
	if err != nil {
		return err
	}

	var sources []string
	if sourceFlagSet {
		sources, err = parseExplicitSourceFlag(rawSources)
		if err != nil {
			return err
		}
	}

	cfg, err := config.LoadConfig(customBaseDir)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	if !sourceFlagSet {
		sources, err = resolveFirewallDefaultSources(cfg)
		if err != nil {
			return err
		}
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

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
		return createMissingFirewallForAllow(ctx, cmd, prov, cfg, serverID, serverName, specs, sources)
	}
	if err != nil {
		return fmt.Errorf("failed to fetch firewall for %s: %w", serverName, err)
	}

	nextRules, report := firewall.Allow(fwInfo.InboundRules, specs, sources)
	finalRules := fwInfo.InboundRules
	if report.HasChanges() {
		updated, updateErr := prov.UpdateFirewallRules(ctx, serverID, nextRules)
		if updateErr != nil {
			return fmt.Errorf("failed to update firewall for %s: %w", serverName, updateErr)
		}
		finalRules = updated.InboundRules
	}

	return renderFirewallMutationOutput(cmd.OutOrStdout(), report, finalRules)
}

// createMissingFirewallForAllow initializes a new firewall with 22/tcp (default sources)
// merged with the requested rules when a droplet does not yet have a dev-vps firewall.
func createMissingFirewallForAllow(
	ctx context.Context,
	cmd *cobra.Command,
	prov provider.Provider,
	cfg *config.Config,
	serverID string,
	serverName string,
	specs []firewall.Rule,
	sources []string,
) error {
	defaultSources, err := resolveFirewallDefaultSources(cfg)
	if err != nil {
		return err
	}

	baseRules := []firewall.Rule{firewall.SSHRule(defaultSources)}
	initialRules, _ := firewall.Allow(baseRules, specs, sources)

	fwName := provider.FirewallNamePrefix + serverName
	created, err := prov.CreateFirewall(ctx, serverID, fwName, initialRules)
	if err != nil {
		return fmt.Errorf("failed to create firewall %s: %w", fwName, err)
	}

	// Every rule on a brand-new firewall is newly added, including the required 22/tcp rule.
	var report firewall.ChangeReport
	for _, r := range initialRules {
		report.Added = append(report.Added, firewall.RuleChange{
			Rule:    r,
			Sources: r.Sources,
		})
	}

	cmd.Printf("Created firewall %s.\n", fwName)
	return renderFirewallMutationOutput(cmd.OutOrStdout(), report, created.InboundRules)
}

// runFirewallDeny validates inputs, removes matching rules/sources, and persists changes.
func runFirewallDeny(cmd *cobra.Command, target string, rawSpecs []string, rawSources []string, sourceFlagSet bool) error {
	specs, err := firewall.ParseRuleSpecs(rawSpecs)
	if err != nil {
		return err
	}

	var sources []string
	if sourceFlagSet {
		sources, err = parseExplicitSourceFlag(rawSources)
		if err != nil {
			return err
		}
	}

	cfg, err := config.LoadConfig(customBaseDir)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()

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
		return fmt.Errorf("no dev-vps firewall found for %s", serverName)
	}
	if err != nil {
		return fmt.Errorf("failed to fetch firewall for %s: %w", serverName, err)
	}

	nextRules, report, err := firewall.Deny(fwInfo.InboundRules, specs, sources)
	if errors.Is(err, firewall.ErrSSHRuleProtected) {
		return fmt.Errorf(
			"%w\nTo restrict SSH to your IP instead:\n  dev-vps firewall allow %s 22 -s <your-ip>\n  dev-vps firewall deny %s 22 -s any\nWarning: verify <your-ip> is your current public IP before removing broad sources, or you may lock yourself out.",
			err, serverName, serverName,
		)
	}
	if err != nil {
		return err
	}

	finalRules := fwInfo.InboundRules
	if report.HasChanges() {
		updated, updateErr := prov.UpdateFirewallRules(ctx, serverID, nextRules)
		if updateErr != nil {
			return fmt.Errorf("failed to update firewall for %s: %w", serverName, updateErr)
		}
		finalRules = updated.InboundRules
	}

	return renderFirewallMutationOutput(cmd.OutOrStdout(), report, finalRules)
}

// parseExplicitSourceFlag validates sources supplied via --source / -s before any API call.
func parseExplicitSourceFlag(rawSources []string) ([]string, error) {
	if len(rawSources) == 0 {
		return nil, fmt.Errorf("--source requires at least one IP address, CIDR, or %q", firewall.SourceKeywordAny)
	}
	return firewall.ParseSources(rawSources)
}

// renderFirewallMutationOutput prints the change report followed by the resulting rule table.
func renderFirewallMutationOutput(w io.Writer, report firewall.ChangeReport, rules []firewall.Rule) error {
	renderChangeReport(w, report)
	fmt.Fprintln(w)
	return renderFirewallRulesTable(w, rules)
}

// renderChangeReport prints added, removed, skipped, and covered-by lines from a ChangeReport.
func renderChangeReport(w io.Writer, report firewall.ChangeReport) {
	for _, ch := range report.Added {
		fmt.Fprintf(w, "Added:   %s (%s)\n", ch.Rule.Spec(), strings.Join(ch.Sources, ", "))
	}
	for _, ch := range report.Removed {
		fmt.Fprintf(w, "Removed: %s (%s)\n", ch.Rule.Spec(), strings.Join(ch.Sources, ", "))
	}
	for _, ch := range report.Skipped {
		if len(ch.Sources) > 0 {
			fmt.Fprintf(w, "Skipped: %s (%s)\n", ch.Rule.Spec(), strings.Join(ch.Sources, ", "))
			continue
		}
		fmt.Fprintf(w, "Skipped: %s (not open)\n", ch.Rule.Spec())
	}
	for _, cov := range report.CoveredBy {
		covSpecs := make([]string, len(cov.CoveredBy))
		for i, r := range cov.CoveredBy {
			covSpecs[i] = r.Spec()
		}
		fmt.Fprintf(w, "Skipped: %s not open (covered by %s)\n", cov.Target.Spec(), strings.Join(covSpecs, ", "))
	}
	if !report.HasChanges() {
		fmt.Fprintln(w, "No firewall changes applied.")
	}
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
