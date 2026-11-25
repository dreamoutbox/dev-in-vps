package digitalocean

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/digitalocean/godo"
	"github.com/dreamoutbox/dev-in-vps/pkg/firewall"
	"github.com/dreamoutbox/dev-in-vps/pkg/provider"
	"github.com/dreamoutbox/dev-in-vps/pkg/types"
)

const (
	// doAllPorts is the DigitalOcean API value denoting all TCP or UDP ports (1-65535).
	doAllPorts = "0"
	// doAllPortsAlias is the alternate DigitalOcean API representation for all ports.
	doAllPortsAlias = "all"
)

// CreateFirewall creates a DigitalOcean Cloud Firewall attached to the specified droplet
// with the requested inbound rules and allow-all outbound rules for TCP, UDP, and ICMP.
//
// Input args:
//   - ctx: execution context.
//   - serverID: numeric DigitalOcean droplet ID string.
//   - name: firewall name (typically dev-vps-<droplet_name>).
//   - rules: inbound firewall rules to apply.
//
// Returns:
//   - *provider.FirewallInfo: created firewall metadata and inbound rules.
//   - error: non-nil if serverID is invalid or the API call fails.
//
// Example:
//
//	fw, err := client.CreateFirewall(ctx, "1001", "dev-vps-alpha", rules)
func (c *Client) CreateFirewall(ctx context.Context, serverID string, name string, rules []firewall.Rule) (*provider.FirewallInfo, error) {
	dropletID, err := parseDropletID(serverID)
	if err != nil {
		return nil, err
	}

	req := &godo.FirewallRequest{
		Name:          name,
		InboundRules:  rulesToGodoInbound(rules, nil),
		OutboundRules: defaultOutboundRules(),
		DropletIDs:    []int{dropletID},
	}

	fw, _, err := c.client.Firewalls.Create(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create DigitalOcean firewall %q: %w", name, err)
	}
	return godoFirewallToInfo(fw, serverID), nil
}

// GetFirewall fetches the dev-vps managed firewall attached to the specified droplet.
// Firewalls whose names do not start with provider.FirewallNamePrefix are ignored.
//
// Input args:
//   - ctx: execution context.
//   - serverID: numeric DigitalOcean droplet ID string.
//
// Returns:
//   - *provider.FirewallInfo: matched managed firewall metadata and inbound rules.
//   - error: provider.ErrFirewallNotFound if none exists, or an API/validation error.
//
// Example:
//
//	fw, err := client.GetFirewall(ctx, "1001")
func (c *Client) GetFirewall(ctx context.Context, serverID string) (*provider.FirewallInfo, error) {
	dropletID, err := parseDropletID(serverID)
	if err != nil {
		return nil, err
	}

	fw, err := c.findManagedFirewall(ctx, dropletID)
	if err != nil {
		return nil, err
	}
	return godoFirewallToInfo(fw, serverID), nil
}

// UpdateFirewallRules replaces the inbound rules of the droplet's dev-vps managed firewall
// while preserving its name, attached droplet IDs, tags, outbound rules, and any console-made
// non-address sources (tags, droplet IDs, load balancers, Kubernetes clusters).
//
// Input args:
//   - ctx: execution context.
//   - serverID: numeric DigitalOcean droplet ID string.
//   - rules: complete replacement set of address-based inbound rules.
//
// Returns:
//   - *provider.FirewallInfo: updated firewall metadata and inbound rules.
//   - error: provider.ErrFirewallNotFound if no managed firewall exists, or an API error.
//
// Example:
//
//	fw, err := client.UpdateFirewallRules(ctx, "1001", updatedRules)
func (c *Client) UpdateFirewallRules(ctx context.Context, serverID string, rules []firewall.Rule) (*provider.FirewallInfo, error) {
	dropletID, err := parseDropletID(serverID)
	if err != nil {
		return nil, err
	}

	existing, err := c.findManagedFirewall(ctx, dropletID)
	if err != nil {
		return nil, err
	}

	req := &godo.FirewallRequest{
		Name:          existing.Name,
		InboundRules:  rulesToGodoInbound(rules, existing.InboundRules),
		OutboundRules: existing.OutboundRules,
		DropletIDs:    existing.DropletIDs,
		Tags:          existing.Tags,
	}

	updated, _, err := c.client.Firewalls.Update(ctx, existing.ID, req)
	if err != nil {
		return nil, fmt.Errorf("failed to update DigitalOcean firewall %s: %w", existing.ID, err)
	}
	return godoFirewallToInfo(updated, serverID), nil
}

// DeleteFirewall deletes the dev-vps managed firewall attached to the specified droplet.
// If no managed firewall exists for the droplet, DeleteFirewall is a no-op and returns nil.
//
// Input args:
//   - ctx: execution context.
//   - serverID: numeric DigitalOcean droplet ID string.
//
// Returns:
//   - error: non-nil only if serverID is invalid or an unexpected API error occurs.
//
// Example:
//
//	err := client.DeleteFirewall(ctx, "1001")
func (c *Client) DeleteFirewall(ctx context.Context, serverID string) error {
	dropletID, err := parseDropletID(serverID)
	if err != nil {
		return err
	}

	existing, err := c.findManagedFirewall(ctx, dropletID)
	if errors.Is(err, provider.ErrFirewallNotFound) {
		return nil
	}
	if err != nil {
		return err
	}

	resp, err := c.client.Firewalls.Delete(ctx, existing.ID)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil
		}
		return fmt.Errorf("failed to delete DigitalOcean firewall %s: %w", existing.ID, err)
	}
	return nil
}

// parseDropletID converts a string server ID into a DigitalOcean integer droplet ID.
func parseDropletID(serverID string) (int, error) {
	dropletID, err := strconv.Atoi(serverID)
	if err != nil {
		return 0, fmt.Errorf("invalid droplet id %s: %w", serverID, err)
	}
	return dropletID, nil
}

// findManagedFirewall returns the first firewall attached to dropletID whose name starts
// with provider.FirewallNamePrefix, ignoring user-created firewalls.
func (c *Client) findManagedFirewall(ctx context.Context, dropletID int) (*godo.Firewall, error) {
	opts := &godo.ListOptions{PerPage: 200}
	firewalls, resp, err := c.client.Firewalls.ListByDroplet(ctx, dropletID, opts)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, provider.ErrFirewallNotFound
		}
		return nil, fmt.Errorf("failed to list firewalls for droplet %d: %w", dropletID, err)
	}

	for i := range firewalls {
		if strings.HasPrefix(firewalls[i].Name, provider.FirewallNamePrefix) {
			return &firewalls[i], nil
		}
	}
	return nil, provider.ErrFirewallNotFound
}

// defaultOutboundRules builds allow-all egress rules for TCP, UDP, and ICMP so droplets
// can reach package repositories, git remotes, and external services during bootstrap.
func defaultOutboundRules() []godo.OutboundRule {
	allDestinations := func() *godo.Destinations {
		return &godo.Destinations{
			Addresses: []string{firewall.AnyIPv4, firewall.AnyIPv6},
		}
	}
	return []godo.OutboundRule{
		{
			Protocol:     types.ProtocolTCP.String(),
			PortRange:    doAllPorts,
			Destinations: allDestinations(),
		},
		{
			Protocol:     types.ProtocolUDP.String(),
			PortRange:    doAllPorts,
			Destinations: allDestinations(),
		},
		{
			Protocol:     types.ProtocolICMP.String(),
			Destinations: allDestinations(),
		},
	}
}

// rulesToGodoInbound converts domain firewall rules to godo inbound rules while preserving
// any non-address sources (tags, droplet IDs, load balancers, Kubernetes IDs) from existing.
func rulesToGodoInbound(rules []firewall.Rule, existing []godo.InboundRule) []godo.InboundRule {
	preservedByKey, preservedOrder := extractNonAddressSources(existing)
	matchedKeys := make(map[firewall.RuleKey]struct{}, len(rules))

	out := make([]godo.InboundRule, 0, len(rules))
	for _, r := range rules {
		key := r.Key()
		matchedKeys[key] = struct{}{}

		sources := &godo.Sources{
			Addresses: append([]string(nil), r.Sources...),
		}
		if extra, ok := preservedByKey[key]; ok {
			mergeNonAddressSources(sources, extra)
		}

		out = append(out, godo.InboundRule{
			Protocol:  r.Protocol.String(),
			PortRange: formatGodoPortRange(r),
			Sources:   sources,
		})
	}

	// Keep console-made rules that carry non-address sources even if they had no
	// address sources or their address sources were removed.
	for _, key := range preservedOrder {
		if _, matched := matchedKeys[key]; matched {
			continue
		}
		extra := preservedByKey[key]
		rule := firewall.Rule{Protocol: key.Protocol, Ports: key.Ports}
		sources := &godo.Sources{}
		mergeNonAddressSources(sources, extra)
		out = append(out, godo.InboundRule{
			Protocol:  rule.Protocol.String(),
			PortRange: formatGodoPortRange(rule),
			Sources:   sources,
		})
	}

	return out
}

// formatGodoPortRange formats a rule's port range for the DigitalOcean API.
// ICMP rules return "" so godo omits the "ports" field.
func formatGodoPortRange(r firewall.Rule) string {
	if r.Protocol == types.ProtocolICMP {
		return ""
	}
	return r.Ports.String()
}

// godoFirewallToInfo converts a godo.Firewall into provider.FirewallInfo.
func godoFirewallToInfo(fw *godo.Firewall, serverID string) *provider.FirewallInfo {
	if fw == nil {
		return nil
	}
	return &provider.FirewallInfo{
		ID:           fw.ID,
		Name:         fw.Name,
		ServerID:     serverID,
		InboundRules: godoInboundToRules(fw.InboundRules),
	}
}

// godoInboundToRules converts DigitalOcean inbound rules into domain firewall rules.
// Rules with the same (protocol, port range) identity have their addresses merged, and
// rules that contain only non-address sources (e.g. tags) are omitted from address rules.
func godoInboundToRules(inbound []godo.InboundRule) []firewall.Rule {
	rules := make([]firewall.Rule, 0, len(inbound))
	indexByKey := make(map[firewall.RuleKey]int, len(inbound))

	for _, in := range inbound {
		rule, ok := godoInboundToRule(in)
		if !ok {
			continue
		}
		if len(rule.Sources) == 0 && hasNonAddressSources(in.Sources) {
			continue
		}

		key := rule.Key()
		if idx, exists := indexByKey[key]; exists {
			rules[idx].Sources = appendUniqueStrings(rules[idx].Sources, rule.Sources)
			continue
		}
		indexByKey[key] = len(rules)
		rules = append(rules, rule)
	}
	return rules
}

// godoInboundToRule maps a single godo.InboundRule to a firewall.Rule.
// DigitalOcean's "all" or "0" port values become 1-65535.
func godoInboundToRule(in godo.InboundRule) (firewall.Rule, bool) {
	proto, err := types.ParseNetworkProtocol(in.Protocol)
	if err != nil {
		return firewall.Rule{}, false
	}

	var ports firewall.PortRange
	if proto != types.ProtocolICMP {
		parsedPorts, ok := parseGodoPortRange(in.PortRange, proto)
		if !ok {
			return firewall.Rule{}, false
		}
		ports = parsedPorts
	}

	var addresses []string
	if in.Sources != nil && len(in.Sources.Addresses) > 0 {
		addresses = normalizeGodoAddresses(in.Sources.Addresses)
	}

	return firewall.Rule{
		Protocol: proto,
		Ports:    ports,
		Sources:  addresses,
	}, true
}

// parseGodoPortRange parses DigitalOcean's port range string ("0", "all", "9000", "9000-9010").
func parseGodoPortRange(raw string, proto types.NetworkProtocol) (firewall.PortRange, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == doAllPorts || strings.EqualFold(trimmed, doAllPortsAlias) {
		return firewall.PortRange{From: firewall.MinPort, To: firewall.MaxPort}, true
	}

	spec := fmt.Sprintf("%s/%s", trimmed, proto.String())
	rule, err := firewall.ParseRuleSpec(spec)
	if err != nil {
		return firewall.PortRange{}, false
	}
	return rule.Ports, true
}

// normalizeGodoAddresses normalizes valid CIDR/IP addresses while preserving any
// unrecognized raw entries so unexpected API responses never fail conversion.
func normalizeGodoAddresses(raw []string) []string {
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, addr := range raw {
		parsed, err := firewall.ParseSources([]string{addr})
		if err != nil || len(parsed) == 0 {
			out = appendUniqueStrings(out, []string{addr})
			continue
		}
		for _, norm := range parsed {
			if _, exists := seen[norm]; exists {
				continue
			}
			seen[norm] = struct{}{}
			out = append(out, norm)
		}
	}
	return out
}

// extractNonAddressSources collects non-address sources from existing godo inbound rules,
// grouped by RuleKey in first-seen order so UpdateFirewallRules never erases console sources.
func extractNonAddressSources(existing []godo.InboundRule) (map[firewall.RuleKey]*godo.Sources, []firewall.RuleKey) {
	byKey := make(map[firewall.RuleKey]*godo.Sources)
	var order []firewall.RuleKey

	for _, in := range existing {
		if !hasNonAddressSources(in.Sources) {
			continue
		}
		rule, ok := godoInboundToRule(in)
		if !ok {
			continue
		}
		key := rule.Key()
		dst, exists := byKey[key]
		if !exists {
			dst = &godo.Sources{}
			byKey[key] = dst
			order = append(order, key)
		}
		mergeNonAddressSources(dst, in.Sources)
	}
	return byKey, order
}

// hasNonAddressSources reports whether s contains any tags, droplet IDs, load balancer UIDs,
// or Kubernetes cluster IDs.
func hasNonAddressSources(s *godo.Sources) bool {
	if s == nil {
		return false
	}
	return len(s.Tags) > 0 ||
		len(s.DropletIDs) > 0 ||
		len(s.LoadBalancerUIDs) > 0 ||
		len(s.KubernetesIDs) > 0
}

// mergeNonAddressSources copies non-address source slices from src into dst without duplicates.
func mergeNonAddressSources(dst, src *godo.Sources) {
	if dst == nil || src == nil {
		return
	}
	dst.Tags = appendUniqueStrings(dst.Tags, src.Tags)
	dst.DropletIDs = appendUniqueInts(dst.DropletIDs, src.DropletIDs)
	dst.LoadBalancerUIDs = appendUniqueStrings(dst.LoadBalancerUIDs, src.LoadBalancerUIDs)
	dst.KubernetesIDs = appendUniqueStrings(dst.KubernetesIDs, src.KubernetesIDs)
}

// appendUniqueStrings appends values from add into base while avoiding duplicates.
func appendUniqueStrings(base, add []string) []string {
	seen := make(map[string]struct{}, len(base))
	for _, v := range base {
		seen[v] = struct{}{}
	}
	for _, v := range add {
		if _, exists := seen[v]; exists {
			continue
		}
		seen[v] = struct{}{}
		base = append(base, v)
	}
	return base
}

// appendUniqueInts appends integers from add into base while avoiding duplicates.
func appendUniqueInts(base, add []int) []int {
	seen := make(map[int]struct{}, len(base))
	for _, v := range base {
		seen[v] = struct{}{}
	}
	for _, v := range add {
		if _, exists := seen[v]; exists {
			continue
		}
		seen[v] = struct{}{}
		base = append(base, v)
	}
	return base
}
