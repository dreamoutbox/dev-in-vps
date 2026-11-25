package main

import (
	"fmt"

	"github.com/dreamoutbox/dev-in-vps/pkg/config"
	"github.com/dreamoutbox/dev-in-vps/pkg/firewall"
)

// resolveFirewallDefaultSources resolves and validates firewall.default_sources from cfg.
// A nil config, nil firewall block, or nil default_sources field falls back to the built-in
// defaults (0.0.0.0/0, ::/0). An explicit empty slice or invalid source returns an error
// naming firewall.default_sources.
//
// Input args:
//   - cfg: loaded configuration (may be nil).
//
// Returns:
//   - []string: normalized, deduplicated default CIDR sources.
//   - error: non-nil if configured sources are invalid or explicitly empty.
//
// Example:
//
//	sources, err := resolveFirewallDefaultSources(cfg)
func resolveFirewallDefaultSources(cfg *config.Config) ([]string, error) {
	rawSources := firewall.DefaultSources()
	if cfg != nil && cfg.Firewall != nil && cfg.Firewall.DefaultSources != nil {
		rawSources = cfg.Firewall.DefaultSources
	}

	sources, err := firewall.ParseSources(rawSources)
	if err != nil {
		return nil, fmt.Errorf("invalid firewall.default_sources in config: %w", err)
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("invalid firewall.default_sources in config: at least one source is required")
	}
	return sources, nil
}

// resolveFirewallDefaults resolves cfg into the initial firewall rule set and normalized
// default sources.
// A nil firewall block or nil field falls back to the built-in defaults; an explicit empty
// firewall.default_rules resolves to 22/tcp only.
//
// Input args:
//   - cfg: loaded configuration (may be nil).
//
// Returns:
//   - []firewall.Rule: initial firewall rules with 22/tcp guaranteed.
//   - []string: normalized default sources.
//   - error: non-nil if firewall.default_rules or firewall.default_sources is invalid.
//
// Example:
//
//	rules, sources, err := resolveFirewallDefaults(cfg)
func resolveFirewallDefaults(cfg *config.Config) ([]firewall.Rule, []string, error) {
	rawSpecs := firewall.DefaultRuleSpecs()
	if cfg != nil && cfg.Firewall != nil && cfg.Firewall.DefaultRules != nil {
		rawSpecs = cfg.Firewall.DefaultRules
	}

	if _, err := firewall.ParseRuleSpecs(rawSpecs); err != nil {
		return nil, nil, fmt.Errorf("invalid firewall.default_rules in config: %w", err)
	}

	sources, err := resolveFirewallDefaultSources(cfg)
	if err != nil {
		return nil, nil, err
	}

	rules, err := firewall.BuildDefaultRules(rawSpecs, sources)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid firewall config: %w", err)
	}
	return rules, sources, nil
}
