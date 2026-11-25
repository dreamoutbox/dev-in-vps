package firewall

import (
	"errors"
	"fmt"
)

// DefaultRuleSpecs returns a fresh slice of the built-in default firewall rule specs.
//
// Returns:
//   - []string: default rule specs ("22", "80", "443", "8080", "8081", "3000", "8000").
//
// Example:
//
//	specs := firewall.DefaultRuleSpecs()
func DefaultRuleSpecs() []string {
	return []string{"22", "80", "443", "8080", "8081", "3000", "8000"}
}

// DefaultSources returns a fresh slice of the built-in default firewall sources.
//
// Returns:
//   - []string: default sources ("0.0.0.0/0", "::/0").
//
// Example:
//
//	sources := firewall.DefaultSources()
func DefaultSources() []string {
	return []string{AnyIPv4, AnyIPv6}
}

// BuildDefaultRules parses the given rule specs and sources into a complete initial rule set,
// guaranteeing that the exact SSH rule (22/tcp) is always present.
//
// Input args:
//   - specs: raw rule spec strings (may be empty, in which case only 22/tcp is returned).
//   - sources: raw source strings (must resolve to at least one valid source).
//
// Returns:
//   - []Rule: parsed rules with normalized sources attached and 22/tcp guaranteed.
//   - error: non-nil if any spec or source is invalid, or if sources is empty.
//
// Example:
//
//	rules, err := firewall.BuildDefaultRules(firewall.DefaultRuleSpecs(), firewall.DefaultSources())
func BuildDefaultRules(specs, sources []string) ([]Rule, error) {
	parsedRules, err := ParseRuleSpecs(specs)
	if err != nil {
		return nil, fmt.Errorf("invalid rule specs: %w", err)
	}

	parsedSources, err := ParseSources(sources)
	if err != nil {
		return nil, fmt.Errorf("invalid sources: %w", err)
	}
	if len(parsedSources) == 0 {
		return nil, errors.New("at least one firewall source is required")
	}

	hasSSH := false
	for _, r := range parsedRules {
		if r.IsSSH() {
			hasSSH = true
			break
		}
	}

	capacity := len(parsedRules)
	if !hasSSH {
		capacity++
	}

	result := make([]Rule, 0, capacity)
	if !hasSSH {
		result = append(result, SSHRule(parsedSources))
	}
	for _, r := range parsedRules {
		result = append(result, Rule{
			Protocol: r.Protocol,
			Ports:    r.Ports,
			Sources:  cloneStrings(parsedSources),
		})
	}
	return result, nil
}
