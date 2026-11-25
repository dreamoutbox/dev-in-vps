package firewall

import (
	"errors"
	"fmt"

	"github.com/dreamoutbox/dev-in-vps/pkg/types"
)

// ErrSSHRuleProtected is returned when a Deny operation would remove the 22/tcp SSH
// rule or leave it with no remaining sources.
var ErrSSHRuleProtected = errors.New("SSH rule 22/tcp is protected and must keep at least one allowed source")

// RuleChange records sources added, removed, or skipped for a single rule.
type RuleChange struct {
	Rule    Rule
	Sources []string
}

// CoveredRule records a deny target that had no exact match but is covered by
// one or more wider open rules of the same protocol.
type CoveredRule struct {
	Target    Rule
	CoveredBy []Rule
}

// ChangeReport summarizes the effects of Allow or Deny.
type ChangeReport struct {
	Added     []RuleChange
	Removed   []RuleChange
	Skipped   []RuleChange
	CoveredBy []CoveredRule
}

// HasChanges reports whether any rule or source was added or removed.
//
// Returns:
//   - bool: true if Added or Removed is non-empty.
//
// Example:
//
//	if !report.HasChanges() {
//	    return nil // skip API write
//	}
func (r ChangeReport) HasChanges() bool {
	return len(r.Added) > 0 || len(r.Removed) > 0
}

// Allow merges specs with the given sources into current and returns the updated rule set
// along with a ChangeReport of added and skipped sources.
// Existing rules keep all their existing sources (preserving SSH access on 22/tcp);
// overlapping port ranges are treated as distinct rules and are never merged.
//
// Input args:
//   - current: existing firewall rules (not mutated).
//   - specs: target rules identifying (protocol, port range) pairs to allow.
//   - sources: normalized CIDR sources (from ParseSources) to add to each target rule.
//
// Returns:
//   - []Rule: new rule set with requested rules and sources merged in.
//   - ChangeReport: summary of added and skipped sources.
//
// Example:
//
//	next, report := firewall.Allow(current, specs, sources)
func Allow(current []Rule, specs []Rule, sources []string) ([]Rule, ChangeReport) {
	result := cloneRules(current)
	var report ChangeReport

	normSources := dedupeCanonicalSources(sources)
	if len(normSources) == 0 {
		return result, report
	}

	indexByKey := indexRules(result)
	uniqueSpecs := dedupeSpecs(specs)

	for _, spec := range uniqueSpecs {
		key := spec.Key()
		idx, exists := indexByKey[key]
		if !exists {
			newRule := Rule{
				Protocol: key.Protocol,
				Ports:    key.Ports,
				Sources:  cloneStrings(normSources),
			}
			indexByKey[key] = len(result)
			result = append(result, newRule)
			report.Added = append(report.Added, RuleChange{
				Rule:    spec.withoutSources(),
				Sources: cloneStrings(normSources),
			})
			continue
		}

		toAdd, skipped := partitionNewSources(result[idx].Sources, normSources)
		if len(toAdd) > 0 {
			result[idx].Sources = append(result[idx].Sources, toAdd...)
			report.Added = append(report.Added, RuleChange{
				Rule:    spec.withoutSources(),
				Sources: toAdd,
			})
		}
		if len(skipped) > 0 {
			report.Skipped = append(report.Skipped, RuleChange{
				Rule:    spec.withoutSources(),
				Sources: skipped,
			})
		}
	}

	return result, report
}

// Deny removes specs (or specific sources from specs) from current and returns the
// updated rule set and ChangeReport.
// When sources is empty, the entire matching rule is removed. When sources is non-empty,
// only those sources are removed, and the rule is removed if no sources remain.
// Overlapping ranges are never split; denying a sub-range reports it in CoveredBy.
// Denying 22/tcp without sources, or removing all remaining sources from 22/tcp,
// returns ErrSSHRuleProtected without modifying the rule set.
//
// Input args:
//   - current: existing firewall rules (not mutated).
//   - specs: target rules identifying (protocol, port range) pairs to deny.
//   - sources: optional normalized CIDR sources to remove; empty removes the entire rule.
//
// Returns:
//   - []Rule: new rule set after applying the removals.
//   - ChangeReport: summary of removed, skipped, and covered-by targets.
//   - error: ErrSSHRuleProtected if the operation would remove SSH access.
//
// Example:
//
//	next, report, err := firewall.Deny(current, specs, sources)
func Deny(current []Rule, specs []Rule, sources []string) ([]Rule, ChangeReport, error) {
	working := cloneRules(current)
	var report ChangeReport

	normSources := dedupeCanonicalSources(sources)
	uniqueSpecs := dedupeSpecs(specs)
	indexByKey := indexRules(working)
	removedIndices := make(map[int]struct{})

	for _, spec := range uniqueSpecs {
		if err := applySingleDeny(working, indexByKey, removedIndices, spec, normSources, &report); err != nil {
			return nil, ChangeReport{}, err
		}
	}

	result := make([]Rule, 0, len(working)-len(removedIndices))
	for i, rule := range working {
		if _, removed := removedIndices[i]; removed {
			continue
		}
		result = append(result, rule)
	}
	return result, report, nil
}

// applySingleDeny applies one deduplicated deny spec to the working rule slice.
func applySingleDeny(
	working []Rule,
	indexByKey map[RuleKey]int,
	removedIndices map[int]struct{},
	spec Rule,
	normSources []string,
	report *ChangeReport,
) error {
	if len(normSources) == 0 {
		return denyWholeRule(working, indexByKey, removedIndices, spec, report)
	}
	return denyRuleSources(working, indexByKey, removedIndices, spec, normSources, report)
}

// denyWholeRule removes an entire rule when no --source filter was given.
func denyWholeRule(
	working []Rule,
	indexByKey map[RuleKey]int,
	removedIndices map[int]struct{},
	spec Rule,
	report *ChangeReport,
) error {
	if spec.IsSSH() {
		return fmt.Errorf("%w: cannot remove 22/tcp without specifying sources to keep", ErrSSHRuleProtected)
	}

	idx, exists := indexByKey[spec.Key()]
	if !exists {
		recordMissingOrCovered(working, removedIndices, spec, nil, report)
		return nil
	}

	removedIndices[idx] = struct{}{}
	report.Removed = append(report.Removed, RuleChange{
		Rule:    spec.withoutSources(),
		Sources: cloneStrings(working[idx].Sources),
	})
	return nil
}

// denyRuleSources removes only the specified sources from a matching rule.
func denyRuleSources(
	working []Rule,
	indexByKey map[RuleKey]int,
	removedIndices map[int]struct{},
	spec Rule,
	normSources []string,
	report *ChangeReport,
) error {
	idx, exists := indexByKey[spec.Key()]
	if !exists {
		recordMissingOrCovered(working, removedIndices, spec, normSources, report)
		return nil
	}

	existing := working[idx]
	toRemove, notPresent, remaining := partitionRemovedSources(existing.Sources, normSources)

	if spec.IsSSH() && len(remaining) == 0 {
		return fmt.Errorf("%w: removing %v would leave 22/tcp with no sources", ErrSSHRuleProtected, normSources)
	}

	if len(toRemove) > 0 {
		if len(remaining) == 0 {
			removedIndices[idx] = struct{}{}
		} else {
			working[idx].Sources = remaining
		}
		report.Removed = append(report.Removed, RuleChange{
			Rule:    spec.withoutSources(),
			Sources: toRemove,
		})
	}
	if len(notPresent) > 0 {
		report.Skipped = append(report.Skipped, RuleChange{
			Rule:    spec.withoutSources(),
			Sources: notPresent,
		})
	}
	return nil
}

// recordMissingOrCovered records a non-matching deny spec as either covered by wider
// open rules or skipped because it is not open.
func recordMissingOrCovered(
	working []Rule,
	removedIndices map[int]struct{},
	spec Rule,
	sources []string,
	report *ChangeReport,
) {
	covering := findCoveringRules(working, removedIndices, spec)
	if len(covering) > 0 {
		report.CoveredBy = append(report.CoveredBy, CoveredRule{
			Target:    spec.withoutSources(),
			CoveredBy: covering,
		})
		return
	}
	report.Skipped = append(report.Skipped, RuleChange{
		Rule:    spec.withoutSources(),
		Sources: cloneStrings(sources),
	})
}

// findCoveringRules returns active rules with the same protocol whose port range covers spec.
func findCoveringRules(working []Rule, removedIndices map[int]struct{}, spec Rule) []Rule {
	if spec.Protocol == types.ProtocolICMP {
		return nil
	}
	var covering []Rule
	for i, rule := range working {
		if _, removed := removedIndices[i]; removed {
			continue
		}
		if rule.Protocol != spec.Protocol {
			continue
		}
		if rule.Ports.Contains(spec.Ports) && rule.Ports != spec.Ports {
			covering = append(covering, rule.withoutSources())
		}
	}
	return covering
}

// partitionNewSources splits candidate sources into those missing from existing and those already present.
func partitionNewSources(existing, candidates []string) (toAdd []string, alreadyPresent []string) {
	present := make(map[string]struct{}, len(existing))
	for _, s := range existing {
		present[canonicalSource(s)] = struct{}{}
	}
	for _, s := range candidates {
		if _, exists := present[s]; exists {
			alreadyPresent = append(alreadyPresent, s)
			continue
		}
		toAdd = append(toAdd, s)
	}
	return toAdd, alreadyPresent
}

// partitionRemovedSources splits target sources into matched removals, missing skips,
// and the remaining sources on the rule.
func partitionRemovedSources(existing, targets []string) (toRemove, notPresent, remaining []string) {
	existingCanonical := make(map[string]struct{}, len(existing))
	for _, s := range existing {
		existingCanonical[canonicalSource(s)] = struct{}{}
	}

	targetSet := make(map[string]struct{}, len(targets))
	for _, s := range targets {
		targetSet[s] = struct{}{}
		if _, exists := existingCanonical[s]; exists {
			toRemove = append(toRemove, s)
			continue
		}
		notPresent = append(notPresent, s)
	}

	for _, s := range existing {
		if _, drop := targetSet[canonicalSource(s)]; drop {
			continue
		}
		remaining = append(remaining, s)
	}
	return toRemove, notPresent, remaining
}

// dedupeCanonicalSources canonicalizes and deduplicates sources while preserving order.
func dedupeCanonicalSources(sources []string) []string {
	out := make([]string, 0, len(sources))
	seen := make(map[string]struct{}, len(sources))
	for _, s := range sources {
		c := canonicalSource(s)
		if _, exists := seen[c]; exists {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

// dedupeSpecs deduplicates target specs by RuleKey while preserving order.
func dedupeSpecs(specs []Rule) []Rule {
	out := make([]Rule, 0, len(specs))
	seen := make(map[RuleKey]struct{}, len(specs))
	for _, spec := range specs {
		key := spec.Key()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, spec)
	}
	return out
}

// cloneRules deep-copies a slice of Rules so caller inputs are never mutated.
func cloneRules(rules []Rule) []Rule {
	out := make([]Rule, len(rules))
	for i, r := range rules {
		out[i] = Rule{
			Protocol: r.Protocol,
			Ports:    r.Ports,
			Sources:  cloneStrings(r.Sources),
		}
	}
	return out
}

// indexRules builds a lookup map from RuleKey to slice index.
func indexRules(rules []Rule) map[RuleKey]int {
	idx := make(map[RuleKey]int, len(rules))
	for i, r := range rules {
		idx[r.Key()] = i
	}
	return idx
}
