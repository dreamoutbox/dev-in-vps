package firewall

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

const (
	// AnyIPv4 is the CIDR representing all IPv4 addresses.
	AnyIPv4 = "0.0.0.0/0"
	// AnyIPv6 is the CIDR representing all IPv6 addresses.
	AnyIPv6 = "::/0"
	// SourceKeywordAny is the shorthand keyword that expands to both AnyIPv4 and AnyIPv6.
	SourceKeywordAny = "any"
)

// ParseSources validates, normalizes, and deduplicates firewall source values.
// Accepted inputs:
//   - IPv4 or IPv6 CIDR (must have no host bits set)
//   - bare IPv4 or IPv6 address (normalized to /32 or /128)
//   - "any" (case-insensitive, expands to 0.0.0.0/0 and ::/0)
//
// Hostnames and CIDRs with host bits set are rejected; every invalid input is
// reported together in one error.
//
// Input args:
//   - values: slice of raw source strings.
//
// Returns:
//   - []string: normalized, deduplicated CIDR strings in first-seen order.
//   - error: joined error listing every invalid source, or nil if all are valid.
//
// Example:
//
//	sources, err := firewall.ParseSources([]string{"203.0.113.7", "10.0.0.0/8"})
func ParseSources(values []string) ([]string, error) {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	var errs []error

	for _, raw := range values {
		expanded, err := parseSingleSource(raw)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, cidr := range expanded {
			if _, exists := seen[cidr]; exists {
				continue
			}
			seen[cidr] = struct{}{}
			result = append(result, cidr)
		}
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return result, nil
}

// parseSingleSource parses one source token into one or two normalized CIDR strings.
func parseSingleSource(raw string) ([]string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("invalid source %q: empty source", raw)
	}

	if strings.EqualFold(trimmed, SourceKeywordAny) {
		return []string{AnyIPv4, AnyIPv6}, nil
	}

	if strings.ContainsRune(trimmed, '/') {
		prefix, err := netip.ParsePrefix(trimmed)
		if err != nil {
			return nil, fmt.Errorf("invalid source %q: expected IP address, CIDR, or %q", raw, SourceKeywordAny)
		}
		masked := prefix.Masked()
		// Reject host bits so typos like 10.0.0.1/8 are never silently widened.
		if prefix != masked {
			return nil, fmt.Errorf("invalid source %q: CIDR has host bits set; did you mean %s?", raw, masked.String())
		}
		return []string{masked.String()}, nil
	}

	addr, err := netip.ParseAddr(trimmed)
	if err != nil || addr.Zone() != "" {
		return nil, fmt.Errorf("invalid source %q: expected IP address, CIDR, or %q", raw, SourceKeywordAny)
	}
	prefix := netip.PrefixFrom(addr, addr.BitLen())
	return []string{prefix.String()}, nil
}

// canonicalSource normalizes a valid IP or already-masked CIDR for set comparison.
// Unrecognized or unmasked inputs are returned as-is so comparison never widens them.
func canonicalSource(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if strings.ContainsRune(trimmed, '/') {
		prefix, err := netip.ParsePrefix(trimmed)
		if err == nil && prefix == prefix.Masked() {
			return prefix.String()
		}
		return raw
	}
	addr, err := netip.ParseAddr(trimmed)
	if err == nil && addr.Zone() == "" {
		return netip.PrefixFrom(addr, addr.BitLen()).String()
	}
	return raw
}
