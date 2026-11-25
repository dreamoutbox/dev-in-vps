package firewall

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/dreamoutbox/dev-in-vps/pkg/types"
)

// ParseRuleSpec parses a single firewall rule spec string into a Rule without sources.
// Accepted forms (case-insensitive):
//   - "9000" -> 9000/tcp
//   - "9000/tcp", "9001/udp" -> single port with explicit protocol
//   - "9000-9010", "9000-9010/udp" -> inclusive port range
//   - "icmp" -> ICMP with no port range
//
// Input args:
//   - raw: rule spec string from CLI args or config.
//
// Returns:
//   - Rule: parsed rule with empty Sources.
//   - error: non-nil if syntax, port bounds, or protocol are invalid.
//
// Example:
//
//	rule, err := firewall.ParseRuleSpec("9000-9010/udp")
func ParseRuleSpec(raw string) (Rule, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return Rule{}, fmt.Errorf("invalid rule spec %q: empty spec", raw)
	}

	lower := strings.ToLower(trimmed)
	if lower == types.ProtocolICMP.String() {
		return Rule{Protocol: types.ProtocolICMP}, nil
	}

	portPart, proto, err := splitSpecProtocol(raw, lower)
	if err != nil {
		return Rule{}, err
	}
	if proto == types.ProtocolICMP {
		return Rule{}, fmt.Errorf("invalid rule spec %q: icmp does not take ports", raw)
	}

	ports, err := parsePortSpec(raw, portPart)
	if err != nil {
		return Rule{}, err
	}

	return Rule{
		Protocol: proto,
		Ports:    ports,
	}, nil
}

// ParseRuleSpecs parses multiple rule spec strings, deduplicating rules with the same
// (protocol, port range) identity while preserving first-seen order.
// Every invalid argument is collected and returned together in one error.
//
// Input args:
//   - args: slice of raw rule spec strings.
//
// Returns:
//   - []Rule: deduplicated parsed rules with empty Sources.
//   - error: joined error listing every invalid spec, or nil if all specs are valid.
//
// Example:
//
//	rules, err := firewall.ParseRuleSpecs([]string{"9000", "9000/tcp", "icmp"})
func ParseRuleSpecs(args []string) ([]Rule, error) {
	rules := make([]Rule, 0, len(args))
	seen := make(map[RuleKey]struct{}, len(args))
	var errs []error

	for _, raw := range args {
		rule, err := ParseRuleSpec(raw)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		key := rule.Key()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		rules = append(rules, rule)
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return rules, nil
}

// splitSpecProtocol splits a lowercased rule spec into its port part and protocol.
// A bare port or range without "/" defaults to TCP.
func splitSpecProtocol(raw, lower string) (string, types.NetworkProtocol, error) {
	slashIdx := strings.IndexByte(lower, '/')
	if slashIdx == -1 {
		return lower, types.ProtocolTCP, nil
	}

	portPart := lower[:slashIdx]
	protoPart := lower[slashIdx+1:]

	if strings.ContainsRune(protoPart, '/') {
		return "", "", fmt.Errorf("invalid rule spec %q: unexpected '/'", raw)
	}
	if portPart == types.ProtocolICMP.String() {
		return "", "", fmt.Errorf("invalid rule spec %q: icmp must not include a protocol suffix", raw)
	}
	if protoPart == "" {
		return "", "", fmt.Errorf("invalid rule spec %q: missing protocol after '/'", raw)
	}

	proto, err := types.ParseNetworkProtocol(protoPart)
	if err != nil {
		return "", "", fmt.Errorf("invalid rule spec %q: unsupported protocol %q (use tcp or udp)", raw, protoPart)
	}
	return portPart, proto, nil
}

// parsePortSpec parses either a single port ("9000") or an inclusive range ("9000-9010").
func parsePortSpec(raw, portPart string) (PortRange, error) {
	if portPart == "" {
		return PortRange{}, fmt.Errorf("invalid rule spec %q: missing port", raw)
	}

	dashIdx := strings.IndexByte(portPart, '-')
	if dashIdx == -1 {
		port, err := parseStrictPort(portPart)
		if err != nil {
			return PortRange{}, fmt.Errorf("invalid rule spec %q: %w", raw, err)
		}
		pr, err := NewPortRange(port, port)
		if err != nil {
			return PortRange{}, fmt.Errorf("invalid rule spec %q: %w", raw, err)
		}
		return pr, nil
	}

	fromStr := portPart[:dashIdx]
	toStr := portPart[dashIdx+1:]
	if fromStr == "" || toStr == "" || strings.ContainsRune(toStr, '-') {
		return PortRange{}, fmt.Errorf("invalid rule spec %q: malformed port range", raw)
	}

	from, err := parseStrictPort(fromStr)
	if err != nil {
		return PortRange{}, fmt.Errorf("invalid rule spec %q: %w", raw, err)
	}
	to, err := parseStrictPort(toStr)
	if err != nil {
		return PortRange{}, fmt.Errorf("invalid rule spec %q: %w", raw, err)
	}

	pr, err := NewPortRange(from, to)
	if err != nil {
		return PortRange{}, fmt.Errorf("invalid rule spec %q: %w", raw, err)
	}
	return pr, nil
}

// parseStrictPort parses an unsigned ASCII decimal port number, rejecting signs and whitespace.
func parseStrictPort(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty port")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("invalid port %q", s)
		}
	}
	port, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return port, nil
}
