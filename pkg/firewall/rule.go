package firewall

import (
	"fmt"

	"github.com/dreamoutbox/dev-in-vps/pkg/types"
)

// SSHPort is the protected TCP port for SSH access.
const SSHPort = 22

// RuleKey uniquely identifies a firewall rule by its protocol and port range.
type RuleKey struct {
	Protocol types.NetworkProtocol
	Ports    PortRange
}

// Rule represents an inbound firewall rule with a protocol, optional port range,
// and the set of normalized CIDR sources permitted by the rule.
type Rule struct {
	Protocol types.NetworkProtocol `json:"protocol"`
	Ports    PortRange             `json:"ports"`
	Sources  []string              `json:"sources"`
}

// SSHRule constructs the exact 22/tcp SSH rule with a copy of the given sources.
//
// Input args:
//   - sources: allowed CIDR sources for SSH.
//
// Returns:
//   - Rule: the 22/tcp firewall rule.
//
// Example:
//
//	rule := firewall.SSHRule(firewall.DefaultSources())
func SSHRule(sources []string) Rule {
	return Rule{
		Protocol: types.ProtocolTCP,
		Ports:    PortRange{From: SSHPort, To: SSHPort},
		Sources:  cloneStrings(sources),
	}
}

// Key returns the RuleKey that uniquely identifies this rule's protocol and port range.
// For ICMP rules, Ports is normalized to the zero PortRange so identity comparisons are consistent.
//
// Returns:
//   - RuleKey: comparable identity key for map lookups and equality checks.
//
// Example:
//
//	key := rule.Key()
func (r Rule) Key() RuleKey {
	if r.Protocol == types.ProtocolICMP {
		return RuleKey{Protocol: types.ProtocolICMP}
	}
	return RuleKey{
		Protocol: r.Protocol,
		Ports:    r.Ports,
	}
}

// Spec renders the rule's canonical spec notation, such as "9000/tcp", "9000-9010/udp", or "icmp".
//
// Returns:
//   - string: formatted rule spec without sources.
//
// Example:
//
//	s := firewall.Rule{Protocol: types.ProtocolTCP, Ports: firewall.PortRange{From: 9000, To: 9010}}.Spec()
func (r Rule) Spec() string {
	if r.Protocol == types.ProtocolICMP {
		return types.ProtocolICMP.String()
	}
	return fmt.Sprintf("%s/%s", r.Ports.String(), r.Protocol.String())
}

// Validate checks that the rule's protocol is supported and its port range matches the protocol.
//
// Returns:
//   - error: non-nil if the protocol is invalid, ICMP has ports, or TCP/UDP ports are invalid.
//
// Example:
//
//	if err := rule.Validate(); err != nil {
//	    return err
//	}
func (r Rule) Validate() error {
	if !r.Protocol.IsValid() {
		return fmt.Errorf("invalid protocol %q", r.Protocol)
	}
	if r.Protocol == types.ProtocolICMP {
		if !r.Ports.IsZero() {
			return fmt.Errorf("icmp rules must not specify ports (got %s)", r.Ports.String())
		}
		return nil
	}
	return r.Ports.Validate()
}

// IsSSH reports whether this rule is the exact protected SSH rule (22/tcp).
//
// Returns:
//   - bool: true only when protocol is TCP and ports are exactly 22-22.
//
// Example:
//
//	if rule.IsSSH() {
//	    // apply SSH protection
//	}
func (r Rule) IsSSH() bool {
	return r.Protocol == types.ProtocolTCP && r.Ports.From == SSHPort && r.Ports.To == SSHPort
}

// withoutSources returns a copy of the rule carrying only its protocol and port identity.
func (r Rule) withoutSources() Rule {
	key := r.Key()
	return Rule{
		Protocol: key.Protocol,
		Ports:    key.Ports,
	}
}

// cloneStrings returns an independent copy of a string slice, preserving nil vs empty semantics.
func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}
