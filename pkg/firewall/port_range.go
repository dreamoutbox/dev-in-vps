// Package firewall implements pure firewall rule parsing, normalization, and merge logic.
package firewall

import (
	"fmt"
	"strconv"
)

const (
	// MinPort is the lowest valid TCP/UDP port number.
	MinPort = 1
	// MaxPort is the highest valid TCP/UDP port number.
	MaxPort = 65535
)

// PortRange represents an inclusive TCP or UDP port range.
// A single port has From == To. A zero-value PortRange represents no ports (used for ICMP).
type PortRange struct {
	From int `json:"from"`
	To   int `json:"to"`
}

// NewPortRange constructs and validates an inclusive PortRange from start to end.
//
// Input args:
//   - from: inclusive starting port (1-65535).
//   - to: inclusive ending port (1-65535, >= from).
//
// Returns:
//   - PortRange: the validated port range.
//   - error: non-nil if either port is out of bounds or the range is reversed.
//
// Example:
//
//	pr, err := firewall.NewPortRange(9000, 9010)
func NewPortRange(from, to int) (PortRange, error) {
	pr := PortRange{From: from, To: to}
	if err := pr.Validate(); err != nil {
		return PortRange{}, err
	}
	return pr, nil
}

// Validate checks that both ports are within [MinPort, MaxPort] and From <= To.
//
// Returns:
//   - error: non-nil if the port range is invalid.
//
// Example:
//
//	if err := pr.Validate(); err != nil {
//	    return err
//	}
func (p PortRange) Validate() error {
	if p.From < MinPort || p.From > MaxPort {
		return fmt.Errorf("port %d out of range (%d-%d)", p.From, MinPort, MaxPort)
	}
	if p.To < MinPort || p.To > MaxPort {
		return fmt.Errorf("port %d out of range (%d-%d)", p.To, MinPort, MaxPort)
	}
	if p.From > p.To {
		return fmt.Errorf("reversed port range %d-%d (start must be <= end)", p.From, p.To)
	}
	return nil
}

// IsZero reports whether the port range is unset (both From and To are zero).
//
// Returns:
//   - bool: true if both bounds are zero.
//
// Example:
//
//	if pr.IsZero() {
//	    // ICMP rule has no port range
//	}
func (p PortRange) IsZero() bool {
	return p.From == 0 && p.To == 0
}

// Contains reports whether p completely covers other (inclusive on both ends).
// Zero-value or invalid ranges never contain anything.
//
// Input args:
//   - other: candidate port range to test for containment.
//
// Returns:
//   - bool: true if p.From <= other.From and p.To >= other.To for valid ranges.
//
// Example:
//
//	covered := PortRange{From: 9000, To: 9010}.Contains(PortRange{From: 9005, To: 9005})
func (p PortRange) Contains(other PortRange) bool {
	if p.Validate() != nil || other.Validate() != nil {
		return false
	}
	return p.From <= other.From && p.To >= other.To
}

// String renders a single port as "9000", a range as "9000-9010", and a zero range as "".
//
// Returns:
//   - string: formatted port or port range.
//
// Example:
//
//	s := firewall.PortRange{From: 9000, To: 9010}.String() // "9000-9010"
func (p PortRange) String() string {
	if p.IsZero() {
		return ""
	}
	if p.From == p.To {
		return strconv.Itoa(p.From)
	}
	return fmt.Sprintf("%d-%d", p.From, p.To)
}
