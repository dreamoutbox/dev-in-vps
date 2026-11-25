// Package types defines shared domain types and closed enumerations for dev-vps.
package types

import (
	"fmt"
	"strings"
)

// ProviderType represents a closed set of supported cloud providers.
type ProviderType string

const (
	// ProviderDigitalOcean identifies the DigitalOcean cloud provider.
	ProviderDigitalOcean ProviderType = "digitalocean"
)

// String returns the string representation of ProviderType.
// Example:
//
//	s := types.ProviderDigitalOcean.String()
func (p ProviderType) String() string {
	return string(p)
}

// IsValid checks if the provider type is supported.
//
// Example:
//
//	if !provider.IsValid() {
//	    return fmt.Errorf("unsupported provider")
//	}
func (p ProviderType) IsValid() bool {
	switch p {
	case ProviderDigitalOcean:
		return true
	default:
		return false
	}
}

// ServerStatus represents a closed set of lifecycle states for a dev server.
type ServerStatus string

const (
	// StatusPending indicates the server is currently being provisioned.
	StatusPending ServerStatus = "pending"
	// StatusActive indicates the server is running and accessible.
	StatusActive ServerStatus = "active"
	// StatusOff indicates the server is powered down.
	StatusOff ServerStatus = "off"
	// StatusDestroyed indicates the server has been terminated.
	StatusDestroyed ServerStatus = "destroyed"
)

// String returns the string representation of ServerStatus.
// Example:
//
//	s := types.StatusActive.String()
func (s ServerStatus) String() string {
	return string(s)
}

// ParseProviderType validates and returns a ProviderType from raw input string.
//
// Input args:
//   - raw: string representation of the provider name.
//
// Returns:
//   - ProviderType: the parsed enum value.
//   - error: error if the provider is unknown.
//
// Example:
//
//	provider, err := types.ParseProviderType("digitalocean")
func ParseProviderType(raw string) (ProviderType, error) {
	pt := ProviderType(raw)
	if !pt.IsValid() {
		return "", fmt.Errorf("unknown provider type: %q", raw)
	}
	return pt, nil
}

// NetworkProtocol represents a closed set of supported firewall network protocols.
type NetworkProtocol string

const (
	// ProtocolTCP identifies the TCP network protocol.
	ProtocolTCP NetworkProtocol = "tcp"
	// ProtocolUDP identifies the UDP network protocol.
	ProtocolUDP NetworkProtocol = "udp"
	// ProtocolICMP identifies the ICMP network protocol.
	ProtocolICMP NetworkProtocol = "icmp"
)

// String returns the string representation of NetworkProtocol.
// Example:
//
//	s := types.ProtocolTCP.String()
func (p NetworkProtocol) String() string {
	return string(p)
}

// IsValid reports whether the network protocol is supported.
//
// Example:
//
//	if !proto.IsValid() {
//	    return fmt.Errorf("unsupported protocol")
//	}
func (p NetworkProtocol) IsValid() bool {
	switch p {
	case ProtocolTCP, ProtocolUDP, ProtocolICMP:
		return true
	default:
		return false
	}
}

// ParseNetworkProtocol validates and returns a NetworkProtocol from a raw input string.
// Matching is case-insensitive and returns the canonical lowercase enum value.
//
// Input args:
//   - raw: string representation of the protocol name (e.g. "tcp", "UDP", "icmp").
//
// Returns:
//   - NetworkProtocol: the parsed enum value.
//   - error: non-nil if the protocol is unknown.
//
// Example:
//
//	proto, err := types.ParseNetworkProtocol("TCP")
func ParseNetworkProtocol(raw string) (NetworkProtocol, error) {
	proto := NetworkProtocol(strings.ToLower(raw))
	if !proto.IsValid() {
		return "", fmt.Errorf("unknown network protocol: %q", raw)
	}
	return proto, nil
}
