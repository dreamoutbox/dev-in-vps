// Package types defines shared domain types and closed enumerations for dev-vps.
package types

import "fmt"

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
