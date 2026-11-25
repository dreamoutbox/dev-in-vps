// Package provider defines the cloud provider interface and common abstractions for managing VPS instances.
package provider

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/dreamoutbox/dev-in-vps/pkg/config"
	"github.com/dreamoutbox/dev-in-vps/pkg/firewall"
	"github.com/dreamoutbox/dev-in-vps/pkg/types"
)

const (
	// DevVPSTag is the cloud provider tag attached to instances provisioned by dev-vps.
	DevVPSTag = "dev-vps"
	// FirewallNamePrefix identifies cloud firewalls created and managed by dev-vps.
	FirewallNamePrefix = "dev-vps-"
)

// ErrFirewallNotFound is returned when a server has no dev-vps managed firewall attached.
var ErrFirewallNotFound = errors.New("firewall not found")

// Region encapsulates cloud provider datacenter region metadata.
type Region struct {
	Slug      string `json:"slug"`
	Name      string `json:"name"`
	Available bool   `json:"available"`
}

// Size encapsulates hardware specifications and pricing for a cloud server size.
type Size struct {
	Slug         string   `json:"slug"`
	VCPUs        int      `json:"vcpus"`
	MemoryMB     int      `json:"memory_mb"`
	DiskGB       int      `json:"disk_gb"`
	PriceMonthly float64  `json:"price_monthly"`
	PriceHourly  float64  `json:"price_hourly"`
	Regions      []string `json:"regions"`
}

// CreateServerRequest holds the parameters needed to provision a new VPS instance.
type CreateServerRequest struct {
	Name         string   `json:"name"`
	Region       string   `json:"region"`
	Size         string   `json:"size"`
	Image        string   `json:"image"`
	SSHKeyID     string   `json:"ssh_key_id"`
	UserData     string   `json:"user_data"`
	Tags         []string `json:"tags"`
}

// ServerInfo represents the current status and network details of a remote server.
type ServerInfo struct {
	ID               string             `json:"id"`
	Name             string             `json:"name"`
	Provider         types.ProviderType `json:"provider"`
	Region           string             `json:"region"`
	Size             string             `json:"size"`
	IPAddress        string             `json:"ip_address"`
	PrivateIPAddress string             `json:"private_ip_address"`
	Status           types.ServerStatus `json:"status"`
	CreatedAt        time.Time          `json:"created_at"`
}

// FirewallInfo represents a managed cloud firewall attached to a server.
type FirewallInfo struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	ServerID     string          `json:"server_id"`
	InboundRules []firewall.Rule `json:"inbound_rules"`
}

// Provider defines the contract that cloud infrastructure adapters must implement.
type Provider interface {
	// Type returns the provider type enumeration.
	Type() types.ProviderType

	// ListRegions fetches available datacenter regions.
	ListRegions(ctx context.Context) ([]Region, error)

	// ListSizes fetches available compute sizes, optionally filtered by region availability.
	ListSizes(ctx context.Context, regionSlug string) ([]Size, error)

	// EnsureSSHKey checks if an SSH key exists on the provider, uploading it if missing.
	EnsureSSHKey(ctx context.Context, name string, publicKey string) (string, error)

	// CreateServer provisions a new server instance.
	CreateServer(ctx context.Context, req CreateServerRequest) (*ServerInfo, error)

	// ListServers lists all active servers provisioned by dev-vps.
	ListServers(ctx context.Context) ([]ServerInfo, error)

	// GetServer fetches current status and details for a server by its provider ID.
	GetServer(ctx context.Context, id string) (*ServerInfo, error)

	// DeleteServer terminates and removes the server instance by its provider ID.
	DeleteServer(ctx context.Context, id string) error

	// CreateFirewall creates a managed firewall attached to the server with the given inbound rules.
	CreateFirewall(ctx context.Context, serverID string, name string, rules []firewall.Rule) (*FirewallInfo, error)

	// GetFirewall returns the dev-vps managed firewall attached to the server, or ErrFirewallNotFound.
	GetFirewall(ctx context.Context, serverID string) (*FirewallInfo, error)

	// UpdateFirewallRules replaces the inbound rules on the server's managed firewall while
	// preserving its name, attached servers, outbound rules, and non-address sources.
	UpdateFirewallRules(ctx context.Context, serverID string, rules []firewall.Rule) (*FirewallInfo, error)

	// DeleteFirewall deletes the dev-vps managed firewall attached to the server.
	// Returns nil if no managed firewall exists.
	DeleteFirewall(ctx context.Context, serverID string) error
}

// ResolveDigitalOceanToken resolves the DigitalOcean API token from environment or config.
// Precedence order: DEV_VPS_DO_TOKEN > DIGITALOCEAN_TOKEN > cfg.DigitalOceanToken.
//
// Input args:
//   - cfg: optional pointer to loaded Config (can be nil).
//
// Returns:
//   - string: resolved API token.
//   - error: non-nil if no token is configured.
//
// Example:
//
//	token, err := provider.ResolveDigitalOceanToken(cfg)
func ResolveDigitalOceanToken(cfg *config.Config) (string, error) {
	if token := os.Getenv("DEV_VPS_DO_TOKEN"); token != "" {
		return token, nil
	}
	if token := os.Getenv("DIGITALOCEAN_TOKEN"); token != "" {
		return token, nil
	}
	if cfg != nil && cfg.DigitalOceanToken != "" {
		return cfg.DigitalOceanToken, nil
	}
	return "", errors.New("DigitalOcean API token not found; set DEV_VPS_DO_TOKEN, DIGITALOCEAN_TOKEN, or configure digitalocean_token in ~/.dev-vps/config.json")
}
