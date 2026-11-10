package main

import (
	"context"
	"fmt"

	"github.com/dreamoutbox/dev-in-vps/pkg/config"
	"github.com/dreamoutbox/dev-in-vps/pkg/provider"
	"github.com/dreamoutbox/dev-in-vps/pkg/provider/digitalocean"
	"github.com/dreamoutbox/dev-in-vps/pkg/types"
)

// providerFactory is the function used to instantiate the provider client.
// It can be replaced in unit tests with a mock provider.
var providerFactory = newProviderFromConfig

// newProviderFromConfig instantiates the configured cloud provider implementation.
//
// Input args:
//   - cfg: application configuration.
//
// Returns:
//   - provider.Provider: initialized cloud provider client.
//   - error: non-nil if token resolution or initialization fails.
//
// Example:
//
//	p, err := newProviderFromConfig(cfg)
func newProviderFromConfig(cfg *config.Config) (provider.Provider, error) {
	switch cfg.DefaultProvider {
	case types.ProviderDigitalOcean:
		token, err := provider.ResolveDigitalOceanToken(cfg)
		if err != nil {
			return nil, err
		}
		return digitalocean.New(token), nil
	default:
		return nil, fmt.Errorf("unsupported provider: %s", cfg.DefaultProvider)
	}
}

// ServerInfoToRecord converts a provider.ServerInfo model into a config.ServerRecord.
//
// Input args:
//   - info: server information from cloud provider.
//
// Returns:
//   - config.ServerRecord: local state server record representation.
//
// Example:
//
//	rec := ServerInfoToRecord(info)
func ServerInfoToRecord(info provider.ServerInfo) config.ServerRecord {
	return config.ServerRecord{
		ID:               info.ID,
		Name:             info.Name,
		Provider:         info.Provider,
		Region:           info.Region,
		Size:             info.Size,
		IPAddress:        info.IPAddress,
		PrivateIPAddress: info.PrivateIPAddress,
		Status:           info.Status,
		CreatedAt:        info.CreatedAt,
	}
}

// fetchRemoteServers queries the active cloud provider for all dev VPS instances.
//
// Input args:
//   - ctx: context controlling timeout and cancellation.
//   - baseDir: root configuration directory.
//
// Returns:
//   - []provider.ServerInfo: list of active instances returned by provider API.
//   - error: non-nil if config loading, provider initialization, or API call fails.
//
// Example:
//
//	servers, err := fetchRemoteServers(ctx, "")
func fetchRemoteServers(ctx context.Context, baseDir string) ([]provider.ServerInfo, error) {
	cfg, err := config.LoadConfig(baseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	prov, err := providerFactory(cfg)
	if err != nil {
		return nil, err
	}

	return prov.ListServers(ctx)
}
