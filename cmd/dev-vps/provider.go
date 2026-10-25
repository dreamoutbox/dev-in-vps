package main

import (
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
