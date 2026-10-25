package provider_test

import (
	"testing"

	"github.com/dreamoutbox/dev-in-vps/pkg/config"
	"github.com/dreamoutbox/dev-in-vps/pkg/provider"
)

func TestResolveDigitalOceanToken(t *testing.T) {
	t.Run("from DEV_VPS_DO_TOKEN env", func(t *testing.T) {
		t.Setenv("DEV_VPS_DO_TOKEN", "token-from-dev-vps")
		t.Setenv("DIGITALOCEAN_TOKEN", "token-from-do")

		token, err := provider.ResolveDigitalOceanToken(nil)
		if err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}
		if token != "token-from-dev-vps" {
			t.Errorf("expected token-from-dev-vps, got %s", token)
		}
	})

	t.Run("from DIGITALOCEAN_TOKEN env", func(t *testing.T) {
		t.Setenv("DEV_VPS_DO_TOKEN", "")
		t.Setenv("DIGITALOCEAN_TOKEN", "token-from-do")

		token, err := provider.ResolveDigitalOceanToken(nil)
		if err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}
		if token != "token-from-do" {
			t.Errorf("expected token-from-do, got %s", token)
		}
	})

	t.Run("from config file fallback", func(t *testing.T) {
		t.Setenv("DEV_VPS_DO_TOKEN", "")
		t.Setenv("DIGITALOCEAN_TOKEN", "")

		cfg := &config.Config{DigitalOceanToken: "token-from-cfg"}
		token, err := provider.ResolveDigitalOceanToken(cfg)
		if err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}
		if token != "token-from-cfg" {
			t.Errorf("expected token-from-cfg, got %s", token)
		}
	})

	t.Run("missing token returns error", func(t *testing.T) {
		t.Setenv("DEV_VPS_DO_TOKEN", "")
		t.Setenv("DIGITALOCEAN_TOKEN", "")

		_, err := provider.ResolveDigitalOceanToken(nil)
		if err == nil {
			t.Fatalf("expected error when no token configured, got nil")
		}
	})
}
