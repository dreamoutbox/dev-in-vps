package types_test

import (
	"testing"

	"github.com/dreamoutbox/dev-in-vps/pkg/types"
)

func TestProviderType(t *testing.T) {
	t.Run("valid provider", func(t *testing.T) {
		pt, err := types.ParseProviderType("digitalocean")
		if err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}
		if pt != types.ProviderDigitalOcean {
			t.Errorf("expected %v, got %v", types.ProviderDigitalOcean, pt)
		}
		if !pt.IsValid() {
			t.Errorf("expected IsValid() to be true")
		}
	})

	t.Run("invalid provider", func(t *testing.T) {
		_, err := types.ParseProviderType("aws")
		if err == nil {
			t.Fatalf("expected error for unsupported provider, got nil")
		}
	})
}
