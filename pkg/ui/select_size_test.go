package ui

import (
	"errors"
	"testing"

	"github.com/dreamoutbox/dev-in-vps/pkg/provider"
)

func TestBuildSizeOptionsIncludesCustomEntry(t *testing.T) {
	sizes := []provider.Size{
		{Slug: "s-1vcpu-1gb", VCPUs: 1, MemoryMB: 1024, DiskGB: 25, PriceMonthly: 6.0},
		{Slug: "s-2vcpu-4gb", VCPUs: 2, MemoryMB: 4096, DiskGB: 80, PriceMonthly: 24.0},
	}

	options, selected := buildSizeOptions(sizes, "s-2vcpu-4gb")
	if len(options) != 3 {
		t.Fatalf("expected 3 options (custom + 2 sizes), got %d", len(options))
	}
	if options[0].Value != customSizeSentinel || options[0].Key != customSizeLabel {
		t.Errorf("expected custom option first, got key=%q value=%q", options[0].Key, options[0].Value)
	}
	if selected != "s-2vcpu-4gb" {
		t.Errorf("expected default selected slug s-2vcpu-4gb, got %q", selected)
	}

	// Missing default should fall back to first real size, not custom sentinel.
	_, fallback := buildSizeOptions(sizes, "missing-slug")
	if fallback != "s-1vcpu-1gb" {
		t.Errorf("expected fallback s-1vcpu-1gb, got %q", fallback)
	}
}

func TestResolveSizeSelection(t *testing.T) {
	t.Run("preset size returns directly without prompting", func(t *testing.T) {
		promptCalled := false
		slug, err := resolveSizeSelection("s-2vcpu-4gb", func() (string, error) {
			promptCalled = true
			return "", nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if slug != "s-2vcpu-4gb" {
			t.Errorf("expected s-2vcpu-4gb, got %q", slug)
		}
		if promptCalled {
			t.Errorf("expected custom prompt not to be called for preset size")
		}
	})

	t.Run("custom selection prompts and trims valid slug", func(t *testing.T) {
		slug, err := resolveSizeSelection(customSizeSentinel, func() (string, error) {
			return "  s-4vcpu-8gb-amd  ", nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if slug != "s-4vcpu-8gb-amd" {
			t.Errorf("expected s-4vcpu-8gb-amd, got %q", slug)
		}
	})

	t.Run("custom selection propagates prompt cancellation", func(t *testing.T) {
		cancelErr := errors.New("cancelled")
		_, err := resolveSizeSelection(customSizeSentinel, func() (string, error) {
			return "", cancelErr
		})
		if !errors.Is(err, cancelErr) {
			t.Fatalf("expected cancellation error, got %v", err)
		}
	})

	t.Run("custom selection rejects invalid slug", func(t *testing.T) {
		for _, invalid := range []string{"", "   ", "s-2vcpu 4gb"} {
			if _, err := resolveSizeSelection(customSizeSentinel, func() (string, error) {
				return invalid, nil
			}); err == nil {
				t.Errorf("expected error for invalid custom slug %q, got nil", invalid)
			}
		}
	})
}
