package ui_test

import (
	"testing"

	"github.com/dreamoutbox/dev-in-vps/pkg/provider"
	"github.com/dreamoutbox/dev-in-vps/pkg/ui"
)

func TestSelectRegionNonInteractive(t *testing.T) {
	regions := []provider.Region{
		{Slug: "nyc1", Name: "New York 1", Available: true},
		{Slug: "sfo3", Name: "San Francisco 3", Available: true},
	}

	selected, err := ui.SelectRegion(regions, "sfo3")
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if selected != "sfo3" {
		t.Errorf("expected sfo3, got %s", selected)
	}

	// Empty regions returns error
	_, err = ui.SelectRegion(nil, "")
	if err == nil {
		t.Errorf("expected error for empty regions, got nil")
	}
}

func TestSelectSizeNonInteractive(t *testing.T) {
	sizes := []provider.Size{
		{Slug: "s-1vcpu-1gb", VCPUs: 1, MemoryMB: 1024, DiskGB: 25, PriceMonthly: 6.0},
		{Slug: "s-2vcpu-4gb", VCPUs: 2, MemoryMB: 4096, DiskGB: 80, PriceMonthly: 24.0},
	}

	selected, err := ui.SelectSize(sizes, "s-2vcpu-4gb")
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if selected != "s-2vcpu-4gb" {
		t.Errorf("expected s-2vcpu-4gb, got %s", selected)
	}

	// Empty sizes returns error
	_, err = ui.SelectSize(nil, "")
	if err == nil {
		t.Errorf("expected error for empty sizes, got nil")
	}
}

func TestPromptTextNonInteractive(t *testing.T) {
	val, err := ui.PromptText("Server name:", "default-box")
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if val != "default-box" {
		t.Errorf("expected default-box, got %s", val)
	}
}

func TestPromptConfirmNonInteractive(t *testing.T) {
	confirmed, err := ui.PromptConfirm("Confirm action?")
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if confirmed {
		t.Errorf("expected non-interactive confirm to be false")
	}
}
