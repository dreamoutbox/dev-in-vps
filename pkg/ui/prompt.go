// Package ui provides interactive terminal prompts and menus using Charmbracelet Huh.
package ui

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/dreamoutbox/dev-in-vps/pkg/provider"
	"golang.org/x/term"
)

// IsInteractive returns true if standard input is attached to an interactive terminal.
//
// Returns:
//   - bool: true if running in interactive terminal.
//
// Example:
//
//	if ui.IsInteractive() { ... }
func IsInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// SelectRegion presents a selection list of available cloud regions.
//
// Input args:
//   - regions: list of available regions.
//   - defaultSlug: pre-selected or fallback region slug.
//
// Returns:
//   - string: chosen region slug.
//   - error: non-nil if prompt is cancelled or input reading fails.
//
// Example:
//
//	region, err := ui.SelectRegion(regions, "nyc1")
func SelectRegion(regions []provider.Region, defaultSlug string) (string, error) {
	if len(regions) == 0 {
		return defaultSlug, fmt.Errorf("no regions available")
	}

	options := make([]huh.Option[string], 0, len(regions))
	selected := defaultSlug

	foundDefault := false
	for _, r := range regions {
		label := fmt.Sprintf("%-10s (%s)", r.Slug, r.Name)
		options = append(options, huh.NewOption(label, r.Slug))
		if r.Slug == defaultSlug {
			foundDefault = true
		}
	}

	if !foundDefault && len(regions) > 0 {
		selected = regions[0].Slug
	}

	if !IsInteractive() {
		return selected, nil
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Select Datacenter Region").
				Options(options...).
				Value(&selected),
		),
	)

	if err := form.Run(); err != nil {
		return "", fmt.Errorf("region selection cancelled: %w", err)
	}

	return selected, nil
}

// SelectSize presents a selection list of available compute sizes with specs and pricing.
//
// Input args:
//   - sizes: list of available sizes.
//   - defaultSlug: pre-selected or fallback size slug.
//
// Returns:
//   - string: chosen size slug.
//   - error: non-nil if prompt is cancelled or input reading fails.
//
// Example:
//
//	size, err := ui.SelectSize(sizes, "s-2vcpu-4gb")
func SelectSize(sizes []provider.Size, defaultSlug string) (string, error) {
	if len(sizes) == 0 {
		return defaultSlug, fmt.Errorf("no sizes available")
	}

	options := make([]huh.Option[string], 0, len(sizes))
	selected := defaultSlug

	foundDefault := false
	for _, s := range sizes {
		label := fmt.Sprintf("%-16s | %2d vCPU | %5d MB RAM | %3d GB Disk | $%0.2f/mo",
			s.Slug, s.VCPUs, s.MemoryMB, s.DiskGB, s.PriceMonthly)
		options = append(options, huh.NewOption(label, s.Slug))
		if s.Slug == defaultSlug {
			foundDefault = true
		}
	}

	if !foundDefault && len(sizes) > 0 {
		selected = sizes[0].Slug
	}

	if !IsInteractive() {
		return selected, nil
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Select Server Size").
				Options(options...).
				Value(&selected),
		),
	)

	if err := form.Run(); err != nil {
		return "", fmt.Errorf("size selection cancelled: %w", err)
	}

	return selected, nil
}

// PromptText prompts the user for a text input with an optional default value.
//
// Input args:
//   - title: prompt message.
//   - defaultValue: default text if user leaves input blank.
//
// Returns:
//   - string: entered string.
//   - error: non-nil if input reading fails.
//
// Example:
//
//	name, err := ui.PromptText("Server name:", "dev-box")
func PromptText(title string, defaultValue string) (string, error) {
	if !IsInteractive() {
		if defaultValue != "" {
			return defaultValue, nil
		}
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			val := strings.TrimSpace(scanner.Text())
			if val != "" {
				return val, nil
			}
		}
		return defaultValue, nil
	}

	value := defaultValue
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title(title).
				Value(&value),
		),
	)

	if err := form.Run(); err != nil {
		return "", fmt.Errorf("input cancelled: %w", err)
	}

	if strings.TrimSpace(value) == "" {
		return defaultValue, nil
	}
	return strings.TrimSpace(value), nil
}

// PromptConfirm prompts the user with a Yes/No confirmation dialog.
//
// Input args:
//   - title: confirmation question.
//
// Returns:
//   - bool: true if confirmed, false otherwise.
//   - error: non-nil if prompt is cancelled.
//
// Example:
//
//	confirmed, err := ui.PromptConfirm("Destroy server?")
func PromptConfirm(title string) (bool, error) {
	if !IsInteractive() {
		return false, nil
	}

	var confirmed bool
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title(title).
				Value(&confirmed),
		),
	)

	if err := form.Run(); err != nil {
		return false, fmt.Errorf("confirmation cancelled: %w", err)
	}

	return confirmed, nil
}
