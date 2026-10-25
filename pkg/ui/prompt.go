// Package ui provides interactive terminal prompts and menus using Charmbracelet Huh.
package ui

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/dreamoutbox/dev-in-vps/pkg/config"
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

// formatMemory converts memory in megabytes to a formatted string.
func formatMemory(mb int) string {
	if mb >= 1024 && mb%1024 == 0 {
		return fmt.Sprintf("%d GB", mb/1024)
	}
	if mb >= 1024 {
		return fmt.Sprintf("%.1f GB", float64(mb)/1024)
	}
	return fmt.Sprintf("%d MB", mb)
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

	type formattedSpec struct {
		slug  string
		vcpu  string
		ram   string
		disk  string
		price string
	}

	specs := make([]formattedSpec, len(sizes))
	maxSlugLen := 0
	maxRAMLen := 0
	maxDiskLen := 0
	maxPriceLen := 0

	for i, s := range sizes {
		spec := formattedSpec{
			slug:  s.Slug,
			vcpu:  fmt.Sprintf("%2d vCPU", s.VCPUs),
			ram:   formatMemory(s.MemoryMB),
			disk:  fmt.Sprintf("%d GB", s.DiskGB),
			price: fmt.Sprintf("$%0.2f/mo", s.PriceMonthly),
		}
		if len(spec.slug) > maxSlugLen {
			maxSlugLen = len(spec.slug)
		}
		if len(spec.ram) > maxRAMLen {
			maxRAMLen = len(spec.ram)
		}
		if len(spec.disk) > maxDiskLen {
			maxDiskLen = len(spec.disk)
		}
		if len(spec.price) > maxPriceLen {
			maxPriceLen = len(spec.price)
		}
		specs[i] = spec
	}

	options := make([]huh.Option[string], 0, len(sizes))
	selected := defaultSlug
	foundDefault := false

	for i, s := range sizes {
		spec := specs[i]
		label := fmt.Sprintf("%-*s | %s | %*s | %*s | %*s",
			maxSlugLen, spec.slug,
			spec.vcpu,
			maxRAMLen, spec.ram,
			maxDiskLen, spec.disk,
			maxPriceLen, spec.price,
		)
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

// SelectServer presents an interactive selection list of active server instances.
//
// Input args:
//   - servers: list of server records to choose from.
//
// Returns:
//   - string: name of the chosen server.
//   - error: non-nil if prompt is cancelled or input reading fails.
//
// Example:
//
//	chosen, err := ui.SelectServer(servers)
func SelectServer(servers []config.ServerRecord) (string, error) {
	if len(servers) == 0 {
		return "", fmt.Errorf("no servers available")
	}

	options := make([]huh.Option[string], 0, len(servers))
	for _, s := range servers {
		label := fmt.Sprintf("%-14s | %s | %s | %s (%s)", s.Name, s.IPAddress, s.Size, s.Region, s.Status)
		options = append(options, huh.NewOption(label, s.Name))
	}

	selected := servers[0].Name

	if !IsInteractive() {
		return selected, nil
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Select Server to Connect").
				Options(options...).
				Value(&selected),
		),
	)

	if err := form.Run(); err != nil {
		return "", fmt.Errorf("server selection cancelled: %w", err)
	}

	return selected, nil
}

// PromptSimpleConfirm presents a plain text confirmation prompt on stdout and reads user input from stdin.
//
// Input args:
//   - title: confirmation question to display.
//
// Returns:
//   - bool: true if user answers 'y' or 'yes' (case-insensitive), false otherwise.
//   - error: non-nil if input reading fails.
//
// Example:
//
//	confirmed, err := ui.PromptSimpleConfirm("Destroy server?")
func PromptSimpleConfirm(title string) (bool, error) {
	if !IsInteractive() {
		return false, nil
	}

	fmt.Printf("%s [y/N]: ", title)
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		text := strings.ToLower(strings.TrimSpace(scanner.Text()))
		return text == "y" || text == "yes", nil
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("failed to read confirmation: %w", err)
	}
	return false, nil
}

// PromptConfirm is a backwards-compatible alias for PromptSimpleConfirm.
func PromptConfirm(title string) (bool, error) {
	return PromptSimpleConfirm(title)
}
