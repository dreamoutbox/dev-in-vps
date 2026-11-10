// Package version defines the current release version of dev-vps.
package version

// Version holds the semantic version string of the binary.
var Version = "1.3.0"

// Current returns the current semantic version string.
func Current() string {
	return Version
}
