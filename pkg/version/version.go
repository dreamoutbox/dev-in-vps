// Package version defines the current release version of dev-vps.
package version

// Version holds the semantic version string of the binary.
// It can be overridden at compile time with -ldflags "-X ...version.Version=x.y.z".
var Version = "0.1.0"

// Current returns the current semantic version string.
//
// Returns:
//   - string: semver string (e.g. "0.1.0").
//
// Example:
//
//	v := version.Current()
func Current() string {
	return Version
}
