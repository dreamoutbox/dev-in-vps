package version_test

import (
	"testing"

	"github.com/dreamoutbox/dev-in-vps/pkg/version"
)

func TestVersionCurrent(t *testing.T) {
	v := version.Current()
	if v == "" {
		t.Fatalf("expected non-empty version string")
	}
	if v != version.Version {
		t.Errorf("expected Current() to equal %s, got %s", version.Version, v)
	}
}
