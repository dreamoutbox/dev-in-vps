package firewall_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/dreamoutbox/dev-in-vps/pkg/firewall"
)

func TestParseSourcesValidAndNormalized(t *testing.T) {
	cases := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "empty slice",
			input: []string{},
			want:  []string{},
		},
		{
			name:  "bare IPv4 becomes /32",
			input: []string{"203.0.113.7"},
			want:  []string{"203.0.113.7/32"},
		},
		{
			name:  "bare IPv6 becomes /128 and normalizes",
			input: []string{"2001:0db8:0000:0000::0001"},
			want:  []string{"2001:db8::1/128"},
		},
		{
			name:  "IPv4 and IPv6 CIDRs",
			input: []string{"10.0.0.0/8", "2001:db8::/32"},
			want:  []string{"10.0.0.0/8", "2001:db8::/32"},
		},
		{
			name:  "any expands to IPv4 and IPv6 all",
			input: []string{"any"},
			want:  []string{"0.0.0.0/0", "::/0"},
		},
		{
			name:  "ANY is case-insensitive",
			input: []string{"ANY"},
			want:  []string{"0.0.0.0/0", "::/0"},
		},
		{
			name:  "deduplicates bare IP and /32",
			input: []string{"1.2.3.4", "1.2.3.4/32"},
			want:  []string{"1.2.3.4/32"},
		},
		{
			name:  "deduplicates any with explicit 0.0.0.0/0 and ::/0",
			input: []string{"0.0.0.0/0", "any", "0000:0000::/0"},
			want:  []string{"0.0.0.0/0", "::/0"},
		},
		{
			name:  "deduplicates IPv6 forms",
			input: []string{"2001:0db8::1", "2001:db8::1/128"},
			want:  []string{"2001:db8::1/128"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := firewall.ParseSources(tc.input)
			if err != nil {
				t.Fatalf("ParseSources(%v) unexpected error: %v", tc.input, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ParseSources(%v) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestParseSourcesRejectsHostBitsWithSuggestion(t *testing.T) {
	cases := []struct {
		input      string
		suggestion string
	}{
		{input: "10.0.0.1/8", suggestion: "10.0.0.0/8"},
		{input: "192.168.1.5/24", suggestion: "192.168.1.0/24"},
		{input: "2001:db8::1/32", suggestion: "2001:db8::/32"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			_, err := firewall.ParseSources([]string{tc.input})
			if err == nil {
				t.Fatalf("expected error for host bits in %q, got nil", tc.input)
			}
			if !strings.Contains(err.Error(), tc.suggestion) {
				t.Errorf("expected error to suggest masked CIDR %q, got: %v", tc.suggestion, err)
			}
		})
	}
}

func TestParseSourcesRejectsInvalidValuesAndAggregatesErrors(t *testing.T) {
	invalid := []string{
		"",
		"example.com",
		"localhost",
		"tag:web",
		"droplet:12345",
		"10.0.0.1/8",
		"fe80::1%eth0",
		"999.999.999.999",
		"10.0.0.0/33",
	}

	got, err := firewall.ParseSources(invalid)
	if err == nil {
		t.Fatalf("expected error for invalid sources, got %v", got)
	}
	if got != nil {
		t.Errorf("expected nil result on error, got %v", got)
	}

	msg := err.Error()
	for _, bad := range invalid[1:] {
		if !strings.Contains(msg, bad) {
			t.Errorf("expected aggregated error to mention %q; got:\n%s", bad, msg)
		}
	}
}
