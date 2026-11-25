package firewall_test

import (
	"testing"

	"github.com/dreamoutbox/dev-in-vps/pkg/firewall"
)

func TestNewPortRangeAndValidate(t *testing.T) {
	validCases := []struct {
		name     string
		from     int
		to       int
		wantText string
	}{
		{name: "single min port", from: 1, to: 1, wantText: "1"},
		{name: "single port", from: 9000, to: 9000, wantText: "9000"},
		{name: "single max port", from: 65535, to: 65535, wantText: "65535"},
		{name: "port range", from: 9000, to: 9010, wantText: "9000-9010"},
		{name: "full port range", from: 1, to: 65535, wantText: "1-65535"},
	}

	for _, tc := range validCases {
		t.Run(tc.name, func(t *testing.T) {
			pr, err := firewall.NewPortRange(tc.from, tc.to)
			if err != nil {
				t.Fatalf("expected nil error, got: %v", err)
			}
			if pr.From != tc.from || pr.To != tc.to {
				t.Errorf("expected {%d, %d}, got {%d, %d}", tc.from, tc.to, pr.From, pr.To)
			}
			if pr.String() != tc.wantText {
				t.Errorf("expected String() %q, got %q", tc.wantText, pr.String())
			}
			if pr.IsZero() {
				t.Errorf("expected IsZero() to be false for %v", pr)
			}
		})
	}

	invalidCases := []struct {
		name string
		from int
		to   int
	}{
		{name: "zero port", from: 0, to: 0},
		{name: "negative from", from: -1, to: 80},
		{name: "from too high", from: 65536, to: 65536},
		{name: "to too high", from: 80, to: 65536},
		{name: "to zero", from: 80, to: 0},
		{name: "reversed range", from: 9010, to: 9000},
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := firewall.NewPortRange(tc.from, tc.to)
			if err == nil {
				t.Fatalf("expected error for {%d, %d}, got nil", tc.from, tc.to)
			}
		})
	}
}

func TestPortRangeZeroAndContains(t *testing.T) {
	var zero firewall.PortRange
	if !zero.IsZero() {
		t.Errorf("expected zero PortRange.IsZero() to be true")
	}
	if zero.String() != "" {
		t.Errorf("expected zero PortRange.String() to be empty, got %q", zero.String())
	}

	wide := firewall.PortRange{From: 9000, To: 9010}
	cases := []struct {
		name  string
		outer firewall.PortRange
		inner firewall.PortRange
		want  bool
	}{
		{name: "contains single port inside", outer: wide, inner: firewall.PortRange{From: 9005, To: 9005}, want: true},
		{name: "contains start boundary", outer: wide, inner: firewall.PortRange{From: 9000, To: 9000}, want: true},
		{name: "contains end boundary", outer: wide, inner: firewall.PortRange{From: 9010, To: 9010}, want: true},
		{name: "contains subrange", outer: wide, inner: firewall.PortRange{From: 9002, To: 9008}, want: true},
		{name: "contains equal range", outer: wide, inner: wide, want: true},
		{name: "does not contain partial overlap high", outer: wide, inner: firewall.PortRange{From: 9005, To: 9020}, want: false},
		{name: "does not contain partial overlap low", outer: wide, inner: firewall.PortRange{From: 8995, To: 9005}, want: false},
		{name: "does not contain disjoint", outer: wide, inner: firewall.PortRange{From: 80, To: 80}, want: false},
		{name: "zero outer contains nothing", outer: zero, inner: firewall.PortRange{From: 80, To: 80}, want: false},
		{name: "zero inner is not contained", outer: wide, inner: zero, want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.outer.Contains(tc.inner); got != tc.want {
				t.Errorf("%v.Contains(%v) = %v, want %v", tc.outer, tc.inner, got, tc.want)
			}
		})
	}
}
