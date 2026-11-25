package firewall_test

import (
	"strings"
	"testing"

	"github.com/dreamoutbox/dev-in-vps/pkg/firewall"
	"github.com/dreamoutbox/dev-in-vps/pkg/types"
)

func TestParseRuleSpecValidSyntaxTable(t *testing.T) {
	cases := []struct {
		raw      string
		wantProto types.NetworkProtocol
		wantFrom int
		wantTo   int
		wantSpec string
	}{
		{raw: "9000", wantProto: types.ProtocolTCP, wantFrom: 9000, wantTo: 9000, wantSpec: "9000/tcp"},
		{raw: "9000/tcp", wantProto: types.ProtocolTCP, wantFrom: 9000, wantTo: 9000, wantSpec: "9000/tcp"},
		{raw: "9000/TCP", wantProto: types.ProtocolTCP, wantFrom: 9000, wantTo: 9000, wantSpec: "9000/tcp"},
		{raw: "9001/udp", wantProto: types.ProtocolUDP, wantFrom: 9001, wantTo: 9001, wantSpec: "9001/udp"},
		{raw: "9001/UDP", wantProto: types.ProtocolUDP, wantFrom: 9001, wantTo: 9001, wantSpec: "9001/udp"},
		{raw: "9000-9010", wantProto: types.ProtocolTCP, wantFrom: 9000, wantTo: 9010, wantSpec: "9000-9010/tcp"},
		{raw: "9000-9010/tcp", wantProto: types.ProtocolTCP, wantFrom: 9000, wantTo: 9010, wantSpec: "9000-9010/tcp"},
		{raw: "9000-9010/udp", wantProto: types.ProtocolUDP, wantFrom: 9000, wantTo: 9010, wantSpec: "9000-9010/udp"},
		{raw: "9000-9000/Tcp", wantProto: types.ProtocolTCP, wantFrom: 9000, wantTo: 9000, wantSpec: "9000/tcp"},
		{raw: "1", wantProto: types.ProtocolTCP, wantFrom: 1, wantTo: 1, wantSpec: "1/tcp"},
		{raw: "65535/udp", wantProto: types.ProtocolUDP, wantFrom: 65535, wantTo: 65535, wantSpec: "65535/udp"},
		{raw: "1-65535", wantProto: types.ProtocolTCP, wantFrom: 1, wantTo: 65535, wantSpec: "1-65535/tcp"},
		{raw: "icmp", wantProto: types.ProtocolICMP, wantFrom: 0, wantTo: 0, wantSpec: "icmp"},
		{raw: "ICMP", wantProto: types.ProtocolICMP, wantFrom: 0, wantTo: 0, wantSpec: "icmp"},
		{raw: "Icmp", wantProto: types.ProtocolICMP, wantFrom: 0, wantTo: 0, wantSpec: "icmp"},
	}

	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			got, err := firewall.ParseRuleSpec(tc.raw)
			if err != nil {
				t.Fatalf("ParseRuleSpec(%q) unexpected error: %v", tc.raw, err)
			}
			if got.Protocol != tc.wantProto || got.Ports.From != tc.wantFrom || got.Ports.To != tc.wantTo {
				t.Errorf("ParseRuleSpec(%q) = %+v, want proto=%s ports=%d-%d",
					tc.raw, got, tc.wantProto, tc.wantFrom, tc.wantTo)
			}
			if got.Spec() != tc.wantSpec {
				t.Errorf("Spec() = %q, want %q", got.Spec(), tc.wantSpec)
			}
		})
	}
}

func TestParseRuleSpecRejectsInvalid(t *testing.T) {
	invalidArgs := []string{
		"",
		"   ",
		"0",
		"0/tcp",
		"65536",
		"65536/udp",
		"9010-9000",
		"9010-9000/udp",
		"9000-",
		"-9000",
		"9000-9005-9010",
		"9000/icmp",
		"9000-9010/icmp",
		"icmp/tcp",
		"icmp/udp",
		"icmp/icmp",
		"icmp/",
		"9000/sctp",
		"9000/",
		"/tcp",
		"9000/tcp/udp",
		"http",
		"+80",
		"80 /tcp",
	}

	for _, raw := range invalidArgs {
		t.Run("reject_"+raw, func(t *testing.T) {
			got, err := firewall.ParseRuleSpec(raw)
			if err == nil {
				t.Fatalf("ParseRuleSpec(%q) expected error, got %+v", raw, got)
			}
		})
	}
}

func TestParseRuleSpecsDeduplicationAndOrder(t *testing.T) {
	rules, err := firewall.ParseRuleSpecs([]string{
		"9000",
		"9000/tcp",
		"9000-9000/TCP",
		"9000/udp",
		"icmp",
		"ICMP",
		"9000-9010",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantSpecs := []string{"9000/tcp", "9000/udp", "icmp", "9000-9010/tcp"}
	if len(rules) != len(wantSpecs) {
		t.Fatalf("expected %d rules, got %d: %+v", len(wantSpecs), len(rules), rules)
	}
	for i, want := range wantSpecs {
		if rules[i].Spec() != want {
			t.Errorf("rules[%d].Spec() = %q, want %q", i, rules[i].Spec(), want)
		}
	}
}

func TestParseRuleSpecsEmptySlice(t *testing.T) {
	rules, err := firewall.ParseRuleSpecs([]string{})
	if err != nil {
		t.Fatalf("expected nil error for empty slice, got %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rules))
	}
}

func TestParseRuleSpecsReportsAllInvalidArgsTogether(t *testing.T) {
	invalidBatch := []string{
		"80",
		"0",
		"65536",
		"9010-9000",
		"9000-",
		"9000/icmp",
		"icmp/tcp",
		"9000/sctp",
		"9000/",
	}

	rules, err := firewall.ParseRuleSpecs(invalidBatch)
	if err == nil {
		t.Fatalf("expected aggregated error, got nil (rules=%+v)", rules)
	}
	if rules != nil {
		t.Errorf("expected nil rules on error, got %+v", rules)
	}

	msg := err.Error()
	for _, bad := range invalidBatch[1:] {
		if !strings.Contains(msg, bad) {
			t.Errorf("expected error message to mention invalid arg %q; got:\n%s", bad, msg)
		}
	}
}
