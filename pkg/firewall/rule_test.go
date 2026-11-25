package firewall_test

import (
	"testing"

	"github.com/dreamoutbox/dev-in-vps/pkg/firewall"
	"github.com/dreamoutbox/dev-in-vps/pkg/types"
)

func TestRuleSpecAndKey(t *testing.T) {
	singleTCP := firewall.Rule{
		Protocol: types.ProtocolTCP,
		Ports:    firewall.PortRange{From: 9000, To: 9000},
		Sources:  []string{"0.0.0.0/0"},
	}
	if got := singleTCP.Spec(); got != "9000/tcp" {
		t.Errorf("expected Spec() %q, got %q", "9000/tcp", got)
	}

	rangeUDP := firewall.Rule{
		Protocol: types.ProtocolUDP,
		Ports:    firewall.PortRange{From: 9000, To: 9010},
	}
	if got := rangeUDP.Spec(); got != "9000-9010/udp" {
		t.Errorf("expected Spec() %q, got %q", "9000-9010/udp", got)
	}

	icmpRule := firewall.Rule{Protocol: types.ProtocolICMP}
	if got := icmpRule.Spec(); got != "icmp" {
		t.Errorf("expected Spec() %q, got %q", "icmp", got)
	}

	// Same protocol and ports with different sources must share identity Key.
	sameTCPDifferentSources := firewall.Rule{
		Protocol: types.ProtocolTCP,
		Ports:    firewall.PortRange{From: 9000, To: 9000},
		Sources:  []string{"10.0.0.0/8"},
	}
	if singleTCP.Key() != sameTCPDifferentSources.Key() {
		t.Errorf("expected identical keys for same protocol/ports, got %v vs %v", singleTCP.Key(), sameTCPDifferentSources.Key())
	}

	samePortUDP := firewall.Rule{
		Protocol: types.ProtocolUDP,
		Ports:    firewall.PortRange{From: 9000, To: 9000},
	}
	if singleTCP.Key() == samePortUDP.Key() {
		t.Errorf("expected distinct keys for TCP vs UDP on same port")
	}

	// ICMP key normalizes any stray Ports to zero.
	icmpWithStrayPort := firewall.Rule{
		Protocol: types.ProtocolICMP,
		Ports:    firewall.PortRange{From: 80, To: 80},
	}
	if icmpRule.Key() != icmpWithStrayPort.Key() {
		t.Errorf("expected ICMP keys to match regardless of stray ports")
	}
}

func TestRuleValidate(t *testing.T) {
	validRules := []firewall.Rule{
		{Protocol: types.ProtocolTCP, Ports: firewall.PortRange{From: 22, To: 22}},
		{Protocol: types.ProtocolUDP, Ports: firewall.PortRange{From: 9000, To: 9010}},
		{Protocol: types.ProtocolICMP},
	}
	for _, r := range validRules {
		if err := r.Validate(); err != nil {
			t.Errorf("expected valid rule %+v, got error: %v", r, err)
		}
	}

	invalidRules := []struct {
		name string
		rule firewall.Rule
	}{
		{name: "invalid protocol", rule: firewall.Rule{Protocol: "sctp", Ports: firewall.PortRange{From: 80, To: 80}}},
		{name: "icmp with port", rule: firewall.Rule{Protocol: types.ProtocolICMP, Ports: firewall.PortRange{From: 80, To: 80}}},
		{name: "tcp zero port", rule: firewall.Rule{Protocol: types.ProtocolTCP}},
		{name: "udp reversed range", rule: firewall.Rule{Protocol: types.ProtocolUDP, Ports: firewall.PortRange{From: 9010, To: 9000}}},
	}
	for _, tc := range invalidRules {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.rule.Validate(); err == nil {
				t.Fatalf("expected error for invalid rule %+v, got nil", tc.rule)
			}
		})
	}
}

func TestRuleIsSSHAndSSHRuleHelper(t *testing.T) {
	sources := []string{"0.0.0.0/0", "::/0"}
	ssh := firewall.SSHRule(sources)
	if !ssh.IsSSH() {
		t.Fatalf("expected SSHRule().IsSSH() to be true")
	}
	if ssh.Spec() != "22/tcp" {
		t.Errorf("expected 22/tcp, got %q", ssh.Spec())
	}

	// Mutating original slice must not affect SSHRule sources.
	sources[0] = "1.2.3.4/32"
	if ssh.Sources[0] != "0.0.0.0/0" {
		t.Errorf("expected SSHRule to clone sources, got %v", ssh.Sources)
	}

	nonSSH := []firewall.Rule{
		{Protocol: types.ProtocolUDP, Ports: firewall.PortRange{From: 22, To: 22}},
		{Protocol: types.ProtocolTCP, Ports: firewall.PortRange{From: 20, To: 25}},
		{Protocol: types.ProtocolTCP, Ports: firewall.PortRange{From: 22, To: 23}},
		{Protocol: types.ProtocolTCP, Ports: firewall.PortRange{From: 2222, To: 2222}},
		{Protocol: types.ProtocolICMP},
	}
	for _, r := range nonSSH {
		if r.IsSSH() {
			t.Errorf("expected %s not to be classified as SSH rule", r.Spec())
		}
	}
}
