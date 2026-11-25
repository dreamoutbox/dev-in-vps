package types_test

import (
	"testing"

	"github.com/dreamoutbox/dev-in-vps/pkg/types"
)

func TestProviderType(t *testing.T) {
	t.Run("valid provider", func(t *testing.T) {
		pt, err := types.ParseProviderType("digitalocean")
		if err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}
		if pt != types.ProviderDigitalOcean {
			t.Errorf("expected %v, got %v", types.ProviderDigitalOcean, pt)
		}
		if !pt.IsValid() {
			t.Errorf("expected IsValid() to be true")
		}
	})

	t.Run("invalid provider", func(t *testing.T) {
		_, err := types.ParseProviderType("aws")
		if err == nil {
			t.Fatalf("expected error for unsupported provider, got nil")
		}
	})
}

func TestNetworkProtocol(t *testing.T) {
	validCases := []struct {
		name string
		raw  string
		want types.NetworkProtocol
	}{
		{name: "tcp lowercase", raw: "tcp", want: types.ProtocolTCP},
		{name: "tcp uppercase", raw: "TCP", want: types.ProtocolTCP},
		{name: "udp lowercase", raw: "udp", want: types.ProtocolUDP},
		{name: "udp mixed case", raw: "Udp", want: types.ProtocolUDP},
		{name: "icmp lowercase", raw: "icmp", want: types.ProtocolICMP},
		{name: "icmp uppercase", raw: "ICMP", want: types.ProtocolICMP},
	}

	for _, tc := range validCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := types.ParseNetworkProtocol(tc.raw)
			if err != nil {
				t.Fatalf("expected nil error for %q, got: %v", tc.raw, err)
			}
			if got != tc.want {
				t.Errorf("expected %q, got %q", tc.want, got)
			}
			if !got.IsValid() {
				t.Errorf("expected IsValid() to be true for %q", got)
			}
			if got.String() != string(tc.want) {
				t.Errorf("expected String() %q, got %q", string(tc.want), got.String())
			}
		})
	}

	invalidCases := []string{"", "sctp", "http", " tcp", "tcp ", "icmpv6"}
	for _, raw := range invalidCases {
		t.Run("invalid_"+raw, func(t *testing.T) {
			got, err := types.ParseNetworkProtocol(raw)
			if err == nil {
				t.Fatalf("expected error for %q, got protocol %q", raw, got)
			}
			if types.NetworkProtocol(raw).IsValid() {
				t.Errorf("expected IsValid() to be false for %q", raw)
			}
		})
	}
}
