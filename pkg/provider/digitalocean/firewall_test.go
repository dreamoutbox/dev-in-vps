package digitalocean_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/digitalocean/godo"
	"github.com/dreamoutbox/dev-in-vps/pkg/firewall"
	"github.com/dreamoutbox/dev-in-vps/pkg/provider"
	"github.com/dreamoutbox/dev-in-vps/pkg/provider/digitalocean"
	"github.com/dreamoutbox/dev-in-vps/pkg/types"
)

func TestDigitalOceanFirewalls(t *testing.T) {
	var (
		lastCreateRaw []byte
		lastUpdateRaw []byte
		deleteCalls   []string
	)

	firewalls := map[string]*godo.Firewall{
		"fw-manual": {
			ID:         "fw-manual",
			Name:       "my-manual-firewall",
			DropletIDs: []int{1001, 2002},
			InboundRules: []godo.InboundRule{
				{
					Protocol:  "tcp",
					PortRange: "443",
					Sources:   &godo.Sources{Addresses: []string{"0.0.0.0/0"}},
				},
			},
		},
	}

	mux := http.NewServeMux()

	// POST /v2/firewalls (Create)
	mux.HandleFunc("/v2/firewalls", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		lastCreateRaw = body

		var req godo.FirewallRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		fw := &godo.Firewall{
			ID:            "fw-dev-1001",
			Name:          req.Name,
			InboundRules:  req.InboundRules,
			OutboundRules: req.OutboundRules,
			DropletIDs:    req.DropletIDs,
			Tags:          req.Tags,
		}
		firewalls[fw.ID] = fw
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]*godo.Firewall{"firewall": fw})
	})

	// PUT /v2/firewalls/{id} (Update) and DELETE /v2/firewalls/{id} (Delete)
	mux.HandleFunc("/v2/firewalls/", func(w http.ResponseWriter, r *http.Request) {
		fwID := strings.TrimPrefix(r.URL.Path, "/v2/firewalls/")
		existing, ok := firewalls[fwID]
		if !ok {
			http.NotFound(w, r)
			return
		}

		switch r.Method {
		case http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			lastUpdateRaw = body

			var req godo.FirewallRequest
			if err := json.Unmarshal(body, &req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			updated := &godo.Firewall{
				ID:            existing.ID,
				Name:          req.Name,
				InboundRules:  req.InboundRules,
				OutboundRules: req.OutboundRules,
				DropletIDs:    req.DropletIDs,
				Tags:          req.Tags,
			}
			firewalls[fwID] = updated
			_ = json.NewEncoder(w).Encode(map[string]*godo.Firewall{"firewall": updated})

		case http.MethodDelete:
			deleteCalls = append(deleteCalls, fwID)
			delete(firewalls, fwID)
			w.WriteHeader(http.StatusNoContent)

		default:
			http.NotFound(w, r)
		}
	})

	// GET /v2/droplets/{id}/firewalls (ListByDroplet)
	mux.HandleFunc("/v2/droplets/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/firewalls") {
			http.NotFound(w, r)
			return
		}
		trimmed := strings.TrimPrefix(r.URL.Path, "/v2/droplets/")
		idStr := strings.TrimSuffix(trimmed, "/firewalls")

		var dropletID int
		if _, err := json.Number(idStr).Int64(); err != nil {
			http.NotFound(w, r)
			return
		}
		n, _ := json.Number(idStr).Int64()
		dropletID = int(n)

		// Put manual firewall first so tests prove prefix filtering skips it.
		var matched []godo.Firewall
		if manual, ok := firewalls["fw-manual"]; ok && containsInt(manual.DropletIDs, dropletID) {
			matched = append(matched, *manual)
		}
		for id, fw := range firewalls {
			if id == "fw-manual" {
				continue
			}
			if containsInt(fw.DropletIDs, dropletID) {
				matched = append(matched, *fw)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string][]godo.Firewall{"firewalls": matched})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := digitalocean.New(
		"fake-token",
		digitalocean.WithHTTPClient(server.Client()),
		digitalocean.WithBaseURL(server.URL),
	)
	ctx := context.Background()

	t.Run("GetFirewall skips non-dev-vps firewalls and returns ErrFirewallNotFound", func(t *testing.T) {
		_, err := client.GetFirewall(ctx, "1001")
		if !errors.Is(err, provider.ErrFirewallNotFound) {
			t.Fatalf("expected ErrFirewallNotFound when only manual firewall exists, got: %v", err)
		}
	})

	t.Run("DeleteFirewall is a no-op when no managed firewall exists", func(t *testing.T) {
		if err := client.DeleteFirewall(ctx, "1001"); err != nil {
			t.Fatalf("expected nil on no-op DeleteFirewall, got: %v", err)
		}
		if len(deleteCalls) != 0 {
			t.Errorf("expected no DELETE calls, got %v", deleteCalls)
		}
	})

	t.Run("CreateFirewall sends outbound rules, range 9000-9010, and ICMP without ports", func(t *testing.T) {
		rules := []firewall.Rule{
			firewall.SSHRule([]string{"0.0.0.0/0", "::/0"}),
			{
				Protocol: types.ProtocolUDP,
				Ports:    firewall.PortRange{From: 9000, To: 9010},
				Sources:  []string{"10.0.0.0/8"},
			},
			{
				Protocol: types.ProtocolICMP,
				Sources:  []string{"203.0.113.7/32"},
			},
		}

		info, err := client.CreateFirewall(ctx, "1001", "dev-vps-alpha", rules)
		if err != nil {
			t.Fatalf("CreateFirewall failed: %v", err)
		}
		if info.ID != "fw-dev-1001" || info.Name != "dev-vps-alpha" || info.ServerID != "1001" {
			t.Errorf("unexpected FirewallInfo: %+v", info)
		}

		// Inspect raw JSON payload sent to DigitalOcean.
		var rawPayload struct {
			Name          string           `json:"name"`
			DropletIDs    []int            `json:"droplet_ids"`
			InboundRules  []map[string]any `json:"inbound_rules"`
			OutboundRules []map[string]any `json:"outbound_rules"`
		}
		if err := json.Unmarshal(lastCreateRaw, &rawPayload); err != nil {
			t.Fatalf("failed to unmarshal create payload: %v", err)
		}

		if rawPayload.Name != "dev-vps-alpha" || !reflect.DeepEqual(rawPayload.DropletIDs, []int{1001}) {
			t.Errorf("unexpected create metadata: name=%q droplets=%v", rawPayload.Name, rawPayload.DropletIDs)
		}

		// Assert outbound rules include TCP, UDP, and ICMP to anywhere.
		if len(rawPayload.OutboundRules) != 3 {
			t.Fatalf("expected 3 outbound rules (tcp/udp/icmp), got %d: %+v", len(rawPayload.OutboundRules), rawPayload.OutboundRules)
		}
		outboundProtos := map[string]bool{}
		for _, ob := range rawPayload.OutboundRules {
			proto, _ := ob["protocol"].(string)
			outboundProtos[proto] = true
			if proto == "icmp" {
				if _, hasPorts := ob["ports"]; hasPorts {
					t.Errorf("outbound icmp rule must not include 'ports' key: %+v", ob)
				}
			}
		}
		for _, wantProto := range []string{"tcp", "udp", "icmp"} {
			if !outboundProtos[wantProto] {
				t.Errorf("missing outbound rule for protocol %q", wantProto)
			}
		}

		// Assert inbound rules formatting on the wire.
		if len(rawPayload.InboundRules) != 3 {
			t.Fatalf("expected 3 inbound rules, got %d", len(rawPayload.InboundRules))
		}
		if rawPayload.InboundRules[0]["ports"] != "22" {
			t.Errorf("expected SSH ports '22', got %v", rawPayload.InboundRules[0]["ports"])
		}
		if rawPayload.InboundRules[1]["ports"] != "9000-9010" || rawPayload.InboundRules[1]["protocol"] != "udp" {
			t.Errorf("expected UDP range '9000-9010', got %+v", rawPayload.InboundRules[1])
		}
		if rawPayload.InboundRules[2]["protocol"] != "icmp" {
			t.Errorf("expected icmp rule, got %+v", rawPayload.InboundRules[2])
		}
		if _, hasPorts := rawPayload.InboundRules[2]["ports"]; hasPorts {
			t.Errorf("inbound icmp rule must not include 'ports' field, got %+v", rawPayload.InboundRules[2])
		}
	})

	t.Run("GetFirewall finds dev-vps firewall and maps all/0 ports to 1-65535", func(t *testing.T) {
		// Simulate console edits: add "all" TCP rule, "0" UDP rule, extra droplet ID, tags,
		// and non-address sources on existing and console-only rules.
		fw := firewalls["fw-dev-1001"]
		fw.DropletIDs = []int{1001, 1002}
		fw.Tags = []string{"managed-tag"}
		fw.InboundRules = []godo.InboundRule{
			{
				Protocol:  "tcp",
				PortRange: "22",
				Sources: &godo.Sources{
					Addresses:  []string{"0.0.0.0/0", "::/0"},
					Tags:       []string{"bastion"},
					DropletIDs: []int{555},
				},
			},
			{
				Protocol:  "tcp",
				PortRange: "all",
				Sources:   &godo.Sources{Addresses: []string{"10.0.0.0/8"}},
			},
			{
				Protocol:  "udp",
				PortRange: "0",
				Sources:   &godo.Sources{Addresses: []string{"192.168.1.1"}},
			},
			{
				Protocol: "icmp",
				Sources:  &godo.Sources{Addresses: []string{"203.0.113.7/32"}},
			},
			{
				Protocol:  "tcp",
				PortRange: "9090",
				Sources: &godo.Sources{
					Tags:             []string{"prometheus"},
					LoadBalancerUIDs: []string{"lb-1"},
				},
			},
		}

		info, err := client.GetFirewall(ctx, "1001")
		if err != nil {
			t.Fatalf("GetFirewall failed: %v", err)
		}
		if info.Name != "dev-vps-alpha" {
			t.Errorf("expected dev-vps-alpha (skipping my-manual-firewall), got %q", info.Name)
		}

		// Console-only non-address rule (9090/tcp) should not pollute address rules.
		wantSpecs := []string{"22/tcp", "1-65535/tcp", "1-65535/udp", "icmp"}
		if len(info.InboundRules) != len(wantSpecs) {
			t.Fatalf("expected %d inbound rules, got %d: %+v", len(wantSpecs), len(info.InboundRules), info.InboundRules)
		}
		for i, want := range wantSpecs {
			if info.InboundRules[i].Spec() != want {
				t.Errorf("InboundRules[%d].Spec() = %q, want %q", i, info.InboundRules[i].Spec(), want)
			}
		}
		// Bare IP from DO should normalize to /32.
		if !reflect.DeepEqual(info.InboundRules[2].Sources, []string{"192.168.1.1/32"}) {
			t.Errorf("expected normalized /32 source, got %v", info.InboundRules[2].Sources)
		}
	})

	t.Run("UpdateFirewallRules preserves outbound rules, droplet IDs, tags, and non-address sources", func(t *testing.T) {
		newRules := []firewall.Rule{
			firewall.SSHRule([]string{"203.0.113.7/32"}),
			{
				Protocol: types.ProtocolTCP,
				Ports:    firewall.PortRange{From: 80, To: 80},
				Sources:  []string{"0.0.0.0/0", "::/0"},
			},
		}

		updated, err := client.UpdateFirewallRules(ctx, "1001", newRules)
		if err != nil {
			t.Fatalf("UpdateFirewallRules failed: %v", err)
		}
		if len(updated.InboundRules) != 2 {
			t.Fatalf("expected 2 address-based inbound rules, got %+v", updated.InboundRules)
		}

		var sent godo.FirewallRequest
		if err := json.Unmarshal(lastUpdateRaw, &sent); err != nil {
			t.Fatalf("failed to decode update request: %v", err)
		}
		if sent.Name != "dev-vps-alpha" {
			t.Errorf("expected preserved name dev-vps-alpha, got %q", sent.Name)
		}
		if !reflect.DeepEqual(sent.DropletIDs, []int{1001, 1002}) {
			t.Errorf("expected preserved droplet IDs [1001 1002], got %v", sent.DropletIDs)
		}
		if !reflect.DeepEqual(sent.Tags, []string{"managed-tag"}) {
			t.Errorf("expected preserved firewall tags [managed-tag], got %v", sent.Tags)
		}
		if len(sent.OutboundRules) != 3 {
			t.Errorf("expected 3 preserved outbound rules, got %d", len(sent.OutboundRules))
		}

		// Verify 22/tcp kept its non-address sources alongside updated addresses, AND
		// console-only 9090/tcp rule with tags/LB was preserved.
		if len(sent.InboundRules) != 3 {
			t.Fatalf("expected 3 inbound rules sent (22/tcp, 80/tcp, preserved 9090/tcp), got %+v", sent.InboundRules)
		}
		sshSent := sent.InboundRules[0]
		if !reflect.DeepEqual(sshSent.Sources.Addresses, []string{"203.0.113.7/32"}) {
			t.Errorf("expected updated SSH addresses, got %v", sshSent.Sources.Addresses)
		}
		if !reflect.DeepEqual(sshSent.Sources.Tags, []string{"bastion"}) || !reflect.DeepEqual(sshSent.Sources.DropletIDs, []int{555}) {
			t.Errorf("expected preserved non-address sources on 22/tcp, got %+v", sshSent.Sources)
		}

		preserved9090 := sent.InboundRules[2]
		if preserved9090.PortRange != "9090" || !reflect.DeepEqual(preserved9090.Sources.Tags, []string{"prometheus"}) || !reflect.DeepEqual(preserved9090.Sources.LoadBalancerUIDs, []string{"lb-1"}) {
			t.Errorf("expected console-only 9090/tcp sources preserved, got %+v", preserved9090)
		}
	})

	t.Run("DeleteFirewall deletes managed firewall and ignores manual firewall", func(t *testing.T) {
		if err := client.DeleteFirewall(ctx, "1001"); err != nil {
			t.Fatalf("DeleteFirewall failed: %v", err)
		}
		if !reflect.DeepEqual(deleteCalls, []string{"fw-dev-1001"}) {
			t.Errorf("expected delete call for fw-dev-1001 only, got %v", deleteCalls)
		}
		if _, exists := firewalls["fw-manual"]; !exists {
			t.Errorf("manual firewall must not be deleted")
		}

		// Second GetFirewall should now return ErrFirewallNotFound.
		_, err := client.GetFirewall(ctx, "1001")
		if !errors.Is(err, provider.ErrFirewallNotFound) {
			t.Errorf("expected ErrFirewallNotFound after delete, got %v", err)
		}
	})

	t.Run("invalid droplet ID returns error", func(t *testing.T) {
		if _, err := client.GetFirewall(ctx, "not-a-number"); err == nil {
			t.Errorf("expected error for non-numeric droplet ID")
		}
		if _, err := client.CreateFirewall(ctx, "not-a-number", "dev-vps-x", nil); err == nil {
			t.Errorf("expected error for non-numeric droplet ID")
		}
		if _, err := client.UpdateFirewallRules(ctx, "not-a-number", nil); err == nil {
			t.Errorf("expected error for non-numeric droplet ID")
		}
		if err := client.DeleteFirewall(ctx, "not-a-number"); err == nil {
			t.Errorf("expected error for non-numeric droplet ID")
		}
	})
}

func containsInt(values []int, target int) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}
