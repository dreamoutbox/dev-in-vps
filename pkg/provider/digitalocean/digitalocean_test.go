package digitalocean_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/digitalocean/godo"
	"github.com/dreamoutbox/dev-in-vps/pkg/provider"
	"github.com/dreamoutbox/dev-in-vps/pkg/provider/digitalocean"
	"github.com/dreamoutbox/dev-in-vps/pkg/types"
	"golang.org/x/crypto/ssh"
)

// generateTestSSHKey produces a valid Ed25519 public key in authorized_keys format.
func generateTestSSHKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("failed to convert to ssh public key: %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

func TestDigitalOceanProvider(t *testing.T) {
	mux := http.NewServeMux()

	// 1. Mock Regions
	mux.HandleFunc("/v2/regions", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string][]godo.Region{
			"regions": {
				{Slug: "nyc1", Name: "New York 1", Available: true},
				{Slug: "sfo3", Name: "San Francisco 3", Available: true},
				{Slug: "ams3", Name: "Amsterdam 3", Available: false},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	// 2. Mock Sizes
	mux.HandleFunc("/v2/sizes", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string][]godo.Size{
			"sizes": {
				{
					Slug:         "s-1vcpu-1gb",
					Available:    true,
					Vcpus:        1,
					Memory:       1024,
					Disk:         25,
					PriceMonthly: 6.0,
					PriceHourly:  0.009,
					Regions:      []string{"nyc1", "sfo3"},
				},
				{
					Slug:         "s-2vcpu-4gb",
					Available:    true,
					Vcpus:        2,
					Memory:       4096,
					Disk:         80,
					PriceMonthly: 24.0,
					PriceHourly:  0.036,
					Regions:      []string{"nyc1"},
				},
				{
					Slug:      "s-inactive",
					Available: false,
					Vcpus:     4,
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	// 3. Mock SSH Keys
	keysCreated := 0
	mux.HandleFunc("/v2/account/keys", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			keysCreated++
			resp := map[string]*godo.Key{
				"ssh_key": {
					ID:          999,
					Name:        "dev-vps-key",
					Fingerprint: "mock-fingerprint",
				},
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		http.NotFound(w, r)
	})

	// Mock GetByFingerprint
	mux.HandleFunc("/v2/account/keys/", func(w http.ResponseWriter, r *http.Request) {
		// Fingerprint check: return 404 for first lookup, or key if matching existing
		if strings.HasSuffix(r.URL.Path, "existing-fp") {
			resp := map[string]*godo.Key{
				"ssh_key": {
					ID:          888,
					Name:        "existing-key",
					Fingerprint: "existing-fp",
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		http.NotFound(w, r)
	})

	// 4. Mock Droplet creation and listing
	droplets := map[int]*godo.Droplet{
		1001: {
			ID:       1001,
			Name:     "dev-server-1",
			Status:   "active",
			SizeSlug: "s-2vcpu-4gb",
			Region:   &godo.Region{Slug: "nyc1", Name: "New York 1"},
			Networks: &godo.Networks{
				V4: []godo.NetworkV4{
					{IPAddress: "203.0.113.10", Type: "public"},
				},
			},
			Tags:    []string{provider.DevVPSTag},
			Created: "2026-10-26T00:00:00Z",
		},
	}

	mux.HandleFunc("/v2/droplets", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var req struct {
				Name   string   `json:"name"`
				Region string   `json:"region"`
				Size   string   `json:"size"`
				Tags   []string `json:"tags"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			newD := &godo.Droplet{
				ID:       1002,
				Name:     req.Name,
				Status:   "new",
				SizeSlug: req.Size,
				Region:   &godo.Region{Slug: req.Region},
				Tags:     req.Tags,
				Created:  "2026-10-26T01:00:00Z",
			}
			droplets[1002] = newD
			resp := map[string]*godo.Droplet{"droplet": newD}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		if r.Method == http.MethodGet {
			list := make([]godo.Droplet, 0, len(droplets))
			for _, d := range droplets {
				list = append(list, *d)
			}
			resp := map[string][]godo.Droplet{"droplets": list}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		http.NotFound(w, r)
	})

	// 5. Mock Droplet get / delete
	mux.HandleFunc("/v2/droplets/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		idStr := parts[len(parts)-1]
		var id int
		_, _ = fmt.Sscanf(idStr, "%d", &id)

		d, exists := droplets[id]
		if !exists {
			http.NotFound(w, r)
			return
		}

		if r.Method == http.MethodGet {
			resp := map[string]*godo.Droplet{"droplet": d}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		if r.Method == http.MethodDelete {
			delete(droplets, id)
			w.WriteHeader(http.StatusNoContent)
			return
		}

		http.NotFound(w, r)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := digitalocean.New(
		"fake-token",
		digitalocean.WithHTTPClient(server.Client()),
		digitalocean.WithBaseURL(server.URL),
	)

	ctx := context.Background()

	t.Run("Type", func(t *testing.T) {
		if client.Type() != types.ProviderDigitalOcean {
			t.Errorf("expected %v, got %v", types.ProviderDigitalOcean, client.Type())
		}
	})

	t.Run("ListRegions", func(t *testing.T) {
		regions, err := client.ListRegions(ctx)
		if err != nil {
			t.Fatalf("ListRegions failed: %v", err)
		}
		if len(regions) != 3 {
			t.Errorf("expected 3 regions, got %d", len(regions))
		}
	})

	t.Run("ListSizes with and without filter", func(t *testing.T) {
		allSizes, err := client.ListSizes(ctx, "")
		if err != nil {
			t.Fatalf("ListSizes failed: %v", err)
		}
		if len(allSizes) != 2 {
			t.Errorf("expected 2 active sizes, got %d", len(allSizes))
		}

		sfoSizes, err := client.ListSizes(ctx, "sfo3")
		if err != nil {
			t.Fatalf("ListSizes for sfo3 failed: %v", err)
		}
		if len(sfoSizes) != 1 || sfoSizes[0].Slug != "s-1vcpu-1gb" {
			t.Errorf("expected s-1vcpu-1gb for sfo3, got %+v", sfoSizes)
		}
	})

	t.Run("EnsureSSHKey creates key if not present", func(t *testing.T) {
		pubKey := generateTestSSHKey(t)
		keyID, err := client.EnsureSSHKey(ctx, "test-key", pubKey)
		if err != nil {
			t.Fatalf("EnsureSSHKey failed: %v", err)
		}
		if keyID != "999" {
			t.Errorf("expected key ID 999, got %s", keyID)
		}
	})

	t.Run("CreateServer", func(t *testing.T) {
		info, err := client.CreateServer(ctx, provider.CreateServerRequest{
			Name:     "dev-server-2",
			Region:   "nyc1",
			Size:     "s-2vcpu-4gb",
			SSHKeyID: "999",
			UserData: "echo hello",
		})
		if err != nil {
			t.Fatalf("CreateServer failed: %v", err)
		}
		if info.ID != "1002" || info.Status != types.StatusPending {
			t.Errorf("unexpected ServerInfo: %+v", info)
		}
	})

	t.Run("GetServer", func(t *testing.T) {
		info, err := client.GetServer(ctx, "1001")
		if err != nil {
			t.Fatalf("GetServer failed: %v", err)
		}
		if info.IPAddress != "203.0.113.10" || info.Status != types.StatusActive {
			t.Errorf("unexpected ServerInfo: %+v", info)
		}
	})

	t.Run("ListServers", func(t *testing.T) {
		servers, err := client.ListServers(ctx)
		if err != nil {
			t.Fatalf("ListServers failed: %v", err)
		}
		if len(servers) < 1 {
			t.Errorf("expected at least 1 server, got %d", len(servers))
		}
	})

	t.Run("DeleteServer", func(t *testing.T) {
		if err := client.DeleteServer(ctx, "1001"); err != nil {
			t.Fatalf("DeleteServer failed: %v", err)
		}
		_, err := client.GetServer(ctx, "1001")
		if err == nil {
			t.Errorf("expected error getting deleted server, got nil")
		}
	})
}
