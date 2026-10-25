package main

import (
	"bytes"
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dreamoutbox/dev-in-vps/pkg/config"
	"github.com/dreamoutbox/dev-in-vps/pkg/provider"
	"github.com/dreamoutbox/dev-in-vps/pkg/types"
)

type mockProvider struct {
	mu            sync.Mutex
	regions       []provider.Region
	sizes         []provider.Size
	servers       map[string]*provider.ServerInfo
	keysEnsured   map[string]string
	createdReqs   []provider.CreateServerRequest
	deletedServer []string
}

func newMockProvider() *mockProvider {
	return &mockProvider{
		regions: []provider.Region{
			{Slug: "nyc1", Name: "New York 1", Available: true},
			{Slug: "sfo3", Name: "San Francisco 3", Available: true},
		},
		sizes: []provider.Size{
			{Slug: "s-1vcpu-1gb", VCPUs: 1, MemoryMB: 1024, DiskGB: 25, PriceMonthly: 6.0},
			{Slug: "s-2vcpu-4gb", VCPUs: 2, MemoryMB: 4096, DiskGB: 80, PriceMonthly: 24.0},
		},
		servers:     make(map[string]*provider.ServerInfo),
		keysEnsured: make(map[string]string),
	}
}

func (m *mockProvider) Type() types.ProviderType {
	return types.ProviderDigitalOcean
}

func (m *mockProvider) ListRegions(ctx context.Context) ([]provider.Region, error) {
	return m.regions, nil
}

func (m *mockProvider) ListSizes(ctx context.Context, regionSlug string) ([]provider.Size, error) {
	return m.sizes, nil
}

func (m *mockProvider) EnsureSSHKey(ctx context.Context, name string, publicKey string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keysEnsured[name] = publicKey
	return "mock-key-123", nil
}

func (m *mockProvider) CreateServer(ctx context.Context, req provider.CreateServerRequest) (*provider.ServerInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createdReqs = append(m.createdReqs, req)
	info := &provider.ServerInfo{
		ID:        "server-999",
		Name:      req.Name,
		Provider:  types.ProviderDigitalOcean,
		Region:    req.Region,
		Size:      req.Size,
		IPAddress: "198.51.100.25",
		Status:    types.StatusActive,
		CreatedAt: time.Now(),
	}
	m.servers[info.ID] = info
	return info, nil
}

func (m *mockProvider) ListServers(ctx context.Context) ([]provider.ServerInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var list []provider.ServerInfo
	for _, s := range m.servers {
		list = append(list, *s)
	}
	return list, nil
}

func (m *mockProvider) GetServer(ctx context.Context, id string) (*provider.ServerInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.servers[id]; ok {
		return s, nil
	}
	return nil, nil
}

func (m *mockProvider) DeleteServer(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.servers, id)
	m.deletedServer = append(m.deletedServer, id)
	return nil
}

func TestSSHCreateCommand(t *testing.T) {
	tempDir := filepath.Join(t.TempDir(), "test-home")
	mock := newMockProvider()

	oldFactory := providerFactory
	providerFactory = func(cfg *config.Config) (provider.Provider, error) {
		return mock, nil
	}
	defer func() { providerFactory = oldFactory }()

	cmd := newRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--home-dir", tempDir, "ssh", "create"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("ssh create failed: %v", err)
	}

	if len(mock.keysEnsured) == 0 {
		t.Errorf("expected SSH key to be ensured on provider")
	}
}

func TestCreateServerCommand(t *testing.T) {
	tempDir := filepath.Join(t.TempDir(), "test-home")
	mock := newMockProvider()

	oldFactory := providerFactory
	providerFactory = func(cfg *config.Config) (provider.Provider, error) {
		return mock, nil
	}
	defer func() { providerFactory = oldFactory }()

	cmd := newRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{
		"--home-dir", tempDir,
		"create",
		"--name", "alpha-box",
		"--region", "nyc1",
		"--size", "s-2vcpu-4gb",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("dev-vps create failed: %v", err)
	}

	// Verify server was recorded in state
	st, err := config.LoadState(tempDir)
	if err != nil {
		t.Fatalf("failed to load state: %v", err)
	}

	rec, ok := st.GetServer("alpha-box")
	if !ok {
		t.Fatalf("expected alpha-box to be saved in state.json")
	}
	if rec.IPAddress != "198.51.100.25" || rec.Size != "s-2vcpu-4gb" {
		t.Errorf("unexpected record saved: %+v", rec)
	}
}
