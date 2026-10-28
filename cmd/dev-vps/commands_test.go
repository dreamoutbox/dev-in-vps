package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
		ID:               "server-999",
		Name:             req.Name,
		Provider:         types.ProviderDigitalOcean,
		Region:           req.Region,
		Size:             req.Size,
		IPAddress:        "198.51.100.25",
		PrivateIPAddress: "10.132.0.8",
		Status:           types.StatusActive,
		CreatedAt:        time.Now(),
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

	if !bytes.Contains(buf.Bytes(), []byte("Create command for reuse:")) {
		t.Errorf("expected reuse command in output, got: %s", buf.String())
	}
	if !bytes.Contains(buf.Bytes(), []byte("dev-vps create --name alpha-box --region nyc1 --size s-2vcpu-4gb")) {
		t.Errorf("expected exact reuse command args in output, got: %s", buf.String())
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
	if rec.IPAddress != "198.51.100.25" || rec.PrivateIPAddress != "10.132.0.8" || rec.Size != "s-2vcpu-4gb" {
		t.Errorf("unexpected record saved: %+v", rec)
	}
	if !bytes.Contains(buf.Bytes(), []byte("Internal IP: 10.132.0.8")) {
		t.Errorf("expected internal IP in create output, got: %s", buf.String())
	}

	if len(mock.createdReqs) != 1 {
		t.Fatalf("expected 1 create server request, got %d", len(mock.createdReqs))
	}
	if !strings.Contains(mock.createdReqs[0].UserData, "/dev-vps/startup.log") {
		t.Errorf("expected user data to contain /dev-vps/startup.log, got: %s", mock.createdReqs[0].UserData)
	}
}

func TestListCommand(t *testing.T) {
	tempDir := filepath.Join(t.TempDir(), "test-home")

	// 1. List when empty
	cmd := newRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--home-dir", tempDir, "list"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("list command failed: %v", err)
	}

	if !bytes.Contains(buf.Bytes(), []byte("No active dev servers found")) {
		t.Errorf("expected empty message, got: %s", buf.String())
	}

	// 2. Add server to state
	st, err := config.LoadState(tempDir)
	if err != nil {
		t.Fatalf("failed to load state: %v", err)
	}
	st.AddServer(config.ServerRecord{
		ID:               "srv-101",
		Name:             "dev-worker",
		Provider:         types.ProviderDigitalOcean,
		Region:           "nyc1",
		Size:             "s-2vcpu-4gb",
		IPAddress:        "203.0.113.55",
		PrivateIPAddress: "10.132.0.12",
		Status:           types.StatusActive,
		CreatedAt:        time.Now(),
	})
	_ = config.SaveState(tempDir, st)

	// 3. Tabular list
	buf.Reset()
	cmd = newRootCmd()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--home-dir", tempDir, "list"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("list command with server failed: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("dev-worker")) || !bytes.Contains(buf.Bytes(), []byte("203.0.113.55")) || !bytes.Contains(buf.Bytes(), []byte("10.132.0.12")) {
		t.Errorf("expected tabular output with dev-worker and internal IP, got: %s", buf.String())
	}

	// 4. JSON list
	buf.Reset()
	cmd = newRootCmd()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--home-dir", tempDir, "list", "--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("list --json failed: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"name": "dev-worker"`)) {
		t.Errorf("expected JSON output with dev-worker, got: %s", buf.String())
	}
}

func TestSSHConnectCommand(t *testing.T) {
	tempDir := filepath.Join(t.TempDir(), "test-home")

	// Ensure SSH key exists
	if err := config.InitStorage(tempDir); err != nil {
		t.Fatalf("InitStorage failed: %v", err)
	}

	privKeyPath := config.SSHPrivateKeyPath(tempDir)
	_ = os.WriteFile(privKeyPath, []byte("fake-key"), 0600)

	st, _ := config.LoadState(tempDir)
	st.AddServer(config.ServerRecord{
		ID:        "srv-202",
		Name:      "remote-dev",
		Provider:  types.ProviderDigitalOcean,
		Region:    "nyc1",
		Size:      "s-2vcpu-4gb",
		IPAddress: "203.0.113.88",
		Status:    types.StatusActive,
		CreatedAt: time.Now(),
	})
	_ = config.SaveState(tempDir, st)

	var executedArgs []string
	oldSSH := sshExecutor
	sshExecutor = func(args []string) error {
		executedArgs = args
		return nil
	}
	defer func() { sshExecutor = oldSSH }()

	// Connect by name
	cmd := newRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--home-dir", tempDir, "ssh", "remote-dev"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("ssh remote-dev failed: %v", err)
	}

	expectedTarget := "root@203.0.113.88"
	foundTarget := false
	for _, arg := range executedArgs {
		if arg == expectedTarget {
			foundTarget = true
			break
		}
	}
	if !foundTarget {
		t.Errorf("expected SSH target %s in arguments %+v", expectedTarget, executedArgs)
	}

	// Execute command on server and exit
	buf.Reset()
	cmd = newRootCmd()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--home-dir", tempDir, "ssh", "remote-dev", "echo", "1"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("ssh remote-dev echo 1 failed: %v", err)
	}

	if buf.Len() > 0 {
		t.Errorf("expected no banner output on stdout when executing remote command, got: %s", buf.String())
	}

	if len(executedArgs) < 5 || executedArgs[len(executedArgs)-2] != "echo" || executedArgs[len(executedArgs)-1] != "1" {
		t.Errorf("expected ['echo', '1'] at end of ssh args, got: %+v", executedArgs)
	}

	// Execute command with flags
	buf.Reset()
	cmd = newRootCmd()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--home-dir", tempDir, "ssh", "remote-dev", "ls", "-la"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("ssh remote-dev ls -la failed: %v", err)
	}

	if len(executedArgs) < 5 || executedArgs[len(executedArgs)-2] != "ls" || executedArgs[len(executedArgs)-1] != "-la" {
		t.Errorf("expected ['ls', '-la'] at end of ssh args, got: %+v", executedArgs)
	}

	// Test ssh help output
	buf.Reset()
	cmd = newRootCmd()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--home-dir", tempDir, "ssh", "--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("ssh --help failed: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("Connect directly to a provisioned dev server")) {
		t.Errorf("expected help output, got: %s", buf.String())
	}

	// Test ssh error propagation
	sshExecutor = func(args []string) error {
		// Run a command that exits with status 1
		proc := exec.Command("sh", "-c", "exit 1")
		return proc.Run()
	}

	buf.Reset()
	cmd = newRootCmd()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--home-dir", tempDir, "ssh", "remote-dev", "false"})

	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected error from failed remote command, got nil")
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected *exec.ExitError, got %T: %v", err, err)
	}
	if exitErr.ExitCode() != 1 {
		t.Errorf("expected exit code 1, got %d", exitErr.ExitCode())
	}
}

func TestDestroyCommand(t *testing.T) {
	tempDir := filepath.Join(t.TempDir(), "test-home")
	mock := newMockProvider()

	oldFactory := providerFactory
	providerFactory = func(cfg *config.Config) (provider.Provider, error) {
		return mock, nil
	}
	defer func() { providerFactory = oldFactory }()

	if err := config.InitStorage(tempDir); err != nil {
		t.Fatalf("InitStorage failed: %v", err)
	}

	st, _ := config.LoadState(tempDir)
	st.AddServer(config.ServerRecord{
		ID:        "server-to-destroy",
		Name:      "doomed-server",
		Provider:  types.ProviderDigitalOcean,
		Region:    "nyc1",
		Size:      "s-2vcpu-4gb",
		IPAddress: "203.0.113.99",
		Status:    types.StatusActive,
		CreatedAt: time.Now(),
	})
	_ = config.SaveState(tempDir, st)
	mock.servers["server-to-destroy"] = &provider.ServerInfo{
		ID:   "server-to-destroy",
		Name: "doomed-server",
	}

	// 1. Without --force in non-interactive mode should fail
	cmd := newRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--home-dir", tempDir, "destroy", "doomed-server"})

	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected error without --force in non-interactive mode, got nil")
	}

	// 2. With -y should succeed and remove from state and provider
	buf.Reset()
	cmd = newRootCmd()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--home-dir", tempDir, "destroy", "doomed-server", "-y"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("destroy doomed-server -y failed: %v", err)
	}

	// Verify server was removed from provider
	if len(mock.deletedServer) != 1 || mock.deletedServer[0] != "server-to-destroy" {
		t.Errorf("expected server-to-destroy to be deleted on provider, got %+v", mock.deletedServer)
	}

	// Verify server was removed from state
	stReloaded, _ := config.LoadState(tempDir)
	if _, found := stReloaded.GetServer("doomed-server"); found {
		t.Errorf("expected doomed-server to be removed from local state")
	}
}
