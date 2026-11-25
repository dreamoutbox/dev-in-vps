package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dreamoutbox/dev-in-vps/pkg/config"
	"github.com/dreamoutbox/dev-in-vps/pkg/firewall"
	"github.com/dreamoutbox/dev-in-vps/pkg/provider"
	"github.com/dreamoutbox/dev-in-vps/pkg/sshutil"
	"github.com/dreamoutbox/dev-in-vps/pkg/types"
)

type mockProvider struct {
	mu                sync.Mutex
	regions           []provider.Region
	sizes             []provider.Size
	servers           map[string]*provider.ServerInfo
	firewalls         map[string]*provider.FirewallInfo
	keysEnsured       map[string]string
	createdReqs       []provider.CreateServerRequest
	deletedServer     []string
	callLog           []string
	createFirewallErr error
	deleteFirewallErr error
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
		firewalls:   make(map[string]*provider.FirewallInfo),
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
	m.callLog = append(m.callLog, "ListServers")
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
	m.callLog = append(m.callLog, "DeleteServer:"+id)
	delete(m.servers, id)
	m.deletedServer = append(m.deletedServer, id)
	return nil
}

func (m *mockProvider) CreateFirewall(ctx context.Context, serverID string, name string, rules []firewall.Rule) (*provider.FirewallInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callLog = append(m.callLog, "CreateFirewall:"+serverID)
	if m.createFirewallErr != nil {
		return nil, m.createFirewallErr
	}
	info := &provider.FirewallInfo{
		ID:           "fw-" + serverID,
		Name:         name,
		ServerID:     serverID,
		InboundRules: cloneMockRules(rules),
	}
	m.firewalls[serverID] = info
	return cloneMockFirewallInfo(info), nil
}

func (m *mockProvider) GetFirewall(ctx context.Context, serverID string) (*provider.FirewallInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callLog = append(m.callLog, "GetFirewall:"+serverID)
	fw, ok := m.firewalls[serverID]
	if !ok {
		return nil, provider.ErrFirewallNotFound
	}
	return cloneMockFirewallInfo(fw), nil
}

func (m *mockProvider) UpdateFirewallRules(ctx context.Context, serverID string, rules []firewall.Rule) (*provider.FirewallInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callLog = append(m.callLog, "UpdateFirewallRules:"+serverID)
	fw, ok := m.firewalls[serverID]
	if !ok {
		return nil, provider.ErrFirewallNotFound
	}
	fw.InboundRules = cloneMockRules(rules)
	return cloneMockFirewallInfo(fw), nil
}

func (m *mockProvider) DeleteFirewall(ctx context.Context, serverID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callLog = append(m.callLog, "DeleteFirewall:"+serverID)
	if m.deleteFirewallErr != nil {
		return m.deleteFirewallErr
	}
	delete(m.firewalls, serverID)
	return nil
}

func cloneMockFirewallInfo(fw *provider.FirewallInfo) *provider.FirewallInfo {
	if fw == nil {
		return nil
	}
	return &provider.FirewallInfo{
		ID:           fw.ID,
		Name:         fw.Name,
		ServerID:     fw.ServerID,
		InboundRules: cloneMockRules(fw.InboundRules),
	}
}

func cloneMockRules(rules []firewall.Rule) []firewall.Rule {
	out := make([]firewall.Rule, len(rules))
	for i, r := range rules {
		out[i] = firewall.Rule{
			Protocol: r.Protocol,
			Ports:    r.Ports,
			Sources:  append([]string(nil), r.Sources...),
		}
	}
	return out
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

func TestSSHCopyCommand(t *testing.T) {
	tempDir := filepath.Join(t.TempDir(), "test-home")
	destDir := filepath.Join(t.TempDir(), "dest-keys")

	// 1. Missing keys
	cmd := newRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--home-dir", tempDir, "ssh", "copy", destDir})
	if err := cmd.Execute(); err == nil {
		t.Fatalf("expected error when managed SSH keys do not exist")
	}

	// 2. Generate keys
	if _, _, _, _, err := sshutil.EnsureLocalSSHKey(tempDir); err != nil {
		t.Fatalf("EnsureLocalSSHKey failed: %v", err)
	}

	// 3. Successful copy
	buf.Reset()
	cmd = newRootCmd()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--home-dir", tempDir, "ssh", "copy", destDir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("ssh copy failed: %v", err)
	}
	if !strings.Contains(buf.String(), "Copied SSH key pair to") {
		t.Errorf("expected copy success output, got: %s", buf.String())
	}

	// Verify copied files exist with correct permissions
	privStat, err := os.Stat(filepath.Join(destDir, "id_ed25519"))
	if err != nil {
		t.Fatalf("copied private key not found: %v", err)
	}
	if perm := privStat.Mode().Perm(); perm != 0600 {
		t.Errorf("expected private key perm 0600, got %04o", perm)
	}

	pubStat, err := os.Stat(filepath.Join(destDir, "id_ed25519.pub"))
	if err != nil {
		t.Fatalf("copied public key not found: %v", err)
	}
	if perm := pubStat.Mode().Perm(); perm != 0644 {
		t.Errorf("expected public key perm 0644, got %04o", perm)
	}

	// 4. Overwrite refusal without --force
	buf.Reset()
	cmd = newRootCmd()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--home-dir", tempDir, "ssh", "copy", destDir})
	if err := cmd.Execute(); err == nil {
		t.Fatalf("expected error when destination files already exist without --force")
	}

	// 5. Overwrite allowed with --force
	buf.Reset()
	cmd = newRootCmd()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--home-dir", tempDir, "ssh", "copy", "--force", destDir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("ssh copy with --force failed: %v", err)
	}
}

func TestSSHImportCommand(t *testing.T) {
	tempDir := filepath.Join(t.TempDir(), "test-home")
	srcDir := filepath.Join(t.TempDir(), "src-keys")

	// 1. Missing source key
	cmd := newRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--home-dir", tempDir, "ssh", "import", filepath.Join(srcDir, "nonexistent")})
	if err := cmd.Execute(); err == nil {
		t.Fatalf("expected error importing nonexistent key")
	}

	// 2. Prepare valid key in srcDir
	srcPriv, _, _, _, err := sshutil.EnsureLocalSSHKey(srcDir)
	if err != nil {
		t.Fatalf("EnsureLocalSSHKey failed: %v", err)
	}

	// 3. Successful import
	buf.Reset()
	cmd = newRootCmd()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--home-dir", tempDir, "ssh", "import", srcPriv})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("ssh import failed: %v", err)
	}
	if !strings.Contains(buf.String(), "Imported SSH key pair") {
		t.Errorf("expected import confirmation in output, got: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "dev-vps ssh create") {
		t.Errorf("expected reminder to run dev-vps ssh create, got: %s", buf.String())
	}

	// Verify imported file permissions
	destPriv := config.SSHPrivateKeyPath(tempDir)
	privStat, err := os.Stat(destPriv)
	if err != nil {
		t.Fatalf("imported private key not found: %v", err)
	}
	if perm := privStat.Mode().Perm(); perm != 0600 {
		t.Errorf("expected imported private key perm 0600, got %04o", perm)
	}

	// 4. Overwrite refusal without --force
	buf.Reset()
	cmd = newRootCmd()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--home-dir", tempDir, "ssh", "import", srcPriv})
	if err := cmd.Execute(); err == nil {
		t.Fatalf("expected error overwriting existing keys without --force")
	}

	// 5. Overwrite allowed with --force
	buf.Reset()
	cmd = newRootCmd()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--home-dir", tempDir, "ssh", "import", "--force", srcPriv})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("ssh import with --force failed: %v", err)
	}

	// 6. Test with corrupted key
	corruptedDir := t.TempDir()
	corruptedPriv := filepath.Join(corruptedDir, "id_ed25519")
	_ = os.WriteFile(corruptedPriv, []byte("bad-key"), 0600)
	_ = os.WriteFile(corruptedPriv+".pub", []byte("bad-pub"), 0644)

	buf.Reset()
	cmd = newRootCmd()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--home-dir", tempDir, "ssh", "import", "--force", corruptedPriv})
	if err := cmd.Execute(); err == nil {
		t.Fatalf("expected error importing corrupted key")
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
	mock := newMockProvider()

	oldFactory := providerFactory
	providerFactory = func(cfg *config.Config) (provider.Provider, error) {
		return mock, nil
	}
	defer func() { providerFactory = oldFactory }()

	// 1. List when empty remotely and locally
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

	// 2. Provider API-only server (created from another machine)
	remoteServer := &provider.ServerInfo{
		ID:               "srv-remote-1",
		Name:             "remote-worker",
		Provider:         types.ProviderDigitalOcean,
		Region:           "nyc1",
		Size:             "s-2vcpu-4gb",
		IPAddress:        "203.0.113.55",
		PrivateIPAddress: "10.132.0.12",
		Status:           types.StatusActive,
		CreatedAt:        time.Now(),
	}
	mock.servers[remoteServer.ID] = remoteServer

	buf.Reset()
	cmd = newRootCmd()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--home-dir", tempDir, "list"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("list command with remote server failed: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("remote-worker")) || !bytes.Contains(buf.Bytes(), []byte("203.0.113.55")) || !bytes.Contains(buf.Bytes(), []byte("10.132.0.12")) {
		t.Errorf("expected tabular output with remote-worker and internal IP, got: %s", buf.String())
	}

	// Verify local state was synchronized from the provider API
	st, err := config.LoadState(tempDir)
	if err != nil {
		t.Fatalf("failed to load state: %v", err)
	}
	if rec, found := st.GetServer("remote-worker"); !found || rec.ID != "srv-remote-1" {
		t.Errorf("expected local state to be updated with remote-worker, got: %+v", rec)
	}

	// 3. Stale local server removal: add a stale server to local state that provider doesn't have
	st.AddServer(config.ServerRecord{
		ID:        "srv-stale-99",
		Name:      "ghost-server",
		Provider:  types.ProviderDigitalOcean,
		Region:    "sfo3",
		Size:      "s-1vcpu-1gb",
		IPAddress: "198.51.100.99",
		Status:    types.StatusActive,
		CreatedAt: time.Now(),
	})
	_ = config.SaveState(tempDir, st)

	buf.Reset()
	cmd = newRootCmd()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--home-dir", tempDir, "list"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("list command failed: %v", err)
	}
	if bytes.Contains(buf.Bytes(), []byte("ghost-server")) {
		t.Errorf("expected stale ghost-server to be purged, but it was present in output: %s", buf.String())
	}

	st, _ = config.LoadState(tempDir)
	if _, found := st.GetServer("ghost-server"); found {
		t.Errorf("expected ghost-server to be removed from local state file")
	}

	// 4. JSON list output
	buf.Reset()
	cmd = newRootCmd()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--home-dir", tempDir, "list", "--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("list --json failed: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"name": "remote-worker"`)) {
		t.Errorf("expected JSON output with remote-worker, got: %s", buf.String())
	}

	// 5. Offline fallback: when provider call fails, cached state is retained and warning printed
	providerFactory = func(cfg *config.Config) (provider.Provider, error) {
		return nil, errors.New("simulated network failure")
	}

	outBuf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	cmd = newRootCmd()
	cmd.SetOut(outBuf)
	cmd.SetErr(errBuf)
	cmd.SetArgs([]string{"--home-dir", tempDir, "list"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("list command failed during offline fallback: %v", err)
	}
	if !bytes.Contains(errBuf.Bytes(), []byte("Warning: failed to fetch live servers from provider")) {
		t.Errorf("expected warning on stderr, got: %s", errBuf.String())
	}
	if !bytes.Contains(outBuf.Bytes(), []byte("remote-worker")) {
		t.Errorf("expected cached remote-worker to be displayed during fallback, got: %s", outBuf.String())
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
	if strings.Contains(buf.String(), "Usage:") {
		t.Errorf("expected no usage help text when SSH session exits with error, got: %s", buf.String())
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

func TestCreateServerFirewallLifecycle(t *testing.T) {
	t.Cleanup(func() {
		customBaseDir = ""
		createName = ""
		createRegion = ""
		createSize = ""
		createInitScript = ""
	})

	t.Run("create uses configured firewall rules and sources", func(t *testing.T) {
		tempDir := filepath.Join(t.TempDir(), "custom-fw-home")
		if err := config.InitStorage(tempDir); err != nil {
			t.Fatalf("InitStorage failed: %v", err)
		}
		cfg := config.DefaultConfig()
		cfg.Firewall = &config.FirewallConfig{
			DefaultRules:   []string{"80", "9000-9010/udp", "icmp"},
			DefaultSources: []string{"203.0.113.7"},
		}
		if err := config.SaveConfig(tempDir, cfg); err != nil {
			t.Fatalf("SaveConfig failed: %v", err)
		}

		mock := newMockProvider()
		oldFactory := providerFactory
		providerFactory = func(cfg *config.Config) (provider.Provider, error) { return mock, nil }
		defer func() { providerFactory = oldFactory }()

		cmd := newRootCmd()
		outBuf := new(bytes.Buffer)
		errBuf := new(bytes.Buffer)
		cmd.SetOut(outBuf)
		cmd.SetErr(errBuf)
		cmd.SetArgs([]string{
			"--home-dir", tempDir,
			"create",
			"--name", "custom-box",
			"--region", "nyc1",
			"--size", "s-2vcpu-4gb",
		})

		if err := cmd.Execute(); err != nil {
			t.Fatalf("create failed: %v", err)
		}

		fw, ok := mock.firewalls["server-999"]
		if !ok {
			t.Fatalf("expected firewall to be created for server-999")
		}
		if fw.Name != "dev-vps-custom-box" {
			t.Errorf("expected firewall name dev-vps-custom-box, got %q", fw.Name)
		}
		wantSpecs := []string{"22/tcp", "80/tcp", "9000-9010/udp", "icmp"}
		if len(fw.InboundRules) != len(wantSpecs) {
			t.Fatalf("expected %d rules, got %+v", len(wantSpecs), fw.InboundRules)
		}
		for i, want := range wantSpecs {
			if fw.InboundRules[i].Spec() != want {
				t.Errorf("rule[%d] = %q, want %q", i, fw.InboundRules[i].Spec(), want)
			}
			if !reflect.DeepEqual(fw.InboundRules[i].Sources, []string{"203.0.113.7/32"}) {
				t.Errorf("rule[%d].Sources = %v, want [203.0.113.7/32]", i, fw.InboundRules[i].Sources)
			}
		}
		if !strings.Contains(outBuf.String(), "dev-vps-custom-box") || !strings.Contains(outBuf.String(), "9000-9010/udp") {
			t.Errorf("expected firewall rules in create summary, got:\n%s", outBuf.String())
		}
	})

	t.Run("create with no firewall block uses built-in defaults without 5432", func(t *testing.T) {
		tempDir := filepath.Join(t.TempDir(), "legacy-fw-home")
		if err := config.InitStorage(tempDir); err != nil {
			t.Fatalf("InitStorage failed: %v", err)
		}
		legacyJSON := `{"default_provider":"digitalocean","default_region":"nyc1","default_size":"s-2vcpu-4gb"}`
		if err := os.WriteFile(config.ConfigPath(tempDir), []byte(legacyJSON), 0600); err != nil {
			t.Fatalf("failed to write legacy config: %v", err)
		}

		mock := newMockProvider()
		oldFactory := providerFactory
		providerFactory = func(cfg *config.Config) (provider.Provider, error) { return mock, nil }
		defer func() { providerFactory = oldFactory }()

		cmd := newRootCmd()
		cmd.SetOut(new(bytes.Buffer))
		cmd.SetErr(new(bytes.Buffer))
		cmd.SetArgs([]string{
			"--home-dir", tempDir,
			"create",
			"--name", "legacy-box",
			"--region", "nyc1",
			"--size", "s-2vcpu-4gb",
		})

		if err := cmd.Execute(); err != nil {
			t.Fatalf("create failed: %v", err)
		}

		fw, ok := mock.firewalls["server-999"]
		if !ok {
			t.Fatalf("expected firewall to be created for server-999")
		}
		wantSpecs := []string{"22/tcp", "80/tcp", "443/tcp", "8080/tcp", "8081/tcp", "3000/tcp", "8000/tcp"}
		if len(fw.InboundRules) != len(wantSpecs) {
			t.Fatalf("expected %d built-in rules, got %+v", len(wantSpecs), fw.InboundRules)
		}
		for i, want := range wantSpecs {
			if fw.InboundRules[i].Spec() != want {
				t.Errorf("rule[%d] = %q, want %q", i, fw.InboundRules[i].Spec(), want)
			}
			if fw.InboundRules[i].Spec() == "5432/tcp" {
				t.Errorf("5432/tcp must not be in built-in defaults")
			}
		}
	})

	t.Run("invalid firewall config fails fast with no CreateServer call", func(t *testing.T) {
		tempDir := filepath.Join(t.TempDir(), "invalid-fw-home")
		if err := config.InitStorage(tempDir); err != nil {
			t.Fatalf("InitStorage failed: %v", err)
		}
		cfg := config.DefaultConfig()
		cfg.Firewall = &config.FirewallConfig{
			DefaultRules:   []string{"22", "9000/sctp"},
			DefaultSources: []string{"any"},
		}
		if err := config.SaveConfig(tempDir, cfg); err != nil {
			t.Fatalf("SaveConfig failed: %v", err)
		}

		mock := newMockProvider()
		oldFactory := providerFactory
		providerFactory = func(cfg *config.Config) (provider.Provider, error) { return mock, nil }
		defer func() { providerFactory = oldFactory }()

		cmd := newRootCmd()
		cmd.SetOut(new(bytes.Buffer))
		cmd.SetErr(new(bytes.Buffer))
		cmd.SetArgs([]string{
			"--home-dir", tempDir,
			"create",
			"--name", "bad-config-box",
			"--region", "nyc1",
			"--size", "s-2vcpu-4gb",
		})

		err := cmd.Execute()
		if err == nil {
			t.Fatalf("expected create to fail on invalid firewall config")
		}
		if !strings.Contains(err.Error(), "firewall.default_rules") {
			t.Errorf("expected error to name firewall.default_rules, got: %v", err)
		}
		if len(mock.createdReqs) != 0 {
			t.Errorf("expected zero CreateServer calls on invalid config, got %d", len(mock.createdReqs))
		}
		if len(mock.firewalls) != 0 {
			t.Errorf("expected zero firewalls created on invalid config, got %d", len(mock.firewalls))
		}
	})

	t.Run("firewall API error warns and still completes server creation", func(t *testing.T) {
		tempDir := filepath.Join(t.TempDir(), "fw-api-err-home")
		mock := newMockProvider()
		mock.createFirewallErr = errors.New("token lacks firewall write scope")

		oldFactory := providerFactory
		providerFactory = func(cfg *config.Config) (provider.Provider, error) { return mock, nil }
		defer func() { providerFactory = oldFactory }()

		cmd := newRootCmd()
		outBuf := new(bytes.Buffer)
		errBuf := new(bytes.Buffer)
		cmd.SetOut(outBuf)
		cmd.SetErr(errBuf)
		cmd.SetArgs([]string{
			"--home-dir", tempDir,
			"create",
			"--name", "warn-box",
			"--region", "nyc1",
			"--size", "s-2vcpu-4gb",
		})

		if err := cmd.Execute(); err != nil {
			t.Fatalf("expected create to succeed despite firewall error, got: %v", err)
		}
		if !strings.Contains(errBuf.String(), "Warning: failed to create firewall") {
			t.Errorf("expected firewall warning on stderr, got: %s", errBuf.String())
		}
		if len(mock.createdReqs) != 1 {
			t.Errorf("expected server to remain created, got %d requests", len(mock.createdReqs))
		}
		st, err := config.LoadState(tempDir)
		if err != nil {
			t.Fatalf("LoadState failed: %v", err)
		}
		if _, found := st.GetServer("warn-box"); !found {
			t.Errorf("expected warn-box to be persisted in local state")
		}
	})
}

func TestDestroyServerFirewallLifecycle(t *testing.T) {
	t.Cleanup(func() {
		customBaseDir = ""
		destroyForce = false
	})

	seedServer := func(t *testing.T, tempDir, id, name string, mock *mockProvider, withFirewall bool) {
		t.Helper()
		if err := config.InitStorage(tempDir); err != nil {
			t.Fatalf("InitStorage failed: %v", err)
		}
		st, _ := config.LoadState(tempDir)
		st.AddServer(config.ServerRecord{
			ID:        id,
			Name:      name,
			Provider:  types.ProviderDigitalOcean,
			Region:    "nyc1",
			Size:      "s-2vcpu-4gb",
			IPAddress: "203.0.113.99",
			Status:    types.StatusActive,
			CreatedAt: time.Now(),
		})
		_ = config.SaveState(tempDir, st)
		mock.servers[id] = &provider.ServerInfo{ID: id, Name: name}
		if withFirewall {
			mock.firewalls[id] = &provider.FirewallInfo{
				ID:           "fw-" + id,
				Name:         provider.FirewallNamePrefix + name,
				ServerID:     id,
				InboundRules: []firewall.Rule{firewall.SSHRule(firewall.DefaultSources())},
			}
		}
	}

	t.Run("destroy deletes firewall before deleting droplet", func(t *testing.T) {
		tempDir := filepath.Join(t.TempDir(), "destroy-fw-home")
		mock := newMockProvider()
		seedServer(t, tempDir, "srv-fw-1", "fw-box", mock, true)

		oldFactory := providerFactory
		providerFactory = func(cfg *config.Config) (provider.Provider, error) { return mock, nil }
		defer func() { providerFactory = oldFactory }()

		cmd := newRootCmd()
		cmd.SetOut(new(bytes.Buffer))
		cmd.SetErr(new(bytes.Buffer))
		cmd.SetArgs([]string{"--home-dir", tempDir, "destroy", "fw-box", "-y"})

		if err := cmd.Execute(); err != nil {
			t.Fatalf("destroy failed: %v", err)
		}
		if _, exists := mock.firewalls["srv-fw-1"]; exists {
			t.Errorf("expected firewall to be deleted")
		}
		wantOrder := []string{"DeleteFirewall:srv-fw-1", "DeleteServer:srv-fw-1"}
		if !reflect.DeepEqual(mock.callLog, wantOrder) {
			t.Errorf("call order = %v, want %v", mock.callLog, wantOrder)
		}
	})

	t.Run("destroying droplet without firewall succeeds cleanly", func(t *testing.T) {
		tempDir := filepath.Join(t.TempDir(), "destroy-nofw-home")
		mock := newMockProvider()
		seedServer(t, tempDir, "srv-nofw-1", "nofw-box", mock, false)

		oldFactory := providerFactory
		providerFactory = func(cfg *config.Config) (provider.Provider, error) { return mock, nil }
		defer func() { providerFactory = oldFactory }()

		cmd := newRootCmd()
		errBuf := new(bytes.Buffer)
		cmd.SetOut(new(bytes.Buffer))
		cmd.SetErr(errBuf)
		cmd.SetArgs([]string{"--home-dir", tempDir, "destroy", "nofw-box", "-y"})

		if err := cmd.Execute(); err != nil {
			t.Fatalf("destroy failed: %v", err)
		}
		if errBuf.Len() != 0 {
			t.Errorf("expected no warnings on stderr, got: %s", errBuf.String())
		}
		if len(mock.deletedServer) != 1 || mock.deletedServer[0] != "srv-nofw-1" {
			t.Errorf("expected srv-nofw-1 deleted, got %v", mock.deletedServer)
		}
	})

	t.Run("firewall delete error warns and still deletes droplet", func(t *testing.T) {
		tempDir := filepath.Join(t.TempDir(), "destroy-fwerr-home")
		mock := newMockProvider()
		mock.deleteFirewallErr = errors.New("firewall API error")
		seedServer(t, tempDir, "srv-fwerr-1", "fwerr-box", mock, true)

		oldFactory := providerFactory
		providerFactory = func(cfg *config.Config) (provider.Provider, error) { return mock, nil }
		defer func() { providerFactory = oldFactory }()

		cmd := newRootCmd()
		errBuf := new(bytes.Buffer)
		cmd.SetOut(new(bytes.Buffer))
		cmd.SetErr(errBuf)
		cmd.SetArgs([]string{"--home-dir", tempDir, "destroy", "fwerr-box", "-y"})

		if err := cmd.Execute(); err != nil {
			t.Fatalf("expected destroy to continue despite firewall error, got: %v", err)
		}
		if !strings.Contains(errBuf.String(), "Warning: failed to delete firewall") {
			t.Errorf("expected firewall deletion warning on stderr, got: %s", errBuf.String())
		}
		if len(mock.deletedServer) != 1 || mock.deletedServer[0] != "srv-fwerr-1" {
			t.Errorf("expected droplet srv-fwerr-1 to be deleted, got %v", mock.deletedServer)
		}
		st, _ := config.LoadState(tempDir)
		if _, found := st.GetServer("fwerr-box"); found {
			t.Errorf("expected fwerr-box to be removed from local state")
		}
	})
}
