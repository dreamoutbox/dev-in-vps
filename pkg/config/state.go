package config

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/dreamoutbox/dev-in-vps/pkg/types"
)

// ServerRecord encapsulates saved metadata for a managed VPS instance.
type ServerRecord struct {
	ID        string             `json:"id"`
	Name      string             `json:"name"`
	Provider  types.ProviderType `json:"provider"`
	Region    string             `json:"region"`
	Size      string             `json:"size"`
	IPAddress string             `json:"ip_address"`
	Status    types.ServerStatus `json:"status"`
	CreatedAt time.Time          `json:"created_at"`
}

// State stores local tracking information for all provisioned instances.
type State struct {
	mu      sync.RWMutex
	Servers map[string]ServerRecord `json:"servers"`
}

// NewState creates an empty initialized State instance.
//
// Returns:
//   - *State: empty state with initialized map.
//
// Example:
//
//	st := config.NewState()
func NewState() *State {
	return &State{
		Servers: make(map[string]ServerRecord),
	}
}

// LoadState reads and unmarshals state.json from base directory.
//
// Input args:
//   - base: root directory path (if empty, BaseDir() is used).
//
// Returns:
//   - *State: parsed state struct.
//   - error: non-nil if file reading or JSON unmarshaling fails.
//
// Example:
//
//	st, err := config.LoadState("")
func LoadState(base string) (*State, error) {
	path := StatePath(base)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read state file %s: %w", path, err)
	}

	st := NewState()
	if err := json.Unmarshal(data, st); err != nil {
		return nil, fmt.Errorf("failed to parse state file %s: %w", path, err)
	}
	if st.Servers == nil {
		st.Servers = make(map[string]ServerRecord)
	}

	return st, nil
}

// SaveState marshals and writes the state to state.json safely.
//
// Input args:
//   - base: root directory path (if empty, BaseDir() is used).
//   - st: state pointer to persist.
//
// Returns:
//   - error: non-nil if marshaling or file writing fails.
//
// Example:
//
//	err := config.SaveState("", st)
func SaveState(base string, st *State) error {
	st.mu.RLock()
	defer st.mu.RUnlock()

	path := StatePath(base)
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		return fmt.Errorf("failed to write state file %s: %w", path, err)
	}

	return nil
}

// AddServer inserts or updates a server record keyed by its Name.
//
// Input args:
//   - rec: the ServerRecord to store.
//
// Example:
//
//	st.AddServer(rec)
func (s *State) AddServer(rec ServerRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Servers[rec.Name] = rec
}

// RemoveServer deletes a server record by matching either its Name or ID.
//
// Input args:
//   - nameOrID: server name or provider ID string.
//
// Returns:
//   - bool: true if a record was found and deleted, false otherwise.
//
// Example:
//
//	deleted := st.RemoveServer("dev-box")
func (s *State) RemoveServer(nameOrID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.Servers[nameOrID]; ok {
		delete(s.Servers, nameOrID)
		return true
	}

	for key, rec := range s.Servers {
		if rec.ID == nameOrID {
			delete(s.Servers, key)
			return true
		}
	}

	return false
}

// GetServer finds a server record by matching its Name or ID.
//
// Input args:
//   - nameOrID: server name or provider ID string.
//
// Returns:
//   - ServerRecord: found server record or empty struct.
//   - bool: true if found, false otherwise.
//
// Example:
//
//	rec, ok := st.GetServer("dev-box")
func (s *State) GetServer(nameOrID string) (ServerRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if rec, ok := s.Servers[nameOrID]; ok {
		return rec, true
	}

	for _, rec := range s.Servers {
		if rec.ID == nameOrID {
			return rec, true
		}
	}

	return ServerRecord{}, false
}

// ListServers returns all tracked servers sorted chronologically by CreatedAt.
//
// Returns:
//   - []ServerRecord: list of server records.
//
// Example:
//
//	list := st.ListServers()
func (s *State) ListServers() []ServerRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]ServerRecord, 0, len(s.Servers))
	for _, rec := range s.Servers {
		result = append(result, rec)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})

	return result
}
