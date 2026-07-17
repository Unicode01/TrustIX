package iptunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Manager struct {
	statePath string
	mu        sync.Mutex
}

type TunnelRecord struct {
	Name      string    `json:"name"`
	Protocol  string    `json:"protocol"`
	Endpoint  string    `json:"endpoint,omitempty"`
	Role      string    `json:"role,omitempty"`
	Config    string    `json:"config,omitempty"`
	RefCount  int       `json:"ref_count,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type tunnelState struct {
	Tunnels []TunnelRecord `json:"tunnels"`
}

var managerKernelTunnelExists = kernelTunnelExists
var managerDeleteKernelTunnel = deleteKernelTunnel

func NewManager(dataDir string) *Manager {
	if dataDir == "" {
		return nil
	}
	return &Manager{statePath: filepath.Join(dataDir, "iptunnel", "state.json")}
}

func DeterministicTunnelName(protocol, config string) string {
	prefix := tunnelNamePrefix(protocol)
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(protocol)) + "\x00" + strings.TrimSpace(config)))
	return "tix" + prefix + hex.EncodeToString(sum[:])[:8]
}

func (manager *Manager) Acquire(ctx context.Context, record TunnelRecord, create func() (string, error)) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if create == nil {
		return "", fmt.Errorf("iptunnel create function is required")
	}
	if manager == nil {
		return create()
	}
	if record.Protocol == "" {
		return "", fmt.Errorf("iptunnel record protocol is required")
	}
	if record.Config == "" {
		return "", fmt.Errorf("iptunnel record config is required")
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	if record.RefCount <= 0 {
		record.RefCount = 1
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	state, err := manager.readStateLocked()
	if err != nil {
		return "", err
	}
	out := state.Tunnels[:0]
	acquiredName := ""
	for _, existing := range state.Tunnels {
		if existing.RefCount <= 0 {
			existing.RefCount = 1
		}
		if existing.Protocol == record.Protocol && existing.Config == record.Config {
			if acquiredName == "" && existing.Name != "" && managerKernelTunnelExists(existing.Name) {
				existing.RefCount++
				existing.Endpoint = mergeRecordField(existing.Endpoint, record.Endpoint)
				existing.Role = mergeRecordField(existing.Role, record.Role)
				out = append(out, existing)
				acquiredName = existing.Name
			}
			continue
		}
		out = append(out, existing)
	}
	state.Tunnels = out
	if acquiredName != "" {
		if err := manager.writeStateLocked(state); err != nil {
			if tunnelStateCommitSucceeded(err) {
				return acquiredName, err
			}
			return "", err
		}
		return acquiredName, nil
	}
	if record.Name == "" {
		record.Name = DeterministicTunnelName(record.Protocol, record.Config)
	}
	if record.Name != "" && managerKernelTunnelExists(record.Name) {
		record.RefCount = 1
		state.Tunnels = append(state.Tunnels, record)
		if err := manager.writeStateLocked(state); err != nil {
			if tunnelStateCommitSucceeded(err) {
				return record.Name, err
			}
			return "", err
		}
		return record.Name, nil
	}
	name, err := create()
	if err != nil {
		if record.Name != "" && managerKernelTunnelExists(record.Name) {
			record.RefCount = 1
			state.Tunnels = append(state.Tunnels, record)
			if writeErr := manager.writeStateLocked(state); writeErr != nil {
				if tunnelStateCommitSucceeded(writeErr) {
					return record.Name, writeErr
				}
				return "", writeErr
			}
			return record.Name, nil
		}
		return "", err
	}
	record.Name = name
	state.Tunnels = append(state.Tunnels, record)
	if err := manager.writeStateLocked(state); err != nil {
		if tunnelStateCommitSucceeded(err) {
			return name, err
		}
		return "", errors.Join(err, wrapManagerError("delete untracked kernel tunnel "+name, managerDeleteKernelTunnel(name)))
	}
	return name, nil
}

func (manager *Manager) Release(ctx context.Context, name string) error {
	if manager == nil {
		return managerDeleteKernelTunnel(name)
	}
	if name == "" {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	state, err := manager.readStateLocked()
	if err != nil {
		return err
	}
	out := state.Tunnels[:0]
	var deleteName string
	for _, record := range state.Tunnels {
		if record.Name != name {
			out = append(out, record)
			continue
		}
		refCount := record.RefCount
		if refCount <= 0 {
			refCount = 1
		}
		refCount--
		if refCount > 0 {
			record.RefCount = refCount
			out = append(out, record)
			continue
		}
		deleteName = record.Name
	}
	state.Tunnels = out
	if deleteName != "" {
		if err := managerDeleteKernelTunnel(deleteName); err != nil {
			return err
		}
	}
	return manager.writeStateLocked(state)
}

func (manager *Manager) Record(ctx context.Context, record TunnelRecord) error {
	if manager == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if record.Name == "" {
		return fmt.Errorf("iptunnel record name is required")
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	if record.RefCount <= 0 {
		record.RefCount = 1
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	state, err := manager.readStateLocked()
	if err != nil {
		return err
	}
	replaced := false
	for i := range state.Tunnels {
		if state.Tunnels[i].Name == record.Name {
			state.Tunnels[i] = record
			replaced = true
			break
		}
	}
	if !replaced {
		state.Tunnels = append(state.Tunnels, record)
	}
	return manager.writeStateLocked(state)
}

func (manager *Manager) Forget(ctx context.Context, name string) error {
	if manager == nil || name == "" {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	state, err := manager.readStateLocked()
	if err != nil {
		return err
	}
	out := state.Tunnels[:0]
	for _, record := range state.Tunnels {
		if record.Name != name {
			out = append(out, record)
		}
	}
	state.Tunnels = out
	return manager.writeStateLocked(state)
}

func mergeRecordField(existing, next string) string {
	if next == "" || existing == next {
		return existing
	}
	if existing == "" {
		return next
	}
	parts := strings.Split(existing, ",")
	for _, part := range parts {
		if strings.TrimSpace(part) == next {
			return existing
		}
	}
	return existing + "," + next
}

func (manager *Manager) Cleanup(ctx context.Context) ([]TunnelRecord, error) {
	if manager == nil {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	state, err := manager.readStateLocked()
	if err != nil {
		return nil, err
	}
	var remaining []TunnelRecord
	var cleanupErrs []error
	for _, record := range state.Tunnels {
		if err := ctx.Err(); err != nil {
			return state.Tunnels, err
		}
		if err := managerDeleteKernelTunnel(record.Name); err != nil {
			remaining = append(remaining, record)
			cleanupErrs = append(cleanupErrs, fmt.Errorf("delete kernel tunnel %q: %w", record.Name, err))
		}
	}
	writeErr := manager.writeStateLocked(tunnelState{Tunnels: remaining})
	if err := errors.Join(errors.Join(cleanupErrs...), wrapManagerError("persist remaining kernel tunnels", writeErr)); err != nil {
		return state.Tunnels, err
	}
	return state.Tunnels, nil
}

func wrapManagerError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func (manager *Manager) Plan(ctx context.Context) ([]TunnelRecord, error) {
	if manager == nil {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	state, err := manager.readStateLocked()
	if err != nil {
		return nil, err
	}
	return append([]TunnelRecord(nil), state.Tunnels...), nil
}

func (manager *Manager) readStateLocked() (tunnelState, error) {
	payload, err := os.ReadFile(manager.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return tunnelState{}, nil
		}
		return tunnelState{}, fmt.Errorf("read iptunnel state %q: %w", manager.statePath, err)
	}
	if len(payload) == 0 {
		return tunnelState{}, nil
	}
	var state tunnelState
	if err := json.Unmarshal(payload, &state); err != nil {
		return tunnelState{}, fmt.Errorf("decode iptunnel state %q: %w", manager.statePath, err)
	}
	return state, nil
}

func (manager *Manager) writeStateLocked(state tunnelState) error {
	if err := os.MkdirAll(filepath.Dir(manager.statePath), 0o700); err != nil {
		return fmt.Errorf("create iptunnel state dir: %w", err)
	}
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode iptunnel state: %w", err)
	}
	payload = append(payload, '\n')
	if err := writeTunnelStateAtomic(manager.statePath, payload, 0o600); err != nil {
		return fmt.Errorf("write iptunnel state %q: %w", manager.statePath, err)
	}
	return nil
}
