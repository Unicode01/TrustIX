package kernelmodule

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"trustix.local/trustix/internal/config"
)

const (
	ModeDisabled = "disabled"
	ModeAuto     = "auto"
	ModeRequired = "required"
)

type Status struct {
	Name             string     `json:"name"`
	Mode             string     `json:"mode"`
	Loaded           bool       `json:"loaded"`
	Managed          bool       `json:"managed"`
	Path             string     `json:"path,omitempty"`
	SHA256           string     `json:"sha256,omitempty"`
	LoadedSHA256     string     `json:"loaded_sha256,omitempty"`
	Parameters       string     `json:"parameters,omitempty"`
	ReloadOnUpgrade  string     `json:"reload_on_upgrade,omitempty"`
	UpgradeState     string     `json:"upgrade_state,omitempty"`
	RefCount         int        `json:"ref_count,omitempty"`
	UsedBy           []string   `json:"used_by,omitempty"`
	InitState        string     `json:"init_state,omitempty"`
	Version          string     `json:"version,omitempty"`
	ABIVersion       int        `json:"abi_version,omitempty"`
	Features         []string   `json:"features,omitempty"`
	MissingFeatures  []string   `json:"missing_features,omitempty"`
	CapabilityTier   string     `json:"capability_tier,omitempty"`
	CapabilityReason string     `json:"capability_reason,omitempty"`
	State            string     `json:"state"`
	Reason           string     `json:"reason,omitempty"`
	LoadedAt         *time.Time `json:"loaded_at,omitempty"`
	UnloadOnExit     bool       `json:"unload_on_exit,omitempty"`
}

// ReloadAssessment describes whether an already-loaded module must be
// replaced before the desired configuration can be applied.
type ReloadAssessment struct {
	Required            bool     `json:"required"`
	Upgrade             bool     `json:"upgrade,omitempty"`
	ParameterMismatches []string `json:"parameter_mismatches,omitempty"`
	Reason              string   `json:"reason,omitempty"`
}

type Manager struct {
	mu                  sync.Mutex
	name                string
	embedded            embeddedModuleAsset
	loadedByUs          bool
	pendingReloadReason string
	status              Status
}

func NewTrustIXCryptoManager() *Manager {
	return NewManager("trustix_crypto")
}

func NewTrustIXDatapathHelpersManager() *Manager {
	return NewManager("trustix_datapath_helpers")
}

func NewTrustIXDatapathManager() *Manager {
	return NewManager("trustix_datapath")
}

func NewManager(name string) *Manager {
	manager := &Manager{name: strings.TrimSpace(name)}
	manager.embedded = embeddedModuleForName(manager.name)
	return manager
}

func ProbeTrustIXCryptoStatus() Status {
	return probeStatus(NewTrustIXCryptoManager())
}

func ProbeTrustIXDatapathHelpersStatus() Status {
	return probeStatus(NewTrustIXDatapathHelpersManager())
}

func ProbeTrustIXDatapathStatus() Status {
	return probeStatus(NewTrustIXDatapathManager())
}

func probeStatus(manager *Manager) Status {
	status, err := manager.Ensure(context.Background(), config.KernelModuleConfig{Mode: ModeDisabled})
	if err != nil {
		status.State = "error"
		status.Reason = err.Error()
	}
	return status
}

func (manager *Manager) Ensure(ctx context.Context, module config.KernelModuleConfig) (Status, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	mode := normalizeMode(module.Mode)
	if !supportedModuleName(manager.name) {
		status := unsupportedModuleStatus(manager.name, module, mode)
		manager.status = status
		if mode == ModeRequired {
			return status, fmt.Errorf("%s is not a supported first-release TrustIX kernel module", manager.name)
		}
		return status, nil
	}
	if manager.embedded.name == "" {
		manager.embedded = embeddedModuleForName(manager.name)
	}
	return manager.ensureLocked(ctx, module)
}

func (manager *Manager) Close(ctx context.Context) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if !supportedModuleName(manager.name) {
		return ctx.Err()
	}
	if manager.embedded.name == "" {
		manager.embedded = embeddedModuleForName(manager.name)
	}
	return manager.closeLocked(ctx)
}

func (manager *Manager) AssessReload(module config.KernelModuleConfig) (Status, ReloadAssessment) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if !supportedModuleName(manager.name) {
		status := unsupportedModuleStatus(manager.name, module, normalizeMode(module.Mode))
		manager.status = status
		return status, ReloadAssessment{}
	}
	if manager.embedded.name == "" {
		manager.embedded = embeddedModuleForName(manager.name)
	}
	status, assessment := manager.assessReloadLocked(module)
	manager.status = status
	return status, assessment
}

// UnloadForCoordinatedReload unloads a supported TrustIX module after the
// daemon has quiesced its dataplane and approved the dependency-wide reload.
func (manager *Manager) UnloadForCoordinatedReload(ctx context.Context, module config.KernelModuleConfig, reason string) (Status, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if !supportedModuleName(manager.name) {
		status := unsupportedModuleStatus(manager.name, module, normalizeMode(module.Mode))
		manager.status = status
		return status, fmt.Errorf("%s is not a supported TrustIX kernel module", manager.name)
	}
	if manager.embedded.name == "" {
		manager.embedded = embeddedModuleForName(manager.name)
	}
	return manager.unloadForCoordinatedReloadLocked(ctx, module, reason)
}

func (manager *Manager) Snapshot() Status {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.status.Name == "" {
		manager.status.Name = manager.name
	}
	return completeCapabilityStatus(manager.status)
}

// UpdateLifecycle changes daemon-owned lifecycle policy without probing or
// reloading a live module. Load-affecting changes still go through Ensure.
func (manager *Manager) UpdateLifecycle(module config.KernelModuleConfig) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.status.Name == "" {
		manager.status.Name = manager.name
	}
	manager.status.ReloadOnUpgrade = normalizedReloadOnUpgrade(module.ReloadOnUpgrade)
	manager.status.UnloadOnExit = module.UnloadOnExit
}

func (manager *Manager) SetStatusForTest(status Status) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.status = status
	if manager.status.Name == "" {
		manager.status.Name = manager.name
	}
	manager.status = completeCapabilityStatus(manager.status)
}

func normalizeMode(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	switch raw {
	case ModeAuto, ModeRequired:
		return raw
	default:
		return ModeDisabled
	}
}

func normalizedReloadOnUpgrade(raw string) string {
	policy := config.NormalizeKernelModuleReloadOnUpgrade(raw)
	if policy == "" {
		return "auto"
	}
	return policy
}

func supportedModuleName(name string) bool {
	switch name {
	case "trustix_crypto", "trustix_datapath", "trustix_datapath_helpers":
		return true
	default:
		return false
	}
}

func unsupportedModuleStatus(name string, module config.KernelModuleConfig, mode string) Status {
	status := Status{
		Name:            name,
		Mode:            mode,
		Path:            strings.TrimSpace(module.Path),
		Parameters:      module.Parameters,
		ReloadOnUpgrade: normalizedReloadOnUpgrade(module.ReloadOnUpgrade),
		UnloadOnExit:    module.UnloadOnExit,
		State:           "unsupported",
		UpgradeState:    "unsupported_module",
		Reason:          "unsupported TrustIX kernel module name; first release manages trustix_crypto, trustix_datapath, and trustix_datapath_helpers only",
	}
	if mode == ModeDisabled {
		status.State = ModeDisabled
		status.Reason = "module lifecycle is disabled"
	}
	return completeCapabilityStatus(status)
}
