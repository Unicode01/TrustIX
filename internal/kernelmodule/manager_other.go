//go:build !linux

package kernelmodule

import (
	"context"
	"fmt"

	"trustix.local/trustix/internal/config"
)

func (manager *Manager) ensureLocked(ctx context.Context, module config.KernelModuleConfig) (Status, error) {
	if err := ctx.Err(); err != nil {
		return manager.status, err
	}
	mode := normalizeMode(module.Mode)
	status := Status{
		Name:            manager.name,
		Mode:            mode,
		Path:            module.Path,
		Parameters:      module.Parameters,
		ReloadOnUpgrade: normalizedReloadOnUpgrade(module.ReloadOnUpgrade),
		UnloadOnExit:    module.UnloadOnExit,
		State:           "unavailable",
		UpgradeState:    "unsupported_platform",
		Reason:          "kernel module lifecycle is only available on Linux",
	}
	if mode == ModeDisabled {
		status.State = ModeDisabled
		status.Reason = "module lifecycle is disabled"
	}
	status = completeCapabilityStatus(status)
	manager.status = status
	if mode == ModeRequired {
		return status, fmt.Errorf("%s is required but kernel modules are only available on Linux", manager.name)
	}
	return status, nil
}

func (manager *Manager) closeLocked(ctx context.Context) error {
	return ctx.Err()
}

func (manager *Manager) assessReloadLocked(module config.KernelModuleConfig) (Status, ReloadAssessment) {
	status, _ := manager.ensureLocked(context.Background(), module)
	return status, ReloadAssessment{}
}

func (manager *Manager) unloadForCoordinatedReloadLocked(ctx context.Context, module config.KernelModuleConfig, reason string) (Status, error) {
	status, _ := manager.ensureLocked(ctx, module)
	return status, fmt.Errorf("%s cannot be reloaded: kernel module lifecycle is only available on Linux", manager.name)
}

func CloseAEADDirectOwnerFiles() error {
	return nil
}
