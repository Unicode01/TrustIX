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
		ReloadOnUpgrade: config.NormalizeKernelModuleReloadOnUpgrade(module.ReloadOnUpgrade),
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
