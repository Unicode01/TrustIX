package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const runtimeReconcileInterval = 2 * time.Second

type runtimeReconcileStatus struct {
	Pending       bool      `json:"pending"`
	Reason        string    `json:"reason,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
	Attempts      uint64    `json:"attempts"`
	RequestedAt   time.Time `json:"requested_at,omitempty"`
	LastAttemptAt time.Time `json:"last_attempt_at,omitempty"`
	LastSuccessAt time.Time `json:"last_success_at,omitempty"`
}

func (daemon *Daemon) requestRuntimeReconcile(reason string, err error) {
	if daemon == nil || err == nil {
		return
	}
	now := time.Now().UTC()
	daemon.reconcileMu.Lock()
	daemon.reconcileGeneration++
	daemon.reconcileState.Pending = true
	daemon.reconcileState.Reason = reason
	daemon.reconcileState.LastError = err.Error()
	daemon.reconcileState.RequestedAt = now
	wake := daemon.reconcileWake
	daemon.reconcileMu.Unlock()
	if wake != nil {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}

func (daemon *Daemon) runtimeReconcileStatus() runtimeReconcileStatus {
	if daemon == nil {
		return runtimeReconcileStatus{}
	}
	daemon.reconcileMu.Lock()
	defer daemon.reconcileMu.Unlock()
	return daemon.reconcileState
}

func (daemon *Daemon) runtimeReconcileDoctorCheck() doctorCheck {
	status := daemon.runtimeReconcileStatus()
	if !status.Pending {
		return doctorCheck{Name: "runtime_reconcile", Status: "ok", Detail: "runtime state is reconciled"}
	}
	detail := fmt.Sprintf("pending reason=%s attempts=%d", status.Reason, status.Attempts)
	if status.LastError != "" {
		detail += "; last_error=" + status.LastError
	}
	return doctorCheck{Name: "runtime_reconcile", Status: "degraded", Detail: detail}
}

func (daemon *Daemon) runtimeReconcileWorker(ctx context.Context) {
	ticker := time.NewTicker(runtimeReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-daemon.reconcileWake:
		case <-ticker.C:
		}
		daemon.retryPendingRuntimeReconcile(ctx)
	}
}

func (daemon *Daemon) retryPendingRuntimeReconcile(ctx context.Context) {
	daemon.reconcileAttemptMu.Lock()
	defer daemon.reconcileAttemptMu.Unlock()

	daemon.reconcileMu.Lock()
	if !daemon.reconcileState.Pending {
		daemon.reconcileMu.Unlock()
		return
	}
	generation := daemon.reconcileGeneration
	daemon.reconcileState.Attempts++
	daemon.reconcileState.LastAttemptAt = time.Now().UTC()
	daemon.reconcileMu.Unlock()

	err := daemon.reconcileRuntimeState(ctx)
	now := time.Now().UTC()
	daemon.reconcileMu.Lock()
	defer daemon.reconcileMu.Unlock()
	if err != nil {
		if daemon.reconcileGeneration == generation {
			daemon.reconcileState.LastError = err.Error()
		}
		return
	}
	if daemon.reconcileGeneration == generation {
		daemon.reconcileState.Pending = false
		daemon.reconcileState.Reason = ""
		daemon.reconcileState.LastError = ""
		daemon.reconcileState.LastSuccessAt = now
	}
}

func (daemon *Daemon) reconcileRuntimeState(ctx context.Context) error {
	daemon.configMu.Lock()
	defer daemon.configMu.Unlock()
	var headErr error
	if daemon.store == nil {
		headErr = errors.New("config log store is not initialized")
	} else if head, err := daemon.store.Head(); err != nil {
		headErr = err
	} else {
		daemon.head = head
	}
	_, trustErr := daemon.applyLatestDomainTrustFromLogLocked(ctx)
	admissionErr := daemon.afterAdmissionStateChangedLocked(ctx)
	_, endpointGrantErr := daemon.dropDataSessionsUnauthorizedByEndpointGrantPolicyAtLocked(time.Now().UTC())
	_, enforceErr := daemon.enforceRuntimeTrustState()
	_, revokedSessionErr := daemon.dropRevokedDeviceAccessSessions()
	membersPersistErr := daemon.persistMembers()
	if membersPersistErr == nil {
		daemon.clearBackgroundError("members_persist")
	}
	pendingPersistErr := daemon.persistPendingMembers()
	if pendingPersistErr == nil {
		daemon.clearBackgroundError("pending_members_persist")
	}
	dataplaneErr := daemon.applyRuntimeDataplaneSnapshot(ctx)
	if dataplaneErr == nil {
		daemon.clearBackgroundError("expired_member_session_close")
	}
	return errors.Join(
		wrapReconcileError("refresh config log head", headErr),
		wrapReconcileError("apply latest domain trust", trustErr),
		wrapReconcileError("reconcile admission state", admissionErr),
		wrapReconcileError("enforce endpoint grants", endpointGrantErr),
		wrapReconcileError("enforce trust state", enforceErr),
		wrapReconcileError("close revoked device sessions", revokedSessionErr),
		wrapReconcileError("persist members", membersPersistErr),
		wrapReconcileError("persist pending members", pendingPersistErr),
		wrapReconcileError("persist config signer cache", daemon.persistConfigSignerCache()),
		wrapReconcileError("apply dataplane snapshot", dataplaneErr),
		wrapReconcileError("refresh local advertisement", daemon.refreshLocalAdvertisement()),
	)
}

func wrapReconcileError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func (daemon *Daemon) reconcileRuntimeAfterSessionRemoval(ctx context.Context, reason string, refreshAdvertisement bool) error {
	var advertisementErr error
	dataplaneErr := daemon.applyRuntimeDataplaneSnapshot(ctx)
	if refreshAdvertisement && daemon.localAdvertisementConfigured() {
		advertisementErr = daemon.refreshLocalAdvertisement()
	}
	err := errors.Join(
		wrapReconcileError("apply dataplane snapshot", dataplaneErr),
		wrapReconcileError("refresh local advertisement", advertisementErr),
	)
	if err != nil {
		daemon.requestRuntimeReconcile(reason, err)
	}
	return err
}
