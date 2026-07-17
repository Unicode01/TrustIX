package daemon

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/configlog"
	"trustix.local/trustix/internal/dataplane"
)

func TestRuntimeReconcileRetriesFailedDataplaneRemoval(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, desired)
	manager := &failNthSnapshotManager{inner: dataplane.NewNoopManager(), failAt: 1}
	daemon.dataplane = manager

	err := daemon.reconcileRuntimeAfterSessionRemoval(context.Background(), "endpoint grant expiry", false)
	if err == nil {
		t.Fatal("initial dataplane reconciliation unexpectedly succeeded")
	}
	status := daemon.runtimeReconcileStatus()
	if !status.Pending || status.Reason != "endpoint grant expiry" || !strings.Contains(status.LastError, "injected snapshot failure") {
		t.Fatalf("pending reconcile status = %#v", status)
	}
	if check := daemon.runtimeReconcileDoctorCheck(); check.Status != "degraded" {
		t.Fatalf("pending reconcile doctor check = %#v", check)
	}

	callsBeforeRetry := manager.calls
	daemon.retryPendingRuntimeReconcile(context.Background())
	status = daemon.runtimeReconcileStatus()
	if status.Pending || status.LastError != "" || status.Attempts != 1 || status.LastSuccessAt.IsZero() {
		t.Fatalf("reconciled status = %#v", status)
	}
	if manager.calls <= callsBeforeRetry {
		t.Fatalf("snapshot calls = %d, want more than %d", manager.calls, callsBeforeRetry)
	}
	if check := daemon.runtimeReconcileDoctorCheck(); check.Status != "ok" {
		t.Fatalf("reconciled doctor check = %#v", check)
	}
}

func TestRuntimeReconcileRefreshesConfigLogHead(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemon := newConfigApplyTestDaemon(t, configApplyDesired(pkiSet, "10.0.1.0/24"))
	want, err := daemon.store.Head()
	if err != nil {
		t.Fatalf("read config log head: %v", err)
	}
	daemon.head = configlog.Head{}
	daemon.requestRuntimeReconcile("stale config log head", errors.New("injected stale head"))

	daemon.retryPendingRuntimeReconcile(context.Background())

	if daemon.head != want {
		t.Fatalf("config log head = %+v, want %+v", daemon.head, want)
	}
	if status := daemon.runtimeReconcileStatus(); status.Pending || status.LastError != "" {
		t.Fatalf("reconcile status = %#v", status)
	}
}

func TestRuntimeReconcileAppliesLatestDomainTrust(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemon := newConfigApplyTestDaemon(t, configApplyDesired(pkiSet, "10.0.1.0/24"))
	oldTrust := daemon.desired.Trust
	want := config.TrustConfig{RevokedCertFingerprints: []string{fingerprintForCertPath(t, pkiSet.ixCerts["ix-c"])}}
	body := mustJSON(t, want)
	request := httptest.NewRequest(http.MethodPost, "/v1/trust", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, request, body, pkiSet.adminCert, pkiSet.adminKey)
	proof, err := daemon.verifyAdminRequest(request, body)
	if err != nil {
		t.Fatalf("verify admin request: %v", err)
	}
	ctx := context.WithValue(context.Background(), adminProofContextKey{}, proof)
	if changed, err := daemon.applyTrustConfig(ctx, want); err != nil || !changed {
		t.Fatalf("append domain trust event changed=%t err=%v", changed, err)
	}
	daemon.desired.Trust = oldTrust
	daemon.requestRuntimeReconcile("stale domain trust", errors.New("injected stale trust"))

	daemon.retryPendingRuntimeReconcile(context.Background())

	if !trustConfigsEqual(daemon.desired.Trust, want) {
		t.Fatalf("runtime trust = %#v, want %#v", daemon.desired.Trust, want)
	}
	if status := daemon.runtimeReconcileStatus(); status.Pending || status.LastError != "" {
		t.Fatalf("reconcile status = %#v", status)
	}
}

func TestBackgroundErrorsAreObservableAndClearable(t *testing.T) {
	daemon := &Daemon{backgroundErrors: make(map[string]backgroundErrorStatus)}
	daemon.recordBackgroundError("watchdog", context.DeadlineExceeded)
	daemon.recordBackgroundError("watchdog", context.DeadlineExceeded)
	statuses := daemon.backgroundErrorSnapshot()
	if len(statuses) != 1 || statuses[0].Count != 2 || statuses[0].Operation != "watchdog" {
		t.Fatalf("background errors = %#v", statuses)
	}
	if check := daemon.backgroundErrorsDoctorCheck(); check.Status != "degraded" {
		t.Fatalf("background error doctor check = %#v", check)
	}
	daemon.clearBackgroundError("watchdog")
	if statuses := daemon.backgroundErrorSnapshot(); len(statuses) != 0 {
		t.Fatalf("cleared background errors = %#v", statuses)
	}
}

func TestRuntimeReconcileOldAttemptDoesNotOverwriteNewRequest(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemon := newConfigApplyTestDaemon(t, configApplyDesired(pkiSet, "10.0.1.0/24"))
	manager := &blockingSnapshotManager{
		Manager: dataplane.NewNoopManager(),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	daemon.dataplane = manager
	daemon.requestRuntimeReconcile("old request", errors.New("old request error"))
	done := make(chan struct{})
	go func() {
		defer close(done)
		daemon.retryPendingRuntimeReconcile(context.Background())
	}()
	<-manager.started
	daemon.requestRuntimeReconcile("new request", errors.New("new request error"))
	close(manager.release)
	<-done

	status := daemon.runtimeReconcileStatus()
	if !status.Pending || status.Reason != "new request" || status.LastError != "new request error" {
		t.Fatalf("reconcile status after overlapping request = %#v", status)
	}
}

type blockingSnapshotManager struct {
	dataplane.Manager
	started     chan struct{}
	release     chan struct{}
	startedOnce sync.Once
}

func (manager *blockingSnapshotManager) ApplySnapshot(context.Context, dataplane.Snapshot) error {
	manager.startedOnce.Do(func() {
		close(manager.started)
		<-manager.release
	})
	return errors.New("old attempt failed")
}
