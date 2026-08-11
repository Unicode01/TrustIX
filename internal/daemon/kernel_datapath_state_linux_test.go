//go:build linux

package daemon

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/kernelmodule"
	"trustix.local/trustix/internal/routing"
	"trustix.local/trustix/internal/transport"
)

func TestApplyKernelDatapathStateRecordsReturnsZeroProgressError(t *testing.T) {
	wantErr := errors.New("injected kernel state apply failure")
	original := kernelDatapathApplyStateBatch
	kernelDatapathApplyStateBatch = func(string, []kernelmodule.DatapathStateRecord) (uint32, []kernelmodule.DatapathStateRecord, error) {
		return 0, nil, wantErr
	}
	t.Cleanup(func() { kernelDatapathApplyStateBatch = original })

	err := (&Daemon{}).applyKernelDatapathStateRecords(context.Background(), []kernelmodule.DatapathStateRecord{{Kind: 1}})
	if !errors.Is(err, wantErr) {
		t.Fatalf("apply state error = %v, want %v", err, wantErr)
	}
}

func TestApplyKernelDatapathStateRecordsRetriesPartialProgress(t *testing.T) {
	wantErr := errors.New("injected partial kernel state apply failure")
	original := kernelDatapathApplyStateBatch
	calls := 0
	kernelDatapathApplyStateBatch = func(_ string, records []kernelmodule.DatapathStateRecord) (uint32, []kernelmodule.DatapathStateRecord, error) {
		calls++
		switch calls {
		case 1:
			if len(records) != 3 {
				t.Fatalf("first batch size = %d, want 3", len(records))
			}
			return 1, records[:1], wantErr
		case 2:
			if len(records) != 2 {
				t.Fatalf("retry batch size = %d, want 2", len(records))
			}
			return 2, records, nil
		default:
			t.Fatalf("unexpected apply call %d", calls)
			return 0, nil, nil
		}
	}
	t.Cleanup(func() { kernelDatapathApplyStateBatch = original })

	records := []kernelmodule.DatapathStateRecord{{Kind: 1}, {Kind: 2}, {Kind: 3}}
	if err := (&Daemon{}).applyKernelDatapathStateRecords(context.Background(), records); err != nil {
		t.Fatalf("apply state after partial progress: %v", err)
	}
	if calls != 2 {
		t.Fatalf("apply calls = %d, want 2", calls)
	}
}

func TestApplyKernelDatapathStateRecordsRejectsShortSuccess(t *testing.T) {
	original := kernelDatapathApplyStateBatch
	kernelDatapathApplyStateBatch = func(_ string, records []kernelmodule.DatapathStateRecord) (uint32, []kernelmodule.DatapathStateRecord, error) {
		return uint32(len(records) - 1), records[:len(records)-1], nil
	}
	t.Cleanup(func() { kernelDatapathApplyStateBatch = original })

	err := (&Daemon{}).applyKernelDatapathStateRecords(context.Background(), []kernelmodule.DatapathStateRecord{{Kind: 1}, {Kind: 2}})
	if err == nil {
		t.Fatal("short successful kernel state apply returned nil error")
	}
}

func TestPeriodicKernelDatapathStateSyncDoesNotClearHealthyTables(t *testing.T) {
	daemon := newKernelDatapathStateSyncTestDaemon(true)
	snapshot := dataplane.Snapshot{Routes: []routing.Route{kernelDatapathStateSyncTestRoute()}}
	originalStats := kernelDatapathStateStatsQuery
	originalApply := kernelDatapathApplyStateBatch
	kernelDatapathStateStatsQuery = func(string) (kernelmodule.DatapathStateStats, error) {
		return kernelmodule.DatapathStateStats{
			MaxRoutes: 16, Routes: 1,
			MaxSessions: 16, MaxFlows: 16, MaxSessionWires: 16,
		}, nil
	}
	var applied []kernelmodule.DatapathStateRecord
	kernelDatapathApplyStateBatch = func(_ string, records []kernelmodule.DatapathStateRecord) (uint32, []kernelmodule.DatapathStateRecord, error) {
		applied = append(applied, records...)
		return uint32(len(records)), records, nil
	}
	t.Cleanup(func() {
		kernelDatapathStateStatsQuery = originalStats
		kernelDatapathApplyStateBatch = originalApply
	})

	if err := daemon.syncKernelDatapathState(context.Background(), snapshot); err != nil {
		t.Fatalf("periodic state sync: %v", err)
	}
	if len(applied) != 1 || applied[0].Op != kernelmodule.TrustIXDatapathStateOpUpsert {
		t.Fatalf("healthy periodic sync records = %#v, want one route upsert and no clear", applied)
	}
}

func TestInitialKernelDatapathStateSyncClearsUnknownPersistedState(t *testing.T) {
	daemon := newKernelDatapathStateSyncTestDaemon(false)
	snapshot := dataplane.Snapshot{Routes: []routing.Route{kernelDatapathStateSyncTestRoute()}}
	originalStats := kernelDatapathStateStatsQuery
	originalApply := kernelDatapathApplyStateBatch
	kernelDatapathStateStatsQuery = func(string) (kernelmodule.DatapathStateStats, error) {
		return kernelmodule.DatapathStateStats{
			MaxRoutes: 16, Routes: 1,
			MaxSessions: 16, MaxFlows: 16, MaxSessionWires: 16,
		}, nil
	}
	var applied []kernelmodule.DatapathStateRecord
	kernelDatapathApplyStateBatch = func(_ string, records []kernelmodule.DatapathStateRecord) (uint32, []kernelmodule.DatapathStateRecord, error) {
		applied = append(applied, records...)
		return uint32(len(records)), records, nil
	}
	t.Cleanup(func() {
		kernelDatapathStateStatsQuery = originalStats
		kernelDatapathApplyStateBatch = originalApply
	})

	if err := daemon.syncKernelDatapathState(context.Background(), snapshot); err != nil {
		t.Fatalf("initial state sync: %v", err)
	}
	clearSeen := false
	for _, record := range applied {
		clearSeen = clearSeen || record.Op == kernelmodule.TrustIXDatapathStateOpClear
	}
	if !clearSeen || !daemon.kernelDatapathStateInitialized {
		t.Fatalf("initial sync records=%#v initialized=%t, want clear and initialized state", applied, daemon.kernelDatapathStateInitialized)
	}
}

func TestPeriodicKernelDatapathStateSyncKeepsAllLargeBatchesNonDestructive(t *testing.T) {
	const routeCount = 5000
	daemon := newKernelDatapathStateSyncTestDaemon(true)
	routes := make([]routing.Route, 0, routeCount)
	for i := 0; i < routeCount; i++ {
		addr := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		routes = append(routes, routing.Route{
			Prefix:   core.Prefix(addr.String() + "/32"),
			Owner:    "ix-b",
			NextHop:  "ix-b",
			Endpoint: "wan-tix-tcp",
			Kind:     routing.RouteUnicast,
		})
	}
	originalStats := kernelDatapathStateStatsQuery
	originalApply := kernelDatapathApplyStateBatch
	kernelDatapathStateStatsQuery = func(string) (kernelmodule.DatapathStateStats, error) {
		return kernelmodule.DatapathStateStats{
			MaxRoutes: 8192, Routes: routeCount,
			MaxSessions: 16, MaxFlows: 16, MaxSessionWires: 16,
		}, nil
	}
	applyCalls := 0
	applied := 0
	kernelDatapathApplyStateBatch = func(_ string, records []kernelmodule.DatapathStateRecord) (uint32, []kernelmodule.DatapathStateRecord, error) {
		applyCalls++
		applied += len(records)
		for _, record := range records {
			if record.Op == kernelmodule.TrustIXDatapathStateOpClear {
				t.Fatalf("large periodic batch %d contains destructive clear", applyCalls)
			}
		}
		return uint32(len(records)), records, nil
	}
	t.Cleanup(func() {
		kernelDatapathStateStatsQuery = originalStats
		kernelDatapathApplyStateBatch = originalApply
	})

	if err := daemon.syncKernelDatapathState(context.Background(), dataplane.Snapshot{Routes: routes}); err != nil {
		t.Fatalf("large periodic state sync: %v", err)
	}
	if applyCalls != 2 || applied != routeCount {
		t.Fatalf("large periodic sync apply calls=%d records=%d, want 2 and %d", applyCalls, applied, routeCount)
	}
}

func TestPeriodicKernelDatapathStateSyncRepairsCountMismatchBeforeReset(t *testing.T) {
	daemon := newKernelDatapathStateSyncTestDaemon(true)
	snapshot := dataplane.Snapshot{Routes: []routing.Route{kernelDatapathStateSyncTestRoute()}}
	originalStats := kernelDatapathStateStatsQuery
	originalApply := kernelDatapathApplyStateBatch
	statsCalls := 0
	kernelDatapathStateStatsQuery = func(string) (kernelmodule.DatapathStateStats, error) {
		statsCalls++
		routes := uint32(0)
		if statsCalls > 1 {
			routes = 1
		}
		return kernelmodule.DatapathStateStats{
			MaxRoutes: 16, Routes: routes,
			MaxSessions: 16, MaxFlows: 16, MaxSessionWires: 16,
		}, nil
	}
	var calls [][]kernelmodule.DatapathStateRecord
	kernelDatapathApplyStateBatch = func(_ string, records []kernelmodule.DatapathStateRecord) (uint32, []kernelmodule.DatapathStateRecord, error) {
		calls = append(calls, append([]kernelmodule.DatapathStateRecord(nil), records...))
		return uint32(len(records)), records, nil
	}
	t.Cleanup(func() {
		kernelDatapathStateStatsQuery = originalStats
		kernelDatapathApplyStateBatch = originalApply
	})

	if err := daemon.syncKernelDatapathState(context.Background(), snapshot); err != nil {
		t.Fatalf("repair state sync: %v", err)
	}
	if statsCalls != 2 || len(calls) != 1 {
		t.Fatalf("repair stats calls=%d apply calls=%d, want 2 and 1", statsCalls, len(calls))
	}
	for _, record := range calls[0] {
		if record.Op == kernelmodule.TrustIXDatapathStateOpClear {
			t.Fatalf("non-destructive repair unexpectedly cleared state: %#v", calls[0])
		}
	}
}

func TestPeriodicKernelDatapathStateSyncResetsPersistentCountMismatch(t *testing.T) {
	daemon := newKernelDatapathStateSyncTestDaemon(true)
	snapshot := dataplane.Snapshot{Routes: []routing.Route{kernelDatapathStateSyncTestRoute()}}
	originalStats := kernelDatapathStateStatsQuery
	originalApply := kernelDatapathApplyStateBatch
	kernelDatapathStateStatsQuery = func(string) (kernelmodule.DatapathStateStats, error) {
		return kernelmodule.DatapathStateStats{
			MaxRoutes: 16, Routes: 2,
			MaxSessions: 16, MaxFlows: 16, MaxSessionWires: 16,
		}, nil
	}
	var calls [][]kernelmodule.DatapathStateRecord
	kernelDatapathApplyStateBatch = func(_ string, records []kernelmodule.DatapathStateRecord) (uint32, []kernelmodule.DatapathStateRecord, error) {
		calls = append(calls, append([]kernelmodule.DatapathStateRecord(nil), records...))
		return uint32(len(records)), records, nil
	}
	t.Cleanup(func() {
		kernelDatapathStateStatsQuery = originalStats
		kernelDatapathApplyStateBatch = originalApply
	})

	if err := daemon.syncKernelDatapathState(context.Background(), snapshot); err != nil {
		t.Fatalf("persistent mismatch state sync: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("persistent mismatch apply calls = %d, want repair then reset", len(calls))
	}
	for _, record := range calls[0] {
		if record.Op == kernelmodule.TrustIXDatapathStateOpClear {
			t.Fatalf("first repair pass cleared state: %#v", calls[0])
		}
	}
	clearSeen := false
	for _, record := range calls[1] {
		clearSeen = clearSeen || record.Op == kernelmodule.TrustIXDatapathStateOpClear
	}
	if !clearSeen {
		t.Fatalf("persistent mismatch reset is missing clear records: %#v", calls[1])
	}
}

func TestPeriodicKernelDatapathStateSyncDoesNotClearAfterRepairFailure(t *testing.T) {
	daemon := newKernelDatapathStateSyncTestDaemon(true)
	snapshot := dataplane.Snapshot{Routes: []routing.Route{kernelDatapathStateSyncTestRoute()}}
	wantErr := errors.New("injected non-destructive repair failure")
	originalStats := kernelDatapathStateStatsQuery
	originalApply := kernelDatapathApplyStateBatch
	kernelDatapathStateStatsQuery = func(string) (kernelmodule.DatapathStateStats, error) {
		return kernelmodule.DatapathStateStats{
			MaxRoutes: 16, Routes: 2,
			MaxSessions: 16, MaxFlows: 16, MaxSessionWires: 16,
		}, nil
	}
	var calls [][]kernelmodule.DatapathStateRecord
	kernelDatapathApplyStateBatch = func(_ string, records []kernelmodule.DatapathStateRecord) (uint32, []kernelmodule.DatapathStateRecord, error) {
		calls = append(calls, append([]kernelmodule.DatapathStateRecord(nil), records...))
		return 0, nil, wantErr
	}
	t.Cleanup(func() {
		kernelDatapathStateStatsQuery = originalStats
		kernelDatapathApplyStateBatch = originalApply
	})

	err := daemon.syncKernelDatapathState(context.Background(), snapshot)
	if !errors.Is(err, wantErr) {
		t.Fatalf("repair failure = %v, want %v", err, wantErr)
	}
	if len(calls) != 1 {
		t.Fatalf("repair failure apply calls = %d, want 1", len(calls))
	}
	for _, record := range calls[0] {
		if record.Op == kernelmodule.TrustIXDatapathStateOpClear {
			t.Fatalf("failed non-destructive repair cleared live state: %#v", calls[0])
		}
	}
}

func newKernelDatapathStateSyncTestDaemon(initialized bool) *Daemon {
	manager := kernelmodule.NewTrustIXDatapathManager()
	manager.SetStatusForTest(kernelmodule.Status{Name: "trustix_datapath", Loaded: true, State: "loaded"})
	return &Daemon{
		kernelDatapath:                 manager,
		kernelDatapathStateInitialized: initialized,
	}
}

func kernelDatapathStateSyncTestRoute() routing.Route {
	return routing.Route{
		Prefix:   core.Prefix("10.82.0.0/24"),
		Owner:    "ix-b",
		NextHop:  "ix-b",
		Endpoint: "wan-tix-tcp",
		Policy:   "fast",
		Kind:     routing.RouteUnicast,
	}
}

func TestSyncKernelDatapathSessionUpsertCommitsEpochZeroCryptoAfterApply(t *testing.T) {
	daemon, manager, key, session := newKernelDatapathCryptoLifecycleFixture()
	original := kernelDatapathApplyStateBatch
	appliedCrypto := false
	kernelDatapathApplyStateBatch = func(_ string, records []kernelmodule.DatapathStateRecord) (uint32, []kernelmodule.DatapathStateRecord, error) {
		for _, record := range records {
			if record.Kind == kernelmodule.TrustIXDatapathStateKindSessionCrypto && record.Op == kernelmodule.TrustIXDatapathStateOpUpsert {
				appliedCrypto = true
			}
		}
		return uint32(len(records)), records, nil
	}
	t.Cleanup(func() { kernelDatapathApplyStateBatch = original })

	daemon.syncKernelDatapathSessionRecords(key, nil, session)
	if !appliedCrypto {
		t.Fatal("session upsert did not apply a crypto state record")
	}
	if len(manager.commitCalls) != 1 || manager.commitCalls[0] != [2]uint64{manager.state.FlowID, manager.state.Send.Epoch} {
		t.Fatalf("crypto commit calls = %v, want flow %d epoch %d", manager.commitCalls, manager.state.FlowID, manager.state.Send.Epoch)
	}
}

func TestSyncKernelDatapathSessionUpsertDoesNotCommitCryptoAfterApplyFailure(t *testing.T) {
	daemon, manager, key, session := newKernelDatapathCryptoLifecycleFixture()
	wantErr := errors.New("injected session upsert failure")
	original := kernelDatapathApplyStateBatch
	kernelDatapathApplyStateBatch = func(_ string, _ []kernelmodule.DatapathStateRecord) (uint32, []kernelmodule.DatapathStateRecord, error) {
		return 0, nil, wantErr
	}
	t.Cleanup(func() { kernelDatapathApplyStateBatch = original })

	daemon.syncKernelDatapathSessionRecords(key, nil, session)
	if len(manager.commitCalls) != 0 {
		t.Fatalf("crypto committed before failed state apply: %v", manager.commitCalls)
	}
	if status := daemon.runtimeReconcileStatus(); !status.Pending || status.LastError == "" {
		t.Fatalf("failed state apply did not request reconciliation: %+v", status)
	}
}

func TestKernelDatapathSessionReadinessWaitsForStateCommit(t *testing.T) {
	manager := kernelmodule.NewTrustIXDatapathManager()
	manager.SetStatusForTest(kernelmodule.Status{Name: "trustix_datapath", Loaded: true, State: "loaded"})
	key := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "wan-tix-tcp",
		Transport:  transport.ProtocolTIXTCP,
		Address:    "198.51.100.2:17042",
		Encryption: "plaintext",
	}
	session := &kernelDatapathReadyTestSession{
		info: transport.KernelDatapathSessionInfo{
			FlowID:        7,
			Protocol:      transport.ProtocolTIXTCP,
			Peer:          key.Peer,
			Endpoint:      key.Endpoint,
			LocalAddress:  "192.0.2.1:17041",
			RemoteAddress: "198.51.100.2:17042",
		},
		ready: make(chan struct{}),
	}
	runtime := &dataSessionRuntime{key: key, session: session}
	daemon := &Daemon{
		kernelDatapath:   manager,
		dataSessions:     map[dataSessionKey]transport.Session{key: session},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{key: runtime},
	}

	applyEntered := make(chan struct{})
	releaseApply := make(chan struct{})
	original := kernelDatapathApplyStateBatch
	var enterOnce sync.Once
	kernelDatapathApplyStateBatch = func(_ string, records []kernelmodule.DatapathStateRecord) (uint32, []kernelmodule.DatapathStateRecord, error) {
		enterOnce.Do(func() { close(applyEntered) })
		<-releaseApply
		return uint32(len(records)), records, nil
	}
	t.Cleanup(func() { kernelDatapathApplyStateBatch = original })

	done := make(chan struct{})
	go func() {
		daemon.syncKernelDatapathSessionUpsert(key, runtime, session)
		close(done)
	}()
	select {
	case <-applyEntered:
	case <-time.After(time.Second):
		t.Fatal("kernel state apply did not start")
	}
	select {
	case <-session.ready:
		t.Fatal("session readiness was advertised before the kernel state commit completed")
	default:
	}
	close(releaseApply)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("session upsert did not complete")
	}
	select {
	case <-session.ready:
	case <-time.After(time.Second):
		t.Fatal("session readiness was not advertised after the kernel state commit")
	}
}

func TestKernelDatapathSessionReadinessIsWithheldAfterStateFailure(t *testing.T) {
	manager := kernelmodule.NewTrustIXDatapathManager()
	manager.SetStatusForTest(kernelmodule.Status{Name: "trustix_datapath", Loaded: true, State: "loaded"})
	key := dataSessionKey{Peer: "ix-b", Endpoint: "wan-tix-tcp", Transport: transport.ProtocolTIXTCP}
	session := &kernelDatapathReadyTestSession{
		info:  transport.KernelDatapathSessionInfo{FlowID: 7, Protocol: transport.ProtocolTIXTCP},
		ready: make(chan struct{}),
	}
	runtime := &dataSessionRuntime{key: key, session: session}
	daemon := &Daemon{
		kernelDatapath:   manager,
		dataSessions:     map[dataSessionKey]transport.Session{key: session},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{key: runtime},
	}
	original := kernelDatapathApplyStateBatch
	kernelDatapathApplyStateBatch = func(_ string, _ []kernelmodule.DatapathStateRecord) (uint32, []kernelmodule.DatapathStateRecord, error) {
		return 0, nil, errors.New("injected readiness state failure")
	}
	t.Cleanup(func() { kernelDatapathApplyStateBatch = original })

	daemon.syncKernelDatapathSessionUpsert(key, runtime, session)
	select {
	case <-session.ready:
		t.Fatal("session readiness was advertised after a failed kernel state commit")
	default:
	}
}

func TestSyncKernelDatapathSessionDeleteReleasesCryptoAfterApply(t *testing.T) {
	daemon, manager, key, session := newKernelDatapathCryptoLifecycleFixture()
	original := kernelDatapathApplyStateBatch
	appliedCryptoDelete := false
	kernelDatapathApplyStateBatch = func(_ string, records []kernelmodule.DatapathStateRecord) (uint32, []kernelmodule.DatapathStateRecord, error) {
		for _, record := range records {
			if record.Kind == kernelmodule.TrustIXDatapathStateKindSessionCrypto && record.Op == kernelmodule.TrustIXDatapathStateOpDelete {
				appliedCryptoDelete = true
			}
		}
		return uint32(len(records)), records, nil
	}
	t.Cleanup(func() { kernelDatapathApplyStateBatch = original })

	delete(daemon.dataSessions, key)
	daemon.syncKernelDatapathSessionDelete(key, session)
	if !appliedCryptoDelete {
		t.Fatal("session delete did not apply a crypto state delete record")
	}
	if len(manager.releaseCalls) != 1 || manager.releaseCalls[0] != manager.state.FlowID {
		t.Fatalf("crypto release calls = %v, want flow %d", manager.releaseCalls, manager.state.FlowID)
	}
}

func TestSyncKernelDatapathSessionDeleteRetainingFlowKeepsCryptoAfterApply(t *testing.T) {
	daemon, manager, key, session := newKernelDatapathCryptoLifecycleFixture()
	original := kernelDatapathApplyStateBatch
	appliedCryptoDelete := false
	kernelDatapathApplyStateBatch = func(_ string, records []kernelmodule.DatapathStateRecord) (uint32, []kernelmodule.DatapathStateRecord, error) {
		for _, record := range records {
			if record.Kind == kernelmodule.TrustIXDatapathStateKindSessionCrypto && record.Op == kernelmodule.TrustIXDatapathStateOpDelete {
				appliedCryptoDelete = true
			}
		}
		return uint32(len(records)), records, nil
	}
	t.Cleanup(func() { kernelDatapathApplyStateBatch = original })

	delete(daemon.dataSessions, key)
	daemon.syncKernelDatapathSessionDeleteRetainingFlow(key, session)
	if !appliedCryptoDelete {
		t.Fatal("retained session delete did not remove the old keyed crypto record")
	}
	if len(manager.releaseCalls) != 0 {
		t.Fatalf("retained session delete released the transferred crypto flow: %v", manager.releaseCalls)
	}
}

func TestDropSessionsForPeerTransportDeletesKernelStateAndReleasesCrypto(t *testing.T) {
	daemon, manager, key, _ := newKernelDatapathCryptoLifecycleFixture()
	original := kernelDatapathApplyStateBatch
	deleteKinds := make(map[uint32]bool)
	kernelDatapathApplyStateBatch = func(_ string, records []kernelmodule.DatapathStateRecord) (uint32, []kernelmodule.DatapathStateRecord, error) {
		for _, record := range records {
			if record.Op == kernelmodule.TrustIXDatapathStateOpDelete {
				deleteKinds[record.Kind] = true
			}
		}
		return uint32(len(records)), records, nil
	}
	t.Cleanup(func() { kernelDatapathApplyStateBatch = original })

	if dropped := daemon.dropSessionsForPeerTransport(key.Peer, key.Transport); dropped != 1 {
		t.Fatalf("dropped peer transport sessions = %d, want 1", dropped)
	}
	if _, ok := daemon.dataSessions[key]; ok {
		t.Fatal("dropped peer transport session remains in the daemon session map")
	}
	for _, kind := range []uint32{
		kernelmodule.TrustIXDatapathStateKindSession,
		kernelmodule.TrustIXDatapathStateKindSessionWire,
		kernelmodule.TrustIXDatapathStateKindSessionCrypto,
	} {
		if !deleteKinds[kind] {
			t.Fatalf("peer transport cleanup is missing kernel delete kind %d", kind)
		}
	}
	if len(manager.releaseCalls) != 1 || manager.releaseCalls[0] != manager.state.FlowID {
		t.Fatalf("peer transport cleanup crypto releases = %v, want flow %d", manager.releaseCalls, manager.state.FlowID)
	}
}

func TestSyncKernelDatapathSessionDeleteDoesNotReleaseCryptoAfterApplyFailure(t *testing.T) {
	daemon, manager, key, session := newKernelDatapathCryptoLifecycleFixture()
	wantErr := errors.New("injected session delete failure")
	original := kernelDatapathApplyStateBatch
	kernelDatapathApplyStateBatch = func(_ string, _ []kernelmodule.DatapathStateRecord) (uint32, []kernelmodule.DatapathStateRecord, error) {
		return 0, nil, wantErr
	}
	t.Cleanup(func() { kernelDatapathApplyStateBatch = original })

	delete(daemon.dataSessions, key)
	daemon.syncKernelDatapathSessionDelete(key, session)
	if len(manager.releaseCalls) != 0 {
		t.Fatalf("crypto released before failed state delete: %v", manager.releaseCalls)
	}
	if status := daemon.runtimeReconcileStatus(); !status.Pending || status.LastError == "" {
		t.Fatalf("failed state delete did not request reconciliation: %+v", status)
	}
}

func TestKernelDatapathStateSyncSerializesConcurrentSessionDeleteAfterStaleSnapshot(t *testing.T) {
	daemon, manager, key, session := newKernelDatapathCryptoLifecycleFixture()
	originalStats := kernelDatapathStateStatsQuery
	originalApply := kernelDatapathApplyStateBatch
	kernelDatapathStateStatsQuery = func(string) (kernelmodule.DatapathStateStats, error) {
		return kernelmodule.DatapathStateStats{MaxRoutes: 16, MaxSessions: 16, MaxFlows: 16}, nil
	}
	firstApplyStarted := make(chan struct{})
	allowFirstApply := make(chan struct{})
	var calls [][]kernelmodule.DatapathStateRecord
	kernelDatapathApplyStateBatch = func(_ string, records []kernelmodule.DatapathStateRecord) (uint32, []kernelmodule.DatapathStateRecord, error) {
		calls = append(calls, append([]kernelmodule.DatapathStateRecord(nil), records...))
		if len(calls) == 1 {
			close(firstApplyStarted)
			<-allowFirstApply
		}
		return uint32(len(records)), records, nil
	}
	t.Cleanup(func() {
		kernelDatapathStateStatsQuery = originalStats
		kernelDatapathApplyStateBatch = originalApply
	})

	fullSyncDone := make(chan error, 1)
	go func() {
		fullSyncDone <- daemon.syncKernelDatapathState(context.Background(), dataplane.Snapshot{})
	}()
	select {
	case <-firstApplyStarted:
	case <-time.After(time.Second):
		t.Fatal("full state sync did not reach the blocked apply")
	}

	daemon.dataMu.Lock()
	delete(daemon.dataSessions, key)
	delete(daemon.dataSessionState, key)
	daemon.dataMu.Unlock()
	deleteDone := make(chan struct{})
	go func() {
		daemon.syncKernelDatapathSessionDelete(key, session)
		close(deleteDone)
	}()
	select {
	case <-deleteDone:
		t.Fatal("session delete bypassed the in-progress full state sync")
	case <-time.After(100 * time.Millisecond):
	}

	close(allowFirstApply)
	if err := <-fullSyncDone; err != nil {
		t.Fatalf("full state sync: %v", err)
	}
	select {
	case <-deleteDone:
	case <-time.After(time.Second):
		t.Fatal("session delete did not run after the full state sync completed")
	}
	if len(calls) != 2 {
		t.Fatalf("kernel state apply calls = %d, want full sync then delete", len(calls))
	}
	deleteKinds := make(map[uint32]bool)
	for _, record := range calls[1] {
		if record.Op == kernelmodule.TrustIXDatapathStateOpDelete {
			deleteKinds[record.Kind] = true
		}
	}
	for _, kind := range []uint32{
		kernelmodule.TrustIXDatapathStateKindSession,
		kernelmodule.TrustIXDatapathStateKindSessionWire,
		kernelmodule.TrustIXDatapathStateKindSessionCrypto,
	} {
		if !deleteKinds[kind] {
			t.Fatalf("final serialized apply is missing delete kind %d: %#v", kind, calls[1])
		}
	}
	if len(manager.releaseCalls) != 1 || manager.releaseCalls[0] != manager.state.FlowID {
		t.Fatalf("serialized delete crypto releases = %v, want flow %d", manager.releaseCalls, manager.state.FlowID)
	}
}

func TestKernelDatapathSessionUpsertSkipsSessionRemovedWhileWaitingForStateLock(t *testing.T) {
	daemon, manager, key, session := newKernelDatapathCryptoLifecycleFixture()
	originalApply := kernelDatapathApplyStateBatch
	applyCalls := 0
	kernelDatapathApplyStateBatch = func(_ string, records []kernelmodule.DatapathStateRecord) (uint32, []kernelmodule.DatapathStateRecord, error) {
		applyCalls++
		return uint32(len(records)), records, nil
	}
	t.Cleanup(func() { kernelDatapathApplyStateBatch = originalApply })

	daemon.kernelDatapathStateMu.Lock()
	done := make(chan struct{})
	go func() {
		daemon.syncKernelDatapathSessionRecords(key, nil, session)
		close(done)
	}()
	daemon.dataMu.Lock()
	delete(daemon.dataSessions, key)
	delete(daemon.dataSessionState, key)
	daemon.dataMu.Unlock()
	daemon.kernelDatapathStateMu.Unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stale session upsert did not return")
	}
	if applyCalls != 0 {
		t.Fatalf("stale session upsert applied %d kernel batches, want 0", applyCalls)
	}
	if len(manager.commitCalls) != 0 {
		t.Fatalf("stale session upsert committed crypto state: %v", manager.commitCalls)
	}
}

func TestKernelDatapathSessionDeleteConvergesReplacementBeforeReleasingOldCrypto(t *testing.T) {
	daemon, manager, key, oldSession := newKernelDatapathCryptoLifecycleFixture()
	replacementInfo := oldSession.(kernelDatapathTestSession).info
	replacementInfo.FlowID++
	replacement := kernelDatapathTestSession{info: replacementInfo}
	daemon.dataSessions[key] = replacement

	originalApply := kernelDatapathApplyStateBatch
	var applied []kernelmodule.DatapathStateRecord
	kernelDatapathApplyStateBatch = func(_ string, records []kernelmodule.DatapathStateRecord) (uint32, []kernelmodule.DatapathStateRecord, error) {
		applied = append(applied, records...)
		return uint32(len(records)), records, nil
	}
	t.Cleanup(func() { kernelDatapathApplyStateBatch = originalApply })

	daemon.syncKernelDatapathSessionDelete(key, oldSession)
	deleteSeen := false
	replacementSeen := false
	for _, record := range applied {
		if record.Kind != kernelmodule.TrustIXDatapathStateKindSession {
			continue
		}
		deleteSeen = deleteSeen || record.Op == kernelmodule.TrustIXDatapathStateOpDelete
		replacementSeen = replacementSeen || record.Op == kernelmodule.TrustIXDatapathStateOpUpsert && record.Value[0] == replacementInfo.FlowID
	}
	if !deleteSeen || !replacementSeen {
		t.Fatalf("replacement convergence records = %#v, want old delete followed by replacement upsert", applied)
	}
	if len(manager.releaseCalls) != 1 || manager.releaseCalls[0] != manager.state.FlowID {
		t.Fatalf("replaced session crypto releases = %v, want old flow %d", manager.releaseCalls, manager.state.FlowID)
	}
}

func TestKernelDatapathSessionReplacementApplyFailureRetainsOldCrypto(t *testing.T) {
	daemon, manager, key, oldSession := newKernelDatapathCryptoLifecycleFixture()
	replacementInfo := oldSession.(kernelDatapathTestSession).info
	replacementInfo.FlowID++
	daemon.dataSessions[key] = kernelDatapathTestSession{info: replacementInfo}
	wantErr := errors.New("injected replacement convergence failure")

	originalApply := kernelDatapathApplyStateBatch
	kernelDatapathApplyStateBatch = func(_ string, _ []kernelmodule.DatapathStateRecord) (uint32, []kernelmodule.DatapathStateRecord, error) {
		return 0, nil, wantErr
	}
	t.Cleanup(func() { kernelDatapathApplyStateBatch = originalApply })

	daemon.syncKernelDatapathSessionDelete(key, oldSession)
	if len(manager.releaseCalls) != 0 {
		t.Fatalf("replacement failure released old crypto before state convergence: %v", manager.releaseCalls)
	}
	if status := daemon.runtimeReconcileStatus(); !status.Pending || !strings.Contains(status.LastError, wantErr.Error()) {
		t.Fatalf("replacement failure reconcile status = %+v, want pending error %q", status, wantErr)
	}
}

func TestKernelDatapathFlowUpsertSkipsReleasedBinding(t *testing.T) {
	daemon, _, _, _ := newKernelDatapathCryptoLifecycleFixture()
	binding := routing.FlowBinding{
		Key: routing.FlowKey{
			SourceIP: netip.MustParseAddr("192.0.2.10"), DestinationIP: netip.MustParseAddr("198.51.100.10"),
			SourcePort: 12345, DestinationPort: 443, Protocol: 6,
		},
		NextHop: "ix-b", Endpoint: "wan-tix-tcp", LastSeen: time.Now(), ExpiresAt: time.Now().Add(time.Minute),
	}
	daemon.flows = map[routing.FlowKey]routing.FlowBinding{}

	originalApply := kernelDatapathApplyStateBatch
	applyCalls := 0
	kernelDatapathApplyStateBatch = func(_ string, records []kernelmodule.DatapathStateRecord) (uint32, []kernelmodule.DatapathStateRecord, error) {
		applyCalls++
		return uint32(len(records)), records, nil
	}
	t.Cleanup(func() { kernelDatapathApplyStateBatch = originalApply })

	daemon.syncKernelDatapathFlowUpsert(binding)
	if applyCalls != 0 {
		t.Fatalf("stale flow upsert applied %d kernel batches, want 0", applyCalls)
	}
}

func TestKernelDatapathFlowDeleteConvergesReplacementAtSameKey(t *testing.T) {
	daemon, _, _, _ := newKernelDatapathCryptoLifecycleFixture()
	key := routing.FlowKey{
		SourceIP: netip.MustParseAddr("192.0.2.10"), DestinationIP: netip.MustParseAddr("198.51.100.10"),
		SourcePort: 12345, DestinationPort: 443, Protocol: 6,
	}
	daemon.flows = map[routing.FlowKey]routing.FlowBinding{
		key: {Key: key, NextHop: "ix-b", Endpoint: "replacement", LastSeen: time.Now(), ExpiresAt: time.Now().Add(time.Minute)},
	}

	originalApply := kernelDatapathApplyStateBatch
	var applied []kernelmodule.DatapathStateRecord
	kernelDatapathApplyStateBatch = func(_ string, records []kernelmodule.DatapathStateRecord) (uint32, []kernelmodule.DatapathStateRecord, error) {
		applied = append(applied, records...)
		return uint32(len(records)), records, nil
	}
	t.Cleanup(func() { kernelDatapathApplyStateBatch = originalApply })

	daemon.syncKernelDatapathFlowDelete(key)
	if len(applied) != 1 || applied[0].Kind != kernelmodule.TrustIXDatapathStateKindFlow || applied[0].Op != kernelmodule.TrustIXDatapathStateOpUpsert {
		t.Fatalf("replacement flow convergence records = %#v, want one upsert", applied)
	}
}

func TestSyncKernelDatapathStateRetriesRetiredCryptoCleanup(t *testing.T) {
	daemon, manager, _, _ := newKernelDatapathCryptoLifecycleFixture()
	wantErr := errors.New("injected retired crypto cleanup failure")
	manager.releaseRetiredErrors = []error{wantErr, nil}
	originalStats := kernelDatapathStateStatsQuery
	originalApply := kernelDatapathApplyStateBatch
	kernelDatapathStateStatsQuery = func(string) (kernelmodule.DatapathStateStats, error) {
		return kernelmodule.DatapathStateStats{MaxRoutes: 16, MaxSessions: 16, MaxFlows: 16}, nil
	}
	kernelDatapathApplyStateBatch = func(_ string, records []kernelmodule.DatapathStateRecord) (uint32, []kernelmodule.DatapathStateRecord, error) {
		return uint32(len(records)), records, nil
	}
	t.Cleanup(func() {
		kernelDatapathStateStatsQuery = originalStats
		kernelDatapathApplyStateBatch = originalApply
	})

	if err := daemon.syncKernelDatapathState(context.Background(), dataplane.Snapshot{}); !errors.Is(err, wantErr) {
		t.Fatalf("first full sync error = %v, want %v", err, wantErr)
	}
	if err := daemon.syncKernelDatapathState(context.Background(), dataplane.Snapshot{}); err != nil {
		t.Fatalf("retry full sync: %v", err)
	}
	if manager.releaseRetiredCalls != 2 {
		t.Fatalf("retired crypto cleanup calls = %d, want 2", manager.releaseRetiredCalls)
	}
}

func TestKernelDatapathRouteRecordEncodesIPv4Prefix(t *testing.T) {
	route := routing.Route{
		Prefix:   core.Prefix("10.82.0.0/24"),
		Owner:    "ix-b",
		NextHop:  "ix-c",
		Endpoint: "wan-tcp",
		Metric:   100,
		Policy:   "fast",
		Kind:     routing.RouteUnicast,
		Source:   "dynamic",
	}
	record, ok := kernelDatapathRouteRecord(route)
	if !ok {
		t.Fatal("route record was not encoded")
	}
	addr := netip.MustParseAddr("10.82.0.0").As4()
	if record.Kind != kernelmodule.TrustIXDatapathStateKindRoute ||
		record.Op != kernelmodule.TrustIXDatapathStateOpUpsert ||
		record.Flags != 1 ||
		record.Key[0] != uint64(binary.BigEndian.Uint32(addr[:])) ||
		record.Key[1] != 24 ||
		record.Key[2] == 0 ||
		record.Key[3] == 0 ||
		record.Value[0] != 100 ||
		record.Value[1] == 0 ||
		record.Value[2] == 0 ||
		record.Value[3] == 0 {
		t.Fatalf("unexpected route record: %#v", record)
	}
}

func TestKernelDatapathRouteRecordSkipsIPv6ForNow(t *testing.T) {
	_, ok := kernelDatapathRouteRecord(routing.Route{Prefix: core.Prefix("fd00::/64"), NextHop: "ix-b"})
	if ok {
		t.Fatal("IPv6 route should be skipped until the first full datapath ABI defines IPv6 keys")
	}
}

func TestKernelDatapathSessionRecordEncodesKernelFlow(t *testing.T) {
	key := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "wan-udp",
		Transport:  transport.ProtocolTIXTCP,
		Address:    "198.51.100.2:9000",
		Encryption: "secure",
		PoolIndex:  2,
	}
	runtime := &dataSessionRuntime{
		key:         key,
		peer:        config.PeerConfig{ID: "ix-b"},
		endpoint:    config.EndpointConfig{Name: "wan-udp"},
		controlOnly: true,
	}
	runtime.lastRX.Store(100)
	runtime.lastTX.Store(200)
	session := kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
		FlowID:                                  0x1020304050607080,
		Protocol:                                transport.ProtocolTIXTCP,
		Peer:                                    "ix-b",
		Endpoint:                                "wan-udp",
		LocalAddress:                            "192.0.2.1:51820",
		RemoteAddress:                           "198.51.100.2:17041",
		Epoch:                                   7,
		CryptoSuite:                             "AES-128-GCM-X25519",
		CryptoPlacement:                         "kernel",
		Encrypted:                               true,
		SendEncrypted:                           true,
		ReceiveEncrypted:                        true,
		NativeBatching:                          true,
		Datagram:                                true,
		FragmentingDatagram:                     true,
		MaxPacketSize:                           64000,
		InnerTCPChecksumPartialLocal:            true,
		InnerTCPChecksumPartialPeer:             true,
		InnerTCPChecksumPartialNegotiated:       true,
		SecureInnerTCPChecksumPartialLocal:      true,
		SecureInnerTCPChecksumPartialPeer:       true,
		SecureInnerTCPChecksumPartialNegotiated: true,
		InnerGSOLocal:                           true,
		InnerGSOPeer:                            true,
		InnerGSONegotiated:                      true,
		TIXTCPPortShardingLocal:                 true,
		TIXTCPPortShardingPeer:                  true,
		TIXTCPPortShardingNegotiated:            true,
	}}
	record, ok := kernelDatapathSessionRecord(key, runtime, session)
	if !ok {
		t.Fatal("session record was not encoded")
	}
	if record.Kind != kernelmodule.TrustIXDatapathStateKindSession ||
		record.Op != kernelmodule.TrustIXDatapathStateOpUpsert ||
		record.Key != kernelDatapathSessionStateKey(key) ||
		record.Value[0] != 0x1020304050607080 ||
		record.Value[1] != uint64(kernelDatapathTransportCode(transport.ProtocolTIXTCP)) ||
		record.Value[2] != 7 ||
		record.Value[3] == 0 ||
		record.Value[4] != 1 ||
		record.Value[5] != 100 ||
		record.Value[6] != 200 ||
		record.Value[7] != 2 {
		t.Fatalf("unexpected session record: %#v", record)
	}
	for _, flag := range []uint32{
		kernelDatapathSessionFlagControlOnly,
		kernelDatapathSessionFlagKernelFlow,
		kernelDatapathSessionFlagEncrypted,
		kernelDatapathSessionFlagSendEncrypted,
		kernelDatapathSessionFlagReceiveEncrypted,
		kernelDatapathSessionFlagCryptoKernel,
		kernelDatapathSessionFlagNativeBatching,
		kernelDatapathSessionFlagDatagram,
		kernelDatapathSessionFlagFragmentingDatagram,
		kernelDatapathSessionFlagSendSecureInnerTCPChecksumPartial,
		kernelDatapathSessionFlagReceiveSecureInnerTCPChecksumPartial,
		kernelDatapathSessionFlagSendTIXTCPPortSharding,
		kernelDatapathSessionFlagReceiveTIXTCPPortSharding,
	} {
		if record.Flags&flag == 0 {
			t.Fatalf("session record missing flag %#x: %#v", flag, record)
		}
	}
	if forbidden := record.Flags & (kernelDatapathSessionFlagSendInnerTCPChecksumPartial |
		kernelDatapathSessionFlagReceiveInnerTCPChecksumPartial |
		kernelDatapathSessionFlagSendInnerGSO |
		kernelDatapathSessionFlagReceiveInnerGSO); forbidden != 0 {
		t.Fatalf("secure session record contains plaintext-only flags %#x: %#v", forbidden, record)
	}
}

func TestKernelDatapathSessionChecksumPartialFlagsAreDirectional(t *testing.T) {
	key := dataSessionKey{Transport: transport.ProtocolTIXTCP}
	info := transport.KernelDatapathSessionInfo{
		Protocol:                          transport.ProtocolTIXTCP,
		InnerTCPChecksumPartialLocal:      true,
		InnerTCPChecksumPartialPeer:       false,
		InnerTCPChecksumPartialNegotiated: false,
		InnerGSOLocal:                     true,
		InnerGSOPeer:                      false,
		InnerGSONegotiated:                false,
		TIXTCPPortShardingLocal:           true,
		TIXTCPPortShardingPeer:            false,
		TIXTCPPortShardingNegotiated:      false,
	}
	flags := kernelDatapathSessionFlags(key, nil, info)
	if flags&kernelDatapathSessionFlagReceiveInnerTCPChecksumPartial == 0 ||
		flags&kernelDatapathSessionFlagSendInnerTCPChecksumPartial != 0 ||
		flags&kernelDatapathSessionFlagReceiveInnerGSO == 0 ||
		flags&kernelDatapathSessionFlagSendInnerGSO != 0 ||
		flags&kernelDatapathSessionFlagReceiveTIXTCPPortSharding == 0 ||
		flags&kernelDatapathSessionFlagSendTIXTCPPortSharding != 0 {
		t.Fatalf("local-only flags = %#x, want receive-only inner optimizations", flags)
	}
	info.InnerTCPChecksumPartialLocal = false
	info.InnerTCPChecksumPartialPeer = true
	info.InnerGSOLocal = false
	info.InnerGSOPeer = true
	info.TIXTCPPortShardingLocal = false
	info.TIXTCPPortShardingPeer = true
	flags = kernelDatapathSessionFlags(key, nil, info)
	if flags&kernelDatapathSessionFlagReceiveInnerTCPChecksumPartial != 0 ||
		flags&kernelDatapathSessionFlagSendInnerTCPChecksumPartial == 0 ||
		flags&kernelDatapathSessionFlagReceiveInnerGSO != 0 ||
		flags&kernelDatapathSessionFlagSendInnerGSO == 0 ||
		flags&kernelDatapathSessionFlagReceiveTIXTCPPortSharding != 0 ||
		flags&kernelDatapathSessionFlagSendTIXTCPPortSharding == 0 {
		t.Fatalf("peer-only flags = %#x, want send-only inner optimizations", flags)
	}
	info.InnerTCPChecksumPartialLocal = true
	info.InnerTCPChecksumPartialPeer = true
	info.InnerTCPChecksumPartialNegotiated = true
	info.InnerGSOLocal = true
	info.InnerGSOPeer = true
	info.InnerGSONegotiated = true
	info.TIXTCPPortShardingLocal = true
	info.TIXTCPPortShardingPeer = true
	info.TIXTCPPortShardingNegotiated = true
	flags = kernelDatapathSessionFlags(key, nil, info)
	if flags&kernelDatapathSessionFlagReceiveInnerTCPChecksumPartial == 0 ||
		flags&kernelDatapathSessionFlagSendInnerTCPChecksumPartial == 0 ||
		flags&kernelDatapathSessionFlagReceiveInnerGSO == 0 ||
		flags&kernelDatapathSessionFlagSendInnerGSO == 0 ||
		flags&kernelDatapathSessionFlagReceiveTIXTCPPortSharding == 0 ||
		flags&kernelDatapathSessionFlagSendTIXTCPPortSharding == 0 {
		t.Fatalf("negotiated flags = %#x, want send+receive inner optimizations", flags)
	}
	info.Protocol = transport.ProtocolUDP
	key.Transport = transport.ProtocolUDP
	if flags = kernelDatapathSessionFlags(key, nil, info); flags&(kernelDatapathSessionFlagSendInnerTCPChecksumPartial|kernelDatapathSessionFlagReceiveInnerTCPChecksumPartial|kernelDatapathSessionFlagSendInnerGSO|kernelDatapathSessionFlagReceiveInnerGSO|kernelDatapathSessionFlagSendTIXTCPPortSharding|kernelDatapathSessionFlagReceiveTIXTCPPortSharding) != 0 {
		t.Fatalf("UDP flags = %#x, inner optimization capabilities are TIX TCP-only", flags)
	}
}

func TestKernelDatapathSessionSecureChecksumPartialFlagsAreDirectionalAndIsolated(t *testing.T) {
	key := dataSessionKey{Transport: transport.ProtocolTIXTCP}
	info := transport.KernelDatapathSessionInfo{
		Protocol:                                transport.ProtocolTIXTCP,
		SendEncrypted:                           true,
		ReceiveEncrypted:                        true,
		InnerTCPChecksumPartialLocal:            true,
		InnerTCPChecksumPartialPeer:             true,
		InnerTCPChecksumPartialNegotiated:       true,
		SecureInnerTCPChecksumPartialLocal:      true,
		SecureInnerTCPChecksumPartialPeer:       false,
		SecureInnerTCPChecksumPartialNegotiated: false,
		InnerGSOLocal:                           true,
		InnerGSOPeer:                            true,
		InnerGSONegotiated:                      true,
	}
	flags := kernelDatapathSessionFlags(key, nil, info)
	if flags&kernelDatapathSessionFlagReceiveSecureInnerTCPChecksumPartial == 0 ||
		flags&kernelDatapathSessionFlagSendSecureInnerTCPChecksumPartial != 0 {
		t.Fatalf("local-only secure flags = %#x, want receive-only secure checksum-partial", flags)
	}
	if forbidden := flags & (kernelDatapathSessionFlagSendInnerTCPChecksumPartial |
		kernelDatapathSessionFlagReceiveInnerTCPChecksumPartial |
		kernelDatapathSessionFlagSendInnerGSO |
		kernelDatapathSessionFlagReceiveInnerGSO); forbidden != 0 {
		t.Fatalf("secure session inherited plaintext capability flags %#x", forbidden)
	}

	info.SecureInnerTCPChecksumPartialPeer = true
	info.SecureInnerTCPChecksumPartialNegotiated = true
	flags = kernelDatapathSessionFlags(key, nil, info)
	if flags&kernelDatapathSessionFlagReceiveSecureInnerTCPChecksumPartial == 0 ||
		flags&kernelDatapathSessionFlagSendSecureInnerTCPChecksumPartial == 0 {
		t.Fatalf("negotiated secure flags = %#x, want send+receive", flags)
	}

	info.SecureInnerTCPChecksumPartialLocal = false
	info.SecureInnerTCPChecksumPartialPeer = false
	info.SecureInnerTCPChecksumPartialNegotiated = false
	flags = kernelDatapathSessionFlags(key, nil, info)
	if flags&(kernelDatapathSessionFlagSendSecureInnerTCPChecksumPartial|
		kernelDatapathSessionFlagReceiveSecureInnerTCPChecksumPartial|
		kernelDatapathSessionFlagSendInnerTCPChecksumPartial|
		kernelDatapathSessionFlagReceiveInnerTCPChecksumPartial) != 0 {
		t.Fatalf("legacy plaintext capability enabled secure checksum flags: %#x", flags)
	}
}

func TestKernelDatapathSyntheticChecksumPartialReceiveIsReadyBeforePeerNegotiation(t *testing.T) {
	manager := kernelmodule.NewTrustIXDatapathManager()
	manager.SetStatusForTest(kernelmodule.Status{
		Loaded:   true,
		Features: []string{kernelmodule.FeatureFullDatapath, kernelmodule.FeatureInnerTCPChecksumPartial},
	})
	daemon := &Daemon{
		kernelDatapath:   manager,
		dataSessions:     map[dataSessionKey]transport.Session{},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{},
	}
	peer := config.PeerConfig{ID: "ix-b"}
	endpoint := config.EndpointConfig{
		Name:      "wan-tix-tcp",
		Address:   "198.51.100.2:17042",
		Transport: string(transport.ProtocolTIXTCP),
	}
	send, receive := daemon.kernelDatapathFullPlaintextEndpointInnerTCPChecksumPartial(peer, endpoint, 0)
	if send || !receive {
		t.Fatalf("pre-negotiation synthetic capability = send:%t receive:%t, want false/true", send, receive)
	}

	key := dataSessionKey{
		Peer:       peer.ID,
		Endpoint:   endpoint.Name,
		Transport:  transport.ProtocolTIXTCP,
		Address:    endpoint.Address,
		Encryption: "plaintext",
	}
	daemon.dataSessions[key] = kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
		FlowID:                            7,
		Protocol:                          transport.ProtocolTIXTCP,
		Peer:                              peer.ID,
		Endpoint:                          endpoint.Name,
		InnerTCPChecksumPartialLocal:      true,
		InnerTCPChecksumPartialPeer:       false,
		InnerTCPChecksumPartialNegotiated: false,
	}}
	send, receive = daemon.kernelDatapathFullPlaintextEndpointInnerTCPChecksumPartial(peer, endpoint, 0)
	if send || !receive {
		t.Fatalf("one-sided synthetic capability = send:%t receive:%t, want false/true", send, receive)
	}

	daemon.dataSessions[key] = kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
		FlowID:                            7,
		Protocol:                          transport.ProtocolTIXTCP,
		Peer:                              peer.ID,
		Endpoint:                          endpoint.Name,
		InnerTCPChecksumPartialLocal:      true,
		InnerTCPChecksumPartialPeer:       true,
		InnerTCPChecksumPartialNegotiated: true,
		InnerGSOLocal:                     true,
		InnerGSOPeer:                      true,
		InnerGSONegotiated:                true,
		TIXTCPPortShardingLocal:           true,
		TIXTCPPortShardingPeer:            true,
		TIXTCPPortShardingNegotiated:      true,
	}}
	send, receive = daemon.kernelDatapathFullPlaintextEndpointInnerTCPChecksumPartial(peer, endpoint, 0)
	if !send || !receive {
		t.Fatalf("negotiated synthetic capability = send:%t receive:%t, want true/true", send, receive)
	}
}

func TestKernelDatapathSyntheticInnerGSOIsDirectional(t *testing.T) {
	manager := kernelmodule.NewTrustIXDatapathManager()
	manager.SetStatusForTest(kernelmodule.Status{
		Loaded:   true,
		Features: []string{kernelmodule.FeatureFullDatapath, kernelmodule.FeatureInnerTCPChecksumPartial, kernelmodule.FeatureInnerGSO},
	})
	daemon := &Daemon{
		kernelDatapath:   manager,
		dataSessions:     map[dataSessionKey]transport.Session{},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{},
	}
	peer := config.PeerConfig{ID: "ix-b"}
	endpoint := config.EndpointConfig{
		Name:      "wan-tix-tcp",
		Address:   "198.51.100.2:17042",
		Transport: string(transport.ProtocolTIXTCP),
	}
	send, receive := daemon.kernelDatapathFullPlaintextEndpointInnerGSO(peer, endpoint, 0)
	if send || receive {
		t.Fatalf("pre-negotiation inner GSO = send:%t receive:%t, want false/false", send, receive)
	}

	key := dataSessionKey{
		Peer:       peer.ID,
		Endpoint:   endpoint.Name,
		Transport:  transport.ProtocolTIXTCP,
		Address:    endpoint.Address,
		Encryption: "plaintext",
	}
	daemon.dataSessions[key] = kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
		FlowID:             7,
		Protocol:           transport.ProtocolTIXTCP,
		Peer:               peer.ID,
		Endpoint:           endpoint.Name,
		InnerGSOLocal:      true,
		InnerGSOPeer:       false,
		InnerGSONegotiated: false,
	}}
	send, receive = daemon.kernelDatapathFullPlaintextEndpointInnerGSO(peer, endpoint, 0)
	if send || !receive {
		t.Fatalf("one-sided inner GSO = send:%t receive:%t, want false/true", send, receive)
	}

	daemon.dataSessions[key] = kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
		FlowID:             7,
		Protocol:           transport.ProtocolTIXTCP,
		Peer:               peer.ID,
		Endpoint:           endpoint.Name,
		InnerGSOLocal:      false,
		InnerGSOPeer:       true,
		InnerGSONegotiated: false,
	}}
	send, receive = daemon.kernelDatapathFullPlaintextEndpointInnerGSO(peer, endpoint, 0)
	if !send || receive {
		t.Fatalf("peer-only inner GSO = send:%t receive:%t, want true/false", send, receive)
	}

	daemon.dataSessions[key] = kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
		FlowID:             7,
		Protocol:           transport.ProtocolTIXTCP,
		Peer:               peer.ID,
		Endpoint:           endpoint.Name,
		InnerGSOLocal:      true,
		InnerGSOPeer:       true,
		InnerGSONegotiated: true,
	}}
	send, receive = daemon.kernelDatapathFullPlaintextEndpointInnerGSO(peer, endpoint, 0)
	if !send || !receive {
		t.Fatalf("negotiated inner GSO = send:%t receive:%t, want true/true", send, receive)
	}
}

func TestKernelDatapathSyntheticPortShardingIsDirectional(t *testing.T) {
	manager := kernelmodule.NewTrustIXDatapathManager()
	manager.SetStatusForTest(kernelmodule.Status{
		Loaded:   true,
		Features: []string{kernelmodule.FeatureFullDatapath, kernelmodule.FeatureTIXTCPPortSharding},
	})
	daemon := &Daemon{
		kernelDatapath:   manager,
		dataSessions:     map[dataSessionKey]transport.Session{},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{},
	}
	peer := config.PeerConfig{ID: "ix-b"}
	endpoint := config.EndpointConfig{
		Name:      "wan-tix-tcp",
		Address:   "198.51.100.2:17042",
		Transport: string(transport.ProtocolTIXTCP),
	}
	send, receive := daemon.kernelDatapathFullPlaintextEndpointPortSharding(peer, endpoint, 0)
	if send || !receive {
		t.Fatalf("pre-negotiation port sharding = send:%t receive:%t, want false/true", send, receive)
	}

	key := dataSessionKey{
		Peer:       peer.ID,
		Endpoint:   endpoint.Name,
		Transport:  transport.ProtocolTIXTCP,
		Address:    endpoint.Address,
		Encryption: "plaintext",
	}
	daemon.dataSessions[key] = kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
		FlowID:                       7,
		Protocol:                     transport.ProtocolTIXTCP,
		Peer:                         peer.ID,
		Endpoint:                     endpoint.Name,
		TIXTCPPortShardingLocal:      true,
		TIXTCPPortShardingPeer:       false,
		TIXTCPPortShardingNegotiated: false,
	}}
	send, receive = daemon.kernelDatapathFullPlaintextEndpointPortSharding(peer, endpoint, 0)
	if send || !receive {
		t.Fatalf("one-sided port sharding = send:%t receive:%t, want false/true", send, receive)
	}

	daemon.dataSessions[key] = kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
		FlowID:                       7,
		Protocol:                     transport.ProtocolTIXTCP,
		Peer:                         peer.ID,
		Endpoint:                     endpoint.Name,
		TIXTCPPortShardingLocal:      true,
		TIXTCPPortShardingPeer:       true,
		TIXTCPPortShardingNegotiated: true,
	}}
	send, receive = daemon.kernelDatapathFullPlaintextEndpointPortSharding(peer, endpoint, 0)
	if !send || !receive {
		t.Fatalf("negotiated port sharding = send:%t receive:%t, want true/true", send, receive)
	}
}

func TestKernelDatapathSessionWireRecordEncodesIPv4Underlay(t *testing.T) {
	key := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "wan-udp",
		Transport:  transport.ProtocolUDP,
		Address:    "198.51.100.2:17041",
		Encryption: "none",
		PoolIndex:  5,
	}
	session := kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
		FlowID:        0x1020304050607080,
		Protocol:      transport.ProtocolUDP,
		Peer:          "ix-b",
		Endpoint:      "wan-udp",
		LocalAddress:  "192.0.2.1:51820",
		RemoteAddress: "198.51.100.2:17041",
		MaxPacketSize: 64000,
		Epoch:         11,
	}}
	record, ok := (*Daemon)(nil).kernelDatapathSessionWireRecord(key, session)
	if !ok {
		t.Fatal("session wire record was not encoded")
	}
	local := netip.MustParseAddr("192.0.2.1").As4()
	remote := netip.MustParseAddr("198.51.100.2").As4()
	if record.Kind != kernelmodule.TrustIXDatapathStateKindSessionWire ||
		record.Op != kernelmodule.TrustIXDatapathStateOpUpsert ||
		record.Flags != kernelDatapathSessionWireFlagIPv4|kernelDatapathSessionWireFlagLocalKnown|kernelDatapathSessionWireFlagRemoteKnown ||
		record.Key != kernelDatapathSessionStateKey(key) ||
		record.Value[0] != 0x1020304050607080 ||
		record.Value[1] != uint64(binary.BigEndian.Uint32(local[:])) ||
		record.Value[2] != uint64(binary.BigEndian.Uint32(remote[:])) ||
		record.Value[3] != uint64(51820)<<16|uint64(17041) ||
		record.Value[4] != 1 ||
		record.Value[5] != 64000 ||
		record.Value[6] != 0 ||
		record.Value[7] != 5 {
		t.Fatalf("unexpected session wire record: %#v", record)
	}
}

func TestKernelDatapathSessionWireRecordKeepsTIXTCPEpoch(t *testing.T) {
	key := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "wan-tix-tcp",
		Transport:  transport.ProtocolTIXTCP,
		Address:    "198.51.100.2:17041",
		Encryption: "secure",
	}
	session := kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
		FlowID:        0x1020304050607080,
		Protocol:      transport.ProtocolTIXTCP,
		LocalAddress:  "192.0.2.1:51820",
		RemoteAddress: "198.51.100.2:17041",
		Epoch:         11,
	}}
	record, ok := (*Daemon)(nil).kernelDatapathSessionWireRecord(key, session)
	if !ok {
		t.Fatal("session wire record was not encoded")
	}
	if record.Value[4] != 2 || record.Value[6] != 11 {
		t.Fatalf("unexpected tix_tcp wire record: %#v", record)
	}
}

func TestKernelDatapathSessionCryptoRecordRequiresAdvertisedFeature(t *testing.T) {
	lookup := &kernelDatapathCryptoStateManager{
		NoopManager: dataplane.NewNoopManager(),
		state: dataplane.TIXTCPCryptoState{
			FlowID: 7,
			Send: dataplane.KernelCryptoDirectState{
				SlotID: 1, Suite: 1, WireFormat: 1, Epoch: 11, ReplayWindow: 65536,
			},
			Receive: dataplane.KernelCryptoDirectState{
				SlotID: 2, Suite: 1, WireFormat: 1, Epoch: 11, ReplayWindow: 65536,
			},
		},
		found: true,
	}
	manager := kernelmodule.NewTrustIXDatapathManager()
	manager.SetStatusForTest(kernelmodule.Status{
		Loaded:   true,
		Features: []string{kernelmodule.FeatureFullDatapath},
	})
	daemon := &Daemon{dataplane: lookup, kernelDatapath: manager}
	key := dataSessionKey{Peer: "ix-b", Endpoint: "wan-tix-tcp", Transport: transport.ProtocolTIXTCP, Encryption: "secure"}
	session := kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
		FlowID: 7, Protocol: transport.ProtocolTIXTCP, Epoch: 11, Encrypted: true,
		CryptoPlacement: string(dataplane.CryptoPlacementKernel),
	}}
	if _, ok := daemon.kernelDatapathSessionCryptoRecord(key, session); ok {
		t.Fatal("secure crypto state must remain gated until the module advertises support")
	}
	if lookup.calls != 0 {
		t.Fatalf("crypto lookup calls = %d, want 0 before capability gate", lookup.calls)
	}
}

func TestKernelDatapathSessionCryptoRecordEncodesEpochZeroDirectSlots(t *testing.T) {
	sendIV := [12]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b}
	receiveIV := [12]byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b}
	lookup := &kernelDatapathCryptoStateManager{
		NoopManager: dataplane.NewNoopManager(),
		state: dataplane.TIXTCPCryptoState{
			FlowID: 0x1020304050607080,
			Send: dataplane.KernelCryptoDirectState{
				SlotID: 3, Suite: 1, WireFormat: 1, Epoch: 0, IV: sendIV,
				ReplayWindow: 65536, LastSequence: 0x1122334455667788,
			},
			Receive: dataplane.KernelCryptoDirectState{
				SlotID: 9, Suite: 1, WireFormat: 1, Epoch: 0, IV: receiveIV,
				ReplayWindow: 65536, LastSequence: 0x8877665544332211,
			},
		},
		found: true,
	}
	manager := kernelmodule.NewTrustIXDatapathManager()
	manager.SetStatusForTest(kernelmodule.Status{
		Loaded:   true,
		Features: []string{kernelmodule.FeatureFullDatapath, kernelmodule.FeatureSecureTIXTCPFullDatapath},
	})
	daemon := &Daemon{dataplane: lookup, kernelDatapath: manager}
	key := dataSessionKey{Peer: "ix-b", Endpoint: "wan-tix-tcp", Transport: transport.ProtocolTIXTCP, Encryption: "secure", PoolIndex: 4}
	session := kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
		FlowID: 0x1020304050607080, Protocol: transport.ProtocolTIXTCP, Epoch: 0, Encrypted: true,
		CryptoPlacement: string(dataplane.CryptoPlacementKernel),
	}}
	record, ok := daemon.kernelDatapathSessionCryptoRecord(key, session)
	if !ok {
		t.Fatal("secure crypto state was not encoded")
	}
	if lookup.calls != 1 ||
		record.Kind != kernelmodule.TrustIXDatapathStateKindSessionCrypto ||
		record.Op != kernelmodule.TrustIXDatapathStateOpUpsert ||
		record.Flags != kernelDatapathSessionCryptoFlagSendReady|kernelDatapathSessionCryptoFlagReceiveReady ||
		record.Key != kernelDatapathSessionStateKey(key) ||
		record.Value[0] != 0x1020304050607080 ||
		record.Value[1] != 0 ||
		record.Value[2] != uint64(3)|uint64(9)<<32 ||
		record.Value[3] != uint64(1)|uint64(1)<<16|uint64(65536)<<32 ||
		record.Value[4] != 0x0706050403020100 ||
		record.Value[5] != 0x131211100b0a0908 ||
		record.Value[6] != 0x1b1a191817161514 ||
		record.Value[7] != 0x8877665544332211 {
		t.Fatalf("unexpected session crypto record: %#v", record)
	}
}

func TestKernelDatapathSessionStateKeySeparatesReverseDirection(t *testing.T) {
	outbound := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "wan-tix-tcp",
		Transport:  transport.ProtocolTIXTCP,
		Address:    "198.51.100.2:17041",
		Encryption: "plaintext",
		PoolIndex:  3,
	}
	reverse := outbound
	reverse.Address = reverseSessionAddress
	if kernelDatapathSessionStateKey(outbound) == kernelDatapathSessionStateKey(reverse) {
		t.Fatal("outbound and reverse sessions must not share a kernel state key")
	}
}

func TestKernelDatapathSessionStateRecordsKeepFlowWithoutWireTuple(t *testing.T) {
	key := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "wan-tix-tcp",
		Transport:  transport.ProtocolTIXTCP,
		Address:    reverseSessionAddress,
		Encryption: "plaintext",
	}
	records := (*Daemon)(nil).kernelDatapathSessionStateRecords(key, nil, kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
		FlowID:   0x1020304050607080,
		Protocol: transport.ProtocolTIXTCP,
	}})
	if len(records) != 1 ||
		records[0].Kind != kernelmodule.TrustIXDatapathStateKindSession ||
		records[0].Value[0] != 0x1020304050607080 {
		t.Fatalf("session-only kernel records = %#v, want negotiated flow record", records)
	}
}

func TestKernelDatapathSessionStateRecordsSkipCryptoWithoutWireTuple(t *testing.T) {
	daemon, lookup, key, session := newKernelDatapathCryptoLifecycleFixture()
	info := session.(kernelDatapathTestSession).info
	info.LocalAddress = ""
	info.RemoteAddress = ""

	records := daemon.kernelDatapathSessionStateRecords(key, nil, kernelDatapathTestSession{info: info})
	if len(records) != 1 || records[0].Kind != kernelmodule.TrustIXDatapathStateKindSession {
		t.Fatalf("half-ready secure session records = %#v, want session only", records)
	}
	if lookup.calls != 0 {
		t.Fatalf("crypto lookup calls = %d, want 0 without a wire tuple", lookup.calls)
	}
}

func TestKernelDatapathSessionStateRecordsOrderSecureDependencies(t *testing.T) {
	daemon, lookup, key, session := newKernelDatapathCryptoLifecycleFixture()

	records := daemon.kernelDatapathSessionStateRecords(key, nil, session)
	if len(records) != 3 ||
		records[0].Kind != kernelmodule.TrustIXDatapathStateKindSession ||
		records[1].Kind != kernelmodule.TrustIXDatapathStateKindSessionWire ||
		records[2].Kind != kernelmodule.TrustIXDatapathStateKindSessionCrypto {
		t.Fatalf("secure session dependency order = %#v, want session, wire, crypto", records)
	}
	if lookup.calls != 1 {
		t.Fatalf("crypto lookup calls = %d, want 1", lookup.calls)
	}
}

func TestKernelDatapathSessionWireRecordSkipsUnresolvedUnderlay(t *testing.T) {
	key := dataSessionKey{Peer: "ix-b", Endpoint: "wan-udp", Transport: transport.ProtocolUDP}
	session := kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
		FlowID:        7,
		Protocol:      transport.ProtocolUDP,
		LocalAddress:  "192.0.2.1:51820",
		RemoteAddress: "peer.example.net:17041",
	}}
	if _, ok := (*Daemon)(nil).kernelDatapathSessionWireRecord(key, session); ok {
		t.Fatal("session wire record should skip unresolved domain names until provider resolves them")
	}
}

func TestKernelDatapathSessionAndWireRecordsSkipHalfReadySession(t *testing.T) {
	key := dataSessionKey{Peer: "ix-b", Endpoint: "wan-udp", Transport: transport.ProtocolUDP}
	session := kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
		FlowID:        7,
		Protocol:      transport.ProtocolUDP,
		LocalAddress:  "192.0.2.1:51820",
		RemoteAddress: "peer.example.net:17041",
	}}
	if _, ok := kernelDatapathSessionRecord(key, nil, session); !ok {
		t.Fatal("session record should still be encodable by itself")
	}
	if sessionRecord, wireRecord, ok := (*Daemon)(nil).kernelDatapathSessionAndWireRecords(key, nil, session); ok {
		t.Fatalf("half-ready session should not be published to kernel datapath: session=%#v wire=%#v", sessionRecord, wireRecord)
	}
}

func TestKernelDatapathSessionRecordSkipsUserspaceSession(t *testing.T) {
	key := dataSessionKey{Peer: "ix-b", Endpoint: "wan-tcp", Transport: transport.ProtocolTCP}
	if _, ok := kernelDatapathSessionRecord(key, nil, kernelDatapathUserspaceTestSession{}); ok {
		t.Fatal("userspace session without kernel datapath info should be skipped")
	}
}

func TestKernelDatapathKernelUDPFlowRecordsEncodeSessionAndWire(t *testing.T) {
	flow := dataplane.KernelUDPFlow{
		ID:              0x1122334455667788,
		Peer:            "ix-b",
		Endpoint:        "wan-udp",
		LocalAddress:    "192.0.2.1:17001",
		RemoteAddress:   "198.51.100.2:52000",
		SourcePort:      17001,
		DestinationPort: 52000,
		Epoch:           42,
		CryptoSuite:     "AES-128-GCM-X25519",
		CryptoPlacement: dataplane.CryptoPlacementKernel,
		LastSeen:        time.Unix(0, 1000).UTC(),
	}
	session, ok := kernelDatapathKernelUDPFlowSessionRecord(flow)
	if !ok {
		t.Fatal("kernel_udp flow session record was not encoded")
	}
	wire, ok := kernelDatapathKernelUDPFlowSessionWireRecord(flow)
	if !ok {
		t.Fatal("kernel_udp flow wire record was not encoded")
	}
	local := netip.MustParseAddr("192.0.2.1").As4()
	remote := netip.MustParseAddr("198.51.100.2").As4()
	if session.Kind != kernelmodule.TrustIXDatapathStateKindSession ||
		session.Op != kernelmodule.TrustIXDatapathStateOpUpsert ||
		session.Value[0] != flow.ID ||
		session.Value[1] != 1 ||
		session.Value[2] != 42 ||
		session.Value[3] == 0 ||
		session.Value[4] != 1 ||
		session.Value[5] != 1000 ||
		session.Value[6] != 1000 ||
		session.Flags&kernelDatapathSessionFlagKernelFlow == 0 ||
		session.Flags&kernelDatapathSessionFlagDatagram == 0 ||
		session.Flags&kernelDatapathSessionFlagCryptoKernel == 0 {
		t.Fatalf("unexpected kernel_udp flow session record: %#v", session)
	}
	if wire.Kind != kernelmodule.TrustIXDatapathStateKindSessionWire ||
		wire.Op != kernelmodule.TrustIXDatapathStateOpUpsert ||
		wire.Key != session.Key ||
		wire.Value[0] != flow.ID ||
		wire.Value[1] != uint64(binary.BigEndian.Uint32(local[:])) ||
		wire.Value[2] != uint64(binary.BigEndian.Uint32(remote[:])) ||
		wire.Value[3] != uint64(17001)<<16|uint64(52000) ||
		wire.Value[4] != 1 ||
		wire.Value[6] != 0 {
		t.Fatalf("unexpected kernel_udp flow wire record: %#v", wire)
	}
}

func TestKernelDatapathKernelUDPFlowRecordsSkipExistingSessionFlowID(t *testing.T) {
	daemon := &Daemon{
		dataplane: &kernelDatapathFlowSnapshotManager{flows: []dataplane.KernelUDPFlow{{
			ID:              7,
			Peer:            "ix-b",
			Endpoint:        "wan-udp",
			LocalAddress:    "192.0.2.1:17001",
			RemoteAddress:   "198.51.100.2:52000",
			SourcePort:      17001,
			DestinationPort: 52000,
		}}},
		dataSessions: map[dataSessionKey]transport.Session{
			{Peer: "ix-b", Endpoint: "wan-udp", Transport: transport.ProtocolUDP, Encryption: "none"}: kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
				FlowID:        7,
				Protocol:      transport.ProtocolUDP,
				Peer:          "ix-b",
				Endpoint:      "wan-udp",
				LocalAddress:  "192.0.2.1:17001",
				RemoteAddress: "198.51.100.2:52000",
			}},
		},
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
	}
	if records := daemon.kernelDatapathKernelUDPFlowRecords(context.Background()); len(records) != 0 {
		t.Fatalf("records for existing session flow = %#v, want none", records)
	}
}

func TestKernelDatapathKernelUDPFlowRecordsSkipHalfReadyFlow(t *testing.T) {
	daemon := &Daemon{
		dataplane: &kernelDatapathFlowSnapshotManager{flows: []dataplane.KernelUDPFlow{{
			ID:            7,
			Peer:          "ix-b",
			Endpoint:      "wan-udp",
			LocalAddress:  "192.0.2.1:17001",
			RemoteAddress: "peer.example.net:52000",
		}}},
		dataSessions:     map[dataSessionKey]transport.Session{},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{},
	}
	if records := daemon.kernelDatapathKernelUDPFlowRecords(context.Background()); len(records) != 0 {
		t.Fatalf("half-ready kernel UDP flow records = %#v, want none", records)
	}
}

func TestKernelDatapathFullPlaintextRouteSessionRecordsInheritNegotiatedCapabilities(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_FORCE_FULL_PLAINTEXT_TX", "1")
	daemon := &Daemon{
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-a"},
			KernelModules: config.KernelModulesConfig{
				CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
			},
			TransportPolicy: config.TransportPolicyConfig{
				Encryption: "plaintext",
			},
			Endpoints: []config.EndpointConfig{{
				Name:      "wan-tix-tcp",
				Mode:      config.EndpointModePassive,
				Listen:    "192.0.2.1:17041",
				Address:   "192.0.2.1:17041",
				Transport: string(transport.ProtocolTIXTCP),
				Security: config.EndpointSecurityConfig{
					Encryption: "plaintext",
				},
				Enabled: true,
			}},
			Peers: []config.PeerConfig{{
				ID: "ix-b",
				Endpoints: []config.EndpointConfig{{
					Name:      "wan-tix-tcp",
					Mode:      config.EndpointModePassive,
					Address:   "198.51.100.2:17042",
					Transport: string(transport.ProtocolTIXTCP),
					Security: config.EndpointSecurityConfig{
						Encryption: "plaintext",
					},
					Enabled: true,
				}},
			}},
		},
		dataSessions:     map[dataSessionKey]transport.Session{},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{},
	}
	existingKey := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "wan-tix-tcp",
		Transport:  transport.ProtocolTIXTCP,
		Address:    "198.51.100.2:17042",
		Encryption: "plaintext",
	}
	daemon.dataSessions[existingKey] = kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
		FlowID:                            7,
		Protocol:                          transport.ProtocolTIXTCP,
		Peer:                              "ix-b",
		Endpoint:                          "wan-tix-tcp",
		InnerTCPChecksumPartialLocal:      true,
		InnerTCPChecksumPartialPeer:       true,
		InnerTCPChecksumPartialNegotiated: true,
		InnerGSOLocal:                     true,
		InnerGSOPeer:                      true,
		InnerGSONegotiated:                true,
		TIXTCPPortShardingLocal:           true,
		TIXTCPPortShardingPeer:            true,
		TIXTCPPortShardingNegotiated:      true,
	}}
	daemon.dataSessionState[existingKey] = &dataSessionRuntime{key: existingKey}

	records := daemon.kernelDatapathFullPlaintextRouteSessionRecords(context.Background(), []routing.Route{{
		Prefix:   core.Prefix("10.202.12.0/24"),
		NextHop:  "ix-b",
		Endpoint: "wan-tix-tcp",
		Kind:     routing.RouteUnicast,
	}})
	if len(records) != 2 {
		t.Fatalf("full plaintext records = %#v, want session+wire", records)
	}
	syntheticKey := existingKey
	syntheticKey.Address = kernelDatapathFullPlaintextAddressPrefix + existingKey.Address
	if records[0].Kind != kernelmodule.TrustIXDatapathStateKindSession ||
		records[1].Kind != kernelmodule.TrustIXDatapathStateKindSessionWire ||
		records[0].Key != kernelDatapathSessionStateKey(syntheticKey) ||
		records[1].Key != records[0].Key {
		t.Fatalf("unexpected full plaintext records: %#v", records)
	}
	if records[1].Value[0] != records[0].Value[0] || records[1].Value[0] == 0 {
		t.Fatalf("wire record does not match synthetic flow id: session=%#v wire=%#v", records[0], records[1])
	}
	if records[0].Flags&kernelDatapathSessionFlagReceiveInnerTCPChecksumPartial == 0 ||
		records[0].Flags&kernelDatapathSessionFlagSendInnerTCPChecksumPartial == 0 ||
		records[0].Flags&kernelDatapathSessionFlagReceiveInnerGSO == 0 ||
		records[0].Flags&kernelDatapathSessionFlagSendInnerGSO == 0 ||
		records[0].Flags&kernelDatapathSessionFlagReceiveTIXTCPPortSharding == 0 ||
		records[0].Flags&kernelDatapathSessionFlagSendTIXTCPPortSharding == 0 {
		t.Fatalf("synthetic session did not inherit negotiated inner capabilities: %#v", records[0])
	}
}

func TestKernelDatapathFullPlaintextRouteSessionRecordsCoverActivePoolIndexes(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_FORCE_FULL_PLAINTEXT_TX", "1")
	daemon := &Daemon{
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-a"},
			KernelModules: config.KernelModulesConfig{
				CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
			},
			TransportPolicy: config.TransportPolicyConfig{
				Encryption: "plaintext",
			},
			Endpoints: []config.EndpointConfig{{
				Name:      "wan-udp",
				Mode:      config.EndpointModePassive,
				Listen:    "192.0.2.1:17041",
				Address:   "192.0.2.1:17041",
				Transport: string(transport.ProtocolUDP),
				Security: config.EndpointSecurityConfig{
					Encryption: "plaintext",
				},
				Enabled: true,
			}},
			Peers: []config.PeerConfig{{
				ID: "ix-b",
				Endpoints: []config.EndpointConfig{{
					Name:      "wan-udp",
					Mode:      config.EndpointModePassive,
					Address:   "198.51.100.2:17042",
					Transport: string(transport.ProtocolUDP),
					Security: config.EndpointSecurityConfig{
						Encryption: "plaintext",
					},
					Enabled: true,
				}},
			}},
		},
		dataSessions:     map[dataSessionKey]transport.Session{},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{},
	}
	for _, poolIndex := range []int{0, 7, 1} {
		address := "198.51.100.2:17042"
		if poolIndex == 7 {
			address = reverseSessionAddress
		}
		key := dataSessionKey{
			Peer:       "ix-b",
			Endpoint:   "wan-udp",
			Transport:  transport.ProtocolUDP,
			Address:    address,
			Encryption: "plaintext",
			PoolIndex:  poolIndex,
		}
		daemon.dataSessions[key] = kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
			FlowID:   uint64(100 + poolIndex),
			Peer:     "ix-b",
			Endpoint: "wan-udp",
		}}
		daemon.dataSessionState[key] = &dataSessionRuntime{key: key}
	}

	records := daemon.kernelDatapathFullPlaintextRouteSessionRecords(context.Background(), []routing.Route{{
		Prefix:   core.Prefix("10.202.12.0/24"),
		NextHop:  "ix-b",
		Endpoint: "wan-udp",
		Kind:     routing.RouteUnicast,
	}})
	if len(records) != 6 {
		t.Fatalf("full plaintext records = %#v, want three session/wire pairs", records)
	}
	for i, poolIndex := range []int{0, 1, 7} {
		session := records[i*2]
		wire := records[i*2+1]
		key := dataSessionKey{
			Peer:       "ix-b",
			Endpoint:   "wan-udp",
			Transport:  transport.ProtocolUDP,
			Address:    kernelDatapathFullPlaintextAddressPrefix + "198.51.100.2:17042",
			Encryption: "plaintext",
			PoolIndex:  poolIndex,
		}
		if session.Kind != kernelmodule.TrustIXDatapathStateKindSession ||
			wire.Kind != kernelmodule.TrustIXDatapathStateKindSessionWire ||
			session.Key != kernelDatapathSessionStateKey(key) ||
			wire.Key != session.Key ||
			session.Value[7] != uint64(poolIndex) ||
			wire.Value[7] != uint64(poolIndex) ||
			wire.Value[0] != session.Value[0] ||
			wire.Value[0] == 0 {
			t.Fatalf("unexpected pool %d records: session=%#v wire=%#v", poolIndex, session, wire)
		}
	}
}

func TestKernelDatapathStateRecordsSeparateSyntheticFallbackFromIncompleteNegotiatedSession(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_FORCE_FULL_PLAINTEXT_TX", "1")
	localEndpoint := config.EndpointConfig{
		Name:      "wan-tix-tcp",
		Mode:      config.EndpointModePassive,
		Listen:    "192.0.2.1:17041",
		Address:   "192.0.2.1:17041",
		Transport: string(transport.ProtocolTIXTCP),
		Security:  config.EndpointSecurityConfig{Encryption: "plaintext"},
		Enabled:   true,
	}
	remoteEndpoint := config.EndpointConfig{
		Name:      "wan-tix-tcp",
		Mode:      config.EndpointModePassive,
		Address:   "198.51.100.2:17042",
		Transport: string(transport.ProtocolTIXTCP),
		Security:  config.EndpointSecurityConfig{Encryption: "plaintext"},
		Enabled:   true,
	}
	outboundKey := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   remoteEndpoint.Name,
		Transport:  transport.ProtocolTIXTCP,
		Address:    remoteEndpoint.Address,
		Encryption: "plaintext",
	}
	reverseKey := outboundKey
	reverseKey.Address = reverseSessionAddress
	daemon := &Daemon{
		desired: config.Desired{
			IX:              config.IXConfig{ID: "ix-a"},
			KernelModules:   config.KernelModulesConfig{CapabilityProfile: config.KernelCapabilityProfileFullPlaintext},
			TransportPolicy: config.TransportPolicyConfig{Encryption: "plaintext"},
			Endpoints:       []config.EndpointConfig{localEndpoint},
			Peers: []config.PeerConfig{{
				ID:        "ix-b",
				Endpoints: []config.EndpointConfig{remoteEndpoint},
			}},
		},
		dataSessions: map[dataSessionKey]transport.Session{
			outboundKey: kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
				FlowID:   7,
				Protocol: transport.ProtocolTIXTCP,
				Peer:     "ix-b",
				Endpoint: remoteEndpoint.Name,
			}},
			reverseKey: kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
				FlowID:   9,
				Protocol: transport.ProtocolTIXTCP,
				Peer:     "ix-b",
				Endpoint: remoteEndpoint.Name,
			}},
		},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.202.12.0/24"),
		NextHop:  "ix-b",
		Endpoint: remoteEndpoint.Name,
		Kind:     routing.RouteUnicast,
	}
	records := daemon.kernelDatapathStateRecords(context.Background(), dataplane.Snapshot{Routes: []routing.Route{route}})
	syntheticKey := outboundKey
	syntheticKey.Address = kernelDatapathFullPlaintextAddressPrefix + remoteEndpoint.Address
	negotiatedFlowID := uint64(0)
	negotiatedWireFound := false
	syntheticSessionFlowID := uint64(0)
	syntheticWireFlowID := uint64(0)
	reverseFound := false
	for _, record := range records {
		if record.Op != kernelmodule.TrustIXDatapathStateOpUpsert {
			continue
		}
		switch {
		case record.Kind == kernelmodule.TrustIXDatapathStateKindSession && record.Key == kernelDatapathSessionStateKey(outboundKey):
			negotiatedFlowID = record.Value[0]
		case record.Kind == kernelmodule.TrustIXDatapathStateKindSessionWire && record.Key == kernelDatapathSessionStateKey(outboundKey):
			negotiatedWireFound = true
		case record.Kind == kernelmodule.TrustIXDatapathStateKindSession && record.Key == kernelDatapathSessionStateKey(syntheticKey):
			syntheticSessionFlowID = record.Value[0]
			if record.Flags&kernelDatapathSessionFlagSyntheticFallback == 0 {
				t.Fatalf("synthetic fallback flags = %#x, want synthetic marker", record.Flags)
			}
		case record.Kind == kernelmodule.TrustIXDatapathStateKindSessionWire && record.Key == kernelDatapathSessionStateKey(syntheticKey):
			syntheticWireFlowID = record.Value[0]
		case record.Kind == kernelmodule.TrustIXDatapathStateKindSession && record.Key == kernelDatapathSessionStateKey(reverseKey):
			reverseFound = record.Value[0] == 9
		}
	}
	if negotiatedFlowID != 7 {
		t.Fatalf("negotiated outbound session flow id = %d, want 7; records=%#v", negotiatedFlowID, records)
	}
	if negotiatedWireFound {
		t.Fatalf("incomplete negotiated session unexpectedly has a wire record: %#v", records)
	}
	if syntheticSessionFlowID == 0 || syntheticSessionFlowID != syntheticWireFlowID {
		t.Fatalf("synthetic session/wire flow ids = %d/%d, want a matching nonzero fallback; records=%#v", syntheticSessionFlowID, syntheticWireFlowID, records)
	}
	if !reverseFound {
		t.Fatalf("negotiated reverse flow 9 missing from kernel records: %#v", records)
	}
}

func TestKernelDatapathFullPlaintextFlowIDIsSharedAcrossDirections(t *testing.T) {
	daemon := &Daemon{}
	endpointA := config.EndpointConfig{
		Name:      "ix-a-full",
		Mode:      config.EndpointModePassive,
		Listen:    "192.0.2.1:17041",
		Address:   "192.0.2.1:17041",
		Transport: string(transport.ProtocolUDP),
		Enabled:   true,
	}
	endpointB := config.EndpointConfig{
		Name:      "ix-b-full",
		Mode:      config.EndpointModePassive,
		Listen:    "198.51.100.2:17042",
		Address:   "198.51.100.2:17042",
		Transport: string(transport.ProtocolUDP),
		Enabled:   true,
	}
	sessionAB, wireAB, ok := daemon.kernelDatapathFullPlaintextEndpointRecords(
		context.Background(),
		config.PeerConfig{ID: "ix-b"},
		endpointB,
		endpointA,
		0,
	)
	if !ok {
		t.Fatal("ix-a to ix-b full plaintext records were not encoded")
	}
	sessionBA, wireBA, ok := daemon.kernelDatapathFullPlaintextEndpointRecords(
		context.Background(),
		config.PeerConfig{ID: "ix-a"},
		endpointA,
		endpointB,
		0,
	)
	if !ok {
		t.Fatal("ix-b to ix-a full plaintext records were not encoded")
	}
	if sessionAB.Value[0] == 0 ||
		sessionAB.Value[0] != wireAB.Value[0] ||
		sessionAB.Value[0] != sessionBA.Value[0] ||
		sessionBA.Value[0] != wireBA.Value[0] {
		t.Fatalf("full plaintext flow ids should match both directions: ab session=%#v wire=%#v ba session=%#v wire=%#v", sessionAB, wireAB, sessionBA, wireBA)
	}
	if wireAB.Value[1] != wireBA.Value[2] ||
		wireAB.Value[2] != wireBA.Value[1] ||
		uint16(wireAB.Value[3]>>16) != uint16(wireBA.Value[3]) ||
		uint16(wireAB.Value[3]) != uint16(wireBA.Value[3]>>16) {
		t.Fatalf("full plaintext wire tuples should remain local-perspective encoded: ab=%#v ba=%#v", wireAB, wireBA)
	}
}

func TestKernelDatapathKernelUDPFlowSessionKeyIncludesFlowID(t *testing.T) {
	first, ok := kernelDatapathKernelUDPFlowSessionKey(dataplane.KernelUDPFlow{
		ID:       1,
		Peer:     "ix-b",
		Endpoint: "wan-udp",
	})
	if !ok {
		t.Fatal("first flow key was not encoded")
	}
	second, ok := kernelDatapathKernelUDPFlowSessionKey(dataplane.KernelUDPFlow{
		ID:       2,
		Peer:     "ix-b",
		Endpoint: "wan-udp",
	})
	if !ok {
		t.Fatal("second flow key was not encoded")
	}
	if first == second {
		t.Fatalf("different kernel_udp flow ids produced same session key: %#v", first)
	}
}

func TestKernelDatapathFlowRecordEncodesIPv4Tuple(t *testing.T) {
	binding := routing.FlowBinding{
		Key: routing.FlowKey{
			SourceIP:        netip.MustParseAddr("10.82.0.2"),
			DestinationIP:   netip.MustParseAddr("10.216.0.9"),
			SourcePort:      12345,
			DestinationPort: 5201,
			Protocol:        6,
		},
		NextHop:   "ix-b",
		Endpoint:  "wan-tix-tcp",
		PoolIndex: 3,
		LastSeen:  time.Unix(0, 1000).UTC(),
		ExpiresAt: time.Unix(0, 2000).UTC(),
	}
	record, ok := kernelDatapathFlowRecord(binding)
	if !ok {
		t.Fatal("flow record was not encoded")
	}
	source := netip.MustParseAddr("10.82.0.2").As4()
	destination := netip.MustParseAddr("10.216.0.9").As4()
	if record.Kind != kernelmodule.TrustIXDatapathStateKindFlow ||
		record.Op != kernelmodule.TrustIXDatapathStateOpUpsert ||
		record.Flags != kernelDatapathFlowFlagIPv4 ||
		record.Key[0] != uint64(binary.BigEndian.Uint32(source[:])) ||
		record.Key[1] != uint64(binary.BigEndian.Uint32(destination[:])) ||
		record.Key[2] != uint64(12345)<<16|uint64(5201) ||
		record.Key[3] != 6 ||
		record.Value[0] == 0 ||
		record.Value[1] == 0 ||
		record.Value[2] != 3 ||
		record.Value[3] != 1000 ||
		record.Value[4] != 2000 {
		t.Fatalf("unexpected flow record: %#v", record)
	}
}

func TestKernelDatapathFlowRecordSkipsIPv6ForNow(t *testing.T) {
	_, ok := kernelDatapathFlowRecord(routing.FlowBinding{Key: routing.FlowKey{
		SourceIP:      netip.MustParseAddr("fd00::1"),
		DestinationIP: netip.MustParseAddr("10.216.0.9"),
		Protocol:      17,
	}})
	if ok {
		t.Fatal("IPv6 flow should be skipped until the first full datapath ABI defines IPv6 keys")
	}
}

type kernelDatapathTestSession struct {
	info transport.KernelDatapathSessionInfo
}

type kernelDatapathReadyTestSession struct {
	info      transport.KernelDatapathSessionInfo
	hookMu    sync.Mutex
	hook      func() error
	readyOnce sync.Once
	ready     chan struct{}
}

func (session *kernelDatapathReadyTestSession) KernelDatapathSessionInfo() (transport.KernelDatapathSessionInfo, bool) {
	return session.info, true
}

func (session *kernelDatapathReadyTestSession) SetKernelDatapathSessionStateChangeHook(hook func() error) {
	session.hookMu.Lock()
	session.hook = hook
	session.hookMu.Unlock()
}

func (session *kernelDatapathReadyTestSession) MarkKernelDatapathSessionReady(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	session.readyOnce.Do(func() { close(session.ready) })
	return nil
}

func (session *kernelDatapathReadyTestSession) SendPacket(pkt []byte) error { return nil }
func (session *kernelDatapathReadyTestSession) RecvPacket() ([]byte, error) {
	return nil, errors.New("not implemented")
}
func (session *kernelDatapathReadyTestSession) Close() error { return nil }
func (session *kernelDatapathReadyTestSession) Stats() transport.TransportStats {
	return transport.TransportStats{}
}

func (session kernelDatapathTestSession) KernelDatapathSessionInfo() (transport.KernelDatapathSessionInfo, bool) {
	return session.info, true
}

func (session kernelDatapathTestSession) SendPacket(pkt []byte) error { return nil }
func (session kernelDatapathTestSession) RecvPacket() ([]byte, error) {
	return nil, errors.New("not implemented")
}
func (session kernelDatapathTestSession) Close() error { return nil }
func (session kernelDatapathTestSession) Stats() transport.TransportStats {
	return transport.TransportStats{}
}

type kernelDatapathUserspaceTestSession struct{}

func (session kernelDatapathUserspaceTestSession) SendPacket(pkt []byte) error { return nil }
func (session kernelDatapathUserspaceTestSession) RecvPacket() ([]byte, error) {
	return nil, errors.New("not implemented")
}
func (session kernelDatapathUserspaceTestSession) Close() error { return nil }
func (session kernelDatapathUserspaceTestSession) Stats() transport.TransportStats {
	return transport.TransportStats{}
}

type kernelDatapathFlowSnapshotManager struct {
	dataplane.NoopManager
	flows []dataplane.KernelUDPFlow
}

type kernelDatapathCryptoStateManager struct {
	*dataplane.NoopManager
	state                dataplane.TIXTCPCryptoState
	found                bool
	err                  error
	calls                int
	commitCalls          [][2]uint64
	releaseCalls         []uint64
	releaseRetiredCalls  int
	commitErr            error
	releaseErr           error
	releaseRetiredErrors []error
}

func (manager *kernelDatapathCryptoStateManager) TIXTCPCryptoState(ctx context.Context, flowID uint64) (dataplane.TIXTCPCryptoState, bool, error) {
	manager.calls++
	if err := ctx.Err(); err != nil {
		return dataplane.TIXTCPCryptoState{}, false, err
	}
	if manager.err != nil {
		return dataplane.TIXTCPCryptoState{}, false, manager.err
	}
	if flowID != manager.state.FlowID {
		return dataplane.TIXTCPCryptoState{}, false, nil
	}
	return manager.state, manager.found, nil
}

func (manager *kernelDatapathCryptoStateManager) CommitTIXTCPCryptoState(ctx context.Context, flowID uint64, epoch uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	manager.commitCalls = append(manager.commitCalls, [2]uint64{flowID, epoch})
	return manager.commitErr
}

func (manager *kernelDatapathCryptoStateManager) ReleaseTIXTCPCryptoState(ctx context.Context, flowID uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	manager.releaseCalls = append(manager.releaseCalls, flowID)
	return manager.releaseErr
}

func (manager *kernelDatapathCryptoStateManager) ReleaseRetiredTIXTCPCryptoStates(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	manager.releaseRetiredCalls++
	index := manager.releaseRetiredCalls - 1
	if index < len(manager.releaseRetiredErrors) {
		return manager.releaseRetiredErrors[index]
	}
	return nil
}

func newKernelDatapathCryptoLifecycleFixture() (*Daemon, *kernelDatapathCryptoStateManager, dataSessionKey, transport.Session) {
	flowID := uint64(0x1020304050607080)
	epoch := uint64(0)
	manager := &kernelDatapathCryptoStateManager{
		NoopManager: dataplane.NewNoopManager(),
		state: dataplane.TIXTCPCryptoState{
			FlowID: flowID,
			Send: dataplane.KernelCryptoDirectState{
				SlotID: 1, Suite: 1, WireFormat: 1, Epoch: epoch, ReplayWindow: 65536,
			},
			Receive: dataplane.KernelCryptoDirectState{
				SlotID: 2, Suite: 1, WireFormat: 1, Epoch: epoch, ReplayWindow: 65536,
			},
		},
		found: true,
	}
	kernelManager := kernelmodule.NewTrustIXDatapathManager()
	kernelManager.SetStatusForTest(kernelmodule.Status{
		Loaded: true,
		Features: []string{
			kernelmodule.FeatureFullDatapath,
			kernelmodule.FeatureSecureTIXTCPFullDatapath,
		},
	})
	key := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "wan-tix-tcp",
		Transport:  transport.ProtocolTIXTCP,
		Address:    "198.51.100.2:17041",
		Encryption: "secure",
	}
	session := kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
		FlowID:           flowID,
		Protocol:         transport.ProtocolTIXTCP,
		Peer:             "ix-b",
		Endpoint:         "wan-tix-tcp",
		LocalAddress:     "192.0.2.1:17041",
		RemoteAddress:    "198.51.100.2:17041",
		Epoch:            epoch,
		CryptoPlacement:  string(dataplane.CryptoPlacementKernel),
		Encrypted:        true,
		SendEncrypted:    true,
		ReceiveEncrypted: true,
	}}
	daemon := &Daemon{
		dataplane:        manager,
		kernelDatapath:   kernelManager,
		dataSessions:     map[dataSessionKey]transport.Session{key: session},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{},
	}
	return daemon, manager, key, session
}

func (manager kernelDatapathFlowSnapshotManager) KernelUDPFlows(ctx context.Context) ([]dataplane.KernelUDPFlow, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]dataplane.KernelUDPFlow(nil), manager.flows...), nil
}
