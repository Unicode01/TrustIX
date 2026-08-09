//go:build linux

package daemon

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/kernelmodule"
	"trustix.local/trustix/internal/routing"
	"trustix.local/trustix/internal/transport"
	securetransport "trustix.local/trustix/internal/transport/secure"
)

const (
	kernelDatapathSessionFlagReverse                              = uint32(1 << 0)
	kernelDatapathSessionFlagControlOnly                          = uint32(1 << 1)
	kernelDatapathSessionFlagKernelFlow                           = uint32(1 << 2)
	kernelDatapathSessionFlagEncrypted                            = uint32(1 << 3)
	kernelDatapathSessionFlagSendEncrypted                        = uint32(1 << 4)
	kernelDatapathSessionFlagReceiveEncrypted                     = uint32(1 << 5)
	kernelDatapathSessionFlagCryptoKernel                         = uint32(1 << 6)
	kernelDatapathSessionFlagCryptoUserspace                      = uint32(1 << 7)
	kernelDatapathSessionFlagNativeBatching                       = uint32(1 << 8)
	kernelDatapathSessionFlagDatagram                             = uint32(1 << 9)
	kernelDatapathSessionFlagFragmentingDatagram                  = uint32(1 << 10)
	kernelDatapathSessionFlagSyntheticFallback                    = uint32(1 << 11)
	kernelDatapathSessionFlagSendInnerTCPChecksumPartial          = uint32(1 << 12)
	kernelDatapathSessionFlagReceiveInnerTCPChecksumPartial       = uint32(1 << 13)
	kernelDatapathSessionFlagSendInnerGSO                         = uint32(1 << 14)
	kernelDatapathSessionFlagReceiveInnerGSO                      = uint32(1 << 15)
	kernelDatapathSessionFlagSendTIXTCPPortSharding               = uint32(1 << 16)
	kernelDatapathSessionFlagReceiveTIXTCPPortSharding            = uint32(1 << 17)
	kernelDatapathSessionFlagSendSecureInnerTCPChecksumPartial    = uint32(1 << 18)
	kernelDatapathSessionFlagReceiveSecureInnerTCPChecksumPartial = uint32(1 << 19)

	kernelDatapathFlowFlagIPv4 = uint32(1 << 0)

	kernelDatapathSessionWireFlagIPv4        = uint32(1 << 0)
	kernelDatapathSessionWireFlagLocalKnown  = uint32(1 << 1)
	kernelDatapathSessionWireFlagRemoteKnown = uint32(1 << 2)

	kernelDatapathSessionCryptoFlagSendReady    = uint32(1 << 0)
	kernelDatapathSessionCryptoFlagReceiveReady = uint32(1 << 1)
)

const (
	kernelDatapathKernelUDPFlowAddressPrefix = "kernel_udp_flow:"
	kernelDatapathFullPlaintextAddressPrefix = "full_plaintext_fallback:"
	kernelDatapathStateSyncInterval          = 2 * time.Second
)

type kernelDatapathSessionSnapshot struct {
	key     dataSessionKey
	runtime *dataSessionRuntime
	session transport.Session
}

type kernelDatapathStateCounts struct {
	routes       uint32
	sessions     uint32
	flows        uint32
	sessionWires uint32
}

var (
	kernelDatapathStateStatsQuery = kernelmodule.DatapathStateStatsQuery
	kernelDatapathApplyStateBatch = kernelmodule.DatapathApplyStateBatch
)

func (daemon *Daemon) syncKernelDatapathState(ctx context.Context, snapshot dataplane.Snapshot) error {
	daemon.kernelDatapathStateMu.Lock()
	defer daemon.kernelDatapathStateMu.Unlock()
	return daemon.syncKernelDatapathStateLocked(ctx, snapshot)
}

func (daemon *Daemon) syncCurrentKernelDatapathState(ctx context.Context) error {
	daemon.kernelDatapathStateMu.Lock()
	defer daemon.kernelDatapathStateMu.Unlock()
	return daemon.syncKernelDatapathStateLocked(ctx, daemon.runtimeDataplaneSnapshot())
}

func (daemon *Daemon) syncKernelDatapathStateLocked(ctx context.Context, snapshot dataplane.Snapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !daemon.kernelDatapathAvailable() {
		return daemon.releaseRetiredTIXTCPCryptoStates(ctx)
	}
	stats, err := kernelDatapathStateStatsQuery(kernelmodule.TrustIXDatapathDevicePath)
	if err != nil {
		return fmt.Errorf("query kernel datapath state capacity: %w", err)
	}
	if stats.MaxRoutes == 0 || stats.MaxSessions == 0 || stats.MaxFlows == 0 {
		return fmt.Errorf(
			"kernel datapath reported invalid state capacity routes=%d sessions=%d flows=%d",
			stats.MaxRoutes,
			stats.MaxSessions,
			stats.MaxFlows,
		)
	}
	upserts := daemon.kernelDatapathStateUpsertRecords(ctx, snapshot)
	if err := ctx.Err(); err != nil {
		return err
	}
	counts := kernelDatapathStateRecordCounts(upserts)
	if err := validateKernelDatapathStateCapacity(stats, counts); err != nil {
		return err
	}

	reset := !daemon.kernelDatapathStateInitialized
	if !reset && kernelDatapathStateCountsMatch(stats, counts) {
		if err := daemon.applyKernelDatapathStateRecords(ctx, upserts); err != nil {
			return err
		}
	} else if !reset {
		if err := daemon.applyKernelDatapathStateRecords(ctx, upserts); err != nil {
			return fmt.Errorf("repair kernel datapath state without clearing live tables: %w", err)
		}
		refreshed, refreshErr := kernelDatapathStateStatsQuery(kernelmodule.TrustIXDatapathDevicePath)
		if refreshErr != nil {
			return fmt.Errorf("re-query kernel datapath state after non-destructive repair: %w", refreshErr)
		}
		reset = !kernelDatapathStateCountsMatch(refreshed, counts)
	}
	if reset {
		records := append(daemon.kernelDatapathStateClearRecords(), upserts...)
		if err := daemon.applyKernelDatapathStateRecords(ctx, records); err != nil {
			daemon.kernelDatapathStateInitialized = false
			return fmt.Errorf("reset kernel datapath state: %w", err)
		}
		daemon.kernelDatapathStateInitialized = true
	}
	if err := daemon.releaseRetiredTIXTCPCryptoStates(ctx); err != nil {
		return fmt.Errorf("release retired tix_tcp crypto states after full kernel datapath sync: %w", err)
	}
	daemon.clearBackgroundError("kernel_datapath_state_sync")
	return nil
}

func (daemon *Daemon) kernelDatapathStateRecords(ctx context.Context, snapshot dataplane.Snapshot) []kernelmodule.DatapathStateRecord {
	records := daemon.kernelDatapathStateClearRecords()
	return append(records, daemon.kernelDatapathStateUpsertRecords(ctx, snapshot)...)
}

func (daemon *Daemon) kernelDatapathStateClearRecords() []kernelmodule.DatapathStateRecord {
	records := make([]kernelmodule.DatapathStateRecord, 0, 5)
	for _, kind := range []uint32{
		kernelmodule.TrustIXDatapathStateKindRoute,
		kernelmodule.TrustIXDatapathStateKindSession,
		kernelmodule.TrustIXDatapathStateKindSessionWire,
		kernelmodule.TrustIXDatapathStateKindFlow,
	} {
		records = append(records, kernelmodule.DatapathStateRecord{Kind: kind, Op: kernelmodule.TrustIXDatapathStateOpClear})
	}
	if daemon.kernelDatapathSecureTIXTCPReady() {
		records = append(records, kernelmodule.DatapathStateRecord{Kind: kernelmodule.TrustIXDatapathStateKindSessionCrypto, Op: kernelmodule.TrustIXDatapathStateOpClear})
	}
	return records
}

func (daemon *Daemon) kernelDatapathStateUpsertRecords(ctx context.Context, snapshot dataplane.Snapshot) []kernelmodule.DatapathStateRecord {
	records := make([]kernelmodule.DatapathStateRecord, 0, len(snapshot.Routes))
	for _, route := range snapshot.Routes {
		if record, ok := kernelDatapathRouteRecord(route); ok {
			records = append(records, record)
		}
	}
	// Synthetic full-plaintext records use distinct keys so an incomplete
	// negotiated session cannot leave a mismatched synthetic wire record.
	records = append(records, daemon.kernelDatapathFullPlaintextRouteSessionRecords(ctx, snapshot.Routes)...)
	for _, item := range daemon.kernelDatapathSessionSnapshot() {
		if ctx.Err() != nil {
			return records
		}
		records = append(records, daemon.kernelDatapathSessionStateRecords(item.key, item.runtime, item.session)...)
	}
	records = append(records, daemon.kernelDatapathKernelUDPFlowRecords(ctx)...)
	for _, flow := range daemon.flowSnapshot() {
		if ctx.Err() != nil {
			return records
		}
		if record, ok := kernelDatapathFlowRecord(flow); ok {
			records = append(records, record)
		}
	}
	return records
}

func kernelDatapathStateRecordCounts(records []kernelmodule.DatapathStateRecord) kernelDatapathStateCounts {
	type recordKey struct {
		kind uint32
		key  [4]uint64
	}
	seen := make(map[recordKey]struct{}, len(records))
	counts := kernelDatapathStateCounts{}
	for _, record := range records {
		if record.Op != kernelmodule.TrustIXDatapathStateOpUpsert {
			continue
		}
		key := recordKey{kind: record.Kind, key: record.Key}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		switch record.Kind {
		case kernelmodule.TrustIXDatapathStateKindRoute:
			counts.routes++
		case kernelmodule.TrustIXDatapathStateKindSession:
			counts.sessions++
		case kernelmodule.TrustIXDatapathStateKindFlow:
			counts.flows++
		case kernelmodule.TrustIXDatapathStateKindSessionWire:
			counts.sessionWires++
		}
	}
	return counts
}

func validateKernelDatapathStateCapacity(stats kernelmodule.DatapathStateStats, counts kernelDatapathStateCounts) error {
	if counts.routes > stats.MaxRoutes || counts.sessions > stats.MaxSessions || counts.flows > stats.MaxFlows ||
		(stats.MaxSessionWires > 0 && counts.sessionWires > stats.MaxSessionWires) {
		return fmt.Errorf("kernel datapath desired state exceeds capacity routes=%d/%d sessions=%d/%d flows=%d/%d session_wires=%d/%d",
			counts.routes, stats.MaxRoutes,
			counts.sessions, stats.MaxSessions,
			counts.flows, stats.MaxFlows,
			counts.sessionWires, stats.MaxSessionWires)
	}
	return nil
}

func kernelDatapathStateCountsMatch(stats kernelmodule.DatapathStateStats, counts kernelDatapathStateCounts) bool {
	return stats.Routes == counts.routes &&
		stats.Sessions == counts.sessions &&
		stats.Flows == counts.flows &&
		stats.SessionWires == counts.sessionWires
}

func (daemon *Daemon) runKernelDatapathStateSync(ctx context.Context) {
	ticker := time.NewTicker(kernelDatapathStateSyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := daemon.syncCurrentKernelDatapathState(ctx); err != nil {
				daemon.recordBackgroundError("kernel_datapath_state_sync", err)
				daemon.requestRuntimeReconcile("kernel datapath state sync", err)
			}
		}
	}
}

func (daemon *Daemon) syncKernelDatapathSessionUpsert(key dataSessionKey, runtime *dataSessionRuntime, session transport.Session) {
	if notifier, ok := session.(transport.KernelDatapathSessionStateChangeHookSetter); ok {
		notifier.SetKernelDatapathSessionStateChangeHook(func() {
			daemon.syncKernelDatapathSessionStateChange(key, runtime, session)
		})
	}
	daemon.syncKernelDatapathSessionRecords(key, runtime, session)
}

func (daemon *Daemon) syncKernelDatapathSessionStateChange(key dataSessionKey, runtime *dataSessionRuntime, session transport.Session) {
	if daemon == nil || session == nil {
		return
	}
	daemon.syncKernelDatapathSessionRecords(key, runtime, session)
}

func (daemon *Daemon) syncKernelDatapathSessionRecords(key dataSessionKey, runtime *dataSessionRuntime, session transport.Session) {
	daemon.kernelDatapathStateMu.Lock()
	defer daemon.kernelDatapathStateMu.Unlock()

	if !daemon.kernelDatapathSessionIsCurrent(key, runtime, session) {
		return
	}
	if !daemon.kernelDatapathAvailable() {
		return
	}
	records := daemon.kernelDatapathSessionStateRecords(key, runtime, session)
	if len(records) == 0 {
		return
	}
	records = append(records, daemon.kernelDatapathFullPlaintextRouteSessionRecords(
		context.Background(), daemon.runtimeDataplaneSnapshot().Routes,
	)...)
	records = append(records, daemon.kernelDatapathKernelUDPFlowRecords(context.Background())...)
	if err := daemon.applyKernelDatapathStateRecords(context.Background(), records); err != nil {
		daemon.recordBackgroundError("kernel_datapath_state_sync", fmt.Errorf("upsert kernel datapath session: %w", err))
		daemon.requestRuntimeReconcile("kernel datapath session upsert", err)
		return
	}
	if err := daemon.commitTIXTCPCryptoStateRecords(context.Background(), records); err != nil {
		daemon.recordBackgroundError("kernel_datapath_crypto_state_sync", fmt.Errorf("commit tix_tcp crypto state: %w", err))
		daemon.requestRuntimeReconcile("kernel datapath crypto state commit", err)
	}
}

func (daemon *Daemon) syncKernelDatapathSessionDelete(key dataSessionKey, session transport.Session) {
	daemon.syncKernelDatapathSessionDeleteWithRetention(key, session, false)
}

func (daemon *Daemon) syncKernelDatapathSessionDeleteRetainingFlow(key dataSessionKey, session transport.Session) {
	daemon.syncKernelDatapathSessionDeleteWithRetention(key, session, true)
}

func (daemon *Daemon) syncKernelDatapathSessionDeleteWithRetention(key dataSessionKey, session transport.Session, retainFlow bool) {
	daemon.kernelDatapathStateMu.Lock()
	defer daemon.kernelDatapathStateMu.Unlock()

	flowID, releaseCrypto := kernelDatapathSecureTIXTCPFlowID(session)
	releaseCrypto = releaseCrypto && !retainFlow
	currentSession, currentRuntime, current := daemon.kernelDatapathSessionAndRuntimeForKey(key)
	if current && currentSession == session {
		return
	}
	currentFlowID, _ := kernelDatapathSecureTIXTCPFlowID(currentSession)
	releaseCrypto = releaseCrypto && currentFlowID != flowID
	if !daemon.kernelDatapathAvailable() {
		if releaseCrypto {
			daemon.releaseTIXTCPCryptoState(context.Background(), flowID)
		}
		return
	}
	records := daemon.kernelDatapathSessionDeleteRecords(key)
	if current {
		records = append(records, daemon.kernelDatapathSessionStateRecords(key, currentRuntime, currentSession)...)
		records = append(records, daemon.kernelDatapathFullPlaintextRouteSessionRecords(
			context.Background(), daemon.runtimeDataplaneSnapshot().Routes,
		)...)
	}
	records = append(records, daemon.kernelDatapathKernelUDPFlowRecords(context.Background())...)
	if err := daemon.applyKernelDatapathStateRecords(context.Background(), records); err != nil {
		daemon.recordBackgroundError("kernel_datapath_state_sync", fmt.Errorf("delete kernel datapath session: %w", err))
		daemon.requestRuntimeReconcile("kernel datapath session delete", err)
		return
	}
	if current {
		if err := daemon.commitTIXTCPCryptoStateRecords(context.Background(), records); err != nil {
			daemon.recordBackgroundError("kernel_datapath_crypto_state_sync", fmt.Errorf("commit replacement tix_tcp crypto state: %w", err))
			daemon.requestRuntimeReconcile("kernel datapath replacement crypto state commit", err)
			return
		}
	}
	if releaseCrypto {
		daemon.releaseTIXTCPCryptoState(context.Background(), flowID)
	}
}

func (daemon *Daemon) kernelDatapathSessionDeleteRecords(key dataSessionKey) []kernelmodule.DatapathStateRecord {
	stateKey := kernelDatapathSessionStateKey(key)
	records := []kernelmodule.DatapathStateRecord{
		{Kind: kernelmodule.TrustIXDatapathStateKindSession, Op: kernelmodule.TrustIXDatapathStateOpDelete, Key: stateKey},
		{Kind: kernelmodule.TrustIXDatapathStateKindSessionWire, Op: kernelmodule.TrustIXDatapathStateOpDelete, Key: stateKey},
	}
	if daemon.kernelDatapathSecureTIXTCPReady() {
		records = append(records, kernelmodule.DatapathStateRecord{
			Kind: kernelmodule.TrustIXDatapathStateKindSessionCrypto,
			Op:   kernelmodule.TrustIXDatapathStateOpDelete,
			Key:  stateKey,
		})
	}
	return records
}

func kernelDatapathSecureTIXTCPFlowID(session transport.Session) (uint64, bool) {
	info, ok := kernelDatapathSessionInfo(session)
	return info.FlowID, ok && info.FlowID != 0 &&
		info.Protocol == transport.ProtocolTIXTCP && info.Encrypted &&
		info.CryptoPlacement == string(dataplane.CryptoPlacementKernel)
}

func (daemon *Daemon) commitTIXTCPCryptoStateRecords(ctx context.Context, records []kernelmodule.DatapathStateRecord) error {
	lifecycle, ok := daemon.dataplane.(dataplane.TIXTCPCryptoStateLifecycle)
	if !ok {
		return nil
	}
	var resultErr error
	for _, record := range records {
		if record.Kind != kernelmodule.TrustIXDatapathStateKindSessionCrypto ||
			record.Op != kernelmodule.TrustIXDatapathStateOpUpsert ||
			record.Value[0] == 0 {
			continue
		}
		resultErr = errors.Join(resultErr, lifecycle.CommitTIXTCPCryptoState(ctx, record.Value[0], record.Value[1]))
	}
	return resultErr
}

func (daemon *Daemon) releaseTIXTCPCryptoState(ctx context.Context, flowID uint64) {
	lifecycle, ok := daemon.dataplane.(dataplane.TIXTCPCryptoStateLifecycle)
	if !ok || flowID == 0 {
		return
	}
	if err := lifecycle.ReleaseTIXTCPCryptoState(ctx, flowID); err != nil {
		daemon.recordBackgroundError("kernel_datapath_crypto_state_sync", fmt.Errorf("release tix_tcp crypto state for flow %d: %w", flowID, err))
		daemon.requestRuntimeReconcile("kernel datapath crypto state release", err)
	}
}

func (daemon *Daemon) releaseRetiredTIXTCPCryptoStates(ctx context.Context) error {
	lifecycle, ok := daemon.dataplane.(dataplane.TIXTCPCryptoStateLifecycle)
	if !ok {
		return nil
	}
	return lifecycle.ReleaseRetiredTIXTCPCryptoStates(ctx)
}

func (daemon *Daemon) syncKernelDatapathFlowUpsert(binding routing.FlowBinding) {
	daemon.kernelDatapathStateMu.Lock()
	defer daemon.kernelDatapathStateMu.Unlock()

	current, ok := daemon.kernelDatapathFlowForKey(binding.Key)
	if !ok {
		return
	}
	if !daemon.kernelDatapathAvailable() {
		return
	}
	record, ok := kernelDatapathFlowRecord(current)
	if !ok {
		return
	}
	if err := daemon.applyKernelDatapathStateRecords(context.Background(), []kernelmodule.DatapathStateRecord{record}); err != nil {
		daemon.recordBackgroundError("kernel_datapath_state_sync", fmt.Errorf("upsert kernel datapath flow: %w", err))
		daemon.requestRuntimeReconcile("kernel datapath flow upsert", err)
	}
}

func (daemon *Daemon) syncKernelDatapathFlowDelete(key routing.FlowKey) {
	daemon.kernelDatapathStateMu.Lock()
	defer daemon.kernelDatapathStateMu.Unlock()

	if !daemon.kernelDatapathAvailable() {
		return
	}
	current, currentExists := daemon.kernelDatapathFlowForKey(key)
	var record kernelmodule.DatapathStateRecord
	var ok bool
	if currentExists {
		record, ok = kernelDatapathFlowRecord(current)
	} else {
		record, ok = kernelDatapathFlowDeleteRecord(key)
	}
	if !ok {
		return
	}
	if err := daemon.applyKernelDatapathStateRecords(context.Background(), []kernelmodule.DatapathStateRecord{record}); err != nil {
		daemon.recordBackgroundError("kernel_datapath_state_sync", fmt.Errorf("delete kernel datapath flow: %w", err))
		daemon.requestRuntimeReconcile("kernel datapath flow delete", err)
	}
}

func (daemon *Daemon) kernelDatapathSessionIsCurrent(key dataSessionKey, runtime *dataSessionRuntime, session transport.Session) bool {
	currentSession, currentRuntime, ok := daemon.kernelDatapathSessionAndRuntimeForKey(key)
	return ok && currentSession == session && currentRuntime == runtime
}

func (daemon *Daemon) kernelDatapathSessionAndRuntimeForKey(key dataSessionKey) (transport.Session, *dataSessionRuntime, bool) {
	daemon.dataMu.Lock()
	defer daemon.dataMu.Unlock()
	session, ok := daemon.dataSessions[key]
	if !ok || session == nil {
		return nil, nil, false
	}
	return session, daemon.dataSessionState[key], true
}

func (daemon *Daemon) kernelDatapathFlowForKey(key routing.FlowKey) (routing.FlowBinding, bool) {
	daemon.flowMu.RLock()
	defer daemon.flowMu.RUnlock()
	binding, ok := daemon.flows[key]
	return binding, ok
}

func (daemon *Daemon) kernelDatapathAvailable() bool {
	return daemon != nil && daemon.kernelDatapath != nil && daemon.kernelDatapath.Snapshot().Loaded
}

func (daemon *Daemon) applyKernelDatapathStateRecords(ctx context.Context, records []kernelmodule.DatapathStateRecord) error {
	total := len(records)
	for len(records) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		limit := len(records)
		if limit > kernelmodule.TrustIXDatapathStateBatchMax {
			limit = kernelmodule.TrustIXDatapathStateBatchMax
		}
		applied, _, err := kernelDatapathApplyStateBatch(kernelmodule.TrustIXDatapathDevicePath, records[:limit])
		if applied > uint32(limit) {
			return fmt.Errorf("apply kernel datapath state returned invalid applied count %d for batch of %d", applied, limit)
		}
		if err != nil {
			if applied == 0 {
				return fmt.Errorf("apply kernel datapath state after %d of %d records: %w", total-len(records), total, err)
			}
			records = records[int(applied):]
			continue
		}
		if applied != uint32(limit) {
			return fmt.Errorf("apply kernel datapath state applied %d of %d records without an error", applied, limit)
		}
		records = records[limit:]
	}
	return nil
}

func (daemon *Daemon) kernelDatapathSessionSnapshot() []kernelDatapathSessionSnapshot {
	if daemon == nil {
		return nil
	}
	daemon.dataMu.Lock()
	defer daemon.dataMu.Unlock()
	sessions := make([]kernelDatapathSessionSnapshot, 0, len(daemon.dataSessions))
	for key, session := range daemon.dataSessions {
		if session == nil {
			continue
		}
		sessions = append(sessions, kernelDatapathSessionSnapshot{
			key:     key,
			runtime: daemon.dataSessionState[key],
			session: session,
		})
	}
	sort.Slice(sessions, func(i, j int) bool {
		left := sessions[i].key
		right := sessions[j].key
		if left.Peer != right.Peer {
			return left.Peer < right.Peer
		}
		if left.Endpoint != right.Endpoint {
			return left.Endpoint < right.Endpoint
		}
		if left.Transport != right.Transport {
			return left.Transport < right.Transport
		}
		if left.Address != right.Address {
			return left.Address < right.Address
		}
		if left.Encryption != right.Encryption {
			return left.Encryption < right.Encryption
		}
		return left.PoolIndex < right.PoolIndex
	})
	return sessions
}

func (daemon *Daemon) kernelDatapathSessionAndWireRecords(key dataSessionKey, runtime *dataSessionRuntime, session transport.Session) (kernelmodule.DatapathStateRecord, kernelmodule.DatapathStateRecord, bool) {
	sessionRecord, ok := kernelDatapathSessionRecord(key, runtime, session)
	if !ok {
		return kernelmodule.DatapathStateRecord{}, kernelmodule.DatapathStateRecord{}, false
	}
	wireRecord, ok := daemon.kernelDatapathSessionWireRecord(key, session)
	if !ok {
		return kernelmodule.DatapathStateRecord{}, kernelmodule.DatapathStateRecord{}, false
	}
	return sessionRecord, wireRecord, true
}

func (daemon *Daemon) kernelDatapathSessionStateRecords(key dataSessionKey, runtime *dataSessionRuntime, session transport.Session) []kernelmodule.DatapathStateRecord {
	sessionRecord, ok := kernelDatapathSessionRecord(key, runtime, session)
	if !ok {
		return nil
	}
	records := []kernelmodule.DatapathStateRecord{sessionRecord}
	wireRecord, ok := daemon.kernelDatapathSessionWireRecord(key, session)
	if !ok {
		return records
	}
	records = append(records, wireRecord)
	if cryptoRecord, ok := daemon.kernelDatapathSessionCryptoRecord(key, session); ok {
		records = append(records, cryptoRecord)
	}
	return records
}

func (daemon *Daemon) kernelDatapathSessionCryptoRecord(key dataSessionKey, session transport.Session) (kernelmodule.DatapathStateRecord, bool) {
	if daemon == nil || daemon.dataplane == nil || !daemon.kernelDatapathSecureTIXTCPReady() {
		return kernelmodule.DatapathStateRecord{}, false
	}
	info, ok := kernelDatapathSessionInfo(session)
	if !ok || info.FlowID == 0 || info.Protocol != transport.ProtocolTIXTCP || !info.Encrypted || info.CryptoPlacement != string(dataplane.CryptoPlacementKernel) {
		return kernelmodule.DatapathStateRecord{}, false
	}
	lookup, ok := daemon.dataplane.(dataplane.TIXTCPCryptoStateLookup)
	if !ok {
		return kernelmodule.DatapathStateRecord{}, false
	}
	state, found, err := lookup.TIXTCPCryptoState(context.Background(), info.FlowID)
	if err != nil {
		daemon.recordBackgroundError("kernel_datapath_crypto_state_sync", err)
		return kernelmodule.DatapathStateRecord{}, false
	}
	if !found || state.FlowID != info.FlowID || state.Send.Epoch != state.Receive.Epoch || state.Send.Epoch != info.Epoch || state.Send.Suite == 0 || state.Send.Suite != state.Receive.Suite || state.Send.WireFormat == 0 || state.Send.WireFormat != state.Receive.WireFormat || state.Send.ReplayWindow == 0 || state.Receive.ReplayWindow == 0 {
		return kernelmodule.DatapathStateRecord{}, false
	}
	return kernelmodule.DatapathStateRecord{
		Kind:  kernelmodule.TrustIXDatapathStateKindSessionCrypto,
		Op:    kernelmodule.TrustIXDatapathStateOpUpsert,
		Flags: kernelDatapathSessionCryptoFlagSendReady | kernelDatapathSessionCryptoFlagReceiveReady,
		Key:   kernelDatapathSessionStateKey(key),
		Value: [8]uint64{
			state.FlowID,
			state.Send.Epoch,
			uint64(state.Send.SlotID) | uint64(state.Receive.SlotID)<<32,
			uint64(state.Send.Suite) | uint64(state.Send.WireFormat)<<16 | uint64(state.Receive.ReplayWindow)<<32,
			kernelDatapathPackBytes8(state.Send.IV[:8]),
			uint64(kernelDatapathPackBytes4(state.Send.IV[8:])) | uint64(kernelDatapathPackBytes4(state.Receive.IV[:4]))<<32,
			kernelDatapathPackBytes8(state.Receive.IV[4:]),
			state.Receive.LastSequence,
		},
	}, true
}

func kernelDatapathPackBytes4(value []byte) uint32 {
	if len(value) < 4 {
		return 0
	}
	return uint32(value[0]) | uint32(value[1])<<8 | uint32(value[2])<<16 | uint32(value[3])<<24
}

func kernelDatapathPackBytes8(value []byte) uint64 {
	if len(value) < 8 {
		return 0
	}
	return uint64(kernelDatapathPackBytes4(value[:4])) | uint64(kernelDatapathPackBytes4(value[4:8]))<<32
}

func (daemon *Daemon) kernelDatapathSecureTIXTCPReady() bool {
	if daemon == nil || daemon.kernelDatapath == nil {
		return false
	}
	status := daemon.kernelDatapath.Snapshot()
	return status.Loaded && status.HasFeature(kernelmodule.FeatureSecureTIXTCPFullDatapath)
}

func (daemon *Daemon) kernelDatapathFullPlaintextRouteSessionRecords(ctx context.Context, routes []routing.Route) []kernelmodule.DatapathStateRecord {
	if daemon == nil || !kernelDatapathFullPlaintextEnabledForDesired(daemon.desired) {
		return nil
	}
	records := make([]kernelmodule.DatapathStateRecord, 0, len(routes)*2)
	for _, route := range routes {
		if ctx.Err() != nil {
			return records
		}
		if route.NextHop == "" || route.Kind != "" && route.Kind != routing.RouteUnicast {
			continue
		}
		peer, ok := daemon.peerConfig(route.NextHop)
		if !ok {
			continue
		}
		candidates, _, err := daemon.candidatePeerEndpoints(peer, route, routing.FlowKey{}, false)
		if err != nil {
			continue
		}
		for _, endpoint := range candidates {
			if !daemon.kernelDatapathFullPlaintextEndpointCompatible(endpoint) {
				continue
			}
			local, ok := daemon.kernelDatapathFullPlaintextLocalEndpoint(endpoint)
			if !ok {
				continue
			}
			for _, poolIndex := range daemon.kernelDatapathFullPlaintextEndpointPoolIndexes(peer, endpoint) {
				sessionRecord, wireRecord, ok := daemon.kernelDatapathFullPlaintextEndpointRecords(ctx, peer, endpoint, local, poolIndex)
				if !ok {
					continue
				}
				records = append(records, sessionRecord, wireRecord)
			}
			break
		}
	}
	return records
}

func (daemon *Daemon) kernelDatapathFullPlaintextEndpointCompatible(endpoint config.EndpointConfig) bool {
	if strings.TrimSpace(endpoint.Address) == "" {
		return false
	}
	switch transport.Protocol(strings.ToLower(strings.TrimSpace(endpoint.Transport))) {
	case transport.ProtocolUDP, transport.ProtocolTIXTCP:
	default:
		return false
	}
	if parseSecureTransportEncryption(daemon.endpointDialEncryption(endpoint)) != securetransport.EncryptionPlaintext {
		return false
	}
	return daemon.endpointSecurityCompatible(endpoint) && daemon.endpointTransportProfileCompatible(endpoint)
}

func (daemon *Daemon) kernelDatapathFullPlaintextLocalEndpoint(remote config.EndpointConfig) (config.EndpointConfig, bool) {
	var fallback config.EndpointConfig
	hasFallback := false
	remoteTransport := strings.ToLower(strings.TrimSpace(remote.Transport))
	for _, endpoint := range daemon.desired.Endpoints {
		if !endpoint.Enabled ||
			endpoint.Mode != config.EndpointModePassive ||
			strings.ToLower(strings.TrimSpace(endpoint.Transport)) != remoteTransport ||
			strings.TrimSpace(endpoint.Listen) == "" {
			continue
		}
		if parseSecureTransportEncryption(daemon.endpointDialEncryption(endpoint)) != securetransport.EncryptionPlaintext {
			continue
		}
		if !daemon.endpointSecurityCompatible(endpoint) || !daemon.endpointTransportProfileCompatible(endpoint) {
			continue
		}
		if endpoint.Name == remote.Name {
			return endpoint, true
		}
		if !hasFallback {
			fallback = endpoint
			hasFallback = true
		}
	}
	return fallback, hasFallback
}

func (daemon *Daemon) kernelDatapathFullPlaintextEndpointPoolIndexes(peer config.PeerConfig, endpoint config.EndpointConfig) []int {
	if daemon == nil {
		return []int{0}
	}
	protocol := transport.Protocol(strings.ToLower(strings.TrimSpace(endpoint.Transport)))
	indexes := map[int]bool{}
	for _, item := range daemon.kernelDatapathSessionSnapshot() {
		key := item.key
		address := strings.TrimSpace(key.Address)
		if key.Peer != peer.ID ||
			key.Endpoint != endpoint.Name ||
			key.Transport != protocol ||
			(address != strings.TrimSpace(endpoint.Address) && address != reverseSessionAddress) ||
			parseSecureTransportEncryption(key.Encryption) != securetransport.EncryptionPlaintext ||
			key.PoolIndex < 0 {
			continue
		}
		indexes[key.PoolIndex] = true
	}
	if len(indexes) == 0 {
		return []int{0}
	}
	out := make([]int, 0, len(indexes))
	for index := range indexes {
		out = append(out, index)
	}
	sort.Ints(out)
	return out
}

func (daemon *Daemon) kernelDatapathFullPlaintextEndpointRecords(ctx context.Context, peer config.PeerConfig, endpoint config.EndpointConfig, local config.EndpointConfig, poolIndex int) (kernelmodule.DatapathStateRecord, kernelmodule.DatapathStateRecord, bool) {
	if poolIndex < 0 {
		poolIndex = 0
	}
	key := dataSessionKey{
		Peer:       peer.ID,
		Endpoint:   endpoint.Name,
		Transport:  transport.Protocol(strings.ToLower(strings.TrimSpace(endpoint.Transport))),
		Address:    kernelDatapathFullPlaintextAddressPrefix + strings.TrimSpace(endpoint.Address),
		Encryption: securetransport.EncryptionPlaintext,
		PoolIndex:  poolIndex,
	}
	localIP, localPort, remoteIP, remotePort, ok := kernelDatapathFullPlaintextWireTuple(ctx, local, endpoint)
	if !ok {
		return kernelmodule.DatapathStateRecord{}, kernelmodule.DatapathStateRecord{}, false
	}
	flowID := kernelDatapathFullPlaintextFlowID(key.Transport, localIP, localPort, remoteIP, remotePort)
	flags := kernelDatapathSessionFlagKernelFlow |
		kernelDatapathSessionFlagCryptoUserspace |
		kernelDatapathSessionFlagSyntheticFallback
	if key.Transport == transport.ProtocolTIXTCP {
		sendPartial, receivePartial := daemon.kernelDatapathFullPlaintextEndpointInnerTCPChecksumPartial(peer, endpoint, poolIndex)
		if sendPartial {
			flags |= kernelDatapathSessionFlagSendInnerTCPChecksumPartial
		}
		if receivePartial {
			flags |= kernelDatapathSessionFlagReceiveInnerTCPChecksumPartial
		}
		sendGSO, receiveGSO := daemon.kernelDatapathFullPlaintextEndpointInnerGSO(peer, endpoint, poolIndex)
		if sendGSO {
			flags |= kernelDatapathSessionFlagSendInnerGSO
		}
		if receiveGSO {
			flags |= kernelDatapathSessionFlagReceiveInnerGSO
		}
		sendPortSharding, receivePortSharding := daemon.kernelDatapathFullPlaintextEndpointPortSharding(peer, endpoint, poolIndex)
		if sendPortSharding {
			flags |= kernelDatapathSessionFlagSendTIXTCPPortSharding
		}
		if receivePortSharding {
			flags |= kernelDatapathSessionFlagReceiveTIXTCPPortSharding
		}
	}
	if key.Transport == transport.ProtocolUDP {
		flags |= kernelDatapathSessionFlagDatagram |
			kernelDatapathSessionFlagNativeBatching |
			kernelDatapathSessionFlagFragmentingDatagram
	}
	now := kernelDatapathUnixNano(time.Now().UTC().UnixNano())
	session := kernelmodule.DatapathStateRecord{
		Kind:  kernelmodule.TrustIXDatapathStateKindSession,
		Op:    kernelmodule.TrustIXDatapathStateOpUpsert,
		Flags: flags,
		Key:   kernelDatapathSessionStateKey(key),
		Value: [8]uint64{
			flowID,
			uint64(kernelDatapathTransportCode(key.Transport)),
			0,
			0,
			uint64(kernelDatapathCryptoPlacementCode(string(dataplane.CryptoPlacementUserspace))),
			now,
			now,
			uint64(uint32(poolIndex)),
		},
	}
	wire := kernelmodule.DatapathStateRecord{
		Kind:  kernelmodule.TrustIXDatapathStateKindSessionWire,
		Op:    kernelmodule.TrustIXDatapathStateOpUpsert,
		Flags: kernelDatapathSessionWireFlagIPv4 | kernelDatapathSessionWireFlagLocalKnown | kernelDatapathSessionWireFlagRemoteKnown,
		Key:   session.Key,
		Value: [8]uint64{
			flowID,
			uint64(localIP),
			uint64(remoteIP),
			uint64(localPort)<<16 | uint64(remotePort),
			uint64(kernelDatapathTransportCode(key.Transport)),
			0,
			0,
			uint64(uint32(poolIndex)),
		},
	}
	return session, wire, true
}

func (daemon *Daemon) kernelDatapathFullPlaintextEndpointInnerTCPChecksumPartial(peer config.PeerConfig, endpoint config.EndpointConfig, poolIndex int) (send, receive bool) {
	if daemon == nil || transport.Protocol(strings.ToLower(strings.TrimSpace(endpoint.Transport))) != transport.ProtocolTIXTCP {
		return false, false
	}
	receive = daemon.kernelDatapathInnerTCPChecksumPartialReady()
	address := strings.TrimSpace(endpoint.Address)
	for _, item := range daemon.kernelDatapathSessionSnapshot() {
		key := item.key
		if key.Peer != peer.ID ||
			key.Endpoint != endpoint.Name ||
			key.Transport != transport.ProtocolTIXTCP ||
			(strings.TrimSpace(key.Address) != address && key.Address != reverseSessionAddress) ||
			parseSecureTransportEncryption(key.Encryption) != securetransport.EncryptionPlaintext ||
			key.PoolIndex != poolIndex {
			continue
		}
		info, ok := kernelDatapathSessionInfo(item.session)
		if !ok {
			continue
		}
		receive = receive || info.InnerTCPChecksumPartialLocal
		send = send || info.InnerTCPChecksumPartialNegotiated
	}
	return send, receive
}

func (daemon *Daemon) kernelDatapathInnerTCPChecksumPartialReady() bool {
	if daemon == nil || daemon.kernelDatapath == nil {
		return false
	}
	status := daemon.kernelDatapath.Snapshot()
	return status.Loaded && status.HasFeature(kernelmodule.FeatureInnerTCPChecksumPartial)
}

func (daemon *Daemon) kernelDatapathFullPlaintextEndpointInnerGSO(peer config.PeerConfig, endpoint config.EndpointConfig, poolIndex int) (send, receive bool) {
	if daemon == nil || transport.Protocol(strings.ToLower(strings.TrimSpace(endpoint.Transport))) != transport.ProtocolTIXTCP {
		return false, false
	}
	address := strings.TrimSpace(endpoint.Address)
	for _, item := range daemon.kernelDatapathSessionSnapshot() {
		key := item.key
		if key.Peer != peer.ID || key.Endpoint != endpoint.Name || key.Transport != transport.ProtocolTIXTCP ||
			(strings.TrimSpace(key.Address) != address && key.Address != reverseSessionAddress) ||
			parseSecureTransportEncryption(key.Encryption) != securetransport.EncryptionPlaintext || key.PoolIndex != poolIndex {
			continue
		}
		info, ok := kernelDatapathSessionInfo(item.session)
		if !ok {
			continue
		}
		receive = receive || info.InnerGSOLocal
		send = send || info.InnerGSONegotiated
	}
	return send, receive
}

func (daemon *Daemon) kernelDatapathFullPlaintextEndpointPortSharding(peer config.PeerConfig, endpoint config.EndpointConfig, poolIndex int) (send, receive bool) {
	if daemon == nil || transport.Protocol(strings.ToLower(strings.TrimSpace(endpoint.Transport))) != transport.ProtocolTIXTCP {
		return false, false
	}
	receive = daemon.kernelDatapathTIXTCPPortShardingReady()
	address := strings.TrimSpace(endpoint.Address)
	for _, item := range daemon.kernelDatapathSessionSnapshot() {
		key := item.key
		if key.Peer != peer.ID || key.Endpoint != endpoint.Name || key.Transport != transport.ProtocolTIXTCP ||
			(strings.TrimSpace(key.Address) != address && key.Address != reverseSessionAddress) ||
			parseSecureTransportEncryption(key.Encryption) != securetransport.EncryptionPlaintext || key.PoolIndex != poolIndex {
			continue
		}
		info, ok := kernelDatapathSessionInfo(item.session)
		if !ok {
			continue
		}
		receive = receive || info.TIXTCPPortShardingLocal
		send = send || info.TIXTCPPortShardingNegotiated
	}
	return send, receive
}

func (daemon *Daemon) kernelDatapathTIXTCPPortShardingReady() bool {
	if daemon == nil || daemon.kernelDatapath == nil {
		return false
	}
	status := daemon.kernelDatapath.Snapshot()
	return status.Loaded && status.HasFeature(kernelmodule.FeatureTIXTCPPortSharding)
}

func kernelDatapathFullPlaintextFlowID(protocol transport.Protocol, localIP uint32, localPort uint16, remoteIP uint32, remotePort uint16) uint64 {
	leftIP, leftPort := localIP, localPort
	rightIP, rightPort := remoteIP, remotePort
	if rightIP < leftIP || rightIP == leftIP && rightPort < leftPort {
		leftIP, rightIP = rightIP, leftIP
		leftPort, rightPort = rightPort, leftPort
	}
	flowID := hashString64("full_plaintext\x00" +
		string(protocol) + "\x00" +
		strconv.FormatUint(uint64(leftIP), 10) + ":" + strconv.FormatUint(uint64(leftPort), 10) + "\x00" +
		strconv.FormatUint(uint64(rightIP), 10) + ":" + strconv.FormatUint(uint64(rightPort), 10))
	if flowID == 0 {
		return 1
	}
	return flowID
}

func kernelDatapathFullPlaintextWireTuple(ctx context.Context, local config.EndpointConfig, remote config.EndpointConfig) (uint32, uint16, uint32, uint16, bool) {
	remoteIP, remotePort, ok := kernelDatapathResolveIPv4AddrPort(remote.Address)
	if !ok || remoteIP == 0 || remotePort == 0 {
		return 0, 0, 0, 0, false
	}
	localPort, ok := kernelDatapathEndpointListenPort(local)
	if !ok || localPort == 0 {
		return 0, 0, 0, 0, false
	}
	if sourceIP := strings.TrimSpace(local.LocalBind.SourceIP); sourceIP != "" {
		if ip, ok := kernelDatapathParseIPv4Addr(sourceIP); ok && ip != 0 {
			return ip, localPort, remoteIP, remotePort, true
		}
	}
	localIP, _, ok := kernelDatapathResolveIPv4AddrPort(local.Listen)
	if (!ok || localIP == 0) && strings.TrimSpace(local.Address) != "" {
		localIP, _, ok = kernelDatapathResolveIPv4AddrPort(local.Address)
	}
	if !ok || localIP == 0 {
		if ip, err := kernelDatapathRouteSourceIPv4(ctx, remoteIP, remotePort); err == nil {
			localIP = ip
			ok = true
		}
	}
	if !ok || localIP == 0 {
		return 0, 0, 0, 0, false
	}
	return localIP, localPort, remoteIP, remotePort, true
}

func kernelDatapathEndpointListenPort(endpoint config.EndpointConfig) (uint16, bool) {
	if _, port, ok := kernelDatapathResolveIPv4AddrPort(endpoint.Listen); ok && port != 0 {
		return port, true
	}
	if _, port, ok := kernelDatapathResolveIPv4AddrPort(endpoint.Address); ok && port != 0 {
		return port, true
	}
	return 0, false
}

func kernelDatapathResolveIPv4AddrPort(address string) (uint32, uint16, bool) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return 0, 0, false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return 0, 0, false
	}
	ip, ok := kernelDatapathResolveIPv4Host(host)
	return ip, uint16(port), ok
}

func kernelDatapathResolveIPv4Host(host string) (uint32, bool) {
	host = strings.Trim(host, "[]")
	if host == "" {
		return 0, false
	}
	if ip, ok := kernelDatapathParseIPv4Addr(host); ok {
		return ip, true
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return 0, false
	}
	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		return binary.BigEndian.Uint32(ip4), true
	}
	return 0, false
}

func kernelDatapathParseIPv4Addr(raw string) (uint32, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || !addr.Is4() || addr.IsUnspecified() {
		return 0, false
	}
	ip := addr.As4()
	return binary.BigEndian.Uint32(ip[:]), true
}

func kernelDatapathRouteSourceIPv4(ctx context.Context, remoteIP uint32, remotePort uint16) (source uint32, resultErr error) {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], remoteIP)
	addr := netip.AddrFrom4(raw)
	dialer := net.Dialer{Timeout: 500 * time.Millisecond}
	conn, err := dialer.DialContext(ctx, "udp4", net.JoinHostPort(addr.String(), strconv.Itoa(int(remotePort))))
	if err != nil {
		return 0, err
	}
	defer func() {
		if err := conn.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close kernel datapath route probe: %w", err))
		}
	}()
	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || udpAddr.IP == nil {
		return 0, net.InvalidAddrError("local UDP address is unavailable")
	}
	ip4 := udpAddr.IP.To4()
	if ip4 == nil {
		return 0, net.InvalidAddrError("local UDP address is not IPv4")
	}
	return binary.BigEndian.Uint32(ip4), nil
}

func (daemon *Daemon) kernelDatapathKernelUDPFlowRecords(ctx context.Context) []kernelmodule.DatapathStateRecord {
	if daemon == nil || daemon.dataplane == nil {
		return nil
	}
	snapshotter, ok := daemon.dataplane.(dataplane.KernelUDPFlowSnapshotter)
	if !ok {
		return nil
	}
	flows, err := snapshotter.KernelUDPFlows(ctx)
	if err != nil || len(flows) == 0 {
		return nil
	}
	sessionFlowIDs := daemon.kernelDatapathSessionFlowIDs()
	records := make([]kernelmodule.DatapathStateRecord, 0, len(flows)*2)
	for _, flow := range flows {
		if ctx.Err() != nil {
			return records
		}
		if flow.ID == 0 || sessionFlowIDs[flow.ID] {
			continue
		}
		sessionRecord, sessionOK := kernelDatapathKernelUDPFlowSessionRecord(flow)
		wireRecord, wireOK := kernelDatapathKernelUDPFlowSessionWireRecord(flow)
		if sessionOK && wireOK {
			records = append(records, sessionRecord, wireRecord)
		}
	}
	return records
}

func (daemon *Daemon) kernelDatapathSessionFlowIDs() map[uint64]bool {
	ids := make(map[uint64]bool)
	for _, item := range daemon.kernelDatapathSessionSnapshot() {
		info, ok := kernelDatapathSessionInfo(item.session)
		if ok && info.FlowID != 0 {
			ids[info.FlowID] = true
		}
	}
	return ids
}

func kernelDatapathRouteRecord(route routing.Route) (kernelmodule.DatapathStateRecord, bool) {
	prefix, err := route.Prefix.Parse()
	if err != nil || !prefix.Addr().Is4() {
		return kernelmodule.DatapathStateRecord{}, false
	}
	prefix = prefix.Masked()
	addr := prefix.Addr().As4()
	record := kernelmodule.DatapathStateRecord{
		Kind:  kernelmodule.TrustIXDatapathStateKindRoute,
		Op:    kernelmodule.TrustIXDatapathStateOpUpsert,
		Flags: kernelDatapathRouteKindFlag(route.Kind),
		Key: [4]uint64{
			uint64(binary.BigEndian.Uint32(addr[:])),
			uint64(prefix.Bits()),
			hashString64(string(route.NextHop)),
			hashString64(string(route.Endpoint)),
		},
		Value: [8]uint64{
			uint64(route.Metric),
			hashString64(string(route.Owner)),
			hashString64(string(route.Policy)),
			hashString64(route.Source),
		},
	}
	if route.LocalProtocol != 0 || route.LocalPort != 0 {
		record.Value[4] = uint64(route.LocalProtocol)
		record.Value[5] = uint64(route.LocalPort)
	}
	return record, true
}

func kernelDatapathSessionRecord(key dataSessionKey, runtime *dataSessionRuntime, session transport.Session) (kernelmodule.DatapathStateRecord, bool) {
	info, ok := kernelDatapathSessionInfo(session)
	if !ok || info.FlowID == 0 {
		return kernelmodule.DatapathStateRecord{}, false
	}
	if info.Protocol == "" {
		info.Protocol = key.Transport
	}
	record := kernelmodule.DatapathStateRecord{
		Kind:  kernelmodule.TrustIXDatapathStateKindSession,
		Op:    kernelmodule.TrustIXDatapathStateOpUpsert,
		Flags: kernelDatapathSessionFlags(key, runtime, info),
		Key:   kernelDatapathSessionStateKey(key),
		Value: [8]uint64{
			info.FlowID,
			uint64(kernelDatapathTransportCode(info.Protocol)),
			info.Epoch,
			hashString64(info.CryptoSuite),
			uint64(kernelDatapathCryptoPlacementCode(info.CryptoPlacement)),
			kernelDatapathRuntimeLastRX(runtime),
			kernelDatapathRuntimeLastTX(runtime),
			uint64(uint32(key.PoolIndex)),
		},
	}
	return record, true
}

func kernelDatapathKernelUDPFlowSessionRecord(flow dataplane.KernelUDPFlow) (kernelmodule.DatapathStateRecord, bool) {
	key, ok := kernelDatapathKernelUDPFlowSessionKey(flow)
	if !ok {
		return kernelmodule.DatapathStateRecord{}, false
	}
	record := kernelmodule.DatapathStateRecord{
		Kind: kernelmodule.TrustIXDatapathStateKindSession,
		Op:   kernelmodule.TrustIXDatapathStateOpUpsert,
		Flags: kernelDatapathSessionFlagKernelFlow |
			kernelDatapathSessionFlagDatagram |
			kernelDatapathSessionFlagNativeBatching,
		Key: key,
		Value: [8]uint64{
			flow.ID,
			uint64(kernelDatapathTransportCode(transport.ProtocolUDP)),
			flow.Epoch,
			hashString64(flow.CryptoSuite),
			uint64(kernelDatapathCryptoPlacementCode(string(flow.CryptoPlacement))),
			kernelDatapathUnixNano(flow.LastSeen.UnixNano()),
			kernelDatapathUnixNano(flow.LastSeen.UnixNano()),
			0,
		},
	}
	switch flow.CryptoPlacement {
	case dataplane.CryptoPlacementKernel:
		record.Flags |= kernelDatapathSessionFlagCryptoKernel
	case dataplane.CryptoPlacementUserspace:
		record.Flags |= kernelDatapathSessionFlagCryptoUserspace
	}
	if flow.CryptoSuite != "" {
		record.Flags |= kernelDatapathSessionFlagEncrypted
	}
	return record, true
}

func (daemon *Daemon) kernelDatapathSessionWireRecord(key dataSessionKey, session transport.Session) (kernelmodule.DatapathStateRecord, bool) {
	info, ok := kernelDatapathSessionInfo(session)
	if !ok || info.FlowID == 0 {
		return kernelmodule.DatapathStateRecord{}, false
	}
	if info.Protocol == "" {
		info.Protocol = key.Transport
	}
	info = daemon.kernelDatapathResolveSessionWireInfo(info)
	local, localPort, ok := kernelDatapathParseIPv4AddrPort(info.LocalAddress)
	if !ok {
		return kernelmodule.DatapathStateRecord{}, false
	}
	remote, remotePort, ok := kernelDatapathParseIPv4AddrPort(info.RemoteAddress)
	if !ok {
		return kernelmodule.DatapathStateRecord{}, false
	}
	if info.SourcePort != 0 {
		localPort = info.SourcePort
	}
	if info.DestinationPort != 0 {
		remotePort = info.DestinationPort
	}
	if localPort == 0 || remotePort == 0 {
		return kernelmodule.DatapathStateRecord{}, false
	}
	return kernelmodule.DatapathStateRecord{
		Kind:  kernelmodule.TrustIXDatapathStateKindSessionWire,
		Op:    kernelmodule.TrustIXDatapathStateOpUpsert,
		Flags: kernelDatapathSessionWireFlagIPv4 | kernelDatapathSessionWireFlagLocalKnown | kernelDatapathSessionWireFlagRemoteKnown,
		Key:   kernelDatapathSessionStateKey(key),
		Value: [8]uint64{
			info.FlowID,
			uint64(local),
			uint64(remote),
			uint64(localPort)<<16 | uint64(remotePort),
			uint64(kernelDatapathTransportCode(info.Protocol)),
			info.MaxPacketSize,
			kernelDatapathSessionWireEpoch(info),
			uint64(uint32(key.PoolIndex)),
		},
	}, true
}

func kernelDatapathKernelUDPFlowSessionWireRecord(flow dataplane.KernelUDPFlow) (kernelmodule.DatapathStateRecord, bool) {
	key, ok := kernelDatapathKernelUDPFlowSessionKey(flow)
	if !ok {
		return kernelmodule.DatapathStateRecord{}, false
	}
	local, localPort, ok := kernelDatapathParseIPv4AddrPort(flow.LocalAddress)
	if !ok {
		return kernelmodule.DatapathStateRecord{}, false
	}
	remote, remotePort, ok := kernelDatapathParseIPv4AddrPort(flow.RemoteAddress)
	if !ok {
		return kernelmodule.DatapathStateRecord{}, false
	}
	if flow.SourcePort != 0 {
		localPort = flow.SourcePort
	}
	if flow.DestinationPort != 0 {
		remotePort = flow.DestinationPort
	}
	if localPort == 0 || remotePort == 0 {
		return kernelmodule.DatapathStateRecord{}, false
	}
	return kernelmodule.DatapathStateRecord{
		Kind:  kernelmodule.TrustIXDatapathStateKindSessionWire,
		Op:    kernelmodule.TrustIXDatapathStateOpUpsert,
		Flags: kernelDatapathSessionWireFlagIPv4 | kernelDatapathSessionWireFlagLocalKnown | kernelDatapathSessionWireFlagRemoteKnown,
		Key:   key,
		Value: [8]uint64{
			flow.ID,
			uint64(local),
			uint64(remote),
			uint64(localPort)<<16 | uint64(remotePort),
			uint64(kernelDatapathTransportCode(transport.ProtocolUDP)),
			0,
			0,
			0,
		},
	}, true
}

func kernelDatapathSessionWireEpoch(info transport.KernelDatapathSessionInfo) uint64 {
	if info.Protocol == transport.ProtocolUDP {
		return 0
	}
	return info.Epoch
}

func (daemon *Daemon) kernelDatapathResolveSessionWireInfo(info transport.KernelDatapathSessionInfo) transport.KernelDatapathSessionInfo {
	if daemon == nil || daemon.dataplane == nil || info.FlowID == 0 {
		return info
	}
	switch info.Protocol {
	case transport.ProtocolUDP:
		lookup, ok := daemon.dataplane.(dataplane.KernelUDPFlowLookup)
		if !ok {
			return info
		}
		flow, found, err := lookup.KernelUDPFlow(context.Background(), info.FlowID)
		if err != nil || !found {
			return info
		}
		if flow.LocalAddress != "" {
			info.LocalAddress = flow.LocalAddress
		}
		if flow.RemoteAddress != "" {
			info.RemoteAddress = flow.RemoteAddress
		}
		if flow.SourcePort != 0 {
			info.SourcePort = flow.SourcePort
		}
		if flow.DestinationPort != 0 {
			info.DestinationPort = flow.DestinationPort
		}
	case transport.ProtocolTIXTCP:
		lookup, ok := daemon.dataplane.(dataplane.TIXTCPFlowLookup)
		if !ok {
			return info
		}
		flow, found, err := lookup.TIXTCPFlow(context.Background(), info.FlowID)
		if err != nil || !found {
			return info
		}
		if flow.LocalAddress != "" {
			info.LocalAddress = flow.LocalAddress
		}
		if flow.RemoteAddress != "" {
			info.RemoteAddress = flow.RemoteAddress
		}
		if flow.SourcePort != 0 {
			info.SourcePort = flow.SourcePort
		}
		if flow.DestinationPort != 0 {
			info.DestinationPort = flow.DestinationPort
		}
	}
	return info
}

func kernelDatapathSessionInfo(session transport.Session) (transport.KernelDatapathSessionInfo, bool) {
	if session == nil {
		return transport.KernelDatapathSessionInfo{}, false
	}
	introspector, ok := session.(transport.KernelDatapathSession)
	if !ok {
		return transport.KernelDatapathSessionInfo{}, false
	}
	return introspector.KernelDatapathSessionInfo()
}

func kernelDatapathSessionStateKey(key dataSessionKey) [4]uint64 {
	return [4]uint64{
		hashString64(string(key.Peer)),
		hashString64(string(key.Endpoint)),
		hashString64(string(key.Transport)),
		hashString64(key.Encryption + "\x00" + strconv.Itoa(key.PoolIndex) + "\x00" + key.Address),
	}
}

func kernelDatapathKernelUDPFlowSessionKey(flow dataplane.KernelUDPFlow) ([4]uint64, bool) {
	if flow.ID == 0 || flow.Peer == "" || flow.Endpoint == "" {
		return [4]uint64{}, false
	}
	return [4]uint64{
		hashString64(string(flow.Peer)),
		hashString64(string(flow.Endpoint)),
		hashString64(string(transport.ProtocolUDP)),
		hashString64(kernelDatapathKernelUDPFlowAddressPrefix + strconv.FormatUint(flow.ID, 16)),
	}, true
}

func kernelDatapathSessionFlags(key dataSessionKey, runtime *dataSessionRuntime, info transport.KernelDatapathSessionInfo) uint32 {
	flags := kernelDatapathSessionFlagKernelFlow
	if key.Address == reverseSessionAddress {
		flags |= kernelDatapathSessionFlagReverse
	}
	if runtime != nil && runtime.controlOnly {
		flags |= kernelDatapathSessionFlagControlOnly
	}
	if info.Encrypted {
		flags |= kernelDatapathSessionFlagEncrypted
	}
	if info.SendEncrypted {
		flags |= kernelDatapathSessionFlagSendEncrypted
	}
	if info.ReceiveEncrypted {
		flags |= kernelDatapathSessionFlagReceiveEncrypted
	}
	switch info.CryptoPlacement {
	case "kernel":
		flags |= kernelDatapathSessionFlagCryptoKernel
	case "userspace":
		flags |= kernelDatapathSessionFlagCryptoUserspace
	}
	if info.NativeBatching {
		flags |= kernelDatapathSessionFlagNativeBatching
	}
	if info.Datagram {
		flags |= kernelDatapathSessionFlagDatagram
	}
	if info.FragmentingDatagram {
		flags |= kernelDatapathSessionFlagFragmentingDatagram
	}
	if key.Transport == transport.ProtocolTIXTCP || info.Protocol == transport.ProtocolTIXTCP {
		if info.SendEncrypted && info.SecureInnerTCPChecksumPartialNegotiated {
			flags |= kernelDatapathSessionFlagSendSecureInnerTCPChecksumPartial
		} else if !info.SendEncrypted && info.InnerTCPChecksumPartialNegotiated {
			flags |= kernelDatapathSessionFlagSendInnerTCPChecksumPartial
		}
		if info.ReceiveEncrypted && info.SecureInnerTCPChecksumPartialLocal {
			flags |= kernelDatapathSessionFlagReceiveSecureInnerTCPChecksumPartial
		} else if !info.ReceiveEncrypted && info.InnerTCPChecksumPartialLocal {
			flags |= kernelDatapathSessionFlagReceiveInnerTCPChecksumPartial
		}
		if !info.SendEncrypted && info.InnerGSONegotiated {
			flags |= kernelDatapathSessionFlagSendInnerGSO
		}
		if !info.ReceiveEncrypted && info.InnerGSOLocal {
			flags |= kernelDatapathSessionFlagReceiveInnerGSO
		}
		if info.TIXTCPPortShardingNegotiated {
			flags |= kernelDatapathSessionFlagSendTIXTCPPortSharding
		}
		if info.TIXTCPPortShardingLocal {
			flags |= kernelDatapathSessionFlagReceiveTIXTCPPortSharding
		}
	}
	return flags
}

func kernelDatapathFlowRecord(binding routing.FlowBinding) (kernelmodule.DatapathStateRecord, bool) {
	key, ok := kernelDatapathFlowStateKey(binding.Key)
	if !ok {
		return kernelmodule.DatapathStateRecord{}, false
	}
	return kernelmodule.DatapathStateRecord{
		Kind:  kernelmodule.TrustIXDatapathStateKindFlow,
		Op:    kernelmodule.TrustIXDatapathStateOpUpsert,
		Flags: kernelDatapathFlowFlagIPv4,
		Key:   key,
		Value: [8]uint64{
			hashString64(string(binding.NextHop)),
			hashString64(string(binding.Endpoint)),
			uint64(uint32(binding.PoolIndex)),
			kernelDatapathUnixNano(binding.LastSeen.UnixNano()),
			kernelDatapathUnixNano(binding.ExpiresAt.UnixNano()),
		},
	}, true
}

func kernelDatapathFlowDeleteRecord(key routing.FlowKey) (kernelmodule.DatapathStateRecord, bool) {
	stateKey, ok := kernelDatapathFlowStateKey(key)
	if !ok {
		return kernelmodule.DatapathStateRecord{}, false
	}
	return kernelmodule.DatapathStateRecord{
		Kind: kernelmodule.TrustIXDatapathStateKindFlow,
		Op:   kernelmodule.TrustIXDatapathStateOpDelete,
		Key:  stateKey,
	}, true
}

func kernelDatapathFlowStateKey(key routing.FlowKey) ([4]uint64, bool) {
	source, ok := kernelDatapathIPv4Uint32(key.SourceIP)
	if !ok {
		return [4]uint64{}, false
	}
	destination, ok := kernelDatapathIPv4Uint32(key.DestinationIP)
	if !ok {
		return [4]uint64{}, false
	}
	return [4]uint64{
		uint64(source),
		uint64(destination),
		uint64(key.SourcePort)<<16 | uint64(key.DestinationPort),
		uint64(key.Protocol),
	}, true
}

func kernelDatapathRouteKindFlag(kind routing.RouteKind) uint32 {
	switch kind {
	case "", routing.RouteUnicast:
		return 1
	case routing.RouteLocal:
		return 2
	case routing.RouteBlackhole:
		return 3
	case routing.RouteReject:
		return 4
	default:
		return 0
	}
}

func kernelDatapathTransportCode(protocol transport.Protocol) uint32 {
	switch protocol {
	case transport.ProtocolUDP:
		return 1
	case transport.ProtocolTIXTCP:
		return 2
	case transport.ProtocolGRE:
		return 3
	case transport.ProtocolIPIP:
		return 4
	case transport.ProtocolVXLAN:
		return 5
	case transport.ProtocolTCP:
		return 6
	default:
		return 0
	}
}

func kernelDatapathCryptoPlacementCode(placement string) uint32 {
	switch placement {
	case "kernel":
		return 1
	case "userspace":
		return 2
	case "auto":
		return 3
	default:
		return 0
	}
}

func kernelDatapathRuntimeLastRX(runtime *dataSessionRuntime) uint64 {
	if runtime == nil {
		return 0
	}
	return kernelDatapathUnixNano(runtime.lastRX.Load())
}

func kernelDatapathRuntimeLastTX(runtime *dataSessionRuntime) uint64 {
	if runtime == nil {
		return 0
	}
	return kernelDatapathUnixNano(runtime.lastTX.Load())
}

func kernelDatapathUnixNano(value int64) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value)
}

func kernelDatapathIPv4Uint32(addr netip.Addr) (uint32, bool) {
	addr = addr.Unmap()
	if !addr.Is4() {
		return 0, false
	}
	raw := addr.As4()
	return binary.BigEndian.Uint32(raw[:]), true
}

func kernelDatapathParseIPv4AddrPort(address string) (uint32, uint16, bool) {
	address = strings.TrimSpace(address)
	if address == "" {
		return 0, 0, false
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return 0, 0, false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return 0, 0, false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return 0, 0, false
	}
	ipv4, ok := kernelDatapathIPv4Uint32(addr)
	if !ok {
		return 0, 0, false
	}
	return ipv4, uint16(port), true
}

func hashString64(value string) uint64 {
	if value == "" {
		return 0
	}
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(value))
	return hash.Sum64()
}
