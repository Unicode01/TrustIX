package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/configlog"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/pki"
	"trustix.local/trustix/internal/routing"
)

const maxDesiredConfigBytes = 4 << 20

type configValidateResponse struct {
	Valid     bool   `json:"valid"`
	DomainID  string `json:"domain_id"`
	IXID      string `json:"ix_id"`
	Endpoints int    `json:"endpoints"`
	Peers     int    `json:"peers"`
	Routes    int    `json:"routes"`
}

type configApplyResponse struct {
	Applied bool         `json:"applied"`
	Changed bool         `json:"changed"`
	Head    headResponse `json:"head"`
}

type configRollbackResponse struct {
	RolledBack bool         `json:"rolled_back"`
	Changed    bool         `json:"changed"`
	TargetSeq  uint64       `json:"target_seq"`
	Head       headResponse `json:"head"`
}

func (daemon *Daemon) handleConfigDesired(w http.ResponseWriter, r *http.Request) {
	daemon.configMu.RLock()
	desired := daemon.desired
	daemon.configMu.RUnlock()
	writeJSON(w, http.StatusOK, desired)
}

func (daemon *Daemon) handleConfigValidate(w http.ResponseWriter, r *http.Request) {
	desired, err := decodeDesiredConfigRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	daemon.configMu.RLock()
	err = daemon.validateDesiredForRuntime(desired)
	daemon.configMu.RUnlock()
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, validationSummary(desired))
}

func (daemon *Daemon) handleConfigApply(w http.ResponseWriter, r *http.Request) {
	desired, err := decodeDesiredConfigRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ctx, err := daemon.preflightConfigMutation(r.Context(), "config apply", desired)
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	changed, err := daemon.applyDesiredConfig(ctx, desired)
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	daemon.configMu.RLock()
	head := daemon.head
	daemon.configMu.RUnlock()
	writeJSON(w, http.StatusOK, configApplyResponse{
		Applied: true,
		Changed: changed,
		Head:    headResponse{Seq: head.Seq, Hash: head.Hash},
	})
}

func (daemon *Daemon) handleConfigRollback(w http.ResponseWriter, r *http.Request) {
	targetSeq, err := rollbackSeqFromRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ctx, err := daemon.preflightConfigMutation(r.Context(), "config rollback")
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	target, changed, err := daemon.rollbackDesiredConfig(ctx, targetSeq)
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	daemon.configMu.RLock()
	head := daemon.head
	daemon.configMu.RUnlock()
	writeJSON(w, http.StatusOK, configRollbackResponse{
		RolledBack: true,
		Changed:    changed,
		TargetSeq:  target,
		Head:       headResponse{Seq: head.Seq, Hash: head.Hash},
	})
}

func decodeDesiredConfigRequest(r *http.Request) (config.Desired, error) {
	payload, err := readLimitedBody(r.Body, maxDesiredConfigBytes)
	if err != nil {
		return config.Desired{}, err
	}
	if len(bytes.TrimSpace(payload)) == 0 {
		return config.Desired{}, fmt.Errorf("desired config body is required")
	}
	return config.DecodeBytes(payload, desiredConfigExt(r))
}

func desiredConfigExt(r *http.Request) string {
	switch strings.ToLower(strings.TrimPrefix(r.URL.Query().Get("format"), ".")) {
	case "json":
		return ".json"
	case "yaml", "yml":
		return ".yaml"
	}
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	switch {
	case strings.Contains(contentType, "json"):
		return ".json"
	case strings.Contains(contentType, "yaml"), strings.Contains(contentType, "yml"):
		return ".yaml"
	default:
		return ".yaml"
	}
}

func readLimitedBody(reader io.Reader, limit int64) ([]byte, error) {
	limited := io.LimitReader(reader, limit+1)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read request body: %w", err)
	}
	if int64(len(payload)) > limit {
		return nil, fmt.Errorf("request body exceeds %d bytes", limit)
	}
	return payload, nil
}

func validationSummary(desired config.Desired) configValidateResponse {
	return configValidateResponse{
		Valid:     true,
		DomainID:  string(desired.Domain.ID),
		IXID:      string(desired.IX.ID),
		Endpoints: len(desired.Endpoints),
		Peers:     len(desired.Peers),
		Routes:    len(desired.Routes),
	}
}

func rollbackSeqFromRequest(r *http.Request) (*uint64, error) {
	if raw := strings.TrimSpace(r.URL.Query().Get("seq")); raw != "" {
		value, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || value == 0 {
			return nil, fmt.Errorf("invalid rollback seq %q", raw)
		}
		return &value, nil
	}
	payload, err := readLimitedBody(r.Body, 1024)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(payload)) == 0 {
		return nil, nil
	}
	var request struct {
		Seq *uint64 `json:"seq"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return nil, fmt.Errorf("decode rollback request: %w", err)
	}
	if request.Seq != nil && *request.Seq == 0 {
		return nil, fmt.Errorf("rollback seq must be greater than zero")
	}
	return request.Seq, nil
}

func (daemon *Daemon) validateDesiredForRuntime(desired config.Desired) error {
	desired = config.Normalize(desired)
	if err := daemon.validateDesiredSchemaForRuntime(desired); err != nil {
		return err
	}
	if daemon.desired.Domain.ID != "" && desired.Domain.ID != daemon.desired.Domain.ID {
		return fmt.Errorf("hot apply cannot change domain id from %q to %q", daemon.desired.Domain.ID, desired.Domain.ID)
	}
	if daemon.desired.IX.ID != "" && desired.IX.ID != daemon.desired.IX.ID {
		return fmt.Errorf("hot apply cannot change local ix id from %q to %q", daemon.desired.IX.ID, desired.IX.ID)
	}
	if err := validateTrustRoots(desired); err != nil {
		return err
	}
	if err := verifyLocalRouteAuthorizations(desired); err != nil {
		return err
	}
	if err := verifyDesiredSigner(desired); err != nil {
		return err
	}
	if err := validateDesiredKernelTunnelConflicts(desired); err != nil {
		return err
	}
	routes := routing.NewTable()
	if err := routes.Replace(routesFromConfig(desired)); err != nil {
		return err
	}
	return nil
}

func (daemon *Daemon) validateDesiredSchemaForRuntime(desired config.Desired) error {
	return desired.ValidateWithRoutePeers(daemon.runtimeRouteValidationPeers(desired))
}

func (daemon *Daemon) runtimeRouteValidationPeers(desired config.Desired) []config.PeerConfig {
	peers := append([]config.PeerConfig(nil), desired.Peers...)
	seen := make(map[core.IXID]struct{}, len(peers))
	for _, peer := range peers {
		seen[peer.ID] = struct{}{}
	}
	if desired.IX.ID != daemon.desired.IX.ID {
		localPeer := daemon.localRouteValidationPeer()
		if localPeer.ID != "" {
			if _, ok := seen[localPeer.ID]; !ok {
				peers = append(peers, localPeer)
				seen[localPeer.ID] = struct{}{}
			}
		}
	}
	daemon.membershipMu.RLock()
	ids := make([]string, 0, len(daemon.members))
	for ixID := range daemon.members {
		if ixID == desired.IX.ID {
			continue
		}
		if _, ok := seen[ixID]; ok {
			continue
		}
		ids = append(ids, string(ixID))
	}
	sort.Strings(ids)
	for _, rawID := range ids {
		ixID := core.IXID(rawID)
		record := daemon.members[ixID]
		peers = append(peers, daemon.peerConfigFromAdvertisement(record.Advertisement))
		seen[ixID] = struct{}{}
	}
	daemon.membershipMu.RUnlock()
	for _, route := range desired.Routes {
		owner := route.Owner
		if owner == "" || owner == route.NextHop || owner == desired.IX.ID {
			continue
		}
		if _, ok := seen[owner]; ok {
			continue
		}
		if err := owner.Validate(); err != nil {
			continue
		}
		peers = append(peers, config.PeerConfig{
			ID:              owner,
			AllowedPrefixes: []core.Prefix{route.Prefix},
		})
		seen[owner] = struct{}{}
	}
	return peers
}

func (daemon *Daemon) localRouteValidationPeer() config.PeerConfig {
	prefixes := make([]core.Prefix, 0, len(config.EffectiveLANAdvertise(daemon.desired)))
	for _, prefix := range daemon.localAdvertisementPrefixStringsForDesired(daemon.desired) {
		prefixes = append(prefixes, core.Prefix(prefix))
	}
	endpoints := make([]config.EndpointConfig, 0, len(daemon.desired.Endpoints))
	for _, endpoint := range daemon.desired.Endpoints {
		endpoints = append(endpoints, config.EndpointConfig{
			Name:      endpoint.Name,
			Transport: endpoint.Transport,
			Enabled:   endpoint.Enabled,
		})
	}
	return config.PeerConfig{
		ID:              daemon.desired.IX.ID,
		Domain:          daemon.desired.Domain.ID,
		AllowedPrefixes: prefixes,
		Endpoints:       endpoints,
	}
}

func validateTrustRoots(desired config.Desired) error {
	for _, path := range desired.Domain.TrustRoots {
		cert, _, err := pki.LoadCertificate(path)
		if err != nil {
			return fmt.Errorf("load trust root %q: %w", path, err)
		}
		if err := verifyCertificateNotRevokedByDesired(desired, cert, fmt.Sprintf("trust root %q", path)); err != nil {
			return err
		}
	}
	return nil
}

func verifyDesiredSigner(desired config.Desired) error {
	payload, err := json.Marshal(desired)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	event := configlog.Event{
		DomainID:    desired.Domain.ID,
		EventID:     core.EventID("evt-validate"),
		Seq:         1,
		Resource:    core.ResourcePath("/desired"),
		Action:      configlog.ActionUpsert,
		Payload:     payload,
		SignerID:    core.SignerID("ix:" + string(desired.IX.ID)),
		CreatedAt:   now,
		EffectiveAt: now,
	}
	return signConfigEvent(&event, desired)
}

func (daemon *Daemon) applyDesiredConfig(ctx context.Context, desired config.Desired) (bool, error) {
	var err error
	ctx, err = daemon.preflightConfigMutation(ctx, "config apply", desired)
	if err != nil {
		return false, err
	}
	daemon.configMu.Lock()
	defer daemon.configMu.Unlock()
	return daemon.applyDesiredConfigLocked(ctx, desired)
}

func (daemon *Daemon) applyDesiredConfigLocked(ctx context.Context, desired config.Desired) (bool, error) {
	if daemon.store == nil {
		return false, fmt.Errorf("config log store is not initialized")
	}
	if err := daemon.validateDesiredForRuntime(desired); err != nil {
		return false, err
	}
	adminProofs := adminProofsFromContext(ctx)
	trustChanged := !trustConfigsEqual(daemon.desired.Trust, desired.Trust)
	if trustChanged {
		if err := daemon.verifyAdminProofPolicy(adminProofs, daemon.desired.Trust); err != nil {
			return false, err
		}
	}
	head, err := daemon.store.Head()
	if err != nil {
		return false, err
	}
	eventsToAppend := make([]configlog.Event, 0, 3)
	appendPlanned := func(event *configlog.Event, plannedHead configlog.Head, changed bool) {
		if !changed || event == nil {
			return
		}
		eventsToAppend = append(eventsToAppend, *event)
		head = plannedHead
	}

	var baselineProofs []configlog.AdminProof
	if desiredConfigsEqual(daemon.desired, desired) {
		baselineProofs = adminProofs
	}
	baselineExists, err := daemon.hasLocalDesiredEventLocked(daemon.desired.IX.ID)
	if err != nil {
		return false, err
	}
	baselineChanged := false
	if !baselineExists {
		payload, err := json.Marshal(daemon.desired)
		if err != nil {
			return false, fmt.Errorf("encode baseline desired config: %w", err)
		}
		event, plannedHead, changed, err := daemon.desiredEventIfChangedAtHead(daemon.desired, baselineProofs, head, payload)
		if err != nil {
			return false, err
		}
		baselineChanged = changed
		appendPlanned(event, plannedHead, changed)
	}

	if trustChanged {
		event, plannedHead, changed, err := daemon.domainTrustEventIfChangedAtHead(desired.Trust, adminProofs, head)
		if err != nil {
			return false, err
		}
		appendPlanned(event, plannedHead, changed)
	}

	desiredChanged := false
	if !(baselineChanged && desiredConfigsEqual(daemon.desired, desired)) {
		desiredProofs := adminProofs
		if trustChanged {
			desiredProofs = adminProofsNotRevokedByTrust(adminProofs, desired.Trust)
		}
		payload, err := json.Marshal(desired)
		if err != nil {
			return false, fmt.Errorf("encode desired config: %w", err)
		}
		event, plannedHead, changed, err := daemon.desiredEventIfChangedAtHead(desired, desiredProofs, head, payload)
		if err != nil {
			return false, err
		}
		desiredChanged = changed
		appendPlanned(event, plannedHead, changed)
	}
	if len(eventsToAppend) == 0 {
		if !desiredConfigsEqual(daemon.desired, desired) {
			if err := daemon.switchDesiredRuntime(ctx, desired, head); err != nil {
				return false, err
			}
		}
		return false, nil
	}

	oldDesired := daemon.desired
	oldHead := daemon.head
	if err := daemon.switchDesiredRuntime(ctx, desired, head); err != nil {
		return false, err
	}
	for _, event := range eventsToAppend {
		if err := daemon.store.Append(event); err != nil {
			restoreErr := daemon.switchDesiredRuntime(ctx, oldDesired, oldHead)
			if restoreErr != nil {
				return false, fmt.Errorf("append desired config event: %w; restore previous runtime: %v", err, restoreErr)
			}
			return false, fmt.Errorf("append desired config event: %w", err)
		}
	}
	head, err = daemon.store.Head()
	if err != nil {
		return desiredChanged || trustChanged || baselineChanged, err
	}
	daemon.head = head
	runtimeTrustChanged, err := daemon.enforceRuntimeTrustState()
	if err != nil {
		return desiredChanged || trustChanged || baselineChanged, err
	}
	if runtimeTrustChanged {
		if err := daemon.applyRuntimeDataplaneSnapshot(ctx); err != nil {
			return desiredChanged || trustChanged || baselineChanged, err
		}
	}
	return desiredChanged || trustChanged || baselineChanged, nil
}

func (daemon *Daemon) ensureLocalDesiredBaselineLocked(adminProofs []configlog.AdminProof) (bool, error) {
	exists, err := daemon.hasLocalDesiredEventLocked(daemon.desired.IX.ID)
	if err != nil || exists {
		return false, err
	}
	event, _, changed, err := daemon.desiredEventIfChanged(daemon.desired, adminProofs)
	if err != nil || !changed {
		return false, err
	}
	if err := daemon.store.Append(*event); err != nil {
		return false, fmt.Errorf("append baseline desired config event: %w", err)
	}
	head, err := daemon.store.Head()
	if err != nil {
		return true, err
	}
	daemon.head = head
	return true, nil
}

func (daemon *Daemon) hasLocalDesiredEventLocked(ix core.IXID) (bool, error) {
	head, err := daemon.store.Head()
	if err != nil {
		return false, err
	}
	if head.Seq == 0 {
		return false, nil
	}
	events, err := daemon.store.Range(1, head.Seq)
	if err != nil {
		return false, err
	}
	resource := desiredResourceForIX(ix)
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Resource == resource || daemon.eventIsLocalDesired(events[i], ix) {
			return true, nil
		}
	}
	return false, nil
}

func (daemon *Daemon) rollbackDesiredConfig(ctx context.Context, targetSeq *uint64) (uint64, bool, error) {
	var err error
	ctx, err = daemon.preflightConfigMutation(ctx, "config rollback")
	if err != nil {
		return 0, false, err
	}
	daemon.configMu.Lock()
	defer daemon.configMu.Unlock()
	event, err := daemon.rollbackTargetDesiredEvent(targetSeq)
	if err != nil {
		return 0, false, err
	}
	desired, err := config.DecodeBytes(event.Payload, ".json")
	if err != nil {
		return 0, false, fmt.Errorf("decode desired config from event seq %d: %w", event.Seq, err)
	}
	changed, err := daemon.applyDesiredConfigLocked(ctx, desired)
	if err != nil {
		return 0, false, err
	}
	return event.Seq, changed, nil
}

func (daemon *Daemon) rollbackTargetDesiredEvent(targetSeq *uint64) (configlog.Event, error) {
	if daemon.store == nil {
		return configlog.Event{}, fmt.Errorf("config log store is not initialized")
	}
	head, err := daemon.store.Head()
	if err != nil {
		return configlog.Event{}, err
	}
	if head.Seq == 0 {
		return configlog.Event{}, fmt.Errorf("config log is empty")
	}
	events, err := daemon.store.Range(1, head.Seq)
	if err != nil {
		return configlog.Event{}, err
	}
	if targetSeq != nil {
		if *targetSeq > head.Seq {
			return configlog.Event{}, fmt.Errorf("rollback seq %d is after config head %d", *targetSeq, head.Seq)
		}
		for i := len(events) - 1; i >= 0; i-- {
			if events[i].Seq <= *targetSeq && (events[i].Resource == desiredResourceForIX(daemon.desired.IX.ID) || daemon.eventIsLocalDesired(events[i], daemon.desired.IX.ID)) {
				return events[i], nil
			}
		}
		return configlog.Event{}, fmt.Errorf("no desired config event at or before seq %d", *targetSeq)
	}

	seenCurrent := false
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Resource != desiredResourceForIX(daemon.desired.IX.ID) && !daemon.eventIsLocalDesired(events[i], daemon.desired.IX.ID) {
			continue
		}
		if !seenCurrent {
			seenCurrent = true
			continue
		}
		return events[i], nil
	}
	return configlog.Event{}, fmt.Errorf("no previous desired config event to roll back to")
}

func (daemon *Daemon) eventIsLocalDesired(event configlog.Event, ix core.IXID) bool {
	if event.Resource != "/desired" {
		return false
	}
	var desired config.Desired
	if err := json.Unmarshal(event.Payload, &desired); err != nil {
		return false
	}
	return desired.IX.ID == ix
}

func (daemon *Daemon) switchDesiredRuntime(ctx context.Context, desired config.Desired, head configlog.Head) error {
	oldDesired := daemon.desired
	oldHead := daemon.head
	oldDomain := daemon.cfg.DomainID
	oldIX := daemon.cfg.IXID
	oldFlows := daemon.snapshotFlows()
	restartListeners := dataPathListenersNeedRestart(oldDesired, desired)
	restartAllSessions, restartPeers := daemon.dataPathSessionRestartScope(oldDesired, desired)
	restartHostAPI := managementHostAPINeedsRestart(oldDesired, desired)
	restartPrimaryAPI := managementPrimaryAPINeedsRestart(oldDesired, desired, daemon.cfg.APIAddr)
	restartDNS := dnsResolverNeedsRestart(oldDesired, desired)
	syncDNSMasq := restartDNS || dnsMasqIntegrationNeedsRestart(oldDesired, desired)
	kernelModuleDataplaneChange := !reflect.DeepEqual(oldDesired.KernelModules, desired.KernelModules) &&
		kernelModulesMayAffectDataplane(oldDesired, desired)
	reloadDataplane := dataplaneAttachSpecNeedsReload(oldDesired, desired) ||
		kernelModuleDataplaneChange

	preDetachedDataplane := false
	if kernelModuleDataplaneChange {
		daemon.closeDataPath()
		daemon.closeCaptureForwarder()
		if err := daemon.dataplane.Detach(ctx); err != nil {
			return daemon.restoreDesiredRuntime(ctx, oldDesired, oldHead, oldDomain, oldIX, oldFlows, err)
		}
		preDetachedDataplane = true
		restartListeners = true
		restartAllSessions = false
		restartPeers = nil
	}

	if _, err := daemon.ensureKernelModules(ctx, desired); err != nil {
		if preDetachedDataplane {
			return daemon.restoreDesiredRuntime(ctx, oldDesired, oldHead, oldDomain, oldIX, oldFlows, err)
		}
		return err
	}

	if restartListeners {
		if !preDetachedDataplane {
			daemon.closeDataPath()
		}
	} else if restartAllSessions {
		daemon.closeDataSessions()
	} else if len(restartPeers) > 0 {
		daemon.closeDataSessionsForPeers(restartPeers)
		daemon.clearFlowsForPeers(restartPeers)
	}
	daemon.setRuntimeDesired(desired, head)
	daemon.clearFlows()
	if restartHostAPI {
		if err := daemon.restartHostAPIServers(ctx); err != nil {
			return daemon.restoreDesiredRuntime(ctx, oldDesired, oldHead, oldDomain, oldIX, oldFlows, err)
		}
	}
	if restartDNS {
		if err := daemon.restartDNSServer(ctx); err != nil {
			return daemon.restoreDesiredRuntime(ctx, oldDesired, oldHead, oldDomain, oldIX, oldFlows, err)
		}
	}
	if syncDNSMasq {
		if err := daemon.syncDNSMasq(ctx); err != nil {
			return daemon.restoreDesiredRuntime(ctx, oldDesired, oldHead, oldDomain, oldIX, oldFlows, err)
		}
	}
	if reloadDataplane {
		daemon.stopKernelDatapathRXStage()
		daemon.closeCaptureForwarder()
		if !preDetachedDataplane {
			if err := daemon.dataplane.Detach(ctx); err != nil {
				return daemon.restoreDesiredRuntime(ctx, oldDesired, oldHead, oldDomain, oldIX, oldFlows, err)
			}
		}
		if err := daemon.loadAttachDataplane(ctx, desired); err != nil {
			return daemon.restoreDesiredRuntime(ctx, oldDesired, oldHead, oldDomain, oldIX, oldFlows, err)
		}
		if err := daemon.startKernelDatapathRXStage(daemon.listenerContext(ctx), dataplaneAttachSpec(daemon.cfg.DataDir, desired)); err != nil {
			return daemon.restoreDesiredRuntime(ctx, oldDesired, oldHead, oldDomain, oldIX, oldFlows, err)
		}
		if err := daemon.startCaptureForwarder(daemon.listenerContext(ctx)); err != nil {
			return daemon.restoreDesiredRuntime(ctx, oldDesired, oldHead, oldDomain, oldIX, oldFlows, err)
		}
	}
	if restartListeners {
		if err := daemon.startTransportListeners(daemon.listenerContext(ctx)); err != nil {
			return daemon.restoreDesiredRuntime(ctx, oldDesired, oldHead, oldDomain, oldIX, oldFlows, err)
		}
	}
	if err := daemon.refreshLocalAdvertisement(); err != nil {
		return daemon.restoreDesiredRuntime(ctx, oldDesired, oldHead, oldDomain, oldIX, oldFlows, err)
	}
	if err := daemon.applyRuntimeDataplaneSnapshot(ctx); err != nil {
		return daemon.restoreDesiredRuntime(ctx, oldDesired, oldHead, oldDomain, oldIX, oldFlows, err)
	}
	daemon.cancelRouteSessionWarmups()
	if err := daemon.warmKernelDirectRouteSessions(ctx); err != nil {
		return daemon.restoreDesiredRuntime(ctx, oldDesired, oldHead, oldDomain, oldIX, oldFlows, err)
	}
	if daemon.sessionPoolWarmupEnabled() {
		go daemon.runRouteSessionWarmup(daemon.listenerContext(ctx))
	}
	if restartPrimaryAPI {
		daemon.restartAPIServersSoon()
	}
	return nil
}

func dataPathListenersNeedRestart(oldDesired, newDesired config.Desired) bool {
	if oldDesired.IX.CertPath != newDesired.IX.CertPath || oldDesired.IX.KeyPath != newDesired.IX.KeyPath {
		return true
	}
	if !reflect.DeepEqual(oldDesired.Domain.TrustRoots, newDesired.Domain.TrustRoots) ||
		!reflect.DeepEqual(oldDesired.Trust.TrustRootsPEM, newDesired.Trust.TrustRootsPEM) ||
		!reflect.DeepEqual(oldDesired.Trust.RevokedCertFingerprints, newDesired.Trust.RevokedCertFingerprints) {
		return true
	}
	if effectiveTransportCryptoPlacementConfig(oldDesired.TransportPolicy) != effectiveTransportCryptoPlacementConfig(newDesired.TransportPolicy) {
		return true
	}
	if oldDesired.TransportPolicy.KernelTransport.Mode != newDesired.TransportPolicy.KernelTransport.Mode {
		return true
	}
	if oldDesired.TransportPolicy.CryptoKeySource != newDesired.TransportPolicy.CryptoKeySource {
		return true
	}
	if oldDesired.TransportPolicy.Encryption != newDesired.TransportPolicy.Encryption {
		return true
	}
	if !reflect.DeepEqual(oldDesired.TransportPolicy.CryptoSuites, newDesired.TransportPolicy.CryptoSuites) {
		return true
	}
	return !reflect.DeepEqual(passiveListenerEndpoints(oldDesired.Endpoints), passiveListenerEndpoints(newDesired.Endpoints))
}

func dataplaneAttachSpecNeedsReload(oldDesired, newDesired config.Desired) bool {
	return kernelUDPTXDirectOnlyFailClosedForDesired(oldDesired) != kernelUDPTXDirectOnlyFailClosedForDesired(newDesired) ||
		kernelUDPSecureFullDirectForDesired(oldDesired) != kernelUDPSecureFullDirectForDesired(newDesired) ||
		nativePlaintextKernelTunnelRouteOffloadForDesired(oldDesired) != nativePlaintextKernelTunnelRouteOffloadForDesired(newDesired) ||
		!reflect.DeepEqual(dataplaneLANAttachSpecs(oldDesired), dataplaneLANAttachSpecs(newDesired))
}

func managementHostAPINeedsRestart(oldDesired, newDesired config.Desired) bool {
	if !reflect.DeepEqual(oldDesired.Management.HostAPI, newDesired.Management.HostAPI) {
		return true
	}
	if managementTLSServerConfigChanged(oldDesired, newDesired) {
		return true
	}
	if !reflect.DeepEqual(effectiveLANGateways(oldDesired), effectiveLANGateways(newDesired)) {
		return true
	}
	return false
}

func effectiveLANGateways(desired config.Desired) []string {
	lans := config.EffectiveLANs(desired)
	out := make([]string, 0, len(lans))
	for _, lan := range lans {
		if strings.TrimSpace(lan.Gateway) != "" {
			out = append(out, strings.TrimSpace(lan.Gateway))
		}
	}
	sort.Strings(out)
	return out
}

func passiveListenerEndpoints(endpoints []config.EndpointConfig) []config.EndpointConfig {
	out := make([]config.EndpointConfig, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint.Enabled && endpoint.Mode == config.EndpointModePassive {
			endpoint.Priority = 0
			endpoint.Publish = config.EndpointPublishConfig{}
			out = append(out, endpoint)
		}
	}
	return out
}

func (daemon *Daemon) restoreDesiredRuntime(ctx context.Context, desired config.Desired, head configlog.Head, domain core.DomainID, ix core.IXID, flows map[routing.FlowKey]routing.FlowBinding, cause error) error {
	daemon.closeDataPath()
	daemon.closeCaptureForwarder()
	daemon.restoreFlows(flows)

	var restoreErrs []error
	daemon.setRuntimeDesired(desired, head)
	daemon.cfg.DomainID = domain
	daemon.cfg.IXID = ix
	if _, err := daemon.ensureKernelModules(ctx, desired); err != nil {
		restoreErrs = append(restoreErrs, err)
	}
	if err := daemon.dataplane.Detach(ctx); err != nil {
		restoreErrs = append(restoreErrs, err)
	}
	if err := daemon.loadAttachDataplane(ctx, desired); err != nil {
		restoreErrs = append(restoreErrs, err)
	}
	if err := daemon.startKernelDatapathRXStage(daemon.listenerContext(ctx), dataplaneAttachSpec(daemon.cfg.DataDir, desired)); err != nil {
		restoreErrs = append(restoreErrs, err)
	}
	if err := daemon.startCaptureForwarder(daemon.listenerContext(ctx)); err != nil {
		restoreErrs = append(restoreErrs, err)
	}
	if err := daemon.startTransportListeners(daemon.listenerContext(ctx)); err != nil {
		restoreErrs = append(restoreErrs, err)
	}
	if err := daemon.restartHostAPIServers(ctx); err != nil {
		restoreErrs = append(restoreErrs, err)
	}
	if err := daemon.restartDNSServer(ctx); err != nil {
		restoreErrs = append(restoreErrs, err)
	}
	if err := daemon.syncDNSMasq(ctx); err != nil {
		restoreErrs = append(restoreErrs, err)
	}
	if err := daemon.refreshLocalAdvertisement(); err != nil {
		restoreErrs = append(restoreErrs, err)
	}
	if err := daemon.applyRuntimeDataplaneSnapshot(ctx); err != nil {
		restoreErrs = append(restoreErrs, err)
	}
	if len(restoreErrs) > 0 {
		return fmt.Errorf("%w; restore previous runtime: %v", cause, errors.Join(restoreErrs...))
	}
	return cause
}

func (daemon *Daemon) setRuntimeDesired(desired config.Desired, head configlog.Head) {
	daemon.desired = desired
	daemon.head = head
	daemon.cfg.DomainID = desired.Domain.ID
	daemon.cfg.IXID = desired.IX.ID
	daemon.resetControlClients()
	daemon.configureNATTable()
	daemon.configureLocalLANCache(desired)
	daemon.setTransportCryptoPlacement(desired.TransportPolicy)
	daemon.setSecureTransportKeySource(desired.TransportPolicy.CryptoKeySource)
	daemon.setSecureTransportEncryption(desired.TransportPolicy.Encryption)
	daemon.setSecureTransportCryptoSuites(desired.TransportPolicy.CryptoSuites)
}

func (daemon *Daemon) listenerContext(fallback context.Context) context.Context {
	if daemon.runCtx != nil {
		return daemon.runCtx
	}
	return fallback
}

func desiredConfigsEqual(left, right config.Desired) bool {
	leftPayload, err := json.Marshal(left)
	if err != nil {
		return false
	}
	rightPayload, err := json.Marshal(right)
	if err != nil {
		return false
	}
	return bytes.Equal(leftPayload, rightPayload)
}

func (daemon *Daemon) snapshotFlows() map[routing.FlowKey]routing.FlowBinding {
	daemon.flowMu.Lock()
	defer daemon.flowMu.Unlock()
	flows := make(map[routing.FlowKey]routing.FlowBinding, len(daemon.flows))
	for key, binding := range daemon.flows {
		flows[key] = binding
	}
	return flows
}

func (daemon *Daemon) clearFlows() {
	daemon.flowMu.Lock()
	daemon.flows = make(map[routing.FlowKey]routing.FlowBinding)
	daemon.flowMu.Unlock()
	daemon.clearForwardCache()
}

func (daemon *Daemon) restoreFlows(flows map[routing.FlowKey]routing.FlowBinding) {
	daemon.flowMu.Lock()
	daemon.flows = make(map[routing.FlowKey]routing.FlowBinding, len(flows))
	for key, binding := range flows {
		daemon.flows[key] = binding
	}
	daemon.flowMu.Unlock()
}
