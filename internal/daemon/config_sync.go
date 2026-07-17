package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"trustix.local/trustix/internal/adminauth"
	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/configlog"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/pki"
)

const maxConfigEventsBytes = 8 << 20
const maxConfigSnapshotBytes = 32 << 20
const genesisSignature = "trustix-genesis-v1"

type configSyncPeerState struct {
	Peer         string       `json:"peer,omitempty"`
	DomainID     string       `json:"domain_id,omitempty"`
	ControlAPI   string       `json:"control_api,omitempty"`
	Status       string       `json:"status"`
	LocalHead    headResponse `json:"local_head"`
	RemoteHead   headResponse `json:"remote_head"`
	LastSync     time.Time    `json:"last_sync,omitempty"`
	LastError    string       `json:"last_error,omitempty"`
	PulledEvents int          `json:"pulled_events,omitempty"`
	PushedEvents int          `json:"pushed_events,omitempty"`
}

type controlConfigHeadResponse struct {
	DomainID string       `json:"domain_id"`
	IXID     string       `json:"ix_id"`
	Head     headResponse `json:"head"`
}

type configSignerCertificate struct {
	SignerID    core.SignerID `json:"signer_id"`
	Certificate []byte        `json:"certificate"`
}

type configEventsEnvelope struct {
	Head    headResponse              `json:"head,omitempty"`
	Events  []configlog.Event         `json:"events"`
	Signers []configSignerCertificate `json:"signers,omitempty"`
}

type configEventsApplyResponse struct {
	Accepted bool         `json:"accepted"`
	Appended int          `json:"appended"`
	Head     headResponse `json:"head"`
}

type configSnapshotEnvelope struct {
	DomainID    string                    `json:"domain_id"`
	IXID        string                    `json:"ix_id"`
	Head        headResponse              `json:"head"`
	Events      []configlog.Event         `json:"events"`
	Signers     []configSignerCertificate `json:"signers,omitempty"`
	GeneratedAt time.Time                 `json:"generated_at"`
}

type configRejoinRequest struct {
	ControlAPI           string        `json:"control_api"`
	IXID                 core.IXID     `json:"ix_id,omitempty"`
	DomainID             core.DomainID `json:"domain_id,omitempty"`
	PreserveLocalDesired *bool         `json:"preserve_local_desired,omitempty"`
}

type configRejoinResponse struct {
	Rejoined              bool         `json:"rejoined"`
	PreservedLocalDesired bool         `json:"preserved_local_desired"`
	Events                int          `json:"events"`
	RemoteHead            headResponse `json:"remote_head"`
	Head                  headResponse `json:"head"`
}

type configMutationConflictError struct {
	Operation  string
	Target     controlTarget
	LocalHead  configlog.Head
	RemoteHead configlog.Head
	Err        error
}

type configMutationConflictResponse struct {
	Error      string       `json:"error"`
	Operation  string       `json:"operation,omitempty"`
	Peer       core.IXID    `json:"peer,omitempty"`
	ControlAPI string       `json:"control_api,omitempty"`
	LocalHead  headResponse `json:"local_head"`
	RemoteHead headResponse `json:"remote_head"`
	RejoinHint string       `json:"rejoin_hint,omitempty"`
}

type configMutationPreflightContextKey struct{}

type persistedConfigSigners struct {
	Version int                       `json:"version"`
	Signers []configSignerCertificate `json:"signers"`
}

type genesisPayload struct {
	Version    int      `json:"version"`
	DomainID   string   `json:"domain_id"`
	TrustRoots []string `json:"trust_roots"`
}

func (daemon *Daemon) handleConfigPeers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, daemon.configSyncSnapshot())
}

func (daemon *Daemon) handleConfigVerify(w http.ResponseWriter, r *http.Request) {
	verify := daemon.verifyCurrentConfigLog()
	if !verify.Valid {
		writeJSON(w, http.StatusConflict, verify)
		return
	}
	writeJSON(w, http.StatusOK, verify)
}

func (daemon *Daemon) handleConfigSnapshot(w http.ResponseWriter, r *http.Request) {
	snapshot, err := daemon.localConfigSnapshot()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (daemon *Daemon) handleConfigRestoreBackup(w http.ResponseWriter, r *http.Request) {
	payload, err := readLimitedBody(r.Body, 4096)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var request configRestoreBackupRequest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode config restore-backup request: %w", err))
		return
	}
	response, err := daemon.restoreConfigLogBackup(r.Context(), request.Path)
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (daemon *Daemon) handleConfigRejoin(w http.ResponseWriter, r *http.Request) {
	payload, err := readLimitedBody(r.Body, 4096)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var request configRejoinRequest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode config rejoin request: %w", err))
		return
	}
	if strings.TrimSpace(request.ControlAPI) == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("control_api is required"))
		return
	}
	if err := validateControlAPI(request.ControlAPI); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("control_api: %w", err))
		return
	}
	if request.IXID != "" {
		if err := request.IXID.Validate(); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	domain := request.DomainID
	if domain == "" {
		domain = daemon.desired.Domain.ID
	}
	if err := domain.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if domain != daemon.desired.Domain.ID {
		writeError(w, http.StatusBadRequest, fmt.Errorf("rejoin domain %q does not match local domain %q", domain, daemon.desired.Domain.ID))
		return
	}
	preserveLocalDesired := true
	if request.PreserveLocalDesired != nil {
		preserveLocalDesired = *request.PreserveLocalDesired
	}
	target := controlTarget{
		ID:         request.IXID,
		Domain:     domain,
		ControlAPI: request.ControlAPI,
	}
	result, err := daemon.rejoinConfigLogWithTarget(r.Context(), target, preserveLocalDesired)
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (daemon *Daemon) handleControlConfigHead(w http.ResponseWriter, r *http.Request) {
	daemon.configMu.RLock()
	head := daemon.head
	daemon.configMu.RUnlock()
	writeJSON(w, http.StatusOK, controlConfigHeadResponse{
		DomainID: string(daemon.desired.Domain.ID),
		IXID:     string(daemon.desired.IX.ID),
		Head:     headResponse{Seq: head.Seq, Hash: head.Hash},
	})
}

func (daemon *Daemon) handleControlConfigLog(w http.ResponseWriter, r *http.Request) {
	daemon.configMu.RLock()
	head := daemon.head
	daemon.configMu.RUnlock()
	if head.Seq == 0 {
		writeJSON(w, http.StatusOK, configEventsEnvelope{
			Head: headResponse{},
		})
		return
	}
	from, err := parseUintParam(r, "from", 1)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	to, err := parseUintParam(r, "to", head.Seq)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	daemon.configMu.RLock()
	events, err := daemon.store.Range(from, to)
	daemon.configMu.RUnlock()
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, configEventsEnvelope{
		Head:    headResponse{Seq: head.Seq, Hash: head.Hash},
		Events:  events,
		Signers: daemon.signerCertificatesForEvents(events),
	})
}

func (daemon *Daemon) handleControlConfigSnapshot(w http.ResponseWriter, r *http.Request) {
	snapshot, err := daemon.localConfigSnapshot()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (daemon *Daemon) handleControlConfigEventsPost(w http.ResponseWriter, r *http.Request) {
	payload, err := readLimitedBody(r.Body, maxConfigEventsBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var envelope configEventsEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		var events []configlog.Event
		if eventErr := json.Unmarshal(payload, &events); eventErr != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode config events: %w", err))
			return
		}
		envelope.Events = events
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		if _, err := daemon.registerConfigSignerCertificate(r.TLS.PeerCertificates[0], true); err != nil {
			err = fmt.Errorf("register peer signer certificate: %w", err)
			if stateFileCommitSucceeded(err) {
				daemon.requestRuntimeReconcile("peer signer cache durability", err)
				err = newCommittedConfigMutationError("register peer signer certificate", err)
			}
			writeConfigMutationError(w, err)
			return
		}
	}
	appended, err := daemon.appendVerifiedConfigEvents(r.Context(), envelope.Events, envelope.Signers)
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	daemon.configMu.RLock()
	head := daemon.head
	daemon.configMu.RUnlock()
	writeJSON(w, http.StatusOK, configEventsApplyResponse{
		Accepted: true,
		Appended: appended,
		Head:     headResponse{Seq: head.Seq, Hash: head.Hash},
	})
}

func (daemon *Daemon) syncConfigLogWithTarget(ctx context.Context, target controlTarget) error {
	parsed, err := url.Parse(target.ControlAPI)
	if err != nil {
		return fmt.Errorf("parse control_api: %w", err)
	}
	client, err := daemon.controlClient(target)
	if err != nil {
		return err
	}
	remoteHead, remoteIX, err := daemon.fetchPeerConfigHead(ctx, client, parsed)
	if err != nil {
		daemon.recordConfigSync(target, "error", remoteHead, 0, 0, err)
		return err
	}
	return daemon.syncConfigLogWithKnownHead(ctx, target, client, parsed, remoteHead, remoteIX)
}

func (daemon *Daemon) syncConfigLogWithAdvertisement(ctx context.Context, target controlTarget, advertisement advertisementResponse) error {
	parsed, err := url.Parse(target.ControlAPI)
	if err != nil {
		return fmt.Errorf("parse control_api: %w", err)
	}
	client, err := daemon.controlClient(target)
	if err != nil {
		return err
	}
	remoteHead := configlog.Head{Seq: advertisement.ConfigHead.Seq, Hash: advertisement.ConfigHead.Hash}
	return daemon.syncConfigLogWithKnownHead(ctx, target, client, parsed, remoteHead, core.IXID(advertisement.IXID))
}

func (daemon *Daemon) syncConfigLogWithKnownHead(ctx context.Context, target controlTarget, client *http.Client, parsed *url.URL, remoteHead configlog.Head, remoteIX core.IXID) error {
	if target.ID == "" && remoteIX != "" {
		target.ID = remoteIX
	}
	if target.ID != "" && remoteIX != "" && target.ID != remoteIX {
		err := fmt.Errorf("peer config head ix is %q, want %q", remoteIX, target.ID)
		daemon.recordConfigSync(target, "error", remoteHead, 0, 0, err)
		return err
	}
	daemon.configMu.RLock()
	localHead := daemon.head
	daemon.configMu.RUnlock()

	switch {
	case localHead.Seq == remoteHead.Seq:
		if localHead.Hash != remoteHead.Hash {
			err := fmt.Errorf("%w: config log conflict with peer %q: same seq %d but hash differs", configlog.ErrConflict, target.ID, localHead.Seq)
			daemon.recordConfigSync(target, "conflict", remoteHead, 0, 0, err)
			return err
		}
		daemon.recordConfigSync(target, "synced", remoteHead, 0, 0, nil)
		return nil
	case localHead.Seq < remoteHead.Seq:
		events, signers, err := daemon.fetchPeerConfigEvents(ctx, client, parsed, localHead.Seq+1, remoteHead.Seq)
		if err != nil {
			daemon.recordConfigSync(target, "error", remoteHead, 0, 0, err)
			return err
		}
		appended, err := daemon.appendVerifiedConfigEvents(ctx, events, signers)
		if err != nil {
			status := "error"
			if errors.Is(err, configlog.ErrConflict) {
				status = "conflict"
			}
			daemon.recordConfigSync(target, status, remoteHead, appended, 0, err)
			return err
		}
		daemon.recordConfigSync(target, "pulled", remoteHead, appended, 0, nil)
		return nil
	default:
		events, err := daemon.localConfigEventsAfter(remoteHead)
		if err != nil {
			daemon.recordConfigSync(target, "conflict", remoteHead, 0, 0, err)
			return err
		}
		if len(events) == 0 {
			daemon.recordConfigSync(target, "synced", remoteHead, 0, 0, nil)
			return nil
		}
		if err := daemon.pushPeerConfigEvents(ctx, client, parsed, events); err != nil {
			status := "error"
			if errors.Is(err, configlog.ErrConflict) {
				status = "conflict"
			}
			daemon.recordConfigSync(target, status, remoteHead, 0, 0, err)
			return err
		}
		daemon.recordConfigSync(target, "pushed", remoteHead, 0, len(events), nil)
		return nil
	}
}

func (daemon *Daemon) preflightConfigMutation(ctx context.Context, operation string, desiredCandidates ...config.Desired) (context.Context, error) {
	if ctx.Value(configMutationPreflightContextKey{}) == true {
		return ctx, nil
	}
	targets := daemon.configMutationSyncTargets(desiredCandidates...)
	for _, target := range targets {
		if err := daemon.syncConfigLogWithTarget(ctx, target); err != nil {
			if errors.Is(err, configlog.ErrConflict) {
				return ctx, daemon.newConfigMutationConflictError(operation, target, err)
			}
			continue
		}
	}
	return context.WithValue(ctx, configMutationPreflightContextKey{}, true), nil
}

func (daemon *Daemon) configMutationSyncTargets(desiredCandidates ...config.Desired) []controlTarget {
	daemon.configMu.RLock()
	current := daemon.desired
	daemon.configMu.RUnlock()

	seen := make(map[string]struct{})
	targets := make([]controlTarget, 0)
	add := func(target controlTarget) {
		target.ControlAPI = strings.TrimSpace(target.ControlAPI)
		if target.ControlAPI == "" {
			return
		}
		if target.ID == current.IX.ID {
			return
		}
		if _, ok := seen[target.ControlAPI]; ok {
			return
		}
		seen[target.ControlAPI] = struct{}{}
		targets = append(targets, target)
	}
	for _, target := range daemon.controlTargetsForDesired(current) {
		add(target)
	}
	for _, desired := range desiredCandidates {
		if desired.Domain.ID != "" && desired.Domain.ID != current.Domain.ID {
			continue
		}
		if desired.IX.ID != "" && desired.IX.ID != current.IX.ID {
			continue
		}
		for _, target := range daemon.controlTargetsForDesired(desired) {
			add(target)
		}
	}
	return targets
}

func (daemon *Daemon) newConfigMutationConflictError(operation string, target controlTarget, cause error) error {
	state, ok := daemon.configSyncState(target)
	var localHead, remoteHead configlog.Head
	if ok {
		localHead = configlog.Head{Seq: state.LocalHead.Seq, Hash: state.LocalHead.Hash}
		remoteHead = configlog.Head{Seq: state.RemoteHead.Seq, Hash: state.RemoteHead.Hash}
	} else {
		daemon.configMu.RLock()
		localHead = daemon.head
		daemon.configMu.RUnlock()
	}
	return &configMutationConflictError{
		Operation:  operation,
		Target:     target,
		LocalHead:  localHead,
		RemoteHead: remoteHead,
		Err:        cause,
	}
}

func (err *configMutationConflictError) Error() string {
	if err == nil {
		return ""
	}
	peer := string(err.Target.ID)
	if peer == "" {
		peer = err.Target.ControlAPI
	}
	if peer == "" {
		peer = "peer"
	}
	return fmt.Sprintf("config mutation %q blocked by config log conflict with %s; run %s", err.Operation, peer, err.rejoinHint())
}

func (err *configMutationConflictError) Unwrap() error {
	if err == nil || err.Err == nil {
		return configlog.ErrConflict
	}
	return err.Err
}

func (err *configMutationConflictError) rejoinHint() string {
	if err == nil || err.Target.ControlAPI == "" {
		return "trustixctl config rejoin <control_api> [ix_id]"
	}
	hint := "trustixctl config rejoin " + err.Target.ControlAPI
	if err.Target.ID != "" {
		hint += " " + string(err.Target.ID)
	}
	return hint
}

type committedConfigMutationError struct {
	Operation string
	Err       error
}

func newCommittedConfigMutationError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return &committedConfigMutationError{Operation: operation, Err: err}
}

func (err *committedConfigMutationError) Error() string {
	if err == nil {
		return "config mutation committed but reconciliation failed"
	}
	if err.Operation == "" {
		return fmt.Sprintf("config mutation committed but reconciliation failed: %v", err.Err)
	}
	return fmt.Sprintf("config mutation %q committed but reconciliation failed: %v", err.Operation, err.Err)
}

func (err *committedConfigMutationError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}

type committedConfigMutationResponse struct {
	Error             string `json:"error"`
	Operation         string `json:"operation,omitempty"`
	Committed         bool   `json:"committed"`
	ReconcileRequired bool   `json:"reconcile_required"`
}

type configMutationRequestError struct {
	Err error
}

func newConfigMutationRequestError(err error) error {
	if err == nil {
		return nil
	}
	return &configMutationRequestError{Err: err}
}

func (err *configMutationRequestError) Error() string {
	if err == nil || err.Err == nil {
		return "invalid config mutation request"
	}
	return err.Err.Error()
}

func (err *configMutationRequestError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}

func writeConfigMutationError(w http.ResponseWriter, err error) {
	var committed *committedConfigMutationError
	if errors.As(err, &committed) {
		writeJSON(w, http.StatusInternalServerError, committedConfigMutationResponse{
			Error:             committed.Error(),
			Operation:         committed.Operation,
			Committed:         true,
			ReconcileRequired: true,
		})
		return
	}
	var conflict *configMutationConflictError
	if errors.As(err, &conflict) {
		writeJSON(w, http.StatusConflict, configMutationConflictResponse{
			Error:      conflict.Error(),
			Operation:  conflict.Operation,
			Peer:       conflict.Target.ID,
			ControlAPI: conflict.Target.ControlAPI,
			LocalHead:  headResponse{Seq: conflict.LocalHead.Seq, Hash: conflict.LocalHead.Hash},
			RemoteHead: headResponse{Seq: conflict.RemoteHead.Seq, Hash: conflict.RemoteHead.Hash},
			RejoinHint: conflict.rejoinHint(),
		})
		return
	}
	if errors.Is(err, configlog.ErrConflict) {
		writeError(w, http.StatusConflict, err)
		return
	}
	var requestErr *configMutationRequestError
	if errors.As(err, &requestErr) {
		writeError(w, http.StatusBadRequest, requestErr)
		return
	}
	writeError(w, http.StatusInternalServerError, err)
}

func (daemon *Daemon) fetchPeerConfigHead(ctx context.Context, client *http.Client, parsed *url.URL) (configlog.Head, core.IXID, error) {
	requestURL := parsed.ResolveReference(&url.URL{Path: "/v1/control/config/head"})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return configlog.Head{}, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return configlog.Head{}, "", fmt.Errorf("fetch config head from %s: %w", requestURL, err)
	}
	defer drainAndCloseResponse(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return configlog.Head{}, "", fmt.Errorf("fetch config head from %s returned %s", requestURL, resp.Status)
	}
	var response controlConfigHeadResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return configlog.Head{}, "", fmt.Errorf("decode config head from %s: %w", requestURL, err)
	}
	if response.DomainID != string(daemon.desired.Domain.ID) {
		return configlog.Head{}, "", fmt.Errorf("peer config head domain is %q, want %q", response.DomainID, daemon.desired.Domain.ID)
	}
	if response.Head.Seq == 0 && response.Head.Hash != "" {
		return configlog.Head{}, "", fmt.Errorf("peer config head seq is zero but hash is not empty")
	}
	return configlog.Head{Seq: response.Head.Seq, Hash: response.Head.Hash}, core.IXID(response.IXID), nil
}

func (daemon *Daemon) fetchPeerConfigEvents(ctx context.Context, client *http.Client, parsed *url.URL, from, to uint64) ([]configlog.Event, []configSignerCertificate, error) {
	query := url.Values{}
	query.Set("from", fmt.Sprint(from))
	query.Set("to", fmt.Sprint(to))
	requestURL := parsed.ResolveReference(&url.URL{Path: "/v1/control/config/log", RawQuery: query.Encode()})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch config events from %s: %w", requestURL, err)
	}
	defer drainAndCloseResponse(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("fetch config events from %s returned %s", requestURL, resp.Status)
	}
	var envelope configEventsEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, nil, fmt.Errorf("decode config events from %s: %w", requestURL, err)
	}
	return envelope.Events, envelope.Signers, nil
}

func (daemon *Daemon) pushPeerConfigEvents(ctx context.Context, client *http.Client, parsed *url.URL, events []configlog.Event) error {
	envelope := configEventsEnvelope{
		Events:  events,
		Signers: daemon.signerCertificatesForEvents(events),
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	requestURL := parsed.ResolveReference(&url.URL{Path: "/v1/control/config/events"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("push config events to %s: %w", requestURL, err)
	}
	defer drainAndCloseResponse(resp)
	if resp.StatusCode == http.StatusConflict {
		return fmt.Errorf("%w: push config events to %s returned %s", configlog.ErrConflict, requestURL, resp.Status)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("push config events to %s returned %s", requestURL, resp.Status)
	}
	return nil
}

func (daemon *Daemon) localConfigSnapshot() (configSnapshotEnvelope, error) {
	daemon.configMu.RLock()
	head := daemon.head
	var events []configlog.Event
	var err error
	if head.Seq > 0 {
		events, err = daemon.store.Range(1, head.Seq)
	}
	daemon.configMu.RUnlock()
	if err != nil {
		return configSnapshotEnvelope{}, err
	}
	return configSnapshotEnvelope{
		DomainID:    string(daemon.desired.Domain.ID),
		IXID:        string(daemon.desired.IX.ID),
		Head:        headResponse{Seq: head.Seq, Hash: head.Hash},
		Events:      events,
		Signers:     daemon.signerCertificatesForEvents(events),
		GeneratedAt: time.Now().UTC(),
	}, nil
}

func (daemon *Daemon) rejoinConfigLogWithTarget(ctx context.Context, target controlTarget, preserveLocalDesired bool) (configRejoinResponse, error) {
	snapshot, err := daemon.fetchPeerConfigSnapshot(ctx, target)
	if err != nil {
		daemon.recordConfigSync(target, "error", configlog.Head{}, 0, 0, err)
		return configRejoinResponse{}, err
	}
	remoteHead := configlog.Head{Seq: snapshot.Head.Seq, Hash: snapshot.Head.Hash}
	appendedLocalDesired, err := daemon.replaceConfigLogWithVerifiedSnapshot(ctx, snapshot, preserveLocalDesired)
	if err != nil {
		status := "error"
		if errors.Is(err, configlog.ErrConflict) {
			status = "conflict"
		}
		daemon.recordConfigSync(target, status, remoteHead, 0, 0, err)
		return configRejoinResponse{}, err
	}
	daemon.configMu.RLock()
	head := daemon.head
	daemon.configMu.RUnlock()
	daemon.recordConfigSync(target, "rejoined", remoteHead, len(snapshot.Events), 0, nil)
	return configRejoinResponse{
		Rejoined:              true,
		PreservedLocalDesired: appendedLocalDesired,
		Events:                len(snapshot.Events),
		RemoteHead:            snapshot.Head,
		Head:                  headResponse{Seq: head.Seq, Hash: head.Hash},
	}, nil
}

func (daemon *Daemon) fetchPeerConfigSnapshot(ctx context.Context, target controlTarget) (configSnapshotEnvelope, error) {
	parsed, err := url.Parse(target.ControlAPI)
	if err != nil {
		return configSnapshotEnvelope{}, fmt.Errorf("parse control_api: %w", err)
	}
	client, err := daemon.controlClient(target)
	if err != nil {
		return configSnapshotEnvelope{}, err
	}
	requestURL := parsed.ResolveReference(&url.URL{Path: "/v1/control/config/snapshot"})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return configSnapshotEnvelope{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return configSnapshotEnvelope{}, fmt.Errorf("fetch config snapshot from %s: %w", requestURL, err)
	}
	defer drainAndCloseResponse(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return configSnapshotEnvelope{}, fmt.Errorf("fetch config snapshot from %s returned %s", requestURL, resp.Status)
	}
	payload, err := readLimitedBody(resp.Body, maxConfigSnapshotBytes)
	if err != nil {
		return configSnapshotEnvelope{}, err
	}
	var snapshot configSnapshotEnvelope
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return configSnapshotEnvelope{}, fmt.Errorf("decode config snapshot from %s: %w", requestURL, err)
	}
	if snapshot.DomainID != string(daemon.desired.Domain.ID) {
		return configSnapshotEnvelope{}, fmt.Errorf("peer config snapshot domain is %q, want %q", snapshot.DomainID, daemon.desired.Domain.ID)
	}
	if target.ID != "" && snapshot.IXID != "" && snapshot.IXID != string(target.ID) {
		return configSnapshotEnvelope{}, fmt.Errorf("peer config snapshot ix is %q, want %q", snapshot.IXID, target.ID)
	}
	return snapshot, nil
}

func (daemon *Daemon) replaceConfigLogWithVerifiedSnapshot(ctx context.Context, snapshot configSnapshotEnvelope, preserveLocalDesired bool) (bool, error) {
	daemon.configMu.Lock()
	defer daemon.configMu.Unlock()
	if daemon.store == nil {
		return false, fmt.Errorf("config log store is not initialized")
	}
	usedSigners, err := daemon.verifyConfigSnapshotLocked(snapshot)
	if err != nil {
		return false, err
	}
	oldDesired := daemon.desired
	oldHead := daemon.head
	oldDomain := daemon.cfg.DomainID
	oldIX := daemon.cfg.IXID
	oldFlows := daemon.snapshotFlows()
	oldState := daemon.snapshotConfigRestoreMutableState()
	storeHead, err := daemon.store.Head()
	if err != nil {
		return false, fmt.Errorf("read config log before rejoin: %w", err)
	}
	if storeHead != oldHead {
		return false, fmt.Errorf("%w: config log head changed before rejoin: runtime=%+v store=%+v", configlog.ErrConflict, oldHead, storeHead)
	}
	oldEvents, err := configLogEventsThroughHead(daemon.store, storeHead)
	if err != nil {
		return false, fmt.Errorf("snapshot current config log before rejoin: %w", err)
	}
	result := configSnapshotRestoreResult{
		head:      configlog.Head{Seq: snapshot.Head.Seq, Hash: snapshot.Head.Hash},
		committed: true,
	}
	rollback := func(cause error) (bool, error) {
		_, rollbackErr := daemon.rollbackFailedConfigSnapshotRestore(
			ctx,
			"config rejoin",
			result,
			cause,
			oldEvents,
			oldDesired,
			oldHead,
			oldDomain,
			oldIX,
			oldFlows,
			oldState,
		)
		return false, rollbackErr
	}
	var commitErr error
	if err := daemon.store.ReplaceAll(snapshot.Events); err != nil {
		if configlog.CommitSucceeded(err) {
			commitErr = err
		} else {
			return false, fmt.Errorf("replace config log from snapshot: %w", err)
		}
	}
	head, err := daemon.store.Head()
	if err != nil {
		return rollback(fmt.Errorf("read rejoined config log head: %w", err))
	}
	result.head = head
	daemon.head = head
	if _, err := daemon.applyLatestDomainTrustFromLogLocked(ctx); err != nil {
		return rollback(err)
	}
	if err := daemon.afterAdmissionStateChangedLocked(ctx); err != nil {
		return rollback(err)
	}
	appendedLocalDesired := false
	if preserveLocalDesired {
		changed, err := daemon.ensureLocalDesiredBaselineLocked(nil)
		if err != nil {
			var committed *committedConfigMutationError
			if errors.As(err, &committed) {
				commitErr = errors.Join(commitErr, err)
			} else {
				return rollback(err)
			}
		}
		appendedLocalDesired = changed
	}
	if err := daemon.refreshLocalAdvertisement(); err != nil {
		return rollback(err)
	}
	if err := daemon.commitConfigSignerCertificatesAfterLogCommit(usedSigners); err != nil {
		daemon.requestRuntimeReconcile("config rejoin signer cache", err)
		return appendedLocalDesired, newCommittedConfigMutationError("config rejoin", err)
	}
	if commitErr != nil {
		daemon.requestRuntimeReconcile("config rejoin durability", commitErr)
		return appendedLocalDesired, newCommittedConfigMutationError("config rejoin", commitErr)
	}
	return appendedLocalDesired, nil
}

func (daemon *Daemon) verifyConfigSnapshotLocked(snapshot configSnapshotEnvelope) (map[core.SignerID]*x509.Certificate, error) {
	if snapshot.DomainID != string(daemon.desired.Domain.ID) {
		return nil, fmt.Errorf("snapshot domain is %q, want %q", snapshot.DomainID, daemon.desired.Domain.ID)
	}
	if snapshot.Head.Seq == 0 {
		if snapshot.Head.Hash != "" {
			return nil, fmt.Errorf("%w: snapshot zero head has non-empty hash", configlog.ErrConflict)
		}
		if len(snapshot.Events) != 0 {
			return nil, fmt.Errorf("%w: snapshot zero head has %d events", configlog.ErrConflict, len(snapshot.Events))
		}
		return nil, nil
	}
	if uint64(len(snapshot.Events)) != snapshot.Head.Seq {
		return nil, fmt.Errorf("%w: snapshot has %d events for head seq %d", configlog.ErrConflict, len(snapshot.Events), snapshot.Head.Seq)
	}
	if len(snapshot.Events) == 0 {
		return nil, fmt.Errorf("%w: snapshot head seq %d has no events", configlog.ErrConflict, snapshot.Head.Seq)
	}
	if snapshot.Events[0].Resource != "/domain/genesis" {
		return nil, fmt.Errorf("%w: snapshot first event is %q, want /domain/genesis", configlog.ErrConflict, snapshot.Events[0].Resource)
	}
	stagedSigners, err := daemon.parseConfigSignerCertificates(snapshot.Signers)
	if err != nil {
		return nil, err
	}
	usedSigners := make(map[core.SignerID]*x509.Certificate)
	validator := configlog.NewMemoryStore()
	trust := daemon.desired.Trust
	if eventsContainDomainTrust(snapshot.Events) {
		trust = config.TrustConfig{}
	}
	for _, event := range snapshot.Events {
		if err := validator.Append(event); err != nil {
			return nil, err
		}
		cert, err := daemon.verifyConfigEventWithTrustAndSigners(event, trust, stagedSigners)
		if err != nil {
			return nil, fmt.Errorf("verify snapshot config event seq %d: %w", event.Seq, err)
		}
		if cert != nil {
			usedSigners[event.SignerID] = cert
		}
		if event.Resource == domainTrustResource {
			nextTrust, err := parseDomainTrustPayload(event.Payload, daemon.desired.Domain.ID)
			if err != nil {
				return nil, fmt.Errorf("decode snapshot domain trust seq %d: %w", event.Seq, err)
			}
			trust = nextTrust
		}
	}
	head, err := validator.Head()
	if err != nil {
		return nil, err
	}
	if head.Seq != snapshot.Head.Seq || head.Hash != snapshot.Head.Hash {
		return nil, fmt.Errorf("%w: snapshot head mismatch: events seq=%d hash=%s envelope seq=%d hash=%s",
			configlog.ErrConflict,
			head.Seq,
			head.Hash,
			snapshot.Head.Seq,
			snapshot.Head.Hash,
		)
	}
	return usedSigners, nil
}

func (daemon *Daemon) appendVerifiedConfigEvents(ctx context.Context, events []configlog.Event, signers []configSignerCertificate) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}
	daemon.configMu.Lock()
	defer daemon.configMu.Unlock()
	if daemon.store == nil {
		return 0, fmt.Errorf("config log store is not initialized")
	}
	head, err := daemon.store.Head()
	if err != nil {
		return 0, err
	}
	expectedSeq := head.Seq + 1
	expectedPrevHash := head.Hash
	trust := daemon.desired.Trust
	hasDomainTrust, err := daemon.storeHasDomainTrustLocked()
	if err != nil {
		return 0, err
	}
	if !hasDomainTrust && eventsContainDomainTrust(events) {
		trust = config.TrustConfig{}
	}
	stagedSigners, err := daemon.parseConfigSignerCertificates(signers)
	if err != nil {
		return 0, newConfigMutationRequestError(err)
	}
	usedSigners := make(map[core.SignerID]*x509.Certificate)
	for _, event := range events {
		if event.Seq != expectedSeq {
			return 0, fmt.Errorf("%w: expected seq %d, got %d", configlog.ErrConflict, expectedSeq, event.Seq)
		}
		if event.PrevHash != expectedPrevHash {
			return 0, fmt.Errorf("%w: prev_hash mismatch at seq %d", configlog.ErrConflict, event.Seq)
		}
		cert, err := daemon.verifyConfigEventWithTrustAndSigners(event, trust, stagedSigners)
		if err != nil {
			return 0, newConfigMutationRequestError(fmt.Errorf("verify config event seq %d: %w", event.Seq, err))
		}
		if cert != nil {
			usedSigners[event.SignerID] = cert
		}
		if event.Resource == domainTrustResource {
			trust, err = parseDomainTrustPayload(event.Payload, daemon.desired.Domain.ID)
			if err != nil {
				return 0, newConfigMutationRequestError(fmt.Errorf("decode domain trust event seq %d: %w", event.Seq, err))
			}
		}
		expectedSeq++
		expectedPrevHash, err = event.Hash()
		if err != nil {
			return 0, err
		}
	}

	var commitErr error
	if err := daemon.store.AppendBatch(events); err != nil {
		if configlog.CommitSucceeded(err) {
			commitErr = err
		} else {
			return 0, err
		}
	}
	appended := len(events)
	head, err = daemon.store.Head()
	if err != nil {
		daemon.requestRuntimeReconcile("config sync", err)
		return appended, newCommittedConfigMutationError("config sync", err)
	}
	daemon.head = head
	if _, err := daemon.applyLatestDomainTrustFromLogLocked(ctx); err != nil {
		daemon.requestRuntimeReconcile("config sync", err)
		return appended, newCommittedConfigMutationError("config sync", err)
	}
	if err := daemon.afterAdmissionStateChangedLocked(ctx); err != nil {
		daemon.requestRuntimeReconcile("config sync", err)
		return appended, newCommittedConfigMutationError("config sync", err)
	}
	if err := daemon.refreshLocalAdvertisement(); err != nil {
		daemon.requestRuntimeReconcile("config sync", err)
		return appended, newCommittedConfigMutationError("config sync", err)
	}
	if err := daemon.commitConfigSignerCertificatesAfterLogCommit(usedSigners); err != nil {
		daemon.requestRuntimeReconcile("config sync", err)
		return appended, newCommittedConfigMutationError("config sync", err)
	}
	if commitErr != nil {
		daemon.requestRuntimeReconcile("config sync durability", commitErr)
		return appended, newCommittedConfigMutationError("config sync", commitErr)
	}
	return appended, nil
}

func (daemon *Daemon) commitConfigSignerCertificatesAfterLogCommit(signers map[core.SignerID]*x509.Certificate) error {
	err := daemon.commitConfigSignerCertificates(signers, true)
	if err == nil {
		return nil
	}
	stageErr := daemon.commitConfigSignerCertificates(signers, false)
	return errors.Join(err, wrapOperationError("stage config signer cache for persistence retry", stageErr))
}

func (daemon *Daemon) ensureConfigGenesisEvent(desired config.Desired) error {
	if daemon.store == nil {
		return fmt.Errorf("config log store is not initialized")
	}
	head, err := daemon.store.Head()
	if err != nil {
		return err
	}
	if head.Seq > 0 {
		return nil
	}
	event, err := daemon.configGenesisEvent(desired)
	if err != nil {
		return err
	}
	if err := daemon.store.Append(event); err != nil {
		return fmt.Errorf("append config genesis event: %w", err)
	}
	return nil
}

func (daemon *Daemon) configGenesisEvent(desired config.Desired) (configlog.Event, error) {
	payload, err := daemon.configGenesisPayload(desired)
	if err != nil {
		return configlog.Event{}, err
	}
	return configlog.Event{
		DomainID:    desired.Domain.ID,
		EventID:     core.EventID("evt-genesis-" + string(desired.Domain.ID)),
		Seq:         1,
		Resource:    core.ResourcePath("/domain/genesis"),
		Action:      configlog.ActionCreate,
		Payload:     payload,
		SignerID:    core.SignerID("genesis:" + string(desired.Domain.ID)),
		Signature:   []byte(genesisSignature),
		CreatedAt:   time.Unix(0, 0).UTC(),
		EffectiveAt: time.Unix(0, 0).UTC(),
	}, nil
}

func (daemon *Daemon) configGenesisPayload(desired config.Desired) ([]byte, error) {
	fingerprints := make([]string, 0, len(desired.Domain.TrustRoots))
	for _, path := range desired.Domain.TrustRoots {
		cert, _, err := pki.LoadCertificate(path)
		if err != nil {
			return nil, fmt.Errorf("load trust root %q: %w", path, err)
		}
		sum := sha256.Sum256(cert.Raw)
		fingerprints = append(fingerprints, hex.EncodeToString(sum[:]))
	}
	sort.Strings(fingerprints)
	return json.Marshal(genesisPayload{
		Version:    1,
		DomainID:   string(desired.Domain.ID),
		TrustRoots: fingerprints,
	})
}

func (daemon *Daemon) verifyConfigGenesisEvent(event configlog.Event) error {
	if err := event.ValidateBasic(); err != nil {
		return err
	}
	if event.Seq != 1 {
		return fmt.Errorf("genesis event seq is %d, want 1", event.Seq)
	}
	if event.DomainID != daemon.desired.Domain.ID {
		return fmt.Errorf("genesis event domain is %q, want %q", event.DomainID, daemon.desired.Domain.ID)
	}
	if event.EventID != core.EventID("evt-genesis-"+string(daemon.desired.Domain.ID)) {
		return fmt.Errorf("genesis event id is %q", event.EventID)
	}
	if event.Resource != "/domain/genesis" {
		return fmt.Errorf("genesis event resource is %q", event.Resource)
	}
	if event.Action != configlog.ActionCreate {
		return fmt.Errorf("genesis event action is %q, want %q", event.Action, configlog.ActionCreate)
	}
	if event.PrevHash != "" {
		return fmt.Errorf("genesis event prev_hash must be empty")
	}
	if event.SignerID != core.SignerID("genesis:"+string(daemon.desired.Domain.ID)) {
		return fmt.Errorf("genesis event signer is %q", event.SignerID)
	}
	if !bytes.Equal(event.Signature, []byte(genesisSignature)) {
		return fmt.Errorf("genesis event signature is invalid")
	}
	if !event.CreatedAt.Equal(time.Unix(0, 0).UTC()) || !event.EffectiveAt.Equal(time.Unix(0, 0).UTC()) {
		return fmt.Errorf("genesis event timestamps are not canonical")
	}
	want, err := daemon.configGenesisPayload(daemon.desired)
	if err != nil {
		return err
	}
	if !bytes.Equal(event.Payload, want) {
		return fmt.Errorf("genesis payload does not match local domain trust roots")
	}
	return nil
}

func (daemon *Daemon) localConfigEventsAfter(remoteHead configlog.Head) ([]configlog.Event, error) {
	daemon.configMu.RLock()
	defer daemon.configMu.RUnlock()
	localHead := daemon.head
	if remoteHead.Seq == 0 && remoteHead.Hash != "" {
		return nil, fmt.Errorf("%w: remote zero head has non-empty hash", configlog.ErrConflict)
	}
	if remoteHead.Seq > localHead.Seq {
		return nil, fmt.Errorf("%w: remote head seq %d is after local head %d", configlog.ErrConflict, remoteHead.Seq, localHead.Seq)
	}
	if remoteHead.Seq > 0 {
		events, err := daemon.store.Range(remoteHead.Seq, remoteHead.Seq)
		if err != nil {
			return nil, err
		}
		hash, err := events[0].Hash()
		if err != nil {
			return nil, err
		}
		if hash != remoteHead.Hash {
			return nil, fmt.Errorf("%w: remote head seq %d hash is not a local prefix", configlog.ErrConflict, remoteHead.Seq)
		}
	}
	if remoteHead.Seq == localHead.Seq {
		return nil, nil
	}
	return daemon.store.Range(remoteHead.Seq+1, localHead.Seq)
}

func (daemon *Daemon) verifyExistingConfigLog(store configlog.Store, desired config.Desired) error {
	head, err := store.Head()
	if err != nil {
		return err
	}
	if head.Seq == 0 {
		return nil
	}
	events, err := store.Range(1, head.Seq)
	if err != nil {
		return err
	}
	expectedSeq := uint64(1)
	expectedPrevHash := ""
	trust := desired.Trust
	if eventsContainDomainTrust(events) {
		trust = config.TrustConfig{}
	}
	for _, event := range events {
		if event.Seq != expectedSeq {
			return fmt.Errorf("%w: expected seq %d, got %d", configlog.ErrConflict, expectedSeq, event.Seq)
		}
		if event.PrevHash != expectedPrevHash {
			return fmt.Errorf("%w: prev_hash mismatch at seq %d", configlog.ErrConflict, event.Seq)
		}
		if err := daemon.verifyConfigEventWithTrust(event, trust); err != nil {
			return err
		}
		if event.Resource == domainTrustResource {
			trust, err = parseDomainTrustPayload(event.Payload, desired.Domain.ID)
			if err != nil {
				return err
			}
		}
		expectedSeq++
		expectedPrevHash, err = event.Hash()
		if err != nil {
			return err
		}
	}
	return nil
}

func (daemon *Daemon) verifyConfigEvent(event configlog.Event) error {
	return daemon.verifyConfigEventWithTrust(event, daemon.desired.Trust)
}

func (daemon *Daemon) verifyConfigEventWithTrust(event configlog.Event, trust config.TrustConfig) error {
	_, err := daemon.verifyConfigEventWithTrustAndSigners(event, trust, nil)
	return err
}

func (daemon *Daemon) verifyConfigEventWithTrustAndSigners(event configlog.Event, trust config.TrustConfig, stagedSigners map[core.SignerID]*x509.Certificate) (*x509.Certificate, error) {
	if event.Resource == "/domain/genesis" {
		return nil, daemon.verifyConfigGenesisEvent(event)
	}
	if err := event.ValidateBasic(); err != nil {
		return nil, err
	}
	if event.DomainID != daemon.desired.Domain.ID {
		return nil, fmt.Errorf("event domain is %q, want %q", event.DomainID, daemon.desired.Domain.ID)
	}
	signerIX, ok := ixFromSignerID(event.SignerID)
	if !ok {
		return nil, fmt.Errorf("unsupported signer id %q", event.SignerID)
	}
	cert, err := daemon.verifyConfigEventSigner(event, signerIX, trust, stagedSigners)
	if err != nil {
		return nil, err
	}
	if err := daemon.verifyConfigEventAdminProofs(event, trust); err != nil {
		return nil, err
	}
	if event.Resource == "/desired" || isIXDesiredResource(event.Resource) {
		if event.Action != configlog.ActionUpsert {
			return nil, fmt.Errorf("desired event action is %q, want %q", event.Action, configlog.ActionUpsert)
		}
		var desired config.Desired
		if err := json.Unmarshal(event.Payload, &desired); err != nil {
			return nil, fmt.Errorf("decode desired payload: %w", err)
		}
		desired = config.Normalize(desired)
		if err := daemon.validateDesiredSchemaForRuntime(desired); err != nil {
			return nil, fmt.Errorf("validate desired payload: %w", err)
		}
		if desired.Domain.ID != event.DomainID {
			return nil, fmt.Errorf("desired payload domain is %q, want %q", desired.Domain.ID, event.DomainID)
		}
		if desired.IX.ID != signerIX {
			return nil, fmt.Errorf("desired payload ix is %q, want signer %q", desired.IX.ID, signerIX)
		}
		if event.Resource != "/desired" && event.Resource != desiredResourceForIX(signerIX) {
			return nil, fmt.Errorf("desired event resource is %q, want %q", event.Resource, desiredResourceForIX(signerIX))
		}
		return cert, nil
	}
	if event.Resource == domainTrustResource {
		if event.Action != configlog.ActionUpsert {
			return nil, fmt.Errorf("domain trust event action is %q, want %q", event.Action, configlog.ActionUpsert)
		}
		if err := daemon.verifyAdminProofPolicy(event.AdminProofs, trust); err != nil {
			return nil, err
		}
		if _, err := parseDomainTrustPayload(event.Payload, daemon.desired.Domain.ID); err != nil {
			return nil, err
		}
		return cert, nil
	}
	if isDomainAdmissionResource(event.Resource) {
		if event.Action != configlog.ActionUpsert {
			return nil, fmt.Errorf("domain admission event action is %q, want %q", event.Action, configlog.ActionUpsert)
		}
		if err := daemon.verifyAdminProofPolicy(event.AdminProofs, trust); err != nil {
			return nil, err
		}
		admission, err := parseAdmissionPayload(event.Payload, daemon.desired.Domain.ID)
		if err != nil {
			return nil, err
		}
		if resourceIX, ok := ixFromAdmissionResource(event.Resource); !ok || resourceIX != admission.IXID {
			return nil, fmt.Errorf("domain admission resource is %q, want %q", event.Resource, admissionResourceForIX(admission.IXID))
		}
		return cert, nil
	}
	if isDomainEndpointGrantResource(event.Resource) {
		if event.Action != configlog.ActionUpsert {
			return nil, fmt.Errorf("domain endpoint grant event action is %q, want %q", event.Action, configlog.ActionUpsert)
		}
		if err := daemon.verifyAdminProofPolicy(event.AdminProofs, trust); err != nil {
			return nil, err
		}
		grant, err := parseEndpointGrantPayload(event.Payload, daemon.desired.Domain.ID)
		if err != nil {
			return nil, err
		}
		if resourceGrantID, ok := grantIDFromEndpointGrantResource(event.Resource); !ok || resourceGrantID != grant.GrantID {
			return nil, fmt.Errorf("domain endpoint grant resource is %q, want %q", event.Resource, endpointGrantResourceForID(grant.GrantID))
		}
		return cert, nil
	}
	return nil, fmt.Errorf("unsupported config resource %q", event.Resource)
}

func (daemon *Daemon) verifyConfigEventSigner(event configlog.Event, signerIX core.IXID, trust config.TrustConfig, stagedSigners map[core.SignerID]*x509.Certificate) (*x509.Certificate, error) {
	candidates := daemon.configSignerCertificateCandidates(event.SignerID, stagedSigners)
	if len(candidates) == 0 {
		return nil, fmt.Errorf("signer certificate %q is not known", event.SignerID)
	}
	var errs []error
	for _, cert := range candidates {
		if cert == nil {
			continue
		}
		if err := daemon.verifyConfigEventSignerCertificate(event, signerIX, trust, cert); err != nil {
			errs = append(errs, err)
			continue
		}
		return cert, nil
	}
	if len(errs) == 0 {
		return nil, fmt.Errorf("signer certificate %q is not known", event.SignerID)
	}
	return nil, fmt.Errorf("verify signer certificate %q: %w", event.SignerID, errors.Join(errs...))
}

func (daemon *Daemon) verifyConfigEventSignerCertificate(event configlog.Event, signerIX core.IXID, trust config.TrustConfig, cert *x509.Certificate) error {
	if err := verifyCertificateNotRevokedByTrust(trust, cert, "signer certificate"); err != nil {
		return err
	}
	meta := pki.ParseMetadata(cert)
	if meta.Role != pki.RoleIX {
		return fmt.Errorf("signer certificate role is %q, want %q", meta.Role, pki.RoleIX)
	}
	if meta.Domain != string(daemon.desired.Domain.ID) {
		return fmt.Errorf("signer certificate domain is %q, want %q", meta.Domain, daemon.desired.Domain.ID)
	}
	if meta.IX != string(signerIX) {
		return fmt.Errorf("signer certificate ix is %q, want %q", meta.IX, signerIX)
	}
	roots, err := daemon.trustRootCertificatesWithTrust(trust)
	if err != nil {
		return err
	}
	if err := pki.VerifyChain(cert, roots, nil); err != nil {
		return err
	}
	signingBytes, err := event.SigningBytes()
	if err != nil {
		return err
	}
	return pki.Verify(cert, signingBytes, event.Signature)
}

func (daemon *Daemon) verifyConfigEventAdminProofs(event configlog.Event, trust config.TrustConfig) error {
	for i, proof := range event.AdminProofs {
		if proof.SignerID == "" {
			return fmt.Errorf("admin proof %d signer_id is required", i)
		}
		if len(proof.Certificate) == 0 {
			return fmt.Errorf("admin proof %d certificate is required", i)
		}
		if len(proof.Signature) == 0 {
			return fmt.Errorf("admin proof %d signature is required", i)
		}
		if proof.Timestamp.IsZero() {
			return fmt.Errorf("admin proof %d timestamp is required", i)
		}
		cert, err := x509.ParseCertificate(proof.Certificate)
		if err != nil {
			return fmt.Errorf("parse admin proof %d certificate: %w", i, err)
		}
		if got := signerIDForAdminCert(cert); got != proof.SignerID {
			return fmt.Errorf("admin proof %d signer is %q, certificate is %q", i, proof.SignerID, got)
		}
		if err := daemon.verifyAdminCertificateWithTrust(cert, trust); err != nil {
			return fmt.Errorf("verify admin proof %d certificate: %w", i, err)
		}
		if proof.Timestamp.Before(cert.NotBefore) || proof.Timestamp.After(cert.NotAfter) {
			return fmt.Errorf("admin proof %d timestamp is outside certificate validity", i)
		}
		signingBytes := adminauth.SigningBytesForBodyHash(proof.Method, proof.RequestURI, proof.Timestamp.UTC().Format(time.RFC3339Nano), proof.BodySHA256)
		if err := pki.Verify(cert, signingBytes, proof.Signature); err != nil {
			return fmt.Errorf("verify admin proof %d signature: %w", i, err)
		}
	}
	return nil
}

func (daemon *Daemon) registerLocalConfigSigner() error {
	if daemon.desired.IX.CertPath == "" {
		return nil
	}
	cert, _, err := pki.LoadCertificate(daemon.desired.IX.CertPath)
	if err != nil {
		return err
	}
	signerID, err := daemon.configSignerIDForCertificate(cert)
	if err != nil {
		return err
	}
	return daemon.commitConfigSignerCertificates(map[core.SignerID]*x509.Certificate{signerID: cert}, false)
}

func (daemon *Daemon) parseConfigSignerCertificates(signers []configSignerCertificate) (map[core.SignerID]*x509.Certificate, error) {
	if len(signers) == 0 {
		return nil, nil
	}
	result := make(map[core.SignerID]*x509.Certificate, len(signers))
	for _, signer := range signers {
		if len(signer.Certificate) == 0 {
			return nil, fmt.Errorf("signer certificate %q is empty", signer.SignerID)
		}
		cert, err := x509.ParseCertificate(signer.Certificate)
		if err != nil {
			return nil, fmt.Errorf("parse signer certificate %q: %w", signer.SignerID, err)
		}
		signerID, err := daemon.configSignerIDForCertificate(cert)
		if err != nil {
			return nil, err
		}
		if signer.SignerID != "" && signer.SignerID != signerID {
			return nil, fmt.Errorf("signer certificate id is %q, envelope listed %q", signerID, signer.SignerID)
		}
		if existing := result[signerID]; existing != nil && !bytes.Equal(existing.Raw, cert.Raw) {
			return nil, fmt.Errorf("multiple certificates supplied for signer %q", signerID)
		}
		result[signerID] = cert
	}
	return result, nil
}

func (daemon *Daemon) configSignerIDForCertificate(cert *x509.Certificate) (core.SignerID, error) {
	if cert == nil {
		return "", fmt.Errorf("signer certificate is required")
	}
	meta := pki.ParseMetadata(cert)
	if meta.Role != pki.RoleIX {
		return "", fmt.Errorf("signer certificate role is %q, want %q", meta.Role, pki.RoleIX)
	}
	if meta.Domain != string(daemon.desired.Domain.ID) {
		return "", fmt.Errorf("signer certificate domain is %q, want %q", meta.Domain, daemon.desired.Domain.ID)
	}
	if strings.TrimSpace(meta.IX) == "" {
		return "", fmt.Errorf("signer certificate ix is required")
	}
	return signerIDForIX(core.IXID(meta.IX)), nil
}

func (daemon *Daemon) commitConfigSignerCertificates(signers map[core.SignerID]*x509.Certificate, persist bool) error {
	if len(signers) == 0 {
		return nil
	}
	validated := make(map[core.SignerID]*x509.Certificate, len(signers))
	for signerID, cert := range signers {
		if cert == nil {
			continue
		}
		expected, err := daemon.configSignerIDForCertificate(cert)
		if err != nil {
			return err
		}
		if expected != signerID {
			return fmt.Errorf("signer certificate id is %q, used as %q", expected, signerID)
		}
		validated[signerID] = cert
	}

	daemon.signerMu.Lock()
	defer daemon.signerMu.Unlock()
	next := make(map[core.SignerID]*x509.Certificate, len(daemon.signerCerts)+len(validated))
	for signerID, cert := range daemon.signerCerts {
		next[signerID] = cert
	}
	changed := false
	for signerID, cert := range validated {
		existing := next[signerID]
		if existing == nil || !bytes.Equal(existing.Raw, cert.Raw) {
			next[signerID] = cert
			changed = true
		}
	}
	if persist && changed {
		if err := daemon.persistConfigSignerCacheState(next); err != nil {
			if stateFileCommitSucceeded(err) {
				daemon.signerCerts = next
			}
			return err
		}
	}
	daemon.signerCerts = next
	return nil
}

func (daemon *Daemon) registerConfigSignerCertificate(cert *x509.Certificate, persist bool) (core.SignerID, error) {
	if cert == nil {
		return "", newConfigMutationRequestError(fmt.Errorf("signer certificate is required"))
	}
	meta := pki.ParseMetadata(cert)
	if meta.Role != pki.RoleIX {
		return "", newConfigMutationRequestError(fmt.Errorf("signer certificate role is %q, want %q", meta.Role, pki.RoleIX))
	}
	if meta.Domain != string(daemon.desired.Domain.ID) {
		return "", newConfigMutationRequestError(fmt.Errorf("signer certificate domain is %q, want %q", meta.Domain, daemon.desired.Domain.ID))
	}
	if err := daemon.verifyCertificateNotRevoked(cert, "signer certificate"); err != nil {
		return "", newConfigMutationRequestError(err)
	}
	if strings.TrimSpace(meta.IX) == "" {
		return "", newConfigMutationRequestError(fmt.Errorf("signer certificate ix is required"))
	}
	roots, err := daemon.trustRootCertificates()
	if err != nil {
		return "", err
	}
	if err := pki.VerifyChain(cert, roots, nil); err != nil {
		return "", newConfigMutationRequestError(err)
	}
	signerID := signerIDForIX(core.IXID(meta.IX))
	if err := daemon.commitConfigSignerCertificates(map[core.SignerID]*x509.Certificate{signerID: cert}, persist); err != nil {
		return "", err
	}
	return signerID, nil
}

func (daemon *Daemon) configSignerCertificate(signer core.SignerID) (*x509.Certificate, bool) {
	daemon.signerMu.RLock()
	defer daemon.signerMu.RUnlock()
	cert := daemon.signerCerts[signer]
	return cert, cert != nil
}

func (daemon *Daemon) configSignerCertificateCandidates(signer core.SignerID, staged map[core.SignerID]*x509.Certificate) []*x509.Certificate {
	candidates := make([]*x509.Certificate, 0, 2)
	if cert := staged[signer]; cert != nil {
		candidates = append(candidates, cert)
	}
	daemon.signerMu.RLock()
	cert := daemon.signerCerts[signer]
	daemon.signerMu.RUnlock()
	if cert != nil {
		if len(candidates) == 0 || !bytes.Equal(candidates[0].Raw, cert.Raw) {
			candidates = append(candidates, cert)
		}
	}
	return candidates
}

func (daemon *Daemon) signerCertificatesForEvents(events []configlog.Event) []configSignerCertificate {
	seen := make(map[core.SignerID]struct{}, len(events))
	out := make([]configSignerCertificate, 0)
	daemon.signerMu.RLock()
	defer daemon.signerMu.RUnlock()
	for _, event := range events {
		if _, ok := seen[event.SignerID]; ok {
			continue
		}
		seen[event.SignerID] = struct{}{}
		cert := daemon.signerCerts[event.SignerID]
		if cert == nil {
			continue
		}
		out = append(out, configSignerCertificate{
			SignerID:    event.SignerID,
			Certificate: cert.Raw,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].SignerID < out[j].SignerID
	})
	return out
}

func signerIDForIX(ix core.IXID) core.SignerID {
	return core.SignerID("ix:" + string(ix))
}

func desiredResourceForIX(ix core.IXID) core.ResourcePath {
	return core.ResourcePath("/ix/" + string(ix) + "/desired")
}

func isIXDesiredResource(resource core.ResourcePath) bool {
	raw := string(resource)
	return strings.HasPrefix(raw, "/ix/") && strings.HasSuffix(raw, "/desired") && len(raw) > len("/ix//desired")
}

func ixFromSignerID(signer core.SignerID) (core.IXID, bool) {
	prefix, value, ok := strings.Cut(string(signer), ":")
	if !ok || prefix != "ix" || strings.TrimSpace(value) == "" {
		return "", false
	}
	return core.IXID(value), true
}

func (daemon *Daemon) configSignerCachePath() string {
	if daemon.cfg.DataDir == "" {
		return ""
	}
	return filepath.Join(daemon.cfg.DataDir, "config-signers.json")
}

func (daemon *Daemon) loadConfigSignerCache() error {
	path := daemon.configSignerCachePath()
	if path == "" {
		return nil
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read config signer cache %q: %w", path, err)
	}
	var state persistedConfigSigners
	if err := json.Unmarshal(payload, &state); err != nil {
		return fmt.Errorf("decode config signer cache %q: %w", path, err)
	}
	signers, err := daemon.parseConfigSignerCertificates(state.Signers)
	if err != nil {
		return err
	}
	return daemon.commitConfigSignerCertificates(signers, false)
}

func (daemon *Daemon) persistConfigSignerCache() error {
	daemon.signerMu.Lock()
	defer daemon.signerMu.Unlock()
	return daemon.persistConfigSignerCacheState(daemon.signerCerts)
}

func (daemon *Daemon) persistConfigSignerCacheState(signers map[core.SignerID]*x509.Certificate) error {
	path := daemon.configSignerCachePath()
	if path == "" {
		return nil
	}
	ids := make([]string, 0, len(signers))
	for signerID := range signers {
		ids = append(ids, string(signerID))
	}
	sort.Strings(ids)
	state := persistedConfigSigners{Version: 1, Signers: make([]configSignerCertificate, 0, len(ids))}
	for _, rawID := range ids {
		signerID := core.SignerID(rawID)
		cert := signers[signerID]
		if cert == nil {
			continue
		}
		state.Signers = append(state.Signers, configSignerCertificate{SignerID: signerID, Certificate: cert.Raw})
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create config signer cache dir: %w", err)
	}
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err := writeStateFileAtomic(path, payload, 0o600); err != nil {
		return fmt.Errorf("replace config signer cache %q: %w", path, err)
	}
	return nil
}

func (daemon *Daemon) recordConfigSync(target controlTarget, status string, remoteHead configlog.Head, pulled, pushed int, err error) {
	key := configSyncTargetKey(target)
	daemon.configMu.RLock()
	localHead := daemon.head
	daemon.configMu.RUnlock()
	state := configSyncPeerState{
		Peer:         string(target.ID),
		DomainID:     string(target.Domain),
		ControlAPI:   target.ControlAPI,
		Status:       status,
		LocalHead:    headResponse{Seq: localHead.Seq, Hash: localHead.Hash},
		RemoteHead:   headResponse{Seq: remoteHead.Seq, Hash: remoteHead.Hash},
		LastSync:     time.Now().UTC(),
		PulledEvents: pulled,
		PushedEvents: pushed,
	}
	if err != nil {
		state.LastError = err.Error()
	}
	daemon.configSyncMu.Lock()
	if daemon.configSync == nil {
		daemon.configSync = make(map[string]configSyncPeerState)
	}
	daemon.configSync[key] = state
	daemon.configSyncMu.Unlock()
}

func (daemon *Daemon) configSyncSnapshot() []configSyncPeerState {
	daemon.configSyncMu.RLock()
	defer daemon.configSyncMu.RUnlock()
	keys := make([]string, 0, len(daemon.configSync))
	for key := range daemon.configSync {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]configSyncPeerState, 0, len(keys))
	for _, key := range keys {
		out = append(out, daemon.configSync[key])
	}
	return out
}

func (daemon *Daemon) configSyncState(target controlTarget) (configSyncPeerState, bool) {
	daemon.configSyncMu.RLock()
	defer daemon.configSyncMu.RUnlock()
	state, ok := daemon.configSync[configSyncTargetKey(target)]
	if ok {
		return state, true
	}
	if target.ControlAPI != "" {
		for _, state := range daemon.configSync {
			if state.ControlAPI == target.ControlAPI {
				return state, true
			}
		}
	}
	return state, ok
}

func configSyncTargetKey(target controlTarget) string {
	if target.ID != "" {
		return string(target.ID)
	}
	return target.ControlAPI
}

func configSyncDoctorStatus(states []configSyncPeerState) string {
	if len(states) == 0 {
		return "ok"
	}
	worst := "ok"
	for _, state := range states {
		switch state.Status {
		case "conflict":
			return "degraded"
		case "error":
			worst = "warn"
		}
	}
	return worst
}

func configSyncDoctorDetail(states []configSyncPeerState) string {
	if len(states) == 0 {
		return "no config sync peers"
	}
	counts := make(map[string]int)
	for _, state := range states {
		counts[state.Status]++
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", key, counts[key]))
	}
	return strings.Join(parts, " ")
}
