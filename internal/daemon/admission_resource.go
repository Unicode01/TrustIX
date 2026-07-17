package daemon

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"trustix.local/trustix/internal/configlog"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/pki"
)

const (
	domainAdmissionsPrefix = "/domain/admissions/"

	admissionStateApproved = "approved"
	admissionStateRevoked  = "revoked"
)

type admissionPayload struct {
	Version                     int             `json:"version"`
	DomainID                    core.DomainID   `json:"domain_id"`
	IXID                        core.IXID       `json:"ix_id"`
	State                       string          `json:"state"`
	IXCertFingerprint           string          `json:"ix_cert_fingerprint"`
	AllowedPrefixes             []core.Prefix   `json:"allowed_prefixes,omitempty"`
	RouteAuthFingerprints       []string        `json:"route_auth_fingerprints,omitempty"`
	ControlAPI                  string          `json:"control_api,omitempty"`
	EffectiveSeq                uint64          `json:"effective_seq"`
	EffectiveAt                 time.Time       `json:"effective_at"`
	ApprovedByConfigHead        headResponse    `json:"approved_by_config_head,omitempty"`
	ObservedBy                  []admissionSeen `json:"observed_by,omitempty"`
	LastObservedAdvertisementAt time.Time       `json:"last_observed_advertisement_at,omitempty"`
}

type admissionSeen struct {
	IXID       core.IXID `json:"ix_id"`
	ConfigSeq  uint64    `json:"config_seq"`
	ConfigHash string    `json:"config_hash"`
	SeenAt     time.Time `json:"seen_at"`
	Source     string    `json:"source,omitempty"`
}

type admissionApplyRequest struct {
	IXID                  core.IXID     `json:"ix_id"`
	IXCertFingerprint     string        `json:"ix_cert_fingerprint"`
	AllowedPrefixes       []core.Prefix `json:"allowed_prefixes,omitempty"`
	RouteAuthFingerprints []string      `json:"route_auth_fingerprints,omitempty"`
	ControlAPI            string        `json:"control_api,omitempty"`
	EffectiveAt           time.Time     `json:"effective_at,omitempty"`
}

type admissionApprovePendingRequest struct {
	IXID                  core.IXID     `json:"ix_id"`
	AllowedPrefixes       []core.Prefix `json:"allowed_prefixes,omitempty"`
	RouteAuthFingerprints []string      `json:"route_auth_fingerprints,omitempty"`
	ControlAPI            string        `json:"control_api,omitempty"`
	EffectiveAt           time.Time     `json:"effective_at,omitempty"`
}

type admissionRevokeRequest struct {
	IXID core.IXID `json:"ix_id"`
}

type admissionListResponse struct {
	Mode       string             `json:"mode"`
	Head       headResponse       `json:"head"`
	Admissions []admissionPayload `json:"admissions"`
}

type pendingAdmissionsResponse struct {
	Pending []pendingAdmissionResponse `json:"pending"`
}

type pendingAdmissionResponse struct {
	IXID                  core.IXID             `json:"ix_id"`
	FirstSeen             time.Time             `json:"first_seen"`
	LastSeen              time.Time             `json:"last_seen"`
	ExpiresAt             time.Time             `json:"expires_at"`
	TTLSeconds            int64                 `json:"ttl_seconds"`
	Expired               bool                  `json:"expired"`
	Source                string                `json:"source,omitempty"`
	RejectReason          string                `json:"reject_reason,omitempty"`
	IXCertFingerprint     string                `json:"ix_cert_fingerprint,omitempty"`
	AllowedPrefixes       []core.Prefix         `json:"allowed_prefixes,omitempty"`
	RouteAuthFingerprints []string              `json:"route_auth_fingerprints,omitempty"`
	ControlAPI            string                `json:"control_api,omitempty"`
	ConfigHead            headResponse          `json:"config_head"`
	Advertisement         advertisementResponse `json:"advertisement"`
}

func admissionResourceForIX(ix core.IXID) core.ResourcePath {
	return core.ResourcePath(domainAdmissionsPrefix + string(ix))
}

func isDomainAdmissionResource(resource core.ResourcePath) bool {
	raw := string(resource)
	return strings.HasPrefix(raw, domainAdmissionsPrefix) && len(raw) > len(domainAdmissionsPrefix)
}

func ixFromAdmissionResource(resource core.ResourcePath) (core.IXID, bool) {
	if !isDomainAdmissionResource(resource) {
		return "", false
	}
	ix := core.IXID(strings.TrimPrefix(string(resource), domainAdmissionsPrefix))
	if err := ix.Validate(); err != nil {
		return "", false
	}
	return ix, true
}

func (daemon *Daemon) handleAdmissionsList(w http.ResponseWriter, r *http.Request) {
	daemon.configMu.RLock()
	admissions, err := daemon.latestAdmissionsFromLogLocked()
	head := daemon.head
	daemon.configMu.RUnlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	admissions = daemon.decorateAdmissionObservations(admissions, head)
	writeJSON(w, http.StatusOK, admissionListResponse{
		Mode:       admissionMode(),
		Head:       headResponse{Seq: head.Seq, Hash: head.Hash},
		Admissions: admissions,
	})
}

func (daemon *Daemon) handleAdmissionShow(w http.ResponseWriter, r *http.Request) {
	ixID := core.IXID(r.PathValue("ix_id"))
	if err := ixID.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	daemon.configMu.RLock()
	admission, ok, err := daemon.latestAdmissionForIXLocked(ixID)
	daemon.configMu.RUnlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, struct {
			IXID core.IXID `json:"ix_id"`
			Mode string    `json:"mode"`
		}{IXID: ixID, Mode: admissionMode()})
		return
	}
	daemon.configMu.RLock()
	head := daemon.head
	daemon.configMu.RUnlock()
	admission = daemon.decorateAdmissionObservation(admission, head)
	writeJSON(w, http.StatusOK, admission)
}

func (daemon *Daemon) handleAdmissionsPendingList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, pendingAdmissionsResponse{Pending: daemon.pendingAdmissionsSnapshot()})
}

func (daemon *Daemon) handleAdmissionPendingShow(w http.ResponseWriter, r *http.Request) {
	ixID := core.IXID(r.PathValue("ix_id"))
	if err := ixID.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	pending, ok := daemon.pendingAdmissionSnapshot(ixID)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("pending IX %q is not found", ixID))
		return
	}
	writeJSON(w, http.StatusOK, pending)
}

func (daemon *Daemon) handleAdmissionApprove(w http.ResponseWriter, r *http.Request) {
	payload, err := readLimitedBody(r.Body, 64<<10)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var request admissionApplyRequest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode admission request: %w", err))
		return
	}
	admission, err := daemon.admissionPayloadFromApproveRequest(request)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	changed, err := daemon.applyAdmissionConfig(r.Context(), admission)
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	daemon.configMu.RLock()
	head := daemon.head
	daemon.configMu.RUnlock()
	writeJSON(w, http.StatusOK, struct {
		Applied   bool             `json:"applied"`
		Changed   bool             `json:"changed"`
		Admission admissionPayload `json:"admission"`
		Head      headResponse     `json:"head"`
	}{Applied: true, Changed: changed, Admission: admission, Head: headResponse{Seq: head.Seq, Hash: head.Hash}})
}

func (daemon *Daemon) handleAdmissionApprovePending(w http.ResponseWriter, r *http.Request) {
	payload, err := readLimitedBody(r.Body, 64<<10)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var request admissionApprovePendingRequest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode approve pending admission request: %w", err))
		return
	}
	admission, err := daemon.admissionPayloadFromApprovePendingRequest(request)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	changed, err := daemon.applyAdmissionConfig(r.Context(), admission)
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	memberAccepted := false
	if merged, err := daemon.mergePendingAdvertisement(request.IXID, "approved-pending"); err == nil {
		memberAccepted = merged
	} else if _, ok := daemon.dynamicPeerConfig(request.IXID); ok {
		memberAccepted = true
	}
	if memberAccepted {
		if err := daemon.applyRuntimeDataplaneSnapshot(r.Context()); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		daemon.scheduleRuntimeRouteWarmup(r.Context())
	}
	daemon.configMu.RLock()
	head := daemon.head
	daemon.configMu.RUnlock()
	writeJSON(w, http.StatusOK, struct {
		Applied        bool             `json:"applied"`
		Changed        bool             `json:"changed"`
		MemberAccepted bool             `json:"member_accepted"`
		Admission      admissionPayload `json:"admission"`
		Head           headResponse     `json:"head"`
	}{Applied: true, Changed: changed, MemberAccepted: memberAccepted, Admission: admission, Head: headResponse{Seq: head.Seq, Hash: head.Hash}})
}

func (daemon *Daemon) handleAdmissionRevoke(w http.ResponseWriter, r *http.Request) {
	payload, err := readLimitedBody(r.Body, 4096)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var request admissionRevokeRequest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode admission revoke request: %w", err))
		return
	}
	if err := request.IXID.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ctx, err := daemon.preflightConfigMutation(r.Context(), "admissions revoke")
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	daemon.configMu.RLock()
	current, ok, err := daemon.latestAdmissionForIXLocked(request.IXID)
	daemon.configMu.RUnlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("admission for %q is not found", request.IXID))
		return
	}
	current.State = admissionStateRevoked
	current.EffectiveAt = time.Now().UTC()
	changed, err := daemon.applyAdmissionConfig(ctx, current)
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	daemon.configMu.RLock()
	head := daemon.head
	daemon.configMu.RUnlock()
	writeJSON(w, http.StatusOK, struct {
		Applied   bool             `json:"applied"`
		Changed   bool             `json:"changed"`
		Admission admissionPayload `json:"admission"`
		Head      headResponse     `json:"head"`
	}{Applied: true, Changed: changed, Admission: current, Head: headResponse{Seq: head.Seq, Hash: head.Hash}})
}

func (daemon *Daemon) admissionPayloadFromApproveRequest(request admissionApplyRequest) (admissionPayload, error) {
	if err := request.IXID.Validate(); err != nil {
		return admissionPayload{}, err
	}
	fingerprint, err := pki.NormalizeCertificateFingerprintSHA256(request.IXCertFingerprint)
	if err != nil {
		return admissionPayload{}, fmt.Errorf("ix_cert_fingerprint: %w", err)
	}
	allowedPrefixes, err := normalizeCorePrefixes(request.AllowedPrefixes)
	if err != nil {
		return admissionPayload{}, fmt.Errorf("allowed_prefixes: %w", err)
	}
	routeAuthFingerprints, err := normalizeFingerprintList(request.RouteAuthFingerprints)
	if err != nil {
		return admissionPayload{}, fmt.Errorf("route_auth_fingerprints: %w", err)
	}
	controlAPI := strings.TrimSpace(request.ControlAPI)
	if controlAPI != "" {
		if err := validateControlAPI(controlAPI); err != nil {
			return admissionPayload{}, fmt.Errorf("control_api: %w", err)
		}
	}
	effectiveAt := request.EffectiveAt
	if effectiveAt.IsZero() {
		effectiveAt = time.Now().UTC()
	} else {
		effectiveAt = effectiveAt.UTC()
	}
	return admissionPayload{
		Version:               1,
		DomainID:              daemon.desired.Domain.ID,
		IXID:                  request.IXID,
		State:                 admissionStateApproved,
		IXCertFingerprint:     fingerprint,
		AllowedPrefixes:       allowedPrefixes,
		RouteAuthFingerprints: routeAuthFingerprints,
		ControlAPI:            controlAPI,
		EffectiveAt:           effectiveAt,
	}, nil
}

func (daemon *Daemon) admissionPayloadFromApprovePendingRequest(request admissionApprovePendingRequest) (admissionPayload, error) {
	if err := request.IXID.Validate(); err != nil {
		return admissionPayload{}, err
	}
	daemon.membershipMu.RLock()
	record, ok := daemon.pendingMembers[request.IXID]
	daemon.membershipMu.RUnlock()
	if !ok {
		return admissionPayload{}, fmt.Errorf("pending IX %q is not found", request.IXID)
	}
	cert, err := daemon.verifyAdvertisementBase(record.Advertisement)
	if err != nil {
		return admissionPayload{}, fmt.Errorf("pending advertisement is no longer valid: %w", err)
	}
	prefixes := append([]core.Prefix(nil), request.AllowedPrefixes...)
	if len(prefixes) == 0 {
		prefixes = corePrefixesFromAdvertisement(record.Advertisement)
	}
	routeAuthFingerprints := append([]string(nil), request.RouteAuthFingerprints...)
	if len(routeAuthFingerprints) == 0 {
		routeAuthFingerprints, err = routeAuthFingerprintsFromAdvertisement(record.Advertisement)
		if err != nil {
			return admissionPayload{}, err
		}
	}
	controlAPI := strings.TrimSpace(request.ControlAPI)
	if controlAPI == "" {
		controlAPI = strings.TrimSpace(record.Advertisement.ControlAPI)
	}
	return daemon.admissionPayloadFromApproveRequest(admissionApplyRequest{
		IXID:                  request.IXID,
		IXCertFingerprint:     pki.CertificateFingerprintSHA256(cert),
		AllowedPrefixes:       prefixes,
		RouteAuthFingerprints: routeAuthFingerprints,
		ControlAPI:            controlAPI,
		EffectiveAt:           request.EffectiveAt,
	})
}

func (daemon *Daemon) applyAdmissionConfig(ctx context.Context, admission admissionPayload) (bool, error) {
	var err error
	ctx, err = daemon.preflightConfigMutation(ctx, "admissions apply")
	if err != nil {
		return false, err
	}
	daemon.configMu.Lock()
	defer daemon.configMu.Unlock()
	return daemon.applyAdmissionConfigLocked(ctx, admission)
}

func (daemon *Daemon) applyAdmissionConfigLocked(ctx context.Context, admission admissionPayload) (bool, error) {
	admission.DomainID = daemon.desired.Domain.ID
	adminProofs := adminProofsFromContext(ctx)
	if err := daemon.verifyAdminProofPolicy(adminProofs, daemon.desired.Trust); err != nil {
		return false, newConfigMutationRequestError(err)
	}
	head, err := daemon.store.Head()
	if err != nil {
		return false, err
	}
	admission.EffectiveSeq = head.Seq + 1
	if admission.EffectiveAt.IsZero() {
		admission.EffectiveAt = time.Now().UTC()
	}
	if err := validateAdmissionPayload(admission, daemon.desired.Domain.ID); err != nil {
		return false, newConfigMutationRequestError(err)
	}
	event, plannedHead, changed, err := daemon.admissionEventIfChangedAtHead(admission, adminProofs, head)
	if err != nil || !changed {
		return changed, err
	}
	var commitErr error
	if err := daemon.store.Append(*event); err != nil {
		if configlog.CommitSucceeded(err) {
			commitErr = err
		} else {
			return false, fmt.Errorf("append admission event: %w", err)
		}
	}
	daemon.head = plannedHead
	if err := daemon.afterAdmissionStateChangedLocked(ctx); err != nil {
		daemon.requestRuntimeReconcile("admission mutation", err)
		return true, newCommittedConfigMutationError("admission mutation", err)
	}
	if commitErr != nil {
		daemon.requestRuntimeReconcile("admission mutation durability", commitErr)
		return true, newCommittedConfigMutationError("admission mutation", commitErr)
	}
	return true, nil
}

func (daemon *Daemon) afterAdmissionStateChangedLocked(ctx context.Context) error {
	membersChanged := daemon.pruneUnadmittedMembersLocked()
	admittedPending := daemon.admitPendingMembers()
	var sessionCloseErr error
	if membersChanged {
		if err := daemon.persistMembers(); err != nil {
			return err
		}
		sessionCloseErr = errors.Join(sessionCloseErr, daemon.closeUntrustedDataSessions())
	}
	if len(admittedPending) > 0 {
		sessionCloseErr = errors.Join(sessionCloseErr, daemon.closeDataSessionsForPeers(admittedPending))
		daemon.clearFlowsForPeers(admittedPending)
	}
	if err := daemon.persistPendingMembers(); err != nil {
		return errors.Join(sessionCloseErr, err)
	}
	runtimeChanged := membersChanged || len(admittedPending) > 0
	if err := daemon.applyRuntimeDataplaneSnapshot(ctx); err != nil {
		return errors.Join(sessionCloseErr, err)
	}
	if runtimeChanged {
		daemon.scheduleRuntimeRouteWarmup(ctx)
	}
	return errors.Join(sessionCloseErr, daemon.refreshLocalAdvertisement())
}

func (daemon *Daemon) admissionEventIfChangedAtHead(admission admissionPayload, adminProofs []configlog.AdminProof, head configlog.Head) (*configlog.Event, configlog.Head, bool, error) {
	resource := admissionResourceForIX(admission.IXID)
	admission.ApprovedByConfigHead = headResponse{Seq: head.Seq, Hash: head.Hash}
	payload, err := encodeAdmissionPayload(admission)
	if err != nil {
		return nil, configlog.Head{}, false, err
	}
	if latest, ok, err := daemon.latestResourcePayload(resource); err != nil {
		return nil, configlog.Head{}, false, err
	} else if ok && bytes.Equal(latest, payload) {
		return nil, head, false, nil
	}
	return daemon.signedConfigEventAtHead(resource, configlog.ActionUpsert, payload, daemon.desired, adminProofs, head)
}

func encodeAdmissionPayload(admission admissionPayload) ([]byte, error) {
	admission, err := normalizeAdmissionPayload(admission)
	if err != nil {
		return nil, err
	}
	return json.Marshal(admission)
}

func parseAdmissionPayload(payload []byte, domain core.DomainID) (admissionPayload, error) {
	var admission admissionPayload
	if err := json.Unmarshal(payload, &admission); err != nil {
		return admissionPayload{}, fmt.Errorf("decode admission payload: %w", err)
	}
	admission, err := normalizeAdmissionPayload(admission)
	if err != nil {
		return admissionPayload{}, err
	}
	if err := validateAdmissionPayload(admission, domain); err != nil {
		return admissionPayload{}, err
	}
	return admission, nil
}

func normalizeAdmissionPayload(admission admissionPayload) (admissionPayload, error) {
	if admission.Version == 0 {
		admission.Version = 1
	}
	admission.State = strings.ToLower(strings.TrimSpace(admission.State))
	admission.IXCertFingerprint = strings.TrimSpace(admission.IXCertFingerprint)
	if admission.IXCertFingerprint != "" {
		fingerprint, err := pki.NormalizeCertificateFingerprintSHA256(admission.IXCertFingerprint)
		if err != nil {
			return admissionPayload{}, fmt.Errorf("ix_cert_fingerprint: %w", err)
		}
		admission.IXCertFingerprint = fingerprint
	}
	prefixes, err := normalizeCorePrefixes(admission.AllowedPrefixes)
	if err != nil {
		return admissionPayload{}, err
	}
	admission.AllowedPrefixes = prefixes
	fingerprints, err := normalizeFingerprintList(admission.RouteAuthFingerprints)
	if err != nil {
		return admissionPayload{}, err
	}
	admission.RouteAuthFingerprints = fingerprints
	admission.ControlAPI = strings.TrimSpace(admission.ControlAPI)
	if !admission.EffectiveAt.IsZero() {
		admission.EffectiveAt = admission.EffectiveAt.UTC()
	}
	return admission, nil
}

func validateAdmissionPayload(admission admissionPayload, domain core.DomainID) error {
	if admission.Version != 1 {
		return fmt.Errorf("admission payload version is %d, want 1", admission.Version)
	}
	if admission.DomainID != domain {
		return fmt.Errorf("admission domain is %q, want %q", admission.DomainID, domain)
	}
	if err := admission.IXID.Validate(); err != nil {
		return err
	}
	if admission.State != admissionStateApproved && admission.State != admissionStateRevoked {
		return fmt.Errorf("admission state is %q, want approved or revoked", admission.State)
	}
	if admission.IXCertFingerprint == "" {
		return fmt.Errorf("admission ix_cert_fingerprint is required")
	}
	if _, err := pki.NormalizeCertificateFingerprintSHA256(admission.IXCertFingerprint); err != nil {
		return fmt.Errorf("admission ix_cert_fingerprint: %w", err)
	}
	for _, rawPrefix := range admission.AllowedPrefixes {
		if _, err := rawPrefix.Parse(); err != nil {
			return fmt.Errorf("admission allowed prefix %q: %w", rawPrefix, err)
		}
	}
	for _, raw := range admission.RouteAuthFingerprints {
		if _, err := pki.NormalizeCertificateFingerprintSHA256(raw); err != nil {
			return fmt.Errorf("admission route auth fingerprint %q: %w", raw, err)
		}
	}
	if admission.ControlAPI != "" {
		if err := validateControlAPI(admission.ControlAPI); err != nil {
			return fmt.Errorf("admission control_api: %w", err)
		}
	}
	return nil
}

func (daemon *Daemon) latestAdmissionsFromLogLocked() ([]admissionPayload, error) {
	head, err := daemon.storeHeadLocked()
	if err != nil || head.Seq == 0 {
		return nil, err
	}
	events, err := daemon.store.Range(1, head.Seq)
	if err != nil {
		return nil, err
	}
	latest := make(map[core.IXID]admissionPayload)
	for _, event := range events {
		if !isDomainAdmissionResource(event.Resource) {
			continue
		}
		admission, err := parseAdmissionPayload(event.Payload, daemon.desired.Domain.ID)
		if err != nil {
			return nil, fmt.Errorf("decode admission seq %d: %w", event.Seq, err)
		}
		latest[admission.IXID] = admission
	}
	ids := make([]string, 0, len(latest))
	for ixID := range latest {
		ids = append(ids, string(ixID))
	}
	sort.Strings(ids)
	admissions := make([]admissionPayload, 0, len(ids))
	for _, rawID := range ids {
		admissions = append(admissions, latest[core.IXID(rawID)])
	}
	return admissions, nil
}

func (daemon *Daemon) latestAdmissionForIXLocked(ixID core.IXID) (admissionPayload, bool, error) {
	admissions, err := daemon.latestAdmissionsFromLogLocked()
	if err != nil {
		return admissionPayload{}, false, err
	}
	for _, admission := range admissions {
		if admission.IXID == ixID {
			return admission, true, nil
		}
	}
	return admissionPayload{}, false, nil
}

func (daemon *Daemon) storeHeadLocked() (configlog.Head, error) {
	if daemon.store == nil {
		return configlog.Head{}, nil
	}
	return daemon.store.Head()
}

func (daemon *Daemon) verifyAdmissionForAdvertisement(advertisement advertisementResponse, cert *x509.Certificate) error {
	return daemon.verifyAdmissionForAdvertisementLocked(advertisement, cert)
}

func (daemon *Daemon) verifyAdmissionForAdvertisementLocked(advertisement advertisementResponse, cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("admission check requires IX certificate")
	}
	ixID := core.IXID(advertisement.IXID)
	if ixID == daemon.desired.IX.ID {
		return nil
	}
	admission, ok, err := daemon.latestAdmissionForIXLocked(ixID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("IX %q has no approved chain admission", ixID)
	}
	if admission.State != admissionStateApproved {
		return fmt.Errorf("IX %q admission state is %q", ixID, admission.State)
	}
	if !admission.EffectiveAt.IsZero() && time.Now().UTC().Before(admission.EffectiveAt) {
		return fmt.Errorf("IX %q admission is not effective until %s", ixID, admission.EffectiveAt.Format(time.RFC3339))
	}
	if got := pki.CertificateFingerprintSHA256(cert); got != admission.IXCertFingerprint {
		return fmt.Errorf("IX %q certificate fingerprint %s does not match admission %s", ixID, got, admission.IXCertFingerprint)
	}
	if admission.ControlAPI != "" && strings.TrimSpace(advertisement.ControlAPI) != admission.ControlAPI {
		return fmt.Errorf("IX %q control_api %q does not match admission %q", ixID, advertisement.ControlAPI, admission.ControlAPI)
	}
	if err := admissionAllowsAdvertisementPrefixes(admission, advertisement); err != nil {
		return err
	}
	if err := admissionAllowsRouteAuthorizations(admission, advertisement); err != nil {
		return err
	}
	return nil
}

func admissionAllowsAdvertisementPrefixes(admission admissionPayload, advertisement advertisementResponse) error {
	if len(admission.AllowedPrefixes) == 0 {
		return nil
	}
	allowed := parsedPolicyPrefixes(admission.AllowedPrefixes)
	for _, rawPrefix := range corePrefixesFromAdvertisement(advertisement) {
		prefix, err := rawPrefix.Parse()
		if err != nil {
			return fmt.Errorf("advertisement %q prefix %q: %w", advertisement.IXID, rawPrefix, err)
		}
		if !prefixCovered(prefix.Masked(), allowed) {
			return fmt.Errorf("advertised prefix %q is not allowed by chain admission for %q", prefix.Masked(), advertisement.IXID)
		}
	}
	return nil
}

func admissionAllowsRouteAuthorizations(admission admissionPayload, advertisement advertisementResponse) error {
	if len(admission.RouteAuthFingerprints) == 0 {
		return nil
	}
	allowed := make(map[string]struct{}, len(admission.RouteAuthFingerprints))
	for _, fingerprint := range admission.RouteAuthFingerprints {
		allowed[fingerprint] = struct{}{}
	}
	for _, rawCert := range advertisement.RouteAuthorizations {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return fmt.Errorf("parse route authorization from %q: %w", advertisement.IXID, err)
		}
		fingerprint := pki.CertificateFingerprintSHA256(cert)
		if _, ok := allowed[fingerprint]; !ok {
			return fmt.Errorf("route authorization fingerprint %s is not allowed by chain admission for %q", fingerprint, advertisement.IXID)
		}
	}
	return nil
}

func (daemon *Daemon) pruneUnadmittedMembersLocked() bool {
	_, err := daemon.latestAdmissionsFromLogLocked()
	if err != nil {
		return false
	}
	daemon.membershipMu.RLock()
	ids := make([]core.IXID, 0, len(daemon.members))
	for ixID := range daemon.members {
		if ixID != daemon.desired.IX.ID {
			ids = append(ids, ixID)
		}
	}
	records := make(map[core.IXID]memberRecord, len(ids))
	for _, ixID := range ids {
		records[ixID] = daemon.members[ixID]
	}
	daemon.membershipMu.RUnlock()

	var remove []core.IXID
	for ixID, record := range records {
		cert, err := x509.ParseCertificate(record.Advertisement.IXCertificate)
		if err != nil {
			remove = append(remove, ixID)
			continue
		}
		if err := daemon.verifyAdmissionForAdvertisementLocked(record.Advertisement, cert); err != nil {
			remove = append(remove, ixID)
			continue
		}
	}
	if len(remove) == 0 {
		return false
	}
	daemon.membershipMu.Lock()
	for _, ixID := range remove {
		delete(daemon.members, ixID)
	}
	daemon.membershipMu.Unlock()
	return true
}

func (daemon *Daemon) admitPendingMembers() map[core.IXID]struct{} {
	daemon.membershipMu.RLock()
	ids := make([]core.IXID, 0, len(daemon.pendingMembers))
	for ixID := range daemon.pendingMembers {
		ids = append(ids, ixID)
	}
	daemon.membershipMu.RUnlock()
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	changed := make(map[core.IXID]struct{})
	for _, ixID := range ids {
		merged, err := daemon.mergePendingAdvertisement(ixID, "chain-admission")
		if err != nil {
			if isPendingAdmissionError(err) {
				continue
			}
			daemon.updatePendingMemberRejectReason(ixID, err)
			continue
		}
		if merged {
			changed[ixID] = struct{}{}
		}
	}
	return changed
}

func (daemon *Daemon) updatePendingMemberRejectReason(ixID core.IXID, reason error) {
	if reason == nil {
		return
	}
	daemon.membershipMu.Lock()
	record, ok := daemon.pendingMembers[ixID]
	if ok {
		record.LastSeen = time.Now().UTC()
		record.RejectReason = reason.Error()
		daemon.pendingMembers[ixID] = record
	}
	daemon.membershipMu.Unlock()
	if ok {
		if err := daemon.persistPendingMembers(); err != nil {
			daemon.recordBackgroundError("pending_members_persist", err)
		} else {
			daemon.clearBackgroundError("pending_members_persist")
		}
	}
}

func (daemon *Daemon) pendingAdmissionsSnapshot() []pendingAdmissionResponse {
	daemon.membershipMu.RLock()
	ids := make([]string, 0, len(daemon.pendingMembers))
	for ixID := range daemon.pendingMembers {
		ids = append(ids, string(ixID))
	}
	sort.Strings(ids)
	out := make([]pendingAdmissionResponse, 0, len(ids))
	for _, rawID := range ids {
		record := daemon.pendingMembers[core.IXID(rawID)]
		out = append(out, pendingAdmissionResponseFromRecord(record))
	}
	daemon.membershipMu.RUnlock()
	return out
}

func (daemon *Daemon) pendingAdmissionSnapshot(ixID core.IXID) (pendingAdmissionResponse, bool) {
	daemon.membershipMu.RLock()
	record, ok := daemon.pendingMembers[ixID]
	daemon.membershipMu.RUnlock()
	if !ok {
		return pendingAdmissionResponse{}, false
	}
	return pendingAdmissionResponseFromRecord(record), true
}

func pendingAdmissionResponseFromRecord(record pendingMemberRecord) pendingAdmissionResponse {
	routeAuthFingerprints, _ := routeAuthFingerprintsFromAdvertisement(record.Advertisement)
	certFingerprint := ""
	if cert, err := x509.ParseCertificate(record.Advertisement.IXCertificate); err == nil {
		certFingerprint = pki.CertificateFingerprintSHA256(cert)
	}
	expiresAt := record.LastSeen.Add(pendingMemberTTL).UTC()
	now := time.Now().UTC()
	ttl := int64(0)
	if expiresAt.After(now) {
		ttl = int64(time.Until(expiresAt).Seconds())
		if ttl < 0 {
			ttl = 0
		}
	}
	return pendingAdmissionResponse{
		IXID:                  core.IXID(record.Advertisement.IXID),
		FirstSeen:             record.FirstSeen,
		LastSeen:              record.LastSeen,
		ExpiresAt:             expiresAt,
		TTLSeconds:            ttl,
		Expired:               !expiresAt.After(now),
		Source:                record.Source,
		RejectReason:          record.RejectReason,
		IXCertFingerprint:     certFingerprint,
		AllowedPrefixes:       corePrefixesFromAdvertisement(record.Advertisement),
		RouteAuthFingerprints: routeAuthFingerprints,
		ControlAPI:            strings.TrimSpace(record.Advertisement.ControlAPI),
		ConfigHead:            record.Advertisement.ConfigHead,
		Advertisement:         record.Advertisement,
	}
}

func corePrefixesFromAdvertisement(advertisement advertisementResponse) []core.Prefix {
	announcements := advertisementAnnouncements(advertisement)
	prefixes := make([]core.Prefix, 0, len(announcements))
	seen := make(map[string]struct{}, len(announcements))
	for _, announcement := range announcements {
		rawPrefix := strings.TrimSpace(string(announcement.Prefix))
		if rawPrefix == "" {
			continue
		}
		key := rawPrefix
		if parsed, err := announcement.Prefix.Parse(); err == nil {
			key = parsed.Masked().String()
			rawPrefix = key
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		prefixes = append(prefixes, core.Prefix(rawPrefix))
	}
	return prefixes
}

func routeAuthFingerprintsFromAdvertisement(advertisement advertisementResponse) ([]string, error) {
	fingerprints := make([]string, 0, len(advertisement.RouteAuthorizations))
	for _, rawCert := range advertisement.RouteAuthorizations {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return nil, fmt.Errorf("parse route authorization from %q: %w", advertisement.IXID, err)
		}
		fingerprints = append(fingerprints, pki.CertificateFingerprintSHA256(cert))
	}
	return normalizeFingerprintList(fingerprints)
}

func (daemon *Daemon) decorateAdmissionObservations(admissions []admissionPayload, localHead configlog.Head) []admissionPayload {
	out := append([]admissionPayload(nil), admissions...)
	for i := range out {
		out[i] = daemon.decorateAdmissionObservation(out[i], localHead)
	}
	return out
}

func (daemon *Daemon) decorateAdmissionObservation(admission admissionPayload, localHead configlog.Head) admissionPayload {
	seen := make([]admissionSeen, 0, 1)
	if localHead.Seq >= admission.EffectiveSeq {
		seen = append(seen, admissionSeen{
			IXID:       daemon.desired.IX.ID,
			ConfigSeq:  localHead.Seq,
			ConfigHash: localHead.Hash,
			SeenAt:     time.Now().UTC(),
			Source:     "local",
		})
	}
	daemon.membershipMu.RLock()
	for ixID, record := range daemon.members {
		if ixID == daemon.desired.IX.ID {
			continue
		}
		head := record.Advertisement.ConfigHead
		if head.Seq < admission.EffectiveSeq {
			continue
		}
		seen = append(seen, admissionSeen{
			IXID:       ixID,
			ConfigSeq:  head.Seq,
			ConfigHash: head.Hash,
			SeenAt:     record.LastSeen,
			Source:     record.Source,
		})
		if ixID == admission.IXID && record.LastSeen.After(admission.LastObservedAdvertisementAt) {
			admission.LastObservedAdvertisementAt = record.LastSeen
		}
	}
	daemon.membershipMu.RUnlock()
	sort.Slice(seen, func(i, j int) bool {
		if seen[i].IXID != seen[j].IXID {
			return seen[i].IXID < seen[j].IXID
		}
		return seen[i].ConfigSeq < seen[j].ConfigSeq
	})
	admission.ObservedBy = seen
	return admission
}

func normalizeCorePrefixes(raw []core.Prefix) ([]core.Prefix, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(raw))
	out := make([]core.Prefix, 0, len(raw))
	for _, prefix := range raw {
		parsed, err := prefix.Parse()
		if err != nil {
			return nil, err
		}
		key := parsed.Masked().String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, core.Prefix(key))
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func normalizeFingerprintList(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, value := range raw {
		fingerprint, err := pki.NormalizeCertificateFingerprintSHA256(value)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[fingerprint]; ok {
			continue
		}
		seen[fingerprint] = struct{}{}
		out = append(out, fingerprint)
	}
	sort.Strings(out)
	return out, nil
}

func admissionMode() string {
	return "chain_admission"
}
