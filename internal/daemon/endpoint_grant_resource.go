package daemon

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/configlog"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
)

const (
	domainEndpointGrantsPrefix = "/domain/endpoint-grants/"

	endpointGrantStateActive  = "active"
	endpointGrantStateRevoked = "revoked"

	endpointGrantPermissionDataSession = "data_session"
)

type endpointGrantPayload struct {
	Version      int             `json:"version"`
	DomainID     core.DomainID   `json:"domain_id"`
	GrantID      string          `json:"grant_id"`
	IssuerIX     core.IXID       `json:"issuer_ix"`
	SubjectIX    core.IXID       `json:"subject_ix"`
	Endpoint     core.EndpointID `json:"endpoint"`
	Transport    string          `json:"transport,omitempty"`
	State        string          `json:"state"`
	Permissions  []string        `json:"permissions,omitempty"`
	IssuedAt     time.Time       `json:"issued_at"`
	ExpiresAt    time.Time       `json:"expires_at,omitempty"`
	EffectiveSeq uint64          `json:"effective_seq"`
	EffectiveAt  time.Time       `json:"effective_at"`
	Reason       string          `json:"reason,omitempty"`
}

type endpointGrantIssueRequest struct {
	SubjectIX   core.IXID       `json:"subject_ix"`
	Endpoint    core.EndpointID `json:"endpoint"`
	Transport   string          `json:"transport,omitempty"`
	TTL         string          `json:"ttl,omitempty"`
	ExpiresAt   time.Time       `json:"expires_at,omitempty"`
	Permissions []string        `json:"permissions,omitempty"`
	Reason      string          `json:"reason,omitempty"`
}

type endpointGrantRevokeRequest struct {
	GrantID   string          `json:"grant_id,omitempty"`
	SubjectIX core.IXID       `json:"subject_ix,omitempty"`
	Endpoint  core.EndpointID `json:"endpoint,omitempty"`
	Transport string          `json:"transport,omitempty"`
}

type endpointGrantListResponse struct {
	DomainID string                 `json:"domain_id"`
	Head     headResponse           `json:"head"`
	Grants   []endpointGrantPayload `json:"grants"`
}

type endpointGrantMutationResponse struct {
	Applied bool                 `json:"applied"`
	Changed bool                 `json:"changed"`
	Grant   endpointGrantPayload `json:"grant"`
	Head    headResponse         `json:"head"`
}

func endpointGrantResourceForID(grantID string) core.ResourcePath {
	return core.ResourcePath(domainEndpointGrantsPrefix + strings.TrimSpace(grantID))
}

func isDomainEndpointGrantResource(resource core.ResourcePath) bool {
	raw := string(resource)
	return strings.HasPrefix(raw, domainEndpointGrantsPrefix) && len(raw) > len(domainEndpointGrantsPrefix)
}

func grantIDFromEndpointGrantResource(resource core.ResourcePath) (string, bool) {
	if !isDomainEndpointGrantResource(resource) {
		return "", false
	}
	grantID := strings.TrimPrefix(string(resource), domainEndpointGrantsPrefix)
	if validEndpointGrantID(grantID) {
		return grantID, true
	}
	return "", false
}

func (daemon *Daemon) handleEndpointGrantsList(w http.ResponseWriter, r *http.Request) {
	daemon.configMu.RLock()
	grants, err := daemon.latestEndpointGrantsFromLogLocked()
	head := daemon.head
	daemon.configMu.RUnlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, endpointGrantListResponse{
		DomainID: string(daemon.desired.Domain.ID),
		Head:     headResponse{Seq: head.Seq, Hash: head.Hash},
		Grants:   grants,
	})
}

func (daemon *Daemon) handleEndpointGrantIssue(w http.ResponseWriter, r *http.Request) {
	payload, err := readLimitedBody(r.Body, 64<<10)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var request endpointGrantIssueRequest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode endpoint grant issue request: %w", err))
		return
	}
	grant, err := daemon.endpointGrantPayloadFromIssueRequest(request)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	changed, err := daemon.applyEndpointGrantConfig(r.Context(), grant)
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	daemon.configMu.RLock()
	head := daemon.head
	daemon.configMu.RUnlock()
	writeJSON(w, http.StatusOK, endpointGrantMutationResponse{
		Applied: true,
		Changed: changed,
		Grant:   grant,
		Head:    headResponse{Seq: head.Seq, Hash: head.Hash},
	})
}

func (daemon *Daemon) handleEndpointGrantRevoke(w http.ResponseWriter, r *http.Request) {
	payload, err := readLimitedBody(r.Body, 16<<10)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var request endpointGrantRevokeRequest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode endpoint grant revoke request: %w", err))
		return
	}
	grant, err := daemon.resolveEndpointGrantRevokeTarget(request)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	grant.State = endpointGrantStateRevoked
	grant.EffectiveAt = time.Now().UTC()
	changed, err := daemon.applyEndpointGrantConfig(r.Context(), grant)
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	dropped := daemon.dropDataSessionsUnauthorizedByEndpointGrantPolicy()
	if dropped > 0 {
		if err := daemon.applyRuntimeDataplaneSnapshot(r.Context()); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	daemon.configMu.RLock()
	head := daemon.head
	daemon.configMu.RUnlock()
	writeJSON(w, http.StatusOK, endpointGrantMutationResponse{
		Applied: true,
		Changed: changed || dropped > 0,
		Grant:   grant,
		Head:    headResponse{Seq: head.Seq, Hash: head.Hash},
	})
}

func (daemon *Daemon) endpointGrantPayloadFromIssueRequest(request endpointGrantIssueRequest) (endpointGrantPayload, error) {
	if err := request.SubjectIX.Validate(); err != nil {
		return endpointGrantPayload{}, err
	}
	if err := request.Endpoint.Validate(); err != nil {
		return endpointGrantPayload{}, err
	}
	if request.SubjectIX == daemon.desired.IX.ID {
		return endpointGrantPayload{}, fmt.Errorf("subject_ix cannot be the local IX")
	}
	localEndpoint, ok := endpointByName(daemon.desired.Endpoints, request.Endpoint)
	if !ok {
		return endpointGrantPayload{}, fmt.Errorf("local endpoint %q is not configured", request.Endpoint)
	}
	if !endpointDataSessionEnabled(localEndpoint) {
		return endpointGrantPayload{}, fmt.Errorf("local endpoint %q is disabled", request.Endpoint)
	}
	if endpointDataSessionMode(localEndpoint) != string(config.EndpointModePassive) {
		return endpointGrantPayload{}, fmt.Errorf("local endpoint %q is %q, want passive", request.Endpoint, endpointDataSessionMode(localEndpoint))
	}
	transportName := strings.ToLower(strings.TrimSpace(request.Transport))
	if transportName == "" {
		transportName = strings.ToLower(strings.TrimSpace(localEndpoint.Transport))
	}
	if transportName != "" && !endpointGrantTransportMatches(localEndpoint.Transport, transportName) {
		return endpointGrantPayload{}, fmt.Errorf("endpoint %q transport is %q, not %q", request.Endpoint, localEndpoint.Transport, transportName)
	}
	expiresAt := request.ExpiresAt
	if !expiresAt.IsZero() {
		expiresAt = expiresAt.UTC()
	}
	if ttl := strings.TrimSpace(request.TTL); ttl != "" {
		duration, err := time.ParseDuration(ttl)
		if err != nil {
			return endpointGrantPayload{}, fmt.Errorf("ttl: %w", err)
		}
		if duration <= 0 {
			return endpointGrantPayload{}, fmt.Errorf("ttl must be positive")
		}
		expiresAt = time.Now().UTC().Add(duration)
	} else if expiresAt.IsZero() {
		if defaultTTL := strings.TrimSpace(localEndpoint.Access.DefaultTTL); defaultTTL != "" {
			duration, err := time.ParseDuration(defaultTTL)
			if err != nil {
				return endpointGrantPayload{}, fmt.Errorf("endpoint default_ttl: %w", err)
			}
			expiresAt = time.Now().UTC().Add(duration)
		}
	}
	grantID, err := randomEndpointGrantID()
	if err != nil {
		return endpointGrantPayload{}, err
	}
	now := time.Now().UTC()
	permissions := normalizeEndpointGrantPermissions(request.Permissions)
	if len(permissions) == 0 {
		permissions = []string{endpointGrantPermissionDataSession}
	}
	return endpointGrantPayload{
		Version:     1,
		DomainID:    daemon.desired.Domain.ID,
		GrantID:     grantID,
		IssuerIX:    daemon.desired.IX.ID,
		SubjectIX:   request.SubjectIX,
		Endpoint:    request.Endpoint,
		Transport:   transportName,
		State:       endpointGrantStateActive,
		Permissions: permissions,
		IssuedAt:    now,
		ExpiresAt:   expiresAt,
		EffectiveAt: now,
		Reason:      strings.TrimSpace(request.Reason),
	}, nil
}

func (daemon *Daemon) resolveEndpointGrantRevokeTarget(request endpointGrantRevokeRequest) (endpointGrantPayload, error) {
	daemon.configMu.RLock()
	grants, err := daemon.latestEndpointGrantsFromLogLocked()
	daemon.configMu.RUnlock()
	if err != nil {
		return endpointGrantPayload{}, err
	}
	if strings.TrimSpace(request.GrantID) != "" {
		grantID := strings.TrimSpace(request.GrantID)
		for _, grant := range grants {
			if grant.GrantID == grantID {
				return grant, nil
			}
		}
		return endpointGrantPayload{}, fmt.Errorf("endpoint grant %q is not found", grantID)
	}
	if request.SubjectIX == "" || request.Endpoint == "" {
		return endpointGrantPayload{}, fmt.Errorf("grant_id or subject_ix+endpoint is required")
	}
	transportName := strings.ToLower(strings.TrimSpace(request.Transport))
	for i := len(grants) - 1; i >= 0; i-- {
		grant := grants[i]
		if grant.SubjectIX != request.SubjectIX || grant.Endpoint != request.Endpoint {
			continue
		}
		if transportName != "" && !endpointGrantTransportMatches(grant.Transport, transportName) {
			continue
		}
		if grant.State == endpointGrantStateActive {
			return grant, nil
		}
	}
	return endpointGrantPayload{}, fmt.Errorf("active endpoint grant for peer %q endpoint %q is not found", request.SubjectIX, request.Endpoint)
}

func (daemon *Daemon) applyEndpointGrantConfig(ctx context.Context, grant endpointGrantPayload) (bool, error) {
	var err error
	ctx, err = daemon.preflightConfigMutation(ctx, "endpoint grant apply")
	if err != nil {
		return false, err
	}
	daemon.configMu.Lock()
	defer daemon.configMu.Unlock()
	return daemon.applyEndpointGrantConfigLocked(ctx, grant)
}

func (daemon *Daemon) applyEndpointGrantConfigLocked(ctx context.Context, grant endpointGrantPayload) (bool, error) {
	adminProofs := adminProofsFromContext(ctx)
	if err := daemon.verifyAdminProofPolicy(adminProofs, daemon.desired.Trust); err != nil {
		return false, err
	}
	head, err := daemon.store.Head()
	if err != nil {
		return false, err
	}
	grant.DomainID = daemon.desired.Domain.ID
	if grant.IssuerIX == "" {
		grant.IssuerIX = daemon.desired.IX.ID
	}
	grant.EffectiveSeq = head.Seq + 1
	if grant.EffectiveAt.IsZero() {
		grant.EffectiveAt = time.Now().UTC()
	}
	if err := validateEndpointGrantPayload(grant, daemon.desired.Domain.ID); err != nil {
		return false, err
	}
	event, plannedHead, changed, err := daemon.endpointGrantEventIfChangedAtHead(grant, adminProofs, head)
	if err != nil || !changed {
		return changed, err
	}
	if err := daemon.store.Append(*event); err != nil {
		return false, fmt.Errorf("append endpoint grant event: %w", err)
	}
	daemon.head = plannedHead
	daemon.closeEndpointGrantRevokedSessionsLocked(grant)
	if err := daemon.applyRuntimeDataplaneSnapshot(ctx); err != nil {
		return true, err
	}
	if err := daemon.refreshLocalAdvertisement(); err != nil {
		return true, err
	}
	return true, nil
}

func (daemon *Daemon) endpointGrantEventIfChangedAtHead(grant endpointGrantPayload, adminProofs []configlog.AdminProof, head configlog.Head) (*configlog.Event, configlog.Head, bool, error) {
	payload, err := encodeEndpointGrantPayload(grant)
	if err != nil {
		return nil, configlog.Head{}, false, err
	}
	resource := endpointGrantResourceForID(grant.GrantID)
	if latest, ok, err := daemon.latestResourcePayload(resource); err != nil {
		return nil, configlog.Head{}, false, err
	} else if ok && bytes.Equal(latest, payload) {
		return nil, head, false, nil
	}
	return daemon.signedConfigEventAtHead(resource, configlog.ActionUpsert, payload, daemon.desired, adminProofs, head)
}

func encodeEndpointGrantPayload(grant endpointGrantPayload) ([]byte, error) {
	normalized, err := normalizeEndpointGrantPayload(grant)
	if err != nil {
		return nil, err
	}
	return json.Marshal(normalized)
}

func parseEndpointGrantPayload(payload []byte, domain core.DomainID) (endpointGrantPayload, error) {
	var grant endpointGrantPayload
	if err := json.Unmarshal(payload, &grant); err != nil {
		return endpointGrantPayload{}, fmt.Errorf("decode endpoint grant payload: %w", err)
	}
	grant, err := normalizeEndpointGrantPayload(grant)
	if err != nil {
		return endpointGrantPayload{}, err
	}
	if err := validateEndpointGrantPayload(grant, domain); err != nil {
		return endpointGrantPayload{}, err
	}
	return grant, nil
}

func normalizeEndpointGrantPayload(grant endpointGrantPayload) (endpointGrantPayload, error) {
	if grant.Version == 0 {
		grant.Version = 1
	}
	grant.GrantID = strings.ToLower(strings.TrimSpace(grant.GrantID))
	grant.Transport = strings.ToLower(strings.TrimSpace(grant.Transport))
	grant.State = strings.ToLower(strings.TrimSpace(grant.State))
	grant.Permissions = normalizeEndpointGrantPermissions(grant.Permissions)
	grant.Reason = strings.TrimSpace(grant.Reason)
	if !grant.IssuedAt.IsZero() {
		grant.IssuedAt = grant.IssuedAt.UTC()
	}
	if !grant.ExpiresAt.IsZero() {
		grant.ExpiresAt = grant.ExpiresAt.UTC()
	}
	if !grant.EffectiveAt.IsZero() {
		grant.EffectiveAt = grant.EffectiveAt.UTC()
	}
	return grant, nil
}

func validateEndpointGrantPayload(grant endpointGrantPayload, domain core.DomainID) error {
	if grant.Version != 1 {
		return fmt.Errorf("endpoint grant payload version is %d, want 1", grant.Version)
	}
	if grant.DomainID != domain {
		return fmt.Errorf("endpoint grant domain is %q, want %q", grant.DomainID, domain)
	}
	if !validEndpointGrantID(grant.GrantID) {
		return fmt.Errorf("endpoint grant id %q is invalid", grant.GrantID)
	}
	if err := grant.IssuerIX.Validate(); err != nil {
		return fmt.Errorf("endpoint grant issuer_ix: %w", err)
	}
	if err := grant.SubjectIX.Validate(); err != nil {
		return fmt.Errorf("endpoint grant subject_ix: %w", err)
	}
	if err := grant.Endpoint.Validate(); err != nil {
		return fmt.Errorf("endpoint grant endpoint: %w", err)
	}
	switch grant.State {
	case endpointGrantStateActive, endpointGrantStateRevoked:
	default:
		return fmt.Errorf("endpoint grant state is %q, want active or revoked", grant.State)
	}
	if grant.IssuedAt.IsZero() {
		return fmt.Errorf("endpoint grant issued_at is required")
	}
	if grant.EffectiveAt.IsZero() {
		return fmt.Errorf("endpoint grant effective_at is required")
	}
	if len(grant.Permissions) == 0 {
		return fmt.Errorf("endpoint grant permissions are required")
	}
	for _, permission := range grant.Permissions {
		switch permission {
		case endpointGrantPermissionDataSession:
		default:
			return fmt.Errorf("endpoint grant permission %q is unsupported", permission)
		}
	}
	return nil
}

func (daemon *Daemon) latestEndpointGrantsFromLogLocked() ([]endpointGrantPayload, error) {
	if daemon.store == nil {
		return nil, nil
	}
	head, err := daemon.store.Head()
	if err != nil || head.Seq == 0 {
		return nil, err
	}
	events, err := daemon.store.Range(1, head.Seq)
	if err != nil {
		return nil, err
	}
	latest := make(map[string]endpointGrantPayload)
	for _, event := range events {
		if !isDomainEndpointGrantResource(event.Resource) {
			continue
		}
		grant, err := parseEndpointGrantPayload(event.Payload, daemon.desired.Domain.ID)
		if err != nil {
			return nil, fmt.Errorf("decode endpoint grant seq %d: %w", event.Seq, err)
		}
		latest[grant.GrantID] = grant
	}
	ids := make([]string, 0, len(latest))
	for id := range latest {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	grants := make([]endpointGrantPayload, 0, len(ids))
	for _, id := range ids {
		grants = append(grants, latest[id])
	}
	return grants, nil
}

func (daemon *Daemon) endpointAccessRequiresGrant(endpoint config.EndpointConfig) bool {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(endpoint.Access.Mode), "-", "_")) {
	case "require_grant", "grant", "grants", "authenticated":
		return true
	default:
		return false
	}
}

func endpointAccessAllowlistOnly(endpoint config.EndpointConfig) bool {
	mode := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(endpoint.Access.Mode), "-", "_"))
	return mode == "allow" || mode == "allowlist" || mode == "only"
}

func (daemon *Daemon) endpointAccessAllowsPeer(peer core.IXID, endpoint config.EndpointConfig) bool {
	if peer == "" {
		return false
	}
	for _, allowed := range endpoint.Access.AllowedPeers {
		if allowed == peer {
			return true
		}
	}
	if endpointAccessAllowlistOnly(endpoint) {
		return false
	}
	if !daemon.endpointAccessRequiresGrant(endpoint) {
		return true
	}
	return daemon.peerHasActiveEndpointGrant(peer, endpoint)
}

func (daemon *Daemon) peerHasActiveEndpointGrant(peer core.IXID, endpoint config.EndpointConfig) bool {
	daemon.configMu.RLock()
	grants, err := daemon.latestEndpointGrantsFromLogLocked()
	daemon.configMu.RUnlock()
	if err != nil {
		return false
	}
	now := time.Now().UTC()
	for _, grant := range grants {
		if grant.State != endpointGrantStateActive {
			continue
		}
		if !endpointGrantAllowsDataSession(grant) {
			continue
		}
		if grant.IssuerIX != daemon.desired.IX.ID || grant.SubjectIX != peer || grant.Endpoint != endpoint.Name {
			continue
		}
		if grant.Transport != "" && !endpointGrantTransportMatches(endpoint.Transport, grant.Transport) {
			continue
		}
		if !grant.ExpiresAt.IsZero() && !grant.ExpiresAt.After(now) {
			continue
		}
		if !grant.EffectiveAt.IsZero() && now.Before(grant.EffectiveAt) {
			continue
		}
		return true
	}
	return false
}

func (daemon *Daemon) closeEndpointGrantRevokedSessionsLocked(grant endpointGrantPayload) {
	if grant.State != endpointGrantStateRevoked {
		return
	}
	var sessions []closableSession
	daemon.dataMu.Lock()
	if daemon.dataSessions == nil {
		daemon.dataMu.Unlock()
		return
	}
	for key, session := range daemon.dataSessions {
		if key.Address != reverseSessionAddress || key.Peer != grant.SubjectIX || key.Endpoint != grant.Endpoint {
			continue
		}
		if grant.Transport != "" && !endpointGrantTransportMatches(string(key.Transport), grant.Transport) {
			continue
		}
		if runtime := daemon.dataSessionState[key]; runtime != nil && runtime.cancel != nil {
			runtime.cancel()
		}
		sessions = append(sessions, closableSession{session: session})
		delete(daemon.dataSessions, key)
		delete(daemon.dataSessionState, key)
		daemon.deleteSessionPoolCursorLocked(key)
		daemon.deleteSessionFlowBindingsLocked(key)
	}
	if len(sessions) > 0 {
		daemon.dataSessionEpoch++
	}
	daemon.dataMu.Unlock()
	for _, item := range sessions {
		if item.session != nil {
			daemon.dataStats.staleSessionsDropped.Add(1)
			_ = item.session.Close()
		}
	}
}

type closableSession struct {
	session interface{ Close() error }
}

func (daemon *Daemon) dropDataSessionsUnauthorizedByEndpointGrantPolicy() int {
	type dropped struct {
		session interface{ Close() error }
		runtime *dataSessionRuntime
	}
	daemon.configMu.RLock()
	grants, err := daemon.latestEndpointGrantsFromLogLocked()
	daemon.configMu.RUnlock()
	if err != nil {
		return 0
	}
	droppedSessions := make([]dropped, 0)
	now := time.Now().UTC()
	daemon.dataMu.Lock()
	for key, session := range daemon.dataSessions {
		runtime := daemon.dataSessionState[key]
		endpoint := runtimeEndpointConfig(runtime, key)
		if endpoint.Name == "" || !daemon.endpointAccessRequiresGrant(endpoint) {
			continue
		}
		if daemon.endpointAccessAllowsPeerWithGrants(key.Peer, endpoint, grants, now) {
			continue
		}
		if runtime != nil && runtime.cancel != nil {
			runtime.cancel()
		}
		droppedSessions = append(droppedSessions, dropped{session: session, runtime: runtime})
		delete(daemon.dataSessions, key)
		delete(daemon.dataSessionState, key)
		daemon.deleteSessionPoolCursorLocked(key)
		daemon.deleteSessionFlowBindingsLocked(key)
	}
	if len(droppedSessions) > 0 {
		daemon.dataSessionEpoch++
	}
	daemon.dataMu.Unlock()
	for _, item := range droppedSessions {
		if item.session != nil {
			daemon.dataStats.staleSessionsDropped.Add(1)
			_ = item.session.Close()
		}
	}
	return len(droppedSessions)
}

func runtimeEndpointConfig(runtime *dataSessionRuntime, key dataSessionKey) config.EndpointConfig {
	if runtime != nil && runtime.endpoint.Name != "" {
		return runtime.endpoint
	}
	return config.EndpointConfig{Name: key.Endpoint, Transport: string(key.Transport)}
}

func (daemon *Daemon) endpointAccessAllowsPeerWithGrants(peer core.IXID, endpoint config.EndpointConfig, grants []endpointGrantPayload, now time.Time) bool {
	if peer == "" {
		return false
	}
	for _, allowed := range endpoint.Access.AllowedPeers {
		if allowed == peer {
			return true
		}
	}
	if endpointAccessAllowlistOnly(endpoint) {
		return false
	}
	if !daemon.endpointAccessRequiresGrant(endpoint) {
		return true
	}
	for _, grant := range grants {
		if grant.State != endpointGrantStateActive {
			continue
		}
		if !endpointGrantAllowsDataSession(grant) {
			continue
		}
		if grant.IssuerIX != daemon.desired.IX.ID || grant.SubjectIX != peer || grant.Endpoint != endpoint.Name {
			continue
		}
		if grant.Transport != "" && !endpointGrantTransportMatches(endpoint.Transport, grant.Transport) {
			continue
		}
		if !grant.ExpiresAt.IsZero() && !grant.ExpiresAt.After(now) {
			continue
		}
		if !grant.EffectiveAt.IsZero() && now.Before(grant.EffectiveAt) {
			continue
		}
		return true
	}
	return false
}

func endpointGrantAllowsDataSession(grant endpointGrantPayload) bool {
	for _, permission := range grant.Permissions {
		if permission == endpointGrantPermissionDataSession {
			return true
		}
	}
	return false
}

func endpointAccessMetadataFromConfig(access config.EndpointAccessConfig) dataplane.EndpointAccessMetadata {
	allowed := make([]string, 0, len(access.AllowedPeers))
	for _, peer := range access.AllowedPeers {
		if peer != "" {
			allowed = append(allowed, string(peer))
		}
	}
	return dataplane.EndpointAccessMetadata{
		Mode:         strings.ToLower(strings.ReplaceAll(strings.TrimSpace(access.Mode), "-", "_")),
		AllowedPeers: allowed,
		DefaultTTL:   strings.TrimSpace(access.DefaultTTL),
	}
}

func endpointAccessConfigFromMetadata(access dataplane.EndpointAccessMetadata) config.EndpointAccessConfig {
	allowed := make([]core.IXID, 0, len(access.AllowedPeers))
	for _, peer := range access.AllowedPeers {
		if trimmed := strings.TrimSpace(peer); trimmed != "" {
			allowed = append(allowed, core.IXID(trimmed))
		}
	}
	return config.EndpointAccessConfig{
		Mode:         strings.ToLower(strings.ReplaceAll(strings.TrimSpace(access.Mode), "-", "_")),
		AllowedPeers: allowed,
		DefaultTTL:   strings.TrimSpace(access.DefaultTTL),
	}
}

func normalizeEndpointGrantPermissions(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "-", "_"))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func endpointGrantTransportMatches(left string, right string) bool {
	left = strings.ToLower(strings.TrimSpace(left))
	right = strings.ToLower(strings.TrimSpace(right))
	if left == right {
		return true
	}
	return (left == "kernel_udp" && right == "udp") || (left == "udp" && right == "kernel_udp") ||
		(left == "ackless_tcp" && right == "experimental_tcp") || (left == "experimental_tcp" && right == "ackless_tcp")
}

func validEndpointGrantID(grantID string) bool {
	if grantID = strings.TrimSpace(grantID); grantID == "" || len(grantID) > 128 {
		return false
	}
	for _, r := range grantID {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func randomEndpointGrantID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate endpoint grant id: %w", err)
	}
	return "eg-" + hex.EncodeToString(raw[:]), nil
}
