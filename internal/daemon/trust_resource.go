package daemon

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/configlog"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/pki"
)

const domainTrustResource = core.ResourcePath("/domain/trust")

type domainTrustPayload struct {
	Version                 int                      `json:"version"`
	DomainID                core.DomainID            `json:"domain_id"`
	TrustEpoch              uint64                   `json:"trust_epoch"`
	EffectiveSeq            uint64                   `json:"effective_seq"`
	EffectiveAt             time.Time                `json:"effective_at"`
	RevokedCertFingerprints []string                 `json:"revoked_cert_fingerprints,omitempty"`
	TrustRootsPEM           []string                 `json:"trust_roots_pem,omitempty"`
	AdminPolicy             config.AdminPolicyConfig `json:"admin_policy,omitempty"`
	Trust                   *config.TrustConfig      `json:"trust,omitempty"`
}

type trustStateResponse struct {
	DomainID     string             `json:"domain_id"`
	Trust        config.TrustConfig `json:"trust"`
	EffectiveSeq uint64             `json:"effective_seq"`
	EffectiveAt  time.Time          `json:"effective_at,omitempty"`
}

type trustFingerprintRequest struct {
	Fingerprint string `json:"fingerprint"`
}

type trustRootRequest struct {
	CertificatePEM string `json:"certificate_pem,omitempty"`
	Fingerprint    string `json:"fingerprint,omitempty"`
}

type trustRootInfo struct {
	Source      string `json:"source"`
	Fingerprint string `json:"fingerprint"`
	Subject     string `json:"subject"`
	Role        string `json:"role,omitempty"`
	Domain      string `json:"domain,omitempty"`
	NotAfter    string `json:"not_after,omitempty"`
}

func (daemon *Daemon) handleTrustShow(w http.ResponseWriter, r *http.Request) {
	daemon.configMu.RLock()
	state, err := daemon.currentTrustStateLocked()
	daemon.configMu.RUnlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, state)
}

func (daemon *Daemon) handleTrustApply(w http.ResponseWriter, r *http.Request) {
	payload, err := readLimitedBody(r.Body, 256<<10)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var trust config.TrustConfig
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&trust); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode trust config: %w", err))
		return
	}
	changed, err := daemon.applyTrustConfig(r.Context(), trust)
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	daemon.configMu.RLock()
	head := daemon.head
	daemon.configMu.RUnlock()
	writeJSON(w, http.StatusOK, struct {
		Applied bool         `json:"applied"`
		Changed bool         `json:"changed"`
		Head    headResponse `json:"head"`
	}{Applied: true, Changed: changed, Head: headResponse{Seq: head.Seq, Hash: head.Hash}})
}

func (daemon *Daemon) handleTrustPolicyShow(w http.ResponseWriter, r *http.Request) {
	daemon.configMu.RLock()
	trust := config.NormalizeTrust(daemon.desired.Trust)
	daemon.configMu.RUnlock()
	writeJSON(w, http.StatusOK, struct {
		Policy             config.AdminPolicyConfig `json:"policy"`
		EffectiveThreshold int                      `json:"effective_threshold"`
	}{
		Policy:             trust.AdminPolicy,
		EffectiveThreshold: config.EffectiveAdminThreshold(trust),
	})
}

func (daemon *Daemon) handleTrustPolicyApply(w http.ResponseWriter, r *http.Request) {
	payload, err := readLimitedBody(r.Body, 64<<10)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var policy config.AdminPolicyConfig
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode admin policy: %w", err))
		return
	}
	ctx, err := daemon.preflightConfigMutation(r.Context(), "trust policy apply")
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	daemon.configMu.RLock()
	trust := daemon.desired.Trust
	daemon.configMu.RUnlock()
	trust.AdminPolicy = policy
	changed, err := daemon.applyTrustConfig(ctx, trust)
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	daemon.configMu.RLock()
	head := daemon.head
	daemon.configMu.RUnlock()
	writeJSON(w, http.StatusOK, struct {
		Applied bool         `json:"applied"`
		Changed bool         `json:"changed"`
		Head    headResponse `json:"head"`
	}{Applied: true, Changed: changed, Head: headResponse{Seq: head.Seq, Hash: head.Hash}})
}

func (daemon *Daemon) handleTrustRootsShow(w http.ResponseWriter, r *http.Request) {
	daemon.configMu.RLock()
	trust := daemon.desired.Trust
	daemon.configMu.RUnlock()
	roots, err := daemon.trustRootInfos(trust)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Roots []trustRootInfo `json:"roots"`
	}{Roots: roots})
}

func (daemon *Daemon) handleTrustRootAdd(w http.ResponseWriter, r *http.Request) {
	payload, err := readLimitedBody(r.Body, 256<<10)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var request trustRootRequest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode trust root request: %w", err))
		return
	}
	cert, err := pki.ParseCertificatePEM([]byte(request.CertificatePEM))
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("parse trust root: %w", err))
		return
	}
	if !cert.IsCA {
		writeError(w, http.StatusBadRequest, fmt.Errorf("trust root certificate is not a CA"))
		return
	}
	canonical := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	ctx, err := daemon.preflightConfigMutation(r.Context(), "trust roots add")
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	daemon.configMu.RLock()
	trust := daemon.desired.Trust
	daemon.configMu.RUnlock()
	trust.TrustRootsPEM = append(trust.TrustRootsPEM, canonical)
	changed, err := daemon.applyTrustConfig(ctx, trust)
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	daemon.configMu.RLock()
	head := daemon.head
	daemon.configMu.RUnlock()
	writeJSON(w, http.StatusOK, struct {
		Applied     bool         `json:"applied"`
		Changed     bool         `json:"changed"`
		Fingerprint string       `json:"fingerprint"`
		Head        headResponse `json:"head"`
	}{Applied: true, Changed: changed, Fingerprint: pki.CertificateFingerprintSHA256(cert), Head: headResponse{Seq: head.Seq, Hash: head.Hash}})
}

func (daemon *Daemon) handleTrustRootRemove(w http.ResponseWriter, r *http.Request) {
	payload, err := readLimitedBody(r.Body, 4096)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var request trustRootRequest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode trust root request: %w", err))
		return
	}
	fingerprint := request.Fingerprint
	if fingerprint == "" && request.CertificatePEM != "" {
		cert, err := pki.ParseCertificatePEM([]byte(request.CertificatePEM))
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("parse trust root: %w", err))
			return
		}
		fingerprint = pki.CertificateFingerprintSHA256(cert)
	}
	fingerprint, err = pki.NormalizeCertificateFingerprintSHA256(fingerprint)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ctx, err := daemon.preflightConfigMutation(r.Context(), "trust roots remove")
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	daemon.configMu.RLock()
	trust := daemon.desired.Trust
	daemon.configMu.RUnlock()
	filtered := trust.TrustRootsPEM[:0]
	for _, root := range trust.TrustRootsPEM {
		cert, err := pki.ParseCertificatePEM([]byte(root))
		if err != nil || pki.CertificateFingerprintSHA256(cert) == fingerprint {
			continue
		}
		filtered = append(filtered, root)
	}
	trust.TrustRootsPEM = filtered
	changed, err := daemon.applyTrustConfig(ctx, trust)
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	daemon.configMu.RLock()
	head := daemon.head
	daemon.configMu.RUnlock()
	writeJSON(w, http.StatusOK, struct {
		Applied     bool         `json:"applied"`
		Changed     bool         `json:"changed"`
		Fingerprint string       `json:"fingerprint"`
		Head        headResponse `json:"head"`
	}{Applied: true, Changed: changed, Fingerprint: fingerprint, Head: headResponse{Seq: head.Seq, Hash: head.Hash}})
}

func (daemon *Daemon) handleTrustRevoke(w http.ResponseWriter, r *http.Request) {
	daemon.handleTrustFingerprintMutation(w, r, true)
}

func (daemon *Daemon) handleTrustUnrevoke(w http.ResponseWriter, r *http.Request) {
	daemon.handleTrustFingerprintMutation(w, r, false)
}

func (daemon *Daemon) handleTrustFingerprintMutation(w http.ResponseWriter, r *http.Request, revoke bool) {
	payload, err := readLimitedBody(r.Body, 4096)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var request trustFingerprintRequest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode trust fingerprint request: %w", err))
		return
	}
	fingerprint, err := pki.NormalizeCertificateFingerprintSHA256(request.Fingerprint)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ctx, err := daemon.preflightConfigMutation(r.Context(), "trust revoke")
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	daemon.configMu.RLock()
	trust := daemon.desired.Trust
	daemon.configMu.RUnlock()
	trust = config.NormalizeTrust(trust)
	if revoke {
		seen := revokedCertificateFingerprintsFromTrust(trust)
		if _, ok := seen[fingerprint]; !ok {
			trust.RevokedCertFingerprints = append(trust.RevokedCertFingerprints, fingerprint)
		}
	} else {
		filtered := trust.RevokedCertFingerprints[:0]
		for _, existing := range trust.RevokedCertFingerprints {
			if existing != fingerprint {
				filtered = append(filtered, existing)
			}
		}
		trust.RevokedCertFingerprints = filtered
	}
	changed, err := daemon.applyTrustConfig(ctx, trust)
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	daemon.configMu.RLock()
	head := daemon.head
	daemon.configMu.RUnlock()
	writeJSON(w, http.StatusOK, struct {
		Applied     bool         `json:"applied"`
		Changed     bool         `json:"changed"`
		Fingerprint string       `json:"fingerprint"`
		Head        headResponse `json:"head"`
	}{Applied: true, Changed: changed, Fingerprint: fingerprint, Head: headResponse{Seq: head.Seq, Hash: head.Hash}})
}

func (daemon *Daemon) applyTrustConfig(ctx context.Context, trust config.TrustConfig) (bool, error) {
	var err error
	ctx, err = daemon.preflightConfigMutation(ctx, "trust apply")
	if err != nil {
		return false, err
	}
	daemon.configMu.Lock()
	defer daemon.configMu.Unlock()
	return daemon.applyTrustConfigLocked(ctx, trust)
}

func (daemon *Daemon) applyTrustConfigLocked(ctx context.Context, trust config.TrustConfig) (bool, error) {
	trust = config.NormalizeTrust(trust)
	if err := trust.Validate(); err != nil {
		return false, err
	}
	adminProofs := adminProofsFromContext(ctx)
	if err := daemon.verifyAdminProofPolicy(adminProofs, daemon.desired.Trust); err != nil {
		return false, err
	}
	if trustConfigsEqual(daemon.desired.Trust, trust) {
		return false, nil
	}
	head, err := daemon.store.Head()
	if err != nil {
		return false, err
	}
	event, plannedHead, changed, err := daemon.domainTrustEventIfChangedAtHead(trust, adminProofs, head)
	if err != nil || !changed {
		return changed, err
	}
	if err := daemon.store.Append(*event); err != nil {
		return false, fmt.Errorf("append domain trust event: %w", err)
	}
	daemon.head = plannedHead
	daemon.desired.Trust = trust
	if err := daemon.afterTrustStateChangedLocked(ctx); err != nil {
		return true, err
	}
	return true, nil
}

func (daemon *Daemon) afterTrustStateChangedLocked(ctx context.Context) error {
	if _, err := daemon.enforceRuntimeTrustState(); err != nil {
		return err
	}
	daemon.dropRevokedDeviceAccessSessions()
	if err := daemon.applyRuntimeDataplaneSnapshot(ctx); err != nil {
		return err
	}
	return daemon.refreshLocalAdvertisement()
}

func (daemon *Daemon) domainTrustEventIfChangedAtHead(trust config.TrustConfig, adminProofs []configlog.AdminProof, head configlog.Head) (*configlog.Event, configlog.Head, bool, error) {
	trust = config.NormalizeTrust(trust)
	payload, err := daemon.domainTrustPayload(trust, head.Seq+1)
	if err != nil {
		return nil, configlog.Head{}, false, err
	}
	if latest, ok, err := daemon.latestResourcePayload(domainTrustResource); err != nil {
		return nil, configlog.Head{}, false, err
	} else if ok && bytes.Equal(latest, payload) {
		return nil, head, false, nil
	}
	return daemon.signedConfigEventAtHead(domainTrustResource, configlog.ActionUpsert, payload, daemon.desired, adminProofs, head)
}

func (daemon *Daemon) domainTrustPayload(trust config.TrustConfig, effectiveSeq uint64) ([]byte, error) {
	trust = config.NormalizeTrust(trust)
	if err := trust.Validate(); err != nil {
		return nil, err
	}
	payload := domainTrustPayload{
		Version:                 2,
		DomainID:                daemon.desired.Domain.ID,
		TrustEpoch:              effectiveSeq,
		EffectiveSeq:            effectiveSeq,
		EffectiveAt:             time.Now().UTC(),
		RevokedCertFingerprints: append([]string(nil), trust.RevokedCertFingerprints...),
		TrustRootsPEM:           append([]string(nil), trust.TrustRootsPEM...),
		AdminPolicy:             trust.AdminPolicy,
		Trust:                   &trust,
	}
	return json.Marshal(payload)
}

func parseDomainTrustPayload(payload []byte, domain core.DomainID) (config.TrustConfig, error) {
	var decoded domainTrustPayload
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return config.TrustConfig{}, fmt.Errorf("decode domain trust payload: %w", err)
	}
	if decoded.Version != 1 && decoded.Version != 2 {
		return config.TrustConfig{}, fmt.Errorf("domain trust payload version is %d, want 1 or 2", decoded.Version)
	}
	if decoded.DomainID != "" && decoded.DomainID != domain {
		return config.TrustConfig{}, fmt.Errorf("domain trust payload domain is %q, want %q", decoded.DomainID, domain)
	}
	trust := config.TrustConfig{
		RevokedCertFingerprints: decoded.RevokedCertFingerprints,
		TrustRootsPEM:           decoded.TrustRootsPEM,
		AdminPolicy:             decoded.AdminPolicy,
	}
	if decoded.Trust != nil {
		trust = *decoded.Trust
	}
	trust = config.NormalizeTrust(trust)
	if err := trust.Validate(); err != nil {
		return config.TrustConfig{}, err
	}
	return trust, nil
}

func (daemon *Daemon) currentTrustStateLocked() (trustStateResponse, error) {
	trust, seq, effectiveAt, err := daemon.latestDomainTrustFromLogLocked()
	if err != nil {
		return trustStateResponse{}, err
	}
	if seq == 0 {
		trust = config.NormalizeTrust(daemon.desired.Trust)
	}
	return trustStateResponse{
		DomainID:     string(daemon.desired.Domain.ID),
		Trust:        trust,
		EffectiveSeq: seq,
		EffectiveAt:  effectiveAt,
	}, nil
}

func (daemon *Daemon) latestDomainTrustFromLogLocked() (config.TrustConfig, uint64, time.Time, error) {
	if daemon.store == nil {
		return config.TrustConfig{}, 0, time.Time{}, nil
	}
	head, err := daemon.store.Head()
	if err != nil {
		return config.TrustConfig{}, 0, time.Time{}, err
	}
	if head.Seq == 0 {
		return config.TrustConfig{}, 0, time.Time{}, nil
	}
	events, err := daemon.store.Range(1, head.Seq)
	if err != nil {
		return config.TrustConfig{}, 0, time.Time{}, err
	}
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Resource != domainTrustResource {
			continue
		}
		trust, err := parseDomainTrustPayload(events[i].Payload, daemon.desired.Domain.ID)
		if err != nil {
			return config.TrustConfig{}, 0, time.Time{}, err
		}
		return trust, events[i].Seq, events[i].EffectiveAt, nil
	}
	return config.TrustConfig{}, 0, time.Time{}, nil
}

func (daemon *Daemon) trustRootInfos(trust config.TrustConfig) ([]trustRootInfo, error) {
	infos := make([]trustRootInfo, 0, len(daemon.desired.Domain.TrustRoots)+len(trust.TrustRootsPEM))
	seen := make(map[string]struct{})
	add := func(source string, cert *x509.Certificate) {
		if cert == nil {
			return
		}
		fingerprint := pki.CertificateFingerprintSHA256(cert)
		if _, exists := seen[fingerprint]; exists {
			return
		}
		seen[fingerprint] = struct{}{}
		meta := pki.ParseMetadata(cert)
		infos = append(infos, trustRootInfo{
			Source:      source,
			Fingerprint: fingerprint,
			Subject:     cert.Subject.String(),
			Role:        string(meta.Role),
			Domain:      meta.Domain,
			NotAfter:    cert.NotAfter.UTC().Format(time.RFC3339),
		})
	}
	for _, path := range daemon.desired.Domain.TrustRoots {
		cert, _, err := pki.LoadCertificate(path)
		if err != nil {
			return nil, err
		}
		add("desired:"+path, cert)
	}
	for i, payload := range trust.TrustRootsPEM {
		cert, err := pki.ParseCertificatePEM([]byte(payload))
		if err != nil {
			return nil, fmt.Errorf("parse domain trust root %d: %w", i, err)
		}
		add("domain_trust", cert)
	}
	return infos, nil
}

func (daemon *Daemon) storeHasDomainTrustLocked() (bool, error) {
	if daemon.store == nil {
		return false, nil
	}
	head, err := daemon.store.Head()
	if err != nil || head.Seq == 0 {
		return false, err
	}
	events, err := daemon.store.Range(1, head.Seq)
	if err != nil {
		return false, err
	}
	return eventsContainDomainTrust(events), nil
}

func eventsContainDomainTrust(events []configlog.Event) bool {
	for _, event := range events {
		if event.Resource == domainTrustResource {
			return true
		}
	}
	return false
}

func (daemon *Daemon) applyLatestDomainTrustFromLogLocked(ctx context.Context) (bool, error) {
	trust, seq, _, err := daemon.latestDomainTrustFromLogLocked()
	if err != nil || seq == 0 {
		return false, err
	}
	if trustConfigsEqual(daemon.desired.Trust, trust) {
		return false, nil
	}
	daemon.desired.Trust = trust
	if err := daemon.afterTrustStateChangedLocked(ctx); err != nil {
		return true, err
	}
	return true, nil
}

func trustConfigsEqual(left, right config.TrustConfig) bool {
	left = config.NormalizeTrust(left)
	right = config.NormalizeTrust(right)
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
