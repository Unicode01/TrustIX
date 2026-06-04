package daemon

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/configlog"
	"trustix.local/trustix/internal/pki"
)

func TestTrustRevokeAppendsDomainTrustEvent(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemon := newConfigApplyTestDaemon(t, configApplyDesired(pkiSet, "10.0.1.0/24"))
	fingerprint := fingerprintForCertPath(t, pkiSet.ixCerts["ix-c"])
	trust := config.TrustConfig{RevokedCertFingerprints: []string{fingerprint}}
	body := mustJSON(t, trust)
	request := httptest.NewRequest(http.MethodPost, "/v1/trust", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, request, body, pkiSet.adminCert, pkiSet.adminKey)
	proof, err := daemon.verifyAdminRequest(request, body)
	if err != nil {
		t.Fatalf("verify admin request: %v", err)
	}

	changed, err := daemon.applyTrustConfig(context.WithValue(context.Background(), adminProofContextKey{}, proof), trust)
	if err != nil {
		t.Fatalf("apply trust config: %v", err)
	}
	if !changed {
		t.Fatal("trust apply did not report change")
	}
	if daemon.head.Seq != 2 {
		t.Fatalf("head seq = %d, want 2", daemon.head.Seq)
	}
	if len(daemon.desired.Trust.RevokedCertFingerprints) != 1 || daemon.desired.Trust.RevokedCertFingerprints[0] != fingerprint {
		t.Fatalf("runtime trust = %#v, want revoked %q", daemon.desired.Trust, fingerprint)
	}
	events, err := daemon.store.Range(2, 2)
	if err != nil {
		t.Fatalf("read trust event: %v", err)
	}
	if events[0].Resource != domainTrustResource {
		t.Fatalf("event resource = %q, want %q", events[0].Resource, domainTrustResource)
	}
	if len(events[0].AdminProofs) != 1 {
		t.Fatalf("admin proofs = %#v, want one proof", events[0].AdminProofs)
	}
	if err := daemon.verifyConfigEvent(events[0]); err != nil {
		t.Fatalf("verify domain trust event: %v", err)
	}
}

func TestTrustApplyRequiresAdminProof(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemon := newConfigApplyTestDaemon(t, configApplyDesired(pkiSet, "10.0.1.0/24"))
	trust := config.TrustConfig{RevokedCertFingerprints: []string{fingerprintForCertPath(t, pkiSet.ixCerts["ix-c"])}}

	if _, err := daemon.applyTrustConfig(context.Background(), trust); err == nil {
		t.Fatal("expected trust apply without admin proof to be rejected")
	}
}

func TestDomainTrustEventRequiresAdminProof(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemon := newConfigApplyTestDaemon(t, configApplyDesired(pkiSet, "10.0.1.0/24"))
	trust := config.TrustConfig{RevokedCertFingerprints: []string{fingerprintForCertPath(t, pkiSet.ixCerts["ix-c"])}}
	head, err := daemon.store.Head()
	if err != nil {
		t.Fatal(err)
	}
	event, _, changed, err := daemon.domainTrustEventIfChangedAtHead(trust, nil, head)
	if err != nil {
		t.Fatalf("build trust event: %v", err)
	}
	if !changed {
		t.Fatal("trust event did not report change")
	}
	if err := daemon.verifyConfigEvent(*event); err == nil {
		t.Fatal("expected domain trust event without admin proof to be rejected")
	}
}

func TestConfigSyncAppliesDomainTrustEvent(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	source := newConfigSyncTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "", "10.0.0.0/24"), false)
	target := newConfigSyncTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "", "10.0.2.0/24"), false)
	fingerprint := fingerprintForCertPath(t, pkiSet.adminCert)
	trust := config.TrustConfig{RevokedCertFingerprints: []string{fingerprint}}
	body := mustJSON(t, trust)
	request := httptest.NewRequest(http.MethodPost, "/v1/trust", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, request, body, pkiSet.adminCert, pkiSet.adminKey)
	proof, err := source.verifyAdminRequest(request, body)
	if err != nil {
		t.Fatalf("verify admin request: %v", err)
	}
	if changed, err := source.applyTrustConfig(context.WithValue(context.Background(), adminProofContextKey{}, proof), trust); err != nil || !changed {
		t.Fatalf("apply source trust changed=%t err=%v", changed, err)
	}
	server := httptest.NewServer(source.peerHandler())
	defer server.Close()

	if err := target.syncConfigLogWithTarget(context.Background(), controlTarget{
		ID:         "ix-a",
		Domain:     "lab.local",
		ControlAPI: server.URL,
	}); err != nil {
		t.Fatalf("sync config log: %v", err)
	}
	if target.head.Seq != source.head.Seq || target.head.Hash != source.head.Hash {
		t.Fatalf("target head = %+v, want source %+v", target.head, source.head)
	}
	if len(target.desired.Trust.RevokedCertFingerprints) != 1 || target.desired.Trust.RevokedCertFingerprints[0] != fingerprint {
		t.Fatalf("target trust = %#v, want revoked %q", target.desired.Trust, fingerprint)
	}
	events, err := target.store.Range(2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if events[0].Resource != domainTrustResource {
		t.Fatalf("synced resource = %q, want %q", events[0].Resource, domainTrustResource)
	}
}

func TestDomainTrustRevocationAppliesAfterEvent(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemon := newConfigApplyTestDaemon(t, configApplyDesired(pkiSet, "10.0.1.0/24"))
	event, _, changed, err := daemon.desiredEventIfChanged(configApplyDesired(pkiSet, "10.0.2.0/24"), nil)
	if err != nil || !changed {
		t.Fatalf("build desired event changed=%t err=%v", changed, err)
	}
	if err := daemon.store.Append(*event); err != nil {
		t.Fatalf("append desired event: %v", err)
	}
	head, err := daemon.store.Head()
	if err != nil {
		t.Fatal(err)
	}
	daemon.head = head
	trust := config.TrustConfig{RevokedCertFingerprints: []string{fingerprintForCertPath(t, pkiSet.ixCerts["ix-a"])}}
	body := mustJSON(t, trust)
	request := httptest.NewRequest(http.MethodPost, "/v1/trust", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, request, body, pkiSet.adminCert, pkiSet.adminKey)
	proof, err := daemon.verifyAdminRequest(request, body)
	if err != nil {
		t.Fatalf("verify admin request: %v", err)
	}
	trustEvent, _, changed, err := daemon.domainTrustEventIfChangedAtHead(trust, adminProofsFromContext(context.WithValue(context.Background(), adminProofContextKey{}, proof)), head)
	if err != nil || !changed {
		t.Fatalf("build trust event changed=%t err=%v", changed, err)
	}

	events, err := daemon.store.Range(1, daemon.head.Seq)
	if err != nil {
		t.Fatal(err)
	}
	events = append(events, *trustEvent)
	validator := configlog.NewMemoryStore()
	currentTrust := daemon.desired.Trust
	for _, candidate := range events {
		if err := validator.Append(candidate); err != nil {
			t.Fatalf("validator append seq %d: %v", candidate.Seq, err)
		}
		if err := daemon.verifyConfigEventWithTrust(candidate, currentTrust); err != nil {
			t.Fatalf("verify seq %d with effective trust: %v", candidate.Seq, err)
		}
		if candidate.Resource == domainTrustResource {
			currentTrust, err = parseDomainTrustPayload(candidate.Payload, daemon.desired.Domain.ID)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := daemon.verifyConfigEventWithTrust(*event, trust); err == nil {
		t.Fatal("expected old IX event to be rejected under post-revocation trust")
	}
}

func TestDomainTrustAdminPolicyThreshold(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemon := newConfigApplyTestDaemon(t, configApplyDesired(pkiSet, "10.0.1.0/24"))
	admin1 := fingerprintForCertPath(t, pkiSet.adminCert)
	admin2 := fingerprintForCertPath(t, pkiSet.admin2Cert)
	policyTrust := daemon.desired.Trust
	policyTrust.AdminPolicy = config.AdminPolicyConfig{
		Threshold:           2,
		AllowedFingerprints: []string{admin1, admin2},
	}
	body := mustJSON(t, policyTrust)
	request := httptest.NewRequest(http.MethodPost, "/v1/trust", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, request, body, pkiSet.adminCert, pkiSet.adminKey)
	proof, err := daemon.verifyAdminRequest(request, body)
	if err != nil {
		t.Fatalf("verify initial admin request: %v", err)
	}
	if changed, err := daemon.applyTrustConfig(context.WithValue(context.Background(), adminProofContextKey{}, proof), policyTrust); err != nil || !changed {
		t.Fatalf("apply threshold policy changed=%t err=%v", changed, err)
	}

	revokeTrust := daemon.desired.Trust
	revokeTrust.RevokedCertFingerprints = []string{fingerprintForCertPath(t, pkiSet.ixCerts["ix-c"])}
	body = mustJSON(t, revokeTrust)
	single := httptest.NewRequest(http.MethodPost, "/v1/trust", bytes.NewReader(body))
	single.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, single, body, pkiSet.adminCert, pkiSet.adminKey)
	singleProof, err := daemon.verifyAdminRequest(single, body)
	if err != nil {
		t.Fatalf("verify single admin request: %v", err)
	}
	if _, err := daemon.applyTrustConfig(context.WithValue(context.Background(), adminProofContextKey{}, singleProof), revokeTrust); err == nil {
		t.Fatal("expected one admin proof to be rejected by threshold policy")
	}

	multi := httptest.NewRequest(http.MethodPost, "/v1/trust", bytes.NewReader(body))
	multi.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, multi, body, pkiSet.adminCert, pkiSet.adminKey)
	addAdminTestRequestSignature(t, multi, body, pkiSet.admin2Cert, pkiSet.admin2Key)
	proofs, err := daemon.verifyAdminRequests(multi, body)
	if err != nil {
		t.Fatalf("verify multi admin request: %v", err)
	}
	if changed, err := daemon.applyTrustConfig(context.WithValue(context.Background(), adminProofContextKey{}, proofs), revokeTrust); err != nil || !changed {
		t.Fatalf("apply threshold revoke changed=%t err=%v", changed, err)
	}
	events, err := daemon.store.Range(3, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(events[0].AdminProofs) != 2 {
		t.Fatalf("admin proofs on threshold event = %d, want 2", len(events[0].AdminProofs))
	}
}

func TestDomainTrustRootRotationAllowsNewAdminCA(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemon := newConfigApplyTestDaemon(t, configApplyDesired(pkiSet, "10.0.1.0/24"))
	out := t.TempDir()
	newRoot, err := pki.NewRoot("TrustIX Rotated Root", 1)
	if err != nil {
		t.Fatalf("create rotated root: %v", err)
	}
	newAdmin, err := pki.Issue(newRoot, pki.IssueRequest{
		CommonName: "TrustIX Rotated Admin",
		Role:       pki.RoleAdmin,
		Domain:     "lab.local",
		NotAfter:   time.Now().AddDate(1, 0, 0),
	})
	if err != nil {
		t.Fatalf("issue rotated admin: %v", err)
	}
	if err := pki.WriteBundle(out, "rotated-admin", newAdmin, true); err != nil {
		t.Fatalf("write rotated admin: %v", err)
	}
	rotatedAdminCert := filepath.Join(out, "rotated-admin.crt")
	rotatedAdminKey := filepath.Join(out, "rotated-admin.key")

	rootTrust := daemon.desired.Trust
	rootTrust.TrustRootsPEM = []string{string(newRoot.CertPEM)}
	body := mustJSON(t, rootTrust)
	request := httptest.NewRequest(http.MethodPost, "/v1/trust", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, request, body, pkiSet.adminCert, pkiSet.adminKey)
	proof, err := daemon.verifyAdminRequest(request, body)
	if err != nil {
		t.Fatalf("verify root rotation request: %v", err)
	}
	if changed, err := daemon.applyTrustConfig(context.WithValue(context.Background(), adminProofContextKey{}, proof), rootTrust); err != nil || !changed {
		t.Fatalf("apply root rotation changed=%t err=%v", changed, err)
	}

	revokeTrust := daemon.desired.Trust
	revokeTrust.RevokedCertFingerprints = []string{fingerprintForCertPath(t, pkiSet.ixCerts["ix-c"])}
	body = mustJSON(t, revokeTrust)
	rotatedRequest := httptest.NewRequest(http.MethodPost, "/v1/trust", bytes.NewReader(body))
	rotatedRequest.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, rotatedRequest, body, rotatedAdminCert, rotatedAdminKey)
	rotatedProof, err := daemon.verifyAdminRequest(rotatedRequest, body)
	if err != nil {
		t.Fatalf("verify rotated admin request: %v", err)
	}
	if changed, err := daemon.applyTrustConfig(context.WithValue(context.Background(), adminProofContextKey{}, rotatedProof), revokeTrust); err != nil || !changed {
		t.Fatalf("apply rotated admin trust change changed=%t err=%v", changed, err)
	}
}
