package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trustix.local/trustix/internal/configlog"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/pki"
)

func TestAdmissionApproveRequiresAdminProof(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	daemonA.store = configlog.NewMemoryStore()
	if err := daemonA.store.Append(mustGenesisEvent(t, daemonA)); err != nil {
		t.Fatal(err)
	}
	head, err := daemonA.store.Head()
	if err != nil {
		t.Fatal(err)
	}
	daemonA.head = head

	body := admissionApproveBody(t, pkiSet, "ix-c", "10.0.2.0/24")
	request := httptest.NewRequest(http.MethodPost, "/v1/admissions/approve", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	daemonA.handler().ServeHTTP(recorder, request)

	if recorder.Code < 400 {
		t.Fatalf("unsigned admission approve status = %d, want error", recorder.Code)
	}
}

func TestChainAdmissionRejectsUnapprovedIXAfterFirstAdmission(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	daemonA.store = configlog.NewMemoryStore()
	if err := daemonA.store.Append(mustGenesisEvent(t, daemonA)); err != nil {
		t.Fatal(err)
	}
	approveAdmissionViaAPI(t, daemonA, pkiSet, "ix-b", "10.0.1.0/24")

	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 2)
	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if _, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap"); err == nil {
		t.Fatal("expected unapproved IX advertisement to be rejected after admission mode is enabled")
	}
	if _, ok := daemonA.pendingAdmissionSnapshot("ix-c"); !ok {
		t.Fatal("unapproved IX advertisement was not recorded as pending")
	}
	if _, ok := daemonA.dynamicPeerConfig("ix-c"); ok {
		t.Fatal("pending IX was added as dynamic peer before admission approval")
	}
}

func TestChainAdmissionAllowsApprovedIX(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	daemonA.store = configlog.NewMemoryStore()
	if err := daemonA.store.Append(mustGenesisEvent(t, daemonA)); err != nil {
		t.Fatal(err)
	}
	approveAdmissionViaAPI(t, daemonA, pkiSet, "ix-c", "10.0.2.0/24")

	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 2)
	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	changed, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap")
	if err != nil {
		t.Fatalf("merge approved ix-c advertisement: %v", err)
	}
	if !changed {
		t.Fatal("merge approved ix-c did not change membership")
	}
	if _, ok := daemonA.dynamicPeerConfig("ix-c"); !ok {
		t.Fatal("approved IX was not added as dynamic peer")
	}
}

func TestChainAdmissionRejectsFingerprintMismatch(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	daemonA.store = configlog.NewMemoryStore()
	if err := daemonA.store.Append(mustGenesisEvent(t, daemonA)); err != nil {
		t.Fatal(err)
	}
	approveAdmissionWithFingerprintViaAPI(t, daemonA, pkiSet, "ix-c", fingerprintForCertPath(t, pkiSet.ixCerts["ix-b"]), "10.0.2.0/24")

	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 2)
	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if _, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap"); err == nil {
		t.Fatal("expected fingerprint mismatch to reject advertisement")
	}
}

func TestAdmissionApprovePendingAdmitsObservedIX(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	daemonA.store = configlog.NewMemoryStore()
	if err := daemonA.store.Append(mustGenesisEvent(t, daemonA)); err != nil {
		t.Fatal(err)
	}
	approveAdmissionViaAPI(t, daemonA, pkiSet, "ix-b", "10.0.1.0/24")

	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 2)
	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if _, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap"); !isPendingAdmissionError(err) {
		t.Fatalf("merge unapproved ix-c err = %v, want pending admission error", err)
	}

	body, err := json.Marshal(struct {
		IXID core.IXID `json:"ix_id"`
	}{IXID: "ix-c"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/admissions/approve-pending", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, request, body, pkiSet.adminCert, pkiSet.adminKey)
	recorder := httptest.NewRecorder()
	daemonA.handler().ServeHTTP(recorder, request)
	if recorder.Code < 200 || recorder.Code >= 300 {
		t.Fatalf("approve pending status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if _, ok := daemonA.dynamicPeerConfig("ix-c"); !ok {
		t.Fatal("approve-pending did not add ix-c as dynamic peer")
	}
	if _, ok := daemonA.pendingAdmissionSnapshot("ix-c"); ok {
		t.Fatal("approve-pending did not clear pending ix-c")
	}
	daemonA.configMu.RLock()
	admission, ok, err := daemonA.latestAdmissionForIXLocked("ix-c")
	daemonA.configMu.RUnlock()
	if err != nil || !ok {
		t.Fatalf("latest admission ok=%t err=%v", ok, err)
	}
	if admission.IXCertFingerprint != fingerprintForCertPath(t, pkiSet.ixCerts["ix-c"]) {
		t.Fatalf("approve-pending ix fingerprint = %q", admission.IXCertFingerprint)
	}
	if len(admission.AllowedPrefixes) != 1 || admission.AllowedPrefixes[0] != "10.0.2.0/24" {
		t.Fatalf("approve-pending prefixes = %#v", admission.AllowedPrefixes)
	}
	if len(admission.RouteAuthFingerprints) != 1 || admission.RouteAuthFingerprints[0] != fingerprintForCertPath(t, pkiSet.routeCerts["ix-c"]) {
		t.Fatalf("approve-pending route auth fingerprints = %#v", admission.RouteAuthFingerprints)
	}
	if admission.ControlAPI != "https://127.0.0.1:9445" {
		t.Fatalf("approve-pending control api = %q", admission.ControlAPI)
	}
}

func TestPendingAdmissionPersistenceAndPrune(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	dataDir := t.TempDir()
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	daemonA.cfg.DataDir = dataDir
	daemonA.store = configlog.NewMemoryStore()
	if err := daemonA.store.Append(mustGenesisEvent(t, daemonA)); err != nil {
		t.Fatal(err)
	}
	approveAdmissionViaAPI(t, daemonA, pkiSet, "ix-b", "10.0.1.0/24")

	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 2)
	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if _, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap"); !isPendingAdmissionError(err) {
		t.Fatalf("merge unapproved ix-c err = %v, want pending admission error", err)
	}
	if _, err := os.Stat(daemonA.pendingMembershipStatePath()); err != nil {
		t.Fatalf("pending state was not written: %v", err)
	}

	restarted := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	restarted.cfg.DataDir = dataDir
	restarted.store = daemonA.store
	restarted.head = daemonA.head
	if err := restarted.loadPersistedPendingMembers(); err != nil {
		t.Fatalf("load pending members: %v", err)
	}
	pending, ok := restarted.pendingAdmissionSnapshot("ix-c")
	if !ok {
		t.Fatal("persisted pending ix-c was not restored")
	}
	if pending.Expired || pending.TTLSeconds <= 0 || pending.ExpiresAt.IsZero() {
		t.Fatalf("pending expiry fields = %#v", pending)
	}

	restarted.membershipMu.Lock()
	record := restarted.pendingMembers["ix-c"]
	record.LastSeen = time.Now().Add(-pendingMemberTTL - time.Second)
	restarted.pendingMembers["ix-c"] = record
	restarted.membershipMu.Unlock()
	if !restarted.pruneExpiredPendingMembers() {
		t.Fatal("expired pending member was not pruned")
	}
	if _, ok := restarted.pendingAdmissionSnapshot("ix-c"); ok {
		t.Fatal("expired pending ix-c still exists")
	}
}

func TestPendingAdmissionPrunedWhenTrustRevokesCertificate(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	daemonA.cfg.DataDir = t.TempDir()
	daemonA.store = configlog.NewMemoryStore()
	if err := daemonA.store.Append(mustGenesisEvent(t, daemonA)); err != nil {
		t.Fatal(err)
	}
	approveAdmissionViaAPI(t, daemonA, pkiSet, "ix-b", "10.0.1.0/24")

	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 2)
	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if _, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap"); !isPendingAdmissionError(err) {
		t.Fatalf("merge unapproved ix-c err = %v, want pending admission error", err)
	}

	daemonA.desired.Trust.RevokedCertFingerprints = []string{fingerprintForCertPath(t, pkiSet.ixCerts["ix-c"])}
	changed, err := daemonA.enforceRuntimeTrustState()
	if err != nil {
		t.Fatalf("enforce trust: %v", err)
	}
	if !changed {
		t.Fatal("trust enforcement did not report pending cleanup")
	}
	if _, ok := daemonA.pendingAdmissionSnapshot("ix-c"); ok {
		t.Fatal("revoked pending ix-c still exists")
	}
}

func TestAdmissionRevalidationPrunesPrefixMismatch(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	daemonA.store = configlog.NewMemoryStore()
	if err := daemonA.store.Append(mustGenesisEvent(t, daemonA)); err != nil {
		t.Fatal(err)
	}
	approveAdmissionViaAPI(t, daemonA, pkiSet, "ix-c", "10.0.2.0/24")

	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 2)
	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if _, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap"); err != nil {
		t.Fatalf("merge approved ix-c advertisement: %v", err)
	}
	if _, ok := daemonA.dynamicPeerConfig("ix-c"); !ok {
		t.Fatal("approved ix-c was not added before revalidation")
	}

	body := admissionApproveBodyWithFingerprint(t, pkiSet, "ix-c", fingerprintForCertPath(t, pkiSet.ixCerts["ix-c"]), "10.0.99.0/24")
	request := httptest.NewRequest(http.MethodPost, "/v1/admissions/approve", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, request, body, pkiSet.adminCert, pkiSet.adminKey)
	recorder := httptest.NewRecorder()
	daemonA.handler().ServeHTTP(recorder, request)
	if recorder.Code < 200 || recorder.Code >= 300 {
		t.Fatalf("narrow admission status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if _, ok := daemonA.dynamicPeerConfig("ix-c"); ok {
		t.Fatal("ix-c remained dynamic peer after admission prefix no longer allowed it")
	}
}

func TestChainAdmissionSyncEnablesRemoteAcceptance(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	source := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	source.store = configlog.NewMemoryStore()
	if err := source.store.Append(mustGenesisEvent(t, source)); err != nil {
		t.Fatal(err)
	}
	approveAdmissionViaAPI(t, source, pkiSet, "ix-c", "10.0.2.0/24")
	sourceHead, err := source.store.Head()
	if err != nil {
		t.Fatal(err)
	}
	source.head = sourceHead

	target := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-b", "127.0.0.1:7002", "https://127.0.0.1:9444", "10.0.1.0/24"), 1)
	target.store = configlog.NewMemoryStore()
	if err := target.store.Append(mustGenesisEvent(t, target)); err != nil {
		t.Fatal(err)
	}
	targetHead, err := target.store.Head()
	if err != nil {
		t.Fatal(err)
	}
	target.head = targetHead
	if err := target.registerLocalConfigSigner(); err != nil {
		t.Fatalf("register target signer: %v", err)
	}
	sourceCert, _, err := pki.LoadCertificate(source.desired.IX.CertPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.registerConfigSignerCertificate(sourceCert, false); err != nil {
		t.Fatalf("register source signer: %v", err)
	}
	events, err := source.store.Range(2, sourceHead.Seq)
	if err != nil {
		t.Fatal(err)
	}
	if appended, err := target.appendVerifiedConfigEvents(context.Background(), events, source.signerCertificatesForEvents(events)); err != nil || appended != len(events) {
		t.Fatalf("append synced admissions appended=%d err=%v", appended, err)
	}

	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 2)
	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if _, err := target.mergeAdvertisement(advertisement, "test-sync"); err != nil {
		t.Fatalf("target rejected synced approved admission: %v", err)
	}
}

func approveAdmissionViaAPI(t *testing.T, daemon *Daemon, pkiSet membershipPKI, ixID core.IXID, prefix string) {
	t.Helper()
	approveAdmissionWithFingerprintViaAPI(t, daemon, pkiSet, ixID, fingerprintForCertPath(t, pkiSet.ixCerts[ixID]), prefix)
}

func approveAdmissionWithFingerprintViaAPI(t *testing.T, daemon *Daemon, pkiSet membershipPKI, ixID core.IXID, ixFingerprint, prefix string) {
	t.Helper()
	body := admissionApproveBodyWithFingerprint(t, pkiSet, ixID, ixFingerprint, prefix)
	request := httptest.NewRequest(http.MethodPost, "/v1/admissions/approve", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, request, body, pkiSet.adminCert, pkiSet.adminKey)
	recorder := httptest.NewRecorder()
	daemon.handler().ServeHTTP(recorder, request)
	if recorder.Code < 200 || recorder.Code >= 300 {
		t.Fatalf("approve admission status = %d body=%s", recorder.Code, recorder.Body.String())
	}
}

func admissionApproveBody(t *testing.T, pkiSet membershipPKI, ixID core.IXID, prefix string) []byte {
	t.Helper()
	return admissionApproveBodyWithFingerprint(t, pkiSet, ixID, fingerprintForCertPath(t, pkiSet.ixCerts[ixID]), prefix)
}

func admissionApproveBodyWithFingerprint(t *testing.T, pkiSet membershipPKI, ixID core.IXID, ixFingerprint, prefix string) []byte {
	t.Helper()
	routeFingerprint := fingerprintForCertPath(t, pkiSet.routeCerts[ixID])
	payload := struct {
		IXID                  core.IXID     `json:"ix_id"`
		IXCertFingerprint     string        `json:"ix_cert_fingerprint"`
		AllowedPrefixes       []core.Prefix `json:"allowed_prefixes"`
		RouteAuthFingerprints []string      `json:"route_auth_fingerprints"`
		ControlAPI            string        `json:"control_api"`
	}{
		IXID:                  ixID,
		IXCertFingerprint:     ixFingerprint,
		AllowedPrefixes:       []core.Prefix{core.Prefix(prefix)},
		RouteAuthFingerprints: []string{routeFingerprint},
		ControlAPI:            controlAPIForIX(ixID),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func mustGenesisEvent(t *testing.T, daemon *Daemon) configlog.Event {
	t.Helper()
	event, err := daemon.configGenesisEvent(daemon.desired)
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func controlAPIForIX(ixID core.IXID) string {
	switch ixID {
	case "ix-a":
		return "https://127.0.0.1:9443"
	case "ix-b":
		return "https://127.0.0.1:9444"
	case "ix-c":
		return "https://127.0.0.1:9445"
	default:
		return "https://127.0.0.1:9443"
	}
}

func TestAdmissionListUsesChainAdmissionModeBeforeFirstAdmission(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	daemonA.store = configlog.NewMemoryStore()
	if err := daemonA.store.Append(mustGenesisEvent(t, daemonA)); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/admissions", nil)
	recorder := httptest.NewRecorder()
	daemonA.handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("admissions list status = %d", recorder.Code)
	}
	if !bytes.Contains(recorder.Body.Bytes(), []byte(`"mode": "chain_admission"`)) {
		t.Fatalf("admissions list body = %s", recorder.Body.String())
	}
}

func TestAdmissionApproveNormalizesCertPathInputs(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	request := admissionApplyRequest{
		IXID:                  "ix-c",
		IXCertFingerprint:     fingerprintForCertPath(t, pkiSet.ixCerts["ix-c"]),
		AllowedPrefixes:       []core.Prefix{"10.0.2.99/24"},
		RouteAuthFingerprints: []string{fingerprintForCertPath(t, filepath.Join(filepath.Dir(pkiSet.routeCerts["ix-c"]), "ix-c-route.crt"))},
		ControlAPI:            "https://127.0.0.1:9445",
	}
	admission, err := daemonA.admissionPayloadFromApproveRequest(request)
	if err != nil {
		t.Fatalf("build admission payload: %v", err)
	}
	if len(admission.AllowedPrefixes) != 1 || admission.AllowedPrefixes[0] != "10.0.2.0/24" {
		t.Fatalf("normalized prefixes = %#v", admission.AllowedPrefixes)
	}
}
