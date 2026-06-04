package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trustix.local/trustix/internal/adminauth"
	"trustix.local/trustix/internal/pki"
)

func TestAdminAuthRejectsUnsignedConfigApply(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	initial := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, initial)
	daemon.cfg.APIAdminAuth = true
	body := mustJSON(t, configApplyDesired(pkiSet, "10.0.2.0/24"))
	request := httptest.NewRequest(http.MethodPost, "/v1/config/apply?format=json", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	daemon.handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
	}
}

func TestAdminAuthAcceptsSignedConfigApply(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	initial := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, initial)
	daemon.cfg.APIAdminAuth = true
	body := mustJSON(t, configApplyDesired(pkiSet, "10.0.2.0/24"))
	request := httptest.NewRequest(http.MethodPost, "/v1/config/apply?format=json", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, request, body, pkiSet.adminCert, pkiSet.adminKey)
	recorder := httptest.NewRecorder()

	daemon.handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if daemon.head.Seq != 3 {
		t.Fatalf("head seq = %d, want 3", daemon.head.Seq)
	}
	assertRuntimeRoute(t, daemon, "10.0.2.0/24")
	events, err := daemon.store.Range(3, 3)
	if err != nil {
		t.Fatalf("read applied event: %v", err)
	}
	if len(events[0].AdminProofs) != 1 {
		t.Fatalf("admin proofs = %#v, want one proof", events[0].AdminProofs)
	}
	adminCert, _, err := pki.LoadCertificate(pkiSet.adminCert)
	if err != nil {
		t.Fatal(err)
	}
	if events[0].AdminProofs[0].SignerID != signerIDForAdminCert(adminCert) {
		t.Fatalf("admin proof signer = %q, want %q", events[0].AdminProofs[0].SignerID, signerIDForAdminCert(adminCert))
	}
	if err := daemon.verifyConfigEvent(events[0]); err != nil {
		t.Fatalf("verify applied event with admin proof: %v", err)
	}
}

func TestAdminAuthRecordsOptionalSignedConfigApply(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	initial := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, initial)
	body := mustJSON(t, configApplyDesired(pkiSet, "10.0.2.0/24"))
	request := httptest.NewRequest(http.MethodPost, "/v1/config/apply?format=json", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, request, body, pkiSet.adminCert, pkiSet.adminKey)
	recorder := httptest.NewRecorder()

	daemon.handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	events, err := daemon.store.Range(3, 3)
	if err != nil {
		t.Fatalf("read applied event: %v", err)
	}
	if len(events[0].AdminProofs) != 1 {
		t.Fatalf("admin proofs = %#v, want one optional proof", events[0].AdminProofs)
	}
}

func TestAdminAuthRecordsProofOnInitialSameConfigApply(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	initial := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, initial)
	daemon.cfg.APIAdminAuth = true
	body := mustJSON(t, initial)
	request := httptest.NewRequest(http.MethodPost, "/v1/config/apply?format=json", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, request, body, pkiSet.adminCert, pkiSet.adminKey)
	proof, err := daemon.verifyAdminRequest(request, body)
	if err != nil {
		t.Fatalf("verify admin request: %v", err)
	}

	changed, err := daemon.applyDesiredConfig(context.WithValue(context.Background(), adminProofContextKey{}, proof), initial)
	if err != nil {
		t.Fatalf("apply desired config: %v", err)
	}
	if !changed {
		t.Fatal("same-config initial apply should append baseline")
	}
	if daemon.head.Seq != 2 {
		t.Fatalf("head seq = %d, want 2", daemon.head.Seq)
	}
	events, err := daemon.store.Range(2, 2)
	if err != nil {
		t.Fatalf("read baseline event: %v", err)
	}
	if len(events[0].AdminProofs) != 1 {
		t.Fatalf("admin proofs = %#v, want one proof on baseline", events[0].AdminProofs)
	}
}

func TestHostManagementReadAuthRejectsUnsignedGET(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemon := newConfigApplyTestDaemon(t, configApplyDesired(pkiSet, "10.0.1.0/24"))
	daemon.desired.Management.HostAPI.Enabled = true
	request := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	recorder := httptest.NewRecorder()

	daemon.hostAPIHandler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
	}
}

func TestHostManagementReadAuthAcceptsSignedGET(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemon := newConfigApplyTestDaemon(t, configApplyDesired(pkiSet, "10.0.1.0/24"))
	daemon.desired.Management.HostAPI.Enabled = true
	request := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	signAdminTestRequest(t, request, nil, pkiSet.adminCert, pkiSet.adminKey)
	recorder := httptest.NewRecorder()

	daemon.hostAPIHandler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
}

func TestPrimaryNetworkReadAuthRejectsUnsignedGET(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemon := newConfigApplyTestDaemon(t, configApplyDesired(pkiSet, "10.0.1.0/24"))
	daemon.cfg.APIAddr = "0.0.0.0:8787"
	daemon.cfg.APIAdminAuth = true
	request := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	recorder := httptest.NewRecorder()

	daemon.handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
	}
}

func TestPrimaryNetworkReadAuthAcceptsSignedGET(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemon := newConfigApplyTestDaemon(t, configApplyDesired(pkiSet, "10.0.1.0/24"))
	daemon.cfg.APIAddr = "0.0.0.0:8787"
	daemon.cfg.APIAdminAuth = true
	request := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	signAdminTestRequest(t, request, nil, pkiSet.adminCert, pkiSet.adminKey)
	recorder := httptest.NewRecorder()

	daemon.handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
}

func TestPrimaryNetworkReadAuthStillServesWebUI(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemon := newConfigApplyTestDaemon(t, configApplyDesired(pkiSet, "10.0.1.0/24"))
	daemon.cfg.APIAddr = "0.0.0.0:8787"
	daemon.cfg.APIAdminAuth = true
	daemon.desired.Management.WebUI.Enabled = true
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	recorder := httptest.NewRecorder()

	daemon.handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"require_admin_proof":true`) {
		t.Fatalf("index bootstrap does not require admin proof: %s", recorder.Body.String())
	}
}

func TestHostManagementReadAuthCanBeExplicitlyRelaxed(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemon := newConfigApplyTestDaemon(t, configApplyDesired(pkiSet, "10.0.1.0/24"))
	daemon.desired.Management.HostAPI.Enabled = true
	daemon.desired.Management.HostAPI.AllowUnauthenticatedReads = true
	request := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	recorder := httptest.NewRecorder()

	daemon.hostAPIHandler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
}

func TestHostManagementWriteAuthRequiredByDefault(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	initial := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, initial)
	daemon.desired.Management.HostAPI.Enabled = true
	body := mustJSON(t, configApplyDesired(pkiSet, "10.0.2.0/24"))
	request := httptest.NewRequest(http.MethodPost, "/v1/config/apply?format=json", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	daemon.hostAPIHandler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
	}
}

func TestManagementRejectsCrossSiteMutation(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	initial := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, initial)
	body := mustJSON(t, configApplyDesired(pkiSet, "10.0.2.0/24"))
	request := httptest.NewRequest(http.MethodPost, "/v1/config/apply?format=json", bytes.NewReader(body))
	request.Host = "127.0.0.1:8787"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://evil.example")
	recorder := httptest.NewRecorder()

	daemon.handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusForbidden, recorder.Body.String())
	}
}

func TestManagementRejectsCrossSchemeMutation(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	initial := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, initial)
	body := mustJSON(t, configApplyDesired(pkiSet, "10.0.2.0/24"))
	request := httptest.NewRequest(http.MethodPost, "/v1/config/apply?format=json", bytes.NewReader(body))
	request.Host = "127.0.0.1:8787"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://127.0.0.1:8787")
	recorder := httptest.NewRecorder()

	daemon.handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusForbidden, recorder.Body.String())
	}
}

func TestManagementRejectsCrossSiteFetchMetadataMutation(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	initial := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, initial)
	body := mustJSON(t, configApplyDesired(pkiSet, "10.0.2.0/24"))
	request := httptest.NewRequest(http.MethodPost, "/v1/config/apply?format=json", bytes.NewReader(body))
	request.Host = "127.0.0.1:8787"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	recorder := httptest.NewRecorder()

	daemon.handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusForbidden, recorder.Body.String())
	}
}

func TestManagementAllowsSameOriginMutation(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	initial := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, initial)
	body := mustJSON(t, configApplyDesired(pkiSet, "10.0.2.0/24"))
	request := httptest.NewRequest(http.MethodPost, "/v1/config/apply?format=json", bytes.NewReader(body))
	request.Host = "127.0.0.1:8787"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://127.0.0.1:8787")
	recorder := httptest.NewRecorder()

	daemon.handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
}

func TestAdminAuthRejectsIXSignedConfigApply(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	initial := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, initial)
	daemon.cfg.APIAdminAuth = true
	body := mustJSON(t, configApplyDesired(pkiSet, "10.0.2.0/24"))
	request := httptest.NewRequest(http.MethodPost, "/v1/config/apply?format=json", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, request, body, pkiSet.ixCerts["ix-a"], pkiSet.ixKeys["ix-a"])
	recorder := httptest.NewRecorder()

	daemon.handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
	}
}

func TestAdminAuthRejectsRevokedAdminCertificate(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	initial := configApplyDesired(pkiSet, "10.0.1.0/24")
	initial.Trust.RevokedCertFingerprints = []string{fingerprintForCertPath(t, pkiSet.adminCert)}
	daemon := newConfigApplyTestDaemon(t, initial)
	daemon.cfg.APIAdminAuth = true
	body := mustJSON(t, initial)
	request := httptest.NewRequest(http.MethodPost, "/v1/config/apply?format=json", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, request, body, pkiSet.adminCert, pkiSet.adminKey)
	recorder := httptest.NewRecorder()

	daemon.handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
	}
}

func TestAPIAddrIsLoopback(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{addr: "127.0.0.1:8787", want: true},
		{addr: "localhost:8787", want: true},
		{addr: "[::1]:8787", want: true},
		{addr: "0.0.0.0:8787", want: false},
		{addr: ":8787", want: false},
	}
	for _, test := range tests {
		if got := apiAddrIsLoopback(test.addr); got != test.want {
			t.Fatalf("apiAddrIsLoopback(%q) = %t, want %t", test.addr, got, test.want)
		}
	}
}

func TestAPISecurityDoctorNamesRestoreBackupExposure(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemon := newConfigApplyTestDaemon(t, configApplyDesired(pkiSet, "10.0.1.0/24"))
	daemon.cfg.APIAddr = "0.0.0.0:8787"

	check := daemon.apiSecurityDoctorCheck()
	if check.Name != "api_security" || check.Status != "warn" || !strings.Contains(check.Detail, "config restore-backup") {
		t.Fatalf("api security doctor check = %#v, want warn with restore-backup detail", check)
	}

	daemon.cfg.APIAdminAuth = true
	check = daemon.apiSecurityDoctorCheck()
	if check.Status != "ok" || !strings.Contains(check.Detail, "config apply/rejoin/restore-backup") {
		t.Fatalf("api security doctor check with auth = %#v, want ok with mutation detail", check)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func signAdminTestRequest(t *testing.T, request *http.Request, body []byte, certPath, keyPath string) {
	t.Helper()
	signAdminTestRequestWithMode(t, request, body, certPath, keyPath, false)
}

func addAdminTestRequestSignature(t *testing.T, request *http.Request, body []byte, certPath, keyPath string) {
	t.Helper()
	signAdminTestRequestWithMode(t, request, body, certPath, keyPath, true)
}

func signAdminTestRequestWithMode(t *testing.T, request *http.Request, body []byte, certPath, keyPath string, add bool) {
	t.Helper()
	bundle, err := pki.LoadBundle(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	signingBytes := adminauth.SigningBytes(request.Method, request.URL.RequestURI(), timestamp, body)
	signature, err := pki.Sign(bundle.Key, signingBytes)
	if err != nil {
		t.Fatal(err)
	}
	if add {
		request.Header.Add(adminauth.HeaderCert, base64.StdEncoding.EncodeToString(bundle.Cert.Raw))
		request.Header.Add(adminauth.HeaderSignature, base64.StdEncoding.EncodeToString(signature))
		request.Header.Add(adminauth.HeaderTimestamp, timestamp)
		return
	}
	request.Header.Set(adminauth.HeaderCert, base64.StdEncoding.EncodeToString(bundle.Cert.Raw))
	request.Header.Set(adminauth.HeaderSignature, base64.StdEncoding.EncodeToString(signature))
	request.Header.Set(adminauth.HeaderTimestamp, timestamp)
}
