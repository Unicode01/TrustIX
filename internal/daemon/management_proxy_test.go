package daemon

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
)

func TestManagementProxyFetchesRemoteStatus(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonB := newConfigApplyTestDaemon(t, desiredForManagementProxyTest(pkiSet, "ix-b", "10.0.1.0/24"))
	serverB := httptest.NewServer(daemonB.peerHandler())
	t.Cleanup(serverB.Close)
	daemonA := newConfigApplyTestDaemon(t, desiredForManagementProxyTest(pkiSet, "ix-a", "10.0.0.0/24"))
	daemonA.desired.Peers = []config.PeerConfig{{
		ID:         "ix-b",
		Domain:     "lab.local",
		ControlAPI: serverB.URL,
		Endpoints:  []config.EndpointConfig{},
	}}
	request := httptest.NewRequest(http.MethodGet, "/v1/management/ix/ix-b/v1/status", nil)
	signAdminTestRequest(t, request, nil, pkiSet.adminCert, pkiSet.adminKey)
	recorder := httptest.NewRecorder()

	daemonA.handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var status statusResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status.IXID != "ix-b" {
		t.Fatalf("proxied ix_id = %q, want ix-b", status.IXID)
	}
}

func TestManagementVIPProxyFetchesRemoteStatus(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonB := newConfigApplyTestDaemon(t, desiredForManagementProxyTest(pkiSet, "ix-b", "10.0.1.0/24"))
	serverB := httptest.NewServer(daemonB.peerHandler())
	t.Cleanup(serverB.Close)
	desiredA := desiredForManagementProxyTest(pkiSet, "ix-a", "10.0.0.0/24")
	desiredA.Management.HostAPI.Enabled = true
	desiredA.Management.HostAPI.Listen = "10.0.0.1:8787"
	daemonA := newConfigApplyTestDaemon(t, desiredA)
	daemonA.desired.Peers = []config.PeerConfig{{
		ID:         "ix-b",
		Domain:     "lab.local",
		ControlAPI: serverB.URL,
		Endpoints:  []config.EndpointConfig{},
	}}
	request := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	signAdminTestRequest(t, request, nil, pkiSet.adminCert, pkiSet.adminKey)
	recorder := httptest.NewRecorder()

	daemonA.managementVIPProxyHandler("ix-b").ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var status statusResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status.IXID != "ix-b" {
		t.Fatalf("proxied ix_id = %q, want ix-b", status.IXID)
	}
}

func TestManagementProxyRequiresAdminSignature(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newConfigApplyTestDaemon(t, desiredForManagementProxyTest(pkiSet, "ix-a", "10.0.0.0/24"))
	request := httptest.NewRequest(http.MethodGet, "/v1/management/ix/ix-b/v1/status", nil)
	recorder := httptest.NewRecorder()

	daemonA.handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
	}
}

func TestManagementProxyRemoteApplyRecordsAdminProof(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	initialB := desiredForManagementProxyTest(pkiSet, "ix-b", "10.0.1.0/24")
	daemonB := newConfigApplyTestDaemon(t, initialB)
	serverB := httptest.NewServer(daemonB.peerHandler())
	t.Cleanup(serverB.Close)
	daemonA := newConfigApplyTestDaemon(t, desiredForManagementProxyTest(pkiSet, "ix-a", "10.0.0.0/24"))
	daemonA.desired.Peers = []config.PeerConfig{{
		ID:         "ix-b",
		Domain:     "lab.local",
		ControlAPI: serverB.URL,
		Endpoints:  []config.EndpointConfig{},
	}}
	nextB := initialB
	nextB.Management.HostAPI.Enabled = true
	nextB.Management.HostAPI.Listen = "10.0.1.1:8787"
	body := mustJSON(t, nextB)
	request := httptest.NewRequest(http.MethodPost, "/v1/management/ix/ix-b/v1/config/apply?format=json", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, request, body, pkiSet.adminCert, pkiSet.adminKey)
	recorder := httptest.NewRecorder()

	daemonA.handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	events, err := daemonB.store.Range(3, 3)
	if err != nil {
		t.Fatalf("read remote applied event: %v", err)
	}
	if len(events) != 1 || len(events[0].AdminProofs) != 1 {
		t.Fatalf("remote admin proofs = %#v, want one proof", events)
	}
	if !strings.Contains(events[0].AdminProofs[0].RequestURI, "/v1/management/ix/ix-b/v1/config/apply") {
		t.Fatalf("admin proof request URI = %q, want proxy URI", events[0].AdminProofs[0].RequestURI)
	}
}

func desiredForManagementProxyTest(pkiSet membershipPKI, ixID core.IXID, prefix string) config.Desired {
	desired := desiredForMembershipTest(pkiSet, ixID, "", "", prefix)
	desired.Endpoints = nil
	desired.Peers = nil
	desired.Routes = nil
	desired.Policies = nil
	desired.TransportPolicy = config.TransportPolicyConfig{}
	return desired
}
