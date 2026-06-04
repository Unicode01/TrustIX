package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/routing"
	rstate "trustix.local/trustix/internal/runtime"
	"trustix.local/trustix/internal/transport"
)

func TestEndpointGrantIssueListRevokeAndInboundEnforcement(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	desired.Endpoints = []config.EndpointConfig{{
		Name:       "access-udp",
		Mode:       config.EndpointModePassive,
		Transport:  "udp",
		Enabled:    true,
		EnabledSet: true,
		Access: config.EndpointAccessConfig{
			Mode:       "require_grant",
			DefaultTTL: "1h",
		},
	}}
	desired.Peers[0].Endpoints = []config.EndpointConfig{{
		Name:      "access-udp",
		Mode:      config.EndpointModeActive,
		Transport: "udp",
		Address:   "127.0.0.1:7001",
		Enabled:   true,
	}}
	daemon := newConfigApplyTestDaemon(t, desired)
	prepareEndpointGrantSessionTestDaemon(daemon)

	rejected := &blockingIdentitySession{peer: "ix-b", domain: "lab.local", recv: make(chan struct{})}
	if _, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{Name: "access-udp", Transport: transport.ProtocolUDP}, rejected); err == nil {
		t.Fatal("inbound session without endpoint grant was accepted")
	}

	issueBody := mustJSON(t, endpointGrantIssueRequest{SubjectIX: "ix-b", Endpoint: "access-udp", TTL: "30m"})
	issueRequest := httptest.NewRequest(http.MethodPost, "/v1/endpoint-grants/issue", bytes.NewReader(issueBody))
	issueRequest.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, issueRequest, issueBody, pkiSet.adminCert, pkiSet.adminKey)
	issueRecorder := httptest.NewRecorder()
	daemon.handler().ServeHTTP(issueRecorder, issueRequest)
	if issueRecorder.Code != http.StatusOK {
		t.Fatalf("issue grant status = %d body=%s", issueRecorder.Code, issueRecorder.Body.String())
	}
	var issue endpointGrantMutationResponse
	if err := json.Unmarshal(issueRecorder.Body.Bytes(), &issue); err != nil {
		t.Fatalf("decode grant issue: %v", err)
	}
	if !issue.Applied || issue.Grant.GrantID == "" || issue.Grant.SubjectIX != "ix-b" || issue.Grant.Endpoint != "access-udp" {
		t.Fatalf("grant issue response = %#v", issue)
	}
	if len(issue.Grant.Permissions) != 1 || issue.Grant.Permissions[0] != endpointGrantPermissionDataSession {
		t.Fatalf("grant permissions = %#v, want data_session", issue.Grant.Permissions)
	}

	listRecorder := httptest.NewRecorder()
	daemon.handler().ServeHTTP(listRecorder, httptest.NewRequest(http.MethodGet, "/v1/endpoint-grants", nil))
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("list grants status = %d body=%s", listRecorder.Code, listRecorder.Body.String())
	}
	var list endpointGrantListResponse
	if err := json.Unmarshal(listRecorder.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode grant list: %v", err)
	}
	if len(list.Grants) != 1 || list.Grants[0].GrantID != issue.Grant.GrantID {
		t.Fatalf("grant list = %#v", list)
	}

	accepted := &blockingIdentitySession{peer: "ix-b", domain: "lab.local", recv: make(chan struct{})}
	if _, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{Name: "access-udp", Transport: transport.ProtocolUDP}, accepted); err != nil {
		t.Fatalf("inbound session with endpoint grant rejected: %v", err)
	}

	revokeBody := mustJSON(t, endpointGrantRevokeRequest{GrantID: issue.Grant.GrantID})
	revokeRequest := httptest.NewRequest(http.MethodPost, "/v1/endpoint-grants/revoke", bytes.NewReader(revokeBody))
	revokeRequest.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, revokeRequest, revokeBody, pkiSet.adminCert, pkiSet.adminKey)
	revokeRecorder := httptest.NewRecorder()
	daemon.handler().ServeHTTP(revokeRecorder, revokeRequest)
	if revokeRecorder.Code != http.StatusOK {
		t.Fatalf("revoke grant status = %d body=%s", revokeRecorder.Code, revokeRecorder.Body.String())
	}
	if !accepted.closed {
		t.Fatal("revoking endpoint grant did not close the reverse data session")
	}

	again := &blockingIdentitySession{peer: "ix-b", domain: "lab.local", recv: make(chan struct{})}
	if _, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{Name: "access-udp", Transport: transport.ProtocolUDP}, again); err == nil {
		t.Fatal("inbound session after revoked endpoint grant was accepted")
	}
}

func TestEndpointGrantIssueRejectsUnsupportedPermission(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	desired.Endpoints = []config.EndpointConfig{{
		Name:       "access-udp",
		Mode:       config.EndpointModePassive,
		Transport:  "udp",
		Enabled:    true,
		EnabledSet: true,
		Access: config.EndpointAccessConfig{
			Mode: "require_grant",
		},
	}}
	desired.Peers[0].Endpoints = []config.EndpointConfig{{
		Name:      "access-udp",
		Mode:      config.EndpointModeActive,
		Transport: "udp",
		Address:   "127.0.0.1:7001",
		Enabled:   true,
	}}
	daemon := newConfigApplyTestDaemon(t, desired)

	body := mustJSON(t, endpointGrantIssueRequest{
		SubjectIX:   "ix-b",
		Endpoint:    "access-udp",
		Permissions: []string{"route_advertise"},
	})
	request := httptest.NewRequest(http.MethodPost, "/v1/endpoint-grants/issue", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, request, body, pkiSet.adminCert, pkiSet.adminKey)
	recorder := httptest.NewRecorder()
	daemon.handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
	if !bytes.Contains(recorder.Body.Bytes(), []byte("unsupported")) {
		t.Fatalf("error body = %s, want unsupported permission", recorder.Body.String())
	}
}

func TestEndpointGrantIssueRejectsNonPassiveEndpoint(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	desired.Endpoints = []config.EndpointConfig{{
		Name:       "access-udp",
		Mode:       config.EndpointModeActive,
		Transport:  "udp",
		Address:    "127.0.0.1:7001",
		Enabled:    true,
		EnabledSet: true,
		Access: config.EndpointAccessConfig{
			Mode: "require_grant",
		},
	}}
	daemon := newConfigApplyTestDaemon(t, desired)

	body := mustJSON(t, endpointGrantIssueRequest{SubjectIX: "ix-b", Endpoint: "access-udp"})
	request := httptest.NewRequest(http.MethodPost, "/v1/endpoint-grants/issue", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, request, body, pkiSet.adminCert, pkiSet.adminKey)
	recorder := httptest.NewRecorder()
	daemon.handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
	if !bytes.Contains(recorder.Body.Bytes(), []byte("want passive")) {
		t.Fatalf("error body = %s, want passive endpoint error", recorder.Body.String())
	}
}

func TestEndpointAccessMetadataRoundTripInAdvertisement(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	desired.Endpoints = []config.EndpointConfig{{
		Name:      "access-udp",
		Mode:      config.EndpointModePassive,
		Address:   "198.51.100.10:7000",
		Transport: "udp",
		Enabled:   true,
		Access: config.EndpointAccessConfig{
			Mode:         "require_grant",
			AllowedPeers: []core.IXID{"ix-b"},
			DefaultTTL:   "45m",
		},
	}}
	daemon := newConfigApplyTestDaemon(t, desired)
	endpoints := daemon.localAdvertisementEndpointsForDesiredTarget(desired, controlTarget{ID: "ix-b", Domain: "lab.local"})
	if len(endpoints) != 1 {
		t.Fatalf("advertised endpoints = %#v", endpoints)
	}
	peer := peerConfigFromAdvertisementWithEndpoints(advertisementResponse{
		IXID:     "ix-a",
		DomainID: "lab.local",
	}, endpoints)
	if len(peer.Endpoints) != 1 {
		t.Fatalf("peer endpoints = %#v", peer.Endpoints)
	}
	access := peer.Endpoints[0].Access
	if access.Mode != "require_grant" || len(access.AllowedPeers) != 1 || access.AllowedPeers[0] != "ix-b" || access.DefaultTTL != "45m" {
		t.Fatalf("round-tripped endpoint access = %#v", access)
	}
}

func prepareEndpointGrantSessionTestDaemon(daemon *Daemon) {
	if daemon.dataplane == nil {
		daemon.dataplane = dataplane.NewNoopManager()
	}
	if daemon.routes == nil {
		daemon.routes = routing.NewTable()
	}
	if daemon.dataSessions == nil {
		daemon.dataSessions = make(map[dataSessionKey]transport.Session)
	}
	if daemon.dataSessionState == nil {
		daemon.dataSessionState = make(map[dataSessionKey]*dataSessionRuntime)
	}
	if daemon.endpointState == nil {
		daemon.endpointState = make(map[endpointStateKey]rstate.EndpointState)
	}
}
