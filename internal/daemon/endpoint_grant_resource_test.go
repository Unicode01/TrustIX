package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/configlog"
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
	if !accepted.closed.Load() {
		t.Fatal("revoking endpoint grant did not close the reverse data session")
	}

	again := &blockingIdentitySession{peer: "ix-b", domain: "lab.local", recv: make(chan struct{})}
	if _, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{Name: "access-udp", Transport: transport.ProtocolUDP}, again); err == nil {
		t.Fatal("inbound session after revoked endpoint grant was accepted")
	}
}

func TestEndpointGrantExpiryDropsExistingInboundSession(t *testing.T) {
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
	prepareEndpointGrantSessionTestDaemon(daemon)

	expiresAt := time.Now().UTC().Add(time.Minute)
	issueBody := mustJSON(t, endpointGrantIssueRequest{SubjectIX: "ix-b", Endpoint: "access-udp", ExpiresAt: expiresAt})
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

	accepted := &blockingIdentitySession{peer: "ix-b", domain: "lab.local", recv: make(chan struct{})}
	if _, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{Name: "access-udp", Transport: transport.ProtocolUDP}, accepted); err != nil {
		t.Fatalf("inbound session with endpoint grant rejected: %v", err)
	}

	dropped, err := daemon.dropDataSessionsUnauthorizedByEndpointGrantPolicyAt(issue.Grant.ExpiresAt.Add(time.Nanosecond))
	if err != nil {
		t.Fatalf("drop expired endpoint grant session: %v", err)
	}
	if dropped != 1 {
		t.Fatalf("expired grant dropped %d sessions, want 1", dropped)
	}
	if !accepted.closed.Load() {
		t.Fatal("expired endpoint grant did not close the reverse data session")
	}
}

func TestEndpointGrantCleanupFailsClosedWhenGrantLogUnreadable(t *testing.T) {
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
	daemon := newConfigApplyTestDaemon(t, desired)
	prepareEndpointGrantSessionTestDaemon(daemon)
	daemon.store = failingEndpointGrantStore{}

	session := &blockingIdentitySession{peer: "ix-b", domain: "lab.local", recv: make(chan struct{})}
	key := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "access-udp",
		Transport:  transport.ProtocolUDP,
		Address:    reverseSessionAddress,
		Encryption: "secure",
	}
	daemon.dataSessions[key] = session
	daemon.dataSessionState[key] = &dataSessionRuntime{
		key:      key,
		session:  session,
		endpoint: config.EndpointConfig{Name: "access-udp", Transport: "udp"},
	}

	dropped, err := daemon.dropDataSessionsUnauthorizedByEndpointGrantPolicy()
	if dropped != 1 {
		t.Fatalf("grant cleanup with unreadable log dropped %d sessions, want 1", dropped)
	}
	if err == nil || !strings.Contains(err.Error(), "failing endpoint grant store range") {
		t.Fatalf("grant cleanup error = %v, want store range error", err)
	}
	if !session.closed.Load() {
		t.Fatal("grant cleanup with unreadable log did not close require_grant session")
	}
}

func TestEndpointGrantCleanupReturnsSessionCloseError(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	desired.Endpoints = []config.EndpointConfig{{
		Name:       "access-udp",
		Mode:       config.EndpointModePassive,
		Transport:  "udp",
		Enabled:    true,
		EnabledSet: true,
		Access:     config.EndpointAccessConfig{Mode: "require_grant"},
	}}
	daemon := newConfigApplyTestDaemon(t, desired)
	prepareEndpointGrantSessionTestDaemon(daemon)
	closeErr := errors.New("injected endpoint grant close failure")
	session := &blockingIdentitySession{
		peer:     "ix-b",
		domain:   "lab.local",
		recv:     make(chan struct{}),
		closeErr: closeErr,
	}
	key := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "access-udp",
		Transport:  transport.ProtocolUDP,
		Address:    reverseSessionAddress,
		Encryption: "secure",
	}
	daemon.dataSessions[key] = session
	daemon.dataSessionState[key] = &dataSessionRuntime{
		key:      key,
		session:  session,
		endpoint: desired.Endpoints[0],
	}

	dropped, err := daemon.dropDataSessionsUnauthorizedByEndpointGrantPolicy()
	if dropped != 1 {
		t.Fatalf("dropped sessions = %d, want 1", dropped)
	}
	if !errors.Is(err, closeErr) {
		t.Fatalf("grant cleanup error = %v, want %v", err, closeErr)
	}
	if !session.closed.Load() {
		t.Fatal("endpoint grant session close was not attempted")
	}
}

func TestEndpointGrantCleanupKeepsSessionWithAnotherActiveGrant(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	desired.Endpoints = []config.EndpointConfig{{
		Name:       "access-udp",
		Mode:       config.EndpointModePassive,
		Transport:  "udp",
		Enabled:    true,
		EnabledSet: true,
		Access:     config.EndpointAccessConfig{Mode: "require_grant"},
	}}
	daemon := newConfigApplyTestDaemon(t, desired)
	prepareEndpointGrantSessionTestDaemon(daemon)
	session := &blockingIdentitySession{peer: "ix-b", domain: "lab.local", recv: make(chan struct{})}
	key := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "access-udp",
		Transport:  transport.ProtocolUDP,
		Address:    reverseSessionAddress,
		Encryption: "secure",
	}
	daemon.dataSessions[key] = session
	daemon.dataSessionState[key] = &dataSessionRuntime{
		key:      key,
		session:  session,
		endpoint: desired.Endpoints[0],
	}
	now := time.Now().UTC()
	grants := []endpointGrantPayload{
		{
			IssuerIX:    desired.IX.ID,
			SubjectIX:   "ix-b",
			Endpoint:    "access-udp",
			Transport:   "udp",
			State:       endpointGrantStateRevoked,
			Permissions: []string{endpointGrantPermissionDataSession},
		},
		{
			IssuerIX:    desired.IX.ID,
			SubjectIX:   "ix-b",
			Endpoint:    "access-udp",
			Transport:   "udp",
			State:       endpointGrantStateActive,
			Permissions: []string{endpointGrantPermissionDataSession},
			ExpiresAt:   now.Add(time.Hour),
		},
	}
	localEndpoints := map[core.EndpointID]config.EndpointConfig{"access-udp": desired.Endpoints[0]}

	dropped, err := daemon.dropDataSessionsUnauthorizedByEndpointGrantPolicySnapshot(now, grants, localEndpoints, nil)
	if err != nil {
		t.Fatalf("grant cleanup: %v", err)
	}
	if dropped != 0 {
		t.Fatalf("dropped sessions = %d, want 0", dropped)
	}
	if session.closed.Load() {
		t.Fatal("session with another active grant was closed")
	}
}

type failingEndpointGrantStore struct{}

func (failingEndpointGrantStore) Append(configlog.Event) error {
	return errors.New("failing endpoint grant store is read-only")
}

func (failingEndpointGrantStore) AppendBatch([]configlog.Event) error {
	return errors.New("failing endpoint grant store is read-only")
}

func (failingEndpointGrantStore) ReplaceAll([]configlog.Event) error {
	return errors.New("failing endpoint grant store is read-only")
}

func (failingEndpointGrantStore) Head() (configlog.Head, error) {
	return configlog.Head{Seq: 1, Hash: "unreadable"}, nil
}

func (failingEndpointGrantStore) Range(uint64, uint64) ([]configlog.Event, error) {
	return nil, errors.New("failing endpoint grant store range")
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
