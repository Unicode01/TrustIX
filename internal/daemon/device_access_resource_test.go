package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/pki"
	"trustix.local/trustix/internal/routing"
	rstate "trustix.local/trustix/internal/runtime"
	"trustix.local/trustix/internal/transport"
	securetransport "trustix.local/trustix/internal/transport/secure"
)

func TestDeviceAccessListShowAndRevoke(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemon := newConfigApplyTestDaemon(t, deviceAccessDesiredForResourceTest(pkiSet))
	session := &deviceIdentitySession{
		identity: transport.PeerIdentity{
			Role:            string(pki.RoleDevice),
			Peer:            "ix-a",
			Domain:          "lab.local",
			Device:          "laptop-1",
			CertFingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		recv: make(chan struct{}),
	}
	registerResourceTestDeviceSession(t, daemon, session)

	listRecorder := httptest.NewRecorder()
	daemon.handler().ServeHTTP(listRecorder, httptest.NewRequest(http.MethodGet, "/v1/device-access", nil))
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", listRecorder.Code, listRecorder.Body.String())
	}
	var list deviceAccessListResponse
	if err := json.Unmarshal(listRecorder.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if !list.Enabled || list.Counts.Leased != 1 || list.Counts.Online != 1 || len(list.Leases) != 1 {
		t.Fatalf("device access list = %#v", list)
	}
	lease := list.Leases[0]
	if lease.Device != "laptop-1" || lease.Address != "10.0.0.240" || lease.CertFingerprint != session.identity.CertFingerprint || !lease.Online {
		t.Fatalf("lease response = %#v", lease)
	}

	showRecorder := httptest.NewRecorder()
	daemon.handler().ServeHTTP(showRecorder, httptest.NewRequest(http.MethodGet, "/v1/device-access/laptop-1", nil))
	if showRecorder.Code != http.StatusOK {
		t.Fatalf("show status = %d body=%s", showRecorder.Code, showRecorder.Body.String())
	}

	revokeBody := mustJSON(t, deviceAccessRevokeRequest{Device: "laptop-1"})
	revokeRequest := httptest.NewRequest(http.MethodPost, "/v1/device-access/revoke", bytes.NewReader(revokeBody))
	revokeRequest.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, revokeRequest, revokeBody, pkiSet.adminCert, pkiSet.adminKey)
	revokeRecorder := httptest.NewRecorder()
	daemon.handler().ServeHTTP(revokeRecorder, revokeRequest)
	if revokeRecorder.Code != http.StatusOK {
		t.Fatalf("revoke status = %d body=%s", revokeRecorder.Code, revokeRecorder.Body.String())
	}
	var revoke deviceAccessRevokeResponse
	if err := json.Unmarshal(revokeRecorder.Body.Bytes(), &revoke); err != nil {
		t.Fatalf("decode revoke: %v", err)
	}
	if revoke.Fingerprint != session.identity.CertFingerprint || revoke.DroppedSessions != 1 || !revoke.Changed {
		t.Fatalf("revoke response = %#v", revoke)
	}
	if !session.closed {
		t.Fatal("device session was not closed")
	}
	if len(daemon.deviceLeases) != 0 {
		t.Fatalf("device leases after revoke = %#v, want none", daemon.deviceLeases)
	}
	if route, ok := routeByPrefix(daemon.runtimeRoutes(), "10.0.0.240/32"); ok && route.Source == "device_access" {
		t.Fatalf("device route still exists after revoke: %#v", route)
	}
	if len(daemon.desired.Trust.RevokedCertFingerprints) != 1 || daemon.desired.Trust.RevokedCertFingerprints[0] != session.identity.CertFingerprint {
		t.Fatalf("revoked fingerprints = %#v", daemon.desired.Trust.RevokedCertFingerprints)
	}
}

func TestTrustRevokeDropsDeviceAccessSession(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemon := newConfigApplyTestDaemon(t, deviceAccessDesiredForResourceTest(pkiSet))
	session := &deviceIdentitySession{
		identity: transport.PeerIdentity{
			Role:            string(pki.RoleDevice),
			Peer:            "ix-a",
			Domain:          "lab.local",
			Device:          "laptop-1",
			CertFingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
		recv: make(chan struct{}),
	}
	registerResourceTestDeviceSession(t, daemon, session)

	body := mustJSON(t, trustFingerprintRequest{Fingerprint: session.identity.CertFingerprint})
	request := httptest.NewRequest(http.MethodPost, "/v1/trust/revoke", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, request, body, pkiSet.adminCert, pkiSet.adminKey)
	recorder := httptest.NewRecorder()
	daemon.handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("trust revoke status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if !session.closed {
		t.Fatal("device session was not closed by trust revoke")
	}
	if len(daemon.deviceLeases) != 0 {
		t.Fatalf("device leases after trust revoke = %#v, want none", daemon.deviceLeases)
	}
}

func TestDeviceAccessRevokeRequiresAdminAuth(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemon := newConfigApplyTestDaemon(t, deviceAccessDesiredForResourceTest(pkiSet))
	daemon.cfg.APIAdminAuth = true
	session := &deviceIdentitySession{
		identity: transport.PeerIdentity{
			Role:            string(pki.RoleDevice),
			Peer:            "ix-a",
			Domain:          "lab.local",
			Device:          "laptop-1",
			CertFingerprint: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		},
		recv: make(chan struct{}),
	}
	registerResourceTestDeviceSession(t, daemon, session)

	body := mustJSON(t, deviceAccessRevokeRequest{Device: "laptop-1"})
	request := httptest.NewRequest(http.MethodPost, "/v1/device-access/revoke", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	daemon.handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned revoke status = %d, want %d; body=%s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
	}
	if session.closed {
		t.Fatal("unsigned revoke closed the device session")
	}
	if len(daemon.deviceLeases) != 1 {
		t.Fatalf("device leases after unsigned revoke = %#v, want one", daemon.deviceLeases)
	}
}

func TestDeviceAccessIssueRequiresAdminProofAndReturnsBundle(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := deviceAccessDesiredWithIssuerForResourceTest(t, pkiSet)
	desired.Endpoints[0].Address = "203.0.113.10:7000"
	daemon := newConfigApplyTestDaemon(t, desired)
	daemon.cfg.APIAdminAuth = true

	body := mustJSON(t, deviceAccessIssueRequest{
		Device:            "laptop-2",
		Endpoint:          "access-udp",
		TTL:               "1h",
		AdvertisePrefixes: []string{"10.77.0.7/24"},
		BootstrapRoutes:   []string{"10.0.1.99/24"},
	})
	unsigned := httptest.NewRequest(http.MethodPost, "/v1/device-access/issue", bytes.NewReader(body))
	unsigned.Header.Set("Content-Type", "application/json")
	unsignedRecorder := httptest.NewRecorder()
	daemon.handler().ServeHTTP(unsignedRecorder, unsigned)
	if unsignedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned issue status = %d, want %d; body=%s", unsignedRecorder.Code, http.StatusUnauthorized, unsignedRecorder.Body.String())
	}

	signed := httptest.NewRequest(http.MethodPost, "/v1/device-access/issue", bytes.NewReader(body))
	signed.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, signed, body, pkiSet.adminCert, pkiSet.adminKey)
	recorder := httptest.NewRecorder()
	daemon.handler().ServeHTTP(recorder, signed)
	if recorder.Code != http.StatusOK {
		t.Fatalf("issue status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var response deviceAccessIssueResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode issue response: %v", err)
	}
	if response.Device != "laptop-2" || response.Fingerprint == "" || response.CertificatePEM == "" || response.PrivateKeyPEM == "" {
		t.Fatalf("issue response missing bundle fields: %#v", response)
	}
	if len(response.TrustRootsPEM) == 0 {
		t.Fatal("issue response has no trust roots")
	}
	for index, root := range response.TrustRootsPEM {
		if _, err := pki.ParseCertificatePEM([]byte(root)); err != nil {
			t.Fatalf("parse response trust root %d: %v", index, err)
		}
	}
	if response.ClientConfig.Endpoint.Address != "203.0.113.10:7000" || response.ClientConfig.Endpoint.Name != "access-udp" {
		t.Fatalf("client endpoint config = %#v", response.ClientConfig.Endpoint)
	}
	if got := response.ClientConfig.Interface.BootstrapRoutes; len(got) != 1 || got[0] != "10.0.1.0/24" {
		t.Fatalf("client bootstrap routes = %#v", got)
	}
	certs, err := pki.ParseCertificatesPEM([]byte(response.CertificatePEM))
	if err != nil {
		t.Fatalf("parse issued certificate: %v", err)
	}
	meta := pki.ParseMetadata(certs[0])
	if len(meta.Prefixes) != 1 || meta.Prefixes[0] != "10.77.0.0/24" {
		t.Fatalf("issued device prefixes = %#v", meta.Prefixes)
	}
	if response.ClientConfigJSON == "" {
		t.Fatal("client config json is empty")
	}
}

func TestDeviceAccessIssueEndpointOverrideAllowsDomainPort(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := deviceAccessDesiredWithIssuerForResourceTest(t, pkiSet)
	daemon := newConfigApplyTestDaemon(t, desired)

	response, err := daemon.issueDeviceAccessCertificate(deviceAccessIssueRequest{
		Device:          "router-2",
		Endpoint:        "access-udp",
		EndpointAddress: "router-ddns.example.net:7000",
	})
	if err != nil {
		t.Fatalf("issue device access certificate: %v", err)
	}
	if response.ClientConfig.Endpoint.Address != "router-ddns.example.net:7000" || response.ClientConfig.Endpoint.Name != "access-udp" {
		t.Fatalf("client endpoint config = %#v", response.ClientConfig.Endpoint)
	}
}

func TestDeviceAccessIssueAllowsDelegatedLocalLANSubprefix(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := deviceAccessDesiredWithIssuerForResourceTest(t, pkiSet)
	daemon := newConfigApplyTestDaemon(t, desired)

	response, err := daemon.issueDeviceAccessCertificate(deviceAccessIssueRequest{
		Device:            "router-3",
		Endpoint:          "access-udp",
		EndpointAddress:   "203.0.113.10:7000",
		AdvertisePrefixes: []string{"10.0.0.0/25"},
	})
	if err != nil {
		t.Fatalf("issue device access certificate: %v", err)
	}
	certs, err := pki.ParseCertificatesPEM([]byte(response.CertificatePEM))
	if err != nil {
		t.Fatalf("parse issued certificate: %v", err)
	}
	meta := pki.ParseMetadata(certs[0])
	if len(meta.Prefixes) != 1 || meta.Prefixes[0] != "10.0.0.0/25" {
		t.Fatalf("issued device prefixes = %#v", meta.Prefixes)
	}
}

func TestDeviceAccessIssueRejectsAdvertisePrefixConflict(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := deviceAccessDesiredWithIssuerForResourceTest(t, pkiSet)
	daemon := newConfigApplyTestDaemon(t, desired)

	_, err := daemon.issueDeviceAccessCertificate(deviceAccessIssueRequest{
		Device:            "router-3",
		Endpoint:          "access-udp",
		AdvertisePrefixes: []string{"10.0.0.128/25"},
	})
	if err == nil {
		t.Fatal("expected advertise prefix conflict")
	}
}

func TestDeviceAccessIssueRejectsAdvertisePrefixOutsideExportPolicy(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := deviceAccessDesiredWithIssuerForResourceTest(t, pkiSet)
	desired.RoutePolicy.ExportPrefixes = []core.Prefix{"10.77.0.0/16"}
	daemon := newConfigApplyTestDaemon(t, desired)

	_, err := daemon.issueDeviceAccessCertificate(deviceAccessIssueRequest{
		Device:            "router-4",
		Endpoint:          "access-udp",
		AdvertisePrefixes: []string{"10.88.0.0/24"},
	})
	if err == nil {
		t.Fatal("expected export policy rejection")
	}
}

func deviceAccessDesiredWithIssuerForResourceTest(t *testing.T, pkiSet membershipPKI) config.Desired {
	t.Helper()
	desired := deviceAccessDesiredForResourceTest(pkiSet)
	out := t.TempDir()
	root, err := pki.LoadBundle(filepath.Join(filepath.Dir(pkiSet.trustRoots[0]), "domain-ca.pem"), filepath.Join(filepath.Dir(pkiSet.trustRoots[0]), "domain-ca.key"))
	if err != nil {
		t.Fatalf("load domain ca: %v", err)
	}
	ixCA, err := pki.Issue(root, pki.IssueRequest{
		CommonName: "TrustIX Test IX CA",
		Role:       pki.RoleIX,
		Domain:     string(desired.Domain.ID),
		IX:         string(desired.IX.ID),
		IsCA:       true,
		NotAfter:   time.Now().AddDate(1, 0, 0),
	})
	if err != nil {
		t.Fatalf("issue ix ca: %v", err)
	}
	if err := pki.WriteBundle(out, "ix-a-device-issuer", ixCA, true); err != nil {
		t.Fatalf("write ix ca: %v", err)
	}
	desired.IX.CertPath = filepath.Join(out, "ix-a-device-issuer.crt")
	desired.IX.KeyPath = filepath.Join(out, "ix-a-device-issuer.key")
	return desired
}

func deviceAccessDesiredForResourceTest(pkiSet membershipPKI) config.Desired {
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	desired.LAN.DeviceAccess = config.DeviceAccessConfig{
		Enabled:     true,
		AddressPool: "10.0.0.240/28",
		LeaseTTL:    "1h",
	}
	desired.Endpoints = []config.EndpointConfig{{
		Name:       core.EndpointID("access-udp"),
		Mode:       config.EndpointModePassive,
		Transport:  "udp",
		Enabled:    true,
		EnabledSet: true,
	}}
	desired.TransportPolicy.Encryption = securetransport.EncryptionSecure
	return desired
}

func registerResourceTestDeviceSession(t *testing.T, daemon *Daemon, session *deviceIdentitySession) {
	t.Helper()
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
	if daemon.deviceLeases == nil {
		daemon.deviceLeases = make(map[deviceLeaseKey]deviceAccessLease)
	}
	if daemon.endpointState == nil {
		daemon.endpointState = make(map[endpointStateKey]rstate.EndpointState)
	}
	session.stats = transport.TransportStats{BytesSent: 7, BytesReceived: 11, PacketsSent: 1, PacketsReceived: 2}
	runtime, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{
		Name:      core.EndpointID("access-udp"),
		Transport: transport.ProtocolUDP,
	}, session)
	if err != nil {
		t.Fatalf("register device session: %v", err)
	}
	now := time.Now().UTC().UnixNano()
	runtime.lastUp.Store(now)
	runtime.lastRX.Store(now)
	runtime.lastTX.Store(now)
}
