package daemon

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/pki"
	securetransport "trustix.local/trustix/internal/transport/secure"
)

func TestIXProvisionIssueCreatesOneTimeBootstrapAndAdmission(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	desired.IX.ControlAPI = "https://ix-a.example.com:9443"
	daemon := newConfigApplyTestDaemon(t, desired)
	daemon.cfg.APIAdminAuth = true

	certDir := filepath.Dir(pkiSet.trustRoots[0])
	body := mustJSON(t, ixProvisionIssueRequest{
		IXID:                "ix-d",
		ControlAPI:          "https://ix-d.example.com:9443",
		Advertise:           []core.Prefix{"10.9.0.0/24"},
		EndpointAddress:     "ix-d.example.com:7000",
		LANIface:            "trustix-lan0",
		LANGateway:          "10.9.0.1/24",
		BootstrapControlAPI: "https://ix-a.example.com:9443",
		ProvisionURL:        "https://ix-a.example.com:18787",
		TTL:                 "10m",
		DomainCACert:        filepath.Join(certDir, "domain-ca.pem"),
		DomainCAKey:         filepath.Join(certDir, "domain-ca.key"),
		ConfigCACert:        filepath.Join(certDir, "config-ca.pem"),
		ConfigCAKey:         filepath.Join(certDir, "config-ca.key"),
		TrustRoots:          pkiSet.trustRoots,
	})
	unsigned := httptest.NewRequest(http.MethodPost, "/v1/provision/ix", bytes.NewReader(body))
	unsigned.Header.Set("Content-Type", "application/json")
	unsignedRecorder := httptest.NewRecorder()
	daemon.handler().ServeHTTP(unsignedRecorder, unsigned)
	if unsignedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned provision status = %d, want %d; body=%s", unsignedRecorder.Code, http.StatusUnauthorized, unsignedRecorder.Body.String())
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/provision/ix", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, request, body, pkiSet.adminCert, pkiSet.adminKey)
	recorder := httptest.NewRecorder()
	daemon.handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("provision status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if cacheControl := recorder.Header().Get("Cache-Control"); cacheControl != "no-store" {
		t.Fatalf("cache-control = %q, want no-store", cacheControl)
	}
	var response ixProvisionIssueResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Token == "" || response.Command == "" || response.IXCertFingerprint == "" || len(response.RouteAuthFingerprints) != 1 {
		t.Fatalf("response missing fields: %#v", response)
	}
	if strings.Contains(response.Command, "domain-ca.key") || strings.Contains(response.Command, "config-ca.key") {
		t.Fatalf("provision command leaks CA key paths: %s", response.Command)
	}
	if !strings.Contains(response.Command, "--provision-url") || !strings.Contains(response.Command, "--token") {
		t.Fatalf("provision command does not use token mode: %s", response.Command)
	}

	daemon.configMu.RLock()
	admission, ok, err := daemon.latestAdmissionForIXLocked("ix-d")
	daemon.configMu.RUnlock()
	if err != nil || !ok {
		t.Fatalf("latest admission for ix-d ok=%t err=%v", ok, err)
	}
	if admission.IXCertFingerprint != response.IXCertFingerprint || len(admission.AllowedPrefixes) != 1 || admission.AllowedPrefixes[0] != "10.9.0.0/24" {
		t.Fatalf("admission = %#v", admission)
	}

	consume := httptest.NewRequest(http.MethodGet, "/v1/provision/ix/"+response.Token+"/bootstrap.sh", nil)
	consumeRecorder := httptest.NewRecorder()
	daemon.handler().ServeHTTP(consumeRecorder, consume)
	if consumeRecorder.Code != http.StatusOK {
		t.Fatalf("consume status = %d body=%s", consumeRecorder.Code, consumeRecorder.Body.String())
	}
	if consumeRecorder.Header().Get("X-Content-Type-Options") != "nosniff" ||
		consumeRecorder.Header().Get("X-Frame-Options") != "DENY" ||
		!strings.Contains(consumeRecorder.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("bootstrap security headers = %#v", consumeRecorder.Header())
	}
	script := consumeRecorder.Body.String()
	if !strings.Contains(script, "PRIVATE KEY") || !strings.Contains(script, `"id": "ix-d"`) || strings.Contains(script, "domain-ca.key") {
		t.Fatalf("unexpected bootstrap script:\n%s", script)
	}
	if !strings.Contains(script, `"warmup": true`) {
		t.Fatalf("bootstrap script did not enable session warmup:\n%s", script)
	}
	if !strings.Contains(script, "txqueuelen 1000 up") {
		t.Fatalf("bootstrap script does not set a nonzero managed LAN tx queue length:\n%s", script)
	}
	if _, err := pki.ParseCertificatePEM([]byte(extractFirstPEMBlock(t, script, "CERTIFICATE"))); err != nil {
		t.Fatalf("script does not contain a parseable certificate: %v", err)
	}

	again := httptest.NewRequest(http.MethodGet, "/v1/provision/ix/"+response.Token+"/bootstrap.sh", nil)
	againRecorder := httptest.NewRecorder()
	daemon.handler().ServeHTTP(againRecorder, again)
	if againRecorder.Code != http.StatusGone {
		t.Fatalf("second consume status = %d, want %d; body=%s", againRecorder.Code, http.StatusGone, againRecorder.Body.String())
	}
}

func TestIXProvisionMinimalRequestDerivesUsableDefaults(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	request, prefixes, err := normalizeIXProvisionIssueRequest(ixProvisionIssueRequest{
		IXID:            "ix-e",
		Advertise:       []core.Prefix{"10.42.0.0/24"},
		EndpointAddress: "ix-e.example.com",
		ProvisionURL:    "https://ix-a.example.com:18787",
	}, desired)
	if err != nil {
		t.Fatalf("normalize provision request: %v", err)
	}
	if request.Role != "public_ix" || request.Profile != "stable" {
		t.Fatalf("role/profile = %q/%q, want public_ix/stable", request.Role, request.Profile)
	}
	if request.ControlAPI != "https://ix-e.example.com:9443" {
		t.Fatalf("control_api = %q, want derived https endpoint", request.ControlAPI)
	}
	if request.EndpointAddress != "ix-e.example.com:7000" || request.EndpointListen != "0.0.0.0:7000" {
		t.Fatalf("endpoint = %q listen %q, want ix-e.example.com:7000 / 0.0.0.0:7000", request.EndpointAddress, request.EndpointListen)
	}
	if request.EndpointTransport != "udp" || request.EndpointName != "ix-e-udp" {
		t.Fatalf("endpoint transport/name = %q/%q, want udp/ix-e-udp", request.EndpointTransport, request.EndpointName)
	}
	if request.LANIface != "trustix-ix-e" || request.LANGateway != "10.42.0.1/24" {
		t.Fatalf("lan defaults iface=%q gateway=%q, want trustix-ix-e / 10.42.0.1/24", request.LANIface, request.LANGateway)
	}
	target, err := desiredForIXProvision(request, prefixes, []ixProvisionTrustRootFile{{Name: "root.pem", PEM: "unused"}})
	if err != nil {
		t.Fatalf("desired for provision: %v", err)
	}
	if target.TransportPolicy.Encryption != securetransport.EncryptionSecure ||
		target.TransportPolicy.Profile != config.TransportProfileStable ||
		target.TransportPolicy.KernelTransport.Mode != "auto" {
		t.Fatalf("target transport policy = %#v", target.TransportPolicy)
	}
	if len(target.Endpoints) != 2 ||
		target.Endpoints[0].Name != "ix-e-udp" ||
		target.Endpoints[0].Transport != "udp" ||
		target.Endpoints[0].Priority <= target.Endpoints[1].Priority ||
		target.Endpoints[1].Name != "ix-e-experimental_tcp" ||
		target.Endpoints[1].Transport != "experimental_tcp" {
		t.Fatalf("target endpoints = %#v, want udp primary and experimental_tcp secondary", target.Endpoints)
	}
	if len(target.TransportPolicy.Candidates) != 2 ||
		target.TransportPolicy.Candidates[0] != "ix-e-udp" ||
		target.TransportPolicy.Candidates[1] != "ix-e-experimental_tcp" {
		t.Fatalf("transport candidates = %#v, want udp then experimental_tcp", target.TransportPolicy.Candidates)
	}
	if len(target.TransportPolicy.Profiles) != 1 ||
		target.TransportPolicy.Profiles[0].Transport != "experimental_tcp" ||
		target.TransportPolicy.Profiles[0].Advanced.BatchBytes != dataSessionBatchDefaultBytes ||
		target.TransportPolicy.Profiles[0].Advanced.FlushDelay != "25us" ||
		target.TransportPolicy.Profiles[0].Advanced.MaxFrames != dataSessionBatchMaxPackets {
		t.Fatalf("experimental_tcp profile = %#v, want fixed ackless batching profile", target.TransportPolicy.Profiles)
	}
	if target.Policies[0].LoadBalance == "least_conn" {
		t.Fatalf("generated default policy uses least_conn, want priority-ordered fallback")
	}
}

func TestIXProvisionNonTransitRequiresAdvertisedPrefix(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	_, _, err := normalizeIXProvisionIssueRequest(ixProvisionIssueRequest{
		IXID:            "ix-empty",
		Role:            "public_ix",
		EndpointAddress: "ix-empty.example.com:7000",
		ProvisionURL:    "https://ix-a.example.com:18787",
	}, desired)
	if err == nil || !strings.Contains(err.Error(), "advertise must contain at least one CIDR prefix") {
		t.Fatalf("normalize error = %v, want advertise requirement", err)
	}
}

func TestIXProvisionTransitAllowsNoAdvertisedPrefixes(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	desired.IX.ControlAPI = "https://ix-a.example.com:9443"
	daemon := newConfigApplyTestDaemon(t, desired)
	daemon.cfg.APIAdminAuth = true

	certDir := filepath.Dir(pkiSet.trustRoots[0])
	body := mustJSON(t, ixProvisionIssueRequest{
		IXID:                "ix-transit",
		Role:                "transit_ix",
		EndpointMode:        "active",
		BootstrapControlAPI: "https://ix-a.example.com:9443",
		ProvisionURL:        "https://ix-a.example.com:18787",
		DomainCACert:        filepath.Join(certDir, "domain-ca.pem"),
		DomainCAKey:         filepath.Join(certDir, "domain-ca.key"),
		ConfigCACert:        filepath.Join(certDir, "config-ca.pem"),
		ConfigCAKey:         filepath.Join(certDir, "config-ca.key"),
		TrustRoots:          pkiSet.trustRoots,
	})
	request := httptest.NewRequest(http.MethodPost, "/v1/provision/ix", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	signAdminTestRequest(t, request, body, pkiSet.adminCert, pkiSet.adminKey)
	recorder := httptest.NewRecorder()
	daemon.handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("provision status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var response ixProvisionIssueResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.RouteAuthFingerprints) != 0 || len(response.Admission.RouteAuthFingerprints) != 0 || len(response.Admission.AllowedPrefixes) != 0 {
		t.Fatalf("transit response should not issue route authorization: %#v", response)
	}

	consume := httptest.NewRequest(http.MethodGet, "/v1/provision/ix/"+response.Token+"/bootstrap.sh", nil)
	consumeRecorder := httptest.NewRecorder()
	daemon.handler().ServeHTTP(consumeRecorder, consume)
	if consumeRecorder.Code != http.StatusOK {
		t.Fatalf("consume status = %d body=%s", consumeRecorder.Code, consumeRecorder.Body.String())
	}
	script := consumeRecorder.Body.String()
	if strings.Contains(script, "-route.crt") || strings.Contains(script, "ROUTE_AUTH") {
		t.Fatalf("transit bootstrap script contains route authorization material:\n%s", script)
	}
	if strings.Contains(script, `"advertise": [
      "`) {
		t.Fatalf("transit bootstrap script should not advertise a local prefix by default:\n%s", script)
	}
}

func TestIXProvisionOpenWRTDNSMasqAndServiceManager(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	request, prefixes, err := normalizeIXProvisionIssueRequest(ixProvisionIssueRequest{
		IXID:            "ix-openwrt",
		Advertise:       []core.Prefix{"10.52.0.0/24"},
		EndpointAddress: "router.example.com:7000",
		ProvisionURL:    "https://ix-a.example.com:18787",
		ServiceManager:  "openwrt",
		DNSDomain:       "Trust.IX.",
		OpenWRTDNSMasq:  "1",
	}, desired)
	if err != nil {
		t.Fatalf("normalize provision request: %v", err)
	}
	if request.ServiceManager != "openwrt" || request.DNSEnabled != "1" || request.OpenWRTDNSMasq != "1" || request.DNSDomain != "trust.ix" {
		t.Fatalf("normalized OpenWrt DNS request = %#v", request)
	}
	target, err := desiredForIXProvision(request, prefixes, []ixProvisionTrustRootFile{{Name: "root.pem", PEM: "unused"}})
	if err != nil {
		t.Fatalf("desired for provision: %v", err)
	}
	if !target.DNS.Enabled || !target.DNS.DNSMasq.Enabled || target.DNS.Domain != "trust.ix" {
		t.Fatalf("target DNS = %#v", target.DNS)
	}
	script, err := ixProvisionBootstrapScript(ixProvisionScriptInput{
		IXID:           request.IXID,
		ConfigJSON:     `{"dns":{"enabled":true,"dnsmasq":{"enabled":true}}}`,
		CertificatePEM: "CERT",
		PrivateKeyPEM:  "KEY",
		RouteAuthPEM:   "ROUTE",
		TargetCertDir:  request.TargetCertDir,
		APIAddr:        request.APIAddr,
		PeerAPIAddr:    request.PeerAPIAddr,
		Dataplane:      request.Dataplane,
		ServiceManager: request.ServiceManager,
		BuildBPF:       request.BuildBPF,
		BuildKO:        request.BuildKO,
		BuildWebUI:     request.BuildWebUI,
	})
	if err != nil {
		t.Fatalf("bootstrap script: %v", err)
	}
	if !strings.Contains(script, "--service-manager 'openwrt'") {
		t.Fatalf("bootstrap script does not force OpenWrt service manager:\n%s", script)
	}
}

func TestIXProvisionProfileControlsGeneratedTransportPolicy(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	request, prefixes, err := normalizeIXProvisionIssueRequest(ixProvisionIssueRequest{
		IXID:            "ix-lab",
		Role:            "lab-ix",
		Profile:         "plaintext-performance",
		Advertise:       []core.Prefix{"10.77.0.0/24"},
		EndpointAddress: "ix-lab.example.com:7007",
		ProvisionURL:    "https://ix-a.example.com:18787",
	}, desired)
	if err != nil {
		t.Fatalf("normalize provision request: %v", err)
	}
	if request.Role != "lab_ix" || request.Profile != "plaintext_performance" {
		t.Fatalf("role/profile = %q/%q, want lab_ix/plaintext_performance", request.Role, request.Profile)
	}
	target, err := desiredForIXProvision(request, prefixes, []ixProvisionTrustRootFile{{Name: "root.pem", PEM: "unused"}})
	if err != nil {
		t.Fatalf("desired for provision: %v", err)
	}
	if len(target.Endpoints) != 2 {
		t.Fatalf("target endpoints = %#v, want udp plus experimental_tcp fallback", target.Endpoints)
	}
	if target.TransportPolicy.Encryption != securetransport.EncryptionPlaintext ||
		target.TransportPolicy.Profile != config.TransportProfilePerformance ||
		target.TransportPolicy.Datapath != config.TransportDatapathKernelModule ||
		target.Endpoints[0].Security.Encryption != securetransport.EncryptionPlaintext {
		t.Fatalf("target plaintext performance policy endpoint=%#v policy=%#v", target.Endpoints[0], target.TransportPolicy)
	}
}

func TestIXProvisionEdgeActiveOnlyDoesNotPublishControlAPI(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	desired.IX.ControlAPI = "https://ix-a.example.com:9443"
	request, prefixes, err := normalizeIXProvisionIssueRequest(ixProvisionIssueRequest{
		IXID:                "ix-edge",
		Role:                "edge_ix",
		EndpointMode:        "active",
		Advertise:           []core.Prefix{"10.88.0.0/24"},
		BootstrapControlAPI: "https://ix-a.example.com:9443",
		ProvisionURL:        "https://ix-a.example.com:18787",
	}, desired)
	if err != nil {
		t.Fatalf("normalize provision request: %v", err)
	}
	if request.ControlAPI != "" {
		t.Fatalf("control_api = %q, want empty for active-only edge", request.ControlAPI)
	}
	if request.EndpointAddress != "ix-a.example.com:7000" {
		t.Fatalf("endpoint_address = %q, want derived upstream data endpoint", request.EndpointAddress)
	}
	if request.EndpointMode != "active" || request.EndpointListen != "" {
		t.Fatalf("endpoint mode/listen = %q/%q, want active without listen", request.EndpointMode, request.EndpointListen)
	}
	target, err := desiredForIXProvision(request, prefixes, []ixProvisionTrustRootFile{{Name: "root.pem", PEM: "unused"}})
	if err != nil {
		t.Fatalf("desired for provision: %v", err)
	}
	if target.IX.ControlAPI != "" || target.IX.ControlAPIPublish != "disabled" {
		t.Fatalf("target ix control api = %q publish=%q, want empty/disabled", target.IX.ControlAPI, target.IX.ControlAPIPublish)
	}
	if len(target.Endpoints) != 2 ||
		target.Endpoints[0].Mode != config.EndpointModeActive ||
		target.Endpoints[0].Transport != "udp" ||
		target.Endpoints[0].Address != "ix-a.example.com:7000" ||
		target.Endpoints[0].Listen != "" ||
		target.Endpoints[1].Mode != config.EndpointModeActive ||
		target.Endpoints[1].Transport != "experimental_tcp" ||
		target.Endpoints[1].Address != "ix-a.example.com:7000" ||
		target.Endpoints[1].Listen != "" {
		t.Fatalf("target endpoint = %#v, want active dial to upstream", target.Endpoints)
	}
	if len(target.Bootstrap.Peers) != 1 || target.Bootstrap.Peers[0].ControlAPI != "https://ix-a.example.com:9443" {
		t.Fatalf("bootstrap peers = %#v", target.Bootstrap.Peers)
	}
}

func extractFirstPEMBlock(t *testing.T, script, blockType string) string {
	t.Helper()
	start := "-----BEGIN " + blockType + "-----"
	end := "-----END " + blockType + "-----"
	startIndex := strings.Index(script, start)
	if startIndex < 0 {
		t.Fatalf("missing PEM start %q", start)
	}
	endIndex := strings.Index(script[startIndex:], end)
	if endIndex < 0 {
		t.Fatalf("missing PEM end %q", end)
	}
	endIndex += startIndex + len(end)
	return script[startIndex:endIndex] + "\n"
}
