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
	if strings.Contains(response.Command, "\n") || strings.Contains(response.Command, "\\\n") {
		t.Fatalf("provision command should be a single physical line: %s", response.Command)
	}
	if len(response.Command) > 700 {
		t.Fatalf("provision command is too long for reliable paste: len=%d command=%s", len(response.Command), response.Command)
	}
	if !strings.Contains(response.Command, ixProvisionBootstrapClientPath) {
		t.Fatalf("provision command does not fetch bootstrap client from control API: %s", response.Command)
	}
	if strings.Contains(response.Command, "for url in") || strings.Contains(response.Command, "raw.githubusercontent.com/Unicode01/TrustIX") {
		t.Fatalf("provision command still expands GitHub mirror fallback inline: %s", response.Command)
	}

	client := httptest.NewRequest(http.MethodGet, ixProvisionBootstrapClientPath, nil)
	clientRecorder := httptest.NewRecorder()
	daemon.handler().ServeHTTP(clientRecorder, client)
	if clientRecorder.Code != http.StatusOK {
		t.Fatalf("bootstrap client status = %d body=%s", clientRecorder.Code, clientRecorder.Body.String())
	}
	if clientRecorder.Header().Get("X-Content-Type-Options") != "nosniff" ||
		clientRecorder.Header().Get("X-Frame-Options") != "DENY" ||
		!strings.Contains(clientRecorder.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("bootstrap client security headers = %#v", clientRecorder.Header())
	}
	clientScript := clientRecorder.Body.String()
	if !strings.Contains(clientScript, "TrustIX/archive") ||
		!strings.Contains(clientScript, "opkg install bash") ||
		!strings.Contains(clientScript, "--provision-url") ||
		!strings.Contains(clientScript, "--token") {
		t.Fatalf("bootstrap client does not contain source fetch/token runner logic:\n%s", clientScript)
	}
	if strings.Contains(clientScript, response.Token) || strings.Contains(clientScript, "PRIVATE KEY") {
		t.Fatalf("bootstrap client should not contain token-specific secret material:\n%s", clientScript)
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
	if request.Role != "public_ix" || request.Profile != "plaintext_performance" {
		t.Fatalf("role/profile = %q/%q, want public_ix/plaintext_performance", request.Role, request.Profile)
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
	if target.TransportPolicy.Encryption != securetransport.EncryptionPlaintext ||
		target.TransportPolicy.Profile != config.TransportProfilePerformance ||
		target.TransportPolicy.Datapath != config.TransportDatapathKernelModule ||
		target.TransportPolicy.KernelTransport.Mode != "auto" {
		t.Fatalf("target transport policy = %#v", target.TransportPolicy)
	}
	if len(target.Endpoints) != 1 ||
		target.Endpoints[0].Name != "ix-e-udp" ||
		target.Endpoints[0].Transport != "udp" ||
		target.Endpoints[0].Security.Encryption != securetransport.EncryptionPlaintext {
		t.Fatalf("target endpoints = %#v, want udp plaintext performance primary", target.Endpoints)
	}
	if len(target.TransportPolicy.Candidates) != 1 ||
		target.TransportPolicy.Candidates[0] != "ix-e-udp" {
		t.Fatalf("transport candidates = %#v, want udp", target.TransportPolicy.Candidates)
	}
	if len(target.TransportPolicy.Profiles) != 0 {
		t.Fatalf("transport profiles = %#v, want none for experimental_tcp primary", target.TransportPolicy.Profiles)
	}
	if experimentalTCPPerformanceRouteGSOAsyncForDesired(target) {
		t.Fatalf("default provision config should prefer full-kmod plaintext over experimental_tcp route-GSO: policy=%#v endpoints=%#v", target.TransportPolicy, target.Endpoints)
	}
	if !kernelDatapathFullPlaintextEnabledForDesired(target) {
		t.Fatalf("default provision config did not enable full-kmod plaintext: policy=%#v endpoints=%#v", target.TransportPolicy, target.Endpoints)
	}
	if !target.KernelModules.Datapath.FullPlaintext ||
		!target.KernelModules.Datapath.RXWorker ||
		!target.KernelModules.Datapath.TXPlaintext ||
		target.KernelModules.Datapath.RXStage != config.KernelDatapathRXStageWorker {
		t.Fatalf("default provision config did not persist explicit full-kmod runtime: %#v", target.KernelModules.Datapath)
	}
	if target.Policies[0].LoadBalance == "least_conn" {
		t.Fatalf("generated default policy uses least_conn, want priority-ordered fallback")
	}
}

func TestIXProvisionPlaintextPerformanceIPv4DefaultsToUDPFullKmod(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	request, prefixes, err := normalizeIXProvisionIssueRequest(ixProvisionIssueRequest{
		IXID:            "ix-e",
		Advertise:       []core.Prefix{"10.42.0.0/24"},
		EndpointAddress: "198.51.100.10:7000",
		ProvisionURL:    "https://ix-a.example.com:18787",
	}, desired)
	if err != nil {
		t.Fatalf("normalize provision request: %v", err)
	}
	if request.ControlAPI != "https://198.51.100.10:9443" {
		t.Fatalf("control_api = %q, want derived IPv4 control API", request.ControlAPI)
	}
	if request.EndpointTransport != "udp" || request.EndpointName != "ix-e-udp" {
		t.Fatalf("endpoint transport/name = %q/%q, want udp/ix-e-udp", request.EndpointTransport, request.EndpointName)
	}
	if request.EndpointAddress != "198.51.100.10:7000" || request.EndpointListen != "0.0.0.0:7000" {
		t.Fatalf("endpoint = %q listen %q, want IPv4 UDP endpoint", request.EndpointAddress, request.EndpointListen)
	}
	target, err := desiredForIXProvision(request, prefixes, []ixProvisionTrustRootFile{{Name: "root.pem", PEM: "unused"}})
	if err != nil {
		t.Fatalf("desired for provision: %v", err)
	}
	if len(target.Endpoints) != 1 ||
		target.Endpoints[0].Name != "ix-e-udp" ||
		target.Endpoints[0].Transport != "udp" ||
		target.Endpoints[0].Address != "198.51.100.10:7000" ||
		target.Endpoints[0].Listen != "0.0.0.0:7000" {
		t.Fatalf("target endpoints = %#v, want UDP full-kmod plaintext performance endpoint", target.Endpoints)
	}
	if len(target.TransportPolicy.Candidates) != 1 || target.TransportPolicy.Candidates[0] != "ix-e-udp" {
		t.Fatalf("transport candidates = %#v, want udp", target.TransportPolicy.Candidates)
	}
	if experimentalTCPPerformanceRouteGSOAsyncForDesired(target) {
		t.Fatalf("target IPv4 provision config should prefer UDP full-kmod over route-GSO: policy=%#v endpoints=%#v", target.TransportPolicy, target.Endpoints)
	}
	if !kernelDatapathFullPlaintextEnabledForDesired(target) {
		t.Fatalf("target IPv4 provision config did not enable full-kmod plaintext: policy=%#v endpoints=%#v", target.TransportPolicy, target.Endpoints)
	}
}

func TestIXProvisionPlaintextPerformanceTunnelDeclarationDefaultsToNativeIPIP(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	request, _, err := normalizeIXProvisionIssueRequest(ixProvisionIssueRequest{
		IXID:            "ix-e",
		Advertise:       []core.Prefix{"10.42.0.0/24"},
		EndpointAddress: "local=198.51.100.10,mtu=1480",
		ControlAPI:      "https://198.51.100.10:9443",
		ProvisionURL:    "https://ix-a.example.com:18787",
	}, desired)
	if err != nil {
		t.Fatalf("normalize provision request: %v", err)
	}
	if request.EndpointTransport != "ipip" || request.EndpointName != "ix-e-ipip" {
		t.Fatalf("endpoint transport/name = %q/%q, want ipip/ix-e-ipip", request.EndpointTransport, request.EndpointName)
	}
	if request.EndpointAddress != "local=198.51.100.10,mtu=1480" || request.EndpointListen != "local=198.51.100.10,mtu=1480" {
		t.Fatalf("endpoint tunnel declaration = %q listen %q", request.EndpointAddress, request.EndpointListen)
	}
}

func TestIXProvisionExplicitStableKeepsSecureUDPCompatibility(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	request, prefixes, err := normalizeIXProvisionIssueRequest(ixProvisionIssueRequest{
		IXID:            "ix-stable",
		Profile:         "stable",
		Advertise:       []core.Prefix{"10.43.0.0/24"},
		EndpointAddress: "ix-stable.example.com:7000",
		ProvisionURL:    "https://ix-a.example.com:18787",
	}, desired)
	if err != nil {
		t.Fatalf("normalize provision request: %v", err)
	}
	if request.EndpointTransport != "udp" || request.EndpointName != "ix-stable-udp" {
		t.Fatalf("endpoint transport/name = %q/%q, want udp/ix-stable-udp", request.EndpointTransport, request.EndpointName)
	}
	target, err := desiredForIXProvision(request, prefixes, []ixProvisionTrustRootFile{{Name: "root.pem", PEM: "unused"}})
	if err != nil {
		t.Fatalf("desired for provision: %v", err)
	}
	if target.TransportPolicy.Encryption != securetransport.EncryptionSecure ||
		target.TransportPolicy.Profile != config.TransportProfileStable {
		t.Fatalf("target stable transport policy = %#v", target.TransportPolicy)
	}
	if len(target.Endpoints) != 2 ||
		target.Endpoints[0].Transport != "udp" ||
		target.Endpoints[1].Transport != "experimental_tcp" {
		t.Fatalf("target stable endpoints = %#v, want udp primary and experimental_tcp secondary", target.Endpoints)
	}
	if len(target.TransportPolicy.Profiles) != 1 ||
		target.TransportPolicy.Profiles[0].Transport != "experimental_tcp" ||
		target.TransportPolicy.Profiles[0].Advanced.BatchBytes != dataSessionBatchDefaultBytes ||
		target.TransportPolicy.Profiles[0].Advanced.FlushDelay != "25us" ||
		target.TransportPolicy.Profiles[0].Advanced.MaxFrames != dataSessionBatchMaxPackets {
		t.Fatalf("stable experimental_tcp profile = %#v, want fixed ackless batching profile", target.TransportPolicy.Profiles)
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
	if request.Profile != "plaintext_performance" || request.EndpointTransport != "udp" {
		t.Fatalf("normalized OpenWrt performance defaults profile=%q transport=%q, want plaintext_performance/udp", request.Profile, request.EndpointTransport)
	}
	if request.KernelModules != "auto" || request.BuildKO != "1" {
		t.Fatalf("normalized OpenWrt performance kernel modules/build_ko = %q/%q, want auto/1", request.KernelModules, request.BuildKO)
	}
	target, err := desiredForIXProvision(request, prefixes, []ixProvisionTrustRootFile{{Name: "root.pem", PEM: "unused"}})
	if err != nil {
		t.Fatalf("desired for provision: %v", err)
	}
	if target.TransportPolicy.KernelTransport.Mode != "disabled" || len(target.Endpoints) != 1 || target.Endpoints[0].Transport != "udp" {
		t.Fatalf("target OpenWrt performance defaults policy=%#v endpoints=%#v", target.TransportPolicy, target.Endpoints)
	}
	if target.KernelModules.TrustIXCrypto.Mode != "disabled" ||
		target.KernelModules.TrustIXDatapath.Mode != "required" ||
		target.KernelModules.TrustIXDatapathHelpers.Mode != "disabled" {
		t.Fatalf("target OpenWrt performance kernel module modes = %#v, want datapath required only", target.KernelModules)
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
	if !strings.Contains(script, "--env TRUSTIX_EXPERIMENTAL_TCP_COMPAT_STREAM=1") {
		t.Fatalf("bootstrap script does not enable OpenWrt experimental_tcp compat stream:\n%s", script)
	}
	for _, env := range []string{
		"--env TRUSTIX_KERNEL_UDP_TC_ONLY=1",
		"--env TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY=1",
		"--env TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO=1",
		"--env TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO=0",
		"--env TRUSTIX_KERNEL_UDP_TC_RX_ADJ_ROOM_TUNNEL_GSO=0",
	} {
		if strings.Contains(script, env) {
			t.Fatalf("bootstrap script should not force OpenWrt TC-only env %q by default:\n%s", env, script)
		}
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
	if request.EndpointTransport != "udp" || request.EndpointName != "ix-lab-udp" {
		t.Fatalf("endpoint transport/name = %q/%q, want udp/ix-lab-udp", request.EndpointTransport, request.EndpointName)
	}
	target, err := desiredForIXProvision(request, prefixes, []ixProvisionTrustRootFile{{Name: "root.pem", PEM: "unused"}})
	if err != nil {
		t.Fatalf("desired for provision: %v", err)
	}
	if len(target.Endpoints) != 1 ||
		target.Endpoints[0].Name != "ix-lab-udp" ||
		target.Endpoints[0].Transport != "udp" ||
		len(target.TransportPolicy.Candidates) != 1 ||
		target.TransportPolicy.Candidates[0] != "ix-lab-udp" {
		t.Fatalf("target endpoints/candidates = %#v / %#v, want udp full-kmod primary", target.Endpoints, target.TransportPolicy.Candidates)
	}
	if target.TransportPolicy.Encryption != securetransport.EncryptionPlaintext ||
		target.TransportPolicy.Profile != config.TransportProfilePerformance ||
		target.TransportPolicy.Datapath != config.TransportDatapathKernelModule ||
		target.Endpoints[0].Security.Encryption != securetransport.EncryptionPlaintext {
		t.Fatalf("target plaintext performance policy endpoint=%#v policy=%#v", target.Endpoints[0], target.TransportPolicy)
	}
	if experimentalTCPPerformanceRouteGSOAsyncForDesired(target) {
		t.Fatalf("target plaintext performance config should prefer full-kmod plaintext over route-GSO: policy=%#v endpoints=%#v", target.TransportPolicy, target.Endpoints)
	}
	if kernelDatapathRouteGSOSuppressesLegacyFullPlaintextForDesired(target) {
		t.Fatalf("target plaintext performance config should keep full-kmod plaintext TX")
	}
	if !kernelDatapathFullPlaintextEnabledForDesired(target) {
		t.Fatalf("target plaintext performance config did not enable full-kmod plaintext")
	}
	if target.KernelModules.CapabilityProfile != config.KernelCapabilityProfilePerformance {
		t.Fatalf("target kernel capability profile = %q, want performance", target.KernelModules.CapabilityProfile)
	}
	if target.KernelModules.TrustIXCrypto.Mode != "disabled" ||
		target.KernelModules.TrustIXDatapath.Mode != "required" ||
		target.KernelModules.TrustIXDatapathHelpers.Mode != "disabled" {
		t.Fatalf("target plaintext performance kernel module modes = %#v, want datapath required only", target.KernelModules)
	}
}

func TestIXProvisionOpenWRTPlaintextPerformanceUsesUDPTCOnly(t *testing.T) {
	t.Setenv("TRUSTIX_PROVISION_OPENWRT_UDP_TC_ONLY", "1")
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	request, prefixes, err := normalizeIXProvisionIssueRequest(ixProvisionIssueRequest{
		IXID:              "ix-openwrt-fast",
		Profile:           "plaintext-performance",
		Advertise:         []core.Prefix{"10.79.0.0/24"},
		EndpointAddress:   "router.example.com:7000",
		EndpointTransport: "udp",
		ProvisionURL:      "https://ix-a.example.com:18787",
		ServiceManager:    "openwrt",
	}, desired)
	if err != nil {
		t.Fatalf("normalize provision request: %v", err)
	}
	target, err := desiredForIXProvision(request, prefixes, []ixProvisionTrustRootFile{{Name: "root.pem", PEM: "unused"}})
	if err != nil {
		t.Fatalf("desired for provision: %v", err)
	}
	if len(target.Endpoints) != 1 || target.Endpoints[0].Transport != "udp" {
		t.Fatalf("OpenWrt TC-only target endpoints = %#v, want single UDP endpoint", target.Endpoints)
	}
	if len(target.TransportPolicy.Candidates) != 1 || target.TransportPolicy.Candidates[0] != target.Endpoints[0].Name {
		t.Fatalf("OpenWrt TC-only candidates = %#v endpoints=%#v", target.TransportPolicy.Candidates, target.Endpoints)
	}
	if target.TransportPolicy.KernelTransport.Mode != "require_kernel" {
		t.Fatalf("OpenWrt TC-only kernel transport mode = %q, want require_kernel", target.TransportPolicy.KernelTransport.Mode)
	}
	if len(target.TransportPolicy.Profiles) != 0 {
		t.Fatalf("OpenWrt TC-only transport profiles = %#v, want none", target.TransportPolicy.Profiles)
	}
	if target.KernelModules.TrustIXCrypto.Mode != "disabled" ||
		target.KernelModules.TrustIXDatapath.Mode != "disabled" ||
		target.KernelModules.TrustIXDatapathHelpers.Mode != "disabled" {
		t.Fatalf("OpenWrt TC-only kernel module modes = %#v", target.KernelModules)
	}
	if request.BuildKO != "auto" {
		t.Fatalf("OpenWrt TC-only build_ko = %q, want auto", request.BuildKO)
	}
	if target.KernelModules.CapabilityProfile != config.KernelCapabilityProfilePerformance {
		t.Fatalf("OpenWrt TC-only kernel capability profile = %q, want performance", target.KernelModules.CapabilityProfile)
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
	if len(target.Endpoints) != 1 ||
		target.Endpoints[0].Mode != config.EndpointModeActive ||
		target.Endpoints[0].Transport != "experimental_tcp" ||
		target.Endpoints[0].Address != "ix-a.example.com:7000" ||
		target.Endpoints[0].Listen != "" ||
		target.Endpoints[0].Security.Encryption != securetransport.EncryptionPlaintext {
		t.Fatalf("target endpoint = %#v, want active experimental_tcp plaintext dial to upstream", target.Endpoints)
	}
	if len(target.Bootstrap.Peers) != 1 || target.Bootstrap.Peers[0].ControlAPI != "https://ix-a.example.com:9443" {
		t.Fatalf("bootstrap peers = %#v", target.Bootstrap.Peers)
	}
	if target.TransportPolicy.Datapath != config.TransportDatapathTCXDP {
		t.Fatalf("active experimental_tcp datapath = %q, want tc_xdp route-GSO", target.TransportPolicy.Datapath)
	}
	if request.BuildKO != "1" {
		t.Fatalf("active experimental_tcp build_ko = %q, want 1 for route-GSO modules", request.BuildKO)
	}
	if target.KernelModules.TrustIXCrypto.Mode != "disabled" ||
		target.KernelModules.TrustIXDatapath.Mode != "required" ||
		target.KernelModules.TrustIXDatapathHelpers.Mode != "required" {
		t.Fatalf("active experimental_tcp kernel module modes = %#v, want datapath/helpers required", target.KernelModules)
	}
	if !experimentalTCPPerformanceRouteGSOAsyncForDesired(target) {
		t.Fatalf("active experimental_tcp provision config did not enable route-GSO: policy=%#v endpoints=%#v", target.TransportPolicy, target.Endpoints)
	}
	if kernelDatapathFullPlaintextEnabledForDesired(target) {
		t.Fatalf("active experimental_tcp provision config should not select full-kmod plaintext: policy=%#v endpoints=%#v", target.TransportPolicy, target.Endpoints)
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
