package daemon

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/pki"
	"trustix.local/trustix/internal/transport"
	securetransport "trustix.local/trustix/internal/transport/secure"
)

const (
	defaultIXProvisionTokenTTL = 30 * time.Minute
	maxIXProvisionTokenTTL     = 24 * time.Hour
	ixProvisionPrimaryPriority = 100
	ixProvisionAcklessPriority = 80
)

type ixProvisionIssueRequest struct {
	IXID                core.IXID       `json:"ix_id"`
	Domain              core.DomainID   `json:"domain,omitempty"`
	Role                string          `json:"role,omitempty"`
	Profile             string          `json:"profile,omitempty"`
	ControlAPI          string          `json:"control_api"`
	Advertise           []core.Prefix   `json:"advertise,omitempty"`
	EndpointName        core.EndpointID `json:"endpoint_name,omitempty"`
	EndpointMode        string          `json:"endpoint_mode,omitempty"`
	EndpointTransport   string          `json:"endpoint_transport,omitempty"`
	EndpointListen      string          `json:"endpoint_listen,omitempty"`
	EndpointAddress     string          `json:"endpoint_address"`
	LANIface            string          `json:"lan_iface,omitempty"`
	LANGateway          string          `json:"lan_gateway,omitempty"`
	UnderlayIface       string          `json:"underlay_iface,omitempty"`
	AttachMode          string          `json:"attach_mode,omitempty"`
	APIAddr             string          `json:"api_addr,omitempty"`
	PeerAPIAddr         string          `json:"peer_api_addr,omitempty"`
	Dataplane           string          `json:"dataplane,omitempty"`
	ServiceManager      string          `json:"service_manager,omitempty"`
	DNSEnabled          string          `json:"dns_enabled,omitempty"`
	DNSDomain           string          `json:"dns_domain,omitempty"`
	OpenWRTDNSMasq      string          `json:"openwrt_dnsmasq,omitempty"`
	KernelModules       string          `json:"kernel_modules,omitempty"`
	GOArch              string          `json:"goarch,omitempty"`
	KDir                string          `json:"kdir,omitempty"`
	BuildBPF            string          `json:"build_bpf,omitempty"`
	BuildKO             string          `json:"build_ko,omitempty"`
	BuildWebUI          string          `json:"build_webui,omitempty"`
	SourceCerts         string          `json:"source_certs,omitempty"`
	DomainCACert        string          `json:"domain_ca_cert,omitempty"`
	DomainCAKey         string          `json:"domain_ca_key,omitempty"`
	ConfigCACert        string          `json:"config_ca_cert,omitempty"`
	ConfigCAKey         string          `json:"config_ca_key,omitempty"`
	TrustRoots          []string        `json:"trust_roots,omitempty"`
	TargetCertDir       string          `json:"target_cert_dir,omitempty"`
	BootstrapIX         core.IXID       `json:"bootstrap_ix,omitempty"`
	BootstrapControlAPI string          `json:"bootstrap_control_api,omitempty"`
	ProvisionURL        string          `json:"provision_url,omitempty"`
	TTL                 string          `json:"ttl,omitempty"`
	DNSNames            []string        `json:"dns_names,omitempty"`
	IPAddresses         []string        `json:"ip_addresses,omitempty"`
}

type ixProvisionIssueResponse struct {
	Token                 string           `json:"token"`
	ProvisionURL          string           `json:"provision_url"`
	ExpiresAt             time.Time        `json:"expires_at"`
	Command               string           `json:"command"`
	IXCertFingerprint     string           `json:"ix_cert_fingerprint"`
	RouteAuthFingerprints []string         `json:"route_auth_fingerprints,omitempty"`
	Admission             admissionPayload `json:"admission"`
}

type ixProvisionTokenRecord struct {
	Token                 string    `json:"token"`
	IXID                  core.IXID `json:"ix_id"`
	IssuedAt              time.Time `json:"issued_at"`
	ExpiresAt             time.Time `json:"expires_at"`
	UsedAt                time.Time `json:"used_at,omitempty"`
	Script                string    `json:"script"`
	IXCertFingerprint     string    `json:"ix_cert_fingerprint"`
	RouteAuthFingerprints []string  `json:"route_auth_fingerprints,omitempty"`
}

type ixProvisionTokenStore struct {
	Tokens []ixProvisionTokenRecord `json:"tokens"`
}

type ixProvisionTrustRootFile struct {
	Name string
	PEM  string
}

type ixProvisionProfileDefaults struct {
	TransportProfile string
	Datapath         string
	Encryption       string
	CryptoPlacement  string
	KernelTransport  string
}

type ixProvisionScriptInput struct {
	IXID           core.IXID
	ConfigJSON     string
	CertificatePEM string
	PrivateKeyPEM  string
	RouteAuthPEM   string
	TrustRoots     []ixProvisionTrustRootFile
	TargetCertDir  string
	LANIface       string
	AttachMode     string
	APIAddr        string
	PeerAPIAddr    string
	Dataplane      string
	ServiceManager string
	GOArch         string
	KDir           string
	BuildBPF       string
	BuildKO        string
	BuildWebUI     string
}

func (daemon *Daemon) handleIXProvisionIssue(w http.ResponseWriter, r *http.Request) {
	adminProofs := adminProofsFromContext(r.Context())
	if err := daemon.verifyAdminProofPolicy(adminProofs, daemon.desired.Trust); err != nil {
		writeConfigMutationError(w, err)
		return
	}
	payload, err := readLimitedBody(r.Body, 96<<10)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var request ixProvisionIssueRequest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode IX provision request: %w", err))
		return
	}
	if strings.TrimSpace(request.ProvisionURL) == "" {
		request.ProvisionURL = daemon.ixProvisionBaseURL(r)
	}
	response, err := daemon.issueIXProvisionToken(r.Context(), request)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	setSensitiveResponseHeaders(w)
	writeJSON(w, http.StatusOK, response)
}

func (daemon *Daemon) serveIXProvisionIfRequest(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	token, ok := ixProvisionTokenFromBootstrapPath(r.URL.Path)
	if !ok {
		return false
	}
	record, err := daemon.consumeIXProvisionToken(token)
	if err != nil {
		writeError(w, http.StatusGone, err)
		return true
	}
	setIXProvisionBootstrapSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(record.Script))
	return true
}

func setIXProvisionBootstrapSecurityHeaders(w http.ResponseWriter) {
	header := w.Header()
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	header.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
}

func ixProvisionTokenFromBootstrapPath(rawPath string) (string, bool) {
	const prefix = "/v1/provision/ix/"
	const suffix = "/bootstrap.sh"
	if !strings.HasPrefix(rawPath, prefix) || !strings.HasSuffix(rawPath, suffix) {
		return "", false
	}
	token := strings.TrimSuffix(strings.TrimPrefix(rawPath, prefix), suffix)
	token = strings.TrimSpace(token)
	if token == "" || strings.Contains(token, "/") {
		return "", false
	}
	return token, true
}

func (daemon *Daemon) issueIXProvisionToken(ctx context.Context, request ixProvisionIssueRequest) (ixProvisionIssueResponse, error) {
	daemon.configMu.RLock()
	desired := daemon.desired
	daemon.configMu.RUnlock()

	normalized, prefixes, err := normalizeIXProvisionIssueRequest(request, desired)
	if err != nil {
		return ixProvisionIssueResponse{}, err
	}
	domainCA, configCA, err := loadIXProvisionCAs(normalized)
	if err != nil {
		return ixProvisionIssueResponse{}, err
	}
	if err := validateIXProvisionCA(domainCA.Cert, pki.RoleDomainCA, normalized.Domain, "domain CA"); err != nil {
		return ixProvisionIssueResponse{}, err
	}
	if err := validateIXProvisionCA(configCA.Cert, pki.RoleDomainConfigCA, normalized.Domain, "config CA"); err != nil {
		return ixProvisionIssueResponse{}, err
	}

	dnsNames, ipAddresses, err := ixProvisionSANs(normalized)
	if err != nil {
		return ixProvisionIssueResponse{}, err
	}
	ixBundle, err := pki.Issue(domainCA, pki.IssueRequest{
		CommonName:  "TrustIX IX " + string(normalized.IXID),
		Role:        pki.RoleIX,
		Domain:      string(normalized.Domain),
		IX:          string(normalized.IXID),
		IsCA:        true,
		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,
		NotAfter:    time.Now().UTC().AddDate(1, 0, 0),
	})
	if err != nil {
		return ixProvisionIssueResponse{}, fmt.Errorf("issue IX certificate: %w", err)
	}
	var routeAuthPEM string
	var routeAuthFingerprints []string
	if len(prefixes) > 0 {
		routeBundle, err := pki.Issue(configCA, pki.IssueRequest{
			CommonName: "TrustIX Route Authorization " + string(normalized.IXID),
			Role:       pki.RoleRouteAuthorization,
			Domain:     string(normalized.Domain),
			IX:         string(normalized.IXID),
			Prefixes:   corePrefixStrings(prefixes),
			NotAfter:   time.Now().UTC().AddDate(1, 0, 0),
		})
		if err != nil {
			return ixProvisionIssueResponse{}, fmt.Errorf("issue route authorization: %w", err)
		}
		routeAuthPEM = string(routeBundle.CertPEM)
		routeAuthFingerprints = []string{pki.CertificateFingerprintSHA256(routeBundle.Cert)}
	}
	trustRoots, err := ixProvisionTrustRootFiles(desired, normalized.TrustRoots)
	if err != nil {
		return ixProvisionIssueResponse{}, err
	}
	if len(trustRoots) == 0 {
		return ixProvisionIssueResponse{}, fmt.Errorf("at least one trust root is required")
	}

	targetDesired, err := desiredForIXProvision(normalized, prefixes, trustRoots)
	if err != nil {
		return ixProvisionIssueResponse{}, err
	}
	configJSON, err := json.MarshalIndent(targetDesired, "", "  ")
	if err != nil {
		return ixProvisionIssueResponse{}, fmt.Errorf("encode provisioned IX config: %w", err)
	}
	script, err := ixProvisionBootstrapScript(ixProvisionScriptInput{
		IXID:           normalized.IXID,
		ConfigJSON:     string(configJSON),
		CertificatePEM: string(ixBundle.CertPEM),
		PrivateKeyPEM:  string(ixBundle.KeyPEM),
		RouteAuthPEM:   routeAuthPEM,
		TrustRoots:     trustRoots,
		TargetCertDir:  normalized.TargetCertDir,
		LANIface:       normalized.LANIface,
		AttachMode:     normalized.AttachMode,
		APIAddr:        normalized.APIAddr,
		PeerAPIAddr:    normalized.PeerAPIAddr,
		Dataplane:      normalized.Dataplane,
		ServiceManager: normalized.ServiceManager,
		GOArch:         normalized.GOArch,
		KDir:           normalized.KDir,
		BuildBPF:       normalized.BuildBPF,
		BuildKO:        normalized.BuildKO,
		BuildWebUI:     normalized.BuildWebUI,
	})
	if err != nil {
		return ixProvisionIssueResponse{}, err
	}

	if err := daemon.ensureLocalIXAdmission(ctx, desired); err != nil {
		return ixProvisionIssueResponse{}, err
	}

	admission := admissionPayload{
		Version:               1,
		DomainID:              desired.Domain.ID,
		IXID:                  normalized.IXID,
		State:                 admissionStateApproved,
		IXCertFingerprint:     pki.CertificateFingerprintSHA256(ixBundle.Cert),
		AllowedPrefixes:       prefixes,
		RouteAuthFingerprints: routeAuthFingerprints,
		ControlAPI:            normalized.ControlAPI,
		EffectiveAt:           time.Now().UTC(),
	}
	if changed, err := daemon.applyAdmissionConfig(ctx, admission); err != nil {
		return ixProvisionIssueResponse{}, err
	} else if changed {
		daemon.configMu.RLock()
		if current, ok, err := daemon.latestAdmissionForIXLocked(normalized.IXID); err == nil && ok {
			admission = current
		}
		daemon.configMu.RUnlock()
	}

	token, err := newIXProvisionToken()
	if err != nil {
		return ixProvisionIssueResponse{}, err
	}
	now := time.Now().UTC()
	expiresAt := now.Add(normalizedTTL(normalized.TTL))
	record := ixProvisionTokenRecord{
		Token:                 token,
		IXID:                  normalized.IXID,
		IssuedAt:              now,
		ExpiresAt:             expiresAt,
		Script:                script,
		IXCertFingerprint:     admission.IXCertFingerprint,
		RouteAuthFingerprints: append([]string(nil), admission.RouteAuthFingerprints...),
	}
	if err := daemon.storeIXProvisionToken(record); err != nil {
		return ixProvisionIssueResponse{}, err
	}
	provisionURL := strings.TrimRight(normalized.ProvisionURL, "/")
	return ixProvisionIssueResponse{
		Token:                 token,
		ProvisionURL:          provisionURL,
		ExpiresAt:             expiresAt,
		Command:               ixProvisionCommand(provisionURL, token),
		IXCertFingerprint:     admission.IXCertFingerprint,
		RouteAuthFingerprints: append([]string(nil), admission.RouteAuthFingerprints...),
		Admission:             admission,
	}, nil
}

func (daemon *Daemon) ensureLocalIXAdmission(ctx context.Context, desired config.Desired) error {
	admission, err := daemon.localIXAdmissionForDesired(desired)
	if err != nil {
		return err
	}
	daemon.configMu.RLock()
	current, ok, err := daemon.latestAdmissionForIXLocked(desired.IX.ID)
	daemon.configMu.RUnlock()
	if err != nil {
		return err
	}
	if ok && admissionEquivalentForProvision(current, admission) {
		return nil
	}
	if _, err := daemon.applyAdmissionConfig(ctx, admission); err != nil {
		return fmt.Errorf("apply local IX admission: %w", err)
	}
	return nil
}

func (daemon *Daemon) localIXAdmissionForDesired(desired config.Desired) (admissionPayload, error) {
	daemon.configMu.RLock()
	head := daemon.head
	daemon.configMu.RUnlock()
	advertisement, err := daemon.buildLocalAdvertisementForDesired(desired, head, controlTarget{})
	if err != nil {
		return admissionPayload{}, fmt.Errorf("build local IX admission advertisement: %w", err)
	}
	cert, err := x509.ParseCertificate(advertisement.IXCertificate)
	if err != nil {
		return admissionPayload{}, fmt.Errorf("parse local IX certificate: %w", err)
	}
	routeAuthFingerprints, err := routeAuthFingerprintsFromAdvertisement(advertisement)
	if err != nil {
		return admissionPayload{}, err
	}
	return admissionPayload{
		Version:               1,
		DomainID:              desired.Domain.ID,
		IXID:                  desired.IX.ID,
		State:                 admissionStateApproved,
		IXCertFingerprint:     pki.CertificateFingerprintSHA256(cert),
		AllowedPrefixes:       corePrefixesFromAdvertisement(advertisement),
		RouteAuthFingerprints: routeAuthFingerprints,
		ControlAPI:            strings.TrimSpace(advertisement.ControlAPI),
		EffectiveAt:           time.Now().UTC(),
	}, nil
}

func admissionEquivalentForProvision(current, desired admissionPayload) bool {
	if current.State != admissionStateApproved {
		return false
	}
	if current.DomainID != desired.DomainID || current.IXID != desired.IXID {
		return false
	}
	if current.IXCertFingerprint != desired.IXCertFingerprint {
		return false
	}
	if strings.TrimSpace(current.ControlAPI) != strings.TrimSpace(desired.ControlAPI) {
		return false
	}
	currentPrefixes, err := normalizeCorePrefixes(current.AllowedPrefixes)
	if err != nil {
		return false
	}
	desiredPrefixes, err := normalizeCorePrefixes(desired.AllowedPrefixes)
	if err != nil {
		return false
	}
	currentFingerprints, err := normalizeFingerprintList(current.RouteAuthFingerprints)
	if err != nil {
		return false
	}
	desiredFingerprints, err := normalizeFingerprintList(desired.RouteAuthFingerprints)
	if err != nil {
		return false
	}
	return stringSlicesEqual(corePrefixStrings(currentPrefixes), corePrefixStrings(desiredPrefixes)) &&
		stringSlicesEqual(currentFingerprints, desiredFingerprints)
}

func stringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func normalizeIXProvisionIssueRequest(request ixProvisionIssueRequest, desired config.Desired) (ixProvisionIssueRequest, []core.Prefix, error) {
	request.IXID = core.IXID(strings.TrimSpace(string(request.IXID)))
	if err := request.IXID.Validate(); err != nil {
		return ixProvisionIssueRequest{}, nil, err
	}
	if request.IXID == desired.IX.ID {
		return ixProvisionIssueRequest{}, nil, fmt.Errorf("new IX id must differ from the local IX id")
	}
	request.Domain = core.DomainID(strings.TrimSpace(string(request.Domain)))
	if request.Domain == "" {
		request.Domain = desired.Domain.ID
	}
	if err := request.Domain.Validate(); err != nil {
		return ixProvisionIssueRequest{}, nil, err
	}
	if request.Domain != desired.Domain.ID {
		return ixProvisionIssueRequest{}, nil, fmt.Errorf("provision domain is %q, want local domain %q", request.Domain, desired.Domain.ID)
	}
	request.Role = normalizeIXProvisionRole(request.Role)
	if request.Role == "" {
		request.Role = "public_ix"
	}
	if !validIXProvisionRole(request.Role) {
		return ixProvisionIssueRequest{}, nil, fmt.Errorf("role must be public_ix, edge_ix, transit_ix, or lab_ix")
	}
	request.Profile = normalizeIXProvisionProfile(request.Profile)
	if _, err := ixProvisionDefaultsForProfile(request.Profile); err != nil {
		return ixProvisionIssueRequest{}, nil, err
	}
	prefixes, err := normalizeCorePrefixes(request.Advertise)
	if err != nil {
		return ixProvisionIssueRequest{}, nil, fmt.Errorf("advertise: %w", err)
	}
	if len(prefixes) == 0 && request.Role != "transit_ix" {
		return ixProvisionIssueRequest{}, nil, fmt.Errorf("advertise must contain at least one CIDR prefix unless role is transit_ix")
	}

	request.EndpointTransport = strings.ToLower(strings.TrimSpace(request.EndpointTransport))
	if request.EndpointTransport == "" {
		request.EndpointTransport = string(transport.ProtocolUDP)
	}
	request.EndpointMode = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(request.EndpointMode), "-", "_"))
	if request.EndpointMode == "" {
		request.EndpointMode = string(config.EndpointModePassive)
	}
	switch request.EndpointMode {
	case string(config.EndpointModeActive), string(config.EndpointModePassive):
	default:
		return ixProvisionIssueRequest{}, nil, fmt.Errorf("endpoint_mode must be active or passive")
	}
	request.BootstrapControlAPI = strings.TrimSpace(request.BootstrapControlAPI)
	if request.BootstrapControlAPI == "" {
		request.BootstrapControlAPI = strings.TrimSpace(desired.IX.ControlAPI)
	}
	request.ControlAPI = normalizeProvisionControlAPI(request.ControlAPI)
	request.EndpointAddress = normalizeProvisionEndpointAddress(request.EndpointAddress, "7000")
	if request.EndpointAddress == "" && request.EndpointMode == string(config.EndpointModePassive) && request.ControlAPI != "" {
		request.EndpointAddress = provisionEndpointAddressFromControlAPI(request.ControlAPI, "7000")
	}
	if request.EndpointAddress == "" && request.EndpointMode == string(config.EndpointModeActive) && request.BootstrapControlAPI != "" {
		request.EndpointAddress = provisionEndpointAddressFromControlAPI(request.BootstrapControlAPI, "7000")
	}
	if request.EndpointAddress == "" {
		if request.EndpointMode == string(config.EndpointModeActive) {
			return ixProvisionIssueRequest{}, nil, fmt.Errorf("endpoint_address is required for active endpoint_mode")
		}
		return ixProvisionIssueRequest{}, nil, fmt.Errorf("endpoint_address is required")
	}
	if request.ControlAPI == "" && request.EndpointMode == string(config.EndpointModePassive) {
		request.ControlAPI = provisionControlAPIFromEndpointAddress(request.EndpointAddress, "9443")
	}
	request.ControlAPI = normalizeProvisionControlAPI(request.ControlAPI)
	if request.ControlAPI != "" {
		if err := validateControlAPI(request.ControlAPI); err != nil {
			return ixProvisionIssueRequest{}, nil, fmt.Errorf("control_api: %w", err)
		}
	}
	request.EndpointListen = strings.TrimSpace(request.EndpointListen)
	if request.EndpointMode == string(config.EndpointModePassive) && request.EndpointListen == "" {
		request.EndpointListen = net.JoinHostPort("0.0.0.0", provisionEndpointPort(request.EndpointAddress, "7000"))
	}
	if request.EndpointMode == string(config.EndpointModeActive) {
		request.EndpointListen = ""
	}
	request.EndpointName = core.EndpointID(strings.TrimSpace(string(request.EndpointName)))
	if request.EndpointName == "" {
		request.EndpointName = core.EndpointID(safeProvisionFileName(string(request.IXID), "ix-new") + "-" + request.EndpointTransport)
	}
	if err := request.EndpointName.Validate(); err != nil {
		return ixProvisionIssueRequest{}, nil, err
	}
	request.UnderlayIface = strings.TrimSpace(request.UnderlayIface)
	request.AttachMode = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(request.AttachMode), "_", "-"))
	if request.AttachMode == "" {
		request.AttachMode = string(config.LANAttachModeManaged)
	}
	request.LANIface = strings.TrimSpace(request.LANIface)
	if request.LANIface == "" && len(prefixes) > 0 {
		if request.AttachMode == string(config.LANAttachModeExisting) {
			return ixProvisionIssueRequest{}, nil, fmt.Errorf("lan_iface is required when attach_mode is existing")
		}
		request.LANIface = "trustix-" + safeProvisionFileName(string(request.IXID), "ix")
	}
	request.LANGateway = strings.TrimSpace(request.LANGateway)
	if request.LANGateway == "" && len(prefixes) > 0 && request.Role != "transit_ix" {
		request.LANGateway = defaultLANGatewayForPrefix(prefixes[0])
	}
	request.APIAddr = strings.TrimSpace(request.APIAddr)
	if request.APIAddr == "" {
		request.APIAddr = "127.0.0.1:8787"
	}
	request.PeerAPIAddr = strings.TrimSpace(request.PeerAPIAddr)
	if request.PeerAPIAddr == "" {
		request.PeerAPIAddr = "0.0.0.0:9443"
	}
	request.Dataplane = strings.ToLower(strings.TrimSpace(request.Dataplane))
	if request.Dataplane == "" {
		request.Dataplane = "auto"
	}
	request.ServiceManager = strings.ToLower(strings.TrimSpace(request.ServiceManager))
	if request.ServiceManager == "" {
		request.ServiceManager = "auto"
	}
	switch request.ServiceManager {
	case "auto", "systemd", "openwrt":
	default:
		return ixProvisionIssueRequest{}, nil, fmt.Errorf("service_manager must be auto, systemd, or openwrt")
	}
	request.DNSEnabled = strings.TrimSpace(request.DNSEnabled)
	if request.DNSEnabled == "" {
		request.DNSEnabled = "0"
	}
	request.OpenWRTDNSMasq = strings.TrimSpace(request.OpenWRTDNSMasq)
	if request.OpenWRTDNSMasq == "" {
		request.OpenWRTDNSMasq = "0"
	}
	if err := validateProvisionToggle("dns_enabled", request.DNSEnabled, "0", "1"); err != nil {
		return ixProvisionIssueRequest{}, nil, err
	}
	if err := validateProvisionToggle("openwrt_dnsmasq", request.OpenWRTDNSMasq, "0", "1"); err != nil {
		return ixProvisionIssueRequest{}, nil, err
	}
	if request.OpenWRTDNSMasq == "1" {
		request.DNSEnabled = "1"
	}
	request.DNSDomain = strings.ToLower(strings.Trim(strings.TrimSpace(request.DNSDomain), "."))
	request.KernelModules = strings.ToLower(strings.TrimSpace(request.KernelModules))
	if request.KernelModules == "" {
		request.KernelModules = "auto"
	}
	switch request.KernelModules {
	case "auto", "disabled", "required":
	default:
		return ixProvisionIssueRequest{}, nil, fmt.Errorf("kernel_modules must be auto, disabled, or required")
	}
	request.GOArch = strings.TrimSpace(request.GOArch)
	request.KDir = strings.TrimSpace(request.KDir)
	request.BuildBPF = strings.TrimSpace(request.BuildBPF)
	if request.BuildBPF == "" {
		request.BuildBPF = "1"
	}
	request.BuildKO = strings.TrimSpace(request.BuildKO)
	if request.BuildKO == "" {
		request.BuildKO = "auto"
	}
	request.BuildWebUI = strings.TrimSpace(request.BuildWebUI)
	if request.BuildWebUI == "" {
		request.BuildWebUI = "0"
	}
	if err := validateProvisionToggle("build_bpf", request.BuildBPF, "0", "1"); err != nil {
		return ixProvisionIssueRequest{}, nil, err
	}
	if err := validateProvisionToggle("build_ko", request.BuildKO, "auto", "0", "1"); err != nil {
		return ixProvisionIssueRequest{}, nil, err
	}
	if err := validateProvisionToggle("build_webui", request.BuildWebUI, "0", "1"); err != nil {
		return ixProvisionIssueRequest{}, nil, err
	}
	request.SourceCerts = strings.TrimSpace(request.SourceCerts)
	if request.SourceCerts == "" {
		request.SourceCerts = "certs"
	}
	request.DomainCACert = defaultPath(request.DomainCACert, filepath.Join(request.SourceCerts, "domain-ca.pem"))
	request.DomainCAKey = defaultPath(request.DomainCAKey, filepath.Join(request.SourceCerts, "domain-ca.key"))
	request.ConfigCACert = defaultPath(request.ConfigCACert, filepath.Join(request.SourceCerts, "config-ca.pem"))
	request.ConfigCAKey = defaultPath(request.ConfigCAKey, filepath.Join(request.SourceCerts, "config-ca.key"))
	request.TargetCertDir = strings.TrimSpace(request.TargetCertDir)
	if request.TargetCertDir == "" {
		request.TargetCertDir = "/etc/trustix/certs"
	}
	request.BootstrapIX = core.IXID(strings.TrimSpace(string(request.BootstrapIX)))
	if request.BootstrapIX == "" {
		request.BootstrapIX = desired.IX.ID
	}
	if request.BootstrapIX != "" {
		if err := request.BootstrapIX.Validate(); err != nil {
			return ixProvisionIssueRequest{}, nil, err
		}
	}
	if request.BootstrapControlAPI != "" {
		if err := validateControlAPI(request.BootstrapControlAPI); err != nil {
			return ixProvisionIssueRequest{}, nil, fmt.Errorf("bootstrap_control_api: %w", err)
		}
	}
	request.ProvisionURL = strings.TrimRight(strings.TrimSpace(request.ProvisionURL), "/")
	if err := validateIXProvisionURL(request.ProvisionURL); err != nil {
		return ixProvisionIssueRequest{}, nil, err
	}
	if strings.TrimSpace(request.TTL) != "" {
		ttl, err := time.ParseDuration(strings.TrimSpace(request.TTL))
		if err != nil {
			return ixProvisionIssueRequest{}, nil, fmt.Errorf("ttl: %w", err)
		}
		if ttl <= 0 || ttl > maxIXProvisionTokenTTL {
			return ixProvisionIssueRequest{}, nil, fmt.Errorf("ttl must be in 1ns..%s", maxIXProvisionTokenTTL)
		}
	}
	request.TrustRoots = trimStrings(request.TrustRoots)
	request.DNSNames = trimStrings(request.DNSNames)
	request.IPAddresses = trimStrings(request.IPAddresses)
	return request, prefixes, nil
}

func normalizeIXProvisionRole(role string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(role), "-", "_"))
}

func validIXProvisionRole(role string) bool {
	switch role {
	case "public_ix", "edge_ix", "transit_ix", "lab_ix":
		return true
	default:
		return false
	}
}

func normalizeIXProvisionProfile(profile string) string {
	profile = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(profile), "-", "_"))
	switch profile {
	case "":
		return "stable"
	case "compat", "compatible":
		return "compatibility"
	case "plain", "plaintext", "plaintext_perf", "performance_plaintext":
		return "plaintext_performance"
	default:
		return profile
	}
}

func ixProvisionDefaultsForProfile(profile string) (ixProvisionProfileDefaults, error) {
	profile = normalizeIXProvisionProfile(profile)
	switch profile {
	case "stable":
		return ixProvisionProfileDefaults{
			TransportProfile: config.TransportProfileStable,
			Datapath:         config.TransportDatapathAuto,
			Encryption:       securetransport.EncryptionSecure,
			CryptoPlacement:  "auto",
			KernelTransport:  "auto",
		}, nil
	case "performance":
		return ixProvisionProfileDefaults{
			TransportProfile: config.TransportProfilePerformance,
			Datapath:         config.TransportDatapathAuto,
			Encryption:       securetransport.EncryptionSecure,
			CryptoPlacement:  "auto",
			KernelTransport:  "auto",
		}, nil
	case "latency":
		return ixProvisionProfileDefaults{
			TransportProfile: config.TransportProfileLatency,
			Datapath:         config.TransportDatapathAuto,
			Encryption:       securetransport.EncryptionSecure,
			CryptoPlacement:  "auto",
			KernelTransport:  "auto",
		}, nil
	case "compatibility":
		return ixProvisionProfileDefaults{
			TransportProfile: config.TransportProfileStable,
			Datapath:         config.TransportDatapathUserspace,
			Encryption:       securetransport.EncryptionSecure,
			CryptoPlacement:  "userspace",
			KernelTransport:  "disabled",
		}, nil
	case "plaintext_performance":
		return ixProvisionProfileDefaults{
			TransportProfile: config.TransportProfilePerformance,
			Datapath:         config.TransportDatapathKernelModule,
			Encryption:       securetransport.EncryptionPlaintext,
			CryptoPlacement:  "auto",
			KernelTransport:  "auto",
		}, nil
	default:
		return ixProvisionProfileDefaults{}, fmt.Errorf("profile must be stable, performance, latency, compatibility, or plaintext_performance")
	}
}

func normalizeProvisionControlAPI(raw string) string {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	return raw
}

func normalizeProvisionEndpointAddress(raw, fallbackPort string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" {
		raw = parsed.Host
	}
	if strings.Contains(raw, ",") || strings.Contains(raw, "=") {
		return raw
	}
	if _, _, err := net.SplitHostPort(raw); err == nil {
		return raw
	}
	host := strings.Trim(raw, "[]")
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is6() {
		return net.JoinHostPort(addr.String(), fallbackPort)
	}
	return net.JoinHostPort(host, fallbackPort)
}

func provisionControlAPIFromEndpointAddress(endpointAddress, fallbackPort string) string {
	host := hostForSAN(endpointAddress)
	if host == "" {
		return ""
	}
	return "https://" + net.JoinHostPort(host, fallbackPort)
}

func provisionEndpointAddressFromControlAPI(controlAPI, fallbackPort string) string {
	parsed, err := url.Parse(normalizeProvisionControlAPI(controlAPI))
	if err != nil || parsed.Host == "" {
		return ""
	}
	host := parsed.Hostname()
	if host == "" {
		return ""
	}
	return net.JoinHostPort(host, fallbackPort)
}

func provisionEndpointPort(endpointAddress, fallback string) string {
	_, port, err := net.SplitHostPort(endpointAddress)
	if err == nil && port != "" {
		return port
	}
	return fallback
}

func defaultLANGatewayForPrefix(prefix core.Prefix) string {
	parsed, err := prefix.Parse()
	if err != nil {
		return ""
	}
	network := parsed.Masked()
	addr := network.Addr()
	if bits := network.Bits(); bits < addr.BitLen() {
		next := addr.Next()
		if next.IsValid() && network.Contains(next) {
			addr = next
		}
	}
	return netip.PrefixFrom(addr, network.Bits()).String()
}

func loadIXProvisionCAs(request ixProvisionIssueRequest) (pki.Bundle, pki.Bundle, error) {
	domainCA, err := pki.LoadBundle(request.DomainCACert, request.DomainCAKey)
	if err != nil {
		return pki.Bundle{}, pki.Bundle{}, fmt.Errorf("load domain CA: %w", err)
	}
	configCA, err := pki.LoadBundle(request.ConfigCACert, request.ConfigCAKey)
	if err != nil {
		return pki.Bundle{}, pki.Bundle{}, fmt.Errorf("load config CA: %w", err)
	}
	return domainCA, configCA, nil
}

func validateIXProvisionCA(cert *x509.Certificate, role pki.Role, domain core.DomainID, label string) error {
	if cert == nil {
		return fmt.Errorf("%s certificate is required", label)
	}
	meta := pki.ParseMetadata(cert)
	if meta.Role != role {
		return fmt.Errorf("%s role is %q, want %q", label, meta.Role, role)
	}
	if meta.Domain != string(domain) {
		return fmt.Errorf("%s domain is %q, want %q", label, meta.Domain, domain)
	}
	if !cert.IsCA {
		return fmt.Errorf("%s is not a CA certificate", label)
	}
	return nil
}

func ixProvisionSANs(request ixProvisionIssueRequest) ([]string, []net.IP, error) {
	dns := append([]string(nil), request.DNSNames...)
	ips, err := parseDeviceAccessIssueIPs(request.IPAddresses)
	if err != nil {
		return nil, nil, err
	}
	candidates := []string{request.ControlAPI}
	if request.EndpointMode != string(config.EndpointModeActive) {
		candidates = append(candidates, request.EndpointAddress)
	}
	for _, raw := range candidates {
		host := hostForSAN(raw)
		if host == "" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, host)
		}
	}
	return uniqueStrings(dns), uniqueIPs(ips), nil
}

func hostForSAN(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" {
		raw = parsed.Host
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.Trim(raw, "[]")
	if raw == "" || strings.Contains(raw, ",") || strings.Contains(raw, "=") {
		return ""
	}
	return raw
}

func ixProvisionTrustRootFiles(desired config.Desired, paths []string) ([]ixProvisionTrustRootFile, error) {
	if len(paths) > 0 {
		out := make([]ixProvisionTrustRootFile, 0, len(paths))
		seenName := make(map[string]int, len(paths))
		for index, rootPath := range paths {
			cert, _, err := pki.LoadCertificate(rootPath)
			if err != nil {
				return nil, fmt.Errorf("load trust root %q: %w", rootPath, err)
			}
			name := safeProvisionFileName(filepath.Base(rootPath), fmt.Sprintf("trust-root-%d.pem", index+1))
			name = uniqueProvisionFileName(name, seenName)
			out = append(out, ixProvisionTrustRootFile{
				Name: name,
				PEM:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
			})
		}
		return out, nil
	}
	roots, err := deviceAccessTrustRootsPEM(desired)
	if err != nil {
		return nil, fmt.Errorf("load domain trust roots: %w", err)
	}
	out := make([]ixProvisionTrustRootFile, 0, len(roots))
	for index, rootPEM := range roots {
		out = append(out, ixProvisionTrustRootFile{
			Name: fmt.Sprintf("trust-root-%d.pem", index+1),
			PEM:  rootPEM,
		})
	}
	return out, nil
}

func ixProvisionControlAPIPublishMode(request ixProvisionIssueRequest) string {
	if request.EndpointMode == string(config.EndpointModeActive) && strings.TrimSpace(request.ControlAPI) == "" {
		return "disabled"
	}
	return ""
}

func ixProvisionEndpointConfigs(request ixProvisionIssueRequest, profile ixProvisionProfileDefaults) ([]config.EndpointConfig, []core.EndpointID) {
	primary := ixProvisionEndpointConfig(request, request.EndpointName, request.EndpointTransport, ixProvisionPrimaryPriority, profile)
	endpoints := []config.EndpointConfig{primary}
	candidates := []core.EndpointID{primary.Name}
	if transport.Protocol(request.EndpointTransport) == transport.ProtocolUDP {
		acklessName := ixProvisionAcklessEndpointName(request)
		endpoints = append(endpoints, ixProvisionEndpointConfig(request, acklessName, string(transport.ProtocolExperimentalTCP), ixProvisionAcklessPriority, profile))
		candidates = append(candidates, acklessName)
	}
	return endpoints, candidates
}

func ixProvisionEndpointConfig(request ixProvisionIssueRequest, name core.EndpointID, endpointTransport string, priority int, profile ixProvisionProfileDefaults) config.EndpointConfig {
	return config.EndpointConfig{
		Name:      name,
		Mode:      config.EndpointMode(request.EndpointMode),
		Listen:    request.EndpointListen,
		Address:   request.EndpointAddress,
		Transport: endpointTransport,
		Priority:  priority,
		Security: config.EndpointSecurityConfig{
			Encryption: profile.Encryption,
		},
		Profile: config.EndpointProfileConfig{
			Profile:         profile.TransportProfile,
			Datapath:        profile.Datapath,
			Encryption:      profile.Encryption,
			CryptoPlacement: profile.CryptoPlacement,
		},
		Enabled:    true,
		EnabledSet: true,
	}
}

func ixProvisionAcklessEndpointName(request ixProvisionIssueRequest) core.EndpointID {
	name := strings.TrimSpace(string(request.EndpointName))
	if strings.HasSuffix(name, "-udp") {
		return core.EndpointID(strings.TrimSuffix(name, "-udp") + "-experimental_tcp")
	}
	if name != "" {
		return core.EndpointID(name + "-experimental_tcp")
	}
	return core.EndpointID(safeProvisionFileName(string(request.IXID), "ix-new") + "-experimental_tcp")
}

func ixProvisionTransportProfiles(request ixProvisionIssueRequest, profile ixProvisionProfileDefaults) []config.TransportProfileConfig {
	if transport.Protocol(request.EndpointTransport) != transport.ProtocolUDP {
		return nil
	}
	return []config.TransportProfileConfig{{
		Transport:       string(transport.ProtocolExperimentalTCP),
		Profile:         profile.TransportProfile,
		Datapath:        profile.Datapath,
		Encryption:      profile.Encryption,
		CryptoPlacement: profile.CryptoPlacement,
		Advanced:        ixProvisionAcklessAdvanced(request.Profile),
	}}
}

func ixProvisionAcklessAdvanced(profile string) config.TransportAdvancedConfig {
	advanced := config.TransportAdvancedConfig{
		BatchBytes: dataSessionBatchDefaultBytes,
		FlushDelay: "25us",
		MaxFrames:  dataSessionBatchMaxPackets,
	}
	if normalizeIXProvisionProfile(profile) == "latency" {
		advanced.FlushDelay = "0"
		advanced.MaxFrames = 64
	}
	return advanced
}

func desiredForIXProvision(request ixProvisionIssueRequest, prefixes []core.Prefix, roots []ixProvisionTrustRootFile) (config.Desired, error) {
	ixBase := safeProvisionFileName(string(request.IXID), "ix")
	rootPaths := make([]string, 0, len(roots))
	for _, root := range roots {
		rootPaths = append(rootPaths, path.Join(request.TargetCertDir, root.Name))
	}
	profile, err := ixProvisionDefaultsForProfile(request.Profile)
	if err != nil {
		return config.Desired{}, err
	}
	attachMode := config.LANAttachMode(request.AttachMode)
	manageAddress := attachMode != config.LANAttachModeExisting
	endpoints, candidates := ixProvisionEndpointConfigs(request, profile)
	desired := config.Desired{
		Domain: config.DomainConfig{
			ID:         request.Domain,
			TrustRoots: rootPaths,
		},
		IX: config.IXConfig{
			ID:                request.IXID,
			Domain:            request.Domain,
			CertPath:          path.Join(request.TargetCertDir, ixBase+".crt"),
			KeyPath:           path.Join(request.TargetCertDir, ixBase+".key"),
			ControlAPI:        request.ControlAPI,
			ControlAPIPublish: ixProvisionControlAPIPublishMode(request),
		},
		Management: config.ManagementConfig{
			TLS: config.ManagementTLSConfig{
				Mode:     "auto",
				Identity: "ix_cert",
			},
			HostAPI: config.HostManagementAPIConfig{
				Enabled: false,
			},
			WebUI: config.WebUIConfig{Enabled: true},
		},
		DNS: config.DNSConfig{
			Enabled: request.DNSEnabled == "1",
			Domain:  request.DNSDomain,
			DNSMasq: config.DNSMasqConfig{Enabled: request.OpenWRTDNSMasq == "1"},
		},
		KernelModules: config.KernelModulesConfig{
			TrustIXCrypto:          config.KernelModuleConfig{Mode: request.KernelModules, Path: "embedded", ReloadOnUpgrade: "auto"},
			TrustIXDatapath:        config.KernelModuleConfig{Mode: request.KernelModules, Path: "embedded", ReloadOnUpgrade: "auto"},
			TrustIXDatapathHelpers: config.KernelModuleConfig{Mode: request.KernelModules, Path: "embedded", ReloadOnUpgrade: "auto"},
		},
		Endpoints: endpoints,
		Bootstrap: config.BootstrapConfig{},
		Peers:     []config.PeerConfig{},
		Routes:    []config.RouteConfig{},
		RoutePolicy: config.RoutePolicyConfig{
			DynamicMetric: 1000,
		},
		Policies: []config.PolicyConfig{{
			Name:           core.PolicyID("default-routed"),
			RouteSelection: "longest_prefix",
			FlowStickiness: true,
			Rewrite:        "preserve_source",
		}},
		TransportPolicy: config.TransportPolicyConfig{
			Mode:            "user_defined",
			Candidates:      candidates,
			Failover:        "health_based",
			Profile:         profile.TransportProfile,
			Datapath:        profile.Datapath,
			Encryption:      profile.Encryption,
			CryptoKeySource: securetransport.KeySourceAuto,
			CryptoPlacement: profile.CryptoPlacement,
			Profiles:        ixProvisionTransportProfiles(request, profile),
			KernelTransport: config.KernelTransportPolicyConfig{Mode: profile.KernelTransport},
			SessionPool:     config.SessionPoolPolicyConfig{Warmup: true},
		},
	}
	if len(prefixes) > 0 {
		desired.IX.RouteAuthorizations = []string{path.Join(request.TargetCertDir, ixBase+"-route.crt")}
	}
	if ixProvisionHasLAN(request, prefixes) {
		desired.LAN = config.LANConfig{
			ID:               config.DefaultLANID,
			Type:             config.LANTypeLocal,
			Iface:            request.LANIface,
			UnderlayIface:    request.UnderlayIface,
			Gateway:          request.LANGateway,
			Advertise:        append([]core.Prefix(nil), prefixes...),
			Mode:             config.LANModeRouted,
			AttachMode:       attachMode,
			ManageAddress:    manageAddress && request.LANGateway != "",
			ManageForwarding: len(prefixes) > 0,
			ManageRPFilter:   len(prefixes) > 0,
		}
	}
	if request.BootstrapControlAPI != "" {
		desired.Bootstrap.Peers = []config.BootstrapPeerConfig{{
			ID:         request.BootstrapIX,
			Domain:     request.Domain,
			ControlAPI: request.BootstrapControlAPI,
		}}
	}
	desired = config.Normalize(desired)
	if err := desired.Validate(); err != nil {
		return config.Desired{}, fmt.Errorf("validate provisioned IX config: %w", err)
	}
	return desired, nil
}

func ixProvisionHasLAN(request ixProvisionIssueRequest, prefixes []core.Prefix) bool {
	return len(prefixes) > 0 ||
		strings.TrimSpace(request.LANIface) != "" ||
		strings.TrimSpace(request.UnderlayIface) != "" ||
		strings.TrimSpace(request.LANGateway) != ""
}

func ixProvisionBootstrapScript(input ixProvisionScriptInput) (string, error) {
	ixBase := safeProvisionFileName(string(input.IXID), "ix")
	configFile := ixBase + ".json"
	certFile := ixBase + ".crt"
	keyFile := ixBase + ".key"
	routeFile := ixBase + "-route.crt"
	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\n")
	b.WriteString("set -Eeuo pipefail\n")
	b.WriteString("log() { printf '[trustix-provision] %s\\n' \"$*\" >&2; }\n")
	b.WriteString("die() { log \"ERROR: $*\"; exit 1; }\n")
	b.WriteString("repo_root=\"${TRUSTIX_BOOTSTRAP_REPO_ROOT:-${1:-}}\"\n")
	b.WriteString("[[ -n \"$repo_root\" && -f \"${repo_root}/go.mod\" ]] || die \"TrustIX repo root is required\"\n")
	b.WriteString("work_dir=\"${TRUSTIX_PROVISION_WORKDIR:-}\"\n")
	b.WriteString("if [[ -z \"$work_dir\" ]]; then work_dir=\"$(mktemp -d /tmp/trustix-provision.")
	b.WriteString(shellScriptLiteral(ixBase))
	b.WriteString(".XXXXXX)\"; fi\n")
	b.WriteString("cert_dir=\"${work_dir}/certs\"\n")
	b.WriteString("config_dir=\"${work_dir}/config\"\n")
	b.WriteString("mkdir -p \"$cert_dir\" \"$config_dir\"\n")
	b.WriteString("config_path=\"${config_dir}/")
	b.WriteString(shellScriptLiteral(configFile))
	b.WriteString("\"\n")
	appendHereDoc(&b, "\"${cert_dir}/"+certFile+"\"", "IX_CERT", input.CertificatePEM)
	appendHereDoc(&b, "\"${cert_dir}/"+keyFile+"\"", "IX_KEY", input.PrivateKeyPEM)
	if strings.TrimSpace(input.RouteAuthPEM) != "" {
		appendHereDoc(&b, "\"${cert_dir}/"+routeFile+"\"", "ROUTE_AUTH", input.RouteAuthPEM)
	}
	for _, root := range input.TrustRoots {
		appendHereDoc(&b, "\"${cert_dir}/"+root.Name+"\"", "TRUST_ROOT_"+root.Name, root.PEM)
	}
	appendHereDoc(&b, "$config_path", "CONFIG", input.ConfigJSON)
	b.WriteString("chmod 0600 \"${cert_dir}/")
	b.WriteString(shellScriptLiteral(keyFile))
	b.WriteString("\"\n")
	if strings.TrimSpace(input.LANIface) != "" && input.AttachMode != string(config.LANAttachModeExisting) {
		b.WriteString("if command -v ip >/dev/null 2>&1; then\n")
		b.WriteString("  if ! ip link show ")
		b.WriteString(shellQuote(input.LANIface))
		b.WriteString(" >/dev/null 2>&1; then\n")
		b.WriteString("    log \"create managed LAN interface ")
		b.WriteString(shellScriptLiteral(input.LANIface))
		b.WriteString("\"\n")
		b.WriteString("    ip link add ")
		b.WriteString(shellQuote(input.LANIface))
		b.WriteString(" type dummy || die \"create managed LAN interface\"\n")
		b.WriteString("  fi\n")
		b.WriteString("  ip link set ")
		b.WriteString(shellQuote(input.LANIface))
		b.WriteString(" txqueuelen 1000 up || die \"bring up managed LAN interface\"\n")
		b.WriteString("else\n")
		b.WriteString("  die \"ip command is required for managed LAN interface setup\"\n")
		b.WriteString("fi\n")
	}
	b.WriteString("build_args=(--out \"${repo_root}/build/release\" --version ")
	b.WriteString(shellQuote("provision-" + string(input.IXID)))
	b.WriteString(" --build-bpf ")
	b.WriteString(shellQuote(input.BuildBPF))
	b.WriteString(" --build-ko ")
	b.WriteString(shellQuote(input.BuildKO))
	b.WriteString(" --json)\n")
	if input.BuildWebUI == "0" {
		b.WriteString("build_args+=(--skip-webui)\n")
	}
	if input.GOArch != "" {
		b.WriteString("build_args+=(--goarch ")
		b.WriteString(shellQuote(input.GOArch))
		b.WriteString(")\n")
	}
	if input.KDir != "" {
		b.WriteString("build_args+=(--kdir ")
		b.WriteString(shellQuote(input.KDir))
		b.WriteString(")\n")
	}
	b.WriteString("log \"build TrustIX release\"\n")
	b.WriteString("build_json=\"$(\"${repo_root}/scripts/trustix-build.sh\" \"${build_args[@]}\")\"\n")
	b.WriteString("tarball=\"$(printf '%s' \"$build_json\" | sed -n 's/.*\"tarball\":\"\\([^\"]*\\)\".*/\\1/p')\"\n")
	b.WriteString("[[ -n \"$tarball\" ]] || die \"could not parse build tarball path\"\n")
	b.WriteString("deploy_args=(--tarball \"$tarball\" --instance ")
	b.WriteString(shellQuote(string(input.IXID)))
	b.WriteString(" --config \"$config_path\" --cert-dir \"$cert_dir\" --target-cert-dir ")
	b.WriteString(shellQuote(input.TargetCertDir))
	b.WriteString(" --api ")
	b.WriteString(shellQuote(input.APIAddr))
	b.WriteString(" --peer-api ")
	b.WriteString(shellQuote(input.PeerAPIAddr))
	b.WriteString(" --dataplane ")
	b.WriteString(shellQuote(input.Dataplane))
	b.WriteString(" --service-manager ")
	b.WriteString(shellQuote(input.ServiceManager))
	b.WriteString(" --admin-auth --json)\n")
	b.WriteString("log \"install TrustIX IX ")
	b.WriteString(shellScriptLiteral(string(input.IXID)))
	b.WriteString("\"\n")
	b.WriteString("deploy_json=\"$(\"${repo_root}/scripts/trustix-deploy.sh\" \"${deploy_args[@]}\")\"\n")
	b.WriteString("printf '{\"ix\":%s,\"config\":\"%s\",\"cert_dir\":\"%s\",\"tarball\":\"%s\",\"deploy\":%s}\\n' ")
	b.WriteString(shellQuote(string(mustJSONScalar(input.IXID))))
	b.WriteString(" \"$config_path\" \"$cert_dir\" \"$tarball\" \"$deploy_json\"\n")
	return b.String(), nil
}

func appendHereDoc(builder *strings.Builder, target, marker, content string) {
	delimiter := uniqueHereDocDelimiter(marker, content)
	builder.WriteString("cat > ")
	builder.WriteString(target)
	builder.WriteString(" <<'")
	builder.WriteString(delimiter)
	builder.WriteString("'\n")
	builder.WriteString(strings.TrimRight(content, "\n"))
	builder.WriteString("\n")
	builder.WriteString(delimiter)
	builder.WriteString("\n")
}

func uniqueHereDocDelimiter(marker, content string) string {
	base := "TRUSTIX_" + strings.ToUpper(safeProvisionFileName(marker, "PAYLOAD"))
	base = strings.ReplaceAll(base, ".", "_")
	base = strings.ReplaceAll(base, "-", "_")
	delimiter := base + "_EOF"
	for strings.Contains(content, delimiter) {
		delimiter += "_X"
	}
	return delimiter
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

func shellScriptLiteral(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	value = strings.ReplaceAll(value, "$", "\\$")
	value = strings.ReplaceAll(value, "`", "\\`")
	return value
}

func mustJSONScalar(value any) []byte {
	payload, err := json.Marshal(value)
	if err != nil {
		return []byte(`""`)
	}
	return payload
}

func ixProvisionCommand(provisionURL, token string) string {
	args := []string{"--provision-url", provisionURL, "--token", token}
	parts := []string{
		"tmp=\"$(mktemp /tmp/trustix-bootstrap.XXXXXX)\"",
		ixProvisionDownloadBootstrapCommand(ixBootstrapScriptURLs()),
		"if ! command -v bash >/dev/null 2>&1; then if command -v opkg >/dev/null 2>&1; then opkg update && opkg install bash; elif command -v apt-get >/dev/null 2>&1; then apt-get update && apt-get install -y bash; elif command -v dnf >/dev/null 2>&1; then dnf install -y bash; elif command -v yum >/dev/null 2>&1; then yum install -y bash; elif command -v apk >/dev/null 2>&1; then apk add --no-cache bash; else echo 'bash is required' >&2; rm -f \"$tmp\"; exit 127; fi; fi",
		"bash \"$tmp\"",
	}
	for _, arg := range args {
		parts[len(parts)-1] += " " + shellQuote(arg)
	}
	parts[len(parts)-1] += "; rc=$?; rm -f \"$tmp\"; [ \"$rc\" -eq 0 ]"
	return strings.Join(parts, " && \\\n")
}

func ixProvisionDownloadBootstrapCommand(urls []string) string {
	var builder strings.Builder
	builder.WriteString("ok=0; for url in")
	for _, url := range urls {
		builder.WriteByte(' ')
		builder.WriteString(shellQuote(url))
	}
	builder.WriteString("; do if (curl -fsSL --connect-timeout 8 \"$url\" -o \"$tmp\" 2>/dev/null || wget -T 12 -qO \"$tmp\" \"$url\" 2>/dev/null); then ok=1; break; fi; done; [ \"$ok\" -eq 1 ] || { echo 'download trustix bootstrap failed' >&2; rm -f \"$tmp\"; exit 1; }")
	return builder.String()
}

func ixBootstrapScriptURLs() []string {
	url := ixBootstrapScriptURL()
	return []string{
		url,
		"https://ghproxy.net/" + url,
		"https://gh-proxy.com/" + url,
		"https://ghfast.top/" + url,
		"https://gh.ddlc.top/" + url,
		"https://gh.llkk.cc/" + url,
		"https://mirror.ghproxy.com/" + url,
	}
}

func ixBootstrapScriptURL() string {
	return "https://raw.githubusercontent.com/Unicode01/TrustIX/main/scripts/trustix-bootstrap-ix.sh"
}

func (daemon *Daemon) ixProvisionBaseURL(r *http.Request) string {
	proto := firstHeaderValue(r.Header.Get("X-Forwarded-Proto"))
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	host := firstHeaderValue(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = r.Host
	}
	if host == "" {
		host = daemon.cfg.APIAddr
	}
	return strings.TrimRight(proto+"://"+host, "/")
}

func firstHeaderValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if before, _, ok := strings.Cut(value, ","); ok {
		value = before
	}
	return strings.TrimSpace(value)
}

func validateIXProvisionURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("provision_url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("provision_url scheme must be http or https")
	}
	if parsed.Host == "" {
		return fmt.Errorf("provision_url host is required")
	}
	return nil
}

func validateProvisionToggle(label, value string, allowed ...string) error {
	for _, candidate := range allowed {
		if value == candidate {
			return nil
		}
	}
	return fmt.Errorf("%s must be one of %s", label, strings.Join(allowed, ", "))
}

func defaultPath(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value != "" {
		return value
	}
	return fallback
}

func normalizedTTL(raw string) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultIXProvisionTokenTTL
	}
	ttl, err := time.ParseDuration(raw)
	if err != nil || ttl <= 0 || ttl > maxIXProvisionTokenTTL {
		return defaultIXProvisionTokenTTL
	}
	return ttl
}

func corePrefixStrings(prefixes []core.Prefix) []string {
	out := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		out = append(out, string(prefix))
	}
	return out
}

func newIXProvisionToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate provision token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func (daemon *Daemon) storeIXProvisionToken(record ixProvisionTokenRecord) error {
	daemon.provisionMu.Lock()
	defer daemon.provisionMu.Unlock()
	if err := daemon.loadIXProvisionTokensLocked(); err != nil {
		return err
	}
	daemon.pruneIXProvisionTokensLocked(time.Now().UTC())
	daemon.provisionTokens[record.Token] = record
	return daemon.persistIXProvisionTokensLocked()
}

func (daemon *Daemon) consumeIXProvisionToken(token string) (ixProvisionTokenRecord, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return ixProvisionTokenRecord{}, fmt.Errorf("provision token is required")
	}
	daemon.provisionMu.Lock()
	defer daemon.provisionMu.Unlock()
	if err := daemon.loadIXProvisionTokensLocked(); err != nil {
		return ixProvisionTokenRecord{}, err
	}
	now := time.Now().UTC()
	daemon.pruneIXProvisionTokensLocked(now)
	record, ok := daemon.provisionTokens[token]
	if !ok {
		_ = daemon.persistIXProvisionTokensLocked()
		return ixProvisionTokenRecord{}, fmt.Errorf("provision token is not found or has expired")
	}
	if !record.UsedAt.IsZero() {
		delete(daemon.provisionTokens, token)
		_ = daemon.persistIXProvisionTokensLocked()
		return ixProvisionTokenRecord{}, fmt.Errorf("provision token was already used")
	}
	if !record.ExpiresAt.After(now) {
		delete(daemon.provisionTokens, token)
		_ = daemon.persistIXProvisionTokensLocked()
		return ixProvisionTokenRecord{}, fmt.Errorf("provision token has expired")
	}
	record.UsedAt = now
	delete(daemon.provisionTokens, token)
	if err := daemon.persistIXProvisionTokensLocked(); err != nil {
		return ixProvisionTokenRecord{}, err
	}
	return record, nil
}

func (daemon *Daemon) loadIXProvisionTokensLocked() error {
	if daemon.provisionLoaded {
		return nil
	}
	if daemon.provisionTokens == nil {
		daemon.provisionTokens = make(map[string]ixProvisionTokenRecord)
	}
	path := daemon.ixProvisionTokenStorePath()
	if path == "" {
		daemon.provisionLoaded = true
		return nil
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			daemon.provisionLoaded = true
			return nil
		}
		return fmt.Errorf("read IX provision tokens: %w", err)
	}
	var store ixProvisionTokenStore
	if err := json.Unmarshal(payload, &store); err != nil {
		return fmt.Errorf("decode IX provision tokens: %w", err)
	}
	for _, record := range store.Tokens {
		if strings.TrimSpace(record.Token) == "" {
			continue
		}
		daemon.provisionTokens[record.Token] = record
	}
	daemon.provisionLoaded = true
	return nil
}

func (daemon *Daemon) persistIXProvisionTokensLocked() error {
	path := daemon.ixProvisionTokenStorePath()
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create IX provision token dir: %w", err)
	}
	records := make([]ixProvisionTokenRecord, 0, len(daemon.provisionTokens))
	for _, record := range daemon.provisionTokens {
		if record.UsedAt.IsZero() && record.ExpiresAt.After(time.Now().UTC()) {
			records = append(records, record)
		}
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].ExpiresAt.Equal(records[j].ExpiresAt) {
			return records[i].Token < records[j].Token
		}
		return records[i].ExpiresAt.Before(records[j].ExpiresAt)
	})
	payload, err := json.MarshalIndent(ixProvisionTokenStore{Tokens: records}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode IX provision tokens: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return fmt.Errorf("write IX provision token store: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace IX provision token store: %w", err)
	}
	return nil
}

func (daemon *Daemon) pruneIXProvisionTokensLocked(now time.Time) {
	for token, record := range daemon.provisionTokens {
		if !record.UsedAt.IsZero() || !record.ExpiresAt.After(now) {
			delete(daemon.provisionTokens, token)
		}
	}
}

func (daemon *Daemon) ixProvisionTokenStorePath() string {
	if strings.TrimSpace(daemon.cfg.DataDir) == "" {
		return ""
	}
	return filepath.Join(daemon.cfg.DataDir, "provision-tokens.json")
}

func trimStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func uniqueIPs(values []net.IP) []net.IP {
	seen := make(map[string]struct{}, len(values))
	out := make([]net.IP, 0, len(values))
	for _, value := range values {
		if value == nil {
			continue
		}
		addr, ok := netip.AddrFromSlice(value)
		if !ok {
			continue
		}
		key := addr.String()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, append(net.IP(nil), value...))
	}
	return out
}

func uniqueProvisionFileName(name string, seen map[string]int) string {
	if seen == nil {
		return name
	}
	base := name
	ext := ""
	if dot := strings.LastIndex(name, "."); dot > 0 {
		base = name[:dot]
		ext = name[dot:]
	}
	count := seen[name]
	seen[name] = count + 1
	if count == 0 {
		return name
	}
	for {
		candidate := fmt.Sprintf("%s-%d%s", base, count+1, ext)
		if seen[candidate] == 0 {
			seen[candidate] = 1
			return candidate
		}
		count++
	}
}

func safeProvisionFileName(value, fallback string) string {
	value = strings.TrimSpace(value)
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
		if b.Len() >= 96 {
			break
		}
	}
	out := strings.Trim(b.String(), ".-_")
	if out == "" {
		return fallback
	}
	return out
}
