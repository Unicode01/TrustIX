package daemon

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/device"
	"trustix.local/trustix/internal/pki"
	"trustix.local/trustix/internal/transport"
	securetransport "trustix.local/trustix/internal/transport/secure"
)

type deviceAccessListResponse struct {
	Enabled     bool                        `json:"enabled"`
	AddressPool string                      `json:"address_pool,omitempty"`
	LeaseTTL    string                      `json:"lease_ttl,omitempty"`
	LANs        []deviceAccessLANResponse   `json:"lans,omitempty"`
	Leases      []deviceAccessLeaseResponse `json:"leases"`
	Revoked     []deviceAccessRevokedDevice `json:"revoked,omitempty"`
	Counts      deviceAccessCounts          `json:"counts"`
}

type deviceAccessLANResponse struct {
	ID          string         `json:"id"`
	Type        config.LANType `json:"type,omitempty"`
	AddressPool string         `json:"address_pool,omitempty"`
	LeaseTTL    string         `json:"lease_ttl,omitempty"`
	Gateway     string         `json:"gateway,omitempty"`
	Advertise   []core.Prefix  `json:"advertise,omitempty"`
}

type deviceAccessCounts struct {
	Online  int `json:"online"`
	Leased  int `json:"leased"`
	Revoked int `json:"revoked"`
}

type deviceAccessLeaseResponse struct {
	Domain            string                   `json:"domain,omitempty"`
	IX                string                   `json:"ix"`
	Device            string                   `json:"device"`
	LANID             string                   `json:"lan_id,omitempty"`
	Peer              string                   `json:"peer"`
	Address           string                   `json:"address"`
	Prefix            string                   `json:"prefix"`
	AdvertisePrefixes []string                 `json:"advertise_prefixes,omitempty"`
	Endpoint          string                   `json:"endpoint,omitempty"`
	Transport         string                   `json:"transport,omitempty"`
	Encryption        string                   `json:"encryption,omitempty"`
	Online            bool                     `json:"online"`
	Revoked           bool                     `json:"revoked"`
	CertFingerprint   string                   `json:"cert_fingerprint,omitempty"`
	ExpiresAt         time.Time                `json:"expires_at,omitempty"`
	LastRX            time.Time                `json:"last_rx,omitempty"`
	LastTX            time.Time                `json:"last_tx,omitempty"`
	LastUp            time.Time                `json:"last_up,omitempty"`
	LastPong          time.Time                `json:"last_pong,omitempty"`
	Stats             transport.TransportStats `json:"stats,omitempty"`
}

type deviceAccessRevokedDevice struct {
	Fingerprint string `json:"fingerprint"`
}

type deviceAccessRevokeRequest struct {
	Device      string `json:"device,omitempty"`
	IX          string `json:"ix,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type deviceAccessIssueRequest struct {
	Device            core.DeviceID   `json:"device"`
	LANID             string          `json:"lan_id,omitempty"`
	Endpoint          core.EndpointID `json:"endpoint,omitempty"`
	EndpointAddress   string          `json:"endpoint_address,omitempty"`
	Transport         string          `json:"transport,omitempty"`
	TTL               string          `json:"ttl,omitempty"`
	DNSNames          []string        `json:"dns_names,omitempty"`
	IPAddresses       []string        `json:"ip_addresses,omitempty"`
	InterfaceName     string          `json:"interface_name,omitempty"`
	InterfaceMTU      int             `json:"interface_mtu,omitempty"`
	BootstrapRoutes   []string        `json:"bootstrap_routes,omitempty"`
	AdvertisePrefixes []string        `json:"advertise_prefixes,omitempty"`
	Routes            []string        `json:"routes,omitempty"`
	ServerName        string          `json:"server_name,omitempty"`
	Encryption        string          `json:"encryption,omitempty"`
	CryptoKeySource   string          `json:"crypto_key_source,omitempty"`
	CryptoSuites      []string        `json:"crypto_suites,omitempty"`
}

type deviceAccessIssueResponse struct {
	Domain           string            `json:"domain"`
	IX               string            `json:"ix"`
	Device           string            `json:"device"`
	LANID            string            `json:"lan_id,omitempty"`
	CertificatePEM   string            `json:"certificate_pem"`
	PrivateKeyPEM    string            `json:"private_key_pem"`
	IssuerCertPEM    string            `json:"issuer_cert_pem,omitempty"`
	TrustRootsPEM    []string          `json:"trust_roots_pem,omitempty"`
	Fingerprint      string            `json:"fingerprint"`
	NotAfter         time.Time         `json:"not_after"`
	ClientConfig     device.FileConfig `json:"client_config"`
	ClientConfigJSON string            `json:"client_config_json"`
}

type deviceAccessRevokeResponse struct {
	Applied         bool         `json:"applied"`
	Changed         bool         `json:"changed"`
	Fingerprint     string       `json:"fingerprint"`
	Device          string       `json:"device,omitempty"`
	IX              string       `json:"ix,omitempty"`
	DroppedSessions int          `json:"dropped_sessions"`
	Head            headResponse `json:"head"`
}

type deviceAccessSnapshot struct {
	Enabled     bool
	AddressPool string
	LeaseTTL    string
	LANs        []deviceAccessLANResponse
	Leases      []deviceAccessLeaseResponse
}

type deviceAccessRuntime struct {
	Lease       deviceAccessLease
	Session     transport.Session
	Runtime     *dataSessionRuntime
	Fingerprint string
	Revoked     bool
	Online      bool
}

func (daemon *Daemon) handleDeviceAccessList(w http.ResponseWriter, r *http.Request) {
	snapshot := daemon.deviceAccessSnapshot()
	revoked := daemon.deviceAccessRevokedSnapshot()
	response := deviceAccessListResponse{
		Enabled:     snapshot.Enabled,
		AddressPool: snapshot.AddressPool,
		LeaseTTL:    snapshot.LeaseTTL,
		LANs:        snapshot.LANs,
		Leases:      snapshot.Leases,
		Revoked:     revoked,
		Counts: deviceAccessCounts{
			Leased:  len(snapshot.Leases),
			Revoked: len(revoked),
		},
	}
	for _, lease := range snapshot.Leases {
		if lease.Online {
			response.Counts.Online++
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func (daemon *Daemon) handleDeviceAccessShow(w http.ResponseWriter, r *http.Request) {
	device := strings.TrimSpace(r.PathValue("device_id"))
	if device == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("device_id is required"))
		return
	}
	snapshot := daemon.deviceAccessSnapshot()
	for _, lease := range snapshot.Leases {
		if lease.Device == device || lease.Peer == device || lease.Address == device || lease.CertFingerprint == device {
			writeJSON(w, http.StatusOK, lease)
			return
		}
	}
	writeError(w, http.StatusNotFound, fmt.Errorf("device %q is not found", device))
}

func (daemon *Daemon) handleDeviceAccessIssue(w http.ResponseWriter, r *http.Request) {
	adminProofs := adminProofsFromContext(r.Context())
	if err := daemon.verifyAdminProofPolicy(adminProofs, daemon.desired.Trust); err != nil {
		writeConfigMutationError(w, err)
		return
	}
	payload, err := readLimitedBody(r.Body, 64<<10)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var request deviceAccessIssueRequest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode device access issue request: %w", err))
		return
	}
	response, err := daemon.issueDeviceAccessCertificate(request)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	setSensitiveResponseHeaders(w)
	writeJSON(w, http.StatusOK, response)
}

func (daemon *Daemon) issueDeviceAccessCertificate(request deviceAccessIssueRequest) (deviceAccessIssueResponse, error) {
	deviceID := core.DeviceID(strings.TrimSpace(string(request.Device)))
	if err := deviceID.Validate(); err != nil {
		return deviceAccessIssueResponse{}, err
	}
	daemon.configMu.RLock()
	desired := daemon.desired
	daemon.configMu.RUnlock()
	lan, err := deviceAccessLANForRequest(desired, request.LANID)
	if err != nil {
		return deviceAccessIssueResponse{}, err
	}
	ixBundle, err := pki.LoadBundle(desired.IX.CertPath, desired.IX.KeyPath)
	if err != nil {
		return deviceAccessIssueResponse{}, err
	}
	meta := pki.ParseMetadata(ixBundle.Cert)
	if meta.Role != pki.RoleIX {
		return deviceAccessIssueResponse{}, fmt.Errorf("issuer certificate role is %q, want %q", meta.Role, pki.RoleIX)
	}
	if meta.Domain != string(desired.Domain.ID) {
		return deviceAccessIssueResponse{}, fmt.Errorf("issuer certificate domain is %q, want %q", meta.Domain, desired.Domain.ID)
	}
	if meta.IX != string(desired.IX.ID) {
		return deviceAccessIssueResponse{}, fmt.Errorf("issuer certificate ix is %q, want %q", meta.IX, desired.IX.ID)
	}
	if !ixBundle.Cert.IsCA {
		return deviceAccessIssueResponse{}, fmt.Errorf("issuer IX certificate is not a CA")
	}
	ipAddresses, err := parseDeviceAccessIssueIPs(request.IPAddresses)
	if err != nil {
		return deviceAccessIssueResponse{}, err
	}
	advertisePrefixes, err := normalizeDeviceAccessIssuePrefixes(request.AdvertisePrefixes, "advertise_prefixes")
	if err != nil {
		return deviceAccessIssueResponse{}, err
	}
	if err := daemon.validateDeviceAccessIssueAdvertisePrefixes(desired, lan, advertisePrefixes); err != nil {
		return deviceAccessIssueResponse{}, err
	}
	notAfter := time.Now().UTC().AddDate(1, 0, 0)
	if ttl := strings.TrimSpace(request.TTL); ttl != "" {
		duration, err := time.ParseDuration(ttl)
		if err != nil {
			return deviceAccessIssueResponse{}, fmt.Errorf("ttl: %w", err)
		}
		if duration <= 0 {
			return deviceAccessIssueResponse{}, fmt.Errorf("ttl must be positive")
		}
		notAfter = time.Now().UTC().Add(duration)
	}
	bundle, err := pki.Issue(ixBundle, pki.IssueRequest{
		CommonName:  "TrustIX Device " + string(deviceID),
		Role:        pki.RoleDevice,
		Domain:      string(desired.Domain.ID),
		IX:          string(desired.IX.ID),
		Device:      string(deviceID),
		LANID:       lan.ID,
		Prefixes:    deviceAccessIssuePrefixStrings(advertisePrefixes),
		DNSNames:    request.DNSNames,
		IPAddresses: ipAddresses,
		NotAfter:    notAfter,
	})
	if err != nil {
		return deviceAccessIssueResponse{}, err
	}
	certPEM := string(append(append([]byte(nil), bundle.CertPEM...), ixBundle.CertPEM...))
	clientConfig, err := daemon.deviceAccessClientConfigForIssueRequest(desired, lan, request, bundle)
	if err != nil {
		return deviceAccessIssueResponse{}, err
	}
	trustRootsPEM, err := deviceAccessTrustRootsPEM(desired)
	if err != nil {
		return deviceAccessIssueResponse{}, fmt.Errorf("load device client trust roots: %w", err)
	}
	if len(trustRootsPEM) == 0 {
		return deviceAccessIssueResponse{}, fmt.Errorf("at least one trust root is required for device client config")
	}
	configJSON, err := json.MarshalIndent(clientConfig, "", "  ")
	if err != nil {
		return deviceAccessIssueResponse{}, fmt.Errorf("encode device client config: %w", err)
	}
	return deviceAccessIssueResponse{
		Domain:           string(desired.Domain.ID),
		IX:               string(desired.IX.ID),
		Device:           string(deviceID),
		LANID:            lan.ID,
		CertificatePEM:   certPEM,
		PrivateKeyPEM:    string(bundle.KeyPEM),
		IssuerCertPEM:    string(ixBundle.CertPEM),
		TrustRootsPEM:    trustRootsPEM,
		Fingerprint:      pki.CertificateFingerprintSHA256(bundle.Cert),
		NotAfter:         bundle.Cert.NotAfter.UTC(),
		ClientConfig:     clientConfig,
		ClientConfigJSON: string(configJSON),
	}, nil
}

func deviceAccessLANForRequest(desired config.Desired, rawLANID string) (config.LANConfig, error) {
	lanID := strings.TrimSpace(rawLANID)
	lans := config.DeviceAccessLANs(desired)
	if len(lans) == 0 {
		return config.LANConfig{}, fmt.Errorf("lan device_access is disabled")
	}
	if lanID == "" {
		if len(lans) == 1 {
			return lans[0], nil
		}
		return config.LANConfig{}, fmt.Errorf("lan_id is required when multiple device_access LANs are enabled")
	}
	lan, ok := config.DeviceAccessLANByID(desired, lanID)
	if !ok {
		return config.LANConfig{}, fmt.Errorf("device_access lan_id %q is not enabled", lanID)
	}
	return lan, nil
}

func deviceAccessTrustRootsPEM(desired config.Desired) ([]string, error) {
	roots := make([]string, 0, len(desired.Domain.TrustRoots)+len(desired.Trust.TrustRootsPEM))
	seen := make(map[string]struct{}, len(desired.Domain.TrustRoots)+len(desired.Trust.TrustRootsPEM))
	addRoot := func(label string, payload []byte) error {
		cert, err := pki.ParseCertificatePEM(payload)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		fingerprint := pki.CertificateFingerprintSHA256(cert)
		if _, exists := seen[fingerprint]; exists {
			return nil
		}
		seen[fingerprint] = struct{}{}
		roots = append(roots, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
		return nil
	}
	for _, path := range desired.Domain.TrustRoots {
		_, payload, err := pki.LoadCertificate(path)
		if err != nil {
			return nil, err
		}
		if err := addRoot("domain trust root "+path, payload); err != nil {
			return nil, err
		}
	}
	for index, payload := range desired.Trust.TrustRootsPEM {
		if err := addRoot(fmt.Sprintf("trust.trust_roots_pem[%d]", index), []byte(payload)); err != nil {
			return nil, err
		}
	}
	return roots, nil
}

func (daemon *Daemon) deviceAccessClientConfigForIssueRequest(desired config.Desired, lan config.LANConfig, request deviceAccessIssueRequest, bundle pki.Bundle) (device.FileConfig, error) {
	endpoint, err := daemon.deviceAccessIssueEndpoint(desired, request)
	if err != nil {
		return device.FileConfig{}, err
	}
	encryption := securetransport.NormalizeEncryptionMode(request.Encryption)
	if encryption == "" {
		encryption = daemon.endpointDialEncryption(endpoint)
	}
	if encryption == "" {
		encryption = securetransport.EncryptionSecure
	}
	keySource := strings.TrimSpace(request.CryptoKeySource)
	if keySource == "" {
		keySource = strings.TrimSpace(desired.TransportPolicy.CryptoKeySource)
	}
	if keySource == "" {
		keySource = securetransport.KeySourceAuto
	}
	interfaceName := strings.TrimSpace(request.InterfaceName)
	if interfaceName == "" {
		interfaceName = "trustix0"
	}
	mtu := request.InterfaceMTU
	if mtu == 0 {
		mtu = desired.TransportPolicy.MTU
	}
	if mtu == 0 {
		mtu = 1400
	}
	certPath := fmt.Sprintf("%s-%s.crt", desired.IX.ID, request.Device)
	keyPath := fmt.Sprintf("%s-%s.key", desired.IX.ID, request.Device)
	bootstrapRoutes := request.BootstrapRoutes
	if len(bootstrapRoutes) == 0 && len(request.Routes) > 0 {
		bootstrapRoutes = request.Routes
	}
	bootstrapRoutes, err = normalizeDeviceAccessIssueRouteStrings(bootstrapRoutes, "bootstrap_routes")
	if err != nil {
		return device.FileConfig{}, err
	}
	return device.FileConfig{
		Domain:          desired.Domain.ID,
		IX:              desired.IX.ID,
		LANID:           lan.ID,
		CertPath:        certPath,
		KeyPath:         keyPath,
		TrustRoots:      append([]string(nil), desired.Domain.TrustRoots...),
		ServerName:      strings.TrimSpace(request.ServerName),
		Encryption:      encryption,
		CryptoKeySource: keySource,
		CryptoSuites:    securetransport.CryptoSuitesOrDefault(append([]string(nil), request.CryptoSuites...)),
		Endpoint: device.FileEndpointConfig{
			Name:       endpoint.Name,
			Address:    endpoint.Address,
			Transport:  transport.Protocol(strings.ToLower(strings.TrimSpace(endpoint.Transport))),
			Encryption: encryption,
		},
		Interface: device.FileInterfaceConfig{
			Name:            interfaceName,
			MTU:             mtu,
			BootstrapRoutes: append([]string(nil), bootstrapRoutes...),
		},
		StatsEvery: "30s",
	}, nil
}

func (daemon *Daemon) deviceAccessIssueEndpoint(desired config.Desired, request deviceAccessIssueRequest) (config.EndpointConfig, error) {
	endpointName := request.Endpoint
	if endpointName == "" {
		endpointName = "device-access"
	}
	var endpoint config.EndpointConfig
	if found, ok := endpointByName(desired.Endpoints, endpointName); ok {
		endpoint = found
	} else {
		for _, candidate := range desired.Endpoints {
			if candidate.Enabled && candidate.Mode == config.EndpointModePassive {
				endpoint = candidate
				break
			}
		}
	}
	if endpoint.Name == "" {
		return config.EndpointConfig{}, fmt.Errorf("device access endpoint %q is not configured", endpointName)
	}
	address := strings.TrimSpace(request.EndpointAddress)
	if address == "" {
		address = strings.TrimSpace(endpoint.Address)
	}
	if address == "" {
		address = strings.TrimSpace(endpoint.Listen)
	}
	if address == "" {
		return config.EndpointConfig{}, fmt.Errorf("endpoint_address is required for device config")
	}
	endpoint.Address = address
	transportName := strings.ToLower(strings.TrimSpace(request.Transport))
	if transportName != "" {
		endpoint.Transport = transportName
	}
	if strings.TrimSpace(endpoint.Transport) == "" {
		endpoint.Transport = "udp"
	}
	return endpoint, nil
}

func parseDeviceAccessIssueIPs(values []string) ([]net.IP, error) {
	out := make([]net.IP, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		ip := net.ParseIP(value)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP SAN %q", value)
		}
		out = append(out, ip)
	}
	return out, nil
}

func parseDeviceAccessIssuePrefixes(values []string, label string) ([]string, error) {
	prefixes, err := normalizeDeviceAccessIssuePrefixes(values, label)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		out = append(out, prefix.String())
	}
	return out, nil
}

func normalizeDeviceAccessIssueRouteStrings(values []string, label string) ([]string, error) {
	prefixes, err := normalizeDeviceAccessIssuePrefixes(values, label)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		out = append(out, prefix.String())
	}
	return out, nil
}

func normalizeDeviceAccessIssuePrefixes(values []string, label string) ([]netip.Prefix, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make([]netip.Prefix, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("%s %q: %w", label, value, err)
		}
		prefix = prefix.Masked()
		if !prefix.Addr().Is4() {
			return nil, fmt.Errorf("%s %q must be IPv4 CIDR", label, value)
		}
		raw := prefix.String()
		if _, exists := seen[raw]; exists {
			continue
		}
		seen[raw] = struct{}{}
		out = append(out, prefix)
	}
	return out, nil
}

func deviceAccessIssuePrefixStrings(prefixes []netip.Prefix) []string {
	if len(prefixes) == 0 {
		return nil
	}
	out := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		out = append(out, prefix.Masked().String())
	}
	return out
}

type deviceAccessIssueReservedPrefix struct {
	Prefix                  netip.Prefix
	Source                  string
	AllowDelegatedSubprefix bool
}

func (daemon *Daemon) validateDeviceAccessIssueAdvertisePrefixes(desired config.Desired, lan config.LANConfig, prefixes []netip.Prefix) error {
	if len(prefixes) == 0 {
		return nil
	}
	reserved := deviceAccessIssueReservedPrefixes(desired, lan.ID)
	exportPrefixes := parsedPolicyPrefixes(desired.RoutePolicy.ExportPrefixes)
	for _, prefix := range prefixes {
		prefix = prefix.Masked()
		for _, candidate := range reserved {
			if prefixOverlaps(prefix, candidate.Prefix) {
				if candidate.AllowDelegatedSubprefix && prefixIsDelegatedSubprefix(prefix, candidate.Prefix) {
					continue
				}
				return fmt.Errorf("advertise_prefixes %q overlaps %s %q", prefix, candidate.Source, candidate.Prefix)
			}
		}
		if allowed, _ := exportPolicyAllows(prefix, exportPrefixes); !allowed {
			return fmt.Errorf("advertise_prefixes %q is not covered by route_policy.export_prefixes", prefix)
		}
	}
	daemon.dataMu.Lock()
	expiredSessions := daemon.pruneExpiredDeviceLeasesLocked(time.Now().UTC())
	for _, prefix := range prefixes {
		prefix = prefix.Masked()
		for key, lease := range daemon.deviceLeases {
			if lease.Prefix.IsValid() && prefixOverlaps(prefix, lease.Prefix.Masked()) {
				daemon.dataMu.Unlock()
				daemon.closeDroppedDataSessions(expiredSessions)
				return fmt.Errorf("advertise_prefixes %q overlaps device lease %q", prefix, lease.Prefix.Masked())
			}
			for _, advertised := range lease.AdvertisePrefixes {
				if advertised.IsValid() && prefixOverlaps(prefix, advertised.Masked()) {
					daemon.dataMu.Unlock()
					daemon.closeDroppedDataSessions(expiredSessions)
					return fmt.Errorf("advertise_prefixes %q overlaps device %s/%s prefix %q", prefix, key.IX, key.Device, advertised.Masked())
				}
			}
		}
	}
	daemon.dataMu.Unlock()
	daemon.closeDroppedDataSessions(expiredSessions)
	return nil
}

func deviceAccessIssueReservedPrefixes(desired config.Desired, lanID string) []deviceAccessIssueReservedPrefix {
	reserved := make([]deviceAccessIssueReservedPrefix, 0, len(desired.Routes)+len(config.EffectiveLANAdvertise(desired))+len(config.DeviceAccessLANs(desired)))
	for _, route := range routesFromConfig(desired) {
		prefix, err := route.Prefix.Parse()
		if err == nil {
			reserved = append(reserved, deviceAccessIssueReservedPrefix{Prefix: prefix.Masked(), Source: "static route"})
		}
	}
	for _, candidateLAN := range config.EffectiveLANs(desired) {
		for _, rawPrefix := range candidateLAN.Advertise {
			prefix, err := rawPrefix.Parse()
			if err == nil {
				reserved = append(reserved, deviceAccessIssueReservedPrefix{
					Prefix:                  prefix.Masked(),
					Source:                  "local LAN " + candidateLAN.ID,
					AllowDelegatedSubprefix: candidateLAN.ID == lanID,
				})
			}
		}
	}
	for _, lan := range config.DeviceAccessLANs(desired) {
		pool, err := netip.ParsePrefix(strings.TrimSpace(lan.DeviceAccess.AddressPool))
		if err == nil {
			reserved = append(reserved, deviceAccessIssueReservedPrefix{Prefix: pool.Masked(), Source: "device address pool " + lan.ID})
		}
	}
	return reserved
}

func (daemon *Daemon) handleDeviceAccessRevoke(w http.ResponseWriter, r *http.Request) {
	payload, err := readLimitedBody(r.Body, 4096)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var request deviceAccessRevokeRequest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode device access revoke request: %w", err))
		return
	}
	fingerprint, ix, device, err := daemon.resolveDeviceAccessRevokeTarget(request)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ctx, err := daemon.preflightConfigMutation(r.Context(), "device access revoke")
	if err != nil {
		writeConfigMutationError(w, err)
		return
	}
	daemon.configMu.RLock()
	trust := daemon.desired.Trust
	daemon.configMu.RUnlock()
	trust = config.NormalizeTrust(trust)
	seen := revokedCertificateFingerprintsFromTrust(trust)
	changed := false
	if _, ok := seen[fingerprint]; !ok {
		trust.RevokedCertFingerprints = append(trust.RevokedCertFingerprints, fingerprint)
		changed = true
	}
	droppable := daemon.countDeviceAccessSessionsByFingerprint(fingerprint)
	var applyChanged bool
	if changed {
		applyChanged, err = daemon.applyTrustConfig(ctx, trust)
		if err != nil {
			writeConfigMutationError(w, err)
			return
		}
	}
	dropped := daemon.dropDeviceAccessSessionsByFingerprint(fingerprint)
	if changed && dropped == 0 {
		dropped = droppable
	}
	if dropped > 0 {
		if err := daemon.applyRuntimeDataplaneSnapshot(ctx); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if daemon.localAdvertisementConfigured() {
			if err := daemon.refreshLocalAdvertisement(); err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
		}
	}
	daemon.configMu.RLock()
	head := daemon.head
	daemon.configMu.RUnlock()
	writeJSON(w, http.StatusOK, deviceAccessRevokeResponse{
		Applied:         true,
		Changed:         changed || applyChanged || dropped > 0,
		Fingerprint:     fingerprint,
		Device:          string(device),
		IX:              string(ix),
		DroppedSessions: dropped,
		Head:            headResponse{Seq: head.Seq, Hash: head.Hash},
	})
}

func (daemon *Daemon) resolveDeviceAccessRevokeTarget(request deviceAccessRevokeRequest) (string, core.IXID, core.DeviceID, error) {
	if strings.TrimSpace(request.Fingerprint) != "" {
		fingerprint, err := pki.NormalizeCertificateFingerprintSHA256(request.Fingerprint)
		return fingerprint, core.IXID(strings.TrimSpace(request.IX)), core.DeviceID(strings.TrimSpace(request.Device)), err
	}
	device := core.DeviceID(strings.TrimSpace(request.Device))
	ix := core.IXID(strings.TrimSpace(request.IX))
	if device == "" {
		return "", "", "", fmt.Errorf("device or fingerprint is required")
	}
	if ix == "" {
		ix = daemon.desired.IX.ID
	}
	snapshot := daemon.deviceAccessRuntimeSnapshot()
	for _, runtime := range snapshot {
		if runtime.Lease.Key.Device == device && runtime.Lease.Key.IX == ix {
			if runtime.Fingerprint == "" {
				return "", ix, device, fmt.Errorf("active device %q has no certificate fingerprint; revoke by fingerprint instead", device)
			}
			return runtime.Fingerprint, ix, device, nil
		}
	}
	return "", ix, device, fmt.Errorf("active device %q issued by %q is not found; revoke by fingerprint for offline devices", device, ix)
}

func (daemon *Daemon) deviceAccessSnapshot() deviceAccessSnapshot {
	daemon.configMu.RLock()
	lans := config.DeviceAccessLANs(daemon.desired)
	lanResponses := deviceAccessLANResponses(lans)
	var cfg config.DeviceAccessConfig
	if len(lans) == 1 {
		cfg = lans[0].DeviceAccess
	} else if len(lans) > 1 {
		cfg = lans[0].DeviceAccess
	}
	domain := daemon.desired.Domain.ID
	daemon.configMu.RUnlock()
	runtimes := daemon.deviceAccessRuntimeSnapshot()
	leases := make([]deviceAccessLeaseResponse, 0, len(runtimes))
	for _, runtime := range runtimes {
		lease := runtime.Lease
		response := deviceAccessLeaseResponse{
			Domain:            string(domain),
			IX:                string(lease.Key.IX),
			Device:            string(lease.Key.Device),
			LANID:             lease.LANID,
			Peer:              string(deviceAccessPeerID(transport.PeerIdentity{Peer: lease.Key.IX, Device: lease.Key.Device, LANID: lease.LANID})),
			Address:           lease.Address.String(),
			Prefix:            deviceAccessPrefixFromAddress(lease.Address).String(),
			AdvertisePrefixes: deviceAccessLeaseAdvertisePrefixStrings(lease),
			Endpoint:          string(lease.Endpoint.Name),
			Transport:         string(lease.Endpoint.Transport),
			Encryption:        lease.SessionKey.Encryption,
			Online:            runtime.Online,
			Revoked:           runtime.Revoked,
			CertFingerprint:   runtime.Fingerprint,
			ExpiresAt:         lease.ExpiresAt,
		}
		if runtime.Runtime != nil {
			response.LastRX = unixNanoTime(runtime.Runtime.lastRX.Load())
			response.LastTX = unixNanoTime(runtime.Runtime.lastTX.Load())
			response.LastUp = unixNanoTime(runtime.Runtime.lastUp.Load())
			response.LastPong = unixNanoTime(runtime.Runtime.lastPong.Load())
		}
		if runtime.Session != nil {
			response.Stats = runtime.Session.Stats()
		}
		leases = append(leases, response)
	}
	sort.Slice(leases, func(i, j int) bool {
		if leases[i].IX != leases[j].IX {
			return leases[i].IX < leases[j].IX
		}
		if leases[i].Device != leases[j].Device {
			return leases[i].Device < leases[j].Device
		}
		return leases[i].Address < leases[j].Address
	})
	return deviceAccessSnapshot{
		Enabled:     len(lans) > 0,
		AddressPool: cfg.AddressPool,
		LeaseTTL:    cfg.LeaseTTL,
		LANs:        lanResponses,
		Leases:      leases,
	}
}

func deviceAccessLANResponses(lans []config.LANConfig) []deviceAccessLANResponse {
	if len(lans) == 0 {
		return nil
	}
	out := make([]deviceAccessLANResponse, 0, len(lans))
	for _, lan := range lans {
		out = append(out, deviceAccessLANResponse{
			ID:          lan.ID,
			Type:        lan.Type,
			AddressPool: lan.DeviceAccess.AddressPool,
			LeaseTTL:    lan.DeviceAccess.LeaseTTL,
			Gateway:     lan.Gateway,
			Advertise:   append([]core.Prefix(nil), lan.Advertise...),
		})
	}
	return out
}

func deviceAccessLeaseAdvertisePrefixStrings(lease deviceAccessLease) []string {
	if len(lease.AdvertisePrefixes) == 0 {
		return nil
	}
	out := make([]string, 0, len(lease.AdvertisePrefixes))
	seen := make(map[string]struct{}, len(lease.AdvertisePrefixes))
	for _, prefix := range lease.AdvertisePrefixes {
		if !prefix.IsValid() || !prefix.Addr().Is4() {
			continue
		}
		raw := prefix.Masked().String()
		if _, exists := seen[raw]; exists {
			continue
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
	}
	return out
}

func (daemon *Daemon) deviceAccessRuntimeSnapshot() []deviceAccessRuntime {
	revoked := revokedCertificateFingerprints(daemon.desired)
	daemon.dataMu.Lock()
	defer daemon.dataMu.Unlock()
	runtimes := make([]deviceAccessRuntime, 0, len(daemon.deviceLeases))
	for _, lease := range daemon.deviceLeases {
		if !lease.Address.IsValid() {
			continue
		}
		session := daemon.dataSessions[lease.SessionKey]
		runtime := daemon.dataSessionState[lease.SessionKey]
		fingerprint := deviceAccessSessionFingerprint(session)
		_, isRevoked := revoked[fingerprint]
		runtimes = append(runtimes, deviceAccessRuntime{
			Lease:       lease,
			Session:     session,
			Runtime:     runtime,
			Fingerprint: fingerprint,
			Revoked:     fingerprint != "" && isRevoked,
			Online:      session != nil,
		})
	}
	return runtimes
}

func (daemon *Daemon) deviceAccessRevokedSnapshot() []deviceAccessRevokedDevice {
	daemon.configMu.RLock()
	trust := daemon.desired.Trust
	daemon.configMu.RUnlock()
	seen := revokedCertificateFingerprintsFromTrust(trust)
	out := make([]deviceAccessRevokedDevice, 0, len(seen))
	for fingerprint := range seen {
		out = append(out, deviceAccessRevokedDevice{Fingerprint: fingerprint})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Fingerprint < out[j].Fingerprint
	})
	return out
}

func (daemon *Daemon) dropDeviceAccessSessionsByFingerprint(fingerprint string) int {
	fingerprint, err := pki.NormalizeCertificateFingerprintSHA256(fingerprint)
	if err != nil {
		return 0
	}
	type dropped struct {
		session transport.Session
		runtime *dataSessionRuntime
	}
	droppedSessions := make([]dropped, 0)
	daemon.clearForwardCache()
	daemon.dataMu.Lock()
	for leaseKey, lease := range daemon.deviceLeases {
		session := daemon.dataSessions[lease.SessionKey]
		if deviceAccessSessionFingerprint(session) != fingerprint {
			continue
		}
		droppedSessions = append(droppedSessions, dropped{session: session, runtime: daemon.dataSessionState[lease.SessionKey]})
		delete(daemon.dataSessions, lease.SessionKey)
		delete(daemon.dataSessionState, lease.SessionKey)
		delete(daemon.deviceLeases, leaseKey)
		daemon.deleteSessionPoolCursorLocked(lease.SessionKey)
		daemon.deleteSessionFlowBindingsLocked(lease.SessionKey)
	}
	if len(droppedSessions) > 0 {
		daemon.dataSessionEpoch++
	}
	if len(daemon.dataSessions) == 0 {
		daemon.sessionPoolRR = nil
		daemon.sessionPoolFlow = nil
	}
	daemon.dataMu.Unlock()
	for _, item := range droppedSessions {
		if item.runtime != nil && item.runtime.cancel != nil {
			item.runtime.cancel()
		}
		if item.session != nil {
			daemon.dataStats.staleSessionsDropped.Add(1)
			_ = item.session.Close()
		}
	}
	return len(droppedSessions)
}

func (daemon *Daemon) countDeviceAccessSessionsByFingerprint(fingerprint string) int {
	fingerprint, err := pki.NormalizeCertificateFingerprintSHA256(fingerprint)
	if err != nil {
		return 0
	}
	daemon.dataMu.Lock()
	defer daemon.dataMu.Unlock()
	count := 0
	for _, lease := range daemon.deviceLeases {
		if deviceAccessSessionFingerprint(daemon.dataSessions[lease.SessionKey]) == fingerprint {
			count++
		}
	}
	return count
}

func (daemon *Daemon) dropRevokedDeviceAccessSessions() int {
	revoked := revokedCertificateFingerprints(daemon.desired)
	if len(revoked) == 0 {
		return 0
	}
	type dropped struct {
		session transport.Session
		runtime *dataSessionRuntime
	}
	droppedSessions := make([]dropped, 0)
	daemon.clearForwardCache()
	daemon.dataMu.Lock()
	for leaseKey, lease := range daemon.deviceLeases {
		fingerprint := deviceAccessSessionFingerprint(daemon.dataSessions[lease.SessionKey])
		if fingerprint == "" {
			continue
		}
		if _, ok := revoked[fingerprint]; !ok {
			continue
		}
		droppedSessions = append(droppedSessions, dropped{
			session: daemon.dataSessions[lease.SessionKey],
			runtime: daemon.dataSessionState[lease.SessionKey],
		})
		delete(daemon.dataSessions, lease.SessionKey)
		delete(daemon.dataSessionState, lease.SessionKey)
		delete(daemon.deviceLeases, leaseKey)
		daemon.deleteSessionPoolCursorLocked(lease.SessionKey)
		daemon.deleteSessionFlowBindingsLocked(lease.SessionKey)
	}
	if len(droppedSessions) > 0 {
		daemon.dataSessionEpoch++
	}
	if len(daemon.dataSessions) == 0 {
		daemon.sessionPoolRR = nil
		daemon.sessionPoolFlow = nil
	}
	daemon.dataMu.Unlock()
	for _, item := range droppedSessions {
		if item.runtime != nil && item.runtime.cancel != nil {
			item.runtime.cancel()
		}
		if item.session != nil {
			daemon.dataStats.staleSessionsDropped.Add(1)
			_ = item.session.Close()
		}
	}
	return len(droppedSessions)
}

func deviceAccessSessionFingerprint(session transport.Session) string {
	if session == nil {
		return ""
	}
	if detail, ok := session.(transport.PeerIdentityDetailSession); ok {
		if identity, ok := detail.PeerIdentityDetail(); ok && identity.Role == string(pki.RoleDevice) {
			if fingerprint, ok := deviceAccessIdentityFingerprint(identity); ok {
				return fingerprint
			}
		}
	}
	return ""
}

func deviceAccessIdentityFingerprint(identity transport.PeerIdentity) (string, bool) {
	if identity.CertFingerprint == "" {
		return "", false
	}
	fingerprint, err := pki.NormalizeCertificateFingerprintSHA256(identity.CertFingerprint)
	if err != nil {
		return "", false
	}
	return fingerprint, true
}

func deviceAccessPrefixFromAddress(addr netip.Addr) netip.Prefix {
	if !addr.IsValid() {
		return netip.Prefix{}
	}
	if addr.Is4() {
		return netip.PrefixFrom(addr, 32)
	}
	return netip.PrefixFrom(addr, 128)
}
