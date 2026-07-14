package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/configlog"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/pki"
	"trustix.local/trustix/internal/routing"
	"trustix.local/trustix/internal/transport"
	iptunneltransport "trustix.local/trustix/internal/transport/iptunnel"
)

const (
	dynamicRouteMetric                = 1000
	memberRecordTTL                   = 2 * time.Minute
	pendingMemberTTL                  = 24 * time.Hour
	defaultControlClientTimeout       = 15 * time.Second
	defaultControlClientCacheTTL      = 5 * time.Minute
	controlClientIdleConnTimeout      = 30 * time.Second
	defaultAdvertisementPushInterval  = 60 * time.Second
	defaultDynamicControlTargetFanout = 128
	edgeDynamicControlTargetFanout    = 32
	reflectorControlTargetFanout      = 256
	coreDynamicControlTargetFanout    = 512
	defaultControlMemberPageSize      = 256
	edgeControlMemberPageSize         = 128
	reflectorControlMemberPageSize    = 512
	coreControlMemberPageSize         = 1024
	maxControlMemberPageSize          = 4096
)

type cachedControlClient struct {
	client    *http.Client
	transport *http.Transport
	expiresAt time.Time
}

type cachedControlMembers struct {
	etag     string
	response membersResponse
}

type cachedAdvertisementPush struct {
	payloadHash string
	lastPush    time.Time
}

type memberRecord struct {
	Advertisement advertisementResponse `json:"advertisement"`
	LastSeen      time.Time             `json:"last_seen"`
	Source        string                `json:"source,omitempty"`
	Direct        bool                  `json:"direct"`
	Via           core.IXID             `json:"via,omitempty"`
}

type pendingMemberRecord struct {
	Advertisement advertisementResponse `json:"advertisement"`
	FirstSeen     time.Time             `json:"first_seen"`
	LastSeen      time.Time             `json:"last_seen"`
	Source        string                `json:"source,omitempty"`
	RejectReason  string                `json:"reject_reason,omitempty"`
}

type pendingAdmissionError struct {
	err error
}

func (err pendingAdmissionError) Error() string {
	if err.err == nil {
		return "IX admission is pending"
	}
	return err.err.Error()
}

func (err pendingAdmissionError) Unwrap() error {
	return err.err
}

func isPendingAdmissionError(err error) bool {
	var pending pendingAdmissionError
	return errors.As(err, &pending)
}

type membersResponse struct {
	Members    []advertisementResponse `json:"members"`
	NextCursor string                  `json:"next_cursor,omitempty"`
	Limit      int                     `json:"limit,omitempty"`
	Total      int                     `json:"total,omitempty"`
	Truncated  bool                    `json:"truncated,omitempty"`
}

type persistedMembers struct {
	Version int            `json:"version"`
	Members []memberRecord `json:"members"`
}

type persistedPendingMembers struct {
	Version int                   `json:"version"`
	Pending []pendingMemberRecord `json:"pending"`
}

type prefixOwnerIndex struct {
	v4 prefixOwnerTrieNode
	v6 prefixOwnerTrieNode
}

type prefixOwnerTrieNode struct {
	child [2]*prefixOwnerTrieNode

	terminalSet   bool
	terminalOwner core.IXID
	terminalMixed bool

	subtreeSet   bool
	subtreeOwner core.IXID
	subtreeMixed bool
}

type runtimeDataplaneProjection struct {
	Routes          []routing.Route
	Peers           []dataplane.PeerMetadata
	Endpoints       []dataplane.EndpointMetadata
	NAT             *dataplane.NATSnapshot
	RoutePolicy     []routePolicyDecision
	RouteCandidates []routeCandidate
}

type runtimeProjectionOptions struct {
	IncludeRouteCandidates bool
}

type routePolicyStatus struct {
	Config             config.RoutePolicyConfig `json:"config"`
	Decisions          []routePolicyDecision    `json:"decisions"`
	Candidates         []routeCandidate         `json:"candidates,omitempty"`
	DecisionTotal      int                      `json:"decision_total,omitempty"`
	DecisionOffset     int                      `json:"decision_offset,omitempty"`
	DecisionLimit      int                      `json:"decision_limit,omitempty"`
	DecisionTruncated  bool                     `json:"decision_truncated,omitempty"`
	CandidateTotal     int                      `json:"candidate_total,omitempty"`
	CandidateOffset    int                      `json:"candidate_offset,omitempty"`
	CandidateLimit     int                      `json:"candidate_limit,omitempty"`
	CandidateTruncated bool                     `json:"candidate_truncated,omitempty"`
}

type routePolicyDecision struct {
	Direction string      `json:"direction"`
	IXID      core.IXID   `json:"ix_id"`
	OriginIX  core.IXID   `json:"origin_ix,omitempty"`
	NextHopIX core.IXID   `json:"next_hop_ix,omitempty"`
	Prefix    core.Prefix `json:"prefix"`
	Action    string      `json:"action"`
	Reason    string      `json:"reason,omitempty"`
	Source    string      `json:"source,omitempty"`
}

type routeCandidate struct {
	Prefix         core.Prefix       `json:"prefix"`
	Owner          core.IXID         `json:"owner,omitempty"`
	OriginIX       core.IXID         `json:"origin_ix,omitempty"`
	NextHop        core.IXID         `json:"next_hop,omitempty"`
	LearnedFrom    core.IXID         `json:"learned_from,omitempty"`
	Endpoint       core.EndpointID   `json:"endpoint,omitempty"`
	Kind           routing.RouteKind `json:"kind,omitempty"`
	Metric         int               `json:"metric,omitempty"`
	Source         string            `json:"source,omitempty"`
	SourcePriority int               `json:"source_priority,omitempty"`
	Action         string            `json:"action"`
	Reason         string            `json:"reason,omitempty"`
	Health         string            `json:"health,omitempty"`
	Selected       bool              `json:"selected,omitempty"`
	Direct         bool              `json:"direct,omitempty"`
	Static         bool              `json:"static,omitempty"`
	LastSeen       time.Time         `json:"last_seen,omitempty"`
	Path           []core.IXID       `json:"path,omitempty"`
}

type knownRoutePrefix struct {
	Static bool
}

func recordKnownRoutePrefix(known map[string]knownRoutePrefix, prefix string, source string) {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return
	}
	record := known[prefix]
	record.Static = record.Static || source == "static"
	known[prefix] = record
}

func duplicateRouteCandidateStatus(known knownRoutePrefix) (action string, reason string, health string) {
	if known.Static {
		return "shadow", "shadowed_by_static", "shadowed"
	}
	return "reject", "duplicate_prefix", "blocked"
}

type advertisementSigningPayload struct {
	DomainID            string                       `json:"domain_id"`
	IXID                string                       `json:"ix_id"`
	ConfigHead          headResponse                 `json:"config_head"`
	ControlAPI          string                       `json:"control_api,omitempty"`
	Management          *managementAdvertisement     `json:"management,omitempty"`
	LANPrefixes         []string                     `json:"lan_prefixes"`
	AnnouncedPrefixes   []announcedPrefix            `json:"announced_prefixes,omitempty"`
	Endpoints           []dataplane.EndpointMetadata `json:"endpoints"`
	IXCertificate       []byte                       `json:"ix_certificate,omitempty"`
	RouteAuthorizations [][]byte                     `json:"route_authorizations,omitempty"`
	IssuedAt            time.Time                    `json:"issued_at,omitempty"`
}

type controlTarget struct {
	ID         core.IXID
	Domain     core.DomainID
	ControlAPI string
	Static     bool
}

type tunnelEndpointSpec struct {
	localUnderlay netip.Addr
	underlayIf    string
	carrierPort   uint16
	mtu           int
	vni           int
	vxlanPort     uint16
	queues        int
}

func (daemon *Daemon) refreshLocalAdvertisement() error {
	advertisement, err := daemon.buildLocalAdvertisement()
	if err != nil {
		return err
	}
	daemon.membershipMu.Lock()
	defer daemon.membershipMu.Unlock()
	daemon.localAd = advertisement
	daemon.members[daemon.desired.IX.ID] = memberRecord{
		Advertisement: advertisement,
		LastSeen:      time.Now().UTC(),
		Source:        "local",
		Direct:        true,
	}
	return nil
}

func (daemon *Daemon) buildLocalAdvertisement() (advertisementResponse, error) {
	return daemon.buildLocalAdvertisementForDesired(daemon.desired, daemon.head, controlTarget{})
}

func (daemon *Daemon) localAdvertisementForTarget(target controlTarget) (advertisementResponse, error) {
	if target.ID == "" || !endpointPublishPolicyConfigured(daemon.desired.Endpoints) {
		daemon.membershipMu.RLock()
		advertisement := daemon.localAd
		daemon.membershipMu.RUnlock()
		return advertisement, nil
	}
	daemon.configMu.RLock()
	desired := daemon.desired
	head := daemon.head
	daemon.configMu.RUnlock()
	return daemon.buildLocalAdvertisementForDesired(desired, head, target)
}

func (daemon *Daemon) buildLocalAdvertisementForDesired(desired config.Desired, head configlog.Head, target controlTarget) (advertisementResponse, error) {
	bundle, err := pki.LoadBundle(desired.IX.CertPath, desired.IX.KeyPath)
	if err != nil {
		return advertisementResponse{}, err
	}
	if err := daemon.verifyCertificateNotRevoked(bundle.Cert, "local IX certificate"); err != nil {
		return advertisementResponse{}, err
	}
	routeAuthorizations := make([][]byte, 0, len(desired.IX.RouteAuthorizations))
	for _, path := range desired.IX.RouteAuthorizations {
		cert, _, err := pki.LoadCertificate(path)
		if err != nil {
			return advertisementResponse{}, err
		}
		if err := daemon.verifyCertificateNotRevoked(cert, "local route authorization certificate"); err != nil {
			return advertisementResponse{}, err
		}
		routeAuthorizations = append(routeAuthorizations, cert.Raw)
	}
	lanPrefixes := daemon.localAdvertisementPrefixStringsForDesired(desired)
	advertisement := advertisementResponse{
		DomainID:            string(desired.Domain.ID),
		IXID:                string(desired.IX.ID),
		ConfigHead:          headResponse{Seq: head.Seq, Hash: head.Hash},
		ControlAPI:          daemon.advertisedControlAPIForDesired(desired),
		Management:          daemon.localManagementAdvertisementForDesired(desired),
		LANPrefixes:         lanPrefixes,
		AnnouncedPrefixes:   localAnnouncedPrefixesForPrefixStrings(desired.IX.ID, lanPrefixes),
		Endpoints:           daemon.localAdvertisementEndpointsForDesiredTarget(desired, target),
		IXCertificate:       bundle.Cert.Raw,
		RouteAuthorizations: routeAuthorizations,
		IssuedAt:            time.Now().UTC(),
	}
	signingBytes, err := advertisementSigningBytes(advertisement)
	if err != nil {
		return advertisementResponse{}, err
	}
	signature, err := pki.Sign(bundle.Key, signingBytes)
	if err != nil {
		return advertisementResponse{}, err
	}
	advertisement.Signature = signature
	return advertisement, nil
}

func endpointPublishPolicyConfigured(endpoints []config.EndpointConfig) bool {
	for _, endpoint := range endpoints {
		publish := endpoint.Publish
		if strings.TrimSpace(publish.Mode) != "" || len(publish.OnlyPeers) > 0 || len(publish.ExceptPeers) > 0 || len(publish.Domains) > 0 {
			return true
		}
	}
	return false
}

func (daemon *Daemon) advertisedControlAPI() string {
	return daemon.advertisedControlAPIForDesired(daemon.desired)
}

func (daemon *Daemon) advertisedControlAPIForDesired(desired config.Desired) string {
	if strings.EqualFold(strings.TrimSpace(desired.IX.ControlAPIPublish), "disabled") {
		return ""
	}
	if desired.IX.ControlAPI != "" {
		return desired.IX.ControlAPI
	}
	if daemon.cfg.PeerAPIAddr == "" {
		return ""
	}
	if strings.Contains(daemon.cfg.PeerAPIAddr, "://") {
		return daemon.cfg.PeerAPIAddr
	}
	return "https://" + daemon.cfg.PeerAPIAddr
}

func (daemon *Daemon) localManagementAdvertisement() *managementAdvertisement {
	return daemon.localManagementAdvertisementForDesired(daemon.desired)
}

func (daemon *Daemon) localManagementAdvertisementForDesired(desired config.Desired) *managementAdvertisement {
	if !desired.Management.HostAPI.Enabled {
		return nil
	}
	host, port, ok := daemon.managementHostAPIAdvertisedHostPortForDesired(desired)
	if !ok {
		return nil
	}
	return &managementAdvertisement{
		HostAPI: &hostAPIAdvertisement{
			IP:        host.String(),
			Port:      port,
			ReadAuth:  managementHostAPIReadAuthRequiredForDesired(desired),
			WriteAuth: daemon.managementHostAPIWriteAuthRequiredForDesired(desired),
		},
	}
}

func (daemon *Daemon) managementHostAPIAdvertisedHostPort() (netip.Addr, string, bool) {
	return daemon.managementHostAPIAdvertisedHostPortForDesired(daemon.desired)
}

func (daemon *Daemon) managementHostAPIAdvertisedHostPortForDesired(desired config.Desired) (netip.Addr, string, bool) {
	if !desired.Management.HostAPI.Enabled {
		return netip.Addr{}, "", false
	}
	listen, err := managementHostAPIListenAddressForDesired(desired, daemon.cfg.APIAddr)
	if err != nil {
		return netip.Addr{}, "", false
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return netip.Addr{}, "", false
	}
	host = strings.Trim(host, "[]")
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.Is4() {
		return netip.Addr{}, "", false
	}
	if addr.IsUnspecified() {
		gateway, ok := managementAdvertisementGatewayAddr(desired)
		if !ok {
			return netip.Addr{}, "", false
		}
		addr = gateway
	}
	return addr, port, true
}

func managementAdvertisementGatewayAddr(desired config.Desired) (netip.Addr, bool) {
	lan, ok := config.FirstLANGatewayLAN(desired)
	if !ok {
		return netip.Addr{}, false
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(lan.Gateway))
	if err != nil || !prefix.Addr().Is4() || prefix.Addr().IsUnspecified() {
		return netip.Addr{}, false
	}
	return prefix.Addr(), true
}

func (daemon *Daemon) localAdvertisementEndpoints() []dataplane.EndpointMetadata {
	return daemon.localAdvertisementEndpointsForTarget(controlTarget{})
}

func (daemon *Daemon) localAdvertisementEndpointsForTarget(target controlTarget) []dataplane.EndpointMetadata {
	return daemon.localAdvertisementEndpointsForDesiredTarget(daemon.desired, target)
}

func (daemon *Daemon) localAdvertisementEndpointsForDesiredTarget(desired config.Desired, target controlTarget) []dataplane.EndpointMetadata {
	endpoints := make([]dataplane.EndpointMetadata, 0, len(desired.Endpoints))
	for _, endpoint := range desired.Endpoints {
		if !endpointPublishedToTarget(endpoint, target) {
			continue
		}
		metadata := dataplane.EndpointMetadata{
			ID:        endpoint.Name,
			Peer:      desired.IX.ID,
			Transport: endpoint.Transport,
			Address:   advertisedEndpointAddress(endpoint),
			Priority:  endpoint.Priority,
			Enabled:   endpoint.Enabled,
			Security:  endpointSecurityMetadataForPolicy(endpoint, desired.TransportPolicy),
			Profile:   endpointTransportProfileMetadataForDesired(endpoint, desired),
			Access:    endpointAccessMetadataFromConfig(endpoint.Access),
		}
		if !daemon.endpointTransportUsable(metadata) {
			metadata.Enabled = false
		}
		endpoints = append(endpoints, metadata)
	}
	return endpoints
}

func advertisedEndpointAddress(endpoint config.EndpointConfig) string {
	if transportProtocolIsKernelTunnel(endpoint.Transport) {
		return strings.TrimSpace(firstNonEmpty(endpoint.Address, endpoint.Listen))
	}
	if endpoint.Mode == config.EndpointModeActive {
		return ""
	}
	return endpoint.Address
}

func endpointPublishedToTarget(endpoint config.EndpointConfig, target controlTarget) bool {
	publish := endpoint.Publish
	mode := strings.ToLower(strings.TrimSpace(publish.Mode))
	switch mode {
	case "private", "disabled", "none":
		return false
	}
	if len(publish.Domains) > 0 {
		if target.Domain == "" {
			return false
		}
		found := false
		for _, domain := range publish.Domains {
			if domain == target.Domain {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(publish.OnlyPeers) > 0 || mode == "allowlist" || mode == "only" {
		if target.ID == "" {
			return false
		}
		for _, peer := range publish.OnlyPeers {
			if peer == target.ID {
				return true
			}
		}
		return false
	}
	if len(publish.ExceptPeers) > 0 || mode == "denylist" || mode == "except" {
		for _, peer := range publish.ExceptPeers {
			if target.ID != "" && peer == target.ID {
				return false
			}
		}
	}
	return true
}

func advertisementSigningBytes(advertisement advertisementResponse) ([]byte, error) {
	payload := advertisementSigningPayload{
		DomainID:            advertisement.DomainID,
		IXID:                advertisement.IXID,
		ConfigHead:          advertisement.ConfigHead,
		ControlAPI:          advertisement.ControlAPI,
		Management:          advertisement.Management,
		LANPrefixes:         advertisement.LANPrefixes,
		AnnouncedPrefixes:   advertisement.AnnouncedPrefixes,
		Endpoints:           advertisement.Endpoints,
		IXCertificate:       advertisement.IXCertificate,
		RouteAuthorizations: advertisement.RouteAuthorizations,
		IssuedAt:            advertisement.IssuedAt,
	}
	return json.Marshal(payload)
}

func (daemon *Daemon) verifyAdvertisement(advertisement advertisementResponse) error {
	cert, err := daemon.verifyAdvertisementBase(advertisement)
	if err != nil {
		return err
	}
	return daemon.verifyAdmissionForAdvertisement(advertisement, cert)
}

func (daemon *Daemon) verifyAdvertisementBase(advertisement advertisementResponse) (*x509.Certificate, error) {
	if advertisement.DomainID != string(daemon.desired.Domain.ID) {
		return nil, fmt.Errorf("advertisement domain is %q, want %q", advertisement.DomainID, daemon.desired.Domain.ID)
	}
	ixID := core.IXID(advertisement.IXID)
	if err := ixID.Validate(); err != nil {
		return nil, err
	}
	if len(advertisement.IXCertificate) == 0 {
		return nil, fmt.Errorf("advertisement %q has no IX certificate", advertisement.IXID)
	}
	cert, err := x509.ParseCertificate(advertisement.IXCertificate)
	if err != nil {
		return nil, fmt.Errorf("parse advertisement IX certificate: %w", err)
	}
	if err := daemon.verifyCertificateNotRevoked(cert, "advertisement IX certificate"); err != nil {
		return nil, err
	}
	meta := pki.ParseMetadata(cert)
	if meta.Role != pki.RoleIX {
		return nil, fmt.Errorf("advertisement certificate role is %q, want %q", meta.Role, pki.RoleIX)
	}
	if meta.Domain != advertisement.DomainID {
		return nil, fmt.Errorf("advertisement certificate domain is %q, want %q", meta.Domain, advertisement.DomainID)
	}
	if meta.IX != advertisement.IXID {
		return nil, fmt.Errorf("advertisement certificate ix is %q, want %q", meta.IX, advertisement.IXID)
	}
	roots, err := daemon.trustRootCertificates()
	if err != nil {
		return nil, err
	}
	if err := pki.VerifyChain(cert, roots, nil); err != nil {
		return nil, fmt.Errorf("verify advertisement IX certificate: %w", err)
	}
	signingBytes, err := advertisementSigningBytes(advertisement)
	if err != nil {
		return nil, err
	}
	if err := pki.Verify(cert, signingBytes, advertisement.Signature); err != nil {
		return nil, fmt.Errorf("verify advertisement signature: %w", err)
	}
	if advertisement.ControlAPI != "" {
		if err := validateControlAPI(advertisement.ControlAPI); err != nil {
			return nil, fmt.Errorf("advertisement control_api: %w", err)
		}
	}
	if err := validateManagementAdvertisement(advertisement.Management); err != nil {
		return nil, err
	}
	if err := validateAdvertisementAnnouncements(advertisement); err != nil {
		return nil, err
	}
	if err := daemon.verifyAdvertisedRouteAuthorizations(advertisement, roots); err != nil {
		return nil, err
	}
	for _, endpoint := range advertisement.Endpoints {
		if strings.TrimSpace(string(endpoint.ID)) == "" {
			return nil, fmt.Errorf("advertisement %q endpoint without id", advertisement.IXID)
		}
		if endpoint.Peer != ixID {
			return nil, fmt.Errorf("advertisement %q endpoint %q owner is %q", advertisement.IXID, endpoint.ID, endpoint.Peer)
		}
		if strings.TrimSpace(endpoint.Transport) == "" {
			return nil, fmt.Errorf("advertisement %q endpoint %q transport is empty", advertisement.IXID, endpoint.ID)
		}
		if _, ok := daemon.transports.Get(transport.Protocol(endpoint.Transport)); !ok {
			continue
		}
	}
	return cert, nil
}

func validateManagementAdvertisement(management *managementAdvertisement) error {
	if management == nil || management.HostAPI == nil {
		return nil
	}
	if strings.TrimSpace(management.HostAPI.IP) == "" {
		return fmt.Errorf("management host_api advertisement ip is required")
	}
	if _, err := netip.ParseAddr(management.HostAPI.IP); err != nil {
		return fmt.Errorf("management host_api advertisement ip %q is invalid: %w", management.HostAPI.IP, err)
	}
	if strings.TrimSpace(management.HostAPI.Port) == "" {
		return fmt.Errorf("management host_api advertisement port is required")
	}
	return nil
}

func validateAdvertisementAnnouncements(advertisement advertisementResponse) error {
	ixID := core.IXID(advertisement.IXID)
	for _, announcement := range advertisement.AnnouncedPrefixes {
		if strings.TrimSpace(string(announcement.Prefix)) == "" {
			return fmt.Errorf("advertisement %q announced prefix is empty", advertisement.IXID)
		}
		if _, err := announcement.Prefix.Parse(); err != nil {
			return fmt.Errorf("advertisement %q announced prefix %q: %w", advertisement.IXID, announcement.Prefix, err)
		}
		origin := announcement.OriginIX
		if origin == "" {
			origin = ixID
		}
		if err := origin.Validate(); err != nil {
			return fmt.Errorf("advertisement %q announced prefix %q origin_ix: %w", advertisement.IXID, announcement.Prefix, err)
		}
		if origin != ixID {
			return fmt.Errorf("advertisement %q announced prefix %q origin_ix is %q, want %q", advertisement.IXID, announcement.Prefix, origin, ixID)
		}
		if announcement.NextHopIX != "" {
			if err := announcement.NextHopIX.Validate(); err != nil {
				return fmt.Errorf("advertisement %q announced prefix %q next_hop_ix: %w", advertisement.IXID, announcement.Prefix, err)
			}
			if announcement.NextHopIX != ixID {
				return fmt.Errorf("advertisement %q announced prefix %q next_hop_ix is %q, want %q", advertisement.IXID, announcement.Prefix, announcement.NextHopIX, ixID)
			}
		}
		if announcement.Metric < 0 {
			return fmt.Errorf("advertisement %q announced prefix %q has negative metric", advertisement.IXID, announcement.Prefix)
		}
		for index, hop := range announcement.Path {
			if err := hop.Validate(); err != nil {
				return fmt.Errorf("advertisement %q announced prefix %q path[%d]: %w", advertisement.IXID, announcement.Prefix, index, err)
			}
			if index == 0 && hop != ixID {
				return fmt.Errorf("advertisement %q announced prefix %q path starts with %q, want %q", advertisement.IXID, announcement.Prefix, hop, ixID)
			}
		}
	}
	return nil
}

func (daemon *Daemon) verifyAdvertisedRouteAuthorizations(advertisement advertisementResponse, roots []*x509.Certificate) error {
	rawAdvertised := corePrefixesFromAdvertisement(advertisement)
	if len(rawAdvertised) == 0 {
		return nil
	}
	if len(advertisement.RouteAuthorizations) == 0 {
		return fmt.Errorf("advertisement %q has LAN prefixes but no route authorization certificates", advertisement.IXID)
	}
	advertised := make([]netip.Prefix, 0, len(rawAdvertised))
	for _, rawPrefix := range rawAdvertised {
		parsed, err := rawPrefix.Parse()
		if err != nil {
			return fmt.Errorf("advertisement %q prefix %q: %w", advertisement.IXID, rawPrefix, err)
		}
		advertised = append(advertised, parsed.Masked())
	}
	authorized := make([]netip.Prefix, 0, len(advertisement.RouteAuthorizations))
	for _, rawCert := range advertisement.RouteAuthorizations {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return fmt.Errorf("parse route authorization from %q: %w", advertisement.IXID, err)
		}
		if err := daemon.verifyCertificateNotRevoked(cert, "advertised route authorization certificate"); err != nil {
			return err
		}
		if err := pki.VerifyChain(cert, roots, nil); err != nil {
			return fmt.Errorf("verify route authorization from %q: %w", advertisement.IXID, err)
		}
		now := time.Now()
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return fmt.Errorf("route authorization from %q is not currently valid", advertisement.IXID)
		}
		meta := pki.ParseMetadata(cert)
		if meta.Role != pki.RoleRouteAuthorization {
			return fmt.Errorf("route authorization from %q role is %q, want %q", advertisement.IXID, meta.Role, pki.RoleRouteAuthorization)
		}
		if meta.Domain != advertisement.DomainID {
			return fmt.Errorf("route authorization from %q domain is %q, want %q", advertisement.IXID, meta.Domain, advertisement.DomainID)
		}
		if meta.IX != advertisement.IXID {
			return fmt.Errorf("route authorization from %q ix is %q, want %q", advertisement.IXID, meta.IX, advertisement.IXID)
		}
		for _, rawPrefix := range meta.Prefixes {
			parsed, err := netip.ParsePrefix(rawPrefix)
			if err != nil {
				return fmt.Errorf("route authorization from %q prefix %q: %w", advertisement.IXID, rawPrefix, err)
			}
			authorized = append(authorized, parsed.Masked())
		}
	}
	for _, prefix := range advertised {
		if !prefixCovered(prefix, authorized) {
			return fmt.Errorf("advertised prefix %q is not covered by route authorization from %q", prefix, advertisement.IXID)
		}
	}
	return nil
}

func validateControlAPI(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("%q is invalid", value)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("scheme %q is unsupported", parsed.Scheme)
	}
	return nil
}

func (daemon *Daemon) trustRootCertificates() ([]*x509.Certificate, error) {
	return daemon.trustRootCertificatesWithTrust(daemon.desired.Trust)
}

func (daemon *Daemon) trustRootCertificatesWithTrust(trust config.TrustConfig) ([]*x509.Certificate, error) {
	roots := make([]*x509.Certificate, 0, len(daemon.desired.Domain.TrustRoots)+len(trust.TrustRootsPEM))
	seen := make(map[string]struct{}, len(daemon.desired.Domain.TrustRoots)+len(trust.TrustRootsPEM))
	revoked := revokedCertificateFingerprintsFromTrust(trust)
	for _, path := range daemon.desired.Domain.TrustRoots {
		cert, _, err := pki.LoadCertificate(path)
		if err != nil {
			return nil, err
		}
		fingerprint := pki.CertificateFingerprintSHA256(cert)
		if _, ok := revoked[fingerprint]; ok {
			continue
		}
		if _, exists := seen[fingerprint]; exists {
			continue
		}
		seen[fingerprint] = struct{}{}
		roots = append(roots, cert)
	}
	for i, payload := range trust.TrustRootsPEM {
		cert, err := pki.ParseCertificatePEM([]byte(payload))
		if err != nil {
			return nil, fmt.Errorf("parse domain trust root %d: %w", i, err)
		}
		fingerprint := pki.CertificateFingerprintSHA256(cert)
		if _, ok := revoked[fingerprint]; ok {
			continue
		}
		if _, exists := seen[fingerprint]; exists {
			continue
		}
		seen[fingerprint] = struct{}{}
		roots = append(roots, cert)
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("no active trust root certificates")
	}
	return roots, nil
}

type mergeAdvertisementOptions struct {
	refreshSeen bool
	direct      bool
	via         core.IXID
}

func (daemon *Daemon) mergeAdvertisement(advertisement advertisementResponse, source string) (bool, error) {
	return daemon.mergeAdvertisementWithOptions(advertisement, source, mergeAdvertisementOptions{refreshSeen: true, direct: true})
}

func (daemon *Daemon) mergeAdvertisementFromControlTarget(advertisement advertisementResponse, target controlTarget) (bool, error) {
	direct := advertisementMatchesControlTarget(advertisement, target)
	var via core.IXID
	if !direct {
		via = target.ID
	}
	return daemon.mergeAdvertisementWithOptions(advertisement, target.ControlAPI, mergeAdvertisementOptions{refreshSeen: direct, direct: direct, via: via})
}

func (daemon *Daemon) mergeAdvertisementWithOptions(advertisement advertisementResponse, source string, options mergeAdvertisementOptions) (bool, error) {
	cert, err := daemon.verifyAdvertisementBase(advertisement)
	if err != nil {
		return false, err
	}
	if err := daemon.verifyAdmissionForAdvertisement(advertisement, cert); err != nil {
		daemon.recordPendingMember(advertisement, source, err)
		return false, pendingAdmissionError{err: err}
	}
	ixID := core.IXID(advertisement.IXID)
	if ixID == daemon.desired.IX.ID {
		daemon.deletePendingMember(ixID)
		return false, nil
	}
	via := options.via
	if options.direct || via == ixID || via == daemon.desired.IX.ID {
		via = ""
	}
	if _, err := daemon.registerConfigSignerCertificate(cert, true); err != nil {
		return false, err
	}

	pendingChanged := false
	now := time.Now().UTC()
	daemon.membershipMu.Lock()
	existing, exists := daemon.members[ixID]
	sessionSurfaceChanged := !exists || !advertisementDataSessionSurfacesEqual(existing.Advertisement, advertisement)
	lastSeen := existing.LastSeen
	if !exists || options.refreshSeen || lastSeen.IsZero() {
		lastSeen = now
	}
	direct := existing.Direct || options.direct
	if direct {
		via = ""
	} else if via == "" {
		via = existing.Via
	}
	recordSource := existing.Source
	if !exists || options.refreshSeen || recordSource == "" {
		recordSource = source
	}
	if exists && !advertisementNewer(existing.Advertisement, advertisement) {
		recordChanged := !existing.LastSeen.Equal(lastSeen) || existing.Source != recordSource || existing.Direct != direct || existing.Via != via
		runtimeChanged := existing.Direct != direct || existing.Via != via
		if recordChanged {
			existing.LastSeen = lastSeen
			existing.Source = recordSource
			existing.Direct = direct
			existing.Via = via
			daemon.members[ixID] = existing
		}
		if _, ok := daemon.pendingMembers[ixID]; ok {
			delete(daemon.pendingMembers, ixID)
			pendingChanged = true
		}
		daemon.membershipMu.Unlock()
		if recordChanged {
			if err := daemon.persistMembers(); err != nil {
				return false, err
			}
		}
		if pendingChanged {
			if err := daemon.persistPendingMembers(); err != nil {
				return false, err
			}
		}
		return runtimeChanged, nil
	}
	daemon.members[ixID] = memberRecord{
		Advertisement: advertisement,
		LastSeen:      lastSeen,
		Source:        recordSource,
		Direct:        direct,
		Via:           via,
	}
	if _, ok := daemon.pendingMembers[ixID]; ok {
		delete(daemon.pendingMembers, ixID)
		pendingChanged = true
	}
	daemon.membershipMu.Unlock()
	if err := daemon.persistMembers(); err != nil {
		return false, err
	}
	if pendingChanged {
		if err := daemon.persistPendingMembers(); err != nil {
			return false, err
		}
	}
	if sessionSurfaceChanged {
		daemon.closeDataSessionsForPeers(map[core.IXID]struct{}{ixID: {}})
		daemon.clearFlowsForPeers(map[core.IXID]struct{}{ixID: {}})
	}
	return true, nil
}

func (daemon *Daemon) mergePendingAdvertisement(ixID core.IXID, source string) (bool, error) {
	daemon.membershipMu.RLock()
	record, ok := daemon.pendingMembers[ixID]
	daemon.membershipMu.RUnlock()
	if !ok {
		return false, fmt.Errorf("pending IX %q is not found", ixID)
	}
	if source == "" {
		source = record.Source
	}
	return daemon.mergeAdvertisement(record.Advertisement, source)
}

func (daemon *Daemon) recordPendingMember(advertisement advertisementResponse, source string, reason error) {
	ixID := core.IXID(advertisement.IXID)
	if ixID == "" || ixID == daemon.desired.IX.ID {
		return
	}
	now := time.Now().UTC()
	daemon.membershipMu.Lock()
	if daemon.pendingMembers == nil {
		daemon.pendingMembers = make(map[core.IXID]pendingMemberRecord)
	}
	record := daemon.pendingMembers[ixID]
	if record.FirstSeen.IsZero() {
		record.FirstSeen = now
	}
	record.LastSeen = now
	record.Advertisement = advertisement
	record.Source = source
	if reason != nil {
		record.RejectReason = reason.Error()
	}
	daemon.pendingMembers[ixID] = record
	daemon.membershipMu.Unlock()
	_ = daemon.persistPendingMembers()
}

func (daemon *Daemon) deletePendingMember(ixID core.IXID) {
	daemon.membershipMu.Lock()
	_, existed := daemon.pendingMembers[ixID]
	if existed {
		delete(daemon.pendingMembers, ixID)
	}
	daemon.membershipMu.Unlock()
	if existed {
		_ = daemon.persistPendingMembers()
	}
}

func advertisementNewer(existing, candidate advertisementResponse) bool {
	if candidate.ConfigHead.Seq != existing.ConfigHead.Seq {
		return candidate.ConfigHead.Seq > existing.ConfigHead.Seq
	}
	if candidate.ConfigHead.Hash != existing.ConfigHead.Hash {
		return true
	}
	return candidate.IssuedAt.After(existing.IssuedAt)
}

func (daemon *Daemon) runtimeSnapshotEpoch() uint64 {
	daemon.membershipMu.RLock()
	defer daemon.membershipMu.RUnlock()
	return daemon.runtimeSnapshotEpochLocked()
}

func (daemon *Daemon) runtimeSnapshotEpochLocked() uint64 {
	return daemon.head.Seq + daemon.runtimeEpoch
}

func (daemon *Daemon) runtimeDataplaneState() ([]routing.Route, []dataplane.PeerMetadata, []dataplane.EndpointMetadata) {
	daemon.membershipMu.RLock()
	defer daemon.membershipMu.RUnlock()
	projection := daemon.runtimeDataplaneProjectionLockedWithOptions(runtimeProjectionOptions{})
	return projection.Routes, projection.Peers, projection.Endpoints
}

func (daemon *Daemon) runtimeDataplaneSnapshot() dataplane.Snapshot {
	daemon.membershipMu.RLock()
	projection := daemon.runtimeDataplaneProjectionLockedWithOptions(runtimeProjectionOptions{})
	epoch := daemon.runtimeSnapshotEpochLocked()
	daemon.membershipMu.RUnlock()
	return dataplane.Snapshot{
		Epoch:         epoch,
		Routes:        projection.Routes,
		Peers:         projection.Peers,
		Endpoints:     projection.Endpoints,
		EndpointState: daemon.endpointStateSnapshot(),
		PacketPolicy:  daemon.dataplanePacketPolicy(),
		NAT:           projection.NAT,
	}
}

func (daemon *Daemon) dataplanePacketPolicy() dataplane.PacketPolicy {
	policy := dataplane.PacketPolicy{
		KernelTransportMode: daemon.kernelTransportMode(),
	}
	if daemon.desired.TransportPolicy.MTU > 0 {
		policy.MTU = uint32(daemon.desired.TransportPolicy.MTU)
	}
	policy.DropFragments = daemon.fragmentPolicyDrop()
	if mss := daemon.effectiveTCPMSSClamp(); mss > 0 {
		policy.TCPMSSClamp = uint32(mss)
	}
	return policy
}

func (daemon *Daemon) runtimeRoutePolicyStatus() routePolicyStatus {
	daemon.membershipMu.RLock()
	projection := daemon.runtimeDataplaneProjectionLocked()
	daemon.membershipMu.RUnlock()

	decisions := append(exportRoutePolicyDecisions(daemon.desired), projection.RoutePolicy...)
	sortRoutePolicyDecisions(decisions)
	candidates := append([]routeCandidate(nil), projection.RouteCandidates...)
	sortRouteCandidates(candidates)
	return routePolicyStatus{
		Config:     daemon.desired.RoutePolicy,
		Decisions:  decisions,
		Candidates: candidates,
	}
}

func (daemon *Daemon) runtimeRoutePolicyDecisions() []routePolicyDecision {
	daemon.membershipMu.RLock()
	projection := daemon.runtimeDataplaneProjectionLockedWithOptions(runtimeProjectionOptions{})
	daemon.membershipMu.RUnlock()

	decisions := append(exportRoutePolicyDecisions(daemon.desired), projection.RoutePolicy...)
	sortRoutePolicyDecisions(decisions)
	return decisions
}

func (daemon *Daemon) runtimeRoutePolicyStatusForRequest(r *http.Request) (routePolicyStatus, error) {
	status := daemon.runtimeRoutePolicyStatus()
	query := r.URL.Query()
	decisionOffset, decisionLimit, err := parseNamedPagination(query, "decision_offset", "decision_limit", 0)
	if err != nil {
		return routePolicyStatus{}, err
	}
	candidateOffset, candidateLimit, err := parseNamedPagination(query, "candidate_offset", "candidate_limit", 0)
	if err != nil {
		return routePolicyStatus{}, err
	}
	if query.Get("limit") != "" {
		_, limit, err := parsePaginationParams(r, 0)
		if err != nil {
			return routePolicyStatus{}, err
		}
		if decisionLimit == 0 {
			decisionLimit = limit
		}
		if candidateLimit == 0 {
			candidateLimit = limit
		}
	}
	status.Decisions, status.DecisionTotal, status.DecisionTruncated = paginateSlice(status.Decisions, decisionOffset, decisionLimit)
	status.DecisionOffset = decisionOffset
	status.DecisionLimit = decisionLimit
	status.Candidates, status.CandidateTotal, status.CandidateTruncated = paginateSlice(status.Candidates, candidateOffset, candidateLimit)
	status.CandidateOffset = candidateOffset
	status.CandidateLimit = candidateLimit
	return status, nil
}

func parseNamedPagination(query url.Values, offsetName, limitName string, defaultLimit int) (int, int, error) {
	offset := 0
	limit := defaultLimit
	if raw := strings.TrimSpace(query.Get(offsetName)); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 0 {
			return 0, 0, fmt.Errorf("invalid %s %q", offsetName, raw)
		}
		offset = value
	}
	if raw := strings.TrimSpace(query.Get(limitName)); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 0 {
			return 0, 0, fmt.Errorf("invalid %s %q", limitName, raw)
		}
		limit = value
	}
	if limit > maxPaginatedAPILimit {
		limit = maxPaginatedAPILimit
	}
	return offset, limit, nil
}

func (daemon *Daemon) runtimeDataplaneProjectionLocked() runtimeDataplaneProjection {
	return daemon.runtimeDataplaneProjectionLockedWithOptions(runtimeProjectionOptions{IncludeRouteCandidates: true})
}

func (daemon *Daemon) runtimeDataplaneProjectionLockedWithOptions(options runtimeProjectionOptions) runtimeDataplaneProjection {
	routes := routesFromConfig(daemon.desired)
	routes = daemon.appendLocalLANRoutes(routes)
	routes = daemon.appendDeviceAccessRoutes(routes)
	var routeCandidates []routeCandidate
	if options.IncludeRouteCandidates {
		routeCandidates = daemon.routeCandidatesForRuntimeRoutes(routes)
	}
	addRouteCandidate := func(candidate routeCandidate) {
		if options.IncludeRouteCandidates {
			routeCandidates = append(routeCandidates, candidate)
		}
	}
	peers := peersFromConfig(daemon.desired)
	peers = daemon.appendDeviceAccessPeers(peers)
	endpoints := daemon.endpointsFromConfig(daemon.desired)
	routePolicy := make([]routePolicyDecision, 0, len(daemon.members))
	importPrefixes := parsedPolicyPrefixes(daemon.desired.RoutePolicy.ImportPrefixes)
	importTransitRoutes := config.RoutePolicyImportTransitRoutesEnabled(daemon.desired.RoutePolicy)
	metric := daemon.dynamicRouteMetric()
	staticPeers := make(map[core.IXID]struct{}, len(daemon.desired.Peers))
	for _, peer := range daemon.desired.Peers {
		staticPeers[peer.ID] = struct{}{}
	}

	localAdvertise := config.EffectiveLANAdvertise(daemon.desired)
	knownPrefixes := make(map[string]knownRoutePrefix, len(routes)+len(localAdvertise))
	claimedPrefixes := newPrefixOwnerIndex()
	for _, route := range routes {
		recordKnownRoutePrefix(knownPrefixes, string(route.Prefix), route.Source)
		if prefix, err := route.Prefix.Parse(); err == nil {
			masked := prefix.Masked()
			recordKnownRoutePrefix(knownPrefixes, masked.String(), route.Source)
			claimedPrefixes.Add(routeOwner(route), masked)
		}
	}
	for _, rawPrefix := range localAdvertise {
		prefix, err := rawPrefix.Parse()
		if err == nil {
			masked := prefix.Masked()
			claimedPrefixes.Add(daemon.desired.IX.ID, masked)
			recordKnownRoutePrefix(knownPrefixes, masked.String(), "local_lan")
		}
	}
	if rawPrefix, ok := daemon.localManagementPrefixString(); ok {
		prefix, err := netip.ParsePrefix(rawPrefix)
		if err == nil {
			masked := prefix.Masked()
			claimedPrefixes.Add(daemon.desired.IX.ID, masked)
			recordKnownRoutePrefix(knownPrefixes, masked.String(), "management_vip")
		}
	}

	ids := make([]string, 0, len(daemon.members))
	for ixID := range daemon.members {
		if ixID == daemon.desired.IX.ID {
			continue
		}
		ids = append(ids, string(ixID))
	}
	sort.Strings(ids)
	for _, rawID := range ids {
		ixID := core.IXID(rawID)
		record := daemon.members[ixID]
		advertisement := record.Advertisement
		if _, exists := staticPeers[ixID]; !exists {
			peers = append(peers, dataplane.PeerMetadata{
				ID:       ixID,
				DomainID: core.DomainID(advertisement.DomainID),
				Trusted:  true,
			})
			endpoints = append(endpoints, daemon.localizeAdvertisementEndpoints(advertisement)...)
		} else {
			endpoints = append(endpoints, daemon.localizedAdvertisementEndpointsNotConfigured(ixID, advertisement)...)
		}
		managementVIP := managementVIPFromAdvertisement(advertisement)
		managementVIPPrefix := netip.Prefix{}
		if managementVIP.IsValid() && managementVIP.Is4() {
			managementVIPPrefix = netip.PrefixFrom(managementVIP, 32)
		}
		announcements := advertisementAnnouncements(advertisement)
		managementVIPCovered := managementVIPCoveredByAdvertisedPrefix(managementVIPPrefix, announcementPrefixStrings(announcements))
		for _, announcement := range announcements {
			rawPrefix := strings.TrimSpace(string(announcement.Prefix))
			prefix, err := netip.ParsePrefix(rawPrefix)
			if err != nil {
				routePolicy = append(routePolicy, routePolicyDecision{
					Direction: "import",
					IXID:      announcement.OriginIX,
					OriginIX:  announcement.OriginIX,
					NextHopIX: record.Via,
					Prefix:    core.Prefix(rawPrefix),
					Action:    "reject",
					Reason:    "invalid_prefix",
					Source:    record.Source,
				})
				addRouteCandidate(routeCandidateFromAnnouncement(announcement, record, core.Prefix(rawPrefix), "", routing.RouteUnicast, metric+announcement.Metric, "reject", "invalid_prefix", "down"))
				continue
			}
			prefix = prefix.Masked()
			originIX := announcement.OriginIX
			if originIX == "" {
				originIX = ixID
			}
			nextHop := daemon.routeNextHopForMemberRecord(ixID, record, staticPeers)
			if nextHop == "" && announcement.NextHopIX != "" && announcement.NextHopIX != daemon.desired.IX.ID {
				nextHop = announcement.NextHopIX
			}
			if nextHop == originIX && !record.Direct && record.Via != "" {
				if _, static := staticPeers[originIX]; !static {
					nextHop = ""
				}
			}
			if announcementPathContainsIX(announcement.Path, daemon.desired.IX.ID) {
				routePolicy = append(routePolicy, routePolicyDecision{
					Direction: "import",
					IXID:      originIX,
					OriginIX:  originIX,
					NextHopIX: nextHop,
					Prefix:    core.Prefix(prefix.String()),
					Action:    "reject",
					Reason:    "path_loop",
					Source:    record.Source,
				})
				addRouteCandidate(routeCandidateFromAnnouncement(announcement, record, core.Prefix(prefix.String()), nextHop, routing.RouteUnicast, metric+announcement.Metric, "reject", "path_loop", "blocked"))
				continue
			}
			isManagementVIP := managementVIPPrefix.IsValid() && prefix == managementVIPPrefix && !managementVIPCovered
			if isManagementVIP && !daemon.managementHostAPIEnabled() {
				routePolicy = append(routePolicy, routePolicyDecision{
					Direction: "import",
					IXID:      originIX,
					OriginIX:  originIX,
					NextHopIX: nextHop,
					Prefix:    core.Prefix(prefix.String()),
					Action:    "reject",
					Reason:    "management_host_api_disabled",
					Source:    record.Source,
				})
				addRouteCandidate(routeCandidateFromAnnouncement(announcement, record, core.Prefix(prefix.String()), nextHop, routing.RouteLocal, metric+announcement.Metric, "reject", "management_host_api_disabled", "down"))
				continue
			}
			if isManagementVIP && strings.TrimSpace(advertisement.ControlAPI) == "" {
				routePolicy = append(routePolicy, routePolicyDecision{
					Direction: "import",
					IXID:      originIX,
					OriginIX:  originIX,
					NextHopIX: nextHop,
					Prefix:    core.Prefix(prefix.String()),
					Action:    "reject",
					Reason:    "no_control_api",
					Source:    record.Source,
				})
				addRouteCandidate(routeCandidateFromAnnouncement(announcement, record, core.Prefix(prefix.String()), nextHop, routing.RouteLocal, metric+announcement.Metric, "reject", "no_control_api", "down"))
				continue
			}
			if !isManagementVIP && nextHop == "" {
				routePolicy = append(routePolicy, routePolicyDecision{
					Direction: "import",
					IXID:      originIX,
					OriginIX:  originIX,
					NextHopIX: nextHop,
					Prefix:    core.Prefix(prefix.String()),
					Action:    "reject",
					Reason:    "no_transit_next_hop",
					Source:    record.Source,
				})
				addRouteCandidate(routeCandidateFromAnnouncement(announcement, record, core.Prefix(prefix.String()), nextHop, routing.RouteUnicast, metric+announcement.Metric, "reject", "no_transit_next_hop", "down"))
				continue
			}
			if !isManagementVIP && nextHop != originIX && !importTransitRoutes {
				routePolicy = append(routePolicy, routePolicyDecision{
					Direction: "import",
					IXID:      originIX,
					OriginIX:  originIX,
					NextHopIX: nextHop,
					Prefix:    core.Prefix(prefix.String()),
					Action:    "reject",
					Reason:    "transit_import_disabled",
					Source:    record.Source,
				})
				addRouteCandidate(routeCandidateFromAnnouncement(announcement, record, core.Prefix(prefix.String()), nextHop, routing.RouteUnicast, metric+announcement.Metric, "reject", "transit_import_disabled", "blocked"))
				continue
			}
			if !isManagementVIP && !daemon.hasUsableRouteNextHopEndpoint(nextHop) {
				routePolicy = append(routePolicy, routePolicyDecision{
					Direction: "import",
					IXID:      originIX,
					OriginIX:  originIX,
					NextHopIX: nextHop,
					Prefix:    core.Prefix(prefix.String()),
					Action:    "reject",
					Reason:    "no_usable_endpoint",
					Source:    record.Source,
				})
				addRouteCandidate(routeCandidateFromAnnouncement(announcement, record, core.Prefix(prefix.String()), nextHop, routing.RouteUnicast, metric+announcement.Metric, "reject", "no_usable_endpoint", "down"))
				continue
			}
			allowed, reason := importPolicyAllows(prefix, importPrefixes)
			if !allowed {
				routePolicy = append(routePolicy, routePolicyDecision{
					Direction: "import",
					IXID:      originIX,
					OriginIX:  originIX,
					NextHopIX: nextHop,
					Prefix:    core.Prefix(prefix.String()),
					Action:    "reject",
					Reason:    reason,
					Source:    record.Source,
				})
				addRouteCandidate(routeCandidateFromAnnouncement(announcement, record, core.Prefix(prefix.String()), nextHop, routing.RouteUnicast, metric+announcement.Metric, "reject", reason, "blocked"))
				continue
			}
			if known, exists := knownPrefixes[prefix.String()]; exists {
				action, reason, health := duplicateRouteCandidateStatus(known)
				routePolicy = append(routePolicy, routePolicyDecision{
					Direction: "import",
					IXID:      originIX,
					OriginIX:  originIX,
					NextHopIX: nextHop,
					Prefix:    core.Prefix(prefix.String()),
					Action:    action,
					Reason:    reason,
					Source:    record.Source,
				})
				addRouteCandidate(routeCandidateFromAnnouncement(announcement, record, core.Prefix(prefix.String()), nextHop, routing.RouteUnicast, metric+announcement.Metric, action, reason, health))
				continue
			}
			if claimedPrefixes.Conflicts(originIX, prefix) {
				routePolicy = append(routePolicy, routePolicyDecision{
					Direction: "import",
					IXID:      originIX,
					OriginIX:  originIX,
					NextHopIX: nextHop,
					Prefix:    core.Prefix(prefix.String()),
					Action:    "reject",
					Reason:    "prefix_conflict",
					Source:    record.Source,
				})
				addRouteCandidate(routeCandidateFromAnnouncement(announcement, record, core.Prefix(prefix.String()), nextHop, routing.RouteUnicast, metric+announcement.Metric, "reject", "prefix_conflict", "blocked"))
				continue
			}
			knownPrefixes[prefix.String()] = knownRoutePrefix{}
			claimedPrefixes.Add(originIX, prefix)
			routePolicy = append(routePolicy, routePolicyDecision{
				Direction: "import",
				IXID:      originIX,
				OriginIX:  originIX,
				NextHopIX: nextHop,
				Prefix:    core.Prefix(prefix.String()),
				Action:    "accept",
				Reason:    reason,
				Source:    record.Source,
			})
			kind := routing.RouteUnicast
			source := "dynamic"
			if nextHop != originIX {
				source = "dynamic_transit"
			}
			if isManagementVIP {
				kind = routing.RouteLocal
				source = "management_vip"
				nextHop = daemon.desired.IX.ID
			}
			route := routing.Route{
				Prefix:        core.Prefix(prefix.String()),
				Owner:         originIX,
				NextHop:       nextHop,
				Metric:        metric + announcement.Metric,
				Kind:          kind,
				LocalProtocol: managementVIPLocalProtocol(isManagementVIP),
				LocalPort:     managementVIPLocalPort(isManagementVIP, advertisement),
				Source:        source,
				Reason:        reason,
			}
			routes = append(routes, route)
			addRouteCandidate(routeCandidateFromAcceptedDynamicRoute(route, announcement, record))
		}
	}
	if options.IncludeRouteCandidates {
		markSelectedRouteCandidates(routeCandidates, routes)
	}
	return runtimeDataplaneProjection{
		Routes:          routes,
		Peers:           peers,
		Endpoints:       endpoints,
		NAT:             daemon.natSnapshotForRoutes(routes),
		RoutePolicy:     routePolicy,
		RouteCandidates: routeCandidates,
	}
}

func (daemon *Daemon) routeCandidatesForRuntimeRoutes(routes []routing.Route) []routeCandidate {
	candidates := make([]routeCandidate, 0, len(routes))
	for _, route := range routes {
		candidates = append(candidates, routeCandidate{
			Prefix:         normalizedRoutePrefix(route.Prefix),
			Owner:          routeOwner(route),
			OriginIX:       routeOwner(route),
			NextHop:        route.NextHop,
			Endpoint:       route.Endpoint,
			Kind:           route.Kind,
			Metric:         route.Metric,
			Source:         route.Source,
			SourcePriority: routeCandidateSourcePriority(route.Source, route.Kind),
			Action:         "accept",
			Reason:         firstNonEmpty(route.Reason, "configured"),
			Health:         daemon.routeHealthForRoute(route),
			Static:         route.Source == "static",
		})
	}
	return candidates
}

func routeCandidateFromAcceptedDynamicRoute(route routing.Route, announcement announcedPrefix, record memberRecord) routeCandidate {
	candidate := routeCandidateFromAnnouncement(announcement, record, route.Prefix, route.NextHop, route.Kind, route.Metric, "accept", firstNonEmpty(route.Reason, "import_default"), "ok")
	candidate.Owner = route.Owner
	candidate.OriginIX = route.Owner
	candidate.Endpoint = route.Endpoint
	candidate.Source = route.Source
	candidate.SourcePriority = routeCandidateSourcePriority(route.Source, route.Kind)
	return candidate
}

func routeCandidateFromAnnouncement(announcement announcedPrefix, record memberRecord, prefix core.Prefix, nextHop core.IXID, kind routing.RouteKind, metric int, action, reason, health string) routeCandidate {
	origin := announcement.OriginIX
	if origin == "" {
		origin = core.IXID(record.Advertisement.IXID)
	}
	source := "dynamic"
	if nextHop != "" && origin != "" && nextHop != origin {
		source = "dynamic_transit"
	}
	if kind == routing.RouteLocal {
		source = "management_vip"
	}
	learnedFrom := core.IXID(record.Advertisement.IXID)
	if !record.Direct && record.Via != "" {
		learnedFrom = record.Via
	}
	return routeCandidate{
		Prefix:         normalizedRoutePrefix(prefix),
		Owner:          origin,
		OriginIX:       origin,
		NextHop:        nextHop,
		LearnedFrom:    learnedFrom,
		Kind:           kind,
		Metric:         metric,
		Source:         source,
		SourcePriority: routeCandidateSourcePriority(source, kind),
		Action:         action,
		Reason:         reason,
		Health:         health,
		Direct:         record.Direct,
		LastSeen:       record.LastSeen,
		Path:           append([]core.IXID(nil), announcement.Path...),
	}
}

func (daemon *Daemon) routeHealthForRoute(route routing.Route) string {
	switch route.Kind {
	case routing.RouteBlackhole, routing.RouteReject:
		return "blocked"
	case routing.RouteLocal:
		return "ok"
	}
	if route.NextHop == "" {
		return "down"
	}
	if route.NextHop == daemon.desired.IX.ID {
		return "ok"
	}
	if daemon.transports == nil {
		return "unknown"
	}
	if daemon.hasUsableRouteNextHopEndpoint(route.NextHop) {
		return "ok"
	}
	return "down"
}

func normalizedRoutePrefix(prefix core.Prefix) core.Prefix {
	if parsed, err := prefix.Parse(); err == nil {
		return core.Prefix(parsed.Masked().String())
	}
	return prefix
}

func routeCandidateSourcePriority(source string, kind routing.RouteKind) int {
	if kind == routing.RouteLocal {
		return 10
	}
	switch source {
	case "local_lan", "management_vip":
		return 10
	case "device_access":
		return 20
	case "static":
		return 30
	case "dynamic":
		return 40
	case "dynamic_transit":
		return 50
	default:
		return 90
	}
}

func markSelectedRouteCandidates(candidates []routeCandidate, routes []routing.Route) {
	selected := selectedRouteCandidateKeys(routes)
	for index := range candidates {
		if candidates[index].Action != "accept" {
			continue
		}
		if _, ok := selected[routeCandidateKeyFromCandidate(candidates[index])]; ok {
			candidates[index].Selected = true
		}
	}
}

func selectedRouteCandidateKeys(routes []routing.Route) map[string]struct{} {
	type selectedRoute struct {
		route routing.Route
		index int
	}
	best := make(map[string]selectedRoute, len(routes))
	for index, route := range routes {
		key := string(normalizedRoutePrefix(route.Prefix))
		if key == "" {
			continue
		}
		current, exists := best[key]
		if !exists ||
			route.Metric < current.route.Metric ||
			route.Metric == current.route.Metric && index < current.index {
			best[key] = selectedRoute{route: route, index: index}
		}
	}
	out := make(map[string]struct{}, len(best))
	for _, selected := range best {
		out[routeCandidateKeyFromRoute(selected.route)] = struct{}{}
	}
	return out
}

func routeCandidateKeyFromRoute(route routing.Route) string {
	return strings.Join([]string{
		string(normalizedRoutePrefix(route.Prefix)),
		string(routeOwner(route)),
		string(route.NextHop),
		string(route.Endpoint),
		string(route.Kind),
		strconv.Itoa(route.Metric),
		route.Source,
	}, "\x00")
}

func routeCandidateKeyFromCandidate(candidate routeCandidate) string {
	return strings.Join([]string{
		string(normalizedRoutePrefix(candidate.Prefix)),
		string(candidate.Owner),
		string(candidate.NextHop),
		string(candidate.Endpoint),
		string(candidate.Kind),
		strconv.Itoa(candidate.Metric),
		candidate.Source,
	}, "\x00")
}

func (daemon *Daemon) appendDeviceAccessRoutes(routes []routing.Route) []routing.Route {
	if !daemon.deviceAccessEnabled() {
		return routes
	}
	now := time.Now().UTC()
	daemon.dataMu.Lock()
	expiredSessions := daemon.pruneExpiredDeviceLeasesLocked(now)
	leases := make([]deviceAccessLease, 0, len(daemon.deviceLeases))
	for _, lease := range daemon.deviceLeases {
		if lease.Address.IsValid() {
			leases = append(leases, lease)
		}
	}
	daemon.dataMu.Unlock()
	daemon.closeDroppedDataSessions(expiredSessions)
	sort.Slice(leases, func(i, j int) bool {
		if leases[i].Address.Compare(leases[j].Address) != 0 {
			return leases[i].Address.Compare(leases[j].Address) < 0
		}
		if leases[i].Key.IX != leases[j].Key.IX {
			return leases[i].Key.IX < leases[j].Key.IX
		}
		return leases[i].Key.Device < leases[j].Key.Device
	})
	for _, lease := range leases {
		identity := transport.PeerIdentity{
			Role:   string(pki.RoleDevice),
			Peer:   lease.Key.IX,
			Domain: daemon.desired.Domain.ID,
			Device: lease.Key.Device,
			LANID:  lease.LANID,
		}
		peerID := deviceAccessPeerID(identity)
		for _, prefix := range deviceAccessLeaseRoutePrefixes(lease) {
			routes = append(routes, routing.Route{
				Prefix:  core.Prefix(prefix.String()),
				Owner:   peerID,
				NextHop: peerID,
				Metric:  1,
				Kind:    routing.RouteUnicast,
				Source:  "device_access",
			})
		}
	}
	return routes
}

func (daemon *Daemon) appendDeviceAccessPeers(peers []dataplane.PeerMetadata) []dataplane.PeerMetadata {
	if !daemon.deviceAccessEnabled() {
		return peers
	}
	now := time.Now().UTC()
	daemon.dataMu.Lock()
	expiredSessions := daemon.pruneExpiredDeviceLeasesLocked(now)
	leases := make([]deviceAccessLease, 0, len(daemon.deviceLeases))
	for _, lease := range daemon.deviceLeases {
		leases = append(leases, lease)
	}
	daemon.dataMu.Unlock()
	daemon.closeDroppedDataSessions(expiredSessions)
	sort.Slice(leases, func(i, j int) bool {
		return deviceAccessPeerID(transport.PeerIdentity{Peer: leases[i].Key.IX, Device: leases[i].Key.Device, LANID: leases[i].LANID}) <
			deviceAccessPeerID(transport.PeerIdentity{Peer: leases[j].Key.IX, Device: leases[j].Key.Device, LANID: leases[j].LANID})
	})
	for _, lease := range leases {
		peerID := deviceAccessPeerID(transport.PeerIdentity{Peer: lease.Key.IX, Device: lease.Key.Device, LANID: lease.LANID})
		peers = append(peers, dataplane.PeerMetadata{
			ID:       peerID,
			DomainID: daemon.desired.Domain.ID,
			Trusted:  true,
		})
	}
	return peers
}

func (daemon *Daemon) appendLocalLANRoutes(routes []routing.Route) []routing.Route {
	localAdvertise := config.EffectiveLANAdvertise(daemon.desired)
	if len(localAdvertise) == 0 {
		return routes
	}
	existing := make(map[string]struct{}, len(routes))
	for _, route := range routes {
		prefix, err := route.Prefix.Parse()
		if err != nil {
			existing[string(route.Prefix)] = struct{}{}
			continue
		}
		existing[prefix.Masked().String()] = struct{}{}
	}
	for _, rawPrefix := range localAdvertise {
		prefix, err := rawPrefix.Parse()
		if err != nil {
			continue
		}
		masked := prefix.Masked()
		if _, ok := existing[masked.String()]; ok {
			continue
		}
		routes = append(routes, routing.Route{
			Prefix:  core.Prefix(masked.String()),
			Owner:   daemon.desired.IX.ID,
			NextHop: daemon.desired.IX.ID,
			Kind:    routing.RouteLocal,
			Source:  "local_lan",
		})
		existing[masked.String()] = struct{}{}
	}
	return routes
}

func managementVIPLocalProtocol(isManagementVIP bool) uint8 {
	if !isManagementVIP {
		return 0
	}
	return ipProtocolTCP
}

func managementVIPLocalPort(isManagementVIP bool, advertisement advertisementResponse) uint16 {
	if !isManagementVIP || advertisement.Management == nil || advertisement.Management.HostAPI == nil {
		return 0
	}
	port, err := parseUint16(advertisement.Management.HostAPI.Port)
	if err != nil {
		return 0
	}
	return port
}

func parseUint16(raw string) (uint16, error) {
	value, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 16)
	if err != nil || value == 0 {
		return 0, fmt.Errorf("parse uint16 %q", raw)
	}
	return uint16(value), nil
}

func (daemon *Daemon) localAdvertisementPrefixStrings() []string {
	return daemon.localAdvertisementPrefixStringsForDesired(daemon.desired)
}

func (daemon *Daemon) localAdvertisementPrefixStringsForDesired(desired config.Desired) []string {
	decisions := exportRoutePolicyDecisions(desired)
	prefixes := make([]string, 0, len(decisions))
	seen := make(map[string]struct{}, len(decisions)+1)
	advertisedPrefixes := make([]netip.Prefix, 0, len(decisions))
	for _, decision := range decisions {
		if decision.Action == "accept" {
			prefix := string(decision.Prefix)
			prefixes = append(prefixes, prefix)
			seen[prefix] = struct{}{}
			if parsed, err := netip.ParsePrefix(prefix); err == nil {
				advertisedPrefixes = append(advertisedPrefixes, parsed.Masked())
			}
		}
	}
	prefixes, advertisedPrefixes = daemon.appendLocalDeviceAccessAdvertisementPrefixes(prefixes, advertisedPrefixes, seen, desired)
	if prefix, ok := daemon.localManagementPrefixStringForDesired(desired); ok {
		if parsed, err := netip.ParsePrefix(prefix); err == nil && prefixCoveredByMoreGeneralPrefix(parsed.Masked(), advertisedPrefixes) {
			return prefixes
		}
		if _, exists := seen[prefix]; !exists && localManagementExportAllowed(prefix, desired.RoutePolicy.ExportPrefixes) {
			prefixes = append(prefixes, prefix)
		}
	}
	return prefixes
}

func localAnnouncedPrefixesForPrefixStrings(ixID core.IXID, prefixes []string) []announcedPrefix {
	announcements := make([]announcedPrefix, 0, len(prefixes))
	for _, rawPrefix := range prefixes {
		rawPrefix = strings.TrimSpace(rawPrefix)
		if rawPrefix == "" {
			continue
		}
		announcements = append(announcements, announcedPrefix{
			Prefix:    core.Prefix(rawPrefix),
			OriginIX:  ixID,
			NextHopIX: ixID,
			Source:    "local",
			Path:      []core.IXID{ixID},
		})
	}
	return announcements
}

func advertisementAnnouncements(advertisement advertisementResponse) []announcedPrefix {
	ixID := core.IXID(advertisement.IXID)
	announcements := make([]announcedPrefix, 0, len(advertisement.AnnouncedPrefixes)+len(advertisement.LANPrefixes))
	seen := make(map[string]struct{}, len(advertisement.AnnouncedPrefixes)+len(advertisement.LANPrefixes))
	for _, announcement := range advertisement.AnnouncedPrefixes {
		announcement.Prefix = core.Prefix(strings.TrimSpace(string(announcement.Prefix)))
		if announcement.Prefix == "" {
			continue
		}
		if announcement.OriginIX == "" {
			announcement.OriginIX = ixID
		}
		if announcement.NextHopIX == "" {
			announcement.NextHopIX = ixID
		}
		if len(announcement.Path) == 0 && announcement.OriginIX != "" {
			announcement.Path = []core.IXID{announcement.OriginIX}
		}
		key := string(announcement.Prefix)
		if parsed, err := announcement.Prefix.Parse(); err == nil {
			key = parsed.Masked().String()
			announcement.Prefix = core.Prefix(key)
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		announcements = append(announcements, announcement)
	}
	for _, rawPrefix := range advertisement.LANPrefixes {
		rawPrefix = strings.TrimSpace(rawPrefix)
		if rawPrefix == "" {
			continue
		}
		key := rawPrefix
		if parsed, err := netip.ParsePrefix(rawPrefix); err == nil {
			key = parsed.Masked().String()
			rawPrefix = key
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		announcements = append(announcements, announcedPrefix{
			Prefix:    core.Prefix(rawPrefix),
			OriginIX:  ixID,
			NextHopIX: ixID,
			Source:    "lan_prefixes",
			Path:      []core.IXID{ixID},
		})
	}
	return announcements
}

func announcementPrefixStrings(announcements []announcedPrefix) []string {
	prefixes := make([]string, 0, len(announcements))
	for _, announcement := range announcements {
		prefix := strings.TrimSpace(string(announcement.Prefix))
		if prefix != "" {
			prefixes = append(prefixes, prefix)
		}
	}
	return prefixes
}

func (daemon *Daemon) appendLocalDeviceAccessAdvertisementPrefixes(prefixes []string, advertisedPrefixes []netip.Prefix, seen map[string]struct{}, desired config.Desired) ([]string, []netip.Prefix) {
	if daemon == nil {
		return prefixes, advertisedPrefixes
	}
	if _, ok := config.DeviceAccessLAN(desired); !ok {
		return prefixes, advertisedPrefixes
	}
	allowed := parsedPolicyPrefixes(desired.RoutePolicy.ExportPrefixes)
	now := time.Now().UTC()
	daemon.dataMu.Lock()
	expiredSessions := daemon.pruneExpiredDeviceLeasesLocked(now)
	leases := make([]deviceAccessLease, 0, len(daemon.deviceLeases))
	for _, lease := range daemon.deviceLeases {
		if lease.Prefix.IsValid() && lease.Prefix.Addr().Is4() {
			leases = append(leases, lease)
		}
	}
	daemon.dataMu.Unlock()
	daemon.closeDroppedDataSessions(expiredSessions)
	sort.Slice(leases, func(i, j int) bool {
		return leases[i].Prefix.String() < leases[j].Prefix.String()
	})
	for _, lease := range leases {
		for _, prefix := range deviceAccessLeaseRoutePrefixes(lease) {
			prefix = prefix.Masked()
			raw := prefix.String()
			if _, exists := seen[raw]; exists {
				continue
			}
			if covered, _ := exportPolicyAllows(prefix, allowed); !covered {
				continue
			}
			prefixes = append(prefixes, raw)
			advertisedPrefixes = append(advertisedPrefixes, prefix)
			seen[raw] = struct{}{}
		}
	}
	return prefixes, advertisedPrefixes
}

func deviceAccessLeaseRoutePrefixes(lease deviceAccessLease) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, 1+len(lease.AdvertisePrefixes))
	seen := make(map[string]struct{}, 1+len(lease.AdvertisePrefixes))
	if lease.Prefix.IsValid() && lease.Prefix.Addr().Is4() {
		prefix := lease.Prefix.Masked()
		prefixes = append(prefixes, prefix)
		seen[prefix.String()] = struct{}{}
	}
	for _, prefix := range lease.AdvertisePrefixes {
		if !prefix.IsValid() || !prefix.Addr().Is4() {
			continue
		}
		prefix = prefix.Masked()
		if _, exists := seen[prefix.String()]; exists {
			continue
		}
		seen[prefix.String()] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

func (daemon *Daemon) localManagementPrefixString() (string, bool) {
	return daemon.localManagementPrefixStringForDesired(daemon.desired)
}

func (daemon *Daemon) localManagementPrefixStringForDesired(desired config.Desired) (string, bool) {
	addr, _, ok := daemon.managementHostAPIAdvertisedHostPortForDesired(desired)
	if !ok {
		return "", false
	}
	if !addr.IsValid() || !addr.Is4() {
		return "", false
	}
	return netip.PrefixFrom(addr, 32).String(), true
}

func localManagementExportAllowed(rawPrefix string, rawAllowed []core.Prefix) bool {
	prefix, err := netip.ParsePrefix(rawPrefix)
	if err != nil {
		return false
	}
	allowed, _ := exportPolicyAllows(prefix.Masked(), parsedPolicyPrefixes(rawAllowed))
	return allowed
}

func managementVIPCoveredByAdvertisedPrefix(vip netip.Prefix, rawPrefixes []string) bool {
	if !vip.IsValid() || vip.Bits() != 32 || !vip.Addr().Is4() {
		return false
	}
	for _, rawPrefix := range rawPrefixes {
		prefix, err := netip.ParsePrefix(rawPrefix)
		if err != nil {
			continue
		}
		prefix = prefix.Masked()
		if prefix == vip {
			continue
		}
		if prefix.Contains(vip.Addr()) && prefix.Bits() <= vip.Bits() {
			return true
		}
	}
	return false
}

func prefixCoveredByMoreGeneralPrefix(prefix netip.Prefix, candidates []netip.Prefix) bool {
	if !prefix.IsValid() {
		return false
	}
	for _, candidate := range candidates {
		if candidate == prefix {
			continue
		}
		if candidate.Contains(prefix.Addr()) && candidate.Bits() <= prefix.Bits() {
			return true
		}
	}
	return false
}

func exportRoutePolicyDecisions(desired config.Desired) []routePolicyDecision {
	exportPrefixes := parsedPolicyPrefixes(desired.RoutePolicy.ExportPrefixes)
	lanPrefixes := config.EffectiveLANAdvertise(desired)
	decisions := make([]routePolicyDecision, 0, len(lanPrefixes))
	for _, rawPrefix := range lanPrefixes {
		prefix, err := rawPrefix.Parse()
		if err != nil {
			decisions = append(decisions, routePolicyDecision{
				Direction: "export",
				IXID:      desired.IX.ID,
				OriginIX:  desired.IX.ID,
				NextHopIX: desired.IX.ID,
				Prefix:    rawPrefix,
				Action:    "reject",
				Reason:    "invalid_prefix",
				Source:    "local",
			})
			continue
		}
		prefix = prefix.Masked()
		allowed, reason := exportPolicyAllows(prefix, exportPrefixes)
		action := "accept"
		if !allowed {
			action = "reject"
		}
		decisions = append(decisions, routePolicyDecision{
			Direction: "export",
			IXID:      desired.IX.ID,
			OriginIX:  desired.IX.ID,
			NextHopIX: desired.IX.ID,
			Prefix:    core.Prefix(prefix.String()),
			Action:    action,
			Reason:    reason,
			Source:    "local",
		})
	}
	return decisions
}

func parsedPolicyPrefixes(raw []core.Prefix) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(raw))
	for _, prefix := range raw {
		parsed, err := prefix.Parse()
		if err == nil {
			prefixes = append(prefixes, parsed.Masked())
		}
	}
	return prefixes
}

func importPolicyAllows(prefix netip.Prefix, allowedPrefixes []netip.Prefix) (bool, string) {
	if prefixIsDefaultRoute(prefix) && !explicitPrefixAllowed(prefix, allowedPrefixes) {
		return false, "default_route_not_explicit"
	}
	if len(allowedPrefixes) == 0 {
		return true, "import_default"
	}
	if prefixCovered(prefix, allowedPrefixes) {
		return true, "import_prefix_match"
	}
	return false, "import_prefix_denied"
}

func exportPolicyAllows(prefix netip.Prefix, allowedPrefixes []netip.Prefix) (bool, string) {
	if prefixIsDefaultRoute(prefix) && !explicitPrefixAllowed(prefix, allowedPrefixes) {
		return false, "default_route_not_explicit"
	}
	if len(allowedPrefixes) == 0 {
		return true, "export_default"
	}
	if prefixCovered(prefix, allowedPrefixes) {
		return true, "export_prefix_match"
	}
	return false, "export_prefix_denied"
}

func prefixIsDefaultRoute(prefix netip.Prefix) bool {
	return prefix.IsValid() && prefix.Bits() == 0
}

func explicitPrefixAllowed(prefix netip.Prefix, allowedPrefixes []netip.Prefix) bool {
	prefix = prefix.Masked()
	for _, allowed := range allowedPrefixes {
		if allowed.Masked() == prefix {
			return true
		}
	}
	return false
}

func (daemon *Daemon) dynamicRouteMetric() int {
	if daemon.desired.RoutePolicy.DynamicMetric > 0 {
		return daemon.desired.RoutePolicy.DynamicMetric
	}
	return dynamicRouteMetric
}

func sortRoutePolicyDecisions(decisions []routePolicyDecision) {
	sort.Slice(decisions, func(i, j int) bool {
		if decisions[i].Direction != decisions[j].Direction {
			return decisions[i].Direction < decisions[j].Direction
		}
		if decisions[i].IXID != decisions[j].IXID {
			return decisions[i].IXID < decisions[j].IXID
		}
		return decisions[i].Prefix < decisions[j].Prefix
	})
}

func sortRouteCandidates(candidates []routeCandidate) {
	sort.Slice(candidates, func(i, j int) bool {
		left := candidates[i]
		right := candidates[j]
		if left.Prefix != right.Prefix {
			return left.Prefix < right.Prefix
		}
		if left.Selected != right.Selected {
			return left.Selected
		}
		if left.Action != right.Action {
			return left.Action < right.Action
		}
		if left.SourcePriority != right.SourcePriority {
			return left.SourcePriority < right.SourcePriority
		}
		if left.Metric != right.Metric {
			return left.Metric < right.Metric
		}
		if left.Owner != right.Owner {
			return left.Owner < right.Owner
		}
		if left.NextHop != right.NextHop {
			return left.NextHop < right.NextHop
		}
		return left.Source < right.Source
	})
}

func (daemon *Daemon) routeNextHopForMemberRecord(ixID core.IXID, record memberRecord, staticPeers map[core.IXID]struct{}) core.IXID {
	if record.Direct {
		return ixID
	}
	if _, static := staticPeers[ixID]; static {
		if daemon.staticPeerHasUsableEndpoint(ixID) {
			return ixID
		}
	}
	if record.Via == "" {
		return ixID
	}
	return record.Via
}

func (daemon *Daemon) staticPeerHasUsableEndpoint(peerID core.IXID) bool {
	peer, ok := daemon.staticPeerConfig(peerID)
	if !ok {
		return false
	}
	for _, endpoint := range peer.Endpoints {
		metadata := daemon.peerEndpointMetadataForRoute(peerID, endpoint)
		if metadata.Enabled && daemon.endpointTransportUsable(metadata) {
			return true
		}
	}
	return false
}

func announcementPathContainsIX(path []core.IXID, ixID core.IXID) bool {
	for _, hop := range path {
		if hop == ixID {
			return true
		}
	}
	return false
}

func (daemon *Daemon) hasUsableRouteNextHopEndpoint(nextHop core.IXID) bool {
	if nextHop == "" {
		return false
	}
	if nextHop == daemon.desired.IX.ID {
		return true
	}
	if peer, ok := daemon.staticPeerConfig(nextHop); ok {
		if record, dynamic := daemon.members[nextHop]; dynamic {
			peer = daemon.mergeStaticPeerWithAdvertisement(peer, record.Advertisement)
		}
		return daemon.peerConfigHasUsableEndpoint(nextHop, peer)
	}
	if peer, ok := daemon.deviceAccessPeerConfigByID(nextHop); ok {
		return daemon.peerConfigHasUsableEndpoint(nextHop, peer)
	}
	record, ok := daemon.members[nextHop]
	if !ok {
		return false
	}
	return daemon.peerConfigHasUsableEndpoint(nextHop, daemon.peerConfigFromAdvertisement(record.Advertisement))
}

func (daemon *Daemon) peerConfigHasUsableEndpoint(peerID core.IXID, peer config.PeerConfig) bool {
	for _, endpoint := range peer.Endpoints {
		metadata := daemon.peerEndpointMetadataForRoute(peerID, endpoint)
		if !metadata.Enabled {
			continue
		}
		if daemon.endpointTransportUsable(metadata) {
			return true
		}
	}
	return false
}

func (daemon *Daemon) peerEndpointMetadataForRoute(peer core.IXID, endpoint config.EndpointConfig) dataplane.EndpointMetadata {
	security := endpointSecurityMetadataFromConfig(endpoint.Security, endpoint.TLSServerName)
	if security.Encryption == "" {
		security.Encryption = parseSecureTransportEncryption(daemon.desired.TransportPolicy.Encryption)
	}
	return dataplane.EndpointMetadata{
		ID:        endpoint.Name,
		Peer:      peer,
		Transport: endpoint.Transport,
		Address:   endpoint.Address,
		Listen:    endpoint.Listen,
		LocalBind: endpointLocalBindMetadataFromConfig(endpoint.LocalBind),
		Priority:  endpoint.Priority,
		Enabled:   endpointDataSessionEnabled(endpoint),
		Security:  security,
		Profile:   endpointTransportProfileMetadataFromConfig(endpoint.Profile),
		Access:    endpointAccessMetadataFromConfig(endpoint.Access),
	}
}

func (daemon *Daemon) hasUsableAdvertisedEndpoint(advertisement advertisementResponse) bool {
	for _, endpoint := range daemon.localizeAdvertisementEndpoints(advertisement) {
		if !endpoint.Enabled {
			continue
		}
		if !daemon.endpointTransportUsable(endpoint) {
			continue
		}
		return true
	}
	return false
}

func (daemon *Daemon) localizeAdvertisementEndpoints(advertisement advertisementResponse) []dataplane.EndpointMetadata {
	endpoints := make([]dataplane.EndpointMetadata, 0, len(advertisement.Endpoints))
	for _, endpoint := range advertisement.Endpoints {
		localized, ok := daemon.localizeAdvertisementEndpoint(endpoint)
		if !ok {
			continue
		}
		endpoints = append(endpoints, localized)
	}
	return endpoints
}

func (daemon *Daemon) localizeAdvertisementEndpoint(endpoint dataplane.EndpointMetadata) (dataplane.EndpointMetadata, bool) {
	if !endpoint.Enabled {
		return dataplane.EndpointMetadata{}, false
	}
	protocol := transport.Protocol(strings.ToLower(strings.TrimSpace(endpoint.Transport)))
	if !transportProtocolIsKernelTunnel(string(protocol)) || strings.TrimSpace(endpoint.Address) == "" {
		return endpoint, true
	}
	cfg, err := iptunneltransport.ParseTunnelConfig(endpoint.Address)
	if err != nil {
		localized, ok := daemon.negotiateKernelTunnelEndpoint(protocol, endpoint)
		if !ok {
			return dataplane.EndpointMetadata{}, false
		}
		return localized, true
	}
	localUnderlay, ok := daemon.localUnderlayAddressForTunnelEndpoint(cfg.RemoteUnderlay)
	if !ok {
		return dataplane.EndpointMetadata{}, false
	}
	if cfg.RemoteUnderlay != localUnderlay {
		return dataplane.EndpointMetadata{}, false
	}
	var address string
	if protocol == transport.ProtocolVXLAN {
		address, err = iptunneltransport.ReverseKernelTunnelConfig(protocol, endpoint.Address, config.PrimaryLAN(daemon.desired).UnderlayIface)
	} else {
		address, err = iptunneltransport.ReverseKernelTunnelConfig(protocol, endpoint.Address)
	}
	if err != nil {
		return dataplane.EndpointMetadata{}, false
	}
	endpoint.Address = address
	endpoint.Listen = ""
	return endpoint, true
}

func (daemon *Daemon) negotiateKernelTunnelEndpoint(protocol transport.Protocol, endpoint dataplane.EndpointMetadata) (dataplane.EndpointMetadata, bool) {
	remote, ok := parseTunnelEndpointSpec(endpoint.Address)
	if !ok || !remote.localUnderlay.IsValid() {
		return dataplane.EndpointMetadata{}, false
	}
	localEndpoint, local, ok := daemon.localKernelTunnelEndpointForRemote(protocol, core.IXID(endpoint.Peer), remote.localUnderlay)
	if !ok || !local.localUnderlay.IsValid() {
		return dataplane.EndpointMetadata{}, false
	}
	carrierPrefix, remoteCarrier := negotiatedTunnelCarrier(daemon.desired.IX.ID, core.IXID(endpoint.Peer), protocol)
	cfg := negotiatedKernelTunnelConfig{
		localUnderlay:  local.localUnderlay,
		remoteUnderlay: remote.localUnderlay,
		underlayIf:     firstNonEmpty(local.underlayIf, config.PrimaryLAN(daemon.desired).UnderlayIface),
		localCarrier:   carrierPrefix,
		remoteCarrier:  remoteCarrier,
		port:           chooseTunnelPort(local.carrierPort, remote.carrierPort),
		mtu:            chooseTunnelMTU(local.mtu, remote.mtu),
		vni:            chooseTunnelVNI(protocol, local.vni, remote.vni, daemon.desired.IX.ID, core.IXID(endpoint.Peer)),
		vxlanPort:      chooseVXLANPort(local.vxlanPort, remote.vxlanPort),
		queues:         chooseTunnelQueues(local.queues, remote.queues),
	}
	endpoint.Address = formatNegotiatedKernelTunnelConfig(protocol, cfg)
	endpoint.Listen = ""
	if localEndpoint.Security.Encryption != "" && endpoint.Security.Encryption == "" {
		endpoint.Security.Encryption = localEndpoint.Security.Encryption
	}
	return endpoint, true
}

type negotiatedKernelTunnelConfig struct {
	localUnderlay  netip.Addr
	remoteUnderlay netip.Addr
	underlayIf     string
	localCarrier   netip.Prefix
	remoteCarrier  netip.Addr
	port           uint16
	mtu            int
	vni            int
	vxlanPort      uint16
	queues         int
}

func (daemon *Daemon) localKernelTunnelEndpointForRemote(protocol transport.Protocol, peer core.IXID, remote netip.Addr) (dataplane.EndpointMetadata, tunnelEndpointSpec, bool) {
	for _, endpoint := range daemon.localAdvertisementEndpointsForTarget(controlTarget{ID: peer, Domain: daemon.desired.Domain.ID}) {
		if transport.Protocol(strings.ToLower(strings.TrimSpace(endpoint.Transport))) != protocol {
			continue
		}
		spec, ok := parseTunnelEndpointSpec(endpoint.Address)
		if !ok || !spec.localUnderlay.IsValid() {
			continue
		}
		return endpoint, spec, true
	}
	return dataplane.EndpointMetadata{}, tunnelEndpointSpec{}, false
}

func parseTunnelEndpointSpec(raw string) (tunnelEndpointSpec, bool) {
	values, err := parseTunnelEndpointValues(raw)
	if err != nil {
		return tunnelEndpointSpec{}, false
	}
	var spec tunnelEndpointSpec
	if rawLocal := strings.TrimSpace(values["local"]); rawLocal != "" {
		addr, err := netip.ParseAddr(rawLocal)
		if err != nil || !addr.Is4() {
			return tunnelEndpointSpec{}, false
		}
		spec.localUnderlay = addr
	} else {
		addr, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil || !addr.Is4() {
			return tunnelEndpointSpec{}, false
		}
		spec.localUnderlay = addr
	}
	spec.underlayIf = firstNonEmpty(values["underlay_if"], values["underlay_iface"], values["dev"], values["link"])
	spec.carrierPort = parseOptionalUint16(values["port"])
	spec.mtu = parseOptionalInt(values["mtu"])
	spec.vni = parseOptionalInt(values["vni"])
	spec.vxlanPort = parseOptionalUint16(firstNonEmpty(values["vxlan_port"], values["outer_port"]))
	spec.queues = parseOptionalInt(firstNonEmpty(values["queues"], values["num_queues"], values["vxlan_queues"]))
	return spec, true
}

func parseTunnelEndpointValues(raw string) (map[string]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty tunnel endpoint")
	}
	if strings.Contains(raw, "://") {
		parts := strings.SplitN(raw, "://", 2)
		raw = parts[1]
	}
	if !strings.Contains(raw, "=") {
		return map[string]string{"local": raw}, nil
	}
	values := make(map[string]string)
	for _, field := range strings.Split(raw, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			return nil, fmt.Errorf("field %q must use key=value", field)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			return nil, fmt.Errorf("field %q is incomplete", field)
		}
		values[key] = value
	}
	return values, nil
}

func parseOptionalInt(raw string) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value <= 0 {
		return 0
	}
	return value
}

func parseOptionalUint16(raw string) uint16 {
	value, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 16)
	if err != nil || value == 0 {
		return 0
	}
	return uint16(value)
}

func chooseTunnelPort(local, remote uint16) uint16 {
	if local != 0 {
		return local
	}
	if remote != 0 {
		return remote
	}
	return 47819
}

func chooseTunnelMTU(local, remote int) int {
	if local > 0 && remote > 0 {
		if local < remote {
			return local
		}
		return remote
	}
	if local > 0 {
		return local
	}
	if remote > 0 {
		return remote
	}
	return 1400
}

func chooseVXLANPort(local, remote uint16) uint16 {
	if local != 0 {
		return local
	}
	if remote != 0 {
		return remote
	}
	return 4789
}

func chooseTunnelQueues(local, remote int) int {
	if local > 0 {
		return local
	}
	if remote > 0 {
		return remote
	}
	return 0
}

func chooseTunnelVNI(protocol transport.Protocol, local, remote int, left, right core.IXID) int {
	if protocol != transport.ProtocolVXLAN {
		return 0
	}
	if local > 0 {
		return local
	}
	if remote > 0 {
		return remote
	}
	return int(1 + deterministicTunnelUint32("vni", left, right)%16777215)
}

func negotiatedTunnelCarrier(local, peer core.IXID, protocol transport.Protocol) (netip.Prefix, netip.Addr) {
	left, right := orderedIXPair(local, peer)
	slot := deterministicTunnelUint32("carrier:"+string(protocol), left, right) % (1 << 20)
	base := (uint32(100) << 24) | (uint32(64) << 16) | slot*4
	leftAddr := netip.AddrFrom4([4]byte{byte(base >> 24), byte(base >> 16), byte(base >> 8), byte(base) + 1})
	rightAddr := netip.AddrFrom4([4]byte{byte(base >> 24), byte(base >> 16), byte(base >> 8), byte(base) + 2})
	if local == left {
		return netip.PrefixFrom(leftAddr, 30), rightAddr
	}
	return netip.PrefixFrom(rightAddr, 30), leftAddr
}

func orderedIXPair(left, right core.IXID) (core.IXID, core.IXID) {
	if string(right) < string(left) {
		return right, left
	}
	return left, right
}

func deterministicTunnelUint32(label string, left, right core.IXID) uint32 {
	orderedLeft, orderedRight := orderedIXPair(left, right)
	sum := sha256.Sum256([]byte(label + "\x00" + string(orderedLeft) + "\x00" + string(orderedRight)))
	return binary.BigEndian.Uint32(sum[:4])
}

func formatNegotiatedKernelTunnelConfig(protocol transport.Protocol, cfg negotiatedKernelTunnelConfig) string {
	fields := []string{
		fmt.Sprintf("local=%s", cfg.localUnderlay),
		fmt.Sprintf("remote=%s", cfg.remoteUnderlay),
	}
	if cfg.underlayIf != "" {
		fields = append(fields, fmt.Sprintf("underlay_if=%s", cfg.underlayIf))
	}
	fields = append(fields,
		fmt.Sprintf("local_carrier=%s", cfg.localCarrier),
		fmt.Sprintf("remote_carrier=%s", cfg.remoteCarrier),
		fmt.Sprintf("port=%d", cfg.port),
		fmt.Sprintf("mtu=%d", cfg.mtu),
	)
	if cfg.queues > 0 {
		fields = append(fields, fmt.Sprintf("queues=%d", cfg.queues))
	}
	if protocol == transport.ProtocolVXLAN {
		fields = append(fields, fmt.Sprintf("vni=%d", cfg.vni), fmt.Sprintf("vxlan_port=%d", cfg.vxlanPort))
	}
	return strings.Join(fields, ",")
}

func (daemon *Daemon) localUnderlayAddressForTunnelEndpoint(candidate netip.Addr) (netip.Addr, bool) {
	if !candidate.IsValid() {
		return netip.Addr{}, false
	}
	if ifaceName := strings.TrimSpace(config.PrimaryLAN(daemon.desired).UnderlayIface); ifaceName != "" {
		if addr, ok := interfaceAddressMatchingCandidate(ifaceName, candidate); ok {
			return addr, true
		}
	}
	for _, endpoint := range daemon.desired.Endpoints {
		if !transportProtocolIsKernelTunnel(endpoint.Transport) {
			continue
		}
		raw := strings.TrimSpace(endpoint.Address)
		if raw == "" {
			raw = strings.TrimSpace(endpoint.Listen)
		}
		cfg, err := iptunneltransport.ParseTunnelConfig(raw)
		if err != nil {
			continue
		}
		if cfg.LocalUnderlay == candidate {
			return cfg.LocalUnderlay, true
		}
	}
	return netip.Addr{}, false
}

func interfaceAddressMatchingCandidate(ifaceName string, candidate netip.Addr) (netip.Addr, bool) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return netip.Addr{}, false
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, false
	}
	for _, rawAddr := range addrs {
		prefix, ok := interfaceAddrPrefix(rawAddr)
		if !ok {
			continue
		}
		if prefix.Addr() == candidate {
			return prefix.Addr(), true
		}
	}
	return netip.Addr{}, false
}

func interfaceAddrPrefix(rawAddr net.Addr) (netip.Prefix, bool) {
	switch addr := rawAddr.(type) {
	case *net.IPNet:
		prefix, ok := netip.AddrFromSlice(addr.IP)
		if !ok {
			return netip.Prefix{}, false
		}
		ones, _ := addr.Mask.Size()
		return netip.PrefixFrom(prefix.Unmap(), ones), true
	case *net.IPAddr:
		prefix, ok := netip.AddrFromSlice(addr.IP)
		if !ok {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(prefix.Unmap(), prefix.BitLen()), true
	default:
		prefix, err := netip.ParsePrefix(rawAddr.String())
		if err == nil {
			return prefix, true
		}
		parsedAddr, err := netip.ParseAddr(rawAddr.String())
		if err != nil {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(parsedAddr, parsedAddr.BitLen()), true
	}
}

func (daemon *Daemon) endpointTransportUsable(endpoint dataplane.EndpointMetadata) bool {
	protocol := transport.Protocol(endpoint.Transport)
	if _, ok := daemon.transports.Get(protocol); !ok {
		return false
	}
	if protocol != transport.ProtocolTIXTCP && protocol != transport.ProtocolUDP {
		return true
	}
	if protocol == transport.ProtocolUDP {
		if daemon.kernelTransportMode() != dataplane.KernelTransportModeRequireKernel && daemon.transportCryptoPlacement() != dataplane.CryptoPlacementKernel {
			return true
		}
		provider, ok := daemon.dataplane.(dataplane.KernelUDPProvider)
		if !ok {
			return false
		}
		status, err := provider.KernelUDPStatus(context.Background())
		if err != nil {
			return false
		}
		if !status.Available || !status.Reinject {
			return false
		}
		return daemon.kernelUDPCryptoPlacementAvailable(status) == nil
	}
	provider, ok := daemon.dataplane.(dataplane.TIXTCPProvider)
	if !ok {
		return false
	}
	status, err := provider.TIXTCPStatus(context.Background())
	if err != nil {
		return false
	}
	if !status.Available || !status.Reinject {
		return false
	}
	return daemon.tixTCPCryptoPlacementAvailable(status) == nil
}

func prefixOverlapsAny(prefix netip.Prefix, candidates []netip.Prefix) bool {
	for _, candidate := range candidates {
		if prefix.Overlaps(candidate) {
			return true
		}
	}
	return false
}

func newPrefixOwnerIndex() *prefixOwnerIndex {
	return &prefixOwnerIndex{}
}

func (index *prefixOwnerIndex) Add(owner core.IXID, prefix netip.Prefix) {
	if index == nil || !prefix.IsValid() {
		return
	}
	prefix = prefix.Masked()
	node := index.root(prefix)
	node.recordSubtreeOwner(owner)
	for bit := 0; bit < prefix.Bits(); bit++ {
		childIndex := prefixBit(prefix, bit)
		if node.child[childIndex] == nil {
			node.child[childIndex] = &prefixOwnerTrieNode{}
		}
		node = node.child[childIndex]
		node.recordSubtreeOwner(owner)
	}
	node.recordTerminalOwner(owner)
}

func (index *prefixOwnerIndex) Conflicts(owner core.IXID, prefix netip.Prefix) bool {
	if index == nil || !prefix.IsValid() {
		return false
	}
	prefix = prefix.Masked()
	node := index.root(prefix)
	if node.hasDifferentTerminalOwner(owner) {
		return true
	}
	for bit := 0; bit < prefix.Bits(); bit++ {
		node = node.child[prefixBit(prefix, bit)]
		if node == nil {
			return false
		}
		if node.hasDifferentTerminalOwner(owner) {
			return true
		}
	}
	return node.hasDifferentSubtreeOwner(owner)
}

func (index *prefixOwnerIndex) root(prefix netip.Prefix) *prefixOwnerTrieNode {
	if prefix.Addr().Is4() {
		return &index.v4
	}
	return &index.v6
}

func (node *prefixOwnerTrieNode) recordSubtreeOwner(owner core.IXID) {
	if !node.subtreeSet {
		node.subtreeSet = true
		node.subtreeOwner = owner
		return
	}
	if node.subtreeOwner != owner {
		node.subtreeMixed = true
	}
}

func (node *prefixOwnerTrieNode) recordTerminalOwner(owner core.IXID) {
	if !node.terminalSet {
		node.terminalSet = true
		node.terminalOwner = owner
		return
	}
	if node.terminalOwner != owner {
		node.terminalMixed = true
	}
}

func (node *prefixOwnerTrieNode) hasDifferentTerminalOwner(owner core.IXID) bool {
	if node == nil || !node.terminalSet {
		return false
	}
	return node.terminalMixed || node.terminalOwner != owner
}

func (node *prefixOwnerTrieNode) hasDifferentSubtreeOwner(owner core.IXID) bool {
	if node == nil || !node.subtreeSet {
		return false
	}
	return node.subtreeMixed || node.subtreeOwner != owner
}

func prefixBit(prefix netip.Prefix, bit int) int {
	if prefix.Addr().Is4() {
		addr := prefix.Addr().As4()
		return int((addr[bit/8] >> uint(7-bit%8)) & 1)
	}
	addr := prefix.Addr().As16()
	return int((addr[bit/8] >> uint(7-bit%8)) & 1)
}

func routeOwner(route routing.Route) core.IXID {
	if route.Owner != "" {
		return route.Owner
	}
	return route.NextHop
}

func (daemon *Daemon) applyRuntimeDataplaneSnapshot(ctx context.Context) error {
	snapshot := daemon.runtimeDataplaneSnapshot()
	if err := validateRuntimeKernelTunnelConflicts(snapshot); err != nil {
		return err
	}
	nextRoutes := routing.NewTable()
	if err := nextRoutes.Replace(snapshot.Routes); err != nil {
		return err
	}
	daemon.reconcileForwardCacheForRoutes(nextRoutes)
	if err := daemon.routes.Replace(snapshot.Routes); err != nil {
		return err
	}
	daemon.pruneDataPathMetrics(snapshot)
	daemon.reconcileRouteSelectedOutboundSessions()
	daemon.membershipMu.Lock()
	daemon.runtimeEpoch++
	snapshot.Epoch = daemon.runtimeSnapshotEpochLocked()
	daemon.membershipMu.Unlock()
	if err := daemon.dataplane.ApplySnapshot(ctx, snapshot); err != nil {
		return err
	}
	daemon.syncKernelDatapathState(ctx, snapshot)
	if err := daemon.syncKernelTunnelListeners(daemon.listenerContext(ctx)); err != nil {
		return err
	}
	if err := daemon.syncManagementVIPAPIServers(ctx); err != nil {
		return err
	}
	daemon.refreshDeviceAccessClientRoutes()
	return nil
}

func (daemon *Daemon) membershipStatePath() string {
	if daemon.cfg.DataDir == "" {
		return ""
	}
	return filepath.Join(daemon.cfg.DataDir, "members.json")
}

func (daemon *Daemon) pendingMembershipStatePath() string {
	if daemon.cfg.DataDir == "" {
		return ""
	}
	return filepath.Join(daemon.cfg.DataDir, "pending-members.json")
}

func (daemon *Daemon) loadPersistedMembers() error {
	path := daemon.membershipStatePath()
	if path == "" {
		return nil
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read membership state %q: %w", path, err)
	}
	var state persistedMembers
	if err := json.Unmarshal(payload, &state); err != nil {
		if quarantined, quarantineErr := quarantineBadStateFile(path, err); quarantineErr == nil {
			if quarantined != "" {
				return nil
			}
		} else {
			return fmt.Errorf("decode membership state %q: %w; quarantine failed: %v", path, err, quarantineErr)
		}
		return fmt.Errorf("decode membership state %q: %w", path, err)
	}
	now := time.Now().UTC()
	changed := false
	for _, record := range state.Members {
		ixID := core.IXID(record.Advertisement.IXID)
		if ixID == "" || ixID == daemon.desired.IX.ID {
			continue
		}
		if now.Sub(record.LastSeen) > memberRecordTTL {
			changed = true
			continue
		}
		if state.Version < 2 && !record.Direct {
			record.Direct = true
			changed = true
		}
		if err := daemon.verifyAdvertisement(record.Advertisement); err != nil {
			changed = true
			continue
		}
		if cert, err := x509.ParseCertificate(record.Advertisement.IXCertificate); err == nil {
			if _, err := daemon.registerConfigSignerCertificate(cert, false); err != nil {
				changed = true
				continue
			}
		} else {
			changed = true
			continue
		}
		daemon.membershipMu.Lock()
		daemon.members[ixID] = record
		daemon.membershipMu.Unlock()
	}
	if changed {
		return daemon.persistMembers()
	}
	return nil
}

func (daemon *Daemon) loadPersistedPendingMembers() error {
	path := daemon.pendingMembershipStatePath()
	if path == "" {
		return nil
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read pending membership state %q: %w", path, err)
	}
	var state persistedPendingMembers
	if err := json.Unmarshal(payload, &state); err != nil {
		if quarantined, quarantineErr := quarantineBadStateFile(path, err); quarantineErr == nil {
			if quarantined != "" {
				return nil
			}
		} else {
			return fmt.Errorf("decode pending membership state %q: %w; quarantine failed: %v", path, err, quarantineErr)
		}
		return fmt.Errorf("decode pending membership state %q: %w", path, err)
	}
	now := time.Now().UTC()
	changed := false
	for _, record := range state.Pending {
		ixID := core.IXID(record.Advertisement.IXID)
		if ixID == "" || ixID == daemon.desired.IX.ID {
			changed = true
			continue
		}
		if err := ixID.Validate(); err != nil {
			changed = true
			continue
		}
		if record.FirstSeen.IsZero() {
			record.FirstSeen = record.LastSeen
			changed = true
		}
		if record.LastSeen.IsZero() {
			record.LastSeen = record.FirstSeen
			changed = true
		}
		if record.FirstSeen.IsZero() || now.Sub(record.LastSeen) > pendingMemberTTL {
			changed = true
			continue
		}
		if _, err := daemon.verifyAdvertisementBase(record.Advertisement); err != nil {
			changed = true
			continue
		}
		if err := daemon.verifyAdvertisement(record.Advertisement); err == nil {
			changed = true
			continue
		} else {
			record.RejectReason = err.Error()
		}
		daemon.membershipMu.Lock()
		if daemon.pendingMembers == nil {
			daemon.pendingMembers = make(map[core.IXID]pendingMemberRecord)
		}
		daemon.pendingMembers[ixID] = record
		daemon.membershipMu.Unlock()
	}
	if changed {
		return daemon.persistPendingMembers()
	}
	return nil
}

func (daemon *Daemon) persistMembers() error {
	if daemon.membershipStatePath() == "" {
		return nil
	}
	daemon.membershipDiskMu.Lock()
	defer daemon.membershipDiskMu.Unlock()
	daemon.membershipMu.RLock()
	ids := make([]string, 0, len(daemon.members))
	for ixID := range daemon.members {
		if ixID == daemon.desired.IX.ID {
			continue
		}
		ids = append(ids, string(ixID))
	}
	sort.Strings(ids)
	state := persistedMembers{Version: 2, Members: make([]memberRecord, 0, len(ids))}
	for _, rawID := range ids {
		state.Members = append(state.Members, daemon.members[core.IXID(rawID)])
	}
	daemon.membershipMu.RUnlock()

	if err := os.MkdirAll(filepath.Dir(daemon.membershipStatePath()), 0o755); err != nil {
		return fmt.Errorf("create data dir for membership state: %w", err)
	}
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	path := daemon.membershipStatePath()
	if err := writeStateFileAtomic(path, payload, 0o600); err != nil {
		return fmt.Errorf("replace membership state %q: %w", path, err)
	}
	return nil
}

func (daemon *Daemon) persistPendingMembers() error {
	if daemon.pendingMembershipStatePath() == "" {
		return nil
	}
	daemon.membershipDiskMu.Lock()
	defer daemon.membershipDiskMu.Unlock()
	daemon.membershipMu.RLock()
	ids := make([]string, 0, len(daemon.pendingMembers))
	for ixID := range daemon.pendingMembers {
		if ixID == daemon.desired.IX.ID {
			continue
		}
		ids = append(ids, string(ixID))
	}
	sort.Strings(ids)
	state := persistedPendingMembers{Version: 1, Pending: make([]pendingMemberRecord, 0, len(ids))}
	for _, rawID := range ids {
		state.Pending = append(state.Pending, daemon.pendingMembers[core.IXID(rawID)])
	}
	daemon.membershipMu.RUnlock()

	path := daemon.pendingMembershipStatePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create data dir for pending membership state: %w", err)
	}
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err := writeStateFileAtomic(path, payload, 0o600); err != nil {
		return fmt.Errorf("replace pending membership state %q: %w", path, err)
	}
	return nil
}

func (daemon *Daemon) pruneExpiredMembers() bool {
	now := time.Now().UTC()
	var changed bool
	expiredDynamicOnly := make(map[core.IXID]struct{})
	daemon.membershipMu.Lock()
	for ixID, record := range daemon.members {
		if ixID == daemon.desired.IX.ID {
			continue
		}
		if now.Sub(record.LastSeen) > memberRecordTTL {
			delete(daemon.members, ixID)
			if _, static := daemon.staticPeerConfig(ixID); !static {
				expiredDynamicOnly[ixID] = struct{}{}
			}
			changed = true
		}
	}
	daemon.membershipMu.Unlock()
	if changed {
		_ = daemon.persistMembers()
	}
	if len(expiredDynamicOnly) > 0 {
		daemon.closeDataSessionsForPeers(expiredDynamicOnly)
		daemon.clearFlowsForPeers(expiredDynamicOnly)
	}
	if daemon.pruneExpiredPendingMembers() {
		changed = true
	}
	return changed
}

func (daemon *Daemon) pruneExpiredPendingMembers() bool {
	now := time.Now().UTC()
	changed := false
	daemon.membershipMu.Lock()
	for ixID, record := range daemon.pendingMembers {
		if record.LastSeen.IsZero() || now.Sub(record.LastSeen) > pendingMemberTTL {
			delete(daemon.pendingMembers, ixID)
			changed = true
		}
	}
	daemon.membershipMu.Unlock()
	if changed {
		_ = daemon.persistPendingMembers()
	}
	return changed
}

func (daemon *Daemon) runtimeRoutes() []routing.Route {
	routes, _, _ := daemon.runtimeDataplaneState()
	return routes
}

func (daemon *Daemon) dynamicPeerConfig(id core.IXID) (config.PeerConfig, bool) {
	daemon.membershipMu.RLock()
	defer daemon.membershipMu.RUnlock()
	record, ok := daemon.members[id]
	if !ok || id == daemon.desired.IX.ID {
		return config.PeerConfig{}, false
	}
	return daemon.peerConfigFromAdvertisement(record.Advertisement), true
}

func (daemon *Daemon) staticPeerConfig(id core.IXID) (config.PeerConfig, bool) {
	for _, peer := range daemon.desired.Peers {
		if peer.ID == id {
			return peer, true
		}
	}
	return config.PeerConfig{}, false
}

func (daemon *Daemon) effectivePeerConfig(id core.IXID) (config.PeerConfig, bool) {
	if peer, ok := daemon.staticPeerConfig(id); ok {
		daemon.membershipMu.RLock()
		record, dynamic := daemon.members[id]
		daemon.membershipMu.RUnlock()
		if dynamic {
			return daemon.mergeStaticPeerWithAdvertisement(peer, record.Advertisement), true
		}
		return peer, true
	}
	if peer, ok := daemon.deviceAccessPeerConfigByID(id); ok {
		return peer, true
	}
	return daemon.dynamicPeerConfig(id)
}

func (daemon *Daemon) deviceAccessPeerConfigByID(id core.IXID) (config.PeerConfig, bool) {
	if !daemon.deviceAccessEnabled() {
		return config.PeerConfig{}, false
	}
	now := time.Now().UTC()
	daemon.dataMu.Lock()
	expiredSessions := daemon.pruneExpiredDeviceLeasesLocked(now)
	for _, lease := range daemon.deviceLeases {
		identity := transport.PeerIdentity{
			Role:   string(pki.RoleDevice),
			Peer:   lease.Key.IX,
			Domain: daemon.desired.Domain.ID,
			Device: lease.Key.Device,
			LANID:  lease.LANID,
		}
		if deviceAccessPeerID(identity) == id {
			daemon.dataMu.Unlock()
			daemon.closeDroppedDataSessions(expiredSessions)
			return daemon.deviceAccessPeerConfig(identity, lease), true
		}
	}
	daemon.dataMu.Unlock()
	daemon.closeDroppedDataSessions(expiredSessions)
	return config.PeerConfig{}, false
}

func (daemon *Daemon) peerConfigFromAdvertisement(advertisement advertisementResponse) config.PeerConfig {
	return peerConfigFromAdvertisementWithEndpoints(advertisement, daemon.localizeAdvertisementEndpoints(advertisement))
}

func peerConfigFromAdvertisement(advertisement advertisementResponse) config.PeerConfig {
	return peerConfigFromAdvertisementWithEndpoints(advertisement, advertisement.Endpoints)
}

func peerConfigFromAdvertisementWithEndpoints(advertisement advertisementResponse, metadata []dataplane.EndpointMetadata) config.PeerConfig {
	prefixes := corePrefixesFromAdvertisement(advertisement)
	endpoints := make([]config.EndpointConfig, 0, len(metadata))
	for _, endpoint := range metadata {
		mode := config.EndpointModeActive
		if strings.TrimSpace(endpoint.Address) == "" {
			mode = config.EndpointModePassive
		}
		endpoints = append(endpoints, config.EndpointConfig{
			Name:          endpoint.ID,
			Mode:          mode,
			Address:       endpoint.Address,
			LocalBind:     endpointLocalBindConfigFromMetadata(endpoint.LocalBind),
			Transport:     endpoint.Transport,
			Priority:      endpoint.Priority,
			TLSServerName: endpoint.Security.TLSServerName,
			Security:      endpointSecurityConfigFromMetadata(endpoint.Security),
			Profile:       endpointTransportProfileConfigFromMetadata(endpoint.Profile),
			Access:        endpointAccessConfigFromMetadata(endpoint.Access),
			Enabled:       endpoint.Enabled,
		})
	}
	return config.PeerConfig{
		ID:              core.IXID(advertisement.IXID),
		Domain:          core.DomainID(advertisement.DomainID),
		ControlAPI:      advertisement.ControlAPI,
		Endpoints:       endpoints,
		AllowedPrefixes: prefixes,
	}
}

func (daemon *Daemon) mergeStaticPeerWithAdvertisement(peer config.PeerConfig, advertisement advertisementResponse) config.PeerConfig {
	dynamic := daemon.peerConfigFromAdvertisement(advertisement)
	if dynamic.ID == "" || dynamic.ID != peer.ID {
		return peer
	}
	merged := peer
	if merged.Domain == "" {
		merged.Domain = dynamic.Domain
	}
	if strings.TrimSpace(merged.ControlAPI) == "" {
		merged.ControlAPI = dynamic.ControlAPI
	}
	if strings.TrimSpace(merged.TLSServerName) == "" {
		merged.TLSServerName = dynamic.TLSServerName
	}
	if len(merged.AllowedPrefixes) == 0 {
		merged.AllowedPrefixes = append([]core.Prefix(nil), dynamic.AllowedPrefixes...)
	}
	seen := make(map[core.EndpointID]struct{}, len(merged.Endpoints)+len(dynamic.Endpoints))
	for _, endpoint := range merged.Endpoints {
		seen[endpoint.Name] = struct{}{}
	}
	for _, endpoint := range dynamic.Endpoints {
		if _, exists := seen[endpoint.Name]; exists {
			continue
		}
		merged.Endpoints = append(merged.Endpoints, endpoint)
		seen[endpoint.Name] = struct{}{}
	}
	return merged
}

func (daemon *Daemon) localizedAdvertisementEndpointsNotConfigured(peer core.IXID, advertisement advertisementResponse) []dataplane.EndpointMetadata {
	static, ok := daemon.staticPeerConfig(peer)
	if !ok {
		return daemon.localizeAdvertisementEndpoints(advertisement)
	}
	configured := make(map[core.EndpointID]struct{}, len(static.Endpoints))
	for _, endpoint := range static.Endpoints {
		configured[endpoint.Name] = struct{}{}
	}
	localized := daemon.localizeAdvertisementEndpoints(advertisement)
	out := make([]dataplane.EndpointMetadata, 0, len(localized))
	for _, endpoint := range localized {
		if _, exists := configured[endpoint.ID]; exists {
			continue
		}
		out = append(out, endpoint)
	}
	return out
}

func (daemon *Daemon) controlTargets() []controlTarget {
	daemon.configMu.RLock()
	desired := daemon.desired
	daemon.configMu.RUnlock()
	return daemon.controlTargetsForDesired(desired)
}

func (daemon *Daemon) controlTargetsForDesired(desired config.Desired) []controlTarget {
	seen := make(map[string]struct{})
	targets := make([]controlTarget, 0, len(desired.Peers)+len(desired.Bootstrap.Peers))
	dynamicTargets := make([]controlTarget, 0)
	add := func(target controlTarget) {
		if target.ControlAPI == "" {
			return
		}
		if _, exists := seen[target.ControlAPI]; exists {
			return
		}
		seen[target.ControlAPI] = struct{}{}
		targets = append(targets, target)
	}
	for _, peer := range desired.Peers {
		add(controlTarget{ID: peer.ID, Domain: peer.Domain, ControlAPI: peer.ControlAPI, Static: true})
	}
	for _, peer := range desired.Bootstrap.Peers {
		domain := peer.Domain
		if domain == "" {
			domain = desired.Domain.ID
		}
		add(controlTarget{ID: peer.ID, Domain: domain, ControlAPI: peer.ControlAPI})
	}
	daemon.membershipMu.RLock()
	for ixID, record := range daemon.members {
		if ixID == desired.IX.ID {
			continue
		}
		ad := record.Advertisement
		if ad.ControlAPI != "" {
			dynamicTargets = append(dynamicTargets, controlTarget{
				ID:         core.IXID(ad.IXID),
				Domain:     core.DomainID(ad.DomainID),
				ControlAPI: ad.ControlAPI,
			})
		}
	}
	daemon.membershipMu.RUnlock()
	sort.Slice(dynamicTargets, func(i, j int) bool {
		if dynamicTargets[i].ControlAPI != dynamicTargets[j].ControlAPI {
			return dynamicTargets[i].ControlAPI < dynamicTargets[j].ControlAPI
		}
		return dynamicTargets[i].ID < dynamicTargets[j].ID
	})
	for _, target := range daemon.selectDynamicControlTargets(dynamicTargets) {
		add(target)
	}
	return targets
}

func (daemon *Daemon) selectDynamicControlTargets(targets []controlTarget) []controlTarget {
	fanout := daemon.dynamicControlTargetFanout()
	if fanout <= 0 || fanout >= len(targets) {
		return targets
	}
	if len(targets) == 0 {
		return nil
	}
	start := int((daemon.controlTargetCursor.Add(1) - 1) % uint64(len(targets)))
	selected := make([]controlTarget, 0, fanout)
	for i := 0; i < fanout; i++ {
		selected = append(selected, targets[(start+i)%len(targets)])
	}
	return selected
}

func (daemon *Daemon) dynamicControlTargetFanout() int {
	if value, ok := controlFabricLimitFromEnv("TRUSTIX_DYNAMIC_CONTROL_TARGET_FANOUT", defaultDynamicControlTargetFanout); ok {
		return value
	}
	daemon.configMu.RLock()
	configured := daemon.desired.ControlFabric.DynamicControlFanout
	profile := daemon.desired.ControlFabric.Profile
	daemon.configMu.RUnlock()
	if configured != nil {
		return *configured
	}
	return dynamicControlTargetFanoutForProfile(profile)
}

func dynamicControlTargetFanoutForProfile(profile string) int {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(profile), "-", "_")) {
	case "small":
		return 0
	case "edge":
		return edgeDynamicControlTargetFanout
	case "reflector", "route_reflector":
		return reflectorControlTargetFanout
	case "core", "authority":
		return coreDynamicControlTargetFanout
	default:
		return defaultDynamicControlTargetFanout
	}
}

func (daemon *Daemon) controlMemberPageSize() int {
	if value, ok := controlFabricLimitFromEnv("TRUSTIX_CONTROL_MEMBER_PAGE_SIZE", defaultControlMemberPageSize); ok {
		return clampControlMemberPageSize(value)
	}
	daemon.configMu.RLock()
	configured := daemon.desired.ControlFabric.MemberPageSize
	profile := daemon.desired.ControlFabric.Profile
	daemon.configMu.RUnlock()
	if configured != nil {
		return clampControlMemberPageSize(*configured)
	}
	return clampControlMemberPageSize(controlMemberPageSizeForProfile(profile))
}

func controlMemberPageSizeForProfile(profile string) int {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(profile), "-", "_")) {
	case "small":
		return 0
	case "edge":
		return edgeControlMemberPageSize
	case "reflector", "route_reflector":
		return reflectorControlMemberPageSize
	case "core", "authority":
		return coreControlMemberPageSize
	default:
		return defaultControlMemberPageSize
	}
}

func (daemon *Daemon) controlMemberImportLimit() int {
	if value, ok := controlFabricLimitFromEnv("TRUSTIX_CONTROL_MEMBER_IMPORT_LIMIT", defaultControlMemberPageSize); ok {
		return value
	}
	daemon.configMu.RLock()
	configured := daemon.desired.ControlFabric.MemberImportLimit
	profile := daemon.desired.ControlFabric.Profile
	daemon.configMu.RUnlock()
	if configured != nil {
		return *configured
	}
	return controlMemberPageSizeForProfile(profile)
}

func clampControlMemberPageSize(value int) int {
	if value <= 0 {
		return 0
	}
	if value > maxControlMemberPageSize {
		return maxControlMemberPageSize
	}
	return value
}

func controlFabricLimitFromEnv(name string, fallback int) (int, bool) {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	switch raw {
	case "":
		return 0, false
	case "0", "off", "false", "disabled", "unlimited", "all":
		return 0, true
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return fallback, true
	}
	return value, true
}

func (daemon *Daemon) controlClient(target controlTarget) (*http.Client, error) {
	parsed, err := url.Parse(target.ControlAPI)
	if err != nil {
		return nil, err
	}
	key := controlClientCacheKey(target)
	now := time.Now()
	ttl := controlClientCacheTTL()
	if ttl > 0 {
		daemon.controlClientMu.Lock()
		if daemon.controlClients == nil {
			daemon.controlClients = make(map[string]*cachedControlClient)
		}
		daemon.pruneExpiredControlClientsLocked(now)
		if cached := daemon.controlClients[key]; cached != nil && now.Before(cached.expiresAt) {
			client := cached.client
			daemon.controlClientMu.Unlock()
			return client, nil
		}
		daemon.controlClientMu.Unlock()
	}

	client, transport, err := daemon.newControlClient(target, parsed)
	if err != nil {
		return nil, err
	}
	if ttl <= 0 {
		return client, nil
	}
	daemon.controlClientMu.Lock()
	if daemon.controlClients == nil {
		daemon.controlClients = make(map[string]*cachedControlClient)
	}
	if old := daemon.controlClients[key]; old != nil && old.transport != nil {
		old.transport.CloseIdleConnections()
	}
	daemon.controlClients[key] = &cachedControlClient{
		client:    client,
		transport: transport,
		expiresAt: now.Add(ttl),
	}
	daemon.controlClientMu.Unlock()
	return client, nil
}

func (daemon *Daemon) newControlClient(target controlTarget, parsed *url.URL) (*http.Client, *http.Transport, error) {
	var tlsConf *tls.Config
	if parsed.Scheme == "https" {
		var err error
		tlsConf, err = daemon.controlClientTLSConfig(target)
		if err != nil {
			return nil, nil, err
		}
	}
	transport := &http.Transport{
		TLSClientConfig:     tlsConf,
		ForceAttemptHTTP2:   true,
		DialContext:         (&net.Dialer{Timeout: controlClientTimeout(), KeepAlive: controlClientTCPKeepAlive()}).DialContext,
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 2,
		MaxConnsPerHost:     4,
		IdleConnTimeout:     controlClientIdleConnTimeout,
	}
	return &http.Client{
		Timeout:   controlClientTimeout(),
		Transport: transport,
	}, transport, nil
}

func controlClientCacheKey(target controlTarget) string {
	return strings.TrimSpace(target.ControlAPI) + "\x00" + string(target.Domain) + "\x00" + string(target.ID)
}

func controlMemberPageCacheKey(target controlTarget, cursor string, limit int) string {
	return controlClientCacheKey(target) + "\x00members\x00" + strings.TrimSpace(cursor) + "\x00" + strconv.Itoa(limit)
}

func controlClientCacheTTL() time.Duration {
	raw := strings.TrimSpace(os.Getenv("TRUSTIX_CONTROL_CLIENT_CACHE_TTL"))
	if raw == "" {
		return defaultControlClientCacheTTL
	}
	if seconds, err := strconv.ParseFloat(raw, 64); err == nil && seconds >= 0 {
		return time.Duration(seconds * float64(time.Second))
	}
	if ttl, err := time.ParseDuration(raw); err == nil && ttl >= 0 {
		return ttl
	}
	return defaultControlClientCacheTTL
}

func advertisementPushInterval() time.Duration {
	raw := strings.TrimSpace(os.Getenv("TRUSTIX_ADVERTISEMENT_PUSH_INTERVAL"))
	if raw == "" {
		return defaultAdvertisementPushInterval
	}
	if seconds, err := strconv.ParseFloat(raw, 64); err == nil && seconds >= 0 {
		return time.Duration(seconds * float64(time.Second))
	}
	if interval, err := time.ParseDuration(raw); err == nil && interval >= 0 {
		return interval
	}
	return defaultAdvertisementPushInterval
}

func (daemon *Daemon) cachedControlMembers(key string) (string, membersResponse, bool) {
	daemon.controlClientMu.Lock()
	defer daemon.controlClientMu.Unlock()
	cached, ok := daemon.controlMembers[key]
	if !ok || cached.etag == "" {
		return "", membersResponse{}, false
	}
	return cached.etag, cloneMembersResponse(cached.response), true
}

func (daemon *Daemon) storeCachedControlMembers(key, etag string, response membersResponse) {
	etag = strings.TrimSpace(etag)
	if etag == "" {
		return
	}
	daemon.controlClientMu.Lock()
	if daemon.controlMembers == nil {
		daemon.controlMembers = make(map[string]cachedControlMembers)
	}
	daemon.controlMembers[key] = cachedControlMembers{
		etag:     etag,
		response: cloneMembersResponse(response),
	}
	daemon.controlClientMu.Unlock()
}

func (daemon *Daemon) controlMemberCursor(key string) string {
	daemon.controlClientMu.Lock()
	defer daemon.controlClientMu.Unlock()
	return daemon.controlMemberCursors[key]
}

func (daemon *Daemon) storeControlMemberCursor(key, cursor string) {
	daemon.controlClientMu.Lock()
	if daemon.controlMemberCursors == nil {
		daemon.controlMemberCursors = make(map[string]string)
	}
	if strings.TrimSpace(cursor) == "" {
		delete(daemon.controlMemberCursors, key)
	} else {
		daemon.controlMemberCursors[key] = strings.TrimSpace(cursor)
	}
	daemon.controlClientMu.Unlock()
}

func cloneMembersResponse(response membersResponse) membersResponse {
	response.Members = cloneAdvertisements(response.Members)
	return response
}

func cloneAdvertisements(members []advertisementResponse) []advertisementResponse {
	if len(members) == 0 {
		return nil
	}
	return append([]advertisementResponse(nil), members...)
}

func (daemon *Daemon) shouldPushLocalAdvertisement(target controlTarget, payloadHash string, now time.Time) bool {
	interval := advertisementPushInterval()
	if interval <= 0 {
		return true
	}
	key := controlClientCacheKey(target)
	daemon.controlClientMu.Lock()
	defer daemon.controlClientMu.Unlock()
	if daemon.controlAdPush == nil {
		daemon.controlAdPush = make(map[string]cachedAdvertisementPush)
		return true
	}
	cached, ok := daemon.controlAdPush[key]
	if !ok || cached.payloadHash != payloadHash || now.Sub(cached.lastPush) >= interval {
		return true
	}
	return false
}

func (daemon *Daemon) markLocalAdvertisementPushed(target controlTarget, payloadHash string, pushedAt time.Time) {
	if advertisementPushInterval() <= 0 {
		return
	}
	key := controlClientCacheKey(target)
	daemon.controlClientMu.Lock()
	if daemon.controlAdPush == nil {
		daemon.controlAdPush = make(map[string]cachedAdvertisementPush)
	}
	daemon.controlAdPush[key] = cachedAdvertisementPush{
		payloadHash: payloadHash,
		lastPush:    pushedAt,
	}
	daemon.controlClientMu.Unlock()
}

func (daemon *Daemon) forgetLocalAdvertisementPush(target controlTarget) {
	key := controlClientCacheKey(target)
	daemon.controlClientMu.Lock()
	if daemon.controlAdPush != nil {
		delete(daemon.controlAdPush, key)
	}
	daemon.controlClientMu.Unlock()
}

func controlPayloadHash(payload []byte) string {
	sum := sha256.Sum256(payload)
	return fmt.Sprintf("%x", sum)
}

func (daemon *Daemon) pruneExpiredControlClientsLocked(now time.Time) {
	for key, cached := range daemon.controlClients {
		if cached == nil || now.Before(cached.expiresAt) {
			continue
		}
		if cached.transport != nil {
			cached.transport.CloseIdleConnections()
		}
		delete(daemon.controlClients, key)
	}
}

func (daemon *Daemon) resetControlClients() {
	daemon.controlClientMu.Lock()
	defer daemon.controlClientMu.Unlock()
	daemon.closeControlClientsLocked()
}

func (daemon *Daemon) closeControlClients() {
	daemon.controlClientMu.Lock()
	defer daemon.controlClientMu.Unlock()
	daemon.closeControlClientsLocked()
}

func (daemon *Daemon) closeControlClientsLocked() {
	for key, cached := range daemon.controlClients {
		if cached != nil && cached.transport != nil {
			cached.transport.CloseIdleConnections()
		}
		delete(daemon.controlClients, key)
	}
	for key := range daemon.controlMembers {
		delete(daemon.controlMembers, key)
	}
	for key := range daemon.controlMemberCursors {
		delete(daemon.controlMemberCursors, key)
	}
	for key := range daemon.controlAdPush {
		delete(daemon.controlAdPush, key)
	}
}

func controlClientTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv("TRUSTIX_CONTROL_CLIENT_TIMEOUT"))
	if raw == "" {
		return defaultControlClientTimeout
	}
	if seconds, err := strconv.ParseFloat(raw, 64); err == nil && seconds > 0 {
		return time.Duration(seconds * float64(time.Second))
	}
	if timeout, err := time.ParseDuration(raw); err == nil && timeout > 0 {
		return timeout
	}
	return defaultControlClientTimeout
}

func (daemon *Daemon) controlClientTLSConfig(target controlTarget) (*tls.Config, error) {
	cert, err := loadTLSCertificateChecked(daemon.desired, daemon.desired.IX.CertPath, daemon.desired.IX.KeyPath, "local control client certificate")
	if err != nil {
		return nil, fmt.Errorf("load peer client certificate: %w", err)
	}
	pool, err := daemon.trustPool()
	if err != nil {
		return nil, err
	}
	domain := target.Domain
	if domain == "" {
		domain = daemon.desired.Domain.ID
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   string(domain),
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("peer server certificate is required")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			if err := daemon.verifyCertificateNotRevoked(cert, "peer server certificate"); err != nil {
				return err
			}
			meta := pki.ParseMetadata(cert)
			if meta.Role != pki.RoleIX {
				return fmt.Errorf("peer server certificate role is %q, want %q", meta.Role, pki.RoleIX)
			}
			if meta.Domain != string(domain) {
				return fmt.Errorf("peer server certificate domain is %q, want %q", meta.Domain, domain)
			}
			if target.ID != "" && meta.IX != string(target.ID) {
				return fmt.Errorf("peer server certificate ix is %q, want %q", meta.IX, target.ID)
			}
			return nil
		},
	}, nil
}

func (daemon *Daemon) fetchMembers(ctx context.Context, target controlTarget) ([]advertisementResponse, error) {
	parsed, err := url.Parse(target.ControlAPI)
	if err != nil {
		return nil, fmt.Errorf("parse control_api: %w", err)
	}
	client, err := daemon.controlClient(target)
	if err != nil {
		return nil, err
	}
	baseCacheKey := controlClientCacheKey(target)
	cursor := daemon.controlMemberCursor(baseCacheKey)
	pageSize := daemon.controlMemberPageSize()
	importLimit := daemon.controlMemberImportLimit()
	advertisements := make([]advertisementResponse, 0)
	seen := make(map[core.IXID]struct{})
	importedRemote := 0
	for pages := 0; pages < maxControlMemberPaginationPages(); pages++ {
		limit := pageSize
		if importLimit > 0 {
			remaining := importLimit - importedRemote
			if remaining <= 0 {
				daemon.storeControlMemberCursor(baseCacheKey, cursor)
				return advertisements, nil
			}
			if limit <= 0 || limit > remaining {
				limit = remaining
			}
		}
		response, fallback, err := daemon.fetchMembersPage(ctx, target, client, parsed, cursor, limit)
		if fallback {
			if len(advertisements) > 0 {
				daemon.storeControlMemberCursor(baseCacheKey, cursor)
				return advertisements, nil
			}
			return daemon.fetchSingleAdvertisement(ctx, target, client, parsed)
		}
		if err != nil {
			if len(advertisements) > 0 {
				daemon.storeControlMemberCursor(baseCacheKey, cursor)
				return advertisements, nil
			}
			return nil, err
		}
		for _, advertisement := range response.Members {
			ixID := core.IXID(strings.TrimSpace(advertisement.IXID))
			if ixID == "" {
				continue
			}
			if _, exists := seen[ixID]; exists {
				continue
			}
			seen[ixID] = struct{}{}
			advertisements = append(advertisements, advertisement)
			if !advertisementMatchesControlTarget(advertisement, target) {
				importedRemote++
			}
		}
		cursor = strings.TrimSpace(response.NextCursor)
		if cursor == "" {
			daemon.storeControlMemberCursor(baseCacheKey, "")
			return advertisements, nil
		}
	}
	daemon.storeControlMemberCursor(baseCacheKey, cursor)
	return advertisements, nil
}

func (daemon *Daemon) fetchMembersPage(ctx context.Context, target controlTarget, client *http.Client, parsed *url.URL, cursor string, limit int) (membersResponse, bool, error) {
	cacheKey := controlMemberPageCacheKey(target, cursor, limit)
	cachedETag, cachedResponse, cached := daemon.cachedControlMembers(cacheKey)
	query := url.Values{}
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	query.Set("limit", strconv.Itoa(limit))
	requestURL := parsed.ResolveReference(&url.URL{Path: "/v1/control/members", RawQuery: query.Encode()})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return membersResponse{}, false, err
	}
	if cachedETag != "" {
		req.Header.Set("If-None-Match", cachedETag)
	}
	resp, err := client.Do(req)
	if err == nil && resp.StatusCode == http.StatusNotModified && cached {
		drainAndCloseResponse(resp)
		return cachedResponse, false, nil
	}
	if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		defer drainAndCloseResponse(resp)
		var response membersResponse
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			return membersResponse{}, false, fmt.Errorf("decode members from %s: %w", requestURL, err)
		}
		daemon.storeCachedControlMembers(cacheKey, resp.Header.Get("ETag"), response)
		return response, false, nil
	}
	if resp != nil {
		drainAndCloseResponse(resp)
	}
	return membersResponse{}, true, nil
}

func maxControlMemberPaginationPages() int {
	raw := strings.TrimSpace(os.Getenv("TRUSTIX_CONTROL_MEMBER_MAX_PAGES"))
	if raw == "" {
		return 16
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return 16
	}
	return value
}

func (daemon *Daemon) fetchSingleAdvertisement(ctx context.Context, target controlTarget, client *http.Client, parsed *url.URL) ([]advertisementResponse, error) {
	requestURL := parsed.ResolveReference(&url.URL{Path: "/v1/control/advertisements"})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch peer advertisement from %s: %w", requestURL, err)
	}
	defer drainAndCloseResponse(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fetch peer advertisement from %s returned %s", requestURL, resp.Status)
	}
	var advertisement advertisementResponse
	if err := json.NewDecoder(resp.Body).Decode(&advertisement); err != nil {
		return nil, fmt.Errorf("decode peer advertisement: %w", err)
	}
	return []advertisementResponse{advertisement}, nil
}

func (daemon *Daemon) pushLocalAdvertisement(ctx context.Context, target controlTarget) error {
	parsed, err := url.Parse(target.ControlAPI)
	if err != nil {
		return fmt.Errorf("parse control_api: %w", err)
	}
	client, err := daemon.controlClient(target)
	if err != nil {
		return err
	}
	advertisement, err := daemon.localAdvertisementForTarget(target)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(advertisement)
	if err != nil {
		return err
	}
	now := time.Now()
	payloadHash := controlPayloadHash(payload)
	if !daemon.shouldPushLocalAdvertisement(target, payloadHash, now) {
		return nil
	}
	requestURL := parsed.ResolveReference(&url.URL{Path: "/v1/control/advertisements"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("push local advertisement to %s: %w", requestURL, err)
	}
	defer drainAndCloseResponse(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("push local advertisement to %s returned %s", requestURL, resp.Status)
	}
	daemon.markLocalAdvertisementPushed(target, payloadHash, now)
	return nil
}
