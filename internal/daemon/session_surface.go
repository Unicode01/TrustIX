package daemon

import (
	"reflect"
	"sort"
	"strings"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/transport"
)

type dataSessionDesiredSurface struct {
	LocalEndpoints  []dataSessionLocalEndpointSurface
	Peers           []dataSessionPeerSurface
	TransportPolicy dataSessionTransportPolicySurface
}

type dataSessionTransportPolicySurface struct {
	Mode            string
	Candidates      []core.EndpointID
	Profile         string
	Datapath        string
	Encryption      string
	CryptoKeySource string
	CryptoSuites    []string
	CryptoPlacement string
	Profiles        []config.TransportProfileConfig
	Advanced        config.TransportAdvancedConfig
	SessionPool     config.SessionPoolPolicyConfig
	TLSIdentity     config.TransportTLSIdentityConfig
	KernelTransport config.KernelTransportPolicyConfig
}

type dataSessionPeerSurface struct {
	ID            core.IXID
	Domain        core.DomainID
	TLSServerName string
	Endpoints     []dataSessionEndpointSurface
}

type dataSessionEndpointSurface struct {
	Name          core.EndpointID
	Mode          string
	Address       string
	Listen        string
	LocalBind     config.EndpointLocalBindConfig
	Transport     string
	Priority      int
	TLSServerName string
	Enabled       bool
	Security      dataplane.EndpointSecurityMetadata
	Profile       dataplane.TransportProfileMetadata
}

type dataSessionLocalEndpointSurface struct {
	Name      core.EndpointID
	Transport string
	Priority  int
	Enabled   bool
	Publish   config.EndpointPublishConfig
	LocalBind config.EndpointLocalBindConfig
	Profile   dataplane.TransportProfileMetadata
}

type advertisementDataSessionSurface struct {
	DomainID      string
	IXID          string
	IXCertificate []byte
	Endpoints     []dataplane.EndpointMetadata
}

func dataPathSessionsNeedRestart(oldDesired, newDesired config.Desired) bool {
	return !reflect.DeepEqual(desiredDataSessionSurface(oldDesired), desiredDataSessionSurface(newDesired))
}

func (daemon *Daemon) dataPathSessionRestartScope(oldDesired, newDesired config.Desired) (bool, map[core.IXID]struct{}) {
	if !reflect.DeepEqual(dataSessionTransportPolicySurfaceForDesired(oldDesired), dataSessionTransportPolicySurfaceForDesired(newDesired)) {
		return true, nil
	}
	if !reflect.DeepEqual(localEndpointSelectionSurface(oldDesired.Endpoints), localEndpointSelectionSurface(newDesired.Endpoints)) {
		return true, nil
	}
	routePeers := routeEndpointSelectionChangedPeers(oldDesired.Routes, newDesired.Routes)
	oldPeers := daemon.effectiveDataSessionPeerSurfaceMap(oldDesired)
	newPeers := daemon.effectiveDataSessionPeerSurfaceMap(newDesired)
	changed := make(map[core.IXID]struct{})
	for peer := range routePeers {
		changed[peer] = struct{}{}
	}
	for peer, oldSurface := range oldPeers {
		if newSurface, ok := newPeers[peer]; !ok || !dataSessionPeerSurfacesCompatible(oldSurface, newSurface) {
			changed[peer] = struct{}{}
		}
	}
	for peer := range newPeers {
		if _, ok := oldPeers[peer]; !ok {
			changed[peer] = struct{}{}
		}
	}
	if len(changed) == 0 {
		return false, nil
	}
	return false, changed
}

func routeEndpointSelectionChangedPeers(oldRoutes, newRoutes []config.RouteConfig) map[core.IXID]struct{} {
	oldByKey := routeEndpointSelectionMap(oldRoutes)
	newByKey := routeEndpointSelectionMap(newRoutes)
	changed := make(map[core.IXID]struct{})
	for key, oldRoute := range oldByKey {
		newRoute, ok := newByKey[key]
		if !ok {
			continue
		}
		if oldRoute.NextHop != newRoute.NextHop || oldRoute.Endpoint != newRoute.Endpoint {
			if oldRoute.NextHop != "" {
				changed[oldRoute.NextHop] = struct{}{}
			}
			if newRoute.NextHop != "" {
				changed[newRoute.NextHop] = struct{}{}
			}
		}
	}
	return changed
}

func routeEndpointSelectionMap(routes []config.RouteConfig) map[string]config.RouteConfig {
	out := make(map[string]config.RouteConfig, len(routes))
	for _, route := range routes {
		if route.Prefix != "" {
			out[string(route.Prefix)] = route
		}
	}
	return out
}

func desiredDataSessionSurface(desired config.Desired) dataSessionDesiredSurface {
	peers := make([]dataSessionPeerSurface, 0, len(desired.Peers))
	for _, peer := range desired.Peers {
		peers = append(peers, dataSessionPeerSurface{
			ID:            peer.ID,
			Domain:        peer.Domain,
			TLSServerName: peer.TLSServerName,
			Endpoints:     endpointConfigDataSessionSurfaceForPolicy(peer.Endpoints, desired.TransportPolicy),
		})
	}
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].ID < peers[j].ID
	})
	return dataSessionDesiredSurface{
		LocalEndpoints:  localEndpointSelectionSurface(desired.Endpoints),
		Peers:           peers,
		TransportPolicy: dataSessionTransportPolicySurfaceForDesired(desired),
	}
}

func localEndpointSelectionSurface(endpoints []config.EndpointConfig) []dataSessionLocalEndpointSurface {
	out := make([]dataSessionLocalEndpointSurface, 0, len(endpoints))
	for _, endpoint := range endpoints {
		out = append(out, dataSessionLocalEndpointSurface{
			Name:      endpoint.Name,
			Transport: strings.TrimSpace(endpoint.Transport),
			Priority:  endpoint.Priority,
			Enabled:   endpoint.Enabled,
			Publish:   endpoint.Publish,
			LocalBind: endpointLocalBindSurface(endpoint.LocalBind),
			Profile:   endpointTransportProfileSurfaceFromConfig(endpoint),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].Transport != out[j].Transport {
			return out[i].Transport < out[j].Transport
		}
		return out[i].Priority < out[j].Priority
	})
	return out
}

func dataSessionTransportPolicySurfaceForDesired(desired config.Desired) dataSessionTransportPolicySurface {
	policy := desired.TransportPolicy
	return dataSessionTransportPolicySurface{
		Mode:            strings.TrimSpace(policy.Mode),
		Candidates:      append([]core.EndpointID(nil), policy.Candidates...),
		Profile:         strings.TrimSpace(policy.Profile),
		Datapath:        strings.TrimSpace(policy.Datapath),
		Encryption:      strings.TrimSpace(policy.Encryption),
		CryptoKeySource: strings.TrimSpace(policy.CryptoKeySource),
		CryptoSuites:    effectiveSecureTransportCryptoSuitesForDesired(desired),
		CryptoPlacement: effectiveTransportCryptoPlacementConfig(policy),
		Profiles:        append([]config.TransportProfileConfig(nil), policy.Profiles...),
		Advanced:        policy.Advanced,
		SessionPool:     policy.SessionPool,
		TLSIdentity:     policy.TLSIdentity,
		KernelTransport: policy.KernelTransport,
	}
}

func (daemon *Daemon) effectiveDataSessionPeerSurfaceMap(desired config.Desired) map[core.IXID]dataSessionPeerSurface {
	peers := make(map[core.IXID]dataSessionPeerSurface)
	daemon.membershipMu.RLock()
	for ixID, record := range daemon.members {
		if ixID == desired.IX.ID {
			continue
		}
		peer := daemon.peerConfigFromAdvertisement(record.Advertisement)
		peers[ixID] = daemon.dataSessionPeerSurfaceForConfig(peer, desired.TransportPolicy)
	}
	daemon.membershipMu.RUnlock()
	for _, peer := range desired.Peers {
		daemon.membershipMu.RLock()
		record, dynamic := daemon.members[peer.ID]
		daemon.membershipMu.RUnlock()
		if dynamic {
			peer = daemon.mergeStaticPeerWithAdvertisement(peer, record.Advertisement)
		}
		peers[peer.ID] = daemon.dataSessionPeerSurfaceForConfig(peer, desired.TransportPolicy)
	}
	return peers
}

func (daemon *Daemon) dataSessionPeerSurfaceForConfig(peer config.PeerConfig, policy config.TransportPolicyConfig) dataSessionPeerSurface {
	surface := dataSessionPeerSurfaceForConfig(peer, policy)
	for index := range surface.Endpoints {
		surface.Endpoints[index].Security.CryptoPlacements = daemon.compatibleEndpointCryptoPlacements(surface.Endpoints[index].Transport, surface.Endpoints[index].Security)
	}
	return surface
}

func dataSessionPeerSurfaceForConfig(peer config.PeerConfig, policy config.TransportPolicyConfig) dataSessionPeerSurface {
	return dataSessionPeerSurface{
		ID:            peer.ID,
		Domain:        peer.Domain,
		TLSServerName: strings.TrimSpace(peer.TLSServerName),
		Endpoints:     endpointConfigDataSessionSurfaceForPolicy(peer.Endpoints, policy),
	}
}

func (daemon *Daemon) compatibleEndpointCryptoPlacements(rawTransport string, security dataplane.EndpointSecurityMetadata) []string {
	if !transportSupportsCryptoPlacement(rawTransport) || !endpointEncryptionFullySecure(security.Encryption) {
		return nil
	}
	local := advertisedTransportCryptoPlacements(effectiveTransportCryptoPlacementConfig(daemon.desired.TransportPolicy))
	remote := security.CryptoPlacements
	if len(remote) == 0 {
		return local
	}
	out := make([]string, 0, len(local))
	for _, placement := range local {
		if endpointListContains(remote, placement, normalizeEndpointCryptoPlacement) {
			out = append(out, placement)
		}
	}
	if len(out) == 0 {
		return remote
	}
	return out
}

func dataSessionPeerSurfacesCompatible(left, right dataSessionPeerSurface) bool {
	if left.ID != right.ID || left.Domain != right.Domain ||
		strings.TrimSpace(left.TLSServerName) != strings.TrimSpace(right.TLSServerName) ||
		len(left.Endpoints) != len(right.Endpoints) {
		return false
	}
	for index := range left.Endpoints {
		if !dataSessionEndpointSurfacesCompatible(left.Endpoints[index], right.Endpoints[index]) {
			return false
		}
	}
	return true
}

func dataSessionEndpointSurfacesCompatible(left, right dataSessionEndpointSurface) bool {
	if left.Name != right.Name ||
		strings.TrimSpace(left.Mode) != strings.TrimSpace(right.Mode) ||
		strings.TrimSpace(left.Address) != strings.TrimSpace(right.Address) ||
		strings.TrimSpace(left.Listen) != strings.TrimSpace(right.Listen) ||
		endpointLocalBindSurface(left.LocalBind) != endpointLocalBindSurface(right.LocalBind) ||
		strings.TrimSpace(left.Transport) != strings.TrimSpace(right.Transport) ||
		left.Priority != right.Priority ||
		strings.TrimSpace(left.TLSServerName) != strings.TrimSpace(right.TLSServerName) ||
		left.Enabled != right.Enabled {
		return false
	}
	return endpointSecuritySurfacesCompatible(left.Security, right.Security) &&
		transportProfileSurfacesCompatible(left.Profile, right.Profile)
}

func endpointSecuritySurfacesCompatible(left, right dataplane.EndpointSecurityMetadata) bool {
	leftPlacements := normalizeEndpointList(left.CryptoPlacements, normalizeEndpointCryptoPlacement)
	rightPlacements := normalizeEndpointList(right.CryptoPlacements, normalizeEndpointCryptoPlacement)
	left.CryptoPlacements = nil
	right.CryptoPlacements = nil
	if !reflect.DeepEqual(left, right) {
		return false
	}
	return endpointCryptoPlacementSetsCompatible(leftPlacements, rightPlacements)
}

func endpointCryptoPlacementSetsCompatible(left, right []string) bool {
	if len(left) == 0 || len(right) == 0 {
		return len(left) == len(right)
	}
	for _, placement := range left {
		if endpointListContains(right, placement, normalizeEndpointCryptoPlacement) {
			return true
		}
	}
	return false
}

func endpointConfigDataSessionSurface(endpoints []config.EndpointConfig) []dataSessionEndpointSurface {
	return endpointConfigDataSessionSurfaceForPolicy(endpoints, config.TransportPolicyConfig{})
}

func endpointConfigDataSessionSurfaceForPolicy(endpoints []config.EndpointConfig, policy config.TransportPolicyConfig) []dataSessionEndpointSurface {
	out := make([]dataSessionEndpointSurface, 0, len(endpoints))
	for _, endpoint := range endpoints {
		out = append(out, dataSessionEndpointSurface{
			Name:          endpoint.Name,
			Mode:          endpointDataSessionMode(endpoint),
			Address:       strings.TrimSpace(endpoint.Address),
			Listen:        strings.TrimSpace(endpoint.Listen),
			LocalBind:     endpointLocalBindSurface(endpoint.LocalBind),
			Transport:     strings.TrimSpace(endpoint.Transport),
			Priority:      endpoint.Priority,
			TLSServerName: strings.TrimSpace(endpoint.TLSServerName),
			Enabled:       endpointDataSessionEnabled(endpoint),
			Security:      endpointSecuritySurfaceForPolicy(endpoint, policy),
			Profile:       endpointTransportProfileSurfaceFromConfig(endpoint),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].Transport != out[j].Transport {
			return out[i].Transport < out[j].Transport
		}
		return out[i].Address < out[j].Address
	})
	return out
}

func endpointLocalBindSurface(bind config.EndpointLocalBindConfig) config.EndpointLocalBindConfig {
	return config.EndpointLocalBindConfig{
		SourceIP: strings.TrimSpace(bind.SourceIP),
		Iface:    strings.TrimSpace(bind.Iface),
	}
}

func endpointTransportProfileSurfaceFromConfig(endpoint config.EndpointConfig) dataplane.TransportProfileMetadata {
	if !endpointTransportProfileConfigured(endpoint.Profile) {
		return dataplane.TransportProfileMetadata{}
	}
	return endpointTransportProfileMetadataFromConfig(endpoint.Profile)
}

func endpointDataSessionMode(endpoint config.EndpointConfig) string {
	if endpoint.Mode != "" {
		return string(endpoint.Mode)
	}
	if strings.TrimSpace(endpoint.Address) != "" && strings.TrimSpace(endpoint.Listen) == "" {
		return string(config.EndpointModeActive)
	}
	return string(config.EndpointModePassive)
}

func endpointDataSessionEnabled(endpoint config.EndpointConfig) bool {
	if endpoint.Enabled {
		return true
	}
	return !endpoint.EnabledSet
}

func endpointSecuritySurfaceForPolicy(endpoint config.EndpointConfig, policy config.TransportPolicyConfig) dataplane.EndpointSecurityMetadata {
	metadata := endpointSecurityMetadataFromConfig(endpoint.Security, endpoint.TLSServerName)
	if metadata.LinkTLS == "" {
		if transportSupportsTLSExporter(transportProtocolFromString(endpoint.Transport)) {
			metadata.LinkTLS = endpointLinkTLSOptional
		} else {
			metadata.LinkTLS = endpointLinkTLSUnsupported
		}
	}
	if metadata.TLSIdentity == "" && metadata.LinkTLS != endpointLinkTLSUnsupported {
		metadata.TLSIdentity = normalizedTransportTLSIdentityMode(policy.TLSIdentity.Mode)
	}
	if metadata.Encryption == "" {
		metadata.Encryption = parseSecureTransportEncryption(policy.Encryption)
	}
	if len(metadata.KeySources) == 0 && endpointEncryptionUsesCrypto(metadata.Encryption) {
		metadata.KeySources = advertisedEndpointKeySources(policy.CryptoKeySource, endpoint.Transport)
	}
	if metadata.WireFormat == "" && endpointEncryptionUsesSecureEnvelope(metadata.Encryption) {
		metadata.WireFormat = endpointWireFormatTrustIXSecureDataV1
	}
	if len(metadata.CryptoSuites) == 0 && endpointEncryptionUsesCrypto(metadata.Encryption) {
		metadata.CryptoSuites = effectiveSecureTransportCryptoSuitesForEndpointPolicy(endpoint, policy)
	}
	if len(metadata.CryptoPlacements) == 0 && transportSupportsCryptoPlacement(endpoint.Transport) && endpointEncryptionFullySecure(metadata.Encryption) {
		metadata.CryptoPlacements = advertisedTransportCryptoPlacements(effectiveTransportCryptoPlacementConfig(policy))
	}
	return metadata
}

func transportProtocolFromString(raw string) transport.Protocol {
	return transport.Protocol(strings.ToLower(strings.TrimSpace(raw)))
}

func advertisementDataSessionSurfacesEqual(left, right advertisementResponse) bool {
	return reflect.DeepEqual(advertisementDataSessionSurfaceFor(left), advertisementDataSessionSurfaceFor(right))
}

func advertisementDataSessionSurfaceFor(advertisement advertisementResponse) advertisementDataSessionSurface {
	endpoints := append([]dataplane.EndpointMetadata(nil), advertisement.Endpoints...)
	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].ID != endpoints[j].ID {
			return endpoints[i].ID < endpoints[j].ID
		}
		if endpoints[i].Transport != endpoints[j].Transport {
			return endpoints[i].Transport < endpoints[j].Transport
		}
		return endpoints[i].Address < endpoints[j].Address
	})
	return advertisementDataSessionSurface{
		DomainID:      strings.TrimSpace(advertisement.DomainID),
		IXID:          strings.TrimSpace(advertisement.IXID),
		IXCertificate: append([]byte(nil), advertisement.IXCertificate...),
		Endpoints:     endpoints,
	}
}
