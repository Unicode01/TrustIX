package daemon

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/routing"
	rstate "trustix.local/trustix/internal/runtime"
	"trustix.local/trustix/internal/transport"
)

type linkDiagnosticsResponse struct {
	LocalIX   string                 `json:"local_ix"`
	Links     []linkDiagnosticStatus `json:"links"`
	Total     int                    `json:"total,omitempty"`
	Offset    int                    `json:"offset,omitempty"`
	Limit     int                    `json:"limit,omitempty"`
	Truncated bool                   `json:"truncated,omitempty"`
}

type linkDiagnosticStatus struct {
	Peer            string                   `json:"peer"`
	Domain          string                   `json:"domain,omitempty"`
	Source          string                   `json:"source,omitempty"`
	ControlAPI      string                   `json:"control_api,omitempty"`
	Static          bool                     `json:"static"`
	Dynamic         bool                     `json:"dynamic"`
	Trusted         bool                     `json:"trusted"`
	State           string                   `json:"state"`
	Warnings        []string                 `json:"warnings,omitempty"`
	ActiveSessions  int                      `json:"active_sessions"`
	CurrentFlows    uint64                   `json:"current_flows"`
	PacketsSent     uint64                   `json:"packets_sent"`
	PacketsReceived uint64                   `json:"packets_received"`
	BytesSent       uint64                   `json:"bytes_sent"`
	BytesReceived   uint64                   `json:"bytes_received"`
	SendErrors      uint64                   `json:"send_errors"`
	LastTX          time.Time                `json:"last_tx,omitempty"`
	LastRX          time.Time                `json:"last_rx,omitempty"`
	LastUp          time.Time                `json:"last_up,omitempty"`
	Routes          []linkDiagnosticRoute    `json:"routes,omitempty"`
	Endpoints       []linkDiagnosticEndpoint `json:"endpoints"`
	Sessions        []dataPathSessionStatus  `json:"sessions,omitempty"`
}

type linkDiagnosticRoute struct {
	Prefix   core.Prefix       `json:"prefix"`
	Owner    core.IXID         `json:"owner,omitempty"`
	NextHop  core.IXID         `json:"next_hop,omitempty"`
	Endpoint core.EndpointID   `json:"endpoint,omitempty"`
	Policy   core.PolicyID     `json:"policy,omitempty"`
	Kind     routing.RouteKind `json:"kind,omitempty"`
	Metric   int               `json:"metric"`
	Source   string            `json:"source,omitempty"`
}

type linkDiagnosticEndpoint struct {
	Name               string        `json:"name"`
	Transport          string        `json:"transport"`
	Mode               string        `json:"mode,omitempty"`
	Address            string        `json:"address,omitempty"`
	Enabled            bool          `json:"enabled"`
	ReverseOnly        bool          `json:"reverse_only,omitempty"`
	Usable             bool          `json:"usable"`
	KernelCompatible   bool          `json:"kernel_compatible"`
	SecurityCompatible bool          `json:"security_compatible"`
	ProfileCompatible  bool          `json:"profile_compatible"`
	Profile            string        `json:"profile,omitempty"`
	Datapath           string        `json:"datapath,omitempty"`
	Features           []string      `json:"features,omitempty"`
	LinkTLS            string        `json:"link_tls,omitempty"`
	Encryption         string        `json:"encryption,omitempty"`
	CryptoPlacements   []string      `json:"crypto_placements,omitempty"`
	ActiveSessions     int           `json:"active_sessions"`
	CurrentFlows       uint64        `json:"current_flows"`
	Health             string        `json:"health,omitempty"`
	RTT                time.Duration `json:"rtt,omitempty"`
	LastError          string        `json:"last_error,omitempty"`
	ObservedAt         time.Time     `json:"observed_at,omitempty"`
	LastSent           time.Time     `json:"last_sent,omitempty"`
	LastReceived       time.Time     `json:"last_received,omitempty"`
	SendErrors         uint64        `json:"send_errors,omitempty"`
	PacketsSent        uint64        `json:"packets_sent,omitempty"`
	PacketsReceived    uint64        `json:"packets_received,omitempty"`
	BytesSent          uint64        `json:"bytes_sent,omitempty"`
	BytesReceived      uint64        `json:"bytes_received,omitempty"`
}

type linkDiagnosticTraffic struct {
	PacketsSent     uint64
	PacketsReceived uint64
	BytesSent       uint64
	BytesReceived   uint64
	LastTX          time.Time
	LastRX          time.Time
}

func (daemon *Daemon) handleLinks(w http.ResponseWriter, r *http.Request) {
	peer := core.IXID(strings.TrimSpace(firstQueryValue(r.URL.Query(), "peer", "ix", "ix_id")))
	offset, limit, err := parsePaginationParams(r, 0)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, daemon.linkDiagnostics(peer, offset, limit))
}

func (daemon *Daemon) linkDiagnostics(peerFilter core.IXID, offset, limit int) linkDiagnosticsResponse {
	view := daemon.controlViewSnapshot()
	dataPath := view.DataPath
	routes := view.Routes
	peers := daemon.peerConfigsSnapshot()
	dynamic := daemon.dynamicMemberSources()
	static := make(map[core.IXID]struct{}, len(daemon.desired.Peers))
	for _, peer := range daemon.desired.Peers {
		static[peer.ID] = struct{}{}
	}
	sessionsByPeer := make(map[core.IXID][]dataPathSessionStatus)
	for _, session := range dataPath.Sessions {
		peer := core.IXID(session.Peer)
		sessionsByPeer[peer] = append(sessionsByPeer[peer], session)
	}
	routeByPeer := make(map[core.IXID][]linkDiagnosticRoute)
	for _, route := range routes {
		if route.NextHop == "" || route.NextHop == daemon.desired.IX.ID {
			continue
		}
		routeByPeer[route.NextHop] = append(routeByPeer[route.NextHop], linkDiagnosticRoute{
			Prefix:   route.Prefix,
			Owner:    route.Owner,
			NextHop:  route.NextHop,
			Endpoint: route.Endpoint,
			Policy:   route.Policy,
			Kind:     route.Kind,
			Metric:   route.Metric,
			Source:   route.Source,
		})
	}
	endpointStates := linkEndpointStateMap(dataPath.EndpointState)
	endpointStats := linkEndpointStatsMap(dataPath.EndpointStats)
	peerTraffic, endpointTraffic := linkTelemetryTraffic(dataPath)
	seen := make(map[core.IXID]struct{}, len(peers)+len(sessionsByPeer))
	links := make([]linkDiagnosticStatus, 0, len(peers)+len(sessionsByPeer))
	for _, peer := range peers {
		if peerFilter != "" && peer.ID != peerFilter {
			continue
		}
		links = append(links, daemon.buildLinkDiagnostic(peer, static, dynamic, sessionsByPeer[peer.ID], routeByPeer[peer.ID], endpointStates, endpointStats, peerTraffic[peer.ID], endpointTraffic))
		seen[peer.ID] = struct{}{}
	}
	for peer, sessions := range sessionsByPeer {
		if _, ok := seen[peer]; ok {
			continue
		}
		if peerFilter != "" && peer != peerFilter {
			continue
		}
		links = append(links, daemon.buildLinkDiagnostic(config.PeerConfig{ID: peer}, static, dynamic, sessions, routeByPeer[peer], endpointStates, endpointStats, peerTraffic[peer], endpointTraffic))
	}
	sort.Slice(links, func(i, j int) bool {
		return links[i].Peer < links[j].Peer
	})
	pagedLinks, total, truncated := paginateSlice(links, offset, limit)
	return linkDiagnosticsResponse{
		LocalIX:   string(daemon.desired.IX.ID),
		Links:     pagedLinks,
		Total:     total,
		Offset:    offset,
		Limit:     limit,
		Truncated: truncated,
	}
}

func (daemon *Daemon) buildLinkDiagnostic(peer config.PeerConfig, static map[core.IXID]struct{}, dynamic map[core.IXID]memberRecord, sessions []dataPathSessionStatus, routes []linkDiagnosticRoute, endpointStates map[linkEndpointKey]rstate.EndpointState, endpointStats map[endpointStateKey]dataPathEndpointStats, peerTraffic linkDiagnosticTraffic, endpointTraffic map[endpointStateKey]linkDiagnosticTraffic) linkDiagnosticStatus {
	_, isStatic := static[peer.ID]
	record, isDynamic := dynamic[peer.ID]
	source := "static"
	trusted := isStatic
	if isDynamic {
		trusted = true
		if record.Source != "" {
			source = record.Source
		} else if !isStatic {
			source = "dynamic"
		}
	} else if !isStatic {
		source = "session"
	}
	status := linkDiagnosticStatus{
		Peer:       string(peer.ID),
		Domain:     string(peer.Domain),
		Source:     source,
		ControlAPI: peer.ControlAPI,
		Static:     isStatic,
		Dynamic:    isDynamic,
		Trusted:    trusted,
		Routes:     append([]linkDiagnosticRoute(nil), routes...),
		Sessions:   append([]dataPathSessionStatus(nil), sessions...),
	}
	for _, session := range sessions {
		status.ActiveSessions++
		status.PacketsSent += session.Stats.PacketsSent
		status.PacketsReceived += session.Stats.PacketsReceived
		status.BytesSent += session.Stats.BytesSent
		status.BytesReceived += session.Stats.BytesReceived
		if session.LastTX.After(status.LastTX) {
			status.LastTX = session.LastTX
		}
		if session.LastRX.After(status.LastRX) {
			status.LastRX = session.LastRX
		}
		if session.LastUp.After(status.LastUp) {
			status.LastUp = session.LastUp
		}
	}
	mergeLinkDiagnosticTraffic(&status, peerTraffic)
	status.Endpoints = daemon.linkDiagnosticEndpoints(peer, sessions, endpointStates, endpointStats, endpointTraffic)
	for _, endpoint := range status.Endpoints {
		status.CurrentFlows += endpoint.CurrentFlows
		status.SendErrors += endpoint.SendErrors
	}
	status.State, status.Warnings = linkDiagnosticState(status)
	return status
}

func (daemon *Daemon) linkDiagnosticEndpoints(peer config.PeerConfig, sessions []dataPathSessionStatus, endpointStates map[linkEndpointKey]rstate.EndpointState, endpointStats map[endpointStateKey]dataPathEndpointStats, endpointTraffic map[endpointStateKey]linkDiagnosticTraffic) []linkDiagnosticEndpoint {
	out := make([]linkDiagnosticEndpoint, 0, len(peer.Endpoints))
	for _, endpoint := range peer.Endpoints {
		security := endpointSecurityMetadataFromConfig(endpoint.Security, endpoint.TLSServerName)
		if security.Encryption == "" {
			security.Encryption = parseSecureTransportEncryption(daemon.desired.TransportPolicy.Encryption)
		}
		kernelCompatible := daemon.endpointKernelTransportCompatible(endpoint.Transport)
		securityCompatible := daemon.endpointSecurityCompatible(endpoint)
		profileCompatible := daemon.endpointTransportProfileCompatible(endpoint)
		profile := endpointTransportProfileMetadataFromConfig(endpoint.Profile)
		activeReverse := daemon.activeReverseSessionsForEndpoint(peer.ID, endpoint)
		reverseOnly := strings.TrimSpace(endpoint.Address) == ""
		activeSessions := activeReverse
		for _, session := range sessions {
			if session.Endpoint != string(endpoint.Name) || session.Transport != endpoint.Transport {
				continue
			}
			if !session.Reverse {
				activeSessions++
			}
		}
		key := endpointKey(peer.ID, endpoint)
		state := endpointStates[linkEndpointKey{Peer: peer.ID, Endpoint: endpoint.Name}]
		stats := endpointStats[key]
		traffic := endpointTraffic[key]
		if key.Address != "" {
			endpointOnlyKey := key
			endpointOnlyKey.Address = ""
			traffic = maxLinkDiagnosticTraffic(traffic, endpointTraffic[endpointOnlyKey])
		}
		lastSent := latestTime(stats.LastSent, traffic.LastTX)
		usable := endpoint.Enabled && kernelCompatible && securityCompatible && profileCompatible && (!reverseOnly || activeReverse > 0)
		out = append(out, linkDiagnosticEndpoint{
			Name:               string(endpoint.Name),
			Transport:          endpoint.Transport,
			Mode:               string(endpoint.Mode),
			Address:            endpoint.Address,
			Enabled:            endpoint.Enabled,
			ReverseOnly:        reverseOnly,
			Usable:             usable,
			KernelCompatible:   kernelCompatible,
			SecurityCompatible: securityCompatible,
			ProfileCompatible:  profileCompatible,
			Profile:            profile.Profile,
			Datapath:           profile.Datapath,
			Features:           append([]string(nil), profile.Features...),
			LinkTLS:            security.LinkTLS,
			Encryption:         security.Encryption,
			CryptoPlacements:   append([]string(nil), security.CryptoPlacements...),
			ActiveSessions:     activeSessions,
			CurrentFlows:       daemon.endpointFlowCount(peer.ID, endpoint.Name),
			Health:             string(state.Health),
			RTT:                state.RTT,
			LastError:          firstNonEmpty(state.Error, stats.LastError),
			ObservedAt:         state.ObservedAt,
			LastSent:           lastSent,
			LastReceived:       traffic.LastRX,
			SendErrors:         stats.SendErrors,
			PacketsSent:        maxUint64(stats.PacketsSent, traffic.PacketsSent),
			PacketsReceived:    traffic.PacketsReceived,
			BytesSent:          maxUint64(stats.BytesSent, traffic.BytesSent),
			BytesReceived:      traffic.BytesReceived,
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

func (daemon *Daemon) dynamicMemberSources() map[core.IXID]memberRecord {
	daemon.membershipMu.RLock()
	defer daemon.membershipMu.RUnlock()
	out := make(map[core.IXID]memberRecord, len(daemon.members))
	for ixID, record := range daemon.members {
		if ixID == daemon.desired.IX.ID {
			continue
		}
		out[ixID] = record
	}
	return out
}

type linkEndpointKey struct {
	Peer     core.IXID
	Endpoint core.EndpointID
}

func linkEndpointStateMap(states []rstate.EndpointState) map[linkEndpointKey]rstate.EndpointState {
	out := make(map[linkEndpointKey]rstate.EndpointState, len(states))
	for _, state := range states {
		key := linkEndpointKey{Peer: state.Peer, Endpoint: state.Endpoint}
		out[key] = state
	}
	return out
}

func linkEndpointStatsMap(stats []dataPathEndpointStats) map[endpointStateKey]dataPathEndpointStats {
	out := make(map[endpointStateKey]dataPathEndpointStats, len(stats))
	for _, stat := range stats {
		key := endpointStateKey{
			Peer:      stat.Peer,
			Endpoint:  stat.Endpoint,
			Transport: transportProtocol(stat.Transport),
			Address:   stat.Address,
		}
		out[key] = stat
	}
	return out
}

func linkTelemetryTraffic(dataPath dataPathStatus) (map[core.IXID]linkDiagnosticTraffic, map[endpointStateKey]linkDiagnosticTraffic) {
	byPeer := make(map[core.IXID]linkDiagnosticTraffic)
	byEndpoint := make(map[endpointStateKey]linkDiagnosticTraffic)
	if dataPath.ExperimentalTCP != nil {
		addLinkTelemetryTraffic(byPeer, byEndpoint, dataPath.ExperimentalTCP.Telemetry)
	}
	if dataPath.KernelUDP != nil {
		addLinkTelemetryTraffic(byPeer, byEndpoint, dataPath.KernelUDP.Telemetry)
	}
	return byPeer, byEndpoint
}

func addLinkTelemetryTraffic(byPeer map[core.IXID]linkDiagnosticTraffic, byEndpoint map[endpointStateKey]linkDiagnosticTraffic, items []dataplane.TransportPathTelemetry) {
	for _, item := range items {
		if item.Peer == "" {
			continue
		}
		traffic := linkDiagnosticTraffic{
			PacketsSent:     item.TXFrames,
			PacketsReceived: item.RXFrames,
			BytesSent:       item.TXBytes,
			BytesReceived:   item.RXBytes,
		}
		if item.TXFrames > 0 || item.TXBytes > 0 {
			traffic.LastTX = item.LastSeen
		}
		if item.RXFrames > 0 || item.RXBytes > 0 {
			traffic.LastRX = item.LastSeen
		}
		if linkDiagnosticTrafficEmpty(traffic) {
			continue
		}
		addPeerLinkTraffic(byPeer, item.Peer, traffic)
		if item.Endpoint == "" {
			continue
		}
		key := endpointStateKey{
			Peer:      item.Peer,
			Endpoint:  item.Endpoint,
			Transport: linkTelemetryTransport(item.Protocol),
			Address:   item.RemoteAddress,
		}
		addEndpointLinkTraffic(byEndpoint, key, traffic)
		if key.Address != "" {
			key.Address = ""
			addEndpointLinkTraffic(byEndpoint, key, traffic)
		}
	}
}

func addPeerLinkTraffic(items map[core.IXID]linkDiagnosticTraffic, peer core.IXID, traffic linkDiagnosticTraffic) {
	current := items[peer]
	current.add(traffic)
	items[peer] = current
}

func addEndpointLinkTraffic(items map[endpointStateKey]linkDiagnosticTraffic, key endpointStateKey, traffic linkDiagnosticTraffic) {
	if key.Transport == "" {
		return
	}
	current := items[key]
	current.add(traffic)
	items[key] = current
}

func (traffic *linkDiagnosticTraffic) add(other linkDiagnosticTraffic) {
	traffic.PacketsSent += other.PacketsSent
	traffic.PacketsReceived += other.PacketsReceived
	traffic.BytesSent += other.BytesSent
	traffic.BytesReceived += other.BytesReceived
	traffic.LastTX = latestTime(traffic.LastTX, other.LastTX)
	traffic.LastRX = latestTime(traffic.LastRX, other.LastRX)
}

func linkDiagnosticTrafficEmpty(traffic linkDiagnosticTraffic) bool {
	return traffic.PacketsSent == 0 &&
		traffic.PacketsReceived == 0 &&
		traffic.BytesSent == 0 &&
		traffic.BytesReceived == 0 &&
		traffic.LastTX.IsZero() &&
		traffic.LastRX.IsZero()
}

func mergeLinkDiagnosticTraffic(status *linkDiagnosticStatus, traffic linkDiagnosticTraffic) {
	status.PacketsSent = maxUint64(status.PacketsSent, traffic.PacketsSent)
	status.PacketsReceived = maxUint64(status.PacketsReceived, traffic.PacketsReceived)
	status.BytesSent = maxUint64(status.BytesSent, traffic.BytesSent)
	status.BytesReceived = maxUint64(status.BytesReceived, traffic.BytesReceived)
	status.LastTX = latestTime(status.LastTX, traffic.LastTX)
	status.LastRX = latestTime(status.LastRX, traffic.LastRX)
}

func maxLinkDiagnosticTraffic(a, b linkDiagnosticTraffic) linkDiagnosticTraffic {
	return linkDiagnosticTraffic{
		PacketsSent:     maxUint64(a.PacketsSent, b.PacketsSent),
		PacketsReceived: maxUint64(a.PacketsReceived, b.PacketsReceived),
		BytesSent:       maxUint64(a.BytesSent, b.BytesSent),
		BytesReceived:   maxUint64(a.BytesReceived, b.BytesReceived),
		LastTX:          latestTime(a.LastTX, b.LastTX),
		LastRX:          latestTime(a.LastRX, b.LastRX),
	}
}

func linkTelemetryTransport(protocol string) transport.Protocol {
	switch protocol {
	case "kernel_udp":
		return transport.ProtocolUDP
	default:
		return transport.Protocol(protocol)
	}
}

func latestTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func maxUint64(a, b uint64) uint64 {
	if b > a {
		return b
	}
	return a
}

func linkDiagnosticState(status linkDiagnosticStatus) (string, []string) {
	var warnings []string
	if status.ActiveSessions == 0 {
		warnings = append(warnings, "no active transport session")
	}
	usableEndpoints := 0
	selectedEndpoints := linkDiagnosticSelectedEndpoints(status)
	for _, endpoint := range status.Endpoints {
		if endpoint.Usable {
			usableEndpoints++
		}
		if !endpoint.Enabled {
			continue
		}
		if len(selectedEndpoints) > 0 {
			if _, selected := selectedEndpoints[endpoint.Name]; !selected && endpoint.ActiveSessions == 0 && endpoint.SendErrors == 0 {
				continue
			}
		}
		if endpoint.Enabled && !endpoint.KernelCompatible {
			warnings = append(warnings, endpoint.Name+": kernel transport incompatible")
		}
		if endpoint.Enabled && !endpoint.SecurityCompatible {
			warnings = append(warnings, endpoint.Name+": security policy incompatible")
		}
		if endpoint.ReverseOnly && endpoint.ActiveSessions == 0 {
			warnings = append(warnings, endpoint.Name+": waiting for reverse session")
		}
		if endpoint.LastError != "" {
			warnings = append(warnings, endpoint.Name+": "+endpoint.LastError)
		}
	}
	switch {
	case status.ActiveSessions > 0 && len(warnings) == 0:
		return "up", nil
	case status.ActiveSessions > 0:
		return "degraded", warnings
	case usableEndpoints > 0:
		return "idle", warnings
	default:
		return "down", warnings
	}
}

func linkDiagnosticSelectedEndpoints(status linkDiagnosticStatus) map[string]struct{} {
	selected := make(map[string]struct{})
	for _, route := range status.Routes {
		if route.Endpoint != "" {
			selected[string(route.Endpoint)] = struct{}{}
		}
	}
	if len(selected) > 0 {
		return selected
	}
	for _, session := range status.Sessions {
		if session.Endpoint != "" {
			selected[session.Endpoint] = struct{}{}
		}
	}
	if len(selected) == 0 {
		return nil
	}
	return selected
}
