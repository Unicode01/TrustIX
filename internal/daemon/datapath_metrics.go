package daemon

import (
	"sort"
	"sync"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/routing"
	"trustix.local/trustix/internal/transport"
)

type dataPathMetrics struct {
	mu        sync.Mutex
	routes    map[dataPathRouteKey]*dataPathRouteStats
	peers     map[core.IXID]*dataPathPeerStats
	endpoints map[endpointStateKey]*dataPathEndpointStats
}

type dataPathRouteKey struct {
	Prefix   core.Prefix
	Owner    core.IXID
	NextHop  core.IXID
	Endpoint core.EndpointID
	Policy   core.PolicyID
	Kind     routing.RouteKind
}

type dataPathRouteStats struct {
	Prefix      core.Prefix       `json:"prefix"`
	Owner       core.IXID         `json:"owner,omitempty"`
	NextHop     core.IXID         `json:"next_hop,omitempty"`
	Endpoint    core.EndpointID   `json:"endpoint,omitempty"`
	Policy      core.PolicyID     `json:"policy,omitempty"`
	Kind        routing.RouteKind `json:"kind,omitempty"`
	Hits        uint64            `json:"hits"`
	PacketsSent uint64            `json:"packets_sent"`
	SendErrors  uint64            `json:"send_errors"`
	BytesSent   uint64            `json:"bytes_sent"`
	LastHit     time.Time         `json:"last_hit,omitempty"`
	LastSent    time.Time         `json:"last_sent,omitempty"`
	LastError   string            `json:"last_error,omitempty"`
}

type dataPathPeerStats struct {
	Peer           core.IXID `json:"peer"`
	PacketsSent    uint64    `json:"packets_sent"`
	SendErrors     uint64    `json:"send_errors"`
	BytesSent      uint64    `json:"bytes_sent"`
	ActiveSessions int       `json:"active_sessions"`
	LastSent       time.Time `json:"last_sent,omitempty"`
	LastError      string    `json:"last_error,omitempty"`
}

type dataPathEndpointStats struct {
	Peer           core.IXID       `json:"peer"`
	Endpoint       core.EndpointID `json:"endpoint"`
	Transport      string          `json:"transport,omitempty"`
	Address        string          `json:"address,omitempty"`
	PacketsSent    uint64          `json:"packets_sent"`
	SendErrors     uint64          `json:"send_errors"`
	BytesSent      uint64          `json:"bytes_sent"`
	ActiveSessions int             `json:"active_sessions"`
	CurrentFlows   uint64          `json:"current_flows"`
	LastSent       time.Time       `json:"last_sent,omitempty"`
	LastError      string          `json:"last_error,omitempty"`
}

func (daemon *Daemon) recordRouteHit(decision routing.Decision) {
	now := time.Now().UTC()
	daemon.dataMetrics.mu.Lock()
	stats := daemon.dataMetrics.routeStatsLocked(decision.Route)
	stats.Hits++
	stats.LastHit = now
	daemon.dataMetrics.mu.Unlock()
}

func (daemon *Daemon) recordRouteSend(decision routing.Decision, bytes int, err error) {
	now := time.Now().UTC()
	daemon.dataMetrics.mu.Lock()
	stats := daemon.dataMetrics.routeStatsLocked(decision.Route)
	if err != nil {
		stats.SendErrors++
		stats.LastError = err.Error()
	} else {
		stats.PacketsSent++
		stats.BytesSent += uint64(bytes)
		stats.LastError = ""
	}
	stats.LastSent = now
	daemon.dataMetrics.mu.Unlock()
}

func (daemon *Daemon) recordPeerSend(peer core.IXID, bytes int, err error) {
	now := time.Now().UTC()
	daemon.dataMetrics.mu.Lock()
	if daemon.dataMetrics.peers == nil {
		daemon.dataMetrics.peers = make(map[core.IXID]*dataPathPeerStats)
	}
	stats := daemon.dataMetrics.peers[peer]
	if stats == nil {
		stats = &dataPathPeerStats{Peer: peer}
		daemon.dataMetrics.peers[peer] = stats
	}
	if err != nil {
		stats.SendErrors++
		stats.LastError = err.Error()
	} else {
		stats.PacketsSent++
		stats.BytesSent += uint64(bytes)
		stats.LastError = ""
	}
	stats.LastSent = now
	daemon.dataMetrics.mu.Unlock()
}

func (daemon *Daemon) recordEndpointSend(peer core.IXID, endpoint config.EndpointConfig, bytes int, err error) {
	now := time.Now().UTC()
	key := endpointKey(peer, endpoint)
	daemon.dataMetrics.mu.Lock()
	if daemon.dataMetrics.endpoints == nil {
		daemon.dataMetrics.endpoints = make(map[endpointStateKey]*dataPathEndpointStats)
	}
	stats := daemon.dataMetrics.endpoints[key]
	if stats == nil {
		stats = &dataPathEndpointStats{
			Peer:      peer,
			Endpoint:  endpoint.Name,
			Transport: endpoint.Transport,
			Address:   endpoint.Address,
		}
		daemon.dataMetrics.endpoints[key] = stats
	}
	if err != nil {
		stats.SendErrors++
		stats.LastError = err.Error()
	} else {
		stats.PacketsSent++
		stats.BytesSent += uint64(bytes)
		stats.LastError = ""
	}
	stats.LastSent = now
	daemon.dataMetrics.mu.Unlock()
}

func (daemon *Daemon) recordSendMetrics(decision routing.Decision, peer core.IXID, endpoint config.EndpointConfig, bytes int, err error) {
	daemon.recordSendMetricsBatch(decision, peer, endpoint, bytes, 1, err)
}

func (daemon *Daemon) recordSendMetricsBatch(decision routing.Decision, peer core.IXID, endpoint config.EndpointConfig, bytes int, packets int, err error) {
	if packets <= 0 {
		packets = 1
	}
	now := time.Now().UTC()
	endpointKey := endpointKey(peer, endpoint)
	daemon.dataMetrics.mu.Lock()
	routeStats := daemon.dataMetrics.routeStatsLocked(decision.Route)
	if err != nil {
		routeStats.SendErrors++
		routeStats.LastError = err.Error()
	} else {
		routeStats.PacketsSent += uint64(packets)
		routeStats.BytesSent += uint64(bytes)
		routeStats.LastError = ""
	}
	routeStats.LastSent = now

	if daemon.dataMetrics.peers == nil {
		daemon.dataMetrics.peers = make(map[core.IXID]*dataPathPeerStats)
	}
	peerStats := daemon.dataMetrics.peers[peer]
	if peerStats == nil {
		peerStats = &dataPathPeerStats{Peer: peer}
		daemon.dataMetrics.peers[peer] = peerStats
	}
	if err != nil {
		peerStats.SendErrors++
		peerStats.LastError = err.Error()
	} else {
		peerStats.PacketsSent += uint64(packets)
		peerStats.BytesSent += uint64(bytes)
		peerStats.LastError = ""
	}
	peerStats.LastSent = now

	if daemon.dataMetrics.endpoints == nil {
		daemon.dataMetrics.endpoints = make(map[endpointStateKey]*dataPathEndpointStats)
	}
	endpointStats := daemon.dataMetrics.endpoints[endpointKey]
	if endpointStats == nil {
		endpointStats = &dataPathEndpointStats{
			Peer:      peer,
			Endpoint:  endpoint.Name,
			Transport: endpoint.Transport,
			Address:   endpoint.Address,
		}
		daemon.dataMetrics.endpoints[endpointKey] = endpointStats
	}
	if err != nil {
		endpointStats.SendErrors++
		endpointStats.LastError = err.Error()
	} else {
		endpointStats.PacketsSent += uint64(packets)
		endpointStats.BytesSent += uint64(bytes)
		endpointStats.LastError = ""
	}
	endpointStats.LastSent = now
	daemon.dataMetrics.mu.Unlock()
}

func (metrics *dataPathMetrics) routeStatsLocked(route routing.Route) *dataPathRouteStats {
	if metrics.routes == nil {
		metrics.routes = make(map[dataPathRouteKey]*dataPathRouteStats)
	}
	key := dataPathRouteKeyForRoute(route)
	stats := metrics.routes[key]
	if stats == nil {
		stats = &dataPathRouteStats{
			Prefix:   route.Prefix,
			Owner:    routeOwner(route),
			NextHop:  route.NextHop,
			Endpoint: route.Endpoint,
			Policy:   route.Policy,
			Kind:     route.Kind,
		}
		metrics.routes[key] = stats
	}
	return stats
}

func dataPathRouteKeyForRoute(route routing.Route) dataPathRouteKey {
	return dataPathRouteKey{
		Prefix:   route.Prefix,
		Owner:    routeOwner(route),
		NextHop:  route.NextHop,
		Endpoint: route.Endpoint,
		Policy:   route.Policy,
		Kind:     route.Kind,
	}
}

func dataPathEndpointKeyForMetadata(endpoint dataplane.EndpointMetadata) endpointStateKey {
	return endpointStateKey{
		Peer:      endpoint.Peer,
		Endpoint:  endpoint.ID,
		Transport: transport.Protocol(endpoint.Transport),
		Address:   endpoint.Address,
	}
}

func (daemon *Daemon) pruneDataPathMetrics(snapshot dataplane.Snapshot) {
	daemon.dataMetrics.mu.Lock()
	defer daemon.dataMetrics.mu.Unlock()

	if len(daemon.dataMetrics.routes) > 0 {
		activeRoutes := make(map[dataPathRouteKey]struct{}, len(snapshot.Routes))
		for _, route := range snapshot.Routes {
			activeRoutes[dataPathRouteKeyForRoute(route)] = struct{}{}
		}
		for key := range daemon.dataMetrics.routes {
			if _, ok := activeRoutes[key]; !ok {
				delete(daemon.dataMetrics.routes, key)
			}
		}
	}
	if len(daemon.dataMetrics.peers) > 0 {
		activePeers := make(map[core.IXID]struct{}, len(snapshot.Peers))
		for _, peer := range snapshot.Peers {
			activePeers[peer.ID] = struct{}{}
		}
		for peer := range daemon.dataMetrics.peers {
			if _, ok := activePeers[peer]; !ok {
				delete(daemon.dataMetrics.peers, peer)
			}
		}
	}
	if len(daemon.dataMetrics.endpoints) > 0 {
		activeEndpoints := make(map[endpointStateKey]struct{}, len(snapshot.Endpoints))
		for _, endpoint := range snapshot.Endpoints {
			activeEndpoints[dataPathEndpointKeyForMetadata(endpoint)] = struct{}{}
		}
		for key := range daemon.dataMetrics.endpoints {
			if _, ok := activeEndpoints[key]; !ok {
				delete(daemon.dataMetrics.endpoints, key)
			}
		}
	}
}

func (daemon *Daemon) dataPathMetricsSnapshot() ([]dataPathRouteStats, []dataPathPeerStats, []dataPathEndpointStats) {
	daemon.dataMetrics.mu.Lock()
	routes := make([]dataPathRouteStats, 0, len(daemon.dataMetrics.routes))
	for _, stats := range daemon.dataMetrics.routes {
		routes = append(routes, *stats)
	}
	peers := make([]dataPathPeerStats, 0, len(daemon.dataMetrics.peers))
	for _, stats := range daemon.dataMetrics.peers {
		peers = append(peers, *stats)
	}
	endpoints := make([]dataPathEndpointStats, 0, len(daemon.dataMetrics.endpoints))
	for _, stats := range daemon.dataMetrics.endpoints {
		endpoints = append(endpoints, *stats)
	}
	daemon.dataMetrics.mu.Unlock()

	activeByPeer, activeByEndpoint := daemon.activeDataSessions()
	var flowCounts map[endpointFlowKey]uint64
	if len(endpoints) > 0 {
		flowCounts = daemon.endpointFlowCounts()
	}
	for i := range peers {
		peers[i].ActiveSessions = activeByPeer[peers[i].Peer]
	}
	for i := range endpoints {
		key := endpointStateKey{
			Peer:      endpoints[i].Peer,
			Endpoint:  endpoints[i].Endpoint,
			Transport: transportProtocol(endpoints[i].Transport),
			Address:   endpoints[i].Address,
		}
		endpoints[i].ActiveSessions = activeByEndpoint[key]
		endpoints[i].CurrentFlows = flowCounts[endpointFlowKey{Peer: endpoints[i].Peer, Endpoint: endpoints[i].Endpoint}]
	}

	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Prefix != routes[j].Prefix {
			return routes[i].Prefix < routes[j].Prefix
		}
		if routes[i].Owner != routes[j].Owner {
			return routes[i].Owner < routes[j].Owner
		}
		if routes[i].NextHop != routes[j].NextHop {
			return routes[i].NextHop < routes[j].NextHop
		}
		return routes[i].Endpoint < routes[j].Endpoint
	})
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].Peer < peers[j].Peer
	})
	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].Peer != endpoints[j].Peer {
			return endpoints[i].Peer < endpoints[j].Peer
		}
		if endpoints[i].Endpoint != endpoints[j].Endpoint {
			return endpoints[i].Endpoint < endpoints[j].Endpoint
		}
		return endpoints[i].Address < endpoints[j].Address
	})
	return routes, peers, endpoints
}

func (daemon *Daemon) activeDataSessions() (map[core.IXID]int, map[endpointStateKey]int) {
	byPeer := make(map[core.IXID]int)
	byEndpoint := make(map[endpointStateKey]int)
	daemon.dataMu.Lock()
	defer daemon.dataMu.Unlock()
	for key := range daemon.dataSessions {
		byPeer[key.Peer]++
		address := key.Address
		if address == reverseSessionAddress {
			if runtime := daemon.dataSessionState[key]; runtime != nil {
				address = runtime.endpoint.Address
			} else {
				address = ""
			}
		}
		byEndpoint[endpointStateKey{
			Peer:      key.Peer,
			Endpoint:  key.Endpoint,
			Transport: key.Transport,
			Address:   address,
		}]++
	}
	return byPeer, byEndpoint
}

func transportProtocol(raw string) transport.Protocol {
	return transport.Protocol(raw)
}
