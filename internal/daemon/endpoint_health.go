package daemon

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	rstate "trustix.local/trustix/internal/runtime"
	"trustix.local/trustix/internal/transport"
)

const (
	defaultEndpointHealthTTL     = 90 * time.Second
	defaultEndpointProbeInterval = 30 * time.Second
	defaultEndpointProbeTimeout  = 2 * time.Second
)

type endpointStateKey struct {
	Peer      core.IXID
	Endpoint  core.EndpointID
	Transport transport.Protocol
	Address   string
}

type endpointFlowKey struct {
	Peer     core.IXID
	Endpoint core.EndpointID
}

type endpointByteCounter struct {
	Sent     uint64
	Received uint64
}

func (daemon *Daemon) endpointHealthPoller(ctx context.Context) {
	if daemon.probePeerEndpoints(ctx) {
		_ = daemon.applyRuntimeDataplaneSnapshot(ctx)
	}
	ticker := time.NewTicker(endpointProbeInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if daemon.probePeerEndpoints(ctx) {
				_ = daemon.applyRuntimeDataplaneSnapshot(ctx)
			}
		}
	}
}

func (daemon *Daemon) probePeerEndpoints(ctx context.Context) bool {
	var changed bool
	for _, peer := range daemon.peerConfigsSnapshot() {
		for _, endpoint := range peer.Endpoints {
			if endpoint.Address == "" || endpoint.Transport == "" {
				continue
			}
			protocol := transport.Protocol(endpoint.Transport)
			if !endpointSupportsPassiveProbe(protocol) {
				continue
			}
			tr, ok := daemon.transports.Get(protocol)
			if !ok {
				continue
			}
			probeCtx, cancel := context.WithTimeout(ctx, endpointProbeTimeout())
			result := tr.Probe(probeCtx, transport.Peer{
				ID:       peer.ID,
				DomainID: peer.Domain,
				Endpoints: []transport.Endpoint{
					transportEndpointFromConfig(endpoint),
				},
			})
			cancel()
			if result.CheckedAt.IsZero() {
				result.CheckedAt = time.Now().UTC()
			}
			if result.Healthy {
				if daemon.recordEndpointUp(peer.ID, endpoint, result.RTT) {
					changed = true
				}
				continue
			}
			if result.Error == "" && probeCtx.Err() != nil {
				result.Error = probeCtx.Err().Error()
			}
			if daemon.recordEndpointDown(peer.ID, endpoint, fmt.Errorf("%s", result.Error)) {
				changed = true
			}
		}
	}
	return changed
}

func endpointSupportsPassiveProbe(protocol transport.Protocol) bool {
	switch protocol {
	case transport.ProtocolTCP,
		transport.ProtocolWebSocket,
		transport.ProtocolHTTPConnect,
		transport.ProtocolQUIC,
		transport.ProtocolExperimentalTCP,
		transport.ProtocolUDP,
		transport.ProtocolGRE,
		transport.ProtocolIPIP,
		transport.ProtocolVXLAN:
		return true
	default:
		return false
	}
}

func (daemon *Daemon) peerConfigsSnapshot() []config.PeerConfig {
	daemon.membershipMu.RLock()
	staticMembers := make(map[core.IXID]advertisementResponse, len(daemon.members))
	dynamicIDs := make([]string, 0, len(daemon.members))
	static := make(map[core.IXID]struct{}, len(daemon.desired.Peers))
	for _, peer := range daemon.desired.Peers {
		static[peer.ID] = struct{}{}
		if record, ok := daemon.members[peer.ID]; ok {
			staticMembers[peer.ID] = record.Advertisement
		}
	}
	for ixID := range daemon.members {
		if ixID == daemon.desired.IX.ID {
			continue
		}
		if _, exists := static[ixID]; exists {
			continue
		}
		dynamicIDs = append(dynamicIDs, string(ixID))
	}
	sort.Strings(dynamicIDs)
	daemon.membershipMu.RUnlock()
	peers := make([]config.PeerConfig, 0, len(daemon.desired.Peers)+len(dynamicIDs))
	for _, peer := range daemon.desired.Peers {
		if advertisement, ok := staticMembers[peer.ID]; ok {
			peers = append(peers, daemon.mergeStaticPeerWithAdvertisement(peer, advertisement))
			continue
		}
		peers = append(peers, peer)
	}
	daemon.membershipMu.RLock()
	for _, rawID := range dynamicIDs {
		ixID := core.IXID(rawID)
		peers = append(peers, daemon.peerConfigFromAdvertisement(daemon.members[ixID].Advertisement))
	}
	daemon.membershipMu.RUnlock()
	return peers
}

func (daemon *Daemon) recordEndpointUp(peer core.IXID, endpoint config.EndpointConfig, rtt time.Duration) bool {
	return daemon.recordEndpointState(peer, endpoint, rstate.EndpointUp, rtt, "")
}

func (daemon *Daemon) recordEndpointDown(peer core.IXID, endpoint config.EndpointConfig, err error) bool {
	message := ""
	if err != nil {
		message = err.Error()
	}
	return daemon.recordEndpointState(peer, endpoint, rstate.EndpointDown, 0, message)
}

func endpointProbeInterval() time.Duration {
	return durationFromEnv("TRUSTIX_ENDPOINT_PROBE_INTERVAL", defaultEndpointProbeInterval)
}

func endpointProbeTimeout() time.Duration {
	return durationFromEnv("TRUSTIX_ENDPOINT_PROBE_TIMEOUT", defaultEndpointProbeTimeout)
}

func endpointHealthTTL() time.Duration {
	ttl := durationFromEnv("TRUSTIX_ENDPOINT_HEALTH_TTL", defaultEndpointHealthTTL)
	minimum := endpointProbeInterval() * 3
	if ttl < minimum {
		return minimum
	}
	return ttl
}

func durationFromEnv(name string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	if seconds, err := strconv.ParseFloat(raw, 64); err == nil && seconds > 0 {
		return time.Duration(seconds * float64(time.Second))
	}
	if value, err := time.ParseDuration(raw); err == nil && value > 0 {
		return value
	}
	return fallback
}

func (daemon *Daemon) recordEndpointDownIfNoActiveSession(peer core.IXID, endpoint config.EndpointConfig, err error) bool {
	if daemon.endpointHasActiveDataSession(peer, endpoint) {
		return false
	}
	return daemon.recordEndpointDown(peer, endpoint, err)
}

func (daemon *Daemon) endpointHasActiveDataSession(peer core.IXID, endpoint config.EndpointConfig) bool {
	key := endpointKey(peer, endpoint)
	daemon.dataMu.Lock()
	defer daemon.dataMu.Unlock()
	for sessionKey := range daemon.dataSessions {
		if sessionKey.Peer != key.Peer ||
			sessionKey.Endpoint != key.Endpoint ||
			sessionKey.Transport != key.Transport {
			continue
		}
		if sessionKey.Address == key.Address || sessionKey.Address == reverseSessionAddress {
			return true
		}
	}
	return false
}

func (daemon *Daemon) recordEndpointState(peer core.IXID, endpoint config.EndpointConfig, health rstate.EndpointHealth, rtt time.Duration, message string) bool {
	if endpoint.Name == "" || endpoint.Address == "" {
		return false
	}
	now := time.Now().UTC()
	key := endpointKey(peer, endpoint)
	daemon.endpointMu.Lock()
	defer daemon.endpointMu.Unlock()
	if daemon.endpointState == nil {
		daemon.endpointState = make(map[endpointStateKey]rstate.EndpointState)
	}
	previous, existed := daemon.endpointState[key]
	daemon.endpointState[key] = rstate.EndpointState{
		Peer:       peer,
		Endpoint:   endpoint.Name,
		Health:     health,
		RTT:        rtt,
		Error:      message,
		ObservedAt: now,
		ExpiresAt:  now.Add(endpointHealthTTL()),
	}
	return !existed || previous.Health != health
}

func (daemon *Daemon) endpointMarkedDown(peer core.IXID, endpoint config.EndpointConfig) bool {
	state, ok := daemon.endpointStateFor(peer, endpoint)
	return ok && state.Health == rstate.EndpointDown
}

func (daemon *Daemon) endpointStateFor(peer core.IXID, endpoint config.EndpointConfig) (rstate.EndpointState, bool) {
	now := time.Now().UTC()
	key := endpointKey(peer, endpoint)
	daemon.endpointMu.Lock()
	defer daemon.endpointMu.Unlock()
	state, ok := daemon.endpointState[key]
	if !ok {
		return rstate.EndpointState{}, false
	}
	if state.Expired(now) {
		delete(daemon.endpointState, key)
		return rstate.EndpointState{}, false
	}
	return state, true
}

func (daemon *Daemon) filterHealthyEndpoints(peer core.IXID, endpoints []config.EndpointConfig) []config.EndpointConfig {
	filtered := endpoints[:0]
	for _, endpoint := range endpoints {
		if daemon.endpointMarkedDown(peer, endpoint) {
			continue
		}
		filtered = append(filtered, endpoint)
	}
	return filtered
}

func (daemon *Daemon) endpointStateSnapshot() []rstate.EndpointState {
	now := time.Now().UTC()
	daemon.endpointMu.Lock()
	states := make([]rstate.EndpointState, 0, len(daemon.endpointState))
	for key, state := range daemon.endpointState {
		if state.Expired(now) {
			delete(daemon.endpointState, key)
			continue
		}
		states = append(states, state)
	}
	daemon.endpointMu.Unlock()
	if len(states) == 0 {
		return states
	}
	flowCounts := daemon.endpointFlowCounts()
	byteCounters := daemon.endpointByteCounterSnapshot()
	for i := range states {
		key := endpointFlowKey{Peer: states[i].Peer, Endpoint: states[i].Endpoint}
		states[i].CurrentFlows = flowCounts[key]
		if counters, ok := byteCounters[key]; ok {
			states[i].BytesSent = counters.Sent
			states[i].BytesReceived = counters.Received
		}
	}
	sort.Slice(states, func(i, j int) bool {
		if states[i].Peer != states[j].Peer {
			return states[i].Peer < states[j].Peer
		}
		return states[i].Endpoint < states[j].Endpoint
	})
	return states
}

func (daemon *Daemon) endpointFlowCounts() map[endpointFlowKey]uint64 {
	now := time.Now().UTC()
	daemon.flowMu.Lock()
	defer daemon.flowMu.Unlock()
	daemon.pruneFlowsLocked(now)
	counts := make(map[endpointFlowKey]uint64, len(daemon.flows))
	for _, binding := range daemon.flows {
		counts[endpointFlowKey{Peer: binding.NextHop, Endpoint: binding.Endpoint}]++
	}
	return counts
}

func (daemon *Daemon) endpointFlowCount(peer core.IXID, endpoint core.EndpointID) uint64 {
	now := time.Now().UTC()
	var count uint64
	daemon.flowMu.Lock()
	defer daemon.flowMu.Unlock()
	daemon.pruneFlowsLocked(now)
	for _, binding := range daemon.flows {
		if binding.NextHop == peer && binding.Endpoint == endpoint {
			count++
		}
	}
	return count
}

func (daemon *Daemon) endpointByteCounterSnapshot() map[endpointFlowKey]endpointByteCounter {
	daemon.dataMu.Lock()
	defer daemon.dataMu.Unlock()
	counters := make(map[endpointFlowKey]endpointByteCounter, len(daemon.dataSessions))
	for key, session := range daemon.dataSessions {
		stats := session.Stats()
		counterKey := endpointFlowKey{Peer: key.Peer, Endpoint: key.Endpoint}
		counter := counters[counterKey]
		counter.Sent += stats.BytesSent
		counter.Received += stats.BytesReceived
		counters[counterKey] = counter
	}
	return counters
}

func (daemon *Daemon) endpointByteCounters(peer core.IXID, endpoint core.EndpointID) (uint64, uint64) {
	var sent uint64
	var received uint64
	daemon.dataMu.Lock()
	defer daemon.dataMu.Unlock()
	for key, session := range daemon.dataSessions {
		if key.Peer != peer || key.Endpoint != endpoint {
			continue
		}
		stats := session.Stats()
		sent += stats.BytesSent
		received += stats.BytesReceived
	}
	return sent, received
}

func (daemon *Daemon) healthBasedFailoverEnabled() bool {
	return daemon.desired.TransportPolicy.Failover == "health_based"
}

func endpointKey(peer core.IXID, endpoint config.EndpointConfig) endpointStateKey {
	return endpointStateKey{
		Peer:      peer,
		Endpoint:  endpoint.Name,
		Transport: transport.Protocol(endpoint.Transport),
		Address:   endpoint.Address,
	}
}
