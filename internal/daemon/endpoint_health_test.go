package daemon

import (
	"context"
	"testing"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	rstate "trustix.local/trustix/internal/runtime"
	"trustix.local/trustix/internal/transport"
)

func TestEndpointSupportsPassiveProbeIncludesNativeTunnels(t *testing.T) {
	for _, protocol := range []transport.Protocol{
		transport.ProtocolQUIC,
		transport.ProtocolUDP,
		transport.ProtocolGRE,
		transport.ProtocolIPIP,
		transport.ProtocolVXLAN,
	} {
		if !endpointSupportsPassiveProbe(protocol) {
			t.Fatalf("%s should support passive endpoint probe", protocol)
		}
	}
}

func TestEndpointSupportsPassiveProbeExcludesHandshakeStreams(t *testing.T) {
	for _, protocol := range []transport.Protocol{
		transport.ProtocolTCP,
		transport.ProtocolWebSocket,
		transport.ProtocolHTTPConnect,
	} {
		if endpointSupportsPassiveProbe(protocol) {
			t.Fatalf("%s must not use a bare connection as an endpoint probe", protocol)
		}
	}
}

func TestEndpointProbeIntervalTimeoutAndTTLDefaultsAndEnv(t *testing.T) {
	t.Setenv("TRUSTIX_ENDPOINT_PROBE_INTERVAL", "")
	t.Setenv("TRUSTIX_ENDPOINT_PROBE_TIMEOUT", "")
	t.Setenv("TRUSTIX_ENDPOINT_HEALTH_TTL", "")
	if got := endpointProbeInterval(); got != defaultEndpointProbeInterval {
		t.Fatalf("default endpoint probe interval = %s, want %s", got, defaultEndpointProbeInterval)
	}
	if got := endpointProbeTimeout(); got != defaultEndpointProbeTimeout {
		t.Fatalf("default endpoint probe timeout = %s, want %s", got, defaultEndpointProbeTimeout)
	}
	if got := endpointHealthTTL(); got != defaultEndpointHealthTTL {
		t.Fatalf("default endpoint health ttl = %s, want %s", got, defaultEndpointHealthTTL)
	}

	t.Setenv("TRUSTIX_ENDPOINT_PROBE_INTERVAL", "2.5")
	t.Setenv("TRUSTIX_ENDPOINT_PROBE_TIMEOUT", "750ms")
	t.Setenv("TRUSTIX_ENDPOINT_HEALTH_TTL", "20s")
	if got := endpointProbeInterval(); got != 2500*time.Millisecond {
		t.Fatalf("numeric endpoint probe interval = %s, want 2.5s", got)
	}
	if got := endpointProbeTimeout(); got != 750*time.Millisecond {
		t.Fatalf("duration endpoint probe timeout = %s, want 750ms", got)
	}
	if got := endpointHealthTTL(); got != 20*time.Second {
		t.Fatalf("duration endpoint health ttl = %s, want 20s", got)
	}
}

func TestEndpointHealthTTLDoesNotExpireBeforeThreeProbeIntervals(t *testing.T) {
	t.Setenv("TRUSTIX_ENDPOINT_PROBE_INTERVAL", "30s")
	t.Setenv("TRUSTIX_ENDPOINT_HEALTH_TTL", "10s")
	if got := endpointHealthTTL(); got != 90*time.Second {
		t.Fatalf("short endpoint health ttl = %s, want 90s", got)
	}
}

func TestProbePeerEndpointsUsesActiveSessionWithoutOpeningProbeConnection(t *testing.T) {
	endpoint := config.EndpointConfig{
		Name:      core.EndpointID("tcp-b"),
		Address:   "192.0.2.20:7000",
		Transport: string(transport.ProtocolTCP),
	}
	peer := config.PeerConfig{
		ID:        core.IXID("ix-b"),
		Endpoints: []config.EndpointConfig{endpoint},
	}
	probe := &recordingProbeTransport{
		name:   transport.ProtocolTCP,
		result: transport.ProbeResult{Healthy: false, Error: "probe should not run"},
	}
	registry := transport.NewRegistry()
	if err := registry.Register(probe); err != nil {
		t.Fatalf("register probe transport: %v", err)
	}
	key := dataSessionKey{
		Peer:      peer.ID,
		Endpoint:  endpoint.Name,
		Transport: transport.ProtocolTCP,
		Address:   endpoint.Address,
	}
	daemon := &Daemon{
		desired:       config.Desired{Peers: []config.PeerConfig{peer}},
		transports:    registry,
		dataSessions:  map[dataSessionKey]transport.Session{key: &recordingSession{}},
		endpointState: make(map[endpointStateKey]rstate.EndpointState),
	}

	if !daemon.probePeerEndpoints(context.Background()) {
		t.Fatal("active session did not establish endpoint health")
	}
	if probe.peer.ID != "" {
		t.Fatalf("transport probe ran for active session: peer=%q", probe.peer.ID)
	}
	state, ok := daemon.endpointStateFor(peer.ID, endpoint)
	if !ok || state.Health != rstate.EndpointUp {
		t.Fatalf("endpoint state = %#v, want up", state)
	}
}

func TestProbePeerEndpointsDoesNotOpenInactiveHandshakeStream(t *testing.T) {
	endpoint := config.EndpointConfig{
		Name:      core.EndpointID("tcp-b"),
		Address:   "192.0.2.20:7000",
		Transport: string(transport.ProtocolTCP),
	}
	peer := config.PeerConfig{
		ID:        core.IXID("ix-b"),
		Endpoints: []config.EndpointConfig{endpoint},
	}
	probe := &recordingProbeTransport{
		name:   transport.ProtocolTCP,
		result: transport.ProbeResult{Healthy: true, CheckedAt: time.Now()},
	}
	registry := transport.NewRegistry()
	if err := registry.Register(probe); err != nil {
		t.Fatalf("register probe transport: %v", err)
	}
	daemon := &Daemon{
		desired:       config.Desired{Peers: []config.PeerConfig{peer}},
		transports:    registry,
		dataSessions:  make(map[dataSessionKey]transport.Session),
		endpointState: make(map[endpointStateKey]rstate.EndpointState),
	}

	if daemon.probePeerEndpoints(context.Background()) {
		t.Fatal("inactive handshake stream unexpectedly changed endpoint health")
	}
	if probe.peer.ID != "" {
		t.Fatalf("inactive handshake stream opened a probe connection for peer %q", probe.peer.ID)
	}
	if _, ok := daemon.endpointStateFor(peer.ID, endpoint); ok {
		t.Fatal("inactive handshake stream unexpectedly recorded endpoint state")
	}
}
