package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/routing"
	rstate "trustix.local/trustix/internal/runtime"
	"trustix.local/trustix/internal/transport"
)

func TestLinksEndpointReportsPeerSessions(t *testing.T) {
	session := &recordingSession{stats: transport.TransportStats{
		BytesSent:       1200,
		BytesReceived:   900,
		PacketsSent:     12,
		PacketsReceived: 9,
		Encrypted:       true,
		Encryption:      "secure",
		CryptoPlacement: "kernel",
	}}
	key := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "ep-b",
		Transport:  transport.ProtocolUDP,
		Address:    "192.0.2.2:7000",
		Encryption: "secure",
	}
	now := time.Now().UTC()
	daemon := &Daemon{
		dataplane: &kernelTransportDataplane{
			NoopManager: dataplane.NewNoopManager(),
			status: dataplane.KernelTransportStatus{
				Available: true,
				Provider:  "test",
				Protocols: []dataplane.KernelTransportProtocol{{
					Protocol:  string(transport.ProtocolTIXTCP),
					Available: true,
				}},
			},
		},
		routes:           routing.NewTable(),
		transports:       transport.NewRegistry(),
		dataSessions:     map[dataSessionKey]transport.Session{key: session},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{},
		flows:            make(map[routing.FlowKey]routing.FlowBinding),
		forwardCache:     make(map[routing.FlowKey]*dataForwardCacheEntry),
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-a"},
			TransportPolicy: config.TransportPolicyConfig{
				Encryption: "secure",
			},
			Peers: []config.PeerConfig{{
				ID:         "ix-b",
				Domain:     "lab.local",
				ControlAPI: "https://ix-b.example.test",
				Endpoints: []config.EndpointConfig{{
					Name:      "ep-b",
					Mode:      config.EndpointModeActive,
					Address:   "192.0.2.2:7000",
					Transport: "udp",
					Enabled:   true,
				}},
			}},
			Routes: []config.RouteConfig{{
				Prefix:  "10.0.2.0/24",
				NextHop: "ix-b",
				Metric:  100,
				Kind:    routing.RouteUnicast,
			}},
		},
	}
	runtime := &dataSessionRuntime{key: key, session: session}
	runtime.lastRX.Store(now.Add(-time.Second).UnixNano())
	runtime.lastTX.Store(now.UnixNano())
	runtime.lastUp.Store(now.Add(-2 * time.Second).UnixNano())
	runtime.lastPong.Store(now.Add(-time.Second).UnixNano())
	daemon.dataSessionState[key] = runtime
	if err := daemon.routes.Replace(routesFromConfig(daemon.desired)); err != nil {
		t.Fatalf("replace routes: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/v1/links?peer=ix-b", nil)
	recorder := httptest.NewRecorder()
	daemon.managementMux().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var response linkDiagnosticsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.LocalIX != "ix-a" || len(response.Links) != 1 {
		t.Fatalf("response = %#v", response)
	}
	link := response.Links[0]
	if link.Peer != "ix-b" || link.State != "up" || link.ActiveSessions != 1 {
		t.Fatalf("link = %#v", link)
	}
	if link.BytesSent != 1200 || link.BytesReceived != 900 || link.PacketsSent != 12 || link.PacketsReceived != 9 {
		t.Fatalf("link counters = sent:%d/%d recv:%d/%d", link.PacketsSent, link.BytesSent, link.PacketsReceived, link.BytesReceived)
	}
	if len(link.Endpoints) != 1 || link.Endpoints[0].ActiveSessions != 1 || !link.Endpoints[0].Usable {
		t.Fatalf("endpoints = %#v", link.Endpoints)
	}
	if len(link.Routes) != 1 || link.Routes[0].NextHop != "ix-b" {
		t.Fatalf("routes = %#v, want next_hop ix-b", link.Routes)
	}
	if len(link.Sessions) != 1 || link.Sessions[0].Stats.CryptoPlacement != "kernel" || link.Sessions[0].LastTX.IsZero() {
		t.Fatalf("sessions = %#v", link.Sessions)
	}
}

func TestLinksEndpointIgnoresDisabledEndpointLastError(t *testing.T) {
	session := &recordingSession{}
	key := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "ep-b",
		Transport:  transport.ProtocolQUIC,
		Address:    "192.0.2.2:7443",
		Encryption: "secure",
	}
	now := time.Now().UTC()
	daemon := &Daemon{
		dataplane: &kernelTransportDataplane{
			NoopManager: dataplane.NewNoopManager(),
			status: dataplane.KernelTransportStatus{
				Available: true,
				Provider:  "test",
				Protocols: []dataplane.KernelTransportProtocol{{
					Protocol:  string(transport.ProtocolTIXTCP),
					Available: true,
				}},
			},
		},
		routes:           routing.NewTable(),
		transports:       transport.NewRegistry(),
		dataSessions:     map[dataSessionKey]transport.Session{key: session},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{},
		endpointState:    make(map[endpointStateKey]rstate.EndpointState),
		flows:            make(map[routing.FlowKey]routing.FlowBinding),
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-a"},
			TransportPolicy: config.TransportPolicyConfig{
				Encryption: "secure",
			},
			Peers: []config.PeerConfig{{
				ID:     "ix-b",
				Domain: "lab.local",
				Endpoints: []config.EndpointConfig{
					{Name: "ep-b", Mode: config.EndpointModeActive, Address: "192.0.2.2:7443", Transport: "quic", Enabled: true},
					{Name: "tix-tcp-b", Mode: config.EndpointModeActive, Address: "192.0.2.2:7143", Transport: "tix_tcp", Enabled: false},
				},
			}},
		},
	}
	runtime := &dataSessionRuntime{key: key, session: session}
	runtime.lastUp.Store(now.UnixNano())
	daemon.dataSessionState[key] = runtime
	daemon.recordEndpointDown("ix-b", daemon.desired.Peers[0].Endpoints[1], fmt.Errorf("tix_tcp TC/XDP reinject is unavailable"))

	request := httptest.NewRequest(http.MethodGet, "/v1/links?peer=ix-b", nil)
	recorder := httptest.NewRecorder()
	daemon.managementMux().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var response linkDiagnosticsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	link := response.Links[0]
	if link.State != "up" || len(link.Warnings) != 0 {
		t.Fatalf("link state=%q warnings=%v, want up without disabled endpoint warning", link.State, link.Warnings)
	}
}

func TestLinksEndpointIgnoresUnselectedKernelIncompatibleEndpoint(t *testing.T) {
	session := &recordingSession{}
	key := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "tix-tcp-b",
		Transport:  transport.ProtocolTIXTCP,
		Address:    "192.0.2.2:7143",
		Encryption: "plaintext",
	}
	now := time.Now().UTC()
	daemon := &Daemon{
		dataplane: &kernelTransportDataplane{
			NoopManager: dataplane.NewNoopManager(),
			status: dataplane.KernelTransportStatus{
				Available: true,
				Provider:  "test",
				Protocols: []dataplane.KernelTransportProtocol{{
					Protocol:  string(transport.ProtocolTIXTCP),
					Available: true,
				}},
			},
		},
		routes:           routing.NewTable(),
		transports:       transport.NewRegistry(),
		dataSessions:     map[dataSessionKey]transport.Session{key: session},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{},
		flows:            make(map[routing.FlowKey]routing.FlowBinding),
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-a"},
			TransportPolicy: config.TransportPolicyConfig{
				Encryption: "plaintext",
				KernelTransport: config.KernelTransportPolicyConfig{
					Mode: string(dataplane.KernelTransportModeRequireKernel),
				},
			},
			Peers: []config.PeerConfig{{
				ID:     "ix-b",
				Domain: "lab.local",
				Endpoints: []config.EndpointConfig{
					{Name: "tix-tcp-b", Mode: config.EndpointModeActive, Address: "192.0.2.2:7143", Transport: "tix_tcp", Enabled: true},
					{Name: "tcp-b", Mode: config.EndpointModeActive, Address: "192.0.2.2:7043", Transport: "tcp", Enabled: true},
				},
			}},
			Routes: []config.RouteConfig{{
				Prefix:   "10.0.2.0/24",
				NextHop:  "ix-b",
				Endpoint: "tix-tcp-b",
				Metric:   100,
			}},
		},
	}
	runtime := &dataSessionRuntime{key: key, session: session}
	runtime.lastUp.Store(now.UnixNano())
	daemon.dataSessionState[key] = runtime
	if err := daemon.routes.Replace(routesFromConfig(daemon.desired)); err != nil {
		t.Fatalf("replace routes: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/v1/links?peer=ix-b", nil)
	recorder := httptest.NewRecorder()
	daemon.managementMux().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var response linkDiagnosticsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	link := response.Links[0]
	if link.State != "up" || len(link.Warnings) != 0 {
		t.Fatalf("link state=%q warnings=%v, want up without unselected endpoint warning", link.State, link.Warnings)
	}
}

func TestLinksEndpointReportsKernelTelemetryTraffic(t *testing.T) {
	session := &recordingSession{stats: transport.TransportStats{
		CryptoPlacement: "kernel",
	}}
	key := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "ep-b",
		Transport:  transport.ProtocolUDP,
		Address:    "192.0.2.2:7000",
		Encryption: "none",
	}
	now := time.Now().UTC()
	manager := &linkTelemetryManager{
		NoopManager: dataplane.NewNoopManager(),
		kernelUDP: dataplane.KernelUDPStatus{
			Available: true,
			Provider:  "test",
			FastPath:  true,
			Telemetry: []dataplane.TransportPathTelemetry{{
				Protocol:      "kernel_udp",
				FlowID:        7,
				Peer:          "ix-b",
				Endpoint:      "ep-b",
				RemoteAddress: "192.0.2.2:7000",
				TXFrames:      21,
				TXBytes:       42_000,
				RXFrames:      11,
				RXBytes:       31_000,
				LastSeen:      now,
			}},
		},
	}
	daemon := &Daemon{
		dataplane:        manager,
		routes:           routing.NewTable(),
		transports:       transport.NewRegistry(),
		dataSessions:     map[dataSessionKey]transport.Session{key: session},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{},
		flows:            make(map[routing.FlowKey]routing.FlowBinding),
		forwardCache:     make(map[routing.FlowKey]*dataForwardCacheEntry),
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-a"},
			TransportPolicy: config.TransportPolicyConfig{
				Encryption: "none",
			},
			Peers: []config.PeerConfig{{
				ID:     "ix-b",
				Domain: "lab.local",
				Endpoints: []config.EndpointConfig{{
					Name:      "ep-b",
					Mode:      config.EndpointModeActive,
					Address:   "192.0.2.2:7000",
					Transport: "udp",
					Enabled:   true,
				}},
			}},
		},
	}
	runtime := &dataSessionRuntime{key: key, session: session}
	runtime.lastUp.Store(now.Add(-2 * time.Second).UnixNano())
	daemon.dataSessionState[key] = runtime

	request := httptest.NewRequest(http.MethodGet, "/v1/links?peer=ix-b", nil)
	recorder := httptest.NewRecorder()
	daemon.managementMux().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var response linkDiagnosticsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Links) != 1 {
		t.Fatalf("response links = %#v", response.Links)
	}
	link := response.Links[0]
	if link.BytesSent != 42_000 || link.BytesReceived != 31_000 || link.PacketsSent != 21 || link.PacketsReceived != 11 {
		t.Fatalf("link counters = sent:%d/%d recv:%d/%d", link.PacketsSent, link.BytesSent, link.PacketsReceived, link.BytesReceived)
	}
	if link.LastTX.IsZero() || link.LastRX.IsZero() {
		t.Fatalf("link last tx/rx not populated: %#v", link)
	}
	if len(link.Endpoints) != 1 {
		t.Fatalf("endpoints = %#v", link.Endpoints)
	}
	endpoint := link.Endpoints[0]
	if endpoint.BytesSent != 42_000 || endpoint.BytesReceived != 31_000 || endpoint.PacketsSent != 21 || endpoint.PacketsReceived != 11 {
		t.Fatalf("endpoint counters = %#v", endpoint)
	}
}

func TestReconcileForwardCacheKeepsUnaffectedFlows(t *testing.T) {
	oldDecision := routing.Decision{
		Prefix: netip.MustParsePrefix("10.0.2.0/24"),
		Route: routing.Route{
			Prefix:  "10.0.2.0/24",
			NextHop: "ix-b",
			Metric:  100,
			Kind:    routing.RouteUnicast,
		},
	}
	flowKey := routing.FlowKey{
		SourceIP:        netip.MustParseAddr("10.0.1.10"),
		DestinationIP:   netip.MustParseAddr("10.0.2.20"),
		SourcePort:      12345,
		DestinationPort: 443,
		Protocol:        ipProtocolTCP,
	}
	daemon := &Daemon{
		forwardCache: map[routing.FlowKey]*dataForwardCacheEntry{
			flowKey: {
				Decision:  oldDecision,
				Session:   &recordingSession{},
				Runtime:   &dataSessionRuntime{},
				ExpiresAt: time.Now().UTC().Add(time.Minute),
			},
		},
		flows: map[routing.FlowKey]routing.FlowBinding{
			flowKey: {Key: flowKey, NextHop: "ix-b", Endpoint: "ep-b"},
		},
	}
	nextRoutes := routing.NewTable()
	if err := nextRoutes.Replace([]routing.Route{
		oldDecision.Route,
		{Prefix: "10.0.3.0/24", NextHop: "ix-c", Metric: 100, Kind: routing.RouteUnicast},
	}); err != nil {
		t.Fatalf("replace routes: %v", err)
	}

	daemon.reconcileForwardCacheForRoutes(nextRoutes)

	if _, ok := daemon.forwardCache[flowKey]; !ok {
		t.Fatal("forward cache for unaffected flow was removed")
	}
	if _, ok := daemon.flows[flowKey]; !ok {
		t.Fatal("flow binding for unaffected flow was removed")
	}
}

type linkTelemetryManager struct {
	*dataplane.NoopManager
	kernelUDP dataplane.KernelUDPStatus
}

func (manager *linkTelemetryManager) KernelUDPStatus(ctx context.Context) (dataplane.KernelUDPStatus, error) {
	if err := ctx.Err(); err != nil {
		return dataplane.KernelUDPStatus{}, err
	}
	return manager.kernelUDP, nil
}

func TestReconcileForwardCacheDropsChangedRoute(t *testing.T) {
	oldDecision := routing.Decision{
		Prefix: netip.MustParsePrefix("10.0.2.0/24"),
		Route: routing.Route{
			Prefix:  "10.0.2.0/24",
			NextHop: "ix-b",
			Metric:  100,
			Kind:    routing.RouteUnicast,
		},
	}
	flowKey := routing.FlowKey{
		SourceIP:        netip.MustParseAddr("10.0.1.10"),
		DestinationIP:   netip.MustParseAddr("10.0.2.20"),
		SourcePort:      12345,
		DestinationPort: 443,
		Protocol:        ipProtocolTCP,
	}
	daemon := &Daemon{
		forwardCache: map[routing.FlowKey]*dataForwardCacheEntry{
			flowKey: {
				Decision:  oldDecision,
				Session:   &recordingSession{},
				Runtime:   &dataSessionRuntime{},
				ExpiresAt: time.Now().UTC().Add(time.Minute),
			},
		},
		flows: map[routing.FlowKey]routing.FlowBinding{
			flowKey: {Key: flowKey, NextHop: "ix-b", Endpoint: "ep-b"},
		},
	}
	nextRoutes := routing.NewTable()
	if err := nextRoutes.Replace([]routing.Route{{
		Prefix:  "10.0.2.0/24",
		NextHop: "ix-c",
		Metric:  100,
		Kind:    routing.RouteUnicast,
	}}); err != nil {
		t.Fatalf("replace routes: %v", err)
	}

	daemon.reconcileForwardCacheForRoutes(nextRoutes)

	if _, ok := daemon.forwardCache[flowKey]; ok {
		t.Fatal("forward cache for changed route was kept")
	}
	if _, ok := daemon.flows[flowKey]; ok {
		t.Fatal("flow binding for changed route was kept")
	}
}
