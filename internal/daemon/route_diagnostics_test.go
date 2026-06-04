package daemon

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/observability"
	"trustix.local/trustix/internal/routing"
	"trustix.local/trustix/internal/transport"
)

func TestEndpointProbeCallsTransportAndRecordsHealth(t *testing.T) {
	registry := transport.NewRegistry()
	probeTransport := &recordingProbeTransport{
		name: transport.ProtocolUDP,
		result: transport.ProbeResult{
			Healthy:   true,
			RTT:       7 * time.Millisecond,
			CheckedAt: time.Date(2026, 5, 16, 1, 2, 3, 0, time.UTC),
		},
	}
	if err := registry.Register(probeTransport); err != nil {
		t.Fatalf("register probe transport: %v", err)
	}
	daemon := &Daemon{
		transports: registry,
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-a"},
			Peers: []config.PeerConfig{{
				ID:     "ix-b",
				Domain: "lab.local",
				Endpoints: []config.EndpointConfig{{
					Name:      "ep-1",
					Address:   "192.0.2.10:7000",
					Transport: "udp",
					Mode:      config.EndpointModeActive,
					Enabled:   true,
				}},
			}},
		},
	}

	request := httptest.NewRequest(http.MethodGet, "/v1/endpoint/probe?peer=ix-b&endpoint=ep-1&timeout_ms=500", nil)
	recorder := httptest.NewRecorder()
	daemon.managementMux().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var response endpointProbeResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !response.OK || !response.Healthy || response.RTT != 7*time.Millisecond {
		t.Fatalf("probe response = %#v, want healthy OK with RTT", response)
	}
	if response.Peer != "ix-b" || response.Endpoint != "ep-1" || response.Transport != "udp" || response.Address != "192.0.2.10:7000" {
		t.Fatalf("probe endpoint identity = %#v", response)
	}
	if !response.Updated {
		t.Fatalf("probe response updated = false, want health state write")
	}
	if probeTransport.peer.ID != "ix-b" || len(probeTransport.peer.Endpoints) != 1 || probeTransport.peer.Endpoints[0].Name != "ep-1" {
		t.Fatalf("recorded probe peer = %#v", probeTransport.peer)
	}
	if state, ok := daemon.endpointStateFor("ix-b", config.EndpointConfig{Name: "ep-1", Address: "192.0.2.10:7000", Transport: "udp"}); !ok || state.RTT != 7*time.Millisecond {
		t.Fatalf("endpoint state = %#v ok=%t, want RTT", state, ok)
	}
}

func TestEndpointProbeReportsReverseOnlyEndpoint(t *testing.T) {
	daemon := &Daemon{
		transports: transport.NewRegistry(),
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-a"},
			Peers: []config.PeerConfig{{
				ID:     "ix-b",
				Domain: "lab.local",
				Endpoints: []config.EndpointConfig{{
					Name:      "ep-1",
					Transport: "udp",
					Mode:      config.EndpointModePassive,
					Enabled:   true,
				}},
			}},
		},
	}

	request := httptest.NewRequest(http.MethodGet, "/v1/endpoint/probe?peer=ix-b&endpoint=ep-1", nil)
	recorder := httptest.NewRecorder()
	daemon.managementMux().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var response endpointProbeResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.OK || response.Error == "" {
		t.Fatalf("probe response = %#v, want reverse-only explanation", response)
	}
	if response.Updated {
		t.Fatalf("probe response updated = true, want no health write")
	}
}

func TestRouteProbeReturnsDecisionAndCandidateEndpoints(t *testing.T) {
	table := routing.NewTable()
	if err := table.Replace([]routing.Route{{
		Prefix:   "10.0.2.0/24",
		Owner:    "ix-c",
		NextHop:  "ix-b",
		Endpoint: "ep-1",
		Metric:   10,
		Policy:   "default",
		Kind:     routing.RouteUnicast,
	}}); err != nil {
		t.Fatalf("replace routes: %v", err)
	}
	daemon := &Daemon{
		routes:    table,
		dataplane: dataplane.NewNoopManager(),
		desired: config.Desired{
			IX:       config.IXConfig{ID: "ix-a"},
			Policies: []config.PolicyConfig{{Name: "default", FlowStickiness: true}},
			Peers: []config.PeerConfig{{
				ID:     "ix-b",
				Domain: "lab.local",
				Endpoints: []config.EndpointConfig{{
					Name:      "ep-1",
					Address:   "192.0.2.10:7000",
					Transport: "udp",
					Enabled:   true,
				}},
			}},
		},
		flows: make(map[routing.FlowKey]routing.FlowBinding),
	}

	request := httptest.NewRequest(http.MethodGet, "/v1/route/probe?dst=10.0.2.44&src=10.0.1.9&proto=6&sport=12345&dport=443", nil)
	recorder := httptest.NewRecorder()
	daemon.managementMux().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var response routeProbeResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !response.OK || !response.Matched {
		t.Fatalf("probe response = %#v, want matched OK", response)
	}
	if response.Prefix != "10.0.2.0/24" || response.Route == nil || response.Route.NextHop != "ix-b" {
		t.Fatalf("probe route = prefix:%q route:%#v", response.Prefix, response.Route)
	}
	if response.Protocol != ipProtocolTCP || response.SourcePort != 12345 || response.DestinationPort != 443 {
		t.Fatalf("probe tuple = proto:%d %d->%d", response.Protocol, response.SourcePort, response.DestinationPort)
	}
	if !response.NextHopConfigured || len(response.CandidateEndpoints) != 1 || response.CandidateEndpoints[0].Name != "ep-1" {
		t.Fatalf("probe candidates = configured:%t endpoints:%#v", response.NextHopConfigured, response.CandidateEndpoints)
	}
	if response.Policy == nil || response.Policy.Name != "default" || !response.Policy.FlowStickiness {
		t.Fatalf("probe policy = %#v", response.Policy)
	}
}

func TestRouteTraceShowsLocalHopAndNextHop(t *testing.T) {
	tableB := routing.NewTable()
	if err := tableB.Replace([]routing.Route{{
		Prefix:  "10.0.2.0/24",
		Owner:   "ix-b",
		NextHop: "ix-b",
		Metric:  10,
		Kind:    routing.RouteLocal,
	}}); err != nil {
		t.Fatalf("replace ix-b routes: %v", err)
	}
	daemonB := &Daemon{
		routes:    tableB,
		dataplane: dataplane.NewNoopManager(),
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-b"},
		},
	}
	serverB := httptest.NewServer(daemonB.peerHandler())
	t.Cleanup(serverB.Close)

	table := routing.NewTable()
	if err := table.Replace([]routing.Route{{
		Prefix:   "10.0.2.0/24",
		Owner:    "ix-b",
		NextHop:  "ix-b",
		Endpoint: "ep-1",
		Metric:   10,
		Kind:     routing.RouteUnicast,
	}}); err != nil {
		t.Fatalf("replace routes: %v", err)
	}
	daemon := &Daemon{
		routes:    table,
		dataplane: dataplane.NewNoopManager(),
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-a"},
			Peers: []config.PeerConfig{{
				ID:         "ix-b",
				Domain:     "lab.local",
				ControlAPI: serverB.URL,
				Endpoints: []config.EndpointConfig{{
					Name:      "ep-1",
					Address:   "192.0.2.10:7000",
					Transport: "udp",
					Enabled:   true,
				}},
			}},
		},
	}

	request := httptest.NewRequest(http.MethodGet, "/v1/route/trace?dst=10.0.2.44&max_hops=4", nil)
	recorder := httptest.NewRecorder()
	daemon.managementMux().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var response routeTraceResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !response.OK || !response.Complete {
		t.Fatalf("trace response = %#v, want complete OK", response)
	}
	if len(response.Hops) != 2 {
		t.Fatalf("trace hops = %#v, want local and remote terminal hops", response.Hops)
	}
	if response.Hops[0].IXID != "ix-a" || response.Hops[0].NextHop != "ix-b" || response.Hops[0].Prefix != "10.0.2.0/24" {
		t.Fatalf("local hop = %#v", response.Hops[0])
	}
	if response.Hops[1].IXID != "ix-b" || !response.Hops[1].Terminal || response.Hops[1].Kind != string(routing.RouteLocal) || response.Hops[1].Reason != "local route" {
		t.Fatalf("remote terminal hop = %#v", response.Hops[1])
	}
	if response.Hops[0].Index != 1 || response.Hops[1].Index != 2 {
		t.Fatalf("hop indices = %#v", response.Hops)
	}
}

func TestRouteTraceDetectsRecursiveLoop(t *testing.T) {
	tableB := routing.NewTable()
	if err := tableB.Replace([]routing.Route{{
		Prefix:  "10.0.2.0/24",
		Owner:   "ix-a",
		NextHop: "ix-a",
		Metric:  10,
		Kind:    routing.RouteUnicast,
	}}); err != nil {
		t.Fatalf("replace ix-b routes: %v", err)
	}
	daemonB := &Daemon{
		routes:    tableB,
		dataplane: dataplane.NewNoopManager(),
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-b"},
		},
	}
	serverB := httptest.NewServer(daemonB.peerHandler())
	t.Cleanup(serverB.Close)

	tableA := routing.NewTable()
	if err := tableA.Replace([]routing.Route{{
		Prefix:  "10.0.2.0/24",
		Owner:   "ix-b",
		NextHop: "ix-b",
		Metric:  10,
		Kind:    routing.RouteUnicast,
	}}); err != nil {
		t.Fatalf("replace ix-a routes: %v", err)
	}
	daemonA := &Daemon{
		routes:    tableA,
		dataplane: dataplane.NewNoopManager(),
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-a"},
			Peers: []config.PeerConfig{{
				ID:         "ix-b",
				Domain:     "lab.local",
				ControlAPI: serverB.URL,
				Endpoints: []config.EndpointConfig{{
					Name:      "ep-1",
					Address:   "192.0.2.10:7000",
					Transport: "udp",
					Enabled:   true,
				}},
			}},
		},
	}

	request := httptest.NewRequest(http.MethodGet, "/v1/route/trace?dst=10.0.2.44&max_hops=4", nil)
	recorder := httptest.NewRecorder()
	daemonA.managementMux().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var response routeTraceResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.OK || !response.Complete || response.Reason == "" {
		t.Fatalf("trace response = %#v, want complete loop failure", response)
	}
	if len(response.Hops) != 3 {
		t.Fatalf("trace hops = %#v, want ix-a, ix-b, loop placeholder", response.Hops)
	}
	if response.Hops[2].IXID != "ix-a" || response.Hops[2].Reason != "loop detected" || !response.Hops[2].Terminal {
		t.Fatalf("loop hop = %#v", response.Hops[2])
	}
}

func TestDecrementIPv4TTLReturnsSentinel(t *testing.T) {
	packet := tcpPayloadIPv4Packet([]byte("ttl"))
	packet[8] = 1
	binary.BigEndian.PutUint16(packet[10:12], 0)
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:20]))

	if _, err := decrementIPv4TTL(packet); !errors.Is(err, errIPv4TTLExpired) {
		t.Fatalf("decrement TTL error = %v, want errIPv4TTLExpired", err)
	}
}

func TestDecrementIPv4TTLUpdatesHeaderChecksumIncrementally(t *testing.T) {
	packet := tcpPayloadIPv4Packet([]byte("ttl"))
	packet[8] = 64
	binary.BigEndian.PutUint16(packet[10:12], 0)
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:20]))

	forwarded, err := decrementIPv4TTL(packet)
	if err != nil {
		t.Fatalf("decrement TTL: %v", err)
	}
	if forwarded[8] != 63 {
		t.Fatalf("forwarded TTL = %d, want 63", forwarded[8])
	}
	if got := ipv4Checksum(forwarded[:20]); got != 0 {
		t.Fatalf("forwarded IPv4 checksum = %#x, want valid", got)
	}
	recomputed := append([]byte(nil), packet...)
	recomputed[8] = 63
	binary.BigEndian.PutUint16(recomputed[10:12], 0)
	binary.BigEndian.PutUint16(recomputed[10:12], ipv4Checksum(recomputed[:20]))
	if got, want := binary.BigEndian.Uint16(forwarded[10:12]), binary.BigEndian.Uint16(recomputed[10:12]); got != want {
		t.Fatalf("incremental checksum = %#x, want recomputed %#x", got, want)
	}
	if packet[8] != 64 {
		t.Fatalf("source packet TTL mutated to %d", packet[8])
	}
}

func TestForwardTransitPacketTTLExpiredSendsICMPTimeExceeded(t *testing.T) {
	table := routing.NewTable()
	if err := table.Replace([]routing.Route{{
		Prefix:   "10.0.2.0/24",
		Owner:    "ix-c",
		NextHop:  "ix-c",
		Endpoint: "ep-c",
		Metric:   100,
		Kind:     routing.RouteUnicast,
	}}); err != nil {
		t.Fatalf("replace routes: %v", err)
	}
	injector := &recordingLANInjector{}
	daemon := &Daemon{
		routes:     table,
		dataplane:  injector,
		transports: transport.NewRegistry(),
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-b"},
			LAN: config.LANConfig{
				Advertise: []core.Prefix{"10.0.0.0/24"},
			},
			Peers: []config.PeerConfig{{
				ID:     "ix-c",
				Domain: "lab.local",
				Endpoints: []config.EndpointConfig{{
					Name:      "ep-c",
					Address:   "192.0.2.3:7003",
					Transport: "udp",
					Enabled:   true,
				}},
			}},
		},
	}
	packet := normalizeCapturedIPv4Checksums(tcpPayloadIPv4Packet([]byte("expired")))
	copy(packet[16:20], []byte{10, 0, 2, 2})
	packet[8] = 1
	binary.BigEndian.PutUint16(packet[10:12], 0)
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:20]))

	err := daemon.forwardTransitPacket(context.Background(), packet, netip.MustParseAddr("10.0.2.2"))
	if !errors.Is(err, errIPv4TTLExpired) {
		t.Fatalf("forward transit error = %v, want errIPv4TTLExpired", err)
	}
	if len(injector.packets) != 1 {
		t.Fatalf("injected replies = %d, want 1", len(injector.packets))
	}
	reply := injector.packets[0]
	if reply[9] != ipProtocolICMP || reply[20] != icmpTypeTimeExceeded || reply[21] != icmpCodeTTLExceeded {
		t.Fatalf("ICMP reply header = proto:%d type:%d code:%d", reply[9], reply[20], reply[21])
	}
	if got := netip.AddrFrom4([4]byte{reply[12], reply[13], reply[14], reply[15]}); got != netip.MustParseAddr("10.0.2.2") {
		t.Fatalf("reply source = %s, want original destination", got)
	}
	if got := netip.AddrFrom4([4]byte{reply[16], reply[17], reply[18], reply[19]}); got != netip.MustParseAddr("10.0.0.2") {
		t.Fatalf("reply destination = %s, want original source", got)
	}
	if injector.destinations[0] != netip.MustParseAddr("10.0.0.2") {
		t.Fatalf("inject destination = %s, want original source", injector.destinations[0])
	}
	if got := ipv4Checksum(reply[:20]); got != 0 {
		t.Fatalf("ICMP reply IPv4 checksum = %#04x, want valid", got)
	}
	if got := ipv4Checksum(reply[20:]); got != 0 {
		t.Fatalf("ICMP checksum = %#04x, want valid", got)
	}
	if len(reply) < 56 || !equalBytes(reply[28:56], packet[:28]) {
		t.Fatalf("quoted packet mismatch")
	}
	counters := daemon.dataStats.snapshot()
	if counters.TTLICMPGenerated != 1 || counters.RejectICMPGenerated != 0 || counters.PacketsInjected != 1 || counters.RejectReplyErrors != 0 {
		t.Fatalf("TTL ICMP counters = %#v", counters)
	}
	drops := daemon.dataStats.dropReasonSnapshot()
	if drops[observability.DropTTLExpired] != 1 {
		t.Fatalf("drop reasons = %#v, want TTL_EXPIRED", drops)
	}
}

func TestForwardCaptureEventTTLExpiredSendsICMPTimeExceeded(t *testing.T) {
	table := routing.NewTable()
	if err := table.Replace([]routing.Route{{
		Prefix:   "10.0.2.0/24",
		Owner:    "ix-c",
		NextHop:  "ix-c",
		Endpoint: "ep-c",
		Metric:   100,
		Kind:     routing.RouteUnicast,
	}}); err != nil {
		t.Fatalf("replace routes: %v", err)
	}
	injector := &recordingLANInjector{}
	daemon := &Daemon{
		routes:    table,
		dataplane: injector,
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-a"},
			LAN: config.LANConfig{
				Advertise: []core.Prefix{"10.0.0.0/24"},
			},
			Peers: []config.PeerConfig{{
				ID:     "ix-c",
				Domain: "lab.local",
				Endpoints: []config.EndpointConfig{{
					Name:      "ep-c",
					Address:   "192.0.2.3:7003",
					Transport: "udp",
					Enabled:   true,
				}},
			}},
		},
	}
	packet := normalizeCapturedIPv4Checksums(tcpPayloadIPv4Packet([]byte("first-hop-expired")))
	copy(packet[16:20], []byte{10, 0, 2, 2})
	packet[8] = 1
	binary.BigEndian.PutUint16(packet[10:12], 0)
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:20]))

	err := daemon.forwardCaptureEvent(context.Background(), dataplane.CaptureEvent{
		Hook:          "lan_ingress_route_hit",
		PacketLength:  uint32(len(packet)),
		SampleLength:  uint32(len(packet)),
		DestinationIP: "10.0.2.2",
		Payload:       packet,
	})
	if !errors.Is(err, errIPv4TTLExpired) {
		t.Fatalf("forward capture error = %v, want errIPv4TTLExpired", err)
	}
	if len(injector.packets) != 1 {
		t.Fatalf("injected replies = %d, want 1", len(injector.packets))
	}
	reply := injector.packets[0]
	if reply[9] != ipProtocolICMP || reply[20] != icmpTypeTimeExceeded || reply[21] != icmpCodeTTLExceeded {
		t.Fatalf("ICMP reply header = proto:%d type:%d code:%d", reply[9], reply[20], reply[21])
	}
	if got := netip.AddrFrom4([4]byte{reply[12], reply[13], reply[14], reply[15]}); got != netip.MustParseAddr("10.0.2.2") {
		t.Fatalf("reply source = %s, want original destination", got)
	}
	if got := netip.AddrFrom4([4]byte{reply[16], reply[17], reply[18], reply[19]}); got != netip.MustParseAddr("10.0.0.2") {
		t.Fatalf("reply destination = %s, want original source", got)
	}
	counters := daemon.dataStats.snapshot()
	if counters.TTLICMPGenerated != 1 || counters.PacketsInjected != 1 || counters.PacketsSent != 0 {
		t.Fatalf("TTL capture counters = %#v", counters)
	}
}

func TestForwardTransitPacketTTLExpiredRoutesRemoteReply(t *testing.T) {
	table := routing.NewTable()
	if err := table.Replace([]routing.Route{
		{
			Prefix:   "10.0.2.0/24",
			Owner:    "ix-c",
			NextHop:  "ix-c",
			Endpoint: "ep-c",
			Metric:   100,
			Kind:     routing.RouteUnicast,
		},
		{
			Prefix:   "10.0.9.0/24",
			Owner:    "ix-a",
			NextHop:  "ix-a",
			Endpoint: "ep-a",
			Metric:   100,
			Kind:     routing.RouteUnicast,
		},
	}); err != nil {
		t.Fatalf("replace routes: %v", err)
	}
	session := &recordingSession{}
	registry := transport.NewRegistry()
	if err := registry.Register(fakeTransport{name: "udp"}); err != nil {
		t.Fatalf("register fake transport: %v", err)
	}
	daemon := &Daemon{
		routes:     table,
		dataplane:  &recordingLANInjector{},
		transports: registry,
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-b"},
			LAN: config.LANConfig{
				Advertise: []core.Prefix{"10.0.1.0/24"},
			},
			Peers: []config.PeerConfig{
				{
					ID:     "ix-c",
					Domain: "lab.local",
					Endpoints: []config.EndpointConfig{{
						Name:      "ep-c",
						Address:   "192.0.2.3:7003",
						Transport: "udp",
						Enabled:   true,
					}},
				},
				{
					ID:     "ix-a",
					Domain: "lab.local",
					Endpoints: []config.EndpointConfig{{
						Name:      "ep-a",
						Address:   "192.0.2.1:7001",
						Transport: "udp",
						Enabled:   true,
					}},
				},
			},
		},
		dataSessions: map[dataSessionKey]transport.Session{
			{Peer: "ix-a", Endpoint: "ep-a", Transport: "udp", Address: "192.0.2.1:7001", Encryption: "secure"}: session,
		},
		flows: make(map[routing.FlowKey]routing.FlowBinding),
	}
	packet := normalizeCapturedIPv4Checksums(tcpPayloadIPv4Packet([]byte("remote-expired")))
	copy(packet[12:16], []byte{10, 0, 9, 9})
	copy(packet[16:20], []byte{10, 0, 2, 2})
	packet[8] = 1
	binary.BigEndian.PutUint16(packet[10:12], 0)
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:20]))

	err := daemon.forwardTransitPacket(context.Background(), packet, netip.MustParseAddr("10.0.2.2"))
	if !errors.Is(err, errIPv4TTLExpired) {
		t.Fatalf("forward transit error = %v, want errIPv4TTLExpired", err)
	}
	if len(session.sent) != 1 {
		t.Fatalf("routed TTL replies = %d, want 1", len(session.sent))
	}
	reply := session.sent[0]
	if reply[9] != ipProtocolICMP || reply[20] != icmpTypeTimeExceeded || reply[21] != icmpCodeTTLExceeded {
		t.Fatalf("ICMP reply header = proto:%d type:%d code:%d", reply[9], reply[20], reply[21])
	}
	if got := netip.AddrFrom4([4]byte{reply[16], reply[17], reply[18], reply[19]}); got != netip.MustParseAddr("10.0.9.9") {
		t.Fatalf("reply destination = %s, want remote source", got)
	}
	counters := daemon.dataStats.snapshot()
	if counters.TTLICMPGenerated != 1 || counters.PacketsSent != 1 || counters.PacketsInjected != 0 {
		t.Fatalf("remote TTL counters = %#v", counters)
	}
}

type recordingProbeTransport struct {
	name   transport.Protocol
	result transport.ProbeResult
	peer   transport.Peer
}

func (transportImpl *recordingProbeTransport) Name() transport.Protocol {
	return transportImpl.name
}

func (transportImpl *recordingProbeTransport) Probe(ctx context.Context, peer transport.Peer) transport.ProbeResult {
	transportImpl.peer = peer
	return transportImpl.result
}

func (transportImpl *recordingProbeTransport) Dial(ctx context.Context, peer transport.Peer, tlsConf *tls.Config) (transport.Session, error) {
	return nil, fmt.Errorf("unexpected recording probe transport dial")
}

func (transportImpl *recordingProbeTransport) Listen(ctx context.Context, ep transport.Endpoint, tlsConf *tls.Config) (transport.Listener, error) {
	return nil, fmt.Errorf("unexpected recording probe transport listen")
}

func equalBytes(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
