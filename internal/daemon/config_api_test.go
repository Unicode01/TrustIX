package daemon

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/configlog"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/routing"
	"trustix.local/trustix/internal/transport"
)

func TestConfigValidateRejectsBadDesired(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemon := newConfigApplyTestDaemon(t, configApplyDesired(pkiSet, "10.0.1.0/24"))
	request := httptest.NewRequest(http.MethodPost, "/v1/config/validate?format=yaml", strings.NewReader("domain:\n  id: \"\"\n"))
	request.Header.Set("Content-Type", "application/x-yaml")
	recorder := httptest.NewRecorder()

	daemon.handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
}

func TestConfigApplyUpdatesRoutesAndConfigHead(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	initial := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, initial)
	next := configApplyDesired(pkiSet, "10.0.2.0/24")

	changed, err := daemon.applyDesiredConfig(context.Background(), next)
	if err != nil {
		t.Fatalf("apply desired config: %v", err)
	}
	if !changed {
		t.Fatal("apply did not report config log change")
	}
	if daemon.head.Seq != 3 {
		t.Fatalf("head seq = %d, want 3", daemon.head.Seq)
	}
	assertRuntimeRoute(t, daemon, "10.0.2.0/24")
	assertNoRuntimeRoute(t, daemon, "10.0.1.0/24")
	daemon.membershipMu.RLock()
	adSeq := daemon.localAd.ConfigHead.Seq
	daemon.membershipMu.RUnlock()
	if adSeq != 3 {
		t.Fatalf("local advertisement seq = %d, want 3", adSeq)
	}
}

func TestConfigRollbackRestoresPreviousDesired(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	initial := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, initial)
	next := configApplyDesired(pkiSet, "10.0.2.0/24")
	if changed, err := daemon.applyDesiredConfig(context.Background(), next); err != nil || !changed {
		t.Fatalf("apply next changed=%t err=%v", changed, err)
	}

	targetSeq, changed, err := daemon.rollbackDesiredConfig(context.Background(), nil)
	if err != nil {
		t.Fatalf("rollback desired config: %v", err)
	}
	if targetSeq != 2 {
		t.Fatalf("rollback target seq = %d, want 2", targetSeq)
	}
	if !changed {
		t.Fatal("rollback did not append a desired config event")
	}
	if daemon.head.Seq != 4 {
		t.Fatalf("head seq = %d, want 4", daemon.head.Seq)
	}
	assertRuntimeRoute(t, daemon, "10.0.1.0/24")
	assertNoRuntimeRoute(t, daemon, "10.0.2.0/24")
}

func TestConfigRollbackExplicitSeqUsesLocalIXDesiredResource(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	initial := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, initial)
	next := configApplyDesired(pkiSet, "10.0.2.0/24")
	if changed, err := daemon.applyDesiredConfig(context.Background(), next); err != nil || !changed {
		t.Fatalf("apply next changed=%t err=%v", changed, err)
	}

	seq := uint64(2)
	targetSeq, changed, err := daemon.rollbackDesiredConfig(context.Background(), &seq)
	if err != nil {
		t.Fatalf("rollback desired config to seq: %v", err)
	}
	if targetSeq != seq {
		t.Fatalf("rollback target seq = %d, want %d", targetSeq, seq)
	}
	if !changed {
		t.Fatal("rollback did not append a desired config event")
	}
	if daemon.head.Seq != 4 {
		t.Fatalf("head seq = %d, want 4", daemon.head.Seq)
	}
	assertRuntimeRoute(t, daemon, "10.0.1.0/24")
	assertNoRuntimeRoute(t, daemon, "10.0.2.0/24")
}

func TestRestoreLatestLocalDesiredFromConfigLogUpdatesRuntime(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	initial := configApplyDesired(pkiSet, "10.0.1.0/24")
	next := configApplyDesired(pkiSet, "10.0.2.0/24")
	daemon := newConfigApplyTestDaemon(t, initial)
	if changed, err := daemon.applyDesiredConfig(context.Background(), next); err != nil || !changed {
		t.Fatalf("apply next changed=%t err=%v", changed, err)
	}

	restarted := newConfigApplyTestDaemon(t, initial)
	restarted.store = daemon.store
	head, err := restarted.store.Head()
	if err != nil {
		t.Fatalf("read config head: %v", err)
	}
	restarted.head = head
	if err := restarted.restoreLatestLocalDesiredFromLogLocked(context.Background()); err != nil {
		t.Fatalf("restore latest desired: %v", err)
	}

	assertRuntimeRoute(t, restarted, "10.0.2.0/24")
	assertNoRuntimeRoute(t, restarted, "10.0.1.0/24")
	if !desiredConfigsEqual(restarted.desired, config.Normalize(next)) {
		t.Fatal("runtime desired was not restored from config log")
	}
}

func TestConfigApplySameLoggedDesiredReconcilesRuntimeDrift(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	initial := configApplyDesired(pkiSet, "10.0.1.0/24")
	next := configApplyDesired(pkiSet, "10.0.2.0/24")
	daemon := newConfigApplyTestDaemon(t, initial)
	if changed, err := daemon.applyDesiredConfig(context.Background(), next); err != nil || !changed {
		t.Fatalf("apply next changed=%t err=%v", changed, err)
	}
	daemon.setRuntimeDesired(initial, daemon.head)
	if err := daemon.applyRuntimeDataplaneSnapshot(context.Background()); err != nil {
		t.Fatalf("apply drifted snapshot: %v", err)
	}

	changed, err := daemon.applyDesiredConfig(context.Background(), next)
	if err != nil {
		t.Fatalf("reconcile same logged desired: %v", err)
	}
	if changed {
		t.Fatal("same logged desired should not append a config event")
	}
	assertRuntimeRoute(t, daemon, "10.0.2.0/24")
	assertNoRuntimeRoute(t, daemon, "10.0.1.0/24")
}

func TestStartPeerAPIServerDisabledReturnsNilChannel(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemon := newConfigApplyTestDaemon(t, configApplyDesired(pkiSet, "10.0.1.0/24"))
	daemon.cfg.PeerAPIAddr = ""

	server, errc, err := daemon.startPeerAPIServer()
	if err != nil {
		t.Fatalf("start disabled peer api: %v", err)
	}
	if server != nil {
		t.Fatalf("server = %#v, want nil", server)
	}
	if errc != nil {
		t.Fatalf("errc = %#v, want nil", errc)
	}
}

func TestDataPathListenersNeedRestartIgnoresRouteOnlyChanges(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	oldDesired := configApplyDesired(pkiSet, "10.0.1.0/24")
	oldDesired.Endpoints = []config.EndpointConfig{{
		Name:      "a-exp",
		Mode:      config.EndpointModePassive,
		Listen:    "127.0.0.1:7001",
		Address:   "127.0.0.1:7001",
		Transport: "experimental_tcp",
		Enabled:   true,
	}}
	newDesired := oldDesired
	newDesired.Endpoints = append([]config.EndpointConfig(nil), oldDesired.Endpoints...)
	newDesired.Routes = []config.RouteConfig{{
		Prefix:  "10.0.2.0/24",
		Owner:   "ix-c",
		NextHop: "ix-b",
		Metric:  50,
	}}

	if dataPathListenersNeedRestart(oldDesired, newDesired) {
		t.Fatal("route-only change should not restart passive listeners")
	}
	newDesired.Endpoints[0].Listen = "127.0.0.1:7009"
	if !dataPathListenersNeedRestart(oldDesired, newDesired) {
		t.Fatal("listener endpoint change should restart passive listeners")
	}
	priorityOnly := oldDesired
	priorityOnly.Endpoints = append([]config.EndpointConfig(nil), oldDesired.Endpoints...)
	priorityOnly.Endpoints[0].Priority = 100
	if dataPathListenersNeedRestart(oldDesired, priorityOnly) {
		t.Fatal("passive endpoint priority change should not restart listeners")
	}
}

func TestDataPathSessionsNeedRestartIgnoresRouteOnlyChanges(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	oldDesired := configApplyDesired(pkiSet, "10.0.1.0/24")
	newDesired := oldDesired
	newDesired.Routes = []config.RouteConfig{{
		Prefix:  "10.0.2.0/24",
		Owner:   "ix-c",
		NextHop: "ix-b",
		Metric:  50,
	}}
	newDesired.RoutePolicy.ImportPrefixes = []core.Prefix{"10.0.0.0/8"}

	if dataPathSessionsNeedRestart(oldDesired, newDesired) {
		t.Fatal("route-only change should not restart data sessions")
	}
	endpointChanged := configApplyDesired(pkiSet, "10.0.1.0/24")
	endpointChanged.Peers[0].Endpoints[0].Address = "127.0.0.1:7999"
	if !dataPathSessionsNeedRestart(oldDesired, endpointChanged) {
		t.Fatal("peer endpoint address change should restart data sessions")
	}
	priorityChanged := configApplyDesired(pkiSet, "10.0.1.0/24")
	priorityChanged.Peers[0].Endpoints[0].Priority = 100
	if !dataPathSessionsNeedRestart(oldDesired, priorityChanged) {
		t.Fatal("peer endpoint priority change should restart data sessions")
	}
	localPriorityChanged := oldDesired
	localPriorityChanged.Endpoints = []config.EndpointConfig{{
		Name:      "a-udp",
		Mode:      config.EndpointModePassive,
		Listen:    "127.0.0.1:7001",
		Transport: "udp",
		Enabled:   true,
		Priority:  100,
	}}
	oldWithLocal := oldDesired
	oldWithLocal.Endpoints = []config.EndpointConfig{{
		Name:      "a-udp",
		Mode:      config.EndpointModePassive,
		Listen:    "127.0.0.1:7001",
		Transport: "udp",
		Enabled:   true,
	}}
	if !dataPathSessionsNeedRestart(oldWithLocal, localPriorityChanged) {
		t.Fatal("local endpoint priority change should restart data sessions")
	}
}

func TestConfigApplyRouteOnlyKeepsDataSessions(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	initial := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, initial)
	session := &recordingSession{}
	key := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "b-udp",
		Transport:  "udp",
		Address:    "127.0.0.1:7002",
		Encryption: "secure",
	}
	daemon.dataSessions[key] = session
	daemon.dataSessionState[key] = &dataSessionRuntime{key: key, session: session}

	next := configApplyDesired(pkiSet, "10.0.2.0/24")
	if changed, err := daemon.applyDesiredConfig(context.Background(), next); err != nil || !changed {
		t.Fatalf("apply route-only desired changed=%t err=%v", changed, err)
	}
	if session.closed {
		t.Fatal("route-only config apply closed an existing data session")
	}
	if daemon.dataSessions[key] != session {
		t.Fatal("route-only config apply removed an existing data session")
	}
}

func TestConfigApplyRouteEndpointChangeRestartsPeerSessions(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	initial := configApplyDesired(pkiSet, "10.0.1.0/24")
	initial.Peers[0].Endpoints = append(initial.Peers[0].Endpoints, config.EndpointConfig{
		Name:      core.EndpointID("b-experimental-tcp"),
		Address:   "127.0.0.1:7142",
		Transport: "experimental_tcp",
		Enabled:   true,
	})
	daemon := newConfigApplyTestDaemon(t, initial)
	session := &recordingSession{}
	key := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "b-udp",
		Transport:  "udp",
		Address:    "127.0.0.1:7002",
		Encryption: "secure",
	}
	daemon.dataSessions[key] = session
	daemon.dataSessionState[key] = &dataSessionRuntime{key: key, session: session}

	next := configApplyDesired(pkiSet, "10.0.1.0/24")
	next.Peers[0].Endpoints = append(next.Peers[0].Endpoints, config.EndpointConfig{
		Name:      core.EndpointID("b-experimental-tcp"),
		Address:   "127.0.0.1:7142",
		Transport: "experimental_tcp",
		Enabled:   true,
	})
	next.Routes[0].Endpoint = core.EndpointID("b-experimental-tcp")
	if changed, err := daemon.applyDesiredConfig(context.Background(), next); err != nil || !changed {
		t.Fatalf("apply route endpoint change changed=%t err=%v", changed, err)
	}
	if !session.closed {
		t.Fatal("route endpoint change should close existing peer data session")
	}
	if _, ok := daemon.dataSessions[key]; ok {
		t.Fatal("route endpoint change should remove old peer data session")
	}
}

func TestConfigApplyDisablingRouteEndpointRestartsPeerSessions(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	initial := configApplyDesired(pkiSet, "10.0.1.0/24")
	daemon := newConfigApplyTestDaemon(t, initial)
	session := &recordingSession{}
	key := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "b-udp",
		Transport:  "udp",
		Address:    "127.0.0.1:7002",
		Encryption: "secure",
	}
	daemon.dataSessions[key] = session
	daemon.dataSessionState[key] = &dataSessionRuntime{key: key, session: session}

	next := configApplyDesired(pkiSet, "10.0.1.0/24")
	next.Peers[0].Endpoints[0].Enabled = false
	next.Peers[0].Endpoints[0].EnabledSet = true
	if changed, err := daemon.applyDesiredConfig(context.Background(), next); err != nil || !changed {
		t.Fatalf("apply endpoint disable changed=%t err=%v", changed, err)
	}
	if !session.closed {
		t.Fatal("disabling a selected endpoint should close existing peer data session")
	}
	if _, ok := daemon.dataSessions[key]; ok {
		t.Fatal("disabling a selected endpoint should remove old peer data session")
	}
	route := routesFromConfig(next)[0]
	if _, _, err := daemon.candidatePeerEndpoints(next.Peers[0], route, routing.FlowKey{}, false); err == nil {
		t.Fatal("disabled explicit route endpoint should not be selectable")
	}
}

func TestEndpointsFromConfigMarksDefaultEnabledPeerEndpointUsable(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	desired.Peers[0].Endpoints[0].Enabled = false
	desired.Peers[0].Endpoints[0].EnabledSet = false

	endpoints := endpointsFromConfig(desired)
	for _, endpoint := range endpoints {
		if endpoint.Peer == desired.Peers[0].ID && endpoint.ID == desired.Peers[0].Endpoints[0].Name {
			if !endpoint.Enabled {
				t.Fatalf("default-enabled peer endpoint metadata = disabled: %#v", endpoint)
			}
			return
		}
	}
	t.Fatalf("peer endpoint %q missing from metadata: %#v", desired.Peers[0].Endpoints[0].Name, endpoints)
}

func TestConfigApplyRouteEndpointChangeWarmsNewKernelDirectSession(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	initial := configApplyDesired(pkiSet, "10.0.1.0/24")
	initial.Peers[0].Endpoints = append(initial.Peers[0].Endpoints, config.EndpointConfig{
		Name:      core.EndpointID("b-experimental-tcp"),
		Address:   "127.0.0.1:7142",
		Transport: string(transport.ProtocolExperimentalTCP),
		Enabled:   true,
	})
	initial.TransportPolicy = config.TransportPolicyConfig{
		Encryption: "plaintext",
		KernelTransport: config.KernelTransportPolicyConfig{
			Mode: string(dataplane.KernelTransportModeRequireKernel),
		},
		SessionPool: config.SessionPoolPolicyConfig{Warmup: true},
	}
	daemon := newConfigApplyTestDaemon(t, initial)
	registry := transport.NewRegistry()
	if err := registry.Register(&recordingDialTransport{name: transport.ProtocolUDP}); err != nil {
		t.Fatalf("register udp transport: %v", err)
	}
	expTransport := &recordingDialTransport{name: transport.ProtocolExperimentalTCP}
	if err := registry.Register(expTransport); err != nil {
		t.Fatalf("register experimental_tcp transport: %v", err)
	}
	daemon.transports = registry
	daemon.dataplane = &captureCountingManager{}
	session := &recordingSession{}
	oldKey := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "b-udp",
		Transport:  transport.ProtocolUDP,
		Address:    "127.0.0.1:7002",
		Encryption: "plaintext",
	}
	daemon.dataSessions[oldKey] = session
	daemon.dataSessionState[oldKey] = &dataSessionRuntime{key: oldKey, session: session}

	next := initial
	next.Routes = append([]config.RouteConfig(nil), initial.Routes...)
	next.Routes[0].Endpoint = core.EndpointID("b-experimental-tcp")
	if changed, err := daemon.applyDesiredConfig(context.Background(), next); err != nil || !changed {
		t.Fatalf("apply route endpoint change changed=%t err=%v", changed, err)
	}
	if !session.closed {
		t.Fatal("route endpoint change should close old udp session")
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if expTransport.dialCount() > 0 {
			daemon.dataMu.Lock()
			_, oldExists := daemon.dataSessions[oldKey]
			newExists := false
			for key := range daemon.dataSessions {
				if key.Peer == "ix-b" && key.Endpoint == "b-experimental-tcp" && key.Transport == transport.ProtocolExperimentalTCP {
					newExists = true
				}
			}
			daemon.dataMu.Unlock()
			if oldExists {
				t.Fatal("old udp session still exists after endpoint hot-swap")
			}
			if !newExists {
				t.Fatal("new experimental_tcp session was dialed but not registered")
			}
			for _, runtime := range daemon.dataSessionState {
				if runtime.key.Peer == "ix-b" && runtime.key.Endpoint == "b-experimental-tcp" && !runtime.controlOnly {
					t.Fatal("route warmup session should be control-only until traffic uses it")
				}
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("route endpoint hot-swap did not warm the new experimental_tcp session")
}

func TestConfigApplyRouteEndpointChangeReconcilesStaleOutboundSession(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := configApplyDesired(pkiSet, "10.0.1.0/24")
	desired.Peers[0].Endpoints = append(desired.Peers[0].Endpoints, config.EndpointConfig{
		Name:      core.EndpointID("b-experimental-tcp"),
		Address:   "127.0.0.1:7142",
		Transport: string(transport.ProtocolExperimentalTCP),
		Enabled:   true,
	})
	desired.Routes[0].Endpoint = core.EndpointID("b-experimental-tcp")
	daemon := newConfigApplyTestDaemon(t, desired)

	stale := &recordingSession{}
	staleKey := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "b-udp",
		Transport:  transport.ProtocolUDP,
		Address:    "127.0.0.1:7002",
		Encryption: "secure",
	}
	current := &recordingSession{}
	currentKey := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "b-experimental-tcp",
		Transport:  transport.ProtocolExperimentalTCP,
		Address:    "127.0.0.1:7142",
		Encryption: "secure",
	}
	daemon.dataSessions[staleKey] = stale
	daemon.dataSessionState[staleKey] = &dataSessionRuntime{key: staleKey, session: stale}
	daemon.dataSessions[currentKey] = current
	daemon.dataSessionState[currentKey] = &dataSessionRuntime{key: currentKey, session: current}

	if dropped := daemon.reconcileRouteSelectedOutboundSessions(); dropped != 1 {
		t.Fatalf("dropped sessions = %d, want 1", dropped)
	}
	if !stale.closed {
		t.Fatal("stale route endpoint session should be closed")
	}
	if _, ok := daemon.dataSessions[staleKey]; ok {
		t.Fatal("stale route endpoint session should be removed")
	}
	if current.closed {
		t.Fatal("current route endpoint session should be kept")
	}
	if daemon.dataSessions[currentKey] != current {
		t.Fatal("current route endpoint session should remain registered")
	}
}

func TestConfigApplyDynamicToStaticPeerKeepsEquivalentSession(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	initial := configApplyDesired(pkiSet, "10.0.1.0/24")
	initial.Peers = nil
	daemon := newConfigApplyTestDaemon(t, initial)
	daemon.membershipMu.Lock()
	daemon.members["ix-b"] = memberRecord{
		Advertisement: advertisementResponse{
			DomainID: "lab.local",
			IXID:     "ix-b",
			Endpoints: []dataplane.EndpointMetadata{{
				ID:        "b-udp",
				Peer:      "ix-b",
				Transport: "udp",
				Address:   "127.0.0.1:7002",
				Enabled:   true,
				Security: dataplane.EndpointSecurityMetadata{
					LinkTLS:          "unsupported",
					Encryption:       "secure",
					KeySources:       []string{"trustix_x25519"},
					WireFormat:       "trustix-secure-data-v1",
					CryptoSuites:     []string{"AES-256-GCM-X25519"},
					CryptoPlacements: []string{"userspace"},
				},
			}},
		},
		LastSeen: time.Now().UTC(),
		Direct:   true,
	}
	daemon.membershipMu.Unlock()
	session := &recordingSession{}
	key := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "b-udp",
		Transport:  "udp",
		Address:    "127.0.0.1:7002",
		Encryption: "secure",
	}
	daemon.dataSessions[key] = session
	daemon.dataSessionState[key] = &dataSessionRuntime{key: key, session: session}

	next := configApplyDesired(pkiSet, "10.0.2.0/24")
	next.Routes[0].Owner = "ix-c"
	next.Peers[0].Endpoints[0].Enabled = false
	next.Peers[0].Endpoints[0].EnabledSet = false
	if changed, err := daemon.applyDesiredConfig(context.Background(), next); err != nil || !changed {
		t.Fatalf("apply static peer desired changed=%t err=%v", changed, err)
	}
	if session.closed {
		t.Fatal("dynamic-to-static equivalent peer update closed an existing data session")
	}
	if daemon.dataSessions[key] != session {
		t.Fatal("dynamic-to-static equivalent peer update removed an existing data session")
	}
}

func TestConfigApplyRouteToDynamicPeer(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	initial := configApplyDesired(pkiSet, "10.0.1.0/24")
	initial.Peers = nil
	initial.Routes = nil
	daemonA := newConfigApplyTestDaemon(t, initial)
	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 2)
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-c", "10.0.2.0/24")
	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if _, err := daemonA.mergeAdvertisement(advertisement, "test"); err != nil {
		t.Fatalf("merge ix-c advertisement: %v", err)
	}

	next := initial
	next.Routes = []config.RouteConfig{{
		Prefix:  "10.0.2.0/24",
		Owner:   "ix-c",
		NextHop: "ix-c",
		Metric:  100,
	}}
	if changed, err := daemonA.applyDesiredConfig(context.Background(), next); err != nil || !changed {
		t.Fatalf("apply route to dynamic peer changed=%t err=%v", changed, err)
	}
	route, ok := routeByPrefix(daemonA.runtimeRoutes(), "10.0.2.0/24")
	if !ok {
		t.Fatalf("route to dynamic peer missing: %#v", daemonA.runtimeRoutes())
	}
	if route.Source != "static" || route.Owner != "ix-c" || route.NextHop != "ix-c" {
		t.Fatalf("route to dynamic peer = %#v", route)
	}
}

func TestDataSessionSurfaceAutoCompatibleWithUserspaceAdvertisement(t *testing.T) {
	left := dataSessionPeerSurface{
		ID:        "ix-b",
		Domain:    "lab.local",
		Endpoints: []dataSessionEndpointSurface{dataSessionSurfaceEndpointWithPlacements("kernel", "userspace")},
	}
	right := dataSessionPeerSurface{
		ID:        "ix-b",
		Domain:    "lab.local",
		Endpoints: []dataSessionEndpointSurface{dataSessionSurfaceEndpointWithPlacements("userspace")},
	}
	if !dataSessionPeerSurfacesCompatible(left, right) {
		t.Fatal("auto surface should remain compatible with an existing userspace-only session")
	}
}

func TestDataSessionSurfaceExplicitKernelAndUserspaceAreNotCompatible(t *testing.T) {
	left := dataSessionPeerSurface{
		ID:        "ix-b",
		Domain:    "lab.local",
		Endpoints: []dataSessionEndpointSurface{dataSessionSurfaceEndpointWithPlacements("kernel")},
	}
	right := dataSessionPeerSurface{
		ID:        "ix-b",
		Domain:    "lab.local",
		Endpoints: []dataSessionEndpointSurface{dataSessionSurfaceEndpointWithPlacements("userspace")},
	}
	if dataSessionPeerSurfacesCompatible(left, right) {
		t.Fatal("explicit kernel-only and userspace-only surfaces must restart the session")
	}
}

func TestDataSessionSurfaceEmptyTransportProfileRemainsCompatible(t *testing.T) {
	left := dataSessionPeerSurface{
		ID:        "ix-b",
		Domain:    "lab.local",
		Endpoints: []dataSessionEndpointSurface{dataSessionSurfaceEndpointWithPlacements("kernel")},
	}
	right := dataSessionPeerSurface{
		ID:     "ix-b",
		Domain: "lab.local",
		Endpoints: []dataSessionEndpointSurface{func() dataSessionEndpointSurface {
			endpoint := dataSessionSurfaceEndpointWithPlacements("kernel")
			endpoint.Profile = dataplane.TransportProfileMetadata{
				Version:  transportProfileMetadataVersion,
				Profile:  "performance",
				Datapath: "kernel_module",
				Features: []string{"gso_batch_rx"},
			}
			return endpoint
		}()},
	}
	if !dataSessionPeerSurfacesCompatible(left, right) {
		t.Fatal("missing transport profile metadata should remain compatible with an advertised profile")
	}
}

func TestDataSessionSurfaceTransportProfileFeatureChangeIsIncompatible(t *testing.T) {
	left := dataSessionPeerSurface{
		ID:     "ix-b",
		Domain: "lab.local",
		Endpoints: []dataSessionEndpointSurface{func() dataSessionEndpointSurface {
			endpoint := dataSessionSurfaceEndpointWithPlacements("kernel")
			endpoint.Profile = dataplane.TransportProfileMetadata{
				Version:  transportProfileMetadataVersion,
				Profile:  "performance",
				Datapath: "kernel_module",
				Features: []string{"gso_batch_rx"},
			}
			return endpoint
		}()},
	}
	right := dataSessionPeerSurface{
		ID:     "ix-b",
		Domain: "lab.local",
		Endpoints: []dataSessionEndpointSurface{func() dataSessionEndpointSurface {
			endpoint := dataSessionSurfaceEndpointWithPlacements("kernel")
			endpoint.Profile = dataplane.TransportProfileMetadata{
				Version:  transportProfileMetadataVersion,
				Profile:  "performance",
				Datapath: "kernel_module",
				Features: []string{"gso_batch_rx", "outer_gso_rx"},
			}
			return endpoint
		}()},
	}
	if dataSessionPeerSurfacesCompatible(left, right) {
		t.Fatal("explicit transport profile feature changes must restart the session")
	}
}

func TestDataPathSessionsNeedRestartWhenTransportProfilePolicyChanges(t *testing.T) {
	oldDesired := config.Desired{}
	newDesired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:  "performance",
			Datapath: "kernel_module",
			Profiles: []config.TransportProfileConfig{{
				Transport: "experimental_tcp",
				Profile:   "performance",
				Advanced: config.TransportAdvancedConfig{
					GSO:       "enabled",
					MaxFrames: 64,
				},
			}},
		},
	}
	if !dataPathSessionsNeedRestart(oldDesired, newDesired) {
		t.Fatal("transport profile policy changes should restart data sessions")
	}
}

func dataSessionSurfaceEndpointWithPlacements(placements ...string) dataSessionEndpointSurface {
	return dataSessionEndpointSurface{
		Name:      "b-udp",
		Address:   "127.0.0.1:7002",
		Transport: "udp",
		Security: dataplane.EndpointSecurityMetadata{
			LinkTLS:          "unsupported",
			Encryption:       "secure",
			KeySources:       []string{"trustix_x25519"},
			WireFormat:       "trustix-secure-data-v1",
			CryptoSuites:     []string{"AES-256-GCM-X25519"},
			CryptoPlacements: placements,
		},
	}
}

type recordingDialTransport struct {
	name  transport.Protocol
	dials int
}

func (fake *recordingDialTransport) Name() transport.Protocol {
	return fake.name
}

func (fake *recordingDialTransport) Probe(ctx context.Context, peer transport.Peer) transport.ProbeResult {
	return transport.ProbeResult{}
}

func (fake *recordingDialTransport) Dial(ctx context.Context, peer transport.Peer, tlsConf *tls.Config) (transport.Session, error) {
	fake.dials++
	if len(peer.Endpoints) != 1 {
		return nil, fmt.Errorf("recording dial transport expected one endpoint, got %d", len(peer.Endpoints))
	}
	encryption := peer.Endpoints[0].Encryption
	return &statsSession{stats: transport.TransportStats{
		Datagram:         true,
		Encryption:       encryption,
		Encrypted:        encryption != "" && encryption != "plaintext",
		SendEncrypted:    encryption == "secure" || encryption == "send_encrypted",
		ReceiveEncrypted: encryption == "secure" || encryption == "receive_encrypted",
		CryptoPlacement:  "userspace",
		MaxPacketSize:    65536,
		NativeBatching:   true,
	}}, nil
}

func (fake *recordingDialTransport) Listen(ctx context.Context, ep transport.Endpoint, tlsConf *tls.Config) (transport.Listener, error) {
	return nil, fmt.Errorf("unexpected recording dial transport listen")
}

func (fake *recordingDialTransport) dialCount() int {
	return fake.dials
}

func newConfigApplyTestDaemon(t *testing.T, desired config.Desired) *Daemon {
	t.Helper()
	daemon, err := New(Config{DataplaneMode: "noop", DataDir: t.TempDir()}, WithDataplane(dataplane.NewNoopManager()))
	if err != nil {
		t.Fatalf("new daemon: %v", err)
	}
	daemon.desired = desired
	daemon.cfg.DomainID = desired.Domain.ID
	daemon.cfg.IXID = desired.IX.ID
	daemon.store = configlog.NewMemoryStore()
	if err := daemon.registerLocalConfigSigner(); err != nil {
		t.Fatalf("register local config signer: %v", err)
	}
	if err := daemon.ensureConfigGenesisEvent(desired); err != nil {
		t.Fatalf("append genesis: %v", err)
	}
	head, err := daemon.store.Head()
	if err != nil {
		t.Fatalf("read config head: %v", err)
	}
	daemon.head = head
	if err := daemon.refreshLocalAdvertisement(); err != nil {
		t.Fatalf("refresh local advertisement: %v", err)
	}
	if err := daemon.applyRuntimeDataplaneSnapshot(context.Background()); err != nil {
		t.Fatalf("apply initial snapshot: %v", err)
	}
	return daemon
}

func configApplyDesired(pkiSet membershipPKI, peerPrefix string) config.Desired {
	desired := desiredForMembershipTest(pkiSet, "ix-a", "", "", "10.0.0.0/24")
	desired.Endpoints = nil
	desired.Peers = []config.PeerConfig{
		{
			ID:     core.IXID("ix-b"),
			Domain: core.DomainID("lab.local"),
			Endpoints: []config.EndpointConfig{
				{
					Name:      core.EndpointID("b-udp"),
					Address:   "127.0.0.1:7002",
					Transport: "udp",
					Enabled:   true,
				},
			},
			AllowedPrefixes: []core.Prefix{core.Prefix(peerPrefix)},
		},
	}
	desired.Routes = []config.RouteConfig{
		{
			Prefix:   core.Prefix(peerPrefix),
			NextHop:  core.IXID("ix-b"),
			Endpoint: core.EndpointID("b-udp"),
			Policy:   core.PolicyID("default-routed"),
			Metric:   100,
		},
	}
	desired.Policies = []config.PolicyConfig{
		{Name: core.PolicyID("default-routed"), RouteSelection: "longest_prefix"},
	}
	desired.TransportPolicy = config.TransportPolicyConfig{}
	return desired
}

func assertRuntimeRoute(t *testing.T, daemon *Daemon, prefix core.Prefix) {
	t.Helper()
	for _, route := range daemon.runtimeRoutes() {
		if route.Prefix == prefix {
			return
		}
	}
	t.Fatalf("runtime route %q was not found in %#v", prefix, daemon.runtimeRoutes())
}

func assertNoRuntimeRoute(t *testing.T, daemon *Daemon, prefix core.Prefix) {
	t.Helper()
	for _, route := range daemon.runtimeRoutes() {
		if route.Prefix == prefix {
			t.Fatalf("runtime route %q should not be present: %#v", prefix, daemon.runtimeRoutes())
		}
	}
}
