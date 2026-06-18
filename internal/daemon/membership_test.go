package daemon

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/configlog"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/pki"
	"trustix.local/trustix/internal/routing"
	"trustix.local/trustix/internal/transport"
)

type membershipPKI struct {
	trustRoots []string
	ixCerts    map[core.IXID]string
	ixKeys     map[core.IXID]string
	adminCert  string
	adminKey   string
	admin2Cert string
	admin2Key  string
	routeCerts map[core.IXID]string
}

func TestMergeAdvertisementAddsDynamicRoute(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 2)
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-c", "10.0.2.0/24")

	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	changed, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap")
	if err != nil {
		t.Fatalf("merge ix-c advertisement: %v", err)
	}
	if !changed {
		t.Fatal("merge did not report a new dynamic member")
	}
	if err := daemonA.applyRuntimeDataplaneSnapshot(context.Background()); err != nil {
		t.Fatalf("apply dynamic snapshot: %v", err)
	}

	routes := daemonA.runtimeRoutes()
	var found bool
	for _, route := range routes {
		if route.Prefix == "10.0.2.0/24" {
			found = true
			if route.NextHop != "ix-c" {
				t.Fatalf("dynamic route next hop = %q, want ix-c", route.NextHop)
			}
			if route.Owner != "ix-c" {
				t.Fatalf("dynamic route owner = %q, want ix-c", route.Owner)
			}
			if route.Endpoint != "" {
				t.Fatalf("dynamic route endpoint = %q, want empty for policy selection", route.Endpoint)
			}
			if route.Metric != dynamicRouteMetric {
				t.Fatalf("dynamic route metric = %d, want %d", route.Metric, dynamicRouteMetric)
			}
		}
	}
	if !found {
		t.Fatalf("runtime routes do not include ix-c prefix: %#v", routes)
	}

	peer, ok := daemonA.dynamicPeerConfig("ix-c")
	if !ok {
		t.Fatal("dynamic peer config for ix-c was not created")
	}
	if peer.ControlAPI != "https://127.0.0.1:9445" {
		t.Fatalf("dynamic peer control_api = %q", peer.ControlAPI)
	}
	if len(peer.Endpoints) != 1 || peer.Endpoints[0].Address != "127.0.0.1:7003" {
		t.Fatalf("dynamic peer endpoints = %#v", peer.Endpoints)
	}
	if peer.Endpoints[0].Security.WireFormat != "trustix-secure-data-v1" {
		t.Fatalf("dynamic peer endpoint security = %#v, want TrustIX secure wire format", peer.Endpoints[0].Security)
	}
	if len(peer.Endpoints[0].Security.CryptoSuites) != 1 || peer.Endpoints[0].Security.CryptoSuites[0] != "AES-256-GCM-X25519" {
		t.Fatalf("dynamic peer endpoint crypto suites = %#v", peer.Endpoints[0].Security.CryptoSuites)
	}
}

func TestLocalAdvertisementCarriesEndpointSecurity(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24")
	desired.Endpoints[0].Transport = "tcp"
	desired.Endpoints[0].TLSServerName = "ix-a.example.test"
	desired.TransportPolicy.CryptoKeySource = "tls_exporter"
	desired.TransportPolicy.TLSIdentity.Mode = "custom_cert"
	desired.TransportPolicy.TLSIdentity.CertPath = desired.IX.CertPath
	desired.TransportPolicy.TLSIdentity.KeyPath = desired.IX.KeyPath
	desired.TransportPolicy.TLSIdentity.TrustRoots = desired.Domain.TrustRoots
	desired.TransportPolicy.Encryption = "send_encrypted"
	desired.TransportPolicy.CryptoSuites = []string{"AES-128-GCM-X25519", "CHACHA20-POLY1305-X25519"}
	daemonA := newMembershipTestDaemon(t, desired, 1)

	advertisement, err := daemonA.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build advertisement: %v", err)
	}
	if len(advertisement.Endpoints) != 1 {
		t.Fatalf("advertised endpoints = %#v", advertisement.Endpoints)
	}
	security := advertisement.Endpoints[0].Security
	if security.LinkTLS != "optional" || security.TLSIdentity != "custom_cert" || security.TLSServerName != "ix-a.example.test" {
		t.Fatalf("advertised TLS security = %#v", security)
	}
	if len(security.KeySources) != 1 || security.KeySources[0] != "tls_exporter" {
		t.Fatalf("advertised key sources = %#v, want tls_exporter", security.KeySources)
	}
	if security.Encryption != "send_encrypted" {
		t.Fatalf("advertised encryption = %q, want send_encrypted", security.Encryption)
	}
	if security.WireFormat != "trustix-secure-data-v1" {
		t.Fatalf("advertised wire format = %q", security.WireFormat)
	}
	if len(security.CryptoSuites) != 2 || security.CryptoSuites[0] != "AES-128-GCM-X25519" || security.CryptoSuites[1] != "CHACHA20-POLY1305-X25519" {
		t.Fatalf("advertised crypto suites = %#v", security.CryptoSuites)
	}
}

func TestLocalAdvertisementIncludesAllEffectiveLANPrefixes(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24")
	desired.LANs = []config.LANConfig{{
		ID:        "trusted-public",
		Type:      config.LANTypeTrustedPublic,
		Iface:     "br-public",
		Gateway:   "10.0.3.1/24",
		Advertise: []core.Prefix{"10.0.3.0/24"},
		Mode:      config.LANModeRouted,
	}}
	daemonA := newMembershipTestDaemon(t, desired, 1)

	advertisement, err := daemonA.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build advertisement: %v", err)
	}
	if !containsString(advertisement.LANPrefixes, "10.0.0.0/24") || !containsString(advertisement.LANPrefixes, "10.0.3.0/24") {
		t.Fatalf("LAN prefixes = %#v, want both legacy and lans prefixes", advertisement.LANPrefixes)
	}
	if !containsAnnouncedPrefix(advertisement.AnnouncedPrefixes, "10.0.0.0/24", "ix-a", "ix-a") ||
		!containsAnnouncedPrefix(advertisement.AnnouncedPrefixes, "10.0.3.0/24", "ix-a", "ix-a") {
		t.Fatalf("announced prefixes = %#v, want both effective LAN prefixes", advertisement.AnnouncedPrefixes)
	}

	routes := daemonA.runtimeRoutes()
	if !runtimeRoutesContainPrefix(routes, "10.0.0.0/24") || !runtimeRoutesContainPrefix(routes, "10.0.3.0/24") {
		t.Fatalf("runtime routes = %#v, want both local LAN routes", routes)
	}
}

func TestLocalAdvertisementCarriesPlaintextEndpointSecurity(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24")
	desired.TransportPolicy.Encryption = "plaintext"
	daemonA := newMembershipTestDaemon(t, desired, 1)

	advertisement, err := daemonA.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build advertisement: %v", err)
	}
	security := advertisement.Endpoints[0].Security
	if security.Encryption != "plaintext" {
		t.Fatalf("advertised encryption = %q, want plaintext", security.Encryption)
	}
	if security.WireFormat != "" || len(security.CryptoSuites) != 0 || len(security.KeySources) != 0 {
		t.Fatalf("plaintext security should not advertise crypto envelope fields: %#v", security)
	}
}

func TestLocalAdvertisementCarriesTransportProfile(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24")
	desired.Endpoints[0].Transport = "experimental_tcp"
	desired.TransportPolicy = config.TransportPolicyConfig{
		Profiles: []config.TransportProfileConfig{{
			Transport:  "experimental_tcp",
			Profile:    "performance",
			Datapath:   "kernel_module",
			Encryption: "plaintext",
		}},
	}
	daemonA := newMembershipTestDaemon(t, desired, 1)

	advertisement, err := daemonA.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build advertisement: %v", err)
	}
	if len(advertisement.Endpoints) != 1 {
		t.Fatalf("advertised endpoints = %#v", advertisement.Endpoints)
	}
	profile := advertisement.Endpoints[0].Profile
	if profile.Version != transportProfileMetadataVersion || profile.Profile != "performance" || profile.Datapath != "kernel_module" || profile.Encryption != "plaintext" {
		t.Fatalf("advertised transport profile = %#v", profile)
	}
	for _, feature := range []string{"tixt_v1", "ackless_tcp", "tixb_batching", "tc_xdp", "af_xdp", "tc_tx_direct", "plaintext_ack_only"} {
		if !containsString(profile.Features, feature) {
			t.Fatalf("advertised transport profile features = %#v, missing %q", profile.Features, feature)
		}
	}
	for _, feature := range []string{"route_gso_async", "route_gso_async_outer_gso", "route_xmit_worker", "route_gso_sync", "tixt_large_frame_rx", "outer_gso_rx", "gso_batch_rx"} {
		if containsString(profile.Features, feature) {
			t.Fatalf("advertised transport profile features = %#v, must not include opt-in/unselected feature %q", profile.Features, feature)
		}
	}
}

func TestPeerConfigFromAdvertisementPreservesTransportProfile(t *testing.T) {
	peer := peerConfigFromAdvertisement(advertisementResponse{
		DomainID: "lab.local",
		IXID:     "ix-b",
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        "ix-b-tcp",
			Transport: "experimental_tcp",
			Address:   "203.0.113.10:7001",
			Enabled:   true,
			Profile: dataplane.TransportProfileMetadata{
				Version:         transportProfileMetadataVersion,
				Profile:         "throughput",
				Datapath:        "full-kernel",
				Encryption:      "PLAINTEXT",
				CryptoPlacement: "USERSPACE",
				Features:        []string{"outer-gso-rx", "gso_batch_rx"},
			},
		}},
	})

	if len(peer.Endpoints) != 1 {
		t.Fatalf("peer endpoints = %#v, want one endpoint", peer.Endpoints)
	}
	profile := peer.Endpoints[0].Profile
	if profile.Version != transportProfileMetadataVersion || profile.Profile != "performance" || profile.Datapath != "kernel_module" || profile.Encryption != "plaintext" || profile.CryptoPlacement != "userspace" {
		t.Fatalf("peer endpoint profile = %#v", profile)
	}
	for _, feature := range []string{"outer_gso_rx", "gso_batch_rx"} {
		if !containsString(profile.Features, feature) {
			t.Fatalf("peer endpoint profile features = %#v, missing %q", profile.Features, feature)
		}
	}
}

func TestLocalAdvertisementForTargetFiltersEndpointPublishPolicy(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24")
	desired.Endpoints = append(desired.Endpoints, config.EndpointConfig{
		Name:      "ix-a-private",
		Mode:      config.EndpointModePassive,
		Listen:    "127.0.0.1:7011",
		Address:   "127.0.0.1:7011",
		Transport: "udp",
		Publish:   config.EndpointPublishConfig{OnlyPeers: []core.IXID{"ix-b"}},
		Enabled:   true,
	})
	daemonA := newMembershipTestDaemon(t, desired, 1)

	adB, err := daemonA.localAdvertisementForTarget(controlTarget{ID: "ix-b", Domain: "lab.local"})
	if err != nil {
		t.Fatalf("build ix-b targeted advertisement: %v", err)
	}
	if err := daemonA.verifyAdvertisement(adB); err != nil {
		t.Fatalf("verify ix-b targeted advertisement: %v", err)
	}
	if !advertisementHasEndpoint(adB, "ix-a-private") {
		t.Fatalf("ix-b targeted advertisement endpoints = %#v, want private endpoint", adB.Endpoints)
	}

	adC, err := daemonA.localAdvertisementForTarget(controlTarget{ID: "ix-c", Domain: "lab.local"})
	if err != nil {
		t.Fatalf("build ix-c targeted advertisement: %v", err)
	}
	if err := daemonA.verifyAdvertisement(adC); err != nil {
		t.Fatalf("verify ix-c targeted advertisement: %v", err)
	}
	if advertisementHasEndpoint(adC, "ix-a-private") {
		t.Fatalf("ix-c targeted advertisement endpoints = %#v, want private endpoint filtered", adC.Endpoints)
	}
}

func TestDynamicPeerConfigNegotiatesKernelTunnelEndpointFromLocalDeclarations(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desiredB := desiredForMembershipTest(pkiSet, "ix-b", "127.0.0.1:7002", "https://127.0.0.1:9444", "10.0.1.0/24")
	desiredB.Endpoints = []config.EndpointConfig{{
		Name:      "ix-b-gre",
		Mode:      config.EndpointModePassive,
		Listen:    "local=198.18.0.2,mtu=1450,port=47900,queues=4",
		Address:   "local=198.18.0.2,mtu=1450,port=47900,queues=4",
		Transport: "gre",
		Enabled:   true,
	}}
	daemonB := newMembershipTestDaemon(t, desiredB, 1)
	adA := advertisementResponse{
		DomainID:    "lab.local",
		IXID:        "ix-a",
		ControlAPI:  "https://127.0.0.1:9443",
		LANPrefixes: []string{"10.0.0.0/24"},
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        "ix-a-gre",
			Peer:      "ix-a",
			Transport: "gre",
			Address:   "local=198.18.0.1,mtu=1400",
			Enabled:   true,
		}},
	}

	peer := daemonB.peerConfigFromAdvertisement(adA)
	if len(peer.Endpoints) != 1 {
		t.Fatalf("negotiated peer endpoints = %#v, want one GRE endpoint", peer.Endpoints)
	}
	address := peer.Endpoints[0].Address
	for _, want := range []string{"local=198.18.0.2", "remote=198.18.0.1", "local_carrier=", "remote_carrier=", "port=47900", "mtu=1400", "queues=4"} {
		if !strings.Contains(address, want) {
			t.Fatalf("negotiated GRE address = %q, missing %q", address, want)
		}
	}
}

func TestStaticPeerConfigMergesNegotiatedDynamicKernelTunnelEndpoints(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desiredB := desiredForMembershipTest(pkiSet, "ix-b", "127.0.0.1:7002", "https://127.0.0.1:9444", "10.0.1.0/24")
	desiredB.Endpoints = []config.EndpointConfig{{
		Name:      "ix-b-gre",
		Mode:      config.EndpointModePassive,
		Listen:    "local=198.18.0.2",
		Address:   "local=198.18.0.2",
		Transport: "gre",
		Enabled:   true,
	}}
	desiredB.Peers = []config.PeerConfig{{
		ID:     "ix-a",
		Domain: "lab.local",
		Endpoints: []config.EndpointConfig{{
			Name:      "ix-a-udp",
			Mode:      config.EndpointModeActive,
			Address:   "127.0.0.1:7001",
			Transport: "udp",
			Enabled:   true,
		}},
		AllowedPrefixes: []core.Prefix{"10.0.0.0/24"},
	}}
	daemonB := newMembershipTestDaemon(t, desiredB, 1)
	adA := advertisementResponse{
		DomainID:    "lab.local",
		IXID:        "ix-a",
		ControlAPI:  "https://127.0.0.1:9443",
		LANPrefixes: []string{"10.0.0.0/24"},
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        "ix-a-gre",
			Peer:      "ix-a",
			Transport: "gre",
			Address:   "local=198.18.0.1",
			Enabled:   true,
		}},
	}
	daemonB.membershipMu.Lock()
	daemonB.members["ix-a"] = memberRecord{Advertisement: adA, LastSeen: time.Now().UTC(), Source: "test"}
	daemonB.membershipMu.Unlock()

	peer, ok := daemonB.effectivePeerConfig("ix-a")
	if !ok {
		t.Fatal("effective static peer was not found")
	}
	if len(peer.Endpoints) != 2 {
		t.Fatalf("merged static peer endpoints = %#v, want static udp plus negotiated gre", peer.Endpoints)
	}
	var foundGRE bool
	for _, endpoint := range peer.Endpoints {
		if endpoint.Name != "ix-a-gre" {
			continue
		}
		foundGRE = true
		for _, want := range []string{"local=198.18.0.2", "remote=198.18.0.1", "local_carrier=", "remote_carrier="} {
			if !strings.Contains(endpoint.Address, want) {
				t.Fatalf("merged GRE endpoint address = %q, missing %q", endpoint.Address, want)
			}
		}
	}
	if !foundGRE {
		t.Fatalf("merged static peer endpoints = %#v, missing negotiated gre", peer.Endpoints)
	}

	var projected bool
	_, _, endpoints := daemonB.runtimeDataplaneState()
	for _, endpoint := range endpoints {
		if endpoint.Peer == "ix-a" && endpoint.ID == "ix-a-gre" {
			projected = true
			break
		}
	}
	if !projected {
		t.Fatalf("runtime endpoints = %#v, missing negotiated static peer gre", endpoints)
	}
}

func TestLocalAdvertisementDoesNotPublishListenAddressAsDialAddress(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24")
	desired.Endpoints[0].Address = ""
	daemonA := newMembershipTestDaemon(t, desired, 1)

	advertisement, err := daemonA.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build advertisement: %v", err)
	}
	if len(advertisement.Endpoints) != 1 {
		t.Fatalf("advertised endpoints = %#v", advertisement.Endpoints)
	}
	if advertisement.Endpoints[0].Address != "" {
		t.Fatalf("advertised endpoint address = %q, want empty", advertisement.Endpoints[0].Address)
	}
	if advertisement.Endpoints[0].Listen != "" {
		t.Fatalf("advertised endpoint listen = %q, want empty local bind metadata", advertisement.Endpoints[0].Listen)
	}
	if !advertisement.Endpoints[0].Enabled {
		t.Fatal("endpoint without public address should remain enabled for reverse session reuse")
	}
}

func advertisementHasEndpoint(ad advertisementResponse, id core.EndpointID) bool {
	for _, endpoint := range ad.Endpoints {
		if endpoint.ID == id {
			return true
		}
	}
	return false
}

func TestRuntimeDataplaneSnapshotKeepsLocalListenForNoPublicEndpoint(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24")
	desired.Endpoints[0].Address = ""
	daemonA := newMembershipTestDaemon(t, desired, 1)

	snapshot := daemonA.runtimeDataplaneSnapshot()
	if len(snapshot.Endpoints) != 1 {
		t.Fatalf("snapshot endpoints = %#v", snapshot.Endpoints)
	}
	endpoint := snapshot.Endpoints[0]
	if endpoint.Address != "" || endpoint.Listen != "127.0.0.1:7001" {
		t.Fatalf("snapshot endpoint address/listen = %q/%q, want empty/listen", endpoint.Address, endpoint.Listen)
	}
}

func TestRuntimeDataplaneSnapshotInheritsPlaintextPeerEndpointSecurity(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24")
	desired.TransportPolicy.Encryption = "plaintext"
	desired.Peers = []config.PeerConfig{{
		ID:     "ix-b",
		Domain: "lab.local",
		Endpoints: []config.EndpointConfig{{
			Name:      "ep-b",
			Address:   "127.0.0.1:7002",
			Transport: "udp",
			Enabled:   true,
		}},
	}}
	daemonA := newMembershipTestDaemon(t, desired, 1)

	snapshot := daemonA.runtimeDataplaneSnapshot()
	for _, endpoint := range snapshot.Endpoints {
		if endpoint.Peer == "ix-b" && endpoint.ID == "ep-b" {
			if endpoint.Security.Encryption != "plaintext" {
				t.Fatalf("peer endpoint encryption = %q, want plaintext", endpoint.Security.Encryption)
			}
			return
		}
	}
	t.Fatalf("peer endpoint ep-b not found in snapshot: %#v", snapshot.Endpoints)
}

func TestDynamicRouteImportsEndpointWithoutDialAddress(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	desiredC := desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24")
	desiredC.Endpoints[0].Address = ""
	daemonC := newMembershipTestDaemon(t, desiredC, 2)
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-c", "10.0.2.0/24")

	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if _, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap"); err != nil {
		t.Fatalf("merge ix-c advertisement: %v", err)
	}
	if _, ok := routeByPrefix(daemonA.runtimeRoutes(), "10.0.2.0/24"); !ok {
		t.Fatalf("runtime routes do not include reverse-only ix-c prefix: %#v", daemonA.runtimeRoutes())
	}
	peer, ok := daemonA.dynamicPeerConfig("ix-c")
	if !ok {
		t.Fatal("dynamic peer config for ix-c was not created")
	}
	if len(peer.Endpoints) != 1 || peer.Endpoints[0].Address != "" {
		t.Fatalf("dynamic peer endpoints = %#v, want reverse-only endpoint", peer.Endpoints)
	}
	if peer.Endpoints[0].Mode != config.EndpointModePassive {
		t.Fatalf("dynamic peer endpoint mode = %q, want passive", peer.Endpoints[0].Mode)
	}
}

func TestLocalAdvertisementDoesNotPublishActiveDialAddress(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7002", "https://127.0.0.1:9445", "10.0.2.0/24")
	desired.IX.ControlAPI = ""
	desired.IX.ControlAPIPublish = "disabled"
	desired.Endpoints = []config.EndpointConfig{{
		Name:      "edge-active",
		Mode:      config.EndpointModeActive,
		Address:   "ix-a.example.com:7000",
		Transport: "udp",
		Enabled:   true,
	}}
	daemonEdge := newMembershipTestDaemon(t, desired, 1)

	advertisement, err := daemonEdge.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build local advertisement: %v", err)
	}
	if advertisement.ControlAPI != "" {
		t.Fatalf("advertised control_api = %q, want empty", advertisement.ControlAPI)
	}
	if len(advertisement.Endpoints) != 1 {
		t.Fatalf("advertised endpoints = %#v, want one reverse-only endpoint", advertisement.Endpoints)
	}
	if advertisement.Endpoints[0].Address != "" {
		t.Fatalf("advertised active endpoint address = %q, want empty reverse-only address", advertisement.Endpoints[0].Address)
	}
}

func TestDynamicRouteRejectsEndpointWithUnusableTransport(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	desiredC := desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24")
	desiredC.Endpoints[0].Transport = "experimental_tcp"
	desiredC.Endpoints[0].Address = ""
	daemonC := newMembershipTestDaemon(t, desiredC, 2)
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-c", "10.0.2.0/24")

	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if _, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap"); err != nil {
		t.Fatalf("merge ix-c advertisement: %v", err)
	}
	if _, ok := routeByPrefix(daemonA.runtimeRoutes(), "10.0.2.0/24"); ok {
		t.Fatalf("runtime routes imported endpoint with unusable transport: %#v", daemonA.runtimeRoutes())
	}
	status := daemonA.runtimeRoutePolicyStatus()
	if !hasRoutePolicyDecision(status.Decisions, "import", "ix-c", "10.0.2.0/24", "reject", "no_usable_endpoint") {
		t.Fatalf("route policy decisions missing unusable endpoint reject: %#v", status.Decisions)
	}
}

func TestDynamicPeerConfigDropsDisabledAdvertisedEndpoint(t *testing.T) {
	daemonA := &Daemon{desired: config.Desired{IX: config.IXConfig{ID: "ix-a"}}}
	adB := advertisementResponse{
		DomainID: "lab.local",
		IXID:     "ix-b",
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        "ix-b-udp",
			Peer:      "ix-b",
			Transport: "udp",
			Address:   "127.0.0.1:7002",
			Enabled:   false,
		}},
	}

	peer := daemonA.peerConfigFromAdvertisement(adB)
	if len(peer.Endpoints) != 0 {
		t.Fatalf("dynamic peer endpoints = %#v, want disabled advertised endpoint filtered", peer.Endpoints)
	}
}

func TestDynamicPeerConfigLocalizesKernelTunnelEndpointForThisIX(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desiredB := desiredForMembershipTest(pkiSet, "ix-b", "127.0.0.1:7002", "https://127.0.0.1:9444", "10.0.1.0/24")
	desiredB.LAN.UnderlayIface = "test-underlay-b"
	desiredB.Endpoints = []config.EndpointConfig{{
		Name:      "ix-b-gre",
		Mode:      config.EndpointModePassive,
		Listen:    "local=198.18.0.2,remote=198.18.0.1,local_carrier=10.255.0.2/30,remote_carrier=10.255.0.1,port=47820,mtu=1476",
		Address:   "local=198.18.0.2,remote=198.18.0.1,local_carrier=10.255.0.2/30,remote_carrier=10.255.0.1,port=47820,mtu=1476",
		Transport: "gre",
		Enabled:   true,
	}}
	daemonB := newMembershipTestDaemon(t, desiredB, 1)
	adA := advertisementResponse{
		DomainID:    "lab.local",
		IXID:        "ix-a",
		ControlAPI:  "https://127.0.0.1:9443",
		LANPrefixes: []string{"10.0.0.0/24"},
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        "ix-a-gre",
			Peer:      "ix-a",
			Transport: "gre",
			Address:   "local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.0.1/30,remote_carrier=10.255.0.2,port=47820,mtu=1476",
			Enabled:   true,
		}},
	}

	peer := daemonB.peerConfigFromAdvertisement(adA)
	if len(peer.Endpoints) != 1 {
		t.Fatalf("localized peer endpoints = %#v, want one GRE endpoint", peer.Endpoints)
	}
	wantAddress := "local=198.18.0.2,remote=198.18.0.1,local_carrier=10.255.0.2/30,remote_carrier=10.255.0.1,port=47820,mtu=1476"
	if peer.Endpoints[0].Address != wantAddress {
		t.Fatalf("localized GRE address = %q, want %q", peer.Endpoints[0].Address, wantAddress)
	}
	if peer.Endpoints[0].Mode != config.EndpointModeActive || !peer.Endpoints[0].Enabled {
		t.Fatalf("localized GRE endpoint = %#v, want active enabled", peer.Endpoints[0])
	}
}

func TestDynamicPeerConfigUsesLocalUnderlayInterfaceForVXLANEndpoint(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desiredB := desiredForMembershipTest(pkiSet, "ix-b", "127.0.0.1:7002", "https://127.0.0.1:9444", "10.0.1.0/24")
	desiredB.LAN.UnderlayIface = "tix-b-underlay"
	desiredB.Endpoints = []config.EndpointConfig{{
		Name:      "ix-b-vxlan",
		Mode:      config.EndpointModePassive,
		Listen:    "local=198.18.0.2,remote=198.18.0.1,underlay_if=tix-b-underlay,local_carrier=10.255.0.2/30,remote_carrier=10.255.0.1,port=47820,mtu=1450,vni=7",
		Address:   "local=198.18.0.2,remote=198.18.0.1,underlay_if=tix-b-underlay,local_carrier=10.255.0.2/30,remote_carrier=10.255.0.1,port=47820,mtu=1450,vni=7",
		Transport: "vxlan",
		Enabled:   true,
	}}
	daemonB := newMembershipTestDaemon(t, desiredB, 1)
	adA := advertisementResponse{
		DomainID:    "lab.local",
		IXID:        "ix-a",
		ControlAPI:  "https://127.0.0.1:9443",
		LANPrefixes: []string{"10.0.0.0/24"},
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        "ix-a-vxlan",
			Peer:      "ix-a",
			Transport: "vxlan",
			Address:   "local=198.18.0.1,remote=198.18.0.2,underlay_if=tix-a-underlay,local_carrier=10.255.0.1/30,remote_carrier=10.255.0.2,port=47820,mtu=1450,vni=7",
			Enabled:   true,
		}},
	}

	peer := daemonB.peerConfigFromAdvertisement(adA)
	if len(peer.Endpoints) != 1 {
		t.Fatalf("localized peer endpoints = %#v, want one VXLAN endpoint", peer.Endpoints)
	}
	if !strings.Contains(peer.Endpoints[0].Address, "underlay_if=tix-b-underlay") {
		t.Fatalf("localized VXLAN address = %q, want local underlay iface", peer.Endpoints[0].Address)
	}
	if strings.Contains(peer.Endpoints[0].Address, "underlay_if=tix-a-underlay") {
		t.Fatalf("localized VXLAN address kept remote underlay iface: %q", peer.Endpoints[0].Address)
	}
}

func TestDynamicRouteRejectsKernelTunnelEndpointForDifferentIX(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desiredC := desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24")
	desiredC.Endpoints = []config.EndpointConfig{{
		Name:      "ix-c-gre",
		Mode:      config.EndpointModePassive,
		Listen:    "local=198.18.0.3,remote=198.18.0.1,local_carrier=10.255.1.2/30,remote_carrier=10.255.1.1,port=47821,mtu=1476",
		Address:   "local=198.18.0.3,remote=198.18.0.1,local_carrier=10.255.1.2/30,remote_carrier=10.255.1.1,port=47821,mtu=1476",
		Transport: "gre",
		Enabled:   true,
	}}
	daemonC := newMembershipTestDaemon(t, desiredC, 1)
	adA := advertisementResponse{
		DomainID:    "lab.local",
		IXID:        "ix-a",
		ControlAPI:  "https://127.0.0.1:9443",
		LANPrefixes: []string{"10.0.0.0/24"},
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        "ix-a-gre",
			Peer:      "ix-a",
			Transport: "gre",
			Address:   "local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.0.1/30,remote_carrier=10.255.0.2,port=47820,mtu=1476",
			Enabled:   true,
		}},
	}
	daemonC.membershipMu.Lock()
	daemonC.members["ix-a"] = memberRecord{Advertisement: adA, LastSeen: time.Now().UTC(), Source: "test"}
	daemonC.membershipMu.Unlock()

	if peer := daemonC.peerConfigFromAdvertisement(adA); len(peer.Endpoints) != 0 {
		t.Fatalf("localized peer endpoints = %#v, want none for a tunnel to a different IX", peer.Endpoints)
	}
	if _, ok := routeByPrefix(daemonC.runtimeRoutes(), "10.0.0.0/24"); ok {
		t.Fatalf("runtime routes imported non-localized tunnel endpoint: %#v", daemonC.runtimeRoutes())
	}
	status := daemonC.runtimeRoutePolicyStatus()
	if !hasRoutePolicyDecision(status.Decisions, "import", "ix-a", "10.0.0.0/24", "reject", "no_usable_endpoint") {
		t.Fatalf("route policy decisions missing non-local tunnel reject: %#v", status.Decisions)
	}
}

func TestManagementVIPImportsAsLocalRoute(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desiredA := desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24")
	desiredA.Management.HostAPI.Enabled = true
	desiredA.Management.HostAPI.Listen = "10.0.0.1:8787"
	daemonA := newMembershipTestDaemon(t, desiredA, 1)
	desiredB := desiredForMembershipTest(pkiSet, "ix-b", "127.0.0.1:7002", "https://127.0.0.1:9444", "10.0.1.0/24")
	desiredB.Management.HostAPI.Enabled = true
	desiredB.Management.HostAPI.Listen = "10.0.1.200:8787"
	desiredB.RoutePolicy.ExportPrefixes = []core.Prefix{"10.0.1.200/32"}
	daemonB := newMembershipTestDaemon(t, desiredB, 2)
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-b", "10.0.1.0/24", "10.0.1.200/32")

	advertisement, err := daemonB.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-b advertisement: %v", err)
	}
	if _, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap"); err != nil {
		t.Fatalf("merge ix-b advertisement: %v", err)
	}

	route, ok := routeByPrefix(daemonA.runtimeRoutes(), "10.0.1.200/32")
	if !ok {
		t.Fatalf("management VIP route was not imported: %#v", daemonA.runtimeRoutes())
	}
	if route.Kind != routing.RouteLocal || route.Source != "management_vip" || route.Owner != "ix-b" || route.NextHop != "ix-a" {
		t.Fatalf("management VIP route = %#v, want local ix-b via ix-a", route)
	}
	if route.LocalProtocol != ipProtocolTCP || route.LocalPort != 8787 {
		t.Fatalf("management VIP local match = proto %d port %d, want tcp/8787", route.LocalProtocol, route.LocalPort)
	}
	targets := daemonA.managementVIPTargets()
	if len(targets) != 1 || targets[0].IXID != "ix-b" || targets[0].listenAddress() != "10.0.1.200:8787" {
		t.Fatalf("management VIP targets = %#v", targets)
	}
}

func TestManagementVIPAdvertisementUsesLANGatewayForWildcardListen(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desiredA := desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24")
	desiredA.Management.HostAPI.Enabled = true
	desiredA.Management.HostAPI.Listen = "0.0.0.0:8787"
	daemonA := newMembershipTestDaemon(t, desiredA, 1)
	desiredB := desiredForMembershipTest(pkiSet, "ix-b", "127.0.0.1:7002", "https://127.0.0.1:9444", "10.0.1.0/24")
	desiredB.Management.HostAPI.Enabled = true
	desiredB.Management.HostAPI.Listen = "0.0.0.0:8788"
	daemonB := newMembershipTestDaemon(t, desiredB, 2)
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-b", "10.0.1.0/24")

	advertisement, err := daemonB.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-b advertisement: %v", err)
	}
	if advertisement.Management == nil || advertisement.Management.HostAPI == nil {
		t.Fatalf("management advertisement is missing: %#v", advertisement.Management)
	}
	if advertisement.Management.HostAPI.IP != "10.0.1.1" {
		t.Fatalf("management host ip = %q, want LAN gateway 10.0.1.1", advertisement.Management.HostAPI.IP)
	}
	if containsString(advertisement.LANPrefixes, "10.0.1.1/32") {
		t.Fatalf("advertised prefixes = %#v, want management VIP covered by LAN only", advertisement.LANPrefixes)
	}
	if containsString(advertisement.LANPrefixes, "0.0.0.0/32") {
		t.Fatalf("advertised wildcard management prefix: %#v", advertisement.LANPrefixes)
	}
	if _, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap"); err != nil {
		t.Fatalf("merge ix-b advertisement: %v", err)
	}
	if _, ok := routeByPrefix(daemonA.runtimeRoutes(), "10.0.1.1/32"); ok {
		t.Fatalf("covered management VIP route was imported: %#v", daemonA.runtimeRoutes())
	}
	lanRoute, ok := routeByPrefix(daemonA.runtimeRoutes(), "10.0.1.0/24")
	if !ok || lanRoute.Kind != routing.RouteUnicast || lanRoute.NextHop != "ix-b" {
		t.Fatalf("remote LAN route = %#v, ok=%t", lanRoute, ok)
	}
}

func TestManagementVIPCoveredByAdvertisedLANDoesNotImportLocalRoute(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desiredA := desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24")
	desiredA.Management.HostAPI.Enabled = true
	desiredA.Management.HostAPI.Listen = "10.0.0.1:8787"
	daemonA := newMembershipTestDaemon(t, desiredA, 1)
	desiredB := desiredForMembershipTest(pkiSet, "ix-b", "127.0.0.1:7002", "https://127.0.0.1:9444", "10.0.1.0/24")
	desiredB.Management.HostAPI.Enabled = true
	desiredB.Management.HostAPI.Listen = "10.0.1.1:8787"
	daemonB := newMembershipTestDaemon(t, desiredB, 2)
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-b", "10.0.1.0/24")

	advertisement, err := daemonB.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-b advertisement: %v", err)
	}
	advertisement.LANPrefixes = append(advertisement.LANPrefixes, "10.0.1.1/32")
	resignAdvertisement(t, &advertisement, pkiSet.ixKeys["ix-b"])
	if _, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap"); err != nil {
		t.Fatalf("merge ix-b advertisement: %v", err)
	}

	if route, ok := routeByPrefix(daemonA.runtimeRoutes(), "10.0.1.1/32"); ok {
		if route.Kind == routing.RouteLocal || route.Source == "management_vip" {
			t.Fatalf("covered management VIP route = %#v, want ordinary unicast or no route", route)
		}
	}
	lanRoute, ok := routeByPrefix(daemonA.runtimeRoutes(), "10.0.1.0/24")
	if !ok || lanRoute.Kind != routing.RouteUnicast || lanRoute.NextHop != "ix-b" {
		t.Fatalf("remote LAN route = %#v, ok=%t", lanRoute, ok)
	}
}

func TestManagementVIPAddressOutsideAdvertisedLANIsExported(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desiredB := desiredForMembershipTest(pkiSet, "ix-b", "127.0.0.1:7002", "https://127.0.0.1:9444", "10.0.1.0/24")
	desiredB.Management.HostAPI.Enabled = true
	desiredB.Management.HostAPI.Listen = "10.0.1.200:8787"
	desiredB.RoutePolicy.ExportPrefixes = []core.Prefix{"10.0.1.200/32"}
	daemonB := newMembershipTestDaemon(t, desiredB, 2)

	advertisement, err := daemonB.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-b advertisement: %v", err)
	}
	if !containsString(advertisement.LANPrefixes, "10.0.1.200/32") {
		t.Fatalf("advertised prefixes = %#v, want standalone management VIP", advertisement.LANPrefixes)
	}
	if containsString(advertisement.LANPrefixes, "10.0.1.0/24") {
		t.Fatalf("advertised prefixes = %#v, want export policy to suppress LAN", advertisement.LANPrefixes)
	}
}

func TestRoutePolicyRejectsDynamicImportOutsideAllowedPrefixes(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desiredA := desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24")
	desiredA.RoutePolicy.ImportPrefixes = []core.Prefix{"10.0.99.0/24"}
	daemonA := newMembershipTestDaemon(t, desiredA, 1)
	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 2)
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-c", "10.0.2.0/24")

	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if changed, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap"); err != nil || !changed {
		t.Fatalf("merge ix-c advertisement changed=%t err=%v", changed, err)
	}
	for _, route := range daemonA.runtimeRoutes() {
		if route.Prefix == "10.0.2.0/24" {
			t.Fatalf("route policy imported denied prefix: %#v", route)
		}
	}
	status := daemonA.runtimeRoutePolicyStatus()
	if !hasRoutePolicyDecision(status.Decisions, "import", "ix-c", "10.0.2.0/24", "reject", "import_prefix_denied") {
		t.Fatalf("route policy decisions missing import reject: %#v", status.Decisions)
	}
}

func TestRoutePolicyAcceptsDynamicImportWithConfiguredMetric(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desiredA := desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24")
	desiredA.RoutePolicy.ImportPrefixes = []core.Prefix{"10.0.0.0/8"}
	desiredA.RoutePolicy.DynamicMetric = 250
	daemonA := newMembershipTestDaemon(t, desiredA, 1)
	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 2)
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-c", "10.0.2.0/24")

	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if _, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap"); err != nil {
		t.Fatalf("merge ix-c advertisement: %v", err)
	}
	route, ok := routeByPrefix(daemonA.runtimeRoutes(), "10.0.2.0/24")
	if !ok {
		t.Fatalf("dynamic route was not imported: %#v", daemonA.runtimeRoutes())
	}
	if route.Metric != 250 || route.Source != "dynamic" || route.Reason != "import_prefix_match" {
		t.Fatalf("dynamic route policy fields = %#v", route)
	}
}

func TestPrefixOwnerIndexDetectsAncestorAndDescendantConflicts(t *testing.T) {
	index := newPrefixOwnerIndex()
	index.Add("ix-b", netip.MustParsePrefix("10.0.0.0/16"))
	if !index.Conflicts("ix-c", netip.MustParsePrefix("10.0.1.0/24")) {
		t.Fatal("more-specific prefix from a different owner did not conflict with existing ancestor")
	}
	if index.Conflicts("ix-b", netip.MustParsePrefix("10.0.1.0/24")) {
		t.Fatal("more-specific prefix from the same owner conflicted with existing ancestor")
	}

	index = newPrefixOwnerIndex()
	index.Add("ix-b", netip.MustParsePrefix("10.0.1.0/24"))
	if !index.Conflicts("ix-c", netip.MustParsePrefix("10.0.0.0/16")) {
		t.Fatal("less-specific prefix from a different owner did not conflict with existing descendant")
	}
	if index.Conflicts("ix-b", netip.MustParsePrefix("10.0.0.0/16")) {
		t.Fatal("less-specific prefix from the same owner conflicted with existing descendant")
	}
}

func TestRoutePolicyFiltersLocalExport(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desiredC := desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24")
	desiredC.RoutePolicy.ExportPrefixes = []core.Prefix{"10.99.0.0/16"}
	daemonC := newMembershipTestDaemon(t, desiredC, 2)

	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if len(advertisement.LANPrefixes) != 0 {
		t.Fatalf("export policy advertised prefixes = %#v, want none", advertisement.LANPrefixes)
	}
	status := daemonC.runtimeRoutePolicyStatus()
	if !hasRoutePolicyDecision(status.Decisions, "export", "ix-c", "10.0.2.0/24", "reject", "export_prefix_denied") {
		t.Fatalf("route policy decisions missing export reject: %#v", status.Decisions)
	}
}

func TestRoutePolicyDefaultRouteRequiresExplicitAllow(t *testing.T) {
	defaultRoute := netip.MustParsePrefix("0.0.0.0/0")
	if allowed, reason := importPolicyAllows(defaultRoute, nil); allowed || reason != "default_route_not_explicit" {
		t.Fatalf("import default route allowed=%t reason=%q, want explicit reject", allowed, reason)
	}
	if allowed, reason := exportPolicyAllows(defaultRoute, nil); allowed || reason != "default_route_not_explicit" {
		t.Fatalf("export default route allowed=%t reason=%q, want explicit reject", allowed, reason)
	}
	if allowed, reason := importPolicyAllows(defaultRoute, []netip.Prefix{defaultRoute}); !allowed || reason != "import_prefix_match" {
		t.Fatalf("explicit import default route allowed=%t reason=%q", allowed, reason)
	}
	if allowed, reason := exportPolicyAllows(defaultRoute, []netip.Prefix{defaultRoute}); !allowed || reason != "export_prefix_match" {
		t.Fatalf("explicit export default route allowed=%t reason=%q", allowed, reason)
	}
}

func TestMembershipGossipsThreeIXTopology(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	daemonB := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-b", "127.0.0.1:7002", "https://127.0.0.1:9444", "10.0.1.0/24"), 2)
	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 3)
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-b", "10.0.1.0/24")
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-c", "10.0.2.0/24")
	authorizeMembershipTestIX(t, daemonB, pkiSet, "ix-a", "10.0.0.0/24")
	authorizeMembershipTestIX(t, daemonB, pkiSet, "ix-c", "10.0.2.0/24")
	if err := daemonA.refreshLocalAdvertisement(); err != nil {
		t.Fatalf("refresh ix-a advertisement: %v", err)
	}
	if err := daemonB.refreshLocalAdvertisement(); err != nil {
		t.Fatalf("refresh ix-b advertisement: %v", err)
	}
	if err := daemonC.refreshLocalAdvertisement(); err != nil {
		t.Fatalf("refresh ix-c advertisement: %v", err)
	}

	adA, err := daemonA.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-a advertisement: %v", err)
	}
	adC, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if _, err := daemonB.mergeAdvertisement(adA, "test-a"); err != nil {
		t.Fatalf("merge ix-a into ix-b: %v", err)
	}
	if _, err := daemonB.mergeAdvertisement(adC, "test-c"); err != nil {
		t.Fatalf("merge ix-c into ix-b: %v", err)
	}

	server := httptest.NewServer(daemonB.peerHandler())
	defer server.Close()
	targetB := controlTarget{ID: "ix-b", ControlAPI: server.URL}
	advertisements, err := daemonA.fetchMembers(context.Background(), targetB)
	if err != nil {
		t.Fatalf("fetch ix-b members: %v", err)
	}
	for _, advertisement := range advertisements {
		if _, err := daemonA.mergeAdvertisementFromControlTarget(advertisement, targetB); err != nil {
			t.Fatalf("merge gossiped advertisement %q: %v", advertisement.IXID, err)
		}
	}
	if _, ok := routeByPrefix(daemonA.runtimeRoutes(), "10.0.1.0/24"); !ok {
		t.Fatalf("ix-a did not learn ix-b route through gossip: %#v", daemonA.runtimeRoutes())
	}
	routeC, ok := routeByPrefix(daemonA.runtimeRoutes(), "10.0.2.0/24")
	if !ok {
		t.Fatalf("ix-a did not learn ix-c route through ix-b gossip: %#v", daemonA.runtimeRoutes())
	}
	if routeC.Owner != "ix-c" || routeC.NextHop != "ix-b" || routeC.Source != "dynamic_transit" {
		t.Fatalf("ix-c route through ix-b gossip = %#v, want owner ix-c next_hop ix-b dynamic_transit", routeC)
	}
}

func TestMembershipHubOutageReconnectRestoresPrunedMembers(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "", "10.0.0.0/24"), 1)
	daemonB := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-b", "127.0.0.1:7002", "", "10.0.1.0/24"), 2)
	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "", "10.0.2.0/24"), 3)

	hubOnline := atomic.Bool{}
	hubOnline.Store(true)
	serverA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hubOnline.Load() {
			http.Error(w, "hub offline", http.StatusServiceUnavailable)
			return
		}
		daemonA.peerHandler().ServeHTTP(w, r)
	}))
	defer serverA.Close()
	serverB := httptest.NewServer(daemonB.peerHandler())
	defer serverB.Close()
	serverC := httptest.NewServer(daemonC.peerHandler())
	defer serverC.Close()

	daemonA.desired.IX.ControlAPI = serverA.URL
	daemonB.desired.IX.ControlAPI = serverB.URL
	daemonC.desired.IX.ControlAPI = serverC.URL
	daemonB.desired.Bootstrap.Peers = []config.BootstrapPeerConfig{{
		ID:         "ix-a",
		Domain:     "lab.local",
		ControlAPI: serverA.URL,
	}}
	daemonC.desired.Bootstrap.Peers = []config.BootstrapPeerConfig{{
		ID:         "ix-a",
		Domain:     "lab.local",
		ControlAPI: serverA.URL,
	}}

	authorizeMembershipTestIXWithControlAPI(t, daemonA, pkiSet, "ix-b", serverB.URL, "10.0.1.0/24")
	authorizeMembershipTestIXWithControlAPI(t, daemonA, pkiSet, "ix-c", serverC.URL, "10.0.2.0/24")
	authorizeMembershipTestIXWithControlAPI(t, daemonB, pkiSet, "ix-a", serverA.URL, "10.0.0.0/24")
	authorizeMembershipTestIXWithControlAPI(t, daemonB, pkiSet, "ix-c", serverC.URL, "10.0.2.0/24")
	authorizeMembershipTestIXWithControlAPI(t, daemonC, pkiSet, "ix-a", serverA.URL, "10.0.0.0/24")
	authorizeMembershipTestIXWithControlAPI(t, daemonC, pkiSet, "ix-b", serverB.URL, "10.0.1.0/24")

	for _, daemon := range []*Daemon{daemonA, daemonB, daemonC} {
		if err := daemon.refreshLocalAdvertisement(); err != nil {
			t.Fatalf("refresh local advertisement for %s: %v", daemon.desired.IX.ID, err)
		}
	}

	ctx := context.Background()
	daemonB.pollPeers(ctx)
	daemonC.pollPeers(ctx)
	daemonB.pollPeers(ctx)
	daemonB.pollPeers(ctx)
	daemonC.pollPeers(ctx)
	if _, ok := routeByPrefix(daemonA.runtimeRoutes(), "10.0.1.0/24"); !ok {
		t.Fatalf("hub did not learn ix-b before outage: %#v", daemonA.runtimeRoutes())
	}
	if _, ok := routeByPrefix(daemonA.runtimeRoutes(), "10.0.2.0/24"); !ok {
		t.Fatalf("hub did not learn ix-c before outage: %#v", daemonA.runtimeRoutes())
	}
	if route, ok := routeByPrefix(daemonB.runtimeRoutes(), "10.0.2.0/24"); !ok || route.NextHop != "ix-c" {
		t.Fatalf("ix-b did not learn direct ix-c before outage: route=%#v ok=%t", route, ok)
	}

	hubOnline.Store(false)
	for _, daemon := range []*Daemon{daemonB, daemonC} {
		daemon.membershipMu.Lock()
		record := daemon.members["ix-a"]
		record.LastSeen = time.Now().Add(-memberRecordTTL - time.Second)
		daemon.members["ix-a"] = record
		daemon.membershipMu.Unlock()
		daemon.pollPeers(ctx)
		if _, ok := routeByPrefix(daemon.runtimeRoutes(), "10.0.0.0/24"); ok {
			t.Fatalf("%s kept expired hub route during outage: %#v", daemon.desired.IX.ID, daemon.runtimeRoutes())
		}
	}

	daemonA.membershipMu.Lock()
	delete(daemonA.members, "ix-b")
	delete(daemonA.members, "ix-c")
	daemonA.membershipMu.Unlock()
	if err := daemonA.applyRuntimeDataplaneSnapshot(ctx); err != nil {
		t.Fatalf("apply emptied hub snapshot: %v", err)
	}
	hubOnline.Store(true)
	daemonB.pollPeers(ctx)
	daemonC.pollPeers(ctx)
	daemonB.pollPeers(ctx)

	if _, ok := routeByPrefix(daemonA.runtimeRoutes(), "10.0.1.0/24"); !ok {
		t.Fatalf("hub did not relearn ix-b after reconnect: %#v", daemonA.runtimeRoutes())
	}
	if _, ok := routeByPrefix(daemonA.runtimeRoutes(), "10.0.2.0/24"); !ok {
		t.Fatalf("hub did not relearn ix-c after reconnect: %#v", daemonA.runtimeRoutes())
	}
	if route, ok := routeByPrefix(daemonB.runtimeRoutes(), "10.0.0.0/24"); !ok || route.NextHop != "ix-a" {
		t.Fatalf("ix-b did not restore hub route after reconnect: route=%#v ok=%t", route, ok)
	}
	if route, ok := routeByPrefix(daemonC.runtimeRoutes(), "10.0.0.0/24"); !ok || route.NextHop != "ix-a" {
		t.Fatalf("ix-c did not restore hub route after reconnect: route=%#v ok=%t", route, ok)
	}
}

func TestMembershipAllIXColdRestartRestoresRoutes(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "", "10.0.0.0/24"), 1)
	daemonB := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-b", "127.0.0.1:7002", "", "10.0.1.0/24"), 2)
	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "", "10.0.2.0/24"), 3)
	daemonA.cfg.DataDir = t.TempDir()
	daemonB.cfg.DataDir = t.TempDir()
	daemonC.cfg.DataDir = t.TempDir()
	enableFileConfigLogForMembershipTest(t, daemonA)
	enableFileConfigLogForMembershipTest(t, daemonB)
	enableFileConfigLogForMembershipTest(t, daemonC)

	serverA := newSwitchablePeerServer(t, daemonA)
	defer serverA.Close()
	serverB := newSwitchablePeerServer(t, daemonB)
	defer serverB.Close()
	serverC := newSwitchablePeerServer(t, daemonC)
	defer serverC.Close()

	configureRestartMembershipTopology(t, pkiSet, daemonA, daemonB, daemonC, serverA.URL(), serverB.URL(), serverC.URL())

	ctx := context.Background()
	pollMembershipSet(ctx, daemonA, daemonB, daemonC, 5)
	assertAllIXDirectRoutes(t, daemonA, daemonB, daemonC)

	serverA.SetOnline(false)
	serverB.SetOnline(false)
	serverC.SetOnline(false)

	restartedA := restartMembershipTestDaemon(t, daemonA)
	restartedB := restartMembershipTestDaemon(t, daemonB)
	restartedC := restartMembershipTestDaemon(t, daemonC)
	serverA.SetDaemon(restartedA)
	serverB.SetDaemon(restartedB)
	serverC.SetDaemon(restartedC)
	serverA.SetOnline(true)
	serverB.SetOnline(true)
	serverC.SetOnline(true)

	assertAllIXDirectRoutes(t, restartedA, restartedB, restartedC)
	pollMembershipSet(ctx, restartedA, restartedB, restartedC, 3)
	assertAllIXDirectRoutes(t, restartedA, restartedB, restartedC)

	serverA.SetOnline(false)
	serverB.SetOnline(false)
	serverC.SetOnline(false)
	expirePersistedMembersForRestartTest(t, restartedA, restartedB, restartedC)

	staleRestartA := restartMembershipTestDaemon(t, restartedA)
	staleRestartB := restartMembershipTestDaemon(t, restartedB)
	staleRestartC := restartMembershipTestDaemon(t, restartedC)
	serverA.SetDaemon(staleRestartA)
	serverB.SetDaemon(staleRestartB)
	serverC.SetDaemon(staleRestartC)
	serverA.SetOnline(true)
	serverB.SetOnline(true)
	serverC.SetOnline(true)

	pollMembershipSet(ctx, staleRestartA, staleRestartB, staleRestartC, 6)
	assertAllIXDirectRoutes(t, staleRestartA, staleRestartB, staleRestartC)
}

func TestControlTargetsBoundsDynamicFanout(t *testing.T) {
	now := time.Now().UTC()
	fanout := 2
	daemon := &Daemon{
		desired: config.Desired{
			Domain: config.DomainConfig{ID: "lab.local"},
			IX:     config.IXConfig{ID: "ix-a", Domain: "lab.local"},
			ControlFabric: config.ControlFabricConfig{
				Profile:              "edge",
				DynamicControlFanout: &fanout,
			},
			Peers: []config.PeerConfig{{
				ID:         "ix-static",
				Domain:     "lab.local",
				ControlAPI: "https://127.0.0.1:9444",
			}},
			Bootstrap: config.BootstrapConfig{Peers: []config.BootstrapPeerConfig{{
				ID:         "ix-reflector",
				Domain:     "lab.local",
				ControlAPI: "https://127.0.0.1:9445",
			}}},
		},
		members: map[core.IXID]memberRecord{},
	}
	for i := 0; i < 5; i++ {
		ixID := core.IXID(fmt.Sprintf("ix-dyn-%d", i))
		daemon.members[ixID] = memberRecord{
			Advertisement: advertisementResponse{
				DomainID:   "lab.local",
				IXID:       string(ixID),
				ControlAPI: fmt.Sprintf("https://127.0.0.1:%d", 9500+i),
			},
			LastSeen: now,
			Direct:   true,
		}
	}

	first := daemon.controlTargets()
	second := daemon.controlTargets()
	if countDynamicControlTargets(first) != 2 {
		t.Fatalf("first dynamic control targets = %#v, want exactly 2 dynamic targets", first)
	}
	if countDynamicControlTargets(second) != 2 {
		t.Fatalf("second dynamic control targets = %#v, want exactly 2 dynamic targets", second)
	}
	if !hasControlTarget(first, "ix-static") || !hasControlTarget(first, "ix-reflector") {
		t.Fatalf("bounded fanout dropped static/bootstrap targets: %#v", first)
	}
	if dynamicControlTargetIDs(first) == dynamicControlTargetIDs(second) {
		t.Fatalf("dynamic control target window did not rotate: first=%#v second=%#v", first, second)
	}
}

func TestDynamicControlTargetFanoutEnvOverridesConfig(t *testing.T) {
	t.Setenv("TRUSTIX_DYNAMIC_CONTROL_TARGET_FANOUT", "1")
	fanout := 4
	daemon := &Daemon{
		desired: config.Desired{ControlFabric: config.ControlFabricConfig{DynamicControlFanout: &fanout}},
	}
	if got := daemon.dynamicControlTargetFanout(); got != 1 {
		t.Fatalf("dynamic control fanout = %d, want env override 1", got)
	}
}

func TestDynamicControlTargetFanoutProfileDefaults(t *testing.T) {
	t.Setenv("TRUSTIX_DYNAMIC_CONTROL_TARGET_FANOUT", "")
	tests := []struct {
		name    string
		profile string
		want    int
	}{
		{name: "default", profile: "", want: defaultDynamicControlTargetFanout},
		{name: "small", profile: "small", want: 0},
		{name: "edge", profile: "edge", want: edgeDynamicControlTargetFanout},
		{name: "reflector", profile: "reflector", want: reflectorControlTargetFanout},
		{name: "route-reflector-normalized", profile: "route-reflector", want: reflectorControlTargetFanout},
		{name: "core", profile: "core", want: coreDynamicControlTargetFanout},
		{name: "authority", profile: "authority", want: coreDynamicControlTargetFanout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &Daemon{
				desired: config.Desired{ControlFabric: config.ControlFabricConfig{Profile: tt.profile}},
			}
			if got := daemon.dynamicControlTargetFanout(); got != tt.want {
				t.Fatalf("dynamic control fanout = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestRoutePolicyRejectsDynamicTransitImportWhenDisabled(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	disabled := false
	desiredA := desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24")
	desiredA.RoutePolicy.ImportTransitRoutes = &disabled
	daemonA := newMembershipTestDaemon(t, desiredA, 1)
	daemonB := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-b", "127.0.0.1:7002", "https://127.0.0.1:9444", "10.0.1.0/24"), 2)
	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 3)
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-b", "10.0.1.0/24")
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-c", "10.0.2.0/24")
	authorizeMembershipTestIX(t, daemonB, pkiSet, "ix-a", "10.0.0.0/24")
	authorizeMembershipTestIX(t, daemonB, pkiSet, "ix-c", "10.0.2.0/24")
	if err := daemonA.refreshLocalAdvertisement(); err != nil {
		t.Fatalf("refresh ix-a advertisement: %v", err)
	}
	if err := daemonB.refreshLocalAdvertisement(); err != nil {
		t.Fatalf("refresh ix-b advertisement: %v", err)
	}
	if err := daemonC.refreshLocalAdvertisement(); err != nil {
		t.Fatalf("refresh ix-c advertisement: %v", err)
	}

	adA, err := daemonA.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-a advertisement: %v", err)
	}
	adC, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if _, err := daemonB.mergeAdvertisement(adA, "test-a"); err != nil {
		t.Fatalf("merge ix-a into ix-b: %v", err)
	}
	if _, err := daemonB.mergeAdvertisement(adC, "test-c"); err != nil {
		t.Fatalf("merge ix-c into ix-b: %v", err)
	}

	server := httptest.NewServer(daemonB.peerHandler())
	defer server.Close()
	targetB := controlTarget{ID: "ix-b", ControlAPI: server.URL}
	advertisements, err := daemonA.fetchMembers(context.Background(), targetB)
	if err != nil {
		t.Fatalf("fetch ix-b members: %v", err)
	}
	for _, advertisement := range advertisements {
		if _, err := daemonA.mergeAdvertisementFromControlTarget(advertisement, targetB); err != nil {
			t.Fatalf("merge gossiped advertisement %q: %v", advertisement.IXID, err)
		}
	}
	if _, ok := routeByPrefix(daemonA.runtimeRoutes(), "10.0.1.0/24"); !ok {
		t.Fatalf("ix-a did not learn direct ix-b route: %#v", daemonA.runtimeRoutes())
	}
	if route, ok := routeByPrefix(daemonA.runtimeRoutes(), "10.0.2.0/24"); ok {
		t.Fatalf("ix-a installed disabled transit route: %#v", route)
	}
	status := daemonA.runtimeRoutePolicyStatus()
	if !hasRoutePolicyDecision(status.Decisions, "import", "ix-c", "10.0.2.0/24", "reject", "transit_import_disabled") {
		t.Fatalf("route policy decisions missing transit disabled reject: %#v", status.Decisions)
	}
}

func TestMembershipRejectsAnnouncedPrefixPathLoop(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 3)
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-c", "10.0.2.0/24")

	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if len(advertisement.AnnouncedPrefixes) == 0 {
		t.Fatal("ix-c advertisement has no announced prefixes")
	}
	advertisement.AnnouncedPrefixes[0].Path = []core.IXID{"ix-c", "ix-a"}
	resignAdvertisement(t, &advertisement, pkiSet.ixKeys["ix-c"])
	if _, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap"); err != nil {
		t.Fatalf("merge ix-c advertisement: %v", err)
	}
	if route, ok := routeByPrefix(daemonA.runtimeRoutes(), "10.0.2.0/24"); ok {
		t.Fatalf("path-looped route was installed: %#v", route)
	}
	status := daemonA.runtimeRoutePolicyStatus()
	if !hasRoutePolicyDecision(status.Decisions, "import", "ix-c", "10.0.2.0/24", "reject", "path_loop") {
		t.Fatalf("route policy decisions missing path_loop reject: %#v", status.Decisions)
	}
}

func TestIndirectGossipDoesNotKeepMemberAlive(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	daemonB := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-b", "127.0.0.1:7002", "https://127.0.0.1:9444", "10.0.1.0/24"), 2)
	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 3)
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-c", "10.0.2.0/24")
	authorizeMembershipTestIX(t, daemonB, pkiSet, "ix-c", "10.0.2.0/24")

	adC, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if _, err := daemonB.mergeAdvertisement(adC, "test-c"); err != nil {
		t.Fatalf("merge ix-c into ix-b: %v", err)
	}

	targetB := controlTarget{ID: "ix-b", ControlAPI: "https://127.0.0.1:9444"}
	if _, err := daemonA.mergeAdvertisementFromControlTarget(adC, targetB); err != nil {
		t.Fatalf("merge indirect ix-c into ix-a: %v", err)
	}
	daemonA.membershipMu.Lock()
	firstSeen := daemonA.members["ix-c"].LastSeen
	daemonA.membershipMu.Unlock()

	time.Sleep(time.Millisecond)
	if _, err := daemonA.mergeAdvertisementFromControlTarget(adC, targetB); err != nil {
		t.Fatalf("merge repeated indirect ix-c into ix-a: %v", err)
	}
	daemonA.membershipMu.RLock()
	record := daemonA.members["ix-c"]
	daemonA.membershipMu.RUnlock()
	if !record.LastSeen.Equal(firstSeen) {
		t.Fatalf("indirect gossip refreshed LastSeen from %s to %s", firstSeen, record.LastSeen)
	}
	if record.Direct {
		t.Fatal("indirect gossip marked ix-c as directly observed")
	}

	daemonA.membershipMu.Lock()
	record.LastSeen = time.Now().Add(-memberRecordTTL - time.Second)
	daemonA.members["ix-c"] = record
	daemonA.membershipMu.Unlock()
	if !daemonA.pruneExpiredMembers() {
		t.Fatal("expired indirectly learned member was not pruned")
	}
	if _, ok := daemonA.dynamicPeerConfig("ix-c"); ok {
		t.Fatal("expired indirectly learned member still exists")
	}
}

func TestDirectObservationOfGossipedMemberRefreshesRuntimeNextHop(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desiredA := desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24")
	desiredA.Peers = []config.PeerConfig{{
		ID:              "ix-b",
		Domain:          "lab.local",
		ControlAPI:      "https://127.0.0.1:9444",
		AllowedPrefixes: []core.Prefix{"10.0.1.0/24"},
		Endpoints: []config.EndpointConfig{{
			Name:      "ix-b-udp",
			Mode:      config.EndpointModeActive,
			Address:   "127.0.0.1:7002",
			Transport: "udp",
			Enabled:   true,
		}},
	}}
	daemonA := newMembershipTestDaemon(t, desiredA, 1)
	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 3)
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-c", "10.0.2.0/24")

	adC, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	changed, err := daemonA.mergeAdvertisementFromControlTarget(adC, controlTarget{ID: "ix-b", ControlAPI: "https://127.0.0.1:9444"})
	if err != nil {
		t.Fatalf("merge indirect ix-c into ix-a: %v", err)
	}
	if !changed {
		t.Fatal("initial indirect merge did not report changed")
	}
	route, ok := routeByPrefix(daemonA.runtimeRoutes(), "10.0.2.0/24")
	if !ok || route.NextHop != "ix-b" || route.Source != "dynamic_transit" {
		t.Fatalf("indirect route = %#v ok=%t, want next hop ix-b dynamic_transit", route, ok)
	}
	status := daemonA.runtimeRoutePolicyStatus()
	if !hasRouteCandidate(status.Candidates, "10.0.2.0/24", "ix-c", "ix-b", "dynamic_transit", "accept", true) {
		t.Fatalf("route candidates missing selected indirect path: %#v", status.Candidates)
	}

	changed, err = daemonA.mergeAdvertisementFromControlTarget(adC, controlTarget{ID: "ix-c", ControlAPI: "https://127.0.0.1:9445"})
	if err != nil {
		t.Fatalf("merge direct ix-c into ix-a: %v", err)
	}
	if !changed {
		t.Fatal("direct observation did not report runtime route change")
	}
	route, ok = routeByPrefix(daemonA.runtimeRoutes(), "10.0.2.0/24")
	if !ok || route.NextHop != "ix-c" || route.Source != "dynamic" {
		t.Fatalf("direct route = %#v ok=%t, want next hop ix-c dynamic", route, ok)
	}
}

func TestDirectControlTargetRefreshesGossipedMember(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 3)
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-c", "10.0.2.0/24")

	adC, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if _, err := daemonA.mergeAdvertisementFromControlTarget(adC, controlTarget{ID: "ix-b", ControlAPI: "https://127.0.0.1:9444"}); err != nil {
		t.Fatalf("merge indirect ix-c into ix-a: %v", err)
	}
	daemonA.membershipMu.Lock()
	record := daemonA.members["ix-c"]
	record.LastSeen = time.Now().Add(-memberRecordTTL + time.Second)
	daemonA.members["ix-c"] = record
	oldSeen := record.LastSeen
	daemonA.membershipMu.Unlock()

	time.Sleep(time.Millisecond)
	if _, err := daemonA.mergeAdvertisementFromControlTarget(adC, controlTarget{ID: "ix-c", ControlAPI: "https://127.0.0.1:9445"}); err != nil {
		t.Fatalf("merge direct ix-c into ix-a: %v", err)
	}
	daemonA.membershipMu.RLock()
	record = daemonA.members["ix-c"]
	daemonA.membershipMu.RUnlock()
	if !record.LastSeen.After(oldSeen) {
		t.Fatalf("direct control target did not refresh LastSeen: old=%s new=%s", oldSeen, record.LastSeen)
	}
	if !record.Direct {
		t.Fatal("direct control target did not mark ix-c as directly observed")
	}
}

func TestControlMembersResponseOnlyPropagatesDirectLiveMembers(t *testing.T) {
	now := time.Now().UTC()
	daemon := &Daemon{
		localAd: advertisementResponse{IXID: "ix-a", DomainID: "lab.local"},
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-a"},
		},
		members: map[core.IXID]memberRecord{
			"ix-a": {Advertisement: advertisementResponse{IXID: "ix-a", DomainID: "lab.local"}, LastSeen: now, Direct: true},
			"ix-b": {Advertisement: advertisementResponse{IXID: "ix-b", DomainID: "lab.local"}, LastSeen: now, Direct: true},
			"ix-c": {Advertisement: advertisementResponse{IXID: "ix-c", DomainID: "lab.local"}, LastSeen: now, Direct: false},
			"ix-d": {Advertisement: advertisementResponse{IXID: "ix-d", DomainID: "lab.local"}, LastSeen: now.Add(-memberRecordTTL - time.Second), Direct: true},
		},
	}

	response := daemon.controlMembersResponse(controlTarget{}, controlMembersPageOptions{})
	var got []string
	for _, member := range response.Members {
		got = append(got, member.IXID)
	}
	if strings.Join(got, ",") != "ix-a,ix-b" {
		t.Fatalf("control members = %#v, want local plus direct live member only", got)
	}
}

func TestPersistedMembershipKeepsIndirectMemberIndirect(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	daemonA.cfg.DataDir = t.TempDir()
	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 3)
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-c", "10.0.2.0/24")

	adC, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if _, err := daemonA.mergeAdvertisementFromControlTarget(adC, controlTarget{ID: "ix-b", ControlAPI: "https://127.0.0.1:9444"}); err != nil {
		t.Fatalf("merge indirect ix-c into ix-a: %v", err)
	}

	restarted := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	restarted.cfg.DataDir = daemonA.cfg.DataDir
	restarted.store = daemonA.store
	restarted.head = daemonA.head
	if err := restarted.loadPersistedMembers(); err != nil {
		t.Fatalf("load persisted members: %v", err)
	}
	restarted.membershipMu.RLock()
	record, ok := restarted.members["ix-c"]
	restarted.membershipMu.RUnlock()
	if !ok {
		t.Fatal("persisted indirect member was not restored")
	}
	if record.Direct {
		t.Fatal("persisted indirect member was restored as direct")
	}
}

func TestStaticTransitRouteOwnsPrefixViaDifferentNextHop(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desiredA := desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24")
	desiredA.Peers = []config.PeerConfig{
		{
			ID:     "ix-b",
			Domain: "lab.local",
			Endpoints: []config.EndpointConfig{{
				Name:      "ix-b-udp",
				Address:   "127.0.0.1:7002",
				Transport: "udp",
			}},
			AllowedPrefixes: []core.Prefix{"10.0.1.0/24"},
		},
		{
			ID:              "ix-c",
			Domain:          "lab.local",
			AllowedPrefixes: []core.Prefix{"10.0.2.0/24"},
		},
	}
	desiredA.Routes = []config.RouteConfig{{
		Prefix:   "10.0.2.0/24",
		Owner:    "ix-c",
		NextHop:  "ix-b",
		Endpoint: "ix-b-udp",
		Metric:   50,
	}}
	daemonA := newMembershipTestDaemon(t, desiredA, 1)
	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 2)
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-c", "10.0.2.0/24")

	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if _, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap"); err != nil {
		t.Fatalf("merge ix-c advertisement: %v", err)
	}

	route, ok := routeByPrefix(daemonA.runtimeRoutes(), "10.0.2.0/24")
	if !ok {
		t.Fatalf("static transit route was not present: %#v", daemonA.runtimeRoutes())
	}
	if route.Owner != "ix-c" || route.NextHop != "ix-b" || route.Endpoint != "ix-b-udp" || route.Source != "static" {
		t.Fatalf("transit route = %#v", route)
	}
	status := daemonA.runtimeRoutePolicyStatus()
	if hasRoutePolicyDecision(status.Decisions, "import", "ix-c", "10.0.2.0/24", "reject", "duplicate_prefix") {
		t.Fatalf("static-shadowed dynamic route should not be reported as a duplicate reject: %#v", status.Decisions)
	}
	if !hasRoutePolicyDecision(status.Decisions, "import", "ix-c", "10.0.2.0/24", "shadow", "shadowed_by_static") {
		t.Fatalf("dynamic route was not reported as shadowed by static route: %#v", status.Decisions)
	}
	if !hasRouteCandidate(status.Candidates, "10.0.2.0/24", "ix-c", "ix-c", "dynamic", "shadow", false) {
		t.Fatalf("route candidates missing shadowed dynamic route: %#v", status.Candidates)
	}
}

func TestRoutesFromConfigPreservesRouteKind(t *testing.T) {
	desired := config.Desired{
		IX: config.IXConfig{ID: "ix-a"},
		Routes: []config.RouteConfig{
			{Prefix: "10.66.0.0/16", Kind: routing.RouteBlackhole, Metric: 10},
			{Prefix: "10.77.0.0/16", Kind: routing.RouteReject, Metric: 20},
			{Prefix: "10.88.0.0/16", Kind: routing.RouteLocal, Owner: "ix-b", Metric: 30},
		},
	}
	routes := routesFromConfig(desired)
	if len(routes) != 3 {
		t.Fatalf("routes = %d, want 3", len(routes))
	}
	if routes[0].Kind != routing.RouteBlackhole || routes[0].NextHop != "" {
		t.Fatalf("blackhole route = %#v", routes[0])
	}
	if routes[1].Kind != routing.RouteReject {
		t.Fatalf("reject route = %#v", routes[1])
	}
	if routes[2].Kind != routing.RouteLocal || routes[2].NextHop != "ix-a" || routes[2].Owner != "ix-b" {
		t.Fatalf("local route = %#v", routes[2])
	}
}

func TestRuntimeRoutesIncludeAdvertisedLocalLANRoute(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)

	route, ok := routeByPrefix(daemonA.runtimeRoutes(), "10.0.0.0/24")
	if !ok {
		t.Fatalf("runtime routes do not include local LAN prefix: %#v", daemonA.runtimeRoutes())
	}
	if route.Kind != routing.RouteLocal || route.Owner != "ix-a" || route.NextHop != "ix-a" || route.Source != "local_lan" {
		t.Fatalf("local LAN route = %#v", route)
	}
}

func TestRuntimeRoutesKeepExplicitRouteForAdvertisedLANPrefix(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24")
	desired.Routes = []config.RouteConfig{{
		Prefix: "10.0.0.0/24",
		Kind:   routing.RouteBlackhole,
		Metric: 50,
		Policy: "maintenance",
	}}
	daemonA := newMembershipTestDaemon(t, desired, 1)

	route, ok := routeByPrefix(daemonA.runtimeRoutes(), "10.0.0.0/24")
	if !ok {
		t.Fatalf("runtime routes do not include explicit LAN prefix: %#v", daemonA.runtimeRoutes())
	}
	if route.Kind != routing.RouteBlackhole || route.Source != "static" || route.Policy != "maintenance" {
		t.Fatalf("explicit route was overwritten by local LAN route: %#v", route)
	}
}

func TestMergeAdvertisementRejectsUnauthorizedPrefix(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.3.0/24"), 2)

	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if _, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap"); err == nil {
		t.Fatal("expected unauthorized advertisement to be rejected")
	}
}

func TestMergeAdvertisementRejectsRevokedIXCertificate(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desiredA := desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24")
	desiredA.Trust.RevokedCertFingerprints = []string{fingerprintForCertPath(t, pkiSet.ixCerts["ix-c"])}
	daemonA := newMembershipTestDaemon(t, desiredA, 1)
	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 2)

	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if _, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap"); err == nil {
		t.Fatal("expected revoked IX advertisement to be rejected")
	}
}

func TestMergeAdvertisementRejectsRevokedRouteAuthorization(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desiredA := desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24")
	desiredA.Trust.RevokedCertFingerprints = []string{fingerprintForCertPath(t, pkiSet.routeCerts["ix-c"])}
	daemonA := newMembershipTestDaemon(t, desiredA, 1)
	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 2)

	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if _, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap"); err == nil {
		t.Fatal("expected revoked route authorization advertisement to be rejected")
	}
}

func TestVerifyLocalRouteAuthorizationsRejectsRevokedCertificate(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24")
	desired.Trust.RevokedCertFingerprints = []string{fingerprintForCertPath(t, pkiSet.routeCerts["ix-a"])}

	if err := verifyLocalRouteAuthorizations(desired); err == nil {
		t.Fatal("expected revoked local route authorization to be rejected")
	}
}

func TestMembershipPersistenceAndPrune(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	daemonA.cfg.DataDir = t.TempDir()
	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 2)
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-c", "10.0.2.0/24")
	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if changed, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap"); err != nil || !changed {
		t.Fatalf("merge ix-c advertisement changed=%t err=%v", changed, err)
	}

	restarted := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	restarted.cfg.DataDir = daemonA.cfg.DataDir
	restarted.store = daemonA.store
	restarted.head = daemonA.head
	if err := restarted.loadPersistedMembers(); err != nil {
		t.Fatalf("load persisted members: %v", err)
	}
	if _, ok := restarted.dynamicPeerConfig("ix-c"); !ok {
		t.Fatal("persisted dynamic peer ix-c was not restored")
	}

	restarted.membershipMu.Lock()
	record := restarted.members["ix-c"]
	record.LastSeen = time.Now().Add(-memberRecordTTL - time.Second)
	restarted.members["ix-c"] = record
	restarted.membershipMu.Unlock()
	if !restarted.pruneExpiredMembers() {
		t.Fatal("expired member was not pruned")
	}
	if _, ok := restarted.dynamicPeerConfig("ix-c"); ok {
		t.Fatal("expired dynamic peer ix-c still exists")
	}
}

func TestPruneExpiredStaticMemberKeepsDataSessions(t *testing.T) {
	peer := testPeer()
	key := dataSessionKey{
		Peer:       peer.ID,
		Endpoint:   peer.Endpoints[0].Name,
		Transport:  transport.Protocol(peer.Endpoints[0].Transport),
		Address:    peer.Endpoints[0].Address,
		Encryption: "plaintext",
	}
	session := &recordingSession{}
	runtime := &dataSessionRuntime{key: key, session: session}
	daemon := &Daemon{
		cfg: Config{DataDir: t.TempDir()},
		desired: config.Desired{
			IX:     config.IXConfig{ID: core.IXID("ix-a")},
			Domain: config.DomainConfig{ID: peer.Domain},
			Peers:  []config.PeerConfig{peer},
		},
		members: map[core.IXID]memberRecord{
			peer.ID: {
				Advertisement: advertisementResponse{IXID: string(peer.ID), DomainID: string(peer.Domain)},
				LastSeen:      time.Now().UTC().Add(-memberRecordTTL - time.Second),
				Direct:        true,
			},
		},
		dataSessions: map[dataSessionKey]transport.Session{
			key: session,
		},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{
			key: runtime,
		},
	}

	if !daemon.pruneExpiredMembers() {
		t.Fatal("expired dynamic overlay for static peer was not pruned")
	}
	if _, ok := daemon.members[peer.ID]; ok {
		t.Fatal("expired dynamic overlay for static peer still exists")
	}
	if got := daemon.dataSessions[key]; got != session {
		t.Fatalf("static peer session = %#v, want existing session", got)
	}
	if session.closed {
		t.Fatal("static peer session was closed by dynamic member pruning")
	}
	if counters := daemon.dataStats.snapshot(); counters.StaleSessionsDropped != 0 {
		t.Fatalf("stale sessions dropped = %d, want 0", counters.StaleSessionsDropped)
	}
}

func TestNewerAdvertisementCanWithdrawRoutes(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 2)
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-c", "10.0.2.0/24")
	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if _, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap"); err != nil {
		t.Fatalf("merge ix-c advertisement: %v", err)
	}
	withdraw := advertisement
	withdraw.ConfigHead.Seq++
	withdraw.LANPrefixes = nil
	withdraw.AnnouncedPrefixes = nil
	withdraw.RouteAuthorizations = nil
	withdraw.IssuedAt = time.Now().UTC()
	signingBytes, err := advertisementSigningBytes(withdraw)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := pki.LoadBundle(daemonC.desired.IX.CertPath, daemonC.desired.IX.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	withdraw.Signature, err = pki.Sign(bundle.Key, signingBytes)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := daemonA.mergeAdvertisement(withdraw, "test-bootstrap")
	if err != nil {
		t.Fatalf("merge withdraw advertisement: %v", err)
	}
	if !changed {
		t.Fatal("withdraw advertisement did not update member")
	}
	for _, route := range daemonA.runtimeRoutes() {
		if route.NextHop == "ix-c" {
			t.Fatalf("withdrawn ix-c route still exists: %#v", route)
		}
	}
}

func TestPeerHandlerDoesNotAllowMemberDelete(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 2)
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-c", "10.0.2.0/24")
	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if changed, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap"); err != nil || !changed {
		t.Fatalf("merge ix-c advertisement changed=%t err=%v", changed, err)
	}

	request := httptest.NewRequest(http.MethodDelete, "/v1/control/members/ix-c", nil)
	recorder := httptest.NewRecorder()
	daemonA.peerHandler().ServeHTTP(recorder, request)

	if recorder.Code >= 200 && recorder.Code < 300 {
		t.Fatalf("peer handler delete status = %d, want non-2xx", recorder.Code)
	}
	if _, ok := daemonA.dynamicPeerConfig("ix-c"); !ok {
		t.Fatal("peer handler deleted dynamic member")
	}
}

func TestAdvertisementRouteOnlyUpdateKeepsDataSession(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 2)
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-c", "10.0.2.0/24")
	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if _, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap"); err != nil {
		t.Fatalf("merge ix-c advertisement: %v", err)
	}
	session := &recordingSession{}
	key := dataSessionKey{
		Peer:       "ix-c",
		Endpoint:   "ix-c-udp",
		Transport:  "udp",
		Address:    "127.0.0.1:7003",
		Encryption: "secure",
	}
	daemonA.dataSessions[key] = session
	daemonA.dataSessionState[key] = &dataSessionRuntime{key: key, session: session}

	updated := advertisement
	updated.ConfigHead.Seq++
	updated.Management = &managementAdvertisement{HostAPI: &hostAPIAdvertisement{
		IP:        "127.0.0.1",
		Port:      "9445",
		ReadAuth:  true,
		WriteAuth: true,
	}}
	updated.IssuedAt = time.Now().UTC()
	signingBytes, err := advertisementSigningBytes(updated)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := pki.LoadBundle(daemonC.desired.IX.CertPath, daemonC.desired.IX.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	updated.Signature, err = pki.Sign(bundle.Key, signingBytes)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := daemonA.mergeAdvertisement(updated, "test-bootstrap")
	if err != nil {
		t.Fatalf("merge updated advertisement: %v", err)
	}
	if !changed {
		t.Fatal("updated advertisement did not report a dynamic member change")
	}
	if session.closed {
		t.Fatal("route-only advertisement update closed an existing data session")
	}
	if daemonA.dataSessions[key] != session {
		t.Fatal("route-only advertisement update removed an existing data session")
	}
}

func TestAdvertisementEndpointUpdateClosesDataSession(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 2)
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-c", "10.0.2.0/24")
	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if _, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap"); err != nil {
		t.Fatalf("merge ix-c advertisement: %v", err)
	}
	session := &recordingSession{}
	key := dataSessionKey{
		Peer:       "ix-c",
		Endpoint:   "ix-c-udp",
		Transport:  "udp",
		Address:    "127.0.0.1:7003",
		Encryption: "secure",
	}
	daemonA.dataSessions[key] = session
	daemonA.dataSessionState[key] = &dataSessionRuntime{key: key, session: session}

	updatedDesired := desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7999", "https://127.0.0.1:9445", "10.0.2.0/24")
	updatedDaemon := newMembershipTestDaemon(t, updatedDesired, 3)
	updated, err := updatedDaemon.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build updated ix-c advertisement: %v", err)
	}
	if _, err := daemonA.mergeAdvertisement(updated, "test-bootstrap"); err != nil {
		t.Fatalf("merge endpoint update advertisement: %v", err)
	}
	if !session.closed {
		t.Fatal("endpoint advertisement update did not close an existing data session")
	}
	if _, ok := daemonA.dataSessions[key]; ok {
		t.Fatal("endpoint advertisement update kept stale data session")
	}
}

func TestAdvertisementEndpointPriorityUpdateClosesDataSession(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	daemonA := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24"), 1)
	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 2)
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-c", "10.0.2.0/24")
	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	if _, err := daemonA.mergeAdvertisement(advertisement, "test-bootstrap"); err != nil {
		t.Fatalf("merge ix-c advertisement: %v", err)
	}
	session := &recordingSession{}
	key := dataSessionKey{
		Peer:       "ix-c",
		Endpoint:   "ix-c-udp",
		Transport:  "udp",
		Address:    "127.0.0.1:7003",
		Encryption: "secure",
	}
	daemonA.dataSessions[key] = session
	daemonA.dataSessionState[key] = &dataSessionRuntime{key: key, session: session}

	updatedDesired := desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24")
	updatedDesired.Endpoints[0].Priority = 100
	updatedDaemon := newMembershipTestDaemon(t, updatedDesired, 3)
	updated, err := updatedDaemon.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build updated ix-c advertisement: %v", err)
	}
	if _, err := daemonA.mergeAdvertisement(updated, "test-bootstrap"); err != nil {
		t.Fatalf("merge endpoint priority update advertisement: %v", err)
	}
	if !session.closed {
		t.Fatal("endpoint priority advertisement update did not close an existing data session")
	}
}

func resignAdvertisement(t *testing.T, advertisement *advertisementResponse, keyPath string) {
	t.Helper()
	key, _, err := pki.LoadPrivateKey(keyPath)
	if err != nil {
		t.Fatalf("load signing key: %v", err)
	}
	signingBytes, err := advertisementSigningBytes(*advertisement)
	if err != nil {
		t.Fatalf("advertisement signing bytes: %v", err)
	}
	signature, err := pki.Sign(key, signingBytes)
	if err != nil {
		t.Fatalf("sign advertisement: %v", err)
	}
	advertisement.Signature = signature
}

func routeByPrefix(routes []routing.Route, prefix core.Prefix) (routing.Route, bool) {
	for _, route := range routes {
		if route.Prefix == prefix {
			return route, true
		}
	}
	return routing.Route{}, false
}

func hasRoutePolicyDecision(decisions []routePolicyDecision, direction string, ixID core.IXID, prefix core.Prefix, action, reason string) bool {
	for _, decision := range decisions {
		if decision.Direction == direction &&
			decision.IXID == ixID &&
			decision.Prefix == prefix &&
			decision.Action == action &&
			decision.Reason == reason {
			return true
		}
	}
	return false
}

func hasRouteCandidate(candidates []routeCandidate, prefix core.Prefix, owner core.IXID, nextHop core.IXID, source string, action string, selected bool) bool {
	for _, candidate := range candidates {
		if candidate.Prefix == prefix &&
			candidate.Owner == owner &&
			candidate.NextHop == nextHop &&
			candidate.Source == source &&
			candidate.Action == action &&
			candidate.Selected == selected {
			return true
		}
	}
	return false
}

func countDynamicControlTargets(targets []controlTarget) int {
	count := 0
	for _, target := range targets {
		if strings.HasPrefix(string(target.ID), "ix-dyn-") {
			count++
		}
	}
	return count
}

func hasControlTarget(targets []controlTarget, ixID core.IXID) bool {
	for _, target := range targets {
		if target.ID == ixID {
			return true
		}
	}
	return false
}

func dynamicControlTargetIDs(targets []controlTarget) string {
	ids := make([]string, 0, len(targets))
	for _, target := range targets {
		if strings.HasPrefix(string(target.ID), "ix-dyn-") {
			ids = append(ids, string(target.ID))
		}
	}
	sort.Strings(ids)
	return strings.Join(ids, ",")
}

type switchablePeerServer struct {
	server  *httptest.Server
	online  atomic.Bool
	current atomic.Value
}

func newSwitchablePeerServer(t *testing.T, daemon *Daemon) *switchablePeerServer {
	t.Helper()
	out := &switchablePeerServer{}
	out.online.Store(true)
	out.current.Store(daemon)
	out.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !out.online.Load() {
			http.Error(w, "peer offline", http.StatusServiceUnavailable)
			return
		}
		current, _ := out.current.Load().(*Daemon)
		if current == nil {
			http.Error(w, "peer unavailable", http.StatusServiceUnavailable)
			return
		}
		current.peerHandler().ServeHTTP(w, r)
	}))
	return out
}

func (server *switchablePeerServer) URL() string {
	return server.server.URL
}

func (server *switchablePeerServer) Close() {
	server.server.Close()
}

func (server *switchablePeerServer) SetOnline(online bool) {
	server.online.Store(online)
}

func (server *switchablePeerServer) SetDaemon(daemon *Daemon) {
	server.current.Store(daemon)
}

func configureRestartMembershipTopology(t *testing.T, pkiSet membershipPKI, daemonA, daemonB, daemonC *Daemon, urlA, urlB, urlC string) {
	t.Helper()
	daemonA.desired.IX.ControlAPI = urlA
	daemonB.desired.IX.ControlAPI = urlB
	daemonC.desired.IX.ControlAPI = urlC
	daemonB.desired.Bootstrap.Peers = []config.BootstrapPeerConfig{{
		ID:         "ix-a",
		Domain:     "lab.local",
		ControlAPI: urlA,
	}}
	daemonC.desired.Bootstrap.Peers = []config.BootstrapPeerConfig{{
		ID:         "ix-a",
		Domain:     "lab.local",
		ControlAPI: urlA,
	}}
	for _, daemon := range []*Daemon{daemonA, daemonB, daemonC} {
		authorizeMembershipTestIXWithControlAPI(t, daemon, pkiSet, "ix-a", urlA, "10.0.0.0/24")
		authorizeMembershipTestIXWithControlAPI(t, daemon, pkiSet, "ix-b", urlB, "10.0.1.0/24")
		authorizeMembershipTestIXWithControlAPI(t, daemon, pkiSet, "ix-c", urlC, "10.0.2.0/24")
		if err := daemon.refreshLocalAdvertisement(); err != nil {
			t.Fatalf("refresh local advertisement for %s: %v", daemon.desired.IX.ID, err)
		}
	}
}

func restartMembershipTestDaemon(t *testing.T, previous *Daemon) *Daemon {
	t.Helper()
	restarted := newMembershipTestDaemon(t, previous.desired, previous.head.Seq)
	restarted.cfg.DataDir = previous.cfg.DataDir
	restarted.logPath = previous.logPath
	if previous.logPath != "" && previous.logPath != "memory" {
		store, err := configlog.NewFileStore(previous.logPath)
		if err != nil {
			t.Fatalf("reopen config log for %s: %v", restarted.desired.IX.ID, err)
		}
		restarted.store = store
		head, err := store.Head()
		if err != nil {
			t.Fatalf("read reopened config log head for %s: %v", restarted.desired.IX.ID, err)
		}
		restarted.head = head
	} else {
		restarted.store = previous.store
		restarted.head = previous.head
	}
	if err := restarted.registerLocalConfigSigner(); err != nil {
		t.Fatalf("register restarted signer for %s: %v", restarted.desired.IX.ID, err)
	}
	if err := restarted.loadConfigSignerCache(); err != nil {
		t.Fatalf("load restarted signer cache for %s: %v", restarted.desired.IX.ID, err)
	}
	if err := restarted.loadPersistedMembers(); err != nil {
		t.Fatalf("load persisted members for %s: %v", restarted.desired.IX.ID, err)
	}
	if err := restarted.refreshLocalAdvertisement(); err != nil {
		t.Fatalf("refresh restarted local advertisement for %s: %v", restarted.desired.IX.ID, err)
	}
	if err := restarted.applyRuntimeDataplaneSnapshot(context.Background()); err != nil {
		t.Fatalf("apply restarted runtime snapshot for %s: %v", restarted.desired.IX.ID, err)
	}
	return restarted
}

func enableFileConfigLogForMembershipTest(t *testing.T, daemon *Daemon) {
	t.Helper()
	if daemon.cfg.DataDir == "" {
		daemon.cfg.DataDir = t.TempDir()
	}
	logPath := filepath.Join(daemon.cfg.DataDir, "config.log")
	store, err := configlog.NewFileStore(logPath)
	if err != nil {
		t.Fatalf("create config log for %s: %v", daemon.desired.IX.ID, err)
	}
	daemon.store = store
	daemon.logPath = logPath
	if err := daemon.registerLocalConfigSigner(); err != nil {
		t.Fatalf("register config signer for %s: %v", daemon.desired.IX.ID, err)
	}
	if err := daemon.ensureConfigGenesisEvent(daemon.desired); err != nil {
		t.Fatalf("append config genesis for %s: %v", daemon.desired.IX.ID, err)
	}
	head, err := store.Head()
	if err != nil {
		t.Fatalf("read config log head for %s: %v", daemon.desired.IX.ID, err)
	}
	daemon.head = head
}

func expirePersistedMembersForRestartTest(t *testing.T, daemons ...*Daemon) {
	t.Helper()
	expired := time.Now().UTC().Add(-memberRecordTTL - time.Second)
	for _, daemon := range daemons {
		daemon.membershipMu.Lock()
		for ixID, record := range daemon.members {
			if ixID == daemon.desired.IX.ID {
				continue
			}
			record.LastSeen = expired
			daemon.members[ixID] = record
		}
		daemon.membershipMu.Unlock()
		if err := daemon.persistMembers(); err != nil {
			t.Fatalf("persist expired members for %s: %v", daemon.desired.IX.ID, err)
		}
	}
}

func pollMembershipSet(ctx context.Context, daemonA, daemonB, daemonC *Daemon, rounds int) {
	for i := 0; i < rounds; i++ {
		daemonA.pollPeers(ctx)
		daemonB.pollPeers(ctx)
		daemonC.pollPeers(ctx)
	}
}

func assertAllIXDirectRoutes(t *testing.T, daemonA, daemonB, daemonC *Daemon) {
	t.Helper()
	assertDirectRoute(t, daemonA, "10.0.1.0/24", "ix-b")
	assertDirectRoute(t, daemonA, "10.0.2.0/24", "ix-c")
	assertDirectRoute(t, daemonB, "10.0.0.0/24", "ix-a")
	assertDirectRoute(t, daemonB, "10.0.2.0/24", "ix-c")
	assertDirectRoute(t, daemonC, "10.0.0.0/24", "ix-a")
	assertDirectRoute(t, daemonC, "10.0.1.0/24", "ix-b")
}

func assertDirectRoute(t *testing.T, daemon *Daemon, prefix core.Prefix, nextHop core.IXID) {
	t.Helper()
	route, ok := routeByPrefix(daemon.runtimeRoutes(), prefix)
	if !ok {
		t.Fatalf("%s missing route %s after restart/convergence: %#v", daemon.desired.IX.ID, prefix, daemon.runtimeRoutes())
	}
	if route.NextHop != nextHop || route.Owner != nextHop {
		t.Fatalf("%s route %s = %#v, want direct owner/next_hop %s", daemon.desired.IX.ID, prefix, route, nextHop)
	}
}

func newMembershipTestDaemon(t *testing.T, desired config.Desired, seq uint64) *Daemon {
	t.Helper()
	daemon, err := New(Config{DataplaneMode: "noop"}, WithDataplane(dataplane.NewNoopManager()))
	if err != nil {
		t.Fatalf("new daemon: %v", err)
	}
	daemon.desired = desired
	daemon.head = configlog.Head{Seq: seq, Hash: string(desired.IX.ID) + "-hash"}
	return daemon
}

func authorizeMembershipTestIX(t *testing.T, daemon *Daemon, pkiSet membershipPKI, ixID core.IXID, prefixes ...core.Prefix) {
	t.Helper()
	authorizeMembershipTestIXWithControlAPI(t, daemon, pkiSet, ixID, controlAPIForIX(ixID), prefixes...)
}

func authorizeMembershipTestIXWithControlAPI(t *testing.T, daemon *Daemon, pkiSet membershipPKI, ixID core.IXID, controlAPI string, prefixes ...core.Prefix) {
	t.Helper()
	if daemon.store == nil {
		daemon.store = configlog.NewMemoryStore()
		if err := daemon.store.Append(mustGenesisEvent(t, daemon)); err != nil {
			t.Fatalf("append test genesis: %v", err)
		}
	}
	head, err := daemon.store.Head()
	if err != nil {
		t.Fatalf("read test config head: %v", err)
	}
	if daemon.head.Seq != head.Seq || daemon.head.Hash != head.Hash {
		daemon.head = head
	}
	if len(prefixes) == 0 {
		if routeCert, ok := pkiSet.routeCerts[ixID]; ok {
			cert, _, err := pki.LoadCertificate(routeCert)
			if err != nil {
				t.Fatalf("load route cert for %s: %v", ixID, err)
			}
			for _, prefix := range pki.ParseMetadata(cert).Prefixes {
				prefixes = append(prefixes, core.Prefix(prefix))
			}
		}
	}
	admission, err := daemon.admissionPayloadFromApproveRequest(admissionApplyRequest{
		IXID:                  ixID,
		IXCertFingerprint:     fingerprintForCertPath(t, pkiSet.ixCerts[ixID]),
		AllowedPrefixes:       prefixes,
		RouteAuthFingerprints: []string{fingerprintForCertPath(t, pkiSet.routeCerts[ixID])},
		ControlAPI:            controlAPI,
	})
	if err != nil {
		t.Fatalf("build test admission for %s: %v", ixID, err)
	}
	event, plannedHead, changed, err := daemon.admissionEventIfChangedAtHead(admission, nil, head)
	if err != nil {
		t.Fatalf("build test admission event for %s: %v", ixID, err)
	}
	if !changed {
		return
	}
	if err := daemon.store.Append(*event); err != nil {
		t.Fatalf("append test admission for %s: %v", ixID, err)
	}
	daemon.head = plannedHead
}

func desiredForMembershipTest(pkiSet membershipPKI, ixID core.IXID, endpointAddress, controlAPI, prefix string) config.Desired {
	return config.Desired{
		Domain: config.DomainConfig{
			ID:         "lab.local",
			TrustRoots: pkiSet.trustRoots,
		},
		IX: config.IXConfig{
			ID:                  ixID,
			Domain:              "lab.local",
			CertPath:            pkiSet.ixCerts[ixID],
			KeyPath:             pkiSet.ixKeys[ixID],
			ControlAPI:          controlAPI,
			RouteAuthorizations: []string{pkiSet.routeCerts[ixID]},
		},
		LAN: config.LANConfig{
			Iface:     "br-lan-" + string(ixID),
			Gateway:   gatewayForPrefix(prefix),
			Advertise: []core.Prefix{core.Prefix(prefix)},
			Mode:      config.LANModeRouted,
		},
		Endpoints: []config.EndpointConfig{
			{
				Name:      core.EndpointID(string(ixID) + "-udp"),
				Mode:      config.EndpointModePassive,
				Listen:    endpointAddress,
				Address:   endpointAddress,
				Transport: "udp",
				Enabled:   true,
			},
		},
	}
}

func gatewayForPrefix(prefix string) string {
	switch prefix {
	case "10.0.0.0/24":
		return "10.0.0.1/24"
	case "10.0.1.0/24":
		return "10.0.1.1/24"
	case "10.0.2.0/24":
		return "10.0.2.1/24"
	case "10.0.3.0/24":
		return "10.0.3.1/24"
	default:
		return ""
	}
}

func buildMembershipPKI(t *testing.T) membershipPKI {
	t.Helper()
	out := t.TempDir()
	root, err := pki.NewRoot("TrustIX Test Root", 1)
	if err != nil {
		t.Fatalf("new root: %v", err)
	}
	if err := pki.WriteBundle(out, "root-ca", root, true); err != nil {
		t.Fatalf("write root: %v", err)
	}
	domainCA, err := pki.Issue(root, pki.IssueRequest{
		CommonName: "TrustIX Test Domain CA",
		Role:       pki.RoleDomainCA,
		Domain:     "lab.local",
		IsCA:       true,
		NotAfter:   time.Now().AddDate(1, 0, 0),
	})
	if err != nil {
		t.Fatalf("issue domain ca: %v", err)
	}
	if err := pki.WriteBundle(out, "domain-ca", domainCA, true); err != nil {
		t.Fatalf("write domain ca: %v", err)
	}
	configCA, err := pki.Issue(domainCA, pki.IssueRequest{
		CommonName: "TrustIX Test Config CA",
		Role:       pki.RoleDomainConfigCA,
		Domain:     "lab.local",
		IsCA:       true,
		NotAfter:   time.Now().AddDate(1, 0, 0),
	})
	if err != nil {
		t.Fatalf("issue config ca: %v", err)
	}
	if err := pki.WriteBundle(out, "config-ca", configCA, true); err != nil {
		t.Fatalf("write config ca: %v", err)
	}
	adminCert, err := pki.Issue(configCA, pki.IssueRequest{
		CommonName: "TrustIX Test Admin",
		Role:       pki.RoleAdmin,
		Domain:     "lab.local",
		NotAfter:   time.Now().AddDate(1, 0, 0),
	})
	if err != nil {
		t.Fatalf("issue admin cert: %v", err)
	}
	if err := pki.WriteBundle(out, "admin-1", adminCert, true); err != nil {
		t.Fatalf("write admin cert: %v", err)
	}
	admin2Cert, err := pki.Issue(configCA, pki.IssueRequest{
		CommonName: "TrustIX Test Admin 2",
		Role:       pki.RoleAdmin,
		Domain:     "lab.local",
		NotAfter:   time.Now().AddDate(1, 0, 0),
	})
	if err != nil {
		t.Fatalf("issue admin 2 cert: %v", err)
	}
	if err := pki.WriteBundle(out, "admin-2", admin2Cert, true); err != nil {
		t.Fatalf("write admin 2 cert: %v", err)
	}

	result := membershipPKI{
		trustRoots: []string{
			filepath.Join(out, "root-ca.pem"),
			filepath.Join(out, "domain-ca.pem"),
			filepath.Join(out, "config-ca.pem"),
		},
		ixCerts:    make(map[core.IXID]string),
		ixKeys:     make(map[core.IXID]string),
		adminCert:  filepath.Join(out, "admin-1.crt"),
		adminKey:   filepath.Join(out, "admin-1.key"),
		admin2Cert: filepath.Join(out, "admin-2.crt"),
		admin2Key:  filepath.Join(out, "admin-2.key"),
		routeCerts: make(map[core.IXID]string),
	}
	issueIXForMembershipTest(t, out, domainCA, configCA, result, "ix-a", "10.0.0.0/24")
	issueIXForMembershipTest(t, out, domainCA, configCA, result, "ix-b", "10.0.1.0/24")
	issueIXForMembershipTest(t, out, domainCA, configCA, result, "ix-c", "10.0.2.0/24")
	return result
}

func issueIXForMembershipTest(t *testing.T, out string, domainCA, configCA pki.Bundle, result membershipPKI, ixID core.IXID, prefix string) {
	t.Helper()
	ixCert, err := pki.Issue(domainCA, pki.IssueRequest{
		CommonName: "TrustIX Test " + string(ixID),
		Role:       pki.RoleIX,
		Domain:     "lab.local",
		IX:         string(ixID),
		NotAfter:   time.Now().AddDate(1, 0, 0),
	})
	if err != nil {
		t.Fatalf("issue %s cert: %v", ixID, err)
	}
	if err := pki.WriteBundle(out, string(ixID), ixCert, true); err != nil {
		t.Fatalf("write %s cert: %v", ixID, err)
	}
	routeCert, err := pki.Issue(configCA, pki.IssueRequest{
		CommonName: "TrustIX Test Route " + string(ixID),
		Role:       pki.RoleRouteAuthorization,
		Domain:     "lab.local",
		IX:         string(ixID),
		Prefixes:   []string{prefix},
		NotAfter:   time.Now().AddDate(1, 0, 0),
	})
	if err != nil {
		t.Fatalf("issue %s route cert: %v", ixID, err)
	}
	if err := pki.WriteBundle(out, string(ixID)+"-route", routeCert, false); err != nil {
		t.Fatalf("write %s route cert: %v", ixID, err)
	}
	result.ixCerts[ixID] = filepath.Join(out, string(ixID)+".crt")
	result.ixKeys[ixID] = filepath.Join(out, string(ixID)+".key")
	result.routeCerts[ixID] = filepath.Join(out, string(ixID)+"-route.crt")
}

func fingerprintForCertPath(t *testing.T, path string) string {
	t.Helper()
	cert, _, err := pki.LoadCertificate(path)
	if err != nil {
		t.Fatal(err)
	}
	return pki.CertificateFingerprintSHA256(cert)
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsAnnouncedPrefix(values []announcedPrefix, prefix string, origin core.IXID, nextHop core.IXID) bool {
	for _, value := range values {
		if value.Prefix == core.Prefix(prefix) && value.OriginIX == origin && value.NextHopIX == nextHop {
			return true
		}
	}
	return false
}

func runtimeRoutesContainPrefix(routes []routing.Route, want string) bool {
	for _, route := range routes {
		if string(route.Prefix) == want {
			return true
		}
	}
	return false
}
