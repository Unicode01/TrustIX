//go:build linux

package ebpf

import (
	"testing"

	"trustix.local/trustix/internal/dataplane"
)

func TestLANOffloadProtectionAppliesByMode(t *testing.T) {
	t.Setenv("TRUSTIX_LAN_OFFLOAD_PROTECTION", "")
	if !lanOffloadProtectionApplies(dataplane.AttachSpec{LANAttachMode: "managed"}) {
		t.Fatal("auto mode should protect managed LAN interfaces")
	}
	if lanOffloadProtectionApplies(dataplane.AttachSpec{LANAttachMode: "existing"}) {
		t.Fatal("auto mode should not modify existing LAN interfaces")
	}
	if !lanOffloadProtectionApplies(dataplane.AttachSpec{LANAttachMode: "existing", ExperimentalTCPTXDirect: true}) {
		t.Fatal("auto mode should protect experimental_tcp TC direct LAN interfaces")
	}
	if !lanOffloadProtectionApplies(dataplane.AttachSpec{LANAttachMode: "existing", KernelUDPTXDirectOnly: true}) {
		t.Fatal("auto mode should protect fail-closed TC direct LAN interfaces")
	}

	t.Setenv("TRUSTIX_LAN_OFFLOAD_PROTECTION", "force")
	if !lanOffloadProtectionApplies(dataplane.AttachSpec{LANAttachMode: "existing"}) {
		t.Fatal("force mode should protect existing LAN interfaces")
	}

	t.Setenv("TRUSTIX_LAN_OFFLOAD_PROTECTION", "off")
	if lanOffloadProtectionApplies(dataplane.AttachSpec{LANAttachMode: "managed"}) {
		t.Fatal("off mode should disable LAN offload protection")
	}
}

func TestLANOffloadProtectionPreservesRouteGSOForExperimentalTCP(t *testing.T) {
	t.Setenv("TRUSTIX_LAN_OFFLOAD_PROTECTION", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "1")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_ROUTE_TCP_HEADER_KFUNC", "1")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC", "1")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_TC_TX_OUTER_TCP_HEADER_KFUNC_PARTIAL_CSUM", "1")
	if !lanOffloadProtectionPreservesRouteGSO(dataplane.AttachSpec{ExperimentalTCPTXDirect: true}) {
		t.Fatal("auto mode should preserve TX offloads for experimental_tcp route-GSO kfunc")
	}
	features := lanOffloadProtectionFeaturesForSpec(dataplane.AttachSpec{ExperimentalTCPTXDirect: true})
	if _, ok := features["generic-segmentation-offload"]; ok {
		t.Fatal("route-GSO offload protection should not disable TX/GSO")
	}
	if _, ok := features["generic-receive-offload"]; !ok {
		t.Fatal("route-GSO offload protection should still disable GRO")
	}

	t.Setenv("TRUSTIX_LAN_OFFLOAD_PROTECTION_PRESERVE_ROUTE_GSO", "0")
	if lanOffloadProtectionPreservesRouteGSO(dataplane.AttachSpec{ExperimentalTCPTXDirect: true}) {
		t.Fatal("route-GSO preservation ignored explicit disable")
	}
}

func TestLANOffloadProtectionPreservesRouteGSOForExperimentalTCPFinalizeActiveGSO(t *testing.T) {
	t.Setenv("TRUSTIX_LAN_OFFLOAD_PROTECTION", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "1")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_ACTIVE_GSO_SAFE", "1")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_ALLOW_UNSAFE_ACTIVE_GSO", "1")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_TC_TX_FINALIZE_FLOW_TCP_HEADER_KFUNC", "1")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_SKIP_OUTER_TCP_CHECKSUM", "0")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM", "0")

	spec := dataplane.AttachSpec{ExperimentalTCPTXDirect: true}
	if !lanOffloadProtectionPreservesRouteGSO(spec) {
		t.Fatal("auto mode should preserve TX offloads for experimental_tcp finalize-flow active-GSO")
	}
	features := lanOffloadProtectionFeaturesForSpec(spec)
	if _, ok := features["generic-segmentation-offload"]; ok {
		t.Fatal("finalize-flow active-GSO offload protection should not disable TX/GSO")
	}
	if _, ok := features["generic-receive-offload"]; !ok {
		t.Fatal("finalize-flow active-GSO offload protection should still disable GRO by default")
	}
}

func TestLANOffloadProtectionCanPreserveRXGROForRouteGSOExperiment(t *testing.T) {
	t.Setenv("TRUSTIX_LAN_OFFLOAD_PROTECTION", "")
	t.Setenv("TRUSTIX_LAN_OFFLOAD_PROTECTION_PRESERVE_ROUTE_GSO", "1")
	t.Setenv("TRUSTIX_LAN_OFFLOAD_PROTECTION_PRESERVE_RX_GRO", "")

	spec := dataplane.AttachSpec{KernelUDPTXDirectOnly: true}
	if lanOffloadProtectionPreservesRouteGSORX(spec) {
		t.Fatal("RX offloads should stay protected unless explicitly preserved")
	}

	t.Setenv("TRUSTIX_LAN_OFFLOAD_PROTECTION_PRESERVE_RX_GRO", "1")
	if !lanOffloadProtectionPreservesRouteGSORX(spec) {
		t.Fatal("explicit RX GRO preservation was ignored")
	}
	if got := lanOffloadProtectionFeaturesForSpec(spec); len(got) != 0 {
		t.Fatalf("RX GRO preserved feature set = %#v, want no disabled features", got)
	}

	t.Setenv("TRUSTIX_LAN_OFFLOAD_PROTECTION_PRESERVE_ROUTE_GSO", "0")
	if lanOffloadProtectionPreservesRouteGSORX(spec) {
		t.Fatal("RX GRO preservation should require route-GSO preservation")
	}
}

func TestPersistedLinkOffloadStateDetail(t *testing.T) {
	state := &persistedLinkOffloadState{
		Iface: "lan0",
		Features: []persistedLinkOffloadFeature{
			{Name: "tx-checksum-ip-generic", Active: true},
			{Name: "generic-segmentation-offload", Active: true},
		},
	}
	if got, want := state.Detail(), "tx-checksum-ip-generic,generic-segmentation-offload"; got != want {
		t.Fatalf("Detail() = %q, want %q", got, want)
	}

	state.Peers = []persistedLinkOffloadState{{
		Iface:     "eth0",
		NetNSName: "trustix-ns",
		Features:  []persistedLinkOffloadFeature{{Name: "generic-segmentation-offload", Active: true}},
	}}
	if got, want := state.Detail(), "tx-checksum-ip-generic,generic-segmentation-offload;peer trustix-ns/eth0:generic-segmentation-offload"; got != want {
		t.Fatalf("Detail() with peer = %q, want %q", got, want)
	}
}

func TestMergePeerLinkOffloadStateDeduplicatesFeatures(t *testing.T) {
	state := &persistedLinkOffloadState{Iface: "lan0"}
	state = mergePeerLinkOffloadState(state, persistedLinkOffloadState{
		Iface:     "eth0",
		NetNSPath: "/run/netns/trustix-ns",
		Features:  []persistedLinkOffloadFeature{{Name: "tx-checksum-ip-generic", Active: true}},
	})
	state = mergePeerLinkOffloadState(state, persistedLinkOffloadState{
		Iface:     "eth0",
		NetNSPath: "/run/netns/trustix-ns",
		Features: []persistedLinkOffloadFeature{
			{Name: "tx-checksum-ip-generic", Active: true},
			{Name: "generic-segmentation-offload", Active: true},
		},
	})
	if len(state.Peers) != 1 {
		t.Fatalf("peer count = %d, want 1", len(state.Peers))
	}
	if len(state.Peers[0].Features) != 2 {
		t.Fatalf("peer feature count = %d, want 2", len(state.Peers[0].Features))
	}
}

func TestFeatureBitHelpers(t *testing.T) {
	if got := featureBlocks(65); got != 3 {
		t.Fatalf("featureBlocks(65) = %d, want 3", got)
	}
	blocks := []uint32{0, 1 << 5}
	if !bitIsSet(blocks, 37) {
		t.Fatal("bit 37 should be set")
	}
	if bitIsSet(blocks, 36) || bitIsSet(blocks, 80) {
		t.Fatal("unexpected feature bit state")
	}
}
