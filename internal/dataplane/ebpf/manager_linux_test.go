//go:build linux

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/kernelmodule"
	"trustix.local/trustix/internal/routing"
	"trustix.local/trustix/internal/transport/kerneludp"
	"trustix.local/trustix/internal/transport/tixtcp"
)

func skipIfKernelKfuncUnavailable(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	text := strings.ToLower(err.Error())
	if strings.Contains(text, "no btf") ||
		strings.Contains(text, "btf is unavailable") ||
		strings.Contains(text, "not supported") ||
		strings.Contains(text, "kfunc") {
		t.Skipf("kernel kfunc verifier support unavailable: %v", err)
	}
}

func TestAnnotateTCFilterAttachErrorHintsOpenWrtBPFClassifier(t *testing.T) {
	err := annotateTCFilterAttachError(os.ErrNotExist)
	if err == nil {
		t.Fatal("annotated error is nil")
	}
	text := err.Error()
	if !strings.Contains(text, "kmod-sched-bpf") || !strings.Contains(text, "clsact") {
		t.Fatalf("annotated TC attach error missing OpenWrt dependency hint: %v", err)
	}
}

func TestKernelUDPTXRouteValueABI(t *testing.T) {
	if got := unsafe.Sizeof(kernelUDPTXRouteValue{}); got != kernelUDPTXRouteValueSize {
		t.Fatalf("kernelUDPTXRouteValue size = %d, want %d", got, kernelUDPTXRouteValueSize)
	}
	if got := unsafe.Offsetof(kernelUDPTXRouteValue{}.Inline1); got != kernelUDPTXRouteInlineFlowOffset {
		t.Fatalf("kernelUDPTXRouteValue inline offset = %d, want %d", got, kernelUDPTXRouteInlineFlowOffset)
	}
	if got := unsafe.Offsetof(kernelUDPTXRouteValue{}.Inline8); got != kernelUDPTXRouteInlineFlow8Offset {
		t.Fatalf("kernelUDPTXRouteValue inline8 offset = %d, want %d", got, kernelUDPTXRouteInlineFlow8Offset)
	}
	value := kernelUDPTXRouteValue{Flags: kernelUDPTXRouteFlagDirectOnly}
	if value.Flags != kernelUDPTXRouteFlagDirectOnly {
		t.Fatalf("route flags = %#x, want direct-only flag", value.Flags)
	}
	value = kernelUDPTXRouteValue{}
	if !appendKernelUDPTXRouteFlow(&value, 11, 0) ||
		!appendKernelUDPTXRouteFlow(&value, 22, 1) ||
		!appendKernelUDPTXRouteFlow(&value, 88, 7) {
		t.Fatal("appendKernelUDPTXRouteFlow rejected valid indexes")
	}
	value.FlowID = value.FlowID1
	if value.FlowID != 11 || value.FlowID1 != 11 || value.FlowID2 != 22 || value.FlowID8 != 88 {
		t.Fatalf("route flow slots = %#v", value)
	}
	if appendKernelUDPTXRouteFlow(&value, 99, 8) {
		t.Fatal("appendKernelUDPTXRouteFlow accepted out-of-range index")
	}
}

func TestAddKernelCryptoDatapathQueryStatsUsesDistinctPrefixes(t *testing.T) {
	stats := make(map[string]uint64)
	query := kernelmodule.DatapathQuery{
		ModuleABIVersion:   7,
		DatapathABIVersion: 3,
		Features:           []string{kernelmodule.FeatureFullDatapath},
		SafeFeatures:       []string{kernelmodule.FeatureFullDatapath},
		Flags:              2,
	}

	addKernelCryptoDatapathQueryStats(stats, "kernel_crypto_module_full_datapath", query)

	if stats["kernel_crypto_module_full_datapath_abi_version"] != 3 {
		t.Fatalf("full datapath ABI stat = %d, want 3", stats["kernel_crypto_module_full_datapath_abi_version"])
	}
	if stats["kernel_crypto_module_full_datapath_module_abi_version"] != 7 {
		t.Fatalf("full module ABI stat = %d, want 7", stats["kernel_crypto_module_full_datapath_module_abi_version"])
	}
	if stats["kernel_crypto_module_full_datapath_features_full_datapath"] != 1 {
		t.Fatalf("full datapath feature stat = %d, want 1", stats["kernel_crypto_module_full_datapath_features_full_datapath"])
	}
	if _, ok := stats["kernel_crypto_module_datapath_features_full_datapath"]; ok {
		t.Fatal("full datapath stats should not overwrite legacy helper datapath prefix")
	}
}

func TestIsTrustIXTCFilterMatchesOnlyTrustIXBPFNames(t *testing.T) {
	for _, name := range []string{
		"trustix_ingress",
		"trustix_egress",
		"trustix_kudp_txk",
		"trustix_kudp_txke",
		"trustix_kudp_rx",
		"trustix_kudp_rxk",
	} {
		if !isTrustIXTCFilter(&netlink.BpfFilter{Name: " " + name + " "}) {
			t.Fatalf("TrustIX TC filter %q was not matched", name)
		}
	}
	for _, name := range []string{"", "forward_ingress", "trustix_tc_dynamic", "trustix"} {
		if isTrustIXTCFilter(&netlink.BpfFilter{Name: name}) {
			t.Fatalf("non-TrustIX TC filter %q was matched", name)
		}
	}
	if isTrustIXTCFilter(nil) {
		t.Fatal("nil filter was matched")
	}
}

func TestKernelUDPTXRouteCacheValueABI(t *testing.T) {
	if got := unsafe.Sizeof(kernelUDPTXRouteCacheValue{}); got != kernelUDPTXRouteCacheValueSize {
		t.Fatalf("kernelUDPTXRouteCacheValue size = %d, want %d", got, kernelUDPTXRouteCacheValueSize)
	}
	if got := unsafe.Offsetof(kernelUDPTXRouteCacheValue{}.Route); got != kernelUDPTXRouteCacheRouteOffset {
		t.Fatalf("kernelUDPTXRouteCacheValue route offset = %d, want %d", got, kernelUDPTXRouteCacheRouteOffset)
	}
}

func TestTIXTCPRouteGSOAsyncSpecRequestsSafeKfuncPath(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_SAFE_MODE", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_KFUNC", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_ASYNC_KFUNC", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "")

	spec := dataplane.AttachSpec{TIXTCPRouteGSOAsync: true}
	if !tixTCPTXDirectRouteTCPGSOAsyncKfuncRequestedForSpec(spec) {
		t.Fatal("async route-GSO spec did not request async kfunc path")
	}
	if !tixTCPTXDirectRouteTCPGSOKfuncRequestedForSpec(spec) {
		t.Fatal("async route-GSO spec did not request route-GSO kfunc")
	}
	options := kernelUDPTXDirectProgramOptions{
		TIXTCPOnly:            true,
		DirectOnly:            true,
		RouteTCPGSOKfunc:      true,
		RouteTCPGSOAsyncKfunc: true,
	}
	if !kernelUDPTunnelGSOEnabledForOptions(options) {
		t.Fatal("async route-GSO options did not enable tunnel GSO")
	}
	if !kernelUDPTunnelGSOActiveSKBEnabledForOptions(options) {
		t.Fatal("async route-GSO options did not enable active GSO")
	}
}

func TestTIXTCPRouteGSOAttachIgnoresGenericUDPDirectDisable(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_TIX_TCP_ONLY", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_ONLY", "")

	spec := dataplane.AttachSpec{
		KernelUDPTXDirectOnly: true,
		TIXTCPTXDirect:        true,
		TIXTCPRouteGSOAsync:   true,
	}
	if !kernelUDPTXDirectProgramEnabledForSpec(spec) {
		t.Fatal("generic UDP TX direct disable must not disable tix_tcp route-GSO TC program")
	}
	if !kernelUDPTXDirectOnlyEnabled(spec) {
		t.Fatal("generic UDP direct-only disable must not disable tix_tcp route-GSO direct-only mode")
	}
	if !kernelUDPTXDirectTIXTCPOnlyEnabledForSpec(spec) {
		t.Fatal("route-GSO attach should remain tix_tcp-only")
	}
}

func TestKernelUDPTCOnlyProviderRequestedForSpecIgnoresFalseyEnv(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ONLY_PROVIDER", "0")

	if !kernelUDPTCOnlyProviderRequestedForSpec(dataplane.AttachSpec{KernelUDPTCOnlyProvider: true}) {
		t.Fatal("spec-requested TC-only provider should not be disabled by legacy falsey env")
	}
	if kernelUDPTCOnlyProviderRequestedForSpec(dataplane.AttachSpec{}) {
		t.Fatal("empty spec with falsey env should not request TC-only provider")
	}
}

func TestTIXTCPRouteGSOAttachWithFullKmodEnvEmitsRouteKfuncPath(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "0")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_ONLY", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_TIX_TCP_ONLY", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PUSH_ROUTE_TCP_HEADER_KFUNC", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM", "")

	spec := dataplane.AttachSpec{
		KernelUDPTXDirectOnly:   true,
		TIXTCPTXDirect:          true,
		TIXTCPRouteGSOSync:      true,
		TIXTCPRouteGSOAsync:     true,
		TIXTCPRouteXmitWorker:   true,
		TIXTCPPlainSkipSequence: true,
		TIXTCPPlainACKOnly:      true,
	}
	if !kernelUDPTXDirectProgramEnabledForSpec(spec) {
		t.Fatal("full_kmod route-GSO spec should keep the TC TX direct program enabled")
	}
	if !kernelUDPTXDirectTIXTCPOnlyEnabledForSpec(spec) || kernelUDPTXDirectKernelUDPOnlyEnabledForSpec(spec) {
		t.Fatal("full_kmod route-GSO spec should select the tix_tcp-only TC program")
	}
	if !kernelUDPTXDirectOnlyEnabled(spec) {
		t.Fatal("full_kmod route-GSO spec should force direct-only mode")
	}

	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "tix_tcp_route_gso_full_kmod_env")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	routeKfuncCall, err := loadSKBTIXTTXPushRouteTCPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load route TCP header-push kfunc metadata: %v", err)
	}
	gsoKfuncCall, err := loadSKBTIXTTXSegmentRouteTCPGSOKfuncCall()
	if err != nil {
		t.Fatalf("load route TCP GSO kfunc metadata: %v", err)
	}
	xmitKfuncCall, err := loadSKBTIXTTXRouteTCPXmitKfuncCall()
	if err != nil {
		t.Fatalf("load route TCP xmit kfunc metadata: %v", err)
	}
	options := kernelUDPTXDirectProgramOptions{
		Enabled:                     kernelUDPTXDirectProgramEnabledForSpec(spec),
		TIXTCPOnly:                  kernelUDPTXDirectTIXTCPOnlyEnabledForSpec(spec),
		KernelUDPOnly:               kernelUDPTXDirectKernelUDPOnlyEnabledForSpec(spec),
		DirectOnly:                  kernelUDPTXDirectOnlyEnabled(spec),
		TIXTCPSkipPlainSequence:     tixTCPTXPlainSkipSequenceEnabledForSpec(spec),
		TIXTCPACKOnly:               tixTCPTXPlainACKOnlyEnabledForSpec(spec),
		PushRouteTCPHeaderKfunc:     tixTCPTXDirectPushRouteTCPHeaderKfuncRequestedForSpec(spec),
		PushRouteTCPHeaderKfuncCall: routeKfuncCall,
		RouteTCPGSOKfunc:            tixTCPTXDirectRouteTCPGSOKfuncRequestedForSpec(spec),
		RouteTCPGSOKfuncCall:        gsoKfuncCall,
		RouteTCPGSOAsyncKfunc:       tixTCPTXDirectRouteTCPGSOAsyncKfuncRequestedForSpec(spec),
		RouteTCPXmitKfunc:           tixTCPTXDirectRouteTCPXmitKfuncRequestedForSpec(spec),
		RouteTCPXmitKfuncCall:       xmitKfuncCall,
	}
	if !kernelUDPTunnelGSOEnabledForOptions(options) || !kernelUDPTunnelGSOActiveSKBEnabledForOptions(options) {
		t.Fatalf("full_kmod route-GSO options did not enable tunnel/active GSO: %+v", options)
	}
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word), asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word)},
		statsMap,
		routeMap,
		flowMap,
		options,
	)
	if instructionSymbolIndex(out, "kudp_tx_direct_route_tcp_kfunc") < 0 {
		t.Fatalf("full_kmod route-GSO spec did not emit route TCP GSO kfunc path; options=%+v", options)
	}
	if instructionSymbolIndex(out, "kudp_tx_direct_route_tcp_xmit_kfunc") < 0 {
		t.Fatalf("full_kmod route-GSO spec did not emit route TCP xmit kfunc path; options=%+v", options)
	}
}

func TestTIXTCPRouteGSORXDirectIgnoresGenericUDPDirectDisable(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT", "0")

	spec := dataplane.AttachSpec{
		TIXTCPTXDirect:      true,
		TIXTCPRouteGSOAsync: true,
	}
	if kernelUDPRXDirectDisabledForSpec(spec) {
		t.Fatal("generic UDP RX direct disable must not disable tix_tcp route-GSO RX direct")
	}

	manager := NewManager()
	manager.spec = spec
	manager.kernelUDPRXDirectAttached = true
	if !manager.kernelUDPRXDirectConfigEnabledLocked() {
		t.Fatal("generic UDP RX direct disable must not suppress route-GSO RX direct config")
	}
}

func TestGenericUDPDirectDisableStillDisablesNonRouteGSOProgram(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "0")

	if kernelUDPTXDirectProgramEnabledForSpec(dataplane.AttachSpec{}) {
		t.Fatal("generic UDP TX direct disable should still disable non-route-GSO TC program")
	}
	if kernelUDPTXDirectOnlyEnabled(dataplane.AttachSpec{KernelUDPTXDirectOnly: true}) {
		t.Fatal("generic UDP direct-only disable should still override non-route-GSO direct-only mode")
	}
	tcOnlySpec := dataplane.AttachSpec{KernelUDPTXDirectOnly: true, KernelUDPTCOnlyProvider: true}
	if !kernelUDPTXDirectProgramEnabledForSpec(tcOnlySpec) {
		t.Fatal("spec-requested TC-only provider should override legacy falsey TX direct env")
	}
	if !kernelUDPTXDirectOnlyEnabled(tcOnlySpec) {
		t.Fatal("spec-requested TC-only provider should override legacy falsey direct-only env")
	}
}

func TestGenericUDPDirectDisableStillDisablesNonRouteGSORXDirect(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT", "0")

	if !kernelUDPRXDirectDisabledForSpec(dataplane.AttachSpec{}) {
		t.Fatal("generic UDP RX direct disable should still disable non-route-GSO RX direct")
	}
	if kernelUDPRXDirectDisabledForSpec(dataplane.AttachSpec{KernelUDPTXDirectOnly: true, KernelUDPTCOnlyProvider: true}) {
		t.Fatal("spec-requested TC-only provider should override legacy falsey RX direct env")
	}

	manager := NewManager()
	manager.kernelUDPRXDirectAttached = true
	if manager.kernelUDPRXDirectConfigEnabledLocked() {
		t.Fatal("generic UDP RX direct disable should still suppress non-route-GSO RX direct config")
	}
}

func TestKernelUDPTXFlowValueABI(t *testing.T) {
	if got := unsafe.Sizeof(kernelUDPTXFlowValue{}); got != kernelUDPTXFlowValueSize {
		t.Fatalf("kernelUDPTXFlowValue size = %d, want %d", got, kernelUDPTXFlowValueSize)
	}
	if got := unsafe.Offsetof(kernelUDPTXFlowValue{}.IPv4ChecksumUDP); got != 30 {
		t.Fatalf("IPv4ChecksumUDP offset = %d, want 30", got)
	}
	if got := unsafe.Offsetof(kernelUDPTXFlowValue{}.IPv4ChecksumTCP); got != 38 {
		t.Fatalf("IPv4ChecksumTCP offset = %d, want 38", got)
	}
	source := netip.MustParseAddr("192.0.2.1").As4()
	destination := netip.MustParseAddr("198.51.100.2").As4()
	for _, protocol := range []uint8{ipProtocolUDP, ipProtocolTCP} {
		base := kernelUDPTXIPv4ChecksumBase(source, destination, protocol)
		packet := make([]byte, rejectIPv4HeaderLen)
		packet[0] = 0x45
		binary.BigEndian.PutUint16(packet[2:4], 1280)
		binary.BigEndian.PutUint16(packet[6:8], 0x4000)
		packet[8] = 64
		packet[9] = protocol
		copy(packet[12:16], source[:])
		copy(packet[16:20], destination[:])
		want := captureChecksum(packet)
		got := captureChecksumFold(uint32(base) + 1280)
		if got != want {
			t.Fatalf("protocol %d precomputed checksum = %#x, want %#x", protocol, got, want)
		}
	}
}

func TestAppendTCPChecksumIncludesChecksumFold(t *testing.T) {
	fold := appendChecksumFold(nil)
	instructions := appendTCPChecksum(nil, "checksum_error")
	if len(instructions) <= len(fold) {
		t.Fatalf("TCP checksum instructions = %d, want checksum setup plus %d fold instructions", len(instructions), len(fold))
	}
	if suffix := instructions[len(instructions)-len(fold):]; !reflect.DeepEqual(suffix, fold) {
		t.Fatalf("TCP checksum instructions do not end with checksum fold\n got: %#v\nwant: %#v", suffix, fold)
	}
}

func TestKernelUDPTXBPFMapSnapshotIncludesRoutesFlowsAndInlineSlots(t *testing.T) {
	routeMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_route_snapshot_test", Type: cebpf.LPMTrie, KeySize: 8, ValueSize: kernelUDPTXRouteValueSize, MaxEntries: 16, Flags: 1})
	defer routeMap.Close()
	flowMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_flow_snapshot_test", Type: cebpf.Hash, KeySize: 8, ValueSize: kernelUDPTXFlowValueSize, MaxEntries: 16})
	defer flowMap.Close()

	flow := kernelUDPTXFlowValue{
		Sequence:        123,
		SourceIP:        netip.MustParseAddr("192.0.2.1").As4(),
		DestinationIP:   netip.MustParseAddr("198.51.100.2").As4(),
		SourcePort:      htons(32000),
		DestinationPort: htons(18100),
		Ifindex:         7,
		DestinationMAC0: binary.LittleEndian.Uint32([]byte{0x00, 0x11, 0x22, 0x33}),
		DestinationMAC1: binary.LittleEndian.Uint16([]byte{0x44, 0x55}),
		SourceMAC0:      binary.LittleEndian.Uint32([]byte{0xaa, 0xbb, 0xcc, 0xdd}),
		SourceMAC1:      binary.LittleEndian.Uint16([]byte{0xee, 0xff}),
		MTU:             1500,
		Flags:           kernelUDPTXFlowFlagTIXTCP | kernelUDPTXFlowFlagTrustInnerChecksum,
	}
	if err := flowMap.Update(uint64(42), flow, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed flow map: %v", err)
	}
	routeValue := kernelUDPTXRouteValue{
		FlowID:   42,
		FlowID1:  42,
		FlowID2:  43,
		FlowMask: 1,
		Flags:    kernelUDPTXRouteFlagInlineFlow | kernelUDPTXRouteFlagDirectOnly,
		Inline1:  flow,
		Inline2:  flow,
	}
	routeValue.Inline2.Sequence = 456
	if err := routeMap.Update(routeKey{PrefixLen: 24, Addr: netip.MustParseAddr("10.9.8.0").As4()}, routeValue, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed route map: %v", err)
	}

	manager := &Manager{kernelUDPTXRouteMap: routeMap, kernelUDPTXFlowMap: flowMap}
	snapshot, err := manager.BPFMapSnapshot(context.Background())
	if err != nil {
		t.Fatalf("BPFMapSnapshot: %v", err)
	}
	if len(snapshot.KernelUDPTXFlows) != 1 {
		t.Fatalf("flow snapshots = %d, want 1", len(snapshot.KernelUDPTXFlows))
	}
	gotFlow := snapshot.KernelUDPTXFlows[0]
	if gotFlow.FlowID != 42 || gotFlow.Sequence != 123 || gotFlow.SourcePort != 32000 || gotFlow.DestinationPort != 18100 ||
		gotFlow.SourceIP != "192.0.2.1" || gotFlow.DestinationIP != "198.51.100.2" || !gotFlow.TIXTCP || !gotFlow.TrustInnerChecksum {
		t.Fatalf("flow snapshot = %#v", gotFlow)
	}
	if gotFlow.DestinationMAC != "00:11:22:33:44:55" || gotFlow.SourceMAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("flow MACs = %s %s", gotFlow.DestinationMAC, gotFlow.SourceMAC)
	}
	if len(snapshot.KernelUDPTXRoutes) != 1 {
		t.Fatalf("route snapshots = %d, want 1", len(snapshot.KernelUDPTXRoutes))
	}
	gotRoute := snapshot.KernelUDPTXRoutes[0]
	if gotRoute.Prefix != "10.9.8.0/24" || gotRoute.FlowID != 42 || gotRoute.ActiveFlowCount != 2 ||
		!reflect.DeepEqual(gotRoute.FlowIDs, []uint64{42, 43}) || !gotRoute.Inline || !gotRoute.DirectOnly {
		t.Fatalf("route snapshot = %#v", gotRoute)
	}
	if len(gotRoute.InlineFlows) != 2 || gotRoute.InlineFlows[0].Slot != 1 || gotRoute.InlineFlows[1].Slot != 2 ||
		gotRoute.InlineFlows[0].Sequence != 123 || gotRoute.InlineFlows[1].Sequence != 456 {
		t.Fatalf("inline snapshots = %#v", gotRoute.InlineFlows)
	}
}

func TestKernelCryptoCtxSlotValueABI(t *testing.T) {
	if got := unsafe.Sizeof(kernelCryptoCtxSlotValue{}); got != kernelCryptoCtxSlotValueSize {
		t.Fatalf("kernelCryptoCtxSlotValue size = %d, want %d", got, kernelCryptoCtxSlotValueSize)
	}
}

func TestKernelUDPTelemetrySnapshotIncludesKernelCryptoTraffic(t *testing.T) {
	manager := NewManager()
	ctxSlots := newTestBPFMap(t, &cebpf.MapSpec{
		Name:       "ix_kernel_crypto_ctx_slots_telemetry_test",
		Type:       cebpf.Array,
		KeySize:    4,
		ValueSize:  uint32(unsafe.Sizeof(kernelCryptoCtxSlotValue{})),
		MaxEntries: 8,
	})
	defer ctxSlots.Close()
	manager.kernelCryptoProvider = &kernelCryptoProviderObject{contextSlots: ctxSlots}
	manager.kernelCryptoCtxSlots = map[kernelCryptoFlowKey]uint32{
		kernelCryptoFlowKeyFor(kernelCryptoNamespaceKernelUDP, 7, kernelCryptoDirectionSend): 1,
		kernelCryptoFlowKeyFor(kernelCryptoNamespaceKernelUDP, 7, kernelCryptoDirectionRecv): 2,
		kernelCryptoFlowKeyFor(kernelCryptoNamespaceKernelUDP, 8, kernelCryptoDirectionSend): 3,
	}
	if err := ctxSlots.Update(uint32(1), kernelCryptoCtxSlotValue{Packets: 10, Bytes: 1000}, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed send slot 1: %v", err)
	}
	if err := ctxSlots.Update(uint32(2), kernelCryptoCtxSlotValue{Packets: 4, Bytes: 400}, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed recv slot 2: %v", err)
	}
	if err := ctxSlots.Update(uint32(3), kernelCryptoCtxSlotValue{Packets: 9, Bytes: 900}, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed send slot 3: %v", err)
	}
	manager.kernelUDPFlows[7] = dataplane.KernelUDPFlow{
		ID:              7,
		Peer:            core.IXID("ix-b"),
		Endpoint:        core.EndpointID("ep-b"),
		RemoteAddress:   "192.0.2.2:7000",
		SourcePort:      17041,
		DestinationPort: 54000,
		CryptoPlacement: dataplane.CryptoPlacementKernel,
	}
	manager.kernelUDPFlows[8] = dataplane.KernelUDPFlow{
		ID:              8,
		Peer:            core.IXID("ix-c"),
		Endpoint:        core.EndpointID("ep-c"),
		RemoteAddress:   "198.51.100.2:7001",
		SourcePort:      17042,
		DestinationPort: 54001,
		CryptoPlacement: dataplane.CryptoPlacementKernel,
	}
	manager.kernelUDPTelemetry[7] = &dataplane.TransportPathTelemetry{
		Protocol:      "kernel_udp",
		FlowID:        7,
		Peer:          "ix-b",
		Endpoint:      "ep-b",
		RemoteAddress: "192.0.2.2:7000",
		TXFrames:      2,
		TXBytes:       200,
		RXFrames:      1,
		RXBytes:       120,
	}

	snapshot := manager.kernelUDPTelemetrySnapshotLocked()
	if len(snapshot) != 2 {
		t.Fatalf("telemetry snapshot length = %d, want 2", len(snapshot))
	}
	byFlow := make(map[uint64]dataplane.TransportPathTelemetry, len(snapshot))
	for _, item := range snapshot {
		byFlow[item.FlowID] = item
	}
	flow7, ok := byFlow[7]
	if !ok {
		t.Fatal("missing telemetry for flow 7")
	}
	if flow7.Peer != "ix-b" || flow7.Endpoint != "ep-b" {
		t.Fatalf("flow 7 identity = %+v", flow7)
	}
	if flow7.TXFrames != 12 || flow7.TXBytes != 1200 || flow7.RXFrames != 5 || flow7.RXBytes != 520 {
		t.Fatalf("flow 7 telemetry = %+v", flow7)
	}
	flow8, ok := byFlow[8]
	if !ok {
		t.Fatal("missing telemetry for flow 8")
	}
	if flow8.Peer != "ix-c" || flow8.Endpoint != "ep-c" {
		t.Fatalf("flow 8 identity = %+v", flow8)
	}
	if flow8.TXFrames != 9 || flow8.TXBytes != 900 || flow8.RXFrames != 0 || flow8.RXBytes != 0 {
		t.Fatalf("flow 8 telemetry = %+v", flow8)
	}
	if flow8.FirstSeen.IsZero() || flow8.LastSeen.IsZero() {
		t.Fatalf("flow 8 timestamps not populated: %+v", flow8)
	}

	stats := manager.kernelUDPProviderStatsLocked()
	if stats["telemetry_tx_frames"] != 21 || stats["telemetry_tx_bytes"] != 2100 || stats["telemetry_rx_frames"] != 5 || stats["telemetry_rx_bytes"] != 520 {
		t.Fatalf("kernel udp telemetry stats = %#v", stats)
	}
}

func TestKernelUDPProviderStatsIncludeLANReinjectCounters(t *testing.T) {
	oldStats := lanPacketStats
	lanPacketStats = &lanPacketInjectorStats{}
	t.Cleanup(func() {
		lanPacketStats = oldStats
	})
	lanPacketStats.gsoAttempts.Store(3)
	lanPacketStats.gsoSuccesses.Store(2)
	lanPacketStats.gsoRawAttempts.Store(3)
	lanPacketStats.gsoRawSuccesses.Store(2)
	lanPacketStats.gsoErrnoENOBUFS.Store(1)
	lanPacketStats.rawVNetBatchAttempts.Store(4)
	lanPacketStats.rawVNetBatchMessages.Store(7)
	lanPacketStats.batchSendAttempts.Store(5)
	lanPacketStats.batchSendMessages.Store(8)

	manager := &Manager{}
	stats := manager.kernelUDPProviderStatsLocked()

	if stats["lan_reinject_gso_attempts"] != 3 ||
		stats["lan_reinject_gso_successes"] != 2 ||
		stats["lan_reinject_gso_raw_attempts"] != 3 ||
		stats["lan_reinject_gso_raw_successes"] != 2 ||
		stats["lan_reinject_gso_error_enobufs"] != 1 ||
		stats["lan_reinject_raw_vnet_batch_attempts"] != 4 ||
		stats["lan_reinject_raw_vnet_batch_messages"] != 7 ||
		stats["lan_reinject_batch_send_attempts"] != 5 ||
		stats["lan_reinject_batch_send_messages"] != 8 {
		t.Fatalf("LAN reinject provider stats = %#v", stats)
	}
}

func TestKernelUDPProviderStatsIncludeKernelCryptoBatchSizes(t *testing.T) {
	manager := &Manager{}
	manager.observeKernelCryptoDeviceSealBatchLocked([]kernelCryptoDeviceSealRequest{
		{Plain: []byte("one")},
		{Plain: []byte("three")},
	})
	manager.observeKernelCryptoDeviceOpenBatchLocked([]kernelCryptoDeviceOpenRequest{
		{Payload: []byte("sealed-a")},
		{Payload: []byte("sealed-payload-b")},
		{Payload: []byte("c")},
	})
	manager.observeKernelCryptoDeviceOpenResultsLocked([]kernelCryptoDeviceOpenResult{
		{Plain: []byte("plain-a")},
		{Plain: []byte("larger-plain-b")},
	})

	stats := manager.kernelUDPProviderStatsLocked()
	if stats["kernel_crypto_device_seal_batch_calls"] != 1 ||
		stats["kernel_crypto_device_seal_batch_requests"] != 2 ||
		stats["kernel_crypto_device_seal_batch_max_requests"] != 2 ||
		stats["kernel_crypto_device_seal_batch_plaintext_bytes"] != 8 ||
		stats["kernel_crypto_device_seal_batch_max_plaintext_len"] != 5 {
		t.Fatalf("seal batch stats = %#v", stats)
	}
	if stats["kernel_crypto_device_open_batch_calls"] != 1 ||
		stats["kernel_crypto_device_open_batch_requests"] != 3 ||
		stats["kernel_crypto_device_open_batch_max_requests"] != 3 ||
		stats["kernel_crypto_device_open_batch_ciphertext_bytes"] != 25 ||
		stats["kernel_crypto_device_open_batch_max_ciphertext_len"] != 16 ||
		stats["kernel_crypto_device_open_batch_plaintext_bytes"] != 21 ||
		stats["kernel_crypto_device_open_batch_max_plaintext_len"] != 14 {
		t.Fatalf("open batch stats = %#v", stats)
	}
}

func TestKernelUDPProviderStatsIncludeTCHotCounters(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF map test: %v", err)
	}
	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_stats_provider_test", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	defer statsMap.Close()
	put := func(key uint32, value uint64) {
		t.Helper()
		if err := statsMap.Update(key, value, cebpf.UpdateAny); err != nil {
			t.Fatalf("update stats counter %d: %v", key, err)
		}
	}
	put(kernelUDPTXStatSuccess, 17)
	put(kernelUDPTXDirectStatLenGSOFallbacks, 3)
	put(kernelUDPRXDirectStatLocalDeliveries, 11)
	put(kernelUDPTXDirectStatGSOInputs, 5)
	put(kernelUDPTXDirectStatGSOActiveAccepts, 4)
	put(kernelUDPTXDirectStatGSOSuccesses, 2)
	put(packetPolicyTCPMSSClampStatSuccess, 9)
	put(packetPolicyTCPMSSClampStatErrors, 1)
	put(packetPolicyTCPMSSClampStatDrops, 2)
	put(kernelUDPTXSecureDirectStatMTUUnderlayFallbacks, 6)
	put(kernelUDPTXSecureDirectStatMTUUnderlay1500Fallbacks, 4)
	put(kernelUDPTXSecureDirectStatMTUUnderlayJumboFallbacks, 1)
	put(kernelUDPTXSecureDirectStatMTUUnderlayInnerGT1400Fallbacks, 3)
	put(kernelUDPTXSecureDirectStatMTUUnderlayInnerLE1400Fallbacks, 2)

	manager := &Manager{
		statsMap:                               statsMap,
		kernelUDPRXDirectAttached:              true,
		kernelUDPRXDirectStaticDestinationPort: 17001,
		kernelUDPRXDirectParseDecapL2Kfunc:     true,
		snapshot: dataplane.Snapshot{PacketPolicy: dataplane.PacketPolicy{
			MTU:           1500,
			DropFragments: true,
			TCPMSSClamp:   1320,
		}},
	}
	stats := manager.kernelUDPProviderStatsLocked()
	if stats["tc_kernel_udp_tx_direct_packets"] != 17 ||
		stats["tc_kernel_udp_tx_direct_len_gso_fallbacks"] != 3 ||
		stats["tc_kernel_udp_rx_direct_local_deliveries"] != 11 ||
		stats["tc_kernel_udp_tx_direct_gso_inputs"] != 5 ||
		stats["tc_kernel_udp_tx_direct_gso_active_accepts"] != 4 ||
		stats["tc_kernel_udp_tx_direct_gso_successes"] != 2 ||
		stats["tc_kernel_udp_rx_direct_attached"] != 1 ||
		stats["tc_kernel_udp_rx_direct_static_destination_port"] != 17001 ||
		stats["tc_kernel_udp_rx_direct_parse_decap_l2_kfunc"] != 1 ||
		stats["tc_packet_policy_mtu"] != 1500 ||
		stats["tc_packet_policy_drop_fragments"] != 1 ||
		stats["tc_packet_policy_tcp_mss_clamp"] != 1320 ||
		stats["tc_packet_policy_tcp_mss_clamps"] != 9 ||
		stats["tc_packet_policy_tcp_mss_clamp_errors"] != 1 ||
		stats["tc_packet_policy_tcp_mss_clamp_drops"] != 2 ||
		stats["tc_kernel_udp_tx_secure_direct_mtu_underlay_fallbacks"] != 6 ||
		stats["tc_kernel_udp_tx_secure_direct_mtu_underlay_1500ish_fallbacks"] != 4 ||
		stats["tc_kernel_udp_tx_secure_direct_mtu_underlay_jumbo_fallbacks"] != 1 ||
		stats["tc_kernel_udp_tx_secure_direct_mtu_underlay_inner_gt_1400_fallbacks"] != 3 ||
		stats["tc_kernel_udp_tx_secure_direct_mtu_underlay_inner_le_1400_fallbacks"] != 2 {
		t.Fatalf("TC hot provider stats = %#v", stats)
	}
}

func TestCapturePerfBufferPagesDefaultAndCap(t *testing.T) {
	t.Setenv("TRUSTIX_CAPTURE_PERF_BUFFER_PAGES", "")
	if got := capturePerfBufferPages(); got != capturePerfBufferDefaultPages {
		t.Fatalf("default capture perf buffer pages = %d, want %d", got, capturePerfBufferDefaultPages)
	}
	t.Setenv("TRUSTIX_CAPTURE_PERF_BUFFER_PAGES", "64")
	if got := capturePerfBufferPages(); got != 64 {
		t.Fatalf("env capture perf buffer pages = %d, want 64", got)
	}
	t.Setenv("TRUSTIX_CAPTURE_PERF_BUFFER_PAGES", "999999")
	if got := capturePerfBufferPages(); got != capturePerfBufferMaxPages {
		t.Fatalf("capped capture perf buffer pages = %d, want %d", got, capturePerfBufferMaxPages)
	}
	t.Setenv("TRUSTIX_CAPTURE_PERF_BUFFER_PAGES", "-1")
	if got := capturePerfBufferPages(); got != capturePerfBufferDefaultPages {
		t.Fatalf("invalid capture perf buffer pages = %d, want default %d", got, capturePerfBufferDefaultPages)
	}
}

func TestDefaultCaptureSampleLimitFitsLegacyPerCPUMapValueLimit(t *testing.T) {
	t.Setenv("TRUSTIX_CAPTURE_SAMPLE_LIMIT", "")
	if got := configuredCaptureSampleLimit(); got != captureScratchMaxSize {
		t.Fatalf("default capture sample limit = %d, want scratch max %d", got, captureScratchMaxSize)
	}
	if captureEventHeader+configuredCaptureSampleLimit() > 32*1024 {
		t.Fatalf("capture scratch value size = %d, want <= 32KiB for legacy kernels", captureEventHeader+configuredCaptureSampleLimit())
	}
}

func TestCaptureReaderDrainTimeoutDefaultAndEnv(t *testing.T) {
	t.Setenv("TRUSTIX_CAPTURE_READER_DRAIN_TIMEOUT", "")
	if got := configuredCaptureReaderDrainTimeout(); got != 50*time.Microsecond {
		t.Fatalf("default capture reader drain timeout = %s, want 50us", got)
	}
	t.Setenv("TRUSTIX_CAPTURE_READER_DRAIN_TIMEOUT", "75us")
	if got := configuredCaptureReaderDrainTimeout(); got != 75*time.Microsecond {
		t.Fatalf("env capture reader drain timeout = %s, want 75us", got)
	}
	t.Setenv("TRUSTIX_CAPTURE_READER_DRAIN_TIMEOUT", "0")
	if got := configuredCaptureReaderDrainTimeout(); got != 0 {
		t.Fatalf("disabled capture reader drain timeout = %s, want 0", got)
	}
	t.Setenv("TRUSTIX_CAPTURE_READER_DRAIN_TIMEOUT", "10s")
	if got := configuredCaptureReaderDrainTimeout(); got != 5*time.Millisecond {
		t.Fatalf("capped capture reader drain timeout = %s, want 5ms", got)
	}
	t.Setenv("TRUSTIX_CAPTURE_READER_DRAIN_TIMEOUT", "invalid")
	if got := configuredCaptureReaderDrainTimeout(); got != 50*time.Microsecond {
		t.Fatalf("invalid capture reader drain timeout = %s, want default 50us", got)
	}
}

func TestDeliverCaptureEventBatchMarksMutableOnlyForSingleSubscriberNoHistory(t *testing.T) {
	oldHistory := captureHistoryEnabled
	captureHistoryEnabled = false
	t.Cleanup(func() { captureHistoryEnabled = oldHistory })

	manager := &Manager{captureSubs: make(map[chan []dataplane.CaptureEvent]struct{})}
	sub := make(chan []dataplane.CaptureEvent, 1)
	manager.captureSubs[sub] = struct{}{}
	batch := []dataplane.CaptureEvent{{Payload: []byte{1, 2, 3}}}
	if !manager.deliverCaptureEventBatchLocked(batch) {
		t.Fatal("deliver returned false")
	}
	delivered := <-sub
	if !delivered[0].PayloadMutable {
		t.Fatal("single-subscriber no-history payload should be mutable")
	}

	sub2 := make(chan []dataplane.CaptureEvent, 1)
	manager.captureSubs[sub2] = struct{}{}
	batch = []dataplane.CaptureEvent{{Payload: []byte{4, 5, 6}}}
	if !manager.deliverCaptureEventBatchLocked(batch) {
		t.Fatal("deliver with two subscribers returned false")
	}
	delivered = <-sub
	if delivered[0].PayloadMutable {
		t.Fatal("multi-subscriber payload should not be mutable")
	}

	captureHistoryEnabled = true
	delete(manager.captureSubs, sub2)
	batch = []dataplane.CaptureEvent{{Payload: []byte{7, 8, 9}}}
	if !manager.deliverCaptureEventBatchLocked(batch) {
		t.Fatal("deliver with history returned false")
	}
	delivered = <-sub
	if delivered[0].PayloadMutable {
		t.Fatal("history-enabled payload should not be mutable")
	}
}

func TestDeliverCaptureEventBatchTracksBorrowedLeaseForBatchSubscriber(t *testing.T) {
	oldHistory := captureHistoryEnabled
	captureHistoryEnabled = false
	t.Cleanup(func() { captureHistoryEnabled = oldHistory })

	manager := &Manager{
		captureSubs:      make(map[chan []dataplane.CaptureEvent]struct{}),
		captureSubOwners: make(map[chan []dataplane.CaptureEvent]*captureSubscription),
	}
	events := make(chan []dataplane.CaptureEvent, 1)
	subscription := &captureSubscription{manager: manager, events: events}
	manager.captureSubs[events] = struct{}{}
	manager.captureSubOwners[events] = subscription
	lease := &captureEventBatchLease{
		events: []dataplane.CaptureEvent{{Payload: []byte{1, 2, 3}}},
		arena:  []byte{1, 2, 3},
	}

	consumed, retained := manager.deliverCaptureEventBatchLeaseLocked(lease.events, lease)
	if !consumed {
		t.Fatal("borrowed delivery was not consumed")
	}
	if !retained {
		t.Fatal("borrowed delivery should be retained until ReleaseBatch")
	}
	delivered := <-events
	if !delivered[0].PayloadMutable {
		t.Fatal("borrowed single-subscriber payload should be mutable")
	}
	if got := len(subscription.borrowed); got != 1 {
		t.Fatalf("borrowed batch count = %d, want 1", got)
	}
	subscription.ReleaseBatch(delivered)
	if got := len(subscription.borrowed); got != 0 {
		t.Fatalf("borrowed batch count after release = %d, want 0", got)
	}
	subscription.ReleaseBatch(delivered)
}

func TestDeliverCaptureEventBatchDoesNotRetainDroppedBorrowedLease(t *testing.T) {
	oldHistory := captureHistoryEnabled
	captureHistoryEnabled = false
	t.Cleanup(func() { captureHistoryEnabled = oldHistory })

	manager := &Manager{
		captureSubs:      make(map[chan []dataplane.CaptureEvent]struct{}),
		captureSubOwners: make(map[chan []dataplane.CaptureEvent]*captureSubscription),
	}
	events := make(chan []dataplane.CaptureEvent)
	subscription := &captureSubscription{manager: manager, events: events}
	manager.captureSubs[events] = struct{}{}
	manager.captureSubOwners[events] = subscription
	lease := &captureEventBatchLease{
		events: []dataplane.CaptureEvent{{Payload: []byte{1, 2, 3}}},
		arena:  []byte{1, 2, 3},
	}

	consumed, retained := manager.deliverCaptureEventBatchLeaseLocked(lease.events, lease)
	if !consumed {
		t.Fatal("dropped delivery should still be consumed")
	}
	if retained {
		t.Fatal("dropped delivery should not retain the borrowed lease")
	}
	if got := len(subscription.borrowed); got != 0 {
		t.Fatalf("borrowed batch count after dropped delivery = %d, want 0", got)
	}
}

func TestDeliverCaptureEventBatchCopiesBorrowedLeaseForLegacySubscriber(t *testing.T) {
	oldHistory := captureHistoryEnabled
	captureHistoryEnabled = false
	t.Cleanup(func() { captureHistoryEnabled = oldHistory })

	manager := &Manager{
		captureSubs:      make(map[chan []dataplane.CaptureEvent]struct{}),
		captureSubOwners: make(map[chan []dataplane.CaptureEvent]*captureSubscription),
	}
	events := make(chan []dataplane.CaptureEvent, 1)
	subscription := &captureSubscription{manager: manager, events: events, legacy: make(chan dataplane.CaptureEvent, 1)}
	manager.captureSubs[events] = struct{}{}
	manager.captureSubOwners[events] = subscription
	lease := &captureEventBatchLease{
		events: []dataplane.CaptureEvent{{Payload: []byte{1, 2, 3}}},
		arena:  []byte{1, 2, 3},
	}

	consumed, retained := manager.deliverCaptureEventBatchLeaseLocked(lease.events, lease)
	if !consumed {
		t.Fatal("legacy delivery was not consumed")
	}
	if retained {
		t.Fatal("legacy delivery should copy instead of retaining the borrowed lease")
	}
	delivered := <-events
	if delivered[0].PayloadMutable {
		t.Fatal("legacy copied payload should not be mutable")
	}
	if len(delivered[0].Payload) == 0 || &delivered[0].Payload[0] == &lease.events[0].Payload[0] {
		t.Fatal("legacy copied payload aliases the borrowed lease")
	}
	if got := len(subscription.borrowed); got != 0 {
		t.Fatalf("borrowed batch count after legacy delivery = %d, want 0", got)
	}
}

func TestDeliverCaptureEventBatchHistoryCopiesBorrowedPayload(t *testing.T) {
	oldHistory := captureHistoryEnabled
	captureHistoryEnabled = true
	t.Cleanup(func() { captureHistoryEnabled = oldHistory })

	manager := &Manager{captureSubs: make(map[chan []dataplane.CaptureEvent]struct{})}
	lease := &captureEventBatchLease{
		events: []dataplane.CaptureEvent{{Payload: []byte{1, 2, 3}}},
		arena:  []byte{1, 2, 3},
	}
	consumed, retained := manager.deliverCaptureEventBatchLeaseLocked(lease.events, lease)
	if consumed {
		t.Fatal("history-only delivery should not report subscriber consumption")
	}
	if retained {
		t.Fatal("history-only delivery should not retain the borrowed lease")
	}
	if manager.captureEventCount != 1 {
		t.Fatalf("capture history count = %d, want 1", manager.captureEventCount)
	}
	history := manager.captureEvents[0]
	if len(history.Payload) == 0 || &history.Payload[0] == &lease.events[0].Payload[0] {
		t.Fatal("capture history payload aliases the borrowed lease")
	}
	lease.events[0].Payload[0] = 9
	if history.Payload[0] != 1 {
		t.Fatalf("capture history payload mutated through lease: got %d want 1", history.Payload[0])
	}
}

func TestTCStatsCounterKeysDoNotOverlap(t *testing.T) {
	keys := map[uint32]string{}
	add := func(name string, key uint32) {
		if key >= tcStatsMapMaxEntries {
			t.Fatalf("%s key %d exceeds stats map max %d", name, key, tcStatsMapMaxEntries)
		}
		if previous := keys[key]; previous != "" {
			t.Fatalf("stats key %d reused by %s and %s", key, previous, name)
		}
		keys[key] = name
	}
	for _, item := range []struct {
		name string
		key  uint32
	}{
		{"kernel_udp_rx_secure_direct_attempts", kernelUDPRXSecureDirectStatAttempts},
		{"kernel_udp_rx_secure_direct_candidates", kernelUDPRXSecureDirectStatCandidates},
		{"kernel_udp_rx_secure_direct_packets", kernelUDPRXSecureDirectStatSuccess},
		{"kernel_udp_rx_secure_direct_fallbacks", kernelUDPRXSecureDirectStatFallbacks},
		{"kernel_udp_rx_secure_direct_no_context", kernelUDPRXSecureDirectStatNoContext},
		{"kernel_udp_rx_secure_direct_header_errors", kernelUDPRXSecureDirectStatHeaderErrors},
		{"kernel_udp_rx_secure_direct_decrypt_errors", kernelUDPRXSecureDirectStatDecryptErrors},
		{"kernel_udp_rx_secure_direct_replay_drops", kernelUDPRXSecureDirectStatReplayDrops},
		{"kernel_udp_rx_secure_direct_replay_old_drops", kernelUDPRXSecureDirectStatReplayOldDrops},
		{"kernel_udp_rx_secure_direct_replay_seen_drops", kernelUDPRXSecureDirectStatReplaySeenDrops},
		{"kernel_udp_rx_secure_direct_drops", kernelUDPRXSecureDirectStatDrops},
		{"kernel_udp_rx_secure_direct_neighbor_hits", kernelUDPRXSecureDirectStatNeighHits},
		{"kernel_udp_rx_secure_direct_neighbor_misses", kernelUDPRXSecureDirectStatNeighMisses},
		{"kernel_udp_rx_secure_direct_adjust_errors", kernelUDPRXSecureDirectStatAdjustErrors},
		{"kernel_udp_rx_secure_direct_store_errors", kernelUDPRXSecureDirectStatStoreErrors},
		{"kernel_udp_rx_secure_direct_broadcasts", kernelUDPRXSecureDirectStatBroadcasts},
		{"kernel_udp_rx_secure_direct_peer_redirects", kernelUDPRXSecureDirectStatPeerRedirects},
		{"kernel_udp_rx_secure_direct_redirects", kernelUDPRXSecureDirectStatRedirects},
		{"kernel_udp_rx_secure_direct_debug_l2_ipv4", kernelUDPRXSecureDirectStatDebugL2IPv4},
		{"kernel_udp_rx_secure_direct_debug_l3_ipv4", kernelUDPRXSecureDirectStatDebugL3IPv4},
		{"kernel_udp_rx_secure_direct_debug_udp", kernelUDPRXSecureDirectStatDebugUDP},
		{"kernel_udp_rx_secure_direct_debug_tixu_magic", kernelUDPRXSecureDirectStatDebugTIXUMagic},
		{"kernel_udp_rx_secure_direct_debug_tixu_header", kernelUDPRXSecureDirectStatDebugTIXUHeader},
		{"kernel_udp_rx_secure_direct_debug_tixu_flags", kernelUDPRXSecureDirectStatDebugTIXUFlags},
		{"kernel_udp_rx_secure_direct_debug_tixu_len", kernelUDPRXSecureDirectStatDebugTIXULen},
		{"kernel_udp_rx_secure_direct_debug_port", kernelUDPRXSecureDirectStatDebugPort},
		{"kernel_udp_rx_secure_direct_debug_secure_header", kernelUDPRXSecureDirectStatDebugSecureHeader},
		{"kernel_udp_rx_secure_direct_debug_l3_tixu_magic", kernelUDPRXSecureDirectStatDebugL3TIXUMagic},
		{"kernel_udp_rx_secure_direct_kfunc_open_attempts", kernelUDPRXSecureDirectStatDirectKfuncOpenAttempts},
		{"kernel_udp_rx_secure_direct_kfunc_open_errors", kernelUDPRXSecureDirectStatDirectKfuncOpenErrors},
		{"kernel_udp_rx_secure_direct_kfunc_open_einval", kernelUDPRXSecureDirectStatDirectKfuncOpenEINVAL},
		{"kernel_udp_rx_secure_direct_kfunc_open_eopnotsupp", kernelUDPRXSecureDirectStatDirectKfuncOpenEOPNOTSUPP},
		{"kernel_udp_rx_secure_direct_kfunc_open_efault", kernelUDPRXSecureDirectStatDirectKfuncOpenEFAULT},
		{"kernel_udp_rx_secure_direct_kfunc_open_enoent", kernelUDPRXSecureDirectStatDirectKfuncOpenENOENT},
		{"kernel_udp_rx_secure_direct_kfunc_open_ebadmsg", kernelUDPRXSecureDirectStatDirectKfuncOpenEBADMSG},
		{"kernel_udp_rx_secure_direct_kfunc_open_other", kernelUDPRXSecureDirectStatDirectKfuncOpenOther},
		{"kernel_udp_rx_secure_direct_fallback_l2_short", kernelUDPRXSecureDirectStatFallbackL2Short},
		{"kernel_udp_rx_secure_direct_fallback_non_ipv4", kernelUDPRXSecureDirectStatFallbackNonIPv4},
		{"kernel_udp_rx_secure_direct_fallback_ip_header", kernelUDPRXSecureDirectStatFallbackIPHeader},
		{"kernel_udp_rx_secure_direct_fallback_fragment", kernelUDPRXSecureDirectStatFallbackFragment},
		{"kernel_udp_rx_secure_direct_fallback_skb_short", kernelUDPRXSecureDirectStatFallbackSKBShort},
		{"kernel_udp_rx_secure_direct_fallback_linear_short", kernelUDPRXSecureDirectStatFallbackLinearShort},
		{"kernel_udp_rx_secure_direct_fallback_non_udp_tcp", kernelUDPRXSecureDirectStatFallbackNonUDPTCP},
		{"kernel_udp_rx_secure_direct_fallback_udp_len", kernelUDPRXSecureDirectStatFallbackUDPLen},
		{"kernel_udp_rx_secure_direct_fallback_port_miss", kernelUDPRXSecureDirectStatFallbackPortMiss},
		{"kernel_udp_rx_secure_direct_fallback_tixu_flags", kernelUDPRXSecureDirectStatFallbackTIXUFlags},
		{"kernel_udp_rx_secure_direct_fallback_tixu_len", kernelUDPRXSecureDirectStatFallbackTIXULen},
		{"kernel_udp_tx_secure_direct_kfunc_seal_attempts", kernelUDPTXSecureDirectStatDirectKfuncSealAttempts},
		{"kernel_udp_tx_secure_direct_kfunc_seal_errors", kernelUDPTXSecureDirectStatDirectKfuncSealErrors},
		{"kernel_udp_tx_secure_direct_kfunc_seal_einval", kernelUDPTXSecureDirectStatDirectKfuncSealEINVAL},
		{"kernel_udp_tx_secure_direct_kfunc_seal_eopnotsupp", kernelUDPTXSecureDirectStatDirectKfuncSealEOPNOTSUPP},
		{"kernel_udp_tx_secure_direct_kfunc_seal_efault", kernelUDPTXSecureDirectStatDirectKfuncSealEFAULT},
		{"kernel_udp_tx_secure_direct_kfunc_seal_enoent", kernelUDPTXSecureDirectStatDirectKfuncSealENOENT},
		{"kernel_udp_tx_secure_direct_kfunc_seal_ebadmsg", kernelUDPTXSecureDirectStatDirectKfuncSealEBADMSG},
		{"kernel_udp_tx_secure_direct_kfunc_seal_other", kernelUDPTXSecureDirectStatDirectKfuncSealOther},
		{"kernel_udp_tx_secure_direct_tcp_mss_candidates", kernelUDPTXSecureDirectStatTCPMSSCandidates},
		{"kernel_udp_tx_secure_direct_tcp_mss_clamps", kernelUDPTXSecureDirectStatTCPMSSClamps},
		{"kernel_udp_tx_secure_direct_tcp_mss_noops", kernelUDPTXSecureDirectStatTCPMSSNoops},
		{"kernel_udp_tx_secure_direct_tcp_mss_errors", kernelUDPTXSecureDirectStatTCPMSSErrors},
		{"kernel_udp_tx_direct_mtu_linear_fallbacks", kernelUDPTXDirectStatMTULinearFallbacks},
		{"kernel_udp_tx_direct_mtu_gso_fallbacks", kernelUDPTXDirectStatMTUGSOFallbacks},
		{"kernel_udp_tx_direct_mtu_gso_size_zero_fallbacks", kernelUDPTXDirectStatMTUGSOSizeZeroFallbacks},
		{"kernel_udp_tx_direct_mtu_gso_bypasses", kernelUDPTXDirectStatMTUGSOBypasses},
		{"kernel_udp_tx_direct_only_drops", kernelUDPTXDirectStatDirectOnlyDrops},
		{"kernel_udp_tx_direct_inner_udp_checksum_fixes", kernelUDPTXDirectStatInnerUDPChecksumFixes},
		{"kernel_udp_tx_direct_inner_udp_checksum_store_errors", kernelUDPTXDirectStatInnerUDPChecksumStoreErrors},
		{"kernel_udp_tx_direct_inner_udp_checksum_invalid", kernelUDPTXDirectStatInnerUDPChecksumInvalid},
		{"kernel_udp_tx_direct_gso_inputs", kernelUDPTXDirectStatGSOInputs},
		{"kernel_udp_tx_direct_gso_active_accepts", kernelUDPTXDirectStatGSOActiveAccepts},
		{"kernel_udp_tx_direct_linear_accepts", kernelUDPTXDirectStatLinearAccepts},
		{"kernel_udp_tx_direct_gso_successes", kernelUDPTXDirectStatGSOSuccesses},
		{"kernel_udp_tx_direct_outer_tcp_checksum_kfunc_fixes", kernelUDPTXDirectStatOuterTCPChecksumKfuncFixes},
		{"kernel_udp_tx_direct_outer_tcp_checksum_kfunc_drops", kernelUDPTXDirectStatOuterTCPChecksumKfuncDrops},
		{"kernel_udp_tx_direct_route_tcp_gso_successes", kernelUDPTXDirectStatRouteTCPGSOSuccesses},
		{"kernel_udp_tx_direct_route_tcp_gso_fallbacks", kernelUDPTXDirectStatRouteTCPGSOFallbacks},
		{"kernel_udp_tx_direct_route_tcp_gso_drops", kernelUDPTXDirectStatRouteTCPGSODrops},
		{"kernel_udp_tx_direct_route_tcp_xmit_successes", kernelUDPTXDirectStatRouteTCPXmitSuccesses},
		{"kernel_udp_tx_direct_route_tcp_xmit_fallbacks", kernelUDPTXDirectStatRouteTCPXmitFallbacks},
		{"kernel_udp_tx_direct_route_tcp_xmit_drops", kernelUDPTXDirectStatRouteTCPXmitDrops},
		{"kernel_udp_tx_direct_push_flow_tcp_header_kfunc_successes", kernelUDPTXDirectStatPushFlowTCPHeaderKfuncSuccesses},
		{"kernel_udp_tx_direct_push_flow_tcp_header_kfunc_einval", kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEINVAL},
		{"kernel_udp_tx_direct_push_flow_tcp_header_kfunc_eprotonosupport", kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEPROTONOSUPPORT},
		{"kernel_udp_tx_direct_push_flow_tcp_header_kfunc_enomem", kernelUDPTXDirectStatPushFlowTCPHeaderKfuncENOMEM},
		{"kernel_udp_tx_direct_push_flow_tcp_header_kfunc_emsgsize", kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEMSGSIZE},
		{"kernel_udp_tx_direct_push_flow_tcp_header_kfunc_other_drops", kernelUDPTXDirectStatPushFlowTCPHeaderKfuncOtherDrops},
		{"kernel_udp_tx_direct_push_flow_tcp_header_kfunc_efault", kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEFAULT},
		{"kernel_udp_tx_direct_push_flow_tcp_header_kfunc_eio", kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEIO},
		{"kernel_udp_tx_direct_push_flow_tcp_header_kfunc_ebadmsg", kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEBADMSG},
		{"kernel_udp_tx_direct_push_flow_tcp_header_kfunc_enodev", kernelUDPTXDirectStatPushFlowTCPHeaderKfuncENODEV},
		{"kernel_udp_tx_direct_push_flow_tcp_header_kfunc_eperm", kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEPERM},
		{"kernel_udp_tx_direct_push_flow_tcp_header_kfunc_enospc", kernelUDPTXDirectStatPushFlowTCPHeaderKfuncENOSPC},
		{"kernel_udp_tx_direct_push_flow_tcp_header_kfunc_eagain", kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEAGAIN},
		{"kernel_udp_rx_direct_frame_header_errors", kernelUDPRXDirectStatFrameHeaderErrors},
		{"kernel_udp_rx_direct_inner_header_errors", kernelUDPRXDirectStatInnerHeaderErrors},
		{"kernel_udp_rx_direct_inner_len_errors", kernelUDPRXDirectStatInnerLenErrors},
		{"kernel_udp_rx_direct_outer_len_errors", kernelUDPRXDirectStatOuterLenErrors},
		{"kernel_udp_rx_direct_gso_tail_segments", kernelUDPRXDirectStatGSOTailSegments},
		{"kernel_udp_rx_direct_adjust_drops", kernelUDPRXDirectStatAdjustDrops},
		{"kernel_udp_rx_direct_store_drops", kernelUDPRXDirectStatStoreDrops},
		{"kernel_udp_rx_direct_local_deliveries", kernelUDPRXDirectStatLocalDeliveries},
		{"tc_ttl_exceeded_icmp_generated", tcTTLExceededICMPGeneratedStat},
		{"tc_ttl_exceeded_icmp_errors", tcTTLExceededICMPErrorsStat},
		{"tc_ttl_exceeded_no_reply_drops", tcTTLExceededNoReplyDropsStat},
		{"tc_ttl_exceeded_fallbacks", tcTTLExceededFallbacksStat},
		{"capture_pull_errors", captureStatPullErrors},
		{"capture_linear_short_errors", captureStatLinearShortErrors},
		{"capture_ethertype_errors", captureStatEtherTypeErrors},
		{"capture_header_short_errors", captureStatHeaderShortErrors},
		{"capture_route_miss_errors", captureStatRouteMissErrors},
		{"capture_ready", captureStatReady},
	} {
		add(item.name, item.key)
	}
}

func TestKernelUDPRXSecureDirectCStatsMatchGoKeys(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "..", "kernel", "bpf", "dataplane", "kernel_udp_rx_kernel_crypto_tc.c"))
	if err != nil {
		t.Fatalf("read kernel_udp RX secure C source: %v", err)
	}
	for macro, want := range map[string]uint32{
		"TRUSTIX_KUDP_RX_SECURE_STAT_ATTEMPTS":                     kernelUDPRXSecureDirectStatAttempts,
		"TRUSTIX_KUDP_RX_SECURE_STAT_CANDIDATES":                   kernelUDPRXSecureDirectStatCandidates,
		"TRUSTIX_KUDP_RX_SECURE_STAT_SUCCESSES":                    kernelUDPRXSecureDirectStatSuccess,
		"TRUSTIX_KUDP_RX_SECURE_STAT_FALLBACKS":                    kernelUDPRXSecureDirectStatFallbacks,
		"TRUSTIX_KUDP_RX_SECURE_STAT_NO_CONTEXT":                   kernelUDPRXSecureDirectStatNoContext,
		"TRUSTIX_KUDP_RX_SECURE_STAT_HEADER_ERRORS":                kernelUDPRXSecureDirectStatHeaderErrors,
		"TRUSTIX_KUDP_RX_SECURE_STAT_DECRYPT_ERRORS":               kernelUDPRXSecureDirectStatDecryptErrors,
		"TRUSTIX_KUDP_RX_SECURE_STAT_REPLAY_DROPS":                 kernelUDPRXSecureDirectStatReplayDrops,
		"TRUSTIX_KUDP_RX_SECURE_STAT_REPLAY_OLD_DROPS":             kernelUDPRXSecureDirectStatReplayOldDrops,
		"TRUSTIX_KUDP_RX_SECURE_STAT_REPLAY_SEEN_DROPS":            kernelUDPRXSecureDirectStatReplaySeenDrops,
		"TRUSTIX_KUDP_RX_SECURE_STAT_DROPS":                        kernelUDPRXSecureDirectStatDrops,
		"TRUSTIX_KUDP_RX_SECURE_STAT_NEIGH_HITS":                   kernelUDPRXSecureDirectStatNeighHits,
		"TRUSTIX_KUDP_RX_SECURE_STAT_NEIGH_MISSES":                 kernelUDPRXSecureDirectStatNeighMisses,
		"TRUSTIX_KUDP_RX_SECURE_STAT_ADJUST_ERRORS":                kernelUDPRXSecureDirectStatAdjustErrors,
		"TRUSTIX_KUDP_RX_SECURE_STAT_STORE_ERRORS":                 kernelUDPRXSecureDirectStatStoreErrors,
		"TRUSTIX_KUDP_RX_SECURE_STAT_BROADCASTS":                   kernelUDPRXSecureDirectStatBroadcasts,
		"TRUSTIX_KUDP_RX_SECURE_STAT_PEER_REDIRECTS":               kernelUDPRXSecureDirectStatPeerRedirects,
		"TRUSTIX_KUDP_RX_SECURE_STAT_REDIRECTS":                    kernelUDPRXSecureDirectStatRedirects,
		"TRUSTIX_KUDP_RX_SECURE_STAT_DBG_L2_IPV4":                  kernelUDPRXSecureDirectStatDebugL2IPv4,
		"TRUSTIX_KUDP_RX_SECURE_STAT_DBG_L3_IPV4":                  kernelUDPRXSecureDirectStatDebugL3IPv4,
		"TRUSTIX_KUDP_RX_SECURE_STAT_DBG_UDP":                      kernelUDPRXSecureDirectStatDebugUDP,
		"TRUSTIX_KUDP_RX_SECURE_STAT_DBG_TIXU_MAGIC":               kernelUDPRXSecureDirectStatDebugTIXUMagic,
		"TRUSTIX_KUDP_RX_SECURE_STAT_DBG_TIXU_HEADER":              kernelUDPRXSecureDirectStatDebugTIXUHeader,
		"TRUSTIX_KUDP_RX_SECURE_STAT_DBG_TIXU_FLAGS":               kernelUDPRXSecureDirectStatDebugTIXUFlags,
		"TRUSTIX_KUDP_RX_SECURE_STAT_DBG_TIXU_LEN":                 kernelUDPRXSecureDirectStatDebugTIXULen,
		"TRUSTIX_KUDP_RX_SECURE_STAT_DBG_PORT":                     kernelUDPRXSecureDirectStatDebugPort,
		"TRUSTIX_KUDP_RX_SECURE_STAT_DBG_SECURE_HEADER":            kernelUDPRXSecureDirectStatDebugSecureHeader,
		"TRUSTIX_KUDP_RX_SECURE_STAT_DBG_L3_TIXU_MAGIC":            kernelUDPRXSecureDirectStatDebugL3TIXUMagic,
		"TRUSTIX_KUDP_RX_SECURE_STAT_ERR_PAYLOAD_LEN":              kernelUDPRXSecureDirectStatErrPayloadLen,
		"TRUSTIX_KUDP_RX_SECURE_STAT_ERR_CIPHER_LEN":               kernelUDPRXSecureDirectStatErrCipherLen,
		"TRUSTIX_KUDP_RX_SECURE_STAT_ERR_SECURE_MAGIC":             kernelUDPRXSecureDirectStatErrSecureMagic,
		"TRUSTIX_KUDP_RX_SECURE_STAT_ERR_SECURE_EPOCH":             kernelUDPRXSecureDirectStatErrSecureEpoch,
		"TRUSTIX_KUDP_RX_SECURE_STAT_ERR_CTX_EPOCH":                kernelUDPRXSecureDirectStatErrContextEpoch,
		"TRUSTIX_KUDP_RX_SECURE_STAT_ERR_OPEN_EINVAL":              kernelUDPRXSecureDirectStatErrOpenEINVAL,
		"TRUSTIX_KUDP_RX_SECURE_STAT_ERR_OPEN_EBADMSG":             kernelUDPRXSecureDirectStatErrOpenEBADMSG,
		"TRUSTIX_KUDP_RX_SECURE_STAT_ERR_INNER_IPV4":               kernelUDPRXSecureDirectStatErrInnerIPv4,
		"TRUSTIX_KUDP_RX_SECURE_STAT_DIRECT_KFUNC_OPEN_ATTEMPTS":   kernelUDPRXSecureDirectStatDirectKfuncOpenAttempts,
		"TRUSTIX_KUDP_RX_SECURE_STAT_DIRECT_KFUNC_OPEN_ERRORS":     kernelUDPRXSecureDirectStatDirectKfuncOpenErrors,
		"TRUSTIX_KUDP_RX_SECURE_STAT_DIRECT_KFUNC_OPEN_EINVAL":     kernelUDPRXSecureDirectStatDirectKfuncOpenEINVAL,
		"TRUSTIX_KUDP_RX_SECURE_STAT_DIRECT_KFUNC_OPEN_EOPNOTSUPP": kernelUDPRXSecureDirectStatDirectKfuncOpenEOPNOTSUPP,
		"TRUSTIX_KUDP_RX_SECURE_STAT_DIRECT_KFUNC_OPEN_EFAULT":     kernelUDPRXSecureDirectStatDirectKfuncOpenEFAULT,
		"TRUSTIX_KUDP_RX_SECURE_STAT_DIRECT_KFUNC_OPEN_ENOENT":     kernelUDPRXSecureDirectStatDirectKfuncOpenENOENT,
		"TRUSTIX_KUDP_RX_SECURE_STAT_DIRECT_KFUNC_OPEN_EBADMSG":    kernelUDPRXSecureDirectStatDirectKfuncOpenEBADMSG,
		"TRUSTIX_KUDP_RX_SECURE_STAT_DIRECT_KFUNC_OPEN_OTHER":      kernelUDPRXSecureDirectStatDirectKfuncOpenOther,
		"TRUSTIX_KUDP_RX_SECURE_STAT_FALLBACK_L2_SHORT":            kernelUDPRXSecureDirectStatFallbackL2Short,
		"TRUSTIX_KUDP_RX_SECURE_STAT_FALLBACK_NON_IPV4":            kernelUDPRXSecureDirectStatFallbackNonIPv4,
		"TRUSTIX_KUDP_RX_SECURE_STAT_FALLBACK_IP_HEADER":           kernelUDPRXSecureDirectStatFallbackIPHeader,
		"TRUSTIX_KUDP_RX_SECURE_STAT_FALLBACK_FRAGMENT":            kernelUDPRXSecureDirectStatFallbackFragment,
		"TRUSTIX_KUDP_RX_SECURE_STAT_FALLBACK_SKB_SHORT":           kernelUDPRXSecureDirectStatFallbackSKBShort,
		"TRUSTIX_KUDP_RX_SECURE_STAT_FALLBACK_LINEAR_SHORT":        kernelUDPRXSecureDirectStatFallbackLinearShort,
		"TRUSTIX_KUDP_RX_SECURE_STAT_FALLBACK_NON_UDP_TCP":         kernelUDPRXSecureDirectStatFallbackNonUDPTCP,
		"TRUSTIX_KUDP_RX_SECURE_STAT_FALLBACK_UDP_LEN":             kernelUDPRXSecureDirectStatFallbackUDPLen,
		"TRUSTIX_KUDP_RX_SECURE_STAT_FALLBACK_PORT_MISS":           kernelUDPRXSecureDirectStatFallbackPortMiss,
		"TRUSTIX_KUDP_RX_SECURE_STAT_FALLBACK_TIXU_FLAGS":          kernelUDPRXSecureDirectStatFallbackTIXUFlags,
		"TRUSTIX_KUDP_RX_SECURE_STAT_FALLBACK_TIXU_LEN":            kernelUDPRXSecureDirectStatFallbackTIXULen,
	} {
		line := []byte(fmt.Sprintf("#define %s %d", macro, want))
		if !bytes.Contains(source, line) {
			t.Fatalf("C source missing %q", string(line))
		}
	}
}

func TestKernelUDPTXSecureDirectCStatsMatchGoKeys(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "..", "kernel", "bpf", "dataplane", "kernel_udp_tx_kernel_crypto_tc.c"))
	if err != nil {
		t.Fatalf("read kernel_udp TX secure C source: %v", err)
	}
	for macro, want := range map[string]uint32{
		"TRUSTIX_KUDP_TX_SECURE_STAT_ATTEMPTS":                             kernelUDPTXSecureDirectStatAttempts,
		"TRUSTIX_KUDP_TX_SECURE_STAT_CANDIDATES":                           kernelUDPTXSecureDirectStatCandidates,
		"TRUSTIX_KUDP_TX_SECURE_STAT_SUCCESSES":                            kernelUDPTXSecureDirectStatSuccess,
		"TRUSTIX_KUDP_TX_SECURE_STAT_FALLBACKS":                            kernelUDPTXSecureDirectStatFallbacks,
		"TRUSTIX_KUDP_TX_SECURE_STAT_NO_CONTEXT":                           kernelUDPTXSecureDirectStatNoContext,
		"TRUSTIX_KUDP_TX_SECURE_STAT_HEADER_ERRORS":                        kernelUDPTXSecureDirectStatHeaderErrors,
		"TRUSTIX_KUDP_TX_SECURE_STAT_ENCRYPT_ERRORS":                       kernelUDPTXSecureDirectStatEncryptErrors,
		"TRUSTIX_KUDP_TX_SECURE_STAT_SEQUENCE_ERRORS":                      kernelUDPTXSecureDirectStatSequenceErrors,
		"TRUSTIX_KUDP_TX_SECURE_STAT_MTU_FALLBACKS":                        kernelUDPTXSecureDirectStatMTUFallbacks,
		"TRUSTIX_KUDP_TX_SECURE_STAT_DROPS":                                kernelUDPTXSecureDirectStatDrops,
		"TRUSTIX_KUDP_TX_SECURE_STAT_ROUTE_MISSES":                         kernelUDPTXSecureDirectStatRouteMisses,
		"TRUSTIX_KUDP_TX_SECURE_STAT_FLOW_MISSES":                          kernelUDPTXSecureDirectStatFlowMisses,
		"TRUSTIX_KUDP_TX_SECURE_STAT_FLAG_MISSES":                          kernelUDPTXSecureDirectStatFlagMisses,
		"TRUSTIX_KUDP_TX_SECURE_STAT_FRAGMENT_FALLBACKS":                   kernelUDPTXSecureDirectStatFragmentFallbacks,
		"TRUSTIX_KUDP_TX_SECURE_STAT_LEN_MISMATCHES":                       kernelUDPTXSecureDirectStatLenMismatches,
		"TRUSTIX_KUDP_TX_SECURE_STAT_NON_TCP_FALLBACKS":                    kernelUDPTXSecureDirectStatNonTCPFallbacks,
		"TRUSTIX_KUDP_TX_SECURE_STAT_SYN_FALLBACKS":                        kernelUDPTXSecureDirectStatSYNFallbacks,
		"TRUSTIX_KUDP_TX_SECURE_STAT_CHECKSUM_FALLBACKS":                   kernelUDPTXSecureDirectStatChecksumFallbacks,
		"TRUSTIX_KUDP_TX_SECURE_STAT_MTU_PLAIN_MAX_FALLBACKS":              kernelUDPTXSecureDirectStatMTUPlainMaxFallbacks,
		"TRUSTIX_KUDP_TX_SECURE_STAT_MTU_UNDERLAY_FALLBACKS":               kernelUDPTXSecureDirectStatMTUUnderlayFallbacks,
		"TRUSTIX_KUDP_TX_SECURE_STAT_LEN_GSO_FALLBACKS":                    kernelUDPTXSecureDirectStatLenGSOFallbacks,
		"TRUSTIX_KUDP_TX_SECURE_STAT_LEN_SHORT_FALLBACKS":                  kernelUDPTXSecureDirectStatLenShortFallbacks,
		"TRUSTIX_KUDP_TX_SECURE_STAT_MTU_UNDERLAY_1500ISH_FALLBACKS":       kernelUDPTXSecureDirectStatMTUUnderlay1500Fallbacks,
		"TRUSTIX_KUDP_TX_SECURE_STAT_MTU_UNDERLAY_JUMBO_FALLBACKS":         kernelUDPTXSecureDirectStatMTUUnderlayJumboFallbacks,
		"TRUSTIX_KUDP_TX_SECURE_STAT_MTU_UNDERLAY_INNER_GT_1400_FALLBACKS": kernelUDPTXSecureDirectStatMTUUnderlayInnerGT1400Fallbacks,
		"TRUSTIX_KUDP_TX_SECURE_STAT_MTU_UNDERLAY_INNER_LE_1400_FALLBACKS": kernelUDPTXSecureDirectStatMTUUnderlayInnerLE1400Fallbacks,
		"TRUSTIX_KUDP_TX_SECURE_STAT_DIRECT_KFUNC_SEAL_ATTEMPTS":           kernelUDPTXSecureDirectStatDirectKfuncSealAttempts,
		"TRUSTIX_KUDP_TX_SECURE_STAT_DIRECT_KFUNC_SEAL_ERRORS":             kernelUDPTXSecureDirectStatDirectKfuncSealErrors,
		"TRUSTIX_KUDP_TX_SECURE_STAT_DIRECT_KFUNC_SEAL_EINVAL":             kernelUDPTXSecureDirectStatDirectKfuncSealEINVAL,
		"TRUSTIX_KUDP_TX_SECURE_STAT_DIRECT_KFUNC_SEAL_EOPNOTSUPP":         kernelUDPTXSecureDirectStatDirectKfuncSealEOPNOTSUPP,
		"TRUSTIX_KUDP_TX_SECURE_STAT_DIRECT_KFUNC_SEAL_EFAULT":             kernelUDPTXSecureDirectStatDirectKfuncSealEFAULT,
		"TRUSTIX_KUDP_TX_SECURE_STAT_DIRECT_KFUNC_SEAL_ENOENT":             kernelUDPTXSecureDirectStatDirectKfuncSealENOENT,
		"TRUSTIX_KUDP_TX_SECURE_STAT_DIRECT_KFUNC_SEAL_EBADMSG":            kernelUDPTXSecureDirectStatDirectKfuncSealEBADMSG,
		"TRUSTIX_KUDP_TX_SECURE_STAT_DIRECT_KFUNC_SEAL_OTHER":              kernelUDPTXSecureDirectStatDirectKfuncSealOther,
		"TRUSTIX_KUDP_TX_SECURE_STAT_TCP_MSS_CANDIDATES":                   kernelUDPTXSecureDirectStatTCPMSSCandidates,
		"TRUSTIX_KUDP_TX_SECURE_STAT_TCP_MSS_CLAMPS":                       kernelUDPTXSecureDirectStatTCPMSSClamps,
		"TRUSTIX_KUDP_TX_SECURE_STAT_TCP_MSS_NOOPS":                        kernelUDPTXSecureDirectStatTCPMSSNoops,
		"TRUSTIX_KUDP_TX_SECURE_STAT_TCP_MSS_ERRORS":                       kernelUDPTXSecureDirectStatTCPMSSErrors,
	} {
		line := []byte(fmt.Sprintf("#define %s %d", macro, want))
		if !bytes.Contains(source, line) {
			t.Fatalf("C source missing %q", string(line))
		}
	}
}

func TestKernelUDPTXSecureDirectBypassesRouteFlag(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "..", "kernel", "bpf", "dataplane", "kernel_udp_tx_kernel_crypto_tc.c"))
	if err != nil {
		t.Fatalf("read kernel_udp TX secure C source: %v", err)
	}
	macro := []byte(fmt.Sprintf("#define TRUSTIX_KUDP_TX_ROUTE_FLAG_BYPASS %d", kernelUDPTXRouteFlagBypass))
	if !bytes.Contains(source, macro) {
		t.Fatalf("C source missing %q", string(macro))
	}
	bodyStart := bytes.Index(source, []byte("int trustix_kudp_tx_secure(struct __sk_buff *skb)"))
	if bodyStart < 0 {
		t.Fatal("kernel_udp TX secure classifier entry not found")
	}
	body := source[bodyStart:]
	lookup := bytes.Index(body, []byte("route = bpf_map_lookup_elem(&ix_kudp_tx_route, &route_key);"))
	bypass := bytes.Index(body, []byte("if (route->flags & TRUSTIX_KUDP_TX_ROUTE_FLAG_BYPASS)\n        return TC_ACT_UNSPEC;"))
	selectFlow := bytes.Index(body, []byte("flow_id = trustix_kudp_select_route_flow(route, data, data_end);"))
	if lookup < 0 || bypass < 0 || selectFlow < 0 {
		t.Fatalf("secure route lookup/bypass/select not found: lookup=%d bypass=%d select=%d", lookup, bypass, selectFlow)
	}
	if !(lookup < bypass && bypass < selectFlow) {
		t.Fatalf("secure bypass must run after route lookup and before flow selection: lookup=%d bypass=%d select=%d", lookup, bypass, selectFlow)
	}
}

func TestKernelUDPTXSecureDirectEncryptsTCPSYNBeforeFallback(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "..", "kernel", "bpf", "dataplane", "kernel_udp_tx_kernel_crypto_tc.c"))
	if err != nil {
		t.Fatalf("read kernel_udp TX secure C source: %v", err)
	}
	bodyStart := bytes.Index(source, []byte("int trustix_kudp_tx_secure(struct __sk_buff *skb)"))
	if bodyStart < 0 {
		t.Fatal("kernel_udp TX secure classifier entry not found")
	}
	body := source[bodyStart:]
	syn := bytes.Index(body, []byte("goto syn_fallback"))
	if syn >= 0 {
		t.Fatal("kernel_udp TX secure direct still falls back TCP SYN packets before encryption")
	}
	clamp := bytes.Index(source, []byte("trustix_clamp_inner_tcp_mss(scratch, inner_len, mss_clamp)"))
	if clamp < 0 {
		t.Fatal("kernel_udp TX secure direct does not clamp TCP SYN MSS inside the encrypt path")
	}
	guard := []byte("if (trustix_inner_tcp_syn_candidate(scratch, inner_len))")
	if got := bytes.Count([]byte(sourceFunctionBody(t, string(source), "trustix_encrypt_inner_ipv4")), guard); got != 1 {
		t.Fatalf("kernel_udp TX secure direct shared MSS clamp guard count = %d, want 1", got)
	}
	if !bytes.Contains(source, []byte("? TRUSTIX_TIX_TCP_SECURE_OUTER_OVERHEAD")) ||
		!bytes.Contains(source, []byte(": TRUSTIX_KUDP_SECURE_OUTER_OVERHEAD")) {
		t.Fatal("kernel_udp TX secure direct MSS clamp does not select tix_tcp and kernel_udp overheads in the shared encrypt path")
	}
	encrypt := bytes.Index(body, []byte("cipher_len = trustix_encrypt_inner_ipv4"))
	if encrypt < 0 {
		t.Fatal("kernel_udp TX secure direct encrypt call not found")
	}
	mtu := bytes.Index(body, []byte("outer_len = inner_len + outer_overhead"))
	if mtu < 0 {
		t.Fatal("kernel_udp TX secure direct MTU check setup not found")
	}
	if mtu > encrypt {
		t.Fatalf("secure direct MTU check must occur before encrypt: mtu=%d encrypt=%d", mtu, encrypt)
	}
}

func TestKernelUDPTXSecureDirectTIXTCPComputesOuterChecksum(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "..", "kernel", "bpf", "dataplane", "kernel_udp_tx_kernel_crypto_tc.c"))
	if err != nil {
		t.Fatalf("read kernel_udp TX secure C source: %v", err)
	}
	if !bytes.Contains(source, []byte("static __noinline int trustix_tix_tcp_outer_checksum")) {
		t.Fatal("tix_tcp secure TX outer TCP checksum helper not found")
	}
	if !bytes.Contains(source, []byte("trustix_kudp_tx_secure_outer_tcp_csum_kfunc")) {
		t.Fatal("tix_tcp secure TX outer TCP checksum kfunc gate not found")
	}
	if !bytes.Contains(source, []byte("trustix_kudp_tx_secure_outer_tcp_partial_csum_kfunc")) {
		t.Fatal("tix_tcp secure TX outer TCP partial checksum kfunc gate not found")
	}
	bodyStart := bytes.Index(source, []byte("int trustix_kudp_tx_secure(struct __sk_buff *skb)"))
	if bodyStart < 0 {
		t.Fatal("kernel_udp TX secure classifier entry not found")
	}
	body := source[bodyStart:]
	condition := bytes.Index(body, []byte("if (!skb_sealed && tix_tcp && !outer_tcp_csum_kfunc &&\n        !(flow->flags & TRUSTIX_KUDP_TX_FLOW_FLAG_SKIP_OUTER_TCP_CHECKSUM))"))
	if condition < 0 {
		t.Fatal("tix_tcp secure TX does not gate checksum generation on the explicit skip flag")
	}
	compute := bytes.Index(body, []byte("trustix_tix_tcp_outer_checksum(scratch, (__u32)cipher_len, &outer_tcp_checksum)"))
	if compute < 0 {
		t.Fatal("tix_tcp secure TX outer checksum helper is not called")
	}
	if !bytes.Contains(body, []byte("if (!skb_sealed && tix_tcp && !outer_tcp_csum_kfunc")) {
		t.Fatal("tix_tcp secure TX pre-adjust checksum is not gated by the kfunc checksum path")
	}
	store := bytes.Index(body, []byte("trustix_write_be16(scratch->io.split.header + 50, outer_tcp_checksum)"))
	if store < 0 {
		t.Fatal("tix_tcp secure TX outer checksum is not written to the TCP header")
	}
	adjust := bytes.Index(body, []byte("bpf_skb_adjust_room"))
	if adjust < 0 {
		t.Fatal("kernel_udp TX secure adjust_room call not found")
	}
	if condition > compute || compute > store || store > adjust {
		t.Fatalf("outer TCP checksum must be computed and stored before adjust_room: condition=%d compute=%d store=%d adjust=%d", condition, compute, store, adjust)
	}
	postStore := bytes.Index(body, []byte("trustix_store_cipher_to_packet(skb, cipher_offset, scratch, (__u32)cipher_len)"))
	kfunc := bytes.Index(body, []byte("trustix_kernel_skb_tixt_fix_outer_tcp_csum(skb, csum_flags)"))
	if postStore < 0 || kfunc < 0 || postStore > kfunc {
		t.Fatalf("outer TCP checksum kfunc must run after ciphertext is stored: store=%d kfunc=%d", postStore, kfunc)
	}
	partialFlag := bytes.Index(body, []byte("TRUSTIX_TIXT_TX_FINALIZE_TCP_PARTIAL_CSUM"))
	if partialFlag < 0 || partialFlag > kfunc {
		t.Fatalf("outer TCP partial checksum flag must be selected before the kfunc call: flag=%d kfunc=%d", partialFlag, kfunc)
	}
}

func TestKernelUDPTXSecureDirectOuterTCPChecksumKfuncCompiledOutByDefault(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "..", "kernel", "bpf", "dataplane", "kernel_udp_tx_kernel_crypto_tc.c"))
	if err != nil {
		t.Fatalf("read kernel_udp TX secure C source: %v", err)
	}
	requireSourceContains(t, string(source), "#define TRUSTIX_KUDP_SECURE_OUTER_TCP_CSUM_KFUNC 0")
	requireSourceContains(t, string(source), "#if TRUSTIX_KUDP_SECURE_OUTER_TCP_CSUM_KFUNC\nextern int trustix_kernel_skb_tixt_fix_outer_tcp_csum")
	requireSourceContains(t, string(source), "#if TRUSTIX_KUDP_SECURE_OUTER_TCP_CSUM_KFUNC\n        __u32 csum_flags = outer_tcp_partial_csum_kfunc ?")

	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_OUTER_TCP_CHECKSUM_KFUNC", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_OUTER_TCP_PARTIAL_CHECKSUM_KFUNC", "1")
	options := kernelUDPTXSecureDirectProgramOptionsForSpec(dataplane.AttachSpec{})
	if options.OuterTCPChecksumKfunc || options.OuterTCPPartialCSUMKfunc {
		t.Fatalf("outer TCP checksum kfunc options enabled with embedded object compiled without support: %+v", options)
	}
}

func TestKernelUDPTXSecureDirectBoundsInnerUDPChecksumLength(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "..", "kernel", "bpf", "dataplane", "kernel_udp_tx_kernel_crypto_tc.c"))
	if err != nil {
		t.Fatalf("read kernel_udp TX secure C source: %v", err)
	}

	l4Body := sourceFunctionBody(t, string(source), "trustix_l4_checksum")
	requireSourceContains(t, l4Body, "l4_len > TRUSTIX_KERNEL_CRYPTO_PLAIN_MAX - 20")
	requireSourceContains(t, l4Body, "barrier_var(l4_len);")

	fixBody := sourceFunctionBody(t, string(source), "trustix_fix_inner_checksums")
	requireSourceContains(t, fixBody, "udp_len > TRUSTIX_KERNEL_CRYPTO_PLAIN_MAX - 20")
	requireSourceContains(t, fixBody, "barrier_var(udp_len);")
}

func TestKernelUDPTXSecureDirectCanFixInnerChecksumsWithoutTrustFlag(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "..", "kernel", "bpf", "dataplane", "kernel_udp_tx_kernel_crypto_tc.c"))
	if err != nil {
		t.Fatalf("read kernel_udp TX secure C source: %v", err)
	}
	gate := []byte("if (!trustix_kudp_tx_fix_inner_checksums &&\n        !(flow->flags & TRUSTIX_KUDP_TX_FLOW_FLAG_TRUST_INNER_CHECKSUM))")
	if got := bytes.Count(source, gate); got != 1 {
		t.Fatalf("secure direct checksum gate count = %d, want 1 shared fallback path", got)
	}
	legacyGate := []byte("if (!(flow->flags & TRUSTIX_KUDP_TX_FLOW_FLAG_TRUST_INNER_CHECKSUM))")
	if bytes.Contains(source, legacyGate) {
		t.Fatal("secure direct still requires trusted inner checksums before the checksum-fix compatibility path")
	}
}

func TestKernelUDPTXSecureDirectRouteGSOPassesTrustPartialInnerChecksum(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "..", "kernel", "bpf", "dataplane", "kernel_udp_tx_kernel_crypto_tc.c"))
	if err != nil {
		t.Fatalf("read kernel_udp TX secure C source: %v", err)
	}
	body := sourceFunctionBody(t, string(source), "trustix_secure_route_gso_direct")
	requireSourceContains(t, string(source), "#define TRUSTIX_KUDP_SECURE_ROUTE_GSO_KFUNC 0")
	requireSourceContains(t, string(source), "#if TRUSTIX_KUDP_SECURE_ROUTE_GSO_KFUNC\nextern int trustix_kernel_skb_tixt_tx_segment_secure_route_tcp_gso")
	requireSourceContains(t, body, "TRUSTIX_TIXT_TX_FINALIZE_TCP_TRUST_PARTIAL_INNER_CSUM")
	requireSourceContains(t, body, "if (!trustix_kudp_tx_fix_inner_checksums &&")
	requireSourceContains(t, body, "(flow->flags & TRUSTIX_KUDP_TX_FLOW_FLAG_TRUST_INNER_CHECKSUM)")
	requireSourceContains(t, body, "#if TRUSTIX_KUDP_SECURE_ROUTE_GSO_KFUNC")
}

func TestKernelUDPTXSecureDirectRouteGSOUsesDedicatedEmbeddedObject(t *testing.T) {
	loader, err := os.ReadFile("kernel_udp_tx_kernel_crypto_tc_linux.go")
	if err != nil {
		t.Fatalf("read kernel_udp TX secure loader: %v", err)
	}
	for _, want := range []string{
		"bpf/kernel_udp_tx_kernel_crypto_tc_bpfel.o bpf/kernel_udp_tx_kernel_crypto_tc_routegso_bpfel.o",
		`kernelUDPTXSecureDirectRouteGSOObjectName            = "kernel_udp_tx_kernel_crypto_tc_routegso_bpfel.o"`,
		"if options.SecureRouteTCPGSOKfunc {",
		"objectName = kernelUDPTXSecureDirectRouteGSOObjectName",
	} {
		if !bytes.Contains(loader, []byte(want)) {
			t.Fatalf("kernel_udp TX secure loader missing %q", want)
		}
	}

	builder, err := os.ReadFile(filepath.Join("..", "..", "..", "scripts", "build-embedded-bpf.sh"))
	if err != nil {
		t.Fatalf("read build-embedded-bpf.sh: %v", err)
	}
	if !bytes.Contains(builder, []byte("kernel_udp_tx_kernel_crypto_tc_routegso_bpfel.o|kernel/bpf/dataplane/kernel_udp_tx_kernel_crypto_tc.c|-DTRUSTIX_KUDP_SECURE_ROUTE_GSO_KFUNC=1")) {
		t.Fatal("build-embedded-bpf.sh does not build the route-GSO kernel_udp TX secure object")
	}
}

func TestKernelUDPTXSecureDirectRouteGSOHandlesKernelUDP(t *testing.T) {
	txSource, err := os.ReadFile(filepath.Join("..", "..", "..", "kernel", "bpf", "dataplane", "kernel_udp_tx_kernel_crypto_tc.c"))
	if err != nil {
		t.Fatalf("read kernel_udp TX secure C source: %v", err)
	}
	txBody := sourceFunctionBody(t, string(txSource), "trustix_secure_route_gso_direct")
	for _, want := range []string{
		"if (flow->flags & TRUSTIX_KUDP_TX_FLOW_FLAG_TIX_TCP)",
		"key.reserved[0] = TRUSTIX_KERNEL_CRYPTO_NAMESPACE_KERNEL_UDP",
	} {
		requireSourceContains(t, txBody, want)
	}
	if strings.Contains(string(txSource), "if (tix_tcp && data[23] == IPPROTO_TCP)") {
		t.Fatal("secure kernel_udp TX still gates route-GSO on tix_tcp")
	}

	helperSource, err := os.ReadFile(filepath.Join("..", "..", "..", "kernel", "trustix_datapath_helpers", "trustix_datapath_helpers_kfuncs.c"))
	if err != nil {
		t.Fatalf("read TrustIX datapath helper source: %v", err)
	}
	helper := string(helperSource)
	validateBody := sourceFunctionBody(t, helper, "trustix_tixt_tx_validate_route_secure_flow_pulled")
	if strings.Contains(validateBody, "!(flow_flags & TRUSTIX_KUDP_TX_FLOW_FLAG_TIX_TCP)") {
		t.Fatal("secure route-GSO helper still rejects kernel_udp secure flows")
	}
	initBody := sourceFunctionBody(t, helper, "trustix_tixt_tx_init_secure_route_gso_template")
	for _, want := range []string{
		"tmpl->kernel_udp = true;",
		"iph->protocol = IPPROTO_UDP;",
		"kudp[5] = TRUSTIX_KUDP_FLAG_ENCRYPTED | TRUSTIX_KUDP_FLAG_INNER_IPV4;",
		"tmpl->ip_check_base = READ_ONCE(flow->ipv4_check_udp);",
	} {
		requireSourceContains(t, initBody, want)
	}
	streamBody := sourceFunctionBody(t, helper, "trustix_tixt_tx_route_gso_async_try_stream_direct")
	for _, want := range []string{
		"item->tmpl.kernel_udp",
		"trustix_kudp_tx_build_secure_route_gso_frame_skb",
		"sizeof(struct udphdr)",
	} {
		requireSourceContains(t, streamBody, want)
	}
}

func TestKernelUDPTXSecureDirectKfuncSealUsesSplitCipherBuffer(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "..", "kernel", "bpf", "dataplane", "kernel_udp_tx_kernel_crypto_tc.c"))
	if err != nil {
		t.Fatalf("read kernel_udp TX secure C source: %v", err)
	}
	if got := bytes.Count(source, []byte("trustix_kernel_direct_seal(")); got != 2 {
		t.Fatalf("direct seal reference count = %d, want declaration plus shared call site", got)
	}
	if got := bytes.Count(source, []byte("trustix_kernel_direct_seal(direct_slot->slot_id, scratch->plain")); got != 1 {
		t.Fatalf("direct seal call count = %d, want shared kernel_udp and tix_tcp path", got)
	}
	if got := bytes.Count(source, []byte("scratch->io.split.cipher")); got < 3 {
		t.Fatalf("split cipher buffer references = %d, want direct seal plus dynptr fallback users", got)
	}
	if bytes.Contains(source, []byte("trustix_kernel_direct_seal(*slot_index, scratch->plain,\n                                           scratch->plain")) ||
		bytes.Contains(source, []byte("trustix_kernel_direct_seal(*slot_index, scratch->plain, scratch->plain")) {
		t.Fatal("secure direct kfunc seal still uses in-place plain buffer output")
	}
}

func TestKernelUDPSecureDirectKfuncsUseDirectSlotMap(t *testing.T) {
	txSource, err := os.ReadFile(filepath.Join("..", "..", "..", "kernel", "bpf", "dataplane", "kernel_udp_tx_kernel_crypto_tc.c"))
	if err != nil {
		t.Fatalf("read kernel_udp TX secure C source: %v", err)
	}
	rxSource, err := os.ReadFile(filepath.Join("..", "..", "..", "kernel", "bpf", "dataplane", "kernel_udp_rx_kernel_crypto_tc.c"))
	if err != nil {
		t.Fatalf("read kernel_udp RX secure C source: %v", err)
	}
	for name, source := range map[string][]byte{
		"tx": txSource,
		"rx": rxSource,
	} {
		if !bytes.Contains(source, []byte("} trustix_kernel_crypto_direct_slots SEC(\".maps\");")) {
			t.Fatalf("%s secure direct source does not declare direct slot map", name)
		}
		if !bytes.Contains(source, []byte("bpf_map_lookup_elem(&trustix_kernel_crypto_direct_slots, slot_index)")) {
			t.Fatalf("%s secure direct source does not look up the direct slot map", name)
		}
		if bytes.Contains(source, []byte("trustix_kernel_direct_seal(*slot_index")) ||
			bytes.Contains(source, []byte("trustix_kernel_direct_open(*slot_index")) {
			t.Fatalf("%s secure direct source passes provider ctx slot directly to .ko kfunc", name)
		}
	}
	txLoader, err := os.ReadFile("kernel_udp_tx_kernel_crypto_tc_linux.go")
	if err != nil {
		t.Fatalf("read kernel_udp TX secure loader: %v", err)
	}
	rxLoader, err := os.ReadFile("kernel_udp_rx_kernel_crypto_tc_linux.go")
	if err != nil {
		t.Fatalf("read kernel_udp RX secure loader: %v", err)
	}
	for name, source := range map[string][]byte{
		"tx-loader": txLoader,
		"rx-loader": rxLoader,
	} {
		if !bytes.Contains(source, []byte("provider.directSlotMap == nil")) {
			t.Fatalf("%s does not require provider direct slot map", name)
		}
		if !bytes.Contains(source, []byte(`"trustix_kernel_crypto_direct_slots":`)) ||
			!bytes.Contains(source, []byte("provider.directSlotMap")) {
			t.Fatalf("%s does not replace trustix_kernel_crypto_direct_slots with provider map", name)
		}
	}
}

func TestKernelUDPTCClassifiersYieldExternalFiltersOnFallback(t *testing.T) {
	for name, path := range map[string]string{
		"tx": filepath.Join("..", "..", "..", "kernel", "bpf", "dataplane", "kernel_udp_tx_kernel_crypto_tc.c"),
		"rx": filepath.Join("..", "..", "..", "kernel", "bpf", "dataplane", "kernel_udp_rx_kernel_crypto_tc.c"),
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read kernel_udp %s secure C source: %v", name, err)
		}
		source := strings.ReplaceAll(string(raw), "\r\n", "\n")
		if !strings.Contains(source, "#define TC_ACT_UNSPEC (-1)") {
			t.Fatalf("%s secure TC source does not define TC_ACT_UNSPEC", name)
		}
		if strings.Contains(source, "return TC_ACT_PIPE") || strings.Contains(source, "return TC_ACT_OK") {
			t.Fatalf("%s secure TC source still has a terminal fallback/pass return", name)
		}
		if !strings.Contains(source, "fallback:\n") || !strings.Contains(source, "return TC_ACT_UNSPEC;") {
			t.Fatalf("%s secure TC fallback does not yield to later filters", name)
		}
	}
}

func TestKernelUDPRXDirectPassYieldsExternalFilters(t *testing.T) {
	source, err := os.ReadFile("manager_linux.go")
	if err != nil {
		t.Fatalf("read manager_linux.go: %v", err)
	}
	if !bytes.Contains(source, []byte("tcActUnspec                                                       = -1")) {
		t.Fatal("manager source does not define TC_ACT_UNSPEC equivalent")
	}
	if !bytes.Contains(source, []byte(`asm.Mov.Imm(asm.R0, tcActUnspec).WithSymbol("kudp_rx_direct_pass")`)) {
		t.Fatal("kernel_udp RX direct pass path does not yield to later TC filters")
	}
	if bytes.Contains(source, []byte(`asm.Mov.Imm(asm.R0, tcActOK).WithSymbol("kudp_rx_direct_pass")`)) {
		t.Fatal("kernel_udp RX direct pass path still terminates TC classification")
	}
}

func TestMainTCMissPathsYieldExternalFilters(t *testing.T) {
	source, err := os.ReadFile("manager_linux.go")
	if err != nil {
		t.Fatalf("read manager_linux.go: %v", err)
	}
	text := strings.ReplaceAll(string(source), "\r\n", "\n")
	for name, needle := range map[string]string{
		"ingress yield exit": `asm.Mov.Imm(asm.R0, tcActUnspec).WithSymbol("yield_exit")`,
		"egress yield exit":  `asm.Mov.Imm(asm.R0, tcActUnspec).WithSymbol("egress_yield_exit")`,
		"egress nat l4 miss": `appendNATBindingLookup(instructions, natBindingMap, "egress_nat_lookup_l4", "egress_nat_l4_binding_fresh", "egress_yield_exit")`,
		"egress nat ip miss": `appendNATBindingLookup(instructions, natBindingMap, "egress_nat_lookup_ip_only", "egress_nat_ip_only_binding_fresh", "egress_yield_exit")`,
	} {
		if !strings.Contains(text, needle) {
			t.Fatalf("%s does not yield to later TC filters", name)
		}
	}
	assertSymbolBlockContains := func(name, startSymbol, endSymbol, needle string) {
		t.Helper()
		startNeedle := fmt.Sprintf(`WithSymbol("%s")`, startSymbol)
		start := strings.Index(text, startNeedle)
		if start < 0 {
			t.Fatalf("%s symbol %q is missing", name, startSymbol)
		}
		endNeedle := fmt.Sprintf(`WithSymbol("%s")`, endSymbol)
		relEnd := strings.Index(text[start+len(startNeedle):], endNeedle)
		if relEnd < 0 {
			t.Fatalf("%s following symbol %q is missing", name, endSymbol)
		}
		block := text[start : start+len(startNeedle)+relEnd]
		if !strings.Contains(block, needle) {
			t.Fatalf("%s does not yield to later TC filters", name)
		}
	}
	assertSymbolBlockContains("ingress route miss", "route_miss", "packet_mtu_drop", `asm.Ja.Label("yield_exit")`)
	assertSymbolBlockContains("ingress non-ipv4", "non_ipv4", "parse_error", `asm.Ja.Label("yield_exit")`)
	if parseError := strings.Index(text, `WithSymbol("parse_error")`); parseError < 0 {
		t.Fatal("ingress parse_error symbol is missing")
	} else if yieldExit := strings.Index(text[parseError:], `WithSymbol("yield_exit")`); yieldExit < 0 {
		t.Fatal("ingress parse_error does not fall through to yield_exit")
	}
	assertSymbolBlockContains("egress parse error", "egress_parse_error", "egress_yield_exit", `asm.Ja.Label("egress_yield_exit")`)
	if strings.Contains(text, `asm.JEq.Imm(asm.R0, 0, "egress_exit"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.Word)`) {
		t.Fatal("egress NAT binding miss still terminates TC classification")
	}
	if strings.Contains(text, `asm.JGT.Reg(asm.R0, asm.R1, "egress_exit"),
		asm.Mov.Imm(asm.R0, 0).WithSymbol(freshLabel)`) {
		t.Fatal("egress expired NAT binding still terminates TC classification")
	}
}

func TestMainTCMissPathsYieldToLaterTCFiltersLive(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("live TC filter test requires Linux")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root to create veth pair and attach TC filters")
	}
	if _, err := exec.LookPath("ping"); err != nil {
		t.Skipf("ping is required for live TC filter test: %v", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for live TC filter test: %v", err)
	}

	t.Run("ingress", func(t *testing.T) {
		runMainTCMissYieldLiveTest(t, netlink.HANDLE_MIN_INGRESS, "198.18.91.1", "198.18.91.2")
	})
	t.Run("egress", func(t *testing.T) {
		runMainTCMissYieldLiveTest(t, netlink.HANDLE_MIN_EGRESS, "198.18.92.1", "198.18.92.2")
	})
}

func runMainTCMissYieldLiveTest(t *testing.T, parent uint32, hostIP string, peerIP string) {
	t.Helper()
	suffix := fmt.Sprintf("%d%d", os.Getpid()%10000, time.Now().UnixNano()%10000)
	if len(suffix) > 8 {
		suffix = suffix[:8]
	}
	hostName := "tixy" + suffix
	peerName := "tixz" + suffix
	_ = netlink.LinkDel(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: hostName}})
	t.Cleanup(func() {
		_ = netlink.LinkDel(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: hostName}})
		_ = netlink.LinkDel(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: peerName}})
	})
	if err := netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: hostName},
		PeerName:  peerName,
	}); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("requires CAP_NET_ADMIN to create veth pair: %v", err)
		}
		t.Fatalf("create veth pair: %v", err)
	}
	hostLink, err := netlink.LinkByName(hostName)
	if err != nil {
		t.Fatalf("inspect host veth: %v", err)
	}
	peerLink, err := netlink.LinkByName(peerName)
	if err != nil {
		t.Fatalf("inspect peer veth: %v", err)
	}
	if err := netlink.AddrAdd(hostLink, mustTestAddr(t, hostIP+"/30")); err != nil && !isNetlinkAlreadyExists(err) {
		t.Fatalf("add host veth address: %v", err)
	}
	if err := netlink.AddrAdd(peerLink, mustTestAddr(t, peerIP+"/30")); err != nil && !isNetlinkAlreadyExists(err) {
		t.Fatalf("add peer veth address: %v", err)
	}
	if err := netlink.LinkSetUp(hostLink); err != nil {
		t.Fatalf("set host veth up: %v", err)
	}
	if err := netlink.LinkSetUp(peerLink); err != nil {
		t.Fatalf("set peer veth up: %v", err)
	}
	setStaticNeighbor(t, hostLink, peerIP, peerLink.Attrs().HardwareAddr)
	setStaticNeighbor(t, peerLink, hostIP, hostLink.Attrs().HardwareAddr)
	if err := replaceClsact(hostLink); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("requires CAP_NET_ADMIN to attach clsact: %v", err)
		}
		t.Fatalf("attach clsact to host veth: %v", err)
	}

	statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap := newIngressFastPathTestMaps(t)
	defer statsMap.Close()
	defer packetPolicyMap.Close()
	defer routeMap.Close()
	defer kernelUDPTXRouteMap.Close()
	defer kernelUDPTXFlowMap.Close()
	defer natConfigMap.Close()
	defer natSourceMap.Close()
	defer natRouteMap.Close()
	defer natExcludeMap.Close()
	defer captureMap.Close()
	natBindingMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_nat_bindings_tc_yield_live", Type: cebpf.Hash, KeySize: 20, ValueSize: 16, MaxEntries: 16})
	defer natBindingMap.Close()
	counterMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tc_yield_live_counter", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	defer counterMap.Close()

	var trustIXProgram *cebpf.Program
	var trustIXName string
	if parent == netlink.HANDLE_MIN_INGRESS {
		trustIXName = "trustix_ingress"
		trustIXProgram, err = loadIngressFastPathProgram("tix_ing_yield", statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap, kernelUDPTXDirectProgramOptions{Enabled: true})
	} else {
		trustIXName = "trustix_egress"
		trustIXProgram, err = loadEgressFastPathProgram("tix_eg_yield", statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, natBindingMap, captureMap, kernelUDPTXDirectProgramOptions{Enabled: true})
	}
	if err != nil {
		t.Fatalf("load TrustIX TC program: %v", err)
	}
	defer trustIXProgram.Close()
	counterProgram, err := loadTCCountingDropProgram("tix_drop_yield", counterMap)
	if err != nil {
		t.Fatalf("load later TC counter/drop program: %v", err)
	}
	defer counterProgram.Close()

	trustIXFilter := bpfFilterWithPriority(hostLink, parent, netlink.MakeHandle(0, 1), trustIXName, trustIXProgram.FD(), 1)
	counterFilter := bpfFilterWithPriority(hostLink, parent, netlink.MakeHandle(0, 10), "tix_later_drop", counterProgram.FD(), 10)
	if err := netlink.FilterReplace(trustIXFilter); err != nil {
		t.Fatalf("attach TrustIX TC filter: %v", err)
	}
	if err := netlink.FilterReplace(counterFilter); err != nil {
		t.Fatalf("attach later TC counter/drop filter: %v", err)
	}

	pingSource, pingTarget := peerName, hostIP
	if parent == netlink.HANDLE_MIN_EGRESS {
		pingSource, pingTarget = hostName, peerIP
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "ping", "-c", "1", "-W", "1", "-I", pingSource, pingTarget).Run()

	var count uint64
	key := uint32(0)
	if err := counterMap.Lookup(key, &count); err != nil {
		t.Fatalf("read later TC counter: %v", err)
	}
	if count == 0 {
		t.Fatalf("later TC filter did not run after TrustIX %s miss", tcParentName(parent))
	}
}

func loadTCCountingDropProgram(name string, counterMap *cebpf.Map) (*cebpf.Program, error) {
	instructions := appendCounter(nil, counterMap, 0, "counter_done")
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, tcActShot),
		asm.Return(),
	)
	return cebpf.NewProgramWithOptions(&cebpf.ProgramSpec{
		Name:         name,
		Type:         cebpf.SchedCLS,
		Instructions: withTCProgramBTFMetadata(instructions),
		License:      "GPL",
	}, cebpf.ProgramOptions{LogLevel: cebpf.LogLevelBranch})
}

func mustTestAddr(t *testing.T, cidr string) *netlink.Addr {
	t.Helper()
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		t.Fatalf("parse test address %q: %v", cidr, err)
	}
	return addr
}

func setStaticNeighbor(t *testing.T, link netlink.Link, ip string, mac net.HardwareAddr) {
	t.Helper()
	if err := netlink.NeighSet(&netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		Family:       unix.AF_INET,
		State:        netlink.NUD_PERMANENT,
		IP:           net.ParseIP(ip).To4(),
		HardwareAddr: mac,
	}); err != nil && !isNetlinkAlreadyExists(err) {
		t.Fatalf("set static neighbor %s on %s: %v", ip, link.Attrs().Name, err)
	}
}

func isNetlinkAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	return errors.Is(err, os.ErrExist) ||
		errors.Is(err, unix.EEXIST) ||
		strings.Contains(lower, "file exists") ||
		strings.Contains(lower, "object already exists")
}

func tcParentName(parent uint32) string {
	if parent == netlink.HANDLE_MIN_INGRESS {
		return "ingress"
	}
	if parent == netlink.HANDLE_MIN_EGRESS {
		return "egress"
	}
	return fmt.Sprintf("parent %#x", parent)
}

func TestKernelUDPRXSecureDirectLocalDeliveryBypassesRedirectPeer(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "..", "kernel", "bpf", "dataplane", "kernel_udp_rx_kernel_crypto_tc.c"))
	if err != nil {
		t.Fatalf("read kernel_udp RX secure C source: %v", err)
	}
	local := bytes.Index(source, []byte("redirect_ingress = 1;"))
	if local < 0 {
		t.Fatal("local management VIP path does not mark ingress redirect")
	}
	peer := bytes.Index(source, []byte("if (trustix_kudp_rx_secure_redirect_peer && !redirect_ingress)"))
	if peer < 0 {
		t.Fatal("redirect_peer path is not gated away from local ingress delivery")
	}
	ingress := bytes.Index(source, []byte("return bpf_redirect(scratch->ifindex, BPF_F_INGRESS);"))
	if ingress < 0 {
		t.Fatal("local ingress redirect return path not found")
	}
	if !(local < peer && peer < ingress) {
		t.Fatalf("local delivery guard order is wrong: local=%d peer=%d ingress=%d", local, peer, ingress)
	}
}

func TestKernelModuleRXCBOffsetsDoNotOverlap(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "..", "kernel", "trustix_datapath_helpers", "trustix_datapath_helpers_kfuncs.c"))
	if err != nil {
		t.Fatalf("read datapath module C source: %v", err)
	}
	if !bytes.Contains(source, []byte("#define TRUSTIX_SKB_CB_RX_NEXT_HOP 0")) {
		t.Fatal("datapath module next-hop skb->cb offset changed unexpectedly")
	}
	if !bytes.Contains(source, []byte("#define TRUSTIX_SKB_CB_RX_OUTER_LEN 4")) {
		t.Fatal("datapath module outer-len skb->cb offset must not overlap the 4-byte next-hop field")
	}
}

func TestKernelModuleTIXTHeaderWritersUseNonZeroACK(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "..", "kernel", "trustix_datapath_helpers", "trustix_datapath_helpers_kfuncs.c"))
	if err != nil {
		t.Fatalf("read datapath module C source: %v", err)
	}
	if bytes.Contains(source, []byte("put_unaligned_be32(0, tcph + offsetof(struct tcphdr, ack_seq));")) {
		t.Fatal("TIXT TCP header writers must not emit zero ACK sequence with ACK set")
	}
	if got := bytes.Count(source, []byte("put_unaligned_be32(1, tcph + offsetof(struct tcphdr, ack_seq));")); got < 2 {
		t.Fatalf("TIXT TCP header non-zero ACK stores = %d, want at least 2", got)
	}
	if !bytes.Contains(source, []byte("tcph->ack_seq = htonl(1);")) {
		t.Fatal("TIXT route TCP template must emit a non-zero ACK sequence")
	}
}

func TestKernelModuleTIXTRXStreamTailBypassesPlainDecap(t *testing.T) {
	sourceBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "kernel", "trustix_datapath_helpers", "trustix_datapath_helpers_kfuncs.c"))
	if err != nil {
		t.Fatalf("read datapath module C source: %v", err)
	}
	source := string(sourceBytes)
	plainBody := sourceFunctionBody(t, source, "trustix_skb_kudp_rx_parse_plain")
	if !strings.Contains(plainBody, "trustix_tixt_tcp_outer_has_stream_tail(skb, ip_len)") ||
		!strings.Contains(plainBody, "return -EPROTONOSUPPORT;") {
		t.Fatal("plain TIXT RX parser must reject TCP skbs that carry a stream tail")
	}
	wantedBody := sourceFunctionBody(t, source, "trustix_tixt_rx_stream_parse_wanted")
	if !strings.Contains(wantedBody, "trustix_tixt_rx_tcp_outer_needs_stream_parse(skb)") {
		t.Fatal("TIXT RX stream parser must be selected for TCP GSO/GRO stream candidates")
	}
	parseBody := sourceFunctionBody(t, source, "trustix_tixt_rx_stream_parse_frames")
	if !strings.Contains(parseBody, "trustix_tixt_tcp_outer_has_stream_tail(skb, ip_len)") ||
		!strings.Contains(parseBody, "payload_end = skb->len;") {
		t.Fatal("TIXT RX stream parser must parse TCP stream tails through the skb payload end")
	}
	disableBody := sourceFunctionBody(t, source, "trustix_datapath_helpers_disable_panic_risk_params")
	for _, forbidden := range []string{
		"WRITE_ONCE(trustix_tixt_rx_stream_parse, false);",
		"WRITE_ONCE(trustix_tixt_rx_stream_xmit_extra, false);",
		"WRITE_ONCE(trustix_tixt_rx_stream_gso_xmit, false);",
	} {
		if strings.Contains(disableBody, forbidden) {
			t.Fatalf("safe TIXT RX stream parameter is still forcibly disabled: %s", forbidden)
		}
	}
}

func TestTrustIXCryptoTCKfuncSetIsCryptoOnly(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "..", "kernel", "trustix_crypto", "trustix_crypto.c"))
	if err != nil {
		t.Fatalf("read kernel module C source: %v", err)
	}
	start := bytes.Index(source, []byte("BTF_KFUNCS_START(trustix_aead_tc_kfunc_ids)"))
	if start < 0 {
		t.Fatal("trustix_crypto TC kfunc set not found")
	}
	endRelative := bytes.Index(source[start:], []byte("BTF_KFUNCS_END(trustix_aead_tc_kfunc_ids)"))
	if endRelative < 0 {
		t.Fatal("trustix_crypto TC kfunc set end not found")
	}
	block := source[start : start+endRelative]
	for _, want := range []string{
		"BTF_ID_FLAGS(func, trustix_kernel_direct_seal)",
		"BTF_ID_FLAGS(func, trustix_kernel_direct_open)",
		"BTF_ID_FLAGS(func, trustix_kernel_skb_direct_open)",
		"BTF_ID_FLAGS(func, trustix_kernel_skb_direct_seal)",
	} {
		if !bytes.Contains(block, []byte(want)) {
			t.Fatalf("trustix_crypto TC kfunc set missing %s", want)
		}
	}
	if got := bytes.Count(block, []byte("BTF_ID_FLAGS(func,")); got != 4 {
		t.Fatalf("trustix_crypto TC kfunc count = %d, want exactly 4 crypto-only kfuncs", got)
	}
	for _, forbidden := range []string{
		"trustix_kernel_skb_clear_tx_offload",
		"trustix_kernel_skb_fix_inner_tcp_csum",
		"trustix_kernel_skb_kudp_rx_decap_l2",
		"trustix_kernel_skb_tixt_tx_",
		"trustix_kernel_skb_kudp_tx_",
	} {
		if bytes.Contains(block, []byte(forbidden)) {
			t.Fatalf("trustix_crypto TC kfunc set still registers datapath helper %q", forbidden)
		}
	}
	for _, forbidden := range []string{
		"__bpf_kfunc int trustix_kernel_skb_clear_tx_offload",
		"__bpf_kfunc int trustix_kernel_skb_fix_inner_tcp_csum",
		"__bpf_kfunc int trustix_kernel_skb_kudp",
		"__bpf_kfunc int trustix_kernel_skb_tixt",
		"dev_queue_xmit(",
		"skb_gso_segment(",
	} {
		if bytes.Contains(source, []byte(forbidden)) {
			t.Fatalf("trustix_crypto source still carries datapath/XMIT implementation %q", forbidden)
		}
	}
}

func TestTrustIXCryptoUserspaceIOCTLUsesWaitableRequests(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "..", "kernel", "trustix_crypto", "trustix_crypto.c"))
	if err != nil {
		t.Fatalf("read kernel module C source: %v", err)
	}
	for _, bounds := range [][2]string{
		{"static long trustix_aead_ioc_crypt(", "static long trustix_aead_ioc_batch("},
		{"static long trustix_aead_ioc_batch(", "static long trustix_aead_ioc_set_key("},
	} {
		start := bytes.Index(source, []byte(bounds[0]))
		if start < 0 {
			t.Fatalf("crypto ioctl function %q not found", bounds[0])
		}
		endRelative := bytes.Index(source[start:], []byte(bounds[1]))
		if endRelative < 0 {
			t.Fatalf("crypto ioctl function end %q not found", bounds[1])
		}
		body := source[start : start+endRelative]
		if !bytes.Contains(body, []byte("trustix_aead_ioc_alloc_ctx")) ||
			!bytes.Contains(body, []byte("key_len, true)")) {
			t.Fatalf("crypto ioctl %q must allocate a waitable request", bounds[0])
		}
		if bytes.Contains(body, []byte("key_len, false)")) {
			t.Fatalf("crypto ioctl %q still allocates a non-waitable request", bounds[0])
		}
	}
}

func TestTrustIXDatapathHelpersOwnsSKBAndRouteHeaderKfuncs(t *testing.T) {
	mainSource, err := os.ReadFile(filepath.Join("..", "..", "..", "kernel", "trustix_datapath_helpers", "trustix_datapath_helpers_main.c"))
	if err != nil {
		t.Fatalf("read datapath module main C source: %v", err)
	}
	helperSource, err := os.ReadFile(filepath.Join("..", "..", "..", "kernel", "trustix_datapath_helpers", "trustix_datapath_helpers_kfuncs.c"))
	if err != nil {
		t.Fatalf("read datapath module helper C source: %v", err)
	}
	if !bytes.Contains(mainSource, []byte("trustix_datapath_helpers_feature_mask()")) {
		t.Fatal("trustix_datapath_helpers feature reporting must be tied to helper registration")
	}
	start := bytes.Index(helperSource, []byte("BTF_KFUNCS_START(trustix_datapath_helpers_tc_kfunc_ids)"))
	if start < 0 {
		t.Fatal("trustix_datapath_helpers TC kfunc set not found")
	}
	endRelative := bytes.Index(helperSource[start:], []byte("BTF_KFUNCS_END(trustix_datapath_helpers_tc_kfunc_ids)"))
	if endRelative < 0 {
		t.Fatal("trustix_datapath_helpers TC kfunc set end not found")
	}
	block := helperSource[start : start+endRelative]
	for _, want := range []string{
		"BTF_ID_FLAGS(func, trustix_kernel_skb_clear_tx_offload)",
		"BTF_ID_FLAGS(func, trustix_kernel_skb_fix_inner_tcp_csum)",
		"BTF_ID_FLAGS(func, trustix_kernel_skb_kudp_rx_decap_l2)",
		"BTF_ID_FLAGS(func, trustix_kernel_skb_tixt_tx_push_route_tcp_header)",
		"BTF_ID_FLAGS(func, trustix_kernel_skb_tixt_tx_segment_route_tcp_gso)",
		"BTF_ID_FLAGS(func, trustix_kernel_skb_tixt_tx_route_tcp)",
		"BTF_ID_FLAGS(func, trustix_kernel_skb_tixt_tx_route_tcp_xmit)",
		"BTF_ID_FLAGS(func, trustix_kernel_skb_kudp_tx_push_udp_header)",
	} {
		if !bytes.Contains(block, []byte(want)) {
			t.Fatalf("trustix_datapath_helpers TC kfunc set missing %s", want)
		}
	}
	if !bytes.Contains(helperSource, []byte("return -EOPNOTSUPP;")) {
		t.Fatal("trustix_datapath_helpers route GSO/xmit stubs must fail closed until validated")
	}
	if !bytes.Contains(helperSource, []byte("trustix_route_tcp_xmit_worker_fn")) ||
		!bytes.Contains(helperSource, []byte("dev_queue_xmit(")) {
		t.Fatal("trustix_datapath_helpers route TCP xmit must be isolated to the worker implementation")
	}
	if !bytes.Contains(helperSource, []byte("trustix_route_tcp_gso_async_worker_fn")) ||
		!bytes.Contains(helperSource, []byte("skb_gso_segment(")) {
		t.Fatal("trustix_datapath_helpers route TCP GSO must be isolated to the async worker implementation")
	}
	xmitStart := bytes.Index(helperSource, []byte("__bpf_kfunc int\ntrustix_kernel_skb_tixt_tx_route_tcp_xmit("))
	if xmitStart < 0 {
		t.Fatal("trustix_datapath_helpers route TCP xmit kfunc body not found")
	}
	xmitEnd := bytes.Index(helperSource[xmitStart:], []byte("__bpf_kfunc int trustix_kernel_skb_kudp_tx_store_l2_l3_l4"))
	if xmitEnd < 0 {
		t.Fatal("trustix_datapath_helpers route TCP xmit kfunc body end not found")
	}
	xmitBody := helperSource[xmitStart : xmitStart+xmitEnd]
	if bytes.Contains(xmitBody, []byte("dev_queue_xmit(")) {
		t.Fatal("trustix_datapath_helpers route TCP xmit kfunc must enqueue instead of directly calling dev_queue_xmit")
	}
	gsoStart := bytes.Index(helperSource, []byte("__bpf_kfunc int\ntrustix_kernel_skb_tixt_tx_segment_route_tcp_gso("))
	if gsoStart < 0 {
		t.Fatal("trustix_datapath_helpers route TCP GSO kfunc body not found")
	}
	gsoEnd := bytes.Index(helperSource[gsoStart:], []byte("__bpf_kfunc int\ntrustix_kernel_skb_tixt_tx_route_tcp("))
	if gsoEnd < 0 {
		t.Fatal("trustix_datapath_helpers route TCP GSO kfunc body end not found")
	}
	gsoBody := helperSource[gsoStart : gsoStart+gsoEnd]
	if bytes.Contains(gsoBody, []byte("skb_gso_segment(")) ||
		bytes.Contains(gsoBody, []byte("dev_queue_xmit(")) ||
		bytes.Contains(gsoBody, []byte("dev_direct_xmit(")) {
		t.Fatal("trustix_datapath_helpers route TCP GSO kfunc must only enqueue async worker work")
	}
	for _, want := range []string{
		"route_tcp_xmit_worker",
		"route_tcp_xmit_worker_steal",
		"route_tcp_xmit_worker_queue_limit",
		"route_tcp_xmit_worker_depth",
		"trustix_route_tcp_xmit_worker_scheduled",
		"skb_queue_head_init(&trustix_route_tcp_xmit_worker_queue)",
		"__skb_queue_tail(&trustix_route_tcp_xmit_worker_queue",
		"skb_clone(skb, GFP_ATOMIC)",
		"trustix_route_tcp_xmit_worker_flush()",
		"trustix_route_tcp_gso_async_flush()",
		"trustix_tixt_rx_single_coalesce_gso_set",
		"module_param_cb(tixt_rx_single_coalesce_gso",
		"trustix_tixt_rx_single_coalesce_drop_all()",
		"TRUSTIX_TIXT_TX_ROUTE_TCP_XMIT_QUEUED",
	} {
		if !bytes.Contains(helperSource, []byte(want)) {
			t.Fatalf("trustix_datapath_helpers worker xmit source missing %q", want)
		}
	}
	if bytes.Contains(helperSource, []byte("module_param_named(tixt_rx_single_coalesce_gso,")) {
		t.Fatal("tixt_rx_single_coalesce_gso must drain stale RX coalesce state through its custom setter")
	}
	if bytes.Contains(xmitBody, []byte("struct trustix_route_tcp_xmit_item")) ||
		bytes.Contains(xmitBody, []byte("kzalloc(sizeof(*item)")) ||
		bytes.Contains(xmitBody, []byte("kfree(item)")) {
		t.Fatal("trustix_datapath_helpers route TCP xmit worker should queue skbs without per-packet worker item allocation")
	}
	if bytes.Contains(helperSource, []byte("trustix_tixt_tx_route_tcp_steal_safe")) {
		t.Fatal("trustix_datapath_helpers route TCP xmit worker must not steal the TC-owned skb")
	}
	if !bytes.Contains(helperSource, []byte("register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS")) {
		t.Fatal("trustix_datapath_helpers helper kfuncs are not registered for TC")
	}
}

func TestKernelUDPTXDirectTIXTHeaderStoreImmediates(t *testing.T) {
	wire := make([]byte, 20+tixtcp.HeaderLen+20)
	binary.LittleEndian.PutUint16(wire[12:14], 0x1850)
	binary.LittleEndian.PutUint16(wire[14:16], 0xffff)
	binary.LittleEndian.PutUint32(wire[16:20], 0)
	binary.LittleEndian.PutUint32(wire[20:24], 0x54584954)
	binary.LittleEndian.PutUint32(wire[24:28], 0x28000801)
	binary.BigEndian.PutUint64(wire[28:36], 7)
	binary.BigEndian.PutUint64(wire[36:44], 0)
	binary.BigEndian.PutUint64(wire[44:52], 9)
	binary.BigEndian.PutUint32(wire[52:56], 20)
	binary.LittleEndian.PutUint32(wire[56:60], 0)
	copy(wire[60:], bytes.Repeat([]byte{0xa5}, 20))

	if wire[12] != 0x50 || wire[13] != 0x18 {
		t.Fatalf("TCP data offset/flags bytes = %#02x/%#02x, want 0x50/0x18", wire[12], wire[13])
	}
	if got := binary.BigEndian.Uint16(wire[14:16]); got != 0xffff {
		t.Fatalf("TCP window = %#x, want 0xffff", got)
	}
	frame, err := tixtcp.ParseFrameNoCopy(wire[20:])
	if err != nil {
		t.Fatalf("parse TC TX TIXT header immediates: %v", err)
	}
	if frame.Flags != tixtcp.FlagInnerIPv4 || frame.FlowID != 7 || frame.Epoch != 0 ||
		frame.Sequence != 9 || len(frame.Payload) != 20 {
		t.Fatalf("parsed frame = %+v payload=%d", frame, len(frame.Payload))
	}
}

func TestChecksumStoresUseNetworkByteOrder(t *testing.T) {
	instructions := appendStoreNetworkHalfFromR0(nil, -10)
	if len(instructions) != 2 {
		t.Fatalf("network checksum store emitted %d instructions, want 2", len(instructions))
	}
	swap := instructions[0]
	if swap.OpCode.Class() != asm.ALUClass || swap.OpCode.ALUOp() != asm.Swap ||
		swap.OpCode.Endianness() != asm.BE || swap.Constant != 16 || swap.Dst != asm.R0 {
		t.Fatalf("checksum byte-order conversion = %#v, want 16-bit host-to-BE on r0", swap)
	}
	store := instructions[1]
	if store.OpCode != asm.StoreMemOp(asm.Half) || store.Dst != asm.RFP ||
		store.Src != asm.R0 || store.Offset != -10 {
		t.Fatalf("checksum store = %#v, want half store from r0 to stack offset", store)
	}
}

func TestTCPMSSClampUpdatesTCPChecksumInPlace(t *testing.T) {
	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_stats_mss_l4_order_test", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	defer statsMap.Close()

	instructions := appendTCPMSSClampWithLabels(nil, statsMap, "mss_order", "mss_done", "mss_drop", "mss_parse_error")
	for _, instruction := range instructions {
		if instruction.IsBuiltinCall() && instruction.Constant == int64(asm.FnL4CsumReplace) {
			t.Fatalf("TCP MSS clamp should update the checksum in place, not through bpf_l4_csum_replace: %#v", instruction)
		}
	}
	checksumOffset := int16(rejectEthernetHeaderLen + rejectIPv4HeaderLen + 16)
	if !instructionsLoadPacketHalfWithNetworkConversion(instructions, checksumOffset, asm.R0) {
		t.Fatal("TCP MSS clamp does not read the TCP checksum in network byte order")
	}
	if !instructionsStorePacketNetworkHalfFromR0(instructions, checksumOffset) {
		t.Fatal("TCP MSS clamp does not store the updated TCP checksum in network byte order")
	}
	if !instructionsLoadStackHalf(instructions, packetPolicyMSSClampOldOffset, asm.R1) ||
		!instructionsLoadStackHalf(instructions, packetPolicyMSSClampNewOffset, asm.R1) {
		t.Fatal("TCP MSS clamp checksum delta does not use old and new MSS stack values")
	}
}

func TestNativeLocalBypassRunsBeforePreMSSClamp(t *testing.T) {
	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_stats_local_bypass_order_test", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	defer statsMap.Close()
	packetPolicyMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_packet_policy_local_bypass_order_test", Type: cebpf.Array, KeySize: 4, ValueSize: 12, MaxEntries: 1})
	defer packetPolicyMap.Close()
	routeMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_route_local_bypass_order_test", Type: cebpf.LPMTrie, KeySize: 8, ValueSize: 16, MaxEntries: 16, Flags: 1})
	defer routeMap.Close()

	instructions := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
		asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
	}
	instructions = appendNativeLocalRouteBypass(instructions, statsMap, routeMap, "parse_error", "exit")
	instructions = appendPacketPolicyTCPMSSClamp(instructions, statsMap, packetPolicyMap, "parse_error")

	bypassIndex := instructionSymbolIndex(instructions, "native_local_route_bypass_allow")
	mssIndex := instructionSymbolIndex(instructions, "packet_policy_pre_mss_lookup")
	if bypassIndex < 0 || mssIndex < 0 {
		t.Fatalf("missing local bypass or pre-MSS symbols: bypass=%d mss=%d", bypassIndex, mssIndex)
	}
	if bypassIndex > mssIndex {
		t.Fatalf("native local bypass runs after pre-MSS clamp: bypass=%d mss=%d", bypassIndex, mssIndex)
	}
}

func TestKernelUDPTXDirectBlockedRouteValue(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp TX route map test requires Linux")
	}
	m := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_blocked_route_test", Type: cebpf.LPMTrie, KeySize: 8, ValueSize: kernelUDPTXRouteValueSize, MaxEntries: 16, Flags: 1})
	defer m.Close()
	manager := &Manager{kernelUDPTXRouteMap: m, spec: dataplane.AttachSpec{KernelUDPTXDirectOnly: true}}
	route := routing.Route{Prefix: "10.80.0.0/16", NextHop: "ix-b"}
	prefix := netip.MustParsePrefix("10.80.0.0/16")
	if err := manager.syncKernelUDPTXDirectBlockedRouteLocked(route, prefix); err != nil {
		t.Fatalf("sync blocked route: %v", err)
	}
	key := routeKey{PrefixLen: 32, Addr: netip.MustParseAddr("10.80.1.2").As4()}
	var value kernelUDPTXRouteValue
	if err := m.Lookup(key, &value); err != nil {
		t.Fatalf("lookup blocked route: %v", err)
	}
	if value.Flags&kernelUDPTXRouteFlagDirectOnly == 0 {
		t.Fatalf("blocked direct-only route flags = %#x, want direct-only flag", value.Flags)
	}
	if value.Flags&kernelUDPTXRouteFlagBypass == 0 {
		t.Fatalf("blocked direct-only route flags = %#x, want bypass flag", value.Flags)
	}
	value.Flags &^= kernelUDPTXRouteFlagDirectOnly | kernelUDPTXRouteFlagBypass
	if value != (kernelUDPTXRouteValue{}) {
		t.Fatalf("blocked route flow value = %#v, want no flows", value)
	}
}

func TestKernelUDPTXDirectBlockedRouteSkippedOutsideDirectOnly(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp TX route map test requires Linux")
	}
	m := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_blocked_route_skip_test", Type: cebpf.LPMTrie, KeySize: 8, ValueSize: kernelUDPTXRouteValueSize, MaxEntries: 16, Flags: 1})
	defer m.Close()
	manager := &Manager{kernelUDPTXRouteMap: m}
	route := routing.Route{Prefix: "10.81.0.0/16", NextHop: "ix-b"}
	prefix := netip.MustParsePrefix("10.81.0.0/16")
	if err := manager.syncKernelUDPTXDirectBlockedRouteLocked(route, prefix); err != nil {
		t.Fatalf("sync blocked route: %v", err)
	}
	key := routeKey{PrefixLen: 32, Addr: netip.MustParseAddr("10.81.1.2").As4()}
	var value kernelUDPTXRouteValue
	if err := m.Lookup(key, &value); !errors.Is(err, cebpf.ErrKeyNotExist) {
		t.Fatalf("lookup non-direct-only blocked route error = %v value=%#v, want key not exist", err, value)
	}
}

func TestKernelUDPTXDirectBlockedRouteSkippedForTIXTCPFallback(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp TX route map test requires Linux")
	}
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_ONLY", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_TIX_TCP_ONLY", "")
	m := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_blocked_route_exp_skip_test", Type: cebpf.LPMTrie, KeySize: 8, ValueSize: kernelUDPTXRouteValueSize, MaxEntries: 16, Flags: 1})
	defer m.Close()
	manager := &Manager{
		kernelUDPTXRouteMap: m,
		spec:                dataplane.AttachSpec{KernelUDPTXDirectOnly: true},
		snapshot: dataplane.Snapshot{Endpoints: []dataplane.EndpointMetadata{{
			ID:        "exp-b",
			Peer:      "ix-b",
			Transport: "tix_tcp",
			Enabled:   true,
		}}},
	}
	route := routing.Route{Prefix: "10.83.0.0/16", NextHop: "ix-b", Endpoint: "exp-b"}
	prefix := netip.MustParsePrefix("10.83.0.0/16")
	if err := manager.syncKernelUDPTXDirectBlockedRouteLocked(route, prefix); err != nil {
		t.Fatalf("sync blocked route: %v", err)
	}
	key := routeKey{PrefixLen: 32, Addr: netip.MustParseAddr("10.83.1.2").As4()}
	var value kernelUDPTXRouteValue
	if err := m.Lookup(key, &value); !errors.Is(err, cebpf.ErrKeyNotExist) {
		t.Fatalf("lookup tix_tcp fallback route error = %v value=%#v, want key not exist", err, value)
	}
}

func TestKernelUDPTXDirectBypassRouteValue(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp TX route map test requires Linux")
	}
	m := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_bypass_route_test", Type: cebpf.LPMTrie, KeySize: 8, ValueSize: kernelUDPTXRouteValueSize, MaxEntries: 16, Flags: 1})
	defer m.Close()
	manager := &Manager{kernelUDPTXRouteMap: m, spec: dataplane.AttachSpec{KernelUDPTXDirectOnly: true}}
	prefix := netip.MustParsePrefix("10.82.0.1/32")
	if err := manager.syncKernelUDPTXDirectBypassRouteLocked(prefix); err != nil {
		t.Fatalf("sync bypass route: %v", err)
	}
	key := routeKey{PrefixLen: 32, Addr: netip.MustParseAddr("10.82.0.1").As4()}
	var value kernelUDPTXRouteValue
	if err := m.Lookup(key, &value); err != nil {
		t.Fatalf("lookup bypass route: %v", err)
	}
	if value.Flags&kernelUDPTXRouteFlagBypass == 0 {
		t.Fatalf("bypass route flags = %#x, want bypass flag", value.Flags)
	}
	if value.Flags&kernelUDPTXRouteFlagDirectOnly != 0 {
		t.Fatalf("bypass route flags = %#x, want control-plane fallback outside direct-only drop", value.Flags)
	}
	value.Flags &^= kernelUDPTXRouteFlagBypass
	if value != (kernelUDPTXRouteValue{}) {
		t.Fatalf("bypass route flow value = %#v, want no flows", value)
	}
}

func TestDetachLockedIgnoresMissingLANIface(t *testing.T) {
	manager := NewManager()
	manager.spec = dataplane.AttachSpec{
		LANIface: "trustix-missing-lan0",
		DataDir:  t.TempDir(),
	}

	if err := manager.detachLocked(context.Background(), nil); err != nil {
		t.Fatalf("detach with missing LAN iface: %v", err)
	}
}

func TestEffectiveLANAttachSpecsLegacyAndMulti(t *testing.T) {
	legacy := effectiveLANAttachSpecs(dataplane.AttachSpec{
		LANIface:      "br-lan",
		UnderlayIface: "eth0",
		Gateway:       "192.168.1.1/24",
		ManageQdisc:   true,
	})
	if len(legacy) != 1 || legacy[0].Iface != "br-lan" || legacy[0].UnderlayIface != "eth0" || legacy[0].LANAttachMode != "managed" {
		t.Fatalf("legacy effective LANs = %#v", legacy)
	}

	spec := normalizeAttachSpec(dataplane.AttachSpec{
		LANIface:      "br-lan",
		UnderlayIface: "eth0",
		Gateway:       "192.168.1.1/24",
		ManageQdisc:   true,
		LANs: []dataplane.LANAttachSpec{{
			ID:            "home",
			Iface:         "br-home",
			Gateway:       "192.168.10.1/24",
			LANAttachMode: "existing",
		}, {
			ID:      "guest",
			Iface:   "br-guest",
			Gateway: "192.168.20.1/24",
		}},
	})
	if spec.LANIface != "br-home" || spec.UnderlayIface != "eth0" || spec.Gateway != "192.168.10.1/24" || spec.LANAttachMode != "existing" {
		t.Fatalf("normalized primary fields = %#v", spec)
	}
	if len(spec.LANs) != 2 || spec.LANs[1].UnderlayIface != "eth0" || spec.LANs[1].LANAttachMode != "managed" {
		t.Fatalf("normalized LANs = %#v", spec.LANs)
	}
}

func TestLANIfaceForDestinationMatchesMostSpecificLANPrefix(t *testing.T) {
	manager := NewManager()
	manager.spec = normalizeAttachSpec(dataplane.AttachSpec{
		LANs: []dataplane.LANAttachSpec{{
			ID:        "primary",
			Iface:     "br-lan",
			Gateway:   "10.0.0.1/8",
			Advertise: []core.Prefix{"10.42.0.0/16"},
		}, {
			ID:               "devices",
			Iface:            "br-dev",
			Gateway:          "192.168.50.1/24",
			Advertise:        []core.Prefix{"10.42.9.0/24"},
			DeviceAccess:     true,
			DeviceAccessPool: "172.31.8.0/24",
		}},
	})
	if got := manager.lanIfaceForDestinationLocked(netip.MustParseAddr("10.42.9.7")); got != "br-dev" {
		t.Fatalf("destination 10.42.9.7 iface = %q, want br-dev", got)
	}
	if got := manager.lanIfaceForDestinationLocked(netip.MustParseAddr("10.42.7.7")); got != "br-lan" {
		t.Fatalf("destination 10.42.7.7 iface = %q, want br-lan", got)
	}
	if got := manager.lanIfaceForDestinationLocked(netip.MustParseAddr("172.31.8.12")); got != "br-dev" {
		t.Fatalf("device destination iface = %q, want br-dev", got)
	}
	if got := manager.lanIfaceForDestinationLocked(netip.MustParseAddr("203.0.113.10")); got != "br-lan" {
		t.Fatalf("fallback iface = %q, want br-lan", got)
	}
}

func TestSingleLANIfaceFastPathOnlyForSingleLAN(t *testing.T) {
	manager := NewManager()
	manager.spec = dataplane.AttachSpec{LANIface: "br-lan"}
	if got := manager.singleLANIfaceLocked(); got != "br-lan" {
		t.Fatalf("legacy single LAN iface = %q, want br-lan", got)
	}

	manager.spec = normalizeAttachSpec(dataplane.AttachSpec{
		LANIface: "fallback",
		LANs: []dataplane.LANAttachSpec{{
			Iface: "br-home",
		}},
	})
	if got := manager.singleLANIfaceLocked(); got != "br-home" {
		t.Fatalf("single configured LAN iface = %q, want br-home", got)
	}

	manager.spec = normalizeAttachSpec(dataplane.AttachSpec{
		LANs: []dataplane.LANAttachSpec{{
			Iface: "br-home",
		}, {
			Iface: "br-guest",
		}},
	})
	if got := manager.singleLANIfaceLocked(); got != "" {
		t.Fatalf("multi LAN fast path iface = %q, want empty", got)
	}
}

func TestPlanCleanupIncludesMultipleLANs(t *testing.T) {
	pinPath := t.TempDir()
	state := persistedDataplaneState{
		Version:  persistedStateVersion,
		Spec:     normalizeAttachSpec(dataplane.AttachSpec{PinPath: pinPath, LANs: []dataplane.LANAttachSpec{{ID: "home", Iface: "br-lan", Gateway: "192.168.1.1/24", ManageQdisc: true, ManageAddress: true}, {ID: "guest", Iface: "br-guest", Gateway: "192.168.2.1/24", ManageQdisc: true, ManageAddress: true}}}),
		Attached: true,
		LANs: []persistedLANAttachState{{
			ID:            "home",
			Iface:         "br-lan",
			AddressAdded:  true,
			QdiscPrepared: true,
		}, {
			ID:            "guest",
			Iface:         "br-guest",
			LinkAdded:     true,
			AddressAdded:  true,
			QdiscPrepared: true,
		}},
	}
	payload, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pinPath, "state.json"), payload, 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}
	manager := NewManager()
	plan, err := manager.PlanCleanup(context.Background(), dataplane.AttachSpec{PinPath: pinPath})
	if err != nil {
		t.Fatalf("plan cleanup: %v", err)
	}
	if !cleanupPlanHasStep(plan, "remove_tc_filters", "br-lan") || !cleanupPlanHasStep(plan, "remove_tc_filters", "br-guest") {
		t.Fatalf("cleanup plan missing multi-LAN TC cleanup: %#v", plan.Steps)
	}
	if !cleanupPlanHasStep(plan, "remove_lan_gateway", "br-lan") || !cleanupPlanHasStep(plan, "remove_lan_gateway", "br-guest") {
		t.Fatalf("cleanup plan missing multi-LAN gateway cleanup: %#v", plan.Steps)
	}
	if cleanupPlanHasStep(plan, "delete_managed_lan_iface", "br-lan") {
		t.Fatalf("cleanup plan should not delete pre-existing LAN iface: %#v", plan.Steps)
	}
	if !cleanupPlanHasStep(plan, "delete_managed_lan_iface", "br-guest") {
		t.Fatalf("cleanup plan missing TrustIX-created LAN iface cleanup: %#v", plan.Steps)
	}
}

func TestDetachClosesDataplaneSocketRefsBeforeDeletingManagedLANs(t *testing.T) {
	payload, err := os.ReadFile("manager_linux.go")
	if err != nil {
		t.Fatalf("read manager_linux.go: %v", err)
	}
	text := string(payload)
	closeMarker := "if err := manager.closeDataplaneSocketRefsLocked(); err != nil {\n\t\terrs = append(errs, err.Error())\n\t}\n\tfor _, lan := range effectiveLANAttachSpecs(manager.spec) {"
	closeIdx := strings.Index(text, closeMarker)
	if closeIdx < 0 {
		t.Fatalf("detachLocked does not close dataplane socket refs immediately before managed LAN cleanup")
	}
	if !strings.Contains(text[closeIdx:], "netlink.LinkDel(target)") {
		t.Fatalf("detachLocked managed LAN cleanup no longer deletes links with netlink.LinkDel")
	}
}

func TestPlanCleanupIncludesDistinctUnderlayTCFilters(t *testing.T) {
	pinPath := t.TempDir()
	state := persistedDataplaneState{
		Version: persistedStateVersion,
		Spec: normalizeAttachSpec(dataplane.AttachSpec{
			PinPath:       pinPath,
			LANIface:      "br-lan",
			UnderlayIface: "eth0",
			Gateway:       "192.168.1.1/24",
			ManageQdisc:   true,
			ManageAddress: true,
		}),
		Attached:      true,
		QdiscPrepared: true,
		AddressAdded:  true,
	}
	payload, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pinPath, "state.json"), payload, 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}
	manager := NewManager()
	plan, err := manager.PlanCleanup(context.Background(), dataplane.AttachSpec{PinPath: pinPath})
	if err != nil {
		t.Fatalf("plan cleanup: %v", err)
	}
	if !cleanupPlanHasStep(plan, "remove_tc_filters", "eth0") || !cleanupPlanHasStep(plan, "delete_clsact_qdisc", "eth0") {
		t.Fatalf("cleanup plan missing underlay TC cleanup: %#v", plan.Steps)
	}
}

func TestPlanCleanupSkipsDuplicateUnderlayLANStep(t *testing.T) {
	pinPath := t.TempDir()
	state := persistedDataplaneState{
		Version: persistedStateVersion,
		Spec: normalizeAttachSpec(dataplane.AttachSpec{
			PinPath:       pinPath,
			LANIface:      "br-lan",
			UnderlayIface: "br-lan",
			Gateway:       "192.168.1.1/24",
			ManageQdisc:   true,
			ManageAddress: true,
		}),
		Attached:      true,
		QdiscPrepared: true,
		AddressAdded:  true,
	}
	payload, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pinPath, "state.json"), payload, 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}
	manager := NewManager()
	plan, err := manager.PlanCleanup(context.Background(), dataplane.AttachSpec{PinPath: pinPath})
	if err != nil {
		t.Fatalf("plan cleanup: %v", err)
	}
	count := 0
	for _, step := range plan.Steps {
		if step.Action == "remove_tc_filters" && step.Target == "br-lan" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("cleanup plan should include one br-lan TC cleanup step, got %d: %#v", count, plan.Steps)
	}
}

func TestManagedLANBridgeSourceSetsNonZeroTxQueueLen(t *testing.T) {
	source, err := os.ReadFile("manager_linux.go")
	if err != nil {
		t.Fatalf("read manager source: %v", err)
	}
	if !bytes.Contains(source, []byte("LinkAttrs{Name: iface, TxQLen: managedLANTxQueueLen}")) {
		t.Fatal("managed LAN bridge creation must set a nonzero TxQLen; plain LinkAttrs{Name: iface} creates tx_queue_len=0")
	}
	if !bytes.Contains(source, []byte("netlink.LinkSetTxQLen(link, managedLANTxQueueLen)")) {
		t.Fatal("managed LAN attach must repair existing tx_queue_len=0 interfaces")
	}
}

func cleanupPlanHasStep(plan dataplane.CleanupPlan, action, target string) bool {
	for _, step := range plan.Steps {
		if step.Action == action && step.Target == target {
			return true
		}
	}
	return false
}

func TestCleanupQuarantinesCorruptPersistedDataplaneState(t *testing.T) {
	pinPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(pinPath, "state.json"), []byte("{"), 0o600); err != nil {
		t.Fatalf("write corrupt state: %v", err)
	}
	manager := NewManager()
	if err := manager.Cleanup(context.Background(), dataplane.AttachSpec{PinPath: pinPath, LANIface: "trustix-missing-lan0"}); err != nil {
		t.Fatalf("cleanup with corrupt state: %v", err)
	}
	if _, err := os.Stat(filepath.Join(pinPath, "state.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state.json stat error = %v, want not exist", err)
	}
	matches, err := filepath.Glob(filepath.Join(pinPath, "state.corrupt-*.json"))
	if err != nil {
		t.Fatalf("glob corrupt state: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("corrupt state backups = %v, want exactly one", matches)
	}
}

func TestCleanupQuarantinesSemanticRouteCorruptionAndContinues(t *testing.T) {
	pinPath := t.TempDir()
	state := persistedDataplaneState{
		Spec: dataplane.AttachSpec{PinPath: pinPath, LANIface: "trustix-missing-lan0"},
		ManagedCaptureRoutes: []persistedManagedCaptureRoute{
			{Prefix: "not-a-prefix", Iface: "trustix-missing-lan0"},
			{Prefix: "10.91.0.0/24", Iface: "trustix-missing-lan0", Gateway: "not-an-ip"},
		},
		NativeTunnelRoutes: []persistedNativeTunnelRoute{
			{Protocol: "gre", Tunnel: "trustix-missing-gre0", Prefix: "10.92.0.0/24", Gateway: "not-an-ip"},
		},
	}
	payload, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal semantically corrupt state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pinPath, "state.json"), payload, 0o600); err != nil {
		t.Fatalf("write semantically corrupt state: %v", err)
	}

	manager := NewManager()
	if err := manager.Cleanup(context.Background(), dataplane.AttachSpec{PinPath: pinPath}); err != nil {
		t.Fatalf("cleanup with semantically corrupt state: %v", err)
	}
	if _, err := os.Stat(filepath.Join(pinPath, "state.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state.json stat error = %v, want not exist", err)
	}
	matches, err := filepath.Glob(filepath.Join(pinPath, "state.corrupt-*.json"))
	if err != nil {
		t.Fatalf("glob semantic corruption quarantine: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("semantic corruption backups = %v, want exactly one", matches)
	}
}

func TestDesiredNativeTunnelRoutesRequiresPlaintextKernelTunnel(t *testing.T) {
	manager := NewManager()
	manager.spec = dataplane.AttachSpec{LANIface: "lan0", UnderlayIface: "eth0", DataDir: t.TempDir()}
	snapshot := dataplane.Snapshot{
		Routes: []routing.Route{
			{
				Prefix:   "10.90.0.0/24",
				NextHop:  "ix-b",
				Endpoint: "ix-b-gre",
				Kind:     routing.RouteUnicast,
			},
			{
				Prefix:   "10.91.0.0/24",
				NextHop:  "ix-b",
				Endpoint: "ix-b-vxlan",
				Kind:     routing.RouteUnicast,
			},
		},
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        "ix-b-gre",
			Peer:      "ix-b",
			Transport: "gre",
			Address:   "local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.30.1/30,remote_carrier=10.255.30.2,mtu=1400",
			Enabled:   true,
			Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
		}, {
			ID:        "ix-b-vxlan",
			Peer:      "ix-b",
			Transport: "vxlan",
			Address:   "local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.31.1/30,remote_carrier=10.255.31.2,port=4789,mtu=1450,vni=7",
			Enabled:   true,
			Security:  dataplane.EndpointSecurityMetadata{Encryption: "none"},
		}},
	}
	routes, err := manager.desiredNativeTunnelRoutesLocked(snapshot)
	if err != nil {
		t.Fatalf("desired native tunnel routes: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("native routes = %#v, want two", routes)
	}
	route := routes[nativeTunnelRouteKey("gre", "10.90.0.0/24", "ix-b-gre")]
	if route.Protocol != "gre" || route.Gateway != netip.MustParseAddr("10.255.30.2") || route.MTU != 1400 || route.AdvMSS != 1360 {
		t.Fatalf("native route = %#v", route)
	}
	route = routes[nativeTunnelRouteKey("vxlan", "10.91.0.0/24", "ix-b-vxlan")]
	if route.Protocol != "vxlan" || route.Gateway != netip.MustParseAddr("10.255.31.2") || route.MTU != 1450 || route.AdvMSS != 1410 {
		t.Fatalf("native vxlan route = %#v", route)
	}
	snapshot.Endpoints[0].Security.Encryption = "secure"
	snapshot.Endpoints[1].Security.Encryption = "secure"
	routes, err = manager.desiredNativeTunnelRoutesLocked(snapshot)
	if err != nil {
		t.Fatalf("desired secure native tunnel routes: %v", err)
	}
	if len(routes) != 0 {
		t.Fatalf("secure endpoint native routes = %#v, want none", routes)
	}
}

func TestDesiredNativeTunnelRoutesRequireExplicitPlaintext(t *testing.T) {
	manager := NewManager()
	manager.spec = dataplane.AttachSpec{LANIface: "lan0", UnderlayIface: "eth0", DataDir: t.TempDir()}
	snapshot := dataplane.Snapshot{
		Routes: []routing.Route{{
			Prefix:   "10.92.0.0/24",
			NextHop:  "ix-b",
			Endpoint: "ix-b-gre",
			Kind:     routing.RouteUnicast,
		}},
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        "ix-b-gre",
			Peer:      "ix-b",
			Transport: "gre",
			Address:   "local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.32.1/30,remote_carrier=10.255.32.2,mtu=1400",
			Enabled:   true,
		}},
	}
	routes, err := manager.desiredNativeTunnelRoutesLocked(snapshot)
	if err != nil {
		t.Fatalf("desired native tunnel routes: %v", err)
	}
	if len(routes) != 0 {
		t.Fatalf("implicit secure endpoint native routes = %#v, want none", routes)
	}
	snapshot.Endpoints[0].Security.Encryption = "none"
	routes, err = manager.desiredNativeTunnelRoutesLocked(snapshot)
	if err != nil {
		t.Fatalf("desired plaintext native tunnel routes: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("explicit plaintext native routes = %#v, want one", routes)
	}
}

func TestDesiredManagedCaptureRoutesSkipsNonCaptureRoutes(t *testing.T) {
	manager := NewManager()
	manager.spec = dataplane.AttachSpec{LANIface: "lan0"}
	manager.nativeTunnelRoutes = map[string]nativeTunnelRouteState{
		nativeTunnelRouteKey("gre", "10.91.0.0/24", "ix-b-gre"): {
			Key:      nativeTunnelRouteKey("gre", "10.91.0.0/24", "ix-b-gre"),
			Protocol: "gre",
			Prefix:   netip.MustParsePrefix("10.91.0.0/24"),
			Endpoint: "ix-b-gre",
		},
	}
	snapshot := dataplane.Snapshot{
		Routes: []routing.Route{{
			Prefix:  "10.90.0.0/24",
			NextHop: "ix-b",
			Kind:    routing.RouteUnicast,
		}, {
			Prefix:   "10.91.0.0/24",
			NextHop:  "ix-b",
			Endpoint: "ix-b-gre",
			Kind:     routing.RouteUnicast,
		}, {
			Prefix:  "10.92.0.0/24",
			NextHop: "ix-a",
			Kind:    routing.RouteLocal,
		}, {
			Prefix:  "10.93.0.0/24",
			NextHop: "ix-b",
			Kind:    routing.RouteBlackhole,
		}, {
			Prefix:  "::/64",
			NextHop: "ix-b",
			Kind:    routing.RouteUnicast,
		}, {
			Prefix:  "0.0.0.0/0",
			NextHop: "ix-b",
			Kind:    routing.RouteUnicast,
		}},
	}
	routes, err := manager.desiredManagedCaptureRoutesLocked(snapshot)
	if err != nil {
		t.Fatalf("desired managed capture routes: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("managed capture routes = %#v, want one", routes)
	}
	route, ok := routes[managedCaptureRouteKey(netip.MustParsePrefix("10.90.0.0/24"))]
	if !ok {
		t.Fatalf("managed capture route for 10.90.0.0/24 missing: %#v", routes)
	}
	if route.Iface != "lan0" || route.Prefix != netip.MustParsePrefix("10.90.0.0/24") {
		t.Fatalf("managed capture route = %#v", route)
	}
	if len(manager.warnings) == 0 || !strings.Contains(manager.warnings[len(manager.warnings)-1], "default route") {
		t.Fatalf("expected default route warning, got %#v", manager.warnings)
	}
}

func TestRouteUsesNativeTunnelFallsBackToRouteState(t *testing.T) {
	manager := NewManager()
	manager.nativeTunnelRoutes = map[string]nativeTunnelRouteState{
		nativeTunnelRouteKey("gre", "10.91.0.0/24", "ix-b-gre"): {
			Key:      nativeTunnelRouteKey("gre", "10.91.0.0/24", "ix-b-gre"),
			Protocol: "gre",
			Prefix:   netip.MustParsePrefix("10.91.0.0/24"),
			Endpoint: "ix-b-gre",
		},
	}
	if !manager.routeUsesNativeTunnelLocked(routing.Route{
		Prefix:   "10.91.0.0/24",
		Endpoint: "ix-b-gre",
	}) {
		t.Fatal("native tunnel route state was not recognized without endpoint metadata")
	}
}

func TestDesiredManagedCaptureRoutesCanUseLegacyScopeLink(t *testing.T) {
	t.Setenv("TRUSTIX_MANAGED_CAPTURE_SCOPE_LINK_ROUTES", "1")
	manager := NewManager()
	manager.spec = dataplane.AttachSpec{LANIface: "lan0"}
	snapshot := dataplane.Snapshot{
		Routes: []routing.Route{{
			Prefix:  "10.90.0.0/24",
			NextHop: "ix-b",
			Kind:    routing.RouteUnicast,
		}},
	}
	routes, err := manager.desiredManagedCaptureRoutesLocked(snapshot)
	if err != nil {
		t.Fatalf("desired managed capture routes: %v", err)
	}
	route := routes[managedCaptureRouteKey(netip.MustParsePrefix("10.90.0.0/24"))]
	if route.Gateway.IsValid() {
		t.Fatalf("managed capture legacy route gateway = %s, want zero", route.Gateway)
	}
}

func TestManagedCaptureRouteGatewayFallsBackWithoutIface(t *testing.T) {
	manager := NewManager()
	manager.spec = dataplane.AttachSpec{LANIface: "missing-lan0"}
	gateway, destinationMAC := manager.managedCaptureRouteGatewayLocked()
	if gateway.IsValid() || destinationMAC != "" {
		t.Fatalf("managed capture gateway = %s mac=%q, want legacy fallback", gateway, destinationMAC)
	}
}

func TestManagedCaptureRouteGatewayUsesSyntheticVethPeer(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create veth pair")
	}
	suffix := fmt.Sprintf("%d", os.Getpid()%100000)
	hostName := "tixm" + suffix
	peerName := "tixn" + suffix
	_ = netlink.LinkDel(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: hostName}})
	t.Cleanup(func() {
		_ = netlink.LinkDel(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: hostName}})
		_ = netlink.LinkDel(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: peerName}})
	})
	if err := netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: hostName},
		PeerName:  peerName,
	}); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("requires CAP_NET_ADMIN to create veth pair: %v", err)
		}
		t.Fatalf("create veth pair: %v", err)
	}
	peer, err := netlink.LinkByName(peerName)
	if err != nil {
		t.Fatalf("inspect peer veth: %v", err)
	}
	manager := NewManager()
	manager.spec = dataplane.AttachSpec{LANIface: hostName}
	gateway, destinationMAC := manager.managedCaptureRouteGatewayLocked()
	if gateway != netip.MustParseAddr(managedCaptureSyntheticGateway) {
		t.Fatalf("managed capture gateway = %s, want synthetic gateway", gateway)
	}
	if destinationMAC != peer.Attrs().HardwareAddr.String() {
		t.Fatalf("managed capture neighbor MAC = %q, want peer %s", destinationMAC, peer.Attrs().HardwareAddr)
	}
}

func TestManagedCaptureRouteStateRoundTrip(t *testing.T) {
	manager := NewManager()
	manager.managedCaptureRoutes = map[string]managedCaptureRouteState{
		"10.90.0.0/24": {
			Key:            "10.90.0.0/24",
			Prefix:         netip.MustParsePrefix("10.90.0.0/24"),
			Iface:          "lan0",
			Ifindex:        7,
			Gateway:        netip.MustParseAddr(managedCaptureSyntheticGateway),
			DestinationMAC: "02:00:00:00:00:02",
		},
	}
	items := manager.managedCaptureRouteSnapshotLocked()
	if len(items) != 1 ||
		items[0].Prefix != "10.90.0.0/24" ||
		items[0].Iface != "lan0" ||
		items[0].Ifindex != 7 ||
		items[0].Gateway != managedCaptureSyntheticGateway ||
		items[0].DestinationMAC != "02:00:00:00:00:02" {
		t.Fatalf("managed capture route snapshot = %#v", items)
	}
	restored, err := managedCaptureRouteStateMap(items)
	if err != nil {
		t.Fatalf("restore managed capture route: %v", err)
	}
	if restored["10.90.0.0/24"] != manager.managedCaptureRoutes["10.90.0.0/24"] {
		t.Fatalf("managed capture route restore = %#v", restored)
	}
}

func TestDesiredDeviceAccessProxyARPSelectsIPv4HostRoutes(t *testing.T) {
	manager := NewManager()
	manager.spec = dataplane.AttachSpec{LANIface: "br-lan"}
	snapshot := dataplane.Snapshot{
		Routes: []routing.Route{{
			Prefix:  "10.0.0.240/32",
			NextHop: "device:ix-a:laptop-1",
			Kind:    routing.RouteUnicast,
			Source:  "device_access",
		}, {
			Prefix:  "10.0.0.0/24",
			NextHop: "device:ix-a:ignored",
			Kind:    routing.RouteUnicast,
			Source:  "device_access",
		}, {
			Prefix:  "10.0.0.241/32",
			NextHop: "ix-b",
			Kind:    routing.RouteUnicast,
			Source:  "static",
		}, {
			Prefix: "2001:db8::1/128",
			Kind:   routing.RouteLocal,
			Source: "device_access",
		}},
	}
	desired, err := manager.desiredDeviceAccessProxyARPLocked(snapshot)
	if err != nil {
		t.Fatalf("desired device proxy ARP: %v", err)
	}
	if len(desired) != 1 {
		t.Fatalf("device proxy ARP entries = %#v, want one", desired)
	}
	key := deviceAccessProxyARPKey("br-lan", netip.MustParseAddr("10.0.0.240"))
	proxy, ok := desired[key]
	if !ok {
		t.Fatalf("missing device proxy ARP entry %q: %#v", key, desired)
	}
	if proxy.Iface != "br-lan" || proxy.Address != netip.MustParseAddr("10.0.0.240") {
		t.Fatalf("device proxy ARP entry = %#v", proxy)
	}
}

func TestDeviceAccessProxyARPStateRoundTrip(t *testing.T) {
	manager := NewManager()
	key := deviceAccessProxyARPKey("br-lan", netip.MustParseAddr("10.0.0.240"))
	manager.deviceAccessProxyARP = map[string]deviceAccessProxyARPState{
		key: {
			Key:     key,
			Iface:   "br-lan",
			Ifindex: 7,
			Address: netip.MustParseAddr("10.0.0.240"),
		},
	}
	items := manager.deviceAccessProxyARPSnapshotLocked()
	if len(items) != 1 ||
		items[0].Key != key ||
		items[0].Iface != "br-lan" ||
		items[0].Ifindex != 7 ||
		items[0].Address != "10.0.0.240" {
		t.Fatalf("device proxy ARP snapshot = %#v", items)
	}
	restored := deviceAccessProxyARPStateMap(items)
	if restored[key] != manager.deviceAccessProxyARP[key] {
		t.Fatalf("device proxy ARP restore = %#v", restored)
	}
}

func TestEnsureManagedCaptureRouteNeighborSkipsWithoutMAC(t *testing.T) {
	if err := ensureManagedCaptureRouteNeighbor(7, netip.MustParseAddr(managedCaptureSyntheticGateway), ""); err != nil {
		t.Fatalf("empty MAC should skip neighbor install: %v", err)
	}
	if err := ensureManagedCaptureRouteNeighbor(7, netip.MustParseAddr(managedCaptureSyntheticGateway), "bad-mac"); err == nil {
		t.Fatal("invalid MAC should fail")
	}
}

func TestKernelTransportStatusReportsNativeTunnelRouteStats(t *testing.T) {
	manager := NewManager()
	manager.attached = true
	manager.nativeTunnelRoutes = map[string]nativeTunnelRouteState{
		"gre|ix-b|10.90.0.0/24": {
			Key:      "gre|ix-b|10.90.0.0/24",
			Protocol: "gre",
			Prefix:   netip.MustParsePrefix("10.90.0.0/24"),
			Endpoint: "ix-b-gre",
		},
		"vxlan|ix-c|10.91.0.0/24": {
			Key:      "vxlan|ix-c|10.91.0.0/24",
			Protocol: "vxlan",
			Prefix:   netip.MustParsePrefix("10.91.0.0/24"),
			Endpoint: "ix-c-vxlan",
		},
	}

	status, err := manager.KernelTransportStatus(context.Background())
	if err != nil {
		t.Fatalf("kernel transport status: %v", err)
	}
	stats := status.Statistics
	if stats["native_tunnel_route_offload_enabled"] != 1 ||
		stats["native_tunnel_routes"] != 2 ||
		stats["native_tunnel_routes_gre"] != 1 ||
		stats["native_tunnel_routes_vxlan"] != 1 {
		t.Fatalf("native tunnel stats = %#v", stats)
	}
}

func TestKernelTransportProtocolTIXTCPReportsRawFallbackAvailable(t *testing.T) {
	protocol := kernelTransportProtocolTIXTCP(dataplane.TIXTCPStatus{
		Available:         true,
		Provider:          "raw_socket_fallback",
		UserspaceCrypto:   true,
		Reinject:          true,
		RawSocketFallback: true,
	})

	if !protocol.Available {
		t.Fatalf("tix_tcp raw fallback available = false, want true: %+v", protocol)
	}
	if protocol.Placement != "fallback" {
		t.Fatalf("tix_tcp raw fallback placement = %q, want fallback", protocol.Placement)
	}
	if protocol.Provider != "raw_socket_fallback" {
		t.Fatalf("tix_tcp raw fallback provider = %q, want raw_socket_fallback", protocol.Provider)
	}
	if !protocol.UserspaceFallback {
		t.Fatalf("tix_tcp raw fallback userspace_fallback = false, want true")
	}
}

func TestKernelTransportProtocolTIXTCPReportsRawFallbackKernelCrypto(t *testing.T) {
	protocol := kernelTransportProtocolTIXTCP(dataplane.TIXTCPStatus{
		Available:         true,
		Provider:          "raw_socket_fallback",
		UserspaceCrypto:   true,
		KernelCrypto:      true,
		Reinject:          true,
		RawSocketFallback: true,
	})

	if !protocol.Available {
		t.Fatalf("tix_tcp raw fallback kernel crypto available = false: %+v", protocol)
	}
	if protocol.Placement != "kernel" {
		t.Fatalf("tix_tcp raw fallback kernel crypto placement = %q, want kernel", protocol.Placement)
	}
	if protocol.UserspaceFallback {
		t.Fatalf("tix_tcp raw fallback kernel crypto userspace_fallback = true, want false")
	}
}

func TestEnsureKernelTransportFastPathAutoDegradesAttachFailure(t *testing.T) {
	manager := NewManager()
	manager.spec = dataplane.AttachSpec{UnderlayIface: "trustix-missing-underlay0"}
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeAuto},
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        "exp-a",
			Peer:      "ix-a",
			Transport: "tix_tcp",
			Listen:    "127.0.0.1:17043",
			Enabled:   true,
		}},
	}

	if err := manager.ensureKernelTransportFastPathLocked(context.Background()); err != nil {
		t.Fatalf("auto kernel transport attach should degrade: %v", err)
	}
	if len(manager.warnings) == 0 || !strings.Contains(manager.warnings[len(manager.warnings)-1], "continuing without AF_XDP provider") {
		t.Fatalf("warnings = %#v, want AF_XDP degradation warning", manager.warnings)
	}
}

func TestEnsureKernelTransportFastPathRequireKernelFailsAttachFailure(t *testing.T) {
	manager := NewManager()
	manager.spec = dataplane.AttachSpec{UnderlayIface: "trustix-missing-underlay0"}
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        "exp-a",
			Peer:      "ix-a",
			Transport: "tix_tcp",
			Listen:    "127.0.0.1:17043",
			Enabled:   true,
		}},
	}

	if err := manager.ensureKernelTransportFastPathLocked(context.Background()); err == nil {
		t.Fatal("require_kernel attach failure returned nil")
	}
}

func TestEnsureKernelTransportFastPathDetachesAFXDPPForFullPlaintext(t *testing.T) {
	manager := NewManager()
	manager.attached = true
	manager.spec = dataplane.AttachSpec{KernelDatapathFullPlaintext: true}
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        "exp-a",
			Peer:      "ix-a",
			Transport: "tix_tcp",
			Listen:    "127.0.0.1:17043",
			Enabled:   true,
		}},
	}
	manager.tixTCPFastPath = testTIXTCPFastPathWithQueues(1)
	manager.tixTCPFastPath.provider = "af_xdp"
	manager.tixTCPFastPath.done = make(chan struct{})
	manager.tixTCPFastPath.ready.Store(true)

	if err := manager.ensureKernelTransportFastPathLocked(context.Background()); err != nil {
		t.Fatalf("full plaintext should detach AF_XDP without error: %v", err)
	}
	if manager.tixTCPFastPath != nil {
		t.Fatal("full plaintext left tix_tcp AF_XDP attached")
	}
}

func TestEnsureKernelTransportFastPathDetachesStaleXDPForFullPlaintext(t *testing.T) {
	manager := NewManager()
	manager.attached = true
	manager.spec = dataplane.AttachSpec{
		KernelDatapathFullPlaintext: true,
		UnderlayIface:               "eth1",
	}
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        "exp-a",
			Peer:      "ix-a",
			Transport: "tix_tcp",
			Listen:    "127.0.0.1:17043",
			Enabled:   true,
		}},
	}

	calls := 0
	oldDetach := detachIdleStaleTIXTCPXDP
	detachIdleStaleTIXTCPXDP = func(got *Manager) error {
		calls++
		if got != manager {
			t.Fatal("stale XDP detach called with wrong manager")
		}
		return nil
	}
	t.Cleanup(func() {
		detachIdleStaleTIXTCPXDP = oldDetach
	})

	if err := manager.ensureKernelTransportFastPathLocked(context.Background()); err != nil {
		t.Fatalf("full plaintext should detach stale XDP without error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("stale XDP detach calls = %d, want 1", calls)
	}
}

func TestKernelUDPTXRouteFlowPowerOfTwoLimit(t *testing.T) {
	tests := []struct {
		count int
		max   int
		want  int
	}{
		{count: 0, max: 8, want: 0},
		{count: 1, max: 8, want: 1},
		{count: 2, max: 8, want: 2},
		{count: 3, max: 8, want: 2},
		{count: 4, max: 8, want: 4},
		{count: 7, max: 8, want: 4},
		{count: 8, max: 8, want: 8},
		{count: 12, max: 8, want: 8},
		{count: 12, max: 4, want: 4},
	}
	for _, tt := range tests {
		if got := kernelUDPTXRouteFlowPowerOfTwoLimit(tt.count, tt.max); got != tt.want {
			t.Fatalf("limit count=%d max=%d = %d, want %d", tt.count, tt.max, got, tt.want)
		}
	}
}

func TestAttachExistingLANRejectsMissingGatewayAddress(t *testing.T) {
	iface := loopbackInterfaceName(t)
	missing := firstMissingLoopbackPrefix(t)
	manager := NewManager()

	err := manager.Attach(context.Background(), dataplane.AttachSpec{
		LANIface:      iface,
		Gateway:       missing,
		LANAttachMode: "existing",
		ManageQdisc:   false,
		ManageAddress: false,
		PinPath:       t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "does not have gateway address") {
		t.Fatalf("Attach error = %v, want missing existing LAN gateway", err)
	}
}

func loopbackInterfaceName(t *testing.T) string {
	t.Helper()
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("loopback interface unavailable: %v", err)
	}
	return iface.Name
}

func firstMissingLoopbackPrefix(t *testing.T) string {
	t.Helper()
	iface, err := net.InterfaceByName(loopbackInterfaceName(t))
	if err != nil {
		t.Skipf("loopback interface unavailable: %v", err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		t.Fatalf("list loopback addresses: %v", err)
	}
	used := make(map[string]struct{}, len(addrs))
	for _, addr := range addrs {
		used[addr.String()] = struct{}{}
	}
	for i := 250; i > 1; i-- {
		candidate := netip.PrefixFrom(netip.AddrFrom4([4]byte{127, byte(i), 254, 254}), 32).String()
		if _, exists := used[candidate]; !exists {
			return candidate
		}
	}
	t.Fatal("could not find a loopback /32 address absent from the interface")
	return ""
}

func TestKernelUDPRefCountRelease(t *testing.T) {
	var calls atomic.Int32
	release := kernelUDPRefCountRelease(func() {
		calls.Add(1)
	}, 2)
	if release == nil {
		t.Fatal("release is nil")
	}
	release()
	if got := calls.Load(); got != 0 {
		t.Fatalf("release calls after first recipient = %d, want 0", got)
	}
	release()
	if got := calls.Load(); got != 1 {
		t.Fatalf("release calls after second recipient = %d, want 1", got)
	}
	release()
	if got := calls.Load(); got != 1 {
		t.Fatalf("release calls after extra recipient = %d, want 1", got)
	}
}

func TestKernelUDPDeliveredReleasePrefersFlowSubscriber(t *testing.T) {
	manager := NewManager()
	global := make(chan []dataplane.KernelUDPFrame, 1)
	flow := make(chan []dataplane.KernelUDPFrame, 1)
	manager.kernelUDPSubs[global] = struct{}{}
	manager.kernelUDPFlowSubs[7] = map[chan []dataplane.KernelUDPFrame]struct{}{flow: {}}

	var calls atomic.Int32
	frames := []dataplane.KernelUDPFrame{{
		FlowID:  7,
		Payload: []byte("payload"),
		Release: func() {
			calls.Add(1)
		},
	}}
	manager.prepareKernelUDPDeliveredReleasesLocked(frames)
	if frames[0].Release == nil {
		t.Fatal("release is nil")
	}
	frames[0].Release()
	if got := calls.Load(); got != 1 {
		t.Fatalf("release calls = %d, want 1 for exclusive flow subscriber", got)
	}
	if globalFrames := kernelUDPGlobalDeliveryFrames(frames, manager.kernelUDPFlowSubs); len(globalFrames) != 0 {
		t.Fatalf("global delivery frames = %d, want 0 when flow subscriber owns frame", len(globalFrames))
	}
}

func TestKernelUDPDeliveredReleaseCanMirrorFlowSubscriberToGlobal(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_EXCLUSIVE_FLOW_SUBSCRIBERS", "0")
	manager := NewManager()
	global := make(chan []dataplane.KernelUDPFrame, 1)
	flow := make(chan []dataplane.KernelUDPFrame, 1)
	manager.kernelUDPSubs[global] = struct{}{}
	manager.kernelUDPFlowSubs[7] = map[chan []dataplane.KernelUDPFrame]struct{}{flow: {}}

	var calls atomic.Int32
	frames := []dataplane.KernelUDPFrame{{
		FlowID:  7,
		Payload: []byte("payload"),
		Release: func() {
			calls.Add(1)
		},
	}}
	manager.prepareKernelUDPDeliveredReleasesLocked(frames)
	if frames[0].Release == nil {
		t.Fatal("release is nil")
	}
	frames[0].Release()
	if got := calls.Load(); got != 0 {
		t.Fatalf("release calls after first mirrored recipient = %d, want 0", got)
	}
	frames[0].Release()
	if got := calls.Load(); got != 1 {
		t.Fatalf("release calls after second mirrored recipient = %d, want 1", got)
	}
}

func TestKernelUDPDeliverSingleFlowBatchSkipsGlobalWhenExclusive(t *testing.T) {
	manager := NewManager()
	manager.kernelUDPFlows[7] = dataplane.KernelUDPFlow{
		ID:              7,
		Peer:            core.IXID("ix-a"),
		Endpoint:        core.EndpointID("ix-a-udp"),
		SourcePort:      17041,
		DestinationPort: 54000,
	}
	global := make(chan []dataplane.KernelUDPFrame, 1)
	flow := make(chan []dataplane.KernelUDPFrame, 1)
	manager.kernelUDPSubs[global] = struct{}{}
	manager.kernelUDPFlowSubs[7] = map[chan []dataplane.KernelUDPFrame]struct{}{flow: {}}
	packet := kerneludp.UDPPacket{
		SourceIP:        netip.MustParseAddr("198.51.100.10"),
		DestinationIP:   netip.MustParseAddr("192.0.2.20"),
		SourcePort:      54000,
		DestinationPort: 17041,
	}
	frames := []receivedKernelUDPFrame{
		{
			frame: dataplane.KernelUDPFrame{
				FlowID:    7,
				Direction: dataplane.KernelTransportInbound,
				Sequence:  1,
				Payload:   []byte("one"),
			},
			packet: packet,
		},
		{
			frame: dataplane.KernelUDPFrame{
				FlowID:    7,
				Direction: dataplane.KernelTransportInbound,
				Sequence:  2,
				Payload:   []byte("two"),
			},
			packet: packet,
		},
	}

	manager.deliverKernelUDPFrames(frames)

	select {
	case batch := <-flow:
		if len(batch) != 2 || string(batch[0].Payload) != "one" || string(batch[1].Payload) != "two" {
			t.Fatalf("flow batch = %#v, want two delivered frames", batch)
		}
	default:
		t.Fatal("flow subscriber did not receive delivered batch")
	}
	select {
	case batch := <-global:
		t.Fatalf("global subscriber received exclusive single-flow batch: %#v", batch)
	default:
	}
}

func TestKernelUDPDeliverSingleFlowBatchMirrorsGlobalWhenNotExclusive(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_EXCLUSIVE_FLOW_SUBSCRIBERS", "0")
	manager := NewManager()
	manager.kernelUDPFlows[7] = dataplane.KernelUDPFlow{
		ID:              7,
		Peer:            core.IXID("ix-a"),
		Endpoint:        core.EndpointID("ix-a-udp"),
		SourcePort:      17041,
		DestinationPort: 54000,
	}
	global := make(chan []dataplane.KernelUDPFrame, 1)
	flow := make(chan []dataplane.KernelUDPFrame, 1)
	manager.kernelUDPSubs[global] = struct{}{}
	manager.kernelUDPFlowSubs[7] = map[chan []dataplane.KernelUDPFrame]struct{}{flow: {}}
	packet := kerneludp.UDPPacket{
		SourceIP:        netip.MustParseAddr("198.51.100.10"),
		DestinationIP:   netip.MustParseAddr("192.0.2.20"),
		SourcePort:      54000,
		DestinationPort: 17041,
	}
	frames := []receivedKernelUDPFrame{
		{
			frame: dataplane.KernelUDPFrame{
				FlowID:    7,
				Direction: dataplane.KernelTransportInbound,
				Sequence:  1,
				Payload:   []byte("one"),
			},
			packet: packet,
		},
		{
			frame: dataplane.KernelUDPFrame{
				FlowID:    7,
				Direction: dataplane.KernelTransportInbound,
				Sequence:  2,
				Payload:   []byte("two"),
			},
			packet: packet,
		},
	}

	manager.deliverKernelUDPFrames(frames)

	select {
	case batch := <-flow:
		if len(batch) != 2 {
			t.Fatalf("flow batch len = %d, want 2", len(batch))
		}
	default:
		t.Fatal("flow subscriber did not receive delivered batch")
	}
	select {
	case batch := <-global:
		if len(batch) != 2 {
			t.Fatalf("global batch len = %d, want 2", len(batch))
		}
	default:
		t.Fatal("global subscriber did not receive mirrored batch")
	}
}

func TestKernelUDPDeliveredBatchReleaseWaitsForAllRecipients(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_EXCLUSIVE_FLOW_SUBSCRIBERS", "0")
	manager := NewManager()
	global := make(chan []dataplane.KernelUDPFrame, 1)
	flow := make(chan []dataplane.KernelUDPFrame, 1)
	manager.kernelUDPSubs[global] = struct{}{}
	manager.kernelUDPFlowSubs[7] = map[chan []dataplane.KernelUDPFrame]struct{}{flow: {}}
	var payloadReleases atomic.Int32
	holder, frames := takeDeliveredKernelUDPFrameBatch(1)
	frames = append(frames, dataplane.KernelUDPFrame{
		FlowID:  7,
		Payload: []byte("payload"),
		Release: func() {
			payloadReleases.Add(1)
		},
	})

	manager.prepareKernelUDPDeliveredReleasesLocked(frames)
	manager.prepareKernelUDPDeliveredBatchReleaseLocked(frames, holder)

	frames[0].Release()
	if got := payloadReleases.Load(); got != 0 {
		t.Fatalf("payload releases after first recipient = %d, want 0", got)
	}
	if frames[0].Payload == nil {
		t.Fatal("pooled frame was cleared before all recipients released")
	}
	frames[0].Release()
	if got := payloadReleases.Load(); got != 1 {
		t.Fatalf("payload releases after second recipient = %d, want 1", got)
	}
	if frames[0].Payload != nil {
		t.Fatal("pooled frame was not cleared after all recipients released")
	}
}

func TestTIXTCPDeliverReleasesLoopbackFrame(t *testing.T) {
	manager := NewManager()
	manager.tixTCPFlows[7] = dataplane.TIXTCPFlow{
		ID:              7,
		LocalAddress:    "198.51.100.10:17041",
		RemoteAddress:   "192.0.2.20:54000",
		SourcePort:      17041,
		DestinationPort: 54000,
	}

	var calls atomic.Int32
	manager.deliverTIXTCPFrame(dataplane.TIXTCPFrame{
		FlowID:  7,
		Payload: []byte("loopback"),
		Release: func() {
			calls.Add(1)
		},
	}, tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("198.51.100.10"),
		DestinationIP:   netip.MustParseAddr("192.0.2.20"),
		SourcePort:      17041,
		DestinationPort: 54000,
	})

	if got := calls.Load(); got != 1 {
		t.Fatalf("release calls = %d, want 1 for dropped loopback frame", got)
	}
}

func TestTIXTCPDeliverDoesNotDropRemoteFrameWithSamePorts(t *testing.T) {
	manager := NewManager()
	manager.tixTCPFlows[7] = dataplane.TIXTCPFlow{
		ID:              7,
		LocalAddress:    "198.51.100.10:17041",
		RemoteAddress:   "192.0.2.20:54000",
		SourcePort:      17041,
		DestinationPort: 54000,
	}
	events := make(chan []dataplane.TIXTCPFrame, 1)
	manager.tixTCPSubs[events] = struct{}{}

	var calls atomic.Int32
	manager.deliverTIXTCPFrame(dataplane.TIXTCPFrame{
		FlowID:  7,
		Payload: []byte("remote"),
		Release: func() {
			calls.Add(1)
		},
	}, tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.20"),
		DestinationIP:   netip.MustParseAddr("198.51.100.10"),
		SourcePort:      17041,
		DestinationPort: 54000,
	})

	select {
	case batch := <-events:
		if len(batch) != 1 || string(batch[0].Payload) != "remote" {
			t.Fatalf("delivered batch = %#v, want remote frame", batch)
		}
		releaseTIXTCPFramePayloads(batch)
	default:
		t.Fatal("remote frame with matching ports was dropped")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("release calls after subscriber release = %d, want 1", got)
	}
	if flow := manager.tixTCPFlows[7]; !flow.ExpiresAt.IsZero() {
		t.Fatalf("established tix_tcp flow expires_at = %s after RX, want persistent zero value", flow.ExpiresAt)
	}
}

func TestTIXTCPDeliverUsesExclusiveFlowSubscriber(t *testing.T) {
	manager := NewManager()
	manager.tixTCPFlows[7] = dataplane.TIXTCPFlow{
		ID:              7,
		LocalAddress:    "198.51.100.10:17041",
		RemoteAddress:   "192.0.2.20:54000",
		SourcePort:      17041,
		DestinationPort: 54000,
	}
	globalEvents := make(chan []dataplane.TIXTCPFrame, 1)
	flowEvents := make(chan []dataplane.TIXTCPFrame, 1)
	manager.tixTCPSubs[globalEvents] = struct{}{}
	manager.tixTCPFlowSubs[7] = map[chan []dataplane.TIXTCPFrame]struct{}{flowEvents: {}}

	var calls atomic.Int32
	manager.deliverTIXTCPFrame(dataplane.TIXTCPFrame{
		FlowID:  7,
		Payload: []byte("flow-owned"),
		Release: func() {
			calls.Add(1)
		},
	}, tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.20"),
		DestinationIP:   netip.MustParseAddr("198.51.100.10"),
		SourcePort:      17041,
		DestinationPort: 54000,
	})

	select {
	case batch := <-flowEvents:
		if len(batch) != 1 || string(batch[0].Payload) != "flow-owned" {
			t.Fatalf("flow delivery batch = %#v, want flow-owned frame", batch)
		}
		releaseTIXTCPFramePayloads(batch)
	default:
		t.Fatal("flow-owned frame was not delivered to flow subscriber")
	}
	select {
	case batch := <-globalEvents:
		releaseTIXTCPFramePayloads(batch)
		t.Fatal("flow-owned frame was also delivered to global subscriber")
	default:
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("release calls = %d, want 1 for exclusive flow delivery", got)
	}
}

func TestTIXTCPGlobalDeliveryFramesExcludesFlowOwnedFrames(t *testing.T) {
	flowEvents := make(chan []dataplane.TIXTCPFrame, 1)
	frames := []dataplane.TIXTCPFrame{
		{FlowID: 7, Payload: []byte("flow-owned")},
		{FlowID: 8, Payload: []byte("global")},
	}
	global := tixTCPGlobalDeliveryFrames(frames, map[uint64]map[chan []dataplane.TIXTCPFrame]struct{}{
		7: {flowEvents: {}},
	})
	if len(global) != 1 || global[0].FlowID != 8 || string(global[0].Payload) != "global" {
		t.Fatalf("global delivery frames = %#v, want only flow 8", global)
	}
}

func TestTIXTCPDeliverLearnsTupleForControlOnlyFlow(t *testing.T) {
	manager := NewManager()
	manager.tixTCPFlows[7] = dataplane.TIXTCPFlow{
		ID:       7,
		Peer:     core.IXID("ix-a"),
		Endpoint: core.EndpointID("ix-a-tixt"),
	}
	events := make(chan []dataplane.TIXTCPFrame, 1)
	manager.tixTCPSubs[events] = struct{}{}

	manager.deliverTIXTCPFrame(dataplane.TIXTCPFrame{
		FlowID:  7,
		Payload: []byte("learn"),
	}, tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.20"),
		DestinationIP:   netip.MustParseAddr("198.51.100.10"),
		SourcePort:      41017,
		DestinationPort: 17041,
	})

	select {
	case batch := <-events:
		if len(batch) != 1 || string(batch[0].Payload) != "learn" {
			t.Fatalf("delivered batch = %#v, want learned frame", batch)
		}
	default:
		t.Fatal("learned control-only flow frame was not delivered")
	}
	flow := manager.tixTCPFlows[7]
	if flow.LocalAddress != "198.51.100.10:17041" || flow.RemoteAddress != "192.0.2.20:41017" {
		t.Fatalf("learned addresses local=%q remote=%q", flow.LocalAddress, flow.RemoteAddress)
	}
	if flow.SourcePort != 17041 || flow.DestinationPort != 41017 {
		t.Fatalf("learned ports source=%d destination=%d", flow.SourcePort, flow.DestinationPort)
	}
}

func TestTIXTCPDeliverInfersInboundPeerIdentityFromEndpointAddress(t *testing.T) {
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Peers: []dataplane.PeerMetadata{{ID: core.IXID("ix-b"), Trusted: true}},
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-a-tixt"),
				Peer:      core.IXID("ix-a"),
				Transport: "tix_tcp",
				Listen:    "192.0.2.20:17041",
				Address:   "192.0.2.20:17041",
				Enabled:   true,
			},
			{
				ID:        core.EndpointID("ix-b-tixt"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Address:   "198.51.100.10:17041",
				Enabled:   true,
			},
		},
	}
	events := make(chan []dataplane.TIXTCPFrame, 1)
	manager.tixTCPSubs[events] = struct{}{}

	manager.deliverTIXTCPFrame(dataplane.TIXTCPFrame{
		FlowID:  7,
		Payload: []byte("plain"),
	}, tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("198.51.100.10"),
		DestinationIP:   netip.MustParseAddr("192.0.2.20"),
		SourcePort:      17041,
		DestinationPort: 17041,
	})

	delivered := <-events
	if len(delivered) != 1 {
		t.Fatalf("delivered frames = %d, want 1", len(delivered))
	}
	frame := delivered[0]
	if frame.Peer != "ix-b" {
		t.Fatalf("delivered peer = %q, want ix-b", frame.Peer)
	}
	if frame.Endpoint != "ix-a-tixt" {
		t.Fatalf("delivered endpoint = %q, want local listener endpoint", frame.Endpoint)
	}
	flow := manager.tixTCPFlows[7]
	if flow.Peer != "ix-b" || flow.Endpoint != "ix-b-tixt" {
		t.Fatalf("learned flow identity peer=%q endpoint=%q, want ix-b/ix-b-tixt", flow.Peer, flow.Endpoint)
	}
	if flow.LocalAddress != "192.0.2.20:17041" || flow.RemoteAddress != "198.51.100.10:17041" {
		t.Fatalf("learned flow addresses local=%q remote=%q", flow.LocalAddress, flow.RemoteAddress)
	}
}

func TestTIXTCPDeliverCorrectsEndpointFilledControlFlowTuple(t *testing.T) {
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Peers: []dataplane.PeerMetadata{{ID: core.IXID("ix-b"), Trusted: true}},
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-a-tixt"),
				Peer:      core.IXID("ix-a"),
				Transport: "tix_tcp",
				Listen:    "192.0.2.20:17041",
				Enabled:   true,
			},
			{
				ID:        core.EndpointID("ix-b-tixt"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Address:   "198.51.100.10:17041",
				Enabled:   true,
			},
		},
	}
	manager.tixTCPFlows[7] = dataplane.TIXTCPFlow{
		ID:              7,
		Peer:            core.IXID("ix-b"),
		Endpoint:        core.EndpointID("ix-b-tixt"),
		RemoteAddress:   "198.51.100.10:17041",
		CryptoPlacement: dataplane.CryptoPlacementUserspace,
	}
	events := make(chan []dataplane.TIXTCPFrame, 1)
	manager.tixTCPSubs[events] = struct{}{}

	manager.deliverTIXTCPFrame(dataplane.TIXTCPFrame{
		FlowID:  7,
		Payload: []byte("learn"),
	}, tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("198.51.100.10"),
		DestinationIP:   netip.MustParseAddr("192.0.2.20"),
		SourcePort:      49231,
		DestinationPort: 17041,
	})

	frame := (<-events)[0]
	if frame.Endpoint != "ix-a-tixt" {
		t.Fatalf("delivered endpoint = %q, want local listener endpoint", frame.Endpoint)
	}
	flow := manager.tixTCPFlows[7]
	if flow.RemoteAddress != "198.51.100.10:49231" {
		t.Fatalf("remote address = %q, want learned packet tuple", flow.RemoteAddress)
	}
	if flow.SourcePort != 17041 || flow.DestinationPort != 49231 {
		t.Fatalf("learned ports source=%d destination=%d", flow.SourcePort, flow.DestinationPort)
	}
}

func TestTIXTCPDeliverCorrectsPreparedOutboundTupleFromInboundPacket(t *testing.T) {
	manager := NewManager()
	manager.tixTCPFlows[7] = dataplane.TIXTCPFlow{
		ID:              7,
		Peer:            core.IXID("ix-a"),
		Endpoint:        core.EndpointID("ix-a-tixt"),
		LocalAddress:    "10.10.0.12:57390",
		RemoteAddress:   "10.10.0.11:7141",
		SourcePort:      57390,
		DestinationPort: 7141,
		CryptoPlacement: dataplane.CryptoPlacementUserspace,
	}
	events := make(chan []dataplane.TIXTCPFrame, 1)
	manager.tixTCPFlowSubs[7] = map[chan []dataplane.TIXTCPFrame]struct{}{events: {}}

	manager.deliverTIXTCPFrame(dataplane.TIXTCPFrame{
		FlowID:  7,
		Payload: []byte("reverse"),
	}, tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("10.10.0.11"),
		DestinationIP:   netip.MustParseAddr("10.10.0.12"),
		SourcePort:      57390,
		DestinationPort: 7142,
	})

	<-events
	flow := manager.tixTCPFlows[7]
	if flow.LocalAddress != "10.10.0.12:7142" || flow.RemoteAddress != "10.10.0.11:57390" {
		t.Fatalf("corrected addresses local=%q remote=%q", flow.LocalAddress, flow.RemoteAddress)
	}
	if flow.SourcePort != 7142 || flow.DestinationPort != 57390 {
		t.Fatalf("corrected ports source=%d destination=%d", flow.SourcePort, flow.DestinationPort)
	}
}

func TestTIXTCPDeliverPreservesFlowEndpointWhenLocalEndpointUnknown(t *testing.T) {
	manager := NewManager()
	manager.tixTCPFlows[7] = dataplane.TIXTCPFlow{
		ID:              7,
		Peer:            core.IXID("ix-a"),
		Endpoint:        core.EndpointID("ix-a-tixt"),
		LocalAddress:    "198.51.100.10:17041",
		RemoteAddress:   "192.0.2.20:54000",
		SourcePort:      17041,
		DestinationPort: 54000,
	}
	events := make(chan []dataplane.TIXTCPFrame, 1)
	manager.tixTCPFlowSubs[7] = map[chan []dataplane.TIXTCPFrame]struct{}{events: {}}

	manager.deliverTIXTCPFrames([]receivedTIXTCPFrame{
		{
			frame: dataplane.TIXTCPFrame{
				FlowID:   7,
				Sequence: 10,
				Payload:  []byte("first"),
			},
			packet: tixtcp.TCPPacket{
				SourceIP:        netip.MustParseAddr("192.0.2.20"),
				DestinationIP:   netip.MustParseAddr("198.51.100.10"),
				SourcePort:      54000,
				DestinationPort: 17041,
				Sequence:        100,
				Payload:         bytes.Repeat([]byte{0x5a}, 80),
			},
		},
		{
			frame: dataplane.TIXTCPFrame{
				FlowID:   7,
				Sequence: 11,
				Payload:  []byte("second"),
			},
			packet: tixtcp.TCPPacket{
				SourceIP:        netip.MustParseAddr("192.0.2.20"),
				DestinationIP:   netip.MustParseAddr("198.51.100.10"),
				SourcePort:      54000,
				DestinationPort: 17041,
				Sequence:        181,
				Payload:         bytes.Repeat([]byte{0x5a}, 80),
			},
		},
	})

	batch := <-events
	if batch[0].Endpoint != "ix-a-tixt" {
		t.Fatalf("delivered endpoint = %q, want flow endpoint when local endpoint is unknown", batch[0].Endpoint)
	}
}

func TestTIXTCPDeliverSingleFlowBatchToSubscriber(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_RX_SINGLE_FLOW_BATCH", "1")
	manager := NewManager()
	manager.tixTCPFlows[7] = dataplane.TIXTCPFlow{
		ID:              7,
		Peer:            core.IXID("ix-a"),
		Endpoint:        core.EndpointID("ix-a-tixt"),
		LocalAddress:    "198.51.100.10:17041",
		RemoteAddress:   "192.0.2.20:54000",
		SourcePort:      17041,
		DestinationPort: 54000,
	}
	events := make(chan []dataplane.TIXTCPFrame, 1)
	manager.tixTCPFlowSubs[7] = map[chan []dataplane.TIXTCPFrame]struct{}{events: {}}

	var releases atomic.Int32
	packet := tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.20"),
		DestinationIP:   netip.MustParseAddr("198.51.100.10"),
		SourcePort:      54000,
		DestinationPort: 17041,
		Sequence:        100,
		Payload:         bytes.Repeat([]byte{0x5a}, 80),
	}
	manager.deliverTIXTCPFrames([]receivedTIXTCPFrame{
		{
			frame: dataplane.TIXTCPFrame{
				FlowID:   7,
				Sequence: 10,
				Payload:  []byte("first"),
				Release:  func() { releases.Add(1) },
			},
			packet: packet,
		},
		{
			frame: dataplane.TIXTCPFrame{
				FlowID:   7,
				Sequence: 11,
				Payload:  []byte("second"),
				Release:  func() { releases.Add(1) },
			},
			packet: packet,
		},
	})

	select {
	case batch := <-events:
		if len(batch) != 2 {
			t.Fatalf("delivered batch length = %d, want 2", len(batch))
		}
		if string(batch[0].Payload) != "first" || string(batch[1].Payload) != "second" {
			t.Fatalf("delivered payloads = %q/%q", batch[0].Payload, batch[1].Payload)
		}
		if batch[0].Peer != "ix-a" || batch[0].Endpoint != "ix-a-tixt" {
			t.Fatalf("delivered identity = %s/%s", batch[0].Peer, batch[0].Endpoint)
		}
		releaseTIXTCPFramePayloads(batch)
	default:
		t.Fatal("single-flow batch was not delivered to flow subscriber")
	}
	if got := releases.Load(); got != 2 {
		t.Fatalf("release calls = %d, want 2", got)
	}
	if got := manager.tixTCPReceived; got != 2 {
		t.Fatalf("tixTCPReceived = %d, want 2", got)
	}
	if flow := manager.tixTCPFlows[7]; !flow.ExpiresAt.IsZero() {
		t.Fatalf("established tix_tcp flow expires_at = %s after batched RX, want persistent zero value", flow.ExpiresAt)
	}
}

func TestKernelUDPDeliverDoesNotDowngradeKernelCryptoFlow(t *testing.T) {
	manager := NewManager()
	manager.kernelUDPFlows[7] = dataplane.KernelUDPFlow{
		ID:              7,
		Peer:            core.IXID("ix-a"),
		Endpoint:        core.EndpointID("ix-a-udp"),
		SourcePort:      17041,
		DestinationPort: 54000,
		CryptoSuite:     kernelCryptoSuiteAES256GCMX25519,
		CryptoPlacement: dataplane.CryptoPlacementKernel,
	}

	manager.deliverKernelUDPFrame(dataplane.KernelUDPFrame{
		FlowID:          7,
		Direction:       dataplane.KernelTransportInbound,
		Sequence:        2,
		Payload:         []byte("plain handshake or duplicate"),
		CryptoPlacement: dataplane.CryptoPlacementUserspace,
	}, kerneludp.UDPPacket{
		SourceIP:        netip.MustParseAddr("198.51.100.10"),
		DestinationIP:   netip.MustParseAddr("192.0.2.20"),
		SourcePort:      54000,
		DestinationPort: 17041,
	})

	flow := manager.kernelUDPFlows[7]
	if flow.CryptoPlacement != dataplane.CryptoPlacementKernel {
		t.Fatalf("flow crypto placement = %q, want kernel", flow.CryptoPlacement)
	}
	if got := manager.kernelUDPTelemetry[7].CryptoPlacement; got != dataplane.CryptoPlacementKernel {
		t.Fatalf("telemetry crypto placement = %q, want kernel", got)
	}
	if !flow.ExpiresAt.IsZero() {
		t.Fatalf("established kernel UDP flow expires_at = %s after RX, want persistent zero value", flow.ExpiresAt)
	}
}

func TestKernelUDPDeliverInfersInboundPeerIdentityFromEndpointAddress(t *testing.T) {
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
		Peers: []dataplane.PeerMetadata{
			{ID: core.IXID("ix-b"), DomainID: core.DomainID("lab.local"), Trusted: true},
		},
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-a-kernel_udp"),
				Peer:      core.IXID("ix-a"),
				Transport: "udp",
				Listen:    "192.0.2.20:17041",
				Address:   "192.0.2.20:17041",
				Enabled:   true,
			},
			{
				ID:        core.EndpointID("ix-b-kernel_udp"),
				Peer:      core.IXID("ix-b"),
				Transport: "udp",
				Address:   "198.51.100.10:17041",
				Enabled:   true,
			},
		},
	}
	events := make(chan []dataplane.KernelUDPFrame, 1)
	manager.kernelUDPSubs[events] = struct{}{}

	manager.deliverKernelUDPFrame(dataplane.KernelUDPFrame{
		FlowID:    7,
		Direction: dataplane.KernelTransportInbound,
		Sequence:  1,
		InnerIPv4: true,
		Payload:   []byte("plain"),
	}, kerneludp.UDPPacket{
		SourceIP:        netip.MustParseAddr("198.51.100.10"),
		DestinationIP:   netip.MustParseAddr("192.0.2.20"),
		SourcePort:      17041,
		DestinationPort: 17041,
	})

	delivered := <-events
	if len(delivered) != 1 {
		t.Fatalf("delivered frames = %d, want 1", len(delivered))
	}
	frame := delivered[0]
	if frame.Peer != "ix-b" {
		t.Fatalf("delivered peer = %q, want ix-b", frame.Peer)
	}
	if frame.Endpoint != "ix-a-kernel_udp" {
		t.Fatalf("delivered endpoint = %q, want local listener endpoint", frame.Endpoint)
	}
	flow := manager.kernelUDPFlows[7]
	if flow.Peer != "ix-b" || flow.Endpoint != "ix-b-kernel_udp" {
		t.Fatalf("learned flow identity peer=%q endpoint=%q, want ix-b/ix-b-kernel_udp", flow.Peer, flow.Endpoint)
	}
	if flow.LocalAddress != "192.0.2.20:17041" || flow.RemoteAddress != "198.51.100.10:17041" {
		t.Fatalf("learned flow addresses local=%q remote=%q", flow.LocalAddress, flow.RemoteAddress)
	}
	if telemetry := manager.kernelUDPTelemetry[7]; telemetry == nil || telemetry.Peer != "ix-b" || telemetry.Endpoint != "ix-b-kernel_udp" || telemetry.RXFrames != 1 {
		t.Fatalf("telemetry = %+v, want inferred identity and one RX frame", telemetry)
	}
}

func TestKernelUDPDeliverPreservesFrameEndpointWhenLocalEndpointUnknown(t *testing.T) {
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Peers: []dataplane.PeerMetadata{{ID: core.IXID("ix-b"), Trusted: true}},
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        core.EndpointID("ix-b-kernel_udp"),
			Peer:      core.IXID("ix-b"),
			Transport: "udp",
			Address:   "198.51.100.10:17041",
			Enabled:   true,
		}},
	}
	events := make(chan []dataplane.KernelUDPFrame, 1)
	manager.kernelUDPSubs[events] = struct{}{}

	manager.deliverKernelUDPFrame(dataplane.KernelUDPFrame{
		FlowID:    8,
		Direction: dataplane.KernelTransportInbound,
		Endpoint:  core.EndpointID("explicit-local"),
		Payload:   []byte("hello"),
	}, kerneludp.UDPPacket{
		SourceIP:        netip.MustParseAddr("198.51.100.10"),
		DestinationIP:   netip.MustParseAddr("192.0.2.20"),
		SourcePort:      17041,
		DestinationPort: 17041,
	})

	frame := (<-events)[0]
	if frame.Endpoint != "explicit-local" {
		t.Fatalf("delivered endpoint = %q, want explicit frame endpoint", frame.Endpoint)
	}
	if flow := manager.kernelUDPFlows[8]; flow.Peer != "ix-b" || flow.Endpoint != "ix-b-kernel_udp" {
		t.Fatalf("learned flow identity peer=%q endpoint=%q, want ix-b/ix-b-kernel_udp", flow.Peer, flow.Endpoint)
	}
}

func TestKernelUDPDeliverInfersPeerFromUniqueEndpointIPWhenSourcePortIsEphemeral(t *testing.T) {
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Peers: []dataplane.PeerMetadata{{ID: core.IXID("ix-b"), Trusted: true}},
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-a-kernel_udp"),
				Peer:      core.IXID("ix-a"),
				Transport: "udp",
				Listen:    "192.0.2.20:17041",
				Enabled:   true,
			},
			{
				ID:        core.EndpointID("ix-b-kernel_udp"),
				Peer:      core.IXID("ix-b"),
				Transport: "udp",
				Address:   "198.51.100.10:17041",
				Enabled:   true,
			},
		},
	}
	events := make(chan []dataplane.KernelUDPFrame, 1)
	manager.kernelUDPSubs[events] = struct{}{}

	manager.deliverKernelUDPFrame(dataplane.KernelUDPFrame{
		FlowID:    9,
		Direction: dataplane.KernelTransportInbound,
		Payload:   []byte("data"),
	}, kerneludp.UDPPacket{
		SourceIP:        netip.MustParseAddr("198.51.100.10"),
		DestinationIP:   netip.MustParseAddr("192.0.2.20"),
		SourcePort:      43123,
		DestinationPort: 17041,
	})

	frame := (<-events)[0]
	if frame.Peer != "ix-b" || frame.Endpoint != "ix-a-kernel_udp" {
		t.Fatalf("delivered identity peer=%q endpoint=%q, want ix-b/local endpoint", frame.Peer, frame.Endpoint)
	}
	if flow := manager.kernelUDPFlows[9]; flow.Peer != "ix-b" || flow.Endpoint != "ix-b-kernel_udp" {
		t.Fatalf("learned flow identity peer=%q endpoint=%q, want ix-b/ix-b-kernel_udp", flow.Peer, flow.Endpoint)
	}
}

func TestKernelUDPDeliverDoesNotInferAmbiguousPeerFromEndpointIP(t *testing.T) {
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Peers: []dataplane.PeerMetadata{
			{ID: core.IXID("ix-b"), Trusted: true},
			{ID: core.IXID("ix-c"), Trusted: true},
		},
		Endpoints: []dataplane.EndpointMetadata{
			{ID: core.EndpointID("ix-b-kernel_udp"), Peer: core.IXID("ix-b"), Transport: "udp", Address: "198.51.100.10:17041", Enabled: true},
			{ID: core.EndpointID("ix-c-kernel_udp"), Peer: core.IXID("ix-c"), Transport: "udp", Address: "198.51.100.10:27041", Enabled: true},
		},
	}
	events := make(chan []dataplane.KernelUDPFrame, 1)
	manager.kernelUDPSubs[events] = struct{}{}

	manager.deliverKernelUDPFrame(dataplane.KernelUDPFrame{
		FlowID:    10,
		Direction: dataplane.KernelTransportInbound,
		Payload:   []byte("data"),
	}, kerneludp.UDPPacket{
		SourceIP:        netip.MustParseAddr("198.51.100.10"),
		DestinationIP:   netip.MustParseAddr("192.0.2.20"),
		SourcePort:      43123,
		DestinationPort: 17041,
	})

	frame := (<-events)[0]
	if frame.Peer != "" {
		t.Fatalf("delivered peer = %q, want no ambiguous inference", frame.Peer)
	}
	if flow := manager.kernelUDPFlows[10]; flow.Peer != "" || flow.Endpoint != "" {
		t.Fatalf("learned flow identity peer=%q endpoint=%q, want none", flow.Peer, flow.Endpoint)
	}
}

func TestInstalledKernelUDPFlowLifetimeIsSessionPersistent(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()

	flow := refreshInstalledKernelUDPFlowLifetime(dataplane.KernelUDPFlow{ID: 7}, now)

	if flow.CreatedAt != now {
		t.Fatalf("created_at = %s, want %s", flow.CreatedAt, now)
	}
	if flow.LastSeen != now {
		t.Fatalf("last_seen = %s, want %s", flow.LastSeen, now)
	}
	if !flow.ExpiresAt.IsZero() {
		t.Fatalf("installed kernel UDP flow expires_at = %s, want persistent zero value", flow.ExpiresAt)
	}
}

func TestEstablishedKernelUDPFlowClearsLearnedExpiry(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	learned := refreshKernelUDPFlowLifetime(dataplane.KernelUDPFlow{ID: 7}, now.Add(-time.Minute))

	flow := persistEstablishedKernelUDPFlowLifetime(learned, now)

	if flow.LastSeen != now {
		t.Fatalf("last_seen = %s, want %s", flow.LastSeen, now)
	}
	if !flow.ExpiresAt.IsZero() {
		t.Fatalf("established kernel UDP flow expires_at = %s, want persistent zero value", flow.ExpiresAt)
	}
}

func TestPreparedKernelUDPFlowPreservesPersistentLifetime(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	persistent := persistEstablishedKernelUDPFlowLifetime(dataplane.KernelUDPFlow{ID: 7}, now.Add(-time.Minute))

	flow := refreshKernelUDPPreparedFlowLifetime(persistent, now)

	if flow.LastSeen != now {
		t.Fatalf("last_seen = %s, want %s", flow.LastSeen, now)
	}
	if !flow.ExpiresAt.IsZero() {
		t.Fatalf("prepared persistent kernel UDP flow expires_at = %s, want zero value", flow.ExpiresAt)
	}
}

func TestInstalledTIXTCPFlowLifetimeIsSessionPersistent(t *testing.T) {
	manager := NewManager()

	if err := manager.InstallTIXTCPFlows(context.Background(), []dataplane.TIXTCPFlow{{
		ID:            7,
		RemoteAddress: "198.51.100.2:17041",
	}}); err != nil {
		t.Fatalf("install tix_tcp flow: %v", err)
	}
	flow := manager.tixTCPFlows[7]

	if flow.CreatedAt.IsZero() {
		t.Fatal("created_at was not set")
	}
	if flow.LastSeen.IsZero() {
		t.Fatal("last_seen was not set")
	}
	if !flow.ExpiresAt.IsZero() {
		t.Fatalf("installed tix_tcp flow expires_at = %s, want persistent zero value", flow.ExpiresAt)
	}
}

func TestControlOnlyTIXTCPFlowKeepsLearnedTTL(t *testing.T) {
	manager := NewManager()

	if err := manager.InstallTIXTCPFlows(context.Background(), []dataplane.TIXTCPFlow{{
		ID: 7,
	}}); err != nil {
		t.Fatalf("install control-only tix_tcp flow: %v", err)
	}
	flow := manager.tixTCPFlows[7]

	if flow.ExpiresAt.IsZero() {
		t.Fatal("control-only tix_tcp flow should keep a TTL until a remote tuple is learned or a session annotates it")
	}
}

func TestEstablishedTIXTCPFlowClearsLearnedExpiry(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	learned := refreshTIXTCPFlowLifetime(dataplane.TIXTCPFlow{ID: 7}, now.Add(-time.Minute))

	flow := persistEstablishedTIXTCPFlowLifetime(learned, now)

	if flow.LastSeen != now {
		t.Fatalf("last_seen = %s, want %s", flow.LastSeen, now)
	}
	if !flow.ExpiresAt.IsZero() {
		t.Fatalf("established tix_tcp flow expires_at = %s, want persistent zero value", flow.ExpiresAt)
	}
}

func TestPreparedTIXTCPFlowPreservesPersistentLifetime(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	persistent := persistEstablishedTIXTCPFlowLifetime(dataplane.TIXTCPFlow{ID: 7}, now.Add(-time.Minute))

	flow := refreshTIXTCPPreparedFlowLifetime(persistent, now)

	if flow.LastSeen != now {
		t.Fatalf("last_seen = %s, want %s", flow.LastSeen, now)
	}
	if !flow.ExpiresAt.IsZero() {
		t.Fatalf("prepared persistent tix_tcp flow expires_at = %s, want zero value", flow.ExpiresAt)
	}
}

func TestTIXTCPRawDecodeFiltersOtherInstanceBeforeChecksum(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_TCP_PRIMER", "1")
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
		Peers:        []dataplane.PeerMetadata{{ID: core.IXID("ix-b"), Trusted: true}},
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-a-tixt"),
				Peer:      core.IXID("ix-a"),
				Transport: "tix_tcp",
				Listen:    "192.0.2.10:18001",
				Enabled:   true,
			},
			{
				ID:        core.EndpointID("ix-b-tixt"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Address:   "198.51.100.20:18002",
				Enabled:   true,
			},
		},
	}
	manager.tixTCPFlows[77] = dataplane.TIXTCPFlow{
		ID:              77,
		LocalAddress:    "192.0.2.10:18001",
		RemoteAddress:   "198.51.100.20:43000",
		SourcePort:      18001,
		DestinationPort: 43000,
	}
	manager.tixTCPRawReceiveFilter.Store(manager.tixTCPRawReceiveFilterLocked())

	makeWire := func(destination string, port uint16, corruptTCPChecksum bool) []byte {
		t.Helper()
		frameWire, err := (tixtcp.Frame{
			FlowID:   77,
			Sequence: 1,
			Payload:  []byte("payload"),
		}).MarshalBinary()
		if err != nil {
			t.Fatalf("marshal tix_tcp frame: %v", err)
		}
		wire, err := tixtcp.MarshalTCPShapedIPv4(tixtcp.TCPPacket{
			SourceIP:        netip.MustParseAddr("198.51.100.20"),
			DestinationIP:   netip.MustParseAddr(destination),
			SourcePort:      43000,
			DestinationPort: port,
			Sequence:        100,
			Acknowledgment:  1,
			Payload:         frameWire,
		})
		if err != nil {
			t.Fatalf("marshal tix_tcp packet: %v", err)
		}
		if corruptTCPChecksum {
			wire[36] ^= 0xff
		}
		return wire
	}

	if _, ok := manager.decodeTIXTCPRawPacket(
		makeWire("192.0.2.11", 18001, true),
		tixtcp.ParseTCPShapedIPv4NoCopy,
	); ok {
		t.Fatal("raw decode accepted another instance using the same port on a different local address")
	}
	if _, ok := manager.decodeTIXTCPRawPacket(
		makeWire("192.0.2.10", 18011, true),
		tixtcp.ParseTCPShapedIPv4NoCopy,
	); ok {
		t.Fatal("raw decode accepted another instance using a different local port")
	}
	manager.tixTCPFlows[77] = dataplane.TIXTCPFlow{
		ID:              77,
		LocalAddress:    "192.0.2.10:18001",
		RemoteAddress:   "198.51.100.20:40077",
		SourcePort:      18001,
		DestinationPort: 40077,
	}
	manager.tixTCPRawReceiveFilter.Store(manager.tixTCPRawReceiveFilterLocked())
	if _, ok := manager.decodeTIXTCPRawPacket(
		makeWire("192.0.2.10", 18001, false),
		tixtcp.ParseTCPShapedIPv4NoCopy,
	); ok {
		t.Fatal("raw decode accepted compat primer temporary source port for an installed flow")
	}

	manager.tixTCPFlows[77] = dataplane.TIXTCPFlow{
		ID:              77,
		LocalAddress:    "192.0.2.10:18001",
		RemoteAddress:   "198.51.100.20:43000",
		SourcePort:      18001,
		DestinationPort: 43000,
	}
	manager.tixTCPRawReceiveFilter.Store(manager.tixTCPRawReceiveFilterLocked())
	if got := manager.dropReasons["CHECKSUM_ERROR"]; got != 0 {
		t.Fatalf("disallowed instance packets recorded checksum drops = %d, want 0", got)
	}

	item, ok := manager.decodeTIXTCPRawPacket(
		makeWire("192.0.2.10", 18001, false),
		tixtcp.ParseTCPShapedIPv4NoCopy,
	)
	if !ok || item.frame.FlowID != 77 {
		t.Fatalf("allowed instance packet decode = (%#v, %t), want flow 77", item.frame, ok)
	}
	if _, ok := manager.decodeTIXTCPRawPacket(
		makeWire("192.0.2.10", 18001, true),
		tixtcp.ParseTCPShapedIPv4NoCopy,
	); ok {
		t.Fatal("raw decode accepted an allowed packet with a bad TCP checksum")
	}
	if got := manager.dropReasons["CHECKSUM_ERROR"]; got != 1 {
		t.Fatalf("allowed bad packet checksum drops = %d, want 1", got)
	}
}

func TestTIXTCPRawReceiveFilterIncludesEstablishedLocalFlowPort(t *testing.T) {
	manager := NewManager()
	manager.tixTCPFlows[7] = dataplane.TIXTCPFlow{
		ID:              7,
		LocalAddress:    "192.0.2.10:43000",
		RemoteAddress:   "198.51.100.20:17041",
		SourcePort:      43000,
		DestinationPort: 17041,
	}
	filter := manager.tixTCPRawReceiveFilterLocked()

	packet := tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("198.51.100.20"),
		DestinationIP:   netip.MustParseAddr("192.0.2.10"),
		SourcePort:      17041,
		DestinationPort: 43000,
	}
	if !filter.allows(packet, 7) {
		t.Fatal("established flow local receive tuple was not allowed")
	}
	packet.DestinationIP = netip.MustParseAddr("192.0.2.11")
	if filter.allows(packet, 7) {
		t.Fatal("established flow port was allowed on another local address")
	}
	packet.DestinationIP = netip.MustParseAddr("192.0.2.10")
	packet.SourcePort = 17042
	if filter.allows(packet, 7) {
		t.Fatal("established flow accepted another remote source port")
	}
}

func TestTIXTCPRawReceiveFilterAllowsUnknownFlowOnlyWithoutPrimer(t *testing.T) {
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        core.EndpointID("ix-a-tixt"),
			Peer:      core.IXID("ix-a"),
			Transport: "tix_tcp",
			Listen:    "192.0.2.10:18001",
			Enabled:   true,
		}},
	}
	packet := tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("198.51.100.20"),
		DestinationIP:   netip.MustParseAddr("192.0.2.10"),
		SourcePort:      43000,
		DestinationPort: 18001,
	}

	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_TCP_PRIMER", "1")
	if manager.tixTCPRawReceiveFilterLocked().allows(packet, 77) {
		t.Fatal("primer mode accepted an unknown raw flow")
	}
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_TCP_PRIMER", "0")
	if !manager.tixTCPRawReceiveFilterLocked().allows(packet, 77) {
		t.Fatal("explicit no-primer mode rejected an unknown raw listener flow")
	}
}

func TestTIXTCPRawValidatedDeliveryDoesNotRewriteInstalledTuple(t *testing.T) {
	manager := NewManager()
	manager.tixTCPFlows[77] = dataplane.TIXTCPFlow{
		ID:              77,
		LocalAddress:    "192.0.2.10:18001",
		RemoteAddress:   "198.51.100.20:40077",
		SourcePort:      18001,
		DestinationPort: 40077,
	}
	events := make(chan []dataplane.TIXTCPFrame, 1)
	manager.tixTCPFlowSubs[77] = map[chan []dataplane.TIXTCPFrame]struct{}{events: {}}
	var releases atomic.Int32

	manager.deliverTIXTCPFrames([]receivedTIXTCPFrame{{
		frame: dataplane.TIXTCPFrame{
			FlowID:  77,
			Payload: []byte("primer-tuple"),
			Release: func() { releases.Add(1) },
		},
		packet: tixtcp.TCPPacket{
			SourceIP:        netip.MustParseAddr("198.51.100.20"),
			DestinationIP:   netip.MustParseAddr("192.0.2.10"),
			SourcePort:      43000,
			DestinationPort: 18001,
		},
		rawTupleValidated: true,
	}})

	select {
	case batch := <-events:
		releaseTIXTCPFramePayloads(batch)
		t.Fatal("raw delivery accepted a stale compat primer tuple")
	default:
	}
	flow := manager.tixTCPFlows[77]
	if flow.LocalAddress != "192.0.2.10:18001" || flow.RemoteAddress != "198.51.100.20:40077" ||
		flow.SourcePort != 18001 || flow.DestinationPort != 40077 {
		t.Fatalf("raw delivery rewrote installed flow tuple: %+v", flow)
	}
	if got := releases.Load(); got != 1 {
		t.Fatalf("rejected raw frame release calls = %d, want 1", got)
	}
}

func TestKernelTransportDNSTemplatesExpireAndRefresh(t *testing.T) {
	oldTTL := kernelTransportDNSCacheTTL
	kernelTransportDNSCacheTTL = time.Second
	t.Cleanup(func() {
		kernelTransportDNSCacheTTL = oldTTL
	})
	manager := NewManager()
	manager.kernelUDPFlows[7] = dataplane.KernelUDPFlow{
		ID:            7,
		LocalAddress:  "127.0.0.1:47007",
		RemoteAddress: "localhost:17041",
	}
	manager.tixTCPFlows[8] = dataplane.TIXTCPFlow{
		ID:            8,
		LocalAddress:  "127.0.0.1:47008",
		RemoteAddress: "localhost:17042",
	}

	if _, _, err := manager.prepareKernelUDPPacketLocked(7); err != nil {
		t.Fatalf("prepare kernel_udp hostname packet: %v", err)
	}
	if _, ok := manager.kernelUDPTXTemplates[7]; !ok {
		t.Fatal("kernel_udp DNS template was not cached")
	}
	if _, _, err := manager.prepareTIXTCPPacketLocked(8, 1); err != nil {
		t.Fatalf("prepare tix_tcp hostname packet: %v", err)
	}
	if _, ok := manager.tixTCPTXTemplates[8]; !ok {
		t.Fatal("tix_tcp DNS template was not cached")
	}
	if !manager.refreshKernelTransportDNSTemplatesLocked(time.Now().UTC().Add(time.Second)) {
		t.Fatal("DNS template refresh reported no expired templates")
	}
	if _, ok := manager.kernelUDPTXTemplates[7]; ok {
		t.Fatal("expired kernel_udp DNS template survived refresh")
	}
	if _, ok := manager.tixTCPTXTemplates[8]; ok {
		t.Fatal("expired tix_tcp DNS template survived refresh")
	}
}

func TestKernelTransportLiteralTemplatesDoNotExpire(t *testing.T) {
	manager := NewManager()
	manager.kernelUDPFlows[7] = dataplane.KernelUDPFlow{
		ID:            7,
		LocalAddress:  "127.0.0.1:47007",
		RemoteAddress: "127.0.0.1:17041",
	}
	manager.tixTCPFlows[8] = dataplane.TIXTCPFlow{
		ID:            8,
		LocalAddress:  "127.0.0.1:47008",
		RemoteAddress: "127.0.0.1:17042",
	}

	if _, _, err := manager.prepareKernelUDPPacketLocked(7); err != nil {
		t.Fatalf("prepare kernel_udp literal packet: %v", err)
	}
	if _, _, err := manager.prepareTIXTCPPacketLocked(8, 1); err != nil {
		t.Fatalf("prepare tix_tcp literal packet: %v", err)
	}
	if manager.refreshKernelTransportDNSTemplatesLocked(time.Now().UTC().Add(24 * time.Hour)) {
		t.Fatal("literal endpoint templates should not expire through DNS refresh")
	}
	if _, ok := manager.kernelUDPTXTemplates[7]; !ok {
		t.Fatal("literal kernel_udp template was removed")
	}
	if _, ok := manager.tixTCPTXTemplates[8]; !ok {
		t.Fatal("literal tix_tcp template was removed")
	}
}

func TestKernelTransportExpiredAutoLocalDNSRefreshClearsLearnedSource(t *testing.T) {
	oldTTL := kernelTransportDNSCacheTTL
	kernelTransportDNSCacheTTL = time.Second
	t.Cleanup(func() {
		kernelTransportDNSCacheTTL = oldTTL
	})
	manager := NewManager()
	manager.kernelUDPFlows[7] = dataplane.KernelUDPFlow{
		ID:            7,
		RemoteAddress: "localhost:17041",
	}

	if _, _, err := manager.prepareKernelUDPPacketLocked(7); err != nil {
		t.Fatalf("prepare kernel_udp hostname packet: %v", err)
	}
	if flow := manager.kernelUDPFlows[7]; flow.LocalAddress == "" || flow.SourcePort == 0 {
		t.Fatalf("prepared flow did not learn local source: %+v", flow)
	}
	if !manager.refreshKernelTransportDNSTemplatesLocked(time.Now().UTC().Add(2 * time.Second)) {
		t.Fatal("DNS template refresh reported no expired templates")
	}
	if flow := manager.kernelUDPFlows[7]; flow.LocalAddress != "" || flow.SourcePort != 0 {
		t.Fatalf("expired auto-local template kept learned source: %+v", flow)
	}
}

func TestPruneKernelUDPFlowsClearsCryptoState(t *testing.T) {
	manager := NewManager()
	now := time.Unix(1700000000, 0).UTC()
	manager.kernelUDPFlows[7] = dataplane.KernelUDPFlow{
		ID:        7,
		ExpiresAt: now.Add(-time.Second),
	}
	manager.kernelUDPTXDirectSequences[7] = 42
	manager.kernelUDPTelemetry[7] = &dataplane.TransportPathTelemetry{}
	manager.kernelCryptoFlowMapEntries = map[kernelCryptoFlowKey]struct{}{
		kernelCryptoFlowKeyFor(kernelCryptoNamespaceKernelUDP, 7, kernelCryptoDirectionSend): {},
		kernelCryptoFlowKeyFor(kernelCryptoNamespaceKernelUDP, 7, kernelCryptoDirectionRecv): {},
	}
	manager.kernelCryptoCtxSlots = map[kernelCryptoFlowKey]uint32{
		kernelCryptoFlowKeyFor(kernelCryptoNamespaceKernelUDP, 7, kernelCryptoDirectionSend): 1,
		kernelCryptoFlowKeyFor(kernelCryptoNamespaceKernelUDP, 7, kernelCryptoDirectionRecv): 2,
	}

	if !manager.pruneKernelUDPFlowsLocked(now) {
		t.Fatal("pruneKernelUDPFlowsLocked returned false, want true")
	}
	if _, ok := manager.kernelUDPFlows[7]; ok {
		t.Fatal("expired kernel UDP flow was not pruned")
	}
	if _, ok := manager.kernelUDPTXDirectSequences[7]; ok {
		t.Fatal("expired kernel UDP TX direct sequence was not pruned")
	}
	if _, ok := manager.kernelUDPTelemetry[7]; ok {
		t.Fatal("expired kernel UDP telemetry was not pruned")
	}
	if got := len(manager.kernelCryptoFlowMapEntries); got != 0 {
		t.Fatalf("kernel crypto flow map entries = %d, want 0", got)
	}
	if got := len(manager.kernelCryptoCtxSlots); got != 0 {
		t.Fatalf("kernel crypto ctx slots = %d, want 0", got)
	}
}

func TestKernelUDPDeliverSingleFlowBatchToSubscribers(t *testing.T) {
	manager := NewManager()
	manager.kernelUDPFlows[7] = dataplane.KernelUDPFlow{
		ID:              7,
		Peer:            core.IXID("ix-a"),
		Endpoint:        core.EndpointID("ix-a-udp"),
		SourcePort:      17041,
		DestinationPort: 54000,
		CryptoSuite:     kernelCryptoSuiteAES256GCMX25519,
		CryptoPlacement: dataplane.CryptoPlacementKernel,
	}
	global := make(chan []dataplane.KernelUDPFrame, 1)
	flow := make(chan []dataplane.KernelUDPFrame, 1)
	manager.kernelUDPSubs[global] = struct{}{}
	manager.kernelUDPFlowSubs[7] = map[chan []dataplane.KernelUDPFrame]struct{}{flow: {}}
	packet := kerneludp.UDPPacket{
		SourceIP:        netip.MustParseAddr("198.51.100.10"),
		DestinationIP:   netip.MustParseAddr("192.0.2.20"),
		SourcePort:      54000,
		DestinationPort: 17041,
	}
	frames := []receivedKernelUDPFrame{
		{
			frame: dataplane.KernelUDPFrame{
				FlowID:    7,
				Direction: dataplane.KernelTransportInbound,
				Sequence:  10,
				Payload:   []byte("one"),
			},
			packet: packet,
		},
		{
			frame: dataplane.KernelUDPFrame{
				FlowID:    7,
				Direction: dataplane.KernelTransportInbound,
				Sequence:  11,
				Payload:   []byte("two"),
			},
			packet: packet,
		},
	}

	manager.deliverKernelUDPFrames(frames)

	select {
	case batch := <-flow:
		if len(batch) != 2 || string(batch[0].Payload) != "one" || string(batch[1].Payload) != "two" {
			t.Fatalf("flow batch = %#v, want two delivered frames", batch)
		}
	default:
		t.Fatal("flow subscriber did not receive delivered batch")
	}
	select {
	case batch := <-global:
		t.Fatalf("global subscriber received exclusive flow batch: %#v", batch)
	default:
	}
	telemetry := manager.kernelUDPTelemetry[7]
	if telemetry == nil || telemetry.RXFrames != 2 || telemetry.RXBytes != 6 || telemetry.RXLastSequence != 11 || telemetry.RXExpectedSequence != 12 {
		t.Fatalf("telemetry = %+v, want two sequential RX frames", telemetry)
	}
	if flow := manager.kernelUDPFlows[7]; !flow.ExpiresAt.IsZero() {
		t.Fatalf("established kernel UDP flow expires_at = %s after batched RX, want persistent zero value", flow.ExpiresAt)
	}
}

func TestKernelCryptoInstallStats(t *testing.T) {
	manager := NewManager()
	spec := validKernelCryptoSpec(42)

	err := manager.InstallTIXTCPCrypto(context.Background(), []dataplane.TIXTCPCryptoSpec{spec})
	if err == nil || !strings.Contains(err.Error(), "kernel crypto provider is not available") {
		t.Fatalf("install crypto error = %v, want provider unavailable", err)
	}

	badSpec := spec
	badSpec.FlowID = 43
	badSpec.SendKey = badSpec.SendKey[:kernelCryptoAES256KeyLen-1]
	err = manager.InstallTIXTCPCrypto(context.Background(), []dataplane.TIXTCPCryptoSpec{badSpec})
	if err == nil || !strings.Contains(err.Error(), "send key length") {
		t.Fatalf("install bad crypto error = %v, want send key length", err)
	}

	status, err := manager.TIXTCPStatus(context.Background())
	if err != nil {
		t.Fatalf("experimental tcp status: %v", err)
	}
	stats := status.ProviderStats
	wantStats := map[string]uint64{
		"kernel_crypto_install_attempts":              2,
		"kernel_crypto_specs_validated":               1,
		"kernel_crypto_specs_rejected":                2,
		"kernel_crypto_spec_validate_errors":          1,
		"kernel_crypto_provider_unavailable_errors":   1,
		"kernel_crypto_entries_encoded":               2,
		"kernel_crypto_flow_map_ready":                0,
		"kernel_crypto_flow_map_create_errors":        0,
		"kernel_crypto_flow_map_updates":              0,
		"kernel_crypto_flow_map_deletes":              0,
		"kernel_crypto_flow_map_entries":              0,
		"kernel_crypto_ctx_provider_loaded":           0,
		"kernel_crypto_ctx_provider_load_errors":      0,
		"kernel_crypto_aead_gcm_ctx_create_attempts":  0,
		"kernel_crypto_aead_gcm_ctx_create_successes": 0,
		"kernel_crypto_aead_gcm_ctx_create_errors":    0,
		"kernel_crypto_aead_gcm_roundtrip_attempts":   0,
		"kernel_crypto_aead_gcm_roundtrip_successes":  0,
		"kernel_crypto_aead_gcm_roundtrip_errors":     0,
		"kernel_crypto_command_size":                  uint64(kernelCryptoCommandSize()),
		"kernel_crypto_map_key_size":                  uint64(kernelCryptoMapSchema().FlowKeySize),
		"kernel_crypto_map_value_size":                uint64(kernelCryptoMapSchema().FlowValueSize),
		"kernel_crypto_map_max_entries":               uint64(kernelCryptoMaxEntries),
	}
	for name, want := range wantStats {
		if got := stats[name]; got != want {
			t.Fatalf("provider stat %s = %d, want %d", name, got, want)
		}
	}
	for name := range stats {
		if strings.Contains(name, "key_material") || strings.Contains(name, "send_key") || strings.Contains(name, "recv_key") {
			t.Fatalf("provider stats exposed secret-looking key %q", name)
		}
	}
}

func TestInstallTIXTCPFlowsReplacesDuplicatePath(t *testing.T) {
	manager := NewManager()
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		1: {
			ID:              1,
			Peer:            "ix-b",
			Endpoint:        "exp-b",
			LocalAddress:    "198.18.0.1:41001",
			RemoteAddress:   "198.18.0.2:17042",
			SourcePort:      41001,
			DestinationPort: 17042,
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
	}
	manager.tixTCPTelemetry = map[uint64]*dataplane.TransportPathTelemetry{
		1: {Protocol: "tix_tcp", FlowID: 1},
	}
	manager.kernelUDPTXDirectSequences = map[uint64]uint64{1: 7}
	manager.tixTCPOuterTXSequences = map[uint64]uint32{1: 8}
	manager.tixTCPOuterTXAcknowledgments = map[uint64]uint32{1: 9}

	if err := manager.InstallTIXTCPFlows(context.Background(), []dataplane.TIXTCPFlow{{
		ID:              2,
		Peer:            "ix-b",
		Endpoint:        "exp-b",
		LocalAddress:    "198.18.0.1:41001",
		RemoteAddress:   "198.18.0.2:17042",
		SourcePort:      41001,
		DestinationPort: 17042,
		CryptoPlacement: dataplane.CryptoPlacementUserspace,
	}}); err != nil {
		t.Fatalf("install duplicate tix_tcp flow: %v", err)
	}
	if _, ok := manager.tixTCPFlows[1]; ok {
		t.Fatal("old duplicate tix_tcp flow was not removed")
	}
	if _, ok := manager.tixTCPFlows[2]; !ok {
		t.Fatal("new tix_tcp flow was not installed")
	}
	if _, ok := manager.tixTCPTelemetry[1]; ok {
		t.Fatal("old tix_tcp telemetry was not removed")
	}
	if _, ok := manager.kernelUDPTXDirectSequences[1]; ok {
		t.Fatal("old kernel UDP direct sequence was not removed")
	}
	if _, ok := manager.tixTCPOuterTXSequences[1]; ok {
		t.Fatal("old tix_tcp outer TX sequence was not removed")
	}
	if _, ok := manager.tixTCPOuterTXAcknowledgments[1]; ok {
		t.Fatal("old tix_tcp outer TX acknowledgment was not removed")
	}
}

func TestInstallTIXTCPFlowsKeepsSameEndpointPoolMembers(t *testing.T) {
	manager := NewManager()
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		1: {
			ID:              1,
			Peer:            "ix-b",
			Endpoint:        "exp-b",
			LocalAddress:    "198.18.0.1:41001",
			RemoteAddress:   "198.18.0.2:17042",
			SourcePort:      41001,
			DestinationPort: 17042,
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}

	if err := manager.InstallTIXTCPFlows(context.Background(), []dataplane.TIXTCPFlow{{
		ID:              2,
		Peer:            "ix-b",
		Endpoint:        "exp-b",
		LocalAddress:    "198.18.0.1:41002",
		RemoteAddress:   "198.18.0.2:17042",
		SourcePort:      41002,
		DestinationPort: 17042,
		CryptoPlacement: dataplane.CryptoPlacementUserspace,
	}}); err != nil {
		t.Fatalf("install pooled tix_tcp flow: %v", err)
	}
	if _, ok := manager.tixTCPFlows[1]; !ok {
		t.Fatal("existing pooled tix_tcp flow was removed")
	}
	if _, ok := manager.tixTCPFlows[2]; !ok {
		t.Fatal("new pooled tix_tcp flow was not installed")
	}
}

func TestInstallTIXTCPRouteGSOFlowReplacesStaleEndpointAddressFlow(t *testing.T) {
	manager := NewManager()
	manager.spec = dataplane.AttachSpec{TIXTCPRouteGSOSync: true}
	manager.snapshot = dataplane.Snapshot{
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        "exp-b",
			Peer:      "ix-b",
			Transport: "tix_tcp",
			Address:   "198.18.0.2:17042",
			Enabled:   true,
			Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
		}},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		1: {
			ID:              1,
			Peer:            "ix-b",
			Endpoint:        "exp-b",
			RemoteAddress:   "198.18.0.2:17042",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}
	manager.tixTCPTelemetry = map[uint64]*dataplane.TransportPathTelemetry{
		1: {Protocol: "tix_tcp", FlowID: 1},
	}
	manager.kernelUDPTXDirectSequences = map[uint64]uint64{1: 7}
	manager.tixTCPOuterTXSequences = map[uint64]uint32{1: 8}
	manager.tixTCPOuterTXAcknowledgments = map[uint64]uint32{1: 9}

	if err := manager.InstallTIXTCPFlows(context.Background(), []dataplane.TIXTCPFlow{{
		ID:              2,
		Peer:            "ix-b",
		Endpoint:        "exp-b",
		LocalAddress:    "198.18.0.1:47484",
		RemoteAddress:   "198.18.0.2:17042",
		SourcePort:      47484,
		DestinationPort: 17042,
		CryptoPlacement: dataplane.CryptoPlacementUserspace,
	}}); err != nil {
		t.Fatalf("install replacement tix_tcp route-GSO flow: %v", err)
	}
	if _, ok := manager.tixTCPFlows[1]; ok {
		t.Fatal("stale route-GSO endpoint-address flow was not removed")
	}
	if _, ok := manager.tixTCPFlows[2]; !ok {
		t.Fatal("replacement route-GSO endpoint-address flow was not installed")
	}
	if _, ok := manager.tixTCPTelemetry[1]; ok {
		t.Fatal("stale route-GSO telemetry was not removed")
	}
	if _, ok := manager.kernelUDPTXDirectSequences[1]; ok {
		t.Fatal("stale route-GSO direct sequence was not removed")
	}
	if _, ok := manager.tixTCPOuterTXSequences[1]; ok {
		t.Fatal("stale route-GSO outer TX sequence was not removed")
	}
	if _, ok := manager.tixTCPOuterTXAcknowledgments[1]; ok {
		t.Fatal("stale route-GSO outer TX acknowledgment was not removed")
	}
}

func TestInstallTIXTCPRouteGSOFlowsKeepsEndpointAddressPoolMembers(t *testing.T) {
	manager := NewManager()
	manager.spec = dataplane.AttachSpec{TIXTCPRouteGSOSync: true}
	manager.snapshot = dataplane.Snapshot{
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        "exp-b",
			Peer:      "ix-b",
			Transport: "tix_tcp",
			Address:   "198.18.0.2:17042",
			Enabled:   true,
			Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
		}},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		1: {
			ID:              1,
			Peer:            "ix-b",
			Endpoint:        "exp-b",
			LocalAddress:    "198.18.0.1:56145",
			RemoteAddress:   "198.18.0.2:17042",
			SourcePort:      56145,
			DestinationPort: 17042,
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}
	manager.tixTCPTelemetry = map[uint64]*dataplane.TransportPathTelemetry{
		1: {Protocol: "tix_tcp", FlowID: 1},
	}
	manager.kernelUDPTXDirectSequences = map[uint64]uint64{1: 7}
	manager.tixTCPOuterTXSequences = map[uint64]uint32{1: 8}
	manager.tixTCPOuterTXAcknowledgments = map[uint64]uint32{1: 9}

	if err := manager.InstallTIXTCPFlows(context.Background(), []dataplane.TIXTCPFlow{{
		ID:              2,
		Peer:            "ix-b",
		Endpoint:        "exp-b",
		LocalAddress:    "198.18.0.1:47484",
		RemoteAddress:   "198.18.0.2:17042",
		SourcePort:      47484,
		DestinationPort: 17042,
		CryptoPlacement: dataplane.CryptoPlacementUserspace,
	}}); err != nil {
		t.Fatalf("install pooled tix_tcp route-GSO flow: %v", err)
	}
	for _, flowID := range []uint64{1, 2} {
		if _, ok := manager.tixTCPFlows[flowID]; !ok {
			t.Fatalf("route-GSO endpoint-address pool flow %d was removed: %#v", flowID, manager.tixTCPFlows)
		}
	}
	if _, ok := manager.tixTCPTelemetry[1]; !ok {
		t.Fatal("retained route-GSO pool flow telemetry was removed")
	}
	if _, ok := manager.kernelUDPTXDirectSequences[1]; !ok {
		t.Fatal("retained route-GSO pool flow direct sequence was removed")
	}
	if _, ok := manager.tixTCPOuterTXSequences[1]; !ok {
		t.Fatal("retained route-GSO pool flow outer TX sequence was removed")
	}
	if _, ok := manager.tixTCPOuterTXAcknowledgments[1]; !ok {
		t.Fatal("retained route-GSO pool flow outer TX acknowledgment was removed")
	}
}

func TestInstallKernelUDPFlowsKeepsDuplicatePathFlowIDs(t *testing.T) {
	manager := NewManager()
	fastPath := testTIXTCPFastPathWithQueues(1)
	fastPath.ready.Store(true)
	manager.tixTCPFastPath = fastPath
	manager.kernelUDPFlows = map[uint64]dataplane.KernelUDPFlow{
		1: {
			ID:              1,
			Peer:            "ix-b",
			Endpoint:        "udp-b",
			LocalAddress:    "198.18.0.1:41001",
			RemoteAddress:   "198.18.0.2:17042",
			SourcePort:      41001,
			DestinationPort: 17042,
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
	}
	manager.kernelUDPTelemetry = map[uint64]*dataplane.TransportPathTelemetry{
		1: {Protocol: "kernel_udp", FlowID: 1},
	}
	manager.kernelUDPTXDirectSequences = map[uint64]uint64{1: 7}
	manager.kernelUDPTXTemplates = map[uint64]kernelUDPTXTemplate{1: {}}
	manager.kernelUDPCryptoFragments = map[kernelUDPCryptoFragmentKey]*kernelUDPCryptoFragmentAssembly{
		{flowID: 1, sequence: 9}: {},
	}
	manager.kernelCryptoFlowMapEntries = map[kernelCryptoFlowKey]struct{}{
		kernelCryptoFlowKeyFor(kernelCryptoNamespaceKernelUDP, 1, kernelCryptoDirectionSend): {},
		kernelCryptoFlowKeyFor(kernelCryptoNamespaceKernelUDP, 1, kernelCryptoDirectionRecv): {},
	}
	manager.kernelCryptoCtxSlots = map[kernelCryptoFlowKey]uint32{
		kernelCryptoFlowKeyFor(kernelCryptoNamespaceKernelUDP, 1, kernelCryptoDirectionSend): 1,
		kernelCryptoFlowKeyFor(kernelCryptoNamespaceKernelUDP, 1, kernelCryptoDirectionRecv): 2,
	}

	if err := manager.InstallKernelUDPFlows(context.Background(), []dataplane.KernelUDPFlow{{
		ID:              2,
		Peer:            "ix-b",
		Endpoint:        "udp-b",
		LocalAddress:    "198.18.0.1:41001",
		RemoteAddress:   "198.18.0.2:17042",
		SourcePort:      41001,
		DestinationPort: 17042,
		CryptoPlacement: dataplane.CryptoPlacementUserspace,
	}}); err != nil {
		t.Fatalf("install duplicate kernel_udp flow: %v", err)
	}
	if _, ok := manager.kernelUDPFlows[1]; !ok {
		t.Fatal("old duplicate-path kernel_udp flow was removed")
	}
	if _, ok := manager.kernelUDPFlows[2]; !ok {
		t.Fatal("new kernel_udp flow was not installed")
	}
	if _, ok := manager.kernelUDPTelemetry[1]; !ok {
		t.Fatal("old kernel_udp telemetry was removed")
	}
	if _, ok := manager.kernelUDPTXDirectSequences[1]; !ok {
		t.Fatal("old kernel_udp direct sequence was removed")
	}
	if _, ok := manager.kernelUDPTXTemplates[1]; !ok {
		t.Fatal("old kernel_udp TX template was removed")
	}
	if got := len(manager.kernelUDPCryptoFragments); got != 1 {
		t.Fatalf("kernel_udp crypto fragments = %d, want 1", got)
	}
	if got := len(manager.kernelCryptoFlowMapEntries); got != 2 {
		t.Fatalf("kernel crypto flow entries = %d, want 2", got)
	}
	if got := len(manager.kernelCryptoCtxSlots); got != 2 {
		t.Fatalf("kernel crypto ctx slots = %d, want 2", got)
	}
}

func TestInstallKernelUDPFlowsKeepsSameEndpointPoolMembers(t *testing.T) {
	manager := NewManager()
	fastPath := testTIXTCPFastPathWithQueues(1)
	fastPath.ready.Store(true)
	manager.tixTCPFastPath = fastPath
	manager.kernelUDPFlows = map[uint64]dataplane.KernelUDPFlow{
		1: {
			ID:              1,
			Peer:            "ix-b",
			Endpoint:        "udp-b",
			LocalAddress:    "198.18.0.1:41001",
			RemoteAddress:   "198.18.0.2:17042",
			SourcePort:      41001,
			DestinationPort: 17042,
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}

	if err := manager.InstallKernelUDPFlows(context.Background(), []dataplane.KernelUDPFlow{{
		ID:              2,
		Peer:            "ix-b",
		Endpoint:        "udp-b",
		LocalAddress:    "198.18.0.1:41002",
		RemoteAddress:   "198.18.0.2:17042",
		SourcePort:      41002,
		DestinationPort: 17042,
		CryptoPlacement: dataplane.CryptoPlacementUserspace,
	}}); err != nil {
		t.Fatalf("install pooled kernel_udp flow: %v", err)
	}
	if _, ok := manager.kernelUDPFlows[1]; !ok {
		t.Fatal("existing pooled kernel_udp flow was removed")
	}
	if _, ok := manager.kernelUDPFlows[2]; !ok {
		t.Fatal("new pooled kernel_udp flow was not installed")
	}
}

func TestSetTIXTCPFlowPeerReplacesDuplicatePath(t *testing.T) {
	manager := NewManager()
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		1: {
			ID:              1,
			Peer:            "ix-b",
			Endpoint:        "exp-b",
			LocalAddress:    "198.18.0.1:41001",
			RemoteAddress:   "198.18.0.2:17042",
			SourcePort:      41001,
			DestinationPort: 17042,
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
		2: {
			ID:              2,
			LocalAddress:    "198.18.0.1:41001",
			RemoteAddress:   "198.18.0.2:17042",
			SourcePort:      41001,
			DestinationPort: 17042,
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}

	if err := manager.SetTIXTCPFlowPeer(context.Background(), 2, "ix-b", "exp-b"); err != nil {
		t.Fatalf("set tix_tcp flow peer: %v", err)
	}
	if _, ok := manager.tixTCPFlows[1]; ok {
		t.Fatal("old duplicate tix_tcp flow was not removed after annotation")
	}
	flow, ok := manager.tixTCPFlows[2]
	if !ok {
		t.Fatal("annotated tix_tcp flow was removed")
	}
	if flow.Peer != "ix-b" || flow.Endpoint != "exp-b" {
		t.Fatalf("annotated flow identity = peer %q endpoint %q", flow.Peer, flow.Endpoint)
	}
	if !flow.ExpiresAt.IsZero() {
		t.Fatalf("annotated tix_tcp flow expires_at = %s, want persistent zero value", flow.ExpiresAt)
	}
}

func TestSetTIXTCPFlowPeerFillsRemoteAddressFromEndpoint(t *testing.T) {
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("exp-b"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Address:   "198.51.100.2:17042",
				Enabled:   true,
			},
		},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		7: {
			ID:              7,
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}

	if err := manager.SetTIXTCPFlowPeer(context.Background(), 7, "ix-b", "exp-b"); err != nil {
		t.Fatalf("set tix_tcp flow peer: %v", err)
	}
	flow := manager.tixTCPFlows[7]
	if flow.RemoteAddress != "198.51.100.2:17042" {
		t.Fatalf("remote address = %q, want endpoint address", flow.RemoteAddress)
	}
	if flow.DestinationPort != 0 || flow.SourcePort != 0 || flow.LocalAddress != "" {
		t.Fatalf("flow tuple was prepared too early: %+v", flow)
	}
}

func TestSetTIXTCPFlowPeerKeepsLearnedRemoteAddress(t *testing.T) {
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("exp-b"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Address:   "198.51.100.2:17042",
				Enabled:   true,
			},
		},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		7: {
			ID:              7,
			RemoteAddress:   "198.51.100.2:48865",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}

	if err := manager.SetTIXTCPFlowPeer(context.Background(), 7, "ix-b", "exp-b"); err != nil {
		t.Fatalf("set tix_tcp flow peer: %v", err)
	}
	if got := manager.tixTCPFlows[7].RemoteAddress; got != "198.51.100.2:48865" {
		t.Fatalf("remote address = %q, want learned tuple preserved", got)
	}
}

func TestSetTIXTCPFlowPeerDoesNotFillLocalListenerFlowRemoteAddress(t *testing.T) {
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Peers: []dataplane.PeerMetadata{{ID: core.IXID("ix-b"), Trusted: true}},
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-a-tixt"),
				Peer:      core.IXID("ix-a"),
				Transport: "tix_tcp",
				Listen:    "192.0.2.1:17041",
				Enabled:   true,
			},
			{
				ID:        core.EndpointID("ix-b-tixt"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Address:   "198.51.100.2:17042",
				Enabled:   true,
			},
		},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		7: {
			ID:              7,
			LocalAddress:    "192.0.2.1:17041",
			SourcePort:      17041,
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}

	if err := manager.SetTIXTCPFlowPeer(context.Background(), 7, "ix-b", "ix-b-tixt"); err != nil {
		t.Fatalf("set tix_tcp flow peer: %v", err)
	}
	flow := manager.tixTCPFlows[7]
	if flow.RemoteAddress != "" {
		t.Fatalf("remote address = %q, want no endpoint fill for local listener flow", flow.RemoteAddress)
	}
	if flow.Peer != "ix-b" || flow.Endpoint != "ix-b-tixt" {
		t.Fatalf("flow identity = %s/%s, want annotated peer endpoint", flow.Peer, flow.Endpoint)
	}
}

func TestSetKernelUDPFlowPeerKeepsDuplicatePathFlowIDs(t *testing.T) {
	manager := NewManager()
	manager.kernelUDPFlows = map[uint64]dataplane.KernelUDPFlow{
		1: {
			ID:              1,
			Peer:            "ix-b",
			Endpoint:        "udp-b",
			LocalAddress:    "198.18.0.1:41001",
			RemoteAddress:   "198.18.0.2:17042",
			SourcePort:      41001,
			DestinationPort: 17042,
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
		2: {
			ID:              2,
			LocalAddress:    "198.18.0.1:41001",
			RemoteAddress:   "198.18.0.2:17042",
			SourcePort:      41001,
			DestinationPort: 17042,
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}

	if err := manager.SetKernelUDPFlowPeer(context.Background(), 2, "ix-b", "udp-b"); err != nil {
		t.Fatalf("set kernel_udp flow peer: %v", err)
	}
	if _, ok := manager.kernelUDPFlows[1]; !ok {
		t.Fatal("old duplicate-path kernel_udp flow was removed after annotation")
	}
	flow, ok := manager.kernelUDPFlows[2]
	if !ok {
		t.Fatal("annotated kernel_udp flow was removed")
	}
	if flow.Peer != "ix-b" || flow.Endpoint != "udp-b" {
		t.Fatalf("annotated flow identity = peer %q endpoint %q", flow.Peer, flow.Endpoint)
	}
	if !flow.ExpiresAt.IsZero() {
		t.Fatalf("annotated kernel_udp flow expires_at = %s, want persistent zero value", flow.ExpiresAt)
	}
}

func TestSetKernelUDPFlowPeerNoopDoesNotResyncTXDirect(t *testing.T) {
	manager := NewManager()
	manager.kernelUDPFlows = map[uint64]dataplane.KernelUDPFlow{
		7: {
			ID:              7,
			Peer:            "ix-b",
			Endpoint:        "udp-b",
			LocalAddress:    "198.18.0.1:41001",
			RemoteAddress:   "198.18.0.2:17042",
			SourcePort:      41001,
			DestinationPort: 17042,
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}

	if err := manager.SetKernelUDPFlowPeer(context.Background(), 7, "ix-b", "udp-b"); err != nil {
		t.Fatalf("noop set kernel_udp flow peer: %v", err)
	}
	if got := manager.kernelUDPTXDirectSync.Attempts; got != 0 {
		t.Fatalf("TX direct sync attempts = %d, want 0 for unchanged identity", got)
	}
}

func TestKernelUDPTXSecureDirectPrefersInboundReverseFlowRole(t *testing.T) {
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Routes: []routing.Route{{
			Prefix:  "10.216.0.0/24",
			NextHop: "ix-b",
			Kind:    routing.RouteUnicast,
		}},
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        "udp-b",
			Peer:      "ix-b",
			Transport: "udp",
			Address:   "198.18.0.2:17041",
			Enabled:   true,
			Security:  dataplane.EndpointSecurityMetadata{Encryption: "secure"},
		}},
	}
	manager.kernelUDPFlows = map[uint64]dataplane.KernelUDPFlow{
		1: {
			ID:              1,
			Peer:            "ix-b",
			Endpoint:        "udp-b",
			Role:            dataplane.KernelUDPFlowRoleOutbound,
			LocalAddress:    "198.18.0.1:41001",
			RemoteAddress:   "198.18.0.2:17041",
			SourcePort:      41001,
			DestinationPort: 17041,
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
		2: {
			ID:              2,
			Peer:            "ix-b",
			Endpoint:        "udp-b",
			Role:            dataplane.KernelUDPFlowRoleInboundReverse,
			LocalAddress:    "198.18.0.1:41002",
			RemoteAddress:   "198.18.0.2:17041",
			SourcePort:      41002,
			DestinationPort: 17041,
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(manager.snapshot.Routes[0], false, true, kernelUDPTXRouteMaxFlows)
	if got := len(flows); got != 1 {
		t.Fatalf("secure direct route flows = %d, want 1", got)
	}
	if flows[0].id != 2 {
		t.Fatalf("secure direct selected flow %d, want inbound reverse flow 2", flows[0].id)
	}
}

func TestSetTIXTCPFlowPeerNoopDoesNotResyncTXDirect(t *testing.T) {
	manager := NewManager()
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		7: {
			ID:              7,
			Peer:            "ix-b",
			Endpoint:        "exp-b",
			LocalAddress:    "198.18.0.1:41001",
			RemoteAddress:   "198.18.0.2:17042",
			SourcePort:      41001,
			DestinationPort: 17042,
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}

	if err := manager.SetTIXTCPFlowPeer(context.Background(), 7, "ix-b", "exp-b"); err != nil {
		t.Fatalf("noop set tix_tcp flow peer: %v", err)
	}
	if got := manager.kernelUDPTXDirectSync.Attempts; got != 0 {
		t.Fatalf("TX direct sync attempts = %d, want 0 for unchanged identity", got)
	}
}

func TestShouldUpdateKernelUDPFlowCryptoPlacementIgnoresNoop(t *testing.T) {
	if shouldUpdateKernelUDPFlowCryptoPlacement(dataplane.CryptoPlacementUserspace, dataplane.CryptoPlacementUserspace) {
		t.Fatal("userspace -> userspace should not update")
	}
	if shouldUpdateKernelUDPFlowCryptoPlacement(dataplane.CryptoPlacementKernel, dataplane.CryptoPlacementKernel) {
		t.Fatal("kernel -> kernel should not update")
	}
	if shouldUpdateKernelUDPFlowCryptoPlacement(dataplane.CryptoPlacementKernel, dataplane.CryptoPlacementUserspace) {
		t.Fatal("kernel -> userspace should not downgrade")
	}
	if !shouldUpdateKernelUDPFlowCryptoPlacement(dataplane.CryptoPlacementUserspace, dataplane.CryptoPlacementKernel) {
		t.Fatal("userspace -> kernel should update")
	}
}

func TestKernelTransportStatusReportsUDPFastPath(t *testing.T) {
	manager := NewManager()
	manager.attached = true
	manager.tixTCPFastPath = testTIXTCPFastPathWithQueues(2)
	manager.tixTCPFastPath.provider = "af_xdp"
	manager.tixTCPFastPath.ready.Store(true)

	status, err := manager.KernelTransportStatus(context.Background())
	if err != nil {
		t.Fatalf("kernel transport status: %v", err)
	}
	if !status.Available {
		t.Fatalf("kernel transport available = false, want true")
	}
	var found bool
	for _, protocol := range status.Protocols {
		if protocol.Protocol != "udp" {
			continue
		}
		found = true
		if !protocol.Available {
			t.Fatalf("udp protocol available = false, want true: %+v", protocol)
		}
		if protocol.Provider != "af_xdp" {
			t.Fatalf("udp provider = %q, want af_xdp", protocol.Provider)
		}
		if protocol.Placement != "hybrid" {
			t.Fatalf("udp placement = %q, want hybrid", protocol.Placement)
		}
	}
	if !found {
		t.Fatalf("kernel transport status did not include udp protocol: %+v", status.Protocols)
	}
}

func TestKernelUDPStatusReportsFullPlaintextKernelDatapathProvider(t *testing.T) {
	manager := NewManager()
	manager.attached = true
	manager.spec = dataplane.AttachSpec{KernelDatapathFullPlaintext: true}
	manager.tixTCPFastPath = testTIXTCPFastPathWithQueues(1)
	manager.tixTCPFastPath.provider = "af_xdp"
	manager.tixTCPFastPath.ready.Store(true)

	status, err := manager.KernelUDPStatus(context.Background())
	if err != nil {
		t.Fatalf("kernel udp status: %v", err)
	}
	if !status.Available || !status.Reinject || !status.FastPath || !status.DirectOnly || !status.TCOnly {
		t.Fatalf("full plaintext status = %+v, want available direct kernel provider", status)
	}
	if status.Provider != "kernel_datapath_full_plaintext" {
		t.Fatalf("provider = %q, want kernel_datapath_full_plaintext", status.Provider)
	}
	protocol := kernelTransportProtocolUDP(status)
	if !protocol.Available || protocol.Placement != "kernel" || protocol.UserspaceFallback {
		t.Fatalf("full plaintext protocol = %+v, want kernel placement without userspace fallback", protocol)
	}
}

func TestTIXTCPStatusReportsFullPlaintextKernelDatapathProvider(t *testing.T) {
	manager := NewManager()
	manager.attached = true
	manager.spec = dataplane.AttachSpec{KernelDatapathFullPlaintext: true}
	manager.tixTCPFastPath = testTIXTCPFastPathWithQueues(1)
	manager.tixTCPFastPath.provider = "af_xdp"
	manager.tixTCPFastPath.ready.Store(true)

	status, err := manager.TIXTCPStatus(context.Background())
	if err != nil {
		t.Fatalf("tix_tcp status: %v", err)
	}
	if !status.Available || !status.Reinject || !status.FastPath {
		t.Fatalf("full plaintext tix_tcp status = %+v, want available kernel provider", status)
	}
	if status.Provider != "kernel_datapath_full_plaintext" {
		t.Fatalf("provider = %q, want kernel_datapath_full_plaintext", status.Provider)
	}
	protocol := kernelTransportProtocolTIXTCP(status)
	if !protocol.Available || protocol.Placement != "kernel" || protocol.UserspaceFallback {
		t.Fatalf("full plaintext tix_tcp protocol = %+v, want kernel placement without userspace fallback", protocol)
	}
}

func TestTIXTCPStatusReportsRouteGSOTCOnlyProvider(t *testing.T) {
	manager := NewManager()
	manager.attached = true
	manager.spec = dataplane.AttachSpec{
		LANIface:                             "lan0",
		UnderlayIface:                        "eth0",
		KernelUDPTXDirectOnly:                true,
		KernelUDPTCOnlyProvider:              true,
		TIXTCPTXDirect:                       true,
		TIXTCPRouteGSOSync:                   true,
		TIXTCPRouteGSOAsync:                  true,
		TIXTCPRouteXmitWorker:                true,
		KernelDatapathSuppressLegacyRXWorker: true,
	}
	manager.statsMap = &cebpf.Map{}
	manager.kernelUDPTXRouteMap = &cebpf.Map{}
	manager.kernelUDPTXFlowMap = &cebpf.Map{}
	manager.kernelUDPRXDirectAttached = true
	manager.underlayIngressProg = &cebpf.Program{}
	manager.kernelTransportPortMap = &cebpf.Map{}
	manager.kernelUDPTXDirectPushRouteTCPHeaderKfunc = true
	manager.kernelUDPTXDirectRouteTCPGSOKfunc = true
	manager.kernelUDPTXDirectRouteTCPGSOAsyncKfunc = true
	manager.kernelUDPTXDirectRouteTCPXmitKfunc = true
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		9: {
			ID:              9,
			Peer:            "ix-b",
			Endpoint:        "remote",
			RemoteAddress:   "198.18.0.2:9443",
			SourcePort:      41000,
			DestinationPort: 9443,
		},
	}
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
		Endpoints: []dataplane.EndpointMetadata{
			{ID: "local", Peer: "ix-a", Transport: "tix_tcp", Listen: "198.18.0.1:9443", Enabled: true, Security: dataplane.EndpointSecurityMetadata{Encryption: "plaintext"}},
			{ID: "remote", Peer: "ix-b", Transport: "tix_tcp", Address: "198.18.0.2:9443", Enabled: true, Security: dataplane.EndpointSecurityMetadata{Encryption: "plaintext"}},
		},
		Peers: []dataplane.PeerMetadata{{ID: "ix-b", Trusted: true}},
	}

	status, err := manager.TIXTCPStatus(context.Background())
	if err != nil {
		t.Fatalf("tix_tcp status: %v", err)
	}
	if !status.Available || !status.Reinject || !status.FastPath {
		t.Fatalf("route-GSO TC-only status = %+v, want available fast-path reinject", status)
	}
	if status.Provider != "kernel_udp_tc_only" {
		t.Fatalf("provider = %q, want kernel_udp_tc_only", status.Provider)
	}
	if !status.UserspaceCrypto || status.KernelCrypto {
		t.Fatalf("route-GSO plaintext crypto status = userspace:%t kernel:%t, want userspace placeholder without kernel crypto", status.UserspaceCrypto, status.KernelCrypto)
	}
	protocol := kernelTransportProtocolTIXTCP(status)
	if !protocol.Available || protocol.Placement != "kernel" || protocol.UserspaceFallback {
		t.Fatalf("route-GSO TC-only protocol = %+v, want kernel placement without userspace fallback", protocol)
	}

	manager.spec.TIXTCPRouteGSOSync = false
	manager.spec.TIXTCPRouteGSOAsync = false
	status, err = manager.TIXTCPStatus(context.Background())
	if err != nil {
		t.Fatalf("tix_tcp status without route-GSO: %v", err)
	}
	if status.Available || status.Reinject || status.Provider == "kernel_udp_tc_only" {
		t.Fatalf("tix_tcp status without route-GSO = %+v, want TC-only provider unavailable", status)
	}
}

func TestTIXTCPStatusRejectsRouteGSOTCOnlyProviderWithoutRequestedKfuncs(t *testing.T) {
	tests := []struct {
		name string
		miss func(*Manager)
		want string
	}{
		{
			name: "push_route_tcp_header",
			miss: func(manager *Manager) {
				manager.kernelUDPTXDirectPushRouteTCPHeaderKfunc = false
			},
			want: "push_route_tcp_header",
		},
		{
			name: "route_tcp_gso",
			miss: func(manager *Manager) {
				manager.kernelUDPTXDirectRouteTCPGSOKfunc = false
			},
			want: "route_tcp_gso",
		},
		{
			name: "route_tcp_gso_async",
			miss: func(manager *Manager) {
				manager.kernelUDPTXDirectRouteTCPGSOAsyncKfunc = false
			},
			want: "route_tcp_gso_async",
		},
		{
			name: "route_tcp_xmit",
			miss: func(manager *Manager) {
				manager.kernelUDPTXDirectRouteTCPXmitKfunc = false
			},
			want: "route_tcp_xmit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := newRouteGSOTCOnlyTIXTCPManagerForTest()
			tt.miss(manager)

			status, err := manager.TIXTCPStatus(context.Background())
			if err != nil {
				t.Fatalf("tix_tcp status: %v", err)
			}
			if status.Available || status.Reinject || status.FastPath || status.Provider == "kernel_udp_tc_only" {
				t.Fatalf("status with missing %s = %+v, want route-GSO TC-only unavailable", tt.want, status)
			}
			if !strings.Contains(status.FastPathFallback, tt.want) {
				t.Fatalf("fast path fallback = %q, want missing kfunc %q", status.FastPathFallback, tt.want)
			}
		})
	}
}

func TestTIXTCPStatusRouteGSOUnavailableIncludesKfuncFallbackWarning(t *testing.T) {
	manager := newRouteGSOTCOnlyTIXTCPManagerForTest()
	manager.kernelUDPTXDirectRouteTCPGSOKfunc = false
	manager.kernelUDPTXDirectRouteTCPGSOAsyncKfunc = false
	manager.kernelUDPTXDirectKfuncFallbackWarning = "tix_tcp TC TX direct route TCP GSO kfunc disabled after verifier/load rejection: load ingress BPF program: fixing up kfuncs: finding kfunc in kernel: no BTF found"

	status, err := manager.TIXTCPStatus(context.Background())
	if err != nil {
		t.Fatalf("tix_tcp status: %v", err)
	}
	if status.Available || status.Reinject || status.FastPath || status.Provider == "kernel_udp_tc_only" {
		t.Fatalf("status with fallback-disabled route-GSO = %+v, want unavailable", status)
	}
	for _, want := range []string{"route_tcp_gso", "route_tcp_gso_async", "no BTF found"} {
		if !strings.Contains(status.FastPathFallback, want) {
			t.Fatalf("fast path fallback = %q, want %q", status.FastPathFallback, want)
		}
	}
}

func newRouteGSOTCOnlyTIXTCPManagerForTest() *Manager {
	manager := NewManager()
	manager.attached = true
	manager.spec = dataplane.AttachSpec{
		LANIface:                             "lan0",
		UnderlayIface:                        "eth0",
		KernelUDPTXDirectOnly:                true,
		KernelUDPTCOnlyProvider:              true,
		TIXTCPTXDirect:                       true,
		TIXTCPRouteGSOSync:                   true,
		TIXTCPRouteGSOAsync:                  true,
		TIXTCPRouteXmitWorker:                true,
		KernelDatapathSuppressLegacyRXWorker: true,
	}
	manager.statsMap = &cebpf.Map{}
	manager.kernelUDPTXRouteMap = &cebpf.Map{}
	manager.kernelUDPTXFlowMap = &cebpf.Map{}
	manager.kernelUDPRXDirectAttached = true
	manager.underlayIngressProg = &cebpf.Program{}
	manager.kernelTransportPortMap = &cebpf.Map{}
	manager.kernelUDPTXDirectPushRouteTCPHeaderKfunc = true
	manager.kernelUDPTXDirectRouteTCPGSOKfunc = true
	manager.kernelUDPTXDirectRouteTCPGSOAsyncKfunc = true
	manager.kernelUDPTXDirectRouteTCPXmitKfunc = true
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		42: {
			ID:              42,
			Peer:            "ix-b",
			Endpoint:        "remote",
			RemoteAddress:   "198.18.0.2:9443",
			SourcePort:      41000,
			DestinationPort: 9443,
		},
	}
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
		Endpoints: []dataplane.EndpointMetadata{
			{ID: "local", Peer: "ix-a", Transport: "tix_tcp", Listen: "198.18.0.1:9443", Enabled: true, Security: dataplane.EndpointSecurityMetadata{Encryption: "plaintext"}},
			{ID: "remote", Peer: "ix-b", Transport: "tix_tcp", Address: "198.18.0.2:9443", Enabled: true, Security: dataplane.EndpointSecurityMetadata{Encryption: "plaintext"}},
		},
		Peers: []dataplane.PeerMetadata{{ID: "ix-b", Trusted: true}},
	}
	return manager
}

func TestSubscribeTIXTCPAllowsFullPlaintextKernelDatapathProvider(t *testing.T) {
	manager := NewManager()
	manager.attached = true
	manager.spec = dataplane.AttachSpec{KernelDatapathFullPlaintext: true}

	subscription, err := manager.SubscribeTIXTCP(context.Background(), 8)
	if err != nil {
		t.Fatalf("subscribe tix_tcp: %v", err)
	}
	if subscription == nil {
		t.Fatal("subscription is nil")
	}
	if err := subscription.Close(); err != nil {
		t.Fatalf("close subscription: %v", err)
	}
}

func TestSubscribeTIXTCPAllowsRouteGSOTCOnlyProvider(t *testing.T) {
	manager := newRouteGSOTCOnlyTIXTCPManagerForTest()

	subscription, err := manager.SubscribeTIXTCP(context.Background(), 8)
	if err != nil {
		t.Fatalf("subscribe tix_tcp: %v", err)
	}
	if subscription == nil {
		t.Fatal("subscription is nil")
	}
	if manager.tixTCPRawFD != -1 {
		t.Fatalf("raw TCP receiver fd = %d, want unopened for route-GSO TC-only provider", manager.tixTCPRawFD)
	}
	if err := subscription.Close(); err != nil {
		t.Fatalf("close subscription: %v", err)
	}
}

func TestSubscribeTIXTCPFlowAllowsFullPlaintextKernelDatapathProvider(t *testing.T) {
	manager := NewManager()
	manager.attached = true
	manager.spec = dataplane.AttachSpec{KernelDatapathFullPlaintext: true}

	subscription, err := manager.SubscribeTIXTCPFlow(context.Background(), 42, 8)
	if err != nil {
		t.Fatalf("subscribe tix_tcp flow: %v", err)
	}
	if subscription == nil {
		t.Fatal("subscription is nil")
	}
	if err := subscription.Close(); err != nil {
		t.Fatalf("close subscription: %v", err)
	}
}

func TestSubscribeTIXTCPFlowAllowsRouteGSOTCOnlyProvider(t *testing.T) {
	manager := newRouteGSOTCOnlyTIXTCPManagerForTest()

	subscription, err := manager.SubscribeTIXTCPFlow(context.Background(), 42, 8)
	if err != nil {
		t.Fatalf("subscribe tix_tcp flow: %v", err)
	}
	if subscription == nil {
		t.Fatal("subscription is nil")
	}
	if manager.tixTCPRawFD != -1 {
		t.Fatalf("raw TCP receiver fd = %d, want unopened for route-GSO TC-only provider", manager.tixTCPRawFD)
	}
	if err := subscription.Close(); err != nil {
		t.Fatalf("close subscription: %v", err)
	}
}

func TestSubmitTIXTCPFrameRejectsFullPlaintextKernelDatapathProvider(t *testing.T) {
	manager := NewManager()
	manager.attached = true
	manager.spec = dataplane.AttachSpec{KernelDatapathFullPlaintext: true}
	manager.tixTCPFlows[42] = dataplane.TIXTCPFlow{
		ID:       42,
		Peer:     core.IXID("ix-b"),
		Endpoint: core.EndpointID("exp-b"),
	}

	err := manager.SubmitTIXTCPFrame(context.Background(), dataplane.TIXTCPFrame{
		FlowID:    42,
		Direction: dataplane.TIXTCPOutbound,
		Sequence:  1,
		Payload:   []byte("data"),
	})
	if err == nil || !strings.Contains(err.Error(), "full plaintext kernel datapath owns data frames") {
		t.Fatalf("submit error = %v, want full plaintext kernel datapath ownership", err)
	}
}

func TestSubmitTIXTCPFrameRejectsRouteGSOTCOnlyProvider(t *testing.T) {
	manager := newRouteGSOTCOnlyTIXTCPManagerForTest()

	err := manager.SubmitTIXTCPFrame(context.Background(), dataplane.TIXTCPFrame{
		FlowID:    42,
		Direction: dataplane.TIXTCPOutbound,
		Sequence:  1,
		Payload:   []byte("data"),
	})
	if err == nil || !strings.Contains(err.Error(), "route-GSO TC-only kernel datapath owns data frames") {
		t.Fatalf("submit error = %v, want route-GSO TC-only kernel datapath ownership", err)
	}
}

func TestSubmitTIXTCPFramesRejectsFullPlaintextKernelDatapathProvider(t *testing.T) {
	manager := NewManager()
	manager.attached = true
	manager.spec = dataplane.AttachSpec{KernelDatapathFullPlaintext: true}
	manager.tixTCPFlows[42] = dataplane.TIXTCPFlow{
		ID:       42,
		Peer:     core.IXID("ix-b"),
		Endpoint: core.EndpointID("exp-b"),
	}

	err := manager.SubmitTIXTCPFrames(context.Background(), []dataplane.TIXTCPFrame{{
		FlowID:    42,
		Direction: dataplane.TIXTCPOutbound,
		Sequence:  1,
		Payload:   []byte("data"),
	}})
	if err == nil || !strings.Contains(err.Error(), "full plaintext kernel datapath owns data frames") {
		t.Fatalf("batch submit error = %v, want full plaintext kernel datapath ownership", err)
	}
}

func TestSubmitTIXTCPFramesRejectsRouteGSOTCOnlyProvider(t *testing.T) {
	manager := newRouteGSOTCOnlyTIXTCPManagerForTest()

	err := manager.SubmitTIXTCPFrames(context.Background(), []dataplane.TIXTCPFrame{{
		FlowID:    42,
		Direction: dataplane.TIXTCPOutbound,
		Sequence:  1,
		Payload:   []byte("data"),
	}})
	if err == nil || !strings.Contains(err.Error(), "route-GSO TC-only kernel datapath owns data frames") {
		t.Fatalf("batch submit error = %v, want route-GSO TC-only kernel datapath ownership", err)
	}
}

func TestKernelUDPStatusReportsKernelCryptoWhenDeviceFlowExists(t *testing.T) {
	manager := NewManager()
	manager.attached = true
	manager.tixTCPFastPath = testTIXTCPFastPathWithQueues(1)
	manager.tixTCPFastPath.provider = "af_xdp"
	manager.tixTCPFastPath.ready.Store(true)
	manager.kernelCryptoDevices = map[uint64]*kernelCryptoDevice{42: {}}

	status, err := manager.KernelUDPStatus(context.Background())
	if err != nil {
		t.Fatalf("kernel udp status: %v", err)
	}
	if !status.KernelCrypto {
		t.Fatalf("kernel crypto = false, reason=%q", status.KernelCryptoReason)
	}
	if status.PreferredCrypto != dataplane.CryptoPlacementKernel {
		t.Fatalf("preferred crypto = %q, want kernel", status.PreferredCrypto)
	}
	if len(status.SupportedCrypto) != 2 || status.SupportedCrypto[1] != dataplane.CryptoPlacementKernel {
		t.Fatalf("supported crypto = %#v, want userspace+kernel", status.SupportedCrypto)
	}
}

func TestKernelUDPStatusReportsRawFallbackKernelCryptoWhenDeviceFlowExists(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_RAW_FALLBACK", "1")
	manager := NewManager()
	manager.attached = true
	manager.kernelCryptoDevices = map[uint64]*kernelCryptoDevice{42: {}}

	status, err := manager.KernelUDPStatus(context.Background())
	if err != nil {
		t.Fatalf("kernel udp status: %v", err)
	}
	if status.Provider != "raw_udp_fallback" {
		t.Fatalf("provider = %q, want raw_udp_fallback", status.Provider)
	}
	if !status.KernelCrypto {
		t.Fatalf("kernel crypto = false, reason=%q", status.KernelCryptoReason)
	}
	protocol := kernelTransportProtocolUDP(status)
	if protocol.Placement != "kernel" {
		t.Fatalf("udp protocol placement = %q, want kernel: %+v", protocol.Placement, protocol)
	}
	if protocol.UserspaceFallback {
		t.Fatalf("udp protocol userspace_fallback = true, want false")
	}
}

func TestOpenReceivedKernelUDPFramesForwardsEncryptedPayloadWhenKernelCryptoUnavailable(t *testing.T) {
	manager := NewManager()
	payload := []byte{'T', 'I', 'X', 'D', 1, 1, 0, 0, 0, 0}
	frames := []receivedKernelUDPFrame{{
		frame: dataplane.KernelUDPFrame{
			FlowID:          42,
			Sequence:        7,
			Payload:         append([]byte(nil), payload...),
			Encrypted:       true,
			InnerIPv4:       true,
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
		encryptedKernelPayload: true,
	}}

	got, ok := manager.openReceivedKernelUDPFrames(frames)
	if !ok {
		t.Fatal("openReceivedKernelUDPFrames dropped encrypted frame without kernel crypto")
	}
	if len(got) != 1 {
		t.Fatalf("frames = %d, want 1", len(got))
	}
	frame := got[0].frame
	if !bytes.Equal(frame.Payload, payload) {
		t.Fatalf("payload = %x, want %x", frame.Payload, payload)
	}
	if frame.Encrypted || frame.InnerIPv4 || frame.CryptoPlacement != dataplane.CryptoPlacementUserspace {
		t.Fatalf("frame metadata = encrypted:%v inner:%v placement:%q, want userspace secure fallback", frame.Encrypted, frame.InnerIPv4, frame.CryptoPlacement)
	}
	if got[0].encryptedKernelPayload || got[0].encryptedKernelFragment {
		t.Fatalf("internal encrypted markers survived fallback: %+v", got[0])
	}
}

func TestKernelUDPKernelCryptoUnavailableReasonMentionsBothBackends(t *testing.T) {
	manager := NewManager()

	reason := manager.kernelUDPKernelCryptoUnavailableReasonLocked()
	if !strings.Contains(reason, "TC direct BPF crypto provider") {
		t.Fatalf("reason %q does not mention TC direct provider", reason)
	}
	if !strings.Contains(reason, "AEAD device") {
		t.Fatalf("reason %q does not mention AEAD device", reason)
	}
}

func TestKernelTransportStatusReportsTunnelCarrierContract(t *testing.T) {
	manager := NewManager()
	manager.attached = true

	status, err := manager.KernelTransportStatus(context.Background())
	if err != nil {
		t.Fatalf("kernel transport status: %v", err)
	}
	for _, name := range []string{"gre", "ipip", "vxlan"} {
		var found bool
		for _, protocol := range status.Protocols {
			if protocol.Protocol != name {
				continue
			}
			found = true
			if !protocol.Available {
				t.Fatalf("%s available = false, want true: %+v", name, protocol)
			}
			if protocol.UserspaceFallback {
				t.Fatalf("%s unexpectedly allows userspace fallback", name)
			}
			if protocol.Contract != "trustix-kernel-tunnel-carrier-v1" || protocol.Carrier == "" {
				t.Fatalf("%s carrier contract = carrier:%q contract:%q", name, protocol.Carrier, protocol.Contract)
			}
			if len(protocol.RequiredConfig) == 0 {
				t.Fatalf("%s required config is empty", name)
			}
		}
		if !found {
			t.Fatalf("kernel transport status did not include %s: %+v", name, status.Protocols)
		}
	}
}

func TestKernelTransportAllowedPortsUseLocalListenAndFlows(t *testing.T) {
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
		Peers: []dataplane.PeerMetadata{
			{ID: core.IXID("ix-b"), DomainID: core.DomainID("lab.local"), Trusted: true},
		},
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("local-exp"),
				Peer:      core.IXID("ix-a"),
				Transport: "tix_tcp",
				Listen:    "198.18.0.1:17041",
				Address:   "",
				Enabled:   true,
			},
			{
				ID:        core.EndpointID("local-udp"),
				Peer:      core.IXID("ix-a"),
				Transport: "udp",
				Listen:    "198.18.0.1:17001",
				Address:   "",
				Enabled:   true,
			},
			{
				ID:        core.EndpointID("remote-exp"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Address:   "198.18.0.2:27041",
				Enabled:   true,
			},
			{
				ID:        core.EndpointID("remote-udp"),
				Peer:      core.IXID("ix-b"),
				Transport: "udp",
				Address:   "198.18.0.2:27001",
				Enabled:   true,
			},
		},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		10: {SourcePort: 41000, LocalAddress: "198.18.0.1:41001"},
	}
	manager.kernelUDPFlows = map[uint64]dataplane.KernelUDPFlow{
		20: {SourcePort: 42000, LocalAddress: "198.18.0.1:42001"},
	}

	tixTCPPorts := manager.desiredTIXTCPPortsLocked()
	for _, port := range []uint16{17041, 41000, 41001} {
		if _, ok := tixTCPPorts[port]; !ok {
			t.Fatalf("tix_tcp desired ports missing %d: %#v", port, tixTCPPorts)
		}
	}
	for _, port := range []uint16{27041, 17001} {
		if _, ok := tixTCPPorts[port]; ok {
			t.Fatalf("tix_tcp desired ports unexpectedly include %d: %#v", port, tixTCPPorts)
		}
	}

	udpPorts := manager.desiredKernelUDPPortsLocked()
	for _, port := range []uint16{17001, 42000, 42001} {
		if _, ok := udpPorts[port]; !ok {
			t.Fatalf("kernel_udp desired ports missing %d: %#v", port, udpPorts)
		}
	}
	for _, port := range []uint16{27001, 17041} {
		if _, ok := udpPorts[port]; ok {
			t.Fatalf("kernel_udp desired ports unexpectedly include %d: %#v", port, udpPorts)
		}
	}
}

func TestTIXTCPAllowedPortHoldKeepsDeletedFlowPorts(t *testing.T) {
	oldHoldDown := tixTCPAllowedPortHoldDown
	tixTCPAllowedPortHoldDown = time.Minute
	t.Cleanup(func() { tixTCPAllowedPortHoldDown = oldHoldDown })

	manager := NewManager()
	manager.snapshot.PacketPolicy = dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel}
	flow := dataplane.TIXTCPFlow{
		SourcePort:      41000,
		DestinationPort: 27000,
		LocalAddress:    "198.18.0.1:41001",
		RemoteAddress:   "198.18.0.2:27002",
	}
	manager.tixTCPFlows[7] = flow

	now := time.Now().UTC()
	manager.holdTIXTCPAllowedPortsLocked(flow, now)
	delete(manager.tixTCPFlows, 7)

	ports := manager.desiredTIXTCPPortsLocked()
	for _, port := range []uint16{41000, 27000, 41001, 27002} {
		if _, ok := ports[port]; !ok {
			t.Fatalf("held tix_tcp desired ports missing %d: %#v", port, ports)
		}
		manager.tixTCPAllowedPortHoldUntil[port] = now.Add(-time.Second)
	}

	ports = manager.desiredTIXTCPPortsLocked()
	for _, port := range []uint16{41000, 27000, 41001, 27002} {
		if _, ok := ports[port]; ok {
			t.Fatalf("expired tix_tcp held port %d is still desired: %#v", port, ports)
		}
	}
	if len(manager.tixTCPAllowedPortHoldUntil) != 0 {
		t.Fatalf("expired tix_tcp held ports were not pruned: %#v", manager.tixTCPAllowedPortHoldUntil)
	}
}

func TestTIXTCPAllowedPortHoldKeepsOverwrittenFlowPorts(t *testing.T) {
	oldHoldDown := tixTCPAllowedPortHoldDown
	tixTCPAllowedPortHoldDown = time.Minute
	t.Cleanup(func() { tixTCPAllowedPortHoldDown = oldHoldDown })

	manager := NewManager()
	manager.snapshot.PacketPolicy = dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel}
	manager.tixTCPFlows[7] = dataplane.TIXTCPFlow{
		SourcePort:      41000,
		DestinationPort: 27000,
		LocalAddress:    "198.18.0.1:41001",
		RemoteAddress:   "198.18.0.2:27002",
	}

	manager.setTIXTCPFlowLocked(7, dataplane.TIXTCPFlow{
		SourcePort:      42000,
		DestinationPort: 28000,
		LocalAddress:    "198.18.0.1:42001",
		RemoteAddress:   "198.18.0.2:28002",
	}, time.Now().UTC())

	ports := manager.desiredTIXTCPPortsLocked()
	for _, port := range []uint16{41000, 27000, 41001, 27002, 42000, 28000, 42001, 28002} {
		if _, ok := ports[port]; !ok {
			t.Fatalf("overwritten tix_tcp desired ports missing %d: %#v", port, ports)
		}
	}
}

func TestTIXTCPAllowedPortHoldKeepsDuplicateDeletedFlowPorts(t *testing.T) {
	oldHoldDown := tixTCPAllowedPortHoldDown
	tixTCPAllowedPortHoldDown = time.Minute
	t.Cleanup(func() { tixTCPAllowedPortHoldDown = oldHoldDown })

	manager := NewManager()
	manager.snapshot.PacketPolicy = dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel}
	existing := dataplane.TIXTCPFlow{
		ID:              1,
		Peer:            core.IXID("ix-b"),
		Endpoint:        core.EndpointID("b-exp"),
		SourcePort:      41000,
		DestinationPort: 27000,
		LocalAddress:    "198.18.0.1:41001",
		RemoteAddress:   "198.18.0.2:27002",
	}
	manager.tixTCPFlows[1] = existing
	replacement := existing
	replacement.ID = 2

	manager.deleteDuplicateTIXTCPFlowsLocked(replacement)

	if _, ok := manager.tixTCPFlows[1]; ok {
		t.Fatalf("duplicate tix_tcp flow was retained: %#v", manager.tixTCPFlows)
	}
	ports := manager.desiredTIXTCPPortsLocked()
	for _, port := range []uint16{41000, 27000, 41001, 27002} {
		if _, ok := ports[port]; !ok {
			t.Fatalf("duplicate-deleted tix_tcp desired ports missing %d: %#v", port, ports)
		}
	}
}

func TestTIXTCPAllowedPortHoldKeepsPrunedFlowPorts(t *testing.T) {
	oldHoldDown := tixTCPAllowedPortHoldDown
	tixTCPAllowedPortHoldDown = time.Minute
	t.Cleanup(func() { tixTCPAllowedPortHoldDown = oldHoldDown })

	manager := NewManager()
	manager.snapshot.PacketPolicy = dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel}
	now := time.Now().UTC()
	manager.tixTCPFlows[7] = dataplane.TIXTCPFlow{
		SourcePort:      41000,
		DestinationPort: 27000,
		LocalAddress:    "198.18.0.1:41001",
		RemoteAddress:   "198.18.0.2:27002",
		ExpiresAt:       now,
	}

	if !manager.pruneTIXTCPFlowsLocked(now) {
		t.Fatal("expired tix_tcp flow was not pruned")
	}
	if _, ok := manager.tixTCPFlows[7]; ok {
		t.Fatalf("expired tix_tcp flow remains: %#v", manager.tixTCPFlows)
	}
	ports := manager.desiredTIXTCPPortsLocked()
	for _, port := range []uint16{41000, 27000, 41001, 27002} {
		if _, ok := ports[port]; !ok {
			t.Fatalf("pruned tix_tcp desired ports missing %d: %#v", port, ports)
		}
	}
}

func TestKernelTransportAllowedPortsDisabledModeKeepsUserspaceUDPPortsOutOfXDP(t *testing.T) {
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeDisabled},
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("local-exp"),
				Peer:      core.IXID("ix-a"),
				Transport: "tix_tcp",
				Listen:    "198.18.0.1:17041",
				Enabled:   true,
			},
			{
				ID:        core.EndpointID("local-udp"),
				Peer:      core.IXID("ix-a"),
				Transport: "udp",
				Listen:    "198.18.0.1:17001",
				Enabled:   true,
			},
		},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		10: {SourcePort: 41000, LocalAddress: "198.18.0.1:41001"},
	}
	manager.kernelUDPFlows = map[uint64]dataplane.KernelUDPFlow{
		20: {SourcePort: 42000, LocalAddress: "198.18.0.1:42001"},
	}

	if ports := manager.desiredTIXTCPPortsLocked(); len(ports) != 0 {
		t.Fatalf("tix_tcp desired ports = %#v, want none while disabled", ports)
	}
	if ports := manager.desiredKernelUDPPortsLocked(); len(ports) != 0 {
		t.Fatalf("kernel_udp desired ports = %#v, want none while disabled", ports)
	}
}

func TestTIXTCPFastPathDisabledKeepsExperimentalPortsOutOfXDP(t *testing.T) {
	manager := NewManager()
	manager.spec = dataplane.AttachSpec{
		TIXTCPFastPathDisabled:       true,
		TIXTCPFastPathDisabledReason: "mixed tcp+tix_tcp",
	}
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
		Peers: []dataplane.PeerMetadata{
			{ID: core.IXID("ix-b"), DomainID: core.DomainID("lab.local"), Trusted: true},
		},
		Endpoints: []dataplane.EndpointMetadata{
			{ID: core.EndpointID("local-exp"), Peer: core.IXID("ix-a"), Transport: "tix_tcp", Listen: "198.18.0.1:17041", Enabled: true},
			{ID: core.EndpointID("local-udp"), Peer: core.IXID("ix-a"), Transport: "udp", Listen: "198.18.0.1:17001", Enabled: true},
		},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		10: {SourcePort: 41000, LocalAddress: "198.18.0.1:41001"},
	}
	manager.kernelUDPFlows = map[uint64]dataplane.KernelUDPFlow{
		20: {SourcePort: 42000, LocalAddress: "198.18.0.1:42001"},
	}

	if ports := manager.desiredTIXTCPPortsLocked(); len(ports) != 0 {
		t.Fatalf("tix_tcp desired ports = %#v, want none while fast path is disabled", ports)
	}
	udpPorts := manager.desiredKernelUDPPortsLocked()
	for _, port := range []uint16{17001, 42000, 42001} {
		if _, ok := udpPorts[port]; !ok {
			t.Fatalf("kernel_udp desired ports missing %d while tix_tcp is disabled: %#v", port, udpPorts)
		}
	}
}

func TestKernelTransportFastPathNotNeededForNativeTunnelEndpoints(t *testing.T) {
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
		Endpoints: []dataplane.EndpointMetadata{
			{ID: core.EndpointID("local-gre"), Peer: core.IXID("ix-a"), Transport: "gre", Listen: "198.18.0.1", Enabled: true},
			{ID: core.EndpointID("local-ipip"), Peer: core.IXID("ix-a"), Transport: "ipip", Listen: "198.18.0.1", Enabled: true},
			{ID: core.EndpointID("local-vxlan"), Peer: core.IXID("ix-a"), Transport: "vxlan", Listen: "198.18.0.1:4789", Enabled: true},
		},
	}

	if manager.snapshotNeedsKernelTransportFastPathLocked() {
		t.Fatal("native tunnel endpoints requested AF_XDP kernel transport fast path")
	}
}

func TestTIXTCPFastPathDisabledDoesNotRequestFastPathForTIXTCPOnly(t *testing.T) {
	manager := NewManager()
	manager.spec = dataplane.AttachSpec{
		TIXTCPFastPathDisabled:       true,
		TIXTCPFastPathDisabledReason: "mixed tcp+tix_tcp",
	}
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
		Peers: []dataplane.PeerMetadata{
			{ID: core.IXID("ix-b"), DomainID: core.DomainID("lab.local"), Trusted: true},
		},
		Endpoints: []dataplane.EndpointMetadata{
			{ID: core.EndpointID("local"), Peer: core.IXID("ix-a"), Transport: "tix_tcp", Listen: "198.18.0.1:17001", Enabled: true},
			{ID: core.EndpointID("remote"), Peer: core.IXID("ix-b"), Transport: "tix_tcp", Address: "198.18.0.2:27001", Enabled: true},
		},
	}
	manager.tixTCPFlows[7] = dataplane.TIXTCPFlow{ID: 7}

	if manager.snapshotNeedsKernelTransportFastPathLocked() {
		t.Fatal("disabled tix_tcp requested AF_XDP kernel transport fast path")
	}
	manager.snapshot.Endpoints = append(manager.snapshot.Endpoints, dataplane.EndpointMetadata{
		ID: core.EndpointID("local-udp"), Peer: core.IXID("ix-a"), Transport: "udp", Listen: "198.18.0.1:17002", Enabled: true,
	})
	if !manager.snapshotNeedsKernelTransportFastPathLocked() {
		t.Fatal("kernel_udp endpoint should still request AF_XDP kernel transport fast path")
	}
}

func TestKernelTransportFastPathNeededForLocalUDPAndTIXTCP(t *testing.T) {
	for _, transport := range []string{"udp", "kernel_udp", "tix_tcp"} {
		t.Run(transport, func(t *testing.T) {
			manager := NewManager()
			manager.snapshot = dataplane.Snapshot{
				PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
				Peers: []dataplane.PeerMetadata{
					{ID: core.IXID("ix-b"), DomainID: core.DomainID("lab.local"), Trusted: true},
				},
				Endpoints: []dataplane.EndpointMetadata{
					{ID: core.EndpointID("local"), Peer: core.IXID("ix-a"), Transport: transport, Listen: "198.18.0.1:17001", Enabled: true},
					{ID: core.EndpointID("remote"), Peer: core.IXID("ix-b"), Transport: transport, Address: "198.18.0.2:27001", Enabled: true},
				},
			}

			if !manager.snapshotNeedsKernelTransportFastPathLocked() {
				t.Fatal("local endpoint did not request AF_XDP kernel transport fast path")
			}
		})
	}
}

func TestSnapshotHasLocalTIXTCPEndpoint(t *testing.T) {
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
		Peers: []dataplane.PeerMetadata{
			{ID: core.IXID("ix-b"), DomainID: core.DomainID("lab.local"), Trusted: true},
		},
		Endpoints: []dataplane.EndpointMetadata{
			{ID: core.EndpointID("remote"), Peer: core.IXID("ix-b"), Transport: "tix_tcp", Address: "198.18.0.2:27001", Enabled: true},
		},
	}
	if manager.snapshotHasLocalTIXTCPEndpointLocked() {
		t.Fatal("remote-only tix_tcp endpoint should not enable raw fallback attach degradation")
	}
	manager.snapshot.Endpoints = append(manager.snapshot.Endpoints, dataplane.EndpointMetadata{
		ID: core.EndpointID("local"), Peer: core.IXID("ix-a"), Transport: "tix_tcp", Listen: "198.18.0.1:17001", Enabled: true,
	})
	if !manager.snapshotHasLocalTIXTCPEndpointLocked() {
		t.Fatal("local tix_tcp endpoint was not detected")
	}
}

func TestKernelTransportFastPathNeededForInstalledFlows(t *testing.T) {
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
	}
	if manager.snapshotNeedsKernelTransportFastPathLocked() {
		t.Fatal("empty snapshot requested AF_XDP kernel transport fast path")
	}

	manager.kernelUDPFlows[7] = dataplane.KernelUDPFlow{ID: 7}
	if !manager.snapshotNeedsKernelTransportFastPathLocked() {
		t.Fatal("kernel_udp flow did not request AF_XDP kernel transport fast path")
	}

	manager.snapshot.PacketPolicy.KernelTransportMode = dataplane.KernelTransportModeDisabled
	if manager.snapshotNeedsKernelTransportFastPathLocked() {
		t.Fatal("disabled kernel transport requested AF_XDP kernel transport fast path")
	}
}

func TestKernelTransportFastPathNotNeededForFullPlaintextKernelUDP(t *testing.T) {
	manager := NewManager()
	manager.spec = dataplane.AttachSpec{KernelDatapathFullPlaintext: true}
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
		Endpoints: []dataplane.EndpointMetadata{
			{ID: core.EndpointID("local-udp"), Peer: core.IXID("ix-a"), Transport: "udp", Listen: "198.18.0.1:17001", Enabled: true},
		},
	}
	manager.kernelUDPFlows[7] = dataplane.KernelUDPFlow{ID: 7}

	if manager.snapshotNeedsKernelTransportFastPathLocked() {
		t.Fatal("full plaintext kernel datapath UDP should not request AF_XDP")
	}
	if !kernelDatapathRXWorkerOwnsStackRXForSpec(manager.spec) {
		t.Fatal("full plaintext kernel datapath should own stack RX")
	}
}

func TestInstallKernelUDPFlowAllowsFullPlaintextKernelDatapathWithoutAFXDPPProvider(t *testing.T) {
	manager := NewManager()
	manager.attached = true
	manager.spec = dataplane.AttachSpec{KernelDatapathFullPlaintext: true}
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
	}

	err := manager.InstallKernelUDPFlows(context.Background(), []dataplane.KernelUDPFlow{{
		ID:            7,
		Peer:          core.IXID("ix-b"),
		Endpoint:      core.EndpointID("udp-b"),
		RemoteAddress: "198.18.0.2:17001",
	}})
	if err != nil {
		t.Fatalf("install full plaintext kernel_udp flow: %v", err)
	}
}

func TestKernelTransportFastPathNotNeededForTIXTCPWithFullPlaintextSpec(t *testing.T) {
	manager := NewManager()
	manager.spec = dataplane.AttachSpec{KernelDatapathFullPlaintext: true}
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
		Endpoints: []dataplane.EndpointMetadata{
			{ID: core.EndpointID("local-exp"), Peer: core.IXID("ix-a"), Transport: "tix_tcp", Listen: "198.18.0.1:17041", Enabled: true},
		},
	}

	if manager.snapshotNeedsKernelTransportFastPathLocked() {
		t.Fatal("full plaintext tix_tcp should not request AF_XDP")
	}
}

func TestTIXTCPLocalAddressUsesPerFlowSourcePortWithLocalEndpoint(t *testing.T) {
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
		Peers: []dataplane.PeerMetadata{
			{ID: core.IXID("ix-b"), DomainID: core.DomainID("lab.local"), Trusted: true},
		},
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("local-exp"),
				Peer:      core.IXID("ix-a"),
				Transport: "tix_tcp",
				Listen:    "198.18.0.1:17041",
				Enabled:   true,
			},
			{
				ID:        core.EndpointID("remote-exp"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Address:   "198.18.0.2:27041",
				Enabled:   true,
			},
		},
	}
	manager.tixTCPFlows[77] = dataplane.TIXTCPFlow{
		ID:            77,
		Peer:          core.IXID("ix-b"),
		Endpoint:      core.EndpointID("remote-exp"),
		RemoteAddress: "198.51.100.77:27041",
	}

	packet, _, err := manager.prepareTIXTCPPacketLocked(77, 9)
	if err != nil {
		t.Fatalf("prepare tix_tcp packet: %v", err)
	}
	if packet.SourcePort != 40077 {
		t.Fatalf("source port = %d, want derived per-flow port 40077", packet.SourcePort)
	}
	flow := manager.tixTCPFlows[77]
	if flow.SourcePort != 40077 || !strings.HasSuffix(flow.LocalAddress, ":40077") {
		t.Fatalf("flow local identity = %+v, want derived per-flow port", flow)
	}
}

func TestTIXTCPLocalAddressFallsBackToDerivedSourcePort(t *testing.T) {
	manager := NewManager()
	manager.tixTCPFlows[77] = dataplane.TIXTCPFlow{
		ID:            77,
		Peer:          core.IXID("ix-b"),
		RemoteAddress: "198.51.100.77:27041",
	}

	packet, _, err := manager.prepareTIXTCPPacketLocked(77, 9)
	if err != nil {
		t.Fatalf("prepare tix_tcp packet: %v", err)
	}
	if packet.SourcePort != 40077 {
		t.Fatalf("source port = %d, want derived port 40077", packet.SourcePort)
	}
}

func TestTIXTCPLocalAddressAcceptsSourceIPOnly(t *testing.T) {
	manager := NewManager()
	manager.tixTCPFlows[77] = dataplane.TIXTCPFlow{
		ID:            77,
		Peer:          core.IXID("ix-b"),
		LocalAddress:  "192.0.2.10",
		RemoteAddress: "198.51.100.77:27041",
	}

	packet, _, err := manager.prepareTIXTCPPacketLocked(77, 9)
	if err != nil {
		t.Fatalf("prepare tix_tcp packet: %v", err)
	}
	if packet.SourceIP.String() != "192.0.2.10" || packet.SourcePort != 40077 {
		t.Fatalf("source tuple = %s:%d, want 192.0.2.10:40077", packet.SourceIP, packet.SourcePort)
	}
	if got := manager.tixTCPFlows[77].LocalAddress; got != "192.0.2.10:40077" {
		t.Fatalf("normalized local address = %q, want 192.0.2.10:40077", got)
	}
}

func TestKernelUDPLocalAddressAcceptsSourceIPOnly(t *testing.T) {
	manager := NewManager()
	manager.kernelUDPFlows[77] = dataplane.KernelUDPFlow{
		ID:            77,
		Peer:          core.IXID("ix-b"),
		LocalAddress:  "192.0.2.20",
		RemoteAddress: "198.51.100.77:17041",
	}

	packet, _, flow, err := manager.prepareKernelUDPPacketForFlowLocked(77, manager.kernelUDPFlows[77])
	if err != nil {
		t.Fatalf("prepare kernel_udp packet: %v", err)
	}
	if packet.SourceIP.String() != "192.0.2.20" || packet.SourcePort != 40077 {
		t.Fatalf("source tuple = %s:%d, want 192.0.2.20:40077", packet.SourceIP, packet.SourcePort)
	}
	if flow.LocalAddress != "192.0.2.20:40077" {
		t.Fatalf("normalized local address = %q, want 192.0.2.20:40077", flow.LocalAddress)
	}
}

func TestTIXTCPPacketUsesObservedOuterAcknowledgment(t *testing.T) {
	manager := NewManager()
	manager.tixTCPFlows[77] = dataplane.TIXTCPFlow{
		ID:            77,
		LocalAddress:  "192.0.2.10:41000",
		RemoteAddress: "198.51.100.20:17041",
	}

	packet, _, err := manager.prepareTIXTCPPacketLocked(77, 1)
	if err != nil {
		t.Fatalf("prepare packet: %v", err)
	}
	if packet.Acknowledgment != 1 {
		t.Fatalf("initial ack = %d, want 1", packet.Acknowledgment)
	}

	manager.recordTIXTCPOuterAcknowledgmentLocked(77, tixtcp.TCPPacket{
		Sequence: 9000,
		Payload:  []byte("payload"),
	})
	manager.invalidateTIXTCPTXTemplateLocked(77)
	packet, _, err = manager.prepareTIXTCPPacketLocked(77, 2)
	if err != nil {
		t.Fatalf("prepare packet after ack: %v", err)
	}
	if got, want := packet.Acknowledgment, uint32(9000+len("payload")); got != want {
		t.Fatalf("ack = %d, want %d", got, want)
	}
}

func TestTIXTCPPayloadMaxClampsToUnderlayMTU(t *testing.T) {
	manager := NewManager()
	manager.tixTCPFastPath = testTIXTCPFastPathWithQueues(1)
	manager.tixTCPFastPath.ready.Store(true)
	manager.tixTCPFastPath.sockets[0].umemFrameSize = 4096
	manager.snapshot.PacketPolicy.MTU = 1500

	got, err := manager.TIXTCPPayloadMax(context.Background(), dataplane.CryptoPlacementKernel, true)
	if err != nil {
		t.Fatalf("payload max: %v", err)
	}
	want := 1500 - rejectIPv4HeaderLen - rejectTCPHeaderLen - tixtcp.HeaderLen - tixTCPKernelCryptoOverhead
	if got != want {
		t.Fatalf("kernel secure payload max = %d, want %d", got, want)
	}
	if got > 1500 {
		t.Fatalf("payload max %d was not clamped by underlay MTU", got)
	}
	stats := manager.tixTCPProviderStatsLocked()
	if stats["effective_payload_max_kernel"] != uint64(want) || stats["underlay_mtu_l3"] != 1500 {
		t.Fatalf("stats payload/mtu = %d/%d, want %d/1500", stats["effective_payload_max_kernel"], stats["underlay_mtu_l3"], want)
	}
}

func TestTIXTCPPayloadMaxUsesFastPathLinkMTU(t *testing.T) {
	manager := NewManager()
	manager.tixTCPFastPath = testTIXTCPFastPathWithQueues(1)
	manager.tixTCPFastPath.ready.Store(true)
	manager.tixTCPFastPath.sockets[0].umemFrameSize = 4096
	manager.tixTCPFastPath.sockets[0].linkMTU = 1500

	got, err := manager.TIXTCPPayloadMax(context.Background(), dataplane.CryptoPlacementUserspace, false)
	if err != nil {
		t.Fatalf("payload max: %v", err)
	}
	want := 1500 - rejectIPv4HeaderLen - rejectTCPHeaderLen - tixtcp.HeaderLen
	if got != want {
		t.Fatalf("userspace payload max = %d, want %d", got, want)
	}
	stats := manager.tixTCPProviderStatsLocked()
	if stats["effective_payload_max"] != uint64(want) || stats["underlay_mtu_l3"] != 1500 {
		t.Fatalf("stats payload/mtu = %d/%d, want %d/1500", stats["effective_payload_max"], stats["underlay_mtu_l3"], want)
	}
}

func TestTIXTCPPayloadMaxUsesRawFallbackMTU(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_RAW_FALLBACK", "1")
	manager := NewManager()
	manager.attached = true
	manager.snapshot.PacketPolicy.MTU = 1500

	got, err := manager.TIXTCPPayloadMax(context.Background(), dataplane.CryptoPlacementUserspace, true)
	if err != nil {
		t.Fatalf("payload max: %v", err)
	}
	want := 1500 - rejectIPv4HeaderLen - rejectTCPHeaderLen - tixtcp.HeaderLen - tixTCPKernelCryptoOverhead
	if got != want {
		t.Fatalf("raw fallback secure payload max = %d, want %d", got, want)
	}
	stats := manager.tixTCPProviderStatsLocked()
	if stats["effective_payload_max_secure"] != uint64(want) || stats["underlay_mtu_l3"] != 1500 {
		t.Fatalf("stats payload/mtu = %d/%d, want %d/1500", stats["effective_payload_max_secure"], stats["underlay_mtu_l3"], want)
	}
}

func TestKernelUDPPayloadMaxClampsAFXDPCryptoPayloadToUnderlayMTU(t *testing.T) {
	manager := NewManager()
	manager.tixTCPFastPath = testTIXTCPFastPathWithQueues(1)
	manager.tixTCPFastPath.ready.Store(true)
	manager.tixTCPFastPath.sockets[0].umemFrameSize = 4096
	manager.snapshot.PacketPolicy.MTU = 1500
	manager.kernelCryptoDevices = map[uint64]*kernelCryptoDevice{1: {}}

	got, err := manager.KernelUDPPayloadMax(context.Background(), dataplane.CryptoPlacementKernel, true)
	if err != nil {
		t.Fatalf("payload max: %v", err)
	}
	want := 1500 - rejectIPv4HeaderLen - 8 - kerneludp.HeaderLen - tixTCPKernelCryptoOverhead
	if got != want {
		t.Fatalf("kernel UDP crypto payload max = %d, want %d", got, want)
	}
}

func TestKernelUDPPayloadMaxAllowsSecureTCOnlyWarmup(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_RAW_FALLBACK", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_RAW_UDP_FALLBACK", "")

	manager := NewManager()
	manager.spec = dataplane.AttachSpec{
		LANIface:                    "lan0",
		UnderlayIface:               "eth0",
		KernelUDPTXDirectOnly:       true,
		KernelUDPTXDirectOnlyReason: "transport_policy.encryption=secure transport_policy.crypto_placement=kernel kernel_udp_tc_only_provider=enabled",
		KernelUDPTCOnlyProvider:     true,
	}
	manager.statsMap = &cebpf.Map{}
	manager.kernelUDPTXRouteMap = &cebpf.Map{}
	manager.kernelUDPTXFlowMap = &cebpf.Map{}
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{
			KernelTransportMode: dataplane.KernelTransportModeRequireKernel,
			MTU:                 1500,
		},
		Endpoints: []dataplane.EndpointMetadata{
			{ID: "local", Transport: "udp", Listen: "198.18.0.1:17041", Enabled: true, Security: dataplane.EndpointSecurityMetadata{Encryption: "secure"}},
		},
	}
	manager.kernelCryptoProvider = &kernelCryptoProviderObject{
		flowIndexMap:  &cebpf.Map{},
		contextSlots:  &cebpf.Map{},
		directSlotMap: &cebpf.Map{},
	}
	manager.kernelCryptoFlowMap = &cebpf.Map{}
	manager.kernelCryptoAEADCreateSuccesses = 1
	manager.kernelCryptoAEADRoundTripSuccesses = 1

	got, err := manager.KernelUDPPayloadMax(context.Background(), dataplane.CryptoPlacementKernel, true)
	if err != nil {
		t.Fatalf("payload max: %v", err)
	}
	want := 1500 - rejectIPv4HeaderLen - 8 - kerneludp.HeaderLen - tixTCPKernelCryptoOverhead
	if got != want {
		t.Fatalf("secure TC-only warmup payload max = %d, want %d", got, want)
	}
}

func TestKernelUDPPayloadMaxRejectsWithoutProvider(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_RAW_FALLBACK", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_RAW_UDP_FALLBACK", "")

	manager := NewManager()
	if _, err := manager.KernelUDPPayloadMax(context.Background(), dataplane.CryptoPlacementUserspace, false); err == nil {
		t.Fatal("payload max succeeded without AF_XDP, TC-only, or raw provider")
	}
}

func TestKernelUDPTXDirectFlowsForRouteMatchesPeerEndpointAndSecurePlacement(t *testing.T) {
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-b-udp"),
				Peer:      core.IXID("ix-b"),
				Transport: "udp",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "secure"},
			},
		},
	}
	manager.kernelUDPTXSecureDirectAttached = true
	manager.kernelUDPFlows = map[uint64]dataplane.KernelUDPFlow{
		0: {
			Peer: core.IXID("ix-b"),
		},
		7: {
			ID:              7,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-udp"),
			LocalAddress:    "192.0.2.1:41007",
			RemoteAddress:   "198.51.100.2:17001",
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
		8: {
			ID:              8,
			Peer:            core.IXID("ix-c"),
			Endpoint:        core.EndpointID("ix-c-udp"),
			LocalAddress:    "192.0.2.1:41008",
			RemoteAddress:   "198.51.100.3:17001",
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
		9: {
			ID:              9,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-udp"),
			LocalAddress:    "192.0.2.1:41009",
			RemoteAddress:   "198.51.100.4:17001",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.42.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-udp"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, true, kernelUDPTXRouteMaxFlows)
	if len(flows) != 1 {
		t.Fatalf("matched flows = %d, want 1: %+v", len(flows), flows)
	}
	if flows[0].id != 7 {
		t.Fatalf("matched flow id = %d, want 7", flows[0].id)
	}
	if flows[0].packet.SourcePort != 41007 || flows[0].packet.DestinationPort != 17001 {
		t.Fatalf("packet ports = %d/%d", flows[0].packet.SourcePort, flows[0].packet.DestinationPort)
	}
	stats := manager.kernelUDPTXDirectSync
	if stats.FlowsPeerMatches != 2 {
		t.Fatalf("peer matches = %d, want 2", stats.FlowsPeerMatches)
	}
	if stats.FlowsSecurityAllowed != 1 || stats.FlowsSecurityBlocked != 1 {
		t.Fatalf("security allowed/blocked = %d/%d, want 1/1", stats.FlowsSecurityAllowed, stats.FlowsSecurityBlocked)
	}
	if stats.PreparePacketErrors != 0 {
		t.Fatalf("prepare packet errors = %d, want 0", stats.PreparePacketErrors)
	}
}

func TestKernelUDPTXDirectRouteForSyncAllowsManagementVIPLocalRoute(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.1.1/32")
	route := routing.Route{
		Prefix:        core.Prefix(prefix.String()),
		Kind:          routing.RouteLocal,
		Source:        "management_vip",
		Owner:         core.IXID("ix-b"),
		NextHop:       core.IXID("ix-a"),
		LocalProtocol: ipProtocolTCP,
		LocalPort:     8787,
	}

	got, ok := kernelUDPTXDirectRouteForSync(route, prefix)
	if !ok {
		t.Fatal("management VIP local route was not accepted for TX direct sync")
	}
	if got.Kind != routing.RouteUnicast || got.NextHop != "ix-b" || got.Owner != "ix-b" || got.Source != "management_vip" {
		t.Fatalf("direct route = %#v, want unicast via owner ix-b preserving source/owner", got)
	}
}

func TestKernelUDPTXDirectManagementVIPLocalRouteSkipsSecureDirectFlows(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_TCP_CHECKSUM", "1")
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-b-udp"),
				Peer:      core.IXID("ix-b"),
				Transport: "udp",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "secure"},
			},
			{
				ID:        core.EndpointID("ix-b-tixt"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "secure"},
			},
		},
	}
	manager.kernelUDPTXSecureDirectAttached = true
	manager.kernelUDPFlows = map[uint64]dataplane.KernelUDPFlow{
		7: {
			ID:              7,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-udp"),
			LocalAddress:    "192.0.2.1:41007",
			RemoteAddress:   "198.51.100.2:17001",
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		8: {
			ID:              8,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:42008",
			RemoteAddress:   "198.51.100.3:18001",
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
	}
	route := routing.Route{
		Prefix:        core.Prefix("10.0.1.1/32"),
		Kind:          routing.RouteUnicast,
		Source:        "management_vip",
		Owner:         core.IXID("ix-b"),
		NextHop:       core.IXID("ix-b"),
		LocalProtocol: ipProtocolTCP,
		LocalPort:     8787,
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, true, kernelUDPTXRouteMaxFlows)
	if len(flows) != 0 {
		t.Fatalf("management VIP secure-direct flows = %+v, want none", flows)
	}
	stats := manager.kernelUDPTXDirectSync
	if stats.FlowsSecurityAllowed != 0 || stats.FlowsSecurityBlocked != 2 {
		t.Fatalf("security allowed/blocked = %d/%d, want 0/2", stats.FlowsSecurityAllowed, stats.FlowsSecurityBlocked)
	}
}

func TestKernelUDPTXDirectRouteForSyncRejectsNonManagementLocalRoutes(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.1.1/32")
	cases := []routing.Route{
		{Prefix: core.Prefix(prefix.String()), Kind: routing.RouteLocal, Source: "local_lan", Owner: "ix-b", LocalProtocol: ipProtocolTCP, LocalPort: 8787},
		{Prefix: core.Prefix(prefix.String()), Kind: routing.RouteLocal, Source: "management_vip", Owner: "ix-b", LocalProtocol: ipProtocolUDP, LocalPort: 8787},
		{Prefix: core.Prefix(prefix.String()), Kind: routing.RouteLocal, Source: "management_vip", Owner: "ix-b", LocalProtocol: ipProtocolTCP},
		{Prefix: core.Prefix(prefix.String()), Kind: routing.RouteBlackhole, Source: "management_vip", Owner: "ix-b", LocalProtocol: ipProtocolTCP, LocalPort: 8787},
	}
	for _, route := range cases {
		if got, ok := kernelUDPTXDirectRouteForSync(route, prefix); ok {
			t.Fatalf("route %#v unexpectedly accepted as %#v", route, got)
		}
	}
}

func TestKernelUDPTXDirectBypassRouteForSync(t *testing.T) {
	if !kernelUDPTXDirectBypassRouteForSync(routing.Route{Kind: routing.RouteLocal}) {
		t.Fatal("local route was not marked as TX direct bypass")
	}
	for _, kind := range []routing.RouteKind{"", routing.RouteUnicast, routing.RouteBlackhole, routing.RouteReject} {
		if kernelUDPTXDirectBypassRouteForSync(routing.Route{Kind: kind}) {
			t.Fatalf("route kind %q unexpectedly marked as TX direct bypass", kind)
		}
	}
}

func TestKernelUDPTXDirectFlowsForRouteRequiresExplicitEndpointFlow(t *testing.T) {
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("fallback-udp"),
				Peer:      core.IXID("ix-b"),
				Transport: "udp",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
		},
	}
	manager.kernelUDPFlows = map[uint64]dataplane.KernelUDPFlow{
		11: {
			ID:              11,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("fallback-udp"),
			LocalAddress:    "192.0.2.1:41011",
			RemoteAddress:   "198.51.100.11:17001",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.43.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("preferred-udp"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, false, kernelUDPTXRouteMaxFlows)
	if len(flows) != 0 {
		t.Fatalf("explicit endpoint matched fallback flows = %+v, want none", flows)
	}
}

func TestTIXTCPTXDirectFlowsRequirePlaintextAndSkipChecksum(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_TCP_CHECKSUM", "1")
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-b-tixt"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
			{
				ID:        core.EndpointID("ix-c-tixt"),
				Peer:      core.IXID("ix-c"),
				Transport: "tix_tcp",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "secure"},
			},
		},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		21: {
			ID:              21,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:42021",
			RemoteAddress:   "198.51.100.21:18001",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
		22: {
			ID:              22,
			Peer:            core.IXID("ix-c"),
			Endpoint:        core.EndpointID("ix-c-tixt"),
			LocalAddress:    "192.0.2.1:42022",
			RemoteAddress:   "198.51.100.22:18001",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
		23: {
			ID:              23,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:42023",
			RemoteAddress:   "198.51.100.23:18001",
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.44.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-tixt"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, false, kernelUDPTXRouteMaxFlows)
	if len(flows) != 1 {
		t.Fatalf("matched tix_tcp flows = %d, want 1: %+v", len(flows), flows)
	}
	if flows[0].id != 21 || !flows[0].tixTCP {
		t.Fatalf("matched flow = %+v, want tix_tcp flow 21", flows[0])
	}
	if flows[0].tixTCPPacket.SourcePort != 42021 || flows[0].tixTCPPacket.DestinationPort != 18001 {
		t.Fatalf("packet ports = %d/%d", flows[0].tixTCPPacket.SourcePort, flows[0].tixTCPPacket.DestinationPort)
	}
	stats := manager.kernelUDPTXDirectSync
	if stats.FlowsSecurityAllowed != 1 || stats.FlowsSecurityBlocked != 1 {
		t.Fatalf("security allowed/blocked = %d/%d, want 1/1", stats.FlowsSecurityAllowed, stats.FlowsSecurityBlocked)
	}
}

func TestTIXTCPTXDirectFlowsAllowSecureKernelPlacement(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_TCP_CHECKSUM", "1")
	manager := NewManager()
	manager.kernelUDPTXSecureDirectAttached = true
	manager.snapshot = dataplane.Snapshot{
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-b-tixt"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "secure"},
			},
		},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		31: {
			ID:              31,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:42031",
			RemoteAddress:   "198.51.100.31:18001",
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
		32: {
			ID:              32,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:42032",
			RemoteAddress:   "198.51.100.32:18001",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.45.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-tixt"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, true, kernelUDPTXRouteMaxFlows)
	if len(flows) != 1 {
		t.Fatalf("matched secure tix_tcp flows = %d, want 1: %+v", len(flows), flows)
	}
	if flows[0].id != 31 || !flows[0].tixTCP {
		t.Fatalf("matched flow = %+v, want tix_tcp flow 31", flows[0])
	}
	if flows[0].tixTCPPacket.SourcePort != 42031 || flows[0].tixTCPPacket.DestinationPort != 18001 {
		t.Fatalf("packet ports = %d/%d", flows[0].tixTCPPacket.SourcePort, flows[0].tixTCPPacket.DestinationPort)
	}
	stats := manager.kernelUDPTXDirectSync
	if stats.FlowsSecurityAllowed != 1 || stats.FlowsSecurityBlocked != 1 {
		t.Fatalf("security allowed/blocked = %d/%d, want 1/1", stats.FlowsSecurityAllowed, stats.FlowsSecurityBlocked)
	}
}

func TestTIXTCPTXSecureDirectKeepsStableFlowSet(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	manager := NewManager()
	manager.kernelUDPTXSecureDirectAttached = true
	manager.snapshot = dataplane.Snapshot{
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        core.EndpointID("ix-b-tixt"),
			Peer:      core.IXID("ix-b"),
			Transport: "tix_tcp",
			Enabled:   true,
			Security:  dataplane.EndpointSecurityMetadata{Encryption: "secure"},
		}},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		34: {
			ID:              34,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:42034",
			RemoteAddress:   "198.51.100.34:18001",
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
		33: {
			ID:              33,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:42033",
			RemoteAddress:   "198.51.100.33:18001",
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
		35: {
			ID:              35,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:42035",
			RemoteAddress:   "198.51.100.35:18001",
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.45.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-tixt"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, true, kernelUDPTXRouteMaxFlows)
	if len(flows) != 2 {
		t.Fatalf("secure direct flows = %d, want stable power-of-two set: %+v", len(flows), flows)
	}
	for i, wantID := range []uint64{33, 34} {
		if flows[i].id != wantID {
			t.Fatalf("secure direct flow[%d] = %d, want %d", i, flows[i].id, wantID)
		}
	}
}

func TestTIXTCPTXSecureDirectPrefersOutboundFlowOverListenerSource(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	manager := NewManager()
	manager.kernelUDPTXSecureDirectAttached = true
	manager.snapshot = dataplane.Snapshot{
		Peers: []dataplane.PeerMetadata{{ID: core.IXID("ix-b")}},
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-a-tixt"),
				Peer:      core.IXID("ix-a"),
				Transport: "tix_tcp",
				Listen:    "192.0.2.1:17041",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "secure"},
			},
			{
				ID:        core.EndpointID("ix-b-tixt"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "secure"},
			},
		},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		10: {
			ID:              10,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:17041",
			RemoteAddress:   "198.51.100.2:48865",
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
		20: {
			ID:              20,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:50158",
			RemoteAddress:   "198.51.100.2:17042",
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
		21: {
			ID:              21,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:50159",
			RemoteAddress:   "198.51.100.2:17042",
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.47.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-tixt"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, true, kernelUDPTXRouteMaxFlows)
	if len(flows) != 2 {
		t.Fatalf("secure direct flows = %d, want outbound flow set: %+v", len(flows), flows)
	}
	for i, wantID := range []uint64{20, 21} {
		if flows[i].id != wantID {
			t.Fatalf("secure direct flow[%d] = %d, want %d", i, flows[i].id, wantID)
		}
	}
	if flows[0].tixTCPPacket.SourcePort != 50158 || flows[0].tixTCPPacket.DestinationPort != 17042 {
		t.Fatalf("selected packet ports = %d/%d, want 50158/17042", flows[0].tixTCPPacket.SourcePort, flows[0].tixTCPPacket.DestinationPort)
	}
}

func TestKernelUDPTXSecureDirectRouteWithoutEndpointUsesPreferredTransportOnly(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	manager := NewManager()
	manager.kernelUDPTXSecureDirectAttached = true
	manager.snapshot = dataplane.Snapshot{
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-b-udp"),
				Peer:      core.IXID("ix-b"),
				Transport: "udp",
				Priority:  10,
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "secure"},
			},
			{
				ID:        core.EndpointID("ix-b-tixt"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Priority:  90,
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "secure"},
			},
		},
	}
	manager.kernelUDPFlows = map[uint64]dataplane.KernelUDPFlow{
		11: {
			ID:              11,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-udp"),
			LocalAddress:    "192.0.2.1:41011",
			RemoteAddress:   "198.51.100.11:17001",
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		21: {
			ID:              21,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:42021",
			RemoteAddress:   "198.51.100.21:18001",
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
		22: {
			ID:              22,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:42022",
			RemoteAddress:   "198.51.100.22:18001",
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
	}
	route := routing.Route{
		Prefix:  core.Prefix("10.50.0.0/16"),
		NextHop: core.IXID("ix-b"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, true, kernelUDPTXRouteMaxFlows)
	if len(flows) != 2 {
		t.Fatalf("secure direct route flows = %d, want preferred tix_tcp set only: %+v", len(flows), flows)
	}
	for i, wantID := range []uint64{21, 22} {
		if flows[i].id != wantID || !flows[i].tixTCP {
			t.Fatalf("flow[%d] = %+v, want tix_tcp flow %d", i, flows[i], wantID)
		}
	}
}

func TestKernelUDPTXSecureDirectTIXTCPUsesAttachSpecDirectFlag(t *testing.T) {
	manager := NewManager()
	manager.spec = dataplane.AttachSpec{
		TIXTCPTXDirect:                           true,
		KernelUDPTXSecureDirect:                  true,
		KernelUDPSecureDirectTrustInnerChecksums: true,
	}
	manager.kernelUDPTXSecureDirectAttached = true
	manager.snapshot = dataplane.Snapshot{
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        core.EndpointID("ix-b-tixt"),
			Peer:      core.IXID("ix-b"),
			Transport: "tix_tcp",
			Enabled:   true,
			Security:  dataplane.EndpointSecurityMetadata{Encryption: "secure"},
		}},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		21: {
			ID:              21,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:42021",
			RemoteAddress:   "198.51.100.21:18001",
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.50.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-tixt"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, true, kernelUDPTXRouteMaxFlows)
	if len(flows) != 1 {
		t.Fatalf("secure tix_tcp direct flows = %d, want one flow from attach spec: %+v", len(flows), flows)
	}
	if flows[0].id != 21 || !flows[0].tixTCP {
		t.Fatalf("secure tix_tcp flow = %+v, want tix_tcp flow 21", flows[0])
	}
}

func TestKernelUDPTXSecureDirectRouteWithoutEndpointFallsBackToSingleTransport(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	manager := NewManager()
	manager.kernelUDPTXSecureDirectAttached = true
	manager.snapshot = dataplane.Snapshot{
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-b-udp"),
				Peer:      core.IXID("ix-b"),
				Transport: "udp",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "secure"},
			},
			{
				ID:        core.EndpointID("ix-b-tixt"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "secure"},
			},
		},
	}
	manager.kernelUDPFlows = map[uint64]dataplane.KernelUDPFlow{
		11: {
			ID:              11,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-udp"),
			LocalAddress:    "192.0.2.1:41011",
			RemoteAddress:   "198.51.100.11:17001",
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		21: {
			ID:              21,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:42021",
			RemoteAddress:   "198.51.100.21:18001",
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
	}
	route := routing.Route{
		Prefix:  core.Prefix("10.51.0.0/16"),
		NextHop: core.IXID("ix-b"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, true, kernelUDPTXRouteMaxFlows)
	if len(flows) != 1 {
		t.Fatalf("secure direct route flows = %d, want one transport family: %+v", len(flows), flows)
	}
	if flows[0].tixTCP {
		t.Fatalf("fallback selected tix_tcp flow = %+v, want first sorted transport family kernel_udp", flows[0])
	}
}

func TestKernelUDPTXPlaintextDirectRouteWithoutEndpointUsesPreferredTransportOnly(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-b-udp"),
				Peer:      core.IXID("ix-b"),
				Transport: "udp",
				Priority:  10,
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
			{
				ID:        core.EndpointID("ix-b-tixt"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Priority:  90,
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
		},
	}
	manager.kernelUDPFlows = map[uint64]dataplane.KernelUDPFlow{
		11: {
			ID:              11,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-udp"),
			LocalAddress:    "192.0.2.1:41011",
			RemoteAddress:   "198.51.100.11:17001",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		21: {
			ID:              21,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:42021",
			RemoteAddress:   "198.51.100.21:18001",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}
	route := routing.Route{
		Prefix:  core.Prefix("10.52.0.0/16"),
		NextHop: core.IXID("ix-b"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, false, kernelUDPTXRouteMaxFlows)
	if len(flows) != 1 {
		t.Fatalf("plaintext direct route flows = %d, want preferred tix_tcp only: %+v", len(flows), flows)
	}
	if flows[0].id != 21 || !flows[0].tixTCP {
		t.Fatalf("selected flow = %+v, want tix_tcp flow 21", flows[0])
	}
}

func TestKernelUDPTXSecureDirectPrefersOutboundFlowOverListenerSource(t *testing.T) {
	manager := NewManager()
	manager.kernelUDPTXSecureDirectAttached = true
	manager.snapshot = dataplane.Snapshot{
		Peers: []dataplane.PeerMetadata{{ID: core.IXID("ix-b")}},
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-a-udp"),
				Peer:      core.IXID("ix-a"),
				Transport: "udp",
				Listen:    "192.0.2.1:37001",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "secure"},
			},
			{
				ID:        core.EndpointID("ix-b-udp"),
				Peer:      core.IXID("ix-b"),
				Transport: "udp",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "secure"},
			},
		},
	}
	manager.kernelUDPFlows = map[uint64]dataplane.KernelUDPFlow{
		10: {
			ID:              10,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-udp"),
			LocalAddress:    "192.0.2.1:37001",
			RemoteAddress:   "198.51.100.2:50960",
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
		20: {
			ID:              20,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-udp"),
			LocalAddress:    "192.0.2.1:47119",
			RemoteAddress:   "198.51.100.2:37001",
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
		21: {
			ID:              21,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-udp"),
			LocalAddress:    "192.0.2.1:47120",
			RemoteAddress:   "198.51.100.2:37001",
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.48.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-udp"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, true, kernelUDPTXRouteMaxFlows)
	if len(flows) != 2 {
		t.Fatalf("secure direct flows = %d, want outbound flow set: %+v", len(flows), flows)
	}
	for i, wantID := range []uint64{20, 21} {
		if flows[i].id != wantID {
			t.Fatalf("secure direct flow[%d] = %d, want %d", i, flows[i].id, wantID)
		}
	}
	if flows[0].packet.SourcePort != 47119 || flows[0].packet.DestinationPort != 37001 {
		t.Fatalf("selected packet ports = %d/%d, want 47119/37001", flows[0].packet.SourcePort, flows[0].packet.DestinationPort)
	}
}

func TestKernelUDPTXSecureDirectRewritesListenerFallbackToEndpointAddress(t *testing.T) {
	manager := NewManager()
	manager.kernelUDPTXSecureDirectAttached = true
	manager.snapshot = dataplane.Snapshot{
		Peers: []dataplane.PeerMetadata{{ID: core.IXID("ix-b")}},
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-a-udp"),
				Peer:      core.IXID("ix-a"),
				Transport: "udp",
				Listen:    "192.0.2.1:37001",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "secure"},
			},
			{
				ID:        core.EndpointID("ix-b-udp"),
				Peer:      core.IXID("ix-b"),
				Transport: "udp",
				Address:   "198.51.100.2:37001",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "secure"},
			},
		},
	}
	manager.kernelUDPFlows = map[uint64]dataplane.KernelUDPFlow{
		10: {
			ID:              10,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-udp"),
			LocalAddress:    "192.0.2.1:37001",
			RemoteAddress:   "198.51.100.2:50960",
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.49.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-udp"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, true, kernelUDPTXRouteMaxFlows)
	if len(flows) != 1 {
		t.Fatalf("secure direct flows = %d, want 1 listener fallback: %+v", len(flows), flows)
	}
	if flows[0].id != 10 {
		t.Fatalf("secure direct flow id = %d, want fallback flow 10", flows[0].id)
	}
	if flows[0].packet.SourcePort != 37001 || flows[0].packet.DestinationPort != 37001 {
		t.Fatalf("selected packet ports = %d/%d, want 37001/37001", flows[0].packet.SourcePort, flows[0].packet.DestinationPort)
	}
	if got := flows[0].packet.DestinationIP; got != netip.MustParseAddr("198.51.100.2") {
		t.Fatalf("selected destination IP = %s, want endpoint address", got)
	}
}

func TestTIXTCPTXSecureDirectRewritesListenerFallbackToEndpointAddress(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	manager := NewManager()
	manager.kernelUDPTXSecureDirectAttached = true
	manager.snapshot = dataplane.Snapshot{
		Peers: []dataplane.PeerMetadata{{ID: core.IXID("ix-b")}},
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-a-tixt"),
				Peer:      core.IXID("ix-a"),
				Transport: "tix_tcp",
				Listen:    "192.0.2.1:37001",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "secure"},
			},
			{
				ID:        core.EndpointID("ix-b-tixt"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Address:   "198.51.100.2:37002",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "secure"},
			},
		},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		10: {
			ID:              10,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:37001",
			RemoteAddress:   "198.51.100.2:50960",
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.50.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-tixt"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, true, kernelUDPTXRouteMaxFlows)
	if len(flows) != 1 {
		t.Fatalf("secure tix_tcp direct flows = %d, want 1 listener fallback: %+v", len(flows), flows)
	}
	if flows[0].id != 10 {
		t.Fatalf("secure tix_tcp direct flow id = %d, want fallback flow 10", flows[0].id)
	}
	if flows[0].tixTCPPacket.SourcePort != 37001 || flows[0].tixTCPPacket.DestinationPort != 37002 {
		t.Fatalf("selected packet ports = %d/%d, want 37001/37002", flows[0].tixTCPPacket.SourcePort, flows[0].tixTCPPacket.DestinationPort)
	}
	if got := flows[0].tixTCPPacket.DestinationIP; got != netip.MustParseAddr("198.51.100.2") {
		t.Fatalf("selected destination IP = %s, want endpoint address", got)
	}
}

func TestTIXTCPTXPlaintextDirectPrefersOutboundFlowOverListenerSource(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_TCP_CHECKSUM", "1")
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Peers: []dataplane.PeerMetadata{{ID: core.IXID("ix-b")}},
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-a-tixt"),
				Peer:      core.IXID("ix-a"),
				Transport: "tix_tcp",
				Listen:    "192.0.2.1:17041",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
			{
				ID:        core.EndpointID("ix-b-tixt"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
		},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		10: {
			ID:              10,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:17041",
			RemoteAddress:   "198.51.100.2:48865",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
		20: {
			ID:              20,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:50158",
			RemoteAddress:   "198.51.100.2:17042",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.47.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-tixt"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, false, kernelUDPTXRouteMaxFlows)
	if len(flows) != 1 {
		t.Fatalf("plaintext direct flows = %d, want 1 outbound flow: %+v", len(flows), flows)
	}
	if flows[0].id != 20 {
		t.Fatalf("plaintext direct flow id = %d, want outbound flow 20", flows[0].id)
	}
	if flows[0].tixTCPPacket.SourcePort != 50158 || flows[0].tixTCPPacket.DestinationPort != 17042 {
		t.Fatalf("selected packet ports = %d/%d, want 50158/17042", flows[0].tixTCPPacket.SourcePort, flows[0].tixTCPPacket.DestinationPort)
	}
}

func TestTIXTCPTXPlaintextDirectCanPreferListenerSource(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_TCP_CHECKSUM", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PREFER_LISTENER_SOURCE", "1")
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Peers: []dataplane.PeerMetadata{{ID: core.IXID("ix-b")}},
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-a-tixt"),
				Peer:      core.IXID("ix-a"),
				Transport: "tix_tcp",
				Listen:    "192.0.2.1:17041",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
			{
				ID:        core.EndpointID("ix-b-tixt"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
		},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		10: {
			ID:              10,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:17041",
			RemoteAddress:   "198.51.100.2:48865",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
		20: {
			ID:              20,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:50158",
			RemoteAddress:   "198.51.100.2:17042",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.47.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-tixt"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, false, kernelUDPTXRouteMaxFlows)
	if len(flows) != 1 {
		t.Fatalf("plaintext direct flows = %d, want 1 listener flow: %+v", len(flows), flows)
	}
	if flows[0].id != 10 {
		t.Fatalf("plaintext direct flow id = %d, want listener flow 10", flows[0].id)
	}
	if flows[0].tixTCPPacket.SourcePort != 17041 || flows[0].tixTCPPacket.DestinationPort != 48865 {
		t.Fatalf("selected packet ports = %d/%d, want listener/reverse tuple", flows[0].tixTCPPacket.SourcePort, flows[0].tixTCPPacket.DestinationPort)
	}
}

func TestTIXTCPTXPlaintextDirectFallsBackToListenerSource(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_TCP_CHECKSUM", "1")
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Peers: []dataplane.PeerMetadata{{ID: core.IXID("ix-b")}},
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-a-tixt"),
				Peer:      core.IXID("ix-a"),
				Transport: "tix_tcp",
				Listen:    "192.0.2.1:17041",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
			{
				ID:        core.EndpointID("ix-b-tixt"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
		},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		10: {
			ID:              10,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:17041",
			RemoteAddress:   "198.51.100.2:48865",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.47.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-tixt"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, false, kernelUDPTXRouteMaxFlows)
	if len(flows) != 1 {
		t.Fatalf("plaintext direct fallback flows = %d, want 1 listener flow: %+v", len(flows), flows)
	}
	if flows[0].id != 10 {
		t.Fatalf("plaintext direct fallback flow id = %d, want listener flow 10", flows[0].id)
	}
}

func TestTIXTCPTXPlaintextDirectUsesEstablishedListenerReverseFlowForEndpointAddressRoute(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_TCP_CHECKSUM", "1")
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Peers: []dataplane.PeerMetadata{{ID: core.IXID("ix-b")}},
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-a-tixt"),
				Peer:      core.IXID("ix-a"),
				Transport: "tix_tcp",
				Listen:    "10.203.3.204:13000",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
			{
				ID:        core.EndpointID("ix-b-tixt"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Address:   "10.203.3.205:13001",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
		},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		10: {
			ID:              10,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "10.203.3.204:13000",
			RemoteAddress:   "10.203.3.205:58299",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.205.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-tixt"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, false, kernelUDPTXRouteMaxFlows)
	if len(flows) != 1 {
		t.Fatalf("plaintext direct fallback flows = %d, want established listener reverse flow: %+v", len(flows), flows)
	}
	if flows[0].id != 10 {
		t.Fatalf("plaintext direct fallback flow id = %d, want listener flow 10", flows[0].id)
	}
	if flows[0].tixTCPPacket.SourcePort != 13000 || flows[0].tixTCPPacket.DestinationPort != 58299 {
		t.Fatalf("selected packet ports = %d/%d, want established reverse tuple 13000/58299", flows[0].tixTCPPacket.SourcePort, flows[0].tixTCPPacket.DestinationPort)
	}
}

func TestTIXTCPTXPlaintextDirectSkipsFakeListenerEndpointTuple(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_TCP_CHECKSUM", "1")
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Peers: []dataplane.PeerMetadata{{ID: core.IXID("ix-b")}},
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-a-tixt"),
				Peer:      core.IXID("ix-a"),
				Transport: "tix_tcp",
				Listen:    "10.203.3.204:13000",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
			{
				ID:        core.EndpointID("ix-b-tixt"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Address:   "10.203.3.205:13001",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
		},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		10: {
			ID:              10,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "10.203.3.204:13000",
			RemoteAddress:   "10.203.3.205:13001",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.205.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-tixt"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, false, kernelUDPTXRouteMaxFlows)
	if len(flows) != 0 {
		t.Fatalf("plaintext direct fallback flows = %d, want fake listener-sourced endpoint tuple skipped: %+v", len(flows), flows)
	}
}

func TestTIXTCPTXPlaintextDirectPrefersEndpointAddressOutboundFlow(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_TCP_CHECKSUM", "1")
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Peers: []dataplane.PeerMetadata{{ID: core.IXID("ix-b")}},
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-a-tixt"),
				Peer:      core.IXID("ix-a"),
				Transport: "tix_tcp",
				Listen:    "10.203.3.204:13000",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
			{
				ID:        core.EndpointID("ix-b-tixt"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Address:   "10.203.3.205:13001",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
		},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		10: {
			ID:              10,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "10.203.3.204:13000",
			RemoteAddress:   "10.203.3.205:58299",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
		20: {
			ID:              20,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "10.203.3.204:44000",
			RemoteAddress:   "10.203.3.205:13001",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.205.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-tixt"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, false, kernelUDPTXRouteMaxFlows)
	if len(flows) != 1 {
		t.Fatalf("plaintext direct flows = %d, want endpoint-address outbound flow: %+v", len(flows), flows)
	}
	if flows[0].id != 20 {
		t.Fatalf("plaintext direct flow id = %d, want outbound flow 20", flows[0].id)
	}
	if flows[0].tixTCPPacket.SourcePort != 44000 || flows[0].tixTCPPacket.DestinationPort != 13001 {
		t.Fatalf("selected packet ports = %d/%d, want 44000/13001", flows[0].tixTCPPacket.SourcePort, flows[0].tixTCPPacket.DestinationPort)
	}
}

func TestTIXTCPRouteGSOUsesEndpointAddressFlowPool(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_TCP_CHECKSUM", "1")
	manager := NewManager()
	manager.spec = dataplane.AttachSpec{
		TIXTCPTXDirect:     true,
		TIXTCPRouteGSOSync: true,
	}
	manager.snapshot = dataplane.Snapshot{
		Peers: []dataplane.PeerMetadata{{ID: core.IXID("ix-b")}},
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-a-tixt"),
				Peer:      core.IXID("ix-a"),
				Transport: "tix_tcp",
				Listen:    "10.203.3.204:13000",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
			{
				ID:        core.EndpointID("ix-b-tixt"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Address:   "10.203.3.205:13001",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
		},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		10: {
			ID:              10,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "10.203.3.204:13000",
			RemoteAddress:   "10.203.3.205:58299",
			SourcePort:      13000,
			DestinationPort: 58299,
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}
	for i := 0; i < 10; i++ {
		flowID := uint64(100 + i)
		sourcePort := uint16(44000 + i)
		manager.tixTCPFlows[flowID] = dataplane.TIXTCPFlow{
			ID:              flowID,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    fmt.Sprintf("10.203.3.204:%d", sourcePort),
			RemoteAddress:   "10.203.3.205:13001",
			SourcePort:      sourcePort,
			DestinationPort: 13001,
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		}
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.205.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-tixt"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, false, kernelUDPTXRouteMaxFlows)
	if len(flows) != kernelUDPTXRouteMaxFlows {
		t.Fatalf("route-GSO endpoint-address flow pool = %d, want %d: %+v", len(flows), kernelUDPTXRouteMaxFlows, flows)
	}
	for i, flow := range flows {
		wantID := uint64(100 + i)
		if flow.id != wantID {
			t.Fatalf("route-GSO flow[%d] = %d, want %d", i, flow.id, wantID)
		}
		if flow.tixTCPPacket.SourcePort == 13000 || flow.tixTCPPacket.DestinationPort != 13001 {
			t.Fatalf("route-GSO flow[%d] ports = %d/%d, want outbound source and destination 13001", i, flow.tixTCPPacket.SourcePort, flow.tixTCPPacket.DestinationPort)
		}
	}
}

func TestTIXTCPTXPlaintextDirectPrefersFreshEndpointAddressOutboundFlow(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_TCP_CHECKSUM", "1")
	now := time.Date(2026, 7, 1, 9, 55, 0, 0, time.UTC)
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Peers: []dataplane.PeerMetadata{{ID: core.IXID("ix-b")}},
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-a-tixt"),
				Peer:      core.IXID("ix-a"),
				Transport: "tix_tcp",
				Listen:    "10.203.3.204:13000",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
			{
				ID:        core.EndpointID("ix-b-tixt"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Address:   "10.203.3.205:13001",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
		},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		10: {
			ID:              10,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "10.203.3.204:56145",
			RemoteAddress:   "10.203.3.205:13001",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
			CreatedAt:       now.Add(-10 * time.Minute),
			LastSeen:        now.Add(-10 * time.Minute),
		},
		20: {
			ID:              20,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "10.203.3.204:47484",
			RemoteAddress:   "10.203.3.205:13001",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
			CreatedAt:       now,
			LastSeen:        now,
		},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.205.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-tixt"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, false, kernelUDPTXRouteMaxFlows)
	if len(flows) != 1 {
		t.Fatalf("plaintext direct flows = %d, want fresh endpoint-address outbound flow: %+v", len(flows), flows)
	}
	if flows[0].id != 20 {
		t.Fatalf("plaintext direct flow id = %d, want fresh flow 20", flows[0].id)
	}
	if flows[0].tixTCPPacket.SourcePort != 47484 || flows[0].tixTCPPacket.DestinationPort != 13001 {
		t.Fatalf("selected packet ports = %d/%d, want 47484/13001", flows[0].tixTCPPacket.SourcePort, flows[0].tixTCPPacket.DestinationPort)
	}
}

func TestTIXTCPTXPlaintextDirectMultiFlowKeepsSingleRouteFlowByDefault(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_TCP_CHECKSUM", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PLAINTEXT_MULTI_FLOW", "1")
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        core.EndpointID("ix-b-tixt"),
			Peer:      core.IXID("ix-b"),
			Transport: "tix_tcp",
			Enabled:   true,
			Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
		}},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		34: {
			ID:              34,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:42034",
			RemoteAddress:   "198.51.100.34:18001",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
		33: {
			ID:              33,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:42033",
			RemoteAddress:   "198.51.100.33:18001",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
		35: {
			ID:              35,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:42035",
			RemoteAddress:   "198.51.100.35:18001",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.47.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-tixt"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, false, kernelUDPTXRouteMaxFlows)
	if len(flows) != 1 {
		t.Fatalf("plaintext direct default route flows = %d, want one safe flow: %+v", len(flows), flows)
	}
	if flows[0].id != 33 {
		t.Fatalf("plaintext direct default route flow id = %d, want stable flow 33", flows[0].id)
	}
}

func TestTIXTCPTXPlaintextDirectMultiFlowKeepsStableFlowSet(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_TCP_CHECKSUM", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PLAINTEXT_MULTI_FLOW", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PLAINTEXT_ROUTE_MULTI_FLOW_UNSAFE", "1")
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        core.EndpointID("ix-b-tixt"),
			Peer:      core.IXID("ix-b"),
			Transport: "tix_tcp",
			Enabled:   true,
			Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
		}},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		34: {
			ID:              34,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:42034",
			RemoteAddress:   "198.51.100.34:18001",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
		33: {
			ID:              33,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:42033",
			RemoteAddress:   "198.51.100.33:18001",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
		35: {
			ID:              35,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:42035",
			RemoteAddress:   "198.51.100.35:18001",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.47.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-tixt"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, false, kernelUDPTXRouteMaxFlows)
	if len(flows) != 2 {
		t.Fatalf("plaintext direct multi-flow = %d, want stable power-of-two set: %+v", len(flows), flows)
	}
	for i, wantID := range []uint64{33, 34} {
		if flows[i].id != wantID {
			t.Fatalf("plaintext direct multi-flow[%d] = %d, want %d", i, flows[i].id, wantID)
		}
	}
}

func TestTIXTCPTXPlaintextDirectMultiFlowPrefersOutboundFlowOverListenerSource(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_TCP_CHECKSUM", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PLAINTEXT_MULTI_FLOW", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PLAINTEXT_ROUTE_MULTI_FLOW_UNSAFE", "1")
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Peers: []dataplane.PeerMetadata{{ID: core.IXID("ix-b")}},
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-a-tixt"),
				Peer:      core.IXID("ix-a"),
				Transport: "tix_tcp",
				Listen:    "192.0.2.1:17041",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
			{
				ID:        core.EndpointID("ix-b-tixt"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
		},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		10: {
			ID:              10,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:17041",
			RemoteAddress:   "198.51.100.2:48865",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
		20: {
			ID:              20,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:50158",
			RemoteAddress:   "198.51.100.2:17042",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
		21: {
			ID:              21,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:50159",
			RemoteAddress:   "198.51.100.2:17042",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.47.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-tixt"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, false, kernelUDPTXRouteMaxFlows)
	if len(flows) != 2 {
		t.Fatalf("plaintext direct multi-flow = %d, want outbound flow set: %+v", len(flows), flows)
	}
	for i, wantID := range []uint64{20, 21} {
		if flows[i].id != wantID {
			t.Fatalf("plaintext direct multi-flow[%d] = %d, want %d", i, flows[i].id, wantID)
		}
	}
	if flows[0].tixTCPPacket.SourcePort != 50158 || flows[0].tixTCPPacket.DestinationPort != 17042 {
		t.Fatalf("selected packet ports = %d/%d, want 50158/17042", flows[0].tixTCPPacket.SourcePort, flows[0].tixTCPPacket.DestinationPort)
	}
}

func TestTIXTCPTXPlaintextDirectMultiFlowCanPreferListenerSource(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_TCP_CHECKSUM", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PLAINTEXT_MULTI_FLOW", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PLAINTEXT_ROUTE_MULTI_FLOW_UNSAFE", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PREFER_LISTENER_SOURCE", "1")
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Peers: []dataplane.PeerMetadata{{ID: core.IXID("ix-b")}},
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-a-tixt"),
				Peer:      core.IXID("ix-a"),
				Transport: "tix_tcp",
				Listen:    "192.0.2.1:17041",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
			{
				ID:        core.EndpointID("ix-b-tixt"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
		},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		10: {
			ID:              10,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:17041",
			RemoteAddress:   "198.51.100.2:48865",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
		11: {
			ID:              11,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:17041",
			RemoteAddress:   "198.51.100.2:48866",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
		20: {
			ID:              20,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:50158",
			RemoteAddress:   "198.51.100.2:17042",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.47.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-tixt"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, false, kernelUDPTXRouteMaxFlows)
	if len(flows) != 2 {
		t.Fatalf("plaintext direct multi-flow = %d, want listener flow set: %+v", len(flows), flows)
	}
	for i, wantID := range []uint64{10, 11} {
		if flows[i].id != wantID {
			t.Fatalf("plaintext direct multi-flow[%d] = %d, want %d", i, flows[i].id, wantID)
		}
		if flows[i].tixTCPPacket.SourcePort != 17041 {
			t.Fatalf("plaintext direct multi-flow[%d] source port = %d, want listener port", i, flows[i].tixTCPPacket.SourcePort)
		}
	}
}

func TestTIXTCPTXPlaintextDirectSkipsControlOnlyFlowWithoutRemoteTuple(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_TCP_CHECKSUM", "1")
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Peers: []dataplane.PeerMetadata{{ID: core.IXID("ix-b")}},
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-a-tixt"),
				Peer:      core.IXID("ix-a"),
				Transport: "tix_tcp",
				Listen:    "192.0.2.1:17041",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
			{
				ID:        core.EndpointID("ix-b-tixt"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
		},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		10: {
			ID:              10,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
		20: {
			ID:              20,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			RemoteAddress:   "198.51.100.2:17042",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.47.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-tixt"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, false, kernelUDPTXRouteMaxFlows)
	if len(flows) != 1 {
		t.Fatalf("plaintext direct flows = %d, want one outbound flow: %+v", len(flows), flows)
	}
	if flows[0].id != 20 {
		t.Fatalf("plaintext direct flow id = %d, want outbound flow 20", flows[0].id)
	}
	if flows[0].tixTCPPacket.SourcePort != tixTCPDerivedSourcePort(20) || flows[0].tixTCPPacket.DestinationPort != 17042 {
		t.Fatalf("selected packet ports = %d/%d, want derived/%d", flows[0].tixTCPPacket.SourcePort, flows[0].tixTCPPacket.DestinationPort, 17042)
	}
}

func TestTIXTCPStatusIncludesActiveFlowSnapshot(t *testing.T) {
	manager := NewManager()
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		20: {
			ID:              20,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("b-tix-tcp"),
			LocalAddress:    "192.0.2.1:50158",
			RemoteAddress:   "198.51.100.2:7142",
			SourcePort:      50158,
			DestinationPort: 7142,
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
		10: {
			ID:              10,
			Peer:            core.IXID("ix-a"),
			Endpoint:        core.EndpointID("a-tix-tcp"),
			LocalAddress:    "192.0.2.1:7141",
			RemoteAddress:   "198.51.100.1:51585",
			SourcePort:      7141,
			DestinationPort: 51585,
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}

	status, err := manager.TIXTCPStatus(context.Background())
	if err != nil {
		t.Fatalf("tix_tcp status: %v", err)
	}
	if status.ActiveFlows != 2 {
		t.Fatalf("active flows = %d, want 2", status.ActiveFlows)
	}
	if len(status.Flows) != 2 {
		t.Fatalf("status flows = %d, want 2", len(status.Flows))
	}
	if status.Flows[0].ID != 10 || status.Flows[1].ID != 20 {
		t.Fatalf("status flow order = %d,%d; want 10,20", status.Flows[0].ID, status.Flows[1].ID)
	}
	if status.Flows[1].RemoteAddress != "198.51.100.2:7142" || status.Flows[1].SourcePort != 50158 {
		t.Fatalf("status outbound flow = %+v", status.Flows[1])
	}
}

func TestTIXTCPStatusReportsFastPathDisabled(t *testing.T) {
	manager := NewManager()
	manager.attached = true
	manager.spec = dataplane.AttachSpec{
		TIXTCPFastPathDisabled:       true,
		TIXTCPFastPathDisabledReason: "mixed tcp+tix_tcp",
	}

	status, err := manager.TIXTCPStatus(context.Background())
	if err != nil {
		t.Fatalf("tix_tcp status: %v", err)
	}
	if status.Available || status.FastPath || status.Reinject {
		t.Fatalf("disabled tix_tcp status = %+v, want unavailable/no fast path", status)
	}
	if !strings.Contains(status.FastPathFallback, "mixed tcp+tix_tcp") {
		t.Fatalf("fast path fallback = %q, want disabled reason", status.FastPathFallback)
	}
	found := false
	for _, note := range status.Notes {
		if strings.Contains(note, "mixed tcp+tix_tcp") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("status notes missing disabled reason: %#v", status.Notes)
	}
}

func TestInstallTIXTCPFlowsRejectsFastPathDisabled(t *testing.T) {
	manager := NewManager()
	manager.spec = dataplane.AttachSpec{
		TIXTCPFastPathDisabled:       true,
		TIXTCPFastPathDisabledReason: "mixed tcp+tix_tcp",
	}

	err := manager.InstallTIXTCPFlows(context.Background(), []dataplane.TIXTCPFlow{{
		ID:              7,
		Peer:            core.IXID("ix-b"),
		Endpoint:        core.EndpointID("exp-b"),
		RemoteAddress:   "198.51.100.2:7142",
		CryptoPlacement: dataplane.CryptoPlacementUserspace,
	}})
	if err == nil || !strings.Contains(err.Error(), "mixed tcp+tix_tcp") {
		t.Fatalf("install tix_tcp flow error = %v, want disabled reason", err)
	}
	if len(manager.tixTCPFlows) != 0 {
		t.Fatalf("disabled tix_tcp installed flows: %#v", manager.tixTCPFlows)
	}
}

func TestKernelUDPTXDirectPlaintextReadyIgnoresTIXTCPControlOnlyFlow(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Routes: []routing.Route{{
			Prefix:   core.Prefix("10.47.0.0/16"),
			NextHop:  core.IXID("ix-b"),
			Endpoint: core.EndpointID("ix-b-tixt"),
		}},
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-b-tixt"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
		},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		10: {
			ID:              10,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}
	if manager.kernelUDPTXDirectPlaintextReadyLocked() {
		t.Fatal("plaintext direct ready with only control-only tix_tcp flow")
	}

	flow := manager.tixTCPFlows[10]
	flow.RemoteAddress = "198.51.100.2:17042"
	manager.tixTCPFlows[10] = flow
	if !manager.kernelUDPTXDirectPlaintextReadyLocked() {
		t.Fatal("plaintext direct not ready after tix_tcp remote tuple is available")
	}
}

func TestKernelUDPTXDirectPlaintextKeepsMultipleFlows(t *testing.T) {
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        core.EndpointID("ix-b-udp"),
			Peer:      core.IXID("ix-b"),
			Transport: "udp",
			Enabled:   true,
			Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
		}},
	}
	manager.kernelUDPFlows = map[uint64]dataplane.KernelUDPFlow{
		41: {
			ID:              41,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-udp"),
			LocalAddress:    "192.0.2.1:41041",
			RemoteAddress:   "198.51.100.41:17001",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
		42: {
			ID:              42,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-udp"),
			LocalAddress:    "192.0.2.1:41042",
			RemoteAddress:   "198.51.100.42:17001",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
		43: {
			ID:              43,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-udp"),
			LocalAddress:    "192.0.2.1:41043",
			RemoteAddress:   "198.51.100.43:17001",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
		44: {
			ID:              44,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-udp"),
			LocalAddress:    "192.0.2.1:41044",
			RemoteAddress:   "198.51.100.44:17001",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.45.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-udp"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, false, kernelUDPTXRouteMaxFlows)
	if len(flows) != 4 {
		t.Fatalf("plaintext direct flows = %d, want 4: %+v", len(flows), flows)
	}
	for i, wantID := range []uint64{41, 42, 43, 44} {
		if flows[i].id != wantID {
			t.Fatalf("plaintext flow[%d] = %d, want %d", i, flows[i].id, wantID)
		}
	}
}

func TestKernelUDPTXDirectPlaintextDropsListenerSourcedFlowWhenOutboundExists(t *testing.T) {
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Peers: []dataplane.PeerMetadata{{ID: core.IXID("ix-b")}},
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-a-udp"),
				Peer:      core.IXID("ix-a"),
				Transport: "udp",
				Listen:    "192.0.2.1:17001",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
			{
				ID:        core.EndpointID("ix-b-udp"),
				Peer:      core.IXID("ix-b"),
				Transport: "udp",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
		},
	}
	manager.kernelUDPFlows = map[uint64]dataplane.KernelUDPFlow{
		10: {
			ID:              10,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-udp"),
			LocalAddress:    "192.0.2.1:17001",
			RemoteAddress:   "198.51.100.2:48865",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
		20: {
			ID:              20,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-udp"),
			LocalAddress:    "192.0.2.1:50158",
			RemoteAddress:   "198.51.100.2:17002",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
		21: {
			ID:              21,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-udp"),
			LocalAddress:    "192.0.2.1:50159",
			RemoteAddress:   "198.51.100.2:17002",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.48.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-udp"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, false, kernelUDPTXRouteMaxFlows)
	if len(flows) != 2 {
		t.Fatalf("plaintext direct flows = %d, want two outbound flows: %+v", len(flows), flows)
	}
	for i, wantID := range []uint64{20, 21} {
		if flows[i].id != wantID {
			t.Fatalf("plaintext flow[%d] = %d, want %d", i, flows[i].id, wantID)
		}
	}
}

func TestKernelUDPTXDirectPlaintextFallsBackToListenerSourcedKernelUDPFlow(t *testing.T) {
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Peers: []dataplane.PeerMetadata{{ID: core.IXID("ix-b")}},
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-a-udp"),
				Peer:      core.IXID("ix-a"),
				Transport: "udp",
				Listen:    "192.0.2.1:17001",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
			{
				ID:        core.EndpointID("ix-b-udp"),
				Peer:      core.IXID("ix-b"),
				Transport: "udp",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
		},
	}
	manager.kernelUDPFlows = map[uint64]dataplane.KernelUDPFlow{
		10: {
			ID:              10,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-udp"),
			LocalAddress:    "192.0.2.1:17001",
			RemoteAddress:   "198.51.100.2:48865",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.48.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-udp"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, false, kernelUDPTXRouteMaxFlows)
	if len(flows) != 1 {
		t.Fatalf("plaintext fallback flows = %d, want 1 listener flow: %+v", len(flows), flows)
	}
	if flows[0].id != 10 {
		t.Fatalf("plaintext fallback flow id = %d, want listener flow 10", flows[0].id)
	}
}

func TestKernelUDPTXDirectFlowValueMarksSecureTIXTCP(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_TCP_CHECKSUM", "1")
	manager := NewManager()
	manager.kernelUDPTXSecureDirectAttached = true
	flow := dataplane.TIXTCPFlow{
		ID:              41,
		Peer:            core.IXID("ix-b"),
		Endpoint:        core.EndpointID("ix-b-tixt"),
		CryptoPlacement: dataplane.CryptoPlacementKernel,
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.46.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-tixt"),
	}
	manager.snapshot = dataplane.Snapshot{
		Routes: []routing.Route{route},
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        core.EndpointID("ix-b-tixt"),
			Peer:      core.IXID("ix-b"),
			Transport: "tix_tcp",
			Enabled:   true,
			Security:  dataplane.EndpointSecurityMetadata{Encryption: "secure"},
		}},
	}

	flags := manager.kernelUDPTXDirectFlowFlagsLocked(route, kernelUDPTXRouteFlow{
		id:         41,
		tixTCPFlow: flow,
		tixTCP:     true,
	}, true)
	if flags&kernelUDPTXFlowFlagTIXTCP == 0 {
		t.Fatalf("flow flags %#x missing tix_tcp", flags)
	}
	if flags&kernelUDPTXFlowFlagSecure == 0 {
		t.Fatalf("flow flags %#x missing secure", flags)
	}
}

func TestKernelUDPTXDirectFlowValueSkipsTIXTCPOuterChecksum(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "1")
	manager := NewManager()
	flow := dataplane.TIXTCPFlow{
		ID:              42,
		Peer:            core.IXID("ix-b"),
		Endpoint:        core.EndpointID("ix-b-tixt"),
		CryptoPlacement: dataplane.CryptoPlacementKernel,
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.46.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-tixt"),
	}
	manager.snapshot = dataplane.Snapshot{
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        core.EndpointID("ix-b-tixt"),
			Peer:      core.IXID("ix-b"),
			Transport: "tix_tcp",
			Enabled:   true,
			Security:  dataplane.EndpointSecurityMetadata{Encryption: "secure"},
		}},
	}

	flags := manager.kernelUDPTXDirectFlowFlagsLocked(route, kernelUDPTXRouteFlow{
		id:         42,
		tixTCPFlow: flow,
		tixTCP:     true,
	}, true)
	if flags&kernelUDPTXFlowFlagSkipOuterTCPChecksum == 0 {
		t.Fatalf("flow flags %#x missing skip outer TCP checksum", flags)
	}
}

func TestKernelUDPTXInlineRouteFlowAllowedForKernelUDPPlaintext(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_PLAIN_SKIP_SEQUENCE", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PUSH_ROUTE_TCP_HEADER_KFUNC", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_INLINE_TIX_TCP", "")
	if !kernelUDPTXInlineRouteFlowAllowed([]kernelUDPTXRouteFlow{{id: 7}}, 1) {
		t.Fatal("single kernel_udp plaintext route flow should allow inline route value")
	}
	if !kernelUDPTXInlineRouteFlowAllowed([]kernelUDPTXRouteFlow{{id: 7}, {id: 8}}, 2) {
		t.Fatal("multi-flow kernel_udp plaintext route should allow inline route values")
	}
	if kernelUDPTXInlineRouteFlowAllowed([]kernelUDPTXRouteFlow{{id: 7, tixTCP: true}}, 1) {
		t.Fatal("tix_tcp route flow should not allow inline route value")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_PLAIN_SKIP_SEQUENCE", "0")
	if kernelUDPTXInlineRouteFlowAllowed([]kernelUDPTXRouteFlow{{id: 7}}, 1) {
		t.Fatal("sequence-tracked route flow should not allow inline route value")
	}
}

func TestKernelUDPTXInlineRouteFlowAllowsTIXTCPWithRouteKfunc(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_PLAIN_SKIP_SEQUENCE", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PUSH_ROUTE_TCP_HEADER_KFUNC", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_INLINE_TIX_TCP", "")
	if !kernelUDPTXInlineRouteFlowAllowed([]kernelUDPTXRouteFlow{{id: 7, tixTCP: true}}, 1) {
		t.Fatal("tix_tcp route kfunc path should allow inline route value by default")
	}
	if !kernelUDPTXInlineRouteFlowValueAllowed(kernelUDPTXFlowValue{Flags: kernelUDPTXFlowFlagTIXTCP}) {
		t.Fatal("tix_tcp route kfunc path should allow inline flow value by default")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_INLINE_TIX_TCP", "0")
	if kernelUDPTXInlineRouteFlowAllowed([]kernelUDPTXRouteFlow{{id: 7, tixTCP: true}}, 1) {
		t.Fatal("explicit inline tix_tcp disable should be honored")
	}
}

func TestKernelUDPTXInlineRouteFlowAllowsTIXTCPWithFinalizeFlowKfunc(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_PLAIN_SKIP_SEQUENCE", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_FINALIZE_FLOW_TCP_HEADER_KFUNC", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_INLINE_TIX_TCP", "")
	if !kernelUDPTXInlineRouteFlowAllowed([]kernelUDPTXRouteFlow{{id: 7, tixTCP: true}}, 1) {
		t.Fatal("tix_tcp finalize-flow kfunc path should allow inline route value by default")
	}
	if !kernelUDPTXInlineRouteFlowValueAllowed(kernelUDPTXFlowValue{Flags: kernelUDPTXFlowFlagTIXTCP}) {
		t.Fatal("tix_tcp finalize-flow kfunc path should allow inline flow value by default")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_INLINE_TIX_TCP", "0")
	if kernelUDPTXInlineRouteFlowAllowed([]kernelUDPTXRouteFlow{{id: 7, tixTCP: true}}, 1) {
		t.Fatal("explicit inline tix_tcp disable should be honored")
	}
}

func TestKernelUDPTXInlineRouteFlowAllowsTIXTCPRouteGSOEnv(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_PLAIN_SKIP_SEQUENCE", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_INLINE_TIX_TCP", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PUSH_ROUTE_TCP_HEADER_KFUNC", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC", "1")
	if !kernelUDPTXInlineRouteFlowAllowed([]kernelUDPTXRouteFlow{{id: 7, tixTCP: true}}, 1) {
		t.Fatal("tix_tcp route-GSO path requires an inline route value")
	}
	if !kernelUDPTXInlineRouteFlowValueAllowed(kernelUDPTXFlowValue{Flags: kernelUDPTXFlowFlagTIXTCP}) {
		t.Fatal("tix_tcp route-GSO path should allow inline flow values")
	}
}

func TestKernelUDPTXInlineRouteFlowAllowsTIXTCPRouteGSOSpec(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_PLAIN_SKIP_SEQUENCE", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_INLINE_TIX_TCP", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PUSH_ROUTE_TCP_HEADER_KFUNC", "")

	spec := dataplane.AttachSpec{TIXTCPRouteGSOSync: true}
	if !kernelUDPTXInlineRouteFlowAllowedForSpec(spec, []kernelUDPTXRouteFlow{{id: 7, tixTCP: true}}, 1) {
		t.Fatal("tix_tcp route-GSO spec requires an inline route value for the route kfunc path")
	}
	if !kernelUDPTXInlineRouteFlowValueAllowedForSpec(spec, kernelUDPTXFlowValue{Flags: kernelUDPTXFlowFlagTIXTCP}) {
		t.Fatal("tix_tcp route-GSO spec should allow inline tix_tcp flow values")
	}
	routeValue := kernelUDPTXRouteValue{}
	if !appendKernelUDPTXRouteFlow(&routeValue, 7, 0) {
		t.Fatal("append route flow")
	}
	if !appendKernelUDPTXRouteInlineFlowsForSpec(spec, &routeValue, map[uint64]kernelUDPTXFlowValue{
		7: {Ifindex: 101, Flags: kernelUDPTXFlowFlagTIXTCP},
	}, 1) {
		t.Fatal("tix_tcp route-GSO spec should append inline route flow values")
	}

	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_INLINE_TIX_TCP", "0")
	if kernelUDPTXInlineRouteFlowAllowedForSpec(spec, []kernelUDPTXRouteFlow{{id: 7, tixTCP: true}}, 1) {
		t.Fatal("explicit inline tix_tcp disable should override the route-GSO spec")
	}
}

func TestAppendKernelUDPTXRouteInlineFlows(t *testing.T) {
	routeValue := kernelUDPTXRouteValue{}
	if !appendKernelUDPTXRouteFlow(&routeValue, 11, 0) || !appendKernelUDPTXRouteFlow(&routeValue, 22, 1) {
		t.Fatal("append route flows")
	}
	values := map[uint64]kernelUDPTXFlowValue{
		11: {Ifindex: 101},
		22: {Ifindex: 202},
	}
	if !appendKernelUDPTXRouteInlineFlows(&routeValue, values, 2) {
		t.Fatal("appendKernelUDPTXRouteInlineFlows rejected plaintext values")
	}
	if routeValue.Inline1.Ifindex != 101 || routeValue.Inline2.Ifindex != 202 {
		t.Fatalf("inline values = %+v/%+v", routeValue.Inline1, routeValue.Inline2)
	}
	values[22] = kernelUDPTXFlowValue{Ifindex: 202, Flags: kernelUDPTXFlowFlagSecure}
	if appendKernelUDPTXRouteInlineFlows(&routeValue, values, 2) {
		t.Fatal("appendKernelUDPTXRouteInlineFlows accepted secure inline value")
	}
}

func TestKernelUDPTXInlineRouteFlowValueRejectsSecureOrExperimental(t *testing.T) {
	if !kernelUDPTXInlineRouteFlowValueAllowed(kernelUDPTXFlowValue{}) {
		t.Fatal("plain kernel_udp flow value should allow inline route value")
	}
	if kernelUDPTXInlineRouteFlowValueAllowed(kernelUDPTXFlowValue{Flags: kernelUDPTXFlowFlagSecure}) {
		t.Fatal("secure flow value should not allow inline route value")
	}
	if kernelUDPTXInlineRouteFlowValueAllowed(kernelUDPTXFlowValue{Flags: kernelUDPTXFlowFlagTIXTCP}) {
		t.Fatal("tix_tcp flow value should not allow inline route value")
	}
}

func TestKernelUDPTXSecureDirectAdjustRoomNoChecksumResetDefaultsOn(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_NO_CSUM_RESET", "")
	if got := kernelUDPTXSecureDirectAdjustRoomFlags(); got&bpfAdjRoomNoCSUMReset == 0 {
		t.Fatalf("secure direct adjust_room flags %#x missing no-csum-reset", got)
	}
}

func TestKernelUDPTXSecureDirectAdjustRoomNoChecksumResetCanDisable(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_NO_CSUM_RESET", "0")
	if got := kernelUDPTXSecureDirectAdjustRoomFlags(); got&bpfAdjRoomNoCSUMReset != 0 {
		t.Fatalf("secure direct adjust_room flags %#x unexpectedly set no-csum-reset", got)
	}
}

func TestKernelUDPTXSecureDirectAdjustRoomTunnelGSOOptIn(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_NO_CSUM_RESET", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_TUNNEL_GSO", "1")
	if got := kernelUDPTXSecureDirectAdjustRoomFlags(); got&(bpfAdjRoomFixedGSO|bpfAdjRoomEncapL3IPv4|bpfAdjRoomEncapL4UDP) == 0 {
		t.Fatalf("secure direct adjust_room flags %#x missing UDP tunnel encapsulation bits after opt-in", got)
	}
}

func TestKernelUDPTXSecureDirectKfuncSealDefaultsOff(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_KFUNC_SEAL", "")
	if kernelUDPTXSecureDirectKfuncSealEnabled() {
		t.Fatal("kfunc seal default enabled; custom module kfuncs must be explicit opt-in")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_KFUNC_SEAL", "1")
	if !kernelUDPTXSecureDirectKfuncSealEnabled() {
		t.Fatal("kfunc seal disabled with explicit opt-in")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_KFUNC_SEAL", "true")
	if !kernelUDPTXSecureDirectKfuncSealEnabled() {
		t.Fatal("kfunc seal disabled with true opt-in")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_KFUNC_SEAL", "0")
	if kernelUDPTXSecureDirectKfuncSealEnabled() {
		t.Fatal("kfunc seal enabled with explicit opt-out")
	}
}

func TestKernelUDPTXSecureDirectSKBSealKfuncDefaultsOff(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_SKB_SEAL_KFUNC", "")
	if kernelUDPTXSecureDirectSKBSealKfuncEnabled() {
		t.Fatal("skb seal kfunc enabled by default; custom skb mutation kfuncs must be explicit opt-in")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_SKB_SEAL_KFUNC", "1")
	if kernelUDPTXSecureDirectSKBSealKfuncEnabled() {
		t.Fatal("skb seal kfunc enabled while the embedded object is built without verifier-safe skb mutation kfunc support")
	}
}

func TestKernelUDPTXSecureDirectFixInnerChecksumsDefaultsOff(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_FIX_INNER_CHECKSUMS", "")
	if kernelUDPTXSecureDirectFixInnerChecksumsEnabled() {
		t.Fatal("inner checksum normalization default enabled, want trusted-checksum fast path")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_FIX_INNER_CHECKSUMS", "1")
	if !kernelUDPTXSecureDirectFixInnerChecksumsEnabled() {
		t.Fatal("inner checksum normalization disabled with explicit opt-in")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_FIX_INNER_CHECKSUMS", "true")
	if !kernelUDPTXSecureDirectFixInnerChecksumsEnabled() {
		t.Fatal("inner checksum normalization disabled with true opt-in")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_FIX_INNER_CHECKSUMS", "0")
	if kernelUDPTXSecureDirectFixInnerChecksumsEnabled() {
		t.Fatal("inner checksum normalization ignored explicit opt-out")
	}
}

func TestKernelUDPTXSecureDirectInnerTCPChecksumKfuncDefaultsOff(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_INNER_TCP_CHECKSUM_KFUNC", "")
	if kernelUDPTXSecureDirectInnerTCPChecksumKfuncEnabled() {
		t.Fatal("secure direct inner TCP checksum kfunc enabled by default; datapath helper kfuncs must be explicit opt-in")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_INNER_TCP_CHECKSUM_KFUNC", "1")
	if kernelUDPTXSecureDirectInnerTCPChecksumKfuncEnabled() {
		t.Fatal("secure direct inner TCP checksum kfunc enabled while the embedded object is built without datapath helper kfunc support")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_INNER_TCP_CHECKSUM_KFUNC", "0")
	if kernelUDPTXSecureDirectInnerTCPChecksumKfuncEnabled() {
		t.Fatal("secure direct inner TCP checksum kfunc enabled with explicit opt-out")
	}
}

func TestKernelUDPTXSecureDirectInnerTCPChecksumKfuncIsCompileTimeOptional(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "..", "kernel", "bpf", "dataplane", "kernel_udp_tx_kernel_crypto_tc.c"))
	if err != nil {
		t.Fatalf("read kernel_udp TX secure C source: %v", err)
	}
	text := string(source)
	if !strings.Contains(text, "#define TRUSTIX_KUDP_SECURE_INNER_TCP_CSUM_KFUNC 0") {
		t.Fatal("secure direct inner TCP checksum kfunc must default to a disabled compile-time feature")
	}
	extern := "extern int trustix_kernel_skb_fix_inner_tcp_csum"
	call := "err = trustix_kernel_skb_fix_inner_tcp_csum(skb, 14, inner_len, 0);"
	for _, needle := range []string{extern, call} {
		index := strings.Index(text, needle)
		if index < 0 {
			t.Fatalf("secure direct source missing guarded kfunc reference %q", needle)
		}
		prefix := text[:index]
		open := strings.LastIndex(prefix, "#if TRUSTIX_KUDP_SECURE_INNER_TCP_CSUM_KFUNC")
		close := strings.LastIndex(prefix, "#endif")
		if open < 0 || close > open {
			t.Fatalf("kfunc reference %q is not guarded by TRUSTIX_KUDP_SECURE_INNER_TCP_CSUM_KFUNC", needle)
		}
	}
	if !strings.Contains(text, "kernelUDPTXSecureDirectInnerTCPChecksumKfuncCompiled = false") {
		loader, err := os.ReadFile("kernel_udp_tx_kernel_crypto_tc_linux.go")
		if err != nil {
			t.Fatalf("read kernel_udp TX secure loader: %v", err)
		}
		if !bytes.Contains(loader, []byte("kernelUDPTXSecureDirectInnerTCPChecksumKfuncCompiled = false")) {
			t.Fatal("loader must keep inner TCP checksum kfunc disabled for the default embedded object")
		}
	}
}

func TestKernelUDPTXSecureDirectIngressDefaultsOn(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_INGRESS", "")
	if !kernelUDPTXSecureDirectIngressEnabled() {
		t.Fatal("secure TX direct ingress disabled by default; TX fast path expects LAN ingress packets")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_INGRESS", "0")
	if kernelUDPTXSecureDirectIngressEnabled() {
		t.Fatal("secure TX direct ingress ignored explicit opt-out")
	}
}

func TestKernelUDPTXSecureDirectEgressDefaultsOn(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_EGRESS", "")
	if !kernelUDPTXSecureDirectEgressEnabled() {
		t.Fatal("secure TX direct egress disabled by default")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_EGRESS", "0")
	if kernelUDPTXSecureDirectEgressEnabled() {
		t.Fatal("secure TX direct egress ignored explicit opt-out")
	}
}

func TestKernelUDPTXSecureDirectOuterTCPChecksumKfuncDefaultsOff(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_OUTER_TCP_CHECKSUM_KFUNC", "")
	if kernelUDPTXSecureDirectOuterTCPChecksumKfuncEnabled() {
		t.Fatal("outer TCP checksum kfunc default enabled; keep it explicit until public-path validation is complete")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_OUTER_TCP_CHECKSUM_KFUNC", "1")
	if !kernelUDPTXSecureDirectOuterTCPChecksumKfuncEnabled() {
		t.Fatal("outer TCP checksum kfunc disabled with explicit opt-in")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_OUTER_TCP_CHECKSUM_KFUNC", "0")
	if kernelUDPTXSecureDirectOuterTCPChecksumKfuncEnabled() {
		t.Fatal("outer TCP checksum kfunc enabled with explicit opt-out")
	}
}

func TestKernelUDPTXSecureDirectOuterTCPPartialChecksumKfuncDefaultsOff(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_OUTER_TCP_PARTIAL_CHECKSUM_KFUNC", "")
	if kernelUDPTXSecureDirectOuterTCPPartialChecksumKfuncEnabled() {
		t.Fatal("outer TCP partial checksum kfunc default enabled; keep it explicit until public-path validation is complete")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_OUTER_TCP_PARTIAL_CHECKSUM_KFUNC", "1")
	if !kernelUDPTXSecureDirectOuterTCPPartialChecksumKfuncEnabled() {
		t.Fatal("outer TCP partial checksum kfunc disabled with explicit opt-in")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_OUTER_TCP_PARTIAL_CHECKSUM_KFUNC", "0")
	if kernelUDPTXSecureDirectOuterTCPPartialChecksumKfuncEnabled() {
		t.Fatal("outer TCP partial checksum kfunc enabled with explicit opt-out")
	}
}

func TestKernelUDPRXSecureDirectRecomputeInnerChecksumsDefaultsOff(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_RECOMPUTE_INNER_CHECKSUMS", "")
	if kernelUDPRXSecureDirectRecomputeInnerChecksumEnabled() {
		t.Fatal("RX inner checksum recompute default enabled, want lightweight store path")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_RECOMPUTE_INNER_CHECKSUMS", "1")
	if !kernelUDPRXSecureDirectRecomputeInnerChecksumEnabled() {
		t.Fatal("RX inner checksum recompute disabled with explicit opt-in")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_RECOMPUTE_INNER_CHECKSUMS", "true")
	if !kernelUDPRXSecureDirectRecomputeInnerChecksumEnabled() {
		t.Fatal("RX inner checksum recompute disabled with true opt-in")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_RECOMPUTE_INNER_CHECKSUMS", "0")
	if kernelUDPRXSecureDirectRecomputeInnerChecksumEnabled() {
		t.Fatal("RX inner checksum recompute ignored explicit opt-out")
	}
}

func TestKernelUDPRXDirectDecapL2KfuncDefaultsOff(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT_DECAP_L2_KFUNC", "")
	if kernelUDPRXDirectDecapL2KfuncEnabledForOptions(kernelUDPRXDirectProgramOptions{}) {
		t.Fatal("RX direct decap L2 kfunc default enabled; datapath helper kfuncs must be explicit opt-in")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT_DECAP_L2_KFUNC", "0")
	if kernelUDPRXDirectDecapL2KfuncEnabledForOptions(kernelUDPRXDirectProgramOptions{}) {
		t.Fatal("RX direct decap L2 kfunc ignored explicit opt-out")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT_DECAP_L2_KFUNC", "1")
	if !kernelUDPRXDirectDecapL2KfuncEnabledForOptions(kernelUDPRXDirectProgramOptions{}) {
		t.Fatal("RX direct decap L2 kfunc disabled with explicit opt-in")
	}
}

func TestKernelUDPRXSecureDirectKfuncOpenDefaultsOff(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_KFUNC_OPEN", "")
	if kernelUDPRXSecureDirectKfuncOpenEnabled() {
		t.Fatal("RX kfunc open default enabled; custom SIMD kfuncs must be explicit opt-in")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_KFUNC_OPEN", "1")
	if !kernelUDPRXSecureDirectKfuncOpenEnabled() {
		t.Fatal("RX kfunc open disabled with explicit opt-in")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_KFUNC_OPEN", "true")
	if !kernelUDPRXSecureDirectKfuncOpenEnabled() {
		t.Fatal("RX kfunc open disabled with true opt-in")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_KFUNC_OPEN", "0")
	if kernelUDPRXSecureDirectKfuncOpenEnabled() {
		t.Fatal("RX kfunc open ignored explicit opt-out")
	}
}

func TestKernelUDPRXSecureDirectHelperKfuncsKeepSKBOpenOptIn(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_SKB_OPEN_KFUNC", "")
	if kernelUDPRXSecureDirectSKBOpenKfuncEnabled() {
		t.Fatal("secure RX skb-open helper kfunc enabled by default; keep experimental skb-open path opt-in")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_SKB_OPEN_KFUNC", "1")
	if !kernelUDPRXSecureDirectSKBOpenKfuncEnabled() {
		t.Fatal("secure RX skb-open helper kfunc ignored explicit opt-in")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_SKB_OPEN_KFUNC", "0")
	if kernelUDPRXSecureDirectSKBOpenKfuncEnabled() {
		t.Fatal("secure RX skb-open helper kfunc ignored explicit opt-out")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_DECAP_L2_KFUNC", "")
	if kernelUDPRXSecureDirectDecapL2KfuncEnabled() {
		t.Fatal("secure RX decap L2 helper kfunc enabled by default; datapath helper kfuncs must be explicit opt-in")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_DECAP_L2_KFUNC", "1")
	if !kernelUDPRXSecureDirectDecapL2KfuncEnabled() {
		t.Fatal("secure RX decap L2 helper kfunc ignored explicit opt-in")
	}
}

func TestKernelUDPRXSecureDirectObjectVariantsPreferDecapAndFallback(t *testing.T) {
	variants := kernelUDPRXSecureDirectObjectVariants(true, true)
	want := []kernelUDPRXSecureDirectObjectVariant{
		{skbOpenKfunc: true, decapL2Kfunc: true},
		{skbOpenKfunc: true, decapL2Kfunc: false},
		{skbOpenKfunc: false, decapL2Kfunc: false},
	}
	if !reflect.DeepEqual(variants, want) {
		t.Fatalf("secure RX variants = %+v, want %+v", variants, want)
	}
}

func TestKernelUDPRXSecureDirectHelperKfuncsAreCompileTimeOptional(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "..", "kernel", "bpf", "dataplane", "kernel_udp_rx_kernel_crypto_tc.c"))
	if err != nil {
		t.Fatalf("read kernel_udp RX secure C source: %v", err)
	}
	text := string(source)
	requireSourceContains(t, text, "#define TRUSTIX_KUDP_SECURE_SKB_OPEN_KFUNC 0")
	requireSourceContains(t, text, "#define TRUSTIX_KUDP_SECURE_DECAP_L2_KFUNC 0")
	for macro, needles := range map[string][]string{
		"TRUSTIX_KUDP_SECURE_SKB_OPEN_KFUNC": {
			"extern int trustix_kernel_skb_direct_open",
			"static __noinline int trustix_open_secure_frame_skb_direct",
			"plain_len = trustix_open_secure_frame_skb_direct(",
		},
		"TRUSTIX_KUDP_SECURE_DECAP_L2_KFUNC": {
			"extern int trustix_kernel_skb_kudp_rx_decap_l2",
			"static __noinline int trustix_secure_decap_l2_kfunc",
			"trustix_secure_decap_l2_kfunc(skb, scratch, decap_len, inner_len)",
		},
	} {
		for _, needle := range needles {
			index := strings.Index(text, needle)
			if index < 0 {
				t.Fatalf("secure RX source missing guarded kfunc reference %q", needle)
			}
			prefix := text[:index]
			open := strings.LastIndex(prefix, "#if "+macro)
			close := strings.LastIndex(prefix, "#endif")
			if open < 0 || close > open {
				t.Fatalf("secure RX kfunc reference %q is not guarded by %s", needle, macro)
			}
		}
	}
	loader, err := os.ReadFile("kernel_udp_rx_kernel_crypto_tc_linux.go")
	if err != nil {
		t.Fatalf("read kernel_udp RX secure loader: %v", err)
	}
	if !bytes.Contains(loader, []byte("kernelUDPRXSecureDirectSKBOpenKfuncCompiled = true")) ||
		!bytes.Contains(loader, []byte("kernelUDPRXSecureDirectDecapL2KfuncCompiled = true")) {
		t.Fatal("secure RX loader must enable compiled skb-open and decap-L2 embedded objects")
	}
	if !bytes.Contains(loader, []byte("kernel_udp_rx_kernel_crypto_tc_skbopen_bpfel.o")) {
		t.Fatal("secure RX loader must be able to select the skb-open embedded object")
	}
	if !bytes.Contains(loader, []byte("kernel_udp_rx_kernel_crypto_tc_skbopen_decap_l2_bpfel.o")) {
		t.Fatal("secure RX loader must be able to select the skb-open decap-L2 embedded object")
	}
}

func TestKernelUDPOpenBorrowedPoolDefaultsOffAndTIXTCPAutoOn(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_OPEN_BORROW_POOL", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_SEAL_BORROW_POOL", "")
	t.Setenv("TRUSTIX_TIX_TCP_OPEN_BORROW_POOL", "")
	t.Setenv("TRUSTIX_TIX_TCP_KERNEL_OPEN_INPLACE", "")
	t.Setenv("TRUSTIX_AF_XDP_TX_DEFER_FLUSH", "")
	if kernelUDPOpenBorrowedPoolEnabled() {
		t.Fatal("kernel_udp borrowed-open default enabled")
	}
	if kernelUDPSealBorrowedPoolEnabled() {
		t.Fatal("kernel_udp borrowed-seal default enabled")
	}
	if !tixTCPOpenBorrowedPoolEnabled() {
		t.Fatal("tix_tcp borrowed-open auto default disabled")
	}

	t.Setenv("TRUSTIX_KERNEL_UDP_OPEN_BORROW_POOL", "1")
	if !kernelUDPOpenBorrowedPoolEnabled() {
		t.Fatal("kernel_udp borrowed-open ignored explicit opt-in")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_SEAL_BORROW_POOL", "1")
	if !kernelUDPSealBorrowedPoolEnabled() {
		t.Fatal("kernel_udp borrowed-seal ignored explicit opt-in")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_OPEN_BORROW_POOL", "0")
	if kernelUDPOpenBorrowedPoolEnabled() {
		t.Fatal("kernel_udp borrowed-open ignored explicit opt-out")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_SEAL_BORROW_POOL", "0")
	if kernelUDPSealBorrowedPoolEnabled() {
		t.Fatal("kernel_udp borrowed-seal ignored explicit opt-out")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_OPEN_BORROW_POOL", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_SEAL_BORROW_POOL", "")

	t.Setenv("TRUSTIX_TIX_TCP_KERNEL_OPEN_INPLACE", "1")
	if tixTCPOpenBorrowedPoolEnabled() {
		t.Fatal("tix_tcp borrowed-open auto ignored kernel open-in-place")
	}
	t.Setenv("TRUSTIX_TIX_TCP_KERNEL_OPEN_INPLACE", "")
	t.Setenv("TRUSTIX_AF_XDP_TX_DEFER_FLUSH", "1")
	if tixTCPOpenBorrowedPoolEnabled() {
		t.Fatal("tix_tcp borrowed-open auto ignored deferred TX flush")
	}
	t.Setenv("TRUSTIX_AF_XDP_TX_DEFER_FLUSH", "")
	if !tixTCPOpenBorrowedPoolEnabled() {
		t.Fatal("tix_tcp borrowed-open incorrectly inherited kernel_udp opt-out")
	}

	t.Setenv("TRUSTIX_TIX_TCP_OPEN_BORROW_POOL", "1")
	if !tixTCPOpenBorrowedPoolEnabled() {
		t.Fatal("tix_tcp borrowed-open ignored explicit opt-in")
	}
	t.Setenv("TRUSTIX_TIX_TCP_OPEN_BORROW_POOL", "0")
	if tixTCPOpenBorrowedPoolEnabled() {
		t.Fatal("tix_tcp borrowed-open ignored explicit opt-out")
	}
}

func TestKernelUDPAFXDPIdleFallbackEnv(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_AF_XDP_IDLE_FALLBACK", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_AF_XDP_IDLE_FALLBACK_AFTER", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_AF_XDP_IDLE_FALLBACK_MAX_FRAMES", "")
	if kernelUDPAFXDPIdleFallbackEnabled() {
		t.Fatal("kernel_udp AF_XDP idle fallback default enabled")
	}
	if got := kernelUDPAFXDPIdleFallbackAfter(); got != 2*time.Second {
		t.Fatalf("idle fallback default after = %s, want 2s", got)
	}
	if got := kernelUDPAFXDPIdleFallbackMaxFrames(); got != 16 {
		t.Fatalf("idle fallback default max frames = %d, want 16", got)
	}
	if !kernelUDPAFXDPIdleFallbackUnderlayPacketEnabled() {
		t.Fatal("idle fallback default path did not use underlay packet fallback")
	}

	t.Setenv("TRUSTIX_KERNEL_UDP_AF_XDP_IDLE_FALLBACK", "1")
	if !kernelUDPAFXDPIdleFallbackEnabled() {
		t.Fatal("idle fallback ignored explicit opt-in")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_AF_XDP_IDLE_FALLBACK", "off")
	if kernelUDPAFXDPIdleFallbackEnabled() {
		t.Fatal("idle fallback ignored explicit opt-out")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_AF_XDP_IDLE_FALLBACK_PATH", "udp_socket")
	if kernelUDPAFXDPIdleFallbackUnderlayPacketEnabled() {
		t.Fatal("idle fallback path ignored udp_socket override")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_AF_XDP_IDLE_FALLBACK_AFTER", "0")
	if got := kernelUDPAFXDPIdleFallbackAfter(); got != 0 {
		t.Fatalf("idle fallback after 0 = %s, want 0", got)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_AF_XDP_IDLE_FALLBACK_AFTER", "bad")
	if got := kernelUDPAFXDPIdleFallbackAfter(); got != 2*time.Second {
		t.Fatalf("idle fallback invalid after = %s, want default", got)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_AF_XDP_IDLE_FALLBACK_MAX_FRAMES", "0")
	if got := kernelUDPAFXDPIdleFallbackMaxFrames(); got != 0 {
		t.Fatalf("idle fallback max frames 0 = %d, want full-batch sentinel", got)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_AF_XDP_IDLE_FALLBACK_MAX_FRAMES", "999999")
	if got := kernelUDPAFXDPIdleFallbackMaxFrames(); got != 4096 {
		t.Fatalf("idle fallback max frames cap = %d, want 4096", got)
	}
}

func TestKernelUDPAFXDPIdleFallbackReservation(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_AF_XDP_IDLE_FALLBACK", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_AF_XDP_IDLE_FALLBACK_AFTER", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_AF_XDP_IDLE_FALLBACK_MAX_FRAMES", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_AF_XDP_IDLE_FALLBACK_PATH", "udp_socket")
	t.Setenv("TRUSTIX_KERNEL_UDP_SOCKET_FALLBACK", "")
	manager := NewManager()
	now := time.Unix(100, 0)

	manager.mu.Lock()
	if got := manager.reserveKernelUDPAFXDPIdleFallbackLocked(now, 20); got != 0 {
		t.Fatalf("reserve without UDP fallback socket = %d, want 0", got)
	}
	if manager.kernelUDPAFXDPIdleFallbackSkips != 1 {
		t.Fatalf("idle fallback skips = %d, want 1", manager.kernelUDPAFXDPIdleFallbackSkips)
	}
	manager.kernelUDPUDPFallbackSockets[1234] = &kernelUDPUDPFallbackSocket{port: 1234, fd: 1}
	if got := manager.reserveKernelUDPAFXDPIdleFallbackLocked(now, 20); got != 16 {
		t.Fatalf("first idle reserve = %d, want capped 16", got)
	}
	if manager.kernelUDPAFXDPIdleFallbackAttempts != 1 || manager.kernelUDPAFXDPIdleFallbackFrames != 16 {
		t.Fatalf("idle fallback stats attempts=%d frames=%d, want 1/16", manager.kernelUDPAFXDPIdleFallbackAttempts, manager.kernelUDPAFXDPIdleFallbackFrames)
	}
	if got := manager.reserveKernelUDPAFXDPIdleFallbackLocked(now.Add(time.Second), 20); got != 0 {
		t.Fatalf("hot reserve = %d, want 0", got)
	}
	if got := manager.reserveKernelUDPAFXDPIdleFallbackLocked(now.Add(3*time.Second), 3); got != 3 {
		t.Fatalf("second idle reserve = %d, want 3", got)
	}
	manager.mu.Unlock()
}

func TestKernelUDPAFXDPIdleFallbackReservationUnderlayPacketDoesNotRequireSocket(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_AF_XDP_IDLE_FALLBACK", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_AF_XDP_IDLE_FALLBACK_AFTER", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_AF_XDP_IDLE_FALLBACK_MAX_FRAMES", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_AF_XDP_IDLE_FALLBACK_PATH", "underlay_packet")
	manager := NewManager()
	now := time.Unix(100, 0)

	manager.mu.Lock()
	if got := manager.reserveKernelUDPAFXDPIdleFallbackLocked(now, 20); got != 16 {
		t.Fatalf("underlay-packet idle reserve = %d, want capped 16", got)
	}
	if manager.kernelUDPAFXDPIdleFallbackSkips != 0 {
		t.Fatalf("underlay-packet idle fallback skips = %d, want 0", manager.kernelUDPAFXDPIdleFallbackSkips)
	}
	manager.mu.Unlock()
}

func TestKernelUDPTunnelGSOAdjustRoomFlagsRequireExplicitEnv(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_NO_CSUM_RESET", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "")
	if kernelUDPTunnelGSOEnabled() {
		t.Fatal("kernel_udp tunnel GSO enabled without explicit env")
	}
	if !kernelUDPTunnelGSOEnabledForOptions(kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true}) {
		t.Fatal("kernel_udp plaintext direct-only did not enable tunnel GSO by default")
	}
	if got := kernelUDPTCTXAdjustRoomFlags(); got != bpfAdjRoomNoCSUMReset {
		t.Fatalf("TX adjust_room flags = %#x, want no-csum-reset only", got)
	}
	if got := kernelUDPTCTXAdjustRoomFlagsForOptions(kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true}); got&(bpfAdjRoomFixedGSO|bpfAdjRoomEncapL3IPv4|bpfAdjRoomEncapL4UDP) == 0 {
		t.Fatalf("direct-only TX adjust_room flags %#x missing tunnel GSO encapsulation bits", got)
	}
	if got := kernelUDPTCTXAdjustRoomFlagsForOptions(kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true}); got>>bpfAdjRoomEncapL2Shift != 0 || got&bpfAdjRoomEncapL2ETH != 0 {
		t.Fatalf("direct-only TX adjust_room encap L2 flags = %#x, want disabled by default", got)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_ENCAP_L2_LEN", "0")
	if got := kernelUDPTCTXAdjustRoomFlagsForOptions(kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true}); got>>bpfAdjRoomEncapL2Shift != 0 || got&bpfAdjRoomEncapL2ETH != 0 {
		t.Fatalf("disabled TX adjust_room encap L2 flags = %#x, want disabled", got)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_ENCAP_L2_LEN", strconv.Itoa(kerneludp.HeaderLen))
	if got := kernelUDPTCTXAdjustRoomFlagsForOptions(kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true}); got>>bpfAdjRoomEncapL2Shift != kerneludp.HeaderLen || got&bpfAdjRoomEncapL2ETH == 0 {
		t.Fatalf("explicit TX adjust_room encap L2 flags = %#x, want Ethernet len %d", got, kerneludp.HeaderLen)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_ENCAP_L2_LEN", "")
	if got := kernelUDPTCRXAdjustRoomFlags(); got != bpfAdjRoomNoCSUMReset {
		t.Fatalf("RX adjust_room flags = %#x, want no-csum-reset only", got)
	}
	if got := kernelUDPTCRXAdjustRoomFlagsForOptions(kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true}); got != bpfAdjRoomNoCSUMReset {
		t.Fatalf("direct-only RX adjust_room flags = %#x, want no-csum-reset only by default", got)
	}

	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "0")
	if kernelUDPTunnelGSOEnabledForOptions(kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true}) {
		t.Fatal("kernel_udp plaintext direct-only ignored explicit tunnel GSO disable")
	}

	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "1")
	if !kernelUDPTunnelGSOEnabled() {
		t.Fatal("kernel_udp tunnel GSO did not enable after explicit env")
	}
	if got := kernelUDPTCTXAdjustRoomFlags(); got&(bpfAdjRoomFixedGSO|bpfAdjRoomEncapL3IPv4|bpfAdjRoomEncapL4UDP) == 0 {
		t.Fatalf("TX adjust_room flags %#x missing tunnel GSO encapsulation bits", got)
	}
	if got := kernelUDPTCRXAdjustRoomFlags(); got&(bpfAdjRoomFixedGSO|bpfAdjRoomDecapL3IPv4) == 0 {
		t.Fatalf("RX adjust_room flags %#x missing GSO decap bits", got)
	}

	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_ADJ_ROOM_TUNNEL_GSO", "1")
	if got := kernelUDPTCRXAdjustRoomFlagsForOptions(kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true}); got&(bpfAdjRoomFixedGSO|bpfAdjRoomDecapL3IPv4) == 0 {
		t.Fatalf("explicit RX adjust_room flags %#x missing GSO decap bits", got)
	}

	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_ADJ_ROOM_TUNNEL_GSO", "0")
	if got := kernelUDPTCRXAdjustRoomFlagsForOptions(kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true}); got&(bpfAdjRoomFixedGSO|bpfAdjRoomDecapL3IPv4) != 0 {
		t.Fatalf("explicit RX adjust_room disable ignored, flags %#x", got)
	}
}

func TestKernelUDPTXDirectActiveGSODefaultsOnForDirectOnly(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "")
	if !kernelUDPTunnelGSOActiveSKBEnabledForOptions(kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true}) {
		t.Fatal("kernel_udp plaintext direct-only did not enable active GSO by default")
	}
	if kernelUDPTunnelGSOActiveSKBEnabledForOptions(kernelUDPTXDirectProgramOptions{Enabled: true}) {
		t.Fatal("kernel_udp non-direct-only enabled active GSO by default")
	}
	if kernelUDPTunnelGSOActiveSKBEnabledForOptions(kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true, TIXTCPOnly: true}) {
		t.Fatal("tix_tcp direct-only enabled kernel_udp active GSO by default")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "1")
	if !kernelUDPTunnelGSOActiveSKBEnabledForOptions(kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true}) {
		t.Fatal("kernel_udp plaintext direct-only ignored explicit active GSO opt-in")
	}
	if kernelUDPTunnelGSOActiveSKBEnabledForOptions(kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true, TIXTCPOnly: true}) {
		t.Fatal("tix_tcp active GSO should require its separate unsafe ack")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "0")
	if kernelUDPTunnelGSOActiveSKBEnabledForOptions(kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true}) {
		t.Fatal("kernel_udp plaintext direct-only ignored explicit active GSO disable")
	}
}

func TestTIXTCPRouteTCPGSOKfuncEnablesSafeActiveGSO(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_SAFE", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC", "0")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC", "0")

	withoutRouteKfunc := kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true, TIXTCPOnly: true}
	if kernelUDPTunnelGSOEnabledForOptions(withoutRouteKfunc) {
		t.Fatal("tix_tcp route-GSO env enabled tunnel-GSO without an available route GSO kfunc")
	}
	if kernelUDPTunnelGSOActiveSKBEnabledForOptions(withoutRouteKfunc) {
		t.Fatal("tix_tcp route-GSO env enabled active-GSO without an available route GSO kfunc")
	}

	withRouteKfunc := withoutRouteKfunc
	withRouteKfunc.RouteTCPGSOKfunc = true
	if !kernelUDPTunnelGSOEnabledForOptions(withRouteKfunc) {
		t.Fatal("tix_tcp route-GSO kfunc should enable tunnel-GSO packet handling")
	}
	if !kernelUDPTunnelGSOActiveSKBEnabledForOptions(withRouteKfunc) {
		t.Fatal("tix_tcp route-GSO kfunc should enable active GSO input without unsafe active-GSO ack")
	}

	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "0")
	if kernelUDPTunnelGSOActiveSKBEnabledForOptions(withRouteKfunc) {
		t.Fatal("explicit active-GSO disable should still override route-GSO sync")
	}
}

func TestKernelUDPTXDirectKernelUDPOnlyDefaultsNoChecksumReset(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_NO_CSUM_RESET", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "0")
	options := kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true, KernelUDPOnly: true}
	if got := kernelUDPTCTXAdjustRoomFlagsForOptions(options); got&bpfAdjRoomNoCSUMReset == 0 {
		t.Fatalf("kernel_udp-only direct TX flags %#x missing no-csum-reset default", got)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_NO_CSUM_RESET", "0")
	if got := kernelUDPTCTXAdjustRoomFlagsForOptions(options); got&bpfAdjRoomNoCSUMReset != 0 {
		t.Fatalf("kernel_udp-only direct TX flags %#x ignored explicit no-csum-reset disable", got)
	}
}

func TestTIXTCPActiveGSOAllowsSafeFinalizeFlowMode(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_ACTIVE_GSO_SAFE", "1")
	t.Setenv("TRUSTIX_TIX_TCP_ALLOW_UNSAFE_ACTIVE_GSO", "")
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM", "0")
	kfuncCall, err := loadSKBTIXTTXFinalizeFlowTCPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load flow TCP header-finalize kfunc metadata: %v", err)
	}
	options := kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true, TIXTCPOnly: true}
	if kernelUDPTunnelGSOActiveSKBEnabledForOptions(options) {
		t.Fatal("tix_tcp safe active-GSO should require the finalize-flow kfunc")
	}
	options.FinalizeFlowTCPHeaderKfunc = true
	options.FinalizeFlowTCPHeaderKfuncCall = kfuncCall
	if tixTCPTXDirectSafeActiveGSOEnabledForOptions(options) {
		t.Fatal("tix_tcp active-GSO should require the explicit unsafe ack")
	}
	if kernelUDPTunnelGSOActiveSKBEnabledForOptions(options) {
		t.Fatal("tix_tcp active-GSO should stay disabled without unsafe ack")
	}
	t.Setenv("TRUSTIX_TIX_TCP_ALLOW_UNSAFE_ACTIVE_GSO", "1")
	if tixTCPTXDirectSafeActiveGSOEnabledForOptions(options) {
		t.Fatal("tix_tcp active-GSO accepted unsafe ack after production hard-disable")
	}
	if kernelUDPTunnelGSOActiveSKBEnabledForOptions(options) {
		t.Fatal("tix_tcp active-GSO enabled after production hard-disable")
	}
	options.PushRouteTCPHeaderKfunc = true
	if tixTCPTXDirectSafeActiveGSOEnabledForOptions(options) {
		t.Fatal("tix_tcp active-GSO allowed route TCP kfuncs")
	}
}

func TestTIXTCPActiveGSORequiresUnsafeAck(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_ACTIVE_GSO_UNSAFE", "1")
	t.Setenv("TRUSTIX_TIX_TCP_ALLOW_UNSAFE_ACTIVE_GSO", "")

	options := kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true, TIXTCPOnly: true}
	if tixTCPTXDirectActiveGSOUnsafeEnabled() {
		t.Fatal("tix_tcp active GSO unsafe flag should require its ack")
	}
	if kernelUDPTunnelGSOActiveSKBEnabledForOptions(options) {
		t.Fatal("tix_tcp unsafe active-GSO should stay disabled without unsafe ack")
	}

	t.Setenv("TRUSTIX_TIX_TCP_ALLOW_UNSAFE_ACTIVE_GSO", "1")
	if tixTCPTXDirectActiveGSOUnsafeEnabled() {
		t.Fatal("tix_tcp active GSO unsafe flag accepted explicit ack after production hard-disable")
	}
	if kernelUDPTunnelGSOActiveSKBEnabledForOptions(options) {
		t.Fatal("tix_tcp unsafe active-GSO enabled after production hard-disable")
	}
}

func TestKernelUDPTXDirectRedirectPeerDefaultsToVethDirectOnly(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_REDIRECT_PEER", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_REDIRECT_PEER", "")
	if !kernelUDPTXDirectRedirectPeerEnabledForLink(&netlink.Veth{}, true, true) {
		t.Fatal("kernel_udp TX direct did not default to redirect_peer on veth direct-only")
	}
	if kernelUDPTXDirectRedirectPeerEnabledForLink(nil, true, true) {
		t.Fatal("kernel_udp TX direct enabled redirect_peer without a veth link")
	}
	if kernelUDPTXDirectRedirectPeerEnabledForLink(&netlink.Veth{}, false, true) {
		t.Fatal("kernel_udp TX direct enabled redirect_peer outside kernel_udp-only mode")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_REDIRECT_PEER", "0")
	if kernelUDPTXDirectRedirectPeerEnabledForLink(&netlink.Veth{}, true, true) {
		t.Fatal("kernel_udp TX direct ignored explicit redirect_peer disable")
	}
}

func TestKernelUDPTXDirectRouteCacheDefaultsOnForDirectPaths(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_ROUTE_CACHE", "")
	if kernelUDPTXDirectRouteCacheEnabled() {
		t.Fatal("kernel_udp route cache enabled without a direct-path context")
	}
	if !kernelUDPTXDirectRouteCacheEnabled(kernelUDPTXDirectProgramOptions{DirectOnly: true}) {
		t.Fatal("kernel_udp route cache should default on for direct-only paths")
	}
	if !kernelUDPTXDirectRouteCacheEnabled(kernelUDPTXDirectProgramOptions{TIXTCPOnly: true}) {
		t.Fatal("kernel_udp route cache should default on for tix_tcp direct paths")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_ROUTE_CACHE", "1")
	if !kernelUDPTXDirectRouteCacheEnabled() {
		t.Fatal("kernel_udp route cache ignored explicit opt-in")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_ROUTE_CACHE", "0")
	if kernelUDPTXDirectRouteCacheEnabled() {
		t.Fatal("kernel_udp route cache ignored explicit opt-out")
	}
}

func TestKernelUDPTXDirectRouteCacheCandidateAllowsFlowRoute(t *testing.T) {
	value := kernelUDPTXRouteValue{
		FlowID:   11,
		FlowID1:  11,
		FlowID2:  22,
		FlowMask: 1,
		Flags:    kernelUDPTXRouteFlagInlineFlow,
		Inline1:  kernelUDPTXFlowValue{Ifindex: 101},
		Inline2:  kernelUDPTXFlowValue{Ifindex: 202},
	}
	if !kernelUDPTXDirectRouteCacheCandidate(false, value) {
		t.Fatal("kernel_udp route cache rejected a multi-flow inline route")
	}
	if kernelUDPTXDirectRouteCacheCandidate(true, value) {
		t.Fatal("kernel_udp route cache accepted a second cached route")
	}
	value.Flags |= kernelUDPTXRouteFlagBypass
	if kernelUDPTXDirectRouteCacheCandidate(false, value) {
		t.Fatal("kernel_udp route cache accepted a bypass route")
	}
	value.Flags = 0
	if !kernelUDPTXDirectRouteCacheCandidate(false, value) {
		t.Fatal("kernel_udp route cache rejected a non-inline route with flow ids")
	}
	value.FlowID = 0
	value.FlowID1 = 0
	if kernelUDPTXDirectRouteCacheCandidate(false, value) {
		t.Fatal("kernel_udp route cache accepted a route without flow ids")
	}
}

func TestKernelUDPTXDirectTunnelGSOMTUUsesSegmentSize(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp TX direct BPF instruction test requires Linux maps")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF map test: %v", err)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "1")
	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_stats_gso_segment_len_test", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	defer statsMap.Close()
	routeMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_gso_segment_route_test", Type: cebpf.LPMTrie, KeySize: 8, ValueSize: kernelUDPTXRouteValueSize, MaxEntries: 16, Flags: 1})
	defer routeMap.Close()
	flowMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_gso_segment_flow_test", Type: cebpf.Hash, KeySize: 8, ValueSize: kernelUDPTXFlowValueSize, MaxEntries: 16})
	defer flowMap.Close()
	out := appendKernelUDPTXDirect(asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}, statsMap, routeMap, flowMap, kernelUDPTXDirectProgramOptions{Enabled: true})
	if !instructionsContainLoadMem(out, asm.R6, skbGSOSizeOffset, asm.Word) {
		t.Fatalf("kernel_udp TX direct GSO path does not read skb gso_size offset %d", skbGSOSizeOffset)
	}
	if !instructionsContainLoadMem(out, asm.RFP, kernelUDPTXGSOSegmentLenOffset, asm.Word) {
		t.Fatalf("kernel_udp TX direct GSO path does not reload computed segment length from stack")
	}
	if !instructionsContainReferenceAfterSymbol(out, "kudp_tx_direct_adjust_flags_ready", "kudp_tx_direct_adjust_drop", 32) {
		t.Fatal("kernel_udp TX direct GSO path does not rejoin after selecting adjust_room flags")
	}
	if !instructionsContainImm(out, int64(kernelUDPTCAdjustRoomBaseFlags())) {
		t.Fatal("kernel_udp TX direct GSO path does not keep linear adjust_room flags available")
	}
	if !instructionsContainImm(out, int64(kernelUDPTCTXAdjustRoomFlags())) {
		t.Fatal("kernel_udp TX direct GSO path does not keep tunnel-GSO adjust_room flags available")
	}
}

func TestKernelUDPTXDirectTunnelGSOHeadersUseSegmentSize(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp TX direct BPF instruction test requires Linux maps")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF map test: %v", err)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "1")
	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_stats_gso_header_len_test", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	defer statsMap.Close()
	routeMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_gso_header_route_test", Type: cebpf.LPMTrie, KeySize: 8, ValueSize: kernelUDPTXRouteValueSize, MaxEntries: 16, Flags: 1})
	defer routeMap.Close()
	flowMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_gso_header_flow_test", Type: cebpf.Hash, KeySize: 8, ValueSize: kernelUDPTXFlowValueSize, MaxEntries: 16})
	defer flowMap.Close()
	out := appendKernelUDPTXDirect(asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}, statsMap, routeMap, flowMap, kernelUDPTXDirectProgramOptions{Enabled: true})
	if got := instructionsCountLoadMem(out, asm.RFP, kernelUDPTXGSOSegmentLenOffset, asm.Word); got < 4 {
		t.Fatalf("kernel_udp TX direct GSO path reloads segment length %d times, want at least MTU/IP/UDP/TIXU header loads", got)
	}
}

func TestKernelUDPTXDirectTIXTCPTIXTActiveGSOHeadersUseSegmentSize(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("tix_tcp TX direct BPF instruction test requires Linux maps")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF map test: %v", err)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_ACTIVE_GSO_SAFE", "1")
	t.Setenv("TRUSTIX_TIX_TCP_ALLOW_UNSAFE_ACTIVE_GSO", "1")
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM", "0")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "tix_tcp_tixt_active_gso_headers")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	kfuncCall, err := loadSKBTIXTTXFinalizeFlowTCPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load flow TCP header-finalize kfunc metadata: %v", err)
	}
	options := kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true, FinalizeFlowTCPHeaderKfunc: true, FinalizeFlowTCPHeaderKfuncCall: kfuncCall}
	if !kernelUDPTunnelGSOActiveSKBEnabledForOptions(options) {
		t.Skip("tix_tcp active GSO is production-hard-disabled")
	}
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word), asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word)},
		statsMap,
		routeMap,
		flowMap,
		options,
	)
	if got := instructionsCountLoadMem(out, asm.RFP, kernelUDPTXGSOSegmentLenOffset, asm.Word); got < 4 {
		t.Fatalf("tix_tcp TIXT active GSO path reloads segment length %d times, want IP/TCP/TIXT/checksum header loads", got)
	}
	if !instructionsContainSymbol(out, "kudp_tx_direct_build_tixt") {
		t.Fatal("tix_tcp TIXT active GSO path lost the TIXT build label")
	}
	if !instructionsContainSymbol(out, "kudp_tx_direct_gso_success_counter_skip") {
		t.Fatal("tix_tcp TIXT active GSO path does not preserve GSO success accounting")
	}
}

func TestKernelUDPTXDirectTIXTCPActiveGSOSkipsMTUCheckBeforeFlowLoad(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("tix_tcp TX direct BPF instruction test requires Linux maps")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF map test: %v", err)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_ACTIVE_GSO_SAFE", "1")
	t.Setenv("TRUSTIX_TIX_TCP_ALLOW_UNSAFE_ACTIVE_GSO", "1")
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM", "0")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "tix_tcp_active_gso_mtu_skip")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	kfuncCall, err := loadSKBTIXTTXFinalizeFlowTCPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load flow TCP header-finalize kfunc metadata: %v", err)
	}
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word), asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true, FinalizeFlowTCPHeaderKfunc: true, FinalizeFlowTCPHeaderKfuncCall: kfuncCall},
	)
	if !instructionsJumpBeforeLoadMem(out, "kudp_tx_direct_len_ok", "kudp_tx_direct_mtu_ok", asm.R0, 40, asm.Word) {
		t.Fatal("tix_tcp active-GSO path does not skip MTU flow load before the MTU check")
	}
}

func TestKernelUDPTXDirectOnlyEnablesGSOInstructionPathByDefault(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp TX direct BPF instruction test requires Linux maps")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF map test: %v", err)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "")
	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_stats_direct_only_gso_default_test", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	defer statsMap.Close()
	routeMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_direct_only_gso_default_route_test", Type: cebpf.LPMTrie, KeySize: 8, ValueSize: kernelUDPTXRouteValueSize, MaxEntries: 16, Flags: 1})
	defer routeMap.Close()
	flowMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_direct_only_gso_default_flow_test", Type: cebpf.Hash, KeySize: 8, ValueSize: kernelUDPTXFlowValueSize, MaxEntries: 16})
	defer flowMap.Close()
	out := appendKernelUDPTXDirect(asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}, statsMap, routeMap, flowMap, kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true})
	if !instructionsContainLoadMem(out, asm.R6, skbGSOSizeOffset, asm.Word) {
		t.Fatalf("kernel_udp direct-only TX path does not read skb gso_size offset %d by default", skbGSOSizeOffset)
	}
	if !instructionsContainImm(out, int64(kernelUDPTCTXAdjustRoomFlagsForOptions(kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true}))) {
		t.Fatal("kernel_udp direct-only TX path does not include tunnel-GSO adjust_room flags by default")
	}
}

func TestLANOffloadProtectionPreservesKernelUDPDirectGSOByDefault(t *testing.T) {
	t.Setenv("TRUSTIX_LAN_OFFLOAD_PROTECTION", "")
	t.Setenv("TRUSTIX_LAN_OFFLOAD_PROTECTION_PRESERVE_ROUTE_GSO", "")
	t.Setenv("TRUSTIX_LAN_OFFLOAD_PROTECTION_PRESERVE_TX_GSO", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_SAFE", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "")

	spec := dataplane.AttachSpec{KernelUDPTXDirectOnly: true}
	if !lanOffloadProtectionPreservesRouteGSO(spec) {
		t.Fatal("kernel_udp direct-only active GSO should preserve LAN TX/GSO offloads by default")
	}
	if got := lanOffloadProtectionFeaturesForSpec(spec); !reflect.DeepEqual(got, lanRouteGSOPreservedOffloadFeatures) {
		t.Fatalf("kernel_udp direct-only GSO feature set = %#v, want route-GSO preserved set", got)
	}

	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "0")
	if lanOffloadProtectionPreservesRouteGSO(spec) {
		t.Fatal("explicit active-GSO disable should disable LAN TX/GSO preservation")
	}
}

func TestKernelUDPTXDirectSafeModeDisablesImplicitGSOButAllowsExplicitRouteTCPKfuncs(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_SAFE", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC", "1")

	options := kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true}
	if kernelUDPTunnelGSOEnabledForOptions(options) {
		t.Fatal("safe direct mode should disable implicit tunnel-GSO")
	}
	if kernelUDPTunnelGSOActiveSKBEnabledForOptions(options) {
		t.Fatal("safe direct mode should disable implicit active-GSO")
	}
	if !tixTCPTXDirectRouteTCPGSOKfuncRequested() {
		t.Fatal("safe direct mode should allow explicit tix_tcp route TCP GSO kfunc")
	}
	if !tixTCPTXDirectRouteTCPXmitKfuncRequested() {
		t.Fatal("safe direct mode should allow explicit tix_tcp route TCP clone-worker xmit kfunc")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC", "1")
	if tixTCPTXDirectRouteTCPGSOAsyncKfuncRequested() {
		t.Fatal("safe direct mode should block tix_tcp route TCP async GSO kfunc")
	}
}

func TestKernelUDPTXDirectSafeModeAllowsExplicitLinearDirectProgram(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp TX direct BPF instruction test requires Linux maps")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF map test: %v", err)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_SAFE", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_HOT_STATS", "1")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "safe_linear_direct")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()

	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, KernelUDPOnly: true, DirectOnly: true},
	)
	if instructionsContainSymbol(out, "kudp_tx_direct_len_gso_ok") {
		t.Fatal("safe direct mode emitted the tunnel-GSO instruction branch")
	}
	if !instructionsContainSymbol(out, "kudp_tx_direct_len_gso_fallback") {
		t.Fatal("safe direct mode should keep an explicit GSO fallback label")
	}
	if !instructionsContainSymbol(out, "kudp_tx_direct_success_counter_done") {
		t.Fatal("safe direct mode did not emit the linear TX direct success path")
	}
}

func TestKernelUDPTXDirectGSOHotCountersInstrumentActivePath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp TX direct BPF instruction test requires Linux maps")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF map test: %v", err)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_HOT_STATS", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "1")
	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_stats_gso_hot_counter_test", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	defer statsMap.Close()
	routeMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_gso_hot_counter_route_test", Type: cebpf.LPMTrie, KeySize: 8, ValueSize: kernelUDPTXRouteValueSize, MaxEntries: 16, Flags: 1})
	defer routeMap.Close()
	flowMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_gso_hot_counter_flow_test", Type: cebpf.Hash, KeySize: 8, ValueSize: kernelUDPTXFlowValueSize, MaxEntries: 16})
	defer flowMap.Close()

	out := appendKernelUDPTXDirect(asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}, statsMap, routeMap, flowMap, kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true})
	for _, item := range []struct {
		name string
		key  uint32
	}{
		{name: "gso_inputs", key: kernelUDPTXDirectStatGSOInputs},
		{name: "gso_active_accepts", key: kernelUDPTXDirectStatGSOActiveAccepts},
		{name: "linear_accepts", key: kernelUDPTXDirectStatLinearAccepts},
		{name: "gso_successes", key: kernelUDPTXDirectStatGSOSuccesses},
	} {
		if !instructionsContainImm(out, int64(item.key)) {
			t.Fatalf("kernel_udp TX direct active-GSO path missing %s counter key %d", item.name, item.key)
		}
	}
	if !instructionsContainSymbol(out, "kudp_tx_direct_gso_success_counter_skip") {
		t.Fatal("kernel_udp TX direct active-GSO success counter is not guarded by GSO-active check")
	}
}

func TestKernelUDPTXDirectSKBClearTXOffloadIsOptIn(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp TX direct BPF instruction test requires Linux maps")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF map test: %v", err)
	}
	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_stats_skb_clear_test", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	defer statsMap.Close()
	routeMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_skb_clear_route_test", Type: cebpf.LPMTrie, KeySize: 8, ValueSize: kernelUDPTXRouteValueSize, MaxEntries: 16, Flags: 1})
	defer routeMap.Close()
	flowMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_skb_clear_flow_test", Type: cebpf.Hash, KeySize: 8, ValueSize: kernelUDPTXFlowValueSize, MaxEntries: 16})
	defer flowMap.Close()

	disabled := appendKernelUDPTXDirect(asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}, statsMap, routeMap, flowMap, kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true})
	if instructionsContainKfuncCall(disabled) {
		t.Fatal("kernel_udp TX direct emitted skb kfunc call without opt-in")
	}

	kfuncCall, err := loadSKBClearTXOffloadKfuncCall()
	if err != nil {
		t.Fatalf("load skb clear kfunc metadata: %v", err)
	}
	enabled := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true, SKBClearTXOffload: true, SKBClearKfuncCall: kfuncCall},
	)
	if !instructionsContainKfuncCall(enabled) {
		t.Fatal("kernel_udp TX direct did not emit skb offload-clear kfunc call")
	}
	if !instructionsContainSymbol(enabled, "kudp_tx_direct_skb_clear_tx_offload") ||
		!instructionsContainSymbol(enabled, "kudp_tx_direct_skb_clear_tx_offload_done") {
		t.Fatal("kernel_udp TX direct missing skb offload-clear labels")
	}
	if !instructionsContainImm(enabled, int64(trustIXSKBClearTXOffloadCSUM|trustIXSKBClearTXOffloadEncap)) {
		t.Fatal("kernel_udp TX direct missing skb offload-clear flags")
	}
}

func TestKernelUDPTXDirectSKBClearTXOffloadSkipsActiveGSOByDefault(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp TX direct BPF instruction test requires Linux maps")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF map test: %v", err)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_CLEAR_SKB_ACTIVE_GSO", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_CLEAR_SKB_OFFLOAD_ACTIVE_GSO", "")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "skb_clear_skip_active_gso")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()

	kfuncCall, err := loadSKBClearTXOffloadKfuncCall()
	if err != nil {
		t.Fatalf("load skb clear kfunc metadata: %v", err)
	}
	defaultProtected := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true, SKBClearTXOffload: true, SKBClearKfuncCall: kfuncCall},
	)
	if !instructionsContainSymbol(defaultProtected, "kudp_tx_direct_skb_clear_tx_offload_skip_active_gso") {
		t.Fatal("kernel_udp TX direct does not skip skb offload-clear on active GSO by default")
	}
	if !instructionsContainKfuncCall(defaultProtected) {
		t.Fatal("kernel_udp TX direct dropped skb offload-clear kfunc call for linear packets")
	}

	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_CLEAR_SKB_ACTIVE_GSO", "1")
	enabledForActiveGSO := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true, SKBClearTXOffload: true, SKBClearKfuncCall: kfuncCall},
	)
	if instructionsContainSymbol(enabledForActiveGSO, "kudp_tx_direct_skb_clear_tx_offload_skip_active_gso") {
		t.Fatal("kernel_udp TX direct still skips skb offload-clear after explicit active-GSO opt-in")
	}
}

func TestKernelUDPTXDirectStrongFlowHashIsEnvGated(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_STRONG_FLOW_HASH", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_SKB_FLOW_HASH", "")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "strong_flow_hash")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()

	disabled := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true},
	)
	if instructionsContainSymbol(disabled, "kudp_tx_direct_hash_ready_strong") ||
		instructionsContainSymbol(disabled, "kudp_tx_direct_inline_hash_ready_strong") {
		t.Fatal("kernel_udp TX direct emitted strong flow hash labels by default")
	}

	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_STRONG_FLOW_HASH", "1")
	enabled := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true},
	)
	if !instructionsContainSymbol(enabled, "kudp_tx_direct_hash_ready") ||
		!instructionsContainSymbol(enabled, "kudp_tx_direct_inline_hash_ready") ||
		!instructionsContainSymbol(enabled, "kudp_tx_direct_hash_ready_strong") ||
		!instructionsContainSymbol(enabled, "kudp_tx_direct_inline_hash_ready_strong") {
		t.Fatal("kernel_udp TX direct strong hash path lost hash labels")
	}
}

func TestKernelUDPTXDirectSKBFlowHashIsEnvGated(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_SKB_FLOW_HASH", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_PORT_FLOW_HASH", "")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "skb_flow_hash")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()

	disabled := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true},
	)
	if instructionsContainSymbol(disabled, "kudp_tx_direct_hash_ready_skb_hash") ||
		instructionsContainSymbol(disabled, "kudp_tx_direct_inline_hash_ready_skb_hash") ||
		instructionsCountBuiltinCalls(disabled, asm.FnGetHashRecalc) != 0 {
		t.Fatal("kernel_udp TX direct emitted skb flow hash path by default")
	}

	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_SKB_FLOW_HASH", "1")
	enabled := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true},
	)
	if !instructionsContainSymbol(enabled, "kudp_tx_direct_hash_ready_skb_hash") ||
		!instructionsContainSymbol(enabled, "kudp_tx_direct_inline_hash_ready_skb_hash") {
		t.Fatal("kernel_udp TX direct did not emit skb flow hash labels after opt-in")
	}
	if got := instructionsCountBuiltinCalls(enabled, asm.FnGetHashRecalc); got != 2 {
		t.Fatalf("bpf_get_hash_recalc calls = %d, want 2", got)
	}
	if !instructionsContainStoreMem(enabled, asm.RFP, kernelUDPTXFlowMaskScratchOffset, asm.Word) ||
		!instructionsContainLoadMemInto(enabled, asm.R1, asm.RFP, kernelUDPTXFlowMaskScratchOffset, asm.Word) {
		t.Fatal("kernel_udp TX direct skb hash path does not preserve flow mask across bpf_get_hash_recalc")
	}
	if !instructionsContainLoadMemInto(enabled, asm.R0, asm.RFP, kernelUDPTXRoutePtrOffset, asm.DWord) {
		t.Fatal("kernel_udp TX direct skb hash path does not restore route pointer after bpf_get_hash_recalc")
	}
}

func TestKernelUDPTXDirectPortFlowHashIsEnvGated(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_SKB_FLOW_HASH", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_PORT_FLOW_HASH", "")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "port_flow_hash")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()

	disabled := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true},
	)
	if instructionsContainSymbol(disabled, "kudp_tx_direct_hash_ready_port") ||
		instructionsContainSymbol(disabled, "kudp_tx_direct_inline_hash_ready_port") {
		t.Fatal("kernel_udp TX direct emitted port flow hash path by default")
	}

	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_PORT_FLOW_HASH", "1")
	enabled := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true},
	)
	if !instructionsContainSymbol(enabled, "kudp_tx_direct_hash_ready_port") ||
		!instructionsContainSymbol(enabled, "kudp_tx_direct_inline_hash_ready_port") {
		t.Fatal("kernel_udp TX direct did not emit port flow hash labels after opt-in")
	}
}

func TestKernelUDPTXDirectInnerTCPChecksumKfuncCanBeDisabled(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_INNER_TCP_CHECKSUM_KFUNC", "0")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "inner_tcp_kfunc")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	disabled := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, KernelUDPOnly: true, DirectOnly: true},
	)
	if instructionsContainSymbol(disabled, "kudp_tx_direct_inner_tcp_post_csum_kfunc") {
		t.Fatal("kernel_udp TX direct emitted inner TCP checksum kfunc after explicit disable")
	}
	kfuncCall, err := loadSKBFixInnerTCPCsumKfuncCall()
	if err != nil {
		t.Fatalf("load inner TCP checksum kfunc metadata: %v", err)
	}
	enabled := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, KernelUDPOnly: true, DirectOnly: true, InnerTCPKfunc: true, InnerTCPKfuncCall: kfuncCall},
	)
	if !instructionsContainSymbol(enabled, "kudp_tx_direct_inner_tcp_post_csum_kfunc") ||
		!instructionsContainSymbol(enabled, "kudp_tx_direct_inner_tcp_post_csum_kfunc_success") {
		t.Fatal("kernel_udp TX direct missing inner TCP checksum kfunc labels")
	}
	if !instructionsContainKfuncCall(enabled) {
		t.Fatal("kernel_udp TX direct did not emit inner TCP checksum kfunc call")
	}
	if !instructionsContainJump(enabled, "kudp_tx_direct_inner_tcp_post_csum_kfunc_fallback", "kudp_tx_direct_inner_tcp_post_csum_payload_payload_chunk_0_next") {
		t.Fatal("inner TCP checksum kfunc path does not fall back to the eBPF checksum scanner")
	}
}

func TestKernelUDPTXDirectInnerTCPChecksumKfuncIsOptIn(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_INNER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_INNER_TCP_CHECKSUM_KFUNC", "")
	options := kernelUDPTXDirectProgramOptions{Enabled: true, KernelUDPOnly: true, DirectOnly: true}
	if kernelUDPTXDirectInnerTCPChecksumKfuncRequestedForOptions(options) {
		t.Fatal("kernel_udp TX direct should not request inner TCP checksum kfunc by default")
	}

	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_INNER_TCP_CHECKSUM_KFUNC", "1")
	if !kernelUDPTXDirectInnerTCPChecksumKfuncRequestedForOptions(options) {
		t.Fatal("kernel_udp TX direct did not request inner TCP checksum kfunc after explicit opt-in")
	}

	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_INNER_TCP_CHECKSUM_KFUNC", "0")
	if kernelUDPTXDirectInnerTCPChecksumKfuncRequestedForOptions(options) {
		t.Fatal("kernel_udp TX direct should not request inner TCP checksum kfunc after explicit disable")
	}
}

func TestTIXTCPTXDirectOuterTCPChecksumKfuncIsOptIn(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_OUTER_TCP_CHECKSUM_KFUNC", "")
	if tixTCPTXDirectOuterTCPChecksumKfuncRequested() {
		t.Fatal("tix_tcp outer TCP checksum kfunc should be opt-in")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_OUTER_TCP_CHECKSUM_KFUNC", "1")
	if !tixTCPTXDirectOuterTCPChecksumKfuncRequested() {
		t.Fatal("tix_tcp outer TCP checksum kfunc was not requested after opt-in")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_OUTER_TCP_CHECKSUM_KFUNC", "0")
	if tixTCPTXDirectOuterTCPChecksumKfuncRequested() {
		t.Fatal("tix_tcp outer TCP checksum kfunc ignored explicit disable")
	}
}

func TestTIXTCPTXDirectOuterTCPHeaderKfuncIsOptIn(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_OUTER_TCP_HEADER_KFUNC", "")
	if tixTCPTXDirectOuterTCPHeaderKfuncRequested() {
		t.Fatal("tix_tcp outer TCP header kfunc should be opt-in")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_OUTER_TCP_HEADER_KFUNC", "1")
	if !tixTCPTXDirectOuterTCPHeaderKfuncRequested() {
		t.Fatal("tix_tcp outer TCP header kfunc was not requested after opt-in")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_OUTER_TCP_HEADER_KFUNC", "0")
	if tixTCPTXDirectOuterTCPHeaderKfuncRequested() {
		t.Fatal("tix_tcp outer TCP header kfunc ignored explicit disable")
	}
}

func TestTIXTCPTXDirectPushTCPHeaderKfuncIsOptIn(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PUSH_TCP_HEADER_KFUNC", "")
	if tixTCPTXDirectPushTCPHeaderKfuncRequested() {
		t.Fatal("tix_tcp TCP header-push kfunc should be opt-in")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PUSH_TCP_HEADER_KFUNC", "1")
	if !tixTCPTXDirectPushTCPHeaderKfuncRequested() {
		t.Fatal("tix_tcp TCP header-push kfunc was not requested after opt-in")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PUSH_TCP_HEADER_KFUNC", "0")
	if tixTCPTXDirectPushTCPHeaderKfuncRequested() {
		t.Fatal("tix_tcp TCP header-push kfunc ignored explicit disable")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PUSH_TCP_HEADER_KFUNC_REQUIRED", "1")
	if !tixTCPTXDirectPushTCPHeaderKfuncRequired() {
		t.Fatal("tix_tcp TCP header-push kfunc required flag was not detected")
	}
}

func TestTIXTCPTXDirectPushFlowTCPHeaderKfuncIsOptIn(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PUSH_FLOW_TCP_HEADER_KFUNC", "")
	if tixTCPTXDirectPushFlowTCPHeaderKfuncRequested() {
		t.Fatal("tix_tcp flow TCP header-push kfunc should be opt-in")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PUSH_FLOW_TCP_HEADER_KFUNC", "1")
	if !tixTCPTXDirectPushFlowTCPHeaderKfuncRequested() {
		t.Fatal("tix_tcp flow TCP header-push kfunc was not requested after opt-in")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PUSH_FLOW_TCP_HEADER_KFUNC", "0")
	if tixTCPTXDirectPushFlowTCPHeaderKfuncRequested() {
		t.Fatal("tix_tcp flow TCP header-push kfunc ignored explicit disable")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PUSH_FLOW_TCP_HEADER_KFUNC_REQUIRED", "1")
	if !tixTCPTXDirectPushFlowTCPHeaderKfuncRequired() {
		t.Fatal("tix_tcp flow TCP header-push kfunc required flag was not detected")
	}
}

func TestTIXTCPTXDirectFinalizeFlowTCPHeaderKfuncIsOptIn(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_FINALIZE_FLOW_TCP_HEADER_KFUNC", "")
	if tixTCPTXDirectFinalizeFlowTCPHeaderKfuncRequested() {
		t.Fatal("tix_tcp flow TCP header-finalize kfunc should be opt-in")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_FINALIZE_FLOW_TCP_HEADER_KFUNC", "1")
	if !tixTCPTXDirectFinalizeFlowTCPHeaderKfuncRequested() {
		t.Fatal("tix_tcp flow TCP header-finalize kfunc was not requested after opt-in")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_FINALIZE_FLOW_TCP_HEADER_KFUNC", "0")
	if tixTCPTXDirectFinalizeFlowTCPHeaderKfuncRequested() {
		t.Fatal("tix_tcp flow TCP header-finalize kfunc ignored explicit disable")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_FINALIZE_FLOW_TCP_HEADER_KFUNC_REQUIRED", "1")
	if !tixTCPTXDirectFinalizeFlowTCPHeaderKfuncRequired() {
		t.Fatal("tix_tcp flow TCP header-finalize kfunc required flag was not detected")
	}
}

func TestTIXTCPTXDirectPushRouteTCPHeaderKfuncIsExplicitOptIn(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PUSH_ROUTE_TCP_HEADER_KFUNC", "")
	if tixTCPTXDirectPushRouteTCPHeaderKfuncRequested() {
		t.Fatal("tix_tcp route TCP header-push kfunc should stay off without direct mode or explicit opt-in")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	if tixTCPTXDirectPushRouteTCPHeaderKfuncRequested() {
		t.Fatal("tix_tcp route TCP header-push kfunc should stay off without explicit opt-in")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PUSH_ROUTE_TCP_HEADER_KFUNC", "1")
	if !tixTCPTXDirectPushRouteTCPHeaderKfuncRequested() {
		t.Fatal("tix_tcp route TCP header-push kfunc was not requested after opt-in")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PUSH_ROUTE_TCP_HEADER_KFUNC", "0")
	if tixTCPTXDirectPushRouteTCPHeaderKfuncRequested() {
		t.Fatal("tix_tcp route TCP header-push kfunc ignored explicit disable")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PUSH_ROUTE_TCP_HEADER_KFUNC_REQUIRED", "1")
	if !tixTCPTXDirectPushRouteTCPHeaderKfuncRequired() {
		t.Fatal("tix_tcp route TCP header-push kfunc required flag was not detected")
	}
}

func TestTIXTCPTXDirectRouteTCPGSOKfuncIsExplicitOptIn(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PUSH_ROUTE_TCP_HEADER_KFUNC", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC", "")
	if tixTCPTXDirectRouteTCPGSOKfuncRequested() {
		t.Fatal("tix_tcp route TCP GSO kfunc should stay off without explicit opt-in")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	if tixTCPTXDirectRouteTCPGSOKfuncRequested() {
		t.Fatal("tix_tcp route TCP GSO kfunc should not default on with direct mode")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PUSH_ROUTE_TCP_HEADER_KFUNC", "1")
	if tixTCPTXDirectRouteTCPGSOKfuncRequested() {
		t.Fatal("tix_tcp route TCP GSO kfunc should not follow route header-push kfunc by default")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC", "1")
	if !tixTCPTXDirectRouteTCPGSOKfuncRequested() {
		t.Fatal("tix_tcp route TCP GSO kfunc was not requested after safe sync opt-in")
	}

	t.Setenv("TRUSTIX_TIX_TCP_ALLOW_UNSAFE_ROUTE_TCP_KFUNCS", "1")
	if !tixTCPTXDirectRouteTCPGSOKfuncRequested() {
		t.Fatal("tix_tcp route TCP GSO kfunc should ignore legacy unsafe ack and keep safe sync opt-in")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC", "1")
	if !tixTCPTXDirectRouteTCPGSOKfuncRequested() {
		t.Fatal("tix_tcp route TCP GSO kfunc should stay requested while async stays separately gated")
	}

	t.Setenv("TRUSTIX_TIX_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_GSO_ASYNC", "1")
	if !tixTCPTXDirectRouteTCPGSOKfuncRequested() {
		t.Fatal("tix_tcp route TCP GSO kfunc should not depend on async crash-risk ack")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC", "")
	if !tixTCPTXDirectRouteTCPGSOKfuncRequested() {
		t.Fatal("tix_tcp route TCP async GSO opt-in should request the route GSO kfunc")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC", "0")
	t.Setenv("TRUSTIX_TIX_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_XMIT", "1")
	if tixTCPTXDirectRouteTCPGSOKfuncRequested() {
		t.Fatal("tix_tcp route TCP GSO kfunc accepted unrelated crash-risk opt-in without explicit GSO request")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC", "0")
	if tixTCPTXDirectRouteTCPGSOKfuncRequested() {
		t.Fatal("tix_tcp route TCP GSO kfunc ignored explicit disable")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC_REQUIRED", "1")
	if tixTCPTXDirectRouteTCPGSOKfuncRequired() {
		t.Fatal("tix_tcp route TCP GSO kfunc required flag should require the route GSO kfunc request")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC", "1")
	if !tixTCPTXDirectRouteTCPGSOKfuncRequired() {
		t.Fatal("tix_tcp route TCP GSO kfunc required flag was not detected")
	}
}

func TestTIXTCPTXDirectRouteTCPGSOKfuncCanFollowAttachSpec(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_ONLY", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_TIX_TCP_ONLY", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PUSH_ROUTE_TCP_HEADER_KFUNC", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC", "")
	t.Setenv("TRUSTIX_TIX_TCP_TX_PLAIN_SKIP_SEQUENCE", "")
	t.Setenv("TRUSTIX_TIX_TCP_TX_PLAIN_ACK_ONLY", "")

	spec := dataplane.AttachSpec{
		TIXTCPTXDirect:          true,
		TIXTCPRouteGSOSync:      true,
		TIXTCPRouteXmitWorker:   true,
		TIXTCPPlainSkipSequence: true,
		TIXTCPPlainACKOnly:      true,
	}
	if !tixTCPTXDirectEnabledForSpec(spec) {
		t.Fatal("attach spec did not enable tix_tcp TX direct")
	}
	if !kernelUDPTXDirectProgramEnabledForSpec(spec) {
		t.Fatal("attach spec did not enable the TX direct program")
	}
	if !kernelUDPTXDirectTIXTCPOnlyEnabledForSpec(spec) || kernelUDPTXDirectKernelUDPOnlyEnabledForSpec(spec) {
		t.Fatal("attach spec should request tix_tcp-only direct program")
	}
	if !tixTCPTXDirectPushRouteTCPHeaderKfuncRequestedForSpec(spec) {
		t.Fatal("route-GSO sync spec did not request route TCP header kfunc")
	}
	if !tixTCPTXDirectRouteTCPGSOKfuncRequestedForSpec(spec) {
		t.Fatal("route-GSO sync spec did not request route TCP GSO kfunc")
	}
	if !tixTCPTXDirectRouteTCPXmitKfuncRequestedForSpec(spec) {
		t.Fatal("route-GSO sync spec did not request route TCP clone-worker xmit kfunc")
	}
	if !tixTCPTXPlainSkipSequenceEnabledForSpec(spec) || !tixTCPTXPlainACKOnlyEnabledForSpec(spec) {
		t.Fatal("route-GSO sync spec did not enable plaintext fast flags")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC", "0")
	if tixTCPTXDirectRouteTCPGSOKfuncRequestedForSpec(spec) {
		t.Fatal("explicit route TCP GSO kfunc disable should override attach spec")
	}
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PUSH_ROUTE_TCP_HEADER_KFUNC", "0")
	if tixTCPTXDirectPushRouteTCPHeaderKfuncRequestedForSpec(spec) {
		t.Fatal("explicit route TCP header kfunc disable should override attach spec")
	}
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PUSH_ROUTE_TCP_HEADER_KFUNC", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC", "0")
	if tixTCPTXDirectRouteTCPXmitKfuncRequestedForSpec(spec) {
		t.Fatal("explicit route TCP clone-worker xmit kfunc disable should override attach spec")
	}
}

func TestTIXTCPTXDirectRouteTCPXmitKfuncIsExplicitOptIn(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC", "")
	if tixTCPTXDirectRouteTCPXmitKfuncRequested() {
		t.Fatal("tix_tcp route TCP xmit kfunc should stay off without explicit opt-in")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	if tixTCPTXDirectRouteTCPXmitKfuncRequested() {
		t.Fatal("tix_tcp route TCP xmit kfunc should not default on with direct mode")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC", "1")
	if tixTCPTXDirectRouteTCPXmitKfuncRequested() {
		t.Fatal("tix_tcp route TCP xmit kfunc should not follow route GSO kfunc by default")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC", "0")
	if tixTCPTXDirectRouteTCPXmitKfuncRequested() {
		t.Fatal("tix_tcp route TCP xmit kfunc ignored explicit disable")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC", "1")
	if !tixTCPTXDirectRouteTCPXmitKfuncRequested() {
		t.Fatal("tix_tcp route TCP clone-worker xmit kfunc was not requested after explicit opt-in")
	}

	t.Setenv("TRUSTIX_TIX_TCP_ALLOW_UNSAFE_ROUTE_TCP_KFUNCS", "1")
	if !tixTCPTXDirectRouteTCPXmitKfuncRequested() {
		t.Fatal("tix_tcp route TCP clone-worker xmit kfunc should ignore legacy unsafe ack and keep explicit opt-in")
	}

	t.Setenv("TRUSTIX_TIX_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_XMIT", "1")
	if !tixTCPTXDirectRouteTCPXmitKfuncRequested() {
		t.Fatal("tix_tcp route TCP clone-worker xmit kfunc should ignore crash-risk ack and keep explicit opt-in")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC_REQUIRED", "1")
	if !tixTCPTXDirectRouteTCPXmitKfuncRequired() {
		t.Fatal("tix_tcp route TCP clone-worker xmit kfunc required flag was not detected")
	}
}

func TestTIXTCPTXDirectPreOuterInnerChecksumDefaultsOffForRouteTCPKfuncs(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PUSH_ROUTE_TCP_HEADER_KFUNC", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC", "1")
	t.Setenv("TRUSTIX_TIX_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_XMIT", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM", "")
	if tixTCPTXDirectPreOuterInnerChecksumEnabled() {
		t.Fatal("route TCP GSO/XMIT kfuncs should disable pre-outer inner checksum by default")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM", "1")
	if !tixTCPTXDirectPreOuterInnerChecksumEnabled() {
		t.Fatal("explicit pre-outer inner checksum enable should be honored")
	}
}

func TestTIXTCPTXDirectPreOuterInnerChecksumDefaultsOffForRouteTCPGSOOptions(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM", "")
	options := kernelUDPTXDirectProgramOptions{
		TIXTCPOnly:              true,
		DirectOnly:              true,
		PushRouteTCPHeaderKfunc: true,
		RouteTCPGSOKfunc:        true,
	}
	if tixTCPTXDirectPreOuterInnerChecksumEnabledForOptions(options) {
		t.Fatal("route TCP GSO options should disable pre-outer inner checksum by default")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM", "1")
	if !tixTCPTXDirectPreOuterInnerChecksumEnabledForOptions(options) {
		t.Fatal("explicit pre-outer inner checksum enable should override route TCP GSO options")
	}
}

func TestRouteTCPGSOSyncKfuncFixesInnerL4Checksum(t *testing.T) {
	sourcePath := filepath.Join("..", "..", "..", "kernel", "trustix_datapath_helpers", "trustix_datapath_helpers_kfuncs.c")
	payload, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read datapath helpers source: %v", err)
	}
	source := string(payload)
	helper := sourceFunctionBody(t, source, "trustix_tixt_tx_fix_inner_l4_csum")
	for _, needle := range []string{
		"IPPROTO_TCP",
		"IPPROTO_UDP",
		"skb_checksum",
		"csum_tcpudp_magic",
		"trustix_skb_clear_csum_metadata",
	} {
		if !strings.Contains(helper, needle) {
			t.Fatalf("inner L4 checksum helper missing %q", needle)
		}
	}
	for _, name := range []string{
		"trustix_kernel_skb_tixt_tx_push_route_tcp_header",
		"trustix_tixt_tx_prepare_route_tcp_snapshot",
	} {
		body := sourceFunctionBody(t, source, name)
		if !strings.Contains(body, "trustix_tixt_tx_fix_inner_l4_csum") {
			t.Fatalf("%s does not fix inner L4 checksum before route TCP transmit", name)
		}
	}
	syncBody := sourceFunctionBody(t, source, "trustix_kernel_skb_tixt_tx_segment_route_tcp_gso_sync")
	for _, needle := range []string{"sync_async_redirects", "trustix_kernel_skb_tixt_tx_segment_route_tcp_gso_async"} {
		if !strings.Contains(syncBody, needle) {
			t.Fatalf("route TCP GSO sync body missing %q", needle)
		}
	}
	for _, forbidden := range []string{"trustix_tixt_tx_gso_segment_inner", "trustix_tixt_tx_prepare_one_segment", "dev_queue_xmit"} {
		if strings.Contains(syncBody, forbidden) {
			t.Fatalf("route TCP GSO sync body must redirect to the worker before %q", forbidden)
		}
	}
	streamLimitBody := sourceFunctionBody(t, source, "trustix_route_tcp_gso_sync_stream_max_frames_value")
	if !strings.Contains(streamLimitBody, "TRUSTIX_TIXT_TX_ROUTE_SYNC_STREAM_MAX_FRAMES") {
		t.Fatal("route TCP GSO sync stream max_frames must clamp to the sync stack-array size")
	}
	streamBody := sourceFunctionBody(t, source, "trustix_tixt_tx_route_gso_sync_try_stream")
	if !strings.Contains(streamBody, "frame_count < ARRAY_SIZE(frames)") {
		t.Fatal("route TCP GSO sync stream loop must guard frame_count with ARRAY_SIZE(frames)")
	}
	segmentBody := sourceFunctionBody(t, source, "trustix_tixt_tx_gso_segment_inner")
	if !strings.Contains(segmentBody, "skb_gso_segment") {
		t.Fatal("route TCP GSO segment helper does not call skb_gso_segment")
	}
	if !strings.Contains(source, "route_tcp_gso_sync_async_redirects") {
		t.Fatal("route TCP GSO sync redirects must be observable")
	}
}

func sourceFunctionBody(t *testing.T, source string, name string) string {
	t.Helper()
	offset := 0
	for {
		start := strings.Index(source[offset:], name+"(")
		if start < 0 {
			t.Fatalf("function %s not found", name)
		}
		start += offset
		openRel := strings.Index(source[start:], "{")
		if openRel < 0 {
			t.Fatalf("function %s has no body", name)
		}
		open := start + openRel
		if semiRel := strings.Index(source[start:open], ";"); semiRel >= 0 {
			offset = open + 1
			continue
		}
		depth := 0
		for i := open; i < len(source); i++ {
			switch source[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					return source[open : i+1]
				}
			}
		}
		t.Fatalf("function %s body is not closed", name)
	}
}

func TestKernelUDPTXDirectStoreHeaderKfuncIsOptIn(t *testing.T) {
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "store_header_kfunc")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	disabled := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, KernelUDPOnly: true, DirectOnly: true},
	)
	if instructionsContainSymbol(disabled, "kudp_tx_direct_store_header_kfunc") {
		t.Fatal("kernel_udp TX direct emitted header-store kfunc without opt-in")
	}
	kfuncCall, err := loadSKBKernelUDPTXStoreL2L3L4KfuncCall()
	if err != nil {
		t.Fatalf("load TX header-store kfunc metadata: %v", err)
	}
	enabled := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, KernelUDPOnly: true, DirectOnly: true, StoreHeaderKfunc: true, StoreHeaderKfuncCall: kfuncCall},
	)
	if !instructionsContainSymbol(enabled, "kudp_tx_direct_store_header_kfunc") ||
		!instructionsContainSymbol(enabled, "kudp_tx_direct_store_header_kfunc_done") {
		t.Fatal("kernel_udp TX direct missing header-store kfunc labels")
	}
	if !instructionsContainKfuncCall(enabled) {
		t.Fatal("kernel_udp TX direct did not emit header-store kfunc call")
	}
	if !instructionsContainImm(enabled, int64(kernelUDPTXUDPFrameHeaderLen)) {
		t.Fatal("kernel_udp TX direct header-store path missing UDP/TIXU header length")
	}
}

func TestKernelUDPTXDirectBuildUDPHeaderKfuncIsOptIn(t *testing.T) {
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "build_udp_header_kfunc")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	disabled := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, KernelUDPOnly: true, DirectOnly: true, SkipPlainSequence: true},
	)
	if instructionsContainSymbol(disabled, "kudp_tx_direct_build_udp_header_kfunc") {
		t.Fatal("kernel_udp TX direct emitted UDP header-build kfunc without opt-in")
	}
	kfuncCall, err := loadSKBKernelUDPTXBuildUDPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load TX UDP header-build kfunc metadata: %v", err)
	}
	enabled := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, KernelUDPOnly: true, DirectOnly: true, SkipPlainSequence: true, BuildUDPHeaderKfunc: true, BuildUDPHeaderKfuncCall: kfuncCall},
	)
	if !instructionsContainSymbol(enabled, "kudp_tx_direct_build_udp_header_kfunc") ||
		!instructionsContainSymbol(enabled, "kudp_tx_direct_build_udp_header_kfunc_done") {
		t.Fatal("kernel_udp TX direct missing UDP header-build kfunc labels")
	}
	if !instructionsContainKfuncCall(enabled) {
		t.Fatal("kernel_udp TX direct did not emit UDP header-build kfunc call")
	}
}

func TestKernelUDPTXDirectPushUDPHeaderKfuncIsOptIn(t *testing.T) {
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "push_udp_header_kfunc")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	disabled := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, KernelUDPOnly: true, DirectOnly: true, SkipPlainSequence: true},
	)
	if instructionsContainSymbol(disabled, "kudp_tx_direct_push_udp_header_kfunc") {
		t.Fatal("kernel_udp TX direct emitted UDP header-push kfunc without opt-in")
	}
	kfuncCall, err := loadSKBKernelUDPTXPushUDPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load TX UDP header-push kfunc metadata: %v", err)
	}
	enabled := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, KernelUDPOnly: true, DirectOnly: true, SkipPlainSequence: true, PushUDPHeaderKfunc: true, PushUDPHeaderKfuncCall: kfuncCall},
	)
	if !instructionsContainSymbol(enabled, "kudp_tx_direct_push_udp_header_kfunc") ||
		!instructionsContainSymbol(enabled, "kudp_tx_direct_push_udp_header_kfunc_done") {
		t.Fatal("kernel_udp TX direct missing UDP header-push kfunc labels")
	}
	if !instructionsContainKfuncCall(enabled) {
		t.Fatal("kernel_udp TX direct did not emit UDP header-push kfunc call")
	}
	if !instructionsContainStoreMem(enabled, asm.RFP, kernelUDPTXBuildUDPHeaderArgsPayloadLenOffset, asm.Word) ||
		!instructionsContainStoreMem(enabled, asm.RFP, kernelUDPTXBuildUDPHeaderArgsFlowIDOffset, asm.DWord) {
		t.Fatal("kernel_udp TX direct UDP header-push kfunc path does not initialize UDP header args")
	}
	if instructionsContainSymbol(enabled, "kudp_tx_direct_adjust_ready") ||
		instructionsContainSymbol(enabled, "kudp_tx_direct_build_udp_header_kfunc") ||
		instructionsContainSymbol(enabled, "kudp_tx_direct_store_header_kfunc") {
		t.Fatal("kernel_udp TX direct header-push path did not bypass adjust/store header path")
	}
}

func TestKernelUDPTXDirectFinalizeUDPHeaderKfuncIsOptIn(t *testing.T) {
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "finalize_udp_header_kfunc")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	disabled := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, KernelUDPOnly: true, DirectOnly: true, SkipPlainSequence: true},
	)
	if instructionsContainSymbol(disabled, "kudp_tx_direct_finalize_udp_header_kfunc") {
		t.Fatal("kernel_udp TX direct emitted UDP header-finalize kfunc without opt-in")
	}
	kfuncCall, err := loadSKBKernelUDPTXFinalizeUDPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load TX UDP header-finalize kfunc metadata: %v", err)
	}
	enabled := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, KernelUDPOnly: true, DirectOnly: true, SkipPlainSequence: true, FinalizeUDPHeaderKfunc: true, FinalizeUDPKfuncCall: kfuncCall},
	)
	if !instructionsContainSymbol(enabled, "kudp_tx_direct_finalize_udp_header_kfunc") ||
		!instructionsContainSymbol(enabled, "kudp_tx_direct_finalize_udp_header_kfunc_done") {
		t.Fatal("kernel_udp TX direct missing UDP header-finalize kfunc labels")
	}
	if !instructionsContainKfuncCall(enabled) {
		t.Fatal("kernel_udp TX direct did not emit UDP header-finalize kfunc call")
	}
	if !instructionsContainStoreMem(enabled, asm.RFP, kernelUDPTXBuildUDPHeaderArgsPayloadLenOffset, asm.Word) ||
		!instructionsContainStoreMem(enabled, asm.RFP, kernelUDPTXBuildUDPHeaderArgsFlowIDOffset, asm.DWord) {
		t.Fatal("kernel_udp TX direct UDP header-finalize kfunc path does not initialize UDP header args")
	}
	if instructionsContainSymbol(enabled, "kudp_tx_direct_skb_clear_tx_offload") {
		t.Fatal("kernel_udp TX direct finalizer path should fold skb offload clearing into the finalizer kfunc")
	}
	if !instructionsContainImm(enabled, 0) {
		t.Fatal("kernel_udp TX direct finalizer path missing default no-clear flags")
	}
}

func TestKernelUDPTXDirectUDPHeaderPartialChecksumIsOptIn(t *testing.T) {
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "udp_header_partial_csum")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	finalizeKfuncCall, err := loadSKBKernelUDPTXFinalizeUDPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load TX UDP header-finalize kfunc metadata: %v", err)
	}
	pushKfuncCall, err := loadSKBKernelUDPTXPushUDPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load TX UDP header-push kfunc metadata: %v", err)
	}

	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_UDP_HEADER_PARTIAL_CSUM", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_UDP_HEADER_PARTIAL_CSUM", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_OUTER_UDP_PARTIAL_CSUM", "")
	disabledFinalize := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, KernelUDPOnly: true, DirectOnly: true, SkipPlainSequence: true, FinalizeUDPHeaderKfunc: true, FinalizeUDPKfuncCall: finalizeKfuncCall},
	)
	if !instructionsContainMovImmToRegAfterSymbol(disabledFinalize, "kudp_tx_direct_finalize_udp_header_kfunc", asm.R3, 0) {
		t.Fatal("kernel_udp TX direct finalizer did not pass zero UDP header flags without opt-in")
	}
	if instructionsContainMovImmToRegAfterSymbol(disabledFinalize, "kudp_tx_direct_finalize_udp_header_kfunc", asm.R3, trustIXKUDPTXUDPHeaderPartialCSUM) {
		t.Fatal("kernel_udp TX direct finalizer enabled UDP partial checksum without opt-in")
	}

	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_UDP_HEADER_PARTIAL_CSUM", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_UDP_HEADER_PARTIAL_CSUM", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_OUTER_UDP_PARTIAL_CSUM", "")
	enabledFinalize := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, KernelUDPOnly: true, DirectOnly: true, SkipPlainSequence: true, FinalizeUDPHeaderKfunc: true, FinalizeUDPKfuncCall: finalizeKfuncCall},
	)
	if !instructionsContainMovImmToRegAfterSymbol(enabledFinalize, "kudp_tx_direct_finalize_udp_header_kfunc", asm.R3, trustIXKUDPTXUDPHeaderPartialCSUM) {
		t.Fatal("kernel_udp TX direct finalizer did not pass UDP partial checksum flag")
	}

	enabledPush := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, KernelUDPOnly: true, DirectOnly: true, SkipPlainSequence: true, PushUDPHeaderKfunc: true, PushUDPHeaderKfuncCall: pushKfuncCall},
	)
	if !instructionsContainMovImmToRegAfterSymbol(enabledPush, "kudp_tx_direct_push_udp_header_kfunc", asm.R3, trustIXKUDPTXUDPHeaderPartialCSUM) {
		t.Fatal("kernel_udp TX direct header-push path did not pass UDP partial checksum flag")
	}
}

func TestKernelUDPRXDirectDecapL2KfuncIsOptIn(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp RX direct BPF instruction test requires Linux maps")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF map test: %v", err)
	}
	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_stats_rx_decap_kfunc_test", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	defer statsMap.Close()
	portMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_decap_port_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 16})
	defer portMap.Close()
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_decap_neigh_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 16})
	defer neighMap.Close()
	sourceMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

	disabled, err := loadKernelUDPRXDirectProgramWithOptions("trustix_kudp_rx_decap_disabled_test", statsMap, portMap, neighMap, 7, sourceMAC, kernelUDPRXDirectProgramOptions{KernelUDPOnly: true, DirectOnly: true})
	if err != nil {
		t.Fatalf("load kernel_udp RX direct without decap kfunc: %v", err)
	}
	defer disabled.Close()

	kfuncCall, err := loadSKBKernelUDPRXDecapL2KfuncCall()
	if err != nil {
		t.Fatalf("load RX decap L2 kfunc metadata: %v", err)
	}
	enabled, err := loadKernelUDPRXDirectProgramWithOptions(
		"trustix_kudp_rx_decap_enabled_test",
		statsMap,
		portMap,
		neighMap,
		7,
		sourceMAC,
		kernelUDPRXDirectProgramOptions{KernelUDPOnly: true, DirectOnly: true, DecapL2Kfunc: true, DecapL2KfuncCall: kfuncCall},
	)
	if err != nil {
		skipIfKernelKfuncUnavailable(t, err)
		t.Fatalf("load kernel_udp RX direct with decap kfunc: %v", err)
	}
	defer enabled.Close()
}

func TestKernelUDPRXDirectLocalDeliverDevKfuncFailureFallsBack(t *testing.T) {
	manager := NewManager()
	options := kernelUDPRXDirectProgramOptions{}
	const localIPv4 = 0x0200000a
	const localIPv4Mask = 0x00ffffff

	manager.enableKernelUDPRXDirectLocalDeliverDevKfunc(&options, 7, localIPv4, localIPv4Mask, func() (asm.Instruction, error) {
		return asm.Instruction{}, errors.New("missing kfunc program")
	})

	if !options.LocalDeliver {
		t.Fatal("local delivery was not enabled after local-deliver-dev kfunc failure")
	}
	if options.LocalDeliverDev || options.DecapL2DevKfunc || options.DecapL2DevKfuncCall.IsKfuncCall() {
		t.Fatalf("local-deliver-dev kfunc options stayed enabled after loader failure: %+v", options)
	}
	if options.LocalDeliverIfindex != 0 {
		t.Fatalf("local-deliver-dev ifindex = %d, want 0 after fallback", options.LocalDeliverIfindex)
	}
	if options.LocalIPv4 != localIPv4 {
		t.Fatalf("local IPv4 = %#x, want %#x", options.LocalIPv4, localIPv4)
	}
	if options.LocalIPv4Mask != localIPv4Mask {
		t.Fatalf("local IPv4 mask = %#x, want %#x", options.LocalIPv4Mask, localIPv4Mask)
	}
	if len(manager.warnings) != 1 || !strings.Contains(manager.warnings[0], "local-deliver dev kfunc disabled") {
		t.Fatalf("warnings = %q, want local-deliver dev kfunc fallback warning", manager.warnings)
	}
}

func TestKernelUDPRXDirectDecapL2KfuncFailureFallsBack(t *testing.T) {
	manager := NewManager()
	options := kernelUDPRXDirectProgramOptions{}

	manager.enableKernelUDPRXDirectDecapL2Kfunc(&options, func() (asm.Instruction, error) {
		return asm.Instruction{}, errors.New("missing kfunc program")
	})

	if options.DecapL2Kfunc || options.DecapL2KfuncCall.IsKfuncCall() {
		t.Fatalf("decap L2 kfunc options stayed enabled after loader failure: %+v", options)
	}
	if len(manager.warnings) != 1 || !strings.Contains(manager.warnings[0], "decap L2 kfunc disabled") {
		t.Fatalf("warnings = %q, want decap L2 kfunc fallback warning", manager.warnings)
	}
}

func TestKernelUDPRXDirectParseDecapL2KfuncRequiresStaticPortForKernelUDP(t *testing.T) {
	manager := NewManager()
	options := kernelUDPRXDirectProgramOptions{KernelUDPOnly: true}

	manager.enableKernelUDPRXDirectParseDecapL2Kfunc(&options, func() (asm.Instruction, error) {
		t.Fatal("kernel_udp parse+decap loader should not run without a static destination port")
		return asm.Instruction{}, nil
	})

	if options.ParseDecapL2Kfunc || options.ParseDecapL2KfuncCall.IsKfuncCall() {
		t.Fatalf("kernel_udp parse+decap kfunc options enabled without static port: %+v", options)
	}
}

func TestKernelUDPRXDirectParseDecapL2KfuncAllowsTIXTCPDynamicPort(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_RX_STREAM_PARSE", "1")
	t.Setenv("TRUSTIX_TIXT_RX_STREAM_PARSE", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT_PARSE_DECAP_L2_KFUNC", "")
	manager := NewManager()
	loaderCalled := false
	options := kernelUDPRXDirectProgramOptions{
		TIXTCPOnly:          true,
		DirectOnly:          true,
		DestinationPortOnly: true,
	}

	if !kernelUDPRXDirectParseDecapL2KfuncEnabledForOptions(options) {
		t.Fatal("tix_tcp stream parser should enable parse+decap L2 kfunc without a static destination port")
	}
	manager.enableKernelUDPRXDirectParseDecapL2Kfunc(&options, func() (asm.Instruction, error) {
		loaderCalled = true
		return asm.Instruction{}, errors.New("missing kfunc program")
	})

	if !loaderCalled {
		t.Fatal("tix_tcp parse+decap loader was not called for dynamic-port options")
	}
	if options.ParseDecapL2Kfunc || options.ParseDecapL2KfuncCall.IsKfuncCall() {
		t.Fatalf("parse+decap kfunc options stayed enabled after loader failure: %+v", options)
	}
}

func TestKernelUDPRXDirectParseDecapL2KfuncFailureFallsBack(t *testing.T) {
	manager := NewManager()
	options := kernelUDPRXDirectProgramOptions{StaticDestinationPort: 18001}

	manager.enableKernelUDPRXDirectParseDecapL2Kfunc(&options, func() (asm.Instruction, error) {
		return asm.Instruction{}, errors.New("missing kfunc program")
	})

	if options.ParseDecapL2Kfunc || options.ParseDecapL2KfuncCall.IsKfuncCall() {
		t.Fatalf("parse+decap kfunc options stayed enabled after loader failure: %+v", options)
	}
	if len(manager.warnings) != 1 || !strings.Contains(manager.warnings[0], "parse+decap L2 kfunc disabled") {
		t.Fatalf("warnings = %q, want parse+decap fallback warning", manager.warnings)
	}
}

func TestKernelUDPRXDirectParseDecapL2KfuncIsOptIn(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT_PARSE_DECAP_L2_KFUNC", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_RX_STREAM_PARSE", "")
	t.Setenv("TRUSTIX_TIXT_RX_STREAM_PARSE", "")

	options := kernelUDPRXDirectProgramOptions{
		KernelUDPOnly:         true,
		DirectOnly:            true,
		DestinationPortOnly:   true,
		StaticDestinationPort: 17001,
	}
	if kernelUDPRXDirectParseDecapL2KfuncEnabledForOptions(options) {
		t.Fatal("kernel_udp direct-only static-port RX should not default to parse+decap L2 kfunc")
	}

	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT_PARSE_DECAP_L2_KFUNC", "1")
	if !kernelUDPRXDirectParseDecapL2KfuncEnabledForOptions(options) {
		t.Fatal("parse+decap L2 kfunc disabled with explicit opt-in")
	}

	if kernelUDPRXDirectParseDecapL2KfuncEnabledForOptions(kernelUDPRXDirectProgramOptions{
		KernelUDPOnly:       true,
		DirectOnly:          true,
		DestinationPortOnly: true,
	}) {
		t.Fatal("parse+decap L2 kfunc should stay disabled without a static destination port")
	}

	if !kernelUDPRXDirectParseDecapL2KfuncEnabledForOptions(kernelUDPRXDirectProgramOptions{
		TIXTCPOnly:          true,
		DirectOnly:          true,
		DestinationPortOnly: true,
	}) {
		t.Fatal("tix_tcp direct-only parse+decap L2 kfunc should default on for dynamic destination ports")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_RX_STREAM_PARSE", "0")
	if kernelUDPRXDirectParseDecapL2KfuncEnabledForOptions(kernelUDPRXDirectProgramOptions{
		TIXTCPOnly:          true,
		DirectOnly:          true,
		DestinationPortOnly: true,
	}) {
		t.Fatal("tix_tcp parse+decap L2 kfunc should honor explicit stream parser disable")
	}
}

func TestKernelUDPRXDirectParseDecapL2RequiresLocalDeliverDevForTIXTCPStream(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT_PARSE_DECAP_L2_KFUNC", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_RX_STREAM_PARSE", "")
	t.Setenv("TRUSTIX_TIXT_RX_STREAM_PARSE", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_RX_STREAM_LOCAL_DELIVER_DEV", "")
	t.Setenv("TRUSTIX_TIXT_RX_STREAM_LOCAL_DELIVER_DEV", "")

	if !kernelUDPRXDirectParseDecapL2LocalDeliverDevRequiredForOptions(kernelUDPRXDirectProgramOptions{
		TIXTCPOnly:          true,
		DirectOnly:          true,
		DestinationPortOnly: true,
	}) {
		t.Fatal("tix_tcp stream parse should require local-deliver-dev by default")
	}

	if kernelUDPRXDirectParseDecapL2LocalDeliverDevRequiredForOptions(kernelUDPRXDirectProgramOptions{
		KernelUDPOnly:       true,
		DirectOnly:          true,
		DestinationPortOnly: true,
	}) {
		t.Fatal("kernel_udp direct-only parse should not require tix_tcp stream local-deliver-dev")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_RX_STREAM_LOCAL_DELIVER_DEV", "0")
	if kernelUDPRXDirectParseDecapL2LocalDeliverDevRequiredForOptions(kernelUDPRXDirectProgramOptions{
		TIXTCPOnly:          true,
		DirectOnly:          true,
		DestinationPortOnly: true,
	}) {
		t.Fatal("tix_tcp stream local-deliver-dev should honor explicit disable")
	}
}

func TestKernelUDPRXDirectParseDecapL2PrefilterDefaultsOn(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT_PARSE_DECAP_L2_PREFILTER", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_PARSE_DECAP_L2_PREFILTER", "")

	out := appendKernelUDPRXDirectParseDecapL2Candidate(
		nil,
		nil,
		kernelUDPRXDirectProgramOptions{
			KernelUDPOnly:         true,
			DirectOnly:            true,
			DestinationPortOnly:   true,
			StaticDestinationPort: 18001,
			ParseDecapL2KfuncCall: asm.FnSkbChangeTail.Call(),
		},
		3,
		0x0002, 0, 0, 0x0002, 0, 0,
	)

	if !instructionsContainSymbol(out, "kudp_rx_direct_parse_decap_l2_kfunc") {
		t.Fatal("parse+decap L2 kfunc path is missing")
	}
	if !instructionsContainLoadMem(out, asm.R7, 36, asm.Half) {
		t.Fatal("default parse+decap L2 path did not include static destination-port prefilter")
	}
	if !instructionsContainLoadMem(out, asm.R7, 42, asm.Word) {
		t.Fatal("default parse+decap L2 path did not include kernel_udp magic prefilter")
	}
}

func TestKernelUDPRXDirectParseDecapL2PrefilterSkipsTIXTCPStaticPort(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT_PARSE_DECAP_L2_PREFILTER", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_PARSE_DECAP_L2_PREFILTER", "")

	out := appendKernelUDPRXDirectParseDecapL2Candidate(
		nil,
		nil,
		kernelUDPRXDirectProgramOptions{
			TIXTCPOnly:            true,
			DirectOnly:            true,
			DestinationPortOnly:   true,
			StaticDestinationPort: 18001,
			ParseDecapL2KfuncCall: asm.FnSkbChangeTail.Call(),
		},
		3,
		0x0002, 0, 0, 0x0002, 0, 0,
	)

	if !instructionsContainSymbol(out, "kudp_rx_direct_parse_decap_l2_kfunc") {
		t.Fatal("parse+decap L2 kfunc path is missing")
	}
	if instructionsContainLoadMem(out, asm.R7, 36, asm.Half) {
		t.Fatal("tix_tcp parse+decap L2 path still uses static destination-port prefilter")
	}
	if instructionsContainLoadMem(out, asm.R7, 54, asm.Word) {
		t.Fatal("tix_tcp parse+decap L2 path still uses static magic prefilter")
	}
}

func TestKernelUDPRXDirectParseDecapL2KfuncStaticPortArgument(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT_PARSE_DECAP_L2_PREFILTER", "0")

	kudp := appendKernelUDPRXDirectParseDecapL2Candidate(
		nil,
		nil,
		kernelUDPRXDirectProgramOptions{
			KernelUDPOnly:         true,
			DirectOnly:            true,
			DestinationPortOnly:   true,
			StaticDestinationPort: 18001,
			ParseDecapL2KfuncCall: asm.FnSkbChangeTail.Call(),
		},
		3,
		0x0002, 0, 0, 0x0002, 0, 0,
	)
	if !instructionsContainStoreImm(kudp, asm.RFP, kernelUDPRXDirectKfuncParseArgsStaticPortOffset, asm.Word, 18001) {
		t.Fatal("kernel_udp parse+decap L2 kfunc did not receive static destination port")
	}

	exp := appendKernelUDPRXDirectParseDecapL2Candidate(
		nil,
		nil,
		kernelUDPRXDirectProgramOptions{
			TIXTCPOnly:            true,
			DirectOnly:            true,
			DestinationPortOnly:   true,
			StaticDestinationPort: 18001,
			ParseDecapL2KfuncCall: asm.FnSkbChangeTail.Call(),
		},
		3,
		0x0002, 0, 0, 0x0002, 0, 0,
	)
	if !instructionsContainStoreImm(exp, asm.RFP, kernelUDPRXDirectKfuncParseArgsStaticPortOffset, asm.Word, 0) {
		t.Fatal("tix_tcp parse+decap L2 kfunc should allow dynamic derived destination ports")
	}
	if instructionsContainStoreImm(exp, asm.RFP, kernelUDPRXDirectKfuncParseArgsStaticPortOffset, asm.Word, 18001) {
		t.Fatal("tix_tcp parse+decap L2 kfunc still receives the static listen port")
	}
}

func TestKernelUDPRXDirectParseDecapL2PrefilterCanBeDisabled(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT_PARSE_DECAP_L2_PREFILTER", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_PARSE_DECAP_L2_PREFILTER", "")

	out := appendKernelUDPRXDirectParseDecapL2Candidate(
		nil,
		nil,
		kernelUDPRXDirectProgramOptions{
			TIXTCPOnly:            true,
			DirectOnly:            true,
			DestinationPortOnly:   true,
			StaticDestinationPort: 18001,
			ParseDecapL2KfuncCall: asm.FnSkbChangeTail.Call(),
		},
		3,
		0x0002, 0, 0, 0x0002, 0, 0,
	)

	if !instructionsContainSymbol(out, "kudp_rx_direct_parse_decap_l2_kfunc") {
		t.Fatal("parse+decap L2 kfunc path should remain when prefilter is disabled")
	}
	if instructionsContainLoadMem(out, asm.R7, 36, asm.Half) {
		t.Fatal("disabled parse+decap L2 prefilter still loads static destination port")
	}
	if instructionsContainLoadMem(out, asm.R7, 54, asm.Word) {
		t.Fatal("disabled parse+decap L2 prefilter still loads tix_tcp magic")
	}
}

func TestKernelUDPRXDirectParseDecapL2LocalDeliveredFastReturn(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_HOT_STATS", "1")

	out := appendKernelUDPRXDirectParseDecapL2Candidate(
		nil,
		nil,
		kernelUDPRXDirectProgramOptions{
			TIXTCPOnly:            true,
			DirectOnly:            true,
			DestinationPortOnly:   true,
			StaticDestinationPort: 18001,
			ParseDecapL2KfuncCall: asm.FnSkbChangeTail.Call(),
			LocalDeliver:          true,
			LocalDeliverDev:       true,
			LocalDeliverIfindex:   7,
			LocalIPv4:             binary.LittleEndian.Uint32([]byte{10, 0, 0, 1}),
			LocalIPv4Mask:         ipv4MaskKeyFromPrefixBits(24),
			TrustInnerChecksum:    true,
		},
		3,
		0x0002, 0, 0, 0x0002, 0, 0,
	)

	if !instructionsContainSymbol(out, "kudp_rx_direct_parse_decap_l2_kfunc_local_delivered") {
		t.Fatal("parse+decap L2 kfunc local-delivered fast return is missing")
	}
	if !instructionsContainSymbol(out, "kudp_rx_direct_parse_decap_l2_kfunc_success") {
		t.Fatal("parse+decap L2 kfunc normal success path is missing")
	}
}

func TestKernelUDPTXDirectProgramEnabledForExperimentalOnlyDirectOnly(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_ONLY", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "")
	t.Setenv("TRUSTIX_REMOTE_TIX_TCP_TC_TX_DIRECT", "")
	t.Setenv("TRUSTIX_E2E_TIX_TCP_TC_TX_DIRECT", "")
	t.Setenv("TRUSTIX_IPERF3_CRYPTO_BENCH_TIX_TCP_TC_TX_DIRECT", "")
	if !kernelUDPTXDirectProgramEnabled() {
		t.Fatal("kernel_udp TX direct program ignored tix_tcp direct-only mode")
	}

	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_ONLY", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_TIX_TCP_ONLY", "1")
	if !kernelUDPTXDirectProgramEnabled() {
		t.Fatal("kernel_udp TX direct program ignored tix_tcp-only route mode")
	}
}

func TestKernelUDPTXDirectKernelUDPOnlyEnv(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_KERNEL_UDP_ONLY", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_TIX_TCP_ONLY", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_ONLY", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "")
	t.Setenv("TRUSTIX_REMOTE_TIX_TCP_TC_TX_DIRECT", "")
	t.Setenv("TRUSTIX_E2E_TIX_TCP_TC_TX_DIRECT", "")
	t.Setenv("TRUSTIX_IPERF3_CRYPTO_BENCH_TIX_TCP_TC_TX_DIRECT", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ONLY_PROVIDER", "")
	if !kernelUDPTXDirectKernelUDPOnlyEnabled() {
		t.Fatal("kernel_udp-only specialization should be automatic when tix_tcp direct is disabled")
	}
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	if kernelUDPTXDirectKernelUDPOnlyEnabled() {
		t.Fatal("kernel_udp-only specialization stayed automatic when tix_tcp direct is enabled")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_KERNEL_UDP_ONLY", "1")
	if !kernelUDPTXDirectKernelUDPOnlyEnabled() {
		t.Fatal("kernel_udp-only specialization ignored explicit opt-in")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_KERNEL_UDP_ONLY", "0")
	if kernelUDPTXDirectKernelUDPOnlyEnabled() {
		t.Fatal("kernel_udp-only specialization ignored explicit opt-out")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_KERNEL_UDP_ONLY", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_TIX_TCP_ONLY", "1")
	if kernelUDPTXDirectKernelUDPOnlyEnabled() {
		t.Fatal("kernel_udp-only specialization stayed enabled in tix_tcp-only mode")
	}
}

func TestKernelUDPTXDirectKernelUDPOnlyDisabledForTCOnlyProvider(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ONLY_PROVIDER", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_KERNEL_UDP_ONLY", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_UDP_ONLY", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_TIX_TCP_ONLY", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_ONLY", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "")
	t.Setenv("TRUSTIX_REMOTE_TIX_TCP_TC_TX_DIRECT", "")
	t.Setenv("TRUSTIX_E2E_TIX_TCP_TC_TX_DIRECT", "")
	t.Setenv("TRUSTIX_IPERF3_CRYPTO_BENCH_TIX_TCP_TC_TX_DIRECT", "")
	if kernelUDPTXDirectKernelUDPOnlyEnabled() {
		t.Fatal("TC-only provider defaulted to kernel_udp-only and omitted tix_tcp TX direct")
	}
}

func TestKernelUDPTXDirectOnlyFollowsAttachSpecWithEnvOverride(t *testing.T) {
	spec := dataplane.AttachSpec{KernelUDPTXDirectOnly: true}
	if !kernelUDPTXDirectOnlyEnabled(spec) {
		t.Fatal("kernel_udp TX direct-only did not follow attach spec")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "0")
	if kernelUDPTXDirectOnlyEnabled(spec) {
		t.Fatal("kernel_udp TX direct-only ignored explicit env disable")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "1")
	if !kernelUDPTXDirectOnlyEnabled(dataplane.AttachSpec{}) {
		t.Fatal("kernel_udp TX direct-only ignored explicit env enable")
	}
}

func TestKernelUDPTCOnlyProviderRequiresExplicitOptIn(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ONLY_PROVIDER", "")
	manager := NewManager()
	manager.spec = dataplane.AttachSpec{
		LANIface:              "lan0",
		UnderlayIface:         "eth0",
		KernelUDPTXDirectOnly: true,
	}
	manager.attached = true
	manager.statsMap = newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tconly_stats_default", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	defer manager.statsMap.Close()
	manager.kernelUDPTXRouteMap = newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tconly_route_default", Type: cebpf.LPMTrie, KeySize: 8, ValueSize: kernelUDPTXRouteValueSize, MaxEntries: 1, Flags: 1})
	defer manager.kernelUDPTXRouteMap.Close()
	manager.kernelUDPTXFlowMap = newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tconly_flow_default", Type: cebpf.Hash, KeySize: 8, ValueSize: kernelUDPTXFlowValueSize, MaxEntries: 1})
	defer manager.kernelUDPTXFlowMap.Close()
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
		Endpoints: []dataplane.EndpointMetadata{
			{ID: "local", Peer: "ix-a", Transport: "udp", Listen: "198.18.0.1:17041", Enabled: true, Security: dataplane.EndpointSecurityMetadata{Encryption: "plaintext"}},
			{ID: "remote", Peer: "ix-b", Transport: "udp", Address: "198.18.0.2:17041", Enabled: true, Security: dataplane.EndpointSecurityMetadata{Encryption: "plaintext"}},
		},
		Peers: []dataplane.PeerMetadata{{ID: "ix-b", Trusted: true}},
	}

	if manager.snapshotCanUseKernelUDPTCOnlyLocked() {
		t.Fatal("kernel_udp TC-only provider was selected without explicit opt-in")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")
	if !manager.snapshotCanUseKernelUDPTCOnlyLocked() {
		t.Fatal("kernel_udp TC-only provider did not honor explicit opt-in")
	}
}

func TestKernelUDPTCOnlyProviderAllowsSecureKernelDirectSnapshot(t *testing.T) {
	manager := NewManager()
	manager.spec = dataplane.AttachSpec{
		LANIface:                    "lan0",
		UnderlayIface:               "eth0",
		KernelUDPTXDirectOnly:       true,
		KernelUDPTXDirectOnlyReason: "transport_policy.encryption=secure transport_policy.crypto_placement=kernel kernel_udp_tc_only_provider=enabled",
		KernelUDPTCOnlyProvider:     true,
	}
	manager.statsMap = &cebpf.Map{}
	manager.kernelUDPTXRouteMap = &cebpf.Map{}
	manager.kernelUDPTXFlowMap = &cebpf.Map{}
	manager.kernelUDPFlows = map[uint64]dataplane.KernelUDPFlow{
		7: {
			ID:              7,
			Peer:            "ix-b",
			Endpoint:        "remote",
			CryptoPlacement: dataplane.CryptoPlacementKernel,
			CryptoSuite:     kernelCryptoSuiteAES128GCMX25519,
			Epoch:           3,
		},
	}
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
		Endpoints: []dataplane.EndpointMetadata{
			{ID: "local", Transport: "udp", Listen: "198.18.0.1:17041", Enabled: true, Security: dataplane.EndpointSecurityMetadata{Encryption: "secure", CryptoPlacements: []string{"kernel"}}},
			{ID: "remote", Peer: "ix-b", Transport: "udp", Address: "198.18.0.2:17041", Enabled: true, Security: dataplane.EndpointSecurityMetadata{Encryption: "secure", CryptoPlacements: []string{"kernel"}}},
		},
		Peers: []dataplane.PeerMetadata{{ID: "ix-b", Trusted: true}},
	}

	if !manager.kernelUDPTCOnlySecureDirectRequestedLocked() {
		t.Fatal("secure TC-only provider did not request both TX and RX secure direct")
	}
	if !manager.snapshotCanUseKernelUDPTCOnlyLocked() {
		t.Fatal("secure kernel_udp TC-only provider rejected secure kernel-crypto snapshot")
	}
	manager.kernelUDPFlows[8] = dataplane.KernelUDPFlow{
		ID:              8,
		Peer:            "ix-b",
		Endpoint:        "remote",
		CryptoPlacement: dataplane.CryptoPlacementUserspace,
	}
	if !manager.snapshotCanUseKernelUDPTCOnlyLocked() {
		t.Fatal("secure kernel_udp TC-only provider rejected userspace control seed flow")
	}
}

func TestKernelUDPTCOnlyProviderAllowsTIXTCPRouteGSOSnapshot(t *testing.T) {
	manager := NewManager()
	manager.spec = dataplane.AttachSpec{
		LANIface:                             "lan0",
		UnderlayIface:                        "eth0",
		KernelUDPTXDirectOnly:                true,
		KernelUDPTCOnlyProvider:              true,
		TIXTCPTXDirect:                       true,
		TIXTCPRouteGSOSync:                   true,
		TIXTCPRouteGSOAsync:                  true,
		KernelDatapathSuppressLegacyRXWorker: true,
	}
	manager.statsMap = &cebpf.Map{}
	manager.kernelUDPTXRouteMap = &cebpf.Map{}
	manager.kernelUDPTXFlowMap = &cebpf.Map{}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		9: {
			ID:              9,
			Peer:            "ix-b",
			Endpoint:        "remote",
			RemoteAddress:   "198.18.0.2:9443",
			SourcePort:      41000,
			DestinationPort: 9443,
		},
	}
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
		Endpoints: []dataplane.EndpointMetadata{
			{ID: "local", Peer: "ix-a", Transport: "tix_tcp", Listen: "198.18.0.1:9443", Enabled: true, Security: dataplane.EndpointSecurityMetadata{Encryption: "plaintext"}},
			{ID: "remote", Peer: "ix-b", Transport: "tix_tcp", Address: "198.18.0.2:9443", Enabled: true, Security: dataplane.EndpointSecurityMetadata{Encryption: "plaintext"}},
		},
		Peers: []dataplane.PeerMetadata{{ID: "ix-b", Trusted: true}},
	}

	if !manager.snapshotCanUseKernelUDPTCOnlyLocked() {
		t.Fatal("tix_tcp route-GSO TC-only provider rejected plaintext route-GSO snapshot")
	}
	manager.spec.TIXTCPRouteGSOSync = false
	manager.spec.TIXTCPRouteGSOAsync = false
	if manager.snapshotCanUseKernelUDPTCOnlyLocked() {
		t.Fatal("tix_tcp snapshot used TC-only provider without route-GSO")
	}
}

func TestKernelUDPTCOnlyControlFallbackRejectsDataFrames(t *testing.T) {
	manager := &Manager{}
	ipv4 := make([]byte, 40)
	ipv4[0] = 0x45
	binary.BigEndian.PutUint16(ipv4[2:4], uint16(len(ipv4)))

	if err := manager.validateKernelUDPTCOnlyControlFallbackFramesLocked([]dataplane.KernelUDPFrame{{
		FlowID:  7,
		Payload: []byte("TrustIX control"),
	}}); err != nil {
		t.Fatalf("control frame rejected: %v", err)
	}
	if err := manager.validateKernelUDPTCOnlyControlFallbackFramesLocked([]dataplane.KernelUDPFrame{{
		FlowID:  7,
		Payload: ipv4,
	}}); err == nil {
		t.Fatal("valid IPv4 payload was accepted as TC-only control fallback")
	}
	if err := manager.validateKernelUDPTCOnlyControlFallbackFramesLocked([]dataplane.KernelUDPFrame{{
		FlowID:    7,
		InnerIPv4: true,
		Payload:   []byte("not-ip-but-flagged"),
	}}); err == nil {
		t.Fatal("InnerIPv4 flagged frame was accepted as TC-only control fallback")
	}
	if err := manager.validateKernelUDPTCOnlyControlFallbackFramesLocked([]dataplane.KernelUDPFrame{{
		FlowID:        7,
		FragmentIndex: 1,
		FragmentCount: 2,
		Payload:       []byte("fragment"),
	}}); err == nil {
		t.Fatal("fragmented frame was accepted as TC-only control fallback")
	}
}

func TestKernelUDPTCOnlyProviderRejectsSecureUserspaceCryptoSnapshot(t *testing.T) {
	manager := NewManager()
	manager.spec = dataplane.AttachSpec{
		LANIface:                    "lan0",
		UnderlayIface:               "eth0",
		KernelUDPTXDirectOnly:       true,
		KernelUDPTXDirectOnlyReason: "transport_policy.encryption=secure transport_policy.crypto_placement=kernel kernel_udp_tc_only_provider=enabled",
		KernelUDPTCOnlyProvider:     true,
	}
	manager.statsMap = &cebpf.Map{}
	manager.kernelUDPTXRouteMap = &cebpf.Map{}
	manager.kernelUDPTXFlowMap = &cebpf.Map{}
	manager.kernelUDPFlows = map[uint64]dataplane.KernelUDPFlow{
		7: {
			ID:              7,
			Peer:            "ix-b",
			Endpoint:        "remote",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
			CryptoSuite:     kernelCryptoSuiteAES128GCMX25519,
			Epoch:           3,
		},
	}
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
		Endpoints: []dataplane.EndpointMetadata{
			{ID: "local", Transport: "udp", Listen: "198.18.0.1:17041", Enabled: true, Security: dataplane.EndpointSecurityMetadata{Encryption: "secure", CryptoPlacements: []string{"userspace"}}},
			{ID: "remote", Peer: "ix-b", Transport: "udp", Address: "198.18.0.2:17041", Enabled: true, Security: dataplane.EndpointSecurityMetadata{Encryption: "secure", CryptoPlacements: []string{"userspace"}}},
		},
		Peers: []dataplane.PeerMetadata{{ID: "ix-b", Trusted: true}},
	}

	if manager.snapshotCanUseKernelUDPTCOnlyLocked() {
		t.Fatal("secure kernel_udp TC-only provider accepted userspace-crypto snapshot")
	}
}

func TestKernelUDPTCOnlyAvailableRequiresSecureDirectPrograms(t *testing.T) {
	manager := NewManager()
	manager.spec = dataplane.AttachSpec{
		LANIface:                    "lan0",
		UnderlayIface:               "eth0",
		KernelUDPTXDirectOnly:       true,
		KernelUDPTXDirectOnlyReason: "transport_policy.encryption=secure transport_policy.crypto_placement=kernel kernel_udp_tc_only_provider=enabled",
		KernelUDPTCOnlyProvider:     true,
	}
	manager.statsMap = &cebpf.Map{}
	manager.kernelUDPTXRouteMap = &cebpf.Map{}
	manager.kernelUDPTXFlowMap = &cebpf.Map{}
	manager.kernelUDPRXDirectAttached = true
	manager.underlayIngressProg = &cebpf.Program{}
	manager.kernelTransportPortMap = &cebpf.Map{}
	manager.kernelCryptoProvider = &kernelCryptoProviderObject{
		flowIndexMap:  &cebpf.Map{},
		contextSlots:  &cebpf.Map{},
		directSlotMap: &cebpf.Map{},
	}
	manager.kernelCryptoFlowMap = &cebpf.Map{}
	manager.kernelCryptoAEADCreateSuccesses = 1
	manager.kernelCryptoAEADRoundTripSuccesses = 1

	if manager.kernelUDPTCDirectOnlyAvailableLocked() {
		t.Fatal("secure TC-only provider became available without secure TX/RX programs")
	}
	manager.kernelUDPTXSecureDirectAttached = true
	if manager.kernelUDPTCDirectOnlyAvailableLocked() {
		t.Fatal("secure TC-only provider became available without secure RX program")
	}
	manager.kernelUDPRXSecureDirectAttached = true
	if !manager.kernelUDPTCDirectOnlyAvailableLocked() {
		t.Fatal("secure TC-only provider did not become available after secure TX/RX programs and TC crypto were ready")
	}
}

func TestKernelUDPTCOnlyPendingAllowsInitialPlaintextFlowInstall(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_TIX_TCP_ONLY", "0")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_ONLY", "0")
	manager := NewManager()
	underlay := testHardwareUnderlayInterface(t)
	manager.spec = dataplane.AttachSpec{
		LANIface:              "lan0",
		UnderlayIface:         underlay,
		KernelUDPTXDirectOnly: true,
	}
	manager.attached = true
	manager.statsMap = newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tconly_pending_stats", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	defer manager.statsMap.Close()
	manager.kernelUDPTXRouteMap = newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tconly_pending_route", Type: cebpf.LPMTrie, KeySize: 8, ValueSize: kernelUDPTXRouteValueSize, MaxEntries: 1, Flags: 1})
	defer manager.kernelUDPTXRouteMap.Close()
	manager.kernelUDPTXFlowMap = newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tconly_pending_flow", Type: cebpf.Hash, KeySize: 8, ValueSize: kernelUDPTXFlowValueSize, MaxEntries: 1})
	defer manager.kernelUDPTXFlowMap.Close()
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
		Routes: []routing.Route{{
			Prefix:   "10.44.0.0/16",
			NextHop:  "ix-b",
			Endpoint: "remote",
			Kind:     routing.RouteUnicast,
		}},
		Endpoints: []dataplane.EndpointMetadata{
			{ID: "local", Peer: "ix-a", Transport: "udp", Listen: "198.18.0.1:17041", Enabled: true, Security: dataplane.EndpointSecurityMetadata{Encryption: "plaintext"}},
			{ID: "remote", Peer: "ix-b", Transport: "udp", Address: "198.18.0.2:17041", Enabled: true, Security: dataplane.EndpointSecurityMetadata{Encryption: "plaintext"}},
		},
		Peers: []dataplane.PeerMetadata{{ID: "ix-b", Trusted: true}},
	}

	if !manager.kernelUDPTCDirectOnlyPendingLocked() {
		t.Fatal("pending TC-only provider was not recognized before RX direct attach")
	}
	if err := manager.InstallKernelUDPFlows(context.Background(), []dataplane.KernelUDPFlow{{
		ID:              7,
		Peer:            "ix-b",
		Endpoint:        "remote",
		RemoteAddress:   "198.18.0.2:17041",
		CryptoPlacement: dataplane.CryptoPlacementUserspace,
	}}); err != nil {
		t.Fatalf("install pending TC-only flow: %v", err)
	}
	if _, ok := manager.kernelUDPFlows[7]; !ok {
		t.Fatal("pending TC-only flow was not retained")
	}
	if manager.kernelUDPTXDirectSync.FlowsScanned == 0 {
		t.Fatalf("pending TC-only flow install did not sync TX direct state: %+v", manager.kernelUDPTXDirectSync)
	}
}

func testHardwareUnderlayInterface(t *testing.T) string {
	t.Helper()
	links, err := netlink.LinkList()
	if err != nil {
		t.Skipf("list underlay interfaces: %v", err)
	}
	for _, link := range links {
		attrs := link.Attrs()
		if attrs != nil && attrs.Name != "" && attrs.Index > 0 && len(attrs.HardwareAddr) == 6 {
			return attrs.Name
		}
	}
	t.Skip("no hardware-addressed underlay interface is available")
	return ""
}

func TestSnapshotReconcileDropsStaleKernelTransportFlows(t *testing.T) {
	manager := NewManager()
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		1: {
			ID:              1,
			Peer:            "ix-b",
			Endpoint:        "exp-b",
			RemoteAddress:   "198.18.0.2:17042",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}
	manager.tixTCPOuterTXSequences = map[uint64]uint32{1: 11}
	manager.tixTCPOuterTXAcknowledgments = map[uint64]uint32{1: 7}
	manager.tixTCPTXTemplates = map[uint64]tixTCPTXTemplate{1: {}}
	manager.tixTCPTelemetry = map[uint64]*dataplane.TransportPathTelemetry{1: {Protocol: "tix_tcp", FlowID: 1}}
	manager.kernelUDPFlows = map[uint64]dataplane.KernelUDPFlow{
		2: {
			ID:              2,
			Peer:            "ix-b",
			Endpoint:        "udp-b",
			RemoteAddress:   "198.18.0.2:17041",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
		3: {
			ID:              3,
			Peer:            "ix-b",
			Endpoint:        "old-udp-b",
			RemoteAddress:   "198.18.0.2:17043",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}
	manager.kernelUDPTXDirectSequences = map[uint64]uint64{3: 9}
	manager.kernelUDPTXTemplates = map[uint64]kernelUDPTXTemplate{3: {}}
	manager.kernelUDPTelemetry = map[uint64]*dataplane.TransportPathTelemetry{3: {Protocol: "kernel_udp", FlowID: 3}}

	snapshot := dataplane.Snapshot{
		Routes: []routing.Route{{
			Prefix:   "10.0.1.0/24",
			NextHop:  "ix-b",
			Endpoint: "udp-b",
			Kind:     routing.RouteUnicast,
		}},
		Peers: []dataplane.PeerMetadata{{ID: "ix-b", Trusted: true}},
		Endpoints: []dataplane.EndpointMetadata{
			{ID: "local-udp", Peer: "ix-a", Transport: "udp", Listen: "198.18.0.1:17041", Enabled: true},
			{ID: "udp-b", Peer: "ix-b", Transport: "udp", Address: "198.18.0.2:17041", Enabled: true},
			{ID: "exp-b", Peer: "ix-b", Transport: "tix_tcp", Address: "198.18.0.2:17042", Enabled: true},
			{ID: "old-udp-b", Peer: "ix-b", Transport: "udp", Address: "198.18.0.2:17043", Enabled: true},
		},
	}

	if !manager.reconcileKernelTransportFlowsForSnapshotLocked(snapshot) {
		t.Fatal("expected stale kernel transport flow cleanup")
	}
	if _, ok := manager.tixTCPFlows[1]; ok {
		t.Fatal("stale tix_tcp flow survived route endpoint switch")
	}
	if _, ok := manager.kernelUDPFlows[3]; ok {
		t.Fatal("stale kernel_udp flow for unselected endpoint survived")
	}
	if _, ok := manager.kernelUDPFlows[2]; !ok {
		t.Fatal("selected kernel_udp flow was removed")
	}
	if len(manager.tixTCPOuterTXSequences) != 0 || len(manager.tixTCPOuterTXAcknowledgments) != 0 || len(manager.tixTCPTXTemplates) != 0 || len(manager.tixTCPTelemetry) != 0 {
		t.Fatal("stale tix_tcp auxiliary state was not cleaned")
	}
	if _, ok := manager.kernelUDPTXDirectSequences[3]; ok {
		t.Fatal("stale kernel_udp TX direct sequence was not cleaned")
	}
	if _, ok := manager.kernelUDPTXTemplates[3]; ok {
		t.Fatal("stale kernel_udp TX template was not cleaned")
	}
	if _, ok := manager.kernelUDPTelemetry[3]; ok {
		t.Fatal("stale kernel_udp telemetry was not cleaned")
	}
}

func TestKernelUDPTCOnlyFallbackCanBeDisabled(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY_FALLBACK", "")
	manager := NewManager()
	manager.spec = dataplane.AttachSpec{
		LANIface:              "lan0",
		UnderlayIface:         "eth0",
		KernelUDPTXDirectOnly: true,
	}
	manager.attached = true
	manager.statsMap = newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tconly_stats_fallback", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	defer manager.statsMap.Close()
	manager.kernelUDPTXRouteMap = newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tconly_route_fallback", Type: cebpf.LPMTrie, KeySize: 8, ValueSize: kernelUDPTXRouteValueSize, MaxEntries: 1, Flags: 1})
	defer manager.kernelUDPTXRouteMap.Close()
	manager.kernelUDPTXFlowMap = newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tconly_flow_fallback", Type: cebpf.Hash, KeySize: 8, ValueSize: kernelUDPTXFlowValueSize, MaxEntries: 1})
	defer manager.kernelUDPTXFlowMap.Close()
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
		Endpoints: []dataplane.EndpointMetadata{
			{ID: "local", Peer: "ix-a", Transport: "udp", Listen: "198.18.0.1:17041", Enabled: true, Security: dataplane.EndpointSecurityMetadata{Encryption: "plaintext"}},
		},
	}

	if !manager.snapshotCanFallbackToKernelUDPTCOnlyLocked() {
		t.Fatal("kernel_udp TC-only fallback should be enabled by default")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY_FALLBACK", "0")
	if manager.snapshotCanFallbackToKernelUDPTCOnlyLocked() {
		t.Fatal("kernel_udp TC-only fallback ignored explicit disable")
	}
}

func TestKernelUDPSecureDirectRequestedForSecureDirectOnlySpec(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_KERNEL_CRYPTO_DIRECT", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "")

	secureSpec := dataplane.AttachSpec{
		KernelUDPTXDirectOnly:       true,
		KernelUDPTXDirectOnlyReason: "transport_policy.encryption=secure transport_policy.crypto_placement=kernel",
	}
	if !kernelUDPTXSecureDirectRequestedForSpec(secureSpec) {
		t.Fatal("secure direct-only spec should request TX secure direct")
	}
	manager := NewManager()
	manager.spec = secureSpec
	if manager.kernelUDPRXSecureDirectRequestedLocked() {
		t.Fatal("secure direct-only spec should not implicitly request RX secure direct")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT", "1")
	if !manager.kernelUDPRXSecureDirectRequestedLocked() {
		t.Fatal("explicit RX secure direct opt-in should request RX secure direct")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT", "")

	profileSpec := dataplane.AttachSpec{
		KernelUDPTXSecureDirect:                  true,
		KernelUDPRXSecureDirect:                  true,
		KernelUDPSecureDirectTrustInnerChecksums: true,
		KernelUDPTXSecureDirectKfuncSeal:         true,
	}
	if !kernelUDPTXSecureDirectRequestedForSpec(profileSpec) {
		t.Fatal("profile secure direct spec should request TX secure direct")
	}
	manager.spec = profileSpec
	if !manager.kernelUDPRXSecureDirectRequestedLocked() {
		t.Fatal("profile secure direct spec should request RX secure direct")
	}
	if !kernelUDPTXSecureDirectTrustInnerChecksumsForSpec(profileSpec) {
		t.Fatal("profile secure direct spec should trust inner checksums")
	}
	options := kernelUDPTXSecureDirectProgramOptionsForSpec(profileSpec)
	if !options.KfuncSeal || options.SKBSealKfunc {
		t.Fatalf("profile secure direct TX options = %#v, want direct seal enabled and verifier-unsafe skb seal disabled", options)
	}

	plaintextSpec := dataplane.AttachSpec{
		KernelUDPTXDirectOnly:       true,
		KernelUDPTXDirectOnlyReason: "transport_policy.encryption=plaintext",
	}
	if kernelUDPTXSecureDirectRequestedForSpec(plaintextSpec) {
		t.Fatal("plaintext direct-only spec should not request secure direct")
	}

	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "0")
	if kernelUDPTXSecureDirectRequestedForSpec(secureSpec) {
		t.Fatal("explicit direct-only disable should suppress secure direct auto request")
	}
}

func TestSyncKernelUDPTXDirectSkipsMapsWhenProgramDisabled(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp TX route map test requires Linux")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT", "0")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_ONLY", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "")
	t.Setenv("TRUSTIX_REMOTE_TIX_TCP_TC_TX_DIRECT", "")
	t.Setenv("TRUSTIX_E2E_TIX_TCP_TC_TX_DIRECT", "")
	t.Setenv("TRUSTIX_IPERF3_CRYPTO_BENCH_TIX_TCP_TC_TX_DIRECT", "")
	routeMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_disabled_route_test", Type: cebpf.LPMTrie, KeySize: 8, ValueSize: kernelUDPTXRouteValueSize, MaxEntries: 16, Flags: 1})
	defer routeMap.Close()
	flowMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_disabled_flow_test", Type: cebpf.Hash, KeySize: 8, ValueSize: kernelUDPTXFlowValueSize, MaxEntries: 16})
	defer flowMap.Close()
	manager := NewManager()
	manager.kernelUDPTXRouteMap = routeMap
	manager.kernelUDPTXFlowMap = flowMap
	manager.spec = dataplane.AttachSpec{UnderlayIface: "does-not-matter"}
	manager.snapshot = dataplane.Snapshot{
		Routes: []routing.Route{{Prefix: "10.44.0.0/16", NextHop: "ix-b", Endpoint: "ix-b-tixt"}},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		21: {ID: 21, Peer: "ix-b", Endpoint: "ix-b-tixt", LocalAddress: "192.0.2.1:42021", RemoteAddress: "198.51.100.21:18001", CryptoPlacement: dataplane.CryptoPlacementUserspace},
	}

	if err := manager.syncKernelUDPTXDirectLocked(); err != nil {
		t.Fatalf("sync disabled direct: %v", err)
	}
	if manager.kernelUDPTXDirectSync.SkippedDisabled == 0 {
		t.Fatal("disabled direct sync did not record skipped-disabled")
	}
	var value kernelUDPTXRouteValue
	key := routeKey{PrefixLen: 32, Addr: netip.MustParseAddr("10.44.1.2").As4()}
	if err := routeMap.Lookup(key, &value); !errors.Is(err, cebpf.ErrKeyNotExist) {
		t.Fatalf("disabled direct route lookup error = %v value=%#v, want key not exist", err, value)
	}
}

func TestSyncKernelUDPTXDirectFlowValuePreservesLiveSequenceWhenConfigUnchanged(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp TX flow map test requires Linux")
	}
	flowMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_flow_preserve_sequence", Type: cebpf.Hash, KeySize: 8, ValueSize: kernelUDPTXFlowValueSize, MaxEntries: 16})
	defer flowMap.Close()
	manager := NewManager()
	manager.kernelUDPTXFlowMap = flowMap
	manager.kernelUDPTXDirectSequences = map[uint64]uint64{7: 10}
	current := kernelUDPTXFlowValue{
		Sequence:        100,
		SourceIP:        [4]byte{192, 0, 2, 1},
		DestinationIP:   [4]byte{198, 51, 100, 2},
		SourcePort:      htons(41001),
		DestinationPort: htons(17001),
		Ifindex:         2,
		DestinationMAC0: 0x04030201,
		DestinationMAC1: 0x0605,
		SourceMAC0:      0x0a090807,
		SourceMAC1:      0x0c0b,
		IPv4ChecksumUDP: 0x1111,
		IPv4ChecksumTCP: 0x2222,
		MTU:             1500,
		Flags:           kernelUDPTXFlowFlagSecure,
	}
	if err := flowMap.Update(uint64(7), current, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed flow map: %v", err)
	}
	desired := current
	desired.Sequence = 10

	got, wrote, err := manager.syncKernelUDPTXDirectFlowValueLocked(7, desired)
	if err != nil {
		t.Fatalf("sync unchanged flow: %v", err)
	}
	if wrote {
		t.Fatal("unchanged kernel_udp TX flow was rewritten")
	}
	if got.Sequence != current.Sequence {
		t.Fatalf("returned sequence = %d, want live sequence %d", got.Sequence, current.Sequence)
	}
	var stored kernelUDPTXFlowValue
	if err := flowMap.Lookup(uint64(7), &stored); err != nil {
		t.Fatalf("lookup flow: %v", err)
	}
	if stored.Sequence != current.Sequence {
		t.Fatalf("stored sequence = %d, want %d", stored.Sequence, current.Sequence)
	}
	if manager.kernelUDPTXDirectSequences[7] != current.Sequence {
		t.Fatalf("remembered sequence = %d, want %d", manager.kernelUDPTXDirectSequences[7], current.Sequence)
	}
}

func TestSyncKernelUDPTXDirectFlowValueGuardsSequenceWhenConfigChanges(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp TX flow map test requires Linux")
	}
	flowMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_flow_guard_sequence", Type: cebpf.Hash, KeySize: 8, ValueSize: kernelUDPTXFlowValueSize, MaxEntries: 16})
	defer flowMap.Close()
	manager := NewManager()
	manager.kernelUDPTXFlowMap = flowMap
	current := kernelUDPTXFlowValue{
		Sequence:        100,
		SourceIP:        [4]byte{192, 0, 2, 1},
		DestinationIP:   [4]byte{198, 51, 100, 2},
		SourcePort:      htons(41001),
		DestinationPort: htons(17001),
		Ifindex:         2,
		DestinationMAC0: 0x04030201,
		DestinationMAC1: 0x0605,
		SourceMAC0:      0x0a090807,
		SourceMAC1:      0x0c0b,
		IPv4ChecksumUDP: 0x1111,
		IPv4ChecksumTCP: 0x2222,
		MTU:             1500,
		Flags:           kernelUDPTXFlowFlagSecure,
	}
	if err := flowMap.Update(uint64(7), current, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed flow map: %v", err)
	}
	desired := current
	desired.Sequence = 1
	desired.DestinationMAC1 = 0x0e0d

	got, wrote, err := manager.syncKernelUDPTXDirectFlowValueLocked(7, desired)
	if err != nil {
		t.Fatalf("sync changed flow: %v", err)
	}
	if !wrote {
		t.Fatal("changed kernel_udp TX flow was not rewritten")
	}
	wantSequence := current.Sequence + kernelUDPTXDirectSequenceUpdateGuard
	if got.Sequence != wantSequence {
		t.Fatalf("guarded sequence = %d, want %d", got.Sequence, wantSequence)
	}
	var stored kernelUDPTXFlowValue
	if err := flowMap.Lookup(uint64(7), &stored); err != nil {
		t.Fatalf("lookup flow: %v", err)
	}
	if stored.Sequence != wantSequence || stored.DestinationMAC1 != desired.DestinationMAC1 {
		t.Fatalf("stored flow = %+v, want sequence %d destination mac1 %#x", stored, wantSequence, desired.DestinationMAC1)
	}
}

func TestReserveKernelUDPTXSequenceGuardsConcurrentKernelUpdates(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp TX flow map test requires Linux")
	}
	flowMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_sequence_guard", Type: cebpf.Hash, KeySize: 8, ValueSize: kernelUDPTXFlowValueSize, MaxEntries: 16})
	defer flowMap.Close()
	manager := NewManager()
	manager.kernelUDPTXFlowMap = flowMap
	const flowID = uint64(7)
	seed := kernelUDPTXFlowValue{Sequence: 100}
	if err := flowMap.Update(flowID, seed, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed flow map: %v", err)
	}

	first, err := manager.reserveKernelUDPTXSequenceLocked(flowID, 1)
	if err != nil {
		t.Fatalf("reserve first userspace sequence: %v", err)
	}
	wantFirst := kernelUDPTXDirectSequenceWithUpdateGuard(seed.Sequence)
	if first != wantFirst {
		t.Fatalf("first sequence = %d, want guarded sequence %d", first, wantFirst)
	}
	if manager.kernelUDPTXSequenceGuardUpdates != 1 {
		t.Fatalf("sequence guard updates after first reserve = %d, want 1", manager.kernelUDPTXSequenceGuardUpdates)
	}
	second, err := manager.reserveKernelUDPTXSequenceLocked(flowID, first+1)
	if err != nil {
		t.Fatalf("reserve second userspace sequence: %v", err)
	}
	wantSecond := kernelUDPTXDirectSequenceWithUpdateGuard(first)
	if second != wantSecond {
		t.Fatalf("second sequence = %d, want guarded sequence %d", second, wantSecond)
	}
	if manager.kernelUDPTXSequenceGuardUpdates != 2 {
		t.Fatalf("sequence guard updates after second reserve = %d, want 2", manager.kernelUDPTXSequenceGuardUpdates)
	}
	var stored kernelUDPTXFlowValue
	if err := flowMap.Lookup(flowID, &stored); err != nil {
		t.Fatalf("lookup guarded flow: %v", err)
	}
	if stored.Sequence != wantSecond || manager.kernelUDPTXDirectSequences[flowID] != wantSecond {
		t.Fatalf("stored/remembered sequence = %d/%d, want %d", stored.Sequence, manager.kernelUDPTXDirectSequences[flowID], wantSecond)
	}
}

func TestReserveKernelUDPTXSequenceBatchGuardsMapOnce(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp TX flow map test requires Linux")
	}
	flowMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_batch_guard", Type: cebpf.Hash, KeySize: 8, ValueSize: kernelUDPTXFlowValueSize, MaxEntries: 16})
	defer flowMap.Close()
	manager := NewManager()
	manager.kernelUDPTXFlowMap = flowMap
	const flowID = uint64(9)
	seed := kernelUDPTXFlowValue{Sequence: 250}
	if err := flowMap.Update(flowID, seed, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed flow map: %v", err)
	}

	var pendingByFlow map[uint64]*kernelUDPTXSequenceBatch
	var singleFlowID uint64
	var single *kernelUDPTXSequenceBatch
	first, err := manager.reserveKernelUDPTXSequenceBatchLocked(&pendingByFlow, &singleFlowID, &single, flowID, 1, 8)
	if err != nil {
		t.Fatalf("reserve first batched userspace sequence: %v", err)
	}
	wantFirst := kernelUDPTXDirectSequenceWithUpdateGuard(seed.Sequence)
	if first != wantFirst {
		t.Fatalf("first batched sequence = %d, want guarded sequence %d", first, wantFirst)
	}
	second, err := manager.reserveKernelUDPTXSequenceBatchLocked(&pendingByFlow, &singleFlowID, &single, flowID, first+1, 8)
	if err != nil {
		t.Fatalf("reserve second batched userspace sequence: %v", err)
	}
	if second != first+1 {
		t.Fatalf("second batched sequence = %d, want contiguous sequence %d", second, first+1)
	}
	if manager.kernelUDPTXSequenceGuardUpdates != 1 {
		t.Fatalf("batched sequence guard updates = %d, want 1", manager.kernelUDPTXSequenceGuardUpdates)
	}
	var stored kernelUDPTXFlowValue
	if err := flowMap.Lookup(flowID, &stored); err != nil {
		t.Fatalf("lookup flow before batch flush: %v", err)
	}
	if stored.Sequence != seed.Sequence {
		t.Fatalf("sequence before batch flush = %d, want %d", stored.Sequence, seed.Sequence)
	}
	if err := manager.flushKernelUDPTXSequenceBatchesLocked(pendingByFlow, single); err != nil {
		t.Fatalf("flush batched userspace sequences: %v", err)
	}
	if err := flowMap.Lookup(flowID, &stored); err != nil {
		t.Fatalf("lookup flow after batch flush: %v", err)
	}
	if stored.Sequence != second || manager.kernelUDPTXDirectSequences[flowID] != second {
		t.Fatalf("stored/remembered batch sequence = %d/%d, want %d", stored.Sequence, manager.kernelUDPTXDirectSequences[flowID], second)
	}
}

func TestKernelUDPTXDirectAppendCanBeDisabled(t *testing.T) {
	statsMap := &cebpf.Map{}
	routeMap := &cebpf.Map{}
	flowMap := &cebpf.Map{}
	in := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}
	out := appendKernelUDPTXDirect(append(asm.Instructions(nil), in...), statsMap, routeMap, flowMap, kernelUDPTXDirectProgramOptions{})
	if len(out) != len(in) {
		t.Fatalf("disabled direct append emitted %d instructions, want %d", len(out), len(in))
	}
}

func TestPacketPolicyReadsGSOSizeForMTUCheck(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("packet policy BPF instruction test requires Linux maps")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF map test: %v", err)
	}
	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_packet_policy_gso_stats_test", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	defer statsMap.Close()
	packetPolicyMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_packet_policy_gso_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 8, MaxEntries: 16})
	defer packetPolicyMap.Close()
	out := appendPacketPolicy(nil, statsMap, packetPolicyMap)
	if !instructionsContainLoadMem(out, asm.R6, skbGSOSizeOffset, asm.Word) {
		t.Fatalf("packet policy does not read skb gso_size offset %d", skbGSOSizeOffset)
	}
}

func TestPacketPolicyBypassesTCPMTUDropForUserspaceSegmentation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("packet policy BPF instruction test requires Linux maps")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF map test: %v", err)
	}
	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_packet_policy_tcp_seg_stats_test", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	defer statsMap.Close()
	packetPolicyMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_packet_policy_tcp_seg_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 8, MaxEntries: 16})
	defer packetPolicyMap.Close()
	out := appendPacketPolicy(nil, statsMap, packetPolicyMap)
	if !instructionsContainImmJumpTo(out, ipProtocolTCP, "packet_policy_fragment_check") {
		t.Fatal("packet policy does not bypass MTU drop for TCP packets before userspace segmentation")
	}
}

func instructionsContainLoadMem(instructions asm.Instructions, src asm.Register, offset int16, size asm.Size) bool {
	return instructionsCountLoadMem(instructions, src, offset, size) > 0
}

func instructionsContainLoadMemInto(instructions asm.Instructions, dst asm.Register, src asm.Register, offset int16, size asm.Size) bool {
	for _, ins := range instructions {
		if ins.OpCode.Class().IsLoad() &&
			ins.OpCode.Mode() == asm.MemMode &&
			ins.Dst == dst &&
			ins.Src == src &&
			ins.Offset == offset &&
			ins.OpCode.Size() == size {
			return true
		}
	}
	return false
}

func instructionsCountLoadMem(instructions asm.Instructions, src asm.Register, offset int16, size asm.Size) int {
	count := 0
	for _, ins := range instructions {
		if ins.OpCode.Class().IsLoad() &&
			ins.OpCode.Mode() == asm.MemMode &&
			ins.Src == src &&
			ins.Offset == offset &&
			ins.OpCode.Size() == size {
			count++
		}
	}
	return count
}

func instructionsContainStoreMem(instructions asm.Instructions, dst asm.Register, offset int16, size asm.Size) bool {
	for _, ins := range instructions {
		if ins.OpCode.Class().IsStore() &&
			ins.OpCode.Mode() == asm.MemMode &&
			ins.Dst == dst &&
			ins.Offset == offset &&
			ins.OpCode.Size() == size {
			return true
		}
	}
	return false
}

func instructionsContainStoreImm(instructions asm.Instructions, dst asm.Register, offset int16, size asm.Size, value int64) bool {
	for _, ins := range instructions {
		if ins.OpCode.Class().IsStore() &&
			ins.OpCode.Mode() == asm.MemMode &&
			ins.Dst == dst &&
			ins.Offset == offset &&
			ins.OpCode.Size() == size &&
			ins.Constant == value {
			return true
		}
	}
	return false
}

func instructionsContainFetchAddAt(instructions asm.Instructions, dst asm.Register, src asm.Register) bool {
	for _, ins := range instructions {
		if ins.OpCode.Class() == asm.StXClass &&
			ins.OpCode.Mode() == asm.AtomicMode &&
			ins.OpCode.AtomicOp() == asm.FetchAdd &&
			ins.Dst == dst &&
			ins.Src == src {
			return true
		}
	}
	return false
}

func instructionsContainImm(instructions asm.Instructions, value int64) bool {
	for _, ins := range instructions {
		if ins.Constant == value {
			return true
		}
	}
	return false
}

func instructionsContainMovImmToRegAfterSymbol(instructions asm.Instructions, symbol string, dst asm.Register, value int64) bool {
	for i, ins := range instructions {
		if ins.Symbol() != symbol {
			continue
		}
		for _, candidate := range instructions[i+1:] {
			if candidate.Symbol() != "" && candidate.Symbol() != symbol {
				break
			}
			if candidate.OpCode.Class().IsALU() &&
				candidate.OpCode.ALUOp() == asm.Mov &&
				candidate.Dst == dst &&
				candidate.Constant == value {
				return true
			}
		}
	}
	return false
}

func instructionsContainImmJumpTo(instructions asm.Instructions, value int64, to string) bool {
	for _, ins := range instructions {
		if ins.Constant == value && ins.Reference() == to {
			return true
		}
	}
	return false
}

func instructionsContainSymbol(instructions asm.Instructions, symbol string) bool {
	for _, ins := range instructions {
		if ins.Symbol() == symbol {
			return true
		}
	}
	return false
}

func instructionsContainReference(instructions asm.Instructions, reference string) bool {
	for _, ins := range instructions {
		if ins.Reference() == reference {
			return true
		}
	}
	return false
}

func instructionsContainReferenceAfterSymbol(instructions asm.Instructions, symbol string, reference string, limit int) bool {
	start := instructionSymbolIndex(instructions, symbol)
	if start < 0 {
		return false
	}
	end := len(instructions)
	if limit > 0 && start+limit+1 < end {
		end = start + limit + 1
	}
	for _, ins := range instructions[start+1 : end] {
		if ins.Reference() == reference {
			return true
		}
	}
	return false
}

func instructionSymbolIndex(instructions asm.Instructions, symbol string) int {
	for i, ins := range instructions {
		if ins.Symbol() == symbol {
			return i
		}
	}
	return -1
}

func instructionBuiltinCallIndex(instructions asm.Instructions, fn asm.BuiltinFunc) int {
	for i, ins := range instructions {
		if ins.IsBuiltinCall() && ins.Constant == int64(fn) {
			return i
		}
	}
	return -1
}

func duplicateInstructionSymbols(instructions asm.Instructions) []string {
	counts := make(map[string]int)
	for _, ins := range instructions {
		if symbol := ins.Symbol(); symbol != "" {
			counts[symbol]++
		}
	}
	var duplicates []string
	for symbol, count := range counts {
		if count > 1 {
			duplicates = append(duplicates, symbol)
		}
	}
	sort.Strings(duplicates)
	return duplicates
}

func unreachableInstructionIndexes(instructions asm.Instructions) []int {
	if len(instructions) == 0 {
		return nil
	}
	labels := make(map[string]int)
	for i, ins := range instructions {
		if symbol := ins.Symbol(); symbol != "" {
			labels[symbol] = i
		}
	}
	reachable := make([]bool, len(instructions))
	stack := []int{0}
	push := func(index int) {
		if index >= 0 && index < len(instructions) && !reachable[index] {
			stack = append(stack, index)
		}
	}
	pushRef := func(current int, ref string) {
		if ref == "" {
			push(current + 1 + int(instructions[current].Offset))
			return
		}
		if target, ok := labels[ref]; ok {
			push(target)
		}
	}
	for len(stack) > 0 {
		index := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if index < 0 || index >= len(instructions) || reachable[index] {
			continue
		}
		reachable[index] = true
		ins := instructions[index]
		class := ins.OpCode.Class()
		if class != asm.JumpClass && class != asm.Jump32Class {
			push(index + 1)
			continue
		}
		switch ins.OpCode.JumpOp() {
		case asm.Exit:
			continue
		case asm.Call:
			push(index + 1)
		case asm.Ja:
			pushRef(index, ins.Reference())
		default:
			pushRef(index, ins.Reference())
			push(index + 1)
		}
	}
	var unreachable []int
	for i := range instructions {
		if !reachable[i] {
			unreachable = append(unreachable, i)
		}
	}
	return unreachable
}

func describeInstructionIndexes(instructions asm.Instructions, indexes []int, limit int) string {
	if len(indexes) == 0 {
		return ""
	}
	if limit <= 0 || limit > len(indexes) {
		limit = len(indexes)
	}
	parts := make([]string, 0, limit+1)
	for _, index := range indexes[:limit] {
		if index < 0 || index >= len(instructions) {
			parts = append(parts, fmt.Sprintf("%d:<out-of-range>", index))
			continue
		}
		ins := instructions[index]
		parts = append(parts, fmt.Sprintf("%d:%s sym=%q ref=%q", index, ins.OpCode, ins.Symbol(), ins.Reference()))
	}
	if len(indexes) > limit {
		parts = append(parts, fmt.Sprintf("... %d more", len(indexes)-limit))
	}
	return strings.Join(parts, "; ")
}

func instructionsContainKfuncCall(instructions asm.Instructions) bool {
	for _, ins := range instructions {
		if ins.IsKfuncCall() {
			return true
		}
	}
	return false
}

func instructionsLoadPacketHalfWithNetworkConversion(instructions asm.Instructions, offset int16, dst asm.Register) bool {
	for i, ins := range instructions {
		if ins.OpCode != asm.LoadMemOp(asm.Half) || ins.Dst != dst || ins.Src != asm.R7 || ins.Offset != offset {
			continue
		}
		for j := i + 1; j < len(instructions) && j-i <= 3; j++ {
			candidate := instructions[j]
			if candidate.OpCode.Class() == asm.ALUClass &&
				candidate.OpCode.ALUOp() == asm.Swap &&
				candidate.OpCode.Endianness() == asm.BE &&
				candidate.Constant == 16 &&
				candidate.Dst == dst {
				return true
			}
		}
	}
	return false
}

func instructionsLoadStackHalf(instructions asm.Instructions, offset int16, dst asm.Register) bool {
	for _, ins := range instructions {
		if ins.OpCode == asm.LoadMemOp(asm.Half) && ins.Dst == dst && ins.Src == asm.RFP && ins.Offset == offset {
			return true
		}
	}
	return false
}

func instructionsStorePacketNetworkHalfFromR0(instructions asm.Instructions, offset int16) bool {
	for i, ins := range instructions {
		if ins.OpCode != asm.StoreMemOp(asm.Half) || ins.Dst != asm.R7 || ins.Src != asm.R0 || ins.Offset != offset {
			continue
		}
		for j := i - 1; j >= 0 && i-j <= 3; j-- {
			candidate := instructions[j]
			if candidate.OpCode.Class() == asm.ALUClass &&
				candidate.OpCode.ALUOp() == asm.Swap &&
				candidate.OpCode.Endianness() == asm.BE &&
				candidate.Constant == 16 &&
				candidate.Dst == asm.R0 {
				return true
			}
		}
	}
	return false
}

func instructionsStorePacketHalfFromR0(instructions asm.Instructions, offset int16) bool {
	for _, ins := range instructions {
		if ins.OpCode == asm.StoreMemOp(asm.Half) && ins.Dst == asm.R7 && ins.Src == asm.R0 && ins.Offset == offset {
			return true
		}
	}
	return false
}

func instructionsStoreStackHalfFromR0(instructions asm.Instructions, offset int16) bool {
	for _, ins := range instructions {
		if ins.OpCode == asm.StoreMemOp(asm.Half) && ins.Dst == asm.RFP && ins.Src == asm.R0 && ins.Offset == offset {
			return true
		}
	}
	return false
}

func instructionsSwapR0ImmediatelyBeforePacketStore(instructions asm.Instructions, offset int16) bool {
	for i, ins := range instructions {
		if ins.OpCode != asm.StoreMemOp(asm.Half) || ins.Dst != asm.R7 || ins.Src != asm.R0 || ins.Offset != offset || i == 0 {
			continue
		}
		prior := instructions[i-1]
		return prior.OpCode.Class() == asm.ALUClass &&
			prior.OpCode.ALUOp() == asm.Swap &&
			prior.OpCode.Endianness() == asm.BE &&
			prior.Constant == 16 &&
			prior.Dst == asm.R0
	}
	return false
}

func instructionsSwapR0ImmediatelyBeforeStackStore(instructions asm.Instructions, offset int16) bool {
	for i, ins := range instructions {
		if ins.OpCode != asm.StoreMemOp(asm.Half) || ins.Dst != asm.RFP || ins.Src != asm.R0 || ins.Offset != offset || i == 0 {
			continue
		}
		prior := instructions[i-1]
		return prior.OpCode.Class() == asm.ALUClass &&
			prior.OpCode.ALUOp() == asm.Swap &&
			prior.OpCode.Endianness() == asm.BE &&
			prior.Constant == 16 &&
			prior.Dst == asm.R0
	}
	return false
}

func instructionsStoreNetworkHalfBeforeSymbol(instructions asm.Instructions, offset int16, symbol string) bool {
	for i, ins := range instructions {
		if ins.Symbol() == symbol {
			return false
		}
		if ins.OpCode != asm.StoreMemOp(asm.Half) || ins.Dst != asm.RFP || ins.Src != asm.R0 || ins.Offset != offset {
			continue
		}
		for j := i - 1; j >= 0 && i-j <= 3; j-- {
			candidate := instructions[j]
			if candidate.OpCode.Class() == asm.ALUClass &&
				candidate.OpCode.ALUOp() == asm.Swap &&
				candidate.OpCode.Endianness() == asm.BE &&
				candidate.Constant == 16 &&
				candidate.Dst == asm.R0 {
				return true
			}
		}
	}
	return false
}

func instructionsCountBuiltinCalls(instructions asm.Instructions, fn asm.BuiltinFunc) int {
	count := 0
	for _, ins := range instructions {
		if ins.IsBuiltinCall() && ins.Constant == int64(fn) {
			count++
		}
	}
	return count
}

func instructionsContainCallWithImmediateR4(instructions asm.Instructions, fn asm.BuiltinFunc, value int32) bool {
	for i, ins := range instructions {
		if !ins.IsBuiltinCall() || ins.Constant != int64(fn) {
			continue
		}
		for j := i - 1; j >= 0 && i-j <= 8; j-- {
			candidate := instructions[j]
			if candidate.OpCode.Class().IsALU() &&
				candidate.OpCode.ALUOp() == asm.Mov &&
				candidate.Dst == asm.R4 &&
				candidate.Src == asm.R0 &&
				candidate.Constant == int64(value) {
				return true
			}
		}
	}
	return false
}

func instructionsContainJump(instructions asm.Instructions, from string, to string) bool {
	for i, ins := range instructions {
		if ins.Symbol() != from {
			continue
		}
		for _, candidate := range instructions[i+1:] {
			if candidate.Reference() == to {
				return true
			}
			if candidate.Symbol() != "" && candidate.Symbol() != from {
				break
			}
		}
	}
	return false
}

func instructionsJumpBeforeLoadMem(instructions asm.Instructions, from string, to string, src asm.Register, offset int16, size asm.Size) bool {
	start := instructionSymbolIndex(instructions, from)
	if start < 0 {
		return false
	}
	for _, ins := range instructions[start:] {
		if ins.OpCode.Class().IsLoad() &&
			ins.OpCode.Mode() == asm.MemMode &&
			ins.Src == src &&
			ins.Offset == offset &&
			ins.OpCode.Size() == size {
			return false
		}
		if ins.Reference() == to {
			return true
		}
	}
	return false
}

func instructionsContainReturnBeforeSymbol(instructions asm.Instructions, symbol string) bool {
	for i, ins := range instructions {
		if ins.Symbol() != symbol {
			continue
		}
		for _, prior := range instructions[:i] {
			if prior.OpCode.Class() == asm.JumpClass && prior.OpCode.JumpOp() == asm.Exit {
				return true
			}
		}
		return false
	}
	return false
}

func instructionsContainReachableSymbol(instructions asm.Instructions, symbol string) bool {
	unreachable := make(map[int]struct{})
	for _, index := range unreachableInstructionIndexes(instructions) {
		unreachable[index] = struct{}{}
	}
	for i, ins := range instructions {
		if ins.Symbol() != symbol {
			continue
		}
		if _, ok := unreachable[i]; !ok {
			return true
		}
	}
	return false
}

func instructionsRouteTCPKfuncUsesCurrentRoutePtr(instructions asm.Instructions) bool {
	for i, ins := range instructions {
		if ins.Symbol() != "kudp_tx_direct_route_tcp_kfunc" {
			continue
		}
		if i < 2 {
			return false
		}
		prior := instructions[i-1]
		if !(prior.OpCode.Class().IsALU() &&
			prior.OpCode.ALUOp() == asm.Mov &&
			prior.Dst == asm.R2 &&
			prior.Src == asm.R0) {
			return false
		}
		for j := i - 2; j >= 0 && i-j <= 8; j-- {
			candidate := instructions[j]
			if candidate.OpCode.Class().IsLoad() &&
				candidate.OpCode.Mode() == asm.MemMode &&
				candidate.Dst == asm.R0 &&
				candidate.Src == asm.RFP &&
				candidate.Offset == kernelUDPTXRoutePtrOffset &&
				candidate.OpCode.Size() == asm.DWord {
				return true
			}
			if candidate.OpCode.Class().IsLoad() && candidate.Dst == asm.R0 ||
				candidate.OpCode.Class().IsALU() && candidate.Dst == asm.R0 ||
				candidate.IsBuiltinCall() {
				return false
			}
		}
		return false
	}
	return false
}

func instructionsStoreImmNearSymbol(instructions asm.Instructions, symbol string, offset int16, imm int64, limit int) bool {
	for i, ins := range instructions {
		if ins.Symbol() != symbol {
			continue
		}
		start := i - limit
		if start < 0 {
			start = 0
		}
		end := i + limit
		if end >= len(instructions) {
			end = len(instructions) - 1
		}
		for j := start; j <= end; j++ {
			candidate := instructions[j]
			if candidate.OpCode.Class().IsStore() &&
				candidate.OpCode.Mode() == asm.MemMode &&
				candidate.OpCode.Size() == asm.Word &&
				candidate.Dst == asm.RFP &&
				candidate.Offset == offset &&
				candidate.Constant == imm {
				return true
			}
		}
		return false
	}
	return false
}

func TestTIXTCPTXDirectPlaintextFlowsDoNotRequireSkipChecksum(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        core.EndpointID("ix-b-tixt"),
			Peer:      core.IXID("ix-b"),
			Transport: "tix_tcp",
			Enabled:   true,
			Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
		}},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		21: {
			ID:              21,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:42021",
			RemoteAddress:   "198.51.100.21:18001",
			CryptoPlacement: dataplane.CryptoPlacementUserspace,
		},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.44.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-tixt"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, false, kernelUDPTXRouteMaxFlows)
	if len(flows) != 1 {
		t.Fatalf("matched tix_tcp flows without skip checksum = %d, want 1: %+v", len(flows), flows)
	}
	if flows[0].id != 21 || !flows[0].tixTCP {
		t.Fatalf("matched flow = %+v, want tix_tcp flow 21", flows[0])
	}
}

func TestTIXTCPTXDirectSecureFlowsDoNotRequireSkipChecksum(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	manager := NewManager()
	manager.kernelUDPTXSecureDirectAttached = true
	manager.snapshot = dataplane.Snapshot{
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        core.EndpointID("ix-b-tixt"),
			Peer:      core.IXID("ix-b"),
			Transport: "tix_tcp",
			Enabled:   true,
			Security:  dataplane.EndpointSecurityMetadata{Encryption: "secure"},
		}},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		21: {
			ID:              21,
			Peer:            core.IXID("ix-b"),
			Endpoint:        core.EndpointID("ix-b-tixt"),
			LocalAddress:    "192.0.2.1:42021",
			RemoteAddress:   "198.51.100.21:18001",
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		},
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.44.0.0/16"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ix-b-tixt"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, true, kernelUDPTXRouteMaxFlows)
	if len(flows) != 1 {
		t.Fatalf("matched secure tix_tcp flows without skip checksum = %d, want 1: %+v", len(flows), flows)
	}
	if flows[0].id != 21 || !flows[0].tixTCP {
		t.Fatalf("matched flow = %+v, want secure tix_tcp flow 21", flows[0])
	}
}

func TestDecodeCaptureEventPreservesFourKiBTCPPayloadSample(t *testing.T) {
	const tcpPayloadLen = 4096
	const ethernetIPv4TCPHeaderLen = 14 + 20 + 20
	sampleLen := uint32(tcpPayloadLen + ethernetIPv4TCPHeaderLen)
	if captureSampleLimit < int(sampleLen) {
		t.Fatalf("captureSampleLimit = %d, want at least %d for 4KiB TCP payload samples", captureSampleLimit, sampleLen)
	}

	raw := make([]byte, captureEventHeader+int(sampleLen))
	binary.LittleEndian.PutUint32(raw[0:4], captureMagic)
	binary.LittleEndian.PutUint32(raw[4:8], 1)
	binary.LittleEndian.PutUint32(raw[8:12], 1)
	binary.LittleEndian.PutUint32(raw[12:16], sampleLen)
	binary.LittleEndian.PutUint32(raw[16:20], sampleLen)
	copy(raw[20:24], []byte{10, 0, 0, 2})
	copy(raw[24:28], []byte{10, 0, 1, 2})

	event, ok := decodeCaptureEvent(perf.Record{RawSample: raw})
	if !ok {
		t.Fatal("decodeCaptureEvent rejected valid large capture sample")
	}
	if event.PacketLength != sampleLen || event.SampleLength != sampleLen {
		t.Fatalf("capture lengths = packet:%d sample:%d, want %d/%d", event.PacketLength, event.SampleLength, sampleLen, sampleLen)
	}
	if len(event.Payload) != int(sampleLen) {
		t.Fatalf("payload length = %d, want %d", len(event.Payload), sampleLen)
	}
}

func TestDecodeCaptureEventReadsGSOSegmentLength(t *testing.T) {
	raw := make([]byte, captureEventHeader+64)
	binary.LittleEndian.PutUint32(raw[0:4], captureMagic)
	binary.LittleEndian.PutUint32(raw[4:8], 1)
	binary.LittleEndian.PutUint32(raw[8:12], 1)
	binary.LittleEndian.PutUint32(raw[12:16], 64)
	binary.LittleEndian.PutUint32(raw[16:20], 64)
	binary.LittleEndian.PutUint32(raw[36:40], 1448)

	event, ok := decodeCaptureEvent(perf.Record{RawSample: raw})
	if !ok {
		t.Fatal("decodeCaptureEvent rejected valid capture sample")
	}
	if event.GSOSegmentLength != 1448 {
		t.Fatalf("GSO segment length = %d, want 1448", event.GSOSegmentLength)
	}
}

func TestAppendCaptureEventUsesRingbufScratchHelperByDefault(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF map test: %v", err)
	}
	captureMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_capture_helper_test", Type: cebpf.RingBuf, MaxEntries: 4096})
	defer captureMap.Close()
	captureScratchMap, err := newCaptureScratchBPFMap()
	if err != nil {
		t.Skipf("create capture scratch BPF map: %v", err)
	}
	defer captureScratchMap.Close()
	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_capture_helper_stats_test", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	defer statsMap.Close()

	insns := appendCaptureEvent(nil, statsMap, captureMap, captureScratchMap)
	var skbOutputCalls, perfEventOutputCalls, ringbufOutputCalls, skbLoadBytesCalls int
	for _, insn := range insns {
		if !insn.IsBuiltinCall() {
			continue
		}
		switch insn.Constant {
		case int64(asm.FnSkbOutput):
			skbOutputCalls++
		case int64(asm.FnPerfEventOutput):
			perfEventOutputCalls++
		case int64(asm.FnRingbufOutput):
			ringbufOutputCalls++
		case int64(asm.FnSkbLoadBytes):
			skbLoadBytesCalls++
		}
	}
	if skbOutputCalls != 0 {
		t.Fatalf("skb output helper calls = %d, want 0 for OpenWrt 5.15 compatibility", skbOutputCalls)
	}
	if perfEventOutputCalls != 0 {
		t.Fatalf("perf output helper calls = %d, want 0 for ringbuf capture", perfEventOutputCalls)
	}
	if ringbufOutputCalls == 0 {
		t.Fatal("capture event path does not emit through ringbuf output")
	}
	if skbLoadBytesCalls == 0 {
		t.Fatal("capture event path does not copy skb bytes into scratch map")
	}
}

func TestAppendCaptureEventUsesPerfEventScratchHelperWhenRequested(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF map test: %v", err)
	}
	captureMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_capture_perf_helper_test", Type: cebpf.PerfEventArray, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	defer captureMap.Close()
	captureScratchMap, err := newCaptureScratchBPFMap()
	if err != nil {
		t.Skipf("create capture scratch BPF map: %v", err)
	}
	defer captureScratchMap.Close()
	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_capture_perf_helper_stats_test", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	defer statsMap.Close()

	insns := appendCaptureEvent(nil, statsMap, captureMap, captureScratchMap)
	var perfEventOutputCalls, ringbufOutputCalls int
	for _, insn := range insns {
		if !insn.IsBuiltinCall() {
			continue
		}
		switch insn.Constant {
		case int64(asm.FnPerfEventOutput):
			perfEventOutputCalls++
		case int64(asm.FnRingbufOutput):
			ringbufOutputCalls++
		}
	}
	if ringbufOutputCalls != 0 {
		t.Fatalf("ringbuf output helper calls = %d, want 0 for perf capture", ringbufOutputCalls)
	}
	if perfEventOutputCalls == 0 {
		t.Fatal("capture event path does not emit through perf event output")
	}
}

func TestIngressFastPathProgramLoads(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ingress fast path verifier test requires Linux")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap := newIngressFastPathTestMaps(t)
	defer statsMap.Close()
	defer packetPolicyMap.Close()
	defer routeMap.Close()
	defer kernelUDPTXRouteMap.Close()
	defer kernelUDPTXFlowMap.Close()
	defer natConfigMap.Close()
	defer natSourceMap.Close()
	defer natRouteMap.Close()
	defer natExcludeMap.Close()
	defer captureMap.Close()

	program, err := loadIngressFastPathProgram("trustix_ingress_test", statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap, kernelUDPTXDirectProgramOptions{Enabled: true})
	if err != nil {
		t.Fatalf("load ingress fast path program: %v", err)
	}
	defer program.Close()
}

func TestIngressFastPathProgramLoadsWithKernelUDPTXDirectOnly(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ingress fast path verifier test requires Linux")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap := newIngressFastPathTestMaps(t)
	defer statsMap.Close()
	defer packetPolicyMap.Close()
	defer routeMap.Close()
	defer kernelUDPTXRouteMap.Close()
	defer kernelUDPTXFlowMap.Close()
	defer natConfigMap.Close()
	defer natSourceMap.Close()
	defer natRouteMap.Close()
	defer natExcludeMap.Close()
	defer captureMap.Close()

	program, err := loadIngressFastPathProgram("trustix_ingress_direct_only_test", statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap, kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true})
	if err != nil {
		t.Fatalf("load ingress fast path direct-only program: %v", err)
	}
	defer program.Close()
}

func TestIngressFastPathProgramLoadsWithKernelUDPOnlyDirectRouteCacheAndInnerChecksum(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ingress fast path verifier test requires Linux")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "1")
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap := newIngressFastPathTestMaps(t)
	defer statsMap.Close()
	defer packetPolicyMap.Close()
	defer routeMap.Close()
	defer kernelUDPTXRouteMap.Close()
	defer kernelUDPTXFlowMap.Close()
	defer natConfigMap.Close()
	defer natSourceMap.Close()
	defer natRouteMap.Close()
	defer natExcludeMap.Close()
	defer captureMap.Close()
	routeCacheMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_route_cache_load_test", Type: cebpf.Array, KeySize: 4, ValueSize: kernelUDPTXRouteCacheValueSize, MaxEntries: 1})
	defer routeCacheMap.Close()

	program, err := loadIngressFastPathProgram("trustix_ingress_kudp_route_cache_test", statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap, kernelUDPTXDirectProgramOptions{Enabled: true, KernelUDPOnly: true, DirectOnly: true, RouteCacheMap: routeCacheMap})
	if err != nil {
		t.Fatalf("load ingress fast path kernel_udp-only route-cache program: %v", err)
	}
	defer program.Close()
}

func TestIngressFastPathProgramLoadsWithKernelUDPOnlyDirectRouteCacheInnerChecksumKfuncAndActiveGSO(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ingress fast path verifier test requires Linux")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "1")
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap := newIngressFastPathTestMaps(t)
	defer statsMap.Close()
	defer packetPolicyMap.Close()
	defer routeMap.Close()
	defer kernelUDPTXRouteMap.Close()
	defer kernelUDPTXFlowMap.Close()
	defer natConfigMap.Close()
	defer natSourceMap.Close()
	defer natRouteMap.Close()
	defer natExcludeMap.Close()
	defer captureMap.Close()
	routeCacheMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_route_cache_inner_test", Type: cebpf.Array, KeySize: 4, ValueSize: kernelUDPTXRouteCacheValueSize, MaxEntries: 1})
	defer routeCacheMap.Close()
	innerKfuncCall, err := loadSKBFixInnerTCPCsumKfuncCall()
	if err != nil {
		t.Fatalf("load inner TCP checksum kfunc metadata: %v", err)
	}

	program, err := loadIngressFastPathProgram(
		"trustix_ingress_kudp_route_cache_inner_test",
		statsMap,
		packetPolicyMap,
		routeMap,
		kernelUDPTXRouteMap,
		kernelUDPTXFlowMap,
		natConfigMap,
		natSourceMap,
		natRouteMap,
		natExcludeMap,
		captureMap,
		kernelUDPTXDirectProgramOptions{
			Enabled:           true,
			KernelUDPOnly:     true,
			DirectOnly:        true,
			RouteCacheMap:     routeCacheMap,
			InnerTCPKfunc:     true,
			InnerTCPKfuncCall: innerKfuncCall,
		},
	)
	if err != nil {
		skipIfKernelKfuncUnavailable(t, err)
		t.Fatalf("load ingress fast path kernel_udp-only route-cache inner-checksum active-GSO program: %v", err)
	}
	defer program.Close()
}

func TestIngressFastPathProgramLoadsWithKernelUDPOnlyDirectInnerChecksumKfuncAndActiveGSO(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ingress fast path verifier test requires Linux")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "1")
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap := newIngressFastPathTestMaps(t)
	defer statsMap.Close()
	defer packetPolicyMap.Close()
	defer routeMap.Close()
	defer kernelUDPTXRouteMap.Close()
	defer kernelUDPTXFlowMap.Close()
	defer natConfigMap.Close()
	defer natSourceMap.Close()
	defer natRouteMap.Close()
	defer natExcludeMap.Close()
	defer captureMap.Close()

	kfuncCall, err := loadSKBFixInnerTCPCsumKfuncCall()
	if err != nil {
		t.Fatalf("load inner TCP checksum kfunc metadata: %v", err)
	}
	program, err := loadIngressFastPathProgram(
		"trustix_ingress_kudp_inner_kfunc_gso_test",
		statsMap,
		packetPolicyMap,
		routeMap,
		kernelUDPTXRouteMap,
		kernelUDPTXFlowMap,
		natConfigMap,
		natSourceMap,
		natRouteMap,
		natExcludeMap,
		captureMap,
		kernelUDPTXDirectProgramOptions{
			Enabled:           true,
			KernelUDPOnly:     true,
			DirectOnly:        true,
			InnerTCPKfunc:     true,
			InnerTCPKfuncCall: kfuncCall,
		},
	)
	if err != nil {
		skipIfKernelKfuncUnavailable(t, err)
		t.Fatalf("load ingress fast path kernel_udp-only inner checksum kfunc active-GSO program: %v", err)
	}
	defer program.Close()
}

func TestIngressFastPathProgramLoadsWithKernelUDPOnlyDirectHeaderStoreKfuncAndActiveGSO(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ingress fast path verifier test requires Linux")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "1")
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap := newIngressFastPathTestMaps(t)
	defer statsMap.Close()
	defer packetPolicyMap.Close()
	defer routeMap.Close()
	defer kernelUDPTXRouteMap.Close()
	defer kernelUDPTXFlowMap.Close()
	defer natConfigMap.Close()
	defer natSourceMap.Close()
	defer natRouteMap.Close()
	defer natExcludeMap.Close()
	defer captureMap.Close()

	innerKfuncCall, err := loadSKBFixInnerTCPCsumKfuncCall()
	if err != nil {
		t.Fatalf("load inner TCP checksum kfunc metadata: %v", err)
	}
	storeKfuncCall, err := loadSKBKernelUDPTXStoreL2L3L4KfuncCall()
	if err != nil {
		t.Fatalf("load TX header-store kfunc metadata: %v", err)
	}
	program, err := loadIngressFastPathProgram(
		"trustix_ingress_kudp_header_kfunc_gso_test",
		statsMap,
		packetPolicyMap,
		routeMap,
		kernelUDPTXRouteMap,
		kernelUDPTXFlowMap,
		natConfigMap,
		natSourceMap,
		natRouteMap,
		natExcludeMap,
		captureMap,
		kernelUDPTXDirectProgramOptions{
			Enabled:              true,
			KernelUDPOnly:        true,
			DirectOnly:           true,
			InnerTCPKfunc:        true,
			InnerTCPKfuncCall:    innerKfuncCall,
			StoreHeaderKfunc:     true,
			StoreHeaderKfuncCall: storeKfuncCall,
		},
	)
	if err != nil {
		skipIfKernelKfuncUnavailable(t, err)
		t.Fatalf("load ingress fast path kernel_udp-only header-store kfunc active-GSO program: %v", err)
	}
	defer program.Close()
}

func TestIngressFastPathProgramLoadsWithKernelUDPOnlyDirectBuildUDPHeaderKfuncAndActiveGSO(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ingress fast path verifier test requires Linux")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "1")
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap := newIngressFastPathTestMaps(t)
	defer statsMap.Close()
	defer packetPolicyMap.Close()
	defer routeMap.Close()
	defer kernelUDPTXRouteMap.Close()
	defer kernelUDPTXFlowMap.Close()
	defer natConfigMap.Close()
	defer natSourceMap.Close()
	defer natRouteMap.Close()
	defer natExcludeMap.Close()
	defer captureMap.Close()

	innerKfuncCall, err := loadSKBFixInnerTCPCsumKfuncCall()
	if err != nil {
		t.Fatalf("load inner TCP checksum kfunc metadata: %v", err)
	}
	buildKfuncCall, err := loadSKBKernelUDPTXBuildUDPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load TX UDP header-build kfunc metadata: %v", err)
	}
	program, err := loadIngressFastPathProgram(
		"trustix_ingress_kudp_build_udp_kfunc_gso_test",
		statsMap,
		packetPolicyMap,
		routeMap,
		kernelUDPTXRouteMap,
		kernelUDPTXFlowMap,
		natConfigMap,
		natSourceMap,
		natRouteMap,
		natExcludeMap,
		captureMap,
		kernelUDPTXDirectProgramOptions{
			Enabled:                 true,
			KernelUDPOnly:           true,
			DirectOnly:              true,
			SkipPlainSequence:       true,
			InnerTCPKfunc:           true,
			InnerTCPKfuncCall:       innerKfuncCall,
			BuildUDPHeaderKfunc:     true,
			BuildUDPHeaderKfuncCall: buildKfuncCall,
		},
	)
	if err != nil {
		skipIfKernelKfuncUnavailable(t, err)
		t.Fatalf("load ingress fast path kernel_udp-only UDP header-build kfunc active-GSO program: %v", err)
	}
	defer program.Close()
}

func TestIngressFastPathProgramLoadsWithKernelUDPOnlyDirectPushUDPHeaderKfuncAndActiveGSO(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ingress fast path verifier test requires Linux")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "1")
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap := newIngressFastPathTestMaps(t)
	defer statsMap.Close()
	defer packetPolicyMap.Close()
	defer routeMap.Close()
	defer kernelUDPTXRouteMap.Close()
	defer kernelUDPTXFlowMap.Close()
	defer natConfigMap.Close()
	defer natSourceMap.Close()
	defer natRouteMap.Close()
	defer natExcludeMap.Close()
	defer captureMap.Close()

	innerKfuncCall, err := loadSKBFixInnerTCPCsumKfuncCall()
	if err != nil {
		t.Fatalf("load inner TCP checksum kfunc metadata: %v", err)
	}
	pushKfuncCall, err := loadSKBKernelUDPTXPushUDPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load TX UDP header-push kfunc metadata: %v", err)
	}
	program, err := loadIngressFastPathProgram(
		"trustix_ingress_kudp_push_udp_kfunc_gso_test",
		statsMap,
		packetPolicyMap,
		routeMap,
		kernelUDPTXRouteMap,
		kernelUDPTXFlowMap,
		natConfigMap,
		natSourceMap,
		natRouteMap,
		natExcludeMap,
		captureMap,
		kernelUDPTXDirectProgramOptions{
			Enabled:                true,
			KernelUDPOnly:          true,
			DirectOnly:             true,
			SkipPlainSequence:      true,
			InnerTCPKfunc:          true,
			InnerTCPKfuncCall:      innerKfuncCall,
			PushUDPHeaderKfunc:     true,
			PushUDPHeaderKfuncCall: pushKfuncCall,
		},
	)
	if err != nil {
		skipIfKernelKfuncUnavailable(t, err)
		t.Fatalf("load ingress fast path kernel_udp-only UDP header-push kfunc active-GSO program: %v", err)
	}
	defer program.Close()
}

func TestIngressFastPathProgramLoadsWithKernelUDPOnlyDirectFinalizeUDPHeaderKfuncAndActiveGSO(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ingress fast path verifier test requires Linux")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "1")
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap := newIngressFastPathTestMaps(t)
	defer statsMap.Close()
	defer packetPolicyMap.Close()
	defer routeMap.Close()
	defer kernelUDPTXRouteMap.Close()
	defer kernelUDPTXFlowMap.Close()
	defer natConfigMap.Close()
	defer natSourceMap.Close()
	defer natRouteMap.Close()
	defer natExcludeMap.Close()
	defer captureMap.Close()

	innerKfuncCall, err := loadSKBFixInnerTCPCsumKfuncCall()
	if err != nil {
		t.Fatalf("load inner TCP checksum kfunc metadata: %v", err)
	}
	finalizeKfuncCall, err := loadSKBKernelUDPTXFinalizeUDPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load TX UDP header-finalize kfunc metadata: %v", err)
	}
	program, err := loadIngressFastPathProgram(
		"trustix_ingress_kudp_finalize_udp_kfunc_gso_test",
		statsMap,
		packetPolicyMap,
		routeMap,
		kernelUDPTXRouteMap,
		kernelUDPTXFlowMap,
		natConfigMap,
		natSourceMap,
		natRouteMap,
		natExcludeMap,
		captureMap,
		kernelUDPTXDirectProgramOptions{
			Enabled:                true,
			KernelUDPOnly:          true,
			DirectOnly:             true,
			SkipPlainSequence:      true,
			InnerTCPKfunc:          true,
			InnerTCPKfuncCall:      innerKfuncCall,
			FinalizeUDPHeaderKfunc: true,
			FinalizeUDPKfuncCall:   finalizeKfuncCall,
		},
	)
	if err != nil {
		skipIfKernelKfuncUnavailable(t, err)
		t.Fatalf("load ingress fast path kernel_udp-only UDP header-finalize kfunc active-GSO program: %v", err)
	}
	defer program.Close()
}

func TestIngressFastPathProgramLoadsWithTIXTCPDirectOnly(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ingress fast path verifier test requires Linux")
	}
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_TCP_CHECKSUM", "1")
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap := newIngressFastPathTestMaps(t)
	defer statsMap.Close()
	defer packetPolicyMap.Close()
	defer routeMap.Close()
	defer kernelUDPTXRouteMap.Close()
	defer kernelUDPTXFlowMap.Close()
	defer natConfigMap.Close()
	defer natSourceMap.Close()
	defer natRouteMap.Close()
	defer natExcludeMap.Close()
	defer captureMap.Close()

	program, err := loadIngressFastPathProgram("trustix_ingress_exp_direct_only_test", statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap, kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true})
	if err != nil {
		t.Fatalf("load ingress fast path tix_tcp direct-only program: %v", err)
	}
	defer program.Close()
}

func TestIngressFastPathProgramLoadsWithTIXTCPDirectOnlyChecksumRequired(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ingress fast path verifier test requires Linux")
	}
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_TCP_CHECKSUM", "")
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap := newIngressFastPathTestMaps(t)
	defer statsMap.Close()
	defer packetPolicyMap.Close()
	defer routeMap.Close()
	defer kernelUDPTXRouteMap.Close()
	defer kernelUDPTXFlowMap.Close()
	defer natConfigMap.Close()
	defer natSourceMap.Close()
	defer natRouteMap.Close()
	defer natExcludeMap.Close()
	defer captureMap.Close()

	program, err := loadIngressFastPathProgram("trustix_ingress_exp_checksum_required_test", statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap, kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true})
	if err != nil {
		t.Fatalf("load ingress fast path tix_tcp checksum-required direct-only program: %v", err)
	}
	defer program.Close()
}

func TestIngressFastPathProgramLoadsWithTIXTCPSkipOuterChecksum(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ingress fast path verifier test requires Linux")
	}
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "1")
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap := newIngressFastPathTestMaps(t)
	defer statsMap.Close()
	defer packetPolicyMap.Close()
	defer routeMap.Close()
	defer kernelUDPTXRouteMap.Close()
	defer kernelUDPTXFlowMap.Close()
	defer natConfigMap.Close()
	defer natSourceMap.Close()
	defer natRouteMap.Close()
	defer natExcludeMap.Close()
	defer captureMap.Close()

	program, err := loadIngressFastPathProgram("trustix_ingress_exp_skip_outer_csum_test", statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap, kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true})
	if err != nil {
		t.Fatalf("load ingress fast path tix_tcp skip-outer-checksum direct-only program: %v", err)
	}
	defer program.Close()
}

func TestIngressFastPathProgramLoadsWithTIXTCPTrustedInnerChecksum(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ingress fast path verifier test requires Linux")
	}
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_TRUST_INNER_CHECKSUMS", "1")
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap := newIngressFastPathTestMaps(t)
	defer statsMap.Close()
	defer packetPolicyMap.Close()
	defer routeMap.Close()
	defer kernelUDPTXRouteMap.Close()
	defer kernelUDPTXFlowMap.Close()
	defer natConfigMap.Close()
	defer natSourceMap.Close()
	defer natRouteMap.Close()
	defer natExcludeMap.Close()
	defer captureMap.Close()

	program, err := loadIngressFastPathProgram("trustix_ingress_exp_trusted_csum_test", statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap, kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true})
	if err != nil {
		t.Fatalf("load ingress fast path tix_tcp trusted-checksum direct-only program: %v", err)
	}
	defer program.Close()
}

func TestIngressFastPathProgramLoadsWithTIXTCPRouteGSOAndXmitKfuncs(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ingress fast path verifier test requires Linux")
	}
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM", "0")
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap := newIngressFastPathTestMaps(t)
	defer statsMap.Close()
	defer packetPolicyMap.Close()
	defer routeMap.Close()
	defer kernelUDPTXRouteMap.Close()
	defer kernelUDPTXFlowMap.Close()
	defer natConfigMap.Close()
	defer natSourceMap.Close()
	defer natRouteMap.Close()
	defer natExcludeMap.Close()
	defer captureMap.Close()

	routeKfuncCall, err := loadSKBTIXTTXPushRouteTCPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load route TCP header-push kfunc metadata: %v", err)
	}
	gsoKfuncCall, err := loadSKBTIXTTXSegmentRouteTCPGSOKfuncCall()
	if err != nil {
		t.Fatalf("load route TCP GSO kfunc metadata: %v", err)
	}
	xmitKfuncCall, err := loadSKBTIXTTXRouteTCPXmitKfuncCall()
	if err != nil {
		t.Fatalf("load route TCP xmit kfunc metadata: %v", err)
	}
	program, err := loadIngressFastPathProgram(
		"trustix_ingress_exp_route_gso_xmit_test",
		statsMap,
		packetPolicyMap,
		routeMap,
		kernelUDPTXRouteMap,
		kernelUDPTXFlowMap,
		natConfigMap,
		natSourceMap,
		natRouteMap,
		natExcludeMap,
		captureMap,
		kernelUDPTXDirectProgramOptions{
			Enabled:                     true,
			TIXTCPOnly:                  true,
			DirectOnly:                  true,
			PushRouteTCPHeaderKfunc:     true,
			PushRouteTCPHeaderKfuncCall: routeKfuncCall,
			RouteTCPGSOKfunc:            true,
			RouteTCPGSOKfuncCall:        gsoKfuncCall,
			RouteTCPXmitKfunc:           true,
			RouteTCPXmitKfuncCall:       xmitKfuncCall,
		},
	)
	if err != nil {
		skipIfKernelKfuncUnavailable(t, err)
		t.Fatalf("load ingress fast path tix_tcp route-GSO + xmit kfunc program: %v", err)
	}
	defer program.Close()
}

func TestKernelUDPTXDirectOnlyKeepsRouteMissOnNormalTCPath(t *testing.T) {
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "direct_only_route_miss")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	out := appendKernelUDPTXDirect(asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}, statsMap, routeMap, flowMap, kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true})
	if !instructionsContainSymbol(out, "kudp_tx_direct_route_miss_fallback") {
		t.Fatal("direct-only route miss does not keep a normal TC path continuation label")
	}
	if !instructionsContainJump(out, "kudp_tx_direct_route_miss_fallback", "kudp_tx_direct_direct_only_continue") {
		t.Fatal("direct-only route miss does not jump to the caller's normal TC path continuation")
	}
	if !instructionsContainReachableSymbol(out, "kudp_tx_direct_route_miss_fallback") {
		t.Fatal("direct-only route miss continuation is not reachable")
	}
	if !instructionsContainJump(out, "kudp_tx_direct_fallback", "kudp_tx_direct_direct_only_drop") {
		t.Fatal("direct-only route-hit fallback does not branch to the fail-closed drop path")
	}
}

func TestKernelUDPTXDirectKernelUDPOnlyDropsTIXTInstructionPath(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_INNER_TCP_CHECKSUM", "0")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "kernel_udp_only")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, KernelUDPOnly: true, DirectOnly: true},
	)
	if instructionsContainSymbol(out, "kudp_tx_direct_build_tixt") {
		t.Fatal("kernel_udp-only TX direct still emits the TIXT build label")
	}
	if got := instructionsCountBuiltinCalls(out, asm.FnSkbLoadBytes); got != 0 {
		t.Fatalf("kernel_udp-only TX direct still emits TCP checksum skb_load_bytes calls: %d", got)
	}
	if got := instructionsCountBuiltinCalls(out, asm.FnCsumDiff); got != 0 {
		t.Fatalf("kernel_udp-only TX direct still emits TCP checksum csum_diff calls: %d", got)
	}
	if instructionsContainReference(out, "kudp_tx_direct_inner_tcp_post_csum_done") {
		t.Fatal("kernel_udp-only TX direct with disabled inner checksum still references checksum done label")
	}
	if instructionsContainReference(out, "kudp_tx_direct_inner_l4_post_csum_done") {
		t.Fatal("kernel_udp-only TX direct with disabled inner checksum still references mixed checksum done label")
	}
	if !instructionsContainSymbol(out, "kudp_tx_direct_transport_fallback") {
		t.Fatal("kernel_udp-only TX direct did not keep fail-closed transport fallback")
	}
}

func TestKernelUDPTXDirectKernelUDPOnlyNormalizesInnerTCPChecksum(t *testing.T) {
	t.Setenv("TRUSTIX_TRUST_CAPTURED_CHECKSUMS", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_INNER_TCP_CHECKSUM", "")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "kernel_udp_inner_checksum")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, KernelUDPOnly: true, DirectOnly: true},
	)
	if !instructionsContainSymbol(out, "kudp_tx_direct_inner_tcp_post_csum_done") {
		t.Fatal("kernel_udp-only TX direct does not include inner TCP checksum normalization")
	}
	if got := instructionsCountBuiltinCalls(out, asm.FnSkbLoadBytes); got == 0 {
		t.Fatal("kernel_udp-only TX direct checksum path does not use bpf_skb_load_bytes")
	}
	if got := instructionsCountBuiltinCalls(out, asm.FnCsumDiff); got == 0 {
		t.Fatal("kernel_udp-only TX direct checksum path does not use bpf_csum_diff")
	}
	checksumOffset := int16(rejectEthernetHeaderLen + kernelUDPTXOuterOverhead + rejectIPv4HeaderLen + 16)
	if !instructionsStorePacketHalfFromR0(out, checksumOffset) {
		t.Fatal("kernel_udp-only TX direct checksum path does not store the computed TCP checksum")
	}
	if instructionsSwapR0ImmediatelyBeforePacketStore(out, checksumOffset) {
		t.Fatal("kernel_udp-only TX direct checksum path byte-swaps the folded TCP checksum before storing it")
	}
}

func TestKernelUDPTXDirectKernelUDPOnlySkipsInnerChecksumWithExplicitTrust(t *testing.T) {
	t.Setenv("TRUSTIX_TRUST_CAPTURED_CHECKSUMS", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_TRUST_CAPTURED_INNER_CHECKSUMS", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_INNER_TCP_CHECKSUM", "")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "kernel_udp_trusted_inner_checksum")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, KernelUDPOnly: true, DirectOnly: true},
	)
	if instructionsContainReference(out, "kudp_tx_direct_inner_tcp_post_csum_done") {
		t.Fatal("trusted captured checksums still emitted inner TCP checksum path")
	}
	if instructionsContainReference(out, "kudp_tx_direct_inner_l4_post_csum_done") {
		t.Fatal("trusted captured checksums still emitted mixed inner checksum path")
	}
	if got := instructionsCountBuiltinCalls(out, asm.FnSkbLoadBytes); got != 0 {
		t.Fatalf("trusted captured checksums still emitted skb_load_bytes calls: %d", got)
	}
	if got := instructionsCountBuiltinCalls(out, asm.FnCsumDiff); got != 0 {
		t.Fatalf("trusted captured checksums still emitted csum_diff calls: %d", got)
	}
}

func TestKernelUDPTXDirectKernelUDPOnlyStillNormalizesInnerChecksumWhenOnlyUserspaceTrustsCapturedChecksums(t *testing.T) {
	t.Setenv("TRUSTIX_TRUST_CAPTURED_CHECKSUMS", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_TRUST_CAPTURED_INNER_CHECKSUMS", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_INNER_TCP_CHECKSUM", "")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "kernel_udp_userspace_trusted_inner_checksum")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, KernelUDPOnly: true, DirectOnly: true},
	)
	if !instructionsContainSymbol(out, "kudp_tx_direct_inner_tcp_post_csum_done") {
		t.Fatal("userspace captured-checksum trust unexpectedly disabled TC inner checksum normalization")
	}
}

func TestKernelUDPTXDirectKernelUDPOnlyInnerChecksumExplicitOptInOverridesTrust(t *testing.T) {
	t.Setenv("TRUSTIX_TRUST_CAPTURED_CHECKSUMS", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_TRUST_CAPTURED_INNER_CHECKSUMS", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_INNER_TCP_CHECKSUM", "1")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "kernel_udp_trusted_inner_checksum_forced")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, KernelUDPOnly: true, DirectOnly: true},
	)
	if !instructionsContainSymbol(out, "kudp_tx_direct_inner_tcp_post_csum_done") {
		t.Fatal("explicit inner checksum opt-in did not override trusted captured checksums")
	}
}

func TestKernelUDPTXDirectKernelUDPOnlyNormalizesInnerUDPChecksum(t *testing.T) {
	t.Setenv("TRUSTIX_TRUST_CAPTURED_CHECKSUMS", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_INNER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_HOT_STATS", "1")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "kernel_udp_inner_udp_checksum")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, KernelUDPOnly: true, DirectOnly: true},
	)
	if !instructionsContainSymbol(out, "kudp_tx_direct_inner_tcp_post_csum_udp") {
		t.Fatal("kernel_udp-only TX direct does not include inner UDP checksum normalization branch")
	}
	if !instructionsContainImmJumpTo(out, ipProtocolUDP, "kudp_tx_direct_inner_tcp_post_csum_udp") {
		t.Fatal("kernel_udp-only TX direct does not dispatch UDP packets to checksum normalization")
	}
	if !instructionsContainImm(out, 0x00001100) {
		t.Fatal("kernel_udp-only TX direct UDP checksum path does not build a UDP pseudo-header")
	}
	if !instructionsContainImm(out, int64(kernelUDPTXDirectStatInnerUDPChecksumFixes)) {
		t.Fatal("kernel_udp-only TX direct UDP checksum path does not expose a fix counter")
	}
}

func TestKernelUDPTXDirectMixedModeNormalizesKernelUDPInnerUDPChecksum(t *testing.T) {
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "mixed_inner_udp_checksum")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true},
	)
	if !instructionsContainSymbol(out, "kudp_tx_direct_inner_l4_post_csum_udp") {
		t.Fatal("mixed TX direct does not include kernel_udp inner UDP checksum normalization branch")
	}
	if !instructionsContainImmJumpTo(out, ipProtocolUDP, "kudp_tx_direct_inner_l4_post_csum_udp") {
		t.Fatal("mixed TX direct does not dispatch UDP packets to checksum normalization")
	}
	if !instructionsContainJump(out, "kudp_tx_direct_inner_l4_post_csum_done", "kudp_tx_direct_stores_done") {
		t.Fatal("mixed TX direct does not rejoin UDP header store after inner checksum normalization")
	}
	if !instructionsContainImmJumpTo(out, int64(kernelUDPTXFlowFlagTIXTCP), "kudp_tx_direct_after_adjust_tixt") {
		t.Fatal("mixed TX direct does not keep tix_tcp bypass around kernel_udp checksum normalization")
	}
	if !instructionsContainSymbol(out, "kudp_tx_direct_inner_tixt_pre_csum_tcp") {
		t.Fatal("mixed TX direct does not normalize tix_tcp inner TCP checksums before TIXT outer checksum")
	}
}

func TestKernelUDPTXDirectKernelUDPOnlySkipsTIXTCPFlows(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_KERNEL_UDP_ONLY", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		Endpoints: []dataplane.EndpointMetadata{
			{
				ID:        core.EndpointID("ix-b-kudp"),
				Peer:      core.IXID("ix-b"),
				Transport: "udp",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
			{
				ID:        core.EndpointID("ix-b-tixt"),
				Peer:      core.IXID("ix-b"),
				Transport: "tix_tcp",
				Enabled:   true,
				Security:  dataplane.EndpointSecurityMetadata{Encryption: "plaintext"},
			},
		},
	}
	manager.kernelUDPFlows = map[uint64]dataplane.KernelUDPFlow{
		11: {
			ID:            11,
			Peer:          core.IXID("ix-b"),
			Endpoint:      core.EndpointID("ix-b-kudp"),
			LocalAddress:  "192.0.2.1:41011",
			RemoteAddress: "198.51.100.11:17001",
		},
	}
	manager.tixTCPFlows = map[uint64]dataplane.TIXTCPFlow{
		21: {
			ID:            21,
			Peer:          core.IXID("ix-b"),
			Endpoint:      core.EndpointID("ix-b-tixt"),
			LocalAddress:  "192.0.2.1:42021",
			RemoteAddress: "198.51.100.21:18001",
		},
	}
	route := routing.Route{
		Prefix:  core.Prefix("10.44.0.0/16"),
		NextHop: core.IXID("ix-b"),
	}

	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, false, false, kernelUDPTXRouteMaxFlows)
	if len(flows) != 1 {
		t.Fatalf("kernel_udp-only route flows = %d, want 1: %+v", len(flows), flows)
	}
	if flows[0].id != 11 || flows[0].tixTCP {
		t.Fatalf("kernel_udp-only selected flow = %+v, want kernel_udp flow 11", flows[0])
	}
}

func TestTIXTCPTXDirectChecksumUsesChunkedSKBLoads(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_LINEAR_CHECKSUM", "0")
	if kernelUDPTXTCPChecksumChunkLen != 256 {
		t.Fatalf("tix_tcp TX direct checksum chunk length = %d, want 256", kernelUDPTXTCPChecksumChunkLen)
	}
	out := appendTIXTCPTXDirectTCPChecksum(asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}, "checksum_error")
	if got := instructionsCountBuiltinCalls(out, asm.FnSkbLoadBytes); got == 0 {
		t.Fatal("tix_tcp TX direct checksum path does not use bpf_skb_load_bytes")
	}
	if got := instructionsCountBuiltinCalls(out, asm.FnSkbPullData); got != 0 {
		t.Fatalf("tix_tcp TX direct checksum path calls bpf_skb_pull_data %d times, want 0", got)
	}
	if got := instructionsCountBuiltinCalls(out, asm.FnCsumDiff); got < 4 {
		t.Fatalf("tix_tcp TX direct checksum path calls bpf_csum_diff %d times, want pseudo/header/payload chunks", got)
	}
	if !instructionsContainCallWithImmediateR4(out, asm.FnSkbLoadBytes, kernelUDPTXTCPChecksumChunkLen) {
		t.Fatalf("tix_tcp TX direct checksum path does not load %d-byte payload chunks", kernelUDPTXTCPChecksumChunkLen)
	}
}

func TestTIXTCPTXDirectChecksumTriesPacketDirectBeforeChunkedFallback(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_LINEAR_CHECKSUM", "1")
	out := appendTIXTCPTXDirectTCPChecksum(asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}, "checksum_error")
	if !instructionsContainSymbol(out, "kudp_tx_direct_tcp_csum_packet_fallback") ||
		!instructionsContainSymbol(out, "kudp_tx_direct_tcp_csum_loadbytes_continue") ||
		!instructionsContainReference(out, "kudp_tx_direct_tcp_csum_packet_fallback") {
		t.Fatal("tix_tcp checksum path does not try packet-direct checksum before the chunked fallback")
	}
	if got := instructionsCountBuiltinCalls(out, asm.FnSkbLoadBytes); got == 0 {
		t.Fatal("tix_tcp packet-direct checksum path dropped the chunked skb_load_bytes fallback")
	}
	if got := instructionsCountBuiltinCalls(out, asm.FnCsumDiff); got < 10 {
		t.Fatalf("tix_tcp packet-direct checksum path csum_diff calls = %d, want packet-direct plus chunked fallback", got)
	}
}

func TestTIXTCPTXDirectTrustedChecksumUsesPacketIPHeader(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_TRUST_INNER_CHECKSUMS", "1")
	out := appendTIXTCPTXDirectTCPChecksum(asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}, "checksum_error")
	if !instructionsContainJump(out, "kudp_tx_direct_tcp_csum_trusted_pseudo", "kudp_tx_direct_tcp_csum_done") {
		t.Fatal("tix_tcp trusted-checksum path does not bypass payload checksum scan on success")
	}
	if !instructionsContainLoadMem(out, asm.R7, rejectEthernetHeaderLen+12, asm.Half) ||
		!instructionsContainLoadMem(out, asm.R7, rejectEthernetHeaderLen+14, asm.Half) ||
		!instructionsContainLoadMem(out, asm.R7, rejectEthernetHeaderLen+16, asm.Half) ||
		!instructionsContainLoadMem(out, asm.R7, rejectEthernetHeaderLen+18, asm.Half) {
		t.Fatal("tix_tcp trusted-checksum path does not read inner IPv4 pseudo-header from packet memory")
	}
	if instructionsContainLoadMem(out, asm.RFP, rejectEthernetHeaderLen+12, asm.Half) {
		t.Fatal("tix_tcp trusted-checksum path reads packet pseudo-header offsets from stack memory")
	}
	if got := instructionsCountBuiltinCalls(out, asm.FnSkbLoadBytes); got == 0 {
		t.Fatal("tix_tcp trusted-checksum path dropped the skb_load_bytes fallback")
	}
	if got := instructionsCountBuiltinCalls(out, asm.FnSkbPullData); got != 0 {
		t.Fatalf("tix_tcp trusted-checksum path calls bpf_skb_pull_data %d times, want 0", got)
	}
}

func TestTIXTCPTXDirectTrustedChecksumRequiresExplicitOptIn(t *testing.T) {
	t.Setenv("TRUSTIX_TRUST_CAPTURED_CHECKSUMS", "1")
	out := appendTIXTCPTXDirectTCPChecksum(asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}, "checksum_error")
	if instructionsContainJump(out, "kudp_tx_direct_tcp_csum_trusted_pseudo", "kudp_tx_direct_tcp_csum_done") {
		t.Fatal("tix_tcp trusted-checksum path followed captured-checksum trust without explicit opt-in")
	}
	if got := instructionsCountBuiltinCalls(out, asm.FnSkbLoadBytes); got == 0 {
		t.Fatal("tix_tcp checksum path did not keep skb_load_bytes checksum scan")
	}
}

func TestTIXTCPTXDirectTrustedChecksumDisabledExplicitly(t *testing.T) {
	t.Setenv("TRUSTIX_TRUST_CAPTURED_CHECKSUMS", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_TRUST_INNER_CHECKSUMS", "0")
	out := appendTIXTCPTXDirectTCPChecksum(asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}, "checksum_error")
	if instructionsContainJump(out, "kudp_tx_direct_tcp_csum_trusted_pseudo", "kudp_tx_direct_tcp_csum_done") {
		t.Fatal("tix_tcp trusted-checksum path ignored explicit opt-out")
	}
}

func TestKernelUDPTXDirectTIXTCPPathKeepsChunkedChecksum(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TRUST_CAPTURED_CHECKSUMS", "0")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "tix_tcp_chunked_checksum")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	out := appendKernelUDPTXDirect(asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}, statsMap, routeMap, flowMap, kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true})
	if got := instructionsCountBuiltinCalls(out, asm.FnSkbLoadBytes); got == 0 {
		t.Fatal("tix_tcp direct-only TX program does not include bpf_skb_load_bytes checksum loads")
	}
	if !instructionsContainCallWithImmediateR4(out, asm.FnSkbLoadBytes, kernelUDPTXTCPChecksumChunkLen) {
		t.Fatalf("tix_tcp direct-only TX program does not include %d-byte checksum chunks", kernelUDPTXTCPChecksumChunkLen)
	}
	if !instructionsContainSymbol(out, "kudp_tx_direct_inner_tixt_pre_csum_tcp") {
		t.Fatal("tix_tcp direct-only TX program does not normalize the inner TCP checksum before TIXT outer checksum")
	}
}

func TestKernelUDPTXDirectTIXTCPPathUsesInnerChecksumKfuncWhenAvailable(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TRUST_CAPTURED_CHECKSUMS", "0")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "tix_tcp_inner_kfunc")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	kfuncCall, err := loadSKBFixInnerTCPCsumKfuncCall()
	if err != nil {
		t.Fatalf("load inner TCP checksum kfunc metadata: %v", err)
	}
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true, InnerTCPKfunc: true, InnerTCPKfuncCall: kfuncCall},
	)
	if !instructionsContainSymbol(out, "kudp_tx_direct_inner_tixt_pre_csum_kfunc") ||
		!instructionsContainSymbol(out, "kudp_tx_direct_inner_tixt_pre_csum_kfunc_success") {
		t.Fatal("tix_tcp direct-only TX program does not use inner TCP checksum kfunc")
	}
	if !instructionsContainKfuncCall(out) {
		t.Fatal("tix_tcp direct-only TX program did not emit inner TCP checksum kfunc call")
	}
	if !instructionsContainSymbol(out, "kudp_tx_direct_inner_tixt_pre_csum_udp") {
		t.Fatal("tix_tcp direct-only TX program dropped inner UDP checksum normalization fallback")
	}
}

func TestKernelUDPTXDirectTIXTCPPathUsesOuterChecksumKfuncWhenAvailable(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TRUST_CAPTURED_CHECKSUMS", "0")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "tix_tcp_outer_kfunc")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	kfuncCall, err := loadSKBTIXTFixOuterTCPCsumKfuncCall()
	if err != nil {
		t.Fatalf("load outer TCP checksum kfunc metadata: %v", err)
	}
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true, OuterTCPCsumKfunc: true, OuterTCPCsumKfuncCall: kfuncCall},
	)
	if !instructionsContainSymbol(out, "kudp_tx_direct_outer_tcp_csum_kfunc") ||
		!instructionsContainSymbol(out, "kudp_tx_direct_outer_tcp_csum_kfunc_done") {
		t.Fatal("tix_tcp direct-only TX program does not use outer TCP checksum kfunc")
	}
	if !instructionsContainKfuncCall(out) {
		t.Fatal("tix_tcp direct-only TX program did not emit outer TCP checksum kfunc call")
	}
	if instructionsContainSymbol(out, "kudp_tx_direct_tcp_csum_payload_chunk_0_next") {
		t.Fatal("tix_tcp outer checksum kfunc path kept the eBPF checksum scanner")
	}
}

func TestKernelUDPTXDirectTIXTCPPathUsesOuterTCPHeaderKfuncWhenAvailable(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TRUST_CAPTURED_CHECKSUMS", "0")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_OUTER_TCP_HEADER_KFUNC_PARTIAL_CSUM", "")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "tix_tcp_outer_header_kfunc")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	kfuncCall, err := loadSKBTIXTTXFinalizeTCPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load outer TCP header kfunc metadata: %v", err)
	}
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true, OuterTCPKfunc: true, OuterTCPKfuncCall: kfuncCall},
	)
	if !instructionsContainSymbol(out, "kudp_tx_direct_finalize_outer_tcp_header_kfunc") ||
		!instructionsContainSymbol(out, "kudp_tx_direct_finalize_outer_tcp_header_kfunc_done") {
		t.Fatal("tix_tcp direct-only TX program does not use outer TCP header kfunc")
	}
	if !instructionsContainKfuncCall(out) {
		t.Fatal("tix_tcp direct-only TX program did not emit outer TCP header kfunc call")
	}
	if instructionsContainSymbol(out, "kudp_tx_direct_outer_tcp_csum_kfunc") {
		t.Fatal("tix_tcp outer TCP header kfunc path should not also call the outer checksum kfunc")
	}
	if instructionsContainSymbol(out, "kudp_tx_direct_fallback_error") {
		t.Fatal("tix_tcp outer TCP header kfunc path emitted an unused checksum fallback error block")
	}
	if instructionsContainSymbol(out, "kudp_tx_direct_tcp_csum_payload_chunk_0_next") {
		t.Fatal("tix_tcp outer TCP header kfunc path kept the eBPF checksum scanner")
	}
	if !instructionsContainStoreMem(out, asm.RFP, kernelUDPTXTIXTFinalizeTCPHeaderArgsFlowIDOffset, asm.DWord) ||
		!instructionsContainStoreMem(out, asm.RFP, kernelUDPTXTIXTFinalizeTCPHeaderArgsPayloadLenOffset, asm.Word) {
		t.Fatal("tix_tcp outer TCP header kfunc path does not initialize TIXT finalizer args")
	}
	if !instructionsContainMovImmToRegAfterSymbol(out, "kudp_tx_direct_finalize_outer_tcp_header_kfunc", asm.R3, int64(trustIXTIXTTXFinalizeTCPPartialCSUM)) {
		t.Fatal("tix_tcp outer TCP header kfunc partial checksum flag was not emitted by default")
	}
}

func TestKernelUDPTXDirectTIXTCPPathUsesTCPPartialCSUMKfuncWhenAvailable(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TRUST_CAPTURED_CHECKSUMS", "0")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "tix_tcp_partial_csum_kfunc")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	kfuncCall, err := loadSKBTIXTTXSetTCPPartialCSUMKfuncCall()
	if err != nil {
		t.Fatalf("load TCP partial checksum kfunc metadata: %v", err)
	}
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true, TCPPartialCSUMKfunc: true, TCPPartialCSUMKfuncCall: kfuncCall},
	)
	if !instructionsContainSymbol(out, "kudp_tx_direct_tcp_partial_csum_kfunc") ||
		!instructionsContainSymbol(out, "kudp_tx_direct_tcp_partial_csum_kfunc_done") {
		t.Fatal("tix_tcp direct-only TX program does not use TCP partial checksum kfunc")
	}
	if !instructionsContainKfuncCall(out) {
		t.Fatal("tix_tcp direct-only TX program did not emit TCP partial checksum kfunc call")
	}
	if instructionsContainSymbol(out, "kudp_tx_direct_finalize_outer_tcp_header_kfunc") {
		t.Fatal("tix_tcp TCP partial checksum path should not call outer TCP header finalizer")
	}
	if instructionsContainSymbol(out, "kudp_tx_direct_tcp_csum_payload_chunk_0_next") {
		t.Fatal("tix_tcp TCP partial checksum path kept the payload checksum scanner")
	}
	if instructionsContainSymbol(out, "kudp_tx_direct_fallback_error") {
		t.Fatal("tix_tcp TCP partial checksum path kept an unreachable pseudo-header checksum error branch")
	}
	if !instructionsContainStoreMem(out, asm.RFP, kernelUDPTXTCPHeaderOffset+16, asm.Half) {
		t.Fatal("tix_tcp TCP partial checksum path does not preseed TCP check field")
	}
	if !instructionsContainStoreMem(out, asm.RFP, kernelUDPTXTCPHeaderOffset, asm.Half) ||
		!instructionsContainStoreMem(out, asm.RFP, kernelUDPTXTCPFrameHeaderOffset+32, asm.Word) {
		t.Fatal("tix_tcp TCP partial checksum path does not build the stack TCP/TIXT header")
	}
}

func TestKernelUDPTXDirectTIXTCPPathOuterTCPHeaderKfuncPartialChecksumCanBeDisabled(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TRUST_CAPTURED_CHECKSUMS", "0")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_OUTER_TCP_HEADER_KFUNC_PARTIAL_CSUM", "0")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "tix_tcp_outer_header_partial_csum")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	kfuncCall, err := loadSKBTIXTTXFinalizeTCPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load outer TCP header kfunc metadata: %v", err)
	}
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true, OuterTCPKfunc: true, OuterTCPKfuncCall: kfuncCall},
	)
	if instructionsContainMovImmToRegAfterSymbol(out, "kudp_tx_direct_finalize_outer_tcp_header_kfunc", asm.R3, int64(trustIXTIXTTXFinalizeTCPPartialCSUM)) {
		t.Fatal("tix_tcp outer TCP header kfunc partial checksum flag ignored explicit disable")
	}
}

func TestKernelUDPTXDirectTIXTCPSkipPlainSequenceRemovesStackAtomic(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TRUST_CAPTURED_CHECKSUMS", "0")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "tix_tcp_skip_plain_seq_stack")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{
			Enabled:                 true,
			TIXTCPOnly:              true,
			DirectOnly:              true,
			TIXTCPSkipPlainSequence: true,
		},
	)
	if instructionsContainFetchAddAt(out, asm.R0, asm.R2) {
		t.Fatal("tix_tcp plaintext sequence skip kept a flow sequence atomic add")
	}
	if !instructionsContainStoreImm(out, asm.RFP, kernelUDPTXTCPHeaderOffset+4, asm.Word, 0) ||
		!instructionsContainStoreImm(out, asm.RFP, kernelUDPTXTCPFrameHeaderOffset+24, asm.Word, 0) ||
		!instructionsContainStoreImm(out, asm.RFP, kernelUDPTXTCPFrameHeaderOffset+28, asm.Word, 0) {
		t.Fatal("tix_tcp plaintext sequence skip did not zero outer/TIXT sequence fields")
	}
}

func TestKernelUDPTXDirectTIXTCPSkipPlainSequenceRemovesFinalizeAtomic(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TRUST_CAPTURED_CHECKSUMS", "0")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_OUTER_TCP_HEADER_KFUNC_PARTIAL_CSUM", "1")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "tix_tcp_skip_plain_seq_finalize")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	kfuncCall, err := loadSKBTIXTTXFinalizeTCPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load outer TCP header kfunc metadata: %v", err)
	}
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{
			Enabled:                 true,
			TIXTCPOnly:              true,
			DirectOnly:              true,
			OuterTCPKfunc:           true,
			OuterTCPKfuncCall:       kfuncCall,
			TIXTCPSkipPlainSequence: true,
		},
	)
	if instructionsContainFetchAddAt(out, asm.R0, asm.R2) {
		t.Fatal("tix_tcp finalize plaintext sequence skip kept a flow sequence atomic add")
	}
	if !instructionsContainStoreImm(out, asm.RFP, kernelUDPTXTIXTFinalizeTCPHeaderArgsSequenceOffset, asm.Word, 0) ||
		!instructionsContainStoreImm(out, asm.RFP, kernelUDPTXTIXTFinalizeTCPHeaderArgsSequenceOffset+4, asm.Word, 0) {
		t.Fatal("tix_tcp finalize plaintext sequence skip did not zero finalizer sequence args")
	}
}

func TestKernelUDPTXDirectTIXTCPPathUsesPushTCPHeaderKfuncWhenAvailable(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TRUST_CAPTURED_CHECKSUMS", "0")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_OUTER_TCP_HEADER_KFUNC_PARTIAL_CSUM", "")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "tix_tcp_push_header_kfunc")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	kfuncCall, err := loadSKBTIXTTXPushTCPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load TCP header-push kfunc metadata: %v", err)
	}
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true, PushTCPHeaderKfunc: true, PushTCPHeaderKfuncCall: kfuncCall},
	)
	if !instructionsContainSymbol(out, "kudp_tx_direct_push_outer_tcp_header_kfunc") ||
		!instructionsContainSymbol(out, "kudp_tx_direct_push_outer_tcp_header_kfunc_done") {
		t.Fatal("tix_tcp direct-only TX program does not use TCP header-push kfunc")
	}
	if !instructionsContainKfuncCall(out) {
		t.Fatal("tix_tcp direct-only TX program did not emit TCP header-push kfunc call")
	}
	if got := instructionsCountBuiltinCalls(out, asm.FnSkbAdjustRoom); got != 0 {
		t.Fatalf("tix_tcp TCP header-push kfunc path still uses bpf_skb_adjust_room %d times", got)
	}
	if instructionsContainSymbol(out, "kudp_tx_direct_post_adjust_header_drop") {
		t.Fatal("tix_tcp TCP header-push kfunc path emitted post-adjust header drop block")
	}
	if !instructionsContainMovImmToRegAfterSymbol(out, "kudp_tx_direct_push_outer_tcp_header_kfunc", asm.R3, int64(trustIXTIXTTXFinalizeTCPPartialCSUM)) {
		t.Fatal("tix_tcp TCP header-push kfunc partial checksum flag was not emitted by default")
	}
}

func TestKernelUDPTXDirectTIXTCPPathPushTCPHeaderKfuncPartialChecksumCanBeDisabled(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TRUST_CAPTURED_CHECKSUMS", "0")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_OUTER_TCP_HEADER_KFUNC_PARTIAL_CSUM", "0")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "tix_tcp_push_header_partial")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	kfuncCall, err := loadSKBTIXTTXPushTCPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load TCP header-push kfunc metadata: %v", err)
	}
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true, PushTCPHeaderKfunc: true, PushTCPHeaderKfuncCall: kfuncCall},
	)
	if instructionsContainMovImmToRegAfterSymbol(out, "kudp_tx_direct_push_outer_tcp_header_kfunc", asm.R3, int64(trustIXTIXTTXFinalizeTCPPartialCSUM)) {
		t.Fatal("tix_tcp TCP header-push kfunc partial checksum flag ignored explicit disable")
	}
}

func TestKernelUDPTXDirectTIXTCPPathPushTCPHeaderKfuncTrustsInnerChecksumOptIn(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TRUST_CAPTURED_CHECKSUMS", "0")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_OUTER_TCP_HEADER_KFUNC_PARTIAL_CSUM", "0")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_TRUST_INNER_CHECKSUMS", "1")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "tix_tcp_push_header_trust_inner")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	kfuncCall, err := loadSKBTIXTTXPushTCPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load TCP header-push kfunc metadata: %v", err)
	}
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true, PushTCPHeaderKfunc: true, PushTCPHeaderKfuncCall: kfuncCall},
	)
	if !instructionsContainMovImmToRegAfterSymbol(out, "kudp_tx_direct_push_outer_tcp_header_kfunc", asm.R3, int64(trustIXTIXTTXFinalizeTCPTrustInnerCSUM)) {
		t.Fatal("tix_tcp TCP header-push kfunc trusted inner checksum opt-in did not pass the trust flag")
	}
	if instructionsContainMovImmToRegAfterSymbol(out, "kudp_tx_direct_push_outer_tcp_header_kfunc", asm.R3, int64(trustIXTIXTTXFinalizeTCPPartialCSUM)) {
		t.Fatal("tix_tcp TCP header-push kfunc emitted partial checksum flag with trusted inner checksum opt-in")
	}
}

func TestKernelUDPTXDirectTIXTCPPathPushTCPHeaderKfuncPartialChecksumOverridesTrust(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_OUTER_TCP_HEADER_KFUNC_PARTIAL_CSUM", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_TRUST_INNER_CHECKSUMS", "1")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "tix_tcp_push_header_partial_over_trust")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	kfuncCall, err := loadSKBTIXTTXPushTCPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load TCP header-push kfunc metadata: %v", err)
	}
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true, PushTCPHeaderKfunc: true, PushTCPHeaderKfuncCall: kfuncCall},
	)
	if !instructionsContainMovImmToRegAfterSymbol(out, "kudp_tx_direct_push_outer_tcp_header_kfunc", asm.R3, int64(trustIXTIXTTXFinalizeTCPPartialCSUM)) {
		t.Fatal("tix_tcp TCP header-push kfunc partial checksum flag missing")
	}
	if instructionsContainMovImmToRegAfterSymbol(out, "kudp_tx_direct_push_outer_tcp_header_kfunc", asm.R3, int64(trustIXTIXTTXFinalizeTCPTrustInnerCSUM)) {
		t.Fatal("tix_tcp TCP header-push kfunc emitted trusted inner checksum flag together with partial checksum")
	}
}

func TestKernelUDPTXDirectTIXTCPPathUsesPushFlowTCPHeaderKfuncWhenAvailable(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM", "0")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "tix_tcp_push_flow_header_kfunc")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	kfuncCall, err := loadSKBTIXTTXPushFlowTCPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load flow TCP header-push kfunc metadata: %v", err)
	}
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word), asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true, PushFlowTCPHeaderKfunc: true, PushFlowTCPHeaderKfuncCall: kfuncCall},
	)
	if !instructionsContainSymbol(out, "kudp_tx_direct_push_flow_outer_tcp_header_kfunc") ||
		!instructionsContainSymbol(out, "kudp_tx_direct_push_flow_outer_tcp_header_kfunc_done") {
		t.Fatal("tix_tcp direct-only TX program does not use flow TCP header-push kfunc")
	}
	if !instructionsContainKfuncCall(out) {
		t.Fatal("tix_tcp direct-only TX program did not emit flow TCP header-push kfunc call")
	}
	if !instructionsContainStoreMem(out, asm.RFP, kernelUDPTXTIXTPushFlowTCPHeaderArgsFlowIDOffset, asm.DWord) ||
		!instructionsContainStoreMem(out, asm.RFP, kernelUDPTXTIXTPushFlowTCPHeaderArgsPayloadLenOffset, asm.Word) {
		t.Fatal("tix_tcp flow TCP header-push path does not initialize flow kfunc args")
	}
	if !instructionsContainStoreMem(out, asm.RFP, kernelUDPTXFlowPtrOffset, asm.DWord) ||
		!instructionsContainLoadMemInto(out, asm.R2, asm.RFP, kernelUDPTXFlowPtrOffset, asm.DWord) {
		t.Fatal("tix_tcp flow TCP header-push path does not preserve the selected flow pointer for the kfunc call")
	}
	if instructionsContainSymbol(out, "kudp_tx_direct_push_outer_tcp_header_kfunc") ||
		instructionsContainSymbol(out, "kudp_tx_direct_adjust_ready") {
		t.Fatal("tix_tcp flow TCP header-push path did not bypass old push/adjust paths")
	}
}

func TestKernelUDPTXDirectPlainHeaderStoreDoesNotSpillFlowPointerIntoHeaderBuffer(t *testing.T) {
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "plain_no_flowptr_spill")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()

	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true},
	)
	if instructionsContainStoreMem(out, asm.RFP, kernelUDPTXFlowPtrOffset, asm.DWord) {
		t.Fatal("plain TC direct path spills flow map pointer inside the TCP/TIXT header buffer")
	}
	if instructionsContainLoadMemInto(out, asm.R2, asm.RFP, kernelUDPTXFlowPtrOffset, asm.DWord) {
		t.Fatal("plain TC direct path reloads unused flow pointer")
	}
}

func TestKernelUDPTXDirectTIXTCPPathUsesFinalizeFlowTCPHeaderKfuncWhenAvailable(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM", "0")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_OUTER_TCP_HEADER_KFUNC_PARTIAL_CSUM", "1")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "tix_tcp_finalize_flow_header_kfunc")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	kfuncCall, err := loadSKBTIXTTXFinalizeFlowTCPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load flow TCP header-finalize kfunc metadata: %v", err)
	}
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word), asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true, FinalizeFlowTCPHeaderKfunc: true, FinalizeFlowTCPHeaderKfuncCall: kfuncCall},
	)
	if !instructionsContainSymbol(out, "kudp_tx_direct_finalize_flow_outer_tcp_header_kfunc") ||
		!instructionsContainSymbol(out, "kudp_tx_direct_finalize_flow_outer_tcp_header_kfunc_done") {
		t.Fatal("tix_tcp direct-only TX program does not use flow TCP header-finalize kfunc")
	}
	if !instructionsContainKfuncCall(out) {
		t.Fatal("tix_tcp direct-only TX program did not emit flow TCP header-finalize kfunc call")
	}
	if !instructionsContainStoreMem(out, asm.RFP, kernelUDPTXTIXTFinalizeFlowTCPHeaderArgsFlowIDOffset, asm.DWord) ||
		!instructionsContainStoreMem(out, asm.RFP, kernelUDPTXTIXTFinalizeFlowTCPHeaderArgsPayloadLenOffset, asm.Word) {
		t.Fatal("tix_tcp flow TCP header-finalize path does not initialize compact flow kfunc args")
	}
	if !instructionsContainStoreMem(out, asm.RFP, kernelUDPTXFlowPtrOffset, asm.DWord) ||
		!instructionsContainLoadMemInto(out, asm.R2, asm.RFP, kernelUDPTXFlowPtrOffset, asm.DWord) {
		t.Fatal("tix_tcp flow TCP header-finalize path does not preserve the selected flow pointer for the kfunc call")
	}
	if instructionsContainStoreMem(out, asm.RFP, kernelUDPTXTIXTFinalizeTCPHeaderArgsSourceIPOffset, asm.Word) ||
		instructionsContainStoreMem(out, asm.RFP, kernelUDPTXTIXTFinalizeTCPHeaderArgsDestinationIPOffset, asm.Word) {
		t.Fatal("tix_tcp flow TCP header-finalize path still builds full TCP header args")
	}
	if !instructionsContainStoreImm(out, asm.RFP, kernelUDPTXTIXTFinalizeFlowTCPHeaderArgsClearFlagsOffset, asm.Word, int64(trustIXTIXTTXFinalizeTCPTrustValidatedLen|trustIXTIXTTXFinalizeTCPPartialCSUM)) {
		t.Fatal("tix_tcp flow TCP header-finalize path did not pass partial checksum flag")
	}
	if !instructionsContainReference(out, "kudp_tx_direct_post_adjust_header_drop") {
		t.Fatal("tix_tcp flow TCP header-finalize path did not keep the post-adjust header guard")
	}
	if !instructionsContainSymbol(out, "kudp_tx_direct_post_adjust_header_drop") {
		t.Fatal("tix_tcp flow TCP header-finalize path references unresolved post-adjust header drop label")
	}
	if instructionsContainStoreMem(out, asm.R7, rejectEthernetHeaderLen+rejectIPv4HeaderLen, asm.Byte) ||
		instructionsContainStoreMem(out, asm.R7, rejectEthernetHeaderLen+rejectIPv4HeaderLen, asm.Half) ||
		instructionsContainStoreMem(out, asm.R7, rejectEthernetHeaderLen+rejectIPv4HeaderLen, asm.Word) {
		t.Fatal("tix_tcp flow TCP header-finalize path still stores the TCP header from the eBPF stack")
	}
}

func TestKernelUDPTXDirectTIXTCPPathUsesPushRouteTCPHeaderKfuncWhenAvailable(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM", "0")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_OUTER_TCP_HEADER_KFUNC_PARTIAL_CSUM", "0")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "tix_tcp_push_route_header_kfunc")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	kfuncCall, err := loadSKBTIXTTXPushRouteTCPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load route TCP header-push kfunc metadata: %v", err)
	}
	flowKfuncCall, err := loadSKBTIXTTXPushFlowTCPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load flow TCP header-push kfunc metadata: %v", err)
	}
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word), asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true, PushRouteTCPHeaderKfunc: true, PushRouteTCPHeaderKfuncCall: kfuncCall, PushFlowTCPHeaderKfunc: true, PushFlowTCPHeaderKfuncCall: flowKfuncCall},
	)
	if !instructionsContainSymbol(out, "kudp_tx_direct_push_route_outer_tcp_header_kfunc") {
		t.Fatal("tix_tcp direct-only TX program does not use route TCP header-push kfunc")
	}
	if !instructionsContainSymbol(out, "kudp_tx_direct_push_flow_outer_tcp_header_kfunc") {
		t.Fatal("tix_tcp route TCP header-push path lost lower-granularity fallback")
	}
	if instructionsContainSymbol(out, "kudp_tx_direct_push_outer_tcp_header_kfunc") ||
		instructionsContainSymbol(out, "kudp_tx_direct_adjust_ready") {
		t.Fatal("tix_tcp route TCP header-push path did not bypass old push/adjust paths")
	}
	if !instructionsContainKfuncCall(out) {
		t.Fatal("tix_tcp direct-only TX program did not emit route TCP header-push kfunc call")
	}
	routeKfuncIndex := instructionSymbolIndex(out, "kudp_tx_direct_push_route_outer_tcp_header_kfunc")
	if routeKfuncIndex < 0 {
		t.Fatal("tix_tcp route TCP header-push kfunc label is missing")
	}
	routeKfuncEntry := out[routeKfuncIndex]
	if routeKfuncEntry.OpCode.Class().IsLoad() &&
		routeKfuncEntry.OpCode.Mode() == asm.MemMode &&
		routeKfuncEntry.Dst == asm.R4 &&
		routeKfuncEntry.Src == asm.R0 &&
		routeKfuncEntry.Offset == 72 &&
		routeKfuncEntry.OpCode.Size() == asm.Word {
		t.Fatal("tix_tcp route TCP header-push kfunc still pre-checks route flow_mask before helper selection")
	}
	if instructionsContainImm(out, int64(trustIXTIXTTXFinalizeTCPTrustInnerCSUM)) {
		t.Fatal("tix_tcp route TCP header-push path should compute a full outer TCP checksum by default")
	}
}

func TestKernelUDPTXDirectTIXTCPPathUsesRouteTCPGSOKfuncWhenAvailable(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM", "0")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_HOT_STATS", "1")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "tix_tcp_route_gso_kfunc")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	routeKfuncCall, err := loadSKBTIXTTXPushRouteTCPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load route TCP header-push kfunc metadata: %v", err)
	}
	gsoKfuncCall, err := loadSKBTIXTTXSegmentRouteTCPGSOKfuncCall()
	if err != nil {
		t.Fatalf("load route TCP GSO kfunc metadata: %v", err)
	}
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word), asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true, PushRouteTCPHeaderKfunc: true, PushRouteTCPHeaderKfuncCall: routeKfuncCall, RouteTCPGSOKfunc: true, RouteTCPGSOKfuncCall: gsoKfuncCall},
	)
	if !instructionsContainSymbol(out, "kudp_tx_direct_route_tcp_kfunc") ||
		!instructionsContainSymbol(out, "kudp_tx_direct_segment_route_tcp_gso_stolen") {
		t.Fatal("tix_tcp direct-only TX program does not use route TCP GSO kfunc")
	}
	if !instructionsContainSymbol(out, "kudp_tx_direct_route_tcp_gso_check") {
		t.Fatal("tix_tcp route TCP GSO path does not gate on skb gso_size")
	}
	if !instructionsContainLoadMemInto(out, asm.R4, asm.R6, skbGSOSizeOffset, asm.Word) {
		t.Fatalf("tix_tcp route TCP GSO path does not read skb gso_size offset %d", skbGSOSizeOffset)
	}
	if !instructionsContainSymbol(out, "kudp_tx_direct_gso_active_accept_counter_done") {
		t.Fatal("tix_tcp route TCP GSO path does not accept active GSO input before the route kfunc")
	}
	if !instructionsContainImmJumpTo(out, 0, "kudp_tx_direct_route_tcp_linear_kfunc") {
		t.Fatal("tix_tcp route TCP GSO path does not send linear skbs through the safe route TCP kfunc fallback")
	}
	if !instructionsContainSymbol(out, "kudp_tx_direct_route_tcp_linear_kfunc") ||
		!instructionsContainSymbol(out, "kudp_tx_direct_route_tcp_linear_success_counter_done") {
		t.Fatal("tix_tcp route TCP GSO path missing safe linear route TCP kfunc fallback")
	}
	if !instructionsContainJump(out, "kudp_tx_direct_route_tcp_linear_kfunc", "kudp_tx_direct_fallback") {
		t.Fatal("tix_tcp route TCP GSO linear kfunc fallback should fall back to userspace when the kfunc cannot handle the skb")
	}
	if instructionsContainSymbol(out, "kudp_tx_direct_route_tcp_single_flow_guard") {
		t.Fatal("tix_tcp route TCP GSO path still rejects multi-flow route entries before helper selection")
	}
	if instructionsContainSymbol(out, "kudp_tx_direct_route_tcp_xmit_stolen") ||
		instructionsContainSymbol(out, "kudp_tx_direct_route_tcp_xmit_queued") {
		t.Fatal("tix_tcp route TCP GSO path emitted route TCP xmit-only result blocks without the xmit kfunc")
	}
	if !instructionsContainKfuncCall(out) {
		t.Fatal("tix_tcp route TCP GSO path did not emit a kfunc call")
	}
	if !instructionsContainImm(out, int64(tixTCPTXRouteGSOSegmentsStolen)) {
		t.Fatal("tix_tcp route TCP GSO path does not recognize the stolen sentinel")
	}
	if !instructionsContainImm(out, -int64(unix.EOPNOTSUPP)) {
		t.Fatal("tix_tcp route TCP GSO path does not fallback on EOPNOTSUPP")
	}
	if !instructionsRouteTCPKfuncUsesCurrentRoutePtr(out) {
		t.Fatal("tix_tcp route TCP kfunc does not pass the current route pointer")
	}
	if duplicates := duplicateInstructionSymbols(out); len(duplicates) > 0 {
		t.Fatalf("duplicate instruction symbols: %v", duplicates)
	}
	if unreachable := unreachableInstructionIndexes(out); len(unreachable) > 0 {
		t.Fatalf("route TCP GSO path emitted verifier-unreachable instructions: %s", describeInstructionIndexes(out, unreachable, 8))
	}
}

func TestKernelUDPTXDirectTIXTCPRouteGSOAsyncHasNoUnreachableInstructions(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_HOT_STATS", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_TRUST_PARTIAL_INNER_CHECKSUM", "1")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "tix_tcp_route_gso_async_reach")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	routeKfuncCall, err := loadSKBTIXTTXPushRouteTCPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load route TCP header-push kfunc metadata: %v", err)
	}
	gsoKfuncCall, err := loadSKBTIXTTXSegmentRouteTCPGSOKfuncCall()
	if err != nil {
		t.Fatalf("load route TCP GSO kfunc metadata: %v", err)
	}
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word), asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true, PushRouteTCPHeaderKfunc: true, PushRouteTCPHeaderKfuncCall: routeKfuncCall, RouteTCPGSOKfunc: true, RouteTCPGSOKfuncCall: gsoKfuncCall, RouteTCPGSOAsyncKfunc: true},
	)
	if unreachable := unreachableInstructionIndexes(out); len(unreachable) > 0 {
		t.Fatalf("route TCP async GSO path emitted verifier-unreachable instructions: %s", describeInstructionIndexes(out, unreachable, 8))
	}
}

func TestKernelUDPTXDirectTIXTCPRouteGSOAsyncCannotEnableActiveGSO(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_SAFE", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC", "1")
	t.Setenv("TRUSTIX_TIX_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_GSO_ASYNC", "1")

	options := kernelUDPTXDirectProgramOptions{TIXTCPOnly: true, DirectOnly: true}
	if kernelUDPTunnelGSOActiveSKBEnabledForOptions(options) {
		t.Fatal("route TCP async GSO opt-in enabled active-GSO without an available route GSO kfunc")
	}
	options.RouteTCPGSOKfunc = true
	if !kernelUDPTunnelGSOActiveSKBEnabledForOptions(options) {
		t.Fatal("route TCP async GSO opt-in should allow active-GSO when the route GSO kfunc is available")
	}
}

func TestKernelUDPTXDirectTIXTCPRouteGSOEnvCombinationEmitsRouteKfuncBeforeAdjustRoom(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_SAFE", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_KERNEL_UDP_ONLY", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_TIX_TCP_ONLY", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_ONLY", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_PUSH_ROUTE_TCP_HEADER_KFUNC", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC", "0")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_OUTER_TCP_HEADER_KFUNC_PARTIAL_CSUM", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM", "0")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "tix_tcp_route_gso_env")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	routeKfuncCall, err := loadSKBTIXTTXPushRouteTCPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load route TCP header-push kfunc metadata: %v", err)
	}
	gsoKfuncCall, err := loadSKBTIXTTXSegmentRouteTCPGSOKfuncCall()
	if err != nil {
		t.Fatalf("load route TCP GSO kfunc metadata: %v", err)
	}
	options := kernelUDPTXDirectProgramOptions{
		Enabled:                     kernelUDPTXDirectProgramEnabled(),
		TIXTCPOnly:                  kernelUDPTXDirectTIXTCPOnlyEnabled(),
		KernelUDPOnly:               kernelUDPTXDirectKernelUDPOnlyEnabled(),
		DirectOnly:                  kernelUDPTXDirectOnlyEnabled(dataplane.AttachSpec{}),
		PushRouteTCPHeaderKfunc:     routeKfuncCall.IsKfuncCall(),
		PushRouteTCPHeaderKfuncCall: routeKfuncCall,
		RouteTCPGSOKfunc:            gsoKfuncCall.IsKfuncCall() && tixTCPTXDirectRouteTCPGSOKfuncRequested(),
		RouteTCPGSOKfuncCall:        gsoKfuncCall,
	}
	if !kernelUDPTunnelGSOEnabledForOptions(options) {
		t.Fatal("route-GSO sync environment did not enable tunnel-GSO handling")
	}
	if !kernelUDPTunnelGSOActiveSKBEnabledForOptions(options) {
		t.Fatal("route-GSO sync environment did not enable active GSO input")
	}
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word), asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word)},
		statsMap,
		routeMap,
		flowMap,
		options,
	)
	routeIndex := instructionSymbolIndex(out, "kudp_tx_direct_route_tcp_kfunc")
	adjustIndex := instructionBuiltinCallIndex(out, asm.FnSkbAdjustRoom)
	if routeIndex < 0 {
		t.Fatalf("tix_tcp route-GSO environment did not emit route TCP kfunc path; options=%+v", options)
	}
	if adjustIndex >= 0 && routeIndex > adjustIndex {
		t.Fatalf("route TCP kfunc appears after adjust_room: routeIndex=%d adjustIndex=%d", routeIndex, adjustIndex)
	}
}

func TestKernelUDPTXDirectTIXTCPRouteTCPGSOFallbackHasResolvedPostAdjustDrop(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM", "0")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "tix_tcp_route_gso_post_drop")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	routeKfuncCall, err := loadSKBTIXTTXPushRouteTCPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load route TCP header-push kfunc metadata: %v", err)
	}
	gsoKfuncCall, err := loadSKBTIXTTXSegmentRouteTCPGSOKfuncCall()
	if err != nil {
		t.Fatalf("load route TCP GSO kfunc metadata: %v", err)
	}
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word), asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true, PushRouteTCPHeaderKfunc: true, PushRouteTCPHeaderKfuncCall: routeKfuncCall, RouteTCPGSOKfunc: true, RouteTCPGSOKfuncCall: gsoKfuncCall},
	)
	if !instructionsContainReference(out, "kudp_tx_direct_post_adjust_header_drop") {
		t.Fatal("tix_tcp route TCP GSO fallback did not keep the post-adjust header guard")
	}
	if !instructionsContainSymbol(out, "kudp_tx_direct_post_adjust_header_drop") {
		t.Fatal("tix_tcp route TCP GSO fallback references unresolved post-adjust header drop label")
	}
}

func TestKernelUDPTXDirectTIXTCPPathUsesRouteTCPXmitKfuncWhenAvailable(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM", "0")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "tix_tcp_route_xmit_kfunc")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	routeKfuncCall, err := loadSKBTIXTTXPushRouteTCPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load route TCP header-push kfunc metadata: %v", err)
	}
	gsoKfuncCall, err := loadSKBTIXTTXSegmentRouteTCPGSOKfuncCall()
	if err != nil {
		t.Fatalf("load route TCP GSO kfunc metadata: %v", err)
	}
	xmitKfuncCall, err := loadSKBTIXTTXRouteTCPXmitKfuncCall()
	if err != nil {
		t.Fatalf("load route TCP xmit kfunc metadata: %v", err)
	}
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word), asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true, PushRouteTCPHeaderKfunc: true, PushRouteTCPHeaderKfuncCall: routeKfuncCall, RouteTCPGSOKfunc: true, RouteTCPGSOKfuncCall: gsoKfuncCall, RouteTCPXmitKfunc: true, RouteTCPXmitKfuncCall: xmitKfuncCall},
	)
	if !instructionsContainSymbol(out, "kudp_tx_direct_route_tcp_kfunc") ||
		!instructionsContainSymbol(out, "kudp_tx_direct_segment_route_tcp_gso_stolen") {
		t.Fatal("tix_tcp route TCP xmit path must preserve the route-GSO branch for GSO skbs")
	}
	if !instructionsContainImmJumpTo(out, 0, "kudp_tx_direct_route_tcp_xmit_kfunc_prepare") {
		t.Fatal("tix_tcp route TCP xmit path should only take linear skbs from the GSO-size gate")
	}
	if !instructionsContainSymbol(out, "kudp_tx_direct_route_tcp_xmit_stolen") {
		t.Fatal("tix_tcp direct-only TX program does not recognize route TCP xmit kfunc stolen sentinel")
	}
	if !instructionsContainImm(out, int64(tixTCPTXRouteXmitStolen)) {
		t.Fatal("tix_tcp route TCP xmit path does not recognize the stolen sentinel")
	}
	if !instructionsContainSymbol(out, "kudp_tx_direct_route_tcp_xmit_queued") {
		t.Fatal("tix_tcp direct-only TX program does not recognize route TCP worker queued sentinel")
	}
	if !instructionsContainImm(out, int64(tixTCPTXRouteXmitQueued)) {
		t.Fatal("tix_tcp route TCP xmit path does not recognize the worker queued sentinel")
	}
	if !instructionsContainSymbol(out, "kudp_tx_direct_route_tcp_gso_redirect") ||
		!instructionsContainReferenceAfterSymbol(out, "kudp_tx_direct_route_tcp_kfunc", "kudp_tx_direct_route_tcp_gso_redirect", 32) {
		t.Fatal("tix_tcp route TCP xmit path must redirect positive route-GSO kfunc returns instead of dropping them")
	}
	routeIndex := instructionSymbolIndex(out, "kudp_tx_direct_route_tcp_kfunc")
	xmitPrepareIndex := instructionSymbolIndex(out, "kudp_tx_direct_route_tcp_xmit_kfunc_prepare")
	if routeIndex < 0 || xmitPrepareIndex < 0 || routeIndex >= xmitPrepareIndex {
		t.Fatalf("route TCP GSO/xmit block order is invalid: routeIndex=%d xmitPrepareIndex=%d", routeIndex, xmitPrepareIndex)
	}
	for i := routeIndex; i < xmitPrepareIndex; i++ {
		if out[i].OpCode.Class() == asm.JumpClass &&
			out[i].OpCode.JumpOp() == asm.Ja &&
			out[i].Reference() == "kudp_tx_direct_adjust_drop" {
			t.Fatal("tix_tcp route TCP xmit path still drops positive route-GSO kfunc returns")
		}
	}
	if !instructionsContainReferenceAfterSymbol(out, "kudp_tx_direct_route_tcp_xmit_fallback", "kudp_tx_direct_route_tcp_linear_kfunc", 16) {
		t.Fatal("tix_tcp route TCP xmit fallback does not return to the safe linear route TCP kfunc")
	}
	if unreachable := unreachableInstructionIndexes(out); len(unreachable) > 0 {
		t.Fatalf("route TCP xmit path emitted verifier-unreachable instructions: %s", describeInstructionIndexes(out, unreachable, 8))
	}
}

func TestKernelUDPTXDirectTIXTCPRouteXmitHotStatsHasUniqueSymbols(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_HOT_STATS", "1")
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM", "0")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "tix_tcp_route_xmit_hotstats")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	routeKfuncCall, err := loadSKBTIXTTXPushRouteTCPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load route TCP header-push kfunc metadata: %v", err)
	}
	gsoKfuncCall, err := loadSKBTIXTTXSegmentRouteTCPGSOKfuncCall()
	if err != nil {
		t.Fatalf("load route TCP GSO kfunc metadata: %v", err)
	}
	xmitKfuncCall, err := loadSKBTIXTTXRouteTCPXmitKfuncCall()
	if err != nil {
		t.Fatalf("load route TCP xmit kfunc metadata: %v", err)
	}
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word), asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true, PushRouteTCPHeaderKfunc: true, PushRouteTCPHeaderKfuncCall: routeKfuncCall, RouteTCPGSOKfunc: true, RouteTCPGSOKfuncCall: gsoKfuncCall, RouteTCPXmitKfunc: true, RouteTCPXmitKfuncCall: xmitKfuncCall},
	)
	if duplicates := duplicateInstructionSymbols(out); len(duplicates) > 0 {
		t.Fatalf("duplicate instruction symbols: %v", duplicates)
	}
}

func TestKernelUDPTXDirectTIXTCPPathRouteTCPGSOKfuncCanTrustPartialInnerChecksum(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM", "0")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_OUTER_TCP_HEADER_KFUNC_PARTIAL_CSUM", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_GSO_TRUST_PARTIAL_INNER_CHECKSUM", "1")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "tix_tcp_route_gso_trust_partial")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	routeKfuncCall, err := loadSKBTIXTTXPushRouteTCPHeaderKfuncCall()
	if err != nil {
		t.Fatalf("load route TCP header-push kfunc metadata: %v", err)
	}
	gsoKfuncCall, err := loadSKBTIXTTXSegmentRouteTCPGSOKfuncCall()
	if err != nil {
		t.Fatalf("load route TCP GSO kfunc metadata: %v", err)
	}
	out := appendKernelUDPTXDirect(
		asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word), asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word)},
		statsMap,
		routeMap,
		flowMap,
		kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true, PushRouteTCPHeaderKfunc: true, PushRouteTCPHeaderKfuncCall: routeKfuncCall, RouteTCPGSOKfunc: true, RouteTCPGSOKfuncCall: gsoKfuncCall},
	)
	gsoFlags := int64(trustIXTIXTTXFinalizeTCPPartialCSUM | trustIXTIXTTXFinalizeTCPTrustPartialInnerCSUM)
	if !instructionsStoreImmNearSymbol(out, "kudp_tx_direct_route_tcp_kfunc", kernelUDPTXTIXTSegmentRouteTCPGSOArgsClearFlagsOffset, gsoFlags, 8) {
		t.Fatal("tix_tcp route TCP GSO path did not pass trust-partial-inner flag to the GSO kfunc")
	}
	if !instructionsStoreImmNearSymbol(out, "kudp_tx_direct_route_tcp_linear_kfunc", kernelUDPTXTIXTPushRouteTCPHeaderArgsClearFlagsOffset, int64(trustIXTIXTTXFinalizeTCPPartialCSUM), 4) {
		t.Fatal("tix_tcp route TCP GSO linear fallback should keep normal partial checksum flags without trusting partial inner checksums")
	}
}

func TestKernelUDPTXDirectTIXTCPPathTrustsNormalizedCapturedChecksumsByDefault(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_TRUST_CAPTURED_CHECKSUMS", "1")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "tix_tcp_trusted_capture")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	out := appendKernelUDPTXDirect(asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}, statsMap, routeMap, flowMap, kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true})
	if instructionsContainSymbol(out, "kudp_tx_direct_inner_tixt_pre_csum_tcp") {
		t.Fatal("tix_tcp direct-only TX program re-normalized inner TCP checksums despite trusted captured checksums")
	}
}

func TestKernelUDPTXDirectTIXTCPPathSkipsChunkedChecksumWhenOuterChecksumDisabled(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM", "1")
	statsMap, routeMap, flowMap := newKernelUDPTXDirectInstructionTestMaps(t, "tix_tcp_skip_outer_checksum")
	defer statsMap.Close()
	defer routeMap.Close()
	defer flowMap.Close()
	out := appendKernelUDPTXDirect(asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}, statsMap, routeMap, flowMap, kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true})
	if instructionsContainSymbol(out, "kudp_tx_direct_tcp_csum_payload_chunk_0_next") {
		t.Fatal("tix_tcp skip-outer-checksum direct TX kept the outer checksum scanner")
	}
}

func newKernelUDPTXDirectInstructionTestMaps(t *testing.T, suffix string) (*cebpf.Map, *cebpf.Map, *cebpf.Map) {
	t.Helper()
	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_stats_" + suffix, Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	routeMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_route_" + suffix, Type: cebpf.LPMTrie, KeySize: 8, ValueSize: kernelUDPTXRouteValueSize, MaxEntries: 16, Flags: 1})
	flowMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_flow_" + suffix, Type: cebpf.Hash, KeySize: 8, ValueSize: kernelUDPTXFlowValueSize, MaxEntries: 16})
	return statsMap, routeMap, flowMap
}

func TestIngressDirectOnlyDropsCaptureRoute(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ingress fast path verifier test requires Linux")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap := newIngressFastPathTestMaps(t)
	defer statsMap.Close()
	defer packetPolicyMap.Close()
	defer routeMap.Close()
	defer kernelUDPTXRouteMap.Close()
	defer kernelUDPTXFlowMap.Close()
	defer natConfigMap.Close()
	defer natSourceMap.Close()
	defer natRouteMap.Close()
	defer natExcludeMap.Close()
	defer captureMap.Close()

	program, err := loadIngressFastPathProgram("trustix_ingress_direct_only_capture_drop_test", statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap, kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true})
	if err != nil {
		t.Fatalf("load ingress fast path direct-only capture drop program: %v", err)
	}
	defer program.Close()
}

func TestEgressDirectOnlyDropsCaptureRoute(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("egress fast path verifier test requires Linux")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap := newIngressFastPathTestMaps(t)
	defer statsMap.Close()
	defer packetPolicyMap.Close()
	defer routeMap.Close()
	defer kernelUDPTXRouteMap.Close()
	defer kernelUDPTXFlowMap.Close()
	defer natConfigMap.Close()
	defer natSourceMap.Close()
	defer natRouteMap.Close()
	defer natExcludeMap.Close()
	defer captureMap.Close()
	natBindingMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_nat_bindings_egress_direct_only_capture_drop_test", Type: cebpf.Hash, KeySize: 20, ValueSize: 16, MaxEntries: 16})
	defer natBindingMap.Close()

	program, err := loadEgressFastPathProgram("trustix_egress_direct_only_capture_drop_test", statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, natBindingMap, captureMap, kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true})
	if err != nil {
		t.Fatalf("load egress fast path direct-only capture drop program: %v", err)
	}
	defer program.Close()
}

func TestIngressFastPathProgramLoadsWithTunnelGSO(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ingress fast path verifier test requires Linux")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_NO_CSUM_RESET", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "1")
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap := newIngressFastPathTestMaps(t)
	defer statsMap.Close()
	defer packetPolicyMap.Close()
	defer routeMap.Close()
	defer kernelUDPTXRouteMap.Close()
	defer kernelUDPTXFlowMap.Close()
	defer natConfigMap.Close()
	defer natSourceMap.Close()
	defer natRouteMap.Close()
	defer natExcludeMap.Close()
	defer captureMap.Close()

	program, err := loadIngressFastPathProgram("trustix_ingress_gso_test", statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap, kernelUDPTXDirectProgramOptions{Enabled: true})
	if err != nil {
		t.Fatalf("load ingress fast path tunnel GSO program: %v", err)
	}
	defer program.Close()
}

func TestEgressFastPathProgramLoads(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("egress fast path verifier test requires Linux")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap := newIngressFastPathTestMaps(t)
	defer statsMap.Close()
	defer packetPolicyMap.Close()
	defer routeMap.Close()
	defer kernelUDPTXRouteMap.Close()
	defer kernelUDPTXFlowMap.Close()
	defer natConfigMap.Close()
	defer natSourceMap.Close()
	defer natRouteMap.Close()
	defer natExcludeMap.Close()
	defer captureMap.Close()
	natBindingMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_nat_bindings_egress_load_test", Type: cebpf.Hash, KeySize: 20, ValueSize: 16, MaxEntries: 16})
	defer natBindingMap.Close()

	program, err := loadEgressFastPathProgram("trustix_egress_test", statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, natBindingMap, captureMap, kernelUDPTXDirectProgramOptions{Enabled: true})
	if err != nil {
		t.Fatalf("load egress fast path program: %v", err)
	}
	defer program.Close()
}

func TestEgressFastPathProgramLoadsWithKernelUDPTXDirectOnly(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("egress fast path verifier test requires Linux")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap := newIngressFastPathTestMaps(t)
	defer statsMap.Close()
	defer packetPolicyMap.Close()
	defer routeMap.Close()
	defer kernelUDPTXRouteMap.Close()
	defer kernelUDPTXFlowMap.Close()
	defer natConfigMap.Close()
	defer natSourceMap.Close()
	defer natRouteMap.Close()
	defer natExcludeMap.Close()
	defer captureMap.Close()
	natBindingMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_nat_bindings_egress_direct_only_load_test", Type: cebpf.Hash, KeySize: 20, ValueSize: 16, MaxEntries: 16})
	defer natBindingMap.Close()

	program, err := loadEgressFastPathProgram("trustix_egress_direct_only_test", statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, natBindingMap, captureMap, kernelUDPTXDirectProgramOptions{Enabled: true, DirectOnly: true})
	if err != nil {
		t.Fatalf("load egress fast path direct-only program: %v", err)
	}
	defer program.Close()
}

func TestEgressFastPathProgramLoadsWithTIXTCPDirectOnly(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("egress fast path verifier test requires Linux")
	}
	t.Setenv("TRUSTIX_TIX_TCP_SKIP_TCP_CHECKSUM", "1")
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap := newIngressFastPathTestMaps(t)
	defer statsMap.Close()
	defer packetPolicyMap.Close()
	defer routeMap.Close()
	defer kernelUDPTXRouteMap.Close()
	defer kernelUDPTXFlowMap.Close()
	defer natConfigMap.Close()
	defer natSourceMap.Close()
	defer natRouteMap.Close()
	defer natExcludeMap.Close()
	defer captureMap.Close()
	natBindingMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_nat_bindings_egress_exp_direct_only_test", Type: cebpf.Hash, KeySize: 20, ValueSize: 16, MaxEntries: 16})
	defer natBindingMap.Close()

	program, err := loadEgressFastPathProgram("trustix_egress_exp_direct_only_test", statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, natBindingMap, captureMap, kernelUDPTXDirectProgramOptions{Enabled: true, TIXTCPOnly: true, DirectOnly: true})
	if err != nil {
		t.Fatalf("load egress fast path tix_tcp direct-only program: %v", err)
	}
	defer program.Close()
}

func TestEgressFastPathProgramLoadsWithTunnelGSO(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("egress fast path verifier test requires Linux")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_NO_CSUM_RESET", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO", "1")
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap := newIngressFastPathTestMaps(t)
	defer statsMap.Close()
	defer packetPolicyMap.Close()
	defer routeMap.Close()
	defer kernelUDPTXRouteMap.Close()
	defer kernelUDPTXFlowMap.Close()
	defer natConfigMap.Close()
	defer natSourceMap.Close()
	defer natRouteMap.Close()
	defer natExcludeMap.Close()
	defer captureMap.Close()
	natBindingMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_nat_bindings_egress_gso_load_test", Type: cebpf.Hash, KeySize: 20, ValueSize: 16, MaxEntries: 16})
	defer natBindingMap.Close()

	program, err := loadEgressFastPathProgram("trustix_egress_gso_test", statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, natBindingMap, captureMap, kernelUDPTXDirectProgramOptions{Enabled: true})
	if err != nil {
		t.Fatalf("load egress fast path tunnel GSO program: %v", err)
	}
	defer program.Close()
}

func TestKernelUDPRXDirectProgramLoads(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp RX direct verifier test requires Linux")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_stats_rx_direct_test", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	defer statsMap.Close()
	portMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_direct_port_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: 16})
	defer portMap.Close()
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_neigh_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 16})
	defer neighMap.Close()

	program, err := loadKernelUDPRXDirectProgram("trustix_kudp_rx_test", statsMap, portMap, neighMap, 1, net.HardwareAddr{2, 0, 0, 0, 0, 1})
	if err != nil {
		t.Fatalf("load kernel_udp RX direct program: %v", err)
	}
	defer program.Close()
}

func TestKernelUDPRXDirectProgramLoadsWithTIXTPath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp RX direct verifier test requires Linux")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_stats_rx_tixt_direct_test", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	defer statsMap.Close()
	portMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tixt_rx_direct_port_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: 16})
	defer portMap.Close()
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tixt_rx_neigh_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 16})
	defer neighMap.Close()

	program, err := loadKernelUDPRXDirectProgramWithOptions("trustix_tixt_rx_test", statsMap, portMap, neighMap, 1, net.HardwareAddr{2, 0, 0, 0, 0, 1}, kernelUDPRXDirectProgramOptions{Broadcast: true})
	if err != nil {
		t.Fatalf("load tix_tcp TIXT RX direct program: %v", err)
	}
	defer program.Close()
}

func TestKernelUDPRXDirectAcceptsSegmentedGSOTails(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp RX direct packet test requires Linux")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_HOT_STATS", "1")
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF packet test: %v", err)
	}
	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_stats_rx_gso_tail_test", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	defer statsMap.Close()
	portMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_rx_gso_tail_port_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: 16})
	defer portMap.Close()
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_rx_gso_tail_neigh_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 16})
	defer neighMap.Close()

	program, err := loadKernelUDPRXDirectProgramWithOptions(
		"trustix_rx_gso_tail_test",
		statsMap,
		portMap,
		neighMap,
		1,
		net.HardwareAddr{2, 0, 0, 0, 0, 1},
		kernelUDPRXDirectProgramOptions{Broadcast: true},
	)
	if err != nil {
		t.Fatalf("load kernel_udp RX GSO-tail program: %v", err)
	}
	defer program.Close()

	inner := ipv4PacketForXDPTCRXDirectTest()
	udpPacket := mustKernelUDPXDPEthernetFrame(t, kerneludp.Frame{
		Flags:    kerneludp.FlagInnerIPv4,
		FlowID:   11,
		Sequence: 12,
		Payload:  inner,
	}, 17001)
	binary.BigEndian.PutUint32(udpPacket[66:70], 1130)

	tcpFrame := tixtcp.Frame{Flags: tixtcp.FlagInnerIPv4, FlowID: 21, Sequence: 22, Payload: inner}
	tcpFrameLen, err := tixtcp.FrameWireLen(len(inner))
	if err != nil {
		t.Fatalf("tix_tcp frame length: %v", err)
	}
	tcpPacketLen, err := tixtcp.TCPShapedIPv4WireLen(tcpFrameLen)
	if err != nil {
		t.Fatalf("tix_tcp packet length: %v", err)
	}
	tcpPacket := make([]byte, ethernetHeaderLen+tcpPacketLen)
	copy(tcpPacket[0:6], []byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01})
	copy(tcpPacket[6:12], []byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02})
	binary.BigEndian.PutUint16(tcpPacket[12:14], etherTypeIPv4)
	if _, err := tixtcp.MarshalTCPShapedIPv4FrameIntoSkipTCPChecksum(tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.10"),
		DestinationIP:   netip.MustParseAddr("198.51.100.20"),
		SourcePort:      43000,
		DestinationPort: 17002,
		Acknowledgment:  1,
	}, tcpFrame, tcpPacket[ethernetHeaderLen:]); err != nil {
		t.Fatalf("marshal tix_tcp GSO tail: %v", err)
	}
	binary.BigEndian.PutUint32(tcpPacket[86:90], 1130)

	for name, packet := range map[string][]byte{"udp": udpPacket, "tix_tcp": tcpPacket} {
		if _, _, err := program.Test(packet); err != nil {
			t.Fatalf("run %s GSO-tail packet: %v", name, err)
		}
	}
	if got, err := bpfCounterValue(statsMap, kernelUDPRXDirectStatGSOTailSegments); err != nil || got != 2 {
		t.Fatalf("GSO-tail counter = %d, %v; want 2", got, err)
	}
	if got, err := bpfCounterValue(statsMap, kernelUDPRXDirectStatInnerLenErrors); err != nil || got != 0 {
		t.Fatalf("inner-length errors after valid tails = %d, %v; want 0", got, err)
	}

	for name, packet := range map[string][]byte{"udp": udpPacket, "tix_tcp": tcpPacket} {
		invalid := append([]byte(nil), packet...)
		innerOffset := 74
		if name == "tix_tcp" {
			innerOffset = 94
		}
		invalid[innerOffset+9] = ipProtocolUDP
		if _, _, err := program.Test(invalid); err != nil {
			t.Fatalf("run %s non-TCP length mismatch: %v", name, err)
		}
	}
	if got, err := bpfCounterValue(statsMap, kernelUDPRXDirectStatGSOTailSegments); err != nil || got != 2 {
		t.Fatalf("GSO-tail counter after invalid packets = %d, %v; want 2", got, err)
	}
	if got, err := bpfCounterValue(statsMap, kernelUDPRXDirectStatInnerLenErrors); err != nil || got != 2 {
		t.Fatalf("inner-length errors after invalid packets = %d, %v; want 2", got, err)
	}
}

func TestKernelUDPRXDirectKernelUDPOnlyProgramLoads(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp RX direct verifier test requires Linux")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_stats_rx_udp_only_test", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	defer statsMap.Close()
	portMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_udp_only_rx_direct_port_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: 16})
	defer portMap.Close()
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_udp_only_rx_neigh_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 16})
	defer neighMap.Close()

	program, err := loadKernelUDPRXDirectProgramWithOptions("trustix_udp_only_rx_test", statsMap, portMap, neighMap, 1, net.HardwareAddr{2, 0, 0, 0, 0, 1}, kernelUDPRXDirectProgramOptions{Broadcast: true, KernelUDPOnly: true})
	if err != nil {
		t.Fatalf("load kernel_udp-only RX direct program: %v", err)
	}
	defer program.Close()
}

func TestKernelUDPRXDirectMagicWireOrder(t *testing.T) {
	if got, want := htonl(tixtcp.Magic), binary.LittleEndian.Uint32([]byte{'T', 'I', 'X', 'T'}); got != want {
		t.Fatalf("TIXT magic wire-order immediate = %#x, want %#x", got, want)
	}
	if got, want := htonl(kerneludp.Magic), binary.LittleEndian.Uint32([]byte{'T', 'I', 'X', 'U'}); got != want {
		t.Fatalf("TIXU magic wire-order immediate = %#x, want %#x", got, want)
	}
}

func TestKernelUDPRXDirectBroadcastProgramLoads(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp RX direct verifier test requires Linux")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_stats_rx_broadcast_test", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	defer statsMap.Close()
	portMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_broadcast_port_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: 16})
	defer portMap.Close()
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_broadcast_neigh_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 16})
	defer neighMap.Close()

	program, err := loadKernelUDPRXDirectProgramWithOptions("trustix_kudp_rxb_test", statsMap, portMap, neighMap, 1, net.HardwareAddr{2, 0, 0, 0, 0, 1}, kernelUDPRXDirectProgramOptions{Broadcast: true})
	if err != nil {
		t.Fatalf("load kernel_udp broadcast RX direct program: %v", err)
	}
	defer program.Close()
}

func TestKernelUDPRXDirectBroadcastNoChecksumResetProgramLoads(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp RX direct verifier test requires Linux")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_NO_CSUM_RESET", "1")
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_stats_rx_bcast_nocs_test", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	defer statsMap.Close()
	portMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_bcast_nocs_port_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: 16})
	defer portMap.Close()
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_bcast_nocs_neigh_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 16})
	defer neighMap.Close()

	program, err := loadKernelUDPRXDirectProgramWithOptions("trustix_kudp_rxnc_test", statsMap, portMap, neighMap, 1, net.HardwareAddr{2, 0, 0, 0, 0, 1}, kernelUDPRXDirectProgramOptions{Broadcast: true})
	if err != nil {
		t.Fatalf("load kernel_udp broadcast RX direct no-csum-reset program: %v", err)
	}
	defer program.Close()
}

func TestKernelUDPRXDirectBroadcastIngressRedirectProgramLoads(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp RX direct verifier test requires Linux")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_stats_rx_bcast_ing_test", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	defer statsMap.Close()
	portMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_bcast_ing_port_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: 16})
	defer portMap.Close()
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_bcast_ing_neigh_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 16})
	defer neighMap.Close()

	program, err := loadKernelUDPRXDirectProgramWithOptions("trustix_kudp_rxbi_test", statsMap, portMap, neighMap, 1, net.HardwareAddr{2, 0, 0, 0, 0, 1}, kernelUDPRXDirectProgramOptions{Broadcast: true, RedirectIngress: true, DirectOnly: true})
	if err != nil {
		t.Fatalf("load kernel_udp broadcast ingress RX direct program: %v", err)
	}
	defer program.Close()
}

func TestKernelUDPRXDirectLocalDeliverProgramLoads(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp RX direct verifier test requires Linux")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_stats_rx_local_deliver_test", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	defer statsMap.Close()
	portMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_local_deliver_port_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: 16})
	defer portMap.Close()
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_local_deliver_neigh_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 16})
	defer neighMap.Close()

	program, err := loadKernelUDPRXDirectProgramWithOptions("trustix_kudp_rxld_test", statsMap, portMap, neighMap, 1, net.HardwareAddr{2, 0, 0, 0, 0, 1}, kernelUDPRXDirectProgramOptions{
		Broadcast:       true,
		RedirectIngress: true,
		DirectOnly:      true,
		KernelUDPOnly:   true,
		LocalDeliver:    true,
		LocalIPv4:       binary.LittleEndian.Uint32([]byte{10, 0, 0, 1}),
	})
	if err != nil {
		t.Fatalf("load kernel_udp local-deliver RX direct program: %v", err)
	}
	defer program.Close()
}

func TestKernelUDPRXDirectLocalDeliverUsesPrefixMask(t *testing.T) {
	instructions := appendKernelUDPRXDirectLocalDeliverMatch(nil, kernelUDPRXDirectProgramOptions{
		LocalIPv4:     binary.LittleEndian.Uint32([]byte{10, 0, 0, 1}),
		LocalIPv4Mask: ipv4MaskKeyFromPrefixBits(24),
	}, "miss")

	if !instructionsContainImm(instructions, int64(binary.LittleEndian.Uint32([]byte{10, 0, 0, 1}))) {
		t.Fatal("local-deliver prefix match did not include local IPv4")
	}
	if !instructionsContainImm(instructions, int64(ipv4MaskKeyFromPrefixBits(24))) {
		t.Fatal("local-deliver prefix match did not include /24 mask")
	}
	if !instructionsContainSymbolOrReference(instructions, "miss") {
		t.Fatal("local-deliver prefix match did not branch to miss label")
	}
}

func TestKernelUDPRXDirectOptionsForLink(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_BROADCAST_DIRECT", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_PEER_REDIRECT", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_KERNEL_UDP_ONLY", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_UDP_ONLY", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "1")
	t.Setenv("TRUSTIX_E2E_TIX_TCP_TC_TX_DIRECT", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_ONLY", "")
	t.Setenv("TRUSTIX_E2E_TIX_TCP_TC_TX_DIRECT_ONLY", "")
	if got := kernelUDPRXDirectOptionsForLink(&netlink.Veth{}); got != (kernelUDPRXDirectProgramOptions{RedirectPeer: true, Broadcast: true}) {
		t.Fatalf("veth RX direct options = %+v", got)
	}
	if got := kernelUDPRXDirectOptionsForLink(&netlink.Dummy{}); got != (kernelUDPRXDirectProgramOptions{}) {
		t.Fatalf("dummy RX direct options = %+v", got)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_BROADCAST_DIRECT", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_PEER_REDIRECT", "0")
	if got := kernelUDPRXDirectOptionsForLink(&netlink.Dummy{}); got != (kernelUDPRXDirectProgramOptions{Broadcast: true}) {
		t.Fatalf("forced broadcast RX direct options = %+v", got)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_BROADCAST_DIRECT", "0")
	if got := kernelUDPRXDirectOptionsForLink(&netlink.Veth{}); got != (kernelUDPRXDirectProgramOptions{}) {
		t.Fatalf("disabled broadcast RX direct options = %+v", got)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_BROADCAST_DIRECT", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_PEER_REDIRECT", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "1")
	if got := kernelUDPRXDirectOptionsForLink(&netlink.Veth{}); got != (kernelUDPRXDirectProgramOptions{RedirectPeer: true, Broadcast: true, DirectOnly: true}) {
		t.Fatalf("direct-only veth RX direct options = %+v", got)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_KERNEL_UDP_ONLY", "1")
	if got := kernelUDPRXDirectOptionsForLink(&netlink.Veth{}); got != (kernelUDPRXDirectProgramOptions{RedirectPeer: true, Broadcast: true, KernelUDPOnly: true, DirectOnly: true, DestinationPortOnly: true}) {
		t.Fatalf("kernel_udp-only veth RX direct options = %+v", got)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT_DESTINATION_PORT_ONLY", "")
	if got := kernelUDPRXDirectOptionsForLink(&netlink.Veth{}); got != (kernelUDPRXDirectProgramOptions{RedirectPeer: true, Broadcast: true, KernelUDPOnly: true, DirectOnly: true, DestinationPortOnly: true}) {
		t.Fatalf("kernel_udp-only direct-only veth RX direct options = %+v", got)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT_DESTINATION_PORT_ONLY", "0")
	if got := kernelUDPRXDirectOptionsForLink(&netlink.Veth{}); got != (kernelUDPRXDirectProgramOptions{RedirectPeer: true, Broadcast: true, KernelUDPOnly: true, DirectOnly: true}) {
		t.Fatalf("destination-port-only disabled veth RX direct options = %+v", got)
	}
}

func TestKernelUDPRXDirectOptionsFollowAttachSpecAndDummyDirectOnly(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_BROADCAST_DIRECT", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_PEER_REDIRECT", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_KERNEL_UDP_ONLY", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_UDP_ONLY", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT", "")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_ONLY", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")

	spec := dataplane.AttachSpec{KernelUDPTXDirectOnly: true}
	if got := kernelUDPRXDirectOptionsForLinkWithSpec(&netlink.Dummy{}, spec); got != (kernelUDPRXDirectProgramOptions{Broadcast: true, RedirectIngress: true, DirectOnly: true}) {
		t.Fatalf("dummy direct-only RX direct options = %+v", got)
	}
	if got := kernelUDPRXDirectOptionsForLinkWithSpec(&netlink.Veth{}, spec); got != (kernelUDPRXDirectProgramOptions{RedirectPeer: true, Broadcast: true, DirectOnly: true}) {
		t.Fatalf("veth direct-only RX direct options from spec = %+v", got)
	}
}

func TestKernelUDPRXDirectDummyIngressUsesLocalMACDestination(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp RX direct option test requires Linux maps")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")
	manager := NewManager()
	manager.spec = dataplane.AttachSpec{KernelUDPTXDirectOnly: true}
	manager.statsMap = newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_stats_rx_dummy_mac_test", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	defer manager.statsMap.Close()
	portMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_dummy_mac_port_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: 16})
	defer portMap.Close()
	manager.kernelTransportPortMap = portMap
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_dummy_mac_neigh_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 16})
	defer neighMap.Close()
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Name:         "dummy0",
		Index:        10,
		HardwareAddr: net.HardwareAddr{2, 1, 2, 3, 4, 5},
	}}
	options, program, err := manager.loadKernelUDPRXDirectProgramForLink("trustix_kudp_rxdmac_test", neighMap, link, link.Attrs().HardwareAddr)
	if err != nil {
		t.Fatalf("load kernel_udp dummy ingress RX direct program: %v", err)
	}
	defer program.Close()
	if !options.Broadcast || !options.RedirectIngress {
		t.Fatalf("dummy RX direct options = %+v, want broadcast ingress", options)
	}
	if got := net.HardwareAddr(options.BroadcastDestination[:]).String(); got != link.Attrs().HardwareAddr.String() {
		t.Fatalf("dummy ingress broadcast destination = %s, want local MAC %s", got, link.Attrs().HardwareAddr)
	}
}

func TestKernelUDPRXDirectDestinationPortOnlyProgramLoads(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp RX direct verifier test requires Linux")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_stats_rx_dst_port_test", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	defer statsMap.Close()
	portMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_dst_port_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: 16})
	defer portMap.Close()
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_dst_neigh_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 16})
	defer neighMap.Close()

	program, err := loadKernelUDPRXDirectProgramWithOptions("trustix_kudp_rxdst_test", statsMap, portMap, neighMap, 1, net.HardwareAddr{2, 0, 0, 0, 0, 1}, kernelUDPRXDirectProgramOptions{Broadcast: true, KernelUDPOnly: true, DirectOnly: true, DestinationPortOnly: true})
	if err != nil {
		t.Fatalf("load kernel_udp destination-port-only RX direct program: %v", err)
	}
	defer program.Close()
}

func TestKernelUDPRXDirectParseDecapL2KfuncProgramLoads(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp RX direct verifier test requires Linux")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_stats_rx_parse_decap_test", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	defer statsMap.Close()
	portMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_parse_decap_port_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: 16})
	defer portMap.Close()
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_parse_decap_neigh_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 16})
	defer neighMap.Close()
	kfuncCall, err := loadSKBKernelUDPRXParseDecapL2KfuncCall()
	if err != nil {
		t.Fatalf("load RX parse+decap L2 kfunc metadata: %v", err)
	}

	program, err := loadKernelUDPRXDirectProgramWithOptions(
		"trustix_kudp_rx_parse_decap_test",
		statsMap,
		portMap,
		neighMap,
		1,
		net.HardwareAddr{2, 0, 0, 0, 0, 1},
		kernelUDPRXDirectProgramOptions{
			Broadcast:             true,
			TIXTCPOnly:            true,
			DirectOnly:            true,
			DestinationPortOnly:   true,
			StaticDestinationPort: 18001,
			ParseDecapL2Kfunc:     true,
			ParseDecapL2KfuncCall: kfuncCall,
			TrustInnerChecksum:    true,
		},
	)
	if err != nil {
		skipIfKernelKfuncUnavailable(t, err)
		t.Fatalf("load kernel_udp parse+decap RX direct program: %v", err)
	}
	defer program.Close()
}

func TestKernelUDPRXDirectParseDecapL2KfuncProgramLoadsWithLocalDeliverDev(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel_udp RX direct verifier test requires Linux")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("raise memlock limit for BPF verifier test: %v", err)
	}
	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_stats_rx_parse_decap_dev_test", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	defer statsMap.Close()
	portMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_parse_decap_dev_port_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: 16})
	defer portMap.Close()
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_parse_decap_dev_neigh_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 16})
	defer neighMap.Close()
	kfuncCall, err := loadSKBKernelUDPRXParseDecapL2KfuncCall()
	if err != nil {
		t.Fatalf("load RX parse+decap L2 kfunc metadata: %v", err)
	}

	program, err := loadKernelUDPRXDirectProgramWithOptions(
		"trustix_kudp_rx_parse_decap_dev_test",
		statsMap,
		portMap,
		neighMap,
		7,
		net.HardwareAddr{2, 0, 0, 0, 0, 1},
		kernelUDPRXDirectProgramOptions{
			Broadcast:             true,
			TIXTCPOnly:            true,
			DirectOnly:            true,
			DestinationPortOnly:   true,
			StaticDestinationPort: 18001,
			ParseDecapL2Kfunc:     true,
			ParseDecapL2KfuncCall: kfuncCall,
			LocalDeliver:          true,
			LocalDeliverDev:       true,
			LocalDeliverIfindex:   7,
			LocalIPv4:             binary.LittleEndian.Uint32([]byte{10, 0, 0, 1}),
			LocalIPv4Mask:         ipv4MaskKeyFromPrefixBits(24),
			TrustInnerChecksum:    true,
		},
	)
	if err != nil {
		skipIfKernelKfuncUnavailable(t, err)
		t.Fatalf("load kernel_udp parse+decap local-deliver-dev RX direct program: %v", err)
	}
	defer program.Close()
}

func TestKernelUDPRXDirectStaticDestinationPortUsesLocalListenPort(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT_STATIC_DESTINATION_PORT", "")
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
		Endpoints: []dataplane.EndpointMetadata{
			{ID: "local", Peer: "ix-a", Transport: "udp", Listen: "198.18.0.1:17001", Enabled: true},
			{ID: "remote", Peer: "ix-b", Transport: "udp", Address: "198.18.0.2:17002", Enabled: true},
		},
		Peers: []dataplane.PeerMetadata{{ID: "ix-b", Trusted: true}},
	}
	manager.kernelUDPAllowed = map[uint16]struct{}{
		17001: {},
		41000: {},
		42000: {},
	}

	got := manager.kernelUDPRXDirectStaticDestinationPortLocked(kernelUDPRXDirectProgramOptions{
		KernelUDPOnly:       true,
		DirectOnly:          true,
		DestinationPortOnly: true,
	})
	if got != 17001 {
		t.Fatalf("static destination port = %d, want local listen port 17001", got)
	}
}

func TestKernelUDPRXDirectStaticDestinationPortIgnoresOtherTransportPorts(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT_STATIC_DESTINATION_PORT", "")
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
		Endpoints: []dataplane.EndpointMetadata{
			{ID: "local-udp", Peer: "ix-a", Transport: "udp", Listen: "198.18.0.1:17001", Enabled: true},
			{ID: "remote-udp", Peer: "ix-b", Transport: "udp", Address: "198.18.0.2:17002", Enabled: true},
			{ID: "local-tcp", Peer: "ix-a", Transport: "tix_tcp", Listen: "198.18.0.1:18001", Enabled: true},
			{ID: "remote-tcp", Peer: "ix-b", Transport: "tix_tcp", Address: "198.18.0.2:18002", Enabled: true},
		},
		Peers: []dataplane.PeerMetadata{{ID: "ix-b", Trusted: true}},
	}
	manager.kernelUDPAllowed = map[uint16]struct{}{
		17001: {},
	}
	manager.tixTCPAllowed = map[uint16]struct{}{
		18001: {},
	}

	got := manager.kernelUDPRXDirectStaticDestinationPortLocked(kernelUDPRXDirectProgramOptions{
		KernelUDPOnly:       true,
		DirectOnly:          true,
		DestinationPortOnly: true,
	})
	if got != 17001 {
		t.Fatalf("kernel_udp static destination port = %d, want local UDP listen port 17001", got)
	}

	got = manager.kernelUDPRXDirectStaticDestinationPortLocked(kernelUDPRXDirectProgramOptions{
		TIXTCPOnly:          true,
		DirectOnly:          true,
		DestinationPortOnly: true,
	})
	if got != 18001 {
		t.Fatalf("tix_tcp static destination port = %d, want local TCP listen port 18001", got)
	}
}

func TestKernelUDPRXDirectStaticDestinationPortUsesLocalTIXTCPListenPort(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT_STATIC_DESTINATION_PORT", "")
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
		Endpoints: []dataplane.EndpointMetadata{
			{ID: "local", Peer: "ix-a", Transport: "tix_tcp", Listen: "198.18.0.1:18001", Enabled: true},
			{ID: "remote", Peer: "ix-b", Transport: "tix_tcp", Address: "198.18.0.2:18002", Enabled: true},
		},
		Peers: []dataplane.PeerMetadata{{ID: "ix-b", Trusted: true}},
	}
	manager.tixTCPAllowed = map[uint16]struct{}{
		18001: {},
		41000: {},
		42000: {},
	}

	got := manager.kernelUDPRXDirectStaticDestinationPortLocked(kernelUDPRXDirectProgramOptions{
		TIXTCPOnly:          true,
		DirectOnly:          true,
		DestinationPortOnly: true,
	})
	if got != 18001 {
		t.Fatalf("static destination port = %d, want local tix_tcp listen port 18001", got)
	}
}

func TestKernelUDPRXDirectStaticDestinationPortRequiresUniqueLocalListenPort(t *testing.T) {
	manager := NewManager()
	manager.snapshot = dataplane.Snapshot{
		PacketPolicy: dataplane.PacketPolicy{KernelTransportMode: dataplane.KernelTransportModeRequireKernel},
		Endpoints: []dataplane.EndpointMetadata{
			{ID: "local-a", Peer: "ix-a", Transport: "udp", Listen: "198.18.0.1:17001", Enabled: true},
			{ID: "local-b", Peer: "ix-a", Transport: "udp", Listen: "198.18.0.1:17002", Enabled: true},
			{ID: "remote", Peer: "ix-b", Transport: "udp", Address: "198.18.0.2:17002", Enabled: true},
		},
		Peers: []dataplane.PeerMetadata{{ID: "ix-b", Trusted: true}},
	}

	got := manager.kernelUDPRXDirectStaticDestinationPortLocked(kernelUDPRXDirectProgramOptions{
		KernelUDPOnly:       true,
		DirectOnly:          true,
		DestinationPortOnly: true,
	})
	if got != 0 {
		t.Fatalf("static destination port = %d, want disabled for multiple local listen ports", got)
	}
}

func TestKernelUDPXDPRXDirectVethUsesSKBAttachWithoutFallback(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_FORCE", "")

	configMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_xdp_veth_skb_config_test", Type: cebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	defer configMap.Close()
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_xdp_veth_skb_neigh_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 16})
	defer neighMap.Close()
	devMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_xdp_veth_skb_devmap_test", Type: cebpf.DevMap, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	defer devMap.Close()
	rxConfigMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_xdp_veth_skb_rx_config_test", Type: cebpf.Array, KeySize: 4, ValueSize: 20, MaxEntries: 1})
	defer rxConfigMap.Close()

	manager := NewManager()
	manager.tixTCPFastPath = &tixTCPFastPath{xdpAttachMode: tixTCPXDPAttachSKB, xdpObject: &tixTCPXDPObject{configMap: configMap}, queueCount: 1}
	manager.kernelUDPRXNeighMap = neighMap
	manager.kernelUDPRXDevMap = devMap
	manager.kernelUDPRXConfigMap = rxConfigMap
	if err := manager.attachKernelUDPRXXDPDirectLocked(&netlink.Veth{}, &netlink.Dummy{}); err != nil {
		t.Fatalf("attach kernel_udp XDP RX direct: %v", err)
	}
	if !manager.kernelUDPXDPRXDirectEnabled {
		t.Fatal("kernel_udp XDP RX direct disabled for skb XDP veth path")
	}
	if manager.kernelUDPXDPRXDirectVethFallback {
		t.Fatal("kernel_udp XDP RX direct unexpectedly fell back for skb XDP veth path")
	}
}

func TestKernelUDPXDPRXDirectVethNativeFallsBackToTC(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_FORCE", "")

	configMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_xdp_veth_native_config_test", Type: cebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	defer configMap.Close()
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_xdp_veth_native_neigh_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 16})
	defer neighMap.Close()
	devMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_xdp_veth_native_devmap_test", Type: cebpf.DevMap, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	defer devMap.Close()
	rxConfigMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_xdp_veth_native_rx_config_test", Type: cebpf.Array, KeySize: 4, ValueSize: 20, MaxEntries: 1})
	defer rxConfigMap.Close()

	manager := NewManager()
	manager.tixTCPFastPath = &tixTCPFastPath{xdpAttachMode: tixTCPXDPAttachNative, xdpObject: &tixTCPXDPObject{configMap: configMap}, queueCount: 1}
	manager.kernelUDPRXNeighMap = neighMap
	manager.kernelUDPRXDevMap = devMap
	manager.kernelUDPRXConfigMap = rxConfigMap
	if err := manager.attachKernelUDPRXXDPDirectLocked(&netlink.Veth{}, &netlink.Dummy{}); err != nil {
		t.Fatalf("attach kernel_udp XDP RX direct: %v", err)
	}
	if manager.kernelUDPXDPRXDirectEnabled {
		t.Fatal("kernel_udp XDP RX direct enabled for native XDP veth path")
	}
	if !manager.kernelUDPXDPRXDirectVethFallback {
		t.Fatal("kernel_udp XDP RX direct did not fall back for native XDP veth path")
	}
}

func TestKernelUDPXDPRXSecureDirectVethFallsBackToTCSecureRX(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_RX_SECURE_DIRECT", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_FORCE", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_RX_SECURE_DIRECT_FORCE", "")

	configMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_xdp_secure_veth_config_test", Type: cebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	defer configMap.Close()
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_xdp_secure_veth_neigh_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 16})
	defer neighMap.Close()
	devMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_xdp_secure_veth_devmap_test", Type: cebpf.DevMap, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	defer devMap.Close()
	rxConfigMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_xdp_secure_veth_rx_config_test", Type: cebpf.Array, KeySize: 4, ValueSize: 20, MaxEntries: 1})
	defer rxConfigMap.Close()

	manager := NewManager()
	manager.tixTCPFastPath = &tixTCPFastPath{xdpAttachMode: tixTCPXDPAttachSKB, xdpObject: &tixTCPXDPObject{configMap: configMap}, queueCount: 1}
	manager.kernelUDPRXNeighMap = neighMap
	manager.kernelUDPRXDevMap = devMap
	manager.kernelUDPRXConfigMap = rxConfigMap
	manager.kernelUDPRXDirectRedirectPeer = true
	manager.kernelUDPRXDirectBroadcast = true
	manager.kernelUDPRXDirectAttached = true
	manager.kernelUDPRXSecureDirectAttached = true
	if err := manager.attachKernelUDPRXXDPDirectLocked(&netlink.Veth{}, &netlink.Dummy{}); err != nil {
		t.Fatalf("attach kernel_udp secure XDP RX direct: %v", err)
	}
	if !manager.kernelUDPXDPRXDirectEnabled {
		t.Fatal("kernel_udp XDP RX direct disabled unexpectedly")
	}
	if !manager.kernelUDPXDPRXSecureDirectVethFallback {
		t.Fatal("secure XDP RX direct did not fall back for veth peer/broadcast path")
	}
	if manager.tixTCPFastPath.KernelUDPXDPRXSecureDirectEnabled() {
		t.Fatal("secure XDP RX direct remained enabled despite veth fallback")
	}
	var config uint32
	key := uint32(0)
	if err := configMap.Lookup(key, &config); err != nil {
		t.Fatalf("read XDP config map: %v", err)
	}
	if config&tixTCPConfigKernelUDPXDPRXSecureDirect != 0 {
		t.Fatalf("secure XDP bit unexpectedly set in fallback config: %#x", config)
	}
	if config&tixTCPConfigKernelUDPTCRXSecureDirect == 0 {
		t.Fatalf("secure TC RX direct bit was not enabled for XDP secure fallback config: %#x", config)
	}
	if config&tixTCPConfigKernelUDPXDPRXDirect == 0 {
		t.Fatalf("plain XDP RX direct bit was not preserved in fallback config: %#x", config)
	}
}

func TestKernelUDPRXPlaintextPassToTCRequiresDirectOnlyOrFallback(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_SAFE", "")

	manager := NewManager()
	manager.kernelUDPRXDirectAttached = true
	if manager.kernelUDPRXPlaintextPassToTCLocked(true) {
		t.Fatal("mixed AF_XDP provider should keep plaintext RX on AF_XDP for safe userspace fallback")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_SAFE", "1")
	if !manager.kernelUDPRXPlaintextPassToTCLocked(true) {
		t.Fatal("safe TX direct should pass plaintext RX candidates to TC")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_SAFE", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "1")
	if !manager.kernelUDPRXPlaintextPassToTCLocked(true) {
		t.Fatal("direct-only provider should pass plaintext RX to TC")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "")
	manager.kernelUDPXDPRXDirectVethFallback = true
	if !manager.kernelUDPRXPlaintextPassToTCLocked(true) {
		t.Fatal("veth XDP fallback should pass plaintext RX to TC")
	}
	if manager.kernelUDPRXPlaintextPassToTCLocked(false) {
		t.Fatal("disabled RX direct config should not pass plaintext RX to TC")
	}
}

func TestKernelUDPRXConfigKeepsPlaintextOnAFXDPMixedProvider(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_SAFE", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_OPEN", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_PASS_OPENED", "")

	configMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_xdp_mixed_rx_config_test", Type: cebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	defer configMap.Close()

	manager := NewManager()
	manager.tixTCPFastPath = &tixTCPFastPath{xdpObject: &tixTCPXDPObject{configMap: configMap}, queueCount: 1}
	manager.kernelUDPRXDirectAttached = true
	if err := manager.syncKernelUDPRXDirectConfigLocked(); err != nil {
		t.Fatalf("sync mixed RX direct config: %v", err)
	}
	var config uint32
	key := uint32(0)
	if err := configMap.Lookup(key, &config); err != nil {
		t.Fatalf("read XDP config map: %v", err)
	}
	if config&tixTCPConfigKernelUDPTCRXDirect != 0 {
		t.Fatalf("mixed AF_XDP config set TC plaintext direct bit: %#x", config)
	}
}

func TestKernelUDPRXConfigPassesPlaintextToTCForSafeDirect(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_SAFE", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_OPEN", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_PASS_OPENED", "")

	configMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_xdp_safe_direct_rx_config_test", Type: cebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	defer configMap.Close()

	manager := NewManager()
	manager.tixTCPFastPath = &tixTCPFastPath{xdpObject: &tixTCPXDPObject{configMap: configMap}, queueCount: 1}
	manager.kernelUDPRXDirectAttached = true
	if err := manager.syncKernelUDPRXDirectConfigLocked(); err != nil {
		t.Fatalf("sync safe-direct RX direct config: %v", err)
	}
	var config uint32
	key := uint32(0)
	if err := configMap.Lookup(key, &config); err != nil {
		t.Fatalf("read XDP config map: %v", err)
	}
	if config&tixTCPConfigKernelUDPTCRXDirect == 0 {
		t.Fatalf("safe-direct config did not set TC plaintext direct bit: %#x", config)
	}
}

func TestKernelUDPRXConfigPassesPlaintextToTCForDirectOnly(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_SAFE", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_OPEN", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_PASS_OPENED", "")

	configMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_xdp_direct_only_rx_config_test", Type: cebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	defer configMap.Close()

	manager := NewManager()
	manager.tixTCPFastPath = &tixTCPFastPath{xdpObject: &tixTCPXDPObject{configMap: configMap}, queueCount: 1}
	manager.kernelUDPRXDirectAttached = true
	if err := manager.syncKernelUDPRXDirectConfigLocked(); err != nil {
		t.Fatalf("sync direct-only RX direct config: %v", err)
	}
	var config uint32
	key := uint32(0)
	if err := configMap.Lookup(key, &config); err != nil {
		t.Fatalf("read XDP config map: %v", err)
	}
	if config&tixTCPConfigKernelUDPTCRXDirect == 0 {
		t.Fatalf("direct-only config did not set TC plaintext direct bit: %#x", config)
	}
}

func TestKernelUDPRXConfigPassesToKernelDatapathWorker(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_XDP_PASS", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_SAFE", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_OPEN", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_PASS_OPENED", "")

	configMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_xdp_kmod_worker_rx_config_test", Type: cebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	defer configMap.Close()

	manager := NewManager()
	manager.tixTCPFastPath = &tixTCPFastPath{xdpObject: &tixTCPXDPObject{configMap: configMap}, queueCount: 1}
	manager.kernelUDPRXDirectAttached = true
	manager.kernelUDPXDPRXDirectEnabled = true
	if err := manager.syncKernelUDPRXDirectConfigLocked(); err != nil {
		t.Fatalf("sync kernel datapath worker RX direct config: %v", err)
	}
	var config uint32
	key := uint32(0)
	if err := configMap.Lookup(key, &config); err != nil {
		t.Fatalf("read XDP config map: %v", err)
	}
	if config&tixTCPConfigKernelUDPTCRXDirect == 0 {
		t.Fatalf("kernel datapath worker config did not set TC plaintext pass bit: %#x", config)
	}
	if config&tixTCPConfigXDPFallbackPass == 0 {
		t.Fatalf("kernel datapath worker config did not set XDP fallback-pass bit: %#x", config)
	}
	if config&tixTCPConfigKernelUDPXDPRXDirect != 0 {
		t.Fatalf("kernel datapath worker config left XDP RX direct enabled: %#x", config)
	}
}

func TestKernelDatapathRXWorkerDisablesTCRXDirectOwner(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_XDP_PASS", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "1")

	manager := NewManager()
	manager.spec = dataplane.AttachSpec{
		LANIface:              "br-lan",
		UnderlayIface:         "eth0",
		KernelUDPTXDirectOnly: true,
	}
	manager.statsMap = &cebpf.Map{}
	manager.kernelUDPTXRouteMap = &cebpf.Map{}
	manager.kernelUDPTXFlowMap = &cebpf.Map{}

	if manager.kernelUDPTCOnlyEligibleLocked() {
		t.Fatal("kernel datapath RX worker should prevent TC-only RX direct ownership")
	}
}

func TestKernelDatapathRXWorkerSuppressedBySpecAllowsTCRXDirectOwner(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_XDP_PASS", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "1")

	manager := NewManager()
	manager.spec = dataplane.AttachSpec{
		LANIface:                             "br-lan",
		UnderlayIface:                        "eth0",
		KernelUDPTXDirectOnly:                true,
		KernelDatapathSuppressLegacyRXWorker: true,
	}
	manager.statsMap = &cebpf.Map{}
	manager.kernelUDPTXRouteMap = &cebpf.Map{}
	manager.kernelUDPTXFlowMap = &cebpf.Map{}

	if !manager.kernelUDPTCOnlyEligibleLocked() {
		t.Fatal("route-GSO suppression should let TC RX direct own the stack despite legacy RX_WORKER env")
	}
}

func TestKernelUDPRXConfigRouteGSOSuppressionIgnoresLegacyWorkerEnv(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_XDP_PASS", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_SAFE", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_OPEN", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_PASS_OPENED", "")

	configMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_xdp_route_gso_suppressed_worker_config_test", Type: cebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	defer configMap.Close()

	manager := NewManager()
	manager.spec = dataplane.AttachSpec{
		TIXTCPTXDirect:                       true,
		KernelDatapathSuppressLegacyRXWorker: true,
	}
	manager.tixTCPFastPath = &tixTCPFastPath{xdpObject: &tixTCPXDPObject{configMap: configMap}, queueCount: 1}
	manager.kernelUDPRXDirectAttached = true
	manager.kernelUDPXDPRXDirectEnabled = true
	if err := manager.syncKernelUDPRXDirectConfigLocked(); err != nil {
		t.Fatalf("sync route-GSO suppressed-worker RX direct config: %v", err)
	}
	var config uint32
	key := uint32(0)
	if err := configMap.Lookup(key, &config); err != nil {
		t.Fatalf("read XDP config map: %v", err)
	}
	if config&tixTCPConfigKernelUDPTCRXDirect == 0 {
		t.Fatalf("route-GSO suppressed-worker config did not set TC RX direct bit: %#x", config)
	}
	if config&tixTCPConfigXDPFallbackPass != 0 {
		t.Fatalf("route-GSO suppressed-worker config should not keep legacy XDP fallback-pass bit: %#x", config)
	}
}

func TestKernelDatapathRXWorkerConfiguresXDPStackPassWithoutTCRXDirect(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_XDP_PASS", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_SAFE", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_OPEN", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_PASS_OPENED", "")

	configMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_xdp_kmod_worker_stack_pass_config_test", Type: cebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	defer configMap.Close()

	manager := NewManager()
	manager.tixTCPFastPath = &tixTCPFastPath{xdpObject: &tixTCPXDPObject{configMap: configMap}, queueCount: 1}
	if err := manager.syncKernelUDPRXDirectConfigLocked(); err != nil {
		t.Fatalf("sync kernel datapath worker stack-pass config: %v", err)
	}
	var config uint32
	key := uint32(0)
	if err := configMap.Lookup(key, &config); err != nil {
		t.Fatalf("read XDP config map: %v", err)
	}
	if config&tixTCPConfigXDPFallbackPass == 0 {
		t.Fatalf("kernel datapath worker did not set XDP fallback-pass without TC RX direct: %#x", config)
	}
	if config&tixTCPConfigKernelUDPTCRXDirect != 0 {
		t.Fatalf("kernel datapath worker unexpectedly enabled TC RX direct: %#x", config)
	}
	if config&tixTCPConfigKernelUDPXDPRXDirect != 0 {
		t.Fatalf("kernel datapath worker unexpectedly enabled XDP RX direct: %#x", config)
	}
}

func TestKernelUDPRXConfigKernelDatapathPassCanBeDisabled(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_XDP_PASS", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_SAFE", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_OPEN", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_PASS_OPENED", "")

	configMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_xdp_kmod_worker_rx_pass_disabled_config_test", Type: cebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	defer configMap.Close()

	manager := NewManager()
	manager.tixTCPFastPath = &tixTCPFastPath{xdpObject: &tixTCPXDPObject{configMap: configMap}, queueCount: 1}
	manager.kernelUDPRXDirectAttached = true
	manager.kernelUDPXDPRXDirectEnabled = true
	if err := manager.syncKernelUDPRXDirectConfigLocked(); err != nil {
		t.Fatalf("sync kernel datapath worker disabled-pass config: %v", err)
	}
	var config uint32
	key := uint32(0)
	if err := configMap.Lookup(key, &config); err != nil {
		t.Fatalf("read XDP config map: %v", err)
	}
	if config&tixTCPConfigXDPFallbackPass != 0 {
		t.Fatalf("disabled kernel datapath pass still set XDP fallback-pass bit: %#x", config)
	}
	if config&tixTCPConfigKernelUDPXDPRXDirect == 0 {
		t.Fatalf("disabled kernel datapath pass should preserve XDP RX direct: %#x", config)
	}
}

func TestStandaloneKernelUDPXDPRXDirectConfigUsesFallbackPass(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_OPEN", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_PASS_OPENED", "")

	configMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_xdp_standalone_rx_config_test", Type: cebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	defer configMap.Close()

	manager := NewManager()
	manager.kernelUDPXDPRXDirectObject = &tixTCPXDPObject{configMap: configMap}
	manager.kernelUDPRXDirectAttached = true
	manager.kernelUDPXDPRXDirectEnabled = true
	if err := manager.syncKernelUDPRXDirectConfigLocked(); err != nil {
		t.Fatalf("sync standalone XDP RX direct config: %v", err)
	}
	var config uint32
	key := uint32(0)
	if err := configMap.Lookup(key, &config); err != nil {
		t.Fatalf("read standalone XDP config map: %v", err)
	}
	if config&tixTCPConfigKernelUDPXDPRXDirect == 0 {
		t.Fatalf("standalone XDP RX direct bit was not set: %#x", config)
	}
	if config&tixTCPConfigXDPFallbackPass == 0 {
		t.Fatalf("standalone XDP fallback-pass bit was not set: %#x", config)
	}
}

func newIngressFastPathTestMaps(t *testing.T) (*cebpf.Map, *cebpf.Map, *cebpf.Map, *cebpf.Map, *cebpf.Map, *cebpf.Map, *cebpf.Map, *cebpf.Map, *cebpf.Map, *cebpf.Map) {
	t.Helper()
	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_stats_test", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	packetPolicyMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_packet_policy_test", Type: cebpf.Array, KeySize: 4, ValueSize: 12, MaxEntries: 1})
	routeMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_route_lpm_load_test", Type: cebpf.LPMTrie, KeySize: 8, ValueSize: 16, MaxEntries: 16, Flags: 1})
	kernelUDPTXRouteMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_route_load_test", Type: cebpf.LPMTrie, KeySize: 8, ValueSize: kernelUDPTXRouteValueSize, MaxEntries: 16, Flags: 1})
	kernelUDPTXFlowMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_tx_flow_load_test", Type: cebpf.Hash, KeySize: 8, ValueSize: kernelUDPTXFlowValueSize, MaxEntries: 16})
	natConfigMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_nat_config_load_test", Type: cebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	natSourceMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_nat_sources_load_test", Type: cebpf.LPMTrie, KeySize: 8, ValueSize: 4, MaxEntries: 16, Flags: 1})
	natRouteMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_nat_routes_load_test", Type: cebpf.LPMTrie, KeySize: 8, ValueSize: 4, MaxEntries: 16, Flags: 1})
	natExcludeMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_nat_exclude_load_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 16})
	captureMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_capture_events_load_test", Type: cebpf.RingBuf, MaxEntries: 4096})
	return statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap
}

func newTestBPFMap(t *testing.T, spec *cebpf.MapSpec) *cebpf.Map {
	t.Helper()
	m, err := cebpf.NewMap(spec)
	if err != nil {
		t.Skipf("create BPF map %s: %v", spec.Name, err)
	}
	return m
}

func TestRouteActionForKind(t *testing.T) {
	tests := []struct {
		kind routing.RouteKind
		want uint32
	}{
		{kind: "", want: routeActionCapture},
		{kind: routing.RouteUnicast, want: routeActionCapture},
		{kind: routing.RouteLocal, want: routeActionLocal},
		{kind: routing.RouteBlackhole, want: routeActionBlackhole},
		{kind: routing.RouteReject, want: routeActionReject},
	}
	for _, tt := range tests {
		got, ok := routeActionForKind(tt.kind)
		if !ok {
			t.Fatalf("kind %q was not supported", tt.kind)
		}
		if got != tt.want {
			t.Fatalf("kind %q action = %d, want %d", tt.kind, got, tt.want)
		}
	}
	if _, ok := routeActionForKind(routing.RouteKind("throw")); ok {
		t.Fatal("unsupported route kind reported supported")
	}
}

func TestSyncRoutesIncludesDropRouteKinds(t *testing.T) {
	manager := NewManager()
	routeMap, err := cebpf.NewMap(&cebpf.MapSpec{
		Name:       "ix_route_lpm_test",
		Type:       cebpf.LPMTrie,
		KeySize:    8,
		ValueSize:  16,
		MaxEntries: 16,
		Flags:      1,
	})
	if err != nil {
		t.Skipf("create BPF route map: %v", err)
	}
	defer routeMap.Close()
	manager.routeMap = routeMap

	routes := []routing.Route{
		{Prefix: core.Prefix("10.1.0.0/16"), Kind: routing.RouteUnicast},
		{Prefix: core.Prefix("10.2.0.0/16"), Kind: routing.RouteLocal},
		{Prefix: core.Prefix("10.3.0.0/16"), Kind: routing.RouteBlackhole},
		{Prefix: core.Prefix("10.4.0.0/16"), Kind: routing.RouteReject},
	}
	if err := manager.syncRoutesLocked(routes); err != nil {
		t.Fatalf("sync routes: %v", err)
	}
	if manager.routeEntries != uint64(len(routes)) {
		t.Fatalf("route entries = %d, want %d", manager.routeEntries, len(routes))
	}
	for _, route := range routes {
		prefix, _ := route.Prefix.Parse()
		key := routeKey{PrefixLen: uint32(prefix.Bits()), Addr: prefix.Addr().As4()}
		var value routeValue
		if err := routeMap.Lookup(key, &value); err != nil {
			t.Fatalf("lookup route %s: %v", route.Prefix, err)
		}
		want, _ := routeActionForKind(route.Kind)
		if value.Action != want {
			t.Fatalf("route %s action = %d, want %d", route.Prefix, value.Action, want)
		}
	}
}

func TestSyncNATMaps(t *testing.T) {
	manager := NewManager()
	var closeMaps []func() error
	defer func() {
		for _, closeMap := range closeMaps {
			_ = closeMap()
		}
	}()
	newMap := func(spec *cebpf.MapSpec) *cebpf.Map {
		t.Helper()
		m, err := cebpf.NewMap(spec)
		if err != nil {
			t.Skipf("create BPF map %s: %v", spec.Name, err)
		}
		closeMaps = append(closeMaps, m.Close)
		return m
	}
	manager.natConfigMap = newMap(&cebpf.MapSpec{
		Name:       "ix_nat_config_test",
		Type:       cebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
	})
	manager.natSourceMap = newMap(&cebpf.MapSpec{
		Name:       "ix_nat_sources_test",
		Type:       cebpf.LPMTrie,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: 16,
		Flags:      1,
	})
	manager.natRouteMap = newMap(&cebpf.MapSpec{
		Name:       "ix_nat_routes_test",
		Type:       cebpf.LPMTrie,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: 16,
		Flags:      1,
	})
	manager.natExcludeMap = newMap(&cebpf.MapSpec{
		Name:       "ix_nat_exclude_test",
		Type:       cebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 16,
	})
	manager.natBindingMap = newMap(&cebpf.MapSpec{
		Name:       "ix_nat_bindings_test",
		Type:       cebpf.Hash,
		KeySize:    20,
		ValueSize:  16,
		MaxEntries: 16,
	})

	snapshot := &dataplane.NATSnapshot{
		Enabled:              true,
		Gateway:              mustAddr("10.0.0.1"),
		SourcePrefixes:       []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		RoutePrefixes:        []core.Prefix{"10.0.1.0/24"},
		ExcludedDestinations: []netip.Addr{mustAddr("10.0.1.254")},
		Bindings: []dataplane.NATBinding{{
			TranslatedIP: mustAddr("10.0.0.1"),
			RemoteIP:     mustAddr("10.0.1.2"),
			Protocol:     ipProtocolUDP,
			LocalPort:    12345,
			RemotePort:   18100,
			OriginalIP:   mustAddr("10.0.0.2"),
		}},
	}
	if err := manager.syncNATLocked(snapshot); err != nil {
		t.Fatalf("sync NAT maps: %v", err)
	}
	if manager.natSourceEntries != 1 || manager.natRouteEntries != 1 || manager.natExcludeEntries != 1 || manager.natBindingEntries != 1 {
		t.Fatalf("NAT entry counts = source:%d route:%d exclude:%d binding:%d, want 1/1/1/1", manager.natSourceEntries, manager.natRouteEntries, manager.natExcludeEntries, manager.natBindingEntries)
	}
	var cfg natConfigValue
	if err := manager.natConfigMap.Lookup(uint32(0), &cfg); err != nil {
		t.Fatalf("lookup NAT config: %v", err)
	}
	if cfg.Enabled != 1 || cfg.Gateway != [4]byte{10, 0, 0, 1} {
		t.Fatalf("NAT config = %#v", cfg)
	}
	var one uint32
	if err := manager.natSourceMap.Lookup(routeKey{PrefixLen: 24, Addr: [4]byte{10, 0, 0, 0}}, &one); err != nil {
		t.Fatalf("lookup NAT source prefix: %v", err)
	}
	if err := manager.natRouteMap.Lookup(routeKey{PrefixLen: 24, Addr: [4]byte{10, 0, 1, 0}}, &one); err != nil {
		t.Fatalf("lookup NAT route prefix: %v", err)
	}
	if err := manager.natExcludeMap.Lookup([4]byte{10, 0, 1, 254}, &one); err != nil {
		t.Fatalf("lookup NAT exclude destination: %v", err)
	}
	var binding natBindingValue
	if err := manager.natBindingMap.Lookup(natBindingKey{
		TranslatedIP: [4]byte{10, 0, 0, 1},
		RemoteIP:     [4]byte{10, 0, 1, 2},
		Protocol:     ipProtocolUDP,
		LocalPort:    htons(12345),
		RemotePort:   htons(18100),
	}, &binding); err != nil {
		t.Fatalf("lookup NAT binding: %v", err)
	}
	if binding.OriginalIP != [4]byte{10, 0, 0, 2} {
		t.Fatalf("NAT binding value = %#v", binding)
	}

	snapshot.Bindings = []dataplane.NATBinding{{
		TranslatedIP: mustAddr("10.0.0.1"),
		RemoteIP:     mustAddr("10.0.1.3"),
		Protocol:     ipProtocolUDP,
		LocalPort:    12346,
		RemotePort:   18100,
		OriginalIP:   mustAddr("10.0.0.3"),
	}}
	if err := manager.syncNATLocked(snapshot); err != nil {
		t.Fatalf("sync updated NAT maps: %v", err)
	}
	if manager.natBindingEntries != 1 {
		t.Fatalf("NAT binding entries after incremental sync = %d, want 1", manager.natBindingEntries)
	}
	if err := manager.natBindingMap.Lookup(natBindingKey{
		TranslatedIP: [4]byte{10, 0, 0, 1},
		RemoteIP:     [4]byte{10, 0, 1, 2},
		Protocol:     ipProtocolUDP,
		LocalPort:    htons(12345),
		RemotePort:   htons(18100),
	}, &binding); !errors.Is(err, cebpf.ErrKeyNotExist) {
		t.Fatalf("stale NAT binding lookup error = %v, want ErrKeyNotExist", err)
	}
	if err := manager.natBindingMap.Lookup(natBindingKey{
		TranslatedIP: [4]byte{10, 0, 0, 1},
		RemoteIP:     [4]byte{10, 0, 1, 3},
		Protocol:     ipProtocolUDP,
		LocalPort:    htons(12346),
		RemotePort:   htons(18100),
	}, &binding); err != nil {
		t.Fatalf("lookup updated NAT binding: %v", err)
	}
	if binding.OriginalIP != [4]byte{10, 0, 0, 3} {
		t.Fatalf("updated NAT binding value = %#v", binding)
	}

	if err := manager.syncNATLocked(nil); err != nil {
		t.Fatalf("clear NAT maps: %v", err)
	}
	if manager.natSourceEntries != 0 || manager.natRouteEntries != 0 || manager.natExcludeEntries != 0 || manager.natBindingEntries != 0 {
		t.Fatalf("NAT entry counts after clear = source:%d route:%d exclude:%d binding:%d, want 0/0/0/0", manager.natSourceEntries, manager.natRouteEntries, manager.natExcludeEntries, manager.natBindingEntries)
	}
	if err := manager.natSourceMap.Lookup(routeKey{PrefixLen: 24, Addr: [4]byte{10, 0, 0, 0}}, &one); !errors.Is(err, cebpf.ErrKeyNotExist) {
		t.Fatalf("source prefix after clear lookup error = %v, want ErrKeyNotExist", err)
	}
	if err := manager.natConfigMap.Lookup(uint32(0), &cfg); err != nil {
		t.Fatalf("lookup cleared NAT config: %v", err)
	}
	if cfg.Enabled != 0 {
		t.Fatalf("cleared NAT enabled = %d, want 0", cfg.Enabled)
	}
	if err := manager.natBindingMap.Lookup(natBindingKey{
		TranslatedIP: [4]byte{10, 0, 0, 1},
		RemoteIP:     [4]byte{10, 0, 1, 2},
		Protocol:     ipProtocolUDP,
		LocalPort:    htons(12345),
		RemotePort:   htons(18100),
	}, &binding); !errors.Is(err, cebpf.ErrKeyNotExist) {
		t.Fatalf("NAT binding after clear lookup error = %v, want ErrKeyNotExist", err)
	}
}

func mustAddr(raw string) netip.Addr {
	return netip.MustParseAddr(raw)
}

func TestKernelCryptoFlowMapLifecycleBookkeeping(t *testing.T) {
	manager := NewManager()
	send := kernelCryptoFlowKey{FlowID: 42, Direction: kernelCryptoDirectionSend}
	recv := kernelCryptoFlowKey{FlowID: 42, Direction: kernelCryptoDirectionRecv}
	other := kernelCryptoFlowKey{FlowID: 77, Direction: kernelCryptoDirectionSend}
	manager.kernelCryptoFlowMapEntries = map[kernelCryptoFlowKey]struct{}{
		send:  {},
		recv:  {},
		other: {},
	}

	manager.deleteKernelCryptoFlowLocked(42)
	if _, ok := manager.kernelCryptoFlowMapEntries[send]; ok {
		t.Fatalf("send flow entry was not removed")
	}
	if _, ok := manager.kernelCryptoFlowMapEntries[recv]; ok {
		t.Fatalf("recv flow entry was not removed")
	}
	if _, ok := manager.kernelCryptoFlowMapEntries[other]; !ok {
		t.Fatalf("unrelated flow entry was removed")
	}
	if got := manager.kernelCryptoFlowMapDeletes; got != 0 {
		t.Fatalf("kernel crypto map deletes = %d, want 0 without a loaded BPF map", got)
	}

	if err := manager.closeKernelCryptoProviderMapLocked(); err != nil {
		t.Fatalf("close unloaded kernel crypto map: %v", err)
	}
	if manager.kernelCryptoFlowMapEntries != nil {
		t.Fatalf("kernel crypto map entries were not cleared on close")
	}
	if got := manager.kernelCryptoFlowMapEntriesLocked(); got != 0 {
		t.Fatalf("kernel crypto map entry count = %d, want 0", got)
	}
}

func TestKernelCryptoFlowMapStageRequiresLoadedMap(t *testing.T) {
	manager := NewManager()
	spec := validKernelCryptoSpec(99)
	entries, err := encodeKernelCryptoSpec(spec)
	if err != nil {
		t.Fatalf("encode kernel crypto spec: %v", err)
	}
	defer zeroKernelCryptoEntries(entries)

	err = manager.stageKernelCryptoEntriesLocked(entries)
	if err == nil || !strings.Contains(err.Error(), "flow map is not loaded") {
		t.Fatalf("stage without map error = %v, want map not loaded", err)
	}
	if got := manager.kernelCryptoFlowMapUpdates; got != 0 {
		t.Fatalf("kernel crypto map updates = %d, want 0", got)
	}
	if got := manager.kernelCryptoFlowMapEntriesLocked(); got != 0 {
		t.Fatalf("kernel crypto map entries = %d, want 0", got)
	}
}

func TestKernelUDPInstallCryptoPreservesPeerEndpointWhenUnavailable(t *testing.T) {
	manager := NewManager()
	manager.kernelUDPFlows[44] = dataplane.KernelUDPFlow{
		ID:            44,
		Peer:          core.IXID("ix-b"),
		Endpoint:      core.EndpointID("ix-b-udp"),
		RemoteAddress: "198.51.100.44:17001",
	}
	spec := validKernelUDPCryptoSpec(44)

	err := manager.InstallKernelUDPCrypto(context.Background(), []dataplane.KernelUDPCryptoSpec{spec})
	if err == nil || !strings.Contains(err.Error(), "kernel crypto provider is not available") {
		t.Fatalf("install kernel_udp crypto error = %v, want unavailable", err)
	}
	flow := manager.kernelUDPFlows[44]
	if flow.Peer != core.IXID("ix-b") || flow.Endpoint != core.EndpointID("ix-b-udp") {
		t.Fatalf("flow identity changed after failed install: %+v", flow)
	}
	if flow.CryptoPlacement == dataplane.CryptoPlacementKernel {
		t.Fatalf("flow crypto placement changed after failed install: %+v", flow)
	}
}

func TestKernelUDPHasCryptoDeviceForEntriesUsesMatchingFlowID(t *testing.T) {
	manager := NewManager()
	manager.kernelCryptoDevices = map[uint64]*kernelCryptoDevice{55: {}}
	entries, err := encodeKernelUDPCryptoSpec(validKernelUDPCryptoSpec(55))
	if err != nil {
		t.Fatalf("encode kernel_udp crypto spec: %v", err)
	}
	defer zeroKernelCryptoEntries(entries)
	if !manager.hasKernelCryptoDeviceForEntriesLocked(kernelCryptoNamespaceKernelUDP, entries) {
		t.Fatal("expected crypto device for flow 55")
	}

	entries, err = encodeKernelUDPCryptoSpec(validKernelUDPCryptoSpec(56))
	if err != nil {
		t.Fatalf("encode kernel_udp crypto spec: %v", err)
	}
	defer zeroKernelCryptoEntries(entries)
	if manager.hasKernelCryptoDeviceForEntriesLocked(kernelCryptoNamespaceKernelUDP, entries) {
		t.Fatal("unexpected crypto device for flow 56")
	}
}

func validKernelUDPCryptoSpec(flowID uint64) dataplane.KernelUDPCryptoSpec {
	spec := validKernelCryptoSpec(flowID)
	return dataplane.KernelUDPCryptoSpec{
		FlowID:       spec.FlowID,
		Suite:        spec.Suite,
		WireFormat:   spec.WireFormat,
		KeySource:    spec.KeySource,
		Epoch:        spec.Epoch,
		SendKey:      append([]byte(nil), spec.SendKey...),
		SendIV:       append([]byte(nil), spec.SendIV...),
		RecvKey:      append([]byte(nil), spec.RecvKey...),
		RecvIV:       append([]byte(nil), spec.RecvIV...),
		ReplayWindow: spec.ReplayWindow,
	}
}

func TestKernelCryptoProviderSlotAllocatorReusesAndReleasesSlots(t *testing.T) {
	manager := NewManager()
	spec := validKernelCryptoSpec(99)
	entries, err := encodeKernelCryptoSpec(spec)
	if err != nil {
		t.Fatalf("encode kernel crypto spec: %v", err)
	}
	defer zeroKernelCryptoEntries(entries)

	prepared, err := manager.prepareKernelCryptoProviderInstallEntriesLocked(entries)
	if err != nil {
		t.Fatalf("prepare provider install entries: %v", err)
	}
	if len(prepared) != len(entries) {
		t.Fatalf("prepared entries = %d, want %d", len(prepared), len(entries))
	}
	if prepared[0].Slot == prepared[1].Slot {
		t.Fatalf("send and recv entries used the same slot %d", prepared[0].Slot)
	}

	again, err := manager.prepareKernelCryptoProviderInstallEntriesLocked(entries)
	if err != nil {
		t.Fatalf("prepare provider install entries again: %v", err)
	}
	for i := range prepared {
		if again[i].Slot != prepared[i].Slot {
			t.Fatalf("slot for entry %d changed from %d to %d", i, prepared[i].Slot, again[i].Slot)
		}
	}

	manager.rollbackKernelCryptoProviderInstallLocked(entries)
	if len(manager.kernelCryptoCtxSlots) != 0 {
		t.Fatalf("kernel crypto ctx slots were not released: %+v", manager.kernelCryptoCtxSlots)
	}
}

func TestKernelCryptoCommandClearsKeyMaterial(t *testing.T) {
	spec := validKernelCryptoSpec(123)
	entries, err := encodeKernelCryptoSpec(spec)
	if err != nil {
		t.Fatalf("encode kernel crypto spec: %v", err)
	}
	cmd := kernelCryptoCommand{
		Op:    kernelCryptoCommandInstall,
		Key:   entries[0].Key,
		Value: entries[0].Value,
	}
	zeroKernelCryptoCommand(&cmd)
	if cmd != (kernelCryptoCommand{}) {
		t.Fatalf("kernel crypto command was not cleared")
	}
	zeroKernelCryptoEntries(entries)
}

func TestSplitPreparedKernelUDPFramesFragmentsSealedPayload(t *testing.T) {
	packet := kerneludp.UDPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.1"),
		DestinationIP:   netip.MustParseAddr("192.0.2.2"),
		SourcePort:      40000,
		DestinationPort: 50000,
	}
	item := preparedKernelUDPTXFrame{
		packet: packet,
		wireFrame: kerneludp.Frame{
			Flags:    kerneludp.FlagEncrypted | kerneludp.FlagInnerIPv4,
			FlowID:   9,
			Sequence: 100,
			Payload:  bytesOf(0x5a, 2500),
		},
		bytes:            2460,
		sourceIP4:        packet.SourceIP.As4(),
		destinationIP4:   packet.DestinationIP.As4(),
		sourcePort:       packet.SourcePort,
		destinationPort:  packet.DestinationPort,
		fragmentPayload:  1000,
		txInnerHash:      0x12345678,
		txInnerHashValid: true,
	}

	got, err := splitPreparedKernelUDPFrames([]preparedKernelUDPTXFrame{item})
	if err != nil {
		t.Fatalf("split prepared frames: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("fragments = %d, want 3", len(got))
	}
	for i, fragment := range got {
		wantFlags := kerneludp.FlagEncrypted | kerneludp.FlagCryptoFragment | kerneludp.FlagInnerIPv4
		if fragment.wireFrame.Flags&wantFlags != wantFlags {
			t.Fatalf("fragment %d flags = %#x", i, fragment.wireFrame.Flags)
		}
		if fragment.wireFrame.Sequence != 100+uint64(i) || fragment.wireFrame.FragmentIndex != uint16(i) || fragment.wireFrame.FragmentCount != 3 {
			t.Fatalf("fragment %d header = seq %d index %d count %d", i, fragment.wireFrame.Sequence, fragment.wireFrame.FragmentIndex, fragment.wireFrame.FragmentCount)
		}
		if i == 0 && fragment.bytes != item.bytes {
			t.Fatalf("first fragment bytes = %d, want %d", fragment.bytes, item.bytes)
		}
		if i > 0 && fragment.bytes != 0 {
			t.Fatalf("fragment %d bytes = %d, want 0", i, fragment.bytes)
		}
		if !fragment.txInnerHashValid || fragment.txInnerHash != item.txInnerHash {
			t.Fatalf("fragment %d tx inner hash = (%#x,%v), want (%#x,true)", i, fragment.txInnerHash, fragment.txInnerHashValid, item.txInnerHash)
		}
	}
	joined := append(append([]byte(nil), got[0].wireFrame.Payload...), got[1].wireFrame.Payload...)
	joined = append(joined, got[2].wireFrame.Payload...)
	if !bytes.Equal(joined, item.wireFrame.Payload) {
		t.Fatalf("fragment payloads did not reassemble")
	}
}

func TestSplitPreparedTIXTCPFramesFragmentsSealedPayload(t *testing.T) {
	packet := tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.1"),
		DestinationIP:   netip.MustParseAddr("192.0.2.2"),
		SourcePort:      40000,
		DestinationPort: 50000,
	}
	item := preparedTIXTCPTXFrame{
		packet: packet,
		wireFrame: tixtcp.Frame{
			Flags:    tixtcp.FlagEncrypted | tixtcp.FlagInnerIPv4,
			FlowID:   9,
			Sequence: 100,
			Payload:  bytesOf(0x5a, 2500),
		},
		bytes:            2460,
		sourceIP4:        packet.SourceIP.As4(),
		destinationIP4:   packet.DestinationIP.As4(),
		sourcePort:       packet.SourcePort,
		destinationPort:  packet.DestinationPort,
		fragmentPayload:  1000,
		txInnerHash:      0x12345678,
		txInnerHashValid: true,
	}

	got, err := splitPreparedTIXTCPFrames([]preparedTIXTCPTXFrame{item})
	if err != nil {
		t.Fatalf("split prepared frames: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("fragments = %d, want 3", len(got))
	}
	for i, fragment := range got {
		wantFlags := tixtcp.FlagEncrypted | tixtcp.FlagCryptoFragment | tixtcp.FlagInnerIPv4
		if fragment.wireFrame.Flags&wantFlags != wantFlags {
			t.Fatalf("fragment %d flags = %#x", i, fragment.wireFrame.Flags)
		}
		if fragment.wireFrame.Sequence != 100+uint64(i) || fragment.wireFrame.FragmentIndex != uint16(i) || fragment.wireFrame.FragmentCount != 3 {
			t.Fatalf("fragment %d header = seq %d index %d count %d", i, fragment.wireFrame.Sequence, fragment.wireFrame.FragmentIndex, fragment.wireFrame.FragmentCount)
		}
		if i == 0 && fragment.bytes != item.bytes {
			t.Fatalf("first fragment bytes = %d, want %d", fragment.bytes, item.bytes)
		}
		if i > 0 && fragment.bytes != 0 {
			t.Fatalf("fragment %d bytes = %d, want 0", i, fragment.bytes)
		}
		if fragment.frameLen == 0 || fragment.packetLen == 0 || fragment.tcpSeqLen == 0 {
			t.Fatalf("fragment %d lengths were not recomputed: %+v", i, fragment)
		}
		if !fragment.txInnerHashValid || fragment.txInnerHash != item.txInnerHash {
			t.Fatalf("fragment %d tx inner hash = (%#x,%v), want (%#x,true)", i, fragment.txInnerHash, fragment.txInnerHashValid, item.txInnerHash)
		}
	}
	joined := append(append([]byte(nil), got[0].wireFrame.Payload...), got[1].wireFrame.Payload...)
	joined = append(joined, got[2].wireFrame.Payload...)
	if !bytes.Equal(joined, item.wireFrame.Payload) {
		t.Fatalf("fragment payloads did not reassemble")
	}
}

func TestReassembleTIXTCPCryptoFragments(t *testing.T) {
	manager := NewManager()
	payload := bytesOf(0x8c, 2500)
	frames := []receivedTIXTCPFrame{
		{
			frame: dataplane.TIXTCPFrame{
				FlowID:          7,
				Epoch:           3,
				Sequence:        100,
				FragmentIndex:   0,
				FragmentCount:   3,
				Payload:         payload[:1000],
				Encrypted:       true,
				InnerIPv4:       true,
				CryptoPlacement: dataplane.CryptoPlacementKernel,
			},
			encryptedKernelPayload:  true,
			encryptedKernelFragment: true,
		},
		{
			frame: dataplane.TIXTCPFrame{
				FlowID:          7,
				Epoch:           3,
				Sequence:        101,
				FragmentIndex:   1,
				FragmentCount:   3,
				Payload:         payload[1000:2000],
				Encrypted:       true,
				CryptoPlacement: dataplane.CryptoPlacementKernel,
			},
			encryptedKernelPayload:  true,
			encryptedKernelFragment: true,
		},
		{
			frame: dataplane.TIXTCPFrame{
				FlowID:          7,
				Epoch:           3,
				Sequence:        102,
				FragmentIndex:   2,
				FragmentCount:   3,
				Payload:         payload[2000:],
				Encrypted:       true,
				CryptoPlacement: dataplane.CryptoPlacementKernel,
			},
			encryptedKernelPayload:  true,
			encryptedKernelFragment: true,
		},
	}

	got := manager.reassembleTIXTCPCryptoFragments(frames)
	defer releaseReceivedTIXTCPFrames(got)
	if len(got) != 1 {
		t.Fatalf("frames = %d, want 1", len(got))
	}
	frame := got[0].frame
	if frame.Sequence != 100 || frame.FragmentIndex != 0 || frame.FragmentCount != 0 {
		t.Fatalf("reassembled header = seq %d index %d count %d", frame.Sequence, frame.FragmentIndex, frame.FragmentCount)
	}
	if !bytes.Equal(frame.Payload, payload) {
		t.Fatalf("payload was not reassembled")
	}
	if !got[0].encryptedKernelPayload || got[0].encryptedKernelFragment {
		t.Fatalf("encrypted markers = payload:%v fragment:%v, want payload-only", got[0].encryptedKernelPayload, got[0].encryptedKernelFragment)
	}
	wantPlainLen := len(payload) - kernelCryptoSecureHeaderLen - kernelCryptoFrameTagLen
	if got[0].kernelOpenPlain == nil || len(got[0].kernelOpenPlain) != wantPlainLen {
		t.Fatalf("kernel open plain buffer length = %d, want %d", len(got[0].kernelOpenPlain), wantPlainLen)
	}
	if got[0].kernelOpenPlainRelease == nil {
		t.Fatal("kernel open plain release was not installed")
	}
	if !frame.Encrypted || !frame.InnerIPv4 || frame.CryptoPlacement != dataplane.CryptoPlacementKernel {
		t.Fatalf("frame metadata = encrypted:%v inner:%v placement:%q", frame.Encrypted, frame.InnerIPv4, frame.CryptoPlacement)
	}
}

func TestUpdatePreparedKernelUDPPayloadPreservesFrameFlags(t *testing.T) {
	item := preparedKernelUDPTXFrame{
		wireFrame: kerneludp.Frame{
			Flags:   kerneludp.FlagEncrypted | kerneludp.FlagInnerIPv4,
			FlowID:  9,
			Payload: []byte("old"),
		},
	}

	if err := updatePreparedKernelUDPPayload(&item, []byte("new-payload")); err != nil {
		t.Fatalf("update prepared kernel_udp payload: %v", err)
	}
	wantFlags := kerneludp.FlagEncrypted | kerneludp.FlagInnerIPv4
	if item.wireFrame.Flags&wantFlags != wantFlags {
		t.Fatalf("flags = %#x, want to preserve %#x", item.wireFrame.Flags, wantFlags)
	}
	if !bytes.Equal(item.wireFrame.Payload, []byte("new-payload")) {
		t.Fatalf("payload = %q, want new payload", item.wireFrame.Payload)
	}
	if item.frameWireLen == 0 || item.packetWireLen == 0 {
		t.Fatalf("wire lengths were not refreshed: frame=%d packet=%d", item.frameWireLen, item.packetWireLen)
	}
}

func TestReassembleKernelUDPCryptoFragments(t *testing.T) {
	manager := NewManager()
	payload := bytesOf(0x42, 130000)
	fragmentSize := 800
	fragmentCount := (len(payload) + fragmentSize - 1) / fragmentSize
	packet := kerneludp.UDPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.2"),
		DestinationIP:   netip.MustParseAddr("192.0.2.1"),
		SourcePort:      50000,
		DestinationPort: 40000,
	}
	var fragments []receivedKernelUDPFrame
	for i, start := 0, 0; start < len(payload); i, start = i+1, start+fragmentSize {
		end := min(start+fragmentSize, len(payload))
		fragments = append(fragments, receivedKernelUDPFrame{
			frame: dataplane.KernelUDPFrame{
				FlowID:        12,
				Sequence:      77 + uint64(i),
				FragmentIndex: uint16(i),
				FragmentCount: uint16(fragmentCount),
				InnerIPv4:     true,
				Payload:       payload[start:end],
			},
			packet:                  packet,
			encryptedKernelPayload:  true,
			encryptedKernelFragment: true,
		})
	}

	got := manager.reassembleKernelUDPCryptoFragments(fragments[:2])
	if len(got) != 0 {
		t.Fatalf("partial reassembly produced %d frames", len(got))
	}
	got = manager.reassembleKernelUDPCryptoFragments(fragments[2:])
	if len(got) != 1 {
		t.Fatalf("complete reassembly produced %d frames, want 1", len(got))
	}
	frame := got[0].frame
	if frame.Sequence != 77 || frame.FragmentIndex != 0 || frame.FragmentCount != 0 {
		t.Fatalf("reassembled header = seq %d index %d count %d", frame.Sequence, frame.FragmentIndex, frame.FragmentCount)
	}
	if !got[0].encryptedKernelPayload || got[0].encryptedKernelFragment {
		t.Fatalf("reassembled crypto flags payload=%t fragment=%t", got[0].encryptedKernelPayload, got[0].encryptedKernelFragment)
	}
	if !bytes.Equal(frame.Payload, payload) {
		t.Fatalf("reassembled payload len=%d, want %d", len(frame.Payload), len(payload))
	}
	if !frame.InnerIPv4 {
		t.Fatalf("reassembled frame lost inner IPv4 marker")
	}
}

func TestReassembleKernelUDPCryptoFragmentsCoalescesFullRun(t *testing.T) {
	manager := NewManager()
	payload := bytesOf(0x7b, 2300)
	packet := kerneludp.UDPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.2"),
		DestinationIP:   netip.MustParseAddr("192.0.2.1"),
		SourcePort:      50000,
		DestinationPort: 40000,
	}
	fragments := []receivedKernelUDPFrame{
		{
			frame: dataplane.KernelUDPFrame{
				FlowID:        12,
				Sequence:      77,
				FragmentIndex: 0,
				FragmentCount: 3,
				InnerIPv4:     true,
				Payload:       payload[:800],
			},
			packet:                  packet,
			encryptedKernelPayload:  true,
			encryptedKernelFragment: true,
		},
		{
			frame: dataplane.KernelUDPFrame{
				FlowID:        12,
				Sequence:      78,
				FragmentIndex: 1,
				FragmentCount: 3,
				InnerIPv4:     true,
				Payload:       payload[800:1600],
			},
			packet:                  packet,
			encryptedKernelPayload:  true,
			encryptedKernelFragment: true,
		},
		{
			frame: dataplane.KernelUDPFrame{
				FlowID:        12,
				Sequence:      79,
				FragmentIndex: 2,
				FragmentCount: 3,
				InnerIPv4:     true,
				Payload:       payload[1600:],
			},
			packet:                  packet,
			encryptedKernelPayload:  true,
			encryptedKernelFragment: true,
		},
	}
	got := manager.reassembleKernelUDPCryptoFragments(fragments)
	if len(got) != 1 {
		t.Fatalf("full-run reassembly produced %d frames, want 1", len(got))
	}
	if got[0].frame.Sequence != 77 || got[0].frame.FragmentIndex != 0 || got[0].frame.FragmentCount != 0 {
		t.Fatalf("reassembled header = seq %d index %d count %d", got[0].frame.Sequence, got[0].frame.FragmentIndex, got[0].frame.FragmentCount)
	}
	if !got[0].encryptedKernelPayload || got[0].encryptedKernelFragment {
		t.Fatalf("reassembled crypto flags payload=%t fragment=%t", got[0].encryptedKernelPayload, got[0].encryptedKernelFragment)
	}
	if !bytes.Equal(got[0].frame.Payload, payload) {
		t.Fatalf("reassembled payload mismatch")
	}
	if !got[0].frame.InnerIPv4 {
		t.Fatalf("full-run reassembly lost inner IPv4 marker")
	}
	if manager.kernelUDPCryptoFragments != nil && len(manager.kernelUDPCryptoFragments) != 0 {
		t.Fatalf("full-run reassembly used manager fragment map: %d", len(manager.kernelUDPCryptoFragments))
	}
}

func TestIngestKernelUDPCryptoFragmentHandlesLastFragmentFirst(t *testing.T) {
	manager := NewManager()
	payload := bytesOf(0x24, 2300)
	packet := kerneludp.UDPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.2"),
		DestinationIP:   netip.MustParseAddr("192.0.2.1"),
		SourcePort:      50000,
		DestinationPort: 40000,
	}
	makeItem := func(index int, chunk []byte) receivedKernelUDPFrame {
		return receivedKernelUDPFrame{
			frame: dataplane.KernelUDPFrame{
				FlowID:        12,
				Sequence:      77 + uint64(index),
				FragmentIndex: uint16(index),
				FragmentCount: 3,
				InnerIPv4:     index == 0,
				Payload:       chunk,
			},
			packet:                  packet,
			encryptedKernelPayload:  true,
			encryptedKernelFragment: true,
		}
	}
	last := append([]byte(nil), payload[1600:]...)
	if _, ok := manager.ingestKernelUDPCryptoFragment(makeItem(2, last), time.Unix(0, 0)); ok {
		t.Fatalf("last fragment unexpectedly completed assembly")
	}
	for i := range last {
		last[i] = 0
	}
	if _, ok := manager.ingestKernelUDPCryptoFragment(makeItem(0, payload[:800]), time.Unix(0, 1)); ok {
		t.Fatalf("first fragment unexpectedly completed assembly")
	}
	got, ok := manager.ingestKernelUDPCryptoFragment(makeItem(1, payload[800:1600]), time.Unix(0, 2))
	if !ok {
		t.Fatalf("middle fragment did not complete assembly")
	}
	if !bytes.Equal(got.frame.Payload, payload) {
		t.Fatalf("reassembled payload changed after source mutation")
	}
	if !got.frame.InnerIPv4 {
		t.Fatalf("map reassembly lost inner IPv4 marker")
	}
}

func validKernelCryptoSpec(flowID uint64) dataplane.TIXTCPCryptoSpec {
	return dataplane.TIXTCPCryptoSpec{
		FlowID:       flowID,
		Suite:        kernelCryptoSuiteAES256GCMX25519,
		WireFormat:   kernelCryptoWireFormatTrustIXSecureDataV1,
		Epoch:        7,
		SendKey:      bytesOf(0x11, kernelCryptoAES256KeyLen),
		SendIV:       bytesOf(0x33, kernelCryptoAESGCMIVLen),
		RecvKey:      bytesOf(0x22, kernelCryptoAES256KeyLen),
		RecvIV:       bytesOf(0x44, kernelCryptoAESGCMIVLen),
		ReplayWindow: 64,
	}
}

func TestRouteTCPGSOAsyncWorkerHasMemoryAndBatchingGuards(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "kernel", "trustix_datapath_helpers", "trustix_datapath_helpers_kfuncs.c"))
	if err != nil {
		t.Fatalf("read TrustIX datapath helper source: %v", err)
	}
	source := string(body)
	for _, want := range []string{
		"route_tcp_gso_async_bytes_limit",
		"route_tcp_gso_async_queued_bytes",
		"route_tcp_gso_async_queue_bytes_full",
		"atomic_long_add_return",
		"atomic_long_sub_return",
		"trustix_tixt_tx_validate_route_gso_xmit_skb_gso",
		"trustix_tixt_tx_validate_route_gso_stream_frame",
		"route_tcp_gso_async_stream_outer_gso_verify_errors",
		"skb_gso_ok(skb, features)",
		"ip_len != skb->len - ETH_HLEN",
		"frame_len < TRUSTIX_TIXT_HEADER_LEN + sizeof(*inner_iph)",
		"trustix_tixt_tx_route_gso_xmit_ready_async",
		"route_tcp_gso_async_xmit_busy_retry_attempts",
		"route_tcp_gso_async_xmit_busy_retry_successes",
		"route_tcp_gso_async_xmit_busy_retry_failures",
		"route_tcp_gso_async_txq_stopped_queued",
		"trustix_tixt_tx_route_gso_stream_build_direct_batch",
		"trustix_tixt_tx_route_gso_stream_xmit_direct_batch",
		"TRUSTIX_TIXT_TX_ROUTE_SYNC_STREAM_MAX_BATCHES",
		"u32 route_flow_mask;",
		"item->route_flow_mask = READ_ONCE(route->flow_mask);",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("route TCP GSO async worker source missing %q", want)
		}
	}
	plainValidateBody := sourceFunctionBody(t, source, "trustix_tixt_tx_validate_route_plain_flow_pulled")
	if !strings.Contains(plainValidateBody, "trustix_tixt_tx_select_inline_flow(data, data_end, route,") {
		t.Fatal("route TCP plaintext route validation must select the inline flow from the route")
	}
	if strings.Contains(plainValidateBody, "READ_ONCE(route->flow_mask))\n\t\treturn -EPROTONOSUPPORT;") {
		t.Fatal("route TCP plaintext route validation must allow multi-flow route entries")
	}
	templateMatchBody := sourceFunctionBody(t, source, "trustix_route_tcp_gso_async_cross_item_template_match")
	for _, want := range []string{
		"a->queue_hash != b->queue_hash",
		"a->route_flow_mask != b->route_flow_mask",
	} {
		if !strings.Contains(templateMatchBody, want) {
			t.Fatalf("route TCP GSO cross-item template match missing %q", want)
		}
	}
	candidateBody := sourceFunctionBody(t, source, "trustix_route_tcp_gso_async_cross_item_candidate")
	if strings.Contains(candidateBody, "first->route_flow_mask || item->route_flow_mask") {
		t.Fatal("route TCP GSO cross-item candidate must not reject multi-flow route entries before template selection")
	}
	hashBody := sourceFunctionBody(t, source, "trustix_route_tcp_gso_async_hash_skb")
	for _, want := range []string{
		"item->inner_flow_saddr = iph->saddr;",
		"item->inner_flow_daddr = iph->daddr;",
		"item->inner_flow_sport = tcph->source;",
		"item->inner_flow_dport = tcph->dest;",
		"item->inner_tcp_seq_base = ntohl(tcph->seq);",
		"item->inner_flow_key_ready = true;",
	} {
		if !strings.Contains(hashBody, want) {
			t.Fatalf("route TCP GSO inner-flow hash source missing %q", want)
		}
	}
	if strings.Contains(hashBody, "skb_get_hash") {
		t.Fatal("route TCP GSO async queue hash must not use skb_get_hash; use parsed inner TCP flow identity for ordering")
	}
	sameInnerFlowBody := sourceFunctionBody(t, source, "trustix_route_tcp_gso_async_same_inner_tcp_flow")
	for _, want := range []string{
		"a->inner_flow_key_ready && b->inner_flow_key_ready",
		"a->inner_flow_saddr == b->inner_flow_saddr",
		"a->inner_flow_daddr == b->inner_flow_daddr",
		"a->inner_flow_sport == b->inner_flow_sport",
		"a->inner_flow_dport == b->inner_flow_dport",
	} {
		if !strings.Contains(sameInnerFlowBody, want) {
			t.Fatalf("route TCP GSO same-inner-flow guard missing %q", want)
		}
	}
	for _, want := range []string{
		"trustix_route_tcp_gso_async_same_inner_tcp_flow(first,",
		"item->inner_tcp_seq_base != expected_inner_tcp_seq",
	} {
		if !strings.Contains(candidateBody, want) {
			t.Fatalf("route TCP GSO plaintext skip-sequence candidate guard missing %q", want)
		}
	}
	sameStreamBody := sourceFunctionBody(t, source, "trustix_route_tcp_gso_async_cross_item_same_stream")
	for _, want := range []string{
		"trustix_tixt_tx_plain_skip_sequence_enabled()",
		"!first->tmpl.secure && !item->tmpl.secure",
		"trustix_route_tcp_gso_async_same_inner_tcp_flow(",
		"return first->queue_hash == item->queue_hash;",
		"first->flow_id == item->flow_id",
	} {
		if !strings.Contains(sameStreamBody, want) {
			t.Fatalf("route TCP GSO cross-item same-stream guard missing %q", want)
		}
	}
	if strings.Index(sameStreamBody, "trustix_tixt_tx_plain_skip_sequence_enabled()") >
		strings.Index(sameStreamBody, "first->flow_id == item->flow_id") {
		t.Fatal("route TCP GSO plaintext skip-sequence same-stream guard must run before route flow_id fallback")
	}
	tryBody := sourceFunctionBody(t, source, "trustix_route_tcp_gso_async_worker_try_cross_item")
	if strings.Contains(tryBody, "first->route_flow_mask") {
		t.Fatal("route TCP GSO cross-item worker must not self-degrade multi-flow route entries")
	}
	if !strings.Contains(tryBody, "first->inner_tcp_seq_base + first->payload_len") ||
		!strings.Contains(tryBody, "batch->next_inner_tcp_seq") {
		t.Fatal("route TCP GSO cross-item worker must advance plaintext candidates by inner TCP sequence")
	}
	workerDrainBody := sourceFunctionBody(t, source, "trustix_route_tcp_gso_async_worker_drain")
	for _, want := range []string{
		"READ_ONCE(trustix_route_tcp_gso_async_worker_dequeue_batch)",
		"if (dequeue_batch > TRUSTIX_TIXT_TX_ROUTE_STREAM_MAX_FRAMES)",
		"LIST_HEAD(local);",
		"list_add_tail(&item->list, &local);",
		"trustix_route_tcp_gso_async_worker_dequeue_batches++",
		"trustix_route_tcp_gso_async_worker_dequeue_items +=",
		"trustix_route_tcp_gso_async_worker_try_cross_item(\n\t\t\t\t\t&local, NULL, true, item,",
		"list_splice_init(&local, queue);",
	} {
		if !strings.Contains(workerDrainBody, want) {
			t.Fatalf("route TCP GSO worker local dequeue batching missing %q", want)
		}
	}
	secureRouteBody := sourceFunctionBody(t, source, "trustix_kernel_skb_tixt_tx_segment_route_tcp_gso_async_ex")
	if !strings.Contains(secureRouteBody, "if (secure) {\n\t\tsequence = atomic64_fetch_add(\n\t\t\tsegment_count,") ||
		!strings.Contains(secureRouteBody, "&trustix_route_tcp_gso_secure_outer_sequence") ||
		!strings.Contains(secureRouteBody, "item->outer_sequence = outer_sequence;") {
		t.Fatal("secure route TCP GSO must keep AEAD frame sequence separate from the outer TCP byte-sequence range")
	}
	for _, want := range []string{
		"inner_queue_hash =\n\t\ttrustix_route_tcp_gso_async_hash_skb(skb, flow_id, item);",
		"item->queue_hash = inner_queue_hash;",
	} {
		if !strings.Contains(secureRouteBody, want) {
			t.Fatalf("route TCP GSO enqueue path missing %q", want)
		}
	}
	secureStreamBody := sourceFunctionBody(t, source, "trustix_tixt_tx_route_gso_async_try_stream_direct")
	if !strings.Contains(secureStreamBody, "outer_sequence += frame_len;") ||
		!strings.Contains(secureStreamBody, "sequence += item->tmpl.secure ? 1 : frame_len;") {
		t.Fatal("secure route TCP GSO direct stream must keep outer TCP bytes separate from AEAD frame sequence")
	}
	processBody := sourceFunctionBody(t, source, "trustix_tixt_tx_route_gso_async_process_item")
	if !strings.Contains(processBody, "if (!item->resliced || item->tmpl.secure)") ||
		!strings.Contains(processBody, "if (item->tmpl.secure)") {
		t.Fatal("secure route TCP GSO must not fall through to plaintext async segmentation fallback")
	}
	workerBody := sourceFunctionBody(t, source, "trustix_route_tcp_xmit_worker_fn")
	if !strings.Contains(workerBody, "trustix_tixt_tx_sanitize_route_gso_xmit_skb(skb, dev)") {
		t.Fatal("route TCP xmit worker must sanitize skb before dev_queue_xmit")
	}
	sanitizeBody := sourceFunctionBody(t, source, "trustix_tixt_tx_sanitize_route_gso_xmit_skb")
	backoffBody := sourceFunctionBody(t, source, "trustix_tixt_tx_route_gso_maybe_backoff_stopped_txq")
	if !strings.Contains(sanitizeBody, "trustix_tixt_tx_route_gso_maybe_backoff_stopped_txq(txq)") ||
		!strings.Contains(backoffBody, "trustix_route_tcp_gso_async_txq_stopped_queued++") ||
		strings.Contains(sanitizeBody, "return -EBUSY;") ||
		strings.Contains(backoffBody, "return -EBUSY;") {
		t.Fatal("route TCP GSO sanitize must not drop dev_queue_xmit skbs only because the selected TX queue is transiently stopped")
	}
	readyBody := sourceFunctionBody(t, source, "trustix_tixt_tx_route_gso_xmit_ready")
	if strings.Contains(readyBody, "netif_xmit_stopped") {
		t.Fatal("route TCP GSO dev_queue_xmit readiness must not treat a transiently stopped TX queue as a hard failure")
	}
	virtioBody := sourceFunctionBody(t, source, "trustix_tixt_tx_route_gso_virtio_net")
	for _, want := range []string{
		"out_dev->dev.parent",
		"parent->driver",
		`!strcmp(driver->name, "virtio_net")`,
	} {
		if !strings.Contains(virtioBody, want) {
			t.Fatalf("route TCP GSO virtio detection missing %q", want)
		}
	}
	outerGSOCapableBody := sourceFunctionBody(t, source, "trustix_tixt_tx_route_gso_outer_gso_capable")
	for _, want := range []string{
		"trustix_route_tcp_gso_async_stream_allow_virtio_net",
		"trustix_tixt_tx_route_gso_virtio_net(out_dev)",
		"trustix_route_tcp_gso_async_stream_outer_gso_virtio_blocked++",
	} {
		if !strings.Contains(outerGSOCapableBody, want) {
			t.Fatalf("route TCP GSO virtio outer-GSO guard missing %q", want)
		}
	}
	templateBody := sourceFunctionBody(t, source, "trustix_tixt_tx_init_route_gso_template")
	if !strings.Contains(templateBody,
		"trustix_tixt_tx_route_gso_outer_gso_capable(tmpl, false)") {
		t.Fatal("route TCP GSO template must select outer GSO from the actual output device capability")
	}
	crossItemBody := sourceFunctionBody(t, source, "trustix_route_tcp_gso_async_worker_try_cross_item")
	if !strings.Contains(crossItemBody, "!first->tmpl.stream_outer_gso") {
		t.Fatal("route TCP GSO cross-item batching must bypass devices guarded from outer GSO")
	}
}

func TestRemotePerfMatrixAppliesSysfsAfterModuleReload(t *testing.T) {
	path := filepath.Join("..", "..", "..", "build", "run_remote_perf_matrix.py")
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Skipf("remote perf matrix source is not present in this tree: %s", path)
		}
		t.Fatalf("stat remote perf matrix source %s: %v", path, err)
	}
	source := readSourceFile(t, path)
	runCase := sourceFunctionBody(t, source, "run_case")

	restartIdx := strings.Index(runCase, "pids = restart_pair(")
	waitModulesIdx := strings.Index(runCase, "required_modules_after_start = wait_required_modules_loaded(")
	waitReadyIdx := strings.Index(runCase, "ready = wait_ready(")
	firstSysfsIdx := strings.Index(runCase, "kudp_rx_hot_stats_param = set_kudp_rx_hot_stats(")
	if restartIdx < 0 || waitModulesIdx < 0 || waitReadyIdx < 0 || firstSysfsIdx < 0 {
		t.Fatalf("remote matrix run_case is missing expected lifecycle markers")
	}
	if firstSysfsIdx < restartIdx {
		t.Fatalf("remote matrix writes module sysfs knobs before restart_pair")
	}
	if !(restartIdx < waitModulesIdx && waitModulesIdx < firstSysfsIdx && firstSysfsIdx < waitReadyIdx) {
		t.Fatalf("remote matrix must restart, wait for required modules, apply sysfs knobs, then run ready ping")
	}
	requireSourceContains(t, source, "def wait_required_modules_loaded(")
	requireSourceContains(t, source, `"required_modules_after_ready": required_modules_after_ready`)
}

func TestFirstReleasePanicRiskModuleParametersFailClosed(t *testing.T) {
	datapathSource := readSourceFile(t, filepath.Join("..", "..", "..", "kernel", "trustix_datapath", "trustix_datapath.c"))
	helpersMainSource := readSourceFile(t, filepath.Join("..", "..", "..", "kernel", "trustix_datapath_helpers", "trustix_datapath_helpers_main.c"))
	helpersSource := readSourceFile(t, filepath.Join("..", "..", "..", "kernel", "trustix_datapath_helpers", "trustix_datapath_helpers_kfuncs.c"))
	cryptoSource := readSourceFile(t, filepath.Join("..", "..", "..", "kernel", "trustix_crypto", "trustix_crypto.c"))

	for _, name := range []string{
		"rx_worker_steal_skb",
		"rx_worker_inline_stolen",
		"rx_worker_inline_receive",
		"rx_worker_steal_xmit",
		"rx_worker_steal_tcp",
	} {
		requireModuleParamPermission(t, datapathSource, name, "0644")
	}
	for _, name := range []string{
		"rx_worker_xmit",
		"rx_worker_xmit_hash_tx_queue",
		"rx_worker_xmit_more",
		"rx_worker_tc_skip_classify",
		"rx_worker_inline_xmit",
		"rx_worker_inline_xmit_copy_csum",
		"rx_worker_inline_pair_coalesce",
		"rx_worker_inline_pair_flush_jiffies",
		"rx_worker_inline_pair_hold_skb",
		"rx_worker_inline_coalesce_max_frames",
		"rx_worker_single_coalesce",
		"rx_worker_single_coalesce_flush_jiffies",
		"rx_worker_single_coalesce_max_frames",
		"rx_worker_xmit_trust_tcp_checksum_min_len",
		"rx_worker_xmit_trust_tcp_checksum_ack_only",
		"rx_worker_xmit_tcp_partial_csum",
		"rx_worker_xmit_dst_mac_cache",
		"rx_worker_xmit_dst_mac_pcpu_cache",
		"rx_worker_xmit_dst_mac_seq_cache",
		"rx_worker_queue_skb",
		"rx_worker_stream_coalesce_gso",
		"rx_worker_stream_coalesce_software_segment",
		"rx_worker_stream_coalesce_partial_csum",
		"rx_worker_tcp",
		"rx_worker_stream_tcp",
		"rx_worker_stream_batch_queue",
	} {
		requireModuleParamPermission(t, datapathSource, name, "0644")
	}
	requireModuleParamPermission(t, datapathSource, "rx_worker_direct_xmit", "0644")
	if strings.Contains(datapathSource, "dev_direct_xmit(") ||
		strings.Contains(helpersSource, "dev_direct_xmit(") {
		t.Fatal("kernel datapath sources must not call panic-prone dev_direct_xmit")
	}
	if strings.Contains(datapathSource, "netif_receive_skb(") ||
		strings.Contains(datapathSource, "netif_receive_skb_list(") {
		t.Fatal("kernel datapath module must use backlog/worker receive, not direct protocol-stack reinjection")
	}
	for _, want := range []string{
		"trustix_tixt_rx_publish_one_backlog",
		"trustix_tixt_rx_publish_skb_chain_backlog",
		"trustix_tixt_rx_publish_receive_list_backlog",
		"trustix_tixt_rx_backlog_worker_fn",
		"tixt_rx_backlog_worker_queue_limit",
		"tixt_rx_backlog_worker_enqueued",
		"tixt_rx_stream_backlog_packets",
		"tixt_rx_coalesce_segment_backlog_packets",
		"tixt_rx_single_coalesce_netif_rx_drops",
	} {
		requireSourceContains(t, helpersSource, want)
	}
	workerBody := sourceFunctionBody(t, helpersSource, "trustix_tixt_rx_backlog_worker_fn")
	if !strings.Contains(workerBody, "netif_receive_skb(skb)") {
		t.Fatal("TIXT RX backlog worker must own protocol-stack reinjection")
	}
	for _, name := range []string{
		"trustix_tixt_rx_coalesced_segment_and_publish",
		"trustix_tixt_rx_stream_publish_extra_list",
		"trustix_tixt_rx_stream_try_coalesce_gso",
		"trustix_tixt_rx_single_coalesce_publish",
	} {
		body := sourceFunctionBody(t, helpersSource, name)
		if strings.Contains(body, "netif_receive_skb(") ||
			strings.Contains(body, "netif_receive_skb_list(") {
			t.Fatalf("%s must enqueue to the safe RX backlog worker instead of direct receive", name)
		}
	}
	requireSourceContains(t, datapathSource, "trustix_datapath_rx_worker_direct_xmit_safe_fallbacks++;")
	requireSourceContains(t, datapathSource, "trustix_datapath_rx_worker_inline_receive_safe_fallbacks++;")
	requireSourceContains(t, datapathSource, "static bool trustix_datapath_rx_worker_tc_skip_classify;")
	tcSkipBody := sourceFunctionBody(t, datapathSource, "trustix_datapath_rx_worker_request_tc_skip")
	requireSourceContains(t, tcSkipBody, "if (!READ_ONCE(trustix_datapath_rx_worker_tc_skip_classify))\n\t\treturn;")
	requireSourceContains(t, datapathSource, "trustix_datapath_rx_worker_param_set_stolen_noop")
	requireSourceContains(t, datapathSource, "trustix_datapath_rx_worker_steal_param_safe_fallbacks++;")
	requireSourceContains(t, datapathSource, "trustix_datapath_rx_worker_param_set_unsafe_bool_noop")
	requireSourceContains(t, datapathSource, "trustix_datapath_rx_worker_param_set_unsafe_uint_noop")
	requireSourceContains(t, datapathSource, "trustix_datapath_rx_worker_unsafe_param_safe_fallbacks++;")
	requireSourceContains(t, datapathSource, "WRITE_ONCE(*(bool *)kp->arg, false);")
	for _, want := range []string{
		"module_param_cb(rx_worker_steal_skb,\n\t\t&trustix_datapath_rx_worker_stolen_noop_bool_ops",
		"module_param_cb(rx_worker_inline_stolen,\n\t\t&trustix_datapath_rx_worker_stolen_noop_bool_ops",
		"module_param_cb(rx_worker_steal_xmit,\n\t\t&trustix_datapath_rx_worker_stolen_noop_bool_ops",
		"module_param_cb(rx_worker_steal_tcp,\n\t\t&trustix_datapath_rx_worker_stolen_noop_bool_ops",
		"module_param_cb(rx_worker_xmit_tcp_partial_csum,\n\t\t&trustix_datapath_rx_worker_unsafe_noop_bool_ops",
		"module_param_cb(rx_worker_stream_coalesce_partial_csum,\n\t\t&trustix_datapath_rx_worker_unsafe_noop_bool_ops",
		"module_param_cb(rx_worker_xmit_trust_tcp_checksum_ack_only,\n\t\t&trustix_datapath_rx_worker_unsafe_noop_bool_ops",
		"module_param_cb(rx_worker_xmit_trust_tcp_checksum_min_len,\n\t\t&trustix_datapath_rx_worker_unsafe_noop_uint_ops",
	} {
		requireSourceContains(t, datapathSource, want)
	}
	requireSourceContains(t, datapathSource, "trustix_datapath_rx_worker_drop_pending_sync();")
	requireSourceContains(t, datapathSource, "trustix_datapath_rx_worker_dev_ready(dev)")
	requireSourceContains(t, datapathSource, "if (skb_is_gso(skb))")
	requireSourceContains(t, datapathSource, "trustix_datapath_rx_worker_xmit_inner_gso_segments(")
	innerGSOXmitBody := sourceFunctionBody(t, datapathSource, "trustix_datapath_rx_worker_xmit_inner_gso")
	requireSourceContains(t, innerGSOXmitBody, "READ_ONCE(trustix_datapath_rx_worker_stream_coalesce_software_segment)")
	requireSourceContains(t, innerGSOXmitBody, "trustix_datapath_rx_worker_gso_xmit_fallbacks++;")
	softwareSegmentStart := strings.Index(innerGSOXmitBody, "READ_ONCE(trustix_datapath_rx_worker_stream_coalesce_software_segment)")
	supportedStart := strings.Index(innerGSOXmitBody, "trustix_datapath_rx_worker_inner_gso_xmit_supported")
	segmentsStart := strings.Index(innerGSOXmitBody, "trustix_datapath_rx_worker_xmit_inner_gso_segments")
	if softwareSegmentStart < 0 || supportedStart < 0 || segmentsStart < 0 ||
		softwareSegmentStart >= supportedStart || supportedStart >= segmentsStart {
		t.Fatal("rx_worker_stream_coalesce_software_segment must gate direct inner GSO xmit before segment fallback")
	}
	requireSourceContains(t, datapathSource, "current safe implementation falls back to copy/worker")
	requireSourceContains(t, datapathSource, "trustix_datapath_rx_worker_steal_fallbacks++;\n\treturn false;")
	coalescedBuilderBody := sourceFunctionBody(t, datapathSource, "trustix_datapath_rx_worker_build_coalesced_gso_skb")
	requireSourceContains(t, coalescedBuilderBody, "tcph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr,")
	requireSourceContains(t, coalescedBuilderBody, "skb->ip_summed = CHECKSUM_PARTIAL;")
	requireSourceContains(t, coalescedBuilderBody, "skb->csum_start = (unsigned char *)tcph - skb->head;")
	requireSourceContains(t, coalescedBuilderBody, "skb->csum_offset = offsetof(struct tcphdr, check);")
	requireSourceNotContains(t, coalescedBuilderBody, "skb->ip_summed = CHECKSUM_NONE;")
	requireSourceNotContains(t, coalescedBuilderBody, "trustix_datapath_rx_worker_stream_coalesce_checksum_fallbacks++")
	coalescedBody := sourceFunctionBody(t, datapathSource, "trustix_datapath_rx_worker_xmit_coalesced_inner_skb")
	inlineStart := strings.Index(coalescedBody, "if (inline_context)")
	prepareStart := strings.Index(coalescedBody, "trustix_datapath_rx_worker_prepare_inner_skb")
	if inlineStart < 0 || prepareStart < 0 || inlineStart >= prepareStart {
		t.Fatal("coalesced GSO xmit must explicitly reject inline/hook context before preparing the skb")
	}
	inlineCoalescedBranch := coalescedBody[inlineStart:prepareStart]
	if strings.Contains(inlineCoalescedBranch, "trustix_datapath_rx_worker_enqueue_pending_skb") {
		t.Fatal("coalesced GSO skbs must not be queued from inline/hook context")
	}
	requireSourceContains(t, inlineCoalescedBranch, "kfree_skb(skb);")
	requireSourceContains(t, inlineCoalescedBranch, "return -EOPNOTSUPP;")
	for _, name := range []string{
		"trustix_datapath_rx_worker_inline_pair_coalesce_view",
		"trustix_datapath_rx_worker_inline_xmit_stream_copy",
		"trustix_datapath_rx_worker_push_stream_batch_copy",
	} {
		body := sourceFunctionBody(t, datapathSource, name)
		if strings.Contains(body, "trustix_datapath_rx_worker_build_coalesced_gso_skb") ||
			strings.Contains(body, "trustix_datapath_rx_worker_xmit_coalesced_inner_skb") {
			t.Fatalf("%s must self-degrade hook/inline coalesced GSO to per-frame worker queueing", name)
		}
	}
	for _, forbidden := range []string{
		"trustix_datapath_disable_panic_risk_params();",
		"WRITE_ONCE(trustix_datapath_rx_worker_steal_skb, false);",
		"WRITE_ONCE(trustix_datapath_rx_worker_inline_stolen, false);",
	} {
		if strings.Contains(datapathSource, forbidden) {
			t.Fatalf("kernel datapath must not hard-disable safe-fallback RX worker option %q", forbidden)
		}
	}

	for _, name := range []string{
		"tixt_rx_stream_ordered_list",
		"tixt_rx_stream_nonlinear_parse",
	} {
		requireModuleParamPermission(t, helpersSource, name, "0644")
	}
	for _, name := range []string{
		"route_tcp_gso",
		"route_tcp_gso_async",
		"route_tcp_gso_async_dev_xmit",
		"route_tcp_gso_async_unbound_worker",
		"route_tcp_gso_async_sharded_queue",
		"route_tcp_gso_async_flow_shard_queue",
		"route_tcp_gso_async_stream",
		"route_tcp_gso_async_stream_direct_build",
		"route_tcp_gso_async_direct_xmit",
		"route_tcp_gso_async_stream_allow_virtio_net",
		"route_tcp_gso_async_stream_outer_gso",
		"route_tcp_gso_async_stream_outer_gso_hard_enable",
		"route_tcp_gso_async_stream_cross_item_batch",
		"route_tcp_gso_async_stream_cross_item_dequeue_batch",
		"route_tcp_gso_async_hash_tx_queue",
		"route_tcp_xmit_worker_steal",
		"tixt_rx_stream_parse",
		"tixt_rx_stream_xmit_extra",
		"tixt_rx_stream_gso_xmit",
		"tixt_rx_stream_coalesce_gso",
		"tixt_rx_stream_coalesce_mark_gso",
		"tixt_rx_stream_max_frames",
		"tixt_rx_single_coalesce_gso",
		"tixt_rx_single_coalesce_mark_gso",
		"tixt_rx_coalesce_mark_gso_partial_csum",
		"tixt_rx_coalesce_segment_gso",
		"tixt_rx_single_coalesce_skip_tcp_csum",
		"tixt_rx_single_coalesce_direct_list",
		"tixt_rx_single_coalesce_direct_list_max_frames",
		"tixt_rx_single_coalesce_page_only",
		"tixt_rx_single_coalesce_linear_build",
		"tixt_rx_single_coalesce_hybrid_head",
		"tixt_rx_single_coalesce_netif_rx",
		"tixt_rx_single_coalesce_schedule_once",
		"tixt_rx_single_coalesce_stream_fallback",
		"tixt_rx_single_coalesce_defer_full_flush",
		"tixt_rx_single_coalesce_keep_full_timer",
		"tixt_rx_single_coalesce_set_hash",
		"tixt_rx_single_coalesce_schedule_stride",
		"tixt_rx_single_coalesce_max_frames",
		"tixt_rx_single_coalesce_flush_jiffies",
		"tixt_rx_single_coalesce_warmup_frames",
		"tixt_rx_single_coalesce_linear_max",
	} {
		requireModuleParamPermission(t, helpersSource, name, "0644")
	}
	requireSourceContains(t, helpersSource, "module_param_cb(tixt_rx_single_coalesce_linear_max,")
	requireSourceContains(t, helpersSource, "trustix_tixt_rx_single_coalesce_linear_max_ops, NULL, 0644")
	for _, want := range []string{
		"trustix_datapath_helpers_disable_panic_risk_params();",
	} {
		if strings.HasPrefix(want, "trustix_datapath_helpers") {
			requireSourceContains(t, helpersMainSource, want)
			continue
		}
		requireSourceContains(t, helpersSource, want)
	}
	requireSourceContains(t, helpersSource, "datapath can self-degrade under validation")

	requireModuleParamPermission(t, cryptoSource, "kfunc_simd_fastpath", "0644")
	requireModuleParamPermission(t, cryptoSource, "kfunc_simd_irq_fpu_fastpath", "0644")
	for _, name := range []string{
		"direct_kfunc_batch_seal_errors",
		"direct_kfunc_seal_errors",
		"direct_kfunc_open_errors",
		"direct_kfunc_skb_seal_errors",
		"direct_kfunc_skb_open_errors",
		"direct_kfunc_einval_errors",
		"direct_kfunc_eopnotsupp_errors",
		"direct_kfunc_efault_errors",
		"direct_kfunc_enoent_errors",
		"direct_kfunc_ebadmsg_errors",
		"direct_kfunc_other_errors",
		"direct_kfunc_fpu_unavailable_fallbacks",
	} {
		requireModuleParamPermission(t, cryptoSource, name, "0444")
	}
	requireSourceContains(t, cryptoSource, "trustix_direct_kfunc_record_error(\n\tint ret, enum trustix_direct_kfunc_error_site site)")
	requireSourceNotContains(t, cryptoSource, "WRITE_ONCE(trustix_kfunc_simd_fastpath, false);")
}

func TestTrustIXCryptoDirectKfuncKeepsSnapshotFallbackForSlotFastpathOptOut(t *testing.T) {
	cryptoSource := readSourceFile(t, filepath.Join("..", "..", "..", "kernel", "trustix_crypto", "trustix_crypto.c"))

	requireModuleParamPermission(t, cryptoSource, "kfunc_direct_slot_fastpath", "0644")
	requireSourceContains(t, cryptoSource, "static bool trustix_kfunc_direct_slot_fastpath = true;")

	snapshotBody := sourceFunctionBody(t, cryptoSource, "trustix_aead_direct_snapshot_slot")
	requireSourceContains(t, snapshotBody, "rcu_read_lock();")
	requireSourceContains(t, snapshotBody, "rcu_read_unlock();")
	requireSourceNotContains(t, snapshotBody, "kernel_fpu_begin();")

	requireSourceContains(t, cryptoSource, "if (!in_task() && !READ_ONCE(trustix_kfunc_simd_irq_fpu_fastpath))\n\t\treturn false;")
	requireSourceContains(t, cryptoSource, "if (!trustix_aead_fpu_begin()) {\n\t\ttrustix_direct_kfunc_record_fpu_unavailable();\n\t\treturn trustix_aead_direct_crypt_one_soft(slot, op, decrypt);\n\t}\n\tret = trustix_aead_direct_crypt_one_nofpu")
	requireSourceContains(t, cryptoSource, "trustix_aead_fpu_end();")

	slotBody := sourceFunctionBody(t, cryptoSource, "trustix_aead_direct_crypt_one_slot_rcu")
	requireSourceContains(t, slotBody, "if (!trustix_kfunc_direct_slot_fastpath)")
	requireSourceContains(t, slotBody, "rcu_read_lock();")
	requireSourceContains(t, slotBody, "rcu_read_unlock();")
	requireSourceContains(t, slotBody, "trustix_aead_fpu_begin()")
	requireSourceContains(t, slotBody, "trustix_aead_direct_crypt_one_soft_fields(\n\t\t\t\tslot->rk, slot->rounds, slot->h, op, decrypt);")
	requireSourceContains(t, slotBody, "trustix_aead_fpu_end();")

	for _, name := range []string{
		"trustix_kernel_direct_seal",
		"trustix_kernel_direct_open",
		"trustix_kernel_skb_direct_open",
		"trustix_kernel_skb_direct_seal",
	} {
		body := sourceFunctionBody(t, cryptoSource, name)
		slot := strings.Index(body, "trustix_aead_direct_crypt_one_slot_rcu")
		fallback := strings.Index(body, "trustix_aead_direct_snapshot_slot")
		if slot < 0 || fallback < 0 || slot > fallback {
			t.Fatalf("%s must try direct slot before snapshot fallback: slot=%d fallback=%d", name, slot, fallback)
		}
		requireSourceNotContains(t, body, "rcu_read_lock();")
		requireSourceNotContains(t, body, "rcu_read_unlock();")
	}

	skbOpenBody := sourceFunctionBody(t, cryptoSource, "trustix_kernel_skb_direct_open")
	requireSourceContains(t, skbOpenBody, "if (tail_len)\n\t\treturn -EOPNOTSUPP;")
	requireSourceNotContains(t, skbOpenBody, "memmove(cipher + plain_len")
}

func readSourceFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read source %s: %v", path, err)
	}
	return string(body)
}

func requireModuleParamPermission(t *testing.T, source, name, wantPermission string) {
	t.Helper()
	compact := strings.Join(strings.Fields(source), " ")
	start := strings.Index(compact, "module_param_named("+name+",")
	if start < 0 {
		start = strings.Index(compact, "module_param_cb("+name+",")
	}
	if start < 0 {
		t.Fatalf("module parameter %s is missing", name)
	}
	end := strings.Index(compact[start:], ");")
	if end < 0 {
		t.Fatalf("module parameter %s declaration is unterminated", name)
	}
	decl := compact[start : start+end]
	if !strings.Contains(decl, ", "+wantPermission) {
		t.Fatalf("module parameter %s declaration %q does not use permission %s", name, decl, wantPermission)
	}
}

func requireSourceContains(t *testing.T, source, want string) {
	t.Helper()
	if !strings.Contains(source, want) {
		t.Fatalf("source missing %q", want)
	}
}

func requireSourceNotContains(t *testing.T, source, want string) {
	t.Helper()
	if strings.Contains(source, want) {
		t.Fatalf("source unexpectedly contains %q", want)
	}
}
