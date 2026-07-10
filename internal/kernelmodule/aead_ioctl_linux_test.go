//go:build linux

package kernelmodule

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func TestTrustIXDatapathHelpersDeviceQueryAndSelftest(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trustix_datapath_helpers device test requires root")
	}
	if info, err := os.Stat(TrustIXDatapathHelpersDevicePath); err != nil || info.IsDir() {
		t.Skip("trustix_datapath_helpers device is not available; load trustix_datapath_helpers.ko")
	}
	query, err := ProbeDatapath("")
	if err != nil {
		t.Fatalf("probe datapath: %v", err)
	}
	if query.ModuleABIVersion != 1 || query.DatapathABIVersion != 1 {
		t.Fatalf("unexpected datapath ABI query: %#v", query)
	}
	if !query.TIXTSelftestOK() {
		t.Fatalf("datapath TIXT selftest not clean in query: %#v", query)
	}
	if !query.FeaturesActive() {
		t.Fatalf("datapath did not report active packet features: %#v", query)
	}
	if !query.SafeActiveFeature(FeatureGSOSKB) {
		t.Fatalf("datapath did not report safe active gso_skb helper feature: %#v", query)
	}
	if query.SafeActiveFeature(FeatureFullDatapath) {
		t.Fatalf("datapath helper module unexpectedly reports full_datapath: %#v", query)
	}
	selftest, err := RunDatapathSelftest("", TrustIXDatapathHelpersSelftestAll)
	if err != nil {
		t.Fatalf("run datapath selftest: %v", err)
	}
	if selftest.Requested != TrustIXDatapathHelpersSelftestAll ||
		selftest.Passed != TrustIXDatapathHelpersSelftestAll ||
		selftest.Failed != 0 ||
		selftest.Flags&TrustIXDatapathHelpersFlagTIXTSelftestOK == 0 {
		t.Fatalf("unexpected datapath selftest result: %#v", selftest)
	}
}

func TestTrustIXFullDatapathDeviceQueryAndSelftest(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trustix_datapath device test requires root")
	}
	if info, err := os.Stat(TrustIXDatapathDevicePath); err != nil || info.IsDir() {
		t.Skip("trustix_datapath device is not available; load trustix_datapath.ko")
	}
	query, err := ProbeDatapath(TrustIXDatapathDevicePath)
	if err != nil {
		t.Fatalf("probe full datapath: %v", err)
	}
	if query.ModuleABIVersion != 1 || query.DatapathABIVersion != 1 {
		t.Fatalf("unexpected full datapath ABI query: %#v", query)
	}
	if !query.TIXTSelftestOK() {
		t.Fatalf("full datapath TIXT selftest not clean in query: %#v", query)
	}
	if query.FeaturesActive() {
		if !query.SafeActiveFeature(FeatureFullDatapath) {
			t.Fatalf("full datapath module reported active features without safe full_datapath: %#v", query)
		}
	} else if query.SafeActiveFeature(FeatureFullDatapath) {
		t.Fatalf("full datapath module reported safe full_datapath without active feature gate: %#v", query)
	}
	selftest, err := RunDatapathSelftest(TrustIXDatapathDevicePath, TrustIXDatapathSelftestAll)
	if err != nil {
		if errors.Is(err, syscall.EBUSY) {
			t.Skipf("trustix_datapath selftest is busy; unload active datapath users before running this device selftest: %v", err)
		}
		t.Fatalf("run full datapath selftest: %v", err)
	}
	if selftest.Requested != TrustIXDatapathSelftestAll ||
		selftest.Passed != TrustIXDatapathSelftestAll ||
		selftest.Failed != 0 ||
		selftest.Flags&TrustIXDatapathHelpersFlagTIXTSelftestOK == 0 {
		t.Fatalf("unexpected full datapath selftest result: %#v", selftest)
	}
	if query.FeaturesActive() != (selftest.Flags&TrustIXDatapathHelpersFlagFeaturesActive != 0) {
		t.Fatalf("full datapath feature-active flag changed unexpectedly: query=%#v selftest=%#v", query, selftest)
	}
	testTrustIXFullDatapathStateABI(t)
	testTrustIXFullDatapathHookLifecycle(t)
}

func TestTrustIXFullDatapathRXWorkerInjectsWithoutPanic(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trustix_datapath RX worker test requires root")
	}
	if info, err := os.Stat(TrustIXDatapathDevicePath); err != nil || info.IsDir() {
		t.Skip("trustix_datapath device is not available; load trustix_datapath.ko rx_worker_inject=1")
	}
	if !trustIXFullDatapathRXWorkerInjectEnabled() {
		t.Skip("trustix_datapath rx_worker_inject is disabled; load module with rx_worker_inject=1")
	}
	installFullDatapathOuterTestState(t)
	if _, err := DatapathHookDetach(TrustIXDatapathDevicePath); err != nil && err != syscall.ENOENT {
		t.Fatalf("detach before RX worker ingress: %v", err)
	}
	ingress := "tixdwi0"
	peer := "tixdwp0"
	target := "tixdwt0"
	if err := unixLinkAddVeth(ingress, peer); err != nil {
		t.Skipf("veth unavailable for datapath RX worker ingress: %v", err)
	}
	defer unixLinkDelete(ingress)
	if err := unixLinkAddDummy(target); err != nil {
		t.Skipf("dummy netdev unavailable for datapath RX worker target: %v", err)
	}
	defer unixLinkDelete(target)
	if err := unixLinkSetUp(ingress); err != nil {
		t.Skipf("unable to bring RX worker ingress veth up: %v", err)
	}
	if err := unixLinkSetUp(peer); err != nil {
		t.Skipf("unable to bring RX worker peer veth up: %v", err)
	}
	if err := unixLinkSetUp(target); err != nil {
		t.Skipf("unable to bring RX worker target dummy up: %v", err)
	}
	status, err := DatapathHook(TrustIXDatapathDevicePath, DatapathHookRequest{
		Op:           TrustIXDatapathHookOpAttach,
		Flags:        TrustIXDatapathHookFlagRXPreview | TrustIXDatapathHookFlagRXWorker,
		IfName:       ingress,
		TargetIfName: target,
	})
	if err != nil {
		t.Fatalf("attach datapath hook for RX worker ingress: %v", err)
	}
	defer func() {
		if _, err := DatapathHookDetach(TrustIXDatapathDevicePath); err != nil && err != syscall.ENOENT {
			t.Fatalf("detach RX worker ingress hook: %v", err)
		}
	}()
	if status.Flags&TrustIXDatapathHookFlagRXWorker == 0 {
		t.Fatalf("RX worker flag was not retained: %#v", status)
	}
	if status.TargetIfName != target || status.TargetIfIndex <= 0 {
		t.Fatalf("RX worker target was not retained: %#v", status)
	}
	inner := buildIPv4UDPPacketWithPayload(0x0a520001, 0x0a520009, 12345, 5201, bytesOf(0x6b, 48))
	outer, err := DatapathOuterBuild(TrustIXDatapathDevicePath, inner, 654)
	if err != nil {
		t.Fatalf("build outer packet for RX worker hook ingress: %v", err)
	}
	if err := sendIPv4EthernetFrame(peer, outer.Outer); err != nil {
		t.Skipf("unable to inject RX worker outer ingress frame: %v", err)
	}
	var query DatapathHookStatus
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		query, err = DatapathHookQuery(TrustIXDatapathDevicePath)
		if err != nil {
			t.Fatalf("query datapath hook after RX worker ingress: %v", err)
		}
		if query.RXWorkerInjected > 0 || query.RXWorkerDropped > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if query.OuterParsed == 0 || query.RXWorker == 0 || query.RXWorkerInjected == 0 {
		t.Fatalf("RX worker did not inject outer ingress packet cleanly: %#v", query)
	}
	if query.TargetIfName != target || query.TargetIfIndex != status.TargetIfIndex {
		t.Fatalf("RX worker target changed after injection: before=%#v after=%#v", status, query)
	}
}

func TestTrustIXFullDatapathRXWorkerWithTCClsactDoesNotPanic(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trustix_datapath RX worker TC coexistence test requires root")
	}
	if _, err := exec.LookPath("tc"); err != nil {
		t.Skip("tc is not available")
	}
	if info, err := os.Stat(TrustIXDatapathDevicePath); err != nil || info.IsDir() {
		t.Skip("trustix_datapath device is not available; load trustix_datapath.ko rx_worker_inject=1")
	}
	if !trustIXFullDatapathRXWorkerInjectEnabled() {
		t.Skip("trustix_datapath rx_worker_inject is disabled; load module with rx_worker_inject=1")
	}
	installFullDatapathOuterTestState(t)
	if _, err := DatapathHookDetach(TrustIXDatapathDevicePath); err != nil && err != syscall.ENOENT {
		t.Fatalf("detach before RX worker TC ingress: %v", err)
	}
	ingress := "tixdtc0"
	peer := "tixdtp0"
	target := "tixdtt0"
	targetPeer := "tixdtr0"
	if err := unixLinkAddVeth(ingress, peer); err != nil {
		t.Skipf("veth unavailable for datapath RX worker TC ingress: %v", err)
	}
	defer unixLinkDelete(ingress)
	if err := unixLinkAddVeth(target, targetPeer); err != nil {
		t.Skipf("veth unavailable for datapath RX worker TC target: %v", err)
	}
	defer unixLinkDelete(target)
	for _, name := range []string{ingress, peer, target, targetPeer} {
		if err := unixLinkSetUp(name); err != nil {
			t.Skipf("unable to bring RX worker TC netdev %s up: %v", name, err)
		}
	}
	recvFD, err := openIPv4PacketSocket(targetPeer)
	if err != nil {
		t.Skipf("unable to monitor RX worker TC target peer: %v", err)
	}
	defer syscall.Close(recvFD)
	if err := tcQdiscAddClsact(ingress); err != nil {
		t.Skipf("unable to add clsact qdisc to RX worker ingress: %v", err)
	}
	defer tcQdiscDelClsact(ingress)
	_ = tcFilterAddPass(ingress, "ingress")
	_ = tcFilterAddPass(ingress, "egress")
	status, err := DatapathHook(TrustIXDatapathDevicePath, DatapathHookRequest{
		Op:           TrustIXDatapathHookOpAttach,
		Flags:        TrustIXDatapathHookFlagRXPreview | TrustIXDatapathHookFlagRXWorker,
		IfName:       ingress,
		TargetIfName: target,
	})
	if err != nil {
		t.Fatalf("attach datapath hook for RX worker TC ingress: %v", err)
	}
	defer func() {
		if _, err := DatapathHookDetach(TrustIXDatapathDevicePath); err != nil && err != syscall.ENOENT {
			t.Fatalf("detach RX worker TC ingress hook: %v", err)
		}
	}()
	if status.Flags&TrustIXDatapathHookFlagRXWorker == 0 {
		t.Fatalf("RX worker flag was not retained with TC clsact: %#v", status)
	}
	inner := buildIPv4UDPPacketWithPayload(0x0a520001, 0x0a520009, 12345, 5201, bytesOf(0x6c, 48))
	outer, err := DatapathOuterBuild(TrustIXDatapathDevicePath, inner, 655)
	if err != nil {
		t.Fatalf("build outer packet for RX worker TC ingress: %v", err)
	}
	if err := sendIPv4EthernetFrame(peer, outer.Outer); err != nil {
		t.Skipf("unable to inject RX worker TC outer ingress frame: %v", err)
	}
	received, packetType, err := recvIPv4PacketWithType(recvFD, 2*time.Second)
	if err != nil {
		t.Fatalf("receive RX worker inner packet on target veth peer: %v", err)
	}
	if packetType != 0 {
		t.Fatalf("RX worker inner packet type = %d, want PACKET_HOST", packetType)
	}
	if !bytes.Equal(received, inner) {
		t.Fatalf("RX worker inner packet mismatch: got=%x want=%x", received, inner)
	}
	var query DatapathHookStatus
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		query, err = DatapathHookQuery(TrustIXDatapathDevicePath)
		if err != nil {
			t.Fatalf("query datapath hook after RX worker TC ingress: %v", err)
		}
		if query.RXWorkerInjected > 0 || query.RXWorkerDropped > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if query.OuterParsed == 0 || query.RXWorker == 0 || query.RXWorkerInjected == 0 {
		t.Fatalf("RX worker did not inject TC-coexisting outer ingress packet cleanly: %#v", query)
	}
}

func TestTrustIXFullDatapathRXWorkerTCPStreamDoesNotPanic(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trustix_datapath RX worker TCP stream test requires root")
	}
	if info, err := os.Stat(TrustIXDatapathDevicePath); err != nil || info.IsDir() {
		t.Skip("trustix_datapath device is not available; load trustix_datapath.ko rx_worker_inject=1")
	}
	if !trustIXFullDatapathRXWorkerInjectEnabled() {
		t.Skip("trustix_datapath rx_worker_inject is disabled; load module with rx_worker_inject=1")
	}
	if !trustIXFullDatapathRXWorkerXmitEnabled() {
		t.Skip("trustix_datapath rx_worker_xmit is disabled; load module with rx_worker_xmit=1")
	}
	installFullDatapathOuterTestState(t)
	if _, err := DatapathHookDetach(TrustIXDatapathDevicePath); err != nil && err != syscall.ENOENT {
		t.Fatalf("detach before RX worker TCP ingress: %v", err)
	}
	ingress := "tixdxi0"
	peer := "tixdxp0"
	target := "tixdxt0"
	targetPeer := "tixdxr0"
	if err := unixLinkAddVeth(ingress, peer); err != nil {
		t.Skipf("veth unavailable for datapath RX worker TCP ingress: %v", err)
	}
	defer unixLinkDelete(ingress)
	if err := unixLinkAddVeth(target, targetPeer); err != nil {
		t.Skipf("veth unavailable for datapath RX worker TCP target: %v", err)
	}
	defer unixLinkDelete(target)
	for _, name := range []string{ingress, peer, target, targetPeer} {
		if err := unixLinkSetUp(name); err != nil {
			t.Skipf("unable to bring RX worker TCP netdev %s up: %v", name, err)
		}
	}
	status, err := DatapathHook(TrustIXDatapathDevicePath, DatapathHookRequest{
		Op:           TrustIXDatapathHookOpAttach,
		Flags:        TrustIXDatapathHookFlagRXPreview | TrustIXDatapathHookFlagRXWorker,
		IfName:       ingress,
		TargetIfName: target,
	})
	if err != nil {
		t.Fatalf("attach datapath hook for RX worker TCP ingress: %v", err)
	}
	defer func() {
		if _, err := DatapathHookDetach(TrustIXDatapathDevicePath); err != nil && err != syscall.ENOENT {
			t.Fatalf("detach RX worker TCP ingress hook: %v", err)
		}
	}()
	if status.Flags&TrustIXDatapathHookFlagRXWorker == 0 {
		t.Fatalf("RX worker flag was not retained for TCP stream: %#v", status)
	}
	payload0 := bytesOf(0x71, 32)
	payload1 := bytesOf(0x72, 32)
	inner0 := buildIPv4TCPPacketWithPayload(0x0a520001, 0x0a520009, 12345, 5201, 1000, 0, 0x18, payload0)
	inner1 := buildIPv4TCPPacketWithPayload(0x0a520001, 0x0a520009, 12345, 5201, uint32(1000+len(payload0)), 0, 0x18, payload1)
	outer0, err := DatapathOuterBuild(TrustIXDatapathDevicePath, inner0, 656)
	if err != nil {
		t.Fatalf("build first outer TCP packet for RX worker ingress: %v", err)
	}
	outer1, err := DatapathOuterBuild(TrustIXDatapathDevicePath, inner1, 657)
	if err != nil {
		t.Fatalf("build second outer TCP packet for RX worker ingress: %v", err)
	}
	if err := sendIPv4EthernetFrame(peer, outer0.Outer); err != nil {
		t.Skipf("unable to inject first RX worker TCP outer ingress frame: %v", err)
	}
	if err := sendIPv4EthernetFrame(peer, outer1.Outer); err != nil {
		t.Skipf("unable to inject second RX worker TCP outer ingress frame: %v", err)
	}
	var query DatapathHookStatus
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		query, err = DatapathHookQuery(TrustIXDatapathDevicePath)
		if err != nil {
			t.Fatalf("query datapath hook after RX worker TCP ingress: %v", err)
		}
		if query.RXWorkerInjected >= 2 || query.RXWorkerDropped > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if query.OuterParsed < 2 || query.RXWorker < 2 || query.RXWorkerInjected < 2 {
		t.Fatalf("RX worker did not inject TCP stream packets cleanly: %#v", query)
	}
}

func TestTrustIXFullDatapathTXPlaintextEncapsulatesWithoutPanic(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trustix_datapath TX plaintext test requires root")
	}
	if info, err := os.Stat(TrustIXDatapathDevicePath); err != nil || info.IsDir() {
		t.Skip("trustix_datapath device is not available; load trustix_datapath.ko tx_plaintext=1")
	}
	if !trustIXFullDatapathTXPlaintextEnabled() {
		t.Skip("trustix_datapath tx_plaintext is disabled; load module with tx_plaintext=1")
	}
	installFullDatapathOuterTestState(t)
	if _, err := DatapathHookDetach(TrustIXDatapathDevicePath); err != nil && err != syscall.ENOENT {
		t.Fatalf("detach before TX plaintext hook: %v", err)
	}

	lanIngress := "tixdtx0"
	lanPeer := "tixdtxp0"
	underlay := "tixdtu0"
	underlayPeer := "tixdtp0"
	if err := unixLinkAddVeth(lanIngress, lanPeer); err != nil {
		t.Skipf("veth unavailable for datapath TX plaintext LAN ingress: %v", err)
	}
	defer unixLinkDelete(lanIngress)
	if err := unixLinkAddVeth(underlay, underlayPeer); err != nil {
		t.Skipf("veth unavailable for datapath TX plaintext underlay: %v", err)
	}
	defer unixLinkDelete(underlay)
	for _, name := range []string{lanIngress, lanPeer, underlay, underlayPeer} {
		if err := unixLinkSetUp(name); err != nil {
			t.Skipf("unable to bring %s up for TX plaintext test: %v", name, err)
		}
	}
	if err := unixAddrAdd(underlay, "192.0.2.1/24"); err != nil {
		t.Skipf("unable to add underlay source address: %v", err)
	}
	if err := unixRouteReplace("198.51.100.2/32", underlay, "192.0.2.1"); err != nil {
		t.Skipf("unable to install underlay route: %v", err)
	}
	defer unixRouteDelete("198.51.100.2/32", underlay)
	peerIface, err := net.InterfaceByName(underlayPeer)
	if err != nil || len(peerIface.HardwareAddr) < 6 {
		t.Skipf("unable to resolve underlay peer hardware address: iface=%v err=%v", peerIface, err)
	}
	if err := unixNeighReplace(underlay, "198.51.100.2", peerIface.HardwareAddr.String()); err != nil {
		t.Skipf("unable to install underlay neighbor: %v", err)
	}
	defer unixNeighDelete(underlay, "198.51.100.2")

	recvFD, err := openIPv4PacketSocket(underlayPeer)
	if err != nil {
		t.Skipf("unable to open underlay packet capture socket: %v", err)
	}
	defer syscall.Close(recvFD)

	beforeTX, _ := readUint64File("/sys/module/trustix_datapath/parameters/tx_plaintext_packets")
	status, err := DatapathHook(TrustIXDatapathDevicePath, DatapathHookRequest{
		Op:           TrustIXDatapathHookOpAttach,
		Flags:        TrustIXDatapathHookFlagTXPlaintext,
		IfName:       lanIngress,
		TargetIfName: underlay,
	})
	if err != nil {
		t.Fatalf("attach datapath TX plaintext hook: %v", err)
	}
	defer func() {
		if _, err := DatapathHookDetach(TrustIXDatapathDevicePath); err != nil && err != syscall.ENOENT {
			t.Fatalf("detach TX plaintext hook: %v", err)
		}
	}()
	if !status.Attached || status.IfName != lanIngress || status.TargetIfName != underlay || status.TargetIfIndex <= 0 {
		t.Fatalf("unexpected TX plaintext hook attach status: %#v", status)
	}
	if status.Flags&TrustIXDatapathHookFlagTXPlaintext == 0 {
		t.Fatalf("TX plaintext hook flag was not retained: %#v", status)
	}

	innerPayload := bytesOf(0x6b, 48)
	inner := buildIPv4UDPPacketWithPayload(0x0a520001, 0x0a520009, 12345, 5201, innerPayload)
	if err := sendIPv4EthernetFrame(lanPeer, inner); err != nil {
		t.Skipf("unable to inject inner LAN frame: %v", err)
	}
	outerIP, err := recvIPv4Packet(recvFD, 2*time.Second)
	if err != nil {
		t.Fatalf("receive TX plaintext outer packet: %v", err)
	}
	parsed, err := DatapathOuterParse(TrustIXDatapathDevicePath, outerIP)
	if err != nil {
		t.Fatalf("parse TX plaintext outer packet: %v", err)
	}
	if !bytes.Equal(parsed.Inner, inner) ||
		parsed.LocalIPv4 != 0xc0000201 ||
		parsed.RemoteIPv4 != 0xc6336402 ||
		parsed.LocalPort != 51820 ||
		parsed.RemotePort != 17041 ||
		parsed.OuterProtocol != 17 {
		t.Fatalf("unexpected TX plaintext outer packet: parsed=%#v", parsed)
	}

	deadline := time.Now().Add(2 * time.Second)
	var afterTX uint64
	for time.Now().Before(deadline) {
		afterTX, _ = readUint64File("/sys/module/trustix_datapath/parameters/tx_plaintext_packets")
		if afterTX > beforeTX {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if afterTX <= beforeTX {
		t.Fatalf("tx_plaintext_packets did not increase: before=%d after=%d", beforeTX, afterTX)
	}
	query, err := DatapathHookQuery(TrustIXDatapathDevicePath)
	if err != nil {
		t.Fatalf("query TX plaintext hook: %v", err)
	}
	if query.Classified == 0 || query.Drop == 0 {
		t.Fatalf("TX plaintext hook did not classify/drop the inner packet: %#v", query)
	}
}

func testTrustIXFullDatapathStateABI(t *testing.T) {
	t.Helper()
	initial, err := DatapathStateStatsQuery(TrustIXDatapathDevicePath)
	if err != nil {
		t.Fatalf("query full datapath state stats: %v", err)
	}
	if initial.MaxRoutes == 0 || initial.MaxSessions == 0 || initial.MaxFlows == 0 || initial.MaxSessionWires == 0 {
		t.Fatalf("state table capacities were not initialized: %#v", initial)
	}
	records := []DatapathStateRecord{
		{
			Kind:  TrustIXDatapathStateKindRoute,
			Op:    TrustIXDatapathStateOpUpsert,
			Flags: 0x11,
			Key:   [4]uint64{0x0a520001, 24, 0, 0},
			Value: [8]uint64{0x01020304, 1500, 7, 0},
		},
		{
			Kind:  TrustIXDatapathStateKindSession,
			Op:    TrustIXDatapathStateOpUpsert,
			Flags: 0x22,
			Key:   [4]uint64{0x1122334455667788, 1, 0, 0},
			Value: [8]uint64{0x99, 0x0a000001, 51820, 1500},
		},
		{
			Kind:  TrustIXDatapathStateKindSessionWire,
			Op:    TrustIXDatapathStateOpUpsert,
			Flags: 0x44,
			Key:   [4]uint64{0x1122334455667788, 1, 0, 0},
			Value: [8]uint64{0x99, 0xc0000201, 0xc6336402, uint64(51820)<<16 | 17041, 1, 64000},
		},
		{
			Kind:  TrustIXDatapathStateKindFlow,
			Op:    TrustIXDatapathStateOpUpsert,
			Flags: 0x33,
			Key:   [4]uint64{0x9988776655443322, 6, 12345, 443},
			Value: [8]uint64{0x1122334455667788, 1, 2, 3},
		},
	}
	applied, batchRecords, err := DatapathApplyStateBatch(TrustIXDatapathDevicePath, records)
	if err != nil {
		t.Fatalf("batch upsert state: applied=%d err=%v", applied, err)
	}
	if applied != uint32(len(records)) || len(batchRecords) != len(records) {
		t.Fatalf("batch applied=%d records=%d want %d", applied, len(batchRecords), len(records))
	}
	for _, record := range records {
		get := record
		get.Op = TrustIXDatapathStateOpGet
		get.Flags = 0
		get.Value = [8]uint64{}
		got, err := DatapathApplyState(TrustIXDatapathDevicePath, get)
		if err != nil {
			t.Fatalf("get state kind=%d: %v", record.Kind, err)
		}
		if got.Flags != record.Flags || got.Value != record.Value {
			t.Fatalf("state roundtrip kind=%d got=%#v want flags=%#x value=%#v", record.Kind, got, record.Flags, record.Value)
		}
	}
	afterUpsert, err := DatapathStateStatsQuery(TrustIXDatapathDevicePath)
	if err != nil {
		t.Fatalf("query stats after upsert: %v", err)
	}
	if afterUpsert.Routes != initial.Routes+1 ||
		afterUpsert.Sessions != initial.Sessions+1 ||
		afterUpsert.SessionWires != initial.SessionWires+1 ||
		afterUpsert.Flows != initial.Flows+1 {
		t.Fatalf("unexpected state counts after upsert: initial=%#v after=%#v", initial, afterUpsert)
	}
	testTrustIXFullDatapathClassify(t)
	clearRecords := []DatapathStateRecord{
		{Kind: TrustIXDatapathStateKindRoute, Op: TrustIXDatapathStateOpClear},
		{Kind: TrustIXDatapathStateKindSession, Op: TrustIXDatapathStateOpClear},
		{Kind: TrustIXDatapathStateKindSessionWire, Op: TrustIXDatapathStateOpClear},
		{Kind: TrustIXDatapathStateKindFlow, Op: TrustIXDatapathStateOpClear},
	}
	applied, _, err = DatapathApplyStateBatch(TrustIXDatapathDevicePath, clearRecords)
	if err != nil {
		t.Fatalf("batch clear state: applied=%d err=%v", applied, err)
	}
	if applied != uint32(len(clearRecords)) {
		t.Fatalf("batch clear applied=%d want %d", applied, len(clearRecords))
	}
	afterClear, err := DatapathStateStatsQuery(TrustIXDatapathDevicePath)
	if err != nil {
		t.Fatalf("query stats after clear: %v", err)
	}
	if afterClear.Routes != 0 || afterClear.Sessions != 0 || afterClear.SessionWires != 0 || afterClear.Flows != 0 {
		t.Fatalf("state records remain after clear: %#v", afterClear)
	}
}

func testTrustIXFullDatapathClassify(t *testing.T) {
	t.Helper()
	installFullDatapathOuterTestState(t)
	got, err := DatapathClassify(TrustIXDatapathDevicePath, DatapathClassifyRequest{
		SourceIPv4:      0x0a520001,
		DestinationIPv4: 0x0a520009,
		SourcePort:      12345,
		DestinationPort: 5201,
		Protocol:        6,
	})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if got.RouteFlags != TrustIXDatapathRouteFlagUnicast ||
		got.PrefixLen != 24 ||
		got.FlowID != 0x9988776655443322 ||
		got.SessionFlags != 1<<2 {
		t.Fatalf("unexpected classify result: %#v", got)
	}
	testTrustIXFullDatapathPacketClassify(t)
}

func testTrustIXFullDatapathPacketClassify(t *testing.T) {
	t.Helper()
	before, err := DatapathPacketStatsQuery(TrustIXDatapathDevicePath)
	if err != nil {
		t.Fatalf("query packet stats before classify: %v", err)
	}
	packet := buildIPv4UDPPacket(0x0a520001, 0x0a520009, 12345, 5201, 32)
	got, err := DatapathPacketClassify(TrustIXDatapathDevicePath, packet)
	if err != nil {
		t.Fatalf("packet classify: %v", err)
	}
	if got.SourceIPv4 != 0x0a520001 ||
		got.DestinationIPv4 != 0x0a520009 ||
		got.SourcePort != 12345 ||
		got.DestinationPort != 5201 ||
		got.Protocol != 17 ||
		got.IPHeaderLen != 20 ||
		got.L4HeaderLen != 8 ||
		got.RouteFlags != TrustIXDatapathRouteFlagUnicast ||
		got.PrefixLen != 24 ||
		got.FlowID != 0x9988776655443322 ||
		got.SessionFlags != 1<<2 {
		t.Fatalf("unexpected packet classify result: %#v", got)
	}
	after, err := DatapathPacketStatsQuery(TrustIXDatapathDevicePath)
	if err != nil {
		t.Fatalf("query packet stats after classify: %v", err)
	}
	if after.Packets != before.Packets+1 ||
		after.Bytes != before.Bytes+uint64(len(packet)) ||
		after.UnicastRoutes != before.UnicastRoutes+1 {
		t.Fatalf("unexpected packet stats before=%#v after=%#v", before, after)
	}
	badPacket := append([]byte(nil), packet...)
	binary.BigEndian.PutUint16(badPacket[2:4], 18)
	if _, err := DatapathPacketClassify(TrustIXDatapathDevicePath, badPacket); err == nil {
		t.Fatal("packet classify accepted a truncated IPv4 total length")
	}
	afterBad, err := DatapathPacketStatsQuery(TrustIXDatapathDevicePath)
	if err != nil {
		t.Fatalf("query packet stats after bad classify: %v", err)
	}
	if afterBad.ParseErrors != after.ParseErrors+1 {
		t.Fatalf("bad packet did not increment parse errors: before=%#v after=%#v", after, afterBad)
	}
	testTrustIXFullDatapathTIXTEncap(t, packet)
}

func testTrustIXFullDatapathTIXTEncap(t *testing.T, inner []byte) {
	t.Helper()
	got, err := DatapathTIXTEncap(TrustIXDatapathDevicePath, inner, 77)
	if err != nil {
		t.Fatalf("TIXT encap: %v", err)
	}
	if got.WrittenLen != uint32(40+len(inner)) ||
		got.FlowID != 0x9988776655443322 ||
		got.RouteFlags != TrustIXDatapathRouteFlagUnicast ||
		got.PrefixLen != 24 ||
		got.SessionFlags != 1<<2 {
		t.Fatalf("unexpected TIXT encap result: %#v", got)
	}
	if len(got.Wire) != int(got.WrittenLen) ||
		!bytes.Equal(got.Wire[40:], inner) {
		t.Fatalf("unexpected TIXT encap wire len=%d written=%d", len(got.Wire), got.WrittenLen)
	}
	if binary.BigEndian.Uint32(got.Wire[0:4]) != 0x54495854 ||
		got.Wire[4] != 1 ||
		got.Wire[5] != 1<<3 ||
		binary.BigEndian.Uint16(got.Wire[6:8]) != 40 ||
		binary.BigEndian.Uint64(got.Wire[8:16]) != 0x9988776655443322 ||
		binary.BigEndian.Uint64(got.Wire[24:32]) != 77 ||
		binary.BigEndian.Uint32(got.Wire[32:36]) != uint32(len(inner)) {
		t.Fatalf("unexpected TIXT encap header: %x", got.Wire[:40])
	}
	decap, err := DatapathTIXTDecap(TrustIXDatapathDevicePath, got.Wire)
	if err != nil {
		t.Fatalf("TIXT decap: %v", err)
	}
	if decap.WrittenLen != uint32(len(inner)) ||
		decap.FlowID != 0x9988776655443322 ||
		decap.Sequence != 77 ||
		decap.PayloadLen != uint32(len(inner)) ||
		decap.TIXTFlags != 1<<3 ||
		decap.SessionFlags != 1<<2 ||
		!bytes.Equal(decap.Inner, inner) {
		t.Fatalf("unexpected TIXT decap result: %#v", decap)
	}
	testTrustIXFullDatapathOuterBuild(t, inner)
}

func testTrustIXFullDatapathOuterBuild(t *testing.T, inner []byte) {
	t.Helper()
	got, err := DatapathOuterBuild(TrustIXDatapathDevicePath, inner, 123)
	if err != nil {
		t.Fatalf("outer build: %v", err)
	}
	if got.WrittenLen != uint32(20+8+40+len(inner)) ||
		got.FlowID != 0x9988776655443322 ||
		got.Epoch != 9 ||
		got.RouteFlags != TrustIXDatapathRouteFlagUnicast ||
		got.PrefixLen != 24 ||
		got.SessionFlags != 1<<2 ||
		got.LocalIPv4 != 0xc0000201 ||
		got.RemoteIPv4 != 0xc6336402 ||
		got.LocalPort != 51820 ||
		got.RemotePort != 17041 ||
		got.OuterProtocol != 17 ||
		got.TIXTLen != uint32(40+len(inner)) {
		t.Fatalf("unexpected outer build result: %#v", got)
	}
	if len(got.Outer) != int(got.WrittenLen) {
		t.Fatalf("outer len=%d written=%d", len(got.Outer), got.WrittenLen)
	}
	if got.Outer[0] != 0x45 ||
		binary.BigEndian.Uint16(got.Outer[2:4]) != uint16(got.WrittenLen) ||
		got.Outer[9] != 17 ||
		binary.BigEndian.Uint32(got.Outer[12:16]) != 0xc0000201 ||
		binary.BigEndian.Uint32(got.Outer[16:20]) != 0xc6336402 ||
		binary.BigEndian.Uint16(got.Outer[20:22]) != 51820 ||
		binary.BigEndian.Uint16(got.Outer[22:24]) != 17041 ||
		binary.BigEndian.Uint16(got.Outer[24:26]) != uint16(8+40+len(inner)) {
		t.Fatalf("unexpected outer IPv4/UDP header: %x", got.Outer[:28])
	}
	tixt := got.Outer[28:]
	if binary.BigEndian.Uint32(tixt[0:4]) != 0x54495854 ||
		tixt[4] != 1 ||
		tixt[5] != 1<<3 ||
		binary.BigEndian.Uint16(tixt[6:8]) != 40 ||
		binary.BigEndian.Uint64(tixt[8:16]) != 0x9988776655443322 ||
		binary.BigEndian.Uint64(tixt[16:24]) != 9 ||
		binary.BigEndian.Uint64(tixt[24:32]) != 123 ||
		binary.BigEndian.Uint32(tixt[32:36]) != uint32(len(inner)) ||
		!bytes.Equal(tixt[40:], inner) {
		t.Fatalf("unexpected outer TIXT payload: %x", tixt[:40])
	}
	parsed, err := DatapathOuterParse(TrustIXDatapathDevicePath, got.Outer)
	if err != nil {
		t.Fatalf("outer parse: %v", err)
	}
	if parsed.WrittenLen != uint32(len(inner)) ||
		parsed.Flags != 0 ||
		parsed.FlowID != got.FlowID ||
		parsed.Epoch != got.Epoch ||
		parsed.Sequence != 123 ||
		parsed.PayloadLen != uint32(len(inner)) ||
		parsed.TIXTFlags != 1<<3 ||
		parsed.SessionFlags != got.SessionFlags ||
		parsed.LocalIPv4 != got.LocalIPv4 ||
		parsed.RemoteIPv4 != got.RemoteIPv4 ||
		parsed.LocalPort != got.LocalPort ||
		parsed.RemotePort != got.RemotePort ||
		parsed.OuterProtocol != got.OuterProtocol ||
		parsed.TIXTLen != got.TIXTLen ||
		!bytes.Equal(parsed.Inner, inner) {
		t.Fatalf("unexpected outer parse result: %#v", parsed)
	}
}

func testTrustIXFullDatapathHookLifecycle(t *testing.T) {
	t.Helper()
	if _, err := DatapathHookDetach(TrustIXDatapathDevicePath); err != nil && err != syscall.ENOENT {
		t.Fatalf("detach stale datapath hook: %v", err)
	}
	name := "tixdpl0"
	peer := "tixdpp0"
	if err := unixLinkAddVeth(name, peer); err != nil {
		t.Skipf("veth unavailable for datapath hook lifecycle: %v", err)
	}
	defer unixLinkDelete(name)
	if err := unixLinkSetUp(name); err != nil {
		t.Skipf("unable to bring datapath hook veth up: %v", err)
	}
	if err := unixLinkSetUp(peer); err != nil {
		t.Skipf("unable to bring datapath hook peer up: %v", err)
	}
	status, err := DatapathHook(TrustIXDatapathDevicePath, DatapathHookRequest{
		Op:     TrustIXDatapathHookOpAttach,
		IfName: name,
	})
	if err != nil {
		t.Fatalf("attach datapath hook: %v", err)
	}
	if !status.Attached || status.IfName != name || status.IfIndex <= 0 {
		t.Fatalf("unexpected hook attach status: %#v", status)
	}
	query, err := DatapathHookQuery(TrustIXDatapathDevicePath)
	if err != nil {
		t.Fatalf("query datapath hook: %v", err)
	}
	if !query.Attached || query.IfName != name || query.IfIndex != status.IfIndex {
		t.Fatalf("unexpected hook query status: %#v attach=%#v", query, status)
	}
	generateHookTraffic(t, peer)
	query, err = DatapathHookQuery(TrustIXDatapathDevicePath)
	if err != nil {
		t.Fatalf("query datapath hook after traffic: %v", err)
	}
	if query.Seen == 0 || query.Pass == 0 {
		t.Fatalf("hook did not observe dummy traffic: %#v", query)
	}
	detached, err := DatapathHookDetach(TrustIXDatapathDevicePath)
	if err != nil {
		t.Fatalf("detach datapath hook: %v", err)
	}
	if detached.Attached {
		t.Fatalf("hook remained attached after detach: %#v", detached)
	}
	query, err = DatapathHookQuery(TrustIXDatapathDevicePath)
	if err != nil {
		t.Fatalf("query datapath hook after detach: %v", err)
	}
	if query.Attached {
		t.Fatalf("hook query still attached after detach: %#v", query)
	}
	testTrustIXFullDatapathHookOuterIngress(t)
}

func testTrustIXFullDatapathHookOuterIngress(t *testing.T) {
	t.Helper()
	installFullDatapathOuterTestState(t)
	if _, err := DatapathHookDetach(TrustIXDatapathDevicePath); err != nil && err != syscall.ENOENT {
		t.Fatalf("detach before outer hook ingress: %v", err)
	}
	ingress := "tixdpi0"
	peer := "tixdpp0"
	if err := unixLinkAddVeth(ingress, peer); err != nil {
		t.Skipf("veth unavailable for datapath hook outer ingress: %v", err)
	}
	defer unixLinkDelete(ingress)
	if err := unixLinkSetUp(ingress); err != nil {
		t.Skipf("unable to bring ingress veth up: %v", err)
	}
	if err := unixLinkSetUp(peer); err != nil {
		t.Skipf("unable to bring peer veth up: %v", err)
	}
	status, err := DatapathHook(TrustIXDatapathDevicePath, DatapathHookRequest{
		Op:     TrustIXDatapathHookOpAttach,
		Flags:  TrustIXDatapathHookFlagRXPreview | TrustIXDatapathHookFlagRXStage,
		IfName: ingress,
	})
	if err != nil {
		t.Fatalf("attach datapath hook for outer ingress: %v", err)
	}
	defer func() {
		if _, err := DatapathHookDetach(TrustIXDatapathDevicePath); err != nil && err != syscall.ENOENT {
			t.Fatalf("detach outer ingress hook: %v", err)
		}
	}()
	if !status.Attached || status.IfName != ingress || status.IfIndex <= 0 {
		t.Fatalf("unexpected outer ingress hook attach status: %#v", status)
	}
	if status.Flags&(TrustIXDatapathHookFlagRXPreview|TrustIXDatapathHookFlagRXStage) != TrustIXDatapathHookFlagRXPreview|TrustIXDatapathHookFlagRXStage {
		t.Fatalf("outer ingress hook did not retain RX flags: %#v", status)
	}
	if stage, err := DatapathRXStageClear(TrustIXDatapathDevicePath); err != nil {
		t.Fatalf("clear RX stage before outer ingress: %v", err)
	} else if stage.QueueLen != 0 {
		t.Fatalf("RX stage queue not empty after clear: %#v", stage)
	}
	innerPayload := bytesOf(0x5a, 32)
	inner := buildIPv4UDPPacketWithPayload(0x0a520001, 0x0a520009, 12345, 5201, innerPayload)
	outer, err := DatapathOuterBuild(TrustIXDatapathDevicePath, inner, 321)
	if err != nil {
		t.Fatalf("build outer packet for hook ingress: %v", err)
	}
	if err := sendIPv4EthernetFrame(peer, outer.Outer); err != nil {
		t.Skipf("unable to inject outer ingress frame: %v", err)
	}
	var query DatapathHookStatus
	var peeked DatapathRXStageResult
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		query, err = DatapathHookQuery(TrustIXDatapathDevicePath)
		if err != nil {
			t.Fatalf("query datapath hook after outer ingress: %v", err)
		}
		peeked, err = DatapathRXStagePeek(TrustIXDatapathDevicePath)
		if err == nil && bytes.Equal(peeked.Inner, inner) {
			break
		}
		if err != nil && err != syscall.ENOENT {
			t.Fatalf("peek RX staged inner packet: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !bytes.Equal(peeked.Inner, inner) {
		t.Fatalf("peeked RX staged inner packet mismatch: got %x want %x", peeked.Inner, inner)
	}
	if query.OuterParsed == 0 || query.RXPreview == 0 || query.RXStage == 0 {
		t.Fatalf("hook did not report the staged outer ingress packet: %#v", query)
	}
	if peeked.Sequence != 321 || peeked.FlowID != outer.FlowID || peeked.Epoch != outer.Epoch ||
		peeked.PayloadLen != uint32(len(inner)) || peeked.QueueLen == 0 {
		t.Fatalf("unexpected RX stage metadata: %#v outer=%#v", peeked, outer)
	}
	popped, err := DatapathRXStagePop(TrustIXDatapathDevicePath)
	if err != nil {
		t.Fatalf("pop RX staged inner packet: %v", err)
	}
	if !bytes.Equal(popped.Inner, inner) || popped.QueueLen != 0 {
		t.Fatalf("unexpected popped RX staged packet: %#v", popped)
	}
	if _, err := DatapathRXStagePop(TrustIXDatapathDevicePath); err != syscall.ENOENT {
		t.Fatalf("pop empty RX stage err = %v, want ENOENT", err)
	}
}

func installFullDatapathOuterTestState(t *testing.T) {
	t.Helper()
	clearRecords := []DatapathStateRecord{
		{Kind: TrustIXDatapathStateKindRoute, Op: TrustIXDatapathStateOpClear},
		{Kind: TrustIXDatapathStateKindSession, Op: TrustIXDatapathStateOpClear},
		{Kind: TrustIXDatapathStateKindSessionWire, Op: TrustIXDatapathStateOpClear},
		{Kind: TrustIXDatapathStateKindFlow, Op: TrustIXDatapathStateOpClear},
	}
	if applied, _, err := DatapathApplyStateBatch(TrustIXDatapathDevicePath, clearRecords); err != nil || applied != uint32(len(clearRecords)) {
		t.Fatalf("clear before full datapath outer test state: applied=%d err=%v", applied, err)
	}
	records := []DatapathStateRecord{
		{
			Kind:  TrustIXDatapathStateKindRoute,
			Op:    TrustIXDatapathStateOpUpsert,
			Flags: TrustIXDatapathRouteFlagUnicast,
			Key:   [4]uint64{0x0a520000, 24, 0x1111, 0x2222},
			Value: [8]uint64{10},
		},
		{
			Kind:  TrustIXDatapathStateKindSession,
			Op:    TrustIXDatapathStateOpUpsert,
			Flags: 1 << 2,
			Key:   [4]uint64{0x1111, 0x2222, 1, 0},
			Value: [8]uint64{0x9988776655443322, 1, 0, 0, 0, 0, 0, 3},
		},
		{
			Kind:  TrustIXDatapathStateKindSessionWire,
			Op:    TrustIXDatapathStateOpUpsert,
			Flags: 1 | 2 | 4,
			Key:   [4]uint64{0x1111, 0x2222, 1, 0},
			Value: [8]uint64{0x9988776655443322, 0xc0000201, 0xc6336402, uint64(51820)<<16 | 17041, 1, 1500, 9, 3},
		},
		{
			Kind:  TrustIXDatapathStateKindFlow,
			Op:    TrustIXDatapathStateOpUpsert,
			Flags: 1,
			Key:   [4]uint64{0x0a520001, 0x0a520009, uint64(12345)<<16 | 5201, 6},
			Value: [8]uint64{0x1111, 0x2222, 3},
		},
	}
	if applied, _, err := DatapathApplyStateBatch(TrustIXDatapathDevicePath, records); err != nil || applied != uint32(len(records)) {
		t.Fatalf("install full datapath outer test state: applied=%d err=%v", applied, err)
	}
}

func TestTrustIXAEADDeviceBatchSealOpen(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trustix_crypto device test requires root")
	}
	if !AEADDeviceAvailable("") {
		t.Skip("trustix_crypto device is not available; load trustix_crypto.ko")
	}
	key := bytesOf(0x41, 32)
	plain := bytesOf(0x90, 1200)
	nonce1 := bytesOf(0x21, trustIXAEADIOCNonceLen)
	nonce2 := bytesOf(0x22, trustIXAEADIOCNonceLen)

	sealOps := []AEADBatchOp{
		{Nonce: nonce1, In: plain, Out: make([]byte, len(plain)+trustIXAEADIOCTagLen)},
		{Nonce: nonce2, In: plain[:511], Out: make([]byte, 511+trustIXAEADIOCTagLen)},
	}
	if err := AEADSealBatch("", key, sealOps); err != nil {
		t.Fatalf("seal batch: %v", err)
	}
	if len(sealOps[0].Out) != len(plain)+trustIXAEADIOCTagLen {
		t.Fatalf("sealed len = %d", len(sealOps[0].Out))
	}
	if bytes.Equal(sealOps[0].Out[:len(plain)], plain) {
		t.Fatal("sealed payload did not change plaintext")
	}

	gcm := testAESGCM(t, key)
	wantCipher := gcm.Seal(nil, nonce1, plain, nil)
	if !bytes.Equal(sealOps[0].Out, wantCipher) {
		t.Fatal("kernel AEAD ciphertext does not match Go AES-GCM")
	}

	openOps := []AEADBatchOp{
		{Nonce: nonce1, In: sealOps[0].Out, Out: make([]byte, len(sealOps[0].Out)-trustIXAEADIOCTagLen)},
		{Nonce: nonce2, In: sealOps[1].Out, Out: make([]byte, len(sealOps[1].Out)-trustIXAEADIOCTagLen)},
	}
	if err := AEADOpenBatch("", key, openOps); err != nil {
		t.Fatalf("open batch: %v", err)
	}
	if !bytes.Equal(openOps[0].Out, plain) {
		t.Fatalf("opened[0] mismatch")
	}
	if !bytes.Equal(openOps[1].Out, plain[:511]) {
		t.Fatalf("opened[1] mismatch")
	}
}

func TestTrustIXAEADDeviceSessionBatchSealOpen(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trustix_crypto device test requires root")
	}
	if !AEADDeviceAvailable("") {
		t.Skip("trustix_crypto device is not available; load trustix_crypto.ko")
	}
	key := bytesOf(0x42, 32)
	plain := bytesOf(0x91, 1200)
	nonce1 := bytesOf(0x23, trustIXAEADIOCNonceLen)
	nonce2 := bytesOf(0x24, trustIXAEADIOCNonceLen)

	device, err := OpenAEADDevice("")
	if err != nil {
		t.Fatalf("open device: %v", err)
	}
	defer device.Close()
	if err := device.SetKey(key); err != nil {
		t.Fatalf("set key: %v", err)
	}

	sealOps := []AEADBatchOp{
		{Nonce: nonce1, In: plain, Out: make([]byte, len(plain)+trustIXAEADIOCTagLen)},
		{Nonce: nonce2, In: plain[:333], Out: make([]byte, 333+trustIXAEADIOCTagLen)},
	}
	if err := device.SealBatch(sealOps); err != nil {
		t.Fatalf("session seal batch: %v", err)
	}

	gcm := testAESGCM(t, key)
	wantCipher := gcm.Seal(nil, nonce1, plain, nil)
	if !bytes.Equal(sealOps[0].Out, wantCipher) {
		t.Fatal("session kernel AEAD ciphertext does not match Go AES-GCM")
	}

	openOps := []AEADBatchOp{
		{Nonce: nonce1, In: sealOps[0].Out, Out: make([]byte, len(sealOps[0].Out)-trustIXAEADIOCTagLen)},
		{Nonce: nonce2, In: sealOps[1].Out, Out: make([]byte, len(sealOps[1].Out)-trustIXAEADIOCTagLen)},
	}
	if err := device.OpenBatch(openOps); err != nil {
		t.Fatalf("session open batch: %v", err)
	}
	if !bytes.Equal(openOps[0].Out, plain) {
		t.Fatalf("session opened[0] mismatch")
	}
	if !bytes.Equal(openOps[1].Out, plain[:333]) {
		t.Fatalf("session opened[1] mismatch")
	}
	if err := device.ClearKey(); err != nil {
		t.Fatalf("clear key: %v", err)
	}
}

func TestTrustIXAEADDeviceSessionPoolBatchSealOpen(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trustix_crypto device test requires root")
	}
	if !AEADDeviceAvailable("") {
		t.Skip("trustix_crypto device is not available; load trustix_crypto.ko")
	}
	key := bytesOf(0x43, 32)
	plain := bytesOf(0x92, 1200)
	device, err := OpenAEADDevice("")
	if err != nil {
		t.Fatalf("open device: %v", err)
	}
	defer device.Close()
	if err := device.SetKey(key); err != nil {
		t.Fatalf("set key: %v", err)
	}
	pool, err := device.MmapPool(1 << 20)
	if err != nil {
		t.Fatalf("mmap pool: %v", err)
	}
	opsOff := 0
	nonce1Off := alignUp(poolOpsEnd(opsOff, 2), 64)
	nonce2Off := nonce1Off + trustIXAEADIOCNonceLen
	plainOff := alignUp(nonce2Off+trustIXAEADIOCNonceLen, 64)
	out1Off := alignUp(plainOff+len(plain), 64)
	out2Off := alignUp(out1Off+len(plain)+trustIXAEADIOCTagLen, 64)
	open1Off := alignUp(out2Off+333+trustIXAEADIOCTagLen, 64)
	open2Off := alignUp(open1Off+len(plain), 64)
	copy(pool[nonce1Off:], bytesOf(0x25, trustIXAEADIOCNonceLen))
	copy(pool[nonce2Off:], bytesOf(0x26, trustIXAEADIOCNonceLen))
	copy(pool[plainOff:], plain)

	sealOps := []AEADPoolBatchOp{
		{NonceOff: uint64(nonce1Off), InOff: uint64(plainOff), OutOff: uint64(out1Off), NonceLen: trustIXAEADIOCNonceLen, InLen: uint32(len(plain)), OutLen: uint32(len(plain) + trustIXAEADIOCTagLen)},
		{NonceOff: uint64(nonce2Off), InOff: uint64(plainOff), OutOff: uint64(out2Off), NonceLen: trustIXAEADIOCNonceLen, InLen: 333, OutLen: 333 + trustIXAEADIOCTagLen},
	}
	if err := device.SealPoolBatch(opsOff, sealOps); err != nil {
		t.Fatalf("pool seal batch: %v", err)
	}
	if sealOps[0].OutLen != uint32(len(plain)+trustIXAEADIOCTagLen) {
		t.Fatalf("sealed pool len = %d", sealOps[0].OutLen)
	}
	ciphertext := pool[out1Off : out1Off+int(sealOps[0].OutLen)]
	gcm := testAESGCM(t, key)
	wantCipher := gcm.Seal(nil, pool[nonce1Off:nonce1Off+trustIXAEADIOCNonceLen], plain, nil)
	if !bytes.Equal(ciphertext, wantCipher) {
		t.Fatal("pool kernel AEAD ciphertext does not match Go AES-GCM")
	}

	openOps := []AEADPoolBatchOp{
		{NonceOff: uint64(nonce1Off), InOff: uint64(out1Off), OutOff: uint64(open1Off), NonceLen: trustIXAEADIOCNonceLen, InLen: sealOps[0].OutLen, OutLen: uint32(len(plain))},
		{NonceOff: uint64(nonce2Off), InOff: uint64(out2Off), OutOff: uint64(open2Off), NonceLen: trustIXAEADIOCNonceLen, InLen: sealOps[1].OutLen, OutLen: 333},
	}
	if err := device.OpenPoolBatch(opsOff, openOps); err != nil {
		t.Fatalf("pool open batch: %v", err)
	}
	if !bytes.Equal(pool[open1Off:open1Off+int(openOps[0].OutLen)], plain) {
		t.Fatalf("pool opened[0] mismatch")
	}
	if !bytes.Equal(pool[open2Off:open2Off+int(openOps[1].OutLen)], plain[:333]) {
		t.Fatalf("pool opened[1] mismatch")
	}
}

func TestTrustIXAEADDeviceKernelPreparedPoolBatchSealOpen(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trustix_crypto device test requires root")
	}
	if !AEADDeviceAvailable("") {
		t.Skip("trustix_crypto device is not available; load trustix_crypto.ko")
	}
	key := bytesOf(0x46, 32)
	plain := bytesOf(0x95, 1200)
	device, err := OpenAEADDevice("")
	if err != nil {
		t.Fatalf("open device: %v", err)
	}
	defer device.Close()
	if err := device.SetKey(key); err != nil {
		t.Fatalf("set key: %v", err)
	}
	pool, err := device.MmapPool(1 << 20)
	if err != nil {
		t.Fatalf("mmap pool: %v", err)
	}
	const batchSize = 4
	if err := preparePoolSealBenchmark(device, pool, plain, batchSize); err != nil {
		t.Fatalf("prepare pool benchmark: %v", err)
	}
	if err := device.PrepareKernelPoolBatch(0, batchSize, false); err != nil {
		t.Fatalf("kernel prepare pool batch: %v", err)
	}
	if err := device.SealKernelPreparedPoolBatch(0, batchSize); err != nil {
		t.Fatalf("kernel prepared seal batch: %v", err)
	}
	nonceBase := alignUp(poolOpsEnd(0, batchSize), 64)
	plainOff := alignUp(nonceBase+batchSize*trustIXAEADIOCNonceLen, 64)
	outBase := alignUp(plainOff+len(plain), 64)
	gcm := testAESGCM(t, key)
	for i := 0; i < batchSize; i++ {
		nonceOff := nonceBase + i*trustIXAEADIOCNonceLen
		outOff := outBase + i*(len(plain)+trustIXAEADIOCTagLen)
		want := gcm.Seal(nil, pool[nonceOff:nonceOff+trustIXAEADIOCNonceLen], plain, nil)
		got := pool[outOff : outOff+len(want)]
		if !bytes.Equal(got, want) {
			t.Fatalf("prepared kernel ciphertext[%d] mismatch", i)
		}
	}
	openBase := alignUp(outBase+batchSize*(len(plain)+trustIXAEADIOCTagLen), 64)
	openOps := make([]AEADPoolBatchOp, batchSize)
	for i := range openOps {
		nonceOff := nonceBase + i*trustIXAEADIOCNonceLen
		outOff := outBase + i*(len(plain)+trustIXAEADIOCTagLen)
		plainOutOff := openBase + i*len(plain)
		openOps[i] = AEADPoolBatchOp{
			NonceOff: uint64(nonceOff),
			InOff:    uint64(outOff),
			OutOff:   uint64(plainOutOff),
			NonceLen: trustIXAEADIOCNonceLen,
			InLen:    uint32(len(plain) + trustIXAEADIOCTagLen),
			OutLen:   uint32(len(plain)),
		}
	}
	if err := device.PreparePoolBatchOps(0, openOps); err != nil {
		t.Fatalf("prepare open pool ops: %v", err)
	}
	if err := device.PrepareKernelPoolBatch(0, batchSize, true); err != nil {
		t.Fatalf("kernel prepare open pool batch: %v", err)
	}
	if err := device.OpenKernelPreparedPoolBatch(0, batchSize); err != nil {
		t.Fatalf("kernel prepared open batch: %v", err)
	}
	for i := 0; i < batchSize; i++ {
		plainOutOff := openBase + i*len(plain)
		if !bytes.Equal(pool[plainOutOff:plainOutOff+len(plain)], plain) {
			t.Fatalf("prepared kernel opened[%d] mismatch", i)
		}
	}
}

func TestTrustIXAEADDeviceKernelPrepareRunPoolBatchSealOpen(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trustix_crypto device test requires root")
	}
	if !AEADDeviceAvailable("") {
		t.Skip("trustix_crypto device is not available; load trustix_crypto.ko")
	}
	key := bytesOf(0x48, 32)
	plain := bytesOf(0x97, 1200)
	device, err := OpenAEADDevice("")
	if err != nil {
		t.Fatalf("open device: %v", err)
	}
	defer device.Close()
	if err := device.SetKey(key); err != nil {
		t.Fatalf("set key: %v", err)
	}
	pool, err := device.MmapPool(1 << 20)
	if err != nil {
		t.Fatalf("mmap pool: %v", err)
	}
	const batchSize = 4
	if err := preparePoolSealBenchmark(device, pool, plain, batchSize); err != nil {
		t.Fatalf("prepare pool benchmark: %v", err)
	}
	if err := device.PrepareRunKernelPoolBatch(0, batchSize, false); err != nil {
		t.Fatalf("kernel prepare-run seal batch: %v", err)
	}
	nonceBase := alignUp(poolOpsEnd(0, batchSize), 64)
	plainOff := alignUp(nonceBase+batchSize*trustIXAEADIOCNonceLen, 64)
	outBase := alignUp(plainOff+len(plain), 64)
	gcm := testAESGCM(t, key)
	for i := 0; i < batchSize; i++ {
		nonceOff := nonceBase + i*trustIXAEADIOCNonceLen
		outOff := outBase + i*(len(plain)+trustIXAEADIOCTagLen)
		want := gcm.Seal(nil, pool[nonceOff:nonceOff+trustIXAEADIOCNonceLen], plain, nil)
		got := pool[outOff : outOff+len(want)]
		if !bytes.Equal(got, want) {
			t.Fatalf("prepare-run ciphertext[%d] mismatch", i)
		}
	}
	openBase := alignUp(outBase+batchSize*(len(plain)+trustIXAEADIOCTagLen), 64)
	openOps := make([]AEADPoolBatchOp, batchSize)
	for i := range openOps {
		nonceOff := nonceBase + i*trustIXAEADIOCNonceLen
		outOff := outBase + i*(len(plain)+trustIXAEADIOCTagLen)
		plainOutOff := openBase + i*len(plain)
		openOps[i] = AEADPoolBatchOp{
			NonceOff: uint64(nonceOff),
			InOff:    uint64(outOff),
			OutOff:   uint64(plainOutOff),
			NonceLen: trustIXAEADIOCNonceLen,
			InLen:    uint32(len(plain) + trustIXAEADIOCTagLen),
			OutLen:   uint32(len(plain)),
		}
	}
	if err := device.PreparePoolBatchOps(0, openOps); err != nil {
		t.Fatalf("prepare open pool ops: %v", err)
	}
	if err := device.PrepareRunKernelPoolBatch(0, batchSize, true); err != nil {
		t.Fatalf("kernel prepare-run open batch: %v", err)
	}
	for i := 0; i < batchSize; i++ {
		plainOutOff := openBase + i*len(plain)
		if !bytes.Equal(pool[plainOutOff:plainOutOff+len(plain)], plain) {
			t.Fatalf("prepare-run opened[%d] mismatch", i)
		}
	}
}

func TestTrustIXAEADDeviceKernelPrepareRunPoolBatchOpenInPlace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trustix_crypto device test requires root")
	}
	if !AEADDeviceAvailable("") {
		t.Skip("trustix_crypto device is not available; load trustix_crypto.ko")
	}
	key := bytesOf(0x49, 32)
	plain := bytesOf(0x98, 1200)
	device, err := OpenAEADDevice("")
	if err != nil {
		t.Fatalf("open device: %v", err)
	}
	defer device.Close()
	if err := device.SetKey(key); err != nil {
		t.Fatalf("set key: %v", err)
	}
	pool, err := device.MmapPool(1 << 20)
	if err != nil {
		t.Fatalf("mmap pool: %v", err)
	}
	const batchSize = 4
	if err := preparePoolSealBenchmark(device, pool, plain, batchSize); err != nil {
		t.Fatalf("prepare pool benchmark: %v", err)
	}
	if err := device.PrepareRunKernelPoolBatch(0, batchSize, false); err != nil {
		t.Fatalf("kernel prepare-run seal batch: %v", err)
	}
	nonceBase := alignUp(poolOpsEnd(0, batchSize), 64)
	plainOff := alignUp(nonceBase+batchSize*trustIXAEADIOCNonceLen, 64)
	sealOutBase := alignUp(plainOff+len(plain), 64)
	openOps := make([]AEADPoolBatchOp, batchSize)
	for i := range openOps {
		nonceOff := nonceBase + i*trustIXAEADIOCNonceLen
		sealOutOff := sealOutBase + i*(len(plain)+trustIXAEADIOCTagLen)
		openOps[i] = AEADPoolBatchOp{
			NonceOff: uint64(nonceOff),
			InOff:    uint64(sealOutOff),
			OutOff:   uint64(sealOutOff),
			NonceLen: trustIXAEADIOCNonceLen,
			InLen:    uint32(len(plain) + trustIXAEADIOCTagLen),
			OutLen:   uint32(len(plain)),
		}
	}
	if err := device.PreparePoolBatchOps(0, openOps); err != nil {
		t.Fatalf("prepare in-place open pool ops: %v", err)
	}
	if err := device.PrepareRunKernelPoolBatch(0, batchSize, true); err != nil {
		t.Fatalf("kernel prepare-run in-place open batch: %v", err)
	}
	for i := 0; i < batchSize; i++ {
		sealOutOff := sealOutBase + i*(len(plain)+trustIXAEADIOCTagLen)
		if !bytes.Equal(pool[sealOutOff:sealOutOff+len(plain)], plain) {
			t.Fatalf("prepare-run in-place opened[%d] mismatch", i)
		}
	}
}

func BenchmarkTrustIXAEADDeviceBatchSeal1200(b *testing.B) {
	if os.Geteuid() != 0 || !AEADDeviceAvailable("") {
		b.Skip("trustix_crypto device is not available")
	}
	key := bytesOf(0x51, 32)
	plain := bytesOf(0x61, 1200)
	const batchSize = 64
	ops := make([]AEADBatchOp, batchSize)
	for i := range ops {
		nonce := bytesOf(byte(i+1), trustIXAEADIOCNonceLen)
		ops[i] = AEADBatchOp{
			Nonce: nonce,
			In:    plain,
			Out:   make([]byte, len(plain)+trustIXAEADIOCTagLen),
		}
	}
	b.SetBytes(int64(len(plain) * batchSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := AEADSealBatch("", key, ops); err != nil {
			b.Fatalf("seal batch: %v", err)
		}
		for j := range ops {
			ops[j].Out = ops[j].Out[:cap(ops[j].Out)]
		}
	}
}

func BenchmarkTrustIXAEADDeviceSessionBatchSeal1200(b *testing.B) {
	if os.Geteuid() != 0 || !AEADDeviceAvailable("") {
		b.Skip("trustix_crypto device is not available")
	}
	key := bytesOf(0x52, 32)
	plain := bytesOf(0x62, 1200)
	device, err := OpenAEADDevice("")
	if err != nil {
		b.Fatalf("open device: %v", err)
	}
	defer device.Close()
	if err := device.SetKey(key); err != nil {
		b.Fatalf("set key: %v", err)
	}
	const batchSize = 64
	ops := make([]AEADBatchOp, batchSize)
	for i := range ops {
		nonce := bytesOf(byte(i+1), trustIXAEADIOCNonceLen)
		ops[i] = AEADBatchOp{
			Nonce: nonce,
			In:    plain,
			Out:   make([]byte, len(plain)+trustIXAEADIOCTagLen),
		}
	}
	b.SetBytes(int64(len(plain) * batchSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := device.SealBatch(ops); err != nil {
			b.Fatalf("seal batch: %v", err)
		}
		for j := range ops {
			ops[j].Out = ops[j].Out[:cap(ops[j].Out)]
		}
	}
}

func BenchmarkTrustIXAEADDeviceSessionPoolSeal1200(b *testing.B) {
	benchmarkTrustIXAEADDeviceSessionPoolSeal1200(b, 64)
}

func BenchmarkTrustIXAEADDeviceSessionPoolSeal1200Batch256(b *testing.B) {
	benchmarkTrustIXAEADDeviceSessionPoolSeal1200(b, 256)
}

func BenchmarkTrustIXAEADDeviceSessionPoolSeal1200Batch512(b *testing.B) {
	benchmarkTrustIXAEADDeviceSessionPoolSeal1200(b, 512)
}

func BenchmarkTrustIXAEADDeviceSessionPoolSeal1200Batch1024(b *testing.B) {
	benchmarkTrustIXAEADDeviceSessionPoolSeal1200(b, 1024)
}

func BenchmarkTrustIXAEADDeviceSessionPoolSeal1200Batch4096(b *testing.B) {
	benchmarkTrustIXAEADDeviceSessionPoolSeal1200(b, 4096)
}

func BenchmarkTrustIXAEADDeviceSessionPoolSeal16KBatch64(b *testing.B) {
	benchmarkTrustIXAEADDeviceSessionPoolSeal(b, 16*1024, 64)
}

func BenchmarkTrustIXAEADDeviceSessionPoolOpen1200Batch4096(b *testing.B) {
	benchmarkTrustIXAEADDeviceSessionPoolOpen(b, 1200, 4096)
}

func BenchmarkTrustIXAEADDeviceSessionPoolSeal1200Parallel(b *testing.B) {
	if os.Geteuid() != 0 || !AEADDeviceAvailable("") {
		b.Skip("trustix_crypto device is not available")
	}
	const batchSize = 64
	b.SetBytes(int64(1200 * batchSize))
	b.RunParallel(func(pb *testing.PB) {
		key := bytesOf(0x54, 32)
		plain := bytesOf(0x64, 1200)
		device, err := OpenAEADDevice("")
		if err != nil {
			b.Fatalf("open device: %v", err)
		}
		defer device.Close()
		if err := device.SetKey(key); err != nil {
			b.Fatalf("set key: %v", err)
		}
		pool, err := device.MmapPool(1 << 20)
		if err != nil {
			b.Fatalf("mmap pool: %v", err)
		}
		if err := preparePoolSealBenchmark(device, pool, plain, batchSize); err != nil {
			b.Fatalf("prepare pool benchmark: %v", err)
		}
		if err := device.PrepareKernelPoolBatch(0, batchSize, false); err != nil {
			b.Fatalf("kernel prepare pool benchmark: %v", err)
		}
		for pb.Next() {
			if err := device.SealKernelPreparedPoolBatch(0, batchSize); err != nil {
				b.Fatalf("seal kernel prepared pool batch: %v", err)
			}
		}
	})
}

func benchmarkTrustIXAEADDeviceSessionPoolSeal1200(b *testing.B, batchSize int) {
	benchmarkTrustIXAEADDeviceSessionPoolSeal(b, 1200, batchSize)
}

func benchmarkTrustIXAEADDeviceSessionPoolSeal(b *testing.B, payloadLen int, batchSize int) {
	if os.Geteuid() != 0 || !AEADDeviceAvailable("") {
		b.Skip("trustix_crypto device is not available")
	}
	key := bytesOf(0x53, 32)
	plain := bytesOf(0x63, payloadLen)
	device, err := OpenAEADDevice("")
	if err != nil {
		b.Fatalf("open device: %v", err)
	}
	defer device.Close()
	if err := device.SetKey(key); err != nil {
		b.Fatalf("set key: %v", err)
	}
	pool, err := device.MmapPool(poolSealBenchmarkSize(len(plain), batchSize))
	if err != nil {
		b.Fatalf("mmap pool: %v", err)
	}
	if err := preparePoolSealBenchmark(device, pool, plain, batchSize); err != nil {
		b.Fatalf("prepare pool benchmark: %v", err)
	}
	if err := device.PrepareKernelPoolBatch(0, batchSize, false); err != nil {
		b.Fatalf("kernel prepare pool benchmark: %v", err)
	}
	b.SetBytes(int64(len(plain) * batchSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := device.SealKernelPreparedPoolBatch(0, batchSize); err != nil {
			b.Fatalf("seal kernel prepared pool batch: %v", err)
		}
	}
}

func benchmarkTrustIXAEADDeviceSessionPoolOpen(b *testing.B, payloadLen int, batchSize int) {
	if os.Geteuid() != 0 || !AEADDeviceAvailable("") {
		b.Skip("trustix_crypto device is not available")
	}
	key := bytesOf(0x55, 32)
	plain := bytesOf(0x65, payloadLen)
	device, err := OpenAEADDevice("")
	if err != nil {
		b.Fatalf("open device: %v", err)
	}
	defer device.Close()
	if err := device.SetKey(key); err != nil {
		b.Fatalf("set key: %v", err)
	}
	pool, err := device.MmapPool(poolOpenBenchmarkSize(len(plain), batchSize))
	if err != nil {
		b.Fatalf("mmap pool: %v", err)
	}
	if err := preparePoolSealBenchmark(device, pool, plain, batchSize); err != nil {
		b.Fatalf("prepare seal benchmark: %v", err)
	}
	if err := device.PrepareKernelPoolBatch(0, batchSize, false); err != nil {
		b.Fatalf("kernel prepare seal benchmark: %v", err)
	}
	if err := device.SealKernelPreparedPoolBatch(0, batchSize); err != nil {
		b.Fatalf("seal kernel prepared pool batch: %v", err)
	}
	if err := preparePoolOpenBenchmark(device, pool, len(plain), batchSize); err != nil {
		b.Fatalf("prepare open benchmark: %v", err)
	}
	if err := device.PrepareKernelPoolBatch(0, batchSize, true); err != nil {
		b.Fatalf("kernel prepare open benchmark: %v", err)
	}
	b.SetBytes(int64(len(plain) * batchSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := device.OpenKernelPreparedPoolBatch(0, batchSize); err != nil {
			b.Fatalf("open kernel prepared pool batch: %v", err)
		}
	}
}

func preparePoolSealBenchmark(device *AEADDevice, pool []byte, plain []byte, batchSize int) error {
	opsOff := 0
	nonceBase := alignUp(poolOpsEnd(opsOff, batchSize), 64)
	plainOff := alignUp(nonceBase+batchSize*trustIXAEADIOCNonceLen, 64)
	outBase := alignUp(plainOff+len(plain), 64)
	copy(pool[plainOff:], plain)
	ops := make([]AEADPoolBatchOp, batchSize)
	for i := range ops {
		nonceOff := nonceBase + i*trustIXAEADIOCNonceLen
		fillBenchmarkNonce(pool[nonceOff:nonceOff+trustIXAEADIOCNonceLen], i)
		outOff := outBase + i*(len(plain)+trustIXAEADIOCTagLen)
		ops[i] = AEADPoolBatchOp{
			NonceOff: uint64(nonceOff),
			InOff:    uint64(plainOff),
			OutOff:   uint64(outOff),
			NonceLen: trustIXAEADIOCNonceLen,
			InLen:    uint32(len(plain)),
			OutLen:   uint32(len(plain) + trustIXAEADIOCTagLen),
		}
	}
	return device.PreparePoolBatchOps(opsOff, ops)
}

func preparePoolOpenBenchmark(device *AEADDevice, pool []byte, payloadLen int, batchSize int) error {
	opsOff := 0
	nonceBase := alignUp(poolOpsEnd(opsOff, batchSize), 64)
	plainOff := alignUp(nonceBase+batchSize*trustIXAEADIOCNonceLen, 64)
	sealOutBase := alignUp(plainOff+payloadLen, 64)
	openOutBase := alignUp(sealOutBase+batchSize*(payloadLen+trustIXAEADIOCTagLen), 64)
	ops := make([]AEADPoolBatchOp, batchSize)
	for i := range ops {
		nonceOff := nonceBase + i*trustIXAEADIOCNonceLen
		sealOutOff := sealOutBase + i*(payloadLen+trustIXAEADIOCTagLen)
		openOutOff := openOutBase + i*payloadLen
		ops[i] = AEADPoolBatchOp{
			NonceOff: uint64(nonceOff),
			InOff:    uint64(sealOutOff),
			OutOff:   uint64(openOutOff),
			NonceLen: trustIXAEADIOCNonceLen,
			InLen:    uint32(payloadLen + trustIXAEADIOCTagLen),
			OutLen:   uint32(payloadLen),
		}
	}
	return device.PreparePoolBatchOps(opsOff, ops)
}

func poolSealBenchmarkSize(payloadLen int, batchSize int) int {
	opsOff := 0
	nonceBase := alignUp(poolOpsEnd(opsOff, batchSize), 64)
	plainOff := alignUp(nonceBase+batchSize*trustIXAEADIOCNonceLen, 64)
	outBase := alignUp(plainOff+payloadLen, 64)
	need := outBase + batchSize*(payloadLen+trustIXAEADIOCTagLen)
	return alignUp(need, 4096)
}

func poolOpenBenchmarkSize(payloadLen int, batchSize int) int {
	opsOff := 0
	nonceBase := alignUp(poolOpsEnd(opsOff, batchSize), 64)
	plainOff := alignUp(nonceBase+batchSize*trustIXAEADIOCNonceLen, 64)
	sealOutBase := alignUp(plainOff+payloadLen, 64)
	openOutBase := alignUp(sealOutBase+batchSize*(payloadLen+trustIXAEADIOCTagLen), 64)
	need := openOutBase + batchSize*payloadLen
	return alignUp(need, 4096)
}

func fillBenchmarkNonce(dst []byte, index int) {
	value := uint64(index + 1)
	for i := range dst {
		dst[i] = byte(value >> uint((i&7)*8))
	}
	for i := 8; i < len(dst); i++ {
		dst[i] ^= byte(index >> uint((i-8)*8))
	}
}

func testAESGCM(t *testing.T, key []byte) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("new AES: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("new GCM: %v", err)
	}
	return gcm
}

func buildIPv4UDPPacket(sourceIPv4 uint32, destinationIPv4 uint32, sourcePort uint16, destinationPort uint16, payloadLen int) []byte {
	return buildIPv4UDPPacketWithPayload(sourceIPv4, destinationIPv4, sourcePort, destinationPort, make([]byte, payloadLen))
}

func buildIPv4UDPPacketWithPayload(sourceIPv4 uint32, destinationIPv4 uint32, sourcePort uint16, destinationPort uint16, payload []byte) []byte {
	packet := make([]byte, 20+8+len(payload))
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 17
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint32(packet[12:16], sourceIPv4)
	binary.BigEndian.PutUint32(packet[16:20], destinationIPv4)
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(payload)))
	copy(packet[28:], payload)
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:20]))
	binary.BigEndian.PutUint16(packet[26:28], udpIPv4Checksum(packet))
	return packet
}

func buildIPv4TCPPacketWithPayload(sourceIPv4 uint32, destinationIPv4 uint32, sourcePort uint16, destinationPort uint16, seq uint32, ack uint32, flags uint8, payload []byte) []byte {
	packet := make([]byte, 20+20+len(payload))
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 6
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint32(packet[12:16], sourceIPv4)
	binary.BigEndian.PutUint32(packet[16:20], destinationIPv4)
	tcp := packet[20:]
	binary.BigEndian.PutUint16(tcp[0:2], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], destinationPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], payload)
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:20]))
	binary.BigEndian.PutUint16(tcp[16:18], tcpIPv4Checksum(packet))
	return packet
}

func unixLinkAddDummy(name string) error {
	_ = unixLinkDelete(name)
	return exec.Command("ip", "link", "add", name, "type", "dummy").Run()
}

func unixLinkAddVeth(name string, peer string) error {
	_ = unixLinkDelete(name)
	_ = unixLinkDelete(peer)
	return exec.Command("ip", "link", "add", name, "type", "veth", "peer", "name", peer).Run()
}

func unixLinkSetUp(name string) error {
	return exec.Command("ip", "link", "set", name, "up").Run()
}

func unixLinkDelete(name string) error {
	return exec.Command("ip", "link", "delete", name).Run()
}

func unixAddrAdd(name string, cidr string) error {
	return exec.Command("ip", "addr", "add", cidr, "dev", name).Run()
}

func unixRouteReplace(dst string, dev string, src string) error {
	return exec.Command("ip", "route", "replace", dst, "dev", dev, "src", src).Run()
}

func unixRouteDelete(dst string, dev string) error {
	return exec.Command("ip", "route", "delete", dst, "dev", dev).Run()
}

func tcQdiscAddClsact(dev string) error {
	return exec.Command("tc", "qdisc", "add", "dev", dev, "clsact").Run()
}

func tcQdiscDelClsact(dev string) {
	_ = exec.Command("tc", "qdisc", "del", "dev", dev, "clsact").Run()
}

func tcFilterAddPass(dev string, direction string) error {
	return exec.Command("tc", "filter", "add", "dev", dev, direction, "pref", "100", "matchall", "action", "pass").Run()
}

func unixNeighReplace(dev string, ip string, lladdr string) error {
	return exec.Command("ip", "neigh", "replace", ip, "lladdr", lladdr, "dev", dev, "nud", "permanent").Run()
}

func unixNeighDelete(dev string, ip string) error {
	return exec.Command("ip", "neigh", "delete", ip, "dev", dev).Run()
}

func trustIXFullDatapathRXWorkerInjectEnabled() bool {
	value, err := os.ReadFile("/sys/module/trustix_datapath/parameters/rx_worker_inject")
	if err != nil {
		return false
	}
	return len(value) > 0 && (value[0] == 'Y' || value[0] == 'y' || value[0] == '1')
}

func trustIXFullDatapathRXWorkerXmitEnabled() bool {
	value, err := os.ReadFile("/sys/module/trustix_datapath/parameters/rx_worker_xmit")
	if err != nil {
		return false
	}
	return len(value) > 0 && (value[0] == 'Y' || value[0] == 'y' || value[0] == '1')
}

func trustIXFullDatapathTXPlaintextEnabled() bool {
	value, err := os.ReadFile("/sys/module/trustix_datapath/parameters/tx_plaintext")
	if err != nil {
		return false
	}
	return len(value) > 0 && (value[0] == 'Y' || value[0] == 'y' || value[0] == '1')
}

func readUint64File(path string) (uint64, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(value)), 10, 64)
}

func generateHookTraffic(t *testing.T, name string) {
	t.Helper()
	packet := buildIPv4UDPPacketWithPayload(0x0a520001, 0x0a520002, 12345, 5201, bytesOf(0x77, 32))
	if err := sendIPv4EthernetFrame(name, packet); err != nil {
		t.Skipf("unable to inject datapath hook traffic on %s: %v", name, err)
	}
}

func sendIPv4EthernetFrame(ifname string, packet []byte) error {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return err
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, int(htons(0x0800)))
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	frame := make([]byte, 14+len(packet))
	for i := 0; i < 6; i++ {
		frame[i] = 0xff
	}
	if len(iface.HardwareAddr) >= 6 {
		copy(frame[6:12], iface.HardwareAddr[:6])
	}
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	copy(frame[14:], packet)
	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(0x0800),
		Ifindex:  iface.Index,
		Halen:    6,
	}
	for i := 0; i < 6; i++ {
		addr.Addr[i] = 0xff
	}
	return syscall.Sendto(fd, frame, 0, addr)
}

func openIPv4PacketSocket(ifname string) (int, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return -1, err
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, int(htons(0x0800)))
	if err != nil {
		return -1, err
	}
	if err := syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(0x0800),
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(fd, addr); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

func recvIPv4Packet(fd int, timeout time.Duration) ([]byte, error) {
	packet, _, err := recvIPv4PacketWithType(fd, timeout)
	return packet, err
}

func recvIPv4PacketWithType(fd int, timeout time.Duration) ([]byte, uint8, error) {
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 65536)
	var lastErr error
	for time.Now().Before(deadline) {
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err == nil {
			if n < 14 || binary.BigEndian.Uint16(buf[12:14]) != 0x0800 {
				continue
			}
			link, ok := from.(*syscall.SockaddrLinklayer)
			if !ok {
				continue
			}
			packet := make([]byte, n-14)
			copy(packet, buf[14:n])
			return packet, link.Pkttype, nil
		}
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		lastErr = err
		time.Sleep(10 * time.Millisecond)
	}
	if lastErr != nil {
		return nil, 0, lastErr
	}
	return nil, 0, syscall.ETIMEDOUT
}

func htons(value uint16) uint16 {
	return value<<8 | value>>8
}

func ipv4Checksum(header []byte) uint16 {
	return checksumFold(checksumAddBytes(0, header))
}

func udpIPv4Checksum(packet []byte) uint16 {
	if len(packet) < 28 || packet[9] != 17 {
		return 0
	}
	udp := packet[20:]
	sum := checksumAddBytes(0, packet[12:16])
	sum = checksumAddBytes(sum, packet[16:20])
	sum = checksumAddBytes(sum, []byte{0, 17, byte(len(udp) >> 8), byte(len(udp))})
	sum = checksumAddBytes(sum, udp)
	checksum := checksumFold(sum)
	if checksum == 0 {
		return 0xffff
	}
	return checksum
}

func tcpIPv4Checksum(packet []byte) uint16 {
	if len(packet) < 40 || packet[9] != 6 {
		return 0
	}
	tcp := packet[20:]
	sum := checksumAddBytes(0, packet[12:16])
	sum = checksumAddBytes(sum, packet[16:20])
	sum = checksumAddBytes(sum, []byte{0, 6, byte(len(tcp) >> 8), byte(len(tcp))})
	sum = checksumAddBytes(sum, tcp)
	checksum := checksumFold(sum)
	if checksum == 0 {
		return 0xffff
	}
	return checksum
}

func checksumAddBytes(sum uint32, payload []byte) uint32 {
	for len(payload) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(payload[:2]))
		payload = payload[2:]
	}
	if len(payload) == 1 {
		sum += uint32(payload[0]) << 8
	}
	return sum
}

func checksumFold(sum uint32) uint16 {
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func bytesOf(value byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = value
	}
	return out
}

func poolOpsEnd(opsOff int, n int) int {
	return opsOff + n*int(unsafe.Sizeof(trustIXAEADIOCPoolOp{}))
}

func alignUp(value int, alignment int) int {
	return (value + alignment - 1) & ^(alignment - 1)
}
