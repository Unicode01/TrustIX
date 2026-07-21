//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/transport/kerneludp"
	"trustix.local/trustix/internal/transport/tixtcp"
)

func TestTIXTCPTXSocketGSODefaultsOff(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TX_SOCKET_GSO", "")
	t.Setenv("TRUSTIX_TIXT_TX_SOCKET_GSO", "")
	if tixTCPTXSocketGSOEnabled() {
		t.Fatal("tix_tcp TX socket GSO should default off")
	}
	t.Setenv("TRUSTIX_TIX_TCP_TX_SOCKET_GSO", "1")
	if !tixTCPTXSocketGSOEnabled() {
		t.Fatal("tix_tcp TX socket GSO should be opt-in")
	}
}

func TestTIXTCPTXSocketAffinityUsesFlowID(t *testing.T) {
	fastPath := testTIXTCPFastPathWithQueues(4)
	packet := tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("198.18.0.1"),
		DestinationIP:   netip.MustParseAddr("198.18.0.2"),
		SourcePort:      40000,
		DestinationPort: 9443,
	}
	frame := tixtcp.Frame{FlowID: 42, Sequence: 1}

	first := fastPath.selectTXSocket(packet, frame)
	wantQueue := uint32(tixTCPTXQueueIndex(tixTCPMix64(frame.FlowID), len(fastPath.sockets)))
	if first.queueID != wantQueue {
		t.Fatalf("selected queue = %d, want flow hash queue %d", first.queueID, wantQueue)
	}
	for sequence := uint64(2); sequence < 16; sequence++ {
		packet.Sequence = uint32(sequence)
		frame.Sequence = sequence
		got := fastPath.selectTXSocket(packet, frame)
		if got != first {
			t.Fatalf("sequence %d selected queue %d, want sticky queue %d", sequence, got.queueID, first.queueID)
		}
	}
	if got := fastPath.txAffinityFlow.Load(); got != 15 {
		t.Fatalf("flow affinity counter = %d, want 15", got)
	}
	if got := fastPath.txAffinityTuple.Load(); got != 0 {
		t.Fatalf("tuple affinity counter = %d, want 0", got)
	}
}

func TestTIXTCPTXSocketAffinityFallsBackToTuple(t *testing.T) {
	fastPath := testTIXTCPFastPathWithQueues(4)
	packet := tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("198.18.0.10"),
		DestinationIP:   netip.MustParseAddr("198.18.0.20"),
		SourcePort:      41000,
		DestinationPort: 9444,
		Sequence:        1,
	}
	frame := tixtcp.Frame{}

	first := fastPath.selectTXSocket(packet, frame)
	for sequence := uint32(2); sequence < 16; sequence++ {
		packet.Sequence = sequence
		got := fastPath.selectTXSocket(packet, frame)
		if got != first {
			t.Fatalf("sequence %d selected queue %d, want tuple-sticky queue %d", sequence, got.queueID, first.queueID)
		}
	}
	if got := fastPath.txAffinityTuple.Load(); got != 15 {
		t.Fatalf("tuple affinity counter = %d, want 15", got)
	}
	if got := fastPath.txAffinityCursor.Load(); got != 0 {
		t.Fatalf("cursor affinity counter = %d, want 0", got)
	}
}

func TestKernelUDPTXSocketAffinityUsesFlowID(t *testing.T) {
	fastPath := testTIXTCPFastPathWithQueues(4)
	packet := kerneludp.UDPPacket{
		SourceIP:        netip.MustParseAddr("198.18.0.1"),
		DestinationIP:   netip.MustParseAddr("198.18.0.2"),
		SourcePort:      40000,
		DestinationPort: 9443,
	}
	frame := kerneludp.Frame{FlowID: 42, Sequence: 1}

	first := fastPath.selectUDPTXSocket(packet, frame)
	wantQueue := uint32(tixTCPTXQueueIndex(tixTCPMix64(frame.FlowID), len(fastPath.sockets)))
	if first.queueID != wantQueue {
		t.Fatalf("selected queue = %d, want flow hash queue %d", first.queueID, wantQueue)
	}
	for sequence := uint64(2); sequence < 16; sequence++ {
		frame.Sequence = sequence
		got := fastPath.selectUDPTXSocket(packet, frame)
		if got != first {
			t.Fatalf("sequence %d selected queue %d, want sticky queue %d", sequence, got.queueID, first.queueID)
		}
	}
	if got := fastPath.txAffinityFlow.Load(); got != 15 {
		t.Fatalf("flow affinity counter = %d, want 15", got)
	}
	if got := fastPath.txAffinityTuple.Load(); got != 0 {
		t.Fatalf("tuple affinity counter = %d, want 0", got)
	}
}

func TestKernelUDPTXSocketAffinityFallsBackToTuple(t *testing.T) {
	fastPath := testTIXTCPFastPathWithQueues(4)
	packet := kerneludp.UDPPacket{
		SourceIP:        netip.MustParseAddr("198.18.0.10"),
		DestinationIP:   netip.MustParseAddr("198.18.0.20"),
		SourcePort:      41000,
		DestinationPort: 9444,
	}
	frame := kerneludp.Frame{}

	first := fastPath.selectUDPTXSocket(packet, frame)
	for sequence := uint64(2); sequence < 16; sequence++ {
		frame.Sequence = sequence
		got := fastPath.selectUDPTXSocket(packet, frame)
		if got != first {
			t.Fatalf("sequence %d selected queue %d, want tuple-sticky queue %d", sequence, got.queueID, first.queueID)
		}
	}
	if got := fastPath.txAffinityTuple.Load(); got != 15 {
		t.Fatalf("tuple affinity counter = %d, want 15", got)
	}
	if got := fastPath.txAffinityCursor.Load(); got != 0 {
		t.Fatalf("cursor affinity counter = %d, want 0", got)
	}
}

func TestPreparedKernelUDPTXSocketAffinityUsesInnerIPv4BeforeFlowID(t *testing.T) {
	fastPath := testTIXTCPFastPathWithQueues(4)
	packet := kerneludp.UDPPacket{
		SourceIP:        netip.MustParseAddr("198.18.0.1"),
		DestinationIP:   netip.MustParseAddr("198.18.0.2"),
		SourcePort:      40000,
		DestinationPort: 9443,
	}
	first := preparedKernelUDPInnerFrameForTest(t, packet, 42, 10000, 5201)
	second := preparedKernelUDPTXFrame{}
	firstQueue := tixTCPTXQueueIndex(first.txInnerHash, len(fastPath.sockets))
	for port := uint16(10001); port < 10100; port++ {
		candidate := preparedKernelUDPInnerFrameForTest(t, packet, 42, port, 5201)
		if tixTCPTXQueueIndex(candidate.txInnerHash, len(fastPath.sockets)) != firstQueue {
			second = candidate
			break
		}
	}
	if !second.txInnerHashValid {
		t.Fatal("test did not find a second inner flow for a different queue")
	}

	gotFirst := fastPath.selectPreparedUDPTXSocket(first)
	gotSecond := fastPath.selectPreparedUDPTXSocket(second)
	if gotFirst.queueID != uint32(firstQueue) {
		t.Fatalf("first queue = %d, want inner hash queue %d", gotFirst.queueID, firstQueue)
	}
	wantSecondQueue := tixTCPTXQueueIndex(second.txInnerHash, len(fastPath.sockets))
	if gotSecond.queueID != uint32(wantSecondQueue) {
		t.Fatalf("second queue = %d, want inner hash queue %d", gotSecond.queueID, wantSecondQueue)
	}
	if gotFirst == gotSecond {
		t.Fatalf("same FlowID inner flows selected one queue %d, want different queues", gotFirst.queueID)
	}
	first.wireFrame.Sequence = 99
	if got := fastPath.selectPreparedUDPTXSocket(first); got != gotFirst {
		t.Fatalf("sequence change selected queue %d, want sticky inner queue %d", got.queueID, gotFirst.queueID)
	}
	if got := fastPath.txAffinityTuple.Load(); got != 3 {
		t.Fatalf("tuple affinity counter = %d, want 3", got)
	}
	if got := fastPath.txAffinityFlow.Load(); got != 0 {
		t.Fatalf("flow affinity counter = %d, want 0", got)
	}
}

func TestPreparedTIXTCPTXSocketAffinityUsesInnerIPv4BeforeFlowID(t *testing.T) {
	fastPath := testTIXTCPFastPathWithQueues(4)
	packet := tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("198.18.0.1"),
		DestinationIP:   netip.MustParseAddr("198.18.0.2"),
		SourcePort:      40000,
		DestinationPort: 9443,
	}
	first := preparedTIXTCPInnerFrameForTest(t, packet, 42, 11000, 5201)
	second := preparedTIXTCPTXFrame{}
	firstQueue := tixTCPTXQueueIndex(first.txInnerHash, len(fastPath.sockets))
	for port := uint16(11001); port < 11100; port++ {
		candidate := preparedTIXTCPInnerFrameForTest(t, packet, 42, port, 5201)
		if tixTCPTXQueueIndex(candidate.txInnerHash, len(fastPath.sockets)) != firstQueue {
			second = candidate
			break
		}
	}
	if !second.txInnerHashValid {
		t.Fatal("test did not find a second inner flow for a different queue")
	}

	gotFirst := fastPath.selectPreparedTXSocket(first)
	gotSecond := fastPath.selectPreparedTXSocket(second)
	if gotFirst.queueID != uint32(firstQueue) {
		t.Fatalf("first queue = %d, want inner hash queue %d", gotFirst.queueID, firstQueue)
	}
	wantSecondQueue := tixTCPTXQueueIndex(second.txInnerHash, len(fastPath.sockets))
	if gotSecond.queueID != uint32(wantSecondQueue) {
		t.Fatalf("second queue = %d, want inner hash queue %d", gotSecond.queueID, wantSecondQueue)
	}
	if gotFirst == gotSecond {
		t.Fatalf("same FlowID inner flows selected one queue %d, want different queues", gotFirst.queueID)
	}
	if got := fastPath.txAffinityTuple.Load(); got != 2 {
		t.Fatalf("tuple affinity counter = %d, want 2", got)
	}
	if got := fastPath.txAffinityFlow.Load(); got != 0 {
		t.Fatalf("flow affinity counter = %d, want 0", got)
	}
}

func TestPreparedTIXTCPTXSocketAffinityCanSpreadFragments(t *testing.T) {
	t.Setenv("TRUSTIX_AF_XDP_TX_FRAGMENT_AFFINITY", "1")
	fastPath := testTIXTCPFastPathWithQueues(4)
	packet := tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("198.18.0.1"),
		DestinationIP:   netip.MustParseAddr("198.18.0.2"),
		SourcePort:      40000,
		DestinationPort: 9443,
	}
	first := preparedTIXTCPTXFrame{
		packet: packet,
		wireFrame: tixtcp.Frame{
			FlowID:        42,
			Sequence:      100,
			FragmentIndex: 0,
			FragmentCount: 8,
			Payload:       []byte("one"),
		},
	}
	second := first
	firstQueue := tixTCPTXQueueIndex(tixTCPPreparedFragmentHash(first), len(fastPath.sockets))
	for index := uint16(1); index < first.wireFrame.FragmentCount; index++ {
		candidate := first
		candidate.wireFrame.Sequence = first.wireFrame.Sequence + uint64(index)
		candidate.wireFrame.FragmentIndex = index
		if tixTCPTXQueueIndex(tixTCPPreparedFragmentHash(candidate), len(fastPath.sockets)) != firstQueue {
			second = candidate
			break
		}
	}
	if second.wireFrame.FragmentIndex == 0 {
		t.Fatal("test did not find a second fragment for a different queue")
	}

	gotFirst := fastPath.selectPreparedTXSocket(first)
	gotSecond := fastPath.selectPreparedTXSocket(second)
	if gotFirst.queueID != uint32(firstQueue) {
		t.Fatalf("first queue = %d, want fragment hash queue %d", gotFirst.queueID, firstQueue)
	}
	wantSecondQueue := tixTCPTXQueueIndex(tixTCPPreparedFragmentHash(second), len(fastPath.sockets))
	if gotSecond.queueID != uint32(wantSecondQueue) {
		t.Fatalf("second queue = %d, want fragment hash queue %d", gotSecond.queueID, wantSecondQueue)
	}
	if gotFirst == gotSecond {
		t.Fatalf("same FlowID fragments selected one queue %d, want spread", gotFirst.queueID)
	}
	if got := fastPath.txAffinityFragment.Load(); got != 2 {
		t.Fatalf("fragment affinity counter = %d, want 2", got)
	}
	if got := fastPath.txAffinityFlow.Load(); got != 0 {
		t.Fatalf("flow affinity counter = %d, want 0", got)
	}
}

func TestPreparedTIXTCPFragmentedTIXBUsesFirstInnerHash(t *testing.T) {
	fastPath := testTIXTCPFastPathWithQueues(4)
	packet := tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("198.18.0.1"),
		DestinationIP:   netip.MustParseAddr("198.18.0.2"),
		SourcePort:      40000,
		DestinationPort: 9443,
	}
	firstInner := testInnerIPv4TCPPacket(11000, 5201)
	secondInner := testInnerIPv4TCPPacket(11001, 5201)
	batch := []byte{'T', 'I', 'X', 'B', 1, 0, 0, 2}
	batch = binary.BigEndian.AppendUint16(batch, uint16(len(firstInner)))
	batch = append(batch, firstInner...)
	batch = binary.BigEndian.AppendUint16(batch, uint16(len(secondInner)))
	batch = append(batch, secondInner...)
	frameA := preparedTIXTCPTXFrame{
		packet: packet,
		wireFrame: tixtcp.Frame{
			FlowID:        42,
			Sequence:      100,
			FragmentIndex: 0,
			FragmentCount: 2,
			Payload:       batch[:34],
		},
	}
	frameB := frameA
	frameB.wireFrame.Sequence++
	frameB.wireFrame.FragmentIndex = 1
	frameB.wireFrame.Payload = batch[34:]
	frames := []preparedTIXTCPTXFrame{frameA, frameB}
	hash, ok := fragmentedPreparedTIXTCPInnerHash(frames, 1)
	if !ok {
		t.Fatal("fragmented prepared TIXB hash is not valid")
	}
	wantHash, ok := innerIPv4TXHash(firstInner)
	if !ok {
		t.Fatal("first inner IPv4 hash is not valid")
	}
	if hash != wantHash {
		t.Fatalf("fragmented hash = %#x, want %#x", hash, wantHash)
	}
	frames[0].txInnerHash = hash
	frames[0].txInnerHashValid = true
	frames[1].txInnerHash = hash
	frames[1].txInnerHashValid = true

	gotFirst := fastPath.selectPreparedTXSocket(frames[0])
	gotSecond := fastPath.selectPreparedTXSocket(frames[1])
	if gotFirst != gotSecond {
		t.Fatalf("fragmented TIXB selected queues %d and %d, want one queue", gotFirst.queueID, gotSecond.queueID)
	}
	if got := fastPath.txAffinityTuple.Load(); got != 2 {
		t.Fatalf("tuple affinity counter = %d, want 2", got)
	}
}

func TestDataSessionBatchFirstInnerIPv4TXHash(t *testing.T) {
	first := testInnerIPv4TCPPacket(10000, 5201)
	second := testInnerIPv4TCPPacket(10001, 5201)
	batch := []byte{'T', 'I', 'X', 'B', 1, 0, 0, 2}
	batch = binary.BigEndian.AppendUint16(batch, uint16(len(first)))
	batch = append(batch, first...)
	batch = binary.BigEndian.AppendUint16(batch, uint16(len(second)))
	batch = append(batch, second...)
	want, ok := innerIPv4TXHash(first)
	if !ok {
		t.Fatal("first inner IPv4 hash is not valid")
	}

	got, ok := dataSessionBatchFirstInnerIPv4TXHash(batch)
	if !ok {
		t.Fatal("TIXB inner IPv4 hash is not valid")
	}
	if got != want {
		t.Fatalf("TIXB hash = %#x, want first inner hash %#x", got, want)
	}
}

func TestDataSessionBatchFirstInnerIPv4TXHashFromFragmentUsesPartialHeader(t *testing.T) {
	first := testInnerIPv4TCPPacket(10000, 5201)
	second := testInnerIPv4TCPPacket(10001, 5201)
	batch := []byte{'T', 'I', 'X', 'B', 1, 0, 0, 2}
	batch = binary.BigEndian.AppendUint16(batch, uint16(len(first)))
	batch = append(batch, first...)
	batch = binary.BigEndian.AppendUint16(batch, uint16(len(second)))
	batch = append(batch, second...)
	fragment := batch[:34]
	want, ok := innerIPv4TXHash(first)
	if !ok {
		t.Fatal("first inner IPv4 hash is not valid")
	}

	got, ok := dataSessionBatchFirstInnerIPv4TXHashFromFragment(fragment, 0)
	if !ok {
		t.Fatal("fragmented TIXB inner IPv4 hash is not valid")
	}
	if got != want {
		t.Fatalf("fragmented TIXB hash = %#x, want first inner hash %#x", got, want)
	}
}

func TestDataSessionBatchFirstInnerIPv4TXHashRejectsMalformedBatch(t *testing.T) {
	if _, ok := dataSessionBatchFirstInnerIPv4TXHash([]byte{'T', 'I', 'X', 'B', 1, 0, 0, 2, 0, 4, 1, 2}); ok {
		t.Fatal("malformed TIXB hash succeeded")
	}
}

func TestPreparedTXSocketAffinityFallsBackToFlowIDWhenInnerAffinityDisabled(t *testing.T) {
	t.Setenv("TRUSTIX_AF_XDP_TX_INNER_AFFINITY", "0")
	fastPath := testTIXTCPFastPathWithQueues(4)
	packet := kerneludp.UDPPacket{
		SourceIP:        netip.MustParseAddr("198.18.0.1"),
		DestinationIP:   netip.MustParseAddr("198.18.0.2"),
		SourcePort:      40000,
		DestinationPort: 9443,
	}
	frame := preparedKernelUDPInnerFrameForTest(t, packet, 42, 10000, 5201)

	got := fastPath.selectPreparedUDPTXSocket(frame)
	wantQueue := uint32(tixTCPTXQueueIndex(tixTCPMix64(frame.wireFrame.FlowID), len(fastPath.sockets)))
	if got.queueID != wantQueue {
		t.Fatalf("selected queue = %d, want flow hash queue %d", got.queueID, wantQueue)
	}
	if got := fastPath.txAffinityFlow.Load(); got != 1 {
		t.Fatalf("flow affinity counter = %d, want 1", got)
	}
	if got := fastPath.txAffinityTuple.Load(); got != 0 {
		t.Fatalf("tuple affinity counter = %d, want 0", got)
	}
}

func TestTIXTCPTXSocketAffinityCursorFallback(t *testing.T) {
	fastPath := testTIXTCPFastPathWithQueues(3)
	packet := tixtcp.TCPPacket{}
	frame := tixtcp.Frame{}

	if got := fastPath.selectTXSocket(packet, frame).queueID; got != 0 {
		t.Fatalf("first cursor queue = %d, want 0", got)
	}
	if got := fastPath.selectTXSocket(packet, frame).queueID; got != 1 {
		t.Fatalf("second cursor queue = %d, want 1", got)
	}
	if got := fastPath.selectTXSocket(packet, frame).queueID; got != 2 {
		t.Fatalf("third cursor queue = %d, want 2", got)
	}
	if got := fastPath.selectTXSocket(packet, frame).queueID; got != 0 {
		t.Fatalf("fourth cursor queue = %d, want 0", got)
	}
	if got := fastPath.txAffinityCursor.Load(); got != 4 {
		t.Fatalf("cursor affinity counter = %d, want 4", got)
	}
}

func TestTIXTCPDecodeKernelOpenedRXFrameNoCopyUnfragmented(t *testing.T) {
	fastPath := testTIXTCPFastPathWithQueues(1)
	fastPath.skipTCPChecksum = true
	manager := NewManager()
	socket := testAFXDPSocketForRXFrame()
	inner := testIPv4Packet([]byte("kernel-opened"))
	rxFrame, payloadOffset := testTIXTCPRXFrame(t, socket, tixtcp.Frame{
		Flags:    tixtcp.FlagKernelOpened | tixtcp.FlagInnerIPv4,
		FlowID:   7,
		Epoch:    9,
		Sequence: 11,
		Payload:  inner,
	})
	var expBatch []receivedTIXTCPFrame
	var udpBatch []receivedKernelUDPFrame

	mode, err := fastPath.decodeRXFrame(manager, socket, rxFrame, &expBatch, &udpBatch)
	if err != nil {
		t.Fatalf("decodeRXFrame error = %v", err)
	}
	if mode != afXDPRXRecycleByRelease {
		t.Fatalf("recycle mode = %d, want by-release", mode)
	}
	if len(udpBatch) != 0 {
		t.Fatalf("udp batch len = %d, want 0", len(udpBatch))
	}
	if len(expBatch) != 1 {
		t.Fatalf("tix_tcp batch len = %d, want 1", len(expBatch))
	}
	delivered := expBatch[0].frame
	if !bytes.Equal(delivered.Payload, inner) {
		t.Fatalf("payload = %x, want %x", delivered.Payload, inner)
	}
	rxFrame.data[payloadOffset] ^= 0xff
	if delivered.Payload[0] != rxFrame.data[payloadOffset] {
		t.Fatal("kernel-opened unfragmented payload was copied; want borrowed AF_XDP RX storage")
	}
	if !delivered.Encrypted || delivered.CryptoPlacement != dataplane.CryptoPlacementKernel || !delivered.InnerIPv4 {
		t.Fatalf("delivered metadata = encrypted:%v placement:%s inner:%v, want kernel opened inner IPv4", delivered.Encrypted, delivered.CryptoPlacement, delivered.InnerIPv4)
	}
	if delivered.Release == nil {
		t.Fatal("release is nil for borrowed RX storage")
	}
	delivered.Release()
	if rxFrame.recycled == nil || !rxFrame.recycled.Load() {
		t.Fatal("release did not recycle RX frame")
	}
	if got := atomic.LoadUint32(socket.fill.producer); got != 1 {
		t.Fatalf("fill producer after release = %d, want 1", got)
	}
	if socket.fill.descs[0] != rxFrame.addr {
		t.Fatalf("recycled addr = %d, want %d", socket.fill.descs[0], rxFrame.addr)
	}
}

func TestTIXTCPDecodeRXFrameRejectsMissingSocket(t *testing.T) {
	fastPath := testTIXTCPFastPathWithQueues(1)
	manager := NewManager()
	rxFrame := &afXDPRXFrame{data: make([]byte, ethernetHeaderLen)}
	var expBatch []receivedTIXTCPFrame
	var udpBatch []receivedKernelUDPFrame

	mode, err := fastPath.decodeRXFrame(manager, nil, rxFrame, &expBatch, &udpBatch)
	if err == nil {
		t.Fatal("decodeRXFrame error = nil, want missing socket error")
	}
	if mode != afXDPRXRecycleNow {
		t.Fatalf("recycle mode = %d, want recycle-now", mode)
	}
}

func TestTIXTCPDecodeRXFrameRecoversAndContinues(t *testing.T) {
	fastPath := testTIXTCPFastPathWithQueues(1)
	fastPath.skipTCPChecksum = true
	manager := NewManager()
	socket := testAFXDPSocketForRXFrame()
	rxFrame, _ := testTIXTCPRXFrame(t, socket, tixtcp.Frame{
		FlowID:   42,
		Sequence: 1,
		Payload:  []byte("payload"),
	})
	var udpBatch []receivedKernelUDPFrame

	mode, err := fastPath.decodeRXFrame(manager, socket, rxFrame, nil, &udpBatch)
	if err != nil {
		t.Fatalf("decodeRXFrame error = %v, want recovered nil error", err)
	}
	if mode != afXDPRXRecycleNow {
		t.Fatalf("recycle mode = %d, want recycle-now", mode)
	}
	manager.mu.Lock()
	warnings := append([]string(nil), manager.warnings...)
	manager.mu.Unlock()
	if len(warnings) != 1 || !strings.Contains(warnings[0], "tix_tcp AF_XDP RX decode recovered") {
		t.Fatalf("warnings = %#v, want recovered decode warning", warnings)
	}
}

func TestTIXTCPDecodeMultiFrameRXFrameNoCopy(t *testing.T) {
	fastPath := testTIXTCPFastPathWithQueues(1)
	fastPath.skipTCPChecksum = true
	manager := NewManager()
	socket := testAFXDPSocketForRXFrame()
	first := testIPv4Packet([]byte("multi-one"))
	second := testIPv4Packet([]byte("multi-two"))
	rxFrame, payloadOffsets := testTIXTCPRXFrameStream(t, socket,
		tixtcp.Frame{
			Flags:    tixtcp.FlagInnerIPv4,
			FlowID:   7,
			Epoch:    9,
			Sequence: 11,
			Payload:  first,
		},
		tixtcp.Frame{
			Flags:    tixtcp.FlagInnerIPv4,
			FlowID:   7,
			Epoch:    9,
			Sequence: 12,
			Payload:  second,
		},
	)
	var expBatch []receivedTIXTCPFrame
	var udpBatch []receivedKernelUDPFrame

	mode, err := fastPath.decodeRXFrame(manager, socket, rxFrame, &expBatch, &udpBatch)
	if err != nil {
		t.Fatalf("decodeRXFrame error = %v", err)
	}
	if mode != afXDPRXRecycleByRelease {
		t.Fatalf("recycle mode = %d, want by-release", mode)
	}
	if len(udpBatch) != 0 {
		t.Fatalf("udp batch len = %d, want 0", len(udpBatch))
	}
	if len(expBatch) != 2 {
		t.Fatalf("tix_tcp batch len = %d, want 2", len(expBatch))
	}
	if got := socket.stats.rxMultiFrameBatches.Load(); got != 1 {
		t.Fatalf("rx multi-frame batches = %d, want 1", got)
	}
	if got := socket.stats.rxMultiFrameFrames.Load(); got != 2 {
		t.Fatalf("rx multi-frame frames = %d, want 2", got)
	}
	for i, want := range [][]byte{first, second} {
		delivered := expBatch[i].frame
		if !bytes.Equal(delivered.Payload, want) {
			t.Fatalf("payload[%d] = %x, want %x", i, delivered.Payload, want)
		}
		if delivered.Release == nil {
			t.Fatalf("release[%d] is nil for borrowed RX storage", i)
		}
		rxFrame.data[payloadOffsets[i]] ^= 0xff
		if delivered.Payload[0] != rxFrame.data[payloadOffsets[i]] {
			t.Fatalf("payload[%d] was copied; want borrowed AF_XDP RX storage", i)
		}
	}
	expBatch[0].frame.Release()
	if rxFrame.recycled == nil || rxFrame.recycled.Load() {
		t.Fatal("first release recycled shared multi-frame RX storage before all frames were released")
	}
	if got := atomic.LoadUint32(socket.fill.producer); got != 0 {
		t.Fatalf("fill producer after first release = %d, want 0", got)
	}
	expBatch[1].frame.Release()
	if rxFrame.recycled == nil || !rxFrame.recycled.Load() {
		t.Fatal("second release did not recycle shared multi-frame RX storage")
	}
	if got := atomic.LoadUint32(socket.fill.producer); got != 1 {
		t.Fatalf("fill producer after second release = %d, want 1", got)
	}
}

func TestTIXTCPDecodeKernelOpenedRXFrameCopiesFragments(t *testing.T) {
	fastPath := testTIXTCPFastPathWithQueues(1)
	fastPath.skipTCPChecksum = true
	manager := NewManager()
	socket := testAFXDPSocketForRXFrame()
	fragment := []byte("fragment-payload")
	rxFrame, payloadOffset := testTIXTCPRXFrame(t, socket, tixtcp.Frame{
		Flags:         tixtcp.FlagKernelOpened,
		FlowID:        7,
		Epoch:         9,
		Sequence:      11,
		FragmentIndex: 1,
		FragmentCount: 2,
		Payload:       fragment,
	})
	wire := rxFrame.data
	var expBatch []receivedTIXTCPFrame
	var udpBatch []receivedKernelUDPFrame

	mode, err := fastPath.decodeRXFrame(manager, socket, rxFrame, &expBatch, &udpBatch)
	if err != nil {
		t.Fatalf("decodeRXFrame error = %v", err)
	}
	if mode != afXDPRXRecycleNow {
		t.Fatalf("recycle mode = %d, want immediate recycle for copied fragment", mode)
	}
	if len(expBatch) != 1 {
		t.Fatalf("tix_tcp batch len = %d, want 1", len(expBatch))
	}
	delivered := expBatch[0].frame
	if !bytes.Equal(delivered.Payload, fragment) {
		t.Fatalf("payload = %q, want %q", delivered.Payload, fragment)
	}
	wire[payloadOffset] ^= 0xff
	if delivered.Payload[0] == wire[payloadOffset] {
		t.Fatal("fragment payload borrowed AF_XDP RX storage; want independent copy")
	}
	if delivered.Release != nil {
		t.Fatal("release is set for copied fragment")
	}
	if rxFrame.recycled == nil || !rxFrame.recycled.Load() {
		t.Fatal("decode did not immediately recycle copied fragment RX frame")
	}
	if got := atomic.LoadUint32(socket.fill.producer); got != 1 {
		t.Fatalf("fill producer after copied fragment decode = %d, want 1", got)
	}
}

func TestTIXTCPDecodeUserspaceSecureRXFrameCopiesByDefault(t *testing.T) {
	tests := []struct {
		name  string
		magic []byte
	}{
		{name: "data", magic: []byte{'T', 'I', 'X', 'D'}},
		{name: "handshake", magic: []byte{'T', 'I', 'X', 'H'}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fastPath := testTIXTCPFastPathWithQueues(1)
			fastPath.skipTCPChecksum = true
			manager := NewManager()
			socket := testAFXDPSocketForRXFrame()
			payload := append(append([]byte(nil), tt.magic...), []byte("secure-wrapper-payload")...)
			rxFrame, payloadOffset := testTIXTCPRXFrame(t, socket, tixtcp.Frame{
				FlowID:   7,
				Epoch:    9,
				Sequence: 11,
				Payload:  payload,
			})
			wire := rxFrame.data
			var expBatch []receivedTIXTCPFrame
			var udpBatch []receivedKernelUDPFrame

			mode, err := fastPath.decodeRXFrame(manager, socket, rxFrame, &expBatch, &udpBatch)
			if err != nil {
				t.Fatalf("decodeRXFrame error = %v", err)
			}
			if mode != afXDPRXRecycleNow {
				t.Fatalf("recycle mode = %d, want immediate recycle for copied secure userspace frame", mode)
			}
			if len(expBatch) != 1 {
				t.Fatalf("tix_tcp batch len = %d, want 1", len(expBatch))
			}
			delivered := expBatch[0].frame
			if !bytes.Equal(delivered.Payload, payload) {
				t.Fatalf("payload = %x, want %x", delivered.Payload, payload)
			}
			if delivered.Encrypted || delivered.CryptoPlacement != dataplane.CryptoPlacementUserspace {
				t.Fatalf("delivered metadata = encrypted:%v placement:%s, want userspace secure wrapper", delivered.Encrypted, delivered.CryptoPlacement)
			}
			if delivered.Release != nil {
				t.Fatal("release is set for copied secure userspace frame")
			}
			if rxFrame.recycled == nil || !rxFrame.recycled.Load() {
				t.Fatal("decode did not immediately recycle copied secure userspace RX frame")
			}
			wire[payloadOffset] ^= 0xff
			if delivered.Payload[0] == wire[payloadOffset] {
				t.Fatal("secure userspace payload borrowed AF_XDP RX storage; want independent copy")
			}
			if got := atomic.LoadUint32(socket.fill.producer); got != 1 {
				t.Fatalf("fill producer after copied secure userspace decode = %d, want 1", got)
			}
		})
	}
}

func TestTIXTCPDecodeEncryptedRXFrameCopiesByDefault(t *testing.T) {
	fastPath := testTIXTCPFastPathWithQueues(1)
	fastPath.skipTCPChecksum = true
	manager := NewManager()
	socket := testAFXDPSocketForRXFrame()
	sequence := uint64(11)
	payload := bytesOf(0x5a, kernelCryptoSecureHeaderLen+48+kernelCryptoFrameTagLen)
	kernelCryptoPutSecureHeader(payload[:kernelCryptoSecureHeaderLen], byte(kernelCryptoSuiteIDTrustIXAES256GCMX25519), 9, sequence)
	rxFrame, payloadOffset := testTIXTCPRXFrame(t, socket, tixtcp.Frame{
		Flags:    tixtcp.FlagEncrypted,
		FlowID:   7,
		Epoch:    9,
		Sequence: sequence,
		Payload:  payload,
	})
	wire := rxFrame.data
	var expBatch []receivedTIXTCPFrame
	var udpBatch []receivedKernelUDPFrame

	mode, err := fastPath.decodeRXFrame(manager, socket, rxFrame, &expBatch, &udpBatch)
	if err != nil {
		t.Fatalf("decodeRXFrame error = %v", err)
	}
	if mode != afXDPRXRecycleNow {
		t.Fatalf("recycle mode = %d, want immediate recycle for copied encrypted frame", mode)
	}
	if len(expBatch) != 1 {
		t.Fatalf("tix_tcp batch len = %d, want 1", len(expBatch))
	}
	frame := expBatch[0]
	if !frame.encryptedKernelPayload || frame.encryptedKernelFragment {
		t.Fatalf("encrypted flags payload=%t fragment=%t, want encrypted whole frame", frame.encryptedKernelPayload, frame.encryptedKernelFragment)
	}
	if frame.kernelOpenPlain == nil || frame.kernelOpenPlainRelease == nil || frame.kernelOpenPlainInPlace {
		t.Fatal("encrypted fallback should preallocate an open buffer and avoid in-place open by default")
	}
	if frame.frame.Release != nil {
		t.Fatal("release is set for copied encrypted frame")
	}
	if rxFrame.recycled == nil || !rxFrame.recycled.Load() {
		t.Fatal("decode did not immediately recycle copied encrypted RX frame")
	}
	wire[payloadOffset] ^= 0xff
	if frame.frame.Payload[0] == wire[payloadOffset] {
		t.Fatal("encrypted payload borrowed AF_XDP RX storage; want independent copy")
	}
	if got := atomic.LoadUint32(socket.fill.producer); got != 1 {
		t.Fatalf("fill producer after copied encrypted decode = %d, want 1", got)
	}
	frame.kernelOpenPlainRelease()
}

func TestTIXTCPDecodeEncryptedCryptoFragmentCopiesByDefault(t *testing.T) {
	fastPath := testTIXTCPFastPathWithQueues(1)
	fastPath.skipTCPChecksum = true
	manager := NewManager()
	socket := testAFXDPSocketForRXFrame()
	sequence := uint64(11)
	payload := bytesOf(0x5a, kernelCryptoSecureHeaderLen+48+kernelCryptoFrameTagLen)
	kernelCryptoPutSecureHeader(payload[:kernelCryptoSecureHeaderLen], byte(kernelCryptoSuiteIDTrustIXAES256GCMX25519), 9, sequence)
	rxFrame, payloadOffset := testTIXTCPRXFrame(t, socket, tixtcp.Frame{
		Flags:         tixtcp.FlagEncrypted | tixtcp.FlagCryptoFragment,
		FlowID:        7,
		Epoch:         9,
		Sequence:      sequence,
		FragmentIndex: 0,
		FragmentCount: 2,
		Payload:       payload,
	})
	wire := rxFrame.data
	var expBatch []receivedTIXTCPFrame
	var udpBatch []receivedKernelUDPFrame

	mode, err := fastPath.decodeRXFrame(manager, socket, rxFrame, &expBatch, &udpBatch)
	if err != nil {
		t.Fatalf("decodeRXFrame error = %v", err)
	}
	if mode != afXDPRXRecycleNow {
		t.Fatalf("recycle mode = %d, want immediate recycle for copied encrypted fragment", mode)
	}
	if len(expBatch) != 1 {
		t.Fatalf("tix_tcp batch len = %d, want 1", len(expBatch))
	}
	frame := expBatch[0]
	if !frame.encryptedKernelPayload || !frame.encryptedKernelFragment {
		t.Fatalf("encrypted fragment flags payload=%t fragment=%t, want both true", frame.encryptedKernelPayload, frame.encryptedKernelFragment)
	}
	if frame.kernelOpenPlain != nil || frame.kernelOpenPlainRelease != nil || frame.kernelOpenPlainInPlace {
		t.Fatal("encrypted fragment should not preallocate whole-frame open storage")
	}
	if frame.frame.Release != nil {
		t.Fatal("release is set for copied encrypted fragment")
	}
	if rxFrame.recycled == nil || !rxFrame.recycled.Load() {
		t.Fatal("decode did not immediately recycle copied encrypted fragment RX frame")
	}
	wire[payloadOffset] ^= 0xff
	if frame.frame.Payload[0] == wire[payloadOffset] {
		t.Fatal("encrypted fragment borrowed AF_XDP RX storage; want independent copy")
	}
	if got := atomic.LoadUint32(socket.fill.producer); got != 1 {
		t.Fatalf("fill producer after copied encrypted fragment decode = %d, want 1", got)
	}
}

func TestTIXTCPDecodeEncryptedKernelOpenInPlaceOptIn(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_KERNEL_OPEN_INPLACE", "1")
	fastPath := testTIXTCPFastPathWithQueues(1)
	fastPath.skipTCPChecksum = true
	manager := NewManager()
	socket := testAFXDPSocketForRXFrame()
	socket.kernelOpenInPlace = true
	sequence := uint64(11)
	payload := bytesOf(0x5a, kernelCryptoSecureHeaderLen+48+kernelCryptoFrameTagLen)
	kernelCryptoPutSecureHeader(payload[:kernelCryptoSecureHeaderLen], byte(kernelCryptoSuiteIDTrustIXAES256GCMX25519), 9, sequence)
	rxFrame, _ := testTIXTCPRXFrame(t, socket, tixtcp.Frame{
		Flags:    tixtcp.FlagEncrypted | tixtcp.FlagInnerIPv4,
		FlowID:   7,
		Epoch:    9,
		Sequence: sequence,
		Payload:  payload,
	})
	var expBatch []receivedTIXTCPFrame
	var udpBatch []receivedKernelUDPFrame

	mode, err := fastPath.decodeRXFrame(manager, socket, rxFrame, &expBatch, &udpBatch)
	if err != nil {
		t.Fatalf("decodeRXFrame error = %v", err)
	}
	if mode != afXDPRXRecycleByRelease {
		t.Fatalf("recycle mode = %d, want by-release", mode)
	}
	if len(expBatch) != 1 {
		t.Fatalf("tix_tcp batch len = %d, want 1", len(expBatch))
	}
	frame := expBatch[0]
	if !frame.kernelOpenPlainInPlace {
		t.Fatal("encrypted kernel-open frame did not select in-place open")
	}
	if frame.kernelOpenPlain != nil || frame.kernelOpenPlainRelease != nil {
		t.Fatal("in-place kernel-open frame should not preallocate a plain buffer")
	}
	if frame.frame.Release == nil {
		t.Fatal("in-place kernel-open frame must retain RX release callback")
	}
	frame.frame.Release()
	if rxFrame.recycled == nil || !rxFrame.recycled.Load() {
		t.Fatal("release did not recycle in-place RX frame")
	}
}

func TestKernelUDPDecodePlainRXFrameNoCopyUnfragmented(t *testing.T) {
	fastPath := testTIXTCPFastPathWithQueues(1)
	fastPath.skipUDPChecksum = true
	manager := NewManager()
	socket := testAFXDPSocketForRXFrame()
	inner := testIPv4Packet([]byte("kernel-udp-plain"))
	rxFrame, payloadOffset := testKernelUDPRXFrame(t, socket, kerneludp.Frame{
		Flags:    kerneludp.FlagInnerIPv4,
		FlowID:   17,
		Sequence: 23,
		Payload:  inner,
	})
	var expBatch []receivedTIXTCPFrame
	var udpBatch []receivedKernelUDPFrame

	mode, err := fastPath.decodeRXFrame(manager, socket, rxFrame, &expBatch, &udpBatch)
	if err != nil {
		t.Fatalf("decodeRXFrame error = %v", err)
	}
	if mode != afXDPRXRecycleByRelease {
		t.Fatalf("recycle mode = %d, want by-release", mode)
	}
	if len(expBatch) != 0 {
		t.Fatalf("tix_tcp batch len = %d, want 0", len(expBatch))
	}
	if len(udpBatch) != 1 {
		t.Fatalf("kernel_udp batch len = %d, want 1", len(udpBatch))
	}
	delivered := udpBatch[0].frame
	if !bytes.Equal(delivered.Payload, inner) {
		t.Fatalf("payload = %x, want %x", delivered.Payload, inner)
	}
	rxFrame.data[payloadOffset] ^= 0xff
	if delivered.Payload[0] != rxFrame.data[payloadOffset] {
		t.Fatal("kernel_udp plain unfragmented payload was copied; want borrowed AF_XDP RX storage")
	}
	if delivered.Encrypted || delivered.CryptoPlacement != dataplane.CryptoPlacementUserspace || !delivered.InnerIPv4 {
		t.Fatalf("delivered metadata = encrypted:%v placement:%s inner:%v, want plaintext inner IPv4", delivered.Encrypted, delivered.CryptoPlacement, delivered.InnerIPv4)
	}
	if delivered.Release == nil {
		t.Fatal("release is nil for borrowed RX storage")
	}
	delivered.Release()
	if rxFrame.recycled == nil || !rxFrame.recycled.Load() {
		t.Fatal("release did not recycle RX frame")
	}
	if got := atomic.LoadUint32(socket.fill.producer); got != 1 {
		t.Fatalf("fill producer after release = %d, want 1", got)
	}
	if socket.fill.descs[0] != rxFrame.addr {
		t.Fatalf("recycled addr = %d, want %d", socket.fill.descs[0], rxFrame.addr)
	}
}

func TestKernelUDPDecodeKernelOpenedRXFrameNoCopyUnfragmented(t *testing.T) {
	fastPath := testTIXTCPFastPathWithQueues(1)
	fastPath.skipUDPChecksum = true
	manager := NewManager()
	socket := testAFXDPSocketForRXFrame()
	inner := testIPv4Packet([]byte("kernel-udp-opened"))
	rxFrame, payloadOffset := testKernelUDPRXFrame(t, socket, kerneludp.Frame{
		Flags:    kerneludp.FlagKernelOpened | kerneludp.FlagInnerIPv4,
		FlowID:   19,
		Sequence: 29,
		Payload:  inner,
	})
	var expBatch []receivedTIXTCPFrame
	var udpBatch []receivedKernelUDPFrame

	mode, err := fastPath.decodeRXFrame(manager, socket, rxFrame, &expBatch, &udpBatch)
	if err != nil {
		t.Fatalf("decodeRXFrame error = %v", err)
	}
	if mode != afXDPRXRecycleByRelease {
		t.Fatalf("recycle mode = %d, want by-release", mode)
	}
	if len(expBatch) != 0 {
		t.Fatalf("tix_tcp batch len = %d, want 0", len(expBatch))
	}
	if len(udpBatch) != 1 {
		t.Fatalf("kernel_udp batch len = %d, want 1", len(udpBatch))
	}
	delivered := udpBatch[0].frame
	if !bytes.Equal(delivered.Payload, inner) {
		t.Fatalf("payload = %x, want %x", delivered.Payload, inner)
	}
	rxFrame.data[payloadOffset] ^= 0xff
	if delivered.Payload[0] != rxFrame.data[payloadOffset] {
		t.Fatal("kernel_udp kernel-opened unfragmented payload was copied; want borrowed AF_XDP RX storage")
	}
	if !delivered.Encrypted || delivered.CryptoPlacement != dataplane.CryptoPlacementKernel || !delivered.InnerIPv4 {
		t.Fatalf("delivered metadata = encrypted:%v placement:%s inner:%v, want kernel opened inner IPv4", delivered.Encrypted, delivered.CryptoPlacement, delivered.InnerIPv4)
	}
	if delivered.Release == nil {
		t.Fatal("release is nil for borrowed RX storage")
	}
	delivered.Release()
	if rxFrame.recycled == nil || !rxFrame.recycled.Load() {
		t.Fatal("release did not recycle RX frame")
	}
	if got := atomic.LoadUint32(socket.fill.producer); got != 1 {
		t.Fatalf("fill producer after release = %d, want 1", got)
	}
}

func TestKernelUDPDecodeKernelOpenedRXFrameCopiesFragments(t *testing.T) {
	fastPath := testTIXTCPFastPathWithQueues(1)
	fastPath.skipUDPChecksum = true
	manager := NewManager()
	socket := testAFXDPSocketForRXFrame()
	fragment := []byte("kernel-udp-fragment")
	rxFrame, payloadOffset := testKernelUDPRXFrame(t, socket, kerneludp.Frame{
		Flags:         kerneludp.FlagKernelOpened,
		FlowID:        31,
		Sequence:      41,
		FragmentIndex: 1,
		FragmentCount: 2,
		Payload:       fragment,
	})
	wire := rxFrame.data
	var expBatch []receivedTIXTCPFrame
	var udpBatch []receivedKernelUDPFrame

	mode, err := fastPath.decodeRXFrame(manager, socket, rxFrame, &expBatch, &udpBatch)
	if err != nil {
		t.Fatalf("decodeRXFrame error = %v", err)
	}
	if mode != afXDPRXRecycleNow {
		t.Fatalf("recycle mode = %d, want immediate recycle for copied fragment", mode)
	}
	if len(udpBatch) != 1 {
		t.Fatalf("kernel_udp batch len = %d, want 1", len(udpBatch))
	}
	delivered := udpBatch[0].frame
	if !bytes.Equal(delivered.Payload, fragment) {
		t.Fatalf("payload = %q, want %q", delivered.Payload, fragment)
	}
	wire[payloadOffset] ^= 0xff
	if delivered.Payload[0] == wire[payloadOffset] {
		t.Fatal("fragment payload borrowed AF_XDP RX storage; want independent copy")
	}
	if delivered.Release != nil {
		t.Fatal("release is set for copied fragment")
	}
	if rxFrame.recycled == nil || !rxFrame.recycled.Load() {
		t.Fatal("decode did not immediately recycle copied fragment RX frame")
	}
	if got := atomic.LoadUint32(socket.fill.producer); got != 1 {
		t.Fatalf("fill producer after copied fragment decode = %d, want 1", got)
	}
}

func TestKernelUDPDecodePayloadBorrowEncryptedFrames(t *testing.T) {
	manager := NewManager()
	packet := kerneludp.UDPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.1"),
		DestinationIP:   netip.MustParseAddr("198.51.100.2"),
		SourcePort:      40000,
		DestinationPort: 9443,
	}

	encryptedWire := mustKernelUDPFrameWire(t, kerneludp.Frame{
		Flags:    kerneludp.FlagEncrypted,
		FlowID:   17,
		Sequence: 23,
		Payload:  bytesOf(0x5a, kernelCryptoSecureHeaderLen+48+kernelCryptoFrameTagLen),
	})
	encrypted, ok := manager.decodeKernelUDPPayloadBorrowEncrypted(packet, encryptedWire)
	if !ok {
		t.Fatal("decode encrypted borrowed frame failed")
	}
	if len(encrypted.frame.Payload) == 0 || &encrypted.frame.Payload[0] != &encryptedWire[kerneludp.HeaderLen] {
		t.Fatal("encrypted whole-frame payload was copied; want borrowed socket receive storage")
	}
	if !encrypted.borrowedKernelPayload {
		t.Fatal("encrypted whole-frame payload missing borrowed marker")
	}
	if encrypted.kernelOpenPlain != nil || encrypted.kernelOpenPlainRelease != nil || encrypted.frame.Release != nil {
		t.Fatal("encrypted borrowed frame preallocated open buffer before open fallback")
	}

	plainPayload := []byte("plain-kernel-udp")
	plainWire := mustKernelUDPFrameWire(t, kerneludp.Frame{
		FlowID:   19,
		Sequence: 29,
		Payload:  plainPayload,
	})
	plain, ok := manager.decodeKernelUDPPayloadBorrowEncrypted(packet, plainWire)
	if !ok {
		t.Fatal("decode plain frame failed")
	}
	if &plain.frame.Payload[0] == &plainWire[kerneludp.HeaderLen] {
		t.Fatal("plain payload borrowed socket receive storage; want independent copy")
	}
	plainWire[kerneludp.HeaderLen] ^= 0xff
	if bytes.Equal(plain.frame.Payload, plainWire[kerneludp.HeaderLen:]) {
		t.Fatal("plain copied payload changed after receive buffer mutation")
	}
	if plain.frame.Release != nil || plain.kernelOpenPlainRelease != nil {
		t.Fatal("plain frame unexpectedly has release callback")
	}
	if plain.borrowedKernelPayload {
		t.Fatal("plain frame unexpectedly has borrowed marker")
	}

	fragmentWire := mustKernelUDPFrameWire(t, kerneludp.Frame{
		Flags:         kerneludp.FlagEncrypted | kerneludp.FlagCryptoFragment,
		FlowID:        21,
		Sequence:      31,
		FragmentIndex: 0,
		FragmentCount: 2,
		Payload:       []byte("encrypted-fragment"),
	})
	fragment, ok := manager.decodeKernelUDPPayloadBorrowEncrypted(packet, fragmentWire)
	if !ok {
		t.Fatal("decode encrypted fragment failed")
	}
	if &fragment.frame.Payload[0] != &fragmentWire[kerneludp.HeaderLen] {
		t.Fatal("encrypted fragment was copied; want borrowed socket receive storage before reassembly")
	}
	if !fragment.encryptedKernelFragment || !fragment.encryptedKernelPayload {
		t.Fatalf("fragment crypto flags payload=%t fragment=%t, want both true", fragment.encryptedKernelPayload, fragment.encryptedKernelFragment)
	}
	if !fragment.borrowedKernelPayload {
		t.Fatal("encrypted fragment missing borrowed marker")
	}
}

func TestAFXDPAcquireTXFrameWaitsForShortBackpressure(t *testing.T) {
	socket := &afXDPSocket{
		txFree:             make([]uint64, 0, 1),
		txBackpressureWait: 50 * time.Millisecond,
		txBackpressurePoll: time.Millisecond,
	}
	const addr = 2 * tixTCPDefaultUMEMFrameSize
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(2 * time.Millisecond)
		socket.releaseTXFrame(addr)
	}()

	got, ok := socket.acquireTXFrame()
	<-done
	if !ok {
		t.Fatal("acquireTXFrame returned false, want delayed frame")
	}
	if got != addr {
		t.Fatalf("acquired addr = %d, want %d", got, addr)
	}
	if got := socket.stats.txBackpressureWaits.Load(); got != 1 {
		t.Fatalf("backpressure waits = %d, want 1", got)
	}
	if got := socket.stats.txBackpressureTimeouts.Load(); got != 0 {
		t.Fatalf("backpressure timeouts = %d, want 0", got)
	}
}

func TestAFXDPAcquireTXFrameTimesOut(t *testing.T) {
	socket := &afXDPSocket{
		txFree:             make([]uint64, 0, 1),
		txBackpressureWait: time.Nanosecond,
	}
	if addr, ok := socket.acquireTXFrame(); ok {
		t.Fatalf("acquireTXFrame returned addr=%d, want timeout", addr)
	}
	if got := socket.stats.txBackpressureWaits.Load(); got != 1 {
		t.Fatalf("backpressure waits = %d, want 1", got)
	}
	if got := socket.stats.txBackpressureTimeouts.Load(); got != 1 {
		t.Fatalf("backpressure timeouts = %d, want 1", got)
	}
}

func TestAFXDPSocketReclaimCompletionsReturnsFrames(t *testing.T) {
	producer := uint32(1)
	consumer := uint32(0)
	socket := &afXDPSocket{
		txFree: make([]uint64, 0, 1),
		comp: xdpUint64Ring{
			producer: &producer,
			consumer: &consumer,
			descs:    []uint64{tixTCPDefaultUMEMFrameSize, 0},
			size:     2,
			mask:     1,
		},
	}

	if got := socket.ReclaimCompletions(); got != 1 {
		t.Fatalf("reclaimed completions = %d, want 1", got)
	}
	addr, ok := socket.acquireTXFrame()
	if !ok {
		t.Fatal("expected reclaimed tx frame")
	}
	if addr != tixTCPDefaultUMEMFrameSize {
		t.Fatalf("reclaimed addr = %d, want %d", addr, tixTCPDefaultUMEMFrameSize)
	}
	if got := socket.stats.txCompletions.Load(); got != 1 {
		t.Fatalf("tx completions = %d, want 1", got)
	}
}

func TestAFXDPRXRecycleUsesSocketStateWithoutPerFrameAtomic(t *testing.T) {
	producer := uint32(0)
	consumer := uint32(0)
	socket := &afXDPSocket{
		umemFrames:     2,
		umemFrameSize:  tixTCPDefaultUMEMFrameSize,
		rxRecycleState: make([]atomic.Uint64, 2),
		fill: xdpUint64Ring{
			producer: &producer,
			consumer: &consumer,
			descs:    make([]uint64, 2),
			size:     2,
			mask:     1,
		},
	}
	frame := afXDPRXFrame{
		socket:       socket,
		addr:         tixTCPDefaultUMEMFrameSize,
		data:         []byte("payload"),
		recycleIndex: 1,
		recycleToken: 2,
	}
	socket.rxRecycleState[1].Store(2)

	if err := frame.Recycle(); err != nil {
		t.Fatalf("Recycle error = %v", err)
	}
	if got := atomic.LoadUint32(&producer); got != 1 {
		t.Fatalf("fill producer after first recycle = %d, want 1", got)
	}
	if socket.fill.descs[0] != tixTCPDefaultUMEMFrameSize {
		t.Fatalf("recycled addr = %d, want %d", socket.fill.descs[0], tixTCPDefaultUMEMFrameSize)
	}
	if got := socket.rxRecycleState[1].Load(); got != 3 {
		t.Fatalf("socket recycle state = %d, want recycled token 3", got)
	}
	if err := frame.Recycle(); err != nil {
		t.Fatalf("second Recycle error = %v", err)
	}
	if got := atomic.LoadUint32(&producer); got != 1 {
		t.Fatalf("fill producer after duplicate recycle = %d, want 1", got)
	}

	socket.rxRecycleState[1].Store(4)
	if err := frame.Recycle(); err != nil {
		t.Fatalf("stale Recycle error = %v", err)
	}
	if got := atomic.LoadUint32(&producer); got != 1 {
		t.Fatalf("fill producer after stale recycle = %d, want 1", got)
	}
}

func TestAFXDPRXRecycleWithoutTokenFallsBackToCurrentState(t *testing.T) {
	producer := uint32(0)
	consumer := uint32(0)
	socket := &afXDPSocket{
		umemFrames:     1,
		umemFrameSize:  tixTCPDefaultUMEMFrameSize,
		rxRecycleState: make([]atomic.Uint64, 1),
		fill: xdpUint64Ring{
			producer: &producer,
			consumer: &consumer,
			descs:    make([]uint64, 1),
			size:     1,
			mask:     0,
		},
	}
	socket.rxRecycleState[0].Store(6)
	frame := afXDPRXFrame{socket: socket, data: []byte("legacy")}

	if err := frame.Recycle(); err != nil {
		t.Fatalf("Recycle error = %v", err)
	}
	if got := socket.rxRecycleState[0].Load(); got != 7 {
		t.Fatalf("socket recycle state = %d, want 7", got)
	}
	if got := atomic.LoadUint32(&producer); got != 1 {
		t.Fatalf("fill producer = %d, want 1", got)
	}
}

func TestAFXDPSocketRecycleRXFramesBatchesFillRing(t *testing.T) {
	producer := uint32(0)
	consumer := uint32(0)
	socket := &afXDPSocket{
		umemFrames:     4,
		umemFrameSize:  tixTCPDefaultUMEMFrameSize,
		rxRecycleState: make([]atomic.Uint64, 4),
		fill: xdpUint64Ring{
			producer: &producer,
			consumer: &consumer,
			descs:    make([]uint64, 4),
			size:     4,
			mask:     3,
		},
	}
	socket.rxRecycleState[0].Store(2)
	socket.rxRecycleState[1].Store(2)
	frames := []afXDPRXFrame{
		{socket: socket, addr: 0, data: []byte("one"), recycleIndex: 0, recycleToken: 2},
		{socket: socket, addr: tixTCPDefaultUMEMFrameSize, data: []byte("two"), recycleIndex: 1, recycleToken: 2},
	}

	socket.recycleRXFrames(frames)

	if got := atomic.LoadUint32(&producer); got != 2 {
		t.Fatalf("fill producer = %d, want 2", got)
	}
	if socket.fill.descs[0] != 0 || socket.fill.descs[1] != tixTCPDefaultUMEMFrameSize {
		t.Fatalf("fill descs = %#v", socket.fill.descs[:2])
	}
	if socket.rxRecycleState[0].Load() != 3 || socket.rxRecycleState[1].Load() != 3 {
		t.Fatal("socket recycle state was not marked")
	}
}

func TestAFXDPPublishTXFrameWaitsForRingCompletion(t *testing.T) {
	txProducer := uint32(1)
	txConsumer := uint32(0)
	compProducer := uint32(0)
	compConsumer := uint32(0)
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	socket := &afXDPSocket{
		fd:                 fds[0],
		txFree:             make([]uint64, 0, 1),
		txBackpressureWait: 50 * time.Millisecond,
		txBackpressurePoll: time.Millisecond,
		txKickBatch:        128,
		tx: xdpDescRing{
			producer: &txProducer,
			consumer: &txConsumer,
			descs:    []unix.XDPDesc{{}},
			size:     1,
			mask:     0,
		},
		comp: xdpUint64Ring{
			producer: &compProducer,
			consumer: &compConsumer,
			descs:    []uint64{2 * tixTCPDefaultUMEMFrameSize},
			size:     1,
			mask:     0,
		},
	}
	go func() {
		time.Sleep(2 * time.Millisecond)
		atomic.StoreUint32(&txConsumer, 1)
		socket.comp.descs[0] = 2 * tixTCPDefaultUMEMFrameSize
		atomic.StoreUint32(&compProducer, 1)
	}()

	published, err := socket.publishTXFrameLocked(3*tixTCPDefaultUMEMFrameSize, 64, false)
	if err != nil {
		t.Fatalf("publishTXFrameLocked error = %v", err)
	}
	if !published {
		t.Fatal("publishTXFrameLocked published = false, want true")
	}
	if got := socket.stats.txBackpressureWaits.Load(); got != 1 {
		t.Fatalf("backpressure waits = %d, want 1", got)
	}
	if got := socket.stats.txBackpressureTimeouts.Load(); got != 0 {
		t.Fatalf("backpressure timeouts = %d, want 0", got)
	}
	if got := socket.stats.txBackpressureReclaims.Load(); got == 0 {
		t.Fatal("backpressure reclaims = 0, want > 0")
	}
}

func TestXDPDescRingPushBatchAdvancesProducerOnce(t *testing.T) {
	producer := uint32(0)
	consumer := uint32(0)
	ring := xdpDescRing{
		producer: &producer,
		consumer: &consumer,
		descs:    make([]unix.XDPDesc, 4),
		size:     4,
		mask:     3,
	}
	descs := []unix.XDPDesc{
		{Addr: 64, Len: 128},
		{Addr: 256, Len: 512},
		{Addr: 1024, Len: 1500},
	}

	if err := ring.PushBatch(descs); err != nil {
		t.Fatalf("PushBatch error = %v", err)
	}
	if got := atomic.LoadUint32(&producer); got != uint32(len(descs)) {
		t.Fatalf("producer = %d, want %d", got, len(descs))
	}
	for i, want := range descs {
		if got := ring.descs[i]; got != want {
			t.Fatalf("desc[%d] = %#v, want %#v", i, got, want)
		}
	}
	if err := ring.PushBatch([]unix.XDPDesc{{Addr: 2048, Len: 64}, {Addr: 4096, Len: 64}}); !errors.Is(err, errAFXDPRingFull) {
		t.Fatalf("PushBatch overflow error = %v, want ring full", err)
	}
}

func TestXDPDescRingPopBatchAdvancesConsumerOnce(t *testing.T) {
	producer := uint32(3)
	consumer := uint32(0)
	ring := xdpDescRing{
		producer: &producer,
		consumer: &consumer,
		descs: []unix.XDPDesc{
			{Addr: 64, Len: 128},
			{Addr: 256, Len: 512},
			{Addr: 1024, Len: 1500},
			{},
		},
		size: 4,
		mask: 3,
	}
	out := make([]unix.XDPDesc, 2)

	n := ring.PopBatch(out)
	if n != 2 {
		t.Fatalf("PopBatch n = %d, want 2", n)
	}
	if got := atomic.LoadUint32(&consumer); got != 2 {
		t.Fatalf("consumer = %d, want 2", got)
	}
	if out[0].Addr != 64 || out[1].Addr != 256 {
		t.Fatalf("descs = %#v", out)
	}

	n = ring.PopBatch(out)
	if n != 1 {
		t.Fatalf("second PopBatch n = %d, want 1", n)
	}
	if got := atomic.LoadUint32(&consumer); got != 3 {
		t.Fatalf("consumer after second pop = %d, want 3", got)
	}
	n = ring.PopBatch(out)
	if n != 0 {
		t.Fatalf("empty PopBatch n = %d, want 0", n)
	}
}

func TestXDPUint64RingPushBatchAdvancesProducerOnce(t *testing.T) {
	producer := uint32(0)
	consumer := uint32(0)
	ring := xdpUint64Ring{
		producer: &producer,
		consumer: &consumer,
		descs:    make([]uint64, 4),
		size:     4,
		mask:     3,
	}
	addrs := []uint64{64, 256, 1024}

	if err := ring.PushBatch(addrs); err != nil {
		t.Fatalf("PushBatch error = %v", err)
	}
	if got := atomic.LoadUint32(&producer); got != uint32(len(addrs)) {
		t.Fatalf("producer = %d, want %d", got, len(addrs))
	}
	for i, want := range addrs {
		if got := ring.descs[i]; got != want {
			t.Fatalf("desc[%d] = %#v, want %#v", i, got, want)
		}
	}
	if err := ring.PushBatch([]uint64{2048, 4096}); !errors.Is(err, errAFXDPRingFull) {
		t.Fatalf("PushBatch overflow error = %v, want ring full", err)
	}
}

func TestTIXTCPAttachPlansAutoNeedWakeupFallsBack(t *testing.T) {
	t.Setenv("TRUSTIX_XDP_MODE", "skb")
	t.Setenv("TRUSTIX_AF_XDP_BIND_MODE", "copy")
	t.Setenv("TRUSTIX_AF_XDP_NEED_WAKEUP", "auto")

	plans := tixTCPAttachPlans()
	if len(plans) != 2 {
		t.Fatalf("attach plans = %d, want 2", len(plans))
	}
	if !plans[0].needWakeup || plans[0].bindFlags&uint16(unix.XDP_USE_NEED_WAKEUP) == 0 {
		t.Fatalf("first plan should try XDP_USE_NEED_WAKEUP: %#v", plans[0])
	}
	if plans[1].needWakeup || plans[1].bindFlags&uint16(unix.XDP_USE_NEED_WAKEUP) != 0 {
		t.Fatalf("second plan should fall back without XDP_USE_NEED_WAKEUP: %#v", plans[1])
	}
}

func TestTIXTCPAttachPlansPreferSKBForVethXDPDirect(t *testing.T) {
	t.Setenv("TRUSTIX_XDP_MODE", "")
	t.Setenv("TRUSTIX_AF_XDP_BIND_MODE", "auto")
	t.Setenv("TRUSTIX_AF_XDP_NEED_WAKEUP", "")

	plans := tixTCPAttachPlansWithOptions(tixTCPFastPathOptions{preferSKBXDPMode: true})
	if len(plans) == 0 {
		t.Fatal("attach plans empty")
	}
	if got := plans[0].xdpMode; got != tixTCPXDPAttachSKB {
		t.Fatalf("first attach plan XDP mode = %q, want %q", got, tixTCPXDPAttachSKB)
	}
	seenNative := false
	for _, plan := range plans {
		if plan.xdpMode == tixTCPXDPAttachNative {
			seenNative = true
			break
		}
	}
	if !seenNative {
		t.Fatal("native XDP fallback plan missing")
	}
}

func TestTIXTCPAttachPlansExplicitNativeOverridesSKBPreference(t *testing.T) {
	t.Setenv("TRUSTIX_XDP_MODE", "native")
	t.Setenv("TRUSTIX_AF_XDP_BIND_MODE", "auto")

	plans := tixTCPAttachPlansWithOptions(tixTCPFastPathOptions{preferSKBXDPMode: true})
	if len(plans) == 0 {
		t.Fatal("attach plans empty")
	}
	for _, plan := range plans {
		if plan.xdpMode != tixTCPXDPAttachNative {
			t.Fatalf("explicit native plan mode = %q, want only native", plan.xdpMode)
		}
	}
}

func TestTIXTCPAttachPlansVirtioSafetyForcesSKBCopy(t *testing.T) {
	t.Setenv("TRUSTIX_XDP_MODE", "native")
	t.Setenv("TRUSTIX_AF_XDP_BIND_MODE", "zerocopy")
	t.Setenv("TRUSTIX_AF_XDP_NEED_WAKEUP", "")

	plans := tixTCPAttachPlansWithOptions(tixTCPFastPathOptions{
		forceSKBXDPMode:   true,
		forceCopyBindMode: true,
	})
	if len(plans) != 1 {
		t.Fatalf("attach plans = %d, want 1", len(plans))
	}
	if plans[0].xdpMode != tixTCPXDPAttachSKB || plans[0].bindMode != tixTCPAFXDPBindCopy {
		t.Fatalf("attach plan = %#v, want skb/copy", plans[0])
	}
}

func TestTIXTCPQueueCountLimitOptionCapsQueues(t *testing.T) {
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{NumRxQueues: 8}}

	got := tixTCPQueueCountWithOptions(link, tixTCPFastPathOptions{limitQueues: 1})
	if got != 1 {
		t.Fatalf("queue count = %d, want 1", got)
	}
}

func TestTIXTCPQueueCountVirtioSafetyAllowsAvailableQueues(t *testing.T) {
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{NumRxQueues: 8, NumTxQueues: 4}}

	got := tixTCPQueueCountWithOptions(link, tixTCPFastPathOptions{
		forceSKBXDPMode:   true,
		forceCopyBindMode: true,
		virtioNetSafety:   true,
	})
	if got != 4 {
		t.Fatalf("queue count = %d, want all available TX-capped queues", got)
	}
}

func TestTIXTCPQueueCountDirectOnlyAllowsAvailableQueues(t *testing.T) {
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{NumRxQueues: 8, NumTxQueues: 4}}

	got := tixTCPQueueCountWithOptions(link, tixTCPFastPathOptions{
		directOnlyControlPlane: true,
	})
	if got != 4 {
		t.Fatalf("direct-only queue count = %d, want all available TX-capped queues", got)
	}
}

func TestTIXTCPQueueCountCapsToTXQueues(t *testing.T) {
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{NumRxQueues: 8, NumTxQueues: 1}}

	got := tixTCPQueueCountWithOptions(link, tixTCPFastPathOptions{})
	if got != 1 {
		t.Fatalf("queue count = %d, want TX queue cap 1", got)
	}
}

func TestAFXDPSendPreparedTIXTCPFramesBatchesDescriptors(t *testing.T) {
	txProducer := uint32(0)
	txConsumer := uint32(0)
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	socket := &afXDPSocket{
		fd:                     fds[0],
		linkMAC:                net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		umem:                   make([]byte, 3*tixTCPDefaultUMEMFrameSize),
		umemFrameSize:          tixTCPDefaultUMEMFrameSize,
		txFree:                 []uint64{0, tixTCPDefaultUMEMFrameSize},
		txKickBatch:            1024,
		txBackpressurePoll:     time.Millisecond,
		txMultiFrameMaxFrames:  tixTCPTXMultiFrameMaxFrames(),
		txMultiFrameMaxIPv4Len: tixTCPTXMultiFrameMaxIPv4Len(),
		tx: xdpDescRing{
			producer: &txProducer,
			consumer: &txConsumer,
			descs:    make([]unix.XDPDesc, 4),
			size:     4,
			mask:     3,
		},
	}
	packet := tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.1"),
		DestinationIP:   netip.MustParseAddr("198.51.100.2"),
		SourcePort:      40000,
		DestinationPort: 9443,
		Acknowledgment:  1,
	}
	items := []preparedTIXTCPTXFrame{
		{packet: packet, wireFrame: tixtcp.Frame{FlowID: 7, Epoch: 9, Sequence: 1, Payload: []byte("one")}},
		{packet: func() tixtcp.TCPPacket {
			packet := packet
			packet.Sequence = uint32(tixtcp.HeaderLen + len("one"))
			return packet
		}(), wireFrame: tixtcp.Frame{FlowID: 7, Epoch: 9, Sequence: 2, Payload: []byte("two")}},
	}

	if err := socket.SendPreparedFrames(items, net.HardwareAddr{0x02, 0, 0, 0, 0, 2}); err != nil {
		t.Fatalf("SendPreparedFrames error = %v", err)
	}
	if got := atomic.LoadUint32(&txProducer); got != 2 {
		t.Fatalf("tx producer = %d, want 2", got)
	}
	if got := socket.stats.txBatchSubmissions.Load(); got != 1 {
		t.Fatalf("tx batch submissions = %d, want 1", got)
	}
	if got := socket.stats.txBatchFrames.Load(); got != 2 {
		t.Fatalf("tx batch frames = %d, want 2", got)
	}
	for i, item := range items {
		desc := socket.tx.descs[i]
		start := int(desc.Addr)
		end := start + int(desc.Len)
		if end > len(socket.umem) {
			t.Fatalf("desc %d out of bounds: %#v", i, desc)
		}
		wire := socket.umem[start+ethernetHeaderLen : end]
		packet, err := tixtcp.ParseTCPShapedIPv4NoCopy(wire)
		if err != nil {
			t.Fatalf("parse tix_tcp packet %d: %v", i, err)
		}
		frame, err := tixtcp.ParseFrameNoCopy(packet.Payload)
		if err != nil {
			t.Fatalf("parse TIXT %d: %v", i, err)
		}
		if packet.Sequence != item.packet.Sequence {
			t.Fatalf("packet sequence %d = %d, want %d", i, packet.Sequence, item.packet.Sequence)
		}
		if frame.Sequence != item.wireFrame.Sequence || !bytes.Equal(frame.Payload, item.wireFrame.Payload) {
			t.Fatalf("frame %d = %#v, want %#v", i, frame, item.wireFrame)
		}
	}
}

func TestAFXDPSendPreparedTIXTCPFramesMultiFrameCoalescesDescriptors(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TX_MULTI_FRAME", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TX_MULTI_FRAME_MAX_FRAMES", "4")

	txProducer := uint32(0)
	txConsumer := uint32(0)
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	socket := &afXDPSocket{
		fd:                     fds[0],
		linkMAC:                net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		umem:                   make([]byte, 3*tixTCPDefaultUMEMFrameSize),
		umemFrameSize:          tixTCPDefaultUMEMFrameSize,
		txFree:                 []uint64{0, tixTCPDefaultUMEMFrameSize},
		txKickBatch:            1024,
		txBackpressurePoll:     time.Millisecond,
		txMultiFrameMaxFrames:  tixTCPTXMultiFrameMaxFrames(),
		txMultiFrameMaxIPv4Len: tixTCPTXMultiFrameMaxIPv4Len(),
		tx: xdpDescRing{
			producer: &txProducer,
			consumer: &txConsumer,
			descs:    make([]unix.XDPDesc, 4),
			size:     4,
			mask:     3,
		},
	}
	packet := tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.1"),
		DestinationIP:   netip.MustParseAddr("198.51.100.2"),
		SourcePort:      40000,
		DestinationPort: 9443,
		Acknowledgment:  1,
	}
	items := []preparedTIXTCPTXFrame{
		{packet: packet, wireFrame: tixtcp.Frame{FlowID: 7, Epoch: 9, Sequence: 1, Payload: []byte("one")}},
		{packet: func() tixtcp.TCPPacket {
			packet := packet
			packet.Acknowledgment = 99
			return packet
		}(), wireFrame: tixtcp.Frame{FlowID: 7, Epoch: 9, Sequence: 2, Payload: []byte("two")}},
	}

	if err := socket.SendPreparedFrames(items, net.HardwareAddr{0x02, 0, 0, 0, 0, 2}); err != nil {
		t.Fatalf("SendPreparedFrames error = %v", err)
	}
	if got := atomic.LoadUint32(&txProducer); got != 1 {
		t.Fatalf("tx producer = %d, want 1", got)
	}
	if got := socket.stats.txBatchSubmissions.Load(); got != 1 {
		t.Fatalf("tx batch submissions = %d, want 1", got)
	}
	if got := socket.stats.txBatchFrames.Load(); got != 1 {
		t.Fatalf("tx batch frames = %d, want 1 descriptor", got)
	}
	if got := socket.stats.txMultiFrameBatches.Load(); got != 1 {
		t.Fatalf("tx multi-frame batches = %d, want 1", got)
	}
	if got := socket.stats.txMultiFrameInputFrames.Load(); got != 2 {
		t.Fatalf("tx multi-frame input frames = %d, want 2", got)
	}

	desc := socket.tx.descs[0]
	start := int(desc.Addr)
	end := start + int(desc.Len)
	if end > len(socket.umem) {
		t.Fatalf("desc out of bounds: %#v", desc)
	}
	wire := socket.umem[start+ethernetHeaderLen : end]
	packet, err = tixtcp.ParseTCPShapedIPv4NoCopy(wire)
	if err != nil {
		t.Fatalf("parse tix_tcp packet: %v", err)
	}
	if packet.Acknowledgment != items[0].packet.Acknowledgment {
		t.Fatalf("packet acknowledgment = %d, want first frame acknowledgment %d", packet.Acknowledgment, items[0].packet.Acknowledgment)
	}
	cursor := packet.Payload
	for i, item := range items {
		frameLen := tixtcp.HeaderLen + len(item.wireFrame.Payload)
		frame, err := tixtcp.ParseFrameNoCopy(cursor[:frameLen])
		if err != nil {
			t.Fatalf("parse TIXT %d: %v", i, err)
		}
		if frame.Sequence != item.wireFrame.Sequence || !bytes.Equal(frame.Payload, item.wireFrame.Payload) {
			t.Fatalf("frame %d = %#v, want %#v", i, frame, item.wireFrame)
		}
		cursor = cursor[frameLen:]
	}
	if len(cursor) != 0 {
		t.Fatalf("multi-frame payload has %d trailing bytes", len(cursor))
	}
}

func TestAFXDPSendPreparedTIXTCPFramesMultiFrameCoalescesUserspaceFragments(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TX_MULTI_FRAME", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TX_MULTI_FRAME_MAX_FRAMES", "4")
	t.Setenv("TRUSTIX_TIX_TCP_TX_MULTI_FRAME_MAX_IPV4_LEN", "4096")

	txProducer := uint32(0)
	txConsumer := uint32(0)
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	socket := &afXDPSocket{
		fd:                     fds[0],
		linkMAC:                net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		umem:                   make([]byte, 3*tixTCPDefaultUMEMFrameSize),
		umemFrameSize:          tixTCPDefaultUMEMFrameSize,
		txFree:                 []uint64{0, tixTCPDefaultUMEMFrameSize},
		txKickBatch:            1024,
		txBackpressurePoll:     time.Millisecond,
		txMultiFrameMaxFrames:  tixTCPTXMultiFrameMaxFrames(),
		txMultiFrameMaxIPv4Len: tixTCPTXMultiFrameMaxIPv4Len(),
		tx: xdpDescRing{
			producer: &txProducer,
			consumer: &txConsumer,
			descs:    make([]unix.XDPDesc, 4),
			size:     4,
			mask:     3,
		},
	}
	packet := tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.1"),
		DestinationIP:   netip.MustParseAddr("198.51.100.2"),
		SourcePort:      40000,
		DestinationPort: 9443,
		Acknowledgment:  1,
	}
	payloads := [][]byte{
		append([]byte{'T', 'I', 'X', 'D'}, bytes.Repeat([]byte{0xa5}, 256)...),
		bytes.Repeat([]byte{0xb6}, 260),
		bytes.Repeat([]byte{0xc7}, 260),
	}
	items := make([]preparedTIXTCPTXFrame, len(payloads))
	nextSeq := uint32(0)
	for i, payload := range payloads {
		itemPacket := packet
		itemPacket.Sequence = nextSeq
		frameLen := tixtcp.HeaderLen + len(payload)
		nextSeq += uint32(frameLen)
		items[i] = preparedTIXTCPTXFrame{
			packet: itemPacket,
			wireFrame: tixtcp.Frame{
				FlowID:        7,
				Epoch:         9,
				Sequence:      uint64(100 + i),
				FragmentIndex: uint16(i),
				FragmentCount: uint16(len(payloads)),
				Payload:       append([]byte(nil), payload...),
			},
		}
	}

	if err := socket.SendPreparedFrames(items, net.HardwareAddr{0x02, 0, 0, 0, 0, 2}); err != nil {
		t.Fatalf("SendPreparedFrames error = %v", err)
	}
	if got := atomic.LoadUint32(&txProducer); got != 1 {
		t.Fatalf("tx producer = %d, want 1", got)
	}
	if got := socket.stats.txMultiFrameBatches.Load(); got != 1 {
		t.Fatalf("tx multi-frame batches = %d, want 1", got)
	}
	if got := socket.stats.txMultiFrameRejectFragment.Load(); got != 0 {
		t.Fatalf("tx multi-frame fragment rejects = %d, want 0", got)
	}

	desc := socket.tx.descs[0]
	wire := socket.umem[int(desc.Addr)+ethernetHeaderLen : int(desc.Addr)+int(desc.Len)]
	packetOut, err := tixtcp.ParseTCPShapedIPv4NoCopy(wire)
	if err != nil {
		t.Fatalf("parse tix_tcp packet: %v", err)
	}
	frames, err := tixtcp.ParseFrameStreamNoCopy(packetOut.Payload)
	if err != nil {
		t.Fatalf("parse TIXT stream: %v", err)
	}
	if len(frames) != len(items) {
		t.Fatalf("frame count = %d, want %d", len(frames), len(items))
	}
	for i, frame := range frames {
		want := items[i].wireFrame
		if frame.Sequence != want.Sequence ||
			frame.FragmentIndex != want.FragmentIndex ||
			frame.FragmentCount != want.FragmentCount ||
			!bytes.Equal(frame.Payload, want.Payload) {
			t.Fatalf("frame %d = %#v, want %#v", i, frame, want)
		}
	}
}

func TestAFXDPSendPreparedTIXTCPFramesMultiFrameClampsToLinkMTU(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TX_MULTI_FRAME", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TX_MULTI_FRAME_MAX_FRAMES", "4")
	t.Setenv("TRUSTIX_TIX_TCP_TX_MULTI_FRAME_MAX_IPV4_LEN", "4096")

	txProducer := uint32(0)
	txConsumer := uint32(0)
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	socket := &afXDPSocket{
		fd:                     fds[0],
		linkMAC:                net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		linkMTU:                1500,
		umem:                   make([]byte, 3*tixTCPDefaultUMEMFrameSize),
		umemFrameSize:          tixTCPDefaultUMEMFrameSize,
		txFree:                 []uint64{0, tixTCPDefaultUMEMFrameSize},
		txKickBatch:            1024,
		txBackpressurePoll:     time.Millisecond,
		txMultiFrameMaxFrames:  tixTCPTXMultiFrameMaxFrames(),
		txMultiFrameMaxIPv4Len: tixTCPTXMultiFrameMaxIPv4Len(),
		tx: xdpDescRing{
			producer: &txProducer,
			consumer: &txConsumer,
			descs:    make([]unix.XDPDesc, 4),
			size:     4,
			mask:     3,
		},
	}
	packet := tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.1"),
		DestinationIP:   netip.MustParseAddr("198.51.100.2"),
		SourcePort:      40000,
		DestinationPort: 9443,
		Acknowledgment:  1,
	}
	payloads := [][]byte{
		append([]byte{'T', 'I', 'X', 'D'}, bytes.Repeat([]byte{0xa5}, 1180)...),
		bytes.Repeat([]byte{0xb6}, 1184),
	}
	items := make([]preparedTIXTCPTXFrame, len(payloads))
	nextSeq := uint32(0)
	for i, payload := range payloads {
		itemPacket := packet
		itemPacket.Sequence = nextSeq
		frameLen := tixtcp.HeaderLen + len(payload)
		nextSeq += uint32(frameLen)
		items[i] = preparedTIXTCPTXFrame{
			packet: itemPacket,
			wireFrame: tixtcp.Frame{
				FlowID:        7,
				Epoch:         9,
				Sequence:      uint64(100 + i),
				FragmentIndex: uint16(i),
				FragmentCount: uint16(len(payloads)),
				Payload:       append([]byte(nil), payload...),
			},
		}
	}

	if err := socket.SendPreparedFrames(items, net.HardwareAddr{0x02, 0, 0, 0, 0, 2}); err != nil {
		t.Fatalf("SendPreparedFrames error = %v", err)
	}
	if got := atomic.LoadUint32(&txProducer); got != 2 {
		t.Fatalf("tx producer = %d, want 2 descriptors", got)
	}
	if got := socket.stats.txMultiFrameBatches.Load(); got != 0 {
		t.Fatalf("tx multi-frame batches = %d, want 0", got)
	}
	if got := socket.stats.txMultiFrameRejectMTU.Load(); got != 1 {
		t.Fatalf("tx multi-frame MTU rejects = %d, want 1", got)
	}
	for i := range items {
		desc := socket.tx.descs[i]
		if int(desc.Len) > socket.linkMTU+ethernetHeaderLen {
			t.Fatalf("descriptor %d length = %d, want <= %d", i, desc.Len, socket.linkMTU+ethernetHeaderLen)
		}
	}
}

func TestAFXDPSendPreparedTIXTCPFramesEncryptedMultiFrameOptIn(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_TX_SOCKET_GSO", "0")
	newSocket := func(t *testing.T) (*afXDPSocket, *uint32) {
		t.Helper()
		txProducer := new(uint32)
		txConsumer := new(uint32)
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("socketpair: %v", err)
		}
		t.Cleanup(func() {
			unix.Close(fds[0])
			unix.Close(fds[1])
		})
		socket := &afXDPSocket{
			fd:                     fds[0],
			linkMAC:                net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
			umem:                   make([]byte, 3*tixTCPDefaultUMEMFrameSize),
			umemFrameSize:          tixTCPDefaultUMEMFrameSize,
			txFree:                 []uint64{0, tixTCPDefaultUMEMFrameSize},
			txKickBatch:            1024,
			txBackpressurePoll:     time.Millisecond,
			txMultiFrameMaxFrames:  tixTCPTXMultiFrameMaxFrames(),
			txMultiFrameMaxIPv4Len: tixTCPTXMultiFrameMaxIPv4Len(),
			txMultiFrameEncrypted:  tixTCPTXMultiFrameEncryptedEnabled(),
			tx: xdpDescRing{
				producer: txProducer,
				consumer: txConsumer,
				descs:    make([]unix.XDPDesc, 4),
				size:     4,
				mask:     3,
			},
		}
		return socket, txProducer
	}
	packet := tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.1"),
		DestinationIP:   netip.MustParseAddr("198.51.100.2"),
		SourcePort:      40000,
		DestinationPort: 9443,
		Acknowledgment:  1,
	}
	items := []preparedTIXTCPTXFrame{
		{packet: packet, wireFrame: tixtcp.Frame{Flags: tixtcp.FlagEncrypted | tixtcp.FlagInnerIPv4, FlowID: 7, Epoch: 9, Sequence: 1, Payload: []byte("cipher-one")}},
		{packet: func() tixtcp.TCPPacket {
			packet := packet
			packet.Sequence = uint32(tixtcp.HeaderLen + len("cipher-one"))
			return packet
		}(), wireFrame: tixtcp.Frame{Flags: tixtcp.FlagEncrypted | tixtcp.FlagInnerIPv4, FlowID: 7, Epoch: 9, Sequence: 2, Payload: []byte("cipher-two")}},
	}

	t.Run("default keeps encrypted frames separate", func(t *testing.T) {
		t.Setenv("TRUSTIX_TIX_TCP_TX_MULTI_FRAME", "1")
		t.Setenv("TRUSTIX_TIX_TCP_TX_MULTI_FRAME_MAX_FRAMES", "4")
		socket, txProducer := newSocket(t)
		if err := socket.SendPreparedFrames(items, net.HardwareAddr{0x02, 0, 0, 0, 0, 2}); err != nil {
			t.Fatalf("SendPreparedFrames error = %v", err)
		}
		if got := atomic.LoadUint32(txProducer); got != 2 {
			t.Fatalf("tx producer = %d, want 2", got)
		}
		if got := socket.stats.txMultiFrameBatches.Load(); got != 0 {
			t.Fatalf("tx multi-frame batches = %d, want 0", got)
		}
	})

	t.Run("opt in coalesces encrypted frames", func(t *testing.T) {
		t.Setenv("TRUSTIX_TIX_TCP_TX_MULTI_FRAME", "1")
		t.Setenv("TRUSTIX_TIX_TCP_TX_MULTI_FRAME_ENCRYPTED", "1")
		t.Setenv("TRUSTIX_TIX_TCP_TX_MULTI_FRAME_MAX_FRAMES", "4")
		socket, txProducer := newSocket(t)
		if err := socket.SendPreparedFrames(items, net.HardwareAddr{0x02, 0, 0, 0, 0, 2}); err != nil {
			t.Fatalf("SendPreparedFrames error = %v", err)
		}
		if got := atomic.LoadUint32(txProducer); got != 1 {
			t.Fatalf("tx producer = %d, want 1", got)
		}
		if got := socket.stats.txMultiFrameBatches.Load(); got != 1 {
			t.Fatalf("tx multi-frame batches = %d, want 1", got)
		}
		desc := socket.tx.descs[0]
		start := int(desc.Addr)
		end := start + int(desc.Len)
		if end > len(socket.umem) {
			t.Fatalf("desc out of bounds: %#v", desc)
		}
		wire := socket.umem[start+ethernetHeaderLen : end]
		packet, err := tixtcp.ParseTCPShapedIPv4NoCopy(wire)
		if err != nil {
			t.Fatalf("parse tix_tcp packet: %v", err)
		}
		frames, err := tixtcp.ParseFrameStreamNoCopy(packet.Payload)
		if err != nil {
			t.Fatalf("parse TIXT stream: %v", err)
		}
		if len(frames) != len(items) {
			t.Fatalf("frame count = %d, want %d", len(frames), len(items))
		}
		for i, frame := range frames {
			want := items[i].wireFrame
			if frame.Flags != want.Flags || frame.Sequence != want.Sequence || !bytes.Equal(frame.Payload, want.Payload) {
				t.Fatalf("frame %d = %#v, want %#v", i, frame, want)
			}
		}
	})
}

func TestPreparedTIXTCPSocketGSOGroupCoalescesEncryptedFragments(t *testing.T) {
	packet := tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.1"),
		DestinationIP:   netip.MustParseAddr("198.51.100.2"),
		SourcePort:      40000,
		DestinationPort: 9443,
		Acknowledgment:  1,
		Sequence:        1000,
	}
	payload := []byte("cipher-fragment")
	frameLen := tixtcp.HeaderLen + len(payload)
	items := make([]preparedTIXTCPTXFrame, 3)
	for i := range items {
		itemPacket := packet
		itemPacket.Sequence += uint32(i * frameLen)
		items[i] = preparedTIXTCPTXFrame{
			packet: itemPacket,
			wireFrame: tixtcp.Frame{
				Flags:         tixtcp.FlagEncrypted | tixtcp.FlagCryptoFragment | tixtcp.FlagInnerIPv4,
				FlowID:        7,
				Epoch:         9,
				Sequence:      uint64(i + 1),
				FragmentIndex: uint16(i),
				FragmentCount: uint16(len(items)),
				Payload:       append([]byte(nil), payload...),
			},
		}
	}

	group, err := preparedTIXTCPSocketGSOGroupWithReason(items, 1460, 8, 0xffff)
	if err != nil {
		t.Fatalf("group encrypted fragments: %v", err)
	}
	if group.groupLen != len(items) {
		t.Fatalf("group len = %d, want %d reject=%d", group.groupLen, len(items), group.reject)
	}
	if group.frameLen != frameLen {
		t.Fatalf("frame len = %d, want %d", group.frameLen, frameLen)
	}
	if group.packetLen != 20+20+len(items)*frameLen {
		t.Fatalf("packet len = %d, want %d", group.packetLen, 20+20+len(items)*frameLen)
	}
}

func TestPreparedTIXTCPSocketGSOGroupCoalescesUserspaceSecurePayloads(t *testing.T) {
	packet := tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.1"),
		DestinationIP:   netip.MustParseAddr("198.51.100.2"),
		SourcePort:      40000,
		DestinationPort: 9443,
		Acknowledgment:  1,
		Sequence:        3000,
	}
	payload := append([]byte{'T', 'I', 'X', 'D'}, bytes.Repeat([]byte{0xa5}, 96)...)
	frameLen := tixtcp.HeaderLen + len(payload)
	items := make([]preparedTIXTCPTXFrame, 4)
	for i := range items {
		itemPacket := packet
		itemPacket.Sequence += uint32(i * frameLen)
		items[i] = preparedTIXTCPTXFrame{
			packet: itemPacket,
			wireFrame: tixtcp.Frame{
				FlowID:   7,
				Epoch:    9,
				Sequence: uint64(i + 1),
				Payload:  append([]byte(nil), payload...),
			},
		}
	}

	group, err := preparedTIXTCPSocketGSOGroupWithReason(items, 1460, 8, 0xffff)
	if err != nil {
		t.Fatalf("group userspace secure payloads: %v", err)
	}
	if group.groupLen != len(items) {
		t.Fatalf("group len = %d, want %d reject=%d", group.groupLen, len(items), group.reject)
	}
}

func TestPreparedTIXTCPSocketGSOGroupCoalescesUserspaceSecureFragments(t *testing.T) {
	packet := tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.1"),
		DestinationIP:   netip.MustParseAddr("198.51.100.2"),
		SourcePort:      40000,
		DestinationPort: 9443,
		Acknowledgment:  1,
		Sequence:        9000,
	}
	payloads := [][]byte{
		append([]byte{'T', 'I', 'X', 'D'}, bytes.Repeat([]byte{0xa5}, 116)...),
		bytes.Repeat([]byte{0xb6}, 120),
		bytes.Repeat([]byte{0xc7}, 120),
	}
	frameLen := tixtcp.HeaderLen + len(payloads[0])
	items := make([]preparedTIXTCPTXFrame, len(payloads))
	for i := range items {
		itemPacket := packet
		itemPacket.Sequence += uint32(i * frameLen)
		items[i] = preparedTIXTCPTXFrame{
			packet: itemPacket,
			wireFrame: tixtcp.Frame{
				FlowID:        7,
				Epoch:         9,
				Sequence:      uint64(i + 1),
				FragmentIndex: uint16(i),
				FragmentCount: uint16(len(items)),
				Payload:       append([]byte(nil), payloads[i]...),
			},
		}
	}

	group, err := preparedTIXTCPSocketGSOGroupWithReason(items, 1460, 8, 0xffff)
	if err != nil {
		t.Fatalf("group userspace secure fragments: %v", err)
	}
	if group.groupLen != len(items) {
		t.Fatalf("group len = %d, want %d reject=%d", group.groupLen, len(items), group.reject)
	}
}

func TestPreparedTIXTCPSocketGSOGroupRejectsSequenceAndLengthMismatch(t *testing.T) {
	packet := tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.1"),
		DestinationIP:   netip.MustParseAddr("198.51.100.2"),
		SourcePort:      40000,
		DestinationPort: 9443,
		Acknowledgment:  1,
		Sequence:        500,
	}
	payload := []byte("cipher")
	frameLen := tixtcp.HeaderLen + len(payload)
	first := preparedTIXTCPTXFrame{
		packet: packet,
		wireFrame: tixtcp.Frame{
			Flags:    tixtcp.FlagEncrypted | tixtcp.FlagInnerIPv4,
			FlowID:   7,
			Epoch:    9,
			Sequence: 1,
			Payload:  append([]byte(nil), payload...),
		},
	}
	second := first
	second.packet.Sequence += uint32(frameLen + 1)
	second.wireFrame.Sequence = 2
	group, err := preparedTIXTCPSocketGSOGroupWithReason([]preparedTIXTCPTXFrame{first, second}, 1460, 8, 0xffff)
	if err != nil {
		t.Fatalf("sequence mismatch group: %v", err)
	}
	if group.groupLen != 1 || group.reject != preparedTIXTCPSocketGSORejectSequence {
		t.Fatalf("sequence mismatch group = %#v, want singleton sequence reject", group)
	}

	second = first
	second.packet.Sequence += uint32(frameLen)
	second.wireFrame.Sequence = 2
	second.wireFrame.Payload = []byte("different-length")
	group, err = preparedTIXTCPSocketGSOGroupWithReason([]preparedTIXTCPTXFrame{first, second}, 1460, 8, 0xffff)
	if err != nil {
		t.Fatalf("length mismatch group: %v", err)
	}
	if group.groupLen != 1 || group.reject != preparedTIXTCPSocketGSORejectFrameLen {
		t.Fatalf("length mismatch group = %#v, want singleton frame-len reject", group)
	}
}

func TestMarshalPreparedTIXTCPSocketGSOIPv4FrameStream(t *testing.T) {
	packet := tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.1"),
		DestinationIP:   netip.MustParseAddr("198.51.100.2"),
		SourcePort:      40000,
		DestinationPort: 9443,
		Acknowledgment:  1,
		Sequence:        700,
	}
	payload := []byte("cipher-text")
	frameLen := tixtcp.HeaderLen + len(payload)
	items := make([]preparedTIXTCPTXFrame, 3)
	for i := range items {
		itemPacket := packet
		itemPacket.Sequence += uint32(i * frameLen)
		items[i] = preparedTIXTCPTXFrame{
			packet: itemPacket,
			wireFrame: tixtcp.Frame{
				Flags:    tixtcp.FlagEncrypted | tixtcp.FlagInnerIPv4,
				FlowID:   7,
				Epoch:    9,
				Sequence: uint64(i + 1),
				Payload:  append([]byte(nil), payload...),
			},
		}
	}
	group, err := preparedTIXTCPSocketGSOGroupWithReason(items, 1460, 8, 0xffff)
	if err != nil {
		t.Fatalf("group: %v", err)
	}
	wire := make([]byte, group.packetLen)
	if err := marshalPreparedTIXTCPSocketGSOIPv4Into(items, wire); err != nil {
		t.Fatalf("marshal socket GSO packet: %v", err)
	}
	packetOut, err := tixtcp.ParseTCPShapedIPv4NoCopySkipTCPChecksum(wire)
	if err != nil {
		t.Fatalf("parse socket GSO packet: %v", err)
	}
	if packetOut.Sequence != packet.Sequence {
		t.Fatalf("outer sequence = %d, want %d", packetOut.Sequence, packet.Sequence)
	}
	if got, want := binary.BigEndian.Uint16(wire[20+16:20+18]), tcpPseudoHeaderPartialChecksum(wire, len(wire)-20); got != want {
		t.Fatalf("partial TCP checksum = %#x, want %#x", got, want)
	}
	frames, err := tixtcp.ParseFrameStreamNoCopy(packetOut.Payload)
	if err != nil {
		t.Fatalf("parse TIXT stream: %v", err)
	}
	if len(frames) != len(items) {
		t.Fatalf("frame count = %d, want %d", len(frames), len(items))
	}
	for i, frame := range frames {
		if frame.Sequence != items[i].wireFrame.Sequence || !bytes.Equal(frame.Payload, items[i].wireFrame.Payload) {
			t.Fatalf("frame %d = %#v, want %#v", i, frame, items[i].wireFrame)
		}
	}
	virtio := make([]byte, virtioNetHdrLen)
	if err := preparePreparedTIXTCPSocketGSOVirtioHeader(virtio, frameLen); err != nil {
		t.Fatalf("prepare virtio header: %v", err)
	}
	if got := binary.LittleEndian.Uint16(virtio[4:6]); int(got) != frameLen {
		t.Fatalf("gso size = %d, want %d", got, frameLen)
	}
}

func testMinimalIPv4Payload(totalLen int) []byte {
	if totalLen < 20 {
		totalLen = 20
	}
	payload := make([]byte, totalLen)
	payload[0] = 0x45
	binary.BigEndian.PutUint16(payload[2:4], uint16(totalLen))
	return payload
}

type recordingTIXTCPSealer struct {
	inputs [][]byte
}

func (sealer *recordingTIXTCPSealer) SealEthernetInPlace(frame []byte, length int) (int, error) {
	sealer.inputs = append(sealer.inputs, append([]byte(nil), frame[:length]...))
	copy(frame[length:length+tixTCPKernelCryptoOverhead], bytes.Repeat([]byte{0xa5}, tixTCPKernelCryptoOverhead))
	return length + tixTCPKernelCryptoOverhead, nil
}

func TestAFXDPSendPreparedKernelCryptoFramesBatchesDescriptors(t *testing.T) {
	txProducer := uint32(0)
	txConsumer := uint32(0)
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	socket := &afXDPSocket{
		fd:                 fds[0],
		linkMAC:            net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		umem:               make([]byte, 3*tixTCPDefaultUMEMFrameSize),
		umemFrameSize:      tixTCPDefaultUMEMFrameSize,
		txFree:             []uint64{0, tixTCPDefaultUMEMFrameSize},
		txKickBatch:        1024,
		skipTCPChecksum:    true,
		txBackpressurePoll: time.Millisecond,
		tx: xdpDescRing{
			producer: &txProducer,
			consumer: &txConsumer,
			descs:    make([]unix.XDPDesc, 4),
			size:     4,
			mask:     3,
		},
	}
	packet := tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.1"),
		DestinationIP:   netip.MustParseAddr("198.51.100.2"),
		SourcePort:      40000,
		DestinationPort: 9443,
		Acknowledgment:  1,
	}
	items := []preparedTIXTCPTXFrame{
		{packet: packet, wireFrame: tixtcp.Frame{FlowID: 7, Epoch: 9, Sequence: 1, Payload: []byte("one")}},
		{packet: func() tixtcp.TCPPacket {
			packet := packet
			packet.Sequence = uint32(tixtcp.HeaderLen + len("one"))
			return packet
		}(), wireFrame: tixtcp.Frame{FlowID: 7, Epoch: 9, Sequence: 2, Payload: []byte("two")}},
	}
	sealer := &recordingTIXTCPSealer{}

	if err := socket.publishPreparedKernelCryptoFrameBatchLocked(items, net.HardwareAddr{0x02, 0, 0, 0, 0, 2}, sealer); err != nil {
		t.Fatalf("publishPreparedKernelCryptoFrameBatchLocked error = %v", err)
	}
	if got := atomic.LoadUint32(&txProducer); got != 2 {
		t.Fatalf("tx producer = %d, want 2", got)
	}
	if got := socket.stats.txBatchSubmissions.Load(); got != 1 {
		t.Fatalf("tx batch submissions = %d, want 1", got)
	}
	if got := socket.stats.txBatchFrames.Load(); got != 2 {
		t.Fatalf("tx batch frames = %d, want 2", got)
	}
	if len(sealer.inputs) != 2 {
		t.Fatalf("sealed inputs = %d, want 2", len(sealer.inputs))
	}
	for i, item := range items {
		desc := socket.tx.descs[i]
		if got, want := int(desc.Len), len(sealer.inputs[i])+tixTCPKernelCryptoOverhead; got != want {
			t.Fatalf("desc %d len = %d, want %d", i, got, want)
		}
		wire := sealer.inputs[i][ethernetHeaderLen:]
		packet, err := tixtcp.ParseTCPShapedIPv4NoCopySkipTCPChecksum(wire)
		if err != nil {
			t.Fatalf("parse tix_tcp packet %d: %v", i, err)
		}
		frame, err := tixtcp.ParseFrameNoCopy(packet.Payload)
		if err != nil {
			t.Fatalf("parse TIXT %d: %v", i, err)
		}
		if packet.Sequence != item.packet.Sequence {
			t.Fatalf("packet sequence %d = %d, want %d", i, packet.Sequence, item.packet.Sequence)
		}
		if frame.Sequence != item.wireFrame.Sequence || !bytes.Equal(frame.Payload, item.wireFrame.Payload) {
			t.Fatalf("frame %d = %#v, want %#v", i, frame, item.wireFrame)
		}
		if got := binary.BigEndian.Uint16(wire[36:38]); got != 0 {
			t.Fatalf("TCP checksum = %#x, want 0", got)
		}
	}
}

func TestAFXDPSendPreparedUDPFramesBatchesDescriptors(t *testing.T) {
	txProducer := uint32(0)
	txConsumer := uint32(0)
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	socket := &afXDPSocket{
		fd:                 fds[0],
		linkMAC:            net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		umem:               make([]byte, 3*tixTCPDefaultUMEMFrameSize),
		umemFrameSize:      tixTCPDefaultUMEMFrameSize,
		txFree:             []uint64{0, tixTCPDefaultUMEMFrameSize},
		txKickBatch:        1024,
		skipUDPChecksum:    true,
		txBackpressurePoll: time.Millisecond,
		tx: xdpDescRing{
			producer: &txProducer,
			consumer: &txConsumer,
			descs:    make([]unix.XDPDesc, 4),
			size:     4,
			mask:     3,
		},
	}
	packet := kerneludp.UDPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.1"),
		DestinationIP:   netip.MustParseAddr("198.51.100.2"),
		SourcePort:      40000,
		DestinationPort: 9443,
	}
	items := []preparedKernelUDPTXFrame{
		preparedKernelUDPFrameForTest(t, packet, kerneludp.Frame{FlowID: 7, Sequence: 1, Payload: []byte("one")}),
		preparedKernelUDPFrameForTest(t, packet, kerneludp.Frame{FlowID: 7, Sequence: 2, Payload: []byte("two")}),
	}

	if err := socket.SendPreparedUDPFrames(items, net.HardwareAddr{0x02, 0, 0, 0, 0, 2}); err != nil {
		t.Fatalf("SendPreparedUDPFrames error = %v", err)
	}
	if got := atomic.LoadUint32(&txProducer); got != 2 {
		t.Fatalf("tx producer = %d, want 2", got)
	}
	if got := socket.stats.txBatchSubmissions.Load(); got != 1 {
		t.Fatalf("tx batch submissions = %d, want 1", got)
	}
	if got := socket.stats.txBatchFrames.Load(); got != 2 {
		t.Fatalf("tx batch frames = %d, want 2", got)
	}
	for i, item := range items {
		desc := socket.tx.descs[i]
		start := int(desc.Addr)
		end := start + int(desc.Len)
		if end > len(socket.umem) {
			t.Fatalf("desc %d out of bounds: %#v", i, desc)
		}
		wire := socket.umem[start+ethernetHeaderLen : end]
		packet, err := kerneludp.ParseUDPIPv4NoCopy(wire)
		if err != nil {
			t.Fatalf("parse UDP %d: %v", i, err)
		}
		frame, err := kerneludp.ParseFrameNoCopy(packet.Payload)
		if err != nil {
			t.Fatalf("parse TIXU %d: %v", i, err)
		}
		if frame.Sequence != item.wireFrame.Sequence || !bytes.Equal(frame.Payload, item.wireFrame.Payload) {
			t.Fatalf("frame %d = %#v, want %#v", i, frame, item.wireFrame)
		}
		if got := binary.BigEndian.Uint16(wire[26:28]); got != 0 {
			t.Fatalf("UDP checksum = %#x, want 0", got)
		}
	}
}

func TestKernelUDPFallbackFrameGSOGroups(t *testing.T) {
	packet := kerneludp.UDPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.1"),
		DestinationIP:   netip.MustParseAddr("198.51.100.2"),
		SourcePort:      40000,
		DestinationPort: 9443,
	}
	items := []preparedKernelUDPTXFrame{
		preparedKernelUDPFrameForTest(t, packet, kerneludp.Frame{FlowID: 7, Sequence: 1, Payload: []byte("aaa")}),
		preparedKernelUDPFrameForTest(t, packet, kerneludp.Frame{FlowID: 7, Sequence: 2, Payload: []byte("bbb")}),
		preparedKernelUDPFrameForTest(t, packet, kerneludp.Frame{FlowID: 7, Sequence: 3, Payload: []byte("ccc")}),
	}
	groups, totalBytes, ok, err := kernelUDPUDPFallbackFrameGSOGroups(items, 64)
	if err != nil {
		t.Fatalf("group frames: %v", err)
	}
	if !ok || groups != 1 {
		t.Fatalf("groups ok=%v count=%d, want one group", ok, groups)
	}
	if got, want := totalBytes, items[0].frameWireLen*len(items); got != want {
		t.Fatalf("total bytes = %d, want %d", got, want)
	}
	if got := kernelUDPUDPFallbackFramesForGroups(items, 64, 1); got != len(items) {
		t.Fatalf("frames for one group = %d, want %d", got, len(items))
	}
	end, groups, runBytes, runOK, err := kernelUDPUDPFallbackFrameGSOGroupRunEnd(items, 0, 64)
	if err != nil {
		t.Fatalf("group run: %v", err)
	}
	if !runOK || end != len(items) || groups != 1 || runBytes != totalBytes {
		t.Fatalf("run end=%d groups=%d bytes=%d ok=%v, want end=%d groups=1 bytes=%d ok=true", end, groups, runBytes, runOK, len(items), totalBytes)
	}
}

func TestKernelUDPFallbackFrameGSOGroupsRejectsMixedLengths(t *testing.T) {
	packet := kerneludp.UDPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.1"),
		DestinationIP:   netip.MustParseAddr("198.51.100.2"),
		SourcePort:      40000,
		DestinationPort: 9443,
	}
	items := []preparedKernelUDPTXFrame{
		preparedKernelUDPFrameForTest(t, packet, kerneludp.Frame{FlowID: 7, Sequence: 1, Payload: []byte("aaa")}),
		preparedKernelUDPFrameForTest(t, packet, kerneludp.Frame{FlowID: 7, Sequence: 2, Payload: []byte("longer")}),
	}
	if groups, _, ok, err := kernelUDPUDPFallbackFrameGSOGroups(items, 64); err != nil || ok || groups != 0 {
		t.Fatalf("mixed length groups=%d ok=%v err=%v, want no GSO group", groups, ok, err)
	}
	hasGroup, err := kernelUDPUDPFallbackHasFrameGSOGroup(items, 64)
	if err != nil {
		t.Fatalf("has GSO group: %v", err)
	}
	if hasGroup {
		t.Fatal("mixed two-frame batch should not have a GSO group")
	}
}

func TestKernelUDPFallbackHasFrameGSOGroupAllowsMixedBatch(t *testing.T) {
	packet := kerneludp.UDPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.1"),
		DestinationIP:   netip.MustParseAddr("198.51.100.2"),
		SourcePort:      40000,
		DestinationPort: 9443,
	}
	items := []preparedKernelUDPTXFrame{
		preparedKernelUDPFrameForTest(t, packet, kerneludp.Frame{FlowID: 7, Sequence: 1, Payload: []byte("control")}),
		preparedKernelUDPFrameForTest(t, packet, kerneludp.Frame{FlowID: 7, Sequence: 2, Payload: []byte("aaa")}),
		preparedKernelUDPFrameForTest(t, packet, kerneludp.Frame{FlowID: 7, Sequence: 3, Payload: []byte("bbb")}),
		preparedKernelUDPFrameForTest(t, packet, kerneludp.Frame{FlowID: 7, Sequence: 4, Payload: []byte("tail")}),
	}

	hasGroup, err := kernelUDPUDPFallbackHasFrameGSOGroup(items, 64)
	if err != nil {
		t.Fatalf("has GSO group: %v", err)
	}
	if !hasGroup {
		t.Fatal("mixed batch with a contiguous equal-length run should have a GSO group")
	}
	end, groups, _, runOK, err := kernelUDPUDPFallbackFrameGSOGroupRunEnd(items, 1, 64)
	if err != nil {
		t.Fatalf("group run: %v", err)
	}
	if !runOK || end != 3 || groups != 1 {
		t.Fatalf("run from first equal-length frame end=%d groups=%d ok=%v, want end=3 groups=1 ok=true", end, groups, runOK)
	}
	if end, groups, _, runOK, err := kernelUDPUDPFallbackFrameGSOGroupRunEnd(items, 0, 64); err != nil || runOK || end != 0 || groups != 0 {
		t.Fatalf("run from non-GSO prefix end=%d groups=%d ok=%v err=%v, want no run at 0", end, groups, runOK, err)
	}
}

func TestKernelUDPFallbackFrameGSOGroupRunCombinesMultipleGroups(t *testing.T) {
	packet := kerneludp.UDPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.1"),
		DestinationIP:   netip.MustParseAddr("198.51.100.2"),
		SourcePort:      40000,
		DestinationPort: 9443,
	}
	items := []preparedKernelUDPTXFrame{
		preparedKernelUDPFrameForTest(t, packet, kerneludp.Frame{FlowID: 7, Sequence: 1, Payload: []byte("aaa")}),
		preparedKernelUDPFrameForTest(t, packet, kerneludp.Frame{FlowID: 7, Sequence: 2, Payload: []byte("bbb")}),
		preparedKernelUDPFrameForTest(t, packet, kerneludp.Frame{FlowID: 7, Sequence: 3, Payload: []byte("ccc")}),
		preparedKernelUDPFrameForTest(t, packet, kerneludp.Frame{FlowID: 7, Sequence: 4, Payload: []byte("ddd")}),
		preparedKernelUDPFrameForTest(t, packet, kerneludp.Frame{FlowID: 7, Sequence: 5, Payload: []byte("tail")}),
	}
	end, groups, totalBytes, ok, err := kernelUDPUDPFallbackFrameGSOGroupRunEnd(items, 0, 2)
	if err != nil {
		t.Fatalf("group run: %v", err)
	}
	if !ok || end != 4 || groups != 2 {
		t.Fatalf("run end=%d groups=%d ok=%v, want end=4 groups=2 ok=true", end, groups, ok)
	}
	wantBytes := items[0].frameWireLen * 4
	if totalBytes != wantBytes {
		t.Fatalf("run total bytes = %d, want %d", totalBytes, wantBytes)
	}
	if got := kernelUDPUDPFallbackFramesForGroups(items, 2, 2); got != 4 {
		t.Fatalf("frames for two groups = %d, want 4", got)
	}
}

func TestKernelUDPFallbackGSORunBatchDefaultDisabled(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_SOCKET_GSO_RUN_BATCH", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_UDP_GSO_RUN_BATCH", "")
	if kernelUDPUDPFallbackGSORunBatchEnabled() {
		t.Fatal("kernel_udp UDP socket GSO run batching should require explicit enable")
	}
}

func TestKernelUDPFallbackGSORunBatchCanBeEnabled(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_SOCKET_GSO_RUN_BATCH", "1")
	if !kernelUDPUDPFallbackGSORunBatchEnabled() {
		t.Fatal("kernel_udp UDP socket GSO run batching ignored explicit enable")
	}
}

func TestKernelUDPFallbackGSOSendScratchScatterLayout(t *testing.T) {
	scratch := takeKernelUDPUDPFallbackGSOSendScratch(2, 3)
	defer putKernelUDPUDPFallbackSendScratch(scratch)
	if len(scratch.msgs) != 2 {
		t.Fatalf("msgs len = %d, want 2", len(scratch.msgs))
	}
	if len(scratch.iovs) != 6 {
		t.Fatalf("iovs len = %d, want 6", len(scratch.iovs))
	}
	if len(scratch.headers) != 3*kerneludp.HeaderLen {
		t.Fatalf("headers len = %d, want %d", len(scratch.headers), 3*kerneludp.HeaderLen)
	}
	for i := 0; i < 3; i++ {
		header := scratch.headerForFrame(i)
		if len(header) != kerneludp.HeaderLen {
			t.Fatalf("header %d len = %d, want %d", i, len(header), kerneludp.HeaderLen)
		}
		header[0] = byte(i + 1)
	}
	for i := 0; i < 3; i++ {
		if got := scratch.headers[i*kerneludp.HeaderLen]; got != byte(i+1) {
			t.Fatalf("header %d marker = %d", i, got)
		}
	}
}

func preparedKernelUDPFrameForTest(t *testing.T, packet kerneludp.UDPPacket, frame kerneludp.Frame) preparedKernelUDPTXFrame {
	t.Helper()
	frameWireLen, err := kerneludp.FrameWireLen(len(frame.Payload))
	if err != nil {
		t.Fatalf("frame wire len: %v", err)
	}
	packetWireLen, err := kerneludp.UDPIPv4WireLen(frameWireLen)
	if err != nil {
		t.Fatalf("packet wire len: %v", err)
	}
	return preparedKernelUDPTXFrame{
		packet:          packet,
		wireFrame:       frame,
		sourceIP4:       packet.SourceIP.As4(),
		destinationIP4:  packet.DestinationIP.As4(),
		sourcePort:      packet.SourcePort,
		destinationPort: packet.DestinationPort,
		frameWireLen:    frameWireLen,
		packetWireLen:   packetWireLen,
	}
}

func preparedKernelUDPInnerFrameForTest(t *testing.T, packet kerneludp.UDPPacket, flowID uint64, innerSourcePort, innerDestinationPort uint16) preparedKernelUDPTXFrame {
	t.Helper()
	payload := testInnerIPv4TCPPacket(innerSourcePort, innerDestinationPort)
	txInnerHash, txInnerHashValid := innerIPv4TXHash(payload)
	if !txInnerHashValid {
		t.Fatal("inner IPv4 hash not valid")
	}
	item := preparedKernelUDPFrameForTest(t, packet, kerneludp.Frame{
		Flags:    kerneludp.FlagInnerIPv4,
		FlowID:   flowID,
		Sequence: 1,
		Payload:  payload,
	})
	item.txInnerHash = txInnerHash
	item.txInnerHashValid = txInnerHashValid
	return item
}

func preparedTIXTCPInnerFrameForTest(t *testing.T, packet tixtcp.TCPPacket, flowID uint64, innerSourcePort, innerDestinationPort uint16) preparedTIXTCPTXFrame {
	t.Helper()
	payload := testInnerIPv4TCPPacket(innerSourcePort, innerDestinationPort)
	txInnerHash, txInnerHashValid := innerIPv4TXHash(payload)
	if !txInnerHashValid {
		t.Fatal("inner IPv4 hash not valid")
	}
	frameWireLen, err := tixtcp.FrameWireLen(len(payload))
	if err != nil {
		t.Fatalf("frame wire len: %v", err)
	}
	packetWireLen, err := tixtcp.TCPShapedIPv4WireLen(frameWireLen)
	if err != nil {
		t.Fatalf("packet wire len: %v", err)
	}
	return preparedTIXTCPTXFrame{
		packet: packet,
		wireFrame: tixtcp.Frame{
			Flags:    tixtcp.FlagInnerIPv4,
			FlowID:   flowID,
			Sequence: 1,
			Payload:  payload,
		},
		bytes:            len(payload),
		frameLen:         frameWireLen,
		packetLen:        packetWireLen,
		tcpSeqLen:        frameWireLen,
		txInnerHash:      txInnerHash,
		txInnerHashValid: txInnerHashValid,
	}
}

func testInnerIPv4TCPPacket(sourcePort, destinationPort uint16) []byte {
	packet := make([]byte, 40)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = unix.IPPROTO_TCP
	copy(packet[12:16], []byte{10, 0, 0, 1})
	copy(packet[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	packet[32] = 0x50
	packet[33] = 0x18
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum20(packet[:20]))
	return packet
}

func TestTIXTCPAFXDPTuningRoundsToPowerOfTwo(t *testing.T) {
	t.Setenv("TRUSTIX_AF_XDP_RING_ENTRIES", "1500")
	t.Setenv("TRUSTIX_AF_XDP_UMEM_FRAMES", "3000")
	t.Setenv("TRUSTIX_AF_XDP_UMEM_FRAME_SIZE", "7000")

	if got := tixTCPAFXDPRingEntries(); got != 2048 {
		t.Fatalf("ring entries = %d, want 2048", got)
	}
	if got := tixTCPAFXDPUMEMFrames(2048, 8192); got != 4096 {
		t.Fatalf("umem frames = %d, want 4096", got)
	}
	if got := tixTCPAFXDPUMEMFrameSize(); got != 8192 {
		t.Fatalf("umem frame size = %d, want 8192", got)
	}
}

func TestTIXTCPAFXDPDirectOnlyControlDefaults(t *testing.T) {
	options := tixTCPFastPathOptions{directOnlyControlPlane: true}

	if got := tixTCPAFXDPRingEntriesForFrameSizeWithOptions(tixTCPDefaultUMEMFrameSize, options); got != tixTCPDirectOnlyControlRingEntries {
		t.Fatalf("direct-only ring entries = %d, want %d", got, tixTCPDirectOnlyControlRingEntries)
	}
	if got := tixTCPAFXDPUMEMFramesWithOptions(tixTCPDirectOnlyControlRingEntries, tixTCPDefaultUMEMFrameSize, options); got != tixTCPDirectOnlyControlUMEMFrames {
		t.Fatalf("direct-only UMEM frames = %d, want %d", got, tixTCPDirectOnlyControlUMEMFrames)
	}
}

func TestTIXTCPAFXDPDirectOnlyControlEnvOverride(t *testing.T) {
	t.Setenv("TRUSTIX_AF_XDP_RING_ENTRIES", "2048")
	t.Setenv("TRUSTIX_AF_XDP_UMEM_FRAMES", "8192")
	options := tixTCPFastPathOptions{directOnlyControlPlane: true}

	if got := tixTCPAFXDPRingEntriesForFrameSizeWithOptions(tixTCPDefaultUMEMFrameSize, options); got != 2048 {
		t.Fatalf("direct-only ring entries with env = %d, want 2048", got)
	}
	if got := tixTCPAFXDPUMEMFramesWithOptions(2048, tixTCPDefaultUMEMFrameSize, options); got != 8192 {
		t.Fatalf("direct-only UMEM frames with env = %d, want 8192", got)
	}
}

func TestTIXTCPAFXDPDirectOnlyControlAutoUsesLeanDefaults(t *testing.T) {
	t.Setenv("TRUSTIX_AF_XDP_RING_ENTRIES", "auto")
	t.Setenv("TRUSTIX_AF_XDP_UMEM_FRAMES", "auto")
	options := tixTCPFastPathOptions{directOnlyControlPlane: true}

	if got := tixTCPAFXDPRingEntriesForFrameSizeWithOptions(tixTCPDefaultUMEMFrameSize, options); got != tixTCPDirectOnlyControlRingEntries {
		t.Fatalf("direct-only auto ring entries = %d, want %d", got, tixTCPDirectOnlyControlRingEntries)
	}
	if got := tixTCPAFXDPUMEMFramesWithOptions(tixTCPDirectOnlyControlRingEntries, tixTCPDefaultUMEMFrameSize, options); got != tixTCPDirectOnlyControlUMEMFrames {
		t.Fatalf("direct-only auto UMEM frames = %d, want %d", got, tixTCPDirectOnlyControlUMEMFrames)
	}
}

func TestTIXTCPTXFlushIntervalDefaultsAndOverrides(t *testing.T) {
	t.Setenv("TRUSTIX_AF_XDP_TX_FLUSH_INTERVAL", "")
	if got := tixTCPTXFlushInterval(); got != tixTCPDefaultTXFlushInterval {
		t.Fatalf("default TX flush interval = %s, want %s", got, tixTCPDefaultTXFlushInterval)
	}

	t.Setenv("TRUSTIX_AF_XDP_TX_FLUSH_INTERVAL", "0")
	if got := tixTCPTXFlushInterval(); got != 0 {
		t.Fatalf("disabled TX flush interval = %s, want 0", got)
	}

	t.Setenv("TRUSTIX_AF_XDP_TX_FLUSH_INTERVAL", "10us")
	if got := tixTCPTXFlushInterval(); got != 10*time.Microsecond {
		t.Fatalf("custom TX flush interval = %s, want 10us", got)
	}

	t.Setenv("TRUSTIX_AF_XDP_TX_FLUSH_INTERVAL", "invalid")
	if got := tixTCPTXFlushInterval(); got != tixTCPDefaultTXFlushInterval {
		t.Fatalf("invalid TX flush interval = %s, want default %s", got, tixTCPDefaultTXFlushInterval)
	}
}

func TestTIXTCPTXKickBatchDefaultsAndOverrides(t *testing.T) {
	t.Setenv("TRUSTIX_AF_XDP_TX_KICK_BATCH", "")
	if got := tixTCPTXKickBatch(); got != tixTCPDefaultTXKickBatch {
		t.Fatalf("default TX kick batch = %d, want %d", got, tixTCPDefaultTXKickBatch)
	}

	t.Setenv("TRUSTIX_AF_XDP_TX_KICK_BATCH", "1")
	if got := tixTCPTXKickBatch(); got != 1 {
		t.Fatalf("disabled TX kick batch = %d, want 1", got)
	}

	t.Setenv("TRUSTIX_AF_XDP_TX_KICK_BATCH", "128")
	if got := tixTCPTXKickBatch(); got != 128 {
		t.Fatalf("custom TX kick batch = %d, want 128", got)
	}

	t.Setenv("TRUSTIX_AF_XDP_TX_KICK_BATCH", "invalid")
	if got := tixTCPTXKickBatch(); got != tixTCPDefaultTXKickBatch {
		t.Fatalf("invalid TX kick batch = %d, want default %d", got, tixTCPDefaultTXKickBatch)
	}
}

func TestTIXTCPRXPollConfigDefaultsAndCaps(t *testing.T) {
	t.Setenv("TRUSTIX_AF_XDP_RX_POLL_TIMEOUT_MS", "")
	t.Setenv("TRUSTIX_AF_XDP_RX_IDLE_POLL_TIMEOUT_MS", "")
	if got := tixTCPRXPollConfigFromEnv(); got.BaseTimeoutMS != 10 || got.IdleTimeoutMS != 10 {
		t.Fatalf("default RX poll config = %+v, want base=10 idle=10", got)
	}

	t.Setenv("TRUSTIX_AF_XDP_RX_POLL_TIMEOUT_MS", "2")
	t.Setenv("TRUSTIX_AF_XDP_RX_IDLE_POLL_TIMEOUT_MS", "20")
	if got := tixTCPRXPollConfigFromEnv(); got.BaseTimeoutMS != 2 || got.IdleTimeoutMS != 20 {
		t.Fatalf("env RX poll config = %+v, want base=2 idle=20", got)
	}

	t.Setenv("TRUSTIX_AF_XDP_RX_POLL_TIMEOUT_MS", "30")
	t.Setenv("TRUSTIX_AF_XDP_RX_IDLE_POLL_TIMEOUT_MS", "5")
	if got := tixTCPRXPollConfigFromEnv(); got.BaseTimeoutMS != 30 || got.IdleTimeoutMS != 30 {
		t.Fatalf("idle below base RX poll config = %+v, want base=30 idle=30", got)
	}

	t.Setenv("TRUSTIX_AF_XDP_RX_POLL_TIMEOUT_MS", "9999")
	t.Setenv("TRUSTIX_AF_XDP_RX_IDLE_POLL_TIMEOUT_MS", "9999")
	if got := tixTCPRXPollConfigFromEnv(); got.BaseTimeoutMS != 1000 || got.IdleTimeoutMS != 1000 {
		t.Fatalf("capped RX poll config = %+v, want base=1000 idle=1000", got)
	}
}

func TestNextAFXDPRXIdlePollTimeoutBackoff(t *testing.T) {
	config := tixTCPRXPollConfig{BaseTimeoutMS: 2, IdleTimeoutMS: 20}
	if got := nextAFXDPRXIdlePollTimeout(2, config); got != 4 {
		t.Fatalf("first idle poll timeout = %d, want 4", got)
	}
	if got := nextAFXDPRXIdlePollTimeout(4, config); got != 8 {
		t.Fatalf("second idle poll timeout = %d, want 8", got)
	}
	if got := nextAFXDPRXIdlePollTimeout(16, config); got != 20 {
		t.Fatalf("capped idle poll timeout = %d, want 20", got)
	}
	if got := nextAFXDPRXIdlePollTimeout(0, config); got != 1 {
		t.Fatalf("zero-base next idle poll timeout = %d, want 1", got)
	}
	if got := nextAFXDPRXIdlePollTimeout(10, tixTCPRXPollConfig{BaseTimeoutMS: 10, IdleTimeoutMS: 10}); got != 10 {
		t.Fatalf("disabled idle backoff timeout = %d, want 10", got)
	}
}

func TestTIXTCPAutoJumboUMEMFrameSize(t *testing.T) {
	t.Setenv("TRUSTIX_AF_XDP_UMEM_FRAME_SIZE", "auto")
	t.Setenv("TRUSTIX_AF_XDP_AUTO_UMEM_JUMBO", "1")

	if got := tixTCPAFXDPUMEMFrameSize(); got != 4096 {
		t.Fatalf("auto jumbo UMEM frame size = %d, want 4096", got)
	}
}

func TestTIXTCPAFXDPUMEMFrameSizeCandidatesFallbackDown(t *testing.T) {
	got := tixTCPAFXDPUMEMFrameSizeCandidates(10240)
	want := []uint32{16384, 8192, 4096, 2048}
	if len(got) != len(want) {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidates = %v, want %v", got, want)
		}
	}
}

func TestTIXTCPFastPathPayloadMaxUsesSelectedUMEMFrameSize(t *testing.T) {
	fastPath := testTIXTCPFastPathWithQueues(1)
	fastPath.sockets[0].umemFrameSize = 4096
	fastPath.sockets[0].requestedUMEMFrameSize = 16384

	if got, want := fastPath.TIXTCPPayloadMax(dataplane.CryptoPlacementUserspace, false), 4096-tixTCPAFXDPTXFrameTailroom-tixTCPAFXDPBaseOverhead; got != want {
		t.Fatalf("tix_tcp payload max = %d, want %d", got, want)
	}
	if got, want := fastPath.KernelUDPPayloadMax(dataplane.CryptoPlacementUserspace, false), 4096-tixTCPAFXDPTXFrameTailroom-kernelUDPAFXDPBaseOverhead; got != want {
		t.Fatalf("kernel_udp payload max = %d, want %d", got, want)
	}
	if got, want := fastPath.KernelUDPPayloadMaxWithDeviceCrypto(), 4096-tixTCPAFXDPTXFrameTailroom-kernelUDPAFXDPBaseOverhead-tixTCPKernelCryptoOverhead; got != want {
		t.Fatalf("kernel_udp device-crypto payload max = %d, want %d", got, want)
	}
	stats := fastPath.Stats()
	if stats["umem_frame_size_fallback"] != 1 {
		t.Fatalf("umem_frame_size_fallback = %d, want 1", stats["umem_frame_size_fallback"])
	}
	if stats["tix_tcp_payload_max"] != uint64(4096-tixTCPAFXDPTXFrameTailroom-tixTCPAFXDPBaseOverhead) {
		t.Fatalf("tix_tcp_payload_max = %d", stats["tix_tcp_payload_max"])
	}
	if stats["tx_frame_tailroom_bytes"] != tixTCPAFXDPTXFrameTailroom {
		t.Fatalf("tx_frame_tailroom_bytes = %d, want %d", stats["tx_frame_tailroom_bytes"], tixTCPAFXDPTXFrameTailroom)
	}
}

func TestTIXTCPFastPathPayloadMaxUsesConfiguredTailroom(t *testing.T) {
	t.Setenv("TRUSTIX_AF_XDP_TX_FRAME_TAILROOM", "128")
	fastPath := testTIXTCPFastPathWithQueues(1)
	fastPath.sockets[0].umemFrameSize = 4096

	if got, want := fastPath.TIXTCPPayloadMax(dataplane.CryptoPlacementUserspace, false), 4096-128-tixTCPAFXDPBaseOverhead; got != want {
		t.Fatalf("tix_tcp payload max = %d, want %d", got, want)
	}
	stats := fastPath.Stats()
	if stats["tx_frame_tailroom_bytes"] != 128 {
		t.Fatalf("tx_frame_tailroom_bytes = %d, want 128", stats["tx_frame_tailroom_bytes"])
	}
}

func TestTIXTCPFastPathPayloadMaxKeepsMinimumFrameUsable(t *testing.T) {
	fastPath := testTIXTCPFastPathWithQueues(1)
	fastPath.sockets[0].umemFrameSize = tixTCPMinUMEMFrameSize

	if got, want := fastPath.TIXTCPPayloadMax(dataplane.CryptoPlacementUserspace, false), tixTCPMinUMEMFrameSize-tixTCPAFXDPTXFrameTailroom-tixTCPAFXDPBaseOverhead; got != want {
		t.Fatalf("tix_tcp payload max = %d, want %d", got, want)
	}
}

func TestTIXTCPFastPathStatsReportsDirectOnlyControlPlane(t *testing.T) {
	fastPath := testTIXTCPFastPathWithQueues(1)
	fastPath.directOnlyControlPlane = true
	fastPath.sockets[0].ringEntries = tixTCPDirectOnlyControlRingEntries
	fastPath.sockets[0].umemFrames = tixTCPDirectOnlyControlUMEMFrames
	fastPath.sockets[0].umemFrameSize = tixTCPDefaultUMEMFrameSize
	fastPath.sockets[0].requestedUMEMFrameSize = tixTCPDefaultUMEMFrameSize

	stats := fastPath.Stats()
	if stats["direct_only_control_plane"] != 1 {
		t.Fatalf("direct_only_control_plane = %d, want 1", stats["direct_only_control_plane"])
	}
	if stats["umem_bytes_total"] != uint64(tixTCPDirectOnlyControlUMEMFrames*tixTCPDefaultUMEMFrameSize) {
		t.Fatalf("umem_bytes_total = %d", stats["umem_bytes_total"])
	}
}

func TestTIXTCPFastPathStatsReportsBPFConfig(t *testing.T) {
	configMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_af_xdp_config_stats_test", Type: cebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	defer configMap.Close()
	fastPath := testTIXTCPFastPathWithQueues(1)
	fastPath.xdpObject = &tixTCPXDPObject{configMap: configMap}

	if err := fastPath.SetKernelUDPRXDirectWithOptions(true, true, true, tixTCPBPFConfigOptions{
		XDPRXSecureDirect:       true,
		XDPFallbackPass:         true,
		XDPRXTrustInnerChecksum: true,
	}); err != nil {
		t.Fatalf("set kernel_udp RX direct config: %v", err)
	}

	stats := fastPath.Stats()
	if stats["xdp_config_kernel_udp_tc_rx_direct"] != 1 {
		t.Fatalf("xdp_config_kernel_udp_tc_rx_direct = %d, want 1", stats["xdp_config_kernel_udp_tc_rx_direct"])
	}
	if stats["xdp_config_kernel_udp_tc_rx_secure_direct"] != 1 {
		t.Fatalf("xdp_config_kernel_udp_tc_rx_secure_direct = %d, want 1", stats["xdp_config_kernel_udp_tc_rx_secure_direct"])
	}
	if stats["xdp_config_kernel_udp_xdp_rx_direct"] != 1 {
		t.Fatalf("xdp_config_kernel_udp_xdp_rx_direct = %d, want 1", stats["xdp_config_kernel_udp_xdp_rx_direct"])
	}
	if stats["xdp_config_kernel_udp_xdp_rx_secure_direct"] != 1 {
		t.Fatalf("xdp_config_kernel_udp_xdp_rx_secure_direct = %d, want 1", stats["xdp_config_kernel_udp_xdp_rx_secure_direct"])
	}
	if stats["xdp_config_fallback_pass"] != 1 {
		t.Fatalf("xdp_config_fallback_pass = %d, want 1", stats["xdp_config_fallback_pass"])
	}
	if stats["xdp_config_kernel_udp_xdp_rx_trust_inner_checksum"] != 1 {
		t.Fatalf("xdp_config_kernel_udp_xdp_rx_trust_inner_checksum = %d, want 1", stats["xdp_config_kernel_udp_xdp_rx_trust_inner_checksum"])
	}
	if stats["xdp_config_queue_count"] != 1 {
		t.Fatalf("xdp_config_queue_count = %d, want 1", stats["xdp_config_queue_count"])
	}
}

func testTIXTCPFastPathWithQueues(queueCount int) *tixTCPFastPath {
	fastPath := &tixTCPFastPath{
		sockets: make([]*afXDPSocket, queueCount),
	}
	for queueID := range fastPath.sockets {
		fastPath.sockets[queueID] = &afXDPSocket{queueID: uint32(queueID)}
	}
	return fastPath
}

func testAFXDPSocketForRXFrame() *afXDPSocket {
	producer := uint32(0)
	consumer := uint32(0)
	return &afXDPSocket{
		linkIndex:     9,
		umemFrames:    1,
		ringEntries:   1,
		umemFrameSize: tixTCPDefaultUMEMFrameSize,
		fill: xdpUint64Ring{
			producer: &producer,
			consumer: &consumer,
			descs:    make([]uint64, 1),
			size:     1,
			mask:     0,
		},
	}
}

func testTIXTCPRXFrame(t *testing.T, socket *afXDPSocket, frame tixtcp.Frame) (*afXDPRXFrame, int) {
	t.Helper()
	packet := tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.1"),
		DestinationIP:   netip.MustParseAddr("198.51.100.2"),
		SourcePort:      40000,
		DestinationPort: 9443,
		Acknowledgment:  1,
	}
	frameLen, err := tixtcp.FrameWireLen(len(frame.Payload))
	if err != nil {
		t.Fatalf("frame wire len: %v", err)
	}
	packetLen, err := tixtcp.TCPShapedIPv4WireLen(frameLen)
	if err != nil {
		t.Fatalf("packet wire len: %v", err)
	}
	wire := make([]byte, ethernetHeaderLen+packetLen)
	copy(wire[0:6], []byte{0x02, 0, 0, 0, 0, 2})
	copy(wire[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(wire[12:14], etherTypeIPv4)
	if _, err := tixtcp.MarshalTCPShapedIPv4FrameIntoSkipTCPChecksum(packet, frame, wire[ethernetHeaderLen:]); err != nil {
		t.Fatalf("marshal tix_tcp frame: %v", err)
	}
	payloadOffset := ethernetHeaderLen + 20 + 20 + tixtcp.HeaderLen
	recycled := &atomic.Bool{}
	return &afXDPRXFrame{socket: socket, addr: 0, data: wire, recycled: recycled}, payloadOffset
}

func testTIXTCPRXFrameStream(t *testing.T, socket *afXDPSocket, frames ...tixtcp.Frame) (*afXDPRXFrame, []int) {
	t.Helper()
	packet := tixtcp.TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.1"),
		DestinationIP:   netip.MustParseAddr("198.51.100.2"),
		SourcePort:      40000,
		DestinationPort: 9443,
		Acknowledgment:  1,
	}
	var stream []byte
	payloadOffsets := make([]int, 0, len(frames))
	for _, frame := range frames {
		frameWire, err := frame.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal stream frame: %v", err)
		}
		payloadOffsets = append(payloadOffsets, ethernetHeaderLen+20+20+len(stream)+tixtcp.HeaderLen)
		stream = append(stream, frameWire...)
	}
	packet.Payload = stream
	packetLen, err := tixtcp.TCPShapedIPv4WireLen(len(stream))
	if err != nil {
		t.Fatalf("packet wire len: %v", err)
	}
	wire := make([]byte, ethernetHeaderLen+packetLen)
	copy(wire[0:6], []byte{0x02, 0, 0, 0, 0, 2})
	copy(wire[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(wire[12:14], etherTypeIPv4)
	if _, err := tixtcp.MarshalTCPShapedIPv4Into(packet, wire[ethernetHeaderLen:]); err != nil {
		t.Fatalf("marshal tix_tcp stream packet: %v", err)
	}
	recycled := &atomic.Bool{}
	return &afXDPRXFrame{socket: socket, addr: 0, data: wire, recycled: recycled}, payloadOffsets
}

func testKernelUDPRXFrame(t *testing.T, socket *afXDPSocket, frame kerneludp.Frame) (*afXDPRXFrame, int) {
	t.Helper()
	packet := kerneludp.UDPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.1"),
		DestinationIP:   netip.MustParseAddr("198.51.100.2"),
		SourcePort:      40000,
		DestinationPort: 9443,
	}
	frameLen, err := kerneludp.FrameWireLen(len(frame.Payload))
	if err != nil {
		t.Fatalf("frame wire len: %v", err)
	}
	packetLen, err := kerneludp.UDPIPv4WireLen(frameLen)
	if err != nil {
		t.Fatalf("packet wire len: %v", err)
	}
	wire := make([]byte, ethernetHeaderLen+packetLen)
	copy(wire[0:6], []byte{0x02, 0, 0, 0, 0, 2})
	copy(wire[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(wire[12:14], etherTypeIPv4)
	if _, err := kerneludp.MarshalUDPIPv4FrameIntoNoChecksum(packet, frame, wire[ethernetHeaderLen:]); err != nil {
		t.Fatalf("marshal kernel_udp frame: %v", err)
	}
	payloadOffset := ethernetHeaderLen + 20 + 8 + kerneludp.HeaderLen
	recycled := &atomic.Bool{}
	return &afXDPRXFrame{socket: socket, addr: 0, data: wire, recycled: recycled}, payloadOffset
}

func mustKernelUDPFrameWire(t *testing.T, frame kerneludp.Frame) []byte {
	t.Helper()
	wire, err := frame.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal kernel_udp frame: %v", err)
	}
	return wire
}

func testIPv4Packet(payload []byte) []byte {
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = unix.IPPROTO_TCP
	copy(packet[12:16], []byte{10, 0, 0, 1})
	copy(packet[16:20], []byte{10, 0, 0, 2})
	copy(packet[20:], payload)
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum20(packet[:20]))
	return packet
}

func TestKernelUDPOpenPlainBufferPoolAvoidsSliceBoxingAllocation(t *testing.T) {
	payloadLen := kernelCryptoSecureHeaderLen + kernelCryptoFrameTagLen + 1500
	buffer, release := kernelUDPOpenPlainBuffer(true, payloadLen)
	if len(buffer) != 1500 || release == nil {
		t.Fatalf("warm buffer len=%d release=%v", len(buffer), release != nil)
	}
	release()

	allocations := testing.AllocsPerRun(1000, func() {
		buffer, release := kernelUDPOpenPlainBuffer(true, payloadLen)
		if len(buffer) != 1500 || release == nil {
			t.Fatal("pooled open buffer is unavailable")
		}
		release()
	})
	if allocations > 2 {
		t.Fatalf("open buffer allocations = %v, want at most idempotence state and returned closure", allocations)
	}
}
