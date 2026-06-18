//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var testVethNameCounter atomic.Uint32

func TestPacketSocketGSOErrnoUnwrapsSyscallErrors(t *testing.T) {
	err := fmt.Errorf("sendmsg wrapper: %w", &os.SyscallError{Syscall: "sendmsg", Err: unix.EINVAL})
	if got := packetSocketGSOErrno(err); got != unix.EINVAL {
		t.Fatalf("packet socket GSO errno = %v, want EINVAL", got)
	}
	if !isPacketSocketGSOUnsupported(err) {
		t.Fatalf("wrapped EINVAL was not treated as GSO unsupported")
	}

	oldStats := lanPacketStats
	lanPacketStats = lanPacketInjectorStats{}
	t.Cleanup(func() {
		lanPacketStats = oldStats
	})
	lanPacketStats.recordGSOErrno(err)
	if got := lanPacketStats.gsoErrnoEINVAL.Load(); got != 1 {
		t.Fatalf("wrapped EINVAL counter = %d, want 1", got)
	}
	if got := lanPacketStats.gsoErrnoOther.Load(); got != 0 {
		t.Fatalf("other errno counter = %d, want 0", got)
	}
}

func TestPacketSocketGSOErrnoRecordsKnownTransientErrors(t *testing.T) {
	oldStats := lanPacketStats
	lanPacketStats = lanPacketInjectorStats{}
	t.Cleanup(func() {
		lanPacketStats = oldStats
	})

	err := fmt.Errorf("sendmsg wrapper: %w", &os.SyscallError{Syscall: "sendmsg", Err: unix.ENOBUFS})
	lanPacketStats.recordGSOErrno(err)
	if got := lanPacketStats.gsoErrnoENOBUFS.Load(); got != 1 {
		t.Fatalf("wrapped ENOBUFS counter = %d, want 1", got)
	}
	if isPacketSocketGSOUnsupported(err) {
		t.Fatalf("ENOBUFS should be a transient GSO send error, not a capability failure")
	}
}

func TestPacketSocketGSOErrnoUnwrapsJoinedErrors(t *testing.T) {
	err := errors.Join(
		fmt.Errorf("raw configure: %w", &os.SyscallError{Syscall: "setsockopt", Err: unix.ENOPROTOOPT}),
		fmt.Errorf("cooked configure: %w", &os.SyscallError{Syscall: "setsockopt", Err: unix.EINVAL}),
	)
	if got := packetSocketGSOErrno(err); got != unix.ENOPROTOOPT {
		t.Fatalf("joined packet socket GSO errno = %v, want ENOPROTOOPT", got)
	}
	if !isPacketSocketGSOUnsupported(err) {
		t.Fatalf("joined unsupported errno was not treated as GSO unsupported")
	}
}

func TestPacketVNetHeaderSizeOptionalErrors(t *testing.T) {
	for _, errno := range []unix.Errno{unix.EINVAL, unix.ENOPROTOOPT, unix.EOPNOTSUPP, unix.ENOTSUP} {
		err := fmt.Errorf("set PACKET_VNET_HDR_SZ: %w", errno)
		if !isPacketVNetHeaderSizeOptionalError(err) {
			t.Fatalf("%v should allow default VNET header size fallback", errno)
		}
	}
	err := fmt.Errorf("set PACKET_VNET_HDR_SZ: %w", unix.EPERM)
	if isPacketVNetHeaderSizeOptionalError(err) {
		t.Fatalf("EPERM should remain a fatal VNET header size configuration error")
	}
}

func TestLANReinjectGSOQdiscBypassDefaultDisabled(t *testing.T) {
	t.Setenv("TRUSTIX_LAN_REINJECT_GSO_QDISC_BYPASS", "")
	if lanReinjectGSOQdiscBypassEnabled() {
		t.Fatalf("LAN reinject GSO qdisc bypass enabled by default")
	}
	t.Setenv("TRUSTIX_LAN_REINJECT_GSO_QDISC_BYPASS", "1")
	if !lanReinjectGSOQdiscBypassEnabled() {
		t.Fatalf("LAN reinject GSO qdisc bypass env did not enable")
	}
}

func TestLANReinjectSocketSendBufferEnv(t *testing.T) {
	t.Setenv("TRUSTIX_LAN_REINJECT_SNDBUF", "")
	t.Setenv("TRUSTIX_LAN_REINJECT_SOCKET_SNDBUF", "")
	if got := lanReinjectSocketSendBuffer(); got != 0 {
		t.Fatalf("LAN reinject send buffer default = %d, want 0", got)
	}
	t.Setenv("TRUSTIX_LAN_REINJECT_SNDBUF", "4194304")
	if got := lanReinjectSocketSendBuffer(); got != 4194304 {
		t.Fatalf("LAN reinject send buffer = %d, want 4194304", got)
	}
	t.Setenv("TRUSTIX_LAN_REINJECT_SNDBUF", "999999999")
	if got := lanReinjectSocketSendBuffer(); got != 128*1024*1024 {
		t.Fatalf("LAN reinject send buffer clamp = %d, want %d", got, 128*1024*1024)
	}
}

func TestLANReinjectGSORawMixedBatchDefaultsOn(t *testing.T) {
	t.Setenv("TRUSTIX_LAN_REINJECT_GSO_RAW_MIXED_BATCH", "")
	if !lanReinjectGSORawMixedBatchEnabled() {
		t.Fatalf("LAN reinject raw mixed GSO batch disabled by default")
	}
	t.Setenv("TRUSTIX_LAN_REINJECT_GSO_RAW_MIXED_BATCH", "0")
	if lanReinjectGSORawMixedBatchEnabled() {
		t.Fatalf("LAN reinject raw mixed GSO batch env did not disable")
	}
	t.Setenv("TRUSTIX_LAN_REINJECT_GSO_RAW_MIXED_BATCH", "1")
	if !lanReinjectGSORawMixedBatchEnabled() {
		t.Fatalf("LAN reinject raw mixed GSO batch env did not enable")
	}
}

func TestLANReinjectGSORawMixedBatchLimitDefaultAndClamp(t *testing.T) {
	t.Setenv("TRUSTIX_LAN_REINJECT_GSO_RAW_MIXED_BATCH_LIMIT", "")
	if got := lanReinjectGSORawMixedBatchLimit(); got != 256 {
		t.Fatalf("LAN reinject raw mixed GSO batch default limit = %d, want 256", got)
	}
	t.Setenv("TRUSTIX_LAN_REINJECT_GSO_RAW_MIXED_BATCH_LIMIT", "128")
	if got := lanReinjectGSORawMixedBatchLimit(); got != 128 {
		t.Fatalf("LAN reinject raw mixed GSO batch limit = %d, want 128", got)
	}
	t.Setenv("TRUSTIX_LAN_REINJECT_GSO_RAW_MIXED_BATCH_LIMIT", "4096")
	if got := lanReinjectGSORawMixedBatchLimit(); got != 256 {
		t.Fatalf("LAN reinject raw mixed GSO batch limit clamp = %d, want 256", got)
	}
}

func TestLANReinjectRawVNetBatchEnvAndLimit(t *testing.T) {
	t.Setenv("TRUSTIX_LAN_REINJECT_RAW_VNET_BATCH", "")
	t.Setenv("TRUSTIX_LAN_REINJECT_GSO_RAW_VNET_BATCH", "")
	if !lanReinjectRawVNetBatchEnabled() {
		t.Fatalf("LAN reinject raw VNET batch disabled by default")
	}
	t.Setenv("TRUSTIX_LAN_REINJECT_RAW_VNET_BATCH", "0")
	if lanReinjectRawVNetBatchEnabled() {
		t.Fatalf("LAN reinject raw VNET batch env did not disable")
	}
	t.Setenv("TRUSTIX_LAN_REINJECT_RAW_VNET_BATCH", "1")
	if !lanReinjectRawVNetBatchEnabled() {
		t.Fatalf("LAN reinject raw VNET batch env did not enable")
	}

	t.Setenv("TRUSTIX_LAN_REINJECT_RAW_VNET_BATCH_LIMIT", "")
	if got := lanReinjectRawVNetBatchLimit(); got != 256 {
		t.Fatalf("LAN reinject raw VNET batch default limit = %d, want 256", got)
	}
	t.Setenv("TRUSTIX_LAN_REINJECT_RAW_VNET_BATCH_LIMIT", "64")
	if got := lanReinjectRawVNetBatchLimit(); got != 64 {
		t.Fatalf("LAN reinject raw VNET batch limit = %d, want 64", got)
	}
	t.Setenv("TRUSTIX_LAN_REINJECT_RAW_VNET_BATCH_LIMIT", "4096")
	if got := lanReinjectRawVNetBatchLimit(); got != 256 {
		t.Fatalf("LAN reinject raw VNET batch limit clamp = %d, want 256", got)
	}
}

func TestLANPacketInjectorCanAttemptGSOSkipsOnlyAfterBothPathsDisabled(t *testing.T) {
	injector := &lanPacketInjector{}
	if !injector.canAttemptGSO() {
		t.Fatalf("fresh injector should attempt GSO")
	}
	injector.gsoRawDisabled = true
	if !injector.canAttemptGSO() {
		t.Fatalf("cooked GSO path should still be attempted after raw path is disabled")
	}
	injector.gsoDisabled = true
	if injector.canAttemptGSO() {
		t.Fatalf("injector should stop GSO attempts after raw and cooked paths are disabled")
	}
}

func TestSegmentLANIPv4TCPPacketSegmentsLargePayload(t *testing.T) {
	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i)
	}
	packet := lanTCPIPv4PacketForTest(payload, 0x18, 20)
	const mtu = 1500

	segments, err := segmentLANIPv4TCPPacket(packet, mtu)
	if err != nil {
		t.Fatalf("segment LAN IPv4/TCP packet: %v", err)
	}
	if len(segments) != 3 {
		t.Fatalf("segments = %d, want 3", len(segments))
	}

	var reassembled []byte
	var offset uint32
	for i, segment := range segments {
		if len(segment) > mtu {
			t.Fatalf("segment %d length = %d, want <= %d", i, len(segment), mtu)
		}
		assertLANIPv4TCPChecksumValid(t, segment)
		ihl := int(segment[0]&0x0f) * 4
		totalLen := int(binary.BigEndian.Uint16(segment[2:4]))
		if totalLen != len(segment) {
			t.Fatalf("segment %d IPv4 total length = %d, want %d", i, totalLen, len(segment))
		}
		if got, want := binary.BigEndian.Uint16(segment[4:6]), uint16(0x1234+i); got != want {
			t.Fatalf("segment %d IPv4 ID = %#04x, want %#04x", i, got, want)
		}
		tcp := segment[ihl:]
		if got, want := binary.BigEndian.Uint32(tcp[4:8]), uint32(0x01020304)+offset; got != want {
			t.Fatalf("segment %d TCP sequence = %#08x, want %#08x", i, got, want)
		}
		tcpHeaderLen := int(tcp[12]>>4) * 4
		tcpPayload := tcp[tcpHeaderLen:]
		reassembled = append(reassembled, tcpPayload...)
		offset += uint32(len(tcpPayload))
		if i < len(segments)-1 && tcp[13] != 0x10 {
			t.Fatalf("segment %d TCP flags = %#02x, want ACK only", i, tcp[13])
		}
		if i == len(segments)-1 && tcp[13] != 0x18 {
			t.Fatalf("final TCP flags = %#02x, want ACK|PSH", tcp[13])
		}
	}
	if !bytes.Equal(reassembled, payload) {
		t.Fatalf("reassembled payload mismatch")
	}
}

func TestSegmentLANIPv4TCPPacketKeepsFINOnFinalSegment(t *testing.T) {
	payload := bytes.Repeat([]byte{0xab}, 2048)
	packet := lanTCPIPv4PacketForTest(payload, 0x19, 20)

	segments, err := segmentLANIPv4TCPPacket(packet, 1500)
	if err != nil {
		t.Fatalf("segment LAN IPv4/TCP packet: %v", err)
	}
	if len(segments) != 2 {
		t.Fatalf("segments = %d, want 2", len(segments))
	}
	firstTCP := segments[0][20:]
	finalTCP := segments[1][20:]
	if firstTCP[13]&0x09 != 0 {
		t.Fatalf("first TCP flags = %#02x, want PSH/FIN cleared", firstTCP[13])
	}
	if finalTCP[13]&0x09 != 0x09 {
		t.Fatalf("final TCP flags = %#02x, want PSH/FIN retained", finalTCP[13])
	}
}

func TestPrepareLANIPv4TCPGSOPacketBuildsVirtioHeader(t *testing.T) {
	payload := bytes.Repeat([]byte{0xef}, 4096)
	packet := lanTCPIPv4PacketForTest(payload, 0x18, 20)

	wire, err := prepareLANIPv4TCPGSOPacket(packet, 1500)
	if err != nil {
		t.Fatalf("prepare LAN IPv4/TCP GSO packet: %v", err)
	}
	if len(wire) != virtioNetHdrLen+len(packet) {
		t.Fatalf("GSO wire length = %d, want %d", len(wire), virtioNetHdrLen+len(packet))
	}
	if wire[0] != 1 || wire[1] != 1 {
		t.Fatalf("virtio flags/gso_type = %#x/%#x, want NEEDS_CSUM/TCPV4", wire[0], wire[1])
	}
	if got, want := binary.LittleEndian.Uint16(wire[2:4]), uint16(40); got != want {
		t.Fatalf("virtio hdr_len = %d, want %d", got, want)
	}
	if got, want := binary.LittleEndian.Uint16(wire[4:6]), uint16(1460); got != want {
		t.Fatalf("virtio gso_size = %d, want %d", got, want)
	}
	if got, want := binary.LittleEndian.Uint16(wire[6:8]), uint16(20); got != want {
		t.Fatalf("virtio csum_start = %d, want %d", got, want)
	}
	if got, want := binary.LittleEndian.Uint16(wire[8:10]), uint16(16); got != want {
		t.Fatalf("virtio csum_offset = %d, want %d", got, want)
	}
	wantPacket := append([]byte(nil), packet...)
	binary.BigEndian.PutUint16(wantPacket[20+16:20+18], tcpPseudoHeaderPartialChecksum(wantPacket, len(wantPacket)-20))
	if !bytes.Equal(wire[virtioNetHdrLen:], wantPacket) {
		t.Fatalf("GSO payload changed")
	}
	ip := wire[virtioNetHdrLen:]
	tcp := ip[20:]
	if got, want := binary.BigEndian.Uint16(tcp[16:18]), tcpPseudoHeaderPartialChecksum(ip, len(tcp)); got != want {
		t.Fatalf("partial TCP checksum = %#04x, want %#04x", got, want)
	}
}

func TestPrepareLANIPv4TCPGSORawPacketBuildsEthernetVirtioHeader(t *testing.T) {
	payload := bytes.Repeat([]byte{0xca}, 4096)
	packet := lanTCPIPv4PacketForTest(payload, 0x18, 20)
	srcMAC := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	dstMAC := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	wire, err := prepareLANIPv4TCPGSORawPacket(packet, 1500, srcMAC, dstMAC)
	if err != nil {
		t.Fatalf("prepare raw LAN IPv4/TCP GSO packet: %v", err)
	}
	if len(wire) != virtioNetHdrLen+ethernetHeaderLen+len(packet) {
		t.Fatalf("raw GSO wire length = %d, want %d", len(wire), virtioNetHdrLen+ethernetHeaderLen+len(packet))
	}
	if wire[0] != 1 || wire[1] != 1 {
		t.Fatalf("virtio flags/gso_type = %#x/%#x, want NEEDS_CSUM/TCPV4", wire[0], wire[1])
	}
	if got, want := binary.LittleEndian.Uint16(wire[2:4]), uint16(ethernetHeaderLen+40); got != want {
		t.Fatalf("virtio raw hdr_len = %d, want %d", got, want)
	}
	if got, want := binary.LittleEndian.Uint16(wire[4:6]), uint16(1460); got != want {
		t.Fatalf("virtio raw gso_size = %d, want %d", got, want)
	}
	if got, want := binary.LittleEndian.Uint16(wire[6:8]), uint16(ethernetHeaderLen+20); got != want {
		t.Fatalf("virtio raw csum_start = %d, want %d", got, want)
	}
	if got, want := binary.LittleEndian.Uint16(wire[8:10]), uint16(16); got != want {
		t.Fatalf("virtio raw csum_offset = %d, want %d", got, want)
	}
	ethernet := wire[virtioNetHdrLen:]
	if !bytes.Equal(ethernet[0:6], dstMAC) || !bytes.Equal(ethernet[6:12], srcMAC) {
		t.Fatalf("raw GSO ethernet header = %x", ethernet[:12])
	}
	if got := binary.BigEndian.Uint16(ethernet[12:14]); got != etherTypeIPv4 {
		t.Fatalf("raw GSO ethertype = %#04x, want IPv4", got)
	}
	wantPacket := append([]byte(nil), packet...)
	binary.BigEndian.PutUint16(wantPacket[20+16:20+18], tcpPseudoHeaderPartialChecksum(wantPacket, len(wantPacket)-20))
	if !bytes.Equal(ethernet[ethernetHeaderLen:], wantPacket) {
		t.Fatalf("raw GSO payload changed")
	}
}

func TestLANIPv4SingleDestinationBatchKeepsBareIPv4BatchZeroCopy(t *testing.T) {
	packetA := lanTCPIPv4PacketForTest([]byte("alpha"), 0x18, 20)
	packetB := lanTCPIPv4PacketForTest([]byte("bravo"), 0x18, 20)

	packets, dst, ok, err := lanIPv4SingleDestinationBatch([][]byte{packetA, packetB})
	if err != nil {
		t.Fatalf("single destination batch: %v", err)
	}
	if !ok {
		t.Fatal("bare IPv4 packets to the same destination should use the single-destination fast path")
	}
	if dst != netip.MustParseAddr("10.0.1.2") {
		t.Fatalf("destination = %s, want 10.0.1.2", dst)
	}
	if len(packets) != 2 || &packets[0][0] != &packetA[0] || &packets[1][0] != &packetB[0] {
		t.Fatal("bare IPv4 batch should reuse original packet storage")
	}
}

func TestLANIPv4SingleDestinationBatchStripsEthernetFrames(t *testing.T) {
	packetA := ethernetIPv4FrameForNeighborTest(lanTCPIPv4PacketForTest([]byte("alpha"), 0x18, 20))
	packetB := ethernetIPv4FrameForNeighborTest(lanTCPIPv4PacketForTest([]byte("bravo"), 0x18, 20))

	packets, _, ok, err := lanIPv4SingleDestinationBatch([][]byte{packetA, packetB})
	if err != nil {
		t.Fatalf("single destination batch: %v", err)
	}
	if !ok {
		t.Fatal("Ethernet-framed packets to the same destination should use the single-destination fast path")
	}
	if len(packets) != 2 || len(packets[0]) == 0 || len(packets[1]) == 0 {
		t.Fatalf("stripped packets = %#v", packets)
	}
	if &packets[0][0] != &packetA[ethernetHeaderLen] || &packets[1][0] != &packetB[ethernetHeaderLen] {
		t.Fatal("Ethernet-framed batch should expose IPv4 payload slices")
	}
}

func TestLANIPv4SingleDestinationBatchRejectsMixedFraming(t *testing.T) {
	bare := lanTCPIPv4PacketForTest([]byte("alpha"), 0x18, 20)
	framed := ethernetIPv4FrameForNeighborTest(lanTCPIPv4PacketForTest([]byte("bravo"), 0x18, 20))

	_, _, ok, err := lanIPv4SingleDestinationBatch([][]byte{bare, framed})
	if err != nil {
		t.Fatalf("single destination batch: %v", err)
	}
	if ok {
		t.Fatal("mixed bare/Ethernet packet storage should fall back to grouped path")
	}
}

func TestLANIPv4TCPGSOScatterRunCoalescesContiguousPackets(t *testing.T) {
	packetA := lanTCPIPv4PacketForTest(bytes.Repeat([]byte{0xaa}, 700), 0x10, 20)
	packetB := lanTCPIPv4PacketForTest(bytes.Repeat([]byte{0xbb}, 700), 0x18, 20)
	binary.BigEndian.PutUint32(packetB[24:28], binary.BigEndian.Uint32(packetA[24:28])+700)
	binary.BigEndian.PutUint16(packetB[10:12], 0)
	binary.BigEndian.PutUint16(packetB[10:12], captureChecksum(packetB[:20]))
	tcpB := packetB[20:]
	binary.BigEndian.PutUint16(tcpB[16:18], 0)
	binary.BigEndian.PutUint16(tcpB[16:18], captureTransportChecksum(packetB[12:16], packetB[16:20], ipProtocolTCP, tcpB))

	run, meta, totalLen, ok := lanIPv4TCPGSOScatterRun([][]byte{packetA, packetB}, 1500)
	if !ok || run != 2 {
		t.Fatalf("scatter run ok=%v run=%d, want two packets", ok, run)
	}
	if meta.payloadOffset != 40 {
		t.Fatalf("scatter payload offset = %d, want 40", meta.payloadOffset)
	}
	if totalLen != 20+20+1400 {
		t.Fatalf("scatter totalLen = %d, want %d", totalLen, 20+20+1400)
	}
	if flags := lanIPv4TCPGSOScatterFlags([][]byte{packetA, packetB}, meta); flags != 0x18 {
		t.Fatalf("scatter flags = %#x, want ACK|PSH", flags)
	}
}

func TestLANIPv4TCPGSOScatterRunRespectsConfiguredLimits(t *testing.T) {
	t.Setenv("TRUSTIX_LAN_REINJECT_GSO_SCATTER_MAX_IPV4_LEN", "1500")
	t.Setenv("TRUSTIX_LAN_REINJECT_GSO_SCATTER_MAX_SEGMENTS", "32")
	packetA := lanTCPIPv4PacketForTest(bytes.Repeat([]byte{0xaa}, 700), 0x10, 20)
	packetB := lanTCPIPv4PacketForTest(bytes.Repeat([]byte{0xbb}, 700), 0x10, 20)
	packetC := lanTCPIPv4PacketForTest(bytes.Repeat([]byte{0xcc}, 700), 0x18, 20)
	setLANTCPIPv4SequenceForTest(packetB, binary.BigEndian.Uint32(packetA[24:28])+700)
	setLANTCPIPv4SequenceForTest(packetC, binary.BigEndian.Uint32(packetB[24:28])+700)

	run, _, totalLen, ok := lanIPv4TCPGSOScatterRun([][]byte{packetA, packetB, packetC}, 1500)
	if !ok || run != 2 {
		t.Fatalf("scatter run ok=%v run=%d, want limit to two packets", ok, run)
	}
	if totalLen != 20+20+1400 {
		t.Fatalf("scatter totalLen = %d, want %d", totalLen, 20+20+1400)
	}

	t.Setenv("TRUSTIX_LAN_REINJECT_GSO_SCATTER_MAX_IPV4_LEN", "65535")
	t.Setenv("TRUSTIX_LAN_REINJECT_GSO_SCATTER_MAX_SEGMENTS", "2")
	run, _, _, ok = lanIPv4TCPGSOScatterRun([][]byte{packetA, packetB, packetC}, 1500)
	if !ok || run != 2 {
		t.Fatalf("scatter run with segment limit ok=%v run=%d, want two packets", ok, run)
	}
}

func TestPrepareLANIPv4TCPGSOScatterHeaderLeavesPacketUnchanged(t *testing.T) {
	packet := lanTCPIPv4PacketForTest(bytes.Repeat([]byte{0xaa}, 700), 0x10, 20)
	original := append([]byte(nil), packet...)
	_, meta, _, ok := lanIPv4TCPGSOScatterRun([][]byte{
		packet,
		lanTCPIPv4PacketForTest(bytes.Repeat([]byte{0xbb}, 700), 0x10, 20),
	}, 1500)
	if ok {
		t.Fatal("test setup should not produce a contiguous run before sequence adjustment")
	}
	meta, err := lanIPv4TCPSegmentationMeta(packet, 1500)
	if err != nil {
		t.Fatalf("segmentation meta: %v", err)
	}
	var hdr [virtioNetHdrLen]byte
	out, err := prepareLANIPv4TCPGSOScatterHeader(hdr[:], packet, meta, 1500, 1440, true)
	if err != nil {
		t.Fatalf("prepare scatter header: %v", err)
	}
	if len(out) != virtioNetHdrLen {
		t.Fatalf("scatter header len = %d, want %d", len(out), virtioNetHdrLen)
	}
	if out[0] != unix.VIRTIO_NET_HDR_F_NEEDS_CSUM || out[1] != unix.VIRTIO_NET_HDR_GSO_TCPV4 {
		t.Fatalf("scatter virtio flags/gso_type = %#x/%#x", out[0], out[1])
	}
	if got, want := binary.LittleEndian.Uint16(out[2:4]), uint16(ethernetHeaderLen+40); got != want {
		t.Fatalf("scatter hdr_len = %d, want %d", got, want)
	}
	if !bytes.Equal(packet, original) {
		t.Fatal("prepare scatter header mutated source packet")
	}
}

func TestResolveIPv4NeighborPrefersVethPeerMAC(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create veth pair")
	}
	suffix := fmt.Sprintf("%03d%04x", os.Getpid()%1000, testVethNameCounter.Add(1)&0xffff)
	hostName := "tixh" + suffix
	peerName := "tixp" + suffix
	hostMAC := net.HardwareAddr{0x02, 0x54, 0x49, 0x58, byte(testVethNameCounter.Load() >> 8), byte(testVethNameCounter.Load())}
	peerMAC := net.HardwareAddr{0x02, 0x54, 0x49, 0x59, byte(testVethNameCounter.Load() >> 8), byte(testVethNameCounter.Load())}
	_ = netlink.LinkDel(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: hostName}})
	t.Cleanup(func() {
		_ = netlink.LinkDel(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: hostName}})
		_ = netlink.LinkDel(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: peerName}})
	})

	if err := netlink.LinkAdd(&netlink.Veth{
		LinkAttrs:        netlink.LinkAttrs{Name: hostName, HardwareAddr: hostMAC},
		PeerName:         peerName,
		PeerHardwareAddr: peerMAC,
	}); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("requires CAP_NET_ADMIN to create veth pair: %v", err)
		}
		t.Fatalf("create veth pair: %v", err)
	}
	host, err := netlink.LinkByName(hostName)
	if err != nil {
		t.Fatalf("inspect host veth: %v", err)
	}
	peer, err := netlink.LinkByName(peerName)
	if err != nil {
		t.Fatalf("inspect peer veth: %v", err)
	}
	if len(host.Attrs().HardwareAddr) != 6 || len(peer.Attrs().HardwareAddr) != 6 {
		t.Fatalf("veth pair missing hardware addresses: host=%s peer=%s", host.Attrs().HardwareAddr, peer.Attrs().HardwareAddr)
	}

	manager := &Manager{neighborCache: newNeighborCache()}
	got, err := manager.resolveIPv4Neighbor(host.Attrs().Index, netip.MustParseAddr("10.255.254.2"))
	if err != nil {
		t.Fatalf("resolve veth neighbor: %v", err)
	}
	peer, err = netlink.LinkByName(peerName)
	if err != nil {
		t.Fatalf("refresh peer veth after resolve: %v", err)
	}
	if !hardwareAddrEqual6(got, peer.Attrs().HardwareAddr) {
		target, warning := vethPeerOffloadTarget(host)
		byIndex, byIndexErr := netlink.LinkByIndex(host.Attrs().ParentIndex)
		byName, byNameErr := netlink.LinkByName(peerName)
		t.Fatalf("resolved MAC = %s, want peer %s; host=%s idx=%d parent=%d peer=%s idx=%d parent=%d target=%+v warning=%q byIndex=%s/%v byName=%s/%v",
			got, peer.Attrs().HardwareAddr,
			host.Attrs().HardwareAddr, host.Attrs().Index, host.Attrs().ParentIndex,
			peer.Attrs().HardwareAddr, peer.Attrs().Index, peer.Attrs().ParentIndex,
			target, warning, linkDebugString(byIndex), byIndexErr, linkDebugString(byName), byNameErr)
	}
	if hardwareAddrEqual6(got, host.Attrs().HardwareAddr) {
		t.Fatalf("resolved own veth MAC %s, want peer %s", got, peer.Attrs().HardwareAddr)
	}
	cached, ok := manager.neighborCache.lookup(host.Attrs().Index, netip.MustParseAddr("10.255.254.2"))
	if !ok || !hardwareAddrEqual6(cached, net.HardwareAddr(peer.Attrs().HardwareAddr)) {
		t.Fatalf("cached MAC = %s ok=%v, want peer %s", cached, ok, peer.Attrs().HardwareAddr)
	}
}

func linkDebugString(link netlink.Link) string {
	if link == nil || link.Attrs() == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s idx=%d parent=%d hw=%s", link.Attrs().Name, link.Attrs().Index, link.Attrs().ParentIndex, link.Attrs().HardwareAddr)
}

func TestNeighborCacheResolvedInvalidatesOnNextHopChange(t *testing.T) {
	cache := newNeighborCache()
	remote := netip.MustParseAddr("198.51.100.10")
	nextHop := netip.MustParseAddr("192.0.2.1")
	oldMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	newMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 2}
	const ifindex = 7

	cache.apply(netlink.Neigh{
		LinkIndex:    ifindex,
		IP:           net.IP(nextHop.AsSlice()),
		HardwareAddr: oldMAC,
		State:        netlink.NUD_REACHABLE,
	}, false)
	cache.rememberResolved(ifindex, remote, nextHop, oldMAC, time.Now())
	got, ok := cache.lookupResolved(ifindex, remote, time.Now())
	if !ok || !hardwareAddrEqual6(got, oldMAC) {
		t.Fatalf("resolved cache = %s ok=%v, want old MAC %s", got, ok, oldMAC)
	}

	cache.apply(netlink.Neigh{
		LinkIndex:    ifindex,
		IP:           net.IP(nextHop.AsSlice()),
		HardwareAddr: oldMAC,
		State:        netlink.NUD_REACHABLE,
	}, false)
	got, ok = cache.lookupResolved(ifindex, remote, time.Now())
	if !ok || !hardwareAddrEqual6(got, oldMAC) {
		t.Fatalf("unchanged neighbor invalidated resolved cache: got %s ok=%v", got, ok)
	}

	cache.apply(netlink.Neigh{
		LinkIndex:    ifindex,
		IP:           net.IP(nextHop.AsSlice()),
		HardwareAddr: newMAC,
		State:        netlink.NUD_REACHABLE,
	}, false)
	if got, ok := cache.lookupResolved(ifindex, remote, time.Now()); ok {
		t.Fatalf("resolved cache survived changed next-hop MAC: got %s", got)
	}
	got, ok = cache.lookup(ifindex, nextHop)
	if !ok || !hardwareAddrEqual6(got, newMAC) {
		t.Fatalf("neighbor cache = %s ok=%v, want new MAC %s", got, ok, newMAC)
	}
}

func TestResolveIPv4NeighborViaUsesExplicitNextHop(t *testing.T) {
	cache := newNeighborCache()
	remote := netip.MustParseAddr("198.51.100.10")
	nextHop := netip.MustParseAddr("192.0.2.1")
	remoteMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	gatewayMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 2}
	const ifindex = 7

	cache.apply(netlink.Neigh{
		LinkIndex:    ifindex,
		IP:           net.IP(remote.AsSlice()),
		HardwareAddr: remoteMAC,
		State:        netlink.NUD_REACHABLE,
	}, false)
	cache.apply(netlink.Neigh{
		LinkIndex:    ifindex,
		IP:           net.IP(nextHop.AsSlice()),
		HardwareAddr: gatewayMAC,
		State:        netlink.NUD_REACHABLE,
	}, false)

	manager := &Manager{neighborCache: cache}
	got, err := manager.resolveIPv4NeighborVia(ifindex, remote, nextHop)
	if err != nil {
		t.Fatalf("resolve explicit next-hop neighbor: %v", err)
	}
	if !hardwareAddrEqual6(got, gatewayMAC) {
		t.Fatalf("resolved MAC = %s, want gateway %s", got, gatewayMAC)
	}
	cached, ok := cache.lookupResolved(ifindex, remote, time.Now())
	if !ok || !hardwareAddrEqual6(cached, gatewayMAC) {
		t.Fatalf("resolved cache = %s ok=%v, want gateway %s", cached, ok, gatewayMAC)
	}
}

func TestLearnNeighborSyncsKernelUDPRXDirectMap(t *testing.T) {
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_learn_neigh_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 16})
	defer neighMap.Close()

	sourceMAC := [6]byte{0x02, 0x20, 0x21, 0x22, 0x23, 0x24}
	dstMAC := net.HardwareAddr{0x02, 0x10, 0x11, 0x12, 0x13, 0x14}
	addr := netip.MustParseAddr("10.0.1.2")
	const ifindex = 17

	manager := &Manager{
		neighborCache:                   newNeighborCache(),
		kernelUDPRXNeighMap:             neighMap,
		kernelUDPRXDirectLANIfindex:     ifindex,
		kernelUDPRXDirectSourceMAC:      sourceMAC,
		kernelUDPRXDirectDestinationMAC: [6]byte{},
	}
	manager.learnNeighbor(ifindex, addr, dstMAC)

	var got kernelUDPRXNeighValue
	if err := neighMap.Lookup(addr.As4(), &got); err != nil {
		t.Fatalf("lookup learned RX direct neighbor: %v", err)
	}
	if got.Ifindex != ifindex {
		t.Fatalf("learned ifindex = %d, want %d", got.Ifindex, ifindex)
	}
	if got.DestinationMAC0 != binary.LittleEndian.Uint32(dstMAC[0:4]) ||
		got.DestinationMAC1 != binary.LittleEndian.Uint16(dstMAC[4:6]) ||
		got.SourceMAC0 != binary.LittleEndian.Uint32(sourceMAC[0:4]) ||
		got.SourceMAC1 != binary.LittleEndian.Uint16(sourceMAC[4:6]) {
		t.Fatalf("learned RX direct neighbor value = %#v", got)
	}

	if err := neighMap.Delete(addr.As4()); err != nil {
		t.Fatalf("delete learned RX direct neighbor: %v", err)
	}
	manager.learnNeighbor(ifindex, addr, dstMAC)
	if err := neighMap.Lookup(addr.As4(), &got); err != nil {
		t.Fatalf("lookup resynced cached RX direct neighbor: %v", err)
	}
}

func TestSyncKernelUDPRXDirectNeighborsFromCacheRefillsMap(t *testing.T) {
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_kudp_rx_refill_neigh_test", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 16})
	defer neighMap.Close()

	sourceMAC := [6]byte{0x02, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4}
	dstMAC := net.HardwareAddr{0x02, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4}
	addr := netip.MustParseAddr("10.0.1.2")
	const ifindex = 23

	cache := newNeighborCache()
	cache.entries[neighborKey{linkIndex: ifindex, addr: addr}] = append(net.HardwareAddr(nil), dstMAC...)
	cache.entries[neighborKey{linkIndex: ifindex + 1, addr: netip.MustParseAddr("10.0.2.2")}] = net.HardwareAddr{0x02, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4}
	manager := &Manager{
		neighborCache:               cache,
		kernelUDPRXNeighMap:         neighMap,
		kernelUDPRXDirectLANIfindex: ifindex,
		kernelUDPRXDirectSourceMAC:  sourceMAC,
	}

	manager.syncKernelUDPRXDirectNeighborsFromCache(ifindex)

	var got kernelUDPRXNeighValue
	if err := neighMap.Lookup(addr.As4(), &got); err != nil {
		t.Fatalf("lookup refilled RX direct neighbor: %v", err)
	}
	if got.Ifindex != ifindex ||
		got.DestinationMAC0 != binary.LittleEndian.Uint32(dstMAC[0:4]) ||
		got.DestinationMAC1 != binary.LittleEndian.Uint16(dstMAC[4:6]) {
		t.Fatalf("refilled RX direct neighbor value = %#v", got)
	}
	var unexpected kernelUDPRXNeighValue
	if err := neighMap.Lookup(netip.MustParseAddr("10.0.2.2").As4(), &unexpected); err == nil {
		t.Fatalf("refilled neighbor from wrong ifindex: %#v", unexpected)
	}
}

func TestSegmentLANIPv4TCPPacketRejectsUnsupportedLargePackets(t *testing.T) {
	tests := []struct {
		name string
		make func() []byte
		mtu  int
	}{
		{
			name: "non TCP",
			make: func() []byte {
				packet := make([]byte, 20+8+1600)
				packet[0] = 0x45
				packet[8] = 64
				packet[9] = ipProtocolUDP
				binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
				copy(packet[12:16], []byte{10, 0, 0, 2})
				copy(packet[16:20], []byte{10, 0, 1, 2})
				return packet
			},
			mtu: 1500,
		},
		{
			name: "SYN",
			make: func() []byte {
				return lanTCPIPv4PacketForTest(bytes.Repeat([]byte{0xcd}, 1600), 0x12, 20)
			},
			mtu: 1500,
		},
		{
			name: "no payload",
			make: func() []byte {
				return lanTCPIPv4PacketForTest(nil, 0x10, 60)
			},
			mtu: 70,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := segmentLANIPv4TCPPacket(tt.make(), tt.mtu); !errors.Is(err, errMTUExceeded) {
				t.Fatalf("segment error = %v, want MTU exceeded", err)
			}
		})
	}
}

func lanTCPIPv4PacketForTest(payload []byte, flags byte, tcpHeaderLen int) []byte {
	packet := make([]byte, 20+tcpHeaderLen+len(payload))
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = ipProtocolTCP
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[4:6], 0x1234)
	binary.BigEndian.PutUint16(packet[6:8], 0x4000)
	copy(packet[12:16], []byte{10, 0, 0, 2})
	copy(packet[16:20], []byte{10, 0, 1, 2})
	tcp := packet[20:]
	binary.BigEndian.PutUint16(tcp[0:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	binary.BigEndian.PutUint32(tcp[4:8], 0x01020304)
	binary.BigEndian.PutUint32(tcp[8:12], 0x05060708)
	tcp[12] = byte(tcpHeaderLen/4) << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 0xffff)
	for i := 20; i < tcpHeaderLen; i++ {
		tcp[i] = byte(i)
	}
	copy(tcp[tcpHeaderLen:], payload)
	binary.BigEndian.PutUint16(packet[10:12], captureChecksum(packet[:20]))
	binary.BigEndian.PutUint16(tcp[16:18], captureTransportChecksum(packet[12:16], packet[16:20], ipProtocolTCP, tcp))
	return packet
}

func setLANTCPIPv4SequenceForTest(packet []byte, sequence uint32) {
	binary.BigEndian.PutUint32(packet[24:28], sequence)
	binary.BigEndian.PutUint16(packet[10:12], 0)
	binary.BigEndian.PutUint16(packet[10:12], captureChecksum(packet[:20]))
	tcp := packet[20:]
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	binary.BigEndian.PutUint16(tcp[16:18], captureTransportChecksum(packet[12:16], packet[16:20], ipProtocolTCP, tcp))
}

func TestNormalizedIPv4PayloadForInjectionFixesPartialTCPChecksum(t *testing.T) {
	packet := lanTCPIPv4PacketForTest([]byte("local-inject"), 0x18, 20)
	tcp := packet[20:]
	binary.BigEndian.PutUint16(tcp[16:18], tcpPseudoHeaderPartialChecksum(packet, len(tcp)))
	original := append([]byte(nil), packet...)

	normalized, dst, err := normalizedIPv4PayloadForInjection(ethernetIPv4FrameForNeighborTest(packet))
	if err != nil {
		t.Fatalf("normalize injection payload: %v", err)
	}
	if dst != netip.MustParseAddr("10.0.1.2").As4() {
		t.Fatalf("destination = %s, want 10.0.1.2", netip.AddrFrom4(dst))
	}
	if !bytes.Equal(packet, original) {
		t.Fatal("normalization mutated caller packet buffer")
	}
	assertLANIPv4TCPChecksumValid(t, normalized)
}

func ethernetIPv4FrameForNeighborTest(packet []byte) []byte {
	frame := make([]byte, ethernetHeaderLen+len(packet))
	copy(frame[0:6], []byte{0x02, 0, 0, 0, 0, 2})
	copy(frame[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)
	copy(frame[ethernetHeaderLen:], packet)
	return frame
}

func assertLANIPv4TCPChecksumValid(t *testing.T, packet []byte) {
	t.Helper()
	if len(packet) < 40 {
		t.Fatalf("packet length = %d, want at least 40", len(packet))
	}
	ihl := int(packet[0]&0x0f) * 4
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen != len(packet) || ihl != 20 || packet[9] != ipProtocolTCP {
		t.Fatalf("invalid IPv4/TCP test packet: ihl=%d total=%d len=%d proto=%d", ihl, totalLen, len(packet), packet[9])
	}
	if got := captureChecksum(packet[:ihl]); got != 0 {
		t.Fatalf("IPv4 checksum = %#04x, want valid", got)
	}
	tcp := packet[ihl:]
	sum := captureChecksumAddBytes(0, packet[12:16])
	sum = captureChecksumAddBytes(sum, packet[16:20])
	sum = captureChecksumAddBytes(sum, []byte{0, ipProtocolTCP, byte(len(tcp) >> 8), byte(len(tcp))})
	sum = captureChecksumAddBytes(sum, tcp)
	if got := captureChecksumFold(sum); got != 0 {
		t.Fatalf("TCP checksum = %#04x, want valid", got)
	}
}
