package daemon

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/kernelmodule"
	"trustix.local/trustix/internal/observability"
	"trustix.local/trustix/internal/routing"
	rstate "trustix.local/trustix/internal/runtime"
	"trustix.local/trustix/internal/transport"
	securetransport "trustix.local/trustix/internal/transport/secure"
)

func TestFlowKeyFromIPv4PacketParsesTCPFiveTuple(t *testing.T) {
	packet := tcpIPv4Packet()

	key, ok := flowKeyFromIPv4Packet(packet)
	if !ok {
		t.Fatal("expected flow key")
	}
	if key.SourceIP != netip.MustParseAddr("10.0.0.2") || key.DestinationIP != netip.MustParseAddr("10.0.1.2") {
		t.Fatalf("flow addresses = %s -> %s", key.SourceIP, key.DestinationIP)
	}
	if key.Protocol != 6 || key.SourcePort != 12345 || key.DestinationPort != 443 {
		t.Fatalf("flow transport = proto %d %d -> %d", key.Protocol, key.SourcePort, key.DestinationPort)
	}
}

func TestFlowKeyFromIPv4PacketAcceptsEthernetFrame(t *testing.T) {
	ipPacket := tcpIPv4Packet()
	frame := make([]byte, 14+len(ipPacket))
	binary.BigEndian.PutUint16(frame[12:14], ethPIPv4)
	copy(frame[14:], ipPacket)

	key, ok := flowKeyFromIPv4Packet(frame)
	if !ok {
		t.Fatal("expected flow key")
	}
	if key.SourcePort != 12345 || key.DestinationPort != 443 {
		t.Fatalf("flow transport = %d -> %d", key.SourcePort, key.DestinationPort)
	}
}

func TestCaptureForwarderWorkerIndexKeepsFlowSticky(t *testing.T) {
	event := dataplane.CaptureEvent{
		Hook:    "lan_ingress_route_hit",
		Payload: tcpIPv4Packet(),
	}

	first := captureForwarderWorkerIndex(event, 4, 0)
	for fallback := uint64(1); fallback < 32; fallback++ {
		if got := captureForwarderWorkerIndex(event, 4, fallback); got != first {
			t.Fatalf("worker index changed with fallback=%d: got %d want %d", fallback, got, first)
		}
	}
}

func TestCaptureForwarderWorkerIndexFallsBackRoundRobin(t *testing.T) {
	event := dataplane.CaptureEvent{Hook: "lan_ingress_route_hit", Payload: []byte{0xff}}

	for fallback := uint64(0); fallback < 8; fallback++ {
		if got := captureForwarderWorkerIndex(event, 4, fallback); got != int(fallback%4) {
			t.Fatalf("fallback worker index for %d = %d, want %d", fallback, got, fallback%4)
		}
	}
}

func TestForwardCaptureEventDropsFragmentedPacketWhenPolicyRequires(t *testing.T) {
	packet := tcpIPv4Packet()
	binary.BigEndian.PutUint16(packet[6:8], ipv4MoreFragments)
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{FragmentPolicy: "drop"},
		},
	}

	err := daemon.forwardCaptureEvent(context.Background(), dataplane.CaptureEvent{
		Hook:          "lan_ingress_route_hit",
		PacketLength:  uint32(len(packet)),
		SampleLength:  uint32(len(packet)),
		DestinationIP: "10.0.1.2",
		Payload:       packet,
	})
	if err == nil {
		t.Fatal("expected fragmented packet to be rejected")
	}
	drops := daemon.dataStats.dropReasonSnapshot()
	if drops[observability.DropFragmentedPacket] != 1 {
		t.Fatalf("drop reasons = %#v, want FRAGMENTED_PACKET", drops)
	}
}

func TestForwardCaptureEventAppliesConfiguredMTU(t *testing.T) {
	packet := tcpIPv4Packet()
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{MTU: len(packet) - 1},
		},
	}

	err := daemon.forwardCaptureEvent(context.Background(), dataplane.CaptureEvent{
		Hook:          "lan_ingress_route_hit",
		PacketLength:  uint32(len(packet)),
		SampleLength:  uint32(len(packet)),
		DestinationIP: "10.0.1.2",
		Payload:       packet,
	})
	if err == nil {
		t.Fatal("expected packet above configured mtu to be rejected")
	}
	drops := daemon.dataStats.dropReasonSnapshot()
	if drops[observability.DropMTUExceeded] != 1 {
		t.Fatalf("drop reasons = %#v, want MTU_EXCEEDED", drops)
	}
}

func TestCapturedPacketMTULengthUsesGSOSegmentLength(t *testing.T) {
	payload := make([]byte, 8192)
	packet := tcpPayloadIPv4Packet(payload)
	frame := ethernetIPv4Frame(packet)
	event := dataplane.CaptureEvent{
		PacketLength:     uint32(len(frame)),
		SampleLength:     uint32(len(frame)),
		GSOSegmentLength: 1200,
		Payload:          frame,
	}

	if got, want := capturedPacketLength(event), len(packet); got != want {
		t.Fatalf("captured packet length = %d, want full packet %d", got, want)
	}
	if got, want := capturedPacketMTULength(event), 20+20+1200; got != want {
		t.Fatalf("captured MTU length = %d, want GSO segment length %d", got, want)
	}
}

func TestCapturedPacketMTUAllowsSegmentableTCP(t *testing.T) {
	packet := tcpPayloadIPv4Packet(bytes.Repeat([]byte{0x7a}, 3600))
	event := dataplane.CaptureEvent{
		PacketLength: uint32(len(packet)),
		SampleLength: uint32(len(packet)),
		Payload:      packet,
	}

	if got := capturedPacketMTULength(event); got <= 1400 {
		t.Fatalf("captured MTU length = %d, want over configured MTU", got)
	}
	if capturedPacketExceedsMTU(event, 1400) {
		t.Fatal("segmentable TCP payload was treated as an MTU drop")
	}
}

func TestCapturedPacketMTUDropsUnsegmentableTCP(t *testing.T) {
	packet := tcpIPv4Packet()
	event := dataplane.CaptureEvent{
		PacketLength: uint32(len(packet)),
		SampleLength: uint32(len(packet)),
		Payload:      packet,
	}

	if !capturedPacketExceedsMTU(event, len(packet)-1) {
		t.Fatal("unsegmentable TCP packet above MTU was not treated as an MTU drop")
	}
}

func TestForwardCaptureEventDropsBlackholeRoutes(t *testing.T) {
	table := routing.NewTable()
	if err := table.Replace([]routing.Route{{
		Prefix: "10.0.1.0/24",
		Kind:   routing.RouteBlackhole,
		Metric: 10,
	}}); err != nil {
		t.Fatalf("replace routes: %v", err)
	}
	daemon := &Daemon{routes: table}

	err := daemon.forwardCaptureEvent(context.Background(), dataplane.CaptureEvent{
		Hook:          "lan_ingress_route_hit",
		PacketLength:  uint32(len(tcpIPv4Packet())),
		SampleLength:  uint32(len(tcpIPv4Packet())),
		DestinationIP: "10.0.1.2",
		Payload:       tcpIPv4Packet(),
	})
	if err == nil {
		t.Fatal("expected blackhole route to be dropped")
	}
	drops := daemon.dataStats.dropReasonSnapshot()
	if drops[observability.DropBlackholeRoute] != 1 {
		t.Fatalf("drop reasons = %#v, want BLACKHOLE_ROUTE", drops)
	}
}

func TestForwardCaptureEventRejectRouteSendsTCPReset(t *testing.T) {
	table := routing.NewTable()
	if err := table.Replace([]routing.Route{{
		Prefix: "10.0.1.0/24",
		Kind:   routing.RouteReject,
		Metric: 10,
	}}); err != nil {
		t.Fatalf("replace routes: %v", err)
	}
	injector := &recordingLANInjector{}
	daemon := &Daemon{routes: table, dataplane: injector}
	packet := normalizeCapturedIPv4Checksums(tcpPayloadIPv4Packet([]byte("blocked")))

	err := daemon.forwardCaptureEvent(context.Background(), dataplane.CaptureEvent{
		Hook:          "lan_ingress_route_hit",
		PacketLength:  uint32(len(packet)),
		SampleLength:  uint32(len(packet)),
		DestinationIP: "10.0.1.2",
		Payload:       packet,
	})
	if err == nil {
		t.Fatal("expected reject route to stop original packet")
	}
	if len(injector.packets) != 1 {
		t.Fatalf("injected replies = %d, want 1", len(injector.packets))
	}
	reply := injector.packets[0]
	if reply[9] != ipProtocolTCP {
		t.Fatalf("reply protocol = %d, want TCP", reply[9])
	}
	tcp := reply[20:]
	if tcp[13]&tcpFlagRST == 0 {
		t.Fatalf("TCP flags = %#x, want RST", tcp[13])
	}
	if got := netip.AddrFrom4([4]byte{reply[16], reply[17], reply[18], reply[19]}); got != netip.MustParseAddr("10.0.0.2") {
		t.Fatalf("reply destination = %s, want original source", got)
	}
	if injector.destinations[0] != netip.MustParseAddr("10.0.0.2") {
		t.Fatalf("inject destination = %s, want original source", injector.destinations[0])
	}
	if !validTransportChecksumForTest(reply, tcp) {
		t.Fatalf("TCP RST checksum invalid")
	}
	counters := daemon.dataStats.snapshot()
	if counters.RejectRSTGenerated != 1 || counters.RejectICMPGenerated != 0 || counters.RejectReplyErrors != 0 || counters.PacketsInjected != 1 {
		t.Fatalf("reject counters = %#v", counters)
	}
}

func TestForwardCaptureEventRejectRouteSendsICMPUnreachable(t *testing.T) {
	table := routing.NewTable()
	if err := table.Replace([]routing.Route{{
		Prefix: "10.0.1.0/24",
		Kind:   routing.RouteReject,
		Metric: 10,
	}}); err != nil {
		t.Fatalf("replace routes: %v", err)
	}
	injector := &recordingLANInjector{}
	daemon := &Daemon{routes: table, dataplane: injector}
	packet := normalizeCapturedIPv4Checksums(udpIPv4Packet([]byte("blocked")))

	err := daemon.forwardCaptureEvent(context.Background(), dataplane.CaptureEvent{
		Hook:          "lan_ingress_route_hit",
		PacketLength:  uint32(len(packet)),
		SampleLength:  uint32(len(packet)),
		DestinationIP: "10.0.1.2",
		Payload:       packet,
	})
	if err == nil {
		t.Fatal("expected reject route to stop original packet")
	}
	if len(injector.packets) != 1 {
		t.Fatalf("injected replies = %d, want 1", len(injector.packets))
	}
	reply := injector.packets[0]
	if reply[9] != ipProtocolICMP || reply[20] != icmpTypeDestinationUnreachable || reply[21] != icmpCodeHostUnreachable {
		t.Fatalf("ICMP reply header = proto:%d type:%d code:%d", reply[9], reply[20], reply[21])
	}
	if got := ipv4Checksum(reply[:20]); got != 0 {
		t.Fatalf("ICMP reply IPv4 checksum = %#04x, want valid", got)
	}
	if got := ipv4Checksum(reply[20:]); got != 0 {
		t.Fatalf("ICMP checksum = %#04x, want valid", got)
	}
	counters := daemon.dataStats.snapshot()
	if counters.RejectICMPGenerated != 1 || counters.RejectRSTGenerated != 0 || counters.RejectReplyErrors != 0 || counters.PacketsInjected != 1 {
		t.Fatalf("reject counters = %#v", counters)
	}
}

func TestRejectReplySkipsTCPRSTAndICMPErrors(t *testing.T) {
	rst := tcpPayloadIPv4Packet(nil)
	rst[33] = tcpFlagRST
	rst = normalizeCapturedIPv4Checksums(rst)
	if reply, _, kind, err := rejectReplyPacket(rst); err != nil || kind != rejectReplyNone || len(reply) != 0 {
		t.Fatalf("TCP RST reject reply = len:%d kind:%d err:%v, want none", len(reply), kind, err)
	}

	icmpError := make([]byte, 28)
	icmpError[0] = 0x45
	icmpError[8] = 64
	icmpError[9] = ipProtocolICMP
	binary.BigEndian.PutUint16(icmpError[2:4], uint16(len(icmpError)))
	copy(icmpError[12:16], []byte{10, 0, 0, 2})
	copy(icmpError[16:20], []byte{10, 0, 1, 2})
	icmpError[20] = icmpTypeDestinationUnreachable
	icmpError = normalizeCapturedIPv4Checksums(icmpError)
	if reply, _, kind, err := rejectReplyPacket(icmpError); err != nil || kind != rejectReplyNone || len(reply) != 0 {
		t.Fatalf("ICMP error reject reply = len:%d kind:%d err:%v, want none", len(reply), kind, err)
	}
}

func TestLocalICMPEchoReplyPacket(t *testing.T) {
	packet := normalizeCapturedIPv4Checksums(icmpEchoIPv4Packet([]byte("gateway ping")))
	reply, destination, ok, err := localICMPEchoReplyPacket(packet)
	if err != nil {
		t.Fatalf("local ICMP echo reply: %v", err)
	}
	if !ok {
		t.Fatal("expected ICMP echo request to produce a reply")
	}
	if destination != netip.MustParseAddr("10.0.0.2") {
		t.Fatalf("reply destination = %s, want original source", destination)
	}
	if got := netip.AddrFrom4([4]byte{reply[12], reply[13], reply[14], reply[15]}); got != netip.MustParseAddr("10.0.1.2") {
		t.Fatalf("reply source = %s, want original destination", got)
	}
	if got := netip.AddrFrom4([4]byte{reply[16], reply[17], reply[18], reply[19]}); got != netip.MustParseAddr("10.0.0.2") {
		t.Fatalf("reply destination IP = %s, want original source", got)
	}
	if reply[20] != icmpTypeEchoReply || reply[21] != 0 {
		t.Fatalf("ICMP reply type/code = %d/%d, want echo reply", reply[20], reply[21])
	}
	if got := ipv4Checksum(reply[:20]); got != 0 {
		t.Fatalf("reply IPv4 checksum = %#04x, want valid", got)
	}
	if got := ipv4Checksum(reply[20:]); got != 0 {
		t.Fatalf("reply ICMP checksum = %#04x, want valid", got)
	}
	if !bytes.Equal(reply[28:], []byte("gateway ping")) {
		t.Fatalf("reply payload = %q", string(reply[28:]))
	}
}

func TestHandleReceivedDataPathPacketInjectsLocalGatewayReplyToHostStack(t *testing.T) {
	request := normalizeCapturedIPv4Checksums(icmpEchoIPv4Packet([]byte("gateway ping")))
	reply, _, ok, err := localICMPEchoReplyPacket(request)
	if err != nil || !ok {
		t.Fatalf("build echo reply: ok=%t err=%v", ok, err)
	}
	dataplane := &recordingLocalPacketDataplane{NoopManager: dataplane.NewNoopManager()}
	injector := &recordingInjector{}
	daemon := &Daemon{
		dataplane: dataplane,
		desired: config.Desired{
			LAN: config.LANConfig{
				Gateway:   "10.0.0.2/24",
				Advertise: []core.Prefix{"10.0.0.0/24"},
			},
		},
	}

	if err := daemon.handleReceivedDataPathPacket(context.Background(), reply, injector); err != nil {
		t.Fatalf("handle local gateway reply: %v", err)
	}
	if len(dataplane.localPackets) != 1 || !bytes.Equal(dataplane.localPackets[0], reply) {
		t.Fatalf("local host packets = %#v, want echo reply", dataplane.localPackets)
	}
	if len(injector.packets) != 0 || len(injector.batchPackets) != 0 {
		t.Fatalf("LAN injector used for local gateway reply: singles=%d batches=%d", len(injector.packets), len(injector.batchPackets))
	}
	counters := daemon.dataStats.snapshot()
	if counters.PacketsInjected != 1 || counters.InjectErrors != 0 {
		t.Fatalf("local gateway reply counters = %+v, want one injected no errors", counters)
	}
}

func TestForwardCaptureEventDropsBlackholeAndRejectRoutes(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind routing.RouteKind
		want observability.DropReason
	}{
		{name: "blackhole", kind: routing.RouteBlackhole, want: observability.DropBlackholeRoute},
		{name: "reject", kind: routing.RouteReject, want: observability.DropRejectRoute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			table := routing.NewTable()
			if err := table.Replace([]routing.Route{{
				Prefix: "10.0.1.0/24",
				Kind:   tc.kind,
				Metric: 10,
			}}); err != nil {
				t.Fatalf("replace routes: %v", err)
			}
			daemon := &Daemon{routes: table, dataplane: &recordingLANInjector{}}

			err := daemon.forwardCaptureEvent(context.Background(), dataplane.CaptureEvent{
				Hook:          "lan_ingress_route_hit",
				PacketLength:  uint32(len(tcpIPv4Packet())),
				SampleLength:  uint32(len(tcpIPv4Packet())),
				DestinationIP: "10.0.1.2",
				Payload:       tcpIPv4Packet(),
			})
			if err == nil {
				t.Fatal("expected non-unicast route to be dropped")
			}
			drops := daemon.dataStats.dropReasonSnapshot()
			if drops[tc.want] != 1 {
				t.Fatalf("drop reasons = %#v, want %s", drops, tc.want)
			}
		})
	}
}

func TestNormalizeCapturedIPv4ChecksumsFixesUDPEthernetFrame(t *testing.T) {
	frame := ethernetIPv4Frame(udpIPv4Packet([]byte("udp burst payload")))
	normalized := normalizeCapturedIPv4Checksums(frame)
	ip := normalized[14:]
	ihl := int(ip[0]&0x0f) * 4
	if got := ipv4Checksum(ip[:ihl]); got != 0 {
		t.Fatalf("IPv4 checksum after normalize = %#04x, want valid", got)
	}
	udp := ip[ihl:int(binary.BigEndian.Uint16(ip[2:4]))]
	if !validTransportChecksumForTest(ip, udp) {
		t.Fatalf("UDP checksum after normalize is invalid")
	}
	if binary.BigEndian.Uint16(udp[6:8]) == 0 {
		t.Fatalf("UDP checksum after normalize is zero")
	}
}

func TestNormalizeCapturedIPv4ChecksumsFixesTCPPacket(t *testing.T) {
	packet := tcpPayloadIPv4Packet([]byte("tcp burst payload"))
	normalized := normalizeCapturedIPv4Checksums(packet)
	ihl := int(normalized[0]&0x0f) * 4
	if got := ipv4Checksum(normalized[:ihl]); got != 0 {
		t.Fatalf("IPv4 checksum after normalize = %#04x, want valid", got)
	}
	tcp := normalized[ihl:int(binary.BigEndian.Uint16(normalized[2:4]))]
	if !validTransportChecksumForTest(normalized, tcp) {
		t.Fatalf("TCP checksum after normalize is invalid")
	}
}

func TestNormalizeCapturedIPv4ChecksumsFixesICMPPacket(t *testing.T) {
	packet := icmpEchoIPv4Packet([]byte("icmp burst payload"))
	normalized := normalizeCapturedIPv4Checksums(packet)
	ihl := int(normalized[0]&0x0f) * 4
	if got := ipv4Checksum(normalized[:ihl]); got != 0 {
		t.Fatalf("IPv4 checksum after normalize = %#04x, want valid", got)
	}
	icmp := normalized[ihl:int(binary.BigEndian.Uint16(normalized[2:4]))]
	if got := ipv4Checksum(icmp); got != 0 {
		t.Fatalf("ICMP checksum after normalize = %#04x, want valid", got)
	}
}

func TestNormalizeCapturedIPv4ChecksumsClampsTCPMSSWhenConfigured(t *testing.T) {
	t.Setenv("TRUSTIX_TCP_MSS_CLAMP", "1200")
	packet := tcpSYNIPv4PacketWithMSS(1460)

	normalized := normalizeCapturedIPv4Checksums(packet)
	ihl := int(normalized[0]&0x0f) * 4
	tcp := normalized[ihl:int(binary.BigEndian.Uint16(normalized[2:4]))]
	if got := tcpMSSOptionValue(t, tcp); got != 1200 {
		t.Fatalf("MSS option = %d, want 1200", got)
	}
	if !validTransportChecksumForTest(normalized, tcp) {
		t.Fatalf("TCP checksum after MSS clamp is invalid")
	}
}

func TestNormalizeCapturedIPv4ChecksumsDoesNotRaiseTCPMSS(t *testing.T) {
	t.Setenv("TRUSTIX_TCP_MSS_CLAMP", "1200")
	packet := tcpSYNIPv4PacketWithMSS(1000)

	normalized := normalizeCapturedIPv4Checksums(packet)
	ihl := int(normalized[0]&0x0f) * 4
	tcp := normalized[ihl:int(binary.BigEndian.Uint16(normalized[2:4]))]
	if got := tcpMSSOptionValue(t, tcp); got != 1000 {
		t.Fatalf("MSS option = %d, want unchanged 1000", got)
	}
}

func TestNormalizedCapturePayloadClampsMSSWhenAlreadyChecksumNormalized(t *testing.T) {
	t.Setenv("TRUSTIX_TCP_MSS_CLAMP", "1200")
	daemon := &Daemon{}
	packet := tcpSYNIPv4PacketWithMSS(1460)

	normalized := daemon.normalizedCapturePayload(dataplane.CaptureEvent{
		Payload:            packet,
		ChecksumNormalized: true,
	})
	ihl := int(normalized[0]&0x0f) * 4
	tcp := normalized[ihl:int(binary.BigEndian.Uint16(normalized[2:4]))]
	if got := tcpMSSOptionValue(t, tcp); got != 1200 {
		t.Fatalf("MSS option = %d, want 1200", got)
	}
	if !validTransportChecksumForTest(normalized, tcp) {
		t.Fatalf("TCP checksum after MSS clamp is invalid")
	}
	if got := tcpMSSOptionValue(t, packet[ihl:int(binary.BigEndian.Uint16(packet[2:4]))]); got != 1460 {
		t.Fatalf("source packet MSS was mutated to %d", got)
	}
}

func TestNormalizedCapturePayloadStripsEthernetHeader(t *testing.T) {
	daemon := &Daemon{}
	packet := tcpIPv4Packet()
	frame := make([]byte, 14+len(packet))
	binary.BigEndian.PutUint16(frame[12:14], ethPIPv4)
	copy(frame[14:], packet)

	normalized := daemon.normalizedCapturePayload(dataplane.CaptureEvent{
		Payload:            frame,
		PacketLength:       uint32(len(frame)),
		ChecksumNormalized: true,
	})
	if !reflect.DeepEqual(normalized, packet) {
		t.Fatalf("normalized payload len=%d, want IPv4 len=%d", len(normalized), len(packet))
	}
	if got := capturedPacketLength(dataplane.CaptureEvent{Payload: frame, PacketLength: uint32(len(frame))}); got != len(packet) {
		t.Fatalf("captured packet length = %d, want %d", got, len(packet))
	}
}

func TestNormalizedForwardCapturePayloadMatchesNormalizeThenTTL(t *testing.T) {
	t.Setenv("TRUSTIX_TCP_MSS_CLAMP", "1200")
	daemon := &Daemon{}
	packet := tcpSYNIPv4PacketWithMSS(1460)
	frame := ethernetIPv4Frame(packet)
	event := dataplane.CaptureEvent{
		Payload:       frame,
		PacketLength:  uint32(len(frame)),
		SampleLength:  uint32(len(frame)),
		DestinationIP: "10.0.1.2",
	}

	normalized := daemon.normalizedCapturePayloadWithOptions(event, 1200, false)
	want, err := decrementIPv4TTL(normalized)
	if err != nil {
		t.Fatalf("decrement reference TTL: %v", err)
	}
	var scratch captureForwardScratch
	scratch.begin(1, daemon)
	got, err := daemon.normalizedForwardCapturePayload(event, 1200, false, &scratch)
	if err != nil {
		t.Fatalf("normalized forward payload: %v", err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("normalized forward payload differs from normalize+TTL")
	}
	ihl := int(got[0]&0x0f) * 4
	tcp := got[ihl:int(binary.BigEndian.Uint16(got[2:4]))]
	if gotMSS := tcpMSSOptionValue(t, tcp); gotMSS != 1200 {
		t.Fatalf("MSS option = %d, want 1200", gotMSS)
	}
	if !validTransportChecksumForTest(got, tcp) {
		t.Fatal("TCP checksum is invalid")
	}
	if packet[8] != 64 {
		t.Fatalf("source packet TTL mutated to %d", packet[8])
	}
}

func TestNormalizedForwardCapturePayloadCanMutateOwnedPayload(t *testing.T) {
	daemon := &Daemon{}
	packet := tcpPayloadIPv4Packet(nil)
	frame := ethernetIPv4Frame(packet)
	event := dataplane.CaptureEvent{
		Payload:            frame,
		PacketLength:       uint32(len(frame)),
		SampleLength:       uint32(len(frame)),
		ChecksumNormalized: true,
		PayloadMutable:     true,
	}

	var scratch captureForwardScratch
	scratch.begin(1, daemon)
	got, err := daemon.normalizedForwardCapturePayload(event, 0, false, &scratch)
	if err != nil {
		t.Fatalf("normalized forward payload: %v", err)
	}

	if len(scratch.packetArena) != 0 {
		t.Fatalf("packet arena len = %d, want no clone", len(scratch.packetArena))
	}
	if &got[0] != &frame[14] {
		t.Fatal("forward payload did not reuse owned capture payload")
	}
	if got[8] != 63 {
		t.Fatalf("forward TTL = %d, want 63", got[8])
	}
	if frame[14+8] != 63 {
		t.Fatalf("owned frame TTL = %d, want in-place decrement", frame[14+8])
	}
}

func TestReceiveInvalidPacketRecordsInjectErrorSummary(t *testing.T) {
	daemon := &Daemon{}
	packet := []byte{0xde, 0xad, 0xbe, 0xef}

	err := daemon.handleReceivedDataPathPacket(context.Background(), packet, &recordingInjector{})
	if err == nil {
		t.Fatal("handle invalid packet returned nil error")
	}
	counters := daemon.dataStats.snapshot()
	if counters.LastInjectError == "" {
		t.Fatal("last inject error was not recorded")
	}
	if !strings.Contains(counters.LastInjectError, "packet_len=4 head=deadbeef") {
		t.Fatalf("last inject error = %q, want packet summary", counters.LastInjectError)
	}
}

func TestPrepareCaptureForwardWireBatchCoalescesContiguousTCPSegments(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_TX_GSO_COALESCE", "1")
	t.Setenv("TRUSTIX_DATA_SESSION_TX_GSO_COALESCE_BYTES", "65535")
	daemon := &Daemon{}
	session := &recordingNativeBatchSession{stats: transport.TransportStats{
		NativeBatching:      true,
		Datagram:            true,
		FragmentingDatagram: true,
		Encrypted:           true,
		CryptoPlacement:     string(dataplane.CryptoPlacementKernel),
		MaxPacketSize:       65535,
	}}
	runtime := &dataSessionRuntime{session: session}
	var scratch captureForwardScratch
	scratch.begin(2, daemon)
	packetA := tcpPayloadIPv4PacketWithSeq(1, []byte("hello "))
	packetB := tcpPayloadIPv4PacketWithSeq(7, []byte("world"))
	batch := prepareCaptureForwardBatch([]captureForwardBatchCandidate{
		{Packet: packetA},
		{Packet: packetB},
	}, &scratch)

	wire := daemon.prepareCaptureForwardWireBatch(runtime, session, batch, &scratch)

	if len(wire.Packets) != 1 {
		t.Fatalf("wire packets = %d, want coalesced 1", len(wire.Packets))
	}
	if len(wire.Packets[0]) != len(packetA)+len("world") {
		t.Fatalf("coalesced len = %d", len(wire.Packets[0]))
	}
	if got := string(wire.Packets[0][40:]); got != "hello world" {
		t.Fatalf("coalesced payload = %q", got)
	}
	if !validTransportChecksumForTest(wire.Packets[0], wire.Packets[0][20:]) {
		t.Fatal("coalesced TCP checksum is invalid")
	}
	counters := daemon.dataStats.snapshot()
	if counters.SendGSOCoalesceBatches != 1 || counters.SendGSOCoalescePackets != 2 || counters.SendGSOCoalesceWires != 1 {
		t.Fatalf("TX GSO coalesce counters = %+v, want one 2-to-1 coalesce", counters)
	}
	if batch.Bytes != len(packetA)+len(packetB) {
		t.Fatalf("logical batch bytes mutated to %d", batch.Bytes)
	}
}

func TestPrepareCaptureForwardWireBatchRespectsSessionMaxPacketSize(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_TX_GSO_COALESCE", "1")
	daemon := &Daemon{}
	session := &recordingNativeBatchSession{stats: transport.TransportStats{
		NativeBatching:      true,
		Datagram:            true,
		FragmentingDatagram: true,
		Encrypted:           true,
		CryptoPlacement:     string(dataplane.CryptoPlacementKernel),
		MaxPacketSize:       44,
	}}
	runtime := &dataSessionRuntime{session: session}
	var scratch captureForwardScratch
	scratch.begin(2, daemon)
	packetA := tcpPayloadIPv4PacketWithSeq(1, []byte("hello"))
	packetB := tcpPayloadIPv4PacketWithSeq(6, []byte("world"))
	batch := prepareCaptureForwardBatch([]captureForwardBatchCandidate{
		{Packet: packetA},
		{Packet: packetB},
	}, &scratch)

	wire := daemon.prepareCaptureForwardWireBatch(runtime, session, batch, &scratch)

	if len(wire.Packets) != 2 {
		t.Fatalf("wire packets = %d, want uncoalesced 2", len(wire.Packets))
	}
	counters := daemon.dataStats.snapshot()
	if counters.SendGSOCoalesceBatches != 0 || counters.SendGSOCoalescePackets != 0 || counters.SendGSOCoalesceWires != 0 {
		t.Fatalf("TX GSO coalesce counters = %+v, want disabled by max packet size", counters)
	}
}

func TestPrepareCaptureForwardWireBatchCanDisableTXCoalesce(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_TX_GSO_COALESCE", "0")
	daemon := &Daemon{}
	session := &recordingNativeBatchSession{stats: transport.TransportStats{
		NativeBatching:      true,
		Datagram:            true,
		FragmentingDatagram: true,
		Encrypted:           true,
		CryptoPlacement:     string(dataplane.CryptoPlacementKernel),
		MaxPacketSize:       65535,
	}}
	runtime := &dataSessionRuntime{session: session}
	var scratch captureForwardScratch
	scratch.begin(2, daemon)
	packetA := tcpPayloadIPv4PacketWithSeq(1, []byte("hello"))
	packetB := tcpPayloadIPv4PacketWithSeq(6, []byte("world"))
	batch := prepareCaptureForwardBatch([]captureForwardBatchCandidate{
		{Packet: packetA},
		{Packet: packetB},
	}, &scratch)

	wire := daemon.prepareCaptureForwardWireBatch(runtime, session, batch, &scratch)

	if len(wire.Packets) != 2 {
		t.Fatalf("wire packets = %d, want uncoalesced 2", len(wire.Packets))
	}
	counters := daemon.dataStats.snapshot()
	if counters.SendGSOCoalesceBatches != 0 || counters.SendGSOCoalescePackets != 0 || counters.SendGSOCoalesceWires != 0 {
		t.Fatalf("TX GSO coalesce counters = %+v, want disabled", counters)
	}
}

func TestPrepareCaptureForwardWireBatchDefaultsToSmallTXCoalesceWindow(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_TX_GSO_COALESCE", "1")
	daemon := &Daemon{}
	session := &recordingNativeBatchSession{stats: transport.TransportStats{
		NativeBatching:      true,
		Datagram:            true,
		FragmentingDatagram: true,
		Encrypted:           true,
		CryptoPlacement:     string(dataplane.CryptoPlacementKernel),
		MaxPacketSize:       65535,
	}}
	runtime := &dataSessionRuntime{session: session}
	var scratch captureForwardScratch
	scratch.begin(3, daemon)
	payload := bytes.Repeat([]byte{0x7a}, 1460)
	packetA := tcpPayloadIPv4PacketWithSeq(1, payload)
	packetB := tcpPayloadIPv4PacketWithSeq(1461, payload)
	packetC := tcpPayloadIPv4PacketWithSeq(2921, payload)
	batch := prepareCaptureForwardBatch([]captureForwardBatchCandidate{
		{Packet: packetA},
		{Packet: packetB},
		{Packet: packetC},
	}, &scratch)

	wire := daemon.prepareCaptureForwardWireBatch(runtime, session, batch, &scratch)

	if len(wire.Packets) != 2 {
		t.Fatalf("wire packets = %d, want default small-window 3-to-2 coalesce", len(wire.Packets))
	}
	if len(wire.Packets[0]) != len(packetA)+len(payload) || len(wire.Packets[1]) != len(packetC) {
		t.Fatalf("wire packet lengths = %d,%d", len(wire.Packets[0]), len(wire.Packets[1]))
	}
	counters := daemon.dataStats.snapshot()
	if counters.SendGSOCoalesceBatches != 1 || counters.SendGSOCoalescePackets != 2 || counters.SendGSOCoalesceWires != 1 {
		t.Fatalf("TX GSO coalesce counters = %+v, want one 2-to-1 coalesce", counters)
	}
}

func TestPrepareCaptureForwardWireBatchDefaultsOffForPlaintext(t *testing.T) {
	daemon := &Daemon{}
	session := &recordingNativeBatchSession{stats: transport.TransportStats{
		NativeBatching:      true,
		Datagram:            true,
		FragmentingDatagram: true,
		MaxPacketSize:       65535,
	}}
	runtime := &dataSessionRuntime{session: session}
	var scratch captureForwardScratch
	scratch.begin(2, daemon)
	packetA := tcpPayloadIPv4PacketWithSeq(1, []byte("hello"))
	packetB := tcpPayloadIPv4PacketWithSeq(6, []byte("world"))
	batch := prepareCaptureForwardBatch([]captureForwardBatchCandidate{
		{Packet: packetA},
		{Packet: packetB},
	}, &scratch)

	wire := daemon.prepareCaptureForwardWireBatch(runtime, session, batch, &scratch)

	if len(wire.Packets) != 2 {
		t.Fatalf("wire packets = %d, want default plaintext uncoalesced 2", len(wire.Packets))
	}
	counters := daemon.dataStats.snapshot()
	if counters.SendGSOCoalesceBatches != 0 || counters.SendGSOCoalescePackets != 0 || counters.SendGSOCoalesceWires != 0 {
		t.Fatalf("TX GSO coalesce counters = %+v, want plaintext default disabled", counters)
	}
}

func TestPrepareCaptureForwardWireBatchDefaultsOffForKernelCrypto(t *testing.T) {
	daemon := &Daemon{}
	session := &recordingNativeBatchSession{stats: transport.TransportStats{
		NativeBatching:      true,
		Datagram:            true,
		FragmentingDatagram: true,
		Encrypted:           true,
		CryptoPlacement:     string(dataplane.CryptoPlacementKernel),
		MaxPacketSize:       65535,
	}}
	runtime := &dataSessionRuntime{session: session}
	var scratch captureForwardScratch
	scratch.begin(2, daemon)
	packetA := tcpPayloadIPv4PacketWithSeq(1, []byte("hello"))
	packetB := tcpPayloadIPv4PacketWithSeq(6, []byte("world"))
	batch := prepareCaptureForwardBatch([]captureForwardBatchCandidate{
		{Packet: packetA},
		{Packet: packetB},
	}, &scratch)

	wire := daemon.prepareCaptureForwardWireBatch(runtime, session, batch, &scratch)

	if len(wire.Packets) != 2 {
		t.Fatalf("wire packets = %d, want default kernel crypto uncoalesced 2", len(wire.Packets))
	}
	counters := daemon.dataStats.snapshot()
	if counters.SendGSOCoalesceBatches != 0 || counters.SendGSOCoalescePackets != 0 || counters.SendGSOCoalesceWires != 0 {
		t.Fatalf("TX GSO coalesce counters = %+v, want kernel crypto default disabled", counters)
	}
}

func TestHandleReceivedDataPathPacketInjectsLocalLAN(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			LAN: config.LANConfig{
				Advertise: []core.Prefix{"10.0.1.0/24"},
			},
		},
	}
	injector := &recordingInjector{}

	if err := daemon.handleReceivedDataPathPacket(context.Background(), tcpIPv4Packet(), injector); err != nil {
		t.Fatalf("handle received local packet: %v", err)
	}
	if len(injector.packets) != 1 {
		t.Fatalf("injected packets = %d, want 1", len(injector.packets))
	}
	if got := daemon.dataStats.snapshot().PacketsInjected; got != 1 {
		t.Fatalf("packets injected = %d, want 1", got)
	}
}

func TestOutboundNATSNATsToGatewayAndInboundDNATsBack(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			LAN: config.LANConfig{
				Gateway:   "10.0.0.1/24",
				Advertise: []core.Prefix{"10.0.0.0/24"},
				Mode:      config.LANModeNAT,
			},
			Routes: []config.RouteConfig{{
				Prefix:  "10.0.1.0/24",
				NextHop: "ix-b",
				Policy:  "default",
			}},
			Policies: []config.PolicyConfig{{Name: "default"}},
		},
		nat: newNATTable(),
	}
	packet := udpIPv4Packet([]byte("nat payload"))
	outbound, translated, err := daemon.applyOutboundNAT(packet, routing.Route{Kind: routing.RouteUnicast}, config.PolicyConfig{})
	if err != nil {
		t.Fatalf("apply outbound nat: %v", err)
	}
	if !translated {
		t.Fatal("expected outbound packet to be translated")
	}
	if got := netip.AddrFrom4([4]byte{outbound[12], outbound[13], outbound[14], outbound[15]}); got != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("outbound source = %s, want gateway", got)
	}
	ihl := int(outbound[0]&0x0f) * 4
	if got := ipv4Checksum(outbound[:ihl]); got != 0 {
		t.Fatalf("outbound IPv4 checksum = %#04x, want valid", got)
	}
	if !validTransportChecksumForTest(outbound, outbound[ihl:int(binary.BigEndian.Uint16(outbound[2:4]))]) {
		t.Fatalf("outbound UDP checksum invalid")
	}

	reply := udpIPv4Packet([]byte("nat reply"))
	copy(reply[12:16], []byte{10, 0, 1, 2})
	copy(reply[16:20], []byte{10, 0, 0, 1})
	udp := reply[20:]
	binary.BigEndian.PutUint16(udp[0:2], 18100)
	binary.BigEndian.PutUint16(udp[2:4], 12345)
	reply = normalizeCapturedIPv4Checksums(reply)
	inbound, hit, err := daemon.applyInboundNAT(reply)
	if err != nil {
		t.Fatalf("apply inbound nat: %v", err)
	}
	if !hit {
		t.Fatal("expected inbound packet to hit NAT state")
	}
	if got := netip.AddrFrom4([4]byte{inbound[16], inbound[17], inbound[18], inbound[19]}); got != netip.MustParseAddr("10.0.0.2") {
		t.Fatalf("inbound destination = %s, want original host", got)
	}
	if !validTransportChecksumForTest(inbound, inbound[ihl:int(binary.BigEndian.Uint16(inbound[2:4]))]) {
		t.Fatalf("inbound UDP checksum invalid")
	}
}

func TestPolicyRewriteEnablesNATWithoutLANModeNAT(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			LAN: config.LANConfig{
				Gateway:   "10.0.0.1/24",
				Advertise: []core.Prefix{"10.0.0.0/24"},
				Mode:      config.LANModeRouted,
			},
		},
		nat: newNATTable(),
	}
	outbound, translated, err := daemon.applyOutboundNAT(tcpPayloadIPv4Packet([]byte("rewrite nat")), routing.Route{Kind: routing.RouteUnicast}, config.PolicyConfig{Rewrite: "snat_gateway"})
	if err != nil {
		t.Fatalf("apply outbound nat: %v", err)
	}
	if !translated {
		t.Fatal("expected policy rewrite to translate packet")
	}
	if got := netip.AddrFrom4([4]byte{outbound[12], outbound[13], outbound[14], outbound[15]}); got != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("outbound source = %s, want gateway", got)
	}
}

func TestRuntimeDataplaneSnapshotIncludesNATPolicy(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-a"},
			LAN: config.LANConfig{
				Gateway:   "10.0.0.1/24",
				Advertise: []core.Prefix{"10.0.0.0/24"},
				Mode:      config.LANModeNAT,
			},
			Peers: []config.PeerConfig{{
				ID:              "ix-b",
				Domain:          "lab",
				AllowedPrefixes: []core.Prefix{"10.0.1.0/24"},
			}},
			Routes: []config.RouteConfig{{
				Prefix:  "10.0.1.0/24",
				NextHop: "ix-b",
				Policy:  "default",
			}},
			Policies: []config.PolicyConfig{{Name: "default"}},
		},
		members: make(map[core.IXID]memberRecord),
	}
	snapshot := daemon.runtimeDataplaneSnapshot()
	if snapshot.NAT == nil || !snapshot.NAT.Enabled {
		t.Fatalf("expected NAT snapshot, got %#v", snapshot.NAT)
	}
	if snapshot.NAT.Gateway != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("NAT gateway = %s, want 10.0.0.1", snapshot.NAT.Gateway)
	}
	if len(snapshot.NAT.SourcePrefixes) != 1 || snapshot.NAT.SourcePrefixes[0].String() != "10.0.0.0/24" {
		t.Fatalf("NAT source prefixes = %#v", snapshot.NAT.SourcePrefixes)
	}
	if len(snapshot.NAT.RoutePrefixes) != 1 || snapshot.NAT.RoutePrefixes[0] != "10.0.1.0/24" {
		t.Fatalf("NAT route prefixes = %#v", snapshot.NAT.RoutePrefixes)
	}
}

func TestRuntimeDataplaneSnapshotIncludesPacketPolicy(t *testing.T) {
	t.Setenv("TRUSTIX_TCP_MSS_CLAMP", "1180")
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				MTU:            1200,
				FragmentPolicy: "drop",
			},
		},
		members: make(map[core.IXID]memberRecord),
	}

	snapshot := daemon.runtimeDataplaneSnapshot()
	if snapshot.PacketPolicy.MTU != 1200 || !snapshot.PacketPolicy.DropFragments || snapshot.PacketPolicy.TCPMSSClamp != 1180 {
		t.Fatalf("packet policy = %#v, want mtu=1200 drop_fragments=true tcp_mss_clamp=1180", snapshot.PacketPolicy)
	}
	if snapshot.PacketPolicy.KernelTransportMode != dataplane.KernelTransportModeAuto {
		t.Fatalf("packet policy kernel transport mode = %q, want auto", snapshot.PacketPolicy.KernelTransportMode)
	}
}

func TestRuntimeDataplaneSnapshotCarriesKernelTransportDisabled(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				KernelTransport: config.KernelTransportPolicyConfig{Mode: "disabled"},
			},
		},
		members: make(map[core.IXID]memberRecord),
	}

	snapshot := daemon.runtimeDataplaneSnapshot()
	if snapshot.PacketPolicy.KernelTransportMode != dataplane.KernelTransportModeDisabled {
		t.Fatalf("packet policy kernel transport mode = %q, want disabled", snapshot.PacketPolicy.KernelTransportMode)
	}
}

func TestRuntimeDataplaneSnapshotEnvAutoMSSForUserspaceUDP(t *testing.T) {
	t.Setenv("TRUSTIX_UDP_AUTO_TCP_MSS_CLAMP", "1")
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				MTU:             1500,
				KernelTransport: config.KernelTransportPolicyConfig{Mode: "disabled"},
				Encryption:      "plaintext",
				Candidates:      []core.EndpointID{"udp-a"},
			},
			Endpoints: []config.EndpointConfig{{
				Name:      "udp-a",
				Transport: string(transport.ProtocolUDP),
				Enabled:   true,
			}},
		},
		members: make(map[core.IXID]memberRecord),
	}

	snapshot := daemon.runtimeDataplaneSnapshot()
	if snapshot.PacketPolicy.TCPMSSClamp != 1402 {
		t.Fatalf("auto TCP MSS clamp = %d, want 1402", snapshot.PacketPolicy.TCPMSSClamp)
	}
}

func TestRuntimeDataplaneSnapshotAutoMSSForKernelUDPSecureDirect(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT", "1")
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				CryptoPlacement: string(dataplane.CryptoPlacementKernel),
				KernelTransport: config.KernelTransportPolicyConfig{Mode: "require_kernel"},
				Candidates:      []core.EndpointID{"udp-a"},
			},
			Endpoints: []config.EndpointConfig{{
				Name:      "udp-a",
				Transport: string(transport.ProtocolUDP),
				Enabled:   true,
			}},
		},
		members: make(map[core.IXID]memberRecord),
	}

	snapshot := daemon.runtimeDataplaneSnapshot()
	if snapshot.PacketPolicy.TCPMSSClamp != 1340 {
		t.Fatalf("auto TCP MSS clamp = %d, want 1340", snapshot.PacketPolicy.TCPMSSClamp)
	}
}

func TestRuntimeDataplaneSnapshotAutoMSSForKernelUDPUserspaceCrypto(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT", "1")
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				CryptoPlacement: string(dataplane.CryptoPlacementUserspace),
				KernelTransport: config.KernelTransportPolicyConfig{Mode: "require_kernel"},
				Encryption:      "secure",
				Candidates:      []core.EndpointID{"udp-a"},
			},
			Endpoints: []config.EndpointConfig{{
				Name:      "udp-a",
				Transport: string(transport.ProtocolUDP),
				Enabled:   true,
			}},
		},
		members: make(map[core.IXID]memberRecord),
	}

	snapshot := daemon.runtimeDataplaneSnapshot()
	if snapshot.PacketPolicy.TCPMSSClamp != 1340 {
		t.Fatalf("auto TCP MSS clamp = %d, want 1340", snapshot.PacketPolicy.TCPMSSClamp)
	}
}

func TestRuntimeDataplaneSnapshotAutoMSSForSecureKernelUDPTransport(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				CryptoPlacement: string(dataplane.CryptoPlacementUserspace),
				KernelTransport: config.KernelTransportPolicyConfig{Mode: "require_kernel"},
				Encryption:      "secure",
				Candidates:      []core.EndpointID{"udp-a"},
			},
			Endpoints: []config.EndpointConfig{{
				Name:      "udp-a",
				Transport: string(transport.ProtocolUDP),
				Enabled:   true,
			}},
		},
		members: make(map[core.IXID]memberRecord),
	}

	snapshot := daemon.runtimeDataplaneSnapshot()
	if snapshot.PacketPolicy.TCPMSSClamp != 1340 {
		t.Fatalf("auto TCP MSS clamp = %d, want 1340", snapshot.PacketPolicy.TCPMSSClamp)
	}
}

func TestRuntimeDataplaneSnapshotAutoMSSForExperimentalTCPSecureDirect(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT", "1")
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				MTU:             1500,
				CryptoPlacement: string(dataplane.CryptoPlacementKernel),
				KernelTransport: config.KernelTransportPolicyConfig{Mode: "require_kernel"},
				Encryption:      "secure",
				Candidates:      []core.EndpointID{"exp-a"},
			},
			Endpoints: []config.EndpointConfig{{
				Name:      "exp-a",
				Transport: string(transport.ProtocolExperimentalTCP),
				Enabled:   true,
			}},
		},
		members: make(map[core.IXID]memberRecord),
	}

	snapshot := daemon.runtimeDataplaneSnapshot()
	if snapshot.PacketPolicy.TCPMSSClamp != 1320 {
		t.Fatalf("auto TCP MSS clamp = %d, want 1320", snapshot.PacketPolicy.TCPMSSClamp)
	}
}

func TestRuntimeDataplaneSnapshotAutoMSSForExperimentalTCPSecureKernelTransport(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				MTU:             1500,
				CryptoPlacement: string(dataplane.CryptoPlacementKernel),
				KernelTransport: config.KernelTransportPolicyConfig{Mode: "require_kernel"},
				Encryption:      "secure",
				Candidates:      []core.EndpointID{"exp-a"},
			},
			Endpoints: []config.EndpointConfig{{
				Name:      "exp-a",
				Transport: string(transport.ProtocolExperimentalTCP),
				Enabled:   true,
			}},
		},
		members: make(map[core.IXID]memberRecord),
	}

	snapshot := daemon.runtimeDataplaneSnapshot()
	if snapshot.PacketPolicy.TCPMSSClamp != 1320 {
		t.Fatalf("auto TCP MSS clamp = %d, want 1320", snapshot.PacketPolicy.TCPMSSClamp)
	}
}

func TestRuntimeDataplaneSnapshotAutoMSSForKernelUDPPlaintext(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				CryptoPlacement: string(dataplane.CryptoPlacementUserspace),
				KernelTransport: config.KernelTransportPolicyConfig{Mode: "require_kernel"},
				Encryption:      "plaintext",
				Candidates:      []core.EndpointID{"udp-a"},
			},
			Endpoints: []config.EndpointConfig{{
				Name:      "udp-a",
				Transport: string(transport.ProtocolUDP),
				Enabled:   true,
			}},
		},
		members: make(map[core.IXID]memberRecord),
	}

	snapshot := daemon.runtimeDataplaneSnapshot()
	if snapshot.PacketPolicy.TCPMSSClamp != 1090 {
		t.Fatalf("auto TCP MSS clamp = %d, want 1090", snapshot.PacketPolicy.TCPMSSClamp)
	}
}

func TestRuntimeDataplaneSnapshotAutoMSSForKernelUDPPlaintextDirectOnlyActiveGSODefault(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				CryptoPlacement: string(dataplane.CryptoPlacementUserspace),
				KernelTransport: config.KernelTransportPolicyConfig{Mode: "require_kernel"},
				Encryption:      "plaintext",
				Candidates:      []core.EndpointID{"udp-a"},
			},
			Endpoints: []config.EndpointConfig{{
				Name:      "udp-a",
				Transport: string(transport.ProtocolUDP),
				Enabled:   true,
			}},
		},
		members: make(map[core.IXID]memberRecord),
	}

	snapshot := daemon.runtimeDataplaneSnapshot()
	if snapshot.PacketPolicy.TCPMSSClamp != 1090 {
		t.Fatalf("auto TCP MSS clamp = %d, want 1090", snapshot.PacketPolicy.TCPMSSClamp)
	}
}

func TestRuntimeDataplaneSnapshotAutoMSSForKernelUDPPlaintextAllowsExplicitSafeCap(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_PLAINTEXT_SAFE_MSS_CAP", "1200")
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				CryptoPlacement: string(dataplane.CryptoPlacementUserspace),
				KernelTransport: config.KernelTransportPolicyConfig{Mode: "require_kernel"},
				Encryption:      "plaintext",
				Candidates:      []core.EndpointID{"udp-a"},
			},
			Endpoints: []config.EndpointConfig{{
				Name:      "udp-a",
				Transport: string(transport.ProtocolUDP),
				Enabled:   true,
			}},
		},
		members: make(map[core.IXID]memberRecord),
	}

	snapshot := daemon.runtimeDataplaneSnapshot()
	if snapshot.PacketPolicy.TCPMSSClamp != 1200 {
		t.Fatalf("auto TCP MSS clamp = %d, want 1200", snapshot.PacketPolicy.TCPMSSClamp)
	}
}

func TestRuntimeDataplaneSnapshotAutoMSSForKernelUDPPlaintextCanDisableSafeCap(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_PLAINTEXT_SAFE_MSS_CAP", "off")
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				CryptoPlacement: string(dataplane.CryptoPlacementUserspace),
				KernelTransport: config.KernelTransportPolicyConfig{Mode: "require_kernel"},
				Encryption:      "plaintext",
				Candidates:      []core.EndpointID{"udp-a"},
			},
			Endpoints: []config.EndpointConfig{{
				Name:      "udp-a",
				Transport: string(transport.ProtocolUDP),
				Enabled:   true,
			}},
		},
		members: make(map[core.IXID]memberRecord),
	}

	snapshot := daemon.runtimeDataplaneSnapshot()
	if snapshot.PacketPolicy.TCPMSSClamp != 1380 {
		t.Fatalf("auto TCP MSS clamp = %d, want 1380", snapshot.PacketPolicy.TCPMSSClamp)
	}
}

func TestRuntimeDataplaneSnapshotExplicitAutoMSSForExperimentalTCP(t *testing.T) {
	t.Setenv("TRUSTIX_TCP_MSS_CLAMP", "auto")
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				MTU:             1500,
				KernelTransport: config.KernelTransportPolicyConfig{Mode: "require_kernel"},
				Encryption:      "secure",
				Candidates:      []core.EndpointID{"exp-a"},
			},
			Endpoints: []config.EndpointConfig{{
				Name:      "exp-a",
				Transport: string(transport.ProtocolExperimentalTCP),
				Enabled:   true,
			}},
		},
		members: make(map[core.IXID]memberRecord),
	}

	snapshot := daemon.runtimeDataplaneSnapshot()
	if snapshot.PacketPolicy.TCPMSSClamp != 1320 {
		t.Fatalf("auto TCP MSS clamp = %d, want 1320", snapshot.PacketPolicy.TCPMSSClamp)
	}
}

func TestRuntimeDataplaneSnapshotEnvAutoMSSForExperimentalTCPPlaintext(t *testing.T) {
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_AUTO_TCP_MSS_CLAMP", "1")
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				MTU:             1500,
				KernelTransport: config.KernelTransportPolicyConfig{Mode: "require_kernel"},
				Encryption:      "plaintext",
				Candidates:      []core.EndpointID{"exp-a"},
			},
			Endpoints: []config.EndpointConfig{{
				Name:      "exp-a",
				Transport: string(transport.ProtocolExperimentalTCP),
				Enabled:   true,
			}},
		},
		members: make(map[core.IXID]memberRecord),
	}

	snapshot := daemon.runtimeDataplaneSnapshot()
	if snapshot.PacketPolicy.TCPMSSClamp != 1360 {
		t.Fatalf("auto TCP MSS clamp = %d, want 1360", snapshot.PacketPolicy.TCPMSSClamp)
	}
}

func TestRuntimeDataplaneSnapshotAutoMSSForPlainExperimentalTCP(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				MTU:             1500,
				KernelTransport: config.KernelTransportPolicyConfig{Mode: "require_kernel"},
				Encryption:      "plaintext",
				Candidates:      []core.EndpointID{"exp-a"},
			},
			Endpoints: []config.EndpointConfig{{
				Name:      "exp-a",
				Transport: string(transport.ProtocolExperimentalTCP),
				Enabled:   true,
			}},
		},
		members: make(map[core.IXID]memberRecord),
	}

	snapshot := daemon.runtimeDataplaneSnapshot()
	if snapshot.PacketPolicy.TCPMSSClamp != 1360 {
		t.Fatalf("auto TCP MSS clamp = %d, want 1360", snapshot.PacketPolicy.TCPMSSClamp)
	}
}

func TestRuntimeDataplaneSnapshotExplicitAutoMSSForKernelTunnel(t *testing.T) {
	t.Setenv("TRUSTIX_TCP_MSS_CLAMP", "auto")
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				MTU:        1450,
				Candidates: []core.EndpointID{"vxlan-a"},
			},
			Endpoints: []config.EndpointConfig{{
				Name:      "vxlan-a",
				Transport: string(transport.ProtocolVXLAN),
				Enabled:   true,
			}},
		},
		members: make(map[core.IXID]memberRecord),
	}

	snapshot := daemon.runtimeDataplaneSnapshot()
	if snapshot.PacketPolicy.TCPMSSClamp != 1254 {
		t.Fatalf("auto TCP MSS clamp = %d, want 1254", snapshot.PacketPolicy.TCPMSSClamp)
	}
}

func TestRuntimeDataplaneSnapshotAutoMSSForKernelTunnelEndpointMTU(t *testing.T) {
	t.Setenv("TRUSTIX_TCP_MSS_CLAMP", "auto")
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				MTU:        1500,
				Candidates: []core.EndpointID{"gre-a"},
			},
			Endpoints: []config.EndpointConfig{{
				Name:      "gre-a",
				Transport: string(transport.ProtocolGRE),
				Address:   "local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.30.1/30,remote_carrier=10.255.30.2,mtu=1400",
				Enabled:   true,
			}},
		},
		members: make(map[core.IXID]memberRecord),
	}

	snapshot := daemon.runtimeDataplaneSnapshot()
	if snapshot.PacketPolicy.TCPMSSClamp != 1204 {
		t.Fatalf("auto TCP MSS clamp = %d, want 1204", snapshot.PacketPolicy.TCPMSSClamp)
	}
}

func TestRuntimeDataplaneSnapshotEnvAutoMSSForKernelTunnel(t *testing.T) {
	t.Setenv("TRUSTIX_NATIVE_TUNNEL_AUTO_TCP_MSS_CLAMP", "1")
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				MTU:        1476,
				Candidates: []core.EndpointID{"gre-a"},
			},
			Endpoints: []config.EndpointConfig{{
				Name:      "gre-a",
				Transport: string(transport.ProtocolGRE),
				Enabled:   true,
			}},
		},
		members: make(map[core.IXID]memberRecord),
	}

	snapshot := daemon.runtimeDataplaneSnapshot()
	if snapshot.PacketPolicy.TCPMSSClamp != 1280 {
		t.Fatalf("auto TCP MSS clamp = %d, want 1280", snapshot.PacketPolicy.TCPMSSClamp)
	}
}

func TestRuntimeDataplaneSnapshotEnvAutoMSSForKernelTunnelPlaintext(t *testing.T) {
	t.Setenv("TRUSTIX_NATIVE_TUNNEL_AUTO_TCP_MSS_CLAMP", "1")
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				MTU:        1476,
				Encryption: "plaintext",
				Candidates: []core.EndpointID{"gre-a"},
			},
			Endpoints: []config.EndpointConfig{{
				Name:      "gre-a",
				Transport: string(transport.ProtocolGRE),
				Enabled:   true,
			}},
		},
		members: make(map[core.IXID]memberRecord),
	}

	snapshot := daemon.runtimeDataplaneSnapshot()
	if snapshot.PacketPolicy.TCPMSSClamp != 1400 {
		t.Fatalf("auto TCP MSS clamp = %d, want 1400", snapshot.PacketPolicy.TCPMSSClamp)
	}
}

func TestRuntimeDataplaneSnapshotAutoMSSForNativeKernelTunnelEndpointMTU(t *testing.T) {
	t.Setenv("TRUSTIX_NATIVE_TUNNEL_AUTO_TCP_MSS_CLAMP", "1")
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				MTU:        1500,
				Encryption: "plaintext",
				Candidates: []core.EndpointID{"gre-a"},
			},
			Endpoints: []config.EndpointConfig{{
				Name:      "gre-a",
				Transport: string(transport.ProtocolGRE),
				Address:   "local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.30.1/30,remote_carrier=10.255.30.2,mtu=1400",
				Enabled:   true,
			}},
		},
		members: make(map[core.IXID]memberRecord),
	}

	snapshot := daemon.runtimeDataplaneSnapshot()
	if snapshot.PacketPolicy.TCPMSSClamp != 1360 {
		t.Fatalf("auto TCP MSS clamp = %d, want 1360", snapshot.PacketPolicy.TCPMSSClamp)
	}
}

func TestRuntimeDataplaneSnapshotExplicitMSSDisablesAutoMSS(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT", "1")
	t.Setenv("TRUSTIX_TCP_MSS_CLAMP", "off")
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				CryptoPlacement: string(dataplane.CryptoPlacementKernel),
				KernelTransport: config.KernelTransportPolicyConfig{Mode: "require_kernel"},
			},
		},
		members: make(map[core.IXID]memberRecord),
	}

	snapshot := daemon.runtimeDataplaneSnapshot()
	if snapshot.PacketPolicy.TCPMSSClamp != 0 {
		t.Fatalf("TCP MSS clamp = %d, want disabled", snapshot.PacketPolicy.TCPMSSClamp)
	}
}

func TestDataPathKernelOffloadStatusReportsPacketPolicyAndUserspaceBoundaries(t *testing.T) {
	t.Setenv("TRUSTIX_TCP_MSS_CLAMP", "1180")
	moduleManager := kernelmodule.NewTrustIXCryptoManager()
	moduleManager.SetStatusForTest(kernelmodule.Status{
		Name:       "trustix_crypto",
		Mode:       kernelmodule.ModeAuto,
		Loaded:     true,
		State:      "loaded",
		ABIVersion: 2,
		Features:   []string{kernelmodule.FeatureCryptoAEAD, kernelmodule.FeatureDeviceAEAD, kernelmodule.FeatureKfuncTC},
	})
	daemon := &Daemon{
		kernelCrypto: moduleManager,
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				MTU:            1200,
				FragmentPolicy: "drop",
			},
		},
	}

	kernelTransport := &dataplane.KernelTransportStatus{
		Mode:      dataplane.KernelTransportModeAuto,
		Available: true,
		Provider:  "af_xdp",
		Protocols: []dataplane.KernelTransportProtocol{{
			Protocol:          string(transport.ProtocolExperimentalTCP),
			Available:         true,
			Placement:         "kernel",
			Provider:          "af_xdp",
			UserspaceFallback: false,
		}, {
			Protocol:          string(transport.ProtocolUDP),
			Available:         true,
			Placement:         "hybrid",
			Provider:          "af_xdp",
			UserspaceFallback: true,
		}},
	}
	status := daemon.dataPathKernelOffloadStatus(dataplane.Stats{Mode: "linux", Capabilities: []string{"tc-clsact"}}, true, &dataplane.ExperimentalTCPStatus{
		Available:       true,
		Provider:        "af_xdp",
		FastPath:        true,
		KernelCrypto:    true,
		EffectiveCrypto: dataplane.CryptoPlacementKernel,
	}, kernelTransport, &dataplane.KernelUDPStatus{
		Available:       true,
		Provider:        "af_xdp",
		FastPath:        true,
		UserspaceCrypto: true,
		Reinject:        true,
		XDPAttachMode:   "skb",
		AFXDPBindMode:   "copy",
		ActiveFlows:     2,
		SubmittedFrames: 10,
		ReceivedFrames:  8,
		CryptoFallback: dataplane.CryptoFallbackStatus{
			Selected: dataplane.CryptoFallbackKOAEADDevice,
			Chain: []dataplane.CryptoFallbackStep{
				{Name: dataplane.CryptoFallbackFullKernelModuleDatapath, Ready: false, Placement: "kernel", Layer: dataplane.CryptoFallbackLayerKernelModule, Reason: "not ready"},
				{Name: dataplane.CryptoFallbackTCBPFDirect, Ready: false, Placement: "kernel", Layer: dataplane.CryptoFallbackLayerTC, Reason: "not ready"},
				{Name: dataplane.CryptoFallbackKOAEADDevice, Ready: true, Placement: "kernel", Layer: dataplane.CryptoFallbackLayerDevice},
				{Name: dataplane.CryptoFallbackUserspaceAEAD, Ready: true, Placement: "userspace", Layer: dataplane.CryptoFallbackLayerUserspace},
			},
		},
	})
	if status.DataplaneMode != "linux" || status.PacketPolicy.MTU != 1200 ||
		!status.PacketPolicy.DropFragments || status.PacketPolicy.TCPMSSClamp != 1180 {
		t.Fatalf("kernel offload status = %#v", status)
	}
	if !hasKernelPlacement(status.Placements, "packet_policy", "kernel") {
		t.Fatalf("placements missing kernel packet policy: %#v", status.Placements)
	}
	if !hasKernelPlacement(status.Placements, "experimental_tcp", "kernel") {
		t.Fatalf("placements missing kernel experimental_tcp: %#v", status.Placements)
	}
	if !hasKernelPlacement(status.Placements, "transport_plane", "hybrid") {
		t.Fatalf("placements missing hybrid transport plane: %#v", status.Placements)
	}
	if !hasKernelPlacement(status.Placements, "kernel_udp", "hybrid") {
		t.Fatalf("placements missing hybrid kernel_udp: %#v", status.Placements)
	}
	if !hasKernelPlacement(status.Placements, "trustix_crypto", "hybrid") {
		t.Fatalf("placements missing hybrid kernel module: %#v", status.Placements)
	}
	if !kernelPlacementDetailContains(status.Placements, "kernel_udp", "crypto_backend=ko_aead_device") {
		t.Fatalf("kernel_udp placement missing fallback backend: %#v", status.Placements)
	}
	if len(status.UserspaceRemaining) == 0 {
		t.Fatalf("expected userspace boundary notes: %#v", status.UserspaceRemaining)
	}
}

func TestRequireKernelTransportRejectsUserspaceUDP(t *testing.T) {
	daemon := &Daemon{
		dataplane: dataplane.NewNoopManager(),
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				KernelTransport: config.KernelTransportPolicyConfig{Mode: "require_kernel"},
			},
		},
	}
	peer := config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{{
			Name:      core.EndpointID("udp"),
			Transport: string(transport.ProtocolUDP),
			Address:   "203.0.113.10:7000",
		}},
	}

	_, _, err := daemon.candidatePeerEndpoints(peer, routing.Route{NextHop: peer.ID}, routing.FlowKey{}, false)
	if err == nil {
		t.Fatal("expected require_kernel to reject UDP without a kernel transport provider")
	}
	if !strings.Contains(err.Error(), "no endpoints compatible") {
		t.Fatalf("error = %v, want no compatible endpoints", err)
	}
}

func TestRequireKernelTransportAllowsAvailableExperimentalTCP(t *testing.T) {
	manager := &kernelTransportDataplane{
		NoopManager: dataplane.NewNoopManager(),
		status: dataplane.KernelTransportStatus{
			Available: true,
			Provider:  "test",
			Protocols: []dataplane.KernelTransportProtocol{{
				Protocol:  string(transport.ProtocolExperimentalTCP),
				Available: true,
				Placement: "hybrid",
				Provider:  "test",
			}},
		},
	}
	daemon := &Daemon{
		dataplane: manager,
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				KernelTransport: config.KernelTransportPolicyConfig{Mode: "require_kernel"},
			},
		},
	}
	peer := config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{{
			Name:      core.EndpointID("exp"),
			Transport: string(transport.ProtocolExperimentalTCP),
			Address:   "203.0.113.10:9000",
		}},
	}

	endpoints, _, err := daemon.candidatePeerEndpoints(peer, routing.Route{NextHop: peer.ID}, routing.FlowKey{}, false)
	if err != nil {
		t.Fatalf("candidate endpoints: %v", err)
	}
	if len(endpoints) != 1 || endpoints[0].Name != "exp" {
		t.Fatalf("endpoints = %#v, want experimental_tcp", endpoints)
	}
}

func TestRequireKernelTransportAllowsAvailableUDP(t *testing.T) {
	manager := &kernelTransportDataplane{
		NoopManager: dataplane.NewNoopManager(),
		status: dataplane.KernelTransportStatus{
			Available: true,
			Provider:  "test",
			Protocols: []dataplane.KernelTransportProtocol{{
				Protocol:  string(transport.ProtocolUDP),
				Available: true,
				Placement: "hybrid",
				Provider:  "test",
			}},
		},
	}
	daemon := &Daemon{
		dataplane: manager,
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				KernelTransport: config.KernelTransportPolicyConfig{Mode: "require_kernel"},
			},
		},
	}
	peer := config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{{
			Name:      core.EndpointID("udp"),
			Transport: string(transport.ProtocolUDP),
			Address:   "203.0.113.10:7000",
		}},
	}

	endpoints, _, err := daemon.candidatePeerEndpoints(peer, routing.Route{NextHop: peer.ID}, routing.FlowKey{}, false)
	if err != nil {
		t.Fatalf("candidate endpoints: %v", err)
	}
	if len(endpoints) != 1 || endpoints[0].Name != "udp" {
		t.Fatalf("endpoints = %#v, want UDP", endpoints)
	}
}

func TestRequireKernelTransportAllowsPendingUDPForTCOnlyPlaintextWarmup(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")
	manager := &kernelTransportDataplane{
		NoopManager: dataplane.NewNoopManager(),
		status: dataplane.KernelTransportStatus{
			Available: false,
			Provider:  "none",
			Protocols: []dataplane.KernelTransportProtocol{{
				Protocol:        string(transport.ProtocolUDP),
				Available:       false,
				CapabilityReady: false,
				Placement:       "userspace",
				Provider:        "none",
				Reason:          "pending route/flow warmup",
			}},
		},
	}
	daemon := &Daemon{
		dataplane: manager,
		desired: config.Desired{
			Endpoints: []config.EndpointConfig{{
				Name:      core.EndpointID("local-udp"),
				Transport: string(transport.ProtocolUDP),
				Enabled:   true,
			}},
			TransportPolicy: config.TransportPolicyConfig{
				Encryption: "plaintext",
				Candidates: []core.EndpointID{core.EndpointID("local-udp")},
				KernelTransport: config.KernelTransportPolicyConfig{
					Mode: string(dataplane.KernelTransportModeRequireKernel),
				},
			},
		},
	}
	peer := config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{{
			Name:      core.EndpointID("udp"),
			Transport: string(transport.ProtocolUDP),
			Address:   "203.0.113.10:7000",
		}},
	}

	endpoints, _, err := daemon.candidatePeerEndpoints(peer, routing.Route{NextHop: peer.ID}, routing.FlowKey{}, false)
	if err != nil {
		t.Fatalf("candidate endpoints: %v", err)
	}
	if len(endpoints) != 1 || endpoints[0].Name != "udp" {
		t.Fatalf("endpoints = %#v, want pending UDP", endpoints)
	}
}

func TestRequireKernelTransportRejectsPendingUDPForSecureTCOnlyWarmup(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")
	manager := &kernelTransportDataplane{
		NoopManager: dataplane.NewNoopManager(),
		status: dataplane.KernelTransportStatus{
			Available: false,
			Provider:  "none",
			Protocols: []dataplane.KernelTransportProtocol{{
				Protocol:  string(transport.ProtocolUDP),
				Available: false,
				Placement: "userspace",
				Provider:  "none",
			}},
		},
	}
	daemon := &Daemon{
		dataplane: manager,
		desired: config.Desired{
			Endpoints: []config.EndpointConfig{{
				Name:      core.EndpointID("local-udp"),
				Transport: string(transport.ProtocolUDP),
				Enabled:   true,
			}},
			TransportPolicy: config.TransportPolicyConfig{
				Encryption: "secure",
				Candidates: []core.EndpointID{core.EndpointID("local-udp")},
				KernelTransport: config.KernelTransportPolicyConfig{
					Mode: string(dataplane.KernelTransportModeRequireKernel),
				},
			},
		},
	}
	peer := config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{{
			Name:      core.EndpointID("udp"),
			Transport: string(transport.ProtocolUDP),
			Address:   "203.0.113.10:7000",
		}},
	}

	_, _, err := daemon.candidatePeerEndpoints(peer, routing.Route{NextHop: peer.ID}, routing.FlowKey{}, false)
	if err == nil {
		t.Fatal("expected secure pending TC-only UDP to be rejected")
	}
}

func TestRequireKernelTransportAllowsAvailableGRE(t *testing.T) {
	manager := &kernelTransportDataplane{
		NoopManager: dataplane.NewNoopManager(),
		status: dataplane.KernelTransportStatus{
			Available: true,
			Provider:  "test",
			Protocols: []dataplane.KernelTransportProtocol{{
				Protocol:          string(transport.ProtocolGRE),
				Available:         true,
				CapabilityReady:   true,
				Placement:         "kernel",
				Provider:          "linux-netlink",
				Carrier:           "gre-netdev+inner-udp",
				Contract:          "trustix-kernel-tunnel-carrier-v1",
				UserspaceFallback: false,
			}},
		},
	}
	daemon := &Daemon{
		dataplane: manager,
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				KernelTransport: config.KernelTransportPolicyConfig{Mode: "require_kernel"},
			},
		},
	}
	peer := config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{{
			Name:      core.EndpointID("gre"),
			Transport: string(transport.ProtocolGRE),
			Address:   "local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.30.1/30,remote_carrier=10.255.30.2,mtu=1400",
		}},
	}

	endpoints, _, err := daemon.candidatePeerEndpoints(peer, routing.Route{NextHop: peer.ID}, routing.FlowKey{}, false)
	if err != nil {
		t.Fatalf("candidate endpoints: %v", err)
	}
	if len(endpoints) != 1 || endpoints[0].Name != "gre" {
		t.Fatalf("endpoints = %#v, want GRE", endpoints)
	}
	detail := kernelTransportDoctorDetail(dataPathStatus{KernelTransport: &manager.status})
	for _, want := range []string{"gre=kernel/true", "capability=true", "fallback=false", "trustix-kernel-tunnel-carrier-v1"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("kernel transport doctor detail %q does not contain %q", detail, want)
		}
	}
}

func TestMirrorsTCNATBindingFromCapture(t *testing.T) {
	manager := dataplane.NewNoopManager()
	daemon := &Daemon{
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-a"},
			LAN: config.LANConfig{
				Gateway:   "10.0.0.1/24",
				Advertise: []core.Prefix{"10.0.0.0/24"},
				Mode:      config.LANModeNAT,
			},
			Routes: []config.RouteConfig{{
				Prefix:  "10.0.1.0/24",
				NextHop: "ix-b",
				Policy:  "default",
			}},
			Policies: []config.PolicyConfig{{Name: "default"}},
		},
		dataplane: manager,
		nat:       newNATTable(),
	}
	packet := udpIPv4Packet([]byte("tc nat"))
	copy(packet[12:16], []byte{10, 0, 0, 1})
	packet = normalizeCapturedIPv4Checksums(packet)
	ok, err := daemon.mirrorOutboundNATFromCapture(dataplane.CaptureEvent{
		NATTranslated:    true,
		OriginalSourceIP: "10.0.0.2",
		Payload:          packet,
	}, routing.Route{Kind: routing.RouteUnicast}, config.PolicyConfig{})
	if err != nil {
		t.Fatalf("mirror NAT binding: %v", err)
	}
	if !ok {
		t.Fatal("expected NAT binding to be mirrored")
	}
	key := natKey{
		TranslatedIP: netip.MustParseAddr("10.0.0.1"),
		RemoteIP:     netip.MustParseAddr("10.0.1.2"),
		Protocol:     ipProtocolUDP,
		LocalPort:    12345,
		RemotePort:   18100,
	}
	binding, found, _ := daemon.nat.lookup(key)
	if !found {
		t.Fatal("expected mirrored NAT binding")
	}
	if binding.OriginalIP != netip.MustParseAddr("10.0.0.2") {
		t.Fatalf("original IP = %s, want 10.0.0.2", binding.OriginalIP)
	}
	if managerSnapshot := managerSnapshotNAT(manager); managerSnapshot == nil || len(managerSnapshot.Bindings) != 1 {
		t.Fatalf("dataplane NAT bindings = %#v, want one binding", managerSnapshot)
	}
}

func hasKernelPlacement(placements []dataPathKernelPlacement, name string, placement string) bool {
	for _, item := range placements {
		if item.Name == name && item.Placement == placement {
			return true
		}
	}
	return false
}

func kernelPlacementDetailContains(placements []dataPathKernelPlacement, name string, detail string) bool {
	for _, item := range placements {
		if item.Name == name && strings.Contains(item.Detail, detail) {
			return true
		}
	}
	return false
}

func TestNATTableEvictsOldestBindingAtLimit(t *testing.T) {
	table := newNATTableWithLimit(2)
	table.upsert(natKey{
		TranslatedIP: netip.MustParseAddr("10.0.0.1"),
		RemoteIP:     netip.MustParseAddr("10.0.1.2"),
		Protocol:     ipProtocolUDP,
		LocalPort:    1000,
		RemotePort:   2000,
	}, netip.MustParseAddr("10.0.0.2"))
	time.Sleep(time.Millisecond)
	table.upsert(natKey{
		TranslatedIP: netip.MustParseAddr("10.0.0.1"),
		RemoteIP:     netip.MustParseAddr("10.0.1.3"),
		Protocol:     ipProtocolUDP,
		LocalPort:    1001,
		RemotePort:   2001,
	}, netip.MustParseAddr("10.0.0.3"))
	time.Sleep(time.Millisecond)
	table.upsert(natKey{
		TranslatedIP: netip.MustParseAddr("10.0.0.1"),
		RemoteIP:     netip.MustParseAddr("10.0.1.4"),
		Protocol:     ipProtocolUDP,
		LocalPort:    1002,
		RemotePort:   2002,
	}, netip.MustParseAddr("10.0.0.4"))

	snapshot := table.snapshot()
	if snapshot.ActiveBindings != 2 || snapshot.Evictions != 1 {
		t.Fatalf("NAT snapshot active=%d evictions=%d, want 2/1", snapshot.ActiveBindings, snapshot.Evictions)
	}
	for _, binding := range snapshot.Bindings {
		if binding.OriginalIP == netip.MustParseAddr("10.0.0.2") {
			t.Fatalf("oldest NAT binding was not evicted: %#v", snapshot.Bindings)
		}
	}
}

func TestNATTableConfiguresLimitAndTTL(t *testing.T) {
	table := newNATTableWithLimitAndTTL(4, time.Hour)
	for i := 0; i < 4; i++ {
		key := natKey{
			TranslatedIP: netip.MustParseAddr("10.0.0.1"),
			RemoteIP:     netip.AddrFrom4([4]byte{10, 0, 1, byte(i + 1)}),
			Protocol:     ipProtocolUDP,
			LocalPort:    uint16(10000 + i),
			RemotePort:   18100,
		}
		table.upsert(key, netip.MustParseAddr("10.0.0.2"))
	}
	table.configure(2, 30*time.Second)
	snapshot := table.snapshot()
	if snapshot.MaxBindings != 2 || snapshot.ActiveBindings != 2 || snapshot.Evictions != 2 {
		t.Fatalf("configured NAT snapshot = %#v, want max=2 active=2 evictions=2", snapshot)
	}
	if snapshot.BindingTTL != 30*time.Second {
		t.Fatalf("configured NAT ttl = %s, want 30s", snapshot.BindingTTL)
	}
	for _, binding := range snapshot.Bindings {
		remaining := time.Until(binding.ExpiresAt)
		if remaining <= 0 || remaining > 30*time.Second {
			t.Fatalf("binding expiry was not re-based to new ttl: %s", remaining)
		}
	}
}

func TestDaemonConfiguresNATTableFromLANConfig(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			LAN: config.LANConfig{
				Mode: config.LANModeNAT,
				NAT: config.NATConfig{
					MaxBindings: 3,
					BindingTTL:  "45s",
				},
			},
		},
	}
	daemon.configureNATTable()
	if daemon.nat == nil {
		t.Fatal("expected NAT table")
	}
	snapshot := daemon.nat.snapshot()
	if snapshot.MaxBindings != 3 {
		t.Fatalf("nat max bindings = %d, want 3", snapshot.MaxBindings)
	}
	if snapshot.BindingTTL != 45*time.Second {
		t.Fatalf("nat binding ttl = %s, want 45s", snapshot.BindingTTL)
	}
	key := natKey{
		TranslatedIP: netip.MustParseAddr("10.0.0.1"),
		RemoteIP:     netip.MustParseAddr("10.0.1.2"),
		Protocol:     ipProtocolUDP,
		LocalPort:    12345,
		RemotePort:   18100,
	}
	daemon.nat.upsert(key, netip.MustParseAddr("10.0.0.2"))
	binding := daemon.nat.snapshot().Bindings[0]
	remaining := time.Until(binding.ExpiresAt)
	if remaining <= 30*time.Second || remaining > 45*time.Second {
		t.Fatalf("binding ttl remaining = %s, want near 45s", remaining)
	}
}

func TestInboundNATMissFallsThrough(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			LAN: config.LANConfig{
				Gateway:   "10.0.0.1/24",
				Advertise: []core.Prefix{"10.0.0.0/24"},
				Mode:      config.LANModeNAT,
			},
		},
		nat: newNATTable(),
	}
	reply := udpIPv4Packet([]byte("nat miss"))
	copy(reply[12:16], []byte{10, 0, 1, 2})
	copy(reply[16:20], []byte{10, 0, 0, 1})
	reply = normalizeCapturedIPv4Checksums(reply)
	translated, hit, err := daemon.applyInboundNAT(reply)
	if err != nil {
		t.Fatalf("apply inbound nat: %v", err)
	}
	if hit {
		t.Fatal("unexpected NAT hit")
	}
	if &translated[0] != &reply[0] {
		t.Fatal("NAT miss should return original packet without copy")
	}
	if got := daemon.dataStats.snapshot().NATMisses; got != 1 {
		t.Fatalf("nat misses = %d, want 1", got)
	}
}

func TestInboundNATDisabledDoesNotCountGatewayPacketAsMiss(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			LAN: config.LANConfig{
				Gateway:   "10.0.0.1/24",
				Advertise: []core.Prefix{"10.0.0.0/24"},
				Mode:      config.LANModeRouted,
			},
		},
		nat: newNATTable(),
	}
	reply := udpIPv4Packet([]byte("not nat"))
	copy(reply[12:16], []byte{10, 0, 1, 2})
	copy(reply[16:20], []byte{10, 0, 0, 1})
	reply = normalizeCapturedIPv4Checksums(reply)
	_, hit, err := daemon.applyInboundNAT(reply)
	if err != nil {
		t.Fatalf("apply inbound nat: %v", err)
	}
	if hit {
		t.Fatal("unexpected NAT hit")
	}
	if got := daemon.dataStats.snapshot().NATMisses; got != 0 {
		t.Fatalf("nat misses = %d, want 0 when NAT disabled", got)
	}
}

func managerSnapshotNAT(manager *dataplane.NoopManager) *dataplane.NATSnapshot {
	return manager.Snapshot().NAT
}

func TestRouteLocalPortMismatchFallsBackToLessSpecificUnicast(t *testing.T) {
	table := routing.NewTable()
	if err := table.Replace([]routing.Route{
		{Prefix: "10.0.1.0/24", Kind: routing.RouteUnicast, NextHop: "ix-b", Metric: 100},
		{Prefix: "10.0.1.1/32", Kind: routing.RouteLocal, NextHop: "ix-a", Metric: 10, LocalProtocol: ipProtocolTCP, LocalPort: 8787},
	}); err != nil {
		t.Fatalf("replace routes: %v", err)
	}
	packet := udpIPv4Packet([]byte("nat reply to gateway"))
	copy(packet[16:20], []byte{10, 0, 1, 1})
	daemon := &Daemon{routes: table}
	decision, ok := daemon.lookupRouteForPacket(netip.MustParseAddr("10.0.1.1"), packet)
	if !ok {
		t.Fatal("expected fallback route")
	}
	if decision.Route.Kind != routing.RouteUnicast || decision.Route.NextHop != "ix-b" {
		t.Fatalf("fallback decision = %#v", decision.Route)
	}
}

func TestRouteLocalPortMatchUsesLocalRoute(t *testing.T) {
	table := routing.NewTable()
	if err := table.Replace([]routing.Route{
		{Prefix: "10.0.1.0/24", Kind: routing.RouteUnicast, NextHop: "ix-b", Metric: 100},
		{Prefix: "10.0.1.1/32", Kind: routing.RouteLocal, NextHop: "ix-a", Metric: 10, LocalProtocol: ipProtocolTCP, LocalPort: 8787},
	}); err != nil {
		t.Fatalf("replace routes: %v", err)
	}
	packet := tcpPayloadIPv4Packet([]byte("management"))
	copy(packet[16:20], []byte{10, 0, 1, 1})
	binary.BigEndian.PutUint16(packet[22:24], 8787)
	daemon := &Daemon{routes: table}
	decision, ok := daemon.lookupRouteForPacket(netip.MustParseAddr("10.0.1.1"), packet)
	if !ok {
		t.Fatal("expected local route")
	}
	if decision.Route.Kind != routing.RouteLocal {
		t.Fatalf("decision = %#v, want local route", decision.Route)
	}
}

func TestHandleReceivedDataPathPacketForwardsTransitRoute(t *testing.T) {
	table := routing.NewTable()
	route := routing.Route{
		Prefix:   "10.0.2.0/24",
		Owner:    "ix-c",
		NextHop:  "ix-c",
		Endpoint: "ep-c",
		Metric:   100,
		Kind:     routing.RouteUnicast,
	}
	if err := table.Replace([]routing.Route{route}); err != nil {
		t.Fatalf("replace routes: %v", err)
	}
	session := &recordingSession{}
	registry := transport.NewRegistry()
	if err := registry.Register(fakeTransport{name: "udp"}); err != nil {
		t.Fatalf("register fake transport: %v", err)
	}
	daemon := &Daemon{
		routes:     table,
		transports: registry,
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-b"},
			LAN: config.LANConfig{
				Advertise: []core.Prefix{"10.0.1.0/24"},
			},
			Peers: []config.PeerConfig{{
				ID:     "ix-c",
				Domain: "lab.local",
				Endpoints: []config.EndpointConfig{{
					Name:      "ep-c",
					Address:   "192.0.2.3:7003",
					Transport: "udp",
				}},
			}},
		},
		dataSessions: map[dataSessionKey]transport.Session{
			{Peer: "ix-c", Endpoint: "ep-c", Transport: "udp", Address: "192.0.2.3:7003", Encryption: "secure"}: session,
		},
		flows: make(map[routing.FlowKey]routing.FlowBinding),
	}
	packet := tcpPayloadIPv4Packet([]byte("transit"))
	copy(packet[16:20], []byte{10, 0, 2, 2})
	packet[8] = 64

	if err := daemon.handleReceivedDataPathPacket(context.Background(), packet, &recordingInjector{}); err != nil {
		t.Fatalf("handle received transit packet: %v", err)
	}
	if len(session.sent) != 1 {
		t.Fatalf("forwarded packets = %d, want 1", len(session.sent))
	}
	if packet[8] != 64 {
		t.Fatalf("original TTL mutated to %d", packet[8])
	}
	if session.sent[0][8] != 63 {
		t.Fatalf("forwarded TTL = %d, want 63", session.sent[0][8])
	}
	routes, peers, endpoints := daemon.dataPathMetricsSnapshot()
	if len(routes) != 1 || routes[0].Owner != "ix-c" || routes[0].NextHop != "ix-c" || routes[0].PacketsSent != 1 {
		t.Fatalf("route stats = %#v", routes)
	}
	if len(peers) != 1 || peers[0].Peer != "ix-c" || peers[0].PacketsSent != 1 {
		t.Fatalf("peer stats = %#v", peers)
	}
	if len(endpoints) != 1 || endpoints[0].Endpoint != "ep-c" || endpoints[0].PacketsSent != 1 {
		t.Fatalf("endpoint stats = %#v", endpoints)
	}
}

func TestCaptureFilterCanMatchPeerHookAndAddresses(t *testing.T) {
	table := routing.NewTable()
	if err := table.Replace([]routing.Route{{
		Prefix:  core.Prefix("10.0.1.0/24"),
		NextHop: core.IXID("ix-b"),
		Metric:  100,
		Kind:    routing.RouteUnicast,
	}}); err != nil {
		t.Fatalf("replace routes: %v", err)
	}
	events := []dataplane.CaptureEvent{
		{Hook: "lan_ingress_route_hit", SourceIP: "10.0.0.2", DestinationIP: "10.0.1.2"},
		{Hook: "lan_ingress_route_hit", SourceIP: "10.0.0.3", DestinationIP: "10.0.2.2"},
		{Hook: "other", SourceIP: "10.0.0.2", DestinationIP: "10.0.1.2"},
	}

	filtered := filterCaptureEvents(events, captureFilter{
		Hook:           "lan_ingress_route_hit",
		Peer:           core.IXID("ix-b"),
		SourceIP:       netip.MustParseAddr("10.0.0.2"),
		DestinationIP:  netip.MustParseAddr("10.0.1.2"),
		HasSourceIP:    true,
		HasDestination: true,
	}, table)
	if len(filtered) != 1 || filtered[0].SourceIP != "10.0.0.2" {
		t.Fatalf("filtered capture events = %#v", filtered)
	}
}

func TestCandidatePeerEndpointsPrefersStickyFlow(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			Policies: []config.PolicyConfig{
				{Name: core.PolicyID("default"), FlowStickiness: true, LoadBalance: "least_conn"},
			},
		},
		flows: make(map[routing.FlowKey]routing.FlowBinding),
	}
	flowKey := routing.FlowKey{
		SourceIP:      netip.MustParseAddr("10.0.0.2"),
		DestinationIP: netip.MustParseAddr("10.0.1.2"),
		Protocol:      1,
	}
	daemon.bindFlow(flowKey, core.IXID("ix-b"), core.EndpointID("ep-2"))

	endpoints, _, err := daemon.candidatePeerEndpoints(testPeer(), routing.Route{
		NextHop: core.IXID("ix-b"),
		Policy:  core.PolicyID("default"),
	}, flowKey, true)
	if err != nil {
		t.Fatalf("candidate endpoints: %v", err)
	}
	if endpoints[0].Name != "ep-2" {
		t.Fatalf("first endpoint = %q, want ep-2", endpoints[0].Name)
	}
}

func TestCandidatePeerEndpointsLeastConnUsesFlowCounts(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			Policies: []config.PolicyConfig{
				{Name: core.PolicyID("default"), FlowStickiness: true, LoadBalance: "least_conn"},
			},
		},
		flows: make(map[routing.FlowKey]routing.FlowBinding),
	}
	now := time.Now().UTC()
	daemon.flows[routing.FlowKey{SourceIP: netip.MustParseAddr("10.0.0.2"), DestinationIP: netip.MustParseAddr("10.0.1.2"), Protocol: 1}] = routing.FlowBinding{
		NextHop:   core.IXID("ix-b"),
		Endpoint:  core.EndpointID("ep-1"),
		LastSeen:  now,
		ExpiresAt: now.Add(flowBindingTTL),
	}

	endpoints, _, err := daemon.candidatePeerEndpoints(testPeer(), routing.Route{
		NextHop: core.IXID("ix-b"),
		Policy:  core.PolicyID("default"),
	}, routing.FlowKey{}, false)
	if err != nil {
		t.Fatalf("candidate endpoints: %v", err)
	}
	if endpoints[0].Name != "ep-2" {
		t.Fatalf("first endpoint = %q, want ep-2", endpoints[0].Name)
	}
}

func TestCandidatePeerEndpointsSkipsDownEndpointForHealthFailover(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{Failover: "health_based"},
		},
		endpointState: make(map[endpointStateKey]rstate.EndpointState),
	}
	daemon.recordEndpointDown(core.IXID("ix-b"), testPeer().Endpoints[0], fmt.Errorf("dial failed"))

	endpoints, _, err := daemon.candidatePeerEndpoints(testPeer(), routing.Route{
		NextHop: core.IXID("ix-b"),
	}, routing.FlowKey{}, false)
	if err != nil {
		t.Fatalf("candidate endpoints: %v", err)
	}
	if endpoints[0].Name != "ep-2" {
		t.Fatalf("first endpoint = %q, want ep-2", endpoints[0].Name)
	}
}

func TestCandidatePeerEndpointsUsesExplicitDownEndpointWithHealthFailover(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{Failover: "health_based"},
		},
		endpointState: make(map[endpointStateKey]rstate.EndpointState),
	}
	daemon.recordEndpointDown(core.IXID("ix-b"), testPeer().Endpoints[0], fmt.Errorf("dial failed"))

	endpoints, _, err := daemon.candidatePeerEndpoints(testPeer(), routing.Route{
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ep-1"),
	}, routing.FlowKey{}, false)
	if err != nil {
		t.Fatalf("candidate endpoints: %v", err)
	}
	if len(endpoints) != 1 || endpoints[0].Name != "ep-1" {
		t.Fatalf("endpoints = %#v, want pinned ep-1", endpoints)
	}
}

func TestCandidatePeerEndpointsUsesExplicitDownEndpointWithActiveSession(t *testing.T) {
	peer := testPeer()
	endpoint := peer.Endpoints[0]
	activeKey := dataSessionKey{
		Peer:       peer.ID,
		Endpoint:   endpoint.Name,
		Transport:  transport.Protocol(endpoint.Transport),
		Address:    endpoint.Address,
		Encryption: "secure",
		PoolIndex:  1,
	}
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{Failover: "health_based"},
		},
		dataSessions:  map[dataSessionKey]transport.Session{activeKey: &recordingSession{}},
		endpointState: make(map[endpointStateKey]rstate.EndpointState),
	}
	daemon.recordEndpointDown(peer.ID, endpoint, fmt.Errorf("stale dial failure"))

	endpoints, _, err := daemon.candidatePeerEndpoints(peer, routing.Route{
		NextHop:  peer.ID,
		Endpoint: endpoint.Name,
	}, routing.FlowKey{}, false)
	if err != nil {
		t.Fatalf("candidate endpoints: %v", err)
	}
	if len(endpoints) != 1 || endpoints[0].Name != endpoint.Name {
		t.Fatalf("endpoints = %#v, want pinned %q", endpoints, endpoint.Name)
	}
}

func TestCandidatePeerEndpointsRejectsExplicitDownEndpointWithoutHealthFailover(t *testing.T) {
	daemon := &Daemon{
		desired:       config.Desired{},
		endpointState: make(map[endpointStateKey]rstate.EndpointState),
	}
	daemon.recordEndpointDown(core.IXID("ix-b"), testPeer().Endpoints[0], fmt.Errorf("dial failed"))

	endpoints, _, err := daemon.candidatePeerEndpoints(testPeer(), routing.Route{
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ep-1"),
	}, routing.FlowKey{}, false)
	if err != nil {
		t.Fatalf("candidate endpoints: %v", err)
	}
	if len(endpoints) != 1 || endpoints[0].Name != "ep-1" {
		t.Fatalf("endpoints = %#v, want pinned ep-1", endpoints)
	}
}

func TestCandidatePeerEndpointsFiltersIncompatibleSecurity(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				CryptoKeySource: "tls_exporter",
				TLSIdentity: config.TransportTLSIdentityConfig{
					Mode: "custom_cert",
				},
			},
		},
	}
	peer := config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{
			{
				Name:      core.EndpointID("ix-cert"),
				Address:   "192.0.2.1:7001",
				Transport: "tcp",
				Security: config.EndpointSecurityConfig{
					LinkTLS:     "required",
					TLSIdentity: "ix_cert",
					KeySources:  []string{"tls_exporter"},
				},
			},
			{
				Name:      core.EndpointID("x25519"),
				Address:   "192.0.2.2:7002",
				Transport: "tcp",
				Security: config.EndpointSecurityConfig{
					LinkTLS:     "required",
					TLSIdentity: "custom_cert",
					KeySources:  []string{"trustix_x25519"},
				},
			},
			{
				Name:      core.EndpointID("custom-tls"),
				Address:   "192.0.2.3:7003",
				Transport: "tcp",
				Security: config.EndpointSecurityConfig{
					LinkTLS:     "required",
					TLSIdentity: "custom_cert",
					KeySources:  []string{"tls_exporter"},
				},
			},
		},
	}

	endpoints, _, err := daemon.candidatePeerEndpoints(peer, routing.Route{
		NextHop: core.IXID("ix-b"),
	}, routing.FlowKey{}, false)
	if err != nil {
		t.Fatalf("candidate endpoints: %v", err)
	}
	if len(endpoints) != 1 || endpoints[0].Name != "custom-tls" {
		t.Fatalf("compatible endpoints = %#v, want only custom-tls", endpoints)
	}
}

func TestCandidatePeerEndpointsRejectsExplicitIncompatibleSecurity(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{CryptoKeySource: "tls_exporter"},
		},
	}
	peer := testPeer()
	peer.Endpoints[0].Security.KeySources = []string{"trustix_x25519"}

	_, _, err := daemon.candidatePeerEndpoints(peer, routing.Route{
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ep-1"),
	}, routing.FlowKey{}, false)
	if err == nil {
		t.Fatal("expected explicit incompatible endpoint to be rejected")
	}
}

func TestCandidatePeerEndpointsAutoKeySourceUsesTransportDefault(t *testing.T) {
	daemon := &Daemon{desired: config.Desired{}}
	peer := config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{
			{
				Name:      core.EndpointID("x25519"),
				Address:   "192.0.2.1:7001",
				Transport: "tcp",
				Security:  config.EndpointSecurityConfig{KeySources: []string{"trustix_x25519"}},
			},
			{
				Name:      core.EndpointID("exporter"),
				Address:   "192.0.2.2:7002",
				Transport: "tcp",
				Security:  config.EndpointSecurityConfig{KeySources: []string{"tls_exporter"}},
			},
		},
	}

	endpoints, _, err := daemon.candidatePeerEndpoints(peer, routing.Route{
		NextHop: core.IXID("ix-b"),
	}, routing.FlowKey{}, false)
	if err != nil {
		t.Fatalf("candidate endpoints: %v", err)
	}
	if len(endpoints) != 1 || endpoints[0].Name != "exporter" {
		t.Fatalf("auto key-source endpoints = %#v, want only exporter", endpoints)
	}
}

func TestCandidatePeerEndpointsFiltersLegacyEncryptionMismatch(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{Encryption: "send_encrypted"},
		},
	}
	peer := config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{
			{
				Name:      core.EndpointID("secure"),
				Address:   "192.0.2.1:7001",
				Transport: "udp",
			},
			{
				Name:      core.EndpointID("complementary"),
				Address:   "192.0.2.2:7002",
				Transport: "udp",
				Security:  config.EndpointSecurityConfig{Encryption: "receive_encrypted"},
			},
		},
	}

	endpoints, _, err := daemon.candidatePeerEndpoints(peer, routing.Route{
		NextHop: core.IXID("ix-b"),
	}, routing.FlowKey{}, false)
	if err != nil {
		t.Fatalf("candidate endpoints: %v", err)
	}
	if len(endpoints) != 1 || endpoints[0].Name != "complementary" {
		t.Fatalf("compatible encryption endpoints = %#v, want complementary", endpoints)
	}
}

func TestCandidatePeerEndpointsInheritPlaintextGlobalEncryption(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{Encryption: "plaintext"},
		},
	}
	peer := config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{{
			Name:      core.EndpointID("plaintext-peer"),
			Address:   "192.0.2.1:7001",
			Transport: "udp",
		}},
	}

	endpoints, _, err := daemon.candidatePeerEndpoints(peer, routing.Route{
		NextHop: core.IXID("ix-b"),
	}, routing.FlowKey{}, false)
	if err != nil {
		t.Fatalf("candidate endpoints: %v", err)
	}
	if len(endpoints) != 1 || endpoints[0].Name != "plaintext-peer" {
		t.Fatalf("plaintext inherited candidates = %#v", endpoints)
	}
}

func TestCandidatePeerEndpointsPrefersNativeTunnelForPlaintext(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				Encryption: "none",
				KernelTransport: config.KernelTransportPolicyConfig{
					Mode: "require_kernel",
				},
			},
		},
		dataplane: &kernelTransportDataplane{
			NoopManager: dataplane.NewNoopManager(),
			status: dataplane.KernelTransportStatus{
				Available: true,
				Provider:  "test",
				Protocols: []dataplane.KernelTransportProtocol{
					{Protocol: string(transport.ProtocolUDP), Available: true, Placement: "hybrid"},
					{Protocol: string(transport.ProtocolExperimentalTCP), Available: true, Placement: "hybrid"},
					{Protocol: string(transport.ProtocolGRE), Available: true, CapabilityReady: true, Placement: "kernel"},
					{Protocol: string(transport.ProtocolIPIP), Available: true, CapabilityReady: true, Placement: "kernel"},
					{Protocol: string(transport.ProtocolVXLAN), Available: true, CapabilityReady: true, Placement: "kernel"},
				},
			},
		},
	}
	peer := config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{
			{Name: core.EndpointID("udp"), Address: "192.0.2.1:7001", Transport: "udp"},
			{Name: core.EndpointID("exp"), Address: "192.0.2.1:7002", Transport: "experimental_tcp"},
			{Name: core.EndpointID("vxlan"), Address: "local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.31.1/30,remote_carrier=10.255.31.2,mtu=1450", Transport: "vxlan"},
			{Name: core.EndpointID("gre"), Address: "local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.30.1/30,remote_carrier=10.255.30.2,mtu=1476", Transport: "gre"},
			{Name: core.EndpointID("ipip"), Address: "local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.32.1/30,remote_carrier=10.255.32.2,mtu=1480", Transport: "ipip"},
		},
	}

	endpoints, _, err := daemon.candidatePeerEndpoints(peer, routing.Route{NextHop: peer.ID}, routing.FlowKey{}, false)
	if err != nil {
		t.Fatalf("candidate endpoints: %v", err)
	}
	got := make([]core.EndpointID, 0, len(endpoints))
	for _, endpoint := range endpoints {
		got = append(got, endpoint.Name)
	}
	want := []core.EndpointID{"gre", "ipip", "vxlan", "exp", "udp"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("candidate order = %v, want %v", got, want)
	}
}

func TestCandidatePeerEndpointsPrefersHighestEndpointPriorityScore(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			Domain: config.DomainConfig{ID: core.DomainID("lab.local")},
			Endpoints: []config.EndpointConfig{
				{Name: core.EndpointID("local-udp"), Transport: "udp", Priority: 20, Enabled: true},
				{Name: core.EndpointID("local-tcp"), Transport: "experimental_tcp", Priority: 70, Enabled: true},
			},
		},
	}
	peer := config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{
			{Name: core.EndpointID("udp"), Address: "192.0.2.1:7001", Transport: "udp", Priority: 80},
			{Name: core.EndpointID("exp"), Address: "192.0.2.1:7002", Transport: "experimental_tcp", Priority: 40},
		},
	}

	endpoints, _, err := daemon.candidatePeerEndpoints(peer, routing.Route{NextHop: peer.ID}, routing.FlowKey{}, false)
	if err != nil {
		t.Fatalf("candidate endpoints: %v", err)
	}
	if endpoints[0].Name != "exp" {
		t.Fatalf("first endpoint = %q, want exp from higher local+remote priority score", endpoints[0].Name)
	}
}

func TestCandidatePeerEndpointsKeepsSecureTransportOrder(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				Encryption: "secure",
				KernelTransport: config.KernelTransportPolicyConfig{
					Mode: "require_kernel",
				},
			},
		},
		dataplane: &kernelTransportDataplane{
			NoopManager: dataplane.NewNoopManager(),
			status: dataplane.KernelTransportStatus{
				Available: true,
				Provider:  "test",
				Protocols: []dataplane.KernelTransportProtocol{
					{Protocol: string(transport.ProtocolUDP), Available: true, Placement: "hybrid"},
					{Protocol: string(transport.ProtocolGRE), Available: true, CapabilityReady: true, Placement: "kernel"},
				},
			},
		},
	}
	peer := config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{
			{Name: core.EndpointID("udp"), Address: "192.0.2.1:7001", Transport: "udp"},
			{Name: core.EndpointID("gre"), Address: "local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.30.1/30,remote_carrier=10.255.30.2,mtu=1476", Transport: "gre"},
		},
	}

	endpoints, _, err := daemon.candidatePeerEndpoints(peer, routing.Route{NextHop: peer.ID}, routing.FlowKey{}, false)
	if err != nil {
		t.Fatalf("candidate endpoints: %v", err)
	}
	got := []core.EndpointID{endpoints[0].Name, endpoints[1].Name}
	want := []core.EndpointID{"udp", "gre"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("candidate order = %v, want %v", got, want)
	}
}

func TestCandidatePeerEndpointsUsesEndpointEncryptionOverride(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{Encryption: "plaintext"},
		},
	}
	peer := config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{
			{
				Name:      core.EndpointID("secure-peer"),
				Address:   "192.0.2.1:7001",
				Transport: "udp",
				Security:  config.EndpointSecurityConfig{Encryption: "secure"},
			},
		},
	}

	endpoints, _, err := daemon.candidatePeerEndpoints(peer, routing.Route{
		NextHop: core.IXID("ix-b"),
	}, routing.FlowKey{}, false)
	if err != nil {
		t.Fatalf("candidate endpoints: %v", err)
	}
	if len(endpoints) != 1 || endpoints[0].Name != "secure-peer" {
		t.Fatalf("endpoint override candidates = %#v", endpoints)
	}
}

func TestSessionForEndpointUsesComplementaryEndpointEncryption(t *testing.T) {
	clientRegistry := transport.NewRegistry()
	if err := clientRegistry.Register(fakeTransportWithSessionStats{name: transport.ProtocolUDP}); err != nil {
		t.Fatalf("register client transport: %v", err)
	}
	clientDaemon := &Daemon{
		transports:   clientRegistry,
		dataSessions: make(map[dataSessionKey]transport.Session),
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				Encryption: "secure",
				TLSIdentity: config.TransportTLSIdentityConfig{
					Mode:        "custom_cert",
					SystemRoots: true,
				},
			},
		},
	}
	peer := config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
	}
	remoteEndpoint := config.EndpointConfig{
		Name:      core.EndpointID("server"),
		Address:   "127.0.0.1:7001",
		Transport: "udp",
		Security:  config.EndpointSecurityConfig{Encryption: "receive_encrypted"},
	}
	session, key, _, err := clientDaemon.sessionForEndpoint(context.Background(), peer, remoteEndpoint, routing.FlowKey{}, false)
	if err != nil {
		t.Fatalf("session for endpoint: %v", err)
	}
	if key.Encryption != "send_encrypted" {
		t.Fatalf("session key encryption = %q, want send_encrypted", key.Encryption)
	}
	stats := session.Stats()
	if stats.Encryption != "send_encrypted" || !stats.SendEncrypted || stats.ReceiveEncrypted {
		t.Fatalf("session stats = %+v, want send_encrypted only", stats)
	}
}

func TestSessionForEndpointHonorsUnsupportedLinkTLS(t *testing.T) {
	clientRegistry := transport.NewRegistry()
	recorder := &recordingTLSTransport{name: transport.ProtocolTCP}
	if err := clientRegistry.Register(recorder); err != nil {
		t.Fatalf("register client transport: %v", err)
	}
	clientDaemon := &Daemon{
		transports:   clientRegistry,
		dataSessions: make(map[dataSessionKey]transport.Session),
		desired: config.Desired{
			Domain: config.DomainConfig{ID: core.DomainID("lab.local")},
			TransportPolicy: config.TransportPolicyConfig{
				CryptoKeySource: "trustix_x25519",
				TLSIdentity: config.TransportTLSIdentityConfig{
					Mode:        "custom_cert",
					SystemRoots: true,
				},
			},
		},
	}
	peer := config.PeerConfig{
		ID:              core.IXID("ix-b"),
		Domain:          core.DomainID("lab.local"),
		AllowedPrefixes: []core.Prefix{"10.0.1.0/24"},
	}
	endpoint := config.EndpointConfig{
		Name:      core.EndpointID("server"),
		Address:   "127.0.0.1:7001",
		Transport: "tcp",
		Security:  config.EndpointSecurityConfig{LinkTLS: "unsupported"},
	}
	if _, _, _, err := clientDaemon.sessionForEndpoint(context.Background(), peer, endpoint, routing.FlowKey{}, false); err != nil {
		t.Fatalf("session for endpoint: %v", err)
	}
	if recorder.lastDialTLS != nil {
		t.Fatalf("dial TLS config = %#v, want nil for link_tls unsupported", recorder.lastDialTLS)
	}
}

func TestSessionForEndpointUsesLinkTLSByDefault(t *testing.T) {
	clientRegistry := transport.NewRegistry()
	recorder := &recordingTLSTransport{name: transport.ProtocolTCP}
	if err := clientRegistry.Register(recorder); err != nil {
		t.Fatalf("register client transport: %v", err)
	}
	clientDaemon := &Daemon{
		transports:   clientRegistry,
		dataSessions: make(map[dataSessionKey]transport.Session),
		desired: config.Desired{
			Domain: config.DomainConfig{ID: core.DomainID("lab.local")},
			TransportPolicy: config.TransportPolicyConfig{
				CryptoKeySource: "trustix_x25519",
				TLSIdentity: config.TransportTLSIdentityConfig{
					Mode:        "custom_cert",
					SystemRoots: true,
				},
			},
		},
	}
	peer := config.PeerConfig{
		ID:              core.IXID("ix-b"),
		Domain:          core.DomainID("lab.local"),
		AllowedPrefixes: []core.Prefix{"10.0.1.0/24"},
	}
	endpoint := config.EndpointConfig{
		Name:      core.EndpointID("server"),
		Address:   "127.0.0.1:7001",
		Transport: "tcp",
	}
	if _, _, _, err := clientDaemon.sessionForEndpoint(context.Background(), peer, endpoint, routing.FlowKey{}, false); err != nil {
		t.Fatalf("session for endpoint: %v", err)
	}
	if recorder.lastDialTLS == nil {
		t.Fatal("dial TLS config is nil, want default link TLS config")
	}
	if recorder.lastDialTLS.MinVersion != tls.VersionTLS13 {
		t.Fatalf("dial TLS min version = %d, want TLS 1.3", recorder.lastDialTLS.MinVersion)
	}
}

func TestSessionForEndpointRejectsRequiredLinkTLSWithoutTLSState(t *testing.T) {
	clientRegistry := transport.NewRegistry()
	dialedSession := &statsSession{stats: transport.TransportStats{}}
	recorder := &recordingTLSTransport{name: transport.ProtocolTCP, session: dialedSession}
	if err := clientRegistry.Register(recorder); err != nil {
		t.Fatalf("register client transport: %v", err)
	}
	clientDaemon := &Daemon{
		transports:    clientRegistry,
		dataSessions:  make(map[dataSessionKey]transport.Session),
		endpointState: make(map[endpointStateKey]rstate.EndpointState),
		desired: config.Desired{
			Domain: config.DomainConfig{ID: core.DomainID("lab.local")},
			TransportPolicy: config.TransportPolicyConfig{
				Encryption: "plaintext",
				TLSIdentity: config.TransportTLSIdentityConfig{
					Mode:        "custom_cert",
					SystemRoots: true,
				},
			},
		},
	}
	peer := config.PeerConfig{
		ID:              core.IXID("ix-b"),
		Domain:          core.DomainID("lab.local"),
		AllowedPrefixes: []core.Prefix{"10.0.1.0/24"},
	}
	endpoint := config.EndpointConfig{
		Name:      core.EndpointID("server"),
		Address:   "127.0.0.1:7001",
		Transport: "tcp",
		Security: config.EndpointSecurityConfig{
			LinkTLS:    "required",
			Encryption: "plaintext",
		},
	}
	_, _, _, err := clientDaemon.sessionForEndpoint(context.Background(), peer, endpoint, routing.FlowKey{}, false)
	if err == nil {
		t.Fatal("expected required link TLS session without TLS state to fail")
	}
	if recorder.lastDialTLS == nil {
		t.Fatal("dial TLS config is nil, want required link TLS config")
	}
	if len(clientDaemon.dataSessions) != 0 {
		t.Fatalf("data sessions = %d, want none after failed required link TLS", len(clientDaemon.dataSessions))
	}
	if !clientDaemon.endpointMarkedDown(peer.ID, endpoint) {
		t.Fatal("endpoint was not marked down after required link TLS failure")
	}
	select {
	case <-dialedSession.closed:
	default:
		t.Fatal("dialed session was not closed after required link TLS failure")
	}
}

func TestSessionPoolPacketStrategyRotatesConnections(t *testing.T) {
	clientRegistry := transport.NewRegistry()
	if err := clientRegistry.Register(fakeTransportWithSessionStats{name: transport.ProtocolUDP}); err != nil {
		t.Fatalf("register client transport: %v", err)
	}
	clientDaemon := &Daemon{
		transports:   clientRegistry,
		dataSessions: make(map[dataSessionKey]transport.Session),
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				Encryption: "secure",
				SessionPool: config.SessionPoolPolicyConfig{
					Size:     3,
					Strategy: "packet",
				},
				TLSIdentity: config.TransportTLSIdentityConfig{
					Mode:        "custom_cert",
					SystemRoots: true,
				},
			},
		},
	}
	peer := config.PeerConfig{ID: core.IXID("ix-b"), Domain: core.DomainID("lab.local")}
	endpoint := config.EndpointConfig{Name: core.EndpointID("server"), Address: "127.0.0.1:7001", Transport: "udp"}

	var got []int
	for i := 0; i < 5; i++ {
		_, key, _, err := clientDaemon.sessionForEndpoint(context.Background(), peer, endpoint, routing.FlowKey{}, false)
		if err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
		got = append(got, key.PoolIndex)
	}
	want := []int{0, 1, 2, 0, 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("packet pool indexes = %v, want %v", got, want)
	}
	if len(clientDaemon.dataSessions) != 3 {
		t.Fatalf("active pooled sessions = %d, want 3", len(clientDaemon.dataSessions))
	}
}

func TestSessionPoolFlowStrategyKeepsFiveTupleOnSameConnection(t *testing.T) {
	clientRegistry := transport.NewRegistry()
	if err := clientRegistry.Register(fakeTransportWithSessionStats{name: transport.ProtocolUDP}); err != nil {
		t.Fatalf("register client transport: %v", err)
	}
	clientDaemon := &Daemon{
		transports:   clientRegistry,
		dataSessions: make(map[dataSessionKey]transport.Session),
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				Encryption:  "secure",
				SessionPool: config.SessionPoolPolicyConfig{Size: 4, Strategy: "flow"},
				TLSIdentity: config.TransportTLSIdentityConfig{Mode: "custom_cert", SystemRoots: true},
			},
		},
	}
	peer := config.PeerConfig{ID: core.IXID("ix-b"), Domain: core.DomainID("lab.local")}
	endpoint := config.EndpointConfig{Name: core.EndpointID("server"), Address: "127.0.0.1:7001", Transport: "udp"}
	flow := routing.FlowKey{
		SourceIP:        netip.MustParseAddr("10.0.0.2"),
		DestinationIP:   netip.MustParseAddr("10.0.1.2"),
		SourcePort:      12345,
		DestinationPort: 443,
		Protocol:        6,
	}

	_, first, _, err := clientDaemon.sessionForEndpoint(context.Background(), peer, endpoint, flow, true)
	if err != nil {
		t.Fatalf("first flow session: %v", err)
	}
	for i := 0; i < 5; i++ {
		_, key, _, err := clientDaemon.sessionForEndpoint(context.Background(), peer, endpoint, flow, true)
		if err != nil {
			t.Fatalf("flow session %d: %v", i, err)
		}
		if key.PoolIndex != first.PoolIndex {
			t.Fatalf("flow pool index changed from %d to %d", first.PoolIndex, key.PoolIndex)
		}
	}
}

func TestSessionPoolFlowStrategySelectsMatchingReversePoolMember(t *testing.T) {
	peer := config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{
			{Name: core.EndpointID("server"), Mode: config.EndpointModePassive, Transport: "udp"},
		},
	}
	daemon := &Daemon{
		desired: config.Desired{
			Domain: config.DomainConfig{ID: core.DomainID("lab.local")},
			IX:     config.IXConfig{ID: core.IXID("ix-a")},
			Peers:  []config.PeerConfig{peer},
			TransportPolicy: config.TransportPolicyConfig{
				Encryption:  "secure",
				SessionPool: config.SessionPoolPolicyConfig{Size: 4, Strategy: "flow"},
				TLSIdentity: config.TransportTLSIdentityConfig{Mode: "custom_cert", SystemRoots: true},
			},
		},
		transports:       transport.NewRegistry(),
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		endpointState:    make(map[endpointStateKey]rstate.EndpointState),
	}
	defer daemon.closeDataSessions()
	for i := 0; i < 4; i++ {
		session := &blockingIdentitySession{
			peer:   peer.ID,
			domain: peer.Domain,
			recv:   make(chan struct{}),
		}
		if _, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolUDP,
		}, session); err != nil {
			t.Fatalf("register reverse session %d: %v", i, err)
		}
	}
	flow := routing.FlowKey{
		SourceIP:        netip.MustParseAddr("10.0.0.2"),
		DestinationIP:   netip.MustParseAddr("10.0.1.2"),
		SourcePort:      12345,
		DestinationPort: 5201,
		Protocol:        6,
	}

	gotSession, key, _, err := daemon.sessionForEndpoint(context.Background(), peer, peer.Endpoints[0], flow, true)
	if err != nil {
		t.Fatalf("session for reverse pool: %v", err)
	}
	if gotSession == nil {
		t.Fatal("expected reverse pool session")
	}
	if key.Address != reverseSessionAddress {
		t.Fatalf("session address = %q, want reverse", key.Address)
	}
	if key.PoolIndex != 0 {
		t.Fatalf("first flow reverse pool index = %d, want 0", key.PoolIndex)
	}

	flow.SourcePort = 12346
	_, key, _, err = daemon.sessionForEndpoint(context.Background(), peer, peer.Endpoints[0], flow, true)
	if err != nil {
		t.Fatalf("second flow reverse pool: %v", err)
	}
	if key.PoolIndex != 1 {
		t.Fatalf("second flow reverse pool index = %d, want 1", key.PoolIndex)
	}
}

func TestWarmSessionPoolRetriesMissingMembers(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_POOL_WARMUP_RETRY_DELAY", "1ms")
	clientRegistry := transport.NewRegistry()
	flaky := &flakyWarmupTransport{name: transport.ProtocolUDP, fail: 2}
	if err := clientRegistry.Register(flaky); err != nil {
		t.Fatalf("register client transport: %v", err)
	}
	clientDaemon := &Daemon{
		transports:   clientRegistry,
		dataSessions: make(map[dataSessionKey]transport.Session),
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				Encryption:  "secure",
				SessionPool: config.SessionPoolPolicyConfig{Size: 4, Warmup: true},
				TLSIdentity: config.TransportTLSIdentityConfig{Mode: "custom_cert", SystemRoots: true},
			},
		},
	}
	defer clientDaemon.closeDataSessions()
	peer := config.PeerConfig{ID: core.IXID("ix-b"), Domain: core.DomainID("lab.local")}
	cfgEndpoint := config.EndpointConfig{Name: core.EndpointID("server"), Address: "127.0.0.1:7001", Transport: "udp"}
	endpoint := transportEndpointFromConfig(cfgEndpoint)
	endpoint.Enabled = true
	endpoint.Encryption = securetransport.EncryptionSecure
	epoch := clientDaemon.currentDataSessionEpoch()

	clientDaemon.warmSessionPool(context.Background(), epoch, peer, cfgEndpoint, endpoint, 4, -1)

	if got := clientDaemon.missingSessionPoolIndexes(peer.ID, cfgEndpoint, securetransport.EncryptionSecure, 4); len(got) != 0 {
		t.Fatalf("missing pool indexes after retry = %v, want none", got)
	}
	if got := len(clientDaemon.dataSessions); got != 4 {
		t.Fatalf("active pooled sessions = %d, want 4", got)
	}
}

func TestWarmKernelDirectSessionsPreDialsFullPool(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")
	registry := transport.NewRegistry()
	fake := &retainingWarmupTransport{name: transport.ProtocolUDP}
	if err := registry.Register(fake); err != nil {
		t.Fatalf("register client transport: %v", err)
	}
	daemon := &Daemon{
		transports:       registry,
		dataplane:        &warmupKernelUDPDataplane{},
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		endpointState:    make(map[endpointStateKey]rstate.EndpointState),
		flows:            make(map[routing.FlowKey]routing.FlowBinding),
	}
	daemon.desired = config.Desired{
		IX: config.IXConfig{ID: "ix-a"},
		Peers: []config.PeerConfig{{
			ID:     "ix-b",
			Domain: "lab.local",
			Endpoints: []config.EndpointConfig{{
				Name:      "udp-b",
				Address:   "127.0.0.1:17042",
				Transport: string(transport.ProtocolUDP),
				Enabled:   true,
			}},
		}},
		Routes: []config.RouteConfig{{
			Prefix:  "10.0.1.0/24",
			NextHop: "ix-b",
			Metric:  100,
		}},
		TransportPolicy: config.TransportPolicyConfig{
			Encryption: securetransport.EncryptionPlaintext,
			SessionPool: config.SessionPoolPolicyConfig{
				Size:   4,
				Warmup: true,
			},
			KernelTransport: config.KernelTransportPolicyConfig{
				Mode: string(dataplane.KernelTransportModeRequireKernel),
			},
		},
	}
	defer daemon.closeDataSessions()

	if err := daemon.warmKernelDirectSessions(context.Background()); err != nil {
		t.Fatalf("warm kernel direct sessions: %v", err)
	}
	if got := len(daemon.dataSessions); got != 4 {
		t.Fatalf("active direct pool sessions = %d, want 4", got)
	}
	for i := 0; i < 4; i++ {
		key := dataSessionKey{
			Peer:       "ix-b",
			Endpoint:   "udp-b",
			Transport:  transport.ProtocolUDP,
			Address:    "127.0.0.1:17042",
			Encryption: securetransport.EncryptionPlaintext,
			PoolIndex:  i,
		}
		session, ok := daemon.dataSessions[key].(*retainingWarmupSession)
		if !ok {
			t.Fatalf("pool index %d session = %T, want retaining warmup session", i, daemon.dataSessions[key])
		}
		if !session.retained {
			t.Fatalf("pool index %d did not retain kernel flow on close", i)
		}
		runtime := daemon.dataSessionState[key]
		if runtime == nil || !runtime.controlOnly {
			t.Fatalf("pool index %d runtime controlOnly = %#v, want true", i, runtime)
		}
	}
}

func TestWarmKernelDirectRouteSessionsUsesDynamicRuntimeRoutes(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")
	registry := transport.NewRegistry()
	fake := &retainingWarmupTransport{name: transport.ProtocolUDP}
	if err := registry.Register(fake); err != nil {
		t.Fatalf("register client transport: %v", err)
	}
	daemon := &Daemon{
		transports:       registry,
		dataplane:        &warmupKernelUDPDataplane{},
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		endpointState:    make(map[endpointStateKey]rstate.EndpointState),
		flows:            make(map[routing.FlowKey]routing.FlowBinding),
		members: map[core.IXID]memberRecord{
			"ix-b": {
				Advertisement: advertisementResponse{
					DomainID:    "lab.local",
					IXID:        "ix-b",
					LANPrefixes: []string{"10.0.1.0/24"},
					Endpoints: []dataplane.EndpointMetadata{{
						Peer:      "ix-b",
						ID:        "udp-b",
						Address:   "127.0.0.1:17042",
						Transport: string(transport.ProtocolUDP),
						Enabled:   true,
						Security: dataplane.EndpointSecurityMetadata{
							Encryption: securetransport.EncryptionPlaintext,
						},
					}},
				},
				LastSeen: time.Now().UTC(),
				Direct:   true,
			},
		},
	}
	daemon.desired = config.Desired{
		Domain: config.DomainConfig{ID: "lab.local"},
		IX:     config.IXConfig{ID: "ix-a"},
		Endpoints: []config.EndpointConfig{{
			Name:      "ix-a-udp",
			Mode:      config.EndpointModePassive,
			Listen:    "127.0.0.1:17041",
			Address:   "127.0.0.1:17041",
			Transport: string(transport.ProtocolUDP),
			Enabled:   true,
		}},
		TransportPolicy: config.TransportPolicyConfig{
			Encryption: securetransport.EncryptionPlaintext,
			SessionPool: config.SessionPoolPolicyConfig{
				Warmup: true,
			},
			KernelTransport: config.KernelTransportPolicyConfig{
				Mode: string(dataplane.KernelTransportModeAuto),
			},
		},
	}
	defer daemon.closeDataSessions()

	warmed, err := daemon.warmKernelDirectRouteSessionsResult(context.Background())
	if err != nil {
		t.Fatalf("warm kernel direct runtime routes: %v", err)
	}
	if !warmed {
		t.Fatal("dynamic runtime route was not warmed")
	}
	key := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "udp-b",
		Transport:  transport.ProtocolUDP,
		Address:    "127.0.0.1:17042",
		Encryption: securetransport.EncryptionPlaintext,
	}
	session, ok := daemon.dataSessions[key].(*retainingWarmupSession)
	if !ok {
		t.Fatalf("dynamic warmup session = %T, want retaining warmup session", daemon.dataSessions[key])
	}
	if !session.retained {
		t.Fatal("dynamic runtime route warmup did not retain kernel flow on close")
	}
	runtime := daemon.dataSessionState[key]
	if runtime == nil || !runtime.controlOnly {
		t.Fatalf("dynamic runtime route warmup controlOnly = %#v, want true", runtime)
	}
}

func TestWarmRouteSessionsPreDialsSingleSession(t *testing.T) {
	registry := transport.NewRegistry()
	fake := &flakyWarmupTransport{name: transport.ProtocolUDP}
	if err := registry.Register(fake); err != nil {
		t.Fatalf("register client transport: %v", err)
	}
	daemon := &Daemon{
		transports:       registry,
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		endpointState:    make(map[endpointStateKey]rstate.EndpointState),
		flows:            make(map[routing.FlowKey]routing.FlowBinding),
	}
	daemon.desired = config.Desired{
		IX: config.IXConfig{ID: "ix-a"},
		Peers: []config.PeerConfig{{
			ID:     "ix-b",
			Domain: "lab.local",
			Endpoints: []config.EndpointConfig{{
				Name:      "udp-b",
				Address:   "127.0.0.1:17042",
				Transport: string(transport.ProtocolUDP),
				Enabled:   true,
			}},
		}},
		Routes: []config.RouteConfig{{
			Prefix:  "10.0.1.0/24",
			NextHop: "ix-b",
			Metric:  100,
		}},
		TransportPolicy: config.TransportPolicyConfig{
			Encryption:  securetransport.EncryptionPlaintext,
			SessionPool: config.SessionPoolPolicyConfig{Size: 1, Warmup: true},
		},
	}
	defer daemon.closeDataSessions()

	if err := daemon.warmRouteSessions(context.Background()); err != nil {
		t.Fatalf("warm route sessions: %v", err)
	}
	if got := len(daemon.dataSessions); got != 1 {
		t.Fatalf("active sessions = %d, want 1", got)
	}
}

func TestWarmRouteSessionsParallelCandidatesDoesNotBlockOnSlowPreferred(t *testing.T) {
	registry := transport.NewRegistry()
	slow := &blockingWarmupTransport{name: transport.ProtocolHTTPConnect, started: make(chan struct{}, 1)}
	if err := registry.Register(slow); err != nil {
		t.Fatalf("register slow transport: %v", err)
	}
	if err := registry.Register(&retainingWarmupTransport{name: transport.ProtocolUDP}); err != nil {
		t.Fatalf("register udp transport: %v", err)
	}
	daemon := &Daemon{
		transports:       registry,
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		endpointState:    make(map[endpointStateKey]rstate.EndpointState),
		flows:            make(map[routing.FlowKey]routing.FlowBinding),
	}
	daemon.desired = config.Desired{
		IX: config.IXConfig{ID: "ix-b"},
		Peers: []config.PeerConfig{{
			ID:     "ix-a",
			Domain: "lab.local",
			Endpoints: []config.EndpointConfig{
				{Name: "a-http-connect", Address: "127.0.0.1:7091", Transport: string(transport.ProtocolHTTPConnect), Priority: 50},
				{Name: "a-udp", Address: "127.0.0.1:7001", Transport: string(transport.ProtocolUDP), Priority: 10},
			},
		}},
		Routes: []config.RouteConfig{{
			Prefix:  "10.0.0.0/24",
			NextHop: "ix-a",
			Metric:  100,
		}},
		TransportPolicy: config.TransportPolicyConfig{
			Encryption: "plaintext",
			KernelTransport: config.KernelTransportPolicyConfig{
				Mode: string(dataplane.KernelTransportModeDisabled),
			},
			SessionPool: config.SessionPoolPolicyConfig{Warmup: true},
		},
	}
	defer daemon.closeDataSessions()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := daemon.warmRouteSessions(ctx); err != nil {
		t.Fatalf("warm route sessions: %v", err)
	}
	select {
	case <-slow.started:
	case <-time.After(25 * time.Millisecond):
	}
	key := dataSessionKey{
		Peer:       "ix-a",
		Endpoint:   "a-udp",
		Transport:  transport.ProtocolUDP,
		Address:    "127.0.0.1:7001",
		Encryption: "plaintext",
	}
	if _, ok := daemon.dataSessions[key]; !ok {
		t.Fatalf("udp session was not warmed; sessions=%v", daemon.dataSessions)
	}
}

func TestInboundDataSessionRegistersReverseChannel(t *testing.T) {
	peer := config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{
			{Name: core.EndpointID("ep-1"), Mode: config.EndpointModePassive, Transport: "udp"},
		},
	}
	session := &blockingIdentitySession{
		peer:   peer.ID,
		domain: peer.Domain,
		recv:   make(chan struct{}),
	}
	daemon := &Daemon{
		dataplane: &kernelTransportDataplane{
			NoopManager: dataplane.NewNoopManager(),
			status: dataplane.KernelTransportStatus{
				Available: true,
				Provider:  "test",
				Protocols: []dataplane.KernelTransportProtocol{{
					Protocol:  string(transport.ProtocolUDP),
					Available: true,
				}},
			},
		},
		desired: config.Desired{
			Domain: config.DomainConfig{ID: core.DomainID("lab.local")},
			IX:     config.IXConfig{ID: core.IXID("ix-a")},
			Peers:  []config.PeerConfig{peer},
		},
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		endpointState:    make(map[endpointStateKey]rstate.EndpointState),
	}
	defer daemon.closeDataSessions()

	runtime, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{
		Name:      core.EndpointID("ep-1"),
		Transport: transport.ProtocolUDP,
	}, session)
	if err != nil {
		t.Fatalf("register inbound session: %v", err)
	}
	if runtime == nil {
		t.Fatal("expected inbound runtime")
	}
	key := reverseDataSessionKey(peer.ID, peer.Endpoints[0], securetransport.EncryptionSecure)
	if daemon.dataSessions[key] != session {
		t.Fatalf("reverse session not registered under key %#v", key)
	}
	if key.Address != reverseSessionAddress {
		t.Fatalf("reverse session address = %q, want %q", key.Address, reverseSessionAddress)
	}
}

func TestInboundDeviceSessionRegistersLeaseRoute(t *testing.T) {
	session := &deviceIdentitySession{
		identity: transport.PeerIdentity{
			Role:   "device",
			Peer:   "ix-a",
			Domain: "lab.local",
			Device: "laptop-1",
		},
		recv: make(chan struct{}),
	}
	daemon := &Daemon{
		desired: config.Desired{
			Domain: config.DomainConfig{ID: core.DomainID("lab.local")},
			IX:     config.IXConfig{ID: core.IXID("ix-a")},
			LAN: config.LANConfig{
				Gateway: "10.0.0.1/24",
				DeviceAccess: config.DeviceAccessConfig{
					Enabled:     true,
					AddressPool: "10.0.0.240/28",
					LeaseTTL:    "1h",
				},
			},
			Endpoints: []config.EndpointConfig{{
				Name:      core.EndpointID("access-udp"),
				Mode:      config.EndpointModePassive,
				Transport: "udp",
				Enabled:   true,
			}},
		},
		dataplane:        &dataplane.NoopManager{},
		routes:           routing.NewTable(),
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		deviceLeases:     make(map[deviceLeaseKey]deviceAccessLease),
		endpointState:    make(map[endpointStateKey]rstate.EndpointState),
	}
	defer daemon.closeDataSessions()

	runtime, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{
		Name:      core.EndpointID("access-udp"),
		Transport: transport.ProtocolUDP,
	}, session)
	if err != nil {
		t.Fatalf("register inbound device session: %v", err)
	}
	if runtime == nil {
		t.Fatal("expected device runtime")
	}
	peerID := core.IXID("device:ix-a:laptop-1")
	if runtime.peer.ID != peerID {
		t.Fatalf("runtime peer = %q, want %q", runtime.peer.ID, peerID)
	}
	key := reverseDataSessionKey(peerID, daemon.desired.Endpoints[0], securetransport.EncryptionSecure)
	if daemon.dataSessions[key] != session {
		t.Fatalf("device reverse session not registered under key %#v", key)
	}
	leaseKey := deviceLeaseKey{IX: "ix-a", Device: "laptop-1"}
	lease, ok := daemon.deviceLeases[leaseKey]
	if !ok {
		t.Fatal("device lease was not stored")
	}
	if lease.Address != netip.MustParseAddr("10.0.0.240") || lease.Prefix.String() != "10.0.0.240/32" {
		t.Fatalf("lease = %s %s, want 10.0.0.240/32", lease.Address, lease.Prefix)
	}
	if len(session.sent) == 0 || !isDataSessionControlPacket(session.sent[0]) || session.sent[0][5] != dataSessionControlDeviceLease {
		t.Fatalf("lease control frames = %#v", session.sent)
	}
	if got := netip.AddrFrom4([4]byte{session.sent[0][8], session.sent[0][9], session.sent[0][10], session.sent[0][11]}); got != lease.Address {
		t.Fatalf("lease frame address = %s, want %s", got, lease.Address)
	}
	decision, ok := daemon.routes.Lookup(lease.Address)
	if !ok {
		t.Fatal("device lease route not installed")
	}
	if decision.Route.NextHop != peerID || decision.Route.Source != "device_access" {
		t.Fatalf("device route = %+v", decision.Route)
	}
	peer, ok := daemon.effectivePeerConfig(peerID)
	if !ok {
		t.Fatal("device peer config missing")
	}
	if len(peer.AllowedPrefixes) != 1 || peer.AllowedPrefixes[0] != core.Prefix("10.0.0.240/32") {
		t.Fatalf("device allowed prefixes = %#v", peer.AllowedPrefixes)
	}
	if len(peer.Endpoints) != 1 || peer.Endpoints[0].Name != "access-udp" || peer.Endpoints[0].Address != "" {
		t.Fatalf("device peer endpoints = %#v", peer.Endpoints)
	}
}

func TestInboundDeviceSessionRegistersAdvertisedPrefixRoute(t *testing.T) {
	session := &deviceIdentitySession{
		identity: transport.PeerIdentity{
			Role:     "device",
			Peer:     "ix-a",
			Domain:   "lab.local",
			Device:   "router-1",
			Prefixes: []string{"10.0.0.0/25"},
		},
		recv: make(chan struct{}),
	}
	daemon := &Daemon{
		desired: config.Desired{
			Domain: config.DomainConfig{ID: core.DomainID("lab.local")},
			IX:     config.IXConfig{ID: core.IXID("ix-a")},
			LAN: config.LANConfig{
				Gateway:   "10.0.0.1/24",
				Advertise: []core.Prefix{"10.0.0.0/24"},
				DeviceAccess: config.DeviceAccessConfig{
					Enabled:     true,
					AddressPool: "10.0.0.240/28",
					LeaseTTL:    "1h",
				},
			},
			Endpoints: []config.EndpointConfig{{
				Name:      core.EndpointID("access-udp"),
				Mode:      config.EndpointModePassive,
				Transport: "udp",
				Enabled:   true,
			}},
		},
		dataplane:        &dataplane.NoopManager{},
		routes:           routing.NewTable(),
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		deviceLeases:     make(map[deviceLeaseKey]deviceAccessLease),
		endpointState:    make(map[endpointStateKey]rstate.EndpointState),
	}
	defer daemon.closeDataSessions()

	if _, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{
		Name:      core.EndpointID("access-udp"),
		Transport: transport.ProtocolUDP,
	}, session); err != nil {
		t.Fatalf("register inbound device session: %v", err)
	}
	peerID := core.IXID("device:ix-a:router-1")
	route, ok := routeByPrefix(daemon.runtimeRoutes(), "10.0.0.0/25")
	if !ok || route.NextHop != peerID || route.Source != "device_access" {
		t.Fatalf("advertised device route = %#v ok=%t", route, ok)
	}
	peer, ok := daemon.effectivePeerConfig(peerID)
	if !ok {
		t.Fatal("device peer config missing")
	}
	if len(peer.AllowedPrefixes) != 2 || peer.AllowedPrefixes[1] != core.Prefix("10.0.0.0/25") {
		t.Fatalf("device allowed prefixes = %#v", peer.AllowedPrefixes)
	}
	if len(session.sent) == 0 || !isDataSessionControlPacket(session.sent[0]) {
		t.Fatalf("lease control frames = %#v", session.sent)
	}
	if count := int(binary.BigEndian.Uint16(session.sent[0][24:26])); count != 1 {
		t.Fatalf("lease route count = %d, want 1", count)
	}
	got := netip.AddrFrom4([4]byte{session.sent[0][28], session.sent[0][29], session.sent[0][30], session.sent[0][31]})
	if got != netip.MustParseAddr("10.0.0.0") || session.sent[0][32] != 24 {
		t.Fatalf("lease client route = %s/%d, want 10.0.0.0/24", got, session.sent[0][32])
	}
}

func TestRuntimeSnapshotRefreshesDeviceClientRoutes(t *testing.T) {
	session := &deviceIdentitySession{
		identity: transport.PeerIdentity{
			Role:   "device",
			Peer:   "ix-a",
			Domain: "lab.local",
			Device: "laptop-1",
		},
		recv: make(chan struct{}),
	}
	daemon := &Daemon{
		desired: config.Desired{
			Domain: config.DomainConfig{ID: core.DomainID("lab.local")},
			IX:     config.IXConfig{ID: core.IXID("ix-a")},
			LAN: config.LANConfig{
				Gateway:   "10.0.0.1/24",
				Advertise: []core.Prefix{"10.0.0.0/24"},
				DeviceAccess: config.DeviceAccessConfig{
					Enabled:     true,
					AddressPool: "10.0.0.240/28",
					LeaseTTL:    "1h",
				},
			},
			Endpoints: []config.EndpointConfig{{
				Name:      core.EndpointID("access-udp"),
				Mode:      config.EndpointModePassive,
				Transport: "udp",
				Enabled:   true,
			}},
		},
		dataplane:        &dataplane.NoopManager{},
		routes:           routing.NewTable(),
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		deviceLeases:     make(map[deviceLeaseKey]deviceAccessLease),
		endpointState:    make(map[endpointStateKey]rstate.EndpointState),
	}
	defer daemon.closeDataSessions()
	if _, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{
		Name:      core.EndpointID("access-udp"),
		Transport: transport.ProtocolUDP,
	}, session); err != nil {
		t.Fatalf("register inbound device session: %v", err)
	}
	before := len(session.sent)
	daemon.desired.Routes = append(daemon.desired.Routes, config.RouteConfig{
		Prefix:  "10.55.0.0/24",
		Owner:   "ix-a",
		NextHop: "ix-a",
		Kind:    routing.RouteLocal,
	})
	if err := daemon.applyRuntimeDataplaneSnapshot(context.Background()); err != nil {
		t.Fatalf("apply runtime snapshot: %v", err)
	}
	if len(session.sent) <= before {
		t.Fatalf("device route refresh frames = %d, want more than %d", len(session.sent), before)
	}
	frame := session.sent[len(session.sent)-1]
	found := false
	count := int(binary.BigEndian.Uint16(frame[24:26]))
	for i := 0; i < count; i++ {
		offset := dataSessionControlDeviceLeaseLen + i*dataSessionControlDeviceLeaseRouteLen
		addr := netip.AddrFrom4([4]byte{frame[offset], frame[offset+1], frame[offset+2], frame[offset+3]})
		if addr == netip.MustParseAddr("10.55.0.0") && frame[offset+4] == 24 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("refreshed lease frame missing 10.55.0.0/24: %#v", frame)
	}
}

func TestInboundDeviceSessionRefreshesLocalAdvertisement(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desired := desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24")
	desired.LAN.DeviceAccess = config.DeviceAccessConfig{
		Enabled:     true,
		AddressPool: "10.0.0.240/28",
		LeaseTTL:    "1h",
	}
	daemon := newMembershipTestDaemon(t, desired, 1)
	daemon.dataplane = dataplane.NewNoopManager()
	daemon.routes = routing.NewTable()
	daemon.dataSessions = make(map[dataSessionKey]transport.Session)
	daemon.dataSessionState = make(map[dataSessionKey]*dataSessionRuntime)
	daemon.deviceLeases = make(map[deviceLeaseKey]deviceAccessLease)
	daemon.endpointState = make(map[endpointStateKey]rstate.EndpointState)
	session := &deviceIdentitySession{
		identity: transport.PeerIdentity{
			Role:   "device",
			Peer:   "ix-a",
			Domain: "lab.local",
			Device: "laptop-1",
		},
		recv: make(chan struct{}),
	}
	defer daemon.closeDataSessions()

	if _, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{
		Name:      core.EndpointID("ix-a-udp"),
		Transport: transport.ProtocolUDP,
	}, session); err != nil {
		t.Fatalf("register inbound device session: %v", err)
	}
	if !containsString(daemon.localAd.LANPrefixes, "10.0.0.240/32") {
		t.Fatalf("local advertisement prefixes = %#v, want device /32", daemon.localAd.LANPrefixes)
	}
}

func TestReceivedPacketToDeviceAccessRouteUsesReverseSessionBeforeLocalLANInject(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH", "0")
	session := &recordingSession{}
	daemon := &Daemon{
		desired: config.Desired{
			Domain: config.DomainConfig{ID: core.DomainID("lab.local")},
			IX:     config.IXConfig{ID: core.IXID("ix-a")},
			LAN: config.LANConfig{
				Gateway:   "10.0.0.1/24",
				Advertise: []core.Prefix{"10.0.0.0/24"},
				DeviceAccess: config.DeviceAccessConfig{
					Enabled:     true,
					AddressPool: "10.0.0.240/28",
				},
			},
			Endpoints: []config.EndpointConfig{{
				Name:       core.EndpointID("access-udp"),
				Mode:       config.EndpointModePassive,
				Transport:  "udp",
				Enabled:    true,
				EnabledSet: true,
			}},
		},
		routes:           routing.NewTable(),
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		deviceLeases:     make(map[deviceLeaseKey]deviceAccessLease),
	}
	peerID := core.IXID("device:ix-a:laptop-1")
	endpoint := daemon.desired.Endpoints[0]
	key := reverseDataSessionKey(peerID, endpoint, securetransport.EncryptionSecure)
	daemon.dataSessions[key] = session
	daemon.dataSessionState[key] = &dataSessionRuntime{key: key, session: session, peer: config.PeerConfig{
		ID:              peerID,
		Domain:          "lab.local",
		Endpoints:       []config.EndpointConfig{endpoint},
		AllowedPrefixes: []core.Prefix{"10.0.0.240/32"},
	}, endpoint: endpoint}
	daemon.deviceLeases[deviceLeaseKey{IX: "ix-a", Device: "laptop-1"}] = deviceAccessLease{
		Key:        deviceLeaseKey{IX: "ix-a", Device: "laptop-1"},
		Address:    netip.MustParseAddr("10.0.0.240"),
		Prefix:     netip.MustParsePrefix("10.0.0.240/32"),
		SessionKey: key,
		Endpoint:   endpoint,
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	if err := daemon.routes.Replace(daemon.runtimeRoutes()); err != nil {
		t.Fatalf("replace routes: %v", err)
	}
	packet := tcpPayloadIPv4Packet([]byte("to-device"))
	copy(packet[16:20], []byte{10, 0, 0, 240})
	packet[8] = 64
	injector := &recordingInjector{}

	if err := daemon.handleReceivedDataPathPacket(context.Background(), packet, injector); err != nil {
		t.Fatalf("handle received packet to device: %v", err)
	}
	if len(injector.packets) != 0 || len(injector.batchPackets) != 0 {
		t.Fatalf("local LAN injector used for device route: singles=%d batches=%d", len(injector.packets), len(injector.batchPackets))
	}
	if len(session.sent) != 1 {
		t.Fatalf("device reverse session packets = %d, want 1", len(session.sent))
	}
	if got := netip.AddrFrom4([4]byte{session.sent[0][16], session.sent[0][17], session.sent[0][18], session.sent[0][19]}); got != netip.MustParseAddr("10.0.0.240") {
		t.Fatalf("forwarded destination = %s", got)
	}
	if session.sent[0][8] != 63 {
		t.Fatalf("forwarded TTL = %d, want 63", session.sent[0][8])
	}
}

func TestInboundDeviceSessionRejectedWhenAccessDisabled(t *testing.T) {
	session := &deviceIdentitySession{
		identity: transport.PeerIdentity{
			Role:   "device",
			Peer:   "ix-a",
			Domain: "lab.local",
			Device: "laptop-1",
		},
	}
	daemon := &Daemon{
		desired: config.Desired{
			Domain: config.DomainConfig{ID: core.DomainID("lab.local")},
			IX:     config.IXConfig{ID: core.IXID("ix-a")},
			Endpoints: []config.EndpointConfig{{
				Name:      core.EndpointID("access-udp"),
				Mode:      config.EndpointModePassive,
				Transport: "udp",
				Enabled:   true,
			}},
		},
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		endpointState:    make(map[endpointStateKey]rstate.EndpointState),
	}

	if _, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{
		Name:      core.EndpointID("access-udp"),
		Transport: transport.ProtocolUDP,
	}, session); err == nil {
		t.Fatal("expected disabled device access to reject device session")
	}
	if len(daemon.dataSessions) != 0 {
		t.Fatalf("data sessions = %d, want none", len(daemon.dataSessions))
	}
}

func TestInboundDataSessionAnnotatesPeerEndpoint(t *testing.T) {
	peer := config.PeerConfig{
		ID:     core.IXID("ix-a"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{
			{Name: core.EndpointID("ix-a-udp"), Mode: config.EndpointModePassive, Transport: "udp"},
		},
	}
	session := &endpointAnnotatingIdentitySession{
		blockingIdentitySession: blockingIdentitySession{
			peer:   peer.ID,
			domain: peer.Domain,
			recv:   make(chan struct{}),
		},
	}
	daemon := &Daemon{
		desired: config.Desired{
			Domain: config.DomainConfig{ID: core.DomainID("lab.local")},
			IX:     config.IXConfig{ID: core.IXID("ix-b")},
			Peers:  []config.PeerConfig{peer},
		},
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		endpointState:    make(map[endpointStateKey]rstate.EndpointState),
	}
	defer daemon.closeDataSessions()

	if _, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{
		Name:      core.EndpointID("ix-b-udp"),
		Transport: transport.ProtocolUDP,
	}, session); err != nil {
		t.Fatalf("register inbound session: %v", err)
	}
	if session.annotatedPeer != "ix-a" || session.annotatedEndpoint != "ix-a-udp" {
		t.Fatalf("annotated peer endpoint = %q/%q, want ix-a/ix-a-udp", session.annotatedPeer, session.annotatedEndpoint)
	}
}

func TestInboundDataSessionRegistersReversePoolMembers(t *testing.T) {
	peer := config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{
			{Name: core.EndpointID("ep-1"), Mode: config.EndpointModePassive, Transport: "udp"},
		},
	}
	daemon := &Daemon{
		dataplane: &kernelTransportDataplane{
			NoopManager: dataplane.NewNoopManager(),
			status: dataplane.KernelTransportStatus{
				Available: true,
				Provider:  "test",
				Protocols: []dataplane.KernelTransportProtocol{{
					Protocol:  string(transport.ProtocolUDP),
					Available: true,
				}},
			},
		},
		desired: config.Desired{
			Domain: config.DomainConfig{ID: core.DomainID("lab.local")},
			IX:     config.IXConfig{ID: core.IXID("ix-a")},
			Peers:  []config.PeerConfig{peer},
			TransportPolicy: config.TransportPolicyConfig{
				SessionPool: config.SessionPoolPolicyConfig{Size: 3},
			},
		},
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		endpointState:    make(map[endpointStateKey]rstate.EndpointState),
	}
	defer daemon.closeDataSessions()

	for i := 0; i < 3; i++ {
		session := &blockingIdentitySession{
			peer:   peer.ID,
			domain: peer.Domain,
			recv:   make(chan struct{}),
		}
		if _, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{
			Name:      core.EndpointID("ep-1"),
			Transport: transport.ProtocolUDP,
		}, session); err != nil {
			t.Fatalf("register inbound session %d: %v", i, err)
		}
	}

	for i := 0; i < 3; i++ {
		key := reverseDataSessionKey(peer.ID, peer.Endpoints[0], securetransport.EncryptionSecure)
		key.PoolIndex = i
		if daemon.dataSessions[key] == nil {
			t.Fatalf("reverse pool member %d was not registered", i)
		}
	}
	if got := daemon.activeReverseSessionsForEndpoint(peer.ID, peer.Endpoints[0]); got != 3 {
		t.Fatalf("active reverse sessions = %d, want 3", got)
	}
}

func TestInboundDataSessionCapsReversePoolMembers(t *testing.T) {
	peer := config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{
			{Name: core.EndpointID("ep-1"), Mode: config.EndpointModePassive, Transport: "udp"},
		},
	}
	daemon := &Daemon{
		desired: config.Desired{
			Domain: config.DomainConfig{ID: core.DomainID("lab.local")},
			IX:     config.IXConfig{ID: core.IXID("ix-a")},
			Peers:  []config.PeerConfig{peer},
			TransportPolicy: config.TransportPolicyConfig{
				SessionPool: config.SessionPoolPolicyConfig{Size: 2},
			},
		},
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		endpointState:    make(map[endpointStateKey]rstate.EndpointState),
	}
	defer daemon.closeDataSessions()

	first := &blockingIdentitySession{
		peer:   peer.ID,
		domain: peer.Domain,
		recv:   make(chan struct{}),
	}
	if _, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{
		Name:      core.EndpointID("ep-1"),
		Transport: transport.ProtocolUDP,
	}, first); err != nil {
		t.Fatalf("register first inbound session: %v", err)
	}
	second := &blockingIdentitySession{
		peer:   peer.ID,
		domain: peer.Domain,
		recv:   make(chan struct{}),
	}
	if _, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{
		Name:      core.EndpointID("ep-1"),
		Transport: transport.ProtocolUDP,
	}, second); err != nil {
		t.Fatalf("register second inbound session: %v", err)
	}
	key0 := reverseDataSessionKey(peer.ID, peer.Endpoints[0], securetransport.EncryptionSecure)
	key1 := key0
	key1.PoolIndex = 1
	if runtime := daemon.dataSessionState[key0]; runtime != nil {
		runtime.lastRX.Store(1)
		runtime.lastTX.Store(1)
		runtime.lastUp.Store(1)
		runtime.lastPong.Store(1)
	}
	if runtime := daemon.dataSessionState[key1]; runtime != nil {
		now := time.Now().UTC().UnixNano()
		runtime.lastRX.Store(now)
		runtime.lastTX.Store(now)
		runtime.lastUp.Store(now)
		runtime.lastPong.Store(now)
	}
	third := &blockingIdentitySession{
		peer:   peer.ID,
		domain: peer.Domain,
		recv:   make(chan struct{}),
	}
	if _, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{
		Name:      core.EndpointID("ep-1"),
		Transport: transport.ProtocolUDP,
	}, third); err != nil {
		t.Fatalf("register third inbound session: %v", err)
	}

	if got := daemon.activeReverseSessionsForEndpoint(peer.ID, peer.Endpoints[0]); got != 2 {
		t.Fatalf("active reverse sessions = %d, want capped at 2", got)
	}
	if !first.closed {
		t.Fatal("oldest reverse pool member was not closed when the pool was full")
	}
	if daemon.dataSessions[key0] != third {
		t.Fatal("new reverse session did not replace the least active pool member")
	}
	if daemon.dataSessions[key1] != second {
		t.Fatal("active reverse pool member was unexpectedly replaced")
	}
}

func TestInboundDataSessionRejectsRequiredLocalLinkTLSWithoutTLSState(t *testing.T) {
	peer := config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{
			{Name: core.EndpointID("ep-1"), Mode: config.EndpointModePassive, Transport: "tcp"},
		},
	}
	session := &blockingIdentitySession{
		peer:   peer.ID,
		domain: peer.Domain,
		recv:   make(chan struct{}),
	}
	daemon := &Daemon{
		desired: config.Desired{
			Domain: config.DomainConfig{ID: core.DomainID("lab.local")},
			IX:     config.IXConfig{ID: core.IXID("ix-a")},
			Endpoints: []config.EndpointConfig{
				{
					Name:      core.EndpointID("ep-1"),
					Mode:      config.EndpointModePassive,
					Transport: "tcp",
					Security: config.EndpointSecurityConfig{
						LinkTLS: "required",
					},
				},
			},
			Peers: []config.PeerConfig{peer},
		},
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		endpointState:    make(map[endpointStateKey]rstate.EndpointState),
	}

	if _, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{
		Name:      core.EndpointID("ep-1"),
		Transport: transport.ProtocolTCP,
	}, session); err == nil {
		t.Fatal("expected inbound session without link TLS to fail local required link TLS")
	}
	if len(daemon.dataSessions) != 0 {
		t.Fatalf("data sessions = %d, want none after failed inbound required link TLS", len(daemon.dataSessions))
	}
}

func TestSessionForEndpointUsesReverseChannelWithoutAddress(t *testing.T) {
	peer := config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{
			{Name: core.EndpointID("ep-1"), Mode: config.EndpointModePassive, Transport: "udp"},
		},
	}
	session := &blockingIdentitySession{
		peer:   peer.ID,
		domain: peer.Domain,
		recv:   make(chan struct{}),
	}
	daemon := &Daemon{
		desired: config.Desired{
			Domain: config.DomainConfig{ID: core.DomainID("lab.local")},
			IX:     config.IXConfig{ID: core.IXID("ix-a")},
			Peers:  []config.PeerConfig{peer},
		},
		transports:       transport.NewRegistry(),
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		endpointState:    make(map[endpointStateKey]rstate.EndpointState),
	}
	defer daemon.closeDataSessions()
	if _, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{
		Name:      core.EndpointID("ep-1"),
		Transport: transport.ProtocolUDP,
	}, session); err != nil {
		t.Fatalf("register inbound session: %v", err)
	}

	gotSession, key, runtime, err := daemon.sessionForEndpoint(context.Background(), peer, peer.Endpoints[0], routing.FlowKey{}, false)
	if err != nil {
		t.Fatalf("session for reverse endpoint: %v", err)
	}
	if gotSession != session {
		t.Fatal("sessionForEndpoint did not reuse reverse inbound session")
	}
	if runtime == nil {
		t.Fatal("expected reverse runtime")
	}
	if key.Address != reverseSessionAddress {
		t.Fatalf("session key address = %q, want %q", key.Address, reverseSessionAddress)
	}
}

func TestSessionForEndpointPrefersDirectForAddressedEndpointOverReverse(t *testing.T) {
	peer := config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{
			{Name: core.EndpointID("ep-1"), Address: "192.0.2.1:7001", Transport: "udp"},
		},
	}
	reverseSession := &blockingIdentitySession{
		peer:   peer.ID,
		domain: peer.Domain,
		recv:   make(chan struct{}),
	}
	directSession := &statsSession{}
	recorder := &recordingTLSTransport{name: transport.ProtocolUDP, session: directSession}
	registry := transport.NewRegistry()
	if err := registry.Register(recorder); err != nil {
		t.Fatalf("register transport: %v", err)
	}
	daemon := &Daemon{
		desired: config.Desired{
			Domain: config.DomainConfig{ID: core.DomainID("lab.local")},
			IX:     config.IXConfig{ID: core.IXID("ix-a")},
			Peers:  []config.PeerConfig{peer},
		},
		transports:       registry,
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		endpointState:    make(map[endpointStateKey]rstate.EndpointState),
	}
	defer daemon.closeDataSessions()
	if _, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{
		Name:      core.EndpointID("ep-1"),
		Transport: transport.ProtocolUDP,
	}, reverseSession); err != nil {
		t.Fatalf("register reverse session: %v", err)
	}

	gotSession, key, _, err := daemon.sessionForEndpoint(context.Background(), peer, peer.Endpoints[0], routing.FlowKey{}, false)
	if err != nil {
		t.Fatalf("session for addressed endpoint: %v", err)
	}
	if gotSession != directSession {
		t.Fatal("sessionForEndpoint reused reverse session for an addressed endpoint")
	}
	if key.Address != peer.Endpoints[0].Address {
		t.Fatalf("session key address = %q, want direct address %q", key.Address, peer.Endpoints[0].Address)
	}
	if recorder.dialCount != 1 {
		t.Fatalf("dial count = %d, want 1", recorder.dialCount)
	}
}

func TestSessionForEndpointPrefersReverseForAddressedSecureKernelUDP(t *testing.T) {
	peer := config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{
			{Name: core.EndpointID("ep-1"), Address: "192.0.2.1:7001", Transport: "udp"},
		},
	}
	reverseSession := &blockingIdentitySession{
		peer:   peer.ID,
		domain: peer.Domain,
		recv:   make(chan struct{}),
	}
	directSession := &statsSession{}
	recorder := &recordingTLSTransport{name: transport.ProtocolUDP, session: directSession}
	registry := transport.NewRegistry()
	if err := registry.Register(recorder); err != nil {
		t.Fatalf("register transport: %v", err)
	}
	reverseKey := reverseDataSessionKey(peer.ID, peer.Endpoints[0], securetransport.EncryptionSecure)
	reverseRuntime := &dataSessionRuntime{key: reverseKey, session: reverseSession}
	daemon := &Daemon{
		desired: config.Desired{
			Domain: config.DomainConfig{ID: core.DomainID("lab.local")},
			IX:     config.IXConfig{ID: core.IXID("ix-a")},
			Peers:  []config.PeerConfig{peer},
			TransportPolicy: config.TransportPolicyConfig{
				Encryption: securetransport.EncryptionSecure,
				KernelTransport: config.KernelTransportPolicyConfig{
					Mode: string(dataplane.KernelTransportModeRequireKernel),
				},
			},
		},
		transports: registry,
		dataSessions: map[dataSessionKey]transport.Session{
			reverseKey: reverseSession,
		},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{
			reverseKey: reverseRuntime,
		},
		endpointState: make(map[endpointStateKey]rstate.EndpointState),
	}
	defer daemon.closeDataSessions()

	gotSession, key, runtime, err := daemon.sessionForEndpoint(context.Background(), peer, peer.Endpoints[0], routing.FlowKey{}, false)
	if err != nil {
		t.Fatalf("session for secure kernel_udp endpoint: %v", err)
	}
	if gotSession != reverseSession {
		t.Fatal("sessionForEndpoint did not reuse reverse secure kernel_udp session")
	}
	if runtime != reverseRuntime {
		t.Fatal("expected reverse runtime")
	}
	if key.Address != reverseSessionAddress {
		t.Fatalf("session key address = %q, want %q", key.Address, reverseSessionAddress)
	}
	if recorder.dialCount != 0 {
		t.Fatalf("dial count = %d, want 0", recorder.dialCount)
	}
}

func TestSessionForEndpointCanDisableReversePreferenceForAddressedSecureKernelUDP(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_SECURE_PREFER_REVERSE_SESSION", "0")
	peer := config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{
			{Name: core.EndpointID("ep-1"), Address: "192.0.2.1:7001", Transport: "udp"},
		},
	}
	reverseSession := &blockingIdentitySession{
		peer:   peer.ID,
		domain: peer.Domain,
		recv:   make(chan struct{}),
	}
	directSession := &statsSession{}
	recorder := &recordingTLSTransport{name: transport.ProtocolUDP, session: directSession}
	registry := transport.NewRegistry()
	if err := registry.Register(recorder); err != nil {
		t.Fatalf("register transport: %v", err)
	}
	reverseKey := reverseDataSessionKey(peer.ID, peer.Endpoints[0], securetransport.EncryptionSecure)
	daemon := &Daemon{
		desired: config.Desired{
			Domain: config.DomainConfig{ID: core.DomainID("lab.local")},
			IX:     config.IXConfig{ID: core.IXID("ix-a")},
			Peers:  []config.PeerConfig{peer},
			TransportPolicy: config.TransportPolicyConfig{
				Encryption: securetransport.EncryptionSecure,
				KernelTransport: config.KernelTransportPolicyConfig{
					Mode: string(dataplane.KernelTransportModeRequireKernel),
				},
			},
		},
		transports: registry,
		dataSessions: map[dataSessionKey]transport.Session{
			reverseKey: reverseSession,
		},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{
			reverseKey: {key: reverseKey, session: reverseSession},
		},
		endpointState: make(map[endpointStateKey]rstate.EndpointState),
	}
	defer daemon.closeDataSessions()

	gotSession, key, _, err := daemon.sessionForEndpoint(context.Background(), peer, peer.Endpoints[0], routing.FlowKey{}, false)
	if err != nil {
		t.Fatalf("session for secure kernel_udp endpoint: %v", err)
	}
	if gotSession != directSession {
		t.Fatal("sessionForEndpoint did not honor disabled reverse preference")
	}
	if key.Address != peer.Endpoints[0].Address {
		t.Fatalf("session key address = %q, want direct address %q", key.Address, peer.Endpoints[0].Address)
	}
	if recorder.dialCount != 1 {
		t.Fatalf("dial count = %d, want 1", recorder.dialCount)
	}
}

func TestRegisterInboundSecureKernelUDPClearsDirectForwardCache(t *testing.T) {
	peer := config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{
			{Name: core.EndpointID("ep-1"), Address: "192.0.2.1:7001", Transport: "udp"},
		},
	}
	endpoint := peer.Endpoints[0]
	directKey := dataSessionKey{
		Peer:       peer.ID,
		Endpoint:   endpoint.Name,
		Transport:  transport.ProtocolUDP,
		Address:    endpoint.Address,
		Encryption: securetransport.EncryptionSecure,
	}
	flowKey := routing.FlowKey{
		SourceIP:      netip.MustParseAddr("10.0.0.2"),
		DestinationIP: netip.MustParseAddr("10.0.1.2"),
		Protocol:      1,
	}
	daemon := &Daemon{
		dataplane: &kernelTransportDataplane{
			NoopManager: dataplane.NewNoopManager(),
			status: dataplane.KernelTransportStatus{
				Available: true,
				Provider:  "test",
				Protocols: []dataplane.KernelTransportProtocol{{
					Protocol:  string(transport.ProtocolUDP),
					Available: true,
				}},
			},
		},
		desired: config.Desired{
			Domain: config.DomainConfig{ID: core.DomainID("lab.local")},
			IX:     config.IXConfig{ID: core.IXID("ix-a")},
			Peers:  []config.PeerConfig{peer},
			TransportPolicy: config.TransportPolicyConfig{
				Encryption: securetransport.EncryptionSecure,
				KernelTransport: config.KernelTransportPolicyConfig{
					Mode: string(dataplane.KernelTransportModeRequireKernel),
				},
			},
		},
		dataSessions: map[dataSessionKey]transport.Session{
			directKey: &recordingSession{},
		},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{
			directKey: {key: directKey},
		},
		forwardCache: map[routing.FlowKey]*dataForwardCacheEntry{
			flowKey: {
				Key:      directKey,
				Peer:     peer,
				Endpoint: endpoint,
				Session:  &recordingSession{},
				Runtime:  &dataSessionRuntime{key: directKey},
			},
		},
		endpointState: make(map[endpointStateKey]rstate.EndpointState),
	}
	defer daemon.closeDataSessions()
	inbound := &blockingIdentitySession{
		peer:   peer.ID,
		domain: peer.Domain,
		recv:   make(chan struct{}),
	}

	if _, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{
		Name:      endpoint.Name,
		Transport: transport.ProtocolUDP,
	}, inbound); err != nil {
		t.Fatalf("register inbound secure kernel_udp session: %v", err)
	}
	if _, ok := daemon.forwardCache[flowKey]; ok {
		t.Fatal("direct forward cache entry survived reverse secure kernel_udp registration")
	}
}

func TestSessionForEndpointFallsBackToReverseWhenDirectDialFails(t *testing.T) {
	peer := config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{
			{Name: core.EndpointID("ep-1"), Address: "192.0.2.1:7001", Transport: "udp"},
		},
	}
	reverseSession := &blockingIdentitySession{
		peer:   peer.ID,
		domain: peer.Domain,
		recv:   make(chan struct{}),
	}
	recorder := &recordingTLSTransport{
		name:    transport.ProtocolUDP,
		dialErr: fmt.Errorf("direct path unavailable"),
	}
	registry := transport.NewRegistry()
	if err := registry.Register(recorder); err != nil {
		t.Fatalf("register transport: %v", err)
	}
	daemon := &Daemon{
		desired: config.Desired{
			Domain: config.DomainConfig{ID: core.DomainID("lab.local")},
			IX:     config.IXConfig{ID: core.IXID("ix-a")},
			Peers:  []config.PeerConfig{peer},
		},
		transports:       registry,
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		endpointState:    make(map[endpointStateKey]rstate.EndpointState),
	}
	defer daemon.closeDataSessions()
	if _, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{
		Name:      core.EndpointID("ep-1"),
		Transport: transport.ProtocolUDP,
	}, reverseSession); err != nil {
		t.Fatalf("register reverse session: %v", err)
	}

	gotSession, key, runtime, err := daemon.sessionForEndpoint(context.Background(), peer, peer.Endpoints[0], routing.FlowKey{}, false)
	if err != nil {
		t.Fatalf("session for fallback endpoint: %v", err)
	}
	if gotSession != reverseSession {
		t.Fatal("sessionForEndpoint did not fall back to reverse session after direct dial failure")
	}
	if runtime == nil {
		t.Fatal("expected reverse runtime")
	}
	if key.Address != reverseSessionAddress {
		t.Fatalf("session key address = %q, want %q", key.Address, reverseSessionAddress)
	}
	if recorder.dialCount != 1 {
		t.Fatalf("dial count = %d, want 1", recorder.dialCount)
	}
}

func TestSendPacketByDecisionUsesReverseChannel(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH", "0")
	peer := config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{
			{Name: core.EndpointID("ep-1"), Mode: config.EndpointModePassive, Transport: "udp"},
		},
	}
	session := &blockingIdentitySession{
		peer:   peer.ID,
		domain: peer.Domain,
		recv:   make(chan struct{}),
	}
	daemon := &Daemon{
		desired: config.Desired{
			Domain: config.DomainConfig{ID: core.DomainID("lab.local")},
			IX:     config.IXConfig{ID: core.IXID("ix-a")},
			Peers:  []config.PeerConfig{peer},
		},
		transports:       transport.NewRegistry(),
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		endpointState:    make(map[endpointStateKey]rstate.EndpointState),
	}
	defer daemon.closeDataSessions()
	if _, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{
		Name:      core.EndpointID("ep-1"),
		Transport: transport.ProtocolUDP,
	}, session); err != nil {
		t.Fatalf("register inbound session: %v", err)
	}

	decision := routing.Decision{Route: routing.Route{
		NextHop:  peer.ID,
		Endpoint: core.EndpointID("ep-1"),
		Kind:     routing.RouteUnicast,
	}}
	packet := tcpIPv4Packet()
	if err := daemon.sendPacketByDecision(context.Background(), decision, packet, routing.FlowKey{}, false); err != nil {
		t.Fatalf("send by reverse channel: %v", err)
	}
	if len(session.sent) != 1 || !reflect.DeepEqual(session.sent[0], packet) {
		t.Fatalf("sent packets = %#v, want one forwarded packet", session.sent)
	}
}

func TestReverseChannelWorksForNoAddressTCPAndExperimentalTCP(t *testing.T) {
	for _, protocol := range []transport.Protocol{transport.ProtocolTCP, transport.ProtocolExperimentalTCP} {
		t.Run(string(protocol), func(t *testing.T) {
			peer := config.PeerConfig{
				ID:     core.IXID("ix-b"),
				Domain: core.DomainID("lab.local"),
				Endpoints: []config.EndpointConfig{
					{Name: core.EndpointID("ep-1"), Mode: config.EndpointModePassive, Transport: string(protocol)},
				},
			}
			session := &blockingIdentitySession{
				peer:   peer.ID,
				domain: peer.Domain,
				recv:   make(chan struct{}),
			}
			daemon := &Daemon{
				desired: config.Desired{
					Domain: config.DomainConfig{ID: core.DomainID("lab.local")},
					IX:     config.IXConfig{ID: core.IXID("ix-a")},
					Peers:  []config.PeerConfig{peer},
				},
				transports:       transport.NewRegistry(),
				dataSessions:     make(map[dataSessionKey]transport.Session),
				dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
				endpointState:    make(map[endpointStateKey]rstate.EndpointState),
			}
			defer daemon.closeDataSessions()
			if _, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{
				Name:      core.EndpointID("ep-1"),
				Transport: protocol,
			}, session); err != nil {
				t.Fatalf("register inbound %s session: %v", protocol, err)
			}

			gotSession, key, runtime, err := daemon.sessionForEndpoint(context.Background(), peer, peer.Endpoints[0], routing.FlowKey{}, false)
			if err != nil {
				t.Fatalf("session for %s reverse endpoint: %v", protocol, err)
			}
			if gotSession != session {
				t.Fatalf("sessionForEndpoint did not reuse %s reverse inbound session", protocol)
			}
			if runtime == nil {
				t.Fatal("expected reverse runtime")
			}
			if key.Address != reverseSessionAddress || key.Transport != protocol {
				t.Fatalf("session key = %#v, want reverse %s", key, protocol)
			}
		})
	}
}

func TestDataSessionControlFrameRoundTrips(t *testing.T) {
	frame := encodeDataSessionControl(dataSessionControlPing, 42)
	kind, nonce, ok := decodeDataSessionControl(frame)
	if !ok {
		t.Fatal("expected data session control frame")
	}
	if kind != dataSessionControlPing || nonce != 42 {
		t.Fatalf("decoded control frame = kind %d nonce %d, want ping 42", kind, nonce)
	}

	if _, _, ok := decodeDataSessionControl(tcpIPv4Packet()); ok {
		t.Fatal("expected normal IPv4 packet to be ignored by control decoder")
	}
}

func TestDataSessionBatchRoundTrips(t *testing.T) {
	packetA := tcpIPv4Packet()
	packetB := udpIPv4Packet([]byte("batched"))
	batch := append([]byte(nil), dataSessionBatchMagic[:]...)
	batch = append(batch, dataSessionBatchVersion, 0, 0, 0)
	batch = binary.BigEndian.AppendUint16(batch, uint16(len(packetA)))
	batch = append(batch, packetA...)
	batch = binary.BigEndian.AppendUint16(batch, uint16(len(packetB)))
	batch = append(batch, packetB...)
	batch = cloneDataSessionBatchPayload(batch, 2)

	packets, ok := decodeDataSessionBatch(batch)
	if !ok {
		t.Fatal("expected batch to decode")
	}
	if len(packets) != 2 || !reflect.DeepEqual(packets[0], packetA) || !reflect.DeepEqual(packets[1], packetB) {
		t.Fatalf("decoded batch = %#v, want original packets", packets)
	}
	if _, ok := decodeDataSessionBatch(tcpIPv4Packet()); ok {
		t.Fatal("expected normal IPv4 packet to be ignored by batch decoder")
	}
}

func TestSendDataSessionPacketBatchesPayloads(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH", "1")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_BYTES", "4096")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_DELAY", "5ms")
	session := &recordingSession{}
	runtime := &dataSessionRuntime{session: session}
	daemon := &Daemon{}
	packetA := tcpIPv4Packet()
	packetB := udpIPv4Packet([]byte("batched"))

	if err := daemon.sendDataSessionPacket(runtime, session, packetA); err != nil {
		t.Fatalf("send first packet: %v", err)
	}
	if err := daemon.sendDataSessionPacket(runtime, session, packetB); err != nil {
		t.Fatalf("send second packet: %v", err)
	}
	if len(session.sent) != 0 {
		t.Fatalf("batch flushed early with %d packets", len(session.sent))
	}
	if err := daemon.flushDataSessionBatch(runtime); err != nil {
		t.Fatalf("flush batch: %v", err)
	}
	if len(session.sent) != 1 {
		t.Fatalf("sent frames = %d, want one batch", len(session.sent))
	}
	packets, ok := decodeDataSessionBatch(session.sent[0])
	if !ok || len(packets) != 2 {
		t.Fatalf("sent frame did not decode as two-packet batch: ok=%v len=%d", ok, len(packets))
	}
}

func TestSendDataSessionPacketBatchDelayZeroFlushesQueuedPayloads(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH", "1")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_BYTES", "4096")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_DELAY", "0")
	session := &recordingSession{}
	runtime := &dataSessionRuntime{session: session}
	daemon := &Daemon{}
	packetA := tcpIPv4Packet()
	packetB := udpIPv4Packet([]byte("batched"))

	if err := daemon.sendDataSessionPackets(runtime, session, [][]byte{packetA, packetB}); err != nil {
		t.Fatalf("send packet batch: %v", err)
	}
	if len(session.sent) != 1 {
		t.Fatalf("sent frames = %d, want one immediate batch", len(session.sent))
	}
	packets, ok := decodeDataSessionBatch(session.sent[0])
	if !ok || len(packets) != 2 {
		t.Fatalf("sent frame did not decode as two-packet batch: ok=%v len=%d", ok, len(packets))
	}
}

func TestDataSessionBatchCountersTrackFlushAndReceive(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH", "1")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_BYTES", "4096")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_DELAY", "0")
	session := &recordingSession{}
	runtime := &dataSessionRuntime{session: session}
	daemon := &Daemon{}
	packetA := tcpIPv4Packet()
	packetB := udpIPv4Packet([]byte("batched-counters"))

	if err := daemon.sendDataSessionPackets(runtime, session, [][]byte{packetA, packetB}); err != nil {
		t.Fatalf("send packet batch: %v", err)
	}
	if len(session.sent) != 1 {
		t.Fatalf("sent frames = %d, want one batch", len(session.sent))
	}
	counters := daemon.dataStats.snapshot()
	if counters.DataSessionBatchQueuedPackets != 2 || counters.DataSessionBatchFlushes != 1 || counters.DataSessionBatchFlushPackets != 2 {
		t.Fatalf("send batch counters = %+v", counters)
	}
	if counters.DataSessionBatchFlushMaxPackets != 2 || counters.DataSessionBatchFlushMaxBytes != uint64(len(session.sent[0])) {
		t.Fatalf("send batch max counters = %+v, batch len %d", counters, len(session.sent[0]))
	}

	injector := &recordingInjector{}
	daemon.handleReceivedDataPathPackets(context.Background(), runtime, session, session.sent, injector, injector, &dataReceiveScratch{})
	counters = daemon.dataStats.snapshot()
	if counters.DataSessionBatchRXFrames != 1 || counters.DataSessionBatchRXPackets != 2 || counters.DataSessionBatchRXMaxPackets != 2 {
		t.Fatalf("receive batch counters = %+v", counters)
	}
	if counters.DataSessionBatchRXMaxBytes != uint64(len(session.sent[0])) {
		t.Fatalf("receive batch max bytes = %d, want %d", counters.DataSessionBatchRXMaxBytes, len(session.sent[0]))
	}
}

func TestSendDataSessionPacketsUsesNativeBatchingWhenAvailable(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH", "1")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_BYTES", "4096")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_DELAY", "0")
	session := &recordingNativeBatchSession{}
	runtime := &dataSessionRuntime{session: session}
	daemon := &Daemon{}
	packetA := tcpIPv4Packet()
	packetB := udpIPv4Packet([]byte("native-batch"))

	if err := daemon.sendDataSessionPackets(runtime, session, [][]byte{packetA, packetB}); err != nil {
		t.Fatalf("send packet batch: %v", err)
	}
	if len(session.sent) != 0 {
		t.Fatalf("single sends = %d, want 0", len(session.sent))
	}
	if len(session.batches) != 1 || len(session.batches[0]) != 2 {
		t.Fatalf("native batches = %#v, want one two-packet batch", session.batches)
	}
	if _, ok := decodeDataSessionBatch(session.batches[0][0]); ok {
		t.Fatal("native batch should not wrap packets in TIXB")
	}
	if !reflect.DeepEqual(session.batches[0][0], packetA) || !reflect.DeepEqual(session.batches[0][1], packetB) {
		t.Fatalf("native batch packets changed")
	}
}

func TestSendDataSessionPacketsAggregatesPlaintextDatagramWhenEnabled(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH", "1")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_BYTES", "4096")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_DELAY", "0")
	t.Setenv("TRUSTIX_DATA_SESSION_PLAINTEXT_TIXB", "1")
	session := &recordingNativeBatchSession{stats: transport.TransportStats{
		NativeBatching: true,
		Datagram:       true,
		MaxPacketSize:  4096,
	}}
	runtime := &dataSessionRuntime{session: session}
	daemon := &Daemon{}
	packetA := tcpIPv4Packet()
	packetB := udpIPv4Packet([]byte("plaintext-datagram-batch"))

	if err := daemon.sendDataSessionPackets(runtime, session, [][]byte{packetA, packetB}); err != nil {
		t.Fatalf("send packet batch: %v", err)
	}
	if len(session.batches) != 0 {
		t.Fatalf("native batches = %d, want plaintext TIXB aggregation", len(session.batches))
	}
	if len(session.sent) != 1 {
		t.Fatalf("single sends = %d, want one TIXB packet", len(session.sent))
	}
	packets, ok := decodeDataSessionBatch(session.sent[0])
	if !ok || len(packets) != 2 {
		t.Fatalf("sent packet did not decode as plaintext datagram TIXB batch: ok=%v len=%d", ok, len(packets))
	}
}

func TestSendDataSessionPacketsAggregatesPlaintextExperimentalTCPByDefault(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH", "1")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_BYTES", "4096")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_DELAY", "0")
	session := &recordingNativeBatchSession{stats: transport.TransportStats{
		NativeBatching: true,
		Datagram:       true,
		MaxPacketSize:  4096,
	}}
	runtime := &dataSessionRuntime{
		key:     dataSessionKey{Transport: transport.ProtocolExperimentalTCP},
		session: session,
	}
	daemon := &Daemon{}
	packetA := tcpIPv4Packet()
	packetB := udpIPv4Packet([]byte("experimental-tcp-plaintext-default"))

	if err := daemon.sendDataSessionPackets(runtime, session, [][]byte{packetA, packetB}); err != nil {
		t.Fatalf("send packet batch: %v", err)
	}
	if len(session.batches) != 0 {
		t.Fatalf("native batches = %d, want experimental_tcp TIXB aggregation", len(session.batches))
	}
	if len(session.sent) != 1 {
		t.Fatalf("single sends = %d, want one TIXB packet", len(session.sent))
	}
	packets, ok := decodeDataSessionBatch(session.sent[0])
	if !ok || len(packets) != 2 {
		t.Fatalf("sent packet did not decode as experimental_tcp plaintext TIXB batch: ok=%v len=%d", ok, len(packets))
	}
}

func TestSendDataSessionPacketsCanDisableExperimentalTCPAggregation(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH", "1")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_BYTES", "4096")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_DELAY", "0")
	t.Setenv("TRUSTIX_DATA_SESSION_EXPERIMENTAL_TCP_TIXB", "0")
	session := &recordingNativeBatchSession{stats: transport.TransportStats{
		NativeBatching: true,
		Datagram:       true,
		MaxPacketSize:  4096,
	}}
	runtime := &dataSessionRuntime{
		key:     dataSessionKey{Transport: transport.ProtocolExperimentalTCP},
		session: session,
	}
	daemon := &Daemon{}
	packetA := tcpIPv4Packet()
	packetB := udpIPv4Packet([]byte("experimental-tcp-native-override"))

	if err := daemon.sendDataSessionPackets(runtime, session, [][]byte{packetA, packetB}); err != nil {
		t.Fatalf("send packet batch: %v", err)
	}
	if len(session.sent) != 0 {
		t.Fatalf("single sends = %d, want native batch", len(session.sent))
	}
	if len(session.batches) != 1 || len(session.batches[0]) != 2 {
		t.Fatalf("native batches = %#v, want one two-packet batch", session.batches)
	}
	if _, ok := decodeDataSessionBatch(session.batches[0][0]); ok {
		t.Fatal("disabled experimental_tcp aggregation should not wrap packets in TIXB")
	}
}

func TestSendDataSessionPacketsUsesNativeBatchingForKernelCryptoEncryptedSessionByDefault(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH", "1")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_BYTES", "4096")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_DELAY", "0")
	session := &recordingNativeBatchSession{stats: transport.TransportStats{
		NativeBatching:  true,
		Encrypted:       true,
		CryptoPlacement: string(dataplane.CryptoPlacementKernel),
	}}
	runtime := &dataSessionRuntime{session: session}
	daemon := &Daemon{}
	packetA := tcpIPv4Packet()
	packetB := udpIPv4Packet([]byte("encrypted-native-batch"))

	if err := daemon.sendDataSessionPackets(runtime, session, [][]byte{packetA, packetB}); err != nil {
		t.Fatalf("send packet batch: %v", err)
	}
	if len(session.sent) != 0 {
		t.Fatalf("single sends = %d, want 0", len(session.sent))
	}
	if len(session.batches) != 1 || len(session.batches[0]) != 2 {
		t.Fatalf("native batches = %#v, want one two-packet kernel crypto batch", session.batches)
	}
	if _, ok := decodeDataSessionBatch(session.batches[0][0]); ok {
		t.Fatal("kernel crypto native batch should not wrap packets in TIXB by default")
	}
	if !reflect.DeepEqual(session.batches[0][0], packetA) || !reflect.DeepEqual(session.batches[0][1], packetB) {
		t.Fatalf("native batch packets changed")
	}
}

func TestSendDataSessionPacketsUsesNativeBatchingForExperimentalTCPKernelCryptoByDefault(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH", "1")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_BYTES", "4096")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_DELAY", "0")
	session := &recordingNativeBatchSession{stats: transport.TransportStats{
		NativeBatching:  true,
		Encrypted:       true,
		CryptoPlacement: string(dataplane.CryptoPlacementKernel),
		Datagram:        true,
		MaxPacketSize:   4096,
	}}
	runtime := &dataSessionRuntime{
		key:     dataSessionKey{Transport: transport.ProtocolExperimentalTCP},
		session: session,
	}
	daemon := &Daemon{}
	packetA := tcpIPv4Packet()
	packetB := udpIPv4Packet([]byte("experimental-tcp-kernel-crypto-native"))

	if err := daemon.sendDataSessionPackets(runtime, session, [][]byte{packetA, packetB}); err != nil {
		t.Fatalf("send packet batch: %v", err)
	}
	if len(session.sent) != 0 {
		t.Fatalf("single sends = %d, want kernel crypto native batch", len(session.sent))
	}
	if len(session.batches) != 1 || len(session.batches[0]) != 2 {
		t.Fatalf("native batches = %#v, want one two-packet kernel crypto batch", session.batches)
	}
	if _, ok := decodeDataSessionBatch(session.batches[0][0]); ok {
		t.Fatal("experimental_tcp kernel crypto native batch should not wrap packets in TIXB by default")
	}
}

func TestSendDataSessionPacketsUsesNativeBatchingForUserspaceEncryptedDatagramByDefault(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH", "1")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_BYTES", "4096")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_DELAY", "0")
	session := &recordingNativeBatchSession{stats: transport.TransportStats{
		NativeBatching:  true,
		Encrypted:       true,
		CryptoPlacement: string(dataplane.CryptoPlacementUserspace),
		Datagram:        true,
		MaxPacketSize:   4096,
	}}
	runtime := &dataSessionRuntime{session: session}
	daemon := &Daemon{}
	packetA := tcpIPv4Packet()
	packetB := udpIPv4Packet([]byte("encrypted-datagram-native-batch"))

	if err := daemon.sendDataSessionPackets(runtime, session, [][]byte{packetA, packetB}); err != nil {
		t.Fatalf("send packet batch: %v", err)
	}
	if len(session.sent) != 0 {
		t.Fatalf("single sends = %d, want 0", len(session.sent))
	}
	if len(session.batches) != 1 || len(session.batches[0]) != 2 {
		t.Fatalf("native batches = %#v, want one two-packet encrypted datagram batch", session.batches)
	}
	if _, ok := decodeDataSessionBatch(session.batches[0][0]); ok {
		t.Fatal("userspace encrypted datagram native batch should not wrap packets in TIXB by default")
	}
}

func TestSendDataSessionPacketsAggregatesUserspaceEncryptedExperimentalTCPByDefault(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH", "1")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_BYTES", "4096")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_DELAY", "0")
	session := &recordingNativeBatchSession{stats: transport.TransportStats{
		NativeBatching:  true,
		Encrypted:       true,
		CryptoPlacement: string(dataplane.CryptoPlacementUserspace),
		Datagram:        true,
		MaxPacketSize:   4096,
	}}
	runtime := &dataSessionRuntime{
		key:     dataSessionKey{Transport: transport.ProtocolExperimentalTCP},
		session: session,
	}
	daemon := &Daemon{}
	packetA := tcpIPv4Packet()
	packetB := udpIPv4Packet([]byte("experimental-tcp-userspace-encrypted-default"))

	if err := daemon.sendDataSessionPackets(runtime, session, [][]byte{packetA, packetB}); err != nil {
		t.Fatalf("send packet batch: %v", err)
	}
	if len(session.batches) != 0 {
		t.Fatalf("native batches = %d, want experimental_tcp userspace encrypted TIXB aggregation", len(session.batches))
	}
	if len(session.sent) != 1 {
		t.Fatalf("single sends = %d, want one TIXB packet", len(session.sent))
	}
	packets, ok := decodeDataSessionBatch(session.sent[0])
	if !ok || len(packets) != 2 {
		t.Fatalf("sent packet did not decode as experimental_tcp encrypted TIXB batch: ok=%v len=%d", ok, len(packets))
	}
}

func TestDataSessionBatchMaxBytesCapsUserspaceEncryptedAggregationWhenConfigured(t *testing.T) {
	session := &recordingSession{stats: transport.TransportStats{
		Encrypted:       true,
		CryptoPlacement: string(dataplane.CryptoPlacementUserspace),
		Datagram:        true,
		MaxPacketSize:   65535,
	}}
	if got := dataSessionBatchMaxBytesForSession(262144, session); got != 65535 {
		t.Fatalf("default userspace encrypted batch max bytes = %d, want datagram cap 65535", got)
	}

	t.Setenv("TRUSTIX_DATA_SESSION_USERSPACE_ENCRYPTED_BATCH_BYTES", "16384")
	if got := dataSessionBatchMaxBytesForSession(262144, session); got != 16384 {
		t.Fatalf("configured userspace encrypted batch max bytes = %d, want 16384", got)
	}
}

func TestDataSessionBatchMaxBytesAllowsFragmentingDatagramLogicalBatches(t *testing.T) {
	session := &recordingSession{stats: transport.TransportStats{
		Encrypted:           true,
		CryptoPlacement:     string(dataplane.CryptoPlacementUserspace),
		Datagram:            true,
		FragmentingDatagram: true,
		MaxPacketSize:       1400,
	}}
	if got := dataSessionBatchMaxBytesForSession(262144, session); got != 262144 {
		t.Fatalf("fragmenting datagram batch max bytes = %d, want logical batch size", got)
	}
}

func TestSendDataSessionPacketsAggregatesUserspaceEncryptedDatagramWhenEnabled(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH", "1")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_BYTES", "4096")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_DELAY", "0")
	t.Setenv("TRUSTIX_DATA_SESSION_ENCRYPTED_TIXB", "1")
	session := &recordingNativeBatchSession{stats: transport.TransportStats{
		NativeBatching:  true,
		Encrypted:       true,
		CryptoPlacement: string(dataplane.CryptoPlacementUserspace),
		Datagram:        true,
		MaxPacketSize:   1400,
	}}
	runtime := &dataSessionRuntime{session: session}
	daemon := &Daemon{}
	packetA := tcpIPv4Packet()
	packetB := udpIPv4Packet([]byte("encrypted-datagram-native-batch"))

	if err := daemon.sendDataSessionPackets(runtime, session, [][]byte{packetA, packetB}); err != nil {
		t.Fatalf("send packet batch: %v", err)
	}
	if len(session.batches) != 0 {
		t.Fatalf("native batches = %d, want userspace encrypted TIXB aggregation", len(session.batches))
	}
	if len(session.sent) != 1 {
		t.Fatalf("single sends = %d, want one TIXB packet", len(session.sent))
	}
	packets, ok := decodeDataSessionBatch(session.sent[0])
	if !ok || len(packets) != 2 {
		t.Fatalf("sent packet did not decode as encrypted datagram TIXB batch: ok=%v len=%d", ok, len(packets))
	}
}

func TestSendDataSessionPacketsCanBatchKernelCryptoEncryptedSessionBeforeNativeBatching(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH", "1")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_BYTES", "4096")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_DELAY", "0")
	t.Setenv("TRUSTIX_DATA_SESSION_KERNEL_CRYPTO_NATIVE_BATCH", "0")
	session := &recordingNativeBatchSession{stats: transport.TransportStats{
		NativeBatching:  true,
		Encrypted:       true,
		CryptoPlacement: string(dataplane.CryptoPlacementKernel),
	}}
	runtime := &dataSessionRuntime{session: session}
	daemon := &Daemon{}
	packetA := tcpIPv4Packet()
	packetB := udpIPv4Packet([]byte("encrypted-native-batch"))

	if err := daemon.sendDataSessionPackets(runtime, session, [][]byte{packetA, packetB}); err != nil {
		t.Fatalf("send packet batch: %v", err)
	}
	if len(session.batches) != 0 {
		t.Fatalf("native batches = %d, want encrypted packets to aggregate before native batching", len(session.batches))
	}
	if len(session.sent) != 1 {
		t.Fatalf("single sends = %d, want one TIXB packet", len(session.sent))
	}
	packets, ok := decodeDataSessionBatch(session.sent[0])
	if !ok || len(packets) != 2 {
		t.Fatalf("sent packet did not decode as encrypted TIXB batch: ok=%v len=%d", ok, len(packets))
	}
}

func TestDataSessionKernelCryptoBatchBytesDefaultsToMax(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_KERNEL_CRYPTO_BATCH_BYTES", "")

	if got := dataSessionKernelCryptoBatchBytes(); got != dataSessionKernelCryptoBatchMaxBytes {
		t.Fatalf("kernel crypto batch default = %d, want %d", got, dataSessionKernelCryptoBatchMaxBytes)
	}
}

func TestSendDataSessionPacketsCapsKernelCryptoBatchSize(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH", "1")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_BYTES", "524288")
	t.Setenv("TRUSTIX_DATA_SESSION_KERNEL_CRYPTO_BATCH_BYTES", "262144")
	t.Setenv("TRUSTIX_DATA_SESSION_KERNEL_CRYPTO_NATIVE_BATCH", "0")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_DELAY", "0")
	session := &recordingNativeBatchSession{stats: transport.TransportStats{
		NativeBatching:  true,
		Encrypted:       true,
		CryptoPlacement: string(dataplane.CryptoPlacementKernel),
	}}
	runtime := &dataSessionRuntime{session: session}
	daemon := &Daemon{}
	packets := make([][]byte, 0, 400)
	for i := 0; i < cap(packets); i++ {
		packets = append(packets, udpIPv4Packet(make([]byte, 1450)))
	}

	if err := daemon.sendDataSessionPackets(runtime, session, packets); err != nil {
		t.Fatalf("send packet batch: %v", err)
	}
	var wires [][]byte
	wires = append(wires, session.sent...)
	for _, batch := range session.batches {
		wires = append(wires, batch...)
	}
	if len(wires) < 2 {
		t.Fatalf("wire packets = %d, want multiple capped TIXB packets", len(wires))
	}
	for i, wire := range wires {
		if len(wire) > dataSessionKernelCryptoBatchMaxBytes {
			t.Fatalf("wire packet %d size = %d, want <= %d", i, len(wire), dataSessionKernelCryptoBatchMaxBytes)
		}
		if _, ok := decodeDataSessionBatch(wire); !ok {
			t.Fatalf("wire packet %d is not a TIXB batch", i)
		}
	}
}

func TestSendDataSessionPacketsSegmentsOversizedTCPForDatagramMTU(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH", "0")
	session := &recordingSession{stats: transport.TransportStats{
		Datagram:      true,
		MaxPacketSize: 1400,
	}}
	runtime := &dataSessionRuntime{session: session}
	daemon := &Daemon{}
	packet := tcpPayloadIPv4PacketWithSeq(1000, bytes.Repeat([]byte{0x7a}, 3600))

	if err := daemon.sendDataSessionPackets(runtime, session, [][]byte{packet}); err != nil {
		t.Fatalf("send segmented packet: %v", err)
	}
	if len(session.sent) != 3 {
		t.Fatalf("sent segments = %d, want 3", len(session.sent))
	}
	var totalPayload int
	for i, segment := range session.sent {
		if len(segment) > 1400 {
			t.Fatalf("segment %d length = %d, want <= 1400", i, len(segment))
		}
		ihl := int(segment[0]&0x0f) * 4
		if got := ipv4Checksum(segment[:ihl]); got != 0 {
			t.Fatalf("segment %d IPv4 checksum = %#04x, want valid", i, got)
		}
		tcp := segment[ihl:int(binary.BigEndian.Uint16(segment[2:4]))]
		if !validTransportChecksumForTest(segment, tcp) {
			t.Fatalf("segment %d TCP checksum invalid", i)
		}
		if got, want := binary.BigEndian.Uint32(tcp[4:8]), uint32(1000+totalPayload); got != want {
			t.Fatalf("segment %d seq = %d, want %d", i, got, want)
		}
		totalPayload += len(tcp) - int(tcp[12]>>4)*4
		if i < len(session.sent)-1 && tcp[13]&tcpFlagPSH != 0 {
			t.Fatalf("segment %d kept PSH before final segment", i)
		}
	}
	if totalPayload != 3600 {
		t.Fatalf("segmented payload bytes = %d, want 3600", totalPayload)
	}
	counters := daemon.dataStats.snapshot()
	if counters.SendSoftwareSegments != 1 || counters.SendSoftwareSegmentWires != 3 {
		t.Fatalf("software segment counters = %+v, want 1 packet / 3 wires", counters)
	}
}

func TestSendDataSessionPacketsKeepsOversizedTCPForDatagramLogicalMax(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH", "0")
	session := &recordingSession{stats: transport.TransportStats{
		Datagram:      true,
		MaxPacketSize: 65535,
	}}
	runtime := &dataSessionRuntime{session: session}
	daemon := &Daemon{}
	packet := tcpPayloadIPv4PacketWithSeq(1000, bytes.Repeat([]byte{0x7a}, 3600))

	if err := daemon.sendDataSessionPackets(runtime, session, [][]byte{packet}); err != nil {
		t.Fatalf("send packet: %v", err)
	}
	if len(session.sent) != 1 {
		t.Fatalf("sent packets = %d, want 1", len(session.sent))
	}
	if !bytes.Equal(session.sent[0], packet) {
		t.Fatal("sent packet changed, want original logical packet")
	}
	counters := daemon.dataStats.snapshot()
	if counters.SendSoftwareSegments != 0 || counters.SendSoftwareSegmentWires != 0 {
		t.Fatalf("software segment counters = %+v, want zero", counters)
	}
}

func TestSendDataSessionPacketsCanSegmentFragmentingDatagramWhenEnabled(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH", "0")
	t.Setenv("TRUSTIX_DATA_SESSION_SEGMENT_FRAGMENTING_DATAGRAM", "1")
	session := &recordingSession{stats: transport.TransportStats{
		Datagram:            true,
		FragmentingDatagram: true,
		MaxPacketSize:       1400,
	}}
	runtime := &dataSessionRuntime{session: session}
	daemon := &Daemon{}
	packet := tcpPayloadIPv4PacketWithSeq(1000, bytes.Repeat([]byte{0x7a}, 3600))

	if err := daemon.sendDataSessionPackets(runtime, session, [][]byte{packet}); err != nil {
		t.Fatalf("send segmented packet: %v", err)
	}
	if len(session.sent) != 3 {
		t.Fatalf("sent segments = %d, want 3", len(session.sent))
	}
	counters := daemon.dataStats.snapshot()
	if counters.SendSoftwareSegments != 1 ||
		counters.SendSoftwareSegmentFrames != 3 ||
		counters.SendSoftwareSegmentWires != 3 ||
		counters.SendSoftwareSegmentFragDatagram != 1 {
		t.Fatalf("software segment counters = %+v, want fragmenting datagram segmentation", counters)
	}
}

func TestSendDataSessionPacketSkipsTIXBForNativeBatchSession(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH", "1")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_BYTES", "4096")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_DELAY", "5ms")
	session := &recordingNativeBatchSession{}
	runtime := &dataSessionRuntime{session: session}
	daemon := &Daemon{}
	packet := tcpIPv4Packet()

	if err := daemon.sendDataSessionPacket(runtime, session, packet); err != nil {
		t.Fatalf("send packet: %v", err)
	}
	if len(session.sent) != 1 {
		t.Fatalf("single sends = %d, want 1", len(session.sent))
	}
	if err := daemon.flushDataSessionBatch(runtime); err != nil {
		t.Fatalf("flush TIXB batch: %v", err)
	}
	if len(session.batches) != 0 {
		t.Fatalf("TIXB flush sent native packets: %d", len(session.batches))
	}
	if _, ok := decodeDataSessionBatch(session.sent[0]); ok {
		t.Fatal("native batch session single packet should not be wrapped in TIXB")
	}
	if !reflect.DeepEqual(session.sent[0], packet) {
		t.Fatalf("native batch session packet changed")
	}
}

func TestSendDataSessionPacketCachesTransportCapabilities(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH", "1")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_BYTES", "4096")
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH_DELAY", "5ms")
	session := &statsCountingNativeBatchSession{stats: transport.TransportStats{
		NativeBatching: true,
		Datagram:       true,
		MaxPacketSize:  1500,
	}}
	runtime := &dataSessionRuntime{session: session}
	daemon := &Daemon{}
	packet := tcpIPv4Packet()

	for i := 0; i < 3; i++ {
		if err := daemon.sendDataSessionPacket(runtime, session, packet); err != nil {
			t.Fatalf("send packet %d: %v", i, err)
		}
	}
	if session.statsCalls != 1 {
		t.Fatalf("Stats calls = %d, want 1 cached capability lookup", session.statsCalls)
	}
	if len(session.sent) != 3 {
		t.Fatalf("single sends = %d, want 3", len(session.sent))
	}
}

func TestDataSessionBatchEnabledByDefault(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_BATCH", "")
	if !dataSessionBatchEnabled() {
		t.Fatal("data session batching should be enabled by default")
	}
}

func TestDataSessionBatchMaxBytesCapsDatagramSessions(t *testing.T) {
	session := &recordingSession{stats: transport.TransportStats{
		Datagram:      true,
		MaxPacketSize: 1400,
	}}
	if got := dataSessionBatchMaxBytesForSession(524288, session); got != 1400 {
		t.Fatalf("datagram batch max bytes = %d, want 1400", got)
	}
}

func TestCaptureForwarderBatchSizeAllowsKernelCryptoBatchMax(t *testing.T) {
	t.Setenv("TRUSTIX_CAPTURE_FORWARDER_BATCH", "4096")
	if got := captureForwarderBatchSize(); got != 4096 {
		t.Fatalf("capture forwarder batch size = %d, want 4096", got)
	}
	t.Setenv("TRUSTIX_CAPTURE_FORWARDER_BATCH", "8192")
	if got := captureForwarderBatchSize(); got != captureForwarderMaxBatch {
		t.Fatalf("capture forwarder batch size = %d, want clamp %d", got, captureForwarderMaxBatch)
	}
}

func TestCaptureForwarderBufferSizeIsBounded(t *testing.T) {
	t.Setenv("TRUSTIX_CAPTURE_FORWARDER_BUFFER", "")
	if got := captureForwarderBufferSize(); got != captureForwarderDefaultBuffer {
		t.Fatalf("capture forwarder buffer default = %d, want %d", got, captureForwarderDefaultBuffer)
	}
	t.Setenv("TRUSTIX_CAPTURE_FORWARDER_BUFFER", "4096")
	if got := captureForwarderBufferSize(); got != 4096 {
		t.Fatalf("capture forwarder buffer = %d, want 4096", got)
	}
	t.Setenv("TRUSTIX_CAPTURE_FORWARDER_BUFFER", "999999")
	if got := captureForwarderBufferSize(); got != captureForwarderMaxBuffer {
		t.Fatalf("capture forwarder buffer clamp = %d, want %d", got, captureForwarderMaxBuffer)
	}
	t.Setenv("TRUSTIX_CAPTURE_FORWARDER_BUFFER", "bad")
	if got := captureForwarderBufferSize(); got != captureForwarderDefaultBuffer {
		t.Fatalf("invalid capture forwarder buffer = %d, want %d", got, captureForwarderDefaultBuffer)
	}
}

func TestCaptureForwarderWorkerBufferSplitsBoundedBuffer(t *testing.T) {
	t.Setenv("TRUSTIX_CAPTURE_FORWARDER_BUFFER", "1024")
	if got := captureForwarderWorkerBufferSize(4); got != 256 {
		t.Fatalf("worker buffer = %d, want 256", got)
	}
	if got := captureForwarderWorkerBufferSize(2048); got != 1 {
		t.Fatalf("small worker buffer = %d, want 1", got)
	}
}

func TestHandleReceivedDataPathBatchInjectsLocalLANInBatch(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_RX_GSO_COALESCE", "0")
	daemon := &Daemon{
		desired: config.Desired{
			LAN: config.LANConfig{
				Advertise: []core.Prefix{"10.0.1.0/24"},
			},
		},
	}
	injector := &recordingInjector{}
	packets := [][]byte{tcpIPv4Packet(), udpIPv4Packet([]byte("batched"))}

	daemon.handleReceivedDataPathBatch(context.Background(), packets, injector, injector)

	if len(injector.batchPackets) != 1 || len(injector.batchPackets[0]) != 2 {
		t.Fatalf("batch injections = %#v, want one two-packet batch", injector.batchPackets)
	}
	if len(injector.packets) != 0 {
		t.Fatalf("single-packet injections = %d, want 0", len(injector.packets))
	}
	counters := daemon.dataStats.snapshot()
	if counters.ReceiveBatchFrames != 1 || counters.ReceiveBatchPackets != 2 || counters.InjectBatchAttempts != 1 || counters.InjectBatchPackets != 2 || counters.PacketsInjected != 2 {
		t.Fatalf("batch counters = %+v, want frame=1 packets=2 injected=2", counters)
	}
}

func TestLocalLANCacheFollowsRuntimeConfig(t *testing.T) {
	daemon := &Daemon{}
	daemon.configureLocalLANCache(config.Desired{
		LAN: config.LANConfig{
			Gateway:   "10.0.1.1/24",
			Advertise: []core.Prefix{"10.0.2.0/24"},
		},
	})
	if !daemon.destinationInLocalLAN(netip.MustParseAddr("10.0.1.44")) {
		t.Fatal("gateway prefix should match local LAN")
	}
	if !daemon.destinationInLocalLAN(netip.MustParseAddr("10.0.2.44")) {
		t.Fatal("advertised prefix should match local LAN")
	}
	if !daemon.destinationIsLocalGateway(netip.MustParseAddr("10.0.1.1")) {
		t.Fatal("gateway address should match local gateway")
	}

	daemon.configureLocalLANCache(config.Desired{
		LAN: config.LANConfig{
			Gateway:   "10.0.3.1/24",
			Advertise: []core.Prefix{"10.0.4.0/24"},
		},
	})
	if daemon.destinationInLocalLAN(netip.MustParseAddr("10.0.1.44")) {
		t.Fatal("old gateway prefix should not remain after cache update")
	}
	if !daemon.destinationInLocalLAN(netip.MustParseAddr("10.0.4.44")) {
		t.Fatal("new advertised prefix should match local LAN")
	}
}

func TestLocalLANCacheIncludesMultipleConfiguredLANs(t *testing.T) {
	daemon := &Daemon{}
	daemon.configureLocalLANCache(config.Desired{
		LAN: config.LANConfig{
			Gateway:   "10.0.1.1/24",
			Advertise: []core.Prefix{"10.0.1.0/24"},
		},
		LANs: []config.LANConfig{{
			ID:        "public",
			Type:      config.LANTypeTrustedPublic,
			Gateway:   "10.0.3.1/24",
			Advertise: []core.Prefix{"10.0.3.0/24"},
		}},
	})

	if !daemon.destinationInLocalLAN(netip.MustParseAddr("10.0.1.44")) {
		t.Fatal("legacy LAN prefix should match local LAN")
	}
	if !daemon.destinationInLocalLAN(netip.MustParseAddr("10.0.3.44")) {
		t.Fatal("additional LAN prefix should match local LAN")
	}
	if !daemon.destinationIsLocalGateway(netip.MustParseAddr("10.0.1.1")) {
		t.Fatal("legacy gateway should match local gateway")
	}
	if !daemon.destinationIsLocalGateway(netip.MustParseAddr("10.0.3.1")) {
		t.Fatal("additional gateway should match local gateway")
	}
}

func TestHandleReceivedDataPathBatchRepliesToLocalGatewayICMPEcho(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_RX_GSO_COALESCE", "0")
	table := routing.NewTable()
	if err := table.Replace([]routing.Route{{
		Prefix:   "10.0.0.0/24",
		Owner:    "ix-a",
		NextHop:  "ix-a",
		Endpoint: "ep-a",
		Metric:   100,
		Kind:     routing.RouteUnicast,
	}}); err != nil {
		t.Fatalf("replace routes: %v", err)
	}
	registry := transport.NewRegistry()
	if err := registry.Register(fakeTransport{name: "udp"}); err != nil {
		t.Fatalf("register fake transport: %v", err)
	}
	session := &recordingSession{}
	daemon := &Daemon{
		routes:     table,
		transports: registry,
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-b"},
			LAN: config.LANConfig{
				Gateway:   "10.0.1.2/24",
				Advertise: []core.Prefix{"10.0.1.0/24"},
			},
			Peers: []config.PeerConfig{{
				ID:     "ix-a",
				Domain: "lab.local",
				Endpoints: []config.EndpointConfig{{
					Name:      "ep-a",
					Address:   "192.0.2.1:7001",
					Transport: "udp",
				}},
			}},
		},
		dataSessions: map[dataSessionKey]transport.Session{
			{Peer: "ix-a", Endpoint: "ep-a", Transport: "udp", Address: "192.0.2.1:7001", Encryption: "secure"}: session,
		},
		flows: make(map[routing.FlowKey]routing.FlowBinding),
	}
	packet := normalizeCapturedIPv4Checksums(icmpEchoIPv4Packet([]byte("gateway ping")))
	injector := &recordingInjector{}

	daemon.handleReceivedDataPathBatch(context.Background(), [][]byte{packet}, injector, injector)

	if len(injector.batchPackets) != 0 || len(injector.packets) != 0 {
		t.Fatalf("local gateway echo should not be injected locally: singles=%d batches=%d", len(injector.packets), len(injector.batchPackets))
	}
	if len(session.sent) != 1 {
		t.Fatalf("reply packets sent = %d, want 1", len(session.sent))
	}
	reply := session.sent[0]
	if got := netip.AddrFrom4([4]byte{reply[12], reply[13], reply[14], reply[15]}); got != netip.MustParseAddr("10.0.1.2") {
		t.Fatalf("reply source = %s, want local gateway", got)
	}
	if got := netip.AddrFrom4([4]byte{reply[16], reply[17], reply[18], reply[19]}); got != netip.MustParseAddr("10.0.0.2") {
		t.Fatalf("reply destination = %s, want original source", got)
	}
	if reply[20] != icmpTypeEchoReply {
		t.Fatalf("reply ICMP type = %d, want echo reply", reply[20])
	}
	counters := daemon.dataStats.snapshot()
	if counters.ReceiveBatchFrames != 1 || counters.ReceiveBatchPackets != 1 || counters.PacketsSent != 1 || counters.PacketsInjected != 0 || counters.InjectErrors != 0 {
		t.Fatalf("gateway echo counters = %+v, want received=1 sent=1 no inject", counters)
	}
}

func TestHandleReceivedDataPathBatchCoalescesLocalTCPSegmentsForGSO(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_RX_GSO_COALESCE", "1")
	daemon := &Daemon{
		desired: config.Desired{
			LAN: config.LANConfig{
				Advertise: []core.Prefix{"10.0.1.0/24"},
			},
		},
	}
	injector := &recordingInjector{}
	packetA := tcpPayloadIPv4PacketWithSeq(1, []byte("hello "))
	packetB := tcpPayloadIPv4PacketWithSeq(7, []byte("world"))

	daemon.handleReceivedDataPathBatch(context.Background(), [][]byte{packetA, packetB}, injector, injector)

	if len(injector.batchPackets) != 1 || len(injector.batchPackets[0]) != 1 {
		t.Fatalf("batch injections = %#v, want one coalesced wire packet", injector.batchPackets)
	}
	wire := injector.batchPackets[0][0]
	if string(wire[40:]) != "hello world" {
		t.Fatalf("coalesced payload = %q, want hello world", string(wire[40:]))
	}
	if binary.BigEndian.Uint16(wire[2:4]) != uint16(len(wire)) {
		t.Fatalf("coalesced IPv4 total length = %d, want %d", binary.BigEndian.Uint16(wire[2:4]), len(wire))
	}
	if !validTransportChecksumForTest(wire, wire[20:]) {
		t.Fatal("coalesced TCP checksum is invalid")
	}
	counters := daemon.dataStats.snapshot()
	if counters.PacketsInjected != 2 || counters.InjectBatchPackets != 2 {
		t.Fatalf("logical inject counters = %+v, want two logical packets", counters)
	}
	if counters.InjectGSOCoalesceBatches != 1 || counters.InjectGSOCoalescePackets != 2 || counters.InjectGSOCoalesceWires != 1 {
		t.Fatalf("GSO coalesce counters = %+v, want one 2-to-1 coalesce", counters)
	}
}

func TestHandleReceivedDataPathBatchMultiFlowCoalescesInterleavedTCPSegments(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_RX_GSO_COALESCE", "1")
	t.Setenv("TRUSTIX_DATA_SESSION_RX_GSO_COALESCE_MULTI_FLOW", "1")
	daemon := &Daemon{
		desired: config.Desired{
			LAN: config.LANConfig{
				Advertise: []core.Prefix{"10.0.1.0/24"},
			},
		},
	}
	injector := &recordingInjector{}
	flowA1 := tcpPayloadIPv4PacketWithSeqAndPorts(1, 12345, 18200, []byte("aa"))
	flowB1 := tcpPayloadIPv4PacketWithSeqAndPorts(1, 12346, 18200, []byte("bb"))
	flowA2 := tcpPayloadIPv4PacketWithSeqAndPorts(3, 12345, 18200, []byte("AA"))
	flowB2 := tcpPayloadIPv4PacketWithSeqAndPorts(3, 12346, 18200, []byte("BB"))

	daemon.handleReceivedDataPathBatch(context.Background(), [][]byte{flowA1, flowB1, flowA2, flowB2}, injector, injector)

	if len(injector.batchPackets) != 1 || len(injector.batchPackets[0]) != 2 {
		t.Fatalf("batch injections = %#v, want two coalesced wire packets", injector.batchPackets)
	}
	if string(injector.batchPackets[0][0][40:]) != "aaAA" || string(injector.batchPackets[0][1][40:]) != "bbBB" {
		t.Fatalf("coalesced payloads = %q / %q, want aaAA / bbBB", string(injector.batchPackets[0][0][40:]), string(injector.batchPackets[0][1][40:]))
	}
	counters := daemon.dataStats.snapshot()
	if counters.InjectGSOCoalesceBatches != 2 || counters.InjectGSOCoalescePackets != 4 || counters.InjectGSOCoalesceWires != 2 {
		t.Fatalf("GSO coalesce counters = %+v, want two 2-to-1 coalesces", counters)
	}
}

func TestHandleReceivedDataPathBatchDefersTCPChecksumForGSOOffload(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_RX_GSO_COALESCE", "1")
	daemon := &Daemon{
		desired: config.Desired{
			LAN: config.LANConfig{
				Advertise: []core.Prefix{"10.0.1.0/24"},
			},
		},
	}
	injector := &recordingGSOChecksumOffloadInjector{mtu: 64}
	packetA := tcpPayloadIPv4PacketWithSeq(1, bytes.Repeat([]byte("a"), 32))
	packetB := tcpPayloadIPv4PacketWithSeq(33, bytes.Repeat([]byte("b"), 32))

	daemon.handleReceivedDataPathBatch(context.Background(), [][]byte{packetA, packetB}, injector, injector)

	if len(injector.batchPackets) != 1 || len(injector.batchPackets[0]) != 1 {
		t.Fatalf("batch injections = %#v, want one coalesced wire packet", injector.batchPackets)
	}
	wire := injector.batchPackets[0][0]
	if len(wire) <= injector.mtu {
		t.Fatalf("coalesced packet len = %d, want GSO-sized packet above MTU %d", len(wire), injector.mtu)
	}
	if binary.BigEndian.Uint16(wire[2:4]) != uint16(len(wire)) {
		t.Fatalf("coalesced IPv4 total length = %d, want %d", binary.BigEndian.Uint16(wire[2:4]), len(wire))
	}
	if got := binary.BigEndian.Uint16(wire[36:38]); got != 0 {
		t.Fatalf("deferred TCP checksum = %#x, want zero before LAN GSO header preparation", got)
	}
	if ipv4Checksum(wire[:20]) != 0 {
		t.Fatalf("coalesced IPv4 checksum = %#x, want valid header checksum", binary.BigEndian.Uint16(wire[10:12]))
	}
}

func TestCoalesceDataSessionRXTCPLocalPacketsKeepsNonCoalescedPacketsUnchanged(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_RX_GSO_COALESCE", "1")
	packetA := tcpPayloadIPv4PacketWithSeq(1, []byte("hello"))
	packetB := tcpPayloadIPv4PacketWithSeq(99, []byte("world"))
	originalA := append([]byte(nil), packetA...)
	originalB := append([]byte(nil), packetB...)

	packets, stats := coalesceDataSessionRXTCPLocalPackets([][]byte{packetA, packetB})

	if stats.Batches != 0 {
		t.Fatalf("coalesce stats = %+v, want no coalesce", stats)
	}
	if len(packets) != 2 || !reflect.DeepEqual(packets[0], originalA) || !reflect.DeepEqual(packets[1], originalB) {
		t.Fatal("non-coalesced packets should pass through without checksum mutation")
	}
	if !reflect.DeepEqual(packetA, originalA) || !reflect.DeepEqual(packetB, originalB) {
		t.Fatal("source packets were mutated despite no coalesce")
	}
}

func TestHandleReceivedDataPathPacketsDisablesCoalesceForUserspaceEncryptedReceive(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_RX_GSO_COALESCE", "1")
	daemon := &Daemon{
		desired: config.Desired{
			LAN: config.LANConfig{
				Advertise: []core.Prefix{"10.0.1.0/24"},
			},
		},
	}
	injector := &recordingInjector{}
	session := &recordingSession{stats: transport.TransportStats{
		Encrypted:        true,
		ReceiveEncrypted: true,
		CryptoPlacement:  "userspace",
	}}
	packetA := tcpPayloadIPv4PacketWithSeq(1, []byte("hello "))
	packetB := tcpPayloadIPv4PacketWithSeq(7, []byte("world"))

	daemon.handleReceivedDataPathPackets(context.Background(), nil, session, [][]byte{packetA, packetB}, injector, injector, &dataReceiveScratch{})

	if len(injector.batchPackets) != 1 || len(injector.batchPackets[0]) != 2 {
		t.Fatalf("batch injections = %#v, want one uncoalesced two-packet batch", injector.batchPackets)
	}
	counters := daemon.dataStats.snapshot()
	if counters.InjectGSOCoalesceBatches != 0 || counters.InjectGSOCoalescePackets != 0 || counters.InjectGSOCoalesceWires != 0 {
		t.Fatalf("GSO coalesce counters = %+v, want disabled", counters)
	}
}

func TestHandleReceivedDataPathPacketsAllowsCoalesceForUserspaceEncryptedReceiveWhenEnabled(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_RX_GSO_COALESCE", "1")
	t.Setenv("TRUSTIX_DATA_SESSION_RX_GSO_COALESCE_USERSPACE_ENCRYPTED", "1")
	daemon := &Daemon{
		desired: config.Desired{
			LAN: config.LANConfig{
				Advertise: []core.Prefix{"10.0.1.0/24"},
			},
		},
	}
	injector := &recordingInjector{}
	session := &recordingSession{stats: transport.TransportStats{
		Encrypted:        true,
		ReceiveEncrypted: true,
		CryptoPlacement:  "userspace",
	}}
	packetA := tcpPayloadIPv4PacketWithSeq(1, []byte("hello "))
	packetB := tcpPayloadIPv4PacketWithSeq(7, []byte("world"))

	daemon.handleReceivedDataPathPackets(context.Background(), nil, session, [][]byte{packetA, packetB}, injector, injector, &dataReceiveScratch{})

	if len(injector.batchPackets) != 1 || len(injector.batchPackets[0]) != 1 {
		t.Fatalf("batch injections = %#v, want one coalesced wire packet", injector.batchPackets)
	}
	counters := daemon.dataStats.snapshot()
	if counters.InjectGSOCoalesceBatches != 1 || counters.InjectGSOCoalescePackets != 2 || counters.InjectGSOCoalesceWires != 1 {
		t.Fatalf("GSO coalesce counters = %+v, want one 2-to-1 coalesce", counters)
	}
}

func TestHandleReceivedDataPathPacketsAllowsCoalesceForPlaintextByDefault(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_RX_GSO_COALESCE", "1")
	daemon := &Daemon{
		desired: config.Desired{
			LAN: config.LANConfig{
				Advertise: []core.Prefix{"10.0.1.0/24"},
			},
		},
	}
	injector := &recordingInjector{}
	session := &recordingSession{}
	packetA := tcpPayloadIPv4PacketWithSeq(1, []byte("hello "))
	packetB := tcpPayloadIPv4PacketWithSeq(7, []byte("world"))

	daemon.handleReceivedDataPathPackets(context.Background(), nil, session, [][]byte{packetA, packetB}, injector, injector, &dataReceiveScratch{})

	if len(injector.batchPackets) != 1 || len(injector.batchPackets[0]) != 1 {
		t.Fatalf("batch injections = %#v, want one coalesced wire packet", injector.batchPackets)
	}
	counters := daemon.dataStats.snapshot()
	if counters.InjectGSOCoalesceBatches != 1 || counters.InjectGSOCoalescePackets != 2 || counters.InjectGSOCoalesceWires != 1 {
		t.Fatalf("GSO coalesce counters = %+v, want one 2-to-1 coalesce", counters)
	}
}

func TestHandleReceivedDataPathPacketsDisablesCoalesceForPlaintextWhenDisabled(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_RX_GSO_COALESCE", "1")
	t.Setenv("TRUSTIX_DATA_SESSION_RX_GSO_COALESCE_PLAINTEXT", "0")
	daemon := &Daemon{
		desired: config.Desired{
			LAN: config.LANConfig{
				Advertise: []core.Prefix{"10.0.1.0/24"},
			},
		},
	}
	injector := &recordingInjector{}
	session := &recordingSession{}
	packetA := tcpPayloadIPv4PacketWithSeq(1, []byte("hello "))
	packetB := tcpPayloadIPv4PacketWithSeq(7, []byte("world"))

	daemon.handleReceivedDataPathPackets(context.Background(), nil, session, [][]byte{packetA, packetB}, injector, injector, &dataReceiveScratch{})

	if len(injector.batchPackets) != 1 || len(injector.batchPackets[0]) != 2 {
		t.Fatalf("batch injections = %#v, want one uncoalesced two-packet batch", injector.batchPackets)
	}
	counters := daemon.dataStats.snapshot()
	if counters.InjectGSOCoalesceBatches != 0 || counters.InjectGSOCoalescePackets != 0 || counters.InjectGSOCoalesceWires != 0 {
		t.Fatalf("GSO coalesce counters = %+v, want disabled", counters)
	}
}

func TestCoalesceDataSessionRXTCPLocalPacketsKeepsNonContiguousSegments(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_RX_GSO_COALESCE", "1")
	packetA := tcpPayloadIPv4PacketWithSeq(1, []byte("hello"))
	packetB := tcpPayloadIPv4PacketWithSeq(99, []byte("world"))

	packets, stats := coalesceDataSessionRXTCPLocalPackets([][]byte{packetA, packetB})

	if stats.Batches != 0 {
		t.Fatalf("coalesce stats = %+v, want no coalesce", stats)
	}
	if len(packets) != 2 || !reflect.DeepEqual(packets[0], packetA) || !reflect.DeepEqual(packets[1], packetB) {
		t.Fatal("non-contiguous packets should pass through unchanged")
	}
	if len(packets) > 0 && &packets[0][0] != &packetA[0] {
		t.Fatal("non-contiguous packets should keep original storage")
	}
}

func TestCoalesceDataSessionRXTCPLocalPacketsKeepsDifferentTCPOptionsSeparate(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_RX_GSO_COALESCE", "1")
	packetA := tcpPayloadIPv4PacketWithSeqAndTimestamp(1, 100, []byte("hello"))
	packetB := tcpPayloadIPv4PacketWithSeqAndTimestamp(6, 200, []byte("world"))

	packets, stats := coalesceDataSessionRXTCPLocalPackets([][]byte{packetA, packetB})

	if stats.Batches != 0 {
		t.Fatalf("coalesce stats = %+v, want no coalesce", stats)
	}
	if len(packets) != 2 || !reflect.DeepEqual(packets[0], packetA) || !reflect.DeepEqual(packets[1], packetB) {
		t.Fatal("packets with different TCP options should pass through unchanged")
	}
}

func TestReceiveDataPathSessionDrainsRecvPacketBatch(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_RX_GSO_COALESCE", "0")
	session := &batchRecvSession{
		batches: [][][]byte{{tcpIPv4Packet(), udpIPv4Packet([]byte("recv-batch"))}},
		err:     fmt.Errorf("done"),
	}
	injector := &recordingInjector{}
	daemon := &Daemon{
		dataplane: &recordingDataplane{
			NoopManager:       dataplane.NewNoopManager(),
			recordingInjector: injector,
		},
		desired: config.Desired{
			LAN: config.LANConfig{
				Advertise: []core.Prefix{"10.0.1.0/24"},
			},
		},
	}

	daemon.receiveDataPathSession(context.Background(), nil, session)

	if len(injector.batchPackets) != 1 || len(injector.batchPackets[0]) != 2 {
		t.Fatalf("batch injections = %#v, want one two-packet batch", injector.batchPackets)
	}
	counters := daemon.dataStats.snapshot()
	if counters.PacketsReceived != 2 || counters.InjectBatchAttempts != 1 || counters.InjectBatchPackets != 2 || counters.PacketsInjected != 2 {
		t.Fatalf("receive batch counters = %+v, want received=2 injected=2", counters)
	}
	if !session.closed {
		t.Fatal("session was not closed on receive exit")
	}
}

func TestReceiveDataPathSessionControlOnlyIgnoresDataAndKeepsControl(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_RX_GSO_COALESCE", "0")
	session := &batchRecvSession{
		batches: [][][]byte{{tcpIPv4Packet(), encodeDataSessionControl(dataSessionControlPing, 33)}},
		err:     fmt.Errorf("done"),
	}
	injector := &recordingInjector{}
	daemon := &Daemon{
		dataplane: &recordingDataplane{
			NoopManager:       dataplane.NewNoopManager(),
			recordingInjector: injector,
		},
	}
	runtime := &dataSessionRuntime{controlOnly: true}

	daemon.receiveDataPathSession(context.Background(), runtime, session)

	if len(injector.packets) != 0 || len(injector.batchPackets) != 0 {
		t.Fatalf("control-only session injected packets = singles:%d batches:%d, want none", len(injector.packets), len(injector.batchPackets))
	}
	if len(session.sent) != 1 {
		t.Fatalf("control-only sent frames = %d, want pong", len(session.sent))
	}
	kind, nonce, ok := decodeDataSessionControl(session.sent[0])
	if !ok || kind != dataSessionControlPong || nonce != 33 {
		t.Fatalf("pong frame = kind %d nonce %d ok %v, want pong 33", kind, nonce, ok)
	}
	counters := daemon.dataStats.snapshot()
	if counters.PacketsReceived != 0 || counters.PacketsInjected != 0 || counters.SessionHeartbeatReceived != 1 {
		t.Fatalf("control-only counters = %+v, want no data receive/inject and one heartbeat", counters)
	}
	if !session.closed {
		t.Fatal("session was not closed on receive exit")
	}
}

func TestReceiveDataPathSessionControlOnlyReceiveDataInjectsDataAndKeepsControl(t *testing.T) {
	t.Setenv("TRUSTIX_DATA_SESSION_RX_GSO_COALESCE", "0")
	session := &batchRecvSession{
		batches: [][][]byte{{tcpIPv4Packet(), encodeDataSessionControl(dataSessionControlPing, 33)}},
		err:     fmt.Errorf("done"),
	}
	injector := &recordingInjector{}
	daemon := &Daemon{
		dataplane: &recordingDataplane{
			NoopManager:       dataplane.NewNoopManager(),
			recordingInjector: injector,
		},
		desired: config.Desired{
			LAN: config.LANConfig{
				Advertise: []core.Prefix{"10.0.1.0/24"},
			},
		},
	}
	runtime := &dataSessionRuntime{controlOnly: true, receiveData: true}

	daemon.receiveDataPathSession(context.Background(), runtime, session)

	if len(injector.packets) != 0 || len(injector.batchPackets) != 1 || len(injector.batchPackets[0]) != 1 {
		t.Fatalf("control-only receive-data injections = singles:%d batches:%#v, want one batched data packet", len(injector.packets), injector.batchPackets)
	}
	if len(session.sent) != 1 {
		t.Fatalf("control-only receive-data sent frames = %d, want pong", len(session.sent))
	}
	kind, nonce, ok := decodeDataSessionControl(session.sent[0])
	if !ok || kind != dataSessionControlPong || nonce != 33 {
		t.Fatalf("pong frame = kind %d nonce %d ok %v, want pong 33", kind, nonce, ok)
	}
	counters := daemon.dataStats.snapshot()
	if counters.PacketsReceived != 1 || counters.PacketsInjected != 1 || counters.InjectBatchAttempts != 1 || counters.InjectBatchPackets != 1 || counters.SessionHeartbeatReceived != 1 {
		t.Fatalf("control-only receive-data counters = %+v, want one data receive/inject and one heartbeat", counters)
	}
	if !session.closed {
		t.Fatal("session was not closed on receive exit")
	}
}

func TestHandleDataSessionControlRepliesToPingAndSwallowsFrame(t *testing.T) {
	daemon := &Daemon{}
	session := &recordingSession{}
	packet := encodeDataSessionControl(dataSessionControlPing, 7)

	if !daemon.handleDataSessionControl(context.Background(), nil, session, packet) {
		t.Fatal("expected ping control frame to be handled")
	}
	if len(session.sent) != 1 {
		t.Fatalf("sent frames = %d, want pong", len(session.sent))
	}
	kind, nonce, ok := decodeDataSessionControl(session.sent[0])
	if !ok || kind != dataSessionControlPong || nonce != 7 {
		t.Fatalf("pong frame = kind %d nonce %d ok %v, want pong 7", kind, nonce, ok)
	}
	if got := daemon.dataStats.snapshot().SessionHeartbeatReceived; got != 1 {
		t.Fatalf("session heartbeat received counter = %d, want 1", got)
	}
}

func TestHandleDataSessionControlRecordsPongNonce(t *testing.T) {
	daemon := &Daemon{}
	runtime := &dataSessionRuntime{}
	if !daemon.handleDataSessionControl(context.Background(), runtime, &recordingSession{}, encodeDataSessionControl(dataSessionControlPong, 9)) {
		t.Fatal("expected pong control frame to be handled")
	}
	if got := runtime.pongNonce.Load(); got != 9 {
		t.Fatalf("pong nonce = %d, want 9", got)
	}
	if runtime.lastPong.Load() == 0 {
		t.Fatal("expected last pong timestamp to be recorded")
	}
	if runtime.lastRX.Load() == 0 {
		t.Fatal("expected last receive timestamp to be recorded")
	}
}

func TestHandleReceivedDataPathPacketsSkipsSecureHandshakeFrame(t *testing.T) {
	daemon := &Daemon{}
	injector := &recordingInjector{}
	handshake := make([]byte, 76)
	copy(handshake[0:4], dataSessionSecureHandshakeMagic[:])
	handshake[4] = 1
	handshake[5] = 2

	daemon.handleReceivedDataPathPackets(context.Background(), nil, &recordingSession{}, [][]byte{handshake}, injector, injector, &dataReceiveScratch{})

	if len(injector.packets) != 0 || len(injector.batchPackets) != 0 {
		t.Fatalf("injected packets = single:%d batch:%d, want 0", len(injector.packets), len(injector.batchPackets))
	}
	if got := daemon.dataStats.injectErrors.Load(); got != 0 {
		t.Fatalf("inject errors = %d, want 0", got)
	}
}

func TestWaitForDataSessionPongAcceptsPostPingTraffic(t *testing.T) {
	daemon := &Daemon{}
	runtime := &dataSessionRuntime{}
	done := make(chan bool, 1)
	go func() {
		done <- daemon.waitForDataSessionPong(context.Background(), runtime, 11, 250*time.Millisecond)
	}()
	time.Sleep(25 * time.Millisecond)
	runtime.lastRX.Store(time.Now().UTC().UnixNano())

	select {
	case ok := <-done:
		if !ok {
			t.Fatal("expected post-ping receive activity to satisfy heartbeat wait")
		}
	case <-time.After(time.Second):
		t.Fatal("heartbeat wait did not observe receive activity")
	}
}

func TestDataSessionHeartbeatSkipsRecentlyActiveRuntime(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				SessionPool: config.SessionPoolPolicyConfig{
					Heartbeat: config.SessionPoolHeartbeatConfig{
						Mode:     "enabled",
						Interval: "20ms",
						Timeout:  "20ms",
					},
				},
			},
		},
	}
	session := &recordingSession{}
	runtime := &dataSessionRuntime{session: session}
	runtime.lastTX.Store(time.Now().UTC().UnixNano())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go daemon.runDataSessionHeartbeat(ctx, runtime)

	time.Sleep(50 * time.Millisecond)
	cancel()

	if len(session.sent) != 0 {
		t.Fatalf("heartbeat sent %d control packets for a recently active session", len(session.sent))
	}
	if got := daemon.dataStats.snapshot().SessionHeartbeatTimeouts; got != 0 {
		t.Fatalf("heartbeat timeouts = %d, want 0", got)
	}
}

func TestDataSessionWireActivityTimestamps(t *testing.T) {
	daemon := &Daemon{}
	session := &recordingSession{}
	runtime := &dataSessionRuntime{session: session}

	if err := daemon.sendDataSessionWirePacket(runtime, session, tcpIPv4Packet()); err != nil {
		t.Fatalf("send wire packet: %v", err)
	}
	if runtime.lastTX.Load() == 0 {
		t.Fatal("expected transmit timestamp after successful send")
	}

	beforeRX := runtime.lastRX.Load()
	daemon.handleReceivedDataPathPackets(context.Background(), runtime, session, [][]byte{udpIPv4Packet([]byte("rx"))}, nil, nil, nil)
	if runtime.lastRX.Load() <= beforeRX {
		t.Fatal("expected receive timestamp after inbound packet")
	}
}

func TestDropSessionDoesNotInvalidateOtherInFlightDials(t *testing.T) {
	key := dataSessionKey{
		Peer:       core.IXID("ix-b"),
		Endpoint:   core.EndpointID("ep-1"),
		Transport:  transport.ProtocolUDP,
		Address:    "192.0.2.1:7001",
		Encryption: "secure",
		PoolIndex:  1,
	}
	daemon := &Daemon{
		dataSessions:     map[dataSessionKey]transport.Session{key: &recordingSession{}},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{key: &dataSessionRuntime{}},
		dataSessionEpoch: 7,
	}

	daemon.dropSession(key)

	if daemon.dataSessionEpoch != 7 {
		t.Fatalf("data session epoch = %d, want unchanged", daemon.dataSessionEpoch)
	}
	if len(daemon.dataSessions) != 0 || len(daemon.dataSessionState) != 0 {
		t.Fatalf("session maps were not cleared: sessions=%d state=%d", len(daemon.dataSessions), len(daemon.dataSessionState))
	}
}

func TestReceiveDataPathSessionResetDropsSessionWithoutMarkingEndpointDown(t *testing.T) {
	peer := testPeer()
	endpoint := peer.Endpoints[0]
	key := dataSessionKey{
		Peer:       peer.ID,
		Endpoint:   endpoint.Name,
		Transport:  transport.Protocol(endpoint.Transport),
		Address:    endpoint.Address,
		Encryption: "secure",
	}
	session := &errorSession{err: securetransport.ErrSessionReset}
	runtime := &dataSessionRuntime{key: key, peer: peer, endpoint: endpoint}
	daemon := &Daemon{
		dataSessions:     map[dataSessionKey]transport.Session{key: session},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{key: runtime},
		endpointState:    make(map[endpointStateKey]rstate.EndpointState),
	}

	daemon.receiveDataPathSession(context.Background(), runtime, session)

	if len(daemon.dataSessions) != 0 || len(daemon.dataSessionState) != 0 {
		t.Fatalf("session maps not cleared after reset: sessions=%d state=%d", len(daemon.dataSessions), len(daemon.dataSessionState))
	}
	state, ok := daemon.endpointStateFor(peer.ID, endpoint)
	if !ok {
		t.Fatal("endpoint state was not recorded")
	}
	if state.Health != rstate.EndpointUp {
		t.Fatalf("endpoint health = %s, want up", state.Health)
	}
	if session.closed != 2 {
		t.Fatalf("session close count = %d, want 2", session.closed)
	}
	counters := daemon.dataStats.snapshot()
	if counters.SessionResetsReceived != 1 || counters.StaleSessionsDropped != 1 {
		t.Fatalf("reset counters = received:%d stale:%d, want 1/1", counters.SessionResetsReceived, counters.StaleSessionsDropped)
	}
}

func TestEndpointDownFromOnePoolMemberDoesNotDownWholeEndpoint(t *testing.T) {
	peer := testPeer()
	endpoint := peer.Endpoints[0]
	activeKey := dataSessionKey{
		Peer:       peer.ID,
		Endpoint:   endpoint.Name,
		Transport:  transport.Protocol(endpoint.Transport),
		Address:    endpoint.Address,
		Encryption: "secure",
		PoolIndex:  2,
	}
	daemon := &Daemon{
		dataSessions:     map[dataSessionKey]transport.Session{activeKey: &recordingSession{}},
		endpointState:    make(map[endpointStateKey]rstate.EndpointState),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
	}

	if daemon.recordEndpointDownIfNoActiveSession(peer.ID, endpoint, fmt.Errorf("pool member timed out")) {
		t.Fatal("endpoint state changed while another pool member is active")
	}
	if daemon.endpointMarkedDown(peer.ID, endpoint) {
		t.Fatal("endpoint was marked down despite an active pooled session")
	}

	delete(daemon.dataSessions, activeKey)
	if !daemon.recordEndpointDownIfNoActiveSession(peer.ID, endpoint, fmt.Errorf("all pool members down")) {
		t.Fatal("expected endpoint state to change after last pooled session disappeared")
	}
	if !daemon.endpointMarkedDown(peer.ID, endpoint) {
		t.Fatal("endpoint was not marked down after all pooled sessions disappeared")
	}
}

func TestEndpointDownSuppressedByReverseSession(t *testing.T) {
	peer := testPeer()
	endpoint := peer.Endpoints[0]
	reverseKey := reverseDataSessionKey(peer.ID, endpoint, securetransport.EncryptionSecure)
	daemon := &Daemon{
		dataSessions:     map[dataSessionKey]transport.Session{reverseKey: &recordingSession{}},
		endpointState:    make(map[endpointStateKey]rstate.EndpointState),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
	}

	if daemon.recordEndpointDownIfNoActiveSession(peer.ID, endpoint, fmt.Errorf("dial failed")) {
		t.Fatal("endpoint state changed while reverse session is active")
	}
	if daemon.endpointMarkedDown(peer.ID, endpoint) {
		t.Fatal("endpoint was marked down despite an active reverse session")
	}
}

func TestInboundPeerIdentityDoesNotCloseOutboundPooledSessions(t *testing.T) {
	peer := testPeer()
	endpoint := peer.Endpoints[0]
	key := dataSessionKey{
		Peer:       peer.ID,
		Endpoint:   endpoint.Name,
		Transport:  transport.Protocol(endpoint.Transport),
		Address:    endpoint.Address,
		Encryption: "secure",
		PoolIndex:  1,
	}
	daemon := &Daemon{
		desired: config.Desired{IX: config.IXConfig{ID: core.IXID("ix-a")}},
		dataSessions: map[dataSessionKey]transport.Session{
			key: &recordingSession{},
		},
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		dataSessionEpoch: 3,
	}
	inbound := &identitySession{
		peer:   peer.ID,
		domain: peer.Domain,
		err:    fmt.Errorf("done"),
	}

	daemon.receiveDataPathSession(context.Background(), nil, inbound)

	if _, ok := daemon.dataSessions[key]; !ok {
		t.Fatal("inbound peer identity closed an existing outbound pooled session")
	}
	if daemon.dataSessionEpoch != 3 {
		t.Fatalf("data session epoch = %d, want unchanged", daemon.dataSessionEpoch)
	}
	if !inbound.closed {
		t.Fatal("inbound session was not closed on receive exit")
	}
}

func TestRegisterInboundPublicEndpointKeepsOutboundSession(t *testing.T) {
	peer := testPeer()
	endpoint := peer.Endpoints[0]
	outboundKey := dataSessionKey{
		Peer:       peer.ID,
		Endpoint:   endpoint.Name,
		Transport:  transport.Protocol(endpoint.Transport),
		Address:    endpoint.Address,
		Encryption: securetransport.EncryptionSecure,
		PoolIndex:  1,
	}
	outbound := &recordingSession{}
	daemon := &Daemon{
		desired: config.Desired{
			IX:     config.IXConfig{ID: core.IXID("ix-a")},
			Domain: config.DomainConfig{ID: core.DomainID("lab.local")},
			Peers:  []config.PeerConfig{peer},
			TransportPolicy: config.TransportPolicyConfig{
				SessionPool: config.SessionPoolPolicyConfig{Size: 4},
			},
		},
		dataSessions: map[dataSessionKey]transport.Session{
			outboundKey: outbound,
		},
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		endpointState:    make(map[endpointStateKey]rstate.EndpointState),
	}
	inbound := &blockingIdentitySession{
		peer:   peer.ID,
		domain: peer.Domain,
		recv:   make(chan struct{}),
	}

	runtime, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{
		Name:      endpoint.Name,
		Transport: transport.Protocol(endpoint.Transport),
	}, inbound)
	if err != nil {
		t.Fatalf("register inbound session: %v", err)
	}
	if runtime == nil {
		t.Fatal("register inbound session returned nil runtime")
	}
	defer daemon.dropSession(runtime.key)

	if _, ok := daemon.dataSessions[outboundKey]; !ok {
		t.Fatal("public inbound session dropped existing outbound session")
	}
	if outbound.closed {
		t.Fatal("public inbound session closed existing outbound session")
	}
	reverseKey := reverseDataSessionKey(peer.ID, endpoint, securetransport.EncryptionSecure)
	if _, ok := daemon.dataSessions[reverseKey]; !ok {
		t.Fatal("inbound reverse session was not registered")
	}
}

func TestDropSessionsForPeerTransportDropsOnlyMatchingSessions(t *testing.T) {
	peer := testPeer()
	udpKey := dataSessionKey{
		Peer:       peer.ID,
		Endpoint:   core.EndpointID("ep-udp"),
		Transport:  transport.ProtocolUDP,
		Address:    "192.0.2.1:7001",
		Encryption: "secure",
		PoolIndex:  0,
	}
	greKey := dataSessionKey{
		Peer:       peer.ID,
		Endpoint:   core.EndpointID("ep-gre"),
		Transport:  transport.ProtocolGRE,
		Address:    "local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.30.1/30,remote_carrier=10.255.30.2",
		Encryption: "secure",
		PoolIndex:  1,
	}
	otherPeerKey := dataSessionKey{
		Peer:       core.IXID("ix-c"),
		Endpoint:   core.EndpointID("ep-udp"),
		Transport:  transport.ProtocolUDP,
		Address:    "192.0.2.3:7003",
		Encryption: "secure",
	}
	udpSession := &recordingSession{}
	greSession := &recordingSession{}
	otherSession := &recordingSession{}
	udpCancel := false
	greCancel := false
	udpCancelFunc := func() { udpCancel = true }
	greCancelFunc := func() { greCancel = true }
	daemon := &Daemon{
		desired: config.Desired{IX: config.IXConfig{ID: core.IXID("ix-a")}},
		dataSessions: map[dataSessionKey]transport.Session{
			udpKey:       udpSession,
			greKey:       greSession,
			otherPeerKey: otherSession,
		},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{
			udpKey: {key: udpKey, cancel: udpCancelFunc},
			greKey: {key: greKey, cancel: greCancelFunc},
		},
		sessionPoolRR: map[dataSessionPoolKey]uint64{
			{
				Peer:       udpKey.Peer,
				Endpoint:   udpKey.Endpoint,
				Transport:  udpKey.Transport,
				Address:    udpKey.Address,
				Encryption: udpKey.Encryption,
			}: 4,
			{
				Peer:       greKey.Peer,
				Endpoint:   greKey.Endpoint,
				Transport:  greKey.Transport,
				Address:    greKey.Address,
				Encryption: greKey.Encryption,
			}: 7,
		},
	}
	inbound := &identitySession{peer: peer.ID, domain: peer.Domain}

	dropped := daemon.dropSessionsForPeerTransport(inbound.peer, transport.ProtocolGRE)

	if dropped != 1 {
		t.Fatalf("dropped sessions = %d, want 1", dropped)
	}
	if _, ok := daemon.dataSessions[greKey]; ok {
		t.Fatal("GRE outbound session was not dropped")
	}
	if _, ok := daemon.dataSessionState[greKey]; ok {
		t.Fatal("GRE runtime was not dropped")
	}
	if _, ok := daemon.dataSessions[udpKey]; !ok {
		t.Fatal("UDP session for another transport was dropped")
	}
	if _, ok := daemon.dataSessions[otherPeerKey]; !ok {
		t.Fatal("other peer session was dropped")
	}
	if !greCancel {
		t.Fatal("GRE runtime cancel was not called")
	}
	if udpCancel {
		t.Fatal("UDP runtime cancel was called")
	}
	for key := range daemon.sessionPoolRR {
		if key.Transport == transport.ProtocolGRE {
			t.Fatal("GRE pool cursor was not deleted")
		}
	}
	if !greSession.closed {
		t.Fatal("GRE session was not closed")
	}
	if udpSession.closed || otherSession.closed {
		t.Fatal("unrelated session was closed")
	}
}

func TestRegisterInboundReverseOnlyDataSessionDropsMatchingOutboundSession(t *testing.T) {
	peer := testPeer()
	publicAddress := peer.Endpoints[0].Address
	peer.Endpoints[0].Address = ""
	endpoint := peer.Endpoints[0]
	outboundKey := dataSessionKey{
		Peer:       peer.ID,
		Endpoint:   endpoint.Name,
		Transport:  transport.Protocol(endpoint.Transport),
		Address:    publicAddress,
		Encryption: securetransport.EncryptionSecure,
	}
	otherEndpointKey := dataSessionKey{
		Peer:       peer.ID,
		Endpoint:   peer.Endpoints[1].Name,
		Transport:  transport.Protocol(peer.Endpoints[1].Transport),
		Address:    peer.Endpoints[1].Address,
		Encryption: securetransport.EncryptionSecure,
	}
	outboundSession := &recordingSession{}
	otherSession := &recordingSession{}
	outboundCanceled := false
	otherCanceled := false
	daemon := &Daemon{
		desired: config.Desired{
			IX:     config.IXConfig{ID: core.IXID("ix-a")},
			Domain: config.DomainConfig{ID: peer.Domain},
			Peers:  []config.PeerConfig{peer},
		},
		dataSessions: map[dataSessionKey]transport.Session{
			outboundKey:      outboundSession,
			otherEndpointKey: otherSession,
		},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{
			outboundKey:      {key: outboundKey, cancel: func() { outboundCanceled = true }},
			otherEndpointKey: {key: otherEndpointKey, cancel: func() { otherCanceled = true }},
		},
		sessionPoolRR: map[dataSessionPoolKey]uint64{
			{
				Peer:       outboundKey.Peer,
				Endpoint:   outboundKey.Endpoint,
				Transport:  outboundKey.Transport,
				Address:    outboundKey.Address,
				Encryption: outboundKey.Encryption,
			}: 1,
		},
	}
	inbound := &identitySession{peer: peer.ID, domain: peer.Domain}

	runtime, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{
		Name:      endpoint.Name,
		Transport: transport.Protocol(endpoint.Transport),
	}, inbound)
	if err != nil {
		t.Fatalf("register inbound session: %v", err)
	}
	if runtime == nil {
		t.Fatal("register inbound session returned nil runtime")
	}
	if _, ok := daemon.dataSessions[outboundKey]; ok {
		t.Fatal("matching outbound session was not dropped")
	}
	reverseKey := reverseDataSessionKey(peer.ID, endpoint, securetransport.EncryptionSecure)
	if got := daemon.dataSessions[reverseKey]; got != inbound {
		t.Fatalf("reverse session = %#v, want inbound", got)
	}
	if _, ok := daemon.dataSessions[otherEndpointKey]; !ok {
		t.Fatal("unrelated endpoint session was dropped")
	}
	if !outboundCanceled {
		t.Fatal("matching outbound runtime cancel was not called")
	}
	if !outboundSession.closed {
		t.Fatal("matching outbound session was not closed")
	}
	if otherCanceled || otherSession.closed {
		t.Fatal("unrelated endpoint session was canceled or closed")
	}
	if len(daemon.sessionPoolRR) != 0 {
		t.Fatalf("pool cursors were not cleared: %#v", daemon.sessionPoolRR)
	}
	if counters := daemon.dataStats.snapshot(); counters.StaleSessionsDropped != 1 {
		t.Fatalf("stale sessions dropped = %d, want 1", counters.StaleSessionsDropped)
	}
}

func TestRegisterInboundSecureKernelUDPKeepsRecentReverseSession(t *testing.T) {
	peer := testPeer()
	endpoint := peer.Endpoints[0]
	reverseKey := reverseDataSessionKey(peer.ID, endpoint, securetransport.EncryptionSecure)
	secureKernelUDPStats := transport.TransportStats{
		Encrypted:      true,
		Encryption:     securetransport.EncryptionSecure,
		NativeBatching: true,
		Datagram:       true,
	}
	existing := &identitySession{
		recordingSession: recordingSession{stats: secureKernelUDPStats},
		peer:             peer.ID,
		domain:           peer.Domain,
	}
	incoming := &identitySession{
		recordingSession: recordingSession{stats: secureKernelUDPStats},
		peer:             peer.ID,
		domain:           peer.Domain,
	}
	existingRuntime := &dataSessionRuntime{key: reverseKey, session: existing}
	existingRuntime.lastUp.Store(time.Now().UTC().UnixNano())
	daemon := &Daemon{
		desired: config.Desired{
			IX:     config.IXConfig{ID: core.IXID("ix-a")},
			Domain: config.DomainConfig{ID: peer.Domain},
			Peers:  []config.PeerConfig{peer},
			TransportPolicy: config.TransportPolicyConfig{
				Encryption: securetransport.EncryptionSecure,
				KernelTransport: config.KernelTransportPolicyConfig{
					Mode: string(dataplane.KernelTransportModeRequireKernel),
				},
			},
		},
		dataplane: &kernelTransportDataplane{
			status: dataplane.KernelTransportStatus{
				Available: true,
				Protocols: []dataplane.KernelTransportProtocol{{
					Protocol:  string(transport.ProtocolUDP),
					Available: true,
				}},
			},
		},
		dataSessions: map[dataSessionKey]transport.Session{
			reverseKey: existing,
		},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{
			reverseKey: existingRuntime,
		},
		endpointState: make(map[endpointStateKey]rstate.EndpointState),
	}
	defer daemon.closeDataSessions()

	runtime, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{
		Name:      endpoint.Name,
		Transport: transport.Protocol(endpoint.Transport),
	}, incoming)
	if err != nil {
		t.Fatalf("register inbound session: %v", err)
	}
	if runtime != existingRuntime {
		t.Fatal("register inbound session did not keep existing reverse runtime")
	}
	if got := daemon.dataSessions[reverseKey]; got != existing {
		t.Fatalf("reverse session = %#v, want existing", got)
	}
	if !incoming.closed {
		t.Fatal("incoming replacement session was not closed")
	}
	if existing.closed {
		t.Fatal("existing reverse session was closed")
	}
	if counters := daemon.dataStats.snapshot(); counters.StaleSessionsDropped != 0 {
		t.Fatalf("stale sessions dropped = %d, want 0", counters.StaleSessionsDropped)
	}
}

func TestRegisterInboundSecureKernelUDPKeepsIdleReverseSessionWhenHeartbeatDisabled(t *testing.T) {
	peer := testPeer()
	endpoint := peer.Endpoints[0]
	reverseKey := reverseDataSessionKey(peer.ID, endpoint, securetransport.EncryptionSecure)
	secureKernelUDPStats := transport.TransportStats{
		Encrypted:      true,
		Encryption:     securetransport.EncryptionSecure,
		NativeBatching: true,
		Datagram:       true,
	}
	existing := &identitySession{
		recordingSession: recordingSession{stats: secureKernelUDPStats},
		peer:             peer.ID,
		domain:           peer.Domain,
	}
	incoming := &identitySession{
		recordingSession: recordingSession{stats: secureKernelUDPStats},
		peer:             peer.ID,
		domain:           peer.Domain,
	}
	existingRuntime := &dataSessionRuntime{key: reverseKey, session: existing}
	existingRuntime.lastUp.Store(time.Now().UTC().Add(-3 * dataSessionHeartbeatDefaultInterval).UnixNano())
	daemon := &Daemon{
		desired: config.Desired{
			IX:     config.IXConfig{ID: core.IXID("ix-a")},
			Domain: config.DomainConfig{ID: peer.Domain},
			Peers:  []config.PeerConfig{peer},
			TransportPolicy: config.TransportPolicyConfig{
				Encryption: securetransport.EncryptionSecure,
				KernelTransport: config.KernelTransportPolicyConfig{
					Mode: string(dataplane.KernelTransportModeRequireKernel),
				},
			},
		},
		dataplane: &kernelTransportDataplane{
			status: dataplane.KernelTransportStatus{
				Available: true,
				Protocols: []dataplane.KernelTransportProtocol{{
					Protocol:  string(transport.ProtocolUDP),
					Available: true,
				}},
			},
		},
		dataSessions: map[dataSessionKey]transport.Session{
			reverseKey: existing,
		},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{
			reverseKey: existingRuntime,
		},
		endpointState: make(map[endpointStateKey]rstate.EndpointState),
	}
	defer daemon.closeDataSessions()

	runtime, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{
		Name:      endpoint.Name,
		Transport: transport.Protocol(endpoint.Transport),
	}, incoming)
	if err != nil {
		t.Fatalf("register inbound session: %v", err)
	}
	if runtime != existingRuntime {
		t.Fatal("idle reverse session was replaced even though heartbeat is disabled")
	}
	if got := daemon.dataSessions[reverseKey]; got != existing {
		t.Fatalf("reverse session = %#v, want existing", got)
	}
	if !incoming.closed {
		t.Fatal("incoming replacement session was not closed")
	}
	if existing.closed {
		t.Fatal("existing reverse session was closed")
	}
}

func TestRegisterInboundSecureKernelUDPReplacesIdleReverseSessionWhenHeartbeatEnabled(t *testing.T) {
	peer := testPeer()
	endpoint := peer.Endpoints[0]
	reverseKey := reverseDataSessionKey(peer.ID, endpoint, securetransport.EncryptionSecure)
	secureKernelUDPStats := transport.TransportStats{
		Encrypted:      true,
		Encryption:     securetransport.EncryptionSecure,
		NativeBatching: true,
		Datagram:       true,
	}
	existing := &identitySession{
		recordingSession: recordingSession{stats: secureKernelUDPStats},
		peer:             peer.ID,
		domain:           peer.Domain,
	}
	incoming := &blockingIdentitySession{
		recordingSession: recordingSession{stats: secureKernelUDPStats},
		peer:             peer.ID,
		domain:           peer.Domain,
		recv:             make(chan struct{}),
	}
	existingRuntime := &dataSessionRuntime{key: reverseKey, session: existing}
	existingRuntime.lastUp.Store(time.Now().UTC().Add(-3 * dataSessionHeartbeatDefaultInterval).UnixNano())
	daemon := &Daemon{
		desired: config.Desired{
			IX:     config.IXConfig{ID: core.IXID("ix-a")},
			Domain: config.DomainConfig{ID: peer.Domain},
			Peers:  []config.PeerConfig{peer},
			TransportPolicy: config.TransportPolicyConfig{
				Encryption: securetransport.EncryptionSecure,
				KernelTransport: config.KernelTransportPolicyConfig{
					Mode: string(dataplane.KernelTransportModeRequireKernel),
				},
				SessionPool: config.SessionPoolPolicyConfig{
					Heartbeat: config.SessionPoolHeartbeatConfig{Mode: "enabled"},
				},
			},
		},
		dataplane: &kernelTransportDataplane{
			status: dataplane.KernelTransportStatus{
				Available: true,
				Protocols: []dataplane.KernelTransportProtocol{{
					Protocol:  string(transport.ProtocolUDP),
					Available: true,
				}},
			},
		},
		dataSessions: map[dataSessionKey]transport.Session{
			reverseKey: existing,
		},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{
			reverseKey: existingRuntime,
		},
		endpointState: make(map[endpointStateKey]rstate.EndpointState),
	}
	defer daemon.closeDataSessions()

	runtime, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{
		Name:      endpoint.Name,
		Transport: transport.Protocol(endpoint.Transport),
	}, incoming)
	if err != nil {
		t.Fatalf("register inbound session: %v", err)
	}
	if runtime == nil || runtime == existingRuntime {
		t.Fatal("idle reverse session was not replaced when heartbeat is enabled")
	}
	if got := daemon.dataSessions[reverseKey]; got != incoming {
		t.Fatalf("reverse session = %#v, want incoming", got)
	}
	if !existing.closed {
		t.Fatal("stale reverse session was not closed")
	}
}

func TestRegisterInboundExperimentalTCPSessionKeepsDialableOutboundSession(t *testing.T) {
	peer := testPeer()
	peer.Endpoints[0].Name = core.EndpointID("b-experimental-tcp")
	peer.Endpoints[0].Transport = string(transport.ProtocolExperimentalTCP)
	peer.Endpoints[0].Address = "198.51.100.2:7142"
	endpoint := peer.Endpoints[0]
	outboundKey := dataSessionKey{
		Peer:       peer.ID,
		Endpoint:   endpoint.Name,
		Transport:  transport.Protocol(endpoint.Transport),
		Address:    endpoint.Address,
		Encryption: securetransport.EncryptionSecure,
	}
	outboundSession := &recordingSession{}
	outboundCanceled := false
	daemon := &Daemon{
		desired: config.Desired{
			IX:     config.IXConfig{ID: core.IXID("ix-a")},
			Domain: config.DomainConfig{ID: peer.Domain},
			Peers:  []config.PeerConfig{peer},
		},
		dataSessions: map[dataSessionKey]transport.Session{
			outboundKey: outboundSession,
		},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{
			outboundKey: {key: outboundKey, cancel: func() { outboundCanceled = true }},
		},
	}
	inbound := &blockingIdentitySession{
		peer:   peer.ID,
		domain: peer.Domain,
		recv:   make(chan struct{}),
	}
	defer inbound.Close()

	runtime, err := daemon.registerInboundDataSession(context.Background(), transport.Endpoint{
		Name:      endpoint.Name,
		Transport: transport.Protocol(endpoint.Transport),
	}, inbound)
	if err != nil {
		t.Fatalf("register inbound experimental_tcp session: %v", err)
	}
	if runtime == nil {
		t.Fatal("register inbound experimental_tcp session returned nil runtime")
	}
	if got := daemon.dataSessions[outboundKey]; got != outboundSession {
		t.Fatalf("outbound experimental_tcp session = %#v, want existing outbound", got)
	}
	reverseKey := reverseDataSessionKey(peer.ID, endpoint, securetransport.EncryptionSecure)
	if got := daemon.dataSessions[reverseKey]; got != inbound {
		t.Fatalf("reverse experimental_tcp session = %#v, want inbound", got)
	}
	if outboundCanceled {
		t.Fatal("dialable outbound experimental_tcp runtime cancel was called")
	}
	if outboundSession.closed {
		t.Fatal("dialable outbound experimental_tcp session was closed")
	}
}

func TestEndpointStateSnapshotAddsFlowAndSessionCounters(t *testing.T) {
	daemon := &Daemon{
		flows:         make(map[routing.FlowKey]routing.FlowBinding),
		endpointState: make(map[endpointStateKey]rstate.EndpointState),
	}
	daemon.recordEndpointUp(core.IXID("ix-b"), testPeer().Endpoints[0], time.Millisecond)
	daemon.bindFlow(routing.FlowKey{
		SourceIP:      netip.MustParseAddr("10.0.0.2"),
		DestinationIP: netip.MustParseAddr("10.0.1.2"),
		Protocol:      1,
	}, core.IXID("ix-b"), core.EndpointID("ep-1"))

	states := daemon.endpointStateSnapshot()
	if len(states) != 1 {
		t.Fatalf("endpoint states = %d, want 1", len(states))
	}
	if states[0].Health != rstate.EndpointUp || states[0].CurrentFlows != 1 {
		t.Fatalf("endpoint state = %+v, want up with one flow", states[0])
	}
}

func TestActiveDataSessionsCountsReverseSessionUnderConfiguredEndpointAddress(t *testing.T) {
	peer := testPeer()
	endpoint := peer.Endpoints[0]
	reverseKey := reverseDataSessionKey(peer.ID, endpoint, securetransport.EncryptionSecure)
	daemon := &Daemon{
		dataSessions: map[dataSessionKey]transport.Session{reverseKey: &recordingSession{}},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{
			reverseKey: {endpoint: endpoint},
		},
	}

	_, activeByEndpoint := daemon.activeDataSessions()
	key := endpointKey(peer.ID, endpoint)
	if activeByEndpoint[key] != 1 {
		t.Fatalf("active reverse sessions for endpoint = %d, want 1", activeByEndpoint[key])
	}
}

func TestDataPathMetricsSnapshotRecordsRoutePeerEndpointSends(t *testing.T) {
	daemon := &Daemon{
		flows: make(map[routing.FlowKey]routing.FlowBinding),
	}
	route := routing.Route{
		Prefix:   core.Prefix("10.0.1.0/24"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ep-1"),
		Policy:   core.PolicyID("default"),
		Kind:     routing.RouteUnicast,
	}
	decision := routing.Decision{Route: route, Prefix: netip.MustParsePrefix("10.0.1.0/24")}
	endpoint := testPeer().Endpoints[0]

	daemon.recordRouteHit(decision)
	daemon.recordRouteSend(decision, 128, nil)
	daemon.recordPeerSend(core.IXID("ix-b"), 128, nil)
	daemon.recordEndpointSend(core.IXID("ix-b"), endpoint, 128, nil)

	routes, peers, endpoints := daemon.dataPathMetricsSnapshot()
	if len(routes) != 1 || routes[0].Hits != 1 || routes[0].PacketsSent != 1 || routes[0].BytesSent != 128 {
		t.Fatalf("route stats = %#v", routes)
	}
	if len(peers) != 1 || peers[0].Peer != "ix-b" || peers[0].PacketsSent != 1 || peers[0].BytesSent != 128 {
		t.Fatalf("peer stats = %#v", peers)
	}
	if len(endpoints) != 1 || endpoints[0].Endpoint != "ep-1" || endpoints[0].PacketsSent != 1 || endpoints[0].BytesSent != 128 {
		t.Fatalf("endpoint stats = %#v", endpoints)
	}
}

func TestDataPathMetricsPrunesStaleRuntimeSnapshot(t *testing.T) {
	daemon := &Daemon{
		flows: make(map[routing.FlowKey]routing.FlowBinding),
	}
	keepRoute := routing.Route{
		Prefix:   core.Prefix("10.0.1.0/24"),
		NextHop:  core.IXID("ix-b"),
		Endpoint: core.EndpointID("ep-1"),
		Kind:     routing.RouteUnicast,
	}
	staleRoute := routing.Route{
		Prefix:   core.Prefix("10.0.2.0/24"),
		NextHop:  core.IXID("ix-old"),
		Endpoint: core.EndpointID("ep-old"),
		Kind:     routing.RouteUnicast,
	}
	keepEndpoint := config.EndpointConfig{Name: "ep-1", Address: "192.0.2.1:7001", Transport: "udp"}
	staleEndpoint := config.EndpointConfig{Name: "ep-old", Address: "192.0.2.99:7099", Transport: "udp"}

	daemon.recordSendMetrics(routing.Decision{Route: keepRoute}, "ix-b", keepEndpoint, 128, nil)
	daemon.recordSendMetrics(routing.Decision{Route: staleRoute}, "ix-old", staleEndpoint, 64, nil)
	daemon.pruneDataPathMetrics(dataplane.Snapshot{
		Routes: []routing.Route{keepRoute},
		Peers: []dataplane.PeerMetadata{{
			ID: core.IXID("ix-b"),
		}},
		Endpoints: []dataplane.EndpointMetadata{{
			ID:        core.EndpointID("ep-1"),
			Peer:      core.IXID("ix-b"),
			Transport: "udp",
			Address:   "192.0.2.1:7001",
			Enabled:   true,
		}},
	})

	routes, peers, endpoints := daemon.dataPathMetricsSnapshot()
	if len(routes) != 1 || routes[0].NextHop != "ix-b" || routes[0].BytesSent != 128 {
		t.Fatalf("route stats after prune = %#v", routes)
	}
	if len(peers) != 1 || peers[0].Peer != "ix-b" || peers[0].BytesSent != 128 {
		t.Fatalf("peer stats after prune = %#v", peers)
	}
	if len(endpoints) != 1 || endpoints[0].Endpoint != "ep-1" || endpoints[0].BytesSent != 128 {
		t.Fatalf("endpoint stats after prune = %#v", endpoints)
	}
}

func testPeer() config.PeerConfig {
	return config.PeerConfig{
		ID:     core.IXID("ix-b"),
		Domain: core.DomainID("lab.local"),
		Endpoints: []config.EndpointConfig{
			{Name: core.EndpointID("ep-1"), Address: "192.0.2.1:7001", Transport: "udp"},
			{Name: core.EndpointID("ep-2"), Address: "192.0.2.2:7002", Transport: "udp"},
		},
	}
}

type recordingInjector struct {
	packets      [][]byte
	batchPackets [][][]byte
}

func (injector *recordingInjector) InjectPacket(ctx context.Context, packet []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	injector.packets = append(injector.packets, append([]byte(nil), packet...))
	return nil
}

func (injector *recordingInjector) InjectPackets(ctx context.Context, packets [][]byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cloned := make([][]byte, 0, len(packets))
	for _, packet := range packets {
		cloned = append(cloned, append([]byte(nil), packet...))
	}
	injector.batchPackets = append(injector.batchPackets, cloned)
	return nil
}

type recordingGSOChecksumOffloadInjector struct {
	recordingInjector
	mtu int
}

func (injector *recordingGSOChecksumOffloadInjector) InjectBatchGSOChecksumOffloadMTU() int {
	return injector.mtu
}

type recordingLANInjector struct {
	dataplane.NoopManager
	packets      [][]byte
	destinations []netip.Addr
}

func (injector *recordingLANInjector) InjectLANPacket(ctx context.Context, packet []byte, destination netip.Addr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	injector.packets = append(injector.packets, append([]byte(nil), packet...))
	injector.destinations = append(injector.destinations, destination)
	return nil
}

type kernelTransportDataplane struct {
	*dataplane.NoopManager
	status dataplane.KernelTransportStatus
}

func (manager *kernelTransportDataplane) KernelTransportStatus(ctx context.Context) (dataplane.KernelTransportStatus, error) {
	if err := ctx.Err(); err != nil {
		return dataplane.KernelTransportStatus{}, err
	}
	return manager.status, nil
}

type recordingDataplane struct {
	*dataplane.NoopManager
	*recordingInjector
}

func (manager *recordingDataplane) InjectPacket(ctx context.Context, packet []byte) error {
	return manager.recordingInjector.InjectPacket(ctx, packet)
}

func (manager *recordingDataplane) InjectPackets(ctx context.Context, packets [][]byte) error {
	return manager.recordingInjector.InjectPackets(ctx, packets)
}

type recordingLocalPacketDataplane struct {
	*dataplane.NoopManager
	localPackets [][]byte
}

func (manager *recordingLocalPacketDataplane) InjectLocalPacket(ctx context.Context, packet []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	manager.localPackets = append(manager.localPackets, append([]byte(nil), packet...))
	return nil
}

type recordingSession struct {
	sent   [][]byte
	closed bool
	stats  transport.TransportStats
}

func (session *recordingSession) SendPacket(packet []byte) error {
	session.sent = append(session.sent, append([]byte(nil), packet...))
	return nil
}

func (session *recordingSession) RecvPacket() ([]byte, error) {
	return nil, fmt.Errorf("recording session has no packets")
}

func (session *recordingSession) Close() error {
	session.closed = true
	return nil
}

func (session *recordingSession) Stats() transport.TransportStats {
	return session.stats
}

type recordingNativeBatchSession struct {
	recordingSession
	batches [][][]byte
	stats   transport.TransportStats
}

func (session *recordingNativeBatchSession) SendPackets(packets [][]byte) error {
	cloned := make([][]byte, 0, len(packets))
	for _, packet := range packets {
		cloned = append(cloned, append([]byte(nil), packet...))
	}
	session.batches = append(session.batches, cloned)
	return nil
}

func (session *recordingNativeBatchSession) Stats() transport.TransportStats {
	stats := session.stats
	if !stats.NativeBatching && !stats.Encrypted && stats.CryptoPlacement == "" {
		stats.NativeBatching = true
	}
	return stats
}

type statsCountingNativeBatchSession struct {
	recordingNativeBatchSession
	stats      transport.TransportStats
	statsCalls int
}

func (session *statsCountingNativeBatchSession) Stats() transport.TransportStats {
	session.statsCalls++
	return session.stats
}

type errorSession struct {
	err    error
	closed int
}

func (session *errorSession) SendPacket(packet []byte) error {
	return nil
}

func (session *errorSession) RecvPacket() ([]byte, error) {
	return nil, session.err
}

func (session *errorSession) Close() error {
	session.closed++
	return nil
}

func (session *errorSession) Stats() transport.TransportStats {
	return transport.TransportStats{}
}

type batchRecvSession struct {
	batches [][][]byte
	err     error
	sent    [][]byte
	closed  bool
}

func (session *batchRecvSession) SendPacket(packet []byte) error {
	session.sent = append(session.sent, append([]byte(nil), packet...))
	return nil
}

func (session *batchRecvSession) RecvPacket() ([]byte, error) {
	packets, err := session.RecvPackets(1)
	if err != nil {
		return nil, err
	}
	if len(packets) == 0 {
		return nil, fmt.Errorf("batch recv session returned no packets")
	}
	return packets[0], nil
}

func (session *batchRecvSession) RecvPackets(max int) ([][]byte, error) {
	if len(session.batches) == 0 {
		if session.err != nil {
			return nil, session.err
		}
		return nil, fmt.Errorf("batch recv session has no packets")
	}
	batch := session.batches[0]
	session.batches = session.batches[1:]
	if max > 0 && len(batch) > max {
		rest := append([][]byte(nil), batch[max:]...)
		session.batches = append([][][]byte{rest}, session.batches...)
		batch = batch[:max]
	}
	out := make([][]byte, 0, len(batch))
	for _, packet := range batch {
		out = append(out, append([]byte(nil), packet...))
	}
	return out, nil
}

func (session *batchRecvSession) Close() error {
	session.closed = true
	return nil
}

func (session *batchRecvSession) Stats() transport.TransportStats {
	return transport.TransportStats{}
}

type identitySession struct {
	recordingSession
	peer   core.IXID
	domain core.DomainID
	err    error
	closed bool
}

func (session *identitySession) RecvPacket() ([]byte, error) {
	if session.err != nil {
		return nil, session.err
	}
	return nil, fmt.Errorf("identity session has no packets")
}

func (session *identitySession) Close() error {
	session.closed = true
	return nil
}

func (session *identitySession) PeerIdentity() (core.IXID, core.DomainID, bool) {
	return session.peer, session.domain, session.peer != "" || session.domain != ""
}

type deviceIdentitySession struct {
	recordingSession
	identity transport.PeerIdentity
	recv     chan struct{}
}

func (session *deviceIdentitySession) RecvPacket() ([]byte, error) {
	if session.recv == nil {
		return session.recordingSession.RecvPacket()
	}
	<-session.recv
	return nil, fmt.Errorf("device identity session closed")
}

func (session *deviceIdentitySession) Close() error {
	session.recordingSession.Close()
	if session.recv != nil {
		select {
		case <-session.recv:
		default:
			close(session.recv)
		}
	}
	return nil
}

func (session *deviceIdentitySession) PeerIdentity() (core.IXID, core.DomainID, bool) {
	return session.identity.Peer, session.identity.Domain, session.identity.Peer != "" || session.identity.Domain != ""
}

func (session *deviceIdentitySession) PeerIdentityDetail() (transport.PeerIdentity, bool) {
	return session.identity, session.identity.Role != "" || session.identity.Peer != "" || session.identity.Domain != "" || session.identity.Device != ""
}

type blockingIdentitySession struct {
	recordingSession
	peer   core.IXID
	domain core.DomainID
	recv   chan struct{}
}

func (session *blockingIdentitySession) RecvPacket() ([]byte, error) {
	if session.recv == nil {
		session.recv = make(chan struct{})
	}
	<-session.recv
	return nil, fmt.Errorf("blocking identity session closed")
}

func (session *blockingIdentitySession) Close() error {
	session.recordingSession.Close()
	if session.recv == nil {
		session.recv = make(chan struct{})
	}
	select {
	case <-session.recv:
	default:
		close(session.recv)
	}
	return nil
}

func (session *blockingIdentitySession) PeerIdentity() (core.IXID, core.DomainID, bool) {
	return session.peer, session.domain, session.peer != "" || session.domain != ""
}

type endpointAnnotatingIdentitySession struct {
	blockingIdentitySession
	annotatedPeer     core.IXID
	annotatedEndpoint core.EndpointID
}

func (session *endpointAnnotatingIdentitySession) SetPeerEndpoint(peer core.IXID, endpoint core.EndpointID) {
	session.annotatedPeer = peer
	session.annotatedEndpoint = endpoint
}

type fakeTransport struct {
	name transport.Protocol
}

func (fake fakeTransport) Name() transport.Protocol {
	return fake.name
}

func (fake fakeTransport) Probe(ctx context.Context, peer transport.Peer) transport.ProbeResult {
	return transport.ProbeResult{}
}

func (fake fakeTransport) Dial(ctx context.Context, peer transport.Peer, tlsConf *tls.Config) (transport.Session, error) {
	return nil, fmt.Errorf("unexpected fake transport dial")
}

func (fake fakeTransport) Listen(ctx context.Context, ep transport.Endpoint, tlsConf *tls.Config) (transport.Listener, error) {
	return nil, fmt.Errorf("unexpected fake transport listen")
}

type fakeTransportWithSessionStats struct {
	name  transport.Protocol
	stats transport.TransportStats
}

func (fake fakeTransportWithSessionStats) Name() transport.Protocol {
	return fake.name
}

func (fake fakeTransportWithSessionStats) Probe(ctx context.Context, peer transport.Peer) transport.ProbeResult {
	return transport.ProbeResult{}
}

func (fake fakeTransportWithSessionStats) Dial(ctx context.Context, peer transport.Peer, tlsConf *tls.Config) (transport.Session, error) {
	if len(peer.Endpoints) != 1 {
		return nil, fmt.Errorf("fake transport expected one endpoint, got %d", len(peer.Endpoints))
	}
	return &statsSession{stats: transport.TransportStats{
		Encryption:       peer.Endpoints[0].Encryption,
		Encrypted:        peer.Endpoints[0].Encryption != "plaintext",
		SendEncrypted:    peer.Endpoints[0].Encryption == "secure" || peer.Endpoints[0].Encryption == "send_encrypted",
		ReceiveEncrypted: peer.Endpoints[0].Encryption == "secure" || peer.Endpoints[0].Encryption == "receive_encrypted",
	}}, nil
}

func (fake fakeTransportWithSessionStats) Listen(ctx context.Context, ep transport.Endpoint, tlsConf *tls.Config) (transport.Listener, error) {
	return &statsListener{session: &statsSession{stats: fake.stats}}, nil
}

type flakyWarmupTransport struct {
	name transport.Protocol
	mu   sync.Mutex
	fail int
}

func (fake *flakyWarmupTransport) Name() transport.Protocol {
	return fake.name
}

func (fake *flakyWarmupTransport) Probe(ctx context.Context, peer transport.Peer) transport.ProbeResult {
	return transport.ProbeResult{}
}

func (fake *flakyWarmupTransport) Dial(ctx context.Context, peer transport.Peer, tlsConf *tls.Config) (transport.Session, error) {
	fake.mu.Lock()
	if fake.fail > 0 {
		fake.fail--
		fake.mu.Unlock()
		return nil, fmt.Errorf("temporary warmup failure")
	}
	fake.mu.Unlock()
	if len(peer.Endpoints) != 1 {
		return nil, fmt.Errorf("flaky warmup transport expected one endpoint, got %d", len(peer.Endpoints))
	}
	return &statsSession{stats: transport.TransportStats{
		Encryption:       peer.Endpoints[0].Encryption,
		Encrypted:        peer.Endpoints[0].Encryption != "plaintext",
		SendEncrypted:    peer.Endpoints[0].Encryption == "secure" || peer.Endpoints[0].Encryption == "send_encrypted",
		ReceiveEncrypted: peer.Endpoints[0].Encryption == "secure" || peer.Endpoints[0].Encryption == "receive_encrypted",
	}}, nil
}

func (fake *flakyWarmupTransport) Listen(ctx context.Context, ep transport.Endpoint, tlsConf *tls.Config) (transport.Listener, error) {
	return nil, fmt.Errorf("unexpected flaky warmup transport listen")
}

type retainingWarmupTransport struct {
	name transport.Protocol
}

func (fake *retainingWarmupTransport) Name() transport.Protocol {
	return fake.name
}

func (fake *retainingWarmupTransport) Probe(ctx context.Context, peer transport.Peer) transport.ProbeResult {
	return transport.ProbeResult{}
}

func (fake *retainingWarmupTransport) Dial(ctx context.Context, peer transport.Peer, tlsConf *tls.Config) (transport.Session, error) {
	if len(peer.Endpoints) != 1 {
		return nil, fmt.Errorf("retaining warmup transport expected one endpoint, got %d", len(peer.Endpoints))
	}
	return &retainingWarmupSession{statsSession: statsSession{stats: transport.TransportStats{
		Datagram:         true,
		Encryption:       peer.Endpoints[0].Encryption,
		Encrypted:        peer.Endpoints[0].Encryption != "plaintext",
		SendEncrypted:    peer.Endpoints[0].Encryption == "secure" || peer.Endpoints[0].Encryption == "send_encrypted",
		ReceiveEncrypted: peer.Endpoints[0].Encryption == "secure" || peer.Endpoints[0].Encryption == "receive_encrypted",
	}}}, nil
}

func (fake *retainingWarmupTransport) Listen(ctx context.Context, ep transport.Endpoint, tlsConf *tls.Config) (transport.Listener, error) {
	return nil, fmt.Errorf("unexpected retaining warmup transport listen")
}

type retainingWarmupSession struct {
	statsSession
	retained bool
}

func (session *retainingWarmupSession) RetainKernelFlowOnClose() {
	session.retained = true
}

type blockingWarmupTransport struct {
	name    transport.Protocol
	started chan struct{}
}

func (fake *blockingWarmupTransport) Name() transport.Protocol {
	return fake.name
}

func (fake *blockingWarmupTransport) Probe(ctx context.Context, peer transport.Peer) transport.ProbeResult {
	return transport.ProbeResult{}
}

func (fake *blockingWarmupTransport) Dial(ctx context.Context, peer transport.Peer, tlsConf *tls.Config) (transport.Session, error) {
	select {
	case fake.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (fake *blockingWarmupTransport) Listen(ctx context.Context, ep transport.Endpoint, tlsConf *tls.Config) (transport.Listener, error) {
	return nil, fmt.Errorf("unexpected blocking warmup transport listen")
}

type warmupKernelUDPDataplane struct {
	*dataplane.NoopManager
}

func (manager *warmupKernelUDPDataplane) KernelUDPStatus(ctx context.Context) (dataplane.KernelUDPStatus, error) {
	if err := ctx.Err(); err != nil {
		return dataplane.KernelUDPStatus{}, err
	}
	return dataplane.KernelUDPStatus{
		Available:       true,
		Provider:        "test",
		FastPath:        true,
		DirectOnly:      true,
		TCOnly:          true,
		UserspaceCrypto: true,
		Reinject:        false,
		PreferredCrypto: dataplane.CryptoPlacementUserspace,
		SupportedCrypto: []dataplane.CryptoPlacement{dataplane.CryptoPlacementUserspace},
	}, nil
}

func (manager *warmupKernelUDPDataplane) KernelTransportStatus(ctx context.Context) (dataplane.KernelTransportStatus, error) {
	if err := ctx.Err(); err != nil {
		return dataplane.KernelTransportStatus{}, err
	}
	return dataplane.KernelTransportStatus{
		Mode: dataplane.KernelTransportModeRequireKernel,
		Protocols: []dataplane.KernelTransportProtocol{{
			Protocol:  string(transport.ProtocolUDP),
			Available: true,
		}},
	}, nil
}

type recordingTLSTransport struct {
	name        transport.Protocol
	lastDialTLS *tls.Config
	session     transport.Session
	dialErr     error
	dialCount   int
}

func (transportImpl *recordingTLSTransport) Name() transport.Protocol {
	return transportImpl.name
}

func (transportImpl *recordingTLSTransport) Probe(ctx context.Context, peer transport.Peer) transport.ProbeResult {
	return transport.ProbeResult{}
}

func (transportImpl *recordingTLSTransport) Dial(ctx context.Context, peer transport.Peer, tlsConf *tls.Config) (transport.Session, error) {
	transportImpl.lastDialTLS = tlsConf
	transportImpl.dialCount++
	if len(peer.Endpoints) != 1 {
		return nil, fmt.Errorf("recording TLS transport expected one endpoint, got %d", len(peer.Endpoints))
	}
	if transportImpl.dialErr != nil {
		return nil, transportImpl.dialErr
	}
	if transportImpl.session != nil {
		return transportImpl.session, nil
	}
	return &statsSession{stats: transport.TransportStats{}}, nil
}

func (transportImpl *recordingTLSTransport) Listen(ctx context.Context, ep transport.Endpoint, tlsConf *tls.Config) (transport.Listener, error) {
	return &statsListener{session: &statsSession{}}, nil
}

type statsListener struct {
	session transport.Session
}

func (listener *statsListener) Accept(ctx context.Context) (transport.Session, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return listener.session, nil
	}
}

func (listener *statsListener) Close() error {
	return nil
}

type statsSession struct {
	stats  transport.TransportStats
	closed chan struct{}
}

func (session *statsSession) SendPacket(packet []byte) error {
	return nil
}

func (session *statsSession) RecvPacket() ([]byte, error) {
	if session.closed == nil {
		session.closed = make(chan struct{})
	}
	<-session.closed
	return nil, fmt.Errorf("stats session closed")
}

func (session *statsSession) Close() error {
	if session.closed == nil {
		session.closed = make(chan struct{})
	}
	select {
	case <-session.closed:
	default:
		close(session.closed)
	}
	return nil
}

func (session *statsSession) Stats() transport.TransportStats {
	return session.stats
}

func tcpIPv4Packet() []byte {
	packet := make([]byte, 40)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[9] = 6
	copy(packet[12:16], []byte{10, 0, 0, 2})
	copy(packet[16:20], []byte{10, 0, 1, 2})
	binary.BigEndian.PutUint16(packet[20:22], 12345)
	binary.BigEndian.PutUint16(packet[22:24], 443)
	return packet
}

func udpIPv4Packet(payload []byte) []byte {
	packet := make([]byte, 20+8+len(payload))
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = ipProtocolUDP
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], []byte{10, 0, 0, 2})
	copy(packet[16:20], []byte{10, 0, 1, 2})
	udp := packet[20:]
	binary.BigEndian.PutUint16(udp[0:2], 12345)
	binary.BigEndian.PutUint16(udp[2:4], 18100)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	binary.BigEndian.PutUint16(udp[6:8], 0x1234)
	copy(udp[8:], payload)
	return packet
}

func icmpEchoIPv4Packet(payload []byte) []byte {
	packet := make([]byte, 20+8+len(payload))
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = ipProtocolICMP
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], []byte{10, 0, 0, 2})
	copy(packet[16:20], []byte{10, 0, 1, 2})
	icmp := packet[20:]
	icmp[0] = 8
	binary.BigEndian.PutUint16(icmp[2:4], 0x1234)
	binary.BigEndian.PutUint16(icmp[4:6], 1)
	binary.BigEndian.PutUint16(icmp[6:8], 1)
	copy(icmp[8:], payload)
	return packet
}

func tcpPayloadIPv4Packet(payload []byte) []byte {
	return tcpPayloadIPv4PacketWithSeq(0, payload)
}

func tcpPayloadIPv4PacketWithSeq(seq uint32, payload []byte) []byte {
	return tcpPayloadIPv4PacketWithSeqAndPorts(seq, 12345, 18200, payload)
}

func tcpPayloadIPv4PacketWithSeqAndPorts(seq uint32, sourcePort uint16, destinationPort uint16, payload []byte) []byte {
	packet := make([]byte, 20+20+len(payload))
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = ipProtocolTCP
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], []byte{10, 0, 0, 2})
	copy(packet[16:20], []byte{10, 0, 1, 2})
	tcp := packet[20:]
	binary.BigEndian.PutUint16(tcp[0:2], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], destinationPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	tcp[12] = 5 << 4
	tcp[13] = 0x18
	binary.BigEndian.PutUint16(tcp[14:16], 0xffff)
	copy(tcp[20:], payload)
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:20]))
	binary.BigEndian.PutUint16(tcp[16:18], transportChecksum(packet[12:16], packet[16:20], ipProtocolTCP, tcp))
	return packet
}

func tcpPayloadIPv4PacketWithSeqAndTimestamp(seq uint32, ts uint32, payload []byte) []byte {
	packet := make([]byte, 20+32+len(payload))
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = ipProtocolTCP
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], []byte{10, 0, 0, 2})
	copy(packet[16:20], []byte{10, 0, 1, 2})
	tcp := packet[20:]
	binary.BigEndian.PutUint16(tcp[0:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], 18200)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	tcp[12] = 8 << 4
	tcp[13] = 0x18
	binary.BigEndian.PutUint16(tcp[14:16], 0xffff)
	tcp[20] = 1
	tcp[21] = 1
	tcp[22] = 8
	tcp[23] = 10
	binary.BigEndian.PutUint32(tcp[24:28], ts)
	binary.BigEndian.PutUint32(tcp[28:32], 50)
	copy(tcp[32:], payload)
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:20]))
	binary.BigEndian.PutUint16(tcp[16:18], transportChecksum(packet[12:16], packet[16:20], ipProtocolTCP, tcp))
	return packet
}

func tcpSYNIPv4PacketWithMSS(mss uint16) []byte {
	packet := make([]byte, 20+24)
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = ipProtocolTCP
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], []byte{10, 0, 0, 2})
	copy(packet[16:20], []byte{10, 0, 1, 2})
	tcp := packet[20:]
	binary.BigEndian.PutUint16(tcp[0:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], 18200)
	tcp[12] = 6 << 4
	tcp[13] = tcpFlagSYN
	binary.BigEndian.PutUint16(tcp[14:16], 0xffff)
	tcp[20] = tcpOptionMSS
	tcp[21] = 4
	binary.BigEndian.PutUint16(tcp[22:24], mss)
	return packet
}

func tcpMSSOptionValue(t *testing.T, tcp []byte) uint16 {
	t.Helper()
	tcpHeaderLen := int(tcp[12]>>4) * 4
	if tcpHeaderLen > len(tcp) {
		t.Fatalf("tcp header len = %d exceeds packet %d", tcpHeaderLen, len(tcp))
	}
	options := tcp[20:tcpHeaderLen]
	for i := 0; i < len(options); {
		kind := options[i]
		switch kind {
		case 0:
			break
		case 1:
			i++
			continue
		}
		if i+1 >= len(options) {
			t.Fatalf("short TCP option at %d", i)
		}
		length := int(options[i+1])
		if length < 2 || i+length > len(options) {
			t.Fatalf("invalid TCP option length %d at %d", length, i)
		}
		if kind == tcpOptionMSS && length == 4 {
			return binary.BigEndian.Uint16(options[i+2 : i+4])
		}
		i += length
	}
	t.Fatal("MSS option not found")
	return 0
}

func ethernetIPv4Frame(ip []byte) []byte {
	frame := make([]byte, 14+len(ip))
	binary.BigEndian.PutUint16(frame[12:14], ethPIPv4)
	copy(frame[14:], ip)
	return frame
}

func validTransportChecksumForTest(ip []byte, segment []byte) bool {
	sum := checksumAddBytes(0, ip[12:16])
	sum = checksumAddBytes(sum, ip[16:20])
	sum = checksumAddBytes(sum, []byte{0, ip[9], byte(len(segment) >> 8), byte(len(segment))})
	sum = checksumAddBytes(sum, segment)
	return checksumFold(sum) == 0
}
