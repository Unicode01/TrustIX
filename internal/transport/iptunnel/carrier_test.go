package iptunnel

import (
	"bytes"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"trustix.local/trustix/internal/transport"
)

func TestParseTunnelConfig(t *testing.T) {
	cfg, err := parseTunnelConfig("local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.0.1/30,remote_carrier=10.255.0.2,port=47820")
	if err != nil {
		t.Fatalf("parse tunnel config: %v", err)
	}
	if cfg.LocalUnderlay.String() != "198.18.0.1" || cfg.RemoteUnderlay.String() != "198.18.0.2" {
		t.Fatalf("underlay = %s/%s", cfg.LocalUnderlay, cfg.RemoteUnderlay)
	}
	if cfg.LocalCarrier.String() != "10.255.0.1/30" || cfg.RemoteCarrier.String() != "10.255.0.2" {
		t.Fatalf("carrier = %s/%s", cfg.LocalCarrier, cfg.RemoteCarrier)
	}
	if cfg.CarrierPort != 47820 {
		t.Fatalf("carrier port = %d, want 47820", cfg.CarrierPort)
	}
	if cfg.MTU != defaultTunnelMTU {
		t.Fatalf("mtu = %d, want default %d", cfg.MTU, defaultTunnelMTU)
	}
}

func TestParseTunnelConfigAcceptsMTU(t *testing.T) {
	cfg, err := parseTunnelConfig("local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.0.1/30,remote_carrier=10.255.0.2,mtu=1300")
	if err != nil {
		t.Fatalf("parse tunnel config: %v", err)
	}
	if cfg.MTU != 1300 {
		t.Fatalf("mtu = %d, want 1300", cfg.MTU)
	}
}

func TestNormalizeTunnelConfigFillsDefaults(t *testing.T) {
	got := normalizeTunnelConfig("gre://remote=198.18.0.2, local_carrier=10.255.0.1/30, local=198.18.0.1, remote_carrier=10.255.0.2")
	want := "local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.0.1/30,remote_carrier=10.255.0.2,port=47819,mtu=1400"
	if got != want {
		t.Fatalf("normalized config = %q, want %q", got, want)
	}
}

func TestNormalizeTunnelConfigIncludesQueues(t *testing.T) {
	got := normalizeTunnelConfig("ipip://remote=198.18.0.2, local_carrier=10.255.0.1/30, local=198.18.0.1, remote_carrier=10.255.0.2,queues=4")
	want := "local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.0.1/30,remote_carrier=10.255.0.2,port=47819,mtu=1400,queues=4"
	if got != want {
		t.Fatalf("normalized config = %q, want %q", got, want)
	}
}

func TestNormalizeVXLANConfigFillsDefaultVNI(t *testing.T) {
	got := NormalizeKernelTunnelConfig(transport.ProtocolVXLAN, "vxlan://remote=198.18.0.2,local_carrier=10.255.0.1/30,local=198.18.0.1,remote_carrier=10.255.0.2,port=4789")
	want := "local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.0.1/30,remote_carrier=10.255.0.2,port=4789,mtu=1400,vni=5527625,vxlan_port=4789"
	if got != want {
		t.Fatalf("normalized vxlan config = %q, want %q", got, want)
	}
}

func TestParseVXLANConfigAcceptsOuterHashOptions(t *testing.T) {
	cfg, err := parseTunnelConfig("local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.0.1/30,remote_carrier=10.255.0.2,src_port=32768-60999,queues=8,udp_checksum=false")
	if err != nil {
		t.Fatalf("parse vxlan config: %v", err)
	}
	if cfg.VXLANPortLow != 32768 || cfg.VXLANPortHigh != 60999 {
		t.Fatalf("vxlan source port range = %d-%d, want 32768-60999", cfg.VXLANPortLow, cfg.VXLANPortHigh)
	}
	if cfg.Queues != 8 {
		t.Fatalf("queues = %d, want 8", cfg.Queues)
	}
	if cfg.VXLANUDPCSum {
		t.Fatal("VXLAN UDP checksum = true, want false")
	}
}

func TestNormalizeVXLANConfigIncludesOuterHashOptions(t *testing.T) {
	got := NormalizeKernelTunnelConfig(transport.ProtocolVXLAN, "vxlan://remote=198.18.0.2,local_carrier=10.255.0.1/30,local=198.18.0.1,remote_carrier=10.255.0.2,src_port_low=32768,src_port_high=60999,queues=8,udp_checksum=false")
	want := "local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.0.1/30,remote_carrier=10.255.0.2,port=47819,mtu=1400,vni=5527625,vxlan_port=4789,src_port_low=32768,src_port_high=60999,queues=8,udp_checksum=false"
	if got != want {
		t.Fatalf("normalized vxlan config = %q, want %q", got, want)
	}
}

func TestNormalizeVXLANConfigIncludesUnderlayInterface(t *testing.T) {
	got := NormalizeKernelTunnelConfig(transport.ProtocolVXLAN, "vxlan://remote=198.18.0.2,local_carrier=10.255.0.1/30,local=198.18.0.1,remote_carrier=10.255.0.2,underlay_if=tix216ula")
	want := "local=198.18.0.1,remote=198.18.0.2,underlay_if=tix216ula,local_carrier=10.255.0.1/30,remote_carrier=10.255.0.2,port=47819,mtu=1400,vni=5527625,vxlan_port=4789"
	if got != want {
		t.Fatalf("normalized vxlan config = %q, want %q", got, want)
	}
}

func TestReverseKernelTunnelConfigSwapsEndpointPerspective(t *testing.T) {
	got, err := ReverseKernelTunnelConfig(transport.ProtocolGRE, "remote=198.18.0.2,local=198.18.0.1,local_carrier=10.255.0.1/30,remote_carrier=10.255.0.2,mtu=1476")
	if err != nil {
		t.Fatalf("reverse tunnel config: %v", err)
	}
	want := "local=198.18.0.2,remote=198.18.0.1,local_carrier=10.255.0.2/30,remote_carrier=10.255.0.1,port=47819,mtu=1476"
	if got != want {
		t.Fatalf("reversed tunnel config = %q, want %q", got, want)
	}
}

func TestReverseKernelTunnelConfigPreservesVXLANOptions(t *testing.T) {
	got, err := ReverseKernelTunnelConfig(transport.ProtocolVXLAN, "remote=198.18.0.2,local=198.18.0.1,underlay_if=tix216ula,local_carrier=10.255.0.1/30,remote_carrier=10.255.0.2,port=47820,mtu=1450,vni=7,vxlan_port=4790,src_port=32768-60999,queues=4,udp_checksum=false")
	if err != nil {
		t.Fatalf("reverse vxlan tunnel config: %v", err)
	}
	want := "local=198.18.0.2,remote=198.18.0.1,underlay_if=tix216ula,local_carrier=10.255.0.2/30,remote_carrier=10.255.0.1,port=47820,mtu=1450,vni=7,vxlan_port=4790,src_port_low=32768,src_port_high=60999,queues=4,udp_checksum=false"
	if got != want {
		t.Fatalf("reversed vxlan config = %q, want %q", got, want)
	}
}

func TestReverseKernelTunnelConfigCanOverrideUnderlayInterface(t *testing.T) {
	got, err := ReverseKernelTunnelConfig(transport.ProtocolVXLAN, "remote=198.18.0.2,local=198.18.0.1,underlay_if=remote0,local_carrier=10.255.0.1/30,remote_carrier=10.255.0.2", "local0")
	if err != nil {
		t.Fatalf("reverse vxlan tunnel config: %v", err)
	}
	if !strings.Contains(got, "underlay_if=local0") {
		t.Fatalf("reversed vxlan config = %q, want local underlay interface", got)
	}
	if strings.Contains(got, "underlay_if=remote0") {
		t.Fatalf("reversed vxlan config kept remote underlay interface: %q", got)
	}
}

func TestParseTunnelConfigRejectsInvalidMTU(t *testing.T) {
	if _, err := parseTunnelConfig("local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.0.1/30,remote_carrier=10.255.0.2,mtu=8"); err == nil {
		t.Fatal("expected invalid mtu to fail")
	}
}

func TestParseTunnelConfigRequiresExplicitCarrier(t *testing.T) {
	if _, err := parseTunnelConfig("local=198.18.0.1,remote=198.18.0.2"); err == nil {
		t.Fatal("expected missing carrier config to fail")
	}
}

func TestParseTunnelConfigRejectsInvalidUnderlayInterface(t *testing.T) {
	if _, err := parseTunnelConfig("local=198.18.0.1,remote=198.18.0.2,underlay_if=bad/name,local_carrier=10.255.0.1/30,remote_carrier=10.255.0.2"); err == nil {
		t.Fatal("expected invalid underlay interface to fail")
	}
}

func TestCarrierEncodeDecode(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 4096)
	wire, err := encodeCarrier(payload, 99)
	if err != nil {
		t.Fatalf("encode carrier: %v", err)
	}
	got, seq, err := decodeCarrier(wire)
	if err != nil {
		t.Fatalf("decode carrier: %v", err)
	}
	if seq != 99 {
		t.Fatalf("sequence = %d, want 99", seq)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch len=%d want=%d", len(got), len(payload))
	}
}

func TestCarrierDecodeRejectsInvalidHeader(t *testing.T) {
	if _, _, err := decodeCarrier([]byte("not-a-trustix-carrier")); err == nil {
		t.Fatal("expected invalid carrier header to fail")
	}
}

func TestCarrierRecvSkipsInvalidHeader(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer server.Close()
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("not-a-trustix-carrier")); err != nil {
		t.Fatalf("write invalid carrier packet: %v", err)
	}
	wire, err := encodeCarrier([]byte("ok"), 1)
	if err != nil {
		t.Fatalf("encode carrier: %v", err)
	}
	if _, err := client.Write(wire); err != nil {
		t.Fatalf("write carrier packet: %v", err)
	}
	packets, _, release, err := readCarrierBatchLoop(server, 1, 128)
	if err != nil {
		t.Fatalf("read carrier batch: %v", err)
	}
	defer release()
	if len(packets) != 1 || string(packets[0].payload) != "ok" {
		t.Fatalf("packets = %+v, want ok", packets)
	}
}

func TestCarrierSendStatsCountOnlySuccessfulWrites(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer server.Close()

	clientConn, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer clientConn.Close()

	session := &carrier{
		cfg: tunnelConfig{
			LocalCarrier:  netip.MustParsePrefix("127.0.0.1/32"),
			RemoteCarrier: netip.MustParseAddr("127.0.0.1"),
			CarrierPort:   uint16(server.LocalAddr().(*net.UDPAddr).Port),
		},
		conn: clientConn,
	}
	if err := session.SendPacket(bytes.Repeat([]byte("x"), carrierMaxPacket+1)); err == nil {
		t.Fatal("expected oversized packet to fail")
	}
	if stats := session.Stats(); stats.PacketsSent != 0 || stats.BytesSent != 0 {
		t.Fatalf("stats after failed send = %+v, want zero packets/bytes", stats)
	}
	if err := session.SendPacket([]byte("ok")); err != nil {
		t.Fatalf("send packet: %v", err)
	}
	stats := session.Stats()
	if stats.PacketsSent != 1 || stats.BytesSent == 0 {
		t.Fatalf("stats after send = %+v, want one packet and nonzero bytes", stats)
	}
}

func TestCarrierSendPacketsWritesBatchAndStats(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer server.Close()

	clientConn, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer clientConn.Close()

	session := &carrier{
		cfg: tunnelConfig{
			LocalCarrier:  netip.MustParsePrefix("127.0.0.1/32"),
			RemoteCarrier: netip.MustParseAddr("127.0.0.1"),
			CarrierPort:   uint16(server.LocalAddr().(*net.UDPAddr).Port),
		},
		conn: clientConn,
	}
	packets := [][]byte{[]byte("one"), []byte("two"), []byte("three")}
	if err := session.SendPackets(packets); err != nil {
		t.Fatalf("send packet batch: %v", err)
	}
	for i, want := range packets {
		buf := make([]byte, 128)
		n, _, err := server.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("read packet %d: %v", i, err)
		}
		got, seq, err := decodeCarrier(buf[:n])
		if err != nil {
			t.Fatalf("decode packet %d: %v", i, err)
		}
		if seq != uint64(i+1) || !bytes.Equal(got, want) {
			t.Fatalf("packet %d seq/payload = %d/%q, want %d/%q", i, seq, got, i+1, want)
		}
	}
	stats := session.Stats()
	if !stats.NativeBatching {
		t.Fatal("NativeBatching = false, want true")
	}
	if stats.PacketsSent != uint64(len(packets)) || stats.BytesSent == 0 {
		t.Fatalf("stats after batch send = %+v, want %d packets and nonzero bytes", stats, len(packets))
	}
	if stats.Extra["iptunnel_send_batch_calls"] != 1 {
		t.Fatalf("batch calls = %d, want 1", stats.Extra["iptunnel_send_batch_calls"])
	}
	if stats.Extra["iptunnel_send_batch_packets"] != uint64(len(packets)) {
		t.Fatalf("batch packets = %d, want %d", stats.Extra["iptunnel_send_batch_packets"], len(packets))
	}
	if stats.Extra["iptunnel_send_batch_bytes"] != stats.BytesSent {
		t.Fatalf("batch bytes = %d, want bytes sent %d", stats.Extra["iptunnel_send_batch_bytes"], stats.BytesSent)
	}
}

func TestCarrierStatsAdvertisesFragmentingDatagram(t *testing.T) {
	session := &carrier{cfg: tunnelConfig{MTU: 128, CarrierPort: 47820}}
	stats := session.Stats()
	if !stats.Datagram || !stats.FragmentingDatagram {
		t.Fatalf("stats datagram/fragmenting = %v/%v, want true/true", stats.Datagram, stats.FragmentingDatagram)
	}
	if stats.MaxPacketSize != carrierMaxPacket {
		t.Fatalf("MaxPacketSize = %d, want %d", stats.MaxPacketSize, carrierMaxPacket)
	}
	if got := stats.Extra["iptunnel_kernel_fragment"]; got != 1 {
		t.Fatalf("kernel fragment = %d, want 1", got)
	}
	if got, want := stats.Extra["iptunnel_fragment_payload_size"], uint64(carrierMaxUDPPayload-carrierHeaderLen-carrierFragmentHeaderLen); got != want {
		t.Fatalf("fragment payload size = %d, want %d", got, want)
	}
}

func TestCarrierVXLANDefaultsToApplicationFragmentsWithinL3MTU(t *testing.T) {
	t.Setenv("TRUSTIX_IPTUNNEL_KERNEL_FRAGMENT", "")
	const mtu = 1400
	session := &carrier{cfg: tunnelConfig{
		Protocol:    transport.ProtocolVXLAN,
		MTU:         mtu,
		CarrierPort: 47820,
	}}
	stats := session.Stats()
	if got := stats.Extra["iptunnel_kernel_fragment"]; got != 0 {
		t.Fatalf("VXLAN kernel fragment = %d, want 0", got)
	}
	if got, want := stats.Extra["iptunnel_udp_payload_size"], uint64(mtu-carrierIPv4UDPHeaderLen); got != want {
		t.Fatalf("VXLAN UDP payload size = %d, want %d", got, want)
	}
	if got, want := stats.Extra["iptunnel_wire_max_packet_size"], uint64(mtu-carrierIPv4UDPHeaderLen-carrierHeaderLen); got != want {
		t.Fatalf("VXLAN max packet size = %d, want %d", got, want)
	}
	if got, want := stats.Extra["iptunnel_fragment_payload_size"], uint64(mtu-carrierIPv4UDPHeaderLen-carrierHeaderLen-carrierFragmentHeaderLen); got != want {
		t.Fatalf("VXLAN fragment payload size = %d, want %d", got, want)
	}
	if got := int(stats.Extra["iptunnel_udp_payload_size"]) + carrierIPv4UDPHeaderLen; got > mtu {
		t.Fatalf("VXLAN carrier datagram L3 size = %d, exceeds tunnel MTU %d", got, mtu)
	}
}

func TestCarrierVXLANKernelFragmentExplicitOverride(t *testing.T) {
	t.Setenv("TRUSTIX_IPTUNNEL_KERNEL_FRAGMENT", "1")
	session := &carrier{cfg: tunnelConfig{Protocol: transport.ProtocolVXLAN, MTU: 1400}}
	if got := session.Stats().Extra["iptunnel_kernel_fragment"]; got != 1 {
		t.Fatalf("VXLAN explicit kernel fragment = %d, want 1", got)
	}
}

func TestCarrierVXLANReceivesLegacyLargeDatagramDuringRollingUpgrade(t *testing.T) {
	t.Setenv("TRUSTIX_IPTUNNEL_KERNEL_FRAGMENT", "")
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer server.Close()
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer client.Close()

	sender := &carrier{cfg: tunnelConfig{MTU: 1400}, conn: client}
	receiver := &carrier{cfg: tunnelConfig{Protocol: transport.ProtocolVXLAN, MTU: 1400}, conn: server}
	payload := bytes.Repeat([]byte("u"), 4096)
	if err := sender.SendPacket(payload); err != nil {
		t.Fatalf("send legacy large datagram: %v", err)
	}
	if got := sender.Stats().Extra["iptunnel_fragmented_packets_sent"]; got != 0 {
		t.Fatalf("legacy sender application fragments = %d, want 0", got)
	}
	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	packet, err := receiver.RecvPacket()
	if err != nil {
		t.Fatalf("receive legacy large datagram: %v", err)
	}
	if !bytes.Equal(packet, payload) {
		t.Fatalf("received payload length = %d, want %d", len(packet), len(payload))
	}
}

func TestCarrierSendPacketFragmentsAboveMTU(t *testing.T) {
	t.Setenv("TRUSTIX_IPTUNNEL_KERNEL_FRAGMENT", "0")
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer server.Close()

	clientConn, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer clientConn.Close()

	session := &carrier{
		cfg:  tunnelConfig{MTU: 128},
		conn: clientConn,
	}
	payload := bytes.Repeat([]byte("z"), 4096)
	if err := session.SendPacket(payload); err != nil {
		t.Fatalf("send fragmented packet: %v", err)
	}
	stats := session.Stats()
	if stats.PacketsSent != 1 {
		t.Fatalf("PacketsSent = %d, want 1", stats.PacketsSent)
	}
	if stats.Extra["iptunnel_fragmented_packets_sent"] != 1 {
		t.Fatalf("fragmented packets sent = %d, want 1", stats.Extra["iptunnel_fragmented_packets_sent"])
	}
	if stats.Extra["iptunnel_fragments_sent"] <= 1 {
		t.Fatalf("fragments sent = %d, want > 1", stats.Extra["iptunnel_fragments_sent"])
	}

	var reassembler carrierReassembler
	var got carrierReceivedPacket
	deadline := time.Now().Add(2 * time.Second)
	if err := server.SetReadDeadline(deadline); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 256)
	for {
		n, _, err := server.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("read fragment: %v", err)
		}
		frame, err := decodeCarrierFrameView(buf[:n])
		if err != nil {
			t.Fatalf("decode fragment: %v", err)
		}
		frame.wireLen = n
		var ok bool
		got, ok, _ = reassembler.accept(frame)
		if ok {
			break
		}
	}
	if !bytes.Equal(got.payload, payload) {
		t.Fatalf("reassembled payload length = %d, want %d", len(got.payload), len(payload))
	}
}

func TestCarrierRecvPacketsWithReleaseReassemblesFragments(t *testing.T) {
	t.Setenv("TRUSTIX_IPTUNNEL_KERNEL_FRAGMENT", "0")
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer server.Close()

	clientConn, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer clientConn.Close()

	sender := &carrier{cfg: tunnelConfig{MTU: 128}, conn: clientConn}
	receiver := &carrier{cfg: tunnelConfig{MTU: 128}, conn: server}
	payload := bytes.Repeat([]byte("r"), 4096)
	if err := sender.SendPacket(payload); err != nil {
		t.Fatalf("send fragmented packet: %v", err)
	}
	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	packets, release, err := receiver.RecvPacketsWithRelease(64)
	if err != nil {
		t.Fatalf("receive fragmented packet: %v", err)
	}
	defer release()
	if len(packets) != 1 || !bytes.Equal(packets[0], payload) {
		t.Fatalf("received packets = %d len=%d, want one len=%d", len(packets), len(packets[0]), len(payload))
	}
	stats := receiver.Stats()
	if stats.PacketsReceived != 1 {
		t.Fatalf("PacketsReceived = %d, want 1", stats.PacketsReceived)
	}
	if stats.Extra["iptunnel_reassembled_packets"] != 1 {
		t.Fatalf("reassembled packets = %d, want 1", stats.Extra["iptunnel_reassembled_packets"])
	}
}

func TestCarrierServerSessionSendPacketsWritesBatchAndStats(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp server: %v", err)
	}
	defer server.Close()

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp client: %v", err)
	}
	defer client.Close()

	session := &carrierServerSession{
		conn:     server,
		remote:   client.LocalAddr().(*net.UDPAddr),
		listener: &packetListener{cfg: tunnelConfig{MTU: defaultTunnelMTU}},
	}
	packets := [][]byte{[]byte("alpha"), []byte("bravo"), []byte("charlie")}
	if err := session.SendPackets(packets); err != nil {
		t.Fatalf("send server packet batch: %v", err)
	}
	for i, want := range packets {
		buf := make([]byte, 128)
		n, _, err := client.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("read packet %d: %v", i, err)
		}
		got, seq, err := decodeCarrier(buf[:n])
		if err != nil {
			t.Fatalf("decode packet %d: %v", i, err)
		}
		if seq != uint64(i+1) || !bytes.Equal(got, want) {
			t.Fatalf("packet %d seq/payload = %d/%q, want %d/%q", i, seq, got, i+1, want)
		}
	}
	stats := session.Stats()
	if !stats.NativeBatching {
		t.Fatal("NativeBatching = false, want true")
	}
	if stats.PacketsSent != uint64(len(packets)) || stats.BytesSent == 0 {
		t.Fatalf("stats after server batch send = %+v, want %d packets and nonzero bytes", stats, len(packets))
	}
	if stats.Extra["iptunnel_send_batch_calls"] != 1 {
		t.Fatalf("server batch calls = %d, want 1", stats.Extra["iptunnel_send_batch_calls"])
	}
	if stats.Extra["iptunnel_send_batch_packets"] != uint64(len(packets)) {
		t.Fatalf("server batch packets = %d, want %d", stats.Extra["iptunnel_send_batch_packets"], len(packets))
	}
	if stats.Extra["iptunnel_send_batch_bytes"] != stats.BytesSent {
		t.Fatalf("server batch bytes = %d, want bytes sent %d", stats.Extra["iptunnel_send_batch_bytes"], stats.BytesSent)
	}
}

func TestCarrierServerSessionSendPacketFragmentsAboveMTU(t *testing.T) {
	t.Setenv("TRUSTIX_IPTUNNEL_KERNEL_FRAGMENT", "0")
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp server: %v", err)
	}
	defer server.Close()

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp client: %v", err)
	}
	defer client.Close()

	session := &carrierServerSession{
		conn:     server,
		remote:   client.LocalAddr().(*net.UDPAddr),
		listener: &packetListener{cfg: tunnelConfig{MTU: 128}},
	}
	payload := bytes.Repeat([]byte("s"), 4096)
	if err := session.SendPacket(payload); err != nil {
		t.Fatalf("send fragmented server packet: %v", err)
	}
	stats := session.Stats()
	if stats.Extra["iptunnel_fragmented_packets_sent"] != 1 {
		t.Fatalf("fragmented packets sent = %d, want 1", stats.Extra["iptunnel_fragmented_packets_sent"])
	}
	if stats.Extra["iptunnel_fragments_sent"] <= 1 {
		t.Fatalf("fragments sent = %d, want > 1", stats.Extra["iptunnel_fragments_sent"])
	}

	var reassembler carrierReassembler
	var got carrierReceivedPacket
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 256)
	for {
		n, _, err := client.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("read fragment: %v", err)
		}
		frame, err := decodeCarrierFrameView(buf[:n])
		if err != nil {
			t.Fatalf("decode fragment: %v", err)
		}
		frame.wireLen = n
		var ok bool
		got, ok, _ = reassembler.accept(frame)
		if ok {
			break
		}
	}
	if !bytes.Equal(got.payload, payload) {
		t.Fatalf("reassembled payload length = %d, want %d", len(got.payload), len(payload))
	}
}

func TestCarrierServerSessionEnqueueReassemblesFragments(t *testing.T) {
	t.Setenv("TRUSTIX_IPTUNNEL_KERNEL_FRAGMENT", "0")
	session := &carrierServerSession{
		in:       make(chan carrierReceivedPacket, 8),
		listener: &packetListener{cfg: tunnelConfig{MTU: 128}},
	}
	payload := bytes.Repeat([]byte("q"), 4096)
	packets, headers, err := buildCarrierFragmentPackets(nil, nil, payload, 77, 128)
	if err != nil {
		t.Fatalf("build fragments: %v", err)
	}
	defer func() {
		_ = headers
		session.closeInput()
	}()
	for _, packet := range packets {
		wire, err := carrierBatchPacketWire(packet)
		if err != nil {
			t.Fatalf("build wire: %v", err)
		}
		buffer := takeCarrierReadBuffer(len(wire))
		copy(buffer.data, wire)
		frame, err := decodeCarrierFrameView(buffer.data[:len(wire)])
		if err != nil {
			t.Fatalf("decode fragment: %v", err)
		}
		frame.buffer = buffer
		frame.wireLen = len(wire)
		session.enqueue(frame)
	}
	received, release, err := session.RecvPacketsWithRelease(1)
	if err != nil {
		t.Fatalf("receive reassembled packet: %v", err)
	}
	defer release()
	if len(received) != 1 || !bytes.Equal(received[0], payload) {
		t.Fatalf("received packets = %d len=%d, want one len=%d", len(received), len(received[0]), len(payload))
	}
	stats := session.Stats()
	if stats.Extra["iptunnel_reassembled_packets"] != 1 {
		t.Fatalf("reassembled packets = %d, want 1", stats.Extra["iptunnel_reassembled_packets"])
	}
}

func TestCarrierSendRejectsPacketsAboveMTU(t *testing.T) {
	t.Setenv("TRUSTIX_IPTUNNEL_KERNEL_FRAGMENT", "0")
	session := &carrier{cfg: tunnelConfig{MTU: carrierHeaderLen + 4}}
	if err := session.SendPacket([]byte("12345")); err == nil {
		t.Fatal("expected packet above carrier mtu to fail")
	}
	if got := session.Stats().Extra["iptunnel_mtu_drops"]; got != 1 {
		t.Fatalf("mtu drops = %d, want 1", got)
	}
}

func TestCarrierServerSessionStatsTrackQueueDrops(t *testing.T) {
	listener := &packetListener{cfg: tunnelConfig{MTU: defaultTunnelMTU}}
	session := &carrierServerSession{
		in:       make(chan carrierReceivedPacket, 1),
		listener: listener,
	}
	session.enqueue(carrierReceivedPacket{payload: []byte("one"), wireLen: 10, buffer: takeCarrierReadBuffer()})
	session.enqueue(carrierReceivedPacket{payload: []byte("two"), wireLen: 10, buffer: takeCarrierReadBuffer()})
	defer session.closeInput()
	stats := session.Stats()
	if stats.BytesReceived != 0 {
		t.Fatalf("bytes received before consume = %d, want 0", stats.BytesReceived)
	}
	if stats.Extra["iptunnel_packets_dropped"] != 1 {
		t.Fatalf("drop stats = %+v, want one queue drop", stats.Extra)
	}
	packets, release, err := session.RecvPacketsWithRelease(1)
	if err != nil {
		t.Fatalf("receive packet: %v", err)
	}
	if len(packets) != 1 || !bytes.Equal(packets[0], []byte("one")) {
		t.Fatalf("received packets = %q, want one", packets)
	}
	release()
	stats = session.Stats()
	if stats.BytesReceived != 10 || stats.PacketsReceived != 1 {
		t.Fatalf("stats after receive = %+v, want one consumed wire packet", stats)
	}
}

func TestCarrierServerSessionRejectsPacketsAboveMTU(t *testing.T) {
	t.Setenv("TRUSTIX_IPTUNNEL_KERNEL_FRAGMENT", "0")
	session := &carrierServerSession{
		listener: &packetListener{cfg: tunnelConfig{MTU: carrierHeaderLen + 1}},
	}
	if err := session.SendPacket([]byte("too-large")); err == nil {
		t.Fatal("expected packet above carrier mtu to fail")
	}
	if got := session.Stats().Extra["iptunnel_mtu_drops"]; got != 1 {
		t.Fatalf("mtu drops = %d, want 1", got)
	}
}

func TestCarrierBufferPoolsReuseWithoutAllocations(t *testing.T) {
	readBuffer := takeCarrierReadBuffer(2048)
	putCarrierReadBuffer(readBuffer)
	readAllocs := testing.AllocsPerRun(1000, func() {
		buffer := takeCarrierReadBuffer(2048)
		putCarrierReadBuffer(buffer)
	})
	if readAllocs != 0 {
		t.Fatalf("read buffer pool allocations = %v, want 0", readAllocs)
	}

	reassemblyBuffer := takeCarrierReassemblyBuffer(48 * 1024)
	putCarrierReassemblyBuffer(reassemblyBuffer)
	reassemblyAllocs := testing.AllocsPerRun(1000, func() {
		buffer := takeCarrierReassemblyBuffer(48 * 1024)
		putCarrierReassemblyBuffer(buffer)
	})
	if reassemblyAllocs != 0 {
		t.Fatalf("reassembly buffer pool allocations = %v, want 0", reassemblyAllocs)
	}
}
