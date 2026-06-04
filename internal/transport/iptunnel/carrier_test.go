package iptunnel

import (
	"bytes"
	"net"
	"net/netip"
	"strings"
	"testing"

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
	if len(packets) != 1 || string(packets[0]) != "ok" {
		t.Fatalf("packets = %q, want ok", packets)
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

func TestCarrierSendRejectsPacketsAboveMTU(t *testing.T) {
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
