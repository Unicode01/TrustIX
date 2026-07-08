package udp

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/transport"
	securetransport "trustix.local/trustix/internal/transport/secure"
)

func TestTransportSendReceive(t *testing.T) {
	addr := freeUDPAddr(t)
	tr := New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := tr.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolUDP,
		Listen:    addr,
		Enabled:   true,
	}, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan transport.Session, 1)
	acceptErr := make(chan error, 1)
	go func() {
		session, err := listener.Accept(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- session
	}()

	client, err := tr.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{
			{Name: core.EndpointID("server"), Transport: transport.ProtocolUDP, Address: addr},
		},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	if err := client.SendPacket([]byte("hello")); err != nil {
		t.Fatalf("send hello: %v", err)
	}

	var server transport.Session
	select {
	case err := <-acceptErr:
		t.Fatalf("accept: %v", err)
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	received, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if string(received) != "hello" {
		t.Fatalf("server received %q, want hello", received)
	}
	if err := server.SendPacket([]byte("world")); err != nil {
		t.Fatalf("send world: %v", err)
	}
	reply, err := client.RecvPacket()
	if err != nil {
		t.Fatalf("client recv: %v", err)
	}
	if string(reply) != "world" {
		t.Fatalf("client received %q, want world", reply)
	}
}

func TestConnectedSessionCloseUnblocksRecvPacket(t *testing.T) {
	addr := freeUDPAddr(t)
	tr := New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := dialUDPClient(t, ctx, tr, addr)
	done := make(chan error, 1)
	go func() {
		_, err := client.RecvPacket()
		done <- err
	}()

	time.Sleep(20 * time.Millisecond)
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- client.Close()
	}()

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close blocked while RecvPacket was pending")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("RecvPacket returned nil error after close")
		}
	case <-time.After(time.Second):
		t.Fatal("RecvPacket did not unblock after close")
	}
}

func TestUserspaceUDPSessionSendPacketsWritesBatchAndStats(t *testing.T) {
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

	session := &session{conn: clientConn}
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
		if got := buf[:n]; !bytes.Equal(got, want) {
			t.Fatalf("packet %d = %q, want %q", i, got, want)
		}
	}
	stats := session.Stats()
	if !stats.NativeBatching {
		t.Fatal("NativeBatching = false, want true")
	}
	if stats.PacketsSent != uint64(len(packets)) || stats.BytesSent == 0 {
		t.Fatalf("stats after batch send = %+v, want %d packets and nonzero bytes", stats, len(packets))
	}
	if stats.Extra["udp_send_batch_calls"] != 1 {
		t.Fatalf("batch calls = %d, want 1", stats.Extra["udp_send_batch_calls"])
	}
	if stats.Extra["udp_send_batch_packets"] != uint64(len(packets)) {
		t.Fatalf("batch packets = %d, want %d", stats.Extra["udp_send_batch_packets"], len(packets))
	}
	if stats.Extra["udp_send_batch_bytes"] != stats.BytesSent {
		t.Fatalf("batch bytes = %d, want bytes sent %d", stats.Extra["udp_send_batch_bytes"], stats.BytesSent)
	}
}

func TestUserspaceUDPSessionStatsAdvertisesDatagramMaxPacketSize(t *testing.T) {
	session := &session{}
	stats := session.Stats()
	if !stats.NativeBatching || !stats.Datagram {
		t.Fatalf("stats batching/datagram = native:%t datagram:%t, want true/true", stats.NativeBatching, stats.Datagram)
	}
	if got, want := stats.MaxPacketSize, uint64(defaultUserspaceUDPDatagramMaxPacketSize()); got != want {
		t.Fatalf("MaxPacketSize = %d, want %d", got, want)
	}
	if stats.FragmentingDatagram {
		t.Fatal("FragmentingDatagram = true, want false so daemon still enforces UDP payload max")
	}

	t.Setenv("TRUSTIX_UDP_DATAGRAM_MAX_PACKET_SIZE", strconv.Itoa(userspaceUDPDatagramBatchMax))
	if got, want := session.Stats().MaxPacketSize, uint64(userspaceUDPDatagramBatchMax); got != want {
		t.Fatalf("env MaxPacketSize = %d, want %d", got, want)
	}

	t.Setenv("TRUSTIX_UDP_DATAGRAM_MAX_PACKET_SIZE", "999999")
	if got, want := session.Stats().MaxPacketSize, uint64(userspaceUDPDatagramPayloadMax); got != want {
		t.Fatalf("clamped MaxPacketSize = %d, want %d", got, want)
	}
}

func TestUserspaceUDPDefaultDatagramLimit(t *testing.T) {
	want := userspaceUDPDatagramBatchMax
	if runtime.GOOS == "linux" {
		want = userspaceUDPDatagramPayloadMax
	}
	if got := defaultUserspaceUDPDatagramMaxPacketSize(); got != want {
		t.Fatalf("default datagram max = %d, want %d", got, want)
	}
}

func TestUserspaceUDPServerSessionStatsAdvertisesDatagramMaxPacketSize(t *testing.T) {
	session := &serverSession{}
	stats := session.Stats()
	if !stats.NativeBatching || !stats.Datagram {
		t.Fatalf("stats batching/datagram = native:%t datagram:%t, want true/true", stats.NativeBatching, stats.Datagram)
	}
	if got, want := stats.MaxPacketSize, uint64(defaultUserspaceUDPDatagramMaxPacketSize()); got != want {
		t.Fatalf("MaxPacketSize = %d, want %d", got, want)
	}
}

func TestKernelTransportDisabledUsesSocketUDP(t *testing.T) {
	providerA, providerB := newKernelUDPProviderPair()
	clientTransport := NewWithKernelProvider(providerA, Options{
		KernelTransport: func() dataplane.KernelTransportMode {
			return dataplane.KernelTransportModeDisabled
		},
	})
	serverTransport := NewWithKernelProvider(providerB, Options{
		KernelTransport: func() dataplane.KernelTransportMode {
			return dataplane.KernelTransportModeDisabled
		},
	})
	addr := freeUDPAddr(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := serverTransport.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolUDP,
		Listen:    addr,
		Enabled:   true,
	}, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan transport.Session, 1)
	acceptErr := make(chan error, 1)
	go func() {
		session, err := listener.Accept(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- session
	}()

	client, err := clientTransport.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolUDP,
			Address:   addr,
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	if err := client.SendPacket([]byte("socket")); err != nil {
		t.Fatalf("send packet: %v", err)
	}

	var server transport.Session
	select {
	case err := <-acceptErr:
		t.Fatalf("accept: %v", err)
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()
	packet, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("recv packet: %v", err)
	}
	if string(packet) != "socket" {
		t.Fatalf("packet = %q, want socket", packet)
	}
	if providerA.submitted != 0 || providerB.received != 0 {
		t.Fatalf("kernel provider used with disabled mode: submitted=%d received=%d", providerA.submitted, providerB.received)
	}
}

func TestKernelSessionRecvPacketsWithRelease(t *testing.T) {
	session := newKernelSession(nil, nil, 7, core.IXID("ix-b"), core.EndpointID("ep"), dataplane.CryptoPlacementKernel)
	defer session.Close()
	var released atomic.Int32
	releasePacket := func() { released.Add(1) }
	session.handleFrames([]dataplane.KernelUDPFrame{
		{
			FlowID:    7,
			Direction: dataplane.KernelTransportInbound,
			Sequence:  1,
			Payload:   []byte("one"),
			Release:   releasePacket,
		},
		{
			FlowID:    7,
			Direction: dataplane.KernelTransportInbound,
			Sequence:  2,
			Payload:   []byte("two"),
			Release:   releasePacket,
		},
	})

	packets, release, err := session.RecvPacketsWithRelease(8)
	if err != nil {
		t.Fatalf("RecvPacketsWithRelease: %v", err)
	}
	if got := len(packets); got != 2 {
		t.Fatalf("packet count = %d, want 2", got)
	}
	if string(packets[0]) != "one" || string(packets[1]) != "two" {
		t.Fatalf("packets = %q/%q", packets[0], packets[1])
	}
	if got := released.Load(); got != 0 {
		t.Fatalf("released before callback = %d, want 0", got)
	}
	if release == nil {
		t.Fatal("release callback is nil")
	}
	release()
	if got := released.Load(); got != 2 {
		t.Fatalf("released after callback = %d, want 2", got)
	}
}

func TestKernelSessionStatsAdvertisesDatagramDefaultMaxPacketSize(t *testing.T) {
	provider, _ := newKernelUDPProviderPair()
	provider.payloadMax = 1200
	session := newKernelSession(provider, nil, 7, core.IXID("ix-b"), core.EndpointID("ep"), dataplane.CryptoPlacementUserspace)
	defer session.Close()

	stats := session.Stats()
	if !stats.NativeBatching {
		t.Fatal("NativeBatching = false, want true")
	}
	if !stats.Datagram {
		t.Fatal("Datagram = false, want true")
	}
	if got, want := stats.MaxPacketSize, uint64(userspaceUDPSessionMaxPacket); got != want {
		t.Fatalf("MaxPacketSize = %d, want %d", got, want)
	}
	if got, want := stats.Extra[kernelUDPStatFragmentPayloadSize], uint64(1200); got != want {
		t.Fatalf("%s = %d, want %d", kernelUDPStatFragmentPayloadSize, got, want)
	}
}

func TestKernelSessionStatsHonorsConfiguredLogicalMaxPacketSize(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_MAX_PACKET_SIZE", "4096")
	provider, _ := newKernelUDPProviderPair()
	provider.payloadMax = 1200
	session := newKernelSession(provider, nil, 7, core.IXID("ix-b"), core.EndpointID("ep"), dataplane.CryptoPlacementUserspace)
	defer session.Close()

	stats := session.Stats()
	if got, want := stats.MaxPacketSize, uint64(4096); got != want {
		t.Fatalf("MaxPacketSize = %d, want %d", got, want)
	}
}

func TestKernelSessionRecvPacketsWithReleaseSplitsBatchWithoutReleases(t *testing.T) {
	session := newKernelSession(nil, nil, 7, core.IXID("ix-b"), core.EndpointID("ep"), dataplane.CryptoPlacementKernel)
	defer session.Close()
	session.enqueueBatch(kernelUDPPacketBatch{
		packets: [][]byte{
			[]byte("one"),
			[]byte("two"),
			[]byte("three"),
		},
	})

	packets, release, err := session.RecvPacketsWithRelease(2)
	if err != nil {
		t.Fatalf("RecvPacketsWithRelease first: %v", err)
	}
	if release != nil {
		t.Fatal("release callback = non-nil, want nil")
	}
	if len(packets) != 2 || string(packets[0]) != "one" || string(packets[1]) != "two" {
		t.Fatalf("first packets = %q", packets)
	}

	packets, release, err = session.RecvPacketsWithRelease(2)
	if err != nil {
		t.Fatalf("RecvPacketsWithRelease second: %v", err)
	}
	if release != nil {
		t.Fatal("second release callback = non-nil, want nil")
	}
	if len(packets) != 1 || string(packets[0]) != "three" {
		t.Fatalf("second packets = %q", packets)
	}
}

func TestKernelSessionRecvPacketsWithReleaseReturnsPoolOwnerRelease(t *testing.T) {
	session := newKernelSession(nil, nil, 7, core.IXID("ix-b"), core.EndpointID("ep"), dataplane.CryptoPlacementKernel)
	defer session.Close()
	session.handleFrames([]dataplane.KernelUDPFrame{
		{FlowID: 7, Direction: dataplane.KernelTransportInbound, Sequence: 1, Payload: []byte("one")},
		{FlowID: 7, Direction: dataplane.KernelTransportInbound, Sequence: 2, Payload: []byte("two")},
	})

	packets, release, err := session.RecvPacketsWithRelease(8)
	if err != nil {
		t.Fatalf("RecvPacketsWithRelease: %v", err)
	}
	if len(packets) != 2 || string(packets[0]) != "one" || string(packets[1]) != "two" {
		t.Fatalf("packets = %q", packets)
	}
	if release == nil {
		t.Fatal("release callback is nil, want pool owner release")
	}
	release()
}

func TestKernelSessionRecvPacketCopiesAndReleasesBorrowedPayload(t *testing.T) {
	session := newKernelSession(nil, nil, 7, core.IXID("ix-b"), core.EndpointID("ep"), dataplane.CryptoPlacementKernel)
	defer session.Close()
	payload := []byte("borrowed")
	var released atomic.Int32
	session.handleFrame(dataplane.KernelUDPFrame{
		FlowID:    7,
		Direction: dataplane.KernelTransportInbound,
		Sequence:  1,
		Payload:   payload,
		Release:   func() { released.Add(1) },
	})

	packet, err := session.RecvPacket()
	if err != nil {
		t.Fatalf("RecvPacket: %v", err)
	}
	if got := released.Load(); got != 1 {
		t.Fatalf("released after RecvPacket = %d, want 1", got)
	}
	payload[0] = 'X'
	if string(packet) != "borrowed" {
		t.Fatalf("RecvPacket returned borrowed storage: %q", packet)
	}
}

func TestKernelSessionRecvPacketsCopiesAndReleasesBorrowedPayloads(t *testing.T) {
	session := newKernelSession(nil, nil, 7, core.IXID("ix-b"), core.EndpointID("ep"), dataplane.CryptoPlacementKernel)
	defer session.Close()
	payloads := [][]byte{[]byte("one"), []byte("two")}
	var released atomic.Int32
	session.handleFrames([]dataplane.KernelUDPFrame{
		{
			FlowID:    7,
			Direction: dataplane.KernelTransportInbound,
			Sequence:  1,
			Payload:   payloads[0],
			Release:   func() { released.Add(1) },
		},
		{
			FlowID:    7,
			Direction: dataplane.KernelTransportInbound,
			Sequence:  2,
			Payload:   payloads[1],
			Release:   func() { released.Add(1) },
		},
	})

	packets, err := session.RecvPackets(8)
	if err != nil {
		t.Fatalf("RecvPackets: %v", err)
	}
	if got := released.Load(); got != 2 {
		t.Fatalf("released after RecvPackets = %d, want 2", got)
	}
	payloads[0][0] = 'X'
	payloads[1][0] = 'Y'
	if len(packets) != 2 || string(packets[0]) != "one" || string(packets[1]) != "two" {
		t.Fatalf("RecvPackets returned borrowed storage: %q", packets)
	}
}

func TestKernelListenerDispatchBatchReleasesSkippedFrames(t *testing.T) {
	listener := &kernelListener{
		endpoint: transport.Endpoint{Name: core.EndpointID("ep-a")},
		acceptCh: make(chan transport.Session, 1),
		sessions: make(map[uint64]*kernelSession),
		done:     make(chan struct{}),
	}
	var released atomic.Int32
	listener.dispatchBatch([]dataplane.KernelUDPFrame{
		{
			FlowID:    7,
			Direction: dataplane.KernelTransportInbound,
			Endpoint:  core.EndpointID("ep-b"),
			Payload:   []byte("wrong-endpoint"),
			Release:   func() { released.Add(1) },
		},
		{
			FlowID:    8,
			Direction: dataplane.KernelTransportOutbound,
			Endpoint:  core.EndpointID("ep-a"),
			Payload:   []byte("wrong-direction"),
			Release:   func() { released.Add(1) },
		},
	})
	if got := released.Load(); got != 2 {
		t.Fatalf("released skipped frames = %d, want 2", got)
	}
}

func TestKernelListenerKeepsExistingSessionAfterPeerEndpointAnnotation(t *testing.T) {
	listener := &kernelListener{
		endpoint: transport.Endpoint{Name: core.EndpointID("local-ep")},
		acceptCh: make(chan transport.Session, 1),
		sessions: make(map[uint64]*kernelSession),
		done:     make(chan struct{}),
	}
	listener.dispatch(dataplane.KernelUDPFrame{
		FlowID:    7,
		Direction: dataplane.KernelTransportInbound,
		Endpoint:  core.EndpointID("local-ep"),
		Payload:   kernelUDPClientHelloForTest(),
	})
	acceptedRaw := <-listener.acceptCh
	accepted := acceptedRaw.(*kernelSession)
	accepted.SetPeerEndpoint(core.IXID("peer"), core.EndpointID("peer-ep"))
	listener.dispatchBatch([]dataplane.KernelUDPFrame{{
		FlowID:    7,
		Direction: dataplane.KernelTransportInbound,
		Endpoint:  core.EndpointID("peer-ep"),
		Payload:   []byte("data"),
	}})

	first, err := accepted.RecvPacket()
	if err != nil {
		t.Fatalf("recv first packet: %v", err)
	}
	second, err := accepted.RecvPacket()
	if err != nil {
		t.Fatalf("recv second packet: %v", err)
	}
	if !bytes.Equal(first, kernelUDPClientHelloForTest()) || string(second) != "data" {
		t.Fatalf("packets = %q/%q, want client hello/data", first, second)
	}
	select {
	case extra := <-listener.acceptCh:
		t.Fatalf("unexpected replacement session: %#v", extra)
	default:
	}
}

func TestKernelListenerDispatchesInnerIPv4ToExistingSession(t *testing.T) {
	listener := &kernelListener{
		endpoint: transport.Endpoint{Name: core.EndpointID("server")},
		acceptCh: make(chan transport.Session, 1),
		sessions: make(map[uint64]*kernelSession),
		done:     make(chan struct{}),
	}
	listener.dispatch(dataplane.KernelUDPFrame{
		FlowID:    7,
		Direction: dataplane.KernelTransportInbound,
		Endpoint:  core.EndpointID("server"),
		Payload:   kernelUDPClientHelloForTest(),
	})
	acceptedRaw := <-listener.acceptCh
	accepted := acceptedRaw.(*kernelSession)
	packetA := ipv4PacketForKernelUDPTest(40)
	packetB := ipv4PacketForKernelUDPTest(48)
	var released atomic.Int32

	listener.dispatch(dataplane.KernelUDPFrame{
		FlowID:    7,
		Direction: dataplane.KernelTransportInbound,
		Endpoint:  core.EndpointID("server"),
		InnerIPv4: true,
		Payload:   packetA,
		Release:   func() { released.Add(1) },
	})
	listener.dispatchBatch([]dataplane.KernelUDPFrame{{
		FlowID:    7,
		Direction: dataplane.KernelTransportInbound,
		Endpoint:  core.EndpointID("server"),
		InnerIPv4: true,
		Payload:   packetB,
		Release:   func() { released.Add(1) },
	}})

	if got, err := accepted.RecvPacket(); err != nil || !bytes.Equal(got, kernelUDPClientHelloForTest()) {
		t.Fatalf("first packet = %q, %v; want client hello", got, err)
	}
	if got, err := accepted.RecvPacket(); err != nil || !bytes.Equal(got, packetA) {
		t.Fatalf("second packet len=%d err=%v, want first IPv4", len(got), err)
	}
	if got, err := accepted.RecvPacket(); err != nil || !bytes.Equal(got, packetB) {
		t.Fatalf("third packet len=%d err=%v, want second IPv4", len(got), err)
	}
	if got := released.Load(); got != 2 {
		t.Fatalf("released payloads = %d, want 2", got)
	}
}

func TestKernelListenerAcceptsInnerIPv4AsPlaintextNewSession(t *testing.T) {
	provider, _ := newKernelUDPProviderPair()
	listener := &kernelListener{
		provider: provider,
		endpoint: transport.Endpoint{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolUDP,
		},
		acceptCh: make(chan transport.Session, 1),
		done:     make(chan struct{}),
		sessions: make(map[uint64]*kernelSession),
	}
	packet := ipv4PacketForKernelUDPTest(40)

	listener.dispatch(dataplane.KernelUDPFrame{
		FlowID:    42,
		Direction: dataplane.KernelTransportInbound,
		Endpoint:  core.EndpointID("server"),
		InnerIPv4: true,
		Payload:   packet,
	})

	if len(listener.sessions) != 1 {
		t.Fatalf("listener sessions = %d, want one", len(listener.sessions))
	}
	select {
	case session := <-listener.acceptCh:
		got, err := session.RecvPacket()
		if err != nil {
			t.Fatalf("recv plaintext first packet: %v", err)
		}
		if !bytes.Equal(got, packet) {
			t.Fatalf("plaintext first packet len=%d, want %d", len(got), len(packet))
		}
	default:
		t.Fatal("listener did not accept plaintext inner IPv4 session")
	}
}

func TestKernelListenerClosedInboundSessionIsRemovedAndRecreated(t *testing.T) {
	listener := &kernelListener{
		endpoint: transport.Endpoint{Name: core.EndpointID("ep-a")},
		acceptCh: make(chan transport.Session, 1),
		sessions: make(map[uint64]*kernelSession),
		done:     make(chan struct{}),
	}
	listener.dispatch(dataplane.KernelUDPFrame{
		FlowID:    7,
		Direction: dataplane.KernelTransportInbound,
		Endpoint:  core.EndpointID("ep-a"),
		Payload:   kernelUDPClientHelloForTest(),
	})
	firstRaw := <-listener.acceptCh
	first := firstRaw.(*kernelSession)
	if listener.sessions[7] != first {
		t.Fatal("first inbound session was not registered")
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first session: %v", err)
	}
	if got := listener.sessions[7]; got != nil {
		t.Fatalf("listener kept closed session: %#v", got)
	}

	listener.dispatch(dataplane.KernelUDPFrame{
		FlowID:    7,
		Direction: dataplane.KernelTransportInbound,
		Endpoint:  core.EndpointID("ep-a"),
		Payload:   kernelUDPClientHelloForTest(),
	})
	secondRaw := <-listener.acceptCh
	second := secondRaw.(*kernelSession)
	if second == first {
		t.Fatal("listener reused closed inbound session")
	}
	packet, err := second.RecvPacket()
	if err != nil {
		t.Fatalf("recv second packet: %v", err)
	}
	if !bytes.Equal(packet, kernelUDPClientHelloForTest()) {
		t.Fatalf("second packet = %q, want client hello", packet)
	}
}

func TestKernelTransportRequireKernelRejectsUnavailableProvider(t *testing.T) {
	providerA, providerB := newKernelUDPProviderPair()
	providerA.available = false
	providerB.available = false
	requireKernel := Options{
		KernelTransport: func() dataplane.KernelTransportMode {
			return dataplane.KernelTransportModeRequireKernel
		},
	}
	clientTransport := NewWithKernelProvider(providerA, requireKernel)
	serverTransport := NewWithKernelProvider(providerB, requireKernel)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := serverTransport.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolUDP,
		Listen:    freeUDPAddr(t),
		Enabled:   true,
	}, nil); err == nil {
		t.Fatal("expected require_kernel listen failure")
	}
	_, err := clientTransport.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolUDP,
			Address:   freeUDPAddr(t),
		}},
	}, nil)
	if err == nil {
		t.Fatal("expected require_kernel dial failure")
	}
	if providerA.submitted != 0 || providerB.received != 0 {
		t.Fatalf("kernel provider unexpectedly used after failure: submitted=%d received=%d", providerA.submitted, providerB.received)
	}
}

func TestKernelTransportRequireKernelProbeRejectsUnavailableProvider(t *testing.T) {
	providerA, _ := newKernelUDPProviderPair()
	providerA.available = false
	tr := NewWithKernelProvider(providerA, Options{
		KernelTransport: func() dataplane.KernelTransportMode {
			return dataplane.KernelTransportModeRequireKernel
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := tr.Probe(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolUDP,
			Address:   freeUDPAddr(t),
		}},
	})
	if result.Healthy {
		t.Fatalf("probe healthy with unavailable required kernel provider: %#v", result)
	}
	if result.Error == "" {
		t.Fatalf("probe error is empty: %#v", result)
	}
}

func TestListenerDemuxesMultipleRemotes(t *testing.T) {
	addr := freeUDPAddr(t)
	tr := New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := tr.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolUDP,
		Listen:    addr,
		Enabled:   true,
	}, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	clientA := dialUDPClient(t, ctx, tr, addr)
	defer clientA.Close()
	clientB := dialUDPClient(t, ctx, tr, addr)
	defer clientB.Close()

	if err := clientA.SendPacket([]byte("from-a")); err != nil {
		t.Fatalf("send from-a: %v", err)
	}
	if err := clientB.SendPacket([]byte("from-b")); err != nil {
		t.Fatalf("send from-b: %v", err)
	}

	sessions := make(map[string]transport.Session)
	for len(sessions) < 2 {
		session, err := listener.Accept(ctx)
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		packet, err := session.RecvPacket()
		if err != nil {
			t.Fatalf("server recv: %v", err)
		}
		sessions[string(packet)] = session
	}
	if err := sessions["from-a"].SendPacket([]byte("reply-a")); err != nil {
		t.Fatalf("send reply-a: %v", err)
	}
	if err := sessions["from-b"].SendPacket([]byte("reply-b")); err != nil {
		t.Fatalf("send reply-b: %v", err)
	}
	assertRecvPacket(t, clientA, "reply-a")
	assertRecvPacket(t, clientB, "reply-b")
}

func TestKernelUDPProviderSendReceive(t *testing.T) {
	providerA, providerB := newKernelUDPProviderPair()
	clientTransport := NewWithKernelProvider(providerA)
	serverTransport := NewWithKernelProvider(providerB)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := serverTransport.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolUDP,
		Listen:    "198.51.100.2:7000",
		Enabled:   true,
	}, nil)
	if err != nil {
		t.Fatalf("listen kernel udp: %v", err)
	}
	defer listener.Close()

	accepted := make(chan transport.Session, 1)
	go func() {
		session, err := listener.Accept(ctx)
		if err == nil {
			accepted <- session
		}
	}()

	client, err := clientTransport.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolUDP,
			Address:   "198.51.100.2:7000",
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial kernel udp: %v", err)
	}
	defer client.Close()

	if err := client.SendPacket([]byte("kernel-hello")); err != nil {
		t.Fatalf("send kernel hello: %v", err)
	}
	var server transport.Session
	select {
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if string(got) != "kernel-hello" {
		t.Fatalf("server received %q, want kernel-hello", got)
	}
	if err := server.SendPacket([]byte("kernel-world")); err != nil {
		t.Fatalf("send kernel world: %v", err)
	}
	reply, err := client.RecvPacket()
	if err != nil {
		t.Fatalf("client recv: %v", err)
	}
	if string(reply) != "kernel-world" {
		t.Fatalf("client received %q, want kernel-world", reply)
	}
	if providerA.submitted == 0 || providerB.received == 0 {
		t.Fatalf("provider stats A submitted=%d B received=%d", providerA.submitted, providerB.received)
	}
}

func TestKernelUDPProviderFragmentsLargePacket(t *testing.T) {
	providerA, providerB := newKernelUDPProviderPair()
	clientTransport := NewWithKernelProvider(providerA)
	serverTransport := NewWithKernelProvider(providerB)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := serverTransport.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolUDP,
		Listen:    "198.51.100.2:7000",
		Enabled:   true,
	}, nil)
	if err != nil {
		t.Fatalf("listen kernel udp: %v", err)
	}
	defer listener.Close()

	accepted := make(chan transport.Session, 1)
	go func() {
		session, err := listener.Accept(ctx)
		if err == nil {
			accepted <- session
		}
	}()

	client, err := clientTransport.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolUDP,
			Address:   "198.51.100.2:7000",
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial kernel udp: %v", err)
	}
	defer client.Close()

	payload := bytes.Repeat([]byte{0x5a}, kernelUDPFragmentPayloadSize*3+17)
	if err := client.SendPacket(payload); err != nil {
		t.Fatalf("send large kernel udp packet: %v", err)
	}
	var server transport.Session
	select {
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("server received len=%d, want len=%d", len(got), len(payload))
	}
	if got, want := providerA.submitted, uint64(4); got != want {
		t.Fatalf("provider A submitted frames = %d, want %d", got, want)
	}
	if got, want := providerB.received, uint64(4); got != want {
		t.Fatalf("provider B received frames = %d, want %d", got, want)
	}
	stats := client.Stats()
	if stats.Extra[kernelUDPStatFragmentedPacketsSent] != 1 || stats.Extra[kernelUDPStatFragmentsSent] != 4 {
		t.Fatalf("client fragment stats = %#v", stats.Extra)
	}
	serverStats := server.Stats()
	if serverStats.Extra[kernelUDPStatFragmentedPacketsReceived] != 1 || serverStats.Extra[kernelUDPStatFragmentsReassembled] != 4 {
		t.Fatalf("server fragment stats = %#v", serverStats.Extra)
	}
}

func TestKernelUDPSessionBufferFromEnv(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_SESSION_BUFFER", "")
	if got := kernelSessionBuffer(); got != kernelSessionBufferDefault {
		t.Fatalf("session buffer default = %d, want %d", got, kernelSessionBufferDefault)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_SESSION_BUFFER", "2048")
	if got := kernelSessionBuffer(); got != 2048 {
		t.Fatalf("session buffer = %d, want 2048", got)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_SESSION_BUFFER", "999999")
	if got := kernelSessionBuffer(); got != kernelSessionBufferMax {
		t.Fatalf("session buffer clamp = %d, want %d", got, kernelSessionBufferMax)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_SESSION_BUFFER", "bad")
	if got := kernelSessionBuffer(); got != kernelSessionBufferDefault {
		t.Fatalf("invalid session buffer = %d, want %d", got, kernelSessionBufferDefault)
	}
}

func TestKernelUDPReassemblyPrunesOldestWhenFull(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_REASSEMBLY_MAX_ASSEMBLIES", "2")
	session := newKernelSession(nil, nil, 1001, "ix-b", "server", dataplane.CryptoPlacementUserspace)
	defer session.closeInput()

	for _, seq := range []uint64{10, 20, 30} {
		if _, ok := session.handleFrameOne(dataplane.KernelUDPFrame{
			FlowID:        1001,
			Direction:     dataplane.KernelTransportInbound,
			Sequence:      seq,
			FragmentIndex: 0,
			FragmentCount: 2,
			Payload:       []byte{byte(seq)},
		}); ok {
			t.Fatalf("incomplete fragment sequence %d unexpectedly reassembled", seq)
		}
	}

	stats := session.Stats()
	if got := stats.Extra[kernelUDPStatFragmentAssembliesCurrent]; got != 2 {
		t.Fatalf("current assemblies = %d, want 2", got)
	}
	if got := stats.Extra[kernelUDPStatFragmentExpiredAssemblies]; got != 1 {
		t.Fatalf("expired assemblies = %d, want 1", got)
	}
	if got := stats.Extra[kernelUDPStatFragmentExpiredFragments]; got != 1 {
		t.Fatalf("expired fragments = %d, want 1", got)
	}
}

func TestKernelUDPFragmentPayloadClampsToProviderMax(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_FRAGMENT_PAYLOAD_SIZE", "8000")
	provider := &fakeKernelUDPProvider{payloadMax: 3900}
	session := newKernelSession(provider, nil, 1, "ix-a", "ep", dataplane.CryptoPlacementUserspace)

	if got := session.fragmentPayloadSize(); got != 3900 {
		t.Fatalf("fragment payload = %d, want provider max 3900", got)
	}
}

func TestKernelUDPFragmentPayloadAutoRaisesKernelCryptoDefaultToProviderMax(t *testing.T) {
	provider := &fakeKernelUDPProvider{payloadMax: 3900}
	session := newKernelSession(provider, nil, 1, "ix-a", "ep", dataplane.CryptoPlacementKernel)
	session.cryptoOffloaded = true
	session.configuredFragmentPayload = kernelUDPFragmentPayloadSizeForPlacement(session.cryptoPlacement, session.cryptoOffloaded)

	if got := session.fragmentPayloadSize(); got != 3900 {
		t.Fatalf("fragment payload = %d, want provider max 3900", got)
	}
}

func TestKernelUDPFragmentPayloadHonorsExplicitKernelCryptoValueBelowProviderMax(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_FRAGMENT_PAYLOAD_SIZE", "1200")
	provider := &fakeKernelUDPProvider{payloadMax: 3900}
	session := newKernelSession(provider, nil, 1, "ix-a", "ep", dataplane.CryptoPlacementKernel)
	session.cryptoOffloaded = true
	session.configuredFragmentPayload = kernelUDPFragmentPayloadSizeForPlacement(session.cryptoPlacement, session.cryptoOffloaded)

	if got := session.fragmentPayloadSize(); got != 1200 {
		t.Fatalf("fragment payload = %d, want explicit value 1200", got)
	}
}

func TestKernelUDPSendPacketsMarksOnlyValidInnerIPv4(t *testing.T) {
	providerA, providerB := newKernelUDPProviderPair()
	flowID := uint64(77)
	providerA.flows[flowID] = dataplane.KernelUDPFlow{ID: flowID, Peer: "ix-b", Endpoint: "ep"}
	session := newKernelSession(providerA, nil, flowID, "ix-b", "ep", dataplane.CryptoPlacementUserspace)
	validIPv4 := ipv4PacketForKernelUDPTest(40)
	controlLike := []byte{'T', 'I', 'X', 'C', 1, 1, 0, 0}
	invalidIPv4 := append([]byte(nil), validIPv4...)
	binary.BigEndian.PutUint16(invalidIPv4[2:4], uint16(len(invalidIPv4)-1))

	if err := session.SendPackets([][]byte{validIPv4, controlLike, invalidIPv4}); err != nil {
		t.Fatalf("send packets: %v", err)
	}

	frames := providerB.deliveredFrames()
	if len(frames) != 3 {
		t.Fatalf("delivered frames = %d, want 3", len(frames))
	}
	if !frames[0].InnerIPv4 {
		t.Fatalf("valid IPv4 frame was not marked inner IPv4")
	}
	if frames[1].InnerIPv4 {
		t.Fatalf("control-like frame was marked inner IPv4")
	}
	if frames[2].InnerIPv4 {
		t.Fatalf("invalid IPv4 frame was marked inner IPv4")
	}
}

func TestKernelUDPSealBeforeFragmentSubmitsOneKernelCryptoPacket(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_SEAL_BEFORE_FRAGMENT", "1")
	providerA, providerB := newKernelUDPProviderPair()
	flowID := uint64(99)
	providerA.flows[flowID] = dataplane.KernelUDPFlow{ID: flowID, Peer: "ix-b", Endpoint: "ep"}
	cryptoState, err := newFakeKernelUDPCrypto(dataplane.KernelUDPCryptoSpec{
		FlowID:  flowID,
		Suite:   securetransport.SuiteAES256GCMX25519,
		Epoch:   7,
		SendKey: bytes.Repeat([]byte{0x11}, 32),
		RecvKey: bytes.Repeat([]byte{0x22}, 32),
		SendIV:  bytes.Repeat([]byte{0x33}, 12),
		RecvIV:  bytes.Repeat([]byte{0x44}, 12),
	})
	if err != nil {
		t.Fatalf("fake crypto: %v", err)
	}
	providerA.cryptos[flowID] = cryptoState
	providerA.payloadMax = 900
	_ = providerB

	session := newKernelSession(providerA, nil, flowID, "ix-b", "ep", dataplane.CryptoPlacementKernel)
	session.cryptoOffloaded = true
	session.cryptoSuite = securetransport.SuiteAES256GCMX25519
	session.epoch = 7
	session.configuredFragmentPayload = 900
	payload := bytes.Repeat([]byte{0x5a}, 130000)
	if err := session.SendPacket(payload); err != nil {
		t.Fatalf("send large kernel crypto packet: %v", err)
	}
	if got, want := providerA.submitted, uint64(1); got != want {
		t.Fatalf("submitted frames = %d, want %d", got, want)
	}
	stats := session.Stats()
	wantFragments := uint64(kernelUDPFragmentCountForSize(len(payload)+24+16, 900))
	if stats.Extra[kernelUDPStatFragmentedPacketsSent] != 1 || stats.Extra[kernelUDPStatFragmentsSent] != wantFragments {
		t.Fatalf("fragment stats = %#v", stats.Extra)
	}
}

func TestKernelUDPSealBeforeFragmentReservesFragmentSequences(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_SEAL_BEFORE_FRAGMENT", "1")
	provider, remote := newKernelUDPProviderPair()
	flowID := uint64(100)
	provider.flows[flowID] = dataplane.KernelUDPFlow{ID: flowID, Peer: "ix-b", Endpoint: "ep"}
	cryptoState, err := newFakeKernelUDPCrypto(dataplane.KernelUDPCryptoSpec{
		FlowID:  flowID,
		Suite:   securetransport.SuiteAES256GCMX25519,
		Epoch:   7,
		SendKey: bytes.Repeat([]byte{0x11}, 32),
		RecvKey: bytes.Repeat([]byte{0x22}, 32),
		SendIV:  bytes.Repeat([]byte{0x33}, 12),
		RecvIV:  bytes.Repeat([]byte{0x44}, 12),
	})
	if err != nil {
		t.Fatalf("fake crypto: %v", err)
	}
	provider.cryptos[flowID] = cryptoState
	remoteCryptoState, err := newFakeKernelUDPCrypto(dataplane.KernelUDPCryptoSpec{
		FlowID:  flowID,
		Suite:   securetransport.SuiteAES256GCMX25519,
		Epoch:   7,
		SendKey: bytes.Repeat([]byte{0x22}, 32),
		RecvKey: bytes.Repeat([]byte{0x11}, 32),
		SendIV:  bytes.Repeat([]byte{0x44}, 12),
		RecvIV:  bytes.Repeat([]byte{0x33}, 12),
	})
	if err != nil {
		t.Fatalf("remote fake crypto: %v", err)
	}
	remote.cryptos[flowID] = remoteCryptoState
	session := newKernelSession(provider, nil, flowID, "ix-b", "ep", dataplane.CryptoPlacementKernel)
	session.cryptoOffloaded = true
	session.cryptoSuite = securetransport.SuiteAES256GCMX25519
	session.epoch = 7
	session.configuredFragmentPayload = 900

	large := bytes.Repeat([]byte{0x5a}, 130000)
	small := []byte("next-packet")
	if err := session.SendPackets([][]byte{large, small}); err != nil {
		t.Fatalf("send packets: %v", err)
	}

	frames := remote.deliveredFrames()
	if len(frames) != 2 {
		t.Fatalf("delivered frames = %d, want 2", len(frames))
	}
	largeFragments := kernelUDPFragmentCountForSize(len(large)+24+16, 900)
	if frames[0].Sequence != 1 {
		t.Fatalf("large sequence = %d, want 1", frames[0].Sequence)
	}
	if want := uint64(largeFragments + 1); frames[1].Sequence != want {
		t.Fatalf("next sequence = %d, want %d", frames[1].Sequence, want)
	}
}

func ipv4PacketForKernelUDPTest(length int) []byte {
	packet := make([]byte, length)
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 6
	binary.BigEndian.PutUint16(packet[2:4], uint16(length))
	copy(packet[12:16], []byte{10, 0, 0, 1})
	copy(packet[16:20], []byte{10, 0, 0, 2})
	if length >= 24 {
		binary.BigEndian.PutUint16(packet[20:22], 12345)
		binary.BigEndian.PutUint16(packet[22:24], 443)
	}
	return packet
}

func TestKernelUDPProviderDialContextCancelDoesNotCloseSession(t *testing.T) {
	providerA, providerB := newKernelUDPProviderPair()
	clientTransport := NewWithKernelProvider(providerA)
	serverTransport := NewWithKernelProvider(providerB)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := serverTransport.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolUDP,
		Listen:    "198.51.100.2:7000",
		Enabled:   true,
	}, nil)
	if err != nil {
		t.Fatalf("listen kernel udp: %v", err)
	}
	defer listener.Close()

	accepted := make(chan transport.Session, 1)
	go func() {
		session, err := listener.Accept(ctx)
		if err == nil {
			accepted <- session
		}
	}()

	dialCtx, dialCancel := context.WithCancel(ctx)
	client, err := clientTransport.Dial(dialCtx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolUDP,
			Address:   "198.51.100.2:7000",
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial kernel udp: %v", err)
	}
	defer client.Close()
	dialCancel()

	if err := client.SendPacket([]byte("after-cancel")); err != nil {
		t.Fatalf("send after cancel: %v", err)
	}
	var server transport.Session
	select {
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if got, err := server.RecvPacket(); err != nil || string(got) != "after-cancel" {
		t.Fatalf("server recv after cancel = %q, %v", got, err)
	}
	if err := server.SendPacket([]byte("still-open")); err != nil {
		t.Fatalf("server reply after cancel: %v", err)
	}
	assertRecvPacket(t, client, "still-open")
}

func TestKernelListenerDoesNotAcceptInnerIPv4AsNewSession(t *testing.T) {
	provider, _ := newKernelUDPProviderPair()
	listener := &kernelListener{
		provider: provider,
		endpoint: transport.Endpoint{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolUDP,
		},
		acceptCh:                 make(chan transport.Session, 1),
		done:                     make(chan struct{}),
		sessions:                 make(map[uint64]*kernelSession),
		requireSecureClientHello: true,
	}
	var released atomic.Int32

	listener.dispatch(dataplane.KernelUDPFrame{
		FlowID:    42,
		Direction: dataplane.KernelTransportInbound,
		Endpoint:  core.EndpointID("server"),
		InnerIPv4: true,
		Payload:   ipv4PacketForKernelUDPTest(40),
		Release:   func() { released.Add(1) },
	})

	if got := released.Load(); got != 1 {
		t.Fatalf("released inner IPv4 frames = %d, want 1", got)
	}
	if len(listener.sessions) != 0 {
		t.Fatalf("listener sessions = %d, want none", len(listener.sessions))
	}
	select {
	case session := <-listener.acceptCh:
		t.Fatalf("accepted session from inner IPv4 frame: %#v", session)
	default:
	}
}

func TestKernelListenerDoesNotAcceptNonHelloAsNewSession(t *testing.T) {
	provider, _ := newKernelUDPProviderPair()
	listener := &kernelListener{
		provider: provider,
		endpoint: transport.Endpoint{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolUDP,
		},
		acceptCh:                 make(chan transport.Session, 1),
		done:                     make(chan struct{}),
		sessions:                 make(map[uint64]*kernelSession),
		requireSecureClientHello: true,
	}
	var released atomic.Int32

	listener.dispatch(dataplane.KernelUDPFrame{
		FlowID:    42,
		Direction: dataplane.KernelTransportInbound,
		Endpoint:  core.EndpointID("server"),
		Payload:   []byte("not-a-client-hello"),
		Release:   func() { released.Add(1) },
	})

	if got := released.Load(); got != 1 {
		t.Fatalf("released non-hello frames = %d, want 1", got)
	}
	if len(listener.sessions) != 0 {
		t.Fatalf("listener sessions = %d, want none", len(listener.sessions))
	}
	select {
	case session := <-listener.acceptCh:
		t.Fatalf("accepted session from non-hello frame: %#v", session)
	default:
	}
}

func TestKernelListenerAcceptsClientHelloAsNewSession(t *testing.T) {
	provider, _ := newKernelUDPProviderPair()
	listener := &kernelListener{
		provider: provider,
		endpoint: transport.Endpoint{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolUDP,
		},
		acceptCh:                 make(chan transport.Session, 1),
		done:                     make(chan struct{}),
		sessions:                 make(map[uint64]*kernelSession),
		requireSecureClientHello: true,
	}
	clientHello := make([]byte, 76)
	copy(clientHello[0:4], trustIXSecureHandshakeMagic[:])
	clientHello[4] = 1
	clientHello[5] = 1

	listener.dispatch(dataplane.KernelUDPFrame{
		FlowID:    42,
		Direction: dataplane.KernelTransportInbound,
		Endpoint:  core.EndpointID("server"),
		Payload:   clientHello,
	})

	if len(listener.sessions) != 1 {
		t.Fatalf("listener sessions = %d, want one", len(listener.sessions))
	}
	select {
	case session := <-listener.acceptCh:
		if session == nil {
			t.Fatal("accepted nil session")
		}
	default:
		t.Fatal("listener did not accept client hello")
	}
}

func TestKernelListenerBatchDoesNotAcceptInnerIPv4AsNewSession(t *testing.T) {
	provider, _ := newKernelUDPProviderPair()
	listener := &kernelListener{
		provider: provider,
		endpoint: transport.Endpoint{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolUDP,
		},
		acceptCh:                 make(chan transport.Session, 1),
		done:                     make(chan struct{}),
		sessions:                 make(map[uint64]*kernelSession),
		requireSecureClientHello: true,
	}
	var released atomic.Int32

	listener.dispatchBatch([]dataplane.KernelUDPFrame{
		{
			FlowID:    42,
			Direction: dataplane.KernelTransportInbound,
			Endpoint:  core.EndpointID("server"),
			InnerIPv4: true,
			Payload:   ipv4PacketForKernelUDPTest(40),
			Release:   func() { released.Add(1) },
		},
		{
			FlowID:    43,
			Direction: dataplane.KernelTransportInbound,
			Endpoint:  core.EndpointID("server"),
			Payload:   kernelUDPClientHelloForTest(),
		},
	})

	if got := released.Load(); got != 1 {
		t.Fatalf("released inner IPv4 frames = %d, want 1", got)
	}
	if len(listener.sessions) != 1 {
		t.Fatalf("listener sessions = %d, want one control session", len(listener.sessions))
	}
	select {
	case session := <-listener.acceptCh:
		if session == nil {
			t.Fatal("accepted nil session")
		}
	default:
		t.Fatal("listener did not accept non-inner control frame")
	}
}

func TestKernelListenerBatchAcceptsInnerIPv4AsPlaintextNewSession(t *testing.T) {
	provider, _ := newKernelUDPProviderPair()
	listener := &kernelListener{
		provider: provider,
		endpoint: transport.Endpoint{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolUDP,
		},
		acceptCh: make(chan transport.Session, 1),
		done:     make(chan struct{}),
		sessions: make(map[uint64]*kernelSession),
	}
	packet := ipv4PacketForKernelUDPTest(48)

	listener.dispatchBatch([]dataplane.KernelUDPFrame{{
		FlowID:    42,
		Direction: dataplane.KernelTransportInbound,
		Endpoint:  core.EndpointID("server"),
		InnerIPv4: true,
		Payload:   packet,
	}})

	if len(listener.sessions) != 1 {
		t.Fatalf("listener sessions = %d, want one", len(listener.sessions))
	}
	select {
	case session := <-listener.acceptCh:
		got, err := session.RecvPacket()
		if err != nil {
			t.Fatalf("recv plaintext batch first packet: %v", err)
		}
		if !bytes.Equal(got, packet) {
			t.Fatalf("plaintext batch first packet len=%d, want %d", len(got), len(packet))
		}
	default:
		t.Fatal("listener did not accept plaintext batch inner IPv4 session")
	}
}

func kernelUDPClientHelloForTest() []byte {
	clientHello := make([]byte, 76)
	copy(clientHello[0:4], trustIXSecureHandshakeMagic[:])
	clientHello[4] = 1
	clientHello[5] = 1
	return clientHello
}

func TestKernelSessionSetPeerEndpointAnnotatesFlow(t *testing.T) {
	providerA, _ := newKernelUDPProviderPair()
	flowID := uint64(99)
	providerA.flows[flowID] = dataplane.KernelUDPFlow{
		ID:       flowID,
		Peer:     core.IXID("ix-a"),
		Endpoint: core.EndpointID("ix-b-udp"),
	}
	session := newKernelSession(providerA, nil, flowID, core.IXID("ix-a"), core.EndpointID("ix-b-udp"), dataplane.CryptoPlacementKernel)

	session.SetPeerEndpoint(core.IXID("ix-a"), core.EndpointID("ix-a-udp"))

	providerA.mu.Lock()
	flow := providerA.flows[flowID]
	providerA.mu.Unlock()
	if flow.Peer != "ix-a" || flow.Endpoint != "ix-a-udp" {
		t.Fatalf("annotated flow identity = peer:%q endpoint:%q, want ix-a/ix-a-udp", flow.Peer, flow.Endpoint)
	}
}

func TestSecureTransportKernelCryptoOffloadOverKernelUDPProvider(t *testing.T) {
	providerA, providerB := newKernelUDPProviderPair()
	kernelPlacement := Options{CryptoPlacement: func() dataplane.CryptoPlacement {
		return dataplane.CryptoPlacementKernel
	}}
	clientTransport := securetransport.New(NewWithKernelProvider(providerA, kernelPlacement), securetransport.Options{})
	serverTransport := securetransport.New(NewWithKernelProvider(providerB, kernelPlacement), securetransport.Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := serverTransport.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolUDP,
		Listen:    "198.51.100.2:7000",
		Enabled:   true,
	}, nil)
	if err != nil {
		t.Fatalf("listen kernel udp: %v", err)
	}
	defer listener.Close()

	accepted := make(chan transport.Session, 1)
	go func() {
		session, err := listener.Accept(ctx)
		if err == nil {
			accepted <- session
		}
	}()

	client, err := clientTransport.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolUDP,
			Address:   "198.51.100.2:7000",
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial kernel udp: %v", err)
	}
	defer client.Close()

	var server transport.Session
	select {
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()

	payload := []byte("kernel-udp-offloaded-secret")
	if err := client.SendPacket(payload); err != nil {
		t.Fatalf("client send: %v", err)
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("server received %q", got)
	}
	if bytes.Contains(providerA.lastWirePayload(), payload) {
		t.Fatalf("kernel UDP offload wire payload contains plaintext: %x", providerA.lastWirePayload())
	}
	if stats := client.Stats(); !stats.Encrypted || stats.CryptoPlacement != string(dataplane.CryptoPlacementKernel) {
		t.Fatalf("client stats encrypted=%t placement=%q", stats.Encrypted, stats.CryptoPlacement)
	}
}

func TestSecureTransportKernelUDPDefaultAutoUsesKernelCryptoWhenAvailable(t *testing.T) {
	providerA, providerB := newKernelUDPProviderPair()
	clientTransport := securetransport.New(NewWithKernelProvider(providerA), securetransport.Options{})
	serverTransport := securetransport.New(NewWithKernelProvider(providerB), securetransport.Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := serverTransport.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolUDP,
		Listen:    "198.51.100.2:7000",
		Enabled:   true,
	}, nil)
	if err != nil {
		t.Fatalf("listen kernel udp: %v", err)
	}
	defer listener.Close()

	accepted := make(chan transport.Session, 1)
	go func() {
		session, err := listener.Accept(ctx)
		if err == nil {
			accepted <- session
		}
	}()

	client, err := clientTransport.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolUDP,
			Address:   "198.51.100.2:7000",
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial kernel udp: %v", err)
	}
	defer client.Close()

	var server transport.Session
	select {
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()

	payload := []byte("kernel-udp-default-auto-secret")
	if err := client.SendPacket(payload); err != nil {
		t.Fatalf("client send: %v", err)
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("server received %q", got)
	}
	if bytes.Contains(providerA.lastWirePayload(), payload) {
		t.Fatalf("kernel UDP default-auto wire payload contains plaintext: %x", providerA.lastWirePayload())
	}
	if stats := client.Stats(); !stats.Encrypted || stats.CryptoPlacement != string(dataplane.CryptoPlacementKernel) {
		t.Fatalf("client stats encrypted=%t placement=%q", stats.Encrypted, stats.CryptoPlacement)
	}
}

func TestSecureTransportKernelUDPAutoUsesKernelCryptoWhenAvailable(t *testing.T) {
	providerA, providerB := newKernelUDPProviderPair()
	autoPlacement := Options{CryptoPlacement: func() dataplane.CryptoPlacement {
		return dataplane.CryptoPlacementAuto
	}}
	clientTransport := securetransport.New(NewWithKernelProvider(providerA, autoPlacement), securetransport.Options{})
	serverTransport := securetransport.New(NewWithKernelProvider(providerB, autoPlacement), securetransport.Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := serverTransport.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolUDP,
		Listen:    "198.51.100.2:7000",
		Enabled:   true,
	}, nil)
	if err != nil {
		t.Fatalf("listen kernel udp: %v", err)
	}
	defer listener.Close()

	accepted := make(chan transport.Session, 1)
	go func() {
		session, err := listener.Accept(ctx)
		if err == nil {
			accepted <- session
		}
	}()

	client, err := clientTransport.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolUDP,
			Address:   "198.51.100.2:7000",
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial kernel udp: %v", err)
	}
	defer client.Close()

	var server transport.Session
	select {
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()

	payload := []byte("kernel-udp-auto-secret")
	if err := client.SendPacket(payload); err != nil {
		t.Fatalf("client send: %v", err)
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("server received %q", got)
	}
	if bytes.Contains(providerA.lastWirePayload(), payload) {
		t.Fatalf("kernel UDP auto wire payload contains plaintext: %x", providerA.lastWirePayload())
	}
	if stats := client.Stats(); !stats.Encrypted || stats.CryptoPlacement != string(dataplane.CryptoPlacementKernel) {
		t.Fatalf("client stats encrypted=%t placement=%q", stats.Encrypted, stats.CryptoPlacement)
	}
}

func TestKernelUDPPlaintextAutoKeepsKernelTransportWithoutCryptoPlacement(t *testing.T) {
	providerA, _ := newKernelUDPProviderPair()
	tr := NewWithKernelProvider(providerA, Options{
		CryptoPlacement: func() dataplane.CryptoPlacement {
			return dataplane.CryptoPlacementAuto
		},
		Encryption: func() string {
			return "none"
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session, err := tr.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolUDP,
			Address:   "198.51.100.2:7000",
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial kernel udp: %v", err)
	}
	defer session.Close()

	providerA.mu.Lock()
	defer providerA.mu.Unlock()
	if len(providerA.flows) != 1 {
		t.Fatalf("installed flows = %d, want 1", len(providerA.flows))
	}
	for _, flow := range providerA.flows {
		if flow.CryptoPlacement != dataplane.CryptoPlacementUserspace {
			t.Fatalf("plaintext flow crypto placement = %q, want userspace/no crypto", flow.CryptoPlacement)
		}
	}
}

func TestKernelUDPPlaintextTCOnlyDialInstallsFlowWithoutSubscription(t *testing.T) {
	providerA, _ := newKernelUDPProviderPair()
	providerA.tcOnly = true
	tr := NewWithKernelProvider(providerA, Options{
		Encryption: func() string {
			return "none"
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session, err := tr.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolUDP,
			Address:   "198.51.100.2:7000",
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial kernel udp: %v", err)
	}

	providerA.mu.Lock()
	if len(providerA.flows) != 1 {
		providerA.mu.Unlock()
		t.Fatalf("installed flows = %d, want 1", len(providerA.flows))
	}
	if providerA.subscribeCalls != 0 || providerA.flowSubscribeCalls != 0 {
		providerA.mu.Unlock()
		t.Fatalf("subscriptions global=%d flow=%d, want none for TC-only plaintext", providerA.subscribeCalls, providerA.flowSubscribeCalls)
	}
	for _, flow := range providerA.flows {
		if flow.CryptoPlacement != dataplane.CryptoPlacementUserspace {
			providerA.mu.Unlock()
			t.Fatalf("plaintext TC-only flow crypto placement = %q, want userspace/no crypto", flow.CryptoPlacement)
		}
	}
	providerA.mu.Unlock()
	if err := session.Close(); err != nil {
		t.Fatalf("close session: %v", err)
	}
	providerA.mu.Lock()
	defer providerA.mu.Unlock()
	if len(providerA.flows) != 0 {
		t.Fatalf("installed flows after close = %d, want closed TC-only seed removed", len(providerA.flows))
	}
}

func TestKernelUDPPlaintextPendingTCOnlyDialInstallsFlowWithoutSubscription(t *testing.T) {
	providerA, _ := newKernelUDPProviderPair()
	providerA.available = false
	providerA.tcOnly = true
	tr := NewWithKernelProvider(providerA, Options{
		KernelTransport: func() dataplane.KernelTransportMode {
			return dataplane.KernelTransportModeRequireKernel
		},
		Encryption: func() string {
			return "none"
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session, err := tr.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolUDP,
			Address:   "198.51.100.2:7000",
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial pending TC-only kernel udp: %v", err)
	}

	providerA.mu.Lock()
	if len(providerA.flows) != 1 {
		providerA.mu.Unlock()
		t.Fatalf("installed flows = %d, want 1", len(providerA.flows))
	}
	if providerA.subscribeCalls != 0 || providerA.flowSubscribeCalls != 0 {
		providerA.mu.Unlock()
		t.Fatalf("subscriptions global=%d flow=%d, want none for pending TC-only plaintext", providerA.subscribeCalls, providerA.flowSubscribeCalls)
	}
	for _, flow := range providerA.flows {
		if flow.CryptoPlacement != dataplane.CryptoPlacementUserspace {
			providerA.mu.Unlock()
			t.Fatalf("pending plaintext TC-only flow crypto placement = %q, want userspace/no crypto", flow.CryptoPlacement)
		}
	}
	providerA.mu.Unlock()
	if err := session.Close(); err != nil {
		t.Fatalf("close session: %v", err)
	}
}

func TestKernelUDPPlaintextPendingTCOnlyRequireKernelProbeIsHealthy(t *testing.T) {
	providerA, _ := newKernelUDPProviderPair()
	providerA.available = false
	providerA.tcOnly = true
	tr := NewWithKernelProvider(providerA, Options{
		KernelTransport: func() dataplane.KernelTransportMode {
			return dataplane.KernelTransportModeRequireKernel
		},
		Encryption: func() string {
			return "none"
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := tr.Probe(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolUDP,
			Address:   "198.51.100.2:7000",
		}},
	})
	if !result.Healthy {
		t.Fatalf("pending TC-only plaintext probe unhealthy: %#v", result)
	}
}

func TestKernelUDPSecurePendingTCOnlyDialInstallsKernelFlowWithControlSubscription(t *testing.T) {
	providerA, _ := newKernelUDPProviderPair()
	providerA.available = false
	providerA.tcOnly = true
	tr := NewWithKernelProvider(providerA, Options{
		KernelTransport: func() dataplane.KernelTransportMode {
			return dataplane.KernelTransportModeRequireKernel
		},
		Encryption: func() string {
			return "secure"
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session, err := tr.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolUDP,
			Address:   "198.51.100.2:7000",
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial secure pending TC-only kernel udp: %v", err)
	}
	providerA.mu.Lock()
	if len(providerA.flows) != 1 {
		providerA.mu.Unlock()
		t.Fatalf("installed flows = %d, want 1", len(providerA.flows))
	}
	if providerA.subscribeCalls != 0 || providerA.flowSubscribeCalls != 1 {
		providerA.mu.Unlock()
		t.Fatalf("subscriptions global=%d flow=%d, want one flow control subscription for secure pending TC-only", providerA.subscribeCalls, providerA.flowSubscribeCalls)
	}
	for _, flow := range providerA.flows {
		if flow.CryptoPlacement != dataplane.CryptoPlacementKernel {
			providerA.mu.Unlock()
			t.Fatalf("secure pending TC-only flow crypto placement = %q, want kernel", flow.CryptoPlacement)
		}
	}
	providerA.mu.Unlock()
	if err := session.Close(); err != nil {
		t.Fatalf("close session: %v", err)
	}
}

func TestKernelUDPPlaintextPendingTCOnlyListenDoesNotRequireReinjectYet(t *testing.T) {
	providerA, _ := newKernelUDPProviderPair()
	providerA.available = false
	providerA.tcOnly = true
	tr := NewWithKernelProvider(providerA, Options{
		KernelTransport: func() dataplane.KernelTransportMode {
			return dataplane.KernelTransportModeRequireKernel
		},
		Encryption: func() string {
			return "none"
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := tr.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolUDP,
		Listen:    "198.51.100.2:7000",
		Enabled:   true,
	}, nil)
	if err != nil {
		t.Fatalf("listen pending TC-only kernel udp: %v", err)
	}
	defer listener.Close()

	providerA.mu.Lock()
	defer providerA.mu.Unlock()
	if providerA.subscribeCalls != 0 || providerA.flowSubscribeCalls != 0 {
		t.Fatalf("subscriptions global=%d flow=%d, want none for pending TC-only plaintext listener", providerA.subscribeCalls, providerA.flowSubscribeCalls)
	}
}

func TestKernelUDPSecurePendingTCOnlyListenDoesNotRequireReinjectYet(t *testing.T) {
	providerA, _ := newKernelUDPProviderPair()
	providerA.available = false
	providerA.tcOnly = true
	tr := NewWithKernelProvider(providerA, Options{
		KernelTransport: func() dataplane.KernelTransportMode {
			return dataplane.KernelTransportModeRequireKernel
		},
		Encryption: func() string {
			return "secure"
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := tr.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolUDP,
		Listen:    "198.51.100.2:7000",
		Enabled:   true,
	}, nil)
	if err != nil {
		t.Fatalf("listen secure pending TC-only kernel udp: %v", err)
	}
	defer listener.Close()

	kernelListener, ok := listener.(*kernelListener)
	if !ok {
		t.Fatalf("listener type = %T, want *kernelListener", listener)
	}
	if kernelListener.placement != dataplane.CryptoPlacementKernel {
		t.Fatalf("secure pending TC-only listener placement = %q, want kernel", kernelListener.placement)
	}
	providerA.mu.Lock()
	defer providerA.mu.Unlock()
	if providerA.subscribeCalls != 1 || providerA.flowSubscribeCalls != 0 {
		t.Fatalf("subscriptions global=%d flow=%d, want one global control subscription for secure pending TC-only listener", providerA.subscribeCalls, providerA.flowSubscribeCalls)
	}
}

func TestKernelUDPRejectsKernelCryptoWhenUnavailable(t *testing.T) {
	providerA, _ := newKernelUDPProviderPair()
	providerA.kernelCrypto = false
	tr := NewWithKernelProvider(providerA, Options{CryptoPlacement: func() dataplane.CryptoPlacement {
		return dataplane.CryptoPlacementKernel
	}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := tr.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolUDP,
			Address:   "198.51.100.2:7000",
		}},
	}, nil)
	if err == nil {
		t.Fatal("expected kernel crypto placement failure")
	}
}

func TestKernelUDPAutoPrefersKernelCryptoWhenBothPlacementsAvailable(t *testing.T) {
	placement, err := selectCryptoPlacement(dataplane.CryptoPlacementAuto, dataplane.KernelUDPStatus{
		UserspaceCrypto: true,
		KernelCrypto:    true,
		PreferredCrypto: dataplane.CryptoPlacementUserspace,
	})
	if err != nil {
		t.Fatalf("select crypto placement: %v", err)
	}
	if placement != dataplane.CryptoPlacementKernel {
		t.Fatalf("auto crypto placement = %q, want kernel", placement)
	}
}

func TestKernelUDPStatusTCOnlySecureKernelManagedWithoutDirectOnlyFlag(t *testing.T) {
	status := dataplane.KernelUDPStatus{
		TCOnly:       true,
		KernelCrypto: true,
	}
	if !kernelUDPStatusDirectOnlyKernelManaged(status, "secure", dataplane.CryptoPlacementKernel) {
		t.Fatal("TC-only secure kernel crypto status should be treated as kernel-managed even without direct-only flag")
	}
	if kernelUDPStatusDirectOnlyKernelManaged(status, "secure", dataplane.CryptoPlacementUserspace) {
		t.Fatal("TC-only secure userspace crypto status should not be treated as kernel-managed")
	}
}

func TestSecureTransportKernelUDPTCOnlyUsesControlSubscriptionAndKernelCrypto(t *testing.T) {
	providerA, providerB := newKernelUDPProviderPair()
	providerA.tcOnly = true
	providerB.tcOnly = true
	clientTransport := securetransport.New(NewWithKernelProvider(providerA), securetransport.Options{})
	serverTransport := securetransport.New(NewWithKernelProvider(providerB), securetransport.Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := serverTransport.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolUDP,
		Listen:    "198.51.100.2:7000",
		Enabled:   true,
	}, nil)
	if err != nil {
		t.Fatalf("listen secure TC-only kernel udp: %v", err)
	}
	defer listener.Close()

	accepted := make(chan transport.Session, 1)
	acceptErr := make(chan error, 1)
	go func() {
		session, err := listener.Accept(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- session
	}()

	client, err := clientTransport.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolUDP,
			Address:   "198.51.100.2:7000",
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial secure TC-only kernel udp: %v", err)
	}
	defer client.Close()

	var server transport.Session
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		t.Fatalf("accept secure TC-only kernel udp: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()

	payload := []byte("secure-tc-only-control")
	if err := client.SendPacket(payload); err != nil {
		t.Fatalf("client send: %v", err)
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("server received %q, want %q", got, payload)
	}
	if stats := client.Stats(); !stats.Encrypted || stats.CryptoPlacement != string(dataplane.CryptoPlacementKernel) {
		t.Fatalf("client stats encrypted=%t placement=%q, want kernel crypto", stats.Encrypted, stats.CryptoPlacement)
	}
	providerA.mu.Lock()
	aFlowSubs := providerA.flowSubscribeCalls
	providerA.mu.Unlock()
	providerB.mu.Lock()
	bSubs := providerB.subscribeCalls
	providerB.mu.Unlock()
	if aFlowSubs == 0 || bSubs == 0 {
		t.Fatalf("control subscriptions client flow=%d server global=%d, want both non-zero", aFlowSubs, bSubs)
	}
}

func TestSecureTransportKernelUDPUsesUserspaceCryptoWhenProviderUnavailable(t *testing.T) {
	providerA, providerB := newKernelUDPProviderPair()
	providerA.kernelCrypto = false
	providerB.kernelCrypto = false
	clientTransport := securetransport.New(NewWithKernelProvider(providerA), securetransport.Options{})
	serverTransport := securetransport.New(NewWithKernelProvider(providerB), securetransport.Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := serverTransport.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolUDP,
		Listen:    "198.51.100.2:7000",
		Enabled:   true,
	}, nil)
	if err != nil {
		t.Fatalf("listen kernel udp: %v", err)
	}
	defer listener.Close()

	accepted := make(chan transport.Session, 1)
	go func() {
		session, err := listener.Accept(ctx)
		if err == nil {
			accepted <- session
		}
	}()

	client, err := clientTransport.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolUDP,
			Address:   "198.51.100.2:7000",
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial kernel udp: %v", err)
	}
	defer client.Close()

	var server transport.Session
	select {
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()

	payload := []byte("kernel-udp-userspace-secret")
	if err := client.SendPacket(payload); err != nil {
		t.Fatalf("client send: %v", err)
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("server received %q", got)
	}
	if stats := client.Stats(); !stats.Encrypted || stats.CryptoPlacement != string(dataplane.CryptoPlacementUserspace) {
		t.Fatalf("client stats encrypted=%t placement=%q", stats.Encrypted, stats.CryptoPlacement)
	}
}

func dialUDPClient(t *testing.T, ctx context.Context, tr *Transport, addr string) transport.Session {
	t.Helper()
	client, err := tr.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-client"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{
			{Name: core.EndpointID("server"), Transport: transport.ProtocolUDP, Address: addr},
		},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return client
}

func assertRecvPacket(t *testing.T, session transport.Session, want string) {
	t.Helper()
	packet, err := session.RecvPacket()
	if err != nil {
		t.Fatalf("recv %s: %v", want, err)
	}
	if string(packet) != want {
		t.Fatalf("received %q, want %q", packet, want)
	}
}

func freeUDPAddr(t *testing.T) string {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve udp addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("reserve udp addr: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().String()
}

func TestKernelUDPDialCarriesLocalBindSourceIP(t *testing.T) {
	provider, _ := newKernelUDPProviderPair()
	tr := NewWithKernelProvider(provider)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := tr.Dial(ctx, transport.Peer{
		ID: core.IXID("ix-b"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolUDP,
			Address:   "198.51.100.2:17041",
			LocalBind: transport.LocalBind{SourceIP: "192.0.2.10"},
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer session.Close()
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if len(provider.flows) != 1 {
		t.Fatalf("installed flows = %d, want 1", len(provider.flows))
	}
	for _, flow := range provider.flows {
		if flow.LocalAddress != "192.0.2.10" {
			t.Fatalf("flow local address = %q, want 192.0.2.10", flow.LocalAddress)
		}
	}
}

type fakeKernelUDPProvider struct {
	mu                 sync.Mutex
	remote             *fakeKernelUDPProvider
	subs               map[chan dataplane.KernelUDPFrame]struct{}
	flowSubs           map[uint64]map[chan dataplane.KernelUDPFrame]struct{}
	flows              map[uint64]dataplane.KernelUDPFlow
	cryptos            map[uint64]fakeKernelUDPCrypto
	lastWire           []byte
	delivered          []dataplane.KernelUDPFrame
	available          bool
	kernelCrypto       bool
	tcOnly             bool
	payloadMax         int
	submitted          uint64
	received           uint64
	subscribeCalls     int
	flowSubscribeCalls int
}

func newKernelUDPProviderPair() (*fakeKernelUDPProvider, *fakeKernelUDPProvider) {
	a := &fakeKernelUDPProvider{subs: make(map[chan dataplane.KernelUDPFrame]struct{}), flowSubs: make(map[uint64]map[chan dataplane.KernelUDPFrame]struct{}), flows: make(map[uint64]dataplane.KernelUDPFlow), cryptos: make(map[uint64]fakeKernelUDPCrypto), available: true, kernelCrypto: true}
	b := &fakeKernelUDPProvider{subs: make(map[chan dataplane.KernelUDPFrame]struct{}), flowSubs: make(map[uint64]map[chan dataplane.KernelUDPFrame]struct{}), flows: make(map[uint64]dataplane.KernelUDPFlow), cryptos: make(map[uint64]fakeKernelUDPCrypto), available: true, kernelCrypto: true}
	a.remote = b
	b.remote = a
	return a, b
}

func (provider *fakeKernelUDPProvider) KernelUDPStatus(ctx context.Context) (dataplane.KernelUDPStatus, error) {
	if err := ctx.Err(); err != nil {
		return dataplane.KernelUDPStatus{}, err
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	tcOnly := provider.available && provider.tcOnly
	fastPath := provider.available && !tcOnly
	userspaceCrypto := true
	if provider.tcOnly {
		userspaceCrypto = false
	}
	providerName := "fake"
	if !provider.available {
		providerName = "none"
	} else if provider.tcOnly {
		providerName = "tc_direct"
	}
	return dataplane.KernelUDPStatus{
		Available:       provider.available,
		Provider:        providerName,
		FastPath:        fastPath,
		DirectOnly:      provider.tcOnly,
		TCOnly:          tcOnly,
		UserspaceCrypto: userspaceCrypto,
		KernelCrypto:    provider.kernelCrypto,
		Reinject:        provider.available,
		PreferredCrypto: provider.preferredCrypto(),
		SupportedCrypto: provider.supportedCrypto(),
		ActiveFlows:     len(provider.flows),
		SubmittedFrames: provider.submitted,
		ReceivedFrames:  provider.received,
	}, nil
}

func (provider *fakeKernelUDPProvider) preferredCrypto() dataplane.CryptoPlacement {
	if provider.kernelCrypto {
		return dataplane.CryptoPlacementKernel
	}
	return dataplane.CryptoPlacementUserspace
}

func (provider *fakeKernelUDPProvider) supportedCrypto() []dataplane.CryptoPlacement {
	if provider.kernelCrypto {
		return []dataplane.CryptoPlacement{dataplane.CryptoPlacementUserspace, dataplane.CryptoPlacementKernel}
	}
	return []dataplane.CryptoPlacement{dataplane.CryptoPlacementUserspace}
}

func (provider *fakeKernelUDPProvider) KernelUDPPayloadMax(ctx context.Context, placement dataplane.CryptoPlacement, encrypted bool) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return provider.payloadMax, nil
}

func (provider *fakeKernelUDPProvider) KernelUDPSealBeforeFragmentMax(ctx context.Context, placement dataplane.CryptoPlacement) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return kernelUDPSealBeforeFragmentMax, nil
}

func (provider *fakeKernelUDPProvider) InstallKernelUDPFlows(ctx context.Context, flows []dataplane.KernelUDPFlow) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if !provider.available && !provider.tcOnly {
		return fmt.Errorf("kernel udp unavailable")
	}
	for _, flow := range flows {
		provider.flows[flow.ID] = flow
	}
	return nil
}

func (provider *fakeKernelUDPProvider) InstallKernelUDPCrypto(ctx context.Context, specs []dataplane.KernelUDPCryptoSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if !provider.kernelCrypto {
		return fmt.Errorf("kernel udp crypto unavailable")
	}
	for _, spec := range specs {
		cryptoState, err := newFakeKernelUDPCrypto(spec)
		if err != nil {
			return err
		}
		provider.cryptos[spec.FlowID] = cryptoState
		flow := provider.flows[spec.FlowID]
		flow.ID = spec.FlowID
		flow.Epoch = spec.Epoch
		flow.CryptoSuite = spec.Suite
		flow.CryptoPlacement = dataplane.CryptoPlacementKernel
		provider.flows[spec.FlowID] = flow
	}
	return nil
}

func (provider *fakeKernelUDPProvider) DeleteKernelUDPFlows(ctx context.Context, flowIDs []uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	for _, flowID := range flowIDs {
		delete(provider.flows, flowID)
	}
	return nil
}

func (provider *fakeKernelUDPProvider) SetKernelUDPFlowPeer(ctx context.Context, flowID uint64, peer core.IXID, endpoint core.EndpointID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	flow := provider.flows[flowID]
	flow.ID = flowID
	if peer != "" {
		flow.Peer = peer
	}
	if endpoint != "" {
		flow.Endpoint = endpoint
	}
	provider.flows[flowID] = flow
	return nil
}

func (provider *fakeKernelUDPProvider) SubmitKernelUDPFrame(ctx context.Context, frame dataplane.KernelUDPFrame) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	provider.mu.Lock()
	flow, ok := provider.flows[frame.FlowID]
	if ok {
		frame.Peer = flow.Peer
		frame.Endpoint = flow.Endpoint
	}
	provider.submitted++
	provider.mu.Unlock()
	if !ok {
		return fmt.Errorf("kernel udp flow %d is not installed", frame.FlowID)
	}
	inbound := frame
	if frame.CryptoPlacement == dataplane.CryptoPlacementKernel {
		provider.mu.Lock()
		cryptoState, ok := provider.cryptos[frame.FlowID]
		provider.mu.Unlock()
		if !ok {
			return fmt.Errorf("kernel udp crypto for flow %d is not installed", frame.FlowID)
		}
		wire, err := cryptoState.seal(frame.Sequence, frame.Payload)
		if err != nil {
			return err
		}
		inbound.Payload = wire
		inbound.Encrypted = true
		provider.mu.Lock()
		provider.lastWire = append(provider.lastWire[:0], wire...)
		provider.mu.Unlock()
	}
	inbound.Direction = dataplane.KernelTransportInbound
	provider.remote.deliver(inbound)
	return nil
}

func (provider *fakeKernelUDPProvider) SubscribeKernelUDP(ctx context.Context, buffer int) (dataplane.KernelUDPSubscription, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if buffer <= 0 {
		buffer = 1
	}
	events := make(chan dataplane.KernelUDPFrame, buffer)
	provider.mu.Lock()
	provider.subscribeCalls++
	provider.subs[events] = struct{}{}
	provider.mu.Unlock()
	return &fakeKernelUDPSubscription{provider: provider, events: events}, nil
}

func (provider *fakeKernelUDPProvider) SubscribeKernelUDPFlow(ctx context.Context, flowID uint64, buffer int) (dataplane.KernelUDPSubscription, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if flowID == 0 {
		return nil, fmt.Errorf("kernel udp flow subscription requires non-zero flow id")
	}
	if buffer <= 0 {
		buffer = 1
	}
	events := make(chan dataplane.KernelUDPFrame, buffer)
	provider.mu.Lock()
	provider.flowSubscribeCalls++
	if provider.flowSubs == nil {
		provider.flowSubs = make(map[uint64]map[chan dataplane.KernelUDPFrame]struct{})
	}
	subs := provider.flowSubs[flowID]
	if subs == nil {
		subs = make(map[chan dataplane.KernelUDPFrame]struct{})
		provider.flowSubs[flowID] = subs
	}
	subs[events] = struct{}{}
	provider.mu.Unlock()
	return &fakeKernelUDPSubscription{provider: provider, events: events, flowID: flowID}, nil
}

func (provider *fakeKernelUDPProvider) deliver(frame dataplane.KernelUDPFrame) {
	provider.mu.Lock()
	if _, ok := provider.flows[frame.FlowID]; !ok {
		provider.flows[frame.FlowID] = dataplane.KernelUDPFlow{
			ID:       frame.FlowID,
			Peer:     frame.Peer,
			Endpoint: frame.Endpoint,
		}
	}
	if frame.Encrypted && frame.CryptoPlacement == dataplane.CryptoPlacementKernel {
		cryptoState, ok := provider.cryptos[frame.FlowID]
		if !ok {
			provider.mu.Unlock()
			return
		}
		plaintext, err := cryptoState.open(frame.Payload)
		if err != nil {
			provider.mu.Unlock()
			return
		}
		frame.Payload = plaintext
	}
	provider.received++
	provider.delivered = append(provider.delivered, frame)
	deliveredToFlow := false
	for sub := range provider.flowSubs[frame.FlowID] {
		deliveredToFlow = true
		select {
		case sub <- frame:
		default:
		}
	}
	if !deliveredToFlow {
		for sub := range provider.subs {
			select {
			case sub <- frame:
			default:
			}
		}
	}
	provider.mu.Unlock()
}

func (provider *fakeKernelUDPProvider) lastWirePayload() []byte {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return append([]byte(nil), provider.lastWire...)
}

func (provider *fakeKernelUDPProvider) deliveredFrames() []dataplane.KernelUDPFrame {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return append([]dataplane.KernelUDPFrame(nil), provider.delivered...)
}

type fakeKernelUDPCrypto struct {
	epoch    uint64
	suiteID  byte
	sendIV   []byte
	recvIV   []byte
	sendAEAD cipher.AEAD
	recvAEAD cipher.AEAD
}

func newFakeKernelUDPCrypto(spec dataplane.KernelUDPCryptoSpec) (fakeKernelUDPCrypto, error) {
	sendAEAD, err := fakeKernelUDPAEAD(spec.SendKey)
	if err != nil {
		return fakeKernelUDPCrypto{}, err
	}
	recvAEAD, err := fakeKernelUDPAEAD(spec.RecvKey)
	if err != nil {
		return fakeKernelUDPCrypto{}, err
	}
	if len(spec.SendIV) != 12 || len(spec.RecvIV) != 12 {
		return fakeKernelUDPCrypto{}, fmt.Errorf("invalid IV length")
	}
	suiteID, err := fakeKernelUDPSuiteID(spec.Suite)
	if err != nil {
		return fakeKernelUDPCrypto{}, err
	}
	return fakeKernelUDPCrypto{
		epoch:    spec.Epoch,
		suiteID:  suiteID,
		sendIV:   append([]byte(nil), spec.SendIV...),
		recvIV:   append([]byte(nil), spec.RecvIV...),
		sendAEAD: sendAEAD,
		recvAEAD: recvAEAD,
	}, nil
}

func fakeKernelUDPAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (cryptoState fakeKernelUDPCrypto) seal(seq uint64, plaintext []byte) ([]byte, error) {
	header := fakeKernelUDPSecureHeader(cryptoState.suiteID, cryptoState.epoch, seq)
	nonce := fakeKernelUDPNonce(cryptoState.sendIV, seq)
	return cryptoState.sendAEAD.Seal(header, nonce, plaintext, header), nil
}

func (cryptoState fakeKernelUDPCrypto) open(wire []byte) ([]byte, error) {
	if len(wire) < 24 {
		return nil, fmt.Errorf("wire packet too short")
	}
	header := wire[:24]
	seq := binary.BigEndian.Uint64(header[16:24])
	nonce := fakeKernelUDPNonce(cryptoState.recvIV, seq)
	return cryptoState.recvAEAD.Open(nil, nonce, wire[24:], header)
}

func fakeKernelUDPSuiteID(suite string) (byte, error) {
	switch suite {
	case securetransport.SuiteAES256GCMX25519:
		return 1, nil
	case securetransport.SuiteAES128GCMX25519:
		return 2, nil
	default:
		return 0, fmt.Errorf("fake kernel udp crypto suite %q is unsupported", suite)
	}
}

func fakeKernelUDPSecureHeader(suiteID byte, epoch, seq uint64) []byte {
	header := make([]byte, 24)
	copy(header[0:4], []byte{'T', 'I', 'X', 'D'})
	header[4] = 1
	header[5] = suiteID
	binary.BigEndian.PutUint64(header[8:16], epoch)
	binary.BigEndian.PutUint64(header[16:24], seq)
	return header
}

func fakeKernelUDPNonce(prefix []byte, seq uint64) []byte {
	nonce := make([]byte, 12)
	copy(nonce, prefix)
	binary.BigEndian.PutUint64(nonce[4:], seq)
	return nonce
}

type fakeKernelUDPSubscription struct {
	provider *fakeKernelUDPProvider
	events   chan dataplane.KernelUDPFrame
	flowID   uint64
	once     sync.Once
}

func (subscription *fakeKernelUDPSubscription) Events() <-chan dataplane.KernelUDPFrame {
	return subscription.events
}

func (subscription *fakeKernelUDPSubscription) Close() error {
	subscription.once.Do(func() {
		subscription.provider.mu.Lock()
		if subscription.flowID != 0 {
			if subs := subscription.provider.flowSubs[subscription.flowID]; subs != nil {
				delete(subs, subscription.events)
				if len(subs) == 0 {
					delete(subscription.provider.flowSubs, subscription.flowID)
				}
			}
		} else {
			delete(subscription.provider.subs, subscription.events)
		}
		close(subscription.events)
		subscription.provider.mu.Unlock()
	})
	return nil
}
