package quic

import (
	"context"
	"net"
	"testing"
	"time"

	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/transport"
	securetransport "trustix.local/trustix/internal/transport/secure"
	"trustix.local/trustix/internal/transport/stream"
)

func TestTransportSendReceive(t *testing.T) {
	addr := freeUDPAddr(t)
	tr := New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := tr.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolQUIC,
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
			{Name: core.EndpointID("server"), Transport: transport.ProtocolQUIC, Address: addr},
		},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	server := acceptSession(t, ctx, accepted, acceptErr)
	defer server.Close()

	assertPacketRoundTrip(t, client, server)
}

func TestQUICConfigUsesThroughputWindows(t *testing.T) {
	conf := quicConfig()
	if conf.InitialStreamReceiveWindow != quicInitialStreamReceiveWindow {
		t.Fatalf("InitialStreamReceiveWindow = %d, want %d", conf.InitialStreamReceiveWindow, quicInitialStreamReceiveWindow)
	}
	if conf.MaxStreamReceiveWindow != quicMaxStreamReceiveWindow {
		t.Fatalf("MaxStreamReceiveWindow = %d, want %d", conf.MaxStreamReceiveWindow, quicMaxStreamReceiveWindow)
	}
	if conf.InitialConnectionReceiveWindow != quicInitialConnectionReceiveWindow {
		t.Fatalf("InitialConnectionReceiveWindow = %d, want %d", conf.InitialConnectionReceiveWindow, quicInitialConnectionReceiveWindow)
	}
	if conf.MaxConnectionReceiveWindow != quicMaxConnectionReceiveWindow {
		t.Fatalf("MaxConnectionReceiveWindow = %d, want %d", conf.MaxConnectionReceiveWindow, quicMaxConnectionReceiveWindow)
	}
}

func TestTransportSendPacketsBatch(t *testing.T) {
	addr := freeUDPAddr(t)
	tr := New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := tr.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolQUIC,
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
			{Name: core.EndpointID("server"), Transport: transport.ProtocolQUIC, Address: addr},
		},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	var server transport.Session
	select {
	case err := <-acceptErr:
		t.Fatalf("accept: %v", err)
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()

	batch, ok := client.(transport.PacketBatchSession)
	if !ok {
		t.Fatal("quic session does not implement PacketBatchSession")
	}
	if !client.Stats().NativeBatching {
		t.Fatal("quic session should advertise NativeBatching")
	}
	if stats := client.Stats(); !stats.Datagram || stats.MaxPacketSize != uint64(stream.MaxPacketSize) {
		t.Fatalf("quic stats datagram=%t max_packet_size=%d, want true/%d", stats.Datagram, stats.MaxPacketSize, stream.MaxPacketSize)
	}
	packets := [][]byte{[]byte("one"), []byte("two"), []byte("three")}
	if err := batch.SendPackets(packets); err != nil {
		t.Fatalf("send batch: %v", err)
	}
	for i, want := range packets {
		got, err := server.RecvPacket()
		if err != nil {
			t.Fatalf("recv packet %d: %v", i, err)
		}
		if string(got) != string(want) {
			t.Fatalf("recv packet %d = %q, want %q", i, got, want)
		}
	}
}

func TestSecureTransportReportsEncrypted(t *testing.T) {
	addr := freeUDPAddr(t)
	tr := securetransport.New(New(), securetransport.Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := tr.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolQUIC,
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
			{Name: core.EndpointID("server"), Transport: transport.ProtocolQUIC, Address: addr},
		},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	server := acceptSession(t, ctx, accepted, acceptErr)
	defer server.Close()

	assertPacketRoundTrip(t, client, server)
	if stats := client.Stats(); !stats.Encrypted || stats.CryptoSuite != securetransport.SuiteAES256GCMX25519 {
		t.Fatalf("secure wrapper stats = %+v, want encrypted %s", stats, securetransport.SuiteAES256GCMX25519)
	}
}

func acceptSession(t *testing.T, ctx context.Context, accepted <-chan transport.Session, acceptErr <-chan error) transport.Session {
	t.Helper()
	select {
	case err := <-acceptErr:
		t.Fatalf("accept: %v", err)
	case session := <-accepted:
		return session
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	return nil
}

func assertPacketRoundTrip(t *testing.T, client transport.Session, server transport.Session) {
	t.Helper()
	if err := client.SendPacket([]byte("hello")); err != nil {
		t.Fatalf("send hello: %v", err)
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

func freeUDPAddr(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve udp addr: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().String()
}
