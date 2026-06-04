package websocket

import (
	"context"
	"net"
	"testing"
	"time"

	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/transport"
)

func TestTransportSendReceive(t *testing.T) {
	addr := freeTCPAddr(t)
	tr := New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := tr.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolWebSocket,
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
			{Name: core.EndpointID("server"), Transport: transport.ProtocolWebSocket, Address: addr},
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

func TestTransportSendPacketsBatch(t *testing.T) {
	addr := freeTCPAddr(t)
	tr := New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := tr.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolWebSocket,
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
			{Name: core.EndpointID("server"), Transport: transport.ProtocolWebSocket, Address: addr},
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
		t.Fatal("websocket session does not implement PacketBatchSession")
	}
	if !client.Stats().NativeBatching {
		t.Fatal("websocket session should advertise NativeBatching")
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

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve tcp addr: %v", err)
	}
	defer ln.Close()
	return ln.Addr().String()
}
