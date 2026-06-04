package bind

import (
	"context"
	"net"
	"testing"
	"time"

	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/transport"
)

func TestDialerSetsTCPSourceIP(t *testing.T) {
	endpoint := transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolTCP,
		Address:   "127.0.0.1:1",
		LocalBind: transport.LocalBind{SourceIP: "127.0.0.1"},
	}
	dialer, err := Dialer(endpoint, "tcp")
	if err != nil {
		t.Fatalf("dialer: %v", err)
	}
	addr, ok := dialer.LocalAddr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("local addr = %T, want *net.TCPAddr", dialer.LocalAddr)
	}
	if got := addr.IP.String(); got != "127.0.0.1" {
		t.Fatalf("local IP = %s, want 127.0.0.1", got)
	}
}

func TestDialerSetsUDPSourceIP(t *testing.T) {
	endpoint := transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolUDP,
		Address:   "127.0.0.1:1",
		LocalBind: transport.LocalBind{SourceIP: "127.0.0.1"},
	}
	dialer, err := Dialer(endpoint, "udp")
	if err != nil {
		t.Fatalf("dialer: %v", err)
	}
	addr, ok := dialer.LocalAddr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("local addr = %T, want *net.UDPAddr", dialer.LocalAddr)
	}
	if got := addr.IP.String(); got != "127.0.0.1" {
		t.Fatalf("local IP = %s, want 127.0.0.1", got)
	}
}

func TestTCPDialUsesSourceIP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	remoteAddr := make(chan net.Addr, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		remoteAddr <- conn.RemoteAddr()
		_ = conn.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	endpoint := transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolTCP,
		Address:   ln.Addr().String(),
		LocalBind: transport.LocalBind{SourceIP: "127.0.0.1"},
	}
	conn, err := DialContext(ctx, endpoint, "tcp")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()

	select {
	case err := <-acceptErr:
		t.Fatalf("accept: %v", err)
	case addr := <-remoteAddr:
		tcpAddr, ok := addr.(*net.TCPAddr)
		if !ok {
			t.Fatalf("remote addr = %T, want *net.TCPAddr", addr)
		}
		if got := tcpAddr.IP.String(); got != "127.0.0.1" {
			t.Fatalf("remote IP = %s, want 127.0.0.1", got)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
