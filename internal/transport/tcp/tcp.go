// Package tcp implements a length-prefixed packet session over TCP.
package tcp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"trustix.local/trustix/internal/transport"
	"trustix.local/trustix/internal/transport/bind"
	"trustix.local/trustix/internal/transport/stream"
)

type Transport struct{}

func New() *Transport {
	return &Transport{}
}

func (transportImpl *Transport) Name() transport.Protocol {
	return transport.ProtocolTCP
}

func (transportImpl *Transport) Probe(ctx context.Context, peer transport.Peer) transport.ProbeResult {
	start := time.Now()
	for _, endpoint := range peer.Endpoints {
		if endpoint.Transport != transport.ProtocolTCP || endpoint.Address == "" {
			continue
		}
		dialer, err := bind.Dialer(endpoint, "tcp")
		if err != nil {
			return transport.ProbeResult{Healthy: false, Error: err.Error(), CheckedAt: time.Now()}
		}
		conn, err := dialer.DialContext(ctx, "tcp", endpoint.Address)
		if err != nil {
			return transport.ProbeResult{Healthy: false, Error: err.Error(), CheckedAt: time.Now()}
		}
		if err := conn.Close(); err != nil {
			return transport.ProbeResult{Healthy: false, Error: fmt.Sprintf("close tcp probe connection: %v", err), CheckedAt: time.Now()}
		}
		return transport.ProbeResult{Healthy: true, RTT: time.Since(start), CheckedAt: time.Now()}
	}
	return transport.ProbeResult{Healthy: false, Error: "no tcp endpoint", CheckedAt: time.Now()}
}

func (transportImpl *Transport) Dial(ctx context.Context, peer transport.Peer, tlsConf *tls.Config) (transport.Session, error) {
	for _, endpoint := range peer.Endpoints {
		if endpoint.Transport != transport.ProtocolTCP || endpoint.Address == "" {
			continue
		}
		dialer, err := bind.Dialer(endpoint, "tcp")
		if err != nil {
			return nil, err
		}
		var conn net.Conn
		if tlsConf != nil {
			tlsDialer := tls.Dialer{NetDialer: dialer, Config: tlsConf}
			conn, err = tlsDialer.DialContext(ctx, "tcp", endpoint.Address)
		} else {
			conn, err = dialer.DialContext(ctx, "tcp", endpoint.Address)
		}
		if err != nil {
			return nil, err
		}
		return stream.NewSession(conn), nil
	}
	return nil, fmt.Errorf("peer %q has no dialable tcp endpoint", peer.ID)
}

func (transportImpl *Transport) Listen(ctx context.Context, ep transport.Endpoint, tlsConf *tls.Config) (transport.Listener, error) {
	if ep.Transport != transport.ProtocolTCP {
		return nil, fmt.Errorf("endpoint %q transport is %q, want tcp", ep.Name, ep.Transport)
	}
	addr := ep.Listen
	if addr == "" {
		addr = ep.Address
	}
	if addr == "" {
		return nil, fmt.Errorf("tcp endpoint %q listen address is required", ep.Name)
	}
	var ln net.Listener
	var err error
	if tlsConf != nil {
		ln, err = tls.Listen("tcp", addr, tlsConf)
	} else {
		ln, err = net.Listen("tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	listener := &listener{ln: ln}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	return listener, nil
}

type listener struct {
	ln        net.Listener
	closeOnce sync.Once
	closeErr  error
}

func (listener *listener) Accept(ctx context.Context) (transport.Session, error) {
	type accepted struct {
		conn net.Conn
		err  error
	}
	result := make(chan accepted, 1)
	go func() {
		conn, err := listener.ln.Accept()
		result <- accepted{conn: conn, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case accepted := <-result:
		if accepted.err != nil {
			return nil, accepted.err
		}
		return stream.NewSession(accepted.conn), nil
	}
}

func (listener *listener) Close() error {
	listener.closeOnce.Do(func() {
		listener.closeErr = listener.ln.Close()
	})
	return listener.closeErr
}
