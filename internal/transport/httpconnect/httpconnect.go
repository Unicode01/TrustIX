// Package httpconnect implements packet sessions over HTTP CONNECT tunnels.
package httpconnect

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"trustix.local/trustix/internal/transport"
	"trustix.local/trustix/internal/transport/bind"
	"trustix.local/trustix/internal/transport/stream"
)

const connectTarget = "trustix.packet"

type Transport struct{}

func New() *Transport {
	return &Transport{}
}

func (transportImpl *Transport) Name() transport.Protocol {
	return transport.ProtocolHTTPConnect
}

func (transportImpl *Transport) Probe(ctx context.Context, peer transport.Peer) transport.ProbeResult {
	start := time.Now()
	for _, endpoint := range peer.Endpoints {
		if endpoint.Transport != transport.ProtocolHTTPConnect || endpoint.Address == "" {
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
		_ = conn.Close()
		return transport.ProbeResult{Healthy: true, RTT: time.Since(start), CheckedAt: time.Now()}
	}
	return transport.ProbeResult{Healthy: false, Error: "no http_connect endpoint", CheckedAt: time.Now()}
}

func (transportImpl *Transport) Dial(ctx context.Context, peer transport.Peer, tlsConf *tls.Config) (transport.Session, error) {
	for _, endpoint := range peer.Endpoints {
		if endpoint.Transport != transport.ProtocolHTTPConnect || endpoint.Address == "" {
			continue
		}
		conn, err := dialConn(ctx, endpoint, tlsConf)
		if err != nil {
			return nil, err
		}
		if err := writeConnectRequest(conn, endpoint.Address); err != nil {
			_ = conn.Close()
			return nil, err
		}
		reader := bufio.NewReader(conn)
		response, err := http.ReadResponse(reader, nil)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("read HTTP CONNECT response: %w", err)
		}
		_ = response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			_ = conn.Close()
			return nil, fmt.Errorf("HTTP CONNECT returned %s", response.Status)
		}
		return stream.NewSession(&bufferedConn{Conn: conn, reader: reader}), nil
	}
	return nil, fmt.Errorf("peer %q has no dialable http_connect endpoint", peer.ID)
}

func (transportImpl *Transport) Listen(ctx context.Context, ep transport.Endpoint, tlsConf *tls.Config) (transport.Listener, error) {
	if ep.Transport != transport.ProtocolHTTPConnect {
		return nil, fmt.Errorf("endpoint %q transport is %q, want http_connect", ep.Name, ep.Transport)
	}
	addr := ep.Listen
	if addr == "" {
		addr = ep.Address
	}
	if addr == "" {
		return nil, fmt.Errorf("http_connect endpoint %q listen address is required", ep.Name)
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
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	return &listener{ln: ln}, nil
}

type listener struct {
	ln net.Listener
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
		session, err := acceptTunnel(accepted.conn)
		if err != nil {
			_ = accepted.conn.Close()
			return nil, err
		}
		return session, nil
	}
}

func (listener *listener) Close() error {
	return listener.ln.Close()
}

func acceptTunnel(conn net.Conn) (transport.Session, error) {
	reader := bufio.NewReader(conn)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return nil, fmt.Errorf("read HTTP CONNECT request: %w", err)
	}
	_ = request.Body.Close()
	if request.Method != http.MethodConnect {
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
		return nil, fmt.Errorf("HTTP CONNECT expected method CONNECT, got %s", request.Method)
	}
	if strings.TrimSpace(request.Host) == "" {
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		return nil, fmt.Errorf("HTTP CONNECT Host is required")
	}
	if _, err := fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n"); err != nil {
		return nil, err
	}
	return stream.NewSession(&bufferedConn{Conn: conn, reader: reader}), nil
}

func dialConn(ctx context.Context, endpoint transport.Endpoint, tlsConf *tls.Config) (net.Conn, error) {
	dialer, err := bind.Dialer(endpoint, "tcp")
	if err != nil {
		return nil, err
	}
	if tlsConf != nil {
		tlsDialer := tls.Dialer{NetDialer: dialer, Config: tlsConf}
		return tlsDialer.DialContext(ctx, "tcp", endpoint.Address)
	}
	return dialer.DialContext(ctx, "tcp", endpoint.Address)
}

func writeConnectRequest(conn net.Conn, host string) error {
	_, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: TrustIX\r\n\r\n", connectTarget, host)
	return err
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (conn *bufferedConn) ConnectionState() tls.ConnectionState {
	if stateReader, ok := conn.Conn.(interface {
		ConnectionState() tls.ConnectionState
	}); ok {
		return stateReader.ConnectionState()
	}
	return tls.ConnectionState{}
}

func (conn *bufferedConn) Read(payload []byte) (int, error) {
	return conn.reader.Read(payload)
}
