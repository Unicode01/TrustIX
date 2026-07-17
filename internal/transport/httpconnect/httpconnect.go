// Package httpconnect implements packet sessions over HTTP CONNECT tunnels.
package httpconnect

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
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
		if err := conn.Close(); err != nil {
			return transport.ProbeResult{Healthy: false, Error: fmt.Sprintf("close HTTP CONNECT probe connection: %v", err), CheckedAt: time.Now()}
		}
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
			return nil, errors.Join(err, httpConnectCleanupError("close HTTP CONNECT connection", conn.Close()))
		}
		reader := bufio.NewReader(conn)
		response, err := http.ReadResponse(reader, nil)
		if err != nil {
			return nil, errors.Join(
				fmt.Errorf("read HTTP CONNECT response: %w", err),
				httpConnectCleanupError("close HTTP CONNECT connection", conn.Close()),
			)
		}
		if err := response.Body.Close(); err != nil {
			return nil, errors.Join(
				fmt.Errorf("close HTTP CONNECT response body: %w", err),
				httpConnectCleanupError("close HTTP CONNECT connection", conn.Close()),
			)
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return nil, errors.Join(
				fmt.Errorf("HTTP CONNECT returned %s", response.Status),
				httpConnectCleanupError("close HTTP CONNECT connection", conn.Close()),
			)
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
	listener := &listener{ln: ln}
	go func() {
		<-ctx.Done()
		transport.ObserveAsyncError("close HTTP CONNECT listener after context cancellation", listener.Close())
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
		session, err := acceptTunnel(accepted.conn)
		if err != nil {
			return nil, errors.Join(err, httpConnectCleanupError("close rejected HTTP CONNECT connection", accepted.conn.Close()))
		}
		return session, nil
	}
}

func (listener *listener) Close() error {
	listener.closeOnce.Do(func() {
		listener.closeErr = listener.ln.Close()
	})
	return listener.closeErr
}

func acceptTunnel(conn net.Conn) (transport.Session, error) {
	reader := bufio.NewReader(conn)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return nil, fmt.Errorf("read HTTP CONNECT request: %w", err)
	}
	if err := request.Body.Close(); err != nil {
		return nil, fmt.Errorf("close HTTP CONNECT request body: %w", err)
	}
	if request.Method != http.MethodConnect {
		_, writeErr := fmt.Fprintf(conn, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
		return nil, errors.Join(
			fmt.Errorf("HTTP CONNECT expected method CONNECT, got %s", request.Method),
			httpConnectCleanupError("write HTTP CONNECT method rejection", writeErr),
		)
	}
	if strings.TrimSpace(request.Host) == "" {
		_, writeErr := fmt.Fprintf(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		return nil, errors.Join(
			fmt.Errorf("HTTP CONNECT Host is required"),
			httpConnectCleanupError("write HTTP CONNECT host rejection", writeErr),
		)
	}
	if _, err := fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n"); err != nil {
		return nil, err
	}
	return stream.NewSession(&bufferedConn{Conn: conn, reader: reader}), nil
}

func httpConnectCleanupError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
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
