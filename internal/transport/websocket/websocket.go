// Package websocket implements TrustIX packet sessions over RFC 6455 binary
// WebSocket frames.
package websocket

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"trustix.local/trustix/internal/transport"
	"trustix.local/trustix/internal/transport/bind"
	"trustix.local/trustix/internal/transport/stream"
)

const (
	websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	websocketPath = "/trustix/packet"

	sendBatchArenaRetainMax = 4 * 1024 * 1024
	readBufferSize          = 256 * 1024

	opContinuation = 0
	opText         = 1
	opBinary       = 2
	opClose        = 8
	opPing         = 9
	opPong         = 10
)

type Transport struct{}

func New() *Transport {
	return &Transport{}
}

func (transportImpl *Transport) Name() transport.Protocol {
	return transport.ProtocolWebSocket
}

func (transportImpl *Transport) Probe(ctx context.Context, peer transport.Peer) transport.ProbeResult {
	start := time.Now()
	for _, endpoint := range peer.Endpoints {
		if endpoint.Transport != transport.ProtocolWebSocket || endpoint.Address == "" {
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
			return transport.ProbeResult{Healthy: false, Error: fmt.Sprintf("close WebSocket probe connection: %v", err), CheckedAt: time.Now()}
		}
		return transport.ProbeResult{Healthy: true, RTT: time.Since(start), CheckedAt: time.Now()}
	}
	return transport.ProbeResult{Healthy: false, Error: "no websocket endpoint", CheckedAt: time.Now()}
}

func (transportImpl *Transport) Dial(ctx context.Context, peer transport.Peer, tlsConf *tls.Config) (transport.Session, error) {
	for _, endpoint := range peer.Endpoints {
		if endpoint.Transport != transport.ProtocolWebSocket || endpoint.Address == "" {
			continue
		}
		conn, err := dialConn(ctx, endpoint, tlsConf)
		if err != nil {
			return nil, err
		}
		key, err := websocketKey()
		if err != nil {
			return nil, errors.Join(err, websocketCleanupError("close WebSocket connection", conn.Close()))
		}
		if err := writeUpgradeRequest(conn, endpoint.Address, key); err != nil {
			return nil, errors.Join(err, websocketCleanupError("close WebSocket connection", conn.Close()))
		}
		reader := bufio.NewReaderSize(conn, readBufferSize)
		response, err := http.ReadResponse(reader, nil)
		if err != nil {
			return nil, errors.Join(
				fmt.Errorf("read WebSocket upgrade response: %w", err),
				websocketCleanupError("close WebSocket connection", conn.Close()),
			)
		}
		if err := response.Body.Close(); err != nil {
			return nil, errors.Join(
				fmt.Errorf("close WebSocket upgrade response body: %w", err),
				websocketCleanupError("close WebSocket connection", conn.Close()),
			)
		}
		if response.StatusCode != http.StatusSwitchingProtocols {
			return nil, errors.Join(
				fmt.Errorf("WebSocket upgrade returned %s", response.Status),
				websocketCleanupError("close WebSocket connection", conn.Close()),
			)
		}
		if !headerContains(response.Header, "Upgrade", "websocket") || !headerContains(response.Header, "Connection", "upgrade") {
			return nil, errors.Join(
				fmt.Errorf("WebSocket upgrade response is missing upgrade headers"),
				websocketCleanupError("close WebSocket connection", conn.Close()),
			)
		}
		if response.Header.Get("Sec-WebSocket-Accept") != websocketAccept(key) {
			return nil, errors.Join(
				fmt.Errorf("WebSocket upgrade response has invalid accept key"),
				websocketCleanupError("close WebSocket connection", conn.Close()),
			)
		}
		return newSession(conn, reader, true, false), nil
	}
	return nil, fmt.Errorf("peer %q has no dialable websocket endpoint", peer.ID)
}

func (transportImpl *Transport) Listen(ctx context.Context, ep transport.Endpoint, tlsConf *tls.Config) (transport.Listener, error) {
	if ep.Transport != transport.ProtocolWebSocket {
		return nil, fmt.Errorf("endpoint %q transport is %q, want websocket", ep.Name, ep.Transport)
	}
	addr := ep.Listen
	if addr == "" {
		addr = ep.Address
	}
	if addr == "" {
		return nil, fmt.Errorf("websocket endpoint %q listen address is required", ep.Name)
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
		session, err := acceptWebSocket(accepted.conn)
		if err != nil {
			return nil, errors.Join(err, websocketCleanupError("close rejected WebSocket connection", accepted.conn.Close()))
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

type session struct {
	conn            net.Conn
	reader          *bufio.Reader
	maskWrites      bool
	expectMasked    bool
	writeMu         sync.Mutex
	closeOnce       sync.Once
	closeErr        error
	sendFrameArena  []byte
	sendBatchArena  []byte
	recvBatch       [][]byte
	bytesSent       atomic.Uint64
	bytesReceived   atomic.Uint64
	packetsSent     atomic.Uint64
	packetsReceived atomic.Uint64
}

func newSession(conn net.Conn, reader *bufio.Reader, maskWrites bool, expectMasked bool) *session {
	return &session{
		conn:         conn,
		reader:       reader,
		maskWrites:   maskWrites,
		expectMasked: expectMasked,
	}
}

func (session *session) SendPacket(pkt []byte) error {
	if len(pkt) > stream.MaxPacketSize {
		return fmt.Errorf("packet size %d exceeds max %d", len(pkt), stream.MaxPacketSize)
	}
	session.writeMu.Lock()
	defer session.writeMu.Unlock()
	if err := session.writeFrame(opBinary, pkt); err != nil {
		return err
	}
	session.bytesSent.Add(uint64(len(pkt)))
	session.packetsSent.Add(1)
	return nil
}

func (session *session) SendPackets(pkts [][]byte) error {
	if len(pkts) == 0 {
		return nil
	}
	totalPayload := uint64(0)
	totalWire := 0
	for _, pkt := range pkts {
		if len(pkt) > stream.MaxPacketSize {
			return fmt.Errorf("packet size %d exceeds max %d", len(pkt), stream.MaxPacketSize)
		}
		totalWire += websocketFrameWireLen(len(pkt), session.maskWrites)
		totalPayload += uint64(len(pkt))
	}
	session.writeMu.Lock()
	defer session.writeMu.Unlock()
	if cap(session.sendBatchArena) < totalWire {
		session.sendBatchArena = make([]byte, 0, totalWire)
	}
	wire := session.sendBatchArena[:0]
	for _, pkt := range pkts {
		var err error
		wire, err = session.appendFrame(wire, opBinary, pkt)
		if err != nil {
			return err
		}
	}
	if err := writeFull(session.conn, wire); err != nil {
		return err
	}
	session.sendBatchArena = retainSendBatchArena(wire, totalWire)
	session.bytesSent.Add(totalPayload)
	session.packetsSent.Add(uint64(len(pkts)))
	return nil
}

func (session *session) RecvPacket() ([]byte, error) {
	return session.recvPacketBlocking()
}

func (session *session) RecvPackets(max int) ([][]byte, error) {
	if max <= 1 {
		packet, err := session.recvPacketBlocking()
		if err != nil {
			return nil, err
		}
		return [][]byte{packet}, nil
	}
	packet, err := session.recvPacketBlocking()
	if err != nil {
		return nil, err
	}
	if cap(session.recvBatch) < max {
		session.recvBatch = make([][]byte, 0, max)
	} else {
		clear(session.recvBatch)
		session.recvBatch = session.recvBatch[:0]
	}
	session.recvBatch = append(session.recvBatch, packet)
	for len(session.recvBatch) < max {
		packet, ok, err := session.tryRecvBufferedPacket()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		session.recvBatch = append(session.recvBatch, packet)
	}
	return session.recvBatch, nil
}

func (session *session) recvPacketBlocking() ([]byte, error) {
	for {
		opcode, payload, err := session.readFrame()
		if err != nil {
			return nil, err
		}
		switch opcode {
		case opBinary:
			session.bytesReceived.Add(uint64(len(payload)))
			session.packetsReceived.Add(1)
			return payload, nil
		case opPing:
			session.writeMu.Lock()
			err := session.writeFrame(opPong, payload)
			session.writeMu.Unlock()
			if err != nil {
				return nil, fmt.Errorf("write WebSocket pong: %w", err)
			}
		case opPong:
			continue
		case opClose:
			return nil, io.EOF
		default:
			return nil, fmt.Errorf("unsupported WebSocket opcode %d", opcode)
		}
	}
}

func (session *session) tryRecvBufferedPacket() ([]byte, bool, error) {
	for {
		ready, err := session.bufferedFrameReady()
		if err != nil {
			return nil, false, err
		}
		if !ready {
			return nil, false, nil
		}
		opcode, payload, err := session.readFrame()
		if err != nil {
			return nil, false, err
		}
		switch opcode {
		case opBinary:
			session.bytesReceived.Add(uint64(len(payload)))
			session.packetsReceived.Add(1)
			return payload, true, nil
		case opPing:
			session.writeMu.Lock()
			err := session.writeFrame(opPong, payload)
			session.writeMu.Unlock()
			if err != nil {
				return nil, false, fmt.Errorf("write WebSocket pong: %w", err)
			}
		case opPong:
			continue
		case opClose:
			return nil, false, io.EOF
		default:
			return nil, false, fmt.Errorf("unsupported WebSocket opcode %d", opcode)
		}
	}
}

func (session *session) Close() error {
	session.closeOnce.Do(func() {
		session.closeErr = session.conn.Close()
	})
	return session.closeErr
}

func (session *session) Stats() transport.TransportStats {
	tlsState := session.TLSState()
	return transport.TransportStats{
		BytesSent:       session.bytesSent.Load(),
		BytesReceived:   session.bytesReceived.Load(),
		PacketsSent:     session.packetsSent.Load(),
		PacketsReceived: session.packetsReceived.Load(),
		LinkTLS:         tlsState.Enabled,
		TLSVersion:      tlsState.Version,
		TLSCipherSuite:  tlsState.CipherSuite,
		NativeBatching:  true,
	}
}

func (session *session) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	state, ok := websocketTLSConnectionState(session.conn)
	if !ok {
		return nil, transport.ErrTLSExporterUnavailable
	}
	return state.ExportKeyingMaterial(label, context, length)
}

func (session *session) TLSState() transport.TLSState {
	state, ok := websocketTLSConnectionState(session.conn)
	if !ok || state.Version == 0 {
		return transport.TLSState{}
	}
	return transport.TLSState{
		Enabled:     true,
		Version:     tls.VersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
	}
}

type websocketTLSStateReader interface {
	ConnectionState() tls.ConnectionState
}

func websocketTLSConnectionState(conn net.Conn) (*tls.ConnectionState, bool) {
	tlsConn, ok := conn.(websocketTLSStateReader)
	if !ok {
		return nil, false
	}
	state := tlsConn.ConnectionState()
	return &state, true
}

func (session *session) writeFrame(opcode byte, payload []byte) error {
	wireLen := websocketFrameWireLen(len(payload), session.maskWrites)
	if cap(session.sendFrameArena) < wireLen {
		session.sendFrameArena = make([]byte, 0, wireLen)
	}
	wire, err := session.appendFrame(session.sendFrameArena[:0], opcode, payload)
	if err != nil {
		return err
	}
	if err := writeFull(session.conn, wire); err != nil {
		return err
	}
	session.sendFrameArena = retainSendBatchArena(wire, wireLen)
	return nil
}

func (session *session) appendFrame(dst []byte, opcode byte, payload []byte) ([]byte, error) {
	dst = append(dst, 0x80|opcode)
	maskBit := byte(0)
	if session.maskWrites {
		maskBit = 0x80
	}
	switch {
	case len(payload) <= 125:
		dst = append(dst, maskBit|byte(len(payload)))
	case len(payload) <= 0xffff:
		dst = append(dst, maskBit|126)
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(len(payload)))
		dst = append(dst, size[:]...)
	default:
		dst = append(dst, maskBit|127)
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(payload)))
		dst = append(dst, size[:]...)
	}
	if session.maskWrites {
		var mask [4]byte
		if _, err := rand.Read(mask[:]); err != nil {
			return nil, err
		}
		dst = append(dst, mask[:]...)
		base := len(dst)
		dst = append(dst, payload...)
		wirePayload := dst[base:]
		for i := range wirePayload {
			wirePayload[i] ^= mask[i%4]
		}
		return dst, nil
	}
	dst = append(dst, payload...)
	return dst, nil
}

func websocketFrameWireLen(payloadLen int, masked bool) int {
	headerLen := 2
	switch {
	case payloadLen <= 125:
	case payloadLen <= 0xffff:
		headerLen += 2
	default:
		headerLen += 8
	}
	if masked {
		headerLen += 4
	}
	return headerLen + payloadLen
}

func retainSendBatchArena(arena []byte, used int) []byte {
	if cap(arena) > sendBatchArenaRetainMax && used < sendBatchArenaRetainMax/2 {
		return nil
	}
	return arena[:0]
}

func writeFull(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

func (session *session) readFrame() (byte, []byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(session.reader, header[:]); err != nil {
		return 0, nil, err
	}
	if header[0]&0x80 == 0 {
		return 0, nil, fmt.Errorf("fragmented WebSocket frames are not supported")
	}
	opcode := header[0] & 0x0f
	masked := header[1]&0x80 != 0
	if masked != session.expectMasked {
		return 0, nil, fmt.Errorf("WebSocket mask state mismatch")
	}
	size := uint64(header[1] & 0x7f)
	switch size {
	case 126:
		var extended [2]byte
		if _, err := io.ReadFull(session.reader, extended[:]); err != nil {
			return 0, nil, err
		}
		size = uint64(binary.BigEndian.Uint16(extended[:]))
	case 127:
		var extended [8]byte
		if _, err := io.ReadFull(session.reader, extended[:]); err != nil {
			return 0, nil, err
		}
		size = binary.BigEndian.Uint64(extended[:])
	}
	if size > stream.MaxPacketSize {
		return 0, nil, fmt.Errorf("WebSocket frame size %d exceeds max %d", size, stream.MaxPacketSize)
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(session.reader, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(session.reader, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return opcode, payload, nil
}

func (session *session) bufferedFrameReady() (bool, error) {
	buffered := session.reader.Buffered()
	if buffered < 2 {
		return false, nil
	}
	header, err := session.reader.Peek(2)
	if err != nil {
		return false, err
	}
	headerLen := 2
	size := uint64(header[1] & 0x7f)
	switch size {
	case 126:
		headerLen += 2
		if buffered < headerLen {
			return false, nil
		}
		extended, err := session.reader.Peek(headerLen)
		if err != nil {
			return false, err
		}
		size = uint64(binary.BigEndian.Uint16(extended[2:4]))
	case 127:
		headerLen += 8
		if buffered < headerLen {
			return false, nil
		}
		extended, err := session.reader.Peek(headerLen)
		if err != nil {
			return false, err
		}
		size = binary.BigEndian.Uint64(extended[2:10])
	}
	if size > stream.MaxPacketSize {
		return false, fmt.Errorf("WebSocket frame size %d exceeds max %d", size, stream.MaxPacketSize)
	}
	if header[1]&0x80 != 0 {
		headerLen += 4
	}
	if size > uint64(int(^uint(0)>>1)-headerLen) {
		return false, fmt.Errorf("WebSocket frame size %d exceeds platform max", size)
	}
	return buffered >= headerLen+int(size), nil
}

func acceptWebSocket(conn net.Conn) (transport.Session, error) {
	reader := bufio.NewReaderSize(conn, readBufferSize)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return nil, fmt.Errorf("read WebSocket upgrade request: %w", err)
	}
	if err := request.Body.Close(); err != nil {
		return nil, fmt.Errorf("close WebSocket upgrade request body: %w", err)
	}
	if request.Method != http.MethodGet || request.URL.Path != websocketPath {
		_, writeErr := fmt.Fprintf(conn, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
		return nil, errors.Join(
			fmt.Errorf("invalid WebSocket request %s %s", request.Method, request.URL.Path),
			websocketCleanupError("write WebSocket request rejection", writeErr),
		)
	}
	key := request.Header.Get("Sec-WebSocket-Key")
	if !headerContains(request.Header, "Upgrade", "websocket") || !headerContains(request.Header, "Connection", "upgrade") || key == "" {
		_, writeErr := fmt.Fprintf(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		return nil, errors.Join(
			fmt.Errorf("invalid WebSocket upgrade headers"),
			websocketCleanupError("write WebSocket header rejection", writeErr),
		)
	}
	_, err = fmt.Fprintf(conn,
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
		websocketAccept(key),
	)
	if err != nil {
		return nil, err
	}
	return newSession(conn, reader, false, true), nil
}

func websocketCleanupError(operation string, err error) error {
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

func writeUpgradeRequest(conn net.Conn, host string, key string) error {
	_, err := fmt.Fprintf(conn,
		"GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nUser-Agent: TrustIX\r\n\r\n",
		websocketPath,
		host,
		key,
	)
	return err
}

func websocketKey() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw[:]), nil
}

func websocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + websocketGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func headerContains(header http.Header, name string, want string) bool {
	want = strings.ToLower(want)
	for _, value := range header.Values(name) {
		for _, part := range strings.Split(value, ",") {
			if strings.ToLower(strings.TrimSpace(part)) == want {
				return true
			}
		}
	}
	return false
}
