// Package quic implements TrustIX packet sessions over QUIC bidirectional
// streams. The TrustIX secure transport still owns overlay encryption.
package quic

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	quicgo "github.com/quic-go/quic-go"

	"trustix.local/trustix/internal/transport"
	"trustix.local/trustix/internal/transport/bind"
	"trustix.local/trustix/internal/transport/stream"
)

const (
	nextProto     = "trustix-quic"
	streamPreface = byte('T')

	sendBatchArenaRetainMax = 4 * 1024 * 1024
	readBufferSize          = 64 * 1024
	recvArenaBytesPerPacket = 2048
)

type Transport struct{}

func New() *Transport {
	return &Transport{}
}

func (transportImpl *Transport) Name() transport.Protocol {
	return transport.ProtocolQUIC
}

func (transportImpl *Transport) Probe(ctx context.Context, peer transport.Peer) transport.ProbeResult {
	start := time.Now()
	for _, endpoint := range peer.Endpoints {
		if endpoint.Transport != transport.ProtocolQUIC || endpoint.Address == "" {
			continue
		}
		dialer, err := bind.Dialer(endpoint, "udp")
		if err != nil {
			return transport.ProbeResult{Healthy: false, Error: err.Error(), CheckedAt: time.Now()}
		}
		conn, err := dialer.DialContext(ctx, "udp", endpoint.Address)
		if err != nil {
			return transport.ProbeResult{Healthy: false, Error: err.Error(), CheckedAt: time.Now()}
		}
		_ = conn.Close()
		return transport.ProbeResult{Healthy: true, RTT: time.Since(start), CheckedAt: time.Now()}
	}
	return transport.ProbeResult{Healthy: false, Error: "no quic endpoint", CheckedAt: time.Now()}
}

func (transportImpl *Transport) Dial(ctx context.Context, peer transport.Peer, tlsConf *tls.Config) (transport.Session, error) {
	for _, endpoint := range peer.Endpoints {
		if endpoint.Transport != transport.ProtocolQUIC || endpoint.Address == "" {
			continue
		}
		quicTLS, err := clientTLSConfig(tlsConf)
		if err != nil {
			return nil, err
		}
		conn, packetConn, err := dialQUIC(ctx, endpoint, quicTLS)
		if err != nil {
			return nil, err
		}
		str, err := conn.OpenStreamSync(ctx)
		if err != nil {
			_ = conn.CloseWithError(0, "")
			if packetConn != nil {
				_ = packetConn.Close()
			}
			return nil, err
		}
		if err := writeFull(str, []byte{streamPreface}); err != nil {
			_ = conn.CloseWithError(0, "")
			if packetConn != nil {
				_ = packetConn.Close()
			}
			return nil, err
		}
		return newSession(conn, str, packetConn), nil
	}
	return nil, fmt.Errorf("peer %q has no dialable quic endpoint", peer.ID)
}

func dialQUIC(ctx context.Context, endpoint transport.Endpoint, tlsConf *tls.Config) (*quicgo.Conn, net.PacketConn, error) {
	if endpoint.LocalBind.SourceIP == "" && endpoint.LocalBind.Iface == "" {
		conn, err := quicgo.DialAddr(ctx, endpoint.Address, tlsConf, quicConfig())
		return conn, nil, err
	}
	remote, err := net.ResolveUDPAddr("udp", endpoint.Address)
	if err != nil {
		return nil, nil, err
	}
	packetConn, err := bind.ListenPacket(ctx, endpoint, "udp")
	if err != nil {
		return nil, nil, err
	}
	quicTransport := &quicgo.Transport{Conn: packetConn}
	conn, err := quicTransport.Dial(ctx, remote, tlsConf, quicConfig())
	if err != nil {
		_ = quicTransport.Close()
		_ = packetConn.Close()
		return nil, nil, err
	}
	return conn, packetConn, nil
}

func (transportImpl *Transport) Listen(ctx context.Context, ep transport.Endpoint, tlsConf *tls.Config) (transport.Listener, error) {
	if ep.Transport != transport.ProtocolQUIC {
		return nil, fmt.Errorf("endpoint %q transport is %q, want quic", ep.Name, ep.Transport)
	}
	addr := ep.Listen
	if addr == "" {
		addr = ep.Address
	}
	if addr == "" {
		return nil, fmt.Errorf("quic endpoint %q listen address is required", ep.Name)
	}
	quicTLS, err := serverTLSConfig(tlsConf)
	if err != nil {
		return nil, err
	}
	ln, err := quicgo.ListenAddr(addr, quicTLS, quicConfig())
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
	ln *quicgo.Listener
}

func (listener *listener) Accept(ctx context.Context) (transport.Session, error) {
	conn, err := listener.ln.Accept(ctx)
	if err != nil {
		return nil, err
	}
	str, err := conn.AcceptStream(ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, err
	}
	var preface [1]byte
	if _, err := io.ReadFull(str, preface[:]); err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, err
	}
	if preface[0] != streamPreface {
		_ = conn.CloseWithError(0, "")
		return nil, fmt.Errorf("invalid quic stream preface")
	}
	return newSession(conn, str, nil), nil
}

func (listener *listener) Close() error {
	return listener.ln.Close()
}

type session struct {
	conn            *quicgo.Conn
	stream          *quicgo.Stream
	packetConn      net.PacketConn
	reader          *bufio.Reader
	writeMu         sync.Mutex
	closeOnce       sync.Once
	sendBatchArena  []byte
	recvBatch       [][]byte
	recvArena       []byte
	bytesSent       atomic.Uint64
	bytesReceived   atomic.Uint64
	packetsSent     atomic.Uint64
	packetsReceived atomic.Uint64
}

func newSession(conn *quicgo.Conn, str *quicgo.Stream, packetConn net.PacketConn) *session {
	return &session{conn: conn, stream: str, packetConn: packetConn, reader: bufio.NewReaderSize(str, readBufferSize)}
}

func (session *session) SendPacket(pkt []byte) error {
	if len(pkt) > stream.MaxPacketSize {
		return fmt.Errorf("packet size %d exceeds max %d", len(pkt), stream.MaxPacketSize)
	}
	needed := 4 + len(pkt)
	session.writeMu.Lock()
	defer session.writeMu.Unlock()
	if cap(session.sendBatchArena) < needed {
		session.sendBatchArena = make([]byte, 0, needed)
	}
	wire := session.sendBatchArena[:0]
	wire = binary.BigEndian.AppendUint32(wire, uint32(len(pkt)))
	wire = append(wire, pkt...)
	if err := writeFull(session.stream, wire); err != nil {
		return err
	}
	session.sendBatchArena = retainSendBatchArena(wire, needed)
	session.bytesSent.Add(uint64(len(pkt)))
	session.packetsSent.Add(1)
	return nil
}

func (session *session) SendPackets(pkts [][]byte) error {
	if len(pkts) == 0 {
		return nil
	}
	maxInt := int(^uint(0) >> 1)
	total := 0
	totalPayload := uint64(0)
	for _, pkt := range pkts {
		if len(pkt) > stream.MaxPacketSize {
			return fmt.Errorf("packet size %d exceeds max %d", len(pkt), stream.MaxPacketSize)
		}
		if len(pkt) > maxInt-total-4 {
			return fmt.Errorf("quic packet batch is too large")
		}
		total += 4 + len(pkt)
		totalPayload += uint64(len(pkt))
	}
	session.writeMu.Lock()
	defer session.writeMu.Unlock()
	if cap(session.sendBatchArena) < total {
		session.sendBatchArena = make([]byte, 0, total)
	}
	wire := session.sendBatchArena[:0]
	var header [4]byte
	for _, pkt := range pkts {
		binary.BigEndian.PutUint32(header[:], uint32(len(pkt)))
		wire = append(wire, header[:]...)
		wire = append(wire, pkt...)
	}
	if err := writeFull(session.stream, wire); err != nil {
		return err
	}
	session.sendBatchArena = retainSendBatchArena(wire, total)
	session.bytesSent.Add(totalPayload)
	session.packetsSent.Add(uint64(len(pkts)))
	return nil
}

func retainSendBatchArena(arena []byte, used int) []byte {
	if cap(arena) > sendBatchArenaRetainMax && used < sendBatchArenaRetainMax/2 {
		return nil
	}
	return arena[:0]
}

func (session *session) RecvPacket() ([]byte, error) {
	return session.readPacket()
}

func (session *session) RecvPackets(max int) ([][]byte, error) {
	packets, release, err := session.RecvPacketsWithRelease(max)
	if err != nil || release == nil {
		return packets, err
	}
	copied := make([][]byte, len(packets))
	for i, packet := range packets {
		copied[i] = append([]byte(nil), packet...)
	}
	release()
	return copied, nil
}

func (session *session) RecvPacketsWithRelease(max int) ([][]byte, func(), error) {
	if max <= 1 {
		packet, err := session.readPacket()
		if err != nil {
			return nil, nil, err
		}
		return [][]byte{packet}, nil, nil
	}
	session.prepareRecvBatch(max)
	packet, err := session.readBorrowedPacket()
	if err != nil {
		session.releaseRecvBatch()
		return nil, nil, err
	}
	session.recvBatch = append(session.recvBatch, packet)
	for len(session.recvBatch) < max {
		packet, ok, err := session.tryReadBufferedBorrowedPacket()
		if err != nil {
			session.releaseRecvBatch()
			return nil, nil, err
		}
		if !ok {
			break
		}
		session.recvBatch = append(session.recvBatch, packet)
	}
	return session.recvBatch, session.releaseRecvBatch, nil
}

func (session *session) prepareRecvBatch(max int) {
	if cap(session.recvBatch) < max {
		session.recvBatch = make([][]byte, 0, max)
	} else {
		clear(session.recvBatch)
		session.recvBatch = session.recvBatch[:0]
	}
	target := max * recvArenaBytesPerPacket
	if target > sendBatchArenaRetainMax {
		target = sendBatchArenaRetainMax
	}
	if cap(session.recvArena) < target {
		session.recvArena = make([]byte, 0, target)
	} else {
		session.recvArena = session.recvArena[:0]
	}
}

func (session *session) releaseRecvBatch() {
	clear(session.recvBatch)
	session.recvBatch = session.recvBatch[:0]
	used := len(session.recvArena)
	if cap(session.recvArena) > sendBatchArenaRetainMax && used < sendBatchArenaRetainMax/2 {
		session.recvArena = nil
		return
	}
	session.recvArena = session.recvArena[:0]
}

func (session *session) readPacket() ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(session.reader, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size > stream.MaxPacketSize {
		return nil, fmt.Errorf("packet size %d exceeds max %d", size, stream.MaxPacketSize)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(session.reader, payload); err != nil {
		return nil, err
	}
	session.bytesReceived.Add(uint64(size))
	session.packetsReceived.Add(1)
	return payload, nil
}

func (session *session) readBorrowedPacket() ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(session.reader, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size > stream.MaxPacketSize {
		return nil, fmt.Errorf("packet size %d exceeds max %d", size, stream.MaxPacketSize)
	}
	if len(session.recvArena) == 0 && int(size) > cap(session.recvArena) {
		session.recvArena = make([]byte, 0, int(size))
	}
	payload, err := session.appendBorrowedPayload(int(size))
	if err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(session.reader, payload); err != nil {
		return nil, err
	}
	session.bytesReceived.Add(uint64(size))
	session.packetsReceived.Add(1)
	return payload, nil
}

func (session *session) tryReadBufferedBorrowedPacket() ([]byte, bool, error) {
	if session.reader.Buffered() < 4 {
		return nil, false, nil
	}
	header, err := session.reader.Peek(4)
	if err != nil {
		return nil, false, err
	}
	size := binary.BigEndian.Uint32(header)
	if size > stream.MaxPacketSize {
		return nil, false, fmt.Errorf("packet size %d exceeds max %d", size, stream.MaxPacketSize)
	}
	needed := 4 + int(size)
	if session.reader.Buffered() < needed {
		return nil, false, nil
	}
	if len(session.recvArena)+int(size) > cap(session.recvArena) {
		return nil, false, nil
	}
	if _, err := session.reader.Discard(4); err != nil {
		return nil, false, err
	}
	payload, err := session.appendBorrowedPayload(int(size))
	if err != nil {
		return nil, false, err
	}
	if _, err := io.ReadFull(session.reader, payload); err != nil {
		return nil, false, err
	}
	session.bytesReceived.Add(uint64(size))
	session.packetsReceived.Add(1)
	return payload, true, nil
}

func (session *session) appendBorrowedPayload(size int) ([]byte, error) {
	if size < 0 || size > stream.MaxPacketSize {
		return nil, fmt.Errorf("packet size %d exceeds max %d", size, stream.MaxPacketSize)
	}
	base := len(session.recvArena)
	if size > cap(session.recvArena)-base {
		return nil, fmt.Errorf("quic receive batch arena exhausted")
	}
	session.recvArena = session.recvArena[:base+size]
	return session.recvArena[base : base+size], nil
}

func (session *session) Close() error {
	var err error
	session.closeOnce.Do(func() {
		if closeErr := session.stream.Close(); closeErr != nil {
			err = closeErr
		}
		session.stream.CancelRead(0)
		if closeErr := session.conn.CloseWithError(0, ""); err == nil && closeErr != nil {
			err = closeErr
		}
		if session.packetConn != nil {
			if closeErr := session.packetConn.Close(); err == nil && closeErr != nil {
				err = closeErr
			}
		}
	})
	return err
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
	state := session.conn.ConnectionState().TLS
	if state.Version == 0 {
		return nil, transport.ErrTLSExporterUnavailable
	}
	return state.ExportKeyingMaterial(label, context, length)
}

func (session *session) TLSState() transport.TLSState {
	state := session.conn.ConnectionState().TLS
	if state.Version == 0 {
		return transport.TLSState{}
	}
	return transport.TLSState{
		Enabled:     true,
		Version:     tls.VersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
	}
}

func writeFull(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := writer.Write(payload)
		if err != nil {
			return err
		}
		payload = payload[n:]
	}
	return nil
}

func quicConfig() *quicgo.Config {
	return &quicgo.Config{
		HandshakeIdleTimeout: 5 * time.Second,
		MaxIdleTimeout:       30 * time.Second,
		KeepAlivePeriod:      10 * time.Second,
	}
}

func serverTLSConfig(tlsConf *tls.Config) (*tls.Config, error) {
	if tlsConf != nil {
		return cloneQUICTLSConfig(tlsConf), nil
	}
	cert, err := selfSignedCertificate()
	if err != nil {
		return nil, err
	}
	return cloneQUICTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}), nil
}

func clientTLSConfig(tlsConf *tls.Config) (*tls.Config, error) {
	if tlsConf != nil {
		return cloneQUICTLSConfig(tlsConf), nil
	}
	return cloneQUICTLSConfig(&tls.Config{InsecureSkipVerify: true}), nil
}

func cloneQUICTLSConfig(tlsConf *tls.Config) *tls.Config {
	clone := tlsConf.Clone()
	clone.MinVersion = tls.VersionTLS13
	if len(clone.NextProtos) == 0 {
		clone.NextProtos = []string{nextProto}
	}
	return clone
}

func selfSignedCertificate() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate quic test certificate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate quic test certificate serial: %w", err)
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "TrustIX QUIC",
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"trustix.local"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create quic test certificate: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}, nil
}
