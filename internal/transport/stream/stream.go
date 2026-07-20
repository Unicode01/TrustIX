package stream

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"trustix.local/trustix/internal/transport"
)

const MaxPacketSize = 16 * 1024 * 1024
const sendBatchArenaRetainMax = 4 * 1024 * 1024
const readBufferSize = 64 * 1024
const recvArenaBytesPerPacket = 2048

type Session struct {
	conn            net.Conn
	reader          *bufio.Reader
	writeMu         sync.Mutex
	closeOnce       sync.Once
	closeErr        error
	sendBatchArena  []byte
	recvBatch       [][]byte
	recvArena       []byte
	bytesSent       atomic.Uint64
	bytesReceived   atomic.Uint64
	packetsSent     atomic.Uint64
	packetsReceived atomic.Uint64
}

func NewSession(conn net.Conn) *Session {
	return &Session{
		conn:   conn,
		reader: bufio.NewReaderSize(conn, readBufferSize),
	}
}

func (session *Session) SendPacket(pkt []byte) error {
	if len(pkt) > MaxPacketSize {
		return fmt.Errorf("packet size %d exceeds max %d", len(pkt), MaxPacketSize)
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
	if err := writeFull(session.conn, wire); err != nil {
		return err
	}
	session.sendBatchArena = retainSendBatchArena(wire, needed)
	session.bytesSent.Add(uint64(len(pkt)))
	session.packetsSent.Add(1)
	return nil
}

func (session *Session) SendPackets(pkts [][]byte) error {
	if len(pkts) == 0 {
		return nil
	}
	maxInt := int(^uint(0) >> 1)
	total := 0
	totalPayload := uint64(0)
	for _, pkt := range pkts {
		if len(pkt) > MaxPacketSize {
			return fmt.Errorf("packet size %d exceeds max %d", len(pkt), MaxPacketSize)
		}
		if len(pkt) > maxInt-total-4 {
			return fmt.Errorf("stream packet batch is too large")
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
	if err := writeFull(session.conn, wire); err != nil {
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

func (session *Session) RecvPacket() ([]byte, error) {
	return session.readPacket()
}

func (session *Session) RecvPackets(max int) ([][]byte, error) {
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

func (session *Session) RecvPacketsWithRelease(max int) ([][]byte, func(), error) {
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

func (session *Session) prepareRecvBatch(max int) {
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

func (session *Session) releaseRecvBatch() {
	clear(session.recvBatch)
	session.recvBatch = session.recvBatch[:0]
	used := len(session.recvArena)
	if cap(session.recvArena) > sendBatchArenaRetainMax && used < sendBatchArenaRetainMax/2 {
		session.recvArena = nil
		return
	}
	session.recvArena = session.recvArena[:0]
}

func (session *Session) readPacket() ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(session.reader, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size > MaxPacketSize {
		return nil, fmt.Errorf("packet size %d exceeds max %d", size, MaxPacketSize)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(session.reader, payload); err != nil {
		return nil, err
	}
	session.bytesReceived.Add(uint64(size))
	session.packetsReceived.Add(1)
	return payload, nil
}

func (session *Session) readBorrowedPacket() ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(session.reader, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size > MaxPacketSize {
		return nil, fmt.Errorf("packet size %d exceeds max %d", size, MaxPacketSize)
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

func (session *Session) tryReadBufferedBorrowedPacket() ([]byte, bool, error) {
	if session.reader.Buffered() < 4 {
		return nil, false, nil
	}
	header, err := session.reader.Peek(4)
	if err != nil {
		return nil, false, err
	}
	size := binary.BigEndian.Uint32(header)
	if size > MaxPacketSize {
		return nil, false, fmt.Errorf("packet size %d exceeds max %d", size, MaxPacketSize)
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

func (session *Session) appendBorrowedPayload(size int) ([]byte, error) {
	if size < 0 || size > MaxPacketSize {
		return nil, fmt.Errorf("packet size %d exceeds max %d", size, MaxPacketSize)
	}
	base := len(session.recvArena)
	if size > cap(session.recvArena)-base {
		return nil, fmt.Errorf("stream receive batch arena exhausted")
	}
	session.recvArena = session.recvArena[:base+size]
	return session.recvArena[base : base+size], nil
}

func (session *Session) Close() error {
	session.closeOnce.Do(func() {
		session.closeErr = session.conn.Close()
	})
	return session.closeErr
}

func (session *Session) Stats() transport.TransportStats {
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

func (session *Session) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	state, ok := tlsConnectionState(session.conn)
	if !ok {
		return nil, transport.ErrTLSExporterUnavailable
	}
	return state.ExportKeyingMaterial(label, context, length)
}

func (session *Session) TLSState() transport.TLSState {
	state, ok := tlsConnectionState(session.conn)
	if !ok || state.Version == 0 {
		return transport.TLSState{}
	}
	return transport.TLSState{
		Enabled:     true,
		Version:     tls.VersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
	}
}

type connectionStateReader interface {
	ConnectionState() tls.ConnectionState
}

func tlsConnectionState(conn net.Conn) (*tls.ConnectionState, bool) {
	tlsConn, ok := conn.(connectionStateReader)
	if !ok {
		return nil, false
	}
	state := tlsConn.ConnectionState()
	return &state, true
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
