package secure

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/pki"
	"trustix.local/trustix/internal/transport"
	tcptransport "trustix.local/trustix/internal/transport/tcp"
	udptransport "trustix.local/trustix/internal/transport/udp"
)

var secureBenchmarkSink []byte

func TestSessionEncryptsWireAndRoundTrips(t *testing.T) {
	clientInner, serverInner := newMemorySessionPair()

	serverReady := make(chan *Session, 1)
	serverErr := make(chan error, 1)
	go func() {
		session, err := Server(serverInner, nil, Options{Epoch: 7})
		if err != nil {
			serverErr <- err
			return
		}
		serverReady <- session
	}()

	client, err := Client(clientInner, nil, Options{Epoch: 7})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	server := waitServer(t, serverReady, serverErr)

	if err := client.SendPacket([]byte("secret-payload")); err != nil {
		t.Fatalf("send encrypted packet: %v", err)
	}
	wire := clientInner.lastSent()
	if bytes.Contains(wire, []byte("secret-payload")) {
		t.Fatalf("wire packet contains plaintext: %x", wire)
	}

	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if string(got) != "secret-payload" {
		t.Fatalf("server received %q", got)
	}

	if err := server.SendPacket([]byte("reply-payload")); err != nil {
		t.Fatalf("send reply: %v", err)
	}
	reply, err := client.RecvPacket()
	if err != nil {
		t.Fatalf("client recv: %v", err)
	}
	if string(reply) != "reply-payload" {
		t.Fatalf("client received %q", reply)
	}

	stats := client.Stats()
	if !stats.Encrypted || stats.CryptoSuite != SuiteAES256GCMX25519 {
		t.Fatalf("stats crypto fields = encrypted:%t suite:%q", stats.Encrypted, stats.CryptoSuite)
	}
}

func TestSessionCloseIsConcurrentAndErrorPreserving(t *testing.T) {
	wantErr := errors.New("injected secure inner close failure")
	inner := &idempotentCloseTestSession{err: wantErr}
	session := &Session{inner: inner}

	const callers = 16
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- session.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if !errors.Is(err, wantErr) {
			t.Fatalf("close error = %v, want %v", err, wantErr)
		}
	}
	if calls := inner.calls.Load(); calls != 1 {
		t.Fatalf("inner close calls = %d, want 1", calls)
	}
}

type idempotentCloseTestSession struct {
	err   error
	calls atomic.Int32
}

func (session *idempotentCloseTestSession) SendPacket([]byte) error { return nil }

func (session *idempotentCloseTestSession) RecvPacket() ([]byte, error) { return nil, nil }

func (session *idempotentCloseTestSession) Close() error {
	session.calls.Add(1)
	return session.err
}

func (session *idempotentCloseTestSession) Stats() transport.TransportStats {
	return transport.TransportStats{}
}

func TestSessionSendPacketsEncryptsWireAndRoundTrips(t *testing.T) {
	client, server, clientInner := handshakePair(t)
	packets := [][]byte{
		[]byte("batch-one"),
		[]byte("batch-two"),
		[]byte("batch-three"),
	}
	if err := client.SendPackets(packets); err != nil {
		t.Fatalf("send encrypted packet batch: %v", err)
	}
	for i, want := range packets {
		got, err := server.RecvPacket()
		if err != nil {
			t.Fatalf("server recv packet %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("server received packet %d %q, want %q", i, got, want)
		}
	}
	for _, wire := range clientInner.sentPackets() {
		for _, plaintext := range packets {
			if bytes.Contains(wire, plaintext) {
				t.Fatalf("wire packet contains plaintext %q: %x", plaintext, wire)
			}
		}
	}
}

func TestSessionSendPacketsBuildsEncryptedWireInPlace(t *testing.T) {
	clientMemory, serverInner := newMemorySessionPair()
	clientInner := &buildingMemorySession{memorySession: clientMemory}
	serverReady := make(chan *Session, 1)
	serverErr := make(chan error, 1)
	go func() {
		session, err := Server(serverInner, nil, Options{Epoch: 9})
		if err != nil {
			serverErr <- err
			return
		}
		serverReady <- session
	}()
	client, err := Client(clientInner, nil, Options{Epoch: 9})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	server := waitServer(t, serverReady, serverErr)
	packets := [][]byte{[]byte("built-one"), []byte("built-two"), []byte("built-three")}
	if err := client.SendPackets(packets); err != nil {
		t.Fatalf("send encrypted built packet batch: %v", err)
	}
	if calls := clientInner.buildCalls.Load(); calls != 1 {
		t.Fatalf("built packet batch calls = %d, want 1", calls)
	}
	for index, want := range packets {
		got, err := server.RecvPacket()
		if err != nil {
			t.Fatalf("server recv built packet %d: %v", index, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("server received built packet %d %q, want %q", index, got, want)
		}
	}
	for _, wire := range clientInner.builtPackets() {
		for _, plaintext := range packets {
			if bytes.Contains(wire, plaintext) {
				t.Fatalf("built wire packet contains plaintext %q: %x", plaintext, wire)
			}
		}
	}
}

func TestSessionSendPacketsNegotiatesSingleSecureBatchRecord(t *testing.T) {
	client, server, clientInner, _ := handshakeBuildingPair(t, true, true)
	packets := [][]byte{
		[]byte("batch-record-one"),
		[]byte("batch-record-two"),
		[]byte("batch-record-three"),
	}
	if err := client.SendPackets(packets); err != nil {
		t.Fatalf("send secure batch record: %v", err)
	}
	built := clientInner.builtPackets()
	if len(built) != 1 {
		t.Fatalf("built secure records = %d, want 1", len(built))
	}
	if len(built[0]) < dataHeaderLen || built[0][6]&dataFlagBatch == 0 {
		t.Fatalf("secure batch record flags = %#x, want batch", built[0][6])
	}
	got, release, err := server.RecvPacketsWithRelease(64)
	if err != nil {
		t.Fatalf("receive secure batch record: %v", err)
	}
	if release == nil {
		t.Fatal("secure batch record plaintext did not report borrowed storage")
	}
	defer release()
	assertPacketBatchEqual(t, got, packets)

	clientStats := client.Stats()
	if clientStats.Extra["secure_batch_records_negotiated"] != 1 ||
		clientStats.Extra["secure_batch_records_out"] != 1 ||
		clientStats.Extra["secure_batch_record_packets_out"] != uint64(len(packets)) {
		t.Fatalf("client secure batch stats = %#v", clientStats.Extra)
	}
	serverStats := server.Stats()
	if serverStats.PacketsReceived != uint64(len(packets)) ||
		serverStats.Extra["secure_batch_records_in"] != 1 ||
		serverStats.Extra["secure_batch_record_packets_in"] != uint64(len(packets)) {
		t.Fatalf("server secure batch stats = packets:%d extra:%#v", serverStats.PacketsReceived, serverStats.Extra)
	}
}

func TestSecureBatchRecordsRequestedDefaultsEnabledWithExplicitFailback(t *testing.T) {
	t.Setenv("TRUSTIX_SECURE_BATCH_RECORDS", "")
	if !secureBatchRecordsRequested(Options{}) {
		t.Fatal("secure batch records are disabled by default")
	}

	for _, value := range []string{"0", "false", "no", "off", "disabled"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("TRUSTIX_SECURE_BATCH_RECORDS", value)
			if secureBatchRecordsRequested(Options{}) {
				t.Fatalf("secure batch records enabled for failback value %q", value)
			}
		})
	}

	t.Setenv("TRUSTIX_SECURE_BATCH_RECORDS", "0")
	if !secureBatchRecordsRequested(Options{BatchRecords: func() bool { return true }}) {
		t.Fatal("explicit batch-record option did not override the environment")
	}
	t.Setenv("TRUSTIX_SECURE_BATCH_RECORDS", "1")
	if secureBatchRecordsRequested(Options{BatchRecords: func() bool { return false }}) {
		t.Fatal("explicit batch-record failback did not override the environment")
	}
}

func TestSessionSecureBatchRecordFallsBackWithoutPeerCapability(t *testing.T) {
	client, server, clientInner, _ := handshakeBuildingPair(t, true, false)
	if client.batchRecords || server.batchRecords {
		t.Fatal("secure batch records negotiated with a peer that disabled the capability")
	}
	packets := [][]byte{[]byte("legacy-one"), []byte("legacy-two"), []byte("legacy-three")}
	if err := client.SendPackets(packets); err != nil {
		t.Fatalf("send legacy secure records: %v", err)
	}
	built := clientInner.builtPackets()
	if len(built) != len(packets) {
		t.Fatalf("built legacy secure records = %d, want %d", len(built), len(packets))
	}
	for index, wire := range built {
		if wire[6]&dataFlagBatch != 0 {
			t.Fatalf("legacy secure record %d unexpectedly has batch flag", index)
		}
	}
	got, err := server.RecvPackets(64)
	if err != nil {
		t.Fatalf("receive legacy secure records: %v", err)
	}
	assertPacketBatchEqual(t, got, packets)
}

func TestSessionSecureBatchRecordRecvPacketDrainsPendingPackets(t *testing.T) {
	client, server, _, _ := handshakeBuildingPair(t, true, true)
	packets := [][]byte{[]byte("pending-one"), []byte("pending-two"), []byte("pending-three")}
	if err := client.SendPackets(packets); err != nil {
		t.Fatalf("send secure batch record: %v", err)
	}
	for index, want := range packets {
		got, err := server.RecvPacket()
		if err != nil {
			t.Fatalf("receive pending secure packet %d: %v", index, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("pending secure packet %d = %q, want %q", index, got, want)
		}
	}
	if stats := server.Stats(); stats.PacketsReceived != uint64(len(packets)) {
		t.Fatalf("pending secure packet stats = %d, want %d", stats.PacketsReceived, len(packets))
	}
}

func TestSessionSecureBatchRecordHonorsReceiveMaximum(t *testing.T) {
	client, server, _, _ := handshakeBuildingPair(t, true, true)
	packets := [][]byte{[]byte("limit-one"), []byte("limit-two"), []byte("limit-three")}
	if err := client.SendPackets(packets); err != nil {
		t.Fatalf("send secure batch record: %v", err)
	}
	first, release, err := server.RecvPacketsWithRelease(2)
	if err != nil {
		t.Fatalf("receive limited secure batch: %v", err)
	}
	if release != nil {
		release()
	}
	assertPacketBatchEqual(t, first, packets[:2])
	second, release, err := server.RecvPacketsWithRelease(2)
	if err != nil {
		t.Fatalf("receive secure batch overflow: %v", err)
	}
	if release != nil {
		release()
	}
	assertPacketBatchEqual(t, second, packets[2:])
}

func TestAppendSecureBatchRecordPacketsRejectsMalformedLengths(t *testing.T) {
	valid := make([]byte, secureBatchRecordHeaderLen+2*secureBatchRecordLengthLen+3)
	binary.BigEndian.PutUint16(valid[0:2], 2)
	binary.BigEndian.PutUint32(valid[2:6], 1)
	binary.BigEndian.PutUint32(valid[6:10], 2)
	copy(valid[10:], []byte("abc"))
	got, bytesReceived, count, err := appendSecureBatchRecordPackets(nil, valid)
	if err != nil {
		t.Fatalf("parse valid secure batch record: %v", err)
	}
	assertPacketBatchEqual(t, got, [][]byte{[]byte("a"), []byte("bc")})
	if bytesReceived != 3 || count != 2 {
		t.Fatalf("valid secure batch accounting = bytes:%d count:%d", bytesReceived, count)
	}

	malformed := append([]byte(nil), valid...)
	binary.BigEndian.PutUint32(malformed[6:10], 3)
	if _, _, _, err := appendSecureBatchRecordPackets(nil, malformed); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("malformed secure batch length error = %v, want ErrInvalidPacket", err)
	}
	trailing := append(append([]byte(nil), valid...), 0)
	if _, _, _, err := appendSecureBatchRecordPackets(nil, trailing); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("secure batch trailing-byte error = %v, want ErrInvalidPacket", err)
	}
}

func TestSessionSendPacketsBuiltPacketErrorDoesNotUpdateStats(t *testing.T) {
	clientMemory, serverInner := newMemorySessionPair()
	clientInner := &buildingMemorySession{memorySession: clientMemory}
	serverReady := make(chan *Session, 1)
	serverErr := make(chan error, 1)
	go func() {
		session, err := Server(serverInner, nil, Options{Epoch: 10})
		if err != nil {
			serverErr <- err
			return
		}
		serverReady <- session
	}()
	client, err := Client(clientInner, nil, Options{Epoch: 10})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	_ = waitServer(t, serverReady, serverErr)
	wantErr := errors.New("injected built packet failure")
	clientInner.buildErr = wantErr
	if err := client.SendPackets([][]byte{[]byte("not-sent")}); !errors.Is(err, wantErr) {
		t.Fatalf("send encrypted built packet error = %v, want %v", err, wantErr)
	}
	stats := client.Stats()
	if stats.PacketsSent != 0 || stats.BytesSent != 0 {
		t.Fatalf("failed built packet stats = packets:%d bytes:%d", stats.PacketsSent, stats.BytesSent)
	}
}

func TestSessionSendPacketsRejectsMalformedBuiltPacketBuffer(t *testing.T) {
	clientMemory, serverInner := newMemorySessionPair()
	clientInner := &buildingMemorySession{memorySession: clientMemory, buildSizeDelta: -1}
	serverReady := make(chan *Session, 1)
	serverErr := make(chan error, 1)
	go func() {
		session, err := Server(serverInner, nil, Options{Epoch: 11})
		if err != nil {
			serverErr <- err
			return
		}
		serverReady <- session
	}()
	client, err := Client(clientInner, nil, Options{Epoch: 11})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	_ = waitServer(t, serverReady, serverErr)
	err = client.SendPackets([][]byte{[]byte("not-sent")})
	if err == nil || !strings.Contains(err.Error(), "reserved size") {
		t.Fatalf("malformed built packet error = %v, want reserved-size error", err)
	}
	stats := client.Stats()
	if stats.PacketsSent != 0 || stats.BytesSent != 0 {
		t.Fatalf("malformed built packet stats = packets:%d bytes:%d", stats.PacketsSent, stats.BytesSent)
	}
}

func TestSessionRecvPacketsDecryptsBatch(t *testing.T) {
	client, server, _ := handshakePair(t)
	packets := [][]byte{
		[]byte("recv-batch-one"),
		[]byte("recv-batch-two"),
		[]byte("recv-batch-three"),
	}
	if err := client.SendPackets(packets); err != nil {
		t.Fatalf("send encrypted packet batch: %v", err)
	}
	got, err := server.RecvPackets(64)
	if err != nil {
		t.Fatalf("recv encrypted packet batch: %v", err)
	}
	if len(got) != len(packets) {
		t.Fatalf("recv batch len = %d, want %d", len(got), len(packets))
	}
	for i := range packets {
		if !bytes.Equal(got[i], packets[i]) {
			t.Fatalf("recv packet %d = %q, want %q", i, got[i], packets[i])
		}
	}
	stats := server.Stats()
	if stats.PacketsReceived != uint64(len(packets)) {
		t.Fatalf("server packets received = %d, want %d", stats.PacketsReceived, len(packets))
	}
}

func TestSessionRecvPacketsReturnsOwnedPlaintext(t *testing.T) {
	client, server, _ := handshakePair(t)
	firstWant := [][]byte{
		bytes.Repeat([]byte{0x41}, 1400),
		bytes.Repeat([]byte{0x42}, 1400),
	}
	if err := client.SendPackets(firstWant); err != nil {
		t.Fatalf("send first encrypted batch: %v", err)
	}
	first, err := server.RecvPackets(64)
	if err != nil {
		t.Fatalf("receive first encrypted batch: %v", err)
	}
	if err := client.SendPackets([][]byte{
		bytes.Repeat([]byte{0x51}, 1400),
		bytes.Repeat([]byte{0x52}, 1400),
	}); err != nil {
		t.Fatalf("send second encrypted batch: %v", err)
	}
	if _, err := server.RecvPackets(64); err != nil {
		t.Fatalf("receive second encrypted batch: %v", err)
	}
	for i := range firstWant {
		if !bytes.Equal(first[i], firstWant[i]) {
			t.Fatalf("owned packet %d changed after arena reuse", i)
		}
	}
}

func TestSessionRecvPacketsWithReleaseMarksPlaintextArenaBorrowed(t *testing.T) {
	client, server, clientInner := handshakePair(t)
	serverInner := clientInner.peer()
	if err := client.SendPackets([][]byte{[]byte("arena-backed-plaintext")}); err != nil {
		t.Fatalf("send encrypted batch: %v", err)
	}
	got, release, err := server.RecvPacketsWithRelease(64)
	if err != nil {
		t.Fatalf("receive encrypted batch: %v", err)
	}
	if len(got) != 1 || !bytes.Equal(got[0], []byte("arena-backed-plaintext")) {
		t.Fatalf("received packets = %q", got)
	}
	if release == nil {
		t.Fatal("arena-backed plaintext did not return a release function")
	}
	release()
	if serverInner.releaseCount() != 0 {
		t.Fatalf("owned inner batch release count = %d, want 0", serverInner.releaseCount())
	}
}

func TestSessionRecvPacketsWithReleaseUsesInnerBorrowedBatch(t *testing.T) {
	client, server, clientInner := handshakePair(t)
	serverInner := clientInner.peer()
	packets := [][]byte{
		[]byte("borrowed-batch-one"),
		[]byte("borrowed-batch-two"),
	}
	if err := client.SendPackets(packets); err != nil {
		t.Fatalf("send encrypted packet batch: %v", err)
	}
	serverInner.enableBorrowedRecv()
	got, release, err := server.RecvPacketsWithRelease(64)
	if err != nil {
		t.Fatalf("recv encrypted borrowed packet batch: %v", err)
	}
	if release == nil {
		t.Fatal("secure borrowed recv did not return a release function")
	}
	if len(got) != len(packets) {
		t.Fatalf("recv batch len = %d, want %d", len(got), len(packets))
	}
	for i := range packets {
		if !bytes.Equal(got[i], packets[i]) {
			t.Fatalf("recv packet %d = %q, want %q", i, got[i], packets[i])
		}
	}
	if serverInner.releaseCount() != 0 {
		t.Fatalf("inner release count before release = %d, want 0", serverInner.releaseCount())
	}
	release()
	if serverInner.releaseCount() != 1 {
		t.Fatalf("inner release count after release = %d, want 1", serverInner.releaseCount())
	}
}

func TestSessionRecvPacketsWithReleaseReusesPlaintextArena(t *testing.T) {
	client, server, clientInner := handshakePair(t)
	serverInner := clientInner.peer()
	serverInner.enableBorrowedRecv()
	packets := [][]byte{
		bytes.Repeat([]byte{0x31}, 1400),
		bytes.Repeat([]byte{0x32}, 1400),
	}

	if err := client.SendPackets(packets); err != nil {
		t.Fatalf("send first encrypted batch: %v", err)
	}
	got, release, err := server.RecvPacketsWithRelease(64)
	if err != nil {
		t.Fatalf("receive first encrypted batch: %v", err)
	}
	if release == nil {
		t.Fatal("first encrypted batch did not return a release function")
	}
	if len(got) != len(packets) || len(server.recvBatchArena) == 0 {
		t.Fatalf("first encrypted batch = %d packets, arena bytes = %d", len(got), len(server.recvBatchArena))
	}
	firstArena := &server.recvBatchArena[0]
	release()

	if err := client.SendPackets(packets); err != nil {
		t.Fatalf("send second encrypted batch: %v", err)
	}
	got, release, err = server.RecvPacketsWithRelease(64)
	if err != nil {
		t.Fatalf("receive second encrypted batch: %v", err)
	}
	if release == nil {
		t.Fatal("second encrypted batch did not return a release function")
	}
	defer release()
	if len(got) != len(packets) || len(server.recvBatchArena) == 0 {
		t.Fatalf("second encrypted batch = %d packets, arena bytes = %d", len(got), len(server.recvBatchArena))
	}
	if secondArena := &server.recvBatchArena[0]; secondArena != firstArena {
		t.Fatal("encrypted batch plaintext arena was not reused")
	}
	for i := range packets {
		if !bytes.Equal(got[i], packets[i]) {
			t.Fatalf("second received packet %d differs from input", i)
		}
	}
}

func TestSessionRecvBatchArenaRejectsOversizedPreallocation(t *testing.T) {
	_, server, _ := handshakePair(t)
	server.recvBatchArena = make([]byte, 1, 1024)
	overhead := dataHeaderLen + server.recvAEAD.Overhead()
	wirePackets := [][]byte{
		make([]byte, overhead+recvBatchArenaRetainMax/2+1),
		make([]byte, overhead+recvBatchArenaRetainMax/2),
	}
	if arena := server.prepareRecvBatchArena(wirePackets); arena != nil {
		t.Fatalf("oversized receive arena capacity = %d, want nil", cap(arena))
	}
	if server.recvBatchArena != nil {
		t.Fatalf("retained oversized receive arena capacity = %d, want nil", cap(server.recvBatchArena))
	}
}

func BenchmarkSessionSendPacketsEncrypted(b *testing.B) {
	client, server, _ := handshakePair(b)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < b.N; i++ {
			for j := 0; j < 64; j++ {
				pkt, err := server.RecvPacket()
				if err != nil {
					return
				}
				secureBenchmarkSink = pkt
			}
		}
	}()
	packets := make([][]byte, 64)
	for i := range packets {
		packets[i] = bytes.Repeat([]byte{byte(i)}, 1400)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := client.SendPackets(packets); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	_ = client.Close()
	<-done
}

func TestServerInvalidHandshakeSendsReset(t *testing.T) {
	client, server := newMemorySessionPair()
	errc := make(chan error, 1)
	go func() {
		_, err := Server(server, nil, Options{Epoch: 1})
		errc <- err
	}()

	if err := client.SendPacket([]byte("old encrypted data")); err != nil {
		t.Fatalf("send invalid handshake: %v", err)
	}
	select {
	case err := <-errc:
		if !errors.Is(err, ErrInvalidHandshake) {
			t.Fatalf("server error = %v, want ErrInvalidHandshake", err)
		}
		if !errors.Is(err, ErrSessionResetSent) {
			t.Fatalf("server error = %v, want ErrSessionResetSent marker", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not return invalid handshake")
	}
	reset, err := client.RecvPacket()
	if err != nil {
		t.Fatalf("receive reset: %v", err)
	}
	if !isResetPacket(reset) {
		t.Fatalf("reset packet = %x", reset)
	}
}

func TestServerInvalidHandshakeReturnsResetSendFailure(t *testing.T) {
	wantErr := errors.New("injected reset send failure")
	inner := &handshakeSendFailureSession{
		recv:    []byte("old encrypted data"),
		sendErr: wantErr,
	}

	_, err := Server(inner, nil, Options{Epoch: 1})
	if !errors.Is(err, ErrInvalidHandshake) || !errors.Is(err, wantErr) {
		t.Fatalf("server error = %v, want invalid handshake and reset send failure", err)
	}
	if errors.Is(err, ErrSessionResetSent) {
		t.Fatalf("server error = %v, reset was not sent", err)
	}
}

func TestSessionRecvResetReturnsSessionReset(t *testing.T) {
	client, _, clientInner := handshakePair(t)
	clientInner.inject(resetPacket())

	_, err := client.RecvPacket()
	if !errors.Is(err, ErrSessionReset) {
		t.Fatalf("client recv error = %v, want ErrSessionReset", err)
	}
}

func TestClientRetransmitsClientHelloUntilServerHello(t *testing.T) {
	clientInner, serverInner := newMemorySessionPair()
	firstClientHello := make(chan []byte, 1)
	retransmittedClientHello := make(chan []byte, 1)
	serverErr := make(chan error, 1)
	go func() {
		rawClientHello, err := serverInner.RecvPacket()
		if err != nil {
			serverErr <- err
			return
		}
		firstClientHello <- rawClientHello
		select {
		case rawClientHello = <-serverInner.in:
			retransmittedClientHello <- append([]byte(nil), rawClientHello...)
		case <-time.After(2 * time.Second):
			serverErr <- errors.New("timed out waiting for retransmitted client hello")
			return
		}
		clientHello, err := parseHello(rawClientHello, helloTypeClient)
		if err != nil {
			serverErr <- err
			return
		}
		state, serverHello, err := newHandshakeState(helloTypeServer, nil, Options{Epoch: 21})
		if err != nil {
			serverErr <- err
			return
		}
		serverHello.signature, err = state.sign(serverSignaturePayload(clientHello, serverHello))
		if err != nil {
			serverErr <- err
			return
		}
		encodedHello, err := serverHello.encode()
		if err != nil {
			serverErr <- err
			return
		}
		if err := serverInner.SendPacket(encodedHello); err != nil {
			serverErr <- err
			return
		}
	}()

	client, err := Client(clientInner, nil, Options{Epoch: 21})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if client == nil {
		t.Fatal("client session is nil")
	}
	select {
	case err := <-serverErr:
		t.Fatalf("server helper: %v", err)
	default:
	}
	initial := <-firstClientHello
	retry := <-retransmittedClientHello
	if !bytes.Equal(initial, retry) {
		t.Fatalf("retransmitted client hello changed")
	}
}

func TestClientReturnsRetransmitAndCleanupFailures(t *testing.T) {
	wantSendErr := errors.New("injected retransmit failure")
	wantCloseErr := errors.New("injected retransmit cleanup failure")
	inner := &retransmitFailureSession{
		sendErr:  wantSendErr,
		closeErr: wantCloseErr,
		closed:   make(chan struct{}),
	}
	errCh := make(chan error, 1)
	go func() {
		_, err := Client(inner, nil, Options{Epoch: 1})
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, wantSendErr) || !errors.Is(err, wantCloseErr) {
			t.Fatalf("client error = %v, want retransmit and cleanup failures", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client did not stop after handshake retransmit failure")
	}
}

func TestDuplicateClientHelloReturnsServerHelloResendFailure(t *testing.T) {
	wantErr := errors.New("injected duplicate hello reply failure")
	clientHello := resetPacket()
	clientHello[5] = helloTypeClient
	serverHello := resetPacket()
	serverHello[5] = helloTypeServer
	session := &Session{
		inner:          &handshakeSendFailureSession{sendErr: wantErr},
		role:           serverRole,
		clientHelloRaw: clientHello,
		serverHelloRaw: serverHello,
		recvEncrypted:  false,
		sendEncrypted:  false,
		encryptionMode: EncryptionPlaintext,
	}

	_, ok, err := session.openReceivedPacketNoStats(clientHello)
	if ok || !errors.Is(err, wantErr) {
		t.Fatalf("duplicate result ok=%t err=%v, want resend failure", ok, err)
	}
}

func TestServerSessionReplaysServerHelloForDuplicateClientHello(t *testing.T) {
	client, server, clientInner := handshakePair(t)
	clientHello := server.clientHelloRaw
	serverHello := server.serverHelloRaw
	if len(clientHello) == 0 || len(serverHello) == 0 {
		t.Fatal("handshake packets were not retained")
	}

	clientInner.peer().inject(clientHello)
	serverRecv := make(chan []byte, 1)
	serverErr := make(chan error, 1)
	go func() {
		packet, err := server.RecvPacket()
		if err != nil {
			serverErr <- err
			return
		}
		serverRecv <- packet
	}()
	duplicateReply, err := clientInner.RecvPacket()
	if err != nil {
		t.Fatalf("receive replayed server hello: %v", err)
	}
	if !bytes.Equal(duplicateReply, serverHello) {
		t.Fatalf("replayed server hello changed")
	}
	if err := client.SendPacket([]byte("after-duplicate-client-hello")); err != nil {
		t.Fatalf("client send after duplicate hello: %v", err)
	}
	select {
	case err := <-serverErr:
		t.Fatalf("server recv after duplicate hello: %v", err)
	case payload := <-serverRecv:
		if string(payload) != "after-duplicate-client-hello" {
			t.Fatalf("server payload = %q", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not receive payload after duplicate hello")
	}
}

func TestClientSessionIgnoresDuplicateServerHello(t *testing.T) {
	client, server, clientInner := handshakePair(t)
	if len(client.serverHelloRaw) == 0 {
		t.Fatal("server hello was not retained")
	}

	clientInner.inject(client.serverHelloRaw)
	if err := server.SendPacket([]byte("after-duplicate-server-hello")); err != nil {
		t.Fatalf("server send after duplicate hello: %v", err)
	}
	payload, err := client.RecvPacket()
	if err != nil {
		t.Fatalf("client recv payload after duplicate server hello: %v", err)
	}
	if string(payload) != "after-duplicate-server-hello" {
		t.Fatalf("client payload = %q", payload)
	}
}

func TestSessionNegotiatesAdditionalCryptoSuites(t *testing.T) {
	for _, suite := range []string{SuiteAES128GCMX25519, SuiteChaCha20Poly1305X25519} {
		t.Run(suite, func(t *testing.T) {
			clientInner, serverInner := newMemorySessionPair()
			options := Options{
				Epoch: 11,
				CryptoSuites: func() []string {
					return []string{suite}
				},
			}

			serverReady := make(chan *Session, 1)
			serverErr := make(chan error, 1)
			go func() {
				session, err := Server(serverInner, nil, options)
				if err != nil {
					serverErr <- err
					return
				}
				serverReady <- session
			}()

			client, err := Client(clientInner, nil, options)
			if err != nil {
				t.Fatalf("client handshake: %v", err)
			}
			server := waitServer(t, serverReady, serverErr)
			if got := client.Stats().CryptoSuite; got != suite {
				t.Fatalf("client suite = %q, want %q", got, suite)
			}
			if got := server.Stats().CryptoSuite; got != suite {
				t.Fatalf("server suite = %q, want %q", got, suite)
			}

			if err := client.SendPacket([]byte("suite-payload")); err != nil {
				t.Fatalf("send encrypted packet: %v", err)
			}
			got, err := server.RecvPacket()
			if err != nil {
				t.Fatalf("server recv: %v", err)
			}
			if string(got) != "suite-payload" {
				t.Fatalf("server received %q", got)
			}
		})
	}
}

func TestSessionNegotiatesCommonSuiteByPerformancePreference(t *testing.T) {
	clientInner, serverInner := newMemorySessionPair()
	clientOptions := Options{
		Epoch: 12,
		CryptoSuites: func() []string {
			return []string{SuiteAES256GCMX25519, SuiteAES128GCMX25519}
		},
	}
	serverOptions := Options{
		Epoch: 12,
		CryptoSuites: func() []string {
			return []string{SuiteAES256GCMX25519, SuiteAES128GCMX25519}
		},
	}

	serverReady := make(chan *Session, 1)
	serverErr := make(chan error, 1)
	go func() {
		session, err := Server(serverInner, nil, serverOptions)
		if err != nil {
			serverErr <- err
			return
		}
		serverReady <- session
	}()

	client, err := Client(clientInner, nil, clientOptions)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	server := waitServer(t, serverReady, serverErr)
	if got := client.Stats().CryptoSuite; got != SuiteAES128GCMX25519 {
		t.Fatalf("client suite = %q, want %q", got, SuiteAES128GCMX25519)
	}
	if got := server.Stats().CryptoSuite; got != SuiteAES128GCMX25519 {
		t.Fatalf("server suite = %q, want %q", got, SuiteAES128GCMX25519)
	}
}

func TestSessionRejectsNoCommonCryptoSuite(t *testing.T) {
	clientInner, serverInner := newMemorySessionPair()
	clientOptions := Options{
		CryptoSuites: func() []string {
			return []string{SuiteAES128GCMX25519}
		},
	}
	serverOptions := Options{
		CryptoSuites: func() []string {
			return []string{SuiteChaCha20Poly1305X25519}
		},
	}

	serverErr := make(chan error, 1)
	go func() {
		_, err := Server(serverInner, nil, serverOptions)
		serverErr <- err
	}()

	_, clientHello, err := newHandshakeState(helloTypeClient, nil, clientOptions)
	if err != nil {
		t.Fatalf("build client hello: %v", err)
	}
	encoded, err := clientHello.encode()
	if err != nil {
		t.Fatalf("encode client hello: %v", err)
	}
	if err := clientInner.SendPacket(encoded); err != nil {
		t.Fatalf("send client hello: %v", err)
	}
	select {
	case err := <-serverErr:
		if err == nil || !errors.Is(err, ErrInvalidHandshake) {
			t.Fatalf("server err = %v, want ErrInvalidHandshake", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server handshake timed out")
	}
}

func TestSessionPlaintextDataKeepsHandshakeAndSkipsEnvelope(t *testing.T) {
	clientInner, serverInner := newMemorySessionPair()
	options := Options{
		Epoch: 7,
		Encryption: func() string {
			return EncryptionPlaintext
		},
	}

	serverReady := make(chan *Session, 1)
	serverErr := make(chan error, 1)
	go func() {
		session, err := Server(serverInner, nil, options)
		if err != nil {
			serverErr <- err
			return
		}
		serverReady <- session
	}()

	client, err := Client(clientInner, nil, options)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	server := waitServer(t, serverReady, serverErr)

	if err := client.SendPacket([]byte("plain-payload")); err != nil {
		t.Fatalf("send plaintext packet: %v", err)
	}
	wire := clientInner.lastSent()
	if !bytes.Equal(wire, []byte("plain-payload")) {
		t.Fatalf("wire packet = %q, want raw plaintext", wire)
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if string(got) != "plain-payload" {
		t.Fatalf("server received %q", got)
	}

	stats := client.Stats()
	if stats.Encrypted || stats.SendEncrypted || stats.ReceiveEncrypted || stats.CryptoSuite != "" || stats.Encryption != EncryptionPlaintext {
		t.Fatalf("plaintext stats = %+v", stats)
	}
}

func TestSessionDirectionalEncryptionRoundTripsWithComplementaryPolicies(t *testing.T) {
	clientInner, serverInner := newMemorySessionPair()
	clientOptions := Options{
		Epoch: 9,
		Encryption: func() string {
			return EncryptionSendEncrypted
		},
	}
	serverOptions := Options{
		Epoch: 9,
		Encryption: func() string {
			return EncryptionReceiveEncrypted
		},
	}

	serverReady := make(chan *Session, 1)
	serverErr := make(chan error, 1)
	go func() {
		session, err := Server(serverInner, nil, serverOptions)
		if err != nil {
			serverErr <- err
			return
		}
		serverReady <- session
	}()

	client, err := Client(clientInner, nil, clientOptions)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	server := waitServer(t, serverReady, serverErr)

	if err := client.SendPacket([]byte("encrypted-outbound")); err != nil {
		t.Fatalf("send encrypted outbound: %v", err)
	}
	outboundWire := clientInner.lastSent()
	if bytes.Contains(outboundWire, []byte("encrypted-outbound")) {
		t.Fatalf("outbound wire contains plaintext: %x", outboundWire)
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("server recv encrypted outbound: %v", err)
	}
	if string(got) != "encrypted-outbound" {
		t.Fatalf("server received %q", got)
	}

	if err := server.SendPacket([]byte("plain-return")); err != nil {
		t.Fatalf("send plaintext return: %v", err)
	}
	returnWire := serverInner.lastSent()
	if !bytes.Equal(returnWire, []byte("plain-return")) {
		t.Fatalf("return wire = %q, want raw plaintext", returnWire)
	}
	reply, err := client.RecvPacket()
	if err != nil {
		t.Fatalf("client recv plaintext return: %v", err)
	}
	if string(reply) != "plain-return" {
		t.Fatalf("client received %q", reply)
	}

	if stats := client.Stats(); !stats.SendEncrypted || stats.ReceiveEncrypted || !stats.Encrypted || stats.Encryption != EncryptionSendEncrypted {
		t.Fatalf("client directional stats = %+v", stats)
	}
	if stats := server.Stats(); stats.SendEncrypted || !stats.ReceiveEncrypted || !stats.Encrypted || stats.Encryption != EncryptionReceiveEncrypted {
		t.Fatalf("server directional stats = %+v", stats)
	}
}

func TestCryptoOffloadDisabledForPartialEncryption(t *testing.T) {
	clientBase, serverInner := newMemorySessionPair()
	clientInner := &offloadMemorySession{memorySession: clientBase}
	options := Options{
		Epoch: 7,
		Encryption: func() string {
			return EncryptionSendEncrypted
		},
	}

	serverReady := make(chan *Session, 1)
	serverErr := make(chan error, 1)
	go func() {
		session, err := Server(serverInner, nil, Options{
			Epoch: 7,
			Encryption: func() string {
				return EncryptionReceiveEncrypted
			},
		})
		if err != nil {
			serverErr <- err
			return
		}
		serverReady <- session
	}()

	client, err := Client(clientInner, nil, options)
	if err != nil {
		t.Fatalf("client handshake with partial encryption: %v", err)
	}
	_ = waitServer(t, serverReady, serverErr)
	if client.cryptoOffloaded {
		t.Fatal("partial encryption should keep userspace crypto in this first version")
	}
	if len(clientInner.specs) != 0 {
		t.Fatalf("captured offload specs = %d, want 0", len(clientInner.specs))
	}
}

func TestCryptoOffloadClearsTemporaryKeyMaterial(t *testing.T) {
	clientBase, serverInner := newMemorySessionPair()
	clientInner := &offloadMemorySession{memorySession: clientBase}

	serverReady := make(chan *Session, 1)
	serverErr := make(chan error, 1)
	go func() {
		session, err := Server(serverInner, nil, Options{Epoch: 7})
		if err != nil {
			serverErr <- err
			return
		}
		serverReady <- session
	}()

	client, err := Client(clientInner, nil, Options{Epoch: 7})
	if err != nil {
		t.Fatalf("client handshake with offload: %v", err)
	}
	_ = waitServer(t, serverReady, serverErr)
	if !client.cryptoOffloaded {
		t.Fatalf("client did not enable crypto offload")
	}
	if client.sendAEAD != nil || client.sendIV != nil {
		t.Fatalf("offloaded secure session kept userspace send crypto state")
	}
	if client.recvAEAD == nil || client.recvIV == nil {
		t.Fatalf("offloaded secure session must keep receive crypto for mixed-placement fallback")
	}

	spec := clientInner.lastOffloadSpec(t)
	requireZeroed(t, "send key", spec.SendKey)
	requireZeroed(t, "send iv", spec.SendIV)
	requireZeroed(t, "recv key", spec.RecvKey)
	requireZeroed(t, "recv iv", spec.RecvIV)
}

func TestCryptoOffloadedReceiverOpensUserspaceEncryptedFallback(t *testing.T) {
	clientInner, serverBase := newMemorySessionPair()
	serverInner := &offloadMemorySession{memorySession: serverBase}

	serverReady := make(chan *Session, 1)
	serverErr := make(chan error, 1)
	go func() {
		session, err := Server(serverInner, nil, Options{Epoch: 7})
		if err != nil {
			serverErr <- err
			return
		}
		serverReady <- session
	}()

	client, err := Client(clientInner, nil, Options{Epoch: 7})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	server := waitServer(t, serverReady, serverErr)
	if !server.cryptoOffloaded {
		t.Fatalf("server did not enable crypto offload")
	}

	payload := []byte("userspace-encrypted-fallback")
	if err := client.SendPacket(payload); err != nil {
		t.Fatalf("client send: %v", err)
	}
	wire := clientInner.lastSent()
	if !bytes.Equal(wire[:len(dataMagic)], dataMagic[:]) {
		t.Fatalf("client wire magic = %x, want TIXD", wire[:len(dataMagic)])
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("server received %q, want %q", got, payload)
	}
}

func TestSessionRejectsTamperedPacket(t *testing.T) {
	client, server, clientInner := handshakePair(t)
	if err := client.SendPacket([]byte("secret-payload")); err != nil {
		t.Fatalf("send encrypted packet: %v", err)
	}
	wire := clientInner.lastSent()
	if _, err := server.RecvPacket(); err != nil {
		t.Fatalf("server recv first packet: %v", err)
	}
	wire[len(wire)-1] ^= 0xff
	serverInner := clientInner.peer()
	serverInner.inject(wire)

	_, err := server.RecvPacket()
	if err == nil || !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("recv tampered packet err = %v, want ErrInvalidPacket", err)
	}
}

func TestSessionOpensNoAADKernelDeviceFrame(t *testing.T) {
	_, server, _ := handshakePair(t)
	if server.recvAEAD == nil || server.recvIV == nil {
		t.Fatal("server receive crypto is not initialized")
	}
	payload := []byte("kernel-device-no-aad")
	seq := uint64(1)
	var header [dataHeaderLen]byte
	copy(header[0:4], dataMagic[:])
	header[4] = dataVersion
	header[5] = server.cryptoSuite.ID
	binary.BigEndian.PutUint64(header[8:16], server.epoch)
	binary.BigEndian.PutUint64(header[16:24], seq)
	var nonce [12]byte
	copy(nonce[:], server.recvIV)
	binary.BigEndian.PutUint64(nonce[4:], seq)
	wire := append([]byte(nil), header[:]...)
	wire = server.recvAEAD.Seal(wire, nonce[:], payload, nil)

	got, ok, err := server.openReceivedPacketNoStats(wire)
	if err != nil {
		t.Fatalf("open no-AAD frame: %v", err)
	}
	if !ok {
		t.Fatal("no-AAD frame was skipped")
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("opened payload = %q, want %q", got, payload)
	}
}

func TestSessionBatchOpensNoAADKernelDeviceFrameIntoPlaintextArena(t *testing.T) {
	_, server, _ := handshakePair(t)
	if server.recvAEAD == nil || server.recvIV == nil {
		t.Fatal("server receive crypto is not initialized")
	}
	payload := []byte("kernel-device-no-aad-batch")
	seq := uint64(1)
	var header [dataHeaderLen]byte
	copy(header[0:4], dataMagic[:])
	header[4] = dataVersion
	header[5] = server.cryptoSuite.ID
	binary.BigEndian.PutUint64(header[8:16], server.epoch)
	binary.BigEndian.PutUint64(header[16:24], seq)
	var nonce [12]byte
	copy(nonce[:], server.recvIV)
	binary.BigEndian.PutUint64(nonce[4:], seq)
	wire := append([]byte(nil), header[:]...)
	wire = server.recvAEAD.Seal(wire, nonce[:], payload, nil)

	got, bytesReceived, packetsReceived, err := server.openReceivedPacketBatch(nil, [][]byte{wire})
	if err != nil {
		t.Fatalf("open no-AAD batch frame: %v", err)
	}
	if len(got) != 1 || !bytes.Equal(got[0], payload) {
		t.Fatalf("opened batch payloads = %q, want %q", got, payload)
	}
	if bytesReceived != uint64(len(payload)) || packetsReceived != 1 {
		t.Fatalf("opened batch stats = %d bytes/%d packets", bytesReceived, packetsReceived)
	}
	if len(server.recvBatchArena) != len(payload) {
		t.Fatalf("receive plaintext arena bytes = %d, want %d", len(server.recvBatchArena), len(payload))
	}
}

func TestSessionRejectsReplay(t *testing.T) {
	client, server, clientInner := handshakePair(t)
	if err := client.SendPacket([]byte("secret-payload")); err != nil {
		t.Fatalf("send encrypted packet: %v", err)
	}
	wire := clientInner.lastSent()
	if _, err := server.RecvPacket(); err != nil {
		t.Fatalf("server recv first packet: %v", err)
	}

	_, _, err := server.openReceivedPacketNoStats(wire)
	if !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("open replay err = %v, want ErrReplayDetected", err)
	}
}

func TestSessionRecvPacketDropsReplayAndContinues(t *testing.T) {
	client, server, clientInner := handshakePair(t)
	if err := client.SendPacket([]byte("first")); err != nil {
		t.Fatalf("send first packet: %v", err)
	}
	replayWire := clientInner.lastSent()
	if got, err := server.RecvPacket(); err != nil || string(got) != "first" {
		t.Fatalf("server first recv = %q, %v", got, err)
	}

	serverInner := clientInner.peer()
	serverInner.inject(replayWire)
	if err := client.SendPacket([]byte("second")); err != nil {
		t.Fatalf("send second packet: %v", err)
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("server recv after replay: %v", err)
	}
	if string(got) != "second" {
		t.Fatalf("server recv after replay = %q, want second", got)
	}
}

func TestSessionRecvPacketsDropsReplayInsideBatch(t *testing.T) {
	client, server, clientInner := handshakePair(t)
	if err := client.SendPacket([]byte("one")); err != nil {
		t.Fatalf("send one: %v", err)
	}
	replayWire := clientInner.lastSent()
	if got, err := server.RecvPacket(); err != nil || string(got) != "one" {
		t.Fatalf("server first recv = %q, %v", got, err)
	}

	serverInner := clientInner.peer()
	serverInner.inject(replayWire)
	if err := client.SendPacket([]byte("two")); err != nil {
		t.Fatalf("send two: %v", err)
	}
	if err := client.SendPacket([]byte("three")); err != nil {
		t.Fatalf("send three: %v", err)
	}
	got, err := server.RecvPackets(8)
	if err != nil {
		t.Fatalf("server batch recv after replay: %v", err)
	}
	if len(got) != 2 || string(got[0]) != "two" || string(got[1]) != "three" {
		t.Fatalf("server batch recv = %q, want [two three]", got)
	}
}

func TestSessionRecvPacketsDropsReplayedSecureBatchRecord(t *testing.T) {
	client, server, clientInner, serverInner := handshakeBuildingPair(t, true, true)
	first := [][]byte{[]byte("first-one"), []byte("first-two"), []byte("first-three")}
	if err := client.SendPackets(first); err != nil {
		t.Fatalf("send first secure batch record: %v", err)
	}
	built := clientInner.builtPackets()
	if len(built) != 1 {
		t.Fatalf("first secure records = %d, want 1", len(built))
	}
	if got, err := server.RecvPackets(64); err != nil {
		t.Fatalf("receive first secure batch record: %v", err)
	} else {
		assertPacketBatchEqual(t, got, first)
	}

	serverInner.inject(built[0])
	second := [][]byte{[]byte("second-one"), []byte("second-two")}
	if err := client.SendPackets(second); err != nil {
		t.Fatalf("send second secure batch record: %v", err)
	}
	got, err := server.RecvPackets(64)
	if err != nil {
		t.Fatalf("receive after replayed secure batch record: %v", err)
	}
	assertPacketBatchEqual(t, got, second)

	stats := server.Stats()
	if stats.PacketsReceived != uint64(len(first)+len(second)) ||
		stats.Extra["secure_batch_records_in"] != 2 ||
		stats.Extra["secure_batch_record_packets_in"] != uint64(len(first)+len(second)) {
		t.Fatalf("secure batch replay stats = packets:%d extra:%#v", stats.PacketsReceived, stats.Extra)
	}
}

func TestReplayWindowAcceptsLargeOutOfOrderBurst(t *testing.T) {
	window := newReplayWindow(defaultReplayWindowSize)

	if !window.Accept(70000) {
		t.Fatal("first high sequence was rejected")
	}
	if !window.Accept(70000 - 4096) {
		t.Fatal("sequence inside the enlarged replay window was rejected")
	}
	if window.Accept(70000 - defaultReplayWindowSize) {
		t.Fatal("sequence just outside replay window was accepted")
	}
	if window.Accept(70000 - 4096) {
		t.Fatal("duplicate sequence was accepted")
	}
}

func TestReplayWindowAcceptBatchIsAtomic(t *testing.T) {
	window := newReplayWindow(128)

	if !window.Accept(10) {
		t.Fatal("initial sequence was rejected")
	}
	if window.AcceptBatch([]uint64{11, 12, 10}) {
		t.Fatal("batch containing a duplicate sequence was accepted")
	}
	if !window.Accept(11) {
		t.Fatal("failed batch advanced replay state")
	}
}

func TestReplayWindowAcceptBatchIsAtomicAcrossRingWrap(t *testing.T) {
	window := newReplayWindow(65)
	if !window.Accept(100) {
		t.Fatal("initial sequence was rejected")
	}
	batch := make([]uint64, 0, 67)
	for seq := uint64(101); seq <= 166; seq++ {
		batch = append(batch, seq)
	}
	batch = append(batch, 100)
	if window.AcceptBatch(batch) {
		t.Fatal("batch containing an expired sequence was accepted")
	}
	if !window.Accept(101) {
		t.Fatal("failed wrapped batch advanced replay state")
	}
}

func TestReplayWindowMatchesReferenceRandomized(t *testing.T) {
	for _, size := range []uint64{64, 65, 127, 128, 129, 1023, defaultReplayWindowSize} {
		t.Run(fmt.Sprintf("size-%d", size), func(t *testing.T) {
			window := newReplayWindow(size)
			reference := newReplayWindowReference(size)
			rng := rand.New(rand.NewSource(int64(size)))
			frontier := uint64(1)
			for step := 0; step < 30000; step++ {
				seq := replayWindowTestSequence(rng, &frontier, size)
				got := window.Accept(seq)
				want := reference.Accept(seq)
				if got != want {
					t.Fatalf("step %d sequence %d: Accept = %v, want %v (highest=%d head=%d)", step, seq, got, want, window.highest, window.head)
				}
			}
		})
	}
}

func TestReplayWindowAcceptBatchResultsMatchesReferenceRandomized(t *testing.T) {
	const size = uint64(129)
	window := newReplayWindow(size)
	reference := newReplayWindowReference(size)
	rng := rand.New(rand.NewSource(20260731))
	frontier := uint64(1)
	dst := make([]bool, 0, 16)
	for step := 0; step < 5000; step++ {
		seqs := make([]uint64, 1+rng.Intn(16))
		want := make([]bool, len(seqs))
		for i := range seqs {
			seqs[i] = replayWindowTestSequence(rng, &frontier, size)
			want[i] = reference.Accept(seqs[i])
		}
		got := window.AcceptBatchResults(seqs, dst)
		if !slices.Equal(got, want) {
			t.Fatalf("step %d sequences %v: AcceptBatchResults = %v, want %v", step, seqs, got, want)
		}
		dst = got[:0]
	}
}

func BenchmarkReplayWindowAcceptSequential(b *testing.B) {
	window := newReplayWindow(defaultReplayWindowSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !window.Accept(uint64(i) + 1) {
			b.Fatalf("sequence %d was rejected", i+1)
		}
	}
}

type replayWindowReference struct {
	highest uint64
	size    uint64
	seen    map[uint64]struct{}
}

func newReplayWindowReference(size uint64) *replayWindowReference {
	return &replayWindowReference{
		size: normalizeReplayWindowSize(size),
		seen: make(map[uint64]struct{}),
	}
}

func (reference *replayWindowReference) Accept(seq uint64) bool {
	if seq == 0 {
		return false
	}
	if seq <= reference.highest && reference.highest-seq >= reference.size {
		return false
	}
	if _, exists := reference.seen[seq]; exists {
		return false
	}
	if seq > reference.highest {
		reference.highest = seq
	}
	reference.seen[seq] = struct{}{}
	return true
}

func replayWindowTestSequence(rng *rand.Rand, frontier *uint64, size uint64) uint64 {
	switch rng.Intn(12) {
	case 0:
		return 0
	case 1:
		*frontier += size + uint64(rng.Intn(64)) + 1
		return *frontier
	case 2, 3, 4:
		delta := uint64(rng.Intn(int(size*2 + 1)))
		if delta < *frontier {
			return *frontier - delta
		}
		return 1
	default:
		*frontier += uint64(rng.Intn(4)) + 1
		return *frontier
	}
}

func TestSessionAuthenticatesHandshakeWithIXCertificates(t *testing.T) {
	clientTLS, serverTLS := testTLSConfigs(t)
	clientInner, serverInner := newMemorySessionPair()

	serverReady := make(chan *Session, 1)
	serverErr := make(chan error, 1)
	go func() {
		session, err := Server(serverInner, serverTLS, Options{Epoch: 3})
		if err != nil {
			serverErr <- err
			return
		}
		serverReady <- session
	}()

	client, err := Client(clientInner, clientTLS, Options{Epoch: 3})
	if err != nil {
		t.Fatalf("client authenticated handshake: %v", err)
	}
	server := waitServer(t, serverReady, serverErr)

	if err := client.SendPacket([]byte("authenticated")); err != nil {
		t.Fatalf("send authenticated packet: %v", err)
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("recv authenticated packet: %v", err)
	}
	if string(got) != "authenticated" {
		t.Fatalf("server received %q", got)
	}
}

func TestServerRequiresPeerCertificateWhenConfigured(t *testing.T) {
	_, serverTLS := testTLSConfigs(t)
	_, unauthenticatedHello, err := newHandshakeState(helloTypeClient, nil, Options{})
	if err != nil {
		t.Fatalf("build unauthenticated hello: %v", err)
	}
	encoded, err := unauthenticatedHello.encode()
	if err != nil {
		t.Fatalf("encode unauthenticated hello: %v", err)
	}
	clientInner, serverInner := newMemorySessionPair()
	if err := clientInner.SendPacket(encoded); err != nil {
		t.Fatalf("send unauthenticated hello: %v", err)
	}

	_, err = Server(serverInner, serverTLS, Options{})
	if !errors.Is(err, ErrPeerAuthRequired) {
		t.Fatalf("server err = %v, want ErrPeerAuthRequired", err)
	}
}

func TestTransportWrapperUDP(t *testing.T) {
	exerciseTransportWrapper(t, New(udptransport.New(), Options{}), transport.ProtocolUDP, freeUDPAddr(t))
}

func TestTransportWrapperTCP(t *testing.T) {
	exerciseTransportWrapper(t, New(tcptransport.New(), Options{}), transport.ProtocolTCP, freeTCPAddr(t))
}

func TestTransportWrapperTCPUsesTLSExporterKeySource(t *testing.T) {
	clientTLS, serverTLS := testTLSConfigs(t)
	tr := New(tcptransport.New(), Options{
		KeySource: func() string {
			return KeySourceTLSExporter
		},
	})
	clientStats, serverStats := exerciseTransportWrapperWithTLS(t, tr, transport.ProtocolTCP, freeTCPAddr(t), clientTLS, serverTLS)
	if clientStats.CryptoKeySource != KeySourceTLSExporter || serverStats.CryptoKeySource != KeySourceTLSExporter {
		t.Fatalf("crypto key source client=%q server=%q, want %q", clientStats.CryptoKeySource, serverStats.CryptoKeySource, KeySourceTLSExporter)
	}
	if !clientStats.LinkTLS || !serverStats.LinkTLS {
		t.Fatalf("link TLS client=%t server=%t, want true", clientStats.LinkTLS, serverStats.LinkTLS)
	}
	if clientStats.TLSVersion == "" || serverStats.TLSVersion == "" {
		t.Fatalf("TLS versions client=%q server=%q, want populated", clientStats.TLSVersion, serverStats.TLSVersion)
	}
}

func TestTransportWrapperTCPUsesSeparateTransportTLSCertificateAndIXAuth(t *testing.T) {
	clientIXTLS, serverIXTLS := testTLSConfigs(t)
	linkClientTLS, linkServerTLS := testLinkTLSConfigs(t, "127.0.0.1")
	tr := New(tcptransport.New(), Options{
		KeySource: func() string {
			return KeySourceTLSExporter
		},
		ClientAuthTLS: func(peer transport.Peer) (*tls.Config, error) {
			return clientIXTLS, nil
		},
		ServerAuthTLS: func() (*tls.Config, error) {
			return serverIXTLS, nil
		},
	})
	clientStats, serverStats := exerciseTransportWrapperWithTLS(t, tr, transport.ProtocolTCP, freeTCPAddr(t), linkClientTLS, linkServerTLS)
	if clientStats.CryptoKeySource != KeySourceTLSExporter || serverStats.CryptoKeySource != KeySourceTLSExporter {
		t.Fatalf("crypto key source client=%q server=%q, want %q", clientStats.CryptoKeySource, serverStats.CryptoKeySource, KeySourceTLSExporter)
	}
	if clientStats.TLSCipherSuite == "" || serverStats.TLSCipherSuite == "" {
		t.Fatalf("TLS cipher suites client=%q server=%q, want populated", clientStats.TLSCipherSuite, serverStats.TLSCipherSuite)
	}
}

func TestTransportDialContextCoversSecureHandshake(t *testing.T) {
	inner := &blockingTransport{session: newBlockingSecureSession()}
	tr := New(inner, Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()

	_, err := tr.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{
			{Name: core.EndpointID("blocked"), Transport: transport.Protocol("blocked"), Address: "blocked"},
		},
	}, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dial error = %v, want context deadline", err)
	}
	if !inner.session.closed() {
		t.Fatal("inner session was not closed after handshake deadline")
	}
}

func TestSecureHandshakeAnnotatesInnerPeerIdentity(t *testing.T) {
	clientTLS, serverTLS := testTLSConfigs(t)
	clientBase, serverBase := newMemorySessionPair()
	clientInner := &annotatingMemorySession{memorySession: clientBase}
	serverInner := &annotatingMemorySession{memorySession: serverBase}
	serverReady := make(chan *Session, 1)
	serverErr := make(chan error, 1)
	go func() {
		session, err := Server(serverInner, serverTLS, Options{})
		if err != nil {
			serverErr <- err
			return
		}
		serverReady <- session
	}()

	client, err := Client(clientInner, clientTLS, Options{})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	defer client.Close()
	server := waitServer(t, serverReady, serverErr)
	defer server.Close()

	if clientInner.peer != "ix-b" || clientInner.domain != "lab.local" {
		t.Fatalf("client inner peer identity = %q/%q, want ix-b/lab.local", clientInner.peer, clientInner.domain)
	}
	if serverInner.peer != "ix-a" || serverInner.domain != "lab.local" {
		t.Fatalf("server inner peer identity = %q/%q, want ix-a/lab.local", serverInner.peer, serverInner.domain)
	}
}

func TestSecureHandshakeCarriesDeviceCertificateChainAndIdentity(t *testing.T) {
	root, err := pki.NewRoot("TrustIX Test Root", 1)
	if err != nil {
		t.Fatalf("new root: %v", err)
	}
	domain, err := pki.Issue(root, pki.IssueRequest{
		CommonName: "lab.local domain CA",
		Role:       pki.RoleDomainCA,
		Domain:     "lab.local",
		IsCA:       true,
	})
	if err != nil {
		t.Fatalf("issue domain: %v", err)
	}
	ix, err := pki.Issue(domain, pki.IssueRequest{
		CommonName: "ix-a",
		Role:       pki.RoleIX,
		Domain:     "lab.local",
		IX:         "ix-a",
		IsCA:       true,
	})
	if err != nil {
		t.Fatalf("issue ix: %v", err)
	}
	device, err := pki.Issue(ix, pki.IssueRequest{
		CommonName: "device-a",
		Role:       pki.RoleDevice,
		Domain:     "lab.local",
		IX:         "ix-a",
		Device:     "laptop-1",
		LANID:      "public",
		Prefixes:   []string{"10.99.0.0/24"},
	})
	if err != nil {
		t.Fatalf("issue device: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)
	serverTLS := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientCAs:  pool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) != 3 {
				return fmt.Errorf("raw certs = %d, want 3", len(rawCerts))
			}
			if len(verifiedChains) == 0 || len(verifiedChains[0]) != 4 {
				return fmt.Errorf("verified chain length mismatch")
			}
			meta := pki.ParseMetadata(verifiedChains[0][0])
			if meta.Role != pki.RoleDevice || meta.IX != "ix-a" || meta.Device != "laptop-1" || meta.LANID != "public" {
				return fmt.Errorf("metadata = %+v", meta)
			}
			return nil
		},
	}
	clientTLS := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{tlsCertificateWithChain(device, ix, domain)},
	}
	clientBase, serverBase := newMemorySessionPair()
	serverInner := &annotatingMemorySession{memorySession: serverBase}
	serverReady := make(chan *Session, 1)
	serverErr := make(chan error, 1)
	go func() {
		session, err := Server(serverInner, serverTLS, Options{})
		if err != nil {
			serverErr <- err
			return
		}
		serverReady <- session
	}()

	client, err := Client(clientBase, clientTLS, Options{})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	defer client.Close()
	server := waitServer(t, serverReady, serverErr)
	defer server.Close()

	identity, ok := server.PeerIdentityDetail()
	if !ok {
		t.Fatal("server peer identity detail missing")
	}
	if identity.Role != string(pki.RoleDevice) || identity.Peer != "ix-a" || identity.Domain != "lab.local" || identity.Device != "laptop-1" || identity.LANID != "public" {
		t.Fatalf("server identity = %+v", identity)
	}
	if len(identity.Prefixes) != 1 || identity.Prefixes[0] != "10.99.0.0/24" {
		t.Fatalf("server identity prefixes = %#v", identity.Prefixes)
	}
	if serverInner.detail.Role != string(pki.RoleDevice) || serverInner.detail.Device != "laptop-1" {
		t.Fatalf("inner detail identity = %+v", serverInner.detail)
	}
}

func TestClientHandshakeRetriesUDPConnectionRefused(t *testing.T) {
	clientTLS, serverTLS := testTLSConfigs(t)
	clientBase, serverInner := newMemorySessionPair()
	clientInner := &refusedOnceSession{memorySession: clientBase}
	serverReady := make(chan *Session, 1)
	serverErr := make(chan error, 1)
	go func() {
		session, err := Server(serverInner, serverTLS, Options{})
		if err != nil {
			serverErr <- err
			return
		}
		serverReady <- session
	}()

	client, err := Client(clientInner, clientTLS, Options{})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	defer client.Close()
	server := waitServer(t, serverReady, serverErr)
	defer server.Close()

	if got := clientInner.refusals.Load(); got != 1 {
		t.Fatalf("refused reads = %d, want 1", got)
	}
}

func TestTransportWrapperPlaintextBypassesHandshakeWithPeerIdentity(t *testing.T) {
	clientBase, serverBase := newMemorySessionPair()
	clientInner := &identityMemorySession{memorySession: clientBase, peer: "ix-b", domain: "lab.local"}
	serverInner := &identityMemorySession{memorySession: serverBase, peer: "ix-a", domain: "lab.local"}
	innerListener := &singleSessionListener{session: serverInner, ready: make(chan struct{})}
	tr := New(&singleSessionTransport{client: clientInner, listener: innerListener}, Options{
		Encryption: func() string {
			return EncryptionPlaintext
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := tr.Listen(ctx, transport.Endpoint{
		Name:       core.EndpointID("server"),
		Transport:  transport.Protocol("memory"),
		Listen:     "memory",
		Encryption: EncryptionPlaintext,
		Enabled:    true,
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
		Endpoints: []transport.Endpoint{{
			Name:       core.EndpointID("server"),
			Transport:  transport.Protocol("memory"),
			Address:    "memory",
			Encryption: EncryptionPlaintext,
		}},
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

	if sent := clientBase.sentPackets(); len(sent) != 0 {
		t.Fatalf("client sent %d handshake packets, first=%x", len(sent), sent[0])
	}
	if sent := serverBase.sentPackets(); len(sent) != 0 {
		t.Fatalf("server sent %d handshake packets, first=%x", len(sent), sent[0])
	}
	if stats := client.Stats(); stats.Encrypted || stats.Encryption != EncryptionPlaintext {
		t.Fatalf("client stats encrypted=%t encryption=%q, want plaintext", stats.Encrypted, stats.Encryption)
	}

	if err := client.SendPacket([]byte("hello")); err != nil {
		t.Fatalf("send plaintext: %v", err)
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("recv plaintext: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("server received %q, want hello", got)
	}
}

func TestSessionRetainKernelFlowOnCloseForwardsToInner(t *testing.T) {
	clientBase, serverInner := newMemorySessionPair()
	clientInner := &retainMemorySession{memorySession: clientBase}
	serverReady := make(chan *Session, 1)
	serverErr := make(chan error, 1)
	go func() {
		session, err := Server(serverInner, nil, Options{})
		if err != nil {
			serverErr <- err
			return
		}
		serverReady <- session
	}()

	client, err := Client(clientInner, nil, Options{})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	defer client.Close()
	server := waitServer(t, serverReady, serverErr)
	defer server.Close()

	retainer, ok := any(client).(transport.KernelFlowRetentionSession)
	if !ok {
		t.Fatal("secure session does not expose kernel flow retention")
	}
	retainer.RetainKernelFlowOnClose()
	if !clientInner.retained.Load() {
		t.Fatal("secure session did not forward kernel flow retention to inner session")
	}
}

func exerciseTransportWrapper(t *testing.T, tr transport.Transport, protocol transport.Protocol, addr string) {
	exerciseTransportWrapperWithTLS(t, tr, protocol, addr, nil, nil)
}

func exerciseTransportWrapperWithTLS(t *testing.T, tr transport.Transport, protocol transport.Protocol, addr string, clientTLS *tls.Config, serverTLS *tls.Config) (transport.TransportStats, transport.TransportStats) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := tr.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: protocol,
		Listen:    addr,
		Enabled:   true,
	}, serverTLS)
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
			{Name: core.EndpointID("server"), Transport: protocol, Address: addr},
		},
	}, clientTLS)
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
	if !client.Stats().Encrypted || !server.Stats().Encrypted {
		t.Fatal("wrapped transport stats did not report encrypted sessions")
	}
	return client.Stats(), server.Stats()
}

func testTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	root, err := pki.NewRoot("TrustIX Test Root", 1)
	if err != nil {
		t.Fatalf("new root: %v", err)
	}
	domain, err := pki.Issue(root, pki.IssueRequest{
		CommonName: "lab.local domain CA",
		Role:       pki.RoleDomainCA,
		Domain:     "lab.local",
		IsCA:       true,
	})
	if err != nil {
		t.Fatalf("issue domain: %v", err)
	}
	ixA, err := pki.Issue(domain, pki.IssueRequest{
		CommonName: "ix-a",
		Role:       pki.RoleIX,
		Domain:     "lab.local",
		IX:         "ix-a",
	})
	if err != nil {
		t.Fatalf("issue ix-a: %v", err)
	}
	ixB, err := pki.Issue(domain, pki.IssueRequest{
		CommonName: "ix-b",
		Role:       pki.RoleIX,
		Domain:     "lab.local",
		IX:         "ix-b",
	})
	if err != nil {
		t.Fatalf("issue ix-b: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)
	pool.AddCert(domain.Cert)
	clientTLS := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{tlsCertificate(ixA)},
		RootCAs:      pool,
		ServerName:   "lab.local",
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return verifyIXMetadata(rawCerts, "ix-b")
		},
	}
	serverTLS := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{tlsCertificate(ixB)},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return verifyIXMetadata(rawCerts, "ix-a")
		},
	}
	return clientTLS, serverTLS
}

func testLinkTLSConfigs(t *testing.T, serverName string) (*tls.Config, *tls.Config) {
	t.Helper()
	root, err := pki.NewRoot("TrustIX Link TLS Test Root", 1)
	if err != nil {
		t.Fatalf("new link root: %v", err)
	}
	linkCert, err := pki.Issue(root, pki.IssueRequest{
		CommonName:  "TrustIX Link TLS",
		Role:        pki.RoleAdmin,
		Domain:      "link.local",
		IPAddresses: []net.IP{net.ParseIP(serverName)},
		NotAfter:    time.Now().AddDate(1, 0, 0),
	})
	if err != nil {
		t.Fatalf("issue link cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)
	clientTLS := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    pool,
		ServerName: serverName,
	}
	serverTLS := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{tlsCertificate(linkCert)},
	}
	return clientTLS, serverTLS
}

func tlsCertificate(bundle pki.Bundle) tls.Certificate {
	return tls.Certificate{
		Certificate: [][]byte{bundle.Cert.Raw},
		PrivateKey:  bundle.Key,
		Leaf:        bundle.Cert,
	}
}

func tlsCertificateWithChain(bundle pki.Bundle, chain ...pki.Bundle) tls.Certificate {
	cert := tlsCertificate(bundle)
	for _, item := range chain {
		cert.Certificate = append(cert.Certificate, item.Cert.Raw)
	}
	return cert
}

func verifyIXMetadata(rawCerts [][]byte, wantIX string) error {
	if len(rawCerts) == 0 {
		return ErrPeerAuthRequired
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return err
	}
	meta := pki.ParseMetadata(cert)
	if meta.Role != pki.RoleIX || meta.Domain != "lab.local" || meta.IX != wantIX {
		return ErrInvalidHandshake
	}
	return nil
}

func handshakePair(t testing.TB) (*Session, *Session, *memorySession) {
	t.Helper()
	clientInner, serverInner := newMemorySessionPair()
	serverReady := make(chan *Session, 1)
	serverErr := make(chan error, 1)
	go func() {
		session, err := Server(serverInner, nil, Options{Epoch: 1})
		if err != nil {
			serverErr <- err
			return
		}
		serverReady <- session
	}()
	client, err := Client(clientInner, nil, Options{Epoch: 1})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	server := waitServer(t, serverReady, serverErr)
	return client, server, clientInner
}

func handshakeBuildingPair(t testing.TB, clientBatchRecords bool, serverBatchRecords bool) (*Session, *Session, *buildingMemorySession, *buildingMemorySession) {
	t.Helper()
	clientMemory, serverMemory := newMemorySessionPair()
	clientInner := &buildingMemorySession{memorySession: clientMemory}
	serverInner := &buildingMemorySession{memorySession: serverMemory}
	clientOptions := Options{Epoch: 1, BatchRecords: func() bool { return clientBatchRecords }}
	serverOptions := Options{Epoch: 1, BatchRecords: func() bool { return serverBatchRecords }}
	serverReady := make(chan *Session, 1)
	serverErr := make(chan error, 1)
	go func() {
		session, err := Server(serverInner, nil, serverOptions)
		if err != nil {
			serverErr <- err
			return
		}
		serverReady <- session
	}()
	client, err := Client(clientInner, nil, clientOptions)
	if err != nil {
		t.Fatalf("client building handshake: %v", err)
	}
	server := waitServer(t, serverReady, serverErr)
	return client, server, clientInner, serverInner
}

func assertPacketBatchEqual(t testing.TB, got [][]byte, want [][]byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("packet batch length = %d, want %d", len(got), len(want))
	}
	for index := range want {
		if !bytes.Equal(got[index], want[index]) {
			t.Fatalf("packet %d = %x, want %x", index, got[index], want[index])
		}
	}
}

func waitServer(t testing.TB, ready <-chan *Session, errs <-chan error) *Session {
	t.Helper()
	select {
	case err := <-errs:
		t.Fatalf("server handshake: %v", err)
	case session := <-ready:
		return session
	case <-time.After(5 * time.Second):
		t.Fatal("server handshake timed out")
	}
	return nil
}

type memorySession struct {
	in           chan []byte
	out          chan []byte
	peerRef      *memorySession
	mu           sync.Mutex
	sent         [][]byte
	borrowedRecv bool
	releases     int
}

type buildingMemorySession struct {
	*memorySession
	buildCalls     atomic.Uint64
	buildErr       error
	buildSizeDelta int
	builtMu        sync.Mutex
	built          [][]byte
}

func (session *buildingMemorySession) SendBuiltPackets(packetSizes []int, build func(index int, packet []byte) error) error {
	session.buildCalls.Add(1)
	if session.buildErr != nil {
		return session.buildErr
	}
	packets := make([][]byte, len(packetSizes))
	for index, size := range packetSizes {
		size += session.buildSizeDelta
		packets[index] = make([]byte, size)
		if err := build(index, packets[index]); err != nil {
			return err
		}
	}
	session.builtMu.Lock()
	for _, packet := range packets {
		session.built = append(session.built, append([]byte(nil), packet...))
	}
	session.builtMu.Unlock()
	for _, packet := range packets {
		if err := session.SendPacket(packet); err != nil {
			return err
		}
	}
	return nil
}

func (session *buildingMemorySession) builtPackets() [][]byte {
	session.builtMu.Lock()
	defer session.builtMu.Unlock()
	packets := make([][]byte, len(session.built))
	for index, packet := range session.built {
		packets[index] = append([]byte(nil), packet...)
	}
	return packets
}

type handshakeSendFailureSession struct {
	recv    []byte
	sendErr error
}

func (session *handshakeSendFailureSession) SendPacket([]byte) error {
	return session.sendErr
}

func (session *handshakeSendFailureSession) RecvPacket() ([]byte, error) {
	return append([]byte(nil), session.recv...), nil
}

func (session *handshakeSendFailureSession) Close() error {
	return nil
}

func (session *handshakeSendFailureSession) Stats() transport.TransportStats {
	return transport.TransportStats{}
}

type retransmitFailureSession struct {
	sendCalls atomic.Uint64
	sendErr   error
	closeErr  error
	closed    chan struct{}
	closeOnce sync.Once
}

func (session *retransmitFailureSession) SendPacket([]byte) error {
	if session.sendCalls.Add(1) == 1 {
		return nil
	}
	return session.sendErr
}

func (session *retransmitFailureSession) RecvPacket() ([]byte, error) {
	<-session.closed
	return nil, net.ErrClosed
}

func (session *retransmitFailureSession) Close() error {
	session.closeOnce.Do(func() {
		close(session.closed)
	})
	return session.closeErr
}

func (session *retransmitFailureSession) Stats() transport.TransportStats {
	return transport.TransportStats{}
}

type offloadMemorySession struct {
	*memorySession
	offloadMu sync.Mutex
	specs     []transport.CryptoOffloadSpec
}

type retainMemorySession struct {
	*memorySession
	retained atomic.Bool
}

type refusedOnceSession struct {
	*memorySession
	refusals atomic.Uint64
}

type annotatingMemorySession struct {
	*memorySession
	peer   core.IXID
	domain core.DomainID
	detail transport.PeerIdentity
}

type identityMemorySession struct {
	*memorySession
	peer   core.IXID
	domain core.DomainID
}

func (session *annotatingMemorySession) SetPeerIdentity(peer core.IXID, domain core.DomainID) {
	session.peer = peer
	session.domain = domain
	session.detail = transport.PeerIdentity{Peer: peer, Domain: domain}
}

func (session *annotatingMemorySession) SetPeerIdentityDetail(identity transport.PeerIdentity) {
	session.detail = identity
	session.peer = identity.Peer
	session.domain = identity.Domain
}

func (session *identityMemorySession) PeerIdentity() (core.IXID, core.DomainID, bool) {
	return session.peer, session.domain, session.peer != "" || session.domain != ""
}

type singleSessionTransport struct {
	client   transport.Session
	listener transport.Listener
}

func (transportImpl *singleSessionTransport) Name() transport.Protocol {
	return transport.Protocol("memory")
}

func (transportImpl *singleSessionTransport) Probe(ctx context.Context, peer transport.Peer) transport.ProbeResult {
	return transport.ProbeResult{Healthy: true, CheckedAt: time.Now()}
}

func (transportImpl *singleSessionTransport) Dial(ctx context.Context, peer transport.Peer, tlsConf *tls.Config) (transport.Session, error) {
	return transportImpl.client, nil
}

func (transportImpl *singleSessionTransport) Listen(ctx context.Context, ep transport.Endpoint, tlsConf *tls.Config) (transport.Listener, error) {
	return transportImpl.listener, nil
}

type singleSessionListener struct {
	session transport.Session
	ready   chan struct{}
	once    sync.Once
}

func (listener *singleSessionListener) Accept(ctx context.Context) (transport.Session, error) {
	listener.once.Do(func() {
		close(listener.ready)
	})
	return listener.session, nil
}

func (listener *singleSessionListener) Close() error {
	return nil
}

type blockingTransport struct {
	session *blockingSecureSession
}

func (transportImpl *blockingTransport) Name() transport.Protocol {
	return transport.Protocol("blocked")
}

func (transportImpl *blockingTransport) Probe(ctx context.Context, peer transport.Peer) transport.ProbeResult {
	return transport.ProbeResult{Healthy: true, CheckedAt: time.Now()}
}

func (transportImpl *blockingTransport) Dial(ctx context.Context, peer transport.Peer, tlsConf *tls.Config) (transport.Session, error) {
	return transportImpl.session, nil
}

func (transportImpl *blockingTransport) Listen(ctx context.Context, ep transport.Endpoint, tlsConf *tls.Config) (transport.Listener, error) {
	return nil, errors.New("not implemented")
}

type blockingSecureSession struct {
	done      chan struct{}
	closeOnce sync.Once
	closedMu  sync.Mutex
	isClosed  bool
}

func newBlockingSecureSession() *blockingSecureSession {
	return &blockingSecureSession{done: make(chan struct{})}
}

func (session *blockingSecureSession) SendPacket(pkt []byte) error {
	return nil
}

func (session *blockingSecureSession) RecvPacket() ([]byte, error) {
	<-session.done
	return nil, errors.New("closed")
}

func (session *blockingSecureSession) Close() error {
	session.closeOnce.Do(func() {
		session.closedMu.Lock()
		session.isClosed = true
		session.closedMu.Unlock()
		close(session.done)
	})
	return nil
}

func (session *blockingSecureSession) Stats() transport.TransportStats {
	return transport.TransportStats{}
}

func (session *blockingSecureSession) closed() bool {
	session.closedMu.Lock()
	defer session.closedMu.Unlock()
	return session.isClosed
}

func (session *offloadMemorySession) EnableCryptoOffload(spec transport.CryptoOffloadSpec) error {
	session.offloadMu.Lock()
	defer session.offloadMu.Unlock()
	session.specs = append(session.specs, spec)
	return nil
}

func (session *retainMemorySession) RetainKernelFlowOnClose() {
	session.retained.Store(true)
}

func (session *refusedOnceSession) RecvPacket() ([]byte, error) {
	if session.refusals.CompareAndSwap(0, 1) {
		return nil, &net.OpError{Op: "read", Net: "udp", Err: syscall.ECONNREFUSED}
	}
	return session.memorySession.RecvPacket()
}

func (session *offloadMemorySession) lastOffloadSpec(t *testing.T) transport.CryptoOffloadSpec {
	t.Helper()
	session.offloadMu.Lock()
	defer session.offloadMu.Unlock()
	if len(session.specs) == 0 {
		t.Fatal("no crypto offload spec was captured")
	}
	return session.specs[len(session.specs)-1]
}

func requireZeroed(t *testing.T, name string, payload []byte) {
	t.Helper()
	for i, value := range payload {
		if value != 0 {
			t.Fatalf("%s byte %d = 0x%02x, want zero", name, i, value)
		}
	}
}

func newMemorySessionPair() (*memorySession, *memorySession) {
	aToB := make(chan []byte, 16)
	bToA := make(chan []byte, 16)
	a := &memorySession{in: bToA, out: aToB}
	b := &memorySession{in: aToB, out: bToA}
	a.peerRef = b
	b.peerRef = a
	return a, b
}

func (session *memorySession) SendPacket(pkt []byte) error {
	copied := append([]byte(nil), pkt...)
	session.mu.Lock()
	session.sent = append(session.sent, copied)
	session.mu.Unlock()
	session.out <- copied
	return nil
}

func (session *memorySession) RecvPacket() ([]byte, error) {
	pkt := <-session.in
	return append([]byte(nil), pkt...), nil
}

func (session *memorySession) RecvPackets(max int) ([][]byte, error) {
	if max <= 1 {
		pkt, err := session.RecvPacket()
		if err != nil {
			return nil, err
		}
		return [][]byte{pkt}, nil
	}
	first, err := session.RecvPacket()
	if err != nil {
		return nil, err
	}
	packets := make([][]byte, 0, max)
	packets = append(packets, first)
	for len(packets) < max {
		select {
		case pkt := <-session.in:
			packets = append(packets, append([]byte(nil), pkt...))
		default:
			return packets, nil
		}
	}
	return packets, nil
}

func (session *memorySession) RecvPacketsWithRelease(max int) ([][]byte, func(), error) {
	packets, err := session.RecvPackets(max)
	if err != nil {
		return nil, nil, err
	}
	session.mu.Lock()
	borrowed := session.borrowedRecv
	session.mu.Unlock()
	if !borrowed {
		return packets, nil, nil
	}
	return packets, func() {
		session.mu.Lock()
		session.releases++
		session.mu.Unlock()
	}, nil
}

func (session *memorySession) Close() error {
	return nil
}

func (session *memorySession) Stats() transport.TransportStats {
	return transport.TransportStats{}
}

func (session *memorySession) lastSent() []byte {
	session.mu.Lock()
	defer session.mu.Unlock()
	if len(session.sent) == 0 {
		return nil
	}
	return append([]byte(nil), session.sent[len(session.sent)-1]...)
}

func (session *memorySession) sentPackets() [][]byte {
	session.mu.Lock()
	defer session.mu.Unlock()
	out := make([][]byte, 0, len(session.sent))
	for _, pkt := range session.sent {
		out = append(out, append([]byte(nil), pkt...))
	}
	return out
}

func (session *memorySession) peer() *memorySession {
	return session.peerRef
}

func (session *memorySession) enableBorrowedRecv() {
	session.mu.Lock()
	session.borrowedRecv = true
	session.mu.Unlock()
}

func (session *memorySession) releaseCount() int {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.releases
}

func (session *memorySession) inject(pkt []byte) {
	session.in <- append([]byte(nil), pkt...)
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

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve tcp addr: %v", err)
	}
	defer ln.Close()
	return ln.Addr().String()
}
