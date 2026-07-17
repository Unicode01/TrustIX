package secure

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
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
