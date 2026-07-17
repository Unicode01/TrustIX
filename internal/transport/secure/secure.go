// Package secure wraps packet transports with TrustIX's first encrypted overlay
// envelope. The wrapped transport still owns sockets and framing; this layer
// owns handshake, AEAD sealing, header validation, and replay protection.
package secure

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/pki"
	"trustix.local/trustix/internal/transport"
)

const (
	SuiteAES256GCMX25519        = "AES-256-GCM-X25519"
	SuiteAES128GCMX25519        = "AES-128-GCM-X25519"
	SuiteChaCha20Poly1305X25519 = "CHACHA20-POLY1305-X25519"

	EncryptionSecure           = "secure"
	EncryptionPlaintext        = "plaintext"
	EncryptionSendEncrypted    = "send_encrypted"
	EncryptionReceiveEncrypted = "receive_encrypted"

	KeySourceAuto          = "auto"
	KeySourceTrustIXX25519 = "trustix_x25519"
	KeySourceTLSExporter   = "tls_exporter"

	handshakeVersion = 1
	dataVersion      = 1

	helloTypeClient = 1
	helloTypeServer = 2
	helloTypeReset  = 255

	suiteAES256GCMX25519        byte = 1
	suiteAES128GCMX25519        byte = 2
	suiteChaCha20Poly1305X25519 byte = 3

	dataHeaderLen = 24

	sendWireRetainMax       = 256 * 1024
	sendBatchArenaRetainMax = 4 * 1024 * 1024

	maxHandshakeCertLen = 64 * 1024
	maxHandshakeSigLen  = 8 * 1024

	handshakeRetransmitInterval = 200 * time.Millisecond

	tlsExporterLabel = "EXPORTER-TrustIX-secure-transport-v1"

	defaultReplayWindowSize = 65536
	minReplayWindowSize     = 64
	maxReplayWindowSize     = 1 << 20
)

var (
	handshakeMagic = [4]byte{'T', 'I', 'X', 'H'}
	dataMagic      = [4]byte{'T', 'I', 'X', 'D'}

	ErrInvalidHandshake = errors.New("invalid TrustIX secure transport handshake")
	ErrInvalidPacket    = errors.New("invalid TrustIX encrypted packet")
	ErrReplayDetected   = errors.New("TrustIX encrypted packet replay detected")
	ErrPeerAuthRequired = errors.New("TrustIX peer authentication is required")
	ErrSessionReset     = errors.New("TrustIX secure transport session reset")
	ErrSessionResetSent = errors.New("TrustIX secure transport session reset sent")
)

type cryptoSuite struct {
	Name     string
	ID       byte
	KeyLen   int
	NonceLen int
	KDFInfo  string
}

var supportedSuites = []cryptoSuite{
	{
		Name:     SuiteAES256GCMX25519,
		ID:       suiteAES256GCMX25519,
		KeyLen:   32,
		NonceLen: 12,
		KDFInfo:  "TrustIX secure transport AES-256-GCM X25519 v1",
	},
	{
		Name:     SuiteChaCha20Poly1305X25519,
		ID:       suiteChaCha20Poly1305X25519,
		KeyLen:   chacha20poly1305.KeySize,
		NonceLen: chacha20poly1305.NonceSize,
		KDFInfo:  "TrustIX secure transport CHACHA20-POLY1305 X25519 v1",
	},
	{
		Name:     SuiteAES128GCMX25519,
		ID:       suiteAES128GCMX25519,
		KeyLen:   16,
		NonceLen: 12,
		KDFInfo:  "TrustIX secure transport AES-128-GCM X25519 v1",
	},
}

var defaultSuite = supportedSuites[0]

var negotiatedSuitePreference = []string{
	SuiteAES128GCMX25519,
	SuiteAES256GCMX25519,
	SuiteChaCha20Poly1305X25519,
}

func SupportedCryptoSuites() []string {
	out := make([]string, 0, len(supportedSuites))
	for _, suite := range supportedSuites {
		out = append(out, suite.Name)
	}
	return out
}

func NormalizeCryptoSuite(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "":
		return ""
	case SuiteAES256GCMX25519:
		return SuiteAES256GCMX25519
	case SuiteAES128GCMX25519:
		return SuiteAES128GCMX25519
	case SuiteChaCha20Poly1305X25519, "CHACHA20POLY1305-X25519":
		return SuiteChaCha20Poly1305X25519
	default:
		return ""
	}
}

func CryptoSuitesOrDefault(raw []string) []string {
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, item := range raw {
		suite := NormalizeCryptoSuite(item)
		if suite == "" {
			continue
		}
		if _, exists := seen[suite]; exists {
			continue
		}
		seen[suite] = struct{}{}
		out = append(out, suite)
	}
	if len(out) == 0 {
		return []string{defaultSuite.Name}
	}
	return out
}

func suiteByName(name string) (cryptoSuite, bool) {
	normalized := NormalizeCryptoSuite(name)
	for _, suite := range supportedSuites {
		if suite.Name == normalized {
			return suite, true
		}
	}
	return cryptoSuite{}, false
}

func suiteByID(id byte) (cryptoSuite, bool) {
	for _, suite := range supportedSuites {
		if suite.ID == id {
			return suite, true
		}
	}
	return cryptoSuite{}, false
}

func suiteMaskForOptions(options Options) uint16 {
	if options.CryptoSuites == nil {
		return suiteMaskForSuites([]string{defaultSuite.Name})
	}
	return suiteMaskForSuites(options.CryptoSuites())
}

func suiteMaskForSuites(names []string) uint16 {
	var mask uint16
	for _, name := range CryptoSuitesOrDefault(names) {
		suite, ok := suiteByName(name)
		if !ok {
			continue
		}
		mask |= suiteMaskBit(suite.ID)
	}
	if mask == 0 {
		return suiteMaskBit(defaultSuite.ID)
	}
	return mask
}

func normalizedSuiteMask(mask uint16) uint16 {
	if mask == 0 {
		return suiteMaskBit(defaultSuite.ID)
	}
	return mask
}

func isDefaultSuiteMask(mask uint16) bool {
	return normalizedSuiteMask(mask) == suiteMaskBit(defaultSuite.ID)
}

func suiteMaskBit(id byte) uint16 {
	if id == 0 || id > 16 {
		return 0
	}
	return 1 << (id - 1)
}

func negotiateSuite(clientMask uint16, serverMask uint16) (cryptoSuite, error) {
	intersection := normalizedSuiteMask(clientMask) & normalizedSuiteMask(serverMask)
	if intersection == 0 {
		return cryptoSuite{}, fmt.Errorf("%w: no common crypto suite", ErrInvalidHandshake)
	}
	for _, name := range negotiatedSuitePreference {
		suite, ok := suiteByName(name)
		if !ok {
			continue
		}
		if intersection&suiteMaskBit(suite.ID) != 0 {
			return suite, nil
		}
	}
	return cryptoSuite{}, fmt.Errorf("%w: unsupported crypto suite mask 0x%04x", ErrInvalidHandshake, intersection)
}

type Options struct {
	Epoch           uint64
	RequirePeerAuth bool
	KeySource       func() string
	Encryption      func() string
	CryptoSuites    func() []string
	ClientAuthTLS   func(peer transport.Peer) (*tls.Config, error)
	ServerAuthTLS   func() (*tls.Config, error)
}

type EncryptionPolicy struct {
	Mode             string
	SendEncrypted    bool
	ReceiveEncrypted bool
}

func (policy EncryptionPolicy) AnyEncrypted() bool {
	return policy.SendEncrypted || policy.ReceiveEncrypted
}

func (policy EncryptionPolicy) FullyEncrypted() bool {
	return policy.SendEncrypted && policy.ReceiveEncrypted
}

type Transport struct {
	inner   transport.Transport
	options Options
}

func New(inner transport.Transport, options Options) *Transport {
	return &Transport{inner: inner, options: options}
}

func (secureTransport *Transport) Name() transport.Protocol {
	return secureTransport.inner.Name()
}

func (secureTransport *Transport) Probe(ctx context.Context, peer transport.Peer) transport.ProbeResult {
	return secureTransport.inner.Probe(ctx, peer)
}

func (secureTransport *Transport) Dial(ctx context.Context, peer transport.Peer, tlsConf *tls.Config) (transport.Session, error) {
	session, err := secureTransport.inner.Dial(ctx, peer, tlsConf)
	if err != nil {
		return nil, err
	}
	options := secureTransport.optionsForPeer(peer)
	if plaintextHandshakeBypassAllowed(session, options) {
		return newPlaintextBypassSession(session, clientRole, options, peer.ID, peer.DomainID), nil
	}
	authTLSConf := tlsConf
	if secureTransport.options.ClientAuthTLS != nil {
		authTLSConf, err = secureTransport.options.ClientAuthTLS(peer)
		if err != nil {
			return nil, errors.Join(err, wrapCloseError("close data session after client auth config failure", session.Close()))
		}
	}
	secureSession, err := clientWithContext(ctx, session, authTLSConf, options)
	if err != nil {
		return nil, errors.Join(err, wrapCloseError("close data session after client handshake failure", session.Close()))
	}
	return secureSession, nil
}

func (secureTransport *Transport) Listen(ctx context.Context, ep transport.Endpoint, tlsConf *tls.Config) (transport.Listener, error) {
	listener, err := secureTransport.inner.Listen(ctx, ep, tlsConf)
	if err != nil {
		return nil, err
	}
	authTLSConf := tlsConf
	if secureTransport.options.ServerAuthTLS != nil {
		authTLSConf, err = secureTransport.options.ServerAuthTLS()
		if err != nil {
			return nil, errors.Join(err, wrapCloseError("close data listener after server auth config failure", listener.Close()))
		}
	}
	return &Listener{inner: listener, tlsConf: authTLSConf, options: secureTransport.optionsForEndpoint(ep)}, nil
}

func (secureTransport *Transport) optionsForPeer(peer transport.Peer) Options {
	options := secureTransport.options
	if encryption := firstPeerEndpointEncryption(peer); encryption != "" {
		options.Encryption = func() string {
			return encryption
		}
	}
	return options
}

func (secureTransport *Transport) optionsForEndpoint(endpoint transport.Endpoint) Options {
	options := secureTransport.options
	if strings.TrimSpace(endpoint.Encryption) != "" {
		encryption := NormalizeEncryptionMode(endpoint.Encryption)
		options.Encryption = func() string {
			return encryption
		}
	}
	return options
}

func firstPeerEndpointEncryption(peer transport.Peer) string {
	for _, endpoint := range peer.Endpoints {
		if strings.TrimSpace(endpoint.Encryption) != "" {
			return NormalizeEncryptionMode(endpoint.Encryption)
		}
	}
	return ""
}

type Listener struct {
	inner   transport.Listener
	tlsConf *tls.Config
	options Options
}

func (listener *Listener) Accept(ctx context.Context) (transport.Session, error) {
	session, err := listener.inner.Accept(ctx)
	if err != nil {
		return nil, err
	}
	if plaintextHandshakeBypassAllowed(session, listener.options) {
		peerIX, peerDomain, _ := sessionPeerIdentity(session)
		return newPlaintextBypassSession(session, serverRole, listener.options, peerIX, peerDomain), nil
	}
	secureSession, err := serverWithContext(ctx, session, listener.tlsConf, listener.options)
	if err != nil {
		return nil, errors.Join(err, wrapCloseError("close data session after server handshake failure", session.Close()))
	}
	return secureSession, nil
}

func plaintextHandshakeBypassAllowed(inner transport.Session, options Options) bool {
	if policy, ok := inner.(interface{ PlaintextHandshakeBypassDisabled() bool }); ok && policy.PlaintextHandshakeBypassDisabled() {
		return false
	}
	if requestedEncryptionPolicy(options).AnyEncrypted() {
		return false
	}
	if options.RequirePeerAuth {
		return false
	}
	if _, _, ok := sessionPeerIdentity(inner); !ok {
		return false
	}
	return true
}

func sessionPeerIdentity(inner transport.Session) (core.IXID, core.DomainID, bool) {
	if identity, ok := sessionPeerIdentityDetail(inner); ok {
		return identity.Peer, identity.Domain, identity.Peer != "" || identity.Domain != ""
	}
	identity, ok := inner.(transport.PeerIdentitySession)
	if !ok {
		return "", "", false
	}
	return identity.PeerIdentity()
}

func sessionPeerIdentityDetail(inner transport.Session) (transport.PeerIdentity, bool) {
	identity, ok := inner.(transport.PeerIdentityDetailSession)
	if !ok {
		return transport.PeerIdentity{}, false
	}
	return identity.PeerIdentityDetail()
}

func newPlaintextBypassSession(inner transport.Session, role role, options Options, peerIX core.IXID, peerDomain core.DomainID) *Session {
	encryption := requestedEncryptionPolicy(options)
	return &Session{
		inner:          inner,
		role:           role,
		epoch:          options.Epoch,
		encryptionMode: encryption.Mode,
		sendEncrypted:  false,
		recvEncrypted:  false,
		peerIX:         peerIX,
		peerDomain:     peerDomain,
		peerIdentity: transport.PeerIdentity{
			Peer:   peerIX,
			Domain: peerDomain,
		},
		replay: newReplayWindow(defaultReplayWindowSize),
	}
}

func (listener *Listener) Close() error {
	return listener.inner.Close()
}

type handshakeResult struct {
	session *Session
	err     error
}

func clientWithContext(ctx context.Context, inner transport.Session, tlsConf *tls.Config, options Options) (*Session, error) {
	return handshakeWithContext(ctx, inner, func() (*Session, error) {
		return Client(inner, tlsConf, options)
	})
}

func serverWithContext(ctx context.Context, inner transport.Session, tlsConf *tls.Config, options Options) (*Session, error) {
	return handshakeWithContext(ctx, inner, func() (*Session, error) {
		return Server(inner, tlsConf, options)
	})
}

func handshakeWithContext(ctx context.Context, inner transport.Session, run func() (*Session, error)) (*Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, wrapCloseError("close data session before handshake", inner.Close()))
	}
	done := make(chan handshakeResult, 1)
	go func() {
		session, err := run()
		done <- handshakeResult{session: session, err: err}
	}()
	select {
	case result := <-done:
		return result.session, result.err
	case <-ctx.Done():
		return nil, errors.Join(ctx.Err(), wrapCloseError("close data session after handshake cancellation", inner.Close()))
	}
}

func wrapCloseError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

type Session struct {
	inner            transport.Session
	role             role
	sendAEAD         cipher.AEAD
	recvAEAD         cipher.AEAD
	sendIV           []byte
	recvIV           []byte
	epoch            uint64
	cryptoOffloaded  bool
	cryptoPlacement  string
	cryptoSuite      cryptoSuite
	cryptoKeySource  string
	encryptionMode   string
	sendEncrypted    bool
	recvEncrypted    bool
	peerIX           core.IXID
	peerDomain       core.DomainID
	peerIdentity     transport.PeerIdentity
	sendSeq          atomic.Uint64
	sendMu           sync.Mutex
	sendHeader       [dataHeaderLen]byte
	sendNonce        [12]byte
	sendWire         []byte
	sendBatchWire    [][]byte
	sendBatchArena   []byte
	recvBatchPlain   [][]byte
	recvBatchSeqs    []uint64
	recvBatchIndexes []int
	recvBatchAccepts []bool
	replay           replayWindow
	bytesSent        atomic.Uint64
	bytesRecv        atomic.Uint64
	packetsOut       atomic.Uint64
	packetsIn        atomic.Uint64
	clientHelloRaw   []byte
	serverHelloRaw   []byte
}

func Client(inner transport.Session, tlsConf *tls.Config, options Options) (*Session, error) {
	state, clientHello, err := newHandshakeState(helloTypeClient, tlsConf, options)
	if err != nil {
		return nil, err
	}
	encodedHello, err := clientHello.encode()
	if err != nil {
		return nil, err
	}
	if err := inner.SendPacket(encodedHello); err != nil {
		return nil, fmt.Errorf("send TrustIX client hello: %w", err)
	}
	retransmitter := retransmitHandshake(inner, encodedHello)
	rawServerHello, recvErr := recvServerHello(inner)
	retransmitErr := retransmitter.Stop()
	if recvErr != nil {
		return nil, errors.Join(fmt.Errorf("receive TrustIX server hello: %w", recvErr), retransmitErr)
	}
	if retransmitErr != nil {
		return nil, retransmitErr
	}
	serverHello, err := parseHello(rawServerHello, helloTypeServer)
	if err != nil {
		return nil, err
	}
	peerCert, err := verifyHello(serverHello, verifyClientSide, tlsConf, options, serverSignaturePayload(clientHello, serverHello))
	if err != nil {
		return nil, err
	}
	suite, err := negotiateSuite(clientHello.suiteMask, serverHello.suiteMask)
	if err != nil {
		return nil, err
	}
	return newSession(inner, clientRole, state.privateKey, serverHello.publicKey, clientHello.random, serverHello.random, clientHello.publicKey, serverHello.publicKey, options, peerCert, suite, encodedHello, rawServerHello)
}

func recvServerHello(inner transport.Session) ([]byte, error) {
	for {
		packet, err := inner.RecvPacket()
		if err == nil {
			return packet, nil
		}
		if !transientUDPHandshakeReceiveError(err) {
			return nil, err
		}
		time.Sleep(handshakeRetransmitInterval / 2)
	}
}

func transientUDPHandshakeReceiveError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && strings.EqualFold(opErr.Op, "read") {
		if errors.Is(opErr.Err, syscall.ECONNREFUSED) {
			return true
		}
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "connection refused")
}

func Server(inner transport.Session, tlsConf *tls.Config, options Options) (*Session, error) {
	rawClientHello, err := inner.RecvPacket()
	if err != nil {
		return nil, fmt.Errorf("receive TrustIX client hello: %w", err)
	}
	clientHello, err := parseHello(rawClientHello, helloTypeClient)
	if err != nil {
		if errors.Is(err, ErrInvalidHandshake) {
			if resetErr := sendReset(inner); resetErr != nil {
				err = errors.Join(err, resetErr)
			} else {
				err = errors.Join(err, ErrSessionResetSent)
			}
		}
		return nil, err
	}
	peerCert, err := verifyHello(clientHello, verifyServerSide, tlsConf, options, clientSignaturePayload(clientHello))
	if err != nil {
		return nil, err
	}
	state, serverHello, err := newHandshakeState(helloTypeServer, tlsConf, options)
	if err != nil {
		return nil, err
	}
	suite, err := negotiateSuite(clientHello.suiteMask, serverHello.suiteMask)
	if err != nil {
		return nil, err
	}
	serverHello.signature, err = state.sign(serverSignaturePayload(clientHello, serverHello))
	if err != nil {
		return nil, err
	}
	encodedHello, err := serverHello.encode()
	if err != nil {
		return nil, err
	}
	if err := inner.SendPacket(encodedHello); err != nil {
		return nil, fmt.Errorf("send TrustIX server hello: %w", err)
	}
	return newSession(inner, serverRole, state.privateKey, clientHello.publicKey, clientHello.random, serverHello.random, clientHello.publicKey, serverHello.publicKey, options, peerCert, suite, rawClientHello, encodedHello)
}

func (session *Session) SendPacket(pkt []byte) error {
	if !session.sendEncrypted {
		if err := session.inner.SendPacket(pkt); err != nil {
			return err
		}
		session.bytesSent.Add(uint64(len(pkt)))
		session.packetsOut.Add(1)
		return nil
	}
	if session.cryptoOffloaded {
		if err := session.inner.SendPacket(pkt); err != nil {
			return err
		}
		session.bytesSent.Add(uint64(len(pkt)))
		session.packetsOut.Add(1)
		return nil
	}
	seq := session.sendSeq.Add(1)
	session.sendMu.Lock()
	defer session.sendMu.Unlock()
	header := session.sendHeader[:]
	binary.BigEndian.PutUint64(header[16:24], seq)

	copy(session.sendNonce[:4], session.sendIV[:4])
	binary.BigEndian.PutUint64(session.sendNonce[4:], seq)
	needed := dataHeaderLen + len(pkt) + session.sendAEAD.Overhead()
	if cap(session.sendWire) < needed {
		session.sendWire = make([]byte, dataHeaderLen, needed)
	} else {
		session.sendWire = session.sendWire[:dataHeaderLen]
	}
	copy(session.sendWire[:dataHeaderLen], header)
	wire := session.sendAEAD.Seal(session.sendWire, session.sendNonce[:], pkt, header)
	if err := session.inner.SendPacket(wire); err != nil {
		return err
	}
	if cap(session.sendWire) > sendWireRetainMax && needed < sendWireRetainMax/2 {
		session.sendWire = nil
	}
	session.bytesSent.Add(uint64(len(pkt)))
	session.packetsOut.Add(1)
	return nil
}

func (session *Session) SendPackets(pkts [][]byte) error {
	if len(pkts) == 0 {
		return nil
	}
	if !session.sendEncrypted || session.cryptoOffloaded {
		if batch, ok := session.inner.(transport.PacketBatchSession); ok {
			if err := batch.SendPackets(pkts); err != nil {
				return err
			}
			session.recordPacketsSent(pkts)
			return nil
		}
		for _, pkt := range pkts {
			if err := session.inner.SendPacket(pkt); err != nil {
				return err
			}
		}
		session.recordPacketsSent(pkts)
		return nil
	}

	totalWire := 0
	totalPlain := uint64(0)
	overhead := session.sendAEAD.Overhead()
	for _, pkt := range pkts {
		totalWire += dataHeaderLen + len(pkt) + overhead
		totalPlain += uint64(len(pkt))
	}
	session.sendMu.Lock()
	defer session.sendMu.Unlock()
	if cap(session.sendBatchWire) < len(pkts) {
		session.sendBatchWire = make([][]byte, len(pkts))
	} else {
		session.sendBatchWire = session.sendBatchWire[:len(pkts)]
	}
	wire := session.sendBatchWire
	if cap(session.sendBatchArena) < totalWire {
		session.sendBatchArena = make([]byte, 0, totalWire)
	}
	arena := session.sendBatchArena[:0]
	baseSeq := session.sendSeq.Add(uint64(len(pkts))) - uint64(len(pkts)) + 1
	header := session.sendHeader[:]
	copy(session.sendNonce[:4], session.sendIV[:4])
	nonce := session.sendNonce[:]
	for i, pkt := range pkts {
		seq := baseSeq + uint64(i)
		binary.BigEndian.PutUint64(header[16:24], seq)

		binary.BigEndian.PutUint64(nonce[4:], seq)
		base := len(arena)
		needed := dataHeaderLen + len(pkt) + overhead
		arena = arena[:base+dataHeaderLen]
		copy(arena[base:base+dataHeaderLen], header)
		dst := arena[base : base+dataHeaderLen : base+needed]
		sealed := session.sendAEAD.Seal(dst, nonce, pkt, header)
		arena = arena[:base+len(sealed)]
		wire[i] = sealed
	}
	session.sendBatchArena = retainSendBatchArena(arena, totalWire)

	if batch, ok := session.inner.(transport.PacketBatchSession); ok {
		if err := batch.SendPackets(wire); err != nil {
			return err
		}
	} else {
		for _, pkt := range wire {
			if err := session.inner.SendPacket(pkt); err != nil {
				return err
			}
		}
	}
	session.bytesSent.Add(totalPlain)
	session.packetsOut.Add(uint64(len(pkts)))
	return nil
}

func retainSendBatchArena(arena []byte, used int) []byte {
	if cap(arena) > sendBatchArenaRetainMax && used < sendBatchArenaRetainMax/2 {
		return nil
	}
	return arena
}

func (session *Session) recordPacketsSent(pkts [][]byte) {
	var bytes uint64
	var packets uint64
	for _, pkt := range pkts {
		bytes += uint64(len(pkt))
		packets++
	}
	session.bytesSent.Add(bytes)
	session.packetsOut.Add(packets)
}

func (session *Session) RecvPacket() ([]byte, error) {
	for {
		wire, err := session.inner.RecvPacket()
		if err != nil {
			return nil, err
		}
		plaintext, ok, err := session.openReceivedPacket(wire)
		if err != nil {
			if errors.Is(err, ErrReplayDetected) {
				continue
			}
			return nil, err
		}
		if !ok {
			continue
		}
		return plaintext, nil
	}
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
		packet, err := session.RecvPacket()
		if err != nil {
			return nil, nil, err
		}
		return [][]byte{packet}, nil, nil
	}
	if receiver, ok := session.inner.(transport.PacketBatchReceiverWithRelease); ok {
		return session.recvPacketsWithRelease(max, receiver)
	}
	if receiver, ok := session.inner.(transport.PacketBatchReceiver); ok {
		return session.recvPacketsFromBatchReceiver(max, receiver)
	}
	packet, err := session.RecvPacket()
	if err != nil {
		return nil, nil, err
	}
	return [][]byte{packet}, nil, nil
}

func (session *Session) recvPacketsFromBatchReceiver(max int, receiver transport.PacketBatchReceiver) ([][]byte, func(), error) {
	for {
		wirePackets, err := receiver.RecvPackets(max)
		if err != nil {
			return nil, nil, err
		}
		if cap(session.recvBatchPlain) < len(wirePackets) {
			session.recvBatchPlain = make([][]byte, 0, len(wirePackets))
		} else {
			session.recvBatchPlain = session.recvBatchPlain[:0]
		}
		plaintextPackets := session.recvBatchPlain
		plaintextPackets, bytesReceived, packetsReceived, err := session.openReceivedPacketBatch(plaintextPackets, wirePackets)
		if err != nil {
			return nil, nil, err
		}
		if len(plaintextPackets) > 0 {
			session.recvBatchPlain = plaintextPackets
			session.recordPacketsReceived(bytesReceived, packetsReceived)
			return plaintextPackets, nil, nil
		}
		session.recvBatchPlain = plaintextPackets
	}
}

func (session *Session) recvPacketsWithRelease(max int, receiver transport.PacketBatchReceiverWithRelease) ([][]byte, func(), error) {
	for {
		wirePackets, release, err := receiver.RecvPacketsWithRelease(max)
		if err != nil {
			if release != nil {
				release()
			}
			return nil, nil, err
		}
		if cap(session.recvBatchPlain) < len(wirePackets) {
			session.recvBatchPlain = make([][]byte, 0, len(wirePackets))
		} else {
			session.recvBatchPlain = session.recvBatchPlain[:0]
		}
		plaintextPackets := session.recvBatchPlain
		plaintextPackets, bytesReceived, packetsReceived, err := session.openReceivedPacketBatch(plaintextPackets, wirePackets)
		if err != nil {
			if release != nil {
				release()
			}
			return nil, nil, err
		}
		if len(plaintextPackets) > 0 {
			session.recvBatchPlain = plaintextPackets
			session.recordPacketsReceived(bytesReceived, packetsReceived)
			return plaintextPackets, release, nil
		}
		session.recvBatchPlain = plaintextPackets
		if release != nil {
			release()
		}
	}
}

func (session *Session) openReceivedPacket(wire []byte) ([]byte, bool, error) {
	plaintext, ok, err := session.openReceivedPacketNoStats(wire)
	if err != nil || !ok {
		return plaintext, ok, err
	}
	session.recordPacketsReceived(uint64(len(plaintext)), 1)
	return plaintext, ok, nil
}

func (session *Session) openReceivedPacketBatch(dst [][]byte, wirePackets [][]byte) ([][]byte, uint64, uint64, error) {
	if len(wirePackets) == 0 {
		return dst, 0, 0, nil
	}
	if !session.recvEncrypted {
		var bytesReceived uint64
		startLen := len(dst)
		for _, wire := range wirePackets {
			if isResetPacket(wire) {
				return dst, bytesReceived, uint64(len(dst) - startLen), ErrSessionReset
			}
			handled, err := session.handleDuplicateHandshake(wire)
			if err != nil {
				return dst, bytesReceived, uint64(len(dst) - startLen), err
			}
			if handled {
				continue
			}
			dst = append(dst, wire)
			bytesReceived += uint64(len(wire))
		}
		return dst, bytesReceived, uint64(len(dst) - startLen), nil
	}
	if cap(session.recvBatchSeqs) < len(wirePackets) {
		session.recvBatchSeqs = make([]uint64, 0, len(wirePackets))
	} else {
		session.recvBatchSeqs = session.recvBatchSeqs[:0]
	}
	if cap(session.recvBatchIndexes) < len(wirePackets) {
		session.recvBatchIndexes = make([]int, 0, len(wirePackets))
	} else {
		session.recvBatchIndexes = session.recvBatchIndexes[:0]
	}
	seqs := session.recvBatchSeqs
	seqIndexes := session.recvBatchIndexes
	startLen := len(dst)
	var bytesReceived uint64
	for _, wire := range wirePackets {
		if isResetPacket(wire) {
			return dst, bytesReceived, uint64(len(dst) - startLen), ErrSessionReset
		}
		handled, err := session.handleDuplicateHandshake(wire)
		if err != nil {
			return dst, bytesReceived, uint64(len(dst) - startLen), err
		}
		if handled {
			continue
		}
		if session.cryptoOffloaded && !session.shouldOpenUserspaceEncryptedFallback(wire) {
			dst = append(dst, wire)
			bytesReceived += uint64(len(wire))
			continue
		}
		plaintext, seq, err := session.openEncryptedPacketNoReplay(wire)
		if err != nil {
			return dst, bytesReceived, uint64(len(dst) - startLen), err
		}
		dst = append(dst, plaintext)
		seqs = append(seqs, seq)
		seqIndexes = append(seqIndexes, len(dst)-1)
		bytesReceived += uint64(len(plaintext))
	}
	if len(seqs) == 0 {
		session.recvBatchSeqs = seqs
		session.recvBatchIndexes = seqIndexes
		return dst, bytesReceived, uint64(len(dst) - startLen), nil
	}
	accepted := session.replay.AcceptBatchResults(seqs, session.recvBatchAccepts[:0])
	dst, bytesReceived = filterReplayRejectedBatch(dst, startLen, seqIndexes, accepted, bytesReceived)
	session.recvBatchSeqs = seqs
	session.recvBatchIndexes = seqIndexes
	session.recvBatchAccepts = accepted
	return dst, bytesReceived, uint64(len(dst) - startLen), nil
}

func filterReplayRejectedBatch(dst [][]byte, startLen int, seqIndexes []int, accepted []bool, bytesReceived uint64) ([][]byte, uint64) {
	if len(seqIndexes) == 0 || len(seqIndexes) != len(accepted) {
		return dst, bytesReceived
	}
	allAccepted := true
	for _, ok := range accepted {
		if !ok {
			allAccepted = false
			break
		}
	}
	if allAccepted {
		return dst, bytesReceived
	}
	write := startLen
	seqCursor := 0
	for read := startLen; read < len(dst); read++ {
		keep := true
		if seqCursor < len(seqIndexes) && seqIndexes[seqCursor] == read {
			keep = accepted[seqCursor]
			seqCursor++
		}
		if !keep {
			bytesReceived -= uint64(len(dst[read]))
			continue
		}
		dst[write] = dst[read]
		write++
	}
	clear(dst[write:])
	return dst[:write], bytesReceived
}

func (session *Session) openReceivedPacketNoStats(wire []byte) ([]byte, bool, error) {
	if isResetPacket(wire) {
		return nil, false, ErrSessionReset
	}
	handled, err := session.handleDuplicateHandshake(wire)
	if err != nil {
		return nil, false, err
	}
	if handled {
		return nil, false, nil
	}
	if !session.recvEncrypted {
		return wire, true, nil
	}
	if session.cryptoOffloaded && !session.shouldOpenUserspaceEncryptedFallback(wire) {
		return wire, true, nil
	}
	plaintext, seq, err := session.openEncryptedPacketNoReplay(wire)
	if err != nil {
		return nil, false, err
	}
	if !session.replay.Accept(seq) {
		return nil, false, ErrReplayDetected
	}
	return plaintext, true, nil
}

func (session *Session) shouldOpenUserspaceEncryptedFallback(wire []byte) bool {
	return len(wire) >= len(dataMagic) && bytes.Equal(wire[:len(dataMagic)], dataMagic[:])
}

func (session *Session) openEncryptedPacketNoReplay(wire []byte) ([]byte, uint64, error) {
	if session.recvAEAD == nil {
		return nil, 0, ErrInvalidPacket
	}
	if len(wire) < dataHeaderLen+session.recvAEAD.Overhead() {
		return nil, 0, ErrInvalidPacket
	}
	header := wire[:dataHeaderLen]
	if !bytes.Equal(header[0:4], dataMagic[:]) || header[4] != dataVersion || header[5] != session.cryptoSuite.ID {
		return nil, 0, ErrInvalidPacket
	}
	epoch := binary.BigEndian.Uint64(header[8:16])
	if epoch != session.epoch {
		return nil, 0, fmt.Errorf("%w: epoch %d != %d", ErrInvalidPacket, epoch, session.epoch)
	}
	seq := binary.BigEndian.Uint64(header[16:24])
	var nonce [12]byte
	copy(nonce[:], session.recvIV)
	binary.BigEndian.PutUint64(nonce[4:], seq)
	ciphertext := wire[dataHeaderLen:]
	plaintext, err := session.recvAEAD.Open(nil, nonce[:], ciphertext, header)
	if err != nil {
		compatCiphertext := wire[dataHeaderLen:]
		plaintext, err = session.recvAEAD.Open(nil, nonce[:], compatCiphertext, nil)
		if err != nil {
			return nil, 0, fmt.Errorf("%w: %v", ErrInvalidPacket, err)
		}
	}
	return plaintext, seq, nil
}

func (session *Session) recordPacketsReceived(bytesReceived uint64, packetsReceived uint64) {
	if packetsReceived == 0 {
		return
	}
	session.bytesRecv.Add(bytesReceived)
	session.packetsIn.Add(packetsReceived)
}

func (session *Session) Close() error {
	return session.inner.Close()
}

func (session *Session) RetainKernelFlowOnClose() {
	if retainer, ok := session.inner.(transport.KernelFlowRetentionSession); ok {
		retainer.RetainKernelFlowOnClose()
	}
}

func (session *Session) KernelDatapathSessionInfo() (transport.KernelDatapathSessionInfo, bool) {
	if session == nil {
		return transport.KernelDatapathSessionInfo{}, false
	}
	introspector, ok := session.inner.(transport.KernelDatapathSession)
	if !ok {
		return transport.KernelDatapathSessionInfo{}, false
	}
	info, ok := introspector.KernelDatapathSessionInfo()
	if !ok {
		return transport.KernelDatapathSessionInfo{}, false
	}
	stats := session.Stats()
	if session.peerIX != "" {
		info.Peer = session.peerIX
	}
	info.Encrypted = stats.Encrypted
	info.SendEncrypted = stats.SendEncrypted
	info.ReceiveEncrypted = stats.ReceiveEncrypted
	info.CryptoSuite = stats.CryptoSuite
	info.CryptoPlacement = stats.CryptoPlacement
	info.MaxPacketSize = stats.MaxPacketSize
	return info, true
}

func (session *Session) PeerIdentity() (core.IXID, core.DomainID, bool) {
	return session.peerIX, session.peerDomain, session.peerIX != "" || session.peerDomain != ""
}

func (session *Session) PeerIdentityDetail() (transport.PeerIdentity, bool) {
	return session.peerIdentity, session.peerIdentity.Peer != "" || session.peerIdentity.Domain != "" || session.peerIdentity.Device != "" || session.peerIdentity.Role != ""
}

func (session *Session) SetPeerEndpoint(peer core.IXID, endpoint core.EndpointID) {
	if annotator, ok := session.inner.(transport.PeerEndpointAnnotator); ok {
		annotator.SetPeerEndpoint(peer, endpoint)
	}
}

func (session *Session) Stats() transport.TransportStats {
	stats := session.inner.Stats()
	stats.BytesSent = session.bytesSent.Load()
	stats.BytesReceived = session.bytesRecv.Load()
	stats.PacketsSent = session.packetsOut.Load()
	stats.PacketsReceived = session.packetsIn.Load()
	stats.Encryption = session.encryptionMode
	stats.Encrypted = session.sendEncrypted || session.recvEncrypted
	stats.SendEncrypted = session.sendEncrypted
	stats.ReceiveEncrypted = session.recvEncrypted
	if stats.Encrypted {
		stats.CryptoSuite = session.cryptoSuite.Name
		stats.CryptoKeySource = session.cryptoKeySource
		if session.cryptoOffloaded {
			stats.CryptoPlacement = session.cryptoPlacement
		} else {
			stats.CryptoPlacement = "userspace"
		}
	}
	if stats.Datagram && stats.MaxPacketSize > 0 && session.sendEncrypted && !session.cryptoOffloaded && session.sendAEAD != nil {
		overhead := uint64(dataHeaderLen + session.sendAEAD.Overhead())
		if stats.MaxPacketSize > overhead {
			stats.MaxPacketSize -= overhead
		} else {
			stats.MaxPacketSize = 0
		}
	}
	stats.ReplayWindow = uint(session.replay.Size())
	return stats
}

type role uint8

const (
	clientRole role = iota + 1
	serverRole
)

type handshakeState struct {
	privateKey *ecdh.PrivateKey
	certDER    []byte
	signer     crypto.Signer
}

type hello struct {
	messageType byte
	suiteMask   uint16
	random      []byte
	publicKey   []byte
	certDER     []byte
	signature   []byte
}

func newHandshakeState(messageType byte, tlsConf *tls.Config, options Options) (handshakeState, hello, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return handshakeState{}, hello{}, fmt.Errorf("generate TrustIX transport key: %w", err)
	}
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return handshakeState{}, hello{}, fmt.Errorf("generate TrustIX transport random: %w", err)
	}
	state := handshakeState{privateKey: privateKey}
	state.certDER, state.signer, err = localCertificate(tlsConf)
	if err != nil {
		return handshakeState{}, hello{}, err
	}
	helloMsg := hello{
		messageType: messageType,
		suiteMask:   suiteMaskForOptions(options),
		random:      randomBytes,
		publicKey:   privateKey.PublicKey().Bytes(),
		certDER:     state.certDER,
	}
	if messageType == helloTypeClient {
		helloMsg.signature, err = state.sign(clientSignaturePayload(helloMsg))
		if err != nil {
			return handshakeState{}, hello{}, err
		}
	}
	return state, helloMsg, nil
}

func (state handshakeState) sign(payload []byte) ([]byte, error) {
	if state.signer == nil {
		return nil, nil
	}
	signature, err := pki.Sign(state.signer, payload)
	if err != nil {
		return nil, fmt.Errorf("sign TrustIX secure transport handshake: %w", err)
	}
	return signature, nil
}

func localCertificate(tlsConf *tls.Config) ([]byte, crypto.Signer, error) {
	if tlsConf == nil || len(tlsConf.Certificates) == 0 || len(tlsConf.Certificates[0].Certificate) == 0 {
		return nil, nil, nil
	}
	certificate := tlsConf.Certificates[0]
	signer, ok := certificate.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("TrustIX transport certificate key is %T, want crypto.Signer", certificate.PrivateKey)
	}
	total := 0
	for _, certDER := range certificate.Certificate {
		total += len(certDER)
	}
	chainDER := make([]byte, 0, total)
	for _, certDER := range certificate.Certificate {
		chainDER = append(chainDER, certDER...)
	}
	return chainDER, signer, nil
}

func (hello hello) encode() ([]byte, error) {
	if len(hello.certDER) > maxHandshakeCertLen || len(hello.signature) > maxHandshakeSigLen {
		return nil, fmt.Errorf("%w: handshake certificate or signature is too large", ErrInvalidHandshake)
	}
	payload := make([]byte, 0, 76+len(hello.certDER)+len(hello.signature))
	payload = append(payload, handshakeMagic[:]...)
	payload = append(payload, handshakeVersion, hello.messageType)
	payload = binary.BigEndian.AppendUint16(payload, normalizedSuiteMask(hello.suiteMask))
	payload = append(payload, hello.random...)
	payload = append(payload, hello.publicKey...)
	payload = binary.BigEndian.AppendUint16(payload, uint16(len(hello.certDER)))
	payload = binary.BigEndian.AppendUint16(payload, uint16(len(hello.signature)))
	payload = append(payload, hello.certDER...)
	payload = append(payload, hello.signature...)
	return payload, nil
}

func resetPacket() []byte {
	payload := make([]byte, 76)
	copy(payload[0:4], handshakeMagic[:])
	payload[4] = handshakeVersion
	payload[5] = helloTypeReset
	return payload
}

func sendReset(session transport.Session) error {
	if err := session.SendPacket(resetPacket()); err != nil {
		return fmt.Errorf("send TrustIX secure transport reset: %w", err)
	}
	return nil
}

type handshakeRetransmitter struct {
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
	mu       sync.Mutex
	err      error
}

func retransmitHandshake(session transport.Session, packet []byte) *handshakeRetransmitter {
	retransmitter := &handshakeRetransmitter{
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	go func() {
		defer close(retransmitter.done)
		ticker := time.NewTicker(handshakeRetransmitInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := session.SendPacket(packet); err != nil {
					retransmitter.mu.Lock()
					retransmitter.err = errors.Join(
						fmt.Errorf("retransmit TrustIX client hello: %w", err),
						wrapCloseError("close data session after handshake retransmit failure", session.Close()),
					)
					retransmitter.mu.Unlock()
					return
				}
			case <-retransmitter.stop:
				return
			}
		}
	}()
	return retransmitter
}

func (retransmitter *handshakeRetransmitter) Stop() error {
	retransmitter.stopOnce.Do(func() {
		close(retransmitter.stop)
	})
	<-retransmitter.done
	retransmitter.mu.Lock()
	defer retransmitter.mu.Unlock()
	return retransmitter.err
}

func isResetPacket(packet []byte) bool {
	return len(packet) == 76 &&
		bytes.Equal(packet[0:4], handshakeMagic[:]) &&
		packet[4] == handshakeVersion &&
		packet[5] == helloTypeReset
}

func (session *Session) handleDuplicateHandshake(packet []byte) (bool, error) {
	if len(packet) < 6 || !bytes.Equal(packet[0:4], handshakeMagic[:]) || packet[4] != handshakeVersion {
		return false, nil
	}
	switch packet[5] {
	case helloTypeClient:
		if session.role != serverRole {
			return false, nil
		}
		if len(session.clientHelloRaw) > 0 && bytes.Equal(packet, session.clientHelloRaw) {
			if len(session.serverHelloRaw) > 0 {
				if err := session.inner.SendPacket(session.serverHelloRaw); err != nil {
					return true, fmt.Errorf("resend TrustIX server hello: %w", err)
				}
			}
			return true, nil
		}
	case helloTypeServer:
		if session.role != clientRole {
			return false, nil
		}
		if len(session.serverHelloRaw) > 0 && bytes.Equal(packet, session.serverHelloRaw) {
			return true, nil
		}
	}
	return false, nil
}

func parseHello(raw []byte, wantType byte) (hello, error) {
	if isResetPacket(raw) {
		return hello{}, ErrSessionReset
	}
	if len(raw) < 76 || !bytes.Equal(raw[0:4], handshakeMagic[:]) || raw[4] != handshakeVersion || raw[5] != wantType {
		return hello{}, ErrInvalidHandshake
	}
	certLen := int(binary.BigEndian.Uint16(raw[72:74]))
	sigLen := int(binary.BigEndian.Uint16(raw[74:76]))
	if certLen > maxHandshakeCertLen || sigLen > maxHandshakeSigLen || len(raw) != 76+certLen+sigLen {
		return hello{}, ErrInvalidHandshake
	}
	return hello{
		messageType: raw[5],
		suiteMask:   binary.BigEndian.Uint16(raw[6:8]),
		random:      slices.Clone(raw[8:40]),
		publicKey:   slices.Clone(raw[40:72]),
		certDER:     slices.Clone(raw[76 : 76+certLen]),
		signature:   slices.Clone(raw[76+certLen:]),
	}, nil
}

type verifySide uint8

const (
	verifyClientSide verifySide = iota + 1
	verifyServerSide
)

func verifyHello(peerHello hello, side verifySide, tlsConf *tls.Config, options Options, signedPayload []byte) (*x509.Certificate, error) {
	authRequired := options.RequirePeerAuth || peerAuthRequired(side, tlsConf)
	if len(peerHello.certDER) == 0 {
		if authRequired {
			return nil, ErrPeerAuthRequired
		}
		return nil, nil
	}
	certs, err := x509.ParseCertificates(peerHello.certDER)
	if err != nil {
		return nil, fmt.Errorf("%w: parse peer certificate: %v", ErrInvalidHandshake, err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: peer certificate chain is empty", ErrInvalidHandshake)
	}
	cert := certs[0]
	intermediates := certs[1:]
	if len(peerHello.signature) == 0 {
		return nil, fmt.Errorf("%w: missing authenticated handshake signature", ErrInvalidHandshake)
	}
	if err := pki.Verify(cert, signedPayload, peerHello.signature); err != nil {
		return nil, fmt.Errorf("%w: verify handshake signature: %v", ErrInvalidHandshake, err)
	}
	if tlsConf == nil {
		return cert, nil
	}
	if err := verifyCertificateChain(cert, intermediates, side, tlsConf); err != nil {
		return nil, err
	}
	if tlsConf.VerifyPeerCertificate != nil {
		var chains [][]*x509.Certificate
		if chain, err := verifiedChain(cert, intermediates, side, tlsConf); err == nil {
			chains = [][]*x509.Certificate{chain}
		}
		rawCerts := make([][]byte, len(certs))
		for i, parsed := range certs {
			rawCerts[i] = parsed.Raw
		}
		if err := tlsConf.VerifyPeerCertificate(rawCerts, chains); err != nil {
			return nil, fmt.Errorf("%w: peer certificate callback rejected certificate: %v", ErrInvalidHandshake, err)
		}
	}
	return cert, nil
}

func peerAuthRequired(side verifySide, tlsConf *tls.Config) bool {
	if tlsConf == nil {
		return false
	}
	switch side {
	case verifyClientSide:
		return tlsConf.RootCAs != nil || tlsConf.ServerName != "" || tlsConf.VerifyPeerCertificate != nil
	case verifyServerSide:
		return tlsConf.ClientAuth >= tls.RequireAnyClientCert || tlsConf.ClientCAs != nil || tlsConf.VerifyPeerCertificate != nil
	default:
		return false
	}
}

func verifyCertificateChain(cert *x509.Certificate, intermediates []*x509.Certificate, side verifySide, tlsConf *tls.Config) error {
	if tlsConf == nil {
		return nil
	}
	if _, err := verifiedChain(cert, intermediates, side, tlsConf); err != nil {
		return err
	}
	return nil
}

func verifiedChain(cert *x509.Certificate, intermediates []*x509.Certificate, side verifySide, tlsConf *tls.Config) ([]*x509.Certificate, error) {
	var roots *x509.CertPool
	if side == verifyClientSide {
		roots = tlsConf.RootCAs
	} else {
		roots = tlsConf.ClientCAs
	}
	if roots == nil {
		return []*x509.Certificate{cert}, nil
	}
	intermediatePool := x509.NewCertPool()
	for _, intermediate := range intermediates {
		intermediatePool.AddCert(intermediate)
	}
	options := x509.VerifyOptions{Roots: roots, Intermediates: intermediatePool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
	if side == verifyClientSide {
		options.DNSName = tlsConf.ServerName
	}
	chains, err := cert.Verify(options)
	if err != nil {
		return nil, fmt.Errorf("%w: verify peer certificate chain: %v", ErrInvalidHandshake, err)
	}
	if len(chains) == 0 {
		return nil, fmt.Errorf("%w: peer certificate chain is empty", ErrInvalidHandshake)
	}
	return chains[0], nil
}

func clientSignaturePayload(clientHello hello) []byte {
	payload := []byte("TrustIX secure transport client hello v1\x00")
	payload = appendSuiteMaskForSignature(payload, clientHello)
	payload = append(payload, clientHello.random...)
	payload = append(payload, clientHello.publicKey...)
	payload = append(payload, clientHello.certDER...)
	return payload
}

func serverSignaturePayload(clientHello hello, serverHello hello) []byte {
	payload := []byte("TrustIX secure transport server hello v1\x00")
	payload = appendSuiteMaskForSignature(payload, clientHello)
	payload = appendSuiteMaskForSignature(payload, serverHello)
	payload = append(payload, clientHello.random...)
	payload = append(payload, clientHello.publicKey...)
	payload = append(payload, serverHello.random...)
	payload = append(payload, serverHello.publicKey...)
	payload = append(payload, serverHello.certDER...)
	return payload
}

func appendSuiteMaskForSignature(payload []byte, hello hello) []byte {
	if isDefaultSuiteMask(hello.suiteMask) {
		return payload
	}
	payload = append(payload, "suite_mask\x00"...)
	return binary.BigEndian.AppendUint16(payload, normalizedSuiteMask(hello.suiteMask))
}

func newSession(inner transport.Session, role role, privateKey *ecdh.PrivateKey, peerPublicBytes []byte, clientRandom []byte, serverRandom []byte, clientPublic []byte, serverPublic []byte, options Options, peerCert *x509.Certificate, suite cryptoSuite, clientHelloRaw []byte, serverHelloRaw []byte) (*Session, error) {
	peerPublic, err := ecdh.X25519().NewPublicKey(peerPublicBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parse peer X25519 key: %v", ErrInvalidHandshake, err)
	}
	secret, err := privateKey.ECDH(peerPublic)
	if err != nil {
		return nil, fmt.Errorf("derive TrustIX transport shared secret: %w", err)
	}
	defer clearBytes(secret)
	encryption := requestedEncryptionPolicy(options)
	session := &Session{
		inner:           inner,
		role:            role,
		epoch:           options.Epoch,
		encryptionMode:  encryption.Mode,
		sendEncrypted:   encryption.SendEncrypted,
		recvEncrypted:   encryption.ReceiveEncrypted,
		cryptoSuite:     suite,
		cryptoKeySource: "",
		replay:          newReplayWindow(defaultReplayWindowSize),
		clientHelloRaw:  slices.Clone(clientHelloRaw),
		serverHelloRaw:  slices.Clone(serverHelloRaw),
	}
	session.initDataHeader()
	if peerCert != nil {
		meta := pki.ParseMetadata(peerCert)
		session.peerIX = core.IXID(meta.IX)
		session.peerDomain = core.DomainID(meta.Domain)
		session.peerIdentity = transport.PeerIdentity{
			Role:            string(meta.Role),
			Peer:            session.peerIX,
			Domain:          session.peerDomain,
			Device:          core.DeviceID(meta.Device),
			LANID:           meta.LANID,
			Prefixes:        append([]string(nil), meta.Prefixes...),
			CertFingerprint: pki.CertificateFingerprintSHA256(peerCert),
		}
		if annotator, ok := inner.(transport.PeerIdentityDetailAnnotator); ok {
			annotator.SetPeerIdentityDetail(session.peerIdentity)
		} else if annotator, ok := inner.(transport.PeerIdentityAnnotator); ok {
			annotator.SetPeerIdentity(session.peerIX, session.peerDomain)
		}
	}
	if !encryption.AnyEncrypted() {
		return session, nil
	}
	material, keySource, err := deriveSessionKeyMaterial(inner, secret, clientRandom, serverRandom, clientPublic, serverPublic, options, suite)
	if err != nil {
		return nil, err
	}
	defer clearBytes(material)
	clientKey := material[0:suite.KeyLen]
	serverKey := material[suite.KeyLen : suite.KeyLen*2]
	clientIV := material[suite.KeyLen*2 : suite.KeyLen*2+suite.NonceLen]
	serverIV := material[suite.KeyLen*2+suite.NonceLen:]
	clientAEAD, err := newAEAD(suite, clientKey)
	if err != nil {
		return nil, err
	}
	serverAEAD, err := newAEAD(suite, serverKey)
	if err != nil {
		return nil, err
	}
	session.cryptoKeySource = keySource
	if role == clientRole {
		if encryption.SendEncrypted {
			session.sendAEAD = clientAEAD
			session.sendIV = slices.Clone(clientIV)
		}
		if encryption.ReceiveEncrypted {
			session.recvAEAD = serverAEAD
			session.recvIV = slices.Clone(serverIV)
		}
	} else {
		if encryption.SendEncrypted {
			session.sendAEAD = serverAEAD
			session.sendIV = slices.Clone(serverIV)
		}
		if encryption.ReceiveEncrypted {
			session.recvAEAD = clientAEAD
			session.recvIV = slices.Clone(clientIV)
		}
	}
	if err := session.enableCryptoOffload(role, clientKey, serverKey, clientIV, serverIV); err != nil {
		return nil, err
	}
	return session, nil
}

func (session *Session) initDataHeader() {
	copy(session.sendHeader[0:4], dataMagic[:])
	session.sendHeader[4] = dataVersion
	session.sendHeader[5] = session.cryptoSuite.ID
	session.sendHeader[6] = 0
	session.sendHeader[7] = 0
	binary.BigEndian.PutUint64(session.sendHeader[8:16], session.epoch)
}

func (session *Session) enableCryptoOffload(role role, clientKey, serverKey, clientIV, serverIV []byte) error {
	if !session.sendEncrypted || !session.recvEncrypted {
		return nil
	}
	offloader, ok := session.inner.(transport.CryptoOffloadSession)
	if !ok {
		return nil
	}
	spec := transport.CryptoOffloadSpec{
		Suite:        session.cryptoSuite.Name,
		WireFormat:   transport.CryptoWireFormatTrustIXSecureDataV1,
		KeySource:    session.cryptoKeySource,
		Epoch:        session.epoch,
		ReplayWindow: uint(session.replay.Size()),
	}
	if role == clientRole {
		spec.SendKey = slices.Clone(clientKey)
		spec.SendIV = slices.Clone(clientIV)
		spec.RecvKey = slices.Clone(serverKey)
		spec.RecvIV = slices.Clone(serverIV)
	} else {
		spec.SendKey = slices.Clone(serverKey)
		spec.SendIV = slices.Clone(serverIV)
		spec.RecvKey = slices.Clone(clientKey)
		spec.RecvIV = slices.Clone(clientIV)
	}
	defer clearCryptoOffloadSpec(&spec)
	if err := offloader.EnableCryptoOffload(spec); err != nil {
		if errors.Is(err, transport.ErrCryptoOffloadUnavailable) {
			return nil
		}
		return fmt.Errorf("enable TrustIX crypto offload: %w", err)
	}
	session.cryptoOffloaded = true
	session.clearUserspaceSendCrypto()
	if stats := session.inner.Stats(); stats.CryptoPlacement != "" {
		session.cryptoPlacement = stats.CryptoPlacement
	} else {
		session.cryptoPlacement = "kernel"
	}
	return nil
}

func (session *Session) clearUserspaceSendCrypto() {
	clearBytes(session.sendIV)
	clearBytes(session.sendNonce[:])
	session.sendIV = nil
	session.sendAEAD = nil
}

func clearCryptoOffloadSpec(spec *transport.CryptoOffloadSpec) {
	if spec == nil {
		return
	}
	clearBytes(spec.SendKey)
	clearBytes(spec.SendIV)
	clearBytes(spec.RecvKey)
	clearBytes(spec.RecvIV)
	spec.SendKey = nil
	spec.SendIV = nil
	spec.RecvKey = nil
	spec.RecvIV = nil
}

func clearBytes(payload []byte) {
	for i := range payload {
		payload[i] = 0
	}
}

func newAEAD(suite cryptoSuite, key []byte) (cipher.AEAD, error) {
	switch suite.Name {
	case SuiteAES256GCMX25519, SuiteAES128GCMX25519:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("create TrustIX AEAD: %w", err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("create TrustIX GCM: %w", err)
		}
		return aead, nil
	case SuiteChaCha20Poly1305X25519:
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, fmt.Errorf("create TrustIX ChaCha20-Poly1305: %w", err)
		}
		return aead, nil
	default:
		return nil, fmt.Errorf("%w: unsupported crypto suite %q", ErrInvalidHandshake, suite.Name)
	}
}

func deriveSessionKeyMaterial(inner transport.Session, secret []byte, clientRandom []byte, serverRandom []byte, clientPublic []byte, serverPublic []byte, options Options, suite cryptoSuite) ([]byte, string, error) {
	requested := requestedKeySource(options)
	materialLen := suite.KeyLen*2 + suite.NonceLen*2
	switch requested {
	case KeySourceTLSExporter:
		material, err := deriveTLSExporterKeyMaterial(inner, clientRandom, serverRandom, clientPublic, serverPublic, materialLen, suite)
		if err != nil {
			return nil, "", err
		}
		return material, KeySourceTLSExporter, nil
	case KeySourceTrustIXX25519:
		return deriveKeyMaterial(secret, clientRandom, serverRandom, materialLen, suite), KeySourceTrustIXX25519, nil
	case KeySourceAuto:
		material, err := deriveTLSExporterKeyMaterial(inner, clientRandom, serverRandom, clientPublic, serverPublic, materialLen, suite)
		if err == nil {
			return material, KeySourceTLSExporter, nil
		}
		// Auto mode falls back to the TrustIX X25519 transcript if the link
		// cannot export TLS keying material, for example on non-TLS packet
		// transports or TLS versions without exporter support.
		return deriveKeyMaterial(secret, clientRandom, serverRandom, materialLen, suite), KeySourceTrustIXX25519, nil
	default:
		return nil, "", fmt.Errorf("%w: unsupported key source %q", ErrInvalidHandshake, requested)
	}
}

func deriveTLSExporterKeyMaterial(inner transport.Session, clientRandom []byte, serverRandom []byte, clientPublic []byte, serverPublic []byte, length int, suite cryptoSuite) ([]byte, error) {
	exporter, ok := inner.(transport.TLSExporterSession)
	if !ok {
		return nil, transport.ErrTLSExporterUnavailable
	}
	contextHash := tlsExporterContext(clientRandom, serverRandom, clientPublic, serverPublic, suite)
	material, err := exporter.ExportKeyingMaterial(tlsExporterLabel, contextHash[:], length)
	if err != nil {
		return nil, fmt.Errorf("derive TrustIX key material from TLS exporter: %w", err)
	}
	if len(material) != length {
		return nil, fmt.Errorf("derive TrustIX key material from TLS exporter: got %d bytes, want %d", len(material), length)
	}
	return material, nil
}

func tlsExporterContext(clientRandom []byte, serverRandom []byte, clientPublic []byte, serverPublic []byte, suite cryptoSuite) [32]byte {
	payload := make([]byte, 0, 64+len(clientPublic)+len(serverPublic))
	payload = append(payload, []byte("TrustIX secure transport TLS exporter context v1\x00")...)
	if suite.Name != defaultSuite.Name {
		payload = append(payload, []byte("suite\x00")...)
		payload = append(payload, suite.Name...)
		payload = append(payload, 0)
	}
	payload = append(payload, clientRandom...)
	payload = append(payload, serverRandom...)
	payload = append(payload, clientPublic...)
	payload = append(payload, serverPublic...)
	return sha256.Sum256(payload)
}

func requestedKeySource(options Options) string {
	if options.KeySource == nil {
		return KeySourceAuto
	}
	return normalizeKeySource(options.KeySource())
}

func requestedEncryptionPolicy(options Options) EncryptionPolicy {
	if options.Encryption == nil {
		return EncryptionPolicyForMode(EncryptionSecure)
	}
	return EncryptionPolicyForMode(options.Encryption())
}

func EncryptionPolicyForMode(raw string) EncryptionPolicy {
	mode := NormalizeEncryptionMode(raw)
	switch mode {
	case EncryptionPlaintext:
		return EncryptionPolicy{Mode: mode}
	case EncryptionSendEncrypted:
		return EncryptionPolicy{Mode: mode, SendEncrypted: true}
	case EncryptionReceiveEncrypted:
		return EncryptionPolicy{Mode: mode, ReceiveEncrypted: true}
	default:
		return EncryptionPolicy{Mode: EncryptionSecure, SendEncrypted: true, ReceiveEncrypted: true}
	}
}

func NormalizeEncryptionMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", EncryptionSecure, "encrypted", "trustix_secure", "trustix-secure":
		return EncryptionSecure
	case EncryptionPlaintext, "none", "disabled", "off":
		return EncryptionPlaintext
	case EncryptionSendEncrypted, "outbound_encrypted", "encrypt_outbound", "send_only":
		return EncryptionSendEncrypted
	case EncryptionReceiveEncrypted, "inbound_encrypted", "encrypt_inbound", "receive_only":
		return EncryptionReceiveEncrypted
	default:
		return raw
	}
}

func normalizeKeySource(source string) string {
	switch source {
	case "", KeySourceAuto:
		return KeySourceAuto
	case KeySourceTrustIXX25519:
		return KeySourceTrustIXX25519
	case KeySourceTLSExporter:
		return KeySourceTLSExporter
	default:
		return source
	}
}

func deriveKeyMaterial(secret []byte, clientRandom []byte, serverRandom []byte, length int, suite cryptoSuite) []byte {
	salt := make([]byte, 0, len(clientRandom)+len(serverRandom))
	salt = append(salt, clientRandom...)
	salt = append(salt, serverRandom...)
	prk := hkdfExtract(salt, secret)
	return hkdfExpand(prk, []byte(suite.KDFInfo), length)
}

func hkdfExtract(salt []byte, secret []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	_, _ = mac.Write(secret)
	return mac.Sum(nil)
}

func hkdfExpand(prk []byte, info []byte, length int) []byte {
	var output []byte
	var previous []byte
	for counter := byte(1); len(output) < length; counter++ {
		mac := hmac.New(sha256.New, prk)
		_, _ = mac.Write(previous)
		_, _ = mac.Write(info)
		_, _ = mac.Write([]byte{counter})
		previous = mac.Sum(nil)
		output = append(output, previous...)
	}
	return output[:length]
}

type replayWindow struct {
	mu      sync.Mutex
	highest uint64
	seen    []uint64
	size    uint64
}

func newReplayWindow(size uint64) replayWindow {
	size = normalizeReplayWindowSize(size)
	return replayWindow{
		seen: make([]uint64, replayWindowWords(size)),
		size: size,
	}
}

func normalizeReplayWindowSize(size uint64) uint64 {
	if size == 0 {
		return defaultReplayWindowSize
	}
	if size < minReplayWindowSize {
		return minReplayWindowSize
	}
	if size > maxReplayWindowSize {
		return maxReplayWindowSize
	}
	return size
}

func replayWindowWords(size uint64) int {
	return int((size + 63) / 64)
}

func (window *replayWindow) Size() uint64 {
	window.mu.Lock()
	defer window.mu.Unlock()
	window.ensureLocked()
	return window.size
}

func (window *replayWindow) ensureLocked() {
	size := normalizeReplayWindowSize(window.size)
	if window.size != size {
		window.size = size
	}
	words := replayWindowWords(size)
	if len(window.seen) != words {
		window.seen = make([]uint64, words)
		return
	}
	maskReplayWindowTail(window.seen, size)
}

func (window *replayWindow) Accept(seq uint64) bool {
	if seq == 0 {
		return false
	}
	window.mu.Lock()
	defer window.mu.Unlock()
	window.ensureLocked()

	return replayWindowAcceptLocked(&window.highest, window.seen, window.size, seq)
}

func (window *replayWindow) AcceptBatch(seqs []uint64) bool {
	if len(seqs) == 0 {
		return true
	}
	window.mu.Lock()
	defer window.mu.Unlock()
	window.ensureLocked()
	highest := window.highest
	seen := append([]uint64(nil), window.seen...)
	for _, seq := range seqs {
		if !replayWindowAcceptLocked(&highest, seen, window.size, seq) {
			return false
		}
	}
	window.highest = highest
	copy(window.seen, seen)
	return true
}

func (window *replayWindow) AcceptBatchResults(seqs []uint64, dst []bool) []bool {
	if cap(dst) < len(seqs) {
		dst = make([]bool, len(seqs))
	} else {
		dst = dst[:len(seqs)]
		clear(dst)
	}
	if len(seqs) == 0 {
		return dst
	}
	window.mu.Lock()
	defer window.mu.Unlock()
	window.ensureLocked()
	for i, seq := range seqs {
		if replayWindowAcceptLocked(&window.highest, window.seen, window.size, seq) {
			dst[i] = true
		}
	}
	return dst
}

func replayWindowAcceptLocked(highest *uint64, seen []uint64, size uint64, seq uint64) bool {
	if seq == 0 {
		return false
	}
	if seq > *highest {
		shiftReplayWindowSeen(seen, seq-*highest, size)
		*highest = seq
		setReplayWindowBit(seen, 0)
		return true
	}
	delta := *highest - seq
	if delta >= size || replayWindowBit(seen, delta) {
		return false
	}
	setReplayWindowBit(seen, delta)
	return true
}

func shiftReplayWindowSeen(seen []uint64, shift uint64, size uint64) {
	if shift == 0 {
		return
	}
	if shift >= size || int(shift/64) >= len(seen) {
		clear(seen)
		return
	}
	wordShift := int(shift / 64)
	bitShift := uint(shift % 64)
	for i := len(seen) - 1; i >= 0; i-- {
		src := i - wordShift
		var value uint64
		if src >= 0 {
			value = seen[src] << bitShift
			if bitShift != 0 && src > 0 {
				value |= seen[src-1] >> (64 - bitShift)
			}
		}
		seen[i] = value
	}
	maskReplayWindowTail(seen, size)
}

func replayWindowBit(seen []uint64, bit uint64) bool {
	word := int(bit / 64)
	if word < 0 || word >= len(seen) {
		return false
	}
	return seen[word]&(uint64(1)<<(bit%64)) != 0
}

func setReplayWindowBit(seen []uint64, bit uint64) {
	word := int(bit / 64)
	if word < 0 || word >= len(seen) {
		return
	}
	seen[word] |= uint64(1) << (bit % 64)
}

func maskReplayWindowTail(seen []uint64, size uint64) {
	if len(seen) == 0 {
		return
	}
	remainder := size % 64
	if remainder == 0 {
		return
	}
	seen[len(seen)-1] &= (uint64(1) << remainder) - 1
}
