package device

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"trustix.local/trustix/internal/pki"
	"trustix.local/trustix/internal/transport"
	securetransport "trustix.local/trustix/internal/transport/secure"
)

func TestClientRunHandlesLeaseControlBatchAndInterfacePacket(t *testing.T) {
	certPath, keyPath, roots := writeDeviceClientTestPKI(t)
	session := newFakeSession()
	iface := newFakeInterface("trustix-test0", 1400)
	iface.readPackets <- []byte{0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 240, 10, 0, 0, 1}
	cfg := Config{
		Domain:     "lab.local",
		IX:         "ix-a",
		Endpoint:   transport.Endpoint{Name: "access-udp", Address: "127.0.0.1:7001", Transport: transport.ProtocolUDP, Encryption: securetransport.EncryptionSecure},
		CertPath:   certPath,
		KeyPath:    keyPath,
		TrustRoots: roots,
		Interface: InterfaceConfig{
			Name:   "trustix-test0",
			MTU:    1400,
			Routes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		},
		StatsEvery: 0,
		OpenInterface: func(cfg InterfaceConfig) (Interface, error) {
			if cfg.Name != "trustix-test0" || cfg.MTU != 1400 {
				t.Fatalf("interface config = %#v", cfg)
			}
			return iface, nil
		},
		DialTransport: func(ctx context.Context, peer transport.Peer, tlsConf *tls.Config) (transport.Session, error) {
			if peer.ID != "ix-a" || peer.DomainID != "lab.local" || len(peer.Endpoints) != 1 {
				t.Fatalf("peer = %#v", peer)
			}
			if tlsConf == nil || len(tlsConf.Certificates) != 1 || tlsConf.RootCAs == nil || tlsConf.ServerName != "lab.local" {
				t.Fatalf("unexpected TLS config: %#v", tlsConf)
			}
			return session, nil
		},
	}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- client.Run(ctx)
	}()

	leaseFrame := leaseControlFrame(netip.MustParseAddr("10.0.0.240"), 32, time.Unix(1700000000, 0))
	session.recv <- leaseFrame
	session.recv <- EncodeControl(DataSessionControlPing, 99)
	session.recv <- encodeTestBatch([]byte("one"), []byte("two"))

	waitFor(t, time.Second, func() bool {
		return iface.configuredPrefix() == netip.MustParsePrefix("10.0.0.240/32") &&
			len(iface.writtenSnapshot()) == 2 &&
			len(session.sentSnapshot()) >= 2
	})
	cancel()
	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
			t.Fatalf("client run returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("client did not stop")
	}
	if got := iface.configuredRoutes(); len(got) != 1 || got[0] != netip.MustParsePrefix("10.0.0.0/24") {
		t.Fatalf("configured routes = %#v", got)
	}
	sent := session.sentSnapshot()
	if !containsPacket(sent, EncodeControl(DataSessionControlPong, 99)) {
		t.Fatalf("sent packets did not include pong: %#v", sent)
	}
	if !containsPacketWithSource(sent, netip.MustParseAddr("10.0.0.240")) {
		t.Fatalf("sent packets did not include interface packet: %#v", sent)
	}
	stats := client.Snapshot()
	if stats.ControlFrames < 2 || stats.BatchesReceived != 1 || stats.PacketsToInterface != 2 || stats.PacketsFromInterface != 1 {
		t.Fatalf("stats = %#v", stats)
	}
}

func TestHandleSessionPacketsReturnsPongSendError(t *testing.T) {
	wantErr := errors.New("injected pong send failure")
	session := newFakeSession()
	session.sendErr = wantErr
	client := &Client{session: session}
	iface := newFakeInterface("trustix-test0", 1400)
	var scratch [][]byte

	err := client.handleSessionPackets(context.Background(), iface, [][]byte{EncodeControl(DataSessionControlPing, 99)}, &scratch)
	if !errors.Is(err, wantErr) {
		t.Fatalf("handle ping error = %v, want %v", err, wantErr)
	}
}

func TestHandleSessionPacketsReturnsLeaseConfigureError(t *testing.T) {
	wantErr := errors.New("injected interface configure failure")
	session := newFakeSession()
	client := &Client{session: session, cfg: Config{Logf: func(string, ...any) {}}}
	iface := newFakeInterface("trustix-test0", 1400)
	iface.configureErr = wantErr
	var scratch [][]byte
	frame := leaseControlFrame(netip.MustParseAddr("10.0.0.240"), 32, time.Now().UTC().Add(time.Hour))

	err := client.handleSessionPackets(context.Background(), iface, [][]byte{frame}, &scratch)
	if !errors.Is(err, wantErr) {
		t.Fatalf("handle lease error = %v, want %v", err, wantErr)
	}
}

func TestClientMergesLeaseRoutesWithBootstrapRoutes(t *testing.T) {
	certPath, keyPath, roots := writeDeviceClientTestPKI(t)
	session := newFakeSession()
	iface := newFakeInterface("trustix-test0", 1400)
	cfg := Config{
		Domain:     "lab.local",
		IX:         "ix-a",
		Endpoint:   transport.Endpoint{Name: "access-udp", Address: "127.0.0.1:7001", Transport: transport.ProtocolUDP, Encryption: securetransport.EncryptionSecure},
		CertPath:   certPath,
		KeyPath:    keyPath,
		TrustRoots: roots,
		Interface: InterfaceConfig{
			Name:   "trustix-test0",
			MTU:    1400,
			Routes: []netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")},
		},
		StatsEvery: 0,
		OpenInterface: func(cfg InterfaceConfig) (Interface, error) {
			return iface, nil
		},
		DialTransport: func(context.Context, transport.Peer, *tls.Config) (transport.Session, error) {
			return session, nil
		},
	}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- client.Run(ctx)
	}()
	session.recv <- leaseControlFrameWithRoutes(netip.MustParseAddr("10.0.0.240"), 32, time.Unix(1700000000, 0),
		netip.MustParsePrefix("10.0.1.0/24"),
		netip.MustParsePrefix("10.0.9.0/24"),
	)
	waitFor(t, time.Second, func() bool {
		return len(iface.configuredRoutes()) == 2
	})
	cancel()
	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
			t.Fatalf("client run returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("client did not stop")
	}
	got := iface.configuredRoutes()
	if len(got) != 2 || got[0] != netip.MustParsePrefix("10.0.1.0/24") || got[1] != netip.MustParsePrefix("10.0.9.0/24") {
		t.Fatalf("configured routes = %#v", got)
	}
}

func TestDecodeFileConfig(t *testing.T) {
	cfg, err := DecodeFileConfig([]byte(`
domain: lab.local
ix: ix-a
endpoint:
  name: access-tcp
  address: ix.example.com:443
  transport: tcp
cert: ./ix-a-laptop.crt
key: ./ix-a-laptop.key
trust_roots:
  - ./domain-ca.pem
encryption: plaintext
crypto_key_source: trustix_x25519
crypto_suites:
  - chacha20poly1305-x25519
interface:
  name: trustix0
  mtu: 1380
  routes:
    - 10.0.0.42/24
stats_every: 5s
`), ".yaml")
	if err != nil {
		t.Fatalf("decode config: %v", err)
	}
	clientCfg, err := cfg.ClientConfig()
	if err != nil {
		t.Fatalf("client config: %v", err)
	}
	if clientCfg.Domain != "lab.local" || clientCfg.IX != "ix-a" || clientCfg.Endpoint.Transport != transport.ProtocolTCP {
		t.Fatalf("client config identity/transport = %#v", clientCfg)
	}
	if clientCfg.Encryption != securetransport.EncryptionPlaintext || clientCfg.Endpoint.Encryption != securetransport.EncryptionPlaintext {
		t.Fatalf("encryption = %q endpoint=%q", clientCfg.Encryption, clientCfg.Endpoint.Encryption)
	}
	if clientCfg.KeySource != securetransport.KeySourceTrustIXX25519 {
		t.Fatalf("key source = %q", clientCfg.KeySource)
	}
	if len(clientCfg.CryptoSuites) != 1 || clientCfg.CryptoSuites[0] != securetransport.SuiteChaCha20Poly1305X25519 {
		t.Fatalf("crypto suites = %#v", clientCfg.CryptoSuites)
	}
	if len(clientCfg.Interface.Routes) != 1 || clientCfg.Interface.Routes[0] != netip.MustParsePrefix("10.0.0.0/24") {
		t.Fatalf("routes = %#v", clientCfg.Interface.Routes)
	}
	if clientCfg.StatsEvery != 5*time.Second {
		t.Fatalf("stats every = %s", clientCfg.StatsEvery)
	}
}

func TestClientRejectsDeviceCertificateWithoutIssuerChain(t *testing.T) {
	certPath, keyPath, roots := writeDeviceClientTestPKI(t)
	payload, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	block, _ := pem.Decode(payload)
	if block == nil {
		t.Fatal("test certificate has no PEM block")
	}
	leafOnlyPath := filepath.Join(t.TempDir(), "device-leaf.crt")
	if err := os.WriteFile(leafOnlyPath, pem.EncodeToMemory(block), 0o644); err != nil {
		t.Fatalf("write leaf only cert: %v", err)
	}
	client, err := NewClient(Config{
		Domain:     "lab.local",
		IX:         "ix-a",
		Endpoint:   transport.Endpoint{Name: "access-udp", Address: "127.0.0.1:7001", Transport: transport.ProtocolUDP},
		CertPath:   leafOnlyPath,
		KeyPath:    keyPath,
		TrustRoots: roots,
		OpenInterface: func(InterfaceConfig) (Interface, error) {
			t.Fatal("interface should not be opened")
			return nil, nil
		},
		DialTransport: func(context.Context, transport.Peer, *tls.Config) (transport.Session, error) {
			t.Fatal("transport should not be dialed")
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if err := client.Run(context.Background()); err == nil {
		t.Fatal("expected missing issuer chain error")
	}
}

type fakeInterface struct {
	name         string
	mtu          int
	readPackets  chan []byte
	closed       chan struct{}
	mu           sync.Mutex
	lease        Lease
	routes       []netip.Prefix
	written      [][]byte
	configureErr error
}

func newFakeInterface(name string, mtu int) *fakeInterface {
	return &fakeInterface{
		name:        name,
		mtu:         mtu,
		readPackets: make(chan []byte, 8),
		closed:      make(chan struct{}),
	}
}

func (iface *fakeInterface) Name() string { return iface.name }

func (iface *fakeInterface) MTU() int { return iface.mtu }

func (iface *fakeInterface) ReadPacket(dst []byte) (int, error) {
	select {
	case packet := <-iface.readPackets:
		return copy(dst, packet), nil
	case <-iface.closed:
		return 0, context.Canceled
	}
}

func (iface *fakeInterface) WritePacket(packet []byte) (int, error) {
	iface.mu.Lock()
	defer iface.mu.Unlock()
	iface.written = append(iface.written, append([]byte(nil), packet...))
	return len(packet), nil
}

func (iface *fakeInterface) Configure(lease Lease, routes []netip.Prefix) error {
	iface.mu.Lock()
	defer iface.mu.Unlock()
	iface.lease = lease
	iface.routes = append([]netip.Prefix(nil), routes...)
	return iface.configureErr
}

func (iface *fakeInterface) Close() error {
	select {
	case <-iface.closed:
	default:
		close(iface.closed)
	}
	return nil
}

func (iface *fakeInterface) configuredPrefix() netip.Prefix {
	iface.mu.Lock()
	defer iface.mu.Unlock()
	return iface.lease.Prefix
}

func (iface *fakeInterface) configuredRoutes() []netip.Prefix {
	iface.mu.Lock()
	defer iface.mu.Unlock()
	return append([]netip.Prefix(nil), iface.routes...)
}

func (iface *fakeInterface) writtenSnapshot() [][]byte {
	iface.mu.Lock()
	defer iface.mu.Unlock()
	return clonePackets(iface.written)
}

type fakeSession struct {
	recv    chan []byte
	closed  chan struct{}
	mu      sync.Mutex
	sent    [][]byte
	sendErr error
}

func newFakeSession() *fakeSession {
	return &fakeSession{
		recv:   make(chan []byte, 16),
		closed: make(chan struct{}),
	}
}

func (session *fakeSession) SendPacket(packet []byte) error {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.sent = append(session.sent, append([]byte(nil), packet...))
	return session.sendErr
}

func (session *fakeSession) RecvPacket() ([]byte, error) {
	select {
	case packet := <-session.recv:
		return packet, nil
	case <-session.closed:
		return nil, context.Canceled
	}
}

func (session *fakeSession) Close() error {
	select {
	case <-session.closed:
	default:
		close(session.closed)
	}
	return nil
}

func (session *fakeSession) Stats() transport.TransportStats {
	return transport.TransportStats{}
}

func (session *fakeSession) sentSnapshot() [][]byte {
	session.mu.Lock()
	defer session.mu.Unlock()
	return clonePackets(session.sent)
}

func writeDeviceClientTestPKI(t *testing.T) (string, string, []string) {
	t.Helper()
	root, err := pki.NewRoot("TrustIX Root", 1)
	if err != nil {
		t.Fatalf("new root: %v", err)
	}
	domain, err := pki.Issue(root, pki.IssueRequest{
		CommonName: "TrustIX Domain lab.local",
		Role:       pki.RoleDomainCA,
		Domain:     "lab.local",
		IsCA:       true,
		NotAfter:   time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("issue domain: %v", err)
	}
	ix, err := pki.Issue(domain, pki.IssueRequest{
		CommonName: "TrustIX IX ix-a",
		Role:       pki.RoleIX,
		Domain:     "lab.local",
		IX:         "ix-a",
		IsCA:       true,
		NotAfter:   time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("issue ix: %v", err)
	}
	deviceBundle, err := pki.Issue(ix, pki.IssueRequest{
		CommonName: "TrustIX Device laptop-1",
		Role:       pki.RoleDevice,
		Domain:     "lab.local",
		IX:         "ix-a",
		Device:     "laptop-1",
		NotAfter:   time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("issue device: %v", err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "device.crt")
	keyPath := filepath.Join(dir, "device.key")
	rootPath := filepath.Join(dir, "domain-ca.pem")
	if err := os.WriteFile(certPath, append(deviceBundle.CertPEM, ix.CertPEM...), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, deviceBundle.KeyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.WriteFile(rootPath, domain.CertPEM, 0o644); err != nil {
		t.Fatalf("write root: %v", err)
	}
	return certPath, keyPath, []string{rootPath}
}

func leaseControlFrame(addr netip.Addr, bits int, expiresAt time.Time) []byte {
	frame := make([]byte, dataSessionControlDeviceLeaseLen)
	copy(frame[0:4], dataSessionControlMagic[:])
	frame[4] = dataSessionControlVersion
	frame[5] = DataSessionControlDeviceLease
	raw := addr.As4()
	copy(frame[8:12], raw[:])
	frame[12] = byte(uint32(bits) >> 24)
	frame[13] = byte(uint32(bits) >> 16)
	frame[14] = byte(uint32(bits) >> 8)
	frame[15] = byte(uint32(bits))
	expires := uint64(expiresAt.Unix())
	for i := 0; i < 8; i++ {
		frame[16+i] = byte(expires >> uint(56-8*i))
	}
	return frame
}

func leaseControlFrameWithRoutes(addr netip.Addr, bits int, expiresAt time.Time, routes ...netip.Prefix) []byte {
	frame := make([]byte, dataSessionControlDeviceLeaseLen+len(routes)*dataSessionControlDeviceLeaseRouteLen)
	copy(frame, leaseControlFrame(addr, bits, expiresAt))
	frame[24] = byte(len(routes) >> 8)
	frame[25] = byte(len(routes))
	offset := dataSessionControlDeviceLeaseLen
	for _, route := range routes {
		route = route.Masked()
		raw := route.Addr().As4()
		copy(frame[offset:offset+4], raw[:])
		frame[offset+4] = byte(route.Bits())
		offset += dataSessionControlDeviceLeaseRouteLen
	}
	return frame
}

func encodeTestBatch(packets ...[]byte) []byte {
	frame := []byte{'T', 'I', 'X', 'B', dataSessionBatchVersion, 0, byte(len(packets) >> 8), byte(len(packets))}
	for _, packet := range packets {
		frame = append(frame, byte(len(packet)>>8), byte(len(packet)))
		frame = append(frame, packet...)
	}
	return frame
}

func waitFor(t *testing.T, timeout time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}

func containsPacket(packets [][]byte, want []byte) bool {
	for _, packet := range packets {
		if string(packet) == string(want) {
			return true
		}
	}
	return false
}

func containsPacketWithSource(packets [][]byte, source netip.Addr) bool {
	raw := source.As4()
	for _, packet := range packets {
		if len(packet) >= 16 && string(packet[12:16]) == string(raw[:]) {
			return true
		}
	}
	return false
}

func clonePackets(packets [][]byte) [][]byte {
	out := make([][]byte, len(packets))
	for i, packet := range packets {
		out[i] = append([]byte(nil), packet...)
	}
	return out
}
