package device

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/pki"
	"trustix.local/trustix/internal/transport"
)

const (
	defaultMTU       = 1400
	defaultBatchSize = 64
)

type Interface interface {
	Name() string
	MTU() int
	ReadPacket([]byte) (int, error)
	WritePacket([]byte) (int, error)
	Configure(Lease, []netip.Prefix) error
	Close() error
}

type InterfaceConfig struct {
	Name   string
	MTU    int
	Routes []netip.Prefix
}

type Config struct {
	Domain        core.DomainID
	IX            core.IXID
	Endpoint      transport.Endpoint
	CertPath      string
	KeyPath       string
	TrustRoots    []string
	ServerName    string
	Encryption    string
	KeySource     string
	CryptoSuites  []string
	Interface     InterfaceConfig
	BatchSize     int
	StatsEvery    time.Duration
	OpenInterface func(InterfaceConfig) (Interface, error)
	DialTransport func(context.Context, transport.Peer, *tls.Config) (transport.Session, error)
	Logf          func(string, ...any)
}

type Stats struct {
	PacketsFromInterface uint64
	BytesFromInterface   uint64
	PacketsToInterface   uint64
	BytesToInterface     uint64
	PacketsSent          uint64
	PacketsReceived      uint64
	ControlFrames        uint64
	BatchesReceived      uint64
	LastLease            Lease
}

type Client struct {
	cfg       Config
	iface     Interface
	session   transport.Session
	stats     Stats
	leaseMu   sync.RWMutex
	lastLease Lease
}

func NewClient(cfg Config) (*Client, error) {
	if cfg.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if cfg.IX == "" {
		return nil, fmt.Errorf("ix is required")
	}
	if cfg.Endpoint.Address == "" {
		return nil, fmt.Errorf("endpoint address is required")
	}
	if cfg.Endpoint.Transport == "" {
		return nil, fmt.Errorf("endpoint transport is required")
	}
	if cfg.CertPath == "" || cfg.KeyPath == "" {
		return nil, fmt.Errorf("device cert and key are required")
	}
	if len(cfg.TrustRoots) == 0 {
		return nil, fmt.Errorf("at least one trust root is required")
	}
	if cfg.Interface.Name == "" {
		cfg.Interface.Name = "trustix0"
	}
	if cfg.Interface.MTU <= 0 {
		cfg.Interface.MTU = defaultMTU
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultBatchSize
	}
	if cfg.OpenInterface == nil {
		cfg.OpenInterface = OpenInterface
	}
	if cfg.DialTransport == nil {
		return nil, fmt.Errorf("dial transport is required")
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	return &Client{cfg: cfg}, nil
}

func (client *Client) Run(ctx context.Context) (resultErr error) {
	tlsConf, err := client.clientTLSConfig()
	if err != nil {
		return err
	}
	session, err := client.cfg.DialTransport(ctx, transport.Peer{
		ID:       client.cfg.IX,
		DomainID: client.cfg.Domain,
		Endpoints: []transport.Endpoint{{
			Name:       client.cfg.Endpoint.Name,
			Mode:       transport.EndpointActive,
			Address:    client.cfg.Endpoint.Address,
			Transport:  client.cfg.Endpoint.Transport,
			Encryption: client.cfg.Encryption,
		}},
	}, tlsConf)
	if err != nil {
		return fmt.Errorf("dial device access endpoint: %w", err)
	}
	client.session = session
	defer func() {
		if err := session.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close device access session: %w", err))
		}
	}()

	iface, err := client.cfg.OpenInterface(client.cfg.Interface)
	if err != nil {
		return err
	}
	client.iface = iface
	defer func() {
		if err := iface.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close device interface: %w", err))
		}
	}()

	errCh := make(chan error, 2)
	go func() {
		errCh <- client.pumpInterfaceToSession(ctx, iface, session)
	}()
	go func() {
		errCh <- client.pumpSessionToInterface(ctx, iface, session)
	}()
	if client.cfg.StatsEvery > 0 {
		go client.logStats(ctx)
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		if err == nil || errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
}

func (client *Client) Snapshot() Stats {
	client.leaseMu.RLock()
	lastLease := client.lastLease
	client.leaseMu.RUnlock()
	return Stats{
		PacketsFromInterface: atomic.LoadUint64(&client.stats.PacketsFromInterface),
		BytesFromInterface:   atomic.LoadUint64(&client.stats.BytesFromInterface),
		PacketsToInterface:   atomic.LoadUint64(&client.stats.PacketsToInterface),
		BytesToInterface:     atomic.LoadUint64(&client.stats.BytesToInterface),
		PacketsSent:          atomic.LoadUint64(&client.stats.PacketsSent),
		PacketsReceived:      atomic.LoadUint64(&client.stats.PacketsReceived),
		ControlFrames:        atomic.LoadUint64(&client.stats.ControlFrames),
		BatchesReceived:      atomic.LoadUint64(&client.stats.BatchesReceived),
		LastLease:            lastLease,
	}
}

func (client *Client) clientTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(client.cfg.CertPath, client.cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("load device certificate: %w", err)
	}
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("device certificate has no certificate chain")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse device certificate: %w", err)
	}
	meta := pki.ParseMetadata(leaf)
	if meta.Role != pki.RoleDevice {
		return nil, fmt.Errorf("device certificate role is %q, want %q", meta.Role, pki.RoleDevice)
	}
	if meta.Domain != string(client.cfg.Domain) {
		return nil, fmt.Errorf("device certificate domain is %q, want %q", meta.Domain, client.cfg.Domain)
	}
	if meta.IX != string(client.cfg.IX) {
		return nil, fmt.Errorf("device certificate issuer ix is %q, want %q", meta.IX, client.cfg.IX)
	}
	pool := x509.NewCertPool()
	for _, path := range client.cfg.TrustRoots {
		payload, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read trust root %q: %w", path, err)
		}
		if !pool.AppendCertsFromPEM(payload) {
			return nil, fmt.Errorf("trust root %q contains no certificates", path)
		}
	}
	if err := verifyLocalDeviceCertificateChain(cert, leaf, pool); err != nil {
		return nil, err
	}
	serverName := client.cfg.ServerName
	if serverName == "" {
		serverName = string(client.cfg.Domain)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("IX server certificate is required")
			}
			peerCert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			meta := pki.ParseMetadata(peerCert)
			if meta.Role != pki.RoleIX {
				return fmt.Errorf("IX server certificate role is %q, want %q", meta.Role, pki.RoleIX)
			}
			if meta.Domain != string(client.cfg.Domain) {
				return fmt.Errorf("IX server certificate domain is %q, want %q", meta.Domain, client.cfg.Domain)
			}
			if meta.IX != string(client.cfg.IX) {
				return fmt.Errorf("IX server certificate ix is %q, want %q", meta.IX, client.cfg.IX)
			}
			return nil
		},
	}, nil
}

func (client *Client) pumpInterfaceToSession(ctx context.Context, iface Interface, session transport.Session) error {
	buf := make([]byte, maxPacketBufferSize(iface.MTU()))
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := iface.ReadPacket(buf)
		if err != nil {
			return fmt.Errorf("read %s: %w", iface.Name(), err)
		}
		if n <= 0 {
			continue
		}
		packet := append([]byte(nil), buf[:n]...)
		if err := session.SendPacket(packet); err != nil {
			return fmt.Errorf("send packet to IX: %w", err)
		}
		atomic.AddUint64(&client.stats.PacketsFromInterface, 1)
		atomic.AddUint64(&client.stats.BytesFromInterface, uint64(n))
		atomic.AddUint64(&client.stats.PacketsSent, 1)
	}
}

func (client *Client) pumpSessionToInterface(ctx context.Context, iface Interface, session transport.Session) error {
	batchReceiver, hasBatchReceiver := session.(transport.PacketBatchReceiver)
	releaseReceiver, hasReleaseReceiver := session.(transport.PacketBatchReceiverWithRelease)
	var scratch [][]byte
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var packets [][]byte
		var release func()
		var err error
		switch {
		case hasReleaseReceiver:
			packets, release, err = releaseReceiver.RecvPacketsWithRelease(client.cfg.BatchSize)
		case hasBatchReceiver:
			packets, err = batchReceiver.RecvPackets(client.cfg.BatchSize)
		default:
			var packet []byte
			packet, err = session.RecvPacket()
			if err == nil {
				packets = [][]byte{packet}
			}
		}
		if err != nil {
			if release != nil {
				release()
			}
			return fmt.Errorf("receive packet from IX: %w", err)
		}
		if err := client.handleSessionPackets(ctx, iface, packets, &scratch); err != nil {
			if release != nil {
				release()
			}
			return err
		}
		if release != nil {
			release()
		}
	}
}

func (client *Client) handleSessionPackets(ctx context.Context, iface Interface, packets [][]byte, scratch *[][]byte) error {
	for _, packet := range packets {
		if err := ctx.Err(); err != nil {
			return err
		}
		handled, err := client.handleControl(iface, packet)
		if err != nil {
			return err
		}
		if handled {
			continue
		}
		if decoded, ok := DecodeBatchInto(packet, (*scratch)[:0]); ok {
			*scratch = decoded
			atomic.AddUint64(&client.stats.BatchesReceived, 1)
			for _, item := range decoded {
				handled, err := client.handleControl(iface, item)
				if err != nil {
					return err
				}
				if handled {
					continue
				}
				if err := client.writeDataPacket(iface, item); err != nil {
					return err
				}
			}
			continue
		}
		if err := client.writeDataPacket(iface, packet); err != nil {
			return err
		}
	}
	return nil
}

func (client *Client) handleControl(iface Interface, packet []byte) (bool, error) {
	kind, nonce, ok := DecodeControl(packet)
	if !ok {
		return false, nil
	}
	atomic.AddUint64(&client.stats.ControlFrames, 1)
	switch kind {
	case DataSessionControlPing:
		if err := client.session.SendPacket(EncodeControl(DataSessionControlPong, nonce)); err != nil {
			return true, fmt.Errorf("send control pong: %w", err)
		}
	case DataSessionControlDeviceLease:
		lease, ok := DecodeLease(packet)
		if !ok {
			return true, fmt.Errorf("decode device lease control frame")
		}
		client.leaseMu.Lock()
		client.lastLease = lease
		client.leaseMu.Unlock()
		routes := mergeLeaseAndBootstrapRoutes(lease.Routes, client.cfg.Interface.Routes)
		if err := iface.Configure(lease, routes); err != nil {
			client.cfg.Logf("configure %s lease %s failed: %v", iface.Name(), lease.Prefix, err)
			return true, fmt.Errorf("configure %s lease %s: %w", iface.Name(), lease.Prefix, err)
		}
		if lease.ExpiresAt.IsZero() {
			client.cfg.Logf("device lease: %s on %s", lease.Prefix, iface.Name())
		} else {
			client.cfg.Logf("device lease: %s on %s expires %s", lease.Prefix, iface.Name(), lease.ExpiresAt.Format(time.RFC3339))
		}
	}
	return true, nil
}

func mergeLeaseAndBootstrapRoutes(leaseRoutes, bootstrapRoutes []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(leaseRoutes)+len(bootstrapRoutes))
	seen := make(map[string]struct{}, len(leaseRoutes)+len(bootstrapRoutes))
	appendRoute := func(prefix netip.Prefix) {
		if !prefix.IsValid() || !prefix.Addr().Is4() {
			return
		}
		prefix = prefix.Masked()
		raw := prefix.String()
		if _, exists := seen[raw]; exists {
			return
		}
		seen[raw] = struct{}{}
		out = append(out, prefix)
	}
	for _, prefix := range leaseRoutes {
		appendRoute(prefix)
	}
	for _, prefix := range bootstrapRoutes {
		appendRoute(prefix)
	}
	return out
}

func verifyLocalDeviceCertificateChain(cert tls.Certificate, leaf *x509.Certificate, roots *x509.CertPool) error {
	if leaf == nil {
		return fmt.Errorf("device certificate leaf is required")
	}
	intermediates := x509.NewCertPool()
	for _, raw := range cert.Certificate[1:] {
		intermediate, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("parse device certificate chain intermediate: %w", err)
		}
		intermediates.AddCert(intermediate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("verify device certificate chain: %w", err)
	}
	return nil
}

func (client *Client) writeDataPacket(iface Interface, packet []byte) error {
	if len(packet) == 0 {
		return nil
	}
	n, err := iface.WritePacket(packet)
	if err != nil {
		return fmt.Errorf("write %s: %w", iface.Name(), err)
	}
	atomic.AddUint64(&client.stats.PacketsToInterface, 1)
	atomic.AddUint64(&client.stats.BytesToInterface, uint64(n))
	atomic.AddUint64(&client.stats.PacketsReceived, 1)
	return nil
}

func (client *Client) logStats(ctx context.Context) {
	ticker := time.NewTicker(client.cfg.StatsEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats := client.Snapshot()
			client.cfg.Logf("stats: tx_if=%d pkts/%d bytes rx_if=%d pkts/%d bytes control=%d batches=%d",
				stats.PacketsFromInterface, stats.BytesFromInterface,
				stats.PacketsToInterface, stats.BytesToInterface,
				stats.ControlFrames, stats.BatchesReceived)
		}
	}
}

func maxPacketBufferSize(mtu int) int {
	if mtu <= 0 {
		mtu = defaultMTU
	}
	if mtu < 1500 {
		return 1500 + 128
	}
	return mtu + 128
}
