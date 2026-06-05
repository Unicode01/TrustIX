// Package transport defines the pluggable data-channel contract. UDP, QUIC,
// TCP, WebSocket, HTTP CONNECT, experimental TCP, and kernel tunnel
// implementations register behind this boundary.
package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"trustix.local/trustix/internal/core"
)

type Protocol string

const (
	ProtocolUDP             Protocol = "udp"
	ProtocolQUIC            Protocol = "quic"
	ProtocolTCP             Protocol = "tcp"
	ProtocolWebSocket       Protocol = "websocket"
	ProtocolHTTPConnect     Protocol = "http_connect"
	ProtocolExperimentalTCP Protocol = "experimental_tcp"
	ProtocolGRE             Protocol = "gre"
	ProtocolIPIP            Protocol = "ipip"
	ProtocolVXLAN           Protocol = "vxlan"
)

type EndpointMode string

const (
	EndpointActive  EndpointMode = "active"
	EndpointPassive EndpointMode = "passive"
)

type Endpoint struct {
	Name          core.EndpointID `json:"name"`
	Mode          EndpointMode    `json:"mode"`
	Listen        string          `json:"listen,omitempty"`
	Address       string          `json:"address,omitempty"`
	LocalBind     LocalBind       `json:"local_bind,omitempty"`
	Transport     Protocol        `json:"transport"`
	TLSServerName string          `json:"tls_server_name,omitempty"`
	Encryption    string          `json:"encryption,omitempty"`
	Enabled       bool            `json:"enabled"`
}

type LocalBind struct {
	SourceIP string `json:"source_ip,omitempty"`
	Iface    string `json:"iface,omitempty"`
}

type Peer struct {
	ID        core.IXID     `json:"id"`
	DomainID  core.DomainID `json:"domain_id"`
	Endpoints []Endpoint    `json:"endpoints"`
}

type ProbeResult struct {
	Healthy   bool          `json:"healthy"`
	RTT       time.Duration `json:"rtt"`
	Error     string        `json:"error,omitempty"`
	CheckedAt time.Time     `json:"checked_at"`
}

type TransportStats struct {
	BytesSent           uint64            `json:"bytes_sent"`
	BytesReceived       uint64            `json:"bytes_received"`
	PacketsSent         uint64            `json:"packets_sent"`
	PacketsReceived     uint64            `json:"packets_received"`
	CurrentFlows        uint64            `json:"current_flows"`
	Extra               map[string]uint64 `json:"extra,omitempty"`
	Encrypted           bool              `json:"encrypted,omitempty"`
	Encryption          string            `json:"encryption,omitempty"`
	SendEncrypted       bool              `json:"send_encrypted,omitempty"`
	ReceiveEncrypted    bool              `json:"receive_encrypted,omitempty"`
	CryptoSuite         string            `json:"crypto_suite,omitempty"`
	CryptoPlacement     string            `json:"crypto_placement,omitempty"`
	CryptoKeySource     string            `json:"crypto_key_source,omitempty"`
	LinkTLS             bool              `json:"link_tls,omitempty"`
	TLSVersion          string            `json:"tls_version,omitempty"`
	TLSCipherSuite      string            `json:"tls_cipher_suite,omitempty"`
	NativeBatching      bool              `json:"native_batching,omitempty"`
	Datagram            bool              `json:"datagram,omitempty"`
	FragmentingDatagram bool              `json:"fragmenting_datagram,omitempty"`
	MaxPacketSize       uint64            `json:"max_packet_size,omitempty"`
}

var ErrCryptoOffloadUnavailable = errors.New("transport crypto offload unavailable")
var ErrTLSExporterUnavailable = errors.New("transport TLS exporter unavailable")

const CryptoWireFormatTrustIXSecureDataV1 = "trustix-secure-data-v1"

type CryptoOffloadSpec struct {
	Suite        string `json:"suite"`
	WireFormat   string `json:"wire_format"`
	KeySource    string `json:"key_source,omitempty"`
	Epoch        uint64 `json:"epoch"`
	SendKey      []byte `json:"send_key"`
	SendIV       []byte `json:"send_iv"`
	RecvKey      []byte `json:"recv_key"`
	RecvIV       []byte `json:"recv_iv"`
	ReplayWindow uint   `json:"replay_window"`
}

type CryptoOffloadSession interface {
	EnableCryptoOffload(spec CryptoOffloadSpec) error
}

type TLSState struct {
	Enabled     bool
	Version     string
	CipherSuite string
}

type TLSExporterSession interface {
	ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)
	TLSState() TLSState
}

type Transport interface {
	Name() Protocol
	Probe(ctx context.Context, peer Peer) ProbeResult
	Dial(ctx context.Context, peer Peer, tlsConf *tls.Config) (Session, error)
	Listen(ctx context.Context, ep Endpoint, tlsConf *tls.Config) (Listener, error)
}

type Session interface {
	SendPacket(pkt []byte) error
	RecvPacket() ([]byte, error)
	Close() error
	Stats() TransportStats
}

type PacketBatchSession interface {
	SendPackets(pkts [][]byte) error
}

type PacketBatchReceiver interface {
	RecvPackets(max int) ([][]byte, error)
}

type PacketBatchReceiverWithRelease interface {
	RecvPacketsWithRelease(max int) (packets [][]byte, release func(), err error)
}

type PeerIdentitySession interface {
	PeerIdentity() (core.IXID, core.DomainID, bool)
}

type PeerIdentityAnnotator interface {
	SetPeerIdentity(peer core.IXID, domain core.DomainID)
}

type PeerIdentity struct {
	Role            string        `json:"role,omitempty"`
	Peer            core.IXID     `json:"peer,omitempty"`
	Domain          core.DomainID `json:"domain,omitempty"`
	Device          core.DeviceID `json:"device,omitempty"`
	LANID           string        `json:"lan_id,omitempty"`
	Prefixes        []string      `json:"prefixes,omitempty"`
	CertFingerprint string        `json:"cert_fingerprint,omitempty"`
}

type PeerIdentityDetailSession interface {
	PeerIdentityDetail() (PeerIdentity, bool)
}

type PeerIdentityDetailAnnotator interface {
	SetPeerIdentityDetail(identity PeerIdentity)
}

type PeerEndpointAnnotator interface {
	SetPeerEndpoint(peer core.IXID, endpoint core.EndpointID)
}

type KernelFlowRetentionSession interface {
	RetainKernelFlowOnClose()
}

type KernelDatapathSessionInfo struct {
	FlowID              uint64
	Protocol            Protocol
	Peer                core.IXID
	Endpoint            core.EndpointID
	LocalAddress        string
	RemoteAddress       string
	SourcePort          uint16
	DestinationPort     uint16
	Epoch               uint64
	CryptoSuite         string
	CryptoPlacement     string
	Encrypted           bool
	SendEncrypted       bool
	ReceiveEncrypted    bool
	NativeBatching      bool
	Datagram            bool
	FragmentingDatagram bool
	MaxPacketSize       uint64
}

type KernelDatapathSession interface {
	KernelDatapathSessionInfo() (KernelDatapathSessionInfo, bool)
}

type Listener interface {
	Accept(ctx context.Context) (Session, error)
	Close() error
}

type Registry struct {
	mu         sync.RWMutex
	transports map[Protocol]Transport
}

func NewRegistry() *Registry {
	return &Registry{transports: make(map[Protocol]Transport)}
}

func (registry *Registry) Register(transport Transport) error {
	if transport == nil {
		return fmt.Errorf("transport is nil")
	}
	name := transport.Name()
	if name == "" {
		return fmt.Errorf("transport name is required")
	}

	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, exists := registry.transports[name]; exists {
		return fmt.Errorf("transport %q already registered", name)
	}
	registry.transports[name] = transport
	return nil
}

func (registry *Registry) Get(protocol Protocol) (Transport, bool) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	transport, ok := registry.transports[protocol]
	return transport, ok
}

func (registry *Registry) Names() []Protocol {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	names := make([]Protocol, 0, len(registry.transports))
	for name := range registry.transports {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		return names[i] < names[j]
	})
	return names
}
