// Package dataplane defines the TC/eBPF management boundary. The production
// implementation will load, attach, and synchronize BPF programs and maps; the
// current no-op implementation keeps the daemon buildable on development hosts.
package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/observability"
	"trustix.local/trustix/internal/routing"
	rstate "trustix.local/trustix/internal/runtime"
)

var ErrUnsupported = errors.New("dataplane implementation unsupported on this platform")

type AttachSpec struct {
	LANIface                                 string          `json:"lan_iface"`
	UnderlayIface                            string          `json:"underlay_iface"`
	Gateway                                  string          `json:"gateway"`
	LANAttachMode                            string          `json:"lan_attach_mode,omitempty"`
	ManageQdisc                              bool            `json:"manage_qdisc"`
	ManageAddress                            bool            `json:"manage_address"`
	ManageForwarding                         bool            `json:"manage_forwarding"`
	ManageRPFilter                           bool            `json:"manage_rp_filter"`
	ManagedMTU                               int             `json:"managed_mtu,omitempty"`
	KernelUDPTXDirectOnly                    bool            `json:"kernel_udp_tx_direct_only,omitempty"`
	KernelUDPTXDirectOnlyReason              string          `json:"kernel_udp_tx_direct_only_reason,omitempty"`
	KernelUDPTXSecureDirect                  bool            `json:"kernel_udp_tx_secure_direct,omitempty"`
	KernelUDPRXSecureDirect                  bool            `json:"kernel_udp_rx_secure_direct,omitempty"`
	KernelUDPSecureDirectTrustInnerChecksums bool            `json:"kernel_udp_secure_direct_trust_inner_checksums,omitempty"`
	KernelUDPTXSecureDirectKfuncSeal         bool            `json:"kernel_udp_tx_secure_direct_kfunc_seal,omitempty"`
	KernelUDPTXSecureDirectSKBSealKfunc      bool            `json:"kernel_udp_tx_secure_direct_skb_seal_kfunc,omitempty"`
	ExperimentalTCPTXDirect                  bool            `json:"experimental_tcp_tx_direct,omitempty"`
	ExperimentalTCPRouteGSOSync              bool            `json:"experimental_tcp_route_gso_sync,omitempty"`
	ExperimentalTCPRouteGSOAsync             bool            `json:"experimental_tcp_route_gso_async,omitempty"`
	ExperimentalTCPRouteXmitWorker           bool            `json:"experimental_tcp_route_xmit_worker,omitempty"`
	ExperimentalTCPPlainSkipSequence         bool            `json:"experimental_tcp_plain_skip_sequence,omitempty"`
	ExperimentalTCPPlainACKOnly              bool            `json:"experimental_tcp_plain_ack_only,omitempty"`
	ExperimentalTCPFastPathDisabled          bool            `json:"experimental_tcp_fast_path_disabled,omitempty"`
	ExperimentalTCPFastPathDisabledReason    string          `json:"experimental_tcp_fast_path_disabled_reason,omitempty"`
	PinPath                                  string          `json:"pin_path"`
	DataDir                                  string          `json:"data_dir,omitempty"`
	LANs                                     []LANAttachSpec `json:"lans,omitempty"`
}

type LANAttachSpec struct {
	ID               string        `json:"id,omitempty"`
	Type             string        `json:"type,omitempty"`
	Iface            string        `json:"iface"`
	UnderlayIface    string        `json:"underlay_iface,omitempty"`
	Gateway          string        `json:"gateway,omitempty"`
	LANAttachMode    string        `json:"lan_attach_mode,omitempty"`
	ManageQdisc      bool          `json:"manage_qdisc"`
	ManageAddress    bool          `json:"manage_address"`
	ManageForwarding bool          `json:"manage_forwarding"`
	ManageRPFilter   bool          `json:"manage_rp_filter"`
	ManagedMTU       int           `json:"managed_mtu,omitempty"`
	Advertise        []core.Prefix `json:"advertise,omitempty"`
	DeviceAccess     bool          `json:"device_access,omitempty"`
	DeviceAccessPool string        `json:"device_access_pool,omitempty"`
}

type PeerMetadata struct {
	ID       core.IXID     `json:"id"`
	DomainID core.DomainID `json:"domain_id"`
	Trusted  bool          `json:"trusted"`
}

type EndpointMetadata struct {
	ID        core.EndpointID           `json:"id"`
	Peer      core.IXID                 `json:"peer"`
	Transport string                    `json:"transport"`
	Address   string                    `json:"address"`
	Listen    string                    `json:"listen,omitempty"`
	LocalBind EndpointLocalBindMetadata `json:"local_bind,omitempty"`
	Priority  int                       `json:"priority,omitempty"`
	Enabled   bool                      `json:"enabled"`
	Security  EndpointSecurityMetadata  `json:"security,omitempty"`
	Profile   TransportProfileMetadata  `json:"transport_profile,omitempty"`
	Access    EndpointAccessMetadata    `json:"access,omitempty"`
}

type EndpointLocalBindMetadata struct {
	SourceIP string `json:"source_ip,omitempty"`
	Iface    string `json:"iface,omitempty"`
}

type EndpointSecurityMetadata struct {
	LinkTLS          string   `json:"link_tls,omitempty"`
	TLSIdentity      string   `json:"tls_identity,omitempty"`
	TLSServerName    string   `json:"tls_server_name,omitempty"`
	Encryption       string   `json:"encryption,omitempty"`
	KeySources       []string `json:"key_sources,omitempty"`
	WireFormat       string   `json:"wire_format,omitempty"`
	CryptoSuites     []string `json:"crypto_suites,omitempty"`
	CryptoPlacements []string `json:"crypto_placements,omitempty"`
}

type EndpointAccessMetadata struct {
	Mode         string   `json:"mode,omitempty"`
	AllowedPeers []string `json:"allowed_peers,omitempty"`
	DefaultTTL   string   `json:"default_ttl,omitempty"`
}

type TransportProfileMetadata struct {
	Version         int      `json:"version,omitempty"`
	Profile         string   `json:"profile,omitempty"`
	Datapath        string   `json:"datapath,omitempty"`
	Encryption      string   `json:"encryption,omitempty"`
	CryptoPlacement string   `json:"crypto_placement,omitempty"`
	Features        []string `json:"features,omitempty"`
	FallbackReason  string   `json:"fallback_reason,omitempty"`
}

type Snapshot struct {
	Epoch         uint64                 `json:"epoch"`
	Routes        []routing.Route        `json:"routes"`
	Peers         []PeerMetadata         `json:"peers"`
	Endpoints     []EndpointMetadata     `json:"endpoints"`
	EndpointState []rstate.EndpointState `json:"endpoint_state"`
	PacketPolicy  PacketPolicy           `json:"packet_policy"`
	NAT           *NATSnapshot           `json:"nat,omitempty"`
}

type PacketPolicy struct {
	MTU                 uint32              `json:"mtu,omitempty"`
	DropFragments       bool                `json:"drop_fragments,omitempty"`
	TCPMSSClamp         uint32              `json:"tcp_mss_clamp,omitempty"`
	KernelTransportMode KernelTransportMode `json:"kernel_transport_mode,omitempty"`
}

type NATSnapshot struct {
	Enabled              bool           `json:"enabled"`
	Gateway              netip.Addr     `json:"gateway,omitempty"`
	SourcePrefixes       []netip.Prefix `json:"source_prefixes,omitempty"`
	RoutePrefixes        []core.Prefix  `json:"route_prefixes,omitempty"`
	ExcludedDestinations []netip.Addr   `json:"excluded_destinations,omitempty"`
	Bindings             []NATBinding   `json:"bindings,omitempty"`
}

type NATBinding struct {
	TranslatedIP netip.Addr `json:"translated_ip"`
	RemoteIP     netip.Addr `json:"remote_ip"`
	Protocol     uint8      `json:"protocol"`
	LocalPort    uint16     `json:"local_port,omitempty"`
	RemotePort   uint16     `json:"remote_port,omitempty"`
	OriginalIP   netip.Addr `json:"original_ip"`
	ExpiresAt    time.Time  `json:"expires_at,omitempty"`
}

type Stats struct {
	Epoch         uint64                              `json:"epoch"`
	Mode          string                              `json:"mode,omitempty"`
	Attached      bool                                `json:"attached,omitempty"`
	LANIface      string                              `json:"lan_iface,omitempty"`
	LANAttachMode string                              `json:"lan_attach_mode,omitempty"`
	LANs          []LANStats                          `json:"lans,omitempty"`
	PinPath       string                              `json:"pin_path,omitempty"`
	Capabilities  []string                            `json:"capabilities,omitempty"`
	Warnings      []string                            `json:"warnings,omitempty"`
	Counters      []observability.Counter             `json:"counters"`
	DropReasons   map[observability.DropReason]uint64 `json:"drop_reasons"`
}

type LANStats struct {
	ID               string `json:"id,omitempty"`
	Type             string `json:"type,omitempty"`
	Iface            string `json:"iface,omitempty"`
	UnderlayIface    string `json:"underlay_iface,omitempty"`
	Gateway          string `json:"gateway,omitempty"`
	LANAttachMode    string `json:"lan_attach_mode,omitempty"`
	ManageQdisc      bool   `json:"manage_qdisc,omitempty"`
	ManageAddress    bool   `json:"manage_address,omitempty"`
	ManageForwarding bool   `json:"manage_forwarding,omitempty"`
	ManageRPFilter   bool   `json:"manage_rp_filter,omitempty"`
	ManagedMTU       int    `json:"managed_mtu,omitempty"`
	LinkAdded        bool   `json:"link_added,omitempty"`
	AddressAdded     bool   `json:"address_added,omitempty"`
	QdiscPrepared    bool   `json:"qdisc_prepared,omitempty"`
}

type CaptureEvent struct {
	CapturedAt         time.Time       `json:"captured_at"`
	CPU                int             `json:"cpu"`
	Hook               string          `json:"hook"`
	PacketLength       uint32          `json:"packet_length"`
	SampleLength       uint32          `json:"sample_length"`
	GSOSegmentLength   uint32          `json:"gso_segment_length,omitempty"`
	SourceIP           string          `json:"source_ip,omitempty"`
	DestinationIP      string          `json:"destination_ip,omitempty"`
	NATTranslated      bool            `json:"nat_translated,omitempty"`
	OriginalSourceIP   string          `json:"original_source_ip,omitempty"`
	ChecksumNormalized bool            `json:"checksum_normalized,omitempty"`
	Payload            []byte          `json:"payload,omitempty"`
	SourceAddr         netip.Addr      `json:"-"`
	DestinationAddr    netip.Addr      `json:"-"`
	OriginalSourceAddr netip.Addr      `json:"-"`
	FlowKey            routing.FlowKey `json:"-"`
	HasFlow            bool            `json:"-"`
	PayloadMutable     bool            `json:"-"`
}

type LocalVIP struct {
	Addr netip.Addr `json:"addr"`
}

type BPFMapSnapshot struct {
	KernelUDPTXRoutes []KernelUDPTXRouteSnapshot `json:"kernel_udp_tx_routes,omitempty"`
	KernelUDPTXFlows  []KernelUDPTXFlowSnapshot  `json:"kernel_udp_tx_flows,omitempty"`
}

type KernelUDPTXRouteSnapshot struct {
	Prefix          string                    `json:"prefix"`
	PrefixLen       uint32                    `json:"prefix_len"`
	Address         string                    `json:"address"`
	FlowID          uint64                    `json:"flow_id,omitempty"`
	FlowIDs         []uint64                  `json:"flow_ids,omitempty"`
	ActiveFlowCount int                       `json:"active_flow_count,omitempty"`
	FlowMask        uint32                    `json:"flow_mask,omitempty"`
	Flags           uint32                    `json:"flags,omitempty"`
	DirectOnly      bool                      `json:"direct_only,omitempty"`
	Inline          bool                      `json:"inline,omitempty"`
	Bypass          bool                      `json:"bypass,omitempty"`
	InlineFlows     []KernelUDPTXFlowSnapshot `json:"inline_flows,omitempty"`
}

type KernelUDPTXFlowSnapshot struct {
	FlowID               uint64 `json:"flow_id,omitempty"`
	Slot                 int    `json:"slot,omitempty"`
	Inline               bool   `json:"inline,omitempty"`
	Sequence             uint64 `json:"sequence"`
	SourceIP             string `json:"source_ip,omitempty"`
	DestinationIP        string `json:"destination_ip,omitempty"`
	SourcePort           uint16 `json:"source_port,omitempty"`
	DestinationPort      uint16 `json:"destination_port,omitempty"`
	Ifindex              uint32 `json:"ifindex,omitempty"`
	DestinationMAC       string `json:"destination_mac,omitempty"`
	SourceMAC            string `json:"source_mac,omitempty"`
	MTU                  uint32 `json:"mtu,omitempty"`
	Flags                uint32 `json:"flags,omitempty"`
	Secure               bool   `json:"secure,omitempty"`
	TrustInnerChecksum   bool   `json:"trust_inner_checksum,omitempty"`
	HotStats             bool   `json:"hot_stats,omitempty"`
	ExperimentalTCP      bool   `json:"experimental_tcp,omitempty"`
	SkipOuterTCPChecksum bool   `json:"skip_outer_tcp_checksum,omitempty"`
	IPv4ChecksumUDPBase  uint16 `json:"ipv4_checksum_udp_base,omitempty"`
	IPv4ChecksumTCPBase  uint16 `json:"ipv4_checksum_tcp_base,omitempty"`
}

type Manager interface {
	Load(ctx context.Context) error
	Attach(ctx context.Context, spec AttachSpec) error
	ApplySnapshot(ctx context.Context, snapshot Snapshot) error
	Stats(ctx context.Context) (Stats, error)
	Detach(ctx context.Context) error
}

type BPFMapSnapshotter interface {
	BPFMapSnapshot(ctx context.Context) (BPFMapSnapshot, error)
}

type Cleaner interface {
	Cleanup(ctx context.Context, spec AttachSpec) error
}

type CleanupStep struct {
	Action string `json:"action"`
	Target string `json:"target,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type CleanupPlan struct {
	Spec  AttachSpec    `json:"spec"`
	Steps []CleanupStep `json:"steps"`
}

type CleanupPlanner interface {
	PlanCleanup(ctx context.Context, spec AttachSpec) (CleanupPlan, error)
}

type CaptureReader interface {
	Capture(ctx context.Context, limit int) ([]CaptureEvent, error)
}

type CaptureSubscription interface {
	Events() <-chan CaptureEvent
	Close() error
}

type CaptureBatchSubscription interface {
	CaptureSubscription
	BatchEvents() <-chan []CaptureEvent
}

type CaptureSubscriber interface {
	SubscribeCapture(ctx context.Context, buffer int) (CaptureSubscription, error)
}

type PacketInjector interface {
	InjectPacket(ctx context.Context, packet []byte) error
}

type PacketBatchInjector interface {
	InjectPackets(ctx context.Context, packets [][]byte) error
}

type PacketBatchGSOChecksumOffloadAdvisor interface {
	InjectBatchGSOChecksumOffloadMTU() int
}

type PacketBatchGSOScatterAdvisor interface {
	InjectBatchGSOScatterMTU() int
}

type LANPacketInjector interface {
	InjectLANPacket(ctx context.Context, packet []byte, destination netip.Addr) error
}

type LocalPacketInjector interface {
	InjectLocalPacket(ctx context.Context, packet []byte) error
}

type NATFastPathInjector interface {
	InjectNATPacket(ctx context.Context, packet []byte, destination netip.Addr) error
}

type NATSnapshotApplier interface {
	ApplyNATSnapshot(ctx context.Context, snapshot *NATSnapshot) error
}

type LocalVIPManager interface {
	SyncLocalVIPs(ctx context.Context, vips []LocalVIP) error
}
