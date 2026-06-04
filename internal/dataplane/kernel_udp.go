package dataplane

import (
	"context"
	"time"

	"trustix.local/trustix/internal/core"
)

type KernelTransportDirection string

const (
	KernelTransportOutbound KernelTransportDirection = "outbound"
	KernelTransportInbound  KernelTransportDirection = "inbound"
)

type KernelUDPFlowRole string

const (
	KernelUDPFlowRoleOutbound       KernelUDPFlowRole = "outbound"
	KernelUDPFlowRoleInboundReverse KernelUDPFlowRole = "inbound_reverse"
)

type KernelUDPStatus struct {
	Available          bool                     `json:"available"`
	Provider           string                   `json:"provider,omitempty"`
	FastPath           bool                     `json:"fast_path"`
	DirectOnly         bool                     `json:"direct_only,omitempty"`
	TCOnly             bool                     `json:"tc_only,omitempty"`
	UserspaceCrypto    bool                     `json:"userspace_crypto"`
	KernelCrypto       bool                     `json:"kernel_crypto"`
	KernelCryptoReason string                   `json:"kernel_crypto_reason,omitempty"`
	CryptoFallback     CryptoFallbackStatus     `json:"crypto_fallback,omitempty"`
	RequestedCrypto    CryptoPlacement          `json:"requested_crypto,omitempty"`
	EffectiveCrypto    CryptoPlacement          `json:"effective_crypto,omitempty"`
	PreferredCrypto    CryptoPlacement          `json:"preferred_crypto"`
	SupportedCrypto    []CryptoPlacement        `json:"supported_crypto"`
	Reinject           bool                     `json:"reinject"`
	XDPAttachMode      string                   `json:"xdp_attach_mode,omitempty"`
	AFXDPBindMode      string                   `json:"af_xdp_bind_mode,omitempty"`
	ZeroCopyEnabled    bool                     `json:"zerocopy_enabled"`
	ActiveFlows        int                      `json:"active_flows"`
	SubmittedFrames    uint64                   `json:"submitted_frames"`
	ReceivedFrames     uint64                   `json:"received_frames"`
	ProviderStats      map[string]uint64        `json:"provider_stats,omitempty"`
	Telemetry          []TransportPathTelemetry `json:"telemetry,omitempty"`
	Notes              []string                 `json:"notes,omitempty"`
}

type KernelUDPFlow struct {
	ID              uint64            `json:"id"`
	Peer            core.IXID         `json:"peer"`
	Endpoint        core.EndpointID   `json:"endpoint"`
	Role            KernelUDPFlowRole `json:"role,omitempty"`
	LocalAddress    string            `json:"local_address,omitempty"`
	RemoteAddress   string            `json:"remote_address"`
	SourcePort      uint16            `json:"source_port,omitempty"`
	DestinationPort uint16            `json:"destination_port,omitempty"`
	Epoch           uint64            `json:"epoch,omitempty"`
	CryptoSuite     string            `json:"crypto_suite,omitempty"`
	CryptoPlacement CryptoPlacement   `json:"crypto_placement,omitempty"`
	CreatedAt       time.Time         `json:"created_at,omitempty"`
	LastSeen        time.Time         `json:"last_seen,omitempty"`
	ExpiresAt       time.Time         `json:"expires_at,omitempty"`
}

type KernelUDPFrame struct {
	FlowID        uint64                   `json:"flow_id"`
	Direction     KernelTransportDirection `json:"direction"`
	Peer          core.IXID                `json:"peer"`
	Endpoint      core.EndpointID          `json:"endpoint"`
	Epoch         uint64                   `json:"epoch,omitempty"`
	Sequence      uint64                   `json:"sequence"`
	FragmentIndex uint16                   `json:"fragment_index,omitempty"`
	FragmentCount uint16                   `json:"fragment_count,omitempty"`
	// FragmentPayloadSize is an internal TX hint used when a kernel-crypto
	// packet should be sealed once and fragmented after encryption.
	FragmentPayloadSize int             `json:"-"`
	Payload             []byte          `json:"payload"`
	Encrypted           bool            `json:"encrypted,omitempty"`
	InnerIPv4           bool            `json:"inner_ipv4,omitempty"`
	CryptoSuite         string          `json:"crypto_suite,omitempty"`
	CryptoPlacement     CryptoPlacement `json:"crypto_placement,omitempty"`
	// Release returns borrowed packet storage after the receiver has injected or
	// copied Payload. It is intentionally omitted from API serialization.
	Release func() `json:"-"`
}

type KernelUDPCryptoSpec struct {
	FlowID       uint64    `json:"flow_id"`
	Suite        string    `json:"suite"`
	WireFormat   string    `json:"wire_format"`
	KeySource    string    `json:"key_source,omitempty"`
	Epoch        uint64    `json:"epoch"`
	SendKey      []byte    `json:"send_key,omitempty"`
	SendIV       []byte    `json:"send_iv,omitempty"`
	RecvKey      []byte    `json:"recv_key,omitempty"`
	RecvIV       []byte    `json:"recv_iv,omitempty"`
	ReplayWindow uint      `json:"replay_window,omitempty"`
	InstalledAt  time.Time `json:"installed_at,omitempty"`
}

type KernelUDPSubscription interface {
	Events() <-chan KernelUDPFrame
	Close() error
}

type KernelUDPBatchSubscription interface {
	KernelUDPSubscription
	BatchEvents() <-chan []KernelUDPFrame
}

type KernelUDPProvider interface {
	KernelUDPStatus(ctx context.Context) (KernelUDPStatus, error)
	InstallKernelUDPFlows(ctx context.Context, flows []KernelUDPFlow) error
	SubmitKernelUDPFrame(ctx context.Context, frame KernelUDPFrame) error
	SubscribeKernelUDP(ctx context.Context, buffer int) (KernelUDPSubscription, error)
}

type KernelUDPBatchProvider interface {
	SubmitKernelUDPFrames(ctx context.Context, frames []KernelUDPFrame) error
}

type KernelUDPFlowSubscriber interface {
	SubscribeKernelUDPFlow(ctx context.Context, flowID uint64, buffer int) (KernelUDPSubscription, error)
}

type KernelUDPPayloadSizer interface {
	KernelUDPPayloadMax(ctx context.Context, placement CryptoPlacement, encrypted bool) (int, error)
}

type KernelUDPSealBeforeFragmentSizer interface {
	KernelUDPSealBeforeFragmentMax(ctx context.Context, placement CryptoPlacement) (int, error)
}

type KernelUDPCryptoInstaller interface {
	InstallKernelUDPCrypto(ctx context.Context, specs []KernelUDPCryptoSpec) error
}

type KernelUDPFlowDeleter interface {
	DeleteKernelUDPFlows(ctx context.Context, flowIDs []uint64) error
}

type KernelUDPFlowLookup interface {
	KernelUDPFlow(ctx context.Context, flowID uint64) (KernelUDPFlow, bool, error)
}

type KernelUDPFlowSnapshotter interface {
	KernelUDPFlows(ctx context.Context) ([]KernelUDPFlow, error)
}

type KernelUDPFlowAnnotator interface {
	SetKernelUDPFlowPeer(ctx context.Context, flowID uint64, peer core.IXID, endpoint core.EndpointID) error
}
