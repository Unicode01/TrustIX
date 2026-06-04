package dataplane

import (
	"context"
	"time"

	"trustix.local/trustix/internal/core"
)

type CryptoPlacement string

const (
	CryptoPlacementAuto      CryptoPlacement = "auto"
	CryptoPlacementUserspace CryptoPlacement = "userspace"
	CryptoPlacementKernel    CryptoPlacement = "kernel"
)

type ExperimentalTCPDirection string

const (
	ExperimentalTCPOutbound ExperimentalTCPDirection = "outbound"
	ExperimentalTCPInbound  ExperimentalTCPDirection = "inbound"
)

type ExperimentalTCPStatus struct {
	Available          bool                     `json:"available"`
	Provider           string                   `json:"provider,omitempty"`
	FastPath           bool                     `json:"fast_path"`
	UserspaceCrypto    bool                     `json:"userspace_crypto"`
	KernelCrypto       bool                     `json:"kernel_crypto"`
	KernelCryptoReason string                   `json:"kernel_crypto_reason,omitempty"`
	KernelCryptoProbe  *KernelCryptoProbe       `json:"kernel_crypto_probe,omitempty"`
	CryptoFallback     CryptoFallbackStatus     `json:"crypto_fallback,omitempty"`
	Reinject           bool                     `json:"reinject"`
	RawSocketFallback  bool                     `json:"raw_socket_fallback"`
	XDPAttachMode      string                   `json:"xdp_attach_mode,omitempty"`
	AFXDPBindMode      string                   `json:"af_xdp_bind_mode,omitempty"`
	ZeroCopyEnabled    bool                     `json:"zerocopy_enabled"`
	FastPathFallback   string                   `json:"fast_path_fallback_reason,omitempty"`
	RequestedCrypto    CryptoPlacement          `json:"requested_crypto,omitempty"`
	EffectiveCrypto    CryptoPlacement          `json:"effective_crypto,omitempty"`
	PreferredCrypto    CryptoPlacement          `json:"preferred_crypto"`
	SupportedCrypto    []CryptoPlacement        `json:"supported_crypto"`
	FastPathQueues     int                      `json:"fast_path_queues,omitempty"`
	ProviderStats      map[string]uint64        `json:"provider_stats,omitempty"`
	Telemetry          []TransportPathTelemetry `json:"telemetry,omitempty"`
	Flows              []ExperimentalTCPFlow    `json:"flows,omitempty"`
	ActiveFlows        int                      `json:"active_flows"`
	SubmittedFrames    uint64                   `json:"submitted_frames"`
	ReceivedFrames     uint64                   `json:"received_frames"`
	Notes              []string                 `json:"notes,omitempty"`
}

type CryptoFallbackStatus struct {
	Selected string               `json:"selected,omitempty"`
	Chain    []CryptoFallbackStep `json:"chain,omitempty"`
}

type CryptoFallbackStep struct {
	Name      string `json:"name"`
	Ready     bool   `json:"ready"`
	Placement string `json:"placement"`
	Layer     string `json:"layer,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

type KernelCryptoProbe struct {
	KernelBTF        bool                   `json:"kernel_btf"`
	CryptoKfuncs     bool                   `json:"crypto_kfuncs"`
	RequiredKfuncs   []string               `json:"required_kfuncs,omitempty"`
	MissingKfuncs    []string               `json:"missing_kfuncs,omitempty"`
	AESGCM           bool                   `json:"aes_gcm"`
	AESNI            bool                   `json:"aes_ni"`
	AESGCMSoftware   bool                   `json:"aes_gcm_software_fallback"`
	CryptoAlgorithms []string               `json:"crypto_algorithms,omitempty"`
	CapabilityReady  bool                   `json:"capability_ready"`
	ProviderReady    bool                   `json:"provider_ready"`
	Reason           string                 `json:"reason,omitempty"`
	SelfTest         *KernelCryptoSelfTest  `json:"self_test,omitempty"`
	MapSchema        *KernelCryptoMapSchema `json:"map_schema,omitempty"`
}

type KernelCryptoSelfTest struct {
	Attempted    bool     `json:"attempted"`
	Passed       bool     `json:"passed"`
	ProgramTypes []string `json:"program_types,omitempty"`
	Reason       string   `json:"reason,omitempty"`
}

type KernelCryptoMapSchema struct {
	MaxEntries         uint32            `json:"max_entries"`
	FlowKeySize        int               `json:"flow_key_size"`
	FlowValueSize      int               `json:"flow_value_size"`
	Directions         []string          `json:"directions,omitempty"`
	KeyNamespaces      []string          `json:"key_namespaces,omitempty"`
	SupportedSuites    []string          `json:"supported_suites,omitempty"`
	SoftwareFallback   []string          `json:"software_fallback_suites,omitempty"`
	UnsupportedSuites  []string          `json:"unsupported_suites,omitempty"`
	UnsupportedReasons map[string]string `json:"unsupported_reasons,omitempty"`
	SupportedFormats   []string          `json:"supported_formats,omitempty"`
}

type ExperimentalTCPFlow struct {
	ID              uint64          `json:"id"`
	Peer            core.IXID       `json:"peer"`
	Endpoint        core.EndpointID `json:"endpoint"`
	LocalAddress    string          `json:"local_address,omitempty"`
	RemoteAddress   string          `json:"remote_address"`
	SourcePort      uint16          `json:"source_port,omitempty"`
	DestinationPort uint16          `json:"destination_port,omitempty"`
	Epoch           uint64          `json:"epoch"`
	CryptoSuite     string          `json:"crypto_suite,omitempty"`
	CryptoPlacement CryptoPlacement `json:"crypto_placement"`
	CreatedAt       time.Time       `json:"created_at,omitempty"`
	LastSeen        time.Time       `json:"last_seen,omitempty"`
	ExpiresAt       time.Time       `json:"expires_at,omitempty"`
}

type ExperimentalTCPCryptoSpec struct {
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

type ExperimentalTCPFrame struct {
	FlowID        uint64                   `json:"flow_id"`
	Direction     ExperimentalTCPDirection `json:"direction"`
	Peer          core.IXID                `json:"peer"`
	Endpoint      core.EndpointID          `json:"endpoint"`
	Epoch         uint64                   `json:"epoch"`
	Sequence      uint64                   `json:"sequence"`
	FragmentIndex uint16                   `json:"fragment_index,omitempty"`
	FragmentCount uint16                   `json:"fragment_count,omitempty"`
	// FragmentPayloadSize is an internal TX hint used when a kernel-crypto
	// packet should be sealed once and fragmented after encryption.
	FragmentPayloadSize int             `json:"-"`
	Payload             []byte          `json:"payload"`
	Encrypted           bool            `json:"encrypted"`
	InnerIPv4           bool            `json:"inner_ipv4,omitempty"`
	CryptoSuite         string          `json:"crypto_suite,omitempty"`
	CryptoPlacement     CryptoPlacement `json:"crypto_placement"`
	// Release returns borrowed packet storage after the receiver has injected or
	// copied Payload. It is intentionally omitted from API serialization.
	Release func() `json:"-"`
}

type ExperimentalTCPSubscription interface {
	Events() <-chan ExperimentalTCPFrame
	Close() error
}

type ExperimentalTCPBatchSubscription interface {
	ExperimentalTCPSubscription
	BatchEvents() <-chan []ExperimentalTCPFrame
}

type ExperimentalTCPProvider interface {
	ExperimentalTCPStatus(ctx context.Context) (ExperimentalTCPStatus, error)
	InstallExperimentalTCPFlows(ctx context.Context, flows []ExperimentalTCPFlow) error
	SubmitExperimentalTCPFrame(ctx context.Context, frame ExperimentalTCPFrame) error
	SubscribeExperimentalTCP(ctx context.Context, buffer int) (ExperimentalTCPSubscription, error)
}

type ExperimentalTCPBatchProvider interface {
	SubmitExperimentalTCPFrames(ctx context.Context, frames []ExperimentalTCPFrame) error
}

type ExperimentalTCPFlowSubscriber interface {
	SubscribeExperimentalTCPFlow(ctx context.Context, flowID uint64, buffer int) (ExperimentalTCPSubscription, error)
}

type ExperimentalTCPPayloadSizer interface {
	ExperimentalTCPPayloadMax(ctx context.Context, placement CryptoPlacement, encrypted bool) (int, error)
}

type ExperimentalTCPSealBeforeFragmentSizer interface {
	ExperimentalTCPSealBeforeFragmentMax(ctx context.Context, placement CryptoPlacement) (int, error)
}

type ExperimentalTCPCryptoInstaller interface {
	InstallExperimentalTCPCrypto(ctx context.Context, specs []ExperimentalTCPCryptoSpec) error
}

type ExperimentalTCPFlowDeleter interface {
	DeleteExperimentalTCPFlows(ctx context.Context, flowIDs []uint64) error
}

type ExperimentalTCPFlowLookup interface {
	ExperimentalTCPFlow(ctx context.Context, flowID uint64) (ExperimentalTCPFlow, bool, error)
}

type ExperimentalTCPFlowAnnotator interface {
	SetExperimentalTCPFlowPeer(ctx context.Context, flowID uint64, peer core.IXID, endpoint core.EndpointID) error
}
