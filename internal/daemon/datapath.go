package daemon

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/observability"
	"trustix.local/trustix/internal/pki"
	"trustix.local/trustix/internal/routing"
	rstate "trustix.local/trustix/internal/runtime"
	"trustix.local/trustix/internal/transport"
	securetransport "trustix.local/trustix/internal/transport/secure"
)

const dataPathDialTimeout = 5 * time.Second
const dataSessionPoolWarmupDefaultDeadline = 30 * time.Second
const dataSessionPoolWarmupDefaultRetryDelay = 250 * time.Millisecond
const dataSessionHeartbeatDefaultInterval = 10 * time.Second
const dataSessionHeartbeatDefaultTimeout = 3 * time.Second
const dataSessionHeartbeatMaxMisses = 3
const dataSessionHeartbeatRecentActivityGrace = 2
const dataSessionEndpointUpRefreshInterval = 5 * time.Second
const deviceAccessExpiryReaperInterval = 5 * time.Second
const captureForwarderDefaultBuffer = 8192
const captureForwarderMaxBuffer = 65536
const captureForwarderDefaultWorkers = 1
const captureForwarderMaxBatch = 4096
const reverseSessionAddress = "reverse://inbound"
const dataSessionBatchDefaultBytes = 256 * 1024
const dataSessionBatchDefaultDelay = 25 * time.Microsecond
const dataSessionBatchMaxPackets = 256
const dataSessionBatchHeaderLen = 8
const dataSessionBatchItemHeaderLen = 2
const dataSessionBatchPayloadRetainMax = 512 * 1024
const dataSessionKernelCryptoBatchMaxBytes = 256 * 1024
const dataSessionKernelCryptoBatchDefaultBytes = dataSessionKernelCryptoBatchMaxBytes
const dataSessionUserspaceEncryptedBatchDefaultBytes = 0
const dataSessionUserspaceEncryptedBatchMaxBytes = 32 * 1024
const captureForwarderDefaultBatch = 1024
const captureForwarderDefaultBatchDelay = 0
const dataSessionReceiveDefaultBatch = 256
const kernelUDPPlaintextWarmupDefaultTimeout = 15 * time.Second
const kernelUDPPlaintextWarmupDefaultRetryDelay = 250 * time.Millisecond
const kernelDatapathRXStageDefaultBatch = 256
const kernelDatapathRXStageMaxBatch = 4096
const kernelDatapathRXStageDefaultIdleDelay = time.Millisecond
const kernelDatapathRXStageDefaultErrorDelay = 250 * time.Millisecond

var dataSessionControlMagic = [4]byte{'T', 'I', 'X', 'C'}
var dataSessionBatchMagic = [4]byte{'T', 'I', 'X', 'B'}
var dataSessionSecureHandshakeMagic = [4]byte{'T', 'I', 'X', 'H'}
var errDataSessionEpochChanged = errors.New("data session epoch changed")

const (
	dataSessionControlVersion             byte = 1
	dataSessionControlPing                byte = 1
	dataSessionControlPong                byte = 2
	dataSessionControlDeviceLease         byte = 3
	dataSessionControlLen                      = 16
	dataSessionControlDeviceLeaseLen           = 28
	dataSessionControlDeviceLeaseRouteLen      = 8
	dataSessionBatchVersion               byte = 1
)

type dataPathStats struct {
	captureEvents                   atomic.Uint64
	captureNonRouteEvents           atomic.Uint64
	captureTruncated                atomic.Uint64
	captureUnavailable              atomic.Uint64
	routeMisses                     atomic.Uint64
	packetsSent                     atomic.Uint64
	sendErrors                      atomic.Uint64
	sendDecisionAttempts            atomic.Uint64
	sendDecisionCandidates          atomic.Uint64
	sendDecisionNoCandidates        atomic.Uint64
	sessionDials                    atomic.Uint64
	sessionDialAttempts             atomic.Uint64
	sessionDialErrors               atomic.Uint64
	packetsReceived                 atomic.Uint64
	receiveErrors                   atomic.Uint64
	packetsInjected                 atomic.Uint64
	injectErrors                    atomic.Uint64
	listenerAcceptErrors            atomic.Uint64
	unsupportedTransport            atomic.Uint64
	sessionHeartbeatSent            atomic.Uint64
	sessionHeartbeatReceived        atomic.Uint64
	sessionHeartbeatTimeouts        atomic.Uint64
	sessionResetsSent               atomic.Uint64
	sessionResetsReceived           atomic.Uint64
	staleSessionsDropped            atomic.Uint64
	natTranslations                 atomic.Uint64
	natReverseHits                  atomic.Uint64
	natMisses                       atomic.Uint64
	natDataplaneSyncErrors          atomic.Uint64
	forwardCacheHits                atomic.Uint64
	forwardCacheMisses              atomic.Uint64
	forwardCacheStores              atomic.Uint64
	receiveBatchFrames              atomic.Uint64
	receiveBatchPackets             atomic.Uint64
	injectBatchAttempts             atomic.Uint64
	injectBatchPackets              atomic.Uint64
	injectGSOCoalesceBatches        atomic.Uint64
	injectGSOCoalescePackets        atomic.Uint64
	injectGSOCoalesceWires          atomic.Uint64
	injectGSOCoalesceBytes          atomic.Uint64
	kernelRXStagePolls              atomic.Uint64
	kernelRXStageEmptyPolls         atomic.Uint64
	kernelRXStagePackets            atomic.Uint64
	kernelRXStageBatches            atomic.Uint64
	kernelRXStageErrors             atomic.Uint64
	sendGSOCoalesceBatches          atomic.Uint64
	sendGSOCoalescePackets          atomic.Uint64
	sendGSOCoalesceWires            atomic.Uint64
	sendGSOCoalesceBytes            atomic.Uint64
	sendSoftwareSegments            atomic.Uint64
	sendSoftwareSegmentFrames       atomic.Uint64
	sendSoftwareSegmentWires        atomic.Uint64
	sendSoftwareSegmentBytes        atomic.Uint64
	sendSoftwareSegmentFragDatagram atomic.Uint64
	sendSoftwareSegmentDrops        atomic.Uint64
	dataSessionBatchQueuedPackets   atomic.Uint64
	dataSessionBatchQueuedBytes     atomic.Uint64
	dataSessionBatchFlushes         atomic.Uint64
	dataSessionBatchFlushPackets    atomic.Uint64
	dataSessionBatchFlushBytes      atomic.Uint64
	dataSessionBatchFlushMaxPackets atomic.Uint64
	dataSessionBatchFlushMaxBytes   atomic.Uint64
	dataSessionBatchDirectPackets   atomic.Uint64
	dataSessionBatchDirectBytes     atomic.Uint64
	dataSessionBatchRXFrames        atomic.Uint64
	dataSessionBatchRXPackets       atomic.Uint64
	dataSessionBatchRXBytes         atomic.Uint64
	dataSessionBatchRXMaxPackets    atomic.Uint64
	dataSessionBatchRXMaxBytes      atomic.Uint64
	rejectICMPGenerated             atomic.Uint64
	rejectRSTGenerated              atomic.Uint64
	ttlICMPGenerated                atomic.Uint64
	rejectReplyErrors               atomic.Uint64
	linkTLSSessionsSeen             atomic.Uint64
	tlsExporterSessionsSeen         atomic.Uint64
	tlsExporterNoLinkSeen           atomic.Uint64
	tlsMu                           sync.Mutex
	lastLinkTLSVersion              string
	lastLinkTLSCipherSuite          string
	lastSessionDialError            atomic.Value
	lastReceiveError                atomic.Value
	lastInjectError                 atomic.Value
	dropMu                          sync.Mutex
	dropReasons                     map[observability.DropReason]uint64
}

type dataPathCounters struct {
	CaptureEvents                   uint64 `json:"capture_events"`
	CaptureNonRouteEvents           uint64 `json:"capture_non_route_events"`
	CaptureTruncated                uint64 `json:"capture_truncated"`
	CaptureUnavailable              uint64 `json:"capture_unavailable"`
	RouteMisses                     uint64 `json:"route_misses"`
	PacketsSent                     uint64 `json:"packets_sent"`
	SendErrors                      uint64 `json:"send_errors"`
	SendDecisionAttempts            uint64 `json:"send_decision_attempts"`
	SendDecisionCandidates          uint64 `json:"send_decision_candidates"`
	SendDecisionNoCandidates        uint64 `json:"send_decision_no_candidates"`
	SessionDials                    uint64 `json:"session_dials"`
	SessionDialAttempts             uint64 `json:"session_dial_attempts"`
	SessionDialErrors               uint64 `json:"session_dial_errors"`
	LastSessionDialError            string `json:"last_session_dial_error,omitempty"`
	PacketsReceived                 uint64 `json:"packets_received"`
	ReceiveErrors                   uint64 `json:"receive_errors"`
	PacketsInjected                 uint64 `json:"packets_injected"`
	InjectErrors                    uint64 `json:"inject_errors"`
	ListenerAcceptErrors            uint64 `json:"listener_accept_errors"`
	UnsupportedTransport            uint64 `json:"unsupported_transport"`
	SessionHeartbeatSent            uint64 `json:"session_heartbeat_sent"`
	SessionHeartbeatReceived        uint64 `json:"session_heartbeat_received"`
	SessionHeartbeatTimeouts        uint64 `json:"session_heartbeat_timeouts"`
	SessionResetsSent               uint64 `json:"session_resets_sent"`
	SessionResetsReceived           uint64 `json:"session_resets_received"`
	StaleSessionsDropped            uint64 `json:"stale_sessions_dropped"`
	NATTranslations                 uint64 `json:"nat_translations"`
	NATReverseHits                  uint64 `json:"nat_reverse_hits"`
	NATMisses                       uint64 `json:"nat_misses"`
	NATDataplaneSyncErrors          uint64 `json:"nat_dataplane_sync_errors"`
	ForwardCacheHits                uint64 `json:"forward_cache_hits"`
	ForwardCacheMisses              uint64 `json:"forward_cache_misses"`
	ForwardCacheStores              uint64 `json:"forward_cache_stores"`
	ReceiveBatchFrames              uint64 `json:"receive_batch_frames"`
	ReceiveBatchPackets             uint64 `json:"receive_batch_packets"`
	InjectBatchAttempts             uint64 `json:"inject_batch_attempts"`
	InjectBatchPackets              uint64 `json:"inject_batch_packets"`
	InjectGSOCoalesceBatches        uint64 `json:"inject_gso_coalesce_batches"`
	InjectGSOCoalescePackets        uint64 `json:"inject_gso_coalesce_packets"`
	InjectGSOCoalesceWires          uint64 `json:"inject_gso_coalesce_wires"`
	InjectGSOCoalesceBytes          uint64 `json:"inject_gso_coalesce_bytes"`
	KernelRXStagePolls              uint64 `json:"kernel_rx_stage_polls"`
	KernelRXStageEmptyPolls         uint64 `json:"kernel_rx_stage_empty_polls"`
	KernelRXStagePackets            uint64 `json:"kernel_rx_stage_packets"`
	KernelRXStageBatches            uint64 `json:"kernel_rx_stage_batches"`
	KernelRXStageErrors             uint64 `json:"kernel_rx_stage_errors"`
	SendGSOCoalesceBatches          uint64 `json:"send_gso_coalesce_batches"`
	SendGSOCoalescePackets          uint64 `json:"send_gso_coalesce_packets"`
	SendGSOCoalesceWires            uint64 `json:"send_gso_coalesce_wires"`
	SendGSOCoalesceBytes            uint64 `json:"send_gso_coalesce_bytes"`
	SendSoftwareSegments            uint64 `json:"send_software_segments"`
	SendSoftwareSegmentFrames       uint64 `json:"send_software_segment_frames"`
	SendSoftwareSegmentWires        uint64 `json:"send_software_segment_wires"`
	SendSoftwareSegmentBytes        uint64 `json:"send_software_segment_bytes"`
	SendSoftwareSegmentFragDatagram uint64 `json:"send_software_segment_fragmenting_datagram"`
	SendSoftwareSegmentDrops        uint64 `json:"send_software_segment_drops"`
	DataSessionBatchQueuedPackets   uint64 `json:"data_session_batch_queued_packets"`
	DataSessionBatchQueuedBytes     uint64 `json:"data_session_batch_queued_bytes"`
	DataSessionBatchFlushes         uint64 `json:"data_session_batch_flushes"`
	DataSessionBatchFlushPackets    uint64 `json:"data_session_batch_flush_packets"`
	DataSessionBatchFlushBytes      uint64 `json:"data_session_batch_flush_bytes"`
	DataSessionBatchFlushMaxPackets uint64 `json:"data_session_batch_flush_max_packets"`
	DataSessionBatchFlushMaxBytes   uint64 `json:"data_session_batch_flush_max_bytes"`
	DataSessionBatchDirectPackets   uint64 `json:"data_session_batch_direct_packets"`
	DataSessionBatchDirectBytes     uint64 `json:"data_session_batch_direct_bytes"`
	DataSessionBatchRXFrames        uint64 `json:"data_session_batch_rx_frames"`
	DataSessionBatchRXPackets       uint64 `json:"data_session_batch_rx_packets"`
	DataSessionBatchRXBytes         uint64 `json:"data_session_batch_rx_bytes"`
	DataSessionBatchRXMaxPackets    uint64 `json:"data_session_batch_rx_max_packets"`
	DataSessionBatchRXMaxBytes      uint64 `json:"data_session_batch_rx_max_bytes"`
	RejectICMPGenerated             uint64 `json:"reject_icmp_generated"`
	RejectRSTGenerated              uint64 `json:"reject_rst_generated"`
	TTLICMPGenerated                uint64 `json:"ttl_icmp_generated"`
	RejectReplyErrors               uint64 `json:"reject_reply_errors"`
	LastReceiveError                string `json:"last_receive_error,omitempty"`
	LastInjectError                 string `json:"last_inject_error,omitempty"`
}

type dataPathStatus struct {
	Listeners                        []dataPathListenerStatus            `json:"listeners"`
	Sessions                         []dataPathSessionStatus             `json:"sessions"`
	ActiveSessions                   int                                 `json:"active_sessions"`
	CaptureForwarderActive           bool                                `json:"capture_forwarder_active"`
	CaptureForwarderSuppressed       bool                                `json:"capture_forwarder_suppressed,omitempty"`
	CaptureForwarderSuppressedReason string                              `json:"capture_forwarder_suppressed_reason,omitempty"`
	Warnings                         []string                            `json:"warnings,omitempty"`
	Counters                         dataPathCounters                    `json:"counters"`
	KernelOffload                    dataPathKernelOffloadStatus         `json:"kernel_offload"`
	KernelRXStage                    kernelDatapathRXStageStatus         `json:"kernel_rx_stage,omitempty"`
	KernelTransport                  *dataplane.KernelTransportStatus    `json:"kernel_transport,omitempty"`
	KernelUDP                        *dataplane.KernelUDPStatus          `json:"kernel_udp,omitempty"`
	TLS                              dataPathTLSObservation              `json:"tls"`
	RouteStats                       []dataPathRouteStats                `json:"route_stats,omitempty"`
	PeerStats                        []dataPathPeerStats                 `json:"peer_stats,omitempty"`
	EndpointStats                    []dataPathEndpointStats             `json:"endpoint_stats,omitempty"`
	EndpointState                    []rstate.EndpointState              `json:"endpoint_state,omitempty"`
	DropReasons                      map[observability.DropReason]uint64 `json:"drop_reasons,omitempty"`
	NAT                              *natStatus                          `json:"nat,omitempty"`
	ExperimentalTCP                  *dataplane.ExperimentalTCPStatus    `json:"experimental_tcp,omitempty"`
}

type dataPathListenerStatus struct {
	Endpoint  string `json:"endpoint"`
	Transport string `json:"transport"`
	Listen    string `json:"listen"`
}

type dataPathSessionStatus struct {
	Peer        string                   `json:"peer"`
	Endpoint    string                   `json:"endpoint"`
	Transport   string                   `json:"transport"`
	Address     string                   `json:"address"`
	Direction   string                   `json:"direction"`
	Reverse     bool                     `json:"reverse"`
	PoolIndex   int                      `json:"pool_index,omitempty"`
	ControlOnly bool                     `json:"control_only,omitempty"`
	ReceiveLoop bool                     `json:"receive_loop"`
	LastRX      time.Time                `json:"last_rx,omitempty"`
	LastTX      time.Time                `json:"last_tx,omitempty"`
	LastUp      time.Time                `json:"last_up,omitempty"`
	LastPong    time.Time                `json:"last_pong,omitempty"`
	Stats       transport.TransportStats `json:"stats"`
}

type dataPathTLSObservation struct {
	LinkTLSSessionsSeen     uint64 `json:"link_tls_sessions_seen"`
	TLSExporterSessionsSeen uint64 `json:"tls_exporter_key_sessions_seen"`
	TLSExporterNoLinkSeen   uint64 `json:"tls_exporter_without_link_tls_seen"`
	LastLinkTLSVersion      string `json:"last_link_tls_version,omitempty"`
	LastLinkTLSCipherSuite  string `json:"last_link_tls_cipher_suite,omitempty"`
}

type dataPathKernelOffloadStatus struct {
	DataplaneMode      string                            `json:"dataplane_mode,omitempty"`
	Capabilities       []string                          `json:"capabilities,omitempty"`
	PacketPolicy       dataplane.PacketPolicy            `json:"packet_policy"`
	Placements         []dataPathKernelPlacement         `json:"placements"`
	KernelCandidates   []dataPathKernelCandidate         `json:"kernel_candidates,omitempty"`
	UserspaceRemaining []dataPathUserspaceResponsibility `json:"userspace_remaining,omitempty"`
}

type dataPathKernelPlacement struct {
	Name      string `json:"name"`
	Layer     string `json:"layer"`
	Placement string `json:"placement"`
	Detail    string `json:"detail,omitempty"`
}

type dataPathKernelCandidate struct {
	Name       string `json:"name"`
	Layer      string `json:"layer"`
	Complexity string `json:"complexity,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

type dataPathUserspaceResponsibility struct {
	Name   string `json:"name"`
	Reason string `json:"reason,omitempty"`
}

type dataSessionKey struct {
	Peer       core.IXID
	Endpoint   core.EndpointID
	Transport  transport.Protocol
	Address    string
	Encryption string
	PoolIndex  int
}

type dataSessionPoolKey struct {
	Peer       core.IXID
	Endpoint   core.EndpointID
	Transport  transport.Protocol
	Address    string
	Encryption string
}

type dataSessionFlowPoolKey struct {
	Pool dataSessionPoolKey
	Flow routing.FlowKey
}

type dataForwardCacheEntry struct {
	Decision       routing.Decision
	Peer           config.PeerConfig
	Endpoint       config.EndpointConfig
	Session        transport.Session
	Key            dataSessionKey
	Runtime        *dataSessionRuntime
	Policy         config.PolicyConfig
	NativeBatching bool
	ExpiresAt      time.Time
}

type dataPacketSendOptions struct {
	UseForwardCache        bool
	AllowDial              bool
	DropSessionOnSendError bool
	RecordEndpointHealth   bool
	BindFlow               bool
}

var defaultDataPacketSendOptions = dataPacketSendOptions{
	UseForwardCache:        true,
	AllowDial:              true,
	DropSessionOnSendError: true,
	RecordEndpointHealth:   true,
	BindFlow:               true,
}

var diagnosticDataPacketSendOptions = dataPacketSendOptions{
	UseForwardCache:        false,
	AllowDial:              false,
	DropSessionOnSendError: false,
	RecordEndpointHealth:   false,
	BindFlow:               false,
}

type dataListenerRuntime struct {
	Endpoint transport.Endpoint
	Listener transport.Listener
	Cancel   context.CancelFunc
}

type dataSessionRuntime struct {
	key          dataSessionKey
	session      transport.Session
	peer         config.PeerConfig
	endpoint     config.EndpointConfig
	cancel       context.CancelFunc
	batching     dataSessionBatchConfig
	controlOnly  bool
	receiveData  bool
	receiveLoop  bool
	sendMu       sync.Mutex
	batchMu      sync.Mutex
	batchNotify  chan struct{}
	batch        dataSessionBatch
	capabilities atomic.Value
	lastPong     atomic.Int64
	pongNonce    atomic.Uint64
	nonce        atomic.Uint64
	lastRX       atomic.Int64
	lastTX       atomic.Int64
	lastUp       atomic.Int64
}

type deviceLeaseKey struct {
	IX     core.IXID
	Device core.DeviceID
}

type deviceAccessLease struct {
	Key               deviceLeaseKey
	LANID             string
	Address           netip.Addr
	Prefix            netip.Prefix
	AdvertisePrefixes []netip.Prefix
	SessionKey        dataSessionKey
	Endpoint          config.EndpointConfig
	ExpiresAt         time.Time
}

type dataSessionBatch struct {
	payload    []byte
	reuse      []byte
	count      int
	firstSeen  time.Time
	lastError  error
	lastFailed bool
}

type dataSessionBatchConfig struct {
	enabled    bool
	maxBytes   int
	maxPackets int
	delay      time.Duration
	ready      bool
}

type captureForwardBatchCandidate struct {
	Entry   *dataForwardCacheEntry
	FlowKey routing.FlowKey
	Packet  []byte
}

type captureForwardBatchGroup struct {
	Runtime *dataSessionRuntime
	Items   []captureForwardBatchCandidate
}

type captureForwardPreparedBatch struct {
	Packets [][]byte
	Bytes   int
}

type captureForwardScratch struct {
	candidates                     []captureForwardBatchCandidate
	fallbacks                      []dataplane.CaptureEvent
	groups                         map[*dataSessionRuntime]int
	batches                        []captureForwardBatchGroup
	packets                        [][]byte
	coalescedPackets               [][]byte
	coalesceArena                  []byte
	packetArena                    []byte
	txGSOCoalesceReady             bool
	txGSOCoalesceEnabled           bool
	txGSOCoalesceExplicit          bool
	txGSOCoalesceMaxBytes          int
	txGSOCoalesceMaxPkts           int
	txGSOCoalesceMultiFlow         bool
	txGSOCoalesceMultiFlowExplicit bool
	mssClamp                       int
	trustCapturedChecksum          bool
	trustCapturedReady             bool
	mtu                            int
	dropFragments                  bool
}

type dataReceiveScratch struct {
	dataPackets            [][]byte
	localPackets           [][]byte
	batchPackets           [][]byte
	coalescedPackets       [][]byte
	coalesceArena          []byte
	disableRXGSOCoalesce   bool
	rxGSOCoalesceReady     bool
	rxGSOCoalesceEnabled   bool
	rxGSOCoalesceMaxBytes  int
	rxGSOCoalesceMaxPkts   int
	rxGSOCoalesceMultiFlow bool
	rxGSOChecksumMTU       int
	rxGSOScatterEnabled    bool
	rxGSOScatterMTU        int
}

type localLANCache struct {
	ready      bool
	advertise  []netip.Prefix
	gateway    netip.Prefix
	hasGateway bool
	gateways   []netip.Prefix
	natEnabled bool
}

func (scratch *captureForwardScratch) begin(eventCount int, daemon *Daemon) {
	if cap(scratch.candidates) < eventCount {
		scratch.candidates = make([]captureForwardBatchCandidate, 0, eventCount)
	} else {
		scratch.candidates = scratch.candidates[:0]
	}
	if cap(scratch.fallbacks) < eventCount {
		scratch.fallbacks = make([]dataplane.CaptureEvent, 0, eventCount)
	} else {
		scratch.fallbacks = scratch.fallbacks[:0]
	}
	if scratch.groups != nil {
		clear(scratch.groups)
	}
	for i := range scratch.batches {
		clear(scratch.batches[i].Items)
		scratch.batches[i].Items = scratch.batches[i].Items[:0]
		scratch.batches[i].Runtime = nil
	}
	scratch.batches = scratch.batches[:0]
	scratch.packets = scratch.packets[:0]
	clear(scratch.coalescedPackets)
	scratch.coalescedPackets = scratch.coalescedPackets[:0]
	scratch.coalesceArena = scratch.coalesceArena[:0]
	if !scratch.txGSOCoalesceReady {
		scratch.txGSOCoalesceEnabled, scratch.txGSOCoalesceExplicit = dataSessionTXGSOCoalescePreference()
		scratch.txGSOCoalesceMaxBytes = dataSessionTXGSOCoalesceMaxBytes()
		scratch.txGSOCoalesceMaxPkts = dataSessionTXGSOCoalesceMaxPackets()
		scratch.txGSOCoalesceMultiFlow, scratch.txGSOCoalesceMultiFlowExplicit = dataSessionTXGSOCoalesceMultiFlowPreference()
		scratch.txGSOCoalesceReady = true
	}
	scratch.mssClamp = daemon.effectiveTCPMSSClamp()
	if !scratch.trustCapturedReady {
		scratch.trustCapturedChecksum = trustCapturedChecksums()
		scratch.trustCapturedReady = true
	}
	scratch.mtu = daemon.desired.TransportPolicy.MTU
	scratch.dropFragments = daemon.fragmentPolicyDrop()
}

func (scratch *captureForwardScratch) reservePacketArena(events []dataplane.CaptureEvent) {
	total := 0
	for _, event := range events {
		total += len(event.Payload)
	}
	if cap(scratch.packetArena) < total {
		scratch.packetArena = make([]byte, 0, total)
		return
	}
	scratch.packetArena = scratch.packetArena[:0]
}

func (scratch *captureForwardScratch) clonePacket(packet []byte) []byte {
	if len(packet) == 0 {
		return nil
	}
	if scratch == nil {
		return append([]byte(nil), packet...)
	}
	start := len(scratch.packetArena)
	scratch.packetArena = append(scratch.packetArena, packet...)
	return scratch.packetArena[start:len(scratch.packetArena)]
}

func (scratch *captureForwardScratch) release() {
	scratch.candidates = scratch.candidates[:0]
	scratch.fallbacks = scratch.fallbacks[:0]
	if scratch.groups != nil {
		clear(scratch.groups)
	}
	for i := range scratch.batches {
		scratch.batches[i].Items = scratch.batches[i].Items[:0]
		scratch.batches[i].Runtime = nil
	}
	scratch.batches = scratch.batches[:0]
	scratch.packets = scratch.packets[:0]
	clear(scratch.coalescedPackets)
	scratch.coalescedPackets = scratch.coalescedPackets[:0]
	scratch.coalesceArena = scratch.coalesceArena[:0]
	scratch.packetArena = scratch.packetArena[:0]
}

func (scratch *dataReceiveScratch) dataSlice(size int) [][]byte {
	if cap(scratch.dataPackets) < size {
		scratch.dataPackets = make([][]byte, 0, size)
	} else {
		scratch.dataPackets = scratch.dataPackets[:0]
	}
	return scratch.dataPackets
}

func (scratch *dataReceiveScratch) localSlice(size int) [][]byte {
	if cap(scratch.localPackets) < size {
		scratch.localPackets = make([][]byte, 0, size)
	} else {
		scratch.localPackets = scratch.localPackets[:0]
	}
	return scratch.localPackets
}

func (scratch *dataReceiveScratch) release() {
	clear(scratch.batchPackets)
	clear(scratch.coalescedPackets)
	scratch.dataPackets = scratch.dataPackets[:0]
	scratch.localPackets = scratch.localPackets[:0]
	scratch.batchPackets = scratch.batchPackets[:0]
	scratch.coalescedPackets = scratch.coalescedPackets[:0]
	scratch.coalesceArena = scratch.coalesceArena[:0]
	scratch.disableRXGSOCoalesce = false
	scratch.rxGSOCoalesceReady = false
	scratch.rxGSOCoalesceEnabled = false
	scratch.rxGSOCoalesceMaxBytes = 0
	scratch.rxGSOCoalesceMaxPkts = 0
	scratch.rxGSOCoalesceMultiFlow = false
	scratch.rxGSOChecksumMTU = 0
	scratch.rxGSOScatterEnabled = false
	scratch.rxGSOScatterMTU = 0
}

func (scratch *dataReceiveScratch) prepareRXGSOCoalesceConfig(disabled bool) {
	scratch.disableRXGSOCoalesce = disabled
	scratch.rxGSOCoalesceReady = true
	if disabled {
		scratch.rxGSOCoalesceEnabled = false
		scratch.rxGSOCoalesceMaxBytes = 0
		scratch.rxGSOCoalesceMaxPkts = 0
		return
	}
	scratch.rxGSOCoalesceEnabled = dataSessionRXGSOCoalesceEnabled()
	scratch.rxGSOCoalesceMaxBytes = dataSessionRXGSOCoalesceMaxBytes()
	scratch.rxGSOCoalesceMaxPkts = dataSessionRXGSOCoalesceMaxPackets()
	scratch.rxGSOCoalesceMultiFlow = dataSessionRXGSOCoalesceMultiFlowEnabled()
	scratch.rxGSOChecksumMTU = 0
	scratch.rxGSOScatterEnabled = dataSessionRXGSOScatterEnabled()
	scratch.rxGSOScatterMTU = 0
}

func (daemon *Daemon) startDataPath(ctx context.Context) (<-chan error, error) {
	errc := make(chan error, 1)
	if err := daemon.startTransportListeners(ctx); err != nil {
		daemon.closeDataPath()
		return nil, err
	}
	if err := daemon.startKernelDatapathRXStage(ctx, dataplaneAttachSpec(daemon.cfg.DataDir, daemon.desired)); err != nil {
		daemon.closeDataPath()
		return nil, err
	}
	go daemon.runKernelDatapathStateSync(ctx)
	if !daemon.captureForwarderSuppressed() {
		if err := daemon.startCaptureForwarder(ctx); err != nil {
			daemon.closeDataPath()
			daemon.closeCaptureForwarder()
			return nil, err
		}
	}
	daemon.dataMu.Lock()
	daemon.dataPathStarted = true
	daemon.dataMu.Unlock()
	daemon.syncKernelDatapathState(ctx, daemon.runtimeDataplaneSnapshot())
	daemon.scheduleRuntimeRouteWarmup(ctx)
	return errc, nil
}

func (daemon *Daemon) scheduleRuntimeRouteWarmup(ctx context.Context) {
	if !daemon.dataPathIsStarted() {
		return
	}
	warmCtx := daemon.listenerContext(ctx)
	if daemon.kernelDirectWarmupEnabled() {
		go daemon.runKernelDirectRouteWarmup(warmCtx)
		return
	}
	if daemon.sessionPoolWarmupEnabled() {
		daemon.cancelRouteSessionWarmups()
		go daemon.runRouteSessionWarmup(warmCtx)
	}
}

func (daemon *Daemon) startTransportListeners(ctx context.Context) error {
	tunnelListeners, err := daemon.desiredKernelTunnelListenerEndpoints()
	if err != nil {
		return err
	}
	for _, cfgEndpoint := range daemon.desired.Endpoints {
		if !cfgEndpoint.Enabled || cfgEndpoint.Mode != config.EndpointModePassive {
			continue
		}
		if transportProtocolIsKernelTunnel(cfgEndpoint.Transport) {
			continue
		}
		if err := daemon.startTransportListenerEndpoint(ctx, cfgEndpoint); err != nil {
			return err
		}
	}
	keys := make([]string, 0, len(tunnelListeners))
	for key := range tunnelListeners {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err := daemon.startTransportListenerEndpoint(ctx, tunnelListeners[key]); err != nil {
			return err
		}
	}
	return nil
}

func (daemon *Daemon) startTransportListenerEndpoint(ctx context.Context, cfgEndpoint config.EndpointConfig) error {
	tlsConf, err := daemon.dataTransportServerTLSConfig(cfgEndpoint)
	if err != nil {
		return err
	}
	endpoint := transportEndpointFromConfig(cfgEndpoint)
	tr, ok := daemon.transports.Get(endpoint.Transport)
	if !ok {
		daemon.dataStats.unsupportedTransport.Add(1)
		return nil
	}
	listener, err := tr.Listen(ctx, endpoint, tlsConf)
	if err != nil {
		if daemon.dataListenerErrorCanDegrade(cfgEndpoint, err) {
			statusEndpoint := cfgEndpoint
			if statusEndpoint.Address == "" {
				statusEndpoint.Address = statusEndpoint.Listen
			}
			daemon.recordEndpointDown(daemon.desired.IX.ID, statusEndpoint, fmt.Errorf("listen data endpoint %q: %w", endpoint.Name, err))
			return nil
		}
		return fmt.Errorf("listen data endpoint %q: %w", endpoint.Name, err)
	}
	listenerCtx, cancel := context.WithCancel(ctx)
	daemon.dataMu.Lock()
	daemon.dataListeners = append(daemon.dataListeners, dataListenerRuntime{
		Endpoint: endpoint,
		Listener: listener,
		Cancel:   cancel,
	})
	daemon.dataMu.Unlock()
	go daemon.acceptDataPathSessions(listenerCtx, endpoint, listener)
	return nil
}

func (daemon *Daemon) dataListenerErrorCanDegrade(endpoint config.EndpointConfig, err error) bool {
	if err == nil || daemon.kernelTransportMode() == dataplane.KernelTransportModeRequireKernel {
		return false
	}
	switch transport.Protocol(endpoint.Transport) {
	case transport.ProtocolExperimentalTCP:
	default:
		return false
	}
	message := err.Error()
	for _, marker := range []string{
		"TC/XDP reinject is unavailable",
		"dataplane provider is unavailable",
		"requires kernel transport",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func (daemon *Daemon) peerConfigsForTunnelListeners() []config.PeerConfig {
	return daemon.peerConfigsSnapshot()
}

func kernelTunnelConfigComplete(raw string) bool {
	values, err := parseTunnelEndpointValues(raw)
	if err != nil {
		return false
	}
	for _, key := range []string{"local", "remote", "local_carrier", "remote_carrier"} {
		if strings.TrimSpace(values[key]) == "" {
			return false
		}
	}
	return true
}

func kernelTunnelConfigKey(protocol transport.Protocol, raw string) string {
	if key, ok := normalizedKernelTunnelConfigKey(protocol, raw); ok {
		return key
	}
	return string(protocol) + "\x00" + strings.TrimSpace(raw)
}

func (daemon *Daemon) startCaptureForwarder(ctx context.Context) error {
	subscriber, ok := daemon.dataplane.(dataplane.CaptureSubscriber)
	if !ok {
		daemon.dataStats.captureUnavailable.Add(1)
		return nil
	}
	captureCtx, cancel := context.WithCancel(ctx)
	subscription, err := subscriber.SubscribeCapture(captureCtx, captureForwarderBufferSize())
	if err != nil {
		cancel()
		return fmt.Errorf("subscribe dataplane capture: %w", err)
	}
	daemon.dataMu.Lock()
	if daemon.captureSub != nil {
		daemon.dataMu.Unlock()
		cancel()
		_ = subscription.Close()
		return fmt.Errorf("dataplane capture forwarder is already running")
	}
	daemon.captureCancel = cancel
	daemon.captureSub = subscription
	daemon.dataMu.Unlock()
	go daemon.forwardCapturedPackets(captureCtx, subscription)
	return nil
}

func (daemon *Daemon) captureForwarderSuppressed() bool {
	return daemon.kernelUDPTCOnlyProviderRequested() && !daemon.transportPolicyUsesExperimentalTCP() ||
		daemon.transportPolicyUsesNativePlaintextKernelTunnelRouteOffload() ||
		kernelDatapathFullPlaintextEnabledForDesired(daemon.desired)
}

func (daemon *Daemon) captureForwarderSuppressedReason() string {
	if !daemon.captureForwarderSuppressed() {
		return ""
	}
	if kernelDatapathFullPlaintextEnabledForDesired(daemon.desired) {
		return "full plaintext kernel datapath owns LAN RX/TX; userspace capture fallback is disabled"
	}
	return "kernel direct-only routes are fail-closed in TC/XDP; userspace capture fallback is disabled"
}

func (daemon *Daemon) kernelDirectWarmupEnabled() bool {
	return (daemon.kernelUDPDirectOnlyEnabled() ||
		kernelUDPSecureFullDirectForDesired(daemon.desired) ||
		kernelDatapathFullPlaintextEnabledForDesired(daemon.desired)) &&
		daemon.transportPolicyUsesKernelDirect() &&
		daemon.kernelTransportMode() != dataplane.KernelTransportModeDisabled
}

func (daemon *Daemon) kernelPlaintextDirectWarmupEnabled() bool {
	return daemon.kernelDirectWarmupEnabled()
}

func (daemon *Daemon) runKernelDirectWarmup(ctx context.Context) {
	deadline := time.Now().Add(kernelUDPPlaintextWarmupTimeout())
	retryDelay := kernelUDPPlaintextWarmupRetryDelay()
	for {
		if err := daemon.warmKernelDirectSessions(ctx); err == nil {
			return
		}
		if !time.Now().Before(deadline) {
			return
		}
		timer := time.NewTimer(retryDelay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}

func (daemon *Daemon) runKernelPlaintextDirectWarmup(ctx context.Context) {
	daemon.runKernelDirectWarmup(ctx)
}

func (daemon *Daemon) runRouteSessionWarmup(ctx context.Context) {
	warmupEpoch := daemon.nextRouteWarmupEpoch()
	deadline := time.Now().Add(dataSessionPoolWarmupDeadline())
	retryDelay := dataSessionPoolWarmupRetryDelay()
	for {
		if err := daemon.warmRouteSessionsForEpoch(ctx, warmupEpoch); err == nil {
			return
		}
		if !daemon.routeWarmupEpochActive(warmupEpoch) {
			return
		}
		if !time.Now().Before(deadline) {
			return
		}
		timer := time.NewTimer(retryDelay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}

func (daemon *Daemon) nextRouteWarmupEpoch() uint64 {
	return daemon.routeWarmupEpoch.Add(1)
}

func (daemon *Daemon) routeWarmupEpochActive(epoch uint64) bool {
	return daemon.routeWarmupEpoch.Load() == epoch
}

func (daemon *Daemon) cancelRouteSessionWarmups() {
	daemon.routeWarmupEpoch.Add(1)
}

func (daemon *Daemon) warmRouteSessions(ctx context.Context) error {
	return daemon.warmRouteSessionsForEpoch(ctx, 0)
}

func (daemon *Daemon) warmRouteSessionsForEpoch(ctx context.Context, warmupEpoch uint64) error {
	if !daemon.sessionPoolWarmupEnabled() {
		return nil
	}
	epoch := daemon.currentDataSessionEpoch()
	routes := daemon.runtimeRoutes()
	if len(routes) == 0 {
		routes = routesFromConfig(daemon.desired)
	}
	poolSize := daemon.sessionPoolSize()
	warmedRoutes := 0
	var lastErr error
	for _, route := range routes {
		if warmupEpoch != 0 && !daemon.routeWarmupEpochActive(warmupEpoch) {
			return errDataSessionEpochChanged
		}
		if route.NextHop == "" || route.Kind != "" && route.Kind != routing.RouteUnicast {
			continue
		}
		peer, ok := daemon.peerConfig(route.NextHop)
		if !ok {
			lastErr = fmt.Errorf("warm route %q: peer %q is not configured", route.Prefix, route.NextHop)
			continue
		}
		candidates, _, err := daemon.candidatePeerEndpoints(peer, route, routing.FlowKey{}, false)
		if err != nil {
			lastErr = fmt.Errorf("warm route %q: %w", route.Prefix, err)
			continue
		}
		if warmupEpoch != 0 && !daemon.routeWarmupEpochActive(warmupEpoch) {
			return errDataSessionEpochChanged
		}
		warmed, err := daemon.warmAnyEndpointSessionPool(ctx, epoch, peer, candidates, poolSize)
		if warmed {
			warmedRoutes++
			continue
		}
		if err != nil {
			lastErr = fmt.Errorf("warm route %q: %w", route.Prefix, err)
			continue
		}
		if !daemon.dataSessionEpochActive(epoch) {
			lastErr = errDataSessionEpochChanged
			continue
		}
	}
	if warmedRoutes > 0 || lastErr == nil {
		return nil
	}
	return lastErr
}

func (daemon *Daemon) warmEndpointSessionPool(ctx context.Context, epoch uint64, peer config.PeerConfig, cfgEndpoint config.EndpointConfig, poolSize int) bool {
	warmed, _ := daemon.warmEndpointSessionPoolResult(ctx, epoch, peer, cfgEndpoint, poolSize)
	return warmed
}

func (daemon *Daemon) warmEndpointSessionPoolResult(ctx context.Context, epoch uint64, peer config.PeerConfig, cfgEndpoint config.EndpointConfig, poolSize int) (bool, error) {
	endpoint := transportEndpointFromConfig(cfgEndpoint)
	endpoint.Enabled = true
	endpoint.Encryption = daemon.endpointDialEncryption(cfgEndpoint)
	if poolSize <= 1 {
		_, _, _, err := daemon.sessionForEndpointWithOptions(ctx, peer, cfgEndpoint, routing.FlowKey{}, false, sessionForEndpointOptions{
			AllowDial:                 true,
			SuppressCanceledDialError: true,
			RequireEpoch:              true,
			ExpectedEpoch:             epoch,
		})
		return err == nil, err
	}
	warmed := false
	var lastErr error
	for _, poolIndex := range daemon.missingSessionPoolIndexes(peer.ID, cfgEndpoint, endpoint.Encryption, poolSize) {
		if !daemon.dataSessionEpochActive(epoch) {
			return warmed, errDataSessionEpochChanged
		}
		if _, _, err := daemon.sessionForEndpointPoolIndexWithOptions(ctx, epoch, peer, cfgEndpoint, endpoint, poolIndex, sessionForEndpointOptions{
			AllowDial:                 true,
			SuppressCanceledDialError: true,
			RequireEpoch:              true,
			ExpectedEpoch:             epoch,
		}); err == nil {
			warmed = true
		} else {
			lastErr = err
		}
	}
	if len(daemon.missingSessionPoolIndexes(peer.ID, cfgEndpoint, endpoint.Encryption, poolSize)) == 0 {
		warmed = true
	}
	if warmed {
		return true, nil
	}
	return false, lastErr
}

func (daemon *Daemon) warmAnyEndpointSessionPool(ctx context.Context, epoch uint64, peer config.PeerConfig, candidates []config.EndpointConfig, poolSize int) (bool, error) {
	if len(candidates) == 0 {
		return false, nil
	}
	if len(candidates) == 1 {
		return daemon.warmEndpointSessionPoolResult(ctx, epoch, peer, candidates[0], poolSize)
	}
	warmCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		warmed bool
		err    error
	}
	results := make(chan result, len(candidates))
	for _, endpoint := range candidates {
		endpoint := endpoint
		go func() {
			warmed, err := daemon.warmEndpointSessionPoolResult(warmCtx, epoch, peer, endpoint, poolSize)
			results <- result{warmed: warmed, err: err}
		}()
	}
	var lastErr error
	for range candidates {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case result := <-results:
			if result.warmed {
				cancel()
				return true, nil
			}
			if result.err != nil {
				lastErr = result.err
			}
		}
	}
	return false, lastErr
}

func (daemon *Daemon) warmKernelDirectEndpointSessionPool(ctx context.Context, epoch uint64, peer config.PeerConfig, cfgEndpoint config.EndpointConfig, poolSize int) (bool, error) {
	endpoint := transportEndpointFromConfig(cfgEndpoint)
	endpoint.Enabled = true
	endpoint.Encryption = daemon.endpointDialEncryption(cfgEndpoint)
	options := sessionForEndpointOptions{
		AllowDial:         true,
		ControlOnlyWarmup: daemon.kernelDirectWarmupControlOnlyEndpoint(cfgEndpoint),
		RequireEpoch:      true,
		ExpectedEpoch:     epoch,
	}
	if poolSize <= 1 {
		_, _, _, err := daemon.sessionForEndpointWithOptions(ctx, peer, cfgEndpoint, routing.FlowKey{}, false, options)
		return err == nil, err
	}
	missing := daemon.missingSessionPoolIndexes(peer.ID, cfgEndpoint, endpoint.Encryption, poolSize)
	if len(missing) == 0 {
		return true, nil
	}
	var lastErr error
	for _, poolIndex := range missing {
		if !daemon.dataSessionEpochActive(epoch) {
			return false, errDataSessionEpochChanged
		}
		if _, _, err := daemon.sessionForEndpointPoolIndexWithOptions(ctx, epoch, peer, cfgEndpoint, endpoint, poolIndex, options); err != nil {
			lastErr = err
			continue
		}
	}
	if missing = daemon.missingSessionPoolIndexes(peer.ID, cfgEndpoint, endpoint.Encryption, poolSize); len(missing) == 0 {
		return true, nil
	}
	if lastErr != nil {
		return false, lastErr
	}
	return false, fmt.Errorf("kernel direct endpoint %q pool incomplete; missing indexes %v", cfgEndpoint.Name, missing)
}

func (daemon *Daemon) warmKernelDirectSessions(ctx context.Context) error {
	if !daemon.kernelDirectWarmupEnabled() {
		return nil
	}
	routes := routesFromConfig(daemon.desired)
	deadline := time.Now().Add(kernelUDPPlaintextWarmupTimeout())
	retryDelay := kernelUDPPlaintextWarmupRetryDelay()
	warmedRoutes := 0
	for _, route := range routes {
		if route.NextHop == "" || route.Kind != "" && route.Kind != routing.RouteUnicast {
			continue
		}
		peer, ok := daemon.peerConfig(route.NextHop)
		if !ok {
			return fmt.Errorf("warm kernel direct route %q: peer %q is not configured", route.Prefix, route.NextHop)
		}
		candidates, _, err := daemon.candidatePeerEndpoints(peer, route, routing.FlowKey{}, false)
		if err != nil {
			return fmt.Errorf("warm kernel direct route %q: %w", route.Prefix, err)
		}
		for {
			warmed := false
			var lastErr error
			epoch := daemon.currentDataSessionEpoch()
			poolSize := daemon.sessionPoolSize()
			for _, endpoint := range candidates {
				if !daemon.kernelDirectWarmupEndpoint(endpoint) {
					continue
				}
				if ok, err := daemon.warmKernelDirectEndpointSessionPool(ctx, epoch, peer, endpoint, poolSize); err != nil {
					lastErr = err
					continue
				} else if !ok {
					continue
				}
				warmed = true
				break
			}
			if warmed {
				warmedRoutes++
				break
			}
			if lastErr == nil {
				return fmt.Errorf("warm kernel direct route %q: no kernel endpoint candidate", route.Prefix)
			}
			if !errors.Is(lastErr, errDataSessionEpochChanged) {
				return fmt.Errorf("warm kernel direct route %q: %w", route.Prefix, lastErr)
			}
			if !time.Now().Before(deadline) {
				return fmt.Errorf("warm kernel direct route %q: %w", route.Prefix, lastErr)
			}
			timer := time.NewTimer(retryDelay)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	if warmedRoutes == 0 {
		return fmt.Errorf("warm kernel direct routes: no unicast route installed a kernel direct session")
	}
	return nil
}

func (daemon *Daemon) warmKernelPlaintextDirectSessions(ctx context.Context) error {
	return daemon.warmKernelDirectSessions(ctx)
}

func (daemon *Daemon) warmKernelUDPPlaintextSessions(ctx context.Context) error {
	return daemon.warmKernelDirectSessions(ctx)
}

func (daemon *Daemon) warmKernelUDPRouteSessions(ctx context.Context) error {
	return daemon.warmKernelDirectRouteSessions(ctx)
}

func (daemon *Daemon) runKernelDirectRouteWarmup(ctx context.Context) {
	deadline := time.Now().Add(kernelUDPPlaintextWarmupTimeout())
	retryDelay := kernelUDPPlaintextWarmupRetryDelay()
	for {
		warmed, err := daemon.warmKernelDirectRouteSessionsResult(ctx)
		if warmed || err == nil && !time.Now().Before(deadline) {
			return
		}
		if !time.Now().Before(deadline) {
			return
		}
		timer := time.NewTimer(retryDelay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}

func (daemon *Daemon) warmKernelDirectRouteSessions(ctx context.Context) error {
	_, _ = daemon.warmKernelDirectRouteSessionsResult(ctx)
	return nil
}

func (daemon *Daemon) warmKernelDirectRouteSessionsResult(ctx context.Context) (bool, error) {
	if daemon.kernelTransportMode() == dataplane.KernelTransportModeDisabled {
		return false, nil
	}
	if _, hasUDP := daemon.dataplane.(dataplane.KernelUDPProvider); !hasUDP {
		if _, hasExperimentalTCP := daemon.dataplane.(dataplane.ExperimentalTCPProvider); !hasExperimentalTCP {
			return false, nil
		}
	}
	if !daemon.transportPolicyUsesKernelDirect() {
		return false, nil
	}
	epoch := daemon.currentDataSessionEpoch()
	poolSize := daemon.sessionPoolSize()
	routes := daemon.runtimeRoutes()
	if len(routes) == 0 {
		routes = routesFromConfig(daemon.desired)
	}
	warmedRoutes := 0
	var lastErr error
	for _, route := range routes {
		if route.NextHop == "" || route.Kind != "" && route.Kind != routing.RouteUnicast {
			continue
		}
		peer, ok := daemon.peerConfig(route.NextHop)
		if !ok {
			lastErr = fmt.Errorf("peer %q is not configured", route.NextHop)
			continue
		}
		candidates, _, err := daemon.candidatePeerEndpoints(peer, route, routing.FlowKey{}, false)
		if err != nil {
			lastErr = err
			continue
		}
		for _, endpoint := range candidates {
			if !daemon.kernelDirectWarmupEndpoint(endpoint) {
				continue
			}
			if ok, err := daemon.warmKernelDirectEndpointSessionPool(ctx, epoch, peer, endpoint, poolSize); err == nil && ok {
				warmedRoutes++
				break
			} else if err != nil {
				lastErr = err
			}
		}
	}
	if warmedRoutes > 0 {
		return true, nil
	}
	return false, lastErr
}

func (daemon *Daemon) kernelUDPPlaintextDirectOnlyEnabled() bool {
	return daemon.kernelUDPDirectOnlyEnabled()
}

func (daemon *Daemon) kernelUDPDirectOnlyEnabled() bool {
	if experimentalTCPPerformanceRouteGSOAsyncForDesired(daemon.desired) ||
		kernelUDPPlaintextPerformanceDirectOnlyForDesired(daemon.desired) {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY")), "0") ||
		strings.EqualFold(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY")), "false") ||
		strings.EqualFold(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY")), "off") ||
		strings.EqualFold(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY")), "disabled") {
		return false
	}
	return kernelUDPTXDirectOnlyForDesired(daemon.desired)
}

func (daemon *Daemon) kernelUDPTCOnlyProviderRequested() bool {
	return kernelUDPTCOnlyProviderForDesired(daemon.desired)
}

func envTruthyAny(names ...string) bool {
	for _, name := range names {
		switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
		case "1", "true", "yes", "on", "enabled":
			return true
		}
	}
	return false
}

func (daemon *Daemon) kernelUDPPlaintextWarmupEndpoint(endpoint config.EndpointConfig) bool {
	return daemon.kernelDirectWarmupEndpoint(endpoint) &&
		transport.Protocol(endpoint.Transport) == transport.ProtocolUDP
}

func (daemon *Daemon) kernelPlaintextDirectWarmupEndpoint(endpoint config.EndpointConfig) bool {
	return daemon.kernelDirectWarmupEndpoint(endpoint)
}

func (daemon *Daemon) kernelDirectWarmupEndpoint(endpoint config.EndpointConfig) bool {
	if !daemon.kernelDirectOnlyEndpointEncryption(daemon.endpointDialEncryption(endpoint)) {
		return false
	}
	if strings.TrimSpace(endpoint.Address) == "" ||
		!daemon.endpointKernelTransportCompatible(endpoint.Transport) ||
		!daemon.endpointSecurityCompatible(endpoint) ||
		!daemon.endpointTransportProfileCompatible(endpoint) {
		return false
	}
	switch transport.Protocol(endpoint.Transport) {
	case transport.ProtocolUDP:
		_, ok := daemon.dataplane.(dataplane.KernelUDPProvider)
		return ok
	case transport.ProtocolExperimentalTCP:
		_, ok := daemon.dataplane.(dataplane.ExperimentalTCPProvider)
		return ok
	default:
		return false
	}
}

func (daemon *Daemon) kernelDirectWarmupControlOnlyEndpoint(endpoint config.EndpointConfig) bool {
	if kernelDatapathFullPlaintextEnabledForDesired(daemon.desired) {
		return false
	}
	return transport.Protocol(endpoint.Transport) == transport.ProtocolUDP ||
		transport.Protocol(endpoint.Transport) == transport.ProtocolExperimentalTCP && !experimentalTCPTXDirectRequestedForPolicy()
}

func (daemon *Daemon) kernelDirectOnlyEndpointEncryption(encryption string) bool {
	switch parseSecureTransportEncryption(encryption) {
	case securetransport.EncryptionPlaintext:
		return true
	case securetransport.EncryptionSecure:
		return parseSecureTransportEncryption(daemon.desired.TransportPolicy.Encryption) == securetransport.EncryptionSecure &&
			desiredTransportPolicyAllowsKernelCryptoDirectOnly(daemon.desired) &&
			(desiredTransportPolicyAllowsSecureDirectOnly(daemon.desired) ||
				kernelUDPSecureFullDirectForDesired(daemon.desired))
	default:
		return false
	}
}

func (daemon *Daemon) kernelUDPWarmupEndpoint(endpoint config.EndpointConfig) bool {
	return transport.Protocol(endpoint.Transport) == transport.ProtocolUDP &&
		strings.TrimSpace(endpoint.Address) != "" &&
		daemon.endpointKernelTransportCompatible(endpoint.Transport) &&
		daemon.endpointSecurityCompatible(endpoint) &&
		daemon.endpointTransportProfileCompatible(endpoint)
}

func (daemon *Daemon) waitKernelUDPPlaintextDirectReady(ctx context.Context) error {
	deadline := time.Now().Add(kernelUDPPlaintextWarmupTimeout())
	retryDelay := kernelUDPPlaintextWarmupRetryDelay()
	for {
		ok, err := daemon.kernelUDPPlaintextDirectReady(ctx)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("kernel_udp plaintext direct-only routes did not become ready before timeout")
		}
		timer := time.NewTimer(retryDelay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (daemon *Daemon) kernelUDPPlaintextDirectReady(ctx context.Context) (bool, error) {
	stats, err := daemon.dataplane.Stats(ctx)
	if err != nil {
		return false, err
	}
	counters := dataplaneCountersByName(stats.Counters)
	routes := counters["tc_kernel_udp_tx_direct_routes"]
	flows := counters["tc_kernel_udp_tx_direct_flows"]
	if routes == 0 || flows == 0 {
		return false, nil
	}
	if counters["tc_kernel_udp_tx_direct_sync_neighbor_misses"] > 0 {
		return false, nil
	}
	return true, nil
}

func dataplaneCountersByName(counters []observability.Counter) map[string]uint64 {
	out := make(map[string]uint64, len(counters))
	for _, counter := range counters {
		out[counter.Name] = counter.Value
	}
	return out
}

func kernelUDPPlaintextWarmupTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_PLAINTEXT_WARMUP_TIMEOUT"))
	if raw == "" {
		return kernelUDPPlaintextWarmupDefaultTimeout
	}
	timeout, err := time.ParseDuration(raw)
	if err != nil || timeout <= 0 {
		return kernelUDPPlaintextWarmupDefaultTimeout
	}
	return timeout
}

func kernelUDPPlaintextWarmupRetryDelay() time.Duration {
	raw := strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_PLAINTEXT_WARMUP_RETRY_DELAY"))
	if raw == "" {
		return kernelUDPPlaintextWarmupDefaultRetryDelay
	}
	delay, err := time.ParseDuration(raw)
	if err != nil || delay <= 0 {
		return kernelUDPPlaintextWarmupDefaultRetryDelay
	}
	return delay
}

func captureForwarderBufferSize() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_CAPTURE_FORWARDER_BUFFER"))
	if value == "" {
		return captureForwarderDefaultBuffer
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return captureForwarderDefaultBuffer
	}
	if parsed > captureForwarderMaxBuffer {
		return captureForwarderMaxBuffer
	}
	return parsed
}

func captureForwarderWorkerCount() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_CAPTURE_FORWARDER_WORKERS"))
	if value == "" {
		return captureForwarderDefaultWorkers
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return captureForwarderDefaultWorkers
	}
	if parsed > 64 {
		return 64
	}
	return parsed
}

func captureForwarderBatchSize() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_CAPTURE_FORWARDER_BATCH"))
	if value == "" {
		return captureForwarderDefaultBatch
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return captureForwarderDefaultBatch
	}
	if parsed > captureForwarderMaxBatch {
		return captureForwarderMaxBatch
	}
	return parsed
}

func captureForwarderBatchDelay() time.Duration {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_CAPTURE_FORWARDER_BATCH_DELAY"))
	if value == "" {
		return captureForwarderDefaultBatchDelay
	}
	delay, err := time.ParseDuration(value)
	if err != nil || delay < 0 {
		return captureForwarderDefaultBatchDelay
	}
	if delay > 5*time.Millisecond {
		return 5 * time.Millisecond
	}
	return delay
}

func dataSessionReceiveBatchSize() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_DATA_SESSION_RECV_BATCH"))
	if value == "" {
		return dataSessionReceiveDefaultBatch
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return dataSessionReceiveDefaultBatch
	}
	if parsed > 1024 {
		return 1024
	}
	return parsed
}

func dataSessionBatchEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_DATA_SESSION_BATCH"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}

func dataSessionBatchMaxBytes() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_DATA_SESSION_BATCH_BYTES"))
	if value == "" {
		return dataSessionBatchDefaultBytes
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1500 {
		return dataSessionBatchDefaultBytes
	}
	return clampDataSessionBatchBytes(parsed)
}

func dataSessionBatchDelay() time.Duration {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_DATA_SESSION_BATCH_DELAY"))
	if value == "" {
		return dataSessionBatchDefaultDelay
	}
	delay, err := time.ParseDuration(value)
	if err != nil || delay < 0 {
		return dataSessionBatchDefaultDelay
	}
	return clampDataSessionBatchDelay(delay)
}

func dataSessionSegmentFragmentingDatagramEnabled() bool {
	return envTruthyAny(
		"TRUSTIX_DATA_SESSION_SEGMENT_FRAGMENTING_DATAGRAM",
		"TRUSTIX_DATA_SESSION_SOFTWARE_SEGMENT_FRAGMENTING_DATAGRAM",
	)
}

func dataSessionBatchConfigFromEnv() dataSessionBatchConfig {
	return dataSessionBatchConfig{
		enabled:    dataSessionBatchEnabled(),
		maxBytes:   dataSessionBatchMaxBytes(),
		maxPackets: dataSessionBatchMaxPackets,
		delay:      dataSessionBatchDelay(),
		ready:      true,
	}
}

func (daemon *Daemon) dataSessionBatchConfigForEndpoint(endpoint config.EndpointConfig) dataSessionBatchConfig {
	batching := dataSessionBatchConfigFromEnv()
	if daemon == nil {
		return batching
	}
	profile := config.EffectiveTransportProfile(daemon.desired.TransportPolicy, endpoint.Transport)
	return dataSessionBatchConfigWithAdvanced(batching, profile.Advanced)
}

func dataSessionBatchConfigWithAdvanced(batching dataSessionBatchConfig, advanced config.TransportAdvancedConfig) dataSessionBatchConfig {
	if advanced.BatchBytes > 0 {
		batching.maxBytes = clampDataSessionBatchBytes(advanced.BatchBytes)
	}
	if advanced.MaxFrames > 0 {
		batching.maxPackets = advanced.MaxFrames
		if batching.maxPackets > dataSessionBatchMaxPackets {
			batching.maxPackets = dataSessionBatchMaxPackets
		}
	}
	if strings.TrimSpace(advanced.FlushDelay) != "" {
		if delay, err := time.ParseDuration(strings.TrimSpace(advanced.FlushDelay)); err == nil {
			batching.delay = clampDataSessionBatchDelay(delay)
		}
	}
	if batching.maxPackets <= 0 {
		batching.maxPackets = dataSessionBatchMaxPackets
	}
	return batching
}

func clampDataSessionBatchBytes(value int) int {
	if value > 512*1024 {
		return 512 * 1024
	}
	return value
}

func clampDataSessionBatchDelay(delay time.Duration) time.Duration {
	if delay < 0 {
		return dataSessionBatchDefaultDelay
	}
	if delay > 5*time.Millisecond {
		return 5 * time.Millisecond
	}
	return delay
}

func dataSessionKernelCryptoBatchBytes() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_DATA_SESSION_KERNEL_CRYPTO_BATCH_BYTES"))
	if value == "" {
		return dataSessionKernelCryptoBatchDefaultBytes
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1500 {
		return dataSessionKernelCryptoBatchDefaultBytes
	}
	if parsed > dataSessionKernelCryptoBatchMaxBytes {
		return dataSessionKernelCryptoBatchMaxBytes
	}
	return parsed
}

func dataSessionUserspaceEncryptedBatchBytes() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_DATA_SESSION_USERSPACE_ENCRYPTED_BATCH_BYTES"))
	if value == "" {
		return dataSessionUserspaceEncryptedBatchDefaultBytes
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1500 {
		return dataSessionUserspaceEncryptedBatchDefaultBytes
	}
	if parsed > dataSessionUserspaceEncryptedBatchMaxBytes {
		return dataSessionUserspaceEncryptedBatchMaxBytes
	}
	return parsed
}

func dataSessionEncryptedBatchAggregationEnabled() bool {
	enabled, _ := dataSessionBoolEnv("TRUSTIX_DATA_SESSION_ENCRYPTED_TIXB")
	return enabled
}

func dataSessionPlaintextBatchAggregationEnabled() bool {
	enabled, _ := dataSessionBoolEnv("TRUSTIX_DATA_SESSION_PLAINTEXT_TIXB")
	return enabled
}

func dataSessionBoolEnv(name string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on", "enabled":
		return true, true
	case "0", "false", "no", "off", "disabled":
		return false, true
	default:
		return false, false
	}
}

func dataSessionExperimentalTCPBatchAggregationEnabled() (bool, bool) {
	return dataSessionBoolEnv("TRUSTIX_DATA_SESSION_EXPERIMENTAL_TCP_TIXB")
}

func dataSessionPlaintextBatchAggregationPreference() (bool, bool) {
	return dataSessionBoolEnv("TRUSTIX_DATA_SESSION_PLAINTEXT_TIXB")
}

func dataSessionEncryptedBatchAggregationPreference() (bool, bool) {
	return dataSessionBoolEnv("TRUSTIX_DATA_SESSION_ENCRYPTED_TIXB")
}

func dataSessionKernelCryptoNativeBatchingPreference() (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_DATA_SESSION_KERNEL_CRYPTO_NATIVE_BATCH"))) {
	case "1", "true", "yes", "on", "enabled":
		return true, true
	case "0", "false", "no", "off", "disabled":
		return false, true
	}
	if strings.TrimSpace(os.Getenv("TRUSTIX_DATA_SESSION_ENCRYPTED_TIXB")) != "" {
		return !dataSessionEncryptedBatchAggregationEnabled(), true
	}
	return true, false
}

func (daemon *Daemon) acceptDataPathSessions(ctx context.Context, endpoint transport.Endpoint, listener transport.Listener) {
	for {
		session, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if errors.Is(err, securetransport.ErrSessionResetSent) {
				daemon.dataStats.sessionResetsSent.Add(1)
			}
			daemon.dataStats.listenerAcceptErrors.Add(1)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		daemon.recordDataSessionTLSObservation(session)
		if _, err := daemon.registerInboundDataSession(ctx, endpoint, session); err != nil {
			_ = session.Close()
		}

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func (daemon *Daemon) registerInboundDataSession(ctx context.Context, listenerEndpoint transport.Endpoint, session transport.Session) (*dataSessionRuntime, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	identity, ok := session.(transport.PeerIdentitySession)
	if !ok {
		return nil, fmt.Errorf("inbound data session on endpoint %q does not expose peer identity", listenerEndpoint.Name)
	}
	if detailSession, ok := session.(transport.PeerIdentityDetailSession); ok {
		if detail, ok := detailSession.PeerIdentityDetail(); ok && detail.Role == string(pki.RoleDevice) {
			return daemon.registerInboundDeviceSession(ctx, listenerEndpoint, session, detail)
		}
	}
	peerID, domainID, ok := identity.PeerIdentity()
	if !ok || peerID == "" {
		return nil, fmt.Errorf("inbound data session on endpoint %q has no peer identity", listenerEndpoint.Name)
	}
	if peerID == daemon.desired.IX.ID {
		return nil, fmt.Errorf("inbound data session on endpoint %q is from local ix %q", listenerEndpoint.Name, peerID)
	}
	if daemon.desired.Domain.ID != "" && domainID != "" && domainID != daemon.desired.Domain.ID {
		return nil, fmt.Errorf("inbound data session peer %q domain is %q, want %q", peerID, domainID, daemon.desired.Domain.ID)
	}
	peer, ok := daemon.peerConfig(peerID)
	if !ok {
		return nil, fmt.Errorf("inbound data session peer %q is not configured", peerID)
	}
	if peer.Domain != "" && domainID != "" && peer.Domain != domainID {
		return nil, fmt.Errorf("inbound data session peer %q domain is %q, want %q", peerID, domainID, peer.Domain)
	}
	if localEndpoint, ok := daemon.localDataEndpointConfig(listenerEndpoint); ok {
		if err := requireEndpointLinkTLS(peer.ID, localEndpoint, session); err != nil {
			return nil, err
		}
		if !daemon.endpointAccessAllowsPeer(peer.ID, localEndpoint) {
			return nil, fmt.Errorf("inbound data session peer %q is not authorized for local endpoint %q", peer.ID, localEndpoint.Name)
		}
	}
	endpoint, ok := daemon.inboundDataEndpointForPeer(peer, listenerEndpoint)
	if !ok {
		return nil, fmt.Errorf("inbound data session peer %q has no compatible %q endpoint", peerID, listenerEndpoint.Transport)
	}
	if err := requireEndpointLinkTLS(peer.ID, endpoint, session); err != nil {
		return nil, err
	}
	endpoint.Transport = string(listenerEndpoint.Transport)
	encryption := daemon.endpointDialEncryption(endpoint)
	if annotator, ok := session.(transport.PeerEndpointAnnotator); ok {
		annotator.SetPeerEndpoint(peer.ID, endpoint.Name)
	}

	daemon.dataMu.Lock()
	if daemon.dataSessions == nil {
		daemon.dataSessions = make(map[dataSessionKey]transport.Session)
	}
	key := daemon.allocateReverseDataSessionKeyLocked(peer.ID, endpoint, encryption)
	existing := daemon.dataSessions[key]
	if existing == session {
		runtime := daemon.dataSessionState[key]
		daemon.dataMu.Unlock()
		if runtime == nil {
			return nil, fmt.Errorf("inbound data session peer %q endpoint %q is already registered without runtime", peer.ID, endpoint.Name)
		}
		return runtime, nil
	}
	existingRuntime := daemon.dataSessionState[key]
	if existing != nil && existingRuntime != nil && daemon.shouldKeepExistingKernelUDPReverseSessionLocked(key, session) {
		daemon.dataMu.Unlock()
		_ = session.Close()
		return existingRuntime, nil
	}
	if existingRuntime != nil && existingRuntime.cancel != nil {
		existingRuntime.cancel()
	}
	daemon.dataSessions[key] = session
	runtime := daemon.startDataSessionRuntimeLocked(key, session, peer, endpoint)
	if daemon.preferReverseSessionForAddressedKernelUDPSecure(endpoint, encryption) {
		daemon.clearForwardCacheForOutboundEndpointLocked(peer.ID, endpoint, encryption)
	}
	var dropped []droppedDataSession
	if daemon.shouldDropOutboundDataSessionsForInbound(endpoint) {
		dropped = daemon.dropOutboundDataSessionsForInboundLocked(peer.ID, endpoint, encryption, key)
	}
	daemon.dataMu.Unlock()
	if existing != nil {
		daemon.dataStats.staleSessionsDropped.Add(1)
		_ = existing.Close()
	}
	daemon.syncKernelDatapathSessionUpsert(key, runtime, session)
	daemon.closeDroppedDataSessions(dropped)
	daemon.recordEndpointUp(peer.ID, endpoint, 0)
	return runtime, nil
}

func (daemon *Daemon) registerInboundDeviceSession(ctx context.Context, listenerEndpoint transport.Endpoint, session transport.Session, identity transport.PeerIdentity) (*dataSessionRuntime, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !daemon.deviceAccessEnabled() {
		return nil, fmt.Errorf("inbound device session on endpoint %q rejected: lan device_access is disabled", listenerEndpoint.Name)
	}
	if identity.Domain != "" && daemon.desired.Domain.ID != "" && identity.Domain != daemon.desired.Domain.ID {
		return nil, fmt.Errorf("inbound device session domain is %q, want %q", identity.Domain, daemon.desired.Domain.ID)
	}
	if identity.Peer == "" || identity.Peer != daemon.desired.IX.ID {
		return nil, fmt.Errorf("inbound device session issuer ix is %q, want local ix %q", identity.Peer, daemon.desired.IX.ID)
	}
	if identity.Device == "" {
		return nil, fmt.Errorf("inbound device session on endpoint %q has no device id", listenerEndpoint.Name)
	}
	endpoint, ok := daemon.localDataEndpointConfig(listenerEndpoint)
	if !ok {
		return nil, fmt.Errorf("inbound device session endpoint %q is not a local data endpoint", listenerEndpoint.Name)
	}
	if err := requireEndpointLinkTLS(daemon.desired.IX.ID, endpoint, session); err != nil {
		return nil, err
	}
	endpoint.Transport = string(listenerEndpoint.Transport)
	encryption := daemon.endpointDialEncryption(endpoint)

	daemon.dataMu.Lock()
	if daemon.dataSessions == nil {
		daemon.dataSessions = make(map[dataSessionKey]transport.Session)
	}
	lease, expiredSessions, err := daemon.allocateDeviceAccessLease(identity)
	if err != nil {
		daemon.dataMu.Unlock()
		daemon.closeDroppedDataSessions(expiredSessions)
		return nil, err
	}
	lease.AdvertisePrefixes = daemon.deviceAccessAdvertisePrefixesForIdentity(identity, lease)
	peer := daemon.deviceAccessPeerConfig(identity, lease)
	key := reverseDataSessionKey(peer.ID, endpoint, encryption)
	existing := daemon.dataSessions[key]
	if existingRuntime := daemon.dataSessionState[key]; existingRuntime != nil && existingRuntime.cancel != nil {
		existingRuntime.cancel()
	}
	daemon.dataSessions[key] = session
	lease.SessionKey = key
	lease.Endpoint = endpoint
	daemon.storeDeviceAccessLeaseLocked(lease)
	runtime := daemon.startDataSessionRuntimeLocked(key, session, peer, endpoint)
	daemon.dataSessionEpoch++
	daemon.dataMu.Unlock()
	daemon.closeDroppedDataSessions(expiredSessions)

	if annotator, ok := session.(transport.PeerEndpointAnnotator); ok {
		annotator.SetPeerEndpoint(peer.ID, endpoint.Name)
	}
	daemon.syncKernelDatapathSessionUpsert(key, runtime, session)
	if existing != nil && existing != session {
		daemon.dataStats.staleSessionsDropped.Add(1)
		_ = existing.Close()
	}
	clientRoutes := daemon.deviceAccessClientRoutesForLease(lease)
	_ = daemon.sendDataSessionWirePacket(runtime, session, encodeDataSessionDeviceLease(lease.Address, uint32(lease.Prefix.Bits()), lease.ExpiresAt, clientRoutes))
	if err := daemon.applyRuntimeDataplaneSnapshot(ctx); err != nil {
		return runtime, err
	}
	if daemon.localAdvertisementConfigured() {
		if err := daemon.refreshLocalAdvertisement(); err != nil {
			return runtime, err
		}
	}
	daemon.recordEndpointUp(peer.ID, endpoint, 0)
	return runtime, nil
}

func (daemon *Daemon) deviceAccessEnabled() bool {
	if daemon == nil {
		return false
	}
	return len(config.DeviceAccessLANs(daemon.desired)) > 0
}

func (daemon *Daemon) localAdvertisementConfigured() bool {
	return daemon != nil &&
		strings.TrimSpace(daemon.desired.IX.CertPath) != "" &&
		strings.TrimSpace(daemon.desired.IX.KeyPath) != ""
}

func (daemon *Daemon) deviceAccessLeaseTTL(lan config.LANConfig) time.Duration {
	raw := strings.TrimSpace(lan.DeviceAccess.LeaseTTL)
	if raw == "" {
		return 24 * time.Hour
	}
	ttl, err := time.ParseDuration(raw)
	if err != nil || ttl <= 0 {
		return 24 * time.Hour
	}
	return ttl
}

func (daemon *Daemon) deviceAccessLANForIdentity(identity transport.PeerIdentity) (config.LANConfig, error) {
	lanID := strings.TrimSpace(identity.LANID)
	lans := config.DeviceAccessLANs(daemon.desired)
	if len(lans) == 0 {
		return config.LANConfig{}, fmt.Errorf("lan device_access is not enabled")
	}
	if lanID == "" {
		if len(lans) == 1 {
			return lans[0], nil
		}
		return config.LANConfig{}, fmt.Errorf("inbound device session certificate has no lan_id and multiple device_access LANs are enabled")
	}
	lan, ok := config.DeviceAccessLANByID(daemon.desired, lanID)
	if !ok {
		return config.LANConfig{}, fmt.Errorf("inbound device session certificate lan_id %q is not enabled", lanID)
	}
	return lan, nil
}

func (daemon *Daemon) allocateDeviceAccessLease(identity transport.PeerIdentity) (deviceAccessLease, []droppedDataSession, error) {
	lan, err := daemon.deviceAccessLANForIdentity(identity)
	if err != nil {
		return deviceAccessLease{}, nil, err
	}
	pool, err := netip.ParsePrefix(strings.TrimSpace(lan.DeviceAccess.AddressPool))
	if err != nil {
		return deviceAccessLease{}, nil, fmt.Errorf("parse lan device_access address_pool: %w", err)
	}
	pool = pool.Masked()
	key := deviceLeaseKey{IX: identity.Peer, Device: identity.Device}
	now := time.Now().UTC()
	expiresAt := now.Add(daemon.deviceAccessLeaseTTL(lan))
	if daemon.deviceLeases == nil {
		daemon.deviceLeases = make(map[deviceLeaseKey]deviceAccessLease)
	}
	expiredSessions := daemon.pruneExpiredDeviceLeasesLocked(now)
	if existing, ok := daemon.deviceLeases[key]; ok && (existing.LANID == "" || existing.LANID == lan.ID) && existing.Address.IsValid() && pool.Contains(existing.Address) {
		existing.LANID = lan.ID
		existing.ExpiresAt = expiresAt
		return existing, expiredSessions, nil
	}
	used := make(map[netip.Addr]struct{}, len(daemon.deviceLeases)+1)
	if gateway, ok := deviceAccessGatewayAddress(lan.Gateway); ok {
		used[gateway] = struct{}{}
	}
	for _, lease := range daemon.deviceLeases {
		if lease.Address.IsValid() && pool.Contains(lease.Address) {
			used[lease.Address] = struct{}{}
		}
	}
	addr, ok := firstFreeDeviceAccessAddress(pool, used)
	if !ok {
		return deviceAccessLease{}, expiredSessions, fmt.Errorf("lan device_access address_pool %q has no free address", pool)
	}
	return deviceAccessLease{
		Key:       key,
		LANID:     lan.ID,
		Address:   addr,
		Prefix:    netip.PrefixFrom(addr, 32),
		ExpiresAt: expiresAt,
	}, expiredSessions, nil
}

func (daemon *Daemon) deviceAccessAdvertisePrefixesForIdentity(identity transport.PeerIdentity, lease deviceAccessLease) []netip.Prefix {
	prefixes := normalizeDeviceAccessAdvertisePrefixes(identity.Prefixes)
	if len(prefixes) == 0 {
		return nil
	}
	allowed := make([]netip.Prefix, 0, len(prefixes))
	seen := map[string]struct{}{
		lease.Prefix.Masked().String(): {},
	}
	for _, prefix := range prefixes {
		prefix = prefix.Masked()
		raw := prefix.String()
		if _, exists := seen[raw]; exists {
			continue
		}
		seen[raw] = struct{}{}
		if daemon.deviceAccessAdvertisePrefixConflictsLocked(lease, prefix) {
			continue
		}
		allowed = append(allowed, prefix)
	}
	return allowed
}

func normalizeDeviceAccessAdvertisePrefixes(values []string) []netip.Prefix {
	if len(values) == 0 {
		return nil
	}
	out := make([]netip.Prefix, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() {
			continue
		}
		prefix = prefix.Masked()
		raw := prefix.String()
		if _, exists := seen[raw]; exists {
			continue
		}
		seen[raw] = struct{}{}
		out = append(out, prefix)
	}
	return out
}

func (daemon *Daemon) deviceAccessAdvertisePrefixConflictsLocked(current deviceAccessLease, prefix netip.Prefix) bool {
	if !prefix.IsValid() || !prefix.Addr().Is4() {
		return true
	}
	if current.Prefix.IsValid() && prefixOverlaps(current.Prefix.Masked(), prefix.Masked()) {
		return true
	}
	staticRoutes := routesFromConfig(daemon.desired)
	for _, route := range staticRoutes {
		routePrefix, err := route.Prefix.Parse()
		if err != nil {
			continue
		}
		if prefixOverlaps(routePrefix.Masked(), prefix.Masked()) {
			return true
		}
	}
	for _, lan := range config.EffectiveLANs(daemon.desired) {
		for _, rawPrefix := range lan.Advertise {
			lanPrefix, err := rawPrefix.Parse()
			if err != nil {
				continue
			}
			lanPrefix = lanPrefix.Masked()
			if prefixOverlaps(lanPrefix, prefix.Masked()) {
				if lan.ID == current.LANID && prefixIsDelegatedSubprefix(prefix.Masked(), lanPrefix) {
					continue
				}
				return true
			}
		}
	}
	for otherKey, lease := range daemon.deviceLeases {
		if otherKey == current.Key {
			continue
		}
		if lease.Prefix.IsValid() && prefixOverlaps(lease.Prefix.Masked(), prefix.Masked()) {
			return true
		}
		for _, advertised := range lease.AdvertisePrefixes {
			if advertised.IsValid() && prefixOverlaps(advertised.Masked(), prefix.Masked()) {
				return true
			}
		}
	}
	return false
}

func prefixOverlaps(left, right netip.Prefix) bool {
	if !left.IsValid() || !right.IsValid() {
		return false
	}
	return left.Contains(right.Addr()) || right.Contains(left.Addr())
}

func prefixIsDelegatedSubprefix(child, parent netip.Prefix) bool {
	if !child.IsValid() || !parent.IsValid() {
		return false
	}
	child = child.Masked()
	parent = parent.Masked()
	return child.Addr().Is4() &&
		parent.Addr().Is4() &&
		child.Bits() > parent.Bits() &&
		parent.Contains(child.Addr())
}

func (daemon *Daemon) storeDeviceAccessLeaseLocked(lease deviceAccessLease) {
	if daemon.deviceLeases == nil {
		daemon.deviceLeases = make(map[deviceLeaseKey]deviceAccessLease)
	}
	daemon.deviceLeases[lease.Key] = lease
}

func (daemon *Daemon) pruneExpiredDeviceLeasesLocked(now time.Time) []droppedDataSession {
	dropped := make([]droppedDataSession, 0)
	for key, lease := range daemon.deviceLeases {
		if lease.ExpiresAt.IsZero() || now.Before(lease.ExpiresAt) {
			continue
		}
		if lease.SessionKey != (dataSessionKey{}) {
			session := daemon.dataSessions[lease.SessionKey]
			if session != nil {
				daemon.clearForwardCacheForSession(lease.SessionKey)
			}
			dropped = append(dropped, droppedDataSession{
				session: session,
				runtime: daemon.dataSessionState[lease.SessionKey],
			})
			delete(daemon.dataSessions, lease.SessionKey)
			delete(daemon.dataSessionState, lease.SessionKey)
			daemon.deleteSessionPoolCursorLocked(lease.SessionKey)
			daemon.deleteSessionFlowBindingsLocked(lease.SessionKey)
		} else {
			dropped = append(dropped, droppedDataSession{})
		}
		delete(daemon.deviceLeases, key)
	}
	if len(dropped) > 0 {
		daemon.dataSessionEpoch++
	}
	if len(daemon.dataSessions) == 0 {
		daemon.sessionPoolRR = nil
		daemon.sessionPoolFlow = nil
	}
	return dropped
}

func (daemon *Daemon) deviceAccessExpiryReaper(ctx context.Context) {
	ticker := time.NewTicker(deviceAccessExpiryReaperInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dropped := daemon.dropExpiredDeviceAccessSessions()
			if dropped == 0 {
				continue
			}
			_ = daemon.applyRuntimeDataplaneSnapshot(ctx)
			if daemon.localAdvertisementConfigured() {
				_ = daemon.refreshLocalAdvertisement()
			}
		}
	}
}

func (daemon *Daemon) dropExpiredDeviceAccessSessions() int {
	if daemon == nil || !daemon.deviceAccessEnabled() {
		return 0
	}
	now := time.Now().UTC()
	daemon.dataMu.Lock()
	dropped := daemon.pruneExpiredDeviceLeasesLocked(now)
	daemon.dataMu.Unlock()
	daemon.closeDroppedDataSessions(dropped)
	return len(dropped)
}

func deviceAccessGatewayAddress(raw string) (netip.Addr, bool) {
	if strings.TrimSpace(raw) == "" {
		return netip.Addr{}, false
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		return netip.Addr{}, false
	}
	return prefix.Addr(), true
}

func firstFreeDeviceAccessAddress(pool netip.Prefix, used map[netip.Addr]struct{}) (netip.Addr, bool) {
	addr := pool.Addr()
	for pool.Contains(addr) {
		if !addr.Is4() {
			return netip.Addr{}, false
		}
		if _, exists := used[addr]; !exists && !addr.IsUnspecified() && !addr.IsMulticast() {
			return addr, true
		}
		next := addr.Next()
		if !next.IsValid() || next == addr {
			break
		}
		addr = next
	}
	return netip.Addr{}, false
}

func (daemon *Daemon) deviceAccessPeerConfig(identity transport.PeerIdentity, lease deviceAccessLease) config.PeerConfig {
	peerID := deviceAccessPeerID(identity)
	allowedPrefixes := []core.Prefix{core.Prefix(lease.Prefix.String())}
	for _, prefix := range lease.AdvertisePrefixes {
		if prefix.IsValid() {
			allowedPrefixes = append(allowedPrefixes, core.Prefix(prefix.Masked().String()))
		}
	}
	peer := config.PeerConfig{
		ID:              peerID,
		Domain:          identity.Domain,
		AllowedPrefixes: allowedPrefixes,
	}
	if lease.Endpoint.Name != "" && lease.Endpoint.Transport != "" {
		endpoint := lease.Endpoint
		endpoint.Mode = config.EndpointModePassive
		endpoint.Address = ""
		endpoint.Enabled = true
		endpoint.EnabledSet = true
		peer.Endpoints = []config.EndpointConfig{endpoint}
	}
	return peer
}

func (daemon *Daemon) deviceAccessClientRoutesForLease(lease deviceAccessLease) []netip.Prefix {
	routes := daemon.runtimeRoutes()
	owned := deviceAccessLeaseRoutePrefixes(lease)
	out := make([]netip.Prefix, 0, len(routes))
	seen := make(map[string]struct{}, len(routes))
	for _, route := range routes {
		if route.Kind != "" && route.Kind != routing.RouteUnicast && route.Kind != routing.RouteLocal {
			continue
		}
		prefix, err := route.Prefix.Parse()
		if err != nil || !prefix.Addr().Is4() {
			continue
		}
		prefix = prefix.Masked()
		if deviceAccessClientRouteIsOwned(prefix, owned) {
			continue
		}
		raw := prefix.String()
		if _, exists := seen[raw]; exists {
			continue
		}
		seen[raw] = struct{}{}
		out = append(out, prefix)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr().Compare(out[j].Addr()) != 0 {
			return out[i].Addr().Compare(out[j].Addr()) < 0
		}
		return out[i].Bits() < out[j].Bits()
	})
	return out
}

func (daemon *Daemon) refreshDeviceAccessClientRoutes() {
	if daemon == nil || !daemon.deviceAccessEnabled() {
		return
	}
	type update struct {
		runtime *dataSessionRuntime
		session transport.Session
		lease   deviceAccessLease
	}
	now := time.Now().UTC()
	daemon.dataMu.Lock()
	expiredSessions := daemon.pruneExpiredDeviceLeasesLocked(now)
	updates := make([]update, 0, len(daemon.deviceLeases))
	for _, lease := range daemon.deviceLeases {
		session := daemon.dataSessions[lease.SessionKey]
		runtime := daemon.dataSessionState[lease.SessionKey]
		if session == nil || runtime == nil || !lease.Address.IsValid() || !lease.Prefix.IsValid() {
			continue
		}
		updates = append(updates, update{runtime: runtime, session: session, lease: lease})
	}
	daemon.dataMu.Unlock()
	daemon.closeDroppedDataSessions(expiredSessions)
	for _, item := range updates {
		routes := daemon.deviceAccessClientRoutesForLease(item.lease)
		frame := encodeDataSessionDeviceLease(item.lease.Address, uint32(item.lease.Prefix.Bits()), item.lease.ExpiresAt, routes)
		_ = daemon.sendDataSessionWirePacket(item.runtime, item.session, frame)
	}
}

func deviceAccessClientRouteIsOwned(route netip.Prefix, owned []netip.Prefix) bool {
	for _, prefix := range owned {
		if !prefix.IsValid() {
			continue
		}
		prefix = prefix.Masked()
		route = route.Masked()
		if prefix.Contains(route.Addr()) && prefix.Bits() <= route.Bits() {
			return true
		}
	}
	return false
}

func deviceAccessPeerID(identity transport.PeerIdentity) core.IXID {
	ix := strings.TrimSpace(string(identity.Peer))
	device := strings.TrimSpace(string(identity.Device))
	if ix == "" {
		ix = "unknown"
	}
	if device == "" {
		device = "unknown"
	}
	return core.IXID("device:" + ix + ":" + device)
}

func (daemon *Daemon) allocateReverseDataSessionKeyLocked(peer core.IXID, endpoint config.EndpointConfig, encryption string) dataSessionKey {
	key := reverseDataSessionKey(peer, endpoint, encryption)
	poolSize := daemon.sessionPoolSize()
	if poolSize <= 1 {
		return key
	}
	for i := 0; i < poolSize; i++ {
		key.PoolIndex = i
		if daemon.dataSessions[key] == nil {
			return key
		}
	}
	var selected dataSessionKey
	var selectedActivity int64
	found := false
	for sessionKey := range daemon.dataSessions {
		if !reverseDataSessionKeyMatches(sessionKey, peer, endpoint, encryption) {
			continue
		}
		if sessionKey.PoolIndex < 0 || sessionKey.PoolIndex >= poolSize {
			continue
		}
		activity := daemon.dataSessionActivityLocked(sessionKey)
		if !found || activity < selectedActivity {
			selected = sessionKey
			selectedActivity = activity
			found = true
		}
	}
	if found {
		return selected
	}
	return key
}

func (daemon *Daemon) dataSessionActivityLocked(key dataSessionKey) int64 {
	runtime := daemon.dataSessionState[key]
	if runtime == nil {
		return 0
	}
	activity := runtime.lastRX.Load()
	if lastTX := runtime.lastTX.Load(); lastTX > activity {
		activity = lastTX
	}
	if lastUp := runtime.lastUp.Load(); lastUp > activity {
		activity = lastUp
	}
	if lastPong := runtime.lastPong.Load(); lastPong > activity {
		activity = lastPong
	}
	return activity
}

func (daemon *Daemon) inboundDataEndpointForPeer(peer config.PeerConfig, listenerEndpoint transport.Endpoint) (config.EndpointConfig, bool) {
	if endpoint, ok := endpointByName(peer.Endpoints, listenerEndpoint.Name); ok &&
		endpointDataSessionEnabled(endpoint) &&
		transport.Protocol(endpoint.Transport) == listenerEndpoint.Transport &&
		daemon.endpointKernelTransportCompatible(endpoint.Transport) &&
		daemon.endpointSecurityCompatible(endpoint) &&
		daemon.endpointTransportProfileCompatible(endpoint) {
		return endpoint, true
	}
	for _, endpoint := range peer.Endpoints {
		if !endpointDataSessionEnabled(endpoint) {
			continue
		}
		if transport.Protocol(endpoint.Transport) != listenerEndpoint.Transport {
			continue
		}
		if !daemon.endpointKernelTransportCompatible(endpoint.Transport) {
			continue
		}
		if !daemon.endpointSecurityCompatible(endpoint) {
			continue
		}
		if !daemon.endpointTransportProfileCompatible(endpoint) {
			continue
		}
		return endpoint, true
	}
	return config.EndpointConfig{}, false
}

func (daemon *Daemon) localDataEndpointConfig(listenerEndpoint transport.Endpoint) (config.EndpointConfig, bool) {
	for _, endpoint := range daemon.desired.Endpoints {
		if endpoint.Name == listenerEndpoint.Name && transport.Protocol(endpoint.Transport) == listenerEndpoint.Transport {
			return endpoint, true
		}
	}
	return config.EndpointConfig{}, false
}

type captureBatchReleaser func([]dataplane.CaptureEvent)

type captureBatchWork struct {
	events  []dataplane.CaptureEvent
	release func()
}

type captureBatchDispatchWork struct {
	index int
	work  captureBatchWork
}

func captureBatchReleaserForSubscription(subscription dataplane.CaptureBatchSubscription) captureBatchReleaser {
	releaser, ok := subscription.(dataplane.CaptureBatchReleaseSubscription)
	if !ok {
		return nil
	}
	return releaser.ReleaseBatch
}

func captureBatchReleaseForBatch(releaser captureBatchReleaser, batch []dataplane.CaptureEvent) func() {
	if releaser == nil || len(batch) == 0 {
		return nil
	}
	return func() {
		releaser(batch)
	}
}

func captureBatchRefCountRelease(release func(), recipients int) func() {
	if release == nil {
		return nil
	}
	if recipients <= 1 {
		return release
	}
	var remaining atomic.Int32
	remaining.Store(int32(recipients))
	return func() {
		if remaining.Add(-1) == 0 {
			release()
		}
	}
}

func (work captureBatchWork) finish() {
	if work.release != nil {
		work.release()
	}
}

func (daemon *Daemon) forwardCapturedPackets(ctx context.Context, subscription dataplane.CaptureSubscription) {
	defer func() {
		_ = subscription.Close()
		daemon.finishCaptureForwarder(subscription)
	}()
	if batchSubscription, ok := subscription.(dataplane.CaptureBatchSubscription); ok {
		daemon.forwardCapturedPacketBatches(ctx, batchSubscription)
		return
	}
	workers := captureForwarderWorkerCount()
	if workers > 1 {
		var wg sync.WaitGroup
		workerBuffer := captureForwarderWorkerBufferSize(workers)
		queues := make([]chan dataplane.CaptureEvent, workers)
		wg.Add(workers)
		for i := 0; i < workers; i++ {
			queues[i] = make(chan dataplane.CaptureEvent, workerBuffer)
			go func(events <-chan dataplane.CaptureEvent) {
				defer wg.Done()
				daemon.forwardCapturedPacketsLoop(ctx, events)
			}(queues[i])
		}
		daemon.dispatchCapturedPackets(ctx, subscription.Events(), queues)
		for _, queue := range queues {
			close(queue)
		}
		wg.Wait()
		return
	}
	daemon.forwardCapturedPacketsLoop(ctx, subscription.Events())
}

func (daemon *Daemon) forwardCapturedPacketBatches(ctx context.Context, subscription dataplane.CaptureBatchSubscription) {
	workers := captureForwarderWorkerCount()
	releaser := captureBatchReleaserForSubscription(subscription)
	if workers > 1 {
		var wg sync.WaitGroup
		workerBuffer := captureForwarderWorkerBufferSize(workers)
		queues := make([]chan captureBatchWork, workers)
		wg.Add(workers)
		for i := 0; i < workers; i++ {
			queues[i] = make(chan captureBatchWork, workerBuffer)
			go func(events <-chan captureBatchWork) {
				defer wg.Done()
				daemon.forwardCapturedPacketBatchWorkLoop(ctx, events)
			}(queues[i])
		}
		daemon.dispatchCapturedPacketBatchGroups(ctx, subscription.BatchEvents(), queues, releaser)
		for _, queue := range queues {
			close(queue)
		}
		wg.Wait()
		return
	}
	daemon.forwardCapturedPacketBatchLoop(ctx, subscription.BatchEvents(), releaser)
}

func captureForwarderWorkerBufferSize(workers int) int {
	if workers <= 1 {
		return captureForwarderBufferSize()
	}
	perWorker := captureForwarderBufferSize() / workers
	if perWorker < 1 {
		return 1
	}
	return perWorker
}

func (daemon *Daemon) dispatchCapturedPackets(ctx context.Context, events <-chan dataplane.CaptureEvent, queues []chan dataplane.CaptureEvent) {
	if len(queues) == 0 {
		return
	}
	var fallback uint64
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-events:
			if !ok {
				return
			}
			index, hasFlow := captureForwarderWorkerIndexWithFlow(event, len(queues), fallback)
			if !hasFlow {
				fallback++
			}
			select {
			case <-ctx.Done():
				return
			case queues[index] <- event:
			}
		}
	}
}

func (daemon *Daemon) dispatchCapturedPacketBatches(ctx context.Context, batches <-chan []dataplane.CaptureEvent, queues []chan dataplane.CaptureEvent) {
	if len(queues) == 0 {
		return
	}
	var fallback uint64
	for {
		select {
		case <-ctx.Done():
			return
		case batch, ok := <-batches:
			if !ok {
				return
			}
			for _, event := range batch {
				index, hasFlow := captureForwarderWorkerIndexWithFlow(event, len(queues), fallback)
				if !hasFlow {
					fallback++
				}
				select {
				case <-ctx.Done():
					return
				case queues[index] <- event:
				}
			}
		}
	}
}

func (daemon *Daemon) dispatchCapturedPacketBatchGroups(ctx context.Context, batches <-chan []dataplane.CaptureEvent, queues []chan captureBatchWork, releaser captureBatchReleaser) {
	if len(queues) == 0 {
		return
	}
	workers := len(queues)
	var fallback uint64
	grouped := make([][]dataplane.CaptureEvent, workers)
	works := make([]captureBatchDispatchWork, 0, workers)
	for {
		select {
		case <-ctx.Done():
			return
		case batch, ok := <-batches:
			if !ok {
				return
			}
			release := captureBatchReleaseForBatch(releaser, batch)
			if len(batch) == 0 {
				if release != nil {
					release()
				}
				continue
			}
			if workers == 1 {
				work := captureBatchWork{events: batch, release: release}
				select {
				case <-ctx.Done():
					work.finish()
					return
				case queues[0] <- work:
				}
				continue
			}
			firstIndex := -1
			singleWorker := true
			nextFallback := fallback
			for _, event := range batch {
				index, hasFlow := captureForwarderWorkerIndexWithFlow(event, workers, nextFallback)
				if !hasFlow {
					nextFallback++
				}
				if firstIndex < 0 {
					firstIndex = index
					continue
				}
				if index != firstIndex {
					singleWorker = false
					break
				}
			}
			if singleWorker {
				fallback = nextFallback
				work := captureBatchWork{events: batch, release: release}
				select {
				case <-ctx.Done():
					work.finish()
					return
				case queues[firstIndex] <- work:
				}
				continue
			}
			for index := range grouped {
				grouped[index] = nil
			}
			works = works[:0]
			nextFallback = fallback
			for _, event := range batch {
				index, hasFlow := captureForwarderWorkerIndexWithFlow(event, workers, nextFallback)
				if !hasFlow {
					nextFallback++
				}
				grouped[index] = append(grouped[index], event)
			}
			for index := range grouped {
				if len(grouped[index]) == 0 {
					continue
				}
				works = append(works, captureBatchDispatchWork{index: index, work: captureBatchWork{events: grouped[index]}})
			}
			done := captureBatchRefCountRelease(release, len(works))
			for i := range works {
				works[i].work.release = done
			}
			for i, item := range works {
				select {
				case <-ctx.Done():
					item.work.finish()
					for j := i + 1; j < len(works); j++ {
						works[j].work.finish()
					}
					return
				case queues[item.index] <- item.work:
				}
			}
			fallback = nextFallback
			for index := range grouped {
				grouped[index] = nil
			}
		}
	}
}

func captureForwarderWorkerIndex(event dataplane.CaptureEvent, workers int, fallback uint64) int {
	index, _ := captureForwarderWorkerIndexWithFlow(event, workers, fallback)
	return index
}

func captureForwarderWorkerIndexWithFlow(event dataplane.CaptureEvent, workers int, fallback uint64) (int, bool) {
	if workers <= 1 {
		return 0, true
	}
	if key, ok := captureEventWorkerFlowKey(event); ok {
		return int(flowKeyHash(key) % uint64(workers)), true
	}
	return int(fallback % uint64(workers)), false
}

func captureEventWorkerFlowKey(event dataplane.CaptureEvent) (routing.FlowKey, bool) {
	if event.Hook != "lan_ingress_route_hit" || len(event.Payload) == 0 {
		return routing.FlowKey{}, false
	}
	if event.HasFlow {
		return event.FlowKey, true
	}
	if key, ok := flowKeyFromIPv4Packet(event.Payload); ok {
		return key, true
	}
	packet := event.Payload
	if len(packet) >= 14 && binary.BigEndian.Uint16(packet[12:14]) == ethPIPv4 {
		packet = packet[14:]
	}
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return routing.FlowKey{}, false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		return routing.FlowKey{}, false
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < ihl || totalLen > len(packet) {
		return routing.FlowKey{}, false
	}
	return routing.FlowKey{
		SourceIP:      netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]}),
		DestinationIP: netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]}),
		Protocol:      packet[9],
	}, true
}

func (daemon *Daemon) forwardCapturedPacketBatchLoop(ctx context.Context, batchCh <-chan []dataplane.CaptureEvent, releaser captureBatchReleaser) {
	batchSize := captureForwarderBatchSize()
	batchDelay := captureForwarderBatchDelay()
	if batchDelay > 0 && batchSize > 1 {
		daemon.forwardCapturedPacketBatchCoalescedLoop(ctx, batchCh, releaser, batchSize, batchDelay)
		return
	}
	var scratch captureForwardScratch
	for {
		select {
		case <-ctx.Done():
			return
		case events, ok := <-batchCh:
			if !ok {
				return
			}
			work := captureBatchWork{events: events, release: captureBatchReleaseForBatch(releaser, events)}
			if !daemon.forwardCaptureBatchWork(ctx, work, &scratch) {
				return
			}
		}
	}
}

func (daemon *Daemon) forwardCapturedPacketBatchWorkLoop(ctx context.Context, workCh <-chan captureBatchWork) {
	batchSize := captureForwarderBatchSize()
	batchDelay := captureForwarderBatchDelay()
	if batchDelay > 0 && batchSize > 1 {
		daemon.forwardCapturedPacketBatchWorkCoalescedLoop(ctx, workCh, batchSize, batchDelay)
		return
	}
	var scratch captureForwardScratch
	for {
		select {
		case <-ctx.Done():
			return
		case work, ok := <-workCh:
			if !ok {
				return
			}
			if !daemon.forwardCaptureBatchWork(ctx, work, &scratch) {
				return
			}
		}
	}
}

func (daemon *Daemon) forwardCaptureBatchWork(ctx context.Context, work captureBatchWork, scratch *captureForwardScratch) bool {
	defer work.finish()
	return daemon.forwardCaptureEventsBatch(ctx, work.events, scratch)
}

func (daemon *Daemon) forwardCapturedPacketBatchCoalescedLoop(ctx context.Context, batchCh <-chan []dataplane.CaptureEvent, releaser captureBatchReleaser, batchSize int, batchDelay time.Duration) {
	events := make([]dataplane.CaptureEvent, 0, batchSize)
	releases := make([]func(), 0, 4)
	var scratch captureForwardScratch
	var timer *time.Timer
	var timerC <-chan time.Time
	stopTimer := func() {
		if timer == nil {
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timerC = nil
	}
	startTimer := func() {
		if batchDelay <= 0 || len(events) == 0 || timerC != nil {
			return
		}
		if timer == nil {
			timer = time.NewTimer(batchDelay)
		} else {
			timer.Reset(batchDelay)
		}
		timerC = timer.C
	}
	releasePending := func() {
		for _, release := range releases {
			if release != nil {
				release()
			}
		}
		releases = releases[:0]
	}
	flush := func() bool {
		if len(events) == 0 {
			return true
		}
		stopTimer()
		ok := daemon.forwardCaptureEventsBatch(ctx, events, &scratch)
		clear(events)
		events = events[:0]
		releasePending()
		return ok
	}
	defer func() {
		stopTimer()
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case batch, ok := <-batchCh:
			if !ok {
				flush()
				return
			}
			release := captureBatchReleaseForBatch(releaser, batch)
			if len(batch) == 0 {
				if release != nil {
					release()
				}
				continue
			}
			if len(events) == 0 && len(batch) >= batchSize {
				work := captureBatchWork{events: batch, release: release}
				if !daemon.forwardCaptureBatchWork(ctx, work, &scratch) {
					return
				}
				continue
			}
			events = append(events, batch...)
			if release != nil {
				releases = append(releases, release)
			}
			if len(events) >= batchSize {
				if !flush() {
					return
				}
				continue
			}
			startTimer()
		case <-timerC:
			timerC = nil
			if !flush() {
				return
			}
		}
	}
}

func (daemon *Daemon) forwardCapturedPacketBatchWorkCoalescedLoop(ctx context.Context, workCh <-chan captureBatchWork, batchSize int, batchDelay time.Duration) {
	events := make([]dataplane.CaptureEvent, 0, batchSize)
	releases := make([]func(), 0, 4)
	var scratch captureForwardScratch
	var timer *time.Timer
	var timerC <-chan time.Time
	stopTimer := func() {
		if timer == nil {
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timerC = nil
	}
	startTimer := func() {
		if batchDelay <= 0 || len(events) == 0 || timerC != nil {
			return
		}
		if timer == nil {
			timer = time.NewTimer(batchDelay)
		} else {
			timer.Reset(batchDelay)
		}
		timerC = timer.C
	}
	releasePending := func() {
		for _, release := range releases {
			if release != nil {
				release()
			}
		}
		releases = releases[:0]
	}
	flush := func() bool {
		if len(events) == 0 {
			return true
		}
		stopTimer()
		ok := daemon.forwardCaptureEventsBatch(ctx, events, &scratch)
		clear(events)
		events = events[:0]
		releasePending()
		return ok
	}
	defer func() {
		stopTimer()
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case work, ok := <-workCh:
			if !ok {
				flush()
				return
			}
			if len(work.events) == 0 {
				work.finish()
				continue
			}
			if len(events) == 0 && len(work.events) >= batchSize {
				if !daemon.forwardCaptureBatchWork(ctx, work, &scratch) {
					return
				}
				continue
			}
			events = append(events, work.events...)
			if work.release != nil {
				releases = append(releases, work.release)
			}
			if len(events) >= batchSize {
				if !flush() {
					return
				}
				continue
			}
			startTimer()
		case <-timerC:
			timerC = nil
			if !flush() {
				return
			}
		}
	}
}

func (daemon *Daemon) forwardCapturedPacketsLoop(ctx context.Context, eventCh <-chan dataplane.CaptureEvent) {
	batchSize := captureForwarderBatchSize()
	if batchSize <= 1 {
		daemon.forwardCapturedPacketsOneByOne(ctx, eventCh)
		return
	}
	events := make([]dataplane.CaptureEvent, 0, batchSize)
	var scratch captureForwardScratch
	flush := func() bool {
		if len(events) == 0 {
			return true
		}
		if !daemon.forwardCaptureEventsBatch(ctx, events, &scratch) {
			return false
		}
		events = events[:0]
		return true
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case event, ok := <-eventCh:
			if !ok {
				flush()
				return
			}
			events = append(events, event)
			if len(events) >= batchSize && !flush() {
				return
			}
		default:
			if !flush() {
				return
			}
			select {
			case <-ctx.Done():
				return
			case event, ok := <-eventCh:
				if !ok {
					return
				}
				events = append(events, event)
			}
		}
	}
}

func (daemon *Daemon) forwardCapturedPacketsOneByOne(ctx context.Context, eventCh <-chan dataplane.CaptureEvent) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-eventCh:
			if !ok {
				return
			}
			if err := daemon.forwardCaptureEvent(ctx, event); err != nil {
				daemon.dataStats.sendErrors.Add(1)
			}
		}
	}
}

func (daemon *Daemon) closeCaptureForwarder() {
	daemon.dataMu.Lock()
	cancel := daemon.captureCancel
	subscription := daemon.captureSub
	daemon.captureCancel = nil
	daemon.captureSub = nil
	daemon.dataMu.Unlock()

	if cancel != nil {
		cancel()
	}
	if subscription != nil {
		_ = subscription.Close()
	}
}

func (daemon *Daemon) finishCaptureForwarder(subscription dataplane.CaptureSubscription) {
	daemon.dataMu.Lock()
	if daemon.captureSub == subscription {
		daemon.captureSub = nil
		daemon.captureCancel = nil
	}
	daemon.dataMu.Unlock()
	daemon.flushAllDataSessionBatches()
}

func (daemon *Daemon) forwardCaptureEvent(ctx context.Context, event dataplane.CaptureEvent) error {
	daemon.dataStats.captureEvents.Add(1)
	if event.Hook != "lan_ingress_route_hit" {
		daemon.dataStats.captureNonRouteEvents.Add(1)
		return nil
	}
	if len(event.Payload) == 0 {
		daemon.dataStats.recordDrop(observability.DropInvalidPacket)
		return fmt.Errorf("captured packet payload is empty")
	}
	if event.SampleLength < event.PacketLength {
		daemon.dataStats.captureTruncated.Add(1)
		daemon.dataStats.recordDrop(observability.DropMTUExceeded)
		return fmt.Errorf("captured packet is truncated: sample=%d packet=%d", event.SampleLength, event.PacketLength)
	}
	if capturedPacketExceedsMTU(event, daemon.desired.TransportPolicy.MTU) {
		daemon.dataStats.recordDrop(observability.DropMTUExceeded)
		return fmt.Errorf("captured packet length %d exceeds transport_policy mtu %d", capturedPacketMTULength(event), daemon.desired.TransportPolicy.MTU)
	}
	if daemon.fragmentPolicyDrop() && ipv4PacketFragmented(event.Payload) {
		daemon.dataStats.recordDrop(observability.DropFragmentedPacket)
		return fmt.Errorf("fragmented IPv4 packet rejected by transport_policy fragment_policy")
	}
	dst := event.DestinationAddr
	if !dst.IsValid() {
		var err error
		dst, err = netip.ParseAddr(event.DestinationIP)
		if err != nil {
			daemon.dataStats.recordDrop(observability.DropInvalidPacket)
			return fmt.Errorf("parse captured destination %q: %w", event.DestinationIP, err)
		}
	}
	flowKey, hasFlow := event.FlowKey, event.HasFlow
	if !hasFlow {
		flowKey, hasFlow = flowKeyFromIPv4Packet(event.Payload)
	}
	if hasFlow && !event.NATTranslated {
		if entry, ok := daemon.lookupForwardCacheForPacket(flowKey, dst); ok {
			packet := daemon.normalizedCapturePayload(event)
			cachedFlowKey := flowKey
			forwarded, ttlOK, err := daemon.decrementForwardTTL(ctx, packet)
			if err != nil {
				return err
			}
			if !ttlOK {
				return errIPv4TTLExpired
			}
			packet = forwarded
			flowKey, hasFlow = flowKeyFromIPv4Packet(packet)
			if !hasFlow {
				daemon.deleteForwardCache(cachedFlowKey)
				daemon.releaseFlow(cachedFlowKey)
				return daemon.sendPacketByDecision(ctx, entry.Decision, packet, routing.FlowKey{}, false)
			}
			return daemon.sendPacketWithForwardCacheEntry(ctx, entry.Decision, packet, flowKey, entry)
		}
		daemon.dataStats.forwardCacheMisses.Add(1)
	}
	decision, ok := daemon.lookupRouteForPacket(dst, event.Payload)
	if !ok {
		daemon.dataStats.routeMisses.Add(1)
		daemon.dataStats.recordDrop(observability.DropNoRoute)
		return fmt.Errorf("no route for captured destination %s", dst)
	}
	if dropReason, drop := routeDropReason(decision.Route); drop {
		daemon.recordRouteHit(decision)
		daemon.dataStats.recordDrop(dropReason)
		if decision.Route.Kind == routing.RouteReject {
			packet := daemon.normalizedCapturePayload(event)
			if err := daemon.replyToRejectedPacket(ctx, packet); err != nil {
				daemon.dataStats.rejectReplyErrors.Add(1)
				return err
			}
		}
		return fmt.Errorf("route %q is %s", decision.Route.Prefix, decision.Route.Kind)
	}
	daemon.recordRouteHit(decision)
	packet := daemon.normalizedCapturePayload(event)
	packet, ttlOK, err := daemon.decrementForwardTTL(ctx, packet)
	if err != nil {
		return err
	}
	if !ttlOK {
		return errIPv4TTLExpired
	}
	policy := daemon.policyForRoute(decision.Route)
	var natTranslated bool
	if event.NATTranslated {
		natTranslated, err = daemon.mirrorOutboundNATFromCapture(event, decision.Route, policy)
		if err != nil {
			daemon.dataStats.recordDrop(observability.DropInvalidPacket)
			return err
		}
	} else {
		packet, natTranslated, err = daemon.applyOutboundNAT(packet, decision.Route, policy)
		if err != nil {
			daemon.dataStats.recordDrop(observability.DropInvalidPacket)
			return err
		}
	}
	if natTranslated {
		daemon.dataStats.natTranslations.Add(1)
	}
	flowKey, hasFlow = flowKeyFromIPv4Packet(packet)
	return daemon.sendPacketByDecision(ctx, decision, packet, flowKey, hasFlow)
}

func (daemon *Daemon) decrementForwardTTL(ctx context.Context, packet []byte) ([]byte, bool, error) {
	forwarded, err := decrementIPv4TTL(packet)
	if err == nil {
		return forwarded, true, nil
	}
	if errors.Is(err, errIPv4TTLExpired) {
		if replyErr := daemon.replyToTTLExpiredPacket(ctx, packet); replyErr != nil {
			daemon.dataStats.rejectReplyErrors.Add(1)
			return nil, false, replyErr
		}
		daemon.dataStats.recordDrop(observability.DropTTLExpired)
		return nil, false, nil
	}
	daemon.dataStats.recordDrop(observability.DropInvalidPacket)
	return nil, false, err
}

func (daemon *Daemon) forwardCaptureEventsBatch(ctx context.Context, events []dataplane.CaptureEvent, scratch *captureForwardScratch) bool {
	if len(events) == 0 {
		return true
	}
	if scratch == nil {
		scratch = &captureForwardScratch{}
	}
	scratch.begin(len(events), daemon)
	scratch.reservePacketArena(events)
	defer scratch.release()
	var singleRuntime *dataSessionRuntime
	singleRuntimeOnly := true
	for _, event := range events {
		candidate, ok := daemon.captureForwardBatchCandidate(event, scratch)
		if !ok {
			scratch.fallbacks = append(scratch.fallbacks, event)
			singleRuntimeOnly = false
			continue
		}
		if singleRuntime == nil {
			singleRuntime = candidate.Entry.Runtime
		} else if singleRuntime != candidate.Entry.Runtime {
			singleRuntimeOnly = false
		}
		scratch.candidates = append(scratch.candidates, candidate)
	}
	for _, event := range scratch.fallbacks {
		if err := daemon.forwardCaptureEvent(ctx, event); err != nil {
			daemon.dataStats.sendErrors.Add(1)
		}
	}
	if len(scratch.candidates) == 0 {
		return ctx.Err() == nil
	}
	if singleRuntimeOnly {
		if err := daemon.sendForwardCacheBatch(ctx, scratch.candidates, scratch); err != nil {
			daemon.dataStats.sendErrors.Add(1)
			if ctx.Err() != nil {
				return false
			}
		}
		return ctx.Err() == nil
	}
	if scratch.groups == nil {
		scratch.groups = make(map[*dataSessionRuntime]int)
	}
	for _, candidate := range scratch.candidates {
		index, found := scratch.groups[candidate.Entry.Runtime]
		if !found {
			index = len(scratch.batches)
			scratch.groups[candidate.Entry.Runtime] = index
			scratch.batches = append(scratch.batches, captureForwardBatchGroup{Runtime: candidate.Entry.Runtime})
		}
		scratch.batches[index].Items = append(scratch.batches[index].Items, candidate)
	}
	for _, batch := range scratch.batches {
		if err := daemon.sendForwardCacheBatch(ctx, batch.Items, scratch); err != nil {
			daemon.dataStats.sendErrors.Add(1)
			if ctx.Err() != nil {
				return false
			}
		}
	}
	return ctx.Err() == nil
}

func (daemon *Daemon) captureForwardBatchCandidate(event dataplane.CaptureEvent, scratch *captureForwardScratch) (captureForwardBatchCandidate, bool) {
	if scratch == nil {
		scratch = &captureForwardScratch{
			mssClamp:              daemon.effectiveTCPMSSClamp(),
			trustCapturedChecksum: trustCapturedChecksums(),
			trustCapturedReady:    true,
			mtu:                   daemon.desired.TransportPolicy.MTU,
			dropFragments:         daemon.fragmentPolicyDrop(),
		}
	}
	if event.Hook != "lan_ingress_route_hit" ||
		len(event.Payload) == 0 ||
		event.SampleLength < event.PacketLength ||
		event.NATTranslated ||
		capturedPacketExceedsMTU(event, scratch.mtu) ||
		(scratch.dropFragments && ipv4PacketFragmented(event.Payload)) {
		return captureForwardBatchCandidate{}, false
	}
	dst := event.DestinationAddr
	if !dst.IsValid() {
		var err error
		dst, err = netip.ParseAddr(event.DestinationIP)
		if err != nil {
			return captureForwardBatchCandidate{}, false
		}
	}
	flowKey := event.FlowKey
	if !event.HasFlow {
		var hasFlow bool
		flowKey, hasFlow = flowKeyFromIPv4Packet(event.Payload)
		if !hasFlow {
			return captureForwardBatchCandidate{}, false
		}
	}
	entry, ok := daemon.lookupForwardCacheForPacket(flowKey, dst)
	if !ok {
		return captureForwardBatchCandidate{}, false
	}
	forwarded, err := daemon.normalizedForwardCapturePayload(event, scratch.mssClamp, scratch.trustCapturedChecksum, scratch)
	if err != nil {
		return captureForwardBatchCandidate{}, false
	}
	daemon.dataStats.captureEvents.Add(1)
	return captureForwardBatchCandidate{
		Entry:   entry,
		FlowKey: flowKey,
		Packet:  forwarded,
	}, true
}

func (daemon *Daemon) sendForwardCacheBatch(ctx context.Context, items []captureForwardBatchCandidate, scratch *captureForwardScratch) error {
	if len(items) == 0 {
		return nil
	}
	entry := items[0].Entry
	if entry.Session == nil || entry.Runtime == nil {
		for _, item := range items {
			daemon.deleteForwardCache(item.FlowKey)
		}
		return fmt.Errorf("forward cache session missing")
	}
	if entry.NativeBatching {
		return daemon.sendForwardCacheNativeBatch(ctx, entry, items, scratch)
	}
	batch := prepareCaptureForwardBatch(items, scratch)
	wireBatch := daemon.prepareCaptureForwardWireBatch(entry.Runtime, entry.Session, batch, scratch)
	if err := daemon.sendDataSessionPackets(entry.Runtime, entry.Session, wireBatch.Packets); err != nil {
		for _, item := range items {
			daemon.deleteForwardCache(item.FlowKey)
			daemon.releaseFlow(item.FlowKey)
		}
		daemon.dropSession(entry.Key)
		daemon.recordEndpointDownIfNoActiveSession(entry.Peer.ID, entry.Endpoint, err)
		daemon.dataStats.recordDrop(observability.DropEndpointDown)
		lastErr := fmt.Errorf("send packet batch to peer %q endpoint %q: %w", entry.Peer.ID, entry.Endpoint.Name, err)
		for _, item := range items {
			daemon.recordSendMetrics(item.Entry.Decision, entry.Peer.ID, entry.Endpoint, len(item.Packet), lastErr)
		}
		return lastErr
	}
	daemon.refreshEndpointUp(entry.Runtime, entry.Peer.ID, entry.Endpoint)
	daemon.dataStats.packetsSent.Add(uint64(len(items)))
	daemon.recordSendMetricsBatch(entry.Decision, entry.Peer.ID, entry.Endpoint, batch.Bytes, len(items), nil)
	return ctx.Err()
}

func (daemon *Daemon) sendForwardCacheNativeBatch(ctx context.Context, entry *dataForwardCacheEntry, items []captureForwardBatchCandidate, scratch *captureForwardScratch) error {
	if len(items) == 0 {
		return nil
	}
	batch := prepareCaptureForwardBatch(items, scratch)
	wireBatch := daemon.prepareCaptureForwardWireBatch(entry.Runtime, entry.Session, batch, scratch)
	if err := daemon.sendDataSessionPackets(entry.Runtime, entry.Session, wireBatch.Packets); err != nil {
		for _, item := range items {
			daemon.deleteForwardCache(item.FlowKey)
			daemon.releaseFlow(item.FlowKey)
		}
		daemon.dropSession(entry.Key)
		daemon.recordEndpointDownIfNoActiveSession(entry.Peer.ID, entry.Endpoint, err)
		daemon.dataStats.recordDrop(observability.DropEndpointDown)
		lastErr := fmt.Errorf("send native packet batch to peer %q endpoint %q: %w", entry.Peer.ID, entry.Endpoint.Name, err)
		for _, item := range items {
			daemon.recordSendMetrics(item.Entry.Decision, entry.Peer.ID, entry.Endpoint, len(item.Packet), lastErr)
		}
		return lastErr
	}
	daemon.refreshEndpointUp(entry.Runtime, entry.Peer.ID, entry.Endpoint)
	daemon.dataStats.packetsSent.Add(uint64(len(items)))
	daemon.recordSendMetricsBatch(entry.Decision, entry.Peer.ID, entry.Endpoint, batch.Bytes, len(items), nil)
	return ctx.Err()
}

func prepareCaptureForwardBatch(items []captureForwardBatchCandidate, scratch *captureForwardScratch) captureForwardPreparedBatch {
	var packets [][]byte
	if scratch != nil {
		if cap(scratch.packets) < len(items) {
			scratch.packets = make([][]byte, len(items))
		} else {
			scratch.packets = scratch.packets[:len(items)]
		}
		packets = scratch.packets
	} else {
		packets = make([][]byte, len(items))
	}
	batch := captureForwardPreparedBatch{Packets: packets}
	for i, item := range items {
		batch.Packets[i] = item.Packet
		batch.Bytes += len(item.Packet)
	}
	return batch
}

func (daemon *Daemon) prepareCaptureForwardWireBatch(runtime *dataSessionRuntime, session transport.Session, batch captureForwardPreparedBatch, scratch *captureForwardScratch) captureForwardPreparedBatch {
	if len(batch.Packets) < 2 || scratch == nil {
		return batch
	}
	maxBytes := scratch.txGSOCoalesceMaxBytes
	if maxBytes <= 0 {
		return batch
	}
	enabled := scratch.txGSOCoalesceEnabled
	multiFlow := scratch.txGSOCoalesceMultiFlow
	if session != nil {
		stats := dataSessionTransportStats(runtime, session)
		if stats.Datagram && stats.MaxPacketSize > 0 && stats.MaxPacketSize <= uint64(int(^uint(0)>>1)) {
			if sessionMax := int(stats.MaxPacketSize); sessionMax > 0 && maxBytes > sessionMax {
				maxBytes = sessionMax
			}
		}
		if !scratch.txGSOCoalesceExplicit && dataSessionTXGSOCoalesceDefaultForRuntime(runtime, stats) {
			enabled = true
		}
		if !scratch.txGSOCoalesceMultiFlowExplicit && dataSessionTXGSOCoalesceMultiFlowDefaultForRuntime(runtime, stats) {
			multiFlow = true
		}
	}
	if !enabled {
		return batch
	}
	coalesceOptions := tcpGSOCoalesceOptions{multiFlow: multiFlow}
	packets, coalesceStats := coalesceDataSessionTCPLocalPacketsConfiguredScratchOptions(batch.Packets, enabled, maxBytes, scratch.txGSOCoalesceMaxPkts, &scratch.coalescedPackets, &scratch.coalesceArena, coalesceOptions)
	if coalesceStats.Batches == 0 {
		return batch
	}
	daemon.dataStats.sendGSOCoalesceBatches.Add(coalesceStats.Batches)
	daemon.dataStats.sendGSOCoalescePackets.Add(coalesceStats.InputPackets)
	daemon.dataStats.sendGSOCoalesceWires.Add(coalesceStats.OutputPackets)
	daemon.dataStats.sendGSOCoalesceBytes.Add(coalesceStats.OutputBytes)
	batch.Packets = packets
	return batch
}

func (daemon *Daemon) normalizedCapturePayload(event dataplane.CaptureEvent) []byte {
	return daemon.normalizedCapturePayloadWithOptions(event, daemon.effectiveTCPMSSClamp(), trustCapturedChecksums())
}

func (daemon *Daemon) normalizedCapturePayloadWithOptions(event dataplane.CaptureEvent, mss int, trustChecksums bool) []byte {
	stripEthernet := func(packet []byte) []byte {
		return capturedIPv4Payload(packet)
	}
	if event.ChecksumNormalized {
		if !capturedPacketNeedsTCPMSSClamp(event.Payload, mss) {
			return stripEthernet(event.Payload)
		}
		return stripEthernet(normalizeCapturedIPv4ChecksumsWithMSS(event.Payload, mss))
	}
	if trustChecksums {
		if capturedPacketNeedsTCPMSSClamp(event.Payload, mss) {
			return stripEthernet(normalizeCapturedIPv4ChecksumsWithMSS(event.Payload, mss))
		}
		return stripEthernet(event.Payload)
	}
	return stripEthernet(normalizeCapturedIPv4ChecksumsWithMSS(event.Payload, mss))
}

func (daemon *Daemon) normalizedForwardCapturePayload(event dataplane.CaptureEvent, mss int, trustChecksums bool, scratch *captureForwardScratch) ([]byte, error) {
	payload := capturedIPv4Payload(event.Payload)
	if len(payload) == 0 {
		return nil, fmt.Errorf("captured packet payload is empty")
	}
	packet := payload
	if !event.PayloadMutable {
		packet = scratch.clonePacket(payload)
	}
	needsMSSClamp := capturedPacketNeedsTCPMSSClamp(packet, mss)
	needsChecksumNormalize := needsMSSClamp || (!event.ChecksumNormalized && !trustChecksums)
	if needsChecksumNormalize {
		if err := decrementIPv4TTLBeforeChecksumInPlace(packet); err != nil {
			return nil, err
		}
		if needsMSSClamp {
			clampCapturedTCPMSSInPlaceWithMSS(packet, mss)
		}
		normalizeCapturedIPv4ChecksumsInPlace(packet)
		return packet, nil
	}
	if err := decrementIPv4TTLInPlace(packet); err != nil {
		return nil, err
	}
	return packet, nil
}

func trustCapturedChecksums() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_TRUST_CAPTURED_CHECKSUMS"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func capturedPacketLength(event dataplane.CaptureEvent) int {
	if event.PacketLength > 0 {
		if len(event.Payload) >= 14 && binary.BigEndian.Uint16(event.Payload[12:14]) == ethPIPv4 && event.PacketLength >= 14 {
			return int(event.PacketLength) - 14
		}
		return int(event.PacketLength)
	}
	return len(capturedIPv4Payload(event.Payload))
}

func capturedPacketMTULength(event dataplane.CaptureEvent) int {
	if event.GSOSegmentLength == 0 {
		return capturedPacketLength(event)
	}
	packet := capturedIPv4Payload(event.Payload)
	if len(packet) < ipv4HeaderLen || packet[0]>>4 != 4 || packet[9] != ipProtocolTCP {
		return capturedPacketLength(event)
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < ipv4HeaderLen || len(packet) < ihl+20 {
		return capturedPacketLength(event)
	}
	flagsAndFragment := binary.BigEndian.Uint16(packet[6:8])
	if flagsAndFragment&(ipv4MoreFragments|ipv4FragmentOffsetMask) != 0 {
		return capturedPacketLength(event)
	}
	tcpHeaderLen := int(packet[ihl+12]>>4) * 4
	if tcpHeaderLen < 20 || len(packet) < ihl+tcpHeaderLen {
		return capturedPacketLength(event)
	}
	return ihl + tcpHeaderLen + int(event.GSOSegmentLength)
}

func capturedPacketExceedsMTU(event dataplane.CaptureEvent, mtu int) bool {
	if mtu <= 0 || capturedPacketMTULength(event) <= mtu {
		return false
	}
	return !capturedPacketSegmentableForMTU(event, mtu)
}

func capturedPacketSegmentableForMTU(event dataplane.CaptureEvent, mtu int) bool {
	packet := capturedIPv4Payload(event.Payload)
	if len(packet) == 0 {
		return false
	}
	_, err := dataSessionIPv4TCPSegmentationMetaForPacket(packet, mtu)
	return err == nil
}

func capturedIPv4Payload(packet []byte) []byte {
	if len(packet) >= 14 && binary.BigEndian.Uint16(packet[12:14]) == ethPIPv4 {
		if ipOffset, _, totalLen, err := ipv4HeaderBounds(packet); err == nil && ipOffset == 14 {
			return packet[ipOffset : ipOffset+totalLen]
		}
	}
	return packet
}

func (daemon *Daemon) fragmentPolicyDrop() bool {
	return daemon.desired.TransportPolicy.FragmentPolicy == "drop"
}

func (daemon *Daemon) sendPacketByDecision(ctx context.Context, decision routing.Decision, packet []byte, flowKey routing.FlowKey, hasFlow bool) error {
	return daemon.sendPacketByDecisionWithOptions(ctx, decision, packet, flowKey, hasFlow, defaultDataPacketSendOptions)
}

func (daemon *Daemon) sendPacketByDecisionWithOptions(ctx context.Context, decision routing.Decision, packet []byte, flowKey routing.FlowKey, hasFlow bool, options dataPacketSendOptions) error {
	daemon.dataStats.sendDecisionAttempts.Add(1)
	if hasFlow && options.UseForwardCache {
		if err := daemon.sendPacketByForwardCacheWithOptions(ctx, decision, packet, flowKey, options); err == nil {
			return nil
		}
	}
	peer, ok := daemon.peerConfig(decision.Route.NextHop)
	if !ok {
		daemon.dataStats.recordDrop(observability.DropPeerDown)
		return fmt.Errorf("route next hop %q is not configured", decision.Route.NextHop)
	}
	candidates, policy, err := daemon.candidatePeerEndpoints(peer, decision.Route, flowKey, hasFlow)
	if err != nil {
		daemon.dataStats.recordDrop(observability.DropEndpointDown)
		return err
	}
	daemon.dataStats.sendDecisionCandidates.Add(uint64(len(candidates)))
	var lastErr error
	for _, endpoint := range candidates {
		session, key, runtime, err := daemon.sessionForEndpointWithOptions(ctx, peer, endpoint, flowKey, hasFlow, sessionForEndpointOptions{AllowDial: options.AllowDial})
		if err != nil {
			if options.RecordEndpointHealth {
				daemon.recordEndpointDownIfNoActiveSession(peer.ID, endpoint, err)
			}
			daemon.dataStats.recordDrop(observability.DropEndpointDown)
			daemon.recordSendMetrics(decision, peer.ID, endpoint, len(packet), err)
			lastErr = err
			continue
		}
		if err := daemon.sendDataSessionPacket(runtime, session, packet); err != nil {
			if options.DropSessionOnSendError {
				daemon.dropSession(key)
			}
			if options.RecordEndpointHealth {
				daemon.recordEndpointDownIfNoActiveSession(peer.ID, endpoint, err)
			}
			daemon.dataStats.recordDrop(observability.DropEndpointDown)
			lastErr = fmt.Errorf("send packet to peer %q endpoint %q: %w", peer.ID, endpoint.Name, err)
			daemon.recordSendMetrics(decision, peer.ID, endpoint, len(packet), lastErr)
			if hasFlow && options.BindFlow {
				daemon.releaseFlow(flowKey)
			}
			continue
		}
		if options.RecordEndpointHealth {
			daemon.refreshEndpointUp(runtime, peer.ID, endpoint)
		}
		daemon.dataStats.packetsSent.Add(1)
		daemon.recordSendMetrics(decision, peer.ID, endpoint, len(packet), nil)
		if hasFlow && policy.FlowStickiness && options.BindFlow {
			daemon.bindFlow(flowKey, decision.Route.NextHop, endpoint.Name, key.PoolIndex)
			runtime.ensureBatchConfig()
			daemon.storeForwardCache(flowKey, dataForwardCacheEntry{
				Decision:       decision,
				Peer:           peer,
				Endpoint:       endpoint,
				Session:        session,
				Key:            key,
				Runtime:        runtime,
				Policy:         policy,
				NativeBatching: dataSessionNativeBatchingPreferred(runtime, session, runtime.batching.enabled),
				ExpiresAt:      time.Now().UTC().Add(flowBindingTTL),
			})
		}
		return nil
	}
	if lastErr == nil {
		daemon.dataStats.sendDecisionNoCandidates.Add(1)
		lastErr = fmt.Errorf("peer %q has no usable data endpoint", peer.ID)
	}
	return lastErr
}

func (daemon *Daemon) sendPacketByForwardCache(ctx context.Context, decision routing.Decision, packet []byte, flowKey routing.FlowKey) error {
	return daemon.sendPacketByForwardCacheWithOptions(ctx, decision, packet, flowKey, defaultDataPacketSendOptions)
}

func (daemon *Daemon) sendPacketByForwardCacheWithOptions(ctx context.Context, decision routing.Decision, packet []byte, flowKey routing.FlowKey, options dataPacketSendOptions) error {
	entry, ok := daemon.lookupForwardCache(flowKey, decision.Route.NextHop)
	if !ok {
		return fmt.Errorf("forward cache miss")
	}
	return daemon.sendPacketWithForwardCacheEntryOptions(ctx, decision, packet, flowKey, entry, options)
}

func (daemon *Daemon) sendPacketWithForwardCacheEntry(ctx context.Context, decision routing.Decision, packet []byte, flowKey routing.FlowKey, entry *dataForwardCacheEntry) error {
	return daemon.sendPacketWithForwardCacheEntryOptions(ctx, decision, packet, flowKey, entry, defaultDataPacketSendOptions)
}

func (daemon *Daemon) sendPacketWithForwardCacheEntryOptions(ctx context.Context, decision routing.Decision, packet []byte, flowKey routing.FlowKey, entry *dataForwardCacheEntry, options dataPacketSendOptions) error {
	if entry == nil || entry.Session == nil {
		daemon.deleteForwardCache(flowKey)
		return fmt.Errorf("forward cache session missing")
	}
	if err := daemon.sendDataSessionPacket(entry.Runtime, entry.Session, packet); err != nil {
		daemon.deleteForwardCache(flowKey)
		if options.DropSessionOnSendError {
			daemon.dropSession(entry.Key)
		}
		if options.RecordEndpointHealth {
			daemon.recordEndpointDownIfNoActiveSession(entry.Peer.ID, entry.Endpoint, err)
		}
		daemon.dataStats.recordDrop(observability.DropEndpointDown)
		lastErr := fmt.Errorf("send packet to peer %q endpoint %q: %w", entry.Peer.ID, entry.Endpoint.Name, err)
		daemon.recordSendMetrics(decision, entry.Peer.ID, entry.Endpoint, len(packet), lastErr)
		if options.BindFlow {
			daemon.releaseFlow(flowKey)
		}
		return lastErr
	}
	if options.RecordEndpointHealth {
		daemon.refreshEndpointUp(entry.Runtime, entry.Peer.ID, entry.Endpoint)
	}
	daemon.dataStats.packetsSent.Add(1)
	daemon.recordSendMetrics(decision, entry.Peer.ID, entry.Endpoint, len(packet), nil)
	return nil
}

func (daemon *Daemon) lookupForwardCache(flowKey routing.FlowKey, nextHop core.IXID) (*dataForwardCacheEntry, bool) {
	daemon.forwardCacheMu.RLock()
	entry, ok := daemon.forwardCache[flowKey]
	if !ok ||
		entry == nil ||
		entry.Decision.Route.NextHop != nextHop ||
		entry.Session == nil ||
		entry.Runtime == nil {
		daemon.forwardCacheMu.RUnlock()
		return nil, false
	}
	daemon.forwardCacheMu.RUnlock()
	return entry, true
}

func (daemon *Daemon) lookupForwardCacheForPacket(flowKey routing.FlowKey, dst netip.Addr) (*dataForwardCacheEntry, bool) {
	daemon.forwardCacheMu.RLock()
	entry, ok := daemon.forwardCache[flowKey]
	if !ok ||
		entry == nil ||
		entry.Session == nil ||
		entry.Runtime == nil ||
		entry.Decision.Route.Kind != routing.RouteUnicast ||
		!entry.Decision.Prefix.Contains(dst) ||
		daemon.natEnabledForRoute(entry.Decision.Route, entry.Policy) {
		daemon.forwardCacheMu.RUnlock()
		return nil, false
	}
	daemon.forwardCacheMu.RUnlock()
	daemon.dataStats.forwardCacheHits.Add(1)
	return entry, true
}

func (daemon *Daemon) storeForwardCache(flowKey routing.FlowKey, entry dataForwardCacheEntry) {
	if entry.Session == nil || entry.Runtime == nil {
		return
	}
	daemon.forwardCacheMu.Lock()
	if daemon.forwardCache == nil {
		daemon.forwardCache = make(map[routing.FlowKey]*dataForwardCacheEntry)
	}
	entryCopy := entry
	daemon.forwardCache[flowKey] = &entryCopy
	daemon.forwardCacheMu.Unlock()
	daemon.dataStats.forwardCacheStores.Add(1)
}

func (daemon *Daemon) deleteForwardCache(flowKey routing.FlowKey) {
	daemon.forwardCacheMu.Lock()
	delete(daemon.forwardCache, flowKey)
	daemon.forwardCacheMu.Unlock()
}

func (daemon *Daemon) clearForwardCache() {
	daemon.forwardCacheMu.Lock()
	daemon.forwardCache = nil
	daemon.forwardCacheMu.Unlock()
}

func (daemon *Daemon) reconcileForwardCacheForRoutes(routes routing.Engine) {
	if routes == nil {
		daemon.clearForwardCache()
		return
	}
	now := time.Now().UTC()
	var released []routing.FlowKey
	daemon.forwardCacheMu.Lock()
	for key, entry := range daemon.forwardCache {
		if entry == nil ||
			entry.Session == nil ||
			entry.Runtime == nil ||
			(!entry.ExpiresAt.IsZero() && !now.Before(entry.ExpiresAt)) ||
			!key.DestinationIP.IsValid() {
			delete(daemon.forwardCache, key)
			released = append(released, key)
			continue
		}
		decision, ok := routes.Lookup(key.DestinationIP)
		if !ok || !forwardCacheRouteEquivalent(decision, entry.Decision) {
			delete(daemon.forwardCache, key)
			released = append(released, key)
		}
	}
	daemon.forwardCacheMu.Unlock()
	if len(released) == 0 {
		return
	}
	daemon.flowMu.Lock()
	for _, key := range released {
		delete(daemon.flows, key)
	}
	daemon.flowMu.Unlock()
}

func forwardCacheRouteEquivalent(left routing.Decision, right routing.Decision) bool {
	return left.Prefix == right.Prefix &&
		left.Route.Prefix == right.Route.Prefix &&
		left.Route.Owner == right.Route.Owner &&
		left.Route.NextHop == right.Route.NextHop &&
		left.Route.Endpoint == right.Route.Endpoint &&
		left.Route.Policy == right.Route.Policy &&
		left.Route.Kind == right.Route.Kind &&
		left.Route.LocalProtocol == right.Route.LocalProtocol &&
		left.Route.LocalPort == right.Route.LocalPort
}

func (daemon *Daemon) clearForwardCacheForPeers(peers map[core.IXID]struct{}) {
	if len(peers) == 0 {
		return
	}
	daemon.forwardCacheMu.Lock()
	for key, entry := range daemon.forwardCache {
		if _, ok := peers[entry.Decision.Route.NextHop]; ok {
			delete(daemon.forwardCache, key)
		}
	}
	daemon.forwardCacheMu.Unlock()
}

func (daemon *Daemon) clearForwardCacheForSession(key dataSessionKey) {
	daemon.forwardCacheMu.Lock()
	for flowKey, entry := range daemon.forwardCache {
		if entry.Key == key {
			delete(daemon.forwardCache, flowKey)
		}
	}
	daemon.forwardCacheMu.Unlock()
}

func (daemon *Daemon) clearForwardCacheForOutboundEndpointLocked(peer core.IXID, endpoint config.EndpointConfig, encryption string) {
	protocol := transport.Protocol(endpoint.Transport)
	daemon.forwardCacheMu.Lock()
	for flowKey, entry := range daemon.forwardCache {
		if entry == nil ||
			entry.Key.Peer != peer ||
			entry.Key.Endpoint != endpoint.Name ||
			entry.Key.Transport != protocol ||
			entry.Key.Encryption != encryption ||
			entry.Key.Address == reverseSessionAddress {
			continue
		}
		delete(daemon.forwardCache, flowKey)
	}
	daemon.forwardCacheMu.Unlock()
}

type sessionForEndpointOptions struct {
	AllowDial                 bool
	ControlOnlyWarmup         bool
	SuppressCanceledDialError bool
	RequireEpoch              bool
	ExpectedEpoch             uint64
}

func (daemon *Daemon) sessionForEndpoint(ctx context.Context, peer config.PeerConfig, cfgEndpoint config.EndpointConfig, flowKey routing.FlowKey, hasFlow bool) (transport.Session, dataSessionKey, *dataSessionRuntime, error) {
	return daemon.sessionForEndpointWithOptions(ctx, peer, cfgEndpoint, flowKey, hasFlow, sessionForEndpointOptions{AllowDial: true})
}

func (daemon *Daemon) sessionForEndpointWithOptions(ctx context.Context, peer config.PeerConfig, cfgEndpoint config.EndpointConfig, flowKey routing.FlowKey, hasFlow bool, options sessionForEndpointOptions) (transport.Session, dataSessionKey, *dataSessionRuntime, error) {
	endpoint := transportEndpointFromConfig(cfgEndpoint)
	endpoint.Enabled = true
	endpoint.Encryption = daemon.endpointDialEncryption(cfgEndpoint)
	poolSize := daemon.sessionPoolSize()
	poolIndex := daemon.sessionPoolIndex(peer.ID, endpoint, flowKey, hasFlow, poolSize, cfgEndpoint)
	key := dataSessionKey{
		Peer:       peer.ID,
		Endpoint:   endpoint.Name,
		Transport:  endpoint.Transport,
		Address:    endpoint.Address,
		Encryption: endpoint.Encryption,
		PoolIndex:  poolIndex,
	}
	epoch := daemon.currentDataSessionEpoch()
	if options.RequireEpoch {
		if options.ExpectedEpoch != epoch {
			return nil, key, nil, errDataSessionEpochChanged
		}
		epoch = options.ExpectedEpoch
	}
	if endpoint.Address == "" {
		if session, reverseKey, runtime := daemon.reverseSessionForEndpoint(peer.ID, cfgEndpoint, endpoint.Encryption, poolIndex); session != nil {
			if options.RequireEpoch && !daemon.dataSessionEpochActive(epoch) {
				return nil, key, nil, errDataSessionEpochChanged
			}
			return session, reverseKey, runtime, nil
		}
		return nil, key, nil, fmt.Errorf("peer %q endpoint %q address is empty", peer.ID, endpoint.Name)
	}
	if daemon.preferReverseSessionForAddressedEndpoint(cfgEndpoint, endpoint.Encryption) {
		if session, reverseKey, runtime := daemon.reverseSessionForEndpoint(peer.ID, cfgEndpoint, endpoint.Encryption, poolIndex); session != nil {
			if options.RequireEpoch && !daemon.dataSessionEpochActive(epoch) {
				return nil, key, nil, errDataSessionEpochChanged
			}
			return session, reverseKey, runtime, nil
		}
	}
	tr, ok := daemon.transports.Get(endpoint.Transport)
	if !ok {
		daemon.dataStats.unsupportedTransport.Add(1)
		return nil, key, nil, fmt.Errorf("transport %q is not registered", endpoint.Transport)
	}

	daemon.dataMu.Lock()
	if options.RequireEpoch && daemon.dataSessionEpoch != epoch {
		daemon.dataMu.Unlock()
		return nil, key, nil, errDataSessionEpochChanged
	}
	if session := daemon.dataSessions[key]; session != nil {
		runtime := daemon.dataSessionState[key]
		daemon.dataMu.Unlock()
		return session, key, runtime, nil
	}
	daemon.dataMu.Unlock()
	if !options.AllowDial {
		if session, reverseKey, runtime := daemon.reverseSessionForEndpoint(peer.ID, cfgEndpoint, endpoint.Encryption, poolIndex); session != nil {
			if options.RequireEpoch && !daemon.dataSessionEpochActive(epoch) {
				return nil, key, nil, errDataSessionEpochChanged
			}
			return session, reverseKey, runtime, nil
		}
		return nil, key, nil, fmt.Errorf("peer %q endpoint %q has no existing data session", peer.ID, endpoint.Name)
	}

	tlsConf, err := daemon.dataTransportClientTLSConfig(peer, cfgEndpoint)
	if err != nil {
		if session, reverseKey, runtime := daemon.reverseSessionForEndpoint(peer.ID, cfgEndpoint, endpoint.Encryption, poolIndex); session != nil {
			if options.RequireEpoch && !daemon.dataSessionEpochActive(epoch) {
				return nil, key, nil, errDataSessionEpochChanged
			}
			return session, reverseKey, runtime, nil
		}
		return nil, key, nil, err
	}
	dialCtx, cancel := context.WithTimeout(ctx, dataPathDialTimeout)
	defer cancel()
	daemon.dataStats.sessionDialAttempts.Add(1)
	session, err := tr.Dial(dialCtx, transport.Peer{
		ID:        peer.ID,
		DomainID:  peer.Domain,
		Endpoints: []transport.Endpoint{endpoint},
	}, tlsConf)
	if err != nil {
		if !options.SuppressCanceledDialError || !errors.Is(err, context.Canceled) {
			daemon.dataStats.sessionDialErrors.Add(1)
			daemon.dataStats.setLastSessionDialError(fmt.Errorf("dial peer %q endpoint %q: %w", peer.ID, endpoint.Name, err))
			daemon.recordEndpointDownIfNoActiveSession(peer.ID, cfgEndpoint, err)
		}
		if session, reverseKey, runtime := daemon.reverseSessionForEndpoint(peer.ID, cfgEndpoint, endpoint.Encryption, poolIndex); session != nil {
			if options.RequireEpoch && !daemon.dataSessionEpochActive(epoch) {
				return nil, key, nil, errDataSessionEpochChanged
			}
			return session, reverseKey, runtime, nil
		}
		return nil, key, nil, fmt.Errorf("dial peer %q endpoint %q: %w", peer.ID, endpoint.Name, err)
	}
	if !daemon.dataSessionEpochActive(epoch) {
		_ = session.Close()
		return nil, key, nil, errDataSessionEpochChanged
	}
	if err := requireEndpointLinkTLS(peer.ID, cfgEndpoint, session); err != nil {
		_ = session.Close()
		daemon.dataStats.sessionDialErrors.Add(1)
		daemon.dataStats.setLastSessionDialError(err)
		daemon.recordEndpointDownIfNoActiveSession(peer.ID, cfgEndpoint, err)
		if fallback, reverseKey, runtime := daemon.reverseSessionForEndpoint(peer.ID, cfgEndpoint, endpoint.Encryption, poolIndex); fallback != nil {
			if options.RequireEpoch && !daemon.dataSessionEpochActive(epoch) {
				return nil, key, nil, errDataSessionEpochChanged
			}
			return fallback, reverseKey, runtime, nil
		}
		return nil, key, nil, err
	}

	daemon.dataMu.Lock()
	if daemon.dataSessionEpoch != epoch {
		daemon.dataMu.Unlock()
		_ = session.Close()
		return nil, key, nil, errDataSessionEpochChanged
	}
	if existing := daemon.dataSessions[key]; existing != nil {
		runtime := daemon.dataSessionState[key]
		daemon.dataMu.Unlock()
		_ = session.Close()
		return existing, key, runtime, nil
	}
	daemon.dataSessions[key] = session
	runtime := daemon.startDataSessionRuntimeLockedWithOptions(key, session, peer, cfgEndpoint, options.ControlOnlyWarmup)
	daemon.dataMu.Unlock()
	daemon.dataStats.sessionDials.Add(1)
	daemon.recordDataSessionTLSObservation(session)
	daemon.syncKernelDatapathSessionUpsert(key, runtime, session)
	daemon.recordEndpointUp(peer.ID, cfgEndpoint, 0)
	if daemon.sessionPoolWarmupEnabled() && poolSize > 1 {
		go daemon.warmSessionPool(context.Background(), epoch, peer, cfgEndpoint, endpoint, poolSize, poolIndex)
	}
	return session, key, runtime, nil
}

func (daemon *Daemon) sessionForEndpointPoolIndex(ctx context.Context, epoch uint64, peer config.PeerConfig, cfgEndpoint config.EndpointConfig, endpoint transport.Endpoint, poolIndex int) (transport.Session, dataSessionKey, error) {
	return daemon.sessionForEndpointPoolIndexWithOptions(ctx, epoch, peer, cfgEndpoint, endpoint, poolIndex, sessionForEndpointOptions{AllowDial: true})
}

func (daemon *Daemon) sessionForEndpointPoolIndexWithOptions(ctx context.Context, epoch uint64, peer config.PeerConfig, cfgEndpoint config.EndpointConfig, endpoint transport.Endpoint, poolIndex int, options sessionForEndpointOptions) (transport.Session, dataSessionKey, error) {
	key := dataSessionKey{
		Peer:       peer.ID,
		Endpoint:   endpoint.Name,
		Transport:  endpoint.Transport,
		Address:    endpoint.Address,
		Encryption: endpoint.Encryption,
		PoolIndex:  poolIndex,
	}
	if options.RequireEpoch && options.ExpectedEpoch != 0 && options.ExpectedEpoch != epoch {
		return nil, key, errDataSessionEpochChanged
	}
	if !daemon.dataSessionEpochActive(epoch) {
		return nil, key, errDataSessionEpochChanged
	}
	if endpoint.Address == "" {
		if session, reverseKey, _ := daemon.reverseSessionForEndpoint(peer.ID, cfgEndpoint, endpoint.Encryption, poolIndex); session != nil {
			if options.RequireEpoch && !daemon.dataSessionEpochActive(epoch) {
				return nil, key, errDataSessionEpochChanged
			}
			return session, reverseKey, nil
		}
		return nil, key, fmt.Errorf("peer %q endpoint %q address is empty", peer.ID, endpoint.Name)
	}
	if daemon.preferReverseSessionForAddressedEndpoint(cfgEndpoint, endpoint.Encryption) {
		if session, reverseKey, _ := daemon.reverseSessionForEndpoint(peer.ID, cfgEndpoint, endpoint.Encryption, poolIndex); session != nil {
			if options.RequireEpoch && !daemon.dataSessionEpochActive(epoch) {
				return nil, key, errDataSessionEpochChanged
			}
			return session, reverseKey, nil
		}
	}
	tr, ok := daemon.transports.Get(endpoint.Transport)
	if !ok {
		daemon.dataStats.unsupportedTransport.Add(1)
		return nil, key, fmt.Errorf("transport %q is not registered", endpoint.Transport)
	}

	daemon.dataMu.Lock()
	if session := daemon.dataSessions[key]; session != nil {
		daemon.dataMu.Unlock()
		return session, key, nil
	}
	daemon.dataMu.Unlock()
	if !options.AllowDial {
		if session, reverseKey, _ := daemon.reverseSessionForEndpoint(peer.ID, cfgEndpoint, endpoint.Encryption, poolIndex); session != nil {
			if options.RequireEpoch && !daemon.dataSessionEpochActive(epoch) {
				return nil, key, errDataSessionEpochChanged
			}
			return session, reverseKey, nil
		}
		return nil, key, fmt.Errorf("peer %q endpoint %q pool %d has no existing data session", peer.ID, endpoint.Name, poolIndex)
	}

	tlsConf, err := daemon.dataTransportClientTLSConfig(peer, cfgEndpoint)
	if err != nil {
		if session, reverseKey, _ := daemon.reverseSessionForEndpoint(peer.ID, cfgEndpoint, endpoint.Encryption, poolIndex); session != nil {
			if options.RequireEpoch && !daemon.dataSessionEpochActive(epoch) {
				return nil, key, errDataSessionEpochChanged
			}
			return session, reverseKey, nil
		}
		return nil, key, err
	}
	dialCtx, cancel := context.WithTimeout(ctx, dataPathDialTimeout)
	defer cancel()
	daemon.dataStats.sessionDialAttempts.Add(1)
	session, err := tr.Dial(dialCtx, transport.Peer{
		ID:        peer.ID,
		DomainID:  peer.Domain,
		Endpoints: []transport.Endpoint{endpoint},
	}, tlsConf)
	if err != nil {
		if !options.SuppressCanceledDialError || !errors.Is(err, context.Canceled) {
			daemon.dataStats.sessionDialErrors.Add(1)
			daemon.dataStats.setLastSessionDialError(fmt.Errorf("dial peer %q endpoint %q pool %d: %w", peer.ID, endpoint.Name, poolIndex, err))
			daemon.recordEndpointDownIfNoActiveSession(peer.ID, cfgEndpoint, err)
		}
		if session, reverseKey, _ := daemon.reverseSessionForEndpoint(peer.ID, cfgEndpoint, endpoint.Encryption, poolIndex); session != nil {
			if options.RequireEpoch && !daemon.dataSessionEpochActive(epoch) {
				return nil, key, errDataSessionEpochChanged
			}
			return session, reverseKey, nil
		}
		return nil, key, fmt.Errorf("dial peer %q endpoint %q pool %d: %w", peer.ID, endpoint.Name, poolIndex, err)
	}
	if !daemon.dataSessionEpochActive(epoch) {
		_ = session.Close()
		return nil, key, errDataSessionEpochChanged
	}
	if err := requireEndpointLinkTLS(peer.ID, cfgEndpoint, session); err != nil {
		_ = session.Close()
		daemon.dataStats.sessionDialErrors.Add(1)
		daemon.dataStats.setLastSessionDialError(err)
		daemon.recordEndpointDownIfNoActiveSession(peer.ID, cfgEndpoint, err)
		if fallback, reverseKey, _ := daemon.reverseSessionForEndpoint(peer.ID, cfgEndpoint, endpoint.Encryption, poolIndex); fallback != nil {
			if options.RequireEpoch && !daemon.dataSessionEpochActive(epoch) {
				return nil, key, errDataSessionEpochChanged
			}
			return fallback, reverseKey, nil
		}
		return nil, key, err
	}

	daemon.dataMu.Lock()
	if daemon.dataSessionEpoch != epoch {
		daemon.dataMu.Unlock()
		_ = session.Close()
		return nil, key, errDataSessionEpochChanged
	}
	if existing := daemon.dataSessions[key]; existing != nil {
		daemon.dataMu.Unlock()
		_ = session.Close()
		return existing, key, nil
	}
	daemon.dataSessions[key] = session
	runtime := daemon.startDataSessionRuntimeLockedWithOptions(key, session, peer, cfgEndpoint, options.ControlOnlyWarmup)
	daemon.dataMu.Unlock()
	daemon.dataStats.sessionDials.Add(1)
	daemon.recordDataSessionTLSObservation(session)
	daemon.syncKernelDatapathSessionUpsert(key, runtime, session)
	daemon.recordEndpointUp(peer.ID, cfgEndpoint, 0)
	return session, key, nil
}

func (daemon *Daemon) reverseSessionForEndpoint(peer core.IXID, endpoint config.EndpointConfig, encryption string, preferredPoolIndex int) (transport.Session, dataSessionKey, *dataSessionRuntime) {
	daemon.dataMu.Lock()
	defer daemon.dataMu.Unlock()
	return daemon.reverseSessionForEndpointLocked(peer, endpoint, encryption, preferredPoolIndex)
}

func (daemon *Daemon) reverseSessionForEndpointLocked(peer core.IXID, endpoint config.EndpointConfig, encryption string, preferredPoolIndex int) (transport.Session, dataSessionKey, *dataSessionRuntime) {
	var selected dataSessionKey
	var found bool
	var selectedActivity int64
	for key, session := range daemon.dataSessions {
		if !reverseDataSessionKeyMatches(key, peer, endpoint, encryption) || session == nil {
			continue
		}
		if preferredPoolIndex >= 0 && key.PoolIndex == preferredPoolIndex {
			return session, key, daemon.dataSessionState[key]
		}
		activity := daemon.dataSessionActivityLocked(key)
		if !found ||
			key.PoolIndex >= 0 && selected.PoolIndex < 0 ||
			(key.PoolIndex >= 0 && selected.PoolIndex >= 0 && activity > selectedActivity) ||
			(activity == selectedActivity && key.PoolIndex < selected.PoolIndex) {
			selected = key
			selectedActivity = activity
			found = true
		}
	}
	if !found {
		return nil, dataSessionKey{}, nil
	}
	return daemon.dataSessions[selected], selected, daemon.dataSessionState[selected]
}

func (daemon *Daemon) shouldDropOutboundDataSessionsForInbound(endpoint config.EndpointConfig) bool {
	return strings.TrimSpace(endpoint.Address) == ""
}

func (daemon *Daemon) shouldKeepExistingKernelUDPReverseSessionLocked(key dataSessionKey, incoming transport.Session) bool {
	if key.Address != reverseSessionAddress ||
		key.Transport != transport.ProtocolUDP ||
		daemon.kernelTransportMode() != dataplane.KernelTransportModeRequireKernel ||
		incoming == nil {
		return false
	}
	stats := incoming.Stats()
	if daemon.shouldKeepExistingFullPlaintextKernelUDPReverseSessionLocked(key, stats) {
		return true
	}
	return daemon.shouldKeepExistingSecureKernelUDPReverseSessionLocked(key, stats)
}

func (daemon *Daemon) shouldKeepExistingFullPlaintextKernelUDPReverseSessionLocked(key dataSessionKey, stats transport.TransportStats) bool {
	if parseSecureTransportEncryption(key.Encryption) != securetransport.EncryptionPlaintext {
		return false
	}
	if !kernelDatapathFullPlaintextEnabledForDesired(daemon.desired) {
		return false
	}
	return !stats.Encrypted && stats.NativeBatching && stats.Datagram
}

func (daemon *Daemon) shouldKeepExistingSecureKernelUDPReverseSessionLocked(key dataSessionKey, stats transport.TransportStats) bool {
	switch parseSecureTransportEncryption(key.Encryption) {
	case securetransport.EncryptionSecure, securetransport.EncryptionSendEncrypted, securetransport.EncryptionReceiveEncrypted:
	default:
		return false
	}
	if !stats.Encrypted || !stats.NativeBatching || !stats.Datagram {
		return false
	}
	activity := daemon.dataSessionActivityLocked(key)
	if activity == 0 {
		return true
	}
	if !daemon.sessionHeartbeatEnabledLocked() {
		return true
	}
	recent := time.Unix(0, activity)
	return time.Since(recent) <= 2*daemon.sessionHeartbeatInterval()
}

func (daemon *Daemon) preferReverseSessionForAddressedKernelUDPSecure(endpoint config.EndpointConfig, encryption string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_SECURE_PREFER_REVERSE_SESSION"))) {
	case "0", "false", "no", "off", "disabled":
		return false
	case "1", "true", "yes", "on", "enabled", "":
	default:
		return true
	}
	if strings.TrimSpace(endpoint.Address) == "" ||
		transport.Protocol(strings.ToLower(strings.TrimSpace(endpoint.Transport))) != transport.ProtocolUDP ||
		daemon.kernelTransportMode() != dataplane.KernelTransportModeRequireKernel {
		return false
	}
	switch parseSecureTransportEncryption(encryption) {
	case securetransport.EncryptionSecure, securetransport.EncryptionSendEncrypted, securetransport.EncryptionReceiveEncrypted:
		return true
	default:
		return false
	}
}

func (daemon *Daemon) preferReverseSessionForAddressedEndpoint(endpoint config.EndpointConfig, encryption string) bool {
	if strings.TrimSpace(endpoint.Address) == "" {
		return false
	}
	switch transport.Protocol(strings.ToLower(strings.TrimSpace(endpoint.Transport))) {
	case transport.ProtocolExperimentalTCP:
		if envTruthyAny("TRUSTIX_EXPERIMENTAL_TCP_SECURE_PREFER_REVERSE_SESSION") {
			return true
		}
		return parseSecureTransportEncryption(encryption) == securetransport.EncryptionPlaintext
	case transport.ProtocolUDP:
		return daemon.preferReverseSessionForAddressedKernelUDPSecure(endpoint, encryption)
	default:
		return false
	}
}

func reverseDataSessionKey(peer core.IXID, endpoint config.EndpointConfig, encryption string) dataSessionKey {
	return dataSessionKey{
		Peer:       peer,
		Endpoint:   endpoint.Name,
		Transport:  transport.Protocol(endpoint.Transport),
		Address:    reverseSessionAddress,
		Encryption: encryption,
		PoolIndex:  0,
	}
}

func reverseDataSessionKeyMatches(key dataSessionKey, peer core.IXID, endpoint config.EndpointConfig, encryption string) bool {
	return key.Peer == peer &&
		key.Endpoint == endpoint.Name &&
		key.Transport == transport.Protocol(endpoint.Transport) &&
		key.Address == reverseSessionAddress &&
		key.Encryption == encryption
}

func (daemon *Daemon) warmSessionPool(ctx context.Context, epoch uint64, peer config.PeerConfig, cfgEndpoint config.EndpointConfig, endpoint transport.Endpoint, poolSize int, selected int) {
	deadline := time.Now().Add(dataSessionPoolWarmupDeadline())
	retryDelay := dataSessionPoolWarmupRetryDelay()
	for {
		missing := daemon.missingSessionPoolIndexes(peer.ID, cfgEndpoint, endpoint.Encryption, poolSize)
		if len(missing) == 0 || !daemon.dataSessionEpochActive(epoch) {
			return
		}
		if selected >= 0 && len(missing) == 1 && missing[0] == selected {
			return
		}
		var wg sync.WaitGroup
		for _, poolIndex := range missing {
			if poolIndex == selected {
				continue
			}
			poolIndex := poolIndex
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _, _ = daemon.sessionForEndpointPoolIndex(ctx, epoch, peer, cfgEndpoint, endpoint, poolIndex)
			}()
		}
		wg.Wait()
		missing = daemon.missingSessionPoolIndexes(peer.ID, cfgEndpoint, endpoint.Encryption, poolSize)
		if len(missing) == 0 || time.Now().After(deadline) || !daemon.dataSessionEpochActive(epoch) {
			return
		}
		timer := time.NewTimer(retryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (daemon *Daemon) missingSessionPoolIndexes(peer core.IXID, endpoint config.EndpointConfig, encryption string, poolSize int) []int {
	if poolSize <= 0 {
		return nil
	}
	seen := make([]bool, poolSize)
	daemon.dataMu.Lock()
	for key, session := range daemon.dataSessions {
		if session == nil || key.PoolIndex < 0 || key.PoolIndex >= poolSize {
			continue
		}
		if (endpoint.Address == "" || daemon.preferReverseSessionForAddressedEndpoint(endpoint, encryption)) && reverseDataSessionKeyMatches(key, peer, endpoint, encryption) ||
			key.Peer == peer &&
				key.Endpoint == endpoint.Name &&
				key.Transport == transport.Protocol(endpoint.Transport) &&
				key.Address == endpoint.Address &&
				key.Encryption == encryption {
			seen[key.PoolIndex] = true
		}
	}
	daemon.dataMu.Unlock()
	missing := make([]int, 0, poolSize)
	for i, ok := range seen {
		if !ok {
			missing = append(missing, i)
		}
	}
	return missing
}

func dataSessionPoolWarmupDeadline() time.Duration {
	raw := strings.TrimSpace(os.Getenv("TRUSTIX_DATA_SESSION_POOL_WARMUP_DEADLINE"))
	if raw == "" {
		return dataSessionPoolWarmupDefaultDeadline
	}
	deadline, err := time.ParseDuration(raw)
	if err != nil || deadline <= 0 {
		return dataSessionPoolWarmupDefaultDeadline
	}
	return deadline
}

func dataSessionPoolWarmupRetryDelay() time.Duration {
	raw := strings.TrimSpace(os.Getenv("TRUSTIX_DATA_SESSION_POOL_WARMUP_RETRY_DELAY"))
	if raw == "" {
		return dataSessionPoolWarmupDefaultRetryDelay
	}
	delay, err := time.ParseDuration(raw)
	if err != nil || delay <= 0 {
		return dataSessionPoolWarmupDefaultRetryDelay
	}
	return delay
}

func (daemon *Daemon) startDataSessionRuntimeLocked(key dataSessionKey, session transport.Session, peer config.PeerConfig, endpoint config.EndpointConfig) *dataSessionRuntime {
	return daemon.startDataSessionRuntimeLockedWithOptions(key, session, peer, endpoint, false)
}

func (daemon *Daemon) startDataSessionRuntimeLockedWithOptions(key dataSessionKey, session transport.Session, peer config.PeerConfig, endpoint config.EndpointConfig, controlOnlyWarmup bool) *dataSessionRuntime {
	if daemon.dataSessionState == nil {
		daemon.dataSessionState = make(map[dataSessionKey]*dataSessionRuntime)
	}
	if existing := daemon.dataSessionState[key]; existing != nil && existing.cancel != nil {
		existing.cancel()
	}
	runtimeCtx, cancel := context.WithCancel(context.Background())
	controlOnly := controlOnlyWarmup || daemon.dataSessionControlOnly(key, endpoint)
	if controlOnly && key.Transport == transport.ProtocolExperimentalTCP && experimentalTCPCompatStreamSession(session) {
		controlOnly = false
	}
	if controlOnlyWarmup && controlOnly && key.Transport == transport.ProtocolUDP {
		retainKernelFlowOnClose(session)
	}
	receiveData := !controlOnly || daemon.controlOnlySessionReceivesData(key, session)
	receiveLoop := receiveData && !daemon.kernelDatapathFullPlaintextOwnsSessionReceive(key)
	runtime := &dataSessionRuntime{
		key:         key,
		session:     session,
		peer:        peer,
		endpoint:    endpoint,
		cancel:      cancel,
		batching:    daemon.dataSessionBatchConfigForEndpoint(endpoint),
		batchNotify: make(chan struct{}, 1),
		controlOnly: controlOnly,
		receiveData: receiveData,
		receiveLoop: receiveLoop,
	}
	now := time.Now().UTC().UnixNano()
	runtime.lastPong.Store(now)
	runtime.lastRX.Store(now)
	runtime.lastTX.Store(now)
	runtime.lastUp.Store(now)
	daemon.dataSessionState[key] = runtime
	runtime.cacheSessionCapabilities(session)
	if runtime.receiveLoop {
		go daemon.receiveDataPathSession(runtimeCtx, runtime, session)
	}
	if runtime.receiveLoop && daemon.sessionHeartbeatEnabledLocked() {
		go daemon.runDataSessionHeartbeat(runtimeCtx, runtime)
	}
	if runtime.batching.enabled {
		go daemon.runDataSessionBatchFlusher(runtimeCtx, runtime)
	}
	return runtime
}

func (daemon *Daemon) kernelDatapathFullPlaintextOwnsSessionReceive(key dataSessionKey) bool {
	if key.Transport != transport.ProtocolUDP {
		return false
	}
	if parseSecureTransportEncryption(key.Encryption) != securetransport.EncryptionPlaintext {
		return false
	}
	if config.EffectiveTransportProfile(daemon.desired.TransportPolicy, string(transport.ProtocolUDP)).Datapath == config.TransportDatapathUserspace {
		return false
	}
	return kernelDatapathFullPlaintextEnabledForDesired(daemon.desired)
}

func (daemon *Daemon) controlOnlySessionReceivesData(key dataSessionKey, session transport.Session) bool {
	if key.Transport != transport.ProtocolUDP || session == nil {
		return false
	}
	stats := session.Stats()
	return stats.Datagram && (stats.NativeBatching || stats.FragmentingDatagram || stats.MaxPacketSize > 0)
}

func retainKernelFlowOnClose(session transport.Session) {
	if session == nil {
		return
	}
	retainer, ok := session.(transport.KernelFlowRetentionSession)
	if !ok {
		return
	}
	retainer.RetainKernelFlowOnClose()
}

func experimentalTCPCompatStreamSession(session transport.Session) bool {
	if session == nil {
		return false
	}
	stats := session.Stats()
	return stats.Extra != nil && stats.Extra["experimental_tcp_compat_stream"] != 0
}

func (daemon *Daemon) dataSessionControlOnly(key dataSessionKey, endpoint config.EndpointConfig) bool {
	if !daemon.kernelUDPTCOnlyProviderRequested() {
		return false
	}
	if key.Transport == transport.ProtocolExperimentalTCP && experimentalTCPCompatStreamEnabledForPolicy() {
		return false
	}
	if key.Transport == transport.ProtocolExperimentalTCP && (!kernelUDPTXDirectExperimentalTCPOnlyRequestedForPolicy() || experimentalTCPTXDirectRequestedForPolicy()) {
		return false
	}
	if key.Transport != transport.ProtocolUDP && key.Transport != transport.ProtocolExperimentalTCP {
		return false
	}
	encryption := key.Encryption
	if strings.TrimSpace(encryption) == "" {
		encryption = daemon.endpointDialEncryption(endpoint)
	}
	return daemon.kernelDirectOnlyEndpointEncryption(encryption)
}

func (daemon *Daemon) sendDataSessionPacket(runtime *dataSessionRuntime, session transport.Session, packet []byte) error {
	packets, err := daemon.splitDataSessionPacketsForMTU(runtime, session, [][]byte{packet})
	if err != nil {
		return err
	}
	if len(packets) != 1 {
		return daemon.sendDataSessionPackets(runtime, session, packets)
	}
	packet = packets[0]
	if runtime == nil {
		return session.SendPacket(packet)
	}
	runtime.ensureBatchConfig()
	if runtime.batching.enabled && !isDataSessionControlPacket(packet) {
		if dataSessionNativeBatchingPreferred(runtime, session, runtime.batching.enabled) {
			if err := daemon.flushDataSessionBatch(runtime); err != nil {
				return err
			}
			return daemon.sendDataSessionWirePacket(runtime, session, packet)
		}
		return daemon.queueDataSessionPacket(runtime, session, packet)
	}
	if err := daemon.flushDataSessionBatch(runtime); err != nil {
		return err
	}
	runtime.sendMu.Lock()
	defer runtime.sendMu.Unlock()
	if err := session.SendPacket(packet); err != nil {
		return err
	}
	runtime.lastTX.Store(time.Now().UTC().UnixNano())
	return nil
}

func (daemon *Daemon) sendDataSessionPackets(runtime *dataSessionRuntime, session transport.Session, packets [][]byte) error {
	if len(packets) == 0 {
		return nil
	}
	var err error
	packets, err = daemon.splitDataSessionPacketsForMTU(runtime, session, packets)
	if err != nil {
		return err
	}
	if len(packets) == 1 {
		return daemon.sendDataSessionPacket(runtime, session, packets[0])
	}
	if runtime == nil {
		if batch, ok := session.(transport.PacketBatchSession); ok {
			return batch.SendPackets(packets)
		}
		for _, packet := range packets {
			if err := session.SendPacket(packet); err != nil {
				return err
			}
		}
		return nil
	}
	runtime.ensureBatchConfig()
	if runtime.batching.enabled {
		if dataSessionNativeBatchingPreferred(runtime, session, runtime.batching.enabled) {
			if err := daemon.flushDataSessionBatch(runtime); err != nil {
				return err
			}
			runtime.sendMu.Lock()
			defer runtime.sendMu.Unlock()
			if err := session.(transport.PacketBatchSession).SendPackets(packets); err != nil {
				return err
			}
			runtime.lastTX.Store(time.Now().UTC().UnixNano())
			return nil
		}
		return daemon.queueDataSessionPackets(runtime, session, packets)
	}
	if err := daemon.flushDataSessionBatch(runtime); err != nil {
		return err
	}
	runtime.sendMu.Lock()
	defer runtime.sendMu.Unlock()
	if batch, ok := session.(transport.PacketBatchSession); ok {
		if err := batch.SendPackets(packets); err != nil {
			return err
		}
		runtime.lastTX.Store(time.Now().UTC().UnixNano())
		return nil
	}
	for _, packet := range packets {
		if err := session.SendPacket(packet); err != nil {
			return err
		}
	}
	runtime.lastTX.Store(time.Now().UTC().UnixNano())
	return nil
}

func (daemon *Daemon) splitDataSessionPacketsForMTU(runtime *dataSessionRuntime, session transport.Session, packets [][]byte) ([][]byte, error) {
	if len(packets) == 0 || session == nil {
		return packets, nil
	}
	stats := dataSessionTransportStats(runtime, session)
	if !stats.Datagram || stats.MaxPacketSize == 0 || stats.MaxPacketSize > uint64(int(^uint(0)>>1)) {
		return packets, nil
	}
	maxPacket := int(stats.MaxPacketSize)
	if maxPacket <= 0 {
		return packets, nil
	}
	segmentFragmentingDatagram := !stats.FragmentingDatagram || dataSessionSegmentFragmentingDatagramEnabled()
	var out [][]byte
	var splitPackets, splitWires, splitBytes uint64
	var splitFrames uint64
	var splitFragmentingDatagram uint64
	for i, packet := range packets {
		if len(packet) <= maxPacket {
			if out != nil {
				out = append(out, packet)
			}
			continue
		}
		if !segmentFragmentingDatagram {
			if out != nil {
				out = append(out, packet)
			}
			continue
		}
		segments, err := segmentDataSessionIPv4TCPPacket(packet, maxPacket)
		if err != nil {
			daemon.dataStats.sendSoftwareSegmentDrops.Add(1)
			return nil, err
		}
		if out == nil {
			out = make([][]byte, 0, len(packets)+len(segments))
			for _, prior := range packets[:i] {
				out = append(out, prior)
			}
		}
		out = append(out, segments...)
		splitFrames += uint64(len(segments))
		splitPackets++
		splitWires += uint64(len(segments))
		if stats.FragmentingDatagram {
			splitFragmentingDatagram++
		}
		for _, segment := range segments {
			splitBytes += uint64(len(segment))
		}
	}
	if out == nil {
		return packets, nil
	}
	daemon.dataStats.sendSoftwareSegments.Add(splitPackets)
	daemon.dataStats.sendSoftwareSegmentFrames.Add(splitFrames)
	daemon.dataStats.sendSoftwareSegmentWires.Add(splitWires)
	daemon.dataStats.sendSoftwareSegmentBytes.Add(splitBytes)
	if splitFragmentingDatagram > 0 {
		daemon.dataStats.sendSoftwareSegmentFragDatagram.Add(splitFragmentingDatagram)
	}
	return out, nil
}

func segmentDataSessionIPv4TCPPacket(packet []byte, mtu int) ([][]byte, error) {
	if len(packet) <= mtu {
		return [][]byte{packet}, nil
	}
	meta, err := dataSessionIPv4TCPSegmentationMetaForPacket(packet, mtu)
	if err != nil {
		return nil, err
	}
	payload := packet[meta.payloadOffset:meta.totalLen]
	segments := make([][]byte, 0, (len(payload)+meta.maxPayload-1)/meta.maxPayload)
	originalSeq := binary.BigEndian.Uint32(packet[meta.tcpOffset+4 : meta.tcpOffset+8])
	originalID := binary.BigEndian.Uint16(packet[meta.ipOffset+4 : meta.ipOffset+6])
	for offset := 0; offset < len(payload); offset += meta.maxPayload {
		chunkLen := min(meta.maxPayload, len(payload)-offset)
		segmentLen := meta.ihl + meta.tcpHeaderLen + chunkLen
		segment := make([]byte, segmentLen)
		ip := packet[meta.ipOffset : meta.ipOffset+meta.ihl]
		tcp := packet[meta.tcpOffset:meta.payloadOffset]
		copy(segment[:meta.ihl], ip)
		copy(segment[meta.ihl:meta.ihl+meta.tcpHeaderLen], tcp)
		copy(segment[meta.ihl+meta.tcpHeaderLen:], payload[offset:offset+chunkLen])

		binary.BigEndian.PutUint16(segment[2:4], uint16(segmentLen))
		binary.BigEndian.PutUint16(segment[4:6], originalID+uint16(len(segments)))
		binary.BigEndian.PutUint16(segment[10:12], 0)
		binary.BigEndian.PutUint16(segment[10:12], ipv4Checksum(segment[:meta.ihl]))

		segmentTCP := segment[meta.ihl:]
		binary.BigEndian.PutUint32(segmentTCP[4:8], originalSeq+uint32(offset))
		if offset+chunkLen < len(payload) {
			segmentTCP[13] &^= tcpFlagFIN | tcpFlagPSH
		}
		binary.BigEndian.PutUint16(segmentTCP[16:18], 0)
		binary.BigEndian.PutUint16(segmentTCP[16:18], transportChecksum(segment[12:16], segment[16:20], ipProtocolTCP, segmentTCP))
		segments = append(segments, segment)
	}
	return segments, nil
}

type dataSessionIPv4TCPSegmentationMeta struct {
	ipOffset      int
	ihl           int
	totalLen      int
	tcpOffset     int
	tcpHeaderLen  int
	payloadOffset int
	maxPayload    int
}

func dataSessionIPv4TCPSegmentationMetaForPacket(packet []byte, mtu int) (dataSessionIPv4TCPSegmentationMeta, error) {
	fail := func(format string, args ...any) (dataSessionIPv4TCPSegmentationMeta, error) {
		return dataSessionIPv4TCPSegmentationMeta{}, fmt.Errorf("packet size %d exceeds datagram max %d and cannot be segmented: "+format, append([]any{len(packet), mtu}, args...)...)
	}
	if mtu <= ipv4HeaderLen+20 {
		return fail("datagram max cannot carry IPv4/TCP headers")
	}
	ipOffset, ihl, totalLen, err := ipv4HeaderBounds(packet)
	if err != nil {
		return fail("%v", err)
	}
	if ipOffset != 0 {
		return fail("Ethernet-framed packets are not valid data session payloads")
	}
	if totalLen != len(packet) {
		return fail("IPv4 total length %d differs from packet length %d", totalLen, len(packet))
	}
	ip := packet[ipOffset : ipOffset+totalLen]
	if ip[9] != ipProtocolTCP {
		return fail("protocol %d is not TCP", ip[9])
	}
	flagsAndFragment := binary.BigEndian.Uint16(ip[6:8])
	if flagsAndFragment&(ipv4MoreFragments|ipv4FragmentOffsetMask) != 0 {
		return fail("packet is already fragmented")
	}
	tcpOffset := ipOffset + ihl
	if len(packet) < tcpOffset+20 {
		return fail("packet is too short for TCP")
	}
	tcpHeaderLen := int(packet[tcpOffset+12]>>4) * 4
	if tcpHeaderLen < 20 || len(packet) < tcpOffset+tcpHeaderLen {
		return fail("invalid TCP header length %d", tcpHeaderLen)
	}
	tcpFlags := packet[tcpOffset+13]
	if tcpFlags&(tcpFlagSYN|tcpFlagRST) != 0 {
		return fail("unsupported TCP flags %#x", tcpFlags)
	}
	payloadOffset := tcpOffset + tcpHeaderLen
	if payloadOffset >= len(packet) {
		return fail("TCP packet has no payload to segment")
	}
	maxPayload := mtu - ihl - tcpHeaderLen
	if maxPayload <= 0 {
		return fail("datagram max cannot carry IPv4/TCP headers of %d bytes", ihl+tcpHeaderLen)
	}
	return dataSessionIPv4TCPSegmentationMeta{
		ipOffset:      ipOffset,
		ihl:           ihl,
		totalLen:      totalLen,
		tcpOffset:     tcpOffset,
		tcpHeaderLen:  tcpHeaderLen,
		payloadOffset: payloadOffset,
		maxPayload:    maxPayload,
	}, nil
}

func dataSessionNativeBatchingPreferred(runtime *dataSessionRuntime, session transport.Session, dataBatchingEnabled bool) bool {
	if session == nil || !dataBatchingEnabled {
		return false
	}
	if _, ok := session.(transport.PacketBatchSession); !ok {
		return false
	}
	stats := dataSessionTransportStats(runtime, session)
	if dataSessionBatchAggregationPreferred(runtime, stats, dataBatchingEnabled) {
		return false
	}
	return transportNativeBatchingPreferredForStats(stats, dataBatchingEnabled)
}

func transportNativeBatchingPreferredForStats(stats transport.TransportStats, dataBatchingEnabled bool) bool {
	if !dataBatchingEnabled || !stats.NativeBatching {
		return false
	}
	if stats.Encrypted && stats.CryptoPlacement == string(dataplane.CryptoPlacementKernel) {
		if native, explicit := dataSessionKernelCryptoNativeBatchingPreference(); native || explicit {
			return native
		}
	}
	if stats.Encrypted && dataSessionEncryptedBatchAggregationEnabled() {
		return false
	}
	if !stats.Encrypted && stats.Datagram && stats.MaxPacketSize > 0 && dataSessionPlaintextBatchAggregationEnabled() {
		return false
	}
	if stats.Encrypted && stats.Datagram && stats.MaxPacketSize > 0 {
		return true
	}
	return true
}

func dataSessionBatchAggregationPreferred(runtime *dataSessionRuntime, stats transport.TransportStats, dataBatchingEnabled bool) bool {
	if !dataBatchingEnabled || !stats.Datagram || stats.MaxPacketSize == 0 {
		return false
	}
	if stats.Encrypted && stats.CryptoPlacement == string(dataplane.CryptoPlacementKernel) {
		if native, explicit := dataSessionKernelCryptoNativeBatchingPreference(); native || explicit {
			return !native
		}
	}
	if stats.Encrypted {
		if enabled, explicit := dataSessionEncryptedBatchAggregationPreference(); explicit {
			return enabled
		}
		return dataSessionEncryptedBatchAggregationDefault(runtime)
	}
	if enabled, explicit := dataSessionPlaintextBatchAggregationPreference(); explicit {
		return enabled
	}
	return dataSessionExperimentalTCPBatchAggregationDefault(runtime)
}

func dataSessionEncryptedBatchAggregationDefault(runtime *dataSessionRuntime) bool {
	switch dataSessionRuntimeTransport(runtime) {
	case transport.ProtocolExperimentalTCP:
		return dataSessionExperimentalTCPBatchAggregationDefault(runtime)
	case transport.ProtocolGRE, transport.ProtocolIPIP, transport.ProtocolVXLAN:
		return true
	default:
		return false
	}
}

func dataSessionExperimentalTCPBatchAggregationDefault(runtime *dataSessionRuntime) bool {
	if enabled, explicit := dataSessionExperimentalTCPBatchAggregationEnabled(); explicit {
		return enabled
	}
	return dataSessionRuntimeTransport(runtime) == transport.ProtocolExperimentalTCP
}

func dataSessionRuntimeTransport(runtime *dataSessionRuntime) transport.Protocol {
	if runtime == nil {
		return ""
	}
	if runtime.key.Transport != "" {
		return runtime.key.Transport
	}
	if runtime.endpoint.Transport != "" {
		return transport.Protocol(strings.ToLower(strings.TrimSpace(runtime.endpoint.Transport)))
	}
	return ""
}

func dataSessionBatchMaxBytesForSession(maxBytes int, session transport.Session) int {
	if maxBytes <= 0 {
		maxBytes = dataSessionBatchDefaultBytes
	}
	if session == nil {
		return maxBytes
	}
	return dataSessionBatchMaxBytesForStats(maxBytes, session.Stats())
}

func dataSessionBatchMaxBytesForRuntime(maxBytes int, runtime *dataSessionRuntime, session transport.Session) int {
	if maxBytes <= 0 {
		maxBytes = dataSessionBatchDefaultBytes
	}
	if session == nil {
		return maxBytes
	}
	return dataSessionBatchMaxBytesForStats(maxBytes, dataSessionTransportStats(runtime, session))
}

func dataSessionBatchMaxBytesForStats(maxBytes int, stats transport.TransportStats) int {
	if maxBytes <= 0 {
		maxBytes = dataSessionBatchDefaultBytes
	}
	if stats.Encrypted && stats.CryptoPlacement == string(dataplane.CryptoPlacementKernel) {
		if kernelMax := dataSessionKernelCryptoBatchBytes(); maxBytes > kernelMax {
			maxBytes = kernelMax
		}
	} else if stats.Encrypted {
		if userMax := dataSessionUserspaceEncryptedBatchBytes(); maxBytes > userMax {
			if userMax > 0 {
				maxBytes = userMax
			}
		}
	}
	if stats.Datagram && !stats.FragmentingDatagram && stats.MaxPacketSize > 0 {
		maxPacket := int(stats.MaxPacketSize)
		if maxPacket > 0 && maxBytes > maxPacket {
			maxBytes = maxPacket
		}
	}
	return maxBytes
}

func dataSessionTransportStats(runtime *dataSessionRuntime, session transport.Session) transport.TransportStats {
	if runtime != nil {
		if stats, ok := runtime.cachedSessionCapabilities(); ok {
			if dataSessionCapabilitiesNeedRefresh(runtime, stats, session) {
				refreshed := session.Stats()
				runtime.storeSessionCapabilities(refreshed)
				return refreshed
			}
			return stats
		}
	}
	if session == nil {
		return transport.TransportStats{}
	}
	stats := session.Stats()
	if runtime != nil {
		runtime.storeSessionCapabilities(stats)
	}
	return stats
}

func (runtime *dataSessionRuntime) cacheSessionCapabilities(session transport.Session) {
	if runtime == nil || session == nil {
		return
	}
	runtime.storeSessionCapabilities(session.Stats())
}

func dataSessionCapabilitiesNeedRefresh(runtime *dataSessionRuntime, stats transport.TransportStats, session transport.Session) bool {
	if runtime == nil || session == nil {
		return false
	}
	if !dataSessionRuntimeExpectsEncrypted(runtime) {
		return false
	}
	if !stats.Encrypted || strings.TrimSpace(stats.CryptoPlacement) == "" {
		return true
	}
	if stats.SendEncrypted && stats.Datagram && stats.MaxPacketSize == 0 {
		return true
	}
	return false
}

func dataSessionRuntimeExpectsEncrypted(runtime *dataSessionRuntime) bool {
	if runtime == nil {
		return false
	}
	encryption := strings.TrimSpace(runtime.key.Encryption)
	if encryption == "" {
		encryption = strings.TrimSpace(endpointTransportEncryption(runtime.endpoint))
	}
	if encryption == "" {
		return false
	}
	switch parseSecureTransportEncryption(encryption) {
	case securetransport.EncryptionSecure, securetransport.EncryptionSendEncrypted, securetransport.EncryptionReceiveEncrypted:
		return true
	default:
		return false
	}
}

func (runtime *dataSessionRuntime) cachedSessionCapabilities() (transport.TransportStats, bool) {
	if runtime == nil {
		return transport.TransportStats{}, false
	}
	value := runtime.capabilities.Load()
	if value == nil {
		return transport.TransportStats{}, false
	}
	stats, ok := value.(transport.TransportStats)
	return stats, ok
}

func (runtime *dataSessionRuntime) storeSessionCapabilities(stats transport.TransportStats) {
	if runtime == nil {
		return
	}
	runtime.capabilities.Store(stats)
}

func (runtime *dataSessionRuntime) ensureBatchConfig() {
	if runtime.batching.ready {
		return
	}
	runtime.batchMu.Lock()
	if !runtime.batching.ready {
		runtime.batching = dataSessionBatchConfigFromEnv()
	}
	runtime.batchMu.Unlock()
}

func initDataSessionBatchLocked(batch *dataSessionBatch, now time.Time) {
	if batch.count != 0 {
		return
	}
	if batch.payload == nil && batch.reuse != nil {
		batch.payload = batch.reuse[:0]
		batch.reuse = nil
	}
	batch.payload = append(batch.payload[:0], dataSessionBatchMagic[:]...)
	batch.payload = append(batch.payload, dataSessionBatchVersion, 0, 0, 0)
	batch.firstSeen = now
	batch.lastFailed = false
	batch.lastError = nil
}

func takeDataSessionBatchPayloadLocked(batch *dataSessionBatch) []byte {
	if batch.count == 0 {
		return nil
	}
	payload := batch.payload
	if len(payload) >= dataSessionBatchHeaderLen {
		binary.BigEndian.PutUint16(payload[6:8], uint16(batch.count))
	}
	batch.payload = nil
	batch.count = 0
	batch.firstSeen = time.Time{}
	return payload
}

func recycleDataSessionBatchPayloadLocked(batch *dataSessionBatch, payload []byte) {
	if batch == nil || cap(payload) == 0 || cap(payload) > dataSessionBatchPayloadRetainMax {
		return
	}
	batch.reuse = payload[:0]
}

func (daemon *Daemon) releaseDataSessionBatchPayload(runtime *dataSessionRuntime, payload []byte) {
	if runtime == nil || payload == nil {
		return
	}
	runtime.batchMu.Lock()
	recycleDataSessionBatchPayloadLocked(&runtime.batch, payload)
	runtime.batchMu.Unlock()
}

func (daemon *Daemon) queueDataSessionPacket(runtime *dataSessionRuntime, session transport.Session, packet []byte) error {
	return daemon.queueDataSessionPackets(runtime, session, [][]byte{packet})
}

func (daemon *Daemon) queueDataSessionPackets(runtime *dataSessionRuntime, session transport.Session, packets [][]byte) error {
	if len(packets) == 0 {
		return nil
	}
	maxBytes := dataSessionBatchMaxBytesForRuntime(runtime.batching.maxBytes, runtime, session)
	now := time.Now()
	var flushes [][]byte
	var directs [][]byte
	runtime.batchMu.Lock()
	for _, packet := range packets {
		if isDataSessionControlPacket(packet) ||
			len(packet)+dataSessionBatchHeaderLen+dataSessionBatchItemHeaderLen > maxBytes ||
			len(packet) > 0xffff {
			if payload := takeDataSessionBatchPayloadLocked(&runtime.batch); len(payload) > 0 {
				flushes = append(flushes, payload)
			}
			directs = append(directs, packet)
			continue
		}
		initDataSessionBatchLocked(&runtime.batch, now)
		need := dataSessionBatchItemHeaderLen + len(packet)
		if runtime.batch.count > 0 && len(runtime.batch.payload)+need > maxBytes {
			if payload := takeDataSessionBatchPayloadLocked(&runtime.batch); len(payload) > 0 {
				flushes = append(flushes, payload)
			}
			initDataSessionBatchLocked(&runtime.batch, now)
		}
		runtime.batch.payload = binary.BigEndian.AppendUint16(runtime.batch.payload, uint16(len(packet)))
		runtime.batch.payload = append(runtime.batch.payload, packet...)
		runtime.batch.count++
		daemon.dataStats.recordDataSessionBatchQueued(packet)
		if runtime.batch.count >= runtime.batching.maxPackets ||
			len(runtime.batch.payload) >= maxBytes ||
			(runtime.batching.delay > 0 && now.Sub(runtime.batch.firstSeen) >= runtime.batching.delay) {
			if payload := takeDataSessionBatchPayloadLocked(&runtime.batch); len(payload) > 0 {
				flushes = append(flushes, payload)
			}
		}
	}
	if runtime.batching.delay == 0 {
		if payload := takeDataSessionBatchPayloadLocked(&runtime.batch); len(payload) > 0 {
			flushes = append(flushes, payload)
		}
	}
	pendingBatch := runtime.batch.count > 0
	runtime.batchMu.Unlock()
	if pendingBatch {
		runtime.notifyBatchPending()
	}
	if err := daemon.sendDataSessionWirePackets(runtime, session, flushes); err != nil {
		daemon.rememberDataSessionBatchError(runtime, err)
		return err
	}
	for _, payload := range flushes {
		daemon.dataStats.recordDataSessionBatchFlush(payload)
		daemon.releaseDataSessionBatchPayload(runtime, payload)
	}
	if err := daemon.sendDataSessionWirePackets(runtime, session, directs); err != nil {
		return err
	}
	for _, packet := range directs {
		daemon.dataStats.recordDataSessionBatchDirect(packet)
	}
	return nil
}

func (daemon *Daemon) flushDataSessionBatch(runtime *dataSessionRuntime) error {
	if runtime == nil {
		return nil
	}
	runtime.batchMu.Lock()
	if runtime.batch.lastFailed {
		err := runtime.batch.lastError
		runtime.batchMu.Unlock()
		if err != nil {
			return err
		}
		return fmt.Errorf("data session batch send failed")
	}
	if runtime.batch.count == 0 {
		runtime.batchMu.Unlock()
		return nil
	}
	payload := takeDataSessionBatchPayloadLocked(&runtime.batch)
	session := runtime.session
	runtime.batchMu.Unlock()
	if err := daemon.sendDataSessionWirePacket(runtime, session, payload); err != nil {
		daemon.rememberDataSessionBatchError(runtime, err)
		return err
	}
	daemon.dataStats.recordDataSessionBatchFlush(payload)
	daemon.releaseDataSessionBatchPayload(runtime, payload)
	return nil
}

func cloneDataSessionBatchPayload(payload []byte, count int) []byte {
	out := append([]byte(nil), payload...)
	if len(out) >= dataSessionBatchHeaderLen {
		binary.BigEndian.PutUint16(out[6:8], uint16(count))
	}
	return out
}

func (daemon *Daemon) runDataSessionBatchFlusher(ctx context.Context, runtime *dataSessionRuntime) {
	delay := runtime.batching.delay
	if delay <= 0 {
		return
	}
	for {
		select {
		case <-ctx.Done():
			_ = daemon.flushDataSessionBatch(runtime)
			return
		case <-runtime.batchNotify:
		}
		for {
			wait, pending := runtime.batchFlushWait(delay)
			if !pending {
				break
			}
			if wait <= 0 {
				_ = daemon.flushDataSessionBatch(runtime)
				continue
			}
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				stopTimer(timer)
				_ = daemon.flushDataSessionBatch(runtime)
				return
			case <-runtime.batchNotify:
				stopTimer(timer)
				continue
			case <-timer.C:
				_ = daemon.flushDataSessionBatch(runtime)
			}
		}
	}
}

func stopTimer(timer *time.Timer) {
	if timer == nil || timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}

func (runtime *dataSessionRuntime) notifyBatchPending() {
	if runtime == nil || runtime.batchNotify == nil {
		return
	}
	select {
	case runtime.batchNotify <- struct{}{}:
	default:
	}
}

func (runtime *dataSessionRuntime) batchFlushWait(delay time.Duration) (time.Duration, bool) {
	if runtime == nil {
		return 0, false
	}
	runtime.batchMu.Lock()
	defer runtime.batchMu.Unlock()
	if runtime.batch.count == 0 {
		return 0, false
	}
	if runtime.batch.firstSeen.IsZero() {
		return 0, true
	}
	return delay - time.Since(runtime.batch.firstSeen), true
}

func (daemon *Daemon) flushAllDataSessionBatches() {
	daemon.dataMu.Lock()
	runtimes := make([]*dataSessionRuntime, 0, len(daemon.dataSessionState))
	for _, runtime := range daemon.dataSessionState {
		if runtime != nil {
			runtimes = append(runtimes, runtime)
		}
	}
	daemon.dataMu.Unlock()
	for _, runtime := range runtimes {
		_ = daemon.flushDataSessionBatch(runtime)
	}
}

func (daemon *Daemon) sendDataSessionWirePacket(runtime *dataSessionRuntime, session transport.Session, packet []byte) error {
	if runtime == nil {
		return session.SendPacket(packet)
	}
	runtime.sendMu.Lock()
	defer runtime.sendMu.Unlock()
	if err := session.SendPacket(packet); err != nil {
		return err
	}
	runtime.lastTX.Store(time.Now().UTC().UnixNano())
	return nil
}

func (daemon *Daemon) trySendDataSessionControlPacket(runtime *dataSessionRuntime, session transport.Session, packet []byte) (bool, error) {
	if runtime == nil {
		return true, session.SendPacket(packet)
	}
	if !runtime.sendMu.TryLock() {
		return false, nil
	}
	defer runtime.sendMu.Unlock()
	if err := session.SendPacket(packet); err != nil {
		return true, err
	}
	runtime.lastTX.Store(time.Now().UTC().UnixNano())
	return true, nil
}

func (daemon *Daemon) sendDataSessionWirePackets(runtime *dataSessionRuntime, session transport.Session, packets [][]byte) error {
	if len(packets) == 0 {
		return nil
	}
	if len(packets) == 1 {
		return daemon.sendDataSessionWirePacket(runtime, session, packets[0])
	}
	if runtime == nil {
		if batch, ok := session.(transport.PacketBatchSession); ok {
			return batch.SendPackets(packets)
		}
		for _, packet := range packets {
			if err := session.SendPacket(packet); err != nil {
				return err
			}
		}
		return nil
	}
	runtime.sendMu.Lock()
	defer runtime.sendMu.Unlock()
	if batch, ok := session.(transport.PacketBatchSession); ok {
		if err := batch.SendPackets(packets); err != nil {
			return err
		}
		runtime.lastTX.Store(time.Now().UTC().UnixNano())
		return nil
	}
	for _, packet := range packets {
		if err := session.SendPacket(packet); err != nil {
			return err
		}
	}
	runtime.lastTX.Store(time.Now().UTC().UnixNano())
	return nil
}

func (daemon *Daemon) rememberDataSessionBatchError(runtime *dataSessionRuntime, err error) {
	if runtime == nil || err == nil {
		return
	}
	runtime.batchMu.Lock()
	runtime.batch.lastFailed = true
	runtime.batch.lastError = err
	runtime.batchMu.Unlock()
}

func (daemon *Daemon) refreshEndpointUp(runtime *dataSessionRuntime, peer core.IXID, endpoint config.EndpointConfig) {
	if runtime == nil {
		daemon.recordEndpointUp(peer, endpoint, 0)
		return
	}
	now := time.Now().UTC()
	nowUnix := now.UnixNano()
	last := runtime.lastUp.Load()
	if last > 0 && nowUnix-last < dataSessionEndpointUpRefreshInterval.Nanoseconds() {
		return
	}
	if runtime.lastUp.CompareAndSwap(last, nowUnix) {
		daemon.recordEndpointUp(peer, endpoint, 0)
	}
}

func (daemon *Daemon) currentDataSessionEpoch() uint64 {
	daemon.dataMu.Lock()
	defer daemon.dataMu.Unlock()
	return daemon.dataSessionEpoch
}

func (daemon *Daemon) dataSessionEpochActive(epoch uint64) bool {
	daemon.dataMu.Lock()
	defer daemon.dataMu.Unlock()
	return daemon.dataSessionEpoch == epoch
}

func (daemon *Daemon) sessionPoolSize() int {
	size := daemon.desired.TransportPolicy.SessionPool.Size
	if size <= 0 {
		return 1
	}
	return size
}

func (daemon *Daemon) sessionPoolWarmupEnabled() bool {
	return daemon.desired.TransportPolicy.SessionPool.Warmup
}

func (daemon *Daemon) sessionHeartbeatEnabledLocked() bool {
	switch strings.ToLower(strings.TrimSpace(daemon.desired.TransportPolicy.SessionPool.Heartbeat.Mode)) {
	case "enabled", "on":
		return true
	case "disabled", "off":
		return false
	default:
		return daemon.desired.TransportPolicy.SessionPool.Size > 1
	}
}

func (daemon *Daemon) sessionHeartbeatInterval() time.Duration {
	raw := strings.TrimSpace(daemon.desired.TransportPolicy.SessionPool.Heartbeat.Interval)
	if raw == "" {
		return dataSessionHeartbeatDefaultInterval
	}
	interval, err := time.ParseDuration(raw)
	if err != nil || interval <= 0 {
		return dataSessionHeartbeatDefaultInterval
	}
	return interval
}

func (daemon *Daemon) sessionHeartbeatTimeout() time.Duration {
	raw := strings.TrimSpace(daemon.desired.TransportPolicy.SessionPool.Heartbeat.Timeout)
	if raw == "" {
		return dataSessionHeartbeatDefaultTimeout
	}
	timeout, err := time.ParseDuration(raw)
	if err != nil || timeout <= 0 {
		return dataSessionHeartbeatDefaultTimeout
	}
	return timeout
}

func (daemon *Daemon) sessionPoolStrategy() string {
	switch strings.ToLower(strings.TrimSpace(daemon.desired.TransportPolicy.SessionPool.Strategy)) {
	case "packet", "round_robin":
		return "packet"
	default:
		return "flow"
	}
}

func (daemon *Daemon) sessionPoolIndex(peer core.IXID, endpoint transport.Endpoint, flowKey routing.FlowKey, hasFlow bool, poolSize int, cfgEndpoint config.EndpointConfig) int {
	if poolSize <= 1 {
		return 0
	}
	if daemon.sessionPoolStrategy() == "packet" || !hasFlow {
		return daemon.nextPacketPoolIndex(peer, endpoint, poolSize)
	}
	if binding, ok := daemon.lookupFlow(flowKey, peer); ok && binding.Endpoint == cfgEndpoint.Name && binding.PoolIndex >= 0 && binding.PoolIndex < poolSize {
		return binding.PoolIndex
	}
	return daemon.flowPoolIndex(peer, endpoint, flowKey, poolSize)
}

func (daemon *Daemon) flowPoolIndex(peer core.IXID, endpoint transport.Endpoint, flowKey routing.FlowKey, poolSize int) int {
	if poolSize <= 1 {
		return 0
	}
	poolKey := dataSessionPoolKey{
		Peer:       peer,
		Endpoint:   endpoint.Name,
		Transport:  endpoint.Transport,
		Address:    endpoint.Address,
		Encryption: endpoint.Encryption,
	}
	key := dataSessionFlowPoolKey{Pool: poolKey, Flow: flowKey}
	daemon.dataMu.Lock()
	if daemon.sessionPoolFlow == nil {
		daemon.sessionPoolFlow = make(map[dataSessionFlowPoolKey]int)
	}
	if poolIndex, ok := daemon.sessionPoolFlow[key]; ok && poolIndex >= 0 && poolIndex < poolSize {
		daemon.dataMu.Unlock()
		return poolIndex
	}
	poolIndex := daemon.nextPacketPoolIndexLocked(poolKey, poolSize)
	daemon.sessionPoolFlow[key] = poolIndex
	daemon.dataMu.Unlock()
	return poolIndex
}

func (daemon *Daemon) nextPacketPoolIndex(peer core.IXID, endpoint transport.Endpoint, poolSize int) int {
	if poolSize <= 1 {
		return 0
	}
	key := dataSessionPoolKey{
		Peer:       peer,
		Endpoint:   endpoint.Name,
		Transport:  endpoint.Transport,
		Address:    endpoint.Address,
		Encryption: endpoint.Encryption,
	}
	daemon.dataMu.Lock()
	poolIndex := daemon.nextPacketPoolIndexLocked(key, poolSize)
	daemon.dataMu.Unlock()
	return poolIndex
}

func (daemon *Daemon) nextPacketPoolIndexLocked(key dataSessionPoolKey, poolSize int) int {
	if poolSize <= 1 {
		return 0
	}
	if daemon.sessionPoolRR == nil {
		daemon.sessionPoolRR = make(map[dataSessionPoolKey]uint64)
	}
	next := daemon.sessionPoolRR[key]
	daemon.sessionPoolRR[key] = next + 1
	return int(next % uint64(poolSize))
}

func flowKeyHash(key routing.FlowKey) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	hash := uint64(offset64)
	writeByte := func(value byte) {
		hash ^= uint64(value)
		hash *= prime64
	}
	writeAddr := func(addr netip.Addr) {
		if addr.Is4() {
			raw := addr.As4()
			for _, value := range raw {
				writeByte(value)
			}
			return
		}
		if addr.Is6() {
			raw := addr.As16()
			for _, value := range raw {
				writeByte(value)
			}
		}
	}
	writeAddr(key.SourceIP)
	writeAddr(key.DestinationIP)
	writeByte(byte(key.SourcePort >> 8))
	writeByte(byte(key.SourcePort))
	writeByte(byte(key.DestinationPort >> 8))
	writeByte(byte(key.DestinationPort))
	writeByte(key.Protocol)
	return hash
}

func (daemon *Daemon) runDataSessionHeartbeat(ctx context.Context, runtime *dataSessionRuntime) {
	interval := daemon.sessionHeartbeatInterval()
	timeout := daemon.sessionHeartbeatTimeout()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	missed := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if runtime.dataSessionRecentlyActive(interval, timeout) {
				missed = 0
				continue
			}
			nonce := runtime.nonce.Add(1)
			sent, err := daemon.trySendDataSessionControlPacket(runtime, runtime.session, encodeDataSessionControl(dataSessionControlPing, nonce))
			if err != nil {
				daemon.dropRuntimeSession(runtime)
				daemon.recordEndpointDownIfNoActiveSession(runtime.peer.ID, runtime.endpoint, err)
				return
			}
			if !sent {
				if runtime.dataSessionRecentlyActive(interval, timeout) {
					missed = 0
				}
				continue
			}
			daemon.dataStats.sessionHeartbeatSent.Add(1)
			if daemon.waitForDataSessionPong(ctx, runtime, nonce, timeout) {
				missed = 0
				continue
			}
			daemon.dataStats.sessionHeartbeatTimeouts.Add(1)
			missed++
			if missed >= dataSessionHeartbeatMaxMisses {
				err := fmt.Errorf("session heartbeat timeout after %d consecutive misses of %s", missed, timeout)
				daemon.dropRuntimeSession(runtime)
				daemon.recordEndpointDownIfNoActiveSession(runtime.peer.ID, runtime.endpoint, err)
				return
			}
		}
	}
}

func (runtime *dataSessionRuntime) dataSessionRecentlyActive(interval, timeout time.Duration) bool {
	if runtime == nil {
		return false
	}
	window := interval + timeout*time.Duration(dataSessionHeartbeatRecentActivityGrace)
	if window <= 0 {
		window = interval
	}
	if window <= 0 {
		return false
	}
	since := time.Now().UTC().Add(-window).UnixNano()
	return runtime.lastRX.Load() >= since || runtime.lastTX.Load() >= since
}

func (daemon *Daemon) waitForDataSessionPong(ctx context.Context, runtime *dataSessionRuntime, nonce uint64, timeout time.Duration) bool {
	sentAt := time.Now().UTC().UnixNano()
	deadlineTimer := time.NewTimer(timeout)
	checkTicker := time.NewTicker(50 * time.Millisecond)
	defer deadlineTimer.Stop()
	defer checkTicker.Stop()
	for {
		if runtime.pongNonce.Load() >= nonce || runtime.lastRX.Load() >= sentAt {
			return true
		}
		select {
		case <-ctx.Done():
			return true
		case <-checkTicker.C:
		case <-deadlineTimer.C:
			return false
		}
	}
}

func encodeDataSessionControl(kind byte, nonce uint64) []byte {
	frame := make([]byte, dataSessionControlLen)
	copy(frame[0:4], dataSessionControlMagic[:])
	frame[4] = dataSessionControlVersion
	frame[5] = kind
	binary.BigEndian.PutUint64(frame[8:16], nonce)
	return frame
}

func encodeDataSessionDeviceLease(addr netip.Addr, prefixBits uint32, expiresAt time.Time, routes []netip.Prefix) []byte {
	if len(routes) > 65535 {
		routes = routes[:65535]
	}
	frameLen := dataSessionControlDeviceLeaseLen + len(routes)*dataSessionControlDeviceLeaseRouteLen
	frame := make([]byte, frameLen)
	copy(frame[0:4], dataSessionControlMagic[:])
	frame[4] = dataSessionControlVersion
	frame[5] = dataSessionControlDeviceLease
	if addr.Is4() {
		raw := addr.As4()
		copy(frame[8:12], raw[:])
	}
	binary.BigEndian.PutUint32(frame[12:16], prefixBits)
	if !expiresAt.IsZero() {
		binary.BigEndian.PutUint64(frame[16:24], uint64(expiresAt.UTC().Unix()))
	}
	binary.BigEndian.PutUint16(frame[24:26], uint16(len(routes)))
	offset := dataSessionControlDeviceLeaseLen
	for _, route := range routes {
		if !route.IsValid() || !route.Addr().Is4() {
			continue
		}
		raw := route.Masked().Addr().As4()
		copy(frame[offset:offset+4], raw[:])
		frame[offset+4] = byte(route.Bits())
		offset += dataSessionControlDeviceLeaseRouteLen
	}
	return frame
}

func isDataSessionControlPacket(packet []byte) bool {
	if len(packet) == dataSessionControlLen {
		return string(packet[0:4]) == string(dataSessionControlMagic[:]) && packet[4] == dataSessionControlVersion
	}
	if len(packet) < dataSessionControlDeviceLeaseLen || string(packet[0:4]) != string(dataSessionControlMagic[:]) || packet[4] != dataSessionControlVersion {
		return false
	}
	if packet[5] != dataSessionControlDeviceLease {
		return false
	}
	count := int(binary.BigEndian.Uint16(packet[24:26]))
	return len(packet) == dataSessionControlDeviceLeaseLen+count*dataSessionControlDeviceLeaseRouteLen
}

func decodeDataSessionControl(packet []byte) (kind byte, nonce uint64, ok bool) {
	if !isDataSessionControlPacket(packet) {
		return 0, 0, false
	}
	switch packet[5] {
	case dataSessionControlPing, dataSessionControlPong, dataSessionControlDeviceLease:
		return packet[5], binary.BigEndian.Uint64(packet[8:16]), true
	default:
		return 0, 0, false
	}
}

func decodeDataSessionBatch(packet []byte) ([][]byte, bool) {
	return decodeDataSessionBatchInto(packet, nil)
}

func decodeDataSessionBatchInto(packet []byte, dst [][]byte) ([][]byte, bool) {
	if len(packet) < dataSessionBatchHeaderLen {
		return nil, false
	}
	if string(packet[0:4]) != string(dataSessionBatchMagic[:]) || packet[4] != dataSessionBatchVersion {
		return nil, false
	}
	count := int(binary.BigEndian.Uint16(packet[6:8]))
	if count <= 0 || count > dataSessionBatchMaxPackets {
		return nil, false
	}
	offset := dataSessionBatchHeaderLen
	var items [][]byte
	if cap(dst) < count {
		items = make([][]byte, 0, count)
	} else {
		items = dst[:0]
	}
	for i := 0; i < count; i++ {
		if len(packet)-offset < dataSessionBatchItemHeaderLen {
			return nil, false
		}
		size := int(binary.BigEndian.Uint16(packet[offset : offset+dataSessionBatchItemHeaderLen]))
		offset += dataSessionBatchItemHeaderLen
		if size <= 0 || len(packet)-offset < size {
			return nil, false
		}
		items = append(items, packet[offset:offset+size])
		offset += size
	}
	if offset != len(packet) {
		return nil, false
	}
	return items, true
}

func (daemon *Daemon) recordDataSessionTLSObservation(session transport.Session) {
	if session == nil {
		return
	}
	daemon.dataStats.recordTLSObservation(session.Stats())
}

func (daemon *Daemon) receiveDataPathSession(ctx context.Context, runtime *dataSessionRuntime, session transport.Session) {
	defer session.Close()
	injector, _ := daemon.dataplane.(dataplane.PacketInjector)
	batchInjector, _ := daemon.dataplane.(dataplane.PacketBatchInjector)
	receiver, hasBatchReceiver := session.(transport.PacketBatchReceiver)
	releaseReceiver, hasReleaseReceiver := session.(transport.PacketBatchReceiverWithRelease)
	receiveBatchSize := dataSessionReceiveBatchSize()
	var scratch dataReceiveScratch
	for {
		var packets [][]byte
		var releasePackets func()
		var err error
		if hasReleaseReceiver {
			packets, releasePackets, err = releaseReceiver.RecvPacketsWithRelease(receiveBatchSize)
		} else if hasBatchReceiver {
			packets, err = receiver.RecvPackets(receiveBatchSize)
		} else {
			var packet []byte
			packet, err = session.RecvPacket()
			if err == nil {
				packets = [][]byte{packet}
			}
		}
		if err != nil {
			if ctx.Err() == nil {
				daemon.dataStats.receiveErrors.Add(1)
				daemon.dataStats.setLastReceiveError(err)
				if runtime != nil {
					daemon.dropRuntimeSession(runtime)
					if errors.Is(err, securetransport.ErrSessionReset) {
						daemon.dataStats.sessionResetsReceived.Add(1)
						daemon.recordEndpointUp(runtime.peer.ID, runtime.endpoint, 0)
					} else {
						daemon.recordEndpointDownIfNoActiveSession(runtime.peer.ID, runtime.endpoint, err)
					}
				}
			}
			return
		}
		daemon.handleReceivedDataPathPackets(ctx, runtime, session, packets, injector, batchInjector, &scratch)
		if releasePackets != nil {
			releasePackets()
		}
		scratch.release()
	}
}

func (daemon *Daemon) handleReceivedDataPathPackets(ctx context.Context, runtime *dataSessionRuntime, session transport.Session, packets [][]byte, injector dataplane.PacketInjector, batchInjector dataplane.PacketBatchInjector, scratch *dataReceiveScratch) {
	if len(packets) == 0 {
		return
	}
	if runtime != nil {
		runtime.lastRX.Store(time.Now().UTC().UnixNano())
	}
	if scratch == nil {
		scratch = &dataReceiveScratch{}
		defer scratch.release()
	}
	if runtime != nil && runtime.controlOnly && !runtime.receiveData {
		for _, packet := range packets {
			daemon.handleDataSessionControl(ctx, runtime, session, packet)
		}
		return
	}
	scratch.prepareRXGSOCoalesceConfig(dataSessionRXGSOCoalesceDisabledForSession(runtime, session))
	dataPackets := scratch.dataSlice(len(packets))
	flushDataPackets := func() {
		if len(dataPackets) == 0 {
			return
		}
		daemon.handleReceivedDataPathBatch(ctx, dataPackets, injector, batchInjector, scratch)
		clear(dataPackets)
		dataPackets = dataPackets[:0]
		scratch.dataPackets = dataPackets
	}
	for _, packet := range packets {
		if daemon.handleDataSessionControl(ctx, runtime, session, packet) {
			continue
		}
		if isDataSessionSecureHandshakePacket(packet) {
			continue
		}
		if decoded, ok := decodeDataSessionBatchInto(packet, scratch.batchPackets[:0]); ok {
			scratch.batchPackets = decoded
			daemon.dataStats.recordDataSessionBatchRX(packet, len(decoded))
			flushDataPackets()
			daemon.handleReceivedDataPathBatch(ctx, decoded, injector, batchInjector, scratch)
			continue
		}
		dataPackets = append(dataPackets, packet)
	}
	flushDataPackets()
}

func (daemon *Daemon) handleDataSessionControl(ctx context.Context, runtime *dataSessionRuntime, session transport.Session, packet []byte) bool {
	kind, nonce, ok := decodeDataSessionControl(packet)
	if !ok {
		return false
	}
	daemon.dataStats.sessionHeartbeatReceived.Add(1)
	switch kind {
	case dataSessionControlPing:
		sent, err := daemon.trySendDataSessionControlPacket(runtime, session, encodeDataSessionControl(dataSessionControlPong, nonce))
		if err != nil {
			if runtime != nil {
				daemon.dropRuntimeSession(runtime)
				daemon.recordEndpointDownIfNoActiveSession(runtime.peer.ID, runtime.endpoint, err)
			}
		} else if !sent && runtime != nil {
			now := time.Now().UTC().UnixNano()
			runtime.lastPong.Store(now)
			runtime.lastRX.Store(now)
		}
	case dataSessionControlPong:
		if runtime != nil {
			now := time.Now().UTC().UnixNano()
			runtime.lastPong.Store(now)
			runtime.lastRX.Store(now)
			runtime.pongNonce.Store(nonce)
		}
	case dataSessionControlDeviceLease:
	}
	return true
}

func isDataSessionSecureHandshakePacket(packet []byte) bool {
	return len(packet) >= len(dataSessionSecureHandshakeMagic) &&
		string(packet[0:4]) == string(dataSessionSecureHandshakeMagic[:])
}

func (daemon *Daemon) handleReceivedDataPathBatch(ctx context.Context, packets [][]byte, injector dataplane.PacketInjector, batchInjector dataplane.PacketBatchInjector, scratches ...*dataReceiveScratch) {
	if len(packets) == 0 {
		return
	}
	daemon.dataStats.receiveBatchFrames.Add(1)
	daemon.dataStats.receiveBatchPackets.Add(uint64(len(packets)))
	daemon.dataStats.packetsReceived.Add(uint64(len(packets)))
	if batchInjector == nil {
		for _, packet := range packets {
			_ = daemon.handleReceivedDataPathPacket(ctx, packet, injector)
		}
		return
	}
	var scratch *dataReceiveScratch
	if len(scratches) > 0 {
		scratch = scratches[0]
	}
	if scratch == nil {
		scratch = &dataReceiveScratch{}
		defer scratch.release()
	}
	if !scratch.rxGSOCoalesceReady {
		scratch.prepareRXGSOCoalesceConfig(scratch.disableRXGSOCoalesce)
	}
	if scratch.rxGSOChecksumMTU == 0 {
		scratch.rxGSOChecksumMTU = -1
		if advisor, ok := batchInjector.(dataplane.PacketBatchGSOChecksumOffloadAdvisor); ok {
			if mtu := advisor.InjectBatchGSOChecksumOffloadMTU(); mtu > 0 {
				scratch.rxGSOChecksumMTU = mtu
			}
		}
	}
	if scratch.rxGSOScatterMTU == 0 {
		scratch.rxGSOScatterMTU = -1
		if advisor, ok := batchInjector.(dataplane.PacketBatchGSOScatterAdvisor); ok {
			if mtu := advisor.InjectBatchGSOScatterMTU(); mtu > 0 {
				scratch.rxGSOScatterMTU = mtu
			}
		}
	}
	localLAN := daemon.localLANCacheSnapshot()
	localPackets := scratch.localSlice(len(packets))
	flushLocal := func() {
		if len(localPackets) == 0 {
			return
		}
		logicalPackets := len(localPackets)
		wirePackets := localPackets
		scatterEligible := scratch.rxGSOScatterEnabled && scratch.rxGSOScatterMTU > 0 && scratch.rxGSOCoalesceEnabled
		if !scatterEligible {
			coalesceOptions := tcpGSOCoalesceOptions{}
			if scratch.rxGSOChecksumMTU > 0 {
				coalesceOptions.skipTCPChecksumAbove = scratch.rxGSOChecksumMTU
			}
			coalesceOptions.multiFlow = scratch.rxGSOCoalesceMultiFlow
			if coalesced, stats := coalesceDataSessionTCPLocalPacketsConfiguredScratchOptions(localPackets, scratch.rxGSOCoalesceEnabled, scratch.rxGSOCoalesceMaxBytes, scratch.rxGSOCoalesceMaxPkts, &scratch.coalescedPackets, &scratch.coalesceArena, coalesceOptions); stats.Batches > 0 {
				wirePackets = coalesced
				daemon.dataStats.injectGSOCoalesceBatches.Add(stats.Batches)
				daemon.dataStats.injectGSOCoalescePackets.Add(stats.InputPackets)
				daemon.dataStats.injectGSOCoalesceWires.Add(stats.OutputPackets)
				daemon.dataStats.injectGSOCoalesceBytes.Add(stats.OutputBytes)
			}
		}
		daemon.dataStats.injectBatchAttempts.Add(1)
		if err := batchInjector.InjectPackets(ctx, wirePackets); err != nil {
			if ctx.Err() == nil {
				daemon.dataStats.injectErrors.Add(1)
				daemon.dataStats.setLastInjectError(err, firstPacket(wirePackets))
				daemon.dataStats.recordDrop(observability.DropInvalidPacket)
			}
		} else {
			daemon.dataStats.packetsInjected.Add(uint64(logicalPackets))
			daemon.dataStats.injectBatchPackets.Add(uint64(logicalPackets))
		}
		clear(localPackets)
		localPackets = localPackets[:0]
		scratch.localPackets = localPackets
	}
	for _, packet := range packets {
		dst, err := ipv4Destination(packet)
		if err != nil {
			flushLocal()
			if ctx.Err() == nil {
				daemon.dataStats.injectErrors.Add(1)
				daemon.dataStats.setLastInjectError(err, packet)
				daemon.dataStats.recordDrop(observability.DropInvalidPacket)
			}
			continue
		}
		if localLAN.destinationInLAN(dst) {
			if localLAN.destinationIsGateway(dst) || localLAN.natEnabled {
				flushLocal()
				_ = daemon.handleReceivedDataPathPacket(ctx, packet, injector)
				continue
			}
			localPackets = append(localPackets, packet)
			continue
		}
		flushLocal()
		_ = daemon.handleReceivedDataPathPacket(ctx, packet, injector)
	}
	flushLocal()
}

func (daemon *Daemon) handleReceivedDataPathPacket(ctx context.Context, packet []byte, injector dataplane.PacketInjector) error {
	if binding, found, eligible, err := daemon.inboundNATBinding(packet); err != nil {
		if ctx.Err() == nil {
			daemon.dataStats.injectErrors.Add(1)
			daemon.dataStats.setLastInjectError(err, packet)
			daemon.dataStats.recordDrop(observability.DropInvalidPacket)
		}
		return err
	} else if eligible && found {
		daemon.dataStats.natReverseHits.Add(1)
		if natInjector, ok := daemon.dataplane.(dataplane.NATFastPathInjector); ok {
			if err := natInjector.InjectNATPacket(ctx, packet, binding.OriginalIP); err != nil {
				if errors.Is(err, dataplane.ErrUnsupported) {
					goto userspaceDNAT
				}
				if ctx.Err() == nil {
					daemon.dataStats.injectErrors.Add(1)
					daemon.dataStats.setLastInjectError(err, packet)
					daemon.dataStats.recordDrop(observability.DropInvalidPacket)
				}
				return err
			}
			daemon.dataStats.packetsInjected.Add(1)
			return nil
		}
	userspaceDNAT:
		translated, err := rewriteIPv4Destination(packet, binding.OriginalIP)
		if err != nil {
			if ctx.Err() == nil {
				daemon.dataStats.injectErrors.Add(1)
				daemon.dataStats.setLastInjectError(err, packet)
				daemon.dataStats.recordDrop(observability.DropInvalidPacket)
			}
			return err
		}
		packet = translated
	} else if eligible {
		daemon.dataStats.natMisses.Add(1)
	}
	dst, err := ipv4Destination(packet)
	if err != nil {
		if ctx.Err() == nil {
			daemon.dataStats.injectErrors.Add(1)
			daemon.dataStats.setLastInjectError(err, packet)
			daemon.dataStats.recordDrop(observability.DropInvalidPacket)
		}
		return err
	}
	if daemon.destinationIsLocalGateway(dst) {
		reply, replyDestination, ok, err := localICMPEchoReplyPacket(packet)
		if err != nil {
			if ctx.Err() == nil {
				daemon.dataStats.injectErrors.Add(1)
				daemon.dataStats.setLastInjectError(err, packet)
				daemon.dataStats.recordDrop(observability.DropInvalidPacket)
			}
			return err
		}
		if ok {
			return daemon.deliverLocalControlReply(ctx, reply, replyDestination)
		}
		if localInjector, ok := daemon.dataplane.(dataplane.LocalPacketInjector); ok {
			if err := localInjector.InjectLocalPacket(ctx, packet); err != nil {
				if ctx.Err() == nil {
					daemon.dataStats.injectErrors.Add(1)
					daemon.dataStats.setLastInjectError(err, packet)
					daemon.dataStats.recordDrop(observability.DropInvalidPacket)
				}
				return err
			}
			daemon.dataStats.packetsInjected.Add(1)
			return nil
		}
	}
	if daemon.destinationIsDeviceAccessRoute(dst, packet) {
		return daemon.forwardTransitPacket(ctx, packet, dst)
	}
	if daemon.destinationInLocalLAN(dst) {
		if injector == nil {
			if ctx.Err() == nil {
				daemon.dataStats.injectErrors.Add(1)
				daemon.dataStats.recordDrop(observability.DropEndpointDown)
			}
			return fmt.Errorf("dataplane packet injection is not available")
		}
		if err := injector.InjectPacket(ctx, packet); err != nil {
			if ctx.Err() == nil {
				daemon.dataStats.injectErrors.Add(1)
				daemon.dataStats.setLastInjectError(err, packet)
				daemon.dataStats.recordDrop(observability.DropInvalidPacket)
			}
			return err
		}
		daemon.dataStats.packetsInjected.Add(1)
		return nil
	}
	return daemon.forwardTransitPacket(ctx, packet, dst)
}

func (daemon *Daemon) destinationIsLocalGateway(dst netip.Addr) bool {
	if !dst.IsValid() {
		return false
	}
	cache := daemon.localLANCacheSnapshot()
	return cache.destinationIsGateway(dst)
}

func (daemon *Daemon) deliverLocalControlReply(ctx context.Context, packet []byte, destination netip.Addr) error {
	if daemon.destinationIsDeviceAccessRoute(destination, packet) {
		return daemon.deliverLocalControlReplyByRoute(ctx, packet, destination)
	}
	if daemon.destinationInLocalLAN(destination) {
		if err := daemon.injectRejectReply(ctx, packet, destination); err != nil {
			if ctx.Err() == nil {
				daemon.dataStats.injectErrors.Add(1)
			}
			daemon.dataStats.recordDrop(observability.DropEndpointDown)
			return err
		}
		daemon.dataStats.packetsInjected.Add(1)
		return nil
	}
	return daemon.deliverLocalControlReplyByRoute(ctx, packet, destination)
}

func (daemon *Daemon) deliverLocalControlReplyByRoute(ctx context.Context, packet []byte, destination netip.Addr) error {
	if daemon.routes == nil {
		daemon.dataStats.routeMisses.Add(1)
		daemon.dataStats.recordDrop(observability.DropNoRoute)
		return fmt.Errorf("no route for local reply destination %s", destination)
	}
	decision, ok := daemon.lookupRouteForPacket(destination, packet)
	if !ok {
		daemon.dataStats.routeMisses.Add(1)
		daemon.dataStats.recordDrop(observability.DropNoRoute)
		return fmt.Errorf("no route for local reply destination %s", destination)
	}
	if dropReason, drop := routeDropReason(decision.Route); drop {
		daemon.recordRouteHit(decision)
		daemon.dataStats.recordDrop(dropReason)
		return fmt.Errorf("local reply route %q is %s", decision.Route.Prefix, decision.Route.Kind)
	}
	if decision.Route.Kind == routing.RouteLocal || decision.Route.NextHop == daemon.desired.IX.ID {
		if err := daemon.injectRejectReply(ctx, packet, destination); err != nil {
			if ctx.Err() == nil {
				daemon.dataStats.injectErrors.Add(1)
			}
			daemon.dataStats.recordDrop(observability.DropEndpointDown)
			return err
		}
		daemon.dataStats.packetsInjected.Add(1)
		return nil
	}
	flowKey, hasFlow := flowKeyFromIPv4Packet(packet)
	daemon.recordRouteHit(decision)
	if err := daemon.sendPacketByDecision(ctx, decision, packet, flowKey, hasFlow); err != nil {
		daemon.dataStats.sendErrors.Add(1)
		return err
	}
	return nil
}

func (daemon *Daemon) destinationInLocalLAN(dst netip.Addr) bool {
	if !dst.IsValid() {
		return false
	}
	cache := daemon.localLANCacheSnapshot()
	return cache.destinationInLAN(dst)
}

func (daemon *Daemon) destinationIsDeviceAccessRoute(dst netip.Addr, packet []byte) bool {
	if daemon == nil || !dst.IsValid() || daemon.routes == nil {
		return false
	}
	decision, ok := daemon.lookupRouteForPacket(dst, packet)
	if !ok {
		return false
	}
	return decision.Route.Source == "device_access" && decision.Route.NextHop != "" && decision.Route.NextHop != daemon.desired.IX.ID
}

func (cache localLANCache) destinationIsGateway(dst netip.Addr) bool {
	if cache.hasGateway && cache.gateway.Addr() == dst {
		return true
	}
	for _, gateway := range cache.gateways {
		if gateway.Addr() == dst {
			return true
		}
	}
	return false
}

func (cache localLANCache) destinationInLAN(dst netip.Addr) bool {
	for _, prefix := range cache.advertise {
		if prefix.Contains(dst) {
			return true
		}
	}
	if cache.hasGateway && cache.gateway.Masked().Contains(dst) {
		return true
	}
	for _, gateway := range cache.gateways {
		if gateway.Masked().Contains(dst) {
			return true
		}
	}
	return false
}

func (daemon *Daemon) configureLocalLANCache(desired config.Desired) {
	cache := buildLocalLANCache(desired)
	daemon.localLAN.Store(cache)
}

func buildLocalLANCache(desired config.Desired) localLANCache {
	lans := config.EffectiveLANs(desired)
	cache := localLANCache{
		ready:     true,
		advertise: make([]netip.Prefix, 0),
		gateways:  make([]netip.Prefix, 0, len(lans)),
	}
	for _, lan := range lans {
		for _, rawPrefix := range lan.Advertise {
			prefix, err := rawPrefix.Parse()
			if err == nil {
				cache.advertise = append(cache.advertise, prefix)
			}
		}
		if lan.Gateway != "" {
			prefix, err := netip.ParsePrefix(lan.Gateway)
			if err != nil {
				continue
			}
			cache.gateways = append(cache.gateways, prefix)
			cache.gateway = prefix
			cache.hasGateway = true
		}
		if lan.Mode == config.LANModeNAT {
			cache.natEnabled = true
		}
	}
	if !cache.natEnabled {
		for _, policy := range desired.Policies {
			if rewritePolicyEnablesNAT(policy.Rewrite) {
				cache.natEnabled = true
				break
			}
		}
	}
	return cache
}

func (daemon *Daemon) localLANCacheSnapshot() localLANCache {
	if value := daemon.localLAN.Load(); value != nil {
		if cache, ok := value.(localLANCache); ok && cache.ready {
			return cache
		}
	}
	daemon.configureLocalLANCache(daemon.desired)
	if value := daemon.localLAN.Load(); value != nil {
		if cache, ok := value.(localLANCache); ok {
			return cache
		}
	}
	return localLANCache{ready: true}
}

func (daemon *Daemon) forwardTransitPacket(ctx context.Context, packet []byte, dst netip.Addr) error {
	if !daemon.transitForwardingEnabled() {
		daemon.dataStats.recordDrop(observability.DropTransitDisabled)
		return fmt.Errorf("transit forwarding is disabled for received packet destination %s", dst)
	}
	decision, ok := daemon.lookupRouteForPacket(dst, packet)
	if !ok {
		daemon.dataStats.routeMisses.Add(1)
		daemon.dataStats.recordDrop(observability.DropNoRoute)
		return fmt.Errorf("no transit route for received packet destination %s", dst)
	}
	if dropReason, drop := routeDropReason(decision.Route); drop {
		daemon.recordRouteHit(decision)
		daemon.dataStats.recordDrop(dropReason)
		return fmt.Errorf("transit route %q is %s", decision.Route.Prefix, decision.Route.Kind)
	}
	if decision.Route.NextHop == daemon.desired.IX.ID {
		daemon.dataStats.recordDrop(observability.DropNoRoute)
		return fmt.Errorf("transit route for %s points back to local IX %q", dst, daemon.desired.IX.ID)
	}
	forwarded, ttlOK, err := daemon.decrementForwardTTL(ctx, packet)
	if err != nil {
		return err
	}
	if !ttlOK {
		return errIPv4TTLExpired
	}
	policy := daemon.policyForRoute(decision.Route)
	var natTranslated bool
	forwarded, natTranslated, err = daemon.applyOutboundNAT(forwarded, decision.Route, policy)
	if err != nil {
		daemon.dataStats.recordDrop(observability.DropInvalidPacket)
		return err
	}
	if natTranslated {
		daemon.dataStats.natTranslations.Add(1)
	}
	flowKey, hasFlow := flowKeyFromIPv4Packet(forwarded)
	daemon.recordRouteHit(decision)
	if err := daemon.sendPacketByDecision(ctx, decision, forwarded, flowKey, hasFlow); err != nil {
		daemon.dataStats.sendErrors.Add(1)
		return err
	}
	return nil
}

func (daemon *Daemon) transitForwardingEnabled() bool {
	if daemon == nil {
		return true
	}
	return config.RoutePolicyTransitForwardingEnabled(daemon.desired.RoutePolicy)
}

func routeDropReason(route routing.Route) (observability.DropReason, bool) {
	switch route.Kind {
	case routing.RouteBlackhole:
		return observability.DropBlackholeRoute, true
	case routing.RouteReject:
		return observability.DropRejectRoute, true
	default:
		return "", false
	}
}

func (daemon *Daemon) lookupRouteForPacket(dst netip.Addr, packet []byte) (routing.Decision, bool) {
	if daemon.routes == nil {
		return routing.Decision{}, false
	}
	return daemon.routes.LookupFiltered(dst, func(route routing.Route) bool {
		return routeMatchesPacket(route, packet)
	})
}

func routeMatchesPacket(route routing.Route, packet []byte) bool {
	if route.Kind != routing.RouteLocal || route.LocalProtocol == 0 && route.LocalPort == 0 {
		return true
	}
	tuple, ok, err := ipv4NATTupleFromPacket(packet)
	if err != nil || !ok {
		return false
	}
	if route.LocalProtocol != 0 && tuple.protocol != route.LocalProtocol {
		return false
	}
	if route.LocalPort != 0 && tuple.destPort != route.LocalPort {
		return false
	}
	return true
}

func (daemon *Daemon) dropSession(key dataSessionKey) {
	daemon.clearForwardCacheForSession(key)
	daemon.dataMu.Lock()
	session := daemon.dataSessions[key]
	delete(daemon.dataSessions, key)
	runtime := daemon.dataSessionState[key]
	delete(daemon.dataSessionState, key)
	leaseChanged := daemon.deleteDeviceAccessLeaseForSessionLocked(key)
	daemon.deleteSessionPoolCursorLocked(key)
	daemon.deleteSessionFlowBindingsLocked(key)
	if len(daemon.dataSessions) == 0 {
		daemon.sessionPoolRR = nil
		daemon.sessionPoolFlow = nil
	}
	daemon.dataMu.Unlock()
	if runtime != nil && runtime.cancel != nil {
		runtime.cancel()
	}
	if session != nil {
		_ = session.Close()
	}
	daemon.syncKernelDatapathSessionDelete(key)
	if leaseChanged {
		_ = daemon.applyRuntimeDataplaneSnapshot(context.Background())
		if daemon.localAdvertisementConfigured() {
			_ = daemon.refreshLocalAdvertisement()
		}
	}
}

func (daemon *Daemon) dropRuntimeSession(runtime *dataSessionRuntime) {
	if runtime == nil {
		return
	}
	daemon.clearForwardCacheForSession(runtime.key)
	daemon.dataMu.Lock()
	if daemon.dataSessionState[runtime.key] != runtime {
		daemon.dataMu.Unlock()
		return
	}
	session := daemon.dataSessions[runtime.key]
	delete(daemon.dataSessions, runtime.key)
	delete(daemon.dataSessionState, runtime.key)
	leaseChanged := daemon.deleteDeviceAccessLeaseForSessionLocked(runtime.key)
	daemon.deleteSessionPoolCursorLocked(runtime.key)
	daemon.deleteSessionFlowBindingsLocked(runtime.key)
	if len(daemon.dataSessions) == 0 {
		daemon.sessionPoolRR = nil
		daemon.sessionPoolFlow = nil
	}
	daemon.dataMu.Unlock()
	if runtime.cancel != nil {
		runtime.cancel()
	}
	if session != nil {
		daemon.dataStats.staleSessionsDropped.Add(1)
		_ = session.Close()
	}
	daemon.syncKernelDatapathSessionDelete(runtime.key)
	if leaseChanged {
		_ = daemon.applyRuntimeDataplaneSnapshot(context.Background())
		if daemon.localAdvertisementConfigured() {
			_ = daemon.refreshLocalAdvertisement()
		}
	}
}

func (daemon *Daemon) deleteDeviceAccessLeaseForSessionLocked(key dataSessionKey) bool {
	changed := false
	for leaseKey, lease := range daemon.deviceLeases {
		if lease.SessionKey == key {
			delete(daemon.deviceLeases, leaseKey)
			changed = true
		}
	}
	return changed
}

func (daemon *Daemon) dropSessionsForPeerTransport(peer core.IXID, protocol transport.Protocol) int {
	type droppedSession struct {
		session transport.Session
		runtime *dataSessionRuntime
	}
	daemon.dataMu.Lock()
	dropped := make([]droppedSession, 0)
	for key, session := range daemon.dataSessions {
		if key.Peer != peer || key.Transport != protocol {
			continue
		}
		daemon.clearForwardCacheForSession(key)
		dropped = append(dropped, droppedSession{
			session: session,
			runtime: daemon.dataSessionState[key],
		})
		delete(daemon.dataSessions, key)
		delete(daemon.dataSessionState, key)
		daemon.deleteSessionPoolCursorLocked(key)
		daemon.deleteSessionFlowBindingsLocked(key)
	}
	if len(daemon.dataSessions) == 0 {
		daemon.sessionPoolRR = nil
		daemon.sessionPoolFlow = nil
	}
	daemon.dataMu.Unlock()
	for _, item := range dropped {
		if item.runtime != nil && item.runtime.cancel != nil {
			item.runtime.cancel()
		}
		if item.session != nil {
			daemon.dataStats.staleSessionsDropped.Add(1)
			_ = item.session.Close()
		}
	}
	return len(dropped)
}

func (daemon *Daemon) reconcileRouteSelectedOutboundSessions() int {
	routes := daemon.runtimeRoutes()
	if len(routes) == 0 {
		routes = routesFromConfig(daemon.desired)
	}
	selected := daemon.routeSelectedEndpointKeys(routes)
	if len(selected) == 0 {
		return 0
	}

	type droppedSession struct {
		session transport.Session
		runtime *dataSessionRuntime
	}
	daemon.dataMu.Lock()
	dropped := make([]droppedSession, 0)
	for key, session := range daemon.dataSessions {
		if key.Address == reverseSessionAddress {
			continue
		}
		endpoints, ok := selected[key.Peer]
		if !ok || len(endpoints) == 0 {
			continue
		}
		if _, ok := endpoints[key.Endpoint]; ok {
			continue
		}
		daemon.clearForwardCacheForSession(key)
		dropped = append(dropped, droppedSession{
			session: session,
			runtime: daemon.dataSessionState[key],
		})
		delete(daemon.dataSessions, key)
		delete(daemon.dataSessionState, key)
		daemon.deleteSessionPoolCursorLocked(key)
		daemon.deleteSessionFlowBindingsLocked(key)
	}
	if len(dropped) > 0 {
		daemon.dataSessionEpoch++
	}
	if len(daemon.dataSessions) == 0 {
		daemon.sessionPoolRR = nil
		daemon.sessionPoolFlow = nil
	}
	daemon.dataMu.Unlock()

	for _, item := range dropped {
		if item.runtime != nil && item.runtime.cancel != nil {
			item.runtime.cancel()
		}
		if item.session != nil {
			daemon.dataStats.staleSessionsDropped.Add(1)
			_ = item.session.Close()
		}
	}
	return len(dropped)
}

func (daemon *Daemon) routeSelectedEndpointKeys(routes []routing.Route) map[core.IXID]map[core.EndpointID]struct{} {
	selected := make(map[core.IXID]map[core.EndpointID]struct{})
	for _, route := range routes {
		if route.NextHop == "" || route.Kind != "" && route.Kind != routing.RouteUnicast {
			continue
		}
		peer, ok := daemon.peerConfig(route.NextHop)
		if !ok {
			continue
		}
		if route.Endpoint != "" {
			if selected[route.NextHop] == nil {
				selected[route.NextHop] = make(map[core.EndpointID]struct{})
			}
			selected[route.NextHop][route.Endpoint] = struct{}{}
			continue
		}
		candidates, _, err := daemon.candidatePeerEndpoints(peer, route, routing.FlowKey{}, false)
		if err != nil || len(candidates) == 0 {
			continue
		}
		for _, endpoint := range candidates {
			if selected[route.NextHop] == nil {
				selected[route.NextHop] = make(map[core.EndpointID]struct{})
			}
			selected[route.NextHop][endpoint.Name] = struct{}{}
		}
	}
	return selected
}

type droppedDataSession struct {
	session transport.Session
	runtime *dataSessionRuntime
}

func (daemon *Daemon) dropOutboundDataSessionsForInboundLocked(peer core.IXID, endpoint config.EndpointConfig, encryption string, keep dataSessionKey) []droppedDataSession {
	protocol := transport.Protocol(endpoint.Transport)
	dropped := make([]droppedDataSession, 0)
	for key, session := range daemon.dataSessions {
		if key == keep || key.Peer != peer || key.Endpoint != endpoint.Name || key.Transport != protocol ||
			key.Address == reverseSessionAddress || key.Encryption != encryption {
			continue
		}
		daemon.clearForwardCacheForSession(key)
		if protocol == transport.ProtocolExperimentalTCP {
			retainKernelFlowOnClose(session)
		}
		dropped = append(dropped, droppedDataSession{
			session: session,
			runtime: daemon.dataSessionState[key],
		})
		delete(daemon.dataSessions, key)
		delete(daemon.dataSessionState, key)
		daemon.deleteSessionPoolCursorLocked(key)
		daemon.deleteSessionFlowBindingsLocked(key)
	}
	if len(daemon.dataSessions) == 0 {
		daemon.sessionPoolRR = nil
		daemon.sessionPoolFlow = nil
	}
	return dropped
}

func (daemon *Daemon) closeDroppedDataSessions(dropped []droppedDataSession) {
	for _, item := range dropped {
		if item.runtime != nil && item.runtime.cancel != nil {
			item.runtime.cancel()
		}
		if item.session != nil {
			daemon.dataStats.staleSessionsDropped.Add(1)
			_ = item.session.Close()
		}
	}
}

func (daemon *Daemon) deleteSessionPoolCursorLocked(key dataSessionKey) {
	for poolKey := range daemon.sessionPoolRR {
		if poolKey.Peer == key.Peer &&
			poolKey.Endpoint == key.Endpoint &&
			poolKey.Transport == key.Transport &&
			poolKey.Address == key.Address &&
			poolKey.Encryption == key.Encryption {
			delete(daemon.sessionPoolRR, poolKey)
		}
	}
}

func (daemon *Daemon) deleteSessionFlowBindingsLocked(key dataSessionKey) {
	for flowKey := range daemon.sessionPoolFlow {
		if flowKey.Pool.Peer == key.Peer &&
			flowKey.Pool.Endpoint == key.Endpoint &&
			flowKey.Pool.Transport == key.Transport &&
			flowKey.Pool.Address == key.Address &&
			flowKey.Pool.Encryption == key.Encryption {
			delete(daemon.sessionPoolFlow, flowKey)
		}
	}
}

func (daemon *Daemon) closeDataPath() {
	daemon.clearForwardCache()
	daemon.stopKernelDatapathRXStage()
	daemon.dataMu.Lock()
	daemon.dataPathStarted = false
	listeners := append([]dataListenerRuntime(nil), daemon.dataListeners...)
	sessions := make([]transport.Session, 0, len(daemon.dataSessions))
	for _, session := range daemon.dataSessions {
		sessions = append(sessions, session)
	}
	runtimes := make([]*dataSessionRuntime, 0, len(daemon.dataSessionState))
	for _, runtime := range daemon.dataSessionState {
		runtimes = append(runtimes, runtime)
	}
	daemon.dataListeners = nil
	daemon.dataSessions = make(map[dataSessionKey]transport.Session)
	daemon.dataSessionState = make(map[dataSessionKey]*dataSessionRuntime)
	daemon.sessionPoolRR = nil
	daemon.sessionPoolFlow = nil
	daemon.dataSessionEpoch++
	daemon.dataMu.Unlock()

	for _, runtime := range listeners {
		if runtime.Cancel != nil {
			runtime.Cancel()
		}
		_ = runtime.Listener.Close()
	}
	for _, session := range sessions {
		_ = session.Close()
	}
	for _, runtime := range runtimes {
		if runtime != nil && runtime.cancel != nil {
			runtime.cancel()
		}
	}
}

func (daemon *Daemon) closeDataSessions() {
	daemon.clearForwardCache()
	daemon.dataMu.Lock()
	sessions := make([]transport.Session, 0, len(daemon.dataSessions))
	for _, session := range daemon.dataSessions {
		sessions = append(sessions, session)
	}
	runtimes := make([]*dataSessionRuntime, 0, len(daemon.dataSessionState))
	for _, runtime := range daemon.dataSessionState {
		runtimes = append(runtimes, runtime)
	}
	daemon.dataSessions = make(map[dataSessionKey]transport.Session)
	daemon.dataSessionState = make(map[dataSessionKey]*dataSessionRuntime)
	daemon.sessionPoolRR = nil
	daemon.sessionPoolFlow = nil
	daemon.dataSessionEpoch++
	daemon.dataMu.Unlock()

	for _, session := range sessions {
		_ = session.Close()
	}
	for _, runtime := range runtimes {
		if runtime != nil && runtime.cancel != nil {
			runtime.cancel()
		}
	}
}

func (daemon *Daemon) closeDataSessionsForPeers(peers map[core.IXID]struct{}) {
	if len(peers) == 0 {
		return
	}
	daemon.dataMu.Lock()
	sessions := make([]transport.Session, 0)
	runtimes := make([]*dataSessionRuntime, 0)
	for key, session := range daemon.dataSessions {
		if _, ok := peers[key.Peer]; !ok {
			continue
		}
		daemon.clearForwardCacheForSession(key)
		sessions = append(sessions, session)
		delete(daemon.dataSessions, key)
		if runtime := daemon.dataSessionState[key]; runtime != nil {
			runtimes = append(runtimes, runtime)
			delete(daemon.dataSessionState, key)
		}
	}
	for key := range daemon.sessionPoolRR {
		if _, ok := peers[key.Peer]; ok {
			delete(daemon.sessionPoolRR, key)
		}
	}
	for key := range daemon.sessionPoolFlow {
		if _, ok := peers[key.Pool.Peer]; ok {
			delete(daemon.sessionPoolFlow, key)
		}
	}
	if len(daemon.dataSessions) == 0 {
		daemon.sessionPoolRR = nil
		daemon.sessionPoolFlow = nil
	}
	daemon.dataSessionEpoch++
	daemon.dataMu.Unlock()

	for _, session := range sessions {
		_ = session.Close()
	}
	for _, runtime := range runtimes {
		if runtime != nil && runtime.cancel != nil {
			runtime.cancel()
		}
	}
}

func (daemon *Daemon) dataPathStatus() dataPathStatus {
	stats, statsErr := daemon.dataplane.Stats(context.Background())
	return daemon.dataPathStatusWithStats(stats, statsErr == nil)
}

func (daemon *Daemon) dataPathStatusWithStats(dataplaneStats dataplane.Stats, dataplaneStatsOK bool) dataPathStatus {
	daemon.dataMu.Lock()
	listeners := make([]dataPathListenerStatus, 0, len(daemon.dataListeners))
	for _, runtime := range daemon.dataListeners {
		listen := runtime.Endpoint.Listen
		if listen == "" {
			listen = runtime.Endpoint.Address
		}
		listeners = append(listeners, dataPathListenerStatus{
			Endpoint:  string(runtime.Endpoint.Name),
			Transport: string(runtime.Endpoint.Transport),
			Listen:    listen,
		})
	}
	sessions := make([]dataPathSessionStatus, 0, len(daemon.dataSessions))
	for key, session := range daemon.dataSessions {
		direction := "outbound"
		reverse := key.Address == reverseSessionAddress
		if reverse {
			direction = "inbound_reverse"
		}
		runtime := daemon.dataSessionState[key]
		var controlOnly, receiveLoop bool
		var lastRX, lastTX, lastUp, lastPong time.Time
		if runtime != nil {
			controlOnly = runtime.controlOnly
			receiveLoop = runtime.receiveLoop
			lastRX = unixNanoTime(runtime.lastRX.Load())
			lastTX = unixNanoTime(runtime.lastTX.Load())
			lastUp = unixNanoTime(runtime.lastUp.Load())
			lastPong = unixNanoTime(runtime.lastPong.Load())
		}
		sessions = append(sessions, dataPathSessionStatus{
			Peer:        string(key.Peer),
			Endpoint:    string(key.Endpoint),
			Transport:   string(key.Transport),
			Address:     key.Address,
			Direction:   direction,
			Reverse:     reverse,
			PoolIndex:   key.PoolIndex,
			ControlOnly: controlOnly,
			ReceiveLoop: receiveLoop,
			LastRX:      lastRX,
			LastTX:      lastTX,
			LastUp:      lastUp,
			LastPong:    lastPong,
			Stats:       session.Stats(),
		})
	}
	activeSessions := len(sessions)
	captureForwarderActive := daemon.captureSub != nil
	daemon.dataMu.Unlock()
	captureForwarderSuppressed := daemon.captureForwarderSuppressed()
	captureForwarderSuppressedReason := daemon.captureForwarderSuppressedReason()
	var experimentalTCP *dataplane.ExperimentalTCPStatus
	var kernelTransport *dataplane.KernelTransportStatus
	if provider, ok := daemon.dataplane.(dataplane.KernelTransportProvider); ok {
		status, err := provider.KernelTransportStatus(context.Background())
		if err == nil {
			daemon.annotateKernelTransportStatus(&status)
			kernelTransport = &status
		}
	}
	if provider, ok := daemon.dataplane.(dataplane.ExperimentalTCPProvider); ok {
		status, err := provider.ExperimentalTCPStatus(context.Background())
		if err == nil {
			daemon.annotateExperimentalTCPStatus(&status)
			experimentalTCP = &status
		}
	}
	var kernelUDP *dataplane.KernelUDPStatus
	if provider, ok := daemon.dataplane.(dataplane.KernelUDPProvider); ok {
		status, err := provider.KernelUDPStatus(context.Background())
		if err == nil {
			daemon.annotateKernelUDPStatus(&status)
			kernelUDP = &status
		}
	}
	dropReasons := daemon.dataStats.dropReasonSnapshot()
	if dataplaneStatsOK {
		if len(dataplaneStats.DropReasons) > 0 {
			if dropReasons == nil {
				dropReasons = make(map[observability.DropReason]uint64, len(dataplaneStats.DropReasons))
			}
			for reason, value := range dataplaneStats.DropReasons {
				dropReasons[reason] += value
			}
		}
	}
	counters := daemon.dataStats.snapshot()
	if dataplaneStatsOK {
		dpCounters := dataplaneCountersByName(dataplaneStats.Counters)
		counters.TTLICMPGenerated += dpCounters["tc_ttl_exceeded_icmp_generated"]
		counters.RejectReplyErrors += dpCounters["tc_ttl_exceeded_icmp_errors"]
	}
	routeStats, peerStats, endpointStats := daemon.dataPathMetricsSnapshot()
	return dataPathStatus{
		Listeners:                        listeners,
		Sessions:                         sessions,
		ActiveSessions:                   activeSessions,
		CaptureForwarderActive:           captureForwarderActive,
		CaptureForwarderSuppressed:       captureForwarderSuppressed,
		CaptureForwarderSuppressedReason: captureForwarderSuppressedReason,
		Warnings:                         append([]string(nil), dataplaneStats.Warnings...),
		Counters:                         counters,
		KernelOffload:                    daemon.dataPathKernelOffloadStatus(dataplaneStats, dataplaneStatsOK, experimentalTCP, kernelTransport, kernelUDP),
		KernelRXStage:                    daemon.kernelDatapathRXStageStatus(),
		KernelTransport:                  kernelTransport,
		KernelUDP:                        kernelUDP,
		TLS:                              daemon.dataStats.tlsObservationSnapshot(),
		RouteStats:                       routeStats,
		PeerStats:                        peerStats,
		EndpointStats:                    endpointStats,
		EndpointState:                    daemon.endpointStateSnapshot(),
		DropReasons:                      dropReasons,
		NAT:                              daemon.natStatus(),
		ExperimentalTCP:                  experimentalTCP,
	}
}

func unixNanoTime(value int64) time.Time {
	if value <= 0 {
		return time.Time{}
	}
	return time.Unix(0, value).UTC()
}

func (stats *dataPathStats) recordDrop(reason observability.DropReason) {
	if reason == "" {
		return
	}
	stats.dropMu.Lock()
	if stats.dropReasons == nil {
		stats.dropReasons = make(map[observability.DropReason]uint64)
	}
	stats.dropReasons[reason]++
	stats.dropMu.Unlock()
}

func (stats *dataPathStats) recordTLSObservation(sessionStats transport.TransportStats) {
	if sessionStats.LinkTLS {
		stats.linkTLSSessionsSeen.Add(1)
		if sessionStats.TLSVersion != "" || sessionStats.TLSCipherSuite != "" {
			stats.tlsMu.Lock()
			if sessionStats.TLSVersion != "" {
				stats.lastLinkTLSVersion = sessionStats.TLSVersion
			}
			if sessionStats.TLSCipherSuite != "" {
				stats.lastLinkTLSCipherSuite = sessionStats.TLSCipherSuite
			}
			stats.tlsMu.Unlock()
		}
	}
	if sessionStats.CryptoKeySource == securetransport.KeySourceTLSExporter {
		stats.tlsExporterSessionsSeen.Add(1)
		if !sessionStats.LinkTLS {
			stats.tlsExporterNoLinkSeen.Add(1)
		}
	}
}

func (stats *dataPathStats) tlsObservationSnapshot() dataPathTLSObservation {
	stats.tlsMu.Lock()
	version := stats.lastLinkTLSVersion
	cipherSuite := stats.lastLinkTLSCipherSuite
	stats.tlsMu.Unlock()
	return dataPathTLSObservation{
		LinkTLSSessionsSeen:     stats.linkTLSSessionsSeen.Load(),
		TLSExporterSessionsSeen: stats.tlsExporterSessionsSeen.Load(),
		TLSExporterNoLinkSeen:   stats.tlsExporterNoLinkSeen.Load(),
		LastLinkTLSVersion:      version,
		LastLinkTLSCipherSuite:  cipherSuite,
	}
}

func (stats *dataPathStats) dropReasonSnapshot() map[observability.DropReason]uint64 {
	stats.dropMu.Lock()
	defer stats.dropMu.Unlock()
	if len(stats.dropReasons) == 0 {
		return nil
	}
	out := make(map[observability.DropReason]uint64, len(stats.dropReasons))
	for reason, value := range stats.dropReasons {
		out[reason] = value
	}
	return out
}

func (stats *dataPathStats) recordDataSessionBatchQueued(packet []byte) {
	stats.dataSessionBatchQueuedPackets.Add(1)
	stats.dataSessionBatchQueuedBytes.Add(uint64(len(packet)))
}

func (stats *dataPathStats) recordDataSessionBatchDirect(packet []byte) {
	stats.dataSessionBatchDirectPackets.Add(1)
	stats.dataSessionBatchDirectBytes.Add(uint64(len(packet)))
}

func (stats *dataPathStats) recordDataSessionBatchFlush(payload []byte) {
	count := dataSessionBatchPayloadCount(payload)
	if count <= 0 {
		return
	}
	bytes := uint64(len(payload))
	packets := uint64(count)
	stats.dataSessionBatchFlushes.Add(1)
	stats.dataSessionBatchFlushPackets.Add(packets)
	stats.dataSessionBatchFlushBytes.Add(bytes)
	observeAtomicUint64Max(&stats.dataSessionBatchFlushMaxPackets, packets)
	observeAtomicUint64Max(&stats.dataSessionBatchFlushMaxBytes, bytes)
}

func (stats *dataPathStats) recordDataSessionBatchRX(payload []byte, count int) {
	if count <= 0 {
		return
	}
	bytes := uint64(len(payload))
	packets := uint64(count)
	stats.dataSessionBatchRXFrames.Add(1)
	stats.dataSessionBatchRXPackets.Add(packets)
	stats.dataSessionBatchRXBytes.Add(bytes)
	observeAtomicUint64Max(&stats.dataSessionBatchRXMaxPackets, packets)
	observeAtomicUint64Max(&stats.dataSessionBatchRXMaxBytes, bytes)
}

func dataSessionBatchPayloadCount(payload []byte) int {
	if len(payload) < dataSessionBatchHeaderLen {
		return 0
	}
	if string(payload[0:4]) != string(dataSessionBatchMagic[:]) || payload[4] != dataSessionBatchVersion {
		return 0
	}
	return int(binary.BigEndian.Uint16(payload[6:8]))
}

func observeAtomicUint64Max(counter *atomic.Uint64, value uint64) {
	for {
		current := counter.Load()
		if value <= current || counter.CompareAndSwap(current, value) {
			return
		}
	}
}

func (stats *dataPathStats) snapshot() dataPathCounters {
	lastReceiveError, _ := stats.lastReceiveError.Load().(string)
	lastSessionDialError, _ := stats.lastSessionDialError.Load().(string)
	lastInjectError, _ := stats.lastInjectError.Load().(string)
	return dataPathCounters{
		CaptureEvents:                   stats.captureEvents.Load(),
		CaptureNonRouteEvents:           stats.captureNonRouteEvents.Load(),
		CaptureTruncated:                stats.captureTruncated.Load(),
		CaptureUnavailable:              stats.captureUnavailable.Load(),
		RouteMisses:                     stats.routeMisses.Load(),
		PacketsSent:                     stats.packetsSent.Load(),
		SendErrors:                      stats.sendErrors.Load(),
		SendDecisionAttempts:            stats.sendDecisionAttempts.Load(),
		SendDecisionCandidates:          stats.sendDecisionCandidates.Load(),
		SendDecisionNoCandidates:        stats.sendDecisionNoCandidates.Load(),
		SessionDials:                    stats.sessionDials.Load(),
		SessionDialAttempts:             stats.sessionDialAttempts.Load(),
		SessionDialErrors:               stats.sessionDialErrors.Load(),
		LastSessionDialError:            lastSessionDialError,
		PacketsReceived:                 stats.packetsReceived.Load(),
		ReceiveErrors:                   stats.receiveErrors.Load(),
		PacketsInjected:                 stats.packetsInjected.Load(),
		InjectErrors:                    stats.injectErrors.Load(),
		ListenerAcceptErrors:            stats.listenerAcceptErrors.Load(),
		UnsupportedTransport:            stats.unsupportedTransport.Load(),
		SessionHeartbeatSent:            stats.sessionHeartbeatSent.Load(),
		SessionHeartbeatReceived:        stats.sessionHeartbeatReceived.Load(),
		SessionHeartbeatTimeouts:        stats.sessionHeartbeatTimeouts.Load(),
		SessionResetsSent:               stats.sessionResetsSent.Load(),
		SessionResetsReceived:           stats.sessionResetsReceived.Load(),
		StaleSessionsDropped:            stats.staleSessionsDropped.Load(),
		NATTranslations:                 stats.natTranslations.Load(),
		NATReverseHits:                  stats.natReverseHits.Load(),
		NATMisses:                       stats.natMisses.Load(),
		NATDataplaneSyncErrors:          stats.natDataplaneSyncErrors.Load(),
		ForwardCacheHits:                stats.forwardCacheHits.Load(),
		ForwardCacheMisses:              stats.forwardCacheMisses.Load(),
		ForwardCacheStores:              stats.forwardCacheStores.Load(),
		ReceiveBatchFrames:              stats.receiveBatchFrames.Load(),
		ReceiveBatchPackets:             stats.receiveBatchPackets.Load(),
		InjectBatchAttempts:             stats.injectBatchAttempts.Load(),
		InjectBatchPackets:              stats.injectBatchPackets.Load(),
		InjectGSOCoalesceBatches:        stats.injectGSOCoalesceBatches.Load(),
		InjectGSOCoalescePackets:        stats.injectGSOCoalescePackets.Load(),
		InjectGSOCoalesceWires:          stats.injectGSOCoalesceWires.Load(),
		InjectGSOCoalesceBytes:          stats.injectGSOCoalesceBytes.Load(),
		KernelRXStagePolls:              stats.kernelRXStagePolls.Load(),
		KernelRXStageEmptyPolls:         stats.kernelRXStageEmptyPolls.Load(),
		KernelRXStagePackets:            stats.kernelRXStagePackets.Load(),
		KernelRXStageBatches:            stats.kernelRXStageBatches.Load(),
		KernelRXStageErrors:             stats.kernelRXStageErrors.Load(),
		SendGSOCoalesceBatches:          stats.sendGSOCoalesceBatches.Load(),
		SendGSOCoalescePackets:          stats.sendGSOCoalescePackets.Load(),
		SendGSOCoalesceWires:            stats.sendGSOCoalesceWires.Load(),
		SendGSOCoalesceBytes:            stats.sendGSOCoalesceBytes.Load(),
		SendSoftwareSegments:            stats.sendSoftwareSegments.Load(),
		SendSoftwareSegmentFrames:       stats.sendSoftwareSegmentFrames.Load(),
		SendSoftwareSegmentWires:        stats.sendSoftwareSegmentWires.Load(),
		SendSoftwareSegmentBytes:        stats.sendSoftwareSegmentBytes.Load(),
		SendSoftwareSegmentFragDatagram: stats.sendSoftwareSegmentFragDatagram.Load(),
		SendSoftwareSegmentDrops:        stats.sendSoftwareSegmentDrops.Load(),
		DataSessionBatchQueuedPackets:   stats.dataSessionBatchQueuedPackets.Load(),
		DataSessionBatchQueuedBytes:     stats.dataSessionBatchQueuedBytes.Load(),
		DataSessionBatchFlushes:         stats.dataSessionBatchFlushes.Load(),
		DataSessionBatchFlushPackets:    stats.dataSessionBatchFlushPackets.Load(),
		DataSessionBatchFlushBytes:      stats.dataSessionBatchFlushBytes.Load(),
		DataSessionBatchFlushMaxPackets: stats.dataSessionBatchFlushMaxPackets.Load(),
		DataSessionBatchFlushMaxBytes:   stats.dataSessionBatchFlushMaxBytes.Load(),
		DataSessionBatchDirectPackets:   stats.dataSessionBatchDirectPackets.Load(),
		DataSessionBatchDirectBytes:     stats.dataSessionBatchDirectBytes.Load(),
		DataSessionBatchRXFrames:        stats.dataSessionBatchRXFrames.Load(),
		DataSessionBatchRXPackets:       stats.dataSessionBatchRXPackets.Load(),
		DataSessionBatchRXBytes:         stats.dataSessionBatchRXBytes.Load(),
		DataSessionBatchRXMaxPackets:    stats.dataSessionBatchRXMaxPackets.Load(),
		DataSessionBatchRXMaxBytes:      stats.dataSessionBatchRXMaxBytes.Load(),
		RejectICMPGenerated:             stats.rejectICMPGenerated.Load(),
		RejectRSTGenerated:              stats.rejectRSTGenerated.Load(),
		TTLICMPGenerated:                stats.ttlICMPGenerated.Load(),
		RejectReplyErrors:               stats.rejectReplyErrors.Load(),
		LastReceiveError:                lastReceiveError,
		LastInjectError:                 lastInjectError,
	}
}

func (stats *dataPathStats) setLastSessionDialError(err error) {
	if err == nil {
		return
	}
	stats.lastSessionDialError.Store(err.Error())
}

func (stats *dataPathStats) setLastReceiveError(err error) {
	if err == nil {
		return
	}
	stats.lastReceiveError.Store(err.Error())
}

func (stats *dataPathStats) setLastInjectError(err error, packet []byte) {
	if err == nil {
		return
	}
	stats.lastInjectError.Store(fmt.Sprintf("%v; %s", err, packetSummary(packet)))
}

func packetSummary(packet []byte) string {
	limit := 16
	if len(packet) < limit {
		limit = len(packet)
	}
	if limit == 0 {
		return "packet_len=0"
	}
	return fmt.Sprintf("packet_len=%d head=%x", len(packet), packet[:limit])
}

func firstPacket(packets [][]byte) []byte {
	for _, packet := range packets {
		if len(packet) > 0 {
			return packet
		}
	}
	return nil
}

func (daemon *Daemon) peerConfig(id core.IXID) (config.PeerConfig, bool) {
	return daemon.effectivePeerConfig(id)
}

func (daemon *Daemon) candidatePeerEndpoints(peer config.PeerConfig, route routing.Route, flowKey routing.FlowKey, hasFlow bool) ([]config.EndpointConfig, config.PolicyConfig, error) {
	policy := daemon.policyForRoute(route)
	if route.Endpoint != "" {
		var explicitErr error
		for _, endpoint := range peer.Endpoints {
			if endpoint.Name == route.Endpoint {
				if !endpointDataSessionEnabled(endpoint) {
					explicitErr = fmt.Errorf("peer %q endpoint %q is disabled", peer.ID, route.Endpoint)
					break
				}
				if !daemon.endpointSecurityCompatible(endpoint) {
					explicitErr = fmt.Errorf("peer %q endpoint %q is incompatible with local transport policy", peer.ID, route.Endpoint)
					break
				}
				if !daemon.endpointTransportProfileCompatible(endpoint) {
					explicitErr = fmt.Errorf("peer %q endpoint %q transport profile is incompatible with local transport policy", peer.ID, route.Endpoint)
					break
				}
				if !daemon.endpointKernelTransportCompatible(endpoint.Transport) {
					explicitErr = daemon.kernelTransportRequirementError(endpoint.Transport)
					break
				}
				return []config.EndpointConfig{endpoint}, policy, nil
			}
		}
		if explicitErr == nil {
			explicitErr = fmt.Errorf("peer %q does not have endpoint %q", peer.ID, route.Endpoint)
		}
		return nil, policy, explicitErr
	}
	candidates := append([]config.EndpointConfig(nil), peer.Endpoints...)
	if len(candidates) == 0 {
		return nil, policy, fmt.Errorf("peer %q has no configured endpoints", peer.ID)
	}
	candidates = daemon.filterCompatibleEndpoints(candidates)
	if len(candidates) == 0 {
		return nil, policy, fmt.Errorf("peer %q has no endpoints compatible with local transport policy", peer.ID)
	}
	if daemon.healthBasedFailoverEnabled() {
		candidates = daemon.filterHealthyEndpoints(peer.ID, candidates)
		if len(candidates) == 0 {
			return nil, policy, fmt.Errorf("peer %q has no healthy data endpoints", peer.ID)
		}
	}
	if hasFlow && policy.FlowStickiness {
		if binding, ok := daemon.lookupFlow(flowKey, route.NextHop); ok {
			if endpoint, ok := endpointByName(candidates, binding.Endpoint); ok {
				return []config.EndpointConfig{endpoint}, policy, nil
			}
		}
	}
	if policy.LoadBalance == "least_conn" {
		daemon.sortEndpointsByFlowCount(route.NextHop, candidates)
	} else {
		daemon.sortEndpointsByTransportPreference(route.NextHop, candidates)
	}
	return candidates, policy, nil
}

func (daemon *Daemon) fallbackPeerEndpoints(peer config.PeerConfig, excluded core.EndpointID) []config.EndpointConfig {
	candidates := make([]config.EndpointConfig, 0, len(peer.Endpoints))
	for _, endpoint := range peer.Endpoints {
		if endpoint.Name == excluded {
			continue
		}
		candidates = append(candidates, endpoint)
	}
	candidates = daemon.filterCompatibleEndpoints(candidates)
	if len(candidates) == 0 {
		return nil
	}
	candidates = daemon.filterHealthyEndpoints(peer.ID, candidates)
	if len(candidates) == 0 {
		return nil
	}
	return candidates
}

func (daemon *Daemon) filterCompatibleEndpoints(endpoints []config.EndpointConfig) []config.EndpointConfig {
	out := endpoints[:0]
	for _, endpoint := range endpoints {
		if endpointDataSessionEnabled(endpoint) &&
			daemon.endpointSecurityCompatible(endpoint) &&
			daemon.endpointTransportProfileCompatible(endpoint) &&
			daemon.endpointKernelTransportCompatible(endpoint.Transport) {
			out = append(out, endpoint)
		}
	}
	return out
}

func (daemon *Daemon) sortEndpointsByTransportPreference(peer core.IXID, endpoints []config.EndpointConfig) {
	if len(endpoints) < 2 {
		return
	}
	originalIndex := make(map[core.EndpointID]int, len(endpoints))
	for i, endpoint := range endpoints {
		originalIndex[endpoint.Name] = i
	}
	sort.SliceStable(endpoints, func(i, j int) bool {
		if daemon.transportPolicyPrefersNativePlaintextKernelTunnel() {
			left := daemon.endpointTransportPreferenceRank(endpoints[i])
			right := daemon.endpointTransportPreferenceRank(endpoints[j])
			if left != right {
				return left < right
			}
		}
		leftPriority := daemon.endpointPriorityScore(peer, endpoints[i])
		rightPriority := daemon.endpointPriorityScore(peer, endpoints[j])
		if leftPriority != rightPriority {
			return leftPriority > rightPriority
		}
		return originalIndex[endpoints[i].Name] < originalIndex[endpoints[j].Name]
	})
}

func (daemon *Daemon) endpointPriorityScore(peer core.IXID, endpoint config.EndpointConfig) int {
	if daemon == nil {
		return endpoint.Priority
	}
	return endpoint.Priority + daemon.localEndpointPriorityForCandidate(peer, endpoint)
}

func (daemon *Daemon) localEndpointPriorityForCandidate(peer core.IXID, candidate config.EndpointConfig) int {
	if daemon == nil {
		return 0
	}
	transportName := strings.ToLower(strings.TrimSpace(candidate.Transport))
	if transportName == "" {
		return 0
	}
	best := 0
	for _, endpoint := range daemon.desired.Endpoints {
		if !endpoint.Enabled || strings.ToLower(strings.TrimSpace(endpoint.Transport)) != transportName {
			continue
		}
		if peer != "" && !endpointPublishedToTarget(endpoint, controlTarget{ID: peer, Domain: daemon.desired.Domain.ID}) {
			continue
		}
		if endpoint.Priority > best {
			best = endpoint.Priority
		}
	}
	return best
}

func (daemon *Daemon) transportPolicyPrefersNativePlaintextKernelTunnel() bool {
	return daemon != nil &&
		!nativeTunnelRouteOffloadDisabledForPolicy() &&
		!daemon.transportPolicySendsSecureData() &&
		daemon.kernelTransportMode() != dataplane.KernelTransportModeDisabled
}

func (daemon *Daemon) endpointTransportPreferenceRank(endpoint config.EndpointConfig) int {
	security := endpointSecurityMetadataFromConfig(endpoint.Security, endpoint.TLSServerName)
	if daemon.endpointLocalEncryptionForSecurity(security) != securetransport.EncryptionPlaintext {
		return 4
	}
	switch transport.Protocol(strings.ToLower(strings.TrimSpace(endpoint.Transport))) {
	case transport.ProtocolIPIP, transport.ProtocolGRE:
		return 0
	case transport.ProtocolVXLAN:
		return 1
	case transport.ProtocolExperimentalTCP:
		return 2
	case transport.ProtocolUDP:
		return 3
	default:
		return 4
	}
}

func transportEndpointFromConfig(endpoint config.EndpointConfig) transport.Endpoint {
	return transport.Endpoint{
		Name:    endpoint.Name,
		Mode:    transport.EndpointMode(endpoint.Mode),
		Listen:  endpoint.Listen,
		Address: endpoint.Address,
		LocalBind: transport.LocalBind{
			SourceIP: strings.TrimSpace(endpoint.LocalBind.SourceIP),
			Iface:    strings.TrimSpace(endpoint.LocalBind.Iface),
		},
		Transport:     transport.Protocol(endpoint.Transport),
		TLSServerName: endpoint.TLSServerName,
		Encryption:    endpointTransportEncryption(endpoint),
		Enabled:       endpoint.Enabled,
	}
}

func endpointTransportEncryption(endpoint config.EndpointConfig) string {
	if endpoint.Mode == config.EndpointModePassive && strings.TrimSpace(endpoint.Security.Encryption) != "" {
		return normalizeEndpointEncryption(endpoint.Security.Encryption)
	}
	return ""
}
