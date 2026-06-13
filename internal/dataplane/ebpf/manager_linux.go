//go:build linux

// Package ebpf contains the Linux dataplane system integration layer. It uses
// netlink directly for link, address, and TC qdisc operations; shelling out to
// ip/tc is intentionally avoided in the runtime path.
package ebpf

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/kernelmodule"
	"trustix.local/trustix/internal/observability"
	"trustix.local/trustix/internal/routing"
	"trustix.local/trustix/internal/transport"
	"trustix.local/trustix/internal/transport/experimentaltcp"
	iptunneltransport "trustix.local/trustix/internal/transport/iptunnel"
	"trustix.local/trustix/internal/transport/kerneludp"
)

type Manager struct {
	mu                                          sync.Mutex
	captureMu                                   sync.Mutex
	rawTXMu                                     sync.Mutex
	kernelUDPUDPFallbackMu                      sync.RWMutex
	kernelUDPRXNeighMu                          sync.RWMutex
	spec                                        dataplane.AttachSpec
	snapshot                                    dataplane.Snapshot
	attached                                    bool
	capabilities                                []string
	warnings                                    []string
	restoreSysctls                              map[string]string
	linkAddedLANs                               map[string]bool
	addressAdded                                bool
	addressAddedLANs                            map[string]bool
	localVIPs                                   map[netip.Addr]struct{}
	qdiscPrepared                               bool
	qdiscPreparedLANs                           map[string]bool
	underlayQdiscPrepared                       bool
	lanOffloadProtection                        *persistedLinkOffloadState
	lanOffloadProtections                       map[string]*persistedLinkOffloadState
	managedCaptureRoutes                        map[string]managedCaptureRouteState
	deviceAccessProxyARP                        map[string]deviceAccessProxyARPState
	ingressProg                                 *cebpf.Program
	egressProg                                  *cebpf.Program
	kernelUDPTXSecureDirect                     *kernelUDPTXSecureDirectObject
	kernelUDPRXSecureDirect                     *kernelUDPRXSecureDirectObject
	ingressFilter                               *netlink.BpfFilter
	egressFilter                                *netlink.BpfFilter
	kernelUDPTXSecureDirectFilter               *netlink.BpfFilter
	kernelUDPTXSecureDirectEgressFilter         *netlink.BpfFilter
	kernelUDPRXSecureDirectFilter               *netlink.BpfFilter
	lanTCFilters                                map[string]lanTCFilterState
	underlayIngressProg                         *cebpf.Program
	underlayIngressFilter                       *netlink.BpfFilter
	kernelTransportPortMap                      *cebpf.Map
	kernelUDPRXNeighMap                         *cebpf.Map
	kernelUDPRXDevMap                           *cebpf.Map
	kernelUDPRXConfigMap                        *cebpf.Map
	kernelUDPRXDirectLANIfindex                 int
	kernelUDPRXDirectSourceMAC                  [6]byte
	kernelUDPRXDirectDestinationMAC             [6]byte
	kernelUDPRXDirectRedirectPeer               bool
	kernelUDPRXDirectBroadcast                  bool
	kernelUDPRXDirectRedirectIngress            bool
	kernelUDPRXDirectStaticDestinationPort      uint16
	kernelUDPRXDirectLocalDeliver               bool
	kernelUDPRXDirectLocalDeliverDev            bool
	kernelUDPRXDirectLocalIPv4                  uint32
	kernelUDPRXDirectLocalIPv4Mask              uint32
	kernelUDPRXDirectDecapL2Kfunc               bool
	kernelUDPRXDirectDecapL2DevKfunc            bool
	kernelUDPRXDirectParseDecapL2Kfunc          bool
	kernelUDPRXDirectTrustInnerChecksum         bool
	kernelUDPXDPRXDirectObject                  *experimentalTCPXDPObject
	kernelUDPXDPRXDirectEnabled                 bool
	kernelUDPXDPRXDirectAttached                bool
	kernelUDPXDPRXDirectAttachMode              string
	kernelUDPXDPRXDirectAttachFlags             int
	kernelUDPXDPRXDirectFallbackPass            bool
	kernelUDPXDPRXSecureDirectVethFallback      bool
	kernelUDPXDPRXDirectVethFallback            bool
	statsMap                                    *cebpf.Map
	packetPolicyMap                             *cebpf.Map
	routeMap                                    *cebpf.Map
	kernelUDPTXRouteMap                         *cebpf.Map
	kernelUDPTXRouteCacheMap                    *cebpf.Map
	kernelUDPTXFlowMap                          *cebpf.Map
	natConfigMap                                *cebpf.Map
	natSourceMap                                *cebpf.Map
	natRouteMap                                 *cebpf.Map
	natExcludeMap                               *cebpf.Map
	natBindingMap                               *cebpf.Map
	captureMap                                  *cebpf.Map
	captureScratchMap                           *cebpf.Map
	captureReader                               *perf.Reader
	captureRingReader                           *ringbuf.Reader
	captureEvents                               []dataplane.CaptureEvent
	captureEventNext                            int
	captureEventCount                           int
	captureSubs                                 map[chan []dataplane.CaptureEvent]struct{}
	captureLost                                 uint64
	captureSubDrops                             uint64
	routeEntries                                uint64
	kernelUDPTXDirectRoutes                     uint64
	kernelUDPTXDirectFlows                      uint64
	kernelUDPTXDirectInlineRoutes               uint64
	kernelUDPTXDirectInlineFlows                uint64
	kernelUDPTXDirectRouteCacheEnabled          bool
	kernelUDPTXDirectRouteCacheException        bool
	kernelUDPTXDirectInnerTCPChecksumKfunc      bool
	kernelUDPTXDirectOuterTCPChecksumKfunc      bool
	kernelUDPTXDirectOuterTCPHeaderKfunc        bool
	kernelUDPTXDirectTCPPartialCSUMKfunc        bool
	kernelUDPTXDirectPushTCPHeaderKfunc         bool
	kernelUDPTXDirectPushFlowTCPHeaderKfunc     bool
	kernelUDPTXDirectFinalizeFlowTCPHeaderKfunc bool
	kernelUDPTXDirectPushRouteTCPHeaderKfunc    bool
	kernelUDPTXDirectRouteTCPGSOKfunc           bool
	kernelUDPTXDirectRouteTCPGSOAsyncKfunc      bool
	kernelUDPTXDirectRouteTCPXmitKfunc          bool
	kernelUDPTXDirectExperimentalTCPSafeGSO     bool
	kernelUDPTXSecureDirectAttached             bool
	kernelUDPTXDirectSync                       kernelUDPTXDirectSyncStats
	kernelUDPRXDirectAttached                   bool
	kernelUDPRXSecureDirectAttached             bool
	nativeTunnelRoutes                          map[string]nativeTunnelRouteState
	natSourceEntries                            uint64
	natRouteEntries                             uint64
	natExcludeEntries                           uint64
	natBindingEntries                           uint64
	natBindingSyncErrors                        uint64
	natBindingKeys                              map[natBindingKey]struct{}
	dropReasons                                 map[observability.DropReason]uint64
	neighborCache                               *neighborCache
	lanInjectors                                map[string]*lanPacketInjector
	expTCPFlows                                 map[uint64]dataplane.ExperimentalTCPFlow
	expTCPTXTemplates                           map[uint64]experimentalTCPTXTemplate
	expTCPOuterTXSequences                      map[uint64]uint32
	expTCPOuterTXAcknowledgments                map[uint64]uint32
	expTCPTelemetry                             map[uint64]*dataplane.TransportPathTelemetry
	expTCPAllowed                               map[uint16]struct{}
	expTCPSubs                                  map[chan []dataplane.ExperimentalTCPFrame]struct{}
	expTCPFlowSubs                              map[uint64]map[chan []dataplane.ExperimentalTCPFrame]struct{}
	expTCPSubDrops                              uint64
	expTCPRXDuplicateDrops                      uint64
	expTCPRXReorderedBatches                    uint64
	kernelTransportAllowed                      map[uint16]struct{}
	expTCPFastPath                              *experimentalTCPFastPath
	expTCPRawFD                                 int
	kernelUDPRawFD                              int
	kernelUDPUDPFallbackSockets                 map[uint16]*kernelUDPUDPFallbackSocket
	rawIPv4TXFD                                 int
	rawIPv4TXFDOpen                             bool
	rawIPv4TXSocketOpens                        uint64
	kernelUDPUDPFallbackTXFrames                uint64
	kernelUDPUDPFallbackRXFrames                uint64
	kernelUDPUDPFallbackTXBatches               uint64
	kernelUDPUDPFallbackRXBatches               uint64
	kernelUDPUDPFallbackTXFallbacks             uint64
	kernelUDPUDPFallbackBindErrors              uint64
	kernelUDPUDPFallbackGSODisabled             atomic.Bool
	kernelUDPUDPFallbackGSOScatterDisabled      atomic.Bool
	kernelUDPUDPFallbackGSOAttempts             uint64
	kernelUDPUDPFallbackGSOSuccesses            uint64
	kernelUDPUDPFallbackGSOFrames               uint64
	kernelUDPUDPFallbackGSOBatches              uint64
	kernelUDPUDPFallbackGSOFallbacks            uint64
	kernelUDPUDPFallbackGSOScatterAttempts      uint64
	kernelUDPUDPFallbackGSOScatterSuccesses     uint64
	kernelUDPUDPFallbackGSOScatterFallbacks     uint64
	kernelUDPLastTX                             time.Time
	kernelUDPAFXDPIdleFallbackAttempts          uint64
	kernelUDPAFXDPIdleFallbackBatches           uint64
	kernelUDPAFXDPIdleFallbackFrames            uint64
	kernelUDPAFXDPIdleFallbackSentFrames        uint64
	kernelUDPAFXDPIdleFallbackErrors            uint64
	kernelUDPAFXDPIdleFallbackSkips             uint64
	rawUnderlayPacketTXAttempts                 uint64
	rawUnderlayPacketTXFrames                   uint64
	rawUnderlayPacketTXBatches                  uint64
	rawUnderlayPacketTXFallbacks                uint64
	expTCPRawTXFrames                           uint64
	expTCPRawTXBatches                          uint64
	expTCPSubmitted                             uint64
	expTCPReceived                              uint64
	kernelUDPFlows                              map[uint64]dataplane.KernelUDPFlow
	kernelUDPTXDirectSequences                  map[uint64]uint64
	kernelUDPTXTemplates                        map[uint64]kernelUDPTXTemplate
	kernelUDPTelemetry                          map[uint64]*dataplane.TransportPathTelemetry
	kernelUDPAllowed                            map[uint16]struct{}
	kernelUDPSubs                               map[chan []dataplane.KernelUDPFrame]struct{}
	kernelUDPFlowSubs                           map[uint64]map[chan []dataplane.KernelUDPFrame]struct{}
	kernelUDPSubDrops                           uint64
	kernelUDPSubmitted                          uint64
	kernelUDPReceived                           uint64
	kernelUDPRawTXFrames                        uint64
	kernelUDPRawRXFrames                        uint64
	kernelUDPRawTXBatches                       uint64
	kernelUDPRawRXBatches                       uint64
	expTCPCryptoFragments                       map[experimentalTCPCryptoFragmentKey]*experimentalTCPCryptoFragmentAssembly
	kernelUDPCryptoFragments                    map[kernelUDPCryptoFragmentKey]*kernelUDPCryptoFragmentAssembly
	kernelCryptoProbe                           dataplane.KernelCryptoProbe
	kernelCryptoProbeValid                      bool
	kernelCryptoInstallAttempts                 uint64
	kernelCryptoSpecsValidated                  uint64
	kernelCryptoSpecsRejected                   uint64
	kernelCryptoSpecValidateErrors              uint64
	kernelCryptoProviderUnavailableErrors       uint64
	kernelCryptoEntriesEncoded                  uint64
	kernelCryptoFlowRejects                     uint64
	kernelCryptoFrameRejects                    uint64
	kernelCryptoFlowMap                         *cebpf.Map
	kernelCryptoFlowMapCreateErrors             uint64
	kernelCryptoFlowMapUpdates                  uint64
	kernelCryptoFlowMapDeletes                  uint64
	kernelCryptoFlowMapEntries                  map[kernelCryptoFlowKey]struct{}
	kernelCryptoProvider                        *kernelCryptoProviderObject
	kernelCryptoCtxSlots                        map[kernelCryptoFlowKey]uint32
	kernelCryptoDevices                         map[uint64]*kernelCryptoDevice
	expTCPKernelCryptoDevices                   map[uint64]*kernelCryptoDevice
	kernelCryptoNextSlot                        uint32
	kernelCryptoProviderLoadErrors              uint64
	kernelCryptoAEADCreateAttempts              uint64
	kernelCryptoAEADCreateSuccesses             uint64
	kernelCryptoAEADCreateErrors                uint64
	kernelCryptoAEADRoundTripAttempts           uint64
	kernelCryptoAEADRoundTripSuccesses          uint64
	kernelCryptoAEADRoundTripErrors             uint64
	kernelCryptoFrameSealAttempts               uint64
	kernelCryptoFrameSealSuccesses              uint64
	kernelCryptoFrameSealErrors                 uint64
	kernelCryptoFrameOpenAttempts               uint64
	kernelCryptoFrameOpenSuccesses              uint64
	kernelCryptoFrameOpenErrors                 uint64
	kernelCryptoFrameReplayDrops                uint64
	kernelCryptoDeviceSealAttempts              uint64
	kernelCryptoDeviceSealSuccesses             uint64
	kernelCryptoDeviceSealErrors                uint64
	kernelCryptoDeviceSealBorrowAttempts        uint64
	kernelCryptoDeviceSealBorrowSuccesses       uint64
	kernelCryptoDeviceSealBorrowFallbacks       uint64
	kernelCryptoDeviceSealBatchCalls            uint64
	kernelCryptoDeviceSealBatchRequests         uint64
	kernelCryptoDeviceSealBatchMaxRequests      uint64
	kernelCryptoDeviceSealBatchPlaintextBytes   uint64
	kernelCryptoDeviceSealBatchMaxPlaintextLen  uint64
	kernelCryptoDeviceOpenAttempts              uint64
	kernelCryptoDeviceOpenSuccesses             uint64
	kernelCryptoDeviceOpenErrors                uint64
	kernelCryptoDeviceOpenBorrowAttempts        uint64
	kernelCryptoDeviceOpenBorrowSuccesses       uint64
	kernelCryptoDeviceOpenBorrowFallbacks       uint64
	kernelCryptoDeviceOpenBatchCalls            uint64
	kernelCryptoDeviceOpenBatchRequests         uint64
	kernelCryptoDeviceOpenBatchMaxRequests      uint64
	kernelCryptoDeviceOpenBatchCiphertextBytes  uint64
	kernelCryptoDeviceOpenBatchMaxCiphertextLen uint64
	kernelCryptoDeviceOpenBatchPlaintextBytes   uint64
	kernelCryptoDeviceOpenBatchMaxPlaintextLen  uint64
	kernelCryptoTCSealConfiguredFlows           uint64
}

type kernelUDPTXDirectSyncStats struct {
	Attempts              uint64
	SkippedMissingMaps    uint64
	SkippedDisabled       uint64
	SkippedNAT            uint64
	SkippedNoUnderlay     uint64
	SkippedNoRoutes       uint64
	SkippedNoFlows        uint64
	UnderlayLookupErrors  uint64
	BadUnderlayAttrs      uint64
	RouteSourceLookups    uint64
	RouteSourceErrors     uint64
	RouteGatewayNextHops  uint64
	RouteIfindexSwitches  uint64
	RouteLinkLookupErrors uint64
	RoutesScanned         uint64
	RoutesSkippedKind     uint64
	RoutesSkippedPrefix   uint64
	RoutesBlocked         uint64
	RoutesWithoutFlows    uint64
	RouteFlowsCandidate   uint64
	FlowsScanned          uint64
	FlowsSkippedZeroID    uint64
	FlowsPeerMatches      uint64
	FlowsEndpointMatches  uint64
	FlowsSecurityAllowed  uint64
	FlowsSecurityBlocked  uint64
	PreparePacketErrors   uint64
	InvalidPackets        uint64
	NeighborMisses        uint64
	RouteFlowAppendReject uint64
	FlowsWritten          uint64
	RoutesWritten         uint64
	SecureFlowsWritten    uint64
	InlineFlowsWritten    uint64
}

type nativeTunnelRouteState struct {
	Key      string
	Protocol string
	Tunnel   string
	Prefix   netip.Prefix
	Gateway  netip.Addr
	MTU      int
	AdvMSS   int
	Endpoint core.EndpointID
}

type managedCaptureRouteState struct {
	Key            string
	Prefix         netip.Prefix
	Iface          string
	Ifindex        int
	Gateway        netip.Addr
	DestinationMAC string
}

type deviceAccessProxyARPState struct {
	Key     string
	Iface   string
	Ifindex int
	Address netip.Addr
}

type experimentalTCPTXTemplate struct {
	packet           experimentaltcp.TCPPacket
	dst              [4]byte
	flow             dataplane.ExperimentalTCPFlow
	expiresAt        time.Time
	autoLocalAddress bool
}

type kernelUDPTXTemplate struct {
	packet           kerneludp.UDPPacket
	dst              [4]byte
	flow             dataplane.KernelUDPFlow
	expiresAt        time.Time
	autoLocalAddress bool
}

type preparedExperimentalTCPTXFrame struct {
	packet           experimentaltcp.TCPPacket
	wireFrame        experimentaltcp.Frame
	flow             dataplane.ExperimentalTCPFlow
	bytes            int
	rawDst           [4]byte
	sourceIP4        [4]byte
	destinationIP4   [4]byte
	sourcePort       uint16
	destinationPort  uint16
	frameLen         int
	packetLen        int
	tcpSeqLen        int
	fragmentPayload  int
	txInnerHash      uint64
	txInnerHashValid bool
	kernelTX         bool
}

type preparedKernelUDPTXFrame struct {
	packet           kerneludp.UDPPacket
	wireFrame        kerneludp.Frame
	flow             dataplane.KernelUDPFlow
	bytes            int
	rawDst           [4]byte
	sourceIP4        [4]byte
	destinationIP4   [4]byte
	sourcePort       uint16
	destinationPort  uint16
	frameWireLen     int
	packetWireLen    int
	fragmentPayload  int
	txInnerHash      uint64
	txInnerHashValid bool
}

type kernelUDPTXTelemetryBatch struct {
	flow   dataplane.KernelUDPFlow
	frames uint64
	bytes  uint64
}

type experimentalTCPTXTelemetryBatch struct {
	flow   dataplane.ExperimentalTCPFlow
	frames uint64
	bytes  uint64
}

type kernelUDPTXSequenceBatch struct {
	flowID       uint64
	current      uint64
	value        kernelUDPTXFlowValue
	haveValue    bool
	mapChecked   bool
	mapDirty     bool
	initialized  bool
	reservedHigh uint64
}

type pendingKernelUDPSealFrame struct {
	index   int
	request kernelCryptoDeviceSealRequest
}

type pendingKernelUDPSealBatch struct {
	indexes  []int
	requests []kernelCryptoDeviceSealRequest
}

type pendingKernelUDPOpenFrame struct {
	index   int
	request kernelCryptoDeviceOpenRequest
	suite   string
	epoch   uint64
}

type pendingKernelUDPOpenBatch struct {
	indexes  []int
	requests []kernelCryptoDeviceOpenRequest
	suites   []string
	epochs   []uint64
}

func kernelUDPSealPendingBatchFor(pendingByFlow *map[uint64]*pendingKernelUDPSealBatch, singleFlowID *uint64, single **pendingKernelUDPSealBatch, flowID uint64, capacity int) *pendingKernelUDPSealBatch {
	if *pendingByFlow != nil {
		pending := (*pendingByFlow)[flowID]
		if pending == nil {
			pending = &pendingKernelUDPSealBatch{}
			(*pendingByFlow)[flowID] = pending
		}
		return pending
	}
	if *single == nil {
		*singleFlowID = flowID
		*single = &pendingKernelUDPSealBatch{
			indexes:  make([]int, 0, capacity),
			requests: make([]kernelCryptoDeviceSealRequest, 0, capacity),
		}
		return *single
	}
	if *singleFlowID == flowID {
		return *single
	}
	*pendingByFlow = map[uint64]*pendingKernelUDPSealBatch{
		*singleFlowID: *single,
	}
	pending := &pendingKernelUDPSealBatch{}
	(*pendingByFlow)[flowID] = pending
	return pending
}

func kernelUDPOpenPendingBatchFor(pendingByFlow *map[uint64]*pendingKernelUDPOpenBatch, singleFlowID *uint64, single **pendingKernelUDPOpenBatch, flowID uint64, capacity int) *pendingKernelUDPOpenBatch {
	if *pendingByFlow != nil {
		pending := (*pendingByFlow)[flowID]
		if pending == nil {
			pending = &pendingKernelUDPOpenBatch{}
			(*pendingByFlow)[flowID] = pending
		}
		return pending
	}
	if *single == nil {
		*singleFlowID = flowID
		*single = &pendingKernelUDPOpenBatch{
			indexes:  make([]int, 0, capacity),
			requests: make([]kernelCryptoDeviceOpenRequest, 0, capacity),
			suites:   make([]string, 0, capacity),
			epochs:   make([]uint64, 0, capacity),
		}
		return *single
	}
	if *singleFlowID == flowID {
		return *single
	}
	*pendingByFlow = map[uint64]*pendingKernelUDPOpenBatch{
		*singleFlowID: *single,
	}
	pending := &pendingKernelUDPOpenBatch{}
	(*pendingByFlow)[flowID] = pending
	return pending
}

type kernelUDPCryptoFragmentKey struct {
	flowID   uint64
	sequence uint64
}

type experimentalTCPCryptoFragmentKey struct {
	flowID   uint64
	sequence uint64
}

type experimentalTCPCryptoFragmentAssembly struct {
	createdAt           time.Time
	frame               dataplane.ExperimentalTCPFrame
	packet              experimentaltcp.TCPPacket
	innerIPv4           bool
	payload             []byte
	pending             [][]byte
	receivedFragments   []bool
	received            int
	totalLen            int
	fragmentPayloadSize int
	lastFragmentLen     int
}

type kernelUDPCryptoFragmentAssembly struct {
	createdAt           time.Time
	frame               dataplane.KernelUDPFrame
	packet              kerneludp.UDPPacket
	innerIPv4           bool
	payload             []byte
	pending             [][]byte
	receivedFragments   []bool
	received            int
	totalLen            int
	fragmentPayloadSize int
	lastFragmentLen     int
}

func kernelUDPCryptoFragmentAssembledMaxPayload() int {
	if kernelCryptoDeviceSecureMaxPlain > 0 {
		return kernelCryptoSecureHeaderLen + kernelCryptoDeviceSecureMaxPlain + kernelCryptoFrameTagLen
	}
	return kerneludp.MaxPayload
}

func experimentalTCPCryptoFragmentAssembledMaxPayload() int {
	if kernelCryptoDeviceSecureMaxPlain > 0 {
		return kernelCryptoSecureHeaderLen + kernelCryptoDeviceSecureMaxPlain + kernelCryptoFrameTagLen
	}
	return experimentaltcp.MaxPayload
}

var preparedKernelUDPTXFramePool = sync.Pool{
	New: func() any {
		frames := make([]preparedKernelUDPTXFrame, 0, 256)
		return &frames
	},
}

var preparedExperimentalTCPTXFramePool = sync.Pool{
	New: func() any {
		frames := make([]preparedExperimentalTCPTXFrame, 0, 256)
		return &frames
	},
}

var receivedKernelUDPFrameBatchPool = sync.Pool{
	New: func() any {
		frames := make([]receivedKernelUDPFrame, 0, 256)
		return &frames
	},
}

var deliveredKernelUDPFrameBatchPool = sync.Pool{
	New: func() any {
		frames := make([]dataplane.KernelUDPFrame, 0, 256)
		return &frames
	},
}

var deliveredExperimentalTCPFrameBatchPool = sync.Pool{
	New: func() any {
		frames := make([]dataplane.ExperimentalTCPFrame, 0, 256)
		return &frames
	},
}

var experimentalTCPCryptoFragmentPayloadPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, 4096)
		return &buf
	},
}

func takePreparedKernelUDPTXFrames(size int) (*[]preparedKernelUDPTXFrame, []preparedKernelUDPTXFrame) {
	holder := preparedKernelUDPTXFramePool.Get().(*[]preparedKernelUDPTXFrame)
	frames := *holder
	if cap(frames) < size {
		frames = make([]preparedKernelUDPTXFrame, 0, size)
	} else {
		frames = frames[:0]
	}
	return holder, frames
}

func putPreparedKernelUDPTXFrames(holder *[]preparedKernelUDPTXFrame, frames []preparedKernelUDPTXFrame) {
	clear(frames)
	if cap(frames) > 4096 {
		*holder = nil
		return
	}
	*holder = frames[:0]
	preparedKernelUDPTXFramePool.Put(holder)
}

func takePreparedExperimentalTCPTXFrames(size int) (*[]preparedExperimentalTCPTXFrame, []preparedExperimentalTCPTXFrame) {
	holder := preparedExperimentalTCPTXFramePool.Get().(*[]preparedExperimentalTCPTXFrame)
	frames := *holder
	if cap(frames) < size {
		frames = make([]preparedExperimentalTCPTXFrame, 0, size)
	} else {
		frames = frames[:0]
	}
	return holder, frames
}

func putPreparedExperimentalTCPTXFrames(holder *[]preparedExperimentalTCPTXFrame, frames []preparedExperimentalTCPTXFrame) {
	clear(frames)
	if cap(frames) > 4096 {
		*holder = nil
		return
	}
	*holder = frames[:0]
	preparedExperimentalTCPTXFramePool.Put(holder)
}

func takeReceivedKernelUDPFrameBatch(size int) (*[]receivedKernelUDPFrame, []receivedKernelUDPFrame) {
	holder := receivedKernelUDPFrameBatchPool.Get().(*[]receivedKernelUDPFrame)
	frames := *holder
	if cap(frames) < size {
		frames = make([]receivedKernelUDPFrame, 0, size)
	} else {
		frames = frames[:0]
	}
	return holder, frames
}

func resetReceivedKernelUDPFrameBatch(frames []receivedKernelUDPFrame) []receivedKernelUDPFrame {
	return frames[:0]
}

func putReceivedKernelUDPFrameBatch(holder *[]receivedKernelUDPFrame, frames []receivedKernelUDPFrame) {
	clear(frames)
	if cap(frames) > 4096 {
		*holder = nil
		return
	}
	*holder = frames[:0]
	receivedKernelUDPFrameBatchPool.Put(holder)
}

func takeDeliveredKernelUDPFrameBatch(size int) (*[]dataplane.KernelUDPFrame, []dataplane.KernelUDPFrame) {
	holder := deliveredKernelUDPFrameBatchPool.Get().(*[]dataplane.KernelUDPFrame)
	frames := *holder
	if cap(frames) < size {
		frames = make([]dataplane.KernelUDPFrame, 0, size)
	} else {
		frames = frames[:0]
	}
	return holder, frames
}

func putDeliveredKernelUDPFrameBatch(holder *[]dataplane.KernelUDPFrame, frames []dataplane.KernelUDPFrame) {
	if holder == nil {
		return
	}
	clear(frames)
	if cap(frames) > 4096 {
		*holder = nil
		return
	}
	*holder = frames[:0]
	deliveredKernelUDPFrameBatchPool.Put(holder)
}

func takeDeliveredExperimentalTCPFrameBatch(size int) (*[]dataplane.ExperimentalTCPFrame, []dataplane.ExperimentalTCPFrame) {
	holder := deliveredExperimentalTCPFrameBatchPool.Get().(*[]dataplane.ExperimentalTCPFrame)
	frames := *holder
	if cap(frames) < size {
		frames = make([]dataplane.ExperimentalTCPFrame, 0, size)
	} else {
		frames = frames[:0]
	}
	return holder, frames
}

func putDeliveredExperimentalTCPFrameBatch(holder *[]dataplane.ExperimentalTCPFrame, frames []dataplane.ExperimentalTCPFrame) {
	if holder == nil {
		return
	}
	clear(frames)
	if cap(frames) > 4096 {
		*holder = nil
		return
	}
	*holder = frames[:0]
	deliveredExperimentalTCPFrameBatchPool.Put(holder)
}

func takeExperimentalTCPCryptoFragmentPayload(size int) ([]byte, func()) {
	if size <= 0 {
		return nil, nil
	}
	const maxPooled = 64 * 1024
	if size > maxPooled {
		return make([]byte, size), nil
	}
	holder := experimentalTCPCryptoFragmentPayloadPool.Get().(*[]byte)
	buf := *holder
	if cap(buf) < size {
		buf = make([]byte, size)
	} else {
		buf = buf[:size]
	}
	released := false
	release := func() {
		if released {
			return
		}
		released = true
		full := buf[:cap(buf)]
		clear(full)
		*holder = full[:0]
		experimentalTCPCryptoFragmentPayloadPool.Put(holder)
	}
	return buf, release
}

func experimentalTCPCryptoFragmentPlainBuffer(payload []byte) []byte {
	if len(payload) <= kernelCryptoSecureHeaderLen+kernelCryptoFrameTagLen {
		return nil
	}
	return payload[kernelCryptoSecureHeaderLen : len(payload)-kernelCryptoFrameTagLen]
}

const (
	captureMagic                                               uint32 = 0x54495845
	captureEventHeader                                                = 40
	capturePerfBufferDefaultPages                                     = 1024
	capturePerfBufferMaxPages                                         = 4096
	captureRingbufDefaultSize                                         = 4 * 1024 * 1024
	captureRingbufMaxSize                                             = 32 * 1024 * 1024
	captureReaderDefaultBatchSize                                     = 256
	captureReaderDefaultDrainTimeout                                  = 50 * time.Microsecond
	captureEventBase                                                  = -128
	captureScratchPtrOffset                                           = captureEventBase - 8
	captureCopyOffsetOffset                                           = captureEventBase - 16
	captureCopyRemainingOffset                                        = captureEventBase - 20
	capturePerfReturnOffset                                           = captureEventBase - 24
	captureOutputModeRingbuf                                          = "ringbuf"
	captureOutputModePerf                                             = "perf"
	captureScratchMaxSize                                             = 32*1024 - captureEventHeader
	captureRingLimit                                                  = 128
	tcStatsMapMaxEntries                                              = 190
	persistedStateVersion                                             = 1
	trustixRouteProtocol                                              = 0x54
	managedLANTxQueueLen                                              = 1000
	managedCaptureSyntheticGateway                                    = "169.254.84.84"
	natDefaultMaxBindings                                             = 16 * 1024
	skbLenOffset                                                      = 0
	skbIfindexOffset                                                  = 40
	skbCBOffset                                                       = 48
	skbDataOffset                                                     = 76
	skbDataEndOffset                                                  = 80
	skbGSOSizeOffset                                                  = 176
	tcActUnspec                                                       = -1
	tcActOK                                                           = 0
	tcActShot                                                         = 2
	tcActStolen                                                       = 4
	bpfFIngress                                                       = 1
	bpfAdjRoomMAC                                                     = 1
	bpfAdjRoomFixedGSO                                                = 1 << 0
	bpfAdjRoomEncapL3IPv4                                             = 1 << 1
	bpfAdjRoomEncapL4UDP                                              = 1 << 4
	bpfAdjRoomNoCSUMReset                                             = 32
	bpfAdjRoomEncapL2ETH                                              = 1 << 6
	bpfAdjRoomDecapL3IPv4                                             = 1 << 7
	bpfAdjRoomEncapL2Shift                                            = 56
	bpfFRecomputeCSUM                                                 = 1 << 0
	bpfFInvalidateHash                                                = 1 << 1
	rejectEthernetHeaderLen                                           = 14
	rejectIPv4HeaderLen                                               = 20
	rejectTCPHeaderLen                                                = 20
	rejectICMPHeaderLen                                               = 8
	rejectICMPQuoteLen                                                = 28
	rejectTCPRSTWireLen                                               = rejectEthernetHeaderLen + rejectIPv4HeaderLen + rejectTCPHeaderLen
	rejectICMPUnreachableWireLen                                      = rejectEthernetHeaderLen + rejectIPv4HeaderLen + rejectICMPHeaderLen + rejectICMPQuoteLen
	routeActionCapture                                                = 1
	routeActionLocal                                                  = 2
	routeActionBlackhole                                              = 3
	routeActionReject                                                 = 4
	ipProtocolICMP                                                    = 1
	ipProtocolTCP                                                     = 6
	ipProtocolUDP                                                     = 17
	ipv4FragmentOffsetMask                                            = 0x1fff
	ipv4FragmentMaskLittleEndian                                      = 0xff3f
	natEventTranslatedFlag                                            = 1
	natFlagOffset                                                     = -24
	natOriginalSourceOffset                                           = -28
	natGatewayOffset                                                  = -32
	natLPMKeyPrefixOffset                                             = -48
	natLPMKeyAddrOffset                                               = -44
	natMapKeyOffset                                                   = -56
	natConfigKeyOffset                                                = -60
	natBindingKeyOffset                                               = -80
	natDnatOriginalOffset                                             = -84
	natDnatGatewayOffset                                              = -88
	natDnatChecksumOffset                                             = -92
	natDnatConfigKeyOffset                                            = -96
	natDnatExpiresOffset                                              = -104
	packetPolicyKeyOffset                                             = -64
	kernelUDPTXFlowDefaultOffset                                      = -512
	kernelUDPTXFlowKeyOffset                                          = -504
	kernelUDPTXRouteKeyOffset                                         = -496
	kernelUDPTXIfindexOffset                                          = -488
	kernelUDPTXFlagsOffset                                            = -484
	kernelUDPTXHeaderOffset                                           = -480
	kernelUDPTXIPHeaderOffset                                         = -464
	kernelUDPTXUDPHeaderOffset                                        = -440
	kernelUDPTXFrameHeaderOffset                                      = kernelUDPTXUDPHeaderOffset + 8
	kernelUDPTXTCPHeaderOffset                                        = kernelUDPTXIPHeaderOffset + rejectIPv4HeaderLen
	kernelUDPTXTCPFrameHeaderOffset                                   = kernelUDPTXTCPHeaderOffset + rejectTCPHeaderLen
	kernelUDPTXChecksumPseudoOffset                                   = -376
	kernelUDPTXGSOSegmentLenOffset                                    = -360
	kernelUDPTXGSOActiveOffset                                        = -356
	kernelUDPTXRouteFlagsOffset                                       = -352
	kernelUDPTXRoutePtrOffset                                         = -384
	kernelUDPTXFlowPtrOffset                                          = -392
	kernelUDPTXFlowMaskScratchOffset                                  = -400
	kernelUDPTXIPChecksumSumOffset                                    = -348
	kernelUDPTXTCPChecksumPayloadOffset                               = -344
	kernelUDPTXTCPChecksumTailOffset                                  = -340
	kernelUDPTXTCPChecksumSumOffset                                   = -336
	kernelUDPTXTCPChecksumInitialSumOffset                            = -332
	kernelUDPTXTCPChecksumChunkOffset                                 = -320
	kernelUDPTXTCPChecksumChunkLen                                    = 256
	kernelUDPTXBuildUDPHeaderArgsOffset                               = kernelUDPTXHeaderOffset
	kernelUDPTXBuildUDPHeaderArgsSourceIPOffset                       = kernelUDPTXBuildUDPHeaderArgsOffset + 16
	kernelUDPTXBuildUDPHeaderArgsDestinationIPOffset                  = kernelUDPTXBuildUDPHeaderArgsOffset + 20
	kernelUDPTXBuildUDPHeaderArgsSourcePortOffset                     = kernelUDPTXBuildUDPHeaderArgsOffset + 24
	kernelUDPTXBuildUDPHeaderArgsDestinationPortOffset                = kernelUDPTXBuildUDPHeaderArgsOffset + 26
	kernelUDPTXBuildUDPHeaderArgsIPTotalLenOffset                     = kernelUDPTXBuildUDPHeaderArgsOffset + 28
	kernelUDPTXBuildUDPHeaderArgsUDPLenOffset                         = kernelUDPTXBuildUDPHeaderArgsOffset + 30
	kernelUDPTXBuildUDPHeaderArgsIPCheckBaseOffset                    = kernelUDPTXBuildUDPHeaderArgsOffset + 32
	kernelUDPTXBuildUDPHeaderArgsFlowIDOffset                         = kernelUDPTXBuildUDPHeaderArgsOffset + 40
	kernelUDPTXBuildUDPHeaderArgsSequenceOffset                       = kernelUDPTXBuildUDPHeaderArgsOffset + 48
	kernelUDPTXBuildUDPHeaderArgsPayloadLenOffset                     = kernelUDPTXBuildUDPHeaderArgsOffset + 56
	kernelUDPTXBuildUDPHeaderArgsFlagsOffset                          = kernelUDPTXBuildUDPHeaderArgsOffset + 60
	kernelUDPTXPushUDPHeaderArgsOffset                                = kernelUDPTXBuildUDPHeaderArgsOffset
	kernelUDPTXTIXTFinalizeTCPHeaderArgsOffset                        = kernelUDPTXHeaderOffset
	kernelUDPTXTIXTFinalizeTCPHeaderArgsSourceIPOffset                = kernelUDPTXTIXTFinalizeTCPHeaderArgsOffset + 16
	kernelUDPTXTIXTFinalizeTCPHeaderArgsDestinationIPOffset           = kernelUDPTXTIXTFinalizeTCPHeaderArgsOffset + 20
	kernelUDPTXTIXTFinalizeTCPHeaderArgsSourcePortOffset              = kernelUDPTXTIXTFinalizeTCPHeaderArgsOffset + 24
	kernelUDPTXTIXTFinalizeTCPHeaderArgsDestinationPortOffset         = kernelUDPTXTIXTFinalizeTCPHeaderArgsOffset + 26
	kernelUDPTXTIXTFinalizeTCPHeaderArgsIPTotalLenOffset              = kernelUDPTXTIXTFinalizeTCPHeaderArgsOffset + 28
	kernelUDPTXTIXTFinalizeTCPHeaderArgsIPCheckBaseOffset             = kernelUDPTXTIXTFinalizeTCPHeaderArgsOffset + 30
	kernelUDPTXTIXTFinalizeTCPHeaderArgsFlowIDOffset                  = kernelUDPTXTIXTFinalizeTCPHeaderArgsOffset + 40
	kernelUDPTXTIXTFinalizeTCPHeaderArgsSequenceOffset                = kernelUDPTXTIXTFinalizeTCPHeaderArgsOffset + 48
	kernelUDPTXTIXTFinalizeTCPHeaderArgsPayloadLenOffset              = kernelUDPTXTIXTFinalizeTCPHeaderArgsOffset + 56
	kernelUDPTXTIXTFinalizeTCPHeaderArgsFlagsOffset                   = kernelUDPTXTIXTFinalizeTCPHeaderArgsOffset + 60
	kernelUDPTXTIXTPushTCPHeaderArgsOffset                            = kernelUDPTXTIXTFinalizeTCPHeaderArgsOffset
	kernelUDPTXTIXTPushFlowTCPHeaderArgsOffset                        = kernelUDPTXHeaderOffset
	kernelUDPTXTIXTPushFlowTCPHeaderArgsFlowIDOffset                  = kernelUDPTXTIXTPushFlowTCPHeaderArgsOffset
	kernelUDPTXTIXTPushFlowTCPHeaderArgsPayloadLenOffset              = kernelUDPTXTIXTPushFlowTCPHeaderArgsOffset + 8
	kernelUDPTXTIXTPushFlowTCPHeaderArgsClearFlagsOffset              = kernelUDPTXTIXTPushFlowTCPHeaderArgsOffset + 12
	kernelUDPTXTIXTFinalizeFlowTCPHeaderArgsOffset                    = kernelUDPTXTIXTPushFlowTCPHeaderArgsOffset
	kernelUDPTXTIXTFinalizeFlowTCPHeaderArgsFlowIDOffset              = kernelUDPTXTIXTPushFlowTCPHeaderArgsFlowIDOffset
	kernelUDPTXTIXTFinalizeFlowTCPHeaderArgsPayloadLenOffset          = kernelUDPTXTIXTPushFlowTCPHeaderArgsPayloadLenOffset
	kernelUDPTXTIXTFinalizeFlowTCPHeaderArgsClearFlagsOffset          = kernelUDPTXTIXTPushFlowTCPHeaderArgsClearFlagsOffset
	kernelUDPTXTIXTPushRouteTCPHeaderArgsOffset                       = kernelUDPTXHeaderOffset
	kernelUDPTXTIXTPushRouteTCPHeaderArgsClearFlagsOffset             = kernelUDPTXTIXTPushRouteTCPHeaderArgsOffset
	kernelUDPTXTIXTSegmentRouteTCPGSOArgsOffset                       = kernelUDPTXHeaderOffset
	kernelUDPTXTIXTSegmentRouteTCPGSOArgsClearFlagsOffset             = kernelUDPTXTIXTSegmentRouteTCPGSOArgsOffset
	kernelUDPTXOuterOverhead                                          = 60
	experimentalTCPTXOuterOverhead                                    = 80
	experimentalTCPTXRouteGSOSegmentsStolen                           = 4
	experimentalTCPTXRouteXmitStolen                                  = 5
	experimentalTCPTXRouteXmitQueued                                  = 6
	kernelUDPTXUDPFrameHeaderLen                                      = 8 + kerneludp.HeaderLen
	kernelUDPTXTCPFrameHeaderLen                                      = rejectTCPHeaderLen + experimentaltcp.HeaderLen
	kernelUDPTXTCPChecksumPayloadMax                                  = 1500
	experimentalTCPRawFallbackDefaultMTU                              = 1500
	kernelUDPRawFallbackDefaultMTU                                    = 1500
	kernelUDPTXRouteMaxFlows                                          = 8
	kernelUDPTXRouteValueSize                                         = 464
	kernelUDPTXFlowValueSize                                          = 48
	kernelUDPTXRouteInlineFlowOffset                                  = 80
	kernelUDPTXRouteInlineFlow2Offset                                 = kernelUDPTXRouteInlineFlowOffset + kernelUDPTXFlowValueSize
	kernelUDPTXRouteInlineFlow3Offset                                 = kernelUDPTXRouteInlineFlow2Offset + kernelUDPTXFlowValueSize
	kernelUDPTXRouteInlineFlow4Offset                                 = kernelUDPTXRouteInlineFlow3Offset + kernelUDPTXFlowValueSize
	kernelUDPTXRouteInlineFlow5Offset                                 = kernelUDPTXRouteInlineFlow4Offset + kernelUDPTXFlowValueSize
	kernelUDPTXRouteInlineFlow6Offset                                 = kernelUDPTXRouteInlineFlow5Offset + kernelUDPTXFlowValueSize
	kernelUDPTXRouteInlineFlow7Offset                                 = kernelUDPTXRouteInlineFlow6Offset + kernelUDPTXFlowValueSize
	kernelUDPTXRouteInlineFlow8Offset                                 = kernelUDPTXRouteInlineFlow7Offset + kernelUDPTXFlowValueSize
	kernelUDPTXRouteCacheRouteOffset                                  = 24
	kernelUDPTXRouteCacheValueSize                                    = 488
	kernelUDPTXRouteFlagDirectOnly                                    = 1
	kernelUDPTXRouteFlagInlineFlow                                    = 2
	kernelUDPTXRouteFlagBypass                                        = 4
	kernelUDPTXStatSuccess                                            = 22
	kernelUDPTXStatErrors                                             = 23
	kernelUDPTXStatDrops                                              = 24
	kernelUDPRXDirectStatSuccess                                      = 25
	kernelUDPRXDirectStatErrors                                       = 26
	kernelUDPRXDirectStatDrops                                        = 27
	kernelUDPRXDirectStatPasses                                       = 28
	packetPolicyTCPMSSClampStatSuccess                                = 29
	packetPolicyTCPMSSClampStatErrors                                 = 30
	packetPolicyTCPMSSClampStatDrops                                  = 31
	kernelUDPRXDirectStatNeighHits                                    = 32
	kernelUDPRXDirectStatNeighMisses                                  = 33
	kernelUDPTXSecureDirectStatAttempts                               = 34
	kernelUDPTXSecureDirectStatCandidates                             = 35
	kernelUDPTXSecureDirectStatSuccess                                = 36
	kernelUDPTXSecureDirectStatFallbacks                              = 37
	kernelUDPTXSecureDirectStatNoContext                              = 38
	kernelUDPTXSecureDirectStatHeaderErrors                           = 39
	kernelUDPTXSecureDirectStatEncryptErrors                          = 40
	kernelUDPTXSecureDirectStatSequenceErrors                         = 41
	kernelUDPTXSecureDirectStatMTUFallbacks                           = 42
	kernelUDPTXSecureDirectStatDrops                                  = 43
	kernelUDPTXSecureDirectStatRouteMisses                            = 44
	kernelUDPTXSecureDirectStatFlowMisses                             = 45
	kernelUDPTXSecureDirectStatFlagMisses                             = 46
	kernelUDPTXSecureDirectStatFragmentFallbacks                      = 47
	kernelUDPTXSecureDirectStatLenMismatches                          = 48
	kernelUDPTXSecureDirectStatNonTCPFallbacks                        = 49
	kernelUDPTXSecureDirectStatSYNFallbacks                           = 50
	kernelUDPTXSecureDirectStatChecksumFallbacks                      = 51
	kernelUDPTXSecureDirectStatMTUPlainMaxFallbacks                   = 52
	kernelUDPTXSecureDirectStatMTUUnderlayFallbacks                   = 53
	kernelUDPTXSecureDirectStatLenGSOFallbacks                        = 54
	kernelUDPTXSecureDirectStatLenShortFallbacks                      = 55
	kernelUDPTXSecureDirectStatMTUUnderlay1500Fallbacks               = 56
	kernelUDPTXSecureDirectStatMTUUnderlayJumboFallbacks              = 57
	kernelUDPTXSecureDirectStatMTUUnderlayInnerGT1400Fallbacks        = 58
	kernelUDPTXSecureDirectStatMTUUnderlayInnerLE1400Fallbacks        = 59
	kernelUDPTXDirectStatRouteMisses                                  = 60
	kernelUDPTXDirectStatFlowMisses                                   = 61
	kernelUDPTXDirectStatSecureFlowFallbacks                          = 62
	kernelUDPTXDirectStatNonIPv4Fallbacks                             = 63
	kernelUDPTXDirectStatFragmentFallbacks                            = 64
	kernelUDPTXDirectStatLenShortFallbacks                            = 65
	kernelUDPTXDirectStatLenGSOFallbacks                              = 66
	kernelUDPTXDirectStatLenMismatches                                = 67
	kernelUDPTXDirectStatMTUFallbacks                                 = 68
	kernelUDPTXDirectStatRouteFlowZeroFallbacks                       = 69
	kernelUDPTXDirectStatHeaderShortFallbacks                         = 70
	captureStatPullErrors                                             = 71
	captureStatLinearShortErrors                                      = 72
	captureStatEtherTypeErrors                                        = 73
	captureStatHeaderShortErrors                                      = 74
	captureStatRouteMissErrors                                        = 75
	captureStatReady                                                  = 76
	captureStatScratchMisses                                          = 77
	captureStatLoadBytesErrors                                        = 78
	captureStatPerfErrors                                             = 79
	captureStatPerfErrENOENT                                          = 80
	captureStatPerfErrEFAULT                                          = 81
	captureStatPerfErrEINVAL                                          = 82
	captureStatPerfErrE2BIG                                           = 83
	captureStatPerfErrENOSPC                                          = 84
	captureStatPerfErrEPERM                                           = 85
	captureStatPerfErrOther                                           = 86
	captureStatPerfLastErrno                                          = 175
	kernelUDPRXSecureDirectStatAttempts                               = 87
	kernelUDPRXSecureDirectStatCandidates                             = 88
	kernelUDPRXSecureDirectStatSuccess                                = 89
	kernelUDPRXSecureDirectStatFallbacks                              = 90
	kernelUDPRXSecureDirectStatNoContext                              = 91
	kernelUDPRXSecureDirectStatHeaderErrors                           = 92
	kernelUDPRXSecureDirectStatDecryptErrors                          = 93
	kernelUDPRXSecureDirectStatReplayDrops                            = 94
	kernelUDPRXSecureDirectStatDrops                                  = 95
	kernelUDPRXSecureDirectStatNeighHits                              = 96
	kernelUDPRXSecureDirectStatNeighMisses                            = 97
	kernelUDPRXSecureDirectStatAdjustErrors                           = 98
	kernelUDPRXSecureDirectStatStoreErrors                            = 99
	kernelUDPRXSecureDirectStatBroadcasts                             = 100
	kernelUDPRXSecureDirectStatPeerRedirects                          = 101
	kernelUDPRXSecureDirectStatRedirects                              = 102
	kernelUDPTXDirectStatMTULinearFallbacks                           = 103
	kernelUDPTXDirectStatMTUGSOFallbacks                              = 104
	kernelUDPTXDirectStatMTUGSOSizeZeroFallbacks                      = 105
	kernelUDPTXDirectStatMTUGSOBypasses                               = 106
	kernelUDPRXDirectStatFrameHeaderErrors                            = 107
	kernelUDPRXDirectStatInnerHeaderErrors                            = 108
	kernelUDPRXDirectStatInnerLenErrors                               = 109
	kernelUDPRXDirectStatOuterLenErrors                               = 110
	kernelUDPRXDirectStatAdjustDrops                                  = 111
	kernelUDPRXDirectStatStoreDrops                                   = 112
	kernelUDPTXDirectStatDirectOnlyDrops                              = 113
	tcTTLExceededICMPGeneratedStat                                    = 114
	tcTTLExceededICMPErrorsStat                                       = 115
	tcTTLExceededNoReplyDropsStat                                     = 116
	tcTTLExceededFallbacksStat                                        = 117
	kernelUDPRXSecureDirectStatDebugL2IPv4                            = 118
	kernelUDPRXSecureDirectStatDebugL3IPv4                            = 119
	kernelUDPRXSecureDirectStatDebugUDP                               = 120
	kernelUDPRXSecureDirectStatDebugTIXUMagic                         = 121
	kernelUDPRXSecureDirectStatDebugTIXUHeader                        = 122
	kernelUDPRXSecureDirectStatDebugTIXUFlags                         = 123
	kernelUDPRXSecureDirectStatDebugTIXULen                           = 124
	kernelUDPRXSecureDirectStatDebugPort                              = 125
	kernelUDPRXSecureDirectStatDebugSecureHeader                      = 126
	kernelUDPRXSecureDirectStatDebugL3TIXUMagic                       = 127
	kernelUDPRXSecureDirectStatErrPayloadLen                          = 128
	kernelUDPRXSecureDirectStatErrCipherLen                           = 129
	kernelUDPRXSecureDirectStatErrSecureMagic                         = 130
	kernelUDPRXSecureDirectStatErrSecureEpoch                         = 131
	kernelUDPRXSecureDirectStatErrContextEpoch                        = 132
	kernelUDPRXSecureDirectStatErrOpenEINVAL                          = 133
	kernelUDPRXSecureDirectStatErrOpenEBADMSG                         = 134
	kernelUDPRXSecureDirectStatErrInnerIPv4                           = 135
	kernelUDPTXDirectStatInnerTCPChecksumFixes                        = 136
	kernelUDPTXDirectStatInnerTCPChecksumStoreErrors                  = 137
	kernelUDPTXDirectStatInnerTCPChecksumNotTCP                       = 138
	kernelUDPTXDirectStatInnerTCPChecksumKfuncFixes                   = 139
	kernelUDPTXDirectStatInnerTCPChecksumKfuncFallbacks               = 140
	kernelUDPTXDirectStatAdjustDrops                                  = 141
	kernelUDPTXDirectStatPostAdjustHeaderDrops                        = 142
	kernelUDPTXDirectStatSKBClearTXOffloadDrops                       = 143
	kernelUDPTXDirectStatInnerTCPChecksumGSOSkips                     = 144
	kernelUDPRXDirectStatLocalDeliveries                              = 145
	kernelUDPTXDirectStatInnerUDPChecksumFixes                        = 146
	kernelUDPTXDirectStatInnerUDPChecksumStoreErrors                  = 147
	kernelUDPTXDirectStatInnerUDPChecksumInvalid                      = 148
	kernelUDPTXDirectStatGSOInputs                                    = 149
	kernelUDPTXDirectStatGSOActiveAccepts                             = 150
	kernelUDPTXDirectStatLinearAccepts                                = 151
	kernelUDPTXDirectStatGSOSuccesses                                 = 152
	kernelUDPTXDirectStatOuterTCPChecksumKfuncFixes                   = 153
	kernelUDPTXDirectStatOuterTCPChecksumKfuncDrops                   = 154
	kernelUDPTXDirectStatRouteTCPGSOSuccesses                         = 155
	kernelUDPTXDirectStatRouteTCPGSOFallbacks                         = 156
	kernelUDPTXDirectStatRouteTCPGSODrops                             = 157
	kernelUDPTXDirectStatRouteTCPXmitSuccesses                        = 158
	kernelUDPTXDirectStatRouteTCPXmitFallbacks                        = 159
	kernelUDPTXDirectStatRouteTCPXmitDrops                            = 160
	kernelUDPTXDirectStatPushFlowTCPHeaderKfuncSuccesses              = 161
	kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEINVAL                 = 163
	kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEPROTONOSUPPORT        = 164
	kernelUDPTXDirectStatPushFlowTCPHeaderKfuncENOMEM                 = 165
	kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEMSGSIZE               = 166
	kernelUDPTXDirectStatPushFlowTCPHeaderKfuncOtherDrops             = 167
	kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEFAULT                 = 168
	kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEIO                    = 169
	kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEBADMSG                = 170
	kernelUDPTXDirectStatPushFlowTCPHeaderKfuncENODEV                 = 171
	kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEPERM                  = 172
	kernelUDPTXDirectStatPushFlowTCPHeaderKfuncENOSPC                 = 173
	kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEAGAIN                 = 174
	kernelUDPTXSecureDirectStatFlowIndexMisses                        = 176
	kernelUDPTXSecureDirectStatDirectSlotMisses                       = 177
	kernelUDPTXSecureDirectStatDirectSlotDisabled                     = 178
	kernelUDPTXSecureDirectStatInnerTCPChecksumKfuncSuccesses         = 188
	kernelUDPTXSecureDirectStatInnerTCPChecksumKfuncFallbacks         = 189
	trustIXSKBClearTXOffloadCSUM                                      = 1
	trustIXSKBClearTXOffloadGSO                                       = 2
	trustIXSKBClearTXOffloadEncap                                     = 4
	trustIXKUDPTXUDPHeaderPartialCSUM                                 = 1 << 8
	trustIXTIXTTXFinalizeTCPPartialCSUM                               = 1 << 8
	trustIXTIXTTXFinalizeTCPTrustInnerCSUM                            = 1 << 9
	trustIXTIXTTXFinalizeTCPTrustPartialInnerCSUM                     = 1 << 10
	trustIXTIXTTXFinalizeTCPTrustValidatedLen                         = 1 << 11
	trustIXKUDPRXDecapL2TrustInnerL4CSUM                              = 1
	trustIXKUDPRXParseExperimentalTCPOnly                             = 1
	trustIXKUDPRXParseKernelUDPOnly                                   = 2
	trustIXKUDPRXParseDecapL2LocalDelivered                           = 1
	trustIXKUDPRXParseDecapL2Stolen                                   = 2
	trustIXSKBCBRXNextHopOffset                                       = 0
	kernelUDPRXDirectKfuncParseArgsStaticPortOffset                   = kernelUDPRXDirectKfuncParseArgsOffset
	kernelUDPRXDirectKfuncParseArgsFlagsOffset                        = kernelUDPRXDirectKfuncParseArgsOffset + 4
	kernelUDPRXDirectKfuncParseArgsL2HeadOffset                       = kernelUDPRXDirectKfuncParseArgsOffset + 8
	kernelUDPRXDirectKfuncParseArgsL2Tail0Offset                      = kernelUDPRXDirectKfuncParseArgsOffset + 16
	kernelUDPRXDirectKfuncParseArgsL2Tail1Offset                      = kernelUDPRXDirectKfuncParseArgsOffset + 20
	kernelUDPRXDirectKfuncParseArgsDecapFlagsOffset                   = kernelUDPRXDirectKfuncParseArgsOffset + 24
	kernelUDPRXDirectKfuncParseArgsLocalIPv4Offset                    = kernelUDPRXDirectKfuncParseArgsOffset + 28
	kernelUDPRXDirectKfuncParseArgsLocalIPv4MaskOffset                = kernelUDPRXDirectKfuncParseArgsOffset + 32
	kernelUDPRXDirectKfuncParseArgsLocalIfindexOffset                 = kernelUDPRXDirectKfuncParseArgsOffset + 36
	kernelUDPRXDirectKfuncParseArgsEgressIfindexOffset                = kernelUDPRXDirectKfuncParseArgsOffset + 40
	kernelUDPRXDirectPortKeyOffset                                    = -16
	kernelUDPRXDirectNeighKeyOffset                                   = -24
	kernelUDPRXDirectIfindexOffset                                    = -28
	kernelUDPRXDirectHeaderOffset                                     = -48
	kernelUDPRXDirectDecapDeltaOffset                                 = -52
	kernelUDPRXDirectInnerLenOffset                                   = -56
	kernelUDPRXDirectSegmentLenOffset                                 = -60
	kernelUDPRXDirectKfuncParseArgsOffset                             = -120
	kernelUDPRXDirectKfuncL2HeadOffset                                = -72
	kernelUDPRXDirectKfuncL2Tail0Offset                               = -76
	kernelUDPRXDirectKfuncL2Tail1Offset                               = -80
	kernelUDPRXDirectKfuncDevArgsOffset                               = -112
	packetPolicyMSSClampHostOffset                                    = -68
	packetPolicyMSSClampOldOffset                                     = -72
	packetPolicyMSSClampNewOffset                                     = -74
	rejectEthernetOffset                                              = -192
	rejectIPOffset                                                    = -224
	rejectTCPOffset                                                   = -256
	rejectPseudoOffset                                                = -288
	rejectICMPOffset                                                  = -384
	rejectICMPQuoteOffset                                             = rejectICMPOffset + rejectICMPHeaderLen
	experimentalTCPFlowTTL                                            = 5 * time.Minute
	kernelTransportDNSCacheTTLDefault                                 = 60 * time.Second
	kernelTransportDNSCacheTTLMin                                     = time.Second
	kernelCryptoOpenRetryAttempts                                     = 20
	kernelCryptoOpenRetryDelay                                        = 10 * time.Millisecond
	tunnelCapabilityCacheTTL                                          = 30 * time.Second
)

var tcProgramBTFMetadataFunc = &btf.Func{
	Name: "trustix_tc_dynamic",
	Type: &btf.FuncProto{
		Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed},
		Params: []btf.FuncParam{{
			Name: "skb",
			Type: &btf.Pointer{Target: &btf.Struct{Name: "__sk_buff"}},
		}},
	},
	Linkage: btf.GlobalFunc,
}

var captureSampleLimit = configuredCaptureSampleLimit()
var captureNormalizeChecksums = configuredCaptureNormalizeChecksums()
var captureHistoryEnabled = configuredCaptureHistoryEnabled()
var captureReaderBatchSize = configuredCaptureReaderBatchSize()
var captureReaderDrainTimeout = configuredCaptureReaderDrainTimeout()
var kernelTransportDNSCacheTTL = configuredKernelTransportDNSCacheTTL()

func withTCProgramBTFMetadata(instructions asm.Instructions) asm.Instructions {
	if len(instructions) == 0 {
		return instructions
	}
	out := make(asm.Instructions, len(instructions))
	copy(out, instructions)
	out[0] = btf.WithFuncMetadata(out[0], tcProgramBTFMetadataFunc).
		WithSource(asm.Comment("trustix dynamic tc program entry"))
	return out
}

func configuredCaptureSampleLimit() int {
	const (
		defaultLimit = captureScratchMaxSize
		minLimit     = 1500
	)
	value := strings.TrimSpace(os.Getenv("TRUSTIX_CAPTURE_SAMPLE_LIMIT"))
	if value == "" {
		return defaultLimit
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minLimit {
		return defaultLimit
	}
	if parsed > captureScratchMaxSize {
		return captureScratchMaxSize
	}
	return parsed
}

func configuredKernelTransportDNSCacheTTL() time.Duration {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_TRANSPORT_DNS_CACHE_TTL"))
	if value == "" {
		return kernelTransportDNSCacheTTLDefault
	}
	ttl, err := time.ParseDuration(value)
	if err != nil || ttl < 0 {
		return kernelTransportDNSCacheTTLDefault
	}
	if ttl > 0 && ttl < kernelTransportDNSCacheTTLMin {
		return kernelTransportDNSCacheTTLMin
	}
	return ttl
}

func configuredCaptureNormalizeChecksums() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_CAPTURE_NORMALIZE_CHECKSUMS"))) {
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}

func configuredCaptureHistoryEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_CAPTURE_HISTORY"))) {
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}

func configuredCaptureReaderBatchSize() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_CAPTURE_READER_BATCH"))
	if value == "" {
		return captureReaderDefaultBatchSize
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return captureReaderDefaultBatchSize
	}
	if parsed > 4096 {
		return 4096
	}
	return parsed
}

func experimentalTCPRawFallbackRecvBatchSize() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_EXPERIMENTAL_TCP_RAW_FALLBACK_RECV_BATCH"))
	if value == "" {
		return captureReaderDefaultBatchSize
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return captureReaderDefaultBatchSize
	}
	if parsed > 4096 {
		return 4096
	}
	return parsed
}

func kernelUDPRawFallbackRecvBatchSize() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_RAW_FALLBACK_RECV_BATCH"))
	if value == "" {
		value = strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_RAW_UDP_FALLBACK_RECV_BATCH"))
	}
	if value == "" {
		return captureReaderDefaultBatchSize
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return captureReaderDefaultBatchSize
	}
	if parsed > 4096 {
		return 4096
	}
	return parsed
}

func configuredCaptureReaderDrainTimeout() time.Duration {
	value := strings.TrimSpace(strings.ToLower(os.Getenv("TRUSTIX_CAPTURE_READER_DRAIN_TIMEOUT")))
	switch value {
	case "":
		return captureReaderDefaultDrainTimeout
	case "0", "off", "false", "no", "disabled":
		return 0
	}
	delay, err := time.ParseDuration(value)
	if err != nil || delay < 0 {
		return captureReaderDefaultDrainTimeout
	}
	if delay > 5*time.Millisecond {
		return 5 * time.Millisecond
	}
	return delay
}

func rawFallbackUnderlayPacketTXEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_RAW_FALLBACK_UNDERLAY_PACKET_TX"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func kernelUDPUDPFallbackEnabled() bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv("TRUSTIX_KERNEL_UDP_SOCKET_FALLBACK")))
	if value == "" {
		value = strings.TrimSpace(strings.ToLower(os.Getenv("TRUSTIX_KERNEL_UDP_UDP_FALLBACK")))
	}
	switch value {
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}

func kernelUDPAFXDPIdleFallbackEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_AF_XDP_IDLE_FALLBACK"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return false
	}
}

func kernelUDPAFXDPIdleFallbackAfter() time.Duration {
	value := strings.TrimSpace(strings.ToLower(os.Getenv("TRUSTIX_KERNEL_UDP_AF_XDP_IDLE_FALLBACK_AFTER")))
	switch value {
	case "":
		return 2 * time.Second
	case "off", "false", "no", "disabled":
		return -1
	}
	delay, err := time.ParseDuration(value)
	if err != nil || delay < 0 {
		return 2 * time.Second
	}
	if delay > time.Minute {
		return time.Minute
	}
	return delay
}

func kernelUDPAFXDPIdleFallbackMaxFrames() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_AF_XDP_IDLE_FALLBACK_MAX_FRAMES"))
	if value == "" {
		return 16
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return 16
	}
	if parsed == 0 {
		return 0
	}
	if parsed > 4096 {
		return 4096
	}
	return parsed
}

func kernelUDPAFXDPIdleFallbackUnderlayPacketEnabled() bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv("TRUSTIX_KERNEL_UDP_AF_XDP_IDLE_FALLBACK_PATH")))
	if value == "" {
		value = strings.TrimSpace(strings.ToLower(os.Getenv("TRUSTIX_KERNEL_UDP_AF_XDP_IDLE_FALLBACK_UNDERLAY_PACKET")))
	}
	switch value {
	case "", "underlay", "underlay_packet", "packet", "af_packet", "raw", "1", "true", "yes", "on", "enabled":
		return true
	case "udp", "udp_socket", "socket", "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}

func kernelUDPUDPFallbackSocketBufferSize() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_SOCKET_BUFFER"))
	if value == "" {
		return 8 * 1024 * 1024
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 8 * 1024 * 1024
	}
	if parsed > 64*1024*1024 {
		return 64 * 1024 * 1024
	}
	return parsed
}

func kernelUDPUDPFallbackGSOEnabled() bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv("TRUSTIX_KERNEL_UDP_SOCKET_GSO")))
	if value == "" {
		value = strings.TrimSpace(strings.ToLower(os.Getenv("TRUSTIX_KERNEL_UDP_UDP_GSO")))
	}
	switch value {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func kernelUDPUDPFallbackGSOScatterEnabled() bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv("TRUSTIX_KERNEL_UDP_SOCKET_GSO_SCATTER")))
	if value == "" {
		value = strings.TrimSpace(strings.ToLower(os.Getenv("TRUSTIX_KERNEL_UDP_UDP_GSO_SCATTER")))
	}
	switch value {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}

func kernelUDPUDPFallbackGSORunBatchEnabled() bool {
	return envTruthy("TRUSTIX_KERNEL_UDP_SOCKET_GSO_RUN_BATCH", "TRUSTIX_KERNEL_UDP_UDP_GSO_RUN_BATCH")
}

func kernelUDPUDPFallbackGSOMaxSegments() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_SOCKET_GSO_SEGMENTS"))
	if value == "" {
		return 16
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 2 {
		return 16
	}
	if parsed > 64 {
		return 64
	}
	return parsed
}

func configuredCaptureOutputMode() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_CAPTURE_OUTPUT"))) {
	case "", "auto", captureOutputModeRingbuf:
		return captureOutputModeRingbuf
	case captureOutputModePerf, "perf_event", "perf-event":
		return captureOutputModePerf
	default:
		return captureOutputModeRingbuf
	}
}

var tunnelCapabilityProbeCache sync.Map

type tunnelCapabilityProbeResult struct {
	ready     bool
	reason    string
	expiresAt time.Time
}

type persistedDataplaneState struct {
	Version              int                                      `json:"version,omitempty"`
	Spec                 dataplane.AttachSpec                     `json:"spec"`
	Snapshot             dataplane.Snapshot                       `json:"snapshot"`
	Attached             bool                                     `json:"attached"`
	LinkAdded            bool                                     `json:"link_added,omitempty"`
	AddressAdded         bool                                     `json:"address_added,omitempty"`
	QdiscPrepared        bool                                     `json:"qdisc_prepared,omitempty"`
	LANs                 []persistedLANAttachState                `json:"lans,omitempty"`
	LocalVIPs            []dataplane.LocalVIP                     `json:"local_vips,omitempty"`
	RestoreSysctls       map[string]string                        `json:"restore_sysctls,omitempty"`
	LANOffloadProtection *persistedLinkOffloadState               `json:"lan_offload_protection,omitempty"`
	ManagedCaptureRoutes []persistedManagedCaptureRoute           `json:"managed_capture_routes,omitempty"`
	DeviceAccessProxyARP []persistedDeviceAccessProxyARP          `json:"device_access_proxy_arp,omitempty"`
	NativeTunnelRoutes   []persistedNativeTunnelRoute             `json:"native_tunnel_routes,omitempty"`
	ExperimentalTCPFlows map[uint64]dataplane.ExperimentalTCPFlow `json:"experimental_tcp_flows,omitempty"`
	KernelUDPFlows       map[uint64]dataplane.KernelUDPFlow       `json:"kernel_udp_flows,omitempty"`
	ExperimentalTCPXDP   *persistedExperimentalTCPXDPState        `json:"experimental_tcp_xdp,omitempty"`
}

type persistedLANAttachState struct {
	ID                   string                     `json:"id,omitempty"`
	Iface                string                     `json:"iface"`
	LinkAdded            bool                       `json:"link_added,omitempty"`
	AddressAdded         bool                       `json:"address_added,omitempty"`
	QdiscPrepared        bool                       `json:"qdisc_prepared,omitempty"`
	LANOffloadProtection *persistedLinkOffloadState `json:"lan_offload_protection,omitempty"`
}

type persistedNativeTunnelRoute struct {
	Key       string `json:"key"`
	Protocol  string `json:"protocol"`
	Tunnel    string `json:"tunnel"`
	Prefix    string `json:"prefix"`
	Gateway   string `json:"gateway,omitempty"`
	MTU       int    `json:"mtu,omitempty"`
	AdvMSS    int    `json:"adv_mss,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	Routeable bool   `json:"routeable,omitempty"`
}

type persistedManagedCaptureRoute struct {
	Key            string `json:"key"`
	Prefix         string `json:"prefix"`
	Iface          string `json:"iface"`
	Ifindex        int    `json:"ifindex,omitempty"`
	Gateway        string `json:"gateway,omitempty"`
	DestinationMAC string `json:"destination_mac,omitempty"`
	Routeable      bool   `json:"routeable,omitempty"`
}

type persistedDeviceAccessProxyARP struct {
	Key     string `json:"key"`
	Iface   string `json:"iface"`
	Ifindex int    `json:"ifindex,omitempty"`
	Address string `json:"address"`
}

type persistedExperimentalTCPXDPState struct {
	Attached    bool   `json:"attached"`
	Underlay    string `json:"underlay_iface,omitempty"`
	AttachFlags int    `json:"attach_flags,omitempty"`
	AttachMode  string `json:"attach_mode,omitempty"`
	BindMode    string `json:"bind_mode,omitempty"`
}

type lanTCFilterState struct {
	ingress                       *netlink.BpfFilter
	egress                        *netlink.BpfFilter
	kernelUDPTXSecureDirect       *netlink.BpfFilter
	kernelUDPTXSecureDirectEgress *netlink.BpfFilter
}

func capturePerfBufferPages() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_CAPTURE_PERF_BUFFER_PAGES"))
	if value == "" {
		return capturePerfBufferDefaultPages
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return capturePerfBufferDefaultPages
	}
	if parsed > capturePerfBufferMaxPages {
		return capturePerfBufferMaxPages
	}
	return parsed
}

func captureRingbufSize() uint32 {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_CAPTURE_RINGBUF_SIZE"))
	if value == "" {
		return captureRingbufDefaultSize
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return captureRingbufDefaultSize
	}
	if parsed > captureRingbufMaxSize {
		parsed = captureRingbufMaxSize
	}
	size := 1
	for size < parsed {
		size <<= 1
	}
	if size > captureRingbufMaxSize {
		size = captureRingbufMaxSize
	}
	return uint32(size)
}

func NewManager() *Manager {
	return &Manager{
		restoreSysctls:               make(map[string]string),
		linkAddedLANs:                make(map[string]bool),
		addressAddedLANs:             make(map[string]bool),
		localVIPs:                    make(map[netip.Addr]struct{}),
		qdiscPreparedLANs:            make(map[string]bool),
		lanOffloadProtections:        make(map[string]*persistedLinkOffloadState),
		managedCaptureRoutes:         make(map[string]managedCaptureRouteState),
		deviceAccessProxyARP:         make(map[string]deviceAccessProxyARPState),
		lanTCFilters:                 make(map[string]lanTCFilterState),
		captureSubs:                  make(map[chan []dataplane.CaptureEvent]struct{}),
		dropReasons:                  make(map[observability.DropReason]uint64),
		natBindingKeys:               make(map[natBindingKey]struct{}),
		lanInjectors:                 make(map[string]*lanPacketInjector),
		expTCPFlows:                  make(map[uint64]dataplane.ExperimentalTCPFlow),
		expTCPTXTemplates:            make(map[uint64]experimentalTCPTXTemplate),
		expTCPOuterTXSequences:       make(map[uint64]uint32),
		expTCPOuterTXAcknowledgments: make(map[uint64]uint32),
		expTCPTelemetry:              make(map[uint64]*dataplane.TransportPathTelemetry),
		expTCPAllowed:                make(map[uint16]struct{}),
		expTCPSubs:                   make(map[chan []dataplane.ExperimentalTCPFrame]struct{}),
		expTCPFlowSubs:               make(map[uint64]map[chan []dataplane.ExperimentalTCPFrame]struct{}),
		kernelTransportAllowed:       make(map[uint16]struct{}),
		expTCPRawFD:                  -1,
		kernelUDPRawFD:               -1,
		kernelUDPUDPFallbackSockets:  make(map[uint16]*kernelUDPUDPFallbackSocket),
		rawIPv4TXFD:                  -1,
		kernelUDPFlows:               make(map[uint64]dataplane.KernelUDPFlow),
		kernelUDPTXDirectSequences:   make(map[uint64]uint64),
		kernelUDPTXTemplates:         make(map[uint64]kernelUDPTXTemplate),
		kernelUDPTelemetry:           make(map[uint64]*dataplane.TransportPathTelemetry),
		kernelUDPAllowed:             make(map[uint16]struct{}),
		kernelUDPSubs:                make(map[chan []dataplane.KernelUDPFrame]struct{}),
		kernelUDPFlowSubs:            make(map[uint64]map[chan []dataplane.KernelUDPFrame]struct{}),
		expTCPCryptoFragments:        make(map[experimentalTCPCryptoFragmentKey]*experimentalTCPCryptoFragmentAssembly),
		kernelUDPCryptoFragments:     make(map[kernelUDPCryptoFragmentKey]*kernelUDPCryptoFragmentAssembly),
		nativeTunnelRoutes:           make(map[string]nativeTunnelRouteState),
	}
}

func (manager *Manager) Load(ctx context.Context) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	manager.capabilities = []string{"netlink", "tc-clsact", "ebpf-sched-cls", "ebpf-stats-map", "ebpf-route-lpm", "ebpf-packet-policy", "ebpf-capture", "experimental-tcp-af-xdp"}
	if configuredCaptureOutputMode() == captureOutputModePerf {
		manager.capabilities = append(manager.capabilities, "ebpf-capture-perf")
	} else {
		manager.capabilities = append(manager.capabilities, "ebpf-capture-ringbuf")
	}
	manager.refreshKernelCryptoProbeLocked()
	if err := rlimit.RemoveMemlock(); err != nil {
		manager.warnings = append(manager.warnings, "could not raise memlock rlimit: "+err.Error())
	}
	manager.initKernelCryptoProviderMapLocked()
	if _, err := os.Stat("/sys/fs/bpf"); err == nil {
		manager.capabilities = append(manager.capabilities, "bpffs")
	} else {
		manager.warnings = append(manager.warnings, "/sys/fs/bpf is not available; pinned BPF maps will need an alternate path")
	}
	return nil
}

func normalizeAttachSpec(spec dataplane.AttachSpec) dataplane.AttachSpec {
	if spec.LANAttachMode == "" {
		spec.LANAttachMode = "managed"
	}
	lans := effectiveLANAttachSpecs(spec)
	if len(lans) == 0 {
		return spec
	}
	primary := lans[0]
	spec.LANIface = primary.Iface
	spec.UnderlayIface = primary.UnderlayIface
	spec.Gateway = primary.Gateway
	spec.LANAttachMode = primary.LANAttachMode
	spec.ManageQdisc = primary.ManageQdisc
	spec.ManageAddress = primary.ManageAddress
	spec.ManageForwarding = primary.ManageForwarding
	spec.ManageRPFilter = primary.ManageRPFilter
	spec.ManagedMTU = primary.ManagedMTU
	spec.LANs = lans
	return spec
}

func effectiveLANAttachSpecs(spec dataplane.AttachSpec) []dataplane.LANAttachSpec {
	if len(spec.LANs) == 0 {
		if !legacyLANAttachConfigured(spec) {
			return nil
		}
		return []dataplane.LANAttachSpec{normalizeLANAttachSpec(dataplane.LANAttachSpec{
			Iface:            spec.LANIface,
			UnderlayIface:    spec.UnderlayIface,
			Gateway:          spec.Gateway,
			LANAttachMode:    spec.LANAttachMode,
			ManageQdisc:      spec.ManageQdisc,
			ManageAddress:    spec.ManageAddress,
			ManageForwarding: spec.ManageForwarding,
			ManageRPFilter:   spec.ManageRPFilter,
			ManagedMTU:       spec.ManagedMTU,
		}, spec, true)}
	}
	out := make([]dataplane.LANAttachSpec, 0, len(spec.LANs))
	for i, lan := range spec.LANs {
		out = append(out, normalizeLANAttachSpec(lan, spec, i == 0))
	}
	return out
}

func attachSpecHasLANIface(spec dataplane.AttachSpec, iface string) bool {
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return false
	}
	for _, lan := range effectiveLANAttachSpecs(spec) {
		if strings.TrimSpace(lan.Iface) == iface {
			return true
		}
	}
	return false
}

func legacyLANAttachConfigured(spec dataplane.AttachSpec) bool {
	return strings.TrimSpace(spec.LANIface) != "" ||
		strings.TrimSpace(spec.UnderlayIface) != "" ||
		strings.TrimSpace(spec.Gateway) != "" ||
		spec.ManageQdisc ||
		spec.ManageAddress ||
		spec.ManageForwarding ||
		spec.ManageRPFilter ||
		spec.ManagedMTU > 0
}

func normalizeLANAttachSpec(lan dataplane.LANAttachSpec, fallback dataplane.AttachSpec, primary bool) dataplane.LANAttachSpec {
	if primary {
		if lan.Iface == "" {
			lan.Iface = fallback.LANIface
		}
		if lan.Gateway == "" {
			lan.Gateway = fallback.Gateway
		}
		if lan.LANAttachMode == "" {
			lan.LANAttachMode = fallback.LANAttachMode
		}
		if lan.ManagedMTU == 0 {
			lan.ManagedMTU = fallback.ManagedMTU
		}
	}
	if lan.UnderlayIface == "" {
		lan.UnderlayIface = fallback.UnderlayIface
	}
	if lan.LANAttachMode == "" {
		lan.LANAttachMode = "managed"
	}
	if lan.Type == "" {
		lan.Type = "local"
	}
	return lan
}

func lanAddressStateKey(lan dataplane.LANAttachSpec) string {
	if id := strings.TrimSpace(lan.ID); id != "" {
		return "id:" + id
	}
	return strings.TrimSpace(lan.Iface) + "|" + strings.TrimSpace(lan.Gateway)
}

func lanAttachSpecsManageForwarding(lans []dataplane.LANAttachSpec) bool {
	for _, lan := range lans {
		if lan.ManageForwarding {
			return true
		}
	}
	return false
}

func specForLANAttach(spec dataplane.AttachSpec, lan dataplane.LANAttachSpec) dataplane.AttachSpec {
	out := spec
	out.LANIface = lan.Iface
	out.UnderlayIface = lan.UnderlayIface
	out.Gateway = lan.Gateway
	out.LANAttachMode = lan.LANAttachMode
	out.ManageQdisc = lan.ManageQdisc
	out.ManageAddress = lan.ManageAddress
	out.ManageForwarding = lan.ManageForwarding
	out.ManageRPFilter = lan.ManageRPFilter
	out.ManagedMTU = lan.ManagedMTU
	return out
}

func cloneLinkOffloadStateMap(values map[string]*persistedLinkOffloadState) map[string]*persistedLinkOffloadState {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]*persistedLinkOffloadState, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func linkOffloadStateMapChanged(current, previous map[string]*persistedLinkOffloadState) bool {
	if len(current) != len(previous) {
		return true
	}
	for key, value := range current {
		if previous[key] != value {
			return true
		}
	}
	return false
}

func (manager *Manager) Attach(ctx context.Context, spec dataplane.AttachSpec) (err error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	if spec.PinPath == "" {
		spec.PinPath = "/sys/fs/bpf/trustix"
	}
	spec = normalizeAttachSpec(spec)
	if err := os.MkdirAll(spec.PinPath, 0o755); err != nil {
		return fmt.Errorf("create dataplane pin path %q: %w", spec.PinPath, err)
	}

	lans := effectiveLANAttachSpecs(spec)
	var primaryLink netlink.Link
	createdLANLinks := make(map[string]netlink.Link)
	initialLANOffloadProtections := cloneLinkOffloadStateMap(manager.lanOffloadProtections)
	defer func() {
		if err != nil && linkOffloadStateMapChanged(manager.lanOffloadProtections, initialLANOffloadProtections) {
			restoreErr := manager.restoreLANOffloadProtectionLocked(primaryLink)
			if restoreErr != nil {
				manager.spec = spec
				if persistErr := manager.persistStateLocked(); persistErr != nil {
					err = fmt.Errorf("%w; rollback LAN offload protection: %v; persist rollback state: %v", err, restoreErr, persistErr)
				} else {
					err = fmt.Errorf("%w; rollback LAN offload protection: %v", err, restoreErr)
				}
			}
		}
		if err != nil {
			for key, link := range createdLANLinks {
				if link != nil {
					_ = netlink.LinkDel(link)
				}
				delete(manager.linkAddedLANs, key)
			}
		}
	}()
	if manager.addressAddedLANs == nil {
		manager.addressAddedLANs = make(map[string]bool)
	}
	if manager.linkAddedLANs == nil {
		manager.linkAddedLANs = make(map[string]bool)
	}
	if manager.qdiscPreparedLANs == nil {
		manager.qdiscPreparedLANs = make(map[string]bool)
	}
	for i, lan := range lans {
		if lan.Iface == "" {
			continue
		}
		lanKey := lanAddressStateKey(lan)
		link, err := netlink.LinkByName(lan.Iface)
		if err != nil {
			if isNotFound(err) && lan.LANAttachMode == "managed" {
				var created bool
				link, created, err = createManagedLANBridge(lan.Iface)
				if err != nil {
					return fmt.Errorf("create managed LAN bridge %q: %w", lan.Iface, err)
				}
				if created {
					manager.linkAddedLANs[lanKey] = true
					createdLANLinks[lanKey] = link
					manager.warnings = append(manager.warnings, fmt.Sprintf("created managed LAN bridge %q", lan.Iface))
				}
			} else {
				return fmt.Errorf("inspect LAN iface %q: %w", lan.Iface, err)
			}
		}
		if lan.LANAttachMode == "managed" {
			if err := ensureManagedLANTxQueueLen(link); err != nil {
				return fmt.Errorf("configure managed LAN tx queue length on %q: %w", lan.Iface, err)
			}
		}
		if i == 0 {
			primaryLink = link
		}
		if lan.LANAttachMode == "existing" {
			if strings.TrimSpace(lan.Gateway) == "" {
				return fmt.Errorf("existing LAN iface %q requires a configured gateway prefix", lan.Iface)
			}
			exists, err := linkHasAddress(link, lan.Gateway)
			if err != nil {
				return err
			}
			if !exists {
				return fmt.Errorf("existing LAN iface %q does not have gateway address %q", lan.Iface, lan.Gateway)
			}
			lan.ManageAddress = false
			spec.LANs[i].ManageAddress = false
			if i == 0 {
				spec.ManageAddress = false
			}
		}
		if lan.ManageAddress && lan.Gateway != "" {
			existed, err := linkHasAddress(link, lan.Gateway)
			if err != nil {
				return err
			}
			addr, err := parseAddress(lan.Gateway)
			if err != nil {
				return err
			}
			if err := netlink.AddrReplace(link, addr); err != nil {
				return fmt.Errorf("configure LAN gateway %q on %q: %w", lan.Gateway, lan.Iface, err)
			}
			manager.addressAddedLANs[lanKey] = !existed
			if i == 0 {
				manager.addressAdded = !existed
			}
		}
		if lan.ManagedMTU > 0 && link.Attrs() != nil && link.Attrs().MTU > lan.ManagedMTU {
			if err := netlink.LinkSetMTU(link, lan.ManagedMTU); err != nil {
				return fmt.Errorf("configure LAN MTU %d on %q: %w", lan.ManagedMTU, lan.Iface, err)
			}
			manager.warnings = append(manager.warnings, fmt.Sprintf("set LAN MTU on %q to %d for native tunnel route offload", lan.Iface, lan.ManagedMTU))
		}
		if lan.ManageQdisc {
			lanSpec := specForLANAttach(spec, lan)
			if err := manager.applyLANOffloadProtectionLocked(link, lanSpec); err != nil {
				if lanOffloadProtectionRequired() {
					return err
				}
				manager.warnings = append(manager.warnings, err.Error())
			}
			if err := replaceClsact(link); err != nil {
				return fmt.Errorf("prepare clsact qdisc on %q: %w", lan.Iface, err)
			}
			manager.qdiscPreparedLANs[lanKey] = true
			if i == 0 {
				manager.qdiscPrepared = true
			}
			if err := manager.attachTCPrograms(link, lanSpec); err != nil {
				return err
			}
		}
		if lan.ManageRPFilter {
			path := filepath.Join("/proc/sys/net/ipv4/conf", lan.Iface, "rp_filter")
			if err := manager.writeSysctl(path, "0"); err != nil {
				return err
			}
		}
	}
	if lanAttachSpecsManageForwarding(lans) {
		if err := manager.writeSysctl("/proc/sys/net/ipv4/ip_forward", "1"); err != nil {
			return err
		}
	}
	if err := manager.startNeighborMonitorLocked(spec); err != nil {
		manager.warnings = append(manager.warnings, "neighbor monitor is unavailable: "+err.Error())
	}

	manager.spec = spec
	manager.attached = true
	return manager.persistStateLocked()
}

func (manager *Manager) ApplySnapshot(ctx context.Context, snapshot dataplane.Snapshot) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	manager.snapshot = snapshot
	if manager.reconcileKernelTransportFlowsForSnapshotLocked(snapshot) {
		_ = manager.syncExperimentalTCPPortsLocked()
		_ = manager.syncKernelUDPPortsLocked()
		_ = manager.syncKernelUDPTXDirectLocked()
	}
	if err := manager.ensureKernelTransportFastPathLocked(ctx); err != nil {
		return err
	}
	if err := manager.syncRoutesLocked(snapshot.Routes); err != nil {
		return err
	}
	if err := manager.syncNativeTunnelRoutesLocked(ctx, snapshot); err != nil {
		return err
	}
	if err := manager.syncManagedCaptureRoutesLocked(ctx, snapshot); err != nil {
		return err
	}
	if err := manager.syncDeviceAccessProxyARPLocked(ctx, snapshot); err != nil {
		return err
	}
	if err := manager.syncPacketPolicyLocked(snapshot.PacketPolicy); err != nil {
		return err
	}
	if err := manager.syncNATLocked(snapshot.NAT); err != nil {
		return err
	}
	if err := manager.syncExperimentalTCPPortsLocked(); err != nil {
		return err
	}
	if err := manager.syncKernelUDPPortsLocked(); err != nil {
		return err
	}
	if err := manager.syncKernelUDPTXDirectLocked(); err != nil {
		return err
	}
	if err := manager.refreshKernelUDPRXDirectProgramLocked(); err != nil {
		return err
	}
	if err := manager.ensureKernelUDPRXSecureDirectLocked(); err != nil {
		manager.warnings = append(manager.warnings, "kernel_udp secure TC RX direct disabled: "+err.Error())
	}
	if err := manager.syncKernelUDPRXDirectConfigLocked(); err != nil {
		manager.warnings = append(manager.warnings, "kernel_udp XDP TC RX direct config sync failed: "+err.Error())
	}
	return manager.persistStateLocked()
}

func (manager *Manager) ApplyNATSnapshot(ctx context.Context, snapshot *dataplane.NATSnapshot) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	manager.snapshot.NAT = snapshot
	if err := manager.syncNATLocked(snapshot); err != nil {
		manager.natBindingSyncErrors++
		return err
	}
	if err := manager.syncKernelUDPTXDirectLocked(); err != nil {
		return err
	}
	return manager.persistStateLocked()
}

func (manager *Manager) Stats(ctx context.Context) (dataplane.Stats, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return dataplane.Stats{}, err
	}
	return dataplane.Stats{
		Epoch:         manager.snapshot.Epoch,
		Mode:          "linux",
		Attached:      manager.attached,
		LANIface:      manager.spec.LANIface,
		LANAttachMode: manager.spec.LANAttachMode,
		LANs:          manager.lanStatsLocked(),
		PinPath:       manager.spec.PinPath,
		Capabilities:  append([]string(nil), manager.capabilities...),
		Warnings:      append([]string(nil), manager.warnings...),
		Counters:      manager.readCountersLocked(),
		DropReasons:   manager.dropReasonsLocked(),
	}, nil
}

func (manager *Manager) lanStatsLocked() []dataplane.LANStats {
	lans := effectiveLANAttachSpecs(manager.spec)
	if len(lans) == 0 {
		return nil
	}
	out := make([]dataplane.LANStats, 0, len(lans))
	for i, lan := range lans {
		key := lanAddressStateKey(lan)
		linkAdded := manager.linkAddedLANs[key]
		addressAdded := manager.addressAddedLANs[key]
		qdiscPrepared := manager.qdiscPreparedLANs[key]
		if i == 0 {
			addressAdded = addressAdded || manager.addressAdded
			qdiscPrepared = qdiscPrepared || manager.qdiscPrepared
		}
		out = append(out, dataplane.LANStats{
			ID:               lan.ID,
			Type:             lan.Type,
			Iface:            lan.Iface,
			UnderlayIface:    lan.UnderlayIface,
			Gateway:          lan.Gateway,
			LANAttachMode:    lan.LANAttachMode,
			ManageQdisc:      lan.ManageQdisc,
			ManageAddress:    lan.ManageAddress,
			ManageForwarding: lan.ManageForwarding,
			ManageRPFilter:   lan.ManageRPFilter,
			ManagedMTU:       lan.ManagedMTU,
			LinkAdded:        linkAdded,
			AddressAdded:     addressAdded,
			QdiscPrepared:    qdiscPrepared,
		})
	}
	return out
}

func (manager *Manager) BPFMapSnapshot(ctx context.Context) (dataplane.BPFMapSnapshot, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return dataplane.BPFMapSnapshot{}, err
	}
	return manager.bpfMapSnapshotLocked()
}

func (manager *Manager) bpfMapSnapshotLocked() (dataplane.BPFMapSnapshot, error) {
	snapshot := dataplane.BPFMapSnapshot{}
	if manager.kernelUDPTXRouteMap != nil {
		routes, err := manager.kernelUDPTXRouteSnapshotsLocked()
		if err != nil {
			return dataplane.BPFMapSnapshot{}, err
		}
		snapshot.KernelUDPTXRoutes = routes
	}
	if manager.kernelUDPTXFlowMap != nil {
		flows, err := manager.kernelUDPTXFlowSnapshotsLocked()
		if err != nil {
			return dataplane.BPFMapSnapshot{}, err
		}
		snapshot.KernelUDPTXFlows = flows
	}
	return snapshot, nil
}

func (manager *Manager) kernelUDPTXRouteSnapshotsLocked() ([]dataplane.KernelUDPTXRouteSnapshot, error) {
	var key routeKey
	var value kernelUDPTXRouteValue
	routes := make([]dataplane.KernelUDPTXRouteSnapshot, 0)
	iterator := manager.kernelUDPTXRouteMap.Iterate()
	for iterator.Next(&key, &value) {
		routes = append(routes, kernelUDPTXRouteSnapshotFromValue(key, value))
	}
	if err := iterator.Err(); err != nil {
		return nil, fmt.Errorf("snapshot kernel_udp TC TX routes: %w", err)
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].PrefixLen != routes[j].PrefixLen {
			return routes[i].PrefixLen < routes[j].PrefixLen
		}
		return routes[i].Address < routes[j].Address
	})
	return routes, nil
}

func (manager *Manager) kernelUDPTXFlowSnapshotsLocked() ([]dataplane.KernelUDPTXFlowSnapshot, error) {
	var flowID uint64
	var value kernelUDPTXFlowValue
	flows := make([]dataplane.KernelUDPTXFlowSnapshot, 0)
	iterator := manager.kernelUDPTXFlowMap.Iterate()
	for iterator.Next(&flowID, &value) {
		flows = append(flows, kernelUDPTXFlowSnapshotFromValue(flowID, 0, false, value))
	}
	if err := iterator.Err(); err != nil {
		return nil, fmt.Errorf("snapshot kernel_udp TC TX flows: %w", err)
	}
	sort.Slice(flows, func(i, j int) bool { return flows[i].FlowID < flows[j].FlowID })
	return flows, nil
}

func (manager *Manager) Capture(ctx context.Context, limit int) ([]dataplane.CaptureEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > captureRingLimit {
		limit = captureRingLimit
	}
	if !captureHistoryEnabled {
		return nil, nil
	}
	manager.captureMu.Lock()
	defer manager.captureMu.Unlock()

	total := manager.captureEventCount
	if limit > total {
		limit = total
	}
	events := make([]dataplane.CaptureEvent, limit)
	start := manager.captureEventNext - limit
	if start < 0 {
		start += captureRingLimit
	}
	for i := 0; i < limit; i++ {
		events[i] = manager.captureEvents[(start+i)%captureRingLimit]
		normalizeCaptureEventPayloadForRead(&events[i])
	}
	return events, nil
}

func (manager *Manager) SubscribeCapture(ctx context.Context, buffer int) (dataplane.CaptureSubscription, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	manager.mu.Lock()
	available := manager.captureReader != nil || manager.captureRingReader != nil
	manager.mu.Unlock()
	if !available {
		return nil, dataplane.ErrUnsupported
	}
	if buffer <= 0 {
		buffer = 256
	}
	events := make(chan []dataplane.CaptureEvent, buffer)
	subscription := &captureSubscription{manager: manager, events: events}

	manager.captureMu.Lock()
	manager.captureSubs[events] = struct{}{}
	manager.captureMu.Unlock()
	return subscription, nil
}

func (manager *Manager) InjectPacket(ctx context.Context, packet []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ipPacket, dst, err := ipv4Payload(packet)
	if err != nil {
		manager.recordDrop(observability.DropInvalidPacket)
		return err
	}
	destination := netip.AddrFrom4(dst)
	manager.mu.Lock()
	lanIface := manager.singleLANIfaceLocked()
	if lanIface == "" {
		lanIface = manager.lanIfaceForDestinationLocked(destination)
	}
	manager.mu.Unlock()
	if lanIface == "" {
		manager.recordDrop(observability.DropEndpointDown)
		return fmt.Errorf("LAN iface is not configured")
	}
	if err := manager.sendLANIPv4Packet(lanIface, ipPacket, destination); err != nil {
		if errors.Is(err, errNeighborUnresolved) {
			manager.recordDrop(observability.DropNeighborUnresolved)
		} else if errors.Is(err, errMTUExceeded) {
			manager.recordDrop(observability.DropMTUExceeded)
		} else {
			manager.recordDrop(observability.DropInvalidPacket)
		}
		return err
	}
	return nil
}

func (manager *Manager) InjectPackets(ctx context.Context, packets [][]byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(packets) == 0 {
		return nil
	}
	manager.mu.Lock()
	singleLANIface := manager.singleLANIfaceLocked()
	manager.mu.Unlock()
	if singleLANIface != "" {
		if err := manager.sendLANIPv4Packets(singleLANIface, packets); err != nil {
			if errors.Is(err, errNeighborUnresolved) {
				manager.recordDrop(observability.DropNeighborUnresolved)
			} else if errors.Is(err, errMTUExceeded) {
				manager.recordDrop(observability.DropMTUExceeded)
			} else {
				manager.recordDrop(observability.DropInvalidPacket)
			}
			return err
		}
		return nil
	}
	groups := make(map[string][][]byte)
	order := make([]string, 0, 1)
	for _, packet := range packets {
		ipPacket, dstRaw, err := ipv4Payload(packet)
		if err != nil {
			manager.recordDrop(observability.DropInvalidPacket)
			return err
		}
		destination := netip.AddrFrom4(dstRaw)
		manager.mu.Lock()
		lanIface := manager.lanIfaceForDestinationLocked(destination)
		manager.mu.Unlock()
		if lanIface == "" {
			manager.recordDrop(observability.DropEndpointDown)
			return fmt.Errorf("LAN iface is not configured")
		}
		if _, ok := groups[lanIface]; !ok {
			order = append(order, lanIface)
		}
		groups[lanIface] = append(groups[lanIface], ipPacket)
	}
	for _, lanIface := range order {
		if err := manager.sendLANIPv4Packets(lanIface, groups[lanIface]); err != nil {
			if errors.Is(err, errNeighborUnresolved) {
				manager.recordDrop(observability.DropNeighborUnresolved)
			} else if errors.Is(err, errMTUExceeded) {
				manager.recordDrop(observability.DropMTUExceeded)
			} else {
				manager.recordDrop(observability.DropInvalidPacket)
			}
			return err
		}
	}
	return nil
}

func (manager *Manager) singleLANIfaceLocked() string {
	if len(manager.spec.LANs) == 0 {
		return manager.spec.LANIface
	}
	if len(manager.spec.LANs) == 1 {
		return normalizeLANAttachSpec(manager.spec.LANs[0], manager.spec, true).Iface
	}
	return ""
}

func (manager *Manager) InjectBatchGSOChecksumOffloadMTU() int {
	if manager == nil {
		return 0
	}
	manager.mu.Lock()
	injectors := make([]*lanPacketInjector, 0, len(manager.lanInjectors))
	for _, lan := range effectiveLANAttachSpecs(manager.spec) {
		if lan.Iface == "" {
			continue
		}
		if injector := manager.lanInjectors[lan.Iface]; injector != nil {
			injectors = append(injectors, injector)
		}
	}
	if len(injectors) == 0 {
		if injector := manager.lanInjectors[manager.spec.LANIface]; injector != nil {
			injectors = append(injectors, injector)
		}
	}
	manager.mu.Unlock()
	if len(injectors) == 0 {
		return 0
	}
	minMTU := 0
	for _, injector := range injectors {
		injector.mu.RLock()
		mtu := injector.mtu
		injector.mu.RUnlock()
		if mtu <= 0 {
			continue
		}
		if minMTU == 0 || mtu < minMTU {
			minMTU = mtu
		}
	}
	if minMTU <= 0 {
		return 0
	}
	return minMTU
}

func (manager *Manager) InjectBatchGSOScatterMTU() int {
	if !lanReinjectGSOScatterEnabled() {
		return 0
	}
	return manager.InjectBatchGSOChecksumOffloadMTU()
}

func (manager *Manager) lanIfaceForDestinationLocked(destination netip.Addr) string {
	lans := effectiveLANAttachSpecs(manager.spec)
	if len(lans) == 0 {
		return manager.spec.LANIface
	}
	bestIface := ""
	bestBits := -1
	for _, lan := range lans {
		if lan.Iface == "" {
			continue
		}
		for _, prefix := range lanDestinationPrefixes(lan) {
			if !prefix.IsValid() || !prefix.Addr().Is4() || !prefix.Contains(destination) {
				continue
			}
			if prefix.Bits() > bestBits {
				bestBits = prefix.Bits()
				bestIface = lan.Iface
			}
		}
	}
	if bestIface != "" {
		return bestIface
	}
	for _, lan := range lans {
		if lan.Iface != "" {
			return lan.Iface
		}
	}
	return manager.spec.LANIface
}

func lanDestinationPrefixes(lan dataplane.LANAttachSpec) []netip.Prefix {
	out := make([]netip.Prefix, 0, 1+len(lan.Advertise))
	if strings.TrimSpace(lan.Gateway) != "" {
		if prefix, err := netip.ParsePrefix(strings.TrimSpace(lan.Gateway)); err == nil {
			out = append(out, prefix.Masked())
		}
	}
	for _, raw := range lan.Advertise {
		if prefix, err := raw.Parse(); err == nil {
			out = append(out, prefix.Masked())
		}
	}
	if strings.TrimSpace(lan.DeviceAccessPool) != "" {
		if prefix, err := netip.ParsePrefix(strings.TrimSpace(lan.DeviceAccessPool)); err == nil {
			out = append(out, prefix.Masked())
		}
	}
	return out
}

func (manager *Manager) InjectLANPacket(ctx context.Context, packet []byte, destination netip.Addr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !destination.Is4() {
		manager.recordDrop(observability.DropInvalidPacket)
		return fmt.Errorf("LAN packet destination %s is not IPv4", destination)
	}
	ipPacket, _, err := ipv4Payload(packet)
	if err != nil {
		manager.recordDrop(observability.DropInvalidPacket)
		return err
	}
	manager.mu.Lock()
	lanIface := manager.lanIfaceForDestinationLocked(destination)
	manager.mu.Unlock()
	if lanIface == "" {
		manager.recordDrop(observability.DropEndpointDown)
		return fmt.Errorf("LAN iface is not configured")
	}
	if err := manager.sendLANIPv4Packet(lanIface, ipPacket, destination); err != nil {
		if errors.Is(err, errNeighborUnresolved) {
			manager.recordDrop(observability.DropNeighborUnresolved)
		} else if errors.Is(err, errMTUExceeded) {
			manager.recordDrop(observability.DropMTUExceeded)
		} else {
			manager.recordDrop(observability.DropInvalidPacket)
		}
		return err
	}
	return nil
}

func (manager *Manager) InjectLocalPacket(ctx context.Context, packet []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ipPacket, dst, err := ipv4Payload(packet)
	if err != nil {
		manager.recordDrop(observability.DropInvalidPacket)
		return err
	}
	manager.mu.Lock()
	lanIface := manager.spec.LANIface
	manager.mu.Unlock()
	if lanIface == "" {
		manager.recordDrop(observability.DropEndpointDown)
		return fmt.Errorf("LAN iface is not configured")
	}
	// Local gateway packets need to re-enter the host IP stack. A plain raw
	// sender would emit them as locally generated traffic on the LAN path,
	// which bypasses the destination socket. Binding the raw socket to loopback
	// keeps the packet on the host receive path so local listeners can accept it.
	if err := sendRawIPv4OnDevice(ipPacket, dst, "lo"); err != nil {
		manager.recordDrop(observability.DropInvalidPacket)
		return err
	}
	return nil
}

func (manager *Manager) InjectNATPacket(ctx context.Context, packet []byte, destination netip.Addr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	manager.mu.Lock()
	available := manager.natBindingMap != nil && manager.natBindingEntries > 0
	lanIface := manager.lanIfaceForDestinationLocked(destination)
	manager.mu.Unlock()
	if !available {
		return dataplane.ErrUnsupported
	}
	ipPacket, _, err := ipv4Payload(packet)
	if err != nil {
		manager.recordDrop(observability.DropInvalidPacket)
		return err
	}
	if !destination.Is4() {
		manager.recordDrop(observability.DropInvalidPacket)
		return fmt.Errorf("NAT reinject destination %s is not IPv4", destination)
	}
	if lanIface == "" {
		manager.recordDrop(observability.DropEndpointDown)
		return fmt.Errorf("LAN iface is not configured")
	}
	if err := manager.sendLANIPv4Packet(lanIface, ipPacket, destination); err != nil {
		if errors.Is(err, errNeighborUnresolved) {
			manager.recordDrop(observability.DropNeighborUnresolved)
		} else if errors.Is(err, errMTUExceeded) {
			manager.recordDrop(observability.DropMTUExceeded)
		} else {
			manager.recordDrop(observability.DropInvalidPacket)
		}
		return err
	}
	return nil
}

func (manager *Manager) SyncLocalVIPs(ctx context.Context, vips []dataplane.LocalVIP) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	return manager.syncLocalVIPsLocked(vips)
}

func (manager *Manager) ExperimentalTCPStatus(ctx context.Context) (dataplane.ExperimentalTCPStatus, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return dataplane.ExperimentalTCPStatus{}, err
	}
	if manager.refreshKernelTransportDNSTemplatesLocked(time.Now().UTC()) {
		_ = manager.syncExperimentalTCPPortsLocked()
		_ = manager.syncKernelUDPPortsLocked()
		_ = manager.syncKernelUDPTXDirectLocked()
	}
	if manager.pruneExperimentalTCPFlowsLocked(time.Now().UTC()) {
		_ = manager.syncExperimentalTCPPortsLocked()
		_ = manager.persistStateLocked()
	}
	rawFallback := experimentalTCPRawFallbackEnabled()
	fastPath := manager.experimentalTCPProviderFastPathAvailableLocked()
	provider := "none"
	switch {
	case fastPath:
		provider = manager.experimentalTCPFastPathProviderLocked()
	case rawFallback:
		provider = "raw_socket_fallback"
	}
	kernelCryptoProbe := manager.kernelCryptoProbeSnapshotLocked()
	kernelCryptoReason := manager.experimentalTCPKernelCryptoUnavailableReasonLocked()
	kernelCryptoReady := manager.attached && manager.experimentalTCPKernelCryptoReadyLocked()
	supportedCrypto := []dataplane.CryptoPlacement{dataplane.CryptoPlacementUserspace}
	preferredCrypto := dataplane.CryptoPlacementUserspace
	if kernelCryptoReady {
		kernelCryptoReason = ""
		preferredCrypto = dataplane.CryptoPlacementKernel
		supportedCrypto = append(supportedCrypto, dataplane.CryptoPlacementKernel)
	}
	xdpAttachMode, afXDPBindMode, zeroCopyEnabled, fastPathFallback := "", "", false, ""
	if !manager.experimentalTCPFastPathDisabledLocked() {
		xdpAttachMode, afXDPBindMode, zeroCopyEnabled, fastPathFallback = manager.experimentalTCPFastPathModeLocked()
	} else if reason := manager.experimentalTCPFastPathDisabledReasonLocked(); reason != "" {
		fastPathFallback = reason
	}
	notes := []string{
		"experimental_tcp flow and frame contract is present",
		"AF_XDP is the production underlay fast path; it is enabled only when XDP redirect and AF_XDP rings are attached",
		"raw socket is not a fast path and is disabled unless TRUSTIX_EXPERIMENTAL_TCP_RAW_FALLBACK=1",
		"kernel crypto capability is probed through kernel BTF and /proc/crypto; provider is enabled only after BPF ctx install plus frame seal/open probes are available",
		"experimental_tcp fast-path TX builds TCP-shaped frames directly in AF_XDP UMEM; kernel TX crypto seals in place before the TX descriptor is published",
	}
	if reason := manager.experimentalTCPFastPathDisabledReasonLocked(); reason != "" {
		notes = append(notes, "experimental_tcp fast path disabled: "+reason)
	}
	if xdpAttachMode != "" || afXDPBindMode != "" {
		notes = append(notes, fmt.Sprintf("AF_XDP negotiated xdp_attach_mode=%s af_xdp_bind_mode=%s zerocopy_enabled=%t", xdpAttachMode, afXDPBindMode, zeroCopyEnabled))
	}
	if fastPathFallback != "" {
		notes = append(notes, "AF_XDP mode fallback: "+fastPathFallback)
	}
	return dataplane.ExperimentalTCPStatus{
		Available:          manager.attached && (fastPath || rawFallback),
		Provider:           provider,
		FastPath:           fastPath,
		UserspaceCrypto:    manager.attached && (fastPath || rawFallback),
		KernelCrypto:       kernelCryptoReady,
		KernelCryptoReason: kernelCryptoReason,
		KernelCryptoProbe:  &kernelCryptoProbe,
		CryptoFallback:     manager.experimentalTCPCryptoFallbackStatusLocked(),
		Reinject:           manager.attached && (fastPath || rawFallback),
		RawSocketFallback:  rawFallback,
		XDPAttachMode:      xdpAttachMode,
		AFXDPBindMode:      afXDPBindMode,
		ZeroCopyEnabled:    zeroCopyEnabled,
		FastPathFallback:   fastPathFallback,
		PreferredCrypto:    preferredCrypto,
		SupportedCrypto:    supportedCrypto,
		FastPathQueues:     manager.experimentalTCPFastPathQueuesLocked(),
		ProviderStats:      manager.experimentalTCPProviderStatsLocked(),
		Telemetry:          manager.experimentalTCPTelemetrySnapshotLocked(),
		Flows:              manager.experimentalTCPFlowSnapshotLocked(),
		ActiveFlows:        len(manager.expTCPFlows),
		SubmittedFrames:    manager.expTCPSubmitted,
		ReceivedFrames:     manager.expTCPReceived,
		Notes:              notes,
	}, nil
}

func (manager *Manager) KernelTransportStatus(ctx context.Context) (dataplane.KernelTransportStatus, error) {
	exp, err := manager.ExperimentalTCPStatus(ctx)
	if err != nil {
		return dataplane.KernelTransportStatus{}, err
	}
	udp, err := manager.KernelUDPStatus(ctx)
	if err != nil {
		return dataplane.KernelTransportStatus{}, err
	}
	protocols := []dataplane.KernelTransportProtocol{
		kernelTransportProtocolExperimentalTCP(exp),
		kernelTransportProtocolUDP(udp),
		{
			Protocol:          "quic",
			Available:         false,
			Placement:         "userspace",
			Contract:          "standard_quic_userspace",
			UserspaceFallback: true,
			Reason:            "standard QUIC state machine remains userspace; kernel plane can carry a fixed TrustIX frame contract instead",
		},
		{
			Protocol:          "tcp",
			Available:         false,
			Placement:         "userspace",
			Contract:          "standard_tcp_userspace",
			UserspaceFallback: true,
			Reason:            "standard TCP transport uses kernel sockets and userspace framing; ACKless kernel data plane is experimental_tcp",
		},
		kernelTransportProtocolTunnel("gre", "gre-netdev+inner-udp"),
		kernelTransportProtocolTunnel("ipip", "ipip-netdev+inner-udp"),
		kernelTransportProtocolTunnel("vxlan", "vxlan-netdev+udp"),
	}
	available := false
	provider := exp.Provider
	for _, protocol := range protocols {
		if protocol.Available {
			available = true
			if protocol.Provider != "" && protocol.Provider != "none" {
				provider = protocol.Provider
			}
		}
	}
	stats := make(map[string]uint64, len(exp.ProviderStats)+len(udp.ProviderStats)+8)
	for name, value := range exp.ProviderStats {
		stats[name] = value
	}
	for name, value := range udp.ProviderStats {
		stats["udp_"+name] = value
	}
	manager.mu.Lock()
	for name, value := range manager.nativeTunnelProviderStatsLocked() {
		stats[name] = value
	}
	manager.mu.Unlock()
	return dataplane.KernelTransportStatus{
		Mode:      dataplane.KernelTransportModeAuto,
		Available: available,
		Provider:  provider,
		Protocols: protocols,
		Notes: []string{
			"experimental_tcp and UDP fixed-frame contracts can use XDP/AF_XDP for TrustIX data frame RX/TX when the underlay fast path is attached",
			"secure handshake and optional userspace AEAD fallback stay in daemon",
		},
		Statistics: stats,
	}, nil
}

func kernelTransportProtocolTunnel(protocol string, carrier string) dataplane.KernelTransportProtocol {
	ready, reason := probeTunnelCapability(protocol)
	placement := "kernel"
	if !ready {
		placement = "unavailable"
	}
	return dataplane.KernelTransportProtocol{
		Protocol:          protocol,
		Available:         ready,
		CapabilityReady:   ready,
		Placement:         placement,
		Provider:          "linux-netlink",
		Carrier:           carrier,
		Contract:          "trustix-kernel-tunnel-carrier-v1",
		UserspaceFallback: false,
		RequiredConfig:    []string{"local", "remote", "local_carrier", "remote_carrier", "mtu"},
		Reason:            reason,
	}
}

func probeTunnelCapability(protocol string) (bool, string) {
	now := time.Now()
	if cached, ok := tunnelCapabilityProbeCache.Load(protocol); ok {
		result := cached.(tunnelCapabilityProbeResult)
		if now.Before(result.expiresAt) {
			return result.ready, result.reason
		}
	}
	ready, reason := probeTunnelCapabilityUncached(protocol)
	tunnelCapabilityProbeCache.Store(protocol, tunnelCapabilityProbeResult{
		ready:     ready,
		reason:    reason,
		expiresAt: now.Add(tunnelCapabilityCacheTTL),
	})
	return ready, reason
}

func probeTunnelCapabilityUncached(protocol string) (bool, string) {
	if os.Geteuid() != 0 {
		return false, "CAP_NET_ADMIN/root is required to create Linux tunnel netdevs"
	}
	name := fmt.Sprintf("tixcap%s%x", protocol, time.Now().UnixNano()&0xffff)
	attrs := netlink.LinkAttrs{Name: name, MTU: 1280}
	local := net.IPv4(127, 0, 0, 1)
	remote := net.IPv4(127, 0, 0, 2)
	var err error
	switch protocol {
	case "gre":
		err = netlink.LinkAdd(&netlink.Gretun{LinkAttrs: attrs, Local: local, Remote: remote})
	case "ipip":
		err = netlink.LinkAdd(&netlink.Iptun{LinkAttrs: attrs, Local: local, Remote: remote})
	case "vxlan":
		err = netlink.LinkAdd(&netlink.Vxlan{LinkAttrs: attrs, VxlanId: 1, SrcAddr: local, Group: remote, Port: 4789})
	default:
		return false, "unsupported tunnel protocol"
	}
	if err != nil {
		return false, fmt.Sprintf("Linux %s tunnel netdev capability probe failed: %v", protocol, err)
	}
	if link, lookupErr := netlink.LinkByName(name); lookupErr == nil {
		_ = netlink.LinkDel(link)
	}
	return true, fmt.Sprintf("Linux %s netdev can carry an inner UDP TrustIX carrier packet; secure handshake and AEAD remain above the carrier unless kernel crypto is selected elsewhere", protocol)
}

func kernelTransportProtocolExperimentalTCP(status dataplane.ExperimentalTCPStatus) dataplane.KernelTransportProtocol {
	placement := "userspace"
	reason := "experimental_tcp AF_XDP provider is unavailable"
	available := status.Available && status.Reinject
	if status.FastPath && status.KernelCrypto {
		placement = "kernel"
		reason = "AF_XDP/XDP handles RX/TX; kernel crypto is available when selected"
	} else if status.FastPath {
		placement = "hybrid"
		reason = "AF_XDP/XDP handles RX/TX; AEAD can fall back to userspace"
	} else if status.RawSocketFallback && available && status.KernelCrypto {
		placement = "kernel"
		reason = "raw socket fallback carries the experimental_tcp frame contract while AES-GCM AEAD runs through the kernel crypto device"
	} else if status.RawSocketFallback && available {
		placement = "fallback"
		reason = "raw socket fallback carries the experimental_tcp frame contract without an attached AF_XDP fast path"
	} else if status.Available {
		placement = "fallback"
		reason = "experimental_tcp contract is available without an attached AF_XDP fast path"
	}
	if status.FastPathFallback != "" {
		reason += "; fallback=" + status.FastPathFallback
	}
	return dataplane.KernelTransportProtocol{
		Protocol:          "experimental_tcp",
		Available:         available,
		CapabilityReady:   status.Available,
		Placement:         placement,
		Provider:          status.Provider,
		Carrier:           "tcp-shaped-ipv4",
		Contract:          "trustix-experimental-tcp-frame-v1",
		UserspaceFallback: !status.KernelCrypto,
		Reason:            reason,
	}
}

func kernelTransportProtocolUDP(status dataplane.KernelUDPStatus) dataplane.KernelTransportProtocol {
	placement := "userspace"
	reason := "UDP AF_XDP provider is unavailable"
	available := status.Available && status.Reinject && (status.FastPath || status.Provider == "raw_udp_fallback")
	if status.FastPath && status.KernelCrypto {
		placement = "kernel"
		reason = "XDP/AF_XDP handles UDP-shaped TIXU frame RX/TX; AES-GCM AEAD can run in the shared kernel crypto provider"
	} else if status.FastPath {
		placement = "hybrid"
		reason = "XDP/AF_XDP handles UDP-shaped TIXU frame RX/TX; AEAD falls back to userspace when kernel crypto is unavailable"
	} else if status.Provider == "raw_udp_fallback" && status.Available && status.Reinject && status.KernelCrypto {
		placement = "kernel"
		reason = "raw UDP fallback carries TIXU frames while AES-GCM AEAD runs through the kernel crypto device"
	} else if status.Provider == "raw_udp_fallback" && status.Available && status.Reinject {
		placement = "fallback"
		reason = "raw UDP fallback carries the kernel_udp TIXU frame contract without an attached AF_XDP fast path"
	} else if status.Available {
		placement = "fallback"
		reason = "UDP kernel transport contract is available but no AF_XDP fast path is attached"
	}
	return dataplane.KernelTransportProtocol{
		Protocol:          "udp",
		Available:         available,
		CapabilityReady:   status.Available,
		Placement:         placement,
		Provider:          status.Provider,
		Carrier:           "udp-ipv4",
		Contract:          "trustix-kernel-udp-frame-v1",
		UserspaceFallback: !status.KernelCrypto,
		Reason:            reason,
	}
}

func (manager *Manager) InstallExperimentalTCPFlows(ctx context.Context, flows []dataplane.ExperimentalTCPFlow) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	if manager.experimentalTCPFastPathDisabledLocked() && !experimentalTCPRawFallbackEnabled() {
		reason := manager.experimentalTCPFastPathDisabledReasonLocked()
		if reason == "" {
			reason = "disabled by attach policy"
		}
		return fmt.Errorf("experimental_tcp fast path is disabled: %s", reason)
	}
	if manager.expTCPFlows == nil {
		manager.expTCPFlows = make(map[uint64]dataplane.ExperimentalTCPFlow, len(flows))
	}
	manager.pruneExperimentalTCPFlowsLocked(time.Now().UTC())
	oldFlows := cloneExperimentalTCPFlows(manager.expTCPFlows)
	oldTemplates := manager.expTCPTXTemplates
	now := time.Now().UTC()
	for _, flow := range flows {
		if flow.CryptoPlacement == dataplane.CryptoPlacementKernel {
			if !manager.experimentalTCPKernelCryptoReadyLocked() {
				manager.kernelCryptoFlowRejects++
				return fmt.Errorf("experimental_tcp flow %d requested kernel crypto, but kernel crypto is not available: %s", flow.ID, manager.experimentalTCPKernelCryptoUnavailableReasonLocked())
			}
		}
		if flow.CryptoPlacement == "" || flow.CryptoPlacement == dataplane.CryptoPlacementAuto {
			flow.CryptoPlacement = dataplane.CryptoPlacementUserspace
		}
		if flow.RemoteAddress != "" {
			flow = persistEstablishedExperimentalTCPFlowLifetime(flow, now)
		} else {
			flow = refreshExperimentalTCPFlowLifetime(flow, now)
		}
		manager.deleteDuplicateExperimentalTCPFlowsLocked(flow)
		manager.expTCPFlows[flow.ID] = flow
		manager.invalidateExperimentalTCPTXTemplateLocked(flow.ID)
		manager.updateExperimentalTCPTelemetryIdentityLocked(flow.ID, flow)
	}
	if err := manager.ensureKernelTransportFastPathLocked(ctx); err != nil {
		manager.expTCPFlows = oldFlows
		manager.expTCPTXTemplates = oldTemplates
		return err
	}
	if err := manager.syncExperimentalTCPPortsLocked(); err != nil {
		manager.expTCPFlows = oldFlows
		manager.expTCPTXTemplates = oldTemplates
		_ = manager.syncExperimentalTCPPortsLocked()
		_ = manager.syncKernelUDPTXDirectLocked()
		return err
	}
	if err := manager.syncKernelUDPTXDirectLocked(); err != nil {
		manager.expTCPFlows = oldFlows
		manager.expTCPTXTemplates = oldTemplates
		_ = manager.syncExperimentalTCPPortsLocked()
		_ = manager.syncKernelUDPTXDirectLocked()
		return err
	}
	return manager.persistStateLocked()
}

func (manager *Manager) deleteDuplicateExperimentalTCPFlowsLocked(flow dataplane.ExperimentalTCPFlow) {
	for flowID, existing := range manager.expTCPFlows {
		if flowID == flow.ID {
			continue
		}
		if !experimentalTCPFlowsSharePathIdentity(existing, flow) {
			continue
		}
		delete(manager.expTCPFlows, flowID)
		delete(manager.kernelUDPTXDirectSequences, flowID)
		delete(manager.expTCPOuterTXSequences, flowID)
		delete(manager.expTCPOuterTXAcknowledgments, flowID)
		manager.invalidateExperimentalTCPTXTemplateLocked(flowID)
		delete(manager.expTCPTelemetry, flowID)
		manager.deleteExperimentalTCPCryptoFragmentsLocked(flowID)
		manager.deleteKernelCryptoFlowLocked(flowID)
		manager.deleteKernelCryptoDeviceLocked(kernelCryptoNamespaceExperimentalTCP, flowID)
	}
}

func experimentalTCPFlowsSharePathIdentity(left, right dataplane.ExperimentalTCPFlow) bool {
	if left.Peer == "" || right.Peer == "" || left.Peer != right.Peer {
		return false
	}
	if left.Endpoint == "" || right.Endpoint == "" || left.Endpoint != right.Endpoint {
		return false
	}
	if left.LocalAddress == "" || right.LocalAddress == "" || left.LocalAddress != right.LocalAddress {
		return false
	}
	if left.RemoteAddress == "" || right.RemoteAddress == "" || left.RemoteAddress != right.RemoteAddress {
		return false
	}
	if left.SourcePort == 0 || right.SourcePort == 0 || left.SourcePort != right.SourcePort {
		return false
	}
	if left.DestinationPort == 0 || right.DestinationPort == 0 || left.DestinationPort != right.DestinationPort {
		return false
	}
	return true
}

func (manager *Manager) DeleteExperimentalTCPFlows(ctx context.Context, flowIDs []uint64) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	if len(flowIDs) == 0 {
		return nil
	}
	for _, flowID := range flowIDs {
		delete(manager.expTCPFlows, flowID)
		delete(manager.kernelUDPTXDirectSequences, flowID)
		delete(manager.expTCPOuterTXSequences, flowID)
		delete(manager.expTCPOuterTXAcknowledgments, flowID)
		manager.invalidateExperimentalTCPTXTemplateLocked(flowID)
		delete(manager.expTCPTelemetry, flowID)
		manager.deleteExperimentalTCPCryptoFragmentsLocked(flowID)
		manager.deleteKernelCryptoFlowLocked(flowID)
		manager.deleteKernelCryptoDeviceLocked(kernelCryptoNamespaceExperimentalTCP, flowID)
	}
	if err := manager.ensureKernelTransportFastPathLocked(ctx); err != nil {
		return err
	}
	if err := manager.syncExperimentalTCPPortsLocked(); err != nil {
		return err
	}
	if err := manager.syncKernelUDPTXDirectLocked(); err != nil {
		return err
	}
	return manager.persistStateLocked()
}

func (manager *Manager) ExperimentalTCPFlow(ctx context.Context, flowID uint64) (dataplane.ExperimentalTCPFlow, bool, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return dataplane.ExperimentalTCPFlow{}, false, err
	}
	if manager.expTCPFlows == nil {
		return dataplane.ExperimentalTCPFlow{}, false, nil
	}
	flow, ok := manager.expTCPFlows[flowID]
	if !ok {
		return dataplane.ExperimentalTCPFlow{}, false, nil
	}
	return flow, true, nil
}

func (manager *Manager) invalidateExperimentalTCPTXTemplateLocked(flowID uint64) {
	if manager.expTCPTXTemplates != nil {
		delete(manager.expTCPTXTemplates, flowID)
	}
}

func (manager *Manager) deleteExperimentalTCPCryptoFragmentsLocked(flowID uint64) {
	for key := range manager.expTCPCryptoFragments {
		if key.flowID == flowID {
			delete(manager.expTCPCryptoFragments, key)
		}
	}
}

func (manager *Manager) SetExperimentalTCPFlowPeer(ctx context.Context, flowID uint64, peer core.IXID, endpoint core.EndpointID) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	flow, ok := manager.expTCPFlows[flowID]
	if !ok {
		return nil
	}
	next := flow
	if peer != "" {
		next.Peer = peer
	}
	if endpoint != "" {
		next.Endpoint = endpoint
	}
	if manager.experimentalTCPFlowRemoteAddressFillAllowedLocked(flow, next) {
		next = manager.fillExperimentalTCPFlowRemoteAddressFromEndpointLocked(next)
	}
	if next.Peer == flow.Peer && next.Endpoint == flow.Endpoint && next.RemoteAddress == flow.RemoteAddress && flow.ExpiresAt.IsZero() {
		return nil
	}
	flow = next
	flow = persistEstablishedExperimentalTCPFlowLifetime(flow, time.Now().UTC())
	manager.deleteDuplicateExperimentalTCPFlowsLocked(flow)
	manager.expTCPFlows[flowID] = flow
	manager.invalidateExperimentalTCPTXTemplateLocked(flowID)
	manager.updateExperimentalTCPTelemetryIdentityLocked(flowID, flow)
	if err := manager.syncKernelUDPTXDirectLocked(); err != nil {
		return err
	}
	return nil
}

func (manager *Manager) KernelUDPStatus(ctx context.Context) (dataplane.KernelUDPStatus, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return dataplane.KernelUDPStatus{}, err
	}
	if manager.refreshKernelTransportDNSTemplatesLocked(time.Now().UTC()) {
		_ = manager.syncExperimentalTCPPortsLocked()
		_ = manager.syncKernelUDPPortsLocked()
		_ = manager.syncKernelUDPTXDirectLocked()
	}
	if manager.pruneKernelUDPFlowsLocked(time.Now().UTC()) {
		_ = manager.syncKernelUDPPortsLocked()
		_ = manager.syncKernelUDPTXDirectLocked()
		_ = manager.persistStateLocked()
	}
	fastPath := manager.experimentalTCPFastPathAvailableLocked()
	tcOnly := manager.kernelUDPTCDirectOnlyAvailableLocked()
	rawFallback := kernelUDPRawFallbackEnabled()
	provider := "none"
	if fastPath {
		provider = manager.experimentalTCPFastPathProviderLocked()
	} else if tcOnly {
		provider = "tc_direct"
	} else if rawFallback {
		provider = "raw_udp_fallback"
	}
	kernelCryptoReady := manager.kernelUDPKernelCryptoReadyLocked() && !tcOnly
	kernelCryptoReason := ""
	if !kernelCryptoReady {
		kernelCryptoReason = manager.kernelUDPKernelCryptoUnavailableReasonLocked()
	}
	supportedCrypto := []dataplane.CryptoPlacement{dataplane.CryptoPlacementUserspace}
	preferredCrypto := dataplane.CryptoPlacementUserspace
	if kernelCryptoReady {
		preferredCrypto = dataplane.CryptoPlacementKernel
		supportedCrypto = append(supportedCrypto, dataplane.CryptoPlacementKernel)
	}
	xdpAttachMode, afXDPBindMode, zeroCopyEnabled, fastPathFallback := manager.experimentalTCPFastPathModeLocked()
	notes := []string{
		"UDP kernel transport uses fixed TIXU frames over IPv4/UDP",
		"XDP redirects allowlisted UDP destination ports into AF_XDP for control and fallback traffic when AF_XDP is attached",
		"secure handshake stays in userspace; AES-GCM data AEAD can run through TC direct BPF crypto when available or through the trustix_crypto AEAD device",
		"ChaCha20-Poly1305 remains userspace-only until the kernel provider exposes a synchronous kfunc AEAD implementation for that suite",
	}
	if kernelUDPTXDirectOnlyEnabled(manager.spec) {
		if tcOnly && !fastPath {
			notes = append(notes, "kernel_udp direct-only is enabled: plaintext payload data uses TC direct paths without AF_XDP userspace control traffic")
		} else {
			notes = append(notes, "kernel_udp direct-only is enabled: payload data uses TC/XDP direct paths when route and flow maps match; AF_XDP remains available for control session establishment")
		}
	}
	if rawFallback && !fastPath {
		notes = append(notes, "kernel_udp raw UDP fallback is enabled: TIXU frames use raw IPv4/UDP sockets when AF_XDP is unavailable; AEAD remains in userspace unless kernel crypto is explicitly ready")
	}
	if xdpAttachMode != "" || afXDPBindMode != "" {
		notes = append(notes, fmt.Sprintf("AF_XDP negotiated xdp_attach_mode=%s af_xdp_bind_mode=%s zerocopy_enabled=%t", xdpAttachMode, afXDPBindMode, zeroCopyEnabled))
	}
	if fastPathFallback != "" {
		notes = append(notes, "AF_XDP mode fallback: "+fastPathFallback)
	}
	return dataplane.KernelUDPStatus{
		Available:          manager.attached && (fastPath || tcOnly || rawFallback),
		Provider:           provider,
		FastPath:           fastPath || tcOnly,
		DirectOnly:         kernelUDPTXDirectOnlyEnabled(manager.spec),
		TCOnly:             tcOnly && !fastPath,
		UserspaceCrypto:    manager.attached && (fastPath || rawFallback),
		KernelCrypto:       kernelCryptoReady,
		KernelCryptoReason: kernelCryptoReason,
		CryptoFallback:     manager.kernelUDPCryptoFallbackStatusLocked(),
		PreferredCrypto:    preferredCrypto,
		SupportedCrypto:    supportedCrypto,
		Reinject:           manager.attached && (fastPath || tcOnly || rawFallback),
		XDPAttachMode:      xdpAttachMode,
		AFXDPBindMode:      afXDPBindMode,
		ZeroCopyEnabled:    zeroCopyEnabled,
		ActiveFlows:        len(manager.kernelUDPFlows),
		SubmittedFrames:    manager.kernelUDPSubmitted,
		ReceivedFrames:     manager.kernelUDPReceived,
		ProviderStats:      manager.kernelUDPProviderStatsLocked(),
		Telemetry:          manager.kernelUDPTelemetrySnapshotLocked(),
		Notes:              notes,
	}, nil
}

func (manager *Manager) ensureKernelTransportFastPathLocked(ctx context.Context) error {
	if manager.snapshotNeedsKernelTransportFastPathLocked() {
		if manager.snapshotCanUseKernelUDPTCOnlyLocked() {
			if err := manager.detachExperimentalTCPFastPathLocked(); err != nil {
				return err
			}
			if err := manager.ensureKernelUDPRXDirectLocked(); err != nil {
				if kernelUDPTCOnlyProviderRequestedForSpec(manager.spec) {
					return fmt.Errorf("attach kernel_udp TC-only RX direct provider: %w", err)
				}
				manager.warnings = append(manager.warnings, "kernel_udp TC RX direct disabled: "+err.Error())
			}
			return nil
		}
		if err := manager.attachExperimentalTCPFastPathLocked(ctx, manager.spec); err != nil {
			if manager.snapshotCanFallbackToKernelUDPTCOnlyLocked() {
				manager.warnings = append(manager.warnings, "experimental_tcp AF_XDP fast path unavailable; falling back to kernel_udp TC-only provider: "+err.Error())
				if detachErr := manager.detachExperimentalTCPFastPathLocked(); detachErr != nil {
					return detachErr
				}
				if rxErr := manager.ensureKernelUDPRXDirectLocked(); rxErr != nil {
					return fmt.Errorf("attach experimental_tcp AF_XDP fast path: %w; attach kernel_udp TC-only fallback: %v", err, rxErr)
				}
				return nil
			}
			if experimentalTCPRawFallbackEnabled() && manager.snapshotHasLocalExperimentalTCPEndpointLocked() {
				manager.warnings = append(manager.warnings, "experimental_tcp AF_XDP fast path unavailable; using raw socket fallback: "+err.Error())
				if detachErr := manager.detachExperimentalTCPFastPathLocked(); detachErr != nil {
					return detachErr
				}
				return nil
			}
			if kernelUDPRawFallbackEnabled() && manager.snapshotHasLocalKernelUDPEndpointLocked() {
				manager.warnings = append(manager.warnings, "kernel_udp AF_XDP fast path unavailable; using raw UDP fallback: "+err.Error())
				if detachErr := manager.detachExperimentalTCPFastPathLocked(); detachErr != nil {
					return detachErr
				}
				return nil
			}
			if manager.snapshot.PacketPolicy.KernelTransportMode != dataplane.KernelTransportModeRequireKernel {
				manager.warnings = append(manager.warnings, "kernel transport fast path unavailable; continuing without AF_XDP provider: "+err.Error())
				if detachErr := manager.detachExperimentalTCPFastPathLocked(); detachErr != nil {
					return detachErr
				}
				return nil
			}
			return err
		}
		if kernelDatapathRXWorkerOwnsStackRXForSpec(manager.spec) {
			if err := manager.syncKernelUDPRXDirectConfigLocked(); err != nil {
				manager.warnings = append(manager.warnings, "kernel datapath RX worker XDP pass config failed: "+err.Error())
			}
		}
		if err := manager.ensureKernelUDPRXDirectLocked(); err != nil {
			manager.warnings = append(manager.warnings, "kernel_udp TC RX direct disabled: "+err.Error())
		}
		return nil
	}
	return manager.detachIdleKernelTransportFastPathLocked()
}

func (manager *Manager) snapshotCanUseKernelUDPTCOnlyLocked() bool {
	return kernelUDPTCOnlyProviderRequestedForSpec(manager.spec) && manager.snapshotKernelUDPTCOnlyEligibleLocked()
}

func (manager *Manager) snapshotCanFallbackToKernelUDPTCOnlyLocked() bool {
	return !kernelUDPTCOnlyFallbackDisabled() && manager.snapshotKernelUDPTCOnlyEligibleLocked()
}

func (manager *Manager) snapshotKernelUDPTCOnlyEligibleLocked() bool {
	if !manager.kernelUDPTCOnlyEligibleLocked() {
		return false
	}
	if len(manager.expTCPFlows) > 0 {
		return false
	}
	for _, flow := range manager.kernelUDPFlows {
		if flow.CryptoPlacement == dataplane.CryptoPlacementKernel || flow.CryptoSuite != "" || flow.Epoch != 0 {
			return false
		}
		encryption := kernelUDPFlowSecurityEncryptionLocked(manager.snapshot, flow)
		if encryption != "" && encryption != "plaintext" {
			return false
		}
	}
	localIX := manager.snapshotLocalIXLocked()
	for _, endpoint := range manager.snapshot.Endpoints {
		if !endpoint.Enabled || !snapshotEndpointIsLocal(localIX, endpoint) {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(endpoint.Transport)) {
		case "experimental_tcp":
			return false
		case "udp", "kernel_udp":
			encryption := secureEndpointEncryption(endpoint.Security.Encryption)
			if encryption != "" && encryption != "plaintext" {
				return false
			}
		}
	}
	return true
}

func (manager *Manager) snapshotHasLocalKernelUDPEndpointLocked() bool {
	localIX := manager.snapshotLocalIXLocked()
	for _, endpoint := range manager.snapshot.Endpoints {
		if !endpoint.Enabled || !snapshotEndpointIsLocal(localIX, endpoint) {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(endpoint.Transport)) {
		case "udp", "kernel_udp":
			return true
		}
	}
	return false
}

func (manager *Manager) kernelUDPTCOnlyEligibleLocked() bool {
	if !kernelUDPTXDirectOnlyEnabled(manager.spec) || kernelUDPTXSecureDirectRequiredBySpec(manager.spec) {
		return false
	}
	if kernelDatapathRXWorkerOwnsStackRXForSpec(manager.spec) {
		return false
	}
	if manager.snapshot.PacketPolicy.KernelTransportMode == dataplane.KernelTransportModeDisabled {
		return false
	}
	if manager.spec.LANIface == "" || manager.spec.UnderlayIface == "" || manager.statsMap == nil ||
		manager.kernelUDPTXRouteMap == nil || manager.kernelUDPTXFlowMap == nil || kernelUDPRXDirectDisabledForSpec(manager.spec) {
		return false
	}
	return true
}

func (manager *Manager) kernelUDPTCDirectOnlyAvailableLocked() bool {
	return manager.expTCPFastPath == nil &&
		manager.kernelUDPTCOnlyEligibleLocked() &&
		manager.kernelUDPRXDirectAttached &&
		manager.underlayIngressProg != nil &&
		manager.kernelTransportPortMap != nil
}

func (manager *Manager) reconcileKernelTransportFlowsForSnapshotLocked(snapshot dataplane.Snapshot) bool {
	expAllowed := make(map[kernelTransportFlowIdentity]struct{}, len(manager.expTCPFlows))
	udpAllowed := make(map[kernelTransportFlowIdentity]struct{}, len(manager.kernelUDPFlows))
	localIX := manager.snapshotLocalIXLocked()
	for _, peer := range snapshot.Peers {
		if peer.ID == "" {
			continue
		}
		for _, endpoint := range snapshot.Endpoints {
			if !endpoint.Enabled || endpoint.Peer != peer.ID || endpoint.Address == "" {
				continue
			}
			if !snapshotPeerHasRouteToEndpoint(snapshot, peer.ID, endpoint.ID) {
				continue
			}
			identity := kernelTransportFlowIdentity{peer: peer.ID, endpoint: endpoint.ID}
			switch strings.ToLower(strings.TrimSpace(endpoint.Transport)) {
			case "experimental_tcp":
				if !manager.experimentalTCPFastPathDisabledLocked() || experimentalTCPRawFallbackEnabled() {
					expAllowed[identity] = struct{}{}
				}
			case "udp", "kernel_udp":
				udpAllowed[identity] = struct{}{}
			}
		}
	}
	// Local listener endpoints are never selected by outbound routes, but
	// keeping reverse/listener learned flows for still-enabled local endpoints
	// avoids deleting inbound state during a pure route-policy refresh.
	for _, endpoint := range snapshot.Endpoints {
		if !endpoint.Enabled || !snapshotEndpointIsLocal(localIX, endpoint) {
			continue
		}
		identity := kernelTransportFlowIdentity{endpoint: endpoint.ID}
		switch strings.ToLower(strings.TrimSpace(endpoint.Transport)) {
		case "experimental_tcp":
			if !manager.experimentalTCPFastPathDisabledLocked() || experimentalTCPRawFallbackEnabled() {
				expAllowed[identity] = struct{}{}
			}
		case "udp", "kernel_udp":
			udpAllowed[identity] = struct{}{}
		}
	}

	changed := false
	for flowID, flow := range manager.expTCPFlows {
		if !kernelTransportFlowAllowed(expAllowed, flow.Peer, flow.Endpoint) {
			delete(manager.expTCPFlows, flowID)
			delete(manager.expTCPOuterTXSequences, flowID)
			delete(manager.expTCPOuterTXAcknowledgments, flowID)
			manager.invalidateExperimentalTCPTXTemplateLocked(flowID)
			delete(manager.expTCPTelemetry, flowID)
			manager.deleteExperimentalTCPCryptoFragmentsLocked(flowID)
			manager.deleteKernelCryptoFlowLocked(flowID)
			manager.deleteKernelCryptoDeviceLocked(kernelCryptoNamespaceExperimentalTCP, flowID)
			changed = true
		}
	}
	for flowID, flow := range manager.kernelUDPFlows {
		if !kernelTransportFlowAllowed(udpAllowed, flow.Peer, flow.Endpoint) {
			manager.deleteKernelUDPFlowStateLocked(flowID)
			changed = true
		}
	}
	return changed
}

type kernelTransportFlowIdentity struct {
	peer     core.IXID
	endpoint core.EndpointID
}

func kernelTransportFlowAllowed(allowed map[kernelTransportFlowIdentity]struct{}, peer core.IXID, endpoint core.EndpointID) bool {
	if len(allowed) == 0 || endpoint == "" {
		return false
	}
	if _, ok := allowed[kernelTransportFlowIdentity{peer: peer, endpoint: endpoint}]; ok {
		return true
	}
	_, ok := allowed[kernelTransportFlowIdentity{endpoint: endpoint}]
	return ok
}

func snapshotPeerHasRouteToEndpoint(snapshot dataplane.Snapshot, peer core.IXID, endpoint core.EndpointID) bool {
	for _, route := range snapshot.Routes {
		if route.NextHop != peer || route.Kind != "" && route.Kind != routing.RouteUnicast {
			continue
		}
		return route.Endpoint == "" || route.Endpoint == endpoint
	}
	return false
}

func secureEndpointEncryption(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "secure", "encrypted", "trustix_secure", "trustix-secure":
		return "secure"
	case "plaintext", "none", "disabled", "off":
		return "plaintext"
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func kernelUDPFlowSecurityEncryptionLocked(snapshot dataplane.Snapshot, flow dataplane.KernelUDPFlow) string {
	for _, endpoint := range snapshot.Endpoints {
		if endpoint.ID == flow.Endpoint && (flow.Peer == "" || endpoint.Peer == "" || endpoint.Peer == flow.Peer) {
			return secureEndpointEncryption(endpoint.Security.Encryption)
		}
	}
	return ""
}

func (manager *Manager) ensureKernelUDPRXDirectLocked() error {
	if manager.kernelUDPRXDirectAttached || kernelUDPRXDirectDisabledForSpec(manager.spec) || kernelDatapathRXWorkerOwnsStackRXForSpec(manager.spec) || manager.spec.LANIface == "" ||
		manager.spec.UnderlayIface == "" || manager.statsMap == nil {
		return nil
	}
	if err := manager.ensureKernelTransportPortMapLocked(); err != nil {
		return err
	}
	lanLink, err := netlink.LinkByName(manager.spec.LANIface)
	if err != nil {
		return fmt.Errorf("inspect LAN iface %q: %w", manager.spec.LANIface, err)
	}
	underlayLink, err := netlink.LinkByName(manager.spec.UnderlayIface)
	if err != nil {
		return fmt.Errorf("inspect underlay iface %q: %w", manager.spec.UnderlayIface, err)
	}
	return manager.attachKernelUDPRXDirectLocked(lanLink, underlayLink)
}

func (manager *Manager) detachIdleKernelTransportFastPathLocked() error {
	if manager.expTCPFastPath == nil && !manager.kernelUDPRXDirectAttached && manager.underlayIngressFilter == nil &&
		manager.underlayIngressProg == nil && manager.kernelUDPRXSecureDirect == nil && manager.kernelUDPRXSecureDirectFilter == nil {
		return nil
	}
	var underlayLink netlink.Link
	if manager.spec.UnderlayIface != "" {
		if link, err := netlink.LinkByName(manager.spec.UnderlayIface); err == nil {
			underlayLink = link
		} else if manager.underlayIngressFilter != nil || manager.underlayQdiscPrepared {
			return fmt.Errorf("inspect underlay iface %q before idle kernel transport detach: %w", manager.spec.UnderlayIface, err)
		}
	}
	if err := manager.detachKernelUDPRXDirectLocked(underlayLink); err != nil {
		return err
	}
	if err := manager.detachExperimentalTCPFastPathLocked(); err != nil {
		return err
	}
	manager.expTCPAllowed = nil
	manager.kernelUDPAllowed = nil
	manager.kernelTransportAllowed = nil
	return nil
}

func (manager *Manager) snapshotNeedsKernelTransportFastPathLocked() bool {
	if manager.snapshot.PacketPolicy.KernelTransportMode == dataplane.KernelTransportModeDisabled {
		return false
	}
	if len(manager.kernelUDPFlows) > 0 {
		return true
	}
	if !manager.experimentalTCPFastPathDisabledLocked() && len(manager.expTCPFlows) > 0 {
		return true
	}
	localIX := manager.snapshotLocalIXLocked()
	for _, endpoint := range manager.snapshot.Endpoints {
		if !endpoint.Enabled || !snapshotEndpointIsLocal(localIX, endpoint) {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(endpoint.Transport)) {
		case "udp", "kernel_udp":
			return true
		case "experimental_tcp":
			if !manager.experimentalTCPFastPathDisabledLocked() {
				return true
			}
		}
	}
	return false
}

func (manager *Manager) snapshotHasLocalExperimentalTCPEndpointLocked() bool {
	if manager.experimentalTCPFastPathDisabledLocked() {
		return false
	}
	localIX := manager.snapshotLocalIXLocked()
	for _, endpoint := range manager.snapshot.Endpoints {
		if !endpoint.Enabled || !snapshotEndpointIsLocal(localIX, endpoint) {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(endpoint.Transport), "experimental_tcp") {
			return true
		}
	}
	return false
}

func (manager *Manager) ExperimentalTCPPayloadMax(ctx context.Context, placement dataplane.CryptoPlacement, encrypted bool) (int, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	fastPath := manager.experimentalTCPProviderFastPathAvailableLocked()
	rawFallback := experimentalTCPRawFallbackEnabled()
	if !fastPath && !rawFallback {
		if reason := manager.experimentalTCPFastPathDisabledReasonLocked(); reason != "" {
			return 0, fmt.Errorf("experimental_tcp AF_XDP fast path is disabled: %s", reason)
		}
		return 0, fmt.Errorf("experimental_tcp AF_XDP fast path is not available")
	}
	effectivePlacement := placement
	effectiveEncrypted := encrypted
	if placement == dataplane.CryptoPlacementKernel && manager.hasKernelCryptoDeviceLocked(kernelCryptoNamespaceExperimentalTCP) {
		effectivePlacement = dataplane.CryptoPlacementUserspace
		effectiveEncrypted = true
	}
	payloadMax := manager.experimentalTCPPayloadMaxLocked(effectivePlacement, effectiveEncrypted)
	if payloadMax <= 0 {
		return 0, fmt.Errorf("experimental_tcp payload max is unavailable")
	}
	return payloadMax, nil
}

func (manager *Manager) ExperimentalTCPSealBeforeFragmentMax(ctx context.Context, placement dataplane.CryptoPlacement) (int, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if placement == dataplane.CryptoPlacementKernel && manager.hasKernelCryptoDeviceLocked(kernelCryptoNamespaceExperimentalTCP) {
		return kernelCryptoDeviceSecureMaxPlain, nil
	}
	if placement == dataplane.CryptoPlacementKernel && manager.kernelCryptoProductionReadyLocked() {
		return kernelCryptoFrameMaxPlain, nil
	}
	return 0, fmt.Errorf("experimental_tcp seal-before-fragment kernel crypto is not available")
}

func (manager *Manager) experimentalTCPPayloadMaxLocked(placement dataplane.CryptoPlacement, encrypted bool) int {
	payloadMax := 0
	if manager.experimentalTCPProviderFastPathAvailableLocked() {
		payloadMax = manager.expTCPFastPath.ExperimentalTCPPayloadMax(placement, encrypted)
	} else if experimentalTCPRawFallbackEnabled() {
		payloadMax = manager.experimentalTCPPayloadMaxForUnderlayMTULocked(placement, encrypted)
		if payloadMax <= 0 {
			payloadMax = experimentalTCPPayloadMaxForMTU(experimentalTCPRawFallbackDefaultMTU, placement, encrypted)
		}
	}
	if mtuMax := manager.experimentalTCPPayloadMaxForUnderlayMTULocked(placement, encrypted); mtuMax > 0 {
		if payloadMax <= 0 {
			payloadMax = mtuMax
		}
		payloadMax = min(payloadMax, mtuMax)
	}
	return payloadMax
}

func (manager *Manager) experimentalTCPPayloadMaxForUnderlayMTULocked(placement dataplane.CryptoPlacement, encrypted bool) int {
	mtu := manager.experimentalTCPUnderlayMTULocked()
	if mtu <= 0 {
		return 0
	}
	return experimentalTCPPayloadMaxForMTU(mtu, placement, encrypted)
}

func experimentalTCPPayloadMaxForMTU(mtu int, placement dataplane.CryptoPlacement, encrypted bool) int {
	overhead := rejectIPv4HeaderLen + rejectTCPHeaderLen + experimentaltcp.HeaderLen
	if placement == dataplane.CryptoPlacementKernel || encrypted {
		overhead += experimentalTCPKernelCryptoOverhead
	}
	if mtu <= overhead {
		return 1
	}
	return mtu - overhead
}

func (manager *Manager) experimentalTCPUnderlayMTULocked() int {
	mtu := 0
	if manager.snapshot.PacketPolicy.MTU > 0 {
		mtu = int(manager.snapshot.PacketPolicy.MTU)
	}
	if manager.spec.UnderlayIface != "" {
		if link, err := netlink.LinkByName(manager.spec.UnderlayIface); err == nil && link != nil && link.Attrs() != nil && link.Attrs().MTU > 0 {
			if mtu == 0 || link.Attrs().MTU < mtu {
				mtu = link.Attrs().MTU
			}
		}
	}
	return mtu
}

func (manager *Manager) KernelUDPPayloadMax(ctx context.Context, placement dataplane.CryptoPlacement, encrypted bool) (int, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	fastPath := manager.experimentalTCPFastPathAvailableLocked()
	rawFallback := kernelUDPRawFallbackEnabled()
	if !fastPath && !rawFallback {
		return 0, fmt.Errorf("UDP AF_XDP kernel transport provider is not available")
	}
	if fastPath && placement == dataplane.CryptoPlacementKernel && manager.hasKernelCryptoDeviceLocked(kernelCryptoNamespaceKernelUDP) {
		return manager.expTCPFastPath.KernelUDPPayloadMaxWithDeviceCrypto(), nil
	}
	if fastPath {
		return manager.expTCPFastPath.KernelUDPPayloadMax(placement, encrypted), nil
	}
	if placement == dataplane.CryptoPlacementKernel {
		if !manager.kernelUDPKernelCryptoReadyLocked() {
			return 0, fmt.Errorf("kernel_udp raw UDP fallback kernel crypto is not available: %s", manager.kernelUDPKernelCryptoUnavailableReasonLocked())
		}
		return manager.kernelUDPRawFallbackPayloadMaxLocked(placement, true), nil
	}
	return manager.kernelUDPRawFallbackPayloadMaxLocked(placement, encrypted), nil
}

func (manager *Manager) KernelUDPSealBeforeFragmentMax(ctx context.Context, placement dataplane.CryptoPlacement) (int, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if placement == dataplane.CryptoPlacementKernel && manager.hasKernelCryptoDeviceLocked(kernelCryptoNamespaceKernelUDP) {
		return kernelCryptoDeviceSecureMaxPlain, nil
	}
	return kerneludp.MaxPayload - kernelCryptoSecureHeaderLen - kernelCryptoFrameTagLen, nil
}

func (manager *Manager) InstallKernelUDPFlows(ctx context.Context, flows []dataplane.KernelUDPFlow) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	if manager.kernelUDPFlows == nil {
		manager.kernelUDPFlows = make(map[uint64]dataplane.KernelUDPFlow, len(flows))
	}
	manager.pruneKernelUDPFlowsLocked(time.Now().UTC())
	oldFlows := cloneKernelUDPFlows(manager.kernelUDPFlows)
	oldTemplates := manager.kernelUDPTXTemplates
	now := time.Now().UTC()
	for _, flow := range flows {
		flow = refreshInstalledKernelUDPFlowLifetime(flow, now)
		// KUDP uses endpoint listen ports as the underlay tuple. A local
		// outbound session and a peer-originated inbound session can therefore
		// have the same path identity while carrying different wire flow IDs.
		// Keep both so replies using either flow ID can still be delivered to
		// the session that owns that ID.
		manager.kernelUDPFlows[flow.ID] = flow
		manager.invalidateKernelUDPTXTemplateLocked(flow.ID)
		manager.updateKernelUDPTelemetryIdentityLocked(flow.ID, flow)
	}
	if err := manager.ensureKernelTransportFastPathLocked(ctx); err != nil {
		manager.kernelUDPFlows = oldFlows
		manager.kernelUDPTXTemplates = oldTemplates
		return err
	}
	if !manager.experimentalTCPFastPathAvailableLocked() && !manager.kernelUDPTCDirectOnlyAvailableLocked() && !manager.kernelUDPTCDirectOnlyPendingLocked() && !kernelUDPRawFallbackEnabled() {
		manager.kernelUDPFlows = oldFlows
		manager.kernelUDPTXTemplates = oldTemplates
		return fmt.Errorf("UDP AF_XDP kernel transport provider is not available")
	}
	if err := manager.syncKernelUDPPortsLocked(); err != nil {
		manager.kernelUDPFlows = oldFlows
		manager.kernelUDPTXTemplates = oldTemplates
		_ = manager.syncKernelUDPPortsLocked()
		_ = manager.syncKernelUDPTXDirectLocked()
		return err
	}
	if err := manager.syncKernelUDPTXDirectLocked(); err != nil {
		manager.kernelUDPFlows = oldFlows
		manager.kernelUDPTXTemplates = oldTemplates
		_ = manager.syncKernelUDPPortsLocked()
		_ = manager.syncKernelUDPTXDirectLocked()
		return err
	}
	return manager.persistStateLocked()
}

func (manager *Manager) kernelUDPTCDirectOnlyPendingLocked() bool {
	return manager.expTCPFastPath == nil &&
		manager.kernelUDPTCOnlyEligibleLocked() &&
		manager.snapshotKernelUDPTCOnlyEligibleLocked()
}

func (manager *Manager) deleteDuplicateKernelUDPFlowsLocked(flow dataplane.KernelUDPFlow) {
	for flowID, existing := range manager.kernelUDPFlows {
		if flowID == flow.ID {
			continue
		}
		if !kernelUDPFlowsSharePathIdentity(existing, flow) {
			continue
		}
		manager.deleteKernelUDPFlowStateLocked(flowID)
	}
}

func kernelUDPFlowsSharePathIdentity(left, right dataplane.KernelUDPFlow) bool {
	if left.Peer == "" || right.Peer == "" || left.Peer != right.Peer {
		return false
	}
	if left.Endpoint == "" || right.Endpoint == "" || left.Endpoint != right.Endpoint {
		return false
	}
	if left.LocalAddress == "" || right.LocalAddress == "" || left.LocalAddress != right.LocalAddress {
		return false
	}
	if left.RemoteAddress == "" || right.RemoteAddress == "" || left.RemoteAddress != right.RemoteAddress {
		return false
	}
	if left.SourcePort == 0 || right.SourcePort == 0 || left.SourcePort != right.SourcePort {
		return false
	}
	if left.DestinationPort == 0 || right.DestinationPort == 0 || left.DestinationPort != right.DestinationPort {
		return false
	}
	return true
}

func (manager *Manager) DeleteKernelUDPFlows(ctx context.Context, flowIDs []uint64) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	if len(flowIDs) == 0 {
		return nil
	}
	for _, flowID := range flowIDs {
		manager.deleteKernelUDPFlowStateLocked(flowID)
	}
	if err := manager.ensureKernelTransportFastPathLocked(ctx); err != nil {
		return err
	}
	if err := manager.syncKernelUDPPortsLocked(); err != nil {
		return err
	}
	if err := manager.syncKernelUDPTXDirectLocked(); err != nil {
		return err
	}
	return manager.persistStateLocked()
}

func (manager *Manager) KernelUDPFlow(ctx context.Context, flowID uint64) (dataplane.KernelUDPFlow, bool, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return dataplane.KernelUDPFlow{}, false, err
	}
	if manager.kernelUDPFlows == nil {
		return dataplane.KernelUDPFlow{}, false, nil
	}
	flow, ok := manager.kernelUDPFlows[flowID]
	if !ok {
		return dataplane.KernelUDPFlow{}, false, nil
	}
	return flow, true, nil
}

func (manager *Manager) KernelUDPFlows(ctx context.Context) ([]dataplane.KernelUDPFlow, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(manager.kernelUDPFlows) == 0 {
		return nil, nil
	}
	flows := make([]dataplane.KernelUDPFlow, 0, len(manager.kernelUDPFlows))
	for _, flow := range manager.kernelUDPFlows {
		flows = append(flows, flow)
	}
	sort.Slice(flows, func(i, j int) bool {
		return flows[i].ID < flows[j].ID
	})
	return flows, nil
}

func (manager *Manager) deleteKernelUDPFlowStateLocked(flowID uint64) {
	delete(manager.kernelUDPFlows, flowID)
	delete(manager.kernelUDPTXDirectSequences, flowID)
	manager.invalidateKernelUDPTXTemplateLocked(flowID)
	delete(manager.kernelUDPTelemetry, flowID)
	manager.deleteKernelUDPCryptoFragmentsLocked(flowID)
	manager.deleteKernelUDPCryptoFlowLocked(flowID)
	manager.deleteKernelCryptoDeviceLocked(kernelCryptoNamespaceKernelUDP, flowID)
}

func (manager *Manager) invalidateKernelUDPTXTemplateLocked(flowID uint64) {
	if manager.kernelUDPTXTemplates != nil {
		delete(manager.kernelUDPTXTemplates, flowID)
	}
}

func (manager *Manager) deleteKernelUDPCryptoFragmentsLocked(flowID uint64) {
	for key := range manager.kernelUDPCryptoFragments {
		if key.flowID == flowID {
			delete(manager.kernelUDPCryptoFragments, key)
		}
	}
}

func (manager *Manager) SetKernelUDPFlowPeer(ctx context.Context, flowID uint64, peer core.IXID, endpoint core.EndpointID) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	flow, ok := manager.kernelUDPFlows[flowID]
	if !ok {
		return nil
	}
	next := flow
	if peer != "" {
		next.Peer = peer
	}
	if endpoint != "" {
		next.Endpoint = endpoint
	}
	if next.Peer == flow.Peer && next.Endpoint == flow.Endpoint && flow.ExpiresAt.IsZero() {
		return nil
	}
	flow = next
	flow = persistEstablishedKernelUDPFlowLifetime(flow, time.Now().UTC())
	manager.kernelUDPFlows[flowID] = flow
	manager.invalidateKernelUDPTXTemplateLocked(flowID)
	manager.updateKernelUDPTelemetryIdentityLocked(flowID, flow)
	if err := manager.syncKernelUDPTXDirectLocked(); err != nil {
		return err
	}
	return nil
}

func (manager *Manager) InstallKernelUDPCrypto(ctx context.Context, specs []dataplane.KernelUDPCryptoSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(specs) == 0 {
		return nil
	}
	entries, err := encodeKernelUDPCryptoSpecs(specs)
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.kernelCryptoInstallAttempts++
	if err != nil {
		manager.kernelCryptoSpecValidateErrors++
		manager.kernelCryptoSpecsRejected += uint64(len(specs))
		return err
	}
	manager.kernelCryptoSpecsValidated += uint64(len(specs))
	manager.kernelCryptoEntriesEncoded += uint64(len(entries))
	defer zeroKernelCryptoEntries(entries)
	if !manager.kernelCryptoTCDirectReadyLocked() && !manager.kernelCryptoDeviceAvailableLocked(kernelCryptoNamespaceKernelUDP) {
		reason := manager.kernelUDPKernelCryptoUnavailableReasonLocked()
		manager.kernelCryptoProviderUnavailableErrors++
		manager.kernelCryptoSpecsRejected += uint64(len(specs))
		return fmt.Errorf("kernel_udp kernel crypto provider is not available: %s", reason)
	}
	providerInstalled := false
	if manager.kernelCryptoTCDirectReadyLocked() {
		installEntries, err := manager.prepareKernelCryptoProviderInstallEntriesLocked(entries)
		if err != nil {
			manager.kernelCryptoSpecsRejected += uint64(len(specs))
			return err
		}
		if manager.kernelCryptoContextProviderReadyLocked() {
			if err := manager.kernelCryptoProvider.InstallAt(installEntries); err != nil {
				manager.rollbackKernelCryptoProviderInstallLocked(entries)
				manager.kernelCryptoSpecsRejected += uint64(len(specs))
				return err
			}
			manager.syncKernelCryptoDirectSlotsLocked(installEntries)
			if err := manager.stageKernelCryptoEntriesLocked(entries); err != nil {
				manager.rollbackKernelCryptoProviderInstallLocked(entries)
				manager.kernelCryptoSpecsRejected += uint64(len(specs))
				return err
			}
			providerInstalled = true
		} else {
			installed, err := manager.installKernelCryptoDirectOnlyLocked(entries)
			if err != nil {
				manager.kernelCryptoSpecsRejected += uint64(len(specs))
				return err
			}
			providerInstalled = installed
		}
	}
	manager.installKernelCryptoDevicesLocked(kernelCryptoNamespaceKernelUDP, entries)
	if !providerInstalled && !manager.hasKernelCryptoDeviceForEntriesLocked(kernelCryptoNamespaceKernelUDP, entries) {
		manager.kernelCryptoProviderUnavailableErrors++
		manager.kernelCryptoSpecsRejected += uint64(len(specs))
		return fmt.Errorf("kernel_udp kernel crypto device could not be opened")
	}
	if manager.kernelUDPFlows == nil {
		manager.kernelUDPFlows = make(map[uint64]dataplane.KernelUDPFlow, len(specs))
	}
	for _, spec := range specs {
		now := time.Now().UTC()
		flow := manager.kernelUDPFlows[spec.FlowID]
		flow.ID = spec.FlowID
		flow.Epoch = spec.Epoch
		flow.CryptoSuite = spec.Suite
		flow.CryptoPlacement = dataplane.CryptoPlacementKernel
		flow = persistEstablishedKernelUDPFlowLifetime(flow, now)
		manager.kernelUDPFlows[spec.FlowID] = flow
		manager.invalidateKernelUDPTXTemplateLocked(spec.FlowID)
		manager.updateKernelUDPTelemetryIdentityLocked(spec.FlowID, flow)
	}
	if err := manager.syncKernelUDPTXDirectLocked(); err != nil {
		return err
	}
	return nil
}

func (manager *Manager) SubmitKernelUDPFrame(ctx context.Context, frame dataplane.KernelUDPFrame) error {
	return manager.SubmitKernelUDPFrames(ctx, []dataplane.KernelUDPFrame{frame})
}

func (manager *Manager) SubmitKernelUDPFrames(ctx context.Context, frames []dataplane.KernelUDPFrame) error {
	if len(frames) == 0 {
		return ctx.Err()
	}
	manager.mu.Lock()
	if err := ctx.Err(); err != nil {
		manager.mu.Unlock()
		return err
	}
	if manager.pruneKernelUDPFlowsLocked(time.Now().UTC()) {
		_ = manager.syncKernelUDPPortsLocked()
		_ = manager.syncKernelUDPTXDirectLocked()
	}
	if !manager.experimentalTCPFastPathAvailableLocked() {
		if kernelUDPRawFallbackEnabled() {
			return manager.submitKernelUDPFramesRawFallbackLocked(ctx, frames)
		}
		manager.recordDropLocked(observability.DropEndpointDown)
		manager.mu.Unlock()
		return fmt.Errorf("UDP AF_XDP kernel transport provider is not available")
	}
	if !manager.kernelUDPKernelCryptoReadyLocked() {
		for _, frame := range frames {
			flow, ok := manager.kernelUDPFlows[frame.FlowID]
			if !ok {
				continue
			}
			placement := frame.CryptoPlacement
			if placement == "" || placement == dataplane.CryptoPlacementAuto {
				placement = flow.CryptoPlacement
			}
			if placement == dataplane.CryptoPlacementKernel {
				manager.kernelCryptoFrameRejects++
				reason := manager.kernelUDPKernelCryptoUnavailableReasonLocked()
				manager.mu.Unlock()
				return fmt.Errorf("kernel_udp frame %d requested kernel crypto, but kernel crypto is not available: %s", frame.FlowID, reason)
			}
		}
	}
	preparedHolder, prepared := takePreparedKernelUDPTXFrames(len(frames))
	defer func() {
		putPreparedKernelUDPTXFrames(preparedHolder, prepared)
	}()
	var pendingSealByFlow map[uint64]*pendingKernelUDPSealBatch
	var pendingSealSingleFlow uint64
	var pendingSealSingle *pendingKernelUDPSealBatch
	var sequenceByFlow map[uint64]*kernelUDPTXSequenceBatch
	var sequenceSingleFlow uint64
	var sequenceSingle *kernelUDPTXSequenceBatch
	useSequenceBatch := kernelUDPTXSequenceBatchEnabled()
	sequenceBatchCapacity := len(frames)
	if sequenceBatchCapacity > 64 {
		sequenceBatchCapacity = 64
	}
	var cachedFlowID uint64
	var cachedFlow dataplane.KernelUDPFlow
	var cachedPacket kerneludp.UDPPacket
	var cachedDst [4]byte
	var cachedFlowOK bool
	var cachedPacketOK bool
	for _, frame := range frames {
		flowID := frame.FlowID
		flow := cachedFlow
		if !cachedFlowOK || flowID != cachedFlowID {
			var ok bool
			flow, ok = manager.kernelUDPFlows[flowID]
			if !ok {
				manager.recordDropLocked(observability.DropFlowNotInstalled)
				manager.mu.Unlock()
				return fmt.Errorf("kernel_udp flow %d is not installed", flowID)
			}
			cachedFlowID = flowID
			cachedFlow = flow
			cachedFlowOK = true
			cachedPacketOK = false
		}
		payload := frame.Payload
		payloadLen := len(payload)
		flags := uint8(0)
		txInnerHash, txInnerHashValid := innerIPv4TXHash(payload)
		if frame.InnerIPv4 && kernelUDPInnerIPv4Eligible(payload) {
			flags |= kerneludp.FlagInnerIPv4
		} else {
			txInnerHashValid = false
		}
		placement := frame.CryptoPlacement
		if placement == "" || placement == dataplane.CryptoPlacementAuto {
			placement = flow.CryptoPlacement
		}
		var sequence uint64
		var err error
		if useSequenceBatch {
			sequence, err = manager.reserveKernelUDPTXSequenceBatchLocked(&sequenceByFlow, &sequenceSingleFlow, &sequenceSingle, flowID, frame.Sequence, sequenceBatchCapacity)
		} else {
			sequence, err = manager.reserveKernelUDPTXSequenceLocked(flowID, frame.Sequence)
		}
		if err != nil {
			manager.mu.Unlock()
			return err
		}
		frame.Sequence = sequence
		if placement == dataplane.CryptoPlacementKernel {
			suite := frame.CryptoSuite
			if suite == "" {
				suite = flow.CryptoSuite
			}
			if suite == "" {
				suite = kernelCryptoSuiteAES256GCMX25519
			}
			suiteID, err := kernelCryptoSuiteID(suite)
			if err != nil {
				manager.kernelCryptoFrameRejects++
				manager.mu.Unlock()
				return fmt.Errorf("kernel_udp frame %d requested unsupported kernel crypto suite %q: %w", flowID, suite, err)
			}
			epoch := frame.Epoch
			if epoch == 0 {
				epoch = flow.Epoch
			}
			flags |= kerneludp.FlagEncrypted
			pending := kernelUDPSealPendingBatchFor(&pendingSealByFlow, &pendingSealSingleFlow, &pendingSealSingle, flowID, len(frames))
			pending.indexes = append(pending.indexes, len(prepared))
			pending.requests = append(pending.requests, kernelCryptoDeviceSealRequest{
				FlowID:   flowID,
				SuiteID:  suiteID,
				Epoch:    epoch,
				Sequence: frame.Sequence,
				Plain:    payload,
			})
		}
		packet := cachedPacket
		dst := cachedDst
		if !cachedPacketOK {
			packet, dst, flow, err = manager.prepareKernelUDPPacketForFlowLocked(flowID, flow)
			if err != nil {
				manager.mu.Unlock()
				return err
			}
			cachedFlow = flow
			cachedPacket = packet
			cachedDst = dst
			cachedPacketOK = true
		}
		fragmentPayload := frame.FragmentPayloadSize
		var packetWireLen int
		var frameWireLen int
		if fragmentPayload > 0 && payloadLen > fragmentPayload {
			packetWireLen = 0
		} else {
			frameWireLen, err = kerneludp.FrameWireLen(payloadLen)
			if err != nil {
				manager.mu.Unlock()
				return err
			}
			packetWireLen, err = kerneludp.UDPIPv4WireLen(frameWireLen)
			if err != nil {
				manager.mu.Unlock()
				return err
			}
		}
		var sourceIP4 [4]byte
		var destinationIP4 [4]byte
		if packet.SourceIP.Is4() && packet.DestinationIP.Is4() {
			sourceIP4 = packet.SourceIP.As4()
			destinationIP4 = packet.DestinationIP.As4()
		}
		prepared = append(prepared, preparedKernelUDPTXFrame{
			packet: packet,
			wireFrame: kerneludp.Frame{
				Flags:         flags,
				FlowID:        flowID,
				Sequence:      frame.Sequence,
				FragmentIndex: frame.FragmentIndex,
				FragmentCount: frame.FragmentCount,
				Payload:       payload,
			},
			flow:             flow,
			bytes:            payloadLen,
			rawDst:           dst,
			sourceIP4:        sourceIP4,
			destinationIP4:   destinationIP4,
			sourcePort:       packet.SourcePort,
			destinationPort:  packet.DestinationPort,
			frameWireLen:     frameWireLen,
			packetWireLen:    packetWireLen,
			fragmentPayload:  fragmentPayload,
			txInnerHash:      txInnerHash,
			txInnerHashValid: txInnerHashValid,
		})
	}
	if useSequenceBatch {
		if err := manager.flushKernelUDPTXSequenceBatchesLocked(sequenceByFlow, sequenceSingle); err != nil {
			manager.mu.Unlock()
			return err
		}
	}
	fastPathProvider := manager.expTCPFastPath
	manager.mu.Unlock()
	releaseSealed, err := manager.sealPreparedKernelUDPFrames(prepared, pendingSealByFlow, pendingSealSingleFlow, pendingSealSingle)
	if err != nil {
		return err
	}
	prepared, err = splitPreparedKernelUDPFrames(prepared)
	if err != nil {
		if releaseSealed != nil {
			releaseSealed()
		}
		return err
	}
	if releaseSealed != nil {
		defer releaseSealed()
	}
	fallbackCount := 0
	manager.mu.Lock()
	fallbackCount = manager.reserveKernelUDPAFXDPIdleFallbackLocked(time.Now().UTC(), len(prepared))
	manager.mu.Unlock()
	fallbackSent := 0
	if fallbackCount > 0 {
		var sent int
		var fallbackErr error
		if kernelUDPAFXDPIdleFallbackUnderlayPacketEnabled() {
			sent, fallbackErr = manager.sendRawKernelUDPPreparedFramesUnderlayPacket(prepared[:fallbackCount])
		} else {
			sent, fallbackErr = manager.sendKernelUDPUDPPreparedFrames(prepared[:fallbackCount])
		}
		if sent > fallbackCount {
			sent = fallbackCount
		}
		fallbackSent = sent
		manager.mu.Lock()
		if sent > 0 {
			now := time.Now().UTC()
			manager.kernelUDPAFXDPIdleFallbackSentFrames += uint64(sent)
			manager.observeKernelUDPTXBatchLocked(prepared[:sent], now)
		}
		if fallbackErr != nil {
			manager.kernelUDPAFXDPIdleFallbackErrors++
		}
		manager.mu.Unlock()
	}
	if fallbackSent < len(prepared) {
		remaining := prepared[fallbackSent:]
		if err := fastPathProvider.SendPreparedUDPFrames(remaining, manager.resolveIPv4Neighbor); err != nil {
			manager.mu.Lock()
			manager.recordExperimentalTCPDropLocked(err)
			manager.mu.Unlock()
			return err
		}
		manager.mu.Lock()
		manager.observeKernelUDPTXBatchLocked(remaining, time.Now().UTC())
		manager.mu.Unlock()
	}
	return nil
}

func (manager *Manager) reserveKernelUDPAFXDPIdleFallbackLocked(now time.Time, frameCount int) int {
	if frameCount <= 0 || !kernelUDPAFXDPIdleFallbackEnabled() {
		return 0
	}
	after := kernelUDPAFXDPIdleFallbackAfter()
	if after < 0 {
		return 0
	}
	if !manager.kernelUDPLastTX.IsZero() && after > 0 && now.Sub(manager.kernelUDPLastTX) < after {
		return 0
	}
	if !kernelUDPAFXDPIdleFallbackUnderlayPacketEnabled() && (!kernelUDPUDPFallbackEnabled() || !manager.kernelUDPUDPFallbackSocketAvailableLocked()) {
		manager.kernelUDPAFXDPIdleFallbackSkips++
		return 0
	}
	limit := kernelUDPAFXDPIdleFallbackMaxFrames()
	fallbackCount := frameCount
	if limit > 0 && limit < fallbackCount {
		fallbackCount = limit
	}
	manager.kernelUDPLastTX = now
	manager.kernelUDPAFXDPIdleFallbackAttempts++
	manager.kernelUDPAFXDPIdleFallbackBatches++
	manager.kernelUDPAFXDPIdleFallbackFrames += uint64(fallbackCount)
	return fallbackCount
}

func (manager *Manager) kernelUDPUDPFallbackSocketAvailableLocked() bool {
	manager.kernelUDPUDPFallbackMu.RLock()
	defer manager.kernelUDPUDPFallbackMu.RUnlock()
	for _, socket := range manager.kernelUDPUDPFallbackSockets {
		if socket != nil && socket.fd >= 0 {
			return true
		}
	}
	return false
}

func (manager *Manager) observeKernelUDPTXBatchLocked(prepared []preparedKernelUDPTXFrame, now time.Time) {
	if len(prepared) == 0 {
		return
	}
	manager.kernelUDPLastTX = now
	if len(prepared) == 1 {
		item := prepared[0]
		flowID := item.wireFrame.FlowID
		telemetryFlow := item.flow
		if latest, ok := manager.kernelUDPFlows[flowID]; ok {
			telemetryFlow = latest
		}
		manager.kernelUDPSubmitted++
		manager.kernelUDPTelemetryLocked(flowID, telemetryFlow).ObserveTXBatch(1, uint64(item.bytes), now)
	} else {
		firstFlowID := prepared[0].wireFrame.FlowID
		singleFlow := true
		var frames uint64
		var bytes uint64
		for _, item := range prepared {
			if item.wireFrame.FlowID != firstFlowID {
				singleFlow = false
				break
			}
			frames++
			if item.bytes > 0 {
				bytes += uint64(item.bytes)
			}
		}
		if singleFlow {
			telemetryFlow := prepared[0].flow
			if latest, ok := manager.kernelUDPFlows[firstFlowID]; ok {
				telemetryFlow = latest
			}
			manager.kernelUDPSubmitted += frames
			manager.kernelUDPTelemetryLocked(firstFlowID, telemetryFlow).ObserveTXBatch(frames, bytes, now)
		} else {
			var telemetryByFlow map[uint64]*kernelUDPTXTelemetryBatch
			for _, item := range prepared {
				flowID := item.wireFrame.FlowID
				if telemetryByFlow == nil {
					telemetryByFlow = make(map[uint64]*kernelUDPTXTelemetryBatch, 1)
				}
				telemetry := telemetryByFlow[flowID]
				if telemetry == nil {
					telemetryFlow := item.flow
					if latest, ok := manager.kernelUDPFlows[flowID]; ok {
						telemetryFlow = latest
					}
					telemetry = &kernelUDPTXTelemetryBatch{flow: telemetryFlow}
					telemetryByFlow[flowID] = telemetry
				}
				telemetry.frames++
				if item.bytes > 0 {
					telemetry.bytes += uint64(item.bytes)
				}
				manager.kernelUDPSubmitted++
			}
			for flowID, telemetry := range telemetryByFlow {
				manager.kernelUDPTelemetryLocked(flowID, telemetry.flow).ObserveTXBatch(telemetry.frames, telemetry.bytes, now)
			}
		}
	}
}

func (manager *Manager) sealPreparedKernelUDPFrames(prepared []preparedKernelUDPTXFrame, pendingByFlow map[uint64]*pendingKernelUDPSealBatch, singleFlowID uint64, single *pendingKernelUDPSealBatch) (func(), error) {
	if len(pendingByFlow) == 0 && (single == nil || len(single.requests) == 0) {
		return nil, nil
	}
	var releases []func()
	releaseAll := func() {
		for i := len(releases) - 1; i >= 0; i-- {
			if releases[i] != nil {
				releases[i]()
			}
		}
	}
	processPending := func(flowID uint64, pending *pendingKernelUDPSealBatch) error {
		if pending == nil || len(pending.requests) == 0 {
			return nil
		}
		var device *kernelCryptoDevice
		var provider *kernelCryptoProviderObject
		manager.mu.Lock()
		device = manager.kernelCryptoDevices[flowID]
		provider = manager.kernelCryptoProvider
		manager.mu.Unlock()
		for start := 0; start < len(pending.requests); {
			end := min(start+kernelCryptoDeviceBatchMax, len(pending.requests))
			requests := pending.requests[start:end]
			indexes := pending.indexes[start:end]
			if device != nil {
				manager.mu.Lock()
				manager.kernelCryptoDeviceSealAttempts += uint64(len(requests))
				manager.observeKernelCryptoDeviceSealBatchLocked(requests)
				manager.mu.Unlock()
				var sealed [][]byte
				var release func()
				var err error
				if len(requests) >= device.poolMinBatchConfigured() {
					manager.mu.Lock()
					manager.kernelCryptoDeviceSealBorrowAttempts += uint64(len(requests))
					manager.mu.Unlock()
					sealed, release, err = device.SealBatchBorrowed(requests)
					if err != nil {
						manager.mu.Lock()
						manager.kernelCryptoDeviceSealBorrowFallbacks += uint64(len(requests))
						manager.mu.Unlock()
					}
				}
				if sealed == nil {
					sealed, err = device.SealBatch(requests)
					release = nil
				}
				if err == nil {
					if release != nil {
						releases = append(releases, release)
						manager.mu.Lock()
						manager.kernelCryptoDeviceSealBorrowSuccesses += uint64(len(sealed))
						manager.mu.Unlock()
					}
					manager.mu.Lock()
					manager.kernelCryptoDeviceSealSuccesses += uint64(len(sealed))
					manager.kernelCryptoFrameSealAttempts += uint64(len(sealed))
					manager.kernelCryptoFrameSealSuccesses += uint64(len(sealed))
					manager.mu.Unlock()
					for i, payload := range sealed {
						if err := updatePreparedKernelUDPPayload(&prepared[indexes[i]], payload); err != nil {
							releaseAll()
							return err
						}
					}
					start = end
					continue
				}
				manager.mu.Lock()
				manager.kernelCryptoDeviceSealErrors += uint64(len(requests))
				manager.mu.Unlock()
			}
			for i, request := range requests {
				manager.mu.Lock()
				manager.kernelCryptoFrameSealAttempts++
				if provider == nil {
					manager.kernelCryptoFrameSealErrors++
					manager.mu.Unlock()
					releaseAll()
					return fmt.Errorf("kernel_udp kernel crypto provider is not available")
				}
				sealed, err := provider.SealFrame(
					kernelCryptoFlowKeyFor(kernelCryptoNamespaceKernelUDP, request.FlowID, kernelCryptoDirectionSend),
					request.SuiteID,
					request.Epoch,
					request.Sequence,
					request.Plain,
				)
				if err != nil {
					manager.kernelCryptoFrameSealErrors++
					manager.mu.Unlock()
					releaseAll()
					return err
				}
				manager.kernelCryptoFrameSealSuccesses++
				manager.mu.Unlock()
				if err := updatePreparedKernelUDPPayload(&prepared[indexes[i]], sealed); err != nil {
					releaseAll()
					return err
				}
			}
			start = end
		}
		return nil
	}
	if len(pendingByFlow) == 0 {
		if err := processPending(singleFlowID, single); err != nil {
			return nil, err
		}
		return releaseAll, nil
	}
	for flowID, pending := range pendingByFlow {
		if err := processPending(flowID, pending); err != nil {
			return nil, err
		}
	}
	return releaseAll, nil
}

func updatePreparedKernelUDPPayload(frame *preparedKernelUDPTXFrame, payload []byte) error {
	frame.wireFrame.Payload = payload
	if frame.fragmentPayload > 0 && len(payload) > frame.fragmentPayload {
		frame.frameWireLen = 0
		frame.packetWireLen = 0
		return nil
	}
	frameWireLen, err := kerneludp.FrameWireLen(len(payload))
	if err != nil {
		return err
	}
	packetWireLen, err := kerneludp.UDPIPv4WireLen(frameWireLen)
	if err != nil {
		return err
	}
	frame.frameWireLen = frameWireLen
	frame.packetWireLen = packetWireLen
	return nil
}

func (manager *Manager) submitKernelUDPFramesRawFallbackLocked(ctx context.Context, frames []dataplane.KernelUDPFrame) error {
	if len(frames) == 0 {
		manager.mu.Unlock()
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		manager.mu.Unlock()
		return err
	}
	preparedHolder, prepared := takePreparedKernelUDPTXFrames(len(frames))
	defer func() {
		putPreparedKernelUDPTXFrames(preparedHolder, prepared)
	}()
	var pendingSealByFlow map[uint64]*pendingKernelUDPSealBatch
	var pendingSealSingleFlow uint64
	var pendingSealSingle *pendingKernelUDPSealBatch
	var sequenceByFlow map[uint64]*kernelUDPTXSequenceBatch
	var sequenceSingleFlow uint64
	var sequenceSingle *kernelUDPTXSequenceBatch
	useSequenceBatch := kernelUDPTXSequenceBatchEnabled()
	sequenceBatchCapacity := len(frames)
	if sequenceBatchCapacity > 64 {
		sequenceBatchCapacity = 64
	}
	var cachedFlowID uint64
	var cachedFlow dataplane.KernelUDPFlow
	var cachedPacket kerneludp.UDPPacket
	var cachedDst [4]byte
	var cachedFlowOK bool
	var cachedPacketOK bool
	for _, frame := range frames {
		flowID := frame.FlowID
		flow := cachedFlow
		if !cachedFlowOK || flowID != cachedFlowID {
			var ok bool
			flow, ok = manager.kernelUDPFlows[flowID]
			if !ok {
				manager.recordDropLocked(observability.DropFlowNotInstalled)
				manager.mu.Unlock()
				return fmt.Errorf("kernel_udp flow %d is not installed", flowID)
			}
			cachedFlowID = flowID
			cachedFlow = flow
			cachedFlowOK = true
			cachedPacketOK = false
		}
		payload := frame.Payload
		payloadLen := len(payload)
		flags := uint8(0)
		txInnerHash, txInnerHashValid := innerIPv4TXHash(payload)
		if frame.InnerIPv4 && kernelUDPInnerIPv4Eligible(payload) {
			flags |= kerneludp.FlagInnerIPv4
		} else {
			txInnerHashValid = false
		}
		placement := frame.CryptoPlacement
		if placement == "" || placement == dataplane.CryptoPlacementAuto {
			placement = flow.CryptoPlacement
		}
		var sequence uint64
		var err error
		if useSequenceBatch {
			sequence, err = manager.reserveKernelUDPTXSequenceBatchLocked(&sequenceByFlow, &sequenceSingleFlow, &sequenceSingle, flowID, frame.Sequence, sequenceBatchCapacity)
		} else {
			sequence, err = manager.reserveKernelUDPTXSequenceLocked(flowID, frame.Sequence)
		}
		if err != nil {
			manager.mu.Unlock()
			return err
		}
		frame.Sequence = sequence
		if placement == dataplane.CryptoPlacementKernel {
			if !manager.kernelUDPKernelCryptoReadyLocked() {
				manager.kernelCryptoFrameRejects++
				manager.mu.Unlock()
				return fmt.Errorf("kernel_udp frame %d requested kernel crypto, but kernel crypto is not available: %s", flowID, manager.kernelUDPKernelCryptoUnavailableReasonLocked())
			}
			suite := frame.CryptoSuite
			if suite == "" {
				suite = flow.CryptoSuite
			}
			if suite == "" {
				suite = kernelCryptoSuiteAES256GCMX25519
			}
			suiteID, err := kernelCryptoSuiteID(suite)
			if err != nil {
				manager.kernelCryptoFrameRejects++
				manager.mu.Unlock()
				return fmt.Errorf("kernel_udp frame %d requested unsupported kernel crypto suite %q: %w", flowID, suite, err)
			}
			epoch := frame.Epoch
			if epoch == 0 {
				epoch = flow.Epoch
			}
			flags |= kerneludp.FlagEncrypted
			pending := kernelUDPSealPendingBatchFor(&pendingSealByFlow, &pendingSealSingleFlow, &pendingSealSingle, flowID, len(frames))
			pending.indexes = append(pending.indexes, len(prepared))
			pending.requests = append(pending.requests, kernelCryptoDeviceSealRequest{
				FlowID:   flowID,
				SuiteID:  suiteID,
				Epoch:    epoch,
				Sequence: frame.Sequence,
				Plain:    payload,
			})
		}
		packet := cachedPacket
		dst := cachedDst
		if !cachedPacketOK {
			packet, dst, flow, err = manager.prepareKernelUDPPacketForFlowLocked(flowID, flow)
			if err != nil {
				manager.mu.Unlock()
				return err
			}
			cachedFlow = flow
			cachedPacket = packet
			cachedDst = dst
			cachedPacketOK = true
		}
		fragmentPayload := frame.FragmentPayloadSize
		var frameWireLen int
		var packetWireLen int
		if fragmentPayload <= 0 || payloadLen <= fragmentPayload {
			frameWireLen, err = kerneludp.FrameWireLen(payloadLen)
			if err != nil {
				manager.mu.Unlock()
				return err
			}
			packetWireLen, err = kerneludp.UDPIPv4WireLen(frameWireLen)
			if err != nil {
				manager.mu.Unlock()
				return err
			}
		}
		var sourceIP4 [4]byte
		var destinationIP4 [4]byte
		if packet.SourceIP.Is4() && packet.DestinationIP.Is4() {
			sourceIP4 = packet.SourceIP.As4()
			destinationIP4 = packet.DestinationIP.As4()
		}
		prepared = append(prepared, preparedKernelUDPTXFrame{
			packet: packet,
			wireFrame: kerneludp.Frame{
				Flags:         flags,
				FlowID:        flowID,
				Sequence:      sequence,
				FragmentIndex: frame.FragmentIndex,
				FragmentCount: frame.FragmentCount,
				Payload:       payload,
			},
			flow:             flow,
			bytes:            payloadLen,
			rawDst:           dst,
			sourceIP4:        sourceIP4,
			destinationIP4:   destinationIP4,
			sourcePort:       packet.SourcePort,
			destinationPort:  packet.DestinationPort,
			frameWireLen:     frameWireLen,
			packetWireLen:    packetWireLen,
			fragmentPayload:  fragmentPayload,
			txInnerHash:      txInnerHash,
			txInnerHashValid: txInnerHashValid,
		})
	}
	if useSequenceBatch {
		if err := manager.flushKernelUDPTXSequenceBatchesLocked(sequenceByFlow, sequenceSingle); err != nil {
			manager.mu.Unlock()
			return err
		}
	}
	manager.mu.Unlock()
	releaseSealed, err := manager.sealPreparedKernelUDPFrames(prepared, pendingSealByFlow, pendingSealSingleFlow, pendingSealSingle)
	if err != nil {
		return err
	}
	prepared, err = splitPreparedKernelUDPFrames(prepared)
	if err != nil {
		if releaseSealed != nil {
			releaseSealed()
		}
		return err
	}
	sent, err := manager.sendRawKernelUDPPreparedFrames(prepared)
	if releaseSealed != nil {
		releaseSealed()
	}
	if sent > 0 {
		manager.mu.Lock()
		now := time.Now().UTC()
		manager.observeKernelUDPTXBatchLocked(prepared[:sent], now)
		manager.kernelUDPRawTXFrames += uint64(sent)
		manager.kernelUDPRawTXBatches++
		manager.mu.Unlock()
	}
	if err != nil {
		manager.mu.Lock()
		manager.recordExperimentalTCPDropLocked(err)
		manager.mu.Unlock()
		return err
	}
	return nil
}

func (manager *Manager) sealPreparedExperimentalTCPFrames(prepared []preparedExperimentalTCPTXFrame, pendingByFlow map[uint64]*pendingKernelUDPSealBatch, singleFlowID uint64, single *pendingKernelUDPSealBatch) (func(), error) {
	if len(pendingByFlow) == 0 && (single == nil || len(single.requests) == 0) {
		return nil, nil
	}
	var releases []func()
	releaseAll := func() {
		for i := len(releases) - 1; i >= 0; i-- {
			if releases[i] != nil {
				releases[i]()
			}
		}
	}
	processPending := func(flowID uint64, pending *pendingKernelUDPSealBatch) error {
		if pending == nil || len(pending.requests) == 0 {
			return nil
		}
		var device *kernelCryptoDevice
		var provider *kernelCryptoProviderObject
		manager.mu.Lock()
		device = manager.kernelCryptoDeviceForFlowLocked(kernelCryptoNamespaceExperimentalTCP, flowID)
		provider = manager.kernelCryptoProvider
		manager.mu.Unlock()
		for start := 0; start < len(pending.requests); {
			end := min(start+kernelCryptoDeviceBatchMax, len(pending.requests))
			requests := pending.requests[start:end]
			indexes := pending.indexes[start:end]
			if device != nil {
				manager.mu.Lock()
				manager.kernelCryptoDeviceSealAttempts += uint64(len(requests))
				manager.observeKernelCryptoDeviceSealBatchLocked(requests)
				manager.mu.Unlock()
				var sealed [][]byte
				var release func()
				var err error
				if len(requests) >= device.poolMinBatchConfigured() {
					manager.mu.Lock()
					manager.kernelCryptoDeviceSealBorrowAttempts += uint64(len(requests))
					manager.mu.Unlock()
					sealed, release, err = device.SealBatchBorrowed(requests)
					if err != nil {
						manager.mu.Lock()
						manager.kernelCryptoDeviceSealBorrowFallbacks += uint64(len(requests))
						manager.mu.Unlock()
					}
				}
				if sealed == nil {
					sealed, err = device.SealBatch(requests)
					release = nil
				}
				if err == nil {
					if release != nil {
						releases = append(releases, release)
						manager.mu.Lock()
						manager.kernelCryptoDeviceSealBorrowSuccesses += uint64(len(sealed))
						manager.mu.Unlock()
					}
					manager.mu.Lock()
					manager.kernelCryptoDeviceSealSuccesses += uint64(len(sealed))
					manager.kernelCryptoFrameSealSuccesses += uint64(len(sealed))
					manager.mu.Unlock()
					for i, payload := range sealed {
						if err := updatePreparedExperimentalTCPPayload(&prepared[indexes[i]], payload); err != nil {
							releaseAll()
							return err
						}
					}
					start = end
					continue
				}
				manager.mu.Lock()
				manager.kernelCryptoDeviceSealErrors += uint64(len(requests))
				manager.mu.Unlock()
			}
			for i, request := range requests {
				manager.mu.Lock()
				if provider == nil {
					manager.kernelCryptoFrameSealErrors++
					manager.mu.Unlock()
					releaseAll()
					return fmt.Errorf("experimental_tcp kernel crypto provider is not available")
				}
				sealed, err := provider.SealFrame(
					kernelCryptoFlowKeyFor(kernelCryptoNamespaceExperimentalTCP, request.FlowID, kernelCryptoDirectionSend),
					request.SuiteID,
					request.Epoch,
					request.Sequence,
					request.Plain,
				)
				if err != nil {
					manager.kernelCryptoFrameSealErrors++
					manager.mu.Unlock()
					releaseAll()
					return err
				}
				manager.kernelCryptoFrameSealSuccesses++
				manager.mu.Unlock()
				if err := updatePreparedExperimentalTCPPayload(&prepared[indexes[i]], sealed); err != nil {
					releaseAll()
					return err
				}
			}
			start = end
		}
		return nil
	}
	if len(pendingByFlow) == 0 {
		if err := processPending(singleFlowID, single); err != nil {
			return nil, err
		}
		return releaseAll, nil
	}
	for flowID, pending := range pendingByFlow {
		if err := processPending(flowID, pending); err != nil {
			return nil, err
		}
	}
	return releaseAll, nil
}

func updatePreparedExperimentalTCPPayload(frame *preparedExperimentalTCPTXFrame, payload []byte) error {
	frame.wireFrame.Payload = payload
	frame.wireFrame.Flags |= experimentaltcp.FlagEncrypted
	if frame.fragmentPayload > 0 && len(payload) > frame.fragmentPayload {
		frame.frameLen = 0
		frame.packetLen = 0
		frame.tcpSeqLen = 0
		return nil
	}
	frameLen, err := experimentaltcp.FrameWireLen(len(payload))
	if err != nil {
		return err
	}
	packetLen, err := experimentaltcp.TCPShapedIPv4WireLen(frameLen)
	if err != nil {
		return err
	}
	frame.frameLen = frameLen
	frame.packetLen = packetLen
	frame.tcpSeqLen = frameLen
	return nil
}

func splitPreparedExperimentalTCPFrames(frames []preparedExperimentalTCPTXFrame) ([]preparedExperimentalTCPTXFrame, error) {
	var out []preparedExperimentalTCPTXFrame
	for frameIndex, frame := range frames {
		payload := frame.wireFrame.Payload
		fragmentPayload := frame.fragmentPayload
		if fragmentPayload <= 0 || len(payload) <= fragmentPayload {
			if out != nil {
				out = append(out, frame)
			}
			continue
		}
		if frame.wireFrame.Flags&experimentaltcp.FlagEncrypted == 0 {
			return nil, fmt.Errorf("experimental_tcp post-seal fragment requested for unencrypted frame")
		}
		count := (len(payload) + fragmentPayload - 1) / fragmentPayload
		if count <= 1 {
			if out != nil {
				out = append(out, frame)
			}
			continue
		}
		if count > 256 {
			return nil, fmt.Errorf("experimental_tcp sealed packet size %d requires %d fragments, max 256", len(payload), count)
		}
		if out == nil {
			out = make([]preparedExperimentalTCPTXFrame, 0, len(frames)+count-1)
			for _, previous := range frames[:frameIndex] {
				out = append(out, previous)
			}
		}
		for index, start := 0, 0; start < len(payload); index, start = index+1, start+fragmentPayload {
			end := min(start+fragmentPayload, len(payload))
			fragment := frame
			fragment.wireFrame.Flags = fragment.wireFrame.Flags | experimentaltcp.FlagEncrypted | experimentaltcp.FlagCryptoFragment
			fragment.wireFrame.Sequence = frame.wireFrame.Sequence + uint64(index)
			fragment.wireFrame.FragmentIndex = uint16(index)
			fragment.wireFrame.FragmentCount = uint16(count)
			fragment.wireFrame.Payload = payload[start:end]
			fragment.fragmentPayload = 0
			if index > 0 {
				fragment.bytes = 0
			}
			frameLen, err := experimentaltcp.FrameWireLen(len(fragment.wireFrame.Payload))
			if err != nil {
				return nil, err
			}
			packetLen, err := experimentaltcp.TCPShapedIPv4WireLen(frameLen)
			if err != nil {
				return nil, err
			}
			fragment.frameLen = frameLen
			fragment.packetLen = packetLen
			fragment.tcpSeqLen = frameLen
			out = append(out, fragment)
		}
	}
	if out == nil {
		return frames, nil
	}
	return out, nil
}

func kernelUDPInnerIPv4Eligible(packet []byte) bool {
	if len(packet) < rejectIPv4HeaderLen || len(packet) > kerneludp.MaxPayload {
		return false
	}
	if packet[0]>>4 != 4 {
		return false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < rejectIPv4HeaderLen || ihl > len(packet) {
		return false
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	return totalLen == len(packet)
}

func splitPreparedKernelUDPFrames(frames []preparedKernelUDPTXFrame) ([]preparedKernelUDPTXFrame, error) {
	var out []preparedKernelUDPTXFrame
	for frameIndex, frame := range frames {
		payload := frame.wireFrame.Payload
		fragmentPayload := frame.fragmentPayload
		if fragmentPayload <= 0 || len(payload) <= fragmentPayload {
			if out != nil {
				out = append(out, frame)
			}
			continue
		}
		count := (len(payload) + fragmentPayload - 1) / fragmentPayload
		if count <= 1 {
			if out != nil {
				out = append(out, frame)
			}
			continue
		}
		if count > 256 {
			return nil, fmt.Errorf("kernel_udp sealed packet size %d requires %d fragments, max 256", len(payload), count)
		}
		if out == nil {
			out = make([]preparedKernelUDPTXFrame, 0, len(frames)+count-1)
			for _, previous := range frames[:frameIndex] {
				out = append(out, previous)
			}
		}
		for index, start := 0, 0; start < len(payload); index, start = index+1, start+fragmentPayload {
			end := min(start+fragmentPayload, len(payload))
			fragment := frame
			fragment.wireFrame.Flags = fragment.wireFrame.Flags | kerneludp.FlagEncrypted | kerneludp.FlagCryptoFragment
			fragment.wireFrame.Sequence = frame.wireFrame.Sequence + uint64(index)
			fragment.wireFrame.FragmentIndex = uint16(index)
			fragment.wireFrame.FragmentCount = uint16(count)
			fragment.wireFrame.Payload = payload[start:end]
			fragment.fragmentPayload = 0
			if index > 0 {
				fragment.bytes = 0
			}
			frameWireLen, err := kerneludp.FrameWireLen(len(fragment.wireFrame.Payload))
			if err != nil {
				return nil, err
			}
			packetWireLen, err := kerneludp.UDPIPv4WireLen(frameWireLen)
			if err != nil {
				return nil, err
			}
			fragment.frameWireLen = frameWireLen
			fragment.packetWireLen = packetWireLen
			out = append(out, fragment)
		}
	}
	if out == nil {
		return frames, nil
	}
	return out, nil
}

func (manager *Manager) SubscribeKernelUDP(ctx context.Context, buffer int) (dataplane.KernelUDPSubscription, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if buffer <= 0 {
		buffer = 256
	}
	manager.mu.Lock()
	if !manager.experimentalTCPFastPathAvailableLocked() && !kernelUDPRawFallbackEnabled() {
		manager.mu.Unlock()
		return nil, fmt.Errorf("UDP AF_XDP kernel transport provider is not available")
	}
	if err := manager.startKernelUDPRawReceiverLocked(); err != nil {
		manager.mu.Unlock()
		return nil, err
	}
	events := make(chan []dataplane.KernelUDPFrame, buffer)
	subscription := &kernelUDPSubscription{manager: manager, events: events}
	manager.kernelUDPSubs[events] = struct{}{}
	manager.mu.Unlock()
	return subscription, nil
}

func (manager *Manager) SubscribeKernelUDPFlow(ctx context.Context, flowID uint64, buffer int) (dataplane.KernelUDPSubscription, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if flowID == 0 {
		return nil, fmt.Errorf("kernel_udp flow subscription requires a non-zero flow id")
	}
	if buffer <= 0 {
		buffer = 256
	}
	manager.mu.Lock()
	if !manager.experimentalTCPFastPathAvailableLocked() && !kernelUDPRawFallbackEnabled() {
		manager.mu.Unlock()
		return nil, fmt.Errorf("kernel_udp provider is not available")
	}
	if err := manager.startKernelUDPRawReceiverLocked(); err != nil {
		manager.mu.Unlock()
		return nil, err
	}
	events := make(chan []dataplane.KernelUDPFrame, buffer)
	subscription := &kernelUDPSubscription{manager: manager, events: events, flowID: flowID}
	if manager.kernelUDPFlowSubs == nil {
		manager.kernelUDPFlowSubs = make(map[uint64]map[chan []dataplane.KernelUDPFrame]struct{})
	}
	subs := manager.kernelUDPFlowSubs[flowID]
	if subs == nil {
		subs = make(map[chan []dataplane.KernelUDPFrame]struct{})
		manager.kernelUDPFlowSubs[flowID] = subs
	}
	subs[events] = struct{}{}
	manager.mu.Unlock()
	return subscription, nil
}

func (manager *Manager) InstallExperimentalTCPCrypto(ctx context.Context, specs []dataplane.ExperimentalTCPCryptoSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(specs) == 0 {
		return nil
	}
	entries, err := encodeKernelCryptoSpecs(specs)
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.kernelCryptoInstallAttempts++
	if err != nil {
		manager.kernelCryptoSpecValidateErrors++
		manager.kernelCryptoSpecsRejected += uint64(len(specs))
		return err
	}
	manager.kernelCryptoSpecsValidated += uint64(len(specs))
	manager.kernelCryptoEntriesEncoded += uint64(len(entries))
	defer zeroKernelCryptoEntries(entries)
	if !manager.experimentalTCPKernelCryptoReadyLocked() || (manager.kernelCryptoFlowMap == nil && !manager.kernelCryptoDeviceAvailableLocked(kernelCryptoNamespaceExperimentalTCP)) {
		reason := manager.experimentalTCPKernelCryptoUnavailableReasonLocked()
		manager.kernelCryptoProviderUnavailableErrors++
		manager.kernelCryptoSpecsRejected += uint64(len(specs))
		return fmt.Errorf("experimental_tcp kernel crypto provider is not available: %s", reason)
	}
	providerInstalled := false
	if (manager.kernelCryptoProductionReadyLocked() || manager.kernelCryptoDirectSlotProviderReadyLocked()) && manager.kernelCryptoFlowMap != nil {
		installEntries, err := manager.prepareKernelCryptoProviderInstallEntriesLocked(entries)
		if err != nil {
			manager.kernelCryptoSpecsRejected += uint64(len(specs))
			return err
		}
		if manager.kernelCryptoProductionReadyLocked() {
			if err := manager.kernelCryptoProvider.InstallAt(installEntries); err != nil {
				manager.rollbackKernelCryptoProviderInstallLocked(entries)
				manager.kernelCryptoSpecsRejected += uint64(len(specs))
				return err
			}
			manager.syncKernelCryptoDirectSlotsLocked(installEntries)
			if err := manager.stageKernelCryptoEntriesLocked(entries); err != nil {
				manager.rollbackKernelCryptoProviderInstallLocked(entries)
				manager.kernelCryptoSpecsRejected += uint64(len(specs))
				return err
			}
			providerInstalled = true
		} else {
			installed, err := manager.installKernelCryptoDirectOnlyLocked(entries)
			if err != nil {
				manager.kernelCryptoSpecsRejected += uint64(len(specs))
				return err
			}
			providerInstalled = installed
		}
	}
	manager.installKernelCryptoDevicesLocked(kernelCryptoNamespaceExperimentalTCP, entries)
	if !providerInstalled && !manager.hasKernelCryptoDeviceForEntriesLocked(kernelCryptoNamespaceExperimentalTCP, entries) {
		manager.kernelCryptoProviderUnavailableErrors++
		manager.kernelCryptoSpecsRejected += uint64(len(specs))
		return fmt.Errorf("experimental_tcp kernel crypto device could not be opened")
	}
	if manager.expTCPFlows == nil {
		manager.expTCPFlows = make(map[uint64]dataplane.ExperimentalTCPFlow, len(specs))
	}
	for _, spec := range specs {
		flow := manager.expTCPFlows[spec.FlowID]
		flow.ID = spec.FlowID
		flow.Epoch = spec.Epoch
		flow.CryptoSuite = spec.Suite
		flow.CryptoPlacement = dataplane.CryptoPlacementKernel
		manager.expTCPFlows[spec.FlowID] = flow
		manager.invalidateExperimentalTCPTXTemplateLocked(spec.FlowID)
	}
	if err := manager.syncKernelUDPTXDirectLocked(); err != nil {
		return err
	}
	if err := manager.ensureKernelUDPRXSecureDirectLocked(); err != nil {
		manager.warnings = append(manager.warnings, "kernel_udp secure TC RX direct disabled: "+err.Error())
	}
	if err := manager.syncKernelUDPRXDirectConfigLocked(); err != nil {
		manager.warnings = append(manager.warnings, "kernel_udp XDP TC RX direct config sync failed: "+err.Error())
	}
	return nil
}

func (manager *Manager) SubmitExperimentalTCPFrame(ctx context.Context, frame dataplane.ExperimentalTCPFrame) error {
	manager.mu.Lock()

	if err := ctx.Err(); err != nil {
		manager.mu.Unlock()
		return err
	}
	if manager.pruneExperimentalTCPFlowsLocked(time.Now().UTC()) {
		_ = manager.syncExperimentalTCPPortsLocked()
	}
	fastPath := manager.experimentalTCPProviderFastPathAvailableLocked()
	rawFallback := experimentalTCPRawFallbackEnabled()
	if !fastPath && !rawFallback {
		manager.recordDropLocked(observability.DropEndpointDown)
		manager.mu.Unlock()
		if reason := manager.experimentalTCPFastPathDisabledReasonLocked(); reason != "" {
			return fmt.Errorf("experimental_tcp TC/XDP provider is disabled: %s", reason)
		}
		return fmt.Errorf("experimental_tcp TC/XDP provider is not available; raw socket fallback is disabled")
	}
	flow, ok := manager.expTCPFlows[frame.FlowID]
	if !ok {
		manager.recordDropLocked(observability.DropFlowNotInstalled)
		manager.mu.Unlock()
		return fmt.Errorf("experimental_tcp flow %d is not installed", frame.FlowID)
	}
	payload := frame.Payload
	payloadLen := len(payload)
	encrypted := frame.Encrypted
	innerIPv4 := frame.InnerIPv4 && frame.FragmentIndex == 0 && frame.FragmentCount == 0 && kernelUDPInnerIPv4Eligible(payload)
	epoch := frame.Epoch
	if epoch == 0 {
		epoch = flow.Epoch
	}
	if frame.CryptoPlacement == dataplane.CryptoPlacementKernel {
		sequence, err := manager.reserveKernelUDPTXSequenceLocked(frame.FlowID, frame.Sequence)
		if err != nil {
			manager.mu.Unlock()
			return err
		}
		frame.Sequence = sequence
		if !manager.experimentalTCPKernelCryptoReadyLocked() {
			manager.kernelCryptoFrameRejects++
			manager.mu.Unlock()
			return fmt.Errorf("experimental_tcp frame %d requested kernel crypto, but kernel crypto is not available: %s", frame.FlowID, manager.experimentalTCPKernelCryptoUnavailableReasonLocked())
		}
		manager.kernelCryptoFrameSealAttempts++
		if device := manager.kernelCryptoDeviceForFlowLocked(kernelCryptoNamespaceExperimentalTCP, frame.FlowID); device != nil {
			suite := frame.CryptoSuite
			if suite == "" {
				suite = flow.CryptoSuite
			}
			if suite == "" {
				suite = kernelCryptoSuiteAES256GCMX25519
			}
			suiteID, err := kernelCryptoSuiteID(suite)
			if err != nil {
				manager.kernelCryptoFrameSealErrors++
				manager.mu.Unlock()
				return fmt.Errorf("experimental_tcp frame %d requested unsupported kernel crypto suite %q: %w", frame.FlowID, suite, err)
			}
			requests := []kernelCryptoDeviceSealRequest{{
				FlowID:   frame.FlowID,
				SuiteID:  suiteID,
				Epoch:    epoch,
				Sequence: uint64(frame.Sequence),
				Plain:    payload,
			}}
			manager.kernelCryptoDeviceSealAttempts++
			manager.observeKernelCryptoDeviceSealBatchLocked(requests)
			sealed, err := device.SealBatch(requests)
			if err != nil {
				manager.kernelCryptoDeviceSealErrors++
				manager.kernelCryptoFrameSealErrors++
				manager.mu.Unlock()
				return err
			}
			manager.kernelCryptoDeviceSealSuccesses++
			manager.kernelCryptoFrameSealSuccesses++
			payload = sealed[0]
			encrypted = true
		} else if fastPath && manager.expTCPFastPath != nil && manager.expTCPFastPath.kernelCryptoTX &&
			manager.kernelCryptoProviderHasFlowLocked(kernelCryptoNamespaceExperimentalTCP, frame.FlowID, kernelCryptoDirectionSend) {
			packet, _, err := manager.prepareExperimentalTCPPacketLocked(frame.FlowID, frame.Sequence)
			if err != nil {
				manager.kernelCryptoFrameSealErrors++
				manager.mu.Unlock()
				return err
			}
			flags := experimentalTCPFrameFlags(false)
			if innerIPv4 {
				flags |= experimentaltcp.FlagInnerIPv4
			}
			wireFrame := experimentaltcp.Frame{
				Flags:         flags,
				FlowID:        frame.FlowID,
				Epoch:         epoch,
				Sequence:      uint64(frame.Sequence),
				FragmentIndex: frame.FragmentIndex,
				FragmentCount: frame.FragmentCount,
				Payload:       payload,
			}
			frameLen, err := experimentaltcp.FrameWireLen(len(payload))
			if err != nil {
				manager.kernelCryptoFrameSealErrors++
				manager.mu.Unlock()
				return err
			}
			packet.Sequence = manager.reserveExperimentalTCPOuterSequenceLocked(frame.FlowID, frameLen)
			fastPathProvider := manager.expTCPFastPath
			manager.mu.Unlock()
			if err := fastPathProvider.SendKernelCryptoFrame(packet, wireFrame, manager.resolveIPv4Neighbor); err != nil {
				manager.mu.Lock()
				manager.kernelCryptoFrameSealErrors++
				manager.recordExperimentalTCPDropLocked(err)
				manager.mu.Unlock()
				return err
			}
			manager.mu.Lock()
			manager.kernelCryptoFrameSealSuccesses++
			telemetryFlow := flow
			if latest, ok := manager.expTCPFlows[frame.FlowID]; ok {
				telemetryFlow = latest
			}
			manager.experimentalTCPTelemetryLocked(frame.FlowID, telemetryFlow).ObserveTX(payloadLen, time.Now().UTC())
			manager.expTCPSubmitted++
			manager.mu.Unlock()
			return nil
		} else {
			if !manager.kernelCryptoProductionReadyLocked() {
				manager.kernelCryptoFrameSealErrors++
				manager.mu.Unlock()
				return fmt.Errorf("experimental_tcp frame %d requested kernel crypto, but BPF provider is not available: %s", frame.FlowID, manager.kernelCryptoUnavailableReasonLocked())
			}
			suite := frame.CryptoSuite
			if suite == "" {
				suite = flow.CryptoSuite
			}
			if suite == "" {
				suite = kernelCryptoSuiteAES256GCMX25519
			}
			suiteID, err := kernelCryptoSuiteID(suite)
			if err != nil {
				manager.kernelCryptoFrameSealErrors++
				manager.mu.Unlock()
				return fmt.Errorf("experimental_tcp frame %d requested unsupported kernel crypto suite %q: %w", frame.FlowID, suite, err)
			}
			sealed, err := manager.kernelCryptoProvider.SealFrame(kernelCryptoFlowKeyFor(kernelCryptoNamespaceExperimentalTCP, frame.FlowID, kernelCryptoDirectionSend), suiteID, epoch, uint64(frame.Sequence), payload)
			if err != nil {
				manager.kernelCryptoFrameSealErrors++
				manager.mu.Unlock()
				return err
			}
			manager.kernelCryptoFrameSealSuccesses++
			payload = sealed
			encrypted = true
		}
	}
	flags := experimentalTCPFrameFlags(encrypted)
	if innerIPv4 {
		flags |= experimentaltcp.FlagInnerIPv4
	}
	wireFrame := experimentaltcp.Frame{
		Flags:         flags,
		FlowID:        frame.FlowID,
		Epoch:         epoch,
		Sequence:      uint64(frame.Sequence),
		FragmentIndex: frame.FragmentIndex,
		FragmentCount: frame.FragmentCount,
		Payload:       payload,
	}
	if fastPath {
		packet, _, err := manager.prepareExperimentalTCPPacketLocked(frame.FlowID, frame.Sequence)
		if err != nil {
			manager.mu.Unlock()
			return err
		}
		frameLen, err := experimentaltcp.FrameWireLen(len(payload))
		if err != nil {
			manager.mu.Unlock()
			return err
		}
		packet.Sequence = manager.reserveExperimentalTCPOuterSequenceLocked(frame.FlowID, frameLen)
		fastPathProvider := manager.expTCPFastPath
		manager.mu.Unlock()
		if err := fastPathProvider.SendFrame(packet, wireFrame, manager.resolveIPv4Neighbor); err != nil {
			manager.mu.Lock()
			manager.recordExperimentalTCPDropLocked(err)
			manager.mu.Unlock()
			return err
		}
	} else {
		wire, err := wireFrame.MarshalBinary()
		if err != nil {
			manager.mu.Unlock()
			return err
		}
		packet, dst, err := manager.buildExperimentalTCPPacketLocked(frame.FlowID, frame.Sequence, wire)
		if err != nil {
			manager.mu.Unlock()
			return err
		}
		manager.mu.Unlock()
		if err := sendRawIPv4(packet, dst); err != nil {
			return err
		}
	}
	manager.mu.Lock()
	telemetryFlow := flow
	if latest, ok := manager.expTCPFlows[frame.FlowID]; ok {
		telemetryFlow = latest
	}
	manager.experimentalTCPTelemetryLocked(frame.FlowID, telemetryFlow).ObserveTX(payloadLen, time.Now().UTC())
	manager.expTCPSubmitted++
	manager.mu.Unlock()
	return nil
}

func (manager *Manager) SubmitExperimentalTCPFrames(ctx context.Context, frames []dataplane.ExperimentalTCPFrame) error {
	if len(frames) == 0 {
		return ctx.Err()
	}
	manager.mu.Lock()
	if err := ctx.Err(); err != nil {
		manager.mu.Unlock()
		return err
	}
	if manager.pruneExperimentalTCPFlowsLocked(time.Now().UTC()) {
		_ = manager.syncExperimentalTCPPortsLocked()
	}
	fastPath := manager.experimentalTCPProviderFastPathAvailableLocked()
	if !fastPath {
		if experimentalTCPRawFallbackEnabled() {
			return manager.submitExperimentalTCPFramesRawFallbackLocked(ctx, frames)
		}
		manager.mu.Unlock()
		for _, frame := range frames {
			if err := manager.SubmitExperimentalTCPFrame(ctx, frame); err != nil {
				return err
			}
		}
		return nil
	}
	preparedHolder, prepared := takePreparedExperimentalTCPTXFrames(len(frames))
	defer func() {
		putPreparedExperimentalTCPTXFrames(preparedHolder, prepared)
	}()
	var pendingSealByFlow map[uint64]*pendingKernelUDPSealBatch
	var pendingSealSingleFlow uint64
	var pendingSealSingle *pendingKernelUDPSealBatch
	var sequenceByFlow map[uint64]*kernelUDPTXSequenceBatch
	var sequenceSingleFlow uint64
	var sequenceSingle *kernelUDPTXSequenceBatch
	useSequenceBatch := kernelUDPTXSequenceBatchEnabled()
	sequenceBatchCapacity := len(frames)
	if sequenceBatchCapacity > 64 {
		sequenceBatchCapacity = 64
	}
	var cachedFlowID uint64
	var cachedFlow dataplane.ExperimentalTCPFlow
	var cachedPacket experimentaltcp.TCPPacket
	var cachedFlowOK bool
	var cachedPacketOK bool
	for frameIndex, frame := range frames {
		flowID := frame.FlowID
		flow := cachedFlow
		if !cachedFlowOK || flowID != cachedFlowID {
			var ok bool
			flow, ok = manager.expTCPFlows[flowID]
			if !ok {
				manager.recordDropLocked(observability.DropFlowNotInstalled)
				manager.mu.Unlock()
				return fmt.Errorf("experimental_tcp flow %d is not installed", flowID)
			}
			cachedFlowID = flowID
			cachedFlow = flow
			cachedFlowOK = true
			cachedPacketOK = false
		}
		payload := frame.Payload
		payloadLen := len(payload)
		fragmentPayload := frame.FragmentPayloadSize
		encrypted := frame.Encrypted
		innerIPv4 := frame.InnerIPv4 && frame.FragmentIndex == 0 && frame.FragmentCount == 0 && kernelUDPInnerIPv4Eligible(payload)
		txInnerHash, txInnerHashValid := innerIPv4TXHash(payload)
		if !innerIPv4 {
			txInnerHash, txInnerHashValid = dataSessionBatchFirstInnerIPv4TXHash(payload)
		}
		if !txInnerHashValid && frame.FragmentCount > 1 {
			txInnerHash, txInnerHashValid = fragmentedExperimentalTCPInnerHash(frames, frameIndex)
		}
		epoch := frame.Epoch
		if epoch == 0 {
			epoch = flow.Epoch
		}
		kernelTX := false
		if frame.CryptoPlacement == dataplane.CryptoPlacementKernel {
			var sequence uint64
			var err error
			if useSequenceBatch {
				sequence, err = manager.reserveKernelUDPTXSequenceBatchLocked(&sequenceByFlow, &sequenceSingleFlow, &sequenceSingle, flowID, frame.Sequence, sequenceBatchCapacity)
			} else {
				sequence, err = manager.reserveKernelUDPTXSequenceLocked(flowID, frame.Sequence)
			}
			if err != nil {
				manager.mu.Unlock()
				return err
			}
			frame.Sequence = sequence
			if !manager.experimentalTCPKernelCryptoReadyLocked() {
				manager.kernelCryptoFrameRejects++
				manager.mu.Unlock()
				return fmt.Errorf("experimental_tcp frame %d requested kernel crypto, but kernel crypto is not available: %s", flowID, manager.experimentalTCPKernelCryptoUnavailableReasonLocked())
			}
			manager.kernelCryptoFrameSealAttempts++
			deviceAvailable := manager.kernelCryptoDeviceForFlowLocked(kernelCryptoNamespaceExperimentalTCP, flowID) != nil
			if deviceAvailable || fragmentPayload > 0 {
				if !deviceAvailable && !manager.kernelCryptoProductionReadyLocked() {
					manager.kernelCryptoFrameSealErrors++
					manager.mu.Unlock()
					return fmt.Errorf("experimental_tcp frame %d requested seal-before-fragment, but BPF provider is not available: %s", flowID, manager.kernelCryptoUnavailableReasonLocked())
				}
				suite := frame.CryptoSuite
				if suite == "" {
					suite = flow.CryptoSuite
				}
				if suite == "" {
					suite = kernelCryptoSuiteAES256GCMX25519
				}
				suiteID, err := kernelCryptoSuiteID(suite)
				if err != nil {
					manager.kernelCryptoFrameSealErrors++
					manager.mu.Unlock()
					return fmt.Errorf("experimental_tcp frame %d requested unsupported kernel crypto suite %q: %w", flowID, suite, err)
				}
				encrypted = true
				pending := kernelUDPSealPendingBatchFor(&pendingSealByFlow, &pendingSealSingleFlow, &pendingSealSingle, flowID, len(frames))
				pending.indexes = append(pending.indexes, len(prepared))
				pending.requests = append(pending.requests, kernelCryptoDeviceSealRequest{
					FlowID:   flowID,
					SuiteID:  suiteID,
					Epoch:    epoch,
					Sequence: uint64(frame.Sequence),
					Plain:    payload,
				})
			} else if manager.expTCPFastPath != nil && manager.expTCPFastPath.kernelCryptoTX &&
				manager.kernelCryptoProviderHasFlowLocked(kernelCryptoNamespaceExperimentalTCP, flowID, kernelCryptoDirectionSend) {
				kernelTX = true
			} else {
				if !manager.kernelCryptoProductionReadyLocked() {
					manager.kernelCryptoFrameSealErrors++
					manager.mu.Unlock()
					return fmt.Errorf("experimental_tcp frame %d requested kernel crypto, but BPF provider is not available: %s", flowID, manager.kernelCryptoUnavailableReasonLocked())
				}
				suite := frame.CryptoSuite
				if suite == "" {
					suite = flow.CryptoSuite
				}
				if suite == "" {
					suite = kernelCryptoSuiteAES256GCMX25519
				}
				suiteID, err := kernelCryptoSuiteID(suite)
				if err != nil {
					manager.kernelCryptoFrameSealErrors++
					manager.mu.Unlock()
					return fmt.Errorf("experimental_tcp frame %d requested unsupported kernel crypto suite %q: %w", flowID, suite, err)
				}
				sealed, err := manager.kernelCryptoProvider.SealFrame(kernelCryptoFlowKeyFor(kernelCryptoNamespaceExperimentalTCP, flowID, kernelCryptoDirectionSend), suiteID, epoch, uint64(frame.Sequence), payload)
				if err != nil {
					manager.kernelCryptoFrameSealErrors++
					manager.mu.Unlock()
					return err
				}
				manager.kernelCryptoFrameSealSuccesses++
				payload = sealed
				encrypted = true
			}
		}
		packet := cachedPacket
		if !cachedPacketOK {
			var err error
			packet, _, err = manager.prepareExperimentalTCPPacketLocked(flowID, frame.Sequence)
			if err != nil {
				if kernelTX {
					manager.kernelCryptoFrameSealErrors++
				}
				manager.mu.Unlock()
				return err
			}
			if latest, ok := manager.expTCPFlows[flowID]; ok {
				flow = latest
				cachedFlow = flow
			}
			cachedPacket = packet
			cachedPacketOK = true
		}
		flags := experimentalTCPFrameFlags(encrypted)
		if kernelTX {
			flags = 0
		}
		if innerIPv4 {
			flags |= experimentaltcp.FlagInnerIPv4
		}
		var frameLen int
		var packetLen int
		if fragmentPayload <= 0 || len(payload) <= fragmentPayload {
			var err error
			frameLen, err = experimentaltcp.FrameWireLen(len(payload))
			if err != nil {
				manager.mu.Unlock()
				return err
			}
			packetLen, err = experimentaltcp.TCPShapedIPv4WireLen(frameLen)
			if err != nil {
				manager.mu.Unlock()
				return err
			}
		}
		var sourceIP4 [4]byte
		var destinationIP4 [4]byte
		if packet.SourceIP.Is4() && packet.DestinationIP.Is4() {
			sourceIP4 = packet.SourceIP.As4()
			destinationIP4 = packet.DestinationIP.As4()
		}
		prepared = append(prepared, preparedExperimentalTCPTXFrame{
			packet: packet,
			wireFrame: experimentaltcp.Frame{
				Flags:         flags,
				FlowID:        flowID,
				Epoch:         epoch,
				Sequence:      uint64(frame.Sequence),
				FragmentIndex: frame.FragmentIndex,
				FragmentCount: frame.FragmentCount,
				Payload:       payload,
			},
			flow:             flow,
			bytes:            payloadLen,
			sourceIP4:        sourceIP4,
			destinationIP4:   destinationIP4,
			sourcePort:       packet.SourcePort,
			destinationPort:  packet.DestinationPort,
			frameLen:         frameLen,
			packetLen:        packetLen,
			tcpSeqLen:        frameLen,
			fragmentPayload:  fragmentPayload,
			txInnerHash:      txInnerHash,
			txInnerHashValid: txInnerHashValid,
			kernelTX:         kernelTX,
		})
	}
	if useSequenceBatch {
		if err := manager.flushKernelUDPTXSequenceBatchesLocked(sequenceByFlow, sequenceSingle); err != nil {
			manager.mu.Unlock()
			return err
		}
	}
	fastPathProvider := manager.expTCPFastPath
	manager.mu.Unlock()
	releaseSealed, err := manager.sealPreparedExperimentalTCPFrames(prepared, pendingSealByFlow, pendingSealSingleFlow, pendingSealSingle)
	if err != nil {
		return err
	}
	prepared, err = splitPreparedExperimentalTCPFrames(prepared)
	if err != nil {
		if releaseSealed != nil {
			releaseSealed()
		}
		return err
	}
	manager.mu.Lock()
	manager.assignExperimentalTCPOuterSequencesLocked(prepared)
	manager.mu.Unlock()
	if err := fastPathProvider.SendPreparedExperimentalTCPFrames(prepared, manager.resolveIPv4Neighbor); err != nil {
		if releaseSealed != nil {
			releaseSealed()
		}
		manager.mu.Lock()
		for _, item := range prepared {
			if item.kernelTX {
				manager.kernelCryptoFrameSealErrors++
			}
		}
		manager.recordExperimentalTCPDropLocked(err)
		manager.mu.Unlock()
		return err
	}
	if releaseSealed != nil {
		releaseSealed()
	}
	manager.mu.Lock()
	now := time.Now().UTC()
	manager.observeExperimentalTCPTXBatchLocked(prepared, now)
	manager.mu.Unlock()
	return nil
}

func (manager *Manager) submitExperimentalTCPFramesRawFallbackLocked(ctx context.Context, frames []dataplane.ExperimentalTCPFrame) error {
	if len(frames) == 0 {
		manager.mu.Unlock()
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		manager.mu.Unlock()
		return err
	}
	preparedHolder, prepared := takePreparedExperimentalTCPTXFrames(len(frames))
	defer func() {
		putPreparedExperimentalTCPTXFrames(preparedHolder, prepared)
	}()
	var pendingSealByFlow map[uint64]*pendingKernelUDPSealBatch
	var pendingSealSingleFlow uint64
	var pendingSealSingle *pendingKernelUDPSealBatch
	var sequenceByFlow map[uint64]*kernelUDPTXSequenceBatch
	var sequenceSingleFlow uint64
	var sequenceSingle *kernelUDPTXSequenceBatch
	useSequenceBatch := kernelUDPTXSequenceBatchEnabled()
	sequenceBatchCapacity := len(frames)
	if sequenceBatchCapacity > 64 {
		sequenceBatchCapacity = 64
	}
	var cachedFlowID uint64
	var cachedFlow dataplane.ExperimentalTCPFlow
	var cachedPacket experimentaltcp.TCPPacket
	var cachedDst [4]byte
	var cachedFlowOK bool
	var cachedPacketOK bool
	for _, frame := range frames {
		flowID := frame.FlowID
		flow := cachedFlow
		if !cachedFlowOK || flowID != cachedFlowID {
			var ok bool
			flow, ok = manager.expTCPFlows[flowID]
			if !ok {
				manager.recordDropLocked(observability.DropFlowNotInstalled)
				manager.mu.Unlock()
				return fmt.Errorf("experimental_tcp flow %d is not installed", flowID)
			}
			cachedFlowID = flowID
			cachedFlow = flow
			cachedFlowOK = true
			cachedPacketOK = false
		}
		payload := frame.Payload
		payloadLen := len(payload)
		fragmentPayload := frame.FragmentPayloadSize
		encrypted := frame.Encrypted
		innerIPv4 := frame.InnerIPv4 && frame.FragmentIndex == 0 && frame.FragmentCount == 0 && kernelUDPInnerIPv4Eligible(payload)
		epoch := frame.Epoch
		if epoch == 0 {
			epoch = flow.Epoch
		}
		if frame.CryptoPlacement == dataplane.CryptoPlacementKernel {
			var sequence uint64
			var err error
			if useSequenceBatch {
				sequence, err = manager.reserveKernelUDPTXSequenceBatchLocked(&sequenceByFlow, &sequenceSingleFlow, &sequenceSingle, flowID, frame.Sequence, sequenceBatchCapacity)
			} else {
				sequence, err = manager.reserveKernelUDPTXSequenceLocked(flowID, frame.Sequence)
			}
			if err != nil {
				manager.mu.Unlock()
				return err
			}
			frame.Sequence = sequence
			if !manager.experimentalTCPKernelCryptoReadyLocked() {
				manager.kernelCryptoFrameRejects++
				manager.mu.Unlock()
				return fmt.Errorf("experimental_tcp frame %d requested kernel crypto, but kernel crypto is not available: %s", flowID, manager.experimentalTCPKernelCryptoUnavailableReasonLocked())
			}
			manager.kernelCryptoFrameSealAttempts++
			suite := frame.CryptoSuite
			if suite == "" {
				suite = flow.CryptoSuite
			}
			if suite == "" {
				suite = kernelCryptoSuiteAES256GCMX25519
			}
			suiteID, err := kernelCryptoSuiteID(suite)
			if err != nil {
				manager.kernelCryptoFrameSealErrors++
				manager.mu.Unlock()
				return fmt.Errorf("experimental_tcp frame %d requested unsupported kernel crypto suite %q: %w", flowID, suite, err)
			}
			encrypted = true
			pending := kernelUDPSealPendingBatchFor(&pendingSealByFlow, &pendingSealSingleFlow, &pendingSealSingle, flowID, len(frames))
			pending.indexes = append(pending.indexes, len(prepared))
			pending.requests = append(pending.requests, kernelCryptoDeviceSealRequest{
				FlowID:   flowID,
				SuiteID:  suiteID,
				Epoch:    epoch,
				Sequence: uint64(frame.Sequence),
				Plain:    payload,
			})
		}
		packet := cachedPacket
		dst := cachedDst
		if !cachedPacketOK {
			var err error
			packet, dst, err = manager.prepareExperimentalTCPPacketLocked(flowID, frame.Sequence)
			if err != nil {
				manager.mu.Unlock()
				return err
			}
			if latest, ok := manager.expTCPFlows[flowID]; ok {
				flow = latest
				cachedFlow = flow
			}
			cachedPacket = packet
			cachedDst = dst
			cachedPacketOK = true
		}
		flags := experimentalTCPFrameFlags(encrypted)
		if innerIPv4 {
			flags |= experimentaltcp.FlagInnerIPv4
		}
		var frameLen int
		var packetLen int
		if fragmentPayload <= 0 || len(payload) <= fragmentPayload {
			var err error
			frameLen, err = experimentaltcp.FrameWireLen(len(payload))
			if err != nil {
				manager.mu.Unlock()
				return err
			}
			packetLen, err = experimentaltcp.TCPShapedIPv4WireLen(frameLen)
			if err != nil {
				manager.mu.Unlock()
				return err
			}
		}
		prepared = append(prepared, preparedExperimentalTCPTXFrame{
			packet: packet,
			wireFrame: experimentaltcp.Frame{
				Flags:         flags,
				FlowID:        flowID,
				Epoch:         epoch,
				Sequence:      uint64(frame.Sequence),
				FragmentIndex: frame.FragmentIndex,
				FragmentCount: frame.FragmentCount,
				Payload:       payload,
			},
			flow:            flow,
			bytes:           payloadLen,
			packetLen:       packetLen,
			frameLen:        frameLen,
			tcpSeqLen:       frameLen,
			fragmentPayload: fragmentPayload,
			rawDst:          dst,
		})
	}
	if useSequenceBatch {
		if err := manager.flushKernelUDPTXSequenceBatchesLocked(sequenceByFlow, sequenceSingle); err != nil {
			manager.mu.Unlock()
			return err
		}
	}
	manager.mu.Unlock()

	releaseSealed, err := manager.sealPreparedExperimentalTCPFrames(prepared, pendingSealByFlow, pendingSealSingleFlow, pendingSealSingle)
	if err != nil {
		return err
	}
	prepared, err = splitPreparedExperimentalTCPFrames(prepared)
	if err != nil {
		if releaseSealed != nil {
			releaseSealed()
		}
		return err
	}
	manager.mu.Lock()
	manager.assignExperimentalTCPOuterSequencesLocked(prepared)
	manager.mu.Unlock()
	sent, err := manager.sendRawExperimentalTCPPreparedFrames(prepared)
	if releaseSealed != nil {
		releaseSealed()
	}
	if sent > 0 {
		manager.mu.Lock()
		manager.observeExperimentalTCPTXBatchLocked(prepared[:sent], time.Now().UTC())
		manager.mu.Unlock()
	}
	if err != nil {
		manager.mu.Lock()
		manager.recordExperimentalTCPDropLocked(err)
		manager.mu.Unlock()
		return err
	}
	return nil
}

func (manager *Manager) observeExperimentalTCPTXBatchLocked(prepared []preparedExperimentalTCPTXFrame, now time.Time) {
	if len(prepared) == 0 {
		return
	}
	var kernelTXSuccesses uint64
	if len(prepared) == 1 {
		item := prepared[0]
		flowID := item.wireFrame.FlowID
		telemetryFlow := item.flow
		if latest, ok := manager.expTCPFlows[flowID]; ok {
			telemetryFlow = latest
		}
		manager.expTCPSubmitted++
		if item.kernelTX {
			kernelTXSuccesses++
		}
		manager.experimentalTCPTelemetryLocked(flowID, telemetryFlow).ObserveTXBatch(1, uint64(max(0, item.bytes)), now)
		if kernelTXSuccesses > 0 {
			manager.kernelCryptoFrameSealSuccesses += kernelTXSuccesses
		}
		return
	}
	firstFlowID := prepared[0].wireFrame.FlowID
	singleFlow := true
	var frames uint64
	var bytes uint64
	for _, item := range prepared {
		if item.wireFrame.FlowID != firstFlowID {
			singleFlow = false
			break
		}
		frames++
		if item.bytes > 0 {
			bytes += uint64(item.bytes)
		}
		if item.kernelTX {
			kernelTXSuccesses++
		}
	}
	if singleFlow {
		telemetryFlow := prepared[0].flow
		if latest, ok := manager.expTCPFlows[firstFlowID]; ok {
			telemetryFlow = latest
		}
		manager.expTCPSubmitted += frames
		manager.experimentalTCPTelemetryLocked(firstFlowID, telemetryFlow).ObserveTXBatch(frames, bytes, now)
		if kernelTXSuccesses > 0 {
			manager.kernelCryptoFrameSealSuccesses += kernelTXSuccesses
		}
		return
	}
	var telemetryByFlow map[uint64]*experimentalTCPTXTelemetryBatch
	for _, item := range prepared {
		flowID := item.wireFrame.FlowID
		if telemetryByFlow == nil {
			telemetryByFlow = make(map[uint64]*experimentalTCPTXTelemetryBatch, 1)
		}
		telemetry := telemetryByFlow[flowID]
		if telemetry == nil {
			telemetryFlow := item.flow
			if latest, ok := manager.expTCPFlows[flowID]; ok {
				telemetryFlow = latest
			}
			telemetry = &experimentalTCPTXTelemetryBatch{flow: telemetryFlow}
			telemetryByFlow[flowID] = telemetry
		}
		telemetry.frames++
		if item.bytes > 0 {
			telemetry.bytes += uint64(item.bytes)
		}
		if item.kernelTX {
			kernelTXSuccesses++
		}
		manager.expTCPSubmitted++
	}
	for flowID, telemetry := range telemetryByFlow {
		manager.experimentalTCPTelemetryLocked(flowID, telemetry.flow).ObserveTXBatch(telemetry.frames, telemetry.bytes, now)
	}
	if kernelTXSuccesses > 0 {
		manager.kernelCryptoFrameSealSuccesses += kernelTXSuccesses
	}
}

func (manager *Manager) SubscribeExperimentalTCP(ctx context.Context, buffer int) (dataplane.ExperimentalTCPSubscription, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if buffer <= 0 {
		buffer = 256
	}
	manager.mu.Lock()
	if !manager.experimentalTCPProviderFastPathAvailableLocked() && !experimentalTCPRawFallbackEnabled() {
		manager.mu.Unlock()
		if reason := manager.experimentalTCPFastPathDisabledReasonLocked(); reason != "" {
			return nil, fmt.Errorf("experimental_tcp TC/XDP provider is disabled: %s", reason)
		}
		return nil, fmt.Errorf("experimental_tcp TC/XDP provider is not available; raw socket fallback is disabled")
	}
	if err := manager.startExperimentalTCPReceiverLocked(); err != nil {
		manager.mu.Unlock()
		return nil, err
	}
	events := make(chan []dataplane.ExperimentalTCPFrame, buffer)
	subscription := &experimentalTCPSubscription{manager: manager, events: events}
	manager.expTCPSubs[events] = struct{}{}
	manager.mu.Unlock()
	return subscription, nil
}

func (manager *Manager) SubscribeExperimentalTCPFlow(ctx context.Context, flowID uint64, buffer int) (dataplane.ExperimentalTCPSubscription, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if flowID == 0 {
		return nil, fmt.Errorf("experimental_tcp flow subscription requires a non-zero flow id")
	}
	if buffer <= 0 {
		buffer = 256
	}
	manager.mu.Lock()
	if !manager.experimentalTCPProviderFastPathAvailableLocked() && !experimentalTCPRawFallbackEnabled() {
		manager.mu.Unlock()
		if reason := manager.experimentalTCPFastPathDisabledReasonLocked(); reason != "" {
			return nil, fmt.Errorf("experimental_tcp TC/XDP provider is disabled: %s", reason)
		}
		return nil, fmt.Errorf("experimental_tcp TC/XDP provider is not available; raw socket fallback is disabled")
	}
	if err := manager.startExperimentalTCPReceiverLocked(); err != nil {
		manager.mu.Unlock()
		return nil, err
	}
	events := make(chan []dataplane.ExperimentalTCPFrame, buffer)
	subscription := &experimentalTCPSubscription{manager: manager, events: events, flowID: flowID}
	if manager.expTCPFlowSubs == nil {
		manager.expTCPFlowSubs = make(map[uint64]map[chan []dataplane.ExperimentalTCPFrame]struct{})
	}
	subs := manager.expTCPFlowSubs[flowID]
	if subs == nil {
		subs = make(map[chan []dataplane.ExperimentalTCPFrame]struct{})
		manager.expTCPFlowSubs[flowID] = subs
	}
	subs[events] = struct{}{}
	manager.mu.Unlock()
	return subscription, nil
}

func (manager *Manager) Detach(ctx context.Context) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	return manager.detachLocked(ctx, nil)
}

func (manager *Manager) Cleanup(ctx context.Context, spec dataplane.AttachSpec) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	if spec.PinPath == "" {
		spec.PinPath = "/sys/fs/bpf/trustix"
	}
	spec = normalizeAttachSpec(spec)
	manager.spec = spec
	manager.snapshot = dataplane.Snapshot{}
	manager.attached = false
	manager.linkAddedLANs = make(map[string]bool)
	manager.addressAdded = false
	manager.addressAddedLANs = make(map[string]bool)
	manager.qdiscPrepared = false
	manager.qdiscPreparedLANs = make(map[string]bool)
	manager.lanOffloadProtection = nil
	manager.lanOffloadProtections = make(map[string]*persistedLinkOffloadState)
	manager.localVIPs = make(map[netip.Addr]struct{})
	manager.restoreSysctls = make(map[string]string)
	manager.managedCaptureRoutes = make(map[string]managedCaptureRouteState)
	manager.deviceAccessProxyARP = make(map[string]deviceAccessProxyARPState)
	manager.expTCPFlows = make(map[uint64]dataplane.ExperimentalTCPFlow)
	manager.expTCPTXTemplates = make(map[uint64]experimentalTCPTXTemplate)
	manager.expTCPOuterTXSequences = make(map[uint64]uint32)
	manager.expTCPOuterTXAcknowledgments = make(map[uint64]uint32)
	manager.expTCPFlowSubs = make(map[uint64]map[chan []dataplane.ExperimentalTCPFrame]struct{})
	manager.kernelUDPFlows = make(map[uint64]dataplane.KernelUDPFlow)
	manager.kernelUDPTXTemplates = make(map[uint64]kernelUDPTXTemplate)
	manager.kernelUDPFlowSubs = make(map[uint64]map[chan []dataplane.KernelUDPFrame]struct{})
	manager.closeKernelUDPUDPFallbackSocketsLocked()
	manager.kernelUDPUDPFallbackSockets = make(map[uint16]*kernelUDPUDPFallbackSocket)
	manager.expTCPCryptoFragments = make(map[experimentalTCPCryptoFragmentKey]*experimentalTCPCryptoFragmentAssembly)
	manager.kernelUDPCryptoFragments = make(map[kernelUDPCryptoFragmentKey]*kernelUDPCryptoFragmentAssembly)
	manager.expTCPAllowed = make(map[uint16]struct{})
	manager.kernelUDPAllowed = make(map[uint16]struct{})
	manager.kernelTransportAllowed = make(map[uint16]struct{})
	manager.nativeTunnelRoutes = make(map[string]nativeTunnelRouteState)

	var staleXDP *persistedExperimentalTCPXDPState
	state, found, err := readPersistedDataplaneState(spec.PinPath)
	if err != nil {
		if quarantineErr := quarantinePersistedDataplaneState(spec.PinPath); quarantineErr != nil {
			return fmt.Errorf("%w; quarantine corrupt dataplane state: %v", err, quarantineErr)
		}
		found = false
	}
	if found {
		if state.Spec.PinPath == "" {
			state.Spec.PinPath = spec.PinPath
		}
		manager.spec = normalizeAttachSpec(mergeCleanupSpec(state.Spec, spec))
		manager.snapshot = state.Snapshot
		manager.attached = state.Attached
		manager.linkAddedLANs = persistedLANLinkAddedMap(state, manager.spec)
		manager.addressAdded = state.AddressAdded
		manager.qdiscPrepared = state.QdiscPrepared
		manager.lanOffloadProtection = state.LANOffloadProtection
		manager.addressAddedLANs = persistedLANAddressAddedMap(state, manager.spec)
		manager.qdiscPreparedLANs = persistedLANQdiscPreparedMap(state, manager.spec)
		manager.lanOffloadProtections = persistedLANOffloadProtectionMap(state)
		if state.Version == 0 && state.Attached && manager.spec.ManageQdisc {
			manager.qdiscPrepared = true
			for _, lan := range effectiveLANAttachSpecs(manager.spec) {
				if lan.Iface != "" && lan.ManageQdisc {
					manager.qdiscPreparedLANs[lanAddressStateKey(lan)] = true
				}
			}
		}
		manager.localVIPs = localVIPMap(state.LocalVIPs)
		manager.restoreSysctls = cloneStringMap(state.RestoreSysctls)
		manager.managedCaptureRoutes = managedCaptureRouteStateMap(state.ManagedCaptureRoutes)
		manager.deviceAccessProxyARP = deviceAccessProxyARPStateMap(state.DeviceAccessProxyARP)
		manager.expTCPFlows = cloneExperimentalTCPFlows(state.ExperimentalTCPFlows)
		manager.expTCPTXTemplates = make(map[uint64]experimentalTCPTXTemplate)
		manager.expTCPOuterTXSequences = make(map[uint64]uint32)
		manager.expTCPOuterTXAcknowledgments = make(map[uint64]uint32)
		manager.kernelUDPFlows = cloneKernelUDPFlows(state.KernelUDPFlows)
		manager.kernelUDPTXTemplates = make(map[uint64]kernelUDPTXTemplate)
		manager.nativeTunnelRoutes = nativeTunnelRouteStateMap(state.NativeTunnelRoutes)
		staleXDP = state.ExperimentalTCPXDP
	} else {
		manager.linkAddedLANs = make(map[string]bool)
		manager.addressAddedLANs = make(map[string]bool)
		manager.qdiscPreparedLANs = make(map[string]bool)
		for i, lan := range effectiveLANAttachSpecs(spec) {
			if lan.ManageQdisc {
				manager.qdiscPreparedLANs[lanAddressStateKey(lan)] = true
				if i == 0 {
					manager.qdiscPrepared = true
				}
			}
		}
	}
	manager.underlayQdiscPrepared = strings.TrimSpace(manager.spec.UnderlayIface) != ""
	if manager.spec.PinPath != "" {
		if err := os.MkdirAll(manager.spec.PinPath, 0o755); err != nil {
			return fmt.Errorf("create dataplane pin path %q: %w", manager.spec.PinPath, err)
		}
	}
	return manager.detachLocked(ctx, staleXDP)
}

func (manager *Manager) PlanCleanup(ctx context.Context, spec dataplane.AttachSpec) (dataplane.CleanupPlan, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return dataplane.CleanupPlan{}, err
	}
	if spec.PinPath == "" {
		spec.PinPath = "/sys/fs/bpf/trustix"
	}
	effective := spec
	state, found, err := readPersistedDataplaneState(spec.PinPath)
	if err != nil {
		return dataplane.CleanupPlan{}, err
	}
	if found {
		if state.Spec.PinPath == "" {
			state.Spec.PinPath = spec.PinPath
		}
		effective = mergeCleanupSpec(state.Spec, spec)
	}
	effective = normalizeAttachSpec(effective)
	steps := []dataplane.CleanupStep{{
		Action: "load_state",
		Target: filepath.Join(spec.PinPath, "state.json"),
		Detail: fmt.Sprintf("found=%t", found),
	}}
	localVIPs := []dataplane.LocalVIP(nil)
	restoreSysctls := map[string]string(nil)
	linkAddedLANs := map[string]bool(nil)
	addressAddedLANs := map[string]bool(nil)
	qdiscPreparedLANs := map[string]bool(nil)
	lanOffloadProtections := map[string]*persistedLinkOffloadState(nil)
	managedCaptureRoutes := []persistedManagedCaptureRoute(nil)
	deviceAccessProxyARP := []persistedDeviceAccessProxyARP(nil)
	var staleXDP *persistedExperimentalTCPXDPState
	if found {
		localVIPs = state.LocalVIPs
		restoreSysctls = state.RestoreSysctls
		linkAddedLANs = persistedLANLinkAddedMap(state, effective)
		addressAddedLANs = persistedLANAddressAddedMap(state, effective)
		qdiscPreparedLANs = persistedLANQdiscPreparedMap(state, effective)
		if state.Version == 0 && state.Attached {
			for _, lan := range effectiveLANAttachSpecs(effective) {
				if lan.Iface != "" && lan.ManageQdisc {
					qdiscPreparedLANs[lanAddressStateKey(lan)] = true
				}
			}
		}
		lanOffloadProtections = persistedLANOffloadProtectionMap(state)
		managedCaptureRoutes = state.ManagedCaptureRoutes
		deviceAccessProxyARP = state.DeviceAccessProxyARP
		staleXDP = state.ExperimentalTCPXDP
	} else {
		linkAddedLANs = make(map[string]bool)
		addressAddedLANs = make(map[string]bool)
		qdiscPreparedLANs = make(map[string]bool)
		for _, lan := range effectiveLANAttachSpecs(effective) {
			if lan.ManageQdisc {
				qdiscPreparedLANs[lanAddressStateKey(lan)] = true
			}
		}
	}
	underlayIface := strings.TrimSpace(effective.UnderlayIface)
	if underlayIface != "" && !attachSpecHasLANIface(effective, underlayIface) {
		steps = append(steps,
			dataplane.CleanupStep{Action: "remove_tc_filters", Target: underlayIface, Detail: "TrustIX underlay BPF filters"},
			dataplane.CleanupStep{Action: "delete_clsact_qdisc", Target: underlayIface},
		)
	}
	for _, lan := range effectiveLANAttachSpecs(effective) {
		if lan.Iface == "" {
			continue
		}
		key := lanAddressStateKey(lan)
		if qdiscPreparedLANs[key] {
			steps = append(steps,
				dataplane.CleanupStep{Action: "remove_tc_filters", Target: lan.Iface, Detail: "trustix ingress/egress BPF filters"},
				dataplane.CleanupStep{Action: "delete_clsact_qdisc", Target: lan.Iface},
			)
		}
		if addressAddedLANs[key] && lan.ManageAddress && lan.Gateway != "" {
			steps = append(steps, dataplane.CleanupStep{Action: "remove_lan_gateway", Target: lan.Iface, Detail: lan.Gateway})
		}
		if state := lanOffloadProtections[lan.Iface]; state != nil && state.Iface != "" && state.hasRestorableFeatures() {
			steps = append(steps, dataplane.CleanupStep{Action: "restore_lan_offloads", Target: state.Iface, Detail: state.Detail()})
		}
	}
	if effective.LANIface != "" && len(localVIPs) > 0 {
		for _, vip := range localVIPs {
			steps = append(steps, dataplane.CleanupStep{Action: "remove_local_vip", Target: effective.LANIface, Detail: vip.Addr.String()})
		}
	}
	for _, route := range managedCaptureRoutes {
		steps = append(steps, dataplane.CleanupStep{Action: "delete_capture_route", Target: route.Prefix, Detail: route.Iface})
	}
	for _, proxy := range deviceAccessProxyARP {
		steps = append(steps, dataplane.CleanupStep{Action: "delete_device_proxy_arp", Target: proxy.Address, Detail: proxy.Iface})
	}
	if found {
		for _, route := range state.NativeTunnelRoutes {
			steps = append(steps, dataplane.CleanupStep{Action: "delete_native_tunnel_route", Target: route.Prefix, Detail: route.Tunnel})
		}
	}
	if staleXDP != nil && staleXDP.Attached {
		target := staleXDP.Underlay
		if target == "" {
			target = effective.UnderlayIface
		}
		steps = append(steps, dataplane.CleanupStep{Action: "detach_experimental_tcp_xdp", Target: target, Detail: fmt.Sprintf("mode=%s flags=%d", staleXDP.AttachMode, staleXDP.AttachFlags)})
	}
	if len(restoreSysctls) > 0 {
		keys := make([]string, 0, len(restoreSysctls))
		for path := range restoreSysctls {
			keys = append(keys, path)
		}
		sort.Strings(keys)
		for _, path := range keys {
			steps = append(steps, dataplane.CleanupStep{Action: "restore_sysctl", Target: path, Detail: restoreSysctls[path]})
		}
	}
	for _, lan := range effectiveLANAttachSpecs(effective) {
		if lan.Iface == "" {
			continue
		}
		if linkAddedLANs[lanAddressStateKey(lan)] {
			steps = append(steps, dataplane.CleanupStep{Action: "delete_managed_lan_iface", Target: lan.Iface, Detail: "created by TrustIX managed LAN attach"})
		}
	}
	steps = append(steps, dataplane.CleanupStep{Action: "close_bpf_objects", Target: spec.PinPath})
	return dataplane.CleanupPlan{Spec: effective, Steps: steps}, nil
}

func (manager *Manager) detachLocked(ctx context.Context, staleXDP *persistedExperimentalTCPXDPState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var errs []string
	if err := manager.syncDeviceAccessProxyARPLocked(ctx, dataplane.Snapshot{}); err != nil {
		errs = append(errs, err.Error())
	}
	if err := manager.syncManagedCaptureRoutesLocked(ctx, dataplane.Snapshot{}); err != nil {
		errs = append(errs, err.Error())
	}
	if err := manager.syncNativeTunnelRoutesLocked(ctx, dataplane.Snapshot{}); err != nil {
		errs = append(errs, err.Error())
	}
	var link netlink.Link
	var underlayLink netlink.Link
	lanLinks := make(map[string]netlink.Link)
	for _, lan := range effectiveLANAttachSpecs(manager.spec) {
		if lan.Iface == "" {
			continue
		}
		if found, err := netlink.LinkByName(lan.Iface); err == nil {
			lanLinks[lan.Iface] = found
			if link == nil && lan.Iface == manager.spec.LANIface {
				link = found
			}
		} else if !isNotFound(err) {
			errs = append(errs, fmt.Sprintf("inspect LAN iface %q: %v", lan.Iface, err))
		}
	}
	if manager.spec.LANIface != "" {
		if found := lanLinks[manager.spec.LANIface]; found != nil {
			link = found
		} else if found, err := netlink.LinkByName(manager.spec.LANIface); err == nil {
			link = found
		} else if !isNotFound(err) {
			errs = append(errs, fmt.Sprintf("inspect LAN iface %q: %v", manager.spec.LANIface, err))
		}
	}
	if manager.spec.UnderlayIface != "" {
		if found, err := netlink.LinkByName(manager.spec.UnderlayIface); err == nil {
			underlayLink = found
		} else if manager.underlayIngressFilter != nil || manager.underlayQdiscPrepared {
			errs = append(errs, fmt.Sprintf("inspect underlay iface %q: %v", manager.spec.UnderlayIface, err))
		}
	}
	if err := manager.detachKernelUDPRXDirectLocked(underlayLink); err != nil {
		errs = append(errs, err.Error())
	}
	if underlayLink != nil && manager.underlayQdiscPrepared && (link == nil || underlayLink.Attrs().Index != link.Attrs().Index) {
		if err := deleteClsact(underlayLink); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if manager.qdiscPrepared || len(manager.qdiscPreparedLANs) > 0 || len(manager.lanTCFilters) > 0 {
		if err := manager.detachTCPrograms(link); err != nil {
			errs = append(errs, err.Error())
		}
		for _, lan := range effectiveLANAttachSpecs(manager.spec) {
			if lan.Iface == "" {
				continue
			}
			key := lanAddressStateKey(lan)
			if !manager.qdiscPreparedLANs[key] && !(lan.Iface == manager.spec.LANIface && manager.qdiscPrepared) {
				continue
			}
			target := lanLinks[lan.Iface]
			if target == nil {
				continue
			}
			if err := deleteClsact(target); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	if link != nil && len(manager.localVIPs) > 0 {
		if err := manager.syncLocalVIPsLocked(nil); err != nil {
			errs = append(errs, err.Error())
		}
	}
	for _, lan := range effectiveLANAttachSpecs(manager.spec) {
		if lan.Iface == "" || !lan.ManageAddress || lan.Gateway == "" {
			continue
		}
		key := lanAddressStateKey(lan)
		if !manager.addressAddedLANs[key] && !(lan.Iface == manager.spec.LANIface && manager.addressAdded) {
			continue
		}
		target := lanLinks[lan.Iface]
		if target == nil {
			continue
		}
		addr, err := parseAddress(lan.Gateway)
		if err != nil {
			errs = append(errs, err.Error())
		} else if err := netlink.AddrDel(target, addr); err != nil && !isNotFound(err) {
			errs = append(errs, fmt.Sprintf("remove LAN gateway %q from %q: %v", lan.Gateway, lan.Iface, err))
		}
	}
	if err := manager.restoreLANOffloadProtectionLocked(link); err != nil {
		errs = append(errs, err.Error())
	}
	if err := manager.detachExperimentalTCPFastPathLocked(); err != nil {
		errs = append(errs, err.Error())
	}
	if err := manager.detachStaleExperimentalTCPXDPLocked(staleXDP); err != nil {
		errs = append(errs, err.Error())
	}
	if err := manager.stopNeighborMonitorLocked(); err != nil {
		errs = append(errs, err.Error())
	}
	if err := manager.closeLANPacketInjectorsLocked(); err != nil {
		errs = append(errs, err.Error())
	}
	for path, value := range manager.restoreSysctls {
		if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", path, err))
		}
	}
	manager.restoreSysctls = make(map[string]string)
	for _, lan := range effectiveLANAttachSpecs(manager.spec) {
		if lan.Iface == "" {
			continue
		}
		key := lanAddressStateKey(lan)
		if !manager.linkAddedLANs[key] {
			continue
		}
		target := lanLinks[lan.Iface]
		if target == nil {
			continue
		}
		if err := netlink.LinkDel(target); err != nil && !isNotFound(err) {
			errs = append(errs, fmt.Sprintf("delete managed LAN iface %q: %v", lan.Iface, err))
		}
	}
	if manager.expTCPRawFD >= 0 {
		if err := unix.Close(manager.expTCPRawFD); err != nil {
			errs = append(errs, "close experimental_tcp raw socket: "+err.Error())
		}
		manager.expTCPRawFD = -1
	}
	if manager.kernelUDPRawFD >= 0 {
		if err := unix.Close(manager.kernelUDPRawFD); err != nil {
			errs = append(errs, "close kernel_udp raw UDP socket: "+err.Error())
		}
		manager.kernelUDPRawFD = -1
	}
	if err := manager.closeKernelUDPUDPFallbackSocketsLocked(); err != nil {
		errs = append(errs, err.Error())
	}
	if err := manager.closeRawIPv4TXSocketLocked(); err != nil {
		errs = append(errs, err.Error())
	}
	if err := manager.closeKernelCryptoProviderMapLocked(); err != nil {
		errs = append(errs, err.Error())
	}
	manager.attached = false
	manager.linkAddedLANs = make(map[string]bool)
	manager.addressAdded = false
	manager.addressAddedLANs = make(map[string]bool)
	manager.qdiscPrepared = false
	manager.qdiscPreparedLANs = make(map[string]bool)
	manager.underlayQdiscPrepared = false
	if err := manager.persistStateLocked(); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("detach linux dataplane: %s", strings.Join(errs, "; "))
	}
	return nil
}

func ipv4Payload(packet []byte) ([]byte, [4]byte, error) {
	if len(packet) >= 14 && binary.BigEndian.Uint16(packet[12:14]) == unix.ETH_P_IP {
		packet = packet[14:]
	}
	if len(packet) < 20 {
		return nil, [4]byte{}, fmt.Errorf("packet is too short for IPv4: %d bytes", len(packet))
	}
	if packet[0]>>4 != 4 {
		return nil, [4]byte{}, fmt.Errorf("packet is not IPv4")
	}
	headerLen := int(packet[0]&0x0f) * 4
	if headerLen < 20 || len(packet) < headerLen {
		return nil, [4]byte{}, fmt.Errorf("invalid IPv4 header length %d", headerLen)
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < headerLen || totalLen > len(packet) {
		return nil, [4]byte{}, fmt.Errorf("invalid IPv4 total length %d for %d-byte packet", totalLen, len(packet))
	}
	var dst [4]byte
	copy(dst[:], packet[16:20])
	return packet[:totalLen], dst, nil
}

type captureSubscription struct {
	manager *Manager
	events  chan []dataplane.CaptureEvent
	legacy  chan dataplane.CaptureEvent
	once    sync.Once
}

func (subscription *captureSubscription) Events() <-chan dataplane.CaptureEvent {
	subscription.ensureLegacy()
	return subscription.legacy
}

func (subscription *captureSubscription) BatchEvents() <-chan []dataplane.CaptureEvent {
	return subscription.events
}

func (subscription *captureSubscription) ensureLegacy() {
	if subscription.legacy != nil {
		return
	}
	subscription.manager.captureMu.Lock()
	if subscription.legacy == nil {
		subscription.legacy = make(chan dataplane.CaptureEvent, cap(subscription.events))
		go subscription.legacyLoop()
	}
	subscription.manager.captureMu.Unlock()
}

func (subscription *captureSubscription) legacyLoop() {
	for batch := range subscription.events {
		for _, event := range batch {
			subscription.legacy <- event
		}
	}
	close(subscription.legacy)
}

func (subscription *captureSubscription) Close() error {
	subscription.once.Do(func() {
		subscription.manager.captureMu.Lock()
		delete(subscription.manager.captureSubs, subscription.events)
		close(subscription.events)
		subscription.manager.captureMu.Unlock()
	})
	return nil
}

type experimentalTCPSubscription struct {
	manager *Manager
	events  chan []dataplane.ExperimentalTCPFrame
	legacy  chan dataplane.ExperimentalTCPFrame
	flowID  uint64
	once    sync.Once
}

func (subscription *experimentalTCPSubscription) Events() <-chan dataplane.ExperimentalTCPFrame {
	subscription.ensureLegacy()
	return subscription.legacy
}

func (subscription *experimentalTCPSubscription) BatchEvents() <-chan []dataplane.ExperimentalTCPFrame {
	return subscription.events
}

func (subscription *experimentalTCPSubscription) ensureLegacy() {
	if subscription.legacy != nil {
		return
	}
	subscription.manager.mu.Lock()
	if subscription.legacy == nil {
		subscription.legacy = make(chan dataplane.ExperimentalTCPFrame, cap(subscription.events))
		go subscription.legacyLoop()
	}
	subscription.manager.mu.Unlock()
}

func (subscription *experimentalTCPSubscription) legacyLoop() {
	for batch := range subscription.events {
		for _, frame := range batch {
			subscription.legacy <- frame
		}
	}
	close(subscription.legacy)
}

func (subscription *experimentalTCPSubscription) Close() error {
	subscription.once.Do(func() {
		subscription.manager.mu.Lock()
		if subscription.flowID != 0 {
			if subs := subscription.manager.expTCPFlowSubs[subscription.flowID]; subs != nil {
				delete(subs, subscription.events)
				if len(subs) == 0 {
					delete(subscription.manager.expTCPFlowSubs, subscription.flowID)
				}
			}
		} else {
			delete(subscription.manager.expTCPSubs, subscription.events)
		}
		close(subscription.events)
		subscription.manager.mu.Unlock()
	})
	return nil
}

type kernelUDPSubscription struct {
	manager *Manager
	events  chan []dataplane.KernelUDPFrame
	legacy  chan dataplane.KernelUDPFrame
	flowID  uint64
	once    sync.Once
}

func (subscription *kernelUDPSubscription) Events() <-chan dataplane.KernelUDPFrame {
	subscription.ensureLegacy()
	return subscription.legacy
}

func (subscription *kernelUDPSubscription) BatchEvents() <-chan []dataplane.KernelUDPFrame {
	return subscription.events
}

func (subscription *kernelUDPSubscription) ensureLegacy() {
	if subscription.legacy != nil {
		return
	}
	subscription.manager.mu.Lock()
	if subscription.legacy == nil {
		subscription.legacy = make(chan dataplane.KernelUDPFrame, cap(subscription.events))
		go subscription.legacyLoop()
	}
	subscription.manager.mu.Unlock()
}

func (subscription *kernelUDPSubscription) legacyLoop() {
	for batch := range subscription.events {
		for _, frame := range batch {
			subscription.legacy <- frame
		}
	}
	close(subscription.legacy)
}

func (subscription *kernelUDPSubscription) Close() error {
	subscription.once.Do(func() {
		subscription.manager.mu.Lock()
		if subscription.flowID != 0 {
			if subs := subscription.manager.kernelUDPFlowSubs[subscription.flowID]; subs != nil {
				delete(subs, subscription.events)
				if len(subs) == 0 {
					delete(subscription.manager.kernelUDPFlowSubs, subscription.flowID)
				}
			}
		} else {
			delete(subscription.manager.kernelUDPSubs, subscription.events)
		}
		close(subscription.events)
		subscription.manager.mu.Unlock()
	})
	return nil
}

func (manager *Manager) startKernelUDPRawReceiverLocked() error {
	if manager.experimentalTCPFastPathAvailableLocked() {
		return nil
	}
	if kernelUDPUDPFallbackEnabled() && len(manager.kernelUDPAllowed) > 0 {
		err := manager.syncKernelUDPUDPFallbackSocketsLocked(manager.kernelUDPAllowed)
		if err == nil {
			return nil
		}
		manager.kernelUDPUDPFallbackBindErrors++
		manager.warnings = append(manager.warnings, "kernel_udp UDP socket fallback unavailable; using raw UDP socket fallback: "+err.Error())
	}
	if manager.kernelUDPRawFD >= 0 {
		return nil
	}
	if !kernelUDPRawFallbackEnabled() {
		return fmt.Errorf("kernel_udp raw UDP fallback is disabled")
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		return fmt.Errorf("open kernel_udp raw UDP receiver socket: %w", err)
	}
	manager.kernelUDPRawFD = fd
	go manager.readKernelUDPRawFrames(fd)
	return nil
}

func (manager *Manager) readKernelUDPRawFrames(fd int) {
	parseUDP := kerneludp.ParseUDPIPv4NoCopy
	if kernelUDPSkipUDPChecksum() {
		parseUDP = kerneludp.ParseUDPIPv4NoCopySkipChecksum
	}
	batchSize := kernelUDPRawFallbackRecvBatchSize()
	if batchSize <= 1 {
		manager.readKernelUDPRawFramesSingle(fd, parseUDP)
		return
	}
	manager.readKernelUDPRawFramesBatch(fd, batchSize, parseUDP)
}

func (manager *Manager) readKernelUDPRawFramesSingle(fd int, parseUDP func([]byte) (kerneludp.UDPPacket, error)) {
	buf := make([]byte, 128*1024)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return
		}
		manager.handleKernelUDPRawPacket(buf[:n], parseUDP)
	}
}

func (manager *Manager) readKernelUDPRawFramesBatch(fd int, batchSize int, parseUDP func([]byte) (kerneludp.UDPPacket, error)) {
	if batchSize <= 1 {
		manager.readKernelUDPRawFramesSingle(fd, parseUDP)
		return
	}
	buffers := make([][]byte, batchSize)
	iovs := make([]unix.Iovec, batchSize)
	msgs := make([]mmsghdr, batchSize)
	for i := range buffers {
		buffers[i] = make([]byte, 128*1024)
		iovs[i].Base = &buffers[i][0]
		iovs[i].SetLen(len(buffers[i]))
		msgs[i].hdr.Iov = &iovs[i]
		msgs[i].hdr.Iovlen = 1
	}
	batchHolder, batch := takeReceivedKernelUDPFrameBatch(batchSize)
	defer putReceivedKernelUDPFrameBatch(batchHolder, batch)
	for {
		for i := range msgs {
			msgs[i].len = 0
		}
		n, err := recvmmsg(fd, msgs, unix.MSG_WAITFORONE)
		if err != nil {
			if n <= 0 {
				return
			}
		}
		batch = resetReceivedKernelUDPFrameBatch(batch)
		for i := 0; i < n; i++ {
			length := int(msgs[i].len)
			if length <= 0 || length > len(buffers[i]) {
				continue
			}
			if item, ok := manager.decodeKernelUDPRawPacket(buffers[i][:length], parseUDP); ok {
				batch = append(batch, item)
			}
		}
		if len(batch) > 0 {
			manager.mu.Lock()
			manager.kernelUDPRawRXBatches++
			manager.kernelUDPRawRXFrames += uint64(len(batch))
			manager.mu.Unlock()
			manager.deliverKernelUDPFrames(batch)
		}
	}
}

func (manager *Manager) handleKernelUDPRawPacket(packet []byte, parseUDP func([]byte) (kerneludp.UDPPacket, error)) {
	item, ok := manager.decodeKernelUDPRawPacket(packet, parseUDP)
	if !ok {
		return
	}
	manager.mu.Lock()
	manager.kernelUDPRawRXBatches++
	manager.kernelUDPRawRXFrames++
	manager.mu.Unlock()
	manager.deliverKernelUDPFrames([]receivedKernelUDPFrame{item})
}

func (manager *Manager) decodeKernelUDPRawPacket(packet []byte, parseUDP func([]byte) (kerneludp.UDPPacket, error)) (receivedKernelUDPFrame, bool) {
	udpPacket, err := parseUDP(packet)
	if err != nil {
		if errors.Is(err, kerneludp.ErrChecksum) {
			manager.recordDrop(observability.DropChecksumError)
		}
		return receivedKernelUDPFrame{}, false
	}
	manager.mu.Lock()
	_, allowed := manager.kernelUDPAllowed[udpPacket.DestinationPort]
	if !allowed {
		_, allowed = manager.kernelUDPAllowed[udpPacket.SourcePort]
	}
	manager.mu.Unlock()
	if !allowed {
		return receivedKernelUDPFrame{}, false
	}
	return manager.decodeKernelUDPPayload(udpPacket, udpPacket.Payload)
}

type kernelUDPDecodePayloadOptions struct {
	BorrowEncryptedPayload bool
}

func (manager *Manager) decodeKernelUDPPayload(udpPacket kerneludp.UDPPacket, payloadBytes []byte) (receivedKernelUDPFrame, bool) {
	return manager.decodeKernelUDPPayloadWithOptions(udpPacket, payloadBytes, kernelUDPDecodePayloadOptions{})
}

func (manager *Manager) decodeKernelUDPPayloadBorrowEncrypted(udpPacket kerneludp.UDPPacket, payloadBytes []byte) (receivedKernelUDPFrame, bool) {
	return manager.decodeKernelUDPPayloadWithOptions(udpPacket, payloadBytes, kernelUDPDecodePayloadOptions{BorrowEncryptedPayload: true})
}

func (manager *Manager) decodeKernelUDPPayloadWithOptions(udpPacket kerneludp.UDPPacket, payloadBytes []byte, options kernelUDPDecodePayloadOptions) (receivedKernelUDPFrame, bool) {
	wireFrame, err := kerneludp.ParseFrameNoCopy(payloadBytes)
	if err != nil {
		manager.recordDrop(observability.DropInvalidOverlayHeader)
		return receivedKernelUDPFrame{}, false
	}
	encrypted := wireFrame.Flags&kerneludp.FlagEncrypted != 0
	kernelOpened := wireFrame.Flags&kerneludp.FlagKernelOpened != 0
	cryptoFragment := wireFrame.Flags&kerneludp.FlagCryptoFragment != 0
	innerIPv4 := wireFrame.Flags&kerneludp.FlagInnerIPv4 != 0
	placement := dataplane.CryptoPlacementUserspace
	if kernelOpened || encrypted && cryptoFragment {
		placement = dataplane.CryptoPlacementKernel
	}
	payload := wireFrame.Payload
	copyPayload := true
	if options.BorrowEncryptedPayload && encrypted && !kernelOpened {
		copyPayload = false
	}
	if copyPayload {
		payload = append([]byte(nil), wireFrame.Payload...)
	}
	innerIPv4 = innerIPv4 && (!encrypted || kernelOpened) && kernelUDPInnerIPv4Eligible(payload)
	return receivedKernelUDPFrame{
		frame: dataplane.KernelUDPFrame{
			FlowID:          wireFrame.FlowID,
			Direction:       dataplane.KernelTransportInbound,
			Sequence:        wireFrame.Sequence,
			FragmentIndex:   wireFrame.FragmentIndex,
			FragmentCount:   wireFrame.FragmentCount,
			Payload:         payload,
			Encrypted:       encrypted || kernelOpened,
			InnerIPv4:       innerIPv4,
			CryptoPlacement: placement,
		},
		packet:                  udpPacket,
		borrowedKernelPayload:   !copyPayload,
		encryptedKernelPayload:  encrypted && !kernelOpened,
		encryptedKernelFragment: encrypted && cryptoFragment && !kernelOpened,
	}, true
}

func (manager *Manager) startExperimentalTCPReceiverLocked() error {
	if manager.experimentalTCPProviderFastPathAvailableLocked() {
		return nil
	}
	if manager.expTCPRawFD >= 0 {
		return nil
	}
	if !experimentalTCPRawFallbackEnabled() {
		return fmt.Errorf("experimental_tcp raw socket fallback is disabled")
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		return fmt.Errorf("open experimental_tcp raw receiver socket: %w", err)
	}
	manager.expTCPRawFD = fd
	go manager.readExperimentalTCPFrames(fd)
	return nil
}

func (manager *Manager) readExperimentalTCPFrames(fd int) {
	parseTCP := experimentaltcp.ParseTCPShapedIPv4NoCopy
	if experimentalTCPSkipTCPChecksum() {
		parseTCP = experimentaltcp.ParseTCPShapedIPv4NoCopySkipTCPChecksum
	}
	batchSize := experimentalTCPRawFallbackRecvBatchSize()
	if batchSize <= 1 {
		manager.readExperimentalTCPFramesSingle(fd, parseTCP)
		return
	}
	manager.readExperimentalTCPFramesBatch(fd, batchSize, parseTCP)
}

func (manager *Manager) readExperimentalTCPFramesSingle(fd int, parseTCP func([]byte) (experimentaltcp.TCPPacket, error)) {
	buf := make([]byte, 128*1024)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return
		}
		manager.handleExperimentalTCPRawPacket(buf[:n], parseTCP)
	}
}

func (manager *Manager) readExperimentalTCPFramesBatch(fd int, batchSize int, parseTCP func([]byte) (experimentaltcp.TCPPacket, error)) {
	if batchSize <= 1 {
		manager.readExperimentalTCPFramesSingle(fd, parseTCP)
		return
	}
	buffers := make([][]byte, batchSize)
	iovs := make([]unix.Iovec, batchSize)
	msgs := make([]mmsghdr, batchSize)
	for i := range buffers {
		buffers[i] = make([]byte, 128*1024)
		iovs[i].Base = &buffers[i][0]
		iovs[i].SetLen(len(buffers[i]))
		msgs[i].hdr.Iov = &iovs[i]
		msgs[i].hdr.Iovlen = 1
	}
	for {
		for i := range msgs {
			msgs[i].len = 0
		}
		n, err := recvmmsg(fd, msgs, unix.MSG_WAITFORONE)
		if err != nil {
			if n <= 0 {
				return
			}
		}
		var batch []receivedExperimentalTCPFrame
		for i := 0; i < n; i++ {
			length := int(msgs[i].len)
			if length <= 0 || length > len(buffers[i]) {
				continue
			}
			if item, ok := manager.decodeExperimentalTCPRawPacket(buffers[i][:length], parseTCP); ok {
				batch = append(batch, item)
			}
		}
		if len(batch) > 0 {
			manager.deliverExperimentalTCPFrames(batch)
		}
	}
}

func (manager *Manager) handleExperimentalTCPRawPacket(raw []byte, parseTCP func([]byte) (experimentaltcp.TCPPacket, error)) {
	item, ok := manager.decodeExperimentalTCPRawPacket(raw, parseTCP)
	if !ok {
		return
	}
	manager.deliverExperimentalTCPFrames([]receivedExperimentalTCPFrame{item})
}

func (manager *Manager) decodeExperimentalTCPRawPacket(raw []byte, parseTCP func([]byte) (experimentaltcp.TCPPacket, error)) (receivedExperimentalTCPFrame, bool) {
	packet, err := parseTCP(raw)
	if err != nil {
		if errors.Is(err, experimentaltcp.ErrChecksum) {
			manager.recordDrop(observability.DropChecksumError)
		} else {
			manager.recordDrop(observability.DropInvalidOverlayHeader)
		}
		return receivedExperimentalTCPFrame{}, false
	}
	if len(packet.Payload) == 0 {
		return receivedExperimentalTCPFrame{}, false
	}
	frame, err := experimentaltcp.ParseFrameNoCopy(packet.Payload)
	if err != nil {
		manager.recordDrop(observability.DropInvalidOverlayHeader)
		return receivedExperimentalTCPFrame{}, false
	}
	payload := frame.Payload
	placement := dataplane.CryptoPlacementUserspace
	encrypted := frame.Flags&experimentaltcp.FlagEncrypted != 0
	kernelOpened := frame.Flags&experimentaltcp.FlagKernelOpened != 0
	cryptoFragment := frame.Flags&experimentaltcp.FlagCryptoFragment != 0
	innerIPv4 := frame.Flags&experimentaltcp.FlagInnerIPv4 != 0
	if kernelOpened {
		placement = dataplane.CryptoPlacementKernel
		payload = append([]byte(nil), payload...)
		innerIPv4 = innerIPv4 && kernelUDPInnerIPv4Eligible(payload)
		manager.recordExperimentalTCPKernelFrameOpened()
	} else if encrypted {
		if cryptoFragment && (frame.FragmentCount <= 1 || frame.FragmentIndex >= frame.FragmentCount) {
			manager.recordDrop(observability.DropInvalidOverlayHeader)
			return receivedExperimentalTCPFrame{}, false
		}
		placement = dataplane.CryptoPlacementKernel
	} else {
		payload = append([]byte(nil), payload...)
		innerIPv4 = innerIPv4 && kernelUDPInnerIPv4Eligible(payload)
	}
	openPlain, openRelease := kernelUDPOpenPlainBuffer(encrypted && !kernelOpened && !cryptoFragment, len(payload))
	return receivedExperimentalTCPFrame{
		frame: dataplane.ExperimentalTCPFrame{
			FlowID:          frame.FlowID,
			Direction:       dataplane.ExperimentalTCPInbound,
			Epoch:           frame.Epoch,
			Sequence:        frame.Sequence,
			FragmentIndex:   frame.FragmentIndex,
			FragmentCount:   frame.FragmentCount,
			Payload:         payload,
			Encrypted:       encrypted || kernelOpened,
			InnerIPv4:       innerIPv4,
			CryptoPlacement: placement,
		},
		packet:                  packet,
		kernelOpenPlain:         openPlain,
		kernelOpenPlainRelease:  openRelease,
		encryptedKernelPayload:  encrypted && !kernelOpened,
		encryptedKernelFragment: encrypted && cryptoFragment && !kernelOpened,
	}, true
}

func (manager *Manager) recordExperimentalTCPKernelFrameOpened() {
	manager.mu.Lock()
	manager.kernelCryptoFrameOpenAttempts++
	manager.kernelCryptoFrameOpenSuccesses++
	manager.mu.Unlock()
}

func (manager *Manager) openExperimentalTCPKernelFrame(flowID uint64, epoch uint64, sequence uint64, payload []byte) ([]byte, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if !manager.experimentalTCPKernelCryptoReadyLocked() {
		manager.kernelCryptoFrameOpenErrors++
		return nil, fmt.Errorf("experimental_tcp kernel crypto frame open requested but provider is not available: %s", manager.experimentalTCPKernelCryptoUnavailableReasonLocked())
	}
	headerSuiteID, _, headerEpoch, headerErr := kernelCryptoSecureFrameMetadata(payload, sequence)
	if headerErr != nil {
		manager.kernelCryptoFrameOpenErrors++
		return nil, headerErr
	}
	if epoch == 0 {
		epoch = headerEpoch
	}
	suiteID := headerSuiteID
	if flow, ok := manager.expTCPFlows[flowID]; ok {
		if flow.Epoch != 0 {
			epoch = flow.Epoch
		}
		if flow.CryptoSuite != "" {
			var err error
			suiteID, err = kernelCryptoSuiteID(flow.CryptoSuite)
			if err != nil {
				manager.kernelCryptoFrameOpenErrors++
				return nil, fmt.Errorf("experimental_tcp kernel crypto frame open suite %q is unsupported: %w", flow.CryptoSuite, err)
			}
		}
	}
	manager.kernelCryptoFrameOpenAttempts++
	if device := manager.kernelCryptoDeviceForFlowLocked(kernelCryptoNamespaceExperimentalTCP, flowID); device != nil {
		requests := []kernelCryptoDeviceOpenRequest{{
			FlowID:   flowID,
			SuiteID:  suiteID,
			Epoch:    epoch,
			Sequence: sequence,
			Payload:  payload,
		}}
		manager.kernelCryptoDeviceOpenAttempts++
		manager.observeKernelCryptoDeviceOpenBatchLocked(requests)
		result, err := device.OpenBatch(requests)
		if err == nil && len(result) == 1 {
			manager.kernelCryptoDeviceOpenSuccesses++
			manager.observeKernelCryptoDeviceOpenResultsLocked(result)
			manager.kernelCryptoFrameOpenSuccesses++
			return result[0].Plain, nil
		}
		manager.kernelCryptoDeviceOpenErrors++
		if isKernelCryptoReplayError(err) {
			manager.kernelCryptoFrameOpenErrors++
			manager.kernelCryptoFrameReplayDrops++
			return nil, err
		}
	}
	if !manager.kernelCryptoProductionReadyLocked() {
		manager.kernelCryptoFrameOpenErrors++
		return nil, fmt.Errorf("experimental_tcp kernel crypto frame open requested but BPF provider is not available: %s", manager.kernelCryptoUnavailableReasonLocked())
	}
	plaintext, err := manager.kernelCryptoProvider.OpenFrame(kernelCryptoFlowKeyFor(kernelCryptoNamespaceExperimentalTCP, flowID, kernelCryptoDirectionRecv), suiteID, epoch, sequence, payload)
	if err != nil {
		if isKernelCryptoReplayError(err) {
			manager.kernelCryptoFrameOpenErrors++
			manager.kernelCryptoFrameReplayDrops++
		} else if !isKernelCryptoNoContextError(err) {
			manager.kernelCryptoFrameOpenErrors++
		}
		return nil, err
	}
	manager.kernelCryptoFrameOpenSuccesses++
	return plaintext, nil
}

func (manager *Manager) openExperimentalTCPKernelFrameWithRetry(flowID uint64, epoch uint64, sequence uint64, payload []byte) ([]byte, error) {
	plaintext, err := manager.openExperimentalTCPKernelFrame(flowID, epoch, sequence, payload)
	for attempt := 0; err != nil && isKernelCryptoNoContextError(err) && attempt < kernelCryptoOpenRetryAttempts; attempt++ {
		time.Sleep(kernelCryptoOpenRetryDelay)
		plaintext, err = manager.openExperimentalTCPKernelFrame(flowID, epoch, sequence, payload)
	}
	return plaintext, err
}

func (manager *Manager) openReceivedExperimentalTCPFrames(frames []receivedExperimentalTCPFrame) ([]receivedExperimentalTCPFrame, bool) {
	if len(frames) == 0 {
		return frames, true
	}
	frames = manager.reassembleExperimentalTCPCryptoFragments(frames)
	if len(frames) == 0 {
		return frames, true
	}
	frames = manager.normalizeExperimentalTCPEncryptedRXBatch(frames)
	if len(frames) == 0 {
		return frames, true
	}
	hasEncryptedPayload := false
	for i := range frames {
		if frames[i].encryptedKernelPayload {
			hasEncryptedPayload = true
			break
		}
	}
	if !hasEncryptedPayload {
		return frames, true
	}
	var pendingByFlow map[uint64]*pendingKernelUDPOpenBatch
	var pendingSingleFlow uint64
	var pendingSingle *pendingKernelUDPOpenBatch
	manager.mu.Lock()
	for i := range frames {
		if !frames[i].encryptedKernelPayload {
			continue
		}
		frame := frames[i].frame
		headerSuiteID, headerSuite, headerEpoch, headerErr := kernelCryptoSecureFrameMetadata(frame.Payload, frame.Sequence)
		if headerErr != nil {
			manager.kernelCryptoFrameOpenErrors++
			manager.recordDropLocked(observability.DropCryptoFailed)
			manager.mu.Unlock()
			return nil, false
		}
		epoch := headerEpoch
		suite := headerSuite
		suiteID := headerSuiteID
		if flow, ok := manager.expTCPFlows[frame.FlowID]; ok {
			if flow.Epoch != 0 {
				epoch = flow.Epoch
			}
			if flow.CryptoSuite != "" {
				suite = flow.CryptoSuite
				var err error
				suiteID, err = kernelCryptoSuiteID(flow.CryptoSuite)
				if err != nil {
					manager.kernelCryptoFrameOpenErrors++
					manager.recordDropLocked(observability.DropCryptoFailed)
					manager.mu.Unlock()
					return nil, false
				}
			}
		}
		pending := kernelUDPOpenPendingBatchFor(&pendingByFlow, &pendingSingleFlow, &pendingSingle, frame.FlowID, len(frames))
		pending.indexes = append(pending.indexes, i)
		pending.requests = append(pending.requests, kernelCryptoDeviceOpenRequest{
			FlowID:   frame.FlowID,
			SuiteID:  suiteID,
			Epoch:    epoch,
			Sequence: frame.Sequence,
			Payload:  frame.Payload,
			Plain:    frames[i].kernelOpenPlain,
		})
		pending.suites = append(pending.suites, suite)
		pending.epochs = append(pending.epochs, epoch)
	}
	if len(pendingByFlow) == 0 && (pendingSingle == nil || len(pendingSingle.requests) == 0) {
		manager.mu.Unlock()
		return frames, true
	}
	if !manager.experimentalTCPKernelCryptoReadyLocked() {
		manager.kernelCryptoFrameOpenErrors++
		manager.recordDropLocked(observability.DropCryptoFailed)
		manager.mu.Unlock()
		return nil, false
	}
	manager.mu.Unlock()
	releaseFrame := func(index int) {
		if frames[index].frame.Release != nil {
			frames[index].frame.Release()
			frames[index].frame.Release = nil
		}
	}
	dropOpenedFrame := func(index int) {
		releaseFrame(index)
		if frames[index].kernelOpenPlainRelease != nil {
			frames[index].kernelOpenPlainRelease()
			frames[index].kernelOpenPlainRelease = nil
			frames[index].kernelOpenPlain = nil
		}
		frames[index].frame.Payload = nil
		frames[index].encryptedKernelPayload = true
	}
	recordDeviceFrameOpenDrop := func(index int, err error) {
		manager.mu.Lock()
		manager.kernelCryptoFrameOpenAttempts++
		manager.kernelCryptoFrameOpenErrors++
		if isKernelCryptoReplayError(err) {
			manager.kernelCryptoFrameReplayDrops++
			manager.recordDropLocked(observability.DropReplayDetected)
		} else {
			manager.recordDropLocked(observability.DropCryptoFailed)
		}
		manager.mu.Unlock()
		dropOpenedFrame(index)
	}
	applyPlainResult := func(index int, result kernelCryptoDeviceOpenResult) {
		openRelease := frames[index].kernelOpenPlainRelease
		if frames[index].kernelOpenPlainInPlace && openRelease == nil {
			openRelease = frames[index].frame.Release
		} else {
			releaseFrame(index)
		}
		if frames[index].kernelOpenPlainRelease != nil {
			frames[index].kernelOpenPlainRelease = nil
			frames[index].kernelOpenPlain = nil
		}
		plain := result.Plain
		frames[index].frame.Payload = plain
		frames[index].frame.CryptoSuite = result.Suite
		frames[index].frame.Epoch = result.Epoch
		frames[index].frame.CryptoPlacement = dataplane.CryptoPlacementKernel
		frames[index].frame.InnerIPv4 = frames[index].frame.InnerIPv4 && kernelUDPInnerIPv4Eligible(plain)
		frames[index].frame.Release = openRelease
		frames[index].encryptedKernelPayload = false
	}
	processPending := func(flowID uint64, pending *pendingKernelUDPOpenBatch) bool {
		if pending == nil || len(pending.requests) == 0 {
			return true
		}
		if sortPendingKernelUDPOpenBatchBySequence(pending) {
			manager.recordExperimentalTCPRXReorderedBatch()
		}
		var device *kernelCryptoDevice
		var provider *kernelCryptoProviderObject
		manager.mu.Lock()
		device = manager.kernelCryptoDeviceForFlowLocked(kernelCryptoNamespaceExperimentalTCP, flowID)
		provider = manager.kernelCryptoProvider
		manager.mu.Unlock()
		var openDeviceBatch func(requests []kernelCryptoDeviceOpenRequest, indexes []int) bool
		openDeviceBatch = func(requests []kernelCryptoDeviceOpenRequest, indexes []int) bool {
			if len(requests) == 0 {
				return true
			}
			manager.mu.Lock()
			manager.kernelCryptoDeviceOpenAttempts += uint64(len(requests))
			manager.observeKernelCryptoDeviceOpenBatchLocked(requests)
			manager.mu.Unlock()
			results, err := device.OpenBatch(requests)
			if err == nil {
				manager.mu.Lock()
				manager.kernelCryptoDeviceOpenSuccesses += uint64(len(results))
				manager.observeKernelCryptoDeviceOpenResultsLocked(results)
				manager.kernelCryptoFrameOpenAttempts += uint64(len(results))
				manager.kernelCryptoFrameOpenSuccesses += uint64(len(results))
				manager.mu.Unlock()
				for i, result := range results {
					applyPlainResult(indexes[i], result)
				}
				return true
			}
			var partial *kernelCryptoDeviceOpenBatchError
			if errors.As(err, &partial) && partial != nil && len(partial.Results) == len(requests) {
				successes := 0
				failedSet := make(map[int]struct{}, len(partial.Failed))
				for _, failed := range partial.Failed {
					failedSet[failed] = struct{}{}
				}
				for i, result := range partial.Results {
					if _, failed := failedSet[i]; failed || len(result.Plain) == 0 {
						continue
					}
					applyPlainResult(indexes[i], result)
					successes++
				}
				manager.mu.Lock()
				manager.kernelCryptoDeviceOpenSuccesses += uint64(successes)
				manager.observeKernelCryptoDeviceOpenResultsLocked(partial.Results)
				manager.kernelCryptoFrameOpenAttempts += uint64(successes)
				manager.kernelCryptoFrameOpenSuccesses += uint64(successes)
				manager.kernelCryptoDeviceOpenErrors += uint64(len(partial.Failed))
				manager.mu.Unlock()
				for _, failed := range partial.Failed {
					recordDeviceFrameOpenDrop(indexes[failed], partial.Err)
				}
				return true
			}
			manager.mu.Lock()
			manager.kernelCryptoDeviceOpenErrors += uint64(len(requests))
			manager.mu.Unlock()
			if len(requests) == 1 {
				recordDeviceFrameOpenDrop(indexes[0], err)
				return true
			}
			mid := len(requests) / 2
			return openDeviceBatch(requests[:mid], indexes[:mid]) &&
				openDeviceBatch(requests[mid:], indexes[mid:])
		}
		for start := 0; start < len(pending.requests); {
			end := min(start+kernelCryptoDeviceBatchMax, len(pending.requests))
			requests := pending.requests[start:end]
			indexes := pending.indexes[start:end]
			suites := pending.suites[start:end]
			epochs := pending.epochs[start:end]
			if device != nil {
				if experimentalTCPOpenBorrowedPoolEnabled() {
					manager.mu.Lock()
					manager.kernelCryptoDeviceOpenAttempts += uint64(len(requests))
					manager.observeKernelCryptoDeviceOpenBatchLocked(requests)
					manager.kernelCryptoDeviceOpenBorrowAttempts += uint64(len(requests))
					manager.mu.Unlock()
					results, release, err := device.OpenBatchBorrowed(requests)
					if err == nil {
						frameRelease := kernelUDPRefCountRelease(release, len(results))
						manager.mu.Lock()
						manager.kernelCryptoDeviceOpenBorrowSuccesses += uint64(len(results))
						manager.kernelCryptoDeviceOpenSuccesses += uint64(len(results))
						manager.observeKernelCryptoDeviceOpenResultsLocked(results)
						manager.kernelCryptoFrameOpenAttempts += uint64(len(results))
						manager.kernelCryptoFrameOpenSuccesses += uint64(len(results))
						manager.mu.Unlock()
						for i, result := range results {
							index := indexes[i]
							releaseFrame(index)
							if frames[index].kernelOpenPlainRelease != nil {
								frames[index].kernelOpenPlainRelease()
								frames[index].kernelOpenPlainRelease = nil
								frames[index].kernelOpenPlain = nil
							}
							frames[index].frame.Payload = result.Plain
							frames[index].frame.CryptoSuite = result.Suite
							frames[index].frame.Epoch = result.Epoch
							frames[index].frame.CryptoPlacement = dataplane.CryptoPlacementKernel
							frames[index].frame.InnerIPv4 = frames[index].frame.InnerIPv4 && kernelUDPInnerIPv4Eligible(result.Plain)
							frames[index].frame.Release = frameRelease
							frames[index].encryptedKernelPayload = false
						}
						start = end
						continue
					}
					manager.mu.Lock()
					manager.kernelCryptoDeviceOpenBorrowFallbacks += uint64(len(requests))
					manager.mu.Unlock()
				}
				if openDeviceBatch(requests, indexes) {
					start = end
					continue
				}
			}
			for i, request := range requests {
				manager.mu.Lock()
				manager.kernelCryptoFrameOpenAttempts++
				if provider == nil {
					manager.kernelCryptoFrameOpenErrors++
					manager.recordDropLocked(observability.DropCryptoFailed)
					manager.mu.Unlock()
					return false
				}
				plaintext, err := provider.OpenFrame(
					kernelCryptoFlowKeyFor(kernelCryptoNamespaceExperimentalTCP, request.FlowID, kernelCryptoDirectionRecv),
					request.SuiteID,
					request.Epoch,
					request.Sequence,
					request.Payload,
				)
				if err != nil {
					if isKernelCryptoReplayError(err) {
						manager.kernelCryptoFrameOpenErrors++
						manager.kernelCryptoFrameReplayDrops++
						manager.recordDropLocked(observability.DropReplayDetected)
					} else if !isKernelCryptoNoContextError(err) {
						manager.kernelCryptoFrameOpenErrors++
						manager.recordDropLocked(observability.DropCryptoFailed)
					}
					manager.mu.Unlock()
					dropOpenedFrame(indexes[i])
					continue
				}
				manager.kernelCryptoFrameOpenSuccesses++
				manager.mu.Unlock()
				index := indexes[i]
				releaseFrame(index)
				if frames[index].kernelOpenPlainRelease != nil {
					frames[index].kernelOpenPlainRelease()
					frames[index].kernelOpenPlainRelease = nil
					frames[index].kernelOpenPlain = nil
				}
				frames[index].frame.Payload = plaintext
				frames[index].frame.CryptoSuite = suites[i]
				frames[index].frame.Epoch = epochs[i]
				frames[index].frame.CryptoPlacement = dataplane.CryptoPlacementKernel
				frames[index].frame.InnerIPv4 = frames[index].frame.InnerIPv4 && kernelUDPInnerIPv4Eligible(plaintext)
				frames[index].encryptedKernelPayload = false
			}
			start = end
		}
		return true
	}
	if len(pendingByFlow) == 0 {
		if !processPending(pendingSingleFlow, pendingSingle) {
			return nil, false
		}
	} else {
		for flowID, pending := range pendingByFlow {
			if !processPending(flowID, pending) {
				return nil, false
			}
		}
	}
	opened := frames[:0]
	for i := range frames {
		if frames[i].encryptedKernelPayload {
			releaseFrame(i)
			if frames[i].kernelOpenPlainRelease != nil {
				frames[i].kernelOpenPlainRelease()
				frames[i].kernelOpenPlainRelease = nil
				frames[i].kernelOpenPlain = nil
			}
			continue
		}
		opened = append(opened, frames[i])
	}
	frames = opened
	if sortReceivedExperimentalTCPFramesBySequence(frames) {
		manager.recordExperimentalTCPRXReorderedBatch()
	}
	return frames, true
}

func (manager *Manager) normalizeExperimentalTCPEncryptedRXBatch(frames []receivedExperimentalTCPFrame) []receivedExperimentalTCPFrame {
	if len(frames) < 2 {
		return frames
	}
	encrypted := 0
	orderedUnique := true
	var previous experimentalTCPRXBatchKey
	havePrevious := false
	for i := range frames {
		if !frames[i].encryptedKernelPayload {
			continue
		}
		frame := frames[i].frame
		key := experimentalTCPRXBatchKey{
			flowID:        frame.FlowID,
			epoch:         frame.Epoch,
			sequence:      frame.Sequence,
			fragmentIndex: frame.FragmentIndex,
			fragmentCount: frame.FragmentCount,
		}
		encrypted++
		if havePrevious {
			if key.flowID < previous.flowID ||
				key.flowID == previous.flowID && (key.sequence < previous.sequence ||
					key.sequence == previous.sequence && key.fragmentIndex <= previous.fragmentIndex) {
				orderedUnique = false
				break
			}
		}
		previous = key
		havePrevious = true
	}
	if encrypted < 2 || orderedUnique {
		return frames
	}
	seen := make(map[experimentalTCPRXBatchKey]int, encrypted)
	for i := range frames {
		if !frames[i].encryptedKernelPayload {
			continue
		}
		frame := frames[i].frame
		key := experimentalTCPRXBatchKey{
			flowID:        frame.FlowID,
			epoch:         frame.Epoch,
			sequence:      frame.Sequence,
			fragmentIndex: frame.FragmentIndex,
			fragmentCount: frame.FragmentCount,
		}
		if previous, ok := seen[key]; ok {
			keep := previous
			drop := i
			if experimentalTCPRXBatchFramePreferred(frames[i], frames[previous]) {
				keep = i
				drop = previous
				seen[key] = i
			}
			_ = keep
			releaseReceivedExperimentalTCPFrames(frames[drop : drop+1])
			frames[drop].encryptedKernelPayload = false
			frames[drop].frame.Payload = nil
			manager.recordExperimentalTCPRXDuplicateDrop()
			continue
		}
		seen[key] = i
	}
	out := frames[:0]
	needCompact := false
	for i := range frames {
		if frames[i].frame.Payload == nil && !frames[i].encryptedKernelPayload {
			needCompact = true
			continue
		}
		out = append(out, frames[i])
	}
	if needCompact {
		frames = out
	}
	return frames
}

func sortPendingKernelUDPOpenBatchBySequence(pending *pendingKernelUDPOpenBatch) bool {
	if pending == nil || len(pending.requests) < 2 {
		return false
	}
	for i := 1; i < len(pending.requests); i++ {
		if pending.requests[i].Sequence < pending.requests[i-1].Sequence {
			sort.Stable(pendingKernelUDPOpenBatchSorter{pending: pending})
			return true
		}
	}
	return false
}

func sortReceivedExperimentalTCPFramesBySequence(frames []receivedExperimentalTCPFrame) bool {
	if len(frames) < 2 {
		return false
	}
	for i := 1; i < len(frames); i++ {
		left := frames[i-1].frame
		right := frames[i].frame
		if right.FlowID < left.FlowID ||
			right.FlowID == left.FlowID && (right.Sequence < left.Sequence ||
				right.Sequence == left.Sequence && right.FragmentIndex < left.FragmentIndex) {
			sort.SliceStable(frames, func(i, j int) bool {
				left := frames[i].frame
				right := frames[j].frame
				if left.FlowID != right.FlowID {
					return left.FlowID < right.FlowID
				}
				if left.Sequence != right.Sequence {
					return left.Sequence < right.Sequence
				}
				if left.FragmentIndex != right.FragmentIndex {
					return left.FragmentIndex < right.FragmentIndex
				}
				return left.FragmentCount < right.FragmentCount
			})
			return true
		}
	}
	return false
}

type pendingKernelUDPOpenBatchSorter struct {
	pending *pendingKernelUDPOpenBatch
}

func (sorter pendingKernelUDPOpenBatchSorter) Len() int {
	return len(sorter.pending.requests)
}

func (sorter pendingKernelUDPOpenBatchSorter) Less(i, j int) bool {
	left := sorter.pending.requests[i]
	right := sorter.pending.requests[j]
	if left.Sequence != right.Sequence {
		return left.Sequence < right.Sequence
	}
	if left.Epoch != right.Epoch {
		return left.Epoch < right.Epoch
	}
	return left.SuiteID < right.SuiteID
}

func (sorter pendingKernelUDPOpenBatchSorter) Swap(i, j int) {
	pending := sorter.pending
	pending.indexes[i], pending.indexes[j] = pending.indexes[j], pending.indexes[i]
	pending.requests[i], pending.requests[j] = pending.requests[j], pending.requests[i]
	pending.suites[i], pending.suites[j] = pending.suites[j], pending.suites[i]
	pending.epochs[i], pending.epochs[j] = pending.epochs[j], pending.epochs[i]
}

type experimentalTCPRXBatchKey struct {
	flowID        uint64
	epoch         uint64
	sequence      uint64
	fragmentIndex uint16
	fragmentCount uint16
}

func experimentalTCPRXBatchFramePreferred(candidate receivedExperimentalTCPFrame, current receivedExperimentalTCPFrame) bool {
	if len(candidate.frame.Payload) != len(current.frame.Payload) {
		return len(candidate.frame.Payload) > len(current.frame.Payload)
	}
	if candidate.kernelOpenPlainRelease != nil && current.kernelOpenPlainRelease == nil {
		return true
	}
	return false
}

func (manager *Manager) recordExperimentalTCPRXDuplicateDrop() {
	manager.mu.Lock()
	manager.expTCPRXDuplicateDrops++
	manager.recordDropLocked(observability.DropReplayDetected)
	manager.mu.Unlock()
}

func (manager *Manager) recordExperimentalTCPRXReorderedBatch() {
	manager.mu.Lock()
	manager.expTCPRXReorderedBatches++
	manager.mu.Unlock()
}

func (manager *Manager) openKernelUDPFrame(flowID uint64, sequence uint64, payload []byte) ([]byte, string, uint64, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if !manager.kernelUDPKernelCryptoReadyLocked() {
		manager.kernelCryptoFrameOpenErrors++
		return nil, "", 0, fmt.Errorf("kernel_udp kernel crypto frame open requested but provider is not available: %s", manager.kernelUDPKernelCryptoUnavailableReasonLocked())
	}
	headerSuiteID, headerSuite, headerEpoch, headerErr := kernelCryptoSecureFrameMetadata(payload, sequence)
	if headerErr != nil {
		manager.kernelCryptoFrameOpenErrors++
		return nil, "", 0, headerErr
	}
	flow, ok := manager.kernelUDPFlows[flowID]
	epoch := headerEpoch
	suite := headerSuite
	suiteID := headerSuiteID
	if ok {
		if flow.Epoch != 0 {
			epoch = flow.Epoch
		}
		if flow.CryptoSuite != "" {
			suite = flow.CryptoSuite
			var err error
			suiteID, err = kernelCryptoSuiteID(flow.CryptoSuite)
			if err != nil {
				manager.kernelCryptoFrameOpenErrors++
				return nil, "", 0, fmt.Errorf("kernel_udp kernel crypto frame open suite %q is unsupported: %w", flow.CryptoSuite, err)
			}
		}
	}
	manager.kernelCryptoFrameOpenAttempts++
	if device := manager.kernelCryptoDevices[flowID]; device != nil {
		requests := []kernelCryptoDeviceOpenRequest{{
			FlowID:   flowID,
			SuiteID:  suiteID,
			Epoch:    epoch,
			Sequence: sequence,
			Payload:  payload,
		}}
		manager.kernelCryptoDeviceOpenAttempts++
		manager.observeKernelCryptoDeviceOpenBatchLocked(requests)
		result, err := device.OpenBatch(requests)
		if err == nil && len(result) == 1 {
			manager.kernelCryptoDeviceOpenSuccesses++
			manager.observeKernelCryptoDeviceOpenResultsLocked(result)
			manager.kernelCryptoFrameOpenSuccesses++
			return result[0].Plain, result[0].Suite, result[0].Epoch, nil
		}
		manager.kernelCryptoDeviceOpenErrors++
		if isKernelCryptoReplayError(err) {
			manager.kernelCryptoFrameOpenErrors++
			manager.kernelCryptoFrameReplayDrops++
			return nil, "", 0, err
		}
	}
	if !manager.kernelCryptoProductionReadyLocked() {
		manager.kernelCryptoFrameOpenErrors++
		return nil, "", 0, fmt.Errorf("kernel_udp kernel crypto frame open requested but BPF provider is not available: %s", manager.kernelCryptoUnavailableReasonLocked())
	}
	plaintext, err := manager.kernelCryptoProvider.OpenFrame(kernelCryptoFlowKeyFor(kernelCryptoNamespaceKernelUDP, flowID, kernelCryptoDirectionRecv), suiteID, epoch, sequence, payload)
	if err != nil {
		if isKernelCryptoReplayError(err) {
			manager.kernelCryptoFrameOpenErrors++
			manager.kernelCryptoFrameReplayDrops++
		} else if !isKernelCryptoNoContextError(err) {
			manager.kernelCryptoFrameOpenErrors++
		}
		return nil, "", 0, err
	}
	manager.kernelCryptoFrameOpenSuccesses++
	return plaintext, suite, epoch, nil
}

func (manager *Manager) openKernelUDPFrameWithRetry(flowID uint64, sequence uint64, payload []byte) ([]byte, string, uint64, error) {
	plaintext, suite, epoch, err := manager.openKernelUDPFrame(flowID, sequence, payload)
	for attempt := 0; err != nil && isKernelCryptoNoContextError(err) && attempt < kernelCryptoOpenRetryAttempts; attempt++ {
		time.Sleep(kernelCryptoOpenRetryDelay)
		plaintext, suite, epoch, err = manager.openKernelUDPFrame(flowID, sequence, payload)
	}
	return plaintext, suite, epoch, err
}

func isKernelCryptoReplayError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "returned -114")
}

func isKernelCryptoNoContextError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "returned -2")
}

func (manager *Manager) deliverExperimentalTCPFrame(frame dataplane.ExperimentalTCPFrame, packet experimentaltcp.TCPPacket) {
	manager.deliverExperimentalTCPFrames([]receivedExperimentalTCPFrame{{frame: frame, packet: packet}})
}

func (manager *Manager) deliverExperimentalTCPFrames(frames []receivedExperimentalTCPFrame) {
	if len(frames) == 0 {
		return
	}
	originalFrames := frames
	var ok bool
	frames, ok = manager.openReceivedExperimentalTCPFrames(frames)
	if !ok || len(frames) == 0 {
		releaseReceivedExperimentalTCPFrames(originalFrames)
		return
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.expTCPFlows == nil {
		manager.expTCPFlows = make(map[uint64]dataplane.ExperimentalTCPFlow)
	}
	now := time.Now().UTC()
	var delivered []dataplane.ExperimentalTCPFrame
	var deliveredHolder *[]dataplane.ExperimentalTCPFrame
	txDirectSyncNeeded := false
	singleFlowHandled := false
	if experimentalTCPRXSingleFlowBatchEnabled() {
		deliveredHolder, delivered, singleFlowHandled = manager.prepareExperimentalTCPDeliveredSingleFlowLocked(frames, now)
	}
	if !singleFlowHandled {
		deliveredHolder, delivered = takeDeliveredExperimentalTCPFrameBatch(len(frames))
		for _, item := range frames {
			frame := item.frame
			packet := item.packet
			identity := manager.inferKernelTransportEndpointLocked("experimental_tcp", packet.SourceIP, packet.SourcePort, packet.DestinationIP, packet.DestinationPort)
			flow, ok := manager.expTCPFlows[frame.FlowID]
			if ok && experimentalTCPPacketMatchesLocalEcho(flow, packet) {
				releaseExperimentalTCPFramePayloads([]dataplane.ExperimentalTCPFrame{frame})
				continue
			}
			manager.recordExperimentalTCPOuterAcknowledgmentLocked(frame.FlowID, packet)
			if !ok {
				flow = dataplane.ExperimentalTCPFlow{
					ID:              frame.FlowID,
					LocalAddress:    net.JoinHostPort(packet.DestinationIP.String(), strconv.Itoa(int(packet.DestinationPort))),
					RemoteAddress:   net.JoinHostPort(packet.SourceIP.String(), strconv.Itoa(int(packet.SourcePort))),
					SourcePort:      packet.DestinationPort,
					DestinationPort: packet.SourcePort,
					CryptoPlacement: dataplane.CryptoPlacementUserspace,
					CreatedAt:       now,
				}
				manager.applyExperimentalTCPInboundIdentityLocked(&flow, frame, identity)
				flow = refreshExperimentalTCPFlowLifetime(flow, now)
				manager.expTCPFlows[frame.FlowID] = flow
				if err := manager.syncExperimentalTCPPortsLocked(); err != nil {
					manager.recordDropLocked(observability.DropEndpointDown)
					releaseExperimentalTCPFramePayloads(delivered)
					releaseExperimentalTCPFramePayloads([]dataplane.ExperimentalTCPFrame{frame})
					putDeliveredExperimentalTCPFrameBatch(deliveredHolder, delivered)
					return
				}
				txDirectSyncNeeded = true
			} else {
				flowChanged := false
				learnedLocal := net.JoinHostPort(packet.DestinationIP.String(), strconv.Itoa(int(packet.DestinationPort)))
				learnedRemote := net.JoinHostPort(packet.SourceIP.String(), strconv.Itoa(int(packet.SourcePort)))
				if flow.SourcePort != 0 && flow.DestinationPort != 0 &&
					flow.SourcePort == packet.DestinationPort && flow.DestinationPort == packet.SourcePort {
					if flow.LocalAddress == "" {
						flow.LocalAddress = learnedLocal
						flowChanged = true
					}
					if flow.RemoteAddress == "" {
						flow.RemoteAddress = learnedRemote
						flowChanged = true
					}
				} else {
					if flow.LocalAddress != learnedLocal {
						flow.LocalAddress = learnedLocal
						flowChanged = true
					}
					if flow.RemoteAddress != learnedRemote {
						flow.RemoteAddress = learnedRemote
						flowChanged = true
					}
				}
				if flow.SourcePort != packet.DestinationPort {
					flow.SourcePort = packet.DestinationPort
					flowChanged = true
				}
				if flow.DestinationPort != packet.SourcePort {
					flow.DestinationPort = packet.SourcePort
					flowChanged = true
				}
				if manager.applyExperimentalTCPInboundIdentityLocked(&flow, frame, identity) {
					flowChanged = true
					txDirectSyncNeeded = true
				}
				flow = refreshExperimentalTCPFlowLifetime(flow, now)
				manager.expTCPFlows[frame.FlowID] = flow
				if flowChanged {
					manager.invalidateExperimentalTCPTXTemplateLocked(frame.FlowID)
					manager.updateExperimentalTCPTelemetryIdentityLocked(frame.FlowID, flow)
					if err := manager.syncExperimentalTCPPortsLocked(); err != nil {
						manager.recordDropLocked(observability.DropEndpointDown)
						releaseExperimentalTCPFramePayloads(delivered)
						releaseExperimentalTCPFramePayloads([]dataplane.ExperimentalTCPFrame{frame})
						putDeliveredExperimentalTCPFrameBatch(deliveredHolder, delivered)
						return
					}
					txDirectSyncNeeded = true
				}
			}
			frame.Peer = flow.Peer
			frame.Endpoint = experimentalTCPInboundDeliveryEndpoint(frame.Endpoint, identity, flow.Endpoint)
			manager.experimentalTCPTelemetryLocked(frame.FlowID, flow).ObserveRX(frame.Sequence, len(frame.Payload), now)
			manager.expTCPReceived++
			delivered = append(delivered, frame)
		}
	}
	if txDirectSyncNeeded {
		if err := manager.syncKernelUDPTXDirectLocked(); err != nil {
			manager.recordDropLocked(observability.DropEndpointDown)
			manager.warnings = append(manager.warnings, "kernel_udp TC TX direct sync after experimental_tcp RX flow update failed: "+err.Error())
			releaseExperimentalTCPFramePayloads(delivered)
			putDeliveredExperimentalTCPFrameBatch(deliveredHolder, delivered)
			return
		}
	}
	if len(delivered) == 0 {
		putDeliveredExperimentalTCPFrameBatch(deliveredHolder, delivered)
		return
	}
	manager.prepareExperimentalTCPDeliveredReleasesLocked(delivered)
	manager.prepareExperimentalTCPDeliveredBatchReleaseLocked(delivered, deliveredHolder)
	if len(manager.expTCPFlowSubs) > 0 {
		if _, subscribers, ok := experimentalTCPSingleFlowSubscriberSet(delivered, manager.expTCPFlowSubs); ok {
			for subscriber := range subscribers {
				select {
				case subscriber <- delivered:
				default:
					manager.expTCPSubDrops += uint64(len(delivered))
					releaseExperimentalTCPFramePayloads(delivered)
				}
			}
		} else {
			var byFlow map[uint64][]dataplane.ExperimentalTCPFrame
			for _, frame := range delivered {
				if len(manager.expTCPFlowSubs[frame.FlowID]) > 0 {
					if byFlow == nil {
						byFlow = make(map[uint64][]dataplane.ExperimentalTCPFrame)
					}
					byFlow[frame.FlowID] = append(byFlow[frame.FlowID], frame)
				}
			}
			for flowID, batch := range byFlow {
				for subscriber := range manager.expTCPFlowSubs[flowID] {
					select {
					case subscriber <- batch:
					default:
						manager.expTCPSubDrops += uint64(len(batch))
						releaseExperimentalTCPFramePayloads(batch)
					}
				}
			}
		}
	}
	for subscriber := range manager.expTCPSubs {
		select {
		case subscriber <- delivered:
		default:
			manager.expTCPSubDrops += uint64(len(delivered))
			releaseExperimentalTCPFramePayloads(delivered)
		}
	}
}

func (manager *Manager) prepareExperimentalTCPDeliveredSingleFlowLocked(frames []receivedExperimentalTCPFrame, now time.Time) (*[]dataplane.ExperimentalTCPFrame, []dataplane.ExperimentalTCPFrame, bool) {
	if len(frames) < 2 {
		return nil, nil, false
	}
	first := frames[0]
	firstFrame := first.frame
	firstPacket := first.packet
	identity := manager.inferKernelTransportEndpointLocked("experimental_tcp", firstPacket.SourceIP, firstPacket.SourcePort, firstPacket.DestinationIP, firstPacket.DestinationPort)
	flow, ok := manager.expTCPFlows[firstFrame.FlowID]
	if !ok || flow.LocalAddress == "" || flow.RemoteAddress == "" || flow.SourcePort == 0 || flow.DestinationPort == 0 {
		return nil, nil, false
	}
	if flow.SourcePort != firstPacket.DestinationPort || flow.DestinationPort != firstPacket.SourcePort {
		return nil, nil, false
	}
	if experimentalTCPPacketMatchesLocalEcho(flow, firstPacket) {
		return nil, nil, false
	}
	if manager.experimentalTCPInboundIdentityWouldUpdateLocked(flow, firstFrame, identity) {
		return nil, nil, false
	}
	bytes := uint64(0)
	wireFrames := uint64(0)
	sequential := firstFrame.Sequence != 0
	previousSequenceEnd := firstFrame.Sequence + first.experimentalTCPWireSequenceCount() - 1
	if previousSequenceEnd < firstFrame.Sequence {
		sequential = false
		previousSequenceEnd = firstFrame.Sequence
	}
	for i := range frames {
		frame := frames[i].frame
		packet := frames[i].packet
		wireSequenceCount := frames[i].experimentalTCPWireSequenceCount()
		if frame.FlowID != firstFrame.FlowID ||
			packet.SourceIP != firstPacket.SourceIP ||
			packet.DestinationIP != firstPacket.DestinationIP ||
			packet.SourcePort != firstPacket.SourcePort ||
			packet.DestinationPort != firstPacket.DestinationPort {
			return nil, nil, false
		}
		if i > 0 {
			if !sequential || frame.Sequence == 0 || frame.Sequence != previousSequenceEnd+1 {
				sequential = false
			}
			previousSequenceEnd = frame.Sequence + wireSequenceCount - 1
			if previousSequenceEnd < frame.Sequence {
				sequential = false
				previousSequenceEnd = frame.Sequence
			}
		}
		wireFrames += wireSequenceCount
		if len(frame.Payload) > 0 {
			bytes += uint64(len(frame.Payload))
		}
		manager.recordExperimentalTCPOuterAcknowledgmentLocked(frame.FlowID, packet)
	}
	flow = refreshExperimentalTCPFlowLifetime(flow, now)
	manager.expTCPFlows[firstFrame.FlowID] = flow
	holder, delivered := takeDeliveredExperimentalTCPFrameBatch(len(frames))
	for _, item := range frames {
		frame := item.frame
		frame.Peer = flow.Peer
		frame.Endpoint = experimentalTCPInboundDeliveryEndpoint(frame.Endpoint, identity, flow.Endpoint)
		delivered = append(delivered, frame)
	}
	telemetry := manager.experimentalTCPTelemetryLocked(firstFrame.FlowID, flow)
	if sequential {
		telemetry.ObserveRXBatchSpan(firstFrame.Sequence, uint64(len(frames)), wireFrames, bytes, now)
	} else {
		for i, frame := range delivered {
			telemetry.ObserveRXSpan(frame.Sequence, frames[i].experimentalTCPWireSequenceCount(), len(frame.Payload), now)
		}
	}
	manager.expTCPReceived += uint64(len(frames))
	return holder, delivered, true
}

func (item receivedExperimentalTCPFrame) experimentalTCPWireSequenceCount() uint64 {
	if item.wireSequenceCount == 0 {
		return 1
	}
	return item.wireSequenceCount
}

func experimentalTCPSingleFlowSubscriberSet(frames []dataplane.ExperimentalTCPFrame, flowSubs map[uint64]map[chan []dataplane.ExperimentalTCPFrame]struct{}) (uint64, map[chan []dataplane.ExperimentalTCPFrame]struct{}, bool) {
	if len(frames) == 0 {
		return 0, nil, false
	}
	flowID := frames[0].FlowID
	subscribers := flowSubs[flowID]
	if len(subscribers) == 0 {
		return flowID, nil, false
	}
	for _, frame := range frames[1:] {
		if frame.FlowID != flowID {
			return 0, nil, false
		}
	}
	return flowID, subscribers, true
}

func experimentalTCPPacketMatchesLocalEcho(flow dataplane.ExperimentalTCPFlow, packet experimentaltcp.TCPPacket) bool {
	if flow.SourcePort == 0 || flow.DestinationPort == 0 {
		return false
	}
	if flow.SourcePort != packet.SourcePort || flow.DestinationPort != packet.DestinationPort {
		return false
	}
	localIP, localPort, err := resolveExperimentalTCPAddress(flow.LocalAddress)
	if err != nil {
		return false
	}
	remoteIP, remotePort, err := resolveExperimentalTCPAddress(flow.RemoteAddress)
	if err != nil {
		return false
	}
	return localPort == packet.SourcePort &&
		remotePort == packet.DestinationPort &&
		localIP == packet.SourceIP &&
		remoteIP == packet.DestinationIP
}

func (manager *Manager) prepareExperimentalTCPDeliveredReleasesLocked(frames []dataplane.ExperimentalTCPFrame) {
	for i := range frames {
		release := frames[i].Release
		if release == nil {
			continue
		}
		flowRecipients := 0
		if subs := manager.expTCPFlowSubs[frames[i].FlowID]; subs != nil {
			flowRecipients = len(subs)
		}
		recipients := len(manager.expTCPSubs) + flowRecipients
		switch {
		case recipients == 0:
			release()
			frames[i].Release = nil
		case recipients > 1:
			frames[i].Release = kernelUDPRefCountRelease(release, recipients)
		}
	}
}

func (manager *Manager) prepareExperimentalTCPDeliveredBatchReleaseLocked(frames []dataplane.ExperimentalTCPFrame, holder *[]dataplane.ExperimentalTCPFrame) {
	if holder == nil || len(frames) == 0 {
		putDeliveredExperimentalTCPFrameBatch(holder, frames)
		return
	}
	totalFrameReleases := 0
	frameRecipients := make([]int, len(frames))
	for i := range frames {
		flowRecipients := 0
		if subs := manager.expTCPFlowSubs[frames[i].FlowID]; subs != nil {
			flowRecipients = len(subs)
		}
		recipients := len(manager.expTCPSubs) + flowRecipients
		frameRecipients[i] = recipients
		totalFrameReleases += recipients
	}
	if totalFrameReleases <= 0 {
		putDeliveredExperimentalTCPFrameBatch(holder, frames)
		return
	}
	releaseBatch := kernelUDPRefCountRelease(func() {
		putDeliveredExperimentalTCPFrameBatch(holder, frames)
	}, totalFrameReleases)
	for i := range frames {
		if frameRecipients[i] <= 0 {
			continue
		}
		release := frames[i].Release
		if release == nil {
			frames[i].Release = releaseBatch
			continue
		}
		frames[i].Release = func() {
			release()
			releaseBatch()
		}
	}
}

func releaseExperimentalTCPFramePayloads(frames []dataplane.ExperimentalTCPFrame) {
	for i := range frames {
		if frames[i].Release != nil {
			frames[i].Release()
		}
	}
}

func releaseReceivedExperimentalTCPFrames(frames []receivedExperimentalTCPFrame) {
	for i := range frames {
		if frames[i].frame.Release != nil {
			frames[i].frame.Release()
			frames[i].frame.Release = nil
		}
		if frames[i].kernelOpenPlainRelease != nil {
			frames[i].kernelOpenPlainRelease()
			frames[i].kernelOpenPlainRelease = nil
			frames[i].kernelOpenPlain = nil
		}
	}
}

func (manager *Manager) reassembleExperimentalTCPCryptoFragments(frames []receivedExperimentalTCPFrame) []receivedExperimentalTCPFrame {
	var out []receivedExperimentalTCPFrame
	var now time.Time
	for frameIndex := 0; frameIndex < len(frames); frameIndex++ {
		item := frames[frameIndex]
		if item.wireSequenceCount == 0 {
			item.wireSequenceCount = 1
		}
		if !item.encryptedKernelFragment {
			if out != nil {
				out = append(out, item)
			}
			continue
		}
		if out == nil {
			out = make([]receivedExperimentalTCPFrame, 0, len(frames))
			for _, previous := range frames[:frameIndex] {
				out = append(out, previous)
			}
		}
		if completed, consumed, ok := reassembleExperimentalTCPCryptoFragmentRun(frames[frameIndex:]); ok {
			out = append(out, completed)
			frameIndex += consumed - 1
			continue
		}
		if now.IsZero() {
			now = time.Now()
		}
		if completed, ok := manager.ingestExperimentalTCPCryptoFragment(item, now); ok {
			out = append(out, completed)
		}
	}
	if out == nil {
		return frames
	}
	return out
}

func reassembleExperimentalTCPCryptoFragmentRun(frames []receivedExperimentalTCPFrame) (receivedExperimentalTCPFrame, int, bool) {
	if len(frames) == 0 || !frames[0].encryptedKernelFragment {
		return receivedExperimentalTCPFrame{}, 0, false
	}
	first := frames[0]
	firstFrame := first.frame
	count := int(firstFrame.FragmentCount)
	if count <= 1 {
		item := first
		frame := firstFrame
		frame.FragmentIndex = 0
		frame.FragmentCount = 0
		frame.FragmentPayloadSize = 0
		item.frame = frame
		item.encryptedKernelFragment = false
		item.wireSequenceCount = 1
		return item, 1, true
	}
	if count > 256 ||
		firstFrame.FragmentIndex != 0 ||
		firstFrame.Sequence < uint64(firstFrame.FragmentIndex) ||
		len(frames) < count {
		return receivedExperimentalTCPFrame{}, 0, false
	}
	baseSeq := firstFrame.Sequence
	fragmentPayloadSize := len(firstFrame.Payload)
	if fragmentPayloadSize == 0 {
		return receivedExperimentalTCPFrame{}, 0, false
	}
	totalLen := 0
	innerIPv4 := firstFrame.InnerIPv4
	for index := 0; index < count; index++ {
		item := frames[index]
		frame := item.frame
		if !item.encryptedKernelFragment ||
			frame.FlowID != firstFrame.FlowID ||
			frame.Epoch != firstFrame.Epoch ||
			frame.FragmentCount != firstFrame.FragmentCount ||
			frame.FragmentIndex != uint16(index) ||
			frame.Sequence < uint64(frame.FragmentIndex) ||
			frame.Sequence != baseSeq+uint64(index) {
			return receivedExperimentalTCPFrame{}, 0, false
		}
		payloadLen := len(frame.Payload)
		if index < count-1 {
			if payloadLen != fragmentPayloadSize {
				return receivedExperimentalTCPFrame{}, 0, false
			}
		} else if payloadLen > fragmentPayloadSize {
			return receivedExperimentalTCPFrame{}, 0, false
		}
		innerIPv4 = innerIPv4 || frame.InnerIPv4
		totalLen += payloadLen
		if totalLen > experimentalTCPCryptoFragmentAssembledMaxPayload() {
			return receivedExperimentalTCPFrame{}, 0, false
		}
	}
	payload, releasePayload := takeExperimentalTCPCryptoFragmentPayload(totalLen)
	offset := 0
	for index := 0; index < count; index++ {
		fragmentPayload := frames[index].frame.Payload
		offset += copy(payload[offset:], fragmentPayload)
	}
	completeFrame := firstFrame
	completeFrame.Sequence = baseSeq
	completeFrame.FragmentIndex = 0
	completeFrame.FragmentCount = 0
	completeFrame.FragmentPayloadSize = 0
	completeFrame.Payload = payload
	completeFrame.Encrypted = true
	completeFrame.InnerIPv4 = innerIPv4
	completeFrame.CryptoPlacement = dataplane.CryptoPlacementKernel
	completeFrame.Release = nil
	return receivedExperimentalTCPFrame{
		frame:                  completeFrame,
		packet:                 first.packet,
		kernelOpenPlain:        experimentalTCPCryptoFragmentPlainBuffer(payload),
		kernelOpenPlainRelease: releasePayload,
		encryptedKernelPayload: true,
		wireSequenceCount:      uint64(count),
	}, count, true
}

func (manager *Manager) ingestExperimentalTCPCryptoFragment(item receivedExperimentalTCPFrame, now time.Time) (receivedExperimentalTCPFrame, bool) {
	frame := item.frame
	if frame.FragmentCount <= 1 {
		frame.FragmentIndex = 0
		frame.FragmentCount = 0
		frame.FragmentPayloadSize = 0
		item.frame = frame
		item.encryptedKernelFragment = false
		item.wireSequenceCount = 1
		return item, true
	}
	if frame.FragmentCount > 256 || frame.FragmentIndex >= frame.FragmentCount ||
		frame.Sequence < uint64(frame.FragmentIndex) {
		manager.recordDrop(observability.DropInvalidOverlayHeader)
		return receivedExperimentalTCPFrame{}, false
	}
	baseSeq := frame.Sequence - uint64(frame.FragmentIndex)
	key := experimentalTCPCryptoFragmentKey{flowID: frame.FlowID, sequence: baseSeq}
	manager.mu.Lock()
	manager.pruneExperimentalTCPCryptoFragmentsLocked(now)
	if manager.expTCPCryptoFragments == nil {
		manager.expTCPCryptoFragments = make(map[experimentalTCPCryptoFragmentKey]*experimentalTCPCryptoFragmentAssembly)
	}
	assembly := manager.expTCPCryptoFragments[key]
	count := int(frame.FragmentCount)
	if assembly == nil {
		assembly = &experimentalTCPCryptoFragmentAssembly{
			createdAt:         now,
			frame:             frame,
			packet:            item.packet,
			innerIPv4:         frame.InnerIPv4,
			receivedFragments: make([]bool, count),
		}
		manager.expTCPCryptoFragments[key] = assembly
	} else if frame.InnerIPv4 {
		assembly.innerIPv4 = true
	}
	if len(assembly.receivedFragments) != count {
		delete(manager.expTCPCryptoFragments, key)
		manager.recordDropLocked(observability.DropInvalidOverlayHeader)
		manager.mu.Unlock()
		return receivedExperimentalTCPFrame{}, false
	}
	completed, invalid := assembly.addExperimentalTCPCryptoFragmentLocked(frame.FragmentIndex, frame.Payload)
	if invalid {
		delete(manager.expTCPCryptoFragments, key)
		manager.recordDropLocked(observability.DropInvalidOverlayHeader)
		manager.mu.Unlock()
		return receivedExperimentalTCPFrame{}, false
	}
	if !completed {
		manager.mu.Unlock()
		return receivedExperimentalTCPFrame{}, false
	}
	delete(manager.expTCPCryptoFragments, key)
	completeFrame := assembly.frame
	completeFrame.Sequence = baseSeq
	completeFrame.FragmentIndex = 0
	completeFrame.FragmentCount = 0
	completeFrame.FragmentPayloadSize = 0
	completeFrame.Payload = assembly.payload[:assembly.totalLen]
	completeFrame.Encrypted = true
	completeFrame.InnerIPv4 = assembly.innerIPv4
	completeFrame.CryptoPlacement = dataplane.CryptoPlacementKernel
	completeFrame.Release = nil
	packet := assembly.packet
	manager.mu.Unlock()
	return receivedExperimentalTCPFrame{
		frame:                  completeFrame,
		packet:                 packet,
		encryptedKernelPayload: true,
		wireSequenceCount:      uint64(count),
	}, true
}

func (assembly *experimentalTCPCryptoFragmentAssembly) addExperimentalTCPCryptoFragmentLocked(fragmentIndex uint16, payload []byte) (bool, bool) {
	count := len(assembly.receivedFragments)
	index := int(fragmentIndex)
	if count == 0 || index < 0 || index >= count {
		return false, true
	}
	if assembly.receivedFragments[index] {
		return false, false
	}
	lastIndex := count - 1
	if index < lastIndex {
		if len(payload) == 0 || !assembly.ensureExperimentalTCPCryptoFragmentPayloadLocked(count, len(payload)) {
			return false, true
		}
	} else if assembly.fragmentPayloadSize > 0 && len(payload) > assembly.fragmentPayloadSize {
		return false, true
	}
	if assembly.payload == nil {
		if assembly.pending == nil {
			assembly.pending = make([][]byte, count)
		}
		assembly.pending[index] = append([]byte(nil), payload...)
	} else if !assembly.copyExperimentalTCPCryptoFragmentPayloadLocked(index, payload) {
		return false, true
	}
	assembly.receivedFragments[index] = true
	assembly.received++
	assembly.totalLen += len(payload)
	if index == lastIndex {
		assembly.lastFragmentLen = len(payload)
	}
	if assembly.received != count {
		return false, false
	}
	if assembly.payload == nil || assembly.totalLen > len(assembly.payload) || assembly.totalLen > experimentalTCPCryptoFragmentAssembledMaxPayload() {
		return false, true
	}
	return true, false
}

func (assembly *experimentalTCPCryptoFragmentAssembly) ensureExperimentalTCPCryptoFragmentPayloadLocked(count int, fragmentPayloadSize int) bool {
	if count <= 0 || fragmentPayloadSize <= 0 {
		return false
	}
	if assembly.fragmentPayloadSize != 0 {
		return assembly.fragmentPayloadSize == fragmentPayloadSize
	}
	allocLen := count * fragmentPayloadSize
	if allocLen > experimentalTCPCryptoFragmentAssembledMaxPayload()+fragmentPayloadSize {
		return false
	}
	assembly.fragmentPayloadSize = fragmentPayloadSize
	assembly.payload = make([]byte, allocLen)
	for index, pending := range assembly.pending {
		if pending == nil {
			continue
		}
		if !assembly.copyExperimentalTCPCryptoFragmentPayloadLocked(index, pending) {
			return false
		}
		assembly.pending[index] = nil
	}
	return true
}

func (assembly *experimentalTCPCryptoFragmentAssembly) copyExperimentalTCPCryptoFragmentPayloadLocked(index int, payload []byte) bool {
	if assembly.payload == nil || assembly.fragmentPayloadSize <= 0 {
		return false
	}
	count := len(assembly.receivedFragments)
	lastIndex := count - 1
	if index < 0 || index >= count {
		return false
	}
	if index < lastIndex {
		if len(payload) != assembly.fragmentPayloadSize {
			return false
		}
	} else if len(payload) > assembly.fragmentPayloadSize {
		return false
	}
	offset := index * assembly.fragmentPayloadSize
	if offset < 0 || offset > len(assembly.payload) || len(payload) > len(assembly.payload)-offset {
		return false
	}
	copy(assembly.payload[offset:offset+len(payload)], payload)
	return true
}

func (manager *Manager) pruneExperimentalTCPCryptoFragmentsLocked(now time.Time) {
	const ttl = 30 * time.Second
	for key, assembly := range manager.expTCPCryptoFragments {
		if assembly == nil || now.Sub(assembly.createdAt) > ttl {
			delete(manager.expTCPCryptoFragments, key)
		}
	}
}

func (manager *Manager) deliverKernelUDPFrame(frame dataplane.KernelUDPFrame, packet kerneludp.UDPPacket) {
	manager.deliverKernelUDPFrames([]receivedKernelUDPFrame{{frame: frame, packet: packet}})
}

func (manager *Manager) reassembleKernelUDPCryptoFragments(frames []receivedKernelUDPFrame) []receivedKernelUDPFrame {
	var out []receivedKernelUDPFrame
	var now time.Time
	for frameIndex := 0; frameIndex < len(frames); frameIndex++ {
		item := frames[frameIndex]
		if item.wireSequenceCount == 0 {
			item.wireSequenceCount = 1
		}
		if !item.encryptedKernelFragment {
			if out != nil {
				out = append(out, item)
			}
			continue
		}
		if out == nil {
			out = make([]receivedKernelUDPFrame, 0, len(frames))
			for _, previous := range frames[:frameIndex] {
				out = append(out, previous)
			}
		}
		if completed, consumed, ok := reassembleKernelUDPCryptoFragmentRun(frames[frameIndex:]); ok {
			out = append(out, completed)
			frameIndex += consumed - 1
			continue
		}
		if now.IsZero() {
			now = time.Now()
		}
		if completed, ok := manager.ingestKernelUDPCryptoFragment(item, now); ok {
			out = append(out, completed)
		}
	}
	if out == nil {
		return frames
	}
	return out
}

func reassembleKernelUDPCryptoFragmentRun(frames []receivedKernelUDPFrame) (receivedKernelUDPFrame, int, bool) {
	if len(frames) == 0 || !frames[0].encryptedKernelFragment {
		return receivedKernelUDPFrame{}, 0, false
	}
	first := frames[0]
	firstFrame := first.frame
	count := int(firstFrame.FragmentCount)
	if count <= 1 {
		item := first
		frame := firstFrame
		frame.FragmentIndex = 0
		frame.FragmentCount = 0
		frame.FragmentPayloadSize = 0
		item.frame = frame
		item.encryptedKernelFragment = false
		item.wireSequenceCount = 1
		return item, 1, true
	}
	if count > 256 ||
		firstFrame.FragmentIndex != 0 ||
		firstFrame.Sequence < uint64(firstFrame.FragmentIndex) ||
		len(frames) < count {
		return receivedKernelUDPFrame{}, 0, false
	}
	baseSeq := firstFrame.Sequence
	fragmentPayloadSize := len(firstFrame.Payload)
	if fragmentPayloadSize == 0 {
		return receivedKernelUDPFrame{}, 0, false
	}
	totalLen := 0
	for index := 0; index < count; index++ {
		item := frames[index]
		frame := item.frame
		if !item.encryptedKernelFragment ||
			frame.FlowID != firstFrame.FlowID ||
			frame.FragmentCount != firstFrame.FragmentCount ||
			frame.FragmentIndex != uint16(index) ||
			frame.Sequence < uint64(frame.FragmentIndex) ||
			frame.Sequence != baseSeq+uint64(index) {
			return receivedKernelUDPFrame{}, 0, false
		}
		payloadLen := len(frame.Payload)
		if index < count-1 {
			if payloadLen != fragmentPayloadSize {
				return receivedKernelUDPFrame{}, 0, false
			}
		} else if payloadLen > fragmentPayloadSize {
			return receivedKernelUDPFrame{}, 0, false
		}
		totalLen += payloadLen
		if totalLen > kernelUDPCryptoFragmentAssembledMaxPayload() {
			return receivedKernelUDPFrame{}, 0, false
		}
	}
	payload := make([]byte, totalLen)
	offset := 0
	for index := 0; index < count; index++ {
		fragmentPayload := frames[index].frame.Payload
		offset += copy(payload[offset:], fragmentPayload)
	}
	completeFrame := firstFrame
	completeFrame.Sequence = baseSeq
	completeFrame.FragmentIndex = 0
	completeFrame.FragmentCount = 0
	completeFrame.FragmentPayloadSize = 0
	completeFrame.Payload = payload
	if firstFrame.InnerIPv4 {
		completeFrame.InnerIPv4 = true
	}
	return receivedKernelUDPFrame{
		frame:                  completeFrame,
		packet:                 first.packet,
		encryptedKernelPayload: true,
		wireSequenceCount:      uint64(count),
	}, count, true
}

func (manager *Manager) ingestKernelUDPCryptoFragment(item receivedKernelUDPFrame, now time.Time) (receivedKernelUDPFrame, bool) {
	frame := item.frame
	if frame.FragmentCount <= 1 {
		frame.FragmentIndex = 0
		frame.FragmentCount = 0
		frame.FragmentPayloadSize = 0
		item.frame = frame
		item.encryptedKernelFragment = false
		item.wireSequenceCount = 1
		return item, true
	}
	if frame.FragmentCount > 256 || frame.FragmentIndex >= frame.FragmentCount ||
		frame.Sequence < uint64(frame.FragmentIndex) {
		manager.recordDrop(observability.DropInvalidOverlayHeader)
		return receivedKernelUDPFrame{}, false
	}
	baseSeq := frame.Sequence - uint64(frame.FragmentIndex)
	key := kernelUDPCryptoFragmentKey{flowID: frame.FlowID, sequence: baseSeq}
	manager.mu.Lock()
	manager.pruneKernelUDPCryptoFragmentsLocked(now)
	if manager.kernelUDPCryptoFragments == nil {
		manager.kernelUDPCryptoFragments = make(map[kernelUDPCryptoFragmentKey]*kernelUDPCryptoFragmentAssembly)
	}
	assembly := manager.kernelUDPCryptoFragments[key]
	count := int(frame.FragmentCount)
	if assembly == nil {
		assembly = &kernelUDPCryptoFragmentAssembly{
			createdAt:         now,
			frame:             frame,
			packet:            item.packet,
			innerIPv4:         frame.InnerIPv4,
			receivedFragments: make([]bool, count),
		}
		manager.kernelUDPCryptoFragments[key] = assembly
	} else if frame.InnerIPv4 {
		assembly.innerIPv4 = true
	}
	if len(assembly.receivedFragments) != count {
		delete(manager.kernelUDPCryptoFragments, key)
		manager.recordDropLocked(observability.DropInvalidOverlayHeader)
		manager.mu.Unlock()
		return receivedKernelUDPFrame{}, false
	}
	completed, invalid := assembly.addKernelUDPCryptoFragmentLocked(frame.FragmentIndex, frame.Payload)
	if invalid {
		delete(manager.kernelUDPCryptoFragments, key)
		manager.recordDropLocked(observability.DropInvalidOverlayHeader)
		manager.mu.Unlock()
		return receivedKernelUDPFrame{}, false
	}
	if !completed {
		manager.mu.Unlock()
		return receivedKernelUDPFrame{}, false
	}
	delete(manager.kernelUDPCryptoFragments, key)
	completeFrame := assembly.frame
	completeFrame.Sequence = baseSeq
	completeFrame.FragmentIndex = 0
	completeFrame.FragmentCount = 0
	completeFrame.FragmentPayloadSize = 0
	completeFrame.Payload = assembly.payload[:assembly.totalLen]
	completeFrame.InnerIPv4 = assembly.innerIPv4
	packet := assembly.packet
	manager.mu.Unlock()
	return receivedKernelUDPFrame{
		frame:                  completeFrame,
		packet:                 packet,
		encryptedKernelPayload: true,
		wireSequenceCount:      uint64(count),
	}, true
}

func (assembly *kernelUDPCryptoFragmentAssembly) addKernelUDPCryptoFragmentLocked(fragmentIndex uint16, payload []byte) (bool, bool) {
	count := len(assembly.receivedFragments)
	index := int(fragmentIndex)
	if count == 0 || index < 0 || index >= count {
		return false, true
	}
	if assembly.receivedFragments[index] {
		return false, false
	}
	lastIndex := count - 1
	if index < lastIndex {
		if len(payload) == 0 || !assembly.ensureKernelUDPCryptoFragmentPayloadLocked(count, len(payload)) {
			return false, true
		}
	} else if assembly.fragmentPayloadSize > 0 && len(payload) > assembly.fragmentPayloadSize {
		return false, true
	}
	if assembly.payload == nil {
		if assembly.pending == nil {
			assembly.pending = make([][]byte, count)
		}
		assembly.pending[index] = append([]byte(nil), payload...)
	} else if !assembly.copyKernelUDPCryptoFragmentPayloadLocked(index, payload) {
		return false, true
	}
	assembly.receivedFragments[index] = true
	assembly.received++
	assembly.totalLen += len(payload)
	if index == lastIndex {
		assembly.lastFragmentLen = len(payload)
	}
	if assembly.received != count {
		return false, false
	}
	if assembly.payload == nil || assembly.totalLen > len(assembly.payload) || assembly.totalLen > kernelUDPCryptoFragmentAssembledMaxPayload() {
		return false, true
	}
	return true, false
}

func (assembly *kernelUDPCryptoFragmentAssembly) ensureKernelUDPCryptoFragmentPayloadLocked(count int, fragmentPayloadSize int) bool {
	if count <= 0 || fragmentPayloadSize <= 0 {
		return false
	}
	if assembly.fragmentPayloadSize != 0 {
		return assembly.fragmentPayloadSize == fragmentPayloadSize
	}
	allocLen := count * fragmentPayloadSize
	if allocLen > kernelUDPCryptoFragmentAssembledMaxPayload()+fragmentPayloadSize {
		return false
	}
	assembly.fragmentPayloadSize = fragmentPayloadSize
	assembly.payload = make([]byte, allocLen)
	for index, pending := range assembly.pending {
		if pending == nil {
			continue
		}
		if !assembly.copyKernelUDPCryptoFragmentPayloadLocked(index, pending) {
			return false
		}
		assembly.pending[index] = nil
	}
	return true
}

func (assembly *kernelUDPCryptoFragmentAssembly) copyKernelUDPCryptoFragmentPayloadLocked(index int, payload []byte) bool {
	if assembly.payload == nil || assembly.fragmentPayloadSize <= 0 {
		return false
	}
	count := len(assembly.receivedFragments)
	lastIndex := count - 1
	if index < 0 || index >= count {
		return false
	}
	if index < lastIndex {
		if len(payload) != assembly.fragmentPayloadSize {
			return false
		}
	} else if len(payload) > assembly.fragmentPayloadSize {
		return false
	}
	offset := index * assembly.fragmentPayloadSize
	if offset < 0 || offset > len(assembly.payload) || len(payload) > len(assembly.payload)-offset {
		return false
	}
	copy(assembly.payload[offset:offset+len(payload)], payload)
	return true
}

func (manager *Manager) pruneKernelUDPCryptoFragmentsLocked(now time.Time) {
	const ttl = 30 * time.Second
	for key, assembly := range manager.kernelUDPCryptoFragments {
		if assembly == nil || now.Sub(assembly.createdAt) > ttl {
			delete(manager.kernelUDPCryptoFragments, key)
		}
	}
}

func (manager *Manager) openReceivedKernelUDPFrames(frames []receivedKernelUDPFrame) ([]receivedKernelUDPFrame, bool) {
	frames = manager.reassembleKernelUDPCryptoFragments(frames)
	if len(frames) == 0 {
		return nil, true
	}
	hasEncryptedPayload := false
	for i := range frames {
		if frames[i].encryptedKernelPayload {
			hasEncryptedPayload = true
			break
		}
	}
	if !hasEncryptedPayload {
		return frames, true
	}
	var pendingByFlow map[uint64]*pendingKernelUDPOpenBatch
	var pendingSingleFlow uint64
	var pendingSingle *pendingKernelUDPOpenBatch
	manager.mu.Lock()
	for i := range frames {
		if !frames[i].encryptedKernelPayload {
			continue
		}
		frame := frames[i].frame
		headerSuiteID, headerSuite, headerEpoch, headerErr := kernelCryptoSecureFrameMetadata(frame.Payload, frame.Sequence)
		if headerErr != nil {
			manager.kernelCryptoFrameOpenErrors++
			manager.recordDropLocked(observability.DropCryptoFailed)
			manager.mu.Unlock()
			return nil, false
		}
		epoch := headerEpoch
		suite := headerSuite
		suiteID := headerSuiteID
		flow, flowOK := manager.kernelUDPFlows[frame.FlowID]
		if !flowOK || flow.CryptoPlacement != dataplane.CryptoPlacementKernel {
			forwardKernelUDPEncryptedFrameToUserspace(&frames[i])
			continue
		}
		if flowOK {
			if flow.Epoch != 0 {
				epoch = flow.Epoch
			}
			if flow.CryptoSuite != "" {
				suite = flow.CryptoSuite
				var err error
				suiteID, err = kernelCryptoSuiteID(flow.CryptoSuite)
				if err != nil {
					manager.kernelCryptoFrameOpenErrors++
					manager.recordDropLocked(observability.DropCryptoFailed)
					manager.mu.Unlock()
					return nil, false
				}
			}
		}
		pending := kernelUDPOpenPendingBatchFor(&pendingByFlow, &pendingSingleFlow, &pendingSingle, frame.FlowID, len(frames))
		pending.indexes = append(pending.indexes, i)
		pending.requests = append(pending.requests, kernelCryptoDeviceOpenRequest{
			FlowID:   frame.FlowID,
			SuiteID:  suiteID,
			Epoch:    epoch,
			Sequence: frame.Sequence,
			Payload:  frame.Payload,
			Plain:    frames[i].kernelOpenPlain,
		})
		pending.suites = append(pending.suites, suite)
		pending.epochs = append(pending.epochs, epoch)
	}
	if len(pendingByFlow) == 0 && (pendingSingle == nil || len(pendingSingle.requests) == 0) {
		manager.mu.Unlock()
		return frames, true
	}
	if !manager.kernelUDPKernelCryptoReadyLocked() {
		manager.mu.Unlock()
		return manager.forwardKernelUDPEncryptedFramesToUserspace(frames), true
	}
	manager.mu.Unlock()
	processPending := func(flowID uint64, pending *pendingKernelUDPOpenBatch) bool {
		if pending == nil || len(pending.requests) == 0 {
			return true
		}
		var device *kernelCryptoDevice
		var provider *kernelCryptoProviderObject
		manager.mu.Lock()
		device = manager.kernelCryptoDevices[flowID]
		provider = manager.kernelCryptoProvider
		manager.mu.Unlock()
		for start := 0; start < len(pending.requests); {
			end := min(start+kernelCryptoDeviceBatchMax, len(pending.requests))
			requests := pending.requests[start:end]
			indexes := pending.indexes[start:end]
			suites := pending.suites[start:end]
			epochs := pending.epochs[start:end]
			if device != nil {
				if kernelUDPOpenBorrowedPoolEnabled() {
					manager.mu.Lock()
					manager.kernelCryptoDeviceOpenAttempts += uint64(len(requests))
					manager.observeKernelCryptoDeviceOpenBatchLocked(requests)
					manager.kernelCryptoDeviceOpenBorrowAttempts += uint64(len(requests))
					manager.mu.Unlock()
					results, release, err := device.OpenBatchBorrowed(requests)
					if err == nil {
						frameRelease := kernelUDPRefCountRelease(release, len(results))
						manager.mu.Lock()
						manager.kernelCryptoDeviceOpenBorrowSuccesses += uint64(len(results))
						manager.kernelCryptoDeviceOpenSuccesses += uint64(len(results))
						manager.observeKernelCryptoDeviceOpenResultsLocked(results)
						manager.kernelCryptoFrameOpenAttempts += uint64(len(results))
						manager.kernelCryptoFrameOpenSuccesses += uint64(len(results))
						manager.mu.Unlock()
						for i, result := range results {
							index := indexes[i]
							if frames[index].kernelOpenPlainRelease != nil {
								frames[index].kernelOpenPlainRelease()
								frames[index].kernelOpenPlainRelease = nil
								frames[index].kernelOpenPlain = nil
							}
							frames[index].frame.Payload = result.Plain
							frames[index].frame.CryptoSuite = result.Suite
							frames[index].frame.Epoch = result.Epoch
							frames[index].frame.CryptoPlacement = dataplane.CryptoPlacementKernel
							frames[index].frame.InnerIPv4 = frames[index].frame.InnerIPv4 && kernelUDPInnerIPv4Eligible(result.Plain)
							frames[index].frame.Release = frameRelease
							frames[index].borrowedKernelPayload = false
							frames[index].encryptedKernelPayload = false
						}
						start = end
						continue
					}
					manager.mu.Lock()
					manager.kernelCryptoDeviceOpenBorrowFallbacks += uint64(len(requests))
					if isKernelCryptoReplayError(err) {
						manager.kernelCryptoDeviceOpenErrors += uint64(len(requests))
						manager.kernelCryptoFrameReplayDrops++
						manager.recordDropLocked(observability.DropReplayDetected)
						manager.mu.Unlock()
						return false
					}
					manager.mu.Unlock()
				}
				manager.mu.Lock()
				manager.kernelCryptoDeviceOpenAttempts += uint64(len(requests))
				manager.observeKernelCryptoDeviceOpenBatchLocked(requests)
				manager.mu.Unlock()
				for i, index := range indexes {
					if !frames[index].borrowedKernelPayload || len(requests[i].Plain) > 0 {
						continue
					}
					openPlain, openRelease := kernelUDPOpenPlainBuffer(true, len(frames[index].frame.Payload))
					requests[i].Plain = openPlain
					frames[index].kernelOpenPlain = openPlain
					frames[index].kernelOpenPlainRelease = openRelease
				}
				releaseOpenFallbackBuffers := func() {
					for _, index := range indexes {
						if frames[index].borrowedKernelPayload && frames[index].kernelOpenPlainRelease != nil {
							frames[index].kernelOpenPlainRelease()
							frames[index].kernelOpenPlainRelease = nil
							frames[index].kernelOpenPlain = nil
						}
					}
				}
				results, err := device.OpenBatch(requests)
				if err == nil {
					manager.mu.Lock()
					manager.kernelCryptoDeviceOpenSuccesses += uint64(len(results))
					manager.observeKernelCryptoDeviceOpenResultsLocked(results)
					manager.kernelCryptoFrameOpenAttempts += uint64(len(results))
					manager.kernelCryptoFrameOpenSuccesses += uint64(len(results))
					manager.mu.Unlock()
					for i, result := range results {
						index := indexes[i]
						plain := result.Plain
						if frames[index].borrowedKernelPayload {
							frames[index].frame.Release = frames[index].kernelOpenPlainRelease
							frames[index].kernelOpenPlain = nil
							frames[index].kernelOpenPlainRelease = nil
							frames[index].borrowedKernelPayload = false
						}
						frames[index].frame.Payload = plain
						frames[index].frame.CryptoSuite = result.Suite
						frames[index].frame.Epoch = result.Epoch
						frames[index].frame.CryptoPlacement = dataplane.CryptoPlacementKernel
						frames[index].frame.InnerIPv4 = frames[index].frame.InnerIPv4 && kernelUDPInnerIPv4Eligible(plain)
						frames[index].encryptedKernelPayload = false
					}
					start = end
					continue
				}
				releaseOpenFallbackBuffers()
				manager.mu.Lock()
				manager.kernelCryptoDeviceOpenErrors += uint64(len(requests))
				if isKernelCryptoReplayError(err) {
					manager.kernelCryptoFrameReplayDrops++
					manager.recordDropLocked(observability.DropReplayDetected)
					manager.mu.Unlock()
					return false
				}
				manager.mu.Unlock()
			}
			for i, request := range requests {
				manager.mu.Lock()
				manager.kernelCryptoFrameOpenAttempts++
				if provider == nil {
					manager.kernelCryptoFrameOpenErrors++
					manager.recordDropLocked(observability.DropCryptoFailed)
					manager.mu.Unlock()
					return false
				}
				plaintext, err := provider.OpenFrame(
					kernelCryptoFlowKeyFor(kernelCryptoNamespaceKernelUDP, request.FlowID, kernelCryptoDirectionRecv),
					request.SuiteID,
					request.Epoch,
					request.Sequence,
					request.Payload,
				)
				if err != nil {
					if isKernelCryptoReplayError(err) {
						manager.kernelCryptoFrameOpenErrors++
						manager.kernelCryptoFrameReplayDrops++
						manager.recordDropLocked(observability.DropReplayDetected)
					} else if !isKernelCryptoNoContextError(err) {
						manager.kernelCryptoFrameOpenErrors++
						manager.recordDropLocked(observability.DropCryptoFailed)
					}
					manager.mu.Unlock()
					return false
				}
				manager.kernelCryptoFrameOpenSuccesses++
				manager.mu.Unlock()
				index := indexes[i]
				frames[index].frame.Payload = plaintext
				frames[index].frame.CryptoSuite = suites[i]
				frames[index].frame.Epoch = epochs[i]
				frames[index].frame.CryptoPlacement = dataplane.CryptoPlacementKernel
				frames[index].frame.InnerIPv4 = frames[index].frame.InnerIPv4 && kernelUDPInnerIPv4Eligible(plaintext)
				frames[index].borrowedKernelPayload = false
				frames[index].encryptedKernelPayload = false
			}
			start = end
		}
		return true
	}
	if len(pendingByFlow) == 0 {
		if !processPending(pendingSingleFlow, pendingSingle) {
			return nil, false
		}
		return frames, true
	}
	for flowID, pending := range pendingByFlow {
		if !processPending(flowID, pending) {
			return nil, false
		}
	}
	return frames, true
}

func (manager *Manager) forwardKernelUDPEncryptedFramesToUserspace(frames []receivedKernelUDPFrame) []receivedKernelUDPFrame {
	for i := range frames {
		if !frames[i].encryptedKernelPayload {
			continue
		}
		forwardKernelUDPEncryptedFrameToUserspace(&frames[i])
	}
	return frames
}

func forwardKernelUDPEncryptedFrameToUserspace(frame *receivedKernelUDPFrame) {
	if frame == nil {
		return
	}
	if frame.kernelOpenPlainRelease != nil {
		frame.kernelOpenPlainRelease()
		frame.kernelOpenPlainRelease = nil
		frame.kernelOpenPlain = nil
	}
	frame.frame.Encrypted = false
	frame.frame.InnerIPv4 = false
	frame.frame.CryptoPlacement = dataplane.CryptoPlacementUserspace
	frame.encryptedKernelPayload = false
	frame.encryptedKernelFragment = false
}

func (manager *Manager) deliverKernelUDPFrames(frames []receivedKernelUDPFrame) {
	if len(frames) == 0 {
		return
	}
	originalFrames := frames
	var ok bool
	frames, ok = manager.openReceivedKernelUDPFrames(frames)
	if !ok || len(frames) == 0 {
		releaseReceivedKernelUDPFrames(originalFrames)
		return
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.kernelUDPFlows == nil {
		manager.kernelUDPFlows = make(map[uint64]dataplane.KernelUDPFlow)
	}
	now := time.Now().UTC()
	var delivered []dataplane.KernelUDPFrame
	var deliveredHolder *[]dataplane.KernelUDPFrame
	txDirectSyncNeeded := false
	singleFlowHandled := false
	if kernelUDPRXSingleFlowBatchEnabled() {
		deliveredHolder, delivered, singleFlowHandled = manager.prepareKernelUDPDeliveredSingleFlowLocked(frames, now)
	}
	if !singleFlowHandled {
		deliveredHolder, delivered = takeDeliveredKernelUDPFrameBatch(len(frames))
		for _, item := range frames {
			frame := item.frame
			packet := item.packet
			identity := manager.inferKernelTransportEndpointLocked("udp", packet.SourceIP, packet.SourcePort, packet.DestinationIP, packet.DestinationPort)
			flow, ok := manager.kernelUDPFlows[frame.FlowID]
			if ok && flow.SourcePort == packet.DestinationPort && flow.DestinationPort == packet.SourcePort {
				flowChanged := false
				if manager.applyKernelUDPInboundIdentityLocked(&flow, frame, identity) {
					flowChanged = true
					txDirectSyncNeeded = true
				}
				flow = refreshKernelUDPFlowLifetime(flow, now)
				if frame.Epoch != 0 {
					flow.Epoch = frame.Epoch
				}
				if frame.CryptoSuite != "" {
					flow.CryptoSuite = frame.CryptoSuite
				}
				if shouldUpdateKernelUDPFlowCryptoPlacement(flow.CryptoPlacement, frame.CryptoPlacement) {
					flow.CryptoPlacement = frame.CryptoPlacement
					flowChanged = true
					txDirectSyncNeeded = true
				}
				manager.kernelUDPFlows[frame.FlowID] = flow
				if flowChanged {
					manager.invalidateKernelUDPTXTemplateLocked(frame.FlowID)
					manager.updateKernelUDPTelemetryIdentityLocked(frame.FlowID, flow)
				}
			} else if !ok {
				flow = dataplane.KernelUDPFlow{
					ID:              frame.FlowID,
					Role:            dataplane.KernelUDPFlowRoleInboundReverse,
					LocalAddress:    net.JoinHostPort(packet.DestinationIP.String(), strconv.Itoa(int(packet.DestinationPort))),
					RemoteAddress:   net.JoinHostPort(packet.SourceIP.String(), strconv.Itoa(int(packet.SourcePort))),
					SourcePort:      packet.DestinationPort,
					DestinationPort: packet.SourcePort,
					Epoch:           frame.Epoch,
					CryptoSuite:     frame.CryptoSuite,
					CryptoPlacement: frame.CryptoPlacement,
					CreatedAt:       now,
				}
				manager.applyKernelUDPInboundIdentityLocked(&flow, frame, identity)
				flow = refreshKernelUDPFlowLifetime(flow, now)
				manager.kernelUDPFlows[frame.FlowID] = flow
				if err := manager.syncKernelUDPPortsLocked(); err != nil {
					manager.recordDropLocked(observability.DropEndpointDown)
					releaseKernelUDPFramePayloads(delivered)
					releaseKernelUDPFramePayloads([]dataplane.KernelUDPFrame{frame})
					putDeliveredKernelUDPFrameBatch(deliveredHolder, delivered)
					return
				}
				txDirectSyncNeeded = true
			} else {
				flowChanged := false
				localAddress := net.JoinHostPort(packet.DestinationIP.String(), strconv.Itoa(int(packet.DestinationPort)))
				remoteAddress := net.JoinHostPort(packet.SourceIP.String(), strconv.Itoa(int(packet.SourcePort)))
				if flow.LocalAddress != localAddress {
					flow.LocalAddress = localAddress
					flowChanged = true
				}
				if flow.RemoteAddress != remoteAddress {
					flow.RemoteAddress = remoteAddress
					flowChanged = true
				}
				if flow.SourcePort != packet.DestinationPort {
					flow.SourcePort = packet.DestinationPort
					flowChanged = true
				}
				if flow.DestinationPort != packet.SourcePort {
					flow.DestinationPort = packet.SourcePort
					flowChanged = true
				}
				if manager.applyKernelUDPInboundIdentityLocked(&flow, frame, identity) {
					flowChanged = true
					txDirectSyncNeeded = true
				}
				if frame.Epoch != 0 {
					flow.Epoch = frame.Epoch
				}
				if frame.CryptoSuite != "" {
					flow.CryptoSuite = frame.CryptoSuite
				}
				if shouldUpdateKernelUDPFlowCryptoPlacement(flow.CryptoPlacement, frame.CryptoPlacement) {
					flow.CryptoPlacement = frame.CryptoPlacement
					flowChanged = true
				}
				flow = refreshKernelUDPFlowLifetime(flow, now)
				manager.kernelUDPFlows[frame.FlowID] = flow
				if flowChanged {
					manager.invalidateKernelUDPTXTemplateLocked(frame.FlowID)
					manager.updateKernelUDPTelemetryIdentityLocked(frame.FlowID, flow)
					txDirectSyncNeeded = true
				}
			}
			frame.Peer = flow.Peer
			frame.Endpoint = kernelTransportInboundDeliveryEndpoint(frame.Endpoint, identity.LocalEndpoint)
			if frame.Epoch == 0 {
				frame.Epoch = flow.Epoch
			}
			if frame.CryptoSuite == "" {
				frame.CryptoSuite = flow.CryptoSuite
			}
			if frame.CryptoPlacement == "" {
				frame.CryptoPlacement = flow.CryptoPlacement
			}
			manager.kernelUDPTelemetryLocked(frame.FlowID, flow).ObserveRXSpan(frame.Sequence, item.kernelUDPWireSequenceCount(), len(frame.Payload), now)
			manager.kernelUDPReceived++
			delivered = append(delivered, frame)
		}
	}
	if txDirectSyncNeeded {
		if err := manager.syncKernelUDPTXDirectLocked(); err != nil {
			manager.recordDropLocked(observability.DropEndpointDown)
			manager.warnings = append(manager.warnings, "kernel_udp TC TX direct sync after kernel_udp RX flow update failed: "+err.Error())
			releaseKernelUDPFramePayloads(delivered)
			putDeliveredKernelUDPFrameBatch(deliveredHolder, delivered)
			return
		}
	}
	if len(delivered) == 0 {
		putDeliveredKernelUDPFrameBatch(deliveredHolder, delivered)
		return
	}
	manager.prepareKernelUDPDeliveredReleasesLocked(delivered)
	if deliveredHolder != nil {
		manager.prepareKernelUDPDeliveredBatchReleaseLocked(delivered, deliveredHolder)
		deliveredHolder = nil
	}
	exclusiveFlowSubscribers := kernelUDPExclusiveFlowSubscribers()
	allDeliveredToFlowSubscribers := false
	if len(manager.kernelUDPFlowSubs) > 0 {
		if _, subscribers, ok := kernelUDPSingleFlowSubscriberSet(delivered, manager.kernelUDPFlowSubs); ok {
			allDeliveredToFlowSubscribers = true
			for subscriber := range subscribers {
				select {
				case subscriber <- delivered:
				default:
					manager.kernelUDPSubDrops++
					releaseKernelUDPFramePayloads(delivered)
				}
			}
		} else {
			var byFlow map[uint64][]dataplane.KernelUDPFrame
			for _, frame := range delivered {
				if len(manager.kernelUDPFlowSubs[frame.FlowID]) > 0 {
					if byFlow == nil {
						byFlow = make(map[uint64][]dataplane.KernelUDPFrame)
					}
					byFlow[frame.FlowID] = append(byFlow[frame.FlowID], frame)
				}
			}
			for flowID, batch := range byFlow {
				for subscriber := range manager.kernelUDPFlowSubs[flowID] {
					select {
					case subscriber <- batch:
					default:
						manager.kernelUDPSubDrops += uint64(len(batch))
						releaseKernelUDPFramePayloads(batch)
					}
				}
			}
		}
	}
	if len(manager.kernelUDPSubs) > 0 {
		globalDelivered := delivered
		if exclusiveFlowSubscribers && allDeliveredToFlowSubscribers {
			globalDelivered = nil
		} else if exclusiveFlowSubscribers && len(manager.kernelUDPFlowSubs) > 0 {
			globalDelivered = kernelUDPGlobalDeliveryFrames(delivered, manager.kernelUDPFlowSubs)
		}
		if len(globalDelivered) > 0 {
			for subscriber := range manager.kernelUDPSubs {
				select {
				case subscriber <- globalDelivered:
				default:
					manager.kernelUDPSubDrops += uint64(len(globalDelivered))
					releaseKernelUDPFramePayloads(globalDelivered)
				}
			}
		}
	}
}

func kernelUDPSingleFlowSubscriberSet(frames []dataplane.KernelUDPFrame, flowSubs map[uint64]map[chan []dataplane.KernelUDPFrame]struct{}) (uint64, map[chan []dataplane.KernelUDPFrame]struct{}, bool) {
	if len(frames) == 0 {
		return 0, nil, false
	}
	flowID := frames[0].FlowID
	subscribers := flowSubs[flowID]
	if len(subscribers) == 0 {
		return flowID, nil, false
	}
	for _, frame := range frames[1:] {
		if frame.FlowID != flowID {
			return 0, nil, false
		}
	}
	return flowID, subscribers, true
}

func (manager *Manager) prepareKernelUDPDeliveredSingleFlowLocked(frames []receivedKernelUDPFrame, now time.Time) (*[]dataplane.KernelUDPFrame, []dataplane.KernelUDPFrame, bool) {
	if len(frames) < 2 {
		return nil, nil, false
	}
	first := frames[0]
	firstFrame := first.frame
	firstPacket := first.packet
	identity := manager.inferKernelTransportEndpointLocked("udp", firstPacket.SourceIP, firstPacket.SourcePort, firstPacket.DestinationIP, firstPacket.DestinationPort)
	flow, ok := manager.kernelUDPFlows[firstFrame.FlowID]
	if !ok || flow.SourcePort != firstPacket.DestinationPort || flow.DestinationPort != firstPacket.SourcePort {
		return nil, nil, false
	}
	if manager.kernelUDPInboundIdentityWouldUpdateLocked(flow, firstFrame, identity) {
		return nil, nil, false
	}
	bytes := uint64(0)
	wireFrames := uint64(0)
	sequential := firstFrame.Sequence != 0
	previousSequenceEnd := firstFrame.Sequence + first.kernelUDPWireSequenceCount() - 1
	if previousSequenceEnd < firstFrame.Sequence {
		sequential = false
		previousSequenceEnd = firstFrame.Sequence
	}
	epoch := firstFrame.Epoch
	cryptoSuite := firstFrame.CryptoSuite
	cryptoPlacement := firstFrame.CryptoPlacement
	for i := range frames {
		frame := frames[i].frame
		packet := frames[i].packet
		wireSequenceCount := frames[i].kernelUDPWireSequenceCount()
		if frame.FlowID != firstFrame.FlowID ||
			packet.SourceIP != firstPacket.SourceIP ||
			packet.DestinationIP != firstPacket.DestinationIP ||
			packet.SourcePort != firstPacket.SourcePort ||
			packet.DestinationPort != firstPacket.DestinationPort {
			return nil, nil, false
		}
		if i > 0 {
			if !sequential || frame.Sequence == 0 || frame.Sequence != previousSequenceEnd+1 {
				sequential = false
			}
			previousSequenceEnd = frame.Sequence + wireSequenceCount - 1
			if previousSequenceEnd < frame.Sequence {
				sequential = false
				previousSequenceEnd = frame.Sequence
			}
		}
		wireFrames += wireSequenceCount
		if frame.Epoch != 0 {
			epoch = frame.Epoch
		}
		if frame.CryptoSuite != "" {
			cryptoSuite = frame.CryptoSuite
		}
		if shouldUpdateKernelUDPFlowCryptoPlacement(cryptoPlacement, frame.CryptoPlacement) {
			cryptoPlacement = frame.CryptoPlacement
		}
		if len(frame.Payload) > 0 {
			bytes += uint64(len(frame.Payload))
		}
	}
	flow = refreshKernelUDPFlowLifetime(flow, now)
	if epoch != 0 {
		flow.Epoch = epoch
	}
	if cryptoSuite != "" {
		flow.CryptoSuite = cryptoSuite
	}
	if shouldUpdateKernelUDPFlowCryptoPlacement(flow.CryptoPlacement, cryptoPlacement) {
		flow.CryptoPlacement = cryptoPlacement
	}
	manager.kernelUDPFlows[firstFrame.FlowID] = flow
	holder, delivered := takeDeliveredKernelUDPFrameBatch(len(frames))
	for _, item := range frames {
		frame := item.frame
		frame.Peer = flow.Peer
		frame.Endpoint = kernelTransportInboundDeliveryEndpoint(frame.Endpoint, identity.LocalEndpoint)
		if frame.Epoch == 0 {
			frame.Epoch = flow.Epoch
		}
		if frame.CryptoSuite == "" {
			frame.CryptoSuite = flow.CryptoSuite
		}
		if frame.CryptoPlacement == "" {
			frame.CryptoPlacement = flow.CryptoPlacement
		}
		delivered = append(delivered, frame)
	}
	telemetry := manager.kernelUDPTelemetryLocked(firstFrame.FlowID, flow)
	if sequential {
		telemetry.ObserveRXBatchSpan(firstFrame.Sequence, uint64(len(frames)), wireFrames, bytes, now)
	} else {
		for i, frame := range delivered {
			telemetry.ObserveRXSpan(frame.Sequence, frames[i].kernelUDPWireSequenceCount(), len(frame.Payload), now)
		}
	}
	manager.kernelUDPReceived += uint64(len(frames))
	return holder, delivered, true
}

func (item receivedKernelUDPFrame) kernelUDPWireSequenceCount() uint64 {
	if item.wireSequenceCount == 0 {
		return 1
	}
	return item.wireSequenceCount
}

func kernelUDPGlobalDeliveryFrames(frames []dataplane.KernelUDPFrame, flowSubs map[uint64]map[chan []dataplane.KernelUDPFrame]struct{}) []dataplane.KernelUDPFrame {
	var filtered []dataplane.KernelUDPFrame
	for i, frame := range frames {
		if len(flowSubs[frame.FlowID]) == 0 {
			if filtered != nil {
				filtered = append(filtered, frame)
			}
			continue
		}
		if filtered == nil {
			filtered = make([]dataplane.KernelUDPFrame, 0, len(frames)-1)
			for _, previous := range frames[:i] {
				if len(flowSubs[previous.FlowID]) == 0 {
					filtered = append(filtered, previous)
				}
			}
		}
	}
	if filtered == nil {
		return frames
	}
	return filtered
}

func releaseReceivedKernelUDPFrames(frames []receivedKernelUDPFrame) {
	for i := range frames {
		if frames[i].frame.Release != nil {
			frames[i].frame.Release()
		}
	}
}

func kernelUDPRXSingleFlowBatchEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_RX_SINGLE_FLOW_BATCH"))) {
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}

func experimentalTCPRXSingleFlowBatchEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_EXPERIMENTAL_TCP_RX_SINGLE_FLOW_BATCH"))) {
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}

func (manager *Manager) prepareKernelUDPDeliveredReleasesLocked(frames []dataplane.KernelUDPFrame) {
	exclusiveFlowSubscribers := kernelUDPExclusiveFlowSubscribers()
	for i := range frames {
		release := frames[i].Release
		if release == nil {
			continue
		}
		flowRecipients := 0
		if subs := manager.kernelUDPFlowSubs[frames[i].FlowID]; subs != nil {
			flowRecipients = len(subs)
		}
		recipients := len(manager.kernelUDPSubs) + flowRecipients
		if exclusiveFlowSubscribers && flowRecipients > 0 {
			recipients = flowRecipients
		}
		switch {
		case recipients == 0:
			release()
			frames[i].Release = nil
		case recipients > 1:
			frames[i].Release = kernelUDPRefCountRelease(release, recipients)
		}
	}
}

func (manager *Manager) prepareKernelUDPDeliveredBatchReleaseLocked(frames []dataplane.KernelUDPFrame, holder *[]dataplane.KernelUDPFrame) {
	if holder == nil || len(frames) == 0 {
		putDeliveredKernelUDPFrameBatch(holder, frames)
		return
	}
	exclusiveFlowSubscribers := kernelUDPExclusiveFlowSubscribers()
	totalFrameReleases := 0
	frameRecipients := make([]int, len(frames))
	for i := range frames {
		flowRecipients := 0
		if subs := manager.kernelUDPFlowSubs[frames[i].FlowID]; subs != nil {
			flowRecipients = len(subs)
		}
		recipients := len(manager.kernelUDPSubs) + flowRecipients
		if exclusiveFlowSubscribers && flowRecipients > 0 {
			recipients = flowRecipients
		}
		frameRecipients[i] = recipients
		totalFrameReleases += recipients
	}
	if totalFrameReleases <= 0 {
		putDeliveredKernelUDPFrameBatch(holder, frames)
		return
	}
	releaseBatch := kernelUDPRefCountRelease(func() {
		putDeliveredKernelUDPFrameBatch(holder, frames)
	}, totalFrameReleases)
	for i := range frames {
		if frameRecipients[i] <= 0 {
			continue
		}
		release := frames[i].Release
		if release == nil {
			frames[i].Release = releaseBatch
			continue
		}
		frames[i].Release = func() {
			release()
			releaseBatch()
		}
	}
}

type kernelTransportEndpointIdentity struct {
	Peer           core.IXID
	RemoteEndpoint core.EndpointID
	LocalEndpoint  core.EndpointID
}

func (manager *Manager) applyKernelUDPInboundIdentityLocked(flow *dataplane.KernelUDPFlow, frame dataplane.KernelUDPFrame, identity kernelTransportEndpointIdentity) bool {
	if flow == nil {
		return false
	}
	changed := false
	peer := frame.Peer
	if peer == "" {
		peer = identity.Peer
	}
	if peer != "" && flow.Peer != peer {
		flow.Peer = peer
		changed = true
	}
	endpoint := identity.RemoteEndpoint
	if endpoint == "" && frame.Endpoint != "" && frame.Endpoint != identity.LocalEndpoint {
		endpoint = frame.Endpoint
	}
	if endpoint != "" && flow.Endpoint != endpoint {
		flow.Endpoint = endpoint
		changed = true
	}
	return changed
}

func (manager *Manager) kernelUDPInboundIdentityWouldUpdateLocked(flow dataplane.KernelUDPFlow, frame dataplane.KernelUDPFrame, identity kernelTransportEndpointIdentity) bool {
	updated := flow
	return manager.applyKernelUDPInboundIdentityLocked(&updated, frame, identity)
}

func (manager *Manager) applyExperimentalTCPInboundIdentityLocked(flow *dataplane.ExperimentalTCPFlow, frame dataplane.ExperimentalTCPFrame, identity kernelTransportEndpointIdentity) bool {
	if flow == nil {
		return false
	}
	changed := false
	peer := frame.Peer
	if peer == "" {
		peer = identity.Peer
	}
	if peer != "" && flow.Peer != peer {
		flow.Peer = peer
		changed = true
	}
	endpoint := identity.RemoteEndpoint
	if endpoint == "" && frame.Endpoint != "" && frame.Endpoint != identity.LocalEndpoint {
		endpoint = frame.Endpoint
	}
	if endpoint != "" && flow.Endpoint != endpoint {
		flow.Endpoint = endpoint
		changed = true
	}
	if frame.Epoch != 0 && flow.Epoch != frame.Epoch {
		flow.Epoch = frame.Epoch
		changed = true
	}
	if frame.CryptoSuite != "" && flow.CryptoSuite != frame.CryptoSuite {
		flow.CryptoSuite = frame.CryptoSuite
		changed = true
	}
	if shouldUpdateKernelUDPFlowCryptoPlacement(flow.CryptoPlacement, frame.CryptoPlacement) {
		flow.CryptoPlacement = frame.CryptoPlacement
		changed = true
	}
	return changed
}

func (manager *Manager) experimentalTCPInboundIdentityWouldUpdateLocked(flow dataplane.ExperimentalTCPFlow, frame dataplane.ExperimentalTCPFrame, identity kernelTransportEndpointIdentity) bool {
	updated := flow
	return manager.applyExperimentalTCPInboundIdentityLocked(&updated, frame, identity)
}

func kernelTransportInboundDeliveryEndpoint(frameEndpoint core.EndpointID, localEndpoint core.EndpointID) core.EndpointID {
	if localEndpoint != "" {
		return localEndpoint
	}
	return frameEndpoint
}

func experimentalTCPInboundDeliveryEndpoint(frameEndpoint core.EndpointID, identity kernelTransportEndpointIdentity, flowEndpoint core.EndpointID) core.EndpointID {
	if identity.LocalEndpoint != "" {
		return identity.LocalEndpoint
	}
	if frameEndpoint != "" && frameEndpoint != identity.RemoteEndpoint {
		return frameEndpoint
	}
	if flowEndpoint != "" && flowEndpoint != identity.RemoteEndpoint {
		return flowEndpoint
	}
	return frameEndpoint
}

func (manager *Manager) inferKernelTransportEndpointLocked(transportName string, remoteIP netip.Addr, remotePort uint16, localIP netip.Addr, localPort uint16) kernelTransportEndpointIdentity {
	localIX := manager.snapshotLocalIXLocked()
	identity := kernelTransportEndpointIdentity{}
	var remoteHostFallback kernelTransportEndpointIdentity
	remoteHostFallbackAmbiguous := false
	for _, endpoint := range manager.snapshot.Endpoints {
		if !endpoint.Enabled || !kernelTransportEndpointTransportMatches(endpoint.Transport, transportName) {
			continue
		}
		if !snapshotEndpointIsLocal(localIX, endpoint) {
			switch {
			case endpointRemoteAddressMatches(endpoint.Address, remoteIP, remotePort):
				if identity.Peer == "" {
					identity.Peer = endpoint.Peer
				}
				if identity.RemoteEndpoint == "" {
					identity.RemoteEndpoint = endpoint.ID
				}
			case endpointHostMatchesLiteral(endpoint.Address, remoteIP):
				candidate := kernelTransportEndpointIdentity{Peer: endpoint.Peer, RemoteEndpoint: endpoint.ID}
				if remoteHostFallback.Peer == "" && remoteHostFallback.RemoteEndpoint == "" {
					remoteHostFallback = candidate
				} else if remoteHostFallback.Peer != candidate.Peer || remoteHostFallback.RemoteEndpoint != candidate.RemoteEndpoint {
					remoteHostFallbackAmbiguous = true
				}
			}
		}
		listenAddress := strings.TrimSpace(endpoint.Listen)
		if listenAddress == "" {
			listenAddress = strings.TrimSpace(endpoint.Address)
		}
		if endpointLocalAddressMatches(listenAddress, localIP, localPort) && snapshotEndpointIsLocal(localIX, endpoint) && identity.LocalEndpoint == "" {
			identity.LocalEndpoint = endpoint.ID
		}
	}
	if identity.Peer == "" && identity.RemoteEndpoint == "" && !remoteHostFallbackAmbiguous {
		identity.Peer = remoteHostFallback.Peer
		identity.RemoteEndpoint = remoteHostFallback.RemoteEndpoint
	}
	return identity
}

func kernelTransportEndpointTransportMatches(endpointTransport string, transportName string) bool {
	endpointTransport = strings.ToLower(strings.TrimSpace(endpointTransport))
	transportName = strings.ToLower(strings.TrimSpace(transportName))
	if endpointTransport == transportName {
		return true
	}
	return transportName == "udp" && endpointTransport == "kernel_udp"
}

func endpointRemoteAddressMatches(address string, ip netip.Addr, port uint16) bool {
	return endpointAddressMatchesLiteral(address, ip, port, false)
}

func endpointLocalAddressMatches(address string, ip netip.Addr, port uint16) bool {
	return endpointAddressMatchesLiteral(address, ip, port, true)
}

func endpointAddressMatchesLiteral(address string, ip netip.Addr, port uint16, allowUnspecified bool) bool {
	address = strings.TrimSpace(address)
	if address == "" || !ip.IsValid() || port == 0 {
		return false
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	endpointPort, err := parseExperimentalTCPPort(portText)
	if err != nil || endpointPort != port {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	if allowUnspecified && addr.IsUnspecified() {
		return true
	}
	return addr == ip
}

func endpointHostMatchesLiteral(address string, ip netip.Addr) bool {
	address = strings.TrimSpace(address)
	if address == "" || !ip.IsValid() {
		return false
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr == ip
}

func kernelUDPExclusiveFlowSubscribers() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_EXCLUSIVE_FLOW_SUBSCRIBERS"))) {
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}

func kernelUDPOpenBorrowedPoolEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_OPEN_BORROW_POOL"))) {
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}

func experimentalTCPOpenBorrowedPoolEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_EXPERIMENTAL_TCP_OPEN_BORROW_POOL"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return experimentalTCPOpenBorrowedPoolAutoEnabled()
	}
}

func experimentalTCPOpenBorrowedPoolAutoEnabled() bool {
	if experimentalTCPKernelOpenInPlaceEnabled() || experimentalTCPTXDeferFlush() {
		return false
	}
	return true
}

func kernelUDPRefCountRelease(release func(), recipients int) func() {
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

func releaseKernelUDPFramePayloads(frames []dataplane.KernelUDPFrame) {
	for i := range frames {
		if frames[i].Release != nil {
			frames[i].Release()
		}
	}
}

func (manager *Manager) buildExperimentalTCPPacketLocked(flowID uint64, sequence uint64, payload []byte) ([]byte, [4]byte, error) {
	spec, dst, err := manager.prepareExperimentalTCPPacketLocked(flowID, sequence)
	if err != nil {
		return nil, [4]byte{}, err
	}
	spec.Sequence = manager.reserveExperimentalTCPOuterSequenceLocked(flowID, len(payload))
	spec.Payload = payload
	packet, err := experimentaltcp.MarshalTCPShapedIPv4(spec)
	if err != nil {
		return nil, [4]byte{}, err
	}
	return packet, dst, nil
}

func (manager *Manager) prepareExperimentalTCPPacketLocked(flowID uint64, sequence uint64) (experimentaltcp.TCPPacket, [4]byte, error) {
	if template, ok := manager.expTCPTXTemplates[flowID]; ok {
		if template.kernelTransportTemplateExpired(time.Now().UTC()) {
			manager.expireExperimentalTCPTXTemplateLocked(flowID, template)
		}
	}
	if template, ok := manager.expTCPTXTemplates[flowID]; ok {
		packet := template.packet
		return packet, template.dst, nil
	}
	flow := manager.expTCPFlows[flowID]
	if strings.TrimSpace(flow.RemoteAddress) == "" {
		return experimentaltcp.TCPPacket{}, [4]byte{}, fmt.Errorf("experimental_tcp flow %d remote address is required", flowID)
	}
	now := time.Now().UTC()
	remoteIP, remotePort, remoteResolvedAt, err := resolveKernelTransportAddress(flow.RemoteAddress, now)
	if err != nil {
		return experimentaltcp.TCPPacket{}, [4]byte{}, err
	}
	autoLocalAddress := strings.TrimSpace(flow.LocalAddress) == ""
	localIP, localPort, err := manager.experimentalTCPLocalAddress(flow, remoteIP)
	if err != nil {
		return experimentaltcp.TCPPacket{}, [4]byte{}, err
	}
	syncPorts := flow.SourcePort != localPort || flow.DestinationPort != remotePort
	flow.SourcePort = localPort
	flow.DestinationPort = remotePort
	if flow.LocalAddress == "" {
		flow.LocalAddress = net.JoinHostPort(localIP.String(), strconv.Itoa(int(localPort)))
		syncPorts = true
	}
	flow = refreshExperimentalTCPPreparedFlowLifetime(flow, now)
	manager.expTCPFlows[flowID] = flow
	manager.updateExperimentalTCPTelemetryIdentityLocked(flowID, flow)
	if syncPorts {
		if err := manager.syncExperimentalTCPPortsLocked(); err != nil {
			return experimentaltcp.TCPPacket{}, [4]byte{}, err
		}
	}
	dst := remoteIP.As4()
	packet := experimentaltcp.TCPPacket{
		SourceIP:        localIP,
		DestinationIP:   remoteIP,
		SourcePort:      localPort,
		DestinationPort: remotePort,
		Acknowledgment:  manager.experimentalTCPOuterAcknowledgmentLocked(flowID),
	}
	if manager.expTCPTXTemplates == nil {
		manager.expTCPTXTemplates = make(map[uint64]experimentalTCPTXTemplate)
	}
	templatePacket := packet
	templatePacket.Sequence = 0
	manager.expTCPTXTemplates[flowID] = experimentalTCPTXTemplate{
		packet:           templatePacket,
		dst:              dst,
		flow:             flow,
		expiresAt:        kernelTransportDNSCacheExpiresAt(remoteResolvedAt),
		autoLocalAddress: autoLocalAddress,
	}
	return packet, dst, nil
}

func (manager *Manager) reserveExperimentalTCPOuterSequenceLocked(flowID uint64, tcpPayloadLen int) uint32 {
	if tcpPayloadLen <= 0 {
		tcpPayloadLen = 1
	}
	if tcpPayloadLen > 1<<20 {
		tcpPayloadLen = 1 << 20
	}
	if manager.expTCPOuterTXSequences == nil {
		manager.expTCPOuterTXSequences = make(map[uint64]uint32)
	}
	sequence := manager.expTCPOuterTXSequences[flowID]
	if sequence == 0 {
		sequence = uint32(experimentalTCPMix64(flowID))
		if sequence == 0 {
			sequence = 1
		}
	}
	next := sequence + uint32(tcpPayloadLen)
	if next == 0 {
		next = 1
	}
	manager.expTCPOuterTXSequences[flowID] = next
	return sequence
}

func (manager *Manager) assignExperimentalTCPOuterSequencesLocked(frames []preparedExperimentalTCPTXFrame) {
	if len(frames) == 0 {
		return
	}
	if manager.expTCPOuterTXSequences == nil {
		manager.expTCPOuterTXSequences = make(map[uint64]uint32)
	}
	var singleFlowID uint64
	var singleSequence uint32
	var haveSingle bool
	sequenceByFlow := map[uint64]uint32(nil)
	loadSequence := func(flowID uint64) uint32 {
		sequence := manager.expTCPOuterTXSequences[flowID]
		if sequence == 0 {
			sequence = uint32(experimentalTCPMix64(flowID))
			if sequence == 0 {
				sequence = 1
			}
		}
		return sequence
	}
	for i := range frames {
		flowID := frames[i].wireFrame.FlowID
		payloadLen := frames[i].frameLen
		if payloadLen <= 0 {
			payloadLen = 1
		}
		if payloadLen > 1<<20 {
			payloadLen = 1 << 20
		}
		var sequence uint32
		if sequenceByFlow != nil {
			var ok bool
			sequence, ok = sequenceByFlow[flowID]
			if !ok {
				sequence = loadSequence(flowID)
			}
			next := sequence + uint32(payloadLen)
			if next == 0 {
				next = 1
			}
			sequenceByFlow[flowID] = next
			frames[i].packet.Sequence = sequence
			continue
		}
		if !haveSingle {
			singleFlowID = flowID
			singleSequence = loadSequence(flowID)
			haveSingle = true
		} else if singleFlowID != flowID {
			sequenceByFlow = make(map[uint64]uint32, 2)
			sequenceByFlow[singleFlowID] = singleSequence
			sequence = loadSequence(flowID)
			next := sequence + uint32(payloadLen)
			if next == 0 {
				next = 1
			}
			sequenceByFlow[flowID] = next
			frames[i].packet.Sequence = sequence
			continue
		}
		sequence = singleSequence
		next := sequence + uint32(payloadLen)
		if next == 0 {
			next = 1
		}
		singleSequence = next
		frames[i].packet.Sequence = sequence
	}
	if sequenceByFlow == nil {
		if haveSingle {
			manager.expTCPOuterTXSequences[singleFlowID] = singleSequence
		}
		return
	}
	for flowID, sequence := range sequenceByFlow {
		manager.expTCPOuterTXSequences[flowID] = sequence
	}
}

func (manager *Manager) experimentalTCPOuterAcknowledgmentLocked(flowID uint64) uint32 {
	if manager.expTCPOuterTXAcknowledgments == nil {
		manager.expTCPOuterTXAcknowledgments = make(map[uint64]uint32)
	}
	ack := manager.expTCPOuterTXAcknowledgments[flowID]
	if ack == 0 {
		return 1
	}
	return ack
}

func (manager *Manager) recordExperimentalTCPOuterAcknowledgmentLocked(flowID uint64, packet experimentaltcp.TCPPacket) {
	if len(packet.Payload) == 0 {
		return
	}
	if manager.expTCPOuterTXAcknowledgments == nil {
		manager.expTCPOuterTXAcknowledgments = make(map[uint64]uint32)
	}
	next := packet.Sequence + uint32(len(packet.Payload))
	if next == 0 {
		next = 1
	}
	current := manager.expTCPOuterTXAcknowledgments[flowID]
	if current == 0 || experimentalTCPSequenceAfter(next, current) {
		manager.expTCPOuterTXAcknowledgments[flowID] = next
	}
}

func experimentalTCPSequenceAfter(candidate uint32, current uint32) bool {
	return int32(candidate-current) > 0
}

func kernelUDPRawFallbackPayloadMaxForMTU(mtu int, placement dataplane.CryptoPlacement, encrypted bool) int {
	overhead := rejectIPv4HeaderLen + 8 + kerneludp.HeaderLen
	if placement == dataplane.CryptoPlacementKernel || encrypted {
		overhead += experimentalTCPKernelCryptoOverhead
	}
	if mtu <= overhead {
		return 1
	}
	return mtu - overhead
}

func (manager *Manager) kernelUDPRawFallbackPayloadMaxLocked(placement dataplane.CryptoPlacement, encrypted bool) int {
	mtu := manager.experimentalTCPUnderlayMTULocked()
	if mtu <= 0 {
		mtu = kernelUDPRawFallbackDefaultMTU
	}
	return kernelUDPRawFallbackPayloadMaxForMTU(mtu, placement, encrypted)
}

func (manager *Manager) prepareKernelUDPPacketLocked(flowID uint64) (kerneludp.UDPPacket, [4]byte, error) {
	if template, ok := manager.kernelUDPTXTemplates[flowID]; ok {
		if template.kernelTransportTemplateExpired(time.Now().UTC()) {
			manager.expireKernelUDPTXTemplateLocked(flowID, template)
		}
	}
	if template, ok := manager.kernelUDPTXTemplates[flowID]; ok {
		return template.packet, template.dst, nil
	}
	flow := manager.kernelUDPFlows[flowID]
	packet, dst, _, err := manager.prepareKernelUDPPacketForFlowLocked(flowID, flow)
	return packet, dst, err
}

func (manager *Manager) prepareKernelUDPPacketForFlowLocked(flowID uint64, flow dataplane.KernelUDPFlow) (kerneludp.UDPPacket, [4]byte, dataplane.KernelUDPFlow, error) {
	if template, ok := manager.kernelUDPTXTemplates[flowID]; ok {
		now := time.Now().UTC()
		if template.kernelTransportTemplateExpired(now) {
			manager.expireKernelUDPTXTemplateLocked(flowID, template)
			if latest, ok := manager.kernelUDPFlows[flowID]; ok {
				flow = latest
			}
		}
	}
	if template, ok := manager.kernelUDPTXTemplates[flowID]; ok {
		return template.packet, template.dst, template.flow, nil
	}
	now := time.Now().UTC()
	if strings.TrimSpace(flow.RemoteAddress) == "" {
		return kerneludp.UDPPacket{}, [4]byte{}, dataplane.KernelUDPFlow{}, fmt.Errorf("kernel_udp flow %d remote address is required", flowID)
	}
	remoteIP, remotePort, remoteResolvedAt, err := resolveKernelTransportAddress(flow.RemoteAddress, now)
	if err != nil {
		return kerneludp.UDPPacket{}, [4]byte{}, dataplane.KernelUDPFlow{}, err
	}
	autoLocalAddress := strings.TrimSpace(flow.LocalAddress) == ""
	localIP, localPort, err := manager.kernelUDPLocalAddress(flow, remoteIP)
	if err != nil {
		return kerneludp.UDPPacket{}, [4]byte{}, dataplane.KernelUDPFlow{}, err
	}
	syncPorts := flow.SourcePort != localPort || flow.DestinationPort != remotePort
	flow.SourcePort = localPort
	flow.DestinationPort = remotePort
	if flow.LocalAddress == "" {
		flow.LocalAddress = net.JoinHostPort(localIP.String(), strconv.Itoa(int(localPort)))
		syncPorts = true
	}
	flow = refreshKernelUDPPreparedFlowLifetime(flow, now)
	manager.kernelUDPFlows[flowID] = flow
	manager.updateKernelUDPTelemetryIdentityLocked(flowID, flow)
	if syncPorts {
		if err := manager.syncKernelUDPPortsLocked(); err != nil {
			return kerneludp.UDPPacket{}, [4]byte{}, dataplane.KernelUDPFlow{}, err
		}
	}
	dst := remoteIP.As4()
	packet := kerneludp.UDPPacket{
		SourceIP:        localIP,
		DestinationIP:   remoteIP,
		SourcePort:      localPort,
		DestinationPort: remotePort,
	}
	if manager.kernelUDPTXTemplates == nil {
		manager.kernelUDPTXTemplates = make(map[uint64]kernelUDPTXTemplate)
	}
	manager.kernelUDPTXTemplates[flowID] = kernelUDPTXTemplate{
		packet:           packet,
		dst:              dst,
		flow:             flow,
		expiresAt:        kernelTransportDNSCacheExpiresAt(remoteResolvedAt),
		autoLocalAddress: autoLocalAddress,
	}
	return packet, dst, flow, nil
}

func (manager *Manager) experimentalTCPLocalAddress(flow dataplane.ExperimentalTCPFlow, remoteIP netip.Addr) (netip.Addr, uint16, error) {
	if flow.LocalAddress != "" {
		localIP, localPort, err := resolveKernelTransportLocalAddress(flow.LocalAddress)
		if err != nil {
			return netip.Addr{}, 0, err
		}
		if flow.SourcePort != 0 {
			localPort = flow.SourcePort
		}
		if localPort == 0 {
			localPort = experimentalTCPDerivedSourcePort(flow.ID)
		}
		return localIP, localPort, nil
	}
	localIP, err := routeSourceIPv4(remoteIP)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	localPort := flow.SourcePort
	if localPort == 0 {
		localPort = experimentalTCPDerivedSourcePort(flow.ID)
	}
	return localIP, localPort, nil
}

func (manager *Manager) fillExperimentalTCPFlowRemoteAddressFromEndpointLocked(flow dataplane.ExperimentalTCPFlow) dataplane.ExperimentalTCPFlow {
	if strings.TrimSpace(flow.RemoteAddress) != "" || flow.Peer == "" || flow.Endpoint == "" {
		return flow
	}
	for _, endpoint := range manager.snapshot.Endpoints {
		if !endpoint.Enabled || !strings.EqualFold(strings.TrimSpace(endpoint.Transport), "experimental_tcp") || endpoint.Peer != flow.Peer || endpoint.ID != flow.Endpoint {
			continue
		}
		address := strings.TrimSpace(endpoint.Address)
		if address == "" {
			continue
		}
		if port, err := experimentalTCPAddressPort(address); err != nil || port == 0 {
			continue
		}
		flow.RemoteAddress = address
		return flow
	}
	return flow
}

func (manager *Manager) experimentalTCPFlowRemoteAddressFillAllowedLocked(previous dataplane.ExperimentalTCPFlow, next dataplane.ExperimentalTCPFlow) bool {
	if strings.TrimSpace(next.RemoteAddress) != "" || next.Peer == "" || next.Endpoint == "" {
		return false
	}
	localIP, localPort, ok := experimentalTCPFlowLocalTuple(next)
	if !ok {
		return true
	}
	localIX := manager.snapshotLocalIXLocked()
	for _, endpoint := range manager.snapshot.Endpoints {
		if !endpoint.Enabled || !kernelTransportEndpointTransportMatches(endpoint.Transport, "experimental_tcp") || !snapshotEndpointIsLocal(localIX, endpoint) {
			continue
		}
		listenAddress := strings.TrimSpace(endpoint.Listen)
		if listenAddress == "" {
			listenAddress = strings.TrimSpace(endpoint.Address)
		}
		if endpointLocalAddressMatches(listenAddress, localIP, localPort) {
			return false
		}
	}
	return previous.LocalAddress == "" && previous.SourcePort == 0 && previous.DestinationPort == 0
}

func experimentalTCPFlowLocalTuple(flow dataplane.ExperimentalTCPFlow) (netip.Addr, uint16, bool) {
	if strings.TrimSpace(flow.LocalAddress) != "" {
		ip, port, err := resolveExperimentalTCPAddress(flow.LocalAddress)
		if err != nil || port == 0 {
			return netip.Addr{}, 0, false
		}
		if flow.SourcePort != 0 {
			port = flow.SourcePort
		}
		return ip, port, true
	}
	if flow.SourcePort == 0 {
		return netip.Addr{}, 0, false
	}
	return netip.Addr{}, flow.SourcePort, true
}

func experimentalTCPDerivedSourcePort(flowID uint64) uint16 {
	return uint16(40000 + flowID%20000)
}

func (manager *Manager) localExperimentalTCPListenPortLocked() (uint16, bool) {
	localIX := manager.snapshotLocalIXLocked()
	for _, endpoint := range manager.snapshot.Endpoints {
		if endpoint.Transport != "experimental_tcp" || !endpoint.Enabled || !snapshotEndpointIsLocal(localIX, endpoint) {
			continue
		}
		address := strings.TrimSpace(endpoint.Listen)
		if address == "" {
			address = strings.TrimSpace(endpoint.Address)
		}
		if address == "" {
			continue
		}
		port, err := experimentalTCPAddressPort(address)
		if err == nil {
			return port, true
		}
	}
	return 0, false
}

func (manager *Manager) uniqueLocalExperimentalTCPListenPortLocked() (uint16, bool) {
	localIX := manager.snapshotLocalIXLocked()
	var selected uint16
	for _, endpoint := range manager.snapshot.Endpoints {
		if endpoint.Transport != "experimental_tcp" || !endpoint.Enabled || !snapshotEndpointIsLocal(localIX, endpoint) {
			continue
		}
		address := strings.TrimSpace(endpoint.Listen)
		if address == "" {
			address = strings.TrimSpace(endpoint.Address)
		}
		if address == "" {
			continue
		}
		port, err := experimentalTCPAddressPort(address)
		if err != nil {
			continue
		}
		if selected == 0 {
			selected = port
			continue
		}
		if selected != port {
			return 0, false
		}
	}
	return selected, selected != 0
}

func (manager *Manager) localKernelUDPListenPortLocked() (uint16, bool) {
	localIX := manager.snapshotLocalIXLocked()
	for _, endpoint := range manager.snapshot.Endpoints {
		if !endpoint.Enabled || !snapshotEndpointIsLocal(localIX, endpoint) {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(endpoint.Transport)) {
		case "udp", "kernel_udp":
		default:
			continue
		}
		address := strings.TrimSpace(endpoint.Listen)
		if address == "" {
			address = strings.TrimSpace(endpoint.Address)
		}
		if address == "" {
			continue
		}
		port, err := experimentalTCPAddressPort(address)
		if err == nil {
			return port, true
		}
	}
	return 0, false
}

func (manager *Manager) uniqueLocalKernelUDPListenPortLocked() (uint16, bool) {
	localIX := manager.snapshotLocalIXLocked()
	var selected uint16
	for _, endpoint := range manager.snapshot.Endpoints {
		if endpoint.Transport != "udp" || !endpoint.Enabled || !snapshotEndpointIsLocal(localIX, endpoint) {
			continue
		}
		address := strings.TrimSpace(endpoint.Listen)
		if address == "" {
			address = strings.TrimSpace(endpoint.Address)
		}
		if address == "" {
			continue
		}
		port, err := experimentalTCPAddressPort(address)
		if err != nil {
			continue
		}
		if selected == 0 {
			selected = port
			continue
		}
		if selected != port {
			return 0, false
		}
	}
	return selected, selected != 0
}

func (manager *Manager) kernelUDPLocalAddress(flow dataplane.KernelUDPFlow, remoteIP netip.Addr) (netip.Addr, uint16, error) {
	if flow.LocalAddress != "" {
		localIP, localPort, err := resolveKernelTransportLocalAddress(flow.LocalAddress)
		if err != nil {
			return netip.Addr{}, 0, err
		}
		if flow.SourcePort != 0 {
			localPort = flow.SourcePort
		}
		if localPort == 0 {
			if listenPort, ok := manager.uniqueLocalKernelUDPListenPortLocked(); ok {
				localPort = listenPort
			} else {
				localPort = uint16(40000 + flow.ID%20000)
			}
		}
		return localIP, localPort, nil
	}
	localIP, err := routeSourceIPv4(remoteIP)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	localPort := flow.SourcePort
	if localPort == 0 {
		if listenPort, ok := manager.uniqueLocalKernelUDPListenPortLocked(); ok {
			localPort = listenPort
		} else {
			localPort = uint16(40000 + flow.ID%20000)
		}
	}
	return localIP, localPort, nil
}

func resolveKernelTransportLocalAddress(address string) (netip.Addr, uint16, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(address))
	if err == nil && addr.Is4() {
		return addr, 0, nil
	}
	return resolveExperimentalTCPAddress(address)
}

func resolveExperimentalTCPAddress(address string) (netip.Addr, uint16, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("parse experimental_tcp address %q: %w", address, err)
	}
	port, err := parseExperimentalTCPPort(portText)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	addr, err := netip.ParseAddr(host)
	if err == nil && addr.Is4() {
		return addr, port, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("resolve experimental_tcp host %q: %w", host, err)
	}
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			return netip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}), port, nil
		}
	}
	return netip.Addr{}, 0, fmt.Errorf("experimental_tcp host %q has no IPv4 address", host)
}

func resolveKernelTransportAddress(address string, now time.Time) (netip.Addr, uint16, time.Time, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return netip.Addr{}, 0, time.Time{}, fmt.Errorf("parse experimental_tcp address %q: %w", address, err)
	}
	port, err := parseExperimentalTCPPort(portText)
	if err != nil {
		return netip.Addr{}, 0, time.Time{}, err
	}
	addr, err := netip.ParseAddr(host)
	if err == nil && addr.Is4() {
		return addr, port, time.Time{}, nil
	}
	resolvedAt := now
	if resolvedAt.IsZero() {
		resolvedAt = time.Now().UTC()
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return netip.Addr{}, 0, time.Time{}, fmt.Errorf("resolve experimental_tcp host %q: %w", host, err)
	}
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			return netip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}), port, resolvedAt, nil
		}
	}
	return netip.Addr{}, 0, time.Time{}, fmt.Errorf("experimental_tcp host %q has no IPv4 address", host)
}

func experimentalTCPAddressPort(address string) (uint16, error) {
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		return 0, fmt.Errorf("parse experimental_tcp address %q: %w", address, err)
	}
	return parseExperimentalTCPPort(portText)
}

func parseExperimentalTCPPort(portText string) (uint16, error) {
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return 0, fmt.Errorf("parse experimental_tcp port %q", portText)
	}
	return uint16(port), nil
}

func routeSourceIPv4(remoteIP netip.Addr) (netip.Addr, error) {
	conn, err := net.Dial("udp4", net.JoinHostPort(remoteIP.String(), "9"))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("discover source address for %s: %w", remoteIP, err)
	}
	defer conn.Close()
	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || udpAddr.IP == nil {
		return netip.Addr{}, fmt.Errorf("discover source address for %s returned %T", remoteIP, conn.LocalAddr())
	}
	ip4 := udpAddr.IP.To4()
	if ip4 == nil {
		return netip.Addr{}, fmt.Errorf("source address for %s is not IPv4: %s", remoteIP, udpAddr.IP)
	}
	return netip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}), nil
}

func sendRawIPv4(packet []byte, dst [4]byte) error {
	return sendRawIPv4OnDevice(packet, dst, "")
}

func (manager *Manager) sendRawExperimentalTCPPreparedFrames(frames []preparedExperimentalTCPTXFrame) (int, error) {
	if len(frames) == 0 {
		return 0, nil
	}
	totalBytes := 0
	for i, frame := range frames {
		packetLen := frame.packetLen
		if packetLen <= 0 {
			frameLen, err := experimentaltcp.FrameWireLen(len(frame.wireFrame.Payload))
			if err != nil {
				return i, err
			}
			packetLen, err = experimentaltcp.TCPShapedIPv4WireLen(frameLen)
			if err != nil {
				return i, err
			}
		}
		totalBytes += packetLen
	}
	scratch := takeRawIPv4PacketBatchScratch(len(frames), totalBytes)
	defer putRawIPv4PacketBatchScratch(scratch)
	packets := scratch.packets
	arena := scratch.arena
	offset := 0
	for i, frame := range frames {
		packetLen := frame.packetLen
		if packetLen <= 0 {
			frameLen, err := experimentaltcp.FrameWireLen(len(frame.wireFrame.Payload))
			if err != nil {
				return i, err
			}
			packetLen, err = experimentaltcp.TCPShapedIPv4WireLen(frameLen)
			if err != nil {
				return i, err
			}
		}
		packet := arena[offset : offset+packetLen]
		offset += packetLen
		if _, err := experimentaltcp.MarshalTCPShapedIPv4FrameInto(frame.packet, frame.wireFrame, packet); err != nil {
			return i, err
		}
		packets[i] = packet
	}
	sent, err := manager.sendRawExperimentalTCPIPv4Batch(packets, frames)
	if sent > 0 {
		manager.mu.Lock()
		manager.expTCPRawTXFrames += uint64(sent)
		manager.expTCPRawTXBatches++
		manager.mu.Unlock()
	}
	return sent, err
}

func (manager *Manager) sendRawKernelUDPPreparedFrames(frames []preparedKernelUDPTXFrame) (int, error) {
	if len(frames) == 0 {
		return 0, nil
	}
	if kernelUDPUDPFallbackEnabled() {
		sent, err := manager.sendKernelUDPUDPPreparedFrames(frames)
		if err == nil {
			return sent, nil
		}
		manager.mu.Lock()
		manager.kernelUDPUDPFallbackTXFallbacks++
		manager.mu.Unlock()
		if sent > 0 {
			return sent, err
		}
	}
	return manager.sendRawKernelUDPPreparedFramesRaw(frames, false)
}

func (manager *Manager) sendRawKernelUDPPreparedFramesUnderlayPacket(frames []preparedKernelUDPTXFrame) (int, error) {
	if len(frames) == 0 {
		return 0, nil
	}
	return manager.sendRawKernelUDPPreparedFramesRaw(frames, true)
}

func (manager *Manager) sendRawKernelUDPPreparedFramesRaw(frames []preparedKernelUDPTXFrame, underlayPacket bool) (int, error) {
	totalBytes := 0
	for i, frame := range frames {
		packetLen := frame.packetWireLen
		if packetLen <= 0 {
			frameLen, err := kerneludp.FrameWireLen(len(frame.wireFrame.Payload))
			if err != nil {
				return i, err
			}
			packetLen, err = kerneludp.UDPIPv4WireLen(frameLen)
			if err != nil {
				return i, err
			}
		}
		totalBytes += packetLen
	}
	scratch := takeRawIPv4PacketBatchScratch(len(frames), totalBytes)
	defer putRawIPv4PacketBatchScratch(scratch)
	packets := scratch.packets
	arena := scratch.arena
	offset := 0
	for i, frame := range frames {
		packetLen := frame.packetWireLen
		if packetLen <= 0 {
			frameLen, err := kerneludp.FrameWireLen(len(frame.wireFrame.Payload))
			if err != nil {
				return i, err
			}
			packetLen, err = kerneludp.UDPIPv4WireLen(frameLen)
			if err != nil {
				return i, err
			}
		}
		packet := arena[offset : offset+packetLen]
		offset += packetLen
		marshal := kerneludp.MarshalUDPIPv4FrameInto
		if kernelUDPSkipUDPChecksum() {
			marshal = kerneludp.MarshalUDPIPv4FrameIntoNoChecksum
		}
		if _, err := marshal(frame.packet, frame.wireFrame, packet); err != nil {
			return i, err
		}
		packets[i] = packet
	}
	if underlayPacket {
		return manager.sendRawKernelUDPUnderlayPacketBatch(packets, frames)
	}
	return manager.sendRawKernelUDPIPv4Batch(packets, frames)
}

func (manager *Manager) sendRawKernelUDPIPv4Batch(packets [][]byte, frames []preparedKernelUDPTXFrame) (int, error) {
	if len(frames) != len(packets) {
		return 0, fmt.Errorf("send kernel_udp raw packet batch: frame count %d does not match packet count %d", len(frames), len(packets))
	}
	if rawFallbackUnderlayPacketTXEnabled() {
		if sent, err := manager.sendRawKernelUDPUnderlayPacketBatch(packets, frames); err == nil {
			return sent, nil
		}
		manager.mu.Lock()
		manager.rawUnderlayPacketTXFallbacks++
		manager.mu.Unlock()
	}
	return manager.sendRawIPv4BatchFunc(packets, "kernel_udp", func(index int) [4]byte {
		return frames[index].rawDst
	})
}

func (manager *Manager) sendRawExperimentalTCPIPv4Batch(packets [][]byte, frames []preparedExperimentalTCPTXFrame) (int, error) {
	if len(frames) != len(packets) {
		return 0, fmt.Errorf("send experimental_tcp raw packet batch: frame count %d does not match packet count %d", len(frames), len(packets))
	}
	if rawFallbackUnderlayPacketTXEnabled() {
		if sent, err := manager.sendRawExperimentalTCPUnderlayPacketBatch(packets, frames); err == nil {
			return sent, nil
		}
		manager.mu.Lock()
		manager.rawUnderlayPacketTXFallbacks++
		manager.mu.Unlock()
	}
	return manager.sendRawIPv4BatchFunc(packets, "experimental_tcp", func(index int) [4]byte {
		return frames[index].rawDst
	})
}

func (manager *Manager) sendRawKernelUDPUnderlayPacketBatch(packets [][]byte, frames []preparedKernelUDPTXFrame) (int, error) {
	return manager.sendRawUnderlayPacketBatch(packets, "kernel_udp", func(index int) [4]byte {
		return frames[index].rawDst
	})
}

func (manager *Manager) sendRawExperimentalTCPUnderlayPacketBatch(packets [][]byte, frames []preparedExperimentalTCPTXFrame) (int, error) {
	return manager.sendRawUnderlayPacketBatch(packets, "experimental_tcp", func(index int) [4]byte {
		return frames[index].rawDst
	})
}

func (manager *Manager) sendRawUnderlayPacketBatch(packets [][]byte, label string, dst func(index int) [4]byte) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	manager.mu.Lock()
	underlay := strings.TrimSpace(manager.spec.UnderlayIface)
	manager.rawUnderlayPacketTXAttempts++
	manager.mu.Unlock()
	if underlay == "" {
		return 0, fmt.Errorf("send %s underlay packet batch: underlay iface is not configured", label)
	}
	injector, err := manager.lanPacketInjectorForIface(underlay)
	if err != nil {
		return 0, err
	}
	type rawUnderlayBatch struct {
		dst    netip.Addr
		dstMAC net.HardwareAddr
		items  [][]byte
		count  int
	}
	batches := make([]rawUnderlayBatch, 0, 1)
	var batchIndexByDst map[netip.Addr]int
	firstDst := netip.Addr{}
	for index, packet := range packets {
		if len(packet) == 0 {
			return index, fmt.Errorf("send %s underlay packet batch: packet %d is empty", label, index)
		}
		if len(packet) > injector.mtu {
			return index, fmt.Errorf("%w: %s underlay packet size %d exceeds MTU %d", errMTUExceeded, label, len(packet), injector.mtu)
		}
		dstAddr := netip.AddrFrom4(dst(index))
		batchIndex := 0
		ok := false
		if len(batches) == 0 {
			dstMAC, err := manager.resolveIPv4Neighbor(injector.ifindex, dstAddr)
			if err != nil {
				return index, err
			}
			batches = append(batches, rawUnderlayBatch{
				dst:    dstAddr,
				dstMAC: dstMAC,
				items:  make([][]byte, 0, len(packets)),
			})
			firstDst = dstAddr
			ok = true
		} else if batchIndexByDst == nil && dstAddr == firstDst {
			ok = true
		} else if batchIndexByDst != nil {
			batchIndex, ok = batchIndexByDst[dstAddr]
		}
		if !ok {
			if batchIndexByDst == nil {
				batchIndexByDst = make(map[netip.Addr]int, len(batches)+1)
				for batchIndex := range batches {
					batchIndexByDst[batches[batchIndex].dst] = batchIndex
				}
			}
			dstMAC, err := manager.resolveIPv4Neighbor(injector.ifindex, dstAddr)
			if err != nil {
				return index, err
			}
			batches = append(batches, rawUnderlayBatch{
				dst:    dstAddr,
				dstMAC: dstMAC,
			})
			batchIndex = len(batches) - 1
			batchIndexByDst[dstAddr] = batchIndex
		}
		batches[batchIndex].items = append(batches[batchIndex].items, packet)
		batches[batchIndex].count++
	}
	sent := 0
	for _, batch := range batches {
		if len(batch.items) == 0 {
			continue
		}
		if len(batch.items) == 1 {
			if err := injector.send(batch.items[0], batch.dst, batch.dstMAC); err != nil {
				return sent, err
			}
			sent++
			continue
		}
		if err := injector.sendBatch(batch.items, batch.dst, batch.dstMAC); err != nil {
			return sent, err
		}
		sent += batch.count
	}
	if sent > 0 {
		manager.mu.Lock()
		manager.rawUnderlayPacketTXFrames += uint64(sent)
		manager.rawUnderlayPacketTXBatches++
		manager.mu.Unlock()
	}
	return sent, nil
}

func (manager *Manager) sendRawIPv4Batch(packets [][]byte, dsts [][4]byte, label string) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	if len(dsts) != len(packets) {
		return 0, fmt.Errorf("send %s raw packet batch: destination count %d does not match packet count %d", label, len(dsts), len(packets))
	}
	return manager.sendRawIPv4BatchFunc(packets, label, func(index int) [4]byte {
		return dsts[index]
	})
}

func (manager *Manager) sendRawIPv4BatchFunc(packets [][]byte, label string, dst func(index int) [4]byte) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	manager.rawTXMu.Lock()
	rawSocketOpened := false
	defer func() {
		manager.rawTXMu.Unlock()
		if rawSocketOpened {
			manager.mu.Lock()
			manager.rawIPv4TXSocketOpens++
			manager.mu.Unlock()
		}
	}()
	fd, opened, err := manager.rawIPv4TXSocketLocked()
	if err != nil {
		return 0, fmt.Errorf("%s raw sender socket: %w", label, err)
	}
	rawSocketOpened = opened
	scratch := takeRawIPv4SendMMSGScratch(len(packets))
	defer putRawIPv4SendMMSGScratch(scratch)
	addrs := scratch.addrs
	iovs := scratch.iovs
	msgs := scratch.msgs
	for i, packet := range packets {
		if len(packet) == 0 {
			return i, fmt.Errorf("send %s raw packet batch: packet %d is empty", label, i)
		}
		resetSendMMSGNoControl(&msgs[i])
		addrs[i] = unix.RawSockaddrInet4{Family: unix.AF_INET, Addr: dst(i)}
		iovs[i].Base = &packet[0]
		iovs[i].SetLen(len(packet))
		msgs[i].hdr.Name = (*byte)(unsafe.Pointer(&addrs[i]))
		msgs[i].hdr.Namelen = unix.SizeofSockaddrInet4
		msgs[i].hdr.Iov = &iovs[i]
		msgs[i].hdr.Iovlen = 1
	}
	var sent int
	for sent < len(msgs) {
		n, err := sendmmsg(fd, msgs[sent:])
		if n > 0 {
			sent += n
		}
		if err != nil {
			if n > 0 {
				continue
			}
			return sent, fmt.Errorf("send %s raw packet batch: %w", label, err)
		}
		if n <= 0 {
			return sent, fmt.Errorf("send %s raw packet batch: %w", label, unix.EIO)
		}
	}
	return sent, nil
}

func (manager *Manager) rawIPv4TXSocketLocked() (int, bool, error) {
	if manager.rawIPv4TXFD >= 0 && manager.rawIPv4TXFDOpen {
		return manager.rawIPv4TXFD, false, nil
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		return -1, false, fmt.Errorf("open: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		_ = unix.Close(fd)
		return -1, false, fmt.Errorf("enable IP_HDRINCL: %w", err)
	}
	manager.rawIPv4TXFD = fd
	manager.rawIPv4TXFDOpen = true
	return fd, true, nil
}

func (manager *Manager) closeRawIPv4TXSocketLocked() error {
	manager.rawTXMu.Lock()
	defer manager.rawTXMu.Unlock()
	if manager.rawIPv4TXFD < 0 || !manager.rawIPv4TXFDOpen {
		manager.rawIPv4TXFD = -1
		manager.rawIPv4TXFDOpen = false
		return nil
	}
	fd := manager.rawIPv4TXFD
	manager.rawIPv4TXFD = -1
	manager.rawIPv4TXFDOpen = false
	if err := unix.Close(fd); err != nil {
		return fmt.Errorf("close raw IPv4 TX socket: %w", err)
	}
	return nil
}

func sendRawIPv4OnDevice(packet []byte, dst [4]byte, ifname string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("open experimental_tcp raw sender socket: %w", err)
	}
	defer unix.Close(fd)
	if strings.TrimSpace(ifname) != "" {
		if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifname); err != nil {
			return fmt.Errorf("bind experimental_tcp raw sender to %q: %w", ifname, err)
		}
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		return fmt.Errorf("enable IP_HDRINCL on experimental_tcp raw sender: %w", err)
	}
	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrInet4{Addr: dst}); err != nil {
		return fmt.Errorf("send experimental_tcp raw packet to %s: %w", net.IP(dst[:]).String(), err)
	}
	return nil
}

func experimentalTCPFrameFlags(encrypted bool) uint8 {
	if encrypted {
		return experimentaltcp.FlagEncrypted
	}
	return 0
}

func (manager *Manager) experimentalTCPFastPathAvailableLocked() bool {
	return manager.expTCPFastPath != nil && manager.expTCPFastPath.Ready()
}

func (manager *Manager) experimentalTCPProviderFastPathAvailableLocked() bool {
	return !manager.experimentalTCPFastPathDisabledLocked() && manager.experimentalTCPFastPathAvailableLocked()
}

func (manager *Manager) experimentalTCPFastPathDisabledLocked() bool {
	return manager.spec.ExperimentalTCPFastPathDisabled
}

func (manager *Manager) experimentalTCPFastPathDisabledReasonLocked() string {
	return strings.TrimSpace(manager.spec.ExperimentalTCPFastPathDisabledReason)
}

func (manager *Manager) experimentalTCPFastPathProviderLocked() string {
	if manager.expTCPFastPath == nil {
		return "none"
	}
	return manager.expTCPFastPath.Provider()
}

func (manager *Manager) experimentalTCPFastPathQueuesLocked() int {
	if manager.expTCPFastPath == nil {
		return 0
	}
	return manager.expTCPFastPath.QueueCount()
}

func (manager *Manager) experimentalTCPFastPathModeLocked() (string, string, bool, string) {
	if manager.expTCPFastPath == nil {
		return "", "", false, ""
	}
	return manager.expTCPFastPath.XDPAttachMode(), manager.expTCPFastPath.AFXDPBindMode(), manager.expTCPFastPath.ZeroCopyEnabled(), manager.expTCPFastPath.ModeFallbackReason()
}

func (manager *Manager) experimentalTCPProviderStatsLocked() map[string]uint64 {
	stats := manager.kernelCryptoProviderStatsLocked()
	stats["subscriber_drops"] = manager.expTCPSubDrops
	manager.addKernelUDPTXDirectCurrentStatsLocked(stats, "")
	addLANPacketInjectorProviderStats(stats)
	manager.addTransportTelemetryStatsLocked(stats, manager.expTCPTelemetry)
	if manager.expTCPFastPath != nil {
		for name, value := range manager.expTCPFastPath.Stats() {
			stats[name] = value
		}
		stats["kernel_udp_xdp_rx_direct_veth_fallback"] = boolCounter(manager.kernelUDPXDPRXDirectVethFallback)
		stats["kernel_udp_xdp_rx_secure_direct_veth_fallback"] = boolCounter(manager.kernelUDPXDPRXSecureDirectVethFallback)
	}
	if manager.expTCPFastPath != nil || experimentalTCPRawFallbackEnabled() {
		stats["effective_payload_max"] = uint64(manager.experimentalTCPPayloadMaxLocked(dataplane.CryptoPlacementUserspace, false))
		stats["effective_payload_max_secure"] = uint64(manager.experimentalTCPPayloadMaxLocked(dataplane.CryptoPlacementUserspace, true))
		stats["effective_payload_max_kernel"] = uint64(manager.experimentalTCPPayloadMaxLocked(dataplane.CryptoPlacementKernel, true))
		if mtu := manager.experimentalTCPUnderlayMTULocked(); mtu > 0 {
			stats["underlay_mtu_l3"] = uint64(mtu)
		}
		stats["allowed_ports"] = uint64(len(manager.expTCPAllowed))
	}
	if experimentalTCPRawFallbackEnabled() {
		stats["raw_ipv4_tx_socket_open"] = boolCounter(manager.rawIPv4TXFD >= 0 && manager.rawIPv4TXFDOpen)
		stats["raw_ipv4_tx_socket_opens"] = manager.rawIPv4TXSocketOpens
		manager.addRawUnderlayPacketTXStatsLocked(stats)
		stats["raw_tcp_tx_frames"] = manager.expTCPRawTXFrames
		stats["raw_tcp_tx_batches"] = manager.expTCPRawTXBatches
	}
	manager.addStandaloneKernelUDPXDPRXDirectStatsLocked(stats)
	return stats
}

func (manager *Manager) kernelUDPProviderStatsLocked() map[string]uint64 {
	stats := map[string]uint64{
		"allowed_ports":    uint64(len(manager.kernelUDPAllowed)),
		"active_flows":     uint64(len(manager.kernelUDPFlows)),
		"submitted_frames": manager.kernelUDPSubmitted,
		"received_frames":  manager.kernelUDPReceived,
		"subscriber_drops": manager.kernelUDPSubDrops,
	}
	stats["tc_only_requested"] = boolCounter(kernelUDPTCOnlyProviderRequestedForSpec(manager.spec))
	stats["tc_only_eligible"] = boolCounter(manager.kernelUDPTCOnlyEligibleLocked())
	stats["tc_only_snapshot_eligible"] = boolCounter(manager.snapshotKernelUDPTCOnlyEligibleLocked())
	stats["tc_only_available"] = boolCounter(manager.kernelUDPTCDirectOnlyAvailableLocked())
	stats["tc_only_pending"] = boolCounter(manager.kernelUDPTCDirectOnlyPendingLocked())
	stats["tc_only_blocking_experimental_tcp_flows"] = uint64(len(manager.expTCPFlows))
	stats["tc_rx_direct_attached"] = boolCounter(manager.kernelUDPRXDirectAttached)
	stats["tc_underlay_ingress_prog_loaded"] = boolCounter(manager.underlayIngressProg != nil)
	stats["tc_underlay_ingress_filter_loaded"] = boolCounter(manager.underlayIngressFilter != nil)
	stats["tc_transport_port_map_loaded"] = boolCounter(manager.kernelTransportPortMap != nil)
	stats["tc_stats_map_loaded"] = boolCounter(manager.statsMap != nil)
	stats["tc_tx_route_map_loaded"] = boolCounter(manager.kernelUDPTXRouteMap != nil)
	stats["tc_tx_flow_map_loaded"] = boolCounter(manager.kernelUDPTXFlowMap != nil)
	stats["tc_lan_iface_configured"] = boolCounter(strings.TrimSpace(manager.spec.LANIface) != "")
	stats["tc_underlay_iface_configured"] = boolCounter(strings.TrimSpace(manager.spec.UnderlayIface) != "")
	stats["af_xdp_idle_fallback_enabled"] = boolCounter(kernelUDPAFXDPIdleFallbackEnabled())
	stats["af_xdp_idle_fallback_underlay_packet"] = boolCounter(kernelUDPAFXDPIdleFallbackUnderlayPacketEnabled())
	if after := kernelUDPAFXDPIdleFallbackAfter(); after > 0 {
		stats["af_xdp_idle_fallback_after_ns"] = uint64(after)
	} else {
		stats["af_xdp_idle_fallback_after_ns"] = 0
	}
	stats["af_xdp_idle_fallback_max_frames"] = uint64(kernelUDPAFXDPIdleFallbackMaxFrames())
	stats["af_xdp_idle_fallback_attempts"] = manager.kernelUDPAFXDPIdleFallbackAttempts
	stats["af_xdp_idle_fallback_batches"] = manager.kernelUDPAFXDPIdleFallbackBatches
	stats["af_xdp_idle_fallback_frames"] = manager.kernelUDPAFXDPIdleFallbackFrames
	stats["af_xdp_idle_fallback_sent_frames"] = manager.kernelUDPAFXDPIdleFallbackSentFrames
	stats["af_xdp_idle_fallback_errors"] = manager.kernelUDPAFXDPIdleFallbackErrors
	stats["af_xdp_idle_fallback_skips"] = manager.kernelUDPAFXDPIdleFallbackSkips
	if kernelUDPRawFallbackEnabled() {
		stats["raw_udp_fallback_enabled"] = 1
		stats["raw_udp_fallback_socket_open"] = boolCounter(manager.kernelUDPRawFD >= 0)
		stats["udp_socket_fallback_enabled"] = boolCounter(kernelUDPUDPFallbackEnabled())
		manager.kernelUDPUDPFallbackMu.RLock()
		stats["udp_socket_fallback_sockets"] = uint64(len(manager.kernelUDPUDPFallbackSockets))
		manager.kernelUDPUDPFallbackMu.RUnlock()
		stats["udp_socket_fallback_tx_frames"] = manager.kernelUDPUDPFallbackTXFrames
		stats["udp_socket_fallback_rx_frames"] = manager.kernelUDPUDPFallbackRXFrames
		stats["udp_socket_fallback_tx_batches"] = manager.kernelUDPUDPFallbackTXBatches
		stats["udp_socket_fallback_rx_batches"] = manager.kernelUDPUDPFallbackRXBatches
		stats["udp_socket_fallback_tx_fallbacks"] = manager.kernelUDPUDPFallbackTXFallbacks
		stats["udp_socket_fallback_bind_errors"] = manager.kernelUDPUDPFallbackBindErrors
		stats["udp_socket_fallback_gso_enabled"] = boolCounter(kernelUDPUDPFallbackGSOEnabled() && !manager.kernelUDPUDPFallbackGSODisabled.Load())
		stats["udp_socket_fallback_gso_scatter"] = boolCounter(kernelUDPUDPFallbackGSOScatterEnabled() && !manager.kernelUDPUDPFallbackGSOScatterDisabled.Load())
		stats["udp_socket_fallback_gso_run_batch"] = boolCounter(kernelUDPUDPFallbackGSORunBatchEnabled())
		stats["udp_socket_fallback_gso_attempts"] = manager.kernelUDPUDPFallbackGSOAttempts
		stats["udp_socket_fallback_gso_successes"] = manager.kernelUDPUDPFallbackGSOSuccesses
		stats["udp_socket_fallback_gso_frames"] = manager.kernelUDPUDPFallbackGSOFrames
		stats["udp_socket_fallback_gso_batches"] = manager.kernelUDPUDPFallbackGSOBatches
		stats["udp_socket_fallback_gso_fallbacks"] = manager.kernelUDPUDPFallbackGSOFallbacks
		stats["udp_socket_fallback_gso_scatter_attempts"] = manager.kernelUDPUDPFallbackGSOScatterAttempts
		stats["udp_socket_fallback_gso_scatter_successes"] = manager.kernelUDPUDPFallbackGSOScatterSuccesses
		stats["udp_socket_fallback_gso_scatter_fallbacks"] = manager.kernelUDPUDPFallbackGSOScatterFallbacks
		stats["raw_ipv4_tx_socket_open"] = boolCounter(manager.rawIPv4TXFD >= 0 && manager.rawIPv4TXFDOpen)
		stats["raw_ipv4_tx_socket_opens"] = manager.rawIPv4TXSocketOpens
		manager.addRawUnderlayPacketTXStatsLocked(stats)
		stats["raw_udp_tx_frames"] = manager.kernelUDPRawTXFrames
		stats["raw_udp_rx_frames"] = manager.kernelUDPRawRXFrames
		stats["raw_udp_tx_batches"] = manager.kernelUDPRawTXBatches
		stats["raw_udp_rx_batches"] = manager.kernelUDPRawRXBatches
		stats["effective_payload_max"] = uint64(manager.kernelUDPRawFallbackPayloadMaxLocked(dataplane.CryptoPlacementUserspace, false))
		stats["effective_payload_max_secure"] = uint64(manager.kernelUDPRawFallbackPayloadMaxLocked(dataplane.CryptoPlacementUserspace, true))
		if mtu := manager.experimentalTCPUnderlayMTULocked(); mtu > 0 {
			stats["underlay_mtu_l3"] = uint64(mtu)
		}
	}
	manager.addKernelUDPTCHotStatsLocked(stats)
	manager.addKernelUDPTXDirectCurrentStatsLocked(stats, "")
	manager.addKernelUDPRXDirectCurrentStatsLocked(stats, "")
	manager.addKernelUDPTXDirectSyncStatsLocked(stats, "")
	addLANPacketInjectorProviderStats(stats)
	manager.addTransportTelemetryStatsFromItemsLocked(stats, manager.kernelUDPTelemetrySnapshotLocked())
	if manager.expTCPFastPath != nil {
		for name, value := range manager.expTCPFastPath.Stats() {
			stats[name] = value
		}
		stats["kernel_udp_xdp_rx_direct_veth_fallback"] = boolCounter(manager.kernelUDPXDPRXDirectVethFallback)
		stats["kernel_udp_xdp_rx_secure_direct_veth_fallback"] = boolCounter(manager.kernelUDPXDPRXSecureDirectVethFallback)
	}
	manager.addStandaloneKernelUDPXDPRXDirectStatsLocked(stats)
	for name, value := range manager.kernelCryptoProviderStatsLocked() {
		stats[name] = value
	}
	return stats
}

func (manager *Manager) addRawUnderlayPacketTXStatsLocked(stats map[string]uint64) {
	if stats == nil {
		return
	}
	stats["raw_underlay_packet_tx_enabled"] = boolCounter(rawFallbackUnderlayPacketTXEnabled())
	stats["raw_underlay_packet_tx_attempts"] = manager.rawUnderlayPacketTXAttempts
	stats["raw_underlay_packet_tx_frames"] = manager.rawUnderlayPacketTXFrames
	stats["raw_underlay_packet_tx_batches"] = manager.rawUnderlayPacketTXBatches
	stats["raw_underlay_packet_tx_fallbacks"] = manager.rawUnderlayPacketTXFallbacks
}

func (manager *Manager) addStandaloneKernelUDPXDPRXDirectStatsLocked(stats map[string]uint64) {
	if stats == nil || manager.kernelUDPXDPRXDirectObject == nil {
		return
	}
	stats["kernel_udp_xdp_rx_direct_standalone"] = 1
	stats["kernel_udp_xdp_rx_direct_standalone_attached"] = boolCounter(manager.kernelUDPXDPRXDirectAttached)
	stats["kernel_udp_xdp_rx_direct_standalone_skb"] = boolCounter(manager.kernelUDPXDPRXDirectAttachMode == expTCPXDPAttachSKB)
	stats["kernel_udp_xdp_rx_direct_standalone_native"] = boolCounter(manager.kernelUDPXDPRXDirectAttachMode == expTCPXDPAttachNative)
	stats["kernel_udp_xdp_rx_direct_fallback_pass"] = boolCounter(manager.kernelUDPXDPRXDirectFallbackPass)
	stats["kernel_udp_xdp_rx_direct_trust_inner_checksum"] = boolCounter(kernelUDPXDPRXDirectTrustInnerChecksumEnabled())
	for name, value := range experimentalTCPXDPStatsFromMap(manager.kernelUDPXDPRXDirectObject.xdpStatsMap) {
		stats[name] = value
	}
}

func (manager *Manager) addKernelUDPTCHotStatsLocked(stats map[string]uint64) {
	if stats == nil || manager.statsMap == nil {
		return
	}
	keys := []struct {
		key  uint32
		name string
	}{
		{key: 0, name: "tc_ingress_packets"},
		{key: 1, name: "tc_egress_packets"},
		{key: 2, name: "tc_ingress_route_hits"},
		{key: 3, name: "tc_ingress_route_misses"},
		{key: 4, name: "tc_ingress_ipv4_packets"},
		{key: 6, name: "tc_ingress_parse_errors"},
		{key: 7, name: "tc_capture_events"},
		{key: 8, name: "tc_capture_errors"},
		{key: captureStatPullErrors, name: "tc_capture_pull_errors"},
		{key: captureStatLinearShortErrors, name: "tc_capture_linear_short_errors"},
		{key: captureStatEtherTypeErrors, name: "tc_capture_ethertype_errors"},
		{key: captureStatHeaderShortErrors, name: "tc_capture_header_short_errors"},
		{key: captureStatRouteMissErrors, name: "tc_capture_route_miss_errors"},
		{key: captureStatReady, name: "tc_capture_ready"},
		{key: captureStatScratchMisses, name: "tc_capture_scratch_misses"},
		{key: captureStatLoadBytesErrors, name: "tc_capture_load_bytes_errors"},
		{key: captureStatPerfErrors, name: "tc_capture_perf_errors"},
		{key: captureStatPerfErrENOENT, name: "tc_capture_perf_err_enoent"},
		{key: captureStatPerfErrEFAULT, name: "tc_capture_perf_err_efault"},
		{key: captureStatPerfErrEINVAL, name: "tc_capture_perf_err_einval"},
		{key: captureStatPerfErrE2BIG, name: "tc_capture_perf_err_e2big"},
		{key: captureStatPerfErrENOSPC, name: "tc_capture_perf_err_enospc"},
		{key: captureStatPerfErrEPERM, name: "tc_capture_perf_err_eperm"},
		{key: captureStatPerfErrOther, name: "tc_capture_perf_err_other"},
		{key: captureStatPerfLastErrno, name: "tc_capture_perf_last_errno"},
		{key: 15, name: "tc_packet_mtu_drops"},
		{key: 16, name: "tc_packet_fragment_drops"},
		{key: kernelUDPTXStatSuccess, name: "tc_kernel_udp_tx_direct_packets"},
		{key: kernelUDPTXStatErrors, name: "tc_kernel_udp_tx_direct_errors"},
		{key: kernelUDPTXStatDrops, name: "tc_kernel_udp_tx_direct_drops"},
		{key: kernelUDPRXDirectStatSuccess, name: "tc_kernel_udp_rx_direct_packets"},
		{key: kernelUDPRXDirectStatErrors, name: "tc_kernel_udp_rx_direct_errors"},
		{key: kernelUDPRXDirectStatDrops, name: "tc_kernel_udp_rx_direct_drops"},
		{key: kernelUDPRXDirectStatPasses, name: "tc_kernel_udp_rx_direct_candidates"},
		{key: kernelUDPTXSecureDirectStatAttempts, name: "tc_kernel_udp_tx_secure_direct_attempts"},
		{key: kernelUDPTXSecureDirectStatCandidates, name: "tc_kernel_udp_tx_secure_direct_candidates"},
		{key: kernelUDPTXSecureDirectStatSuccess, name: "tc_kernel_udp_tx_secure_direct_packets"},
		{key: kernelUDPTXSecureDirectStatFallbacks, name: "tc_kernel_udp_tx_secure_direct_fallbacks"},
		{key: kernelUDPTXSecureDirectStatNoContext, name: "tc_kernel_udp_tx_secure_direct_no_context"},
		{key: kernelUDPTXSecureDirectStatHeaderErrors, name: "tc_kernel_udp_tx_secure_direct_header_errors"},
		{key: kernelUDPTXSecureDirectStatEncryptErrors, name: "tc_kernel_udp_tx_secure_direct_encrypt_errors"},
		{key: kernelUDPTXSecureDirectStatSequenceErrors, name: "tc_kernel_udp_tx_secure_direct_sequence_errors"},
		{key: kernelUDPTXSecureDirectStatMTUFallbacks, name: "tc_kernel_udp_tx_secure_direct_mtu_fallbacks"},
		{key: kernelUDPTXSecureDirectStatDrops, name: "tc_kernel_udp_tx_secure_direct_drops"},
		{key: kernelUDPTXSecureDirectStatRouteMisses, name: "tc_kernel_udp_tx_secure_direct_route_misses"},
		{key: kernelUDPTXSecureDirectStatFlowMisses, name: "tc_kernel_udp_tx_secure_direct_flow_misses"},
		{key: kernelUDPTXSecureDirectStatFlagMisses, name: "tc_kernel_udp_tx_secure_direct_flag_misses"},
		{key: kernelUDPTXSecureDirectStatFragmentFallbacks, name: "tc_kernel_udp_tx_secure_direct_fragment_fallbacks"},
		{key: kernelUDPTXSecureDirectStatLenMismatches, name: "tc_kernel_udp_tx_secure_direct_len_mismatches"},
		{key: kernelUDPTXSecureDirectStatChecksumFallbacks, name: "tc_kernel_udp_tx_secure_direct_checksum_fallbacks"},
		{key: kernelUDPTXSecureDirectStatMTUPlainMaxFallbacks, name: "tc_kernel_udp_tx_secure_direct_mtu_plain_max_fallbacks"},
		{key: kernelUDPTXSecureDirectStatMTUUnderlayFallbacks, name: "tc_kernel_udp_tx_secure_direct_mtu_underlay_fallbacks"},
		{key: kernelUDPTXSecureDirectStatLenGSOFallbacks, name: "tc_kernel_udp_tx_secure_direct_len_gso_fallbacks"},
		{key: kernelUDPTXSecureDirectStatLenShortFallbacks, name: "tc_kernel_udp_tx_secure_direct_len_short_fallbacks"},
		{key: kernelUDPTXSecureDirectStatFlowIndexMisses, name: "tc_kernel_udp_tx_secure_direct_flow_index_misses"},
		{key: kernelUDPTXSecureDirectStatDirectSlotMisses, name: "tc_kernel_udp_tx_secure_direct_direct_slot_misses"},
		{key: kernelUDPTXSecureDirectStatDirectSlotDisabled, name: "tc_kernel_udp_tx_secure_direct_direct_slot_disabled"},
		{key: 179, name: "tc_kernel_udp_tx_secure_direct_skb_seal_successes"},
		{key: 180, name: "tc_kernel_udp_tx_secure_direct_skb_seal_errors"},
		{key: kernelUDPTXSecureDirectStatInnerTCPChecksumKfuncSuccesses, name: "tc_kernel_udp_tx_secure_direct_inner_tcp_checksum_kfunc_successes"},
		{key: kernelUDPTXSecureDirectStatInnerTCPChecksumKfuncFallbacks, name: "tc_kernel_udp_tx_secure_direct_inner_tcp_checksum_kfunc_fallbacks"},
		{key: kernelUDPRXSecureDirectStatAttempts, name: "tc_kernel_udp_rx_secure_direct_attempts"},
		{key: kernelUDPRXSecureDirectStatCandidates, name: "tc_kernel_udp_rx_secure_direct_candidates"},
		{key: kernelUDPRXSecureDirectStatSuccess, name: "tc_kernel_udp_rx_secure_direct_packets"},
		{key: kernelUDPRXSecureDirectStatFallbacks, name: "tc_kernel_udp_rx_secure_direct_fallbacks"},
		{key: kernelUDPRXSecureDirectStatNoContext, name: "tc_kernel_udp_rx_secure_direct_no_context"},
		{key: kernelUDPRXSecureDirectStatHeaderErrors, name: "tc_kernel_udp_rx_secure_direct_header_errors"},
		{key: kernelUDPRXSecureDirectStatDecryptErrors, name: "tc_kernel_udp_rx_secure_direct_decrypt_errors"},
		{key: kernelUDPRXSecureDirectStatReplayDrops, name: "tc_kernel_udp_rx_secure_direct_replay_drops"},
		{key: kernelUDPRXSecureDirectStatDrops, name: "tc_kernel_udp_rx_secure_direct_drops"},
		{key: kernelUDPRXSecureDirectStatNeighHits, name: "tc_kernel_udp_rx_secure_direct_neighbor_hits"},
		{key: kernelUDPRXSecureDirectStatNeighMisses, name: "tc_kernel_udp_rx_secure_direct_neighbor_misses"},
		{key: kernelUDPRXSecureDirectStatAdjustErrors, name: "tc_kernel_udp_rx_secure_direct_adjust_errors"},
		{key: kernelUDPRXSecureDirectStatStoreErrors, name: "tc_kernel_udp_rx_secure_direct_store_errors"},
		{key: kernelUDPRXSecureDirectStatBroadcasts, name: "tc_kernel_udp_rx_secure_direct_broadcasts"},
		{key: kernelUDPRXSecureDirectStatPeerRedirects, name: "tc_kernel_udp_rx_secure_direct_peer_redirects"},
		{key: kernelUDPRXSecureDirectStatRedirects, name: "tc_kernel_udp_rx_secure_direct_redirects"},
		{key: kernelUDPRXSecureDirectStatDebugL2IPv4, name: "tc_kernel_udp_rx_secure_direct_debug_l2_ipv4"},
		{key: kernelUDPRXSecureDirectStatDebugL3IPv4, name: "tc_kernel_udp_rx_secure_direct_debug_l3_ipv4"},
		{key: kernelUDPRXSecureDirectStatDebugUDP, name: "tc_kernel_udp_rx_secure_direct_debug_udp"},
		{key: kernelUDPRXSecureDirectStatDebugTIXUMagic, name: "tc_kernel_udp_rx_secure_direct_debug_tixu_magic"},
		{key: kernelUDPRXSecureDirectStatDebugTIXUHeader, name: "tc_kernel_udp_rx_secure_direct_debug_tixu_header"},
		{key: kernelUDPRXSecureDirectStatDebugTIXUFlags, name: "tc_kernel_udp_rx_secure_direct_debug_tixu_flags"},
		{key: kernelUDPRXSecureDirectStatDebugTIXULen, name: "tc_kernel_udp_rx_secure_direct_debug_tixu_len"},
		{key: kernelUDPRXSecureDirectStatDebugPort, name: "tc_kernel_udp_rx_secure_direct_debug_port"},
		{key: kernelUDPRXSecureDirectStatDebugSecureHeader, name: "tc_kernel_udp_rx_secure_direct_debug_secure_header"},
		{key: kernelUDPRXSecureDirectStatDebugL3TIXUMagic, name: "tc_kernel_udp_rx_secure_direct_debug_l3_tixu_magic"},
		{key: kernelUDPRXSecureDirectStatErrPayloadLen, name: "tc_kernel_udp_rx_secure_direct_err_payload_len"},
		{key: kernelUDPRXSecureDirectStatErrCipherLen, name: "tc_kernel_udp_rx_secure_direct_err_cipher_len"},
		{key: kernelUDPRXSecureDirectStatErrSecureMagic, name: "tc_kernel_udp_rx_secure_direct_err_secure_magic"},
		{key: kernelUDPRXSecureDirectStatErrSecureEpoch, name: "tc_kernel_udp_rx_secure_direct_err_secure_epoch"},
		{key: kernelUDPRXSecureDirectStatErrContextEpoch, name: "tc_kernel_udp_rx_secure_direct_err_context_epoch"},
		{key: kernelUDPRXSecureDirectStatErrOpenEINVAL, name: "tc_kernel_udp_rx_secure_direct_err_open_einval"},
		{key: kernelUDPRXSecureDirectStatErrOpenEBADMSG, name: "tc_kernel_udp_rx_secure_direct_err_open_ebadmsg"},
		{key: kernelUDPRXSecureDirectStatErrInnerIPv4, name: "tc_kernel_udp_rx_secure_direct_err_inner_ipv4"},
		{key: kernelUDPRXDirectStatNeighHits, name: "tc_kernel_udp_rx_direct_neighbor_hits"},
		{key: kernelUDPRXDirectStatNeighMisses, name: "tc_kernel_udp_rx_direct_neighbor_misses"},
		{key: kernelUDPTXDirectStatRouteMisses, name: "tc_kernel_udp_tx_direct_route_misses"},
		{key: kernelUDPTXDirectStatFlowMisses, name: "tc_kernel_udp_tx_direct_flow_misses"},
		{key: kernelUDPTXDirectStatSecureFlowFallbacks, name: "tc_kernel_udp_tx_direct_secure_flow_fallbacks"},
		{key: kernelUDPTXDirectStatNonIPv4Fallbacks, name: "tc_kernel_udp_tx_direct_non_ipv4_fallbacks"},
		{key: kernelUDPTXDirectStatFragmentFallbacks, name: "tc_kernel_udp_tx_direct_fragment_fallbacks"},
		{key: kernelUDPTXDirectStatLenShortFallbacks, name: "tc_kernel_udp_tx_direct_len_short_fallbacks"},
		{key: kernelUDPTXDirectStatLenGSOFallbacks, name: "tc_kernel_udp_tx_direct_len_gso_fallbacks"},
		{key: kernelUDPTXDirectStatLenMismatches, name: "tc_kernel_udp_tx_direct_len_mismatches"},
		{key: kernelUDPTXDirectStatMTUFallbacks, name: "tc_kernel_udp_tx_direct_mtu_fallbacks"},
		{key: kernelUDPTXDirectStatRouteFlowZeroFallbacks, name: "tc_kernel_udp_tx_direct_route_flow_zero_fallbacks"},
		{key: kernelUDPTXDirectStatMTULinearFallbacks, name: "tc_kernel_udp_tx_direct_mtu_linear_fallbacks"},
		{key: kernelUDPTXDirectStatMTUGSOFallbacks, name: "tc_kernel_udp_tx_direct_mtu_gso_fallbacks"},
		{key: kernelUDPTXDirectStatMTUGSOSizeZeroFallbacks, name: "tc_kernel_udp_tx_direct_mtu_gso_size_zero_fallbacks"},
		{key: kernelUDPTXDirectStatMTUGSOBypasses, name: "tc_kernel_udp_tx_direct_mtu_gso_bypasses"},
		{key: kernelUDPTXDirectStatDirectOnlyDrops, name: "tc_kernel_udp_tx_direct_only_drops"},
		{key: kernelUDPTXDirectStatInnerTCPChecksumFixes, name: "tc_kernel_udp_tx_direct_inner_tcp_checksum_fixes"},
		{key: kernelUDPTXDirectStatInnerTCPChecksumStoreErrors, name: "tc_kernel_udp_tx_direct_inner_tcp_checksum_store_errors"},
		{key: kernelUDPTXDirectStatInnerTCPChecksumNotTCP, name: "tc_kernel_udp_tx_direct_inner_tcp_checksum_not_tcp"},
		{key: kernelUDPTXDirectStatInnerTCPChecksumKfuncFixes, name: "tc_kernel_udp_tx_direct_inner_tcp_checksum_kfunc_fixes"},
		{key: kernelUDPTXDirectStatInnerTCPChecksumKfuncFallbacks, name: "tc_kernel_udp_tx_direct_inner_tcp_checksum_kfunc_fallbacks"},
		{key: kernelUDPTXDirectStatAdjustDrops, name: "tc_kernel_udp_tx_direct_adjust_drops"},
		{key: kernelUDPTXDirectStatPostAdjustHeaderDrops, name: "tc_kernel_udp_tx_direct_post_adjust_header_drops"},
		{key: kernelUDPTXDirectStatSKBClearTXOffloadDrops, name: "tc_kernel_udp_tx_direct_skb_clear_tx_offload_drops"},
		{key: kernelUDPTXDirectStatInnerTCPChecksumGSOSkips, name: "tc_kernel_udp_tx_direct_inner_tcp_checksum_gso_skips"},
		{key: kernelUDPTXDirectStatInnerUDPChecksumFixes, name: "tc_kernel_udp_tx_direct_inner_udp_checksum_fixes"},
		{key: kernelUDPTXDirectStatInnerUDPChecksumStoreErrors, name: "tc_kernel_udp_tx_direct_inner_udp_checksum_store_errors"},
		{key: kernelUDPTXDirectStatInnerUDPChecksumInvalid, name: "tc_kernel_udp_tx_direct_inner_udp_checksum_invalid"},
		{key: kernelUDPTXDirectStatGSOInputs, name: "tc_kernel_udp_tx_direct_gso_inputs"},
		{key: kernelUDPTXDirectStatGSOActiveAccepts, name: "tc_kernel_udp_tx_direct_gso_active_accepts"},
		{key: kernelUDPTXDirectStatLinearAccepts, name: "tc_kernel_udp_tx_direct_linear_accepts"},
		{key: kernelUDPTXDirectStatGSOSuccesses, name: "tc_kernel_udp_tx_direct_gso_successes"},
		{key: kernelUDPTXDirectStatOuterTCPChecksumKfuncFixes, name: "tc_kernel_udp_tx_direct_outer_tcp_checksum_kfunc_fixes"},
		{key: kernelUDPTXDirectStatOuterTCPChecksumKfuncDrops, name: "tc_kernel_udp_tx_direct_outer_tcp_checksum_kfunc_drops"},
		{key: kernelUDPTXDirectStatRouteTCPGSOSuccesses, name: "tc_experimental_tcp_tx_direct_route_tcp_gso_kfunc_successes"},
		{key: kernelUDPTXDirectStatRouteTCPGSOFallbacks, name: "tc_experimental_tcp_tx_direct_route_tcp_gso_kfunc_fallbacks"},
		{key: kernelUDPTXDirectStatRouteTCPGSODrops, name: "tc_experimental_tcp_tx_direct_route_tcp_gso_kfunc_drops"},
		{key: kernelUDPTXDirectStatRouteTCPXmitSuccesses, name: "tc_experimental_tcp_tx_direct_route_tcp_xmit_kfunc_successes"},
		{key: kernelUDPTXDirectStatRouteTCPXmitFallbacks, name: "tc_experimental_tcp_tx_direct_route_tcp_xmit_kfunc_fallbacks"},
		{key: kernelUDPTXDirectStatRouteTCPXmitDrops, name: "tc_experimental_tcp_tx_direct_route_tcp_xmit_kfunc_drops"},
		{key: kernelUDPTXDirectStatPushFlowTCPHeaderKfuncSuccesses, name: "tc_experimental_tcp_tx_direct_push_flow_outer_tcp_header_kfunc_successes"},
		{key: kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEINVAL, name: "tc_experimental_tcp_tx_direct_push_flow_outer_tcp_header_kfunc_einval"},
		{key: kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEPROTONOSUPPORT, name: "tc_experimental_tcp_tx_direct_push_flow_outer_tcp_header_kfunc_eprotonosupport"},
		{key: kernelUDPTXDirectStatPushFlowTCPHeaderKfuncENOMEM, name: "tc_experimental_tcp_tx_direct_push_flow_outer_tcp_header_kfunc_enomem"},
		{key: kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEMSGSIZE, name: "tc_experimental_tcp_tx_direct_push_flow_outer_tcp_header_kfunc_emsgsize"},
		{key: kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEFAULT, name: "tc_experimental_tcp_tx_direct_push_flow_outer_tcp_header_kfunc_efault"},
		{key: kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEIO, name: "tc_experimental_tcp_tx_direct_push_flow_outer_tcp_header_kfunc_eio"},
		{key: kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEBADMSG, name: "tc_experimental_tcp_tx_direct_push_flow_outer_tcp_header_kfunc_ebadmsg"},
		{key: kernelUDPTXDirectStatPushFlowTCPHeaderKfuncENODEV, name: "tc_experimental_tcp_tx_direct_push_flow_outer_tcp_header_kfunc_enodev"},
		{key: kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEPERM, name: "tc_experimental_tcp_tx_direct_push_flow_outer_tcp_header_kfunc_eperm"},
		{key: kernelUDPTXDirectStatPushFlowTCPHeaderKfuncENOSPC, name: "tc_experimental_tcp_tx_direct_push_flow_outer_tcp_header_kfunc_enospc"},
		{key: kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEAGAIN, name: "tc_experimental_tcp_tx_direct_push_flow_outer_tcp_header_kfunc_eagain"},
		{key: kernelUDPTXDirectStatPushFlowTCPHeaderKfuncOtherDrops, name: "tc_experimental_tcp_tx_direct_push_flow_outer_tcp_header_kfunc_other_drops"},
		{key: kernelUDPRXDirectStatFrameHeaderErrors, name: "tc_kernel_udp_rx_direct_frame_header_errors"},
		{key: kernelUDPRXDirectStatInnerHeaderErrors, name: "tc_kernel_udp_rx_direct_inner_header_errors"},
		{key: kernelUDPRXDirectStatInnerLenErrors, name: "tc_kernel_udp_rx_direct_inner_len_errors"},
		{key: kernelUDPRXDirectStatOuterLenErrors, name: "tc_kernel_udp_rx_direct_outer_len_errors"},
		{key: kernelUDPRXDirectStatAdjustDrops, name: "tc_kernel_udp_rx_direct_adjust_drops"},
		{key: kernelUDPRXDirectStatStoreDrops, name: "tc_kernel_udp_rx_direct_store_drops"},
		{key: kernelUDPRXDirectStatLocalDeliveries, name: "tc_kernel_udp_rx_direct_local_deliveries"},
	}
	for _, item := range keys {
		value, err := bpfCounterValue(manager.statsMap, item.key)
		if err != nil {
			continue
		}
		stats[item.name] = value
	}
}

func addLANPacketInjectorProviderStats(stats map[string]uint64) {
	if stats == nil {
		return
	}
	stats["lan_reinject_gso_attempts"] = lanPacketStats.gsoAttempts.Load()
	stats["lan_reinject_gso_successes"] = lanPacketStats.gsoSuccesses.Load()
	stats["lan_reinject_gso_unsupported"] = lanPacketStats.gsoUnsupported.Load()
	stats["lan_reinject_gso_errors"] = lanPacketStats.gsoErrors.Load()
	stats["lan_reinject_gso_disabled"] = lanPacketStats.gsoDisabled.Load()
	stats["lan_reinject_gso_raw_attempts"] = lanPacketStats.gsoRawAttempts.Load()
	stats["lan_reinject_gso_raw_successes"] = lanPacketStats.gsoRawSuccesses.Load()
	stats["lan_reinject_gso_raw_batch_attempts"] = lanPacketStats.gsoRawBatchAttempts.Load()
	stats["lan_reinject_gso_raw_batch_successes"] = lanPacketStats.gsoRawBatchSuccesses.Load()
	stats["lan_reinject_gso_raw_batch_messages"] = lanPacketStats.gsoRawBatchMessages.Load()
	stats["lan_reinject_gso_raw_mixed_attempts"] = lanPacketStats.gsoRawMixedAttempts.Load()
	stats["lan_reinject_gso_raw_mixed_successes"] = lanPacketStats.gsoRawMixedSuccesses.Load()
	stats["lan_reinject_gso_raw_mixed_messages"] = lanPacketStats.gsoRawMixedMessages.Load()
	stats["lan_reinject_raw_vnet_batch_attempts"] = lanPacketStats.rawVNetBatchAttempts.Load()
	stats["lan_reinject_raw_vnet_batch_successes"] = lanPacketStats.rawVNetBatchSuccesses.Load()
	stats["lan_reinject_raw_vnet_batch_messages"] = lanPacketStats.rawVNetBatchMessages.Load()
	stats["lan_reinject_raw_vnet_batch_errors"] = lanPacketStats.rawVNetBatchErrors.Load()
	stats["lan_reinject_raw_vnet_batch_unsupported"] = lanPacketStats.rawVNetBatchUnsupported.Load()
	stats["lan_reinject_gso_raw_scatter_attempts"] = lanPacketStats.gsoRawScatterAttempts.Load()
	stats["lan_reinject_gso_raw_scatter_successes"] = lanPacketStats.gsoRawScatterSuccesses.Load()
	stats["lan_reinject_gso_raw_scatter_messages"] = lanPacketStats.gsoRawScatterMessages.Load()
	stats["lan_reinject_gso_cooked_attempts"] = lanPacketStats.gsoCookedAttempts.Load()
	stats["lan_reinject_gso_cooked_successes"] = lanPacketStats.gsoCookedSuccesses.Load()
	stats["lan_reinject_gso_error_einval"] = lanPacketStats.gsoErrnoEINVAL.Load()
	stats["lan_reinject_gso_error_emsgsize"] = lanPacketStats.gsoErrnoEMSGSIZE.Load()
	stats["lan_reinject_gso_error_eopnotsupp"] = lanPacketStats.gsoErrnoEOPNOTSUPP.Load()
	stats["lan_reinject_gso_error_enoprotoopt"] = lanPacketStats.gsoErrnoENOPROTOOPT.Load()
	stats["lan_reinject_gso_error_eperm"] = lanPacketStats.gsoErrnoEPERM.Load()
	stats["lan_reinject_gso_error_eio"] = lanPacketStats.gsoErrnoEIO.Load()
	stats["lan_reinject_gso_error_enotsup"] = lanPacketStats.gsoErrnoENOTSUP.Load()
	stats["lan_reinject_gso_error_eagain"] = lanPacketStats.gsoErrnoEAGAIN.Load()
	stats["lan_reinject_gso_error_eacces"] = lanPacketStats.gsoErrnoEACCES.Load()
	stats["lan_reinject_gso_error_enobufs"] = lanPacketStats.gsoErrnoENOBUFS.Load()
	stats["lan_reinject_gso_error_enodev"] = lanPacketStats.gsoErrnoENODEV.Load()
	stats["lan_reinject_gso_error_enxio"] = lanPacketStats.gsoErrnoENXIO.Load()
	stats["lan_reinject_gso_error_efault"] = lanPacketStats.gsoErrnoEFAULT.Load()
	stats["lan_reinject_gso_error_edestaddrreq"] = lanPacketStats.gsoErrnoEDESTADDRREQ.Load()
	stats["lan_reinject_gso_error_other"] = lanPacketStats.gsoErrnoOther.Load()
	stats["lan_reinject_software_segments"] = lanPacketStats.softwareSegments.Load()
	stats["lan_reinject_software_segment_batches"] = lanPacketStats.softwareSegmentBatches.Load()
	stats["lan_reinject_batch_send_attempts"] = lanPacketStats.batchSendAttempts.Load()
	stats["lan_reinject_batch_send_messages"] = lanPacketStats.batchSendMessages.Load()
	stats["lan_reinject_batch_send_errors"] = lanPacketStats.batchSendErrors.Load()
	stats["lan_reinject_single_send_packets"] = lanPacketStats.singleSendPackets.Load()
}

func (manager *Manager) addKernelUDPRXDirectCurrentStatsLocked(stats map[string]uint64, prefix string) {
	if stats == nil {
		return
	}
	stats[prefix+"tc_kernel_udp_rx_secure_direct_attached"] = boolCounter(manager.kernelUDPRXSecureDirectAttached)
	stats[prefix+"tc_kernel_udp_rx_secure_direct_skb_open_kfunc"] = boolCounter(kernelUDPRXSecureDirectSKBOpenKfuncEnabled())
	stats[prefix+"tc_kernel_udp_rx_secure_direct_decap_l2_kfunc"] = boolCounter(kernelUDPRXSecureDirectDecapL2KfuncEnabled())
	stats[prefix+"tc_kernel_udp_rx_secure_direct_recompute_inner_checksums"] = boolCounter(kernelUDPRXSecureDirectRecomputeInnerChecksumEnabled())
	stats[prefix+"tc_kernel_udp_rx_direct_attached"] = boolCounter(manager.kernelUDPRXDirectAttached)
	stats[prefix+"tc_kernel_udp_rx_direct_broadcast"] = boolCounter(manager.kernelUDPRXDirectBroadcast)
	stats[prefix+"tc_kernel_udp_rx_direct_peer_redirect"] = boolCounter(manager.kernelUDPRXDirectRedirectPeer)
	stats[prefix+"tc_kernel_udp_rx_direct_redirect_ingress"] = boolCounter(manager.kernelUDPRXDirectRedirectIngress)
	stats[prefix+"tc_kernel_udp_rx_direct_static_destination_port"] = uint64(manager.kernelUDPRXDirectStaticDestinationPort)
	stats[prefix+"tc_kernel_udp_rx_direct_local_deliver"] = boolCounter(manager.kernelUDPRXDirectLocalDeliver)
	stats[prefix+"tc_kernel_udp_rx_direct_local_deliver_dev"] = boolCounter(manager.kernelUDPRXDirectLocalDeliverDev)
	stats[prefix+"tc_kernel_udp_rx_direct_local_ipv4"] = uint64(manager.kernelUDPRXDirectLocalIPv4)
	stats[prefix+"tc_kernel_udp_rx_direct_local_ipv4_mask"] = uint64(manager.kernelUDPRXDirectLocalIPv4Mask)
	stats[prefix+"tc_kernel_udp_rx_direct_decap_l2_kfunc"] = boolCounter(manager.kernelUDPRXDirectDecapL2Kfunc)
	stats[prefix+"tc_kernel_udp_rx_direct_decap_l2_dev_kfunc"] = boolCounter(manager.kernelUDPRXDirectDecapL2DevKfunc)
	stats[prefix+"tc_kernel_udp_rx_direct_parse_decap_l2_kfunc"] = boolCounter(manager.kernelUDPRXDirectParseDecapL2Kfunc)
	stats[prefix+"tc_kernel_udp_rx_direct_trust_inner_checksum"] = boolCounter(manager.kernelUDPRXDirectTrustInnerChecksum)
}

func (manager *Manager) addKernelUDPTXDirectCurrentStatsLocked(stats map[string]uint64, prefix string) {
	if stats == nil {
		return
	}
	stats[prefix+"kernel_udp_tx_direct_routes"] = manager.kernelUDPTXDirectRoutes
	stats[prefix+"kernel_udp_tx_direct_flows"] = manager.kernelUDPTXDirectFlows
	stats[prefix+"kernel_udp_tx_direct_inline_routes"] = manager.kernelUDPTXDirectInlineRoutes
	stats[prefix+"kernel_udp_tx_direct_inline_flows"] = manager.kernelUDPTXDirectInlineFlows
	stats[prefix+"kernel_udp_tx_direct_secure_configured_flows"] = manager.kernelCryptoTCSealConfiguredFlows
	stats[prefix+"tc_kernel_udp_tx_direct_enabled"] = boolCounter(kernelUDPTXDirectProgramEnabledForSpec(manager.spec))
	stats[prefix+"tc_kernel_udp_tx_direct_experimental_tcp_only"] = boolCounter(kernelUDPTXDirectExperimentalTCPOnlyEnabledForSpec(manager.spec))
	stats[prefix+"tc_kernel_udp_tx_direct_kernel_udp_only"] = boolCounter(kernelUDPTXDirectKernelUDPOnlyEnabledForSpec(manager.spec))
	stats[prefix+"tc_kernel_udp_tx_direct_only_enabled"] = boolCounter(kernelUDPTXDirectOnlyEnabled(manager.spec))
	stats[prefix+"tc_experimental_tcp_tx_plain_skip_sequence"] = boolCounter(experimentalTCPTXPlainSkipSequenceEnabledForSpec(manager.spec))
	stats[prefix+"tc_experimental_tcp_tx_plain_ack_only"] = boolCounter(experimentalTCPTXPlainACKOnlyEnabledForSpec(manager.spec))
	stats[prefix+"tc_experimental_tcp_tx_direct_push_route_outer_tcp_header_kfunc"] = boolCounter(manager.kernelUDPTXDirectPushRouteTCPHeaderKfunc)
	stats[prefix+"tc_experimental_tcp_tx_direct_push_route_outer_tcp_header_kfunc_requested"] = boolCounter(experimentalTCPTXDirectPushRouteTCPHeaderKfuncRequestedForSpec(manager.spec))
	stats[prefix+"tc_experimental_tcp_tx_direct_route_tcp_gso_kfunc"] = boolCounter(manager.kernelUDPTXDirectRouteTCPGSOKfunc)
	stats[prefix+"tc_experimental_tcp_tx_direct_route_tcp_gso_kfunc_requested"] = boolCounter(experimentalTCPTXDirectRouteTCPGSOKfuncRequestedForSpec(manager.spec))
	stats[prefix+"tc_experimental_tcp_tx_direct_route_tcp_gso_async_kfunc"] = boolCounter(manager.kernelUDPTXDirectRouteTCPGSOAsyncKfunc)
	stats[prefix+"tc_experimental_tcp_tx_direct_route_tcp_gso_async_kfunc_requested"] = boolCounter(experimentalTCPTXDirectRouteTCPGSOAsyncKfuncRequestedForSpec(manager.spec))
	stats[prefix+"tc_experimental_tcp_tx_direct_route_tcp_xmit_kfunc"] = boolCounter(manager.kernelUDPTXDirectRouteTCPXmitKfunc)
	stats[prefix+"tc_experimental_tcp_tx_direct_route_tcp_xmit_kfunc_requested"] = boolCounter(experimentalTCPTXDirectRouteTCPXmitKfuncRequestedForSpec(manager.spec))
	stats[prefix+"tc_kernel_udp_tx_secure_direct_attached"] = boolCounter(manager.kernelUDPTXSecureDirectAttached)
	stats[prefix+"tc_kernel_udp_tx_secure_direct_configured_flows"] = manager.kernelCryptoTCSealConfiguredFlows
	txSecureOptions := kernelUDPTXSecureDirectProgramOptionsForSpec(manager.spec)
	stats[prefix+"tc_kernel_udp_tx_secure_direct_trust_inner_checksums"] = boolCounter(kernelUDPTXSecureDirectTrustInnerChecksumsForSpec(manager.spec))
	stats[prefix+"tc_kernel_udp_tx_secure_direct_kfunc_seal_enabled"] = boolCounter(txSecureOptions.KfuncSeal)
	stats[prefix+"tc_kernel_udp_tx_secure_direct_skb_seal_kfunc"] = boolCounter(txSecureOptions.SKBSealKfunc)
	stats[prefix+"tc_kernel_udp_tx_secure_direct_inner_tcp_checksum_kfunc"] = boolCounter(kernelUDPTXSecureDirectInnerTCPChecksumKfuncEnabled())
	stats[prefix+"tc_kernel_udp_tx_secure_direct_outer_tcp_csum_kfunc"] = boolCounter(kernelUDPTXSecureDirectOuterTCPChecksumKfuncEnabled())
}

func (manager *Manager) addKernelUDPTXDirectSyncStatsLocked(stats map[string]uint64, prefix string) {
	syncStats := manager.kernelUDPTXDirectSync
	values := map[string]uint64{
		"kernel_udp_tx_direct_sync_attempts":                  syncStats.Attempts,
		"kernel_udp_tx_direct_sync_skipped_missing_maps":      syncStats.SkippedMissingMaps,
		"kernel_udp_tx_direct_sync_skipped_disabled":          syncStats.SkippedDisabled,
		"kernel_udp_tx_direct_sync_skipped_nat":               syncStats.SkippedNAT,
		"kernel_udp_tx_direct_sync_skipped_no_underlay":       syncStats.SkippedNoUnderlay,
		"kernel_udp_tx_direct_sync_skipped_no_routes":         syncStats.SkippedNoRoutes,
		"kernel_udp_tx_direct_sync_skipped_no_flows":          syncStats.SkippedNoFlows,
		"kernel_udp_tx_direct_sync_underlay_lookup_errors":    syncStats.UnderlayLookupErrors,
		"kernel_udp_tx_direct_sync_bad_underlay_attrs":        syncStats.BadUnderlayAttrs,
		"kernel_udp_tx_direct_sync_route_source_lookups":      syncStats.RouteSourceLookups,
		"kernel_udp_tx_direct_sync_route_source_errors":       syncStats.RouteSourceErrors,
		"kernel_udp_tx_direct_sync_route_gateway_next_hops":   syncStats.RouteGatewayNextHops,
		"kernel_udp_tx_direct_sync_route_ifindex_switches":    syncStats.RouteIfindexSwitches,
		"kernel_udp_tx_direct_sync_route_link_lookup_errors":  syncStats.RouteLinkLookupErrors,
		"kernel_udp_tx_direct_sync_routes_scanned":            syncStats.RoutesScanned,
		"kernel_udp_tx_direct_sync_routes_skipped_kind":       syncStats.RoutesSkippedKind,
		"kernel_udp_tx_direct_sync_routes_skipped_prefix":     syncStats.RoutesSkippedPrefix,
		"kernel_udp_tx_direct_sync_routes_blocked":            syncStats.RoutesBlocked,
		"kernel_udp_tx_direct_sync_routes_without_flows":      syncStats.RoutesWithoutFlows,
		"kernel_udp_tx_direct_sync_route_flows_candidate":     syncStats.RouteFlowsCandidate,
		"kernel_udp_tx_direct_sync_flows_scanned":             syncStats.FlowsScanned,
		"kernel_udp_tx_direct_sync_flows_skipped_zero_id":     syncStats.FlowsSkippedZeroID,
		"kernel_udp_tx_direct_sync_flows_peer_matches":        syncStats.FlowsPeerMatches,
		"kernel_udp_tx_direct_sync_flows_endpoint_matches":    syncStats.FlowsEndpointMatches,
		"kernel_udp_tx_direct_sync_flows_security_allowed":    syncStats.FlowsSecurityAllowed,
		"kernel_udp_tx_direct_sync_flows_security_blocked":    syncStats.FlowsSecurityBlocked,
		"kernel_udp_tx_direct_sync_prepare_packet_errors":     syncStats.PreparePacketErrors,
		"kernel_udp_tx_direct_sync_invalid_packets":           syncStats.InvalidPackets,
		"kernel_udp_tx_direct_sync_neighbor_misses":           syncStats.NeighborMisses,
		"kernel_udp_tx_direct_sync_route_flow_append_rejects": syncStats.RouteFlowAppendReject,
		"kernel_udp_tx_direct_sync_flows_written":             syncStats.FlowsWritten,
		"kernel_udp_tx_direct_sync_routes_written":            syncStats.RoutesWritten,
		"kernel_udp_tx_direct_sync_secure_flows_written":      syncStats.SecureFlowsWritten,
		"kernel_udp_tx_direct_sync_inline_flows_written":      syncStats.InlineFlowsWritten,
	}
	for name, value := range values {
		stats[prefix+name] = value
	}
}

func (manager *Manager) addTransportTelemetryStatsLocked(stats map[string]uint64, telemetry map[uint64]*dataplane.TransportPathTelemetry) {
	for _, item := range telemetry {
		if item == nil {
			continue
		}
		manager.addTransportTelemetryStatsFromItemLocked(stats, *item)
	}
}

func (manager *Manager) addTransportTelemetryStatsFromItemsLocked(stats map[string]uint64, telemetry []dataplane.TransportPathTelemetry) {
	for i := range telemetry {
		manager.addTransportTelemetryStatsFromItemLocked(stats, telemetry[i])
	}
}

func (manager *Manager) addTransportTelemetryStatsFromItemLocked(stats map[string]uint64, item dataplane.TransportPathTelemetry) {
	stats["telemetry_tx_frames"] += item.TXFrames
	stats["telemetry_tx_bytes"] += item.TXBytes
	stats["telemetry_rx_frames"] += item.RXFrames
	stats["telemetry_rx_bytes"] += item.RXBytes
	stats["telemetry_rx_sequence_gaps"] += item.RXSequenceGaps
	stats["telemetry_rx_missing_frames"] += item.RXMissingFrames
	stats["telemetry_rx_duplicate_or_reordered"] += item.RXDuplicateOrReordered
}

func (manager *Manager) experimentalTCPTelemetrySnapshotLocked() []dataplane.TransportPathTelemetry {
	out := make([]dataplane.TransportPathTelemetry, 0, len(manager.expTCPTelemetry))
	for flowID, telemetry := range manager.expTCPTelemetry {
		if telemetry == nil {
			continue
		}
		item := *telemetry
		if flow, ok := manager.expTCPFlows[flowID]; ok {
			fillExperimentalTCPTelemetryIdentity(&item, flow)
		}
		out = append(out, item)
	}
	sortTransportTelemetry(out)
	return out
}

func (manager *Manager) experimentalTCPFlowSnapshotLocked() []dataplane.ExperimentalTCPFlow {
	if len(manager.expTCPFlows) == 0 {
		return nil
	}
	flows := make([]dataplane.ExperimentalTCPFlow, 0, len(manager.expTCPFlows))
	for _, flow := range manager.expTCPFlows {
		flows = append(flows, flow)
	}
	sort.Slice(flows, func(i, j int) bool {
		if flows[i].Peer != flows[j].Peer {
			return flows[i].Peer < flows[j].Peer
		}
		if flows[i].Endpoint != flows[j].Endpoint {
			return flows[i].Endpoint < flows[j].Endpoint
		}
		return flows[i].ID < flows[j].ID
	})
	return flows
}

func (manager *Manager) kernelUDPTelemetrySnapshotLocked() []dataplane.TransportPathTelemetry {
	outByFlow := make(map[uint64]*dataplane.TransportPathTelemetry, len(manager.kernelUDPTelemetry)+len(manager.kernelUDPFlows))
	for flowID, telemetry := range manager.kernelUDPTelemetry {
		if telemetry == nil {
			continue
		}
		item := *telemetry
		if flow, ok := manager.kernelUDPFlows[flowID]; ok {
			fillKernelUDPTelemetryIdentity(&item, flow)
		}
		outByFlow[flowID] = &item
	}
	manager.kernelUDPTelemetrySnapshotKernelCryptoLocked(outByFlow)
	out := make([]dataplane.TransportPathTelemetry, 0, len(outByFlow))
	for _, telemetry := range outByFlow {
		out = append(out, *telemetry)
	}
	sortTransportTelemetry(out)
	return out
}

type kernelCryptoTrafficSnapshot struct {
	TXFrames uint64
	TXBytes  uint64
	RXFrames uint64
	RXBytes  uint64
}

func (manager *Manager) kernelUDPTelemetrySnapshotKernelCryptoLocked(outByFlow map[uint64]*dataplane.TransportPathTelemetry) {
	if manager.kernelCryptoProvider == nil || manager.kernelCryptoProvider.contextSlots == nil || len(manager.kernelUDPFlows) == 0 || len(manager.kernelCryptoCtxSlots) == 0 {
		return
	}
	now := time.Now().UTC()
	for flowID, flow := range manager.kernelUDPFlows {
		traffic, ok := manager.kernelUDPTrafficLocked(flowID)
		if !ok {
			continue
		}
		telemetry := outByFlow[flowID]
		if telemetry == nil {
			item := dataplane.TransportPathTelemetry{Protocol: "kernel_udp", FlowID: flowID}
			fillKernelUDPTelemetryIdentity(&item, flow)
			telemetry = &item
			outByFlow[flowID] = telemetry
		} else if telemetry.Protocol == "" {
			fillKernelUDPTelemetryIdentity(telemetry, flow)
		}
		if traffic.TXFrames > 0 || traffic.TXBytes > 0 {
			if telemetry.FirstSeen.IsZero() {
				telemetry.FirstSeen = now
			}
			telemetry.TXFrames += traffic.TXFrames
			telemetry.TXBytes += traffic.TXBytes
			telemetry.LastSeen = now
		}
		if traffic.RXFrames > 0 || traffic.RXBytes > 0 {
			if telemetry.FirstSeen.IsZero() {
				telemetry.FirstSeen = now
			}
			telemetry.RXFrames += traffic.RXFrames
			telemetry.RXBytes += traffic.RXBytes
			telemetry.LastSeen = now
		}
	}
}

func (manager *Manager) kernelUDPTrafficLocked(flowID uint64) (kernelCryptoTrafficSnapshot, bool) {
	var traffic kernelCryptoTrafficSnapshot
	if flowID == 0 || manager.kernelCryptoProvider == nil || manager.kernelCryptoProvider.contextSlots == nil || len(manager.kernelCryptoCtxSlots) == 0 {
		return traffic, false
	}
	manager.kernelUDPTrafficFromSlotLocked(flowID, kernelCryptoDirectionSend, &traffic.TXFrames, &traffic.TXBytes)
	manager.kernelUDPTrafficFromSlotLocked(flowID, kernelCryptoDirectionRecv, &traffic.RXFrames, &traffic.RXBytes)
	return traffic, traffic.TXFrames > 0 || traffic.TXBytes > 0 || traffic.RXFrames > 0 || traffic.RXBytes > 0
}

func (manager *Manager) kernelUDPTrafficFromSlotLocked(flowID uint64, direction uint8, packets *uint64, bytes *uint64) bool {
	if packets == nil || bytes == nil {
		return false
	}
	slot, ok := manager.kernelCryptoCtxSlots[kernelCryptoFlowKeyFor(kernelCryptoNamespaceKernelUDP, flowID, direction)]
	if !ok {
		return false
	}
	value, err := manager.kernelCryptoProvider.lookupCtxSlot(slot)
	if err != nil {
		return false
	}
	*packets = value.Packets
	*bytes = value.Bytes
	return value.Packets > 0 || value.Bytes > 0
}

func sortTransportTelemetry(items []dataplane.TransportPathTelemetry) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Peer != items[j].Peer {
			return items[i].Peer < items[j].Peer
		}
		if items[i].Endpoint != items[j].Endpoint {
			return items[i].Endpoint < items[j].Endpoint
		}
		return items[i].FlowID < items[j].FlowID
	})
}

func (manager *Manager) experimentalTCPTelemetryLocked(flowID uint64, flow dataplane.ExperimentalTCPFlow) *dataplane.TransportPathTelemetry {
	if manager.expTCPTelemetry == nil {
		manager.expTCPTelemetry = make(map[uint64]*dataplane.TransportPathTelemetry)
	}
	telemetry := manager.expTCPTelemetry[flowID]
	if telemetry == nil {
		telemetry = &dataplane.TransportPathTelemetry{Protocol: "experimental_tcp", FlowID: flowID}
		manager.expTCPTelemetry[flowID] = telemetry
	}
	fillExperimentalTCPTelemetryIdentity(telemetry, flow)
	return telemetry
}

func (manager *Manager) kernelUDPTelemetryLocked(flowID uint64, flow dataplane.KernelUDPFlow) *dataplane.TransportPathTelemetry {
	if manager.kernelUDPTelemetry == nil {
		manager.kernelUDPTelemetry = make(map[uint64]*dataplane.TransportPathTelemetry)
	}
	telemetry := manager.kernelUDPTelemetry[flowID]
	if telemetry == nil {
		telemetry = &dataplane.TransportPathTelemetry{Protocol: "kernel_udp", FlowID: flowID}
		manager.kernelUDPTelemetry[flowID] = telemetry
	}
	fillKernelUDPTelemetryIdentity(telemetry, flow)
	return telemetry
}

func (manager *Manager) updateExperimentalTCPTelemetryIdentityLocked(flowID uint64, flow dataplane.ExperimentalTCPFlow) {
	if telemetry := manager.expTCPTelemetry[flowID]; telemetry != nil {
		fillExperimentalTCPTelemetryIdentity(telemetry, flow)
	}
}

func (manager *Manager) updateKernelUDPTelemetryIdentityLocked(flowID uint64, flow dataplane.KernelUDPFlow) {
	if telemetry := manager.kernelUDPTelemetry[flowID]; telemetry != nil {
		fillKernelUDPTelemetryIdentity(telemetry, flow)
	}
}

func shouldUpdateKernelUDPFlowCryptoPlacement(current dataplane.CryptoPlacement, incoming dataplane.CryptoPlacement) bool {
	if incoming == "" || incoming == dataplane.CryptoPlacementAuto {
		return false
	}
	if current == incoming {
		return false
	}
	if current == dataplane.CryptoPlacementKernel && incoming == dataplane.CryptoPlacementUserspace {
		return false
	}
	return true
}

func fillExperimentalTCPTelemetryIdentity(telemetry *dataplane.TransportPathTelemetry, flow dataplane.ExperimentalTCPFlow) {
	if telemetry == nil {
		return
	}
	telemetry.Protocol = "experimental_tcp"
	telemetry.FlowID = flow.ID
	telemetry.Peer = flow.Peer
	telemetry.Endpoint = flow.Endpoint
	telemetry.LocalAddress = flow.LocalAddress
	telemetry.RemoteAddress = flow.RemoteAddress
	telemetry.SourcePort = flow.SourcePort
	telemetry.DestinationPort = flow.DestinationPort
	telemetry.CryptoPlacement = flow.CryptoPlacement
}

func fillKernelUDPTelemetryIdentity(telemetry *dataplane.TransportPathTelemetry, flow dataplane.KernelUDPFlow) {
	if telemetry == nil {
		return
	}
	telemetry.Protocol = "kernel_udp"
	telemetry.FlowID = flow.ID
	telemetry.Peer = flow.Peer
	telemetry.Endpoint = flow.Endpoint
	telemetry.LocalAddress = flow.LocalAddress
	telemetry.RemoteAddress = flow.RemoteAddress
	telemetry.SourcePort = flow.SourcePort
	telemetry.DestinationPort = flow.DestinationPort
	telemetry.CryptoPlacement = flow.CryptoPlacement
}

func (manager *Manager) observeKernelCryptoDeviceSealBatchLocked(requests []kernelCryptoDeviceSealRequest) {
	if len(requests) == 0 {
		return
	}
	requestCount := uint64(len(requests))
	manager.kernelCryptoDeviceSealBatchCalls++
	manager.kernelCryptoDeviceSealBatchRequests += requestCount
	if requestCount > manager.kernelCryptoDeviceSealBatchMaxRequests {
		manager.kernelCryptoDeviceSealBatchMaxRequests = requestCount
	}
	var bytes uint64
	var maxLen uint64
	for _, request := range requests {
		plainLen := uint64(len(request.Plain))
		bytes += plainLen
		if plainLen > maxLen {
			maxLen = plainLen
		}
	}
	manager.kernelCryptoDeviceSealBatchPlaintextBytes += bytes
	if maxLen > manager.kernelCryptoDeviceSealBatchMaxPlaintextLen {
		manager.kernelCryptoDeviceSealBatchMaxPlaintextLen = maxLen
	}
}

func (manager *Manager) observeKernelCryptoDeviceOpenBatchLocked(requests []kernelCryptoDeviceOpenRequest) {
	if len(requests) == 0 {
		return
	}
	requestCount := uint64(len(requests))
	manager.kernelCryptoDeviceOpenBatchCalls++
	manager.kernelCryptoDeviceOpenBatchRequests += requestCount
	if requestCount > manager.kernelCryptoDeviceOpenBatchMaxRequests {
		manager.kernelCryptoDeviceOpenBatchMaxRequests = requestCount
	}
	var bytes uint64
	var maxLen uint64
	for _, request := range requests {
		ciphertextLen := uint64(len(request.Payload))
		bytes += ciphertextLen
		if ciphertextLen > maxLen {
			maxLen = ciphertextLen
		}
	}
	manager.kernelCryptoDeviceOpenBatchCiphertextBytes += bytes
	if maxLen > manager.kernelCryptoDeviceOpenBatchMaxCiphertextLen {
		manager.kernelCryptoDeviceOpenBatchMaxCiphertextLen = maxLen
	}
}

func (manager *Manager) observeKernelCryptoDeviceOpenResultsLocked(results []kernelCryptoDeviceOpenResult) {
	if len(results) == 0 {
		return
	}
	var bytes uint64
	var maxLen uint64
	for _, result := range results {
		plainLen := uint64(len(result.Plain))
		bytes += plainLen
		if plainLen > maxLen {
			maxLen = plainLen
		}
	}
	manager.kernelCryptoDeviceOpenBatchPlaintextBytes += bytes
	if maxLen > manager.kernelCryptoDeviceOpenBatchMaxPlaintextLen {
		manager.kernelCryptoDeviceOpenBatchMaxPlaintextLen = maxLen
	}
}

func (manager *Manager) kernelCryptoProviderStatsLocked() map[string]uint64 {
	schema := kernelCryptoMapSchema()
	stats := map[string]uint64{
		"kernel_crypto_install_attempts":                     manager.kernelCryptoInstallAttempts,
		"kernel_crypto_specs_validated":                      manager.kernelCryptoSpecsValidated,
		"kernel_crypto_specs_rejected":                       manager.kernelCryptoSpecsRejected,
		"kernel_crypto_spec_validate_errors":                 manager.kernelCryptoSpecValidateErrors,
		"kernel_crypto_provider_unavailable_errors":          manager.kernelCryptoProviderUnavailableErrors,
		"kernel_crypto_entries_encoded":                      manager.kernelCryptoEntriesEncoded,
		"kernel_crypto_flow_rejects":                         manager.kernelCryptoFlowRejects,
		"kernel_crypto_frame_rejects":                        manager.kernelCryptoFrameRejects,
		"kernel_crypto_flow_map_ready":                       boolCounter(manager.kernelCryptoFlowMapReadyLocked()),
		"kernel_crypto_flow_map_create_errors":               manager.kernelCryptoFlowMapCreateErrors,
		"kernel_crypto_flow_map_updates":                     manager.kernelCryptoFlowMapUpdates,
		"kernel_crypto_flow_map_deletes":                     manager.kernelCryptoFlowMapDeletes,
		"kernel_crypto_flow_map_entries":                     manager.kernelCryptoFlowMapEntriesLocked(),
		"kernel_crypto_ctx_provider_loaded":                  boolCounter(manager.kernelCryptoProvider != nil),
		"kernel_crypto_ctx_provider_load_errors":             manager.kernelCryptoProviderLoadErrors,
		"kernel_crypto_aead_gcm_ctx_create_attempts":         manager.kernelCryptoAEADCreateAttempts,
		"kernel_crypto_aead_gcm_ctx_create_successes":        manager.kernelCryptoAEADCreateSuccesses,
		"kernel_crypto_aead_gcm_ctx_create_errors":           manager.kernelCryptoAEADCreateErrors,
		"kernel_crypto_aead_gcm_roundtrip_attempts":          manager.kernelCryptoAEADRoundTripAttempts,
		"kernel_crypto_aead_gcm_roundtrip_successes":         manager.kernelCryptoAEADRoundTripSuccesses,
		"kernel_crypto_aead_gcm_roundtrip_errors":            manager.kernelCryptoAEADRoundTripErrors,
		"kernel_crypto_frame_seal_attempts":                  manager.kernelCryptoFrameSealAttempts,
		"kernel_crypto_frame_seal_successes":                 manager.kernelCryptoFrameSealSuccesses,
		"kernel_crypto_frame_seal_errors":                    manager.kernelCryptoFrameSealErrors,
		"kernel_crypto_frame_open_attempts":                  manager.kernelCryptoFrameOpenAttempts,
		"kernel_crypto_frame_open_successes":                 manager.kernelCryptoFrameOpenSuccesses,
		"kernel_crypto_frame_open_errors":                    manager.kernelCryptoFrameOpenErrors,
		"kernel_crypto_frame_replay_drops":                   manager.kernelCryptoFrameReplayDrops,
		"kernel_crypto_device_flows":                         uint64(len(manager.kernelCryptoDevices)),
		"kernel_crypto_experimental_tcp_device_flows":        uint64(len(manager.expTCPKernelCryptoDevices)),
		"kernel_crypto_device_seal_attempts":                 manager.kernelCryptoDeviceSealAttempts,
		"kernel_crypto_device_seal_successes":                manager.kernelCryptoDeviceSealSuccesses,
		"kernel_crypto_device_seal_errors":                   manager.kernelCryptoDeviceSealErrors,
		"kernel_crypto_device_seal_borrow_attempts":          manager.kernelCryptoDeviceSealBorrowAttempts,
		"kernel_crypto_device_seal_borrow_successes":         manager.kernelCryptoDeviceSealBorrowSuccesses,
		"kernel_crypto_device_seal_borrow_fallbacks":         manager.kernelCryptoDeviceSealBorrowFallbacks,
		"kernel_crypto_device_seal_batch_calls":              manager.kernelCryptoDeviceSealBatchCalls,
		"kernel_crypto_device_seal_batch_requests":           manager.kernelCryptoDeviceSealBatchRequests,
		"kernel_crypto_device_seal_batch_max_requests":       manager.kernelCryptoDeviceSealBatchMaxRequests,
		"kernel_crypto_device_seal_batch_plaintext_bytes":    manager.kernelCryptoDeviceSealBatchPlaintextBytes,
		"kernel_crypto_device_seal_batch_max_plaintext_len":  manager.kernelCryptoDeviceSealBatchMaxPlaintextLen,
		"kernel_crypto_device_open_attempts":                 manager.kernelCryptoDeviceOpenAttempts,
		"kernel_crypto_device_open_successes":                manager.kernelCryptoDeviceOpenSuccesses,
		"kernel_crypto_device_open_errors":                   manager.kernelCryptoDeviceOpenErrors,
		"kernel_crypto_device_open_borrow_attempts":          manager.kernelCryptoDeviceOpenBorrowAttempts,
		"kernel_crypto_device_open_borrow_successes":         manager.kernelCryptoDeviceOpenBorrowSuccesses,
		"kernel_crypto_device_open_borrow_fallbacks":         manager.kernelCryptoDeviceOpenBorrowFallbacks,
		"kernel_crypto_device_open_batch_calls":              manager.kernelCryptoDeviceOpenBatchCalls,
		"kernel_crypto_device_open_batch_requests":           manager.kernelCryptoDeviceOpenBatchRequests,
		"kernel_crypto_device_open_batch_max_requests":       manager.kernelCryptoDeviceOpenBatchMaxRequests,
		"kernel_crypto_device_open_batch_ciphertext_bytes":   manager.kernelCryptoDeviceOpenBatchCiphertextBytes,
		"kernel_crypto_device_open_batch_max_ciphertext_len": manager.kernelCryptoDeviceOpenBatchMaxCiphertextLen,
		"kernel_crypto_device_open_batch_plaintext_bytes":    manager.kernelCryptoDeviceOpenBatchPlaintextBytes,
		"kernel_crypto_device_open_batch_max_plaintext_len":  manager.kernelCryptoDeviceOpenBatchMaxPlaintextLen,
		"kernel_crypto_frame_max_plaintext":                  uint64(kernelCryptoFrameMaxPlain),
		"kernel_crypto_command_size":                         uint64(kernelCryptoCommandSize()),
		"kernel_crypto_map_max_entries":                      uint64(schema.MaxEntries),
		"kernel_crypto_map_key_size":                         uint64(schema.FlowKeySize),
		"kernel_crypto_map_value_size":                       uint64(schema.FlowValueSize),
	}
	addKernelCryptoModuleStats(stats)
	return stats
}

func addKernelCryptoModuleStats(stats map[string]uint64) {
	for _, name := range []string{
		"prefer_software",
		"experimental_vaes",
		"experimental_vaes_kfunc",
		"experimental_aesni_kfunc",
		"kfunc_fastpath_stats",
		"kfunc_fastpath_wipe",
		"kfunc_simd_fastpath",
		"vaes_available",
		"aesni_available",
		"direct_xdp_available",
		"vaes_attempts",
		"vaes_fallbacks",
		"aesni_attempts",
		"aesni_fallbacks",
		"direct_kfunc_seal_calls",
		"direct_kfunc_open_calls",
		"direct_kfunc_vaes_calls",
		"direct_kfunc_aesni_calls",
		"direct_kfunc_errors",
	} {
		if value, ok := readTrustIXAEADModuleParamUint64(name); ok {
			stats["kernel_crypto_module_"+name] = value
		}
	}
	if query, err := kernelmodule.ProbeDatapath(kernelmodule.TrustIXDatapathHelpersDevicePath); err == nil {
		addKernelCryptoDatapathQueryStats(stats, "kernel_crypto_module_datapath", query)
		addKernelCryptoDatapathQueryStats(stats, "kernel_crypto_module_datapath_helpers", query)
	}
	if query, err := kernelmodule.ProbeDatapath(kernelmodule.TrustIXDatapathDevicePath); err == nil {
		addKernelCryptoDatapathQueryStats(stats, "kernel_crypto_module_full_datapath", query)
	}
}

func addKernelCryptoDatapathQueryStats(stats map[string]uint64, prefix string, query kernelmodule.DatapathQuery) {
	stats[prefix+"_abi_version"] = uint64(query.DatapathABIVersion)
	stats[prefix+"_module_abi_version"] = uint64(query.ModuleABIVersion)
	stats[prefix+"_flags"] = uint64(query.Flags)
	stats[prefix+"_max_direct_slots"] = uint64(query.MaxDirectSlots)
	stats[prefix+"_max_batch_ops"] = uint64(query.MaxBatchOps)
	stats[prefix+"_max_input_len"] = uint64(query.MaxInputLen)
	addKernelCryptoModuleFeatureStats(stats, prefix, "features", query.Features)
	addKernelCryptoModuleFeatureStats(stats, prefix, "safe_features", query.SafeFeatures)
	addKernelCryptoModuleFeatureStats(stats, prefix, "unsafe_features", query.UnsafeFeatures)
}

func addKernelCryptoModuleFeatureStats(stats map[string]uint64, prefix string, group string, features []string) {
	for _, feature := range []string{
		kernelmodule.FeatureCryptoAEAD,
		kernelmodule.FeatureDeviceAEAD,
		kernelmodule.FeatureKfuncTC,
		kernelmodule.FeatureKfuncXDP,
		kernelmodule.FeatureDirectAESNI,
		kernelmodule.FeatureDirectVAES,
		kernelmodule.FeatureGSOSKB,
		kernelmodule.FeatureFullDatapath,
		kernelmodule.FeatureRouteTCPKfunc,
		kernelmodule.FeatureRouteTCPXmit,
	} {
		stats[prefix+"_"+group+"_"+feature] = boolCounter(featureListContains(features, feature))
	}
}

func readTrustIXAEADModuleParamUint64(name string) (uint64, bool) {
	payload, err := os.ReadFile(filepath.Join("/sys/module/trustix_crypto/parameters", name))
	if err != nil {
		return 0, false
	}
	value := strings.TrimSpace(string(payload))
	switch strings.ToLower(value) {
	case "y", "yes", "true", "on", "enabled":
		return 1, true
	case "n", "no", "false", "off", "disabled":
		return 0, true
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func boolCounter(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}

func cloneExperimentalTCPFlows(flows map[uint64]dataplane.ExperimentalTCPFlow) map[uint64]dataplane.ExperimentalTCPFlow {
	if len(flows) == 0 {
		return nil
	}
	out := make(map[uint64]dataplane.ExperimentalTCPFlow, len(flows))
	for flowID, flow := range flows {
		out[flowID] = flow
	}
	return out
}

func cloneKernelUDPFlows(flows map[uint64]dataplane.KernelUDPFlow) map[uint64]dataplane.KernelUDPFlow {
	if len(flows) == 0 {
		return nil
	}
	out := make(map[uint64]dataplane.KernelUDPFlow, len(flows))
	for flowID, flow := range flows {
		out[flowID] = flow
	}
	return out
}

func refreshExperimentalTCPFlowLifetime(flow dataplane.ExperimentalTCPFlow, now time.Time) dataplane.ExperimentalTCPFlow {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if flow.CreatedAt.IsZero() {
		flow.CreatedAt = now
	}
	flow.LastSeen = now
	flow.ExpiresAt = now.Add(experimentalTCPFlowTTL)
	return flow
}

func refreshInstalledExperimentalTCPFlowLifetime(flow dataplane.ExperimentalTCPFlow, now time.Time) dataplane.ExperimentalTCPFlow {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if flow.CreatedAt.IsZero() {
		flow.CreatedAt = now
	}
	flow.LastSeen = now
	return flow
}

func refreshExperimentalTCPPreparedFlowLifetime(flow dataplane.ExperimentalTCPFlow, now time.Time) dataplane.ExperimentalTCPFlow {
	if flow.ExpiresAt.IsZero() {
		return refreshInstalledExperimentalTCPFlowLifetime(flow, now)
	}
	return refreshExperimentalTCPFlowLifetime(flow, now)
}

func persistEstablishedExperimentalTCPFlowLifetime(flow dataplane.ExperimentalTCPFlow, now time.Time) dataplane.ExperimentalTCPFlow {
	flow = refreshInstalledExperimentalTCPFlowLifetime(flow, now)
	flow.ExpiresAt = time.Time{}
	return flow
}

func refreshKernelUDPFlowLifetime(flow dataplane.KernelUDPFlow, now time.Time) dataplane.KernelUDPFlow {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if flow.CreatedAt.IsZero() {
		flow.CreatedAt = now
	}
	flow.LastSeen = now
	flow.ExpiresAt = now.Add(experimentalTCPFlowTTL)
	return flow
}

func refreshInstalledKernelUDPFlowLifetime(flow dataplane.KernelUDPFlow, now time.Time) dataplane.KernelUDPFlow {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if flow.CreatedAt.IsZero() {
		flow.CreatedAt = now
	}
	flow.LastSeen = now
	return flow
}

func refreshKernelUDPPreparedFlowLifetime(flow dataplane.KernelUDPFlow, now time.Time) dataplane.KernelUDPFlow {
	if flow.ExpiresAt.IsZero() {
		return refreshInstalledKernelUDPFlowLifetime(flow, now)
	}
	return refreshKernelUDPFlowLifetime(flow, now)
}

func persistEstablishedKernelUDPFlowLifetime(flow dataplane.KernelUDPFlow, now time.Time) dataplane.KernelUDPFlow {
	flow = refreshInstalledKernelUDPFlowLifetime(flow, now)
	flow.ExpiresAt = time.Time{}
	return flow
}

func (manager *Manager) pruneExperimentalTCPFlowsLocked(now time.Time) bool {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var changed bool
	for flowID, flow := range manager.expTCPFlows {
		if !flow.ExpiresAt.IsZero() && !now.Before(flow.ExpiresAt) {
			delete(manager.expTCPFlows, flowID)
			delete(manager.expTCPOuterTXSequences, flowID)
			delete(manager.expTCPOuterTXAcknowledgments, flowID)
			manager.invalidateExperimentalTCPTXTemplateLocked(flowID)
			delete(manager.expTCPTelemetry, flowID)
			manager.deleteExperimentalTCPCryptoFragmentsLocked(flowID)
			manager.deleteKernelCryptoFlowLocked(flowID)
			changed = true
		}
	}
	return changed
}

func (manager *Manager) pruneKernelUDPFlowsLocked(now time.Time) bool {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var changed bool
	for flowID, flow := range manager.kernelUDPFlows {
		if !flow.ExpiresAt.IsZero() && !now.Before(flow.ExpiresAt) {
			delete(manager.kernelUDPFlows, flowID)
			delete(manager.kernelUDPTXDirectSequences, flowID)
			manager.invalidateKernelUDPTXTemplateLocked(flowID)
			delete(manager.kernelUDPTelemetry, flowID)
			manager.deleteKernelUDPCryptoFragmentsLocked(flowID)
			manager.deleteKernelUDPCryptoFlowLocked(flowID)
			manager.deleteKernelCryptoDeviceLocked(kernelCryptoNamespaceKernelUDP, flowID)
			changed = true
		}
	}
	return changed
}

func (manager *Manager) refreshKernelTransportDNSTemplatesLocked(now time.Time) bool {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var changed bool
	for flowID, template := range manager.expTCPTXTemplates {
		if template.kernelTransportTemplateExpired(now) {
			manager.expireExperimentalTCPTXTemplateLocked(flowID, template)
			changed = true
		}
	}
	for flowID, template := range manager.kernelUDPTXTemplates {
		if template.kernelTransportTemplateExpired(now) {
			manager.expireKernelUDPTXTemplateLocked(flowID, template)
			changed = true
		}
	}
	return changed
}

func (manager *Manager) expireExperimentalTCPTXTemplateLocked(flowID uint64, template experimentalTCPTXTemplate) {
	delete(manager.expTCPTXTemplates, flowID)
	if !template.autoLocalAddress {
		return
	}
	flow, ok := manager.expTCPFlows[flowID]
	if !ok || flow.LocalAddress == "" || flow.SourcePort == 0 {
		return
	}
	if flow.LocalAddress == template.flow.LocalAddress && flow.SourcePort == template.flow.SourcePort {
		flow.LocalAddress = ""
		flow.SourcePort = 0
		manager.expTCPFlows[flowID] = flow
		manager.updateExperimentalTCPTelemetryIdentityLocked(flowID, flow)
	}
}

func (manager *Manager) expireKernelUDPTXTemplateLocked(flowID uint64, template kernelUDPTXTemplate) {
	delete(manager.kernelUDPTXTemplates, flowID)
	if !template.autoLocalAddress {
		return
	}
	flow, ok := manager.kernelUDPFlows[flowID]
	if !ok || flow.LocalAddress == "" || flow.SourcePort == 0 {
		return
	}
	if flow.LocalAddress == template.flow.LocalAddress && flow.SourcePort == template.flow.SourcePort {
		flow.LocalAddress = ""
		flow.SourcePort = 0
		manager.kernelUDPFlows[flowID] = flow
		manager.updateKernelUDPTelemetryIdentityLocked(flowID, flow)
	}
}

func (template experimentalTCPTXTemplate) kernelTransportTemplateExpired(now time.Time) bool {
	return !template.expiresAt.IsZero() && !now.Before(template.expiresAt)
}

func (template kernelUDPTXTemplate) kernelTransportTemplateExpired(now time.Time) bool {
	return !template.expiresAt.IsZero() && !now.Before(template.expiresAt)
}

func kernelTransportDNSCacheExpiresAt(resolvedAt time.Time) time.Time {
	if resolvedAt.IsZero() || kernelTransportDNSCacheTTL == 0 {
		return time.Time{}
	}
	return resolvedAt.Add(kernelTransportDNSCacheTTL)
}

func (manager *Manager) syncExperimentalTCPPortsLocked() error {
	desired := manager.desiredExperimentalTCPPortsLocked()
	if manager.expTCPAllowed == nil {
		manager.expTCPAllowed = make(map[uint16]struct{})
	}
	manager.expTCPAllowed = clonePortSet(desired)
	return manager.syncKernelTransportPortsLocked()
}

func (manager *Manager) desiredExperimentalTCPPortsLocked() map[uint16]struct{} {
	desired := make(map[uint16]struct{})
	if manager.snapshot.PacketPolicy.KernelTransportMode == dataplane.KernelTransportModeDisabled {
		return desired
	}
	if manager.experimentalTCPFastPathDisabledLocked() {
		return desired
	}
	localIX := manager.snapshotLocalIXLocked()
	for _, endpoint := range manager.snapshot.Endpoints {
		if endpoint.Transport != "experimental_tcp" || !endpoint.Enabled || !snapshotEndpointIsLocal(localIX, endpoint) {
			continue
		}
		address := strings.TrimSpace(endpoint.Listen)
		if address == "" {
			address = strings.TrimSpace(endpoint.Address)
		}
		if address == "" {
			continue
		}
		port, err := experimentalTCPAddressPort(address)
		if err != nil {
			manager.warnings = append(manager.warnings, "skip experimental_tcp endpoint port sync for "+address+": "+err.Error())
			continue
		}
		desired[port] = struct{}{}
	}
	for _, flow := range manager.expTCPFlows {
		if flow.SourcePort != 0 {
			desired[flow.SourcePort] = struct{}{}
		}
		if flow.DestinationPort != 0 {
			desired[flow.DestinationPort] = struct{}{}
		}
		if strings.TrimSpace(flow.LocalAddress) != "" {
			port, err := experimentalTCPAddressPort(flow.LocalAddress)
			if err == nil {
				desired[port] = struct{}{}
			}
		}
		if strings.TrimSpace(flow.RemoteAddress) != "" {
			port, err := experimentalTCPAddressPort(flow.RemoteAddress)
			if err == nil {
				desired[port] = struct{}{}
			}
		}
	}
	return desired
}

func (manager *Manager) syncKernelUDPPortsLocked() error {
	desired := manager.desiredKernelUDPPortsLocked()
	if manager.kernelUDPAllowed == nil {
		manager.kernelUDPAllowed = make(map[uint16]struct{})
	}
	manager.kernelUDPAllowed = clonePortSet(desired)
	if kernelUDPAFXDPIdleFallbackEnabled() && !kernelUDPAFXDPIdleFallbackUnderlayPacketEnabled() && kernelUDPUDPFallbackEnabled() {
		if err := manager.syncKernelUDPUDPFallbackSocketsLocked(desired); err != nil {
			manager.kernelUDPUDPFallbackBindErrors++
			manager.warnings = append(manager.warnings, "kernel_udp UDP socket idle fallback unavailable: "+err.Error())
		}
	}
	if kernelUDPRawFallbackEnabled() && len(desired) > 0 {
		if err := manager.startKernelUDPRawReceiverLocked(); err != nil {
			return err
		}
	}
	return manager.syncKernelTransportPortsLocked()
}

func (manager *Manager) desiredKernelUDPPortsLocked() map[uint16]struct{} {
	desired := make(map[uint16]struct{})
	if manager.snapshot.PacketPolicy.KernelTransportMode == dataplane.KernelTransportModeDisabled {
		return desired
	}
	localIX := manager.snapshotLocalIXLocked()
	for _, endpoint := range manager.snapshot.Endpoints {
		if endpoint.Transport != "udp" || !endpoint.Enabled || !snapshotEndpointIsLocal(localIX, endpoint) {
			continue
		}
		address := strings.TrimSpace(endpoint.Listen)
		if address == "" {
			address = strings.TrimSpace(endpoint.Address)
		}
		if address == "" {
			continue
		}
		port, err := experimentalTCPAddressPort(address)
		if err != nil {
			manager.warnings = append(manager.warnings, "skip UDP kernel endpoint port sync for "+address+": "+err.Error())
			continue
		}
		desired[port] = struct{}{}
	}
	for _, flow := range manager.kernelUDPFlows {
		if flow.SourcePort != 0 {
			desired[flow.SourcePort] = struct{}{}
		}
		if flow.DestinationPort != 0 {
			desired[flow.DestinationPort] = struct{}{}
		}
		if strings.TrimSpace(flow.LocalAddress) != "" {
			port, err := experimentalTCPAddressPort(flow.LocalAddress)
			if err == nil {
				desired[port] = struct{}{}
			}
		}
		if strings.TrimSpace(flow.RemoteAddress) != "" {
			port, err := experimentalTCPAddressPort(flow.RemoteAddress)
			if err == nil {
				desired[port] = struct{}{}
			}
		}
	}
	return desired
}

func (manager *Manager) snapshotLocalIXLocked() core.IXID {
	remote := make(map[core.IXID]struct{}, len(manager.snapshot.Peers))
	for _, peer := range manager.snapshot.Peers {
		remote[peer.ID] = struct{}{}
	}
	var local core.IXID
	for _, endpoint := range manager.snapshot.Endpoints {
		if endpoint.Peer == "" {
			continue
		}
		if _, ok := remote[endpoint.Peer]; ok {
			continue
		}
		if local == "" {
			local = endpoint.Peer
			continue
		}
		if local != endpoint.Peer {
			return ""
		}
	}
	return local
}

func snapshotEndpointIsLocal(localIX core.IXID, endpoint dataplane.EndpointMetadata) bool {
	if endpoint.Peer == "" {
		return true
	}
	return localIX != "" && endpoint.Peer == localIX
}

func (manager *Manager) syncKernelTransportPortsLocked() error {
	desired := manager.desiredKernelTransportPortsLocked()
	if err := manager.syncKernelTransportPortMapLocked(manager.kernelTransportPortMap, desired, "kernel transport TC RX port BPF map"); err != nil {
		return err
	}
	if err := manager.refreshKernelUDPRXDirectProgramLocked(); err != nil {
		return err
	}
	if manager.expTCPFastPath != nil {
		if manager.kernelTransportAllowed == nil {
			manager.kernelTransportAllowed = make(map[uint16]struct{})
		}
		for port := range manager.kernelTransportAllowed {
			if _, ok := desired[port]; ok {
				continue
			}
			if err := manager.expTCPFastPath.DeleteAllowedDestinationPort(port); err != nil {
				return fmt.Errorf("delete kernel transport XDP port %d: %w", port, err)
			}
			delete(manager.kernelTransportAllowed, port)
		}
		for port := range desired {
			if _, ok := manager.kernelTransportAllowed[port]; ok {
				continue
			}
			if err := manager.expTCPFastPath.AllowDestinationPort(port); err != nil {
				return fmt.Errorf("allow kernel transport XDP port %d: %w", port, err)
			}
			manager.kernelTransportAllowed[port] = struct{}{}
		}
	}
	if manager.kernelUDPXDPRXDirectObject != nil {
		if err := manager.syncKernelTransportPortMapLocked(manager.kernelUDPXDPRXDirectObject.portMap, desired, "kernel transport standalone XDP port BPF map"); err != nil {
			return err
		}
	}
	return nil
}

func (manager *Manager) desiredKernelTransportPortsLocked() map[uint16]struct{} {
	desired := make(map[uint16]struct{}, len(manager.expTCPAllowed)+len(manager.kernelUDPAllowed))
	for port := range manager.expTCPAllowed {
		desired[port] = struct{}{}
	}
	for port := range manager.kernelUDPAllowed {
		desired[port] = struct{}{}
	}
	return desired
}

func (manager *Manager) refreshKernelUDPRXDirectProgramLocked() error {
	if !manager.kernelUDPRXDirectAttached || manager.spec.LANIface == "" || manager.spec.UnderlayIface == "" {
		return nil
	}
	lanLink, err := netlink.LinkByName(manager.spec.LANIface)
	if err != nil {
		return fmt.Errorf("inspect LAN iface %q for kernel_udp RX direct refresh: %w", manager.spec.LANIface, err)
	}
	underlayLink, err := netlink.LinkByName(manager.spec.UnderlayIface)
	if err != nil {
		return fmt.Errorf("inspect underlay iface %q for kernel_udp RX direct refresh: %w", manager.spec.UnderlayIface, err)
	}
	options := manager.kernelUDPRXDirectProgramOptionsForLink(lanLink)
	if options.RedirectPeer == manager.kernelUDPRXDirectRedirectPeer &&
		options.Broadcast == manager.kernelUDPRXDirectBroadcast &&
		options.RedirectIngress == manager.kernelUDPRXDirectRedirectIngress &&
		options.StaticDestinationPort == manager.kernelUDPRXDirectStaticDestinationPort &&
		options.LocalDeliver == manager.kernelUDPRXDirectLocalDeliver &&
		options.LocalDeliverDev == manager.kernelUDPRXDirectLocalDeliverDev &&
		options.LocalIPv4 == manager.kernelUDPRXDirectLocalIPv4 &&
		options.LocalIPv4Mask == manager.kernelUDPRXDirectLocalIPv4Mask &&
		options.DecapL2Kfunc == manager.kernelUDPRXDirectDecapL2Kfunc &&
		options.DecapL2DevKfunc == manager.kernelUDPRXDirectDecapL2DevKfunc &&
		options.ParseDecapL2Kfunc == manager.kernelUDPRXDirectParseDecapL2Kfunc &&
		options.TrustInnerChecksum == manager.kernelUDPRXDirectTrustInnerChecksum {
		return nil
	}
	if err := manager.detachKernelUDPRXDirectLocked(underlayLink); err != nil {
		return err
	}
	return manager.ensureKernelUDPRXDirectLocked()
}

func (manager *Manager) ensureKernelTransportPortMapLocked() error {
	if manager.kernelTransportPortMap != nil {
		return nil
	}
	portMap, err := cebpf.NewMap(&cebpf.MapSpec{
		Name:       "ix_ktrans_port",
		Type:       cebpf.Hash,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: 4096,
	})
	if err != nil {
		return fmt.Errorf("create kernel transport TC RX port BPF map: %w", err)
	}
	manager.kernelTransportPortMap = portMap
	desired := make(map[uint16]struct{}, len(manager.expTCPAllowed)+len(manager.kernelUDPAllowed))
	for port := range manager.expTCPAllowed {
		desired[port] = struct{}{}
	}
	for port := range manager.kernelUDPAllowed {
		desired[port] = struct{}{}
	}
	if err := manager.syncKernelTransportPortMapLocked(portMap, desired, "kernel transport TC RX port BPF map"); err != nil {
		_ = portMap.Close()
		manager.kernelTransportPortMap = nil
		return err
	}
	return nil
}

func (manager *Manager) syncKernelTransportPortMapLocked(portMap *cebpf.Map, desired map[uint16]struct{}, label string) error {
	if portMap == nil {
		return nil
	}
	if err := clearBPFMap[uint32, uint8](portMap, label); err != nil {
		return err
	}
	value := uint8(1)
	for port := range desired {
		if err := portMap.Update(experimentalTCPPortMapKey(port), value, cebpf.UpdateAny); err != nil {
			return fmt.Errorf("allow kernel transport TC RX port %d: %w", port, err)
		}
	}
	return nil
}

func clonePortSet(ports map[uint16]struct{}) map[uint16]struct{} {
	if len(ports) == 0 {
		return nil
	}
	out := make(map[uint16]struct{}, len(ports))
	for port := range ports {
		out[port] = struct{}{}
	}
	return out
}

func experimentalTCPRawFallbackEnabled() bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv("TRUSTIX_EXPERIMENTAL_TCP_RAW_FALLBACK")))
	return value == "1" || value == "true" || value == "yes"
}

func kernelUDPRawFallbackEnabled() bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv("TRUSTIX_KERNEL_UDP_RAW_FALLBACK")))
	if value == "" {
		value = strings.TrimSpace(strings.ToLower(os.Getenv("TRUSTIX_KERNEL_UDP_RAW_UDP_FALLBACK")))
	}
	return value == "1" || value == "true" || value == "yes"
}

func (manager *Manager) attachTCPrograms(link netlink.Link, spec dataplane.AttachSpec) error {
	if manager.ingressProg != nil || manager.egressProg != nil {
		return manager.attachTCFiltersToLink(link, spec)
	}
	statsMap, err := cebpf.NewMap(&cebpf.MapSpec{
		Name:       "ix_stats_map",
		Type:       cebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: tcStatsMapMaxEntries,
	})
	if err != nil {
		return fmt.Errorf("create stats BPF map: %w", err)
	}
	routeMap, err := cebpf.NewMap(&cebpf.MapSpec{
		Name:       "ix_route_lpm",
		Type:       cebpf.LPMTrie,
		KeySize:    8,
		ValueSize:  16,
		MaxEntries: 4096,
		Flags:      unix.BPF_F_NO_PREALLOC,
	})
	if err != nil {
		_ = statsMap.Close()
		return fmt.Errorf("create route LPM BPF map: %w", err)
	}
	packetPolicyMap, err := cebpf.NewMap(&cebpf.MapSpec{
		Name:       "ix_packet_policy",
		Type:       cebpf.Array,
		KeySize:    4,
		ValueSize:  12,
		MaxEntries: 1,
	})
	if err != nil {
		_ = routeMap.Close()
		_ = statsMap.Close()
		return fmt.Errorf("create packet policy BPF map: %w", err)
	}
	natConfigMap, err := cebpf.NewMap(&cebpf.MapSpec{
		Name:       "ix_nat_config",
		Type:       cebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
	})
	if err != nil {
		_ = packetPolicyMap.Close()
		_ = routeMap.Close()
		_ = statsMap.Close()
		return fmt.Errorf("create NAT config BPF map: %w", err)
	}
	natSourceMap, err := cebpf.NewMap(&cebpf.MapSpec{
		Name:       "ix_nat_sources",
		Type:       cebpf.LPMTrie,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: 256,
		Flags:      unix.BPF_F_NO_PREALLOC,
	})
	if err != nil {
		_ = natConfigMap.Close()
		_ = packetPolicyMap.Close()
		_ = routeMap.Close()
		_ = statsMap.Close()
		return fmt.Errorf("create NAT source LPM BPF map: %w", err)
	}
	natRouteMap, err := cebpf.NewMap(&cebpf.MapSpec{
		Name:       "ix_nat_routes",
		Type:       cebpf.LPMTrie,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: 4096,
		Flags:      unix.BPF_F_NO_PREALLOC,
	})
	if err != nil {
		_ = natSourceMap.Close()
		_ = natConfigMap.Close()
		_ = packetPolicyMap.Close()
		_ = routeMap.Close()
		_ = statsMap.Close()
		return fmt.Errorf("create NAT route LPM BPF map: %w", err)
	}
	natExcludeMap, err := cebpf.NewMap(&cebpf.MapSpec{
		Name:       "ix_nat_exclude",
		Type:       cebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 256,
	})
	if err != nil {
		_ = natRouteMap.Close()
		_ = natSourceMap.Close()
		_ = natConfigMap.Close()
		_ = packetPolicyMap.Close()
		_ = routeMap.Close()
		_ = statsMap.Close()
		return fmt.Errorf("create NAT exclude BPF map: %w", err)
	}
	natBindingMap, err := cebpf.NewMap(&cebpf.MapSpec{
		Name:       "ix_nat_bindings",
		Type:       cebpf.Hash,
		KeySize:    20,
		ValueSize:  16,
		MaxEntries: natDefaultMaxBindings,
	})
	if err != nil {
		_ = natExcludeMap.Close()
		_ = natRouteMap.Close()
		_ = natSourceMap.Close()
		_ = natConfigMap.Close()
		_ = packetPolicyMap.Close()
		_ = routeMap.Close()
		_ = statsMap.Close()
		return fmt.Errorf("create NAT binding BPF map: %w", err)
	}
	captureMap, captureOutputMode, err := newCaptureEventBPFMap()
	if err != nil {
		_ = natBindingMap.Close()
		_ = natExcludeMap.Close()
		_ = natRouteMap.Close()
		_ = natSourceMap.Close()
		_ = natConfigMap.Close()
		_ = packetPolicyMap.Close()
		_ = routeMap.Close()
		_ = statsMap.Close()
		return err
	}
	captureScratchMap, err := newCaptureScratchBPFMap()
	if err != nil {
		_ = captureMap.Close()
		_ = natBindingMap.Close()
		_ = natExcludeMap.Close()
		_ = natRouteMap.Close()
		_ = natSourceMap.Close()
		_ = natConfigMap.Close()
		_ = packetPolicyMap.Close()
		_ = routeMap.Close()
		_ = statsMap.Close()
		return fmt.Errorf("create capture scratch BPF map: %w", err)
	}
	captureReader, captureRingReader, err := newCaptureReader(captureMap)
	if err != nil {
		_ = captureScratchMap.Close()
		_ = captureMap.Close()
		_ = natBindingMap.Close()
		_ = natExcludeMap.Close()
		_ = natRouteMap.Close()
		_ = natSourceMap.Close()
		_ = natConfigMap.Close()
		_ = packetPolicyMap.Close()
		_ = routeMap.Close()
		_ = statsMap.Close()
		return err
	}
	captureReadersOwned := true
	defer func() {
		if captureReadersOwned {
			closeCaptureReaders(captureReader, captureRingReader)
		}
	}()

	underlayLink, _ := netlink.LinkByName(spec.UnderlayIface)
	kernelUDPTXRouteMap, err := cebpf.NewMap(&cebpf.MapSpec{
		Name:       "ix_kudp_tx_route",
		Type:       cebpf.LPMTrie,
		KeySize:    8,
		ValueSize:  kernelUDPTXRouteValueSize,
		MaxEntries: 4096,
		Flags:      unix.BPF_F_NO_PREALLOC,
	})
	if err != nil {
		closeCaptureReaders(captureReader, captureRingReader)
		_ = captureMap.Close()
		_ = natBindingMap.Close()
		_ = natExcludeMap.Close()
		_ = natRouteMap.Close()
		_ = natSourceMap.Close()
		_ = natConfigMap.Close()
		_ = packetPolicyMap.Close()
		_ = routeMap.Close()
		_ = statsMap.Close()
		return fmt.Errorf("create kernel_udp TC TX route map: %w", err)
	}
	kernelUDPTXRouteCacheMap, err := cebpf.NewMap(&cebpf.MapSpec{
		Name:       "ix_kudp_tx_route_cache",
		Type:       cebpf.Array,
		KeySize:    4,
		ValueSize:  kernelUDPTXRouteCacheValueSize,
		MaxEntries: 1,
	})
	if err != nil {
		_ = kernelUDPTXRouteMap.Close()
		closeCaptureReaders(captureReader, captureRingReader)
		_ = captureMap.Close()
		_ = natBindingMap.Close()
		_ = natExcludeMap.Close()
		_ = natRouteMap.Close()
		_ = natSourceMap.Close()
		_ = natConfigMap.Close()
		_ = packetPolicyMap.Close()
		_ = routeMap.Close()
		_ = statsMap.Close()
		return fmt.Errorf("create kernel_udp TC TX route cache map: %w", err)
	}
	kernelUDPTXFlowMap, err := cebpf.NewMap(&cebpf.MapSpec{
		Name:       "ix_kudp_tx_flow",
		Type:       cebpf.Hash,
		KeySize:    8,
		ValueSize:  kernelUDPTXFlowValueSize,
		MaxEntries: 4096,
	})
	if err != nil {
		_ = kernelUDPTXRouteCacheMap.Close()
		_ = kernelUDPTXRouteMap.Close()
		closeCaptureReaders(captureReader, captureRingReader)
		_ = captureMap.Close()
		_ = natBindingMap.Close()
		_ = natExcludeMap.Close()
		_ = natRouteMap.Close()
		_ = natSourceMap.Close()
		_ = natConfigMap.Close()
		_ = packetPolicyMap.Close()
		_ = routeMap.Close()
		_ = statsMap.Close()
		return fmt.Errorf("create kernel_udp TC TX flow map: %w", err)
	}

	txDirectOptions := kernelUDPTXDirectProgramOptions{
		Enabled:                          kernelUDPTXDirectProgramEnabledForSpec(spec),
		ExperimentalTCPOnly:              kernelUDPTXDirectExperimentalTCPOnlyEnabledForSpec(spec),
		KernelUDPOnly:                    kernelUDPTXDirectKernelUDPOnlyEnabledForSpec(spec),
		DirectOnly:                       kernelUDPTXDirectOnlyEnabled(spec),
		SkipPlainSequence:                kernelUDPTXDirectSkipPlainSequenceEnabled(),
		ExperimentalTCPSkipPlainSequence: experimentalTCPTXPlainSkipSequenceEnabledForSpec(spec),
		ExperimentalTCPACKOnly:           experimentalTCPTXPlainACKOnlyEnabledForSpec(spec),
		RedirectPeer:                     kernelUDPTXDirectRedirectPeerEnabledForLink(underlayLink, kernelUDPTXDirectKernelUDPOnlyEnabledForSpec(spec), kernelUDPTXDirectOnlyEnabled(spec)),
	}
	if kernelUDPTXDirectSKBClearTXOffloadEnabled() {
		txDirectOptions.SKBClearTXOffload = true
		txDirectOptions.SKBClearKfuncCall, err = loadSKBClearTXOffloadKfuncCall()
		if err != nil {
			_ = kernelUDPTXFlowMap.Close()
			_ = kernelUDPTXRouteCacheMap.Close()
			_ = kernelUDPTXRouteMap.Close()
			closeCaptureReaders(captureReader, captureRingReader)
			_ = captureMap.Close()
			_ = natBindingMap.Close()
			_ = natExcludeMap.Close()
			_ = natRouteMap.Close()
			_ = natSourceMap.Close()
			_ = natConfigMap.Close()
			_ = packetPolicyMap.Close()
			_ = routeMap.Close()
			_ = statsMap.Close()
			return fmt.Errorf("load skb TX offload-clear kfunc metadata: %w", err)
		}
	}
	if kernelUDPTXDirectInnerTCPChecksumKfuncRequestedForOptions(txDirectOptions) {
		txDirectOptions.InnerTCPKfunc = true
		txDirectOptions.InnerTCPKfuncAuto = !kernelUDPTXDirectInnerTCPChecksumKfuncRequired()
		txDirectOptions.InnerTCPKfuncCall, err = loadSKBFixInnerTCPCsumKfuncCall()
		if err != nil {
			txDirectOptions.InnerTCPKfunc = false
			txDirectOptions.InnerTCPKfuncAuto = false
			if kernelUDPTXDirectInnerTCPChecksumKfuncRequired() {
				_ = kernelUDPTXFlowMap.Close()
				_ = kernelUDPTXRouteCacheMap.Close()
				_ = kernelUDPTXRouteMap.Close()
				closeCaptureReaders(captureReader, captureRingReader)
				_ = captureMap.Close()
				_ = natBindingMap.Close()
				_ = natExcludeMap.Close()
				_ = natRouteMap.Close()
				_ = natSourceMap.Close()
				_ = natConfigMap.Close()
				_ = packetPolicyMap.Close()
				_ = routeMap.Close()
				_ = statsMap.Close()
				return fmt.Errorf("load skb inner TCP checksum kfunc metadata: %w", err)
			}
			manager.warnings = append(manager.warnings, "kernel_udp TC TX direct inner TCP checksum kfunc disabled: "+err.Error())
		}
	}
	if experimentalTCPTXDirectEnabledForSpec(spec) && kernelUDPTXDirectInnerTCPChecksumKfuncEnabled() && !txDirectOptions.InnerTCPKfuncCall.IsKfuncCall() {
		txDirectOptions.InnerTCPKfunc = true
		txDirectOptions.InnerTCPKfuncAuto = !kernelUDPTXDirectInnerTCPChecksumKfuncRequired()
		txDirectOptions.InnerTCPKfuncCall, err = loadSKBFixInnerTCPCsumKfuncCall()
		if err != nil {
			txDirectOptions.InnerTCPKfunc = false
			txDirectOptions.InnerTCPKfuncAuto = false
			if kernelUDPTXDirectInnerTCPChecksumKfuncRequired() {
				_ = kernelUDPTXFlowMap.Close()
				_ = kernelUDPTXRouteCacheMap.Close()
				_ = kernelUDPTXRouteMap.Close()
				closeCaptureReaders(captureReader, captureRingReader)
				_ = captureMap.Close()
				_ = natBindingMap.Close()
				_ = natExcludeMap.Close()
				_ = natRouteMap.Close()
				_ = natSourceMap.Close()
				_ = natConfigMap.Close()
				_ = packetPolicyMap.Close()
				_ = routeMap.Close()
				_ = statsMap.Close()
				return fmt.Errorf("load experimental_tcp inner TCP checksum kfunc metadata: %w", err)
			}
			manager.warnings = append(manager.warnings, "experimental_tcp TC TX direct inner TCP checksum kfunc disabled: "+err.Error())
		}
	}
	if kernelUDPTXDirectStoreHeaderKfuncEnabled() {
		txDirectOptions.StoreHeaderKfunc = true
		txDirectOptions.StoreHeaderKfuncCall, err = loadSKBKernelUDPTXStoreL2L3L4KfuncCall()
		if err != nil {
			_ = kernelUDPTXFlowMap.Close()
			_ = kernelUDPTXRouteCacheMap.Close()
			_ = kernelUDPTXRouteMap.Close()
			closeCaptureReaders(captureReader, captureRingReader)
			_ = captureMap.Close()
			_ = natBindingMap.Close()
			_ = natExcludeMap.Close()
			_ = natRouteMap.Close()
			_ = natSourceMap.Close()
			_ = natConfigMap.Close()
			_ = packetPolicyMap.Close()
			_ = routeMap.Close()
			_ = statsMap.Close()
			return fmt.Errorf("load skb kernel_udp TX header-store kfunc metadata: %w", err)
		}
	}
	if kernelUDPTXDirectBuildUDPHeaderKfuncEnabled() {
		txDirectOptions.BuildUDPHeaderKfunc = true
		txDirectOptions.BuildUDPHeaderKfuncCall, err = loadSKBKernelUDPTXBuildUDPHeaderKfuncCall()
		if err != nil {
			_ = kernelUDPTXFlowMap.Close()
			_ = kernelUDPTXRouteCacheMap.Close()
			_ = kernelUDPTXRouteMap.Close()
			closeCaptureReaders(captureReader, captureRingReader)
			_ = captureMap.Close()
			_ = natBindingMap.Close()
			_ = natExcludeMap.Close()
			_ = natRouteMap.Close()
			_ = natSourceMap.Close()
			_ = natConfigMap.Close()
			_ = packetPolicyMap.Close()
			_ = routeMap.Close()
			_ = statsMap.Close()
			return fmt.Errorf("load skb kernel_udp TX UDP header-build kfunc metadata: %w", err)
		}
	}
	if kernelUDPTXDirectFinalizeUDPHeaderKfuncEnabled() {
		txDirectOptions.FinalizeUDPHeaderKfunc = true
		txDirectOptions.FinalizeUDPKfuncCall, err = loadSKBKernelUDPTXFinalizeUDPHeaderKfuncCall()
		if err != nil {
			_ = kernelUDPTXFlowMap.Close()
			_ = kernelUDPTXRouteCacheMap.Close()
			_ = kernelUDPTXRouteMap.Close()
			closeCaptureReaders(captureReader, captureRingReader)
			_ = captureMap.Close()
			_ = natBindingMap.Close()
			_ = natExcludeMap.Close()
			_ = natRouteMap.Close()
			_ = natSourceMap.Close()
			_ = natConfigMap.Close()
			_ = packetPolicyMap.Close()
			_ = routeMap.Close()
			_ = statsMap.Close()
			return fmt.Errorf("load skb kernel_udp TX UDP header-finalize kfunc metadata: %w", err)
		}
	}
	if kernelUDPTXDirectPushUDPHeaderKfuncEnabled() {
		txDirectOptions.PushUDPHeaderKfunc = true
		txDirectOptions.PushUDPHeaderKfuncCall, err = loadSKBKernelUDPTXPushUDPHeaderKfuncCall()
		if err != nil {
			_ = kernelUDPTXFlowMap.Close()
			_ = kernelUDPTXRouteCacheMap.Close()
			_ = kernelUDPTXRouteMap.Close()
			closeCaptureReaders(captureReader, captureRingReader)
			_ = captureMap.Close()
			_ = natBindingMap.Close()
			_ = natExcludeMap.Close()
			_ = natRouteMap.Close()
			_ = natSourceMap.Close()
			_ = natConfigMap.Close()
			_ = packetPolicyMap.Close()
			_ = routeMap.Close()
			_ = statsMap.Close()
			return fmt.Errorf("load skb kernel_udp TX UDP header-push kfunc metadata: %w", err)
		}
	}
	if experimentalTCPTXDirectEnabledForSpec(spec) && experimentalTCPTXDirectOuterTCPChecksumKfuncRequested() && !experimentalTCPSkipOuterTCPChecksum() {
		txDirectOptions.OuterTCPCsumKfunc = true
		txDirectOptions.OuterTCPCsumKfuncCall, err = loadSKBTIXTFixOuterTCPCsumKfuncCall()
		if err != nil {
			txDirectOptions.OuterTCPCsumKfunc = false
			if experimentalTCPTXDirectOuterTCPChecksumKfuncRequired() {
				_ = kernelUDPTXFlowMap.Close()
				_ = kernelUDPTXRouteCacheMap.Close()
				_ = kernelUDPTXRouteMap.Close()
				closeCaptureReaders(captureReader, captureRingReader)
				_ = captureMap.Close()
				_ = natBindingMap.Close()
				_ = natExcludeMap.Close()
				_ = natRouteMap.Close()
				_ = natSourceMap.Close()
				_ = natConfigMap.Close()
				_ = packetPolicyMap.Close()
				_ = routeMap.Close()
				_ = statsMap.Close()
				return fmt.Errorf("load experimental_tcp outer TCP checksum kfunc metadata: %w", err)
			}
			manager.warnings = append(manager.warnings, "experimental_tcp TC TX direct outer TCP checksum kfunc disabled: "+err.Error())
		}
	}
	if experimentalTCPTXDirectEnabledForSpec(spec) && experimentalTCPTXDirectOuterTCPHeaderKfuncRequested() && !experimentalTCPSkipOuterTCPChecksum() {
		txDirectOptions.OuterTCPKfunc = true
		txDirectOptions.OuterTCPKfuncCall, err = loadSKBTIXTTXFinalizeTCPHeaderKfuncCall()
		if err != nil {
			txDirectOptions.OuterTCPKfunc = false
			if experimentalTCPTXDirectOuterTCPHeaderKfuncRequired() {
				_ = kernelUDPTXFlowMap.Close()
				_ = kernelUDPTXRouteCacheMap.Close()
				_ = kernelUDPTXRouteMap.Close()
				closeCaptureReaders(captureReader, captureRingReader)
				_ = captureMap.Close()
				_ = natBindingMap.Close()
				_ = natExcludeMap.Close()
				_ = natRouteMap.Close()
				_ = natSourceMap.Close()
				_ = natConfigMap.Close()
				_ = packetPolicyMap.Close()
				_ = routeMap.Close()
				_ = statsMap.Close()
				return fmt.Errorf("load experimental_tcp outer TCP header kfunc metadata: %w", err)
			}
			manager.warnings = append(manager.warnings, "experimental_tcp TC TX direct outer TCP header kfunc disabled: "+err.Error())
		}
	}
	if experimentalTCPTXDirectEnabledForSpec(spec) && experimentalTCPTXDirectTCPPartialCSUMKfuncRequested() && !experimentalTCPSkipOuterTCPChecksum() {
		txDirectOptions.TCPPartialCSUMKfunc = true
		txDirectOptions.TCPPartialCSUMKfuncCall, err = loadSKBTIXTTXSetTCPPartialCSUMKfuncCall()
		if err != nil {
			txDirectOptions.TCPPartialCSUMKfunc = false
			if experimentalTCPTXDirectTCPPartialCSUMKfuncRequired() {
				_ = kernelUDPTXFlowMap.Close()
				_ = kernelUDPTXRouteCacheMap.Close()
				_ = kernelUDPTXRouteMap.Close()
				closeCaptureReaders(captureReader, captureRingReader)
				_ = captureMap.Close()
				_ = natBindingMap.Close()
				_ = natExcludeMap.Close()
				_ = natRouteMap.Close()
				_ = natSourceMap.Close()
				_ = natConfigMap.Close()
				_ = packetPolicyMap.Close()
				_ = routeMap.Close()
				_ = statsMap.Close()
				return fmt.Errorf("load experimental_tcp TCP partial checksum kfunc metadata: %w", err)
			}
			manager.warnings = append(manager.warnings, "experimental_tcp TC TX direct TCP partial checksum kfunc disabled: "+err.Error())
		}
	}
	if experimentalTCPTXDirectEnabledForSpec(spec) && experimentalTCPTXDirectPushTCPHeaderKfuncRequested() && !experimentalTCPSkipOuterTCPChecksum() {
		txDirectOptions.PushTCPHeaderKfunc = true
		txDirectOptions.PushTCPHeaderKfuncCall, err = loadSKBTIXTTXPushTCPHeaderKfuncCall()
		if err != nil {
			txDirectOptions.PushTCPHeaderKfunc = false
			if experimentalTCPTXDirectPushTCPHeaderKfuncRequired() {
				_ = kernelUDPTXFlowMap.Close()
				_ = kernelUDPTXRouteCacheMap.Close()
				_ = kernelUDPTXRouteMap.Close()
				closeCaptureReaders(captureReader, captureRingReader)
				_ = captureMap.Close()
				_ = natBindingMap.Close()
				_ = natExcludeMap.Close()
				_ = natRouteMap.Close()
				_ = natSourceMap.Close()
				_ = natConfigMap.Close()
				_ = packetPolicyMap.Close()
				_ = routeMap.Close()
				_ = statsMap.Close()
				return fmt.Errorf("load experimental_tcp TCP header-push kfunc metadata: %w", err)
			}
			manager.warnings = append(manager.warnings, "experimental_tcp TC TX direct TCP header-push kfunc disabled: "+err.Error())
		}
	}
	if experimentalTCPTXDirectEnabledForSpec(spec) && experimentalTCPTXDirectPushFlowTCPHeaderKfuncRequested() && !experimentalTCPSkipOuterTCPChecksum() {
		txDirectOptions.PushFlowTCPHeaderKfunc = true
		txDirectOptions.PushFlowTCPHeaderKfuncCall, err = loadSKBTIXTTXPushFlowTCPHeaderKfuncCall()
		if err != nil {
			txDirectOptions.PushFlowTCPHeaderKfunc = false
			if experimentalTCPTXDirectPushFlowTCPHeaderKfuncRequired() {
				_ = kernelUDPTXFlowMap.Close()
				_ = kernelUDPTXRouteCacheMap.Close()
				_ = kernelUDPTXRouteMap.Close()
				closeCaptureReaders(captureReader, captureRingReader)
				_ = captureMap.Close()
				_ = natBindingMap.Close()
				_ = natExcludeMap.Close()
				_ = natRouteMap.Close()
				_ = natSourceMap.Close()
				_ = natConfigMap.Close()
				_ = packetPolicyMap.Close()
				_ = routeMap.Close()
				_ = statsMap.Close()
				return fmt.Errorf("load experimental_tcp flow TCP header-push kfunc metadata: %w", err)
			}
			manager.warnings = append(manager.warnings, "experimental_tcp TC TX direct flow TCP header-push kfunc disabled: "+err.Error())
		}
	}
	if experimentalTCPTXDirectEnabledForSpec(spec) && experimentalTCPTXDirectFinalizeFlowTCPHeaderKfuncRequested() && !experimentalTCPSkipOuterTCPChecksum() {
		txDirectOptions.FinalizeFlowTCPHeaderKfunc = true
		txDirectOptions.FinalizeFlowTCPHeaderKfuncCall, err = loadSKBTIXTTXFinalizeFlowTCPHeaderKfuncCall()
		if err != nil {
			txDirectOptions.FinalizeFlowTCPHeaderKfunc = false
			if experimentalTCPTXDirectFinalizeFlowTCPHeaderKfuncRequired() {
				_ = kernelUDPTXFlowMap.Close()
				_ = kernelUDPTXRouteCacheMap.Close()
				_ = kernelUDPTXRouteMap.Close()
				closeCaptureReaders(captureReader, captureRingReader)
				_ = captureMap.Close()
				_ = natBindingMap.Close()
				_ = natExcludeMap.Close()
				_ = natRouteMap.Close()
				_ = natSourceMap.Close()
				_ = natConfigMap.Close()
				_ = packetPolicyMap.Close()
				_ = routeMap.Close()
				_ = statsMap.Close()
				return fmt.Errorf("load experimental_tcp flow TCP header-finalize kfunc metadata: %w", err)
			}
			manager.warnings = append(manager.warnings, "experimental_tcp TC TX direct flow TCP header-finalize kfunc disabled: "+err.Error())
		}
	}
	if experimentalTCPTXDirectEnabledForSpec(spec) && experimentalTCPTXDirectPushRouteTCPHeaderKfuncRequestedForSpec(spec) && !experimentalTCPSkipOuterTCPChecksum() {
		txDirectOptions.PushRouteTCPHeaderKfunc = true
		txDirectOptions.PushRouteTCPHeaderKfuncCall, err = loadSKBTIXTTXPushRouteTCPHeaderKfuncCall()
		if err != nil {
			txDirectOptions.PushRouteTCPHeaderKfunc = false
			if experimentalTCPTXDirectPushRouteTCPHeaderKfuncRequired() {
				_ = kernelUDPTXFlowMap.Close()
				_ = kernelUDPTXRouteCacheMap.Close()
				_ = kernelUDPTXRouteMap.Close()
				closeCaptureReaders(captureReader, captureRingReader)
				_ = captureMap.Close()
				_ = natBindingMap.Close()
				_ = natExcludeMap.Close()
				_ = natRouteMap.Close()
				_ = natSourceMap.Close()
				_ = natConfigMap.Close()
				_ = packetPolicyMap.Close()
				_ = routeMap.Close()
				_ = statsMap.Close()
				return fmt.Errorf("load experimental_tcp route TCP header-push kfunc metadata: %w", err)
			}
			manager.warnings = append(manager.warnings, "experimental_tcp TC TX direct route TCP header-push kfunc disabled: "+err.Error())
		}
	}
	if experimentalTCPTXDirectEnabledForSpec(spec) && experimentalTCPTXDirectRouteTCPGSOKfuncRequestedForSpec(spec) && !experimentalTCPSkipOuterTCPChecksum() {
		txDirectOptions.RouteTCPGSOKfunc = true
		txDirectOptions.RouteTCPGSOKfuncCall, err = loadSKBTIXTTXSegmentRouteTCPGSOKfuncCall()
		if err != nil {
			txDirectOptions.RouteTCPGSOKfunc = false
			if experimentalTCPTXDirectRouteTCPGSOKfuncRequired() {
				_ = kernelUDPTXFlowMap.Close()
				_ = kernelUDPTXRouteCacheMap.Close()
				_ = kernelUDPTXRouteMap.Close()
				closeCaptureReaders(captureReader, captureRingReader)
				_ = captureMap.Close()
				_ = natBindingMap.Close()
				_ = natExcludeMap.Close()
				_ = natRouteMap.Close()
				_ = natSourceMap.Close()
				_ = natConfigMap.Close()
				_ = packetPolicyMap.Close()
				_ = routeMap.Close()
				_ = statsMap.Close()
				return fmt.Errorf("load experimental_tcp route TCP GSO kfunc metadata: %w", err)
			}
			manager.warnings = append(manager.warnings, "experimental_tcp TC TX direct route TCP GSO kfunc disabled: "+err.Error())
		}
	}
	if txDirectOptions.RouteTCPGSOKfunc {
		txDirectOptions.RouteTCPGSOAsyncKfunc = experimentalTCPTXDirectRouteTCPGSOAsyncKfuncRequestedForSpec(spec)
	}
	if txDirectOptions.RouteTCPGSOKfunc && experimentalTCPTXDirectRouteTCPXmitKfuncRequestedForSpec(spec) && !experimentalTCPSkipOuterTCPChecksum() {
		txDirectOptions.RouteTCPXmitKfunc = true
		txDirectOptions.RouteTCPXmitKfuncCall, err = loadSKBTIXTTXRouteTCPXmitKfuncCall()
		if err != nil {
			txDirectOptions.RouteTCPXmitKfunc = false
			if experimentalTCPTXDirectRouteTCPXmitKfuncRequired() {
				_ = kernelUDPTXFlowMap.Close()
				_ = kernelUDPTXRouteCacheMap.Close()
				_ = kernelUDPTXRouteMap.Close()
				closeCaptureReaders(captureReader, captureRingReader)
				_ = captureMap.Close()
				_ = natBindingMap.Close()
				_ = natExcludeMap.Close()
				_ = natRouteMap.Close()
				_ = natSourceMap.Close()
				_ = natConfigMap.Close()
				_ = packetPolicyMap.Close()
				_ = routeMap.Close()
				_ = statsMap.Close()
				return fmt.Errorf("load experimental_tcp route TCP xmit kfunc metadata: %w", err)
			}
			manager.warnings = append(manager.warnings, "experimental_tcp TC TX direct route TCP xmit kfunc disabled: "+err.Error())
		}
	}
	if kernelUDPTXDirectRouteCacheEnabled(txDirectOptions) {
		txDirectOptions.RouteCacheMap = kernelUDPTXRouteCacheMap
	}
	ingressProg, egressProg, txDirectOptions, kfuncFallbackWarning, err := loadTCFastPathProgramsWithExperimentalTCPRouteKfuncFallback(
		statsMap,
		packetPolicyMap,
		routeMap,
		kernelUDPTXRouteMap,
		kernelUDPTXFlowMap,
		natConfigMap,
		natSourceMap,
		natRouteMap,
		natExcludeMap,
		natBindingMap,
		captureMap,
		captureScratchMap,
		txDirectOptions,
	)
	if err != nil {
		_ = kernelUDPTXFlowMap.Close()
		_ = kernelUDPTXRouteCacheMap.Close()
		_ = kernelUDPTXRouteMap.Close()
		closeCaptureReaders(captureReader, captureRingReader)
		_ = captureScratchMap.Close()
		_ = captureMap.Close()
		_ = natBindingMap.Close()
		_ = natExcludeMap.Close()
		_ = natRouteMap.Close()
		_ = natSourceMap.Close()
		_ = natConfigMap.Close()
		_ = packetPolicyMap.Close()
		_ = routeMap.Close()
		_ = statsMap.Close()
		return err
	}
	if kfuncFallbackWarning != "" {
		manager.warnings = append(manager.warnings, kfuncFallbackWarning)
	}
	var kernelUDPTXSecureDirect *kernelUDPTXSecureDirectObject
	if kernelUDPTXSecureDirectRequestedForSpec(spec) && !manager.kernelCryptoTCDirectReadyLocked() {
		manager.warnings = append(manager.warnings, "kernel_udp secure TC TX direct unavailable: "+manager.kernelCryptoTCDirectUnavailableReasonLocked())
	}
	if kernelUDPTXSecureDirectRequestedForSpec(spec) && manager.kernelCryptoTCDirectReadyLocked() {
		kernelUDPTXSecureDirect, err = loadKernelUDPTXSecureDirectObject(manager.kernelCryptoProvider, statsMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, kernelUDPTXSecureDirectProgramOptionsForSpec(spec))
		if err != nil {
			_ = kernelUDPTXFlowMap.Close()
			_ = kernelUDPTXRouteCacheMap.Close()
			_ = kernelUDPTXRouteMap.Close()
			closeCaptureReaders(captureReader, captureRingReader)
			_ = captureMap.Close()
			_ = natBindingMap.Close()
			_ = natExcludeMap.Close()
			_ = natRouteMap.Close()
			_ = natSourceMap.Close()
			_ = natConfigMap.Close()
			_ = packetPolicyMap.Close()
			_ = routeMap.Close()
			_ = statsMap.Close()
			_ = ingressProg.Close()
			return fmt.Errorf("load kernel_udp secure TC TX direct BPF object: %w", err)
		}
	}
	ingressFilter := bpfFilter(link, netlink.HANDLE_MIN_INGRESS, netlink.MakeHandle(0, 1), "trustix_ingress", ingressProg.FD())
	egressFilter := bpfFilter(link, netlink.HANDLE_MIN_EGRESS, netlink.MakeHandle(0, 2), "trustix_egress", egressProg.FD())
	var kernelUDPTXSecureDirectFilter *netlink.BpfFilter
	var kernelUDPTXSecureDirectEgressFilter *netlink.BpfFilter
	if kernelUDPTXSecureDirect != nil && kernelUDPTXSecureDirect.program != nil {
		if kernelUDPTXSecureDirectIngressEnabled() {
			kernelUDPTXSecureDirectFilter = bpfFilterWithPriority(link, netlink.HANDLE_MIN_INGRESS, netlink.MakeHandle(0, 4), "trustix_kudp_txk", kernelUDPTXSecureDirect.program.FD(), 1)
			ingressFilter.Priority = 2
		}
		if kernelUDPTXSecureDirectEgressEnabled() {
			kernelUDPTXSecureDirectEgressFilter = bpfFilterWithPriority(link, netlink.HANDLE_MIN_EGRESS, netlink.MakeHandle(0, 4), "trustix_kudp_txke", kernelUDPTXSecureDirect.program.FD(), 1)
			egressFilter.Priority = 2
		}
	}
	if kernelUDPTXSecureDirectFilter != nil {
		if err := netlink.FilterReplace(kernelUDPTXSecureDirectFilter); err != nil {
			_ = kernelUDPTXSecureDirect.Close()
			_ = kernelUDPTXFlowMap.Close()
			_ = kernelUDPTXRouteCacheMap.Close()
			_ = kernelUDPTXRouteMap.Close()
			closeCaptureReaders(captureReader, captureRingReader)
			_ = captureMap.Close()
			_ = natBindingMap.Close()
			_ = natExcludeMap.Close()
			_ = natRouteMap.Close()
			_ = natSourceMap.Close()
			_ = natConfigMap.Close()
			_ = packetPolicyMap.Close()
			_ = routeMap.Close()
			_ = statsMap.Close()
			_ = ingressProg.Close()
			_ = egressProg.Close()
			return fmt.Errorf("attach kernel_udp secure TC TX direct BPF filter on %q: %w", link.Attrs().Name, err)
		}
	}
	if kernelUDPTXSecureDirectEgressFilter != nil {
		if err := netlink.FilterReplace(kernelUDPTXSecureDirectEgressFilter); err != nil {
			if kernelUDPTXSecureDirectFilter != nil {
				_ = netlink.FilterDel(kernelUDPTXSecureDirectFilter)
			}
			_ = kernelUDPTXSecureDirect.Close()
			_ = kernelUDPTXFlowMap.Close()
			_ = kernelUDPTXRouteCacheMap.Close()
			_ = kernelUDPTXRouteMap.Close()
			closeCaptureReaders(captureReader, captureRingReader)
			_ = captureMap.Close()
			_ = natBindingMap.Close()
			_ = natExcludeMap.Close()
			_ = natRouteMap.Close()
			_ = natSourceMap.Close()
			_ = natConfigMap.Close()
			_ = packetPolicyMap.Close()
			_ = routeMap.Close()
			_ = statsMap.Close()
			_ = ingressProg.Close()
			_ = egressProg.Close()
			return fmt.Errorf("attach kernel_udp secure TC TX direct egress BPF filter on %q: %w", link.Attrs().Name, err)
		}
	}
	if err := netlink.FilterReplace(ingressFilter); err != nil {
		if kernelUDPTXSecureDirectEgressFilter != nil {
			_ = netlink.FilterDel(kernelUDPTXSecureDirectEgressFilter)
		}
		if kernelUDPTXSecureDirectFilter != nil {
			_ = netlink.FilterDel(kernelUDPTXSecureDirectFilter)
		}
		if kernelUDPTXSecureDirect != nil {
			_ = kernelUDPTXSecureDirect.Close()
		}
		_ = kernelUDPTXFlowMap.Close()
		_ = kernelUDPTXRouteCacheMap.Close()
		_ = kernelUDPTXRouteMap.Close()
		closeCaptureReaders(captureReader, captureRingReader)
		_ = captureMap.Close()
		_ = natBindingMap.Close()
		_ = natExcludeMap.Close()
		_ = natRouteMap.Close()
		_ = natSourceMap.Close()
		_ = natConfigMap.Close()
		_ = packetPolicyMap.Close()
		_ = routeMap.Close()
		_ = statsMap.Close()
		_ = ingressProg.Close()
		_ = egressProg.Close()
		return fmt.Errorf("attach ingress BPF filter on %q: %w", link.Attrs().Name, err)
	}
	if err := netlink.FilterReplace(egressFilter); err != nil {
		_ = netlink.FilterDel(ingressFilter)
		if kernelUDPTXSecureDirectEgressFilter != nil {
			_ = netlink.FilterDel(kernelUDPTXSecureDirectEgressFilter)
		}
		if kernelUDPTXSecureDirectFilter != nil {
			_ = netlink.FilterDel(kernelUDPTXSecureDirectFilter)
		}
		if kernelUDPTXSecureDirect != nil {
			_ = kernelUDPTXSecureDirect.Close()
		}
		_ = kernelUDPTXFlowMap.Close()
		_ = kernelUDPTXRouteCacheMap.Close()
		_ = kernelUDPTXRouteMap.Close()
		closeCaptureReaders(captureReader, captureRingReader)
		_ = captureMap.Close()
		_ = natBindingMap.Close()
		_ = natExcludeMap.Close()
		_ = natRouteMap.Close()
		_ = natSourceMap.Close()
		_ = natConfigMap.Close()
		_ = packetPolicyMap.Close()
		_ = routeMap.Close()
		_ = statsMap.Close()
		_ = ingressProg.Close()
		_ = egressProg.Close()
		return fmt.Errorf("attach egress BPF filter on %q: %w", link.Attrs().Name, err)
	}

	manager.statsMap = statsMap
	manager.packetPolicyMap = packetPolicyMap
	manager.routeMap = routeMap
	manager.kernelUDPTXRouteMap = kernelUDPTXRouteMap
	manager.kernelUDPTXRouteCacheMap = kernelUDPTXRouteCacheMap
	manager.kernelUDPTXFlowMap = kernelUDPTXFlowMap
	manager.kernelUDPTXSecureDirect = kernelUDPTXSecureDirect
	manager.kernelUDPTXDirectInnerTCPChecksumKfunc = txDirectOptions.InnerTCPKfunc
	manager.kernelUDPTXDirectOuterTCPChecksumKfunc = txDirectOptions.OuterTCPCsumKfunc
	manager.kernelUDPTXDirectOuterTCPHeaderKfunc = txDirectOptions.OuterTCPKfunc
	manager.kernelUDPTXDirectTCPPartialCSUMKfunc = txDirectOptions.TCPPartialCSUMKfunc
	manager.kernelUDPTXDirectPushTCPHeaderKfunc = txDirectOptions.PushTCPHeaderKfunc
	manager.kernelUDPTXDirectPushFlowTCPHeaderKfunc = txDirectOptions.PushFlowTCPHeaderKfunc
	manager.kernelUDPTXDirectFinalizeFlowTCPHeaderKfunc = txDirectOptions.FinalizeFlowTCPHeaderKfunc
	manager.kernelUDPTXDirectPushRouteTCPHeaderKfunc = txDirectOptions.PushRouteTCPHeaderKfunc
	manager.kernelUDPTXDirectRouteTCPGSOKfunc = txDirectOptions.RouteTCPGSOKfunc
	manager.kernelUDPTXDirectRouteTCPGSOAsyncKfunc = txDirectOptions.RouteTCPGSOAsyncKfunc
	manager.kernelUDPTXDirectRouteTCPXmitKfunc = txDirectOptions.RouteTCPXmitKfunc
	manager.kernelUDPTXDirectExperimentalTCPSafeGSO = experimentalTCPTXDirectSafeActiveGSOEnabledForOptions(txDirectOptions)
	manager.natConfigMap = natConfigMap
	manager.natSourceMap = natSourceMap
	manager.natRouteMap = natRouteMap
	manager.natExcludeMap = natExcludeMap
	manager.natBindingMap = natBindingMap
	manager.captureMap = captureMap
	manager.captureScratchMap = captureScratchMap
	manager.captureReader = captureReader
	manager.captureRingReader = captureRingReader
	manager.ingressProg = ingressProg
	manager.egressProg = egressProg
	manager.ingressFilter = ingressFilter
	manager.egressFilter = egressFilter
	manager.kernelUDPTXSecureDirectFilter = kernelUDPTXSecureDirectFilter
	manager.kernelUDPTXSecureDirectEgressFilter = kernelUDPTXSecureDirectEgressFilter
	if manager.lanTCFilters == nil {
		manager.lanTCFilters = make(map[string]lanTCFilterState)
	}
	manager.lanTCFilters[link.Attrs().Name] = lanTCFilterState{
		ingress:                       ingressFilter,
		egress:                        egressFilter,
		kernelUDPTXSecureDirect:       kernelUDPTXSecureDirectFilter,
		kernelUDPTXSecureDirectEgress: kernelUDPTXSecureDirectEgressFilter,
	}
	manager.kernelUDPTXSecureDirectAttached = kernelUDPTXSecureDirectFilter != nil || kernelUDPTXSecureDirectEgressFilter != nil
	captureReadersOwned = false
	if err := manager.syncKernelUDPTXDirectLocked(); err != nil {
		_ = manager.detachTCPrograms(link)
		return err
	}
	if captureOutputMode == captureOutputModePerf {
		go manager.readCaptureEvents(captureReader)
	} else {
		go manager.readCaptureRingEvents(captureRingReader)
	}
	return nil
}

func (manager *Manager) attachKernelUDPRXDirectLocked(lanLink netlink.Link, underlayLink netlink.Link) error {
	if kernelUDPRXDirectDisabledForSpec(manager.spec) || lanLink == nil || underlayLink == nil || manager.statsMap == nil ||
		manager.kernelTransportPortMap == nil || kernelDatapathRXWorkerOwnsStackRXForSpec(manager.spec) {
		return nil
	}
	if manager.underlayIngressProg != nil || manager.underlayIngressFilter != nil {
		return nil
	}
	if err := replaceClsact(underlayLink); err != nil {
		return fmt.Errorf("prepare clsact qdisc on underlay %q: %w", underlayLink.Attrs().Name, err)
	}
	manager.underlayQdiscPrepared = true
	var neighMap *cebpf.Map
	var devMap *cebpf.Map
	var configMap *cebpf.Map
	var err error
	if manager.expTCPFastPath != nil && manager.expTCPFastPath.xdpObject != nil && manager.expTCPFastPath.xdpObject.rxNeighMap != nil &&
		manager.expTCPFastPath.xdpObject.rxDevMap != nil && manager.expTCPFastPath.xdpObject.rxConfigMap != nil {
		neighMap, err = manager.expTCPFastPath.xdpObject.rxNeighMap.Clone()
		if err != nil {
			manager.warnings = append(manager.warnings, "kernel_udp XDP RX direct disabled: clone XDP neighbor map: "+err.Error())
		} else if devMap, err = manager.expTCPFastPath.xdpObject.rxDevMap.Clone(); err != nil {
			manager.warnings = append(manager.warnings, "kernel_udp XDP RX direct disabled: clone XDP devmap: "+err.Error())
			_ = neighMap.Close()
			neighMap = nil
		} else if configMap, err = manager.expTCPFastPath.xdpObject.rxConfigMap.Clone(); err != nil {
			manager.warnings = append(manager.warnings, "kernel_udp XDP RX direct disabled: clone XDP config map: "+err.Error())
			_ = devMap.Close()
			_ = neighMap.Close()
			devMap = nil
			neighMap = nil
		}
	}
	if !kernelUDPXDPRXDirectEnabled() {
		if configMap != nil {
			_ = configMap.Close()
			configMap = nil
		}
		if devMap != nil {
			_ = devMap.Close()
			devMap = nil
		}
		manager.warnings = append(manager.warnings, "kernel_udp XDP RX direct disabled: devmap redirect to LAN is experimental; set TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT=1 to opt in")
	}
	if kernelUDPXDPRXDirectEnabled() && devMap == nil {
		devMap, err = cebpf.NewMap(&cebpf.MapSpec{
			Name:       "ix_kudp_rx_tc_devmap",
			Type:       cebpf.DevMap,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 1,
		})
		if err != nil {
			if configMap != nil {
				_ = configMap.Close()
			}
			if neighMap != nil {
				_ = neighMap.Close()
			}
			return fmt.Errorf("create kernel_udp XDP RX direct devmap: %w", err)
		}
	}
	if kernelUDPXDPRXDirectEnabled() && configMap == nil {
		configMap, err = cebpf.NewMap(&cebpf.MapSpec{
			Name:       "ix_kudp_rx_tc_config",
			Type:       cebpf.Array,
			KeySize:    4,
			ValueSize:  20,
			MaxEntries: 1,
		})
		if err != nil {
			if devMap != nil {
				_ = devMap.Close()
			}
			if neighMap != nil {
				_ = neighMap.Close()
			}
			return fmt.Errorf("create kernel_udp XDP RX direct config map: %w", err)
		}
	}
	if neighMap == nil {
		neighMap, err = cebpf.NewMap(&cebpf.MapSpec{
			Name:       "ix_kudp_rx_tc_neigh",
			Type:       cebpf.Hash,
			KeySize:    4,
			ValueSize:  20,
			MaxEntries: 4096,
		})
		if err != nil {
			return fmt.Errorf("create kernel_udp TC RX direct neighbor map: %w", err)
		}
	}
	sourceMAC := lanLink.Attrs().HardwareAddr
	if len(sourceMAC) != 6 {
		if configMap != nil {
			_ = configMap.Close()
		}
		if devMap != nil {
			_ = devMap.Close()
		}
		_ = neighMap.Close()
		return fmt.Errorf("kernel_udp RX direct requires LAN hardware address on %q", lanLink.Attrs().Name)
	}
	options, program, err := manager.loadKernelUDPRXDirectProgramForLink("trustix_kudp_rx", neighMap, lanLink, sourceMAC)
	if err != nil {
		if configMap != nil {
			_ = configMap.Close()
		}
		if devMap != nil {
			_ = devMap.Close()
		}
		_ = neighMap.Close()
		return fmt.Errorf("load kernel_udp underlay RX direct BPF program: %w", err)
	}
	filter := bpfFilterWithPriority(underlayLink, netlink.HANDLE_MIN_INGRESS, netlink.MakeHandle(0, 3), "trustix_kudp_rx", program.FD(), 2)
	if err := netlink.FilterReplace(filter); err != nil {
		_ = program.Close()
		if configMap != nil {
			_ = configMap.Close()
		}
		if devMap != nil {
			_ = devMap.Close()
		}
		_ = neighMap.Close()
		return fmt.Errorf("attach kernel_udp underlay RX direct BPF filter on %q: %w", underlayLink.Attrs().Name, err)
	}
	manager.underlayIngressProg = program
	manager.underlayIngressFilter = filter
	manager.kernelUDPRXNeighMap = neighMap
	manager.kernelUDPRXDevMap = devMap
	manager.kernelUDPRXConfigMap = configMap
	manager.kernelUDPRXDirectRedirectPeer = options.RedirectPeer
	manager.kernelUDPRXDirectBroadcast = options.Broadcast
	manager.kernelUDPRXDirectRedirectIngress = options.RedirectIngress
	manager.kernelUDPRXDirectStaticDestinationPort = options.StaticDestinationPort
	manager.kernelUDPRXDirectLocalDeliver = options.LocalDeliver
	manager.kernelUDPRXDirectLocalDeliverDev = options.LocalDeliverDev
	manager.kernelUDPRXDirectLocalIPv4 = options.LocalIPv4
	manager.kernelUDPRXDirectLocalIPv4Mask = options.LocalIPv4Mask
	manager.kernelUDPRXDirectDecapL2Kfunc = options.DecapL2Kfunc
	manager.kernelUDPRXDirectDecapL2DevKfunc = options.DecapL2DevKfunc
	manager.kernelUDPRXDirectParseDecapL2Kfunc = options.ParseDecapL2Kfunc
	manager.kernelUDPRXDirectTrustInnerChecksum = options.TrustInnerChecksum
	manager.configureKernelUDPRXDirectNeighborMap(lanLink)
	manager.kernelUDPRXDirectAttached = true
	if err := manager.attachKernelUDPRXSecureDirectLocked(underlayLink, neighMap, lanLink, sourceMAC, options); err != nil {
		manager.warnings = append(manager.warnings, "kernel_udp secure TC RX direct disabled: "+err.Error())
	}
	if err := manager.syncKernelUDPRXDirectConfigLocked(); err != nil {
		manager.warnings = append(manager.warnings, "kernel_udp XDP TC RX direct config sync failed: "+err.Error())
	}
	if err := manager.attachKernelUDPRXXDPDirectLocked(lanLink, underlayLink); err != nil {
		manager.warnings = append(manager.warnings, "kernel_udp XDP RX direct disabled: "+err.Error())
	}
	return nil
}

func (manager *Manager) attachKernelUDPRXSecureDirectLocked(underlayLink netlink.Link, neighMap *cebpf.Map, lanLink netlink.Link, sourceMAC net.HardwareAddr, options kernelUDPRXDirectProgramOptions) error {
	if !manager.kernelUDPRXSecureDirectRequestedLocked() {
		return nil
	}
	if !manager.kernelCryptoTCDirectReadyLocked() {
		return nil
	}
	if manager.kernelCryptoProvider == nil || manager.statsMap == nil || manager.kernelTransportPortMap == nil ||
		underlayLink == nil || neighMap == nil {
		return nil
	}
	if manager.kernelUDPRXSecureDirect != nil || manager.kernelUDPRXSecureDirectFilter != nil {
		return nil
	}
	if len(sourceMAC) != 6 || lanLink == nil || lanLink.Attrs() == nil || lanLink.Attrs().Index <= 0 {
		return fmt.Errorf("secure TC RX direct requires LAN ifindex and source MAC")
	}
	var source [6]byte
	copy(source[:], sourceMAC)
	localIPv4 := firstIPv4AddressKeyForLink(lanLink)
	object, err := loadKernelUDPRXSecureDirectObject(manager.kernelCryptoProvider, manager.statsMap, manager.kernelTransportPortMap, neighMap, lanLink.Attrs().Index, localIPv4, source, options)
	if err != nil {
		return err
	}
	filter := bpfFilterWithPriority(underlayLink, netlink.HANDLE_MIN_INGRESS, netlink.MakeHandle(0, 5), "trustix_kudp_rxk", object.program.FD(), 1)
	if err := netlink.FilterReplace(filter); err != nil {
		_ = object.Close()
		return fmt.Errorf("attach kernel_udp secure underlay RX direct BPF filter on %q: %w", underlayLink.Attrs().Name, err)
	}
	manager.kernelUDPRXSecureDirect = object
	manager.kernelUDPRXSecureDirectFilter = filter
	manager.kernelUDPRXSecureDirectAttached = true
	return nil
}

func (manager *Manager) ensureKernelUDPRXSecureDirectLocked() error {
	if !manager.kernelUDPRXSecureDirectRequestedLocked() || manager.kernelUDPRXSecureDirectAttached ||
		manager.kernelUDPRXSecureDirect != nil || manager.kernelUDPRXSecureDirectFilter != nil {
		return nil
	}
	if !manager.kernelCryptoTCDirectReadyLocked() {
		return nil
	}
	if manager.kernelCryptoProvider == nil || manager.statsMap == nil || manager.kernelTransportPortMap == nil ||
		manager.kernelUDPRXNeighMap == nil ||
		manager.kernelCryptoProvider.flowIndexMap == nil ||
		manager.kernelCryptoProvider.contextSlots == nil ||
		manager.kernelCryptoProvider.directSlotMap == nil {
		return nil
	}
	if manager.spec.LANIface == "" || manager.spec.UnderlayIface == "" {
		return nil
	}
	lanLink, err := netlink.LinkByName(manager.spec.LANIface)
	if err != nil {
		return fmt.Errorf("inspect LAN iface %q: %w", manager.spec.LANIface, err)
	}
	underlayLink, err := netlink.LinkByName(manager.spec.UnderlayIface)
	if err != nil {
		return fmt.Errorf("inspect underlay iface %q: %w", manager.spec.UnderlayIface, err)
	}
	manager.kernelUDPRXNeighMu.RLock()
	sourceMAC := manager.kernelUDPRXDirectSourceMAC
	destinationMAC := manager.kernelUDPRXDirectDestinationMAC
	manager.kernelUDPRXNeighMu.RUnlock()
	if sourceMAC == ([6]byte{}) {
		if hw := lanLink.Attrs().HardwareAddr; len(hw) == 6 {
			copy(sourceMAC[:], hw)
		}
	}
	if sourceMAC == ([6]byte{}) {
		return fmt.Errorf("secure TC RX direct requires LAN source MAC")
	}
	options := kernelUDPRXDirectProgramOptions{
		RedirectPeer:         manager.kernelUDPRXDirectRedirectPeer,
		Broadcast:            manager.kernelUDPRXDirectBroadcast,
		RedirectIngress:      manager.kernelUDPRXDirectRedirectIngress,
		BroadcastDestination: destinationMAC,
		DirectOnly:           kernelUDPTXDirectOnlyEnabled(manager.spec),
	}
	return manager.attachKernelUDPRXSecureDirectLocked(underlayLink, manager.kernelUDPRXNeighMap, lanLink, net.HardwareAddr(sourceMAC[:]), options)
}

func (manager *Manager) loadKernelUDPRXDirectProgramForLink(name string, neighMap *cebpf.Map, lanLink netlink.Link, sourceMAC net.HardwareAddr) (kernelUDPRXDirectProgramOptions, *cebpf.Program, error) {
	if lanLink == nil || lanLink.Attrs() == nil {
		return kernelUDPRXDirectProgramOptions{}, nil, fmt.Errorf("kernel_udp RX direct requires LAN link")
	}
	options := manager.kernelUDPRXDirectProgramOptionsForLink(lanLink)
	ifindex := lanLink.Attrs().Index
	if peerMAC, warning := vethPeerHardwareAddr(lanLink); len(peerMAC) == 6 {
		copy(options.BroadcastDestination[:], peerMAC)
	} else if options.Broadcast && options.RedirectIngress && len(sourceMAC) == 6 {
		copy(options.BroadcastDestination[:], sourceMAC)
	} else if warning != "" {
		manager.warnings = append(manager.warnings, warning)
	}
	if options.RedirectPeer || options.Broadcast {
		loadedOptions, program, err := manager.loadKernelUDPRXDirectProgramWithOptionalKfuncFallback(name, neighMap, ifindex, sourceMAC, options)
		if err == nil {
			return loadedOptions, program, nil
		}
		if options.RedirectPeer {
			manager.warnings = append(manager.warnings, "kernel_udp TC RX veth peer redirect disabled: "+err.Error())
			fallback := options
			fallback.RedirectPeer = false
			loadedFallback, program, fallbackErr := manager.loadKernelUDPRXDirectProgramWithOptionalKfuncFallback(name, neighMap, ifindex, sourceMAC, fallback)
			if fallbackErr == nil {
				return loadedFallback, program, nil
			}
			manager.warnings = append(manager.warnings, "kernel_udp TC RX broadcast direct disabled: "+fallbackErr.Error())
		} else {
			manager.warnings = append(manager.warnings, "kernel_udp TC RX broadcast direct disabled: "+err.Error())
		}
	}
	loadedOptions, program, err := manager.loadKernelUDPRXDirectProgramWithOptionalKfuncFallback(name, neighMap, ifindex, sourceMAC, options)
	if err != nil {
		return kernelUDPRXDirectProgramOptions{}, nil, err
	}
	return loadedOptions, program, nil
}

func (manager *Manager) kernelUDPRXDirectProgramOptionsForLink(lanLink netlink.Link) kernelUDPRXDirectProgramOptions {
	options := kernelUDPRXDirectOptionsForLinkWithSpec(lanLink, manager.spec)
	ifindex := 0
	if lanLink != nil && lanLink.Attrs() != nil {
		ifindex = lanLink.Attrs().Index
	}
	options.DirectOnly = kernelUDPTXDirectOnlyEnabled(manager.spec)
	if options.DestinationPortOnly {
		options.StaticDestinationPort = manager.kernelUDPRXDirectStaticDestinationPortLocked(options)
	}
	options.TrustInnerChecksum = manager.spec.KernelUDPSecureDirectTrustInnerChecksums || kernelUDPRXDirectTrustInnerChecksumEnabledForOptions(options)
	if kernelUDPRXDirectLocalDeliverEnabled() {
		if localIPv4, localIPv4Mask := firstIPv4PrefixKeyForLink(lanLink); localIPv4 != 0 {
			options.LocalDeliver = true
			options.LocalIPv4 = localIPv4
			options.LocalIPv4Mask = localIPv4Mask
		}
	}
	if kernelUDPRXDirectLocalDeliverDevEnabled() {
		if localIPv4, localIPv4Mask := firstIPv4PrefixKeyForLink(lanLink); localIPv4 != 0 {
			manager.enableKernelUDPRXDirectLocalDeliverDevKfunc(&options, ifindex, localIPv4, localIPv4Mask, loadSKBKernelUDPRXDecapL2DevKfuncCall)
		}
	}
	if options.TrustInnerChecksum && options.LocalDeliver && !options.LocalDeliverDev {
		if localIPv4, localIPv4Mask := firstIPv4PrefixKeyForLink(lanLink); localIPv4 != 0 {
			manager.enableKernelUDPRXDirectLocalDeliverDevKfunc(&options, ifindex, localIPv4, localIPv4Mask, loadSKBKernelUDPRXDecapL2DevKfuncCall)
		}
	}
	if kernelUDPRXDirectDecapL2KfuncEnabledForOptions(options) {
		manager.enableKernelUDPRXDirectDecapL2Kfunc(&options, loadSKBKernelUDPRXDecapL2KfuncCall)
	}
	if kernelUDPRXDirectParseDecapL2KfuncEnabledForOptions(options) {
		manager.enableKernelUDPRXDirectParseDecapL2Kfunc(&options, loadSKBKernelUDPRXParseDecapL2KfuncCall)
	}
	return options
}

type skbKfuncCallLoader func() (asm.Instruction, error)

func (manager *Manager) enableKernelUDPRXDirectLocalDeliverDevKfunc(options *kernelUDPRXDirectProgramOptions, ifindex int, localIPv4 uint32, localIPv4Mask uint32, load skbKfuncCallLoader) {
	if options == nil || localIPv4 == 0 {
		return
	}
	options.LocalDeliver = true
	options.LocalIPv4 = localIPv4
	options.LocalIPv4Mask = normalizeKernelUDPRXDirectLocalIPv4Mask(localIPv4Mask)
	kfuncCall, err := load()
	if err != nil {
		manager.warnings = append(manager.warnings, "kernel_udp TC RX local-deliver dev kfunc disabled: "+err.Error())
		return
	}
	if !kfuncCall.IsKfuncCall() {
		manager.warnings = append(manager.warnings, "kernel_udp TC RX local-deliver dev kfunc disabled: metadata has no kfunc call")
		return
	}
	options.LocalDeliverDev = true
	options.LocalDeliverIfindex = ifindex
	options.DecapL2DevKfunc = true
	options.DecapL2DevKfuncCall = kfuncCall
}

func (manager *Manager) enableKernelUDPRXDirectDecapL2Kfunc(options *kernelUDPRXDirectProgramOptions, load skbKfuncCallLoader) {
	if options == nil {
		return
	}
	kfuncCall, err := load()
	if err != nil {
		manager.warnings = append(manager.warnings, "kernel_udp TC RX decap L2 kfunc disabled: "+err.Error())
		return
	}
	if !kfuncCall.IsKfuncCall() {
		manager.warnings = append(manager.warnings, "kernel_udp TC RX decap L2 kfunc disabled: metadata has no kfunc call")
		return
	}
	options.DecapL2Kfunc = true
	options.DecapL2KfuncCall = kfuncCall
}

func (manager *Manager) enableKernelUDPRXDirectParseDecapL2Kfunc(options *kernelUDPRXDirectProgramOptions, load skbKfuncCallLoader) {
	if options == nil {
		return
	}
	if options.StaticDestinationPort == 0 && !options.ExperimentalTCPOnly {
		return
	}
	kfuncCall, err := load()
	if err != nil {
		manager.warnings = append(manager.warnings, "kernel_udp TC RX parse+decap L2 kfunc disabled: "+err.Error())
		return
	}
	if !kfuncCall.IsKfuncCall() {
		manager.warnings = append(manager.warnings, "kernel_udp TC RX parse+decap L2 kfunc disabled: metadata has no kfunc call")
		return
	}
	options.ParseDecapL2Kfunc = true
	options.ParseDecapL2KfuncCall = kfuncCall
}

func (manager *Manager) loadKernelUDPRXDirectProgramWithOptionalKfuncFallback(name string, neighMap *cebpf.Map, ifindex int, sourceMAC net.HardwareAddr, options kernelUDPRXDirectProgramOptions) (kernelUDPRXDirectProgramOptions, *cebpf.Program, error) {
	program, err := loadKernelUDPRXDirectProgramWithOptions(name, manager.statsMap, manager.kernelTransportPortMap, neighMap, ifindex, sourceMAC, options)
	if err == nil {
		return options, program, nil
	}
	if !options.DecapL2Kfunc && !options.DecapL2DevKfunc && !options.ParseDecapL2Kfunc {
		return options, nil, err
	}
	fallback := options
	fallback.DecapL2Kfunc = false
	fallback.DecapL2KfuncCall = asm.Instruction{}
	fallback.DecapL2DevKfunc = false
	fallback.DecapL2DevKfuncCall = asm.Instruction{}
	fallback.ParseDecapL2Kfunc = false
	fallback.ParseDecapL2KfuncCall = asm.Instruction{}
	fallback.LocalDeliverDev = false
	fallback.LocalDeliverIfindex = 0
	fallback.TrustInnerChecksum = false
	program, fallbackErr := loadKernelUDPRXDirectProgramWithOptions(name, manager.statsMap, manager.kernelTransportPortMap, neighMap, ifindex, sourceMAC, fallback)
	if fallbackErr != nil {
		return options, nil, err
	}
	manager.warnings = append(manager.warnings, "kernel_udp TC RX decap kfunc disabled after verifier rejection: "+err.Error())
	return fallback, program, nil
}

func (manager *Manager) kernelUDPRXDirectStaticDestinationPortLocked(options kernelUDPRXDirectProgramOptions) uint16 {
	if !options.DirectOnly || !options.DestinationPortOnly {
		return 0
	}
	if !kernelUDPRXDirectStaticDestinationPortEnabled() {
		return 0
	}
	if options.ExperimentalTCPOnly && !options.KernelUDPOnly {
		port, ok := manager.uniqueLocalExperimentalTCPListenPortLocked()
		if !ok {
			return 0
		}
		return port
	}
	if options.KernelUDPOnly && !options.ExperimentalTCPOnly {
		port, ok := manager.uniqueLocalKernelUDPListenPortLocked()
		if !ok {
			return 0
		}
		return port
	}
	return 0
}

func (manager *Manager) detachKernelUDPRXDirectLocked(underlayLink netlink.Link) error {
	var errs []string
	if manager.expTCPFastPath != nil {
		if err := manager.expTCPFastPath.SetKernelUDPTCRXDirect(false); err != nil {
			errs = append(errs, "disable kernel_udp XDP TC RX direct: "+err.Error())
		}
	}
	if err := manager.detachStandaloneKernelUDPRXXDPDirectLocked(underlayLink); err != nil {
		errs = append(errs, err.Error())
	}
	if manager.underlayIngressFilter != nil {
		if underlayLink != nil {
			if err := netlink.FilterDel(manager.underlayIngressFilter); err != nil && !isNotFound(err) {
				errs = append(errs, fmt.Sprintf("remove kernel_udp underlay RX direct BPF filter from %q: %v", underlayLink.Attrs().Name, err))
			}
		}
		manager.underlayIngressFilter = nil
	}
	if manager.kernelUDPRXSecureDirectFilter != nil {
		if underlayLink != nil {
			if err := netlink.FilterDel(manager.kernelUDPRXSecureDirectFilter); err != nil && !isNotFound(err) {
				errs = append(errs, fmt.Sprintf("remove kernel_udp secure underlay RX direct BPF filter from %q: %v", underlayLink.Attrs().Name, err))
			}
		}
		manager.kernelUDPRXSecureDirectFilter = nil
		manager.kernelUDPRXSecureDirectAttached = false
	}
	if manager.underlayIngressProg != nil {
		if err := manager.underlayIngressProg.Close(); err != nil {
			errs = append(errs, "close kernel_udp underlay RX direct BPF program: "+err.Error())
		}
		manager.underlayIngressProg = nil
	}
	if manager.kernelUDPRXSecureDirect != nil {
		if err := manager.kernelUDPRXSecureDirect.Close(); err != nil {
			errs = append(errs, "close kernel_udp secure underlay RX direct BPF object: "+err.Error())
		}
		manager.kernelUDPRXSecureDirect = nil
	}
	manager.kernelUDPRXNeighMu.Lock()
	manager.kernelUDPRXDirectLANIfindex = 0
	manager.kernelUDPRXDirectSourceMAC = [6]byte{}
	manager.kernelUDPRXDirectDestinationMAC = [6]byte{}
	manager.kernelUDPRXNeighMu.Unlock()
	manager.kernelUDPRXDirectRedirectPeer = false
	manager.kernelUDPRXDirectBroadcast = false
	manager.kernelUDPRXDirectRedirectIngress = false
	manager.kernelUDPRXDirectStaticDestinationPort = 0
	manager.kernelUDPRXDirectLocalDeliver = false
	manager.kernelUDPRXDirectLocalDeliverDev = false
	manager.kernelUDPRXDirectLocalIPv4 = 0
	manager.kernelUDPRXDirectLocalIPv4Mask = 0
	manager.kernelUDPRXDirectDecapL2Kfunc = false
	manager.kernelUDPRXDirectDecapL2DevKfunc = false
	manager.kernelUDPRXDirectParseDecapL2Kfunc = false
	manager.kernelUDPRXDirectTrustInnerChecksum = false
	manager.kernelUDPXDPRXDirectEnabled = false
	manager.kernelUDPXDPRXDirectAttached = false
	manager.kernelUDPXDPRXDirectAttachMode = ""
	manager.kernelUDPXDPRXDirectAttachFlags = 0
	manager.kernelUDPXDPRXDirectFallbackPass = false
	manager.kernelUDPXDPRXSecureDirectVethFallback = false
	manager.kernelUDPXDPRXDirectVethFallback = false
	manager.kernelUDPRXSecureDirectAttached = false
	if manager.kernelUDPRXNeighMap != nil {
		if err := manager.kernelUDPRXNeighMap.Close(); err != nil {
			errs = append(errs, "close kernel_udp RX direct neighbor BPF map: "+err.Error())
		}
		manager.kernelUDPRXNeighMap = nil
	}
	if manager.kernelUDPRXDevMap != nil {
		if err := manager.kernelUDPRXDevMap.Close(); err != nil {
			errs = append(errs, "close kernel_udp RX direct devmap: "+err.Error())
		}
		manager.kernelUDPRXDevMap = nil
	}
	if manager.kernelUDPRXConfigMap != nil {
		if err := manager.kernelUDPRXConfigMap.Close(); err != nil {
			errs = append(errs, "close kernel_udp RX direct config BPF map: "+err.Error())
		}
		manager.kernelUDPRXConfigMap = nil
	}
	if manager.kernelTransportPortMap != nil {
		if err := manager.kernelTransportPortMap.Close(); err != nil {
			errs = append(errs, "close kernel transport TC RX port BPF map: "+err.Error())
		}
		manager.kernelTransportPortMap = nil
	}
	manager.kernelUDPRXDirectAttached = false
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (manager *Manager) attachKernelUDPRXXDPDirectLocked(lanLink netlink.Link, underlayLink netlink.Link) error {
	manager.kernelUDPXDPRXSecureDirectVethFallback = false
	if !kernelUDPXDPRXDirectEnabled() {
		return nil
	}
	if manager.kernelUDPRXNeighMap == nil || manager.kernelUDPRXDevMap == nil ||
		manager.kernelUDPRXConfigMap == nil {
		return nil
	}
	if manager.expTCPFastPath == nil || manager.expTCPFastPath.xdpObject == nil {
		return manager.attachStandaloneKernelUDPRXXDPDirectLocked(lanLink, underlayLink)
	}
	if isVethLink(lanLink) && !kernelUDPXDPRXDirectForceEnabled() &&
		manager.expTCPFastPath != nil && manager.expTCPFastPath.XDPAttachMode() != expTCPXDPAttachSKB {
		manager.kernelUDPXDPRXDirectVethFallback = true
		manager.kernelUDPXDPRXDirectEnabled = false
		manager.warnings = append(manager.warnings, "kernel_udp XDP RX direct falls back to XDP open + TC redirect_peer on veth LAN because the active XDP attach mode is not skb; set TRUSTIX_XDP_MODE=skb to use XDP direct or TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_FORCE=1 to force experimental redirect")
		if err := manager.expTCPFastPath.SetKernelUDPRXDirectWithOptions(true, false, manager.kernelUDPRXSecureDirectConfigEnabledLocked(), experimentalTCPBPFConfigOptions{ForcePassOpened: true}); err != nil {
			return err
		}
		return nil
	}
	queueCount := manager.expTCPFastPath.queueCount
	if queueCount <= 0 {
		queueCount = 1
	}
	secureVethFallback := kernelUDPXDPRXSecureDirectEnabled() &&
		manager.kernelUDPRXSecureDirectConfigEnabledLocked() &&
		isVethLink(lanLink) &&
		(manager.kernelUDPRXDirectRedirectPeer || manager.kernelUDPRXDirectBroadcast) &&
		!kernelUDPXDPRXSecureDirectVethForceEnabled()
	options := experimentalTCPBPFConfigOptions{
		XDPRXSecureDirect:       !secureVethFallback,
		XDPRXTrustInnerChecksum: kernelUDPXDPRXDirectTrustInnerChecksumEnabled(),
	}
	manager.kernelUDPXDPRXDirectEnabled = true
	if err := manager.expTCPFastPath.SetKernelUDPRXDirectWithOptions(true, true, manager.kernelUDPRXSecureDirectConfigEnabledLocked(), options); err != nil {
		manager.kernelUDPXDPRXDirectEnabled = false
		return err
	}
	if secureVethFallback {
		manager.kernelUDPXDPRXSecureDirectVethFallback = true
		manager.warnings = append(manager.warnings, "kernel_udp secure XDP RX direct falls back to TC secure RX on veth LAN because XDP cannot reproduce TC redirect_peer/broadcast ingress semantics; set TRUSTIX_KERNEL_UDP_XDP_RX_SECURE_DIRECT_FORCE=1 only for isolated experiments")
	}
	return nil
}

func (manager *Manager) attachStandaloneKernelUDPRXXDPDirectLocked(lanLink netlink.Link, underlayLink netlink.Link) error {
	if lanLink == nil || underlayLink == nil {
		return nil
	}
	if manager.kernelUDPXDPRXDirectObject != nil || manager.kernelUDPXDPRXDirectAttached {
		return nil
	}
	if isVethLink(lanLink) && !kernelUDPXDPRXDirectForceEnabled() && !standaloneKernelUDPXDPRXDirectPrefersSKB() {
		manager.kernelUDPXDPRXDirectVethFallback = true
		manager.kernelUDPXDPRXDirectEnabled = false
		manager.warnings = append(manager.warnings, "kernel_udp standalone XDP RX direct falls back to TC redirect_peer on veth LAN because skb XDP was not selected; set TRUSTIX_XDP_MODE=skb to use XDP direct or TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_FORCE=1 to force experimental redirect")
		return nil
	}
	object, err := loadKernelUDPStandaloneXDPObject(experimentalTCPXDPReplacements{
		kernelUDPRXNeighMap:  manager.kernelUDPRXNeighMap,
		kernelUDPRXDevMap:    manager.kernelUDPRXDevMap,
		kernelUDPRXConfigMap: manager.kernelUDPRXConfigMap,
	})
	if err != nil {
		return fmt.Errorf("load standalone kernel_udp XDP RX direct object: %w", err)
	}
	if object.fallbackReason != "" {
		manager.warnings = append(manager.warnings, object.fallbackReason)
	}
	var fallbackReasons []string
	var selectedMode string
	var selectedFlags int
	for _, mode := range experimentalTCPRequestedXDPModesWithOptions(experimentalTCPFastPathOptions{preferSKBXDPMode: standaloneKernelUDPXDPRXDirectPrefersSKB()}) {
		flags := experimentalTCPXDPFlags(mode)
		if err := netlink.LinkSetXdpFdWithFlags(underlayLink, object.program.FD(), flags); err != nil {
			fallbackReasons = append(fallbackReasons, fmt.Sprintf("%s attach failed: %v", mode, err))
			continue
		}
		selectedMode = mode
		selectedFlags = flags
		break
	}
	if selectedMode == "" {
		_ = object.Close()
		return fmt.Errorf("attach standalone kernel_udp XDP RX direct on %q: %s", underlayLink.Attrs().Name, strings.Join(fallbackReasons, "; "))
	}
	manager.kernelUDPXDPRXDirectObject = object
	manager.kernelUDPXDPRXDirectAttached = true
	manager.kernelUDPXDPRXDirectAttachMode = selectedMode
	manager.kernelUDPXDPRXDirectAttachFlags = selectedFlags
	manager.kernelUDPXDPRXDirectFallbackPass = true
	manager.kernelUDPXDPRXDirectEnabled = true
	if len(fallbackReasons) > 0 {
		manager.warnings = append(manager.warnings, "kernel_udp standalone XDP RX direct mode fallback: "+strings.Join(fallbackReasons, "; "))
	}
	if err := manager.syncStandaloneKernelUDPRXXDPDirectConfigLocked(); err != nil {
		_ = manager.detachStandaloneKernelUDPRXXDPDirectLocked(underlayLink)
		return err
	}
	desired := manager.desiredKernelTransportPortsLocked()
	if err := manager.syncKernelTransportPortMapLocked(object.portMap, desired, "kernel transport standalone XDP port BPF map"); err != nil {
		_ = manager.detachStandaloneKernelUDPRXXDPDirectLocked(underlayLink)
		return err
	}
	return nil
}

func standaloneKernelUDPXDPRXDirectPrefersSKB() bool {
	mode := normalizeExperimentalTCPModeEnv(os.Getenv("TRUSTIX_XDP_MODE"))
	return mode == "" || mode == expTCPModeEnvAuto || mode == expTCPXDPAttachSKB
}

func (manager *Manager) syncStandaloneKernelUDPRXXDPDirectConfigLocked() error {
	if manager.kernelUDPXDPRXDirectObject == nil {
		return nil
	}
	enabled := manager.kernelUDPRXDirectConfigEnabledLocked()
	xdpEnabled := enabled && manager.kernelUDPXDPRXDirectEnabled && !kernelDatapathRXXDPPassEnabledForSpec(manager.spec)
	secureEnabled := enabled && manager.kernelUDPRXSecureDirectConfigEnabledLocked()
	options := experimentalTCPBPFConfigOptions{
		XDPRXSecureDirect:       kernelUDPXDPRXSecureDirectEnabled() && !manager.kernelUDPXDPRXSecureDirectVethFallback,
		XDPFallbackPass:         true,
		XDPRXTrustInnerChecksum: kernelUDPXDPRXDirectTrustInnerChecksumEnabled(),
	}
	config, err := configureExperimentalTCPBPFConfigValueForOptions(manager.kernelUDPXDPRXDirectObject.configMap, 1, true, xdpEnabled, secureEnabled, options)
	if err != nil {
		return fmt.Errorf("sync standalone kernel_udp XDP RX direct config: %w", err)
	}
	manager.kernelUDPXDPRXDirectObject.skipTCPChecksum = config&experimentalTCPConfigSkipTCPChecksum != 0
	return nil
}

func (manager *Manager) detachStandaloneKernelUDPRXXDPDirectLocked(underlayLink netlink.Link) error {
	var errs []string
	if manager.kernelUDPXDPRXDirectAttached {
		if underlayLink != nil {
			if err := detachExperimentalTCPXDP(underlayLink, manager.kernelUDPXDPRXDirectAttachFlags); err != nil && !isNotFound(err) {
				errs = append(errs, "detach standalone kernel_udp XDP RX direct program: "+err.Error())
			}
		}
		manager.kernelUDPXDPRXDirectAttached = false
	}
	if manager.kernelUDPXDPRXDirectObject != nil {
		if err := manager.kernelUDPXDPRXDirectObject.Close(); err != nil {
			errs = append(errs, "close standalone kernel_udp XDP RX direct object: "+err.Error())
		}
		manager.kernelUDPXDPRXDirectObject = nil
	}
	manager.kernelUDPXDPRXDirectAttachMode = ""
	manager.kernelUDPXDPRXDirectAttachFlags = 0
	manager.kernelUDPXDPRXDirectFallbackPass = false
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (manager *Manager) configureKernelUDPRXDirectNeighborMap(lanLink netlink.Link) {
	if lanLink == nil || manager.kernelUDPRXNeighMap == nil {
		return
	}
	attrs := lanLink.Attrs()
	if attrs == nil || attrs.Index == 0 || len(attrs.HardwareAddr) != 6 {
		return
	}
	var sourceMAC [6]byte
	copy(sourceMAC[:], attrs.HardwareAddr)
	var destinationMAC [6]byte
	if peerMAC, warning := vethPeerHardwareAddr(lanLink); len(peerMAC) == 6 {
		copy(destinationMAC[:], peerMAC)
	} else if warning != "" {
		manager.warnings = append(manager.warnings, warning)
	}
	manager.kernelUDPRXNeighMu.Lock()
	manager.kernelUDPRXDirectLANIfindex = attrs.Index
	manager.kernelUDPRXDirectSourceMAC = sourceMAC
	manager.kernelUDPRXDirectDestinationMAC = destinationMAC
	manager.kernelUDPRXNeighMu.Unlock()
	if manager.kernelUDPRXDevMap != nil {
		key := uint32(0)
		ifindex := uint32(attrs.Index)
		if err := manager.kernelUDPRXDevMap.Update(key, ifindex, cebpf.UpdateAny); err != nil {
			manager.warnings = append(manager.warnings, "configure kernel_udp XDP RX direct devmap: "+err.Error())
		}
	}
	if manager.kernelUDPRXConfigMap != nil {
		key := uint32(0)
		destinationMACForConfig := destinationMAC
		if destinationMACForConfig == ([6]byte{}) {
			for i := range destinationMACForConfig {
				destinationMACForConfig[i] = 0xff
			}
		}
		config := kernelUDPRXConfigValue{
			SourceMAC0:      binary.LittleEndian.Uint32(sourceMAC[0:4]),
			SourceMAC1:      binary.LittleEndian.Uint16(sourceMAC[4:6]),
			Ifindex:         uint32(attrs.Index),
			DestinationMAC0: binary.LittleEndian.Uint32(destinationMACForConfig[0:4]),
			DestinationMAC1: binary.LittleEndian.Uint16(destinationMACForConfig[4:6]),
		}
		if err := manager.kernelUDPRXConfigMap.Update(key, config, cebpf.UpdateAny); err != nil {
			manager.warnings = append(manager.warnings, "configure kernel_udp XDP RX direct config map: "+err.Error())
		}
	}
	if err := clearBPFMap[[4]byte, kernelUDPRXNeighValue](manager.kernelUDPRXNeighMap, "kernel_udp RX direct neighbor BPF map"); err != nil {
		manager.warnings = append(manager.warnings, err.Error())
	}
	manager.seedNeighborCache(attrs.Index)
	neighbors, err := netlink.NeighList(attrs.Index, netlink.FAMILY_V4)
	if err != nil {
		manager.warnings = append(manager.warnings, "seed kernel_udp RX direct neighbor map: "+err.Error())
		return
	}
	for _, neighbor := range neighbors {
		manager.updateKernelUDPRXDirectNeighbor(neighbor, false)
	}
	manager.syncKernelUDPRXDirectNeighborsFromCache(attrs.Index)
}

func kernelUDPRXDirectOptionsForLink(link netlink.Link) kernelUDPRXDirectProgramOptions {
	return kernelUDPRXDirectOptionsForLinkWithSpec(link, dataplane.AttachSpec{})
}

func kernelUDPRXDirectOptionsForLinkWithSpec(link netlink.Link, spec dataplane.AttachSpec) kernelUDPRXDirectProgramOptions {
	directOnly := kernelUDPTXDirectOnlyEnabled(spec)
	expTCPOnly := kernelUDPTXDirectExperimentalTCPOnlyEnabledForSpec(spec)
	kernelUDPOnly := kernelUDPTXDirectKernelUDPOnlyEnabledForSpec(spec)
	dummyDirectOnly := directOnly && isDummyLink(link)
	if kernelUDPRXDirectBroadcastDisabled() {
		return kernelUDPRXDirectProgramOptions{ExperimentalTCPOnly: expTCPOnly, KernelUDPOnly: kernelUDPOnly, DirectOnly: directOnly, DestinationPortOnly: kernelUDPRXDirectDestinationPortOnlyEnabled(kernelUDPOnly, expTCPOnly, directOnly)}
	}
	if !kernelUDPRXDirectBroadcastEnabled() && !isVethLink(link) && !dummyDirectOnly {
		return kernelUDPRXDirectProgramOptions{ExperimentalTCPOnly: expTCPOnly, KernelUDPOnly: kernelUDPOnly, DirectOnly: directOnly, DestinationPortOnly: kernelUDPRXDirectDestinationPortOnlyEnabled(kernelUDPOnly, expTCPOnly, directOnly)}
	}
	options := kernelUDPRXDirectProgramOptions{Broadcast: true, RedirectIngress: dummyDirectOnly, ExperimentalTCPOnly: expTCPOnly, KernelUDPOnly: kernelUDPOnly, DirectOnly: directOnly, DestinationPortOnly: kernelUDPRXDirectDestinationPortOnlyEnabled(kernelUDPOnly, expTCPOnly, directOnly)}
	if !kernelUDPRXDirectPeerRedirectDisabled() && (kernelUDPRXDirectPeerRedirectEnabled() || isVethLink(link)) {
		options.RedirectPeer = true
	}
	return options
}

func kernelUDPRXDirectDestinationPortOnlyEnabled(kernelUDPOnly, experimentalTCPOnly, directOnly bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT_DESTINATION_PORT_ONLY"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return directOnly && (kernelUDPOnly || experimentalTCPOnly)
	}
}

func kernelUDPRXDirectStaticDestinationPortEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT_STATIC_DESTINATION_PORT"))) {
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}

func isVethLink(link netlink.Link) bool {
	if link == nil {
		return false
	}
	if _, ok := link.(*netlink.Veth); ok {
		return true
	}
	return strings.EqualFold(link.Type(), "veth")
}

func isDummyLink(link netlink.Link) bool {
	if link == nil {
		return false
	}
	if _, ok := link.(*netlink.Dummy); ok {
		return true
	}
	return strings.EqualFold(link.Type(), "dummy")
}

func kernelUDPRXDirectBroadcastEnabled() bool {
	return envTruthy("TRUSTIX_KERNEL_UDP_TC_RX_BROADCAST_DIRECT")
}

func kernelUDPRXDirectBroadcastDisabled() bool {
	return envFalsey("TRUSTIX_KERNEL_UDP_TC_RX_BROADCAST_DIRECT")
}

func kernelUDPRXDirectPeerRedirectEnabled() bool {
	return envTruthy("TRUSTIX_KERNEL_UDP_TC_RX_PEER_REDIRECT")
}

func kernelUDPRXDirectPeerRedirectDisabled() bool {
	return envFalsey("TRUSTIX_KERNEL_UDP_TC_RX_PEER_REDIRECT")
}

func kernelUDPRXDirectLocalDeliverEnabled() bool {
	return envTruthy(
		"TRUSTIX_KERNEL_UDP_TC_RX_DIRECT_LOCAL_DELIVER",
		"TRUSTIX_KERNEL_UDP_TC_RX_LOCAL_DELIVER",
	)
}

func kernelUDPRXDirectLocalDeliverDevEnabled() bool {
	return envTruthy(
		"TRUSTIX_KERNEL_UDP_TC_RX_DIRECT_LOCAL_DELIVER_DEV",
		"TRUSTIX_KERNEL_UDP_TC_RX_LOCAL_DELIVER_DEV",
	)
}

func kernelUDPTXDirectRedirectPeerEnabledForLink(link netlink.Link, kernelUDPOnly bool, directOnly bool) bool {
	if envFalsey("TRUSTIX_KERNEL_UDP_TC_TX_REDIRECT_PEER", "TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_REDIRECT_PEER") {
		return false
	}
	if envTruthy("TRUSTIX_KERNEL_UDP_TC_TX_REDIRECT_PEER", "TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_REDIRECT_PEER") {
		return true
	}
	return kernelUDPOnly && directOnly && isVethLink(link)
}

func kernelUDPXDPRXDirectForceEnabled() bool {
	return envTruthy("TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_FORCE")
}

func kernelUDPXDPRXSecureDirectVethForceEnabled() bool {
	return envTruthy("TRUSTIX_KERNEL_UDP_XDP_RX_SECURE_DIRECT_FORCE")
}

func kernelUDPTCAdjustRoomBaseFlags() uint64 {
	if envFalsey("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_NO_CSUM_RESET") {
		return 0
	}
	if envTruthy("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_NO_CSUM_RESET") {
		return bpfAdjRoomNoCSUMReset
	}
	return 0
}

func kernelUDPTunnelGSOEnabled() bool {
	return envTruthy("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO")
}

func kernelUDPTunnelGSOActiveSKBEnabled() bool {
	return envTruthy("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO")
}

func kernelUDPTunnelGSOEnabledForOptions(options kernelUDPTXDirectProgramOptions) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	}
	if kernelUDPTXDirectSafeModeEnabled() {
		return false
	}
	if options.ExperimentalTCPOnly && options.DirectOnly &&
		options.RouteTCPGSOKfunc {
		return true
	}
	return options.DirectOnly && !options.ExperimentalTCPOnly
}

func kernelUDPTunnelGSOActiveSKBEnabledForOptions(options kernelUDPTXDirectProgramOptions) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO"))) {
	case "1", "true", "yes", "on", "enabled":
		if options.ExperimentalTCPOnly {
			if options.DirectOnly && options.RouteTCPGSOKfunc {
				return true
			}
			return experimentalTCPTXDirectSafeActiveGSOEnabledForOptions(options) ||
				(options.RouteTCPGSOKfunc && (options.RouteTCPGSOAsyncKfunc ||
					experimentalTCPTXDirectRouteTCPGSOAsyncKfuncRequested())) ||
				experimentalTCPTXDirectActiveGSOUnsafeEnabled()
		}
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	}
	if kernelUDPTXDirectSafeModeEnabled() {
		return false
	}
	if options.ExperimentalTCPOnly && options.DirectOnly &&
		options.RouteTCPGSOKfunc {
		return true
	}
	return kernelUDPTunnelGSOEnabledForOptions(options) && options.DirectOnly && !options.ExperimentalTCPOnly
}

func experimentalTCPTXDirectSafeActiveGSOEnabledForOptions(options kernelUDPTXDirectProgramOptions) bool {
	if !options.ExperimentalTCPOnly || !options.DirectOnly {
		return false
	}
	if kernelUDPTXDirectSafeModeEnabled() {
		return false
	}
	if !options.FinalizeFlowTCPHeaderKfunc || !options.FinalizeFlowTCPHeaderKfuncCall.IsKfuncCall() {
		return false
	}
	if options.PushRouteTCPHeaderKfunc || options.RouteTCPGSOKfunc || options.RouteTCPXmitKfunc {
		return false
	}
	if experimentalTCPSkipOuterTCPChecksum() || experimentalTCPTXDirectPreOuterInnerChecksumEnabled() {
		return false
	}
	if envFalsey(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_ACTIVE_GSO_SAFE",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_SAFE_ACTIVE_GSO",
	) {
		return false
	}
	if !experimentalTCPUnsafeActiveGSOAcknowledged() {
		return false
	}
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_ACTIVE_GSO_SAFE",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_SAFE_ACTIVE_GSO",
	)
}

func experimentalTCPTXDirectActiveGSOUnsafeEnabled() bool {
	if !experimentalTCPUnsafeActiveGSOAcknowledged() {
		return false
	}
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_ACTIVE_GSO_UNSAFE",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_UNSAFE_ACTIVE_GSO",
	)
}

func experimentalTCPUnsafeActiveGSOAcknowledged() bool {
	return false
}

func experimentalTCPUnsafeRouteTCPKfuncsAcknowledged() bool {
	return false
}

func experimentalTCPAsyncRouteGSOAcknowledged() bool {
	return false
}

func kernelUDPTunnelGSOEncapL2Flags() uint64 {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_ENCAP_L2_LEN"))
	if value == "" {
		return 0
	}
	switch strings.ToLower(value) {
	case "0", "false", "no", "off", "disabled", "none":
		return 0
	}
	parsed, err := strconv.ParseUint(value, 10, 8)
	if err != nil {
		return 0
	}
	if parsed == 0 {
		return 0
	}
	return bpfAdjRoomEncapL2ETH | (parsed << bpfAdjRoomEncapL2Shift)
}

func kernelUDPTCTXAdjustRoomFlags() uint64 {
	flags := kernelUDPTCAdjustRoomBaseFlags()
	if kernelUDPTunnelGSOEnabled() {
		flags |= bpfAdjRoomNoCSUMReset | bpfAdjRoomFixedGSO | bpfAdjRoomEncapL3IPv4 | bpfAdjRoomEncapL4UDP | kernelUDPTunnelGSOEncapL2Flags()
	}
	return flags
}

func kernelUDPTCTXAdjustRoomFlagsForOptions(options kernelUDPTXDirectProgramOptions) uint64 {
	flags := kernelUDPTCAdjustRoomBaseFlags()
	if kernelUDPTunnelGSOEnabledForOptions(options) {
		flags |= bpfAdjRoomNoCSUMReset | bpfAdjRoomFixedGSO | bpfAdjRoomEncapL3IPv4 | bpfAdjRoomEncapL4UDP | kernelUDPTunnelGSOEncapL2Flags()
	}
	if options.DirectOnly && options.KernelUDPOnly && !options.ExperimentalTCPOnly &&
		!envFalsey("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_NO_CSUM_RESET") {
		flags |= bpfAdjRoomNoCSUMReset
	}
	return flags
}

func experimentalTCPTXDirectEnabled() bool {
	return experimentalTCPTXRawDirectExplicitlyEnabled()
}

func experimentalTCPTXDirectEnabledForSpec(spec dataplane.AttachSpec) bool {
	if envFalsey(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT",
		"TRUSTIX_REMOTE_EXPERIMENTAL_TCP_TC_TX_DIRECT",
		"TRUSTIX_E2E_EXPERIMENTAL_TCP_TC_TX_DIRECT",
		"TRUSTIX_IPERF3_CRYPTO_BENCH_EXPERIMENTAL_TCP_TC_TX_DIRECT",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_ONLY",
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_EXPERIMENTAL_TCP_ONLY",
	) {
		return false
	}
	return spec.ExperimentalTCPTXDirect || experimentalTCPTXDirectEnabled()
}

func experimentalTCPTXRawDirectExplicitlyEnabled() bool {
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT",
		"TRUSTIX_REMOTE_EXPERIMENTAL_TCP_TC_TX_DIRECT",
		"TRUSTIX_E2E_EXPERIMENTAL_TCP_TC_TX_DIRECT",
		"TRUSTIX_IPERF3_CRYPTO_BENCH_EXPERIMENTAL_TCP_TC_TX_DIRECT",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_ONLY",
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_EXPERIMENTAL_TCP_ONLY",
	)
}

func kernelUDPTXDirectProgramEnabled() bool {
	if kernelUDPTXDirectDisabled() {
		return false
	}
	if kernelUDPTXDirectExperimentalTCPOnlyEnabled() {
		return experimentalTCPTXDirectEnabled()
	}
	return true
}

func kernelUDPTXDirectProgramEnabledForSpec(spec dataplane.AttachSpec) bool {
	if spec.KernelUDPTCOnlyProvider && spec.KernelUDPTXDirectOnly {
		return true
	}
	if kernelUDPTXDirectDisabled() && !experimentalTCPRouteGSORequestedForSpec(spec) {
		return false
	}
	if kernelUDPTXDirectExperimentalTCPOnlyEnabledForSpec(spec) {
		return experimentalTCPTXDirectEnabledForSpec(spec)
	}
	return true
}

func experimentalTCPRouteGSORequestedForSpec(spec dataplane.AttachSpec) bool {
	return spec.ExperimentalTCPRouteGSOSync || spec.ExperimentalTCPRouteGSOAsync
}

func kernelUDPTCRXAdjustRoomFlags() uint64 {
	flags := kernelUDPTCRXAdjustRoomBaseFlags()
	if kernelUDPTunnelGSOEnabled() {
		flags |= bpfAdjRoomFixedGSO | bpfAdjRoomDecapL3IPv4
		if kernelUDPTCRXAdjustRoomNoCSUMResetEnabled() {
			flags |= bpfAdjRoomNoCSUMReset
		}
	}
	return flags
}

func kernelUDPTCRXAdjustRoomFlagsForOptions(options kernelUDPTXDirectProgramOptions) uint64 {
	flags := kernelUDPTCRXAdjustRoomBaseFlags()
	if kernelUDPTCRXTunnelGSOEnabledForOptions(options) {
		flags |= bpfAdjRoomFixedGSO | bpfAdjRoomDecapL3IPv4
		if kernelUDPTCRXAdjustRoomNoCSUMResetEnabled() {
			flags |= bpfAdjRoomNoCSUMReset
		}
	}
	return flags
}

func kernelUDPTCRXTunnelGSOEnabledForOptions(options kernelUDPTXDirectProgramOptions) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_RX_ADJ_ROOM_TUNNEL_GSO"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	}
	return false
}

func kernelUDPTCRXAdjustRoomBaseFlags() uint64 {
	if kernelUDPTCRXAdjustRoomNoCSUMResetEnabled() {
		return bpfAdjRoomNoCSUMReset
	}
	return 0
}

func kernelUDPTCRXAdjustRoomNoCSUMResetEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_RX_ADJ_ROOM_NO_CSUM_RESET"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	}
	return kernelUDPTCAdjustRoomBaseFlags()&bpfAdjRoomNoCSUMReset != 0
}

func kernelUDPRXDirectDecapL2KfuncEnabled() bool {
	return envTruthy("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT_DECAP_L2_KFUNC")
}

func kernelUDPRXDirectDecapL2KfuncEnabledForOptions(options kernelUDPRXDirectProgramOptions) bool {
	return kernelUDPRXDirectDecapL2KfuncEnabled()
}

func kernelUDPRXDirectParseDecapL2KfuncEnabled() bool {
	return envTruthy("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT_PARSE_DECAP_L2_KFUNC")
}

func kernelUDPRXDirectParseDecapL2KfuncEnabledForOptions(options kernelUDPRXDirectProgramOptions) bool {
	if options.StaticDestinationPort == 0 && !options.ExperimentalTCPOnly {
		return false
	}
	if options.ExperimentalTCPOnly && options.DirectOnly && options.DestinationPortOnly &&
		envTruthy("TRUSTIX_EXPERIMENTAL_TCP_TC_RX_STREAM_PARSE", "TRUSTIX_TIXT_RX_STREAM_PARSE") {
		return true
	}
	if kernelUDPRXDirectParseDecapL2KfuncEnabled() {
		return true
	}
	return false
}

func kernelUDPRXDirectParseDecapL2PrefilterEnabled() bool {
	if envFalsey(
		"TRUSTIX_KERNEL_UDP_TC_RX_DIRECT_PARSE_DECAP_L2_PREFILTER",
		"TRUSTIX_KERNEL_UDP_TC_RX_PARSE_DECAP_L2_PREFILTER",
	) {
		return false
	}
	return true
}

func kernelUDPRXDirectTrustInnerChecksumEnabledForOptions(options kernelUDPRXDirectProgramOptions) bool {
	if envFalsey(
		"TRUSTIX_KERNEL_UDP_TC_RX_DIRECT_TRUST_INNER_CHECKSUM",
		"TRUSTIX_KERNEL_UDP_TC_RX_DIRECT_TRUST_INNER_CHECKSUMS",
		"TRUSTIX_KERNEL_UDP_TC_RX_TRUST_INNER_CHECKSUM",
		"TRUSTIX_KERNEL_UDP_TC_RX_TRUST_INNER_CHECKSUMS",
	) {
		return false
	}
	if envTruthy(
		"TRUSTIX_KERNEL_UDP_TC_RX_DIRECT_TRUST_INNER_CHECKSUM",
		"TRUSTIX_KERNEL_UDP_TC_RX_DIRECT_TRUST_INNER_CHECKSUMS",
		"TRUSTIX_KERNEL_UDP_TC_RX_TRUST_INNER_CHECKSUM",
		"TRUSTIX_KERNEL_UDP_TC_RX_TRUST_INNER_CHECKSUMS",
	) {
		return true
	}
	return !kernelUDPTXDirectInnerTCPChecksumDisabled() && (options.DirectOnly || options.ExperimentalTCPOnly || experimentalTCPTXDirectEnabled())
}

func (manager *Manager) updateKernelUDPRXDirectNeighbor(neighbor netlink.Neigh, deleted bool) {
	addr, ok := ipv4AddrFromIP(neighbor.IP)
	if !ok {
		return
	}
	manager.kernelUDPRXNeighMu.RLock()
	neighMap := manager.kernelUDPRXNeighMap
	lanIfindex := manager.kernelUDPRXDirectLANIfindex
	sourceMAC := manager.kernelUDPRXDirectSourceMAC
	manager.kernelUDPRXNeighMu.RUnlock()
	if neighMap == nil || lanIfindex == 0 || neighbor.LinkIndex != lanIfindex {
		return
	}
	key := addr.As4()
	if deleted || neighbor.State == netlink.NUD_FAILED || neighbor.State == netlink.NUD_INCOMPLETE || len(neighbor.HardwareAddr) != 6 {
		_ = neighMap.Delete(key)
		return
	}
	value := kernelUDPRXNeighValue{
		Ifindex:         uint32(lanIfindex),
		DestinationMAC0: binary.LittleEndian.Uint32(neighbor.HardwareAddr[0:4]),
		DestinationMAC1: binary.LittleEndian.Uint16(neighbor.HardwareAddr[4:6]),
		SourceMAC0:      binary.LittleEndian.Uint32(sourceMAC[0:4]),
		SourceMAC1:      binary.LittleEndian.Uint16(sourceMAC[4:6]),
	}
	_ = neighMap.Update(key, value, cebpf.UpdateAny)
}

func (manager *Manager) detachTCPrograms(link netlink.Link) error {
	var errs []string
	if len(manager.lanTCFilters) > 0 {
		linksByName := map[string]netlink.Link{}
		if link != nil && link.Attrs() != nil {
			linksByName[link.Attrs().Name] = link
		}
		names := make([]string, 0, len(manager.lanTCFilters))
		for name := range manager.lanTCFilters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			target := linksByName[name]
			if target == nil {
				found, err := netlink.LinkByName(name)
				if err != nil {
					if !isNotFound(err) {
						errs = append(errs, fmt.Sprintf("inspect LAN iface %q for TC filter cleanup: %v", name, err))
					}
					delete(manager.lanTCFilters, name)
					continue
				}
				target = found
			}
			if err := manager.detachTCFiltersFromLink(target); err != nil {
				errs = append(errs, err.Error())
			}
		}
	} else {
		if manager.kernelUDPTXSecureDirectEgressFilter != nil {
			if err := netlink.FilterDel(manager.kernelUDPTXSecureDirectEgressFilter); err != nil && !isNotFound(err) && link != nil && link.Attrs() != nil {
				errs = append(errs, fmt.Sprintf("remove kernel_udp secure TC TX direct egress BPF filter from %q: %v", link.Attrs().Name, err))
			}
			manager.kernelUDPTXSecureDirectEgressFilter = nil
		}
		if manager.kernelUDPTXSecureDirectFilter != nil {
			if err := netlink.FilterDel(manager.kernelUDPTXSecureDirectFilter); err != nil && !isNotFound(err) && link != nil && link.Attrs() != nil {
				errs = append(errs, fmt.Sprintf("remove kernel_udp secure TC TX direct BPF filter from %q: %v", link.Attrs().Name, err))
			}
			manager.kernelUDPTXSecureDirectFilter = nil
		}
		if manager.ingressFilter != nil {
			if err := netlink.FilterDel(manager.ingressFilter); err != nil && !isNotFound(err) && link != nil && link.Attrs() != nil {
				errs = append(errs, fmt.Sprintf("remove ingress BPF filter from %q: %v", link.Attrs().Name, err))
			}
			manager.ingressFilter = nil
		}
		if manager.egressFilter != nil {
			if err := netlink.FilterDel(manager.egressFilter); err != nil && !isNotFound(err) && link != nil && link.Attrs() != nil {
				errs = append(errs, fmt.Sprintf("remove egress BPF filter from %q: %v", link.Attrs().Name, err))
			}
			manager.egressFilter = nil
		}
	}
	manager.kernelUDPTXSecureDirectAttached = false
	if manager.ingressProg != nil {
		if err := manager.ingressProg.Close(); err != nil {
			errs = append(errs, "close ingress BPF program: "+err.Error())
		}
		manager.ingressProg = nil
	}
	if manager.egressProg != nil {
		if err := manager.egressProg.Close(); err != nil {
			errs = append(errs, "close egress BPF program: "+err.Error())
		}
		manager.egressProg = nil
	}
	if manager.kernelUDPTXSecureDirect != nil {
		if err := manager.kernelUDPTXSecureDirect.Close(); err != nil {
			errs = append(errs, "close kernel_udp secure TC TX direct BPF object: "+err.Error())
		}
		manager.kernelUDPTXSecureDirect = nil
	}
	if manager.statsMap != nil {
		if err := manager.statsMap.Close(); err != nil {
			errs = append(errs, "close stats BPF map: "+err.Error())
		}
		manager.statsMap = nil
	}
	if manager.captureReader != nil {
		if err := manager.captureReader.Close(); err != nil && !errors.Is(err, perf.ErrClosed) {
			errs = append(errs, "close capture perf reader: "+err.Error())
		}
		manager.captureReader = nil
	}
	if manager.captureRingReader != nil {
		if err := manager.captureRingReader.Close(); err != nil && !errors.Is(err, ringbuf.ErrClosed) {
			errs = append(errs, "close capture ringbuf reader: "+err.Error())
		}
		manager.captureRingReader = nil
	}
	if manager.captureMap != nil {
		if err := manager.captureMap.Close(); err != nil {
			errs = append(errs, "close capture event map: "+err.Error())
		}
		manager.captureMap = nil
	}
	if manager.captureScratchMap != nil {
		if err := manager.captureScratchMap.Close(); err != nil {
			errs = append(errs, "close capture scratch BPF map: "+err.Error())
		}
		manager.captureScratchMap = nil
	}
	if manager.natExcludeMap != nil {
		if err := manager.natExcludeMap.Close(); err != nil {
			errs = append(errs, "close NAT exclude BPF map: "+err.Error())
		}
		manager.natExcludeMap = nil
		manager.natExcludeEntries = 0
	}
	if manager.natBindingMap != nil {
		if err := manager.natBindingMap.Close(); err != nil {
			errs = append(errs, "close NAT binding BPF map: "+err.Error())
		}
		manager.natBindingMap = nil
		manager.natBindingEntries = 0
		manager.natBindingKeys = make(map[natBindingKey]struct{})
	}
	if manager.natRouteMap != nil {
		if err := manager.natRouteMap.Close(); err != nil {
			errs = append(errs, "close NAT route LPM BPF map: "+err.Error())
		}
		manager.natRouteMap = nil
		manager.natRouteEntries = 0
	}
	if manager.natSourceMap != nil {
		if err := manager.natSourceMap.Close(); err != nil {
			errs = append(errs, "close NAT source LPM BPF map: "+err.Error())
		}
		manager.natSourceMap = nil
		manager.natSourceEntries = 0
	}
	if manager.natConfigMap != nil {
		if err := manager.natConfigMap.Close(); err != nil {
			errs = append(errs, "close NAT config BPF map: "+err.Error())
		}
		manager.natConfigMap = nil
	}
	if manager.packetPolicyMap != nil {
		if err := manager.packetPolicyMap.Close(); err != nil {
			errs = append(errs, "close packet policy BPF map: "+err.Error())
		}
		manager.packetPolicyMap = nil
	}
	if manager.kernelTransportPortMap != nil {
		if err := manager.kernelTransportPortMap.Close(); err != nil {
			errs = append(errs, "close kernel transport TC RX port BPF map: "+err.Error())
		}
		manager.kernelTransportPortMap = nil
	}
	if manager.kernelUDPTXFlowMap != nil {
		if err := manager.kernelUDPTXFlowMap.Close(); err != nil {
			errs = append(errs, "close kernel_udp TC TX flow BPF map: "+err.Error())
		}
		manager.kernelUDPTXFlowMap = nil
		manager.kernelUDPTXDirectFlows = 0
	}
	if manager.kernelUDPTXRouteCacheMap != nil {
		if err := manager.kernelUDPTXRouteCacheMap.Close(); err != nil {
			errs = append(errs, "close kernel_udp TC TX route cache BPF map: "+err.Error())
		}
		manager.kernelUDPTXRouteCacheMap = nil
		manager.kernelUDPTXDirectRouteCacheEnabled = false
		manager.kernelUDPTXDirectRouteCacheException = false
	}
	if manager.kernelUDPTXRouteMap != nil {
		if err := manager.kernelUDPTXRouteMap.Close(); err != nil {
			errs = append(errs, "close kernel_udp TC TX route BPF map: "+err.Error())
		}
		manager.kernelUDPTXRouteMap = nil
		manager.kernelUDPTXDirectRoutes = 0
	}
	manager.kernelUDPTXDirectInnerTCPChecksumKfunc = false
	manager.kernelUDPTXDirectOuterTCPChecksumKfunc = false
	manager.kernelUDPTXDirectOuterTCPHeaderKfunc = false
	manager.kernelUDPTXDirectTCPPartialCSUMKfunc = false
	manager.kernelUDPTXDirectPushTCPHeaderKfunc = false
	manager.kernelUDPTXDirectPushFlowTCPHeaderKfunc = false
	manager.kernelUDPTXDirectFinalizeFlowTCPHeaderKfunc = false
	manager.kernelUDPTXDirectPushRouteTCPHeaderKfunc = false
	manager.kernelUDPTXDirectRouteTCPGSOKfunc = false
	manager.kernelUDPTXDirectRouteTCPGSOAsyncKfunc = false
	manager.kernelUDPTXDirectRouteTCPXmitKfunc = false
	if manager.routeMap != nil {
		if err := manager.routeMap.Close(); err != nil {
			errs = append(errs, "close route LPM BPF map: "+err.Error())
		}
		manager.routeMap = nil
		manager.routeEntries = 0
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func loadIngressFastPathProgram(name string, statsMap *cebpf.Map, packetPolicyMap *cebpf.Map, routeMap *cebpf.Map, kernelUDPTXRouteMap *cebpf.Map, kernelUDPTXFlowMap *cebpf.Map, natConfigMap *cebpf.Map, natSourceMap *cebpf.Map, natRouteMap *cebpf.Map, natExcludeMap *cebpf.Map, captureMap *cebpf.Map, txDirectOptions ...kernelUDPTXDirectProgramOptions) (*cebpf.Program, error) {
	captureScratchMap, err := newCaptureScratchBPFMap()
	if err != nil {
		return nil, err
	}
	defer captureScratchMap.Close()
	return loadIngressFastPathProgramWithCaptureScratch(name, statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, captureMap, captureScratchMap, txDirectOptions...)
}

func loadIngressFastPathProgramWithCaptureScratch(name string, statsMap *cebpf.Map, packetPolicyMap *cebpf.Map, routeMap *cebpf.Map, kernelUDPTXRouteMap *cebpf.Map, kernelUDPTXFlowMap *cebpf.Map, natConfigMap *cebpf.Map, natSourceMap *cebpf.Map, natRouteMap *cebpf.Map, natExcludeMap *cebpf.Map, captureMap *cebpf.Map, captureScratchMap *cebpf.Map, txDirectOptions ...kernelUDPTXDirectProgramOptions) (*cebpf.Program, error) {
	txDirectOption := firstKernelUDPTXDirectProgramOptions(txDirectOptions)
	instructions := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
	}
	instructions = appendHotPathCounter(instructions, statsMap, 0, "ingress_packets_done")
	instructions = append(instructions,
		asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),    // skb->data
		asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word), // skb->data_end
		asm.Mov.Reg(asm.R9, asm.R8),
		asm.Sub.Reg(asm.R9, asm.R7),
		asm.Mov.Reg(asm.R4, asm.R7),
		asm.Add.Imm(asm.R4, 14),
		asm.JGT.Reg(asm.R4, asm.R8, "parse_error"),
		asm.LoadMem(asm.R4, asm.R7, 12, asm.Half),
		asm.JNE.Imm(asm.R4, 0x0008, "non_ipv4"), // ETH_P_IP in packet byte order on little-endian hosts.
	)
	instructions = appendHotPathCounter(instructions, statsMap, 4, "ipv4_packets_done")
	instructions = append(instructions,
		asm.Mov.Reg(asm.R4, asm.R7),
		asm.Add.Imm(asm.R4, 34),
		asm.JGT.Reg(asm.R4, asm.R8, "parse_error"),
	)
	instructions = appendNativeLocalRouteBypass(instructions, statsMap, routeMap, "parse_error", "exit")
	instructions = appendPacketPolicyTCPMSSClamp(instructions, statsMap, packetPolicyMap, "parse_error")
	if txDirectOption.DirectOnly {
		instructions = appendKernelUDPTXDirect(instructions, statsMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, txDirectOption)
		instructions = appendReloadIPv4PacketPointers(instructions, "parse_error")
	} else {
		instructions = appendKernelUDPTXDirect(instructions, statsMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, txDirectOption)
	}
	instructions = appendReloadIPv4PacketPointers(instructions, "parse_error")
	instructions = appendPacketPolicy(instructions, statsMap, packetPolicyMap)
	instructions = append(instructions,
		asm.Mov.Reg(asm.R9, asm.R8),
		asm.Sub.Reg(asm.R9, asm.R7),
		asm.LoadMem(asm.R4, asm.R7, 30, asm.Word), // IPv4 destination address.
		asm.StoreImm(asm.RFP, -16, 32, asm.Word),
		asm.StoreMem(asm.RFP, -12, asm.R4, asm.Word),
		asm.LoadMapPtr(asm.R1, routeMap.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -16),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "route_miss"),
		asm.LoadMem(asm.R4, asm.R0, 0, asm.Word),
		asm.JEq.Imm(asm.R4, routeActionLocal, "local_route"),
		asm.JEq.Imm(asm.R4, routeActionBlackhole, "blackhole_route"),
		asm.JEq.Imm(asm.R4, routeActionReject, "reject_route"),
		asm.Ja.Label("capture_route"),
	)
	instructions = append(instructions, asm.Mov.Reg(asm.R6, asm.R6).WithSymbol("local_route"))
	instructions = append(instructions,
		asm.LoadMem(asm.R4, asm.R0, 8, asm.Word),
		asm.JEq.Imm(asm.R4, 0, "local_route_allow"),
		asm.Mov.Reg(asm.R5, asm.R7),
		asm.Add.Imm(asm.R5, 34),
		asm.JGT.Reg(asm.R5, asm.R8, "parse_error"),
		asm.LoadMem(asm.R5, asm.R7, 23, asm.Byte),
		asm.JNE.Reg(asm.R5, asm.R4, "local_route_capture"),
		asm.LoadMem(asm.R4, asm.R0, 12, asm.Word),
		asm.JEq.Imm(asm.R4, 0, "local_route_allow"),
		asm.LoadMem(asm.R5, asm.R7, 14, asm.Byte),
		asm.And.Imm(asm.R5, 0x0f),
		asm.LSh.Imm(asm.R5, 2),
		asm.Mov.Reg(asm.R3, asm.R7),
		asm.Add.Imm(asm.R3, 14),
		asm.Add.Reg(asm.R3, asm.R5),
		asm.Mov.Reg(asm.R5, asm.R3),
		asm.Add.Imm(asm.R5, 4),
		asm.JGT.Reg(asm.R5, asm.R8, "parse_error"),
		asm.LoadMem(asm.R5, asm.R3, 2, asm.Half),
		asm.JNE.Reg(asm.R5, asm.R4, "local_route_capture"),
	)
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("local_route_allow"))
	instructions = appendCounter(instructions, statsMap, 9, "local_route_done")
	instructions = append(instructions, asm.Ja.Label("exit"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("local_route_capture"))
	instructions = append(instructions, asm.Ja.Label("capture_route"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("blackhole_route"))
	instructions = appendCounter(instructions, statsMap, 2, "blackhole_route_hit_done")
	instructions = appendCounter(instructions, statsMap, 10, "blackhole_route_done")
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, tcActShot),
		asm.Return(),
	)
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("reject_route"))
	instructions = appendCounter(instructions, statsMap, 2, "reject_route_hit_done")
	instructions = appendCounter(instructions, statsMap, 11, "reject_route_done")
	instructions = appendRejectNoReplyDrop(instructions, statsMap)
	instructions = append(instructions,
		asm.StoreImm(asm.RFP, natFlagOffset, 0, asm.Word),
		asm.StoreImm(asm.RFP, natOriginalSourceOffset, 0, asm.Word),
		asm.Ja.Label("capture_packet_ready"),
	)
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("capture_route"))
	instructions = appendHotPathCounter(instructions, statsMap, 2, "route_hit_done")
	instructions = appendTTLExceededFastPath(instructions, statsMap, "ttl_exceeded", "ttl_exceeded_done")
	if txDirectOption.DirectOnly {
		instructions = appendKernelUDPTXDirectOnlyCaptureDrop(instructions, statsMap, kernelUDPTXRouteMap, "direct_only_capture_drop", "capture_packet_ready")
	} else {
		instructions = appendNATOutbound(instructions, statsMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap)
	}
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("capture_packet_ready"))
	instructions = appendCapturePacketReady(instructions, statsMap, routeMap)
	instructions = appendCaptureEvent(instructions, statsMap, captureMap, captureScratchMap)
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, tcActStolen),
		asm.Return(),
	)
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("route_miss"))
	instructions = appendHotPathCounter(instructions, statsMap, 3, "route_miss_done")
	instructions = append(instructions, asm.Ja.Label("yield_exit"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("packet_mtu_drop"))
	instructions = appendCounter(instructions, statsMap, 15, "packet_mtu_drop_done")
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, tcActShot),
		asm.Return(),
	)
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("packet_fragment_drop"))
	instructions = appendCounter(instructions, statsMap, 16, "packet_fragment_drop_done")
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, tcActShot),
		asm.Return(),
	)
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("non_ipv4"))
	instructions = appendHotPathCounter(instructions, statsMap, 5, "non_ipv4_done")
	instructions = append(instructions, asm.Ja.Label("yield_exit"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("parse_error"))
	instructions = appendHotPathCounter(instructions, statsMap, 6, "parse_error_done")
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, tcActUnspec).WithSymbol("yield_exit"),
		asm.Return(),
		asm.Mov.Imm(asm.R0, tcActOK).WithSymbol("exit"),
		asm.Return(),
	)

	debugDumpBPFInstructions(name, instructions)
	program, err := newBPFProgramWithOptions(&cebpf.ProgramSpec{
		Name:         name,
		Type:         cebpf.SchedCLS,
		Instructions: withTCProgramBTFMetadata(instructions),
		License:      "GPL",
	}, cebpf.ProgramOptions{LogLevel: cebpf.LogLevelBranch})
	if err != nil {
		return nil, verboseBPFLoadError(err)
	}
	return program, nil
}

func appendPacketPolicyTCPMSSClamp(instructions asm.Instructions, statsMap *cebpf.Map, packetPolicyMap *cebpf.Map, parseErrorLabel string) asm.Instructions {
	instructions = appendTCPMSSClampCandidateGuard(instructions, "packet_policy_pre_mss_done")
	instructions = append(instructions,
		asm.StoreImm(asm.RFP, packetPolicyKeyOffset, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, packetPolicyMap.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, packetPolicyKeyOffset),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "packet_policy_pre_mss_done"),
	)
	instructions = appendTCPMSSClampWithLabels(instructions, statsMap, "packet_policy_pre_mss", "packet_policy_pre_mss_done", "packet_policy_pre_mss_drop", parseErrorLabel)
	return append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("packet_policy_pre_mss_done"))
}

func appendTCPMSSClampCandidateGuard(instructions asm.Instructions, doneLabel string) asm.Instructions {
	return append(instructions,
		// Avoid a packet-policy map lookup on the data path. MSS clamping only
		// applies to non-fragmented IPv4/TCP SYN packets with a standard IPv4
		// header; all other packets can continue directly to route/direct-TX.
		asm.LoadMem(asm.R1, asm.R7, 14, asm.Byte),
		asm.JNE.Imm(asm.R1, 0x45, doneLabel),
		asm.LoadMem(asm.R1, asm.R7, 23, asm.Byte),
		asm.JNE.Imm(asm.R1, ipProtocolTCP, doneLabel),
		asm.LoadMem(asm.R1, asm.R7, 20, asm.Half),
		asm.JSet.Imm(asm.R1, ipv4FragmentMaskLittleEndian, doneLabel),
		asm.Mov.Reg(asm.R1, asm.R7),
		asm.Add.Imm(asm.R1, rejectEthernetHeaderLen+rejectIPv4HeaderLen+rejectTCPHeaderLen),
		asm.JGT.Reg(asm.R1, asm.R8, doneLabel),
		asm.LoadMem(asm.R1, asm.R7, 47, asm.Byte),
		asm.JSet.Imm(asm.R1, 0x02, "packet_policy_pre_mss_lookup"),
		asm.Ja.Label(doneLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("packet_policy_pre_mss_lookup"),
	)
}

func appendReloadIPv4PacketPointers(instructions asm.Instructions, errorLabel string) asm.Instructions {
	return append(instructions,
		asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
		asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
		asm.Mov.Reg(asm.R4, asm.R7),
		asm.Add.Imm(asm.R4, 34),
		asm.JGT.Reg(asm.R4, asm.R8, errorLabel),
		asm.LoadMem(asm.R4, asm.R7, 12, asm.Half),
		asm.JNE.Imm(asm.R4, 0x0008, errorLabel),
	)
}

func appendNativeLocalRouteBypass(instructions asm.Instructions, statsMap *cebpf.Map, routeMap *cebpf.Map, parseErrorLabel, exitLabel string) asm.Instructions {
	instructions = append(instructions,
		asm.LoadMem(asm.R4, asm.R7, 30, asm.Word), // IPv4 destination address.
		asm.StoreImm(asm.RFP, -16, 32, asm.Word),
		asm.StoreMem(asm.RFP, -12, asm.R4, asm.Word),
		asm.LoadMapPtr(asm.R1, routeMap.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -16),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "native_local_route_bypass_done"),
		asm.LoadMem(asm.R4, asm.R0, 0, asm.Word),
		asm.JNE.Imm(asm.R4, routeActionLocal, "native_local_route_bypass_done"),
		asm.LoadMem(asm.R4, asm.R0, 8, asm.Word),
		asm.JEq.Imm(asm.R4, 0, "native_local_route_bypass_allow"),
		asm.LoadMem(asm.R5, asm.R7, 23, asm.Byte),
		asm.JNE.Reg(asm.R5, asm.R4, "native_local_route_bypass_done"),
		asm.LoadMem(asm.R4, asm.R0, 12, asm.Word),
		asm.JEq.Imm(asm.R4, 0, "native_local_route_bypass_allow"),
		asm.LoadMem(asm.R5, asm.R7, 14, asm.Byte),
		asm.And.Imm(asm.R5, 0x0f),
		asm.LSh.Imm(asm.R5, 2),
		asm.Mov.Reg(asm.R3, asm.R7),
		asm.Add.Imm(asm.R3, 14),
		asm.Add.Reg(asm.R3, asm.R5),
		asm.Mov.Reg(asm.R5, asm.R3),
		asm.Add.Imm(asm.R5, 4),
		asm.JGT.Reg(asm.R5, asm.R8, parseErrorLabel),
		asm.LoadMem(asm.R5, asm.R3, 2, asm.Half),
		asm.JNE.Reg(asm.R5, asm.R4, "native_local_route_bypass_done"),
	)
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("native_local_route_bypass_allow"))
	instructions = appendHotPathCounter(instructions, statsMap, 9, "native_local_route_bypass_local_done")
	return append(instructions,
		asm.Ja.Label(exitLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("native_local_route_bypass_done"),
	)
}

func loadKernelUDPRXDirectProgram(name string, statsMap *cebpf.Map, portMap *cebpf.Map, neighMap *cebpf.Map, lanIfindex int, sourceMAC net.HardwareAddr) (*cebpf.Program, error) {
	return loadKernelUDPRXDirectProgramWithOptions(name, statsMap, portMap, neighMap, lanIfindex, sourceMAC, kernelUDPRXDirectProgramOptions{})
}

type kernelUDPRXDirectProgramOptions struct {
	RedirectPeer          bool
	Broadcast             bool
	RedirectIngress       bool
	BroadcastDestination  [6]byte
	ExperimentalTCPOnly   bool
	KernelUDPOnly         bool
	DirectOnly            bool
	DestinationPortOnly   bool
	StaticDestinationPort uint16
	DecapL2Kfunc          bool
	DecapL2KfuncCall      asm.Instruction
	DecapL2DevKfunc       bool
	DecapL2DevKfuncCall   asm.Instruction
	ParseDecapL2Kfunc     bool
	ParseDecapL2KfuncCall asm.Instruction
	LocalDeliver          bool
	LocalDeliverDev       bool
	LocalDeliverIfindex   int
	LocalIPv4             uint32
	LocalIPv4Mask         uint32
	TrustInnerChecksum    bool
}

type kernelUDPTXDirectProgramOptions struct {
	Enabled                          bool
	ExperimentalTCPOnly              bool
	KernelUDPOnly                    bool
	DirectOnly                       bool
	SkipPlainSequence                bool
	ExperimentalTCPSkipPlainSequence bool
	ExperimentalTCPACKOnly           bool
	RedirectPeer                     bool
	RouteCacheMap                    *cebpf.Map
	SKBClearTXOffload                bool
	SKBClearKfuncCall                asm.Instruction
	InnerTCPKfunc                    bool
	InnerTCPKfuncAuto                bool
	InnerTCPKfuncCall                asm.Instruction
	StoreHeaderKfunc                 bool
	StoreHeaderKfuncCall             asm.Instruction
	BuildUDPHeaderKfunc              bool
	BuildUDPHeaderKfuncCall          asm.Instruction
	FinalizeUDPHeaderKfunc           bool
	FinalizeUDPKfuncCall             asm.Instruction
	PushUDPHeaderKfunc               bool
	PushUDPHeaderKfuncCall           asm.Instruction
	OuterTCPCsumKfunc                bool
	OuterTCPCsumKfuncCall            asm.Instruction
	OuterTCPKfunc                    bool
	OuterTCPKfuncCall                asm.Instruction
	TCPPartialCSUMKfunc              bool
	TCPPartialCSUMKfuncCall          asm.Instruction
	PushTCPHeaderKfunc               bool
	PushTCPHeaderKfuncCall           asm.Instruction
	PushFlowTCPHeaderKfunc           bool
	PushFlowTCPHeaderKfuncCall       asm.Instruction
	FinalizeFlowTCPHeaderKfunc       bool
	FinalizeFlowTCPHeaderKfuncCall   asm.Instruction
	PushRouteTCPHeaderKfunc          bool
	PushRouteTCPHeaderKfuncCall      asm.Instruction
	RouteTCPGSOKfunc                 bool
	RouteTCPGSOKfuncCall             asm.Instruction
	RouteTCPGSOAsyncKfunc            bool
	RouteTCPXmitKfunc                bool
	RouteTCPXmitKfuncCall            asm.Instruction
}

func firstKernelUDPTXDirectProgramOptions(options []kernelUDPTXDirectProgramOptions) kernelUDPTXDirectProgramOptions {
	if len(options) == 0 {
		return kernelUDPTXDirectProgramOptions{}
	}
	return options[0]
}

func newCaptureScratchBPFMap() (*cebpf.Map, error) {
	return cebpf.NewMap(&cebpf.MapSpec{
		Name:       "ix_capture_scratch",
		Type:       cebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  uint32(captureEventHeader + captureSampleLimit),
		MaxEntries: 1,
	})
}

func newCaptureEventBPFMap() (*cebpf.Map, string, error) {
	mode := configuredCaptureOutputMode()
	if mode == captureOutputModePerf {
		m, err := cebpf.NewMap(&cebpf.MapSpec{
			Name:       "ix_capture_events",
			Type:       cebpf.PerfEventArray,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: uint32(runtime.NumCPU()),
		})
		if err != nil {
			return nil, "", fmt.Errorf("create capture perf event BPF map: %w", err)
		}
		return m, mode, nil
	}
	m, err := cebpf.NewMap(&cebpf.MapSpec{
		Name:       "ix_capture_events",
		Type:       cebpf.RingBuf,
		MaxEntries: captureRingbufSize(),
	})
	if err != nil {
		return nil, "", fmt.Errorf("create capture ringbuf BPF map: %w", err)
	}
	return m, captureOutputModeRingbuf, nil
}

func newCaptureReader(captureMap *cebpf.Map) (*perf.Reader, *ringbuf.Reader, error) {
	switch captureMap.Type() {
	case cebpf.PerfEventArray:
		reader, err := perf.NewReader(captureMap, os.Getpagesize()*capturePerfBufferPages())
		if err != nil {
			return nil, nil, fmt.Errorf("create capture perf reader: %w", err)
		}
		return reader, nil, nil
	case cebpf.RingBuf:
		reader, err := ringbuf.NewReader(captureMap)
		if err != nil {
			return nil, nil, fmt.Errorf("create capture ringbuf reader: %w", err)
		}
		return nil, reader, nil
	default:
		return nil, nil, fmt.Errorf("unsupported capture map type %s", captureMap.Type())
	}
}

func closeCaptureReaders(perfReader *perf.Reader, ringReader *ringbuf.Reader) {
	if perfReader != nil {
		_ = perfReader.Close()
	}
	if ringReader != nil {
		_ = ringReader.Close()
	}
}

func captureOutputIsRingbuf(captureMap *cebpf.Map) bool {
	return captureMap != nil && captureMap.Type() == cebpf.RingBuf
}

func loadTCFastPathProgramsWithInnerTCPKfuncFallback(
	statsMap *cebpf.Map,
	packetPolicyMap *cebpf.Map,
	routeMap *cebpf.Map,
	kernelUDPTXRouteMap *cebpf.Map,
	kernelUDPTXFlowMap *cebpf.Map,
	natConfigMap *cebpf.Map,
	natSourceMap *cebpf.Map,
	natRouteMap *cebpf.Map,
	natExcludeMap *cebpf.Map,
	natBindingMap *cebpf.Map,
	captureMap *cebpf.Map,
	captureScratchMap *cebpf.Map,
	txDirectOptions kernelUDPTXDirectProgramOptions,
) (*cebpf.Program, *cebpf.Program, kernelUDPTXDirectProgramOptions, string, error) {
	load := func(options kernelUDPTXDirectProgramOptions) (*cebpf.Program, *cebpf.Program, error) {
		ingressProg, err := loadIngressFastPathProgramWithCaptureScratch(
			"trustix_ingress",
			statsMap,
			packetPolicyMap,
			routeMap,
			kernelUDPTXRouteMap,
			kernelUDPTXFlowMap,
			natConfigMap,
			natSourceMap,
			natRouteMap,
			natExcludeMap,
			captureMap,
			captureScratchMap,
			options,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("load ingress BPF program: %w", err)
		}
		egressTXDirectOptions := options
		egressTXDirectOptions.RedirectPeer = false
		egressProg, err := loadEgressFastPathProgramWithCaptureScratch(
			"trustix_egress",
			statsMap,
			packetPolicyMap,
			routeMap,
			kernelUDPTXRouteMap,
			kernelUDPTXFlowMap,
			natConfigMap,
			natSourceMap,
			natRouteMap,
			natExcludeMap,
			natBindingMap,
			captureMap,
			captureScratchMap,
			egressTXDirectOptions,
		)
		if err != nil {
			_ = ingressProg.Close()
			return nil, nil, fmt.Errorf("load egress BPF program: %w", err)
		}
		return ingressProg, egressProg, nil
	}

	ingressProg, egressProg, err := load(txDirectOptions)
	if err == nil {
		return ingressProg, egressProg, txDirectOptions, "", nil
	}
	if txDirectOptions.FinalizeFlowTCPHeaderKfunc && !experimentalTCPTXDirectFinalizeFlowTCPHeaderKfuncRequired() {
		fallbackOptions := txDirectOptions
		fallbackOptions.FinalizeFlowTCPHeaderKfunc = false
		fallbackOptions.FinalizeFlowTCPHeaderKfuncCall = asm.Instruction{}
		ingressProg, egressProg, fallbackErr := load(fallbackOptions)
		if fallbackErr == nil {
			warning := "experimental_tcp TC TX direct flow TCP header-finalize kfunc disabled after verifier/load rejection: " + err.Error()
			return ingressProg, egressProg, fallbackOptions, warning, nil
		}
	}
	if !txDirectOptions.InnerTCPKfunc || !txDirectOptions.InnerTCPKfuncAuto {
		return nil, nil, txDirectOptions, "", err
	}

	fallbackOptions := txDirectOptions
	fallbackOptions.InnerTCPKfunc = false
	fallbackOptions.InnerTCPKfuncAuto = false
	fallbackOptions.InnerTCPKfuncCall = asm.Instruction{}
	ingressProg, egressProg, fallbackErr := load(fallbackOptions)
	if fallbackErr != nil {
		return nil, nil, txDirectOptions, "", fmt.Errorf("%w; retry without inner TCP checksum kfunc: %v", err, fallbackErr)
	}
	warning := "kernel_udp TC TX direct inner TCP checksum kfunc disabled after verifier/load rejection: " + err.Error()
	return ingressProg, egressProg, fallbackOptions, warning, nil
}

func loadTCFastPathProgramsWithExperimentalTCPRouteKfuncFallback(
	statsMap *cebpf.Map,
	packetPolicyMap *cebpf.Map,
	routeMap *cebpf.Map,
	kernelUDPTXRouteMap *cebpf.Map,
	kernelUDPTXFlowMap *cebpf.Map,
	natConfigMap *cebpf.Map,
	natSourceMap *cebpf.Map,
	natRouteMap *cebpf.Map,
	natExcludeMap *cebpf.Map,
	natBindingMap *cebpf.Map,
	captureMap *cebpf.Map,
	captureScratchMap *cebpf.Map,
	txDirectOptions kernelUDPTXDirectProgramOptions,
) (*cebpf.Program, *cebpf.Program, kernelUDPTXDirectProgramOptions, string, error) {
	load := func(options kernelUDPTXDirectProgramOptions) (*cebpf.Program, *cebpf.Program, kernelUDPTXDirectProgramOptions, string, error) {
		return loadTCFastPathProgramsWithInnerTCPKfuncFallback(
			statsMap,
			packetPolicyMap,
			routeMap,
			kernelUDPTXRouteMap,
			kernelUDPTXFlowMap,
			natConfigMap,
			natSourceMap,
			natRouteMap,
			natExcludeMap,
			natBindingMap,
			captureMap,
			captureScratchMap,
			options,
		)
	}
	appendFallbackWarning := func(message, fallbackWarning string) string {
		if fallbackWarning != "" {
			message += "; " + fallbackWarning
		}
		return message
	}

	ingressProg, egressProg, loadedOptions, warning, err := load(txDirectOptions)
	if err == nil {
		return ingressProg, egressProg, loadedOptions, warning, nil
	}

	loadErr := err
	if txDirectOptions.RouteTCPXmitKfunc {
		if experimentalTCPTXDirectRouteTCPXmitKfuncRequired() {
			return ingressProg, egressProg, loadedOptions, warning, err
		}
		fallbackOptions := txDirectOptions
		fallbackOptions.RouteTCPXmitKfunc = false
		fallbackOptions.RouteTCPXmitKfuncCall = asm.Instruction{}
		ingressProg, egressProg, loadedOptions, fallbackWarning, fallbackErr := load(fallbackOptions)
		if fallbackErr == nil {
			message := "experimental_tcp TC TX direct route TCP xmit kfunc disabled after verifier/load rejection: " + err.Error()
			return ingressProg, egressProg, loadedOptions, appendFallbackWarning(message, fallbackWarning), nil
		}
		loadErr = fmt.Errorf("%w; retry without experimental_tcp route TCP xmit kfunc: %v", loadErr, fallbackErr)
	}

	if txDirectOptions.RouteTCPGSOKfunc {
		if experimentalTCPTXDirectRouteTCPGSOKfuncRequired() {
			return ingressProg, egressProg, loadedOptions, warning, loadErr
		}
		fallbackOptions := txDirectOptions
		fallbackOptions.RouteTCPGSOKfunc = false
		fallbackOptions.RouteTCPGSOKfuncCall = asm.Instruction{}
		fallbackOptions.RouteTCPGSOAsyncKfunc = false
		fallbackOptions.RouteTCPXmitKfunc = false
		fallbackOptions.RouteTCPXmitKfuncCall = asm.Instruction{}
		ingressProg, egressProg, loadedOptions, fallbackWarning, fallbackErr := load(fallbackOptions)
		if fallbackErr == nil {
			message := "experimental_tcp TC TX direct route TCP GSO kfunc disabled after verifier/load rejection: " + loadErr.Error()
			return ingressProg, egressProg, loadedOptions, appendFallbackWarning(message, fallbackWarning), nil
		}
		loadErr = fmt.Errorf("%w; retry without experimental_tcp route TCP GSO kfunc: %v", loadErr, fallbackErr)
	}

	if !txDirectOptions.PushRouteTCPHeaderKfunc || experimentalTCPTXDirectPushRouteTCPHeaderKfuncRequired() {
		return ingressProg, egressProg, loadedOptions, warning, loadErr
	}

	fallbackOptions := txDirectOptions
	fallbackOptions.PushRouteTCPHeaderKfunc = false
	fallbackOptions.PushRouteTCPHeaderKfuncCall = asm.Instruction{}
	fallbackOptions.RouteTCPGSOKfunc = false
	fallbackOptions.RouteTCPGSOKfuncCall = asm.Instruction{}
	fallbackOptions.RouteTCPGSOAsyncKfunc = false
	fallbackOptions.RouteTCPXmitKfunc = false
	fallbackOptions.RouteTCPXmitKfuncCall = asm.Instruction{}
	ingressProg, egressProg, loadedOptions, fallbackWarning, fallbackErr := load(fallbackOptions)
	if fallbackErr != nil {
		return nil, nil, txDirectOptions, "", fmt.Errorf("%w; retry without experimental_tcp route TCP header-push kfunc: %v", loadErr, fallbackErr)
	}
	message := "experimental_tcp TC TX direct route TCP header-push kfunc disabled after verifier/load rejection: " + loadErr.Error()
	return ingressProg, egressProg, loadedOptions, appendFallbackWarning(message, fallbackWarning), nil
}

func loadKernelUDPRXDirectProgramWithOptions(name string, statsMap *cebpf.Map, portMap *cebpf.Map, neighMap *cebpf.Map, lanIfindex int, sourceMAC net.HardwareAddr, options kernelUDPRXDirectProgramOptions) (*cebpf.Program, error) {
	if options.ExperimentalTCPOnly {
		options.KernelUDPOnly = false
	}
	if !options.DecapL2KfuncCall.IsKfuncCall() {
		options.DecapL2Kfunc = false
	}
	if !options.DecapL2DevKfuncCall.IsKfuncCall() {
		options.DecapL2DevKfunc = false
	}
	if !options.ParseDecapL2KfuncCall.IsKfuncCall() ||
		(options.StaticDestinationPort == 0 && !options.ExperimentalTCPOnly) {
		options.ParseDecapL2Kfunc = false
	}
	if lanIfindex <= 0 {
		return nil, fmt.Errorf("invalid LAN ifindex %d", lanIfindex)
	}
	if len(sourceMAC) != 6 {
		return nil, fmt.Errorf("invalid LAN source MAC length %d", len(sourceMAC))
	}
	sourceMAC0 := int64(binary.LittleEndian.Uint16(sourceMAC[0:2]))
	sourceMAC1 := int64(binary.LittleEndian.Uint16(sourceMAC[2:4]))
	sourceMAC2 := int64(binary.LittleEndian.Uint16(sourceMAC[4:6]))
	destinationMAC := options.BroadcastDestination
	if destinationMAC == ([6]byte{}) {
		for i := range destinationMAC {
			destinationMAC[i] = 0xff
		}
	}
	destinationMAC0 := int64(binary.LittleEndian.Uint16(destinationMAC[0:2]))
	destinationMAC1 := int64(binary.LittleEndian.Uint16(destinationMAC[2:4]))
	destinationMAC2 := int64(binary.LittleEndian.Uint16(destinationMAC[4:6]))
	adjustRoomFlags := int64(kernelUDPTCRXAdjustRoomFlagsForOptions(kernelUDPTXDirectProgramOptions{DirectOnly: options.DirectOnly, ExperimentalTCPOnly: options.ExperimentalTCPOnly, KernelUDPOnly: options.KernelUDPOnly}))
	loadOffset := func(offset int32) int16 {
		return int16(offset)
	}
	flowLabel := func(prefix string, outerProtocol uint8, magic uint32) string {
		return fmt.Sprintf("%s_%d_%08x", prefix, outerProtocol, magic)
	}
	commonFrameChecks := func(instructions asm.Instructions, frameOffset int32, outerOverhead int32, l4HeaderLen int32, frameLen int32, payloadOffset int32, payloadLenField int32, portKeyOffset int32, outerProtocol uint8, magic uint32) asm.Instructions {
		innerLenExactLabel := flowLabel("kudp_rx_direct_inner_len_exact", outerProtocol, magic)
		innerLenReadyLabel := flowLabel("kudp_rx_direct_inner_len_ready", outerProtocol, magic)
		outerLenOKLabel := flowLabel("kudp_rx_direct_outer_len_ok", outerProtocol, magic)
		instructions = append(instructions,
			asm.LoadMem(asm.R1, asm.R7, loadOffset(frameOffset+0), asm.Word),
			asm.JNE.Imm(asm.R1, int32(htonl(magic)), "kudp_rx_direct_pass"),
			asm.LoadMem(asm.R1, asm.R7, loadOffset(frameOffset+4), asm.Byte),
			asm.JNE.Imm(asm.R1, 1, "kudp_rx_direct_frame_header_error"),
			asm.LoadMem(asm.R1, asm.R7, loadOffset(frameOffset+5), asm.Byte),
			asm.Mov.Reg(asm.R2, asm.R1),
			asm.And.Imm(asm.R2, int32(kerneludp.FlagInnerIPv4)),
			asm.JNE.Imm(asm.R2, int32(kerneludp.FlagInnerIPv4), "kudp_rx_direct_pass"),
			asm.Mov.Reg(asm.R2, asm.R1),
			asm.And.Imm(asm.R2, int32(kerneludp.FlagEncrypted|kerneludp.FlagCryptoFragment)),
			asm.JNE.Imm(asm.R2, 0, "kudp_rx_direct_pass"),
			asm.Mov.Reg(asm.R2, asm.R1),
			asm.And.Imm(asm.R2, 0xff&^int32(kerneludp.FlagKernelOpened|kerneludp.FlagInnerIPv4)),
			asm.JNE.Imm(asm.R2, 0, "kudp_rx_direct_pass"),
			asm.LoadMem(asm.R1, asm.R7, loadOffset(frameOffset+6), asm.Half),
			asm.JNE.Imm(asm.R1, int32(htons(uint16(frameLen))), "kudp_rx_direct_frame_header_error"),
			asm.LoadMem(asm.R1, asm.R7, loadOffset(frameOffset+frameLen-4), asm.Word),
			asm.JNE.Imm(asm.R1, 0, "kudp_rx_direct_pass"),
			asm.Mov.Reg(asm.R1, asm.R7),
			asm.Add.Imm(asm.R1, payloadOffset+rejectIPv4HeaderLen),
			asm.JGT.Reg(asm.R1, asm.R8, "kudp_rx_direct_inner_len_error"),
			asm.LoadMem(asm.R1, asm.R7, loadOffset(payloadOffset), asm.Byte),
			asm.JNE.Imm(asm.R1, 0x45, "kudp_rx_direct_inner_header_error"),
			asm.LoadMem(asm.R1, asm.R7, loadOffset(payloadLenField), asm.Word),
			asm.HostTo(asm.BE, asm.R1, asm.Word),
			asm.StoreMem(asm.RFP, kernelUDPRXDirectInnerLenOffset, asm.R1, asm.Word),
			asm.JLT.Imm(asm.R1, rejectIPv4HeaderLen, "kudp_rx_direct_inner_len_error"),
			asm.LoadMem(asm.R2, asm.R7, loadOffset(payloadOffset+2), asm.Half),
			asm.HostTo(asm.BE, asm.R2, asm.Half),
			asm.JEq.Reg(asm.R1, asm.R2, innerLenExactLabel),
			asm.LoadMem(asm.R3, asm.R6, skbGSOSizeOffset, asm.Word),
			asm.JEq.Imm(asm.R3, 0, "kudp_rx_direct_inner_len_error"),
			asm.LoadMem(asm.R3, asm.R7, loadOffset(payloadOffset+9), asm.Byte),
			asm.JNE.Imm(asm.R3, ipProtocolTCP, "kudp_rx_direct_inner_len_error"),
			asm.LoadMem(asm.R3, asm.R7, loadOffset(payloadOffset), asm.Byte),
			asm.And.Imm(asm.R3, 0x0f),
			asm.JNE.Imm(asm.R3, 5, "kudp_rx_direct_inner_len_error"),
			asm.Mov.Reg(asm.R3, asm.R7),
			asm.Add.Imm(asm.R3, payloadOffset+rejectIPv4HeaderLen+13),
			asm.JGT.Reg(asm.R3, asm.R8, "kudp_rx_direct_inner_len_error"),
			asm.LoadMem(asm.R3, asm.R7, loadOffset(payloadOffset+rejectIPv4HeaderLen+12), asm.Byte),
			asm.RSh.Imm(asm.R3, 4),
			asm.JLT.Imm(asm.R3, 5, "kudp_rx_direct_inner_len_error"),
			asm.LSh.Imm(asm.R3, 2),
			asm.LoadMem(asm.R4, asm.R6, skbGSOSizeOffset, asm.Word),
			asm.Add.Reg(asm.R4, asm.R3),
			asm.Add.Imm(asm.R4, rejectIPv4HeaderLen),
			asm.StoreMem(asm.RFP, kernelUDPRXDirectSegmentLenOffset, asm.R4, asm.Word),
			asm.LoadMem(asm.R3, asm.RFP, kernelUDPRXDirectInnerLenOffset, asm.Word),
			asm.JGT.Reg(asm.R4, asm.R3, "kudp_rx_direct_inner_len_error"),
			asm.Ja.Label(innerLenReadyLabel),
			asm.StoreMem(asm.RFP, kernelUDPRXDirectSegmentLenOffset, asm.R1, asm.Word).WithSymbol(innerLenExactLabel),
			asm.Mov.Imm(asm.R0, 0).WithSymbol(innerLenReadyLabel),
			asm.LoadMem(asm.R2, asm.RFP, kernelUDPRXDirectSegmentLenOffset, asm.Word),
			asm.Add.Imm(asm.R2, rejectIPv4HeaderLen+l4HeaderLen+frameLen),
			asm.JEq.Reg(asm.R2, asm.R9, outerLenOKLabel),
			asm.LoadMem(asm.R3, asm.R6, skbGSOSizeOffset, asm.Word),
			asm.JEq.Imm(asm.R3, 0, "kudp_rx_direct_outer_len_error"),
			asm.LoadMem(asm.R3, asm.R7, loadOffset(payloadOffset+9), asm.Byte),
			asm.JNE.Imm(asm.R3, ipProtocolTCP, "kudp_rx_direct_outer_len_error"),
			asm.JGT.Reg(asm.R9, asm.R2, "kudp_rx_direct_outer_len_error"),
			asm.LoadMem(asm.R3, asm.RFP, kernelUDPRXDirectInnerLenOffset, asm.Word),
			asm.Mov.Reg(asm.R4, asm.R9),
			asm.Sub.Imm(asm.R4, rejectIPv4HeaderLen+l4HeaderLen+frameLen),
			asm.JGT.Reg(asm.R4, asm.R3, "kudp_rx_direct_outer_len_error"),
			asm.Mov.Imm(asm.R0, 0).WithSymbol(outerLenOKLabel),
			asm.LoadMem(asm.R1, asm.R7, loadOffset(payloadOffset+16), asm.Word),
			asm.StoreMem(asm.RFP, kernelUDPRXDirectNeighKeyOffset, asm.R1, asm.Word),
		)
		if outerProtocol == ipProtocolUDP {
			instructions = append(instructions,
				asm.LoadMem(asm.R1, asm.R7, 38, asm.Half),
				asm.HostTo(asm.BE, asm.R1, asm.Half),
				asm.Mov.Reg(asm.R2, asm.R9),
				asm.Sub.Imm(asm.R2, rejectIPv4HeaderLen),
				asm.JNE.Reg(asm.R1, asm.R2, "kudp_rx_direct_pass"),
			)
		}
		instructions = append(instructions,
			asm.LoadMem(asm.R1, asm.R7, loadOffset(portKeyOffset), asm.Half),
			asm.StoreMem(asm.RFP, kernelUDPRXDirectPortKeyOffset, asm.R1, asm.Word),
			asm.StoreImm(asm.RFP, kernelUDPRXDirectDecapDeltaOffset, -int64(outerOverhead), asm.Word),
		)
		if options.StaticDestinationPort != 0 {
			instructions = append(instructions,
				asm.JEq.Imm(asm.R1, int32(experimentalTCPPortMapKey(options.StaticDestinationPort)), "kudp_rx_direct_candidate"),
			)
		}
		instructions = append(instructions,
			asm.LoadMapPtr(asm.R1, portMap.FD()),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, kernelUDPRXDirectPortKeyOffset),
			asm.FnMapLookupElem.Call(),
			asm.JNE.Imm(asm.R0, 0, "kudp_rx_direct_candidate"),
		)
		if options.DestinationPortOnly {
			instructions = append(instructions,
				asm.Ja.Label("kudp_rx_direct_pass"),
			)
		} else {
			instructions = append(instructions,
				asm.LoadMem(asm.R1, asm.R7, loadOffset(portKeyOffset-2), asm.Half),
				asm.StoreMem(asm.RFP, kernelUDPRXDirectPortKeyOffset, asm.R1, asm.Word),
				asm.LoadMapPtr(asm.R1, portMap.FD()),
				asm.Mov.Reg(asm.R2, asm.RFP),
				asm.Add.Imm(asm.R2, kernelUDPRXDirectPortKeyOffset),
				asm.FnMapLookupElem.Call(),
				asm.JEq.Imm(asm.R0, 0, "kudp_rx_direct_pass"),
				asm.Ja.Label("kudp_rx_direct_candidate"),
			)
		}
		return instructions
	}
	instructions := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),    // skb->data
		asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word), // skb->data_end
	}
	if options.ParseDecapL2Kfunc {
		instructions = appendKernelUDPRXDirectParseDecapL2Candidate(
			instructions,
			statsMap,
			options,
			lanIfindex,
			sourceMAC0,
			sourceMAC1,
			sourceMAC2,
			destinationMAC0,
			destinationMAC1,
			destinationMAC2,
		)
	} else {
		instructions = append(instructions,
			asm.Mov.Reg(asm.R1, asm.R7),
			asm.Add.Imm(asm.R1, rejectEthernetHeaderLen+rejectIPv4HeaderLen+rejectTCPHeaderLen+experimentaltcp.HeaderLen),
			asm.JGT.Reg(asm.R1, asm.R8, "kudp_rx_direct_pass"),
			asm.LoadMem(asm.R1, asm.R7, 12, asm.Half),
			asm.JNE.Imm(asm.R1, 0x0008, "kudp_rx_direct_pass"), // ETH_P_IP
			asm.LoadMem(asm.R1, asm.R7, 14, asm.Byte),
			asm.JNE.Imm(asm.R1, 0x45, "kudp_rx_direct_pass"),
			asm.LoadMem(asm.R1, asm.R7, 20, asm.Half),
			asm.JSet.Imm(asm.R1, ipv4FragmentMaskLittleEndian, "kudp_rx_direct_pass"),
			asm.LoadMem(asm.R9, asm.R7, 16, asm.Half), // Outer IPv4 total length.
			asm.HostTo(asm.BE, asm.R9, asm.Half),
			asm.JLT.Imm(asm.R9, rejectIPv4HeaderLen+8+kerneludp.HeaderLen, "kudp_rx_direct_pass"),
			asm.LoadMem(asm.R1, asm.R6, skbLenOffset, asm.Word),
			asm.Mov.Reg(asm.R2, asm.R9),
			asm.Add.Imm(asm.R2, rejectEthernetHeaderLen),
			// Generic XDP can preserve the pre-open skb length after shrinking the
			// UDP/TIXU payload. Accept a longer skb as long as the IPv4/UDP lengths
			// describe a complete opened kernel_udp frame.
			asm.JLT.Reg(asm.R1, asm.R2, "kudp_rx_direct_pass"),
			asm.LoadMem(asm.R1, asm.R7, 23, asm.Byte),
		)
		if options.KernelUDPOnly {
			instructions = append(instructions,
				asm.JNE.Imm(asm.R1, ipProtocolUDP, "kudp_rx_direct_pass"),
				asm.Ja.Label("kudp_rx_direct_udp"),
			)
		} else if options.ExperimentalTCPOnly {
			instructions = append(instructions,
				asm.JNE.Imm(asm.R1, ipProtocolTCP, "kudp_rx_direct_pass"),
				asm.Ja.Label("kudp_rx_direct_tcp"),
			)
		} else {
			instructions = append(instructions,
				asm.JEq.Imm(asm.R1, ipProtocolUDP, "kudp_rx_direct_udp"),
				asm.JEq.Imm(asm.R1, ipProtocolTCP, "kudp_rx_direct_tcp"),
				asm.Ja.Label("kudp_rx_direct_pass"),
			)
		}
		if !options.ExperimentalTCPOnly {
			instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_rx_direct_udp"))
			instructions = commonFrameChecks(instructions, 42, kernelUDPTXOuterOverhead, 8, kerneludp.HeaderLen, 74, 66, 36, ipProtocolUDP, kerneludp.Magic)
		}
		if !options.KernelUDPOnly {
			instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_rx_direct_tcp"))
			instructions = append(instructions,
				asm.LoadMem(asm.R1, asm.R7, 46, asm.Byte),
				asm.JNE.Imm(asm.R1, 0x50, "kudp_rx_direct_pass"),
			)
			instructions = commonFrameChecks(instructions, 54, experimentalTCPTXOuterOverhead, rejectTCPHeaderLen, experimentaltcp.HeaderLen, 94, 86, 36, ipProtocolTCP, experimentaltcp.Magic)
		}
	}
	instructions = appendKernelUDPRXDirectPortMiss(instructions)
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_rx_direct_candidate"))
	instructions = appendHotPathCounter(instructions, statsMap, kernelUDPRXDirectStatPasses, "kudp_rx_direct_pass_counter_done")
	if options.LocalDeliver && options.LocalIPv4 != 0 {
		instructions = appendKernelUDPRXDirectLocalDeliver(instructions, statsMap, sourceMAC0, sourceMAC1, sourceMAC2, destinationMAC0, destinationMAC1, destinationMAC2, options, adjustRoomFlags)
	}
	if options.Broadcast {
		instructions = appendKernelUDPRXDirectBroadcast(instructions, statsMap, lanIfindex, sourceMAC0, sourceMAC1, sourceMAC2, destinationMAC0, destinationMAC1, destinationMAC2, options.RedirectPeer, options)
		return newBPFProgramWithOptions(&cebpf.ProgramSpec{
			Name:         name,
			Type:         cebpf.SchedCLS,
			Instructions: withTCProgramBTFMetadata(instructions),
			License:      "GPL",
		}, cebpf.ProgramOptions{LogLevel: cebpf.LogLevelBranch})
	}
	instructions = append(instructions,
		asm.LoadMapPtr(asm.R1, neighMap.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, kernelUDPRXDirectNeighKeyOffset),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "kudp_rx_direct_neigh_miss"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.Word),
		asm.StoreMem(asm.RFP, kernelUDPRXDirectIfindexOffset, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R0, 4, asm.Word),
		asm.StoreMem(asm.RFP, kernelUDPRXDirectHeaderOffset, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R0, 8, asm.Half),
		asm.StoreMem(asm.RFP, kernelUDPRXDirectHeaderOffset+4, asm.R1, asm.Half),
		asm.LoadMem(asm.R1, asm.R0, 12, asm.Half),
		asm.StoreMem(asm.RFP, kernelUDPRXDirectHeaderOffset+6, asm.R1, asm.Half),
		asm.LoadMem(asm.R1, asm.R0, 14, asm.Half),
		asm.StoreMem(asm.RFP, kernelUDPRXDirectHeaderOffset+8, asm.R1, asm.Half),
		asm.LoadMem(asm.R1, asm.R0, 16, asm.Half),
		asm.StoreMem(asm.RFP, kernelUDPRXDirectHeaderOffset+10, asm.R1, asm.Half),
		asm.StoreImm(asm.RFP, kernelUDPRXDirectHeaderOffset+12, 0x0008, asm.Half),
	)
	instructions = appendHotPathCounter(instructions, statsMap, kernelUDPRXDirectStatNeighHits, "kudp_rx_direct_neigh_hit_counter_done")
	if !options.ParseDecapL2Kfunc {
		instructions = appendKernelUDPRXDirectDecapL2(instructions, options, adjustRoomFlags, "kudp_rx_direct_adjust_drop", "kudp_rx_direct_store_drop", "_redirect")
	}
	instructions = appendHotPathCounter(instructions, statsMap, kernelUDPRXDirectStatSuccess, "kudp_rx_direct_success_counter_done")
	instructions = append(instructions,
		asm.LoadMem(asm.R1, asm.RFP, kernelUDPRXDirectIfindexOffset, asm.Word),
		asm.Mov.Imm(asm.R2, 0),
	)
	if options.RedirectPeer {
		instructions = append(instructions, asm.FnRedirectPeer.Call())
	} else {
		if options.RedirectIngress {
			instructions = append(instructions, asm.Mov.Imm(asm.R2, bpfFIngress))
		}
		instructions = append(instructions, asm.FnRedirect.Call())
	}
	instructions = append(instructions,
		asm.Return(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_rx_direct_neigh_miss"),
	)
	instructions = appendCounter(instructions, statsMap, kernelUDPRXDirectStatNeighMisses, "kudp_rx_direct_neigh_miss_counter_done")
	instructions = append(instructions, asm.Ja.Label("kudp_rx_direct_pass"))
	instructions = appendKernelUDPRXDirectTerminalBlocks(instructions, statsMap)
	return newBPFProgramWithOptions(&cebpf.ProgramSpec{
		Name:         name,
		Type:         cebpf.SchedCLS,
		Instructions: withTCProgramBTFMetadata(instructions),
		License:      "GPL",
	}, cebpf.ProgramOptions{LogLevel: cebpf.LogLevelBranch})
}

func appendKernelUDPRXDirectParseDecapL2Candidate(instructions asm.Instructions, statsMap *cebpf.Map, options kernelUDPRXDirectProgramOptions, lanIfindex int, sourceMAC0, sourceMAC1, sourceMAC2 int64, destinationMAC0, destinationMAC1, destinationMAC2 int64) asm.Instructions {
	l2Tail1Flags := int64(0x0008)
	decapFlags := int64(0)
	if options.TrustInnerChecksum {
		l2Tail1Flags |= int64(trustIXKUDPRXDecapL2TrustInnerL4CSUM) << 16
		decapFlags = trustIXKUDPRXDecapL2TrustInnerL4CSUM
	}
	localIPv4 := int64(0)
	localIPv4Mask := int64(0)
	localIfindex := int64(0)
	if options.LocalDeliverDev && options.LocalIPv4 != 0 && options.LocalDeliverIfindex > 0 {
		localIPv4 = int64(options.LocalIPv4)
		localIPv4Mask = int64(normalizeKernelUDPRXDirectLocalIPv4Mask(options.LocalIPv4Mask))
		localIfindex = int64(options.LocalDeliverIfindex)
	}
	egressIfindex := int64(0)
	if options.Broadcast && !options.RedirectIngress && lanIfindex > 0 {
		egressIfindex = int64(lanIfindex)
	}
	parseFlags := int64(0)
	if options.ExperimentalTCPOnly {
		parseFlags |= trustIXKUDPRXParseExperimentalTCPOnly
	}
	if options.KernelUDPOnly {
		parseFlags |= trustIXKUDPRXParseKernelUDPOnly
	}
	if kernelUDPRXDirectParseDecapL2PrefilterEnabled() {
		instructions = appendKernelUDPRXDirectParseDecapL2Prefilter(instructions, options)
	}
	parseStaticDestinationPort := options.StaticDestinationPort
	if options.ExperimentalTCPOnly {
		parseStaticDestinationPort = 0
	}
	instructions = append(instructions,
		asm.StoreImm(asm.RFP, kernelUDPRXDirectKfuncParseArgsStaticPortOffset, int64(parseStaticDestinationPort), asm.Word),
		asm.StoreImm(asm.RFP, kernelUDPRXDirectKfuncParseArgsFlagsOffset, parseFlags, asm.Word),
		asm.StoreImm(asm.RFP, kernelUDPRXDirectHeaderOffset, destinationMAC0, asm.Half),
		asm.StoreImm(asm.RFP, kernelUDPRXDirectHeaderOffset+2, destinationMAC1, asm.Half),
		asm.StoreImm(asm.RFP, kernelUDPRXDirectHeaderOffset+4, destinationMAC2, asm.Half),
		asm.StoreImm(asm.RFP, kernelUDPRXDirectHeaderOffset+6, sourceMAC0, asm.Half),
		asm.StoreImm(asm.RFP, kernelUDPRXDirectHeaderOffset+8, sourceMAC1, asm.Half),
		asm.StoreImm(asm.RFP, kernelUDPRXDirectHeaderOffset+10, sourceMAC2, asm.Half),
		asm.StoreImm(asm.RFP, kernelUDPRXDirectHeaderOffset+12, 0x0008, asm.Half),
		asm.LoadMem(asm.R1, asm.RFP, kernelUDPRXDirectHeaderOffset, asm.DWord).WithSymbol("kudp_rx_direct_parse_decap_l2_kfunc"),
		asm.StoreMem(asm.RFP, kernelUDPRXDirectKfuncParseArgsL2HeadOffset, asm.R1, asm.DWord),
		asm.LoadMem(asm.R1, asm.RFP, kernelUDPRXDirectHeaderOffset+8, asm.Word),
		asm.StoreMem(asm.RFP, kernelUDPRXDirectKfuncParseArgsL2Tail0Offset, asm.R1, asm.Word),
		asm.StoreImm(asm.RFP, kernelUDPRXDirectKfuncParseArgsL2Tail1Offset, l2Tail1Flags, asm.Word),
		asm.StoreImm(asm.RFP, kernelUDPRXDirectKfuncParseArgsDecapFlagsOffset, decapFlags, asm.Word),
		asm.StoreImm(asm.RFP, kernelUDPRXDirectKfuncParseArgsLocalIPv4Offset, localIPv4, asm.Word),
		asm.StoreImm(asm.RFP, kernelUDPRXDirectKfuncParseArgsLocalIPv4MaskOffset, localIPv4Mask, asm.Word),
		asm.StoreImm(asm.RFP, kernelUDPRXDirectKfuncParseArgsLocalIfindexOffset, localIfindex, asm.Word),
		asm.StoreImm(asm.RFP, kernelUDPRXDirectKfuncParseArgsEgressIfindexOffset, egressIfindex, asm.Word),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, kernelUDPRXDirectKfuncParseArgsOffset),
		options.ParseDecapL2KfuncCall,
		asm.JEq.Imm(asm.R0, trustIXKUDPRXParseDecapL2LocalDelivered, "kudp_rx_direct_parse_decap_l2_kfunc_local_delivered"),
		asm.JEq.Imm(asm.R0, trustIXKUDPRXParseDecapL2Stolen, "kudp_rx_direct_parse_decap_l2_kfunc_stolen"),
		asm.JEq.Imm(asm.R0, 0, "kudp_rx_direct_parse_decap_l2_kfunc_success"),
		asm.JEq.Imm(asm.R0, -int32(unix.EBADMSG), "kudp_rx_direct_frame_header_error"),
		asm.JEq.Imm(asm.R0, -int32(unix.EMSGSIZE), "kudp_rx_direct_inner_len_error"),
		asm.JEq.Imm(asm.R0, -int32(unix.ENODATA), "kudp_rx_direct_store_drop"),
		asm.JEq.Imm(asm.R0, -int32(unix.EACCES), "kudp_rx_direct_port_miss"),
		asm.JEq.Imm(asm.R0, -int32(unix.EPROTO), "kudp_rx_direct_outer_len_error"),
		asm.JNE.Imm(asm.R0, -int32(unix.EPROTONOSUPPORT), "kudp_rx_direct_error"),
		asm.Ja.Label("kudp_rx_direct_pass"),
		asm.LoadMem(asm.R1, asm.R6, skbCBOffset+trustIXSKBCBRXNextHopOffset, asm.Word).WithSymbol("kudp_rx_direct_parse_decap_l2_kfunc_success"),
		asm.StoreMem(asm.RFP, kernelUDPRXDirectNeighKeyOffset, asm.R1, asm.Word),
		asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
		asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
		asm.Mov.Reg(asm.R1, asm.R7),
		asm.Add.Imm(asm.R1, rejectEthernetHeaderLen),
		asm.JGT.Reg(asm.R1, asm.R8, "kudp_rx_direct_store_drop"),
		asm.Ja.Label("kudp_rx_direct_candidate"),
	)
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_rx_direct_parse_decap_l2_kfunc_local_delivered"))
	instructions = appendHotPathCounter(instructions, statsMap, kernelUDPRXDirectStatPasses, "kudp_rx_direct_parse_decap_l2_local_candidate_counter_done")
	instructions = appendHotPathCounter(instructions, statsMap, kernelUDPRXDirectStatSuccess, "kudp_rx_direct_parse_decap_l2_local_success_counter_done")
	instructions = appendHotPathCounter(instructions, statsMap, kernelUDPRXDirectStatLocalDeliveries, "kudp_rx_direct_parse_decap_l2_local_deliver_counter_done")
	instructions = appendKernelUDPRXDirectReturnLocalDeliver(instructions, options)
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_rx_direct_parse_decap_l2_kfunc_stolen"))
	instructions = appendHotPathCounter(instructions, statsMap, kernelUDPRXDirectStatPasses, "kudp_rx_direct_parse_decap_l2_stolen_candidate_counter_done")
	instructions = appendHotPathCounter(instructions, statsMap, kernelUDPRXDirectStatSuccess, "kudp_rx_direct_parse_decap_l2_stolen_success_counter_done")
	return append(instructions,
		asm.Mov.Imm(asm.R0, tcActShot),
		asm.Return(),
	)
}

func appendKernelUDPRXDirectParseDecapL2Prefilter(instructions asm.Instructions, options kernelUDPRXDirectProgramOptions) asm.Instructions {
	if options.StaticDestinationPort == 0 {
		return instructions
	}
	if options.ExperimentalTCPOnly {
		return instructions
	}
	portKey := int32(experimentalTCPPortMapKey(options.StaticDestinationPort))
	appendCommon := func(instructions asm.Instructions, minLen int32, protocol uint8) asm.Instructions {
		return append(instructions,
			asm.Mov.Reg(asm.R1, asm.R7),
			asm.Add.Imm(asm.R1, minLen),
			asm.JGT.Reg(asm.R1, asm.R8, "kudp_rx_direct_pass"),
			asm.LoadMem(asm.R1, asm.R7, 12, asm.Half),
			asm.JNE.Imm(asm.R1, 0x0008, "kudp_rx_direct_pass"),
			asm.LoadMem(asm.R1, asm.R7, 14, asm.Byte),
			asm.JNE.Imm(asm.R1, 0x45, "kudp_rx_direct_pass"),
			asm.LoadMem(asm.R1, asm.R7, 20, asm.Half),
			asm.JSet.Imm(asm.R1, ipv4FragmentMaskLittleEndian, "kudp_rx_direct_pass"),
			asm.LoadMem(asm.R1, asm.R7, 23, asm.Byte),
			asm.JNE.Imm(asm.R1, int32(protocol), "kudp_rx_direct_pass"),
			asm.LoadMem(asm.R1, asm.R7, 36, asm.Half),
			asm.JNE.Imm(asm.R1, portKey, "kudp_rx_direct_pass"),
		)
	}
	if options.KernelUDPOnly {
		return append(appendCommon(instructions, rejectEthernetHeaderLen+rejectIPv4HeaderLen+8+kerneludp.HeaderLen+rejectIPv4HeaderLen, ipProtocolUDP),
			asm.LoadMem(asm.R1, asm.R7, 42, asm.Word),
			asm.JNE.Imm(asm.R1, int32(htonl(kerneludp.Magic)), "kudp_rx_direct_pass"),
			asm.LoadMem(asm.R1, asm.R7, 46, asm.Byte),
			asm.JNE.Imm(asm.R1, int32(kerneludp.Version), "kudp_rx_direct_pass"),
			asm.LoadMem(asm.R1, asm.R7, 48, asm.Half),
			asm.JNE.Imm(asm.R1, int32(htons(uint16(kerneludp.HeaderLen))), "kudp_rx_direct_pass"),
		)
	}
	if options.ExperimentalTCPOnly {
		return append(appendCommon(instructions, rejectEthernetHeaderLen+rejectIPv4HeaderLen+rejectTCPHeaderLen+experimentaltcp.HeaderLen+rejectIPv4HeaderLen, ipProtocolTCP),
			asm.LoadMem(asm.R1, asm.R7, 46, asm.Byte),
			asm.JNE.Imm(asm.R1, 0x50, "kudp_rx_direct_pass"),
			asm.LoadMem(asm.R1, asm.R7, 54, asm.Word),
			asm.JNE.Imm(asm.R1, int32(htonl(experimentaltcp.Magic)), "kudp_rx_direct_pass"),
			asm.LoadMem(asm.R1, asm.R7, 58, asm.Byte),
			asm.JNE.Imm(asm.R1, int32(experimentaltcp.Version), "kudp_rx_direct_pass"),
			asm.LoadMem(asm.R1, asm.R7, 60, asm.Half),
			asm.JNE.Imm(asm.R1, int32(htons(uint16(experimentaltcp.HeaderLen))), "kudp_rx_direct_pass"),
		)
	}
	return instructions
}

func appendKernelUDPRXDirectLocalDeliver(instructions asm.Instructions, statsMap *cebpf.Map, sourceMAC0, sourceMAC1, sourceMAC2 int64, destinationMAC0, destinationMAC1, destinationMAC2 int64, options kernelUDPRXDirectProgramOptions, adjustRoomFlags int64) asm.Instructions {
	return appendKernelUDPRXDirectLocalDeliverWithLabels(instructions, statsMap, sourceMAC0, sourceMAC1, sourceMAC2, destinationMAC0, destinationMAC1, destinationMAC2, options, adjustRoomFlags, "kudp_rx_direct_local_deliver_miss", "kudp_rx_direct_adjust_drop", "kudp_rx_direct_store_drop")
}

func appendKernelUDPRXDirectLocalDeliverMatch(instructions asm.Instructions, options kernelUDPRXDirectProgramOptions, missLabel string) asm.Instructions {
	mask := normalizeKernelUDPRXDirectLocalIPv4Mask(options.LocalIPv4Mask)
	if mask == 0xffffffff {
		return append(instructions,
			asm.LoadMem(asm.R1, asm.RFP, kernelUDPRXDirectNeighKeyOffset, asm.Word),
			asm.JNE.Imm(asm.R1, int32(options.LocalIPv4), missLabel),
		)
	}
	return append(instructions,
		asm.LoadMem(asm.R1, asm.RFP, kernelUDPRXDirectNeighKeyOffset, asm.Word),
		asm.Xor.Imm32(asm.R1, int32(options.LocalIPv4)),
		asm.And.Imm32(asm.R1, int32(mask)),
		asm.JNE.Imm(asm.R1, 0, missLabel),
	)
}

func appendKernelUDPRXDirectLocalDeliverWithLabels(instructions asm.Instructions, statsMap *cebpf.Map, sourceMAC0, sourceMAC1, sourceMAC2 int64, destinationMAC0, destinationMAC1, destinationMAC2 int64, options kernelUDPRXDirectProgramOptions, adjustRoomFlags int64, missLabel string, adjustDropLabel string, storeDropLabel string) asm.Instructions {
	instructions = appendKernelUDPRXDirectLocalDeliverMatch(instructions, options, missLabel)
	if !options.ParseDecapL2Kfunc {
		instructions = append(instructions,
			asm.StoreImm(asm.RFP, kernelUDPRXDirectHeaderOffset, destinationMAC0, asm.Half),
			asm.StoreImm(asm.RFP, kernelUDPRXDirectHeaderOffset+2, destinationMAC1, asm.Half),
			asm.StoreImm(asm.RFP, kernelUDPRXDirectHeaderOffset+4, destinationMAC2, asm.Half),
			asm.StoreImm(asm.RFP, kernelUDPRXDirectHeaderOffset+6, sourceMAC0, asm.Half),
			asm.StoreImm(asm.RFP, kernelUDPRXDirectHeaderOffset+8, sourceMAC1, asm.Half),
			asm.StoreImm(asm.RFP, kernelUDPRXDirectHeaderOffset+10, sourceMAC2, asm.Half),
			asm.StoreImm(asm.RFP, kernelUDPRXDirectHeaderOffset+12, 0x0008, asm.Half),
		)
		if options.LocalDeliverDev && options.DecapL2DevKfunc && options.DecapL2DevKfuncCall.IsKfuncCall() && options.LocalDeliverIfindex > 0 {
			instructions = appendKernelUDPRXDirectDecapL2DevKfunc(instructions, options, adjustDropLabel, storeDropLabel, "_local")
		} else {
			instructions = appendKernelUDPRXDirectDecapL2(instructions, options, adjustRoomFlags, adjustDropLabel, storeDropLabel, "_local")
		}
	}
	instructions = appendHotPathCounter(instructions, statsMap, kernelUDPRXDirectStatSuccess, "kudp_rx_direct_success_local_deliver_counter_done")
	instructions = appendHotPathCounter(instructions, statsMap, kernelUDPRXDirectStatLocalDeliveries, "kudp_rx_direct_local_deliver_counter_done")
	instructions = appendKernelUDPRXDirectReturnLocalDeliver(instructions, options)
	return append(instructions,
		asm.Mov.Imm(asm.R0, 0).WithSymbol(missLabel),
	)
}

func appendKernelUDPRXDirectReturnLocalDeliver(instructions asm.Instructions, options kernelUDPRXDirectProgramOptions) asm.Instructions {
	if options.LocalDeliverIfindex <= 0 {
		return append(instructions,
			asm.Mov.Imm(asm.R0, tcActOK),
			asm.Return(),
		)
	}
	instructions = append(instructions,
		asm.Mov.Imm(asm.R1, int32(options.LocalDeliverIfindex)),
	)
	if options.RedirectIngress {
		instructions = append(instructions, asm.Mov.Imm(asm.R2, bpfFIngress))
	} else {
		instructions = append(instructions, asm.Mov.Imm(asm.R2, 0))
	}
	return append(instructions,
		asm.FnRedirect.Call(),
		asm.Return(),
	)
}

func appendKernelUDPRXDirectDecapL2DevKfunc(instructions asm.Instructions, options kernelUDPRXDirectProgramOptions, adjustDropLabel string, storeDropLabel string, symbolSuffix string) asm.Instructions {
	flags := int64(0)
	if options.TrustInnerChecksum {
		flags = trustIXKUDPRXDecapL2TrustInnerL4CSUM
	}
	doneLabel := "kudp_rx_direct_decap_l2_dev_kfunc_done" + symbolSuffix
	return append(instructions,
		asm.LoadMem(asm.R1, asm.RFP, kernelUDPRXDirectDecapDeltaOffset, asm.Word),
		asm.Mov.Imm(asm.R2, 0),
		asm.Sub.Reg(asm.R2, asm.R1),
		asm.StoreMem(asm.RFP, kernelUDPRXDirectKfuncDevArgsOffset, asm.R2, asm.Word),
		asm.StoreImm(asm.RFP, kernelUDPRXDirectKfuncDevArgsOffset+4, int64(options.LocalDeliverIfindex), asm.Word),
		asm.LoadMem(asm.R1, asm.RFP, kernelUDPRXDirectHeaderOffset, asm.DWord),
		asm.StoreMem(asm.RFP, kernelUDPRXDirectKfuncDevArgsOffset+8, asm.R1, asm.DWord),
		asm.LoadMem(asm.R1, asm.RFP, kernelUDPRXDirectHeaderOffset+8, asm.Word),
		asm.StoreMem(asm.RFP, kernelUDPRXDirectKfuncDevArgsOffset+16, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.RFP, kernelUDPRXDirectHeaderOffset+12, asm.Half),
		asm.StoreMem(asm.RFP, kernelUDPRXDirectKfuncDevArgsOffset+20, asm.R1, asm.Word),
		asm.StoreImm(asm.RFP, kernelUDPRXDirectKfuncDevArgsOffset+24, flags, asm.Word),
		asm.StoreImm(asm.RFP, kernelUDPRXDirectKfuncDevArgsOffset+28, 0, asm.Word),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, kernelUDPRXDirectKfuncDevArgsOffset),
		options.DecapL2DevKfuncCall,
		asm.JNE.Imm(asm.R0, 0, adjustDropLabel),
		asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
		asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
		asm.Mov.Reg(asm.R1, asm.R7),
		asm.Add.Imm(asm.R1, rejectEthernetHeaderLen),
		asm.JGT.Reg(asm.R1, asm.R8, storeDropLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol(doneLabel),
	)
}

func appendKernelUDPRXDirectBroadcast(instructions asm.Instructions, statsMap *cebpf.Map, lanIfindex int, sourceMAC0, sourceMAC1, sourceMAC2 int64, destinationMAC0, destinationMAC1, destinationMAC2 int64, redirectPeer bool, options kernelUDPRXDirectProgramOptions) asm.Instructions {
	adjustRoomFlags := int64(kernelUDPTCRXAdjustRoomFlagsForOptions(kernelUDPTXDirectProgramOptions{DirectOnly: options.DirectOnly, ExperimentalTCPOnly: options.ExperimentalTCPOnly, KernelUDPOnly: options.KernelUDPOnly}))
	if !options.ParseDecapL2Kfunc {
		instructions = append(instructions,
			asm.StoreImm(asm.RFP, kernelUDPRXDirectHeaderOffset, destinationMAC0, asm.Half),
			asm.StoreImm(asm.RFP, kernelUDPRXDirectHeaderOffset+2, destinationMAC1, asm.Half),
			asm.StoreImm(asm.RFP, kernelUDPRXDirectHeaderOffset+4, destinationMAC2, asm.Half),
			asm.StoreImm(asm.RFP, kernelUDPRXDirectHeaderOffset+6, sourceMAC0, asm.Half),
			asm.StoreImm(asm.RFP, kernelUDPRXDirectHeaderOffset+8, sourceMAC1, asm.Half),
			asm.StoreImm(asm.RFP, kernelUDPRXDirectHeaderOffset+10, sourceMAC2, asm.Half),
			asm.StoreImm(asm.RFP, kernelUDPRXDirectHeaderOffset+12, 0x0008, asm.Half),
		)
		instructions = appendKernelUDPRXDirectDecapL2(instructions, options, adjustRoomFlags, "kudp_rx_direct_adjust_drop", "kudp_rx_direct_store_drop", "_broadcast")
	}
	instructions = appendHotPathCounter(instructions, statsMap, kernelUDPRXDirectStatSuccess, "kudp_rx_direct_success_broadcast_counter_done")
	instructions = append(instructions,
		asm.Mov.Imm(asm.R1, int32(lanIfindex)),
		asm.Mov.Imm(asm.R2, 0),
	)
	if redirectPeer {
		instructions = append(instructions, asm.FnRedirectPeer.Call())
	} else {
		if options.RedirectIngress {
			instructions = append(instructions, asm.Mov.Imm(asm.R2, bpfFIngress))
		}
		instructions = append(instructions, asm.FnRedirect.Call())
	}
	instructions = append(instructions,
		asm.Return(),
	)
	return appendKernelUDPRXDirectTerminalBlocks(instructions, statsMap)
}

func appendKernelUDPRXDirectPortMiss(instructions asm.Instructions) asm.Instructions {
	if !instructionsContainSymbolOrReference(instructions, "kudp_rx_direct_port_miss") {
		return instructions
	}
	return append(instructions,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_rx_direct_port_miss"),
		asm.Ja.Label("kudp_rx_direct_pass"),
	)
}

func appendKernelUDPRXDirectTerminalBlocks(instructions asm.Instructions, statsMap *cebpf.Map) asm.Instructions {
	needError := instructionsContainSymbolOrReference(instructions, "kudp_rx_direct_error")
	appendErrorBlock := func(label string, counter uint32) {
		if !instructionsContainSymbolOrReference(instructions, label) {
			return
		}
		instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol(label))
		instructions = appendCounter(instructions, statsMap, counter, label+"_counter_done")
		instructions = append(instructions, asm.Ja.Label("kudp_rx_direct_error"))
		needError = true
	}
	appendErrorBlock("kudp_rx_direct_frame_header_error", kernelUDPRXDirectStatFrameHeaderErrors)
	appendErrorBlock("kudp_rx_direct_inner_header_error", kernelUDPRXDirectStatInnerHeaderErrors)
	appendErrorBlock("kudp_rx_direct_inner_len_error", kernelUDPRXDirectStatInnerLenErrors)
	appendErrorBlock("kudp_rx_direct_outer_len_error", kernelUDPRXDirectStatOuterLenErrors)
	if needError {
		instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_rx_direct_error"))
		instructions = appendCounter(instructions, statsMap, kernelUDPRXDirectStatErrors, "kudp_rx_direct_error_counter_done")
		instructions = append(instructions, asm.Ja.Label("kudp_rx_direct_pass"))
	}

	needDrop := instructionsContainSymbolOrReference(instructions, "kudp_rx_direct_drop")
	appendDropBlock := func(label string, counter uint32) {
		if !instructionsContainSymbolOrReference(instructions, label) {
			return
		}
		instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol(label))
		instructions = appendCounter(instructions, statsMap, counter, label+"_counter_done")
		instructions = append(instructions, asm.Ja.Label("kudp_rx_direct_drop"))
		needDrop = true
	}
	appendDropBlock("kudp_rx_direct_adjust_drop", kernelUDPRXDirectStatAdjustDrops)
	appendDropBlock("kudp_rx_direct_store_drop", kernelUDPRXDirectStatStoreDrops)
	if needDrop {
		instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_rx_direct_drop"))
		instructions = appendCounter(instructions, statsMap, kernelUDPRXDirectStatDrops, "kudp_rx_direct_drop_counter_done")
		instructions = append(instructions,
			asm.Mov.Imm(asm.R0, tcActShot),
			asm.Return(),
		)
	}
	if instructionsContainSymbolOrReference(instructions, "kudp_rx_direct_pass") {
		instructions = append(instructions,
			asm.Mov.Imm(asm.R0, tcActUnspec).WithSymbol("kudp_rx_direct_pass"),
			asm.Return(),
		)
	}
	return instructions
}

func appendKernelUDPRXDirectDecapL2(instructions asm.Instructions, options kernelUDPRXDirectProgramOptions, adjustRoomFlags int64, adjustDropLabel string, storeDropLabel string, symbolSuffix string) asm.Instructions {
	if options.DecapL2Kfunc && options.DecapL2KfuncCall.IsKfuncCall() {
		l2Tail1Flags := int32(0)
		if options.TrustInnerChecksum {
			l2Tail1Flags = trustIXKUDPRXDecapL2TrustInnerL4CSUM << 16
		}
		startLabel := "kudp_rx_direct_decap_l2_kfunc" + symbolSuffix
		doneLabel := "kudp_rx_direct_decap_l2_kfunc_done" + symbolSuffix
		instructions = append(instructions,
			asm.LoadMem(asm.R1, asm.RFP, kernelUDPRXDirectHeaderOffset, asm.DWord).WithSymbol(startLabel),
			asm.StoreMem(asm.RFP, kernelUDPRXDirectKfuncL2HeadOffset, asm.R1, asm.DWord),
			asm.LoadMem(asm.R1, asm.RFP, kernelUDPRXDirectHeaderOffset+8, asm.Word),
			asm.StoreMem(asm.RFP, kernelUDPRXDirectKfuncL2Tail0Offset, asm.R1, asm.Word),
			asm.LoadMem(asm.R1, asm.RFP, kernelUDPRXDirectHeaderOffset+12, asm.Half),
			asm.Or.Imm(asm.R1, l2Tail1Flags),
			asm.StoreMem(asm.RFP, kernelUDPRXDirectKfuncL2Tail1Offset, asm.R1, asm.Word),
			asm.Mov.Reg(asm.R1, asm.R6),
			asm.LoadMem(asm.R2, asm.RFP, kernelUDPRXDirectDecapDeltaOffset, asm.Word),
			asm.Mov.Imm(asm.R3, 0),
			asm.Sub.Reg(asm.R3, asm.R2),
			asm.Mov.Reg(asm.R2, asm.R3),
			asm.LoadMem(asm.R3, asm.RFP, kernelUDPRXDirectKfuncL2HeadOffset, asm.DWord),
			asm.LoadMem(asm.R4, asm.RFP, kernelUDPRXDirectKfuncL2Tail0Offset, asm.Word),
			asm.LoadMem(asm.R5, asm.RFP, kernelUDPRXDirectKfuncL2Tail1Offset, asm.Word),
			options.DecapL2KfuncCall,
			asm.JNE.Imm(asm.R0, 0, adjustDropLabel),
			asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
			asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
			asm.Mov.Reg(asm.R1, asm.R7),
			asm.Add.Imm(asm.R1, rejectEthernetHeaderLen),
			asm.JGT.Reg(asm.R1, asm.R8, storeDropLabel),
			asm.Mov.Imm(asm.R0, 0).WithSymbol(doneLabel),
		)
		return instructions
	}
	instructions = append(instructions,
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.LoadMem(asm.R2, asm.RFP, kernelUDPRXDirectDecapDeltaOffset, asm.Word),
		asm.Mov.Imm(asm.R3, bpfAdjRoomMAC),
		asm.LoadImm(asm.R4, adjustRoomFlags, asm.DWord),
		asm.FnSkbAdjustRoom.Call(),
		asm.JNE.Imm(asm.R0, 0, adjustDropLabel),
		asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
		asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
		asm.Mov.Reg(asm.R1, asm.R7),
		asm.Add.Imm(asm.R1, rejectEthernetHeaderLen),
		asm.JGT.Reg(asm.R1, asm.R8, storeDropLabel),
	)
	return appendStackToPacketStores(instructions, kernelUDPRXDirectHeaderOffset, 0, rejectEthernetHeaderLen)
}

func appendPacketPolicy(instructions asm.Instructions, statsMap *cebpf.Map, packetPolicyMap *cebpf.Map) asm.Instructions {
	instructions = append(instructions,
		asm.StoreImm(asm.RFP, packetPolicyKeyOffset, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, packetPolicyMap.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, packetPolicyKeyOffset),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "packet_policy_done"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.Word), // configured L3 MTU, 0 disables the check.
		asm.JEq.Imm(asm.R1, 0, "packet_policy_fragment_check"),
		asm.LoadMem(asm.R2, asm.R7, 16, asm.Half), // IPv4 total length at Ethernet + 2.
		asm.And.Imm(asm.R2, 0xffff),
		asm.HostTo(asm.BE, asm.R2, asm.Half),
		// TCP skbs may reach TC before software/GSO segmentation. Do not drop
		// them here; userspace validates and segments oversized TCP payloads
		// before sending them over datagram transports.
		asm.LoadMem(asm.R3, asm.R7, 23, asm.Byte),
		asm.JEq.Imm(asm.R3, ipProtocolTCP, "packet_policy_fragment_check"),
		asm.LoadMem(asm.R3, asm.R6, skbGSOSizeOffset, asm.Word),
		asm.JEq.Imm(asm.R3, 0, "packet_policy_mtu_check"),
		asm.LoadMem(asm.R4, asm.R7, 23, asm.Byte),
		asm.JNE.Imm(asm.R4, ipProtocolTCP, "packet_policy_mtu_check"),
		asm.LoadMem(asm.R4, asm.R7, 14, asm.Byte),
		asm.And.Imm(asm.R4, 0x0f),
		asm.JNE.Imm(asm.R4, 5, "packet_policy_mtu_check"),
		asm.Mov.Reg(asm.R4, asm.R7),
		asm.Add.Imm(asm.R4, rejectEthernetHeaderLen+rejectIPv4HeaderLen+13),
		asm.JGT.Reg(asm.R4, asm.R8, "packet_policy_mtu_check"),
		asm.LoadMem(asm.R4, asm.R7, rejectEthernetHeaderLen+rejectIPv4HeaderLen+12, asm.Byte),
		asm.RSh.Imm(asm.R4, 4),
		asm.JLT.Imm(asm.R4, 5, "packet_policy_mtu_check"),
		asm.LSh.Imm(asm.R4, 2),
		asm.Add.Reg(asm.R3, asm.R4),
		asm.Add.Imm(asm.R3, rejectIPv4HeaderLen),
		asm.Mov.Reg(asm.R2, asm.R3),
		asm.JGT.Reg(asm.R2, asm.R1, "packet_mtu_drop").WithSymbol("packet_policy_mtu_check"),
		asm.LoadMem(asm.R1, asm.R0, 4, asm.Word).WithSymbol("packet_policy_fragment_check"),
		asm.JEq.Imm(asm.R1, 0, "packet_policy_done"),
		asm.LoadMem(asm.R2, asm.R7, 20, asm.Half), // IPv4 flags/fragment offset.
		asm.JSet.Imm(asm.R2, ipv4FragmentMaskLittleEndian, "packet_fragment_drop"),
	)
	return append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("packet_policy_done"))
}

func appendTCPMSSClamp(instructions asm.Instructions, statsMap *cebpf.Map) asm.Instructions {
	return appendTCPMSSClampWithLabels(instructions, statsMap, "packet_policy_mss", "packet_policy_done", "packet_policy_mss_drop", "parse_error")
}

func appendTCPMSSClampWithLabels(instructions asm.Instructions, statsMap *cebpf.Map, prefix string, doneLabel string, _ string, parseErrorLabel string) asm.Instructions {
	synLabel := prefix + "_syn"
	instructions = append(instructions,
		asm.LoadMem(asm.R1, asm.R0, 8, asm.Word),
		asm.JEq.Imm(asm.R1, 0, doneLabel),
		asm.JGT.Imm(asm.R1, 0xffff, doneLabel),
		asm.StoreMem(asm.RFP, packetPolicyMSSClampHostOffset, asm.R1, asm.Word),

		// Keep the direct path from fragmenting TCP streams by lowering SYN MSS
		// before either TC direct-TX or userspace capture sees the packet.
		asm.LoadMem(asm.R1, asm.R7, 14, asm.Byte),
		asm.JNE.Imm(asm.R1, 0x45, doneLabel),
		asm.LoadMem(asm.R1, asm.R7, 23, asm.Byte),
		asm.JNE.Imm(asm.R1, ipProtocolTCP, doneLabel),
		asm.LoadMem(asm.R1, asm.R7, 20, asm.Half),
		asm.JSet.Imm(asm.R1, ipv4FragmentMaskLittleEndian, doneLabel),
		asm.Mov.Reg(asm.R1, asm.R7),
		asm.Add.Imm(asm.R1, rejectEthernetHeaderLen+rejectIPv4HeaderLen+rejectTCPHeaderLen),
		asm.JGT.Reg(asm.R1, asm.R8, doneLabel),
		asm.LoadMem(asm.R1, asm.R7, 47, asm.Byte), // TCP flags.
		asm.JSet.Imm(asm.R1, 0x02, synLabel),
		asm.Ja.Label(doneLabel),
		asm.LoadMem(asm.R3, asm.R7, 46, asm.Byte).WithSymbol(synLabel), // TCP data offset/reserved.
		asm.RSh.Imm(asm.R3, 4),
		asm.JLE.Imm(asm.R3, 5, doneLabel),
		asm.LSh.Imm(asm.R3, 2),
		asm.Mov.Reg(asm.R5, asm.R7),
		asm.Add.Imm(asm.R5, rejectEthernetHeaderLen+rejectIPv4HeaderLen),
		asm.Add.Reg(asm.R5, asm.R3), // TCP header end.
		asm.JGT.Reg(asm.R5, asm.R8, doneLabel),
		asm.Mov.Reg(asm.R4, asm.R7),
		asm.Add.Imm(asm.R4, rejectEthernetHeaderLen+rejectIPv4HeaderLen+rejectTCPHeaderLen), // first TCP option.
	)
	for i := 0; i < 10; i++ {
		next := fmt.Sprintf("%s_scan_%d", prefix, i+1)
		nop := fmt.Sprintf("%s_scan_%d_nop", prefix, i)
		advance := fmt.Sprintf("%s_scan_%d_advance", prefix, i)
		if i == 9 {
			next = doneLabel
		}
		instructions = append(instructions,
			asm.Mov.Reg(asm.R1, asm.R4),
			asm.Add.Imm(asm.R1, 1),
			asm.JGT.Reg(asm.R1, asm.R5, doneLabel),
			asm.JGT.Reg(asm.R1, asm.R8, doneLabel),
			asm.LoadMem(asm.R1, asm.R4, 0, asm.Byte), // TCP option kind.
			asm.JEq.Imm(asm.R1, 0, doneLabel),
			asm.JEq.Imm(asm.R1, 1, nop),
			asm.Mov.Reg(asm.R2, asm.R4),
			asm.Add.Imm(asm.R2, 2),
			asm.JGT.Reg(asm.R2, asm.R5, doneLabel),
			asm.JGT.Reg(asm.R2, asm.R8, doneLabel),
			asm.LoadMem(asm.R2, asm.R4, 1, asm.Byte), // TCP option length.
			asm.JLT.Imm(asm.R2, 2, doneLabel),
			asm.JNE.Imm(asm.R1, 2, advance),
			asm.JNE.Imm(asm.R2, 4, advance),
			asm.Mov.Reg(asm.R3, asm.R4),
			asm.Add.Imm(asm.R3, 4),
			asm.JGT.Reg(asm.R3, asm.R5, doneLabel),
			asm.JGT.Reg(asm.R3, asm.R8, doneLabel),
			asm.LoadMem(asm.R3, asm.R4, 2, asm.Half), // MSS in packet byte order.
			asm.Mov.Reg(asm.R1, asm.R3),
			asm.HostTo(asm.BE, asm.R1, asm.Half),
			asm.LoadMem(asm.R2, asm.RFP, packetPolicyMSSClampHostOffset, asm.Word),
			asm.JLE.Reg(asm.R1, asm.R2, doneLabel),
			asm.StoreMem(asm.RFP, packetPolicyMSSClampOldOffset, asm.R1, asm.Half),
			asm.Mov.Reg(asm.R1, asm.R2),
			asm.StoreMem(asm.RFP, packetPolicyMSSClampNewOffset, asm.R1, asm.Half),
			asm.HostTo(asm.BE, asm.R1, asm.Half),
			asm.StoreMem(asm.R4, 2, asm.R1, asm.Half),

			// bpf_l4_csum_replace leaves this TC path sensitive to helper byte
			// order semantics across kernels. Update the TCP checksum in place
			// with RFC 1624 one's-complement delta math instead.
			asm.LoadMem(asm.R0, asm.R7, rejectEthernetHeaderLen+rejectIPv4HeaderLen+16, asm.Half),
			asm.HostTo(asm.BE, asm.R0, asm.Half),
			asm.Xor.Imm(asm.R0, 0xffff),
			asm.And.Imm(asm.R0, 0xffff),
			asm.LoadMem(asm.R1, asm.RFP, packetPolicyMSSClampOldOffset, asm.Half),
			asm.Xor.Imm(asm.R1, 0xffff),
			asm.And.Imm(asm.R1, 0xffff),
			asm.Add.Reg32(asm.R0, asm.R1),
			asm.LoadMem(asm.R1, asm.RFP, packetPolicyMSSClampNewOffset, asm.Half),
			asm.Add.Reg32(asm.R0, asm.R1),
		)
		instructions = appendChecksumFold(instructions)
		instructions = append(instructions,
			asm.HostTo(asm.BE, asm.R0, asm.Half),
			asm.StoreMem(asm.R7, rejectEthernetHeaderLen+rejectIPv4HeaderLen+16, asm.R0, asm.Half),
		)
		instructions = appendCounter(instructions, statsMap, packetPolicyTCPMSSClampStatSuccess, fmt.Sprintf("packet_policy_mss_success_%d_done", i))
		instructions = append(instructions,
			asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
			asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
			asm.Mov.Reg(asm.R1, asm.R7),
			asm.Add.Imm(asm.R1, rejectEthernetHeaderLen+rejectIPv4HeaderLen),
			asm.JGT.Reg(asm.R1, asm.R8, parseErrorLabel),
			asm.Mov.Reg(asm.R9, asm.R8),
			asm.Sub.Reg(asm.R9, asm.R7),
			asm.Ja.Label(doneLabel),
			asm.Add.Imm(asm.R4, 1).WithSymbol(nop),
			asm.Ja.Label(next),
			asm.Add.Reg(asm.R4, asm.R2).WithSymbol(advance),
			asm.Ja.Label(next),
		)
		if i < 9 {
			instructions = append(instructions, asm.Mov.Reg(asm.R4, asm.R4).WithSymbol(next))
		}
	}
	return instructions
}

func appendKernelUDPTXDirect(instructions asm.Instructions, statsMap *cebpf.Map, routeMap *cebpf.Map, flowMap *cebpf.Map, options ...kernelUDPTXDirectProgramOptions) asm.Instructions {
	opts := firstKernelUDPTXDirectProgramOptions(options)
	if !opts.Enabled {
		return instructions
	}
	if opts.ExperimentalTCPOnly {
		opts.KernelUDPOnly = false
	}
	if !opts.StoreHeaderKfuncCall.IsKfuncCall() {
		opts.StoreHeaderKfunc = false
	}
	if !opts.BuildUDPHeaderKfuncCall.IsKfuncCall() {
		opts.BuildUDPHeaderKfunc = false
	}
	if !opts.FinalizeUDPKfuncCall.IsKfuncCall() {
		opts.FinalizeUDPHeaderKfunc = false
	}
	if !opts.PushUDPHeaderKfuncCall.IsKfuncCall() {
		opts.PushUDPHeaderKfunc = false
	}
	if !opts.OuterTCPCsumKfuncCall.IsKfuncCall() {
		opts.OuterTCPCsumKfunc = false
	}
	if !opts.OuterTCPKfuncCall.IsKfuncCall() {
		opts.OuterTCPKfunc = false
	}
	if !opts.TCPPartialCSUMKfuncCall.IsKfuncCall() {
		opts.TCPPartialCSUMKfunc = false
	}
	if !opts.PushTCPHeaderKfuncCall.IsKfuncCall() {
		opts.PushTCPHeaderKfunc = false
	}
	if !opts.PushFlowTCPHeaderKfuncCall.IsKfuncCall() {
		opts.PushFlowTCPHeaderKfunc = false
	}
	if !opts.FinalizeFlowTCPHeaderKfuncCall.IsKfuncCall() {
		opts.FinalizeFlowTCPHeaderKfunc = false
	}
	if !opts.PushRouteTCPHeaderKfuncCall.IsKfuncCall() {
		opts.PushRouteTCPHeaderKfunc = false
	}
	if !opts.RouteTCPGSOKfuncCall.IsKfuncCall() {
		opts.RouteTCPGSOKfunc = false
	}
	if !opts.RouteTCPXmitKfuncCall.IsKfuncCall() {
		opts.RouteTCPXmitKfunc = false
	}
	if !opts.PushRouteTCPHeaderKfunc {
		opts.RouteTCPGSOKfunc = false
		opts.RouteTCPXmitKfunc = false
	}
	tunnelGSO := kernelUDPTunnelGSOEnabledForOptions(opts)
	activeGSO := kernelUDPTunnelGSOActiveSKBEnabledForOptions(opts)
	buildUDPHeaderKfuncPath := opts.KernelUDPOnly && opts.SkipPlainSequence && opts.BuildUDPHeaderKfunc && opts.BuildUDPHeaderKfuncCall.IsKfuncCall()
	finalizeUDPHeaderKfuncPath := opts.KernelUDPOnly && opts.SkipPlainSequence && opts.FinalizeUDPHeaderKfunc && opts.FinalizeUDPKfuncCall.IsKfuncCall()
	pushUDPHeaderKfuncPath := opts.KernelUDPOnly && opts.SkipPlainSequence && opts.PushUDPHeaderKfunc && opts.PushUDPHeaderKfuncCall.IsKfuncCall()
	outerTCPCsumKfuncPath := !opts.KernelUDPOnly && opts.OuterTCPCsumKfunc && opts.OuterTCPCsumKfuncCall.IsKfuncCall() && !experimentalTCPSkipOuterTCPChecksum()
	finalizeOuterTCPKfuncPath := opts.ExperimentalTCPOnly && !opts.KernelUDPOnly && opts.OuterTCPKfunc && opts.OuterTCPKfuncCall.IsKfuncCall() && !experimentalTCPSkipOuterTCPChecksum()
	tcpPartialCSUMKfuncPath := opts.ExperimentalTCPOnly && !opts.KernelUDPOnly && opts.TCPPartialCSUMKfunc && opts.TCPPartialCSUMKfuncCall.IsKfuncCall() && !experimentalTCPSkipOuterTCPChecksum()
	pushOuterTCPKfuncPath := opts.ExperimentalTCPOnly && !opts.KernelUDPOnly && opts.PushTCPHeaderKfunc && opts.PushTCPHeaderKfuncCall.IsKfuncCall() && !experimentalTCPSkipOuterTCPChecksum()
	preOuterInnerChecksum := experimentalTCPTXDirectPreOuterInnerChecksumEnabledForOptions(opts)
	pushFlowOuterTCPKfuncPath := opts.ExperimentalTCPOnly && !opts.KernelUDPOnly && opts.PushFlowTCPHeaderKfunc && opts.PushFlowTCPHeaderKfuncCall.IsKfuncCall() && !experimentalTCPSkipOuterTCPChecksum() && !preOuterInnerChecksum
	finalizeFlowOuterTCPKfuncPath := opts.ExperimentalTCPOnly && !opts.KernelUDPOnly && opts.FinalizeFlowTCPHeaderKfunc && opts.FinalizeFlowTCPHeaderKfuncCall.IsKfuncCall() && !experimentalTCPSkipOuterTCPChecksum() && !preOuterInnerChecksum
	pushRouteOuterTCPKfuncPath := opts.ExperimentalTCPOnly && !opts.KernelUDPOnly && opts.DirectOnly && opts.PushRouteTCPHeaderKfunc && opts.PushRouteTCPHeaderKfuncCall.IsKfuncCall() && !experimentalTCPSkipOuterTCPChecksum() && !preOuterInnerChecksum
	routeTCPGSOKfuncPath := pushRouteOuterTCPKfuncPath && opts.RouteTCPGSOKfunc && opts.RouteTCPGSOKfuncCall.IsKfuncCall()
	routeTCPXmitKfuncPath := routeTCPGSOKfuncPath && opts.RouteTCPXmitKfunc && opts.RouteTCPXmitKfuncCall.IsKfuncCall()
	if pushFlowOuterTCPKfuncPath {
		finalizeFlowOuterTCPKfuncPath = false
		pushOuterTCPKfuncPath = false
		finalizeOuterTCPKfuncPath = false
	}
	if finalizeFlowOuterTCPKfuncPath {
		pushOuterTCPKfuncPath = false
		finalizeOuterTCPKfuncPath = false
	}
	if pushOuterTCPKfuncPath {
		finalizeOuterTCPKfuncPath = false
	}
	if finalizeOuterTCPKfuncPath || pushOuterTCPKfuncPath || pushFlowOuterTCPKfuncPath || finalizeFlowOuterTCPKfuncPath || pushRouteOuterTCPKfuncPath {
		tcpPartialCSUMKfuncPath = false
	}
	if activeGSO && opts.ExperimentalTCPOnly && !finalizeFlowOuterTCPKfuncPath &&
		!routeTCPGSOKfuncPath && !experimentalTCPTXDirectActiveGSOUnsafeEnabled() {
		activeGSO = false
	}
	udpHeaderKfuncArgsPath := buildUDPHeaderKfuncPath || finalizeUDPHeaderKfuncPath || pushUDPHeaderKfuncPath
	routeFlowZeroLabel := "kudp_tx_direct_route_flow_zero"
	if opts.DirectOnly {
		routeFlowZeroLabel = "kudp_tx_direct_fallback"
	}
	if opts.RouteCacheMap != nil {
		instructions = appendKernelUDPTXDirectRouteCache(instructions, opts.RouteCacheMap)
	}
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_route_lookup_start"))
	instructions = append(instructions,
		asm.LoadMem(asm.R4, asm.R7, 30, asm.Word), // Inner IPv4 destination address.
		asm.StoreImm(asm.RFP, kernelUDPTXRouteKeyOffset, 32, asm.Word),
		asm.StoreMem(asm.RFP, kernelUDPTXRouteKeyOffset+4, asm.R4, asm.Word),
		asm.LoadMapPtr(asm.R1, routeMap.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, kernelUDPTXRouteKeyOffset),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "kudp_tx_direct_route_miss"),
		asm.StoreMem(asm.RFP, kernelUDPTXRoutePtrOffset, asm.R0, asm.DWord),
		asm.LoadMem(asm.R1, asm.R0, 76, asm.Word).WithSymbol("kudp_tx_direct_route_ready"),
		asm.StoreMem(asm.RFP, kernelUDPTXRouteFlagsOffset, asm.R1, asm.Word),
		asm.JSet.Imm(asm.R1, kernelUDPTXRouteFlagBypass, "kudp_tx_direct_route_bypass"),
		asm.JSet.Imm(asm.R1, kernelUDPTXRouteFlagInlineFlow, "kudp_tx_direct_inline_flow"),
		asm.LoadMem(asm.R1, asm.R0, 72, asm.Word),
		asm.JEq.Imm(asm.R1, 0, "kudp_tx_direct_route_default"),
		asm.StoreMem(asm.RFP, kernelUDPTXFlowMaskScratchOffset, asm.R1, asm.Word),
	)
	if kernelUDPTXDirectSKBFlowHashEnabled() {
		instructions = appendKernelUDPTXDirectSKBFlowHash(instructions, "kudp_tx_direct_hash_ready")
	} else {
		instructions = appendKernelUDPTXDirectInnerFlowHash(instructions, "kudp_tx_direct_hash_ready", "kudp_tx_direct_route_default")
	}
	instructions = append(instructions,
		asm.LoadMem(asm.R0, asm.RFP, kernelUDPTXRoutePtrOffset, asm.DWord),
		asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXFlowMaskScratchOffset, asm.Word),
		asm.And.Reg(asm.R2, asm.R1),
		asm.JEq.Imm(asm.R2, 0, "kudp_tx_direct_pick_1"),
		asm.JEq.Imm(asm.R2, 1, "kudp_tx_direct_pick_2"),
		asm.JEq.Imm(asm.R2, 2, "kudp_tx_direct_pick_3"),
		asm.JEq.Imm(asm.R2, 3, "kudp_tx_direct_pick_4"),
		asm.JEq.Imm(asm.R2, 4, "kudp_tx_direct_pick_5"),
		asm.JEq.Imm(asm.R2, 5, "kudp_tx_direct_pick_6"),
		asm.JEq.Imm(asm.R2, 6, "kudp_tx_direct_pick_7"),
		asm.LoadMem(asm.R1, asm.R0, 64, asm.DWord),
		asm.Ja.Label("kudp_tx_direct_flow_selected"),
		asm.LoadMem(asm.R1, asm.R0, 8, asm.DWord).WithSymbol("kudp_tx_direct_pick_1"),
		asm.Ja.Label("kudp_tx_direct_flow_selected"),
		asm.LoadMem(asm.R1, asm.R0, 16, asm.DWord).WithSymbol("kudp_tx_direct_pick_2"),
		asm.Ja.Label("kudp_tx_direct_flow_selected"),
		asm.LoadMem(asm.R1, asm.R0, 24, asm.DWord).WithSymbol("kudp_tx_direct_pick_3"),
		asm.Ja.Label("kudp_tx_direct_flow_selected"),
		asm.LoadMem(asm.R1, asm.R0, 32, asm.DWord).WithSymbol("kudp_tx_direct_pick_4"),
		asm.Ja.Label("kudp_tx_direct_flow_selected"),
		asm.LoadMem(asm.R1, asm.R0, 40, asm.DWord).WithSymbol("kudp_tx_direct_pick_5"),
		asm.Ja.Label("kudp_tx_direct_flow_selected"),
		asm.LoadMem(asm.R1, asm.R0, 48, asm.DWord).WithSymbol("kudp_tx_direct_pick_6"),
		asm.Ja.Label("kudp_tx_direct_flow_selected"),
		asm.LoadMem(asm.R1, asm.R0, 56, asm.DWord).WithSymbol("kudp_tx_direct_pick_7"),
		asm.Ja.Label("kudp_tx_direct_flow_selected"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord).WithSymbol("kudp_tx_direct_route_default"),
		asm.JEq.Imm(asm.R1, 0, routeFlowZeroLabel),
		asm.Mov.Reg(asm.R1, asm.R1).WithSymbol("kudp_tx_direct_flow_selected"),
		asm.JEq.Imm(asm.R1, 0, routeFlowZeroLabel),
		asm.StoreMem(asm.RFP, kernelUDPTXFlowKeyOffset, asm.R1, asm.DWord),
		asm.LoadMapPtr(asm.R1, flowMap.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, kernelUDPTXFlowKeyOffset),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "kudp_tx_direct_flow_miss"),
		asm.Ja.Label("kudp_tx_direct_flow_ready"),
		asm.LoadMem(asm.R1, asm.R0, 72, asm.Word).WithSymbol("kudp_tx_direct_inline_flow"),
	)
	if pushRouteOuterTCPKfuncPath {
		var flags int32
		if experimentalTCPTXDirectOuterTCPHeaderKfuncPartialChecksumEnabled() {
			flags |= trustIXTIXTTXFinalizeTCPPartialCSUM
		} else if experimentalTCPTXDirectTrustInnerChecksums() {
			flags |= trustIXTIXTTXFinalizeTCPTrustInnerCSUM
		}
		gsoFlags := flags
		if experimentalTCPTXDirectRouteTCPGSOTrustPartialInnerChecksumEnabled() {
			gsoFlags |= trustIXTIXTTXFinalizeTCPTrustPartialInnerCSUM
		}
		if opts.SKBClearTXOffload {
			flags |= int32(trustIXSKBClearTXOffloadCSUM | trustIXSKBClearTXOffloadEncap)
			gsoFlags |= int32(trustIXSKBClearTXOffloadCSUM | trustIXSKBClearTXOffloadEncap)
			if kernelUDPTXDirectSKBClearTXOffloadGSOEnabled() {
				flags |= trustIXSKBClearTXOffloadGSO
				gsoFlags |= trustIXSKBClearTXOffloadGSO
			}
		}
		instructions = append(instructions, asm.StoreImm(asm.RFP, kernelUDPTXGSOActiveOffset, 0, asm.Word))
		if routeTCPGSOKfuncPath {
			if routeTCPXmitKfuncPath {
				instructions = append(instructions,
					asm.LoadMem(asm.R4, asm.R6, skbGSOSizeOffset, asm.Word).WithSymbol("kudp_tx_direct_route_tcp_gso_check"),
					asm.JEq.Imm(asm.R4, 0, "kudp_tx_direct_route_tcp_xmit_kfunc_prepare"),
				)
			} else {
				instructions = append(instructions,
					asm.LoadMem(asm.R4, asm.R6, skbGSOSizeOffset, asm.Word).WithSymbol("kudp_tx_direct_route_tcp_gso_check"),
					asm.JEq.Imm(asm.R4, 0, "kudp_tx_direct_route_tcp_linear_kfunc"),
				)
			}
			instructions = append(instructions,
				asm.LoadMem(asm.R0, asm.RFP, kernelUDPTXRoutePtrOffset, asm.DWord),
				asm.LoadMem(asm.R4, asm.R0, 72, asm.Word).WithSymbol("kudp_tx_direct_route_tcp_single_flow_guard"),
				asm.JNE.Imm(asm.R4, 0, "kudp_tx_direct_fallback"),
				asm.StoreImm(asm.RFP, kernelUDPTXTIXTSegmentRouteTCPGSOArgsClearFlagsOffset, int64(gsoFlags), asm.Word),
				asm.Mov.Reg(asm.R2, asm.R0),
				asm.Mov.Reg(asm.R1, asm.R6).WithSymbol("kudp_tx_direct_route_tcp_kfunc"),
				asm.Mov.Reg(asm.R3, asm.RFP),
				asm.Add.Imm(asm.R3, kernelUDPTXTIXTSegmentRouteTCPGSOArgsOffset),
				opts.RouteTCPGSOKfuncCall,
				asm.JEq.Imm(asm.R0, experimentalTCPTXRouteGSOSegmentsStolen, "kudp_tx_direct_segment_route_tcp_gso_stolen"),
				asm.JEq.Imm(asm.R0, -int32(unix.EPROTONOSUPPORT), "kudp_tx_direct_segment_route_tcp_gso_fallback"),
				asm.JEq.Imm(asm.R0, -int32(unix.EOPNOTSUPP), "kudp_tx_direct_segment_route_tcp_gso_fallback"),
				asm.JEq.Imm(asm.R0, -int32(unix.EMSGSIZE), "kudp_tx_direct_mtu_kind_fallback"),
				asm.StoreMem(asm.RFP, kernelUDPTXIfindexOffset, asm.R0, asm.Word),
				asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
				asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
			)
			if routeTCPXmitKfuncPath {
				instructions = append(instructions,
					asm.JSLT.Imm(asm.R0, 0, "kudp_tx_direct_adjust_drop"),
					asm.JEq.Imm(asm.R0, 0, "kudp_tx_direct_adjust_drop"),
					asm.Ja.Label("kudp_tx_direct_route_tcp_gso_redirect"),
					asm.LoadMem(asm.R0, asm.RFP, kernelUDPTXRoutePtrOffset, asm.DWord).WithSymbol("kudp_tx_direct_route_tcp_xmit_kfunc_prepare"),
					asm.LoadMem(asm.R4, asm.R0, 72, asm.Word),
					asm.JNE.Imm(asm.R4, 0, "kudp_tx_direct_fallback"),
					asm.StoreImm(asm.RFP, kernelUDPTXTIXTSegmentRouteTCPGSOArgsClearFlagsOffset, int64(gsoFlags), asm.Word),
					asm.Mov.Reg(asm.R2, asm.R0),
					asm.Mov.Reg(asm.R1, asm.R6).WithSymbol("kudp_tx_direct_route_tcp_xmit_kfunc"),
					asm.Mov.Reg(asm.R3, asm.RFP),
					asm.Add.Imm(asm.R3, kernelUDPTXTIXTSegmentRouteTCPGSOArgsOffset),
					opts.RouteTCPXmitKfuncCall,
					asm.JEq.Imm(asm.R0, experimentalTCPTXRouteXmitStolen, "kudp_tx_direct_route_tcp_xmit_stolen"),
					asm.JEq.Imm(asm.R0, experimentalTCPTXRouteXmitQueued, "kudp_tx_direct_route_tcp_xmit_queued"),
					asm.JEq.Imm(asm.R0, -int32(unix.EPROTONOSUPPORT), "kudp_tx_direct_route_tcp_xmit_fallback"),
					asm.JEq.Imm(asm.R0, -int32(unix.EOPNOTSUPP), "kudp_tx_direct_route_tcp_xmit_fallback"),
					asm.JEq.Imm(asm.R0, -int32(unix.EMSGSIZE), "kudp_tx_direct_mtu_kind_fallback"),
					asm.JSLT.Imm(asm.R0, 0, "kudp_tx_direct_route_tcp_xmit_drop"),
					asm.JEq.Imm(asm.R0, 0, "kudp_tx_direct_route_tcp_xmit_drop"),
					asm.Ja.Label("kudp_tx_direct_route_tcp_xmit_fallback"),
				)
			} else {
				instructions = append(instructions,
					asm.JSLT.Imm(asm.R0, 0, "kudp_tx_direct_adjust_drop"),
					asm.JEq.Imm(asm.R0, 0, "kudp_tx_direct_adjust_drop"),
				)
				instructions = append(instructions,
					asm.Ja.Label("kudp_tx_direct_route_tcp_kfunc_done"),
					asm.Mov.Reg(asm.R0, asm.R0).WithSymbol("kudp_tx_direct_route_tcp_kfunc_done"),
				)
			}
		} else {
			instructions = append(instructions,
				asm.StoreImm(asm.RFP, kernelUDPTXTIXTPushRouteTCPHeaderArgsClearFlagsOffset, int64(flags), asm.Word),
				asm.LoadMem(asm.R4, asm.R0, 72, asm.Word).WithSymbol("kudp_tx_direct_push_route_outer_tcp_header_kfunc"),
				asm.JNE.Imm(asm.R4, 0, "kudp_tx_direct_inline_route_unsupported"),
				asm.Mov.Reg(asm.R2, asm.R0),
				asm.Mov.Reg(asm.R1, asm.R6),
				asm.Mov.Reg(asm.R3, asm.RFP),
				asm.Add.Imm(asm.R3, kernelUDPTXTIXTPushRouteTCPHeaderArgsOffset),
				opts.PushRouteTCPHeaderKfuncCall,
				asm.JEq.Imm(asm.R0, -int32(unix.EPROTONOSUPPORT), "kudp_tx_direct_inline_route_unsupported"),
				asm.JEq.Imm(asm.R0, -int32(unix.EOPNOTSUPP), "kudp_tx_direct_inline_route_unsupported"),
				asm.JEq.Imm(asm.R0, -int32(unix.EMSGSIZE), "kudp_tx_direct_mtu_kind_fallback"),
				asm.JSLT.Imm(asm.R0, 0, "kudp_tx_direct_adjust_drop"),
				asm.JEq.Imm(asm.R0, 0, "kudp_tx_direct_adjust_drop"),
				asm.StoreMem(asm.RFP, kernelUDPTXIfindexOffset, asm.R0, asm.Word),
				asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
				asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
			)
		}
		if !(routeTCPGSOKfuncPath && routeTCPXmitKfuncPath) {
			instructions = appendHotPathCounter(instructions, statsMap, kernelUDPTXStatSuccess, "kudp_tx_direct_success_counter_done")
			instructions = append(instructions,
				asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXIfindexOffset, asm.Word),
				asm.Mov.Imm(asm.R2, 0),
			)
			if opts.RedirectPeer {
				instructions = append(instructions, asm.FnRedirectPeer.Call())
			} else {
				instructions = append(instructions, asm.FnRedirect.Call())
			}
			instructions = append(instructions,
				asm.Return(),
			)
		}
		if routeTCPGSOKfuncPath {
			if routeTCPXmitKfuncPath {
				instructions = append(instructions,
					asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_route_tcp_gso_redirect"),
				)
				instructions = appendHotPathCounter(instructions, statsMap, kernelUDPTXDirectStatRouteTCPGSOSuccesses, "kudp_tx_direct_route_tcp_gso_redirect_success_counter_done")
				instructions = appendHotPathCounter(instructions, statsMap, kernelUDPTXStatSuccess, "kudp_tx_direct_route_tcp_gso_redirect_tx_success_counter_done")
				instructions = append(instructions,
					asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXIfindexOffset, asm.Word),
					asm.Mov.Imm(asm.R2, 0),
				)
				if opts.RedirectPeer {
					instructions = append(instructions, asm.FnRedirectPeer.Call())
				} else {
					instructions = append(instructions, asm.FnRedirect.Call())
				}
				instructions = append(instructions, asm.Return())
			}
			instructions = append(instructions,
				asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_segment_route_tcp_gso_stolen"),
			)
			instructions = appendHotPathCounter(instructions, statsMap, kernelUDPTXDirectStatRouteTCPGSOSuccesses, "kudp_tx_direct_segment_route_tcp_gso_success_counter_done")
			instructions = appendHotPathCounter(instructions, statsMap, kernelUDPTXStatSuccess, "kudp_tx_direct_success_counter_done")
			instructions = append(instructions,
				asm.Mov.Imm(asm.R0, tcActShot),
				asm.Return(),
			)
			if routeTCPXmitKfuncPath {
				instructions = append(instructions,
					asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_route_tcp_xmit_stolen"),
				)
				instructions = appendHotPathCounter(instructions, statsMap, kernelUDPTXDirectStatRouteTCPXmitSuccesses, "kudp_tx_direct_route_tcp_xmit_success_counter_done")
				instructions = appendHotPathCounter(instructions, statsMap, kernelUDPTXStatSuccess, "kudp_tx_direct_success_counter_done")
				instructions = append(instructions,
					asm.Mov.Imm(asm.R0, tcActStolen),
					asm.Return(),
					asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_route_tcp_xmit_queued"),
				)
				instructions = appendHotPathCounter(instructions, statsMap, kernelUDPTXDirectStatRouteTCPXmitSuccesses, "kudp_tx_direct_route_tcp_xmit_queued_success_counter_done")
				instructions = appendHotPathCounter(instructions, statsMap, kernelUDPTXStatSuccess, "kudp_tx_direct_queued_success_counter_done")
				instructions = append(instructions,
					asm.Mov.Imm(asm.R0, tcActShot),
					asm.Return(),
				)
			}
			instructions = append(instructions,
				asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_segment_route_tcp_gso_fallback"),
			)
			instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatRouteTCPGSOFallbacks, "kudp_tx_direct_segment_route_tcp_gso_fallback_counter_done")
			if routeTCPXmitKfuncPath {
				instructions = append(instructions,
					asm.Ja.Label("kudp_tx_direct_fallback"),
					asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_route_tcp_xmit_fallback"),
				)
				instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatRouteTCPXmitFallbacks, "kudp_tx_direct_route_tcp_xmit_fallback_counter_done")
				instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_route_tcp_linear_kfunc"))
			}
			if !routeTCPXmitKfuncPath {
				instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_fallback"))
			}
			instructions = append(instructions,
				asm.StoreImm(asm.RFP, kernelUDPTXTIXTPushRouteTCPHeaderArgsClearFlagsOffset, int64(flags), asm.Word).WithSymbol("kudp_tx_direct_route_tcp_linear_kfunc"),
				asm.LoadMem(asm.R0, asm.RFP, kernelUDPTXRoutePtrOffset, asm.DWord),
				asm.LoadMem(asm.R4, asm.R0, 72, asm.Word),
				asm.JNE.Imm(asm.R4, 0, "kudp_tx_direct_fallback"),
				asm.Mov.Reg(asm.R2, asm.R0),
				asm.Mov.Reg(asm.R1, asm.R6),
				asm.Mov.Reg(asm.R3, asm.RFP),
				asm.Add.Imm(asm.R3, kernelUDPTXTIXTPushRouteTCPHeaderArgsOffset),
				opts.PushRouteTCPHeaderKfuncCall,
				asm.JEq.Imm(asm.R0, -int32(unix.EPROTONOSUPPORT), "kudp_tx_direct_fallback"),
				asm.JEq.Imm(asm.R0, -int32(unix.EOPNOTSUPP), "kudp_tx_direct_fallback"),
				asm.JEq.Imm(asm.R0, -int32(unix.EMSGSIZE), "kudp_tx_direct_mtu_kind_fallback"),
				asm.JSLT.Imm(asm.R0, 0, "kudp_tx_direct_adjust_drop"),
				asm.JEq.Imm(asm.R0, 0, "kudp_tx_direct_adjust_drop"),
				asm.StoreMem(asm.RFP, kernelUDPTXIfindexOffset, asm.R0, asm.Word),
				asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
				asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
			)
			instructions = appendHotPathCounter(instructions, statsMap, kernelUDPTXStatSuccess, "kudp_tx_direct_route_tcp_linear_success_counter_done")
			instructions = append(instructions,
				asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXIfindexOffset, asm.Word),
				asm.Mov.Imm(asm.R2, 0),
			)
			if opts.RedirectPeer {
				instructions = append(instructions, asm.FnRedirectPeer.Call())
			} else {
				instructions = append(instructions, asm.FnRedirect.Call())
			}
			instructions = append(instructions, asm.Return())
		}
		if routeTCPXmitKfuncPath {
			instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_route_tcp_xmit_drop"))
			instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatRouteTCPXmitDrops, "kudp_tx_direct_route_tcp_xmit_drop_counter_done")
			instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_adjust_drop"))
		}
		if !routeTCPGSOKfuncPath {
			instructions = append(instructions,
				asm.LoadMem(asm.R0, asm.RFP, kernelUDPTXRoutePtrOffset, asm.DWord).WithSymbol("kudp_tx_direct_inline_route_unsupported"),
				asm.LoadMem(asm.R1, asm.R0, 72, asm.Word),
				asm.JEq.Imm(asm.R1, 0, "kudp_tx_direct_inline_default"),
				asm.StoreMem(asm.RFP, kernelUDPTXFlowMaskScratchOffset, asm.R1, asm.Word),
			)
		}
	}
	if !routeTCPGSOKfuncPath {
		instructions = append(instructions,
			asm.JEq.Imm(asm.R1, 0, "kudp_tx_direct_inline_default"),
		)
		if !pushRouteOuterTCPKfuncPath {
			instructions = append(instructions, asm.StoreMem(asm.RFP, kernelUDPTXFlowMaskScratchOffset, asm.R1, asm.Word))
		}
		if kernelUDPTXDirectSKBFlowHashEnabled() {
			instructions = appendKernelUDPTXDirectSKBFlowHash(instructions, "kudp_tx_direct_inline_hash_ready")
		} else {
			instructions = appendKernelUDPTXDirectInnerFlowHash(instructions, "kudp_tx_direct_inline_hash_ready", "kudp_tx_direct_inline_default")
		}
		instructions = append(instructions,
			asm.LoadMem(asm.R0, asm.RFP, kernelUDPTXRoutePtrOffset, asm.DWord),
			asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXFlowMaskScratchOffset, asm.Word),
			asm.And.Reg(asm.R2, asm.R1),
			asm.JEq.Imm(asm.R2, 0, "kudp_tx_direct_inline_pick_1"),
			asm.JEq.Imm(asm.R2, 1, "kudp_tx_direct_inline_pick_2"),
			asm.JEq.Imm(asm.R2, 2, "kudp_tx_direct_inline_pick_3"),
			asm.JEq.Imm(asm.R2, 3, "kudp_tx_direct_inline_pick_4"),
			asm.JEq.Imm(asm.R2, 4, "kudp_tx_direct_inline_pick_5"),
			asm.JEq.Imm(asm.R2, 5, "kudp_tx_direct_inline_pick_6"),
			asm.JEq.Imm(asm.R2, 6, "kudp_tx_direct_inline_pick_7"),
			asm.LoadMem(asm.R1, asm.R0, 64, asm.DWord),
			asm.Add.Imm(asm.R0, kernelUDPTXRouteInlineFlow8Offset),
			asm.Ja.Label("kudp_tx_direct_inline_selected"),
			asm.LoadMem(asm.R1, asm.R0, 8, asm.DWord).WithSymbol("kudp_tx_direct_inline_pick_1"),
			asm.Add.Imm(asm.R0, kernelUDPTXRouteInlineFlowOffset),
			asm.Ja.Label("kudp_tx_direct_inline_selected"),
			asm.LoadMem(asm.R1, asm.R0, 16, asm.DWord).WithSymbol("kudp_tx_direct_inline_pick_2"),
			asm.Add.Imm(asm.R0, kernelUDPTXRouteInlineFlow2Offset),
			asm.Ja.Label("kudp_tx_direct_inline_selected"),
			asm.LoadMem(asm.R1, asm.R0, 24, asm.DWord).WithSymbol("kudp_tx_direct_inline_pick_3"),
			asm.Add.Imm(asm.R0, kernelUDPTXRouteInlineFlow3Offset),
			asm.Ja.Label("kudp_tx_direct_inline_selected"),
			asm.LoadMem(asm.R1, asm.R0, 32, asm.DWord).WithSymbol("kudp_tx_direct_inline_pick_4"),
			asm.Add.Imm(asm.R0, kernelUDPTXRouteInlineFlow4Offset),
			asm.Ja.Label("kudp_tx_direct_inline_selected"),
			asm.LoadMem(asm.R1, asm.R0, 40, asm.DWord).WithSymbol("kudp_tx_direct_inline_pick_5"),
			asm.Add.Imm(asm.R0, kernelUDPTXRouteInlineFlow5Offset),
			asm.Ja.Label("kudp_tx_direct_inline_selected"),
			asm.LoadMem(asm.R1, asm.R0, 48, asm.DWord).WithSymbol("kudp_tx_direct_inline_pick_6"),
			asm.Add.Imm(asm.R0, kernelUDPTXRouteInlineFlow6Offset),
			asm.Ja.Label("kudp_tx_direct_inline_selected"),
			asm.LoadMem(asm.R1, asm.R0, 56, asm.DWord).WithSymbol("kudp_tx_direct_inline_pick_7"),
			asm.Add.Imm(asm.R0, kernelUDPTXRouteInlineFlow7Offset),
			asm.Ja.Label("kudp_tx_direct_inline_selected"),
			asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord).WithSymbol("kudp_tx_direct_inline_default"),
			asm.Add.Imm(asm.R0, kernelUDPTXRouteInlineFlowOffset),
			asm.JEq.Imm(asm.R1, 0, routeFlowZeroLabel),
			asm.Mov.Reg(asm.R1, asm.R1).WithSymbol("kudp_tx_direct_inline_selected"),
			asm.JEq.Imm(asm.R1, 0, routeFlowZeroLabel),
			asm.StoreMem(asm.RFP, kernelUDPTXFlowKeyOffset, asm.R1, asm.DWord),
		)
	}
	instructions = append(instructions,

		// Plain TC direct-TX only handles flows explicitly marked plaintext. Secure
		// flows are handled by the optional kernel_udp secure direct object before
		// this program; if that object is unavailable or misses, fall through to
		// userspace capture so encryption is preserved.
		asm.LoadMem(asm.R1, asm.R0, 44, asm.Word).WithSymbol("kudp_tx_direct_flow_ready"),
		asm.StoreMem(asm.RFP, kernelUDPTXFlagsOffset, asm.R1, asm.Word),
		asm.JSet.Imm(asm.R1, int32(kernelUDPTXFlowFlagSecure), "kudp_tx_direct_secure_flow_fallback"),
	)
	if pushFlowOuterTCPKfuncPath || finalizeFlowOuterTCPKfuncPath {
		instructions = append(instructions, asm.StoreMem(asm.RFP, kernelUDPTXFlowPtrOffset, asm.R0, asm.DWord))
	}
	if opts.ExperimentalTCPOnly {
		instructions = append(instructions,
			asm.JSet.Imm(asm.R1, int32(kernelUDPTXFlowFlagExperimentalTCP), "kudp_tx_direct_transport_ok"),
			asm.Ja.Label("kudp_tx_direct_transport_fallback"),
			asm.Mov.Reg(asm.R0, asm.R0).WithSymbol("kudp_tx_direct_transport_ok"),
		)
	} else if opts.KernelUDPOnly {
		instructions = append(instructions,
			asm.JSet.Imm(asm.R1, int32(kernelUDPTXFlowFlagExperimentalTCP), "kudp_tx_direct_transport_fallback"),
		)
	}
	instructions = append(instructions,

		// The plain TC direct-TX cut handles linear IPv4 packets by default. When
		// tunnel-GSO is explicitly enabled, it also accepts TCP GSO skbs whose
		// wire segments still fit after the selected TIXU/TIXT encapsulation.
		asm.LoadMem(asm.R1, asm.R7, 14, asm.Byte),
		asm.JNE.Imm(asm.R1, 0x45, "kudp_tx_direct_non_ipv4_fallback"),
		asm.LoadMem(asm.R1, asm.R7, 20, asm.Half),
		asm.JSet.Imm(asm.R1, ipv4FragmentMaskLittleEndian, "kudp_tx_direct_fragment_fallback"),
		asm.LoadMem(asm.R9, asm.R7, 16, asm.Half), // Inner IPv4 total length.
		asm.HostTo(asm.BE, asm.R9, asm.Half),
		asm.And.Imm(asm.R9, 0xffff),
		asm.JLT.Imm(asm.R9, rejectIPv4HeaderLen, "kudp_tx_direct_len_short_fallback"),
		asm.LoadMem(asm.R2, asm.R6, skbLenOffset, asm.Word),
		asm.Mov.Reg(asm.R3, asm.R9),
		asm.Add.Imm(asm.R3, rejectEthernetHeaderLen),
	)
	if tunnelGSO {
		instructions = append(instructions,
			asm.JGT.Reg(asm.R3, asm.R2, "kudp_tx_direct_len_short_fallback"),
			asm.LoadMem(asm.R4, asm.R6, skbGSOSizeOffset, asm.Word),
			asm.JEq.Imm(asm.R4, 0, "kudp_tx_direct_len_maybe_linear"),
			asm.Ja.Label("kudp_tx_direct_len_gso_ok"),
			asm.Mov.Reg(asm.R0, asm.R0).WithSymbol("kudp_tx_direct_len_maybe_linear"),
			asm.JNE.Reg(asm.R2, asm.R3, "kudp_tx_direct_len_gso_fallback"),
			asm.StoreMem(asm.RFP, kernelUDPTXGSOSegmentLenOffset, asm.R9, asm.Word),
			asm.StoreImm(asm.RFP, kernelUDPTXGSOActiveOffset, 0, asm.Word),
		)
		instructions = appendHotPathCounterPreserveR0(instructions, statsMap, kernelUDPTXDirectStatLinearAccepts, "kudp_tx_direct_linear_accept_counter_done")
		instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_len_ok"))
		instructions = append(instructions, asm.Mov.Reg(asm.R0, asm.R0).WithSymbol("kudp_tx_direct_len_gso_ok"))
		instructions = appendHotPathCounterPreserveR0(instructions, statsMap, kernelUDPTXDirectStatGSOInputs, "kudp_tx_direct_gso_input_counter_done")
		instructions = append(instructions,
			asm.LoadMem(asm.R1, asm.R7, 23, asm.Byte),
			asm.JNE.Imm(asm.R1, ipProtocolTCP, "kudp_tx_direct_len_gso_fallback"),
			asm.LoadMem(asm.R1, asm.R7, 14, asm.Byte),
			asm.And.Imm(asm.R1, 0x0f),
			asm.JNE.Imm(asm.R1, 5, "kudp_tx_direct_len_gso_fallback"),
			asm.Mov.Reg(asm.R1, asm.R7),
			asm.Add.Imm(asm.R1, rejectEthernetHeaderLen+rejectIPv4HeaderLen+13),
			asm.JGT.Reg(asm.R1, asm.R8, "kudp_tx_direct_len_gso_fallback"),
			asm.LoadMem(asm.R1, asm.R7, 46, asm.Byte),
			asm.RSh.Imm(asm.R1, 4),
			asm.JLT.Imm(asm.R1, 5, "kudp_tx_direct_len_gso_fallback"),
			asm.LSh.Imm(asm.R1, 2),
			asm.LoadMem(asm.R3, asm.R6, skbGSOSizeOffset, asm.Word),
			asm.JEq.Imm(asm.R3, 0, "kudp_tx_direct_gso_size_zero_fallback"),
		)
		if activeGSO {
			instructions = append(instructions,
				asm.LoadMem(asm.R4, asm.RFP, kernelUDPTXFlagsOffset, asm.Word),
			)
			if !opts.ExperimentalTCPOnly && !experimentalTCPTXDirectActiveGSOUnsafeEnabled() {
				instructions = append(instructions,
					asm.JSet.Imm(asm.R4, int32(kernelUDPTXFlowFlagExperimentalTCP), "kudp_tx_direct_len_gso_fallback"),
				)
			}
			instructions = append(instructions,
				asm.Add.Reg(asm.R3, asm.R1),
				asm.Add.Imm(asm.R3, rejectIPv4HeaderLen),
				asm.StoreMem(asm.RFP, kernelUDPTXGSOSegmentLenOffset, asm.R3, asm.Word),
				asm.StoreImm(asm.RFP, kernelUDPTXGSOActiveOffset, 1, asm.Word),
			)
			instructions = appendHotPathCounterPreserveR0(instructions, statsMap, kernelUDPTXDirectStatGSOActiveAccepts, "kudp_tx_direct_gso_active_accept_counter_done")
		} else {
			instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_len_gso_fallback"))
		}
	} else {
		instructions = append(instructions,
			asm.JGT.Reg(asm.R2, asm.R3, "kudp_tx_direct_len_gso_fallback"),
			asm.JNE.Reg(asm.R2, asm.R3, "kudp_tx_direct_len_short_fallback"),
		)
	}
	if tunnelGSO && opts.ExperimentalTCPOnly {
		instructions = append(instructions,
			asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXGSOActiveOffset, asm.Word).WithSymbol("kudp_tx_direct_len_ok"),
			asm.JNE.Imm(asm.R1, 0, "kudp_tx_direct_mtu_ok"),
		)
	}
	mtuLenOKSymbol := "kudp_tx_direct_len_ok"
	if tunnelGSO && opts.ExperimentalTCPOnly {
		mtuLenOKSymbol = ""
	}
	instructions = append(instructions,
		asm.LoadMem(asm.R2, asm.R0, 40, asm.Word).WithSymbol(mtuLenOKSymbol), // Underlay L3 MTU, 0 disables the check.
		asm.JEq.Imm(asm.R2, 0, "kudp_tx_direct_mtu_ok"),
		asm.Mov.Reg(asm.R3, asm.R9),
	)
	if tunnelGSO {
		instructions = append(instructions,
			asm.LoadMem(asm.R3, asm.RFP, kernelUDPTXGSOSegmentLenOffset, asm.Word).WithSymbol("kudp_tx_direct_mtu_linear_check"),
		)
	}
	if opts.ExperimentalTCPOnly {
		instructions = append(instructions,
			asm.Add.Imm(asm.R3, experimentalTCPTXOuterOverhead),
		)
		instructions = append(instructions,
			asm.JGT.Reg(asm.R3, asm.R2, "kudp_tx_direct_mtu_kind_fallback"),
			asm.Mov.Imm(asm.R3, 0).WithSymbol("kudp_tx_direct_mtu_ok"),
		)
	} else if opts.KernelUDPOnly {
		instructions = append(instructions,
			asm.Add.Imm(asm.R3, kernelUDPTXOuterOverhead),
		)
		instructions = append(instructions,
			asm.JGT.Reg(asm.R3, asm.R2, "kudp_tx_direct_mtu_kind_fallback"),
			asm.Mov.Imm(asm.R3, 0).WithSymbol("kudp_tx_direct_mtu_ok"),
		)
	} else {
		instructions = append(instructions,
			asm.LoadMem(asm.R4, asm.RFP, kernelUDPTXFlagsOffset, asm.Word),
			asm.JSet.Imm(asm.R4, int32(kernelUDPTXFlowFlagExperimentalTCP), "kudp_tx_direct_mtu_exp_tcp"),
			asm.Add.Imm(asm.R3, kernelUDPTXOuterOverhead),
			asm.Ja.Label("kudp_tx_direct_mtu_check"),
			asm.Add.Imm(asm.R3, experimentalTCPTXOuterOverhead).WithSymbol("kudp_tx_direct_mtu_exp_tcp"),
			asm.Mov.Reg(asm.R3, asm.R3).WithSymbol("kudp_tx_direct_mtu_check"),
		)
		instructions = append(instructions,
			asm.JGT.Reg(asm.R3, asm.R2, "kudp_tx_direct_mtu_kind_fallback"),
			asm.Mov.Imm(asm.R3, 0).WithSymbol("kudp_tx_direct_mtu_ok"),
		)
	}
	instructions = append(instructions,
		asm.LoadMem(asm.R1, asm.R0, 20, asm.Word),
		asm.StoreMem(asm.RFP, kernelUDPTXIfindexOffset, asm.R1, asm.Word),
	)
	if !pushFlowOuterTCPKfuncPath && !finalizeFlowOuterTCPKfuncPath {
		instructions = append(instructions,
			// Ethernet header.
			asm.LoadMem(asm.R1, asm.R0, 24, asm.Word),
			asm.StoreMem(asm.RFP, kernelUDPTXHeaderOffset, asm.R1, asm.Word),
			asm.LoadMem(asm.R1, asm.R0, 28, asm.Half),
			asm.StoreMem(asm.RFP, kernelUDPTXHeaderOffset+4, asm.R1, asm.Half),
			asm.LoadMem(asm.R1, asm.R0, 32, asm.Half),
			asm.StoreMem(asm.RFP, kernelUDPTXHeaderOffset+6, asm.R1, asm.Half),
			asm.LoadMem(asm.R1, asm.R0, 34, asm.Half),
			asm.StoreMem(asm.RFP, kernelUDPTXHeaderOffset+8, asm.R1, asm.Half),
			asm.LoadMem(asm.R1, asm.R0, 36, asm.Half),
			asm.StoreMem(asm.RFP, kernelUDPTXHeaderOffset+10, asm.R1, asm.Half),
			asm.StoreImm(asm.RFP, kernelUDPTXHeaderOffset+12, 0x0008, asm.Half),
		)
	}
	if udpHeaderKfuncArgsPath {
		if tunnelGSO {
			instructions = append(instructions,
				asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXGSOSegmentLenOffset, asm.Word),
			)
		} else {
			instructions = append(instructions,
				asm.Mov.Reg(asm.R1, asm.R9),
			)
		}
		instructions = append(instructions,
			asm.Mov.Reg(asm.R2, asm.R1),
			asm.Add.Imm(asm.R2, kernelUDPTXOuterOverhead),
			asm.StoreMem(asm.RFP, kernelUDPTXBuildUDPHeaderArgsIPTotalLenOffset, asm.R2, asm.Half),
			asm.Add.Imm(asm.R1, 8+kerneludp.HeaderLen),
			asm.StoreMem(asm.RFP, kernelUDPTXBuildUDPHeaderArgsUDPLenOffset, asm.R1, asm.Half),
			asm.LoadMem(asm.R1, asm.R0, 8, asm.Word),
			asm.StoreMem(asm.RFP, kernelUDPTXBuildUDPHeaderArgsSourceIPOffset, asm.R1, asm.Word),
			asm.LoadMem(asm.R1, asm.R0, 12, asm.Word),
			asm.StoreMem(asm.RFP, kernelUDPTXBuildUDPHeaderArgsDestinationIPOffset, asm.R1, asm.Word),
			asm.LoadMem(asm.R1, asm.R0, 16, asm.Half),
			asm.StoreMem(asm.RFP, kernelUDPTXBuildUDPHeaderArgsSourcePortOffset, asm.R1, asm.Half),
			asm.LoadMem(asm.R1, asm.R0, 18, asm.Half),
			asm.StoreMem(asm.RFP, kernelUDPTXBuildUDPHeaderArgsDestinationPortOffset, asm.R1, asm.Half),
			asm.LoadMem(asm.R1, asm.R0, 30, asm.Half),
			asm.StoreMem(asm.RFP, kernelUDPTXBuildUDPHeaderArgsIPCheckBaseOffset, asm.R1, asm.Half),
			asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXFlowKeyOffset, asm.DWord),
			asm.StoreMem(asm.RFP, kernelUDPTXBuildUDPHeaderArgsFlowIDOffset, asm.R1, asm.DWord),
			asm.StoreImm(asm.RFP, kernelUDPTXBuildUDPHeaderArgsSequenceOffset, 0, asm.Word),
			asm.StoreImm(asm.RFP, kernelUDPTXBuildUDPHeaderArgsSequenceOffset+4, 0, asm.Word),
		)
		if tunnelGSO {
			instructions = append(instructions,
				asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXGSOSegmentLenOffset, asm.Word),
			)
		} else {
			instructions = append(instructions,
				asm.Mov.Reg(asm.R1, asm.R9),
			)
		}
		instructions = append(instructions,
			asm.StoreMem(asm.RFP, kernelUDPTXBuildUDPHeaderArgsPayloadLenOffset, asm.R1, asm.Word),
			asm.StoreImm(asm.RFP, kernelUDPTXBuildUDPHeaderArgsFlagsOffset, 0, asm.Word),
		)
	} else if pushFlowOuterTCPKfuncPath {
		instructions = append(instructions,
			asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXFlowKeyOffset, asm.DWord),
			asm.StoreMem(asm.RFP, kernelUDPTXTIXTPushFlowTCPHeaderArgsFlowIDOffset, asm.R1, asm.DWord),
			asm.StoreMem(asm.RFP, kernelUDPTXTIXTPushFlowTCPHeaderArgsPayloadLenOffset, asm.R9, asm.Word),
			asm.StoreImm(asm.RFP, kernelUDPTXTIXTPushFlowTCPHeaderArgsClearFlagsOffset, 0, asm.Word),
		)
	} else if finalizeFlowOuterTCPKfuncPath {
		var flags int64 = trustIXTIXTTXFinalizeTCPTrustValidatedLen
		if experimentalTCPTXDirectOuterTCPHeaderKfuncPartialChecksumEnabled() {
			flags |= trustIXTIXTTXFinalizeTCPPartialCSUM
		} else if experimentalTCPTXDirectTrustInnerChecksums() {
			flags |= trustIXTIXTTXFinalizeTCPTrustInnerCSUM
		}
		if opts.SKBClearTXOffload {
			flags |= int64(trustIXSKBClearTXOffloadCSUM | trustIXSKBClearTXOffloadEncap)
			if kernelUDPTXDirectSKBClearTXOffloadGSOEnabled() {
				flags |= trustIXSKBClearTXOffloadGSO
			}
		}
		if tunnelGSO {
			instructions = append(instructions,
				asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXGSOSegmentLenOffset, asm.Word),
			)
		} else {
			instructions = append(instructions,
				asm.Mov.Reg(asm.R1, asm.R9),
			)
		}
		instructions = append(instructions,
			asm.LoadMem(asm.R2, asm.RFP, kernelUDPTXFlowKeyOffset, asm.DWord),
			asm.StoreMem(asm.RFP, kernelUDPTXTIXTFinalizeFlowTCPHeaderArgsFlowIDOffset, asm.R2, asm.DWord),
			asm.StoreMem(asm.RFP, kernelUDPTXTIXTFinalizeFlowTCPHeaderArgsPayloadLenOffset, asm.R1, asm.Word),
			asm.StoreImm(asm.RFP, kernelUDPTXTIXTFinalizeFlowTCPHeaderArgsClearFlagsOffset, flags, asm.Word),
		)
	} else if finalizeOuterTCPKfuncPath || pushOuterTCPKfuncPath {
		if tunnelGSO && finalizeOuterTCPKfuncPath {
			instructions = append(instructions,
				asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXGSOSegmentLenOffset, asm.Word),
			)
		} else {
			instructions = append(instructions,
				asm.Mov.Reg(asm.R1, asm.R9),
			)
		}
		instructions = append(instructions,
			asm.Add.Imm(asm.R1, experimentalTCPTXOuterOverhead),
			asm.StoreMem(asm.RFP, kernelUDPTXTIXTFinalizeTCPHeaderArgsIPTotalLenOffset, asm.R1, asm.Half),
			asm.LoadMem(asm.R1, asm.R0, 8, asm.Word),
			asm.StoreMem(asm.RFP, kernelUDPTXTIXTFinalizeTCPHeaderArgsSourceIPOffset, asm.R1, asm.Word),
			asm.LoadMem(asm.R1, asm.R0, 12, asm.Word),
			asm.StoreMem(asm.RFP, kernelUDPTXTIXTFinalizeTCPHeaderArgsDestinationIPOffset, asm.R1, asm.Word),
			asm.LoadMem(asm.R1, asm.R0, 16, asm.Half),
			asm.StoreMem(asm.RFP, kernelUDPTXTIXTFinalizeTCPHeaderArgsSourcePortOffset, asm.R1, asm.Half),
			asm.LoadMem(asm.R1, asm.R0, 18, asm.Half),
			asm.StoreMem(asm.RFP, kernelUDPTXTIXTFinalizeTCPHeaderArgsDestinationPortOffset, asm.R1, asm.Half),
			asm.LoadMem(asm.R1, asm.R0, 38, asm.Half),
			asm.StoreMem(asm.RFP, kernelUDPTXTIXTFinalizeTCPHeaderArgsIPCheckBaseOffset, asm.R1, asm.Half),
			asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXFlowKeyOffset, asm.DWord),
			asm.StoreMem(asm.RFP, kernelUDPTXTIXTFinalizeTCPHeaderArgsFlowIDOffset, asm.R1, asm.DWord),
		)
		if tunnelGSO && finalizeOuterTCPKfuncPath {
			instructions = append(instructions,
				asm.LoadMem(asm.R2, asm.RFP, kernelUDPTXGSOSegmentLenOffset, asm.Word),
			)
		} else {
			instructions = append(instructions,
				asm.Mov.Reg(asm.R2, asm.R9),
			)
		}
		if opts.ExperimentalTCPSkipPlainSequence {
			instructions = append(instructions,
				asm.StoreImm(asm.RFP, kernelUDPTXTIXTFinalizeTCPHeaderArgsSequenceOffset, 0, asm.Word),
				asm.StoreImm(asm.RFP, kernelUDPTXTIXTFinalizeTCPHeaderArgsSequenceOffset+4, 0, asm.Word),
			)
		} else {
			instructions = append(instructions,
				asm.Add.Imm(asm.R2, experimentaltcp.HeaderLen),
				asm.FetchAdd.Mem(asm.R0, asm.R2, asm.DWord, 0),
				asm.Add.Imm(asm.R2, 1),
				asm.StoreMem(asm.RFP, kernelUDPTXTIXTFinalizeTCPHeaderArgsSequenceOffset, asm.R2, asm.DWord),
			)
		}
		if tunnelGSO && finalizeOuterTCPKfuncPath {
			instructions = append(instructions,
				asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXGSOSegmentLenOffset, asm.Word),
			)
		} else {
			instructions = append(instructions,
				asm.Mov.Reg(asm.R1, asm.R9),
			)
		}
		instructions = append(instructions,
			asm.StoreMem(asm.RFP, kernelUDPTXTIXTFinalizeTCPHeaderArgsPayloadLenOffset, asm.R1, asm.Word),
			asm.StoreImm(asm.RFP, kernelUDPTXTIXTFinalizeTCPHeaderArgsFlagsOffset, 0, asm.Word),
		)
	} else {
		instructions = append(instructions,

			// Outer IPv4 header. UDP/TIXU and TCP/TIXT share Ethernet, IPv4
			// source/destination, and sequence allocation; the L4 header and frame
			// layout branch on the per-flow transport flag.
			asm.StoreImm(asm.RFP, kernelUDPTXIPHeaderOffset, 0x0045, asm.Half),
			asm.StoreImm(asm.RFP, kernelUDPTXIPHeaderOffset+4, 0x00400000, asm.Word),
			asm.LoadMem(asm.R1, asm.R0, 8, asm.Word),
			asm.StoreMem(asm.RFP, kernelUDPTXIPHeaderOffset+12, asm.R1, asm.Word),
			asm.LoadMem(asm.R1, asm.R0, 12, asm.Word),
			asm.StoreMem(asm.RFP, kernelUDPTXIPHeaderOffset+16, asm.R1, asm.Word),
		)
	}
	if pushFlowOuterTCPKfuncPath || finalizeFlowOuterTCPKfuncPath || finalizeOuterTCPKfuncPath || pushOuterTCPKfuncPath {
		instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_headers_ready"))
	} else if opts.ExperimentalTCPOnly {
		instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_build_tixt"))
	} else if opts.KernelUDPOnly && !udpHeaderKfuncArgsPath {
		// Outer UDP header.
		// For active tunnel-GSO the skb still carries the full super-packet,
		// but each emitted segment must advertise the per-segment TIXU wire
		// length. The value is R9 for linear packets and was precomputed from
		// skb_shinfo(skb)->gso_size for GSO skbs.
		if tunnelGSO {
			instructions = append(instructions,
				asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXGSOSegmentLenOffset, asm.Word),
			)
		} else {
			instructions = append(instructions,
				asm.Mov.Reg(asm.R1, asm.R9),
			)
		}
		instructions = append(instructions,
			asm.Add.Imm(asm.R1, kernelUDPTXOuterOverhead),
			asm.LoadMem(asm.R2, asm.R0, 30, asm.Half),
			asm.Add.Reg32(asm.R2, asm.R1),
			asm.StoreMem(asm.RFP, kernelUDPTXIPChecksumSumOffset, asm.R2, asm.Word),
			asm.HostTo(asm.BE, asm.R1, asm.Half),
			asm.StoreMem(asm.RFP, kernelUDPTXIPHeaderOffset+2, asm.R1, asm.Half),
			asm.StoreImm(asm.RFP, kernelUDPTXIPHeaderOffset+8, 0x00001140, asm.Word),
			asm.LoadMem(asm.R1, asm.R0, 16, asm.Half),
			asm.StoreMem(asm.RFP, kernelUDPTXUDPHeaderOffset, asm.R1, asm.Half),
			asm.LoadMem(asm.R1, asm.R0, 18, asm.Half),
			asm.StoreMem(asm.RFP, kernelUDPTXUDPHeaderOffset+2, asm.R1, asm.Half),
		)
		if tunnelGSO {
			instructions = append(instructions,
				asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXGSOSegmentLenOffset, asm.Word),
			)
		} else {
			instructions = append(instructions,
				asm.Mov.Reg(asm.R1, asm.R9),
			)
		}
		instructions = append(instructions,
			asm.Add.Imm(asm.R1, 8+kerneludp.HeaderLen),
			asm.HostTo(asm.BE, asm.R1, asm.Half),
			asm.StoreMem(asm.RFP, kernelUDPTXUDPHeaderOffset+4, asm.R1, asm.Half),
			asm.StoreImm(asm.RFP, kernelUDPTXUDPHeaderOffset+6, 0, asm.Half),

			// TIXU frame header.
			asm.StoreImm(asm.RFP, kernelUDPTXFrameHeaderOffset, 0x55584954, asm.Word),
			asm.StoreImm(asm.RFP, kernelUDPTXFrameHeaderOffset+4, 0x20000801, asm.Word),
			asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXFlowKeyOffset, asm.DWord),
			asm.HostTo(asm.BE, asm.R1, asm.DWord),
			asm.StoreMem(asm.RFP, kernelUDPTXFrameHeaderOffset+8, asm.R1, asm.DWord),
		)
		if opts.SkipPlainSequence {
			instructions = append(instructions,
				asm.StoreImm(asm.RFP, kernelUDPTXFrameHeaderOffset+16, 0, asm.Word),
				asm.StoreImm(asm.RFP, kernelUDPTXFrameHeaderOffset+20, 0, asm.Word),
			)
		} else {
			instructions = append(instructions,
				asm.Mov.Imm(asm.R2, 1),
				asm.FetchAdd.Mem(asm.R0, asm.R2, asm.DWord, 0),
				asm.Mov.Reg(asm.R1, asm.R2),
				asm.Add.Imm(asm.R1, 1),
				asm.Mov.Reg(asm.R2, asm.R1),
				asm.HostTo(asm.BE, asm.R2, asm.DWord),
				asm.StoreMem(asm.RFP, kernelUDPTXFrameHeaderOffset+16, asm.R2, asm.DWord),
			)
		}
		if tunnelGSO {
			instructions = append(instructions,
				asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXGSOSegmentLenOffset, asm.Word),
			)
		} else {
			instructions = append(instructions,
				asm.Mov.Reg(asm.R1, asm.R9),
			)
		}
		instructions = append(instructions,
			asm.HostTo(asm.BE, asm.R1, asm.Word),
			asm.StoreMem(asm.RFP, kernelUDPTXFrameHeaderOffset+24, asm.R1, asm.Word),
			asm.StoreImm(asm.RFP, kernelUDPTXFrameHeaderOffset+28, 0, asm.Word),
		)
	} else if !opts.KernelUDPOnly {
		instructions = append(instructions,
			asm.LoadMem(asm.R4, asm.RFP, kernelUDPTXFlagsOffset, asm.Word),
			asm.JSet.Imm(asm.R4, int32(kernelUDPTXFlowFlagExperimentalTCP), "kudp_tx_direct_build_tixt"),

			// Outer UDP header.
			// For active tunnel-GSO the skb still carries the full super-packet,
			// but each emitted segment must advertise the per-segment TIXU wire
			// length. The value is R9 for linear packets and was precomputed from
			// skb_shinfo(skb)->gso_size for GSO skbs.
		)
		if tunnelGSO {
			instructions = append(instructions,
				asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXGSOSegmentLenOffset, asm.Word),
			)
		} else {
			instructions = append(instructions,
				asm.Mov.Reg(asm.R1, asm.R9),
			)
		}
		instructions = append(instructions,
			asm.Add.Imm(asm.R1, kernelUDPTXOuterOverhead),
			asm.LoadMem(asm.R2, asm.R0, 30, asm.Half),
			asm.Add.Reg32(asm.R2, asm.R1),
			asm.StoreMem(asm.RFP, kernelUDPTXIPChecksumSumOffset, asm.R2, asm.Word),
			asm.HostTo(asm.BE, asm.R1, asm.Half),
			asm.StoreMem(asm.RFP, kernelUDPTXIPHeaderOffset+2, asm.R1, asm.Half),
			asm.StoreImm(asm.RFP, kernelUDPTXIPHeaderOffset+8, 0x00001140, asm.Word),
			asm.LoadMem(asm.R1, asm.R0, 16, asm.Half),
			asm.StoreMem(asm.RFP, kernelUDPTXUDPHeaderOffset, asm.R1, asm.Half),
			asm.LoadMem(asm.R1, asm.R0, 18, asm.Half),
			asm.StoreMem(asm.RFP, kernelUDPTXUDPHeaderOffset+2, asm.R1, asm.Half),
		)
		if tunnelGSO {
			instructions = append(instructions,
				asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXGSOSegmentLenOffset, asm.Word),
			)
		} else {
			instructions = append(instructions,
				asm.Mov.Reg(asm.R1, asm.R9),
			)
		}
		instructions = append(instructions,
			asm.Add.Imm(asm.R1, 8+kerneludp.HeaderLen),
			asm.HostTo(asm.BE, asm.R1, asm.Half),
			asm.StoreMem(asm.RFP, kernelUDPTXUDPHeaderOffset+4, asm.R1, asm.Half),
			asm.StoreImm(asm.RFP, kernelUDPTXUDPHeaderOffset+6, 0, asm.Half),

			// TIXU frame header.
			asm.StoreImm(asm.RFP, kernelUDPTXFrameHeaderOffset, 0x55584954, asm.Word),
			asm.StoreImm(asm.RFP, kernelUDPTXFrameHeaderOffset+4, 0x20000801, asm.Word),
			asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXFlowKeyOffset, asm.DWord),
			asm.HostTo(asm.BE, asm.R1, asm.DWord),
			asm.StoreMem(asm.RFP, kernelUDPTXFrameHeaderOffset+8, asm.R1, asm.DWord),
		)
		if opts.SkipPlainSequence {
			instructions = append(instructions,
				asm.StoreImm(asm.RFP, kernelUDPTXFrameHeaderOffset+16, 0, asm.Word),
				asm.StoreImm(asm.RFP, kernelUDPTXFrameHeaderOffset+20, 0, asm.Word),
			)
		} else {
			instructions = append(instructions,
				asm.Mov.Imm(asm.R2, 1),
				asm.FetchAdd.Mem(asm.R0, asm.R2, asm.DWord, 0),
				asm.Mov.Reg(asm.R1, asm.R2),
				asm.Add.Imm(asm.R1, 1),
				asm.Mov.Reg(asm.R2, asm.R1),
				asm.HostTo(asm.BE, asm.R2, asm.DWord),
				asm.StoreMem(asm.RFP, kernelUDPTXFrameHeaderOffset+16, asm.R2, asm.DWord),
			)
		}
		if tunnelGSO {
			instructions = append(instructions,
				asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXGSOSegmentLenOffset, asm.Word),
			)
		} else {
			instructions = append(instructions,
				asm.Mov.Reg(asm.R1, asm.R9),
			)
		}
		instructions = append(instructions,
			asm.HostTo(asm.BE, asm.R1, asm.Word),
			asm.StoreMem(asm.RFP, kernelUDPTXFrameHeaderOffset+24, asm.R1, asm.Word),
			asm.StoreImm(asm.RFP, kernelUDPTXFrameHeaderOffset+28, 0, asm.Word),
			asm.Ja.Label("kudp_tx_direct_headers_ready"),
		)
	}
	if !opts.KernelUDPOnly && !finalizeOuterTCPKfuncPath && !pushOuterTCPKfuncPath && !pushFlowOuterTCPKfuncPath && !finalizeFlowOuterTCPKfuncPath {
		if tunnelGSO {
			instructions = append(instructions,
				asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXGSOSegmentLenOffset, asm.Word).WithSymbol("kudp_tx_direct_build_tixt"),
			)
		} else {
			instructions = append(instructions,
				asm.Mov.Reg(asm.R1, asm.R9).WithSymbol("kudp_tx_direct_build_tixt"),
			)
		}
		instructions = append(instructions,
			// Outer TCP header and TIXT frame header.
			asm.Add.Imm(asm.R1, experimentalTCPTXOuterOverhead),
			asm.LoadMem(asm.R2, asm.R0, 38, asm.Half),
			asm.Add.Reg32(asm.R2, asm.R1),
			asm.StoreMem(asm.RFP, kernelUDPTXIPChecksumSumOffset, asm.R2, asm.Word),
			asm.HostTo(asm.BE, asm.R1, asm.Half),
			asm.StoreMem(asm.RFP, kernelUDPTXIPHeaderOffset+2, asm.R1, asm.Half),
			asm.StoreImm(asm.RFP, kernelUDPTXIPHeaderOffset+8, 0x00000640, asm.Word),
			asm.LoadMem(asm.R1, asm.R0, 16, asm.Half),
			asm.StoreMem(asm.RFP, kernelUDPTXTCPHeaderOffset, asm.R1, asm.Half),
			asm.LoadMem(asm.R1, asm.R0, 18, asm.Half),
			asm.StoreMem(asm.RFP, kernelUDPTXTCPHeaderOffset+2, asm.R1, asm.Half),
		)
		if opts.ExperimentalTCPSkipPlainSequence {
			instructions = append(instructions,
				asm.StoreImm(asm.RFP, kernelUDPTXTCPHeaderOffset+4, 0, asm.Word),
				asm.StoreImm(asm.RFP, kernelUDPTXTCPHeaderOffset+8, 0x01000000, asm.Word),
				asm.StoreImm(asm.RFP, kernelUDPTXTCPHeaderOffset+12, experimentalTCPTXPlainFlagsImmForOptions(opts), asm.Half),
				asm.StoreImm(asm.RFP, kernelUDPTXTCPHeaderOffset+14, 0xffff, asm.Half),
				asm.StoreImm(asm.RFP, kernelUDPTXTCPHeaderOffset+16, 0, asm.Word),
				asm.StoreImm(asm.RFP, kernelUDPTXTCPFrameHeaderOffset, 0x54584954, asm.Word),
				asm.StoreImm(asm.RFP, kernelUDPTXTCPFrameHeaderOffset+4, 0x28000801, asm.Word),
				asm.LoadMem(asm.R2, asm.RFP, kernelUDPTXFlowKeyOffset, asm.DWord),
				asm.HostTo(asm.BE, asm.R2, asm.DWord),
				asm.StoreMem(asm.RFP, kernelUDPTXTCPFrameHeaderOffset+8, asm.R2, asm.DWord),
				asm.StoreImm(asm.RFP, kernelUDPTXTCPFrameHeaderOffset+16, 0, asm.Word),
				asm.StoreImm(asm.RFP, kernelUDPTXTCPFrameHeaderOffset+20, 0, asm.Word),
				asm.StoreImm(asm.RFP, kernelUDPTXTCPFrameHeaderOffset+24, 0, asm.Word),
				asm.StoreImm(asm.RFP, kernelUDPTXTCPFrameHeaderOffset+28, 0, asm.Word),
			)
		} else {
			if tunnelGSO {
				instructions = append(instructions,
					asm.LoadMem(asm.R2, asm.RFP, kernelUDPTXGSOSegmentLenOffset, asm.Word),
				)
			} else {
				instructions = append(instructions,
					asm.Mov.Reg(asm.R2, asm.R9),
				)
			}
			instructions = append(instructions,
				asm.Add.Imm(asm.R2, experimentaltcp.HeaderLen),
				asm.FetchAdd.Mem(asm.R0, asm.R2, asm.DWord, 0),
				asm.Mov.Reg(asm.R1, asm.R2),
				asm.Add.Imm(asm.R1, 1),
				asm.Mov.Reg(asm.R2, asm.R1),
				asm.HostTo(asm.BE, asm.R2, asm.Word),
				asm.StoreMem(asm.RFP, kernelUDPTXTCPHeaderOffset+4, asm.R2, asm.Word),
				asm.StoreImm(asm.RFP, kernelUDPTXTCPHeaderOffset+8, 0x01000000, asm.Word),
				asm.StoreImm(asm.RFP, kernelUDPTXTCPHeaderOffset+12, experimentalTCPTXPlainFlagsImmForOptions(opts), asm.Half),
				asm.StoreImm(asm.RFP, kernelUDPTXTCPHeaderOffset+14, 0xffff, asm.Half),
				asm.StoreImm(asm.RFP, kernelUDPTXTCPHeaderOffset+16, 0, asm.Word),
				asm.StoreImm(asm.RFP, kernelUDPTXTCPFrameHeaderOffset, 0x54584954, asm.Word),
				asm.StoreImm(asm.RFP, kernelUDPTXTCPFrameHeaderOffset+4, 0x28000801, asm.Word),
				asm.LoadMem(asm.R2, asm.RFP, kernelUDPTXFlowKeyOffset, asm.DWord),
				asm.HostTo(asm.BE, asm.R2, asm.DWord),
				asm.StoreMem(asm.RFP, kernelUDPTXTCPFrameHeaderOffset+8, asm.R2, asm.DWord),
				asm.StoreImm(asm.RFP, kernelUDPTXTCPFrameHeaderOffset+16, 0, asm.Word),
				asm.StoreImm(asm.RFP, kernelUDPTXTCPFrameHeaderOffset+20, 0, asm.Word),
				asm.Mov.Reg(asm.R2, asm.R1),
				asm.HostTo(asm.BE, asm.R2, asm.DWord),
				asm.StoreMem(asm.RFP, kernelUDPTXTCPFrameHeaderOffset+24, asm.R2, asm.DWord),
			)
		}
		if tunnelGSO {
			instructions = append(instructions,
				asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXGSOSegmentLenOffset, asm.Word),
			)
		} else {
			instructions = append(instructions,
				asm.Mov.Reg(asm.R1, asm.R9),
			)
		}
		instructions = append(instructions,
			asm.HostTo(asm.BE, asm.R1, asm.Word),
			asm.StoreMem(asm.RFP, kernelUDPTXTCPFrameHeaderOffset+32, asm.R1, asm.Word),
			asm.StoreImm(asm.RFP, kernelUDPTXTCPFrameHeaderOffset+36, 0, asm.Word),
		)
		if tunnelGSO {
			instructions = append(instructions,
				asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXGSOSegmentLenOffset, asm.Word),
			)
		} else {
			instructions = append(instructions,
				asm.Mov.Reg(asm.R1, asm.R9),
			)
		}
		instructions = append(instructions,
			asm.Add.Imm(asm.R1, rejectTCPHeaderLen+experimentaltcp.HeaderLen),
			asm.HostTo(asm.BE, asm.R1, asm.Half),
			asm.LoadMem(asm.R2, asm.RFP, kernelUDPTXIPHeaderOffset+12, asm.Word),
			asm.StoreMem(asm.RFP, kernelUDPTXChecksumPseudoOffset, asm.R2, asm.Word),
			asm.LoadMem(asm.R2, asm.RFP, kernelUDPTXIPHeaderOffset+16, asm.Word),
			asm.StoreMem(asm.RFP, kernelUDPTXChecksumPseudoOffset+4, asm.R2, asm.Word),
			asm.StoreImm(asm.RFP, kernelUDPTXChecksumPseudoOffset+8, 0x00000600, asm.Word),
			asm.StoreMem(asm.RFP, kernelUDPTXChecksumPseudoOffset+10, asm.R1, asm.Half),
		)
	}
	if !opts.KernelUDPOnly {
		checksumOpts := opts
		checksumOpts.KernelUDPOnly = true
		checksumOpts.ExperimentalTCPOnly = false
		if !pushRouteOuterTCPKfuncPath && !pushFlowOuterTCPKfuncPath && !finalizeFlowOuterTCPKfuncPath && preOuterInnerChecksum && kernelUDPTXDirectInnerTCPChecksumEnabledForOptions(checksumOpts) {
			instructions = appendKernelUDPTXDirectInnerTCPChecksumAtOffset(instructions, statsMap, checksumOpts, rejectEthernetHeaderLen, "kudp_tx_direct_inner_tixt_pre_csum", "kudp_tx_direct_fallback")
		}
	}
	if !opts.KernelUDPOnly && !experimentalTCPSkipOuterTCPChecksum() && !outerTCPCsumKfuncPath && !finalizeOuterTCPKfuncPath && !finalizeFlowOuterTCPKfuncPath && !tcpPartialCSUMKfuncPath && !pushOuterTCPKfuncPath && !pushFlowOuterTCPKfuncPath && !pushRouteOuterTCPKfuncPath {
		instructions = append(instructions,
			asm.JGT.Imm(asm.R9, kernelUDPTXTCPChecksumPayloadMax, "kudp_tx_direct_fallback_error"),
		)
		instructions = appendExperimentalTCPTXDirectTCPChecksum(instructions, "kudp_tx_direct_fallback_error")
		instructions = appendStoreNativeHalfFromR0(instructions, kernelUDPTXTCPHeaderOffset+16)
	} else if tcpPartialCSUMKfuncPath {
		instructions = appendKernelUDPTXDirectOuterTCPPseudoPartialChecksum(instructions)
	} else if outerTCPCsumKfuncPath {
		instructions = append(instructions,
			asm.JGT.Imm(asm.R9, kernelUDPTXTCPChecksumPayloadMax, "kudp_tx_direct_fallback_error"),
		)
	}
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_headers_ready"))
	if pushRouteOuterTCPKfuncPath {
		instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_route_kfunc_fallback_continue"))
	}
	if pushFlowOuterTCPKfuncPath {
		instructions = appendKernelUDPTXDirectPushFlowOuterTCPHeaderKfunc(instructions, statsMap, opts, "kudp_tx_direct_adjust_drop")
		instructions = appendHotPathCounter(instructions, statsMap, kernelUDPTXStatSuccess, "kudp_tx_direct_success_counter_done")
		instructions = append(instructions,
			asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXIfindexOffset, asm.Word),
			asm.Mov.Imm(asm.R2, 0),
		)
		if opts.RedirectPeer {
			instructions = append(instructions, asm.FnRedirectPeer.Call())
		} else {
			instructions = append(instructions, asm.FnRedirect.Call())
		}
		instructions = append(instructions, asm.Return())
	} else if pushOuterTCPKfuncPath {
		instructions = appendKernelUDPTXDirectPushOuterTCPHeaderKfunc(instructions, opts, "kudp_tx_direct_adjust_drop")
		instructions = appendHotPathCounter(instructions, statsMap, kernelUDPTXStatSuccess, "kudp_tx_direct_success_counter_done")
		instructions = append(instructions,
			asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXIfindexOffset, asm.Word),
			asm.Mov.Imm(asm.R2, 0),
		)
		if opts.RedirectPeer {
			instructions = append(instructions, asm.FnRedirectPeer.Call())
		} else {
			instructions = append(instructions, asm.FnRedirect.Call())
		}
		instructions = append(instructions, asm.Return())
	} else if pushUDPHeaderKfuncPath {
		instructions = appendKernelUDPTXDirectPushUDPHeaderKfunc(instructions, opts, "kudp_tx_direct_adjust_drop")
		if opts.KernelUDPOnly {
			innerChecksumEnabled := kernelUDPTXDirectInnerTCPChecksumEnabledForOptions(opts)
			if tunnelGSO && innerChecksumEnabled {
				instructions = append(instructions,
					asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXGSOActiveOffset, asm.Word),
					asm.JEq.Imm(asm.R1, 0, "kudp_tx_direct_inner_tcp_post_csum_linear"),
				)
				if statsMap != nil {
					instructions = appendHotPathCounter(instructions, statsMap, kernelUDPTXDirectStatInnerTCPChecksumGSOSkips, "kudp_tx_direct_inner_tcp_post_csum_gso_skip_counter_done")
				}
				instructions = append(instructions,
					asm.Ja.Label("kudp_tx_direct_inner_tcp_post_csum_done").WithSymbol("kudp_tx_direct_inner_tcp_post_csum_gso_skip"),
					asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_inner_tcp_post_csum_linear"),
				)
			}
			if innerChecksumEnabled {
				instructions = appendKernelUDPTXDirectInnerTCPChecksumAtOffset(instructions, statsMap, opts, rejectEthernetHeaderLen+kernelUDPTXOuterOverhead, "kudp_tx_direct_inner_tcp_post_csum", "kudp_tx_direct_drop")
			}
		}
		instructions = appendHotPathCounter(instructions, statsMap, kernelUDPTXStatSuccess, "kudp_tx_direct_success_counter_done")
		instructions = append(instructions,
			asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXIfindexOffset, asm.Word),
			asm.Mov.Imm(asm.R2, 0),
		)
		if opts.RedirectPeer {
			instructions = append(instructions, asm.FnRedirectPeer.Call())
		} else {
			instructions = append(instructions, asm.FnRedirect.Call())
		}
		instructions = append(instructions, asm.Return())
	} else {
		adjustRoomFlags := int64(kernelUDPTCAdjustRoomBaseFlags())
		gsoAdjustRoomFlags := int64(kernelUDPTCTXAdjustRoomFlagsForOptions(opts))
		if !udpHeaderKfuncArgsPath && !finalizeOuterTCPKfuncPath && !finalizeFlowOuterTCPKfuncPath {
			instructions = append(instructions, asm.LoadMem(asm.R0, asm.RFP, kernelUDPTXIPChecksumSumOffset, asm.Word))
			instructions = appendChecksumFold(instructions)
			instructions = appendStoreNetworkHalfFromR0(instructions, kernelUDPTXIPHeaderOffset+10)
		}
		if opts.ExperimentalTCPOnly {
			instructions = append(instructions, asm.Mov.Imm(asm.R2, experimentalTCPTXOuterOverhead))
		} else if opts.KernelUDPOnly {
			instructions = append(instructions, asm.Mov.Imm(asm.R2, kernelUDPTXOuterOverhead))
		} else {
			instructions = append(instructions,
				asm.LoadMem(asm.R4, asm.RFP, kernelUDPTXFlagsOffset, asm.Word),
				asm.Mov.Imm(asm.R2, kernelUDPTXOuterOverhead),
				asm.JSet.Imm(asm.R4, int32(kernelUDPTXFlowFlagExperimentalTCP), "kudp_tx_direct_adjust_tixt"),
				asm.Ja.Label("kudp_tx_direct_adjust_ready"),
				asm.Mov.Imm(asm.R2, experimentalTCPTXOuterOverhead).WithSymbol("kudp_tx_direct_adjust_tixt"),
				asm.Mov.Reg(asm.R2, asm.R2).WithSymbol("kudp_tx_direct_adjust_ready"),
			)
		}
		instructions = append(instructions,
			asm.Mov.Reg(asm.R1, asm.R6),
			asm.Mov.Imm(asm.R3, bpfAdjRoomMAC),
			asm.LoadImm(asm.R4, adjustRoomFlags, asm.DWord),
		)
		if tunnelGSO {
			instructions = append(instructions,
				asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXGSOActiveOffset, asm.Word),
				asm.JEq.Imm(asm.R1, 0, "kudp_tx_direct_adjust_flags_ready"),
			)
			instructions = appendHotPathCounter(instructions, statsMap, kernelUDPTXDirectStatMTUGSOBypasses, "kudp_tx_direct_gso_bypass_counter_done")
			instructions = append(instructions,
				asm.LoadImm(asm.R4, gsoAdjustRoomFlags, asm.DWord),
				asm.Mov.Reg(asm.R4, asm.R4).WithSymbol("kudp_tx_direct_adjust_flags_ready"),
			)
		}
		if opts.ExperimentalTCPOnly {
			instructions = append(instructions, asm.Mov.Imm(asm.R2, experimentalTCPTXOuterOverhead))
		} else if opts.KernelUDPOnly {
			instructions = append(instructions, asm.Mov.Imm(asm.R2, kernelUDPTXOuterOverhead))
		} else {
			instructions = append(instructions,
				asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXFlagsOffset, asm.Word),
				asm.Mov.Imm(asm.R2, kernelUDPTXOuterOverhead),
				asm.JSet.Imm(asm.R1, int32(kernelUDPTXFlowFlagExperimentalTCP), "kudp_tx_direct_adjust_len_tixt"),
				asm.Ja.Label("kudp_tx_direct_adjust_len_ready"),
				asm.Mov.Imm(asm.R2, experimentalTCPTXOuterOverhead).WithSymbol("kudp_tx_direct_adjust_len_tixt"),
				asm.Mov.Reg(asm.R2, asm.R2).WithSymbol("kudp_tx_direct_adjust_len_ready"),
			)
		}
		instructions = append(instructions,
			asm.Mov.Imm(asm.R3, bpfAdjRoomMAC),
			asm.Mov.Reg(asm.R1, asm.R6),
			asm.FnSkbAdjustRoom.Call(),
			asm.JNE.Imm(asm.R0, 0, "kudp_tx_direct_adjust_drop"),
			asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
			asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
		)
		if tunnelGSO && !(opts.ExperimentalTCPOnly && (finalizeOuterTCPKfuncPath || finalizeFlowOuterTCPKfuncPath)) {
			instructions = appendKernelUDPTXDirectPullGSOOuterHeader(instructions, opts, "kudp_tx_direct_post_adjust_header_drop")
		}
		if opts.KernelUDPOnly {
			innerChecksumEnabled := kernelUDPTXDirectInnerTCPChecksumEnabledForOptions(opts)
			if tunnelGSO && innerChecksumEnabled {
				instructions = append(instructions,
					asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXGSOActiveOffset, asm.Word),
					asm.JEq.Imm(asm.R1, 0, "kudp_tx_direct_inner_tcp_post_csum_linear"),
				)
				if statsMap != nil {
					instructions = appendHotPathCounter(instructions, statsMap, kernelUDPTXDirectStatInnerTCPChecksumGSOSkips, "kudp_tx_direct_inner_tcp_post_csum_gso_skip_counter_done")
				}
				instructions = append(instructions,
					asm.Ja.Label("kudp_tx_direct_inner_tcp_post_csum_done").WithSymbol("kudp_tx_direct_inner_tcp_post_csum_gso_skip"),
					asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_inner_tcp_post_csum_linear"),
				)
			}
			if innerChecksumEnabled {
				instructions = appendKernelUDPTXDirectInnerTCPChecksumAtOffset(instructions, statsMap, opts, rejectEthernetHeaderLen+kernelUDPTXOuterOverhead, "kudp_tx_direct_inner_tcp_post_csum", "kudp_tx_direct_drop")
			}
		}
		if opts.ExperimentalTCPOnly {
			if tunnelGSO && (finalizeOuterTCPKfuncPath || finalizeFlowOuterTCPKfuncPath) {
				instructions = append(instructions,
					asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXGSOActiveOffset, asm.Word),
					asm.JNE.Imm(asm.R1, 0, "kudp_tx_direct_exp_tcp_finalize_header"),
				)
			}
			instructions = append(instructions,
				asm.Mov.Reg(asm.R1, asm.R7),
				asm.Add.Imm(asm.R1, rejectEthernetHeaderLen+rejectIPv4HeaderLen+kernelUDPTXTCPFrameHeaderLen),
				asm.JGT.Reg(asm.R1, asm.R8, "kudp_tx_direct_post_adjust_header_drop"),
			)
			if finalizeOuterTCPKfuncPath || finalizeFlowOuterTCPKfuncPath {
				if tunnelGSO {
					instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_exp_tcp_finalize_header"))
				}
			}
			if finalizeFlowOuterTCPKfuncPath {
				instructions = appendKernelUDPTXDirectFinalizeFlowOuterTCPHeaderKfunc(instructions, statsMap, opts, "kudp_tx_direct_post_adjust_header_drop")
			} else if finalizeOuterTCPKfuncPath {
				instructions = appendKernelUDPTXDirectFinalizeOuterTCPHeaderKfunc(instructions, opts, "kudp_tx_direct_post_adjust_header_drop")
			}
		} else if opts.KernelUDPOnly {
			instructions = append(instructions,
				asm.Mov.Reg(asm.R1, asm.R7),
				asm.Add.Imm(asm.R1, rejectEthernetHeaderLen+rejectIPv4HeaderLen+kernelUDPTXUDPFrameHeaderLen),
				asm.JGT.Reg(asm.R1, asm.R8, "kudp_tx_direct_post_adjust_header_drop"),
			)
			if finalizeUDPHeaderKfuncPath {
				instructions = appendKernelUDPTXDirectFinalizeUDPHeaderKfunc(instructions, opts, "kudp_tx_direct_post_adjust_header_drop")
			} else if opts.SkipPlainSequence && opts.BuildUDPHeaderKfunc && opts.BuildUDPHeaderKfuncCall.IsKfuncCall() {
				instructions = appendKernelUDPTXDirectBuildUDPHeaderKfunc(instructions, opts, "kudp_tx_direct_post_adjust_header_drop")
			} else {
				instructions = appendKernelUDPTXDirectStoreHeader(instructions, opts, kernelUDPTXUDPHeaderOffset, kernelUDPTXUDPFrameHeaderLen, "kudp_tx_direct_post_adjust_header_drop")
			}
			instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_stores_done"))
		} else {
			instructions = append(instructions,
				asm.LoadMem(asm.R4, asm.RFP, kernelUDPTXFlagsOffset, asm.Word),
				asm.JSet.Imm(asm.R4, int32(kernelUDPTXFlowFlagExperimentalTCP), "kudp_tx_direct_after_adjust_tixt"),
			)
			checksumOpts := opts
			checksumOpts.KernelUDPOnly = true
			innerChecksumEnabled := kernelUDPTXDirectInnerTCPChecksumEnabledForOptions(checksumOpts)
			if tunnelGSO && innerChecksumEnabled {
				instructions = append(instructions,
					asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXGSOActiveOffset, asm.Word),
					asm.JEq.Imm(asm.R1, 0, "kudp_tx_direct_inner_l4_post_csum_linear"),
				)
				if statsMap != nil {
					instructions = appendHotPathCounter(instructions, statsMap, kernelUDPTXDirectStatInnerTCPChecksumGSOSkips, "kudp_tx_direct_inner_l4_post_csum_gso_skip_counter_done")
				}
				instructions = append(instructions,
					asm.Ja.Label("kudp_tx_direct_inner_l4_post_csum_done").WithSymbol("kudp_tx_direct_inner_l4_post_csum_gso_skip"),
					asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_inner_l4_post_csum_linear"),
				)
			}
			if innerChecksumEnabled {
				instructions = appendKernelUDPTXDirectInnerTCPChecksumAtOffset(instructions, statsMap, checksumOpts, rejectEthernetHeaderLen+kernelUDPTXOuterOverhead, "kudp_tx_direct_inner_l4_post_csum", "kudp_tx_direct_drop")
			}
			instructions = append(instructions,
				asm.Mov.Reg(asm.R1, asm.R7),
				asm.Add.Imm(asm.R1, rejectEthernetHeaderLen+rejectIPv4HeaderLen+kernelUDPTXUDPFrameHeaderLen),
				asm.JGT.Reg(asm.R1, asm.R8, "kudp_tx_direct_post_adjust_header_drop"),
			)
			instructions = appendKernelUDPTXDirectStoreHeader(instructions, opts, kernelUDPTXUDPHeaderOffset, kernelUDPTXUDPFrameHeaderLen, "kudp_tx_direct_post_adjust_header_drop")
			instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_stores_done"))
			instructions = append(instructions,
				asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_after_adjust_tixt"),
			)
			instructions = append(instructions,
				asm.Mov.Reg(asm.R1, asm.R7),
				asm.Add.Imm(asm.R1, rejectEthernetHeaderLen+rejectIPv4HeaderLen+kernelUDPTXTCPFrameHeaderLen),
				asm.JGT.Reg(asm.R1, asm.R8, "kudp_tx_direct_post_adjust_header_drop"),
			)
		}
		if !opts.KernelUDPOnly && !finalizeOuterTCPKfuncPath && !finalizeFlowOuterTCPKfuncPath {
			instructions = appendKernelUDPTXDirectStoreHeader(instructions, opts, kernelUDPTXTCPHeaderOffset, kernelUDPTXTCPFrameHeaderLen, "kudp_tx_direct_post_adjust_header_drop")
		}
		if opts.ExperimentalTCPOnly {
			instructions = append(instructions, asm.Mov.Imm(asm.R0, 0))
		} else {
			instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_stores_done"))
		}
		if outerTCPCsumKfuncPath {
			if !opts.ExperimentalTCPOnly {
				instructions = append(instructions,
					asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXFlagsOffset, asm.Word),
					asm.JSet.Imm(asm.R1, int32(kernelUDPTXFlowFlagExperimentalTCP), "kudp_tx_direct_outer_tcp_csum_needed"),
					asm.Ja.Label("kudp_tx_direct_outer_tcp_csum_skip"),
					asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_outer_tcp_csum_needed"),
				)
			}
			instructions = appendKernelUDPTXDirectOuterTCPCsumKfunc(instructions, statsMap, opts, "kudp_tx_direct_outer_tcp_csum_drop")
			if !opts.ExperimentalTCPOnly {
				instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_outer_tcp_csum_skip"))
			}
		}
		if tcpPartialCSUMKfuncPath {
			instructions = appendKernelUDPTXDirectTCPPartialCSUMKfunc(instructions, opts, "kudp_tx_direct_tcp_partial_csum_drop")
		}
		if !finalizeUDPHeaderKfuncPath && !finalizeOuterTCPKfuncPath && !finalizeFlowOuterTCPKfuncPath && !tcpPartialCSUMKfuncPath {
			if tunnelGSO && opts.SKBClearTXOffload && opts.SKBClearKfuncCall.IsKfuncCall() && !kernelUDPTXDirectSKBClearTXOffloadActiveGSOEnabled() {
				instructions = append(instructions,
					asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXGSOActiveOffset, asm.Word),
					asm.JNE.Imm(asm.R1, 0, "kudp_tx_direct_skb_clear_tx_offload_skip_active_gso"),
				)
				instructions = appendKernelUDPTXDirectSKBClearTXOffload(instructions, opts, "kudp_tx_direct_skb_clear_tx_offload_drop")
				instructions = append(instructions,
					asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_skb_clear_tx_offload_skip_active_gso"),
				)
			} else {
				instructions = appendKernelUDPTXDirectSKBClearTXOffload(instructions, opts, "kudp_tx_direct_skb_clear_tx_offload_drop")
			}
		}
		if tunnelGSO {
			instructions = append(instructions,
				asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXGSOActiveOffset, asm.Word),
				asm.JEq.Imm(asm.R1, 0, "kudp_tx_direct_gso_success_counter_skip"),
			)
			instructions = appendHotPathCounter(instructions, statsMap, kernelUDPTXDirectStatGSOSuccesses, "kudp_tx_direct_gso_success_counter_done")
			instructions = append(instructions,
				asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_gso_success_counter_skip"),
			)
		}
		instructions = appendHotPathCounter(instructions, statsMap, kernelUDPTXStatSuccess, "kudp_tx_direct_success_counter_done")
		instructions = append(instructions,
			asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXIfindexOffset, asm.Word),
			asm.Mov.Imm(asm.R2, 0),
		)
		if opts.RedirectPeer {
			instructions = append(instructions, asm.FnRedirectPeer.Call())
		} else {
			instructions = append(instructions, asm.FnRedirect.Call())
		}
		instructions = append(instructions, asm.Return())
	}
	if !opts.KernelUDPOnly && !experimentalTCPSkipOuterTCPChecksum() && !finalizeOuterTCPKfuncPath && !finalizeFlowOuterTCPKfuncPath && !tcpPartialCSUMKfuncPath && !pushOuterTCPKfuncPath && !pushFlowOuterTCPKfuncPath && !pushRouteOuterTCPKfuncPath {
		instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_fallback_error"))
		instructions = appendCounter(instructions, statsMap, kernelUDPTXStatErrors, "kudp_tx_direct_error_counter_done")
		instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_fallback"))
	}
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_adjust_drop"))
	instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatAdjustDrops, "kudp_tx_direct_adjust_drop_counter_done")
	instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_drop"))
	if !pushUDPHeaderKfuncPath && !pushOuterTCPKfuncPath && !pushFlowOuterTCPKfuncPath {
		instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_post_adjust_header_drop"))
		instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatPostAdjustHeaderDrops, "kudp_tx_direct_post_adjust_header_drop_counter_done")
		instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_drop"))
	}
	if !pushUDPHeaderKfuncPath && !pushOuterTCPKfuncPath && !pushFlowOuterTCPKfuncPath && opts.SKBClearTXOffload && opts.SKBClearKfuncCall.IsKfuncCall() {
		instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_skb_clear_tx_offload_drop"))
		instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatSKBClearTXOffloadDrops, "kudp_tx_direct_skb_clear_tx_offload_drop_counter_done")
		instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_drop"))
	}
	if outerTCPCsumKfuncPath {
		instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_outer_tcp_csum_drop"))
		instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatOuterTCPChecksumKfuncDrops, "kudp_tx_direct_outer_tcp_csum_drop_counter_done")
		instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_drop"))
	}
	if tcpPartialCSUMKfuncPath {
		instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_tcp_partial_csum_drop"))
		instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatOuterTCPChecksumKfuncDrops, "kudp_tx_direct_tcp_partial_csum_drop_counter_done")
		instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_drop"))
	}
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_drop"))
	instructions = appendCounter(instructions, statsMap, kernelUDPTXStatDrops, "kudp_tx_direct_drop_counter_done")
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, tcActShot),
		asm.Return(),
	)
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_route_miss"))
	instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatRouteMisses, "kudp_tx_direct_route_miss_counter_done")
	instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_route_miss_fallback"))
	if opts.ExperimentalTCPOnly || opts.KernelUDPOnly {
		instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_transport_fallback"))
		instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatRouteFlowZeroFallbacks, "kudp_tx_direct_transport_fallback_counter_done")
		instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_fallback"))
	}
	if !opts.DirectOnly {
		instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_route_flow_zero"))
		instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatRouteFlowZeroFallbacks, "kudp_tx_direct_route_flow_zero_counter_done")
		instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_fallback"))
	}
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_route_bypass"))
	instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_route_miss_fallback"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_flow_miss"))
	instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatFlowMisses, "kudp_tx_direct_flow_miss_counter_done")
	instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_fallback"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_secure_flow_fallback"))
	instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatSecureFlowFallbacks, "kudp_tx_direct_secure_flow_fallback_counter_done")
	instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_fallback"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_non_ipv4_fallback"))
	instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatNonIPv4Fallbacks, "kudp_tx_direct_non_ipv4_fallback_counter_done")
	instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_fallback"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_fragment_fallback"))
	instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatFragmentFallbacks, "kudp_tx_direct_fragment_fallback_counter_done")
	instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_fallback"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_len_short_fallback"))
	instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatLenMismatches, "kudp_tx_direct_len_short_mismatch_counter_done")
	instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatLenShortFallbacks, "kudp_tx_direct_len_short_counter_done")
	instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_fallback"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_len_gso_fallback"))
	instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatLenMismatches, "kudp_tx_direct_len_gso_mismatch_counter_done")
	instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatLenGSOFallbacks, "kudp_tx_direct_len_gso_counter_done")
	instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_fallback"))
	if tunnelGSO {
		instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_gso_size_zero_fallback"))
		instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatMTUGSOSizeZeroFallbacks, "kudp_tx_direct_gso_size_zero_counter_done")
		instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_len_gso_fallback"))
	}
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_mtu_kind_fallback"))
	if tunnelGSO {
		instructions = append(instructions,
			asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXGSOActiveOffset, asm.Word),
			asm.JNE.Imm(asm.R1, 0, "kudp_tx_direct_mtu_gso_fallback"),
		)
	}
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_mtu_linear_fallback"))
	instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatMTULinearFallbacks, "kudp_tx_direct_mtu_linear_counter_done")
	instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_mtu_fallback"))
	if tunnelGSO {
		instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_mtu_gso_fallback"))
		instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatMTUGSOFallbacks, "kudp_tx_direct_mtu_gso_counter_done")
		instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_mtu_fallback"))
	}
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_mtu_fallback"))
	instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatMTUFallbacks, "kudp_tx_direct_mtu_fallback_counter_done")
	instructions = append(instructions, asm.Ja.Label("kudp_tx_direct_fallback"))
	if opts.DirectOnly {
		instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_fallback"))
		instructions = append(instructions,
			asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXRouteFlagsOffset, asm.Word),
			asm.JSet.Imm(asm.R1, kernelUDPTXRouteFlagDirectOnly, "kudp_tx_direct_direct_only_drop"),
			asm.Ja.Label("kudp_tx_direct_direct_only_continue"),
			asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_route_miss_fallback"),
			asm.Ja.Label("kudp_tx_direct_direct_only_continue"),
			asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_direct_only_drop"),
		)
		instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatDirectOnlyDrops, "kudp_tx_direct_direct_only_drop_counter_done")
		return append(instructions,
			asm.Mov.Imm(asm.R0, tcActShot),
			asm.Return(),
			asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_direct_only_continue"),
		)
	}
	return append(instructions,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_route_miss_fallback"),
		asm.Ja.Label("kudp_tx_direct_continue"),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_fallback"),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_continue"),
	)
}

func appendKernelUDPTXDirectFlowHashMix(instructions asm.Instructions, readyLabel string) asm.Instructions {
	instructions = append(instructions, asm.Mov.Reg(asm.R3, asm.R2).WithSymbol(readyLabel))
	if kernelUDPTXDirectStrongFlowHashEnabled() {
		return append(instructions,
			asm.Mov.Reg(asm.R3, asm.R3).WithSymbol(readyLabel+"_strong"),
			asm.RSh.Imm(asm.R3, 11),
			asm.Xor.Reg(asm.R2, asm.R3),
			asm.Mov.Reg(asm.R3, asm.R2),
			asm.LSh.Imm(asm.R3, 7),
			asm.Xor.Reg(asm.R2, asm.R3),
			asm.Mov.Reg(asm.R3, asm.R2),
			asm.RSh.Imm(asm.R3, 13),
			asm.Xor.Reg(asm.R2, asm.R3),
			asm.Mov.Reg(asm.R3, asm.R2),
			asm.LSh.Imm(asm.R3, 17),
			asm.Xor.Reg(asm.R2, asm.R3),
			asm.Mov.Reg(asm.R3, asm.R2),
			asm.RSh.Imm(asm.R3, 16),
			asm.Xor.Reg(asm.R2, asm.R3),
			asm.Mov.Reg(asm.R3, asm.R2),
			asm.RSh.Imm(asm.R3, 5),
			asm.Xor.Reg(asm.R2, asm.R3),
		)
	}
	return append(instructions,
		asm.RSh.Imm(asm.R3, 16),
		asm.Xor.Reg(asm.R2, asm.R3),
		asm.Mov.Reg(asm.R3, asm.R2),
		asm.RSh.Imm(asm.R3, 8),
		asm.Xor.Reg(asm.R2, asm.R3),
	)
}

func appendKernelUDPTXDirectInnerFlowHash(instructions asm.Instructions, readyLabel string, fallbackLabel string) asm.Instructions {
	if kernelUDPTXDirectPortFlowHashEnabled() {
		return appendKernelUDPTXDirectInnerPortFlowHash(instructions, readyLabel, fallbackLabel)
	}
	instructions = append(instructions,
		asm.LoadMem(asm.R4, asm.R7, 30, asm.Word), // Inner IPv4 destination address; helpers clobber R1-R5.
		asm.Mov.Reg(asm.R2, asm.R7),
		asm.Add.Imm(asm.R2, rejectEthernetHeaderLen+rejectIPv4HeaderLen),
		asm.JGT.Reg(asm.R2, asm.R8, fallbackLabel),
		asm.LoadMem(asm.R2, asm.R7, 26, asm.Word), // Inner IPv4 source address.
		asm.Xor.Reg(asm.R2, asm.R4),
		asm.LoadMem(asm.R3, asm.R7, 23, asm.Byte), // Inner protocol.
		asm.LSh.Imm(asm.R3, 16),
		asm.Xor.Reg(asm.R2, asm.R3),
		asm.LoadMem(asm.R3, asm.R7, 14, asm.Byte),
		asm.And.Imm(asm.R3, 0x0f),
		asm.LSh.Imm(asm.R3, 2),
		asm.Mov.Reg(asm.R4, asm.R7),
		asm.Add.Imm(asm.R4, rejectEthernetHeaderLen),
		asm.Add.Reg(asm.R4, asm.R3),
		asm.Mov.Reg(asm.R3, asm.R4),
		asm.Add.Imm(asm.R3, 4),
		asm.JGT.Reg(asm.R3, asm.R8, readyLabel),
		asm.LoadMem(asm.R3, asm.R4, 0, asm.Word), // First 4 bytes of TCP/UDP header: src/dst ports.
		asm.Xor.Reg(asm.R2, asm.R3),
	)
	return appendKernelUDPTXDirectFlowHashMix(instructions, readyLabel)
}

func appendKernelUDPTXDirectInnerPortFlowHash(instructions asm.Instructions, readyLabel string, fallbackLabel string) asm.Instructions {
	instructions = append(instructions,
		asm.LoadMem(asm.R4, asm.R7, 30, asm.Word), // Inner IPv4 destination address; helpers clobber R1-R5.
		asm.Mov.Reg(asm.R2, asm.R7),
		asm.Add.Imm(asm.R2, rejectEthernetHeaderLen+rejectIPv4HeaderLen),
		asm.JGT.Reg(asm.R2, asm.R8, fallbackLabel),
		asm.LoadMem(asm.R2, asm.R7, 26, asm.Word), // Inner IPv4 source address.
		asm.Xor.Reg(asm.R2, asm.R4),
		asm.LoadMem(asm.R3, asm.R7, 23, asm.Byte), // Inner protocol.
		asm.LSh.Imm(asm.R3, 16),
		asm.Xor.Reg(asm.R2, asm.R3),
		asm.LoadMem(asm.R3, asm.R7, 14, asm.Byte),
		asm.And.Imm(asm.R3, 0x0f),
		asm.LSh.Imm(asm.R3, 2),
		asm.Mov.Reg(asm.R4, asm.R7),
		asm.Add.Imm(asm.R4, rejectEthernetHeaderLen),
		asm.Add.Reg(asm.R4, asm.R3),
		asm.Mov.Reg(asm.R3, asm.R4),
		asm.Add.Imm(asm.R3, 4),
		asm.JGT.Reg(asm.R3, asm.R8, readyLabel),
		asm.LoadMem(asm.R3, asm.R4, 0, asm.Word), // First 4 bytes of TCP/UDP header: src/dst ports.
		asm.Mov.Reg(asm.R5, asm.R3).WithSymbol(readyLabel+"_port"),
		asm.RSh.Imm(asm.R5, 8),
		asm.Xor.Reg(asm.R2, asm.R5),
		asm.Mov.Reg(asm.R5, asm.R3),
		asm.RSh.Imm(asm.R5, 24),
		asm.Xor.Reg(asm.R2, asm.R5),
		asm.Xor.Reg(asm.R2, asm.R3),
	)
	return appendKernelUDPTXDirectFlowHashMix(instructions, readyLabel)
}

func appendKernelUDPTXDirectSKBFlowHash(instructions asm.Instructions, readyLabel string) asm.Instructions {
	return append(instructions,
		asm.Mov.Reg(asm.R1, asm.R6).WithSymbol(readyLabel+"_skb_hash"),
		asm.FnGetHashRecalc.Call(),
		asm.Mov.Reg(asm.R2, asm.R0).WithSymbol(readyLabel),
	)
}

func appendKernelUDPTXDirectRouteCache(instructions asm.Instructions, routeCacheMap *cebpf.Map) asm.Instructions {
	if routeCacheMap == nil {
		return instructions
	}
	return append(instructions,
		asm.StoreImm(asm.RFP, kernelUDPTXRouteKeyOffset, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, routeCacheMap.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, kernelUDPTXRouteKeyOffset),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "kudp_tx_direct_route_cache_miss"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.Word),
		asm.JEq.Imm(asm.R1, 0, "kudp_tx_direct_route_cache_miss"),
		asm.LoadMem(asm.R1, asm.R7, 30, asm.Word),
		asm.LoadMem(asm.R2, asm.R0, 4, asm.Word),
		asm.JEq.Imm(asm.R2, 0, "kudp_tx_direct_route_cache_prefix_ready"),
		asm.LoadImm(asm.R3, 0xffffffff, asm.DWord),
		asm.Mov.Imm(asm.R4, 32),
		asm.Sub.Reg(asm.R4, asm.R2),
		asm.LSh.Reg(asm.R3, asm.R4),
		asm.And.Reg(asm.R1, asm.R3),
		asm.Mov.Reg(asm.R1, asm.R1).WithSymbol("kudp_tx_direct_route_cache_prefix_ready"),
		asm.LoadMem(asm.R3, asm.R0, 8, asm.Word),
		asm.JNE.Reg(asm.R1, asm.R3, "kudp_tx_direct_route_cache_miss"),
		asm.LoadMem(asm.R1, asm.R0, 12, asm.Word),
		asm.JEq.Imm(asm.R1, 0, "kudp_tx_direct_route_cache_hit"),
		asm.LoadMem(asm.R1, asm.R7, 30, asm.Word),
		asm.LoadMem(asm.R2, asm.R0, 16, asm.Word),
		asm.JEq.Imm(asm.R2, 0, "kudp_tx_direct_route_cache_exception_ready"),
		asm.LoadImm(asm.R3, 0xffffffff, asm.DWord),
		asm.Mov.Imm(asm.R4, 32),
		asm.Sub.Reg(asm.R4, asm.R2),
		asm.LSh.Reg(asm.R3, asm.R4),
		asm.And.Reg(asm.R1, asm.R3),
		asm.Mov.Reg(asm.R1, asm.R1).WithSymbol("kudp_tx_direct_route_cache_exception_ready"),
		asm.LoadMem(asm.R3, asm.R0, 20, asm.Word),
		asm.JEq.Reg(asm.R1, asm.R3, "kudp_tx_direct_route_cache_miss"),
		asm.Add.Imm(asm.R0, kernelUDPTXRouteCacheRouteOffset).WithSymbol("kudp_tx_direct_route_cache_hit"),
		asm.StoreMem(asm.RFP, kernelUDPTXRoutePtrOffset, asm.R0, asm.DWord),
		asm.Ja.Label("kudp_tx_direct_route_ready"),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_route_cache_miss"),
	)
}

func appendKernelUDPTXDirectSKBClearTXOffload(instructions asm.Instructions, opts kernelUDPTXDirectProgramOptions, errorLabel string) asm.Instructions {
	if !opts.SKBClearTXOffload || !opts.SKBClearKfuncCall.IsKfuncCall() {
		return instructions
	}
	flags := int32(trustIXSKBClearTXOffloadCSUM | trustIXSKBClearTXOffloadEncap)
	if kernelUDPTXDirectSKBClearTXOffloadGSOEnabled() {
		flags |= trustIXSKBClearTXOffloadGSO
	}
	return append(instructions,
		asm.Mov.Reg(asm.R1, asm.R6).WithSymbol("kudp_tx_direct_skb_clear_tx_offload"),
		asm.Mov.Imm(asm.R2, flags),
		opts.SKBClearKfuncCall,
		asm.JNE.Imm(asm.R0, 0, errorLabel),
		asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
		asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_skb_clear_tx_offload_done"),
	)
}

func appendKernelUDPTXDirectPullGSOOuterHeader(instructions asm.Instructions, opts kernelUDPTXDirectProgramOptions, errorLabel string) asm.Instructions {
	const udpPullLen = rejectEthernetHeaderLen + rejectIPv4HeaderLen + kernelUDPTXUDPFrameHeaderLen
	const tcpPullLen = rejectEthernetHeaderLen + rejectIPv4HeaderLen + kernelUDPTXTCPFrameHeaderLen

	instructions = append(instructions,
		asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXGSOActiveOffset, asm.Word),
		asm.JEq.Imm(asm.R1, 0, "kudp_tx_direct_post_adjust_pull_done"),
	)
	if opts.ExperimentalTCPOnly {
		instructions = append(instructions, asm.Mov.Imm(asm.R2, tcpPullLen))
	} else if opts.KernelUDPOnly {
		instructions = append(instructions, asm.Mov.Imm(asm.R2, udpPullLen))
	} else {
		instructions = append(instructions,
			asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXFlagsOffset, asm.Word),
			asm.Mov.Imm(asm.R2, udpPullLen),
			asm.JSet.Imm(asm.R1, int32(kernelUDPTXFlowFlagExperimentalTCP), "kudp_tx_direct_post_adjust_pull_tixt"),
			asm.Ja.Label("kudp_tx_direct_post_adjust_pull_len_ready"),
			asm.Mov.Imm(asm.R2, tcpPullLen).WithSymbol("kudp_tx_direct_post_adjust_pull_tixt"),
			asm.Mov.Reg(asm.R2, asm.R2).WithSymbol("kudp_tx_direct_post_adjust_pull_len_ready"),
		)
	}
	return append(instructions,
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.FnSkbPullData.Call(),
		asm.JNE.Imm(asm.R0, 0, errorLabel),
		asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
		asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_post_adjust_pull_done"),
	)
}

func appendKernelUDPTXDirectStoreHeader(instructions asm.Instructions, opts kernelUDPTXDirectProgramOptions, l4Offset int16, l4Len int32, errorLabel string) asm.Instructions {
	if opts.StoreHeaderKfunc && opts.StoreHeaderKfuncCall.IsKfuncCall() {
		return append(instructions,
			asm.Mov.Reg(asm.R1, asm.R6).WithSymbol("kudp_tx_direct_store_header_kfunc"),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, kernelUDPTXHeaderOffset),
			asm.Mov.Reg(asm.R3, asm.RFP),
			asm.Add.Imm(asm.R3, kernelUDPTXIPHeaderOffset),
			asm.Mov.Reg(asm.R4, asm.RFP),
			asm.Add.Imm(asm.R4, int32(l4Offset)),
			asm.Mov.Imm(asm.R5, l4Len),
			opts.StoreHeaderKfuncCall,
			asm.JNE.Imm(asm.R0, 0, errorLabel),
			asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
			asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
			asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_store_header_kfunc_done"),
		)
	}
	instructions = appendStackToPacketStores(instructions, kernelUDPTXHeaderOffset, 0, rejectEthernetHeaderLen)
	instructions = appendStackToPacketStores(instructions, kernelUDPTXIPHeaderOffset, rejectEthernetHeaderLen, rejectIPv4HeaderLen)
	return appendStackToPacketStores(instructions, l4Offset, rejectEthernetHeaderLen+rejectIPv4HeaderLen, int(l4Len))
}

func appendKernelUDPTXDirectBuildUDPHeaderKfunc(instructions asm.Instructions, opts kernelUDPTXDirectProgramOptions, errorLabel string) asm.Instructions {
	return append(instructions,
		asm.Mov.Reg(asm.R1, asm.R6).WithSymbol("kudp_tx_direct_build_udp_header_kfunc"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, kernelUDPTXBuildUDPHeaderArgsOffset),
		opts.BuildUDPHeaderKfuncCall,
		asm.JNE.Imm(asm.R0, 0, errorLabel),
		asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
		asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_build_udp_header_kfunc_done"),
	)
}

func appendKernelUDPTXDirectFinalizeUDPHeaderKfunc(instructions asm.Instructions, opts kernelUDPTXDirectProgramOptions, errorLabel string) asm.Instructions {
	var flags int32
	if opts.SKBClearTXOffload {
		flags = int32(trustIXSKBClearTXOffloadCSUM | trustIXSKBClearTXOffloadEncap)
		if kernelUDPTXDirectSKBClearTXOffloadGSOEnabled() {
			flags |= trustIXSKBClearTXOffloadGSO
		}
	}
	if kernelUDPTXDirectUDPHeaderPartialChecksumEnabled() {
		flags |= trustIXKUDPTXUDPHeaderPartialCSUM
	}
	return append(instructions,
		asm.Mov.Reg(asm.R1, asm.R6).WithSymbol("kudp_tx_direct_finalize_udp_header_kfunc"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, kernelUDPTXBuildUDPHeaderArgsOffset),
		asm.Mov.Imm(asm.R3, flags),
		opts.FinalizeUDPKfuncCall,
		asm.JNE.Imm(asm.R0, 0, errorLabel),
		asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
		asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_finalize_udp_header_kfunc_done"),
	)
}

func appendKernelUDPTXDirectPushUDPHeaderKfunc(instructions asm.Instructions, opts kernelUDPTXDirectProgramOptions, errorLabel string) asm.Instructions {
	flags := int32(0)
	if kernelUDPTXDirectUDPHeaderPartialChecksumEnabled() {
		flags |= trustIXKUDPTXUDPHeaderPartialCSUM
	}
	return append(instructions,
		asm.Mov.Reg(asm.R1, asm.R6).WithSymbol("kudp_tx_direct_push_udp_header_kfunc"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, kernelUDPTXPushUDPHeaderArgsOffset),
		asm.Mov.Imm(asm.R3, flags),
		opts.PushUDPHeaderKfuncCall,
		asm.JNE.Imm(asm.R0, 0, errorLabel),
		asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
		asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_push_udp_header_kfunc_done"),
	)
}

func appendKernelUDPTXDirectOuterTCPCsumKfunc(instructions asm.Instructions, statsMap *cebpf.Map, opts kernelUDPTXDirectProgramOptions, errorLabel string) asm.Instructions {
	if !opts.OuterTCPCsumKfunc || !opts.OuterTCPCsumKfuncCall.IsKfuncCall() {
		return instructions
	}
	instructions = append(instructions,
		asm.Mov.Reg(asm.R1, asm.R6).WithSymbol("kudp_tx_direct_outer_tcp_csum_kfunc"),
		asm.Mov.Imm(asm.R2, 0),
		opts.OuterTCPCsumKfuncCall,
		asm.JNE.Imm(asm.R0, 0, errorLabel),
		asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
		asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_outer_tcp_csum_kfunc_done"),
	)
	if statsMap != nil {
		instructions = appendHotPathCounter(instructions, statsMap, kernelUDPTXDirectStatOuterTCPChecksumKfuncFixes, "kudp_tx_direct_outer_tcp_csum_counter_done")
	}
	return instructions
}

func appendKernelUDPTXDirectOuterTCPPseudoPartialChecksum(instructions asm.Instructions) asm.Instructions {
	instructions = append(instructions,
		asm.Mov.Imm(asm.R1, 0),
		asm.Mov.Reg(asm.R0, asm.R1),
	)
	instructions = appendStackNetworkHalfChecksumAdd(instructions, kernelUDPTXChecksumPseudoOffset)
	instructions = appendStackNetworkHalfChecksumAdd(instructions, kernelUDPTXChecksumPseudoOffset+2)
	instructions = appendStackNetworkHalfChecksumAdd(instructions, kernelUDPTXChecksumPseudoOffset+4)
	instructions = appendStackNetworkHalfChecksumAdd(instructions, kernelUDPTXChecksumPseudoOffset+6)
	instructions = appendStackNetworkHalfChecksumAdd(instructions, kernelUDPTXChecksumPseudoOffset+8)
	instructions = appendStackNetworkHalfChecksumAdd(instructions, kernelUDPTXChecksumPseudoOffset+10)
	instructions = appendChecksumFold(instructions)
	return append(instructions,
		asm.Xor.Imm(asm.R0, 0xffff),
		asm.And.Imm(asm.R0, 0xffff),
		asm.StoreMem(asm.RFP, kernelUDPTXTCPHeaderOffset+16, asm.R0, asm.Half),
	)
}

func appendKernelUDPTXDirectTCPPartialCSUMKfunc(instructions asm.Instructions, opts kernelUDPTXDirectProgramOptions, errorLabel string) asm.Instructions {
	if !opts.TCPPartialCSUMKfunc || !opts.TCPPartialCSUMKfuncCall.IsKfuncCall() {
		return instructions
	}
	var flags int32
	if opts.SKBClearTXOffload && kernelUDPTXDirectSKBClearTXOffloadGSOEnabled() {
		flags |= trustIXSKBClearTXOffloadGSO
	}
	return append(instructions,
		asm.Mov.Reg(asm.R1, asm.R6).WithSymbol("kudp_tx_direct_tcp_partial_csum_kfunc"),
		asm.Mov.Imm(asm.R2, flags),
		opts.TCPPartialCSUMKfuncCall,
		asm.JNE.Imm(asm.R0, 0, errorLabel),
		asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
		asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_tcp_partial_csum_kfunc_done"),
	)
}

func appendKernelUDPTXDirectFinalizeOuterTCPHeaderKfunc(instructions asm.Instructions, opts kernelUDPTXDirectProgramOptions, errorLabel string) asm.Instructions {
	if !opts.OuterTCPKfunc || !opts.OuterTCPKfuncCall.IsKfuncCall() {
		return instructions
	}
	var flags int32
	if experimentalTCPTXDirectOuterTCPHeaderKfuncPartialChecksumEnabled() {
		flags |= trustIXTIXTTXFinalizeTCPPartialCSUM
	} else if experimentalTCPTXDirectTrustInnerChecksums() {
		flags |= trustIXTIXTTXFinalizeTCPTrustInnerCSUM
	}
	if opts.SKBClearTXOffload {
		flags |= int32(trustIXSKBClearTXOffloadCSUM | trustIXSKBClearTXOffloadEncap)
		if kernelUDPTXDirectSKBClearTXOffloadGSOEnabled() {
			flags |= trustIXSKBClearTXOffloadGSO
		}
	}
	return append(instructions,
		asm.Mov.Reg(asm.R1, asm.R6).WithSymbol("kudp_tx_direct_finalize_outer_tcp_header_kfunc"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, kernelUDPTXTIXTFinalizeTCPHeaderArgsOffset),
		asm.Mov.Imm(asm.R3, flags),
		opts.OuterTCPKfuncCall,
		asm.JNE.Imm(asm.R0, 0, errorLabel),
		asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
		asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_finalize_outer_tcp_header_kfunc_done"),
	)
}

func appendKernelUDPTXDirectPushOuterTCPHeaderKfunc(instructions asm.Instructions, opts kernelUDPTXDirectProgramOptions, errorLabel string) asm.Instructions {
	if !opts.PushTCPHeaderKfunc || !opts.PushTCPHeaderKfuncCall.IsKfuncCall() {
		return instructions
	}
	var flags int32
	if experimentalTCPTXDirectOuterTCPHeaderKfuncPartialChecksumEnabled() {
		flags |= trustIXTIXTTXFinalizeTCPPartialCSUM
	}
	if opts.SKBClearTXOffload {
		flags |= int32(trustIXSKBClearTXOffloadCSUM | trustIXSKBClearTXOffloadEncap)
		if kernelUDPTXDirectSKBClearTXOffloadGSOEnabled() {
			flags |= trustIXSKBClearTXOffloadGSO
		}
	}
	return append(instructions,
		asm.Mov.Reg(asm.R1, asm.R6).WithSymbol("kudp_tx_direct_push_outer_tcp_header_kfunc"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, kernelUDPTXTIXTPushTCPHeaderArgsOffset),
		asm.Mov.Imm(asm.R3, flags),
		opts.PushTCPHeaderKfuncCall,
		asm.JNE.Imm(asm.R0, 0, errorLabel),
		asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
		asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_push_outer_tcp_header_kfunc_done"),
	)
}

func appendKernelUDPTXDirectPushFlowOuterTCPHeaderKfunc(instructions asm.Instructions, statsMap *cebpf.Map, opts kernelUDPTXDirectProgramOptions, errorLabel string) asm.Instructions {
	if !opts.PushFlowTCPHeaderKfunc || !opts.PushFlowTCPHeaderKfuncCall.IsKfuncCall() {
		return instructions
	}
	var flags int32
	if experimentalTCPTXDirectOuterTCPHeaderKfuncPartialChecksumEnabled() {
		flags |= trustIXTIXTTXFinalizeTCPPartialCSUM
	} else if experimentalTCPTXDirectTrustInnerChecksums() {
		flags |= trustIXTIXTTXFinalizeTCPTrustInnerCSUM
	}
	if opts.SKBClearTXOffload {
		flags |= int32(trustIXSKBClearTXOffloadCSUM | trustIXSKBClearTXOffloadEncap)
		if kernelUDPTXDirectSKBClearTXOffloadGSOEnabled() {
			flags |= trustIXSKBClearTXOffloadGSO
		}
	}
	instructions = append(instructions,
		asm.StoreImm(asm.RFP, kernelUDPTXTIXTPushFlowTCPHeaderArgsClearFlagsOffset, int64(flags), asm.Word),
		asm.LoadMem(asm.R2, asm.RFP, kernelUDPTXFlowPtrOffset, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.R6).WithSymbol("kudp_tx_direct_push_flow_outer_tcp_header_kfunc"),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, kernelUDPTXTIXTPushFlowTCPHeaderArgsOffset),
		opts.PushFlowTCPHeaderKfuncCall,
	)
	if !experimentalTCPHotPathStats() {
		return append(instructions,
			asm.JNE.Imm(asm.R0, 0, errorLabel),
			asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
			asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
			asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_push_flow_outer_tcp_header_kfunc_done"),
		)
	}
	instructions = append(instructions,
		asm.JEq.Imm(asm.R0, 0, "kudp_tx_direct_push_flow_outer_tcp_header_kfunc_ok"),
		asm.JEq.Imm(asm.R0, -int32(unix.EINVAL), "kudp_tx_direct_push_flow_outer_tcp_header_kfunc_einval"),
		asm.JEq.Imm(asm.R0, -int32(unix.EPROTONOSUPPORT), "kudp_tx_direct_push_flow_outer_tcp_header_kfunc_eprotonosupport"),
		asm.JEq.Imm(asm.R0, -int32(unix.ENOMEM), "kudp_tx_direct_push_flow_outer_tcp_header_kfunc_enomem"),
		asm.JEq.Imm(asm.R0, -int32(unix.EMSGSIZE), "kudp_tx_direct_push_flow_outer_tcp_header_kfunc_emsgsize"),
		asm.JEq.Imm(asm.R0, -int32(unix.EFAULT), "kudp_tx_direct_push_flow_outer_tcp_header_kfunc_efault"),
		asm.JEq.Imm(asm.R0, -int32(unix.EIO), "kudp_tx_direct_push_flow_outer_tcp_header_kfunc_eio"),
		asm.JEq.Imm(asm.R0, -int32(unix.EBADMSG), "kudp_tx_direct_push_flow_outer_tcp_header_kfunc_ebadmsg"),
		asm.JEq.Imm(asm.R0, -int32(unix.ENODEV), "kudp_tx_direct_push_flow_outer_tcp_header_kfunc_enodev"),
		asm.JEq.Imm(asm.R0, -int32(unix.EPERM), "kudp_tx_direct_push_flow_outer_tcp_header_kfunc_eperm"),
		asm.JEq.Imm(asm.R0, -int32(unix.ENOSPC), "kudp_tx_direct_push_flow_outer_tcp_header_kfunc_enospc"),
		asm.JEq.Imm(asm.R0, -int32(unix.EAGAIN), "kudp_tx_direct_push_flow_outer_tcp_header_kfunc_eagain"),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_push_flow_outer_tcp_header_kfunc_other"),
	)
	instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatPushFlowTCPHeaderKfuncOtherDrops, "kudp_tx_direct_push_flow_outer_tcp_header_kfunc_other_counter_done")
	instructions = append(instructions,
		asm.Ja.Label(errorLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_push_flow_outer_tcp_header_kfunc_einval"),
	)
	instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEINVAL, "kudp_tx_direct_push_flow_outer_tcp_header_kfunc_einval_counter_done")
	instructions = append(instructions,
		asm.Ja.Label(errorLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_push_flow_outer_tcp_header_kfunc_eprotonosupport"),
	)
	instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEPROTONOSUPPORT, "kudp_tx_direct_push_flow_outer_tcp_header_kfunc_eprotonosupport_counter_done")
	instructions = append(instructions,
		asm.Ja.Label(errorLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_push_flow_outer_tcp_header_kfunc_enomem"),
	)
	instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatPushFlowTCPHeaderKfuncENOMEM, "kudp_tx_direct_push_flow_outer_tcp_header_kfunc_enomem_counter_done")
	instructions = append(instructions,
		asm.Ja.Label(errorLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_push_flow_outer_tcp_header_kfunc_emsgsize"),
	)
	instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEMSGSIZE, "kudp_tx_direct_push_flow_outer_tcp_header_kfunc_emsgsize_counter_done")
	instructions = append(instructions,
		asm.Ja.Label(errorLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_push_flow_outer_tcp_header_kfunc_efault"),
	)
	instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEFAULT, "kudp_tx_direct_push_flow_outer_tcp_header_kfunc_efault_counter_done")
	instructions = append(instructions,
		asm.Ja.Label(errorLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_push_flow_outer_tcp_header_kfunc_eio"),
	)
	instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEIO, "kudp_tx_direct_push_flow_outer_tcp_header_kfunc_eio_counter_done")
	instructions = append(instructions,
		asm.Ja.Label(errorLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_push_flow_outer_tcp_header_kfunc_ebadmsg"),
	)
	instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEBADMSG, "kudp_tx_direct_push_flow_outer_tcp_header_kfunc_ebadmsg_counter_done")
	instructions = append(instructions,
		asm.Ja.Label(errorLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_push_flow_outer_tcp_header_kfunc_enodev"),
	)
	instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatPushFlowTCPHeaderKfuncENODEV, "kudp_tx_direct_push_flow_outer_tcp_header_kfunc_enodev_counter_done")
	instructions = append(instructions,
		asm.Ja.Label(errorLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_push_flow_outer_tcp_header_kfunc_eperm"),
	)
	instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEPERM, "kudp_tx_direct_push_flow_outer_tcp_header_kfunc_eperm_counter_done")
	instructions = append(instructions,
		asm.Ja.Label(errorLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_push_flow_outer_tcp_header_kfunc_enospc"),
	)
	instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatPushFlowTCPHeaderKfuncENOSPC, "kudp_tx_direct_push_flow_outer_tcp_header_kfunc_enospc_counter_done")
	instructions = append(instructions,
		asm.Ja.Label(errorLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_push_flow_outer_tcp_header_kfunc_eagain"),
	)
	instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEAGAIN, "kudp_tx_direct_push_flow_outer_tcp_header_kfunc_eagain_counter_done")
	instructions = append(instructions,
		asm.Ja.Label(errorLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_push_flow_outer_tcp_header_kfunc_ok"),
	)
	instructions = appendHotPathCounter(instructions, statsMap, kernelUDPTXDirectStatPushFlowTCPHeaderKfuncSuccesses, "kudp_tx_direct_push_flow_outer_tcp_header_kfunc_success_counter_done")
	return append(instructions,
		asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
		asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_push_flow_outer_tcp_header_kfunc_done"),
	)
}

func appendKernelUDPTXDirectFinalizeFlowOuterTCPHeaderKfunc(instructions asm.Instructions, statsMap *cebpf.Map, opts kernelUDPTXDirectProgramOptions, errorLabel string) asm.Instructions {
	if !opts.FinalizeFlowTCPHeaderKfunc || !opts.FinalizeFlowTCPHeaderKfuncCall.IsKfuncCall() {
		return instructions
	}
	instructions = append(instructions,
		asm.LoadMem(asm.R2, asm.RFP, kernelUDPTXFlowPtrOffset, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.R6).WithSymbol("kudp_tx_direct_finalize_flow_outer_tcp_header_kfunc"),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, kernelUDPTXTIXTFinalizeFlowTCPHeaderArgsOffset),
		opts.FinalizeFlowTCPHeaderKfuncCall,
	)
	if !experimentalTCPHotPathStats() {
		return append(instructions,
			asm.JNE.Imm(asm.R0, 0, errorLabel),
			asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
			asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
			asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_finalize_flow_outer_tcp_header_kfunc_done"),
		)
	}
	instructions = append(instructions,
		asm.JEq.Imm(asm.R0, 0, "kudp_tx_direct_finalize_flow_outer_tcp_header_kfunc_ok"),
		asm.JEq.Imm(asm.R0, -int32(unix.EPROTONOSUPPORT), "kudp_tx_direct_finalize_flow_outer_tcp_header_kfunc_unsupported"),
		asm.Ja.Label(errorLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_finalize_flow_outer_tcp_header_kfunc_unsupported"),
	)
	instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatPushFlowTCPHeaderKfuncEPROTONOSUPPORT, "kudp_tx_direct_finalize_flow_outer_tcp_header_kfunc_unsupported_counter_done")
	instructions = append(instructions,
		asm.Ja.Label(errorLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_finalize_flow_outer_tcp_header_kfunc_ok"),
	)
	instructions = appendHotPathCounter(instructions, statsMap, kernelUDPTXDirectStatPushFlowTCPHeaderKfuncSuccesses, "kudp_tx_direct_finalize_flow_outer_tcp_header_kfunc_success_counter_done")
	return append(instructions,
		asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
		asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_finalize_flow_outer_tcp_header_kfunc_done"),
	)
}

func appendKernelUDPTXDirectOnlyCaptureDrop(instructions asm.Instructions, statsMap *cebpf.Map, txRouteMap *cebpf.Map, label string, fallbackLabel string) asm.Instructions {
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, 0).WithSymbol(label),
	)
	instructions = appendReloadIPv4PacketPointers(instructions, fallbackLabel)
	instructions = append(instructions,
		asm.LoadMem(asm.R1, asm.R7, 30, asm.Word), // Inner IPv4 destination address.
		asm.StoreImm(asm.RFP, kernelUDPTXRouteKeyOffset, 32, asm.Word),
		asm.StoreMem(asm.RFP, kernelUDPTXRouteKeyOffset+4, asm.R1, asm.Word),
		asm.LoadMapPtr(asm.R1, txRouteMap.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, kernelUDPTXRouteKeyOffset),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, fallbackLabel),
		asm.LoadMem(asm.R1, asm.R0, 76, asm.Word),
		asm.JSet.Imm(asm.R1, kernelUDPTXRouteFlagDirectOnly, label+"_drop"),
		asm.Ja.Label(fallbackLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol(label+"_drop"),
	)
	instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatDirectOnlyDrops, label+"_counter_done")
	return append(instructions,
		asm.Mov.Imm(asm.R0, tcActShot),
		asm.Return(),
	)
}

func appendStackToPacketStores(instructions asm.Instructions, stackOffset int16, packetOffset int16, length int) asm.Instructions {
	for copied := 0; copied < length; {
		remaining := length - copied
		size := asm.Word
		width := 4
		if remaining < 4 {
			if remaining >= 2 {
				size = asm.Half
				width = 2
			} else {
				size = asm.Byte
				width = 1
			}
		}
		instructions = append(instructions,
			asm.LoadMem(asm.R1, asm.RFP, stackOffset+int16(copied), size),
			asm.StoreMem(asm.R7, packetOffset+int16(copied), asm.R1, size),
		)
		copied += width
	}
	return instructions
}

func appendRejectNoReplyDrop(instructions asm.Instructions, statsMap *cebpf.Map) asm.Instructions {
	instructions = append(instructions,
		asm.Mov.Reg(asm.R4, asm.R7),
		asm.Add.Imm(asm.R4, 34),
		asm.JGT.Reg(asm.R4, asm.R8, "reject_reply_needed"),
		asm.LoadMem(asm.R9, asm.R7, 14, asm.Byte),
		asm.And.Imm(asm.R9, 0x0f),
		asm.JLT.Imm(asm.R9, 5, "reject_reply_needed"),
		asm.LSh.Imm(asm.R9, 2),
		asm.LoadMem(asm.R4, asm.R7, 20, asm.Half), // IPv4 flags/fragment offset.
		asm.JSet.Imm(asm.R4, ipv4FragmentMaskLittleEndian, "reject_reply_needed"),
		asm.Mov.Reg(asm.R3, asm.R7),
		asm.Add.Imm(asm.R3, 14),
		asm.Add.Reg(asm.R3, asm.R9), // L4 header.
		asm.LoadMem(asm.R4, asm.R7, 23, asm.Byte),
		asm.JEq.Imm(asm.R4, ipProtocolTCP, "reject_tcp_check"),
		asm.JEq.Imm(asm.R4, ipProtocolICMP, "reject_icmp_check"),
		asm.Ja.Label("reject_icmp_unreachable"),
		asm.Mov.Reg(asm.R4, asm.R3).WithSymbol("reject_tcp_check"),
		asm.Add.Imm(asm.R4, 14),
		asm.JGT.Reg(asm.R4, asm.R8, "reject_reply_needed"),
		asm.LoadMem(asm.R4, asm.R3, 13, asm.Byte),
		asm.JSet.Imm(asm.R4, 0x04, "reject_no_reply_drop"), // TCP RST never receives a reject reply.
		asm.Ja.Label("reject_tcp_reset"),
		asm.Mov.Reg(asm.R4, asm.R3).WithSymbol("reject_icmp_check"),
		asm.Add.Imm(asm.R4, 1),
		asm.JGT.Reg(asm.R4, asm.R8, "reject_reply_needed"),
		asm.LoadMem(asm.R4, asm.R3, 0, asm.Byte),
		asm.JEq.Imm(asm.R4, 0, "reject_icmp_unreachable"),  // echo reply
		asm.JEq.Imm(asm.R4, 8, "reject_icmp_unreachable"),  // echo request
		asm.JEq.Imm(asm.R4, 13, "reject_icmp_unreachable"), // timestamp
		asm.JEq.Imm(asm.R4, 14, "reject_icmp_unreachable"), // timestamp reply
		asm.JEq.Imm(asm.R4, 15, "reject_icmp_unreachable"), // information request
		asm.JEq.Imm(asm.R4, 16, "reject_icmp_unreachable"), // information reply
		asm.JEq.Imm(asm.R4, 17, "reject_icmp_unreachable"), // address mask request
		asm.JEq.Imm(asm.R4, 18, "reject_icmp_unreachable"), // address mask reply
		asm.Ja.Label("reject_no_reply_drop"),
	)
	instructions = appendRejectTCPReset(instructions, statsMap, "reject_tcp_reset")
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("reject_tcp_reset_error"))
	instructions = appendCounter(instructions, statsMap, 19, "reject_tcp_reset_error_done")
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, tcActShot),
		asm.Return(),
	)
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("reject_no_reply_drop"))
	instructions = appendCounter(instructions, statsMap, 17, "reject_no_reply_drop_done")
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, tcActShot),
		asm.Return(),
	)
	instructions = appendRejectICMPUnreachable(instructions, statsMap, "reject_icmp_unreachable")
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("reject_icmp_unreachable_error"))
	instructions = appendCounter(instructions, statsMap, 21, "reject_icmp_unreachable_error_done")
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, tcActShot),
		asm.Return(),
	)
	return append(instructions,
		asm.LoadMem(asm.R9, asm.R6, skbLenOffset, asm.Word).WithSymbol("reject_reply_needed"),
		asm.Mov.Imm(asm.R0, 0),
	)
}

func appendRejectNoReplyDropWithLabels(instructions asm.Instructions, statsMap *cebpf.Map, prefix string, doneLabel string) asm.Instructions {
	replyNeeded := prefix + "_reply_needed"
	tcpCheck := prefix + "_tcp_check"
	icmpCheck := prefix + "_icmp_check"
	tcpReset := prefix + "_tcp_reset"
	tcpResetError := prefix + "_tcp_reset_error"
	noReplyDrop := prefix + "_no_reply_drop"
	icmpUnreachable := prefix + "_icmp_unreachable"
	icmpUnreachableError := prefix + "_icmp_unreachable_error"
	instructions = append(instructions,
		asm.Mov.Reg(asm.R4, asm.R7),
		asm.Add.Imm(asm.R4, 34),
		asm.JGT.Reg(asm.R4, asm.R8, replyNeeded),
		asm.LoadMem(asm.R9, asm.R7, 14, asm.Byte),
		asm.And.Imm(asm.R9, 0x0f),
		asm.JLT.Imm(asm.R9, 5, replyNeeded),
		asm.LSh.Imm(asm.R9, 2),
		asm.LoadMem(asm.R4, asm.R7, 20, asm.Half),
		asm.JSet.Imm(asm.R4, ipv4FragmentMaskLittleEndian, replyNeeded),
		asm.Mov.Reg(asm.R3, asm.R7),
		asm.Add.Imm(asm.R3, 14),
		asm.Add.Reg(asm.R3, asm.R9),
		asm.LoadMem(asm.R4, asm.R7, 23, asm.Byte),
		asm.JEq.Imm(asm.R4, ipProtocolTCP, tcpCheck),
		asm.JEq.Imm(asm.R4, ipProtocolICMP, icmpCheck),
		asm.Ja.Label(icmpUnreachable),
		asm.Mov.Reg(asm.R4, asm.R3).WithSymbol(tcpCheck),
		asm.Add.Imm(asm.R4, 14),
		asm.JGT.Reg(asm.R4, asm.R8, replyNeeded),
		asm.LoadMem(asm.R4, asm.R3, 13, asm.Byte),
		asm.JSet.Imm(asm.R4, 0x04, noReplyDrop),
		asm.Ja.Label(tcpReset),
		asm.Mov.Reg(asm.R4, asm.R3).WithSymbol(icmpCheck),
		asm.Add.Imm(asm.R4, 1),
		asm.JGT.Reg(asm.R4, asm.R8, replyNeeded),
		asm.LoadMem(asm.R4, asm.R3, 0, asm.Byte),
		asm.JEq.Imm(asm.R4, 0, icmpUnreachable),
		asm.JEq.Imm(asm.R4, 8, icmpUnreachable),
		asm.JEq.Imm(asm.R4, 13, icmpUnreachable),
		asm.JEq.Imm(asm.R4, 14, icmpUnreachable),
		asm.JEq.Imm(asm.R4, 15, icmpUnreachable),
		asm.JEq.Imm(asm.R4, 16, icmpUnreachable),
		asm.JEq.Imm(asm.R4, 17, icmpUnreachable),
		asm.JEq.Imm(asm.R4, 18, icmpUnreachable),
		asm.Ja.Label(noReplyDrop),
	)
	instructions = appendRejectTCPReset(instructions, statsMap, tcpReset)
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol(tcpResetError))
	instructions = appendCounter(instructions, statsMap, 19, tcpResetError+"_done")
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, tcActShot),
		asm.Return(),
	)
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol(noReplyDrop))
	instructions = appendCounter(instructions, statsMap, 17, noReplyDrop+"_done")
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, tcActShot),
		asm.Return(),
	)
	instructions = appendRejectICMPUnreachable(instructions, statsMap, icmpUnreachable)
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol(icmpUnreachableError))
	instructions = appendCounter(instructions, statsMap, 21, icmpUnreachableError+"_done")
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, tcActShot),
		asm.Return(),
	)
	return append(instructions,
		asm.LoadMem(asm.R9, asm.R6, skbLenOffset, asm.Word).WithSymbol(replyNeeded),
		asm.Ja.Label(doneLabel),
	)
}

func appendTTLExceededFastPath(instructions asm.Instructions, statsMap *cebpf.Map, prefix string, doneLabel string) asm.Instructions {
	fallback := prefix + "_fallback"
	icmpCheck := prefix + "_icmp_check"
	buildReply := prefix + "_icmp_time_exceeded"
	noReplyDrop := prefix + "_no_reply_drop"
	errorLabel := prefix + "_icmp_error"
	instructions = append(instructions,
		asm.LoadMem(asm.R4, asm.R7, rejectEthernetHeaderLen+8, asm.Byte), // IPv4 TTL.
		asm.JGT.Imm(asm.R4, 1, doneLabel),
		asm.LoadMem(asm.R4, asm.R7, rejectEthernetHeaderLen, asm.Byte),
		asm.JNE.Imm(asm.R4, 0x45, fallback), // First fast-path version handles standard IPv4 without options.
		asm.LoadMem(asm.R4, asm.R7, rejectEthernetHeaderLen+6, asm.Half),
		asm.JSet.Imm(asm.R4, ipv4FragmentMaskLittleEndian, fallback),
		asm.Mov.Reg(asm.R4, asm.R7),
		asm.Add.Imm(asm.R4, rejectEthernetHeaderLen+rejectICMPQuoteLen),
		asm.JGT.Reg(asm.R4, asm.R8, fallback),
		asm.LoadMem(asm.R4, asm.R7, rejectEthernetHeaderLen+2, asm.Half),
		asm.And.Imm(asm.R4, 0xffff),
		asm.HostTo(asm.BE, asm.R4, asm.Half),
		asm.JLT.Imm(asm.R4, rejectICMPQuoteLen, fallback),
		asm.LoadMem(asm.R4, asm.R7, rejectEthernetHeaderLen+9, asm.Byte),
		asm.JEq.Imm(asm.R4, ipProtocolICMP, icmpCheck),
		asm.Ja.Label(buildReply),
		asm.LoadMem(asm.R4, asm.R7, rejectEthernetHeaderLen+rejectIPv4HeaderLen, asm.Byte).WithSymbol(icmpCheck),
		asm.JEq.Imm(asm.R4, 0, buildReply),  // echo reply
		asm.JEq.Imm(asm.R4, 8, buildReply),  // echo request
		asm.JEq.Imm(asm.R4, 13, buildReply), // timestamp
		asm.JEq.Imm(asm.R4, 14, buildReply), // timestamp reply
		asm.JEq.Imm(asm.R4, 15, buildReply), // information request
		asm.JEq.Imm(asm.R4, 16, buildReply), // information reply
		asm.JEq.Imm(asm.R4, 17, buildReply), // address mask request
		asm.JEq.Imm(asm.R4, 18, buildReply), // address mask reply
		asm.Ja.Label(noReplyDrop),
		asm.Mov.Imm(asm.R0, 0).WithSymbol(buildReply),
		asm.LoadMem(asm.R1, asm.R7, 6, asm.Half),
		asm.StoreMem(asm.RFP, rejectEthernetOffset, asm.R1, asm.Half),
		asm.LoadMem(asm.R1, asm.R7, 8, asm.Half),
		asm.StoreMem(asm.RFP, rejectEthernetOffset+2, asm.R1, asm.Half),
		asm.LoadMem(asm.R1, asm.R7, 10, asm.Half),
		asm.StoreMem(asm.RFP, rejectEthernetOffset+4, asm.R1, asm.Half),
		asm.LoadMem(asm.R1, asm.R7, 0, asm.Half),
		asm.StoreMem(asm.RFP, rejectEthernetOffset+6, asm.R1, asm.Half),
		asm.LoadMem(asm.R1, asm.R7, 2, asm.Half),
		asm.StoreMem(asm.RFP, rejectEthernetOffset+8, asm.R1, asm.Half),
		asm.LoadMem(asm.R1, asm.R7, 4, asm.Half),
		asm.StoreMem(asm.RFP, rejectEthernetOffset+10, asm.R1, asm.Half),
		asm.LoadMem(asm.R1, asm.R7, 12, asm.Half),
		asm.StoreMem(asm.RFP, rejectEthernetOffset+12, asm.R1, asm.Half),
		asm.StoreImm(asm.RFP, rejectIPOffset, 0x38000045, asm.Word),
		asm.StoreImm(asm.RFP, rejectIPOffset+4, 0, asm.Word),
		asm.StoreImm(asm.RFP, rejectIPOffset+8, 0x00000140, asm.Word),
		asm.LoadMem(asm.R1, asm.R7, rejectEthernetHeaderLen+16, asm.Word),
		asm.StoreMem(asm.RFP, rejectIPOffset+12, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R7, rejectEthernetHeaderLen+12, asm.Word),
		asm.StoreMem(asm.RFP, rejectIPOffset+16, asm.R1, asm.Word),
		asm.StoreImm(asm.RFP, rejectICMPOffset, 0x000b, asm.Half),
		asm.StoreImm(asm.RFP, rejectICMPOffset+2, 0, asm.Half),
		asm.StoreImm(asm.RFP, rejectICMPOffset+4, 0, asm.Word),
		asm.LoadMem(asm.R1, asm.R7, rejectEthernetHeaderLen, asm.Word),
		asm.StoreMem(asm.RFP, rejectICMPQuoteOffset, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R7, rejectEthernetHeaderLen+4, asm.Word),
		asm.StoreMem(asm.RFP, rejectICMPQuoteOffset+4, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R7, rejectEthernetHeaderLen+8, asm.Word),
		asm.StoreMem(asm.RFP, rejectICMPQuoteOffset+8, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R7, rejectEthernetHeaderLen+12, asm.Word),
		asm.StoreMem(asm.RFP, rejectICMPQuoteOffset+12, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R7, rejectEthernetHeaderLen+16, asm.Word),
		asm.StoreMem(asm.RFP, rejectICMPQuoteOffset+16, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R7, rejectEthernetHeaderLen+20, asm.Word),
		asm.StoreMem(asm.RFP, rejectICMPQuoteOffset+20, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R7, rejectEthernetHeaderLen+24, asm.Word),
		asm.StoreMem(asm.RFP, rejectICMPQuoteOffset+24, asm.R1, asm.Word),
	)
	instructions = appendIPv4Checksum(instructions, rejectIPOffset, errorLabel)
	instructions = appendStoreNetworkHalfFromR0(instructions, rejectIPOffset+10)
	instructions = appendStackChecksum(instructions, rejectICMPOffset, rejectICMPHeaderLen+rejectICMPQuoteLen, errorLabel)
	instructions = appendStoreNetworkHalfFromR0(instructions, rejectICMPOffset+2)
	instructions = append(instructions,
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R2, rejectICMPUnreachableWireLen),
		asm.Mov.Imm(asm.R3, 0),
		asm.FnSkbChangeTail.Call(),
		asm.JNE.Imm(asm.R0, 0, errorLabel),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R2, 0),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, rejectEthernetOffset),
		asm.Mov.Imm(asm.R4, rejectEthernetHeaderLen),
		asm.Mov.Imm(asm.R5, 0),
		asm.FnSkbStoreBytes.Call(),
		asm.JNE.Imm(asm.R0, 0, errorLabel),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R2, rejectEthernetHeaderLen),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, rejectIPOffset),
		asm.Mov.Imm(asm.R4, rejectIPv4HeaderLen),
		asm.Mov.Imm(asm.R5, 0),
		asm.FnSkbStoreBytes.Call(),
		asm.JNE.Imm(asm.R0, 0, errorLabel),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R2, rejectEthernetHeaderLen+rejectIPv4HeaderLen),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, rejectICMPOffset),
		asm.Mov.Imm(asm.R4, rejectICMPHeaderLen+rejectICMPQuoteLen),
		asm.Mov.Imm(asm.R5, 0),
		asm.FnSkbStoreBytes.Call(),
		asm.JNE.Imm(asm.R0, 0, errorLabel),
	)
	instructions = appendCounter(instructions, statsMap, tcTTLExceededICMPGeneratedStat, prefix+"_generated_done")
	instructions = append(instructions,
		asm.LoadMem(asm.R1, asm.R6, skbIfindexOffset, asm.Word),
		asm.Mov.Imm(asm.R2, 0),
		asm.FnRedirect.Call(),
		asm.Return(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol(fallback),
	)
	instructions = appendCounter(instructions, statsMap, tcTTLExceededFallbacksStat, fallback+"_counter_done")
	instructions = append(instructions, asm.Ja.Label(doneLabel))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol(noReplyDrop))
	instructions = appendCounter(instructions, statsMap, tcTTLExceededNoReplyDropsStat, noReplyDrop+"_counter_done")
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, tcActShot),
		asm.Return(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol(errorLabel),
	)
	instructions = appendCounter(instructions, statsMap, tcTTLExceededICMPErrorsStat, errorLabel+"_counter_done")
	return append(instructions,
		asm.Mov.Imm(asm.R0, tcActShot),
		asm.Return(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol(doneLabel),
	)
}

func appendRejectTCPReset(instructions asm.Instructions, statsMap *cebpf.Map, label string) asm.Instructions {
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, 0).WithSymbol(label),
		asm.Mov.Reg(asm.R4, asm.R3),
		asm.Add.Imm(asm.R4, 20),
		asm.JGT.Reg(asm.R4, asm.R8, "reject_tcp_reset_error"),
		asm.LoadMem(asm.R4, asm.R3, 12, asm.Byte),
		asm.RSh.Imm(asm.R4, 4),
		asm.JLT.Imm(asm.R4, 5, "reject_tcp_reset_error"),
		asm.LSh.Imm(asm.R4, 2),
		asm.StoreMem(asm.RFP, rejectPseudoOffset, asm.R4, asm.Word),
		asm.LoadMem(asm.R5, asm.R7, 16, asm.Half),
		asm.And.Imm(asm.R5, 0xffff),
		asm.HostTo(asm.BE, asm.R5, asm.Half),
		asm.Mov.Reg(asm.R1, asm.R9),
		asm.Add.Reg(asm.R1, asm.R4),
		asm.JGT.Reg(asm.R1, asm.R5, "reject_tcp_reset_error"),
		asm.Sub.Reg(asm.R5, asm.R1),
		asm.StoreMem(asm.RFP, rejectPseudoOffset+12, asm.R5, asm.Word),
		asm.LoadMem(asm.R4, asm.R3, 13, asm.Byte),
		asm.StoreMem(asm.RFP, rejectPseudoOffset+16, asm.R4, asm.Word),
		asm.Mov.Reg(asm.R1, asm.R4),
		asm.And.Imm(asm.R1, 0x02),
		asm.JEq.Imm(asm.R1, 0, "reject_tcp_payload_syn_done"),
		asm.Add.Imm(asm.R5, 1),
		asm.StoreMem(asm.RFP, rejectPseudoOffset+12, asm.R5, asm.Word),
		asm.Mov.Reg(asm.R1, asm.R4).WithSymbol("reject_tcp_payload_syn_done"),
		asm.And.Imm(asm.R1, 0x01),
		asm.JEq.Imm(asm.R1, 0, "reject_tcp_payload_done"),
		asm.Add.Imm(asm.R5, 1),
		asm.StoreMem(asm.RFP, rejectPseudoOffset+12, asm.R5, asm.Word),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("reject_tcp_payload_done"),
		asm.LoadMem(asm.R1, asm.R7, 6, asm.Half),
		asm.StoreMem(asm.RFP, rejectEthernetOffset, asm.R1, asm.Half),
		asm.LoadMem(asm.R1, asm.R7, 8, asm.Half),
		asm.StoreMem(asm.RFP, rejectEthernetOffset+2, asm.R1, asm.Half),
		asm.LoadMem(asm.R1, asm.R7, 10, asm.Half),
		asm.StoreMem(asm.RFP, rejectEthernetOffset+4, asm.R1, asm.Half),
		asm.LoadMem(asm.R1, asm.R7, 0, asm.Half),
		asm.StoreMem(asm.RFP, rejectEthernetOffset+6, asm.R1, asm.Half),
		asm.LoadMem(asm.R1, asm.R7, 2, asm.Half),
		asm.StoreMem(asm.RFP, rejectEthernetOffset+8, asm.R1, asm.Half),
		asm.LoadMem(asm.R1, asm.R7, 4, asm.Half),
		asm.StoreMem(asm.RFP, rejectEthernetOffset+10, asm.R1, asm.Half),
		asm.LoadMem(asm.R1, asm.R7, 12, asm.Half),
		asm.StoreMem(asm.RFP, rejectEthernetOffset+12, asm.R1, asm.Half),
		asm.StoreImm(asm.RFP, rejectIPOffset, 0x28000045, asm.Word),
		asm.StoreImm(asm.RFP, rejectIPOffset+4, 0, asm.Word),
		asm.StoreImm(asm.RFP, rejectIPOffset+8, 0x00000640, asm.Word),
		asm.LoadMem(asm.R1, asm.R7, 30, asm.Word),
		asm.StoreMem(asm.RFP, rejectIPOffset+12, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R7, 26, asm.Word),
		asm.StoreMem(asm.RFP, rejectIPOffset+16, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R3, 2, asm.Half),
		asm.StoreMem(asm.RFP, rejectTCPOffset, asm.R1, asm.Half),
		asm.LoadMem(asm.R1, asm.R3, 0, asm.Half),
		asm.StoreMem(asm.RFP, rejectTCPOffset+2, asm.R1, asm.Half),
		asm.LoadMem(asm.R4, asm.RFP, rejectPseudoOffset+16, asm.Word),
		asm.And.Imm(asm.R4, 0x10),
		asm.JEq.Imm(asm.R4, 0, "reject_tcp_rst_no_ack"),
		asm.LoadMem(asm.R1, asm.R3, 8, asm.Word),
		asm.StoreMem(asm.RFP, rejectTCPOffset+4, asm.R1, asm.Word),
		asm.StoreImm(asm.RFP, rejectTCPOffset+8, 0, asm.Word),
		asm.StoreImm(asm.RFP, rejectTCPOffset+12, 0x00000450, asm.Word),
		asm.Ja.Label("reject_tcp_rst_common"),
		asm.StoreImm(asm.RFP, rejectTCPOffset+4, 0, asm.Word).WithSymbol("reject_tcp_rst_no_ack"),
		asm.LoadMem(asm.R1, asm.R3, 4, asm.Word),
		asm.HostTo(asm.BE, asm.R1, asm.Word),
		asm.LoadMem(asm.R5, asm.RFP, rejectPseudoOffset+12, asm.Word),
		asm.Add.Reg32(asm.R1, asm.R5),
		asm.HostTo(asm.BE, asm.R1, asm.Word),
		asm.StoreMem(asm.RFP, rejectTCPOffset+8, asm.R1, asm.Word),
		asm.StoreImm(asm.RFP, rejectTCPOffset+12, 0x00001450, asm.Word),
		asm.StoreImm(asm.RFP, rejectTCPOffset+16, 0, asm.Word).WithSymbol("reject_tcp_rst_common"),
		asm.LoadMem(asm.R1, asm.RFP, rejectIPOffset+12, asm.Word),
		asm.StoreMem(asm.RFP, rejectPseudoOffset, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.RFP, rejectIPOffset+16, asm.Word),
		asm.StoreMem(asm.RFP, rejectPseudoOffset+4, asm.R1, asm.Word),
		asm.StoreImm(asm.RFP, rejectPseudoOffset+8, 0x14000600, asm.Word),
	)
	instructions = appendIPv4Checksum(instructions, rejectIPOffset, "reject_tcp_reset_error")
	instructions = appendStoreNetworkHalfFromR0(instructions, rejectIPOffset+10)
	instructions = appendTCPChecksum(instructions, "reject_tcp_reset_error")
	instructions = appendStoreNetworkHalfFromR0(instructions, rejectTCPOffset+16)
	instructions = append(instructions,
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R2, rejectTCPRSTWireLen),
		asm.Mov.Imm(asm.R3, 0),
		asm.FnSkbChangeTail.Call(),
		asm.JNE.Imm(asm.R0, 0, "reject_tcp_reset_error"),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R2, 0),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, rejectEthernetOffset),
		asm.Mov.Imm(asm.R4, rejectEthernetHeaderLen),
		asm.Mov.Imm(asm.R5, 0),
		asm.FnSkbStoreBytes.Call(),
		asm.JNE.Imm(asm.R0, 0, "reject_tcp_reset_error"),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R2, rejectEthernetHeaderLen),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, rejectIPOffset),
		asm.Mov.Imm(asm.R4, rejectIPv4HeaderLen),
		asm.Mov.Imm(asm.R5, 0),
		asm.FnSkbStoreBytes.Call(),
		asm.JNE.Imm(asm.R0, 0, "reject_tcp_reset_error"),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R2, rejectEthernetHeaderLen+rejectIPv4HeaderLen),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, rejectTCPOffset),
		asm.Mov.Imm(asm.R4, rejectTCPHeaderLen),
		asm.Mov.Imm(asm.R5, 0),
		asm.FnSkbStoreBytes.Call(),
		asm.JNE.Imm(asm.R0, 0, "reject_tcp_reset_error"),
	)
	instructions = appendCounter(instructions, statsMap, 18, "reject_tcp_reset_done")
	return append(instructions,
		asm.LoadMem(asm.R1, asm.R6, skbIfindexOffset, asm.Word),
		asm.Mov.Imm(asm.R2, 0),
		asm.FnRedirect.Call(),
		asm.Return(),
	)
}

func appendRejectICMPUnreachable(instructions asm.Instructions, statsMap *cebpf.Map, label string) asm.Instructions {
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, 0).WithSymbol(label),
		asm.Mov.Reg(asm.R4, asm.R7),
		asm.Add.Imm(asm.R4, rejectEthernetHeaderLen+rejectICMPQuoteLen),
		asm.JGT.Reg(asm.R4, asm.R8, "reject_reply_needed"),
		asm.LoadMem(asm.R4, asm.R7, 16, asm.Half), // IPv4 total length.
		asm.And.Imm(asm.R4, 0xffff),
		asm.HostTo(asm.BE, asm.R4, asm.Half),
		asm.JLT.Imm(asm.R4, rejectICMPQuoteLen, "reject_reply_needed"),
		asm.LoadMem(asm.R1, asm.R7, 6, asm.Half),
		asm.StoreMem(asm.RFP, rejectEthernetOffset, asm.R1, asm.Half),
		asm.LoadMem(asm.R1, asm.R7, 8, asm.Half),
		asm.StoreMem(asm.RFP, rejectEthernetOffset+2, asm.R1, asm.Half),
		asm.LoadMem(asm.R1, asm.R7, 10, asm.Half),
		asm.StoreMem(asm.RFP, rejectEthernetOffset+4, asm.R1, asm.Half),
		asm.LoadMem(asm.R1, asm.R7, 0, asm.Half),
		asm.StoreMem(asm.RFP, rejectEthernetOffset+6, asm.R1, asm.Half),
		asm.LoadMem(asm.R1, asm.R7, 2, asm.Half),
		asm.StoreMem(asm.RFP, rejectEthernetOffset+8, asm.R1, asm.Half),
		asm.LoadMem(asm.R1, asm.R7, 4, asm.Half),
		asm.StoreMem(asm.RFP, rejectEthernetOffset+10, asm.R1, asm.Half),
		asm.LoadMem(asm.R1, asm.R7, 12, asm.Half),
		asm.StoreMem(asm.RFP, rejectEthernetOffset+12, asm.R1, asm.Half),
		asm.StoreImm(asm.RFP, rejectIPOffset, 0x38000045, asm.Word),
		asm.StoreImm(asm.RFP, rejectIPOffset+4, 0, asm.Word),
		asm.StoreImm(asm.RFP, rejectIPOffset+8, 0x00000140, asm.Word),
		asm.LoadMem(asm.R1, asm.R7, 30, asm.Word),
		asm.StoreMem(asm.RFP, rejectIPOffset+12, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R7, 26, asm.Word),
		asm.StoreMem(asm.RFP, rejectIPOffset+16, asm.R1, asm.Word),
		asm.StoreImm(asm.RFP, rejectICMPOffset, 0x0103, asm.Half),
		asm.StoreImm(asm.RFP, rejectICMPOffset+2, 0, asm.Half),
		asm.StoreImm(asm.RFP, rejectICMPOffset+4, 0, asm.Word),
		asm.LoadMem(asm.R1, asm.R7, 14, asm.Word),
		asm.StoreMem(asm.RFP, rejectICMPQuoteOffset, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R7, 18, asm.Word),
		asm.StoreMem(asm.RFP, rejectICMPQuoteOffset+4, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R7, 22, asm.Word),
		asm.StoreMem(asm.RFP, rejectICMPQuoteOffset+8, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R7, 26, asm.Word),
		asm.StoreMem(asm.RFP, rejectICMPQuoteOffset+12, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R7, 30, asm.Word),
		asm.StoreMem(asm.RFP, rejectICMPQuoteOffset+16, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R7, 34, asm.Word),
		asm.StoreMem(asm.RFP, rejectICMPQuoteOffset+20, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R7, 38, asm.Word),
		asm.StoreMem(asm.RFP, rejectICMPQuoteOffset+24, asm.R1, asm.Word),
	)
	instructions = appendIPv4Checksum(instructions, rejectIPOffset, "reject_icmp_unreachable_error")
	instructions = appendStoreNetworkHalfFromR0(instructions, rejectIPOffset+10)
	instructions = appendStackChecksum(instructions, rejectICMPOffset, rejectICMPHeaderLen+rejectICMPQuoteLen, "reject_icmp_unreachable_error")
	instructions = appendStoreNetworkHalfFromR0(instructions, rejectICMPOffset+2)
	instructions = append(instructions,
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R2, rejectICMPUnreachableWireLen),
		asm.Mov.Imm(asm.R3, 0),
		asm.FnSkbChangeTail.Call(),
		asm.JNE.Imm(asm.R0, 0, "reject_icmp_unreachable_error"),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R2, 0),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, rejectEthernetOffset),
		asm.Mov.Imm(asm.R4, rejectEthernetHeaderLen),
		asm.Mov.Imm(asm.R5, 0),
		asm.FnSkbStoreBytes.Call(),
		asm.JNE.Imm(asm.R0, 0, "reject_icmp_unreachable_error"),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R2, rejectEthernetHeaderLen),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, rejectIPOffset),
		asm.Mov.Imm(asm.R4, rejectIPv4HeaderLen),
		asm.Mov.Imm(asm.R5, 0),
		asm.FnSkbStoreBytes.Call(),
		asm.JNE.Imm(asm.R0, 0, "reject_icmp_unreachable_error"),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R2, rejectEthernetHeaderLen+rejectIPv4HeaderLen),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, rejectICMPOffset),
		asm.Mov.Imm(asm.R4, rejectICMPHeaderLen+rejectICMPQuoteLen),
		asm.Mov.Imm(asm.R5, 0),
		asm.FnSkbStoreBytes.Call(),
		asm.JNE.Imm(asm.R0, 0, "reject_icmp_unreachable_error"),
	)
	instructions = appendCounter(instructions, statsMap, 20, "reject_icmp_unreachable_done")
	return append(instructions,
		asm.LoadMem(asm.R1, asm.R6, skbIfindexOffset, asm.Word),
		asm.Mov.Imm(asm.R2, 0),
		asm.FnRedirect.Call(),
		asm.Return(),
	)
}

func appendIPv4Checksum(instructions asm.Instructions, base int16, errorLabel string) asm.Instructions {
	return appendStackChecksum(instructions, base, rejectIPv4HeaderLen, errorLabel)
}

func appendIPv4HeaderChecksum20(instructions asm.Instructions, base int16) asm.Instructions {
	for offset := int16(0); offset < rejectIPv4HeaderLen; offset += 2 {
		if offset == 10 {
			continue
		}
		instructions = append(instructions,
			asm.LoadMem(asm.R1, asm.RFP, base+offset, asm.Half),
			asm.HostTo(asm.BE, asm.R1, asm.Half),
		)
		if offset == 0 {
			instructions = append(instructions, asm.Mov.Reg(asm.R0, asm.R1))
		} else {
			instructions = append(instructions, asm.Add.Reg32(asm.R0, asm.R1))
		}
	}
	return appendChecksumFold(instructions)
}

func appendStackChecksum(instructions asm.Instructions, base int16, length int, errorLabel string) asm.Instructions {
	instructions = append(instructions,
		asm.Mov.Imm(asm.R1, 0),
		asm.Mov.Imm(asm.R2, 0),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, int32(base)),
		asm.Mov.Imm(asm.R4, int32(length)),
		asm.Mov.Imm(asm.R5, 0),
		asm.FnCsumDiff.Call(),
		asm.JSLT.Imm(asm.R0, 0, errorLabel),
	)
	return appendChecksumFold(instructions)
}

func appendTCPChecksum(instructions asm.Instructions, errorLabel string) asm.Instructions {
	return append(instructions,
		asm.Mov.Imm(asm.R1, 0),
		asm.Mov.Imm(asm.R2, 0),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, rejectPseudoOffset),
		asm.Mov.Imm(asm.R4, 12),
		asm.Mov.Imm(asm.R5, 0),
		asm.FnCsumDiff.Call(),
		asm.JSLT.Imm(asm.R0, 0, errorLabel),
		asm.Mov.Reg(asm.R5, asm.R0),
		asm.Mov.Imm(asm.R1, 0),
		asm.Mov.Imm(asm.R2, 0),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, rejectTCPOffset),
		asm.Mov.Imm(asm.R4, rejectTCPHeaderLen),
		asm.FnCsumDiff.Call(),
		asm.JSLT.Imm(asm.R0, 0, errorLabel),
	)
	return appendChecksumFold(instructions)
}

func appendExperimentalTCPTXDirectTCPChecksum(instructions asm.Instructions, errorLabel string) asm.Instructions {
	return appendExperimentalTCPTXDirectTCPChecksumAtOffset(instructions, errorLabel, rejectEthernetHeaderLen)
}

func appendExperimentalTCPTXDirectTCPChecksumAtOffset(instructions asm.Instructions, errorLabel string, packetBaseOffset int32) asm.Instructions {
	instructions = append(instructions,
		asm.JGT.Imm(asm.R9, kernelUDPTXTCPChecksumPayloadMax, errorLabel),
	)
	instructions = append(instructions,
		asm.Mov.Imm(asm.R1, 0),
		asm.Mov.Imm(asm.R2, 0),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, kernelUDPTXChecksumPseudoOffset),
		asm.Mov.Imm(asm.R4, 12),
		asm.Mov.Imm(asm.R5, 0),
		asm.FnCsumDiff.Call(),
		asm.JSLT.Imm(asm.R0, 0, errorLabel),
		asm.Mov.Reg(asm.R5, asm.R0),
		asm.Mov.Imm(asm.R1, 0),
		asm.Mov.Imm(asm.R2, 0),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, kernelUDPTXTCPHeaderOffset),
		asm.Mov.Imm(asm.R4, kernelUDPTXTCPFrameHeaderLen),
		asm.FnCsumDiff.Call(),
		asm.JSLT.Imm(asm.R0, 0, errorLabel),
		asm.StoreImm(asm.RFP, kernelUDPTXTCPChecksumPayloadOffset, 0, asm.Word),
	)
	if experimentalTCPTXDirectTrustInnerChecksums() {
		instructions = appendExperimentalTCPTXDirectTCPChecksumTrustedInnerAtOffset(instructions, packetBaseOffset)
	}
	if experimentalTCPTXDirectPacketChecksumEnabled() {
		instructions = appendExperimentalTCPTXDirectTCPChecksumPayloadPacketDirectAtOffset(instructions, errorLabel, packetBaseOffset)
	}
	return appendExperimentalTCPTXDirectTCPChecksumPayloadLoadBytesAtOffset(instructions, errorLabel, packetBaseOffset)
}

func appendKernelUDPTXDirectInnerTCPChecksum(instructions asm.Instructions, opts kernelUDPTXDirectProgramOptions, fallbackLabel string) asm.Instructions {
	return appendKernelUDPTXDirectInnerTCPChecksumAtOffset(instructions, nil, opts, rejectEthernetHeaderLen, "kudp_tx_direct_inner_tcp_csum", fallbackLabel)
}

func appendKernelUDPTXDirectInnerTCPChecksumAtOffset(instructions asm.Instructions, statsMap *cebpf.Map, opts kernelUDPTXDirectProgramOptions, innerIPOffset int32, labelBase string, fallbackLabel string) asm.Instructions {
	if !kernelUDPTXDirectInnerTCPChecksumEnabledForOptions(opts) {
		return instructions
	}
	tcpOnly := labelBase == "kudp_tx_direct_inner_tixt_post_csum" ||
		labelBase == "kudp_tx_direct_inner_mixed_tixt_post_csum"
	doneLabel := labelBase + "_done"
	kfuncFallbackLabel := labelBase + "_kfunc_fallback"
	tcpLabel := labelBase + "_tcp"
	udpLabel := labelBase + "_udp"
	notTCPLabel := labelBase + "_not_tcp"
	invalidLabel := labelBase + "_invalid"
	udpInvalidLabel := labelBase + "_udp_invalid"
	notTCPDoneLabel := labelBase + "_not_tcp_counter_done"
	udpInvalidDoneLabel := labelBase + "_udp_invalid_counter_done"
	instructions = append(instructions,
		asm.Mov.Reg(asm.R1, asm.R7),
		asm.Add.Imm(asm.R1, innerIPOffset+rejectIPv4HeaderLen),
		asm.JGT.Reg(asm.R1, asm.R8, invalidLabel),
		asm.LoadMem(asm.R1, asm.R7, int16(innerIPOffset+9), asm.Byte),
		asm.JEq.Imm(asm.R1, ipProtocolTCP, tcpLabel),
	)
	if !tcpOnly {
		instructions = append(instructions, asm.JEq.Imm(asm.R1, ipProtocolUDP, udpLabel))
	}
	instructions = append(instructions,
		asm.Ja.Label(notTCPLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol(tcpLabel),
	)
	if opts.InnerTCPKfunc && opts.InnerTCPKfuncCall.IsKfuncCall() {
		instructions = append(instructions,
			asm.JGT.Imm(asm.R9, kernelUDPTXTCPChecksumPayloadMax, fallbackLabel),
			asm.LoadMem(asm.R1, asm.R7, int16(innerIPOffset), asm.Byte),
			asm.And.Imm(asm.R1, 0x0f),
			asm.JNE.Imm(asm.R1, 5, invalidLabel),
			asm.JLT.Imm(asm.R9, rejectIPv4HeaderLen+rejectTCPHeaderLen, invalidLabel),
			asm.Mov.Reg(asm.R1, asm.R7),
			asm.Add.Imm(asm.R1, innerIPOffset+rejectIPv4HeaderLen+rejectTCPHeaderLen),
			asm.JGT.Reg(asm.R1, asm.R8, invalidLabel),
			asm.Mov.Reg(asm.R1, asm.R6).WithSymbol(labelBase+"_kfunc"),
			asm.Mov.Imm(asm.R2, innerIPOffset),
			asm.Mov.Reg(asm.R3, asm.R9),
			asm.Mov.Imm(asm.R4, 0),
			opts.InnerTCPKfuncCall,
			asm.JEq.Imm(asm.R0, 0, labelBase+"_kfunc_success"),
		)
		if statsMap != nil {
			instructions = appendHotPathCounter(instructions, statsMap, kernelUDPTXDirectStatInnerTCPChecksumKfuncFallbacks, labelBase+"_kfunc_fallback_counter_done")
		}
		instructions = append(instructions,
			asm.Ja.Label(kfuncFallbackLabel),
			asm.Mov.Imm(asm.R0, 0).WithSymbol(labelBase+"_kfunc_success"),
		)
		if statsMap != nil {
			instructions = appendHotPathCounter(instructions, statsMap, kernelUDPTXDirectStatInnerTCPChecksumKfuncFixes, labelBase+"_kfunc_counter_done")
		}
		instructions = append(instructions,
			asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
			asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
			asm.Ja.Label(doneLabel),
			asm.Mov.Imm(asm.R0, 0).WithSymbol(kfuncFallbackLabel),
		)
		if tcpOnly {
			instructions = append(instructions,
				asm.Ja.Label(fallbackLabel),
				asm.Mov.Imm(asm.R0, 0).WithSymbol(invalidLabel),
				asm.Ja.Label(fallbackLabel),
				asm.Mov.Imm(asm.R0, 0).WithSymbol(notTCPLabel),
			)
			if statsMap != nil {
				instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatInnerTCPChecksumNotTCP, notTCPDoneLabel)
			}
			return append(instructions,
				asm.Ja.Label(doneLabel),
				asm.Mov.Imm(asm.R0, 0).WithSymbol(doneLabel),
			)
		}
	}
	if tcpOnly {
		instructions = append(instructions,
			asm.Ja.Label(fallbackLabel),
			asm.Mov.Imm(asm.R0, 0).WithSymbol(invalidLabel),
			asm.Ja.Label(fallbackLabel),
			asm.Mov.Imm(asm.R0, 0).WithSymbol(notTCPLabel),
		)
		if statsMap != nil {
			instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatInnerTCPChecksumNotTCP, notTCPDoneLabel)
		}
		return append(instructions,
			asm.Ja.Label(doneLabel),
			asm.Mov.Imm(asm.R0, 0).WithSymbol(doneLabel),
		)
	}
	instructions = append(instructions,
		asm.JGT.Imm(asm.R9, kernelUDPTXTCPChecksumPayloadMax, fallbackLabel),
		asm.LoadMem(asm.R1, asm.R7, int16(innerIPOffset), asm.Byte),
		asm.And.Imm(asm.R1, 0x0f),
		asm.JNE.Imm(asm.R1, 5, invalidLabel),
		asm.JLT.Imm(asm.R9, rejectIPv4HeaderLen+rejectTCPHeaderLen, invalidLabel),
		asm.Mov.Reg(asm.R1, asm.R7),
		asm.Add.Imm(asm.R1, innerIPOffset+rejectIPv4HeaderLen+rejectTCPHeaderLen),
		asm.JGT.Reg(asm.R1, asm.R8, invalidLabel),
		asm.Mov.Reg(asm.R1, asm.R9),
		asm.Add.Imm(asm.R1, -rejectIPv4HeaderLen),
		asm.HostTo(asm.BE, asm.R1, asm.Half),
		asm.LoadMem(asm.R2, asm.R7, int16(innerIPOffset+12), asm.Word),
		asm.StoreMem(asm.RFP, kernelUDPTXChecksumPseudoOffset, asm.R2, asm.Word),
		asm.LoadMem(asm.R2, asm.R7, int16(innerIPOffset+16), asm.Word),
		asm.StoreMem(asm.RFP, kernelUDPTXChecksumPseudoOffset+4, asm.R2, asm.Word),
		asm.StoreImm(asm.RFP, kernelUDPTXChecksumPseudoOffset+8, 0x00000600, asm.Word),
		asm.StoreMem(asm.RFP, kernelUDPTXChecksumPseudoOffset+10, asm.R1, asm.Half),
		asm.StoreImm(asm.RFP, kernelUDPTXTCPChecksumPayloadOffset, rejectIPv4HeaderLen, asm.Word),
		asm.StoreImm(asm.R7, int16(innerIPOffset+rejectIPv4HeaderLen+16), 0, asm.Half),
		asm.Mov.Imm(asm.R1, 0),
		asm.Mov.Imm(asm.R2, 0),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, kernelUDPTXChecksumPseudoOffset),
		asm.Mov.Imm(asm.R4, 12),
		asm.Mov.Imm(asm.R5, 0),
		asm.FnCsumDiff.Call(),
		asm.JSLT.Imm(asm.R0, 0, fallbackLabel),
	)
	instructions = appendKernelUDPTXDirectInnerTCPChecksumPayloadLoadBytesAtOffset(instructions, innerIPOffset, labelBase+"_payload", fallbackLabel)
	instructions = append(instructions,
		asm.StoreMem(asm.R7, int16(innerIPOffset+rejectIPv4HeaderLen+16), asm.R0, asm.Half),
	)
	if statsMap != nil {
		instructions = appendHotPathCounter(instructions, statsMap, kernelUDPTXDirectStatInnerTCPChecksumFixes, labelBase+"_counter_done")
	}
	instructions = append(instructions,
		asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
		asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
		asm.Ja.Label(doneLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol(invalidLabel),
		asm.Ja.Label(fallbackLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol(udpLabel),
		asm.JGT.Imm(asm.R9, kernelUDPTXTCPChecksumPayloadMax, fallbackLabel),
		asm.LoadMem(asm.R1, asm.R7, int16(innerIPOffset), asm.Byte),
		asm.And.Imm(asm.R1, 0x0f),
		asm.JNE.Imm(asm.R1, 5, udpInvalidLabel),
		asm.JLT.Imm(asm.R9, rejectIPv4HeaderLen+8, udpInvalidLabel),
		asm.Mov.Reg(asm.R1, asm.R7),
		asm.Add.Imm(asm.R1, innerIPOffset+rejectIPv4HeaderLen+8),
		asm.JGT.Reg(asm.R1, asm.R8, udpInvalidLabel),
		asm.Mov.Reg(asm.R1, asm.R9),
		asm.Add.Imm(asm.R1, -rejectIPv4HeaderLen),
		asm.LoadMem(asm.R2, asm.R7, int16(innerIPOffset+rejectIPv4HeaderLen+4), asm.Half),
		asm.HostTo(asm.BE, asm.R2, asm.Half),
		asm.JNE.Reg(asm.R2, asm.R1, udpInvalidLabel),
		asm.HostTo(asm.BE, asm.R1, asm.Half),
		asm.LoadMem(asm.R2, asm.R7, int16(innerIPOffset+12), asm.Word),
		asm.StoreMem(asm.RFP, kernelUDPTXChecksumPseudoOffset, asm.R2, asm.Word),
		asm.LoadMem(asm.R2, asm.R7, int16(innerIPOffset+16), asm.Word),
		asm.StoreMem(asm.RFP, kernelUDPTXChecksumPseudoOffset+4, asm.R2, asm.Word),
		asm.StoreImm(asm.RFP, kernelUDPTXChecksumPseudoOffset+8, 0x00001100, asm.Word),
		asm.StoreMem(asm.RFP, kernelUDPTXChecksumPseudoOffset+10, asm.R1, asm.Half),
		asm.StoreImm(asm.RFP, kernelUDPTXTCPChecksumPayloadOffset, rejectIPv4HeaderLen, asm.Word),
		asm.StoreImm(asm.R7, int16(innerIPOffset+rejectIPv4HeaderLen+6), 0, asm.Half),
		asm.Mov.Imm(asm.R1, 0),
		asm.Mov.Imm(asm.R2, 0),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, kernelUDPTXChecksumPseudoOffset),
		asm.Mov.Imm(asm.R4, 12),
		asm.Mov.Imm(asm.R5, 0),
		asm.FnCsumDiff.Call(),
		asm.JSLT.Imm(asm.R0, 0, fallbackLabel),
	)
	instructions = appendKernelUDPTXDirectInnerTCPChecksumPayloadLoadBytesAtOffset(instructions, innerIPOffset, labelBase+"_udp_payload", fallbackLabel)
	instructions = append(instructions,
		asm.JNE.Imm(asm.R0, 0, labelBase+"_udp_checksum_ready"),
		asm.Mov.Imm(asm.R0, 0xffff),
		asm.Mov.Reg(asm.R0, asm.R0).WithSymbol(labelBase+"_udp_checksum_ready"),
		asm.StoreMem(asm.R7, int16(innerIPOffset+rejectIPv4HeaderLen+6), asm.R0, asm.Half),
	)
	if statsMap != nil {
		instructions = appendHotPathCounter(instructions, statsMap, kernelUDPTXDirectStatInnerUDPChecksumFixes, labelBase+"_udp_counter_done")
	}
	instructions = append(instructions,
		asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
		asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
		asm.Ja.Label(doneLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol(udpInvalidLabel),
	)
	if statsMap != nil {
		instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatInnerUDPChecksumInvalid, udpInvalidDoneLabel)
	}
	instructions = append(instructions,
		asm.Ja.Label(fallbackLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol(notTCPLabel),
	)
	if statsMap != nil {
		instructions = appendCounter(instructions, statsMap, kernelUDPTXDirectStatInnerTCPChecksumNotTCP, notTCPDoneLabel)
	}
	return append(instructions,
		asm.Ja.Label(doneLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol(doneLabel),
	)
}

func appendKernelUDPTXDirectInnerTCPChecksumPayloadLoadBytes(instructions asm.Instructions, errorLabel string) asm.Instructions {
	return appendKernelUDPTXDirectInnerTCPChecksumPayloadLoadBytesAtOffset(instructions, rejectEthernetHeaderLen, "kudp_tx_direct_inner_tcp_payload_csum", errorLabel)
}

func appendKernelUDPTXDirectInnerTCPChecksumPayloadLoadBytesAtOffset(instructions asm.Instructions, innerIPOffset int32, labelBase string, errorLabel string) asm.Instructions {
	return appendTCPChecksumPayloadLoadBytesWithLabelsAndBase(instructions, errorLabel, labelBase, innerIPOffset)
}

func appendExperimentalTCPTXDirectTCPChecksumTrustedInner(instructions asm.Instructions) asm.Instructions {
	return appendExperimentalTCPTXDirectTCPChecksumTrustedInnerAtOffset(instructions, rejectEthernetHeaderLen)
}

func appendExperimentalTCPTXDirectTCPChecksumTrustedInnerAtOffset(instructions asm.Instructions, packetBaseOffset int32) asm.Instructions {
	const fallbackLabel = "kudp_tx_direct_tcp_csum_trusted_fallback"
	instructions = append(instructions,
		asm.JLT.Imm(asm.R9, rejectIPv4HeaderLen, fallbackLabel),
		asm.StoreMem(asm.RFP, kernelUDPTXTCPChecksumSumOffset, asm.R0, asm.Word),
		asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
		asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
		asm.Mov.Reg(asm.R1, asm.R7),
		asm.Add.Imm(asm.R1, packetBaseOffset+rejectIPv4HeaderLen),
		asm.JGT.Reg(asm.R1, asm.R8, fallbackLabel),
		asm.LoadMem(asm.R1, asm.R7, int16(packetBaseOffset+9), asm.Byte),
		asm.JEq.Imm(asm.R1, ipProtocolTCP, "kudp_tx_direct_tcp_csum_trusted_l4"),
		asm.JEq.Imm(asm.R1, ipProtocolUDP, "kudp_tx_direct_tcp_csum_trusted_udp"),
		asm.JEq.Imm(asm.R1, ipProtocolICMP, "kudp_tx_direct_tcp_csum_trusted_icmp"),
		asm.Ja.Label(fallbackLabel),

		// TCP and UDP inner checksums cover their L4 payload plus the IPv4
		// pseudo-header. For trusted complete checksums, the inner packet sum is
		// equivalent to the one's-complement inverse of that pseudo-header, so
		// direct TX avoids scanning non-linear skb payload bytes.
		asm.Mov.Reg(asm.R4, asm.R9).WithSymbol("kudp_tx_direct_tcp_csum_trusted_l4"),
		asm.Add.Imm(asm.R4, -rejectIPv4HeaderLen),
		asm.JLT.Imm(asm.R4, rejectTCPHeaderLen, fallbackLabel),
		asm.Mov.Reg(asm.R1, asm.R7),
		asm.Add.Imm(asm.R1, packetBaseOffset+rejectIPv4HeaderLen+rejectTCPHeaderLen),
		asm.JGT.Reg(asm.R1, asm.R8, fallbackLabel),
		asm.LoadMem(asm.R1, asm.R7, int16(packetBaseOffset+rejectIPv4HeaderLen+16), asm.Half),
		asm.HostTo(asm.BE, asm.R1, asm.Half),
		asm.JEq.Imm(asm.R1, 0, fallbackLabel),
		asm.LoadMem(asm.R3, asm.R7, int16(packetBaseOffset+9), asm.Byte),
		asm.Ja.Label("kudp_tx_direct_tcp_csum_trusted_pseudo"),

		asm.Mov.Reg(asm.R4, asm.R9).WithSymbol("kudp_tx_direct_tcp_csum_trusted_udp"),
		asm.Add.Imm(asm.R4, -rejectIPv4HeaderLen),
		asm.JLT.Imm(asm.R4, 8, fallbackLabel),
		asm.Mov.Reg(asm.R1, asm.R7),
		asm.Add.Imm(asm.R1, packetBaseOffset+rejectIPv4HeaderLen+8),
		asm.JGT.Reg(asm.R1, asm.R8, fallbackLabel),
		asm.LoadMem(asm.R1, asm.R7, int16(packetBaseOffset+rejectIPv4HeaderLen+4), asm.Half),
		asm.HostTo(asm.BE, asm.R1, asm.Half),
		asm.JNE.Reg(asm.R1, asm.R4, fallbackLabel),
		asm.LoadMem(asm.R1, asm.R7, int16(packetBaseOffset+rejectIPv4HeaderLen+6), asm.Half),
		asm.HostTo(asm.BE, asm.R1, asm.Half),
		asm.JEq.Imm(asm.R1, 0, fallbackLabel),
		asm.Mov.Imm(asm.R3, ipProtocolUDP),
		asm.Ja.Label("kudp_tx_direct_tcp_csum_trusted_pseudo"),

		asm.Mov.Reg(asm.R4, asm.R9).WithSymbol("kudp_tx_direct_tcp_csum_trusted_icmp"),
		asm.Add.Imm(asm.R4, -rejectIPv4HeaderLen),
		asm.JLT.Imm(asm.R4, 4, fallbackLabel),
		asm.Mov.Reg(asm.R1, asm.R7),
		asm.Add.Imm(asm.R1, packetBaseOffset+rejectIPv4HeaderLen+4),
		asm.JGT.Reg(asm.R1, asm.R8, fallbackLabel),
		asm.LoadMem(asm.R0, asm.RFP, kernelUDPTXTCPChecksumSumOffset, asm.Word),
	)
	instructions = appendChecksumFold(instructions)
	instructions = append(instructions,
		asm.Ja.Label("kudp_tx_direct_tcp_csum_done"),

		asm.Mov.Imm(asm.R0, 0).WithSymbol("kudp_tx_direct_tcp_csum_trusted_pseudo"),
	)
	instructions = appendPacketNetworkHalfChecksumAdd(instructions, int16(packetBaseOffset+12))
	instructions = appendPacketNetworkHalfChecksumAdd(instructions, int16(packetBaseOffset+14))
	instructions = appendPacketNetworkHalfChecksumAdd(instructions, int16(packetBaseOffset+16))
	instructions = appendPacketNetworkHalfChecksumAdd(instructions, int16(packetBaseOffset+18))
	instructions = append(instructions,
		asm.Add.Reg32(asm.R0, asm.R3),
		asm.Add.Reg32(asm.R0, asm.R4),
	)
	instructions = appendChecksumFold(instructions)
	instructions = append(instructions,
		asm.LoadMem(asm.R1, asm.RFP, kernelUDPTXTCPChecksumSumOffset, asm.Word),
		asm.Add.Reg32(asm.R0, asm.R1),
	)
	instructions = appendChecksumFold(instructions)
	return append(instructions,
		asm.Ja.Label("kudp_tx_direct_tcp_csum_done"),
		asm.Mov.Reg(asm.R0, asm.R0).WithSymbol(fallbackLabel),
		asm.LoadMem(asm.R0, asm.RFP, kernelUDPTXTCPChecksumSumOffset, asm.Word),
	)
}

func appendExperimentalTCPTXDirectTCPChecksumPayloadLoadBytes(instructions asm.Instructions, errorLabel string) asm.Instructions {
	return appendExperimentalTCPTXDirectTCPChecksumPayloadLoadBytesAtOffset(instructions, errorLabel, rejectEthernetHeaderLen)
}

func appendExperimentalTCPTXDirectTCPChecksumPayloadLoadBytesAtOffset(instructions asm.Instructions, errorLabel string, packetBaseOffset int32) asm.Instructions {
	return appendTCPChecksumPayloadLoadBytesWithLabelsAndBase(instructions, errorLabel, "kudp_tx_direct_tcp_csum", packetBaseOffset)
}

func appendTCPChecksumPayloadLoadBytesWithLabels(instructions asm.Instructions, errorLabel string, labelBase string) asm.Instructions {
	return appendTCPChecksumPayloadLoadBytesWithLabelsAndBase(instructions, errorLabel, labelBase, rejectEthernetHeaderLen)
}

func appendTCPChecksumPayloadLoadBytesWithLabelsAndBase(instructions asm.Instructions, errorLabel string, labelBase string, packetBaseOffset int32) asm.Instructions {
	for chunk := int32(0); chunk < kernelUDPTXTCPChecksumPayloadMax/kernelUDPTXTCPChecksumChunkLen; chunk++ {
		labelPrefix := fmt.Sprintf("%s_payload_chunk_%d", labelBase, chunk)
		doneLabel := fmt.Sprintf("%s_chunk_%d_done", labelBase, chunk)
		instructions = append(instructions,
			asm.LoadMem(asm.R4, asm.RFP, kernelUDPTXTCPChecksumPayloadOffset, asm.Word),
			asm.Mov.Reg(asm.R1, asm.R4),
			asm.Add.Imm(asm.R1, kernelUDPTXTCPChecksumChunkLen),
			asm.JGT.Reg(asm.R1, asm.R9, doneLabel),
			asm.StoreMem(asm.RFP, kernelUDPTXTCPChecksumSumOffset, asm.R0, asm.Word),
			asm.Mov.Reg(asm.R1, asm.R6),
			asm.Mov.Imm(asm.R2, packetBaseOffset),
			asm.Add.Reg(asm.R2, asm.R4),
			asm.Mov.Reg(asm.R3, asm.RFP),
			asm.Add.Imm(asm.R3, kernelUDPTXTCPChecksumChunkOffset),
			asm.Mov.Imm(asm.R4, kernelUDPTXTCPChecksumChunkLen),
			asm.FnSkbLoadBytes.Call(),
			asm.JNE.Imm(asm.R0, 0, errorLabel),
			asm.LoadMem(asm.R5, asm.RFP, kernelUDPTXTCPChecksumSumOffset, asm.Word),
			asm.Mov.Imm(asm.R1, 0),
			asm.Mov.Imm(asm.R2, 0),
			asm.Mov.Reg(asm.R3, asm.RFP),
			asm.Add.Imm(asm.R3, kernelUDPTXTCPChecksumChunkOffset),
			asm.Mov.Imm(asm.R4, kernelUDPTXTCPChecksumChunkLen),
			asm.FnCsumDiff.Call(),
			asm.JSLT.Imm(asm.R0, 0, errorLabel),
			asm.LoadMem(asm.R4, asm.RFP, kernelUDPTXTCPChecksumPayloadOffset, asm.Word),
			asm.Add.Imm(asm.R4, kernelUDPTXTCPChecksumChunkLen),
			asm.StoreMem(asm.RFP, kernelUDPTXTCPChecksumPayloadOffset, asm.R4, asm.Word),
			asm.Ja.Label(labelPrefix+"_next"),
			asm.Mov.Reg(asm.R0, asm.R0).WithSymbol(doneLabel),
			asm.Mov.Reg(asm.R0, asm.R0).WithSymbol(labelPrefix+"_next"),
		)
	}
	for _, chunk := range []int32{128, 64, 32, 16, 8, 4} {
		doneLabel := fmt.Sprintf("%s_rem_%d_done", labelBase, chunk)
		instructions = append(instructions,
			asm.LoadMem(asm.R4, asm.RFP, kernelUDPTXTCPChecksumPayloadOffset, asm.Word),
			asm.Mov.Reg(asm.R1, asm.R4),
			asm.Add.Imm(asm.R1, chunk),
			asm.JGT.Reg(asm.R1, asm.R9, doneLabel),
			asm.StoreMem(asm.RFP, kernelUDPTXTCPChecksumSumOffset, asm.R0, asm.Word),
			asm.Mov.Reg(asm.R1, asm.R6),
			asm.Mov.Imm(asm.R2, packetBaseOffset),
			asm.Add.Reg(asm.R2, asm.R4),
			asm.Mov.Reg(asm.R3, asm.RFP),
			asm.Add.Imm(asm.R3, kernelUDPTXTCPChecksumChunkOffset),
			asm.Mov.Imm(asm.R4, chunk),
			asm.FnSkbLoadBytes.Call(),
			asm.JNE.Imm(asm.R0, 0, errorLabel),
			asm.LoadMem(asm.R5, asm.RFP, kernelUDPTXTCPChecksumSumOffset, asm.Word),
			asm.Mov.Imm(asm.R1, 0),
			asm.Mov.Imm(asm.R2, 0),
			asm.Mov.Reg(asm.R3, asm.RFP),
			asm.Add.Imm(asm.R3, kernelUDPTXTCPChecksumChunkOffset),
			asm.Mov.Imm(asm.R4, chunk),
			asm.FnCsumDiff.Call(),
			asm.JSLT.Imm(asm.R0, 0, errorLabel),
			asm.LoadMem(asm.R4, asm.RFP, kernelUDPTXTCPChecksumPayloadOffset, asm.Word),
			asm.Add.Imm(asm.R4, chunk),
			asm.StoreMem(asm.RFP, kernelUDPTXTCPChecksumPayloadOffset, asm.R4, asm.Word),
			asm.Mov.Reg(asm.R0, asm.R0).WithSymbol(doneLabel),
		)
	}
	instructions = append(instructions,
		asm.Mov.Reg(asm.R1, asm.R9).WithSymbol(labelBase+"_tail_start"),
		asm.And.Imm(asm.R1, 3),
		asm.JEq.Imm(asm.R1, 0, labelBase+"_tail_done"),
		asm.StoreMem(asm.RFP, kernelUDPTXTCPChecksumSumOffset, asm.R0, asm.Word),
		asm.StoreImm(asm.RFP, kernelUDPTXTCPChecksumTailOffset, 0, asm.Word),
		asm.JEq.Imm(asm.R1, 1, labelBase+"_tail_load_1"),
		asm.JEq.Imm(asm.R1, 2, labelBase+"_tail_load_2"),
		asm.Ja.Label(labelBase+"_tail_load_3"),
		asm.Mov.Reg(asm.R1, asm.R6).WithSymbol(labelBase+"_tail_load_1"),
		asm.Mov.Imm(asm.R2, packetBaseOffset),
		asm.LoadMem(asm.R3, asm.RFP, kernelUDPTXTCPChecksumPayloadOffset, asm.Word),
		asm.Add.Reg(asm.R2, asm.R3),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, kernelUDPTXTCPChecksumTailOffset),
		asm.Mov.Imm(asm.R4, 1),
		asm.FnSkbLoadBytes.Call(),
		asm.JNE.Imm(asm.R0, 0, errorLabel),
		asm.Ja.Label(labelBase+"_tail_sum"),
		asm.Mov.Reg(asm.R1, asm.R6).WithSymbol(labelBase+"_tail_load_2"),
		asm.Mov.Imm(asm.R2, packetBaseOffset),
		asm.LoadMem(asm.R3, asm.RFP, kernelUDPTXTCPChecksumPayloadOffset, asm.Word),
		asm.Add.Reg(asm.R2, asm.R3),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, kernelUDPTXTCPChecksumTailOffset),
		asm.Mov.Imm(asm.R4, 2),
		asm.FnSkbLoadBytes.Call(),
		asm.JNE.Imm(asm.R0, 0, errorLabel),
		asm.Ja.Label(labelBase+"_tail_sum"),
		asm.Mov.Reg(asm.R1, asm.R6).WithSymbol(labelBase+"_tail_load_3"),
		asm.Mov.Imm(asm.R2, packetBaseOffset),
		asm.LoadMem(asm.R3, asm.RFP, kernelUDPTXTCPChecksumPayloadOffset, asm.Word),
		asm.Add.Reg(asm.R2, asm.R3),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, kernelUDPTXTCPChecksumTailOffset),
		asm.Mov.Imm(asm.R4, 3),
		asm.FnSkbLoadBytes.Call(),
		asm.JNE.Imm(asm.R0, 0, errorLabel),
		asm.LoadMem(asm.R5, asm.RFP, kernelUDPTXTCPChecksumSumOffset, asm.Word).WithSymbol(labelBase+"_tail_sum"),
		asm.Mov.Imm(asm.R1, 0),
		asm.Mov.Imm(asm.R2, 0),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, kernelUDPTXTCPChecksumTailOffset),
		asm.Mov.Imm(asm.R4, 4),
		asm.FnCsumDiff.Call(),
		asm.JSLT.Imm(asm.R0, 0, errorLabel),
		asm.Mov.Reg(asm.R0, asm.R0).WithSymbol(labelBase+"_tail_done"),
	)
	instructions = appendChecksumFold(instructions)
	return append(instructions, asm.Mov.Reg(asm.R0, asm.R0).WithSymbol(labelBase+"_done"))
}

func appendExperimentalTCPTXDirectTCPChecksumPayloadPacketDirect(instructions asm.Instructions, errorLabel string) asm.Instructions {
	return appendExperimentalTCPTXDirectTCPChecksumPayloadPacketDirectAtOffset(instructions, errorLabel, rejectEthernetHeaderLen)
}

func appendExperimentalTCPTXDirectTCPChecksumPayloadPacketDirectAtOffset(instructions asm.Instructions, errorLabel string, packetBaseOffset int32) asm.Instructions {
	instructions = append(instructions,
		asm.StoreMem(asm.RFP, kernelUDPTXTCPChecksumInitialSumOffset, asm.R0, asm.Word),
		asm.StoreImm(asm.RFP, kernelUDPTXTCPChecksumPayloadOffset, 0, asm.Word),
		asm.Mov.Reg(asm.R1, asm.R7),
		asm.Add.Imm(asm.R1, packetBaseOffset),
		asm.Mov.Reg(asm.R2, asm.R1),
		asm.Add.Reg(asm.R2, asm.R9),
		asm.JGT.Reg(asm.R2, asm.R8, "kudp_tx_direct_tcp_csum_packet_fallback"),
	)
	for offset := int32(0); offset < kernelUDPTXTCPChecksumPayloadMax; offset += kernelUDPTXTCPChecksumChunkLen {
		threshold := offset + kernelUDPTXTCPChecksumChunkLen
		labelPrefix := fmt.Sprintf("kudp_tx_direct_tcp_csum_packet_%d", offset)
		instructions = append(instructions,
			asm.Mov.Reg(asm.R1, asm.R9),
			asm.JLT.Imm(asm.R1, threshold, labelPrefix+"_done"),
			asm.StoreMem(asm.RFP, kernelUDPTXTCPChecksumSumOffset, asm.R0, asm.Word),
			asm.Mov.Reg(asm.R3, asm.R7),
			asm.Add.Imm(asm.R3, packetBaseOffset+offset),
			asm.Mov.Reg(asm.R2, asm.R3),
			asm.Add.Imm(asm.R2, kernelUDPTXTCPChecksumChunkLen),
			asm.JGT.Reg(asm.R2, asm.R8, "kudp_tx_direct_tcp_csum_packet_fallback"),
			asm.Mov.Imm(asm.R1, 0),
			asm.Mov.Imm(asm.R2, 0),
			asm.LoadMem(asm.R5, asm.RFP, kernelUDPTXTCPChecksumSumOffset, asm.Word),
			asm.Mov.Imm(asm.R4, kernelUDPTXTCPChecksumChunkLen),
			asm.FnCsumDiff.Call(),
			asm.JSLT.Imm(asm.R0, 0, errorLabel),
			asm.StoreImm(asm.RFP, kernelUDPTXTCPChecksumPayloadOffset, int64(threshold), asm.Word),
			asm.Ja.Label(labelPrefix+"_next"),
			asm.Mov.Reg(asm.R0, asm.R0).WithSymbol(labelPrefix+"_done"),
			asm.Ja.Label("kudp_tx_direct_tcp_csum_loadbytes_continue"),
			asm.Mov.Reg(asm.R0, asm.R0).WithSymbol(labelPrefix+"_next"),
		)
	}
	return append(instructions,
		asm.Ja.Label("kudp_tx_direct_tcp_csum_loadbytes_continue"),
		asm.LoadMem(asm.R0, asm.RFP, kernelUDPTXTCPChecksumInitialSumOffset, asm.Word).WithSymbol("kudp_tx_direct_tcp_csum_packet_fallback"),
		asm.StoreImm(asm.RFP, kernelUDPTXTCPChecksumPayloadOffset, 0, asm.Word),
		asm.Mov.Reg(asm.R0, asm.R0).WithSymbol("kudp_tx_direct_tcp_csum_loadbytes_continue"),
	)
}

func appendStackNetworkHalfChecksumAdd(instructions asm.Instructions, offset int16) asm.Instructions {
	return append(instructions,
		asm.LoadMem(asm.R1, asm.RFP, offset, asm.Half),
		asm.HostTo(asm.BE, asm.R1, asm.Half),
		asm.Add.Reg32(asm.R0, asm.R1),
	)
}

func appendPacketNetworkHalfChecksumAdd(instructions asm.Instructions, offset int16) asm.Instructions {
	return append(instructions,
		asm.LoadMem(asm.R1, asm.R7, offset, asm.Half),
		asm.HostTo(asm.BE, asm.R1, asm.Half),
		asm.Add.Reg32(asm.R0, asm.R1),
	)
}

func appendStoreNetworkHalfFromR0(instructions asm.Instructions, offset int16) asm.Instructions {
	return append(instructions,
		asm.HostTo(asm.BE, asm.R0, asm.Half),
		asm.StoreMem(asm.RFP, offset, asm.R0, asm.Half),
	)
}

func appendStoreNativeHalfFromR0(instructions asm.Instructions, offset int16) asm.Instructions {
	return append(instructions, asm.StoreMem(asm.RFP, offset, asm.R0, asm.Half))
}

func appendChecksumFold(instructions asm.Instructions) asm.Instructions {
	for i := 0; i < 4; i++ {
		instructions = append(instructions,
			asm.Mov.Reg(asm.R1, asm.R0),
			asm.And.Imm(asm.R1, 0xffff),
			asm.RSh.Imm(asm.R0, 16),
			asm.Add.Reg(asm.R0, asm.R1),
		)
	}
	return append(instructions,
		asm.Xor.Imm(asm.R0, 0xffff),
		asm.And.Imm(asm.R0, 0xffff),
	)
}

func appendCapturePacketReady(instructions asm.Instructions, statsMap *cebpf.Map, routeMap *cebpf.Map) asm.Instructions {
	sampleLimit := int32(captureSampleLimit)
	instructions = append(instructions,
		// TC direct packet pointers can cover only the linear head of a non-linear/GSO skb.
		// Use skb->len as the real packet length, pull the sample window, then reload
		// packet pointers before emitting the perf event.
		asm.LoadMem(asm.R9, asm.R6, skbLenOffset, asm.Word), // skb->len
		asm.Mov.Reg(asm.R2, asm.R9),
		asm.JLE.Imm(asm.R2, sampleLimit, "capture_pull_len_ready"),
		asm.Mov.Imm(asm.R2, sampleLimit),
		asm.Mov.Reg(asm.R1, asm.R6).WithSymbol("capture_pull_len_ready"),
		asm.FnSkbPullData.Call(),
		asm.JNE.Imm(asm.R0, 0, "capture_pull_error"),
		asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),    // skb->data
		asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word), // skb->data_end
		asm.Mov.Reg(asm.R4, asm.R8),
		asm.Sub.Reg(asm.R4, asm.R7),
		asm.Mov.Reg(asm.R5, asm.R9),
		asm.JLE.Imm(asm.R5, sampleLimit, "capture_linear_sample_len_ready"),
		asm.Mov.Imm(asm.R5, sampleLimit),
		asm.JGT.Reg(asm.R5, asm.R4, "capture_linear_short_error").WithSymbol("capture_linear_sample_len_ready"),
		asm.Mov.Reg(asm.R4, asm.R7),
		asm.Add.Imm(asm.R4, 14),
		asm.JGT.Reg(asm.R4, asm.R8, "capture_header_short_error"),
		asm.LoadMem(asm.R4, asm.R7, 12, asm.Half),
		asm.JNE.Imm(asm.R4, 0x0008, "capture_ethertype_error"), // ETH_P_IP in packet byte order on little-endian hosts.
		asm.Mov.Reg(asm.R4, asm.R7),
		asm.Add.Imm(asm.R4, 34),
		asm.JGT.Reg(asm.R4, asm.R8, "capture_header_short_error"),
		asm.LoadMem(asm.R4, asm.R7, 30, asm.Word), // IPv4 destination address.
		asm.StoreImm(asm.RFP, -16, 32, asm.Word),
		asm.StoreMem(asm.RFP, -12, asm.R4, asm.Word),
		asm.LoadMapPtr(asm.R1, routeMap.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -16),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "capture_route_miss_error"),
	)
	instructions = appendHotPathCounter(instructions, statsMap, captureStatReady, "capture_ready_counter_done")
	instructions = append(instructions, asm.Ja.Label("capture_packet_ready_done"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("capture_pull_error"))
	instructions = appendHotPathCounter(instructions, statsMap, captureStatPullErrors, "capture_pull_error_counter_done")
	instructions = append(instructions, asm.Ja.Label("capture_error"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("capture_linear_short_error"))
	instructions = appendHotPathCounter(instructions, statsMap, captureStatLinearShortErrors, "capture_linear_short_error_counter_done")
	instructions = append(instructions, asm.Ja.Label("capture_error"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("capture_ethertype_error"))
	instructions = appendHotPathCounter(instructions, statsMap, captureStatEtherTypeErrors, "capture_ethertype_error_counter_done")
	instructions = append(instructions, asm.Ja.Label("capture_error"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("capture_header_short_error"))
	instructions = appendHotPathCounter(instructions, statsMap, captureStatHeaderShortErrors, "capture_header_short_error_counter_done")
	instructions = append(instructions, asm.Ja.Label("capture_error"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("capture_route_miss_error"))
	instructions = appendHotPathCounter(instructions, statsMap, captureStatRouteMissErrors, "capture_route_miss_error_counter_done")
	return append(instructions,
		asm.Ja.Label("capture_error"),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("capture_packet_ready_done"),
	)
}

func appendNATOutbound(instructions asm.Instructions, statsMap *cebpf.Map, natConfigMap *cebpf.Map, natSourceMap *cebpf.Map, natRouteMap *cebpf.Map, natExcludeMap *cebpf.Map) asm.Instructions {
	return appendNATOutboundWithLabels(instructions, statsMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, "nat", "nat_done")
}

func appendNATOutboundWithLabels(instructions asm.Instructions, statsMap *cebpf.Map, natConfigMap *cebpf.Map, natSourceMap *cebpf.Map, natRouteMap *cebpf.Map, natExcludeMap *cebpf.Map, prefix string, doneLabel string) asm.Instructions {
	errorLabel := prefix + "_error"
	tcpLabel := prefix + "_tcp"
	udpLabel := prefix + "_udp"
	icmpLabel := prefix + "_icmp"
	applyL4Label := prefix + "_apply_l4"
	applyIPOnlyLabel := prefix + "_apply_ip_only"
	storeSourceLabel := prefix + "_store_source"
	instructions = append(instructions,
		asm.StoreImm(asm.RFP, natFlagOffset, 0, asm.Word),
		asm.StoreImm(asm.RFP, natOriginalSourceOffset, 0, asm.Word),
		asm.StoreImm(asm.RFP, natConfigKeyOffset, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, natConfigMap.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, natConfigKeyOffset),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, doneLabel),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.Word),
		asm.JEq.Imm(asm.R1, 0, doneLabel),
		asm.LoadMem(asm.R1, asm.R0, 4, asm.Word),
		asm.StoreMem(asm.RFP, natGatewayOffset, asm.R1, asm.Word),
		asm.LoadMem(asm.R2, asm.R7, 26, asm.Word), // IPv4 source address.
		asm.JEq.Reg(asm.R2, asm.R1, doneLabel),
		asm.StoreMem(asm.RFP, natOriginalSourceOffset, asm.R2, asm.Word),
		asm.StoreImm(asm.RFP, natLPMKeyPrefixOffset, 32, asm.Word),
		asm.StoreMem(asm.RFP, natLPMKeyAddrOffset, asm.R2, asm.Word),
		asm.LoadMapPtr(asm.R1, natSourceMap.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, natLPMKeyPrefixOffset),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, doneLabel),
		asm.LoadMem(asm.R2, asm.R7, 30, asm.Word), // IPv4 destination address.
		asm.StoreImm(asm.RFP, natLPMKeyPrefixOffset, 32, asm.Word),
		asm.StoreMem(asm.RFP, natLPMKeyAddrOffset, asm.R2, asm.Word),
		asm.LoadMapPtr(asm.R1, natRouteMap.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, natLPMKeyPrefixOffset),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, doneLabel),
		asm.LoadMem(asm.R2, asm.R7, 30, asm.Word),
		asm.StoreMem(asm.RFP, natMapKeyOffset, asm.R2, asm.Word),
		asm.LoadMapPtr(asm.R1, natExcludeMap.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, natMapKeyOffset),
		asm.FnMapLookupElem.Call(),
		asm.JNE.Imm(asm.R0, 0, doneLabel),
		asm.LoadMem(asm.R2, asm.R7, 20, asm.Half), // IPv4 flags/fragment offset.
		asm.JSet.Imm(asm.R2, ipv4FragmentMaskLittleEndian, doneLabel),
		asm.LoadMem(asm.R2, asm.R7, 14, asm.Byte),
		asm.And.Imm(asm.R2, 0x0f),
		asm.JLT.Imm(asm.R2, 5, doneLabel),
		asm.LSh.Imm(asm.R2, 2),
		asm.Mov.Reg(asm.R9, asm.R2), // IPv4 header length.
		asm.Mov.Reg(asm.R3, asm.R7),
		asm.Add.Imm(asm.R3, 14),
		asm.Add.Reg(asm.R3, asm.R9), // L4 header.
		asm.LoadMem(asm.R2, asm.R7, 23, asm.Byte),
		asm.JEq.Imm(asm.R2, ipProtocolTCP, tcpLabel),
		asm.JEq.Imm(asm.R2, ipProtocolUDP, udpLabel),
		asm.JEq.Imm(asm.R2, ipProtocolICMP, icmpLabel),
		asm.Ja.Label(doneLabel),
		asm.Mov.Reg(asm.R4, asm.R3).WithSymbol(tcpLabel),
		asm.Add.Imm(asm.R4, 20),
		asm.JGT.Reg(asm.R4, asm.R8, doneLabel),
		asm.Mov.Reg(asm.R2, asm.R9),
		asm.Add.Imm(asm.R2, 30), // Ethernet + IPv4 IHL + TCP checksum offset.
		asm.StoreMem(asm.RFP, natMapKeyOffset, asm.R2, asm.Word),
		asm.Ja.Label(applyL4Label),
		asm.Mov.Reg(asm.R4, asm.R3).WithSymbol(udpLabel),
		asm.Add.Imm(asm.R4, 8),
		asm.JGT.Reg(asm.R4, asm.R8, doneLabel),
		asm.LoadMem(asm.R2, asm.R3, 6, asm.Half),
		asm.JEq.Imm(asm.R2, 0, applyIPOnlyLabel),
		asm.Mov.Reg(asm.R2, asm.R9),
		asm.Add.Imm(asm.R2, 20), // Ethernet + IPv4 IHL + UDP checksum offset.
		asm.StoreMem(asm.RFP, natMapKeyOffset, asm.R2, asm.Word),
		asm.Ja.Label(applyL4Label),
		asm.Mov.Reg(asm.R4, asm.R3).WithSymbol(icmpLabel),
		asm.Add.Imm(asm.R4, 8),
		asm.JGT.Reg(asm.R4, asm.R8, doneLabel),
		asm.LoadMem(asm.R2, asm.R3, 0, asm.Byte),
		asm.JEq.Imm(asm.R2, 0, applyIPOnlyLabel),
		asm.JEq.Imm(asm.R2, 8, applyIPOnlyLabel),
		asm.Ja.Label(doneLabel),
	)
	instructions = appendNATL3Checksum(instructions, applyL4Label, errorLabel)
	instructions = append(instructions,
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.LoadMem(asm.R2, asm.RFP, natMapKeyOffset, asm.Word),
		asm.LoadMem(asm.R3, asm.RFP, natOriginalSourceOffset, asm.Word),
		asm.LoadMem(asm.R4, asm.RFP, natGatewayOffset, asm.Word),
		asm.Mov.Imm(asm.R5, 0x14), // BPF_F_PSEUDO_HDR | sizeof IPv4 address.
		asm.FnL4CsumReplace.Call(),
		asm.JNE.Imm(asm.R0, 0, errorLabel),
		asm.Ja.Label(storeSourceLabel),
	)
	instructions = appendNATL3Checksum(instructions, applyIPOnlyLabel, errorLabel)
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, 0).WithSymbol(storeSourceLabel),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R2, 26), // Ethernet + IPv4 source address offset.
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, natGatewayOffset),
		asm.Mov.Imm(asm.R4, 4),
		asm.Mov.Imm(asm.R5, 0),
		asm.FnSkbStoreBytes.Call(),
		asm.JNE.Imm(asm.R0, 0, errorLabel),
		asm.StoreImm(asm.RFP, natFlagOffset, natEventTranslatedFlag, asm.Word),
	)
	instructions = appendCounter(instructions, statsMap, 12, prefix+"_snat_counter_done")
	instructions = append(instructions, asm.Ja.Label(doneLabel))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol(errorLabel))
	instructions = appendCounter(instructions, statsMap, 13, errorLabel+"_counter_done")
	return append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol(doneLabel))
}

func appendNATL3Checksum(instructions asm.Instructions, label string, errorLabel string) asm.Instructions {
	return append(instructions,
		asm.Mov.Reg(asm.R1, asm.R6).WithSymbol(label),
		asm.Mov.Imm(asm.R2, 24), // Ethernet + IPv4 header checksum offset.
		asm.LoadMem(asm.R3, asm.RFP, natOriginalSourceOffset, asm.Word),
		asm.LoadMem(asm.R4, asm.RFP, natGatewayOffset, asm.Word),
		asm.Mov.Imm(asm.R5, 4),
		asm.FnL3CsumReplace.Call(),
		asm.JNE.Imm(asm.R0, 0, errorLabel),
	)
}

func loadEgressFastPathProgram(name string, statsMap *cebpf.Map, packetPolicyMap *cebpf.Map, routeMap *cebpf.Map, kernelUDPTXRouteMap *cebpf.Map, kernelUDPTXFlowMap *cebpf.Map, natConfigMap *cebpf.Map, natSourceMap *cebpf.Map, natRouteMap *cebpf.Map, natExcludeMap *cebpf.Map, natBindingMap *cebpf.Map, captureMap *cebpf.Map, txDirectOptions ...kernelUDPTXDirectProgramOptions) (*cebpf.Program, error) {
	captureScratchMap, err := newCaptureScratchBPFMap()
	if err != nil {
		return nil, err
	}
	defer captureScratchMap.Close()
	return loadEgressFastPathProgramWithCaptureScratch(name, statsMap, packetPolicyMap, routeMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, natBindingMap, captureMap, captureScratchMap, txDirectOptions...)
}

func loadEgressFastPathProgramWithCaptureScratch(name string, statsMap *cebpf.Map, packetPolicyMap *cebpf.Map, routeMap *cebpf.Map, kernelUDPTXRouteMap *cebpf.Map, kernelUDPTXFlowMap *cebpf.Map, natConfigMap *cebpf.Map, natSourceMap *cebpf.Map, natRouteMap *cebpf.Map, natExcludeMap *cebpf.Map, natBindingMap *cebpf.Map, captureMap *cebpf.Map, captureScratchMap *cebpf.Map, txDirectOptions ...kernelUDPTXDirectProgramOptions) (*cebpf.Program, error) {
	txDirectOption := firstKernelUDPTXDirectProgramOptions(txDirectOptions)
	instructions := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
	}
	instructions = appendHotPathCounter(instructions, statsMap, 1, "egress_packets_done")
	instructions = append(instructions,
		asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),    // skb->data
		asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word), // skb->data_end
		asm.Mov.Reg(asm.R4, asm.R7),
		asm.Add.Imm(asm.R4, 34),
		asm.JGT.Reg(asm.R4, asm.R8, "egress_yield_exit"),
		asm.LoadMem(asm.R4, asm.R7, 12, asm.Half),
		asm.JNE.Imm(asm.R4, 0x0008, "egress_yield_exit"), // ETH_P_IP in packet byte order on little-endian hosts.
	)
	instructions = appendNativeLocalRouteBypass(instructions, statsMap, routeMap, "egress_parse_error", "egress_exit")
	instructions = appendPacketPolicyTCPMSSClamp(instructions, statsMap, packetPolicyMap, "egress_parse_error")
	if txDirectOption.DirectOnly {
		instructions = appendKernelUDPTXDirect(instructions, statsMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, txDirectOption)
		instructions = appendReloadIPv4PacketPointers(instructions, "egress_yield_exit")
	} else {
		instructions = appendKernelUDPTXDirect(instructions, statsMap, kernelUDPTXRouteMap, kernelUDPTXFlowMap, txDirectOption)
	}
	instructions = appendReloadIPv4PacketPointers(instructions, "egress_yield_exit")
	instructions = appendPacketPolicy(instructions, statsMap, packetPolicyMap)
	instructions = append(instructions,
		asm.Mov.Reg(asm.R9, asm.R8),
		asm.Sub.Reg(asm.R9, asm.R7),
		asm.LoadMem(asm.R4, asm.R7, 30, asm.Word), // IPv4 destination address.
		asm.StoreImm(asm.RFP, -16, 32, asm.Word),
		asm.StoreMem(asm.RFP, -12, asm.R4, asm.Word),
		asm.LoadMapPtr(asm.R1, routeMap.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -16),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "egress_route_miss"),
		asm.LoadMem(asm.R4, asm.R0, 0, asm.Word),
		asm.JEq.Imm(asm.R4, routeActionLocal, "egress_local_route"),
		asm.JEq.Imm(asm.R4, routeActionBlackhole, "egress_blackhole_route"),
		asm.JEq.Imm(asm.R4, routeActionReject, "egress_reject_route"),
		asm.Ja.Label("egress_capture_route"),
	)
	instructions = append(instructions, asm.Mov.Reg(asm.R6, asm.R6).WithSymbol("egress_local_route"))
	instructions = append(instructions,
		asm.LoadMem(asm.R4, asm.R0, 8, asm.Word),
		asm.JEq.Imm(asm.R4, 0, "egress_local_route_allow"),
		asm.Mov.Reg(asm.R5, asm.R7),
		asm.Add.Imm(asm.R5, 34),
		asm.JGT.Reg(asm.R5, asm.R8, "egress_exit"),
		asm.LoadMem(asm.R5, asm.R7, 23, asm.Byte),
		asm.JNE.Reg(asm.R5, asm.R4, "egress_local_route_capture"),
		asm.LoadMem(asm.R4, asm.R0, 12, asm.Word),
		asm.JEq.Imm(asm.R4, 0, "egress_local_route_allow"),
		asm.LoadMem(asm.R5, asm.R7, 14, asm.Byte),
		asm.And.Imm(asm.R5, 0x0f),
		asm.LSh.Imm(asm.R5, 2),
		asm.Mov.Reg(asm.R3, asm.R7),
		asm.Add.Imm(asm.R3, 14),
		asm.Add.Reg(asm.R3, asm.R5),
		asm.Mov.Reg(asm.R5, asm.R3),
		asm.Add.Imm(asm.R5, 4),
		asm.JGT.Reg(asm.R5, asm.R8, "egress_exit"),
		asm.LoadMem(asm.R5, asm.R3, 2, asm.Half),
		asm.JNE.Reg(asm.R5, asm.R4, "egress_local_route_capture"),
	)
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("egress_local_route_allow"))
	instructions = appendCounter(instructions, statsMap, 9, "egress_local_route_done")
	instructions = append(instructions, asm.Ja.Label("egress_exit"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("egress_local_route_capture"))
	instructions = append(instructions, asm.Ja.Label("egress_capture_route"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("egress_blackhole_route"))
	instructions = appendCounter(instructions, statsMap, 2, "egress_blackhole_route_hit_done")
	instructions = appendCounter(instructions, statsMap, 10, "egress_blackhole_route_done")
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, tcActShot),
		asm.Return(),
	)
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("egress_reject_route"))
	instructions = appendCounter(instructions, statsMap, 2, "egress_reject_route_hit_done")
	instructions = appendCounter(instructions, statsMap, 11, "egress_reject_route_done")
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, tcActShot),
		asm.Return(),
	)
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("egress_capture_route"))
	instructions = appendHotPathCounter(instructions, statsMap, 2, "egress_route_hit_done")
	instructions = appendTTLExceededFastPath(instructions, statsMap, "egress_ttl_exceeded", "egress_ttl_exceeded_done")
	if txDirectOption.DirectOnly {
		instructions = appendKernelUDPTXDirectOnlyCaptureDrop(instructions, statsMap, kernelUDPTXRouteMap, "egress_direct_only_capture_drop", "egress_capture_packet_ready")
	} else {
		instructions = appendNATOutboundWithLabels(instructions, statsMap, natConfigMap, natSourceMap, natRouteMap, natExcludeMap, "egress_snat", "egress_nat_done")
	}
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("egress_capture_packet_ready"))
	instructions = appendCapturePacketReady(instructions, statsMap, routeMap)
	instructions = appendCaptureEvent(instructions, statsMap, captureMap, captureScratchMap)
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, tcActStolen),
		asm.Return(),
	)
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("egress_route_miss"))
	instructions = appendHotPathCounter(instructions, statsMap, 3, "egress_route_miss_done")
	instructions = append(instructions,
		asm.LoadMem(asm.R7, asm.R6, skbDataOffset, asm.Word),
		asm.LoadMem(asm.R8, asm.R6, skbDataEndOffset, asm.Word),
		asm.Mov.Reg(asm.R4, asm.R7),
		asm.Add.Imm(asm.R4, 34),
		asm.JGT.Reg(asm.R4, asm.R8, "egress_yield_exit"),
		asm.LoadMem(asm.R4, asm.R7, 12, asm.Half),
		asm.JNE.Imm(asm.R4, 0x0008, "egress_yield_exit"),
		asm.StoreImm(asm.RFP, natConfigKeyOffset, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, natConfigMap.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, natConfigKeyOffset),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "egress_yield_exit"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.Word),
		asm.JEq.Imm(asm.R1, 0, "egress_yield_exit"),
		asm.LoadMem(asm.R1, asm.R0, 4, asm.Word), // NAT gateway.
		asm.LoadMem(asm.R2, asm.R7, 30, asm.Word),
		asm.JNE.Reg(asm.R2, asm.R1, "egress_yield_exit"),
		asm.StoreMem(asm.RFP, natOriginalSourceOffset, asm.R1, asm.Word), // old destination.
		asm.LoadMem(asm.R2, asm.R7, 20, asm.Half),                        // IPv4 flags/fragment offset.
		asm.JSet.Imm(asm.R2, ipv4FragmentMaskLittleEndian, "egress_yield_exit"),
		asm.LoadMem(asm.R2, asm.R7, 14, asm.Byte),
		asm.And.Imm(asm.R2, 0x0f),
		asm.JLT.Imm(asm.R2, 5, "egress_yield_exit"),
		asm.LSh.Imm(asm.R2, 2),
		asm.Mov.Reg(asm.R9, asm.R2), // IPv4 header length.
		asm.Mov.Reg(asm.R3, asm.R7),
		asm.Add.Imm(asm.R3, 14),
		asm.Add.Reg(asm.R3, asm.R9), // L4 header.
		asm.StoreMem(asm.RFP, natBindingKeyOffset, asm.R1, asm.Word),
		asm.LoadMem(asm.R2, asm.R7, 26, asm.Word),
		asm.StoreMem(asm.RFP, natBindingKeyOffset+4, asm.R2, asm.Word),
		asm.LoadMem(asm.R2, asm.R7, 23, asm.Byte),
		asm.StoreMem(asm.RFP, natBindingKeyOffset+8, asm.R2, asm.Word),
		asm.StoreImm(asm.RFP, natBindingKeyOffset+16, 0, asm.Word),
		asm.JEq.Imm(asm.R2, ipProtocolTCP, "egress_nat_tcp"),
		asm.JEq.Imm(asm.R2, ipProtocolUDP, "egress_nat_udp"),
		asm.JEq.Imm(asm.R2, ipProtocolICMP, "egress_nat_icmp"),
		asm.Ja.Label("egress_yield_exit"),
		asm.Mov.Reg(asm.R4, asm.R3).WithSymbol("egress_nat_tcp"),
		asm.Add.Imm(asm.R4, 20),
		asm.JGT.Reg(asm.R4, asm.R8, "egress_yield_exit"),
		asm.LoadMem(asm.R4, asm.R3, 2, asm.Half), // destination port = local NAT port.
		asm.StoreMem(asm.RFP, natBindingKeyOffset+12, asm.R4, asm.Half),
		asm.LoadMem(asm.R4, asm.R3, 0, asm.Half), // source port = remote port.
		asm.StoreMem(asm.RFP, natBindingKeyOffset+14, asm.R4, asm.Half),
		asm.Mov.Reg(asm.R2, asm.R9),
		asm.Add.Imm(asm.R2, 30), // Ethernet + IPv4 IHL + TCP checksum offset.
		asm.StoreMem(asm.RFP, natMapKeyOffset, asm.R2, asm.Word),
		asm.Ja.Label("egress_nat_lookup_l4"),
		asm.Mov.Reg(asm.R4, asm.R3).WithSymbol("egress_nat_udp"),
		asm.Add.Imm(asm.R4, 8),
		asm.JGT.Reg(asm.R4, asm.R8, "egress_yield_exit"),
		asm.LoadMem(asm.R4, asm.R3, 2, asm.Half), // destination port = local NAT port.
		asm.StoreMem(asm.RFP, natBindingKeyOffset+12, asm.R4, asm.Half),
		asm.LoadMem(asm.R4, asm.R3, 0, asm.Half), // source port = remote port.
		asm.StoreMem(asm.RFP, natBindingKeyOffset+14, asm.R4, asm.Half),
		asm.LoadMem(asm.R4, asm.R3, 6, asm.Half),
		asm.JEq.Imm(asm.R4, 0, "egress_nat_lookup_ip_only"),
		asm.Mov.Reg(asm.R2, asm.R9),
		asm.Add.Imm(asm.R2, 20), // Ethernet + IPv4 IHL + UDP checksum offset.
		asm.StoreMem(asm.RFP, natMapKeyOffset, asm.R2, asm.Word),
		asm.Ja.Label("egress_nat_lookup_l4"),
		asm.Mov.Reg(asm.R4, asm.R3).WithSymbol("egress_nat_icmp"),
		asm.Add.Imm(asm.R4, 8),
		asm.JGT.Reg(asm.R4, asm.R8, "egress_yield_exit"),
		asm.LoadMem(asm.R4, asm.R3, 0, asm.Byte),
		asm.JEq.Imm(asm.R4, 0, "egress_nat_icmp_type_ok"),
		asm.JNE.Imm(asm.R4, 8, "egress_yield_exit"),
		asm.LoadMem(asm.R4, asm.R3, 4, asm.Half).WithSymbol("egress_nat_icmp_type_ok"),
		asm.StoreMem(asm.RFP, natBindingKeyOffset+12, asm.R4, asm.Half),
		asm.StoreMem(asm.RFP, natBindingKeyOffset+14, asm.R4, asm.Half),
		asm.Ja.Label("egress_nat_lookup_ip_only"),
	)
	instructions = appendNATBindingLookup(instructions, natBindingMap, "egress_nat_lookup_l4", "egress_nat_l4_binding_fresh", "egress_yield_exit")
	instructions = appendNATL3Checksum(instructions, "egress_nat_apply_l4", "egress_nat_error")
	instructions = append(instructions,
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.LoadMem(asm.R2, asm.RFP, natMapKeyOffset, asm.Word),
		asm.LoadMem(asm.R3, asm.RFP, natOriginalSourceOffset, asm.Word),
		asm.LoadMem(asm.R4, asm.RFP, natGatewayOffset, asm.Word),
		asm.Mov.Imm(asm.R5, 0x14), // BPF_F_PSEUDO_HDR | sizeof IPv4 address.
		asm.FnL4CsumReplace.Call(),
		asm.JNE.Imm(asm.R0, 0, "egress_nat_error"),
		asm.Ja.Label("egress_nat_store_destination"),
	)
	instructions = appendNATBindingLookup(instructions, natBindingMap, "egress_nat_lookup_ip_only", "egress_nat_ip_only_binding_fresh", "egress_yield_exit")
	instructions = appendNATL3Checksum(instructions, "egress_nat_apply_ip_only", "egress_nat_error")
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("egress_nat_store_destination"),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R2, 30), // Ethernet + IPv4 destination address offset.
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, natGatewayOffset),
		asm.Mov.Imm(asm.R4, 4),
		asm.Mov.Imm(asm.R5, 0),
		asm.FnSkbStoreBytes.Call(),
		asm.JNE.Imm(asm.R0, 0, "egress_nat_error"),
	)
	instructions = appendCounter(instructions, statsMap, 14, "egress_nat_dnat_counter_done")
	instructions = append(instructions, asm.Ja.Label("egress_exit"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("egress_nat_error"))
	instructions = appendCounter(instructions, statsMap, 13, "egress_nat_error_counter_done")
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("packet_mtu_drop"))
	instructions = appendCounter(instructions, statsMap, 15, "egress_packet_mtu_drop_done")
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, tcActShot),
		asm.Return(),
	)
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("packet_fragment_drop"))
	instructions = appendCounter(instructions, statsMap, 16, "egress_packet_fragment_drop_done")
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, tcActShot),
		asm.Return(),
	)
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("egress_parse_error"))
	instructions = appendHotPathCounter(instructions, statsMap, 6, "egress_parse_error_done")
	instructions = append(instructions, asm.Ja.Label("egress_yield_exit"))
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, tcActUnspec).WithSymbol("egress_yield_exit"),
		asm.Return(),
		asm.Mov.Imm(asm.R0, tcActOK).WithSymbol("egress_exit"),
		asm.Return(),
	)
	debugDumpBPFInstructions(name, instructions)
	program, err := newBPFProgramWithOptions(&cebpf.ProgramSpec{
		Name:         name,
		Type:         cebpf.SchedCLS,
		Instructions: withTCProgramBTFMetadata(instructions),
		License:      "GPL",
	}, cebpf.ProgramOptions{LogLevel: cebpf.LogLevelBranch})
	if err != nil {
		return nil, verboseBPFLoadError(err)
	}
	return program, nil
}

func appendNATBindingLookup(instructions asm.Instructions, natBindingMap *cebpf.Map, label string, freshLabel string, missLabel string) asm.Instructions {
	return append(instructions,
		asm.LoadMapPtr(asm.R1, natBindingMap.FD()).WithSymbol(label),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, natBindingKeyOffset),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, missLabel),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.Word),
		asm.StoreMem(asm.RFP, natGatewayOffset, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R0, 8, asm.DWord),
		asm.JEq.Imm(asm.R1, 0, freshLabel),
		asm.StoreMem(asm.RFP, natDnatExpiresOffset, asm.R1, asm.DWord),
		asm.FnKtimeGetNs.Call(),
		asm.LoadMem(asm.R1, asm.RFP, natDnatExpiresOffset, asm.DWord),
		asm.JGT.Reg(asm.R0, asm.R1, missLabel),
		asm.Mov.Imm(asm.R0, 0).WithSymbol(freshLabel),
	)
}

func loadCountingProgram(name string, statsMap *cebpf.Map, counterKey uint32) (*cebpf.Program, error) {
	instructions := appendCounter(nil, statsMap, counterKey, "counter_done")
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, tcActOK),
		asm.Return(),
	)
	return newBPFProgramWithOptions(&cebpf.ProgramSpec{
		Name:         name,
		Type:         cebpf.SchedCLS,
		Instructions: withTCProgramBTFMetadata(instructions),
		License:      "GPL",
	}, cebpf.ProgramOptions{LogLevel: cebpf.LogLevelBranch})
}

func appendCounter(instructions asm.Instructions, statsMap *cebpf.Map, counterKey uint32, doneLabel string) asm.Instructions {
	doneLabel = uniqueInstructionSymbol(instructions, doneLabel)
	return append(instructions,
		asm.StoreImm(asm.RFP, -4, int64(counterKey), asm.Word),
		asm.LoadMapPtr(asm.R1, statsMap.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, doneLabel),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord),
		asm.Add.Imm(asm.R1, 1),
		asm.StoreMem(asm.R0, 0, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R0, 0).WithSymbol(doneLabel),
	)
}

func appendSetCounterValueFromStackWord(instructions asm.Instructions, statsMap *cebpf.Map, counterKey uint32, valueOffset int16, doneLabel string) asm.Instructions {
	doneLabel = uniqueInstructionSymbol(instructions, doneLabel)
	return append(instructions,
		asm.StoreImm(asm.RFP, -4, int64(counterKey), asm.Word),
		asm.LoadMapPtr(asm.R1, statsMap.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, doneLabel),
		asm.LoadMem(asm.R1, asm.RFP, valueOffset, asm.DWord),
		asm.Mov.Imm(asm.R2, 0),
		asm.Sub.Reg(asm.R2, asm.R1),
		asm.StoreMem(asm.R0, 0, asm.R2, asm.DWord),
		asm.Mov.Imm(asm.R0, 0).WithSymbol(doneLabel),
	)
}

func uniqueInstructionSymbol(instructions asm.Instructions, symbol string) string {
	if symbol == "" || !instructionsContainSymbolOrReference(instructions, symbol) {
		return symbol
	}
	for suffix := 2; ; suffix++ {
		candidate := fmt.Sprintf("%s_%d", symbol, suffix)
		if !instructionsContainSymbolOrReference(instructions, candidate) {
			return candidate
		}
	}
}

func instructionsContainSymbolOrReference(instructions asm.Instructions, symbol string) bool {
	for _, ins := range instructions {
		if ins.Symbol() == symbol || ins.Reference() == symbol {
			return true
		}
	}
	return false
}

func appendHotPathCounter(instructions asm.Instructions, statsMap *cebpf.Map, counterKey uint32, doneLabel string) asm.Instructions {
	if !experimentalTCPHotPathStats() || statsMap == nil {
		return instructions
	}
	return appendCounter(instructions, statsMap, counterKey, doneLabel)
}

func appendHotPathCounterPreserveR0(instructions asm.Instructions, statsMap *cebpf.Map, counterKey uint32, doneLabel string) asm.Instructions {
	if !experimentalTCPHotPathStats() || statsMap == nil {
		return instructions
	}
	instructions = append(instructions, asm.StoreMem(asm.RFP, kernelUDPTXFlowDefaultOffset, asm.R0, asm.DWord))
	instructions = appendCounter(instructions, statsMap, counterKey, doneLabel)
	return append(instructions, asm.LoadMem(asm.R0, asm.RFP, kernelUDPTXFlowDefaultOffset, asm.DWord))
}

func appendCaptureEvent(instructions asm.Instructions, statsMap *cebpf.Map, captureMap *cebpf.Map, captureScratchMap *cebpf.Map) asm.Instructions {
	sampleLimit := int32(captureSampleLimit)
	instructions = append(instructions,
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, captureScratchMap.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "capture_scratch_miss"),
		asm.StoreMem(asm.RFP, captureScratchPtrOffset, asm.R0, asm.DWord),
		asm.StoreImm(asm.RFP, captureEventBase, int64(captureMagic), asm.Word),
		asm.StoreImm(asm.RFP, captureEventBase+4, 1, asm.Word), // version
		asm.StoreImm(asm.RFP, captureEventBase+8, 1, asm.Word), // LAN ingress route hit
		asm.StoreMem(asm.RFP, captureEventBase+12, asm.R9, asm.Word),
		asm.LoadMem(asm.R1, asm.R7, 26, asm.Word), // IPv4 source address.
		asm.StoreMem(asm.RFP, captureEventBase+20, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R7, 30, asm.Word), // IPv4 destination address.
		asm.StoreMem(asm.RFP, captureEventBase+24, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.RFP, natFlagOffset, asm.Word),
		asm.StoreMem(asm.RFP, captureEventBase+28, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.RFP, natOriginalSourceOffset, asm.Word),
		asm.StoreMem(asm.RFP, captureEventBase+32, asm.R1, asm.Word),
		asm.LoadMem(asm.R1, asm.R6, skbGSOSizeOffset, asm.Word),
		asm.StoreMem(asm.RFP, captureEventBase+36, asm.R1, asm.Word),
		asm.Mov.Reg(asm.R4, asm.R9),
		asm.JLE.Imm(asm.R4, 0, "capture_error"),
		asm.JLE.Imm(asm.R4, sampleLimit, "capture_sample_len_ready"),
		asm.Mov.Imm(asm.R4, sampleLimit),
		asm.StoreMem(asm.RFP, captureEventBase+16, asm.R4, asm.Word).WithSymbol("capture_sample_len_ready"),
		asm.LoadMem(asm.R5, asm.RFP, captureScratchPtrOffset, asm.DWord),
		asm.LoadMem(asm.R2, asm.RFP, captureEventBase, asm.DWord),
		asm.StoreMem(asm.R5, 0, asm.R2, asm.DWord),
		asm.LoadMem(asm.R2, asm.RFP, captureEventBase+8, asm.DWord),
		asm.StoreMem(asm.R5, 8, asm.R2, asm.DWord),
		asm.LoadMem(asm.R2, asm.RFP, captureEventBase+16, asm.DWord),
		asm.StoreMem(asm.R5, 16, asm.R2, asm.DWord),
		asm.LoadMem(asm.R2, asm.RFP, captureEventBase+24, asm.DWord),
		asm.StoreMem(asm.R5, 24, asm.R2, asm.DWord),
		asm.LoadMem(asm.R2, asm.RFP, captureEventBase+32, asm.DWord),
		asm.StoreMem(asm.R5, 32, asm.R2, asm.DWord),
	)
	instructions = appendCaptureEventCopyChunks(instructions)
	if captureOutputIsRingbuf(captureMap) {
		instructions = appendCaptureRingbufOutput(instructions, captureMap)
	} else {
		instructions = appendCapturePerfEventOutputBuckets(instructions, captureMap)
	}
	instructions = appendCounter(instructions, statsMap, 7, "capture_success_counter_done")
	instructions = append(instructions, asm.Ja.Label("capture_done"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("capture_scratch_miss"))
	instructions = appendCounter(instructions, statsMap, captureStatScratchMisses, "capture_scratch_miss_counter_done")
	instructions = append(instructions, asm.Ja.Label("capture_error"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("capture_load_bytes_error"))
	instructions = appendCounter(instructions, statsMap, captureStatLoadBytesErrors, "capture_load_bytes_error_counter_done")
	instructions = append(instructions, asm.Ja.Label("capture_error"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("capture_perf_enoent"))
	instructions = appendCounter(instructions, statsMap, captureStatPerfErrENOENT, "capture_perf_enoent_counter_done")
	instructions = append(instructions, asm.Ja.Label("capture_perf_error"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("capture_perf_efault"))
	instructions = appendCounter(instructions, statsMap, captureStatPerfErrEFAULT, "capture_perf_efault_counter_done")
	instructions = append(instructions, asm.Ja.Label("capture_perf_error"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("capture_perf_einval"))
	instructions = appendCounter(instructions, statsMap, captureStatPerfErrEINVAL, "capture_perf_einval_counter_done")
	instructions = append(instructions, asm.Ja.Label("capture_perf_error"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("capture_perf_e2big"))
	instructions = appendCounter(instructions, statsMap, captureStatPerfErrE2BIG, "capture_perf_e2big_counter_done")
	instructions = append(instructions, asm.Ja.Label("capture_perf_error"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("capture_perf_enospc"))
	instructions = appendCounter(instructions, statsMap, captureStatPerfErrENOSPC, "capture_perf_enospc_counter_done")
	instructions = append(instructions, asm.Ja.Label("capture_perf_error"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("capture_perf_eperm"))
	instructions = appendCounter(instructions, statsMap, captureStatPerfErrEPERM, "capture_perf_eperm_counter_done")
	instructions = append(instructions, asm.Ja.Label("capture_perf_error"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("capture_perf_other"))
	instructions = appendCounter(instructions, statsMap, captureStatPerfErrOther, "capture_perf_other_counter_done")
	instructions = append(instructions, asm.Ja.Label("capture_perf_error"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("capture_perf_error"))
	instructions = appendSetCounterValueFromStackWord(instructions, statsMap, captureStatPerfLastErrno, capturePerfReturnOffset, "capture_perf_last_errno_done")
	instructions = appendCounter(instructions, statsMap, captureStatPerfErrors, "capture_perf_error_counter_done")
	instructions = append(instructions, asm.Ja.Label("capture_error"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("capture_error"))
	instructions = appendCounter(instructions, statsMap, 8, "capture_error_counter_done")
	return append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("capture_done"))
}

func appendCaptureEventCopyChunks(instructions asm.Instructions) asm.Instructions {
	return append(instructions,
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R2, 0),
		asm.LoadMem(asm.R3, asm.RFP, captureScratchPtrOffset, asm.DWord),
		asm.Add.Imm(asm.R3, captureEventHeader),
		asm.LoadMem(asm.R4, asm.RFP, captureEventBase+16, asm.Word),
		asm.FnSkbLoadBytes.Call(),
		asm.JNE.Imm(asm.R0, 0, "capture_load_bytes_error"),
	)
}

func appendCapturePerfEventOutputBuckets(instructions asm.Instructions, captureMap *cebpf.Map) asm.Instructions {
	return append(instructions,
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.LoadMapPtr(asm.R2, captureMap.FD()),
		asm.LoadImm(asm.R3, 0xffffffff, asm.DWord), // BPF_F_CURRENT_CPU
		asm.LoadMem(asm.R4, asm.RFP, captureScratchPtrOffset, asm.DWord),
		asm.LoadMem(asm.R5, asm.RFP, captureEventBase+16, asm.Word),
		asm.Add.Imm(asm.R5, captureEventHeader),
		asm.FnPerfEventOutput.Call(),
		asm.StoreMem(asm.RFP, capturePerfReturnOffset, asm.R0, asm.DWord),
		asm.JEq.Imm(asm.R0, 0, "capture_perf_done"),
		asm.JEq.Imm(asm.R0, -int32(unix.ENOENT), "capture_perf_enoent"),
		asm.JEq.Imm(asm.R0, -int32(unix.EFAULT), "capture_perf_efault"),
		asm.JEq.Imm(asm.R0, -int32(unix.EINVAL), "capture_perf_einval"),
		asm.JEq.Imm(asm.R0, -int32(unix.E2BIG), "capture_perf_e2big"),
		asm.JEq.Imm(asm.R0, -int32(unix.ENOSPC), "capture_perf_enospc"),
		asm.JEq.Imm(asm.R0, -int32(unix.EPERM), "capture_perf_eperm"),
		asm.Ja.Label("capture_perf_other"),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("capture_perf_done"),
	)
}

func appendCaptureRingbufOutput(instructions asm.Instructions, captureMap *cebpf.Map) asm.Instructions {
	return append(instructions,
		asm.LoadMapPtr(asm.R1, captureMap.FD()),
		asm.LoadMem(asm.R2, asm.RFP, captureScratchPtrOffset, asm.DWord),
		asm.LoadMem(asm.R3, asm.RFP, captureEventBase+16, asm.Word),
		asm.Add.Imm(asm.R3, captureEventHeader),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnRingbufOutput.Call(),
		asm.StoreMem(asm.RFP, capturePerfReturnOffset, asm.R0, asm.DWord),
		asm.JEq.Imm(asm.R0, 0, "capture_perf_done"),
		asm.JEq.Imm(asm.R0, -int32(unix.ENOENT), "capture_perf_enoent"),
		asm.JEq.Imm(asm.R0, -int32(unix.EFAULT), "capture_perf_efault"),
		asm.JEq.Imm(asm.R0, -int32(unix.EINVAL), "capture_perf_einval"),
		asm.JEq.Imm(asm.R0, -int32(unix.E2BIG), "capture_perf_e2big"),
		asm.JEq.Imm(asm.R0, -int32(unix.ENOSPC), "capture_perf_enospc"),
		asm.JEq.Imm(asm.R0, -int32(unix.EPERM), "capture_perf_eperm"),
		asm.Ja.Label("capture_perf_other"),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("capture_perf_done"),
	)
}

func verboseBPFLoadError(err error) error {
	if err == nil || strings.TrimSpace(os.Getenv("TRUSTIX_VERBOSE_BPF_LOAD_ERROR")) == "" {
		return err
	}
	return fmt.Errorf("%+v", err)
}

func debugDumpBPFInstructions(name string, instructions asm.Instructions) {
	path := strings.TrimSpace(os.Getenv("TRUSTIX_DEBUG_DUMP_BPF_INSTRUCTIONS"))
	if path == "" {
		return
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return
	}
	var builder strings.Builder
	for i, ins := range instructions {
		if sym := ins.Symbol(); sym != "" {
			builder.WriteString(fmt.Sprintf("%04d: <%s>\n", i, sym))
		}
		if ref := ins.Reference(); ref != "" {
			builder.WriteString(fmt.Sprintf("%04d: %v <%s>\n", i, ins, ref))
			continue
		}
		builder.WriteString(fmt.Sprintf("%04d: %v\n", i, ins))
	}
	_ = os.WriteFile(filepath.Join(path, name+".insns"), []byte(builder.String()), 0o644)
}

func bpfFilter(link netlink.Link, parent uint32, handle uint32, name string, fd int) *netlink.BpfFilter {
	return bpfFilterWithPriority(link, parent, handle, name, fd, 1)
}

func bpfFilterWithPriority(link netlink.Link, parent uint32, handle uint32, name string, fd int, priority uint16) *netlink.BpfFilter {
	return &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    parent,
			Handle:    handle,
			Protocol:  unix.ETH_P_ALL,
			Priority:  priority,
		},
		Fd:           fd,
		Name:         name,
		DirectAction: true,
	}
}

func (manager *Manager) attachTCFiltersToLink(link netlink.Link, spec dataplane.AttachSpec) error {
	if link == nil || link.Attrs() == nil {
		return fmt.Errorf("attach TC filters: LAN link is nil")
	}
	if manager.ingressProg == nil || manager.egressProg == nil {
		return fmt.Errorf("attach TC filters on %q: TC programs are not loaded", link.Attrs().Name)
	}
	if manager.lanTCFilters == nil {
		manager.lanTCFilters = make(map[string]lanTCFilterState)
	}
	if _, exists := manager.lanTCFilters[link.Attrs().Name]; exists {
		return nil
	}
	ingressFilter := bpfFilter(link, netlink.HANDLE_MIN_INGRESS, netlink.MakeHandle(0, 1), "trustix_ingress", manager.ingressProg.FD())
	egressFilter := bpfFilter(link, netlink.HANDLE_MIN_EGRESS, netlink.MakeHandle(0, 2), "trustix_egress", manager.egressProg.FD())
	state := lanTCFilterState{ingress: ingressFilter, egress: egressFilter}
	if manager.kernelUDPTXSecureDirect != nil && manager.kernelUDPTXSecureDirect.program != nil {
		if kernelUDPTXSecureDirectIngressEnabled() {
			state.kernelUDPTXSecureDirect = bpfFilterWithPriority(link, netlink.HANDLE_MIN_INGRESS, netlink.MakeHandle(0, 4), "trustix_kudp_txk", manager.kernelUDPTXSecureDirect.program.FD(), 1)
			ingressFilter.Priority = 2
		}
		if kernelUDPTXSecureDirectEgressEnabled() {
			state.kernelUDPTXSecureDirectEgress = bpfFilterWithPriority(link, netlink.HANDLE_MIN_EGRESS, netlink.MakeHandle(0, 4), "trustix_kudp_txke", manager.kernelUDPTXSecureDirect.program.FD(), 1)
			egressFilter.Priority = 2
		}
	}
	if state.kernelUDPTXSecureDirect != nil {
		if err := netlink.FilterReplace(state.kernelUDPTXSecureDirect); err != nil {
			return fmt.Errorf("attach kernel_udp secure TC TX direct BPF filter on %q: %w", link.Attrs().Name, err)
		}
	}
	if state.kernelUDPTXSecureDirectEgress != nil {
		if err := netlink.FilterReplace(state.kernelUDPTXSecureDirectEgress); err != nil {
			if state.kernelUDPTXSecureDirect != nil {
				_ = netlink.FilterDel(state.kernelUDPTXSecureDirect)
			}
			return fmt.Errorf("attach kernel_udp secure TC TX direct egress BPF filter on %q: %w", link.Attrs().Name, err)
		}
	}
	if err := netlink.FilterReplace(ingressFilter); err != nil {
		if state.kernelUDPTXSecureDirectEgress != nil {
			_ = netlink.FilterDel(state.kernelUDPTXSecureDirectEgress)
		}
		if state.kernelUDPTXSecureDirect != nil {
			_ = netlink.FilterDel(state.kernelUDPTXSecureDirect)
		}
		return fmt.Errorf("attach ingress BPF filter on %q: %w", link.Attrs().Name, err)
	}
	if err := netlink.FilterReplace(egressFilter); err != nil {
		_ = netlink.FilterDel(ingressFilter)
		if state.kernelUDPTXSecureDirectEgress != nil {
			_ = netlink.FilterDel(state.kernelUDPTXSecureDirectEgress)
		}
		if state.kernelUDPTXSecureDirect != nil {
			_ = netlink.FilterDel(state.kernelUDPTXSecureDirect)
		}
		return fmt.Errorf("attach egress BPF filter on %q: %w", link.Attrs().Name, err)
	}
	manager.lanTCFilters[link.Attrs().Name] = state
	if link.Attrs().Name == manager.spec.LANIface || manager.ingressFilter == nil {
		manager.ingressFilter = ingressFilter
		manager.egressFilter = egressFilter
		manager.kernelUDPTXSecureDirectFilter = state.kernelUDPTXSecureDirect
		manager.kernelUDPTXSecureDirectEgressFilter = state.kernelUDPTXSecureDirectEgress
	}
	if state.kernelUDPTXSecureDirect != nil || state.kernelUDPTXSecureDirectEgress != nil {
		manager.kernelUDPTXSecureDirectAttached = true
	}
	return nil
}

func (manager *Manager) detachTCFiltersFromLink(link netlink.Link) error {
	if link == nil || link.Attrs() == nil {
		return nil
	}
	state, ok := manager.lanTCFilters[link.Attrs().Name]
	if !ok {
		return nil
	}
	var errs []string
	if state.kernelUDPTXSecureDirectEgress != nil {
		if err := netlink.FilterDel(state.kernelUDPTXSecureDirectEgress); err != nil && !isNotFound(err) {
			errs = append(errs, fmt.Sprintf("remove kernel_udp secure TC TX direct egress BPF filter from %q: %v", link.Attrs().Name, err))
		}
	}
	if state.kernelUDPTXSecureDirect != nil {
		if err := netlink.FilterDel(state.kernelUDPTXSecureDirect); err != nil && !isNotFound(err) {
			errs = append(errs, fmt.Sprintf("remove kernel_udp secure TC TX direct BPF filter from %q: %v", link.Attrs().Name, err))
		}
	}
	if state.ingress != nil {
		if err := netlink.FilterDel(state.ingress); err != nil && !isNotFound(err) {
			errs = append(errs, fmt.Sprintf("remove ingress BPF filter from %q: %v", link.Attrs().Name, err))
		}
	}
	if state.egress != nil {
		if err := netlink.FilterDel(state.egress); err != nil && !isNotFound(err) {
			errs = append(errs, fmt.Sprintf("remove egress BPF filter from %q: %v", link.Attrs().Name, err))
		}
	}
	delete(manager.lanTCFilters, link.Attrs().Name)
	if manager.ingressFilter == state.ingress {
		manager.ingressFilter = nil
	}
	if manager.egressFilter == state.egress {
		manager.egressFilter = nil
	}
	if manager.kernelUDPTXSecureDirectFilter == state.kernelUDPTXSecureDirect {
		manager.kernelUDPTXSecureDirectFilter = nil
	}
	if manager.kernelUDPTXSecureDirectEgressFilter == state.kernelUDPTXSecureDirectEgress {
		manager.kernelUDPTXSecureDirectEgressFilter = nil
	}
	if len(manager.lanTCFilters) == 0 {
		manager.kernelUDPTXSecureDirectAttached = false
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func (manager *Manager) readCountersLocked() []observability.Counter {
	if manager.statsMap == nil {
		return manager.experimentalTCPCountersLocked(nil)
	}
	keys := []struct {
		key  uint32
		name string
	}{
		{key: 0, name: "tc_ingress_packets"},
		{key: 1, name: "tc_egress_packets"},
		{key: 2, name: "tc_ingress_route_hits"},
		{key: 3, name: "tc_ingress_route_misses"},
		{key: 4, name: "tc_ingress_ipv4_packets"},
		{key: 5, name: "tc_ingress_non_ipv4_packets"},
		{key: 6, name: "tc_ingress_parse_errors"},
		{key: 7, name: "tc_capture_events"},
		{key: 8, name: "tc_capture_errors"},
		{key: 9, name: "tc_ingress_local_routes"},
		{key: 10, name: "tc_ingress_blackhole_routes"},
		{key: 11, name: "tc_ingress_reject_routes"},
		{key: 12, name: "tc_nat_snat_translations"},
		{key: 13, name: "tc_nat_errors"},
		{key: 14, name: "tc_nat_dnat_translations"},
		{key: 15, name: "tc_packet_mtu_drops"},
		{key: 16, name: "tc_packet_fragment_drops"},
		{key: 17, name: "tc_reject_no_reply_drops"},
		{key: 18, name: "tc_reject_tcp_rst_generated"},
		{key: 19, name: "tc_reject_tcp_rst_errors"},
		{key: 20, name: "tc_reject_icmp_generated"},
		{key: 21, name: "tc_reject_icmp_errors"},
		{key: kernelUDPTXStatSuccess, name: "tc_kernel_udp_tx_direct_packets"},
		{key: kernelUDPTXStatErrors, name: "tc_kernel_udp_tx_direct_errors"},
		{key: kernelUDPTXStatDrops, name: "tc_kernel_udp_tx_direct_drops"},
		{key: kernelUDPRXDirectStatSuccess, name: "tc_kernel_udp_rx_direct_packets"},
		{key: kernelUDPRXDirectStatErrors, name: "tc_kernel_udp_rx_direct_errors"},
		{key: kernelUDPRXDirectStatDrops, name: "tc_kernel_udp_rx_direct_drops"},
		{key: kernelUDPRXDirectStatPasses, name: "tc_kernel_udp_rx_direct_candidates"},
		{key: packetPolicyTCPMSSClampStatSuccess, name: "tc_packet_policy_tcp_mss_clamps"},
		{key: packetPolicyTCPMSSClampStatErrors, name: "tc_packet_policy_tcp_mss_clamp_errors"},
		{key: packetPolicyTCPMSSClampStatDrops, name: "tc_packet_policy_tcp_mss_clamp_drops"},
		{key: kernelUDPRXDirectStatNeighHits, name: "tc_kernel_udp_rx_direct_neighbor_hits"},
		{key: kernelUDPRXDirectStatNeighMisses, name: "tc_kernel_udp_rx_direct_neighbor_misses"},
		{key: kernelUDPRXDirectStatFrameHeaderErrors, name: "tc_kernel_udp_rx_direct_frame_header_errors"},
		{key: kernelUDPRXDirectStatInnerHeaderErrors, name: "tc_kernel_udp_rx_direct_inner_header_errors"},
		{key: kernelUDPRXDirectStatInnerLenErrors, name: "tc_kernel_udp_rx_direct_inner_len_errors"},
		{key: kernelUDPRXDirectStatOuterLenErrors, name: "tc_kernel_udp_rx_direct_outer_len_errors"},
		{key: kernelUDPRXDirectStatAdjustDrops, name: "tc_kernel_udp_rx_direct_adjust_drops"},
		{key: kernelUDPRXDirectStatStoreDrops, name: "tc_kernel_udp_rx_direct_store_drops"},
		{key: kernelUDPRXDirectStatLocalDeliveries, name: "tc_kernel_udp_rx_direct_local_deliveries"},
		{key: tcTTLExceededICMPGeneratedStat, name: "tc_ttl_exceeded_icmp_generated"},
		{key: tcTTLExceededICMPErrorsStat, name: "tc_ttl_exceeded_icmp_errors"},
		{key: tcTTLExceededNoReplyDropsStat, name: "tc_ttl_exceeded_no_reply_drops"},
		{key: tcTTLExceededFallbacksStat, name: "tc_ttl_exceeded_fallbacks"},
		{key: kernelUDPTXSecureDirectStatAttempts, name: "tc_kernel_udp_tx_secure_direct_attempts"},
		{key: kernelUDPTXSecureDirectStatCandidates, name: "tc_kernel_udp_tx_secure_direct_candidates"},
		{key: kernelUDPTXSecureDirectStatSuccess, name: "tc_kernel_udp_tx_secure_direct_packets"},
		{key: kernelUDPTXSecureDirectStatFallbacks, name: "tc_kernel_udp_tx_secure_direct_fallbacks"},
		{key: kernelUDPTXSecureDirectStatNoContext, name: "tc_kernel_udp_tx_secure_direct_no_context"},
		{key: kernelUDPTXSecureDirectStatHeaderErrors, name: "tc_kernel_udp_tx_secure_direct_header_errors"},
		{key: kernelUDPTXSecureDirectStatEncryptErrors, name: "tc_kernel_udp_tx_secure_direct_encrypt_errors"},
		{key: kernelUDPTXSecureDirectStatSequenceErrors, name: "tc_kernel_udp_tx_secure_direct_sequence_errors"},
		{key: kernelUDPTXSecureDirectStatMTUFallbacks, name: "tc_kernel_udp_tx_secure_direct_mtu_fallbacks"},
		{key: kernelUDPTXSecureDirectStatDrops, name: "tc_kernel_udp_tx_secure_direct_drops"},
		{key: kernelUDPTXSecureDirectStatRouteMisses, name: "tc_kernel_udp_tx_secure_direct_route_misses"},
		{key: kernelUDPTXSecureDirectStatFlowMisses, name: "tc_kernel_udp_tx_secure_direct_flow_misses"},
		{key: kernelUDPTXSecureDirectStatFlagMisses, name: "tc_kernel_udp_tx_secure_direct_flag_misses"},
		{key: kernelUDPTXSecureDirectStatFragmentFallbacks, name: "tc_kernel_udp_tx_secure_direct_fragment_fallbacks"},
		{key: kernelUDPTXSecureDirectStatLenMismatches, name: "tc_kernel_udp_tx_secure_direct_len_mismatches"},
		{key: kernelUDPTXSecureDirectStatNonTCPFallbacks, name: "tc_kernel_udp_tx_secure_direct_non_tcp_fallbacks"},
		{key: kernelUDPTXSecureDirectStatSYNFallbacks, name: "tc_kernel_udp_tx_secure_direct_syn_fallbacks"},
		{key: kernelUDPTXSecureDirectStatChecksumFallbacks, name: "tc_kernel_udp_tx_secure_direct_checksum_fallbacks"},
		{key: kernelUDPTXSecureDirectStatMTUPlainMaxFallbacks, name: "tc_kernel_udp_tx_secure_direct_mtu_plain_max_fallbacks"},
		{key: kernelUDPTXSecureDirectStatMTUUnderlayFallbacks, name: "tc_kernel_udp_tx_secure_direct_mtu_underlay_fallbacks"},
		{key: kernelUDPTXSecureDirectStatLenGSOFallbacks, name: "tc_kernel_udp_tx_secure_direct_len_gso_fallbacks"},
		{key: kernelUDPTXSecureDirectStatLenShortFallbacks, name: "tc_kernel_udp_tx_secure_direct_len_short_fallbacks"},
		{key: kernelUDPTXSecureDirectStatMTUUnderlay1500Fallbacks, name: "tc_kernel_udp_tx_secure_direct_mtu_underlay_1500ish_fallbacks"},
		{key: kernelUDPTXSecureDirectStatMTUUnderlayJumboFallbacks, name: "tc_kernel_udp_tx_secure_direct_mtu_underlay_jumbo_fallbacks"},
		{key: kernelUDPTXSecureDirectStatMTUUnderlayInnerGT1400Fallbacks, name: "tc_kernel_udp_tx_secure_direct_mtu_underlay_inner_gt_1400_fallbacks"},
		{key: kernelUDPTXSecureDirectStatMTUUnderlayInnerLE1400Fallbacks, name: "tc_kernel_udp_tx_secure_direct_mtu_underlay_inner_le_1400_fallbacks"},
		{key: kernelUDPTXSecureDirectStatFlowIndexMisses, name: "tc_kernel_udp_tx_secure_direct_flow_index_misses"},
		{key: kernelUDPTXSecureDirectStatDirectSlotMisses, name: "tc_kernel_udp_tx_secure_direct_direct_slot_misses"},
		{key: kernelUDPTXSecureDirectStatDirectSlotDisabled, name: "tc_kernel_udp_tx_secure_direct_direct_slot_disabled"},
		{key: 179, name: "tc_kernel_udp_tx_secure_direct_skb_seal_successes"},
		{key: 180, name: "tc_kernel_udp_tx_secure_direct_skb_seal_errors"},
		{key: 181, name: "tc_kernel_udp_tx_secure_direct_skb_seal_einval"},
		{key: 182, name: "tc_kernel_udp_tx_secure_direct_skb_seal_eopnotsupp"},
		{key: 183, name: "tc_kernel_udp_tx_secure_direct_skb_seal_efault"},
		{key: 184, name: "tc_kernel_udp_tx_secure_direct_outer_tcp_csum_kfunc_successes"},
		{key: 185, name: "tc_kernel_udp_tx_secure_direct_outer_tcp_csum_kfunc_errors"},
		{key: 186, name: "tc_kernel_udp_tx_secure_direct_outer_tcp_partial_csum_kfunc_successes"},
		{key: 187, name: "tc_kernel_udp_tx_secure_direct_outer_tcp_partial_csum_kfunc_errors"},
		{key: kernelUDPTXSecureDirectStatInnerTCPChecksumKfuncSuccesses, name: "tc_kernel_udp_tx_secure_direct_inner_tcp_checksum_kfunc_successes"},
		{key: kernelUDPTXSecureDirectStatInnerTCPChecksumKfuncFallbacks, name: "tc_kernel_udp_tx_secure_direct_inner_tcp_checksum_kfunc_fallbacks"},
		{key: kernelUDPTXDirectStatRouteMisses, name: "tc_kernel_udp_tx_direct_route_misses"},
		{key: kernelUDPTXDirectStatFlowMisses, name: "tc_kernel_udp_tx_direct_flow_misses"},
		{key: kernelUDPTXDirectStatSecureFlowFallbacks, name: "tc_kernel_udp_tx_direct_secure_flow_fallbacks"},
		{key: kernelUDPTXDirectStatNonIPv4Fallbacks, name: "tc_kernel_udp_tx_direct_non_ipv4_fallbacks"},
		{key: kernelUDPTXDirectStatFragmentFallbacks, name: "tc_kernel_udp_tx_direct_fragment_fallbacks"},
		{key: kernelUDPTXDirectStatLenShortFallbacks, name: "tc_kernel_udp_tx_direct_len_short_fallbacks"},
		{key: kernelUDPTXDirectStatLenGSOFallbacks, name: "tc_kernel_udp_tx_direct_len_gso_fallbacks"},
		{key: kernelUDPTXDirectStatLenMismatches, name: "tc_kernel_udp_tx_direct_len_mismatches"},
		{key: kernelUDPTXDirectStatMTUFallbacks, name: "tc_kernel_udp_tx_direct_mtu_fallbacks"},
		{key: kernelUDPTXDirectStatRouteFlowZeroFallbacks, name: "tc_kernel_udp_tx_direct_route_flow_zero_fallbacks"},
		{key: kernelUDPTXDirectStatHeaderShortFallbacks, name: "tc_kernel_udp_tx_direct_header_short_fallbacks"},
		{key: kernelUDPTXDirectStatMTULinearFallbacks, name: "tc_kernel_udp_tx_direct_mtu_linear_fallbacks"},
		{key: kernelUDPTXDirectStatMTUGSOFallbacks, name: "tc_kernel_udp_tx_direct_mtu_gso_fallbacks"},
		{key: kernelUDPTXDirectStatMTUGSOSizeZeroFallbacks, name: "tc_kernel_udp_tx_direct_mtu_gso_size_zero_fallbacks"},
		{key: kernelUDPTXDirectStatMTUGSOBypasses, name: "tc_kernel_udp_tx_direct_mtu_gso_bypasses"},
		{key: kernelUDPTXDirectStatDirectOnlyDrops, name: "tc_kernel_udp_tx_direct_only_drops"},
		{key: kernelUDPTXDirectStatInnerTCPChecksumFixes, name: "tc_kernel_udp_tx_direct_inner_tcp_checksum_fixes"},
		{key: kernelUDPTXDirectStatInnerTCPChecksumStoreErrors, name: "tc_kernel_udp_tx_direct_inner_tcp_checksum_store_errors"},
		{key: kernelUDPTXDirectStatInnerTCPChecksumNotTCP, name: "tc_kernel_udp_tx_direct_inner_tcp_checksum_not_tcp"},
		{key: kernelUDPTXDirectStatInnerTCPChecksumKfuncFixes, name: "tc_kernel_udp_tx_direct_inner_tcp_checksum_kfunc_fixes"},
		{key: kernelUDPTXDirectStatInnerTCPChecksumKfuncFallbacks, name: "tc_kernel_udp_tx_direct_inner_tcp_checksum_kfunc_fallbacks"},
		{key: kernelUDPTXDirectStatAdjustDrops, name: "tc_kernel_udp_tx_direct_adjust_drops"},
		{key: kernelUDPTXDirectStatPostAdjustHeaderDrops, name: "tc_kernel_udp_tx_direct_post_adjust_header_drops"},
		{key: kernelUDPTXDirectStatSKBClearTXOffloadDrops, name: "tc_kernel_udp_tx_direct_skb_clear_tx_offload_drops"},
		{key: kernelUDPTXDirectStatInnerTCPChecksumGSOSkips, name: "tc_kernel_udp_tx_direct_inner_tcp_checksum_gso_skips"},
		{key: kernelUDPTXDirectStatInnerUDPChecksumFixes, name: "tc_kernel_udp_tx_direct_inner_udp_checksum_fixes"},
		{key: kernelUDPTXDirectStatInnerUDPChecksumStoreErrors, name: "tc_kernel_udp_tx_direct_inner_udp_checksum_store_errors"},
		{key: kernelUDPTXDirectStatInnerUDPChecksumInvalid, name: "tc_kernel_udp_tx_direct_inner_udp_checksum_invalid"},
		{key: kernelUDPTXDirectStatGSOInputs, name: "tc_kernel_udp_tx_direct_gso_inputs"},
		{key: kernelUDPTXDirectStatGSOActiveAccepts, name: "tc_kernel_udp_tx_direct_gso_active_accepts"},
		{key: kernelUDPTXDirectStatLinearAccepts, name: "tc_kernel_udp_tx_direct_linear_accepts"},
		{key: kernelUDPTXDirectStatGSOSuccesses, name: "tc_kernel_udp_tx_direct_gso_successes"},
		{key: kernelUDPTXDirectStatOuterTCPChecksumKfuncFixes, name: "tc_kernel_udp_tx_direct_outer_tcp_checksum_kfunc_fixes"},
		{key: kernelUDPTXDirectStatOuterTCPChecksumKfuncDrops, name: "tc_kernel_udp_tx_direct_outer_tcp_checksum_kfunc_drops"},
		{key: kernelUDPTXDirectStatRouteTCPGSOSuccesses, name: "tc_experimental_tcp_tx_direct_route_tcp_gso_kfunc_successes"},
		{key: kernelUDPTXDirectStatRouteTCPGSOFallbacks, name: "tc_experimental_tcp_tx_direct_route_tcp_gso_kfunc_fallbacks"},
		{key: kernelUDPTXDirectStatRouteTCPGSODrops, name: "tc_experimental_tcp_tx_direct_route_tcp_gso_kfunc_drops"},
		{key: kernelUDPTXDirectStatRouteTCPXmitSuccesses, name: "tc_experimental_tcp_tx_direct_route_tcp_xmit_kfunc_successes"},
		{key: kernelUDPTXDirectStatRouteTCPXmitFallbacks, name: "tc_experimental_tcp_tx_direct_route_tcp_xmit_kfunc_fallbacks"},
		{key: kernelUDPTXDirectStatRouteTCPXmitDrops, name: "tc_experimental_tcp_tx_direct_route_tcp_xmit_kfunc_drops"},
		{key: kernelUDPTXDirectStatPushFlowTCPHeaderKfuncSuccesses, name: "tc_experimental_tcp_tx_direct_push_flow_outer_tcp_header_kfunc_successes"},
		{key: kernelUDPRXSecureDirectStatAttempts, name: "tc_kernel_udp_rx_secure_direct_attempts"},
		{key: kernelUDPRXSecureDirectStatCandidates, name: "tc_kernel_udp_rx_secure_direct_candidates"},
		{key: kernelUDPRXSecureDirectStatSuccess, name: "tc_kernel_udp_rx_secure_direct_packets"},
		{key: kernelUDPRXSecureDirectStatFallbacks, name: "tc_kernel_udp_rx_secure_direct_fallbacks"},
		{key: kernelUDPRXSecureDirectStatNoContext, name: "tc_kernel_udp_rx_secure_direct_no_context"},
		{key: kernelUDPRXSecureDirectStatHeaderErrors, name: "tc_kernel_udp_rx_secure_direct_header_errors"},
		{key: kernelUDPRXSecureDirectStatDecryptErrors, name: "tc_kernel_udp_rx_secure_direct_decrypt_errors"},
		{key: kernelUDPRXSecureDirectStatReplayDrops, name: "tc_kernel_udp_rx_secure_direct_replay_drops"},
		{key: kernelUDPRXSecureDirectStatDrops, name: "tc_kernel_udp_rx_secure_direct_drops"},
		{key: kernelUDPRXSecureDirectStatNeighHits, name: "tc_kernel_udp_rx_secure_direct_neighbor_hits"},
		{key: kernelUDPRXSecureDirectStatNeighMisses, name: "tc_kernel_udp_rx_secure_direct_neighbor_misses"},
		{key: kernelUDPRXSecureDirectStatAdjustErrors, name: "tc_kernel_udp_rx_secure_direct_adjust_errors"},
		{key: kernelUDPRXSecureDirectStatStoreErrors, name: "tc_kernel_udp_rx_secure_direct_store_errors"},
		{key: kernelUDPRXSecureDirectStatBroadcasts, name: "tc_kernel_udp_rx_secure_direct_broadcasts"},
		{key: kernelUDPRXSecureDirectStatPeerRedirects, name: "tc_kernel_udp_rx_secure_direct_peer_redirects"},
		{key: kernelUDPRXSecureDirectStatRedirects, name: "tc_kernel_udp_rx_secure_direct_redirects"},
		{key: kernelUDPRXSecureDirectStatDebugL2IPv4, name: "tc_kernel_udp_rx_secure_direct_debug_l2_ipv4"},
		{key: kernelUDPRXSecureDirectStatDebugL3IPv4, name: "tc_kernel_udp_rx_secure_direct_debug_l3_ipv4"},
		{key: kernelUDPRXSecureDirectStatDebugUDP, name: "tc_kernel_udp_rx_secure_direct_debug_udp"},
		{key: kernelUDPRXSecureDirectStatDebugTIXUMagic, name: "tc_kernel_udp_rx_secure_direct_debug_tixu_magic"},
		{key: kernelUDPRXSecureDirectStatDebugTIXUHeader, name: "tc_kernel_udp_rx_secure_direct_debug_tixu_header"},
		{key: kernelUDPRXSecureDirectStatDebugTIXUFlags, name: "tc_kernel_udp_rx_secure_direct_debug_tixu_flags"},
		{key: kernelUDPRXSecureDirectStatDebugTIXULen, name: "tc_kernel_udp_rx_secure_direct_debug_tixu_len"},
		{key: kernelUDPRXSecureDirectStatDebugPort, name: "tc_kernel_udp_rx_secure_direct_debug_port"},
		{key: kernelUDPRXSecureDirectStatDebugSecureHeader, name: "tc_kernel_udp_rx_secure_direct_debug_secure_header"},
		{key: kernelUDPRXSecureDirectStatDebugL3TIXUMagic, name: "tc_kernel_udp_rx_secure_direct_debug_l3_tixu_magic"},
		{key: kernelUDPRXSecureDirectStatErrPayloadLen, name: "tc_kernel_udp_rx_secure_direct_err_payload_len"},
		{key: kernelUDPRXSecureDirectStatErrCipherLen, name: "tc_kernel_udp_rx_secure_direct_err_cipher_len"},
		{key: kernelUDPRXSecureDirectStatErrSecureMagic, name: "tc_kernel_udp_rx_secure_direct_err_secure_magic"},
		{key: kernelUDPRXSecureDirectStatErrSecureEpoch, name: "tc_kernel_udp_rx_secure_direct_err_secure_epoch"},
		{key: kernelUDPRXSecureDirectStatErrContextEpoch, name: "tc_kernel_udp_rx_secure_direct_err_context_epoch"},
		{key: kernelUDPRXSecureDirectStatErrOpenEINVAL, name: "tc_kernel_udp_rx_secure_direct_err_open_einval"},
		{key: kernelUDPRXSecureDirectStatErrOpenEBADMSG, name: "tc_kernel_udp_rx_secure_direct_err_open_ebadmsg"},
		{key: kernelUDPRXSecureDirectStatErrInnerIPv4, name: "tc_kernel_udp_rx_secure_direct_err_inner_ipv4"},
		{key: captureStatPullErrors, name: "tc_capture_pull_errors"},
		{key: captureStatLinearShortErrors, name: "tc_capture_linear_short_errors"},
		{key: captureStatEtherTypeErrors, name: "tc_capture_ethertype_errors"},
		{key: captureStatHeaderShortErrors, name: "tc_capture_header_short_errors"},
		{key: captureStatRouteMissErrors, name: "tc_capture_route_miss_errors"},
		{key: captureStatReady, name: "tc_capture_ready"},
		{key: captureStatScratchMisses, name: "tc_capture_scratch_misses"},
		{key: captureStatLoadBytesErrors, name: "tc_capture_load_bytes_errors"},
		{key: captureStatPerfErrors, name: "tc_capture_perf_errors"},
		{key: captureStatPerfErrENOENT, name: "tc_capture_perf_err_enoent"},
		{key: captureStatPerfErrEFAULT, name: "tc_capture_perf_err_efault"},
		{key: captureStatPerfErrEINVAL, name: "tc_capture_perf_err_einval"},
		{key: captureStatPerfErrE2BIG, name: "tc_capture_perf_err_e2big"},
		{key: captureStatPerfErrENOSPC, name: "tc_capture_perf_err_enospc"},
		{key: captureStatPerfErrEPERM, name: "tc_capture_perf_err_eperm"},
		{key: captureStatPerfErrOther, name: "tc_capture_perf_err_other"},
		{key: captureStatPerfLastErrno, name: "tc_capture_perf_last_errno"},
	}
	counters := make([]observability.Counter, 0, len(keys))
	for _, item := range keys {
		value, err := bpfCounterValue(manager.statsMap, item.key)
		if err != nil {
			manager.warnings = append(manager.warnings, "read BPF counter "+item.name+": "+err.Error())
			continue
		}
		counters = append(counters, observability.Counter{Name: item.name, Value: value})
	}
	counters = append(counters, observability.Counter{Name: "tc_routes_synced", Value: manager.routeEntries})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_direct_routes", Value: manager.kernelUDPTXDirectRoutes})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_direct_flows", Value: manager.kernelUDPTXDirectFlows})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_direct_inline_routes", Value: manager.kernelUDPTXDirectInlineRoutes})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_direct_inline_flows", Value: manager.kernelUDPTXDirectInlineFlows})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_direct_route_cache_enabled", Value: boolCounter(manager.kernelUDPTXDirectRouteCacheEnabled)})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_direct_route_cache_exception", Value: boolCounter(manager.kernelUDPTXDirectRouteCacheException)})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_direct_experimental_tcp_only", Value: boolCounter(kernelUDPTXDirectExperimentalTCPOnlyEnabledForSpec(manager.spec))})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_direct_kernel_udp_only", Value: boolCounter(kernelUDPTXDirectKernelUDPOnlyEnabledForSpec(manager.spec))})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_direct_only_enabled", Value: boolCounter(kernelUDPTXDirectOnlyEnabled(manager.spec))})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_direct_plain_skip_sequence", Value: boolCounter(kernelUDPTXDirectSkipPlainSequenceEnabled())})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_direct_strong_flow_hash", Value: boolCounter(kernelUDPTXDirectStrongFlowHashEnabled())})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_direct_skb_flow_hash", Value: boolCounter(kernelUDPTXDirectSKBFlowHashEnabled())})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_direct_port_flow_hash", Value: boolCounter(kernelUDPTXDirectPortFlowHashEnabled())})
	counters = append(counters, observability.Counter{Name: "tc_experimental_tcp_tx_plain_skip_sequence", Value: boolCounter(experimentalTCPTXPlainSkipSequenceEnabledForSpec(manager.spec))})
	counters = append(counters, observability.Counter{Name: "tc_experimental_tcp_tx_plain_ack_only", Value: boolCounter(experimentalTCPTXPlainACKOnlyEnabledForSpec(manager.spec))})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_direct_inner_tcp_checksum_kfunc", Value: boolCounter(manager.kernelUDPTXDirectInnerTCPChecksumKfunc)})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_direct_inner_tcp_checksum_kfunc_requested", Value: boolCounter(kernelUDPTXDirectInnerTCPChecksumKfuncEnabled())})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_direct_outer_tcp_checksum_kfunc", Value: boolCounter(manager.kernelUDPTXDirectOuterTCPChecksumKfunc)})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_direct_outer_tcp_checksum_kfunc_requested", Value: boolCounter(experimentalTCPTXDirectOuterTCPChecksumKfuncRequested())})
	counters = append(counters, observability.Counter{Name: "tc_experimental_tcp_tx_direct_finalize_outer_tcp_header_kfunc", Value: boolCounter(manager.kernelUDPTXDirectOuterTCPHeaderKfunc)})
	counters = append(counters, observability.Counter{Name: "tc_experimental_tcp_tx_direct_finalize_outer_tcp_header_kfunc_requested", Value: boolCounter(experimentalTCPTXDirectOuterTCPHeaderKfuncRequested())})
	counters = append(counters, observability.Counter{Name: "tc_experimental_tcp_tx_direct_tcp_partial_csum_kfunc", Value: boolCounter(manager.kernelUDPTXDirectTCPPartialCSUMKfunc)})
	counters = append(counters, observability.Counter{Name: "tc_experimental_tcp_tx_direct_tcp_partial_csum_kfunc_requested", Value: boolCounter(experimentalTCPTXDirectTCPPartialCSUMKfuncRequested())})
	counters = append(counters, observability.Counter{Name: "tc_experimental_tcp_tx_direct_push_outer_tcp_header_kfunc", Value: boolCounter(manager.kernelUDPTXDirectPushTCPHeaderKfunc)})
	counters = append(counters, observability.Counter{Name: "tc_experimental_tcp_tx_direct_push_outer_tcp_header_kfunc_requested", Value: boolCounter(experimentalTCPTXDirectPushTCPHeaderKfuncRequested())})
	counters = append(counters, observability.Counter{Name: "tc_experimental_tcp_tx_direct_push_flow_outer_tcp_header_kfunc", Value: boolCounter(manager.kernelUDPTXDirectPushFlowTCPHeaderKfunc)})
	counters = append(counters, observability.Counter{Name: "tc_experimental_tcp_tx_direct_push_flow_outer_tcp_header_kfunc_requested", Value: boolCounter(experimentalTCPTXDirectPushFlowTCPHeaderKfuncRequested())})
	counters = append(counters, observability.Counter{Name: "tc_experimental_tcp_tx_direct_finalize_flow_outer_tcp_header_kfunc", Value: boolCounter(manager.kernelUDPTXDirectFinalizeFlowTCPHeaderKfunc)})
	counters = append(counters, observability.Counter{Name: "tc_experimental_tcp_tx_direct_finalize_flow_outer_tcp_header_kfunc_requested", Value: boolCounter(experimentalTCPTXDirectFinalizeFlowTCPHeaderKfuncRequested())})
	counters = append(counters, observability.Counter{Name: "tc_experimental_tcp_tx_direct_push_route_outer_tcp_header_kfunc", Value: boolCounter(manager.kernelUDPTXDirectPushRouteTCPHeaderKfunc)})
	counters = append(counters, observability.Counter{Name: "tc_experimental_tcp_tx_direct_push_route_outer_tcp_header_kfunc_requested", Value: boolCounter(experimentalTCPTXDirectPushRouteTCPHeaderKfuncRequestedForSpec(manager.spec))})
	counters = append(counters, observability.Counter{Name: "tc_experimental_tcp_tx_direct_route_tcp_gso_kfunc", Value: boolCounter(manager.kernelUDPTXDirectRouteTCPGSOKfunc)})
	counters = append(counters, observability.Counter{Name: "tc_experimental_tcp_tx_direct_route_tcp_gso_kfunc_requested", Value: boolCounter(experimentalTCPTXDirectRouteTCPGSOKfuncRequestedForSpec(manager.spec))})
	counters = append(counters, observability.Counter{Name: "tc_experimental_tcp_tx_direct_route_tcp_gso_async_kfunc", Value: boolCounter(manager.kernelUDPTXDirectRouteTCPGSOAsyncKfunc)})
	counters = append(counters, observability.Counter{Name: "tc_experimental_tcp_tx_direct_route_tcp_gso_async_kfunc_requested", Value: boolCounter(experimentalTCPTXDirectRouteTCPGSOAsyncKfuncRequestedForSpec(manager.spec))})
	counters = append(counters, observability.Counter{Name: "tc_experimental_tcp_tx_direct_route_tcp_xmit_kfunc", Value: boolCounter(manager.kernelUDPTXDirectRouteTCPXmitKfunc)})
	counters = append(counters, observability.Counter{Name: "tc_experimental_tcp_tx_direct_route_tcp_xmit_kfunc_requested", Value: boolCounter(experimentalTCPTXDirectRouteTCPXmitKfuncRequestedForSpec(manager.spec))})
	counters = append(counters, observability.Counter{Name: "tc_experimental_tcp_tx_direct_route_tcp_gso_trust_partial_inner_checksum", Value: boolCounter(experimentalTCPTXDirectRouteTCPGSOTrustPartialInnerChecksumEnabled())})
	if underlayLink, err := netlink.LinkByName(manager.spec.UnderlayIface); err == nil {
		counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_direct_redirect_peer", Value: boolCounter(kernelUDPTXDirectRedirectPeerEnabledForLink(underlayLink, kernelUDPTXDirectKernelUDPOnlyEnabledForSpec(manager.spec), kernelUDPTXDirectOnlyEnabled(manager.spec)))})
	} else {
		counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_direct_redirect_peer", Value: boolCounter(kernelUDPTXDirectRedirectPeerEnabledForLink(nil, kernelUDPTXDirectKernelUDPOnlyEnabledForSpec(manager.spec), kernelUDPTXDirectOnlyEnabled(manager.spec)))})
	}
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_direct_skb_clear_tx_offload", Value: boolCounter(kernelUDPTXDirectSKBClearTXOffloadEnabled())})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_direct_skb_clear_tx_offload_gso", Value: boolCounter(kernelUDPTXDirectSKBClearTXOffloadGSOEnabled())})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_direct_skb_clear_tx_offload_active_gso", Value: boolCounter(kernelUDPTXDirectSKBClearTXOffloadActiveGSOEnabled())})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_direct_store_header_kfunc", Value: boolCounter(kernelUDPTXDirectStoreHeaderKfuncEnabled())})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_direct_build_udp_header_kfunc", Value: boolCounter(kernelUDPTXDirectBuildUDPHeaderKfuncEnabled())})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_direct_finalize_udp_header_kfunc", Value: boolCounter(kernelUDPTXDirectFinalizeUDPHeaderKfuncEnabled())})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_direct_udp_header_partial_csum", Value: boolCounter(kernelUDPTXDirectUDPHeaderPartialChecksumEnabled())})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_direct_push_udp_header_kfunc", Value: boolCounter(kernelUDPTXDirectPushUDPHeaderKfuncEnabled())})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_secure_direct_attached", Value: boolCounter(manager.kernelUDPTXSecureDirectAttached)})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_secure_direct_configured_flows", Value: manager.kernelCryptoTCSealConfiguredFlows})
	txSecureOptions := kernelUDPTXSecureDirectProgramOptionsForSpec(manager.spec)
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_secure_direct_trust_inner_checksums", Value: boolCounter(kernelUDPTXSecureDirectTrustInnerChecksumsForSpec(manager.spec))})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_secure_direct_no_csum_reset", Value: boolCounter(kernelUDPTXSecureDirectAdjustRoomFlags()&bpfAdjRoomNoCSUMReset != 0)})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_secure_direct_kfunc_seal_enabled", Value: boolCounter(txSecureOptions.KfuncSeal)})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_secure_direct_skb_seal_kfunc", Value: boolCounter(txSecureOptions.SKBSealKfunc)})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_secure_direct_inner_tcp_checksum_kfunc", Value: boolCounter(kernelUDPTXSecureDirectInnerTCPChecksumKfuncEnabled())})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_secure_direct_outer_tcp_csum_kfunc", Value: boolCounter(kernelUDPTXSecureDirectOuterTCPChecksumKfuncEnabled())})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_secure_direct_outer_tcp_partial_csum_kfunc", Value: boolCounter(kernelUDPTXSecureDirectOuterTCPPartialChecksumKfuncEnabled())})
	txDirectStats := make(map[string]uint64)
	manager.addKernelUDPTXDirectSyncStatsLocked(txDirectStats, "tc_")
	txDirectNames := make([]string, 0, len(txDirectStats))
	for name := range txDirectStats {
		txDirectNames = append(txDirectNames, name)
	}
	sort.Strings(txDirectNames)
	for _, name := range txDirectNames {
		counters = append(counters, observability.Counter{Name: name, Value: txDirectStats[name]})
	}
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_rx_direct_attached", Value: boolCounter(manager.kernelUDPRXDirectAttached)})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_rx_direct_broadcast", Value: boolCounter(manager.kernelUDPRXDirectBroadcast)})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_rx_direct_peer_redirect", Value: boolCounter(manager.kernelUDPRXDirectRedirectPeer)})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_rx_direct_redirect_ingress", Value: boolCounter(manager.kernelUDPRXDirectRedirectIngress)})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_rx_direct_static_destination_port", Value: uint64(manager.kernelUDPRXDirectStaticDestinationPort)})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_rx_direct_local_deliver", Value: boolCounter(manager.kernelUDPRXDirectLocalDeliver)})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_rx_direct_local_deliver_dev", Value: boolCounter(manager.kernelUDPRXDirectLocalDeliverDev)})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_rx_direct_local_ipv4", Value: uint64(manager.kernelUDPRXDirectLocalIPv4)})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_rx_direct_local_ipv4_mask", Value: uint64(manager.kernelUDPRXDirectLocalIPv4Mask)})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_rx_direct_decap_l2_kfunc", Value: boolCounter(manager.kernelUDPRXDirectDecapL2Kfunc)})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_rx_direct_decap_l2_dev_kfunc", Value: boolCounter(manager.kernelUDPRXDirectDecapL2DevKfunc)})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_rx_direct_parse_decap_l2_kfunc", Value: boolCounter(manager.kernelUDPRXDirectParseDecapL2Kfunc)})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_rx_direct_trust_inner_checksum", Value: boolCounter(manager.kernelUDPRXDirectTrustInnerChecksum)})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_rx_secure_direct_attached", Value: boolCounter(manager.kernelUDPRXSecureDirectAttached)})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_rx_secure_direct_skb_open_kfunc", Value: boolCounter(kernelUDPRXSecureDirectSKBOpenKfuncEnabled())})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_rx_secure_direct_recompute_inner_checksums", Value: boolCounter(kernelUDPRXSecureDirectRecomputeInnerChecksumEnabled())})
	txDirectOptions := kernelUDPTXDirectProgramOptions{
		Enabled:                          kernelUDPTXDirectProgramEnabledForSpec(manager.spec),
		ExperimentalTCPOnly:              kernelUDPTXDirectExperimentalTCPOnlyEnabledForSpec(manager.spec),
		KernelUDPOnly:                    kernelUDPTXDirectKernelUDPOnlyEnabledForSpec(manager.spec),
		DirectOnly:                       kernelUDPTXDirectOnlyEnabled(manager.spec),
		SkipPlainSequence:                kernelUDPTXDirectSkipPlainSequenceEnabled(),
		ExperimentalTCPSkipPlainSequence: experimentalTCPTXPlainSkipSequenceEnabledForSpec(manager.spec),
		ExperimentalTCPACKOnly:           experimentalTCPTXPlainACKOnlyEnabledForSpec(manager.spec),
		FinalizeFlowTCPHeaderKfunc:       manager.kernelUDPTXDirectFinalizeFlowTCPHeaderKfunc,
		PushRouteTCPHeaderKfunc:          manager.kernelUDPTXDirectPushRouteTCPHeaderKfunc,
		RouteTCPGSOKfunc:                 manager.kernelUDPTXDirectRouteTCPGSOKfunc,
		RouteTCPGSOAsyncKfunc:            manager.kernelUDPTXDirectRouteTCPGSOAsyncKfunc,
		RouteTCPXmitKfunc:                manager.kernelUDPTXDirectRouteTCPXmitKfunc,
	}
	txAdjustRoomFlags := kernelUDPTCTXAdjustRoomFlagsForOptions(txDirectOptions)
	rxAdjustRoomFlags := kernelUDPTCRXAdjustRoomFlagsForOptions(txDirectOptions)
	txDirectActiveGSO := kernelUDPTunnelGSOActiveSKBEnabledForOptions(txDirectOptions) || manager.kernelUDPTXDirectExperimentalTCPSafeGSO
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_adj_room_no_csum_reset", Value: boolCounter(txAdjustRoomFlags&bpfAdjRoomNoCSUMReset != 0 || rxAdjustRoomFlags&bpfAdjRoomNoCSUMReset != 0)})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_adj_room_tunnel_gso", Value: boolCounter(kernelUDPTunnelGSOEnabledForOptions(txDirectOptions))})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_rx_adj_room_tunnel_gso", Value: boolCounter(kernelUDPTCRXTunnelGSOEnabledForOptions(txDirectOptions))})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tc_direct_active_gso", Value: boolCounter(txDirectActiveGSO)})
	counters = append(counters, observability.Counter{Name: "experimental_tcp_tc_tx_direct_active_gso_safe", Value: boolCounter(manager.kernelUDPTXDirectExperimentalTCPSafeGSO)})
	counters = append(counters, observability.Counter{Name: "experimental_tcp_tc_tx_direct_active_gso_unsafe", Value: boolCounter(experimentalTCPTXDirectActiveGSOUnsafeEnabled())})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_tx_adj_room_flags", Value: uint64(txAdjustRoomFlags)})
	counters = append(counters, observability.Counter{Name: "tc_kernel_udp_rx_adj_room_flags", Value: uint64(rxAdjustRoomFlags)})
	counters = append(counters, observability.Counter{Name: "xdp_kernel_udp_rx_direct_attached", Value: boolCounter(manager.kernelUDPXDPRXDirectEnabled)})
	counters = append(counters, observability.Counter{Name: "xdp_kernel_udp_rx_direct_standalone", Value: boolCounter(manager.kernelUDPXDPRXDirectObject != nil)})
	counters = append(counters, observability.Counter{Name: "xdp_kernel_udp_rx_direct_standalone_attached", Value: boolCounter(manager.kernelUDPXDPRXDirectAttached)})
	counters = append(counters, observability.Counter{Name: "xdp_kernel_udp_rx_direct_standalone_skb", Value: boolCounter(manager.kernelUDPXDPRXDirectAttachMode == expTCPXDPAttachSKB)})
	counters = append(counters, observability.Counter{Name: "xdp_kernel_udp_rx_direct_fallback_pass", Value: boolCounter(manager.kernelUDPXDPRXDirectFallbackPass)})
	counters = append(counters, observability.Counter{Name: "xdp_kernel_udp_rx_direct_veth_fallback", Value: boolCounter(manager.kernelUDPXDPRXDirectVethFallback)})
	counters = append(counters, observability.Counter{Name: "xdp_kernel_udp_rx_secure_direct_veth_fallback", Value: boolCounter(manager.kernelUDPXDPRXSecureDirectVethFallback)})
	counters = append(counters, observability.Counter{Name: "xdp_kernel_udp_rx_direct_ifindex_mode", Value: boolCounter(kernelUDPXDPRXDirectIfindexEnabled())})
	counters = append(counters, observability.Counter{Name: "xdp_kernel_udp_rx_direct_trust_inner_checksum", Value: boolCounter(kernelUDPXDPRXDirectTrustInnerChecksumEnabled())})
	counters = append(counters, observability.Counter{Name: "xdp_kernel_udp_tx_idle_fallback_enabled", Value: boolCounter(kernelUDPAFXDPIdleFallbackEnabled())})
	counters = append(counters, observability.Counter{Name: "xdp_kernel_udp_tx_idle_fallback_underlay_packet", Value: boolCounter(kernelUDPAFXDPIdleFallbackUnderlayPacketEnabled())})
	counters = append(counters, observability.Counter{Name: "xdp_kernel_udp_tx_idle_fallback_attempts", Value: manager.kernelUDPAFXDPIdleFallbackAttempts})
	counters = append(counters, observability.Counter{Name: "xdp_kernel_udp_tx_idle_fallback_batches", Value: manager.kernelUDPAFXDPIdleFallbackBatches})
	counters = append(counters, observability.Counter{Name: "xdp_kernel_udp_tx_idle_fallback_frames", Value: manager.kernelUDPAFXDPIdleFallbackFrames})
	counters = append(counters, observability.Counter{Name: "xdp_kernel_udp_tx_idle_fallback_sent_frames", Value: manager.kernelUDPAFXDPIdleFallbackSentFrames})
	counters = append(counters, observability.Counter{Name: "xdp_kernel_udp_tx_idle_fallback_errors", Value: manager.kernelUDPAFXDPIdleFallbackErrors})
	counters = append(counters, observability.Counter{Name: "xdp_kernel_udp_tx_idle_fallback_skips", Value: manager.kernelUDPAFXDPIdleFallbackSkips})
	counters = append(counters, observability.Counter{Name: "tc_packet_policy_mtu", Value: uint64(manager.snapshot.PacketPolicy.MTU)})
	counters = append(counters, observability.Counter{Name: "tc_packet_policy_drop_fragments", Value: boolCounter(manager.snapshot.PacketPolicy.DropFragments)})
	counters = append(counters, observability.Counter{Name: "tc_packet_policy_tcp_mss_clamp", Value: uint64(manager.snapshot.PacketPolicy.TCPMSSClamp)})
	counters = append(counters, observability.Counter{Name: "tc_nat_source_prefixes", Value: manager.natSourceEntries})
	counters = append(counters, observability.Counter{Name: "tc_nat_route_prefixes", Value: manager.natRouteEntries})
	counters = append(counters, observability.Counter{Name: "tc_nat_excluded_destinations", Value: manager.natExcludeEntries})
	counters = append(counters, observability.Counter{Name: "tc_nat_bindings", Value: manager.natBindingEntries})
	counters = append(counters, observability.Counter{Name: "tc_nat_binding_sync_errors", Value: manager.natBindingSyncErrors})
	manager.captureMu.Lock()
	captureBuffered := uint64(manager.captureEventCount)
	captureLost := manager.captureLost
	captureSubDrops := manager.captureSubDrops
	manager.captureMu.Unlock()
	counters = append(counters, observability.Counter{Name: "tc_capture_buffered", Value: captureBuffered})
	counters = append(counters, observability.Counter{Name: "tc_capture_lost", Value: captureLost})
	counters = append(counters, observability.Counter{Name: "tc_capture_subscriber_drops", Value: captureSubDrops})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_attempts", Value: lanPacketStats.gsoAttempts.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_successes", Value: lanPacketStats.gsoSuccesses.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_unsupported", Value: lanPacketStats.gsoUnsupported.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_errors", Value: lanPacketStats.gsoErrors.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_disabled", Value: lanPacketStats.gsoDisabled.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_raw_attempts", Value: lanPacketStats.gsoRawAttempts.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_raw_successes", Value: lanPacketStats.gsoRawSuccesses.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_raw_batch_attempts", Value: lanPacketStats.gsoRawBatchAttempts.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_raw_batch_successes", Value: lanPacketStats.gsoRawBatchSuccesses.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_raw_batch_messages", Value: lanPacketStats.gsoRawBatchMessages.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_raw_mixed_attempts", Value: lanPacketStats.gsoRawMixedAttempts.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_raw_mixed_successes", Value: lanPacketStats.gsoRawMixedSuccesses.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_raw_mixed_messages", Value: lanPacketStats.gsoRawMixedMessages.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_raw_vnet_batch_attempts", Value: lanPacketStats.rawVNetBatchAttempts.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_raw_vnet_batch_successes", Value: lanPacketStats.rawVNetBatchSuccesses.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_raw_vnet_batch_messages", Value: lanPacketStats.rawVNetBatchMessages.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_raw_vnet_batch_errors", Value: lanPacketStats.rawVNetBatchErrors.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_raw_vnet_batch_unsupported", Value: lanPacketStats.rawVNetBatchUnsupported.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_raw_scatter_attempts", Value: lanPacketStats.gsoRawScatterAttempts.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_raw_scatter_successes", Value: lanPacketStats.gsoRawScatterSuccesses.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_raw_scatter_messages", Value: lanPacketStats.gsoRawScatterMessages.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_cooked_attempts", Value: lanPacketStats.gsoCookedAttempts.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_cooked_successes", Value: lanPacketStats.gsoCookedSuccesses.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_error_einval", Value: lanPacketStats.gsoErrnoEINVAL.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_error_emsgsize", Value: lanPacketStats.gsoErrnoEMSGSIZE.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_error_eopnotsupp", Value: lanPacketStats.gsoErrnoEOPNOTSUPP.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_error_enoprotoopt", Value: lanPacketStats.gsoErrnoENOPROTOOPT.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_error_eperm", Value: lanPacketStats.gsoErrnoEPERM.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_error_eio", Value: lanPacketStats.gsoErrnoEIO.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_error_enotsup", Value: lanPacketStats.gsoErrnoENOTSUP.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_error_eagain", Value: lanPacketStats.gsoErrnoEAGAIN.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_error_eacces", Value: lanPacketStats.gsoErrnoEACCES.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_error_enobufs", Value: lanPacketStats.gsoErrnoENOBUFS.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_error_enodev", Value: lanPacketStats.gsoErrnoENODEV.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_error_enxio", Value: lanPacketStats.gsoErrnoENXIO.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_error_efault", Value: lanPacketStats.gsoErrnoEFAULT.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_error_edestaddrreq", Value: lanPacketStats.gsoErrnoEDESTADDRREQ.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_gso_error_other", Value: lanPacketStats.gsoErrnoOther.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_software_segments", Value: lanPacketStats.softwareSegments.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_software_segment_batches", Value: lanPacketStats.softwareSegmentBatches.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_batch_send_attempts", Value: lanPacketStats.batchSendAttempts.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_batch_send_messages", Value: lanPacketStats.batchSendMessages.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_batch_send_errors", Value: lanPacketStats.batchSendErrors.Load()})
	counters = append(counters, observability.Counter{Name: "lan_reinject_single_send_packets", Value: lanPacketStats.singleSendPackets.Load()})
	counters = manager.experimentalTCPCountersLocked(counters)
	counters = manager.kernelUDPCountersLocked(counters)
	return counters
}

func (manager *Manager) experimentalTCPCountersLocked(counters []observability.Counter) []observability.Counter {
	counters = append(counters, observability.Counter{Name: "experimental_tcp_subscriber_drops", Value: manager.expTCPSubDrops})
	kernelCryptoStats := manager.kernelCryptoProviderStatsLocked()
	kernelCryptoNames := make([]string, 0, len(kernelCryptoStats))
	for name := range kernelCryptoStats {
		kernelCryptoNames = append(kernelCryptoNames, name)
	}
	sort.Strings(kernelCryptoNames)
	for _, name := range kernelCryptoNames {
		counters = append(counters, observability.Counter{Name: "experimental_tcp_" + name, Value: kernelCryptoStats[name]})
	}
	counters = append(counters, observability.Counter{Name: "experimental_tcp_allowed_ports", Value: uint64(len(manager.expTCPAllowed))})
	counters = append(counters, observability.Counter{Name: "experimental_tcp_submitted_frames", Value: manager.expTCPSubmitted})
	counters = append(counters, observability.Counter{Name: "experimental_tcp_received_frames", Value: manager.expTCPReceived})
	counters = append(counters, observability.Counter{Name: "experimental_tcp_rx_duplicate_drops", Value: manager.expTCPRXDuplicateDrops})
	counters = append(counters, observability.Counter{Name: "experimental_tcp_rx_reordered_batches", Value: manager.expTCPRXReorderedBatches})
	counters = append(counters, observability.Counter{Name: "experimental_tcp_tc_tx_direct_enabled", Value: boolCounter(experimentalTCPTXDirectEnabledForSpec(manager.spec))})
	counters = append(counters, observability.Counter{Name: "experimental_tcp_tc_tx_direct_configured_flows", Value: manager.experimentalTCPTXDirectConfiguredFlowsLocked()})
	if manager.expTCPFastPath == nil {
		return counters
	}
	stats := manager.expTCPFastPath.Stats()
	names := make([]string, 0, len(stats))
	for name := range stats {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		counters = append(counters, observability.Counter{Name: "experimental_tcp_" + name, Value: stats[name]})
	}
	return counters
}

func (manager *Manager) experimentalTCPTXDirectConfiguredFlowsLocked() uint64 {
	if manager == nil || !experimentalTCPTXDirectEnabledForSpec(manager.spec) {
		return 0
	}
	var count uint64
	for _, flow := range manager.expTCPFlows {
		if flow.ID != 0 {
			count++
		}
	}
	return count
}

func (manager *Manager) kernelUDPCountersLocked(counters []observability.Counter) []observability.Counter {
	counters = append(counters, observability.Counter{Name: "kernel_udp_allowed_ports", Value: uint64(len(manager.kernelUDPAllowed))})
	counters = append(counters, observability.Counter{Name: "kernel_udp_active_flows", Value: uint64(len(manager.kernelUDPFlows))})
	counters = append(counters, observability.Counter{Name: "kernel_udp_submitted_frames", Value: manager.kernelUDPSubmitted})
	counters = append(counters, observability.Counter{Name: "kernel_udp_received_frames", Value: manager.kernelUDPReceived})
	counters = append(counters, observability.Counter{Name: "kernel_udp_subscriber_drops", Value: manager.kernelUDPSubDrops})
	kernelCryptoStats := manager.kernelCryptoProviderStatsLocked()
	kernelCryptoNames := make([]string, 0, len(kernelCryptoStats))
	for name := range kernelCryptoStats {
		kernelCryptoNames = append(kernelCryptoNames, name)
	}
	sort.Strings(kernelCryptoNames)
	for _, name := range kernelCryptoNames {
		counters = append(counters, observability.Counter{Name: "kernel_udp_" + name, Value: kernelCryptoStats[name]})
	}
	return counters
}

func (manager *Manager) dropReasonsLocked() map[observability.DropReason]uint64 {
	out := make(map[observability.DropReason]uint64, len(manager.dropReasons))
	for reason, value := range manager.dropReasons {
		out[reason] = value
	}
	if value := manager.bpfCounterValueLocked(10); value > 0 {
		out[observability.DropBlackholeRoute] += value
	}
	if value := manager.bpfCounterValueLocked(11); value > 0 {
		out[observability.DropRejectRoute] += value
	}
	if value := manager.bpfCounterValueLocked(15); value > 0 {
		out[observability.DropMTUExceeded] += value
	}
	if value := manager.bpfCounterValueLocked(16); value > 0 {
		out[observability.DropFragmentedPacket] += value
	}
	out[observability.DropTTLExpired] += manager.bpfCounterValueLocked(tcTTLExceededICMPGeneratedStat)
	out[observability.DropTTLExpired] += manager.bpfCounterValueLocked(tcTTLExceededNoReplyDropsStat)
	out[observability.DropTTLExpired] += manager.bpfCounterValueLocked(tcTTLExceededICMPErrorsStat)
	if len(out) == 0 {
		return nil
	}
	return out
}

func (manager *Manager) bpfCounterValueLocked(key uint32) uint64 {
	if manager.statsMap == nil {
		return 0
	}
	value, err := bpfCounterValue(manager.statsMap, key)
	if err != nil {
		return 0
	}
	return value
}

func bpfCounterValue(m *cebpf.Map, key uint32) (uint64, error) {
	if m == nil {
		return 0, fmt.Errorf("BPF counter map is nil")
	}
	if m.Type() == cebpf.PerCPUArray || m.Type() == cebpf.PerCPUHash || m.Type() == cebpf.LRUCPUHash {
		var values []uint64
		if err := m.Lookup(key, &values); err != nil {
			return 0, err
		}
		var total uint64
		for _, value := range values {
			total += value
		}
		return total, nil
	}
	var value uint64
	if err := m.Lookup(key, &value); err != nil {
		return 0, err
	}
	return value, nil
}

func (manager *Manager) recordDrop(reason observability.DropReason) {
	manager.mu.Lock()
	manager.recordDropLocked(reason)
	manager.mu.Unlock()
}

func (manager *Manager) recordDropLocked(reason observability.DropReason) {
	if reason == "" {
		return
	}
	if manager.dropReasons == nil {
		manager.dropReasons = make(map[observability.DropReason]uint64)
	}
	manager.dropReasons[reason]++
}

func (manager *Manager) recordExperimentalTCPDropLocked(err error) {
	switch {
	case errors.Is(err, errNeighborUnresolved):
		manager.recordDropLocked(observability.DropNeighborUnresolved)
	case errors.Is(err, errAFXDPTXPoolExhausted):
		manager.recordDropLocked(observability.DropTXPoolExhausted)
	case errors.Is(err, errAFXDPRingFull):
		manager.recordDropLocked(observability.DropRingFull)
	case errors.Is(err, errMTUExceeded):
		manager.recordDropLocked(observability.DropMTUExceeded)
	default:
		manager.recordDropLocked(observability.DropEndpointDown)
	}
}

type routeKey struct {
	PrefixLen uint32
	Addr      [4]byte
}

type routeValue struct {
	Action   uint32
	Metric   uint32
	Protocol uint32
	Port     uint32
}

type kernelUDPTXRouteValue struct {
	FlowID   uint64
	FlowID1  uint64
	FlowID2  uint64
	FlowID3  uint64
	FlowID4  uint64
	FlowID5  uint64
	FlowID6  uint64
	FlowID7  uint64
	FlowID8  uint64
	FlowMask uint32
	Flags    uint32
	Inline1  kernelUDPTXFlowValue
	Inline2  kernelUDPTXFlowValue
	Inline3  kernelUDPTXFlowValue
	Inline4  kernelUDPTXFlowValue
	Inline5  kernelUDPTXFlowValue
	Inline6  kernelUDPTXFlowValue
	Inline7  kernelUDPTXFlowValue
	Inline8  kernelUDPTXFlowValue
}

type kernelUDPTXRouteCacheValue struct {
	Enabled          uint32
	PrefixLen        uint32
	PrefixAddr       [4]byte
	ExceptionEnabled uint32
	ExceptionLen     uint32
	ExceptionAddr    [4]byte
	Route            kernelUDPTXRouteValue
}

type kernelUDPTXFlowValue struct {
	Sequence        uint64
	SourceIP        [4]byte
	DestinationIP   [4]byte
	SourcePort      uint16
	DestinationPort uint16
	Ifindex         uint32
	DestinationMAC0 uint32
	DestinationMAC1 uint16
	IPv4ChecksumUDP uint16
	SourceMAC0      uint32
	SourceMAC1      uint16
	IPv4ChecksumTCP uint16
	MTU             uint32
	Flags           uint32
}

type kernelUDPTXDirectUnderlayTarget struct {
	ifindex        int
	mtu            uint32
	sourceMAC      net.HardwareAddr
	destinationMAC net.HardwareAddr
}

func kernelUDPTXIPv4ChecksumBase(sourceIP [4]byte, destinationIP [4]byte, protocol uint8) uint16 {
	sum := uint32(0x4500) // Version/IHL and DSCP/ECN.
	sum += 0x4000         // Flags/fragment offset: DF, offset zero.
	sum += uint32(0x4000) | uint32(protocol)
	sum += uint32(binary.BigEndian.Uint16(sourceIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(sourceIP[2:4]))
	sum += uint32(binary.BigEndian.Uint16(destinationIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(destinationIP[2:4]))
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}

const (
	kernelUDPTXFlowFlagSecure               uint32 = 1
	kernelUDPTXFlowFlagTrustInnerChecksum   uint32 = 2
	kernelUDPTXFlowFlagHotStats             uint32 = 4
	kernelUDPTXFlowFlagExperimentalTCP      uint32 = 8
	kernelUDPTXFlowFlagSkipOuterTCPChecksum uint32 = 16
)

type kernelUDPRXNeighValue struct {
	Ifindex         uint32
	DestinationMAC0 uint32
	DestinationMAC1 uint16
	Pad0            uint16
	SourceMAC0      uint32
	SourceMAC1      uint16
	Pad1            uint16
}

type kernelUDPRXConfigValue struct {
	SourceMAC0      uint32
	SourceMAC1      uint16
	Pad0            uint16
	Ifindex         uint32
	DestinationMAC0 uint32
	DestinationMAC1 uint16
	Pad1            uint16
}

type natConfigValue struct {
	Enabled uint32
	Gateway [4]byte
}

type packetPolicyValue struct {
	MTU           uint32
	DropFragments uint32
	TCPMSSClamp   uint32
}

type natBindingKey struct {
	TranslatedIP [4]byte
	RemoteIP     [4]byte
	Protocol     uint32
	LocalPort    uint16
	RemotePort   uint16
	Pad          uint32
}

type natBindingValue struct {
	OriginalIP [4]byte
	Pad        uint32
	ExpiresNS  uint64
}

func (manager *Manager) syncRoutesLocked(routes []routing.Route) error {
	if manager.routeMap == nil {
		return nil
	}
	if err := manager.clearRouteMapLocked(); err != nil {
		return err
	}
	var synced uint64
	for _, route := range routes {
		prefix, err := route.Prefix.Parse()
		if err != nil {
			return err
		}
		if !prefix.Addr().Is4() {
			manager.warnings = append(manager.warnings, fmt.Sprintf("skip non-IPv4 route %q in TC fast path", route.Prefix))
			continue
		}
		masked := prefix.Masked()
		key := routeKey{PrefixLen: uint32(masked.Bits()), Addr: masked.Addr().As4()}
		action, ok := routeActionForKind(route.Kind)
		if !ok {
			manager.warnings = append(manager.warnings, fmt.Sprintf("skip unsupported route kind %q for %q in TC fast path", route.Kind, route.Prefix))
			continue
		}
		if manager.routeUsesNativeTunnelLocked(route) {
			action = routeActionLocal
		}
		value := routeValue{
			Action:   action,
			Metric:   uint32(route.Metric),
			Protocol: uint32(route.LocalProtocol),
			Port:     uint32(htons(route.LocalPort)),
		}
		if err := manager.routeMap.Update(key, value, cebpf.UpdateAny); err != nil {
			return fmt.Errorf("sync route %q to BPF LPM map: %w", route.Prefix, err)
		}
		synced++
	}
	manager.routeEntries = synced
	return nil
}

func (manager *Manager) routeUsesNativeTunnelLocked(route routing.Route) bool {
	if len(manager.nativeTunnelRoutes) == 0 || route.Endpoint == "" {
		return false
	}
	endpoint := endpointMetadataByID(manager.snapshot.Endpoints, route.Endpoint)
	protocol := strings.ToLower(strings.TrimSpace(endpoint.Transport))
	if protocol == "" {
		for _, state := range manager.nativeTunnelRoutes {
			if state.Endpoint == route.Endpoint && state.Prefix.String() == string(route.Prefix) {
				return true
			}
		}
		return false
	}
	_, ok := manager.nativeTunnelRoutes[nativeTunnelRouteKey(protocol, route.Prefix, route.Endpoint)]
	return ok
}

func (manager *Manager) syncNativeTunnelRoutesLocked(ctx context.Context, snapshot dataplane.Snapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	desired, err := manager.desiredNativeTunnelRoutesLocked(snapshot)
	if err != nil {
		return err
	}
	if manager.nativeTunnelRoutes == nil {
		manager.nativeTunnelRoutes = make(map[string]nativeTunnelRouteState)
	}
	for key, existing := range manager.nativeTunnelRoutes {
		if _, ok := desired[key]; ok {
			continue
		}
		if err := manager.deleteNativeTunnelRouteLocked(existing); err != nil {
			return err
		}
		delete(manager.nativeTunnelRoutes, key)
	}
	for key, route := range desired {
		if existing, ok := manager.nativeTunnelRoutes[key]; ok && existing == route {
			continue
		}
		if existing, ok := manager.nativeTunnelRoutes[key]; ok {
			if err := manager.deleteNativeTunnelRouteLocked(existing); err != nil {
				return err
			}
			delete(manager.nativeTunnelRoutes, key)
		}
		if err := manager.ensureNativeTunnelRouteLocked(route); err != nil {
			return err
		}
	}
	if err := manager.syncNativeTunnelManagedLANMTULocked(); err != nil {
		return err
	}
	return manager.syncRoutesLocked(snapshot.Routes)
}

func (manager *Manager) syncNativeTunnelManagedLANMTULocked() error {
	if manager.spec.ManagedMTU <= 0 && len(manager.nativeTunnelRoutes) == 0 {
		return nil
	}
	if manager.spec.LANIface == "" {
		return nil
	}
	managedMTU := manager.spec.ManagedMTU
	for _, route := range manager.nativeTunnelRoutes {
		if route.MTU <= 0 {
			continue
		}
		if managedMTU == 0 || route.MTU < managedMTU {
			managedMTU = route.MTU
		}
	}
	if managedMTU <= 0 {
		return nil
	}
	link, err := netlink.LinkByName(manager.spec.LANIface)
	if err != nil {
		return fmt.Errorf("inspect LAN iface %q for native tunnel MTU: %w", manager.spec.LANIface, err)
	}
	if link.Attrs() == nil || link.Attrs().MTU <= managedMTU {
		return nil
	}
	if err := netlink.LinkSetMTU(link, managedMTU); err != nil {
		return fmt.Errorf("configure LAN MTU %d on %q: %w", managedMTU, manager.spec.LANIface, err)
	}
	manager.warnings = append(manager.warnings, fmt.Sprintf("set LAN MTU on %q to %d for native tunnel route offload", manager.spec.LANIface, managedMTU))
	return nil
}

func (manager *Manager) desiredNativeTunnelRoutesLocked(snapshot dataplane.Snapshot) (map[string]nativeTunnelRouteState, error) {
	if manager.spec.DataDir == "" || manager.spec.LANIface == "" || manager.spec.UnderlayIface == "" || nativeTunnelRouteOffloadDisabled() {
		return nil, nil
	}
	if snapshot.NAT != nil && snapshot.NAT.Enabled {
		return nil, nil
	}
	endpoints := make(map[core.EndpointID]dataplane.EndpointMetadata, len(snapshot.Endpoints))
	for _, endpoint := range snapshot.Endpoints {
		if !endpoint.Enabled || endpoint.ID == "" {
			continue
		}
		endpoints[endpoint.ID] = endpoint
	}
	out := make(map[string]nativeTunnelRouteState)
	for _, route := range snapshot.Routes {
		if route.Kind != "" && route.Kind != routing.RouteUnicast || route.Endpoint == "" {
			continue
		}
		endpoint := endpoints[route.Endpoint]
		protocol := strings.ToLower(strings.TrimSpace(endpoint.Transport))
		if protocol != string(transport.ProtocolGRE) && protocol != string(transport.ProtocolIPIP) && protocol != string(transport.ProtocolVXLAN) {
			continue
		}
		if endpoint.ID == "" || !endpointNativeTunnelRouteOffloadAllowed(endpoint.Security) {
			continue
		}
		prefix, err := route.Prefix.Parse()
		if err != nil {
			return nil, err
		}
		if !prefix.Addr().Is4() {
			continue
		}
		cfg, err := iptunneltransport.ParseTunnelConfig(endpoint.Address)
		if err != nil {
			return nil, fmt.Errorf("parse %s endpoint %q for native tunnel route offload: %w", protocol, endpoint.ID, err)
		}
		state := nativeTunnelRouteState{
			Key:      nativeTunnelRouteKey(protocol, route.Prefix, endpoint.ID),
			Protocol: protocol,
			Prefix:   prefix.Masked(),
			Gateway:  cfg.RemoteCarrier,
			MTU:      nativeTunnelRouteMTU(cfg.MTU),
			AdvMSS:   nativeTunnelRouteAdvMSS(cfg.MTU),
			Endpoint: endpoint.ID,
		}
		out[state.Key] = state
	}
	return out, nil
}

func (manager *Manager) ensureNativeTunnelRouteLocked(route nativeTunnelRouteState) error {
	protocol := transport.Protocol(route.Protocol)
	endpoint := endpointMetadataByID(manager.snapshot.Endpoints, route.Endpoint)
	cfg, err := iptunneltransport.ParseTunnelConfig(endpoint.Address)
	if err != nil {
		return err
	}
	normalizedConfig := iptunneltransport.NormalizeParsedKernelTunnelConfig(protocol, cfg)
	nameHint := iptunneltransport.DeterministicTunnelName(route.Protocol, normalizedConfig)
	tunnelManager := iptunneltransport.NewManager(manager.spec.DataDir)
	name, err := tunnelManager.Acquire(context.Background(), iptunneltransport.TunnelRecord{
		Protocol: route.Protocol,
		Endpoint: string(route.Endpoint),
		Role:     "native_route",
		Config:   normalizedConfig,
		Name:     nameHint,
	}, func() (string, error) {
		return iptunneltransport.CreateKernelTunnel(protocol, nameHint, cfg)
	})
	if err != nil {
		return fmt.Errorf("create native %s tunnel for route %s: %w", route.Protocol, route.Prefix, err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		_ = tunnelManager.Release(context.Background(), name)
		return fmt.Errorf("inspect native tunnel %q: %w", name, err)
	}
	route.Tunnel = name
	if err := netlink.RouteReplace(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       netipPrefixToIPNet(route.Prefix),
		Gw:        net.IP(route.Gateway.AsSlice()),
		Protocol:  trustixRouteProtocol,
		MTU:       route.MTU,
		AdvMSS:    route.AdvMSS,
	}); err != nil {
		_ = tunnelManager.Release(context.Background(), name)
		return fmt.Errorf("install native tunnel route %s via %s dev %s: %w", route.Prefix, route.Gateway, name, err)
	}
	manager.nativeTunnelRoutes[route.Key] = route
	return nil
}

func (manager *Manager) deleteNativeTunnelRouteLocked(route nativeTunnelRouteState) error {
	var errs []string
	if route.Prefix.IsValid() {
		nlRoute := netlink.Route{Dst: netipPrefixToIPNet(route.Prefix)}
		if route.Tunnel != "" {
			if link, err := netlink.LinkByName(route.Tunnel); err == nil {
				nlRoute.LinkIndex = link.Attrs().Index
			}
		}
		if err := netlink.RouteDel(&nlRoute); err != nil && !isNotFound(err) {
			errs = append(errs, fmt.Sprintf("delete native tunnel route %s: %v", route.Prefix, err))
		}
	}
	if route.Tunnel != "" {
		if err := iptunneltransport.NewManager(manager.spec.DataDir).Release(context.Background(), route.Tunnel); err != nil {
			errs = append(errs, fmt.Sprintf("release native tunnel %s: %v", route.Tunnel, err))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (manager *Manager) syncManagedCaptureRoutesLocked(ctx context.Context, snapshot dataplane.Snapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	desired, err := manager.desiredManagedCaptureRoutesLocked(snapshot)
	if err != nil {
		return err
	}
	if manager.managedCaptureRoutes == nil {
		manager.managedCaptureRoutes = make(map[string]managedCaptureRouteState)
	}
	for key, existing := range manager.managedCaptureRoutes {
		if _, ok := desired[key]; ok {
			continue
		}
		if err := manager.deleteManagedCaptureRouteLocked(existing); err != nil {
			return err
		}
		delete(manager.managedCaptureRoutes, key)
	}
	for key, route := range desired {
		if existing, ok := manager.managedCaptureRoutes[key]; ok && existing == route {
			continue
		}
		if existing, ok := manager.managedCaptureRoutes[key]; ok {
			if err := manager.deleteManagedCaptureRouteLocked(existing); err != nil {
				return err
			}
			delete(manager.managedCaptureRoutes, key)
		}
		if err := manager.ensureManagedCaptureRouteLocked(route); err != nil {
			return err
		}
	}
	return nil
}

func (manager *Manager) desiredManagedCaptureRoutesLocked(snapshot dataplane.Snapshot) (map[string]managedCaptureRouteState, error) {
	if manager.spec.LANIface == "" {
		return nil, nil
	}
	gateway, destinationMAC := manager.managedCaptureRouteGatewayLocked()
	out := make(map[string]managedCaptureRouteState)
	for _, route := range snapshot.Routes {
		if route.Kind != "" && route.Kind != routing.RouteUnicast || route.NextHop == "" {
			continue
		}
		if manager.routeUsesNativeTunnelLocked(route) {
			continue
		}
		prefix, err := route.Prefix.Parse()
		if err != nil {
			return nil, err
		}
		if !prefix.Addr().Is4() {
			continue
		}
		prefix = prefix.Masked()
		if prefix.Bits() == 0 {
			manager.warnings = append(manager.warnings, "skip managed capture default route in kernel FIB; TC ingress still handles LAN default-route captures")
			continue
		}
		key := managedCaptureRouteKey(prefix)
		out[key] = managedCaptureRouteState{
			Key:            key,
			Prefix:         prefix,
			Iface:          manager.spec.LANIface,
			Gateway:        gateway,
			DestinationMAC: destinationMAC,
		}
	}
	return out, nil
}

func (manager *Manager) managedCaptureRouteGatewayLocked() (netip.Addr, string) {
	if legacyManagedCaptureScopeLinkRoutes() {
		return netip.Addr{}, ""
	}
	gateway := netip.MustParseAddr(managedCaptureSyntheticGateway)
	if manager.spec.LANIface == "" {
		return netip.Addr{}, ""
	}
	link, err := netlink.LinkByName(manager.spec.LANIface)
	if err != nil {
		return netip.Addr{}, ""
	}
	if peerMAC, warning := vethPeerHardwareAddr(link); len(peerMAC) == 6 {
		return gateway, peerMAC.String()
	} else if warning != "" {
		manager.warnings = append(manager.warnings, warning)
	}
	if attrs := link.Attrs(); attrs != nil && len(attrs.HardwareAddr) == 6 {
		return gateway, attrs.HardwareAddr.String()
	}
	return netip.Addr{}, ""
}

func (manager *Manager) ensureManagedCaptureRouteLocked(route managedCaptureRouteState) error {
	if route.Iface == "" || !route.Prefix.IsValid() {
		return nil
	}
	link, err := netlink.LinkByName(route.Iface)
	if err != nil {
		return fmt.Errorf("inspect LAN iface %q for managed capture route %s: %w", route.Iface, route.Prefix, err)
	}
	route.Ifindex = link.Attrs().Index
	nlRoute := netlink.Route{
		LinkIndex: route.Ifindex,
		Dst:       netipPrefixToIPNet(route.Prefix),
		Protocol:  trustixRouteProtocol,
	}
	if route.Gateway.IsValid() && route.Gateway.Is4() {
		nlRoute.Gw = net.IP(route.Gateway.AsSlice())
		nlRoute.Flags = int(netlink.FLAG_ONLINK)
		if err := ensureManagedCaptureRouteNeighbor(route.Ifindex, route.Gateway, route.DestinationMAC); err != nil {
			return err
		}
	} else {
		nlRoute.Scope = netlink.SCOPE_LINK
	}
	if err := netlink.RouteReplace(&nlRoute); err != nil {
		return fmt.Errorf("install managed capture route %s dev %s: %w", route.Prefix, route.Iface, err)
	}
	manager.managedCaptureRoutes[route.Key] = route
	return nil
}

func (manager *Manager) deleteManagedCaptureRouteLocked(route managedCaptureRouteState) error {
	if !route.Prefix.IsValid() {
		return nil
	}
	nlRoute := netlink.Route{
		Dst:      netipPrefixToIPNet(route.Prefix),
		Protocol: trustixRouteProtocol,
	}
	if route.Gateway.IsValid() && route.Gateway.Is4() {
		nlRoute.Gw = net.IP(route.Gateway.AsSlice())
		nlRoute.Flags = int(netlink.FLAG_ONLINK)
	} else {
		nlRoute.Scope = netlink.SCOPE_LINK
	}
	if route.Ifindex > 0 {
		nlRoute.LinkIndex = route.Ifindex
	} else if route.Iface != "" {
		if link, err := netlink.LinkByName(route.Iface); err == nil {
			nlRoute.LinkIndex = link.Attrs().Index
		}
	}
	if err := netlink.RouteDel(&nlRoute); err != nil {
		if !route.Gateway.IsValid() || !route.Gateway.Is4() {
			if !isNotFound(err) {
				return fmt.Errorf("delete managed capture route %s dev %s: %w", route.Prefix, route.Iface, err)
			}
			return nil
		}
		fallback := nlRoute
		fallback.Gw = nil
		fallback.Flags = 0
		fallback.Scope = netlink.SCOPE_LINK
		if fallbackErr := netlink.RouteDel(&fallback); fallbackErr != nil && !isNotFound(fallbackErr) {
			return fmt.Errorf("delete managed capture route %s dev %s: %w; delete legacy scope-link route: %v", route.Prefix, route.Iface, err, fallbackErr)
		}
	}
	return nil
}

func ensureManagedCaptureRouteNeighbor(ifindex int, gateway netip.Addr, destinationMAC string) error {
	if ifindex <= 0 || !gateway.Is4() || strings.TrimSpace(destinationMAC) == "" {
		return nil
	}
	hardwareAddr, err := net.ParseMAC(destinationMAC)
	if err != nil || len(hardwareAddr) != 6 {
		return fmt.Errorf("parse managed capture route neighbor MAC %q: %w", destinationMAC, err)
	}
	if err := netlink.NeighSet(&netlink.Neigh{
		LinkIndex:    ifindex,
		Family:       netlink.FAMILY_V4,
		IP:           net.IP(gateway.AsSlice()),
		HardwareAddr: hardwareAddr,
		State:        netlink.NUD_PERMANENT,
	}); err != nil {
		return fmt.Errorf("install managed capture route neighbor %s lladdr %s: %w", gateway, hardwareAddr, err)
	}
	return nil
}

func endpointMetadataByID(endpoints []dataplane.EndpointMetadata, id core.EndpointID) dataplane.EndpointMetadata {
	for _, endpoint := range endpoints {
		if endpoint.ID == id {
			return endpoint
		}
	}
	return dataplane.EndpointMetadata{}
}

func endpointNativeTunnelRouteOffloadAllowed(security dataplane.EndpointSecurityMetadata) bool {
	switch strings.ToLower(strings.TrimSpace(security.Encryption)) {
	case "plaintext", "plain", "none", "disabled", "off":
		return true
	default:
		return false
	}
}

func (manager *Manager) nativeTunnelProviderStatsLocked() map[string]uint64 {
	enabled := uint64(1)
	if nativeTunnelRouteOffloadDisabled() {
		enabled = 0
	}
	stats := map[string]uint64{
		"native_tunnel_route_offload_enabled": enabled,
		"native_tunnel_routes":                uint64(len(manager.nativeTunnelRoutes)),
	}
	for _, route := range manager.nativeTunnelRoutes {
		if route.Protocol == "" {
			continue
		}
		stats["native_tunnel_routes_"+route.Protocol]++
	}
	return stats
}

func nativeTunnelRouteOffloadDisabled() bool {
	return envFalsey("TRUSTIX_NATIVE_TUNNEL_ROUTE_OFFLOAD", "TRUSTIX_IPTUNNEL_ROUTE_OFFLOAD")
}

func nativeTunnelRouteKey(protocol string, prefix core.Prefix, endpoint core.EndpointID) string {
	return protocol + "|" + string(endpoint) + "|" + string(prefix)
}

func managedCaptureRouteKey(prefix netip.Prefix) string {
	return prefix.Masked().String()
}

func legacyManagedCaptureScopeLinkRoutes() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_MANAGED_CAPTURE_SCOPE_LINK_ROUTES"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func nativeTunnelRouteMTU(mtu int) int {
	if mtu <= 0 {
		return 0
	}
	return mtu
}

func nativeTunnelRouteAdvMSS(mtu int) int {
	const ipv4MinTCPMSS = 536
	if mtu <= rejectIPv4HeaderLen+rejectTCPHeaderLen {
		return 0
	}
	mss := mtu - rejectIPv4HeaderLen - rejectTCPHeaderLen
	if mss < ipv4MinTCPMSS {
		return ipv4MinTCPMSS
	}
	if mss > 0xffff {
		return 0xffff
	}
	return mss
}

func netipPrefixToIPNet(prefix netip.Prefix) *net.IPNet {
	addr := net.IP(prefix.Addr().AsSlice())
	bits := prefix.Bits()
	if bits < 0 {
		bits = 32
	}
	return &net.IPNet{IP: addr, Mask: net.CIDRMask(bits, 32)}
}

func (manager *Manager) nativeTunnelRouteSnapshotLocked() []persistedNativeTunnelRoute {
	if len(manager.nativeTunnelRoutes) == 0 {
		return nil
	}
	keys := make([]string, 0, len(manager.nativeTunnelRoutes))
	for key := range manager.nativeTunnelRoutes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]persistedNativeTunnelRoute, 0, len(keys))
	for _, key := range keys {
		route := manager.nativeTunnelRoutes[key]
		item := persistedNativeTunnelRoute{
			Key:       route.Key,
			Protocol:  route.Protocol,
			Tunnel:    route.Tunnel,
			Prefix:    route.Prefix.String(),
			MTU:       route.MTU,
			AdvMSS:    route.AdvMSS,
			Endpoint:  string(route.Endpoint),
			Routeable: route.Prefix.IsValid(),
		}
		if route.Gateway.IsValid() {
			item.Gateway = route.Gateway.String()
		}
		out = append(out, item)
	}
	return out
}

func nativeTunnelRouteStateMap(items []persistedNativeTunnelRoute) map[string]nativeTunnelRouteState {
	if len(items) == 0 {
		return nil
	}
	out := make(map[string]nativeTunnelRouteState, len(items))
	for _, item := range items {
		prefix, err := netip.ParsePrefix(item.Prefix)
		if err != nil {
			continue
		}
		var gateway netip.Addr
		if item.Gateway != "" {
			gateway, _ = netip.ParseAddr(item.Gateway)
		}
		key := item.Key
		if key == "" {
			key = nativeTunnelRouteKey(item.Protocol, core.Prefix(prefix.String()), core.EndpointID(item.Endpoint))
		}
		out[key] = nativeTunnelRouteState{
			Key:      key,
			Protocol: item.Protocol,
			Tunnel:   item.Tunnel,
			Prefix:   prefix,
			Gateway:  gateway,
			MTU:      item.MTU,
			AdvMSS:   item.AdvMSS,
			Endpoint: core.EndpointID(item.Endpoint),
		}
	}
	return out
}

func (manager *Manager) managedCaptureRouteSnapshotLocked() []persistedManagedCaptureRoute {
	if len(manager.managedCaptureRoutes) == 0 {
		return nil
	}
	keys := make([]string, 0, len(manager.managedCaptureRoutes))
	for key := range manager.managedCaptureRoutes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]persistedManagedCaptureRoute, 0, len(keys))
	for _, key := range keys {
		route := manager.managedCaptureRoutes[key]
		item := persistedManagedCaptureRoute{
			Key:       route.Key,
			Prefix:    route.Prefix.String(),
			Iface:     route.Iface,
			Ifindex:   route.Ifindex,
			Routeable: route.Prefix.IsValid(),
		}
		if route.Gateway.IsValid() {
			item.Gateway = route.Gateway.String()
		}
		item.DestinationMAC = route.DestinationMAC
		out = append(out, item)
	}
	return out
}

func managedCaptureRouteStateMap(items []persistedManagedCaptureRoute) map[string]managedCaptureRouteState {
	if len(items) == 0 {
		return nil
	}
	out := make(map[string]managedCaptureRouteState, len(items))
	for _, item := range items {
		prefix, err := netip.ParsePrefix(item.Prefix)
		if err != nil {
			continue
		}
		prefix = prefix.Masked()
		key := item.Key
		if key == "" {
			key = managedCaptureRouteKey(prefix)
		}
		var gateway netip.Addr
		if item.Gateway != "" {
			gateway, _ = netip.ParseAddr(item.Gateway)
		}
		out[key] = managedCaptureRouteState{
			Key:            key,
			Prefix:         prefix,
			Iface:          item.Iface,
			Ifindex:        item.Ifindex,
			Gateway:        gateway,
			DestinationMAC: item.DestinationMAC,
		}
	}
	return out
}

func (manager *Manager) syncDeviceAccessProxyARPLocked(ctx context.Context, snapshot dataplane.Snapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	desired, err := manager.desiredDeviceAccessProxyARPLocked(snapshot)
	if err != nil {
		return err
	}
	if manager.deviceAccessProxyARP == nil {
		manager.deviceAccessProxyARP = make(map[string]deviceAccessProxyARPState)
	}
	for key, existing := range manager.deviceAccessProxyARP {
		if _, ok := desired[key]; ok {
			continue
		}
		if err := manager.deleteDeviceAccessProxyARPLocked(existing); err != nil {
			return err
		}
		delete(manager.deviceAccessProxyARP, key)
	}
	for key, proxy := range desired {
		if existing, ok := manager.deviceAccessProxyARP[key]; ok {
			if existing.Iface == proxy.Iface && existing.Address == proxy.Address {
				continue
			}
			if err := manager.deleteDeviceAccessProxyARPLocked(existing); err != nil {
				return err
			}
			delete(manager.deviceAccessProxyARP, key)
		}
		if err := manager.ensureDeviceAccessProxyARPLocked(proxy); err != nil {
			return err
		}
	}
	return nil
}

func (manager *Manager) desiredDeviceAccessProxyARPLocked(snapshot dataplane.Snapshot) (map[string]deviceAccessProxyARPState, error) {
	if manager.spec.LANIface == "" && len(manager.spec.LANs) == 0 {
		return nil, nil
	}
	out := make(map[string]deviceAccessProxyARPState)
	for _, route := range snapshot.Routes {
		if route.Source != "device_access" {
			continue
		}
		if route.Kind != "" && route.Kind != routing.RouteUnicast {
			continue
		}
		prefix, err := route.Prefix.Parse()
		if err != nil {
			return nil, err
		}
		prefix = prefix.Masked()
		if !prefix.Addr().Is4() || prefix.Bits() != 32 {
			continue
		}
		iface := manager.lanIfaceForDeviceAccessAddressLocked(prefix.Addr())
		if iface == "" {
			continue
		}
		key := deviceAccessProxyARPKey(iface, prefix.Addr())
		out[key] = deviceAccessProxyARPState{
			Key:     key,
			Iface:   iface,
			Address: prefix.Addr(),
		}
	}
	return out, nil
}

func (manager *Manager) lanIfaceForDeviceAccessAddressLocked(addr netip.Addr) string {
	lans := effectiveLANAttachSpecs(manager.spec)
	for _, lan := range lans {
		if lan.Iface == "" || !lan.DeviceAccess {
			continue
		}
		if strings.TrimSpace(lan.DeviceAccessPool) == "" {
			return lan.Iface
		}
		prefix, err := netip.ParsePrefix(strings.TrimSpace(lan.DeviceAccessPool))
		if err == nil && prefix.Masked().Contains(addr) {
			return lan.Iface
		}
	}
	return manager.lanIfaceForDestinationLocked(addr)
}

func (manager *Manager) ensureDeviceAccessProxyARPLocked(proxy deviceAccessProxyARPState) error {
	if proxy.Iface == "" || !proxy.Address.Is4() {
		return nil
	}
	link, err := netlink.LinkByName(proxy.Iface)
	if err != nil {
		return fmt.Errorf("inspect LAN iface %q for device proxy ARP %s: %w", proxy.Iface, proxy.Address, err)
	}
	proxy.Ifindex = link.Attrs().Index
	for _, name := range []string{"proxy_arp", "proxy_arp_pvlan"} {
		path := filepath.Join("/proc/sys/net/ipv4/conf", proxy.Iface, name)
		if err := manager.writeSysctl(path, "1"); err != nil {
			return err
		}
	}
	if err := netlink.NeighSet(&netlink.Neigh{
		LinkIndex: proxy.Ifindex,
		Family:    netlink.FAMILY_V4,
		Flags:     netlink.NTF_PROXY,
		IP:        net.IP(proxy.Address.AsSlice()),
	}); err != nil {
		return fmt.Errorf("install device proxy ARP %s dev %s: %w", proxy.Address, proxy.Iface, err)
	}
	manager.deviceAccessProxyARP[proxy.Key] = proxy
	return nil
}

func (manager *Manager) deleteDeviceAccessProxyARPLocked(proxy deviceAccessProxyARPState) error {
	if !proxy.Address.Is4() {
		return nil
	}
	if proxy.Ifindex <= 0 && proxy.Iface != "" {
		link, err := netlink.LinkByName(proxy.Iface)
		if err != nil {
			if isNotFound(err) {
				return nil
			}
			return fmt.Errorf("inspect LAN iface %q for device proxy ARP cleanup %s: %w", proxy.Iface, proxy.Address, err)
		}
		proxy.Ifindex = link.Attrs().Index
	}
	if proxy.Ifindex <= 0 {
		return nil
	}
	if err := netlink.NeighDel(&netlink.Neigh{
		LinkIndex: proxy.Ifindex,
		Family:    netlink.FAMILY_V4,
		Flags:     netlink.NTF_PROXY,
		IP:        net.IP(proxy.Address.AsSlice()),
	}); err != nil && !isNotFound(err) {
		return fmt.Errorf("delete device proxy ARP %s dev %s: %w", proxy.Address, proxy.Iface, err)
	}
	return nil
}

func deviceAccessProxyARPKey(iface string, addr netip.Addr) string {
	return iface + "|" + addr.String()
}

func (manager *Manager) deviceAccessProxyARPSnapshotLocked() []persistedDeviceAccessProxyARP {
	if len(manager.deviceAccessProxyARP) == 0 {
		return nil
	}
	keys := make([]string, 0, len(manager.deviceAccessProxyARP))
	for key := range manager.deviceAccessProxyARP {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]persistedDeviceAccessProxyARP, 0, len(keys))
	for _, key := range keys {
		proxy := manager.deviceAccessProxyARP[key]
		out = append(out, persistedDeviceAccessProxyARP{
			Key:     proxy.Key,
			Iface:   proxy.Iface,
			Ifindex: proxy.Ifindex,
			Address: proxy.Address.String(),
		})
	}
	return out
}

func deviceAccessProxyARPStateMap(items []persistedDeviceAccessProxyARP) map[string]deviceAccessProxyARPState {
	if len(items) == 0 {
		return nil
	}
	out := make(map[string]deviceAccessProxyARPState, len(items))
	for _, item := range items {
		addr, err := netip.ParseAddr(item.Address)
		if err != nil || !addr.Is4() {
			continue
		}
		key := item.Key
		if key == "" {
			key = deviceAccessProxyARPKey(item.Iface, addr)
		}
		out[key] = deviceAccessProxyARPState{
			Key:     key,
			Iface:   item.Iface,
			Ifindex: item.Ifindex,
			Address: addr,
		}
	}
	return out
}

func (manager *Manager) syncNATLocked(snapshot *dataplane.NATSnapshot) error {
	if manager.natConfigMap == nil || manager.natSourceMap == nil || manager.natRouteMap == nil || manager.natExcludeMap == nil || manager.natBindingMap == nil {
		return nil
	}
	if err := clearBPFMap[routeKey, uint32](manager.natSourceMap, "NAT source LPM BPF map"); err != nil {
		return err
	}
	if err := clearBPFMap[routeKey, uint32](manager.natRouteMap, "NAT route LPM BPF map"); err != nil {
		return err
	}
	if err := clearBPFMap[[4]byte, uint32](manager.natExcludeMap, "NAT exclude BPF map"); err != nil {
		return err
	}
	manager.natSourceEntries = 0
	manager.natRouteEntries = 0
	manager.natExcludeEntries = 0
	key := uint32(0)
	value := natConfigValue{}
	if snapshot != nil && snapshot.Enabled && snapshot.Gateway.Is4() {
		value.Enabled = 1
		value.Gateway = snapshot.Gateway.As4()
		for _, prefix := range snapshot.SourcePrefixes {
			if !prefix.Addr().Is4() {
				manager.warnings = append(manager.warnings, fmt.Sprintf("skip non-IPv4 NAT source prefix %q", prefix))
				continue
			}
			masked := prefix.Masked()
			key := routeKey{PrefixLen: uint32(masked.Bits()), Addr: masked.Addr().As4()}
			if err := manager.natSourceMap.Update(key, uint32(1), cebpf.UpdateAny); err != nil {
				return fmt.Errorf("sync NAT source prefix %q to BPF LPM map: %w", masked, err)
			}
			manager.natSourceEntries++
		}
		for _, rawPrefix := range snapshot.RoutePrefixes {
			prefix, err := rawPrefix.Parse()
			if err != nil {
				return err
			}
			if !prefix.Addr().Is4() {
				manager.warnings = append(manager.warnings, fmt.Sprintf("skip non-IPv4 NAT route prefix %q", rawPrefix))
				continue
			}
			masked := prefix.Masked()
			key := routeKey{PrefixLen: uint32(masked.Bits()), Addr: masked.Addr().As4()}
			if err := manager.natRouteMap.Update(key, uint32(1), cebpf.UpdateAny); err != nil {
				return fmt.Errorf("sync NAT route prefix %q to BPF LPM map: %w", rawPrefix, err)
			}
			manager.natRouteEntries++
		}
		for _, addr := range snapshot.ExcludedDestinations {
			if !addr.Is4() {
				continue
			}
			key := addr.As4()
			if err := manager.natExcludeMap.Update(key, uint32(1), cebpf.UpdateAny); err != nil {
				return fmt.Errorf("sync NAT excluded destination %q to BPF map: %w", addr, err)
			}
			manager.natExcludeEntries++
		}
		if manager.natSourceEntries == 0 || manager.natRouteEntries == 0 {
			value = natConfigValue{}
		}
	}
	var bindings []dataplane.NATBinding
	if value.Enabled != 0 && snapshot != nil {
		bindings = snapshot.Bindings
	}
	if err := manager.syncNATBindingsLocked(bindings); err != nil {
		manager.natBindingSyncErrors++
		return err
	}
	if err := manager.natConfigMap.Update(key, value, cebpf.UpdateAny); err != nil {
		return fmt.Errorf("sync NAT config to BPF map: %w", err)
	}
	return nil
}

func (manager *Manager) syncNATBindingsLocked(bindings []dataplane.NATBinding) error {
	if manager.natBindingKeys == nil {
		manager.natBindingKeys = make(map[natBindingKey]struct{})
	}
	now := time.Now().UTC()
	nowNS, err := monotonicNowNS()
	if err != nil {
		return err
	}
	desired := make(map[natBindingKey]natBindingValue, len(bindings))
	for _, binding := range bindings {
		if !binding.TranslatedIP.Is4() || !binding.RemoteIP.Is4() || !binding.OriginalIP.Is4() {
			continue
		}
		if !binding.ExpiresAt.IsZero() && !now.Before(binding.ExpiresAt) {
			continue
		}
		expiresNS := uint64(0)
		if !binding.ExpiresAt.IsZero() {
			remaining := binding.ExpiresAt.Sub(now)
			if remaining <= 0 {
				continue
			}
			expiresNS = nowNS + uint64(remaining.Nanoseconds())
		}
		key := natBindingKey{
			TranslatedIP: binding.TranslatedIP.As4(),
			RemoteIP:     binding.RemoteIP.As4(),
			Protocol:     uint32(binding.Protocol),
			LocalPort:    htons(binding.LocalPort),
			RemotePort:   htons(binding.RemotePort),
		}
		value := natBindingValue{
			OriginalIP: binding.OriginalIP.As4(),
			ExpiresNS:  expiresNS,
		}
		desired[key] = value
	}
	for key := range manager.natBindingKeys {
		if _, ok := desired[key]; ok {
			continue
		}
		if err := manager.natBindingMap.Delete(key); err != nil && !errors.Is(err, cebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete stale NAT binding from BPF map: %w", err)
		}
		delete(manager.natBindingKeys, key)
	}
	for key, value := range desired {
		if err := manager.natBindingMap.Update(key, value, cebpf.UpdateAny); err != nil {
			return fmt.Errorf("sync NAT binding to BPF map: %w", err)
		}
		manager.natBindingKeys[key] = struct{}{}
	}
	manager.natBindingEntries = uint64(len(manager.natBindingKeys))
	return nil
}

func monotonicNowNS() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, fmt.Errorf("read monotonic clock for NAT binding expiry: %w", err)
	}
	return uint64(ts.Sec)*uint64(time.Second) + uint64(ts.Nsec), nil
}

func routeActionForKind(kind routing.RouteKind) (uint32, bool) {
	switch kind {
	case "", routing.RouteUnicast:
		return routeActionCapture, true
	case routing.RouteLocal:
		return routeActionLocal, true
	case routing.RouteBlackhole:
		return routeActionBlackhole, true
	case routing.RouteReject:
		return routeActionReject, true
	default:
		return 0, false
	}
}

func (manager *Manager) clearRouteMapLocked() error {
	return clearBPFMap[routeKey, routeValue](manager.routeMap, "route LPM BPF map")
}

func (manager *Manager) kernelUDPTXDirectUnderlayTarget(remoteIP netip.Addr, sourceIP netip.Addr, preferredLink netlink.Link, policyMTU uint32) (kernelUDPTXDirectUnderlayTarget, error) {
	if !remoteIP.Is4() {
		return kernelUDPTXDirectUnderlayTarget{}, fmt.Errorf("kernel_udp TX direct remote %s is not IPv4", remoteIP)
	}
	if preferredLink == nil || preferredLink.Attrs() == nil {
		return kernelUDPTXDirectUnderlayTarget{}, fmt.Errorf("kernel_udp TX direct preferred underlay link is unavailable")
	}
	preferredAttrs := preferredLink.Attrs()
	targetIfindex := preferredAttrs.Index
	nextHop := remoteIP
	routeIP := net.IP(remoteIP.AsSlice())
	var (
		routes []netlink.Route
		err    error
	)
	if sourceIP.Is4() && !sourceIP.IsUnspecified() {
		manager.kernelUDPTXDirectSync.RouteSourceLookups++
		routes, err = netlink.RouteGetWithOptions(routeIP, &netlink.RouteGetOptions{
			SrcAddr: net.IP(sourceIP.AsSlice()),
		})
		if err != nil {
			manager.kernelUDPTXDirectSync.RouteSourceErrors++
			return kernelUDPTXDirectUnderlayTarget{}, fmt.Errorf("route to %s from %s: %w", remoteIP, sourceIP, err)
		}
	} else {
		routes, err = netlink.RouteGet(routeIP)
		if err != nil {
			return kernelUDPTXDirectUnderlayTarget{}, fmt.Errorf("route to %s: %w", remoteIP, err)
		}
	}
	if len(routes) == 0 {
		return kernelUDPTXDirectUnderlayTarget{}, fmt.Errorf("route to %s: no route", remoteIP)
	}
	route := routes[0]
	if route.LinkIndex > 0 {
		targetIfindex = route.LinkIndex
	}
	if route.Gw != nil {
		if gw, ok := ipv4AddrFromIP(route.Gw); ok {
			nextHop = gw
			manager.kernelUDPTXDirectSync.RouteGatewayNextHops++
		}
	}
	if targetIfindex <= 0 {
		return kernelUDPTXDirectUnderlayTarget{}, fmt.Errorf("route to %s returned invalid ifindex %d", remoteIP, targetIfindex)
	}
	targetLink := preferredLink
	if targetIfindex != preferredAttrs.Index {
		manager.kernelUDPTXDirectSync.RouteIfindexSwitches++
		targetLink, err = netlink.LinkByIndex(targetIfindex)
		if err != nil {
			manager.kernelUDPTXDirectSync.RouteLinkLookupErrors++
			return kernelUDPTXDirectUnderlayTarget{}, fmt.Errorf("inspect route ifindex %d for %s: %w", targetIfindex, remoteIP, err)
		}
	}
	targetAttrs := targetLink.Attrs()
	if targetAttrs == nil {
		return kernelUDPTXDirectUnderlayTarget{}, fmt.Errorf("route ifindex %d has no link attributes", targetIfindex)
	}
	sourceMAC := targetAttrs.HardwareAddr
	if len(sourceMAC) != 6 {
		return kernelUDPTXDirectUnderlayTarget{}, fmt.Errorf("route ifindex %d has invalid source MAC %s", targetIfindex, sourceMAC)
	}
	mtu := uint32(targetAttrs.MTU)
	if policyMTU > 0 && (mtu == 0 || policyMTU < mtu) {
		mtu = policyMTU
	}
	destinationMAC, err := manager.resolveIPv4NeighborVia(targetIfindex, remoteIP, nextHop)
	if err != nil {
		return kernelUDPTXDirectUnderlayTarget{}, err
	}
	if len(destinationMAC) != 6 {
		return kernelUDPTXDirectUnderlayTarget{}, fmt.Errorf("%w: invalid neighbor MAC %s for %s via %s on ifindex %d", errNeighborUnresolved, destinationMAC, remoteIP, nextHop, targetIfindex)
	}
	return kernelUDPTXDirectUnderlayTarget{
		ifindex:        targetIfindex,
		mtu:            mtu,
		sourceMAC:      append(net.HardwareAddr(nil), sourceMAC[:6]...),
		destinationMAC: append(net.HardwareAddr(nil), destinationMAC[:6]...),
	}, nil
}

func (manager *Manager) syncKernelUDPTXDirectLocked() error {
	manager.kernelUDPTXDirectSync.Attempts++
	if manager.kernelUDPTXRouteMap == nil || manager.kernelUDPTXFlowMap == nil {
		manager.kernelUDPTXDirectSync.SkippedMissingMaps++
		return nil
	}
	if err := manager.rememberKernelUDPTXDirectSequencesLocked(); err != nil {
		manager.warnings = append(manager.warnings, err.Error())
	}
	if err := clearBPFMap[routeKey, kernelUDPTXRouteValue](manager.kernelUDPTXRouteMap, "kernel_udp TC TX route LPM BPF map"); err != nil {
		return err
	}
	if err := clearBPFMap[uint64, kernelUDPTXFlowValue](manager.kernelUDPTXFlowMap, "kernel_udp TC TX flow BPF map"); err != nil {
		return err
	}
	if err := manager.clearKernelUDPTXDirectRouteCacheLocked(); err != nil {
		return err
	}
	manager.kernelUDPTXDirectRoutes = 0
	manager.kernelUDPTXDirectFlows = 0
	manager.kernelUDPTXDirectInlineRoutes = 0
	manager.kernelUDPTXDirectInlineFlows = 0
	manager.kernelUDPTXDirectRouteCacheEnabled = false
	manager.kernelUDPTXDirectRouteCacheException = false
	manager.kernelCryptoTCSealConfiguredFlows = 0
	if err := manager.syncKernelUDPRXDirectConfigLocked(); err != nil {
		return err
	}
	if !kernelUDPTXDirectProgramEnabledForSpec(manager.spec) {
		manager.kernelUDPTXDirectSync.SkippedDisabled++
		return nil
	}
	if manager.snapshot.NAT != nil && manager.snapshot.NAT.Enabled {
		manager.kernelUDPTXDirectSync.SkippedNAT++
		return nil
	}
	force := kernelUDPTXDirectForceEnabled()
	secureDirect := manager.kernelUDPTXSecureDirectAttached
	underlayName := manager.spec.UnderlayIface
	if underlayName == "" {
		manager.kernelUDPTXDirectSync.SkippedNoUnderlay++
		return nil
	}
	if len(manager.snapshot.Routes) == 0 {
		manager.kernelUDPTXDirectSync.SkippedNoRoutes++
		return nil
	}
	if len(manager.kernelUDPFlows) == 0 && len(manager.expTCPFlows) == 0 {
		manager.kernelUDPTXDirectSync.SkippedNoFlows++
		return nil
	}
	routeCacheOK := kernelUDPTXDirectRouteCacheEnabled(kernelUDPTXDirectProgramOptions{
		ExperimentalTCPOnly: kernelUDPTXDirectExperimentalTCPOnlyEnabledForSpec(manager.spec),
		DirectOnly:          kernelUDPTXDirectOnlyEnabled(manager.spec),
	}) && manager.kernelUDPTXRouteCacheMap != nil && manager.snapshot.NAT == nil && !secureDirect
	var routeCache kernelUDPTXRouteCacheValue
	underlay, err := netlink.LinkByName(underlayName)
	if err != nil {
		manager.kernelUDPTXDirectSync.UnderlayLookupErrors++
		return nil
	}
	if underlay.Attrs() == nil || underlay.Attrs().Index == 0 || len(underlay.Attrs().HardwareAddr) != 6 {
		manager.kernelUDPTXDirectSync.BadUnderlayAttrs++
		return nil
	}
	flowValues := make(map[uint64]kernelUDPTXFlowValue)
	for _, route := range manager.snapshot.Routes {
		manager.kernelUDPTXDirectSync.RoutesScanned++
		prefix, err := route.Prefix.Parse()
		if err != nil || !prefix.Addr().Is4() {
			manager.kernelUDPTXDirectSync.RoutesSkippedPrefix++
			continue
		}
		if directRoute, ok := kernelUDPTXDirectRouteForSync(route, prefix); ok {
			route = directRoute
			if kernelUDPTXDirectManagementVIPRoute(route) {
				if err := manager.syncKernelUDPTXDirectBypassRouteLocked(prefix); err != nil {
					return err
				}
				manager.kernelUDPTXDirectSync.RoutesBlocked++
				continue
			}
		} else if route.Kind != "" && route.Kind != routing.RouteUnicast {
			if kernelUDPTXDirectBypassRouteForSync(route) {
				if err := manager.syncKernelUDPTXDirectBypassRouteLocked(prefix); err != nil {
					return err
				}
			} else if err := manager.syncKernelUDPTXDirectBlockedRouteLocked(route, prefix); err != nil {
				return err
			}
			manager.kernelUDPTXDirectSync.RoutesSkippedKind++
			manager.kernelUDPTXDirectSync.RoutesBlocked++
			continue
		}
		routeFlows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, force, secureDirect, kernelUDPTXRouteMaxFlows)
		manager.kernelUDPTXDirectSync.RouteFlowsCandidate += uint64(len(routeFlows))
		if len(routeFlows) == 0 {
			if err := manager.syncKernelUDPTXDirectBlockedRouteLocked(route, prefix); err != nil {
				return err
			}
			manager.kernelUDPTXDirectSync.RoutesBlocked++
			manager.kernelUDPTXDirectSync.RoutesWithoutFlows++
			continue
		}
		var routeValue kernelUDPTXRouteValue
		routeFlowValues := make(map[uint64]kernelUDPTXFlowValue, len(routeFlows))
		routeFlowCount := 0
		for _, routeFlow := range routeFlows {
			flowID := routeFlow.id
			remote := routeFlow.packet.DestinationIP
			sourceIP := routeFlow.packet.SourceIP
			sourcePort := routeFlow.packet.SourcePort
			destinationPort := routeFlow.packet.DestinationPort
			if routeFlow.experimentalTCP {
				remote = routeFlow.expTCPPacket.DestinationIP
				sourceIP = routeFlow.expTCPPacket.SourceIP
				sourcePort = routeFlow.expTCPPacket.SourcePort
				destinationPort = routeFlow.expTCPPacket.DestinationPort
			}
			if !remote.Is4() || !sourceIP.Is4() || sourcePort == 0 || destinationPort == 0 {
				manager.kernelUDPTXDirectSync.InvalidPackets++
				continue
			}
			underlayTarget, err := manager.kernelUDPTXDirectUnderlayTarget(remote, sourceIP, underlay, manager.snapshot.PacketPolicy.MTU)
			if err != nil {
				manager.kernelUDPTXDirectSync.NeighborMisses++
				continue
			}
			value, exists := flowValues[flowID]
			if !exists {
				sequence := uint64(0)
				if manager.kernelUDPTXDirectSequences != nil {
					sequence = manager.kernelUDPTXDirectSequences[flowID]
				}
				value = kernelUDPTXFlowValue{
					Sequence:        sequence,
					SourceIP:        sourceIP.As4(),
					DestinationIP:   remote.As4(),
					SourcePort:      htons(sourcePort),
					DestinationPort: htons(destinationPort),
					Ifindex:         uint32(underlayTarget.ifindex),
					DestinationMAC0: binary.LittleEndian.Uint32(underlayTarget.destinationMAC[0:4]),
					DestinationMAC1: binary.LittleEndian.Uint16(underlayTarget.destinationMAC[4:6]),
					SourceMAC0:      binary.LittleEndian.Uint32(underlayTarget.sourceMAC[0:4]),
					SourceMAC1:      binary.LittleEndian.Uint16(underlayTarget.sourceMAC[4:6]),
					IPv4ChecksumUDP: kernelUDPTXIPv4ChecksumBase(sourceIP.As4(), remote.As4(), ipProtocolUDP),
					IPv4ChecksumTCP: kernelUDPTXIPv4ChecksumBase(sourceIP.As4(), remote.As4(), ipProtocolTCP),
					MTU:             underlayTarget.mtu,
				}
				value.Flags = manager.kernelUDPTXDirectFlowFlagsLocked(route, routeFlow, secureDirect)
				flowValues[flowID] = value
				if err := manager.kernelUDPTXFlowMap.Update(flowID, value, cebpf.UpdateAny); err != nil {
					return fmt.Errorf("sync kernel_udp TC TX flow %d: %w", flowID, err)
				}
				manager.kernelUDPTXDirectFlows++
				manager.kernelUDPTXDirectSync.FlowsWritten++
			}
			routeFlowValues[flowID] = value
			if !appendKernelUDPTXRouteFlow(&routeValue, flowID, routeFlowCount) {
				manager.kernelUDPTXDirectSync.RouteFlowAppendReject++
				continue
			}
			routeFlowCount++
		}
		if routeFlowCount == 0 {
			if err := manager.syncKernelUDPTXDirectBlockedRouteLocked(route, prefix); err != nil {
				return err
			}
			manager.kernelUDPTXDirectSync.RoutesBlocked++
			continue
		}
		activeRouteFlowCount := kernelUDPTXRouteFlowPowerOfTwoLimit(routeFlowCount, routeFlowCount)
		routeValue.FlowID = routeValue.FlowID1
		routeValue.FlowMask = uint32(activeRouteFlowCount - 1)
		if manager.kernelUDPTXRouteFailClosedLocked(route) {
			routeValue.Flags |= kernelUDPTXRouteFlagDirectOnly
		}
		if kernelUDPTXInlineRouteFlowAllowedForSpec(manager.spec, routeFlows, routeFlowCount) && appendKernelUDPTXRouteInlineFlowsForSpec(manager.spec, &routeValue, routeFlowValues, activeRouteFlowCount) {
			routeValue.Flags |= kernelUDPTXRouteFlagInlineFlow
			manager.kernelUDPTXDirectInlineRoutes++
			manager.kernelUDPTXDirectInlineFlows += uint64(activeRouteFlowCount)
			manager.kernelUDPTXDirectSync.InlineFlowsWritten += uint64(activeRouteFlowCount)
		}
		masked := prefix.Masked()
		if routeCacheOK {
			if !kernelUDPTXDirectRouteCacheCandidate(routeCache.Enabled != 0, routeValue) {
				routeCacheOK = false
			} else {
				routeCache = kernelUDPTXRouteCacheValue{
					Enabled:    1,
					PrefixLen:  uint32(masked.Bits()),
					PrefixAddr: masked.Addr().As4(),
					Route:      routeValue,
				}
			}
		}
		key := routeKey{PrefixLen: uint32(masked.Bits()), Addr: masked.Addr().As4()}
		if err := manager.kernelUDPTXRouteMap.Update(key, routeValue, cebpf.UpdateAny); err != nil {
			return fmt.Errorf("sync kernel_udp TC TX route %q: %w", route.Prefix, err)
		}
		manager.kernelUDPTXDirectRoutes++
		manager.kernelUDPTXDirectSync.RoutesWritten++
	}
	if routeCacheOK && routeCache.Enabled != 0 {
		exception, hasException, ok := manager.kernelUDPTXDirectRouteCacheExceptionLocked(netip.PrefixFrom(netip.AddrFrom4(routeCache.PrefixAddr), int(routeCache.PrefixLen)))
		if !ok {
			routeCache.Enabled = 0
		} else if hasException {
			routeCache.ExceptionEnabled = 1
			routeCache.ExceptionLen = uint32(exception.Bits())
			routeCache.ExceptionAddr = exception.Addr().As4()
		}
	}
	if routeCacheOK && routeCache.Enabled != 0 {
		if err := manager.syncKernelUDPTXDirectRouteCacheLocked(routeCache); err != nil {
			return err
		}
	}
	return nil
}

func kernelUDPTXDirectRouteCacheCandidate(routeCacheSet bool, routeValue kernelUDPTXRouteValue) bool {
	if routeCacheSet {
		return false
	}
	if routeValue.Flags&kernelUDPTXRouteFlagBypass != 0 {
		return false
	}
	if routeValue.FlowID == 0 || routeValue.FlowID1 == 0 {
		return false
	}
	return true
}

func kernelUDPTXDirectRouteForSync(route routing.Route, prefix netip.Prefix) (routing.Route, bool) {
	if route.Kind == "" || route.Kind == routing.RouteUnicast {
		return route, true
	}
	if route.Kind != routing.RouteLocal || route.Source != "management_vip" {
		return routing.Route{}, false
	}
	if !prefix.Addr().Is4() || prefix.Bits() != 32 || route.Owner == "" {
		return routing.Route{}, false
	}
	if route.LocalProtocol != 0 && route.LocalProtocol != ipProtocolTCP {
		return routing.Route{}, false
	}
	if route.LocalPort == 0 {
		return routing.Route{}, false
	}
	route.Kind = routing.RouteUnicast
	route.NextHop = route.Owner
	return route, true
}

func kernelUDPTXDirectBypassRouteForSync(route routing.Route) bool {
	return route.Kind == routing.RouteLocal
}

func (manager *Manager) kernelUDPTXDirectPlaintextReadyLocked() bool {
	if !kernelUDPTXDirectProgramEnabledForSpec(manager.spec) {
		return false
	}
	if manager.snapshot.NAT != nil && manager.snapshot.NAT.Enabled {
		return false
	}
	if len(manager.snapshot.Routes) == 0 {
		return false
	}
	for _, route := range manager.snapshot.Routes {
		if route.NextHop == "" || route.Kind != "" && route.Kind != routing.RouteUnicast {
			continue
		}
		if manager.routeHasKernelUDPTXDirectPlaintextFlowLocked(route) {
			return true
		}
	}
	return false
}

func (manager *Manager) routeHasKernelUDPTXDirectPlaintextFlowLocked(route routing.Route) bool {
	expTCPOnly := kernelUDPTXDirectExperimentalTCPOnlyEnabledForSpec(manager.spec)
	kernelUDPOnly := !expTCPOnly && kernelUDPTXDirectKernelUDPOnlyEnabledForSpec(manager.spec)
	if !expTCPOnly {
		for flowID, flow := range manager.kernelUDPFlows {
			if flowID == 0 || flow.Peer == "" || flow.Peer != route.NextHop {
				continue
			}
			if route.Endpoint != "" && flow.Endpoint != route.Endpoint {
				continue
			}
			if manager.kernelUDPTXDirectPlaintextAllowed(route, flow) {
				return true
			}
		}
	}
	if !kernelUDPOnly && experimentalTCPTXDirectEnabledForSpec(manager.spec) {
		for flowID, flow := range manager.expTCPFlows {
			if flowID == 0 || flow.Peer == "" || flow.Peer != route.NextHop {
				continue
			}
			if route.Endpoint != "" && flow.Endpoint != route.Endpoint {
				continue
			}
			if strings.TrimSpace(flow.RemoteAddress) == "" {
				continue
			}
			if manager.experimentalTCPTXDirectPlaintextAllowed(route, flow) {
				return true
			}
		}
	}
	return false
}

func (manager *Manager) bumpKernelUDPTXDirectSequencesLocked(sequences map[uint64]uint64) error {
	if len(sequences) == 0 {
		return nil
	}
	if manager.kernelUDPTXDirectSequences == nil {
		manager.kernelUDPTXDirectSequences = make(map[uint64]uint64, len(sequences))
	}
	for flowID, sequence := range sequences {
		if sequence == 0 {
			continue
		}
		if manager.kernelUDPTXDirectSequences[flowID] < sequence {
			manager.kernelUDPTXDirectSequences[flowID] = sequence
		}
		if manager.kernelUDPTXFlowMap == nil {
			continue
		}
		var value kernelUDPTXFlowValue
		if err := manager.kernelUDPTXFlowMap.Lookup(flowID, &value); err != nil {
			if errors.Is(err, cebpf.ErrKeyNotExist) {
				continue
			}
			return fmt.Errorf("read kernel_udp TC TX flow %d sequence: %w", flowID, err)
		}
		if value.Sequence >= sequence {
			continue
		}
		value.Sequence = sequence
		if err := manager.kernelUDPTXFlowMap.Update(flowID, value, cebpf.UpdateAny); err != nil {
			return fmt.Errorf("bump kernel_udp TC TX flow %d sequence to %d: %w", flowID, sequence, err)
		}
	}
	return nil
}

func (manager *Manager) syncKernelUDPTXDirectBlockedRouteLocked(route routing.Route, prefix netip.Prefix) error {
	if manager.kernelUDPTXRouteMap == nil {
		return nil
	}
	if !manager.kernelUDPTXRouteFailClosedLocked(route) {
		return nil
	}
	value := kernelUDPTXRouteValue{}
	value.Flags |= kernelUDPTXRouteFlagDirectOnly
	value.Flags |= kernelUDPTXRouteFlagBypass
	masked := prefix.Masked()
	key := routeKey{PrefixLen: uint32(masked.Bits()), Addr: masked.Addr().As4()}
	if err := manager.kernelUDPTXRouteMap.Update(key, value, cebpf.UpdateAny); err != nil {
		return fmt.Errorf("sync kernel_udp TC TX blocked route %q: %w", prefix, err)
	}
	return nil
}

func (manager *Manager) kernelUDPTXRouteFailClosedLocked(route routing.Route) bool {
	if !kernelUDPTXDirectOnlyEnabled(manager.spec) {
		return false
	}
	if route.NextHop == "" {
		return true
	}
	if !manager.routeCanUseOnlyExperimentalTCPDirectLocked(route) {
		return true
	}
	return experimentalTCPTXRawDirectExplicitlyEnabled()
}

func (manager *Manager) routeCanUseOnlyExperimentalTCPDirectLocked(route routing.Route) bool {
	if route.Endpoint != "" {
		return manager.snapshotEndpointTransportLocked(route.NextHop, route.Endpoint) == "experimental_tcp"
	}
	found := false
	for _, endpoint := range manager.snapshot.Endpoints {
		if !endpoint.Enabled || endpoint.Peer != route.NextHop {
			continue
		}
		transportName := strings.ToLower(strings.TrimSpace(endpoint.Transport))
		switch transportName {
		case "udp", "kernel_udp":
			return false
		case "experimental_tcp":
			found = true
		}
	}
	return found
}

func (manager *Manager) snapshotEndpointTransportLocked(peer core.IXID, endpointID core.EndpointID) string {
	for _, endpoint := range manager.snapshot.Endpoints {
		if !endpoint.Enabled || endpoint.Peer != peer || endpoint.ID != endpointID {
			continue
		}
		return strings.ToLower(strings.TrimSpace(endpoint.Transport))
	}
	return ""
}

func (manager *Manager) syncKernelUDPTXDirectBypassRouteLocked(prefix netip.Prefix) error {
	if manager.kernelUDPTXRouteMap == nil {
		return nil
	}
	value := kernelUDPTXRouteValue{Flags: kernelUDPTXRouteFlagBypass}
	masked := prefix.Masked()
	key := routeKey{PrefixLen: uint32(masked.Bits()), Addr: masked.Addr().As4()}
	if err := manager.kernelUDPTXRouteMap.Update(key, value, cebpf.UpdateAny); err != nil {
		return fmt.Errorf("sync kernel_udp TC TX bypass route %q: %w", prefix, err)
	}
	return nil
}

func (manager *Manager) clearKernelUDPTXDirectRouteCacheLocked() error {
	if manager.kernelUDPTXRouteCacheMap == nil {
		return nil
	}
	key := uint32(0)
	value := kernelUDPTXRouteCacheValue{}
	if err := manager.kernelUDPTXRouteCacheMap.Update(key, value, cebpf.UpdateAny); err != nil {
		return fmt.Errorf("clear kernel_udp TC TX route cache BPF map: %w", err)
	}
	return nil
}

func (manager *Manager) syncKernelUDPTXDirectRouteCacheLocked(value kernelUDPTXRouteCacheValue) error {
	if manager.kernelUDPTXRouteCacheMap == nil || value.Enabled == 0 {
		return nil
	}
	key := uint32(0)
	if err := manager.kernelUDPTXRouteCacheMap.Update(key, value, cebpf.UpdateAny); err != nil {
		return fmt.Errorf("sync kernel_udp TC TX route cache BPF map: %w", err)
	}
	manager.kernelUDPTXDirectRouteCacheEnabled = true
	manager.kernelUDPTXDirectRouteCacheException = value.ExceptionEnabled != 0
	return nil
}

func (manager *Manager) kernelUDPTXDirectRouteCacheExceptionLocked(selected netip.Prefix) (netip.Prefix, bool, bool) {
	var exception netip.Prefix
	for _, route := range manager.snapshot.Routes {
		prefix, err := route.Prefix.Parse()
		if err != nil || !prefix.Addr().Is4() {
			continue
		}
		prefix = prefix.Masked()
		if prefix == selected || !selected.Contains(prefix.Addr()) || prefix.Bits() <= selected.Bits() {
			continue
		}
		if exception.IsValid() {
			return netip.Prefix{}, false, false
		}
		exception = prefix
	}
	if !exception.IsValid() {
		return netip.Prefix{}, false, true
	}
	return exception, true, true
}

func kernelUDPTXDirectRouteCacheEnabled(options ...kernelUDPTXDirectProgramOptions) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_TX_ROUTE_CACHE"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		if len(options) > 0 {
			opts := options[0]
			return opts.DirectOnly || opts.ExperimentalTCPOnly
		}
		return false
	}
}

func (manager *Manager) reserveKernelUDPTXSequenceLocked(flowID uint64, requested uint64) (uint64, error) {
	if flowID == 0 {
		return requested, nil
	}
	if manager.kernelUDPTXDirectSequences == nil {
		manager.kernelUDPTXDirectSequences = make(map[uint64]uint64)
	}
	current := manager.kernelUDPTXDirectSequences[flowID]
	var value kernelUDPTXFlowValue
	var haveFlowValue bool
	if manager.kernelUDPTXFlowMap != nil {
		if err := manager.kernelUDPTXFlowMap.Lookup(flowID, &value); err != nil {
			if !errors.Is(err, cebpf.ErrKeyNotExist) {
				return 0, fmt.Errorf("read kernel_udp TC TX flow %d sequence before userspace send: %w", flowID, err)
			}
		} else {
			haveFlowValue = true
			if value.Sequence > current {
				current = value.Sequence
			}
		}
	}
	sequence := requested
	if sequence <= current {
		if current == ^uint64(0) {
			return 0, fmt.Errorf("kernel_udp flow %d TX sequence exhausted", flowID)
		}
		sequence = current + 1
	}
	manager.kernelUDPTXDirectSequences[flowID] = sequence
	if haveFlowValue && value.Sequence < sequence {
		value.Sequence = sequence
		if err := manager.kernelUDPTXFlowMap.Update(flowID, value, cebpf.UpdateAny); err != nil {
			return 0, fmt.Errorf("reserve kernel_udp TC TX flow %d sequence %d: %w", flowID, sequence, err)
		}
	}
	return sequence, nil
}

func kernelUDPTXSequenceBatchEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TX_SEQUENCE_BATCH"))) {
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}

func (manager *Manager) reserveKernelUDPTXSequenceBatchLocked(pendingByFlow *map[uint64]*kernelUDPTXSequenceBatch, singleFlowID *uint64, single **kernelUDPTXSequenceBatch, flowID uint64, requested uint64, capacity int) (uint64, error) {
	if flowID == 0 {
		return requested, nil
	}
	pending := kernelUDPTXSequenceBatchFor(pendingByFlow, singleFlowID, single, flowID, capacity)
	if !pending.initialized {
		if err := manager.initKernelUDPTXSequenceBatchLocked(pending); err != nil {
			return 0, err
		}
	}
	sequence := requested
	if sequence <= pending.current {
		if pending.current == ^uint64(0) {
			return 0, fmt.Errorf("kernel_udp flow %d TX sequence exhausted", flowID)
		}
		sequence = pending.current + 1
	}
	pending.current = sequence
	if manager.kernelUDPTXDirectSequences == nil {
		manager.kernelUDPTXDirectSequences = make(map[uint64]uint64)
	}
	manager.kernelUDPTXDirectSequences[flowID] = sequence
	if pending.haveValue && pending.value.Sequence < sequence {
		pending.value.Sequence = sequence
		pending.mapDirty = true
	}
	if sequence > pending.reservedHigh {
		pending.reservedHigh = sequence
	}
	return sequence, nil
}

func kernelUDPTXSequenceBatchFor(pendingByFlow *map[uint64]*kernelUDPTXSequenceBatch, singleFlowID *uint64, single **kernelUDPTXSequenceBatch, flowID uint64, capacity int) *kernelUDPTXSequenceBatch {
	if *pendingByFlow != nil {
		pending := (*pendingByFlow)[flowID]
		if pending == nil {
			pending = &kernelUDPTXSequenceBatch{flowID: flowID}
			(*pendingByFlow)[flowID] = pending
		}
		return pending
	}
	if *single == nil {
		*singleFlowID = flowID
		*single = &kernelUDPTXSequenceBatch{flowID: flowID}
		return *single
	}
	if *singleFlowID == flowID {
		return *single
	}
	if capacity < 2 {
		capacity = 2
	}
	*pendingByFlow = make(map[uint64]*kernelUDPTXSequenceBatch, capacity)
	(*pendingByFlow)[*singleFlowID] = *single
	pending := &kernelUDPTXSequenceBatch{flowID: flowID}
	(*pendingByFlow)[flowID] = pending
	return pending
}

func (manager *Manager) initKernelUDPTXSequenceBatchLocked(batch *kernelUDPTXSequenceBatch) error {
	if batch == nil || batch.initialized {
		return nil
	}
	if manager.kernelUDPTXDirectSequences == nil {
		manager.kernelUDPTXDirectSequences = make(map[uint64]uint64)
	}
	batch.current = manager.kernelUDPTXDirectSequences[batch.flowID]
	if manager.kernelUDPTXFlowMap != nil {
		batch.mapChecked = true
		if err := manager.kernelUDPTXFlowMap.Lookup(batch.flowID, &batch.value); err != nil {
			if !errors.Is(err, cebpf.ErrKeyNotExist) {
				return fmt.Errorf("read kernel_udp TC TX flow %d sequence before userspace send: %w", batch.flowID, err)
			}
		} else {
			batch.haveValue = true
			if batch.value.Sequence > batch.current {
				batch.current = batch.value.Sequence
			}
		}
	}
	batch.initialized = true
	return nil
}

func (manager *Manager) flushKernelUDPTXSequenceBatchesLocked(pendingByFlow map[uint64]*kernelUDPTXSequenceBatch, single *kernelUDPTXSequenceBatch) error {
	if len(pendingByFlow) == 0 {
		return manager.flushKernelUDPTXSequenceBatchLocked(single)
	}
	for _, pending := range pendingByFlow {
		if err := manager.flushKernelUDPTXSequenceBatchLocked(pending); err != nil {
			return err
		}
	}
	return nil
}

func (manager *Manager) flushKernelUDPTXSequenceBatchLocked(batch *kernelUDPTXSequenceBatch) error {
	if batch == nil || !batch.mapDirty || !batch.haveValue || manager.kernelUDPTXFlowMap == nil {
		return nil
	}
	if batch.value.Sequence < batch.reservedHigh {
		batch.value.Sequence = batch.reservedHigh
	}
	if err := manager.kernelUDPTXFlowMap.Update(batch.flowID, batch.value, cebpf.UpdateAny); err != nil {
		return fmt.Errorf("reserve kernel_udp TC TX flow %d sequence %d: %w", batch.flowID, batch.value.Sequence, err)
	}
	return nil
}

func (manager *Manager) rememberKernelUDPTXDirectSequencesLocked() error {
	if manager.kernelUDPTXFlowMap == nil {
		return nil
	}
	if manager.kernelUDPTXDirectSequences == nil {
		manager.kernelUDPTXDirectSequences = make(map[uint64]uint64)
	}
	var flowID uint64
	var value kernelUDPTXFlowValue
	iterator := manager.kernelUDPTXFlowMap.Iterate()
	for iterator.Next(&flowID, &value) {
		if value.Sequence > manager.kernelUDPTXDirectSequences[flowID] {
			manager.kernelUDPTXDirectSequences[flowID] = value.Sequence
		}
	}
	if err := iterator.Err(); err != nil {
		return fmt.Errorf("remember kernel_udp TC TX direct sequences: %w", err)
	}
	return nil
}

func (manager *Manager) syncKernelUDPRXDirectConfigLocked() error {
	enabled := manager.kernelUDPRXDirectConfigEnabledLocked()
	kernelDatapathRXXDPPass := kernelDatapathRXXDPPassEnabledForSpec(manager.spec)
	tcPlaintextDirect := manager.kernelUDPRXPlaintextPassToTCLocked(enabled) || (enabled && kernelDatapathRXXDPPass)
	xdpEnabled := enabled && manager.kernelUDPXDPRXDirectEnabled && !kernelDatapathRXXDPPass
	secureEnabled := enabled && manager.kernelUDPRXSecureDirectConfigEnabledLocked()
	options := experimentalTCPBPFConfigOptions{
		ForcePassOpened:         tcPlaintextDirect && manager.kernelUDPXDPRXDirectVethFallback,
		XDPRXSecureDirect:       kernelUDPXDPRXSecureDirectEnabled() && !manager.kernelUDPXDPRXSecureDirectVethFallback,
		XDPFallbackPass:         kernelDatapathRXXDPPass,
		XDPRXTrustInnerChecksum: kernelUDPXDPRXDirectTrustInnerChecksumEnabled(),
	}
	if manager.expTCPFastPath != nil {
		if err := manager.expTCPFastPath.SetKernelUDPRXDirectWithOptions(tcPlaintextDirect, xdpEnabled, secureEnabled, options); err != nil {
			return fmt.Errorf("sync kernel_udp XDP TC RX direct config: %w", err)
		}
	}
	if manager.kernelUDPXDPRXDirectObject != nil {
		if err := manager.syncStandaloneKernelUDPRXXDPDirectConfigLocked(); err != nil {
			return err
		}
	}
	return nil
}

func (manager *Manager) kernelUDPRXPlaintextPassToTCLocked(enabled bool) bool {
	if !enabled {
		return false
	}
	if kernelDatapathRXXDPPassEnabledForSpec(manager.spec) {
		return true
	}
	if manager.kernelUDPXDPRXDirectVethFallback {
		return true
	}
	if kernelUDPTXDirectSafeModeEnabled() {
		return true
	}
	if experimentalTCPTXDirectEnabledForSpec(manager.spec) {
		return true
	}
	return kernelUDPTXDirectOnlyEnabled(manager.spec)
}

func (manager *Manager) kernelUDPRXDirectConfigEnabledLocked() bool {
	if !manager.kernelUDPRXDirectAttached || kernelUDPRXDirectDisabledForSpec(manager.spec) ||
		manager.snapshot.NAT != nil && manager.snapshot.NAT.Enabled {
		return false
	}
	return true
}

func (manager *Manager) kernelUDPRXSecureDirectConfigEnabledLocked() bool {
	if !manager.kernelUDPRXSecureDirectAttached || !manager.kernelUDPRXSecureDirectRequestedLocked() ||
		manager.snapshot.NAT != nil && manager.snapshot.NAT.Enabled {
		return false
	}
	return true
}

func kernelUDPTXInlineRouteFlowAllowed(routeFlows []kernelUDPTXRouteFlow, routeFlowCount int) bool {
	return kernelUDPTXInlineRouteFlowAllowedForSpec(dataplane.AttachSpec{}, routeFlows, routeFlowCount)
}

func kernelUDPTXInlineRouteFlowAllowedForSpec(spec dataplane.AttachSpec, routeFlows []kernelUDPTXRouteFlow, routeFlowCount int) bool {
	if routeFlowCount <= 0 || routeFlowCount > kernelUDPTXRouteMaxFlows || len(routeFlows) < routeFlowCount {
		return false
	}
	if !kernelUDPTXDirectSkipPlainSequenceEnabled() {
		return false
	}
	allowExperimentalTCP := kernelUDPTXInlineExperimentalTCPEnabledForSpec(spec)
	for index := 0; index < routeFlowCount; index++ {
		if routeFlows[index].experimentalTCP && !allowExperimentalTCP {
			return false
		}
	}
	return true
}

func kernelUDPTXInlineRouteFlowValueAllowed(value kernelUDPTXFlowValue) bool {
	return kernelUDPTXInlineRouteFlowValueAllowedForSpec(dataplane.AttachSpec{}, value)
}

func kernelUDPTXInlineRouteFlowValueAllowedForSpec(spec dataplane.AttachSpec, value kernelUDPTXFlowValue) bool {
	if value.Flags&kernelUDPTXFlowFlagSecure != 0 {
		return false
	}
	if value.Flags&kernelUDPTXFlowFlagExperimentalTCP != 0 && !kernelUDPTXInlineExperimentalTCPEnabledForSpec(spec) {
		return false
	}
	return true
}

func kernelUDPTXInlineExperimentalTCPEnabled() bool {
	return kernelUDPTXInlineExperimentalTCPEnabledForSpec(dataplane.AttachSpec{})
}

func kernelUDPTXInlineExperimentalTCPEnabledForSpec(spec dataplane.AttachSpec) bool {
	if envFalsey("TRUSTIX_KERNEL_UDP_TC_TX_INLINE_EXPERIMENTAL_TCP") {
		return false
	}
	if envTruthy("TRUSTIX_KERNEL_UDP_TC_TX_INLINE_EXPERIMENTAL_TCP") {
		return true
	}
	return experimentalTCPTXDirectPushRouteTCPHeaderKfuncRequestedForSpec(spec) ||
		experimentalTCPTXDirectFinalizeFlowTCPHeaderKfuncRequested()
}

func (manager *Manager) kernelUDPTXDirectFlowFlagsLocked(route routing.Route, routeFlow kernelUDPTXRouteFlow, secureDirect bool) uint32 {
	var flags uint32
	if routeFlow.experimentalTCP {
		flags |= kernelUDPTXFlowFlagExperimentalTCP
		if experimentalTCPSkipOuterTCPChecksum() {
			flags |= kernelUDPTXFlowFlagSkipOuterTCPChecksum
		}
	}
	secure := manager.kernelUDPTXRouteFlowSecureAllowedLocked(route, routeFlow, secureDirect)
	if !secure {
		return flags
	}
	flags |= kernelUDPTXFlowFlagSecure
	if kernelUDPTXSecureDirectTrustInnerChecksumsForSpec(manager.spec) {
		flags |= kernelUDPTXFlowFlagTrustInnerChecksum
	}
	if experimentalTCPHotPathStats() {
		flags |= kernelUDPTXFlowFlagHotStats
	}
	manager.kernelCryptoTCSealConfiguredFlows++
	manager.kernelUDPTXDirectSync.SecureFlowsWritten++
	return flags
}

type kernelUDPTXRouteFlow struct {
	id              uint64
	flow            dataplane.KernelUDPFlow
	expTCPFlow      dataplane.ExperimentalTCPFlow
	packet          kerneludp.UDPPacket
	expTCPPacket    experimentaltcp.TCPPacket
	experimentalTCP bool
}

func (routeFlow kernelUDPTXRouteFlow) endpoint() core.EndpointID {
	if routeFlow.experimentalTCP {
		return routeFlow.expTCPFlow.Endpoint
	}
	return routeFlow.flow.Endpoint
}

func kernelUDPTXRouteSnapshotFromValue(key routeKey, value kernelUDPTXRouteValue) dataplane.KernelUDPTXRouteSnapshot {
	address := netip.AddrFrom4(key.Addr)
	flowIDs := kernelUDPTXRouteValueFlowIDs(value)
	activeCount := 0
	if len(flowIDs) > 0 {
		activeCount = int(value.FlowMask) + 1
		if activeCount <= 0 || activeCount > len(flowIDs) {
			activeCount = len(flowIDs)
		}
	}
	item := dataplane.KernelUDPTXRouteSnapshot{
		Prefix:          netip.PrefixFrom(address, int(key.PrefixLen)).String(),
		PrefixLen:       key.PrefixLen,
		Address:         address.String(),
		FlowID:          value.FlowID,
		FlowIDs:         flowIDs,
		ActiveFlowCount: activeCount,
		FlowMask:        value.FlowMask,
		Flags:           value.Flags,
		DirectOnly:      value.Flags&kernelUDPTXRouteFlagDirectOnly != 0,
		Inline:          value.Flags&kernelUDPTXRouteFlagInlineFlow != 0,
		Bypass:          value.Flags&kernelUDPTXRouteFlagBypass != 0,
	}
	if item.Inline {
		item.InlineFlows = kernelUDPTXRouteValueInlineFlowSnapshots(value, activeCount)
	}
	return item
}

func kernelUDPTXRouteValueFlowIDs(value kernelUDPTXRouteValue) []uint64 {
	ids := [kernelUDPTXRouteMaxFlows]uint64{
		value.FlowID1,
		value.FlowID2,
		value.FlowID3,
		value.FlowID4,
		value.FlowID5,
		value.FlowID6,
		value.FlowID7,
		value.FlowID8,
	}
	out := make([]uint64, 0, kernelUDPTXRouteMaxFlows)
	for _, id := range ids {
		if id != 0 {
			out = append(out, id)
		}
	}
	return out
}

func kernelUDPTXRouteValueInlineFlowSnapshots(value kernelUDPTXRouteValue, activeCount int) []dataplane.KernelUDPTXFlowSnapshot {
	if activeCount <= 0 {
		return nil
	}
	ids := [kernelUDPTXRouteMaxFlows]uint64{
		value.FlowID1,
		value.FlowID2,
		value.FlowID3,
		value.FlowID4,
		value.FlowID5,
		value.FlowID6,
		value.FlowID7,
		value.FlowID8,
	}
	values := [kernelUDPTXRouteMaxFlows]kernelUDPTXFlowValue{
		value.Inline1,
		value.Inline2,
		value.Inline3,
		value.Inline4,
		value.Inline5,
		value.Inline6,
		value.Inline7,
		value.Inline8,
	}
	if activeCount > kernelUDPTXRouteMaxFlows {
		activeCount = kernelUDPTXRouteMaxFlows
	}
	out := make([]dataplane.KernelUDPTXFlowSnapshot, 0, activeCount)
	for index := 0; index < activeCount; index++ {
		if ids[index] == 0 {
			continue
		}
		out = append(out, kernelUDPTXFlowSnapshotFromValue(ids[index], index+1, true, values[index]))
	}
	return out
}

func kernelUDPTXFlowSnapshotFromValue(flowID uint64, slot int, inline bool, value kernelUDPTXFlowValue) dataplane.KernelUDPTXFlowSnapshot {
	flags := value.Flags
	return dataplane.KernelUDPTXFlowSnapshot{
		FlowID:               flowID,
		Slot:                 slot,
		Inline:               inline,
		Sequence:             value.Sequence,
		SourceIP:             netip.AddrFrom4(value.SourceIP).String(),
		DestinationIP:        netip.AddrFrom4(value.DestinationIP).String(),
		SourcePort:           htons(value.SourcePort),
		DestinationPort:      htons(value.DestinationPort),
		Ifindex:              value.Ifindex,
		DestinationMAC:       kernelUDPTXDebugMACString(value.DestinationMAC0, value.DestinationMAC1),
		SourceMAC:            kernelUDPTXDebugMACString(value.SourceMAC0, value.SourceMAC1),
		MTU:                  value.MTU,
		Flags:                flags,
		Secure:               flags&kernelUDPTXFlowFlagSecure != 0,
		TrustInnerChecksum:   flags&kernelUDPTXFlowFlagTrustInnerChecksum != 0,
		HotStats:             flags&kernelUDPTXFlowFlagHotStats != 0,
		ExperimentalTCP:      flags&kernelUDPTXFlowFlagExperimentalTCP != 0,
		SkipOuterTCPChecksum: flags&kernelUDPTXFlowFlagSkipOuterTCPChecksum != 0,
		IPv4ChecksumUDPBase:  value.IPv4ChecksumUDP,
		IPv4ChecksumTCPBase:  value.IPv4ChecksumTCP,
	}
}

func kernelUDPTXDebugMACString(mac0 uint32, mac1 uint16) string {
	var mac [6]byte
	binary.LittleEndian.PutUint32(mac[0:4], mac0)
	binary.LittleEndian.PutUint16(mac[4:6], mac1)
	return net.HardwareAddr(mac[:]).String()
}

func appendKernelUDPTXRouteFlow(routeValue *kernelUDPTXRouteValue, flowID uint64, index int) bool {
	if routeValue == nil || flowID == 0 || index < 0 || index >= kernelUDPTXRouteMaxFlows {
		return false
	}
	switch index {
	case 0:
		routeValue.FlowID1 = flowID
	case 1:
		routeValue.FlowID2 = flowID
	case 2:
		routeValue.FlowID3 = flowID
	case 3:
		routeValue.FlowID4 = flowID
	case 4:
		routeValue.FlowID5 = flowID
	case 5:
		routeValue.FlowID6 = flowID
	case 6:
		routeValue.FlowID7 = flowID
	case 7:
		routeValue.FlowID8 = flowID
	default:
		return false
	}
	return true
}

func appendKernelUDPTXRouteInlineFlows(routeValue *kernelUDPTXRouteValue, flowValues map[uint64]kernelUDPTXFlowValue, activeCount int) bool {
	return appendKernelUDPTXRouteInlineFlowsForSpec(dataplane.AttachSpec{}, routeValue, flowValues, activeCount)
}

func appendKernelUDPTXRouteInlineFlowsForSpec(spec dataplane.AttachSpec, routeValue *kernelUDPTXRouteValue, flowValues map[uint64]kernelUDPTXFlowValue, activeCount int) bool {
	if routeValue == nil || activeCount <= 0 || activeCount > kernelUDPTXRouteMaxFlows {
		return false
	}
	ids := [kernelUDPTXRouteMaxFlows]uint64{
		routeValue.FlowID1,
		routeValue.FlowID2,
		routeValue.FlowID3,
		routeValue.FlowID4,
		routeValue.FlowID5,
		routeValue.FlowID6,
		routeValue.FlowID7,
		routeValue.FlowID8,
	}
	values := [kernelUDPTXRouteMaxFlows]kernelUDPTXFlowValue{}
	for index := 0; index < activeCount; index++ {
		flowID := ids[index]
		if flowID == 0 {
			return false
		}
		value, ok := flowValues[flowID]
		if !ok || !kernelUDPTXInlineRouteFlowValueAllowedForSpec(spec, value) {
			return false
		}
		values[index] = value
	}
	routeValue.Inline1 = values[0]
	routeValue.Inline2 = values[1]
	routeValue.Inline3 = values[2]
	routeValue.Inline4 = values[3]
	routeValue.Inline5 = values[4]
	routeValue.Inline6 = values[5]
	routeValue.Inline7 = values[6]
	routeValue.Inline8 = values[7]
	return true
}

func kernelUDPTXRouteFlowPowerOfTwoLimit(count int, maxFlows int) int {
	if count <= 0 || maxFlows <= 0 {
		return 0
	}
	if maxFlows > kernelUDPTXRouteMaxFlows {
		maxFlows = kernelUDPTXRouteMaxFlows
	}
	if count > maxFlows {
		count = maxFlows
	}
	limit := 1
	for limit<<1 <= count {
		limit <<= 1
	}
	return limit
}

func (manager *Manager) kernelUDPTXDirectFlowsForRouteLocked(route routing.Route, force bool, secureDirect bool, maxFlows int) []kernelUDPTXRouteFlow {
	if route.NextHop == "" {
		return nil
	}
	expTCPOnly := kernelUDPTXDirectExperimentalTCPOnlyEnabledForSpec(manager.spec)
	kernelUDPOnly := !expTCPOnly && kernelUDPTXDirectKernelUDPOnlyEnabledForSpec(manager.spec)
	totalFlows := 0
	if expTCPOnly || !kernelUDPOnly {
		totalFlows += len(manager.expTCPFlows)
	}
	if !expTCPOnly {
		totalFlows += len(manager.kernelUDPFlows)
	}
	candidates := make([]kernelUDPTXRouteFlow, 0, min(totalFlows, maxFlows))
	if !expTCPOnly {
		manager.collectKernelUDPTXDirectFlowsForRouteLocked(&candidates, route, force, secureDirect)
	}
	if !kernelUDPOnly {
		manager.collectExperimentalTCPTXDirectFlowsForRouteLocked(&candidates, route, force, secureDirect)
	}
	if len(candidates) == 0 {
		return nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].id < candidates[j].id
	})
	if secureDirect {
		candidates = manager.filterKernelUDPTXSecureDirectFlowsLocked(route, candidates, secureDirect)
		if len(candidates) == 0 {
			return nil
		}
	}
	expTCPRouteMultiFlow := !secureDirect && experimentalTCPTXPlaintextDirectRouteMultiFlowEnabled()
	if expTCPRouteMultiFlow {
		candidates = manager.filterExperimentalTCPTXPlaintextDirectListenerSourcedFlowsLocked(route, candidates)
		if len(candidates) == 0 {
			return nil
		}
	}
	if flow, ok := manager.selectExperimentalTCPTXPlaintextDirectFlowLocked(route, candidates, secureDirect); ok {
		return []kernelUDPTXRouteFlow{flow}
	}
	if !secureDirect {
		candidates = manager.filterKernelUDPTXPlaintextDirectListenerSourcedFlowsLocked(route, candidates)
		if expTCPRouteMultiFlow {
			candidates = manager.filterExperimentalTCPTXPlaintextDirectListenerSourcedFlowsLocked(route, candidates)
		}
		candidates = manager.filterKernelUDPTXDirectTransportLocked(route, candidates, secureDirect)
		if expTCPRouteMultiFlow {
			candidates = manager.filterKernelUDPTXPlaintextDirectListenerSourcedFlowsLocked(route, candidates)
			candidates = manager.filterExperimentalTCPTXPlaintextDirectListenerSourcedFlowsLocked(route, candidates)
		}
	}
	limit := kernelUDPTXRouteFlowPowerOfTwoLimit(len(candidates), maxFlows)
	if limit < len(candidates) {
		candidates = candidates[:limit]
	}
	return candidates
}

func (manager *Manager) filterKernelUDPTXSecureDirectFlowsLocked(route routing.Route, candidates []kernelUDPTXRouteFlow, secureDirect bool) []kernelUDPTXRouteFlow {
	expTCPListenPort, hasExpTCPListenPort := manager.localExperimentalTCPListenPortLocked()
	kernelUDPListenPort, hasKernelUDPListenPort := manager.localKernelUDPListenPortLocked()
	inboundReversePreferred := make([]kernelUDPTXRouteFlow, 0, len(candidates))
	filtered := make([]kernelUDPTXRouteFlow, 0, len(candidates))
	listenerSourcedFallbacks := make([]kernelUDPTXRouteFlow, 0, len(candidates))
	for _, candidate := range candidates {
		if !manager.kernelUDPTXRouteFlowSecureAllowedLocked(route, candidate, secureDirect) {
			continue
		}
		if kernelUDPTXRouteFlowInboundReverse(candidate) {
			inboundReversePreferred = append(inboundReversePreferred, candidate)
			continue
		}
		if candidate.experimentalTCP && hasExpTCPListenPort && candidate.expTCPPacket.SourcePort == expTCPListenPort {
			listenerSourcedFallbacks = append(listenerSourcedFallbacks, candidate)
			continue
		}
		if !candidate.experimentalTCP && hasKernelUDPListenPort && candidate.packet.SourcePort == kernelUDPListenPort {
			if adjusted, ok := manager.kernelUDPTXRouteFlowWithEndpointAddressLocked(route, candidate); ok {
				candidate = adjusted
			}
			listenerSourcedFallbacks = append(listenerSourcedFallbacks, candidate)
			continue
		}
		filtered = append(filtered, candidate)
	}
	if len(inboundReversePreferred) > 0 {
		return manager.filterKernelUDPTXDirectTransportLocked(route, inboundReversePreferred, secureDirect)
	}
	if len(filtered) > 0 {
		return manager.filterKernelUDPTXDirectTransportLocked(route, filtered, secureDirect)
	}
	if len(listenerSourcedFallbacks) > 0 {
		return manager.filterKernelUDPTXDirectTransportLocked(route, listenerSourcedFallbacks, secureDirect)
	}
	return nil
}

func kernelUDPTXRouteFlowInboundReverse(routeFlow kernelUDPTXRouteFlow) bool {
	return !routeFlow.experimentalTCP && routeFlow.flow.Role == dataplane.KernelUDPFlowRoleInboundReverse
}

func (manager *Manager) filterKernelUDPTXDirectTransportLocked(route routing.Route, candidates []kernelUDPTXRouteFlow, secureDirect bool) []kernelUDPTXRouteFlow {
	if len(candidates) < 2 || route.Endpoint != "" {
		return candidates
	}
	selected, ok := manager.preferredKernelUDPTXDirectEndpointForRouteLocked(route, secureDirect)
	if ok {
		filtered := filterKernelUDPTXRouteFlowsByEndpoint(candidates, selected.ID)
		if len(filtered) > 0 {
			return filtered
		}
	}
	return filterKernelUDPTXRouteFlowsToSingleTransport(candidates)
}

func (manager *Manager) preferredKernelUDPTXDirectEndpointForRouteLocked(route routing.Route, secureDirect bool) (dataplane.EndpointMetadata, bool) {
	var selected dataplane.EndpointMetadata
	selectedPriority := 0
	for _, endpoint := range manager.snapshot.Endpoints {
		if !endpoint.Enabled || endpoint.Peer != route.NextHop {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(endpoint.Transport)) {
		case "udp", "experimental_tcp":
		default:
			continue
		}
		if !manager.kernelUDPTXRouteEndpointAllowedLocked(route, endpoint, secureDirect) {
			continue
		}
		priority := endpoint.Priority + manager.localKernelUDPTXDirectEndpointPriorityLocked(endpoint.Transport)
		if selected.ID == "" ||
			priority > selectedPriority ||
			priority == selectedPriority && endpoint.ID < selected.ID {
			selected = endpoint
			selectedPriority = priority
		}
	}
	return selected, selected.ID != "" && selectedPriority > 0
}

func (manager *Manager) localKernelUDPTXDirectEndpointPriorityLocked(transportName string) int {
	transportName = strings.ToLower(strings.TrimSpace(transportName))
	localIX := manager.snapshotLocalIXLocked()
	best := 0
	for _, endpoint := range manager.snapshot.Endpoints {
		if !endpoint.Enabled || !snapshotEndpointIsLocal(localIX, endpoint) {
			continue
		}
		if strings.ToLower(strings.TrimSpace(endpoint.Transport)) != transportName {
			continue
		}
		if endpoint.Priority > best {
			best = endpoint.Priority
		}
	}
	return best
}

func (manager *Manager) kernelUDPTXRouteEndpointAllowedLocked(route routing.Route, endpoint dataplane.EndpointMetadata, secureDirect bool) bool {
	switch strings.ToLower(strings.TrimSpace(endpoint.Transport)) {
	case "udp":
		if !secureDirect {
			return manager.kernelUDPTXDirectPlaintextAllowed(route, dataplane.KernelUDPFlow{
				Peer:     endpoint.Peer,
				Endpoint: endpoint.ID,
			})
		}
		return manager.kernelUDPTXDirectSecureAllowed(route, dataplane.KernelUDPFlow{
			Peer:            endpoint.Peer,
			Endpoint:        endpoint.ID,
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		}, true)
	case "experimental_tcp":
		if !secureDirect {
			return manager.experimentalTCPTXDirectPlaintextAllowed(route, dataplane.ExperimentalTCPFlow{
				Peer:            endpoint.Peer,
				Endpoint:        endpoint.ID,
				CryptoPlacement: dataplane.CryptoPlacementUserspace,
			})
		}
		return manager.experimentalTCPTXDirectSecureAllowed(route, dataplane.ExperimentalTCPFlow{
			Peer:            endpoint.Peer,
			Endpoint:        endpoint.ID,
			CryptoPlacement: dataplane.CryptoPlacementKernel,
		}, true)
	default:
		return false
	}
}

func filterKernelUDPTXRouteFlowsByEndpoint(candidates []kernelUDPTXRouteFlow, endpoint core.EndpointID) []kernelUDPTXRouteFlow {
	if endpoint == "" {
		return candidates
	}
	out := make([]kernelUDPTXRouteFlow, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.endpoint() == endpoint {
			out = append(out, candidate)
		}
	}
	return out
}

func filterKernelUDPTXRouteFlowsToSingleTransport(candidates []kernelUDPTXRouteFlow) []kernelUDPTXRouteFlow {
	if len(candidates) < 2 {
		return candidates
	}
	keepExperimentalTCP := candidates[0].experimentalTCP
	for _, candidate := range candidates[1:] {
		if candidate.experimentalTCP != keepExperimentalTCP {
			out := make([]kernelUDPTXRouteFlow, 0, len(candidates))
			for _, item := range candidates {
				if item.experimentalTCP == keepExperimentalTCP {
					out = append(out, item)
				}
			}
			return out
		}
	}
	return candidates
}

func (manager *Manager) kernelUDPTXRouteFlowWithEndpointAddressLocked(route routing.Route, routeFlow kernelUDPTXRouteFlow) (kernelUDPTXRouteFlow, bool) {
	if route.Endpoint == "" {
		return kernelUDPTXRouteFlow{}, false
	}
	for _, endpoint := range manager.snapshot.Endpoints {
		if !endpoint.Enabled || endpoint.Transport != "udp" || endpoint.Peer != route.NextHop || endpoint.ID != route.Endpoint {
			continue
		}
		address := strings.TrimSpace(endpoint.Address)
		if address == "" {
			return kernelUDPTXRouteFlow{}, false
		}
		remoteIP, remotePort, err := resolveExperimentalTCPAddress(address)
		if err != nil || !remoteIP.Is4() || remotePort == 0 {
			return kernelUDPTXRouteFlow{}, false
		}
		if routeFlow.packet.SourcePort == 0 || !routeFlow.packet.SourceIP.Is4() {
			return kernelUDPTXRouteFlow{}, false
		}
		routeFlow.packet.DestinationIP = remoteIP
		routeFlow.packet.DestinationPort = remotePort
		return routeFlow, true
	}
	return kernelUDPTXRouteFlow{}, false
}

func (manager *Manager) selectExperimentalTCPTXPlaintextDirectFlowLocked(route routing.Route, candidates []kernelUDPTXRouteFlow, secureDirect bool) (kernelUDPTXRouteFlow, bool) {
	expTCPOnly := false
	for _, candidate := range candidates {
		if !candidate.experimentalTCP {
			return kernelUDPTXRouteFlow{}, false
		}
		expTCPOnly = true
	}
	if !expTCPOnly {
		return kernelUDPTXRouteFlow{}, false
	}
	if !secureDirect && experimentalTCPTXPlaintextDirectRouteMultiFlowEnabled() {
		return kernelUDPTXRouteFlow{}, false
	}
	expTCPListenPort, hasExpTCPListenPort := manager.localExperimentalTCPListenPortLocked()
	var listenerSourcedFallback kernelUDPTXRouteFlow
	var hasListenerSourcedFallback bool
	preferListenerSourced := experimentalTCPTXPlaintextDirectPreferListenerSourcedEnabled()
	for _, candidate := range candidates {
		if !manager.experimentalTCPTXDirectPlaintextAllowed(route, candidate.expTCPFlow) {
			continue
		}
		if candidate.experimentalTCP && hasExpTCPListenPort && candidate.expTCPPacket.SourcePort == expTCPListenPort {
			if preferListenerSourced {
				return candidate, true
			}
			if !hasListenerSourcedFallback {
				listenerSourcedFallback = candidate
				hasListenerSourcedFallback = true
			}
			continue
		}
		return candidate, true
	}
	if hasListenerSourcedFallback {
		return listenerSourcedFallback, true
	}
	return kernelUDPTXRouteFlow{}, false
}

func (manager *Manager) filterExperimentalTCPTXPlaintextDirectListenerSourcedFlowsLocked(route routing.Route, candidates []kernelUDPTXRouteFlow) []kernelUDPTXRouteFlow {
	if len(candidates) < 2 {
		return candidates
	}
	expTCPOnly := false
	for _, candidate := range candidates {
		if !candidate.experimentalTCP {
			return candidates
		}
		expTCPOnly = true
	}
	if !expTCPOnly {
		return candidates
	}
	expTCPListenPort, hasExpTCPListenPort := manager.localExperimentalTCPListenPortLocked()
	if !hasExpTCPListenPort {
		return candidates
	}
	if experimentalTCPTXPlaintextDirectPreferListenerSourcedEnabled() {
		filtered := make([]kernelUDPTXRouteFlow, 0, len(candidates))
		for _, candidate := range candidates {
			if !manager.experimentalTCPTXDirectPlaintextAllowed(route, candidate.expTCPFlow) {
				filtered = append(filtered, candidate)
				continue
			}
			if candidate.expTCPPacket.SourcePort == expTCPListenPort {
				filtered = append(filtered, candidate)
			}
		}
		if len(filtered) > 0 {
			return filtered
		}
		return candidates
	}
	filtered := make([]kernelUDPTXRouteFlow, 0, len(candidates))
	var listenerSourcedFallback kernelUDPTXRouteFlow
	var hasListenerSourcedFallback bool
	for _, candidate := range candidates {
		if !manager.experimentalTCPTXDirectPlaintextAllowed(route, candidate.expTCPFlow) {
			filtered = append(filtered, candidate)
			continue
		}
		if candidate.expTCPPacket.SourcePort == expTCPListenPort {
			if !hasListenerSourcedFallback {
				listenerSourcedFallback = candidate
				hasListenerSourcedFallback = true
			}
			continue
		}
		filtered = append(filtered, candidate)
	}
	if len(filtered) > 0 {
		return filtered
	}
	if hasListenerSourcedFallback {
		return []kernelUDPTXRouteFlow{listenerSourcedFallback}
	}
	return candidates
}

func (manager *Manager) filterKernelUDPTXPlaintextDirectListenerSourcedFlowsLocked(route routing.Route, candidates []kernelUDPTXRouteFlow) []kernelUDPTXRouteFlow {
	if len(candidates) < 2 {
		return candidates
	}
	kernelUDPOnly := false
	for _, candidate := range candidates {
		if candidate.experimentalTCP {
			return candidates
		}
		kernelUDPOnly = true
	}
	if !kernelUDPOnly {
		return candidates
	}
	kernelUDPListenPort, hasKernelUDPListenPort := manager.localKernelUDPListenPortLocked()
	if !hasKernelUDPListenPort {
		return candidates
	}
	filtered := make([]kernelUDPTXRouteFlow, 0, len(candidates))
	var listenerSourcedFallback kernelUDPTXRouteFlow
	var hasListenerSourcedFallback bool
	for _, candidate := range candidates {
		if !manager.kernelUDPTXDirectPlaintextAllowed(route, candidate.flow) {
			filtered = append(filtered, candidate)
			continue
		}
		if candidate.packet.SourcePort == kernelUDPListenPort {
			if !hasListenerSourcedFallback {
				listenerSourcedFallback = candidate
				hasListenerSourcedFallback = true
			}
			continue
		}
		filtered = append(filtered, candidate)
	}
	if len(filtered) > 0 {
		return filtered
	}
	if hasListenerSourcedFallback {
		return []kernelUDPTXRouteFlow{listenerSourcedFallback}
	}
	return candidates
}

func (manager *Manager) kernelUDPTXRouteFlowSecureAllowedLocked(route routing.Route, routeFlow kernelUDPTXRouteFlow, secureDirect bool) bool {
	if routeFlow.experimentalTCP {
		return manager.experimentalTCPTXDirectSecureAllowed(route, routeFlow.expTCPFlow, secureDirect)
	}
	return manager.kernelUDPTXDirectSecureAllowed(route, routeFlow.flow, secureDirect)
}

func (manager *Manager) collectKernelUDPTXDirectFlowsForRouteLocked(candidates *[]kernelUDPTXRouteFlow, route routing.Route, force bool, secureDirect bool) {
	if candidates == nil {
		return
	}
	for flowID, flow := range manager.kernelUDPFlows {
		manager.kernelUDPTXDirectSync.FlowsScanned++
		if flowID == 0 {
			manager.kernelUDPTXDirectSync.FlowsSkippedZeroID++
			continue
		}
		if flow.Peer == "" || flow.Peer != route.NextHop {
			continue
		}
		manager.kernelUDPTXDirectSync.FlowsPeerMatches++
		if route.Endpoint != "" && flow.Endpoint != route.Endpoint {
			continue
		}
		manager.kernelUDPTXDirectSync.FlowsEndpointMatches++
		if !force && !manager.kernelUDPTXDirectPlaintextAllowed(route, flow) && !manager.kernelUDPTXDirectSecureAllowed(route, flow, secureDirect) {
			manager.kernelUDPTXDirectSync.FlowsSecurityBlocked++
			continue
		}
		manager.kernelUDPTXDirectSync.FlowsSecurityAllowed++
		packet, _, err := manager.prepareKernelUDPPacketLocked(flowID)
		if err != nil {
			manager.kernelUDPTXDirectSync.PreparePacketErrors++
			continue
		}
		if latest, ok := manager.kernelUDPFlows[flowID]; ok {
			flow = latest
		}
		*candidates = append(*candidates, kernelUDPTXRouteFlow{id: flowID, flow: flow, packet: packet})
	}
}

func (manager *Manager) collectExperimentalTCPTXDirectFlowsForRouteLocked(candidates *[]kernelUDPTXRouteFlow, route routing.Route, force bool, secureDirect bool) {
	if candidates == nil || !experimentalTCPTXDirectEnabledForSpec(manager.spec) {
		return
	}
	for flowID, flow := range manager.expTCPFlows {
		manager.kernelUDPTXDirectSync.FlowsScanned++
		if flowID == 0 {
			manager.kernelUDPTXDirectSync.FlowsSkippedZeroID++
			continue
		}
		if flow.Peer == "" || flow.Peer != route.NextHop {
			continue
		}
		manager.kernelUDPTXDirectSync.FlowsPeerMatches++
		if route.Endpoint != "" && flow.Endpoint != route.Endpoint {
			continue
		}
		manager.kernelUDPTXDirectSync.FlowsEndpointMatches++
		if flow.RemoteAddress == "" {
			manager.kernelUDPTXDirectSync.PreparePacketErrors++
			continue
		}
		if !force && !manager.experimentalTCPTXDirectPlaintextAllowed(route, flow) && !manager.experimentalTCPTXDirectSecureAllowed(route, flow, secureDirect) {
			manager.kernelUDPTXDirectSync.FlowsSecurityBlocked++
			continue
		}
		manager.kernelUDPTXDirectSync.FlowsSecurityAllowed++
		packet, _, err := manager.prepareExperimentalTCPPacketLocked(flowID, 0)
		if err != nil {
			manager.kernelUDPTXDirectSync.PreparePacketErrors++
			continue
		}
		if latest, ok := manager.expTCPFlows[flowID]; ok {
			flow = latest
		}
		*candidates = append(*candidates, kernelUDPTXRouteFlow{
			id:              flowID,
			expTCPFlow:      flow,
			expTCPPacket:    packet,
			experimentalTCP: true,
		})
	}
}

func (manager *Manager) kernelUDPTXDirectFlowForRouteLocked(route routing.Route, force bool, secureDirect bool) (uint64, dataplane.KernelUDPFlow, kerneludp.UDPPacket, bool) {
	flows := manager.kernelUDPTXDirectFlowsForRouteLocked(route, force, secureDirect, 1)
	if len(flows) == 0 {
		return 0, dataplane.KernelUDPFlow{}, kerneludp.UDPPacket{}, false
	}
	flow := flows[0]
	return flow.id, flow.flow, flow.packet, true
}

func (manager *Manager) kernelUDPTXDirectPlaintextAllowed(route routing.Route, flow dataplane.KernelUDPFlow) bool {
	for _, endpoint := range manager.snapshot.Endpoints {
		if endpoint.Transport != "udp" || !endpoint.Enabled {
			continue
		}
		peer := flow.Peer
		if peer == "" {
			peer = route.NextHop
		}
		if endpoint.Peer != peer {
			continue
		}
		if route.Endpoint != "" && endpoint.ID != route.Endpoint {
			continue
		}
		return kernelUDPTXEndpointEncryptionPlaintext(endpoint.Security.Encryption)
	}
	return false
}

func (manager *Manager) experimentalTCPTXDirectPlaintextAllowed(route routing.Route, flow dataplane.ExperimentalTCPFlow) bool {
	if flow.CryptoPlacement == dataplane.CryptoPlacementKernel {
		return false
	}
	for _, endpoint := range manager.snapshot.Endpoints {
		if endpoint.Transport != "experimental_tcp" || !endpoint.Enabled {
			continue
		}
		peer := flow.Peer
		if peer == "" {
			peer = route.NextHop
		}
		if endpoint.Peer != peer {
			continue
		}
		if route.Endpoint != "" && endpoint.ID != route.Endpoint {
			continue
		}
		return kernelUDPTXEndpointEncryptionPlaintext(endpoint.Security.Encryption)
	}
	return false
}

func (manager *Manager) experimentalTCPTXDirectSecureAllowed(route routing.Route, flow dataplane.ExperimentalTCPFlow, secureDirect bool) bool {
	if !secureDirect || flow.CryptoPlacement != dataplane.CryptoPlacementKernel {
		return false
	}
	if kernelUDPTXDirectManagementVIPRoute(route) {
		return false
	}
	for _, endpoint := range manager.snapshot.Endpoints {
		if endpoint.Transport != "experimental_tcp" || !endpoint.Enabled {
			continue
		}
		peer := flow.Peer
		if peer == "" {
			peer = route.NextHop
		}
		if endpoint.Peer != peer {
			continue
		}
		if route.Endpoint != "" && endpoint.ID != route.Endpoint {
			continue
		}
		return kernelUDPTXEndpointEncryptionFullySecure(endpoint.Security.Encryption)
	}
	return false
}

func (manager *Manager) kernelUDPTXDirectSecureAllowed(route routing.Route, flow dataplane.KernelUDPFlow, secureDirect bool) bool {
	if !secureDirect || flow.CryptoPlacement != dataplane.CryptoPlacementKernel {
		return false
	}
	if kernelUDPTXDirectManagementVIPRoute(route) {
		return false
	}
	for _, endpoint := range manager.snapshot.Endpoints {
		if endpoint.Transport != "udp" || !endpoint.Enabled {
			continue
		}
		peer := flow.Peer
		if peer == "" {
			peer = route.NextHop
		}
		if endpoint.Peer != peer {
			continue
		}
		if route.Endpoint != "" && endpoint.ID != route.Endpoint {
			continue
		}
		return kernelUDPTXEndpointEncryptionFullySecure(endpoint.Security.Encryption)
	}
	return false
}

func kernelUDPTXDirectManagementVIPRoute(route routing.Route) bool {
	return route.Source == "management_vip" &&
		route.Owner != "" &&
		route.LocalProtocol == ipProtocolTCP &&
		route.LocalPort != 0
}

func kernelUDPTXEndpointEncryptionPlaintext(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "plaintext", "none", "disabled", "off":
		return true
	default:
		return false
	}
}

func kernelUDPTXEndpointEncryptionFullySecure(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "secure", "encrypted", "trustix_secure", "trustix-secure":
		return true
	default:
		return false
	}
}

func kernelUDPTXSecureDirectTrustInnerChecksums() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_TRUST_INNER_CHECKSUMS"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_TRUST_CAPTURED_CHECKSUMS"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func experimentalTCPTXDirectTrustInnerChecksums() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_TRUST_INNER_CHECKSUMS"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func experimentalTCPTXDirectPreOuterInnerChecksumEnabled() bool {
	if envTruthy("TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM") {
		return true
	}
	if envFalsey("TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM") {
		return false
	}
	if experimentalTCPTXDirectPushRouteTCPHeaderKfuncRequested() &&
		(experimentalTCPTXDirectRouteTCPGSOKfuncRequested() ||
			experimentalTCPTXDirectRouteTCPXmitKfuncRequested()) {
		return false
	}
	if experimentalTCPTXDirectPushRouteTCPHeaderKfuncRequested() && experimentalTCPTXDirectOuterTCPHeaderKfuncPartialChecksumEnabled() {
		return false
	}
	return !kernelUDPTXSecureDirectTrustInnerChecksums()
}

func experimentalTCPTXDirectPreOuterInnerChecksumEnabledForOptions(options kernelUDPTXDirectProgramOptions) bool {
	if envTruthy("TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM") {
		return true
	}
	if envFalsey("TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_PRE_OUTER_INNER_CHECKSUM") {
		return false
	}
	if options.PushRouteTCPHeaderKfunc && (options.RouteTCPGSOKfunc || options.RouteTCPXmitKfunc) {
		return false
	}
	if options.PushRouteTCPHeaderKfunc && experimentalTCPTXDirectOuterTCPHeaderKfuncPartialChecksumEnabled() {
		return false
	}
	return experimentalTCPTXDirectPreOuterInnerChecksumEnabled()
}

func experimentalTCPTXDirectRouteTCPGSOTrustPartialInnerChecksumEnabled() bool {
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_TRUST_PARTIAL_INNER_CHECKSUM",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_TRUST_PARTIAL_INNER_CSUM",
	)
}

func experimentalTCPTXDirectRouteTCPGSOAsyncKfuncRequested() bool {
	if kernelUDPTXDirectSafeModeEnabled() {
		return false
	}
	if envFalsey(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_ASYNC_KFUNC",
	) {
		return false
	}
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_ASYNC_KFUNC",
	)
}

func experimentalTCPTXDirectRouteTCPGSOAsyncKfuncRequestedForSpec(spec dataplane.AttachSpec) bool {
	if spec.ExperimentalTCPRouteGSOAsync {
		return true
	}
	return experimentalTCPTXDirectRouteTCPGSOAsyncKfuncRequested()
}

func experimentalTCPTXDirectPacketChecksumEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_LINEAR_CHECKSUM"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func kernelUDPTXDirectInnerTCPChecksumEnabledForOptions(options kernelUDPTXDirectProgramOptions) bool {
	if !options.KernelUDPOnly {
		return false
	}
	if kernelUDPTXDirectInnerTCPChecksumDisabled() {
		return false
	}
	if envTruthy("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_INNER_TCP_CHECKSUM") {
		return true
	}
	if envTruthy(
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_TRUST_CAPTURED_INNER_CHECKSUMS",
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_SKIP_INNER_CHECKSUM",
	) {
		return false
	}
	return true
}

func kernelUDPTXDirectInnerTCPChecksumDisabled() bool {
	return envFalsey("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_INNER_TCP_CHECKSUM")
}

func kernelUDPTXDirectInnerTCPChecksumKfuncEnabled() bool {
	return envTruthy("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_INNER_TCP_CHECKSUM_KFUNC")
}

func kernelUDPTXDirectInnerTCPChecksumKfuncRequired() bool {
	return kernelUDPTXDirectInnerTCPChecksumKfuncEnabled()
}

func kernelUDPTXDirectInnerTCPChecksumKfuncRequestedForOptions(options kernelUDPTXDirectProgramOptions) bool {
	return kernelUDPTXDirectInnerTCPChecksumKfuncEnabled() && kernelUDPTXDirectInnerTCPChecksumEnabledForOptions(options)
}

func kernelUDPTXDirectSKBClearTXOffloadEnabled() bool {
	return envTruthy(
		"TRUSTIX_KERNEL_UDP_TC_TX_CLEAR_SKB_CSUM",
		"TRUSTIX_KERNEL_UDP_TC_TX_CLEAR_SKB_OFFLOAD",
	)
}

func kernelUDPTXDirectSKBClearTXOffloadGSOEnabled() bool {
	return envTruthy(
		"TRUSTIX_KERNEL_UDP_TC_TX_CLEAR_SKB_GSO",
		"TRUSTIX_KERNEL_UDP_TC_TX_CLEAR_SKB_OFFLOAD_GSO",
	)
}

func kernelUDPTXDirectSKBClearTXOffloadActiveGSOEnabled() bool {
	return envTruthy(
		"TRUSTIX_KERNEL_UDP_TC_TX_CLEAR_SKB_ACTIVE_GSO",
		"TRUSTIX_KERNEL_UDP_TC_TX_CLEAR_SKB_OFFLOAD_ACTIVE_GSO",
	)
}

func kernelUDPTXDirectStoreHeaderKfuncEnabled() bool {
	return envTruthy(
		"TRUSTIX_KERNEL_UDP_TC_TX_STORE_HEADER_KFUNC",
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_STORE_HEADER_KFUNC",
	)
}

func kernelUDPTXDirectBuildUDPHeaderKfuncEnabled() bool {
	return envTruthy(
		"TRUSTIX_KERNEL_UDP_TC_TX_BUILD_UDP_HEADER_KFUNC",
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_BUILD_UDP_HEADER_KFUNC",
	)
}

func kernelUDPTXDirectFinalizeUDPHeaderKfuncEnabled() bool {
	return envTruthy(
		"TRUSTIX_KERNEL_UDP_TC_TX_FINALIZE_UDP_HEADER_KFUNC",
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_FINALIZE_UDP_HEADER_KFUNC",
	)
}

func kernelUDPTXDirectUDPHeaderPartialChecksumEnabled() bool {
	return envTruthy(
		"TRUSTIX_KERNEL_UDP_TC_TX_UDP_HEADER_PARTIAL_CSUM",
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_UDP_HEADER_PARTIAL_CSUM",
		"TRUSTIX_KERNEL_UDP_TC_TX_OUTER_UDP_PARTIAL_CSUM",
	)
}

func kernelUDPTXDirectPushUDPHeaderKfuncEnabled() bool {
	return envTruthy(
		"TRUSTIX_KERNEL_UDP_TC_TX_PUSH_UDP_HEADER_KFUNC",
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_PUSH_UDP_HEADER_KFUNC",
		"TRUSTIX_KERNEL_UDP_TC_TX_PREPEND_UDP_HEADER_KFUNC",
	)
}

func experimentalTCPTXDirectOuterTCPChecksumKfuncRequested() bool {
	if envFalsey(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_OUTER_TCP_CHECKSUM_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_OUTER_CHECKSUM_KFUNC",
	) {
		return false
	}
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_OUTER_TCP_CHECKSUM_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_OUTER_CHECKSUM_KFUNC",
	)
}

func experimentalTCPTXDirectOuterTCPChecksumKfuncRequired() bool {
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_OUTER_TCP_CHECKSUM_KFUNC_REQUIRED",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_OUTER_CHECKSUM_KFUNC_REQUIRED",
	)
}

func experimentalTCPTXDirectOuterTCPHeaderKfuncRequested() bool {
	if envFalsey(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_OUTER_TCP_HEADER_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_FINALIZE_TCP_HEADER_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_OUTER_TCP_KFUNC",
	) {
		return false
	}
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_OUTER_TCP_HEADER_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_FINALIZE_TCP_HEADER_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_OUTER_TCP_KFUNC",
	)
}

func experimentalTCPTXDirectOuterTCPHeaderKfuncRequired() bool {
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_OUTER_TCP_HEADER_KFUNC_REQUIRED",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_FINALIZE_TCP_HEADER_KFUNC_REQUIRED",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_OUTER_TCP_KFUNC_REQUIRED",
	)
}

func experimentalTCPTXDirectOuterTCPHeaderKfuncPartialChecksumEnabled() bool {
	if envFalsey(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_OUTER_TCP_HEADER_KFUNC_PARTIAL_CSUM",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_FINALIZE_TCP_HEADER_KFUNC_PARTIAL_CSUM",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_OUTER_TCP_KFUNC_PARTIAL_CSUM",
	) {
		return false
	}
	if envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_OUTER_TCP_HEADER_KFUNC_PARTIAL_CSUM",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_FINALIZE_TCP_HEADER_KFUNC_PARTIAL_CSUM",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_OUTER_TCP_KFUNC_PARTIAL_CSUM",
	) {
		return true
	}
	return true
}

func experimentalTCPTXDirectTCPPartialCSUMKfuncRequested() bool {
	if envFalsey(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_TCP_PARTIAL_CSUM_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_OUTER_TCP_PARTIAL_CSUM_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_SET_TCP_PARTIAL_CSUM_KFUNC",
	) {
		return false
	}
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_TCP_PARTIAL_CSUM_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_OUTER_TCP_PARTIAL_CSUM_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_SET_TCP_PARTIAL_CSUM_KFUNC",
	)
}

func experimentalTCPTXDirectTCPPartialCSUMKfuncRequired() bool {
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_TCP_PARTIAL_CSUM_KFUNC_REQUIRED",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_OUTER_TCP_PARTIAL_CSUM_KFUNC_REQUIRED",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_SET_TCP_PARTIAL_CSUM_KFUNC_REQUIRED",
	)
}

func experimentalTCPTXDirectPushTCPHeaderKfuncRequested() bool {
	if envFalsey(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_TCP_HEADER_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_OUTER_TCP_HEADER_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_TCP_KFUNC",
	) {
		return false
	}
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_TCP_HEADER_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_OUTER_TCP_HEADER_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_TCP_KFUNC",
	)
}

func experimentalTCPTXDirectPushTCPHeaderKfuncRequired() bool {
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_TCP_HEADER_KFUNC_REQUIRED",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_OUTER_TCP_HEADER_KFUNC_REQUIRED",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_TCP_KFUNC_REQUIRED",
	)
}

func experimentalTCPTXDirectPushFlowTCPHeaderKfuncRequested() bool {
	if envFalsey(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_FLOW_TCP_HEADER_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_FLOW_OUTER_TCP_HEADER_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_FLOW_TCP_KFUNC",
	) {
		return false
	}
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_FLOW_TCP_HEADER_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_FLOW_OUTER_TCP_HEADER_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_FLOW_TCP_KFUNC",
	)
}

func experimentalTCPTXDirectPushFlowTCPHeaderKfuncRequired() bool {
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_FLOW_TCP_HEADER_KFUNC_REQUIRED",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_FLOW_OUTER_TCP_HEADER_KFUNC_REQUIRED",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_FLOW_TCP_KFUNC_REQUIRED",
	)
}

func experimentalTCPTXDirectFinalizeFlowTCPHeaderKfuncRequested() bool {
	if envFalsey(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_FINALIZE_FLOW_TCP_HEADER_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_FINALIZE_FLOW_OUTER_TCP_HEADER_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_FINALIZE_FLOW_TCP_KFUNC",
	) {
		return false
	}
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_FINALIZE_FLOW_TCP_HEADER_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_FINALIZE_FLOW_OUTER_TCP_HEADER_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_FINALIZE_FLOW_TCP_KFUNC",
	)
}

func experimentalTCPTXDirectFinalizeFlowTCPHeaderKfuncRequired() bool {
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_FINALIZE_FLOW_TCP_HEADER_KFUNC_REQUIRED",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_FINALIZE_FLOW_OUTER_TCP_HEADER_KFUNC_REQUIRED",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_FINALIZE_FLOW_TCP_KFUNC_REQUIRED",
	)
}

func experimentalTCPTXDirectPushRouteTCPHeaderKfuncRequested() bool {
	if envFalsey(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_ROUTE_TCP_HEADER_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_ROUTE_OUTER_TCP_HEADER_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_ROUTE_TCP_KFUNC",
	) {
		return false
	}
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_ROUTE_TCP_HEADER_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_ROUTE_OUTER_TCP_HEADER_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_ROUTE_TCP_KFUNC",
	)
}

func experimentalTCPTXDirectPushRouteTCPHeaderKfuncRequestedForSpec(spec dataplane.AttachSpec) bool {
	if envFalsey(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_ROUTE_TCP_HEADER_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_ROUTE_OUTER_TCP_HEADER_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_ROUTE_TCP_KFUNC",
	) {
		return false
	}
	return spec.ExperimentalTCPRouteGSOSync || experimentalTCPTXDirectPushRouteTCPHeaderKfuncRequested()
}

func experimentalTCPTXDirectPushRouteTCPHeaderKfuncRequired() bool {
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_ROUTE_TCP_HEADER_KFUNC_REQUIRED",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_ROUTE_OUTER_TCP_HEADER_KFUNC_REQUIRED",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PUSH_ROUTE_TCP_KFUNC_REQUIRED",
	)
}

func experimentalTCPTXDirectRouteTCPGSOKfuncRequested() bool {
	if envFalsey(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_KFUNC",
	) {
		return false
	}
	if envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_KFUNC",
	) {
		return true
	}
	return experimentalTCPTXDirectRouteTCPGSOAsyncKfuncRequested()
}

func experimentalTCPTXDirectRouteTCPGSOKfuncRequestedForSpec(spec dataplane.AttachSpec) bool {
	if envFalsey(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_KFUNC",
	) {
		return false
	}
	return spec.ExperimentalTCPRouteGSOSync ||
		experimentalTCPTXDirectRouteTCPGSOKfuncRequested() ||
		experimentalTCPTXDirectRouteTCPGSOAsyncKfuncRequestedForSpec(spec)
}

func experimentalTCPTXDirectRouteTCPGSOKfuncRequired() bool {
	return experimentalTCPTXDirectRouteTCPGSOKfuncRequested() && envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC_REQUIRED",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_KFUNC_REQUIRED",
	)
}

func experimentalTCPTXDirectRouteTCPXmitKfuncRequested() bool {
	if envFalsey(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_WORKER_KFUNC",
	) {
		return false
	}
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_WORKER_KFUNC",
	)
}

func experimentalTCPTXDirectRouteTCPXmitKfuncRequestedForSpec(spec dataplane.AttachSpec) bool {
	if envFalsey(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_WORKER_KFUNC",
	) {
		return false
	}
	return spec.ExperimentalTCPRouteXmitWorker || experimentalTCPTXDirectRouteTCPXmitKfuncRequested()
}

func experimentalTCPTXDirectRouteTCPXmitKfuncRequired() bool {
	return experimentalTCPTXDirectRouteTCPXmitKfuncRequested() && envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC_REQUIRED",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_WORKER_KFUNC_REQUIRED",
	)
}

func experimentalTCPSkipOuterTCPChecksum() bool {
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_SKIP_OUTER_TCP_CHECKSUM",
		"TRUSTIX_EXPERIMENTAL_TCP_SKIP_TCP_CHECKSUM",
		"TRUSTIX_EXPERIMENTAL_TCP_SKIP_CHECKSUM",
	)
}

func experimentalTCPTXPlainSkipSequenceEnabled() bool {
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TX_PLAIN_SKIP_SEQUENCE",
		"TRUSTIX_TIXT_TX_PLAIN_SKIP_SEQUENCE",
	)
}

func experimentalTCPTXPlainSkipSequenceEnabledForSpec(spec dataplane.AttachSpec) bool {
	if envFalsey(
		"TRUSTIX_EXPERIMENTAL_TCP_TX_PLAIN_SKIP_SEQUENCE",
		"TRUSTIX_TIXT_TX_PLAIN_SKIP_SEQUENCE",
	) {
		return false
	}
	return spec.ExperimentalTCPPlainSkipSequence || experimentalTCPTXPlainSkipSequenceEnabled()
}

func experimentalTCPTXPlainACKOnlyEnabled() bool {
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TX_PLAIN_ACK_ONLY",
		"TRUSTIX_TIXT_TX_PLAIN_ACK_ONLY",
	)
}

func experimentalTCPTXPlainACKOnlyEnabledForSpec(spec dataplane.AttachSpec) bool {
	if envFalsey(
		"TRUSTIX_EXPERIMENTAL_TCP_TX_PLAIN_ACK_ONLY",
		"TRUSTIX_TIXT_TX_PLAIN_ACK_ONLY",
	) {
		return false
	}
	return spec.ExperimentalTCPPlainACKOnly || experimentalTCPTXPlainACKOnlyEnabled()
}

func experimentalTCPTXPlaintextDirectMultiFlowEnabled() bool {
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PLAINTEXT_MULTI_FLOW",
		"TRUSTIX_EXPERIMENTAL_TCP_PLAINTEXT_DIRECT_MULTI_FLOW",
	)
}

func experimentalTCPTXPlaintextDirectRouteMultiFlowEnabled() bool {
	if !experimentalTCPTXPlaintextDirectMultiFlowEnabled() {
		return false
	}
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PLAINTEXT_ROUTE_MULTI_FLOW_UNSAFE",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PLAINTEXT_ROUTE_MULTI_FLOW",
		"TRUSTIX_EXPERIMENTAL_TCP_PLAINTEXT_DIRECT_ROUTE_MULTI_FLOW",
	)
}

func experimentalTCPTXPlaintextDirectPreferListenerSourcedEnabled() bool {
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_PREFER_LISTENER_SOURCE",
		"TRUSTIX_EXPERIMENTAL_TCP_PREFER_LISTENER_SOURCE",
	)
}

func kernelUDPTXDirectStrongFlowHashEnabled() bool {
	return envTruthy(
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_STRONG_FLOW_HASH",
		"TRUSTIX_KERNEL_UDP_DIRECT_STRONG_FLOW_HASH",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_STRONG_FLOW_HASH",
	)
}

func kernelUDPTXDirectSKBFlowHashEnabled() bool {
	return envTruthy(
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_SKB_FLOW_HASH",
		"TRUSTIX_KERNEL_UDP_DIRECT_SKB_FLOW_HASH",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_SKB_FLOW_HASH",
	)
}

func kernelUDPTXDirectPortFlowHashEnabled() bool {
	return envTruthy(
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_PORT_FLOW_HASH",
		"TRUSTIX_KERNEL_UDP_DIRECT_PORT_FLOW_HASH",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_PORT_FLOW_HASH",
	)
}

func experimentalTCPTXPlainFlagsImmForOptions(opts kernelUDPTXDirectProgramOptions) int64 {
	if opts.ExperimentalTCPACKOnly {
		return 0x1050
	}
	return 0x1850
}

func kernelUDPTXDirectDisabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT"))) {
	case "0", "false", "no", "off", "disabled":
		return true
	default:
		return false
	}
}

func kernelUDPTXDirectForceEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT"))) {
	case "force", "unsafe", "unsafe_plaintext":
		return true
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_FORCE"))) {
	case "1", "true", "yes", "on", "enabled", "force", "unsafe":
		return true
	default:
		return false
	}
}

func kernelUDPTXDirectSafeModeEnabled() bool {
	return envTruthy(
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_SAFE",
		"TRUSTIX_KERNEL_UDP_TC_TX_SAFE_DIRECT",
	)
}

func kernelUDPTXDirectExperimentalTCPOnlyEnabled() bool {
	return envTruthy(
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_EXPERIMENTAL_TCP_ONLY",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_ONLY",
	)
}

func kernelUDPTXDirectExperimentalTCPOnlyEnabledForSpec(spec dataplane.AttachSpec) bool {
	if envFalsey(
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_EXPERIMENTAL_TCP_ONLY",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_ONLY",
	) {
		return false
	}
	return spec.ExperimentalTCPTXDirect || kernelUDPTXDirectExperimentalTCPOnlyEnabled()
}

func kernelUDPTXDirectKernelUDPOnlyEnabled() bool {
	if kernelUDPTXDirectExperimentalTCPOnlyEnabled() {
		return false
	}
	if envFalsey(
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_KERNEL_UDP_ONLY",
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_UDP_ONLY",
	) {
		return false
	}
	if envTruthy(
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_KERNEL_UDP_ONLY",
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_UDP_ONLY",
	) {
		return true
	}
	return !experimentalTCPTXDirectEnabled()
}

func kernelUDPTXDirectKernelUDPOnlyEnabledForSpec(spec dataplane.AttachSpec) bool {
	if kernelUDPTXDirectExperimentalTCPOnlyEnabledForSpec(spec) {
		return false
	}
	if envFalsey(
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_KERNEL_UDP_ONLY",
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_UDP_ONLY",
	) {
		return false
	}
	if envTruthy(
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_KERNEL_UDP_ONLY",
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_UDP_ONLY",
	) {
		return true
	}
	return !experimentalTCPTXDirectEnabledForSpec(spec)
}

func kernelUDPTXDirectOnlyEnabled(spec dataplane.AttachSpec) bool {
	if experimentalTCPRouteGSORequestedForSpec(spec) {
		return true
	}
	if spec.KernelUDPTCOnlyProvider && spec.KernelUDPTXDirectOnly {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY"))) {
	case "1", "true", "yes", "on", "enabled", "force":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return spec.KernelUDPTXDirectOnly
	}
}

func kernelUDPTCOnlyProviderRequested() bool {
	return envTruthy(
		"TRUSTIX_KERNEL_UDP_TC_ONLY",
		"TRUSTIX_KERNEL_UDP_TC_DIRECT_ONLY_PROVIDER",
	)
}

func kernelUDPTCOnlyProviderRequestedForSpec(spec dataplane.AttachSpec) bool {
	return spec.KernelUDPTCOnlyProvider || kernelUDPTCOnlyProviderRequested()
}

func kernelUDPTCOnlyFallbackDisabled() bool {
	return envFalsey(
		"TRUSTIX_KERNEL_UDP_TC_ONLY_FALLBACK",
		"TRUSTIX_KERNEL_UDP_TC_DIRECT_ONLY_PROVIDER_FALLBACK",
	)
}

func kernelUDPTXDirectSkipPlainSequenceEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_TX_PLAIN_SKIP_SEQUENCE"))) {
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}

func kernelUDPTXSecureDirectRequestedForSpec(spec dataplane.AttachSpec) bool {
	return spec.KernelUDPTXSecureDirect || kernelUDPTXSecureDirectRequested() || kernelUDPTXSecureDirectRequiredBySpec(spec)
}

func (manager *Manager) kernelUDPRXSecureDirectRequestedLocked() bool {
	return manager.spec.KernelUDPRXSecureDirect || kernelUDPRXSecureDirectRequested()
}

func kernelUDPTXSecureDirectProgramOptionsForSpec(spec dataplane.AttachSpec) kernelUDPTXSecureDirectProgramOptions {
	return kernelUDPTXSecureDirectProgramOptions{
		KfuncSeal:                spec.KernelUDPTXSecureDirectKfuncSeal || kernelUDPTXSecureDirectKfuncSealEnabled(),
		SKBSealKfunc:             kernelUDPTXSecureDirectSKBSealKfuncCompiled && (spec.KernelUDPTXSecureDirectSKBSealKfunc || kernelUDPTXSecureDirectSKBSealKfuncEnabled()),
		FixInnerChecksums:        kernelUDPTXSecureDirectFixInnerChecksumsEnabled(),
		InnerTCPChecksumKfunc:    kernelUDPTXSecureDirectInnerTCPChecksumKfuncEnabled(),
		OuterTCPChecksumKfunc:    kernelUDPTXSecureDirectOuterTCPChecksumKfuncEnabled(),
		OuterTCPPartialCSUMKfunc: kernelUDPTXSecureDirectOuterTCPPartialChecksumKfuncEnabled(),
	}
}

func kernelUDPTXSecureDirectTrustInnerChecksumsForSpec(spec dataplane.AttachSpec) bool {
	return spec.KernelUDPSecureDirectTrustInnerChecksums || kernelUDPTXSecureDirectTrustInnerChecksums()
}

func kernelUDPTXSecureDirectRequiredBySpec(spec dataplane.AttachSpec) bool {
	if !kernelUDPTXDirectOnlyEnabled(spec) {
		return false
	}
	reason := strings.ToLower(spec.KernelUDPTXDirectOnlyReason)
	return strings.Contains(reason, "encryption=secure") ||
		strings.Contains(reason, "crypto_placement=kernel")
}

func kernelDatapathRXXDPPassEnabledForSpec(spec dataplane.AttachSpec) bool {
	if spec.KernelDatapathSuppressLegacyRXWorker {
		return false
	}
	return kernelDatapathRXXDPPassEnabled()
}

func kernelDatapathRXWorkerOwnsStackRXForSpec(spec dataplane.AttachSpec) bool {
	if spec.KernelDatapathSuppressLegacyRXWorker {
		return false
	}
	return kernelDatapathRXWorkerOwnsStackRX()
}

func kernelUDPRXDirectDisabled() bool {
	if kernelUDPTXDirectDisabled() {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT"))) {
	case "0", "false", "no", "off", "disabled":
		return true
	default:
		return false
	}
}

func kernelUDPRXDirectDisabledForSpec(spec dataplane.AttachSpec) bool {
	if experimentalTCPRouteGSORequestedForSpec(spec) {
		return false
	}
	if spec.KernelUDPTCOnlyProvider && spec.KernelUDPTXDirectOnly {
		return false
	}
	return kernelUDPRXDirectDisabled()
}

func kernelUDPRXSecureDirectRequested() bool {
	return envTruthy(
		"TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT",
		"TRUSTIX_KERNEL_UDP_TC_RX_KERNEL_CRYPTO_DIRECT",
	)
}

func (manager *Manager) syncPacketPolicyLocked(policy dataplane.PacketPolicy) error {
	if manager.packetPolicyMap == nil {
		return nil
	}
	value := packetPolicyValue{MTU: policy.MTU, TCPMSSClamp: policy.TCPMSSClamp}
	if policy.DropFragments {
		value.DropFragments = 1
	}
	key := uint32(0)
	if err := manager.packetPolicyMap.Update(key, value, cebpf.UpdateAny); err != nil {
		return fmt.Errorf("sync packet policy to BPF map: %w", err)
	}
	return nil
}

func clearBPFMap[K comparable, V any](m *cebpf.Map, label string) error {
	var key K
	var value V
	var keys []K
	iterator := m.Iterate()
	for iterator.Next(&key, &value) {
		keys = append(keys, key)
	}
	if err := iterator.Err(); err != nil {
		return fmt.Errorf("iterate %s: %w", label, err)
	}
	for _, key := range keys {
		if err := m.Delete(key); err != nil && !errors.Is(err, cebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete stale entry from %s: %w", label, err)
		}
	}
	return nil
}

func (manager *Manager) deliverCaptureEventBatchLocked(batch []dataplane.CaptureEvent) bool {
	if len(batch) == 0 {
		return false
	}
	if captureHistoryEnabled {
		for _, event := range batch {
			manager.recordCaptureEventLocked(event)
		}
	}
	if len(manager.captureSubs) == 0 {
		return false
	}
	if !captureHistoryEnabled && len(manager.captureSubs) == 1 {
		for i := range batch {
			batch[i].PayloadMutable = true
		}
	} else {
		for i := range batch {
			batch[i].PayloadMutable = false
		}
	}
	for subscriber := range manager.captureSubs {
		select {
		case subscriber <- batch:
		default:
			manager.captureSubDrops += uint64(len(batch))
		}
	}
	return true
}

func (manager *Manager) readCaptureEvents(reader *perf.Reader) {
	var record perf.Record
	batch := make([]dataplane.CaptureEvent, 0, captureReaderBatchSize)
	var arena []byte
	deliver := func() {
		if len(batch) == 0 {
			return
		}
		manager.captureMu.Lock()
		if manager.deliverCaptureEventBatchLocked(batch) {
			batch = make([]dataplane.CaptureEvent, 0, captureReaderBatchSize)
		} else {
			batch = batch[:0]
		}
		manager.captureMu.Unlock()
		arena = nil
	}
	blockingRead := true
	for {
		if blockingRead {
			reader.SetDeadline(time.Time{})
		} else {
			reader.SetDeadline(time.Now().Add(captureReaderDrainTimeout))
		}
		if err := reader.ReadInto(&record); err != nil {
			if errors.Is(err, perf.ErrClosed) || errors.Is(err, os.ErrClosed) {
				deliver()
				return
			}
			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, perf.ErrFlushed) {
				deliver()
				blockingRead = true
				continue
			}
			continue
		}
		if record.LostSamples > 0 {
			deliver()
			manager.captureMu.Lock()
			manager.captureLost += record.LostSamples
			manager.captureMu.Unlock()
			blockingRead = true
			continue
		}
		var capturedAt time.Time
		if captureHistoryEnabled {
			capturedAt = time.Now().UTC()
		}
		event, ok := decodeCaptureEventIntoAt(record, &arena, capturedAt)
		if !ok {
			continue
		}
		batch = append(batch, event)
		if len(batch) >= captureReaderBatchSize {
			deliver()
			blockingRead = true
		} else if captureReaderDrainTimeout <= 0 {
			deliver()
			blockingRead = true
		} else {
			blockingRead = false
		}
	}
}

func (manager *Manager) readCaptureRingEvents(reader *ringbuf.Reader) {
	var record ringbuf.Record
	batch := make([]dataplane.CaptureEvent, 0, captureReaderBatchSize)
	var arena []byte
	deliver := func() {
		if len(batch) == 0 {
			return
		}
		manager.captureMu.Lock()
		if manager.deliverCaptureEventBatchLocked(batch) {
			batch = make([]dataplane.CaptureEvent, 0, captureReaderBatchSize)
		} else {
			batch = batch[:0]
		}
		manager.captureMu.Unlock()
		arena = nil
	}
	blockingRead := true
	for {
		if blockingRead {
			reader.SetDeadline(time.Time{})
		} else {
			reader.SetDeadline(time.Now().Add(captureReaderDrainTimeout))
		}
		if err := reader.ReadInto(&record); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed) {
				deliver()
				return
			}
			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, ringbuf.ErrFlushed) {
				deliver()
				blockingRead = true
				continue
			}
			continue
		}
		var capturedAt time.Time
		if captureHistoryEnabled {
			capturedAt = time.Now().UTC()
		}
		event, ok := decodeCaptureRawEventIntoAt(record.RawSample, -1, &arena, capturedAt)
		if !ok {
			continue
		}
		batch = append(batch, event)
		if len(batch) >= captureReaderBatchSize {
			deliver()
			blockingRead = true
		} else if captureReaderDrainTimeout <= 0 {
			deliver()
			blockingRead = true
		} else {
			blockingRead = false
		}
	}
}

func (manager *Manager) recordCaptureEventLocked(event dataplane.CaptureEvent) {
	if !captureHistoryEnabled {
		return
	}
	if len(manager.captureEvents) != captureRingLimit {
		manager.captureEvents = make([]dataplane.CaptureEvent, captureRingLimit)
		manager.captureEventNext = 0
		manager.captureEventCount = 0
	}
	manager.captureEvents[manager.captureEventNext] = event
	manager.captureEventNext = (manager.captureEventNext + 1) % captureRingLimit
	if manager.captureEventCount < captureRingLimit {
		manager.captureEventCount++
	}
}

func decodeCaptureEvent(record perf.Record) (dataplane.CaptureEvent, bool) {
	var arena []byte
	return decodeCaptureEventInto(record, &arena)
}

func decodeCaptureEventInto(record perf.Record, arena *[]byte) (dataplane.CaptureEvent, bool) {
	return decodeCaptureEventIntoAt(record, arena, time.Now().UTC())
}

func decodeCaptureEventIntoAt(record perf.Record, arena *[]byte, capturedAt time.Time) (dataplane.CaptureEvent, bool) {
	return decodeCaptureRawEventIntoAt(record.RawSample, record.CPU, arena, capturedAt)
}

func decodeCaptureRawEventIntoAt(raw []byte, cpu int, arena *[]byte, capturedAt time.Time) (dataplane.CaptureEvent, bool) {
	if len(raw) < captureEventHeader {
		return dataplane.CaptureEvent{}, false
	}
	if binary.LittleEndian.Uint32(raw[0:4]) != captureMagic {
		return dataplane.CaptureEvent{}, false
	}
	hook := "unknown"
	switch binary.LittleEndian.Uint32(raw[8:12]) {
	case 1:
		hook = "lan_ingress_route_hit"
	}
	packetLen := binary.LittleEndian.Uint32(raw[12:16])
	sampleLen := binary.LittleEndian.Uint32(raw[16:20])
	sampleLimit := uint32(captureSampleLimit)
	if sampleLen > sampleLimit {
		sampleLen = sampleLimit
	}
	available := len(raw) - captureEventHeader
	if int(sampleLen) > available {
		sampleLen = uint32(available)
	}
	base := len(*arena)
	*arena = append(*arena, raw[captureEventHeader:captureEventHeader+int(sampleLen)]...)
	payload := (*arena)[base : base+int(sampleLen)]
	if captureNormalizeChecksums {
		normalizeCapturePayloadChecksumsInPlace(payload)
	}
	source := [4]byte{raw[20], raw[21], raw[22], raw[23]}
	destination := [4]byte{raw[24], raw[25], raw[26], raw[27]}
	sourceAddr := netip.AddrFrom4(source)
	destinationAddr := netip.AddrFrom4(destination)
	natTranslated := binary.LittleEndian.Uint32(raw[28:32])&natEventTranslatedFlag != 0
	gsoSegmentLen := binary.LittleEndian.Uint32(raw[36:40])
	flowKey, hasFlow := captureEventFlowKey(payload)
	event := dataplane.CaptureEvent{
		CapturedAt:         capturedAt,
		CPU:                cpu,
		Hook:               hook,
		PacketLength:       packetLen,
		SampleLength:       sampleLen,
		GSOSegmentLength:   gsoSegmentLen,
		NATTranslated:      natTranslated,
		ChecksumNormalized: captureNormalizeChecksums,
		Payload:            payload,
		SourceAddr:         sourceAddr,
		DestinationAddr:    destinationAddr,
		FlowKey:            flowKey,
		HasFlow:            hasFlow,
	}
	if natTranslated {
		event.OriginalSourceAddr = captureEventOriginalSourceAddr(raw)
	}
	return event, true
}

func captureEventFlowKey(packet []byte) (routing.FlowKey, bool) {
	if len(packet) >= rejectEthernetHeaderLen && binary.BigEndian.Uint16(packet[12:14]) == etherTypeIPv4 {
		packet = packet[rejectEthernetHeaderLen:]
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
	flagsAndFragment := binary.BigEndian.Uint16(packet[6:8])
	if flagsAndFragment&ipv4FragmentOffsetMask != 0 {
		return routing.FlowKey{}, false
	}
	key := routing.FlowKey{
		SourceIP:      netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]}),
		DestinationIP: netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]}),
		Protocol:      packet[9],
	}
	switch key.Protocol {
	case unix.IPPROTO_TCP, unix.IPPROTO_UDP:
		if totalLen < ihl+4 {
			return routing.FlowKey{}, false
		}
		key.SourcePort = binary.BigEndian.Uint16(packet[ihl : ihl+2])
		key.DestinationPort = binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
	}
	return key, true
}

func normalizeCaptureEventPayloadForRead(event *dataplane.CaptureEvent) {
	if event == nil {
		return
	}
	if event.SourceIP == "" && event.SourceAddr.IsValid() {
		event.SourceIP = event.SourceAddr.String()
	}
	if event.DestinationIP == "" && event.DestinationAddr.IsValid() {
		event.DestinationIP = event.DestinationAddr.String()
	}
	if event.OriginalSourceIP == "" && event.OriginalSourceAddr.IsValid() {
		event.OriginalSourceIP = event.OriginalSourceAddr.String()
	}
	if len(event.Payload) > 0 {
		payload := append([]byte(nil), event.Payload...)
		if !event.ChecksumNormalized {
			normalizeCapturePayloadChecksumsInPlace(payload)
			event.ChecksumNormalized = true
		}
		event.Payload = payload
	}
}

func normalizeCapturePayloadChecksumsInPlace(packet []byte) {
	ipOffset := 0
	if len(packet) >= rejectEthernetHeaderLen && binary.BigEndian.Uint16(packet[12:14]) == etherTypeIPv4 {
		ipOffset = rejectEthernetHeaderLen
	}
	if len(packet) < ipOffset+rejectIPv4HeaderLen {
		return
	}
	ip := packet[ipOffset:]
	if ip[0]>>4 != 4 {
		return
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < rejectIPv4HeaderLen || len(ip) < ihl {
		return
	}
	totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
	if totalLen < ihl || totalLen > len(ip) {
		return
	}
	ip = packet[ipOffset : ipOffset+totalLen]
	binary.BigEndian.PutUint16(ip[10:12], 0)
	binary.BigEndian.PutUint16(ip[10:12], captureChecksum(ip[:ihl]))
	flagsAndFragment := binary.BigEndian.Uint16(ip[6:8])
	if flagsAndFragment&(0x2000|0x1fff) != 0 {
		return
	}
	segment := ip[ihl:totalLen]
	switch ip[9] {
	case ipProtocolTCP:
		if len(segment) < rejectTCPHeaderLen {
			return
		}
		tcpHeaderLen := int(segment[12]>>4) * 4
		if tcpHeaderLen < rejectTCPHeaderLen || len(segment) < tcpHeaderLen {
			return
		}
		binary.BigEndian.PutUint16(segment[16:18], 0)
		binary.BigEndian.PutUint16(segment[16:18], captureTransportChecksum(ip[12:16], ip[16:20], ip[9], segment))
	case ipProtocolUDP:
		if len(segment) < 8 {
			return
		}
		udpLen := int(binary.BigEndian.Uint16(segment[4:6]))
		if udpLen < 8 || udpLen > len(segment) {
			return
		}
		udp := segment[:udpLen]
		binary.BigEndian.PutUint16(udp[6:8], 0)
		binary.BigEndian.PutUint16(udp[6:8], captureTransportChecksum(ip[12:16], ip[16:20], ip[9], udp))
	}
}

func captureTransportChecksum(src []byte, dst []byte, protocol byte, segment []byte) uint16 {
	sum := captureChecksumAddBytes(0, src)
	sum = captureChecksumAddBytes(sum, dst)
	sum += uint32(protocol)
	sum += uint32(len(segment))
	sum = captureChecksumAddBytes(sum, segment)
	checksum := captureChecksumFold(sum)
	if checksum == 0 {
		return 0xffff
	}
	return checksum
}

func captureChecksum(payload []byte) uint16 {
	return captureChecksumFold(captureChecksumAddBytes(0, payload))
}

func captureChecksumAddBytes(sum uint32, payload []byte) uint32 {
	for len(payload) >= 32 {
		sum += uint32(binary.BigEndian.Uint16(payload[0:2]))
		sum += uint32(binary.BigEndian.Uint16(payload[2:4]))
		sum += uint32(binary.BigEndian.Uint16(payload[4:6]))
		sum += uint32(binary.BigEndian.Uint16(payload[6:8]))
		sum += uint32(binary.BigEndian.Uint16(payload[8:10]))
		sum += uint32(binary.BigEndian.Uint16(payload[10:12]))
		sum += uint32(binary.BigEndian.Uint16(payload[12:14]))
		sum += uint32(binary.BigEndian.Uint16(payload[14:16]))
		sum += uint32(binary.BigEndian.Uint16(payload[16:18]))
		sum += uint32(binary.BigEndian.Uint16(payload[18:20]))
		sum += uint32(binary.BigEndian.Uint16(payload[20:22]))
		sum += uint32(binary.BigEndian.Uint16(payload[22:24]))
		sum += uint32(binary.BigEndian.Uint16(payload[24:26]))
		sum += uint32(binary.BigEndian.Uint16(payload[26:28]))
		sum += uint32(binary.BigEndian.Uint16(payload[28:30]))
		sum += uint32(binary.BigEndian.Uint16(payload[30:32]))
		payload = payload[32:]
	}
	for len(payload) >= 8 {
		value := binary.BigEndian.Uint64(payload[:8])
		sum += uint32(value >> 48)
		sum += uint32((value >> 32) & 0xffff)
		sum += uint32((value >> 16) & 0xffff)
		sum += uint32(value & 0xffff)
		payload = payload[8:]
	}
	for len(payload) > 1 {
		sum += uint32(binary.BigEndian.Uint16(payload[:2]))
		payload = payload[2:]
	}
	if len(payload) == 1 {
		sum += uint32(payload[0]) << 8
	}
	return sum
}

func captureChecksumFold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func captureEventOriginalSourceAddr(raw []byte) netip.Addr {
	if len(raw) < captureEventHeader || binary.LittleEndian.Uint32(raw[28:32])&natEventTranslatedFlag == 0 {
		return netip.Addr{}
	}
	original := [4]byte{raw[32], raw[33], raw[34], raw[35]}
	if original == ([4]byte{}) {
		return netip.Addr{}
	}
	return netip.AddrFrom4(original)
}

func replaceClsact(link netlink.Link) error {
	qdisc := &netlink.Clsact{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
	}
	return netlink.QdiscReplace(qdisc)
}

var trustIXTCFilterNames = map[string]struct{}{
	"trustix_ingress":   {},
	"trustix_egress":    {},
	"trustix_kudp_txk":  {},
	"trustix_kudp_txke": {},
	"trustix_kudp_rx":   {},
	"trustix_kudp_rxk":  {},
}

func deleteClsact(link netlink.Link) error {
	if err := deleteTrustIXTCFilters(link); err != nil {
		return err
	}
	hasFilters, err := clsactHasFilters(link)
	if err != nil {
		return err
	}
	if hasFilters {
		return nil
	}
	qdisc := &netlink.Clsact{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
	}
	if err := netlink.QdiscDel(qdisc); err != nil && !isNotFound(err) && !errors.Is(err, unix.EINVAL) {
		return fmt.Errorf("remove clsact qdisc from %q: %w", link.Attrs().Name, err)
	}
	return nil
}

func deleteTrustIXTCFilters(link netlink.Link) error {
	if link == nil || link.Attrs() == nil {
		return nil
	}
	var errs []string
	for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
		filters, err := netlink.FilterList(link, parent)
		if err != nil {
			if isNotFound(err) || errors.Is(err, unix.EINVAL) {
				continue
			}
			errs = append(errs, fmt.Sprintf("list TC filters on %q: %v", link.Attrs().Name, err))
			continue
		}
		for _, filter := range filters {
			if !isTrustIXTCFilter(filter) {
				continue
			}
			if err := netlink.FilterDel(filter); err != nil && !isNotFound(err) {
				errs = append(errs, fmt.Sprintf("remove stale TrustIX TC filter from %q: %v", link.Attrs().Name, err))
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func clsactHasFilters(link netlink.Link) (bool, error) {
	if link == nil || link.Attrs() == nil {
		return false, nil
	}
	for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
		filters, err := netlink.FilterList(link, parent)
		if err != nil {
			if isNotFound(err) || errors.Is(err, unix.EINVAL) {
				continue
			}
			return false, fmt.Errorf("list TC filters on %q: %w", link.Attrs().Name, err)
		}
		if len(filters) > 0 {
			return true, nil
		}
	}
	return false, nil
}

func isTrustIXTCFilter(filter netlink.Filter) bool {
	bpfFilter, ok := filter.(*netlink.BpfFilter)
	if !ok {
		return false
	}
	_, ok = trustIXTCFilterNames[strings.TrimSpace(bpfFilter.Name)]
	return ok
}

func linkHasAddress(link netlink.Link, cidr string) (bool, error) {
	target, err := parseAddress(cidr)
	if err != nil {
		return false, err
	}
	family := netlink.FAMILY_V4
	if target.IP.To4() == nil {
		family = netlink.FAMILY_V6
	}
	addrs, err := netlink.AddrList(link, family)
	if err != nil {
		return false, fmt.Errorf("list addresses on %q: %w", link.Attrs().Name, err)
	}
	for _, addr := range addrs {
		if addr.IPNet != nil && sameIPNet(addr.IPNet, target.IPNet) {
			return true, nil
		}
	}
	return false, nil
}

func (manager *Manager) syncLocalVIPsLocked(vips []dataplane.LocalVIP) error {
	if manager.localVIPs == nil {
		manager.localVIPs = make(map[netip.Addr]struct{})
	}
	if manager.spec.LANIface == "" {
		if len(manager.localVIPs) == 0 {
			return nil
		}
		return fmt.Errorf("LAN iface is not configured for local VIPs")
	}
	link, err := netlink.LinkByName(manager.spec.LANIface)
	if err != nil {
		return fmt.Errorf("inspect LAN iface %q for local VIPs: %w", manager.spec.LANIface, err)
	}
	desired := make(map[netip.Addr]struct{}, len(vips))
	for _, vip := range vips {
		if !vip.Addr.IsValid() || !vip.Addr.Is4() {
			continue
		}
		desired[vip.Addr] = struct{}{}
		if _, tracked := manager.localVIPs[vip.Addr]; tracked {
			continue
		}
		existed, err := linkHasIPv4Address(link, vip.Addr, 32)
		if err != nil {
			return err
		}
		if existed {
			continue
		}
		addr := netlinkIPv4Address(vip.Addr, 32)
		if err := netlink.AddrReplace(link, addr); err != nil {
			if local, localErr := ipv4AddressExistsAnywhere(vip.Addr); localErr == nil && local {
				manager.warnings = append(manager.warnings, fmt.Sprintf("local VIP %s already exists outside %q; leaving existing address in place", vip.Addr, manager.spec.LANIface))
				continue
			}
			return fmt.Errorf("configure local VIP %s on %q: %w", vip.Addr, manager.spec.LANIface, err)
		}
		manager.localVIPs[vip.Addr] = struct{}{}
	}
	for addr := range manager.localVIPs {
		if _, keep := desired[addr]; keep {
			continue
		}
		if err := netlink.AddrDel(link, netlinkIPv4Address(addr, 32)); err != nil && !isNotFound(err) {
			return fmt.Errorf("remove local VIP %s from %q: %w", addr, manager.spec.LANIface, err)
		}
		delete(manager.localVIPs, addr)
	}
	return nil
}

func linkHasIPv4Address(link netlink.Link, addr netip.Addr, bits int) (bool, error) {
	if !addr.Is4() {
		return false, nil
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return false, fmt.Errorf("list addresses on %q: %w", link.Attrs().Name, err)
	}
	for _, existing := range addrs {
		if existing.IPNet == nil {
			continue
		}
		existingAddr, ok := ipv4AddrFromIP(existing.IP)
		if !ok || existingAddr != addr {
			continue
		}
		ones, total := existing.IPNet.Mask.Size()
		if ones == bits && total == 32 {
			return true, nil
		}
	}
	return false, nil
}

func firstIPv4AddressKeyForLink(link netlink.Link) uint32 {
	addr, _ := firstIPv4PrefixKeyForLink(link)
	return addr
}

func firstIPv4PrefixKeyForLink(link netlink.Link) (uint32, uint32) {
	if link == nil || link.Attrs() == nil {
		return 0, 0
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return 0, 0
	}
	for _, existing := range addrs {
		addr, ok := ipv4AddrFromIP(existing.IP)
		if !ok {
			continue
		}
		raw := addr.As4()
		if raw == ([4]byte{}) {
			continue
		}
		mask := uint32(0xffffffff)
		if existing.IPNet != nil {
			ones, total := existing.IPNet.Mask.Size()
			if total == 32 && ones >= 0 {
				mask = ipv4MaskKeyFromPrefixBits(ones)
			}
		}
		return binary.LittleEndian.Uint32(raw[:]), mask
	}
	return 0, 0
}

func ipv4MaskKeyFromPrefixBits(bits int) uint32 {
	if bits <= 0 {
		return 0
	}
	if bits >= 32 {
		return 0xffffffff
	}
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], ^uint32(0)<<(32-uint(bits)))
	return binary.LittleEndian.Uint32(raw[:])
}

func normalizeKernelUDPRXDirectLocalIPv4Mask(mask uint32) uint32 {
	if mask == 0 {
		return 0xffffffff
	}
	return mask
}

func ipv4AddressExistsAnywhere(addr netip.Addr) (bool, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return false, err
	}
	for _, link := range links {
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			continue
		}
		for _, existing := range addrs {
			existingAddr, ok := ipv4AddrFromIP(existing.IP)
			if ok && existingAddr == addr {
				return true, nil
			}
		}
	}
	return false, nil
}

func netlinkIPv4Address(addr netip.Addr, bits int) *netlink.Addr {
	ip := append(net.IP(nil), addr.AsSlice()...)
	return &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(bits, 32),
		},
	}
}

func parseAddress(cidr string) (*netlink.Addr, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse address %q: %w", cidr, err)
	}
	ipNet.IP = ip
	return &netlink.Addr{IPNet: ipNet}, nil
}

func sameIPNet(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.IP.Equal(b.IP) && len(a.Mask) == len(b.Mask) && string(a.Mask) == string(b.Mask)
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENODEV) {
		return true
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "no such file") ||
		strings.Contains(lower, "not found") ||
		strings.Contains(lower, "no such process") ||
		strings.Contains(lower, "cannot find device")
}

func createManagedLANBridge(iface string) (netlink.Link, bool, error) {
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return nil, false, fmt.Errorf("empty LAN interface name")
	}
	bridge := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: iface, TxQLen: managedLANTxQueueLen}}
	created := true
	if err := netlink.LinkAdd(bridge); err != nil {
		lower := strings.ToLower(err.Error())
		if !errors.Is(err, os.ErrExist) && !errors.Is(err, unix.EEXIST) && !strings.Contains(lower, "file exists") && !strings.Contains(lower, "object already exists") {
			return nil, false, err
		}
		created = false
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, false, err
	}
	if err := ensureManagedLANTxQueueLen(link); err != nil {
		if created {
			_ = netlink.LinkDel(link)
		}
		return nil, false, err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		if created {
			_ = netlink.LinkDel(link)
		}
		return nil, false, err
	}
	return link, created, nil
}

func ensureManagedLANTxQueueLen(link netlink.Link) error {
	if link == nil || link.Attrs() == nil {
		return fmt.Errorf("missing link attributes")
	}
	if link.Attrs().TxQLen > 0 {
		return nil
	}
	return netlink.LinkSetTxQLen(link, managedLANTxQueueLen)
}

func (manager *Manager) writeSysctl(path, value string) error {
	previous, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read sysctl %q: %w", path, err)
	}
	if _, exists := manager.restoreSysctls[path]; !exists {
		manager.restoreSysctls[path] = strings.TrimSpace(string(previous))
	}
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		return fmt.Errorf("write sysctl %q: %w", path, err)
	}
	return nil
}

func (manager *Manager) persistStateLocked() error {
	if manager.spec.PinPath == "" {
		return nil
	}
	state := persistedDataplaneState{
		Version:              persistedStateVersion,
		Spec:                 manager.spec,
		Snapshot:             manager.snapshot,
		Attached:             manager.attached,
		LinkAdded:            manager.primaryLANLinkAddedLocked(),
		AddressAdded:         manager.addressAdded,
		QdiscPrepared:        manager.qdiscPrepared,
		LANs:                 manager.persistedLANAttachSnapshotLocked(),
		LocalVIPs:            manager.localVIPSnapshotLocked(),
		RestoreSysctls:       cloneStringMap(manager.restoreSysctls),
		LANOffloadProtection: manager.lanOffloadProtection,
		ManagedCaptureRoutes: manager.managedCaptureRouteSnapshotLocked(),
		DeviceAccessProxyARP: manager.deviceAccessProxyARPSnapshotLocked(),
		NativeTunnelRoutes:   manager.nativeTunnelRouteSnapshotLocked(),
		ExperimentalTCPFlows: manager.expTCPFlows,
		KernelUDPFlows:       manager.kernelUDPFlows,
	}
	if manager.expTCPFastPath != nil && manager.expTCPFastPath.attachedXDP {
		state.ExperimentalTCPXDP = &persistedExperimentalTCPXDPState{
			Attached:    true,
			Underlay:    manager.spec.UnderlayIface,
			AttachFlags: manager.expTCPFastPath.xdpAttachFlags,
			AttachMode:  manager.expTCPFastPath.xdpAttachMode,
			BindMode:    manager.expTCPFastPath.afXDPBindMode,
		}
	} else if manager.kernelUDPXDPRXDirectAttached {
		state.ExperimentalTCPXDP = &persistedExperimentalTCPXDPState{
			Attached:    true,
			Underlay:    manager.spec.UnderlayIface,
			AttachFlags: manager.kernelUDPXDPRXDirectAttachFlags,
			AttachMode:  manager.kernelUDPXDPRXDirectAttachMode,
		}
	}
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(manager.spec.PinPath, "state.json")
	return os.WriteFile(path, payload, 0o600)
}

func (manager *Manager) persistedLANAttachSnapshotLocked() []persistedLANAttachState {
	lans := effectiveLANAttachSpecs(manager.spec)
	if len(lans) == 0 {
		return nil
	}
	out := make([]persistedLANAttachState, 0, len(lans))
	for i, lan := range lans {
		if lan.Iface == "" {
			continue
		}
		key := lanAddressStateKey(lan)
		linkAdded := manager.linkAddedLANs[key]
		addressAdded := manager.addressAddedLANs[key]
		qdiscPrepared := manager.qdiscPreparedLANs[key]
		if i == 0 {
			addressAdded = addressAdded || manager.addressAdded
			qdiscPrepared = qdiscPrepared || manager.qdiscPrepared
		}
		state := persistedLANAttachState{
			ID:                   lan.ID,
			Iface:                lan.Iface,
			LinkAdded:            linkAdded,
			AddressAdded:         addressAdded,
			QdiscPrepared:        qdiscPrepared,
			LANOffloadProtection: manager.lanOffloadProtections[lan.Iface],
		}
		out = append(out, state)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (manager *Manager) primaryLANLinkAddedLocked() bool {
	lans := effectiveLANAttachSpecs(manager.spec)
	if len(lans) == 0 {
		return false
	}
	return manager.linkAddedLANs[lanAddressStateKey(lans[0])]
}

func readPersistedDataplaneState(pinPath string) (persistedDataplaneState, bool, error) {
	if pinPath == "" {
		return persistedDataplaneState{}, false, nil
	}
	path := filepath.Join(pinPath, "state.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return persistedDataplaneState{}, false, nil
		}
		return persistedDataplaneState{}, false, fmt.Errorf("read dataplane state %q: %w", path, err)
	}
	var state persistedDataplaneState
	if err := json.Unmarshal(payload, &state); err != nil {
		return persistedDataplaneState{}, false, fmt.Errorf("decode dataplane state %q: %w", path, err)
	}
	return state, true, nil
}

func quarantinePersistedDataplaneState(pinPath string) error {
	if pinPath == "" {
		return nil
	}
	path := filepath.Join(pinPath, "state.json")
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat dataplane state %q: %w", path, err)
	}
	quarantine := filepath.Join(pinPath, fmt.Sprintf("state.corrupt-%d.json", time.Now().UnixNano()))
	if err := os.Rename(path, quarantine); err != nil {
		return fmt.Errorf("rename %q to %q: %w", path, quarantine, err)
	}
	return nil
}

func mergeCleanupSpec(persisted dataplane.AttachSpec, fallback dataplane.AttachSpec) dataplane.AttachSpec {
	if persisted.LANIface == "" {
		persisted.LANIface = fallback.LANIface
	}
	if persisted.UnderlayIface == "" {
		persisted.UnderlayIface = fallback.UnderlayIface
	}
	if persisted.Gateway == "" {
		persisted.Gateway = fallback.Gateway
	}
	if persisted.PinPath == "" {
		persisted.PinPath = fallback.PinPath
	}
	if len(persisted.LANs) == 0 {
		persisted.LANs = fallback.LANs
	}
	return persisted
}

func persistedLANLinkAddedMap(state persistedDataplaneState, spec dataplane.AttachSpec) map[string]bool {
	out := make(map[string]bool)
	lans := effectiveLANAttachSpecs(spec)
	byIface := make(map[string]dataplane.LANAttachSpec, len(lans))
	byID := make(map[string]dataplane.LANAttachSpec, len(lans))
	for _, lan := range lans {
		if lan.Iface != "" {
			byIface[lan.Iface] = lan
		}
		if lan.ID != "" {
			byID[lan.ID] = lan
		}
	}
	for _, lanState := range state.LANs {
		lan, ok := byIface[lanState.Iface]
		if !ok && lanState.ID != "" {
			lan, ok = byID[lanState.ID]
		}
		if !ok {
			lan = dataplane.LANAttachSpec{ID: lanState.ID, Iface: lanState.Iface}
		}
		out[lanAddressStateKey(lan)] = lanState.LinkAdded
	}
	if len(state.LANs) == 0 && state.LinkAdded {
		primary := normalizeAttachSpec(spec)
		if len(effectiveLANAttachSpecs(primary)) > 0 {
			out[lanAddressStateKey(effectiveLANAttachSpecs(primary)[0])] = true
		}
	}
	return out
}

func persistedLANAddressAddedMap(state persistedDataplaneState, spec dataplane.AttachSpec) map[string]bool {
	out := make(map[string]bool)
	lans := effectiveLANAttachSpecs(spec)
	byIface := make(map[string]dataplane.LANAttachSpec, len(lans))
	byID := make(map[string]dataplane.LANAttachSpec, len(lans))
	for _, lan := range lans {
		if lan.Iface != "" {
			byIface[lan.Iface] = lan
		}
		if lan.ID != "" {
			byID[lan.ID] = lan
		}
	}
	for _, lanState := range state.LANs {
		lan, ok := byIface[lanState.Iface]
		if !ok && lanState.ID != "" {
			lan, ok = byID[lanState.ID]
		}
		if !ok {
			lan = dataplane.LANAttachSpec{ID: lanState.ID, Iface: lanState.Iface}
		}
		out[lanAddressStateKey(lan)] = lanState.AddressAdded
	}
	if len(state.LANs) == 0 && state.AddressAdded {
		primary := normalizeAttachSpec(spec)
		if len(effectiveLANAttachSpecs(primary)) > 0 {
			out[lanAddressStateKey(effectiveLANAttachSpecs(primary)[0])] = true
		}
	}
	return out
}

func persistedLANQdiscPreparedMap(state persistedDataplaneState, spec dataplane.AttachSpec) map[string]bool {
	out := make(map[string]bool)
	lans := effectiveLANAttachSpecs(spec)
	byIface := make(map[string]dataplane.LANAttachSpec, len(lans))
	byID := make(map[string]dataplane.LANAttachSpec, len(lans))
	for _, lan := range lans {
		if lan.Iface != "" {
			byIface[lan.Iface] = lan
		}
		if lan.ID != "" {
			byID[lan.ID] = lan
		}
	}
	for _, lanState := range state.LANs {
		lan, ok := byIface[lanState.Iface]
		if !ok && lanState.ID != "" {
			lan, ok = byID[lanState.ID]
		}
		if !ok {
			lan = dataplane.LANAttachSpec{ID: lanState.ID, Iface: lanState.Iface}
		}
		out[lanAddressStateKey(lan)] = lanState.QdiscPrepared
	}
	if len(state.LANs) == 0 && state.QdiscPrepared {
		primary := normalizeAttachSpec(spec)
		if len(effectiveLANAttachSpecs(primary)) > 0 {
			out[lanAddressStateKey(effectiveLANAttachSpecs(primary)[0])] = true
		}
	}
	return out
}

func persistedLANOffloadProtectionMap(state persistedDataplaneState) map[string]*persistedLinkOffloadState {
	out := make(map[string]*persistedLinkOffloadState)
	for _, lanState := range state.LANs {
		if lanState.LANOffloadProtection == nil || lanState.LANOffloadProtection.Iface == "" {
			continue
		}
		out[lanState.LANOffloadProtection.Iface] = lanState.LANOffloadProtection
	}
	if state.LANOffloadProtection != nil && state.LANOffloadProtection.Iface != "" {
		out[state.LANOffloadProtection.Iface] = state.LANOffloadProtection
	}
	return out
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func (manager *Manager) localVIPSnapshotLocked() []dataplane.LocalVIP {
	if len(manager.localVIPs) == 0 {
		return nil
	}
	addrs := make([]netip.Addr, 0, len(manager.localVIPs))
	for addr := range manager.localVIPs {
		addrs = append(addrs, addr)
	}
	sort.Slice(addrs, func(i, j int) bool {
		return addrs[i].Less(addrs[j])
	})
	vips := make([]dataplane.LocalVIP, 0, len(addrs))
	for _, addr := range addrs {
		vips = append(vips, dataplane.LocalVIP{Addr: addr})
	}
	return vips
}

func localVIPMap(vips []dataplane.LocalVIP) map[netip.Addr]struct{} {
	out := make(map[netip.Addr]struct{}, len(vips))
	for _, vip := range vips {
		if vip.Addr.IsValid() {
			out[vip.Addr] = struct{}{}
		}
	}
	return out
}
