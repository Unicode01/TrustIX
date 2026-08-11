package tixtcp

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/transport"
	"trustix.local/trustix/internal/transport/bind"
	"trustix.local/trustix/internal/transport/stream"
)

const tixTCPKernelCryptoReplayWindow = 65536

// AF_XDP can deliver short bursts much faster than userspace crypto/inject can
// drain them. Keep the default bounded; oversized queues can pin hundreds of
// MiB of borrowed packet buffers per session when downstream stalls.
const (
	tixTCPSessionBufferDefault           = 512
	tixTCPSessionBufferMax               = 8192
	tixTCPFragmentPayloadSize            = 2000
	tixTCPFragmentPayloadMax             = 32000
	tixTCPKernelFragmentPayloadMax       = 4079
	tixTCPKernelSealBeforeMax            = 512*1024 - 16
	tixTCPSecureFrameOverhead            = 24 + 16
	tixTCPUserspaceCryptoPayloadHint     = tixTCPFragmentPayloadSize
	tixTCPMaxFragments                   = 256
	tixTCPReassemblyTTL                  = 30 * time.Second
	tixTCPReassemblyMaxAssembliesDefault = 1024
	tixTCPReassemblyMaxAssembliesMax     = 8192
	tixTCPRecvCoalesceDelayMax           = 10 * time.Millisecond
	tixTCPRecvDrainDefault               = 0
	tixTCPRecvDrainMax                   = 256
	tixTCPTIXBVersion                    = 1
	tixTCPTIXBHeaderLen                  = 8
	tixTCPTIXBItemHeaderLen              = 2
	tixTCPTIXBMaxPackets                 = 256
)

const (
	tixTCPStatFragmentedPacketsSent                   = "tix_tcp_fragmented_packets_sent"
	tixTCPStatFragmentsSent                           = "tix_tcp_fragments_sent"
	tixTCPStatFragmentsReceived                       = "tix_tcp_fragments_received"
	tixTCPStatFragmentedPacketsReceived               = "tix_tcp_fragmented_packets_received"
	tixTCPStatFragmentsReassembled                    = "tix_tcp_fragments_reassembled"
	tixTCPStatFragmentAssembliesCurrent               = "tix_tcp_fragment_assemblies_current"
	tixTCPStatFragmentDuplicates                      = "tix_tcp_fragment_duplicates"
	tixTCPStatFragmentExpiredAssemblies               = "tix_tcp_fragment_expired_assemblies"
	tixTCPStatFragmentExpiredFragments                = "tix_tcp_fragment_expired_fragments"
	tixTCPStatFragmentMismatches                      = "tix_tcp_fragment_mismatches"
	tixTCPStatFragmentRejects                         = "tix_tcp_fragment_rejects"
	tixTCPStatFragmentPayloadSize                     = "tix_tcp_fragment_payload_size"
	tixTCPStatTIXBExpandedPackets                     = "tix_tcp_tixb_expanded_packets"
	tixTCPStatTIXBExpandedItems                       = "tix_tcp_tixb_expanded_items"
	tixTCPStatFullPlaintextKernel                     = "tix_tcp_full_plaintext_kernel_datapath"
	tixTCPStatFullSecureKernel                        = "tix_tcp_full_secure_kernel_datapath"
	tixTCPStatInnerTCPChecksumPartialLocal            = "tix_tcp_inner_tcp_checksum_partial_local"
	tixTCPStatInnerTCPChecksumPartialPeer             = "tix_tcp_inner_tcp_checksum_partial_peer"
	tixTCPStatInnerTCPChecksumPartialNegotiated       = "tix_tcp_inner_tcp_checksum_partial_negotiated"
	tixTCPStatSecureInnerTCPChecksumPartialLocal      = "tix_tcp_secure_inner_tcp_checksum_partial_local"
	tixTCPStatSecureInnerTCPChecksumPartialPeer       = "tix_tcp_secure_inner_tcp_checksum_partial_peer"
	tixTCPStatSecureInnerTCPChecksumPartialNegotiated = "tix_tcp_secure_inner_tcp_checksum_partial_negotiated"
	tixTCPStatInnerGSOLocal                           = "tix_tcp_inner_gso_local"
	tixTCPStatInnerGSOPeer                            = "tix_tcp_inner_gso_peer"
	tixTCPStatInnerGSONegotiated                      = "tix_tcp_inner_gso_negotiated"
	tixTCPStatPortShardingLocal                       = "tix_tcp_port_sharding_local"
	tixTCPStatPortShardingPeer                        = "tix_tcp_port_sharding_peer"
	tixTCPStatPortShardingNegotiated                  = "tix_tcp_port_sharding_negotiated"
	tixTCPStatKernelDatapathReadyLocal                = "tix_tcp_kernel_datapath_ready_local"
	tixTCPStatKernelDatapathReadyPeer                 = "tix_tcp_kernel_datapath_ready_peer"
	tixTCPStatKernelDatapathReadyNegotiated           = "tix_tcp_kernel_datapath_ready_negotiated"
	tixTCPStatCapabilityWithdrawals                   = "tix_tcp_capability_withdrawals"
	tixTCPStatCapabilityWithdrawalAcks                = "tix_tcp_capability_withdrawal_acks"
	tixTCPStatCapabilityWithdrawalAckTimeouts         = "tix_tcp_capability_withdrawal_ack_timeouts"
)

const (
	tixTCPProviderFullPlaintextKernel = "kernel_datapath_full_plaintext"
	tixTCPProviderFullSecureKernel    = "kernel_datapath_full_secure"
)

const (
	tixTCPCompatTCPPrimerDefault                  = true
	tixTCPCompatTCPPrimerTimeout                  = 3 * time.Second
	tixTCPCompatHandshakePriority                 = 200 * time.Millisecond
	tixTCPCompatPriorityBuffer                    = 8
	tixTCPCompatControlVersion                    = 1
	tixTCPCompatControlInitType                   = 1
	tixTCPCompatControlInitLen                    = 16
	tixTCPCompatControlInitOldLen                 = 14
	tixTCPCompatControlCapabilitiesType           = 4
	tixTCPCompatControlCapabilitiesLen            = 14
	tixTCPCompatControlCapabilityUpdateType       = 5
	tixTCPCompatControlCapabilityAckType          = 6
	tixTCPCompatControlCapabilityTransitionLen    = 18
	tixTCPCompatCapabilityRefreshInterval         = 2 * time.Second
	tixTCPCompatInnerGSOCapabilityRefreshInterval = 50 * time.Millisecond
	tixTCPCapabilityAckTimeoutDefault             = 2 * time.Second
	tixTCPCapabilityWithdrawGraceDefault          = 12 * time.Second
	tixTCPCapabilityWithdrawLegacyGraceDefault    = 30 * time.Second
	tixTCPCapabilityTransitionDurationMax         = 5 * time.Minute
	tixTCPCapabilityInnerTCPChecksumPartial       = uint64(1 << 0)
	tixTCPCapabilityInnerGSO                      = uint64(1 << 1)
	tixTCPCapabilityPortSharding                  = uint64(1 << 2)
	tixTCPCapabilitySecureInnerTCPChecksumPartial = uint64(1 << 3)
	// KernelDatapathReady is a receive-side commit barrier. A sender must not
	// use any kernel-only wire feature unless the peer advertises this bit.
	tixTCPCapabilityKernelDatapathReady = uint64(1 << 4)
	tixTCPKnownCapabilities             = tixTCPCapabilityInnerTCPChecksumPartial | tixTCPCapabilityInnerGSO | tixTCPCapabilityPortSharding | tixTCPCapabilitySecureInnerTCPChecksumPartial | tixTCPCapabilityKernelDatapathReady
)

var (
	errTIXTCPCapabilityAdvertisement = errors.New("tix_tcp capability advertisement failed")
	errTIXTCPCapabilityCommit        = errors.New("tix_tcp capability state commit failed")
	errTIXTCPCapabilityReconnect     = errors.New("tix_tcp capability change requires session reconnect")
)

var (
	tixTCPCompatControlMagic = [4]byte{'T', 'I', 'X', 'C'}
	tixTCPSecureHelloMagic   = [4]byte{'T', 'I', 'X', 'H'}
	tixTCPTIXBMagic          = [4]byte{'T', 'I', 'X', 'B'}
)

var tixTCPPacketBatchPool = sync.Pool{
	New: func() any {
		return &tixTCPPacketBatch{
			packets: make([][]byte, 0, 256),
		}
	},
}

type Options struct {
	CryptoPlacement func() dataplane.CryptoPlacement
	Encryption      func() string
}

type Transport struct {
	provider dataplane.TIXTCPProvider
	options  Options
}

func New(provider dataplane.TIXTCPProvider, options ...Options) *Transport {
	var opts Options
	if len(options) > 0 {
		opts = options[0]
	}
	return &Transport{provider: provider, options: opts}
}

func tixTCPSessionBuffer() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_TIX_TCP_SESSION_BUFFER"))
	if value == "" {
		return tixTCPSessionBufferDefault
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return tixTCPSessionBufferDefault
	}
	if parsed > tixTCPSessionBufferMax {
		return tixTCPSessionBufferMax
	}
	return parsed
}

func tixTCPReassemblyMaxAssemblies() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_TIX_TCP_REASSEMBLY_MAX_ASSEMBLIES"))
	if value == "" {
		return tixTCPReassemblyMaxAssembliesDefault
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return tixTCPReassemblyMaxAssembliesDefault
	}
	if parsed > tixTCPReassemblyMaxAssembliesMax {
		return tixTCPReassemblyMaxAssembliesMax
	}
	return parsed
}

func tixTCPRecvCoalesceDelay() time.Duration {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_TIX_TCP_RECV_COALESCE_DELAY"))
	if value == "" {
		value = strings.TrimSpace(os.Getenv("TRUSTIX_TIX_TCP_RECV_BATCH_DELAY"))
	}
	if value == "" {
		return 0
	}
	if parsed, err := time.ParseDuration(value); err == nil {
		if parsed < 0 {
			return 0
		}
		if parsed > tixTCPRecvCoalesceDelayMax {
			return tixTCPRecvCoalesceDelayMax
		}
		return parsed
	}
	micros, err := strconv.Atoi(value)
	if err != nil || micros <= 0 {
		return 0
	}
	delay := time.Duration(micros) * time.Microsecond
	if delay > tixTCPRecvCoalesceDelayMax {
		return tixTCPRecvCoalesceDelayMax
	}
	return delay
}

func tixTCPRecvDrainBatchLimit() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_TIX_TCP_RECV_DRAIN_BATCHES"))
	if value == "" {
		return tixTCPRecvDrainDefault
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return tixTCPRecvDrainDefault
	}
	if parsed > tixTCPRecvDrainMax {
		return tixTCPRecvDrainMax
	}
	return parsed
}

var tixTCPRecvCoalesceWaitHook func() // test hook; nil in production.

func (transportImpl *Transport) Name() transport.Protocol {
	return transport.ProtocolTIXTCP
}

func (transportImpl *Transport) Probe(ctx context.Context, peer transport.Peer) transport.ProbeResult {
	if tixTCPCompatStreamDataEnabled() {
		hasTIXTCPEndpoint := false
		for _, endpoint := range peer.Endpoints {
			if endpoint.Transport != transport.ProtocolTIXTCP || endpoint.Address == "" {
				continue
			}
			hasTIXTCPEndpoint = true
			if tixTCPCompatPrimerEnabled() && tixTCPCompatPrimerAddressSupported(endpoint.Address, false) {
				return transport.ProbeResult{Healthy: true, CheckedAt: time.Now()}
			}
		}
		if hasTIXTCPEndpoint && transportImpl.provider == nil {
			return transport.ProbeResult{Healthy: false, Error: "tix_tcp compat stream requires a supported TCP primer address", CheckedAt: time.Now()}
		}
	}
	if transportImpl.provider == nil {
		return transport.ProbeResult{Healthy: false, Error: "tix_tcp dataplane provider is unavailable", CheckedAt: time.Now()}
	}
	status, err := transportImpl.provider.TIXTCPStatus(ctx)
	if err != nil {
		return transport.ProbeResult{Healthy: false, Error: err.Error(), CheckedAt: time.Now()}
	}
	if !status.Available || !status.Reinject {
		return transport.ProbeResult{Healthy: false, Error: tixTCPReinjectUnavailableError(status).Error(), CheckedAt: time.Now()}
	}
	for _, endpoint := range peer.Endpoints {
		if endpoint.Transport == transport.ProtocolTIXTCP && endpoint.Address != "" {
			if _, err := transportImpl.selectCryptoPlacementFromStatus(status, endpoint.Encryption); err != nil {
				return transport.ProbeResult{Healthy: false, Error: err.Error(), CheckedAt: time.Now()}
			}
			return transport.ProbeResult{Healthy: true, CheckedAt: time.Now()}
		}
	}
	return transport.ProbeResult{Healthy: false, Error: "no tix_tcp endpoint", CheckedAt: time.Now()}
}

func (transportImpl *Transport) Dial(ctx context.Context, peer transport.Peer, tlsConf *tls.Config) (transport.Session, error) {
	var lastErr error
	for _, endpoint := range peer.Endpoints {
		if endpoint.Transport != transport.ProtocolTIXTCP || endpoint.Address == "" {
			continue
		}
		if tixTCPCompatStreamDataEnabled() {
			primerConn, err := dialTIXTCPCompatPrimer(ctx, endpoint)
			if err != nil {
				lastErr = err
				if tixTCPCompatPrimerRequired() || transportImpl.provider == nil {
					return nil, err
				}
			}
			if primerConn != nil {
				return &compatStreamSession{
					Session:  stream.NewSession(primerConn),
					peer:     peer.ID,
					endpoint: endpoint.Name,
				}, nil
			}
		}
		if transportImpl.provider == nil {
			if lastErr != nil {
				return nil, fmt.Errorf("tix_tcp compat stream unavailable and dataplane provider is unavailable: %w", lastErr)
			}
			return nil, fmt.Errorf("tix_tcp dataplane provider is unavailable")
		}
		status, err := transportImpl.provider.TIXTCPStatus(ctx)
		if err != nil {
			return nil, err
		}
		if !status.Available || !status.Reinject {
			return nil, tixTCPReinjectUnavailableError(status)
		}
		placement, err := transportImpl.selectCryptoPlacementFromStatus(status, endpoint.Encryption)
		if err != nil {
			return nil, err
		}
		fullPlaintextKernel := tixTCPFullPlaintextKernelDatapathStatus(status)
		fullSecureKernel := tixTCPFullSecureKernelDatapathStatus(status)
		fullKernel := fullPlaintextKernel || fullSecureKernel
		flowID, err := randomFlowID()
		if err != nil {
			return nil, err
		}
		primerConn, err := dialTIXTCPCompatPrimer(ctx, endpoint)
		if err != nil {
			if tixTCPCompatPrimerRequired() || fullKernel {
				return nil, err
			}
			primerConn = nil
		}
		if primerConn == nil && fullKernel {
			return nil, fmt.Errorf("tix_tcp full kernel datapath requires compat TCP control primer for endpoint %q", endpoint.Name)
		}
		flow := tixTCPCompatOutboundFlow(flowID, peer.ID, primerConn, endpoint, placement)
		if fullKernel && !tixTCPCompatFlowHasCompleteTuple(flow) {
			closeErr := tixTCPCleanupError("close compat primer", primerConn.Close())
			return nil, errors.Join(
				fmt.Errorf("tix_tcp full kernel datapath could not derive an IPv4 data tuple for endpoint %q", endpoint.Name),
				closeErr,
			)
		}
		if err := transportImpl.provider.InstallTIXTCPFlows(ctx, []dataplane.TIXTCPFlow{flow}); err != nil {
			var closeErr error
			if primerConn != nil {
				closeErr = tixTCPCleanupError("close compat primer", primerConn.Close())
			}
			return nil, errors.Join(err, closeErr)
		}
		localCapabilities := tixTCPLocalCapabilities(status)
		var compatControl *stream.Session
		if primerConn != nil {
			compatControl = stream.NewSession(primerConn)
			if err := compatControl.SendPacket(encodeTIXTCPCompatControlInit(flowID)); err != nil {
				closeErr := tixTCPCleanupError("close compat control", compatControl.Close())
				var deleteErr error
				if deleter, ok := transportImpl.provider.(dataplane.TIXTCPFlowDeleter); ok {
					deleteErr = tixTCPCleanupError("delete tix_tcp flow", deleter.DeleteTIXTCPFlows(context.Background(), []uint64{flowID}))
				}
				return nil, errors.Join(fmt.Errorf("send tix_tcp compat control init: %w", err), closeErr, deleteErr)
			}
		}
		subscription, err := transportImpl.subscribeFlow(ctx, flowID)
		if err != nil {
			var closeErr error
			if compatControl != nil {
				closeErr = tixTCPCleanupError("close compat control", compatControl.Close())
			}
			var deleteErr error
			if deleter, ok := transportImpl.provider.(dataplane.TIXTCPFlowDeleter); ok {
				deleteErr = tixTCPCleanupError("delete tix_tcp flow", deleter.DeleteTIXTCPFlows(context.Background(), []uint64{flowID}))
			}
			return nil, errors.Join(err, closeErr, deleteErr)
		}
		session := newSession(transportImpl.provider, subscription, flowID, peer.ID, endpoint.Name, placement, flow.LocalAddress, flow.RemoteAddress)
		session.compatControl = compatControl
		session.fullPlaintextKernelDatapath = fullPlaintextKernel
		session.fullSecureKernelDatapath = fullSecureKernel
		session.localCapabilities.Store(localCapabilities)
		session.enableCompatPriority()
		// Dial contexts are commonly canceled after setup; the session receive
		// pump must live until Session.Close closes the subscription/input.
		go session.readSubscription(context.Background())
		go session.readCompatControl(context.Background())
		go session.monitorLocalCapabilities(context.Background())
		return session, nil
	}
	return nil, fmt.Errorf("peer %q has no dialable tix_tcp endpoint", peer.ID)
}

func (transportImpl *Transport) subscribeFlow(ctx context.Context, flowID uint64) (dataplane.TIXTCPSubscription, error) {
	if subscriber, ok := transportImpl.provider.(dataplane.TIXTCPFlowSubscriber); ok {
		return subscriber.SubscribeTIXTCPFlow(ctx, flowID, tixTCPSessionBuffer())
	}
	return transportImpl.provider.SubscribeTIXTCP(ctx, tixTCPSessionBuffer())
}

func (transportImpl *Transport) Listen(ctx context.Context, ep transport.Endpoint, tlsConf *tls.Config) (transport.Listener, error) {
	if ep.Transport != transport.ProtocolTIXTCP {
		return nil, fmt.Errorf("endpoint %q transport is %q, want tix_tcp", ep.Name, ep.Transport)
	}
	if tixTCPCompatStreamDataEnabled() {
		listener, err := transportImpl.listenCompatStream(ctx, ep)
		if err != nil {
			return nil, err
		}
		if listener != nil {
			return listener, nil
		}
	}
	if transportImpl.provider == nil {
		return nil, fmt.Errorf("tix_tcp dataplane provider is unavailable")
	}
	status, err := transportImpl.provider.TIXTCPStatus(ctx)
	if err != nil {
		return nil, err
	}
	if !status.Available || !status.Reinject {
		return nil, tixTCPReinjectUnavailableError(status)
	}
	placement, err := transportImpl.selectCryptoPlacementFromStatus(status, ep.Encryption)
	if err != nil {
		return nil, err
	}
	fullPlaintextKernel := tixTCPFullPlaintextKernelDatapathStatus(status)
	fullSecureKernel := tixTCPFullSecureKernelDatapathStatus(status)
	fullKernel := fullPlaintextKernel || fullSecureKernel
	subscription, err := transportImpl.provider.SubscribeTIXTCP(ctx, tixTCPSessionBuffer())
	if err != nil {
		return nil, err
	}
	listener := &listener{
		provider:                    transportImpl.provider,
		endpoint:                    ep,
		subscription:                subscription,
		acceptCh:                    make(chan transport.Session, 64),
		compatAcceptCh:              make(chan transport.Session, 64),
		done:                        make(chan struct{}),
		sessions:                    make(map[uint64]*session),
		placement:                   placement,
		fullPlaintextKernelDatapath: fullPlaintextKernel,
		fullSecureKernelDatapath:    fullSecureKernel,
	}
	if compatListener, err := listenTIXTCPCompatPrimer(ep.Listen); err != nil {
		return nil, errors.Join(err, tixTCPCleanupError("close tix_tcp subscription", subscription.Close()))
	} else {
		listener.compatListener = compatListener
		listener.primerFlowRequired = compatListener != nil
	}
	if fullKernel && listener.compatListener == nil {
		return nil, errors.Join(
			fmt.Errorf("tix_tcp full kernel datapath requires compat TCP control listener for endpoint %q", ep.Name),
			tixTCPCleanupError("close tix_tcp subscription", subscription.Close()),
		)
	}
	go listener.readSubscription(ctx)
	go listener.acceptCompatPrimers()
	return listener, nil
}

func (transportImpl *Transport) listenCompatStream(ctx context.Context, ep transport.Endpoint) (transport.Listener, error) {
	compatListener, err := listenTIXTCPCompatPrimer(ep.Listen)
	if err != nil {
		return nil, err
	}
	if compatListener == nil {
		if transportImpl.provider == nil {
			return nil, fmt.Errorf("tix_tcp compat stream requires a supported TCP primer listen address")
		}
		return nil, nil
	}
	listener := &listener{
		provider:       transportImpl.provider,
		endpoint:       ep,
		acceptCh:       make(chan transport.Session, 64),
		compatAcceptCh: make(chan transport.Session, 64),
		done:           make(chan struct{}),
		sessions:       make(map[uint64]*session),
		placement:      dataplane.CryptoPlacementUserspace,
		compatListener: compatListener,
	}
	go listener.closeOnContext(ctx)
	go listener.acceptCompatPrimers()
	return listener, nil
}

type listener struct {
	provider                    dataplane.TIXTCPProvider
	endpoint                    transport.Endpoint
	subscription                dataplane.TIXTCPSubscription
	acceptCh                    chan transport.Session
	compatAcceptCh              chan transport.Session
	done                        chan struct{}
	closeOnce                   sync.Once
	closeErr                    error
	mu                          sync.Mutex
	sessions                    map[uint64]*session
	placement                   dataplane.CryptoPlacement
	compatListener              net.Listener
	primerFlowRequired          bool
	fullPlaintextKernelDatapath bool
	fullSecureKernelDatapath    bool
}

func (transportImpl *Transport) requestedCryptoPlacement() dataplane.CryptoPlacement {
	if transportImpl.options.CryptoPlacement == nil {
		return dataplane.CryptoPlacementAuto
	}
	return normalizeCryptoPlacement(transportImpl.options.CryptoPlacement())
}

func (transportImpl *Transport) selectCryptoPlacement(ctx context.Context, encryption string) (dataplane.CryptoPlacement, error) {
	status, err := transportImpl.provider.TIXTCPStatus(ctx)
	if err != nil {
		return "", err
	}
	if !status.Available || !status.Reinject {
		return "", tixTCPReinjectUnavailableError(status)
	}
	return transportImpl.selectCryptoPlacementFromStatus(status, encryption)
}

func tixTCPReinjectUnavailableError(status dataplane.TIXTCPStatus) error {
	reason := strings.TrimSpace(status.FastPathFallback)
	if reason == "" {
		for _, note := range status.Notes {
			note = strings.TrimSpace(note)
			if strings.Contains(note, "unavailable:") {
				reason = note
				break
			}
		}
	}
	if reason != "" {
		return fmt.Errorf("tix_tcp TC/XDP reinject is unavailable: %s", reason)
	}
	provider := strings.TrimSpace(status.Provider)
	if provider == "" {
		provider = "none"
	}
	return fmt.Errorf("tix_tcp TC/XDP reinject is unavailable: provider=%s available=%t reinject=%t", provider, status.Available, status.Reinject)
}

func (transportImpl *Transport) selectCryptoPlacementFromStatus(status dataplane.TIXTCPStatus, encryption string) (dataplane.CryptoPlacement, error) {
	if tixTCPPlaintextEncryption(transportImpl.effectiveEncryption(encryption)) {
		if tixTCPFullSecureKernelDatapathStatus(status) {
			return "", fmt.Errorf("tix_tcp full secure kernel datapath requires secure encryption")
		}
		return dataplane.CryptoPlacementUserspace, nil
	}
	placement, err := selectCryptoPlacement(transportImpl.requestedCryptoPlacement(), status)
	if err != nil {
		return "", err
	}
	if tixTCPFullSecureKernelDatapathStatus(status) && placement != dataplane.CryptoPlacementKernel {
		return "", fmt.Errorf("tix_tcp full secure kernel datapath requires kernel crypto")
	}
	return placement, nil
}

func tixTCPFullPlaintextKernelDatapathStatus(status dataplane.TIXTCPStatus) bool {
	return strings.EqualFold(strings.TrimSpace(status.Provider), tixTCPProviderFullPlaintextKernel)
}

func tixTCPFullSecureKernelDatapathStatus(status dataplane.TIXTCPStatus) bool {
	return strings.EqualFold(strings.TrimSpace(status.Provider), tixTCPProviderFullSecureKernel)
}

func (transportImpl *Transport) effectiveEncryption(encryption string) string {
	if strings.TrimSpace(encryption) != "" {
		return encryption
	}
	if transportImpl.options.Encryption != nil {
		return transportImpl.options.Encryption()
	}
	return ""
}

func tixTCPPlaintextEncryption(encryption string) bool {
	switch strings.ToLower(strings.TrimSpace(encryption)) {
	case "plaintext", "none", "disabled", "off":
		return true
	default:
		return false
	}
}

func selectCryptoPlacement(requested dataplane.CryptoPlacement, status dataplane.TIXTCPStatus) (dataplane.CryptoPlacement, error) {
	requested = normalizeCryptoPlacement(requested)
	switch requested {
	case dataplane.CryptoPlacementKernel:
		if status.KernelCrypto {
			return dataplane.CryptoPlacementKernel, nil
		}
		reason := status.KernelCryptoReason
		if reason == "" {
			reason = "kernel crypto provider is not available"
		}
		return "", fmt.Errorf("tix_tcp kernel crypto requested but unavailable: %s", reason)
	case dataplane.CryptoPlacementAuto:
		preferred := normalizeCryptoPlacement(status.PreferredCrypto)
		if preferred == dataplane.CryptoPlacementKernel && status.KernelCrypto {
			return dataplane.CryptoPlacementKernel, nil
		}
		if status.KernelCrypto {
			return dataplane.CryptoPlacementKernel, nil
		}
		if status.UserspaceCrypto {
			return dataplane.CryptoPlacementUserspace, nil
		}
		return "", fmt.Errorf("tix_tcp has no available crypto placement")
	case dataplane.CryptoPlacementUserspace:
		if status.UserspaceCrypto {
			return dataplane.CryptoPlacementUserspace, nil
		}
		return "", fmt.Errorf("tix_tcp userspace crypto is not available")
	default:
		return "", fmt.Errorf("tix_tcp crypto placement %q is unsupported", requested)
	}
}

func normalizeCryptoPlacement(placement dataplane.CryptoPlacement) dataplane.CryptoPlacement {
	switch placement {
	case "", dataplane.CryptoPlacementUserspace:
		return dataplane.CryptoPlacementUserspace
	case dataplane.CryptoPlacementAuto:
		return dataplane.CryptoPlacementAuto
	case dataplane.CryptoPlacementKernel:
		return dataplane.CryptoPlacementKernel
	default:
		return placement
	}
}

func (listener *listener) Accept(ctx context.Context) (transport.Session, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-listener.done:
		return nil, fmt.Errorf("tix_tcp listener is closed")
	case session := <-listener.compatAcceptCh:
		if session == nil {
			return nil, fmt.Errorf("tix_tcp listener is closed")
		}
		return session, nil
	case session := <-listener.acceptCh:
		if session == nil {
			return nil, fmt.Errorf("tix_tcp listener is closed")
		}
		return session, nil
	}
}

func (listener *listener) Close() error {
	listener.closeOnce.Do(func() {
		close(listener.done)
		var errs []error
		if listener.subscription != nil {
			if err := listener.subscription.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close tix_tcp subscription: %w", err))
			}
		}
		if listener.compatListener != nil {
			if err := listener.compatListener.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close tix_tcp compat listener: %w", err))
			}
		}
		listener.mu.Lock()
		for flowID, session := range listener.sessions {
			session.closeInput()
			delete(listener.sessions, flowID)
		}
		listener.mu.Unlock()
		listener.closeErr = errors.Join(errs...)
	})
	return listener.closeErr
}

func tixTCPCleanupError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func (listener *listener) closeOnContext(ctx context.Context) {
	<-ctx.Done()
	transport.ObserveAsyncError("close tix_tcp listener after context cancellation", listener.Close())
}

func (listener *listener) acceptCompatPrimers() {
	if listener.compatListener == nil {
		return
	}
	for {
		conn, err := listener.compatListener.Accept()
		if err != nil {
			select {
			case <-listener.done:
				return
			default:
				return
			}
		}
		if err := tuneTIXTCPCompatConn(conn); err != nil {
			transport.ObserveAsyncError(
				"reject tix_tcp compat connection after socket tuning failure",
				errors.Join(err, tixTCPCleanupError("close untuned tix_tcp compat connection", conn.Close())),
			)
			continue
		}
		if tixTCPCompatStreamDataEnabled() {
			select {
			case <-listener.done:
				transport.ObserveAsyncError("close rejected tix_tcp compat stream", conn.Close())
				return
			case listener.compatAcceptCh <- &compatStreamSession{
				Session:  stream.NewSession(conn),
				endpoint: listener.endpoint.Name,
			}:
			default:
				transport.ObserveAsyncError("close overflowed tix_tcp compat stream", conn.Close())
			}
			continue
		}
		control, init, err := acceptTIXTCPCompatControl(conn)
		if err != nil {
			transport.ObserveAsyncError("close failed tix_tcp compat connection", conn.Close())
			continue
		}
		flow := tixTCPCompatInboundFlow(init, conn, listener.endpoint, listener.placement)
		if err := listener.provider.InstallTIXTCPFlows(context.Background(), []dataplane.TIXTCPFlow{flow}); err != nil {
			transport.ObserveAsyncError("close tix_tcp compat control after flow install failure", control.Close())
			continue
		}
		sess := newSession(listener.provider, nil, init.flowID, "", listener.endpoint.Name, listener.placement, flow.LocalAddress, flow.RemoteAddress)
		sess.compatControl = control
		sess.fullPlaintextKernelDatapath = listener.fullPlaintextKernelDatapath
		sess.fullSecureKernelDatapath = listener.fullSecureKernelDatapath
		sess.localCapabilities.Store(listener.currentLocalCapabilities())
		sess.enableCompatPriority()
		listener.mu.Lock()
		if existing := listener.sessions[init.flowID]; existing != nil && !existing.isClosed() {
			listener.mu.Unlock()
			transport.ObserveAsyncError("close duplicate tix_tcp compat control", control.Close())
			continue
		}
		listener.sessions[init.flowID] = sess
		select {
		case <-listener.done:
			delete(listener.sessions, init.flowID)
			listener.mu.Unlock()
			transport.ObserveAsyncError("close tix_tcp compat control during listener shutdown", control.Close())
			return
		case listener.acceptCh <- sess:
			listener.mu.Unlock()
			listener.forgetSessionWhenClosed(init.flowID, sess)
			go sess.readCompatControl(context.Background())
			go sess.monitorLocalCapabilities(context.Background())
		default:
			delete(listener.sessions, init.flowID)
			listener.mu.Unlock()
			transport.ObserveAsyncError("close overflowed tix_tcp compat control", control.Close())
			if deleter, ok := listener.provider.(dataplane.TIXTCPFlowDeleter); ok {
				transport.ObserveAsyncError("delete overflowed tix_tcp compat flow", deleter.DeleteTIXTCPFlows(context.Background(), []uint64{init.flowID}))
			}
		}
	}
}

func (listener *listener) currentLocalCapabilities() uint64 {
	if listener == nil || listener.provider == nil ||
		(!listener.fullPlaintextKernelDatapath && !listener.fullSecureKernelDatapath) {
		return 0
	}
	capabilities, err := tixTCPProviderLocalCapabilities(context.Background(), listener.provider)
	if err != nil {
		return 0
	}
	return capabilities
}

func (listener *listener) forgetSessionWhenClosed(flowID uint64, sess *session) {
	if sess == nil {
		return
	}
	go func() {
		<-sess.closed
		listener.mu.Lock()
		if listener.sessions[flowID] == sess {
			delete(listener.sessions, flowID)
		}
		listener.mu.Unlock()
	}()
}

func (listener *listener) readSubscription(ctx context.Context) {
	if batchSubscription, ok := listener.subscription.(dataplane.TIXTCPBatchSubscription); ok {
		listener.readBatchSubscription(ctx, batchSubscription)
		return
	}
	for {
		select {
		case <-ctx.Done():
			transport.ObserveAsyncError("close tix_tcp listener after context cancellation", listener.Close())
			return
		case <-listener.done:
			return
		case frame, ok := <-listener.subscription.Events():
			if !ok {
				transport.ObserveAsyncError("close tix_tcp listener after subscription closure", listener.Close())
				return
			}
			if frame.Direction != dataplane.TIXTCPInbound {
				releaseTIXTCPFrame(frame)
				continue
			}
			listener.dispatch(frame)
		}
	}
}

func (listener *listener) readBatchSubscription(ctx context.Context, subscription dataplane.TIXTCPBatchSubscription) {
	for {
		select {
		case <-ctx.Done():
			transport.ObserveAsyncError("close tix_tcp batch listener after context cancellation", listener.Close())
			return
		case <-listener.done:
			return
		case frames, ok := <-subscription.BatchEvents():
			if !ok {
				transport.ObserveAsyncError("close tix_tcp batch listener after subscription closure", listener.Close())
				return
			}
			listener.dispatchBatch(frames)
		}
	}
}

func (listener *listener) dispatch(frame dataplane.TIXTCPFrame) {
	listener.mu.Lock()
	sess := listener.sessions[frame.FlowID]
	if sess != nil && sess.isClosed() {
		delete(listener.sessions, frame.FlowID)
		sess = nil
	}
	if sess == nil {
		if frame.Endpoint != "" && frame.Endpoint != listener.endpoint.Name {
			listener.mu.Unlock()
			releaseTIXTCPFrame(frame)
			return
		}
		if listener.primerFlowRequired {
			listener.mu.Unlock()
			releaseTIXTCPFrame(frame)
			return
		}
		sess = newSession(listener.provider, nil, frame.FlowID, frame.Peer, listener.endpoint.Name, listener.placement, "", "")
		listener.sessions[frame.FlowID] = sess
		select {
		case listener.acceptCh <- sess:
			listener.forgetSessionWhenClosed(frame.FlowID, sess)
		default:
			delete(listener.sessions, frame.FlowID)
			sess.closeInput()
			listener.mu.Unlock()
			releaseTIXTCPFrame(frame)
			return
		}
	}
	listener.mu.Unlock()
	sess.handleFrame(frame)
}

func (listener *listener) dispatchBatch(frames []dataplane.TIXTCPFrame) {
	if len(frames) == 0 {
		return
	}
	var singleSession *session
	var singleFrames []dataplane.TIXTCPFrame
	var accepted map[*session][]dataplane.TIXTCPFrame
	listener.mu.Lock()
	for _, frame := range frames {
		if frame.Direction != dataplane.TIXTCPInbound {
			releaseTIXTCPFrame(frame)
			continue
		}
		sess := listener.sessions[frame.FlowID]
		if sess != nil && sess.isClosed() {
			delete(listener.sessions, frame.FlowID)
			sess = nil
		}
		if sess == nil {
			if frame.Endpoint != "" && frame.Endpoint != listener.endpoint.Name {
				releaseTIXTCPFrame(frame)
				continue
			}
			if listener.primerFlowRequired {
				releaseTIXTCPFrame(frame)
				continue
			}
			sess = newSession(listener.provider, nil, frame.FlowID, frame.Peer, listener.endpoint.Name, listener.placement, "", "")
			listener.sessions[frame.FlowID] = sess
			select {
			case listener.acceptCh <- sess:
				listener.forgetSessionWhenClosed(frame.FlowID, sess)
			default:
				delete(listener.sessions, frame.FlowID)
				sess.closeInput()
				releaseTIXTCPFrame(frame)
				continue
			}
		}
		if accepted != nil {
			accepted[sess] = append(accepted[sess], frame)
			continue
		}
		if singleSession == nil {
			singleSession = sess
			singleFrames = append(singleFrames, frame)
			continue
		}
		if singleSession == sess {
			singleFrames = append(singleFrames, frame)
			continue
		}
		accepted = map[*session][]dataplane.TIXTCPFrame{
			singleSession: singleFrames,
			sess:          {frame},
		}
		singleSession = nil
		singleFrames = nil
	}
	listener.mu.Unlock()
	if accepted == nil {
		if singleSession != nil {
			singleSession.handleFrames(singleFrames)
		}
		return
	}
	for session, sessionFrames := range accepted {
		session.handleFrames(sessionFrames)
	}
}

type session struct {
	provider                    dataplane.TIXTCPProvider
	subscription                dataplane.TIXTCPSubscription
	flowID                      uint64
	peer                        core.IXID
	peerIdentity                transport.PeerIdentity
	endpoint                    core.EndpointID
	localAddress                string
	remoteAddress               string
	in                          chan tixTCPPacketBatch
	recvPending                 tixTCPPacketBatch
	closeOnce                   sync.Once
	closeErr                    error
	backgroundErrors            transport.AsyncErrorTracker
	closeInputOnce              sync.Once
	sendMu                      sync.Mutex
	recvMu                      sync.Mutex
	closed                      chan struct{}
	reassembly                  map[uint64]*fragmentAssembly
	sendSeq                     atomic.Uint64
	bytesSent                   atomic.Uint64
	bytesReceived               atomic.Uint64
	packetsSent                 atomic.Uint64
	packetsReceived             atomic.Uint64
	fragmentedPacketsSent       atomic.Uint64
	fragmentsSent               atomic.Uint64
	fragmentsReceived           atomic.Uint64
	fragmentedPacketsReceived   atomic.Uint64
	fragmentsReassembled        atomic.Uint64
	fragmentDuplicates          atomic.Uint64
	fragmentExpiredAssemblies   atomic.Uint64
	fragmentExpiredFragments    atomic.Uint64
	fragmentMismatches          atomic.Uint64
	fragmentRejects             atomic.Uint64
	tixbExpandedPackets         atomic.Uint64
	tixbExpandedItems           atomic.Uint64
	epoch                       uint64
	cryptoPlacement             dataplane.CryptoPlacement
	cryptoSuite                 string
	cryptoOffloaded             bool
	fullPlaintextKernelDatapath bool
	fullSecureKernelDatapath    bool
	localCapabilities           atomic.Uint64
	peerCapabilities            atomic.Uint64
	capabilityRefreshFailed     atomic.Bool
	capabilityUpdateSequence    atomic.Uint32
	capabilityAckCh             chan tixTCPCapabilityTransition
	capabilityWithdrawals       atomic.Uint64
	capabilityWithdrawalAcks    atomic.Uint64
	capabilityAckTimeouts       atomic.Uint64
	kernelDatapathReadyMu       sync.Mutex
	kernelDatapathReady         atomic.Bool
	kernelDatapathStateHookMu   sync.Mutex
	kernelDatapathStateHook     func() error
	compatControl               *stream.Session
	compatPriority              chan []byte
	compatPriorityWaited        atomic.Bool
	sendFrames                  []dataplane.TIXTCPFrame
	sendExpandedPackets         [][]byte
	reassemblyMaxAssemblies     int
	configuredFragmentPayload   int
	fragmentPayloadCached       int
	fragmentPayloadCacheKey     fragmentPayloadCacheKey
	sealBeforeMaxCached         int
	sealBeforeMaxCacheKey       fragmentPayloadCacheKey
	keepFlowOnClose             bool
}

type fragmentPayloadCacheKey struct {
	placement  dataplane.CryptoPlacement
	offloaded  bool
	configured int
}

type compatStreamSession struct {
	*stream.Session
	peer         core.IXID
	peerIdentity transport.PeerIdentity
	endpoint     core.EndpointID
}

type tixTCPCompatControlInit struct {
	flowID     uint64
	sourcePort uint16
}

type tixTCPCapabilityTransition struct {
	generation   uint32
	capabilities uint64
}

type fragmentAssembly struct {
	createdAt time.Time
	fragments [][]byte
	received  int
	totalLen  int
}

type tixTCPPacketBatch struct {
	packets  [][]byte
	releases []func()
	owner    *tixTCPPacketBatch
}

func takeTIXTCPPacketBatch(size int) tixTCPPacketBatch {
	owner := tixTCPPacketBatchPool.Get().(*tixTCPPacketBatch)
	if cap(owner.packets) < size {
		owner.packets = make([][]byte, 0, size)
	} else {
		owner.packets = owner.packets[:0]
	}
	owner.releases = nil
	owner.owner = owner
	return tixTCPPacketBatch{
		packets: owner.packets,
		owner:   owner,
	}
}

func syncTIXTCPPacketBatchOwner(batch *tixTCPPacketBatch) {
	if batch == nil || batch.owner == nil {
		return
	}
	batch.owner.packets = batch.packets
	batch.owner.releases = batch.releases
	batch.owner.owner = batch.owner
}

func putTIXTCPPacketBatch(owner *tixTCPPacketBatch) {
	if owner == nil {
		return
	}
	clear(owner.packets)
	clear(owner.releases)
	if cap(owner.packets) > 4096 || cap(owner.releases) > 4096 {
		*owner = tixTCPPacketBatch{}
		return
	}
	owner.packets = owner.packets[:0]
	owner.releases = nil
	owner.owner = nil
	tixTCPPacketBatchPool.Put(owner)
}

func releaseTIXTCPPacketBatchOwner(batch tixTCPPacketBatch) {
	if batch.owner != nil {
		putTIXTCPPacketBatch(batch.owner)
	}
}

func tixTCPPacketBatchReleases(batch *tixTCPPacketBatch, prefix int, size int) []func() {
	if prefix < 0 {
		prefix = 0
	}
	if size < prefix {
		size = prefix
	}
	if batch != nil && batch.owner != nil {
		if cap(batch.owner.releases) < size {
			batch.owner.releases = make([]func(), 0, size)
		}
		releases := batch.owner.releases[:prefix]
		clear(releases)
		return releases
	}
	return make([]func(), prefix, size)
}

func newSession(provider dataplane.TIXTCPProvider, subscription dataplane.TIXTCPSubscription, flowID uint64, peer core.IXID, endpoint core.EndpointID, placement dataplane.CryptoPlacement, wireAddresses ...string) *session {
	placement = normalizeCryptoPlacement(placement)
	var localAddress string
	var remoteAddress string
	if len(wireAddresses) > 0 {
		localAddress = wireAddresses[0]
	}
	if len(wireAddresses) > 1 {
		remoteAddress = wireAddresses[1]
	}
	return &session{
		provider:                  provider,
		subscription:              subscription,
		flowID:                    flowID,
		peer:                      peer,
		endpoint:                  endpoint,
		localAddress:              localAddress,
		remoteAddress:             remoteAddress,
		in:                        make(chan tixTCPPacketBatch, tixTCPSessionBuffer()),
		closed:                    make(chan struct{}),
		capabilityAckCh:           make(chan tixTCPCapabilityTransition, 16),
		cryptoPlacement:           placement,
		reassemblyMaxAssemblies:   tixTCPReassemblyMaxAssemblies(),
		configuredFragmentPayload: tixTCPFragmentPayloadSizeForPlacement(placement, false),
	}
}

func (session *session) enableCompatPriority() {
	if session == nil || session.compatPriority != nil {
		return
	}
	session.compatPriority = make(chan []byte, tixTCPCompatPriorityBuffer)
}

func (session *session) sendCompatCapabilities() error {
	if session == nil || session.compatControl == nil {
		return nil
	}
	capabilities := session.localCapabilities.Load() & tixTCPKnownCapabilities
	if session.kernelDatapathReady.Load() {
		capabilities |= tixTCPCapabilityKernelDatapathReady
	}
	if capabilities == 0 {
		return nil
	}
	return session.sendCompatCapabilitiesValue(capabilities)
}

func (session *session) sendCompatCapabilitiesValue(capabilities uint64) error {
	if session == nil || session.compatControl == nil {
		return nil
	}
	capabilities &= tixTCPKnownCapabilities
	session.sendMu.Lock()
	defer session.sendMu.Unlock()
	if err := session.compatControl.SendPacket(encodeTIXTCPCompatControlCapabilities(capabilities)); err != nil {
		return fmt.Errorf("send tix_tcp compat capabilities: %w", err)
	}
	return nil
}

func (session *session) nextCapabilityUpdateGeneration() uint32 {
	generation := session.capabilityUpdateSequence.Add(1)
	if generation == 0 {
		generation = session.capabilityUpdateSequence.Add(1)
	}
	return generation
}

func (session *session) sendCompatCapabilityTransition(
	ctx context.Context, capabilities uint64,
) (acknowledged, advertised bool, resultErr error) {
	if session == nil || session.compatControl == nil {
		return false, false, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	capabilities &= tixTCPKnownCapabilities
	transition := tixTCPCapabilityTransition{
		generation:   session.nextCapabilityUpdateGeneration(),
		capabilities: capabilities,
	}

	// The legacy frame stops old peers. Current peers acknowledge the
	// sequenced frame only after their kernel send state has been updated.
	session.sendMu.Lock()
	if err := session.compatControl.SendPacket(
		encodeTIXTCPCompatControlCapabilities(capabilities),
	); err != nil {
		session.sendMu.Unlock()
		return false, false, fmt.Errorf("send tix_tcp compat capabilities: %w", err)
	}
	advertised = true
	if err := session.compatControl.SendPacket(
		encodeTIXTCPCompatCapabilityTransition(
			tixTCPCompatControlCapabilityUpdateType, transition,
		),
	); err != nil {
		session.sendMu.Unlock()
		return false, true, fmt.Errorf("send tix_tcp capability transition: %w", err)
	}
	session.sendMu.Unlock()

	acknowledged = session.waitCompatCapabilityAck(ctx, transition)
	return acknowledged, true, nil
}

func (session *session) sendCompatCapabilityAck(
	transition tixTCPCapabilityTransition,
) error {
	if session == nil || session.compatControl == nil {
		return nil
	}
	session.sendMu.Lock()
	defer session.sendMu.Unlock()
	if err := session.compatControl.SendPacket(
		encodeTIXTCPCompatCapabilityTransition(
			tixTCPCompatControlCapabilityAckType, transition,
		),
	); err != nil {
		return fmt.Errorf("send tix_tcp capability acknowledgement: %w", err)
	}
	return nil
}

func (session *session) waitCompatCapabilityAck(
	ctx context.Context, wanted tixTCPCapabilityTransition,
) bool {
	if session == nil || session.capabilityAckCh == nil {
		return false
	}
	timer := time.NewTimer(tixTCPCapabilityAckTimeout())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-session.closed:
			return false
		case transition := <-session.capabilityAckCh:
			if transition == wanted {
				return true
			}
		case <-timer.C:
			return false
		}
	}
}

func (session *session) recordCompatCapabilityAck(
	transition tixTCPCapabilityTransition,
) {
	if session == nil || session.capabilityAckCh == nil {
		return
	}
	select {
	case session.capabilityAckCh <- transition:
		return
	default:
	}
	select {
	case <-session.capabilityAckCh:
	default:
	}
	select {
	case session.capabilityAckCh <- transition:
	default:
	}
}

func tixTCPCapabilityTransitionDuration(name string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		return fallback
	}
	if value > tixTCPCapabilityTransitionDurationMax {
		return tixTCPCapabilityTransitionDurationMax
	}
	return value
}

func tixTCPCapabilityAckTimeout() time.Duration {
	return tixTCPCapabilityTransitionDuration(
		"TRUSTIX_TIX_TCP_CAPABILITY_ACK_TIMEOUT",
		tixTCPCapabilityAckTimeoutDefault,
	)
}

func tixTCPCapabilityWithdrawalGrace(acknowledged bool) time.Duration {
	if acknowledged {
		return tixTCPCapabilityTransitionDuration(
			"TRUSTIX_TIX_TCP_CAPABILITY_WITHDRAW_GRACE",
			tixTCPCapabilityWithdrawGraceDefault,
		)
	}
	return tixTCPCapabilityTransitionDuration(
		"TRUSTIX_TIX_TCP_CAPABILITY_WITHDRAW_LEGACY_GRACE",
		tixTCPCapabilityWithdrawLegacyGraceDefault,
	)
}

func (session *session) waitCapabilityWithdrawalDrain(
	ctx context.Context, acknowledged bool,
) bool {
	timer := time.NewTimer(tixTCPCapabilityWithdrawalGrace(acknowledged))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-session.closed:
		return false
	case <-timer.C:
		return true
	}
}

func (session *session) refreshLocalCapabilities(ctx context.Context) error {
	if session == nil || session.provider == nil || session.compatControl == nil ||
		(!session.fullPlaintextKernelDatapath && !session.fullSecureKernelDatapath) {
		return nil
	}
	capabilities, statusErr := tixTCPProviderLocalCapabilities(ctx, session.provider)
	current := session.localCapabilities.Load()
	if capabilities == current {
		if statusErr != nil {
			return fmt.Errorf("refresh tix_tcp local capabilities: %w", statusErr)
		}
		return nil
	}
	if !session.kernelDatapathReady.Load() {
		return errTIXTCPCapabilityReconnect
	}
	// Stop the peer, drain frames emitted before its send-state commit, then
	// remove local receive acceptance. This keeps a recoverable runtime circuit
	// event from becoming a control-plane outage.
	target := current & capabilities
	if withdrawn := current &^ capabilities; withdrawn != 0 {
		advertised := target | tixTCPCapabilityKernelDatapathReady
		acknowledged, sent, sendErr := session.sendCompatCapabilityTransition(
			ctx, advertised,
		)
		if !sent {
			return fmt.Errorf("%w: %w", errTIXTCPCapabilityAdvertisement, sendErr)
		}
		session.capabilityWithdrawals.Add(1)
		if acknowledged {
			session.capabilityWithdrawalAcks.Add(1)
		} else {
			session.capabilityAckTimeouts.Add(1)
		}
		if !session.waitCapabilityWithdrawalDrain(ctx, acknowledged) {
			return nil
		}
		if !session.localCapabilities.CompareAndSwap(current, target) {
			return errTIXTCPCapabilityReconnect
		}
		if err := session.notifyKernelDatapathStateChange(); err != nil {
			return fmt.Errorf("%w: withdraw local capabilities: %w", errTIXTCPCapabilityCommit, err)
		}
		current = target
		if sendErr != nil {
			return fmt.Errorf("%w: %w", errTIXTCPCapabilityAdvertisement, sendErr)
		}
	}
	if statusErr != nil {
		return fmt.Errorf("refresh tix_tcp local capabilities: %w", statusErr)
	}
	if capabilities != current {
		// Additions are enabled by a replacement session whose readiness barrier
		// commits receive state before publishing the new feature bits.
		return errTIXTCPCapabilityReconnect
	}
	return nil
}

func (session *session) monitorLocalCapabilities(ctx context.Context) {
	if session == nil || session.provider == nil || session.compatControl == nil ||
		(!session.fullPlaintextKernelDatapath && !session.fullSecureKernelDatapath) {
		return
	}
	refresh := func() bool {
		if err := session.refreshLocalCapabilities(ctx); err != nil {
			if errors.Is(err, errTIXTCPCapabilityReconnect) {
				session.capabilityRefreshFailed.Store(false)
				transport.ObserveAsyncError(
					"close tix_tcp session for capability change",
					session.Close(),
				)
				return false
			}
			if session.capabilityRefreshFailed.CompareAndSwap(false, true) {
				session.backgroundErrors.Record("refresh tix_tcp local capabilities", err)
			}
			if errors.Is(err, errTIXTCPCapabilityAdvertisement) {
				transport.ObserveAsyncError(
					"close tix_tcp session after capability advertisement failure",
					session.Close(),
				)
				return false
			}
			if errors.Is(err, errTIXTCPCapabilityCommit) {
				transport.ObserveAsyncError(
					"close tix_tcp session after capability state commit failure",
					session.Close(),
				)
				return false
			}
			return true
		}
		session.capabilityRefreshFailed.Store(false)
		return true
	}
	if !refresh() {
		return
	}
	timer := time.NewTimer(session.localCapabilityRefreshInterval())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-session.closed:
			return
		case <-timer.C:
			if !refresh() {
				return
			}
			timer.Reset(session.localCapabilityRefreshInterval())
		}
	}
}

func (session *session) localCapabilityRefreshInterval() time.Duration {
	if session != nil &&
		session.localCapabilities.Load()&tixTCPCapabilityInnerGSO != 0 {
		return tixTCPCompatInnerGSOCapabilityRefreshInterval
	}
	return tixTCPCompatCapabilityRefreshInterval
}

func (session *session) readSubscription(ctx context.Context) {
	if session.subscription == nil {
		return
	}
	if batchSubscription, ok := session.subscription.(dataplane.TIXTCPBatchSubscription); ok {
		session.readBatchSubscription(ctx, batchSubscription)
		return
	}
	defer session.closeInput()
	for {
		select {
		case <-ctx.Done():
			return
		case <-session.closed:
			return
		case frame, ok := <-session.subscription.Events():
			if !ok {
				return
			}
			if frame.Direction != dataplane.TIXTCPInbound || frame.FlowID != session.flowID {
				releaseTIXTCPFrame(frame)
				continue
			}
			session.handleFrame(frame)
		}
	}
}

func (session *session) readCompatControl(ctx context.Context) {
	if session.compatControl == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-session.closed:
			return
		default:
		}
		packet, err := session.compatControl.RecvPacket()
		if err != nil {
			transport.ObserveAsyncError("close tix_tcp session after compat control receive failure", session.Close())
			return
		}
		if transition, ok := decodeTIXTCPCompatCapabilityTransition(
			packet, tixTCPCompatControlCapabilityUpdateType,
		); ok {
			if err := session.setPeerCapabilities(transition.capabilities); err != nil {
				transport.ObserveAsyncError(
					"close tix_tcp session after peer capability state commit failure",
					errors.Join(err, session.Close()),
				)
				return
			}
			if err := session.sendCompatCapabilityAck(transition); err != nil {
				transport.ObserveAsyncError(
					"close tix_tcp session after capability acknowledgement failure",
					errors.Join(err, session.Close()),
				)
				return
			}
			continue
		}
		if transition, ok := decodeTIXTCPCompatCapabilityTransition(
			packet, tixTCPCompatControlCapabilityAckType,
		); ok {
			session.recordCompatCapabilityAck(transition)
			continue
		}
		if capabilities, ok := decodeTIXTCPCompatControlCapabilities(packet); ok {
			if err := session.setPeerCapabilities(capabilities); err != nil {
				transport.ObserveAsyncError(
					"close tix_tcp session after legacy peer capability state commit failure",
					errors.Join(err, session.Close()),
				)
				return
			}
			continue
		}
		if !tixTCPCompatControlEligible(packet) {
			continue
		}
		if session.enqueueCompatPriority(packet) {
			continue
		}
		session.enqueue(packet)
	}
}

func (session *session) readBatchSubscription(ctx context.Context, subscription dataplane.TIXTCPBatchSubscription) {
	defer session.closeInput()
	for {
		select {
		case <-ctx.Done():
			return
		case <-session.closed:
			return
		case frames, ok := <-subscription.BatchEvents():
			if !ok {
				return
			}
			var filtered []dataplane.TIXTCPFrame
			for i, frame := range frames {
				if frame.Direction == dataplane.TIXTCPInbound && frame.FlowID == session.flowID {
					if filtered != nil {
						filtered = append(filtered, frame)
					}
					continue
				}
				if filtered == nil {
					filtered = make([]dataplane.TIXTCPFrame, 0, len(frames))
					for _, previous := range frames[:i] {
						if previous.Direction == dataplane.TIXTCPInbound && previous.FlowID == session.flowID {
							filtered = append(filtered, previous)
						} else {
							releaseTIXTCPFrame(previous)
						}
					}
				}
				releaseTIXTCPFrame(frame)
			}
			if filtered == nil {
				session.handleFrames(frames)
			} else {
				session.handleFrames(filtered)
			}
		}
	}
}

func (session *session) SendPacket(pkt []byte) error {
	if session.compatControl != nil && tixTCPCompatControlEligible(pkt) {
		session.sendMu.Lock()
		defer session.sendMu.Unlock()
		if err := session.compatControl.SendPacket(pkt); err != nil {
			return err
		}
		session.bytesSent.Add(uint64(len(pkt)))
		session.packetsSent.Add(1)
		return nil
	}
	if session.fullPlaintextKernelDatapath || session.fullSecureKernelDatapath {
		return fmt.Errorf("tix_tcp %s owns data frames; userspace frame submit is unavailable", session.fullKernelDatapathName())
	}
	return session.SendPackets([][]byte{pkt})
}

func (session *session) fullKernelDatapathName() string {
	if session != nil && session.fullSecureKernelDatapath {
		return "full secure kernel datapath"
	}
	return "full plaintext kernel datapath"
}

func (session *session) SendPackets(pkts [][]byte) error {
	if len(pkts) == 0 {
		return nil
	}
	select {
	case <-session.closed:
		return fmt.Errorf("tix_tcp session is closed")
	default:
	}
	if session.fullPlaintextKernelDatapath || session.fullSecureKernelDatapath {
		if session.compatControl == nil {
			return fmt.Errorf("tix_tcp %s requires compat TCP control", session.fullKernelDatapathName())
		}
		for _, pkt := range pkts {
			if !tixTCPCompatControlEligible(pkt) {
				return fmt.Errorf("tix_tcp %s owns data frames; userspace frame submit is unavailable", session.fullKernelDatapathName())
			}
		}
		session.sendMu.Lock()
		defer session.sendMu.Unlock()
		var packetBytes uint64
		for _, pkt := range pkts {
			if err := session.compatControl.SendPacket(pkt); err != nil {
				return err
			}
			packetBytes += uint64(len(pkt))
		}
		session.bytesSent.Add(packetBytes)
		session.packetsSent.Add(uint64(len(pkts)))
		return nil
	}
	session.sendMu.Lock()
	defer session.sendMu.Unlock()
	select {
	case <-session.closed:
		return fmt.Errorf("tix_tcp session is closed")
	default:
	}
	payloadSize := session.fragmentPayloadSize()
	placement := dataplane.CryptoPlacementUserspace
	if session.cryptoOffloaded {
		placement = session.cryptoPlacement
	}
	var tixbExpandedPackets uint64
	var tixbExpandedItems uint64
	pkts, tixbExpandedPackets, tixbExpandedItems = session.expandDataSessionTIXBPackets(pkts)
	if tixbExpandedPackets > 0 {
		defer session.clearExpandedPackets()
	}
	sealBeforeFragment := session.kernelCryptoSealBeforeFragment()
	if sealBeforeFragment {
		if _, ok := session.provider.(dataplane.TIXTCPBatchProvider); !ok {
			sealBeforeFragment = false
		}
	}
	sealBeforeFragmentMax := session.sealBeforeFragmentMax(sealBeforeFragment)
	sealBeforeFragmentPayloadSize := payloadSize
	if sealBeforeFragment {
		sealBeforeFragmentPayloadSize = session.sealBeforeFragmentPayloadSize(payloadSize)
	}
	totalFragments := 0
	for _, pkt := range pkts {
		count := session.wireFragmentCount(len(pkt), payloadSize, sealBeforeFragmentPayloadSize, sealBeforeFragment, sealBeforeFragmentMax)
		if count > tixTCPMaxFragments {
			return fmt.Errorf("tix_tcp packet size %d requires %d fragments, max %d", len(pkt), count, tixTCPMaxFragments)
		}
		totalFragments += count
	}
	if cap(session.sendFrames) < totalFragments {
		session.sendFrames = make([]dataplane.TIXTCPFrame, 0, totalFragments)
	} else {
		session.sendFrames = session.sendFrames[:0]
	}
	frames := session.sendFrames
	defer func() {
		clearTIXTCPFrames(frames)
		session.sendFrames = frames[:0]
	}()
	packetBytes := uint64(0)
	packetCount := uint64(0)
	fragmentedPackets := uint64(0)
	fragments := uint64(0)
	for _, pkt := range pkts {
		count := session.wireFragmentCount(len(pkt), payloadSize, sealBeforeFragmentPayloadSize, sealBeforeFragment, sealBeforeFragmentMax)
		if session.shouldSealBeforeFragment(len(pkt), payloadSize, sealBeforeFragment, sealBeforeFragmentMax) {
			baseSeq := session.sendSeq.Add(uint64(count)) - uint64(count) + 1
			frames = append(frames, dataplane.TIXTCPFrame{
				FlowID:              session.flowID,
				Direction:           dataplane.TIXTCPOutbound,
				Peer:                session.peer,
				Endpoint:            session.endpoint,
				Sequence:            baseSeq,
				FragmentPayloadSize: sealBeforeFragmentPayloadSize,
				Payload:             pkt,
				InnerIPv4:           tixTCPInnerIPv4Eligible(pkt),
				CryptoSuite:         session.cryptoSuite,
				CryptoPlacement:     placement,
			})
			packetBytes += uint64(len(pkt))
			packetCount++
			if count > 1 {
				fragmentedPackets++
				fragments += uint64(count)
			}
			continue
		}
		innerIPv4 := count == 1 && tixTCPInnerIPv4Eligible(pkt)
		lastSeq := session.sendSeq.Add(uint64(count))
		baseSeq := lastSeq - uint64(count) + 1
		for i := 0; i < count; i++ {
			start := i * payloadSize
			end := start + payloadSize
			if end > len(pkt) {
				end = len(pkt)
			}
			var fragmentIndex uint16
			var fragmentCount uint16
			if count > 1 {
				fragmentIndex = uint16(i)
				fragmentCount = uint16(count)
			}
			frames = append(frames, dataplane.TIXTCPFrame{
				FlowID:          session.flowID,
				Direction:       dataplane.TIXTCPOutbound,
				Peer:            session.peer,
				Endpoint:        session.endpoint,
				Sequence:        baseSeq + uint64(i),
				FragmentIndex:   fragmentIndex,
				FragmentCount:   fragmentCount,
				Payload:         pkt[start:end],
				InnerIPv4:       innerIPv4,
				CryptoSuite:     session.cryptoSuite,
				CryptoPlacement: placement,
			})
		}
		packetBytes += uint64(len(pkt))
		packetCount++
		if count > 1 {
			fragmentedPackets++
			fragments += uint64(count)
		}
	}
	if batch, ok := session.provider.(dataplane.TIXTCPBatchProvider); ok {
		if err := batch.SubmitTIXTCPFrames(context.Background(), frames); err != nil {
			return err
		}
	} else {
		for _, frame := range frames {
			if err := session.provider.SubmitTIXTCPFrame(context.Background(), frame); err != nil {
				return err
			}
		}
	}
	session.bytesSent.Add(packetBytes)
	session.packetsSent.Add(packetCount)
	if fragmentedPackets > 0 {
		session.fragmentedPacketsSent.Add(fragmentedPackets)
		session.fragmentsSent.Add(fragments)
	}
	if tixbExpandedPackets > 0 {
		session.tixbExpandedPackets.Add(tixbExpandedPackets)
		session.tixbExpandedItems.Add(tixbExpandedItems)
	}
	return nil
}

func (session *session) expandDataSessionTIXBPackets(pkts [][]byte) ([][]byte, uint64, uint64) {
	if session == nil || session.cryptoOffloaded || !tixTCPTIXBExpandEnabled() {
		return pkts, 0, 0
	}
	var expandedPackets uint64
	var expandedItems uint64
	for i, pkt := range pkts {
		items, ok := decodeTIXTCPTIXBInto(pkt, nil)
		if !ok {
			continue
		}
		capacity := len(pkts) + len(items) - 1
		if cap(session.sendExpandedPackets) < capacity {
			session.sendExpandedPackets = make([][]byte, 0, capacity)
		} else {
			session.sendExpandedPackets = session.sendExpandedPackets[:0]
		}
		out := session.sendExpandedPackets
		out = append(out, pkts[:i]...)
		out = append(out, items...)
		expandedPackets++
		expandedItems += uint64(len(items))
		for _, candidate := range pkts[i+1:] {
			items, ok = decodeTIXTCPTIXBInto(candidate, nil)
			if !ok {
				out = append(out, candidate)
				continue
			}
			out = append(out, items...)
			expandedPackets++
			expandedItems += uint64(len(items))
		}
		session.sendExpandedPackets = out
		return out, expandedPackets, expandedItems
	}
	return pkts, 0, 0
}

func (session *session) clearExpandedPackets() {
	if session == nil || session.sendExpandedPackets == nil {
		return
	}
	clear(session.sendExpandedPackets)
	if cap(session.sendExpandedPackets) > 4096 {
		session.sendExpandedPackets = nil
		return
	}
	session.sendExpandedPackets = session.sendExpandedPackets[:0]
}

func tixTCPTIXBExpandEnabled() bool {
	return envTruthy(
		"TRUSTIX_TIX_TCP_EXPAND_TIXB",
		"TRUSTIX_TIX_TCP_TIXB_EXPAND",
	)
}

func decodeTIXTCPTIXBInto(packet []byte, dst [][]byte) ([][]byte, bool) {
	if len(packet) < tixTCPTIXBHeaderLen {
		return nil, false
	}
	if packet[0] != tixTCPTIXBMagic[0] ||
		packet[1] != tixTCPTIXBMagic[1] ||
		packet[2] != tixTCPTIXBMagic[2] ||
		packet[3] != tixTCPTIXBMagic[3] ||
		packet[4] != tixTCPTIXBVersion {
		return nil, false
	}
	count := int(binary.BigEndian.Uint16(packet[6:8]))
	if count <= 0 || count > tixTCPTIXBMaxPackets {
		return nil, false
	}
	offset := tixTCPTIXBHeaderLen
	var items [][]byte
	if cap(dst) < count {
		items = make([][]byte, 0, count)
	} else {
		items = dst[:0]
	}
	for i := 0; i < count; i++ {
		if len(packet)-offset < tixTCPTIXBItemHeaderLen {
			return nil, false
		}
		size := int(binary.BigEndian.Uint16(packet[offset : offset+tixTCPTIXBItemHeaderLen]))
		offset += tixTCPTIXBItemHeaderLen
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

func tixTCPInnerIPv4Eligible(packet []byte) bool {
	if len(packet) < 20 || len(packet) > MaxPayload {
		return false
	}
	if packet[0]>>4 != 4 {
		return false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || ihl > len(packet) {
		return false
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	return totalLen == len(packet)
}

func (session *session) kernelCryptoSealBeforeFragment() bool {
	if session == nil || !session.cryptoOffloaded || session.cryptoPlacement != dataplane.CryptoPlacementKernel {
		return false
	}
	return tixTCPKernelSealBeforeFragmentEnabled()
}

func (session *session) sealBeforeFragmentMax(enabled bool) int {
	if session == nil || !enabled {
		return 0
	}
	configured := session.configuredFragmentPayload
	if configured == 0 {
		configured = tixTCPFragmentPayloadSizeForPlacement(session.cryptoPlacement, session.cryptoOffloaded)
	}
	key := fragmentPayloadCacheKey{
		placement:  session.cryptoPlacement,
		offloaded:  session.cryptoOffloaded,
		configured: configured,
	}
	if session.sealBeforeMaxCached > 0 && session.sealBeforeMaxCacheKey == key {
		return session.sealBeforeMaxCached
	}
	maxPlain := tixTCPKernelSealBeforeMax
	if sizer, ok := session.provider.(dataplane.TIXTCPSealBeforeFragmentSizer); ok {
		if maxSize, err := sizer.TIXTCPSealBeforeFragmentMax(context.Background(), session.cryptoPlacement); err == nil && maxSize > 0 && maxSize < maxPlain {
			maxPlain = maxSize
		}
	}
	if maxPlain < 1 {
		maxPlain = 1
	}
	session.sealBeforeMaxCacheKey = key
	session.sealBeforeMaxCached = maxPlain
	return maxPlain
}

func (session *session) shouldSealBeforeFragment(packetLen int, payloadSize int, enabled bool, maxPlain int) bool {
	if !enabled || packetLen <= payloadSize {
		return false
	}
	if maxPlain <= 0 {
		maxPlain = tixTCPKernelSealBeforeMax
	}
	return packetLen > 0 && packetLen <= maxPlain
}

func (session *session) sealBeforeFragmentPayloadSize(fallback int) int {
	if fallback < 1 {
		fallback = 1
	}
	if !tixTCPKernelSealBeforeFragmentWireMaxEnabled() {
		return fallback
	}
	sizer, ok := session.provider.(dataplane.TIXTCPPayloadSizer)
	if !ok {
		return fallback
	}
	maxSize, err := sizer.TIXTCPPayloadMax(context.Background(), dataplane.CryptoPlacementUserspace, false)
	if err != nil || maxSize < 1 {
		return fallback
	}
	return maxSize
}

func (session *session) wireFragmentCount(packetLen int, payloadSize int, sealBeforeFragmentPayloadSize int, sealBeforeFragment bool, sealBeforeFragmentMax int) int {
	if session.shouldSealBeforeFragment(packetLen, payloadSize, sealBeforeFragment, sealBeforeFragmentMax) {
		return fragmentCountForSize(packetLen+tixTCPSecureFrameOverhead, sealBeforeFragmentPayloadSize)
	}
	return fragmentCountForSize(packetLen, payloadSize)
}

func (session *session) RecvPacket() ([]byte, error) {
	packets, release, err := session.RecvPacketsWithRelease(1)
	if err != nil {
		return nil, err
	}
	if len(packets) == 0 {
		return session.RecvPacket()
	}
	if release != nil {
		packet := append([]byte(nil), packets[0]...)
		release()
		return packet, nil
	}
	return packets[0], nil
}

func (session *session) RecvPackets(max int) ([][]byte, error) {
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

func (session *session) RecvPacketsWithRelease(max int) ([][]byte, func(), error) {
	if max <= 0 {
		max = 1
	}
	coalesceDelay := tixTCPRecvCoalesceDelay()
	drainLimit := tixTCPRecvDrainBatchLimit()
	var packets [][]byte
	var releases []func()
	var releaseBatch tixTCPPacketBatch
	var borrowedBatches []*tixTCPPacketBatch
	appendBatch := func(batch tixTCPPacketBatch, limit int) (tixTCPPacketBatch, bool) {
		batch = trimTIXTCPPacketBatch(batch)
		if len(batch.packets) == 0 {
			releaseTIXTCPPacketBatchOwner(batch)
			return tixTCPPacketBatch{}, false
		}
		if limit > len(batch.packets) {
			limit = len(batch.packets)
		}
		usedBatchDirect := false
		if packets == nil && limit == len(batch.packets) {
			packets = batch.packets
			releases = batch.releases
			if batch.owner != nil {
				borrowedBatches = append(borrowedBatches, batch.owner)
			}
			usedBatchDirect = true
		} else if packets == nil {
			packets = append([][]byte(nil), batch.packets[:limit]...)
		} else {
			packets = append(packets, batch.packets[:limit]...)
		}
		retainOwnerForRelease := false
		if len(batch.releases) > 0 && !usedBatchDirect {
			consumedReleases := batch.releases[:limit]
			if batch.owner != nil && limit < len(batch.packets) {
				consumedReleases = append([]func(){}, consumedReleases...)
			} else {
				retainOwnerForRelease = batch.owner != nil
			}
			if len(releases) == 0 && len(releaseBatch.releases) == 0 {
				releaseBatch.releases = consumedReleases
			} else {
				if len(releaseBatch.releases) > 0 {
					if releases == nil {
						releases = make([]func(), 0, len(releaseBatch.releases)+limit)
					}
					releases = append(releases, releaseBatch.releases...)
					releaseBatch.releases = nil
				}
				releases = append(releases, consumedReleases...)
			}
		}
		if limit == len(batch.packets) {
			if retainOwnerForRelease {
				borrowedBatches = append(borrowedBatches, batch.owner)
			} else if !usedBatchDirect {
				releaseTIXTCPPacketBatchOwner(batch)
			}
			return tixTCPPacketBatch{}, false
		}
		remaining := tixTCPPacketBatch{packets: batch.packets[limit:]}
		if len(batch.releases) > 0 {
			remaining.releases = tixTCPReleaseSuffix(batch.releases, limit)
		}
		remaining.owner = batch.owner
		return remaining, true
	}
	if priorityPackets := session.recvCompatPriorityPackets(max); len(priorityPackets) > 0 {
		session.recordReceivedPackets(priorityPackets)
		return priorityPackets, nil, nil
	}
	if len(session.recvPending.packets) > 0 {
		remaining, hasRemaining := appendBatch(session.recvPending, max)
		session.recvPending = remaining
		if len(packets) > 0 || hasRemaining {
			session.recordReceivedPackets(packets)
			return packets, tixTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
		}
	}
	for len(packets) < max {
		select {
		case <-session.closed:
			if len(packets) > 0 {
				session.recordReceivedPackets(packets)
				return packets, tixTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
			}
			return nil, nil, fmt.Errorf("tix_tcp session is closed")
		case pkt, ok := <-session.compatPriority:
			if !ok || len(pkt) == 0 {
				continue
			}
			packets = append(packets, pkt)
			session.recordReceivedPackets(packets)
			return packets, tixTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
		case batch, ok := <-session.in:
			if !ok {
				if len(packets) > 0 {
					session.recordReceivedPackets(packets)
					return packets, tixTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
				}
				return nil, nil, fmt.Errorf("tix_tcp session is closed")
			}
			remaining, hasRemaining := appendBatch(batch, max-len(packets))
			if hasRemaining {
				session.recvPending = remaining
				session.recordReceivedPackets(packets)
				return packets, tixTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
			}
			if len(packets) == 0 {
				continue
			}
		default:
			if len(packets) > 0 {
				for drained := 0; drained < drainLimit && len(packets) < max; drained++ {
					select {
					case batch, ok := <-session.in:
						if !ok {
							session.recordReceivedPackets(packets)
							return packets, tixTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
						}
						remaining, hasRemaining := appendBatch(batch, max-len(packets))
						if hasRemaining {
							session.recvPending = remaining
							session.recordReceivedPackets(packets)
							return packets, tixTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
						}
					default:
						drained = drainLimit
					}
				}
				if coalesceDelay <= 0 || len(packets) >= max {
					session.recordReceivedPackets(packets)
					return packets, tixTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
				}
				if hook := tixTCPRecvCoalesceWaitHook; hook != nil {
					hook()
				}
				timer := time.NewTimer(coalesceDelay)
				select {
				case <-session.closed:
					stopTIXTCPTimer(timer)
					session.recordReceivedPackets(packets)
					return packets, tixTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
				case pkt, ok := <-session.compatPriority:
					stopTIXTCPTimer(timer)
					if !ok || len(pkt) == 0 {
						session.recordReceivedPackets(packets)
						return packets, tixTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
					}
					packets = append(packets, pkt)
					session.recordReceivedPackets(packets)
					return packets, tixTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
				case batch, ok := <-session.in:
					stopTIXTCPTimer(timer)
					if !ok {
						session.recordReceivedPackets(packets)
						return packets, tixTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
					}
					remaining, hasRemaining := appendBatch(batch, max-len(packets))
					if hasRemaining {
						session.recvPending = remaining
						session.recordReceivedPackets(packets)
						return packets, tixTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
					}
				case <-timer.C:
					session.recordReceivedPackets(packets)
					return packets, tixTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
				}
				continue
			}
			select {
			case <-session.closed:
				return nil, nil, fmt.Errorf("tix_tcp session is closed")
			case pkt, ok := <-session.compatPriority:
				if !ok || len(pkt) == 0 {
					continue
				}
				packets = append(packets, pkt)
				session.recordReceivedPackets(packets)
				return packets, tixTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
			case batch, ok := <-session.in:
				if !ok {
					return nil, nil, fmt.Errorf("tix_tcp session is closed")
				}
				remaining, hasRemaining := appendBatch(batch, max)
				if hasRemaining {
					session.recvPending = remaining
				}
				if len(packets) == 0 {
					continue
				}
			}
		}
	}
	session.recordReceivedPackets(packets)
	return packets, tixTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
}

func stopTIXTCPTimer(timer *time.Timer) {
	if timer == nil || timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}

func trimTIXTCPPacketBatch(batch tixTCPPacketBatch) tixTCPPacketBatch {
	for len(batch.packets) > 0 && batch.packets[0] == nil {
		batch.packets = batch.packets[1:]
		if len(batch.releases) > 0 {
			batch.releases = batch.releases[1:]
		}
	}
	for len(batch.packets) > 0 && batch.packets[len(batch.packets)-1] == nil {
		batch.packets = batch.packets[:len(batch.packets)-1]
		if len(batch.releases) > 0 {
			batch.releases = batch.releases[:len(batch.releases)-1]
		}
	}
	return batch
}

func tixTCPReleaseSuffix(releases []func(), offset int) []func() {
	if len(releases) == 0 || offset >= len(releases) {
		return nil
	}
	if offset <= 0 {
		return releases
	}
	return releases[offset:]
}

func tixTCPReleaseFunc(batch tixTCPPacketBatch, releases []func(), owners []*tixTCPPacketBatch) func() {
	if len(batch.releases) == 0 && len(releases) == 0 && len(owners) == 0 {
		return nil
	}
	return func() {
		for _, release := range batch.releases {
			if release != nil {
				release()
			}
		}
		for _, release := range releases {
			if release != nil {
				release()
			}
		}
		for _, owner := range owners {
			putTIXTCPPacketBatch(owner)
		}
	}
}

func (session *session) recordReceivedPackets(packets [][]byte) {
	var bytes uint64
	for _, pkt := range packets {
		bytes += uint64(len(pkt))
	}
	session.bytesReceived.Add(bytes)
	session.packetsReceived.Add(uint64(len(packets)))
}

func (session *session) KernelDatapathSessionInfo() (transport.KernelDatapathSessionInfo, bool) {
	if session == nil || session.flowID == 0 {
		return transport.KernelDatapathSessionInfo{}, false
	}
	stats := session.Stats()
	localPartial, peerPartial, negotiatedPartial := session.innerTCPChecksumPartialCapabilities()
	localSecurePartial, peerSecurePartial, negotiatedSecurePartial := session.secureInnerTCPChecksumPartialCapabilities()
	localGSO, peerGSO, negotiatedGSO := session.innerGSOCapabilities()
	localPortSharding, peerPortSharding, negotiatedPortSharding := session.portShardingCapabilities()
	info := transport.KernelDatapathSessionInfo{
		FlowID:                                  session.flowID,
		Protocol:                                transport.ProtocolTIXTCP,
		Peer:                                    session.peer,
		Endpoint:                                session.endpoint,
		LocalAddress:                            session.localAddress,
		RemoteAddress:                           session.remoteAddress,
		Epoch:                                   session.epoch,
		CryptoSuite:                             stats.CryptoSuite,
		CryptoPlacement:                         stats.CryptoPlacement,
		Encrypted:                               stats.Encrypted,
		SendEncrypted:                           stats.SendEncrypted,
		ReceiveEncrypted:                        stats.ReceiveEncrypted,
		NativeBatching:                          stats.NativeBatching,
		Datagram:                                stats.Datagram,
		FragmentingDatagram:                     stats.FragmentingDatagram,
		MaxPacketSize:                           stats.MaxPacketSize,
		InnerTCPChecksumPartialLocal:            localPartial,
		InnerTCPChecksumPartialPeer:             peerPartial,
		InnerTCPChecksumPartialNegotiated:       negotiatedPartial,
		SecureInnerTCPChecksumPartialLocal:      localSecurePartial,
		SecureInnerTCPChecksumPartialPeer:       peerSecurePartial,
		SecureInnerTCPChecksumPartialNegotiated: negotiatedSecurePartial,
		InnerGSOLocal:                           localGSO,
		InnerGSOPeer:                            peerGSO,
		InnerGSONegotiated:                      negotiatedGSO,
		TIXTCPPortShardingLocal:                 localPortSharding,
		TIXTCPPortShardingPeer:                  peerPortSharding,
		TIXTCPPortShardingNegotiated:            negotiatedPortSharding,
	}
	return info, true
}

func (session *session) innerTCPChecksumPartialCapabilities() (local, peer, negotiated bool) {
	if session == nil {
		return false, false, false
	}
	local = session.localCapabilities.Load()&tixTCPCapabilityInnerTCPChecksumPartial != 0
	peerCapabilities := session.peerCapabilities.Load()
	peer = peerCapabilities&tixTCPCapabilityInnerTCPChecksumPartial != 0 &&
		peerCapabilities&tixTCPCapabilityKernelDatapathReady != 0
	return local, peer, local && peer && session.kernelDatapathReady.Load()
}

func (session *session) secureInnerTCPChecksumPartialCapabilities() (local, peer, negotiated bool) {
	if session == nil {
		return false, false, false
	}
	local = session.localCapabilities.Load()&tixTCPCapabilitySecureInnerTCPChecksumPartial != 0
	peerCapabilities := session.peerCapabilities.Load()
	peer = peerCapabilities&tixTCPCapabilitySecureInnerTCPChecksumPartial != 0 &&
		peerCapabilities&tixTCPCapabilityKernelDatapathReady != 0
	return local, peer, local && peer && session.kernelDatapathReady.Load()
}

func (session *session) innerGSOCapabilities() (local, peer, negotiated bool) {
	if session == nil {
		return false, false, false
	}
	local = session.localCapabilities.Load()&tixTCPCapabilityInnerGSO != 0
	peerCapabilities := session.peerCapabilities.Load()
	peer = peerCapabilities&tixTCPCapabilityInnerGSO != 0 &&
		peerCapabilities&tixTCPCapabilityKernelDatapathReady != 0
	return local, peer, local && peer && session.kernelDatapathReady.Load()
}

func (session *session) portShardingCapabilities() (local, peer, negotiated bool) {
	if session == nil {
		return false, false, false
	}
	local = session.localCapabilities.Load()&tixTCPCapabilityPortSharding != 0
	peerCapabilities := session.peerCapabilities.Load()
	peer = peerCapabilities&tixTCPCapabilityPortSharding != 0 &&
		peerCapabilities&tixTCPCapabilityKernelDatapathReady != 0
	return local, peer, local && peer && session.kernelDatapathReady.Load()
}

func (session *session) kernelDatapathReadiness() (local, peer, negotiated bool) {
	if session == nil {
		return false, false, false
	}
	local = session.kernelDatapathReady.Load()
	peer = session.peerCapabilities.Load()&tixTCPCapabilityKernelDatapathReady != 0
	return local, peer, local && peer
}

func (session *session) MarkKernelDatapathSessionReady(ctx context.Context) error {
	if session == nil || (!session.fullPlaintextKernelDatapath && !session.fullSecureKernelDatapath) {
		return nil
	}
	if session.compatControl == nil {
		return fmt.Errorf("tix_tcp %s cannot advertise kernel readiness without compat control", session.fullKernelDatapathName())
	}
	if ctx == nil {
		ctx = context.Background()
	}
	session.kernelDatapathReadyMu.Lock()
	defer session.kernelDatapathReadyMu.Unlock()
	if session.kernelDatapathReady.Load() {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-session.closed:
		return fmt.Errorf("tix_tcp session is closed")
	default:
	}
	if session.provider != nil {
		capabilities, err := tixTCPProviderLocalCapabilities(ctx, session.provider)
		if err != nil {
			return fmt.Errorf("verify tix_tcp capabilities before kernel readiness: %w", err)
		}
		current := session.localCapabilities.Load()
		if capabilities != current {
			return fmt.Errorf("%w: tix_tcp capabilities changed before kernel readiness (session=%#x current=%#x)", errTIXTCPCapabilityReconnect, current, capabilities)
		}
	}
	session.kernelDatapathReady.Store(true)
	if err := session.sendCompatCapabilities(); err != nil {
		session.kernelDatapathReady.Store(false)
		return fmt.Errorf("%w: %w", errTIXTCPCapabilityAdvertisement, err)
	}
	return nil
}

func (session *session) SetKernelDatapathSessionStateChangeHook(hook func() error) {
	if session == nil {
		return
	}
	session.kernelDatapathStateHookMu.Lock()
	session.kernelDatapathStateHook = hook
	session.kernelDatapathStateHookMu.Unlock()
}

func (session *session) setPeerCapabilities(capabilities uint64) error {
	if session == nil {
		return nil
	}
	capabilities &= tixTCPKnownCapabilities
	if session.peerCapabilities.Swap(capabilities) == capabilities {
		return nil
	}
	if err := session.notifyKernelDatapathStateChange(); err != nil {
		return fmt.Errorf("commit peer tix_tcp capabilities: %w", err)
	}
	return nil
}

func (session *session) notifyKernelDatapathStateChange() error {
	if session == nil {
		return nil
	}
	session.kernelDatapathStateHookMu.Lock()
	hook := session.kernelDatapathStateHook
	session.kernelDatapathStateHookMu.Unlock()
	if hook != nil {
		return hook()
	}
	return nil
}

func (session *session) EnableCryptoOffload(spec transport.CryptoOffloadSpec) error {
	if session.cryptoPlacement != dataplane.CryptoPlacementKernel {
		return transport.ErrCryptoOffloadUnavailable
	}
	installer, ok := session.provider.(dataplane.TIXTCPCryptoInstaller)
	if !ok {
		return fmt.Errorf("tix_tcp kernel crypto requested but provider does not implement crypto installer")
	}
	if spec.WireFormat != transport.CryptoWireFormatTrustIXSecureDataV1 {
		return fmt.Errorf("tix_tcp crypto offload wire format %q is unsupported", spec.WireFormat)
	}
	cryptoSpec := dataplane.TIXTCPCryptoSpec{
		FlowID:       session.flowID,
		Suite:        spec.Suite,
		WireFormat:   spec.WireFormat,
		KeySource:    spec.KeySource,
		Epoch:        spec.Epoch,
		SendKey:      append([]byte(nil), spec.SendKey...),
		SendIV:       append([]byte(nil), spec.SendIV...),
		RecvKey:      append([]byte(nil), spec.RecvKey...),
		RecvIV:       append([]byte(nil), spec.RecvIV...),
		ReplayWindow: tixTCPReplayWindowForKernelCrypto(spec.ReplayWindow),
		InstalledAt:  time.Now().UTC(),
	}
	defer clearTIXTCPCryptoSpec(&cryptoSpec)
	if err := installer.InstallTIXTCPCrypto(context.Background(), []dataplane.TIXTCPCryptoSpec{cryptoSpec}); err != nil {
		return err
	}
	session.epoch = spec.Epoch
	session.cryptoSuite = spec.Suite
	session.cryptoOffloaded = true
	session.configuredFragmentPayload = tixTCPFragmentPayloadSizeForPlacement(session.cryptoPlacement, true)
	session.fragmentPayloadCached = 0
	if err := session.notifyKernelDatapathStateChange(); err != nil {
		return fmt.Errorf("commit tix_tcp crypto offload state: %w", err)
	}
	return nil
}

func tixTCPReplayWindowForKernelCrypto(window uint) uint {
	if window >= tixTCPKernelCryptoReplayWindow {
		return window
	}
	return tixTCPKernelCryptoReplayWindow
}

func (session *session) SetPeerIdentity(peer core.IXID, domain core.DomainID) {
	if peer == "" {
		return
	}
	session.peer = peer
	session.peerIdentity = transport.PeerIdentity{Peer: peer, Domain: domain}
	if annotator, ok := session.provider.(dataplane.TIXTCPFlowAnnotator); ok {
		session.backgroundErrors.Record(
			fmt.Sprintf("annotate tix_tcp flow %d peer identity", session.flowID),
			annotator.SetTIXTCPFlowPeer(context.Background(), session.flowID, peer, session.endpoint),
		)
	}
}

func (session *session) SetPeerIdentityDetail(identity transport.PeerIdentity) {
	session.peerIdentity = identity
	if identity.Role == "device" {
		return
	}
	session.SetPeerIdentity(identity.Peer, identity.Domain)
}

func (session *session) PeerIdentity() (core.IXID, core.DomainID, bool) {
	if session.peerIdentity.Domain != "" {
		return session.peer, session.peerIdentity.Domain, session.peer != ""
	}
	return session.peer, "", session.peer != ""
}

func (session *session) PeerIdentityDetail() (transport.PeerIdentity, bool) {
	return session.peerIdentity, session.peerIdentity.Peer != "" || session.peerIdentity.Domain != "" || session.peerIdentity.Device != "" || session.peerIdentity.Role != ""
}

func (session *session) PlaintextHandshakeBypassDisabled() bool {
	return true
}

func (session *session) SetPeerEndpoint(peer core.IXID, endpoint core.EndpointID) {
	if peer != "" {
		session.peer = peer
	}
	if endpoint != "" {
		session.endpoint = endpoint
	}
	if annotator, ok := session.provider.(dataplane.TIXTCPFlowAnnotator); ok {
		session.backgroundErrors.Record(
			fmt.Sprintf("annotate tix_tcp flow %d peer endpoint", session.flowID),
			annotator.SetTIXTCPFlowPeer(context.Background(), session.flowID, session.peer, session.endpoint),
		)
	}
}

func (session *compatStreamSession) EnableCryptoOffload(spec transport.CryptoOffloadSpec) error {
	return transport.ErrCryptoOffloadUnavailable
}

func (session *compatStreamSession) PlaintextHandshakeBypassDisabled() bool {
	return true
}

func (session *compatStreamSession) SetPeerIdentity(peer core.IXID, domain core.DomainID) {
	if peer != "" {
		session.peer = peer
	}
	session.peerIdentity = transport.PeerIdentity{Peer: peer, Domain: domain}
}

func (session *compatStreamSession) SetPeerIdentityDetail(identity transport.PeerIdentity) {
	session.peerIdentity = identity
	if identity.Role == "device" {
		return
	}
	session.SetPeerIdentity(identity.Peer, identity.Domain)
}

func (session *compatStreamSession) PeerIdentity() (core.IXID, core.DomainID, bool) {
	if session.peerIdentity.Domain != "" {
		return session.peer, session.peerIdentity.Domain, session.peer != ""
	}
	return session.peer, "", session.peer != ""
}

func (session *compatStreamSession) PeerIdentityDetail() (transport.PeerIdentity, bool) {
	return session.peerIdentity, session.peerIdentity.Peer != "" || session.peerIdentity.Domain != "" || session.peerIdentity.Device != "" || session.peerIdentity.Role != ""
}

func (session *compatStreamSession) SetPeerEndpoint(peer core.IXID, endpoint core.EndpointID) {
	if peer != "" {
		session.peer = peer
	}
	if endpoint != "" {
		session.endpoint = endpoint
	}
}

func (session *compatStreamSession) Stats() transport.TransportStats {
	stats := session.Session.Stats()
	stats.NativeBatching = false
	stats.Datagram = false
	if stats.Extra == nil {
		stats.Extra = make(map[string]uint64, 2)
	}
	stats.Extra["tix_tcp_compat_stream"] = 1
	return stats
}

func clearTIXTCPCryptoSpec(spec *dataplane.TIXTCPCryptoSpec) {
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

func (session *session) Close() error {
	session.closeOnce.Do(func() {
		var errs []error
		session.SetKernelDatapathSessionStateChangeHook(nil)
		if deleter, ok := session.provider.(dataplane.TIXTCPFlowDeleter); ok && !session.keepFlowOnClose {
			if err := deleter.DeleteTIXTCPFlows(context.Background(), []uint64{session.flowID}); err != nil {
				errs = append(errs, fmt.Errorf("delete tix_tcp flow %d: %w", session.flowID, err))
			}
		}
		session.closeInput()
		if session.subscription != nil {
			if err := session.subscription.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close tix_tcp subscription: %w", err))
			}
		}
		if session.compatControl != nil {
			if err := session.compatControl.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close tix_tcp compatibility control: %w", err))
			}
		}
		if err := session.backgroundErrors.Err(); err != nil {
			errs = append(errs, err)
		}
		session.closeErr = errors.Join(errs...)
	})
	return session.closeErr
}

func (session *session) RetainKernelFlowOnClose() {
	session.keepFlowOnClose = true
}

func tixTCPCompatPrimerEnabled() bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_TIX_TCP_COMPAT_TCP_PRIMER")))
	switch raw {
	case "", "auto", "require", "required", "force", "forced", "must":
		return tixTCPCompatTCPPrimerDefault
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return tixTCPCompatTCPPrimerDefault
	}
}

func tixTCPCompatPrimerRequired() bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_TIX_TCP_COMPAT_TCP_PRIMER")))
	switch raw {
	case "require", "required", "force", "forced", "must":
		return true
	default:
		return false
	}
}

func tixTCPCompatStreamEnabled() bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_TIX_TCP_COMPAT_STREAM")))
	switch raw {
	case "", "auto":
		return false
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return false
	}
}

func tixTCPCompatStreamDataEnabled() bool {
	if !tixTCPCompatStreamEnabled() {
		return false
	}
	if envTruthy(
		"TRUSTIX_TIX_TCP_TC_TX_DIRECT",
		"TRUSTIX_REMOTE_TIX_TCP_TC_TX_DIRECT",
		"TRUSTIX_E2E_TIX_TCP_TC_TX_DIRECT",
		"TRUSTIX_IPERF3_CRYPTO_BENCH_TIX_TCP_TC_TX_DIRECT",
		"TRUSTIX_TIX_TCP_TC_TX_DIRECT_ONLY",
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_TIX_TCP_ONLY",
	) {
		return false
	}
	return true
}

func envTruthy(names ...string) bool {
	for _, name := range names {
		switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
		case "1", "true", "yes", "on", "enabled", "force":
			return true
		}
	}
	return false
}

func dialTIXTCPCompatPrimer(ctx context.Context, endpoint transport.Endpoint) (net.Conn, error) {
	if !tixTCPCompatPrimerEnabled() {
		return nil, nil
	}
	address := strings.TrimSpace(endpoint.Address)
	if address == "" {
		return nil, nil
	}
	if !tixTCPCompatPrimerAddressSupported(address, false) {
		return nil, nil
	}
	dialCtx, cancel := context.WithTimeout(ctx, tixTCPCompatTCPPrimerTimeout)
	defer cancel()
	dialer, err := bind.Dialer(endpoint, "tcp")
	if err != nil {
		return nil, err
	}
	dialer.Timeout = tixTCPCompatTCPPrimerTimeout
	dialer.KeepAlive = 30 * time.Second
	conn, err := dialer.DialContext(dialCtx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("tix_tcp compat TCP primer to %s: %w", address, err)
	}
	if err := tuneTIXTCPCompatConn(conn); err != nil {
		return nil, errors.Join(
			fmt.Errorf("tune tix_tcp compat TCP primer to %s: %w", address, err),
			tixTCPCleanupError("close untuned tix_tcp compat primer", conn.Close()),
		)
	}
	return conn, nil
}

func tuneTIXTCPCompatConn(conn net.Conn) error {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil
	}
	return errors.Join(
		tixTCPCleanupError("enable tix_tcp compat TCP keepalive", tcpConn.SetKeepAlive(true)),
		tixTCPCleanupError("set tix_tcp compat TCP keepalive period", tcpConn.SetKeepAlivePeriod(30*time.Second)),
		tixTCPCleanupError("set tix_tcp compat TCP no-delay mode", tcpConn.SetNoDelay(tixTCPCompatNoDelay())),
	)
}

func tixTCPCompatNoDelay() bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_TIX_TCP_COMPAT_NODELAY")))
	switch raw {
	case "", "auto", "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}

func listenTIXTCPCompatPrimer(address string) (net.Listener, error) {
	if !tixTCPCompatPrimerEnabled() {
		return nil, nil
	}
	address = strings.TrimSpace(address)
	if address == "" {
		return nil, nil
	}
	if !tixTCPCompatPrimerAddressSupported(address, true) {
		return nil, nil
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("tix_tcp compat TCP primer listen on %s: %w", address, err)
	}
	return listener, nil
}

func tixTCPCompatPrimerAddressSupported(address string, listen bool) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return listen
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.Is4()
}

func tixTCPCompatDerivedSourcePort(flowID uint64) uint16 {
	return uint16(40000 + flowID%20000)
}

func tixTCPCompatOutboundFlow(flowID uint64, peer core.IXID, conn net.Conn, endpoint transport.Endpoint, placement dataplane.CryptoPlacement) dataplane.TIXTCPFlow {
	flow := dataplane.TIXTCPFlow{
		ID:              flowID,
		Peer:            peer,
		Endpoint:        endpoint.Name,
		LocalAddress:    strings.TrimSpace(endpoint.LocalBind.SourceIP),
		RemoteAddress:   endpoint.Address,
		CryptoPlacement: placement,
		CreatedAt:       time.Now().UTC(),
	}
	if conn == nil {
		return flow
	}
	localIP, _, localOK := tixTCPCompatTCPAddrParts(conn.LocalAddr())
	remoteIP, remotePort, remoteOK := tixTCPCompatTCPAddrParts(conn.RemoteAddr())
	if !localOK || !remoteOK {
		return flow
	}
	sourcePort := tixTCPCompatDerivedSourcePort(flowID)
	flow.LocalAddress = net.JoinHostPort(localIP.String(), strconv.Itoa(int(sourcePort)))
	flow.RemoteAddress = net.JoinHostPort(remoteIP.String(), strconv.Itoa(int(remotePort)))
	flow.SourcePort = sourcePort
	flow.DestinationPort = remotePort
	return flow
}

func tixTCPCompatFlowHasCompleteTuple(flow dataplane.TIXTCPFlow) bool {
	if flow.SourcePort == 0 || flow.DestinationPort == 0 {
		return false
	}
	localIP, localPort, err := resolveTIXTCPCompatHostPort(flow.LocalAddress)
	if err != nil || !localIP.Is4() || localPort != flow.SourcePort {
		return false
	}
	remoteIP, remotePort, err := resolveTIXTCPCompatHostPort(flow.RemoteAddress)
	return err == nil && remoteIP.Is4() && remotePort == flow.DestinationPort
}

func tixTCPCompatInboundFlow(init tixTCPCompatControlInit, conn net.Conn, endpoint transport.Endpoint, placement dataplane.CryptoPlacement) dataplane.TIXTCPFlow {
	now := time.Now().UTC()
	flow := dataplane.TIXTCPFlow{
		ID:              init.flowID,
		Endpoint:        endpoint.Name,
		CryptoPlacement: placement,
		CreatedAt:       now,
	}
	localIP, localPort, localOK := tixTCPCompatTCPAddrParts(conn.LocalAddr())
	remoteIP, _, remoteOK := tixTCPCompatTCPAddrParts(conn.RemoteAddr())
	if localOK && init.sourcePort != 0 && remoteOK {
		flow.LocalAddress = net.JoinHostPort(localIP.String(), strconv.Itoa(int(localPort)))
		flow.RemoteAddress = net.JoinHostPort(remoteIP.String(), strconv.Itoa(int(init.sourcePort)))
		flow.SourcePort = localPort
		flow.DestinationPort = init.sourcePort
		return flow
	}
	if listen := strings.TrimSpace(endpoint.Listen); listen != "" && init.sourcePort != 0 && remoteOK {
		if ip, port, err := resolveTIXTCPCompatHostPort(listen); err == nil && port != 0 {
			flow.LocalAddress = net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
			flow.RemoteAddress = net.JoinHostPort(remoteIP.String(), strconv.Itoa(int(init.sourcePort)))
			flow.SourcePort = port
			flow.DestinationPort = init.sourcePort
		}
	}
	return flow
}

func tixTCPCompatTCPAddrParts(addr net.Addr) (netip.Addr, uint16, bool) {
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok || tcpAddr == nil || tcpAddr.IP == nil || tcpAddr.Port <= 0 || tcpAddr.Port > 65535 {
		return netip.Addr{}, 0, false
	}
	ip, ok := netip.AddrFromSlice(tcpAddr.IP)
	if !ok {
		return netip.Addr{}, 0, false
	}
	ip = ip.Unmap()
	if !ip.Is4() {
		return netip.Addr{}, 0, false
	}
	return ip, uint16(tcpAddr.Port), true
}

func resolveTIXTCPCompatHostPort(address string) (netip.Addr, uint16, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return netip.Addr{}, 0, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		if err == nil {
			err = fmt.Errorf("invalid port %q", portText)
		}
		return netip.Addr{}, 0, err
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return netip.Addr{}, 0, err
	}
	ip = ip.Unmap()
	if !ip.Is4() {
		return netip.Addr{}, 0, fmt.Errorf("non-IPv4 address %q", host)
	}
	return ip, uint16(port), nil
}

func encodeTIXTCPCompatControlInit(flowID uint64) []byte {
	sourcePort := tixTCPCompatDerivedSourcePort(flowID)
	payload := make([]byte, tixTCPCompatControlInitLen)
	copy(payload[0:4], tixTCPCompatControlMagic[:])
	payload[4] = tixTCPCompatControlVersion
	payload[5] = tixTCPCompatControlInitType
	binary.BigEndian.PutUint64(payload[6:14], flowID)
	binary.BigEndian.PutUint16(payload[14:16], sourcePort)
	return payload
}

func tixTCPLocalCapabilities(status dataplane.TIXTCPStatus) uint64 {
	return tixTCPLocalCapabilityBits(dataplane.TIXTCPCapabilities{
		FullPlaintextKernel:           tixTCPFullPlaintextKernelDatapathStatus(status),
		FullSecureKernel:              tixTCPFullSecureKernelDatapathStatus(status),
		InnerTCPChecksumPartial:       status.InnerTCPChecksumPartial,
		SecureInnerTCPChecksumPartial: status.SecureInnerTCPChecksumPartial,
		InnerGSO:                      status.InnerGSO,
		PortSharding:                  status.PortSharding,
	})
}

func tixTCPProviderLocalCapabilities(ctx context.Context, provider dataplane.TIXTCPProvider) (uint64, error) {
	if capabilityProvider, ok := provider.(dataplane.TIXTCPCapabilityProvider); ok {
		capabilities, err := capabilityProvider.TIXTCPCapabilities(ctx)
		if err != nil {
			return 0, err
		}
		return tixTCPLocalCapabilityBits(capabilities), nil
	}
	status, err := provider.TIXTCPStatus(ctx)
	if err != nil {
		return 0, err
	}
	return tixTCPLocalCapabilities(status), nil
}

func tixTCPLocalCapabilityBits(capabilities dataplane.TIXTCPCapabilities) uint64 {
	if !capabilities.FullPlaintextKernel && !capabilities.FullSecureKernel {
		return 0
	}
	var bits uint64
	if capabilities.FullPlaintextKernel && capabilities.InnerTCPChecksumPartial {
		bits |= tixTCPCapabilityInnerTCPChecksumPartial
	}
	if capabilities.FullPlaintextKernel && capabilities.InnerGSO && capabilities.InnerTCPChecksumPartial && capabilities.PortSharding {
		bits |= tixTCPCapabilityInnerGSO
	}
	if capabilities.FullSecureKernel && capabilities.SecureInnerTCPChecksumPartial {
		bits |= tixTCPCapabilitySecureInnerTCPChecksumPartial
	}
	if capabilities.PortSharding {
		bits |= tixTCPCapabilityPortSharding
	}
	return bits
}

func encodeTIXTCPCompatControlCapabilities(capabilities uint64) []byte {
	payload := make([]byte, tixTCPCompatControlCapabilitiesLen)
	copy(payload[0:4], tixTCPCompatControlMagic[:])
	payload[4] = tixTCPCompatControlVersion
	payload[5] = tixTCPCompatControlCapabilitiesType
	binary.BigEndian.PutUint64(payload[6:14], capabilities&tixTCPKnownCapabilities)
	return payload
}

func decodeTIXTCPCompatControlCapabilities(payload []byte) (uint64, bool) {
	if len(payload) != tixTCPCompatControlCapabilitiesLen ||
		string(payload[0:4]) != string(tixTCPCompatControlMagic[:]) ||
		payload[4] != tixTCPCompatControlVersion ||
		payload[5] != tixTCPCompatControlCapabilitiesType {
		return 0, false
	}
	return binary.BigEndian.Uint64(payload[6:14]) & tixTCPKnownCapabilities, true
}

func encodeTIXTCPCompatCapabilityTransition(
	messageType byte, transition tixTCPCapabilityTransition,
) []byte {
	payload := make([]byte, tixTCPCompatControlCapabilityTransitionLen)
	copy(payload[0:4], tixTCPCompatControlMagic[:])
	payload[4] = tixTCPCompatControlVersion
	payload[5] = messageType
	binary.BigEndian.PutUint32(payload[6:10], transition.generation)
	binary.BigEndian.PutUint64(
		payload[10:18], transition.capabilities&tixTCPKnownCapabilities,
	)
	return payload
}

func decodeTIXTCPCompatCapabilityTransition(
	payload []byte, messageType byte,
) (tixTCPCapabilityTransition, bool) {
	if len(payload) != tixTCPCompatControlCapabilityTransitionLen ||
		string(payload[0:4]) != string(tixTCPCompatControlMagic[:]) ||
		payload[4] != tixTCPCompatControlVersion ||
		payload[5] != messageType {
		return tixTCPCapabilityTransition{}, false
	}
	transition := tixTCPCapabilityTransition{
		generation:   binary.BigEndian.Uint32(payload[6:10]),
		capabilities: binary.BigEndian.Uint64(payload[10:18]) & tixTCPKnownCapabilities,
	}
	return transition, transition.generation != 0
}

func decodeTIXTCPCompatControlInit(payload []byte) (tixTCPCompatControlInit, bool) {
	if (len(payload) != tixTCPCompatControlInitLen && len(payload) != tixTCPCompatControlInitOldLen) ||
		string(payload[0:4]) != string(tixTCPCompatControlMagic[:]) ||
		payload[4] != tixTCPCompatControlVersion ||
		payload[5] != tixTCPCompatControlInitType {
		return tixTCPCompatControlInit{}, false
	}
	init := tixTCPCompatControlInit{flowID: binary.BigEndian.Uint64(payload[6:14])}
	if len(payload) >= tixTCPCompatControlInitLen {
		init.sourcePort = binary.BigEndian.Uint16(payload[14:16])
	}
	return init, init.flowID != 0
}

func acceptTIXTCPCompatControl(conn net.Conn) (*stream.Session, tixTCPCompatControlInit, error) {
	control := stream.NewSession(conn)
	initPacket, err := control.RecvPacket()
	if err != nil {
		return nil, tixTCPCompatControlInit{}, errors.Join(err, tixTCPCleanupError("close failed tix_tcp compat control", control.Close()))
	}
	init, ok := decodeTIXTCPCompatControlInit(initPacket)
	if !ok {
		return nil, tixTCPCompatControlInit{}, errors.Join(
			fmt.Errorf("invalid tix_tcp compat control init"),
			tixTCPCleanupError("close invalid tix_tcp compat control", control.Close()),
		)
	}
	return control, init, nil
}

func tixTCPCompatControlEligible(packet []byte) bool {
	if len(packet) < 6 {
		return false
	}
	if string(packet[0:4]) == string(tixTCPSecureHelloMagic[:]) {
		return true
	}
	if string(packet[0:4]) != string(tixTCPCompatControlMagic[:]) || packet[4] != tixTCPCompatControlVersion {
		return false
	}
	switch packet[5] {
	case 1, 2, 3:
		return true
	default:
		return false
	}
}

func tixTCPCompatHandshakePriorityDelay() time.Duration {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_TIX_TCP_COMPAT_HANDSHAKE_PRIORITY_DELAY"))
	if value == "" {
		return tixTCPCompatHandshakePriority
	}
	if parsed, err := time.ParseDuration(value); err == nil {
		if parsed < 0 {
			return 0
		}
		if parsed > tixTCPCompatTCPPrimerTimeout {
			return tixTCPCompatTCPPrimerTimeout
		}
		return parsed
	}
	millis, err := strconv.Atoi(value)
	if err != nil || millis <= 0 {
		return tixTCPCompatHandshakePriority
	}
	delay := time.Duration(millis) * time.Millisecond
	if delay > tixTCPCompatTCPPrimerTimeout {
		return tixTCPCompatTCPPrimerTimeout
	}
	return delay
}

func (session *session) enqueue(pkt []byte) {
	session.enqueueBatch(tixTCPPacketBatch{packets: [][]byte{pkt}})
}

func (session *session) enqueueCompatPriority(pkt []byte) bool {
	if session == nil || session.compatPriority == nil || len(pkt) == 0 {
		return false
	}
	select {
	case <-session.closed:
		return true
	case session.compatPriority <- pkt:
		return true
	default:
		return false
	}
}

func (session *session) recvCompatPriorityPackets(max int) [][]byte {
	if session == nil || session.compatPriority == nil || max <= 0 {
		return nil
	}
	packets := make([][]byte, 0, 1)
	appendPacket := func(pkt []byte, ok bool) bool {
		if !ok || len(pkt) == 0 {
			return false
		}
		packets = append(packets, pkt)
		return true
	}
	select {
	case pkt, ok := <-session.compatPriority:
		appendPacket(pkt, ok)
	default:
	}
	if len(packets) == 0 && session.compatPriorityWaited.CompareAndSwap(false, true) {
		delay := tixTCPCompatHandshakePriorityDelay()
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case pkt, ok := <-session.compatPriority:
				appendPacket(pkt, ok)
			case <-session.closed:
			case <-timer.C:
			}
			stopTIXTCPTimer(timer)
		}
	}
	for len(packets) < max {
		select {
		case pkt, ok := <-session.compatPriority:
			if !appendPacket(pkt, ok) {
				return packets
			}
		default:
			return packets
		}
	}
	return packets
}

func (session *session) enqueueBatch(batch tixTCPPacketBatch) {
	batch = trimTIXTCPPacketBatch(batch)
	if len(batch.packets) == 0 {
		releaseTIXTCPBatch(batch)
		return
	}
	select {
	case <-session.closed:
		releaseTIXTCPBatch(batch)
		return
	default:
	}
	select {
	case <-session.closed:
		releaseTIXTCPBatch(batch)
		return
	case session.in <- batch:
	}
}

func (session *session) handleFrame(frame dataplane.TIXTCPFrame) {
	session.handleFrames([]dataplane.TIXTCPFrame{frame})
}

func (session *session) handleFrames(frames []dataplane.TIXTCPFrame) {
	if len(frames) == 0 {
		return
	}
	if len(frames) == 1 {
		if pkt, release, ok := session.handleFrameOne(frames[0]); ok {
			ready := takeTIXTCPPacketBatch(1)
			ready.packets = append(ready.packets, pkt)
			if release != nil {
				ready.releases = tixTCPPacketBatchReleases(&ready, 0, 1)
				ready.releases = append(ready.releases, release)
			}
			syncTIXTCPPacketBatchOwner(&ready)
			session.enqueueBatch(ready)
		}
		return
	}
	ready := takeTIXTCPPacketBatch(len(frames))
	for _, frame := range frames {
		if pkt, release, ok := session.handleFrameOne(frame); ok {
			ready.packets = append(ready.packets, pkt)
			if release != nil {
				if ready.releases == nil {
					ready.releases = tixTCPPacketBatchReleases(&ready, len(ready.packets)-1, len(frames))
				}
				ready.releases = append(ready.releases, release)
			} else if ready.releases != nil {
				ready.releases = append(ready.releases, nil)
			}
		}
	}
	syncTIXTCPPacketBatchOwner(&ready)
	session.enqueueBatch(ready)
}

func (session *session) handleFrameOne(frame dataplane.TIXTCPFrame) ([]byte, func(), bool) {
	if frame.InnerGSO {
		session.fragmentRejects.Add(1)
		releaseTIXTCPFrame(frame)
		return nil, nil, false
	}
	if frame.FragmentCount == 0 {
		if frame.FragmentIndex != 0 {
			session.fragmentRejects.Add(1)
			releaseTIXTCPFrame(frame)
			return nil, nil, false
		}
		return frame.Payload, frame.Release, true
	}
	if frame.FragmentCount == 1 {
		if frame.FragmentIndex != 0 {
			session.fragmentRejects.Add(1)
			releaseTIXTCPFrame(frame)
			return nil, nil, false
		}
		return frame.Payload, frame.Release, true
	}
	if frame.FragmentCount > tixTCPMaxFragments || frame.FragmentIndex >= frame.FragmentCount {
		session.fragmentRejects.Add(1)
		releaseTIXTCPFrame(frame)
		return nil, nil, false
	}
	if frame.Sequence <= uint64(frame.FragmentIndex) {
		session.fragmentRejects.Add(1)
		releaseTIXTCPFrame(frame)
		return nil, nil, false
	}
	baseSeq := frame.Sequence - uint64(frame.FragmentIndex)
	now := time.Now()
	session.fragmentsReceived.Add(1)

	session.recvMu.Lock()
	session.pruneReassemblyLocked(now)
	if session.reassembly == nil {
		session.reassembly = make(map[uint64]*fragmentAssembly)
	}
	assembly := session.reassembly[baseSeq]
	if assembly == nil {
		session.pruneOldestReassemblyIfFullLocked(session.reassemblyMaxAssemblies)
		assembly = &fragmentAssembly{
			createdAt: now,
			fragments: make([][]byte, int(frame.FragmentCount)),
		}
		session.reassembly[baseSeq] = assembly
	}
	if len(assembly.fragments) != int(frame.FragmentCount) {
		delete(session.reassembly, baseSeq)
		session.fragmentMismatches.Add(1)
		session.fragmentRejects.Add(1)
		session.recvMu.Unlock()
		releaseTIXTCPFrame(frame)
		return nil, nil, false
	}
	index := int(frame.FragmentIndex)
	if assembly.fragments[index] != nil {
		session.fragmentDuplicates.Add(1)
		session.recvMu.Unlock()
		releaseTIXTCPFrame(frame)
		return nil, nil, false
	}
	if frame.Release != nil {
		assembly.fragments[index] = append([]byte(nil), frame.Payload...)
		frame.Release()
		frame.Release = nil
	} else {
		assembly.fragments[index] = frame.Payload
	}
	assembly.received++
	assembly.totalLen += len(frame.Payload)
	if assembly.received != len(assembly.fragments) {
		session.recvMu.Unlock()
		return nil, nil, false
	}
	packet := make([]byte, 0, assembly.totalLen)
	for _, fragment := range assembly.fragments {
		if fragment == nil {
			session.fragmentRejects.Add(1)
			session.recvMu.Unlock()
			releaseTIXTCPFrame(frame)
			return nil, nil, false
		}
		packet = append(packet, fragment...)
	}
	delete(session.reassembly, baseSeq)
	session.recvMu.Unlock()
	session.fragmentedPacketsReceived.Add(1)
	session.fragmentsReassembled.Add(uint64(len(assembly.fragments)))
	return packet, nil, true
}

func tixTCPReleaseSlice(release func()) []func() {
	if release == nil {
		return nil
	}
	return []func(){release}
}

func releaseTIXTCPFrame(frame dataplane.TIXTCPFrame) {
	if frame.Release != nil {
		frame.Release()
	}
}

func clearTIXTCPFrames(frames []dataplane.TIXTCPFrame) {
	for i := range frames {
		frames[i] = dataplane.TIXTCPFrame{}
	}
}

func releaseTIXTCPBatch(batch tixTCPPacketBatch) {
	for _, release := range batch.releases {
		if release != nil {
			release()
		}
	}
	releaseTIXTCPPacketBatchOwner(batch)
}

func (session *session) pruneReassemblyLocked(now time.Time) {
	var expiredAssemblies uint64
	var expiredFragments uint64
	for baseSeq, assembly := range session.reassembly {
		if now.Sub(assembly.createdAt) > tixTCPReassemblyTTL {
			expiredAssemblies++
			for _, fragment := range assembly.fragments {
				if fragment != nil {
					expiredFragments++
				}
			}
			delete(session.reassembly, baseSeq)
		}
	}
	if expiredAssemblies > 0 {
		session.fragmentExpiredAssemblies.Add(expiredAssemblies)
		session.fragmentExpiredFragments.Add(expiredFragments)
	}
}

func (session *session) pruneOldestReassemblyIfFullLocked(maxAssemblies int) {
	if maxAssemblies <= 0 || len(session.reassembly) < maxAssemblies {
		return
	}
	var oldestSeq uint64
	var oldest *fragmentAssembly
	for baseSeq, assembly := range session.reassembly {
		if assembly == nil {
			continue
		}
		if oldest == nil || assembly.createdAt.Before(oldest.createdAt) {
			oldestSeq = baseSeq
			oldest = assembly
		}
	}
	if oldest == nil {
		return
	}
	var fragments uint64
	for _, fragment := range oldest.fragments {
		if fragment != nil {
			fragments++
		}
	}
	delete(session.reassembly, oldestSeq)
	session.fragmentExpiredAssemblies.Add(1)
	session.fragmentExpiredFragments.Add(fragments)
}

func (session *session) closeInput() {
	session.closeInputOnce.Do(func() {
		close(session.closed)
		releaseTIXTCPBatch(session.recvPending)
		session.recvPending = tixTCPPacketBatch{}
		session.drainQueuedBatches()
		session.recvMu.Lock()
		session.reassembly = nil
		session.recvMu.Unlock()
	})
}

func (session *session) drainQueuedBatches() {
	for {
		select {
		case batch := <-session.in:
			releaseTIXTCPBatch(batch)
		default:
			return
		}
	}
}

func (session *session) isClosed() bool {
	if session == nil {
		return true
	}
	select {
	case <-session.closed:
		return true
	default:
		return false
	}
}

func (session *session) Stats() transport.TransportStats {
	extra := session.fragmentStats()
	return transport.TransportStats{
		BytesSent:           session.bytesSent.Load(),
		BytesReceived:       session.bytesReceived.Load(),
		PacketsSent:         session.packetsSent.Load(),
		PacketsReceived:     session.packetsReceived.Load(),
		Extra:               extra,
		CryptoSuite:         session.cryptoSuite,
		CryptoPlacement:     string(session.effectiveCryptoPlacement()),
		NativeBatching:      true,
		Datagram:            true,
		FragmentingDatagram: true,
		MaxPacketSize:       uint64(session.maxPacketSize()),
	}
}

func (session *session) fragmentStats() map[string]uint64 {
	localPartial, peerPartial, negotiatedPartial := session.innerTCPChecksumPartialCapabilities()
	localSecurePartial, peerSecurePartial, negotiatedSecurePartial := session.secureInnerTCPChecksumPartialCapabilities()
	localGSO, peerGSO, negotiatedGSO := session.innerGSOCapabilities()
	localPortSharding, peerPortSharding, negotiatedPortSharding := session.portShardingCapabilities()
	localReady, peerReady, negotiatedReady := session.kernelDatapathReadiness()
	extra := map[string]uint64{
		tixTCPStatFragmentedPacketsSent:                   session.fragmentedPacketsSent.Load(),
		tixTCPStatFragmentsSent:                           session.fragmentsSent.Load(),
		tixTCPStatFragmentsReceived:                       session.fragmentsReceived.Load(),
		tixTCPStatFragmentedPacketsReceived:               session.fragmentedPacketsReceived.Load(),
		tixTCPStatFragmentsReassembled:                    session.fragmentsReassembled.Load(),
		tixTCPStatFragmentDuplicates:                      session.fragmentDuplicates.Load(),
		tixTCPStatFragmentExpiredAssemblies:               session.fragmentExpiredAssemblies.Load(),
		tixTCPStatFragmentExpiredFragments:                session.fragmentExpiredFragments.Load(),
		tixTCPStatFragmentMismatches:                      session.fragmentMismatches.Load(),
		tixTCPStatFragmentRejects:                         session.fragmentRejects.Load(),
		tixTCPStatFragmentPayloadSize:                     uint64(session.fragmentPayloadSize()),
		tixTCPStatTIXBExpandedPackets:                     session.tixbExpandedPackets.Load(),
		tixTCPStatTIXBExpandedItems:                       session.tixbExpandedItems.Load(),
		tixTCPStatInnerTCPChecksumPartialLocal:            tixTCPBoolUint64(localPartial),
		tixTCPStatInnerTCPChecksumPartialPeer:             tixTCPBoolUint64(peerPartial),
		tixTCPStatInnerTCPChecksumPartialNegotiated:       tixTCPBoolUint64(negotiatedPartial),
		tixTCPStatSecureInnerTCPChecksumPartialLocal:      tixTCPBoolUint64(localSecurePartial),
		tixTCPStatSecureInnerTCPChecksumPartialPeer:       tixTCPBoolUint64(peerSecurePartial),
		tixTCPStatSecureInnerTCPChecksumPartialNegotiated: tixTCPBoolUint64(negotiatedSecurePartial),
		tixTCPStatInnerGSOLocal:                           tixTCPBoolUint64(localGSO),
		tixTCPStatInnerGSOPeer:                            tixTCPBoolUint64(peerGSO),
		tixTCPStatInnerGSONegotiated:                      tixTCPBoolUint64(negotiatedGSO),
		tixTCPStatPortShardingLocal:                       tixTCPBoolUint64(localPortSharding),
		tixTCPStatPortShardingPeer:                        tixTCPBoolUint64(peerPortSharding),
		tixTCPStatPortShardingNegotiated:                  tixTCPBoolUint64(negotiatedPortSharding),
		tixTCPStatKernelDatapathReadyLocal:                tixTCPBoolUint64(localReady),
		tixTCPStatKernelDatapathReadyPeer:                 tixTCPBoolUint64(peerReady),
		tixTCPStatKernelDatapathReadyNegotiated:           tixTCPBoolUint64(negotiatedReady),
		tixTCPStatCapabilityWithdrawals:                   session.capabilityWithdrawals.Load(),
		tixTCPStatCapabilityWithdrawalAcks:                session.capabilityWithdrawalAcks.Load(),
		tixTCPStatCapabilityWithdrawalAckTimeouts:         session.capabilityAckTimeouts.Load(),
	}
	if session.fullPlaintextKernelDatapath {
		extra[tixTCPStatFullPlaintextKernel] = 1
	}
	if session.fullSecureKernelDatapath {
		extra[tixTCPStatFullSecureKernel] = 1
	}
	session.recvMu.Lock()
	extra[tixTCPStatFragmentAssembliesCurrent] = uint64(len(session.reassembly))
	session.recvMu.Unlock()
	return extra
}

func tixTCPBoolUint64(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}

func (session *session) effectiveCryptoPlacement() dataplane.CryptoPlacement {
	if session.cryptoOffloaded {
		return session.cryptoPlacement
	}
	return dataplane.CryptoPlacementUserspace
}

func randomFlowID() (uint64, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("generate tix_tcp flow id: %w", err)
	}
	flowID := binary.BigEndian.Uint64(buf[:])
	if flowID == 0 {
		flowID = 1
	}
	return flowID, nil
}

func fragmentCount(packetLen int) int {
	return fragmentCountForSize(packetLen, tixTCPFragmentPayloadSize)
}

func fragmentCountForSize(packetLen int, payloadSize int) int {
	if payloadSize <= 0 {
		payloadSize = tixTCPFragmentPayloadSize
	}
	if packetLen <= payloadSize {
		return 1
	}
	return (packetLen + payloadSize - 1) / payloadSize
}

func (session *session) fragmentPayloadSize() int {
	configured := session.configuredFragmentPayload
	if configured == 0 {
		configured = tixTCPFragmentPayloadSizeForPlacement(session.cryptoPlacement, session.cryptoOffloaded)
	}
	key := fragmentPayloadCacheKey{
		placement:  session.cryptoPlacement,
		offloaded:  session.cryptoOffloaded,
		configured: configured,
	}
	if session.fragmentPayloadCached > 0 && session.fragmentPayloadCacheKey == key {
		return session.fragmentPayloadCached
	}
	payloadSize := session.clampFragmentPayloadSize(configured)
	session.fragmentPayloadCacheKey = key
	session.fragmentPayloadCached = payloadSize
	return payloadSize
}

func (session *session) maxPacketSize() int {
	payloadSize := session.fragmentPayloadSize()
	maxPacket := payloadSize * tixTCPMaxFragments
	if payloadSize < 1 {
		return 1
	}
	if session.kernelCryptoSealBeforeFragment() {
		maxPacket -= tixTCPSecureFrameOverhead
	}
	if maxPacket < 1 {
		return 1
	}
	if configured := tixTCPConfiguredMaxPacketSize(); configured > 0 && maxPacket > configured {
		maxPacket = configured
	}
	if maxPacket < 1 {
		return 1
	}
	if maxPacket > MaxPayload {
		return MaxPayload
	}
	return maxPacket
}

func (session *session) clampFragmentPayloadSize(payloadSize int) int {
	if sizer, ok := session.provider.(dataplane.TIXTCPPayloadSizer); ok {
		if maxSize, err := sizer.TIXTCPPayloadMax(context.Background(), session.cryptoPlacement, session.cryptoOffloaded); err == nil && maxSize > 0 {
			if tixTCPAutoFragmentPayloadEnabled() && payloadSize < maxSize {
				payloadSize = maxSize
			}
			if payloadSize > maxSize {
				payloadSize = maxSize
			}
		}
	}
	if payloadSize < 1 {
		return 1
	}
	return payloadSize
}

func tixTCPConfiguredMaxPacketSize() int {
	const minSize = 576
	value := strings.TrimSpace(os.Getenv("TRUSTIX_TIX_TCP_MAX_PACKET_SIZE"))
	if value == "" {
		return 0
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minSize {
		return 0
	}
	if parsed > MaxPayload {
		return MaxPayload
	}
	return parsed
}

func tixTCPFragmentPayloadSizeForPlacement(placement dataplane.CryptoPlacement, offloaded bool) int {
	if placement == dataplane.CryptoPlacementKernel || offloaded {
		return tixTCPConfiguredFragmentPayloadSize(tixTCPKernelFragmentPayloadMax)
	}
	return tixTCPConfiguredFragmentPayloadSize(tixTCPFragmentPayloadMax)
}

func tixTCPConfiguredFragmentPayloadSize(maxSize int) int {
	const (
		defaultSize = tixTCPFragmentPayloadSize
		minSize     = 576
	)
	value := strings.TrimSpace(os.Getenv("TRUSTIX_TIX_TCP_FRAGMENT_PAYLOAD_SIZE"))
	if value == "" {
		return defaultSize
	}
	if strings.EqualFold(value, "auto") {
		if maxSize < minSize {
			return maxSize
		}
		return maxSize
	}
	if strings.EqualFold(value, "legacy") {
		if tixTCPUserspaceCryptoPayloadHint < maxSize {
			return tixTCPUserspaceCryptoPayloadHint
		}
		return maxSize
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minSize {
		return defaultSize
	}
	if parsed > maxSize {
		return maxSize
	}
	return parsed
}

func tixTCPAutoFragmentPayloadEnabled() bool {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_TIX_TCP_FRAGMENT_PAYLOAD_SIZE"))
	return value == "" && envTruthy(
		"TRUSTIX_TIX_TCP_AUTO_FRAGMENT_PAYLOAD",
		"TRUSTIX_TIX_TCP_FRAGMENT_PAYLOAD_AUTO_MAX",
	)
}

func tixTCPKernelSealBeforeFragmentEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_TIX_TCP_KERNEL_SEAL_BEFORE_FRAGMENT"))) {
	case "", "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}

func tixTCPKernelSealBeforeFragmentWireMaxEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_TIX_TCP_KERNEL_SEAL_BEFORE_FRAGMENT_WIRE_MAX"))) {
	case "0", "false", "no", "off", "disabled":
		return false
	case "1", "true", "yes", "on", "enabled", "force":
		return true
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_TIX_TCP_KERNEL_SEAL_BEFORE_FRAGMENT_MAX_WIRE"))) {
	case "0", "false", "no", "off", "disabled":
		return false
	case "1", "true", "yes", "on", "enabled", "force":
		return true
	}
	return false
}
