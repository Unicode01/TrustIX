// Package udp implements TrustIX's basic datagram transport. It is intentionally
// small: encryption and replay protection belong to the overlay/crypto layer
// above this transport boundary.
package udp

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/transport"
	"trustix.local/trustix/internal/transport/bind"
	"trustix.local/trustix/internal/transport/kerneludp"
)

// Kernel UDP bursts arrive from AF_XDP faster than userspace crypto/inject can
// drain them. Keep the default bounded; very large queues only hide sustained
// bottlenecks and can pin hundreds of MiB of packet buffers.
const (
	kernelSessionBufferDefault              = 512
	kernelSessionBufferMax                  = 8192
	kernelUDPReassemblyMaxAssembliesDefault = 1024
	kernelUDPReassemblyMaxAssembliesMax     = 8192
)

const (
	kernelUDPFragmentPayloadSize       = 1426
	kernelUDPFragmentPayloadMax        = 32000
	kernelUDPKernelFragmentPayloadSize = 1386
	kernelUDPKernelFragmentPayloadMax  = 32000
	kernelUDPMaxFragments              = 256
	kernelUDPSealBeforeFragmentMax     = 512*1024 - 16
	kernelUDPReassemblyTTL             = 30 * time.Second
)

const (
	userspaceUDPSessionMaxPacket      = 64*1024 - 1
	userspaceUDPDatagramPayloadMax    = userspaceUDPSessionMaxPacket - 20 - 8
	userspaceUDPDatagramDefaultMax    = 16 * 1024
	userspaceUDPDatagramBatchMax      = 1500 - 20 - 8
	userspaceUDPListenerBufferDefault = 64
	userspaceUDPListenerBufferMax     = 256
	userspaceUDPCompactMinWaste       = 256 * 1024
	userspaceUDPCompactWasteFactor    = 2
	userspaceUDPReadBatchDefault      = 64
	userspaceUDPReadBatchMax          = 256
)

var kernelUDPPacketBatchPool = sync.Pool{
	New: func() any {
		return &kernelUDPPacketBatch{
			packets: make([][]byte, 0, 256),
		}
	},
}

var trustIXSecureHandshakeMagic = [4]byte{'T', 'I', 'X', 'H'}

const (
	kernelUDPStatFragmentedPacketsSent     = "kernel_udp_fragmented_packets_sent"
	kernelUDPStatFragmentsSent             = "kernel_udp_fragments_sent"
	kernelUDPStatFragmentsReceived         = "kernel_udp_fragments_received"
	kernelUDPStatFragmentedPacketsReceived = "kernel_udp_fragmented_packets_received"
	kernelUDPStatFragmentsReassembled      = "kernel_udp_fragments_reassembled"
	kernelUDPStatFragmentAssembliesCurrent = "kernel_udp_fragment_assemblies_current"
	kernelUDPStatFragmentDuplicates        = "kernel_udp_fragment_duplicates"
	kernelUDPStatFragmentExpiredAssemblies = "kernel_udp_fragment_expired_assemblies"
	kernelUDPStatFragmentExpiredFragments  = "kernel_udp_fragment_expired_fragments"
	kernelUDPStatFragmentMismatches        = "kernel_udp_fragment_mismatches"
	kernelUDPStatFragmentRejects           = "kernel_udp_fragment_rejects"
	kernelUDPStatFragmentPayloadSize       = "kernel_udp_fragment_payload_size"
)

type Transport struct {
	kernel  dataplane.KernelUDPProvider
	options Options
}

type Options struct {
	CryptoPlacement          func() dataplane.CryptoPlacement
	KernelTransport          func() dataplane.KernelTransportMode
	Encryption               func() string
	RequireSecureClientHello bool
}

func New(options ...Options) *Transport {
	var opts Options
	if len(options) > 0 {
		opts = options[0]
	}
	return &Transport{options: opts}
}

func NewWithKernelProvider(provider dataplane.KernelUDPProvider, options ...Options) *Transport {
	var opts Options
	if len(options) > 0 {
		opts = options[0]
	}
	return &Transport{kernel: provider, options: opts}
}

func kernelSessionBuffer() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_SESSION_BUFFER"))
	if value == "" {
		return kernelSessionBufferDefault
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return kernelSessionBufferDefault
	}
	if parsed > kernelSessionBufferMax {
		return kernelSessionBufferMax
	}
	return parsed
}

func kernelUDPReassemblyMaxAssemblies() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_REASSEMBLY_MAX_ASSEMBLIES"))
	if value == "" {
		return kernelUDPReassemblyMaxAssembliesDefault
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return kernelUDPReassemblyMaxAssembliesDefault
	}
	if parsed > kernelUDPReassemblyMaxAssembliesMax {
		return kernelUDPReassemblyMaxAssembliesMax
	}
	return parsed
}

func (transportImpl *Transport) Name() transport.Protocol {
	return transport.ProtocolUDP
}

func (transportImpl *Transport) Probe(ctx context.Context, peer transport.Peer) transport.ProbeResult {
	if transportImpl.kernelTransportEnabled() && transportImpl.kernel != nil {
		status, err := transportImpl.kernel.KernelUDPStatus(ctx)
		if err == nil {
			for _, endpoint := range peer.Endpoints {
				if endpoint.Transport == transport.ProtocolUDP && endpoint.Address != "" {
					effectiveEncryption := transportImpl.effectiveEncryption(endpoint.Encryption)
					placement, placementErr := transportImpl.selectCryptoPlacementFromStatus(status, endpoint.Encryption)
					if placementErr == nil && kernelUDPStatusDirectOnlyKernelManaged(status, effectiveEncryption, placement) {
						return transport.ProbeResult{Healthy: true, CheckedAt: time.Now()}
					}
					if !kernelUDPStatusCanDial(status) {
						continue
					}
					if placementErr != nil {
						return transport.ProbeResult{Healthy: false, Error: placementErr.Error(), CheckedAt: time.Now()}
					}
					return transport.ProbeResult{Healthy: true, CheckedAt: time.Now()}
				}
			}
		}
		if transportImpl.kernelTransportRequired() {
			if err != nil {
				return transport.ProbeResult{Healthy: false, Error: err.Error(), CheckedAt: time.Now()}
			}
			return transport.ProbeResult{Healthy: false, Error: kernelUDPUnavailableError(status).Error(), CheckedAt: time.Now()}
		}
	} else if transportImpl.kernelTransportRequired() {
		return transport.ProbeResult{Healthy: false, Error: "kernel_udp kernel transport requested but provider is unavailable", CheckedAt: time.Now()}
	}
	if transportImpl.requestedCryptoPlacement() == dataplane.CryptoPlacementKernel {
		return transport.ProbeResult{Healthy: false, Error: "kernel_udp kernel crypto requested but kernel UDP provider is unavailable", CheckedAt: time.Now()}
	}
	start := time.Now()
	for _, endpoint := range peer.Endpoints {
		if endpoint.Transport != transport.ProtocolUDP || endpoint.Address == "" {
			continue
		}
		dialer, err := bind.Dialer(endpoint, "udp")
		if err != nil {
			return transport.ProbeResult{Healthy: false, Error: err.Error(), CheckedAt: time.Now()}
		}
		conn, err := dialer.DialContext(ctx, "udp", endpoint.Address)
		if err != nil {
			return transport.ProbeResult{Healthy: false, Error: err.Error(), CheckedAt: time.Now()}
		}
		if err := conn.Close(); err != nil {
			return transport.ProbeResult{Healthy: false, Error: fmt.Sprintf("close udp probe connection: %v", err), CheckedAt: time.Now()}
		}
		return transport.ProbeResult{Healthy: true, RTT: time.Since(start), CheckedAt: time.Now()}
	}
	return transport.ProbeResult{Healthy: false, Error: "no udp endpoint", CheckedAt: time.Now()}
}

func (transportImpl *Transport) Dial(ctx context.Context, peer transport.Peer, tlsConf *tls.Config) (transport.Session, error) {
	if session, ok, err := transportImpl.dialKernel(ctx, peer); ok || err != nil {
		return session, err
	}
	if transportImpl.requestedCryptoPlacement() == dataplane.CryptoPlacementKernel {
		return nil, fmt.Errorf("kernel_udp kernel crypto requested but kernel UDP provider is unavailable")
	}
	for _, endpoint := range peer.Endpoints {
		if endpoint.Transport != transport.ProtocolUDP || endpoint.Address == "" {
			continue
		}
		dialer, err := bind.Dialer(endpoint, "udp")
		if err != nil {
			return nil, err
		}
		conn, err := dialer.DialContext(ctx, "udp", endpoint.Address)
		if err != nil {
			return nil, err
		}
		udpConn, ok := conn.(*net.UDPConn)
		if !ok {
			return nil, errors.Join(
				fmt.Errorf("dial udp returned %T", conn),
				udpCleanupError("close unexpected udp connection", conn.Close()),
			)
		}
		if err := configureUDPConn(udpConn); err != nil {
			return nil, errors.Join(err, udpCleanupError("close UDP connection after socket setup failure", udpConn.Close()))
		}
		return &session{conn: udpConn}, nil
	}
	return nil, fmt.Errorf("peer %q has no dialable udp endpoint", peer.ID)
}

func (transportImpl *Transport) Listen(ctx context.Context, ep transport.Endpoint, tlsConf *tls.Config) (transport.Listener, error) {
	if ep.Transport != transport.ProtocolUDP {
		return nil, fmt.Errorf("endpoint %q transport is %q, want udp", ep.Name, ep.Transport)
	}
	if listener, ok, err := transportImpl.listenKernel(ctx, ep); ok || err != nil {
		return listener, err
	}
	if transportImpl.requestedCryptoPlacement() == dataplane.CryptoPlacementKernel {
		return nil, fmt.Errorf("kernel_udp kernel crypto requested but kernel UDP provider is unavailable")
	}
	addr := ep.Listen
	if addr == "" {
		addr = ep.Address
	}
	if addr == "" {
		return nil, fmt.Errorf("udp endpoint %q listen address is required", ep.Name)
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	if err := configureUDPConn(conn); err != nil {
		return nil, errors.Join(err, udpCleanupError("close UDP listener after socket setup failure", conn.Close()))
	}
	listener := &listener{
		conn:     conn,
		acceptCh: make(chan transport.Session, 64),
		sessions: make(map[string]*serverSession),
		done:     make(chan struct{}),
	}
	go func() {
		<-ctx.Done()
		transport.ObserveAsyncError("close UDP listener after context cancellation", listener.Close())
	}()
	for i := 0; i < userspaceUDPReadWorkers(); i++ {
		go listener.readLoop()
	}
	return listener, nil
}

func userspaceUDPReadWorkers() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_UDP_READ_WORKERS"))
	if value == "" {
		return 1
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 1
	}
	maxWorkers := runtime.GOMAXPROCS(0)
	if maxWorkers < 1 {
		maxWorkers = 1
	}
	if maxWorkers > 16 {
		maxWorkers = 16
	}
	if parsed > maxWorkers {
		return maxWorkers
	}
	return parsed
}

func userspaceUDPReadBatch() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_UDP_READ_BATCH"))
	if value == "" {
		return userspaceUDPReadBatchDefault
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return userspaceUDPReadBatchDefault
	}
	if parsed > userspaceUDPReadBatchMax {
		return userspaceUDPReadBatchMax
	}
	return parsed
}

func userspaceUDPListenerBufferSize() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_UDP_LISTENER_BUFFER"))
	if value == "" {
		return userspaceUDPListenerBufferDefault
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return userspaceUDPListenerBufferDefault
	}
	if parsed > userspaceUDPListenerBufferMax {
		return userspaceUDPListenerBufferMax
	}
	return parsed
}

func userspaceUDPReadPacketSize() int {
	const minSize = 576
	value := strings.TrimSpace(os.Getenv("TRUSTIX_UDP_READ_PACKET_SIZE"))
	if value == "" {
		return defaultUserspaceUDPReadPacketSize()
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minSize {
		return defaultUserspaceUDPReadPacketSize()
	}
	if parsed > userspaceUDPSessionMaxPacket {
		return userspaceUDPSessionMaxPacket
	}
	return parsed
}

func userspaceUDPDatagramMaxPacketSize() uint64 {
	return uint64(userspaceUDPConfiguredDatagramMaxPacketSize())
}

func userspaceUDPConfiguredDatagramMaxPacketSize() int {
	defaultMax := defaultUserspaceUDPDatagramMaxPacketSize()
	value := strings.TrimSpace(os.Getenv("TRUSTIX_UDP_DATAGRAM_MAX_PACKET_SIZE"))
	if value == "" {
		return defaultMax
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < userspaceUDPDatagramBatchMax {
		return defaultMax
	}
	if parsed > userspaceUDPDatagramPayloadMax {
		return userspaceUDPDatagramPayloadMax
	}
	return parsed
}

func (transportImpl *Transport) dialKernel(ctx context.Context, peer transport.Peer) (transport.Session, bool, error) {
	if !transportImpl.kernelTransportEnabled() {
		if transportImpl.requestedCryptoPlacement() == dataplane.CryptoPlacementKernel {
			return nil, true, fmt.Errorf("kernel_udp kernel crypto requested but kernel transport is disabled")
		}
		return nil, false, nil
	}
	if transportImpl.kernel == nil {
		if transportImpl.kernelTransportRequired() {
			return nil, true, fmt.Errorf("kernel_udp kernel transport requested but provider is unavailable")
		}
		return nil, false, nil
	}
	status, err := transportImpl.kernel.KernelUDPStatus(ctx)
	if err != nil || !kernelUDPStatusCanDial(status) {
		if transportImpl.kernelTransportRequired() || transportImpl.requestedCryptoPlacement() == dataplane.CryptoPlacementKernel {
			if err != nil {
				return nil, true, err
			}
			for _, endpoint := range peer.Endpoints {
				if endpoint.Transport != transport.ProtocolUDP || endpoint.Address == "" {
					continue
				}
				effectiveEncryption := transportImpl.effectiveEncryption(endpoint.Encryption)
				placement, placementErr := transportImpl.selectCryptoPlacementFromStatus(status, endpoint.Encryption)
				if placementErr != nil {
					return nil, true, placementErr
				}
				if kernelUDPStatusDirectOnlyKernelManaged(status, effectiveEncryption, placement) {
					return transportImpl.dialKernelUDPFlow(ctx, peer, endpoint, status, placement, effectiveEncryption)
				}
			}
			return nil, true, kernelUDPUnavailableError(status)
		}
		return nil, false, nil
	}
	for _, endpoint := range peer.Endpoints {
		if endpoint.Transport != transport.ProtocolUDP || endpoint.Address == "" {
			continue
		}
		placement, err := transportImpl.selectCryptoPlacementFromStatus(status, endpoint.Encryption)
		if err != nil {
			return nil, true, err
		}
		effectiveEncryption := transportImpl.effectiveEncryption(endpoint.Encryption)
		return transportImpl.dialKernelUDPFlow(ctx, peer, endpoint, status, placement, effectiveEncryption)
	}
	return nil, false, nil
}

func kernelUDPStatusCanDial(status dataplane.KernelUDPStatus) bool {
	return status.Available && status.Reinject
}

func (transportImpl *Transport) dialKernelUDPFlow(ctx context.Context, peer transport.Peer, endpoint transport.Endpoint, status dataplane.KernelUDPStatus, placement dataplane.CryptoPlacement, effectiveEncryption string) (transport.Session, bool, error) {
	flowID, err := randomFlowID()
	if err != nil {
		return nil, true, err
	}
	if err := transportImpl.kernel.InstallKernelUDPFlows(ctx, []dataplane.KernelUDPFlow{{
		ID:              flowID,
		Peer:            peer.ID,
		Endpoint:        endpoint.Name,
		Role:            dataplane.KernelUDPFlowRoleOutbound,
		LocalAddress:    strings.TrimSpace(endpoint.LocalBind.SourceIP),
		RemoteAddress:   endpoint.Address,
		CryptoPlacement: placement,
		CreatedAt:       time.Now().UTC(),
	}}); err != nil {
		return nil, true, err
	}
	if kernelUDPStatusDirectOnlyKernelManaged(status, effectiveEncryption, placement) {
		if kernelUDPStatusNeedsControlSubscription(status, effectiveEncryption, placement) {
			subscription, err := transportImpl.subscribeKernelFlow(ctx, flowID)
			if err != nil {
				return nil, true, errors.Join(err, transportImpl.deleteKernelUDPFlowAfterSetupFailure(flowID))
			}
			session := newKernelSession(transportImpl.kernel, subscription, flowID, peer.ID, endpoint.Name, placement, "", endpoint.Address)
			go session.readSubscription(context.Background())
			return session, true, nil
		}
		return newKernelSession(transportImpl.kernel, nil, flowID, peer.ID, endpoint.Name, placement, "", endpoint.Address), true, nil
	}
	if status.DirectOnly || status.TCOnly {
		return nil, true, errors.Join(
			kernelUDPDirectOnlyUnsupportedError(status, effectiveEncryption, placement),
			transportImpl.deleteKernelUDPFlowAfterSetupFailure(flowID),
		)
	}
	subscription, err := transportImpl.subscribeKernelFlow(ctx, flowID)
	if err != nil {
		return nil, true, errors.Join(err, transportImpl.deleteKernelUDPFlowAfterSetupFailure(flowID))
	}
	session := newKernelSession(transportImpl.kernel, subscription, flowID, peer.ID, endpoint.Name, placement, "", endpoint.Address)
	// Dial callers often use a short-lived context just for setup. Keep the
	// receive pump tied to Session.Close instead of that setup deadline.
	go session.readSubscription(context.Background())
	return session, true, nil
}

func (transportImpl *Transport) deleteKernelUDPFlowAfterSetupFailure(flowID uint64) error {
	deleter, ok := transportImpl.kernel.(dataplane.KernelUDPFlowDeleter)
	if !ok {
		return nil
	}
	return udpCleanupError(
		fmt.Sprintf("delete kernel_udp flow %d after setup failure", flowID),
		deleter.DeleteKernelUDPFlows(context.Background(), []uint64{flowID}),
	)
}

func (transportImpl *Transport) subscribeKernelFlow(ctx context.Context, flowID uint64) (dataplane.KernelUDPSubscription, error) {
	if subscriber, ok := transportImpl.kernel.(dataplane.KernelUDPFlowSubscriber); ok {
		return subscriber.SubscribeKernelUDPFlow(ctx, flowID, kernelSessionBuffer())
	}
	return transportImpl.kernel.SubscribeKernelUDP(ctx, kernelSessionBuffer())
}

func (transportImpl *Transport) listenKernel(ctx context.Context, ep transport.Endpoint) (transport.Listener, bool, error) {
	if !transportImpl.kernelTransportEnabled() {
		if transportImpl.requestedCryptoPlacement() == dataplane.CryptoPlacementKernel {
			return nil, true, fmt.Errorf("kernel_udp kernel crypto requested but kernel transport is disabled")
		}
		return nil, false, nil
	}
	if transportImpl.kernel == nil {
		if transportImpl.kernelTransportRequired() {
			return nil, true, fmt.Errorf("kernel_udp kernel transport requested but provider is unavailable")
		}
		return nil, false, nil
	}
	status, err := transportImpl.kernel.KernelUDPStatus(ctx)
	if err != nil || !status.Available || !status.Reinject {
		if !transportImpl.kernelTransportRequired() && transportImpl.requestedCryptoPlacement() != dataplane.CryptoPlacementKernel {
			return nil, false, nil
		}
		if err != nil {
			return nil, true, err
		}
		effectiveEncryption := transportImpl.effectiveEncryption(ep.Encryption)
		placement, placementErr := transportImpl.selectCryptoPlacementFromStatus(status, ep.Encryption)
		if placementErr != nil {
			return nil, true, placementErr
		}
		if kernelUDPStatusDirectOnlyKernelManaged(status, effectiveEncryption, placement) {
			var subscription dataplane.KernelUDPSubscription
			if kernelUDPStatusNeedsControlSubscription(status, effectiveEncryption, placement) {
				var err error
				subscription, err = transportImpl.kernel.SubscribeKernelUDP(ctx, kernelSessionBuffer())
				if err != nil {
					return nil, true, err
				}
			}
			requireSecureClientHello := transportImpl.options.RequireSecureClientHello && !kernelUDPPlaintextEncryption(effectiveEncryption)
			listener := &kernelListener{
				provider:                 transportImpl.kernel,
				endpoint:                 ep,
				subscription:             subscription,
				acceptCh:                 make(chan transport.Session, 64),
				done:                     make(chan struct{}),
				sessions:                 make(map[uint64]*kernelSession),
				placement:                placement,
				requireSecureClientHello: requireSecureClientHello,
			}
			go func() {
				<-ctx.Done()
				transport.ObserveAsyncError("close kernel UDP listener after context cancellation", listener.Close())
			}()
			if subscription != nil {
				go listener.readSubscription(ctx)
			}
			return listener, true, nil
		}
		return nil, true, kernelUDPUnavailableError(status)
	}
	placement, err := transportImpl.selectCryptoPlacementFromStatus(status, ep.Encryption)
	if err != nil {
		return nil, true, err
	}
	effectiveEncryption := transportImpl.effectiveEncryption(ep.Encryption)
	requireSecureClientHello := transportImpl.options.RequireSecureClientHello && !kernelUDPPlaintextEncryption(effectiveEncryption)
	if kernelUDPStatusDirectOnlyKernelManaged(status, effectiveEncryption, placement) {
		var subscription dataplane.KernelUDPSubscription
		if kernelUDPStatusNeedsControlSubscription(status, effectiveEncryption, placement) {
			var err error
			subscription, err = transportImpl.kernel.SubscribeKernelUDP(ctx, kernelSessionBuffer())
			if err != nil {
				return nil, true, err
			}
		}
		listener := &kernelListener{
			provider:                 transportImpl.kernel,
			endpoint:                 ep,
			subscription:             subscription,
			acceptCh:                 make(chan transport.Session, 64),
			done:                     make(chan struct{}),
			sessions:                 make(map[uint64]*kernelSession),
			placement:                placement,
			requireSecureClientHello: requireSecureClientHello,
		}
		go func() {
			<-ctx.Done()
			transport.ObserveAsyncError("close kernel UDP listener after context cancellation", listener.Close())
		}()
		if subscription != nil {
			go listener.readSubscription(ctx)
		}
		return listener, true, nil
	}
	if status.DirectOnly || status.TCOnly {
		return nil, true, kernelUDPDirectOnlyUnsupportedError(status, effectiveEncryption, placement)
	}
	subscription, err := transportImpl.kernel.SubscribeKernelUDP(ctx, kernelSessionBuffer())
	if err != nil {
		return nil, true, err
	}
	listener := &kernelListener{
		provider:                 transportImpl.kernel,
		endpoint:                 ep,
		subscription:             subscription,
		acceptCh:                 make(chan transport.Session, 64),
		done:                     make(chan struct{}),
		sessions:                 make(map[uint64]*kernelSession),
		placement:                placement,
		requireSecureClientHello: requireSecureClientHello,
	}
	go listener.readSubscription(ctx)
	return listener, true, nil
}

func kernelUDPStatusDirectOnlyKernelManaged(status dataplane.KernelUDPStatus, encryption string, placement dataplane.CryptoPlacement) bool {
	if !status.DirectOnly && !status.TCOnly {
		return false
	}
	if kernelUDPPlaintextEncryption(encryption) {
		return true
	}
	return normalizeCryptoPlacement(placement) == dataplane.CryptoPlacementKernel && status.KernelCrypto
}

func kernelUDPStatusNeedsControlSubscription(status dataplane.KernelUDPStatus, encryption string, placement dataplane.CryptoPlacement) bool {
	return kernelUDPStatusDirectOnlyKernelManaged(status, encryption, placement) && !kernelUDPPlaintextEncryption(encryption)
}

func kernelUDPDirectOnlyUnsupportedError(status dataplane.KernelUDPStatus, encryption string, placement dataplane.CryptoPlacement) error {
	return fmt.Errorf(
		"kernel_udp direct-only provider cannot use userspace subscription: provider=%q direct_only=%t tc_only=%t userspace_crypto=%t kernel_crypto=%t preferred_crypto=%q requested_crypto=%q effective_crypto=%q encryption=%q selected_crypto=%q",
		status.Provider,
		status.DirectOnly,
		status.TCOnly,
		status.UserspaceCrypto,
		status.KernelCrypto,
		status.PreferredCrypto,
		status.RequestedCrypto,
		status.EffectiveCrypto,
		encryption,
		placement,
	)
}

func (transportImpl *Transport) requestedCryptoPlacement() dataplane.CryptoPlacement {
	if transportImpl.options.CryptoPlacement == nil {
		return dataplane.CryptoPlacementAuto
	}
	return normalizeCryptoPlacement(transportImpl.options.CryptoPlacement())
}

func (transportImpl *Transport) kernelTransportEnabled() bool {
	if transportImpl.options.KernelTransport == nil {
		return true
	}
	return transportImpl.options.KernelTransport() != dataplane.KernelTransportModeDisabled
}

func (transportImpl *Transport) kernelTransportRequired() bool {
	return transportImpl.options.KernelTransport != nil &&
		transportImpl.options.KernelTransport() == dataplane.KernelTransportModeRequireKernel
}

func kernelUDPUnavailableError(status dataplane.KernelUDPStatus) error {
	if !status.Available {
		if status.Provider != "" && status.Provider != "none" {
			return fmt.Errorf("kernel_udp kernel transport provider %q is unavailable", status.Provider)
		}
		return fmt.Errorf("kernel_udp kernel transport provider is unavailable")
	}
	if !status.Reinject {
		return fmt.Errorf("kernel_udp TC/XDP reinject is unavailable")
	}
	return fmt.Errorf("kernel_udp kernel transport is unavailable")
}

func (transportImpl *Transport) selectCryptoPlacementFromStatus(status dataplane.KernelUDPStatus, encryption string) (dataplane.CryptoPlacement, error) {
	if kernelUDPPlaintextEncryption(transportImpl.effectiveEncryption(encryption)) {
		return dataplane.CryptoPlacementUserspace, nil
	}
	return selectCryptoPlacement(transportImpl.requestedCryptoPlacement(), status)
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

func kernelUDPPlaintextEncryption(encryption string) bool {
	switch strings.ToLower(strings.TrimSpace(encryption)) {
	case "plaintext", "none", "disabled", "off":
		return true
	default:
		return false
	}
}

func selectCryptoPlacement(requested dataplane.CryptoPlacement, status dataplane.KernelUDPStatus) (dataplane.CryptoPlacement, error) {
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
		return "", fmt.Errorf("kernel_udp kernel crypto requested but unavailable: %s", reason)
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
		return "", fmt.Errorf("kernel_udp has no available crypto placement")
	case dataplane.CryptoPlacementUserspace:
		if status.UserspaceCrypto {
			return dataplane.CryptoPlacementUserspace, nil
		}
		return "", fmt.Errorf("kernel_udp userspace crypto is not available")
	default:
		return "", fmt.Errorf("kernel_udp crypto placement %q is unsupported", requested)
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

type listener struct {
	conn      *net.UDPConn
	acceptCh  chan transport.Session
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
	mu        sync.Mutex
	sessions  map[string]*serverSession
}

func (listener *listener) Accept(ctx context.Context) (transport.Session, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-listener.done:
		return nil, net.ErrClosed
	case session := <-listener.acceptCh:
		if session == nil {
			return nil, net.ErrClosed
		}
		return session, nil
	}
}

func (listener *listener) Close() error {
	listener.closeOnce.Do(func() {
		close(listener.done)
		listener.closeErr = listener.conn.Close()
		listener.mu.Lock()
		for key, session := range listener.sessions {
			session.closeInput()
			delete(listener.sessions, key)
		}
		listener.mu.Unlock()
	})
	return listener.closeErr
}

func (listener *listener) readLoop() {
	for {
		packets, _, release, err := recvUDPBatchFrom(listener.conn, userspaceUDPReadBatch(), userspaceUDPReadPacketSize())
		if len(packets) > 0 {
			releaseOwned := listener.dispatchPackets(packets, release)
			if release != nil && !releaseOwned {
				release()
			}
		} else if release != nil {
			release()
		}
		if err != nil {
			if udpReadErrorClosed(err) {
				transport.ObserveAsyncError("close UDP listener after receive closure", listener.Close())
				return
			}
			transport.ObserveAsyncError("receive UDP listener batch", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}
	}
}

func (listener *listener) dispatchPackets(packets []udpReceivedPacket, release func()) bool {
	if len(packets) == 0 {
		return false
	}
	if release != nil {
		if session, payloads := listener.singleRemoteBatch(packets); session != nil {
			if session.enqueueBatch(udpPacketBatch{packets: payloads, release: release, retainedBytes: udpPayloadsRetainedBytes(payloads)}) {
				return true
			}
			release()
			return true
		}
	}
	var session *serverSession
	var batch [][]byte
	for i := 0; i < len(packets); {
		received := packets[i]
		if received.addr == nil {
			i++
			continue
		}
		session = listener.sessionForAddr(received.addr)
		if session == nil {
			i++
			continue
		}
		batch = batch[:0]
		key := received.addr.String()
		for i < len(packets) {
			item := packets[i]
			if item.addr == nil || item.addr.String() != key {
				break
			}
			batch = append(batch, append([]byte(nil), item.payload...))
			i++
		}
		session.enqueueBatch(udpPacketBatch{packets: batch})
	}
	return false
}

func (listener *listener) singleRemoteBatch(packets []udpReceivedPacket) (*serverSession, [][]byte) {
	if len(packets) == 0 || packets[0].addr == nil {
		return nil, nil
	}
	first := packets[0].addr
	payloads := make([][]byte, 0, len(packets))
	for _, packet := range packets {
		if packet.addr == nil || packet.addr.Port != first.Port || !packet.addr.IP.Equal(first.IP) {
			return nil, nil
		}
		payloads = append(payloads, packet.payload)
	}
	session := listener.sessionForAddr(first)
	if session == nil {
		return nil, nil
	}
	return session, payloads
}

func (listener *listener) sessionForAddr(addr *net.UDPAddr) *serverSession {
	key := addr.String()
	listener.mu.Lock()
	defer listener.mu.Unlock()
	session := listener.sessions[key]
	if session == nil {
		session = &serverSession{
			conn:     listener.conn,
			remote:   addr,
			in:       make(chan udpPacketBatch, userspaceUDPListenerBufferSize()),
			listener: listener,
			key:      key,
		}
		listener.sessions[key] = session
		select {
		case listener.acceptCh <- session:
		default:
			delete(listener.sessions, key)
			close(session.in)
			return nil
		}
	}
	return session
}

type session struct {
	conn                  *net.UDPConn
	recvMu                sync.Mutex
	recvErr               error
	bytesSent             atomic.Uint64
	bytesReceived         atomic.Uint64
	packetsSent           atomic.Uint64
	packetsReceived       atomic.Uint64
	sendBatchCalls        atomic.Uint64
	sendBatchPackets      atomic.Uint64
	sendBatchBytes        atomic.Uint64
	sendBatchMMSGSyscalls atomic.Uint64
	sendBatchLoopSyscalls atomic.Uint64
	sendBatchFallbacks    atomic.Uint64
	recvBatchCalls        atomic.Uint64
	recvBatchPackets      atomic.Uint64
	recvBatchBytes        atomic.Uint64
	recvBatchMMSGSyscalls atomic.Uint64
	recvBatchLoopSyscalls atomic.Uint64
	recvBatchFallbacks    atomic.Uint64
	recvBatchGROPackets   atomic.Uint64
	recvBatchGROSegments  atomic.Uint64
	recvBatchGROBytes     atomic.Uint64
	recvBatchGROErrors    atomic.Uint64
	recvPending           udpPacketBatch
}

func (session *session) SendPacket(pkt []byte) error {
	n, err := session.conn.Write(pkt)
	if err != nil {
		return err
	}
	session.bytesSent.Add(uint64(n))
	session.packetsSent.Add(1)
	return nil
}

func (session *session) SendPackets(pkts [][]byte) error {
	if len(pkts) == 0 {
		return nil
	}
	if len(pkts) == 1 {
		return session.SendPacket(pkts[0])
	}
	result, err := sendUDPBatch(session.conn, pkts)
	if err != nil {
		return err
	}
	session.bytesSent.Add(result.bytesSent)
	session.packetsSent.Add(uint64(len(pkts)))
	session.recordBatchSend(uint64(len(pkts)), result)
	return nil
}

func (session *session) RecvPacket() ([]byte, error) {
	packets, err := session.RecvPackets(1)
	if err != nil {
		return nil, err
	}
	if len(packets) == 0 {
		return session.RecvPacket()
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
	session.recvMu.Lock()
	defer session.recvMu.Unlock()
	if len(session.recvPending.packets) > 0 {
		return session.recvPendingLocked(max)
	}
	if session.recvErr != nil {
		err := session.recvErr
		session.recvErr = nil
		return nil, nil, err
	}
	packets, result, release, err := recvUDPBatch(session.conn, max, userspaceUDPReadPacketSize())
	if err != nil && len(packets) == 0 {
		if release != nil {
			release()
		}
		return nil, nil, err
	}
	if err != nil {
		session.recvErr = err
	}
	if len(packets) > max {
		received := packets
		if release != nil {
			copied := make([][]byte, max)
			for i, packet := range packets[:max] {
				copied[i] = append([]byte(nil), packet...)
			}
			packets = copied
		}
		session.recvPending = udpPacketBatch{packets: received[max:], release: release}
		if release == nil {
			packets = received[:max]
		}
		release = nil
	}
	session.recordReceivedPackets(packets)
	session.recordBatchReceive(uint64(len(packets)), result)
	return packets, release, nil
}

func (session *session) recvPendingLocked(max int) ([][]byte, func(), error) {
	batch := trimUDPPacketBatch(session.recvPending)
	session.recvPending = udpPacketBatch{}
	if len(batch.packets) == 0 {
		if batch.release != nil {
			batch.release()
		}
		return nil, nil, nil
	}
	limit := max
	if limit > len(batch.packets) {
		limit = len(batch.packets)
	}
	packets := batch.packets[:limit]
	var release func()
	if limit == len(batch.packets) {
		release = batch.release
	} else {
		if batch.release != nil {
			copied := make([][]byte, limit)
			for i, packet := range batch.packets[:limit] {
				copied[i] = append([]byte(nil), packet...)
			}
			packets = copied
		}
		session.recvPending = udpPacketBatch{packets: batch.packets[limit:], release: batch.release}
	}
	session.recordReceivedPackets(packets)
	session.recordBatchReceive(uint64(len(packets)), udpBatchReceiveResult{})
	return packets, release, nil
}

func (session *session) recordReceivedPackets(packets [][]byte) {
	var bytes uint64
	for _, packet := range packets {
		bytes += uint64(len(packet))
	}
	session.bytesReceived.Add(bytes)
	session.packetsReceived.Add(uint64(len(packets)))
}

func (session *session) Close() error {
	closeErr := session.conn.Close()
	session.recvMu.Lock()
	recvErr := session.recvErr
	session.recvErr = nil
	releaseUDPPacketBatch(session.recvPending)
	session.recvPending = udpPacketBatch{}
	session.recvMu.Unlock()
	return errors.Join(closeErr, recvErr)
}

func (session *session) Stats() transport.TransportStats {
	return transport.TransportStats{
		BytesSent:       session.bytesSent.Load(),
		BytesReceived:   session.bytesReceived.Load(),
		PacketsSent:     session.packetsSent.Load(),
		PacketsReceived: session.packetsReceived.Load(),
		Extra: map[string]uint64{
			"udp_send_batch_calls":         session.sendBatchCalls.Load(),
			"udp_send_batch_packets":       session.sendBatchPackets.Load(),
			"udp_send_batch_bytes":         session.sendBatchBytes.Load(),
			"udp_send_batch_mmsg_syscalls": session.sendBatchMMSGSyscalls.Load(),
			"udp_send_batch_loop_syscalls": session.sendBatchLoopSyscalls.Load(),
			"udp_send_batch_fallbacks":     session.sendBatchFallbacks.Load(),
			"udp_recv_batch_calls":         session.recvBatchCalls.Load(),
			"udp_recv_batch_packets":       session.recvBatchPackets.Load(),
			"udp_recv_batch_bytes":         session.recvBatchBytes.Load(),
			"udp_recv_batch_mmsg_syscalls": session.recvBatchMMSGSyscalls.Load(),
			"udp_recv_batch_loop_syscalls": session.recvBatchLoopSyscalls.Load(),
			"udp_recv_batch_fallbacks":     session.recvBatchFallbacks.Load(),
			"udp_recv_batch_gro_packets":   session.recvBatchGROPackets.Load(),
			"udp_recv_batch_gro_segments":  session.recvBatchGROSegments.Load(),
			"udp_recv_batch_gro_bytes":     session.recvBatchGROBytes.Load(),
			"udp_recv_batch_gro_errors":    session.recvBatchGROErrors.Load(),
		},
		NativeBatching: true,
		Datagram:       true,
		MaxPacketSize:  userspaceUDPDatagramMaxPacketSize(),
	}
}

func (session *session) recordBatchReceive(packets uint64, result udpBatchReceiveResult) {
	session.recvBatchCalls.Add(1)
	session.recvBatchPackets.Add(packets)
	session.recvBatchBytes.Add(result.bytesReceived)
	session.recvBatchMMSGSyscalls.Add(result.mmsgSyscalls)
	session.recvBatchLoopSyscalls.Add(result.loopSyscalls)
	session.recvBatchFallbacks.Add(result.fallbacks)
	session.recvBatchGROPackets.Add(result.groPackets)
	session.recvBatchGROSegments.Add(result.groSegments)
	session.recvBatchGROBytes.Add(result.groBytes)
	session.recvBatchGROErrors.Add(result.groCmsgErrors + result.groCmsgTruncations)
}

func (session *session) recordBatchSend(packets uint64, result udpBatchSendResult) {
	session.sendBatchCalls.Add(1)
	session.sendBatchPackets.Add(packets)
	session.sendBatchBytes.Add(result.bytesSent)
	session.sendBatchMMSGSyscalls.Add(result.mmsgSyscalls)
	session.sendBatchLoopSyscalls.Add(result.loopSyscalls)
	session.sendBatchFallbacks.Add(result.fallbacks)
}

func udpReadErrorTimeout(err error) bool {
	if err == nil {
		return false
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "i/o timeout") || strings.Contains(text, "resource temporarily unavailable")
}

func udpReadErrorClosed(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "use of closed network connection") || strings.Contains(text, "closed network connection")
}

type serverSession struct {
	conn                  *net.UDPConn
	remote                *net.UDPAddr
	in                    chan udpPacketBatch
	listener              *listener
	key                   string
	closeOnce             sync.Once
	mu                    sync.Mutex
	closed                bool
	recvPending           udpPacketBatch
	bytesSent             atomic.Uint64
	bytesReceived         atomic.Uint64
	packetsSent           atomic.Uint64
	packetsReceived       atomic.Uint64
	sendBatchCalls        atomic.Uint64
	sendBatchPackets      atomic.Uint64
	sendBatchBytes        atomic.Uint64
	sendBatchMMSGSyscalls atomic.Uint64
	sendBatchLoopSyscalls atomic.Uint64
	sendBatchFallbacks    atomic.Uint64
	recvBatchCalls        atomic.Uint64
	recvBatchPackets      atomic.Uint64
	recvBatchBytes        atomic.Uint64
}

type udpPacketBatch struct {
	packets       [][]byte
	release       func()
	retainedBytes int
}

func (session *serverSession) SendPacket(pkt []byte) error {
	n, err := session.conn.WriteToUDP(pkt, session.remote)
	if err != nil {
		return err
	}
	session.bytesSent.Add(uint64(n))
	session.packetsSent.Add(1)
	return nil
}

func (session *serverSession) SendPackets(pkts [][]byte) error {
	if len(pkts) == 0 {
		return nil
	}
	if len(pkts) == 1 {
		return session.SendPacket(pkts[0])
	}
	result, err := sendUDPBatchTo(session.conn, session.remote, pkts)
	if err != nil {
		return err
	}
	session.bytesSent.Add(result.bytesSent)
	session.packetsSent.Add(uint64(len(pkts)))
	session.recordBatchSend(uint64(len(pkts)), result)
	return nil
}

func (session *serverSession) RecvPacket() ([]byte, error) {
	packets, err := session.RecvPackets(1)
	if err != nil {
		return nil, err
	}
	if len(packets) == 0 {
		return session.RecvPacket()
	}
	return packets[0], nil
}

func (session *serverSession) RecvPackets(max int) ([][]byte, error) {
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

func (session *serverSession) RecvPacketsWithRelease(max int) ([][]byte, func(), error) {
	if max <= 0 {
		max = 1
	}
	var packets [][]byte
	var releases []func()
	appendBatch := func(batch udpPacketBatch, limit int) (udpPacketBatch, bool) {
		batch = trimUDPPacketBatch(batch)
		if len(batch.packets) == 0 {
			if batch.release != nil {
				batch.release()
			}
			return udpPacketBatch{}, false
		}
		if limit > len(batch.packets) {
			limit = len(batch.packets)
		}
		usedBatchDirect := false
		if packets == nil && limit == len(batch.packets) {
			packets = batch.packets
			if batch.release != nil {
				releases = append(releases, batch.release)
			}
			usedBatchDirect = true
		} else if batch.release != nil && limit < len(batch.packets) {
			if packets == nil {
				packets = make([][]byte, 0, max)
			}
			for _, packet := range batch.packets[:limit] {
				packets = append(packets, append([]byte(nil), packet...))
			}
		} else if packets == nil {
			packets = append([][]byte(nil), batch.packets[:limit]...)
			if batch.release != nil {
				releases = append(releases, batch.release)
			}
		} else {
			packets = append(packets, batch.packets[:limit]...)
			if batch.release != nil {
				releases = append(releases, batch.release)
			}
		}
		if limit == len(batch.packets) {
			return udpPacketBatch{}, false
		}
		if usedBatchDirect && batch.release != nil {
			return udpPacketBatch{}, false
		}
		remaining := udpPacketBatch{packets: batch.packets[limit:], release: batch.release}
		return remaining, true
	}
	if len(session.recvPending.packets) > 0 {
		remaining, hasRemaining := appendBatch(session.recvPending, max)
		session.recvPending = remaining
		if len(packets) > 0 || hasRemaining {
			session.recordReceivedPackets(packets)
			return packets, udpReleaseFunc(releases), nil
		}
	}
	for len(packets) < max {
		var batch udpPacketBatch
		var ok bool
		if len(packets) == 0 {
			batch, ok = <-session.in
		} else {
			select {
			case batch, ok = <-session.in:
			default:
				session.recordReceivedPackets(packets)
				return packets, udpReleaseFunc(releases), nil
			}
		}
		if !ok {
			if len(packets) > 0 {
				session.recordReceivedPackets(packets)
				return packets, udpReleaseFunc(releases), nil
			}
			return nil, nil, net.ErrClosed
		}
		if len(batch.packets) == 0 {
			if batch.release != nil {
				batch.release()
			}
			continue
		}
		remaining, hasRemaining := appendBatch(batch, max-len(packets))
		if hasRemaining {
			session.recvPending = remaining
			break
		}
	}
	session.recordReceivedPackets(packets)
	return packets, udpReleaseFunc(releases), nil
}

func (session *serverSession) recordReceivedPackets(packets [][]byte) {
	var bytes uint64
	for _, pkt := range packets {
		bytes += uint64(len(pkt))
	}
	session.bytesReceived.Add(bytes)
	session.packetsReceived.Add(uint64(len(packets)))
	session.recvBatchCalls.Add(1)
	session.recvBatchPackets.Add(uint64(len(packets)))
	session.recvBatchBytes.Add(bytes)
}

func (session *serverSession) Close() error {
	session.closeOnce.Do(func() {
		if session.listener != nil {
			session.listener.mu.Lock()
			if session.listener.sessions[session.key] == session {
				delete(session.listener.sessions, session.key)
				session.closeInput()
			}
			session.listener.mu.Unlock()
		}
	})
	return nil
}

func (session *serverSession) enqueueBatch(batch udpPacketBatch) bool {
	if len(batch.packets) == 0 {
		if batch.release != nil {
			batch.release()
		}
		return true
	}
	batch = compactUDPPacketBatchForQueue(batch, len(session.in), cap(session.in))
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		if batch.release != nil {
			batch.release()
		}
		return true
	}
	if batch.release == nil {
		copied := make([][]byte, len(batch.packets))
		copy(copied, batch.packets)
		batch.packets = copied
	}
	select {
	case session.in <- batch:
		return true
	default:
		if batch.release != nil {
			batch.release()
		}
		return true
	}
}

func compactUDPPacketBatchForQueue(batch udpPacketBatch, queueLen int, queueCap int) udpPacketBatch {
	if batch.release == nil || len(batch.packets) == 0 {
		return batch
	}
	payloadBytes := udpPayloadsBytes(batch.packets)
	if payloadBytes <= 0 {
		batch.release()
		return udpPacketBatch{packets: batch.packets}
	}
	retainedBytes := batch.retainedBytes
	if retainedBytes <= 0 {
		retainedBytes = udpPayloadsRetainedBytes(batch.packets)
	}
	if !shouldCompactUDPPacketBatch(payloadBytes, retainedBytes, queueLen, queueCap) {
		return batch
	}
	arena := make([]byte, payloadBytes)
	packets := make([][]byte, len(batch.packets))
	offset := 0
	for i, packet := range batch.packets {
		if len(packet) == 0 {
			continue
		}
		copy(arena[offset:], packet)
		packets[i] = arena[offset : offset+len(packet)]
		offset += len(packet)
	}
	batch.release()
	return udpPacketBatch{packets: packets, retainedBytes: payloadBytes}
}

func shouldCompactUDPPacketBatch(payloadBytes int, retainedBytes int, queueLen int, queueCap int) bool {
	if payloadBytes <= 0 || retainedBytes <= payloadBytes {
		return false
	}
	waste := retainedBytes - payloadBytes
	if waste >= userspaceUDPCompactMinWaste && retainedBytes > payloadBytes*userspaceUDPCompactWasteFactor {
		return true
	}
	return queueCap > 0 && queueLen*2 >= queueCap && waste > 0
}

func udpPayloadsBytes(payloads [][]byte) int {
	total := 0
	for _, payload := range payloads {
		total += len(payload)
	}
	return total
}

func udpPayloadsRetainedBytes(payloads [][]byte) int {
	for _, payload := range payloads {
		if cap(payload) > 0 {
			return cap(payload)
		}
	}
	return 0
}

func (session *serverSession) enqueue(pkt []byte) {
	session.enqueueBatch(udpPacketBatch{packets: [][]byte{pkt}})
}

func (session *serverSession) closeInput() {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return
	}
	session.closed = true
	close(session.in)
	releaseUDPPacketBatch(session.recvPending)
	session.recvPending = udpPacketBatch{}
	for batch := range session.in {
		releaseUDPPacketBatch(batch)
	}
}

func (session *serverSession) recordBatchSend(packets uint64, result udpBatchSendResult) {
	session.sendBatchCalls.Add(1)
	session.sendBatchPackets.Add(packets)
	session.sendBatchBytes.Add(result.bytesSent)
	session.sendBatchMMSGSyscalls.Add(result.mmsgSyscalls)
	session.sendBatchLoopSyscalls.Add(result.loopSyscalls)
	session.sendBatchFallbacks.Add(result.fallbacks)
}

func trimUDPPacketBatch(batch udpPacketBatch) udpPacketBatch {
	for len(batch.packets) > 0 && batch.packets[0] == nil {
		batch.packets = batch.packets[1:]
	}
	for len(batch.packets) > 0 && batch.packets[len(batch.packets)-1] == nil {
		batch.packets = batch.packets[:len(batch.packets)-1]
	}
	return batch
}

func udpReleaseFunc(releases []func()) func() {
	if len(releases) == 0 {
		return nil
	}
	return func() {
		for _, release := range releases {
			if release != nil {
				release()
			}
		}
	}
}

func releaseUDPPacketBatch(batch udpPacketBatch) {
	if batch.release != nil {
		batch.release()
	}
}

type kernelListener struct {
	provider                 dataplane.KernelUDPProvider
	endpoint                 transport.Endpoint
	subscription             dataplane.KernelUDPSubscription
	acceptCh                 chan transport.Session
	done                     chan struct{}
	closeOnce                sync.Once
	closeErr                 error
	mu                       sync.Mutex
	sessions                 map[uint64]*kernelSession
	placement                dataplane.CryptoPlacement
	requireSecureClientHello bool
}

func (listener *kernelListener) Accept(ctx context.Context) (transport.Session, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-listener.done:
		return nil, net.ErrClosed
	case session := <-listener.acceptCh:
		if session == nil {
			return nil, net.ErrClosed
		}
		return session, nil
	}
}

func (listener *kernelListener) Close() error {
	listener.closeOnce.Do(func() {
		close(listener.done)
		if listener.subscription != nil {
			listener.closeErr = listener.subscription.Close()
		}
		listener.mu.Lock()
		for flowID, session := range listener.sessions {
			session.closeInput()
			delete(listener.sessions, flowID)
		}
		listener.mu.Unlock()
	})
	return listener.closeErr
}

func udpCleanupError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func (listener *kernelListener) readSubscription(ctx context.Context) {
	if listener.subscription == nil {
		<-ctx.Done()
		transport.ObserveAsyncError("close kernel UDP listener without subscription", listener.Close())
		return
	}
	if batchSubscription, ok := listener.subscription.(dataplane.KernelUDPBatchSubscription); ok {
		listener.readBatchSubscription(ctx, batchSubscription)
		return
	}
	for {
		select {
		case <-ctx.Done():
			transport.ObserveAsyncError("close kernel UDP listener after context cancellation", listener.Close())
			return
		case <-listener.done:
			return
		case frame, ok := <-listener.subscription.Events():
			if !ok {
				transport.ObserveAsyncError("close kernel UDP listener after subscription closure", listener.Close())
				return
			}
			if frame.Direction != dataplane.KernelTransportInbound {
				releaseKernelUDPFrame(frame)
				continue
			}
			listener.dispatch(frame)
		}
	}
}

func (listener *kernelListener) readBatchSubscription(ctx context.Context, subscription dataplane.KernelUDPBatchSubscription) {
	for {
		select {
		case <-ctx.Done():
			transport.ObserveAsyncError("close kernel UDP batch listener after context cancellation", listener.Close())
			return
		case <-listener.done:
			return
		case frames, ok := <-subscription.BatchEvents():
			if !ok {
				transport.ObserveAsyncError("close kernel UDP batch listener after subscription closure", listener.Close())
				return
			}
			listener.dispatchBatch(frames)
		}
	}
}

func (listener *kernelListener) dispatch(frame dataplane.KernelUDPFrame) {
	listener.mu.Lock()
	session := listener.sessions[frame.FlowID]
	if session != nil && session.isClosed() {
		delete(listener.sessions, frame.FlowID)
		session = nil
	}
	if session == nil && frame.Endpoint != "" && frame.Endpoint != listener.endpoint.Name {
		listener.mu.Unlock()
		releaseKernelUDPFrame(frame)
		return
	}
	if session == nil && listener.requireSecureClientHello && frame.InnerIPv4 {
		listener.mu.Unlock()
		releaseKernelUDPFrame(frame)
		return
	}
	if session == nil && listener.requireSecureClientHello && !kernelUDPFrameStartsSecureClientHello(frame.Payload) {
		listener.mu.Unlock()
		releaseKernelUDPFrame(frame)
		return
	}
	if session == nil {
		session = newKernelSession(listener.provider, nil, frame.FlowID, frame.Peer, listener.endpoint.Name, listener.placement, "", "")
		session.listener = listener
		listener.sessions[frame.FlowID] = session
		select {
		case listener.acceptCh <- session:
		default:
			delete(listener.sessions, frame.FlowID)
			session.closeInput()
			listener.mu.Unlock()
			return
		}
	}
	listener.mu.Unlock()
	session.handleFrame(frame)
}

func (listener *kernelListener) dispatchBatch(frames []dataplane.KernelUDPFrame) {
	if len(frames) == 0 {
		return
	}
	var singleSession *kernelSession
	var singleFrames []dataplane.KernelUDPFrame
	var accepted map[*kernelSession][]dataplane.KernelUDPFrame
	listener.mu.Lock()
	for _, frame := range frames {
		if frame.Direction != dataplane.KernelTransportInbound {
			releaseKernelUDPFrame(frame)
			continue
		}
		session := listener.sessions[frame.FlowID]
		if session != nil && session.isClosed() {
			delete(listener.sessions, frame.FlowID)
			session = nil
		}
		if session == nil && frame.Endpoint != "" && frame.Endpoint != listener.endpoint.Name {
			releaseKernelUDPFrame(frame)
			continue
		}
		if session == nil && listener.requireSecureClientHello && frame.InnerIPv4 {
			releaseKernelUDPFrame(frame)
			continue
		}
		if session == nil && listener.requireSecureClientHello && !kernelUDPFrameStartsSecureClientHello(frame.Payload) {
			releaseKernelUDPFrame(frame)
			continue
		}
		if session == nil {
			session = newKernelSession(listener.provider, nil, frame.FlowID, frame.Peer, listener.endpoint.Name, listener.placement, "", "")
			session.listener = listener
			listener.sessions[frame.FlowID] = session
			select {
			case listener.acceptCh <- session:
			default:
				delete(listener.sessions, frame.FlowID)
				session.closeInput()
				releaseKernelUDPFrame(frame)
				continue
			}
		}
		if accepted != nil {
			accepted[session] = append(accepted[session], frame)
			continue
		}
		if singleSession == nil {
			singleSession = session
			singleFrames = append(singleFrames, frame)
			continue
		}
		if singleSession == session {
			singleFrames = append(singleFrames, frame)
			continue
		}
		accepted = map[*kernelSession][]dataplane.KernelUDPFrame{
			singleSession: singleFrames,
			session:       {frame},
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

func kernelUDPFrameStartsSecureClientHello(payload []byte) bool {
	return len(payload) >= 6 &&
		payload[0] == trustIXSecureHandshakeMagic[0] &&
		payload[1] == trustIXSecureHandshakeMagic[1] &&
		payload[2] == trustIXSecureHandshakeMagic[2] &&
		payload[3] == trustIXSecureHandshakeMagic[3] &&
		payload[4] == 1 &&
		payload[5] == 1
}

type kernelSession struct {
	provider                  dataplane.KernelUDPProvider
	subscription              dataplane.KernelUDPSubscription
	listener                  *kernelListener
	flowID                    uint64
	peer                      core.IXID
	peerIdentity              transport.PeerIdentity
	endpoint                  core.EndpointID
	localAddress              string
	remoteAddress             string
	in                        chan kernelUDPPacketBatch
	inputMu                   sync.RWMutex
	recvPending               kernelUDPPacketBatch
	closeOnce                 sync.Once
	closeErr                  error
	backgroundErrors          transport.AsyncErrorTracker
	closeInputOnce            sync.Once
	closed                    chan struct{}
	sendSeq                   atomic.Uint64
	sendMu                    sync.Mutex
	sendFrames                []dataplane.KernelUDPFrame
	recvReadMu                sync.Mutex
	recvMu                    sync.Mutex
	reassembly                map[uint64]*kernelUDPFragmentAssembly
	bytesSent                 atomic.Uint64
	bytesReceived             atomic.Uint64
	packetsSent               atomic.Uint64
	packetsReceived           atomic.Uint64
	fragmentedPacketsSent     atomic.Uint64
	fragmentsSent             atomic.Uint64
	fragmentsReceived         atomic.Uint64
	fragmentedPacketsReceived atomic.Uint64
	fragmentsReassembled      atomic.Uint64
	fragmentDuplicates        atomic.Uint64
	fragmentExpiredAssemblies atomic.Uint64
	fragmentExpiredFragments  atomic.Uint64
	fragmentMismatches        atomic.Uint64
	fragmentRejects           atomic.Uint64
	epoch                     uint64
	cryptoSuite               string
	cryptoPlacement           dataplane.CryptoPlacement
	cryptoOffloaded           bool
	keepFlowOnClose           bool
	reassemblyMaxAssemblies   int
	configuredFragmentPayload int
	fragmentPayloadCached     int
	fragmentPayloadCacheKey   kernelUDPFragmentPayloadCacheKey
	sealBeforeMaxCached       int
	sealBeforeMaxCacheKey     kernelUDPFragmentPayloadCacheKey
}

type kernelUDPFragmentPayloadCacheKey struct {
	placement  dataplane.CryptoPlacement
	offloaded  bool
	configured int
	explicit   bool
}

type kernelUDPFragmentAssembly struct {
	createdAt time.Time
	fragments [][]byte
	releases  []func()
	received  int
	totalLen  int
}

type kernelUDPPacketBatch struct {
	packets  [][]byte
	releases []func()
	owner    *kernelUDPPacketBatch
}

type kernelUDPHandledPacket struct {
	payload []byte
	release func()
}

func takeKernelUDPPacketBatch(size int) kernelUDPPacketBatch {
	owner := kernelUDPPacketBatchPool.Get().(*kernelUDPPacketBatch)
	if cap(owner.packets) < size {
		owner.packets = make([][]byte, 0, size)
	} else {
		owner.packets = owner.packets[:0]
	}
	owner.releases = nil
	owner.owner = owner
	return kernelUDPPacketBatch{
		packets: owner.packets,
		owner:   owner,
	}
}

func syncKernelUDPPacketBatchOwner(batch *kernelUDPPacketBatch) {
	if batch == nil || batch.owner == nil {
		return
	}
	batch.owner.packets = batch.packets
	batch.owner.releases = batch.releases
	batch.owner.owner = batch.owner
}

func putKernelUDPPacketBatch(owner *kernelUDPPacketBatch) {
	if owner == nil {
		return
	}
	clear(owner.packets)
	clear(owner.releases)
	if cap(owner.packets) > 4096 || cap(owner.releases) > 4096 {
		*owner = kernelUDPPacketBatch{}
		return
	}
	owner.packets = owner.packets[:0]
	owner.releases = nil
	owner.owner = nil
	kernelUDPPacketBatchPool.Put(owner)
}

func releaseKernelUDPPacketBatchOwner(batch kernelUDPPacketBatch) {
	if batch.owner != nil {
		putKernelUDPPacketBatch(batch.owner)
	}
}

func kernelUDPPacketBatchReleases(batch *kernelUDPPacketBatch, prefix int, size int) []func() {
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

func newKernelSession(provider dataplane.KernelUDPProvider, subscription dataplane.KernelUDPSubscription, flowID uint64, peer core.IXID, endpoint core.EndpointID, placement dataplane.CryptoPlacement, wireAddresses ...string) *kernelSession {
	placement = normalizeCryptoPlacement(placement)
	var localAddress string
	var remoteAddress string
	if len(wireAddresses) > 0 {
		localAddress = wireAddresses[0]
	}
	if len(wireAddresses) > 1 {
		remoteAddress = wireAddresses[1]
	}
	return &kernelSession{
		provider:                  provider,
		subscription:              subscription,
		flowID:                    flowID,
		peer:                      peer,
		endpoint:                  endpoint,
		localAddress:              localAddress,
		remoteAddress:             remoteAddress,
		in:                        make(chan kernelUDPPacketBatch, kernelSessionBuffer()),
		closed:                    make(chan struct{}),
		cryptoPlacement:           placement,
		reassemblyMaxAssemblies:   kernelUDPReassemblyMaxAssemblies(),
		configuredFragmentPayload: kernelUDPFragmentPayloadSizeForPlacement(placement, false),
	}
}

func (session *kernelSession) readSubscription(ctx context.Context) {
	if session.subscription == nil {
		return
	}
	if batchSubscription, ok := session.subscription.(dataplane.KernelUDPBatchSubscription); ok {
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
			if frame.Direction != dataplane.KernelTransportInbound || frame.FlowID != session.flowID {
				releaseKernelUDPFrame(frame)
				continue
			}
			session.handleFrame(frame)
		}
	}
}

func (session *kernelSession) readBatchSubscription(ctx context.Context, subscription dataplane.KernelUDPBatchSubscription) {
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
			var filtered []dataplane.KernelUDPFrame
			for i, frame := range frames {
				if frame.Direction == dataplane.KernelTransportInbound && frame.FlowID == session.flowID {
					if filtered != nil {
						filtered = append(filtered, frame)
					}
					continue
				}
				if filtered == nil {
					filtered = make([]dataplane.KernelUDPFrame, 0, len(frames))
					for _, previous := range frames[:i] {
						if previous.Direction == dataplane.KernelTransportInbound && previous.FlowID == session.flowID {
							filtered = append(filtered, previous)
						} else {
							releaseKernelUDPFrame(previous)
						}
					}
				}
				releaseKernelUDPFrame(frame)
			}
			if filtered == nil {
				session.handleFrames(frames)
			} else {
				session.handleFrames(filtered)
			}
		}
	}
}

func (session *kernelSession) SendPacket(pkt []byte) error {
	return session.SendPackets([][]byte{pkt})
}

func (session *kernelSession) SendPackets(pkts [][]byte) error {
	if len(pkts) == 0 {
		return nil
	}
	session.sendMu.Lock()
	defer session.sendMu.Unlock()
	payloadSize := session.fragmentPayloadSize()
	placement := dataplane.CryptoPlacementUserspace
	if session.cryptoOffloaded {
		placement = session.cryptoPlacement
	}
	sealBeforeFragment := session.kernelCryptoSealBeforeFragment()
	sealBeforeFragmentMax := session.kernelUDPSealBeforeFragmentMax(sealBeforeFragment)
	totalFragments := 0
	allUnfragmented := true
	for _, pkt := range pkts {
		count := session.kernelUDPWireFragmentCount(len(pkt), payloadSize, sealBeforeFragment, sealBeforeFragmentMax)
		if count > kernelUDPMaxFragments {
			return fmt.Errorf("kernel_udp packet size %d requires %d fragments, max %d", len(pkt), count, kernelUDPMaxFragments)
		}
		if count > 1 {
			allUnfragmented = false
		}
		totalFragments += count
	}
	if cap(session.sendFrames) < totalFragments {
		session.sendFrames = make([]dataplane.KernelUDPFrame, 0, totalFragments)
	} else {
		session.sendFrames = session.sendFrames[:0]
	}
	frames := session.sendFrames
	defer func() {
		clearKernelUDPFrames(frames)
		session.sendFrames = frames[:0]
	}()
	packetBytes := uint64(0)
	packetCount := uint64(0)
	fragmentedPackets := uint64(0)
	fragments := uint64(0)
	if allUnfragmented {
		baseSeq := session.sendSeq.Add(uint64(len(pkts))) - uint64(len(pkts)) + 1
		for i, pkt := range pkts {
			innerIPv4 := kernelUDPInnerIPv4Eligible(pkt)
			frames = append(frames, dataplane.KernelUDPFrame{
				FlowID:          session.flowID,
				Direction:       dataplane.KernelTransportOutbound,
				Peer:            session.peer,
				Endpoint:        session.endpoint,
				Epoch:           session.epoch,
				Sequence:        baseSeq + uint64(i),
				Payload:         pkt,
				InnerIPv4:       innerIPv4,
				CryptoSuite:     session.cryptoSuite,
				CryptoPlacement: placement,
			})
			packetBytes += uint64(len(pkt))
		}
		packetCount = uint64(len(pkts))
	} else {
		for _, pkt := range pkts {
			count := session.kernelUDPWireFragmentCount(len(pkt), payloadSize, sealBeforeFragment, sealBeforeFragmentMax)
			if session.kernelUDPShouldSealBeforeFragment(len(pkt), payloadSize, sealBeforeFragment, sealBeforeFragmentMax) {
				baseSeq := session.sendSeq.Add(uint64(count)) - uint64(count) + 1
				innerIPv4 := kernelUDPInnerIPv4Eligible(pkt)
				frames = append(frames, dataplane.KernelUDPFrame{
					FlowID:              session.flowID,
					Direction:           dataplane.KernelTransportOutbound,
					Peer:                session.peer,
					Endpoint:            session.endpoint,
					Epoch:               session.epoch,
					Sequence:            baseSeq,
					FragmentPayloadSize: payloadSize,
					Payload:             pkt,
					InnerIPv4:           innerIPv4,
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
				frames = append(frames, dataplane.KernelUDPFrame{
					FlowID:          session.flowID,
					Direction:       dataplane.KernelTransportOutbound,
					Peer:            session.peer,
					Endpoint:        session.endpoint,
					Epoch:           session.epoch,
					Sequence:        baseSeq + uint64(i),
					FragmentIndex:   fragmentIndex,
					FragmentCount:   fragmentCount,
					Payload:         pkt[start:end],
					InnerIPv4:       false,
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
	}
	if batch, ok := session.provider.(dataplane.KernelUDPBatchProvider); ok {
		if err := batch.SubmitKernelUDPFrames(context.Background(), frames); err != nil {
			return err
		}
	} else {
		var sentFragments uint64
		for _, frame := range frames {
			if err := session.provider.SubmitKernelUDPFrame(context.Background(), frame); err != nil {
				if sentFragments > 0 {
					session.fragmentsSent.Add(sentFragments)
				}
				return err
			}
			sentFragments++
		}
	}
	session.bytesSent.Add(packetBytes)
	session.packetsSent.Add(packetCount)
	if fragmentedPackets > 0 {
		session.fragmentedPacketsSent.Add(fragmentedPackets)
		session.fragmentsSent.Add(fragments)
	}
	return nil
}

func kernelUDPInnerIPv4Eligible(packet []byte) bool {
	if len(packet) < 20 || len(packet) > kerneludp.MaxPayload {
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

func (session *kernelSession) kernelCryptoSealBeforeFragment() bool {
	if session == nil || !session.cryptoOffloaded || session.cryptoPlacement != dataplane.CryptoPlacementKernel {
		return false
	}
	return kernelUDPSealBeforeFragmentEnabled()
}

func (session *kernelSession) kernelUDPSealBeforeFragmentMax(enabled bool) int {
	if session == nil || !enabled {
		return 0
	}
	configured := session.configuredFragmentPayload
	if configured == 0 {
		configured = kernelUDPFragmentPayloadSizeForPlacement(session.cryptoPlacement, session.cryptoOffloaded)
	}
	key := kernelUDPFragmentPayloadCacheKey{
		placement:  session.cryptoPlacement,
		offloaded:  session.cryptoOffloaded,
		configured: configured,
		explicit:   kernelUDPConfiguredFragmentPayloadSizeExplicit(kernelUDPFragmentPayloadMaxForPlacement(session.cryptoPlacement, session.cryptoOffloaded)),
	}
	if session.sealBeforeMaxCached > 0 && session.sealBeforeMaxCacheKey == key {
		return session.sealBeforeMaxCached
	}
	maxPlain := kernelUDPSealBeforeFragmentMax
	if session.cryptoOffloaded && session.cryptoPlacement == dataplane.CryptoPlacementKernel {
		if sizer, ok := session.provider.(dataplane.KernelUDPSealBeforeFragmentSizer); ok {
			if maxSize, err := sizer.KernelUDPSealBeforeFragmentMax(context.Background(), session.cryptoPlacement); err == nil && maxSize > 0 && maxSize < maxPlain {
				maxPlain = maxSize
			}
		}
	}
	if maxPlain < 1 {
		maxPlain = 1
	}
	session.sealBeforeMaxCacheKey = key
	session.sealBeforeMaxCached = maxPlain
	return maxPlain
}

func (session *kernelSession) kernelUDPShouldSealBeforeFragment(packetLen int, payloadSize int, enabled bool, maxPlain int) bool {
	if !enabled || packetLen <= payloadSize {
		return false
	}
	if maxPlain <= 0 {
		maxPlain = kernelUDPSealBeforeFragmentMax
	}
	return packetLen > 0 && packetLen <= maxPlain
}

func (session *kernelSession) kernelUDPWireFragmentCount(packetLen int, payloadSize int, sealBeforeFragment bool, sealBeforeFragmentMax int) int {
	if session.kernelUDPShouldSealBeforeFragment(packetLen, payloadSize, sealBeforeFragment, sealBeforeFragmentMax) {
		return kernelUDPFragmentCountForSize(packetLen+24+16, payloadSize)
	}
	return kernelUDPFragmentCountForSize(packetLen, payloadSize)
}

func (session *kernelSession) RecvPacket() ([]byte, error) {
	packets, release, err := session.RecvPacketsWithRelease(1)
	if err != nil {
		return nil, err
	}
	if len(packets) == 0 {
		return session.RecvPacket()
	}
	if release == nil {
		return packets[0], nil
	}
	packet := append([]byte(nil), packets[0]...)
	release()
	return packet, nil
}

func (session *kernelSession) RecvPackets(max int) ([][]byte, error) {
	packets, release, err := session.RecvPacketsWithRelease(max)
	if err != nil || release == nil {
		return packets, err
	}
	copied := make([][]byte, len(packets))
	for i, packet := range packets {
		copied[i] = append([]byte(nil), packet...)
	}
	release()
	packets = copied
	return packets, err
}

func (session *kernelSession) RecvPacketsWithRelease(max int) ([][]byte, func(), error) {
	if max <= 0 {
		max = 1
	}
	session.recvReadMu.Lock()
	defer session.recvReadMu.Unlock()
	var packets [][]byte
	var releases []func()
	var releaseBatch kernelUDPPacketBatch
	var borrowedBatches []*kernelUDPPacketBatch
	appendBatch := func(batch kernelUDPPacketBatch, limit int) (kernelUDPPacketBatch, bool) {
		batch = trimKernelUDPPacketBatch(batch)
		if len(batch.packets) == 0 {
			releaseKernelUDPPacketBatchOwner(batch)
			return kernelUDPPacketBatch{}, false
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
				releaseKernelUDPPacketBatchOwner(batch)
			}
			return kernelUDPPacketBatch{}, false
		}
		return kernelUDPPacketBatch{
			packets:  batch.packets[limit:],
			releases: kernelUDPReleaseSuffix(batch.releases, limit),
			owner:    batch.owner,
		}, true
	}
	if len(session.recvPending.packets) > 0 {
		remaining, hasRemaining := appendBatch(session.recvPending, max)
		session.recvPending = remaining
		if len(packets) > 0 || hasRemaining {
			session.recordReceivedPackets(packets)
			return packets, kernelUDPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
		}
	}
	for len(packets) < max {
		select {
		case <-session.closed:
			if len(packets) > 0 {
				session.recordReceivedPackets(packets)
				return packets, kernelUDPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
			}
			return nil, nil, net.ErrClosed
		case batch, ok := <-session.in:
			if !ok {
				if len(packets) > 0 {
					session.recordReceivedPackets(packets)
					return packets, kernelUDPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
				}
				return nil, nil, net.ErrClosed
			}
			remaining, hasRemaining := appendBatch(batch, max-len(packets))
			if hasRemaining {
				session.recvPending = remaining
				session.recordReceivedPackets(packets)
				return packets, kernelUDPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
			}
			if len(packets) == 0 {
				continue
			}
		default:
			if len(packets) > 0 {
				session.recordReceivedPackets(packets)
				return packets, kernelUDPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
			}
			select {
			case <-session.closed:
				return nil, nil, net.ErrClosed
			case batch, ok := <-session.in:
				if !ok {
					return nil, nil, net.ErrClosed
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
	return packets, kernelUDPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
}

func trimKernelUDPPacketBatch(batch kernelUDPPacketBatch) kernelUDPPacketBatch {
	for len(batch.packets) > 0 && batch.packets[0] == nil {
		batch.packets = batch.packets[1:]
		if len(batch.releases) > 0 {
			batch.releases = batch.releases[1:]
		}
	}
	return batch
}

func kernelUDPReleaseSuffix(releases []func(), offset int) []func() {
	if len(releases) == 0 || offset >= len(releases) {
		return nil
	}
	if offset <= 0 {
		return releases
	}
	return releases[offset:]
}

func kernelUDPReleaseFunc(batch kernelUDPPacketBatch, releases []func(), owners []*kernelUDPPacketBatch) func() {
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
			putKernelUDPPacketBatch(owner)
		}
	}
}

func clearKernelUDPFrames(frames []dataplane.KernelUDPFrame) {
	for i := range frames {
		frames[i] = dataplane.KernelUDPFrame{}
	}
}

func (session *kernelSession) recordReceivedPackets(packets [][]byte) {
	var bytes uint64
	for _, pkt := range packets {
		bytes += uint64(len(pkt))
	}
	session.bytesReceived.Add(bytes)
	session.packetsReceived.Add(uint64(len(packets)))
}

func (session *kernelSession) Close() error {
	session.closeOnce.Do(func() {
		var errs []error
		if deleter, ok := session.provider.(dataplane.KernelUDPFlowDeleter); ok && !session.keepFlowOnClose {
			if err := deleter.DeleteKernelUDPFlows(context.Background(), []uint64{session.flowID}); err != nil {
				errs = append(errs, fmt.Errorf("delete kernel UDP flow %d: %w", session.flowID, err))
			}
		}
		if session.listener != nil {
			session.listener.mu.Lock()
			if session.listener.sessions[session.flowID] == session {
				delete(session.listener.sessions, session.flowID)
			}
			session.listener.mu.Unlock()
		}
		session.closeInput()
		if session.subscription != nil {
			if err := session.subscription.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close kernel UDP subscription: %w", err))
			}
		}
		if err := session.backgroundErrors.Err(); err != nil {
			errs = append(errs, err)
		}
		session.closeErr = errors.Join(errs...)
	})
	return session.closeErr
}

func (session *kernelSession) RetainKernelFlowOnClose() {
	session.keepFlowOnClose = true
}

func (session *kernelSession) KernelDatapathSessionInfo() (transport.KernelDatapathSessionInfo, bool) {
	if session == nil || session.flowID == 0 {
		return transport.KernelDatapathSessionInfo{}, false
	}
	stats := session.Stats()
	info := transport.KernelDatapathSessionInfo{
		FlowID:              session.flowID,
		Protocol:            transport.ProtocolUDP,
		Peer:                session.peer,
		Endpoint:            session.endpoint,
		LocalAddress:        session.localAddress,
		RemoteAddress:       session.remoteAddress,
		Epoch:               session.epoch,
		CryptoSuite:         stats.CryptoSuite,
		CryptoPlacement:     stats.CryptoPlacement,
		Encrypted:           stats.Encrypted,
		SendEncrypted:       stats.SendEncrypted,
		ReceiveEncrypted:    stats.ReceiveEncrypted,
		NativeBatching:      stats.NativeBatching,
		Datagram:            stats.Datagram,
		FragmentingDatagram: stats.FragmentingDatagram,
		MaxPacketSize:       stats.MaxPacketSize,
	}
	return info, true
}

func (session *kernelSession) EnableCryptoOffload(spec transport.CryptoOffloadSpec) error {
	if session.cryptoPlacement != dataplane.CryptoPlacementKernel {
		return transport.ErrCryptoOffloadUnavailable
	}
	if installer, ok := session.provider.(dataplane.KernelUDPCryptoInstaller); ok {
		status, err := session.provider.KernelUDPStatus(context.Background())
		if err != nil || !status.KernelCrypto {
			return transport.ErrCryptoOffloadUnavailable
		}
		if spec.WireFormat != transport.CryptoWireFormatTrustIXSecureDataV1 {
			return fmt.Errorf("kernel_udp crypto offload wire format %q is unsupported", spec.WireFormat)
		}
		cryptoSpec := dataplane.KernelUDPCryptoSpec{
			FlowID:       session.flowID,
			Suite:        spec.Suite,
			WireFormat:   spec.WireFormat,
			KeySource:    spec.KeySource,
			Epoch:        spec.Epoch,
			SendKey:      append([]byte(nil), spec.SendKey...),
			SendIV:       append([]byte(nil), spec.SendIV...),
			RecvKey:      append([]byte(nil), spec.RecvKey...),
			RecvIV:       append([]byte(nil), spec.RecvIV...),
			ReplayWindow: spec.ReplayWindow,
			InstalledAt:  time.Now().UTC(),
		}
		defer clearKernelUDPCryptoSpec(&cryptoSpec)
		if err := installer.InstallKernelUDPCrypto(context.Background(), []dataplane.KernelUDPCryptoSpec{cryptoSpec}); err != nil {
			return err
		}
		session.epoch = spec.Epoch
		session.cryptoSuite = spec.Suite
		session.cryptoOffloaded = true
		session.configuredFragmentPayload = kernelUDPFragmentPayloadSizeForPlacement(session.cryptoPlacement, true)
		session.fragmentPayloadCached = 0
		return nil
	}
	return transport.ErrCryptoOffloadUnavailable
}

func (session *kernelSession) SetPeerIdentity(peer core.IXID, domain core.DomainID) {
	if peer == "" {
		return
	}
	session.peer = peer
	session.peerIdentity = transport.PeerIdentity{Peer: peer, Domain: domain}
	if annotator, ok := session.provider.(dataplane.KernelUDPFlowAnnotator); ok {
		session.backgroundErrors.Record(
			fmt.Sprintf("annotate kernel UDP flow %d peer identity", session.flowID),
			annotator.SetKernelUDPFlowPeer(context.Background(), session.flowID, peer, session.endpoint),
		)
	}
}

func (session *kernelSession) SetPeerIdentityDetail(identity transport.PeerIdentity) {
	session.peerIdentity = identity
	if identity.Role == "device" {
		return
	}
	session.SetPeerIdentity(identity.Peer, identity.Domain)
}

func (session *kernelSession) PeerIdentity() (core.IXID, core.DomainID, bool) {
	if session.peerIdentity.Domain != "" {
		return session.peer, session.peerIdentity.Domain, session.peer != ""
	}
	return session.peer, "", session.peer != ""
}

func (session *kernelSession) PeerIdentityDetail() (transport.PeerIdentity, bool) {
	return session.peerIdentity, session.peerIdentity.Peer != "" || session.peerIdentity.Domain != "" || session.peerIdentity.Device != "" || session.peerIdentity.Role != ""
}

func (session *kernelSession) SetPeerEndpoint(peer core.IXID, endpoint core.EndpointID) {
	if peer != "" {
		session.peer = peer
	}
	if endpoint != "" {
		session.endpoint = endpoint
	}
	if annotator, ok := session.provider.(dataplane.KernelUDPFlowAnnotator); ok {
		session.backgroundErrors.Record(
			fmt.Sprintf("annotate kernel UDP flow %d peer endpoint", session.flowID),
			annotator.SetKernelUDPFlowPeer(context.Background(), session.flowID, session.peer, session.endpoint),
		)
	}
}

func clearKernelUDPCryptoSpec(spec *dataplane.KernelUDPCryptoSpec) {
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

func (session *kernelSession) Stats() transport.TransportStats {
	return transport.TransportStats{
		BytesSent:           session.bytesSent.Load(),
		BytesReceived:       session.bytesReceived.Load(),
		PacketsSent:         session.packetsSent.Load(),
		PacketsReceived:     session.packetsReceived.Load(),
		Extra:               session.fragmentStats(),
		CryptoSuite:         session.cryptoSuite,
		CryptoPlacement:     string(session.effectiveCryptoPlacement()),
		NativeBatching:      true,
		Datagram:            true,
		FragmentingDatagram: true,
		MaxPacketSize:       uint64(session.maxPacketSize()),
	}
}

func (session *kernelSession) effectiveCryptoPlacement() dataplane.CryptoPlacement {
	if session.cryptoOffloaded {
		return session.cryptoPlacement
	}
	return dataplane.CryptoPlacementUserspace
}

func (session *kernelSession) enqueue(packet kernelUDPHandledPacket) {
	session.enqueueBatch(kernelUDPPacketBatch{
		packets:  [][]byte{packet.payload},
		releases: kernelUDPReleaseSlice(packet.release),
	})
}

func (session *kernelSession) enqueueBatch(batch kernelUDPPacketBatch) {
	if len(batch.packets) == 0 {
		kernelUDPReleaseBatch(batch)
		return
	}
	select {
	case <-session.closed:
		kernelUDPReleaseBatch(batch)
		return
	default:
	}
	session.inputMu.RLock()
	defer session.inputMu.RUnlock()
	select {
	case <-session.closed:
		kernelUDPReleaseBatch(batch)
		return
	case session.in <- batch:
	}
}

func (session *kernelSession) handleFrame(frame dataplane.KernelUDPFrame) {
	if pkt, ok := session.handleFrameOne(frame); ok {
		session.enqueue(pkt)
	}
}

func (session *kernelSession) handleFrames(frames []dataplane.KernelUDPFrame) {
	if len(frames) == 0 {
		return
	}
	if len(frames) == 1 {
		session.handleFrame(frames[0])
		return
	}
	ready := takeKernelUDPPacketBatch(len(frames))
	for _, frame := range frames {
		if pkt, ok := session.handleFrameOne(frame); ok {
			ready.packets = append(ready.packets, pkt.payload)
			if pkt.release != nil {
				if ready.releases == nil {
					ready.releases = kernelUDPPacketBatchReleases(&ready, len(ready.packets)-1, len(frames))
				}
				ready.releases = append(ready.releases, pkt.release)
			} else if ready.releases != nil {
				ready.releases = append(ready.releases, nil)
			}
		}
	}
	syncKernelUDPPacketBatchOwner(&ready)
	session.enqueueBatch(ready)
}

func (session *kernelSession) handleFrameOne(frame dataplane.KernelUDPFrame) (kernelUDPHandledPacket, bool) {
	if frame.FragmentCount == 0 {
		if frame.FragmentIndex != 0 {
			session.fragmentRejects.Add(1)
			if frame.Release != nil {
				frame.Release()
			}
			return kernelUDPHandledPacket{}, false
		}
		return kernelUDPHandledPacket{payload: frame.Payload, release: frame.Release}, true
	}
	if frame.FragmentCount == 1 {
		if frame.FragmentIndex != 0 {
			session.fragmentRejects.Add(1)
			if frame.Release != nil {
				frame.Release()
			}
			return kernelUDPHandledPacket{}, false
		}
		return kernelUDPHandledPacket{payload: frame.Payload, release: frame.Release}, true
	}
	if frame.FragmentCount > kernelUDPMaxFragments || frame.FragmentIndex >= frame.FragmentCount {
		session.fragmentRejects.Add(1)
		if frame.Release != nil {
			frame.Release()
		}
		return kernelUDPHandledPacket{}, false
	}
	if frame.Sequence <= uint64(frame.FragmentIndex) {
		session.fragmentRejects.Add(1)
		if frame.Release != nil {
			frame.Release()
		}
		return kernelUDPHandledPacket{}, false
	}
	baseSeq := frame.Sequence - uint64(frame.FragmentIndex)
	now := time.Now()
	session.fragmentsReceived.Add(1)

	session.recvMu.Lock()
	session.pruneReassemblyLocked(now)
	if session.reassembly == nil {
		session.reassembly = make(map[uint64]*kernelUDPFragmentAssembly)
	}
	assembly := session.reassembly[baseSeq]
	if assembly == nil {
		session.pruneOldestReassemblyIfFullLocked(session.reassemblyMaxAssemblies)
		assembly = &kernelUDPFragmentAssembly{
			createdAt: now,
			fragments: make([][]byte, int(frame.FragmentCount)),
			releases:  make([]func(), int(frame.FragmentCount)),
		}
		session.reassembly[baseSeq] = assembly
	}
	if len(assembly.fragments) != int(frame.FragmentCount) {
		delete(session.reassembly, baseSeq)
		kernelUDPReleaseFragmentAssembly(assembly)
		session.fragmentMismatches.Add(1)
		session.fragmentRejects.Add(1)
		session.recvMu.Unlock()
		if frame.Release != nil {
			frame.Release()
		}
		return kernelUDPHandledPacket{}, false
	}
	index := int(frame.FragmentIndex)
	if assembly.fragments[index] != nil {
		session.fragmentDuplicates.Add(1)
		session.recvMu.Unlock()
		if frame.Release != nil {
			frame.Release()
		}
		return kernelUDPHandledPacket{}, false
	}
	assembly.fragments[index] = frame.Payload
	assembly.releases[index] = frame.Release
	assembly.received++
	assembly.totalLen += len(frame.Payload)
	if assembly.received != len(assembly.fragments) {
		session.recvMu.Unlock()
		return kernelUDPHandledPacket{}, false
	}
	packet := make([]byte, 0, assembly.totalLen)
	for _, fragment := range assembly.fragments {
		if fragment == nil {
			session.fragmentRejects.Add(1)
			session.recvMu.Unlock()
			kernelUDPReleaseFragmentAssembly(assembly)
			return kernelUDPHandledPacket{}, false
		}
		packet = append(packet, fragment...)
	}
	delete(session.reassembly, baseSeq)
	kernelUDPReleaseFragmentAssembly(assembly)
	session.recvMu.Unlock()
	session.fragmentedPacketsReceived.Add(1)
	session.fragmentsReassembled.Add(uint64(len(assembly.fragments)))
	return kernelUDPHandledPacket{payload: packet}, true
}

func kernelUDPReleaseSlice(release func()) []func() {
	if release == nil {
		return nil
	}
	return []func(){release}
}

func releaseKernelUDPFrame(frame dataplane.KernelUDPFrame) {
	if frame.Release != nil {
		frame.Release()
	}
}

func kernelUDPReleaseBatch(batch kernelUDPPacketBatch) {
	for _, release := range batch.releases {
		if release != nil {
			release()
		}
	}
	releaseKernelUDPPacketBatchOwner(batch)
}

func kernelUDPReleaseFragmentAssembly(assembly *kernelUDPFragmentAssembly) {
	if assembly == nil {
		return
	}
	for i, release := range assembly.releases {
		if release != nil {
			release()
			assembly.releases[i] = nil
		}
	}
}

func (session *kernelSession) pruneReassemblyLocked(now time.Time) {
	var expiredAssemblies uint64
	var expiredFragments uint64
	for baseSeq, assembly := range session.reassembly {
		if now.Sub(assembly.createdAt) > kernelUDPReassemblyTTL {
			expiredAssemblies++
			for _, fragment := range assembly.fragments {
				if fragment != nil {
					expiredFragments++
				}
			}
			kernelUDPReleaseFragmentAssembly(assembly)
			delete(session.reassembly, baseSeq)
		}
	}
	if expiredAssemblies > 0 {
		session.fragmentExpiredAssemblies.Add(expiredAssemblies)
		session.fragmentExpiredFragments.Add(expiredFragments)
	}
}

func (session *kernelSession) pruneOldestReassemblyIfFullLocked(maxAssemblies int) {
	if maxAssemblies <= 0 || len(session.reassembly) < maxAssemblies {
		return
	}
	var oldestSeq uint64
	var oldest *kernelUDPFragmentAssembly
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
	kernelUDPReleaseFragmentAssembly(oldest)
	delete(session.reassembly, oldestSeq)
	session.fragmentExpiredAssemblies.Add(1)
	session.fragmentExpiredFragments.Add(fragments)
}

func (session *kernelSession) closeInput() {
	session.closeInputOnce.Do(func() {
		close(session.closed)
		session.inputMu.Lock()
		for {
			select {
			case batch := <-session.in:
				kernelUDPReleaseBatch(batch)
			default:
				session.inputMu.Unlock()
				goto inputDrained
			}
		}
	inputDrained:
		session.recvReadMu.Lock()
		kernelUDPReleaseBatch(session.recvPending)
		session.recvPending = kernelUDPPacketBatch{}
		session.recvReadMu.Unlock()
		session.recvMu.Lock()
		for _, assembly := range session.reassembly {
			kernelUDPReleaseFragmentAssembly(assembly)
		}
		session.reassembly = nil
		session.recvMu.Unlock()
	})
}

func (session *kernelSession) isClosed() bool {
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

func (session *kernelSession) fragmentStats() map[string]uint64 {
	extra := map[string]uint64{
		kernelUDPStatFragmentedPacketsSent:     session.fragmentedPacketsSent.Load(),
		kernelUDPStatFragmentsSent:             session.fragmentsSent.Load(),
		kernelUDPStatFragmentsReceived:         session.fragmentsReceived.Load(),
		kernelUDPStatFragmentedPacketsReceived: session.fragmentedPacketsReceived.Load(),
		kernelUDPStatFragmentsReassembled:      session.fragmentsReassembled.Load(),
		kernelUDPStatFragmentDuplicates:        session.fragmentDuplicates.Load(),
		kernelUDPStatFragmentExpiredAssemblies: session.fragmentExpiredAssemblies.Load(),
		kernelUDPStatFragmentExpiredFragments:  session.fragmentExpiredFragments.Load(),
		kernelUDPStatFragmentMismatches:        session.fragmentMismatches.Load(),
		kernelUDPStatFragmentRejects:           session.fragmentRejects.Load(),
		kernelUDPStatFragmentPayloadSize:       uint64(session.fragmentPayloadSize()),
	}
	session.recvMu.Lock()
	extra[kernelUDPStatFragmentAssembliesCurrent] = uint64(len(session.reassembly))
	session.recvMu.Unlock()
	return extra
}

func kernelUDPFragmentCount(packetLen int) int {
	return kernelUDPFragmentCountForSize(packetLen, kernelUDPFragmentPayloadSize)
}

func kernelUDPFragmentCountForSize(packetLen int, payloadSize int) int {
	if payloadSize <= 0 {
		payloadSize = kernelUDPFragmentPayloadSize
	}
	if packetLen <= payloadSize {
		return 1
	}
	return (packetLen + payloadSize - 1) / payloadSize
}

func (session *kernelSession) fragmentPayloadSize() int {
	configured := session.configuredFragmentPayload
	if configured == 0 {
		configured = kernelUDPFragmentPayloadSizeForPlacement(session.cryptoPlacement, session.cryptoOffloaded)
	}
	explicit := kernelUDPConfiguredFragmentPayloadSizeExplicit(kernelUDPFragmentPayloadMaxForPlacement(session.cryptoPlacement, session.cryptoOffloaded))
	key := kernelUDPFragmentPayloadCacheKey{
		placement:  session.cryptoPlacement,
		offloaded:  session.cryptoOffloaded,
		configured: configured,
		explicit:   explicit,
	}
	if session.fragmentPayloadCached > 0 && session.fragmentPayloadCacheKey == key {
		return session.fragmentPayloadCached
	}
	payloadSize := session.clampFragmentPayloadSize(configured, explicit)
	session.fragmentPayloadCacheKey = key
	session.fragmentPayloadCached = payloadSize
	return payloadSize
}

func (session *kernelSession) maxPacketSize() int {
	payloadSize := session.fragmentPayloadSize()
	maxPacket := payloadSize * kernelUDPMaxFragments
	if session.kernelCryptoSealBeforeFragment() {
		maxPacket -= 24 + 16
	}
	if maxPacket < 1 {
		return 1
	}
	if configured := kernelUDPConfiguredMaxPacketSize(); configured > 0 {
		if maxPacket > configured {
			maxPacket = configured
		}
	}
	if maxPacket < 1 {
		return 1
	}
	if maxPacket > userspaceUDPSessionMaxPacket {
		return userspaceUDPSessionMaxPacket
	}
	return maxPacket
}

func (session *kernelSession) clampFragmentPayloadSize(payloadSize int, explicit bool) int {
	if sizer, ok := session.provider.(dataplane.KernelUDPPayloadSizer); ok {
		if maxSize, err := sizer.KernelUDPPayloadMax(context.Background(), session.cryptoPlacement, session.cryptoOffloaded); err == nil && maxSize > 0 {
			if payloadSize > maxSize {
				payloadSize = maxSize
			} else if !explicit && session.autoRaiseKernelUDPFragmentPayload() && payloadSize < maxSize {
				payloadSize = min(maxSize, kernelUDPFragmentPayloadMaxForPlacement(session.cryptoPlacement, session.cryptoOffloaded))
			}
		}
	}
	if payloadSize < 1 {
		return 1
	}
	return payloadSize
}

func (session *kernelSession) autoRaiseKernelUDPFragmentPayload() bool {
	return session != nil && session.cryptoOffloaded && session.cryptoPlacement == dataplane.CryptoPlacementKernel
}

func kernelUDPFragmentPayloadSizeForPlacement(placement dataplane.CryptoPlacement, offloaded bool) int {
	if placement == dataplane.CryptoPlacementKernel || offloaded {
		return kernelUDPConfiguredFragmentPayloadSize(kernelUDPKernelFragmentPayloadSize, kernelUDPKernelFragmentPayloadMax)
	}
	return kernelUDPConfiguredFragmentPayloadSize(kernelUDPFragmentPayloadSize, kernelUDPFragmentPayloadMax)
}

func kernelUDPFragmentPayloadMaxForPlacement(placement dataplane.CryptoPlacement, offloaded bool) int {
	if placement == dataplane.CryptoPlacementKernel || offloaded {
		return kernelUDPKernelFragmentPayloadMax
	}
	return kernelUDPFragmentPayloadMax
}

func kernelUDPSealBeforeFragmentEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_SEAL_BEFORE_FRAGMENT"))) {
	case "", "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}

func kernelUDPConfiguredFragmentPayloadSize(defaultSize int, maxSize int) int {
	if parsed, ok := kernelUDPConfiguredFragmentPayloadSizeValue(maxSize); ok {
		return parsed
	}
	return defaultSize
}

func kernelUDPConfiguredFragmentPayloadSizeExplicit(maxSize int) bool {
	_, ok := kernelUDPConfiguredFragmentPayloadSizeValue(maxSize)
	return ok
}

func kernelUDPConfiguredFragmentPayloadSizeValue(maxSize int) (int, bool) {
	const minSize = 576
	value := strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_FRAGMENT_PAYLOAD_SIZE"))
	if value == "" {
		return 0, false
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minSize {
		return 0, false
	}
	if parsed > maxSize {
		parsed = maxSize
	}
	return parsed, true
}

func kernelUDPConfiguredMaxPacketSize() int {
	const minSize = 576
	value := strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_MAX_PACKET_SIZE"))
	if value == "" {
		return 0
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minSize {
		return 0
	}
	if parsed > userspaceUDPSessionMaxPacket {
		return userspaceUDPSessionMaxPacket
	}
	return parsed
}

func randomFlowID() (uint64, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0, err
	}
	id := binary.BigEndian.Uint64(raw[:])
	if id == 0 {
		id = 1
	}
	return id, nil
}

func (session *serverSession) Stats() transport.TransportStats {
	return transport.TransportStats{
		BytesSent:       session.bytesSent.Load(),
		BytesReceived:   session.bytesReceived.Load(),
		PacketsSent:     session.packetsSent.Load(),
		PacketsReceived: session.packetsReceived.Load(),
		Extra: map[string]uint64{
			"udp_send_batch_calls":         session.sendBatchCalls.Load(),
			"udp_send_batch_packets":       session.sendBatchPackets.Load(),
			"udp_send_batch_bytes":         session.sendBatchBytes.Load(),
			"udp_send_batch_mmsg_syscalls": session.sendBatchMMSGSyscalls.Load(),
			"udp_send_batch_loop_syscalls": session.sendBatchLoopSyscalls.Load(),
			"udp_send_batch_fallbacks":     session.sendBatchFallbacks.Load(),
			"udp_recv_batch_calls":         session.recvBatchCalls.Load(),
			"udp_recv_batch_packets":       session.recvBatchPackets.Load(),
			"udp_recv_batch_bytes":         session.recvBatchBytes.Load(),
		},
		NativeBatching: true,
		Datagram:       true,
		MaxPacketSize:  userspaceUDPDatagramMaxPacketSize(),
	}
}
