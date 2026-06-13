package experimentaltcp

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
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

const experimentalTCPKernelCryptoReplayWindow = 65536

// AF_XDP can deliver short bursts much faster than userspace crypto/inject can
// drain them. Keep the default bounded; oversized queues can pin hundreds of
// MiB of borrowed packet buffers per session when downstream stalls.
const (
	experimentalTCPSessionBufferDefault           = 512
	experimentalTCPSessionBufferMax               = 8192
	experimentalTCPFragmentPayloadSize            = 2000
	experimentalTCPFragmentPayloadMax             = 32000
	experimentalTCPKernelFragmentPayloadMax       = 4079
	experimentalTCPKernelSealBeforeMax            = 512*1024 - 16
	experimentalTCPSecureFrameOverhead            = 24 + 16
	experimentalTCPUserspaceCryptoPayloadHint     = experimentalTCPFragmentPayloadSize
	experimentalTCPMaxFragments                   = 256
	experimentalTCPReassemblyTTL                  = 30 * time.Second
	experimentalTCPReassemblyMaxAssembliesDefault = 1024
	experimentalTCPReassemblyMaxAssembliesMax     = 8192
	experimentalTCPRecvCoalesceDelayMax           = 10 * time.Millisecond
	experimentalTCPRecvDrainDefault               = 0
	experimentalTCPRecvDrainMax                   = 256
	experimentalTCPTIXBVersion                    = 1
	experimentalTCPTIXBHeaderLen                  = 8
	experimentalTCPTIXBItemHeaderLen              = 2
	experimentalTCPTIXBMaxPackets                 = 256
)

const (
	experimentalTCPStatFragmentedPacketsSent     = "experimental_tcp_fragmented_packets_sent"
	experimentalTCPStatFragmentsSent             = "experimental_tcp_fragments_sent"
	experimentalTCPStatFragmentsReceived         = "experimental_tcp_fragments_received"
	experimentalTCPStatFragmentedPacketsReceived = "experimental_tcp_fragmented_packets_received"
	experimentalTCPStatFragmentsReassembled      = "experimental_tcp_fragments_reassembled"
	experimentalTCPStatFragmentAssembliesCurrent = "experimental_tcp_fragment_assemblies_current"
	experimentalTCPStatFragmentDuplicates        = "experimental_tcp_fragment_duplicates"
	experimentalTCPStatFragmentExpiredAssemblies = "experimental_tcp_fragment_expired_assemblies"
	experimentalTCPStatFragmentExpiredFragments  = "experimental_tcp_fragment_expired_fragments"
	experimentalTCPStatFragmentMismatches        = "experimental_tcp_fragment_mismatches"
	experimentalTCPStatFragmentRejects           = "experimental_tcp_fragment_rejects"
	experimentalTCPStatFragmentPayloadSize       = "experimental_tcp_fragment_payload_size"
	experimentalTCPStatTIXBExpandedPackets       = "experimental_tcp_tixb_expanded_packets"
	experimentalTCPStatTIXBExpandedItems         = "experimental_tcp_tixb_expanded_items"
)

const (
	experimentalTCPCompatTCPPrimerDefault  = true
	experimentalTCPCompatTCPPrimerTimeout  = 3 * time.Second
	experimentalTCPCompatHandshakePriority = 200 * time.Millisecond
	experimentalTCPCompatPriorityBuffer    = 8
	experimentalTCPCompatControlVersion    = 1
	experimentalTCPCompatControlInitType   = 1
	experimentalTCPCompatControlInitLen    = 16
	experimentalTCPCompatControlInitOldLen = 14
)

var (
	experimentalTCPCompatControlMagic = [4]byte{'T', 'I', 'X', 'C'}
	experimentalTCPSecureHelloMagic   = [4]byte{'T', 'I', 'X', 'H'}
	experimentalTCPTIXBMagic          = [4]byte{'T', 'I', 'X', 'B'}
)

var experimentalTCPPacketBatchPool = sync.Pool{
	New: func() any {
		return &experimentalTCPPacketBatch{
			packets: make([][]byte, 0, 256),
		}
	},
}

type Options struct {
	CryptoPlacement func() dataplane.CryptoPlacement
	Encryption      func() string
}

type Transport struct {
	provider dataplane.ExperimentalTCPProvider
	options  Options
}

func New(provider dataplane.ExperimentalTCPProvider, options ...Options) *Transport {
	var opts Options
	if len(options) > 0 {
		opts = options[0]
	}
	return &Transport{provider: provider, options: opts}
}

func experimentalTCPSessionBuffer() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_EXPERIMENTAL_TCP_SESSION_BUFFER"))
	if value == "" {
		return experimentalTCPSessionBufferDefault
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return experimentalTCPSessionBufferDefault
	}
	if parsed > experimentalTCPSessionBufferMax {
		return experimentalTCPSessionBufferMax
	}
	return parsed
}

func experimentalTCPReassemblyMaxAssemblies() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_EXPERIMENTAL_TCP_REASSEMBLY_MAX_ASSEMBLIES"))
	if value == "" {
		return experimentalTCPReassemblyMaxAssembliesDefault
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return experimentalTCPReassemblyMaxAssembliesDefault
	}
	if parsed > experimentalTCPReassemblyMaxAssembliesMax {
		return experimentalTCPReassemblyMaxAssembliesMax
	}
	return parsed
}

func experimentalTCPRecvCoalesceDelay() time.Duration {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_EXPERIMENTAL_TCP_RECV_COALESCE_DELAY"))
	if value == "" {
		value = strings.TrimSpace(os.Getenv("TRUSTIX_EXPERIMENTAL_TCP_RECV_BATCH_DELAY"))
	}
	if value == "" {
		return 0
	}
	if parsed, err := time.ParseDuration(value); err == nil {
		if parsed < 0 {
			return 0
		}
		if parsed > experimentalTCPRecvCoalesceDelayMax {
			return experimentalTCPRecvCoalesceDelayMax
		}
		return parsed
	}
	micros, err := strconv.Atoi(value)
	if err != nil || micros <= 0 {
		return 0
	}
	delay := time.Duration(micros) * time.Microsecond
	if delay > experimentalTCPRecvCoalesceDelayMax {
		return experimentalTCPRecvCoalesceDelayMax
	}
	return delay
}

func experimentalTCPRecvDrainBatchLimit() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_EXPERIMENTAL_TCP_RECV_DRAIN_BATCHES"))
	if value == "" {
		return experimentalTCPRecvDrainDefault
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return experimentalTCPRecvDrainDefault
	}
	if parsed > experimentalTCPRecvDrainMax {
		return experimentalTCPRecvDrainMax
	}
	return parsed
}

func (transportImpl *Transport) Name() transport.Protocol {
	return transport.ProtocolExperimentalTCP
}

func (transportImpl *Transport) Probe(ctx context.Context, peer transport.Peer) transport.ProbeResult {
	if experimentalTCPCompatStreamDataEnabled() {
		hasExperimentalTCPEndpoint := false
		for _, endpoint := range peer.Endpoints {
			if endpoint.Transport != transport.ProtocolExperimentalTCP || endpoint.Address == "" {
				continue
			}
			hasExperimentalTCPEndpoint = true
			if experimentalTCPCompatPrimerEnabled() && experimentalTCPCompatPrimerAddressSupported(endpoint.Address, false) {
				return transport.ProbeResult{Healthy: true, CheckedAt: time.Now()}
			}
		}
		if hasExperimentalTCPEndpoint && transportImpl.provider == nil {
			return transport.ProbeResult{Healthy: false, Error: "experimental_tcp compat stream requires a supported TCP primer address", CheckedAt: time.Now()}
		}
	}
	if transportImpl.provider == nil {
		return transport.ProbeResult{Healthy: false, Error: "experimental_tcp dataplane provider is unavailable", CheckedAt: time.Now()}
	}
	status, err := transportImpl.provider.ExperimentalTCPStatus(ctx)
	if err != nil {
		return transport.ProbeResult{Healthy: false, Error: err.Error(), CheckedAt: time.Now()}
	}
	if !status.Available || !status.Reinject {
		return transport.ProbeResult{Healthy: false, Error: "experimental_tcp TC/XDP reinject is unavailable", CheckedAt: time.Now()}
	}
	for _, endpoint := range peer.Endpoints {
		if endpoint.Transport == transport.ProtocolExperimentalTCP && endpoint.Address != "" {
			if _, err := transportImpl.selectCryptoPlacementFromStatus(status, endpoint.Encryption); err != nil {
				return transport.ProbeResult{Healthy: false, Error: err.Error(), CheckedAt: time.Now()}
			}
			return transport.ProbeResult{Healthy: true, CheckedAt: time.Now()}
		}
	}
	return transport.ProbeResult{Healthy: false, Error: "no experimental_tcp endpoint", CheckedAt: time.Now()}
}

func (transportImpl *Transport) Dial(ctx context.Context, peer transport.Peer, tlsConf *tls.Config) (transport.Session, error) {
	var lastErr error
	for _, endpoint := range peer.Endpoints {
		if endpoint.Transport != transport.ProtocolExperimentalTCP || endpoint.Address == "" {
			continue
		}
		if experimentalTCPCompatStreamDataEnabled() {
			primerConn, err := dialExperimentalTCPCompatPrimer(ctx, endpoint)
			if err != nil {
				lastErr = err
				if experimentalTCPCompatPrimerRequired() || transportImpl.provider == nil {
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
				return nil, fmt.Errorf("experimental_tcp compat stream unavailable and dataplane provider is unavailable: %w", lastErr)
			}
			return nil, fmt.Errorf("experimental_tcp dataplane provider is unavailable")
		}
		placement, err := transportImpl.selectCryptoPlacement(ctx, endpoint.Encryption)
		if err != nil {
			return nil, err
		}
		flowID, err := randomFlowID()
		if err != nil {
			return nil, err
		}
		primerConn, err := dialExperimentalTCPCompatPrimer(ctx, endpoint)
		if err != nil {
			if experimentalTCPCompatPrimerRequired() {
				return nil, err
			}
			primerConn = nil
		}
		flow := dataplane.ExperimentalTCPFlow{
			ID:              flowID,
			Peer:            peer.ID,
			Endpoint:        endpoint.Name,
			LocalAddress:    strings.TrimSpace(endpoint.LocalBind.SourceIP),
			RemoteAddress:   endpoint.Address,
			CryptoPlacement: placement,
			CreatedAt:       time.Now().UTC(),
		}
		if err := transportImpl.provider.InstallExperimentalTCPFlows(ctx, []dataplane.ExperimentalTCPFlow{flow}); err != nil {
			if primerConn != nil {
				_ = primerConn.Close()
			}
			return nil, err
		}
		var compatControl *stream.Session
		if primerConn != nil {
			compatControl = stream.NewSession(primerConn)
			if err := compatControl.SendPacket(encodeExperimentalTCPCompatControlInit(flowID)); err != nil {
				_ = compatControl.Close()
				if deleter, ok := transportImpl.provider.(dataplane.ExperimentalTCPFlowDeleter); ok {
					_ = deleter.DeleteExperimentalTCPFlows(context.Background(), []uint64{flowID})
				}
				return nil, fmt.Errorf("send experimental_tcp compat control init: %w", err)
			}
		}
		subscription, err := transportImpl.subscribeFlow(ctx, flowID)
		if err != nil {
			if compatControl != nil {
				_ = compatControl.Close()
			}
			if deleter, ok := transportImpl.provider.(dataplane.ExperimentalTCPFlowDeleter); ok {
				_ = deleter.DeleteExperimentalTCPFlows(context.Background(), []uint64{flowID})
			}
			return nil, err
		}
		session := newSession(transportImpl.provider, subscription, flowID, peer.ID, endpoint.Name, placement, "", endpoint.Address)
		session.compatControl = compatControl
		session.enableCompatPriority()
		// Dial contexts are commonly canceled after setup; the session receive
		// pump must live until Session.Close closes the subscription/input.
		go session.readSubscription(context.Background())
		go session.readCompatControl(context.Background())
		return session, nil
	}
	return nil, fmt.Errorf("peer %q has no dialable experimental_tcp endpoint", peer.ID)
}

func (transportImpl *Transport) subscribeFlow(ctx context.Context, flowID uint64) (dataplane.ExperimentalTCPSubscription, error) {
	if subscriber, ok := transportImpl.provider.(dataplane.ExperimentalTCPFlowSubscriber); ok {
		return subscriber.SubscribeExperimentalTCPFlow(ctx, flowID, experimentalTCPSessionBuffer())
	}
	return transportImpl.provider.SubscribeExperimentalTCP(ctx, experimentalTCPSessionBuffer())
}

func (transportImpl *Transport) Listen(ctx context.Context, ep transport.Endpoint, tlsConf *tls.Config) (transport.Listener, error) {
	if ep.Transport != transport.ProtocolExperimentalTCP {
		return nil, fmt.Errorf("endpoint %q transport is %q, want experimental_tcp", ep.Name, ep.Transport)
	}
	if experimentalTCPCompatStreamDataEnabled() {
		listener, err := transportImpl.listenCompatStream(ctx, ep)
		if err != nil {
			return nil, err
		}
		if listener != nil {
			return listener, nil
		}
	}
	if transportImpl.provider == nil {
		return nil, fmt.Errorf("experimental_tcp dataplane provider is unavailable")
	}
	placement, err := transportImpl.selectCryptoPlacement(ctx, ep.Encryption)
	if err != nil {
		return nil, err
	}
	subscription, err := transportImpl.provider.SubscribeExperimentalTCP(ctx, experimentalTCPSessionBuffer())
	if err != nil {
		return nil, err
	}
	listener := &listener{
		provider:       transportImpl.provider,
		endpoint:       ep,
		subscription:   subscription,
		acceptCh:       make(chan transport.Session, 64),
		compatAcceptCh: make(chan transport.Session, 64),
		done:           make(chan struct{}),
		sessions:       make(map[uint64]*session),
		placement:      placement,
	}
	if compatListener, err := listenExperimentalTCPCompatPrimer(ep.Listen); err != nil {
		_ = subscription.Close()
		return nil, err
	} else {
		listener.compatListener = compatListener
		listener.primerFlowRequired = compatListener != nil
	}
	go listener.readSubscription(ctx)
	go listener.acceptCompatPrimers()
	return listener, nil
}

func (transportImpl *Transport) listenCompatStream(ctx context.Context, ep transport.Endpoint) (transport.Listener, error) {
	compatListener, err := listenExperimentalTCPCompatPrimer(ep.Listen)
	if err != nil {
		return nil, err
	}
	if compatListener == nil {
		if transportImpl.provider == nil {
			return nil, fmt.Errorf("experimental_tcp compat stream requires a supported TCP primer listen address")
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
	provider           dataplane.ExperimentalTCPProvider
	endpoint           transport.Endpoint
	subscription       dataplane.ExperimentalTCPSubscription
	acceptCh           chan transport.Session
	compatAcceptCh     chan transport.Session
	done               chan struct{}
	closeOnce          sync.Once
	mu                 sync.Mutex
	sessions           map[uint64]*session
	placement          dataplane.CryptoPlacement
	compatListener     net.Listener
	primerFlowRequired bool
}

func (transportImpl *Transport) requestedCryptoPlacement() dataplane.CryptoPlacement {
	if transportImpl.options.CryptoPlacement == nil {
		return dataplane.CryptoPlacementAuto
	}
	return normalizeCryptoPlacement(transportImpl.options.CryptoPlacement())
}

func (transportImpl *Transport) selectCryptoPlacement(ctx context.Context, encryption string) (dataplane.CryptoPlacement, error) {
	status, err := transportImpl.provider.ExperimentalTCPStatus(ctx)
	if err != nil {
		return "", err
	}
	if !status.Available || !status.Reinject {
		return "", fmt.Errorf("experimental_tcp TC/XDP reinject is unavailable")
	}
	return transportImpl.selectCryptoPlacementFromStatus(status, encryption)
}

func (transportImpl *Transport) selectCryptoPlacementFromStatus(status dataplane.ExperimentalTCPStatus, encryption string) (dataplane.CryptoPlacement, error) {
	if experimentalTCPPlaintextEncryption(transportImpl.effectiveEncryption(encryption)) {
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

func experimentalTCPPlaintextEncryption(encryption string) bool {
	switch strings.ToLower(strings.TrimSpace(encryption)) {
	case "plaintext", "none", "disabled", "off":
		return true
	default:
		return false
	}
}

func selectCryptoPlacement(requested dataplane.CryptoPlacement, status dataplane.ExperimentalTCPStatus) (dataplane.CryptoPlacement, error) {
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
		return "", fmt.Errorf("experimental_tcp kernel crypto requested but unavailable: %s", reason)
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
		return "", fmt.Errorf("experimental_tcp has no available crypto placement")
	case dataplane.CryptoPlacementUserspace:
		if status.UserspaceCrypto {
			return dataplane.CryptoPlacementUserspace, nil
		}
		return "", fmt.Errorf("experimental_tcp userspace crypto is not available")
	default:
		return "", fmt.Errorf("experimental_tcp crypto placement %q is unsupported", requested)
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
		return nil, fmt.Errorf("experimental_tcp listener is closed")
	case session := <-listener.compatAcceptCh:
		if session == nil {
			return nil, fmt.Errorf("experimental_tcp listener is closed")
		}
		return session, nil
	case session := <-listener.acceptCh:
		if session == nil {
			return nil, fmt.Errorf("experimental_tcp listener is closed")
		}
		return session, nil
	}
}

func (listener *listener) Close() error {
	var err error
	listener.closeOnce.Do(func() {
		close(listener.done)
		if listener.subscription != nil {
			err = listener.subscription.Close()
		}
		if listener.compatListener != nil {
			_ = listener.compatListener.Close()
		}
		listener.mu.Lock()
		for flowID, session := range listener.sessions {
			session.closeInput()
			delete(listener.sessions, flowID)
		}
		listener.mu.Unlock()
	})
	return err
}

func (listener *listener) closeOnContext(ctx context.Context) {
	<-ctx.Done()
	_ = listener.Close()
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
		tuneExperimentalTCPCompatConn(conn)
		if experimentalTCPCompatStreamDataEnabled() {
			select {
			case <-listener.done:
				_ = conn.Close()
				return
			case listener.compatAcceptCh <- &compatStreamSession{
				Session:  stream.NewSession(conn),
				endpoint: listener.endpoint.Name,
			}:
			default:
				_ = conn.Close()
			}
			continue
		}
		control, init, err := acceptExperimentalTCPCompatControl(conn)
		if err != nil {
			_ = conn.Close()
			continue
		}
		flow := experimentalTCPCompatInboundFlow(init, conn, listener.endpoint, listener.placement)
		if err := listener.provider.InstallExperimentalTCPFlows(context.Background(), []dataplane.ExperimentalTCPFlow{flow}); err != nil {
			_ = control.Close()
			continue
		}
		sess := newSession(listener.provider, nil, init.flowID, "", listener.endpoint.Name, listener.placement, flow.LocalAddress, flow.RemoteAddress)
		sess.compatControl = control
		sess.enableCompatPriority()
		listener.mu.Lock()
		if existing := listener.sessions[init.flowID]; existing != nil && !existing.isClosed() {
			listener.mu.Unlock()
			_ = control.Close()
			continue
		}
		listener.sessions[init.flowID] = sess
		select {
		case <-listener.done:
			delete(listener.sessions, init.flowID)
			listener.mu.Unlock()
			_ = control.Close()
			return
		case listener.acceptCh <- sess:
			listener.mu.Unlock()
			listener.forgetSessionWhenClosed(init.flowID, sess)
			go sess.readCompatControl(context.Background())
		default:
			delete(listener.sessions, init.flowID)
			listener.mu.Unlock()
			_ = control.Close()
			if deleter, ok := listener.provider.(dataplane.ExperimentalTCPFlowDeleter); ok {
				_ = deleter.DeleteExperimentalTCPFlows(context.Background(), []uint64{init.flowID})
			}
		}
	}
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
	if batchSubscription, ok := listener.subscription.(dataplane.ExperimentalTCPBatchSubscription); ok {
		listener.readBatchSubscription(ctx, batchSubscription)
		return
	}
	for {
		select {
		case <-ctx.Done():
			_ = listener.Close()
			return
		case <-listener.done:
			return
		case frame, ok := <-listener.subscription.Events():
			if !ok {
				_ = listener.Close()
				return
			}
			if frame.Direction != dataplane.ExperimentalTCPInbound {
				releaseExperimentalTCPFrame(frame)
				continue
			}
			listener.dispatch(frame)
		}
	}
}

func (listener *listener) readBatchSubscription(ctx context.Context, subscription dataplane.ExperimentalTCPBatchSubscription) {
	for {
		select {
		case <-ctx.Done():
			_ = listener.Close()
			return
		case <-listener.done:
			return
		case frames, ok := <-subscription.BatchEvents():
			if !ok {
				_ = listener.Close()
				return
			}
			listener.dispatchBatch(frames)
		}
	}
}

func (listener *listener) dispatch(frame dataplane.ExperimentalTCPFrame) {
	listener.mu.Lock()
	sess := listener.sessions[frame.FlowID]
	if sess != nil && sess.isClosed() {
		delete(listener.sessions, frame.FlowID)
		sess = nil
	}
	if sess == nil {
		if frame.Endpoint != "" && frame.Endpoint != listener.endpoint.Name {
			listener.mu.Unlock()
			releaseExperimentalTCPFrame(frame)
			return
		}
		if listener.primerFlowRequired {
			listener.mu.Unlock()
			releaseExperimentalTCPFrame(frame)
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
			releaseExperimentalTCPFrame(frame)
			return
		}
	}
	listener.mu.Unlock()
	sess.handleFrame(frame)
}

func (listener *listener) dispatchBatch(frames []dataplane.ExperimentalTCPFrame) {
	if len(frames) == 0 {
		return
	}
	var singleSession *session
	var singleFrames []dataplane.ExperimentalTCPFrame
	var accepted map[*session][]dataplane.ExperimentalTCPFrame
	listener.mu.Lock()
	for _, frame := range frames {
		if frame.Direction != dataplane.ExperimentalTCPInbound {
			releaseExperimentalTCPFrame(frame)
			continue
		}
		sess := listener.sessions[frame.FlowID]
		if sess != nil && sess.isClosed() {
			delete(listener.sessions, frame.FlowID)
			sess = nil
		}
		if sess == nil {
			if frame.Endpoint != "" && frame.Endpoint != listener.endpoint.Name {
				releaseExperimentalTCPFrame(frame)
				continue
			}
			if listener.primerFlowRequired {
				releaseExperimentalTCPFrame(frame)
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
				releaseExperimentalTCPFrame(frame)
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
		accepted = map[*session][]dataplane.ExperimentalTCPFrame{
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
	provider                  dataplane.ExperimentalTCPProvider
	subscription              dataplane.ExperimentalTCPSubscription
	flowID                    uint64
	peer                      core.IXID
	peerIdentity              transport.PeerIdentity
	endpoint                  core.EndpointID
	localAddress              string
	remoteAddress             string
	in                        chan experimentalTCPPacketBatch
	recvPending               experimentalTCPPacketBatch
	closeOnce                 sync.Once
	closeInputOnce            sync.Once
	sendMu                    sync.Mutex
	recvMu                    sync.Mutex
	closed                    chan struct{}
	reassembly                map[uint64]*fragmentAssembly
	sendSeq                   atomic.Uint64
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
	tixbExpandedPackets       atomic.Uint64
	tixbExpandedItems         atomic.Uint64
	epoch                     uint64
	cryptoPlacement           dataplane.CryptoPlacement
	cryptoSuite               string
	cryptoOffloaded           bool
	compatControl             *stream.Session
	compatPriority            chan []byte
	compatPriorityWaited      atomic.Bool
	sendFrames                []dataplane.ExperimentalTCPFrame
	sendExpandedPackets       [][]byte
	reassemblyMaxAssemblies   int
	configuredFragmentPayload int
	fragmentPayloadCached     int
	fragmentPayloadCacheKey   fragmentPayloadCacheKey
	sealBeforeMaxCached       int
	sealBeforeMaxCacheKey     fragmentPayloadCacheKey
	keepFlowOnClose           bool
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

type experimentalTCPCompatControlInit struct {
	flowID     uint64
	sourcePort uint16
}

type fragmentAssembly struct {
	createdAt time.Time
	fragments [][]byte
	received  int
	totalLen  int
}

type experimentalTCPPacketBatch struct {
	packets  [][]byte
	releases []func()
	owner    *experimentalTCPPacketBatch
}

func takeExperimentalTCPPacketBatch(size int) experimentalTCPPacketBatch {
	owner := experimentalTCPPacketBatchPool.Get().(*experimentalTCPPacketBatch)
	if cap(owner.packets) < size {
		owner.packets = make([][]byte, 0, size)
	} else {
		owner.packets = owner.packets[:0]
	}
	owner.releases = nil
	owner.owner = owner
	return experimentalTCPPacketBatch{
		packets: owner.packets,
		owner:   owner,
	}
}

func syncExperimentalTCPPacketBatchOwner(batch *experimentalTCPPacketBatch) {
	if batch == nil || batch.owner == nil {
		return
	}
	batch.owner.packets = batch.packets
	batch.owner.releases = batch.releases
	batch.owner.owner = batch.owner
}

func putExperimentalTCPPacketBatch(owner *experimentalTCPPacketBatch) {
	if owner == nil {
		return
	}
	clear(owner.packets)
	clear(owner.releases)
	if cap(owner.packets) > 4096 || cap(owner.releases) > 4096 {
		*owner = experimentalTCPPacketBatch{}
		return
	}
	owner.packets = owner.packets[:0]
	owner.releases = nil
	owner.owner = nil
	experimentalTCPPacketBatchPool.Put(owner)
}

func releaseExperimentalTCPPacketBatchOwner(batch experimentalTCPPacketBatch) {
	if batch.owner != nil {
		putExperimentalTCPPacketBatch(batch.owner)
	}
}

func experimentalTCPPacketBatchReleases(batch *experimentalTCPPacketBatch, prefix int, size int) []func() {
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

func newSession(provider dataplane.ExperimentalTCPProvider, subscription dataplane.ExperimentalTCPSubscription, flowID uint64, peer core.IXID, endpoint core.EndpointID, placement dataplane.CryptoPlacement, wireAddresses ...string) *session {
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
		in:                        make(chan experimentalTCPPacketBatch, experimentalTCPSessionBuffer()),
		closed:                    make(chan struct{}),
		cryptoPlacement:           placement,
		reassemblyMaxAssemblies:   experimentalTCPReassemblyMaxAssemblies(),
		configuredFragmentPayload: experimentalTCPFragmentPayloadSizeForPlacement(placement, false),
	}
}

func (session *session) enableCompatPriority() {
	if session == nil || session.compatPriority != nil {
		return
	}
	session.compatPriority = make(chan []byte, experimentalTCPCompatPriorityBuffer)
}

func (session *session) readSubscription(ctx context.Context) {
	if session.subscription == nil {
		return
	}
	if batchSubscription, ok := session.subscription.(dataplane.ExperimentalTCPBatchSubscription); ok {
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
			if frame.Direction != dataplane.ExperimentalTCPInbound || frame.FlowID != session.flowID {
				releaseExperimentalTCPFrame(frame)
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
			_ = session.Close()
			return
		}
		if !experimentalTCPCompatControlEligible(packet) {
			continue
		}
		if session.enqueueCompatPriority(packet) {
			continue
		}
		session.enqueue(packet)
	}
}

func (session *session) readBatchSubscription(ctx context.Context, subscription dataplane.ExperimentalTCPBatchSubscription) {
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
			var filtered []dataplane.ExperimentalTCPFrame
			for i, frame := range frames {
				if frame.Direction == dataplane.ExperimentalTCPInbound && frame.FlowID == session.flowID {
					if filtered != nil {
						filtered = append(filtered, frame)
					}
					continue
				}
				if filtered == nil {
					filtered = make([]dataplane.ExperimentalTCPFrame, 0, len(frames))
					for _, previous := range frames[:i] {
						if previous.Direction == dataplane.ExperimentalTCPInbound && previous.FlowID == session.flowID {
							filtered = append(filtered, previous)
						} else {
							releaseExperimentalTCPFrame(previous)
						}
					}
				}
				releaseExperimentalTCPFrame(frame)
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
	if session.compatControl != nil && experimentalTCPCompatControlEligible(pkt) {
		if err := session.compatControl.SendPacket(pkt); err != nil {
			return err
		}
		session.bytesSent.Add(uint64(len(pkt)))
		session.packetsSent.Add(1)
		return nil
	}
	return session.SendPackets([][]byte{pkt})
}

func (session *session) SendPackets(pkts [][]byte) error {
	if len(pkts) == 0 {
		return nil
	}
	select {
	case <-session.closed:
		return fmt.Errorf("experimental_tcp session is closed")
	default:
	}
	session.sendMu.Lock()
	defer session.sendMu.Unlock()
	select {
	case <-session.closed:
		return fmt.Errorf("experimental_tcp session is closed")
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
		if _, ok := session.provider.(dataplane.ExperimentalTCPBatchProvider); !ok {
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
		if count > experimentalTCPMaxFragments {
			return fmt.Errorf("experimental_tcp packet size %d requires %d fragments, max %d", len(pkt), count, experimentalTCPMaxFragments)
		}
		totalFragments += count
	}
	if cap(session.sendFrames) < totalFragments {
		session.sendFrames = make([]dataplane.ExperimentalTCPFrame, 0, totalFragments)
	} else {
		session.sendFrames = session.sendFrames[:0]
	}
	frames := session.sendFrames
	defer func() {
		clearExperimentalTCPFrames(frames)
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
			frames = append(frames, dataplane.ExperimentalTCPFrame{
				FlowID:              session.flowID,
				Direction:           dataplane.ExperimentalTCPOutbound,
				Peer:                session.peer,
				Endpoint:            session.endpoint,
				Sequence:            baseSeq,
				FragmentPayloadSize: sealBeforeFragmentPayloadSize,
				Payload:             pkt,
				InnerIPv4:           experimentalTCPInnerIPv4Eligible(pkt),
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
		innerIPv4 := count == 1 && experimentalTCPInnerIPv4Eligible(pkt)
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
			frames = append(frames, dataplane.ExperimentalTCPFrame{
				FlowID:          session.flowID,
				Direction:       dataplane.ExperimentalTCPOutbound,
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
	if batch, ok := session.provider.(dataplane.ExperimentalTCPBatchProvider); ok {
		if err := batch.SubmitExperimentalTCPFrames(context.Background(), frames); err != nil {
			return err
		}
	} else {
		for _, frame := range frames {
			if err := session.provider.SubmitExperimentalTCPFrame(context.Background(), frame); err != nil {
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
	if session == nil || session.cryptoOffloaded || !experimentalTCPTIXBExpandEnabled() {
		return pkts, 0, 0
	}
	var expandedPackets uint64
	var expandedItems uint64
	for i, pkt := range pkts {
		items, ok := decodeExperimentalTCPTIXBInto(pkt, nil)
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
			items, ok = decodeExperimentalTCPTIXBInto(candidate, nil)
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

func experimentalTCPTIXBExpandEnabled() bool {
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_EXPAND_TIXB",
		"TRUSTIX_EXPERIMENTAL_TCP_TIXB_EXPAND",
	)
}

func decodeExperimentalTCPTIXBInto(packet []byte, dst [][]byte) ([][]byte, bool) {
	if len(packet) < experimentalTCPTIXBHeaderLen {
		return nil, false
	}
	if packet[0] != experimentalTCPTIXBMagic[0] ||
		packet[1] != experimentalTCPTIXBMagic[1] ||
		packet[2] != experimentalTCPTIXBMagic[2] ||
		packet[3] != experimentalTCPTIXBMagic[3] ||
		packet[4] != experimentalTCPTIXBVersion {
		return nil, false
	}
	count := int(binary.BigEndian.Uint16(packet[6:8]))
	if count <= 0 || count > experimentalTCPTIXBMaxPackets {
		return nil, false
	}
	offset := experimentalTCPTIXBHeaderLen
	var items [][]byte
	if cap(dst) < count {
		items = make([][]byte, 0, count)
	} else {
		items = dst[:0]
	}
	for i := 0; i < count; i++ {
		if len(packet)-offset < experimentalTCPTIXBItemHeaderLen {
			return nil, false
		}
		size := int(binary.BigEndian.Uint16(packet[offset : offset+experimentalTCPTIXBItemHeaderLen]))
		offset += experimentalTCPTIXBItemHeaderLen
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

func experimentalTCPInnerIPv4Eligible(packet []byte) bool {
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
	return experimentalTCPKernelSealBeforeFragmentEnabled()
}

func (session *session) sealBeforeFragmentMax(enabled bool) int {
	if session == nil || !enabled {
		return 0
	}
	configured := session.configuredFragmentPayload
	if configured == 0 {
		configured = experimentalTCPFragmentPayloadSizeForPlacement(session.cryptoPlacement, session.cryptoOffloaded)
	}
	key := fragmentPayloadCacheKey{
		placement:  session.cryptoPlacement,
		offloaded:  session.cryptoOffloaded,
		configured: configured,
	}
	if session.sealBeforeMaxCached > 0 && session.sealBeforeMaxCacheKey == key {
		return session.sealBeforeMaxCached
	}
	maxPlain := experimentalTCPKernelSealBeforeMax
	if sizer, ok := session.provider.(dataplane.ExperimentalTCPSealBeforeFragmentSizer); ok {
		if maxSize, err := sizer.ExperimentalTCPSealBeforeFragmentMax(context.Background(), session.cryptoPlacement); err == nil && maxSize > 0 && maxSize < maxPlain {
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
		maxPlain = experimentalTCPKernelSealBeforeMax
	}
	return packetLen > 0 && packetLen <= maxPlain
}

func (session *session) sealBeforeFragmentPayloadSize(fallback int) int {
	if fallback < 1 {
		fallback = 1
	}
	if !experimentalTCPKernelSealBeforeFragmentWireMaxEnabled() {
		return fallback
	}
	sizer, ok := session.provider.(dataplane.ExperimentalTCPPayloadSizer)
	if !ok {
		return fallback
	}
	maxSize, err := sizer.ExperimentalTCPPayloadMax(context.Background(), dataplane.CryptoPlacementUserspace, false)
	if err != nil || maxSize < 1 {
		return fallback
	}
	return maxSize
}

func (session *session) wireFragmentCount(packetLen int, payloadSize int, sealBeforeFragmentPayloadSize int, sealBeforeFragment bool, sealBeforeFragmentMax int) int {
	if session.shouldSealBeforeFragment(packetLen, payloadSize, sealBeforeFragment, sealBeforeFragmentMax) {
		return fragmentCountForSize(packetLen+experimentalTCPSecureFrameOverhead, sealBeforeFragmentPayloadSize)
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
	coalesceDelay := experimentalTCPRecvCoalesceDelay()
	drainLimit := experimentalTCPRecvDrainBatchLimit()
	var packets [][]byte
	var releases []func()
	var releaseBatch experimentalTCPPacketBatch
	var borrowedBatches []*experimentalTCPPacketBatch
	appendBatch := func(batch experimentalTCPPacketBatch, limit int) (experimentalTCPPacketBatch, bool) {
		batch = trimExperimentalTCPPacketBatch(batch)
		if len(batch.packets) == 0 {
			releaseExperimentalTCPPacketBatchOwner(batch)
			return experimentalTCPPacketBatch{}, false
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
				releaseExperimentalTCPPacketBatchOwner(batch)
			}
			return experimentalTCPPacketBatch{}, false
		}
		remaining := experimentalTCPPacketBatch{packets: batch.packets[limit:]}
		if len(batch.releases) > 0 {
			remaining.releases = experimentalTCPReleaseSuffix(batch.releases, limit)
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
			return packets, experimentalTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
		}
	}
	for len(packets) < max {
		select {
		case <-session.closed:
			if len(packets) > 0 {
				session.recordReceivedPackets(packets)
				return packets, experimentalTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
			}
			return nil, nil, fmt.Errorf("experimental_tcp session is closed")
		case pkt, ok := <-session.compatPriority:
			if !ok || len(pkt) == 0 {
				continue
			}
			packets = append(packets, pkt)
			session.recordReceivedPackets(packets)
			return packets, experimentalTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
		case batch, ok := <-session.in:
			if !ok {
				if len(packets) > 0 {
					session.recordReceivedPackets(packets)
					return packets, experimentalTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
				}
				return nil, nil, fmt.Errorf("experimental_tcp session is closed")
			}
			remaining, hasRemaining := appendBatch(batch, max-len(packets))
			if hasRemaining {
				session.recvPending = remaining
				session.recordReceivedPackets(packets)
				return packets, experimentalTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
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
							return packets, experimentalTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
						}
						remaining, hasRemaining := appendBatch(batch, max-len(packets))
						if hasRemaining {
							session.recvPending = remaining
							session.recordReceivedPackets(packets)
							return packets, experimentalTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
						}
					default:
						drained = drainLimit
					}
				}
				if coalesceDelay <= 0 || len(packets) >= max {
					session.recordReceivedPackets(packets)
					return packets, experimentalTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
				}
				timer := time.NewTimer(coalesceDelay)
				select {
				case <-session.closed:
					stopExperimentalTCPTimer(timer)
					session.recordReceivedPackets(packets)
					return packets, experimentalTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
				case batch, ok := <-session.in:
					stopExperimentalTCPTimer(timer)
					if !ok {
						session.recordReceivedPackets(packets)
						return packets, experimentalTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
					}
					remaining, hasRemaining := appendBatch(batch, max-len(packets))
					if hasRemaining {
						session.recvPending = remaining
						session.recordReceivedPackets(packets)
						return packets, experimentalTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
					}
				case <-timer.C:
					session.recordReceivedPackets(packets)
					return packets, experimentalTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
				}
				continue
			}
			select {
			case <-session.closed:
				return nil, nil, fmt.Errorf("experimental_tcp session is closed")
			case batch, ok := <-session.in:
				if !ok {
					return nil, nil, fmt.Errorf("experimental_tcp session is closed")
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
	return packets, experimentalTCPReleaseFunc(releaseBatch, releases, borrowedBatches), nil
}

func stopExperimentalTCPTimer(timer *time.Timer) {
	if timer == nil || timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}

func trimExperimentalTCPPacketBatch(batch experimentalTCPPacketBatch) experimentalTCPPacketBatch {
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

func experimentalTCPReleaseSuffix(releases []func(), offset int) []func() {
	if len(releases) == 0 || offset >= len(releases) {
		return nil
	}
	if offset <= 0 {
		return releases
	}
	return releases[offset:]
}

func experimentalTCPReleaseFunc(batch experimentalTCPPacketBatch, releases []func(), owners []*experimentalTCPPacketBatch) func() {
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
			putExperimentalTCPPacketBatch(owner)
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
	info := transport.KernelDatapathSessionInfo{
		FlowID:              session.flowID,
		Protocol:            transport.ProtocolExperimentalTCP,
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

func (session *session) EnableCryptoOffload(spec transport.CryptoOffloadSpec) error {
	if session.cryptoPlacement != dataplane.CryptoPlacementKernel {
		return transport.ErrCryptoOffloadUnavailable
	}
	installer, ok := session.provider.(dataplane.ExperimentalTCPCryptoInstaller)
	if !ok {
		return fmt.Errorf("experimental_tcp kernel crypto requested but provider does not implement crypto installer")
	}
	if spec.WireFormat != transport.CryptoWireFormatTrustIXSecureDataV1 {
		return fmt.Errorf("experimental_tcp crypto offload wire format %q is unsupported", spec.WireFormat)
	}
	cryptoSpec := dataplane.ExperimentalTCPCryptoSpec{
		FlowID:       session.flowID,
		Suite:        spec.Suite,
		WireFormat:   spec.WireFormat,
		KeySource:    spec.KeySource,
		Epoch:        spec.Epoch,
		SendKey:      append([]byte(nil), spec.SendKey...),
		SendIV:       append([]byte(nil), spec.SendIV...),
		RecvKey:      append([]byte(nil), spec.RecvKey...),
		RecvIV:       append([]byte(nil), spec.RecvIV...),
		ReplayWindow: experimentalTCPReplayWindowForKernelCrypto(spec.ReplayWindow),
		InstalledAt:  time.Now().UTC(),
	}
	defer clearExperimentalTCPCryptoSpec(&cryptoSpec)
	if err := installer.InstallExperimentalTCPCrypto(context.Background(), []dataplane.ExperimentalTCPCryptoSpec{cryptoSpec}); err != nil {
		return err
	}
	session.epoch = spec.Epoch
	session.cryptoSuite = spec.Suite
	session.cryptoOffloaded = true
	session.configuredFragmentPayload = experimentalTCPFragmentPayloadSizeForPlacement(session.cryptoPlacement, true)
	session.fragmentPayloadCached = 0
	return nil
}

func experimentalTCPReplayWindowForKernelCrypto(window uint) uint {
	if window >= experimentalTCPKernelCryptoReplayWindow {
		return window
	}
	return experimentalTCPKernelCryptoReplayWindow
}

func (session *session) SetPeerIdentity(peer core.IXID, domain core.DomainID) {
	if peer == "" {
		return
	}
	session.peer = peer
	session.peerIdentity = transport.PeerIdentity{Peer: peer, Domain: domain}
	if annotator, ok := session.provider.(dataplane.ExperimentalTCPFlowAnnotator); ok {
		_ = annotator.SetExperimentalTCPFlowPeer(context.Background(), session.flowID, peer, session.endpoint)
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
	if annotator, ok := session.provider.(dataplane.ExperimentalTCPFlowAnnotator); ok {
		_ = annotator.SetExperimentalTCPFlowPeer(context.Background(), session.flowID, session.peer, session.endpoint)
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
	stats.Extra["experimental_tcp_compat_stream"] = 1
	return stats
}

func clearExperimentalTCPCryptoSpec(spec *dataplane.ExperimentalTCPCryptoSpec) {
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
		if deleter, ok := session.provider.(dataplane.ExperimentalTCPFlowDeleter); ok && !session.keepFlowOnClose {
			_ = deleter.DeleteExperimentalTCPFlows(context.Background(), []uint64{session.flowID})
		}
		session.closeInput()
		if session.subscription != nil {
			_ = session.subscription.Close()
		}
		if session.compatControl != nil {
			_ = session.compatControl.Close()
		}
	})
	return nil
}

func (session *session) RetainKernelFlowOnClose() {
	session.keepFlowOnClose = true
}

func experimentalTCPCompatPrimerEnabled() bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_EXPERIMENTAL_TCP_COMPAT_TCP_PRIMER")))
	switch raw {
	case "", "auto", "require", "required", "force", "forced", "must":
		return experimentalTCPCompatTCPPrimerDefault
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return experimentalTCPCompatTCPPrimerDefault
	}
}

func experimentalTCPCompatPrimerRequired() bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_EXPERIMENTAL_TCP_COMPAT_TCP_PRIMER")))
	switch raw {
	case "require", "required", "force", "forced", "must":
		return true
	default:
		return false
	}
}

func experimentalTCPCompatStreamEnabled() bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_EXPERIMENTAL_TCP_COMPAT_STREAM")))
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

func experimentalTCPCompatStreamDataEnabled() bool {
	if !experimentalTCPCompatStreamEnabled() {
		return false
	}
	if envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT",
		"TRUSTIX_REMOTE_EXPERIMENTAL_TCP_TC_TX_DIRECT",
		"TRUSTIX_E2E_EXPERIMENTAL_TCP_TC_TX_DIRECT",
		"TRUSTIX_IPERF3_CRYPTO_BENCH_EXPERIMENTAL_TCP_TC_TX_DIRECT",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_ONLY",
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_EXPERIMENTAL_TCP_ONLY",
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

func dialExperimentalTCPCompatPrimer(ctx context.Context, endpoint transport.Endpoint) (net.Conn, error) {
	if !experimentalTCPCompatPrimerEnabled() {
		return nil, nil
	}
	address := strings.TrimSpace(endpoint.Address)
	if address == "" {
		return nil, nil
	}
	if !experimentalTCPCompatPrimerAddressSupported(address, false) {
		return nil, nil
	}
	dialCtx, cancel := context.WithTimeout(ctx, experimentalTCPCompatTCPPrimerTimeout)
	defer cancel()
	dialer, err := bind.Dialer(endpoint, "tcp")
	if err != nil {
		return nil, err
	}
	dialer.Timeout = experimentalTCPCompatTCPPrimerTimeout
	dialer.KeepAlive = 30 * time.Second
	conn, err := dialer.DialContext(dialCtx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("experimental_tcp compat TCP primer to %s: %w", address, err)
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tuneExperimentalTCPCompatConn(tcpConn)
	}
	return conn, nil
}

func tuneExperimentalTCPCompatConn(conn net.Conn) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tcpConn.SetKeepAlive(true)
	_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	_ = tcpConn.SetNoDelay(experimentalTCPCompatNoDelay())
}

func experimentalTCPCompatNoDelay() bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_EXPERIMENTAL_TCP_COMPAT_NODELAY")))
	switch raw {
	case "", "auto", "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}

func listenExperimentalTCPCompatPrimer(address string) (net.Listener, error) {
	if !experimentalTCPCompatPrimerEnabled() {
		return nil, nil
	}
	address = strings.TrimSpace(address)
	if address == "" {
		return nil, nil
	}
	if !experimentalTCPCompatPrimerAddressSupported(address, true) {
		return nil, nil
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("experimental_tcp compat TCP primer listen on %s: %w", address, err)
	}
	return listener, nil
}

func experimentalTCPCompatPrimerAddressSupported(address string, listen bool) bool {
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

func experimentalTCPCompatDerivedSourcePort(flowID uint64) uint16 {
	return uint16(40000 + flowID%20000)
}

func experimentalTCPCompatInboundFlow(init experimentalTCPCompatControlInit, conn net.Conn, endpoint transport.Endpoint, placement dataplane.CryptoPlacement) dataplane.ExperimentalTCPFlow {
	now := time.Now().UTC()
	flow := dataplane.ExperimentalTCPFlow{
		ID:              init.flowID,
		Endpoint:        endpoint.Name,
		CryptoPlacement: placement,
		CreatedAt:       now,
	}
	localIP, localPort, localOK := experimentalTCPCompatTCPAddrParts(conn.LocalAddr())
	remoteIP, _, remoteOK := experimentalTCPCompatTCPAddrParts(conn.RemoteAddr())
	if localOK && init.sourcePort != 0 && remoteOK {
		flow.LocalAddress = net.JoinHostPort(localIP.String(), strconv.Itoa(int(localPort)))
		flow.RemoteAddress = net.JoinHostPort(remoteIP.String(), strconv.Itoa(int(init.sourcePort)))
		flow.SourcePort = localPort
		flow.DestinationPort = init.sourcePort
		return flow
	}
	if listen := strings.TrimSpace(endpoint.Listen); listen != "" && init.sourcePort != 0 && remoteOK {
		if ip, port, err := resolveExperimentalTCPCompatHostPort(listen); err == nil && port != 0 {
			flow.LocalAddress = net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
			flow.RemoteAddress = net.JoinHostPort(remoteIP.String(), strconv.Itoa(int(init.sourcePort)))
			flow.SourcePort = port
			flow.DestinationPort = init.sourcePort
		}
	}
	return flow
}

func experimentalTCPCompatTCPAddrParts(addr net.Addr) (netip.Addr, uint16, bool) {
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

func resolveExperimentalTCPCompatHostPort(address string) (netip.Addr, uint16, error) {
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

func encodeExperimentalTCPCompatControlInit(flowID uint64) []byte {
	sourcePort := experimentalTCPCompatDerivedSourcePort(flowID)
	payload := make([]byte, experimentalTCPCompatControlInitLen)
	copy(payload[0:4], experimentalTCPCompatControlMagic[:])
	payload[4] = experimentalTCPCompatControlVersion
	payload[5] = experimentalTCPCompatControlInitType
	binary.BigEndian.PutUint64(payload[6:14], flowID)
	binary.BigEndian.PutUint16(payload[14:16], sourcePort)
	return payload
}

func decodeExperimentalTCPCompatControlInit(payload []byte) (experimentalTCPCompatControlInit, bool) {
	if (len(payload) != experimentalTCPCompatControlInitLen && len(payload) != experimentalTCPCompatControlInitOldLen) ||
		string(payload[0:4]) != string(experimentalTCPCompatControlMagic[:]) ||
		payload[4] != experimentalTCPCompatControlVersion ||
		payload[5] != experimentalTCPCompatControlInitType {
		return experimentalTCPCompatControlInit{}, false
	}
	init := experimentalTCPCompatControlInit{flowID: binary.BigEndian.Uint64(payload[6:14])}
	if len(payload) >= experimentalTCPCompatControlInitLen {
		init.sourcePort = binary.BigEndian.Uint16(payload[14:16])
	}
	return init, init.flowID != 0
}

func acceptExperimentalTCPCompatControl(conn net.Conn) (*stream.Session, experimentalTCPCompatControlInit, error) {
	control := stream.NewSession(conn)
	initPacket, err := control.RecvPacket()
	if err != nil {
		_ = control.Close()
		return nil, experimentalTCPCompatControlInit{}, err
	}
	init, ok := decodeExperimentalTCPCompatControlInit(initPacket)
	if !ok {
		_ = control.Close()
		return nil, experimentalTCPCompatControlInit{}, fmt.Errorf("invalid experimental_tcp compat control init")
	}
	return control, init, nil
}

func experimentalTCPCompatControlEligible(packet []byte) bool {
	return len(packet) >= 6 && string(packet[0:4]) == string(experimentalTCPSecureHelloMagic[:])
}

func experimentalTCPCompatHandshakePriorityDelay() time.Duration {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_EXPERIMENTAL_TCP_COMPAT_HANDSHAKE_PRIORITY_DELAY"))
	if value == "" {
		return experimentalTCPCompatHandshakePriority
	}
	if parsed, err := time.ParseDuration(value); err == nil {
		if parsed < 0 {
			return 0
		}
		if parsed > experimentalTCPCompatTCPPrimerTimeout {
			return experimentalTCPCompatTCPPrimerTimeout
		}
		return parsed
	}
	millis, err := strconv.Atoi(value)
	if err != nil || millis <= 0 {
		return experimentalTCPCompatHandshakePriority
	}
	delay := time.Duration(millis) * time.Millisecond
	if delay > experimentalTCPCompatTCPPrimerTimeout {
		return experimentalTCPCompatTCPPrimerTimeout
	}
	return delay
}

func (session *session) enqueue(pkt []byte) {
	session.enqueueBatch(experimentalTCPPacketBatch{packets: [][]byte{pkt}})
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
		delay := experimentalTCPCompatHandshakePriorityDelay()
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case pkt, ok := <-session.compatPriority:
				appendPacket(pkt, ok)
			case <-session.closed:
			case <-timer.C:
			}
			stopExperimentalTCPTimer(timer)
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

func (session *session) enqueueBatch(batch experimentalTCPPacketBatch) {
	batch = trimExperimentalTCPPacketBatch(batch)
	if len(batch.packets) == 0 {
		releaseExperimentalTCPBatch(batch)
		return
	}
	select {
	case <-session.closed:
		releaseExperimentalTCPBatch(batch)
		return
	default:
	}
	select {
	case <-session.closed:
		releaseExperimentalTCPBatch(batch)
		return
	case session.in <- batch:
	}
}

func (session *session) handleFrame(frame dataplane.ExperimentalTCPFrame) {
	session.handleFrames([]dataplane.ExperimentalTCPFrame{frame})
}

func (session *session) handleFrames(frames []dataplane.ExperimentalTCPFrame) {
	if len(frames) == 0 {
		return
	}
	if len(frames) == 1 {
		if pkt, release, ok := session.handleFrameOne(frames[0]); ok {
			ready := takeExperimentalTCPPacketBatch(1)
			ready.packets = append(ready.packets, pkt)
			if release != nil {
				ready.releases = experimentalTCPPacketBatchReleases(&ready, 0, 1)
				ready.releases = append(ready.releases, release)
			}
			syncExperimentalTCPPacketBatchOwner(&ready)
			session.enqueueBatch(ready)
		}
		return
	}
	ready := takeExperimentalTCPPacketBatch(len(frames))
	for _, frame := range frames {
		if pkt, release, ok := session.handleFrameOne(frame); ok {
			ready.packets = append(ready.packets, pkt)
			if release != nil {
				if ready.releases == nil {
					ready.releases = experimentalTCPPacketBatchReleases(&ready, len(ready.packets)-1, len(frames))
				}
				ready.releases = append(ready.releases, release)
			} else if ready.releases != nil {
				ready.releases = append(ready.releases, nil)
			}
		}
	}
	syncExperimentalTCPPacketBatchOwner(&ready)
	session.enqueueBatch(ready)
}

func (session *session) handleFrameOne(frame dataplane.ExperimentalTCPFrame) ([]byte, func(), bool) {
	if frame.FragmentCount == 0 {
		if frame.FragmentIndex != 0 {
			session.fragmentRejects.Add(1)
			releaseExperimentalTCPFrame(frame)
			return nil, nil, false
		}
		return frame.Payload, frame.Release, true
	}
	if frame.FragmentCount == 1 {
		if frame.FragmentIndex != 0 {
			session.fragmentRejects.Add(1)
			releaseExperimentalTCPFrame(frame)
			return nil, nil, false
		}
		return frame.Payload, frame.Release, true
	}
	if frame.FragmentCount > experimentalTCPMaxFragments || frame.FragmentIndex >= frame.FragmentCount {
		session.fragmentRejects.Add(1)
		releaseExperimentalTCPFrame(frame)
		return nil, nil, false
	}
	if frame.Sequence <= uint64(frame.FragmentIndex) {
		session.fragmentRejects.Add(1)
		releaseExperimentalTCPFrame(frame)
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
		releaseExperimentalTCPFrame(frame)
		return nil, nil, false
	}
	index := int(frame.FragmentIndex)
	if assembly.fragments[index] != nil {
		session.fragmentDuplicates.Add(1)
		session.recvMu.Unlock()
		releaseExperimentalTCPFrame(frame)
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
			releaseExperimentalTCPFrame(frame)
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

func experimentalTCPReleaseSlice(release func()) []func() {
	if release == nil {
		return nil
	}
	return []func(){release}
}

func releaseExperimentalTCPFrame(frame dataplane.ExperimentalTCPFrame) {
	if frame.Release != nil {
		frame.Release()
	}
}

func clearExperimentalTCPFrames(frames []dataplane.ExperimentalTCPFrame) {
	for i := range frames {
		frames[i] = dataplane.ExperimentalTCPFrame{}
	}
}

func releaseExperimentalTCPBatch(batch experimentalTCPPacketBatch) {
	for _, release := range batch.releases {
		if release != nil {
			release()
		}
	}
	releaseExperimentalTCPPacketBatchOwner(batch)
}

func (session *session) pruneReassemblyLocked(now time.Time) {
	var expiredAssemblies uint64
	var expiredFragments uint64
	for baseSeq, assembly := range session.reassembly {
		if now.Sub(assembly.createdAt) > experimentalTCPReassemblyTTL {
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
		releaseExperimentalTCPBatch(session.recvPending)
		session.recvPending = experimentalTCPPacketBatch{}
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
			releaseExperimentalTCPBatch(batch)
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
	extra := map[string]uint64{
		experimentalTCPStatFragmentedPacketsSent:     session.fragmentedPacketsSent.Load(),
		experimentalTCPStatFragmentsSent:             session.fragmentsSent.Load(),
		experimentalTCPStatFragmentsReceived:         session.fragmentsReceived.Load(),
		experimentalTCPStatFragmentedPacketsReceived: session.fragmentedPacketsReceived.Load(),
		experimentalTCPStatFragmentsReassembled:      session.fragmentsReassembled.Load(),
		experimentalTCPStatFragmentDuplicates:        session.fragmentDuplicates.Load(),
		experimentalTCPStatFragmentExpiredAssemblies: session.fragmentExpiredAssemblies.Load(),
		experimentalTCPStatFragmentExpiredFragments:  session.fragmentExpiredFragments.Load(),
		experimentalTCPStatFragmentMismatches:        session.fragmentMismatches.Load(),
		experimentalTCPStatFragmentRejects:           session.fragmentRejects.Load(),
		experimentalTCPStatFragmentPayloadSize:       uint64(session.fragmentPayloadSize()),
		experimentalTCPStatTIXBExpandedPackets:       session.tixbExpandedPackets.Load(),
		experimentalTCPStatTIXBExpandedItems:         session.tixbExpandedItems.Load(),
	}
	session.recvMu.Lock()
	extra[experimentalTCPStatFragmentAssembliesCurrent] = uint64(len(session.reassembly))
	session.recvMu.Unlock()
	return extra
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
		return 0, fmt.Errorf("generate experimental_tcp flow id: %w", err)
	}
	flowID := binary.BigEndian.Uint64(buf[:])
	if flowID == 0 {
		flowID = 1
	}
	return flowID, nil
}

func fragmentCount(packetLen int) int {
	return fragmentCountForSize(packetLen, experimentalTCPFragmentPayloadSize)
}

func fragmentCountForSize(packetLen int, payloadSize int) int {
	if payloadSize <= 0 {
		payloadSize = experimentalTCPFragmentPayloadSize
	}
	if packetLen <= payloadSize {
		return 1
	}
	return (packetLen + payloadSize - 1) / payloadSize
}

func (session *session) fragmentPayloadSize() int {
	configured := session.configuredFragmentPayload
	if configured == 0 {
		configured = experimentalTCPFragmentPayloadSizeForPlacement(session.cryptoPlacement, session.cryptoOffloaded)
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
	maxPacket := payloadSize * experimentalTCPMaxFragments
	if payloadSize < 1 {
		return 1
	}
	if session.kernelCryptoSealBeforeFragment() {
		maxPacket -= experimentalTCPSecureFrameOverhead
	}
	if maxPacket < 1 {
		return 1
	}
	if configured := experimentalTCPConfiguredMaxPacketSize(); configured > 0 && maxPacket > configured {
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
	if sizer, ok := session.provider.(dataplane.ExperimentalTCPPayloadSizer); ok {
		if maxSize, err := sizer.ExperimentalTCPPayloadMax(context.Background(), session.cryptoPlacement, session.cryptoOffloaded); err == nil && maxSize > 0 {
			if experimentalTCPAutoFragmentPayloadEnabled() && payloadSize < maxSize {
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

func experimentalTCPConfiguredMaxPacketSize() int {
	const minSize = 576
	value := strings.TrimSpace(os.Getenv("TRUSTIX_EXPERIMENTAL_TCP_MAX_PACKET_SIZE"))
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

func experimentalTCPFragmentPayloadSizeForPlacement(placement dataplane.CryptoPlacement, offloaded bool) int {
	if placement == dataplane.CryptoPlacementKernel || offloaded {
		return experimentalTCPConfiguredFragmentPayloadSize(experimentalTCPKernelFragmentPayloadMax)
	}
	return experimentalTCPConfiguredFragmentPayloadSize(experimentalTCPFragmentPayloadMax)
}

func experimentalTCPConfiguredFragmentPayloadSize(maxSize int) int {
	const (
		defaultSize = experimentalTCPFragmentPayloadSize
		minSize     = 576
	)
	value := strings.TrimSpace(os.Getenv("TRUSTIX_EXPERIMENTAL_TCP_FRAGMENT_PAYLOAD_SIZE"))
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
		if experimentalTCPUserspaceCryptoPayloadHint < maxSize {
			return experimentalTCPUserspaceCryptoPayloadHint
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

func experimentalTCPAutoFragmentPayloadEnabled() bool {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_EXPERIMENTAL_TCP_FRAGMENT_PAYLOAD_SIZE"))
	return value == "" && envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_AUTO_FRAGMENT_PAYLOAD",
		"TRUSTIX_EXPERIMENTAL_TCP_FRAGMENT_PAYLOAD_AUTO_MAX",
	)
}

func experimentalTCPKernelSealBeforeFragmentEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_EXPERIMENTAL_TCP_KERNEL_SEAL_BEFORE_FRAGMENT"))) {
	case "", "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}

func experimentalTCPKernelSealBeforeFragmentWireMaxEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_EXPERIMENTAL_TCP_KERNEL_SEAL_BEFORE_FRAGMENT_WIRE_MAX"))) {
	case "0", "false", "no", "off", "disabled":
		return false
	case "1", "true", "yes", "on", "enabled", "force":
		return true
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_EXPERIMENTAL_TCP_KERNEL_SEAL_BEFORE_FRAGMENT_MAX_WIRE"))) {
	case "0", "false", "no", "off", "disabled":
		return false
	case "1", "true", "yes", "on", "enabled", "force":
		return true
	}
	return false
}
