package dataplane

import (
	"context"
	"net/netip"
	"sync"
)

type NoopManager struct {
	snapshot Snapshot
	attached bool
	spec     AttachSpec
}

func NewNoopManager() *NoopManager {
	return &NoopManager{}
}

func (manager *NoopManager) Load(ctx context.Context) error {
	return ctx.Err()
}

func (manager *NoopManager) Attach(ctx context.Context, spec AttachSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if spec.LANAttachMode == "" {
		spec.LANAttachMode = "managed"
	}
	manager.spec = spec
	manager.attached = true
	return nil
}

func (manager *NoopManager) ApplySnapshot(ctx context.Context, snapshot Snapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	manager.snapshot = snapshot
	return nil
}

func (manager *NoopManager) ApplyNATSnapshot(ctx context.Context, snapshot *NATSnapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	manager.snapshot.NAT = snapshot
	return nil
}

func (manager *NoopManager) Stats(ctx context.Context) (Stats, error) {
	if err := ctx.Err(); err != nil {
		return Stats{}, err
	}
	return Stats{
		Epoch:         manager.snapshot.Epoch,
		Mode:          "noop",
		Attached:      manager.attached,
		LANIface:      manager.spec.LANIface,
		LANAttachMode: manager.spec.LANAttachMode,
		LANs:          noopLANStats(manager.spec),
	}, nil
}

func noopLANStats(spec AttachSpec) []LANStats {
	lans := spec.LANs
	if len(lans) == 0 && spec.LANIface != "" {
		lans = []LANAttachSpec{{
			Iface:            spec.LANIface,
			UnderlayIface:    spec.UnderlayIface,
			Gateway:          spec.Gateway,
			LANAttachMode:    spec.LANAttachMode,
			ManageQdisc:      spec.ManageQdisc,
			ManageAddress:    spec.ManageAddress,
			ManageForwarding: spec.ManageForwarding,
			ManageRPFilter:   spec.ManageRPFilter,
			ManagedMTU:       spec.ManagedMTU,
		}}
	}
	if len(lans) == 0 {
		return nil
	}
	out := make([]LANStats, 0, len(lans))
	for _, lan := range lans {
		out = append(out, LANStats{
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
		})
	}
	return out
}

func (manager *NoopManager) BPFMapSnapshot(ctx context.Context) (BPFMapSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return BPFMapSnapshot{}, err
	}
	return BPFMapSnapshot{}, ErrUnsupported
}

func (manager *NoopManager) Snapshot() Snapshot {
	return manager.snapshot
}

func (manager *NoopManager) Detach(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	manager.attached = false
	return nil
}

func (manager *NoopManager) Cleanup(ctx context.Context, spec AttachSpec) error {
	return manager.Detach(ctx)
}

func (manager *NoopManager) PlanCleanup(ctx context.Context, spec AttachSpec) (CleanupPlan, error) {
	if err := ctx.Err(); err != nil {
		return CleanupPlan{}, err
	}
	return CleanupPlan{
		Spec: spec,
		Steps: []CleanupStep{{
			Action: "noop_detach",
			Detail: "noop dataplane has no kernel state to remove",
		}},
	}, nil
}

func (manager *NoopManager) Capture(ctx context.Context, limit int) ([]CaptureEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, nil
}

func (manager *NoopManager) SubscribeCapture(ctx context.Context, buffer int) (CaptureSubscription, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	events := make(chan CaptureEvent)
	close(events)
	batches := make(chan []CaptureEvent)
	close(batches)
	return &noopCaptureSubscription{events: events, batches: batches}, nil
}

func (manager *NoopManager) InjectPacket(ctx context.Context, packet []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrUnsupported
}

func (manager *NoopManager) InjectPackets(ctx context.Context, packets [][]byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrUnsupported
}

func (manager *NoopManager) InjectLANPacket(ctx context.Context, packet []byte, destination netip.Addr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrUnsupported
}

func (manager *NoopManager) InjectLocalPacket(ctx context.Context, packet []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrUnsupported
}

func (manager *NoopManager) InjectNATPacket(ctx context.Context, packet []byte, destination netip.Addr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrUnsupported
}

func (manager *NoopManager) SyncLocalVIPs(ctx context.Context, vips []LocalVIP) error {
	return ctx.Err()
}

func (manager *NoopManager) TIXTCPStatus(ctx context.Context) (TIXTCPStatus, error) {
	if err := ctx.Err(); err != nil {
		return TIXTCPStatus{}, err
	}
	return TIXTCPStatus{
		Available:          false,
		Provider:           "none",
		FastPath:           false,
		UserspaceCrypto:    false,
		KernelCrypto:       false,
		KernelCryptoReason: "noop dataplane has no TC/XDP fast path",
		CryptoFallback: CryptoFallbackStatus{Selected: CryptoFallbackUserspaceAEAD, Chain: []CryptoFallbackStep{
			{Name: CryptoFallbackFullKernelModuleDatapath, Ready: false, Placement: "kernel", Layer: CryptoFallbackLayerKernelModule, Reason: "noop dataplane cannot drive the TrustIX kernel module datapath"},
			{Name: CryptoFallbackGSOSKBModuleHelpers, Ready: false, Placement: "kernel", Layer: CryptoFallbackLayerKernelModule, Reason: "noop dataplane cannot drive TrustIX skb/GSO module helpers"},
			{Name: CryptoFallbackBPFProgRunFrame, Ready: false, Placement: "kernel", Layer: CryptoFallbackLayerBPFProgRun, Reason: "noop dataplane has no BPF crypto provider"},
			{Name: CryptoFallbackKOAEADDevice, Ready: false, Placement: "kernel", Layer: CryptoFallbackLayerDevice, Reason: "noop dataplane cannot drive the AEAD module device"},
			{Name: CryptoFallbackUserspaceAEAD, Ready: true, Placement: "userspace", Layer: CryptoFallbackLayerUserspace},
		}},
		Reinject:          false,
		RawSocketFallback: false,
		PreferredCrypto:   CryptoPlacementUserspace,
		SupportedCrypto:   []CryptoPlacement{CryptoPlacementUserspace},
		Notes:             []string{"tix_tcp contract is available; dataplane implementation is not active"},
	}, nil
}

func (manager *NoopManager) KernelTransportStatus(ctx context.Context) (KernelTransportStatus, error) {
	if err := ctx.Err(); err != nil {
		return KernelTransportStatus{}, err
	}
	return KernelTransportStatus{
		Mode:      KernelTransportModeDisabled,
		Available: false,
		Provider:  "none",
		Protocols: []KernelTransportProtocol{
			{
				Protocol:          "tix_tcp",
				Available:         false,
				CapabilityReady:   false,
				Placement:         "userspace",
				Carrier:           "tcp-shaped-ipv4",
				Contract:          "trustix-tix-tcp-frame-v1",
				UserspaceFallback: true,
				Reason:            "noop dataplane has no TC/XDP or AF_XDP transport provider",
			},
			{
				Protocol:          "udp",
				Available:         false,
				CapabilityReady:   false,
				Placement:         "userspace",
				Carrier:           "udp-ipv4",
				Contract:          "trustix-kernel-udp-frame-v1",
				UserspaceFallback: true,
				Reason:            "UDP kernel transport provider is not implemented for noop dataplane",
			},
			{
				Protocol:          "quic",
				Available:         false,
				Placement:         "userspace",
				Contract:          "standard_quic_userspace",
				UserspaceFallback: true,
				Reason:            "standard QUIC remains a userspace transport; kernel plane can only carry fixed TrustIX frame contracts",
			},
			{
				Protocol:          "gre",
				Available:         false,
				CapabilityReady:   false,
				Placement:         "kernel",
				Carrier:           "gre-netdev+inner-udp",
				Contract:          "trustix-kernel-tunnel-carrier-v1",
				UserspaceFallback: false,
				RequiredConfig:    []string{"local", "remote", "local_carrier", "remote_carrier", "mtu"},
				Reason:            "GRE kernel tunnel transport is not implemented for noop dataplane",
			},
			{
				Protocol:          "ipip",
				Available:         false,
				CapabilityReady:   false,
				Placement:         "kernel",
				Carrier:           "ipip-netdev+inner-udp",
				Contract:          "trustix-kernel-tunnel-carrier-v1",
				UserspaceFallback: false,
				RequiredConfig:    []string{"local", "remote", "local_carrier", "remote_carrier", "mtu"},
				Reason:            "IPIP kernel tunnel transport is not implemented for noop dataplane",
			},
		},
		Notes: []string{"noop dataplane cannot move transport TX/RX into kernel"},
	}, nil
}

func (manager *NoopManager) KernelUDPStatus(ctx context.Context) (KernelUDPStatus, error) {
	if err := ctx.Err(); err != nil {
		return KernelUDPStatus{}, err
	}
	return KernelUDPStatus{
		Available:       false,
		Provider:        "none",
		FastPath:        false,
		UserspaceCrypto: false,
		CryptoFallback: CryptoFallbackStatus{Selected: CryptoFallbackUserspaceAEAD, Chain: []CryptoFallbackStep{
			{Name: CryptoFallbackFullKernelModuleDatapath, Ready: false, Placement: "kernel", Layer: CryptoFallbackLayerKernelModule, Reason: "noop dataplane cannot drive the TrustIX kernel module datapath"},
			{Name: CryptoFallbackGSOSKBModuleHelpers, Ready: false, Placement: "kernel", Layer: CryptoFallbackLayerKernelModule, Reason: "noop dataplane cannot drive TrustIX skb/GSO module helpers"},
			{Name: CryptoFallbackTCBPFDirect, Ready: false, Placement: "kernel", Layer: CryptoFallbackLayerTC, Reason: "noop dataplane has no TC/BPF provider"},
			{Name: CryptoFallbackKOAEADDevice, Ready: false, Placement: "kernel", Layer: CryptoFallbackLayerDevice, Reason: "noop dataplane cannot drive the AEAD module device"},
			{Name: CryptoFallbackUserspaceAEAD, Ready: true, Placement: "userspace", Layer: CryptoFallbackLayerUserspace},
		}},
		Reinject:        false,
		PreferredCrypto: CryptoPlacementUserspace,
		SupportedCrypto: []CryptoPlacement{CryptoPlacementUserspace},
		Notes:           []string{"noop dataplane has no UDP kernel transport provider"},
	}, nil
}

func (manager *NoopManager) InstallKernelUDPFlows(ctx context.Context, flows []KernelUDPFlow) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrUnsupported
}

func (manager *NoopManager) DeleteKernelUDPFlows(ctx context.Context, flowIDs []uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrUnsupported
}

func (manager *NoopManager) KernelUDPFlow(ctx context.Context, flowID uint64) (KernelUDPFlow, bool, error) {
	if err := ctx.Err(); err != nil {
		return KernelUDPFlow{}, false, err
	}
	return KernelUDPFlow{}, false, ErrUnsupported
}

func (manager *NoopManager) KernelUDPFlows(ctx context.Context) ([]KernelUDPFlow, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, ErrUnsupported
}

func (manager *NoopManager) SubmitKernelUDPFrame(ctx context.Context, frame KernelUDPFrame) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrUnsupported
}

func (manager *NoopManager) SubscribeKernelUDP(ctx context.Context, buffer int) (KernelUDPSubscription, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, ErrUnsupported
}

func (manager *NoopManager) InstallTIXTCPFlows(ctx context.Context, flows []TIXTCPFlow) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrUnsupported
}

func (manager *NoopManager) DeleteTIXTCPFlows(ctx context.Context, flowIDs []uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrUnsupported
}

func (manager *NoopManager) TIXTCPFlow(ctx context.Context, flowID uint64) (TIXTCPFlow, bool, error) {
	if err := ctx.Err(); err != nil {
		return TIXTCPFlow{}, false, err
	}
	return TIXTCPFlow{}, false, ErrUnsupported
}

func (manager *NoopManager) SubmitTIXTCPFrame(ctx context.Context, frame TIXTCPFrame) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrUnsupported
}

func (manager *NoopManager) SubscribeTIXTCP(ctx context.Context, buffer int) (TIXTCPSubscription, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, ErrUnsupported
}

type noopCaptureSubscription struct {
	once    sync.Once
	events  <-chan CaptureEvent
	batches <-chan []CaptureEvent
}

func (subscription *noopCaptureSubscription) Events() <-chan CaptureEvent {
	return subscription.events
}

func (subscription *noopCaptureSubscription) BatchEvents() <-chan []CaptureEvent {
	return subscription.batches
}

func (subscription *noopCaptureSubscription) Close() error {
	subscription.once.Do(func() {})
	return nil
}
