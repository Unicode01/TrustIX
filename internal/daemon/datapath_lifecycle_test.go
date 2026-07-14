package daemon

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/routing"
	rstate "trustix.local/trustix/internal/runtime"
	"trustix.local/trustix/internal/transport"
	securetransport "trustix.local/trustix/internal/transport/secure"
	tixtcptransport "trustix.local/trustix/internal/transport/tixtcp"
	udptransport "trustix.local/trustix/internal/transport/udp"
)

func TestShutdownRuntimeClosesCaptureForwarderWithoutParentCancel(t *testing.T) {
	manager := &captureCountingManager{}
	daemon := &Daemon{
		dataplane:    manager,
		dataSessions: make(map[dataSessionKey]transport.Session),
	}

	if _, err := daemon.startDataPath(context.Background()); err != nil {
		t.Fatalf("start data path: %v", err)
	}
	if status := daemon.dataPathStatus(); !status.CaptureForwarderActive {
		t.Fatal("capture forwarder should be active after startDataPath")
	}
	subscription := manager.subscription
	if subscription == nil {
		t.Fatal("capture subscription was not started")
	}

	if err := daemon.shutdownRuntime(nil, false); err != nil {
		t.Fatalf("shutdown runtime: %v", err)
	}
	if status := daemon.dataPathStatus(); status.CaptureForwarderActive {
		t.Fatal("capture forwarder should be inactive after shutdown")
	}
	waitForCaptureSubscriptionClose(t, subscription)
	if got := subscription.closes.Load(); got != 1 {
		t.Fatalf("capture subscription closes = %d, want 1", got)
	}
}

func TestCloseDataPathKeepsCaptureForwarderForHotReload(t *testing.T) {
	manager := &captureCountingManager{}
	daemon := &Daemon{
		dataplane:    manager,
		dataSessions: make(map[dataSessionKey]transport.Session),
	}

	if _, err := daemon.startDataPath(context.Background()); err != nil {
		t.Fatalf("start data path: %v", err)
	}
	subscription := manager.subscription
	if subscription == nil {
		t.Fatal("capture subscription was not started")
	}

	daemon.closeDataPath()
	if status := daemon.dataPathStatus(); !status.CaptureForwarderActive {
		t.Fatal("closeDataPath should keep capture forwarder active for hot reload")
	}
	select {
	case <-subscription.closed:
		t.Fatal("closeDataPath closed capture subscription; hot reload would stop packet capture")
	default:
	}

	daemon.closeCaptureForwarder()
	if status := daemon.dataPathStatus(); status.CaptureForwarderActive {
		t.Fatal("capture forwarder should be inactive after closeCaptureForwarder")
	}
	waitForCaptureSubscriptionClose(t, subscription)
}

func TestStartDataPathKeepsCaptureForwarderForKernelUDPPlaintextDirectOnlyWithAFXDP(t *testing.T) {
	manager := &captureCountingManager{}
	daemon := &Daemon{
		dataplane:    manager,
		dataSessions: make(map[dataSessionKey]transport.Session),
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
				Encryption:      securetransport.EncryptionPlaintext,
			},
		},
	}

	if _, err := daemon.startDataPath(context.Background()); err != nil {
		t.Fatalf("start data path: %v", err)
	}
	if manager.subscription == nil {
		t.Fatal("capture subscription should start while AF_XDP remains the kernel_udp provider")
	}
	status := daemon.dataPathStatus()
	if !status.CaptureForwarderActive {
		t.Fatal("capture forwarder should remain active until TC-only provider is explicitly selected")
	}
	if status.CaptureForwarderSuppressed {
		t.Fatal("capture forwarder should not report suppressed for AF_XDP-backed direct-only")
	}
	if status.CaptureForwarderSuppressedReason != "" {
		t.Fatalf("capture forwarder suppression reason = %q, want empty", status.CaptureForwarderSuppressedReason)
	}
	if got := dataPathDoctorStatus(status); got != "warn" {
		t.Fatalf("doctor status = %q, want warn for missing listeners", got)
	}
	status.Listeners = []dataPathListenerStatus{{Endpoint: "udp-a", Transport: string(transport.ProtocolUDP), Listen: "127.0.0.1:17041"}}
	if got := dataPathDoctorStatus(status); got != "ok" {
		t.Fatalf("doctor status with listener = %q, want ok", got)
	}
}

func TestStartDataPathSuppressesCaptureForwarderForKernelUDPTCOnlyProvider(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")
	manager := &captureCountingManager{}
	daemon := &Daemon{
		dataplane:    manager,
		dataSessions: make(map[dataSessionKey]transport.Session),
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
				Encryption:      securetransport.EncryptionPlaintext,
			},
		},
	}

	if _, err := daemon.startDataPath(context.Background()); err != nil {
		t.Fatalf("start data path: %v", err)
	}
	if manager.subscription != nil {
		t.Fatal("capture subscription should not start when TC-only provider is explicitly selected")
	}
	status := daemon.dataPathStatus()
	if status.CaptureForwarderActive {
		t.Fatal("capture forwarder should be inactive when TC-only provider suppresses userspace fallback")
	}
	if !status.CaptureForwarderSuppressed {
		t.Fatal("capture forwarder should report suppressed")
	}
	if status.CaptureForwarderSuppressedReason == "" {
		t.Fatal("capture forwarder suppression reason should be reported")
	}
}

func TestStartDataPathSuppressesCaptureForwarderForMigratedFullPlaintextUDP(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "0")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")
	manager := &captureCountingManager{}
	daemon := &Daemon{
		dataplane:    manager,
		dataSessions: make(map[dataSessionKey]transport.Session),
		desired: config.Desired{
			Endpoints: []config.EndpointConfig{{
				Name:      "udp-a",
				Transport: string(transport.ProtocolUDP),
				Enabled:   true,
			}},
			TransportPolicy: config.TransportPolicyConfig{
				Encryption: securetransport.EncryptionPlaintext,
				Candidates: []core.EndpointID{"udp-a"},
			},
			KernelModules: config.KernelModulesConfig{
				CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
			},
		},
	}

	if _, err := daemon.startDataPath(context.Background()); err != nil {
		t.Fatalf("start data path: %v", err)
	}
	if manager.subscription != nil {
		t.Fatal("capture subscription should not start after full plaintext UDP migrates to TC-only provider")
	}
	status := daemon.dataPathStatus()
	if status.CaptureForwarderActive {
		t.Fatal("capture forwarder should be inactive after full plaintext UDP migrates to TC-only provider")
	}
	if !status.CaptureForwarderSuppressed {
		t.Fatal("capture forwarder should report suppressed")
	}
	if status.CaptureForwarderSuppressedReason == "" {
		t.Fatal("capture forwarder suppression reason should be reported")
	}
}

func TestStartDataPathSuppressesCaptureForwarderForFullPlaintextDatapath(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")
	manager := &captureCountingManager{}
	daemon := &Daemon{
		dataplane:    manager,
		dataSessions: make(map[dataSessionKey]transport.Session),
		desired: config.Desired{
			KernelModules: config.KernelModulesConfig{
				CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
			},
		},
	}

	if _, err := daemon.startDataPath(context.Background()); err != nil {
		t.Fatalf("start data path: %v", err)
	}
	if manager.subscription != nil {
		t.Fatal("capture subscription should not start when full plaintext datapath owns LAN TX/RX")
	}
	status := daemon.dataPathStatus()
	if status.CaptureForwarderActive {
		t.Fatal("capture forwarder should be inactive for full plaintext datapath")
	}
	if !status.CaptureForwarderSuppressed {
		t.Fatal("capture forwarder should report suppressed for full plaintext datapath")
	}
	if !strings.Contains(status.CaptureForwarderSuppressedReason, "full plaintext") {
		t.Fatalf("suppression reason = %q, want full plaintext", status.CaptureForwarderSuppressedReason)
	}
}

func TestStartDataPathFullPlaintextWarmsKernelUDPRouteWithAutoKernelTransport(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_PLAINTEXT_WARMUP_RETRY_DELAY", "1ms")
	t.Setenv("TRUSTIX_KERNEL_UDP_PLAINTEXT_WARMUP_TIMEOUT", "1s")
	manager := &captureCountingManager{
		kernelUDPStatus: &dataplane.KernelUDPStatus{
			Available:       true,
			Provider:        "test",
			FastPath:        true,
			UserspaceCrypto: true,
			PreferredCrypto: dataplane.CryptoPlacementUserspace,
			SupportedCrypto: []dataplane.CryptoPlacement{dataplane.CryptoPlacementUserspace},
			Reinject:        true,
		},
	}
	registry := transport.NewRegistry()
	if err := registry.Register(udptransport.NewWithKernelProvider(manager, udptransport.Options{
		CryptoPlacement: func() dataplane.CryptoPlacement { return dataplane.CryptoPlacementUserspace },
		KernelTransport: func() dataplane.KernelTransportMode {
			return dataplane.KernelTransportModeAuto
		},
		Encryption: func() string { return securetransport.EncryptionPlaintext },
	})); err != nil {
		t.Fatalf("register udp transport: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	daemon := &Daemon{
		dataplane:        manager,
		transports:       registry,
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-a"},
			KernelModules: config.KernelModulesConfig{
				CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
			},
			Peers: []config.PeerConfig{{
				ID:     "ix-b",
				Domain: "lab.local",
				Endpoints: []config.EndpointConfig{{
					Name:      "udp-b",
					Address:   "127.0.0.1:17042",
					Transport: string(transport.ProtocolUDP),
					Enabled:   true,
				}},
			}},
			Routes: []config.RouteConfig{{
				Prefix:  "10.0.1.0/24",
				NextHop: "ix-b",
				Metric:  100,
			}},
			TransportPolicy: config.TransportPolicyConfig{
				Encryption: securetransport.EncryptionPlaintext,
				Datapath:   config.TransportDatapathKernelModule,
				KernelTransport: config.KernelTransportPolicyConfig{
					Mode: string(dataplane.KernelTransportModeAuto),
				},
			},
		},
	}
	defer daemon.closeDataSessions()

	if _, err := daemon.startDataPath(ctx); err != nil {
		t.Fatalf("start data path: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if manager.kernelUDPFlows.Load() == 1 {
			daemon.dataMu.Lock()
			sessions := len(daemon.dataSessions)
			daemon.dataMu.Unlock()
			if sessions == 1 {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	daemon.dataMu.Lock()
	sessions := len(daemon.dataSessions)
	daemon.dataMu.Unlock()
	t.Fatalf("full plaintext warmup installed flows=%d sessions=%d, want 1/1", manager.kernelUDPFlows.Load(), sessions)
}

func TestStartDataPathSecureKernelUDPWarmsSecureDirectRoute(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_PLAINTEXT_WARMUP_RETRY_DELAY", "1ms")
	t.Setenv("TRUSTIX_KERNEL_UDP_PLAINTEXT_WARMUP_TIMEOUT", "1s")
	manager := &captureCountingManager{
		kernelUDPStatus: &dataplane.KernelUDPStatus{
			Available:       true,
			Provider:        "test",
			FastPath:        true,
			UserspaceCrypto: true,
			KernelCrypto:    true,
			PreferredCrypto: dataplane.CryptoPlacementKernel,
			SupportedCrypto: []dataplane.CryptoPlacement{dataplane.CryptoPlacementUserspace, dataplane.CryptoPlacementKernel},
			Reinject:        true,
		},
	}
	registry := transport.NewRegistry()
	if err := registry.Register(udptransport.NewWithKernelProvider(manager, udptransport.Options{
		CryptoPlacement: func() dataplane.CryptoPlacement { return dataplane.CryptoPlacementKernel },
		KernelTransport: func() dataplane.KernelTransportMode {
			return dataplane.KernelTransportModeRequireKernel
		},
		Encryption: func() string { return securetransport.EncryptionSecure },
	})); err != nil {
		t.Fatalf("register udp transport: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	daemon := &Daemon{
		dataplane:        manager,
		transports:       registry,
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-a"},
			Peers: []config.PeerConfig{{
				ID:     "ix-b",
				Domain: "lab.local",
				Endpoints: []config.EndpointConfig{{
					Name:      "udp-b",
					Address:   "127.0.0.1:17042",
					Transport: string(transport.ProtocolUDP),
					Enabled:   true,
				}},
			}},
			Routes: []config.RouteConfig{{
				Prefix:  "10.0.1.0/24",
				NextHop: "ix-b",
				Metric:  100,
			}},
			TransportPolicy: config.TransportPolicyConfig{
				Profile:         config.TransportProfilePerformance,
				Datapath:        config.TransportDatapathTCXDP,
				Encryption:      securetransport.EncryptionSecure,
				CryptoPlacement: string(dataplane.CryptoPlacementKernel),
				KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
			},
		},
	}
	defer daemon.closeDataSessions()

	if _, err := daemon.startDataPath(ctx); err != nil {
		t.Fatalf("start data path: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if manager.kernelUDPFlows.Load() == 1 {
			daemon.dataMu.Lock()
			sessions := len(daemon.dataSessions)
			daemon.dataMu.Unlock()
			if sessions == 1 {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	daemon.dataMu.Lock()
	sessions := len(daemon.dataSessions)
	daemon.dataMu.Unlock()
	t.Fatalf("secure kernel_udp warmup installed flows=%d sessions=%d, want 1/1", manager.kernelUDPFlows.Load(), sessions)
}

func TestStartDataPathKeepsCaptureForwarderForSecureKernelUDPTCOnlyProviderByDefault(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")
	manager := &captureCountingManager{}
	daemon := &Daemon{
		dataplane:    manager,
		dataSessions: make(map[dataSessionKey]transport.Session),
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
				Encryption:      securetransport.EncryptionSecure,
				CryptoPlacement: string(dataplane.CryptoPlacementKernel),
			},
		},
	}

	if _, err := daemon.startDataPath(context.Background()); err != nil {
		t.Fatalf("start data path: %v", err)
	}
	if manager.subscription == nil {
		t.Fatal("secure UDP should keep capture fallback until secure direct-only is explicitly enabled")
	}
	status := daemon.dataPathStatus()
	if !status.CaptureForwarderActive {
		t.Fatal("capture forwarder should stay active for secure UDP by default")
	}
	if status.CaptureForwarderSuppressed {
		t.Fatal("secure UDP should not report capture forwarder suppressed by default")
	}
}

func TestStartDataPathKeepsCaptureForwarderForTIXTCPTCOnlyProvider(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")
	manager := &captureCountingManager{}
	daemon := &Daemon{
		dataplane:    manager,
		dataSessions: make(map[dataSessionKey]transport.Session),
		desired: config.Desired{
			Endpoints: []config.EndpointConfig{{
				Name:      "exp-a",
				Transport: string(transport.ProtocolTIXTCP),
				Enabled:   true,
			}},
			TransportPolicy: config.TransportPolicyConfig{
				KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
				Encryption:      securetransport.EncryptionPlaintext,
				Candidates:      []core.EndpointID{"exp-a"},
			},
		},
	}

	if _, err := daemon.startDataPath(context.Background()); err != nil {
		t.Fatalf("start data path: %v", err)
	}
	if manager.subscription == nil {
		t.Fatal("capture subscription should start for tix_tcp userspace fallback")
	}
	status := daemon.dataPathStatus()
	if !status.CaptureForwarderActive {
		t.Fatal("capture forwarder should stay active for tix_tcp userspace fallback")
	}
	if status.CaptureForwarderSuppressed {
		t.Fatal("capture forwarder should not report suppressed for tix_tcp fallback")
	}
}

func TestStartDataPathDegradesTIXTCPKernelListenerUnavailable(t *testing.T) {
	registry := transport.NewRegistry()
	if err := registry.Register(&failingListenTransport{
		name: transport.ProtocolTIXTCP,
		err:  fmt.Errorf("tix_tcp TC/XDP reinject is unavailable"),
	}); err != nil {
		t.Fatalf("register transport: %v", err)
	}
	daemon := &Daemon{
		dataplane:    &captureCountingManager{},
		transports:   registry,
		dataSessions: make(map[dataSessionKey]transport.Session),
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-a"},
			Endpoints: []config.EndpointConfig{{
				Name:      "exp-a",
				Mode:      config.EndpointModePassive,
				Listen:    "127.0.0.1:17043",
				Transport: string(transport.ProtocolTIXTCP),
				Enabled:   true,
			}},
			TransportPolicy: config.TransportPolicyConfig{
				KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeAuto)},
			},
		},
	}

	if _, err := daemon.startDataPath(context.Background()); err != nil {
		t.Fatalf("start data path: %v", err)
	}
	state, ok := daemon.endpointStateFor("ix-a", config.EndpointConfig{
		Name:      "exp-a",
		Address:   "127.0.0.1:17043",
		Transport: string(transport.ProtocolTIXTCP),
	})
	if !ok {
		t.Fatal("local tix_tcp listener failure was not recorded")
	}
	if state.Health != rstate.EndpointDown {
		t.Fatalf("endpoint health = %q, want down", state.Health)
	}
	if !strings.Contains(state.Error, "TC/XDP reinject is unavailable") {
		t.Fatalf("endpoint error = %q", state.Error)
	}
}

func TestStartDataPathRequiresTIXTCPKernelListener(t *testing.T) {
	registry := transport.NewRegistry()
	if err := registry.Register(&failingListenTransport{
		name: transport.ProtocolTIXTCP,
		err:  fmt.Errorf("tix_tcp TC/XDP reinject is unavailable"),
	}); err != nil {
		t.Fatalf("register transport: %v", err)
	}
	daemon := &Daemon{
		dataplane:    &captureCountingManager{},
		transports:   registry,
		dataSessions: make(map[dataSessionKey]transport.Session),
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-a"},
			Endpoints: []config.EndpointConfig{{
				Name:      "exp-a",
				Mode:      config.EndpointModePassive,
				Listen:    "127.0.0.1:17043",
				Transport: string(transport.ProtocolTIXTCP),
				Enabled:   true,
			}},
			TransportPolicy: config.TransportPolicyConfig{
				KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
			},
		},
	}

	if _, err := daemon.startDataPath(context.Background()); err == nil {
		t.Fatal("start data path succeeded with require_kernel listener failure")
	}
}

func TestWarmKernelPlaintextDirectSessionsWarmsTIXTCPPolicy(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "1")
	manager := &captureCountingManager{}
	registry := transport.NewRegistry()
	if err := registry.Register(tixtcptransport.New(manager)); err != nil {
		t.Fatalf("register tix_tcp transport: %v", err)
	}
	daemon := &Daemon{
		dataplane:        manager,
		transports:       registry,
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-a"},
			Endpoints: []config.EndpointConfig{{
				Name:      "exp-a",
				Transport: string(transport.ProtocolTIXTCP),
				Enabled:   true,
			}},
			Peers: []config.PeerConfig{{
				ID:     "ix-b",
				Domain: "lab.local",
				Endpoints: []config.EndpointConfig{{
					Name:      "exp-a",
					Address:   "127.0.0.1:17042",
					Transport: string(transport.ProtocolTIXTCP),
					Enabled:   true,
				}},
			}},
			Routes: []config.RouteConfig{{
				Prefix:  "10.0.1.0/24",
				NextHop: "ix-b",
				Metric:  100,
			}},
			TransportPolicy: config.TransportPolicyConfig{
				KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
				Encryption:      securetransport.EncryptionPlaintext,
				Candidates:      []core.EndpointID{"exp-a"},
			},
		},
	}
	defer daemon.closeDataSessions()

	if err := daemon.warmKernelPlaintextDirectSessions(context.Background()); err != nil {
		t.Fatalf("warm tix_tcp plaintext policy: %v", err)
	}
	if got := manager.tixTCPFlows.Load(); got != 1 {
		t.Fatalf("tix_tcp flow installs = %d, want 1", got)
	}
	if got := len(daemon.dataSessions); got != 1 {
		t.Fatalf("sessions = %d, want 1", got)
	}
}

func TestWarmKernelSecureDirectSessionsWarmsTIXTCPPolicy(t *testing.T) {
	manager := &captureCountingManager{}
	registry := transport.NewRegistry()
	if err := registry.Register(tixtcptransport.New(manager)); err != nil {
		t.Fatalf("register tix_tcp transport: %v", err)
	}
	daemon := &Daemon{
		dataplane:        manager,
		transports:       registry,
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-a"},
			Endpoints: []config.EndpointConfig{{
				Name:      "exp-a",
				Transport: string(transport.ProtocolTIXTCP),
				Enabled:   true,
			}},
			Peers: []config.PeerConfig{{
				ID:     "ix-b",
				Domain: "lab.local",
				Endpoints: []config.EndpointConfig{{
					Name:      "exp-a",
					Address:   "127.0.0.1:17042",
					Transport: string(transport.ProtocolTIXTCP),
					Enabled:   true,
				}},
			}},
			Routes: []config.RouteConfig{{
				Prefix:  "10.0.1.0/24",
				NextHop: "ix-b",
				Metric:  100,
			}},
			TransportPolicy: config.TransportPolicyConfig{
				KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
				Encryption:      securetransport.EncryptionSecure,
				CryptoPlacement: string(dataplane.CryptoPlacementKernel),
				Candidates:      []core.EndpointID{"exp-a"},
			},
		},
	}
	defer daemon.closeDataSessions()

	if err := daemon.warmKernelPlaintextDirectSessions(context.Background()); err != nil {
		t.Fatalf("warm tix_tcp secure kernel policy: %v", err)
	}
	if got := manager.tixTCPFlows.Load(); got != 1 {
		t.Fatalf("tix_tcp flow installs = %d, want 1", got)
	}
	if got := len(daemon.dataSessions); got != 1 {
		t.Fatalf("sessions = %d, want 1", got)
	}
}

func TestStartDataPathRetriesKernelPlaintextWarmupInBackground(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_PLAINTEXT_WARMUP_RETRY_DELAY", "1ms")
	t.Setenv("TRUSTIX_KERNEL_UDP_PLAINTEXT_WARMUP_TIMEOUT", "1s")

	registry := transport.NewRegistry()
	flaky := &flakyWarmupTransport{name: transport.ProtocolUDP, fail: 2}
	if err := registry.Register(flaky); err != nil {
		t.Fatalf("register transport: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	daemon := &Daemon{
		dataplane:        &captureCountingManager{},
		transports:       registry,
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-a"},
			Peers: []config.PeerConfig{{
				ID:     "ix-b",
				Domain: "lab.local",
				Endpoints: []config.EndpointConfig{{
					Name:      "udp-b",
					Address:   "127.0.0.1:17042",
					Transport: string(transport.ProtocolUDP),
					Enabled:   true,
				}},
			}},
			Routes: []config.RouteConfig{{
				Prefix:  "10.0.1.0/24",
				NextHop: "ix-b",
				Metric:  100,
			}},
			TransportPolicy: config.TransportPolicyConfig{
				Encryption:      securetransport.EncryptionPlaintext,
				KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
			},
		},
	}
	defer daemon.closeDataSessions()

	if _, err := daemon.startDataPath(ctx); err != nil {
		t.Fatalf("start data path: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		daemon.dataMu.Lock()
		sessions := len(daemon.dataSessions)
		daemon.dataMu.Unlock()
		if sessions == 1 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("background plaintext warmup did not install a session")
}

func TestCaptureForwarderSuppressedForNativePlaintextTunnel(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				Encryption: securetransport.EncryptionPlaintext,
				Candidates: []core.EndpointID{"gre-a"},
			},
			Endpoints: []config.EndpointConfig{{
				Name:      "gre-a",
				Transport: string(transport.ProtocolGRE),
				Enabled:   true,
			}},
		},
	}

	if !daemon.captureForwarderSuppressed() {
		t.Fatal("native plaintext tunnel route offload should suppress capture forwarder")
	}
}

func TestWarmKernelUDPPlaintextSessionsRetriesEpochChange(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_PLAINTEXT_WARMUP_RETRY_DELAY", "1ms")
	t.Setenv("TRUSTIX_KERNEL_UDP_PLAINTEXT_WARMUP_TIMEOUT", "1s")

	registry := transport.NewRegistry()
	flaky := &epochBumpTransport{name: transport.ProtocolUDP}
	if err := registry.Register(flaky); err != nil {
		t.Fatalf("register transport: %v", err)
	}
	daemon := &Daemon{
		dataplane:        &captureCountingManager{},
		transports:       registry,
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-a"},
			Peers: []config.PeerConfig{{
				ID:     "ix-b",
				Domain: "lab.local",
				Endpoints: []config.EndpointConfig{{
					Name:      "udp-b",
					Address:   "127.0.0.1:17042",
					Transport: string(transport.ProtocolUDP),
					Enabled:   true,
				}},
			}},
			Routes: []config.RouteConfig{{
				Prefix:  "10.0.1.0/24",
				NextHop: "ix-b",
				Metric:  100,
			}},
			TransportPolicy: config.TransportPolicyConfig{
				Encryption:      securetransport.EncryptionPlaintext,
				KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
			},
		},
	}
	defer daemon.closeDataSessions()
	flaky.daemon = daemon

	if err := daemon.warmKernelUDPPlaintextSessions(context.Background()); err != nil {
		t.Fatalf("warm plaintext sessions: %v", err)
	}
	if got := flaky.dials.Load(); got < 2 {
		t.Fatalf("dials = %d, want retry after epoch change", got)
	}
	if got := len(daemon.dataSessions); got != 1 {
		t.Fatalf("sessions = %d, want 1", got)
	}
}

func TestDataSessionControlOnlyKeepsTIXTCPTCOnlyProviderInUserspace(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")
	daemon := &Daemon{
		desired: config.Desired{
			Endpoints: []config.EndpointConfig{{
				Name:      "exp-a",
				Transport: string(transport.ProtocolTIXTCP),
				Enabled:   true,
			}},
			TransportPolicy: config.TransportPolicyConfig{
				KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
				Encryption:      securetransport.EncryptionPlaintext,
				Candidates:      []core.EndpointID{"exp-a"},
			},
		},
	}
	if daemon.dataSessionControlOnly(dataSessionKey{
		Transport:  transport.ProtocolTIXTCP,
		Encryption: securetransport.EncryptionPlaintext,
	}, config.EndpointConfig{Transport: string(transport.ProtocolTIXTCP)}) {
		t.Fatal("tix_tcp plaintext session should keep userspace RX/TX under UDP TC-only provider")
	}
	if daemon.dataSessionControlOnly(dataSessionKey{
		Transport:  transport.ProtocolTIXTCP,
		Encryption: securetransport.EncryptionSecure,
	}, config.EndpointConfig{Transport: string(transport.ProtocolTIXTCP)}) {
		t.Fatal("secure tix_tcp session should not be control-only")
	}
}

func TestKernelUDPDirectOnlyProgramEnabledForTIXTCPPolicy(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "1")
	daemon := &Daemon{
		desired: config.Desired{
			Endpoints: []config.EndpointConfig{{
				Name:      "exp-a",
				Transport: string(transport.ProtocolTIXTCP),
				Enabled:   true,
			}},
			TransportPolicy: config.TransportPolicyConfig{
				KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
				Encryption:      securetransport.EncryptionPlaintext,
				Candidates:      []core.EndpointID{"exp-a"},
			},
		},
	}
	if !daemon.kernelUDPDirectOnlyProgramEnabledForPolicy() {
		t.Fatal("tix_tcp direct-only policy did not enable the direct program")
	}
}

func TestDataSessionControlOnlyExcludesTIXTCPTXDirectOnlyWithUserspaceRX(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_ONLY", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT", "0")
	daemon := &Daemon{
		desired: config.Desired{
			Endpoints: []config.EndpointConfig{{
				Name:      "exp-a",
				Transport: string(transport.ProtocolTIXTCP),
				Enabled:   true,
			}},
			TransportPolicy: config.TransportPolicyConfig{
				KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
				Encryption:      securetransport.EncryptionPlaintext,
				Candidates:      []core.EndpointID{"exp-a"},
			},
		},
	}
	if daemon.dataSessionControlOnly(dataSessionKey{
		Transport:  transport.ProtocolTIXTCP,
		Encryption: securetransport.EncryptionPlaintext,
	}, config.EndpointConfig{Transport: string(transport.ProtocolTIXTCP)}) {
		t.Fatal("tix_tcp TX direct-only with userspace RX must keep the receive loop")
	}
}

func TestDataSessionControlOnlyExcludesTIXTCPCompatStream(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_ONLY", "1")
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_STREAM", "1")
	daemon := &Daemon{
		desired: config.Desired{
			Endpoints: []config.EndpointConfig{{
				Name:      "exp-a",
				Transport: string(transport.ProtocolTIXTCP),
				Enabled:   true,
			}},
			TransportPolicy: config.TransportPolicyConfig{
				KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
				Encryption:      securetransport.EncryptionPlaintext,
				Candidates:      []core.EndpointID{"exp-a"},
			},
		},
	}
	if daemon.dataSessionControlOnly(dataSessionKey{
		Transport:  transport.ProtocolTIXTCP,
		Encryption: securetransport.EncryptionPlaintext,
	}, config.EndpointConfig{Transport: string(transport.ProtocolTIXTCP)}) {
		t.Fatal("tix_tcp compat stream must keep userspace receive loop")
	}
}

func TestDataSessionControlOnlyKeepsSecureUDPFallbackByDefault(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
				Encryption:      securetransport.EncryptionSecure,
				CryptoPlacement: string(dataplane.CryptoPlacementKernel),
			},
		},
	}
	if daemon.dataSessionControlOnly(dataSessionKey{
		Transport:  transport.ProtocolUDP,
		Encryption: securetransport.EncryptionSecure,
	}, config.EndpointConfig{Transport: string(transport.ProtocolUDP)}) {
		t.Fatal("secure UDP should keep userspace receive fallback unless secure direct-only is explicitly enabled")
	}
	if daemon.dataSessionControlOnly(dataSessionKey{
		Transport:  transport.ProtocolTIXTCP,
		Encryption: securetransport.EncryptionSecure,
	}, config.EndpointConfig{Transport: string(transport.ProtocolTIXTCP)}) {
		t.Fatal("secure tix_tcp session should keep userspace RX/TX under UDP TC-only provider")
	}
}

func TestDataSessionControlOnlyKeepsFullPlaintextUDPOnKernelDatapath(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "0")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")
	daemon := &Daemon{
		desired: config.Desired{
			Endpoints: []config.EndpointConfig{{
				Name:      "udp-a",
				Transport: string(transport.ProtocolUDP),
				Enabled:   true,
			}},
			TransportPolicy: config.TransportPolicyConfig{
				Encryption: securetransport.EncryptionPlaintext,
				Candidates: []core.EndpointID{"udp-a"},
			},
			KernelModules: config.KernelModulesConfig{
				CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
			},
		},
	}
	if daemon.dataSessionControlOnly(dataSessionKey{
		Transport:  transport.ProtocolUDP,
		Encryption: securetransport.EncryptionPlaintext,
	}, config.EndpointConfig{Transport: string(transport.ProtocolUDP)}) {
		t.Fatal("full plaintext UDP session should stay attached to full-kmod datapath")
	}
}

func TestFullPlaintextKernelUDPRuntimeSkipsUserspaceReceiveLoop(t *testing.T) {
	session := &epochBumpSession{stats: transport.TransportStats{Datagram: true, NativeBatching: true, FragmentingDatagram: true, MaxPacketSize: 1500}}
	daemon := &Daemon{
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		desired: config.Desired{
			Endpoints: []config.EndpointConfig{{
				Name:      "udp-a",
				Transport: string(transport.ProtocolUDP),
				Enabled:   true,
			}},
			TransportPolicy: config.TransportPolicyConfig{
				Datapath:   config.TransportDatapathKernelModule,
				Encryption: securetransport.EncryptionPlaintext,
				Candidates: []core.EndpointID{"udp-a"},
			},
			KernelModules: config.KernelModulesConfig{
				CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
			},
		},
	}
	key := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "udp-a",
		Transport:  transport.ProtocolUDP,
		Address:    "127.0.0.1:17042",
		Encryption: securetransport.EncryptionPlaintext,
	}
	daemon.dataSessions[key] = session
	daemon.dataMu.Lock()
	runtime := daemon.startDataSessionRuntimeLocked(key, session, config.PeerConfig{ID: "ix-b"}, config.EndpointConfig{
		Name:      "udp-a",
		Transport: string(transport.ProtocolUDP),
	})
	daemon.dataMu.Unlock()
	defer daemon.closeDataSessions()
	if runtime == nil {
		t.Fatal("runtime should be created")
	}
	if runtime.controlOnly {
		t.Fatal("full plaintext UDP runtime should keep data-plane session semantics for kernel state")
	}
	if !runtime.receiveData {
		t.Fatal("full plaintext UDP runtime should remain a data session")
	}
	if runtime.receiveLoop {
		t.Fatal("full plaintext UDP runtime must not start userspace receive loop")
	}
	time.Sleep(20 * time.Millisecond)
	if session.closed.Load() {
		t.Fatal("full plaintext UDP runtime closed session through userspace receive loop")
	}
}

func TestFullPlaintextKernelUDPRuntimeSkipsUserspaceReceiveLoopWithAutoDatapathProfile(t *testing.T) {
	session := &epochBumpSession{stats: transport.TransportStats{Datagram: true, NativeBatching: true, FragmentingDatagram: true, MaxPacketSize: 1500}}
	daemon := &Daemon{
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		desired: config.Desired{
			Endpoints: []config.EndpointConfig{{
				Name:      "udp-a",
				Transport: string(transport.ProtocolUDP),
				Enabled:   true,
			}},
			TransportPolicy: config.TransportPolicyConfig{
				Encryption: securetransport.EncryptionPlaintext,
				Datapath:   config.TransportDatapathAuto,
				Candidates: []core.EndpointID{"udp-a"},
			},
			KernelModules: config.KernelModulesConfig{
				CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
			},
		},
	}
	key := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "udp-a",
		Transport:  transport.ProtocolUDP,
		Address:    "127.0.0.1:17042",
		Encryption: securetransport.EncryptionPlaintext,
	}
	daemon.dataSessions[key] = session
	daemon.dataMu.Lock()
	runtime := daemon.startDataSessionRuntimeLocked(key, session, config.PeerConfig{ID: "ix-b"}, config.EndpointConfig{
		Name:      "udp-a",
		Transport: string(transport.ProtocolUDP),
	})
	daemon.dataMu.Unlock()
	defer daemon.closeDataSessions()
	if runtime == nil {
		t.Fatal("runtime should be created")
	}
	if runtime.receiveLoop {
		t.Fatal("full plaintext UDP runtime with auto datapath profile must not start userspace receive loop")
	}
}

func TestFullPlaintextKernelUDPUserspaceDatapathKeepsReceiveLoop(t *testing.T) {
	session := &epochBumpSession{stats: transport.TransportStats{Datagram: true, NativeBatching: true, FragmentingDatagram: true, MaxPacketSize: 1500}}
	daemon := &Daemon{
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		desired: config.Desired{
			Endpoints: []config.EndpointConfig{{
				Name:      "udp-a",
				Transport: string(transport.ProtocolUDP),
				Enabled:   true,
			}},
			TransportPolicy: config.TransportPolicyConfig{
				Datapath:   config.TransportDatapathUserspace,
				Encryption: securetransport.EncryptionPlaintext,
				Candidates: []core.EndpointID{"udp-a"},
			},
			KernelModules: config.KernelModulesConfig{
				CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
			},
		},
	}
	key := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "udp-a",
		Transport:  transport.ProtocolUDP,
		Address:    "127.0.0.1:17042",
		Encryption: securetransport.EncryptionPlaintext,
	}
	daemon.dataSessions[key] = session
	daemon.dataMu.Lock()
	runtime := daemon.startDataSessionRuntimeLocked(key, session, config.PeerConfig{ID: "ix-b"}, config.EndpointConfig{
		Name:      "udp-a",
		Transport: string(transport.ProtocolUDP),
	})
	daemon.dataMu.Unlock()
	defer daemon.closeDataSessions()
	if runtime == nil {
		t.Fatal("runtime should be created")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for !session.closed.Load() {
		select {
		case <-ctx.Done():
			t.Fatal("userspace datapath runtime did not start receive loop")
		case <-ticker.C:
		}
	}
}

func TestKernelDirectWarmupKeepsFullPlaintextUDPDataSession(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "1")
	daemon := &Daemon{
		desired: config.Desired{
			Endpoints: []config.EndpointConfig{{
				Name:      "udp-a",
				Transport: string(transport.ProtocolUDP),
				Enabled:   true,
			}},
			TransportPolicy: config.TransportPolicyConfig{
				Profile:    config.TransportProfilePerformance,
				Datapath:   config.TransportDatapathKernelModule,
				Encryption: securetransport.EncryptionPlaintext,
				Candidates: []core.EndpointID{"udp-a"},
			},
			KernelModules: config.KernelModulesConfig{
				CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
			},
		},
	}
	if daemon.kernelDirectWarmupControlOnlyEndpoint(config.EndpointConfig{
		Transport: string(transport.ProtocolUDP),
	}) {
		t.Fatal("full plaintext UDP warmup must keep the data session attached")
	}
}

func TestDataSessionControlOnlyIncludesExplicitSecureKernelDirectOnly(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_SECURE_DIRECT_ONLY", "1")
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
				Encryption:      securetransport.EncryptionSecure,
				CryptoPlacement: string(dataplane.CryptoPlacementKernel),
			},
		},
	}
	if !daemon.dataSessionControlOnly(dataSessionKey{
		Transport:  transport.ProtocolUDP,
		Encryption: securetransport.EncryptionSecure,
	}, config.EndpointConfig{Transport: string(transport.ProtocolUDP)}) {
		t.Fatal("explicit secure UDP kernel direct-only session should be control-only")
	}
}

func TestControlOnlyKernelUDPSessionRuntimeStartsReceiveLoop(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")
	session := &epochBumpSession{stats: transport.TransportStats{Datagram: true, NativeBatching: true, FragmentingDatagram: true, MaxPacketSize: 1500}}
	daemon := &Daemon{
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		desired: config.Desired{
			Endpoints: []config.EndpointConfig{{
				Name:      "udp-a",
				Transport: string(transport.ProtocolUDP),
				Enabled:   true,
			}},
			TransportPolicy: config.TransportPolicyConfig{
				KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
				Encryption:      securetransport.EncryptionPlaintext,
				Candidates:      []core.EndpointID{"udp-a"},
			},
		},
	}
	key := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "udp-a",
		Transport:  transport.ProtocolUDP,
		Address:    "127.0.0.1:17042",
		Encryption: securetransport.EncryptionPlaintext,
	}
	daemon.dataSessions[key] = session
	daemon.dataMu.Lock()
	runtime := daemon.startDataSessionRuntimeLocked(key, session, config.PeerConfig{ID: "ix-b"}, config.EndpointConfig{
		Name:      "udp-a",
		Transport: string(transport.ProtocolUDP),
	})
	daemon.dataMu.Unlock()
	defer daemon.closeDataSessions()
	if runtime == nil || !runtime.controlOnly {
		t.Fatal("UDP plaintext direct-only runtime should be control-only")
	}
	if !runtime.receiveData {
		t.Fatal("UDP plaintext direct-only runtime should receive data")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for !session.closed.Load() {
		select {
		case <-ctx.Done():
			t.Fatal("UDP plaintext direct-only runtime did not start receive loop")
		case <-ticker.C:
		}
	}
}

func TestPlaintextKernelDirectOnlyRuntimeSkipsUnsupportedHeartbeat(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				SessionPool: config.SessionPoolPolicyConfig{
					Size: 8,
					Heartbeat: config.SessionPoolHeartbeatConfig{
						Mode: "enabled",
					},
				},
			},
		},
	}
	runtime := &dataSessionRuntime{
		key: dataSessionKey{
			Transport:  transport.ProtocolUDP,
			Encryption: securetransport.EncryptionPlaintext,
		},
		controlOnly: true,
		receiveLoop: true,
	}
	if daemon.sessionHeartbeatEnabledForRuntimeLocked(runtime) {
		t.Fatal("plaintext UDP direct-only runtime must not start an unsupported userspace heartbeat")
	}

	runtime.key.Encryption = securetransport.EncryptionSecure
	if !daemon.sessionHeartbeatEnabledForRuntimeLocked(runtime) {
		t.Fatal("secure UDP control runtime should retain heartbeat support")
	}
	runtime.key.Encryption = securetransport.EncryptionPlaintext
	runtime.controlOnly = false
	if !daemon.sessionHeartbeatEnabledForRuntimeLocked(runtime) {
		t.Fatal("ordinary plaintext UDP runtime should retain heartbeat support")
	}
	runtime.receiveLoop = false
	if daemon.sessionHeartbeatEnabledForRuntimeLocked(runtime) {
		t.Fatal("runtime without a receive loop must not start a heartbeat")
	}
}

func TestControlOnlyWarmupRetainsUDPKernelFlowOnClose(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")
	session := &epochBumpSession{stats: transport.TransportStats{Datagram: true, NativeBatching: true, FragmentingDatagram: true, MaxPacketSize: 1500}}
	daemon := &Daemon{
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		desired: config.Desired{
			Endpoints: []config.EndpointConfig{{
				Name:      "udp-a",
				Transport: string(transport.ProtocolUDP),
				Enabled:   true,
			}},
			TransportPolicy: config.TransportPolicyConfig{
				KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
				Encryption:      securetransport.EncryptionPlaintext,
				Candidates:      []core.EndpointID{"udp-a"},
			},
		},
	}
	key := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "udp-a",
		Transport:  transport.ProtocolUDP,
		Address:    "127.0.0.1:17042",
		Encryption: securetransport.EncryptionPlaintext,
	}
	daemon.dataSessions[key] = session
	daemon.dataMu.Lock()
	runtime := daemon.startDataSessionRuntimeLockedWithOptions(key, session, config.PeerConfig{ID: "ix-b"}, config.EndpointConfig{
		Name:      "udp-a",
		Transport: string(transport.ProtocolUDP),
	}, true)
	daemon.dataMu.Unlock()
	if runtime == nil || !runtime.controlOnly {
		t.Fatal("UDP warmup runtime should be control-only")
	}
	if !session.retained.Load() {
		t.Fatal("UDP control-only warmup did not mark the kernel flow retained")
	}
	daemon.closeDataSessions()
	if !session.closed.Load() {
		t.Fatal("closeDataSessions did not close the warmup session")
	}
}

func TestTIXTCPCompatStreamWarmupRuntimeKeepsReceiveLoop(t *testing.T) {
	session := &epochBumpSession{stats: transport.TransportStats{
		Extra: map[string]uint64{"tix_tcp_compat_stream": 1},
	}}
	daemon := &Daemon{
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
	}
	key := dataSessionKey{
		Peer:      "ix-b",
		Endpoint:  "exp-a",
		Transport: transport.ProtocolTIXTCP,
		Address:   "127.0.0.1:17042",
	}
	daemon.dataSessions[key] = session
	daemon.dataMu.Lock()
	runtime := daemon.startDataSessionRuntimeLockedWithOptions(key, session, config.PeerConfig{ID: "ix-b"}, config.EndpointConfig{
		Name:      "exp-a",
		Transport: string(transport.ProtocolTIXTCP),
	}, true)
	daemon.dataMu.Unlock()
	defer daemon.closeDataSessions()
	if runtime == nil {
		t.Fatal("runtime should be created")
	}
	if runtime.controlOnly {
		t.Fatal("tix_tcp compat stream warmup runtime must keep the userspace receive loop")
	}
}

func TestTIXTCPDirectWarmupRuntimeKeepsReceiveLoop(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_ONLY", "1")
	session := &epochBumpSession{stats: transport.TransportStats{Datagram: true}}
	daemon := &Daemon{
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		desired: config.Desired{
			Endpoints: []config.EndpointConfig{{
				Name:      "exp-a",
				Transport: string(transport.ProtocolTIXTCP),
				Enabled:   true,
			}},
			TransportPolicy: config.TransportPolicyConfig{
				KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
				Encryption:      securetransport.EncryptionPlaintext,
				Candidates:      []core.EndpointID{"exp-a"},
			},
		},
	}
	key := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "exp-a",
		Transport:  transport.ProtocolTIXTCP,
		Address:    "127.0.0.1:17042",
		Encryption: securetransport.EncryptionPlaintext,
	}
	daemon.dataSessions[key] = session
	daemon.dataMu.Lock()
	runtime := daemon.startDataSessionRuntimeLockedWithOptions(key, session, config.PeerConfig{ID: "ix-b"}, config.EndpointConfig{
		Name:      "exp-a",
		Transport: string(transport.ProtocolTIXTCP),
	}, daemon.kernelDirectWarmupControlOnlyEndpoint(config.EndpointConfig{Transport: string(transport.ProtocolTIXTCP)}))
	daemon.dataMu.Unlock()
	defer daemon.closeDataSessions()
	if runtime == nil {
		t.Fatal("runtime should be created")
	}
	if runtime.controlOnly {
		t.Fatal("tix_tcp direct warmup runtime must keep the userspace receive loop")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for !session.closed.Load() {
		select {
		case <-ctx.Done():
			t.Fatal("tix_tcp direct warmup runtime did not start the receive loop")
		case <-ticker.C:
		}
	}
}

type captureCountingManager struct {
	subscription    *captureCountingSubscription
	kernelUDPStatus *dataplane.KernelUDPStatus
	kernelUDPFlows  atomic.Uint64
	tixTCPFlows     atomic.Uint64
	attachCount     atomic.Uint64
	detachCount     atomic.Uint64
}

func (manager *captureCountingManager) Load(ctx context.Context) error {
	return ctx.Err()
}

func (manager *captureCountingManager) Attach(ctx context.Context, spec dataplane.AttachSpec) error {
	manager.attachCount.Add(1)
	return ctx.Err()
}

func (manager *captureCountingManager) ApplySnapshot(ctx context.Context, snapshot dataplane.Snapshot) error {
	return ctx.Err()
}

func (manager *captureCountingManager) Stats(ctx context.Context) (dataplane.Stats, error) {
	if err := ctx.Err(); err != nil {
		return dataplane.Stats{}, err
	}
	return dataplane.Stats{}, nil
}

func (manager *captureCountingManager) Detach(ctx context.Context) error {
	manager.detachCount.Add(1)
	return ctx.Err()
}

func (manager *captureCountingManager) SubscribeCapture(ctx context.Context, buffer int) (dataplane.CaptureSubscription, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	subscription := &captureCountingSubscription{
		events: make(chan dataplane.CaptureEvent),
		closed: make(chan struct{}),
	}
	manager.subscription = subscription
	return subscription, nil
}

func (manager *captureCountingManager) KernelUDPStatus(ctx context.Context) (dataplane.KernelUDPStatus, error) {
	if err := ctx.Err(); err != nil {
		return dataplane.KernelUDPStatus{}, err
	}
	if manager.kernelUDPStatus != nil {
		status := *manager.kernelUDPStatus
		status.ActiveFlows = int(manager.kernelUDPFlows.Load())
		return status, nil
	}
	return dataplane.KernelUDPStatus{Available: true, Provider: "test", FastPath: true, UserspaceCrypto: true}, nil
}

func (manager *captureCountingManager) InstallKernelUDPFlows(ctx context.Context, flows []dataplane.KernelUDPFlow) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	manager.kernelUDPFlows.Add(uint64(len(flows)))
	return nil
}

func (manager *captureCountingManager) SubmitKernelUDPFrame(ctx context.Context, frame dataplane.KernelUDPFrame) error {
	return ctx.Err()
}

func (manager *captureCountingManager) SubscribeKernelUDP(ctx context.Context, buffer int) (dataplane.KernelUDPSubscription, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &captureCountingKernelUDPSubscription{events: make(chan dataplane.KernelUDPFrame)}, nil
}

func (manager *captureCountingManager) TIXTCPStatus(ctx context.Context) (dataplane.TIXTCPStatus, error) {
	if err := ctx.Err(); err != nil {
		return dataplane.TIXTCPStatus{}, err
	}
	return dataplane.TIXTCPStatus{
		Available:       true,
		Provider:        "test",
		FastPath:        true,
		UserspaceCrypto: true,
		KernelCrypto:    true,
		Reinject:        true,
		PreferredCrypto: dataplane.CryptoPlacementKernel,
		SupportedCrypto: []dataplane.CryptoPlacement{dataplane.CryptoPlacementUserspace, dataplane.CryptoPlacementKernel},
		ActiveFlows:     int(manager.tixTCPFlows.Load()),
	}, nil
}

func (manager *captureCountingManager) InstallTIXTCPFlows(ctx context.Context, flows []dataplane.TIXTCPFlow) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	manager.tixTCPFlows.Add(uint64(len(flows)))
	return nil
}

func (manager *captureCountingManager) SubmitTIXTCPFrame(ctx context.Context, frame dataplane.TIXTCPFrame) error {
	return ctx.Err()
}

func (manager *captureCountingManager) SubscribeTIXTCP(ctx context.Context, buffer int) (dataplane.TIXTCPSubscription, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &captureCountingTIXTCPSubscription{events: make(chan dataplane.TIXTCPFrame)}, nil
}

func (manager *captureCountingManager) KernelTransportStatus(ctx context.Context) (dataplane.KernelTransportStatus, error) {
	if err := ctx.Err(); err != nil {
		return dataplane.KernelTransportStatus{}, err
	}
	return dataplane.KernelTransportStatus{
		Mode:      dataplane.KernelTransportModeRequireKernel,
		Available: true,
		Provider:  "test",
		Protocols: []dataplane.KernelTransportProtocol{{
			Protocol:          string(transport.ProtocolUDP),
			Available:         true,
			CapabilityReady:   true,
			Placement:         "kernel",
			Provider:          "test",
			UserspaceFallback: false,
		}, {
			Protocol:          string(transport.ProtocolTIXTCP),
			Available:         true,
			CapabilityReady:   true,
			Placement:         "kernel",
			Provider:          "test",
			UserspaceFallback: false,
		}},
	}, nil
}

func (manager *captureCountingManager) InstallRoutes(ctx context.Context, routes []routing.Route) error {
	return ctx.Err()
}

func (manager *captureCountingManager) SetKernelUDPFlowPeer(ctx context.Context, flowID uint64, peer core.IXID, endpoint core.EndpointID) error {
	return ctx.Err()
}

type captureCountingKernelUDPSubscription struct {
	events chan dataplane.KernelUDPFrame
}

func (subscription *captureCountingKernelUDPSubscription) Events() <-chan dataplane.KernelUDPFrame {
	return subscription.events
}

func (subscription *captureCountingKernelUDPSubscription) Close() error {
	close(subscription.events)
	return nil
}

type captureCountingTIXTCPSubscription struct {
	events chan dataplane.TIXTCPFrame
}

func (subscription *captureCountingTIXTCPSubscription) Events() <-chan dataplane.TIXTCPFrame {
	return subscription.events
}

func (subscription *captureCountingTIXTCPSubscription) Close() error {
	close(subscription.events)
	return nil
}

type captureCountingSubscription struct {
	events chan dataplane.CaptureEvent
	closed chan struct{}
	once   sync.Once
	closes atomic.Uint64
}

func (subscription *captureCountingSubscription) Events() <-chan dataplane.CaptureEvent {
	return subscription.events
}

func (subscription *captureCountingSubscription) Close() error {
	subscription.once.Do(func() {
		subscription.closes.Add(1)
		close(subscription.events)
		close(subscription.closed)
	})
	return nil
}

func waitForCaptureSubscriptionClose(t *testing.T, subscription *captureCountingSubscription) {
	t.Helper()
	select {
	case <-subscription.closed:
	case <-time.After(time.Second):
		t.Fatal("capture subscription was not closed")
	}
}

type failingListenTransport struct {
	name transport.Protocol
	err  error
}

func (transportImpl *failingListenTransport) Name() transport.Protocol {
	return transportImpl.name
}

func (transportImpl *failingListenTransport) Probe(ctx context.Context, peer transport.Peer) transport.ProbeResult {
	return transport.ProbeResult{}
}

func (transportImpl *failingListenTransport) Dial(ctx context.Context, peer transport.Peer, tlsConf *tls.Config) (transport.Session, error) {
	return nil, fmt.Errorf("unexpected failing transport dial")
}

func (transportImpl *failingListenTransport) Listen(ctx context.Context, ep transport.Endpoint, tlsConf *tls.Config) (transport.Listener, error) {
	return nil, transportImpl.err
}

type epochBumpTransport struct {
	name   transport.Protocol
	daemon *Daemon
	dials  atomic.Uint64
}

func (transportImpl *epochBumpTransport) Name() transport.Protocol {
	return transportImpl.name
}

func (transportImpl *epochBumpTransport) Probe(ctx context.Context, peer transport.Peer) transport.ProbeResult {
	return transport.ProbeResult{}
}

func (transportImpl *epochBumpTransport) Dial(ctx context.Context, peer transport.Peer, tlsConf *tls.Config) (transport.Session, error) {
	if len(peer.Endpoints) != 1 {
		return nil, fmt.Errorf("epoch bump transport expected one endpoint, got %d", len(peer.Endpoints))
	}
	if transportImpl.dials.Add(1) == 1 {
		transportImpl.daemon.dataMu.Lock()
		transportImpl.daemon.dataSessionEpoch++
		transportImpl.daemon.dataMu.Unlock()
	}
	return &epochBumpSession{stats: transport.TransportStats{
		Encryption: peer.Endpoints[0].Encryption,
		Datagram:   true,
	}}, nil
}

func (transportImpl *epochBumpTransport) Listen(ctx context.Context, ep transport.Endpoint, tlsConf *tls.Config) (transport.Listener, error) {
	return nil, fmt.Errorf("unexpected epoch bump transport listen")
}

type epochBumpSession struct {
	stats    transport.TransportStats
	closed   atomic.Bool
	retained atomic.Bool
}

func (session *epochBumpSession) SendPacket(packet []byte) error {
	return nil
}

func (session *epochBumpSession) RecvPacket() ([]byte, error) {
	return nil, context.Canceled
}

func (session *epochBumpSession) Close() error {
	session.closed.Store(true)
	return nil
}

func (session *epochBumpSession) Stats() transport.TransportStats {
	return session.stats
}

func (session *epochBumpSession) RetainKernelFlowOnClose() {
	session.retained.Store(true)
}
