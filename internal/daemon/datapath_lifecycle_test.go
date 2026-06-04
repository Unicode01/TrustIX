package daemon

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/routing"
	"trustix.local/trustix/internal/transport"
	experimentaltcptransport "trustix.local/trustix/internal/transport/experimentaltcp"
	securetransport "trustix.local/trustix/internal/transport/secure"
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

func TestStartDataPathKeepsCaptureForwarderForExperimentalTCPTCOnlyProvider(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")
	manager := &captureCountingManager{}
	daemon := &Daemon{
		dataplane:    manager,
		dataSessions: make(map[dataSessionKey]transport.Session),
		desired: config.Desired{
			Endpoints: []config.EndpointConfig{{
				Name:      "exp-a",
				Transport: string(transport.ProtocolExperimentalTCP),
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
		t.Fatal("capture subscription should start for experimental_tcp userspace fallback")
	}
	status := daemon.dataPathStatus()
	if !status.CaptureForwarderActive {
		t.Fatal("capture forwarder should stay active for experimental_tcp userspace fallback")
	}
	if status.CaptureForwarderSuppressed {
		t.Fatal("capture forwarder should not report suppressed for experimental_tcp fallback")
	}
}

func TestWarmKernelPlaintextDirectSessionsWarmsExperimentalTCPPolicy(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "1")
	manager := &captureCountingManager{}
	registry := transport.NewRegistry()
	if err := registry.Register(experimentaltcptransport.New(manager)); err != nil {
		t.Fatalf("register experimental_tcp transport: %v", err)
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
				Transport: string(transport.ProtocolExperimentalTCP),
				Enabled:   true,
			}},
			Peers: []config.PeerConfig{{
				ID:     "ix-b",
				Domain: "lab.local",
				Endpoints: []config.EndpointConfig{{
					Name:      "exp-a",
					Address:   "127.0.0.1:17042",
					Transport: string(transport.ProtocolExperimentalTCP),
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
		t.Fatalf("warm experimental_tcp plaintext policy: %v", err)
	}
	if got := manager.experimentalTCPFlows.Load(); got != 1 {
		t.Fatalf("experimental_tcp flow installs = %d, want 1", got)
	}
	if got := len(daemon.dataSessions); got != 1 {
		t.Fatalf("sessions = %d, want 1", got)
	}
}

func TestWarmKernelSecureDirectSessionsWarmsExperimentalTCPPolicy(t *testing.T) {
	manager := &captureCountingManager{}
	registry := transport.NewRegistry()
	if err := registry.Register(experimentaltcptransport.New(manager)); err != nil {
		t.Fatalf("register experimental_tcp transport: %v", err)
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
				Transport: string(transport.ProtocolExperimentalTCP),
				Enabled:   true,
			}},
			Peers: []config.PeerConfig{{
				ID:     "ix-b",
				Domain: "lab.local",
				Endpoints: []config.EndpointConfig{{
					Name:      "exp-a",
					Address:   "127.0.0.1:17042",
					Transport: string(transport.ProtocolExperimentalTCP),
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
		t.Fatalf("warm experimental_tcp secure kernel policy: %v", err)
	}
	if got := manager.experimentalTCPFlows.Load(); got != 1 {
		t.Fatalf("experimental_tcp flow installs = %d, want 1", got)
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

func TestDataSessionControlOnlyKeepsExperimentalTCPTCOnlyProviderInUserspace(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")
	daemon := &Daemon{
		desired: config.Desired{
			Endpoints: []config.EndpointConfig{{
				Name:      "exp-a",
				Transport: string(transport.ProtocolExperimentalTCP),
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
		Transport:  transport.ProtocolExperimentalTCP,
		Encryption: securetransport.EncryptionPlaintext,
	}, config.EndpointConfig{Transport: string(transport.ProtocolExperimentalTCP)}) {
		t.Fatal("experimental_tcp plaintext session should keep userspace RX/TX under UDP TC-only provider")
	}
	if daemon.dataSessionControlOnly(dataSessionKey{
		Transport:  transport.ProtocolExperimentalTCP,
		Encryption: securetransport.EncryptionSecure,
	}, config.EndpointConfig{Transport: string(transport.ProtocolExperimentalTCP)}) {
		t.Fatal("secure experimental_tcp session should not be control-only")
	}
}

func TestKernelUDPDirectOnlyProgramEnabledForExperimentalTCPPolicy(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "1")
	daemon := &Daemon{
		desired: config.Desired{
			Endpoints: []config.EndpointConfig{{
				Name:      "exp-a",
				Transport: string(transport.ProtocolExperimentalTCP),
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
		t.Fatal("experimental_tcp direct-only policy did not enable the direct program")
	}
}

func TestDataSessionControlOnlyExcludesExperimentalTCPTXDirectOnlyWithUserspaceRX(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "1")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_ONLY", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT", "0")
	daemon := &Daemon{
		desired: config.Desired{
			Endpoints: []config.EndpointConfig{{
				Name:      "exp-a",
				Transport: string(transport.ProtocolExperimentalTCP),
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
		Transport:  transport.ProtocolExperimentalTCP,
		Encryption: securetransport.EncryptionPlaintext,
	}, config.EndpointConfig{Transport: string(transport.ProtocolExperimentalTCP)}) {
		t.Fatal("experimental_tcp TX direct-only with userspace RX must keep the receive loop")
	}
}

func TestDataSessionControlOnlyExcludesExperimentalTCPCompatStream(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "1")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_ONLY", "1")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_COMPAT_STREAM", "1")
	daemon := &Daemon{
		desired: config.Desired{
			Endpoints: []config.EndpointConfig{{
				Name:      "exp-a",
				Transport: string(transport.ProtocolExperimentalTCP),
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
		Transport:  transport.ProtocolExperimentalTCP,
		Encryption: securetransport.EncryptionPlaintext,
	}, config.EndpointConfig{Transport: string(transport.ProtocolExperimentalTCP)}) {
		t.Fatal("experimental_tcp compat stream must keep userspace receive loop")
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
		Transport:  transport.ProtocolExperimentalTCP,
		Encryption: securetransport.EncryptionSecure,
	}, config.EndpointConfig{Transport: string(transport.ProtocolExperimentalTCP)}) {
		t.Fatal("secure experimental_tcp session should keep userspace RX/TX under UDP TC-only provider")
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

func TestControlOnlySessionRuntimeDoesNotStartReceiveLoop(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")
	session := &epochBumpSession{stats: transport.TransportStats{Datagram: true}}
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
	time.Sleep(25 * time.Millisecond)
	if session.closed.Load() {
		t.Fatal("control-only runtime started receive loop and closed the session")
	}
	daemon.dataMu.Lock()
	_, ok := daemon.dataSessions[key]
	daemon.dataMu.Unlock()
	if !ok {
		t.Fatal("control-only runtime removed the session")
	}
}

func TestControlOnlyWarmupRetainsUDPKernelFlowOnClose(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")
	session := &epochBumpSession{stats: transport.TransportStats{Datagram: true}}
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

func TestExperimentalTCPCompatStreamWarmupRuntimeKeepsReceiveLoop(t *testing.T) {
	session := &epochBumpSession{stats: transport.TransportStats{
		Extra: map[string]uint64{"experimental_tcp_compat_stream": 1},
	}}
	daemon := &Daemon{
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
	}
	key := dataSessionKey{
		Peer:      "ix-b",
		Endpoint:  "exp-a",
		Transport: transport.ProtocolExperimentalTCP,
		Address:   "127.0.0.1:17042",
	}
	daemon.dataSessions[key] = session
	daemon.dataMu.Lock()
	runtime := daemon.startDataSessionRuntimeLockedWithOptions(key, session, config.PeerConfig{ID: "ix-b"}, config.EndpointConfig{
		Name:      "exp-a",
		Transport: string(transport.ProtocolExperimentalTCP),
	}, true)
	daemon.dataMu.Unlock()
	defer daemon.closeDataSessions()
	if runtime == nil {
		t.Fatal("runtime should be created")
	}
	if runtime.controlOnly {
		t.Fatal("experimental_tcp compat stream warmup runtime must keep the userspace receive loop")
	}
}

func TestExperimentalTCPDirectWarmupRuntimeKeepsReceiveLoop(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "1")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_ONLY", "1")
	session := &epochBumpSession{stats: transport.TransportStats{Datagram: true}}
	daemon := &Daemon{
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		desired: config.Desired{
			Endpoints: []config.EndpointConfig{{
				Name:      "exp-a",
				Transport: string(transport.ProtocolExperimentalTCP),
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
		Transport:  transport.ProtocolExperimentalTCP,
		Address:    "127.0.0.1:17042",
		Encryption: securetransport.EncryptionPlaintext,
	}
	daemon.dataSessions[key] = session
	daemon.dataMu.Lock()
	runtime := daemon.startDataSessionRuntimeLockedWithOptions(key, session, config.PeerConfig{ID: "ix-b"}, config.EndpointConfig{
		Name:      "exp-a",
		Transport: string(transport.ProtocolExperimentalTCP),
	}, daemon.kernelDirectWarmupControlOnlyEndpoint(config.EndpointConfig{Transport: string(transport.ProtocolExperimentalTCP)}))
	daemon.dataMu.Unlock()
	defer daemon.closeDataSessions()
	if runtime == nil {
		t.Fatal("runtime should be created")
	}
	if runtime.controlOnly {
		t.Fatal("experimental_tcp direct warmup runtime must keep the userspace receive loop")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for !session.closed.Load() {
		select {
		case <-ctx.Done():
			t.Fatal("experimental_tcp direct warmup runtime did not start the receive loop")
		case <-ticker.C:
		}
	}
}

type captureCountingManager struct {
	subscription         *captureCountingSubscription
	experimentalTCPFlows atomic.Uint64
}

func (manager *captureCountingManager) Load(ctx context.Context) error {
	return ctx.Err()
}

func (manager *captureCountingManager) Attach(ctx context.Context, spec dataplane.AttachSpec) error {
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
	return dataplane.KernelUDPStatus{Available: true, Provider: "test", FastPath: true, UserspaceCrypto: true}, nil
}

func (manager *captureCountingManager) InstallKernelUDPFlows(ctx context.Context, flows []dataplane.KernelUDPFlow) error {
	return ctx.Err()
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

func (manager *captureCountingManager) ExperimentalTCPStatus(ctx context.Context) (dataplane.ExperimentalTCPStatus, error) {
	if err := ctx.Err(); err != nil {
		return dataplane.ExperimentalTCPStatus{}, err
	}
	return dataplane.ExperimentalTCPStatus{
		Available:       true,
		Provider:        "test",
		FastPath:        true,
		UserspaceCrypto: true,
		KernelCrypto:    true,
		Reinject:        true,
		PreferredCrypto: dataplane.CryptoPlacementKernel,
		SupportedCrypto: []dataplane.CryptoPlacement{dataplane.CryptoPlacementUserspace, dataplane.CryptoPlacementKernel},
		ActiveFlows:     int(manager.experimentalTCPFlows.Load()),
	}, nil
}

func (manager *captureCountingManager) InstallExperimentalTCPFlows(ctx context.Context, flows []dataplane.ExperimentalTCPFlow) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	manager.experimentalTCPFlows.Add(uint64(len(flows)))
	return nil
}

func (manager *captureCountingManager) SubmitExperimentalTCPFrame(ctx context.Context, frame dataplane.ExperimentalTCPFrame) error {
	return ctx.Err()
}

func (manager *captureCountingManager) SubscribeExperimentalTCP(ctx context.Context, buffer int) (dataplane.ExperimentalTCPSubscription, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &captureCountingExperimentalTCPSubscription{events: make(chan dataplane.ExperimentalTCPFrame)}, nil
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
			Protocol:          string(transport.ProtocolExperimentalTCP),
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

type captureCountingExperimentalTCPSubscription struct {
	events chan dataplane.ExperimentalTCPFrame
}

func (subscription *captureCountingExperimentalTCPSubscription) Events() <-chan dataplane.ExperimentalTCPFrame {
	return subscription.events
}

func (subscription *captureCountingExperimentalTCPSubscription) Close() error {
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
