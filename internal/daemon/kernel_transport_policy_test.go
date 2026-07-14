package daemon

import (
	"testing"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/transport"
	securetransport "trustix.local/trustix/internal/transport/secure"
)

func TestEffectiveKernelTransportModeDisablesAutoForUserspaceUDP(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfileStable,
			Datapath:   config.TransportDatapathUserspace,
			Encryption: securetransport.EncryptionSecure,
			Candidates: []core.EndpointID{"udp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "udp-a",
			Transport: string(transport.ProtocolUDP),
			Enabled:   true,
		}},
	}

	if got := effectiveKernelTransportModeForDesired(desired); got != dataplane.KernelTransportModeDisabled {
		t.Fatalf("kernel transport mode = %q, want disabled for userspace UDP auto", got)
	}
}

func TestEffectiveKernelTransportModeDisablesEmptyPolicyForUserspaceUDP(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Candidates: []core.EndpointID{"udp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "udp-a",
			Transport: string(transport.ProtocolUDP),
			Enabled:   true,
		}},
	}

	if got := effectiveKernelTransportModeForDesired(desired); got != dataplane.KernelTransportModeDisabled {
		t.Fatalf("kernel transport mode = %q, want disabled for empty userspace UDP policy", got)
	}
}

func TestEffectiveKernelTransportModeDisablesEmptyPolicyForUserspaceTIXTCP(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Candidates: []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolTIXTCP),
			Enabled:   true,
		}},
	}

	if got := effectiveKernelTransportModeForDesired(desired); got != dataplane.KernelTransportModeDisabled {
		t.Fatalf("kernel transport mode = %q, want disabled for empty userspace tix_tcp policy", got)
	}
}

func TestEffectiveKernelTransportModePreservesExplicitAutoForUserspaceTIXTCP(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeAuto)},
			Candidates:      []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolTIXTCP),
			Enabled:   true,
		}},
	}

	if got := effectiveKernelTransportModeForDesired(desired); got != dataplane.KernelTransportModeAuto {
		t.Fatalf("kernel transport mode = %q, want explicit auto for userspace tix_tcp policy", got)
	}
}

func TestEffectiveKernelTransportModeKeepsExplicitPreferForUserspaceUDP(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:         config.TransportProfileStable,
			Datapath:        config.TransportDatapathUserspace,
			Encryption:      securetransport.EncryptionSecure,
			KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModePreferKernel)},
			Candidates:      []core.EndpointID{"udp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "udp-a",
			Transport: string(transport.ProtocolUDP),
			Enabled:   true,
		}},
	}

	if got := effectiveKernelTransportModeForDesired(desired); got != dataplane.KernelTransportModePreferKernel {
		t.Fatalf("kernel transport mode = %q, want explicit prefer_kernel", got)
	}
}

func TestEffectiveKernelTransportModeKeepsAutoForFullKmodUDP(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfilePerformance,
			Datapath:   config.TransportDatapathKernelModule,
			Encryption: securetransport.EncryptionPlaintext,
			Candidates: []core.EndpointID{"udp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "udp-a",
			Transport: string(transport.ProtocolUDP),
			Enabled:   true,
		}},
	}

	if got := effectiveKernelTransportModeForDesired(desired); got != dataplane.KernelTransportModeAuto {
		t.Fatalf("kernel transport mode = %q, want auto for full-kmod UDP", got)
	}
}

func TestEffectiveKernelTransportModeDisablesAutoForSecureUserspaceKernelUDP(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:         config.TransportProfilePerformance,
			Datapath:        config.TransportDatapathTCXDP,
			Encryption:      securetransport.EncryptionSecure,
			CryptoPlacement: string(dataplane.CryptoPlacementUserspace),
			Candidates:      []core.EndpointID{"udp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "udp-a",
			Transport: string(transport.ProtocolUDP),
			Enabled:   true,
		}},
	}

	if got := effectiveKernelTransportModeForDesired(desired); got != dataplane.KernelTransportModeDisabled {
		t.Fatalf("kernel transport mode = %q, want disabled for secure userspace-crypto kernel UDP", got)
	}
}

func TestEffectiveKernelTransportModeKeepsExplicitRequireForSecureUserspaceKernelUDP(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:         config.TransportProfilePerformance,
			Datapath:        config.TransportDatapathTCXDP,
			Encryption:      securetransport.EncryptionSecure,
			CryptoPlacement: string(dataplane.CryptoPlacementUserspace),
			KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
			Candidates:      []core.EndpointID{"udp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "udp-a",
			Transport: string(transport.ProtocolUDP),
			Enabled:   true,
		}},
	}

	if got := effectiveKernelTransportModeForDesired(desired); got != dataplane.KernelTransportModeRequireKernel {
		t.Fatalf("kernel transport mode = %q, want explicit require_kernel", got)
	}
}

func TestEffectiveKernelTransportModeKeepsAutoForSecureKernelCryptoUDP(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:         config.TransportProfilePerformance,
			Datapath:        config.TransportDatapathTCXDP,
			Encryption:      securetransport.EncryptionSecure,
			CryptoPlacement: string(dataplane.CryptoPlacementKernel),
			Candidates:      []core.EndpointID{"udp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "udp-a",
			Transport: string(transport.ProtocolUDP),
			Enabled:   true,
		}},
	}

	if got := effectiveKernelTransportModeForDesired(desired); got != dataplane.KernelTransportModeAuto {
		t.Fatalf("kernel transport mode = %q, want auto for secure kernel-crypto UDP", got)
	}
}

func TestEffectiveKernelTransportModeDisablesAutoForSecureUserspaceTIXTCP(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:         config.TransportProfilePerformance,
			Datapath:        config.TransportDatapathTCXDP,
			Encryption:      securetransport.EncryptionSecure,
			CryptoPlacement: string(dataplane.CryptoPlacementUserspace),
			Candidates:      []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolTIXTCP),
			Enabled:   true,
		}},
	}

	if got := effectiveKernelTransportModeForDesired(desired); got != dataplane.KernelTransportModeDisabled {
		t.Fatalf("kernel transport mode = %q, want disabled for secure userspace-crypto tix_tcp", got)
	}
	if reason := tixTCPFastPathDisabledReasonForDesired(desired); reason == "" {
		t.Fatal("tix_tcp fast path disabled reason is empty")
	}
}

func TestEffectiveKernelTransportModeKeepsAutoForMixedUDPAndSecureUserspaceTIXTCP(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:         config.TransportProfilePerformance,
			Datapath:        config.TransportDatapathKernelModule,
			Encryption:      securetransport.EncryptionPlaintext,
			CryptoPlacement: string(dataplane.CryptoPlacementUserspace),
			Candidates:      []core.EndpointID{"udp-a", "exp-a"},
			Profiles: []config.TransportProfileConfig{
				{
					Transport:       string(transport.ProtocolUDP),
					Profile:         config.TransportProfilePerformance,
					Datapath:        config.TransportDatapathKernelModule,
					Encryption:      securetransport.EncryptionPlaintext,
					CryptoPlacement: string(dataplane.CryptoPlacementUserspace),
				},
				{
					Transport:       string(transport.ProtocolTIXTCP),
					Profile:         config.TransportProfilePerformance,
					Datapath:        config.TransportDatapathTCXDP,
					Encryption:      securetransport.EncryptionSecure,
					CryptoPlacement: string(dataplane.CryptoPlacementUserspace),
				},
			},
		},
		Endpoints: []config.EndpointConfig{
			{
				Name:      "udp-a",
				Transport: string(transport.ProtocolUDP),
				Enabled:   true,
			},
			{
				Name:      "exp-a",
				Transport: string(transport.ProtocolTIXTCP),
				Enabled:   true,
			},
		},
	}

	if got := effectiveKernelTransportModeForDesired(desired); got != dataplane.KernelTransportModeAuto {
		t.Fatalf("kernel transport mode = %q, want auto so UDP/full-kmod remains available", got)
	}
	if reason := tixTCPFastPathDisabledReasonForDesired(desired); reason == "" {
		t.Fatal("mixed policy should still disable only the unsafe tix_tcp fast path")
	}
}

func TestEffectiveKernelTransportModeKeepsExplicitRequireForSecureUserspaceTIXTCP(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:         config.TransportProfilePerformance,
			Datapath:        config.TransportDatapathTCXDP,
			Encryption:      securetransport.EncryptionSecure,
			CryptoPlacement: string(dataplane.CryptoPlacementUserspace),
			KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
			Candidates:      []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolTIXTCP),
			Enabled:   true,
		}},
	}

	if got := effectiveKernelTransportModeForDesired(desired); got != dataplane.KernelTransportModeRequireKernel {
		t.Fatalf("kernel transport mode = %q, want explicit require_kernel", got)
	}
	if reason := tixTCPFastPathDisabledReasonForDesired(desired); reason != "" {
		t.Fatalf("explicit require_kernel unexpectedly disabled tix_tcp fast path: %q", reason)
	}
}

func TestEffectiveKernelTransportModeKeepsAutoForSecureKernelCryptoTIXTCP(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:         config.TransportProfilePerformance,
			Datapath:        config.TransportDatapathTCXDP,
			Encryption:      securetransport.EncryptionSecure,
			CryptoPlacement: string(dataplane.CryptoPlacementKernel),
			Candidates:      []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolTIXTCP),
			Enabled:   true,
		}},
	}

	if got := effectiveKernelTransportModeForDesired(desired); got != dataplane.KernelTransportModeAuto {
		t.Fatalf("kernel transport mode = %q, want auto for secure kernel-crypto tix_tcp", got)
	}
	if tixTCPSecureRouteGSOAsyncForDesired(desired) {
		t.Fatal("TC-XDP secure kernel-crypto tix_tcp should not select route-GSO")
	}
	if reason := tixTCPFastPathDisabledReasonForDesired(desired); reason != "" {
		t.Fatalf("kernel crypto tix_tcp unexpectedly disabled fast path: %q", reason)
	}
}

func TestEffectiveKernelTransportModeRequiresKernelForSecureKernelModuleTIXTCPRouteGSO(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:         config.TransportProfilePerformance,
			Datapath:        config.TransportDatapathKernelModule,
			Encryption:      securetransport.EncryptionSecure,
			CryptoPlacement: string(dataplane.CryptoPlacementKernel),
			Candidates:      []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolTIXTCP),
			Enabled:   true,
		}},
	}

	if !tixTCPSecureRouteGSOAsyncForDesired(desired) {
		t.Fatal("kernel-module secure tix_tcp should select secure route-GSO")
	}
	if got := effectiveKernelTransportModeForDesired(desired); got != dataplane.KernelTransportModeRequireKernel {
		t.Fatalf("kernel transport mode = %q, want require_kernel for secure tix_tcp route-GSO", got)
	}
	if reason := tixTCPFastPathDisabledReasonForDesired(desired); reason != "" {
		t.Fatalf("kernel-module secure tix_tcp unexpectedly disabled fast path: %q", reason)
	}
}

func TestEffectiveKernelTransportModeKeepsAutoForTCXDPPlaintextPerformanceTIXTCP(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfilePerformance,
			Datapath:   config.TransportDatapathTCXDP,
			Encryption: securetransport.EncryptionPlaintext,
			Candidates: []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolTIXTCP),
			Enabled:   true,
		}},
	}

	if got := effectiveKernelTransportModeForDesired(desired); got != dataplane.KernelTransportModeAuto {
		t.Fatalf("kernel transport mode = %q, want auto for TC-XDP plaintext tix_tcp without route-GSO opt-in", got)
	}
	if reason := tixTCPFastPathDisabledReasonForDesired(desired); reason != "" {
		t.Fatalf("plaintext performance tix_tcp unexpectedly disabled fast path: %q", reason)
	}
}

func TestEffectiveKernelTransportModeRequiresKernelForExplicitPlaintextTIXTCPRouteGSO(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_ROUTE_GSO", "1")
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfilePerformance,
			Datapath:   config.TransportDatapathTCXDP,
			Encryption: securetransport.EncryptionPlaintext,
			Candidates: []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolTIXTCP),
			Enabled:   true,
		}},
	}

	if got := effectiveKernelTransportModeForDesired(desired); got != dataplane.KernelTransportModeRequireKernel {
		t.Fatalf("kernel transport mode = %q, want require_kernel for explicit plaintext tix_tcp route-GSO", got)
	}
	if reason := tixTCPFastPathDisabledReasonForDesired(desired); reason != "" {
		t.Fatalf("explicit plaintext tix_tcp route-GSO unexpectedly disabled fast path: %q", reason)
	}
}
