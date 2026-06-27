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

func TestEffectiveKernelTransportModeDisablesEmptyPolicyForUserspaceExperimentalTCP(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Candidates: []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolExperimentalTCP),
			Enabled:   true,
		}},
	}

	if got := effectiveKernelTransportModeForDesired(desired); got != dataplane.KernelTransportModeDisabled {
		t.Fatalf("kernel transport mode = %q, want disabled for empty userspace experimental_tcp policy", got)
	}
}

func TestEffectiveKernelTransportModePreservesExplicitAutoForUserspaceExperimentalTCP(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeAuto)},
			Candidates:      []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolExperimentalTCP),
			Enabled:   true,
		}},
	}

	if got := effectiveKernelTransportModeForDesired(desired); got != dataplane.KernelTransportModeAuto {
		t.Fatalf("kernel transport mode = %q, want explicit auto for userspace experimental_tcp policy", got)
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

func TestEffectiveKernelTransportModeDisablesAutoForSecureUserspaceExperimentalTCP(t *testing.T) {
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
			Transport: string(transport.ProtocolExperimentalTCP),
			Enabled:   true,
		}},
	}

	if got := effectiveKernelTransportModeForDesired(desired); got != dataplane.KernelTransportModeDisabled {
		t.Fatalf("kernel transport mode = %q, want disabled for secure userspace-crypto experimental_tcp", got)
	}
	if reason := experimentalTCPFastPathDisabledReasonForDesired(desired); reason == "" {
		t.Fatal("experimental_tcp fast path disabled reason is empty")
	}
}

func TestEffectiveKernelTransportModeKeepsAutoForMixedUDPAndSecureUserspaceExperimentalTCP(t *testing.T) {
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
					Transport:       string(transport.ProtocolExperimentalTCP),
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
				Transport: string(transport.ProtocolExperimentalTCP),
				Enabled:   true,
			},
		},
	}

	if got := effectiveKernelTransportModeForDesired(desired); got != dataplane.KernelTransportModeAuto {
		t.Fatalf("kernel transport mode = %q, want auto so UDP/full-kmod remains available", got)
	}
	if reason := experimentalTCPFastPathDisabledReasonForDesired(desired); reason == "" {
		t.Fatal("mixed policy should still disable only the unsafe experimental_tcp fast path")
	}
}

func TestEffectiveKernelTransportModeKeepsExplicitRequireForSecureUserspaceExperimentalTCP(t *testing.T) {
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
			Transport: string(transport.ProtocolExperimentalTCP),
			Enabled:   true,
		}},
	}

	if got := effectiveKernelTransportModeForDesired(desired); got != dataplane.KernelTransportModeRequireKernel {
		t.Fatalf("kernel transport mode = %q, want explicit require_kernel", got)
	}
	if reason := experimentalTCPFastPathDisabledReasonForDesired(desired); reason != "" {
		t.Fatalf("explicit require_kernel unexpectedly disabled experimental_tcp fast path: %q", reason)
	}
}

func TestEffectiveKernelTransportModeKeepsAutoForSecureKernelCryptoExperimentalTCP(t *testing.T) {
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
			Transport: string(transport.ProtocolExperimentalTCP),
			Enabled:   true,
		}},
	}

	if got := effectiveKernelTransportModeForDesired(desired); got != dataplane.KernelTransportModeAuto {
		t.Fatalf("kernel transport mode = %q, want auto for secure kernel-crypto experimental_tcp", got)
	}
	if experimentalTCPSecureRouteGSOAsyncForDesired(desired) {
		t.Fatal("TC-XDP secure kernel-crypto experimental_tcp should not select route-GSO")
	}
	if reason := experimentalTCPFastPathDisabledReasonForDesired(desired); reason != "" {
		t.Fatalf("kernel crypto experimental_tcp unexpectedly disabled fast path: %q", reason)
	}
}

func TestEffectiveKernelTransportModeRequiresKernelForSecureKernelModuleExperimentalTCPRouteGSO(t *testing.T) {
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
			Transport: string(transport.ProtocolExperimentalTCP),
			Enabled:   true,
		}},
	}

	if !experimentalTCPSecureRouteGSOAsyncForDesired(desired) {
		t.Fatal("kernel-module secure experimental_tcp should select secure route-GSO")
	}
	if got := effectiveKernelTransportModeForDesired(desired); got != dataplane.KernelTransportModeRequireKernel {
		t.Fatalf("kernel transport mode = %q, want require_kernel for secure experimental_tcp route-GSO", got)
	}
	if reason := experimentalTCPFastPathDisabledReasonForDesired(desired); reason != "" {
		t.Fatalf("kernel-module secure experimental_tcp unexpectedly disabled fast path: %q", reason)
	}
}

func TestEffectiveKernelTransportModeKeepsAutoForTCXDPPlaintextPerformanceExperimentalTCP(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfilePerformance,
			Datapath:   config.TransportDatapathTCXDP,
			Encryption: securetransport.EncryptionPlaintext,
			Candidates: []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolExperimentalTCP),
			Enabled:   true,
		}},
	}

	if got := effectiveKernelTransportModeForDesired(desired); got != dataplane.KernelTransportModeAuto {
		t.Fatalf("kernel transport mode = %q, want auto for TC-XDP plaintext experimental_tcp without route-GSO opt-in", got)
	}
	if reason := experimentalTCPFastPathDisabledReasonForDesired(desired); reason != "" {
		t.Fatalf("plaintext performance experimental_tcp unexpectedly disabled fast path: %q", reason)
	}
}

func TestEffectiveKernelTransportModeRequiresKernelForExplicitPlaintextExperimentalTCPRouteGSO(t *testing.T) {
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO", "1")
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfilePerformance,
			Datapath:   config.TransportDatapathTCXDP,
			Encryption: securetransport.EncryptionPlaintext,
			Candidates: []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolExperimentalTCP),
			Enabled:   true,
		}},
	}

	if got := effectiveKernelTransportModeForDesired(desired); got != dataplane.KernelTransportModeRequireKernel {
		t.Fatalf("kernel transport mode = %q, want require_kernel for explicit plaintext experimental_tcp route-GSO", got)
	}
	if reason := experimentalTCPFastPathDisabledReasonForDesired(desired); reason != "" {
		t.Fatalf("explicit plaintext experimental_tcp route-GSO unexpectedly disabled fast path: %q", reason)
	}
}
