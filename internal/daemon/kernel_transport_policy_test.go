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
