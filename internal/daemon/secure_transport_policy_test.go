package daemon

import (
	"reflect"
	"testing"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/transport"
	securetransport "trustix.local/trustix/internal/transport/secure"
)

func TestEffectiveSecureTransportCryptoSuitesDefaultKeepsAES256Only(t *testing.T) {
	got := effectiveSecureTransportCryptoSuitesForDesired(config.Desired{})
	want := []string{securetransport.SuiteAES256GCMX25519}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("crypto suites = %#v, want %#v", got, want)
	}
}

func TestEffectiveSecureTransportCryptoSuitesPerformanceKernelSecureOffersAES128(t *testing.T) {
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

	got := effectiveSecureTransportCryptoSuitesForDesired(desired)
	want := []string{securetransport.SuiteAES128GCMX25519, securetransport.SuiteAES256GCMX25519}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("crypto suites = %#v, want %#v", got, want)
	}
}

func TestEffectiveSecureTransportCryptoSuitesExplicitConfigWins(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:         config.TransportProfilePerformance,
			Datapath:        config.TransportDatapathKernelModule,
			Encryption:      securetransport.EncryptionSecure,
			CryptoPlacement: string(dataplane.CryptoPlacementKernel),
			CryptoSuites:    []string{securetransport.SuiteChaCha20Poly1305X25519},
			Candidates:      []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolExperimentalTCP),
			Enabled:   true,
		}},
	}

	got := effectiveSecureTransportCryptoSuitesForDesired(desired)
	want := []string{securetransport.SuiteChaCha20Poly1305X25519}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("crypto suites = %#v, want explicit %#v", got, want)
	}
}

func TestEffectiveSecureTransportCryptoSuitesUserspaceCryptoKeepsDefault(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:         config.TransportProfilePerformance,
			Datapath:        config.TransportDatapathKernelModule,
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

	got := effectiveSecureTransportCryptoSuitesForDesired(desired)
	want := []string{securetransport.SuiteAES256GCMX25519}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("crypto suites = %#v, want %#v", got, want)
	}
}
