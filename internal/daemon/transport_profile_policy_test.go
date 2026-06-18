package daemon

import (
	"testing"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/transport"
)

func TestEndpointTransportProfileCompatibleDerivesEmptyPerformanceFeatures(t *testing.T) {
	tests := []struct {
		name      string
		transport string
		datapath  string
	}{
		{name: "udp tc xdp", transport: string(transport.ProtocolUDP), datapath: config.TransportDatapathTCXDP},
		{name: "udp kernel module", transport: string(transport.ProtocolUDP), datapath: config.TransportDatapathKernelModule},
		{name: "experimental tcp kernel module", transport: string(transport.ProtocolExperimentalTCP), datapath: config.TransportDatapathKernelModule},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			daemon := &Daemon{
				desired: config.Desired{
					TransportPolicy: config.TransportPolicyConfig{
						Profiles: []config.TransportProfileConfig{{
							Transport: test.transport,
							Profile:   config.TransportProfilePerformance,
							Datapath:  test.datapath,
						}},
					},
				},
			}
			endpoint := config.EndpointConfig{
				Transport: test.transport,
				Profile: config.EndpointProfileConfig{
					Version:  transportProfileMetadataVersion,
					Profile:  config.TransportProfilePerformance,
					Datapath: test.datapath,
				},
			}

			if !daemon.endpointTransportProfileCompatible(endpoint) {
				t.Fatalf("performance endpoint with derived %s features should be compatible", test.datapath)
			}
		})
	}
}

func TestEndpointTransportProfileCompatibleRejectsStableWithoutPerformanceFeatures(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				Profile:  config.TransportProfilePerformance,
				Datapath: config.TransportDatapathKernelModule,
			},
		},
	}
	endpoint := config.EndpointConfig{
		Transport: string(transport.ProtocolUDP),
		Profile: config.EndpointProfileConfig{
			Version:  transportProfileMetadataVersion,
			Profile:  config.TransportProfileStable,
			Datapath: config.TransportDatapathKernelModule,
		},
	}

	if daemon.endpointTransportProfileCompatible(endpoint) {
		t.Fatal("stable endpoint without performance features should be incompatible")
	}
}

func TestEndpointTransportProfileCompatibleKeepsExplicitFeaturesStrict(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				Profile:  config.TransportProfilePerformance,
				Datapath: config.TransportDatapathKernelModule,
			},
		},
	}
	endpoint := config.EndpointConfig{
		Transport: string(transport.ProtocolUDP),
		Profile: config.EndpointProfileConfig{
			Version:  transportProfileMetadataVersion,
			Profile:  config.TransportProfilePerformance,
			Datapath: config.TransportDatapathKernelModule,
			Features: []string{"tixt_v1"},
		},
	}

	if daemon.endpointTransportProfileCompatible(endpoint) {
		t.Fatal("explicit endpoint features missing required performance features should be incompatible")
	}
}

func TestTransportProfileFeaturesAdvertiseSecureKernelUDPDirect(t *testing.T) {
	features := transportProfileFeatures(string(transport.ProtocolUDP), config.EndpointProfileConfig{
		Profile:         config.TransportProfilePerformance,
		Datapath:        config.TransportDatapathTCXDP,
		Encryption:      "secure",
		CryptoPlacement: "kernel",
	})
	for _, feature := range []string{"secure_tx_direct", "secure_rx_direct", "secure_trust_inner_checksum"} {
		if !stringListContains(features, feature) {
			t.Fatalf("performance secure UDP features = %#v, want %q", features, feature)
		}
	}
	if stringListContains(features, "secure_kfunc_seal") {
		t.Fatalf("performance secure UDP features = %#v, should not advertise opt-in kfunc seal by default", features)
	}
}

func TestTransportProfileFeaturesAdvertiseSafeExperimentalTCPPerformance(t *testing.T) {
	features := transportProfileFeatures(string(transport.ProtocolExperimentalTCP), config.EndpointProfileConfig{
		Profile:    config.TransportProfilePerformance,
		Datapath:   config.TransportDatapathTCXDP,
		Encryption: "plaintext",
	})
	for _, feature := range []string{"tixt_v1", "ackless_tcp", "tixb_batching", "tc_xdp", "af_xdp", "tc_tx_direct", "plaintext_ack_only"} {
		if !stringListContains(features, feature) {
			t.Fatalf("performance experimental_tcp features = %#v, want %q", features, feature)
		}
	}
	for _, feature := range []string{"route_gso_async", "route_gso_async_outer_gso", "route_xmit_worker", "route_gso_sync", "tixt_large_frame_rx", "outer_gso_rx", "gso_batch_rx"} {
		if stringListContains(features, feature) {
			t.Fatalf("performance experimental_tcp features = %#v, must not advertise opt-in/unselected feature %q", features, feature)
		}
	}
}

func TestEndpointTransportProfileCompatibleRequiresSecureKernelUDPDirectFeatures(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				Profiles: []config.TransportProfileConfig{{
					Transport:       string(transport.ProtocolUDP),
					Profile:         config.TransportProfilePerformance,
					Datapath:        config.TransportDatapathTCXDP,
					Encryption:      "secure",
					CryptoPlacement: "kernel",
				}},
			},
		},
	}
	endpoint := config.EndpointConfig{
		Transport: string(transport.ProtocolUDP),
		Profile: config.EndpointProfileConfig{
			Version:  transportProfileMetadataVersion,
			Profile:  config.TransportProfilePerformance,
			Datapath: config.TransportDatapathTCXDP,
			Features: []string{"tixt_v1", "kernel_udp", "large_frame_rx", "gso_rx", "gro_rx"},
		},
	}

	if daemon.endpointTransportProfileCompatible(endpoint) {
		t.Fatal("secure kernel UDP performance endpoint without secure direct features should be incompatible")
	}
}
