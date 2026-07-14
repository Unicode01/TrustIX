package daemon

import (
	"testing"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
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
		{name: "experimental tcp kernel module", transport: string(transport.ProtocolTIXTCP), datapath: config.TransportDatapathKernelModule},
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

func TestTransportProfileFeaturesAdvertiseSafeTIXTCPPerformance(t *testing.T) {
	features := transportProfileFeatures(string(transport.ProtocolTIXTCP), config.EndpointProfileConfig{
		Profile:    config.TransportProfilePerformance,
		Datapath:   config.TransportDatapathTCXDP,
		Encryption: "plaintext",
	})
	for _, feature := range []string{"tixt_v1", "tix_tcp", "tixb_batching", "tc_xdp", "af_xdp", "tc_tx_direct", "plaintext_ack_only"} {
		if !stringListContains(features, feature) {
			t.Fatalf("performance tix_tcp features = %#v, want %q", features, feature)
		}
	}
	for _, feature := range []string{"route_gso_async", "route_gso_async_outer_gso", "route_xmit_worker", "route_gso_sync", "tixt_large_frame_rx", "outer_gso_rx", "gso_batch_rx"} {
		if stringListContains(features, feature) {
			t.Fatalf("performance tix_tcp features = %#v, must not advertise opt-in/unselected feature %q", features, feature)
		}
	}
}

func TestTransportProfileFeaturesAdvertiseNativeTunnelTCOffload(t *testing.T) {
	for _, protocol := range []transport.Protocol{
		transport.ProtocolGRE,
		transport.ProtocolIPIP,
		transport.ProtocolVXLAN,
	} {
		t.Run(string(protocol), func(t *testing.T) {
			features := transportProfileFeatures(string(protocol), config.EndpointProfileConfig{
				Profile:    config.TransportProfileStable,
				Datapath:   config.TransportDatapathTCXDP,
				Encryption: "secure",
			})
			for _, feature := range []string{"native_tunnel", "tc_xdp", "tunnel_tc_offload"} {
				if !stringListContains(features, feature) {
					t.Fatalf("TC tunnel features = %#v, want %q", features, feature)
				}
			}
		})
	}
}

func TestTransportProfileMetadataForDesiredAdvertisesFullKmodRuntimeGate(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:         config.TransportProfilePerformance,
			Datapath:        config.TransportDatapathKernelModule,
			Encryption:      "plaintext",
			CryptoPlacement: string(dataplane.CryptoPlacementUserspace),
			KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
			Candidates:      []core.EndpointID{"exp-full"},
		},
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-full",
			Transport: string(transport.ProtocolTIXTCP),
			Enabled:   true,
		}},
	}

	profile := endpointTransportProfileMetadataForDesired(desired.Endpoints[0], desired)
	for _, feature := range []string{"full_kmod", "tix_tcp_full_kmod", "kernel_datapath_full_plaintext", "rx_worker", "tx_plaintext"} {
		if !stringListContains(profile.Features, feature) {
			t.Fatalf("full-kmod metadata features = %#v, missing %q", profile.Features, feature)
		}
	}
	if stringListContains(profile.Features, "route_gso") {
		t.Fatalf("full-kmod metadata features = %#v, should not advertise route-GSO", profile.Features)
	}
}

func TestTransportProfileMetadataForDesiredAdvertisesPlaintextRouteGSORuntimeGate(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:         config.TransportProfilePerformance,
			Datapath:        config.TransportDatapathKernelModule,
			Encryption:      "plaintext",
			CryptoPlacement: string(dataplane.CryptoPlacementUserspace),
			KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
			Candidates:      []core.EndpointID{"exp-route"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-route",
			Transport: string(transport.ProtocolTIXTCP),
			Enabled:   true,
		}},
	}

	profile := endpointTransportProfileMetadataForDesired(desired.Endpoints[0], desired)
	for _, feature := range []string{"route_gso", "route_gso_async", "route_gso_sync", "route_tcp_kfunc", "route_xmit_worker"} {
		if !stringListContains(profile.Features, feature) {
			t.Fatalf("route-GSO metadata features = %#v, missing %q", profile.Features, feature)
		}
	}
	for _, feature := range []string{"full_kmod", "tix_tcp_full_kmod", "kernel_datapath_full_plaintext"} {
		if stringListContains(profile.Features, feature) {
			t.Fatalf("route-GSO metadata features = %#v, should not advertise %q", profile.Features, feature)
		}
	}
}

func TestTransportProfileMetadataForDesiredAdvertisesSecureKernelRuntimeGates(t *testing.T) {
	for _, test := range []struct {
		name       string
		transport  transport.Protocol
		datapath   string
		want       []string
		mustAbsent []string
	}{
		{
			name:      "secure kernel udp",
			transport: transport.ProtocolUDP,
			datapath:  config.TransportDatapathTCXDP,
			want:      []string{"kernel_crypto", "route_gso", "route_tcp_kfunc", "secure_kudp"},
			mustAbsent: []string{
				"secure_tix_tcp_kernel",
			},
		},
		{
			name:      "secure experimental tcp",
			transport: transport.ProtocolTIXTCP,
			datapath:  config.TransportDatapathKernelModule,
			want:      []string{"kernel_crypto", "route_gso", "route_tcp_kfunc", "secure_tix_tcp_kernel"},
			mustAbsent: []string{
				"secure_kudp",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			desired := config.Desired{
				TransportPolicy: config.TransportPolicyConfig{
					Profile:         config.TransportProfilePerformance,
					Datapath:        test.datapath,
					Encryption:      "secure",
					CryptoPlacement: string(dataplane.CryptoPlacementKernel),
					KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
					Candidates:      []core.EndpointID{"secure"},
				},
				Endpoints: []config.EndpointConfig{{
					Name:      "secure",
					Transport: string(test.transport),
					Enabled:   true,
				}},
			}

			profile := endpointTransportProfileMetadataForDesired(desired.Endpoints[0], desired)
			for _, feature := range test.want {
				if !stringListContains(profile.Features, feature) {
					t.Fatalf("%s metadata features = %#v, missing %q", test.name, profile.Features, feature)
				}
			}
			for _, feature := range test.mustAbsent {
				if stringListContains(profile.Features, feature) {
					t.Fatalf("%s metadata features = %#v, should not advertise %q", test.name, profile.Features, feature)
				}
			}
		})
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

func TestEndpointTransportProfileCompatibleRequiresNativeTunnelTCOffload(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				Profiles: []config.TransportProfileConfig{{
					Transport:  string(transport.ProtocolGRE),
					Profile:    config.TransportProfileStable,
					Datapath:   config.TransportDatapathTCXDP,
					Encryption: "secure",
				}},
			},
		},
	}
	endpoint := config.EndpointConfig{
		Transport: string(transport.ProtocolGRE),
		Profile: config.EndpointProfileConfig{
			Version:  transportProfileMetadataVersion,
			Profile:  config.TransportProfileStable,
			Datapath: config.TransportDatapathUserspace,
			Features: []string{"native_tunnel"},
		},
	}

	if daemon.endpointTransportProfileCompatible(endpoint) {
		t.Fatal("TC tunnel endpoint without TC offload features should be incompatible")
	}
}
