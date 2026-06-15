package daemon

import (
	"path/filepath"
	"testing"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/transport"
	securetransport "trustix.local/trustix/internal/transport/secure"
)

func TestDataplaneAttachSpecUsesExistingLANMode(t *testing.T) {
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface:            "br-lan",
			UnderlayIface:    "eth0",
			Gateway:          "192.168.0.1/24",
			AttachMode:       config.LANAttachModeExisting,
			ManageAddress:    true,
			ManageForwarding: true,
			ManageRPFilter:   true,
		},
	})

	if spec.LANAttachMode != string(config.LANAttachModeExisting) {
		t.Fatalf("LANAttachMode = %q, want existing", spec.LANAttachMode)
	}
	if spec.ManageAddress {
		t.Fatal("existing LAN attach mode must not manage addresses")
	}
	if !spec.ManageQdisc || !spec.ManageForwarding || !spec.ManageRPFilter {
		t.Fatalf("management flags = qdisc:%t forwarding:%t rp_filter:%t", spec.ManageQdisc, spec.ManageForwarding, spec.ManageRPFilter)
	}
	if spec.PinPath != filepath.Join(filepath.Dir(spec.PinPath), filepath.Base(spec.PinPath)) || filepath.Base(spec.PinPath) != "bpf" {
		t.Fatalf("pin path = %q, want data-dir bpf child", spec.PinPath)
	}
}

func TestDataplaneAttachSpecDefaultsLANAttachMode(t *testing.T) {
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface:         "br-lan",
			Gateway:       "192.168.0.1/24",
			ManageAddress: true,
		},
	})

	if spec.LANAttachMode != string(config.LANAttachModeManaged) {
		t.Fatalf("LANAttachMode = %q, want managed", spec.LANAttachMode)
	}
	if !spec.ManageAddress {
		t.Fatal("managed LAN attach mode should preserve manage_address")
	}
}

func TestDataplaneAttachSpecIncludesMultipleLANs(t *testing.T) {
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			ID:               "home",
			Iface:            "br-lan",
			UnderlayIface:    "eth0",
			Gateway:          "192.168.1.1/24",
			Advertise:        []core.Prefix{"192.168.1.0/24"},
			ManageAddress:    true,
			ManageForwarding: true,
			ManageRPFilter:   true,
		},
		LANs: []config.LANConfig{{
			ID:            "public",
			Type:          config.LANTypeTrustedPublic,
			Iface:         "eth1",
			UnderlayIface: "wan0",
			Gateway:       "10.10.0.1/24",
			Advertise:     []core.Prefix{"10.10.0.0/24"},
			AttachMode:    config.LANAttachModeExisting,
			ManageAddress: true,
			DeviceAccess: config.DeviceAccessConfig{
				Enabled:     true,
				AddressPool: "10.10.0.128/25",
			},
		}},
	})

	if spec.LANIface != "br-lan" || spec.UnderlayIface != "eth0" || spec.Gateway != "192.168.1.1/24" {
		t.Fatalf("primary legacy fields = iface:%q underlay:%q gateway:%q", spec.LANIface, spec.UnderlayIface, spec.Gateway)
	}
	if len(spec.LANs) != 2 {
		t.Fatalf("LANs = %#v, want two", spec.LANs)
	}
	if spec.LANs[0].ID != "home" || spec.LANs[0].Iface != "br-lan" || !spec.LANs[0].ManageAddress || !spec.LANs[0].ManageForwarding || !spec.LANs[0].ManageRPFilter {
		t.Fatalf("primary LAN attach spec = %#v", spec.LANs[0])
	}
	if spec.LANs[1].ID != "public" || spec.LANs[1].Type != string(config.LANTypeTrustedPublic) || spec.LANs[1].Iface != "eth1" || spec.LANs[1].UnderlayIface != "wan0" {
		t.Fatalf("secondary LAN attach spec = %#v", spec.LANs[1])
	}
	if spec.LANs[1].ManageAddress {
		t.Fatal("existing secondary LAN attach mode must not manage addresses")
	}
	if !spec.LANs[1].DeviceAccess || spec.LANs[1].DeviceAccessPool != "10.10.0.128/25" {
		t.Fatalf("secondary LAN device access fields = %#v", spec.LANs[1])
	}
	if len(spec.LANs[1].Advertise) != 1 || spec.LANs[1].Advertise[0] != "10.10.0.0/24" {
		t.Fatalf("secondary LAN advertise = %#v", spec.LANs[1].Advertise)
	}
}

func TestDataplaneAttachSpecKeepsUserspaceFallbackForPlaintextUDPByDefault(t *testing.T) {
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface: "br-lan",
		},
		TransportPolicy: config.TransportPolicyConfig{
			Encryption: securetransport.EncryptionPlaintext,
			Candidates: []core.EndpointID{"udp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "udp-a",
			Transport: string(transport.ProtocolUDP),
			Enabled:   true,
		}},
	})

	if spec.KernelUDPTXDirectOnly || spec.KernelUDPTXDirectOnlyReason != "" {
		t.Fatalf("ordinary plaintext UDP should keep userspace fallback available, spec=%#v", spec)
	}
	if spec.ExperimentalTCPTXDirect {
		t.Fatalf("ordinary plaintext UDP should not request experimental_tcp TX direct protection, spec=%#v", spec)
	}
}

func TestDataplaneAttachSpecMarksExperimentalTCPTXDirect(t *testing.T) {
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT", "1")
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface:      "br-lan",
			AttachMode: config.LANAttachModeExisting,
		},
		TransportPolicy: config.TransportPolicyConfig{
			Encryption: securetransport.EncryptionPlaintext,
			Candidates: []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolExperimentalTCP),
			Enabled:   true,
		}},
	})

	if !spec.ExperimentalTCPTXDirect {
		t.Fatalf("experimental_tcp TC direct policy was not marked in attach spec: %#v", spec)
	}
}

func TestDataplaneAttachSpecEnablesPerformancePlaintextExperimentalTCPRouteGSO(t *testing.T) {
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface:      "br-lan",
			AttachMode: config.LANAttachModeExisting,
		},
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
	})

	if !spec.ExperimentalTCPTXDirect || !spec.KernelUDPTXDirectOnly {
		t.Fatalf("performance plaintext experimental_tcp should enable direct route-GSO path, spec=%#v", spec)
	}
	if !spec.ExperimentalTCPRouteGSOAsync || !spec.ExperimentalTCPRouteGSOSync || !spec.ExperimentalTCPRouteXmitWorker || !spec.ExperimentalTCPPlainSkipSequence || !spec.ExperimentalTCPPlainACKOnly {
		t.Fatalf("performance plaintext experimental_tcp route-GSO flags missing, spec=%#v", spec)
	}
	if !spec.KernelDatapathSuppressLegacyRXWorker {
		t.Fatalf("performance plaintext experimental_tcp should suppress legacy RX worker ownership, spec=%#v", spec)
	}
	if spec.KernelUDPTXDirectOnlyReason != "transport_policy.experimental_tcp=performance route_gso_async_outer_gso=enabled encryption=plaintext" {
		t.Fatalf("direct-only reason = %q", spec.KernelUDPTXDirectOnlyReason)
	}
}

func TestDataplaneAttachSpecMigratesKernelModuleExperimentalTCPToRouteGSO(t *testing.T) {
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface:      "br-lan",
			AttachMode: config.LANAttachModeExisting,
		},
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfilePerformance,
		},
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfilePerformance,
			Datapath:   config.TransportDatapathKernelModule,
			Encryption: securetransport.EncryptionPlaintext,
			Candidates: []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolExperimentalTCP),
			Enabled:   true,
		}},
	})

	if !spec.ExperimentalTCPTXDirect || !spec.KernelUDPTXDirectOnly {
		t.Fatalf("performance experimental_tcp kernel_module should migrate to route-GSO direct path, spec=%#v", spec)
	}
	if !spec.ExperimentalTCPRouteGSOAsync || !spec.ExperimentalTCPRouteGSOSync || !spec.ExperimentalTCPRouteXmitWorker {
		t.Fatalf("performance experimental_tcp kernel_module route-GSO flags missing, spec=%#v", spec)
	}
	if !spec.KernelDatapathSuppressLegacyRXWorker {
		t.Fatalf("performance experimental_tcp kernel_module should suppress legacy RX worker ownership, spec=%#v", spec)
	}
}

func TestDataplaneAttachSpecKeepsFullPlaintextExperimentalTCPOnRXWorker(t *testing.T) {
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface:      "br-lan",
			AttachMode: config.LANAttachModeExisting,
		},
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
		},
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfileStable,
			Datapath:   config.TransportDatapathKernelModule,
			Encryption: securetransport.EncryptionPlaintext,
			Candidates: []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolExperimentalTCP),
			Enabled:   true,
		}},
	})

	if spec.ExperimentalTCPTXDirect || spec.KernelUDPTXDirectOnly {
		t.Fatalf("full plaintext experimental_tcp should not migrate to route-GSO direct path, spec=%#v", spec)
	}
	if spec.ExperimentalTCPRouteGSOAsync || spec.ExperimentalTCPRouteGSOSync || spec.ExperimentalTCPRouteXmitWorker || spec.ExperimentalTCPPlainSkipSequence || spec.ExperimentalTCPPlainACKOnly {
		t.Fatalf("full plaintext experimental_tcp should keep route-GSO flags off, spec=%#v", spec)
	}
	if spec.KernelDatapathSuppressLegacyRXWorker {
		t.Fatalf("full plaintext experimental_tcp should keep RX worker ownership, spec=%#v", spec)
	}
}

func TestDataplaneAttachSpecKeepsFullPlaintextPerformanceExperimentalTCPOnRXWorker(t *testing.T) {
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface:      "br-lan",
			AttachMode: config.LANAttachModeExisting,
		},
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
		},
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfilePerformance,
			Datapath:   config.TransportDatapathKernelModule,
			Encryption: securetransport.EncryptionPlaintext,
			Candidates: []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolExperimentalTCP),
			Enabled:   true,
		}},
	})

	if spec.ExperimentalTCPTXDirect || spec.KernelUDPTXDirectOnly {
		t.Fatalf("full plaintext performance experimental_tcp should prefer full-kmod over route-GSO, spec=%#v", spec)
	}
	if spec.ExperimentalTCPRouteGSOAsync || spec.ExperimentalTCPRouteGSOSync || spec.ExperimentalTCPRouteXmitWorker || spec.ExperimentalTCPPlainSkipSequence || spec.ExperimentalTCPPlainACKOnly {
		t.Fatalf("full plaintext performance experimental_tcp should keep route-GSO flags off, spec=%#v", spec)
	}
	if spec.KernelDatapathSuppressLegacyRXWorker {
		t.Fatalf("full plaintext performance experimental_tcp should keep RX worker ownership, spec=%#v", spec)
	}
}

func TestDataplaneAttachSpecKeepsFullPlaintextFallbackWhenRouteGSOExplicitlyDisabled(t *testing.T) {
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO", "0")
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface:      "br-lan",
			AttachMode: config.LANAttachModeExisting,
		},
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
		},
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfileStable,
			Datapath:   config.TransportDatapathKernelModule,
			Encryption: securetransport.EncryptionPlaintext,
			Candidates: []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolExperimentalTCP),
			Enabled:   true,
		}},
	})

	if spec.ExperimentalTCPTXDirect || spec.KernelUDPTXDirectOnly || spec.ExperimentalTCPRouteGSOAsync || spec.ExperimentalTCPRouteGSOSync || spec.ExperimentalTCPRouteXmitWorker {
		t.Fatalf("explicit TC direct disable should keep route-GSO off for full plaintext fallback, spec=%#v", spec)
	}
	if spec.KernelDatapathSuppressLegacyRXWorker {
		t.Fatalf("explicit TC direct disable should keep legacy RX worker ownership available, spec=%#v", spec)
	}
}

func TestDataplaneAttachSpecKeepsFullPlaintextFallbackWhenKernelTransportDisabled(t *testing.T) {
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface:      "br-lan",
			AttachMode: config.LANAttachModeExisting,
		},
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
		},
		TransportPolicy: config.TransportPolicyConfig{
			Profile:         config.TransportProfileStable,
			Datapath:        config.TransportDatapathKernelModule,
			Encryption:      securetransport.EncryptionPlaintext,
			KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeDisabled)},
			Candidates:      []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolExperimentalTCP),
			Enabled:   true,
		}},
	})

	if spec.ExperimentalTCPTXDirect || spec.KernelUDPTXDirectOnly || spec.ExperimentalTCPRouteGSOAsync || spec.ExperimentalTCPRouteGSOSync || spec.ExperimentalTCPRouteXmitWorker {
		t.Fatalf("disabled kernel_transport should keep route-GSO off for full plaintext fallback, spec=%#v", spec)
	}
	if spec.KernelDatapathSuppressLegacyRXWorker {
		t.Fatalf("disabled kernel_transport should keep legacy RX worker ownership available, spec=%#v", spec)
	}
}

func TestDataplaneAttachSpecGenericUDPDirectDisableKeepsFullPlaintextExperimentalTCP(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "0")
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface:      "br-lan",
			AttachMode: config.LANAttachModeExisting,
		},
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
		},
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfileStable,
			Datapath:   config.TransportDatapathKernelModule,
			Encryption: securetransport.EncryptionPlaintext,
			Candidates: []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolExperimentalTCP),
			Enabled:   true,
		}},
	})

	if spec.ExperimentalTCPTXDirect || spec.KernelUDPTXDirectOnly {
		t.Fatalf("generic UDP direct disable should keep full plaintext experimental_tcp off route-GSO, spec=%#v", spec)
	}
	if spec.ExperimentalTCPRouteGSOAsync || spec.ExperimentalTCPRouteGSOSync || spec.ExperimentalTCPRouteXmitWorker {
		t.Fatalf("generic UDP direct disable should keep route-GSO flags off for full plaintext, spec=%#v", spec)
	}
	if spec.KernelDatapathSuppressLegacyRXWorker {
		t.Fatalf("generic UDP direct disable should keep full plaintext RX worker ownership, spec=%#v", spec)
	}
}

func TestDataplaneAttachSpecDisablesExperimentalTCPFastPathForMixedTCP(t *testing.T) {
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface:      "br-lan",
			AttachMode: config.LANAttachModeExisting,
		},
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfilePerformance,
			Datapath:   config.TransportDatapathTCXDP,
			Encryption: securetransport.EncryptionPlaintext,
			Candidates: []core.EndpointID{"tcp-a", "exp-a"},
		},
		Endpoints: []config.EndpointConfig{
			{
				Name:      "tcp-a",
				Transport: string(transport.ProtocolTCP),
				Enabled:   true,
			},
			{
				Name:      "exp-a",
				Transport: string(transport.ProtocolExperimentalTCP),
				Enabled:   true,
			},
		},
	})

	if !spec.ExperimentalTCPFastPathDisabled || spec.ExperimentalTCPFastPathDisabledReason == "" {
		t.Fatalf("mixed tcp+experimental_tcp should disable experimental_tcp fast path, spec=%#v", spec)
	}
	if spec.ExperimentalTCPTXDirect || spec.KernelUDPTXDirectOnly || spec.ExperimentalTCPRouteGSOAsync || spec.ExperimentalTCPRouteGSOSync || spec.ExperimentalTCPRouteXmitWorker {
		t.Fatalf("mixed tcp+experimental_tcp enabled experimental_tcp direct flags, spec=%#v", spec)
	}
}

func TestDataplaneAttachSpecKeepsExperimentalTCPFastPathForMixedUDP(t *testing.T) {
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface:      "br-lan",
			AttachMode: config.LANAttachModeExisting,
		},
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfilePerformance,
			Datapath:   config.TransportDatapathTCXDP,
			Encryption: securetransport.EncryptionPlaintext,
			Candidates: []core.EndpointID{"udp-a", "exp-a"},
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
	})

	if spec.ExperimentalTCPFastPathDisabled {
		t.Fatalf("udp+experimental_tcp should keep experimental_tcp fast path enabled, spec=%#v", spec)
	}
	if !spec.ExperimentalTCPTXDirect || !spec.KernelUDPTXDirectOnly || !spec.ExperimentalTCPRouteGSOAsync {
		t.Fatalf("udp+experimental_tcp performance policy should keep direct route-GSO, spec=%#v", spec)
	}
}

func TestDataplaneAttachSpecAllowsForcedMixedTCPExperimentalTCPFastPath(t *testing.T) {
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_ALLOW_MIXED_TCP_FAST_PATH", "1")
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface:      "br-lan",
			AttachMode: config.LANAttachModeExisting,
		},
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfilePerformance,
			Datapath:   config.TransportDatapathTCXDP,
			Encryption: securetransport.EncryptionPlaintext,
			Candidates: []core.EndpointID{"tcp-a", "exp-a"},
		},
		Endpoints: []config.EndpointConfig{
			{
				Name:      "tcp-a",
				Transport: string(transport.ProtocolTCP),
				Enabled:   true,
			},
			{
				Name:      "exp-a",
				Transport: string(transport.ProtocolExperimentalTCP),
				Enabled:   true,
			},
		},
	})

	if spec.ExperimentalTCPFastPathDisabled {
		t.Fatalf("forced mixed tcp+experimental_tcp unexpectedly disabled fast path, spec=%#v", spec)
	}
	if !spec.ExperimentalTCPTXDirect || !spec.KernelUDPTXDirectOnly || !spec.ExperimentalTCPRouteGSOAsync {
		t.Fatalf("forced mixed tcp+experimental_tcp did not enable direct route-GSO, spec=%#v", spec)
	}
}

func TestDataplaneAttachSpecKeepsFallbackForRequireKernelPlaintextByDefault(t *testing.T) {
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface: "br-lan",
		},
		TransportPolicy: config.TransportPolicyConfig{
			KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
			Encryption:      securetransport.EncryptionPlaintext,
			Candidates:      []core.EndpointID{"udp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "udp-a",
			Transport: string(transport.ProtocolUDP),
			Enabled:   true,
		}},
	})

	if spec.KernelUDPTXDirectOnly || spec.KernelUDPTXDirectOnlyReason != "" {
		t.Fatalf("require_kernel plaintext UDP should keep capture fallback unless TC-only provider is explicit, spec=%#v", spec)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")
	spec = dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface: "br-lan",
		},
		TransportPolicy: config.TransportPolicyConfig{
			KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
			Encryption:      securetransport.EncryptionPlaintext,
			Candidates:      []core.EndpointID{"udp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "udp-a",
			Transport: string(transport.ProtocolUDP),
			Enabled:   true,
		}},
	})

	if !spec.KernelUDPTXDirectOnly {
		t.Fatal("explicit TC-only provider should enable kernel_udp TX direct-only")
	}
	if spec.KernelUDPTXDirectOnlyReason != "transport_policy.encryption=plaintext kernel_udp_tc_only_provider=enabled" {
		t.Fatalf("direct-only reason = %q", spec.KernelUDPTXDirectOnlyReason)
	}
}

func TestDataplaneAttachSpecEnablesPerformancePlaintextUDPFullKmod(t *testing.T) {
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface: "br-lan",
		},
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
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfilePerformance,
		},
	})

	if spec.KernelUDPTXDirectOnly {
		t.Fatalf("performance plaintext UDP kernel_module should not use TC-only direct path, spec=%#v", spec)
	}
	if spec.KernelUDPTCOnlyProvider {
		t.Fatalf("performance plaintext UDP kernel_module should not request TC-only provider, spec=%#v", spec)
	}
	if spec.KernelUDPTXDirectOnlyReason != "" {
		t.Fatalf("direct-only reason = %q", spec.KernelUDPTXDirectOnlyReason)
	}
	if spec.ExperimentalTCPTXDirect || spec.ExperimentalTCPRouteGSOAsync {
		t.Fatalf("UDP performance direct path should not enable experimental_tcp route-GSO flags, spec=%#v", spec)
	}
	if !spec.KernelDatapathFullPlaintext {
		t.Fatalf("performance plaintext UDP kernel_module should mark full plaintext ownership, spec=%#v", spec)
	}
}

func TestDataplaneAttachSpecKeepsLegacyFullPlaintextUDPOnRXWorker(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "0")
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface: "br-lan",
		},
		TransportPolicy: config.TransportPolicyConfig{
			Encryption: securetransport.EncryptionPlaintext,
			Candidates: []core.EndpointID{"udp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "udp-a",
			Transport: string(transport.ProtocolUDP),
			Enabled:   true,
		}},
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
		},
	})

	if spec.KernelUDPTXDirectOnly {
		t.Fatalf("full plaintext UDP should not migrate to TC-only direct path, spec=%#v", spec)
	}
	if spec.KernelUDPTCOnlyProvider {
		t.Fatalf("full plaintext UDP should not request TC-only provider, spec=%#v", spec)
	}
	if spec.KernelDatapathSuppressLegacyRXWorker {
		t.Fatalf("full plaintext UDP should keep RX worker ownership, spec=%#v", spec)
	}
	if !spec.KernelDatapathFullPlaintext {
		t.Fatalf("full plaintext UDP should mark full plaintext ownership, spec=%#v", spec)
	}
}

func TestDataplaneAttachSpecKeepsFallbackForPlaintextNonKernelTransport(t *testing.T) {
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface: "br-lan",
		},
		TransportPolicy: config.TransportPolicyConfig{
			Encryption: securetransport.EncryptionPlaintext,
			Candidates: []core.EndpointID{"tcp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "tcp-a",
			Transport: string(transport.ProtocolTCP),
			Enabled:   true,
		}},
	})

	if spec.KernelUDPTXDirectOnly || spec.KernelUDPTXDirectOnlyReason != "" {
		t.Fatalf("plaintext non-kernel transport should keep userspace fallback available, spec=%#v", spec)
	}
}

func TestDataplaneAttachSpecKeepsFallbackWhenEncryptionEnabled(t *testing.T) {
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface: "br-lan",
		},
		TransportPolicy: config.TransportPolicyConfig{
			Encryption: securetransport.EncryptionSecure,
		},
	})

	if spec.KernelUDPTXDirectOnly || spec.KernelUDPTXDirectOnlyReason != "" {
		t.Fatalf("secure transport should keep userspace fallback available, spec=%#v", spec)
	}
}

func TestDataplaneAttachSpecEnablesPerformanceSecureKernelUDPDirect(t *testing.T) {
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface: "br-lan",
		},
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
	})

	if spec.KernelUDPTXDirectOnly || spec.KernelUDPTXDirectOnlyReason != "" {
		t.Fatalf("performance secure UDP should keep userspace fallback, spec=%#v", spec)
	}
	if !spec.KernelUDPTXSecureDirect || !spec.KernelUDPRXSecureDirect {
		t.Fatalf("performance secure UDP should enable TX/RX secure direct, spec=%#v", spec)
	}
	if !spec.KernelUDPSecureDirectTrustInnerChecksums || spec.KernelUDPTXSecureDirectKfuncSeal || spec.KernelUDPTXSecureDirectSKBSealKfunc {
		t.Fatalf("performance secure UDP should trust inner checksums without forcing kfunc seal variants, spec=%#v", spec)
	}
}

func TestDataplaneAttachSpecKeepsStableSecureKernelUDPDirectDisabled(t *testing.T) {
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface: "br-lan",
		},
		TransportPolicy: config.TransportPolicyConfig{
			Profile:         config.TransportProfileStable,
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
	})

	if spec.KernelUDPTXSecureDirect || spec.KernelUDPRXSecureDirect || spec.KernelUDPSecureDirectTrustInnerChecksums {
		t.Fatalf("stable secure UDP should not enable secure direct, spec=%#v", spec)
	}
}

func TestDataplaneAttachSpecKeepsFallbackForRequireKernelSecureKernelCryptoByDefault(t *testing.T) {
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface: "br-lan",
		},
		TransportPolicy: config.TransportPolicyConfig{
			KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
			Encryption:      securetransport.EncryptionSecure,
			CryptoPlacement: string(dataplane.CryptoPlacementKernel),
			Candidates:      []core.EndpointID{"udp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "udp-a",
			Transport: string(transport.ProtocolUDP),
			Enabled:   true,
		}},
	})

	if spec.KernelUDPTXDirectOnly || spec.KernelUDPTXDirectOnlyReason != "" {
		t.Fatalf("require_kernel secure UDP should keep capture fallback unless secure direct-only is explicit, spec=%#v", spec)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "1")
	spec = dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface: "br-lan",
		},
		TransportPolicy: config.TransportPolicyConfig{
			KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
			Encryption:      securetransport.EncryptionSecure,
			CryptoPlacement: string(dataplane.CryptoPlacementKernel),
			Candidates:      []core.EndpointID{"udp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "udp-a",
			Transport: string(transport.ProtocolUDP),
			Enabled:   true,
		}},
	})

	if spec.KernelUDPTXDirectOnly || spec.KernelUDPTXDirectOnlyReason != "" {
		t.Fatalf("TC-only provider alone should not enable secure UDP direct-only, spec=%#v", spec)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_SECURE_DIRECT_ONLY", "1")
	spec = dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface: "br-lan",
		},
		TransportPolicy: config.TransportPolicyConfig{
			KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
			Encryption:      securetransport.EncryptionSecure,
			CryptoPlacement: string(dataplane.CryptoPlacementKernel),
			Candidates:      []core.EndpointID{"udp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "udp-a",
			Transport: string(transport.ProtocolUDP),
			Enabled:   true,
		}},
	})

	if !spec.KernelUDPTXDirectOnly {
		t.Fatal("explicit secure direct-only should enable secure UDP direct-only")
	}
	if spec.KernelUDPTXDirectOnlyReason != "transport_policy.encryption=secure transport_policy.crypto_placement=kernel kernel_udp_tc_only_provider=enabled" {
		t.Fatalf("direct-only reason = %q", spec.KernelUDPTXDirectOnlyReason)
	}
}

func TestDataplaneAttachSpecRecordsForcedExperimentalTCPSecureDirectOnly(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "1")
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface: "br-lan",
		},
		TransportPolicy: config.TransportPolicyConfig{
			KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
			Encryption:      securetransport.EncryptionSecure,
			CryptoPlacement: string(dataplane.CryptoPlacementKernel),
			Candidates:      []core.EndpointID{"experimental-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "experimental-a",
			Transport: string(transport.ProtocolExperimentalTCP),
			Enabled:   true,
		}},
	})

	if !spec.KernelUDPTXDirectOnly {
		t.Fatal("forced direct-only should be reflected in attach spec")
	}
	if spec.KernelUDPTXDirectOnlyReason != "transport_policy.encryption=secure transport_policy.crypto_placement=kernel" {
		t.Fatalf("direct-only reason = %q", spec.KernelUDPTXDirectOnlyReason)
	}
}

func TestDataplaneAttachSpecEnablesPerformanceSecureExperimentalTCPDirect(t *testing.T) {
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface: "br-lan",
		},
		TransportPolicy: config.TransportPolicyConfig{
			Profile:         config.TransportProfilePerformance,
			Datapath:        config.TransportDatapathTCXDP,
			Encryption:      securetransport.EncryptionSecure,
			CryptoPlacement: string(dataplane.CryptoPlacementKernel),
			Candidates:      []core.EndpointID{"experimental-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "experimental-a",
			Transport: string(transport.ProtocolExperimentalTCP),
			Enabled:   true,
		}},
	})

	if spec.KernelUDPTXDirectOnly || spec.KernelUDPTXDirectOnlyReason != "" {
		t.Fatalf("performance secure experimental_tcp should keep userspace fallback, spec=%#v", spec)
	}
	if !spec.ExperimentalTCPTXDirect {
		t.Fatalf("performance secure experimental_tcp should enable TC direct flow-map sync, spec=%#v", spec)
	}
	if !spec.ExperimentalTCPRouteGSOAsync || !spec.ExperimentalTCPRouteGSOSync || !spec.ExperimentalTCPRouteXmitWorker {
		t.Fatalf("performance secure experimental_tcp should enable secure route-GSO, spec=%#v", spec)
	}
	if spec.ExperimentalTCPPlainSkipSequence || spec.ExperimentalTCPPlainACKOnly {
		t.Fatalf("performance secure experimental_tcp must not enable plaintext route-GSO sequence shortcuts, spec=%#v", spec)
	}
	if !spec.KernelUDPTXSecureDirect || !spec.KernelUDPRXSecureDirect {
		t.Fatalf("performance secure experimental_tcp should enable TX/RX secure direct, spec=%#v", spec)
	}
	if !spec.KernelUDPSecureDirectTrustInnerChecksums {
		t.Fatalf("performance secure experimental_tcp should enable secure direct checksum trust, spec=%#v", spec)
	}
}

func TestDataplaneAttachSpecDisablesAutoExperimentalTCPSecureUserspaceFastPath(t *testing.T) {
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface: "br-lan",
		},
		TransportPolicy: config.TransportPolicyConfig{
			Profile:         config.TransportProfilePerformance,
			Datapath:        config.TransportDatapathTCXDP,
			Encryption:      securetransport.EncryptionSecure,
			CryptoPlacement: string(dataplane.CryptoPlacementUserspace),
			Candidates:      []core.EndpointID{"experimental-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "experimental-a",
			Transport: string(transport.ProtocolExperimentalTCP),
			Enabled:   true,
		}},
	})

	if !spec.ExperimentalTCPFastPathDisabled || spec.ExperimentalTCPFastPathDisabledReason == "" {
		t.Fatalf("secure userspace-crypto experimental_tcp auto policy should disable AF_XDP fast path, spec=%#v", spec)
	}
	if spec.ExperimentalTCPTXDirect || spec.ExperimentalTCPRouteGSOAsync || spec.KernelUDPTXDirectOnly {
		t.Fatalf("secure userspace-crypto experimental_tcp auto policy should not request direct TX, spec=%#v", spec)
	}
}

func TestDataplaneAttachSpecKeepsFallbackForRequireKernelSecureUserspaceCrypto(t *testing.T) {
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface: "br-lan",
		},
		TransportPolicy: config.TransportPolicyConfig{
			KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
			Encryption:      securetransport.EncryptionSecure,
			CryptoPlacement: string(dataplane.CryptoPlacementUserspace),
			Candidates:      []core.EndpointID{"udp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "udp-a",
			Transport: string(transport.ProtocolUDP),
			Enabled:   true,
		}},
	})

	if spec.KernelUDPTXDirectOnly || spec.KernelUDPTXDirectOnlyReason != "" {
		t.Fatalf("explicit userspace crypto should keep userspace fallback available, spec=%#v", spec)
	}
}

func TestDataplaneAttachSpecDisablesLANQdiscForNativePlaintextTunnel(t *testing.T) {
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface:            "br-lan",
			UnderlayIface:    "eth0",
			Gateway:          "192.168.0.1/24",
			ManageAddress:    true,
			ManageForwarding: true,
			ManageRPFilter:   true,
		},
		TransportPolicy: config.TransportPolicyConfig{
			Encryption: securetransport.EncryptionPlaintext,
			Candidates: []core.EndpointID{"gre-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "gre-a",
			Transport: string(transport.ProtocolGRE),
			Address:   "local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.0.1/30,remote_carrier=10.255.0.2,mtu=1400",
			Enabled:   true,
		}},
	})

	if spec.ManageQdisc {
		t.Fatal("native plaintext tunnel route offload should not attach LAN TC/qdisc")
	}
	if !spec.ManageAddress || !spec.ManageForwarding || !spec.ManageRPFilter {
		t.Fatalf("non-qdisc management flags changed unexpectedly: address:%t forwarding:%t rp_filter:%t", spec.ManageAddress, spec.ManageForwarding, spec.ManageRPFilter)
	}
	if spec.ManagedMTU != 1400 {
		t.Fatalf("managed MTU = %d, want native tunnel MTU 1400", spec.ManagedMTU)
	}
}

func TestDataplaneAttachSpecDisablesLANQdiscForFullPlaintextDatapath(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")

	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface:         "br-lan",
			UnderlayIface: "eth0",
			Gateway:       "10.81.0.1/24",
			ManageAddress: true,
		},
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
		},
	})

	if spec.ManageQdisc {
		t.Fatal("full plaintext datapath should not attach LAN TC/qdisc")
	}
}

func TestDataplaneAttachSpecKeepsLANQdiscForSecureTunnel(t *testing.T) {
	spec := dataplaneAttachSpec(t.TempDir(), config.Desired{
		LAN: config.LANConfig{
			Iface:         "br-lan",
			UnderlayIface: "eth0",
		},
		TransportPolicy: config.TransportPolicyConfig{
			Encryption: securetransport.EncryptionSecure,
			Candidates: []core.EndpointID{"gre-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "gre-a",
			Transport: string(transport.ProtocolGRE),
			Enabled:   true,
		}},
	})

	if !spec.ManageQdisc {
		t.Fatal("secure tunnel still needs LAN TC/qdisc for userspace secure transport")
	}
	if spec.ManagedMTU != 0 {
		t.Fatalf("secure tunnel managed MTU = %d, want disabled", spec.ManagedMTU)
	}
}
