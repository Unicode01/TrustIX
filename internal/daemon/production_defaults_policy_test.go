package daemon

import (
	"strings"
	"testing"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/transport"
)

func TestCrossHostProductionDefaultsMapToRuntimeAttachSpec(t *testing.T) {
	rows := readProductionTransportDefaultRowsForProvisionTest(t)
	seenGate := map[string]bool{}
	for _, row := range rows {
		if row.ValidationScope != "cross_host" {
			continue
		}
		row := row
		seenGate[row.GateFamily] = true
		t.Run(strings.ReplaceAll(productionDefaultRuntimeKey(row), ":", "_"), func(t *testing.T) {
			if row.GateFamily == "owdeb_full_kmod" || row.GateFamily == "owdeb_exp_tcp_full_kmod" {
				t.Setenv("TRUSTIX_ASSUME_OPENWRT", "1")
				t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_OPENWRT_FULL_DATAPATH", "1")
			}
			desired := desiredForProductionDefaultRuntimeTest(row)
			if got, want := effectiveKernelTransportModeForDesired(desired), productionDefaultRuntimeKernelTransportMode(row); got != want {
				t.Fatalf("%s kernel transport mode = %q, want %q", productionDefaultRuntimeKey(row), got, want)
			}
			spec := dataplaneAttachSpec(t.TempDir(), desired)
			switch row.GateFamily {
			case "userspace", "userspace_tc":
				assertProductionDefaultNoKernelFastPath(t, row, spec)
			case "full_kmod", "owdeb_full_kmod", "exp_tcp_full_kmod", "owdeb_exp_tcp_full_kmod":
				if !spec.KernelDatapathFullPlaintext {
					t.Fatalf("%s should select full-kmod plaintext ownership: spec=%#v", productionDefaultRuntimeKey(row), spec)
				}
				if spec.KernelUDPTCOnlyProvider || spec.KernelUDPTXDirectOnly ||
					spec.KernelUDPTXSecureDirect || spec.KernelUDPRXSecureDirect ||
					spec.KernelUDPSecureDirectTrustInnerChecksums || spec.KernelUDPSecureRouteGSO ||
					spec.KernelUDPTXSecureDirectKfuncSeal || spec.KernelUDPTXSecureDirectSKBSealKfunc ||
					spec.ExperimentalTCPTXDirect || spec.ExperimentalTCPRouteGSOAsync ||
					spec.ExperimentalTCPRouteGSOSync || spec.ExperimentalTCPRouteXmitWorker ||
					spec.ExperimentalTCPPlainSkipSequence || spec.ExperimentalTCPPlainACKOnly ||
					spec.KernelDatapathSuppressLegacyRXWorker {
					t.Fatalf("%s should not mix TC/direct/route-GSO paths with full-kmod plaintext: spec=%#v", productionDefaultRuntimeKey(row), spec)
				}
			case "tc_direct":
				if !spec.KernelUDPTCOnlyProvider || !spec.KernelUDPTXDirectOnly {
					t.Fatalf("%s should select plaintext kernel_udp TC-direct provider: spec=%#v", productionDefaultRuntimeKey(row), spec)
				}
				if !spec.KernelDatapathSuppressLegacyRXWorker {
					t.Fatalf("%s should suppress legacy RX-worker ownership while TC-direct owns plaintext UDP: spec=%#v", productionDefaultRuntimeKey(row), spec)
				}
				if spec.KernelUDPTXSecureDirect || spec.KernelUDPRXSecureDirect ||
					spec.KernelUDPSecureDirectTrustInnerChecksums || spec.KernelUDPSecureRouteGSO ||
					spec.KernelUDPTXSecureDirectKfuncSeal || spec.KernelUDPTXSecureDirectSKBSealKfunc ||
					spec.ExperimentalTCPTXDirect || spec.ExperimentalTCPRouteGSOAsync ||
					spec.ExperimentalTCPRouteGSOSync || spec.ExperimentalTCPRouteXmitWorker ||
					spec.ExperimentalTCPPlainSkipSequence || spec.ExperimentalTCPPlainACKOnly ||
					spec.KernelDatapathFullPlaintext {
					t.Fatalf("%s should not enable secure/full-kmod/experimental route-GSO paths: spec=%#v", productionDefaultRuntimeKey(row), spec)
				}
			case "secure_kudp":
				if !spec.KernelUDPTXSecureDirect || !spec.KernelUDPRXSecureDirect || !spec.KernelUDPSecureRouteGSO {
					t.Fatalf("%s should select secure kernel_udp route-GSO direct path: spec=%#v", productionDefaultRuntimeKey(row), spec)
				}
				if spec.KernelUDPTXDirectOnly || spec.KernelUDPTCOnlyProvider ||
					spec.KernelUDPTXSecureDirectKfuncSeal || spec.KernelUDPTXSecureDirectSKBSealKfunc ||
					spec.ExperimentalTCPTXDirect || spec.ExperimentalTCPRouteGSOAsync ||
					spec.ExperimentalTCPRouteGSOSync || spec.ExperimentalTCPRouteXmitWorker ||
					spec.ExperimentalTCPPlainSkipSequence || spec.ExperimentalTCPPlainACKOnly ||
					spec.KernelDatapathFullPlaintext || spec.KernelDatapathSuppressLegacyRXWorker {
					t.Fatalf("%s should not enable plaintext/full-kmod/experimental route-GSO: spec=%#v", productionDefaultRuntimeKey(row), spec)
				}
			case "secure_exp_tcp_kernel":
				if !spec.ExperimentalTCPTXDirect || !spec.ExperimentalTCPRouteGSOAsync ||
					!spec.ExperimentalTCPRouteGSOSync || !spec.ExperimentalTCPRouteXmitWorker ||
					!spec.KernelUDPTXSecureDirect || !spec.KernelUDPRXSecureDirect ||
					!spec.KernelUDPSecureDirectTrustInnerChecksums ||
					!spec.KernelUDPTXDirectOnly || !spec.KernelUDPTCOnlyProvider {
					t.Fatalf("%s should select secure experimental_tcp kernel route-GSO path: spec=%#v", productionDefaultRuntimeKey(row), spec)
				}
				if spec.KernelUDPTXSecureDirectKfuncSeal || spec.KernelUDPTXSecureDirectSKBSealKfunc ||
					spec.KernelDatapathFullPlaintext || spec.KernelDatapathSuppressLegacyRXWorker ||
					spec.KernelUDPSecureRouteGSO || spec.ExperimentalTCPPlainSkipSequence ||
					spec.ExperimentalTCPPlainACKOnly {
					t.Fatalf("%s should not enable plaintext/full-kmod/kernel_udp route-GSO shortcuts: spec=%#v", productionDefaultRuntimeKey(row), spec)
				}
			case "route_gso":
				if !spec.ExperimentalTCPTXDirect || !spec.KernelUDPTXDirectOnly || !spec.KernelUDPTCOnlyProvider ||
					!spec.ExperimentalTCPRouteGSOAsync ||
					!spec.ExperimentalTCPRouteGSOSync || !spec.ExperimentalTCPRouteXmitWorker ||
					!spec.ExperimentalTCPPlainSkipSequence || !spec.ExperimentalTCPPlainACKOnly ||
					!spec.KernelDatapathSuppressLegacyRXWorker {
					t.Fatalf("%s should select plaintext experimental_tcp route-GSO path: spec=%#v", productionDefaultRuntimeKey(row), spec)
				}
				if spec.KernelUDPTXSecureDirect || spec.KernelUDPRXSecureDirect || spec.KernelUDPSecureDirectTrustInnerChecksums ||
					spec.KernelUDPSecureRouteGSO || spec.KernelUDPTXSecureDirectKfuncSeal ||
					spec.KernelUDPTXSecureDirectSKBSealKfunc || spec.KernelDatapathFullPlaintext {
					t.Fatalf("%s should not mix full-kmod plaintext ownership or secure-kUDP route-GSO: spec=%#v", productionDefaultRuntimeKey(row), spec)
				}
			default:
				t.Fatalf("production default uses unrecognized runtime gate family %q: %#v", row.GateFamily, row)
			}
		})
	}
	for _, gate := range []string{"userspace", "userspace_tc", "full_kmod", "owdeb_full_kmod", "exp_tcp_full_kmod", "owdeb_exp_tcp_full_kmod", "tc_direct", "secure_kudp", "secure_exp_tcp_kernel", "route_gso"} {
		if !seenGate[gate] {
			t.Fatalf("production defaults missing cross-host runtime gate %q", gate)
		}
	}
}

func TestOpenWrtProductionFullKmodDefaultRequiresDedicatedRuntimeGate(t *testing.T) {
	rows := readProductionTransportDefaultRowsForProvisionTest(t)
	found := map[string]bool{}
	for _, gateFamily := range []string{"owdeb_full_kmod", "owdeb_exp_tcp_full_kmod"} {
		gateFamily := gateFamily
		t.Run(gateFamily, func(t *testing.T) {
			for _, row := range rows {
				if row.ValidationScope != "cross_host" || row.GateFamily != gateFamily {
					continue
				}
				found[gateFamily] = true
				t.Setenv("TRUSTIX_ASSUME_OPENWRT", "1")
				desired := desiredForProductionDefaultRuntimeTest(row)
				spec := dataplaneAttachSpec(t.TempDir(), desired)
				if spec.KernelDatapathFullPlaintext {
					t.Fatalf("%s should not enable OpenWrt full-kmod without dedicated gate: spec=%#v", productionDefaultRuntimeKey(row), spec)
				}
				if got := kernelDatapathRXDisabledReasonForDesired(desired); !strings.Contains(got, "TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_OPENWRT_FULL_DATAPATH=1") {
					t.Fatalf("%s disabled reason = %q, want OpenWrt full datapath gate", productionDefaultRuntimeKey(row), got)
				}
				return
			}
		})
	}
	for _, gateFamily := range []string{"owdeb_full_kmod", "owdeb_exp_tcp_full_kmod"} {
		if !found[gateFamily] {
			t.Fatalf("production defaults missing OpenWrt-Debian full-kmod row for %s", gateFamily)
		}
	}
}

func TestEmptyTransportPolicyRuntimeAttachSpecUsesProductionCompatibilityDefaults(t *testing.T) {
	for _, protocol := range []transport.Protocol{
		transport.ProtocolUDP,
		transport.ProtocolExperimentalTCP,
	} {
		protocol := protocol
		t.Run(string(protocol), func(t *testing.T) {
			desired := config.Desired{
				LAN: config.LANConfig{
					Iface: "br-lan",
				},
				TransportPolicy: config.TransportPolicyConfig{
					Candidates: []core.EndpointID{"runtime-default-a"},
				},
				Endpoints: []config.EndpointConfig{{
					Name:      "runtime-default-a",
					Transport: string(protocol),
					Enabled:   true,
				}},
			}
			spec := dataplaneAttachSpec(t.TempDir(), desired)
			if productionDefaultNoKernelFastPathFieldsFromSpec(spec).anyKernelFastPath() {
				t.Fatalf("empty %s transport policy should stay on production compatibility userspace defaults: spec=%#v", protocol, spec)
			}
			if got := effectiveKernelTransportModeForDesired(desired); got != dataplane.KernelTransportModeDisabled {
				t.Fatalf("empty %s kernel transport mode = %q, want disabled", protocol, got)
			}
		})
	}
}

func desiredForProductionDefaultRuntimeTest(row productionTransportDefaultRowForProvisionTest) config.Desired {
	const endpointName core.EndpointID = "runtime-default-a"
	desired := config.Desired{
		LAN: config.LANConfig{
			Iface: "br-lan",
		},
		TransportPolicy: config.TransportPolicyConfig{
			Profile:         row.Profile,
			Datapath:        row.Datapath,
			Encryption:      row.Encryption,
			CryptoPlacement: row.CryptoPlacement,
			Candidates:      []core.EndpointID{endpointName},
			KernelTransport: config.KernelTransportPolicyConfig{
				Mode: string(productionDefaultRuntimeKernelTransportMode(row)),
			},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      endpointName,
			Transport: productionDefaultRuntimeEndpointTransport(row.Transport),
			Enabled:   true,
		}},
	}
	switch row.GateFamily {
	case "full_kmod", "dd_full_kmod", "owdeb_full_kmod",
		"exp_tcp_full_kmod", "dd_exp_tcp_full_kmod", "owdeb_exp_tcp_full_kmod":
		desired.KernelModules.CapabilityProfile = config.KernelCapabilityProfileFullPlaintext
		desired.KernelModules.Datapath = config.KernelDatapathRuntimeConfig{
			RXStage:                      config.KernelDatapathRXStageWorker,
			RXWorker:                     true,
			TXPlaintext:                  true,
			FullPlaintext:                true,
			RXWorkerAllowExperimentalTCP: true,
		}
	}
	return desired
}

func productionDefaultRuntimeEndpointTransport(transport string) string {
	if transport == "kernel_udp" {
		return "udp"
	}
	return transport
}

func productionDefaultRuntimeKernelTransportMode(row productionTransportDefaultRowForProvisionTest) dataplane.KernelTransportMode {
	switch row.Transport {
	case "gre", "ipip", "vxlan":
		return dataplane.KernelTransportModeRequireKernel
	}
	switch row.GateFamily {
	case "full_kmod", "dd_full_kmod", "owdeb_full_kmod", "exp_tcp_full_kmod", "owdeb_exp_tcp_full_kmod",
		"secure_kudp", "dd_secure_kudp", "owdeb_secure_kudp",
		"secure_exp_tcp_kernel", "dd_secure_exp_tcp_kernel", "owdeb_secure_exp_tcp_kernel",
		"route_gso", "dd_route_gso", "owdeb_route_gso",
		"tc_direct":
		return dataplane.KernelTransportModeRequireKernel
	default:
		return dataplane.KernelTransportModeDisabled
	}
}

func productionDefaultRuntimeKey(row productionTransportDefaultRowForProvisionTest) string {
	return strings.Join([]string{
		row.Transport,
		row.Encryption,
		row.Profile,
		row.Datapath,
		row.CryptoPlacement,
		row.GateFamily,
	}, ":")
}

func assertProductionDefaultNoKernelFastPath(t *testing.T, row productionTransportDefaultRowForProvisionTest, spec dataplane.AttachSpec) {
	t.Helper()
	if productionDefaultNoKernelFastPathFieldsFromSpec(spec).anyKernelFastPath() {
		t.Fatalf("%s should remain on userspace/userspace-TC compatibility path: spec=%#v", productionDefaultRuntimeKey(row), spec)
	}
}

type productionDefaultNoKernelFastPathFields struct {
	KernelUDPTXDirectOnly                bool
	KernelUDPTCOnlyProvider              bool
	KernelUDPTXSecureDirect              bool
	KernelUDPRXSecureDirect              bool
	KernelUDPSecureDirectTrustChecksums  bool
	KernelUDPSecureRouteGSO              bool
	KernelUDPTXSecureDirectKfuncSeal     bool
	KernelUDPTXSecureDirectSKBSealKfunc  bool
	ExperimentalTCPTXDirect              bool
	ExperimentalTCPRouteGSOAsync         bool
	ExperimentalTCPRouteGSOSync          bool
	ExperimentalTCPRouteXmitWorker       bool
	ExperimentalTCPPlainSkipSequence     bool
	ExperimentalTCPPlainACKOnly          bool
	KernelDatapathFullPlaintext          bool
	KernelDatapathSuppressLegacyRXWorker bool
}

func productionDefaultNoKernelFastPathFieldsFromSpec(spec dataplane.AttachSpec) productionDefaultNoKernelFastPathFields {
	return productionDefaultNoKernelFastPathFields{
		KernelUDPTXDirectOnly:                spec.KernelUDPTXDirectOnly,
		KernelUDPTCOnlyProvider:              spec.KernelUDPTCOnlyProvider,
		KernelUDPTXSecureDirect:              spec.KernelUDPTXSecureDirect,
		KernelUDPRXSecureDirect:              spec.KernelUDPRXSecureDirect,
		KernelUDPSecureDirectTrustChecksums:  spec.KernelUDPSecureDirectTrustInnerChecksums,
		KernelUDPSecureRouteGSO:              spec.KernelUDPSecureRouteGSO,
		KernelUDPTXSecureDirectKfuncSeal:     spec.KernelUDPTXSecureDirectKfuncSeal,
		KernelUDPTXSecureDirectSKBSealKfunc:  spec.KernelUDPTXSecureDirectSKBSealKfunc,
		ExperimentalTCPTXDirect:              spec.ExperimentalTCPTXDirect,
		ExperimentalTCPRouteGSOAsync:         spec.ExperimentalTCPRouteGSOAsync,
		ExperimentalTCPRouteGSOSync:          spec.ExperimentalTCPRouteGSOSync,
		ExperimentalTCPRouteXmitWorker:       spec.ExperimentalTCPRouteXmitWorker,
		ExperimentalTCPPlainSkipSequence:     spec.ExperimentalTCPPlainSkipSequence,
		ExperimentalTCPPlainACKOnly:          spec.ExperimentalTCPPlainACKOnly,
		KernelDatapathFullPlaintext:          spec.KernelDatapathFullPlaintext,
		KernelDatapathSuppressLegacyRXWorker: spec.KernelDatapathSuppressLegacyRXWorker,
	}
}

func (fields productionDefaultNoKernelFastPathFields) anyKernelFastPath() bool {
	return fields.KernelUDPTXDirectOnly ||
		fields.KernelUDPTCOnlyProvider ||
		fields.KernelUDPTXSecureDirect ||
		fields.KernelUDPRXSecureDirect ||
		fields.KernelUDPSecureDirectTrustChecksums ||
		fields.KernelUDPSecureRouteGSO ||
		fields.KernelUDPTXSecureDirectKfuncSeal ||
		fields.KernelUDPTXSecureDirectSKBSealKfunc ||
		fields.ExperimentalTCPTXDirect ||
		fields.ExperimentalTCPRouteGSOAsync ||
		fields.ExperimentalTCPRouteGSOSync ||
		fields.ExperimentalTCPRouteXmitWorker ||
		fields.ExperimentalTCPPlainSkipSequence ||
		fields.ExperimentalTCPPlainACKOnly ||
		fields.KernelDatapathFullPlaintext ||
		fields.KernelDatapathSuppressLegacyRXWorker
}
