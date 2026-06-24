package daemon

import (
	"strings"
	"testing"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
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
			desired := desiredForProductionDefaultRuntimeTest(row)
			if row.GateFamily == "route_gso" {
				t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO", "1")
			}
			spec := dataplaneAttachSpec(t.TempDir(), desired)
			switch row.GateFamily {
			case "userspace", "userspace_tc":
				assertProductionDefaultNoKernelFastPath(t, row, spec)
			case "full_kmod", "owdeb_full_kmod":
				if !spec.KernelDatapathFullPlaintext {
					t.Fatalf("%s should select full-kmod plaintext ownership: spec=%#v", productionDefaultRuntimeKey(row), spec)
				}
				if spec.KernelUDPTCOnlyProvider || spec.KernelUDPTXDirectOnly || spec.KernelUDPSecureRouteGSO || spec.ExperimentalTCPRouteGSOAsync {
					t.Fatalf("%s should not mix TC-only or route-GSO with full-kmod plaintext: spec=%#v", productionDefaultRuntimeKey(row), spec)
				}
			case "tc_direct":
				if !spec.KernelUDPTCOnlyProvider || !spec.KernelUDPTXDirectOnly {
					t.Fatalf("%s should select plaintext kernel_udp TC-direct provider: spec=%#v", productionDefaultRuntimeKey(row), spec)
				}
				if spec.KernelDatapathFullPlaintext || spec.KernelUDPSecureRouteGSO || spec.ExperimentalTCPRouteGSOAsync {
					t.Fatalf("%s should not enable full-kmod or route-GSO paths: spec=%#v", productionDefaultRuntimeKey(row), spec)
				}
			case "secure_kudp":
				if !spec.KernelUDPTXSecureDirect || !spec.KernelUDPRXSecureDirect || !spec.KernelUDPSecureRouteGSO {
					t.Fatalf("%s should select secure kernel_udp route-GSO direct path: spec=%#v", productionDefaultRuntimeKey(row), spec)
				}
				if spec.KernelUDPTXDirectOnly || spec.KernelDatapathFullPlaintext || spec.ExperimentalTCPRouteGSOAsync {
					t.Fatalf("%s should not enable plaintext direct-only/full-kmod/experimental route-GSO: spec=%#v", productionDefaultRuntimeKey(row), spec)
				}
			case "secure_exp_tcp_kernel":
				if !spec.ExperimentalTCPTXDirect || !spec.ExperimentalTCPRouteGSOAsync ||
					!spec.ExperimentalTCPRouteGSOSync || !spec.ExperimentalTCPRouteXmitWorker ||
					!spec.KernelUDPTXSecureDirect || !spec.KernelUDPRXSecureDirect ||
					!spec.KernelUDPSecureDirectTrustInnerChecksums {
					t.Fatalf("%s should select secure experimental_tcp kernel route-GSO path: spec=%#v", productionDefaultRuntimeKey(row), spec)
				}
				if spec.KernelUDPTXDirectOnly || spec.KernelDatapathFullPlaintext || spec.KernelUDPSecureRouteGSO ||
					spec.ExperimentalTCPPlainSkipSequence || spec.ExperimentalTCPPlainACKOnly {
					t.Fatalf("%s should not enable plaintext/full-kmod/kernel_udp route-GSO shortcuts: spec=%#v", productionDefaultRuntimeKey(row), spec)
				}
			case "route_gso":
				if !spec.ExperimentalTCPTXDirect || !spec.KernelUDPTXDirectOnly || !spec.ExperimentalTCPRouteGSOAsync ||
					!spec.ExperimentalTCPRouteGSOSync || !spec.ExperimentalTCPRouteXmitWorker ||
					!spec.ExperimentalTCPPlainSkipSequence || !spec.ExperimentalTCPPlainACKOnly ||
					!spec.KernelDatapathSuppressLegacyRXWorker {
					t.Fatalf("%s should select explicit plaintext experimental_tcp route-GSO path: spec=%#v", productionDefaultRuntimeKey(row), spec)
				}
				if spec.KernelDatapathFullPlaintext || spec.KernelUDPSecureRouteGSO {
					t.Fatalf("%s should not mix full-kmod plaintext ownership or secure-kUDP route-GSO: spec=%#v", productionDefaultRuntimeKey(row), spec)
				}
			default:
				t.Fatalf("production default uses unrecognized runtime gate family %q: %#v", row.GateFamily, row)
			}
		})
	}
	for _, gate := range []string{"userspace", "userspace_tc", "full_kmod", "owdeb_full_kmod", "tc_direct", "secure_kudp", "secure_exp_tcp_kernel", "route_gso"} {
		if !seenGate[gate] {
			t.Fatalf("production defaults missing cross-host runtime gate %q", gate)
		}
	}
}

func desiredForProductionDefaultRuntimeTest(row productionTransportDefaultRowForProvisionTest) config.Desired {
	const endpointName core.EndpointID = "runtime-default-a"
	return config.Desired{
		LAN: config.LANConfig{
			Iface: "br-lan",
		},
		TransportPolicy: config.TransportPolicyConfig{
			Profile:         row.Profile,
			Datapath:        row.Datapath,
			Encryption:      row.Encryption,
			CryptoPlacement: row.CryptoPlacement,
			Candidates:      []core.EndpointID{endpointName},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      endpointName,
			Transport: productionDefaultRuntimeEndpointTransport(row.Transport),
			Enabled:   true,
		}},
	}
}

func productionDefaultRuntimeEndpointTransport(transport string) string {
	if transport == "kernel_udp" {
		return "udp"
	}
	return transport
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
	ExperimentalTCPTXDirect              bool
	ExperimentalTCPRouteGSOAsync         bool
	ExperimentalTCPRouteGSOSync          bool
	ExperimentalTCPRouteXmitWorker       bool
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
		ExperimentalTCPTXDirect:              spec.ExperimentalTCPTXDirect,
		ExperimentalTCPRouteGSOAsync:         spec.ExperimentalTCPRouteGSOAsync,
		ExperimentalTCPRouteGSOSync:          spec.ExperimentalTCPRouteGSOSync,
		ExperimentalTCPRouteXmitWorker:       spec.ExperimentalTCPRouteXmitWorker,
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
		fields.ExperimentalTCPTXDirect ||
		fields.ExperimentalTCPRouteGSOAsync ||
		fields.ExperimentalTCPRouteGSOSync ||
		fields.ExperimentalTCPRouteXmitWorker ||
		fields.KernelDatapathFullPlaintext ||
		fields.KernelDatapathSuppressLegacyRXWorker
}
