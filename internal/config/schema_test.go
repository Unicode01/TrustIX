package config

import (
	"strings"
	"testing"

	"trustix.local/trustix/internal/core"
)

func TestEffectiveTransportProfileEmptyPolicyUsesProductionCompatibilityDefaults(t *testing.T) {
	profile := EffectiveTransportProfile(TransportPolicyConfig{}, "udp")
	if profile.Profile != TransportProfileStable ||
		profile.Datapath != TransportDatapathUserspace ||
		profile.Encryption != "secure" ||
		profile.CryptoPlacement != "userspace" {
		t.Fatalf("effective transport profile = %#v, want stable/userspace/secure/userspace", profile)
	}
}

func TestEffectiveTransportProfilePreservesExplicitAutoOverrides(t *testing.T) {
	profile := EffectiveTransportProfile(TransportPolicyConfig{
		Datapath:        TransportDatapathAuto,
		CryptoPlacement: "auto",
	}, "udp")
	if profile.Datapath != TransportDatapathAuto || profile.CryptoPlacement != "auto" {
		t.Fatalf("effective explicit auto profile = %#v, want datapath/crypto auto", profile)
	}
}

func TestEndpointLocalBindValidation(t *testing.T) {
	cfg := Desired{
		Domain: DomainConfig{ID: core.DomainID("lab.local")},
		IX:     IXConfig{ID: core.IXID("ix-a")},
		Endpoints: []EndpointConfig{{
			Name:      core.EndpointID("wan-tcp"),
			Mode:      EndpointModePassive,
			Listen:    "127.0.0.1:7000",
			Transport: "tcp",
			LocalBind: EndpointLocalBindConfig{SourceIP: "192.0.2.10", Iface: "eth0"},
			Enabled:   true,
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate local bind: %v", err)
	}
	cfg.Endpoints[0].LocalBind.SourceIP = "not-an-ip"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected invalid local_bind source_ip error")
	}
	if !strings.Contains(err.Error(), "local_bind source_ip") {
		t.Fatalf("error = %v, want local_bind source_ip", err)
	}
}

func TestEffectiveKernelDatapathRuntimePerformanceDoesNotRequestRXWorker(t *testing.T) {
	runtime := EffectiveKernelDatapathRuntime(KernelModulesConfig{
		CapabilityProfile: KernelCapabilityProfilePerformance,
	})
	if runtime.RXWorker || runtime.RXStage == KernelDatapathRXStageWorker || runtime.TXPlaintext || runtime.FullPlaintext {
		t.Fatalf("performance kernel datapath runtime = %#v, want no full-kernel RX worker/plaintext request", runtime)
	}
}

func TestEffectiveKernelDatapathRuntimeExplicitRXWorkerStillWorks(t *testing.T) {
	runtime := EffectiveKernelDatapathRuntime(KernelModulesConfig{
		CapabilityProfile: KernelCapabilityProfilePerformance,
		Datapath: KernelDatapathRuntimeConfig{
			RXWorker: true,
		},
	})
	if !runtime.RXWorker || runtime.RXStage != KernelDatapathRXStageWorker {
		t.Fatalf("explicit RX worker runtime = %#v, want worker", runtime)
	}
}
