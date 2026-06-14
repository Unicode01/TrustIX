package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/kernelmodule"
	"trustix.local/trustix/internal/transport"
	securetransport "trustix.local/trustix/internal/transport/secure"
)

func moduleParameterHasAssignment(params, want string) bool {
	for _, field := range strings.Fields(params) {
		if field == want {
			return true
		}
	}
	return false
}

func TestTrustIXDatapathModuleParametersAutoEnableRXWorker(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "rx_worker_inject=0 tx_plaintext=0"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersAutoEnableRXWorkerWithCrashRiskGate(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 tx_plaintext=0"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersFullPlaintextEnablesTX(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "rx_worker_inject=0 tx_plaintext=0"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersFullPlaintextEnablesTXWithCrashRiskGate(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 tx_plaintext=1 rx_worker_xmit=1 rx_worker_inline_xmit=1 rx_worker_inline_xmit_copy_csum=1 rx_worker_direct_xmit=1 rx_worker_inline_coalesce_max_frames=16 rx_worker_single_coalesce=1 rx_worker_single_coalesce_max_frames=16 rx_worker_tcp=1 rx_worker_stream_tcp=1 rx_worker_stream_batch_queue=1 rx_worker_stream_coalesce_gso=1 rx_worker_stream_coalesce_software_segment=0 rx_worker_xmit_more=1 rx_worker_xmit_dst_mac_cache=1 tx_plaintext_inline_xmit=1 tx_plaintext_direct_xmit=1 tx_plaintext_skip_inner_tcp_checksum=1 tx_plaintext_stream_coalesce=0 tx_plaintext_stream_coalesce_max_frames=16 tx_plaintext_slots=8192 rx_worker_budget=1024 rx_worker_slots=8192 rx_worker_hot_stats=0"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersOpenWrtRequiresDedicatedGate(t *testing.T) {
	t.Setenv("TRUSTIX_ASSUME_OPENWRT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "rx_worker_inject=0 tx_plaintext=0"
	if got != want {
		t.Fatalf("parameters = %q, want OpenWrt fail-closed runtime parameters %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersOpenWrtDedicatedGateAllowsFullPlaintext(t *testing.T) {
	t.Setenv("TRUSTIX_ASSUME_OPENWRT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_OPENWRT_FULL_DATAPATH", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 tx_plaintext=1 rx_worker_xmit=1 rx_worker_inline_xmit=1 rx_worker_inline_xmit_copy_csum=1 rx_worker_direct_xmit=1 rx_worker_inline_coalesce_max_frames=16 rx_worker_tcp=1 rx_worker_stream_tcp=1 rx_worker_stream_batch_queue=1 rx_worker_stream_coalesce_gso=1 rx_worker_stream_coalesce_software_segment=0 rx_worker_xmit_more=1 rx_worker_xmit_dst_mac_cache=1 tx_plaintext_inline_xmit=1 tx_plaintext_direct_xmit=1 tx_plaintext_skip_inner_tcp_checksum=1 tx_plaintext_stream_coalesce=0 tx_plaintext_stream_coalesce_max_frames=16 tx_plaintext_slots=8192 rx_worker_budget=1024 rx_worker_slots=8192 rx_worker_hot_stats=0"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersRewritesLegacySlowFullPlaintextParams(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")

	got := TrustIXDatapathModuleParameters("tx_plaintext_skip_inner_tcp_checksum=0 tx_plaintext_stream_coalesce=1")
	for _, want := range []string{
		"tx_plaintext_skip_inner_tcp_checksum=1",
		"tx_plaintext_stream_coalesce=0",
	} {
		if !moduleParameterHasAssignment(got, want) {
			t.Fatalf("parameters = %q, missing rewritten %q", got, want)
		}
	}
	for _, unexpected := range []string{
		"tx_plaintext_skip_inner_tcp_checksum=0",
		"tx_plaintext_stream_coalesce=1",
	} {
		if moduleParameterHasAssignment(got, unexpected) {
			t.Fatalf("parameters = %q, kept legacy slow assignment %q", got, unexpected)
		}
	}
}

func TestTrustIXDatapathModuleParametersOpenWrtRewritesLegacySingleCoalesce(t *testing.T) {
	t.Setenv("TRUSTIX_ASSUME_OPENWRT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_OPENWRT_FULL_DATAPATH", "1")

	got := TrustIXDatapathModuleParameters("rx_worker_single_coalesce=1")
	if !moduleParameterHasAssignment(got, "rx_worker_single_coalesce=0") {
		t.Fatalf("parameters = %q, missing OpenWrt single-coalesce disable", got)
	}
	if moduleParameterHasAssignment(got, "rx_worker_single_coalesce=1") {
		t.Fatalf("parameters = %q, kept OpenWrt legacy single-coalesce enable", got)
	}
}

func TestTrustIXDatapathModuleParametersCrashRiskGateWithoutRequestForcesOff(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "rx_worker_inject=0 tx_plaintext=0"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersForDesiredFullPlaintextProfile(t *testing.T) {
	desired := config.Desired{
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
		},
	}

	got := TrustIXDatapathModuleParametersForDesired("", desired)
	for _, want := range []string{
		"enable_features=128",
		"rx_worker_inject=1",
		"tx_plaintext=1",
		"rx_worker_xmit=1",
		"rx_worker_inline_xmit=1",
		"rx_worker_inline_xmit_copy_csum=1",
		"rx_worker_direct_xmit=1",
		"rx_worker_inline_coalesce_max_frames=16",
		"rx_worker_single_coalesce=1",
		"rx_worker_single_coalesce_max_frames=16",
		"rx_worker_tcp=1",
		"rx_worker_stream_tcp=1",
		"rx_worker_stream_batch_queue=1",
		"rx_worker_stream_coalesce_gso=1",
		"rx_worker_stream_coalesce_software_segment=0",
		"rx_worker_xmit_more=1",
		"rx_worker_xmit_dst_mac_cache=1",
		"tx_plaintext_inline_xmit=1",
		"tx_plaintext_direct_xmit=1",
		"tx_plaintext_skip_inner_tcp_checksum=1",
		"tx_plaintext_stream_coalesce=0",
		"tx_plaintext_stream_coalesce_max_frames=16",
		"tx_plaintext_slots=8192",
		"rx_worker_budget=1024",
		"rx_worker_slots=8192",
		"rx_worker_hot_stats=0",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("parameters = %q, missing %q", got, want)
		}
	}
}

func TestTrustIXDatapathModuleParametersForDesiredFullPlaintextProfileWithCrashRiskGate(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")
	desired := config.Desired{
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
		},
	}

	got := TrustIXDatapathModuleParametersForDesired("", desired)
	for _, want := range []string{
		"enable_features=128",
		"rx_worker_inject=1",
		"tx_plaintext=1",
		"rx_worker_xmit=1",
		"rx_worker_inline_xmit=1",
		"rx_worker_inline_xmit_copy_csum=1",
		"rx_worker_tcp=1",
		"rx_worker_stream_tcp=1",
		"tx_plaintext_inline_xmit=1",
		"tx_plaintext_slots=8192",
		"rx_worker_budget=1024",
		"rx_worker_slots=8192",
		"rx_worker_hot_stats=0",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("parameters = %q, missing %q", got, want)
		}
	}
}

func TestKernelDatapathFullPlaintextSoftnetSysctlDefaults(t *testing.T) {
	targets := kernelDatapathFullPlaintextSoftnetSysctls()
	want := map[string]int{
		"/proc/sys/net/core/netdev_max_backlog":  kernelDatapathFullPlaintextNetdevMaxBacklog,
		"/proc/sys/net/core/netdev_budget":       kernelDatapathFullPlaintextNetdevBudget,
		"/proc/sys/net/core/netdev_budget_usecs": kernelDatapathFullPlaintextNetdevBudgetUsecs,
	}
	if len(targets) != len(want) {
		t.Fatalf("targets = %#v, want %d entries", targets, len(want))
	}
	for _, target := range targets {
		if want[target.Path] != target.Value {
			t.Fatalf("target %q = %d, want %d", target.Path, target.Value, want[target.Path])
		}
	}
}

func TestWriteKernelSysctlMinimumRaisesLowValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sysctl")
	if err := os.WriteFile(path, []byte("1000\n"), 0o644); err != nil {
		t.Fatalf("write temp sysctl: %v", err)
	}
	daemon := &Daemon{}
	if err := daemon.writeKernelSysctlMinimum(path, 65536); err != nil {
		t.Fatalf("write minimum: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read temp sysctl: %v", err)
	}
	if strings.TrimSpace(string(got)) != "65536" {
		t.Fatalf("sysctl value = %q, want 65536", strings.TrimSpace(string(got)))
	}
	if daemon.kernelSysctlRestore[path] != "1000" {
		t.Fatalf("restore value = %q, want 1000", daemon.kernelSysctlRestore[path])
	}
}

func TestWriteKernelSysctlMinimumKeepsHigherValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sysctl")
	if err := os.WriteFile(path, []byte("99999\n"), 0o644); err != nil {
		t.Fatalf("write temp sysctl: %v", err)
	}
	daemon := &Daemon{}
	if err := daemon.writeKernelSysctlMinimum(path, 65536); err != nil {
		t.Fatalf("write minimum: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read temp sysctl: %v", err)
	}
	if strings.TrimSpace(string(got)) != "99999" {
		t.Fatalf("sysctl value = %q, want 99999", strings.TrimSpace(string(got)))
	}
	if len(daemon.kernelSysctlRestore) != 0 {
		t.Fatalf("restore map = %#v, want empty", daemon.kernelSysctlRestore)
	}
}

func TestRestoreKernelDatapathFullPlaintextSysctls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sysctl")
	if err := os.WriteFile(path, []byte("65536\n"), 0o644); err != nil {
		t.Fatalf("write temp sysctl: %v", err)
	}
	daemon := &Daemon{kernelSysctlRestore: map[string]string{path: "1000"}}
	if err := daemon.restoreKernelDatapathFullPlaintextSysctls(); err != nil {
		t.Fatalf("restore sysctl: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read temp sysctl: %v", err)
	}
	if strings.TrimSpace(string(got)) != "1000" {
		t.Fatalf("sysctl value = %q, want 1000", strings.TrimSpace(string(got)))
	}
	if len(daemon.kernelSysctlRestore) != 0 {
		t.Fatalf("restore map = %#v, want empty", daemon.kernelSysctlRestore)
	}
}

func TestEffectiveKernelModulesForDesiredProfileDefaultsModes(t *testing.T) {
	desired := config.Desired{
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfilePerformance,
		},
	}

	modules := effectiveKernelModulesForDesired(desired)
	if modules.TrustIXCrypto.Mode != "auto" || modules.TrustIXDatapath.Mode != "auto" || modules.TrustIXDatapathHelpers.Mode != "auto" {
		t.Fatalf("effective modules = %#v, want all auto", modules)
	}

	desired.KernelModules.CapabilityProfile = config.KernelCapabilityProfileDisabled
	modules = effectiveKernelModulesForDesired(desired)
	if modules.TrustIXCrypto.Mode != "disabled" || modules.TrustIXDatapath.Mode != "disabled" || modules.TrustIXDatapathHelpers.Mode != "disabled" {
		t.Fatalf("disabled modules = %#v, want all disabled", modules)
	}
}

func TestEffectiveKernelModulesRequiresHelpersForExperimentalTCPRouteGSO(t *testing.T) {
	desired := config.Desired{
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfileDisabled,
			TrustIXDatapath: config.KernelModuleConfig{
				Mode: kernelmodule.ModeRequired,
				Path: "/tmp/trustix-e2e/modules/trustix_datapath.ko",
			},
			TrustIXDatapathHelpers: config.KernelModuleConfig{
				Mode: kernelmodule.ModeDisabled,
			},
		},
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfilePerformance,
			Datapath:   config.TransportDatapathTCXDP,
			Encryption: "plaintext",
			Candidates: []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolExperimentalTCP),
			Enabled:   true,
		}},
	}

	if !experimentalTCPPerformanceRouteGSOAsyncForDesired(desired) {
		t.Fatal("test desired should select experimental_tcp route-GSO")
	}
	modules := effectiveKernelModulesForDesired(desired)
	if modules.TrustIXDatapathHelpers.Mode != kernelmodule.ModeRequired {
		t.Fatalf("route-GSO helpers mode = %q, want required", modules.TrustIXDatapathHelpers.Mode)
	}
	if modules.TrustIXDatapathHelpers.Path != "/tmp/trustix-e2e/modules/trustix_datapath_helpers.ko" {
		t.Fatalf("route-GSO helpers path = %q, want inferred sibling helper module", modules.TrustIXDatapathHelpers.Path)
	}

	desired.KernelModules.TrustIXDatapath.Path = "embedded://trustix_datapath.ko"
	desired.KernelModules.TrustIXDatapathHelpers.Path = ""
	modules = effectiveKernelModulesForDesired(desired)
	if modules.TrustIXDatapathHelpers.Path != "embedded://trustix_datapath_helpers.ko" {
		t.Fatalf("route-GSO embedded helpers path = %q, want embedded helpers", modules.TrustIXDatapathHelpers.Path)
	}
}

func TestValidateExperimentalTCPRouteGSOHelpersRequiresRouteTCPKfuncs(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfilePerformance,
			Datapath:   config.TransportDatapathTCXDP,
			Encryption: "plaintext",
			Candidates: []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolExperimentalTCP),
			Enabled:   true,
		}},
	}

	err := validateExperimentalTCPRouteGSOHelpersStatus(desired, kernelmodule.Status{
		Name:   "trustix_datapath_helpers",
		Loaded: false,
		State:  kernelmodule.ModeDisabled,
	})
	if err == nil ||
		!strings.Contains(err.Error(), kernelmodule.FeatureRouteTCPKfunc) ||
		!strings.Contains(err.Error(), kernelmodule.FeatureRouteTCPXmit) ||
		!strings.Contains(err.Error(), kernelmodule.ModeDisabled) {
		t.Fatalf("route-GSO disabled-helper validation error = %v, want fail-closed missing route TCP kfuncs", err)
	}

	err = validateExperimentalTCPRouteGSOHelpersStatus(desired, kernelmodule.Status{
		Name:     "trustix_datapath_helpers",
		Loaded:   true,
		State:    "loaded",
		Features: []string{kernelmodule.FeatureGSOSKB},
	})
	if err == nil || !strings.Contains(err.Error(), kernelmodule.FeatureRouteTCPKfunc) || !strings.Contains(err.Error(), kernelmodule.FeatureRouteTCPXmit) {
		t.Fatalf("route-GSO helper validation error = %v, want missing route TCP kfuncs", err)
	}

	err = validateExperimentalTCPRouteGSOHelpersStatus(desired, kernelmodule.Status{
		Name:   "trustix_datapath_helpers",
		Loaded: true,
		State:  "loaded",
		Features: []string{
			kernelmodule.FeatureGSOSKB,
			kernelmodule.FeatureRouteTCPKfunc,
			kernelmodule.FeatureRouteTCPXmit,
		},
	})
	if err != nil {
		t.Fatalf("route-GSO helper validation with route TCP features: %v", err)
	}
}

func TestTrustIXDatapathModuleParametersForDesiredPerformanceProfileDoesNotEnableRXWorker(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER", "1")
	desired := config.Desired{
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfilePerformance,
		},
	}

	got := TrustIXDatapathModuleParametersForDesired("", desired)
	want := "rx_worker_inject=0 tx_plaintext=0"
	if got != want {
		t.Fatalf("parameters = %q, want production-safe performance parameters %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersForDesiredPerformanceExperimentalTCPSuppressesFullPlaintextTX(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")
	desired := config.Desired{
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
		},
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfilePerformance,
			Datapath:   config.TransportDatapathKernelModule,
			Encryption: "plaintext",
			Candidates: []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: "experimental_tcp",
			Enabled:   true,
		}},
	}

	got := TrustIXDatapathModuleParametersForDesired("tx_plaintext=1 tx_plaintext_slots=16384", desired)
	if got != "rx_worker_inject=0 tx_plaintext=0" {
		t.Fatalf("parameters = %q, want route-GSO to suppress legacy full-kmod plaintext params", got)
	}
	if !experimentalTCPPerformanceRouteGSOAsyncForDesired(desired) {
		t.Fatal("performance experimental_tcp kernel_module policy should migrate to route-GSO even with full_plaintext capability")
	}
	if kernelDatapathFullPlaintextEnabledForDesired(desired) {
		t.Fatal("performance experimental_tcp route-GSO should not keep full-kmod plaintext ownership")
	}
	if mode := kernelDatapathRXModeForDesired(desired); mode == kernelDatapathRXModeWorker {
		t.Fatalf("performance experimental_tcp route-GSO should not attach full plaintext RX hook, mode=%q", mode)
	}
}

func TestPerformanceKernelModuleExperimentalTCPMigratesToRouteGSO(t *testing.T) {
	desired := config.Desired{
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
	}

	if !experimentalTCPPerformanceRouteGSOAsyncForDesired(desired) {
		t.Fatalf("performance experimental_tcp kernel_module should migrate to route-GSO")
	}
	if kernelDatapathFullPlaintextEnabledForDesired(desired) {
		t.Fatalf("performance experimental_tcp kernel_module should not claim full-kmod plaintext ownership")
	}
	if !kernelDatapathRouteGSOSuppressesLegacyFullPlaintextForDesired(desired) {
		t.Fatalf("performance experimental_tcp kernel_module should suppress legacy full-kmod plaintext parameters")
	}
}

func TestTrustIXDatapathModuleParametersForDesiredKeepsLegacyFullPlaintextExperimentalTCP(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")
	desired := config.Desired{
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
		},
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfileStable,
			Datapath:   config.TransportDatapathKernelModule,
			Encryption: "plaintext",
			Candidates: []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: "experimental_tcp",
			Enabled:   true,
		}},
	}

	got := TrustIXDatapathModuleParametersForDesired("tx_plaintext=1 tx_plaintext_slots=16384", desired)
	for _, want := range []string{
		"rx_worker_inject=1",
		"tx_plaintext=1",
		"rx_worker_xmit=1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("parameters = %q, missing %q", got, want)
		}
	}
	if experimentalTCPPerformanceRouteGSOAsyncForDesired(desired) {
		t.Fatal("full plaintext experimental_tcp should not use route-GSO performance fast path")
	}
	if !kernelDatapathFullPlaintextEnabledForDesired(desired) {
		t.Fatal("full plaintext experimental_tcp should keep full plaintext datapath ownership")
	}
}

func TestTrustIXDatapathModuleParametersForDesiredKeepsLegacyFullPlaintextUDP(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")
	desired := config.Desired{
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
		},
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfileStable,
			Datapath:   config.TransportDatapathKernelModule,
			Encryption: "plaintext",
			Candidates: []core.EndpointID{"udp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "udp-a",
			Transport: "udp",
			Enabled:   true,
		}},
	}

	got := TrustIXDatapathModuleParametersForDesired("tx_plaintext=1 rx_worker_xmit=1 rx_worker_tcp=1", desired)
	for _, want := range []string{
		"rx_worker_inject=1",
		"tx_plaintext=1",
		"rx_worker_xmit=1",
		"rx_worker_tcp=1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("parameters = %q, missing %q", got, want)
		}
	}
	if kernelUDPPlaintextPerformanceDirectOnlyForDesired(desired) {
		t.Fatal("full plaintext UDP should not use TC-only performance fast path")
	}
	if !kernelDatapathFullPlaintextEnabledForDesired(desired) {
		t.Fatal("full plaintext UDP should keep full plaintext datapath ownership")
	}
	if mode := kernelDatapathRXModeForDesired(desired); mode != kernelDatapathRXModeWorker {
		t.Fatalf("full plaintext UDP should attach RX worker hook, mode=%q", mode)
	}
}

func TestTrustIXDatapathModuleParametersForDesiredKeepsHarnessFullPlaintextUDP(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_ONLY", "0")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")
	desired := config.Desired{
		Endpoints: []config.EndpointConfig{{
			Name:       "ix-a-full_kmod",
			Transport:  "udp",
			Enabled:    true,
			EnabledSet: true,
			Security:   config.EndpointSecurityConfig{Encryption: "plaintext"},
		}},
		Peers: []config.PeerConfig{{
			ID: "ix-b",
			Endpoints: []config.EndpointConfig{{
				Name:       "ix-b-full_kmod",
				Transport:  "udp",
				Enabled:    true,
				EnabledSet: true,
				Security:   config.EndpointSecurityConfig{Encryption: "plaintext"},
			}},
		}},
		TransportPolicy: config.TransportPolicyConfig{
			Mode:            "user_defined",
			Candidates:      []core.EndpointID{"ix-a-full_kmod"},
			Failover:        "health_based",
			LoadBalance:     "least_conn",
			Encryption:      "plaintext",
			CryptoPlacement: "userspace",
		},
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
		},
	}
	desired = config.Normalize(desired)

	got := TrustIXDatapathModuleParametersForDesired("enable_features=128 rx_worker_inject=1 tx_plaintext=1 rx_worker_budget=1024 rx_worker_slots=8192 tx_plaintext_slots=8192", desired)
	for _, want := range []string{
		"rx_worker_inject=1",
		"tx_plaintext=1",
		"rx_worker_xmit=1",
		"tx_plaintext_inline_xmit=1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("parameters = %q, missing %q", got, want)
		}
	}
	if kernelUDPPlaintextPerformanceDirectOnlyForDesired(desired) {
		t.Fatal("harness full plaintext UDP should not use TC-only direct path")
	}
	if kernelUDPTCOnlyProviderForDesired(desired) {
		t.Fatal("harness full plaintext UDP should not request TC-only provider")
	}
}

func TestTrustIXDatapathModuleParametersForDesiredKeepsLegacyRXWorkerEnvForFullPlaintext(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")
	desired := config.Desired{
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
		},
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfileStable,
			Datapath:   config.TransportDatapathKernelModule,
			Encryption: "plaintext",
			Candidates: []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: "experimental_tcp",
			Enabled:   true,
		}},
	}

	got := TrustIXDatapathModuleParametersForDesired(strings.Join([]string{
		"rx_worker_xmit=1",
		"rx_worker_inline_xmit=1",
		"rx_worker_tcp=1",
		"rx_worker_stream_tcp=1",
		"tx_plaintext=1",
		"tx_plaintext_slots=16384",
	}, " "), desired)
	for _, want := range []string{
		"rx_worker_inject=1",
		"tx_plaintext=1",
		"rx_worker_xmit=1",
		"rx_worker_stream_tcp=1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("parameters = %q, missing %q", got, want)
		}
	}
	if mode := kernelDatapathRXModeForDesired(desired); mode != kernelDatapathRXModeWorker {
		t.Fatalf("full plaintext should keep RX worker env, mode=%q", mode)
	}
}

func TestTrustIXDatapathModuleParametersForDesiredGenericUDPDirectDisableKeepsFullPlaintextExperimentalTCP(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT", "0")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "0")
	desired := config.Desired{
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
		},
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfileStable,
			Datapath:   config.TransportDatapathKernelModule,
			Encryption: "plaintext",
			Candidates: []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: "experimental_tcp",
			Enabled:   true,
		}},
	}

	got := TrustIXDatapathModuleParametersForDesired("tx_plaintext=1 rx_worker_xmit=1", desired)
	for _, want := range []string{
		"rx_worker_inject=1",
		"tx_plaintext=1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("parameters = %q, missing %q", got, want)
		}
	}
	if experimentalTCPPerformanceRouteGSOAsyncForDesired(desired) {
		t.Fatal("generic UDP TC direct disable should not force experimental_tcp route-GSO over full plaintext")
	}
	if !kernelDatapathFullPlaintextEnabledForDesired(desired) {
		t.Fatal("generic UDP TC direct disable should keep full plaintext ownership")
	}
}

func TestTrustIXDatapathModuleParametersForDesiredKeepsFullPlaintextWhenRouteGSOExplicitlyDisabled(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO", "0")
	desired := config.Desired{
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
		},
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfileStable,
			Datapath:   config.TransportDatapathKernelModule,
			Encryption: "plaintext",
			Candidates: []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: "experimental_tcp",
			Enabled:   true,
		}},
	}

	got := TrustIXDatapathModuleParametersForDesired("", desired)
	for _, want := range []string{
		"rx_worker_inject=1",
		"tx_plaintext=1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("parameters = %q, missing fallback %q", got, want)
		}
	}
	if experimentalTCPPerformanceRouteGSOAsyncForDesired(desired) {
		t.Fatal("explicit TC direct disable must prevent route-GSO migration")
	}
	if !kernelDatapathFullPlaintextEnabledForDesired(desired) {
		t.Fatal("explicit TC direct disable should keep full plaintext fallback enabled")
	}
}

func TestTrustIXDatapathModuleParametersForDesiredKeepsFullPlaintextWhenKernelTransportDisabled(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")
	desired := config.Desired{
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
		},
		TransportPolicy: config.TransportPolicyConfig{
			Profile:         config.TransportProfileStable,
			Datapath:        config.TransportDatapathKernelModule,
			Encryption:      "plaintext",
			KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeDisabled)},
			Candidates:      []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: "experimental_tcp",
			Enabled:   true,
		}},
	}

	got := TrustIXDatapathModuleParametersForDesired("", desired)
	for _, want := range []string{
		"rx_worker_inject=1",
		"tx_plaintext=1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("parameters = %q, missing fallback %q", got, want)
		}
	}
	if experimentalTCPPerformanceRouteGSOAsyncForDesired(desired) {
		t.Fatal("disabled kernel_transport must prevent route-GSO migration")
	}
	if !kernelDatapathFullPlaintextEnabledForDesired(desired) {
		t.Fatal("disabled kernel_transport should keep full plaintext fallback enabled")
	}
}

func TestTrustIXCryptoModuleParametersStripsPanicRiskRawParameters(t *testing.T) {
	got := TrustIXCryptoModuleParameters("prefer_software=1 kfunc_simd_fastpath=1 experimental_vaes_kfunc=1")
	want := "prefer_software=1 experimental_vaes_kfunc=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXCryptoModuleParametersForDesiredSecurePerformanceEnablesSIMDKfuncFastpath(t *testing.T) {
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

	got := TrustIXCryptoModuleParametersForDesired("", desired)
	if !strings.Contains(got, "kfunc_simd_fastpath=1") {
		t.Fatalf("parameters = %q, missing secure performance SIMD kfunc fast path", got)
	}
	for _, unexpected := range []string{"experimental_aesni_kfunc=1", "experimental_vaes_kfunc=1"} {
		if strings.Contains(got, unexpected) {
			t.Fatalf("parameters = %q, unexpectedly enabled %q", got, unexpected)
		}
	}
}

func TestTrustIXCryptoModuleParametersForDesiredAllowsExplicitSIMDKfuncFastpath(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_CRYPTO_ALLOW_SIMD_KFUNC_FASTPATH", "1")
	desired := config.Desired{}

	got := TrustIXCryptoModuleParametersForDesired("", desired)
	for _, want := range []string{"kfunc_simd_fastpath=1", "experimental_aesni_kfunc=1", "experimental_vaes_kfunc=1"} {
		if !strings.Contains(got, want) {
			t.Fatalf("parameters = %q, missing %q", got, want)
		}
	}
}

func TestTrustIXDatapathModuleParametersCanDisableRXWorkerHotStats(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_HOT_STATS", "0")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 rx_worker_hot_stats=0 tx_plaintext=0"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersRejectsPanicRiskEnvCombinations(t *testing.T) {
	for _, envName := range []string{
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_STEAL",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE_STOLEN",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_LAN_XMIT",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_DIRECT_XMIT",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE_XMIT",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_ALLOW_UNSAFE_XMIT",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE_XMIT_NO_COPY_CSUM",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE_PAIR_COALESCE",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE_PAIR_HOLD_SKB",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_STEAL_XMIT",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_ALLOW_STEAL_XMIT",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_STEAL_TCP",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE_RECEIVE",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_RECEIVE",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_TCP",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_ALLOW_EXPERIMENTAL_TCP",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_STREAM_TCP",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_TCP_STREAM",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_STREAM_BATCH_QUEUE",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_TCP_STREAM_BATCH_QUEUE",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT_TRUST_TCP_CHECKSUM_ACK_ONLY",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT_TCP_PARTIAL_CSUM",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT_HASH_TX_QUEUE",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT_MORE",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT_DST_MAC_CACHE",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT_DST_MAC_PCPU_CACHE",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT_DST_MAC_SEQ_CACHE",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_QUEUE_SKB",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_STREAM_COALESCE_GSO",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_STREAM_COALESCE_SOFTWARE_SEGMENT",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_STREAM_COALESCE_FULL_CSUM",
	} {
		t.Setenv(envName, "1")
	}
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT_TRUST_TCP_CHECKSUM_MIN_LEN", "1024")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE_PAIR_FLUSH_JIFFIES", "2")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE_COALESCE_MAX_FRAMES", "4")

	got := TrustIXDatapathModuleParameters("")
	want := "rx_worker_inject=0 tx_plaintext=0"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersStripsExperimentalRXWorkerRawParametersWithoutExperimentGate(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER", "1")

	raw := strings.Join([]string{
		"rx_worker_slots=64",
		"rx_worker_xmit=1",
		"rx_worker_direct_xmit=1",
		"rx_worker_inline_xmit=1",
		"rx_worker_steal_skb=1",
		"rx_worker_inline_stolen=1",
		"rx_worker_tcp=1",
		"rx_worker_stream_tcp=1",
		"rx_worker_stream_coalesce_gso=1",
		"rx_worker_inline_pair_hold_skb=1",
		"rx_worker_queue_skb=1",
		"rx_worker_hot_stats=0",
		"rx_worker_future_experiment=1",
	}, " ")

	got := TrustIXDatapathModuleParameters(raw)
	want := "rx_worker_slots=64 rx_worker_xmit=1 rx_worker_direct_xmit=1 rx_worker_inline_xmit=1 rx_worker_tcp=1 rx_worker_stream_tcp=1 rx_worker_hot_stats=0 enable_features=128 rx_worker_inject=1 tx_plaintext=0"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersKeepsExperimentalRXWorkerRawParametersWithExperimentGate(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER_EXPERIMENTS", "1")

	raw := strings.Join([]string{
		"rx_worker_slots=64",
		"rx_worker_xmit=1",
		"rx_worker_direct_xmit=1",
		"rx_worker_inline_xmit=1",
		"rx_worker_steal_skb=1",
		"rx_worker_inline_stolen=1",
		"rx_worker_tcp=1",
		"rx_worker_stream_tcp=1",
		"rx_worker_stream_coalesce_gso=1",
		"rx_worker_inline_pair_hold_skb=1",
		"rx_worker_queue_skb=1",
		"rx_worker_hot_stats=0",
		"rx_worker_future_experiment=1",
	}, " ")

	got := TrustIXDatapathModuleParameters(raw)
	want := "rx_worker_slots=64 rx_worker_xmit=1 rx_worker_direct_xmit=1 rx_worker_inline_xmit=1 rx_worker_steal_skb=1 rx_worker_inline_stolen=1 rx_worker_tcp=1 rx_worker_stream_tcp=1 rx_worker_stream_coalesce_gso=1 rx_worker_inline_pair_hold_skb=1 rx_worker_queue_skb=1 rx_worker_hot_stats=0 enable_features=128 rx_worker_inject=1 tx_plaintext=0"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersStripsKnownRXWorkerCrashParamsEvenWithGate(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER", "1")

	raw := strings.Join([]string{
		"rx_worker_xmit=1",
		"rx_worker_xmit_tcp_partial_csum=1",
		"rx_worker_stream_coalesce_partial_csum=1",
		"rx_worker_xmit_trust_tcp_checksum_ack_only=1",
		"rx_worker_xmit_trust_tcp_checksum_min_len=1",
		"rx_worker_inline_pair_flush_jiffies=2",
	}, " ")

	got := TrustIXDatapathModuleParameters(raw)
	want := "rx_worker_xmit=1 enable_features=128 rx_worker_inject=1 tx_plaintext=0"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersStripsRawCrashRiskWithoutGate(t *testing.T) {
	got := TrustIXDatapathModuleParameters("enable_features=128 rx_worker_inject=1 tx_plaintext=1 rx_worker_slots=32")
	want := "enable_features=128 rx_worker_slots=32 rx_worker_inject=0 tx_plaintext=0"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersKeepExplicitSafeValues(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")

	got := TrustIXDatapathModuleParameters("enable_features=0 rx_worker_inject=0 rx_worker_slots=32")
	want := "enable_features=0 rx_worker_inject=0 rx_worker_slots=32 tx_plaintext=0"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathHelpersModuleParametersAllowsRouteTCPXmitCloneWorker(t *testing.T) {
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC", "1")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_XMIT", "1")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_STEAL", "1")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_XMIT_STEAL", "1")

	got := TrustIXDatapathHelpersModuleParameters("tixt_tx_plain_skip_sequence=1")
	want := "tixt_tx_plain_skip_sequence=1 route_tcp_xmit_worker=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathHelpersModuleParametersAllowsRouteGSOSyncStream(t *testing.T) {
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_SYNC_STREAM", "1")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_SYNC_STREAM_MAX_FRAMES", "12")

	got := TrustIXDatapathHelpersModuleParameters("tixt_tx_plain_skip_sequence=1")
	want := "tixt_tx_plain_skip_sequence=1 route_tcp_gso=1 route_tcp_gso_sync_stream=1 route_tcp_gso_sync_stream_max_frames=12 tixt_rx_stream_parse=1 tixt_rx_stream_xmit_extra=1 tixt_rx_stream_gso_xmit=1 tixt_rx_stream_max_frames=12"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathHelpersModuleParametersForDesiredEnablesSafeAcklessTCXDPPerformance(t *testing.T) {
	desired := config.Desired{
		Endpoints: []config.EndpointConfig{{
			Name:      "ackless-a",
			Transport: "experimental_tcp",
			Enabled:   true,
		}},
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfileStable,
			Datapath:   config.TransportDatapathAuto,
			Encryption: "secure",
			Profiles: []config.TransportProfileConfig{{
				Transport:  "experimental_tcp",
				Profile:    config.TransportProfilePerformance,
				Datapath:   config.TransportDatapathTCXDP,
				Encryption: "plaintext",
			}},
		},
	}

	got := TrustIXDatapathHelpersModuleParametersForDesired("", desired)
	for _, want := range []string{
		"tixt_tx_plain_skip_sequence=1",
		"tixt_tx_plain_ack_only=1",
		"route_tcp_gso=1",
		"route_tcp_gso_async=1",
		"route_tcp_gso_async_prefer=1",
		"route_tcp_gso_async_dev_xmit=1",
		"route_tcp_gso_async_stream=1",
		"route_tcp_gso_async_stream_direct_build=1",
		"route_tcp_gso_async_stream_outer_gso=1",
		"route_tcp_gso_async_stream_outer_gso_hard_enable=1",
		"route_tcp_gso_async_stream_cross_item_batch=1",
		"route_tcp_gso_async_flow_shard_queue=1",
		"route_tcp_gso_async_queue_shards=6",
		"route_tcp_gso_async_worker_emit_budget=8",
		"route_tcp_xmit_worker=1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("parameters = %q, missing %q", got, want)
		}
	}
	for _, unexpected := range []string{
		"route_tcp_gso_sync_stream=1",
		"route_tcp_gso_sync_stream_outer_gso=1",
		"tixt_rx_stream_parse=1",
		"tixt_rx_stream_xmit_extra=1",
		"tixt_rx_stream_gso_xmit=1",
	} {
		if strings.Contains(got, unexpected) {
			t.Fatalf("parameters = %q, unexpectedly enabled legacy path %q", got, unexpected)
		}
	}
}

func TestTrustIXDatapathHelpersModuleParametersForDesiredKeepsStableAcklessConservative(t *testing.T) {
	desired := config.Desired{
		Endpoints: []config.EndpointConfig{{
			Name:      "ackless-a",
			Transport: "experimental_tcp",
			Enabled:   true,
		}},
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfileStable,
			Datapath:   config.TransportDatapathKernelModule,
			Encryption: "plaintext",
			Candidates: []core.EndpointID{"ackless-a"},
		},
	}

	got := TrustIXDatapathHelpersModuleParametersForDesired("", desired)
	for _, unexpected := range []string{
		"route_tcp_gso_async=1",
		"route_tcp_gso_async_stream_outer_gso=1",
		"route_tcp_gso_async_stream_outer_gso_hard_enable=1",
		"route_tcp_xmit_worker=1",
	} {
		if strings.Contains(got, unexpected) {
			t.Fatalf("parameters = %q, unexpectedly enabled stable-path fast option %q", got, unexpected)
		}
	}
}

func TestTrustIXDatapathHelpersModuleParametersRejectsTIXTCoalesceEnv(t *testing.T) {
	for _, envName := range []string{
		"TRUSTIX_TIXT_RX_SINGLE_COALESCE_GSO",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_RX_SINGLE_COALESCE_GSO",
		"TRUSTIX_TIXT_RX_SINGLE_COALESCE_SKIP_TCP_CSUM",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_RX_SINGLE_COALESCE_SKIP_TCP_CSUM",
		"TRUSTIX_TIXT_RX_SINGLE_COALESCE_NETIF_RX",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_RX_SINGLE_COALESCE_NETIF_RX",
		"TRUSTIX_TIXT_RX_SINGLE_COALESCE_PAGE_ONLY",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_RX_SINGLE_COALESCE_PAGE_ONLY",
		"TRUSTIX_TIXT_RX_SINGLE_COALESCE_LINEAR_BUILD",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_RX_SINGLE_COALESCE_LINEAR_BUILD",
		"TRUSTIX_TIXT_RX_SINGLE_COALESCE_HYBRID_HEAD",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_RX_SINGLE_COALESCE_HYBRID_HEAD",
		"TRUSTIX_TIXT_RX_STREAM_ORDERED_LIST",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_RX_STREAM_ORDERED_LIST",
	} {
		t.Setenv(envName, "1")
	}

	got := TrustIXDatapathHelpersModuleParameters("tixt_tx_plain_ack_only=1")
	want := "tixt_tx_plain_ack_only=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathHelpersModuleParametersStripsPanicRiskRawParameters(t *testing.T) {
	raw := strings.Join([]string{
		"tixt_tx_plain_skip_sequence=1",
		"route_tcp_gso=1",
		"route_tcp_gso_async=1",
		"route_tcp_gso_async_dev_xmit=1",
		"route_tcp_gso_async_limit=4096",
		"route_tcp_gso_async_worker_item_budget=64",
		"route_tcp_gso_async_stream=1",
		"route_tcp_gso_async_stream_direct_build=1",
		"route_tcp_gso_async_stream_direct_build_fast_copy=1",
		"route_tcp_gso_async_unbound_worker=1",
		"route_tcp_gso_async_sharded_queue=1",
		"route_tcp_gso_async_queue_shards=8",
		"route_tcp_gso_async_stream_cross_item_debug=1",
		"route_tcp_gso_async_stream_outer_gso=1",
		"route_tcp_gso_async_xmit_busy_retries=4",
		"route_tcp_gso_async_xmit_busy_sleep_usecs=50",
		"route_tcp_xmit_worker=1",
		"route_tcp_xmit_worker_steal=1",
		"route_tcp_xmit_worker_budget=128",
		"tixt_rx_stream_parse=1",
		"tixt_rx_stream_xmit_extra=1",
		"tixt_rx_stream_gso_xmit=1",
		"tixt_rx_stream_max_frames=16",
		"tixt_rx_stream_ordered_list=1",
		"tixt_rx_single_coalesce_gso=1",
		"tixt_rx_single_coalesce_max_frames=64",
		"tixt_rx_single_coalesce_netif_rx=1",
		"tixt_rx_coalesce_segment_gso=1",
	}, " ")

	got := TrustIXDatapathHelpersModuleParameters(raw)
	want := "tixt_tx_plain_skip_sequence=1 route_tcp_gso=1 route_tcp_gso_async=1 route_tcp_gso_async_dev_xmit=1 route_tcp_gso_async_limit=4096 route_tcp_gso_async_worker_item_budget=64 route_tcp_gso_async_stream=1 route_tcp_gso_async_stream_direct_build=1 route_tcp_gso_async_stream_direct_build_fast_copy=1 route_tcp_gso_async_unbound_worker=1 route_tcp_gso_async_sharded_queue=1 route_tcp_gso_async_queue_shards=8 route_tcp_gso_async_stream_cross_item_debug=1 route_tcp_gso_async_stream_outer_gso=1 route_tcp_gso_async_xmit_busy_retries=4 route_tcp_gso_async_xmit_busy_sleep_usecs=50 route_tcp_xmit_worker=1 route_tcp_xmit_worker_steal=1 route_tcp_xmit_worker_budget=128 tixt_rx_stream_parse=1 tixt_rx_stream_xmit_extra=1 tixt_rx_stream_gso_xmit=1 tixt_rx_stream_max_frames=16 tixt_rx_single_coalesce_gso=1 tixt_rx_single_coalesce_max_frames=64 tixt_rx_single_coalesce_netif_rx=1 tixt_rx_coalesce_segment_gso=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathHelpersPerformanceExperimentalTCPDoesNotEnableLegacyRXStreamParser(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfilePerformance,
			Datapath:   config.TransportDatapathTCXDP,
			Encryption: "plaintext",
			Candidates: []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: "experimental_tcp",
			Enabled:   true,
		}},
	}

	got := TrustIXDatapathHelpersModuleParametersForDesired("", desired)
	for _, unexpected := range []string{
		"route_tcp_gso_sync_stream=1",
		"route_tcp_gso_sync_stream_outer_gso=1",
		"tixt_rx_stream_parse=1",
		"tixt_rx_stream_xmit_extra=1",
		"tixt_rx_stream_gso_xmit=1",
		"tixt_rx_stream_max_frames=16",
	} {
		if strings.Contains(got, unexpected) {
			t.Fatalf("parameters = %q, unexpectedly enabled legacy path %q", got, unexpected)
		}
	}
}
