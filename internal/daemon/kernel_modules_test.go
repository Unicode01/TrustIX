package daemon

import (
	"strings"
	"testing"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
)

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
	want := "enable_features=128 rx_worker_inject=1 tx_plaintext=1"
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
	want := "enable_features=128 rx_worker_inject=1 tx_plaintext=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
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
	want := "rx_worker_inject=0 tx_plaintext=0"
	if got != want {
		t.Fatalf("parameters = %q, want fail-closed runtime parameters %q without crash-risk gate", got, want)
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
		"rx_worker_budget=128",
		"rx_worker_slots=64",
		"rx_worker_hot_stats=0",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("parameters = %q, missing %q", got, want)
		}
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

func TestTrustIXCryptoModuleParametersStripsPanicRiskRawParameters(t *testing.T) {
	got := TrustIXCryptoModuleParameters("prefer_software=1 kfunc_simd_fastpath=1 experimental_vaes_kfunc=1")
	want := "prefer_software=1 experimental_vaes_kfunc=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
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

func TestTrustIXDatapathModuleParametersKeepsSafeFallbackRawParameters(t *testing.T) {
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

func TestTrustIXDatapathHelpersModuleParametersForDesiredEnablesSafeAcklessPerformance(t *testing.T) {
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
				Datapath:   config.TransportDatapathKernelModule,
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
