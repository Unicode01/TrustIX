package daemon

import (
	"context"
	"fmt"
	"os"
	"strings"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/kernelmodule"
)

func (daemon *Daemon) ensureKernelModules(ctx context.Context, desired config.Desired) ([]kernelmodule.Status, error) {
	if daemon.kernelCrypto == nil {
		daemon.kernelCrypto = kernelmodule.NewTrustIXCryptoManager()
	}
	if daemon.kernelDatapath == nil {
		daemon.kernelDatapath = kernelmodule.NewTrustIXDatapathManager()
	}
	if daemon.kernelHelpers == nil {
		daemon.kernelHelpers = kernelmodule.NewTrustIXDatapathHelpersManager()
	}
	modules := effectiveKernelModulesForDesired(desired)
	if kernelModulesAllDisabled(modules) {
		helpersStatus, helpersErr := daemon.kernelHelpers.Ensure(ctx, modules.TrustIXDatapathHelpers)
		datapathStatus, datapathErr := daemon.kernelDatapath.Ensure(ctx, modules.TrustIXDatapath)
		cryptoStatus, cryptoErr := daemon.kernelCrypto.Ensure(ctx, modules.TrustIXCrypto)
		statuses := []kernelmodule.Status{cryptoStatus, datapathStatus, helpersStatus}
		for _, err := range []error{helpersErr, datapathErr, cryptoErr} {
			if err != nil {
				return statuses, err
			}
		}
		return statuses, nil
	}
	cryptoModule := modules.TrustIXCrypto
	cryptoModule.Parameters = TrustIXCryptoModuleParameters(cryptoModule.Parameters)
	cryptoStatus, err := daemon.kernelCrypto.Ensure(ctx, cryptoModule)
	if err != nil {
		return []kernelmodule.Status{cryptoStatus}, err
	}
	datapathModule := modules.TrustIXDatapath
	datapathModule.Parameters = TrustIXDatapathModuleParametersForDesired(datapathModule.Parameters, desired)
	datapathStatus, err := daemon.kernelDatapath.Ensure(ctx, datapathModule)
	statuses := []kernelmodule.Status{cryptoStatus, datapathStatus}
	if err != nil {
		return statuses, err
	}
	helpersModule := modules.TrustIXDatapathHelpers
	helpersModule.Parameters = TrustIXDatapathHelpersModuleParametersForDesired(helpersModule.Parameters, desired)
	helpersStatus, err := daemon.kernelHelpers.Ensure(ctx, helpersModule)
	statuses = append(statuses, helpersStatus)
	if err != nil {
		return statuses, err
	}
	return statuses, nil
}

func effectiveKernelModulesForDesired(desired config.Desired) config.KernelModulesConfig {
	modules := desired.KernelModules
	profile := config.NormalizeKernelCapabilityProfile(modules.CapabilityProfile)
	switch profile {
	case config.KernelCapabilityProfileDisabled:
		modules.TrustIXCrypto.Mode = kernelmodule.ModeDisabled
		modules.TrustIXDatapath.Mode = kernelmodule.ModeDisabled
		modules.TrustIXDatapathHelpers.Mode = kernelmodule.ModeDisabled
	case config.KernelCapabilityProfileStable, config.KernelCapabilityProfilePerformance, config.KernelCapabilityProfileFullPlaintext, config.KernelCapabilityProfileCustom:
		if strings.TrimSpace(modules.TrustIXCrypto.Mode) == "" {
			modules.TrustIXCrypto.Mode = kernelmodule.ModeAuto
		}
		if strings.TrimSpace(modules.TrustIXDatapath.Mode) == "" {
			modules.TrustIXDatapath.Mode = kernelmodule.ModeAuto
		}
		if strings.TrimSpace(modules.TrustIXDatapathHelpers.Mode) == "" {
			modules.TrustIXDatapathHelpers.Mode = kernelmodule.ModeAuto
		}
	}
	return modules
}

func kernelModulesAllDisabled(modules config.KernelModulesConfig) bool {
	return !kernelmoduleModeActive(modules.TrustIXCrypto.Mode) &&
		!kernelmoduleModeActive(modules.TrustIXDatapath.Mode) &&
		!kernelmoduleModeActive(modules.TrustIXDatapathHelpers.Mode)
}

func TrustIXCryptoModuleParameters(raw string) string {
	return filterModuleParameters(raw, trustIXCryptoPanicRiskModuleParameters)
}

func TrustIXDatapathModuleParameters(raw string) string {
	return TrustIXDatapathModuleParametersForDesired(raw, config.Desired{})
}

func TrustIXDatapathModuleParametersForDesired(raw string, desired config.Desired) string {
	params := filterModuleParametersWithAllowlist(
		raw,
		trustIXDatapathPanicRiskModuleParameters,
		trustIXDatapathSafeRXWorkerModuleParameters,
		"rx_worker_",
	)
	rxWorkerAllowed := kernelDatapathRXWorkerCrashRiskAllowed()
	fullPlaintextAllowed := kernelDatapathFullPlaintextCrashRiskAllowed()
	params = filterTrustIXDatapathRuntimeCrashRiskParameters(params, rxWorkerAllowed, fullPlaintextAllowed)
	runtime := config.EffectiveKernelDatapathRuntime(desired.KernelModules)
	profile := config.NormalizeKernelCapabilityProfile(desired.KernelModules.CapabilityProfile)
	rxWorker := runtime.RXWorker || runtime.RXStage == config.KernelDatapathRXStageWorker
	fullPlaintext := runtime.FullPlaintext || runtime.TXPlaintext
	rxWorker = rxWorker || envTruthyAny("TRUSTIX_KERNEL_DATAPATH_RX_WORKER")
	fullPlaintext = fullPlaintext || envTruthyAny(
		"TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT",
		"TRUSTIX_KERNEL_DATAPATH_TX_PLAINTEXT",
	)
	if fullPlaintext && !fullPlaintextAllowed {
		fullPlaintext = false
	}
	if rxWorker && !rxWorkerAllowed {
		rxWorker = false
	}
	if rxWorker || fullPlaintext {
		params = appendModuleParameterIfMissing(params, "enable_features=128")
		params = appendModuleParameterIfMissing(params, "rx_worker_inject=1")
		if fullPlaintext {
			params = appendModuleParameterIfMissing(params, "tx_plaintext=1")
		}
		if profile == config.KernelCapabilityProfilePerformance || profile == config.KernelCapabilityProfileFullPlaintext {
			params = appendModuleParameterIfMissing(params, "rx_worker_budget=1024")
			params = appendModuleParameterIfMissing(params, "rx_worker_slots=8192")
		}
		if runtime.RXWorkerHotStats != nil && !*runtime.RXWorkerHotStats {
			params = appendModuleParameterIfMissing(params, "rx_worker_hot_stats=0")
		} else if runtime.RXWorkerHotStats == nil && (profile == config.KernelCapabilityProfilePerformance || profile == config.KernelCapabilityProfileFullPlaintext) {
			params = appendModuleParameterIfMissing(params, "rx_worker_hot_stats=0")
		} else if envFalsey("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_HOT_STATS") {
			params = appendModuleParameterIfMissing(params, "rx_worker_hot_stats=0")
		}
	}
	return forceTrustIXDatapathRuntimeCrashRiskOffParameters(params)
}

func filterTrustIXDatapathRuntimeCrashRiskParameters(params string, allowRXWorker bool, allowFullPlaintext bool) string {
	fields := strings.Fields(strings.TrimSpace(params))
	if len(fields) == 0 {
		return ""
	}
	kept := fields[:0]
	for _, field := range fields {
		key, value, _ := strings.Cut(field, "=")
		key = strings.TrimSpace(key)
		switch key {
		case "rx_worker_inject":
			if !allowRXWorker && !moduleParameterValueFalsey(value) {
				continue
			}
		case "tx_plaintext":
			if !allowFullPlaintext && !moduleParameterValueFalsey(value) {
				continue
			}
		}
		kept = append(kept, field)
	}
	return strings.Join(kept, " ")
}

func forceTrustIXDatapathRuntimeCrashRiskOffParameters(params string) string {
	if !moduleParameterTruthy(params, "rx_worker_inject") {
		params = appendModuleParameterIfMissing(params, "rx_worker_inject=0")
	}
	if !moduleParameterTruthy(params, "tx_plaintext") {
		params = appendModuleParameterIfMissing(params, "tx_plaintext=0")
	}
	return params
}

func moduleParameterTruthy(params, wantKey string) bool {
	for _, field := range strings.Fields(params) {
		key, value, ok := strings.Cut(field, "=")
		if ok && strings.TrimSpace(key) == wantKey && !moduleParameterValueFalsey(value) {
			return true
		}
	}
	return false
}

func moduleParameterValueFalsey(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "0", "false", "no", "off", "disabled", "n":
		return true
	default:
		return false
	}
}

func kernelDatapathRXWorkerCrashRiskAllowed() bool {
	return kernelDatapathOpenWrtCrashRiskAllowed() && envTruthyAny(
		"TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER",
		"TRUSTIX_KERNEL_DATAPATH_ALLOW_UNSAFE_RX_WORKER",
		"TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT",
		"TRUSTIX_KERNEL_DATAPATH_ALLOW_UNSAFE_FULL_PLAINTEXT",
	)
}

func kernelDatapathFullPlaintextCrashRiskAllowed() bool {
	return kernelDatapathOpenWrtCrashRiskAllowed() && envTruthyAny(
		"TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT",
		"TRUSTIX_KERNEL_DATAPATH_ALLOW_UNSAFE_FULL_PLAINTEXT",
	)
}

func kernelDatapathOpenWrtCrashRiskAllowed() bool {
	if !runtimeLooksLikeOpenWrt() {
		return true
	}
	return envTruthyAny(
		"TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_OPENWRT_FULL_DATAPATH",
		"TRUSTIX_KERNEL_DATAPATH_ALLOW_UNSAFE_OPENWRT_FULL_DATAPATH",
	)
}

func runtimeLooksLikeOpenWrt() bool {
	if envTruthyAny("TRUSTIX_ASSUME_OPENWRT") {
		return true
	}
	if envFalsey("TRUSTIX_ASSUME_OPENWRT") {
		return false
	}
	if _, err := os.Stat("/etc/openwrt_release"); err == nil {
		return true
	}
	return false
}

func (daemon *Daemon) closeKernelModules(ctx context.Context) error {
	var firstErr error
	if daemon.kernelDatapath != nil {
		if err := daemon.kernelDatapath.Close(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if daemon.kernelHelpers != nil {
		if err := daemon.kernelHelpers.Close(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if daemon.kernelCrypto != nil {
		if err := daemon.kernelCrypto.Close(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (daemon *Daemon) kernelModuleStatuses() []kernelmodule.Status {
	statuses := make([]kernelmodule.Status, 0, 3)
	if daemon.kernelCrypto != nil {
		statuses = append(statuses, daemon.kernelCrypto.Snapshot())
	} else {
		statuses = append(statuses, disabledKernelModuleStatus("trustix_crypto"))
	}
	if daemon.kernelDatapath != nil {
		statuses = append(statuses, daemon.kernelDatapath.Snapshot())
	} else {
		statuses = append(statuses, disabledKernelModuleStatus("trustix_datapath"))
	}
	if daemon.kernelHelpers != nil {
		statuses = append(statuses, daemon.kernelHelpers.Snapshot())
	} else {
		statuses = append(statuses, disabledKernelModuleStatus("trustix_datapath_helpers"))
	}
	return statuses
}

func kernelModulesMayAffectDataplane(oldDesired, newDesired config.Desired) bool {
	return true
}

func disabledKernelModuleStatus(name string) kernelmodule.Status {
	return kernelmodule.Status{
		Name:             name,
		Mode:             kernelmodule.ModeDisabled,
		State:            kernelmodule.ModeDisabled,
		Reason:           "module lifecycle is disabled",
		CapabilityTier:   kernelmodule.CapabilityTierUnavailable,
		CapabilityReason: "module lifecycle is disabled",
	}
}

func kernelmoduleModeActive(mode string) bool {
	switch mode {
	case kernelmodule.ModeAuto, kernelmodule.ModeRequired:
		return true
	default:
		return false
	}
}

func TrustIXDatapathHelpersModuleParameters(raw string) string {
	params := filterModuleParametersWithAllowlist(
		raw,
		trustIXDatapathHelpersPanicRiskModuleParameters,
		trustIXDatapathHelpersSafeAsyncModuleParameters,
		"route_tcp_gso_async_",
		"tixt_rx_stream_",
		"tixt_rx_single_coalesce_",
		"tixt_rx_coalesce_",
	)
	params = appendTrustIXDatapathHelpersTIXTParameters(params)
	return params
}

func TrustIXDatapathHelpersModuleParametersForDesired(raw string, desired config.Desired) string {
	params := TrustIXDatapathHelpersModuleParameters(raw)
	if experimentalTCPPerformanceRouteGSOAsyncForDesired(desired) {
		params = appendModuleParameterIfMissing(params, "tixt_tx_plain_skip_sequence=1")
		params = appendModuleParameterIfMissing(params, "tixt_tx_plain_ack_only=1")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso=1")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async=1")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_prefer=1")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_dev_xmit=1")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_limit=2048")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_bytes_limit=33554432")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_worker_item_budget=32")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_worker_segment_budget=1024")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_worker_emit_budget=8")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_worker_resched_stride=16")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_worker_min_queue_depth=8")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_worker_schedule_delay_usecs=500")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_max_segments_per_item=128")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_unbound_worker=1")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_sharded_queue=1")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_queue_shards=6")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_flow_shard_queue=1")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_stream=1")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_stream_direct_build=1")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_stream_direct_build_inner_csum=1")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_stream_direct_build_fast_copy=1")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_stream_direct_build_frag_fast_copy=1")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_stream_outer_gso=1")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_stream_outer_gso_hard_enable=1")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_stream_max_frames=64")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_stream_cross_item_batch=1")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_stream_cross_item_dequeue_batch=1")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_stream_cross_item_max_frames=24")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_stream_cross_item_dynamic_cap=1")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_stream_cross_item_dynamic_low_frames=12")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_stream_cross_item_dynamic_queue_depth=4")
		params = appendModuleParameterIfMissing(params, "route_tcp_xmit_worker=1")
	}
	return params
}

func appendTrustIXDatapathHelpersTIXTParameters(params string) string {
	if envTruthyAny(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_WORKER_KFUNC",
	) {
		params = appendModuleParameterIfMissing(params, "route_tcp_xmit_worker=1")
	}
	if envTruthyAny(
		"TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_SYNC_STREAM",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_SYNC_STREAM",
	) {
		params = appendModuleParameterIfMissing(params, "route_tcp_gso=1")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_sync_stream=1")
		params = appendModuleParameterFromEnvIfMissing(params, "route_tcp_gso_sync_stream_max_frames", "TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_SYNC_STREAM_MAX_FRAMES")
		params = appendModuleParameterIfMissing(params, "tixt_rx_stream_parse=1")
		params = appendModuleParameterIfMissing(params, "tixt_rx_stream_xmit_extra=1")
		params = appendModuleParameterIfMissing(params, "tixt_rx_stream_gso_xmit=1")
		params = appendModuleParameterFromEnvIfMissing(params, "tixt_rx_stream_max_frames", "TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_SYNC_STREAM_MAX_FRAMES")
	}
	if envTruthyAny(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC",
	) {
		params = appendModuleParameterIfMissing(params, "route_tcp_gso=1")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async=1")
		params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_dev_xmit=1")
		params = appendModuleParameterFromEnvIfMissing(params, "route_tcp_gso_async_limit", "TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_LIMIT")
		params = appendModuleParameterFromEnvIfMissing(params, "route_tcp_gso_async_bytes_limit", "TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_BYTES_LIMIT")
		params = appendModuleParameterFromEnvIfMissing(params, "route_tcp_gso_async_worker_item_budget", "TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_WORKER_ITEM_BUDGET")
		params = appendModuleParameterFromEnvIfMissing(params, "route_tcp_gso_async_worker_segment_budget", "TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_WORKER_SEGMENT_BUDGET")
		params = appendModuleParameterFromEnvIfMissing(params, "route_tcp_gso_async_max_segments_per_item", "TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_MAX_SEGMENTS_PER_ITEM")
		if envTruthyAny("TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_STREAM") {
			params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_stream=1")
			params = appendModuleParameterFromEnvIfMissing(params, "route_tcp_gso_async_stream_max_frames", "TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_STREAM_MAX_FRAMES")
		}
		if envTruthyAny("TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_STREAM_DIRECT_BUILD") {
			params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_stream_direct_build=1")
		}
		if envTruthyAny("TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC_STREAM_OUTER_GSO") {
			params = appendModuleParameterIfMissing(params, "route_tcp_gso_async_stream_outer_gso=1")
		}
	}
	return params
}

func appendModuleParameterIfMissing(params, assignment string) string {
	key, _, ok := strings.Cut(assignment, "=")
	if !ok || strings.TrimSpace(key) == "" {
		return params
	}
	key = strings.TrimSpace(key)
	for _, field := range strings.Fields(params) {
		existing, _, ok := strings.Cut(field, "=")
		if ok && strings.TrimSpace(existing) == key {
			return params
		}
	}
	if strings.TrimSpace(params) == "" {
		return assignment
	}
	return strings.TrimSpace(params) + " " + assignment
}

func appendModuleParameterFromEnvIfMissing(params, key, envName string) string {
	value := strings.TrimSpace(os.Getenv(envName))
	if value == "" {
		return params
	}
	if fields := strings.Fields(value); len(fields) > 0 {
		value = fields[0]
	}
	return appendModuleParameterIfMissing(params, strings.TrimSpace(key)+"="+value)
}

var trustIXDatapathPanicRiskModuleParameters = map[string]struct{}{
	"rx_worker_inline_pair_flush_jiffies":        {},
	"rx_worker_stream_coalesce_partial_csum":     {},
	"rx_worker_xmit_tcp_partial_csum":            {},
	"rx_worker_xmit_trust_tcp_checksum_ack_only": {},
	"rx_worker_xmit_trust_tcp_checksum_min_len":  {},
}

var trustIXDatapathSafeRXWorkerModuleParameters = map[string]struct{}{
	"rx_worker_budget":                           {},
	"rx_worker_direct_xmit":                      {},
	"rx_worker_hot_stats":                        {},
	"rx_worker_inject":                           {},
	"rx_worker_inline_coalesce_max_frames":       {},
	"rx_worker_inline_pair_coalesce":             {},
	"rx_worker_inline_pair_hold_skb":             {},
	"rx_worker_inline_xmit":                      {},
	"rx_worker_inline_xmit_copy_csum":            {},
	"rx_worker_queue_skb":                        {},
	"rx_worker_slots":                            {},
	"rx_worker_steal_skb":                        {},
	"rx_worker_inline_stolen":                    {},
	"rx_worker_inline_receive":                   {},
	"rx_worker_steal_xmit":                       {},
	"rx_worker_steal_tcp":                        {},
	"rx_worker_stream_batch_queue":               {},
	"rx_worker_stream_coalesce_gso":              {},
	"rx_worker_stream_coalesce_software_segment": {},
	"rx_worker_stream_tcp":                       {},
	"rx_worker_tcp":                              {},
	"rx_worker_xmit":                             {},
	"rx_worker_xmit_dev_forward":                 {},
	"rx_worker_xmit_dst_mac_cache":               {},
	"rx_worker_xmit_dst_mac_pcpu_cache":          {},
	"rx_worker_xmit_dst_mac_seq_cache":           {},
	"rx_worker_xmit_hash_tx_queue":               {},
	"rx_worker_xmit_more":                        {},
}

var trustIXCryptoPanicRiskModuleParameters = map[string]struct{}{
	"kfunc_simd_fastpath": {},
}

var trustIXDatapathHelpersPanicRiskModuleParameters = map[string]struct{}{
	"tixt_rx_stream_ordered_list":    {},
	"tixt_rx_stream_nonlinear_parse": {},
}

var trustIXDatapathHelpersSafeAsyncModuleParameters = map[string]struct{}{
	"route_tcp_gso_async_bytes_limit":                                   {},
	"route_tcp_gso_async_dev_xmit":                                      {},
	"route_tcp_gso_async_direct_xmit":                                   {},
	"route_tcp_gso_async_force_inner_checksum":                          {},
	"route_tcp_gso_async_force_software_outer_csum":                     {},
	"route_tcp_gso_async_hot_stats":                                     {},
	"route_tcp_gso_async_limit":                                         {},
	"route_tcp_gso_async_max_segments_per_item":                         {},
	"route_tcp_gso_async_ordered_queue":                                 {},
	"route_tcp_gso_async_prefer":                                        {},
	"route_tcp_gso_async_queue_shards":                                  {},
	"route_tcp_gso_async_sharded_queue":                                 {},
	"route_tcp_gso_async_stream":                                        {},
	"route_tcp_gso_async_stream_direct_build":                           {},
	"route_tcp_gso_async_stream_direct_build_fast_copy":                 {},
	"route_tcp_gso_async_stream_direct_build_frag_fast_copy":            {},
	"route_tcp_gso_async_stream_direct_build_inner_csum":                {},
	"route_tcp_gso_async_stream_max_frames":                             {},
	"route_tcp_gso_async_stream_allow_virtio_net":                       {},
	"route_tcp_gso_async_stream_outer_gso":                              {},
	"route_tcp_gso_async_stream_outer_gso_hard_enable":                  {},
	"route_tcp_gso_async_stream_cross_item_batch":                       {},
	"route_tcp_gso_async_stream_cross_item_debug":                       {},
	"route_tcp_gso_async_stream_cross_item_dequeue_batch":               {},
	"route_tcp_gso_async_stream_cross_item_dynamic_cap":                 {},
	"route_tcp_gso_async_stream_cross_item_dynamic_low_frames":          {},
	"route_tcp_gso_async_stream_cross_item_dynamic_queue_depth":         {},
	"route_tcp_gso_async_stream_cross_item_lookahead":                   {},
	"route_tcp_gso_async_stream_cross_item_max_frames":                  {},
	"route_tcp_gso_async_stream_cross_item_tail_stitch":                 {},
	"route_tcp_gso_async_stream_direct_build_frag_fast_copy_cross_page": {},
	"route_tcp_gso_async_stream_nonlinear_direct_build":                 {},
	"route_tcp_gso_async_stream_software_segment":                       {},
	"route_tcp_gso_async_unbound_worker":                                {},
	"route_tcp_gso_async_flow_shard_queue":                              {},
	"route_tcp_gso_async_hash_tx_queue":                                 {},
	"route_tcp_gso_async_reslice_to_mtu":                                {},
	"route_tcp_gso_async_worker_budget_reschedule_delay_jiffies":        {},
	"route_tcp_gso_async_worker_budget_reschedule_delay_usecs":          {},
	"route_tcp_gso_async_worker_dequeue_batch":                          {},
	"route_tcp_gso_async_worker_item_budget":                            {},
	"route_tcp_gso_async_worker_max_depth_defers":                       {},
	"route_tcp_gso_async_worker_min_queue_depth":                        {},
	"route_tcp_gso_async_worker_resched_stride":                         {},
	"route_tcp_gso_async_worker_schedule_delay_jiffies":                 {},
	"route_tcp_gso_async_worker_schedule_delay_no_accel":                {},
	"route_tcp_gso_async_worker_schedule_delay_usecs":                   {},
	"route_tcp_gso_async_worker_segment_budget":                         {},
	"route_tcp_gso_async_xmit_busy_retries":                             {},
	"route_tcp_gso_async_xmit_busy_sleep_usecs":                         {},
	"route_tcp_gso_async_xmit_more":                                     {},
	"route_tcp_gso_async_xmit_cn_sleep_usecs":                           {},
	"route_tcp_gso_async_yield_on_xmit_cn":                              {},
	"tixt_rx_stream_gso_xmit":                                           {},
	"tixt_rx_stream_coalesce_gso":                                       {},
	"tixt_rx_stream_coalesce_mark_gso":                                  {},
	"tixt_rx_stream_max_frames":                                         {},
	"tixt_rx_stream_parse":                                              {},
	"tixt_rx_stream_xmit_extra":                                         {},
	"tixt_rx_coalesce_mark_gso_partial_csum":                            {},
	"tixt_rx_coalesce_segment_gso":                                      {},
	"tixt_rx_single_coalesce_gso":                                       {},
	"tixt_rx_single_coalesce_mark_gso":                                  {},
	"tixt_rx_single_coalesce_skip_tcp_csum":                             {},
	"tixt_rx_single_coalesce_direct_list":                               {},
	"tixt_rx_single_coalesce_direct_list_max_frames":                    {},
	"tixt_rx_single_coalesce_page_only":                                 {},
	"tixt_rx_single_coalesce_linear_build":                              {},
	"tixt_rx_single_coalesce_hybrid_head":                               {},
	"tixt_rx_single_coalesce_netif_rx":                                  {},
	"tixt_rx_single_coalesce_schedule_once":                             {},
	"tixt_rx_single_coalesce_stream_fallback":                           {},
	"tixt_rx_single_coalesce_hot_stats":                                 {},
	"tixt_rx_single_coalesce_defer_full_flush":                          {},
	"tixt_rx_single_coalesce_keep_full_timer":                           {},
	"tixt_rx_single_coalesce_set_hash":                                  {},
	"tixt_rx_single_coalesce_schedule_stride":                           {},
	"tixt_rx_single_coalesce_max_frames":                                {},
	"tixt_rx_single_coalesce_flush_jiffies":                             {},
	"tixt_rx_single_coalesce_warmup_frames":                             {},
	"tixt_rx_single_coalesce_linear_max":                                {},
}

func filterModuleParameters(params string, deny map[string]struct{}, denyPrefixes ...string) string {
	return filterModuleParametersWithAllowlist(params, deny, nil, denyPrefixes...)
}

func filterModuleParametersWithAllowlist(params string, deny map[string]struct{}, allow map[string]struct{}, denyPrefixes ...string) string {
	fields := strings.Fields(strings.TrimSpace(params))
	if len(fields) == 0 || (len(deny) == 0 && len(denyPrefixes) == 0) {
		return strings.Join(fields, " ")
	}
	kept := fields[:0]
	for _, field := range fields {
		key, _, _ := strings.Cut(field, "=")
		key = strings.TrimSpace(key)
		if _, blocked := deny[key]; blocked {
			continue
		}
		blocked := false
		for _, prefix := range denyPrefixes {
			if strings.HasPrefix(key, prefix) {
				if _, allowed := allow[key]; !allowed {
					blocked = true
				}
				break
			}
		}
		if blocked {
			continue
		}
		kept = append(kept, field)
	}
	return strings.Join(kept, " ")
}

func envFalsey(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "0", "false", "no", "off", "disabled":
		return true
	default:
		return false
	}
}

func kernelModuleDoctorCheck(statuses []kernelmodule.Status) doctorCheck {
	if len(statuses) == 0 {
		return doctorCheck{Name: "kernel_modules", Status: "ok", Detail: "no kernel modules configured"}
	}
	worst := "ok"
	details := make([]string, 0, len(statuses))
	for _, status := range statuses {
		if status.Mode == kernelmodule.ModeRequired && !status.Loaded {
			worst = "degraded"
		} else if worst == "ok" && status.Mode == kernelmodule.ModeAuto && !status.Loaded {
			worst = "warn"
		}
		detail := fmt.Sprintf("%s mode=%s loaded=%t managed=%t state=%s", status.Name, status.Mode, status.Loaded, status.Managed, status.State)
		if status.Path != "" {
			detail += " path=" + status.Path
		}
		if status.SHA256 != "" {
			detail += " sha256=" + status.SHA256
		}
		if status.LoadedSHA256 != "" {
			detail += " loaded_sha256=" + status.LoadedSHA256
		}
		if status.ReloadOnUpgrade != "" {
			detail += " reload_on_upgrade=" + status.ReloadOnUpgrade
		}
		if status.UpgradeState != "" {
			detail += " upgrade_state=" + status.UpgradeState
			switch status.UpgradeState {
			case "mismatch", "missing_loaded_fingerprint", "reload_failed":
				if status.Mode == kernelmodule.ModeRequired {
					worst = "degraded"
				} else if worst == "ok" {
					worst = "warn"
				}
			}
		}
		if status.CapabilityTier != "" {
			detail += " tier=" + status.CapabilityTier
		}
		if status.ABIVersion > 0 {
			detail += fmt.Sprintf(" abi=%d", status.ABIVersion)
		}
		if len(status.Features) > 0 {
			detail += " features=" + joinDetails(status.Features)
		}
		if len(status.MissingFeatures) > 0 {
			detail += " missing=" + joinDetails(status.MissingFeatures)
		}
		if status.Reason != "" {
			detail += " reason=" + status.Reason
		}
		details = append(details, detail)
	}
	return doctorCheck{Name: "kernel_modules", Status: worst, Detail: joinDetails(details)}
}

func joinDetails(details []string) string {
	if len(details) == 0 {
		return ""
	}
	out := details[0]
	for _, detail := range details[1:] {
		out += "; " + detail
	}
	return out
}
