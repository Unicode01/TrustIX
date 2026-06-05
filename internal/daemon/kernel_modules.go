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
	cryptoStatus, err := daemon.kernelCrypto.Ensure(ctx, desired.KernelModules.TrustIXCrypto)
	if err != nil {
		return []kernelmodule.Status{cryptoStatus}, err
	}
	datapathModule := desired.KernelModules.TrustIXDatapath
	datapathModule.Parameters = TrustIXDatapathModuleParameters(datapathModule.Parameters)
	datapathStatus, err := daemon.kernelDatapath.Ensure(ctx, datapathModule)
	statuses := []kernelmodule.Status{cryptoStatus, datapathStatus}
	if err != nil {
		return statuses, err
	}
	helpersModule := desired.KernelModules.TrustIXDatapathHelpers
	helpersModule.Parameters = TrustIXDatapathHelpersModuleParameters(helpersModule.Parameters)
	helpersStatus, err := daemon.kernelHelpers.Ensure(ctx, helpersModule)
	statuses = append(statuses, helpersStatus)
	if err != nil {
		return statuses, err
	}
	return statuses, nil
}

func TrustIXDatapathModuleParameters(raw string) string {
	params := strings.TrimSpace(raw)
	fullPlaintext := envTruthyAny(
		"TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT",
		"TRUSTIX_KERNEL_DATAPATH_TX_PLAINTEXT",
	)
	if !envTruthyAny("TRUSTIX_KERNEL_DATAPATH_RX_WORKER") && !fullPlaintext {
		return params
	}
	params = appendModuleParameterIfMissing(params, "enable_features=128")
	params = appendModuleParameterIfMissing(params, "rx_worker_inject=1")
	if fullPlaintext {
		params = appendModuleParameterIfMissing(params, "tx_plaintext=1")
	}
	if envTruthyAny(
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_STEAL",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE_STOLEN",
	) {
		params = appendModuleParameterIfMissing(params, "rx_worker_steal_skb=1")
	}
	if envTruthyAny(
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE_STOLEN",
	) {
		params = appendModuleParameterIfMissing(params, "rx_worker_inline_stolen=1")
	}
	if envTruthyAny(
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_LAN_XMIT",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE_XMIT",
	) && envTruthyAny("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_ALLOW_UNSAFE_XMIT") {
		params = appendModuleParameterIfMissing(params, "rx_worker_xmit=1")
	}
	if envTruthyAny("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_DIRECT_XMIT") &&
		envTruthyAny("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_ALLOW_UNSAFE_XMIT") {
		params = appendModuleParameterIfMissing(params, "rx_worker_direct_xmit=1")
	}
	if envTruthyAny("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE_XMIT") &&
		envTruthyAny("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_ALLOW_UNSAFE_XMIT") {
		params = appendModuleParameterIfMissing(params, "rx_worker_inline_xmit=1")
	}
	if envTruthyAny("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE_XMIT_NO_COPY_CSUM") {
		params = appendModuleParameterIfMissing(params, "rx_worker_inline_xmit_copy_csum=0")
	}
	if envFalsey("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_HOT_STATS") {
		params = appendModuleParameterIfMissing(params, "rx_worker_hot_stats=0")
	}
	if envTruthyAny("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE_PAIR_COALESCE") {
		params = appendModuleParameterIfMissing(params, "rx_worker_inline_pair_coalesce=1")
		if envTruthyAny("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE_PAIR_HOLD_SKB") {
			params = appendModuleParameterIfMissing(params, "rx_worker_inline_pair_hold_skb=1")
		}
		params = appendModuleParameterFromEnvIfMissing(params, "rx_worker_inline_pair_flush_jiffies", "TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE_PAIR_FLUSH_JIFFIES")
		params = appendModuleParameterFromEnvIfMissing(params, "rx_worker_inline_coalesce_max_frames", "TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE_COALESCE_MAX_FRAMES")
	}
	if envTruthyAny(
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_STEAL_XMIT",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_ALLOW_STEAL_XMIT",
	) {
		params = appendModuleParameterIfMissing(params, "rx_worker_steal_xmit=1")
	}
	if envTruthyAny("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_STEAL_TCP") {
		params = appendModuleParameterIfMissing(params, "rx_worker_steal_tcp=1")
	}
	if envTruthyAny(
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE_RECEIVE",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_RECEIVE",
	) {
		params = appendModuleParameterIfMissing(params, "rx_worker_steal_skb=1")
		params = appendModuleParameterIfMissing(params, "rx_worker_inline_stolen=1")
		params = appendModuleParameterIfMissing(params, "rx_worker_inline_receive=1")
	}
	if envTruthyAny(
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_TCP",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_ALLOW_EXPERIMENTAL_TCP",
	) {
		params = appendModuleParameterIfMissing(params, "rx_worker_tcp=1")
	}
	if envTruthyAny(
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_STREAM_TCP",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_TCP_STREAM",
	) {
		params = appendModuleParameterIfMissing(params, "rx_worker_tcp=1")
		params = appendModuleParameterIfMissing(params, "rx_worker_stream_tcp=1")
	}
	if envTruthyAny(
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_STREAM_BATCH_QUEUE",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_TCP_STREAM_BATCH_QUEUE",
	) {
		params = appendModuleParameterIfMissing(params, "rx_worker_stream_batch_queue=1")
	}
	params = appendModuleParameterFromEnvIfMissing(
		params,
		"rx_worker_xmit_trust_tcp_checksum_min_len",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT_TRUST_TCP_CHECKSUM_MIN_LEN",
	)
	if envTruthyAny("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT_TRUST_TCP_CHECKSUM_ACK_ONLY") {
		params = appendModuleParameterIfMissing(params, "rx_worker_xmit_trust_tcp_checksum_ack_only=1")
	}
	if envTruthyAny("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT_TCP_PARTIAL_CSUM") {
		params = appendModuleParameterIfMissing(params, "rx_worker_xmit_tcp_partial_csum=1")
	}
	if envTruthyAny("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT_HASH_TX_QUEUE") {
		params = appendModuleParameterIfMissing(params, "rx_worker_xmit_hash_tx_queue=1")
	}
	if envTruthyAny("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT_MORE") {
		params = appendModuleParameterIfMissing(params, "rx_worker_xmit_more=1")
	}
	if envTruthyAny("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT_DST_MAC_CACHE") {
		params = appendModuleParameterIfMissing(params, "rx_worker_xmit_dst_mac_cache=1")
	}
	if envTruthyAny("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT_DST_MAC_PCPU_CACHE") {
		params = appendModuleParameterIfMissing(params, "rx_worker_xmit_dst_mac_pcpu_cache=1")
	}
	if envTruthyAny("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT_DST_MAC_SEQ_CACHE") {
		params = appendModuleParameterIfMissing(params, "rx_worker_xmit_dst_mac_seq_cache=1")
	}
	if envTruthyAny("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_QUEUE_SKB") {
		params = appendModuleParameterIfMissing(params, "rx_worker_queue_skb=1")
	}
	if envTruthyAny("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_STREAM_COALESCE_GSO") {
		params = appendModuleParameterIfMissing(params, "rx_worker_stream_coalesce_gso=1")
	}
	if envTruthyAny("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_STREAM_COALESCE_SOFTWARE_SEGMENT") {
		params = appendModuleParameterIfMissing(params, "rx_worker_stream_coalesce_software_segment=1")
	}
	if envTruthyAny("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_STREAM_COALESCE_FULL_CSUM") {
		params = appendModuleParameterIfMissing(params, "rx_worker_stream_coalesce_partial_csum=0")
	}
	return params
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
	return kernelmoduleModeActive(oldDesired.KernelModules.TrustIXCrypto.Mode) ||
		kernelmoduleModeActive(newDesired.KernelModules.TrustIXCrypto.Mode) ||
		kernelmoduleModeActive(oldDesired.KernelModules.TrustIXDatapath.Mode) ||
		kernelmoduleModeActive(newDesired.KernelModules.TrustIXDatapath.Mode) ||
		kernelmoduleModeActive(oldDesired.KernelModules.TrustIXDatapathHelpers.Mode) ||
		kernelmoduleModeActive(newDesired.KernelModules.TrustIXDatapathHelpers.Mode)
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
	params := strings.TrimSpace(raw)
	params = appendTrustIXDatapathHelpersTIXTParameters(params)
	if !datapathRouteTCPXmitWorkerRequested() {
		return params
	}
	params = appendModuleParameterIfMissing(params, "route_tcp_xmit_worker=1")
	if envTruthyAny("TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_STEAL", "TRUSTIX_EXPERIMENTAL_TCP_ROUTE_TCP_XMIT_WORKER_STEAL") &&
		envTruthyAny("TRUSTIX_EXPERIMENTAL_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_XMIT_STEAL") {
		params = appendModuleParameterIfMissing(params, "route_tcp_xmit_worker_steal=1")
	}
	return params
}

func appendTrustIXDatapathHelpersTIXTParameters(params string) string {
	if envTruthyAny(
		"TRUSTIX_TIXT_RX_SINGLE_COALESCE_GSO",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_RX_SINGLE_COALESCE_GSO",
	) {
		params = appendModuleParameterIfMissing(params, "tixt_rx_single_coalesce_gso=1")
	}
	if envTruthyAny(
		"TRUSTIX_TIXT_RX_SINGLE_COALESCE_SKIP_TCP_CSUM",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_RX_SINGLE_COALESCE_SKIP_TCP_CSUM",
	) {
		params = appendModuleParameterIfMissing(params, "tixt_rx_single_coalesce_skip_tcp_csum=1")
	}
	if envTruthyAny(
		"TRUSTIX_TIXT_RX_SINGLE_COALESCE_NETIF_RX",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_RX_SINGLE_COALESCE_NETIF_RX",
	) {
		params = appendModuleParameterIfMissing(params, "tixt_rx_single_coalesce_netif_rx=1")
	}
	if envTruthyAny(
		"TRUSTIX_TIXT_RX_SINGLE_COALESCE_PAGE_ONLY",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_RX_SINGLE_COALESCE_PAGE_ONLY",
	) {
		params = appendModuleParameterIfMissing(params, "tixt_rx_single_coalesce_page_only=1")
	}
	if envTruthyAny(
		"TRUSTIX_TIXT_RX_SINGLE_COALESCE_LINEAR_BUILD",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_RX_SINGLE_COALESCE_LINEAR_BUILD",
	) {
		params = appendModuleParameterIfMissing(params, "tixt_rx_single_coalesce_linear_build=1")
	}
	if envTruthyAny(
		"TRUSTIX_TIXT_RX_SINGLE_COALESCE_HYBRID_HEAD",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_RX_SINGLE_COALESCE_HYBRID_HEAD",
	) {
		params = appendModuleParameterIfMissing(params, "tixt_rx_single_coalesce_hybrid_head=1")
	}
	if envTruthyAny(
		"TRUSTIX_TIXT_RX_STREAM_ORDERED_LIST",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_RX_STREAM_ORDERED_LIST",
	) {
		params = appendModuleParameterIfMissing(params, "tixt_rx_stream_ordered_list=1")
	}
	return params
}

func datapathRouteTCPXmitWorkerRequested() bool {
	return envTruthyAny(
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_XMIT_KFUNC",
	) && envTruthyAny(
		"TRUSTIX_EXPERIMENTAL_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_XMIT",
		"TRUSTIX_EXPERIMENTAL_TCP_ROUTE_TCP_XMIT_CRASH_RISK_ACK",
	)
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
