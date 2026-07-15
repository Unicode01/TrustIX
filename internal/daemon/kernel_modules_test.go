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

func daemonTestSourceFunctionBody(t *testing.T, source string, name string) string {
	t.Helper()
	offset := 0
	for {
		start := strings.Index(source[offset:], name+"(")
		if start < 0 {
			t.Fatalf("function %s not found", name)
		}
		start += offset
		openRel := strings.Index(source[start:], "{")
		if openRel < 0 {
			t.Fatalf("function %s has no body", name)
		}
		open := start + openRel
		if semiRel := strings.Index(source[start:open], ";"); semiRel >= 0 {
			offset = open + 1
			continue
		}
		depth := 0
		for i := open; i < len(source); i++ {
			switch source[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					return source[open : i+1]
				}
			}
		}
		t.Fatalf("function %s body is not closed", name)
	}
}

func TestTrustIXDatapathRXWorkerSoftwareSegmentGatesDirectGSOXmit(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "kernel", "trustix_datapath", "trustix_datapath.c"))
	if err != nil {
		t.Fatalf("read trustix_datapath source: %v", err)
	}
	xmitBody := daemonTestSourceFunctionBody(t, string(body), "trustix_datapath_rx_worker_xmit_inner_gso")
	softwareSegmentStart := strings.Index(xmitBody, "READ_ONCE(trustix_datapath_rx_worker_stream_coalesce_software_segment)")
	supportedStart := strings.Index(xmitBody, "trustix_datapath_rx_worker_inner_gso_xmit_supported")
	directStart := strings.Index(xmitBody, "trustix_datapath_rx_worker_xmit_inner_gso_direct")
	fallbackStart := strings.Index(xmitBody, "trustix_datapath_rx_worker_gso_xmit_fallbacks++;")
	segmentsStart := strings.Index(xmitBody, "trustix_datapath_rx_worker_xmit_inner_gso_segments")
	if softwareSegmentStart < 0 || supportedStart < 0 || directStart < 0 ||
		fallbackStart < 0 || segmentsStart < 0 ||
		softwareSegmentStart >= supportedStart ||
		supportedStart >= directStart ||
		directStart >= fallbackStart ||
		fallbackStart >= segmentsStart {
		t.Fatalf("rx_worker_stream_coalesce_software_segment must disable direct GSO before segment fallback; body:\n%s", xmitBody)
	}
}

func TestTrustIXDatapathReleasesHeldNetdevRefsOnUnregister(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "kernel", "trustix_datapath", "trustix_datapath.c"))
	if err != nil {
		t.Fatalf("read trustix_datapath source: %v", err)
	}
	source := string(body)
	releaseBody := daemonTestSourceFunctionBody(t, source, "trustix_datapath_release_netdev_refs")
	for _, want := range []string{
		"trustix_datapath_hook_release_netdev(dev);",
		"trustix_datapath_rx_worker_drop_pending_sync();",
		"trustix_datapath_tx_plaintext_drop_pending_sync();",
	} {
		if !strings.Contains(releaseBody, want) {
			t.Fatalf("release netdev refs missing %q:\n%s", want, releaseBody)
		}
	}
	eventBody := daemonTestSourceFunctionBody(t, source, "trustix_datapath_netdev_event")
	if !strings.Contains(eventBody, "event == NETDEV_UNREGISTER") ||
		!strings.Contains(eventBody, "trustix_datapath_release_netdev_refs(dev)") {
		t.Fatalf("netdev notifier does not release refs on unregister:\n%s", eventBody)
	}
	initBody := daemonTestSourceFunctionBody(t, source, "trustix_datapath_init")
	if !strings.Contains(initBody, "register_netdevice_notifier(&trustix_datapath_netdev_notifier)") {
		t.Fatalf("datapath init does not register netdev notifier:\n%s", initBody)
	}
	exitBody := daemonTestSourceFunctionBody(t, source, "trustix_datapath_exit")
	unregister := strings.Index(exitBody, "unregister_netdevice_notifier(&trustix_datapath_netdev_notifier)")
	detach := strings.Index(exitBody, "trustix_datapath_hook_detach_all()")
	if unregister < 0 || detach < 0 || unregister > detach {
		t.Fatalf("datapath exit must unregister notifier before detach-all:\n%s", exitBody)
	}
}

func TestTrustIXDatapathRXWorkerMACCacheKeepsMultipleDestinations(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "kernel", "trustix_datapath", "trustix_datapath.c"))
	if err != nil {
		t.Fatalf("read trustix_datapath source: %v", err)
	}
	source := string(body)
	for _, want := range []string{
		"#define TRUSTIX_DATAPATH_RX_WORKER_MAC_CACHE_SETS 64",
		"#define TRUSTIX_DATAPATH_RX_WORKER_MAC_CACHE_WAYS 4",
		"#define TRUSTIX_DATAPATH_MAC_CACHE_TTL (30 * HZ)",
		"trustix_datapath_selftest_rx_worker_mac_cache()",
		"alloc_percpu(struct trustix_datapath_rx_worker_mac_cache)",
		"free_percpu(trustix_datapath_rx_worker_pcpu_mac_cache)",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("multi-destination RX worker MAC cache missing %q", want)
		}
	}
	if strings.Contains(source, "DEFINE_PER_CPU(struct trustix_datapath_rx_worker_mac_cache") {
		t.Fatal("large RX worker MAC cache remains in the module static per-CPU area")
	}
	init := daemonTestSourceFunctionBody(t, source, "trustix_datapath_init")
	if !strings.Contains(init, "trustix_datapath_alloc_rx_worker_pcpu_mac_cache()") ||
		!strings.Contains(init, "trustix_datapath_free_rx_worker_pcpu_mac_cache()") {
		t.Fatal("RX worker per-CPU MAC cache allocation is not covered by init failure cleanup")
	}
	exit := daemonTestSourceFunctionBody(t, source, "trustix_datapath_exit")
	if !strings.Contains(exit, "trustix_datapath_free_rx_worker_pcpu_mac_cache()") {
		t.Fatal("RX worker per-CPU MAC cache is not freed during module exit")
	}
	lookup := daemonTestSourceFunctionBody(t, source, "trustix_datapath_rx_worker_mac_cache_lookup")
	if !strings.Contains(lookup, "time_after_eq(jiffies, entry->expires)") {
		t.Fatal("RX worker MAC cache entries do not expire")
	}
	selftest := daemonTestSourceFunctionBody(t, source, "trustix_datapath_selftest_rx_worker_mac_cache")
	for _, dst := range []string{"htonl(0x0a400001)", "htonl(0x0a400081)"} {
		if !strings.Contains(selftest, dst) {
			t.Fatalf("RX worker MAC cache selftest does not retain destination %s", dst)
		}
	}
}

func TestTrustIXDatapathTXPlaintextMACCacheKeepsSessionPoolTuples(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "kernel", "trustix_datapath", "trustix_datapath.c"))
	if err != nil {
		t.Fatalf("read trustix_datapath source: %v", err)
	}
	source := string(body)
	for _, want := range []string{
		"#define TRUSTIX_DATAPATH_TX_PLAINTEXT_MAC_CACHE_SETS 16",
		"#define TRUSTIX_DATAPATH_TX_PLAINTEXT_MAC_CACHE_WAYS 4",
		"trustix_datapath_selftest_tx_plaintext_mac_cache()",
		"tx_plaintext_hash_tx_queue_partition_transport",
		"trustix_datapath_selftest_tx_plaintext_hash_tx_queue()",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("multi-session TX plaintext MAC cache missing %q", want)
		}
	}
	lookup := daemonTestSourceFunctionBody(t, source, "trustix_datapath_tx_plaintext_mac_cache_lookup")
	if !strings.Contains(lookup, "time_after_eq(jiffies, entry->expires)") {
		t.Fatal("TX plaintext MAC cache entries do not expire")
	}
	queue := daemonTestSourceFunctionBody(t, source, "trustix_datapath_tx_plaintext_set_hash_tx_queue")
	if !strings.Contains(queue, "if (txq_count <= 1)\n\t\treturn;") {
		t.Fatal("single-queue devices must skip TX queue hashing without recording per-packet fallbacks")
	}
	for _, want := range []string{
		"trustix_datapath_tx_plaintext_hash_tx_queue_for_transport",
		"trustix_datapath_tx_plaintext_hash_tx_queue_partition_udp_sets",
		"trustix_datapath_tx_plaintext_hash_tx_queue_partition_tcp_sets",
		"trustix_datapath_tx_plaintext_hash_tx_queue_partition_fallbacks",
	} {
		if !strings.Contains(queue, want) {
			t.Fatalf("plaintext TX queue selection missing transport partition behavior %q", want)
		}
	}
	partition := daemonTestSourceFunctionBody(t, source, "trustix_datapath_tx_plaintext_hash_tx_queue_for_transport")
	for _, want := range []string{
		"mixed % txq_count",
		"(mixed % subset_count) * 2 + 1",
	} {
		if !strings.Contains(partition, want) {
			t.Fatalf("plaintext TX queue partition missing mapping %q", want)
		}
	}
	selftest := daemonTestSourceFunctionBody(t, source, "trustix_datapath_selftest_tx_plaintext_mac_cache")
	if !strings.Contains(selftest, "for (i = 0; i < 16; i++)") ||
		!strings.Contains(selftest, "plan.outer_protocol = (i & 1) ? IPPROTO_TCP : IPPROTO_UDP") ||
		!strings.Contains(selftest, "trustix_datapath_tx_plaintext_mac_cache_invalidate(cache, 10) != 1") {
		t.Fatalf("TX plaintext MAC cache selftest does not retain mixed session-pool tuples")
	}
	for _, want := range []string{
		"#include <net/netevent.h>",
		"register_netevent_notifier(&trustix_datapath_netevent_notifier)",
		"unregister_netevent_notifier(&trustix_datapath_netevent_notifier)",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("TX plaintext MAC cache neighbour invalidation missing %q", want)
		}
	}
	netevent := daemonTestSourceFunctionBody(t, source, "trustix_datapath_netevent")
	for _, want := range []string{
		"NETEVENT_NEIGH_UPDATE",
		"neigh->tbl != &arp_tbl",
		"neigh->dev->ifindex",
		"trustix_datapath_tx_plaintext_dst_mac_cache_invalidate_ifindex",
	} {
		if !strings.Contains(netevent, want) {
			t.Fatalf("TX plaintext MAC cache neighbour callback missing %q", want)
		}
	}
}

func TestTrustIXDatapathModuleParametersForDesiredPartitionsMixedPlaintextTransports(t *testing.T) {
	desired := config.Desired{
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
		},
		TransportPolicy: config.TransportPolicyConfig{
			Datapath:   config.TransportDatapathKernelModule,
			Encryption: securetransport.EncryptionPlaintext,
			Candidates: []core.EndpointID{"udp-a", "exp-a"},
		},
		Endpoints: []config.EndpointConfig{
			{Name: "udp-a", Transport: string(transport.ProtocolUDP), Enabled: true},
			{Name: "exp-a", Transport: string(transport.ProtocolTIXTCP), Enabled: true},
		},
	}

	got := TrustIXDatapathModuleParametersForDesired("", desired)
	if !moduleParameterHasAssignment(got, "tx_plaintext_hash_tx_queue_partition_transport=1") {
		t.Fatalf("mixed plaintext full-kmod parameters = %q, missing transport queue partition", got)
	}

	got = TrustIXDatapathModuleParametersForDesired("tx_plaintext_hash_tx_queue_partition_transport=0", desired)
	if !moduleParameterHasAssignment(got, "tx_plaintext_hash_tx_queue_partition_transport=0") ||
		moduleParameterHasAssignment(got, "tx_plaintext_hash_tx_queue_partition_transport=1") {
		t.Fatalf("mixed plaintext full-kmod parameters = %q, ignored explicit partition disable", got)
	}

	for _, candidate := range []core.EndpointID{"udp-a", "exp-a"} {
		single := desired
		single.TransportPolicy.Candidates = []core.EndpointID{candidate}
		got = TrustIXDatapathModuleParametersForDesired("", single)
		if moduleParameterHasAssignment(got, "tx_plaintext_hash_tx_queue_partition_transport=1") {
			t.Fatalf("single-transport %s parameters = %q, halved available TX queues", candidate, got)
		}
	}

	secure := desired
	secure.TransportPolicy.Encryption = securetransport.EncryptionSecure
	got = TrustIXDatapathModuleParametersForDesired("", secure)
	if moduleParameterHasAssignment(got, "tx_plaintext_hash_tx_queue_partition_transport=1") {
		t.Fatalf("secure mixed-transport parameters = %q, enabled plaintext TX queue partition", got)
	}
}

func TestTrustIXDatapathHelpersFlushQueuedNetdevRefsOnUnregister(t *testing.T) {
	kfuncsBytes, err := os.ReadFile(filepath.Join("..", "..", "kernel", "trustix_datapath_helpers", "trustix_datapath_helpers_kfuncs.c"))
	if err != nil {
		t.Fatalf("read trustix_datapath_helpers kfunc source: %v", err)
	}
	kfuncs := string(kfuncsBytes)
	releaseBody := daemonTestSourceFunctionBody(t, kfuncs, "trustix_datapath_helpers_release_netdev_refs")
	for _, want := range []string{
		"WRITE_ONCE(trustix_route_tcp_gso_async_quiescing, true);",
		"WRITE_ONCE(trustix_tixt_rx_backlog_worker_quiescing, true);",
		"trustix_route_tcp_gso_async_flush();",
		"trustix_route_tcp_xmit_worker_flush();",
		"trustix_tixt_rx_backlog_worker_flush();",
		"trustix_tixt_rx_single_coalesce_drop_all();",
	} {
		if !strings.Contains(releaseBody, want) {
			t.Fatalf("helper release netdev refs missing %q:\n%s", want, releaseBody)
		}
	}
	eventBody := daemonTestSourceFunctionBody(t, kfuncs, "trustix_datapath_helpers_netdev_event")
	if !strings.Contains(eventBody, "event == NETDEV_UNREGISTER") ||
		!strings.Contains(eventBody, "trustix_datapath_helpers_release_netdev_refs(dev)") {
		t.Fatalf("helper netdev notifier does not flush refs on unregister:\n%s", eventBody)
	}
	registerBody := daemonTestSourceFunctionBody(t, kfuncs, "trustix_datapath_helpers_register")
	notifier := strings.Index(registerBody, "register_netdevice_notifier(")
	btf := strings.Index(registerBody, "register_btf_kfunc_id_set(")
	if notifier < 0 || btf < 0 || notifier > btf {
		t.Fatalf("helper register must install netdev notifier before BTF kfunc registration:\n%s", registerBody)
	}
	if !strings.Contains(registerBody, "unregister_netdevice_notifier(") {
		t.Fatalf("helper register failure path must unregister netdev notifier:\n%s", registerBody)
	}
	unregisterBody := daemonTestSourceFunctionBody(t, kfuncs, "trustix_datapath_helpers_unregister")
	if !strings.Contains(unregisterBody, "WRITE_ONCE(trustix_datapath_helpers_registered, false);") ||
		!strings.Contains(unregisterBody, "unregister_netdevice_notifier(") {
		t.Fatalf("helper unregister must fail closed and unregister notifier:\n%s", unregisterBody)
	}

	mainBytes, err := os.ReadFile(filepath.Join("..", "..", "kernel", "trustix_datapath_helpers", "trustix_datapath_helpers_main.c"))
	if err != nil {
		t.Fatalf("read trustix_datapath_helpers main source: %v", err)
	}
	initBody := daemonTestSourceFunctionBody(t, string(mainBytes), "trustix_datapath_helpers_init")
	misc := strings.Index(initBody, "misc_register(&trustix_datapath_helpers_miscdev)")
	cleanup := strings.Index(initBody, "trustix_datapath_helpers_unregister();")
	if misc < 0 || cleanup < 0 || cleanup < misc {
		t.Fatalf("helper init must unregister helper runtime if misc_register fails:\n%s", initBody)
	}
}

func TestCrossHostRunnerUnloadsDatapathBeforeDeletingLAN(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "scripts", "linux-cross-host-soak-runner.sh"))
	if err != nil {
		t.Fatalf("read runner source: %v", err)
	}
	source := string(body)
	unload := strings.Index(source, "rmmod trustix_datapath >/dev/null 2>&1 || true")
	deleteLAN := strings.LastIndex(source, `link del $(remote_quote "$lan_if")`)
	if unload < 0 || deleteLAN < 0 || unload > deleteLAN {
		t.Fatalf("runner must unload trustix_datapath before deleting the LAN link")
	}
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
	want := "enable_features=128 rx_worker_inject=1 tx_plaintext=1 rx_worker_xmit=1 rx_worker_inline_xmit=1 rx_worker_inline_xmit_copy_csum=1 rx_worker_direct_xmit=1 rx_worker_inline_coalesce_max_frames=16 rx_worker_single_coalesce=1 rx_worker_single_coalesce_max_frames=32 rx_worker_tcp=1 rx_worker_stream_tcp=1 rx_worker_stream_batch_queue=1 rx_worker_stream_coalesce_gso=1 rx_worker_stream_coalesce_software_segment=0 rx_worker_xmit_more=1 rx_worker_xmit_dst_mac_cache=1 tx_plaintext_inline_xmit=1 tx_plaintext_direct_xmit=1 tx_plaintext_payload_fast_copy=1 tx_plaintext_hash_tx_queue=1 tx_plaintext_stream_coalesce=0 tx_plaintext_skip_inner_tcp_checksum=0 tx_plaintext_stream_coalesce_max_frames=16 tx_plaintext_slots=8192 rx_worker_budget=1024 rx_worker_slots=8192 rx_worker_hot_stats=0"
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
	want := "enable_features=128 rx_worker_inject=1 tx_plaintext=1 rx_worker_xmit=1 rx_worker_inline_xmit=1 rx_worker_inline_xmit_copy_csum=1 rx_worker_direct_xmit=1 rx_worker_inline_coalesce_max_frames=16 rx_worker_single_coalesce=0 rx_worker_tcp=1 rx_worker_stream_tcp=1 rx_worker_stream_batch_queue=1 rx_worker_stream_coalesce_gso=1 rx_worker_stream_coalesce_software_segment=0 rx_worker_xmit_more=1 rx_worker_xmit_dst_mac_cache=1 tx_plaintext_inline_xmit=1 tx_plaintext_direct_xmit=1 tx_plaintext_payload_fast_copy=1 tx_plaintext_hash_tx_queue=1 tx_plaintext_stream_coalesce=0 tx_plaintext_skip_inner_tcp_checksum=0 tx_plaintext_stream_coalesce_max_frames=16 tx_plaintext_slots=8192 rx_worker_budget=1024 rx_worker_slots=8192 rx_worker_hot_stats=0"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersOpenWrtDisablesSingleCoalesceByDefault(t *testing.T) {
	t.Setenv("TRUSTIX_ASSUME_OPENWRT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_OPENWRT_FULL_DATAPATH", "1")

	got := TrustIXDatapathModuleParameters("")
	if !moduleParameterHasAssignment(got, "rx_worker_single_coalesce=0") {
		t.Fatalf("parameters = %q, missing OpenWrt single-coalesce default disable", got)
	}
	if moduleParameterHasAssignment(got, "rx_worker_single_coalesce=1") ||
		moduleParameterHasAssignment(got, "rx_worker_single_coalesce_max_frames=32") {
		t.Fatalf("parameters = %q, kept OpenWrt single-coalesce enabled by default", got)
	}
}

func TestTrustIXDatapathModuleParametersOpenWrtSingleCoalesceExplicitEnable(t *testing.T) {
	t.Setenv("TRUSTIX_ASSUME_OPENWRT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_OPENWRT_FULL_DATAPATH", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ENABLE_OPENWRT_RX_SINGLE_COALESCE", "1")

	got := TrustIXDatapathModuleParameters("")
	for _, want := range []string{
		"rx_worker_single_coalesce=1",
		"rx_worker_single_coalesce_max_frames=32",
	} {
		if !moduleParameterHasAssignment(got, want) {
			t.Fatalf("parameters = %q, missing explicit OpenWrt single-coalesce assignment %q", got, want)
		}
	}
}

func TestTrustIXDatapathModuleParametersOpenWrtSingleCoalesceExplicitDisable(t *testing.T) {
	t.Setenv("TRUSTIX_ASSUME_OPENWRT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_OPENWRT_FULL_DATAPATH", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_DISABLE_OPENWRT_RX_SINGLE_COALESCE", "1")

	got := TrustIXDatapathModuleParameters("")
	if !moduleParameterHasAssignment(got, "rx_worker_single_coalesce=0") {
		t.Fatalf("parameters = %q, missing explicit OpenWrt single-coalesce disable", got)
	}
	if moduleParameterHasAssignment(got, "rx_worker_single_coalesce=1") ||
		moduleParameterHasAssignment(got, "rx_worker_single_coalesce_max_frames=32") {
		t.Fatalf("parameters = %q, kept OpenWrt single-coalesce enable after explicit disable", got)
	}
}

func TestTrustIXDatapathModuleParametersRewritesLegacyFullPlaintextChecksumSkip(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")

	got := TrustIXDatapathModuleParameters("tx_plaintext_skip_inner_tcp_checksum=1 tx_plaintext_stream_coalesce=1")
	for _, want := range []string{
		"tx_plaintext_skip_inner_tcp_checksum=0",
		"tx_plaintext_stream_coalesce=0",
	} {
		if !moduleParameterHasAssignment(got, want) {
			t.Fatalf("parameters = %q, missing rewritten %q", got, want)
		}
	}
	for _, unexpected := range []string{
		"tx_plaintext_skip_inner_tcp_checksum=1",
		"tx_plaintext_stream_coalesce=1",
	} {
		if moduleParameterHasAssignment(got, unexpected) {
			t.Fatalf("parameters = %q, kept legacy slow assignment %q", got, unexpected)
		}
	}
}

func TestTrustIXDatapathModuleParametersPreservesTXPlaintextExperimentsWhenAllowed(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_TX_PLAINTEXT_EXPERIMENTS", "1")

	got := TrustIXDatapathModuleParameters("tx_plaintext_skip_inner_tcp_checksum=1 tx_plaintext_outer_gso_max_frames=16 tx_plaintext_stream_coalesce=1 tx_plaintext_stream_coalesce_max_frames=32 tx_plaintext_stream_coalesce_flush_jiffies=1")
	for _, want := range []string{
		"tx_plaintext_skip_inner_tcp_checksum=1",
		"tx_plaintext_outer_gso_max_frames=16",
		"tx_plaintext_stream_coalesce=1",
		"tx_plaintext_stream_coalesce_max_frames=32",
		"tx_plaintext_stream_coalesce_flush_jiffies=1",
	} {
		if !moduleParameterHasAssignment(got, want) {
			t.Fatalf("parameters = %q, missing explicit experiment assignment %q", got, want)
		}
	}
}

func TestTrustIXDatapathModuleParametersPreservesExplicitTXPlaintextFastCopyDisable(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")

	got := TrustIXDatapathModuleParameters("tx_plaintext_payload_fast_copy=0")
	if !moduleParameterHasAssignment(got, "tx_plaintext_payload_fast_copy=0") {
		t.Fatalf("parameters = %q, missing explicit fast-copy disable", got)
	}
	if moduleParameterHasAssignment(got, "tx_plaintext_payload_fast_copy=1") {
		t.Fatalf("parameters = %q, default fast-copy enable overrode explicit disable", got)
	}
}

func TestTrustIXDatapathModuleParametersPreservesExplicitTXPlaintextHashTXQueue(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")

	for _, value := range []string{"0", "1"} {
		want := "tx_plaintext_hash_tx_queue=" + value
		got := TrustIXDatapathModuleParameters(want)
		if !moduleParameterHasAssignment(got, want) {
			t.Fatalf("parameters = %q, missing explicit plaintext TX hash queue assignment %q", got, want)
		}
	}
}

func TestTrustIXDatapathModuleParametersPreservesExplicitTCSkipWhenExperimentsAllowed(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER_EXPERIMENTS", "1")

	got := TrustIXDatapathModuleParameters("rx_worker_tc_skip_classify=1")
	if !moduleParameterHasAssignment(got, "rx_worker_tc_skip_classify=1") {
		t.Fatalf("parameters = %q, missing explicit tc-skip assignment", got)
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
		"rx_worker_single_coalesce_max_frames=32",
		"rx_worker_tcp=1",
		"rx_worker_stream_tcp=1",
		"rx_worker_stream_batch_queue=1",
		"rx_worker_stream_coalesce_gso=1",
		"rx_worker_stream_coalesce_software_segment=0",
		"rx_worker_xmit_more=1",
		"rx_worker_xmit_dst_mac_cache=1",
		"tx_plaintext_inline_xmit=1",
		"tx_plaintext_direct_xmit=1",
		"tx_plaintext_payload_fast_copy=1",
		"tx_plaintext_hash_tx_queue=1",
		"tx_plaintext_skip_inner_tcp_checksum=0",
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

func TestTrustIXDatapathModuleParametersForDesiredOpenWrtFullPlaintextProfileRequiresDedicatedGate(t *testing.T) {
	t.Setenv("TRUSTIX_ASSUME_OPENWRT", "1")
	desired := config.Desired{
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
		},
	}

	got := TrustIXDatapathModuleParametersForDesired("", desired)
	want := "rx_worker_inject=0 tx_plaintext=0"
	if got != want {
		t.Fatalf("parameters = %q, want OpenWrt fail-closed profile parameters %q", got, want)
	}
	if kernelDatapathFullPlaintextEnabledForDesired(desired) {
		t.Fatal("OpenWrt full plaintext profile should require the OpenWrt crash-risk gate")
	}
	if mode := kernelDatapathRXModeForDesired(desired); mode != "" {
		t.Fatalf("OpenWrt full plaintext profile RX mode = %q, want disabled without gate", mode)
	}
}

func TestTrustIXDatapathModuleParametersForDesiredOpenWrtDedicatedGateAllowsFullPlaintextProfile(t *testing.T) {
	t.Setenv("TRUSTIX_ASSUME_OPENWRT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_OPENWRT_FULL_DATAPATH", "1")
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
		"rx_worker_single_coalesce=0",
		"tx_plaintext_inline_xmit=1",
		"rx_worker_budget=1024",
		"rx_worker_slots=8192",
		"rx_worker_hot_stats=0",
	} {
		if !moduleParameterHasAssignment(got, want) {
			t.Fatalf("parameters = %q, missing %q", got, want)
		}
	}
	if !kernelDatapathFullPlaintextEnabledForDesired(desired) {
		t.Fatal("OpenWrt dedicated gate should enable full plaintext profile")
	}
	if mode := kernelDatapathRXModeForDesired(desired); mode != kernelDatapathRXModeWorker {
		t.Fatalf("OpenWrt full plaintext profile RX mode = %q, want worker with gate", mode)
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
		"tx_plaintext_payload_fast_copy=1",
		"tx_plaintext_hash_tx_queue=1",
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

func TestEffectiveKernelModulesOpenWrtAutoEmbeddedDisabled(t *testing.T) {
	t.Setenv("TRUSTIX_ASSUME_OPENWRT", "1")
	desired := config.Desired{
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfilePerformance,
			TrustIXCrypto: config.KernelModuleConfig{
				Mode: kernelmodule.ModeAuto,
				Path: "embedded",
			},
			TrustIXDatapath: config.KernelModuleConfig{
				Mode: kernelmodule.ModeAuto,
			},
			TrustIXDatapathHelpers: config.KernelModuleConfig{
				Mode: kernelmodule.ModeAuto,
				Path: "embedded://trustix_datapath_helpers.ko",
			},
		},
	}

	modules := effectiveKernelModulesForDesired(desired)
	if modules.TrustIXCrypto.Mode != kernelmodule.ModeDisabled ||
		modules.TrustIXDatapath.Mode != kernelmodule.ModeDisabled ||
		modules.TrustIXDatapathHelpers.Mode != kernelmodule.ModeDisabled {
		t.Fatalf("OpenWrt auto embedded modules = %#v, want all disabled", modules)
	}
}

func TestValidateOpenWrtKernelModuleSourcesRejectsRequiredEmbedded(t *testing.T) {
	t.Setenv("TRUSTIX_ASSUME_OPENWRT", "1")
	modules := config.KernelModulesConfig{
		TrustIXDatapath: config.KernelModuleConfig{
			Mode: kernelmodule.ModeRequired,
			Path: "embedded",
		},
	}

	err := validateOpenWrtKernelModuleSources(modules)
	if err == nil || !strings.Contains(err.Error(), "OpenWrt") || !strings.Contains(err.Error(), "SDK-built") {
		t.Fatalf("validateOpenWrtKernelModuleSources error = %v, want SDK-built OpenWrt guard", err)
	}
}

func TestValidateOpenWrtKernelModuleSourcesAllowsRequiredExternalPath(t *testing.T) {
	t.Setenv("TRUSTIX_ASSUME_OPENWRT", "1")
	modules := config.KernelModulesConfig{
		TrustIXDatapath: config.KernelModuleConfig{
			Mode: kernelmodule.ModeRequired,
			Path: "/etc/trustix/modules/trustix_datapath.ko",
		},
	}

	if err := validateOpenWrtKernelModuleSources(modules); err != nil {
		t.Fatalf("validateOpenWrtKernelModuleSources external path error = %v", err)
	}
}

func TestValidateOpenWrtKernelModuleSourcesCanAllowEmbeddedOverride(t *testing.T) {
	t.Setenv("TRUSTIX_ASSUME_OPENWRT", "1")
	t.Setenv("TRUSTIX_KERNEL_MODULE_ALLOW_OPENWRT_EMBEDDED", "1")
	modules := config.KernelModulesConfig{
		TrustIXDatapath: config.KernelModuleConfig{
			Mode: kernelmodule.ModeRequired,
			Path: "embedded",
		},
	}

	if err := validateOpenWrtKernelModuleSources(modules); err != nil {
		t.Fatalf("validateOpenWrtKernelModuleSources override error = %v", err)
	}
}

func TestEffectiveKernelModulesRequiresHelpersForTIXTCPRouteGSO(t *testing.T) {
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
			Datapath:   config.TransportDatapathKernelModule,
			Encryption: "plaintext",
			Candidates: []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolTIXTCP),
			Enabled:   true,
		}},
	}

	if !tixTCPPerformanceRouteGSOAsyncForDesired(desired) {
		t.Fatal("test desired should select tix_tcp route-GSO")
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

func TestEffectiveKernelModulesRequiresHelpersForSecureKernelUDPRouteGSO(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_ROUTE_GSO", "0")

	desired := config.Desired{
		KernelModules: config.KernelModulesConfig{
			CapabilityProfile: config.KernelCapabilityProfilePerformance,
			TrustIXCrypto: config.KernelModuleConfig{
				Mode: kernelmodule.ModeRequired,
				Path: "/tmp/trustix-e2e/modules/trustix_crypto.ko",
			},
			TrustIXDatapath: config.KernelModuleConfig{
				Mode: kernelmodule.ModeDisabled,
			},
			TrustIXDatapathHelpers: config.KernelModuleConfig{
				Mode: kernelmodule.ModeDisabled,
			},
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
	}

	if !kernelUDPSecureRouteGSOForDesired(desired) {
		t.Fatal("test desired should select secure kernel_udp route-GSO")
	}
	modules := effectiveKernelModulesForDesired(desired)
	if modules.TrustIXDatapathHelpers.Mode != kernelmodule.ModeRequired {
		t.Fatalf("secure kernel_udp route-GSO helpers mode = %q, want required", modules.TrustIXDatapathHelpers.Mode)
	}
	if modules.TrustIXDatapathHelpers.Path != "/tmp/trustix-e2e/modules/trustix_datapath_helpers.ko" {
		t.Fatalf("secure kernel_udp route-GSO helpers path = %q, want inferred sibling helper module", modules.TrustIXDatapathHelpers.Path)
	}

	desired.KernelModules.TrustIXCrypto.Path = "embedded://trustix_crypto.ko"
	desired.KernelModules.TrustIXDatapathHelpers.Path = ""
	modules = effectiveKernelModulesForDesired(desired)
	if modules.TrustIXDatapathHelpers.Path != "embedded://trustix_datapath_helpers.ko" {
		t.Fatalf("secure kernel_udp route-GSO embedded helpers path = %q, want embedded helpers", modules.TrustIXDatapathHelpers.Path)
	}
}

func TestValidateTIXTCPRouteGSOHelpersRequiresRouteTCPKfuncs(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_ROUTE_GSO", "1")
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfilePerformance,
			Datapath:   config.TransportDatapathTCXDP,
			Encryption: "plaintext",
			Candidates: []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolTIXTCP),
			Enabled:   true,
		}},
	}

	err := validateTIXTCPRouteGSOHelpersStatus(desired, kernelmodule.Status{
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

	err = validateTIXTCPRouteGSOHelpersStatus(desired, kernelmodule.Status{
		Name:     "trustix_datapath_helpers",
		Loaded:   true,
		State:    "loaded",
		Features: []string{kernelmodule.FeatureGSOSKB},
	})
	if err == nil || !strings.Contains(err.Error(), kernelmodule.FeatureRouteTCPKfunc) || !strings.Contains(err.Error(), kernelmodule.FeatureRouteTCPXmit) {
		t.Fatalf("route-GSO helper validation error = %v, want missing route TCP kfuncs", err)
	}

	withTrustIXDatapathHelpersParameters(t, map[string]string{
		"tixt_tx_plain_skip_sequence":                   "Y",
		"tixt_tx_plain_ack_only":                        "Y",
		"route_tcp_gso":                                 "Y",
		"route_tcp_gso_async":                           "Y",
		"route_tcp_gso_async_dev_xmit":                  "Y",
		"route_tcp_gso_async_force_inner_checksum":      "N",
		"route_tcp_gso_async_force_software_outer_csum": "N",
		"route_tcp_gso_async_stream_outer_gso":          "Y",
		"route_tcp_xmit_worker":                         "Y",
	})
	err = validateTIXTCPRouteGSOHelpersStatus(desired, kernelmodule.Status{
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

func TestValidateSecureKernelUDPRouteGSOHelpersRequiresRouteTCPKfuncs(t *testing.T) {
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

	err := validateRouteGSOHelpersStatus(desired, kernelmodule.Status{
		Name:   "trustix_datapath_helpers",
		Loaded: false,
		State:  kernelmodule.ModeDisabled,
	})
	if err == nil ||
		!strings.Contains(err.Error(), "secure kernel_udp route-GSO") ||
		!strings.Contains(err.Error(), kernelmodule.FeatureRouteTCPKfunc) ||
		!strings.Contains(err.Error(), kernelmodule.FeatureRouteTCPXmit) {
		t.Fatalf("secure kernel_udp route-GSO disabled-helper validation error = %v, want fail-closed missing route TCP kfuncs", err)
	}

	withTrustIXDatapathHelpersParameters(t, map[string]string{
		"route_tcp_gso":                                 "Y",
		"route_tcp_gso_async":                           "Y",
		"route_tcp_gso_async_dev_xmit":                  "Y",
		"route_tcp_gso_async_force_inner_checksum":      "N",
		"route_tcp_gso_async_force_software_outer_csum": "N",
		"route_tcp_gso_async_stream_outer_gso":          "Y",
		"route_tcp_xmit_worker":                         "Y",
	})
	err = validateRouteGSOHelpersStatus(desired, kernelmodule.Status{
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
		t.Fatalf("secure kernel_udp route-GSO helper validation with route TCP features: %v", err)
	}
}

func TestValidateTIXTCPRouteGSOHelpersRequiresActiveRuntimeParameters(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_ROUTE_GSO", "1")
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfilePerformance,
			Datapath:   config.TransportDatapathTCXDP,
			Encryption: "plaintext",
			Candidates: []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolTIXTCP),
			Enabled:   true,
		}},
	}
	withTrustIXDatapathHelpersParameters(t, map[string]string{
		"tixt_tx_plain_skip_sequence":                   "Y",
		"tixt_tx_plain_ack_only":                        "Y",
		"route_tcp_gso":                                 "Y",
		"route_tcp_gso_async":                           "N",
		"route_tcp_gso_async_dev_xmit":                  "Y",
		"route_tcp_gso_async_force_inner_checksum":      "N",
		"route_tcp_gso_async_force_software_outer_csum": "N",
		"route_tcp_gso_async_stream_outer_gso":          "Y",
		"route_tcp_xmit_worker":                         "Y",
	})

	err := validateTIXTCPRouteGSOHelpersStatus(desired, kernelmodule.Status{
		Name:   "trustix_datapath_helpers",
		Loaded: true,
		State:  "loaded",
		Features: []string{
			kernelmodule.FeatureGSOSKB,
			kernelmodule.FeatureRouteTCPKfunc,
			kernelmodule.FeatureRouteTCPXmit,
		},
	})
	if err == nil ||
		!strings.Contains(err.Error(), "runtime parameters") ||
		!strings.Contains(err.Error(), "route_tcp_gso_async=N") {
		t.Fatalf("route-GSO helper runtime parameter validation error = %v, want inactive route_tcp_gso_async", err)
	}
}

func TestValidateTIXTCPRouteGSOHelpersRejectsForcedSoftwareOuterChecksum(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_ROUTE_GSO", "1")
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfilePerformance,
			Datapath:   config.TransportDatapathTCXDP,
			Encryption: "plaintext",
			Candidates: []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolTIXTCP),
			Enabled:   true,
		}},
	}
	withTrustIXDatapathHelpersParameters(t, map[string]string{
		"tixt_tx_plain_skip_sequence":                   "Y",
		"tixt_tx_plain_ack_only":                        "Y",
		"route_tcp_gso":                                 "Y",
		"route_tcp_gso_async":                           "Y",
		"route_tcp_gso_async_dev_xmit":                  "Y",
		"route_tcp_gso_async_force_inner_checksum":      "N",
		"route_tcp_gso_async_force_software_outer_csum": "Y",
		"route_tcp_gso_async_stream_outer_gso":          "Y",
		"route_tcp_xmit_worker":                         "Y",
	})

	err := validateTIXTCPRouteGSOHelpersStatus(desired, kernelmodule.Status{
		Name:   "trustix_datapath_helpers",
		Loaded: true,
		State:  "loaded",
		Features: []string{
			kernelmodule.FeatureGSOSKB,
			kernelmodule.FeatureRouteTCPKfunc,
			kernelmodule.FeatureRouteTCPXmit,
		},
	})
	if err == nil ||
		!strings.Contains(err.Error(), "runtime parameters") ||
		!strings.Contains(err.Error(), "route_tcp_gso_async_force_software_outer_csum=Y") {
		t.Fatalf("route-GSO helper runtime parameter validation error = %v, want forced software checksum rejected", err)
	}
}

func withTrustIXDatapathHelpersParameters(t *testing.T, values map[string]string) {
	t.Helper()
	old := readTrustIXDatapathHelpersParameter
	readTrustIXDatapathHelpersParameter = func(name string) (string, error) {
		value, ok := values[name]
		if !ok {
			return "", os.ErrNotExist
		}
		return value, nil
	}
	t.Cleanup(func() {
		readTrustIXDatapathHelpersParameter = old
	})
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

func TestTrustIXDatapathModuleParametersForDesiredPerformanceTIXTCPKeepsFullPlaintextTX(t *testing.T) {
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
			Transport: "tix_tcp",
			Enabled:   true,
		}},
	}

	got := TrustIXDatapathModuleParametersForDesired("tx_plaintext=1 tx_plaintext_slots=16384", desired)
	for _, want := range []string{
		"rx_worker_inject=1",
		"tx_plaintext=1",
		"rx_worker_xmit=1",
		"tx_plaintext_slots=16384",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("parameters = %q, missing full-kmod plaintext parameter %q", got, want)
		}
	}
	if tixTCPPerformanceRouteGSOAsyncForDesired(desired) {
		t.Fatal("performance tix_tcp kernel_module policy should prefer full-kmod plaintext over route-GSO when full_plaintext is selected")
	}
	if !kernelDatapathFullPlaintextEnabledForDesired(desired) {
		t.Fatal("performance tix_tcp should keep full-kmod plaintext ownership")
	}
	if mode := kernelDatapathRXModeForDesired(desired); mode != kernelDatapathRXModeWorker {
		t.Fatalf("performance tix_tcp full-kmod should attach RX worker, mode=%q", mode)
	}
}

func TestPerformanceKernelModuleTIXTCPSelectsRouteGSOByDefault(t *testing.T) {
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
			Transport: string(transport.ProtocolTIXTCP),
			Enabled:   true,
		}},
	}

	if !tixTCPPerformanceRouteGSOAsyncForDesired(desired) {
		t.Fatalf("performance tix_tcp kernel_module should select production route-GSO by default")
	}
	if kernelDatapathFullPlaintextEnabledForDesired(desired) {
		t.Fatalf("performance tix_tcp route-GSO should not claim full-kmod plaintext ownership")
	}
	if !kernelDatapathRouteGSOSuppressesLegacyFullPlaintextForDesired(desired) {
		t.Fatalf("performance tix_tcp route-GSO should suppress legacy full-kmod plaintext parameters")
	}
}

func TestPerformanceKernelModuleTIXTCPRouteGSOExplicitOptIn(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_ROUTE_GSO", "1")
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
			Transport: string(transport.ProtocolTIXTCP),
			Enabled:   true,
		}},
	}

	if !tixTCPPerformanceRouteGSOAsyncForDesired(desired) {
		t.Fatalf("explicit performance tix_tcp kernel_module should enable route-GSO")
	}
	if kernelDatapathFullPlaintextEnabledForDesired(desired) {
		t.Fatalf("explicit route-GSO should not claim full-kmod plaintext ownership")
	}
	if !kernelDatapathRouteGSOSuppressesLegacyFullPlaintextForDesired(desired) {
		t.Fatalf("explicit route-GSO should suppress legacy full-kmod plaintext parameters")
	}
}

func TestPerformanceKernelModuleTIXTCPRouteGSOExplicitDisable(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_ROUTE_GSO", "0")
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
			Transport: string(transport.ProtocolTIXTCP),
			Enabled:   true,
		}},
	}

	if tixTCPPerformanceRouteGSOAsyncForDesired(desired) {
		t.Fatalf("explicit disable should keep performance tix_tcp off route-GSO")
	}
	if kernelDatapathRouteGSOSuppressesLegacyFullPlaintextForDesired(desired) {
		t.Fatalf("explicit route-GSO disable should not suppress legacy full-kmod plaintext parameters")
	}
}

func TestTrustIXDatapathModuleParametersForDesiredKeepsLegacyFullPlaintextTIXTCP(t *testing.T) {
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
			Transport: "tix_tcp",
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
	if tixTCPPerformanceRouteGSOAsyncForDesired(desired) {
		t.Fatal("full plaintext tix_tcp should not use route-GSO performance fast path")
	}
	if !kernelDatapathFullPlaintextEnabledForDesired(desired) {
		t.Fatal("full plaintext tix_tcp should keep full plaintext datapath ownership")
	}
}

func TestTrustIXDatapathModuleParametersForDesiredFullPlaintextTIXTCPDefaultsHashQueues(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")
	desired := config.Desired{
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
			Transport: string(transport.ProtocolTIXTCP),
			Enabled:   true,
		}},
	}

	got := TrustIXDatapathModuleParametersForDesired("", desired)
	for _, want := range []string{
		"tx_plaintext_hash_tx_queue=1",
		"tx_plaintext_stream_coalesce=0",
		"tx_plaintext_stream_coalesce_max_frames=16",
	} {
		if !moduleParameterHasAssignment(got, want) {
			t.Fatalf("parameters = %q, missing tix_tcp full-plaintext default %q", got, want)
		}
	}
	if moduleParameterHasAssignment(got, "tx_plaintext_stream_coalesce=1") {
		t.Fatalf("parameters = %q, enabled low-yield stream coalesce by default", got)
	}
	if kernelDatapathTXPlaintextExperimentsAllowed() {
		t.Fatal("test should not require the TX plaintext experiments gate")
	}
}

func TestTrustIXDatapathModuleParametersForDesiredFullPlaintextTIXTCPKeepsDefaultsWithExperimentsGate(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_TX_PLAINTEXT_EXPERIMENTS", "1")
	desired := config.Desired{
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
			Transport: string(transport.ProtocolTIXTCP),
			Enabled:   true,
		}},
	}

	got := TrustIXDatapathModuleParametersForDesired("", desired)
	for _, want := range []string{
		"tx_plaintext_hash_tx_queue=1",
		"tx_plaintext_stream_coalesce=0",
		"tx_plaintext_stream_coalesce_max_frames=16",
	} {
		if !moduleParameterHasAssignment(got, want) {
			t.Fatalf("parameters = %q, missing tix_tcp default with experiments gate %q", got, want)
		}
	}
}

func TestTrustIXDatapathModuleParametersForDesiredFullPlaintextTIXTCPAllowsExplicitStreamCoalesceDisable(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")
	desired := config.Desired{
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
			Transport: string(transport.ProtocolTIXTCP),
			Enabled:   true,
		}},
	}

	got := TrustIXDatapathModuleParametersForDesired("tx_plaintext_stream_coalesce=0", desired)
	if !moduleParameterHasAssignment(got, "tx_plaintext_stream_coalesce=0") {
		t.Fatalf("parameters = %q, missing explicit stream coalesce disable", got)
	}
	if moduleParameterHasAssignment(got, "tx_plaintext_stream_coalesce=1") {
		t.Fatalf("parameters = %q, ignored explicit stream coalesce disable", got)
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
	if !moduleParameterHasAssignment(got, "tx_plaintext_stream_coalesce=0") {
		t.Fatalf("parameters = %q, UDP full plaintext should keep stream coalesce off by default", got)
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
			Transport: "tix_tcp",
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

func TestTrustIXDatapathModuleParametersForDesiredGenericUDPDirectDisableKeepsFullPlaintextTIXTCP(t *testing.T) {
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
			Transport: "tix_tcp",
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
	if tixTCPPerformanceRouteGSOAsyncForDesired(desired) {
		t.Fatal("generic UDP TC direct disable should not force tix_tcp route-GSO over full plaintext")
	}
	if !kernelDatapathFullPlaintextEnabledForDesired(desired) {
		t.Fatal("generic UDP TC direct disable should keep full plaintext ownership")
	}
}

func TestTrustIXDatapathModuleParametersForDesiredKeepsFullPlaintextWhenRouteGSOExplicitlyDisabled(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT", "1")
	t.Setenv("TRUSTIX_TIX_TCP_ROUTE_GSO", "0")
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
			Transport: "tix_tcp",
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
	if tixTCPPerformanceRouteGSOAsyncForDesired(desired) {
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
			Transport: "tix_tcp",
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
	if tixTCPPerformanceRouteGSOAsyncForDesired(desired) {
		t.Fatal("disabled kernel_transport must prevent route-GSO migration")
	}
	if !kernelDatapathFullPlaintextEnabledForDesired(desired) {
		t.Fatal("disabled kernel_transport should keep full plaintext fallback enabled")
	}
}

func TestTrustIXCryptoModuleParametersStripsPanicRiskRawParameters(t *testing.T) {
	got := TrustIXCryptoModuleParameters("prefer_software=1 kfunc_simd_fastpath=1 kfunc_simd_irq_fpu_fastpath=1 experimental_vaes_kfunc=1")
	want := "prefer_software=1 experimental_vaes_kfunc=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXCryptoModuleParametersForDesiredSecurePerformanceKeepsSIMDKfuncFastpathDisabledByDefault(t *testing.T) {
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

	got := TrustIXCryptoModuleParametersForDesired("kfunc_fastpath_stats=1", desired)
	if strings.Contains(got, "kfunc_simd_fastpath=1") {
		t.Fatalf("parameters = %q, unexpectedly enabled secure performance SIMD kfunc fast path", got)
	}
	for _, unexpected := range []string{"experimental_aesni_kfunc=1", "experimental_vaes_kfunc=1"} {
		if strings.Contains(got, unexpected) {
			t.Fatalf("parameters = %q, unexpectedly enabled %q", got, unexpected)
		}
	}
}

func TestTrustIXCryptoModuleParametersForDesiredTIXTCPSecureKernelPerformanceKeepsDirectKfuncDisabledByDefault(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:         config.TransportProfilePerformance,
			Datapath:        config.TransportDatapathKernelModule,
			Encryption:      securetransport.EncryptionSecure,
			CryptoPlacement: string(dataplane.CryptoPlacementKernel),
			Candidates:      []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolTIXTCP),
			Enabled:   true,
		}},
	}

	got := TrustIXCryptoModuleParametersForDesired("kfunc_fastpath_stats=1", desired)
	for _, unexpected := range []string{
		"kfunc_simd_fastpath=1",
		"experimental_aesni_kfunc=1",
		"experimental_vaes_kfunc=1",
	} {
		if strings.Contains(got, unexpected) {
			t.Fatalf("parameters = %q, unexpectedly enabled %q", got, unexpected)
		}
	}
}

func TestTrustIXCryptoModuleParametersForDesiredTIXTCPUserspaceCryptoKeepsDirectKfuncDisabled(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:         config.TransportProfilePerformance,
			Datapath:        config.TransportDatapathKernelModule,
			Encryption:      securetransport.EncryptionSecure,
			CryptoPlacement: string(dataplane.CryptoPlacementUserspace),
			Candidates:      []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: string(transport.ProtocolTIXTCP),
			Enabled:   true,
		}},
	}

	got := TrustIXCryptoModuleParametersForDesired("", desired)
	for _, unexpected := range []string{
		"kfunc_simd_fastpath=1",
		"experimental_aesni_kfunc=1",
		"experimental_vaes_kfunc=1",
	} {
		if strings.Contains(got, unexpected) {
			t.Fatalf("parameters = %q, unexpectedly kept %q", got, unexpected)
		}
	}
}

func TestTrustIXCryptoModuleParametersForDesiredAllowsExplicitSIMDKfuncFastpath(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_CRYPTO_ALLOW_SIMD_KFUNC_FASTPATH", "1")
	desired := config.Desired{}

	got := TrustIXCryptoModuleParametersForDesired("kfunc_simd_irq_fpu_fastpath=1", desired)
	for _, want := range []string{"kfunc_simd_fastpath=1", "experimental_aesni_kfunc=1", "experimental_vaes_kfunc=1"} {
		if !strings.Contains(got, want) {
			t.Fatalf("parameters = %q, missing %q", got, want)
		}
	}
	if strings.Contains(got, "kfunc_simd_irq_fpu_fastpath=1") {
		t.Fatalf("parameters = %q, ordinary SIMD opt-in must not enable IRQ/FPU kfunc fast path", got)
	}
}

func TestTrustIXCryptoModuleParametersForDesiredAllowsExplicitKfuncFastpathStats(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_CRYPTO_ALLOW_SIMD_KFUNC_FASTPATH", "1")
	t.Setenv("TRUSTIX_KERNEL_CRYPTO_KFUNC_FASTPATH_STATS", "1")
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

	got := TrustIXCryptoModuleParametersForDesired("kfunc_fastpath_stats=0", desired)
	if !strings.Contains(got, "kfunc_fastpath_stats=1") {
		t.Fatalf("parameters = %q, missing explicit kfunc fastpath stats", got)
	}
}

func TestTrustIXCryptoModuleParametersForDesiredAllowsExplicitSIMDIRQFPUKfuncFastpath(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_CRYPTO_ALLOW_SIMD_IRQ_FPU_KFUNC_FASTPATH", "1")
	desired := config.Desired{}

	got := TrustIXCryptoModuleParametersForDesired("", desired)
	if !strings.Contains(got, "kfunc_simd_irq_fpu_fastpath=1") {
		t.Fatalf("parameters = %q, missing explicit IRQ/FPU kfunc fast path", got)
	}
	if strings.Contains(got, "kfunc_simd_fastpath=1") {
		t.Fatalf("parameters = %q, IRQ/FPU opt-in alone must not enable ordinary SIMD kfunc fast path", got)
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
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_ALLOW_TIX_TCP",
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
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC", "1")
	t.Setenv("TRUSTIX_TIX_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_XMIT", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_ROUTE_TCP_XMIT_STEAL", "1")
	t.Setenv("TRUSTIX_TIX_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_XMIT_STEAL", "1")

	got := TrustIXDatapathHelpersModuleParameters("tixt_tx_plain_skip_sequence=1")
	want := "tixt_tx_plain_skip_sequence=1 route_tcp_xmit_worker=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathHelpersModuleParametersAllowsRouteGSOSyncStream(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_ROUTE_GSO_SYNC_STREAM", "1")
	t.Setenv("TRUSTIX_TIX_TCP_ROUTE_GSO_SYNC_STREAM_MAX_FRAMES", "12")

	got := TrustIXDatapathHelpersModuleParameters("tixt_tx_plain_skip_sequence=1")
	want := "tixt_tx_plain_skip_sequence=1 route_tcp_gso=1 route_tcp_gso_sync_stream=1 route_tcp_gso_sync_stream_max_frames=12 tixt_rx_stream_parse=1 tixt_rx_stream_xmit_extra=1 tixt_rx_stream_gso_xmit=1 tixt_rx_stream_max_frames=12"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathHelpersModuleParametersForDesiredEnablesSafeTIXTCPTCXDPPerformance(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_ROUTE_GSO", "1")
	desired := config.Desired{
		Endpoints: []config.EndpointConfig{{
			Name:      "tix-tcp-a",
			Transport: "tix_tcp",
			Enabled:   true,
		}},
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfileStable,
			Datapath:   config.TransportDatapathAuto,
			Encryption: "secure",
			Profiles: []config.TransportProfileConfig{{
				Transport:  "tix_tcp",
				Profile:    config.TransportProfilePerformance,
				Datapath:   config.TransportDatapathTCXDP,
				Encryption: "plaintext",
			}},
		},
	}

	got := TrustIXDatapathHelpersModuleParametersForDesired("", desired)
	for _, want := range []string{
		"enable_features=836",
		"tixt_tx_plain_skip_sequence=1",
		"tixt_tx_plain_ack_only=1",
		"route_tcp_gso=1",
		"route_tcp_gso_async=1",
		"route_tcp_gso_async_prefer=1",
		"route_tcp_gso_async_dev_xmit=1",
		"route_tcp_gso_async_force_inner_checksum=0",
		"route_tcp_gso_async_force_software_outer_csum=0",
		"route_tcp_gso_async_stream=1",
		"route_tcp_gso_async_stream_direct_build=1",
		"route_tcp_gso_async_stream_software_segment=0",
		"route_tcp_gso_async_stream_outer_gso=1",
		"route_tcp_gso_async_stream_cross_item_batch=1",
		"route_tcp_gso_async_flow_shard_queue=1",
		"route_tcp_gso_async_hash_tx_queue=0",
		"route_tcp_gso_async_txq_stopped_backoff_retries=1",
		"route_tcp_gso_async_txq_stopped_backoff_sleep_usecs=50",
		"route_tcp_gso_async_queue_shards=8",
		"route_tcp_gso_async_worker_item_budget=64",
		"route_tcp_gso_async_worker_segment_budget=2048",
		"route_tcp_gso_async_stream_max_frames=128",
		"route_tcp_gso_async_stream_cross_item_max_frames=128",
		"route_tcp_gso_async_stream_cross_item_dynamic_cap=0",
		"route_tcp_gso_async_worker_emit_budget=0",
		"route_tcp_gso_async_worker_dequeue_batch=32",
		"route_tcp_gso_async_worker_min_queue_depth=0",
		"route_tcp_gso_async_worker_schedule_delay_usecs=0",
		"route_tcp_xmit_worker=1",
		"route_tcp_xmit_worker_budget=1024",
		"route_tcp_xmit_worker_queue_limit=32768",
		"tixt_rx_stream_parse=1",
		"tixt_rx_stream_xmit_extra=1",
		"tixt_rx_stream_gso_xmit=1",
		"tixt_rx_stream_max_frames=128",
		"tixt_rx_stream_coalesce_gso=1",
		"tixt_rx_stream_coalesce_mark_gso=1",
		"tixt_rx_coalesce_segment_gso=0",
		"tixt_rx_backlog_worker_budget=2048",
		"tixt_rx_backlog_worker_queue_limit=65536",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("parameters = %q, missing %q", got, want)
		}
	}
	for _, unexpected := range []string{
		"route_tcp_gso_sync_stream=1",
		"route_tcp_gso_sync_stream_outer_gso=1",
		"route_tcp_gso_async_stream_outer_gso_hard_enable=1",
	} {
		if strings.Contains(got, unexpected) {
			t.Fatalf("parameters = %q, unexpectedly enabled legacy path %q", got, unexpected)
		}
	}
}

func TestTrustIXDatapathHelpersModuleParametersForDesiredKeepsStableTIXTCPConservative(t *testing.T) {
	desired := config.Desired{
		Endpoints: []config.EndpointConfig{{
			Name:      "tix-tcp-a",
			Transport: "tix_tcp",
			Enabled:   true,
		}},
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfileStable,
			Datapath:   config.TransportDatapathKernelModule,
			Encryption: "plaintext",
			Candidates: []core.EndpointID{"tix-tcp-a"},
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
		"TRUSTIX_TIX_TCP_TC_RX_SINGLE_COALESCE_GSO",
		"TRUSTIX_TIXT_RX_SINGLE_COALESCE_SKIP_TCP_CSUM",
		"TRUSTIX_TIX_TCP_TC_RX_SINGLE_COALESCE_SKIP_TCP_CSUM",
		"TRUSTIX_TIXT_RX_SINGLE_COALESCE_NETIF_RX",
		"TRUSTIX_TIX_TCP_TC_RX_SINGLE_COALESCE_NETIF_RX",
		"TRUSTIX_TIXT_RX_SINGLE_COALESCE_PAGE_ONLY",
		"TRUSTIX_TIX_TCP_TC_RX_SINGLE_COALESCE_PAGE_ONLY",
		"TRUSTIX_TIXT_RX_SINGLE_COALESCE_LINEAR_BUILD",
		"TRUSTIX_TIX_TCP_TC_RX_SINGLE_COALESCE_LINEAR_BUILD",
		"TRUSTIX_TIXT_RX_SINGLE_COALESCE_HYBRID_HEAD",
		"TRUSTIX_TIX_TCP_TC_RX_SINGLE_COALESCE_HYBRID_HEAD",
		"TRUSTIX_TIXT_RX_STREAM_ORDERED_LIST",
		"TRUSTIX_TIX_TCP_TC_RX_STREAM_ORDERED_LIST",
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
		"route_tcp_gso_async_worker_emit_budget=0",
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
		"tixt_rx_backlog_worker_budget=4096",
		"tixt_rx_stream_ordered_list=1",
		"tixt_rx_single_coalesce_gso=1",
		"tixt_rx_single_coalesce_max_frames=64",
		"tixt_rx_single_coalesce_netif_rx=1",
		"tixt_rx_coalesce_segment_gso=1",
	}, " ")

	got := TrustIXDatapathHelpersModuleParameters(raw)
	want := "tixt_tx_plain_skip_sequence=1 route_tcp_gso=1 route_tcp_gso_async=1 route_tcp_gso_async_dev_xmit=1 route_tcp_gso_async_limit=4096 route_tcp_gso_async_worker_item_budget=64 route_tcp_gso_async_worker_emit_budget=0 route_tcp_gso_async_stream=1 route_tcp_gso_async_stream_direct_build=1 route_tcp_gso_async_stream_direct_build_fast_copy=1 route_tcp_gso_async_unbound_worker=1 route_tcp_gso_async_sharded_queue=1 route_tcp_gso_async_queue_shards=8 route_tcp_gso_async_stream_cross_item_debug=1 route_tcp_gso_async_stream_outer_gso=1 route_tcp_gso_async_xmit_busy_retries=4 route_tcp_gso_async_xmit_busy_sleep_usecs=50 route_tcp_xmit_worker=1 route_tcp_xmit_worker_steal=1 route_tcp_xmit_worker_budget=128 tixt_rx_stream_parse=1 tixt_rx_stream_xmit_extra=1 tixt_rx_stream_gso_xmit=1 tixt_rx_stream_max_frames=16 tixt_rx_backlog_worker_budget=4096 tixt_rx_single_coalesce_gso=1 tixt_rx_single_coalesce_max_frames=64 tixt_rx_single_coalesce_netif_rx=1 tixt_rx_coalesce_segment_gso=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathHelpersPerformanceTIXTCPDoesNotEnableLegacyRXStreamParser(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:    config.TransportProfilePerformance,
			Datapath:   config.TransportDatapathTCXDP,
			Encryption: "plaintext",
			Candidates: []core.EndpointID{"exp-a"},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-a",
			Transport: "tix_tcp",
			Enabled:   true,
		}},
	}

	got := TrustIXDatapathHelpersModuleParametersForDesired("", desired)
	for _, unexpected := range []string{
		"route_tcp_gso=1",
		"route_tcp_gso_async=1",
		"route_tcp_xmit_worker=1",
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

func TestTrustIXDatapathHelpersSecureTIXTCPBuildsValidInnerChecksum(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:         config.TransportProfilePerformance,
			Datapath:        config.TransportDatapathKernelModule,
			Encryption:      securetransport.EncryptionSecure,
			CryptoPlacement: string(dataplane.CryptoPlacementKernel),
			Candidates:      []core.EndpointID{"exp-sec"},
			KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-sec",
			Transport: string(transport.ProtocolTIXTCP),
			Enabled:   true,
		}},
	}

	if !tixTCPSecureRouteGSOAsyncForDesired(desired) {
		t.Fatal("secure tix_tcp kernel crypto policy should select route-GSO")
	}
	got := TrustIXDatapathHelpersModuleParametersForDesired("", desired)
	for _, want := range []string{
		"route_tcp_gso=1",
		"route_tcp_gso_async=1",
		"route_tcp_gso_async_stream_direct_build=1",
		"route_tcp_gso_async_stream_outer_gso=1",
		"route_tcp_gso_async_stream_direct_build_inner_csum=1",
		"route_tcp_gso_async_secure_seal_batch=1",
	} {
		if !moduleParameterHasAssignment(got, want) {
			t.Fatalf("parameters = %q, missing %q", got, want)
		}
	}
}

func TestTrustIXDatapathHelpersTCXDPSecureTIXTCPDoesNotEnableRouteGSO(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:         config.TransportProfilePerformance,
			Datapath:        config.TransportDatapathTCXDP,
			Encryption:      securetransport.EncryptionSecure,
			CryptoPlacement: string(dataplane.CryptoPlacementKernel),
			Candidates:      []core.EndpointID{"exp-sec"},
			KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "exp-sec",
			Transport: string(transport.ProtocolTIXTCP),
			Enabled:   true,
		}},
	}

	if tixTCPSecureRouteGSOAsyncForDesired(desired) {
		t.Fatal("TC-XDP secure tix_tcp kernel crypto policy should not select route-GSO")
	}
	got := TrustIXDatapathHelpersModuleParametersForDesired("", desired)
	for _, unexpected := range []string{
		"route_tcp_gso=1",
		"route_tcp_gso_async=1",
		"route_tcp_gso_async_stream_direct_build=1",
		"route_tcp_gso_async_stream_outer_gso=1",
		"route_tcp_gso_async_stream_direct_build_inner_csum=1",
		"route_tcp_gso_async_secure_seal_batch=1",
	} {
		if moduleParameterHasAssignment(got, unexpected) {
			t.Fatalf("parameters = %q, unexpectedly enabled %q", got, unexpected)
		}
	}
}

func TestTrustIXDatapathHelpersSecureKernelUDPRouteGSOAvoidsPlaintextShortcuts(t *testing.T) {
	desired := config.Desired{
		TransportPolicy: config.TransportPolicyConfig{
			Profile:         config.TransportProfilePerformance,
			Datapath:        config.TransportDatapathTCXDP,
			Encryption:      securetransport.EncryptionSecure,
			CryptoPlacement: string(dataplane.CryptoPlacementKernel),
			Candidates:      []core.EndpointID{"udp-sec"},
			KernelTransport: config.KernelTransportPolicyConfig{Mode: string(dataplane.KernelTransportModeRequireKernel)},
		},
		Endpoints: []config.EndpointConfig{{
			Name:      "udp-sec",
			Transport: string(transport.ProtocolUDP),
			Enabled:   true,
		}},
	}

	if !kernelUDPSecureRouteGSOForDesired(desired) {
		t.Fatal("secure kernel_udp policy should select route-GSO")
	}
	got := TrustIXDatapathHelpersModuleParametersForDesired("", desired)
	for _, want := range []string{
		"route_tcp_gso=1",
		"route_tcp_gso_async=1",
		"route_tcp_gso_async_stream_direct_build=1",
		"route_tcp_gso_async_stream_outer_gso=1",
		"route_tcp_xmit_worker=1",
		"route_tcp_gso_async_secure_seal_batch=1",
	} {
		if !moduleParameterHasAssignment(got, want) {
			t.Fatalf("parameters = %q, missing %q", got, want)
		}
	}
	for _, unexpected := range []string{
		"tixt_tx_plain_skip_sequence=1",
		"tixt_tx_plain_ack_only=1",
	} {
		if moduleParameterHasAssignment(got, unexpected) {
			t.Fatalf("parameters = %q, unexpectedly enabled plaintext shortcut %q", got, unexpected)
		}
	}
}
