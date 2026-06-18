package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProductionMatrixDefaultsAvoidUnsafeExperimentalTCPSecureFastPath(t *testing.T) {
	for _, name := range []string{"linux-production-transport-matrix.sh"} {
		t.Run(name, func(t *testing.T) {
			payload, err := os.ReadFile(filepath.Join(".", name))
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			text := string(payload)
			if strings.Contains(text, "experimental_tcp:secure:stable:kernel_module:userspace") {
				t.Fatalf("%s production defaults still select unsafe secure userspace-crypto experimental_tcp kernel fast path", name)
			}
			for _, wantCase := range []string{
				"udp:plaintext:performance:kernel_module:userspace",
				"kernel_udp:secure:performance:tc_xdp:kernel",
				"experimental_tcp:secure:stable:userspace:userspace",
			} {
				if !strings.Contains(text, wantCase) {
					t.Fatalf("%s production defaults missing %q", name, wantCase)
				}
			}
			for _, unwanted := range []string{
				"kernel_udp:secure:stable:tc_xdp:userspace",
				"experimental_tcp:plaintext:performance:kernel_module:userspace",
			} {
				if strings.Contains(text, unwanted) {
					t.Fatalf("%s production defaults still include slow/unselected combo %q", name, unwanted)
				}
			}
		})
	}
}

func TestProductionTransportMatrixDefaults(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join(".", "linux-production-transport-matrix.sh"))
	if err != nil {
		t.Fatalf("read linux-production-transport-matrix.sh: %v", err)
	}
	text := string(payload)
	for _, want := range []string{
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_PERF_FAST:-1",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_CASE_TIMEOUT",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_FULL_DATAPATH_IOCTL_SELFTEST:-0",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_FULL_DATAPATH_VERIFY_SAFE_DEFAULTS:-0",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_SINGLE_HOST_FULL_DATAPATH:-0",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_SINGLE_HOST_ROUTE_GSO:-0",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_AF_XDP_TX_BACKPRESSURE_WAIT:-50ms",
		"TRUSTIX_E2E_AF_XDP_TX_BACKPRESSURE_WAIT",
		"rx_worker_xmit=1",
		"rx_worker_single_coalesce=1",
		"rx_worker_single_coalesce_max_frames=32",
		"tx_plaintext_skip_inner_tcp_checksum=0",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("linux-production-transport-matrix.sh production defaults missing %q", want)
		}
	}
	for _, unwanted := range []string{
		"rx_worker_single_coalesce=0",
	} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("linux-production-transport-matrix.sh production defaults still include %q", unwanted)
		}
	}
}

func TestE2ESmokeDefaultsAvoidUnsafeDirectKfuncCrypto(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join(".", "linux-e2e-smoke.sh"))
	if err != nil {
		t.Fatalf("read linux-e2e-smoke.sh: %v", err)
	}
	text := string(payload)
	for _, want := range []string{
		"TRUSTIX_E2E_AF_XDP_TX_BACKPRESSURE_WAIT:-50ms",
		"TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_KFUNC_SEAL:-0",
		"TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_KFUNC_OPEN:-0",
		"TRUSTIX_E2E_AF_XDP_TX_BACKPRESSURE_WAIT must be a Go duration or 0",
		"route_tcp_gso_async_worker_emit_budget=0",
		"route_tcp_gso_async_worker_dequeue_batch=4",
		"route_tcp_gso_async_hash_tx_queue=1",
		"route_tcp_gso_async_worker_min_queue_depth=1",
		"route_tcp_gso_async_worker_schedule_delay_usecs=0",
		"experimental_tcp_route_gso_async_worker_item_budget=64",
		"experimental_tcp_route_gso_async_worker_segment_budget=2048",
		"route_tcp_gso_async_worker_item_budget=${experimental_tcp_route_gso_async_worker_item_budget}",
		"route_tcp_gso_async_worker_segment_budget=${experimental_tcp_route_gso_async_worker_segment_budget}",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("linux-e2e-smoke.sh default missing %q", want)
		}
	}
}

func TestProductionSoakWrapsProductionMatrix(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join(".", "linux-production-soak.sh"))
	if err != nil {
		t.Fatalf("read linux-production-soak.sh: %v", err)
	}
	text := string(payload)
	for _, want := range []string{
		"TRUSTIX_PRODUCTION_SOAK_DURATION_SECONDS:-3600",
		"TRUSTIX_PRODUCTION_SOAK_IPERF3_SECONDS:-120",
		"TRUSTIX_PRODUCTION_SOAK_PERF_FAST:-1",
		"TRUSTIX_PRODUCTION_SOAK_CASE_TIMEOUT:-15m",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_CASES",
		"linux-production-transport-matrix.sh",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("linux-production-soak.sh missing %q", want)
		}
	}
}

func TestCrossHostProductionGateRequiresFastPathArtifacts(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join(".", "linux-cross-host-production-gate.sh"))
	if err != nil {
		t.Fatalf("read linux-cross-host-production-gate.sh: %v", err)
	}
	text := string(payload)
	for _, want := range []string{
		"gate_min_gbps=\"${TRUSTIX_CROSS_HOST_GATE_MIN_GBPS:-}\"",
		"TRUSTIX_CROSS_HOST_FULL_KMOD_MIN_GBPS:-${gate_min_gbps:-3}",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_GBPS:-${gate_min_gbps:-1.5}",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_MIN_GBPS:-${gate_min_gbps:-4}",
		"TRUSTIX_CROSS_HOST_GATE_MIN_SECONDS:-900",
		"TRUSTIX_CROSS_HOST_GATE_REQUIRE_BINARY_IDENTITY:-1",
		"TRUSTIX_CROSS_HOST_FULL_KMOD_MIN_SESSIONS:-8",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_SESSIONS:-8",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_MIN_SESSIONS:-8",
		"TRUSTIX_CROSS_HOST_DD_FULL_KMOD",
		"TRUSTIX_CROSS_HOST_OWDEB_FULL_KMOD",
		"TRUSTIX_CROSS_HOST_DD_SECURE_KUDP",
		"TRUSTIX_CROSS_HOST_OWDEB_SECURE_KUDP",
		"TRUSTIX_CROSS_HOST_DD_ROUTE_GSO",
		"validate_number TRUSTIX_CROSS_HOST_FULL_KMOD_MIN_GBPS \"$full_kmod_min_gbps\"",
		"validate_number TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_GBPS \"$secure_kudp_min_gbps\"",
		"validate_number TRUSTIX_CROSS_HOST_ROUTE_GSO_MIN_GBPS \"$route_gso_min_gbps\"",
		"--require-binary-identity",
		"--require-transport-policy-stat encryption=secure",
		"--require-transport-policy-stat crypto_placement=kernel",
		"--require-transport-policy-stat datapath=tc_xdp",
		"--require-transport-policy-min session_pool_size=\"${full_kmod_min_sessions}\"",
		"--require-transport-policy-min session_pool_size=\"${secure_kudp_min_sessions}\"",
		"--require-transport-policy-min session_pool_size=\"${route_gso_min_sessions}\"",
		"--require-transport-policy-stat session_pool_strategy=flow",
		"--require-transport-policy-stat session_pool_warmup=true",
		"--require-status-min data_path.active_sessions=\"${route_gso_min_sessions}\"",
		"--require-status-max data_path.counters.session_dial_errors=0",
		"--require-status-max data_path.counters.session_heartbeat_timeouts=0",
		"--require-datapath-stat kernel_udp.provider_stats.kernel_datapath_full_plaintext_provider=1",
		"--require-datapath-stat kernel_udp.kernel_crypto=true",
		"--require-datapath-stat kernel_udp.requested_crypto=kernel",
		"--require-datapath-stat kernel_udp.effective_crypto=kernel",
		"--require-datapath-stat kernel_udp.provider_stats.kernel_crypto_flow_map_ready=1",
		"--require-datapath-min kernel_udp.provider_stats.kernel_crypto_flow_map_entries=\"${secure_kudp_min_sessions}\"",
		"--require-datapath-min kernel_udp.provider_stats.kernel_crypto_flow_map_updates=\"${secure_kudp_min_sessions}\"",
		"--require-datapath-stat kernel_udp.provider_stats.kernel_crypto_direct_slot_provider_ready=1",
		"--require-datapath-stat kernel_udp.provider_stats.kernel_crypto_direct_kfunc_fastpath_ready=1",
		"--require-datapath-stat kernel_udp.provider_stats.kernel_crypto_tc_direct_ready=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_tx_direct_only_enabled=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_tx_secure_direct_attached=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_attached=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_tx_secure_direct_kfunc_seal_enabled=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_kfunc_open_enabled=1",
		"--require-datapath-any-min kernel_udp.provider_stats.tc_kernel_udp_tx_secure_direct_packets=1",
		"--require-datapath-any-min kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_packets=1",
		"--require-datapath-max kernel_udp.provider_stats.kernel_crypto_frame_seal_errors=0",
		"--require-datapath-max kernel_udp.provider_stats.kernel_crypto_frame_open_errors=0",
		"--require-datapath-max kernel_udp.provider_stats.tc_kernel_udp_tx_secure_direct_encrypt_errors=0",
		"--require-datapath-max kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_decrypt_errors=0",
		"--require-module-param-min trustix_crypto.kfunc_simd_fastpath=1",
		"--require-module-param-min trustix_crypto.kfunc_simd_irq_fpu_fastpath=1",
		"--require-module-param-any-min trustix_crypto.direct_kfunc_seal_calls=1",
		"--require-module-param-any-min trustix_crypto.direct_kfunc_open_calls=1",
		"--require-module-param-max trustix_crypto.direct_kfunc_errors=0",
		"--require-module-param-min trustix_datapath_helpers.route_tcp_gso_async_secure_seal_batch=1",
		"--require-datapath-min kernel_rx_stage.rx_worker_injected=1",
		"--require-datapath-min counters.session_dials=\"${full_kmod_min_sessions}\"",
		"--require-datapath-max counters.session_dial_errors=0",
		"--require-module-param-min trustix_datapath.session_records=\"${full_kmod_min_sessions}\"",
		"--require-module-param-min trustix_datapath.session_wire_records=\"${full_kmod_min_sessions}\"",
		"--require-module-param-min trustix_datapath.rx_worker_single_coalesce_max_frames=32",
		"--require-module-param-any-min trustix_datapath.tx_plaintext_outer_gso_segments=1",
		"--require-module-param-any-min trustix_datapath.tx_plaintext_direct_xmit_dst_mac_cache_hits=1",
		"--require-module-param-any-min trustix_datapath.rx_worker_gso_xmit_segments=1",
		"--require-module-param-max trustix_datapath.rx_worker_alloc_errors=0",
		"--require-module-param-max trustix_datapath.rx_worker_deliver_errors=0",
		"--require-module-param-max trustix_datapath.rx_worker_gso_xmit_errors=0",
		"--require-module-param-max trustix_datapath.rx_worker_xmit_ret_errors=0",
		"--require-module-param-max trustix_datapath.rx_worker_xmit_peer_forward_errors=0",
		"--require-module-param-max trustix_datapath.tx_plaintext_no_sessions=0",
		"--require-module-param-max trustix_datapath.tx_plaintext_no_wires=0",
		"--require-module-param-max trustix_datapath.tx_plaintext_stale_wires=0",
		"--require-module-param-max trustix_datapath.tx_plaintext_xmit_errors=0",
		"--require-module-param-max trustix_datapath.tx_plaintext_queue_drops=0",
		"--require-datapath-stat kernel_udp.provider_stats.tc_experimental_tcp_tx_direct_route_tcp_gso_async_kfunc=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_experimental_tcp_tx_direct_route_tcp_gso_async_kfunc_requested=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_tx_direct_experimental_tcp_only=1",
		"--require-module-param-min trustix_datapath_helpers.route_tcp_gso_async_hash_tx_queue=1",
		"--require-module-param-any-min trustix_datapath_helpers.route_tcp_gso_async_hash_tx_queue_sets=1",
		"--require-module-param-any-min trustix_datapath_helpers.route_tcp_gso_async_stream_outer_gso_frames=1",
		"--require-module-param-any-min trustix_datapath_helpers.route_tcp_gso_async_xmit_packets=1",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_queue_full=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_xmit_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_outer_gso_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_outer_gso_blocked=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_outer_gso_verify_errors=0",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("linux-cross-host-production-gate.sh missing %q", want)
		}
	}
	for _, unwanted := range []string{
		"TRUSTIX_CROSS_HOST_DD_FULL_KMOD_EXPERIMENTAL_TCP",
		"dd-fullkmod-experimental-tcp",
	} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("linux-cross-host-production-gate.sh still promotes diagnostic full-kmod experimental_tcp case %q", unwanted)
		}
	}
}

func TestCrossHostSoakRunnerCoversKernelFastPathsAndCleanup(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join(".", "linux-cross-host-soak-runner.sh"))
	if err != nil {
		t.Fatalf("read linux-cross-host-soak-runner.sh: %v", err)
	}
	text := string(payload)
	for _, want := range []string{
		"TRUSTIX_CROSS_HOST_CASE:-dd-fullkmod",
		"data_a_port=\"${TRUSTIX_CROSS_HOST_DATA_A_PORT:-}\"",
		"data_b_port=\"${TRUSTIX_CROSS_HOST_DATA_B_PORT:-}\"",
		"default_data_port",
		"node_value \"$node\" 13000 13001",
		"TRUSTIX_CROSS_HOST_IPERF_SECONDS:-900",
		"health_port=\"${TRUSTIX_CROSS_HOST_HEALTH_PORT:-}\"",
		"TRUSTIX_CROSS_HOST_IPERF_MODE:-forward",
		"TRUSTIX_CROSS_HOST_IPERF_DIRECTIONS:-both",
		"daemon_ready_sleep=\"${TRUSTIX_CROSS_HOST_READY_SLEEP:-1}\"",
		"iperf_parallel=\"${TRUSTIX_CROSS_HOST_IPERF_PARALLEL:-8}\"",
		"transport_snapshot_delay=\"${TRUSTIX_CROSS_HOST_TRANSPORT_SNAPSHOT_DELAY:-5}\"",
		"session_pool_size=\"${TRUSTIX_CROSS_HOST_SESSION_POOL_SIZE:-$iperf_parallel}\"",
		"session_pool:",
		"size: ${session_pool_size}",
		"strategy: ${session_pool_strategy}",
		"warmup: ${session_pool_warmup}",
		"heartbeat:",
		"mode: ${session_pool_heartbeat_mode}",
		"TRUSTIX_CROSS_HOST_IPERF_DIRECTIONS must be both, a2b, or b2a",
		"TRUSTIX_CROSS_HOST_HEALTH_PORT must differ from TRUSTIX_CROSS_HOST_IPERF_PORT",
		"case \"$iperf_mode\" in bidir|forward|reverse)",
		"TRUSTIX_CROSS_HOST_SESSION_POOL_SIZE must be >= 1",
		"TRUSTIX_CROSS_HOST_TRANSPORT_SNAPSHOT_DELAY must be >= 0",
		"TRUSTIX_CROSS_HOST_SESSION_POOL_STRATEGY must be flow, five_tuple, 5tuple, packet, or round_robin",
		"iperf_artifact_suffix",
		"dd-fullkmod|full-kmod|udp-plaintext-full-kmod|udp_plaintext_full_kmod",
		"dd-secure-kudp|secure-kudp|kernel-udp-secure-kernel|kernel_udp_secure_kernel|udp-secure-kernel|udp_secure_kernel",
		"dd-routegso|route-gso|experimental-tcp-route-gso|experimental_tcp_route_gso",
		"ow-tc-direct|tc-direct|experimental-tcp-tc-direct|experimental_tcp_tc_direct",
		"case_fast_path",
		"case_encryption",
		"case_crypto_placement",
		"case_transport_datapath",
		"secure_kudp|tc_direct) printf 'tc_xdp\\n'",
		"tc_direct) printf 'tc_xdp\\n'",
		"capability_profile: full_plaintext",
		"capability_profile: performance",
		"capability_profile: disabled",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_CRYPTO_PATH:-embedded",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_CRYPTO_PATH_A:-$secure_kudp_crypto_path",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_CRYPTO_PATH_B:-$secure_kudp_crypto_path",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_HELPERS_PATH",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_HELPERS_PATH_A:-$secure_kudp_helpers_path",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_HELPERS_PATH_B:-$secure_kudp_helpers_path",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_CRYPTO_PARAMETERS",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_HELPER_PARAMETERS",
		"infer_helpers_path_from_module_path",
		"embedded://trustix_crypto.ko|embedded://trustix_datapath.ko",
		"route authorize -out \"$workdir/certs\" -domain \"$domain_id\" -ix \"$ix_a\" -prefix \"$lan_a_cidr\"",
		"route authorize -out \"$workdir/certs\" -domain \"$domain_id\" -ix \"$ix_b\" -prefix \"$lan_b_cidr\"",
		"copy_to_node a \"$workdir/certs/.\"",
		"copy_to_node b \"$workdir/certs/.\"",
		"TRUSTIX_CROSS_HOST_FULL_KMOD_DATAPATH_PARAMETERS",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_HELPER_PARAMETERS",
		"TRUSTIX_CROSS_HOST_FULL_KMOD_DATAPATH_PATH:-embedded",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_HELPERS_PATH:-embedded",
		"TRUSTIX_CROSS_HOST_ENDPOINT_TRANSPORT",
		"case_endpoint_transport",
		"TRUSTIX_CROSS_HOST_ENDPOINT_TRANSPORT must be empty, udp, or experimental_tcp",
		"ssh_no_stdin()",
		"ssh -n \"${ssh_opts[@]}\" \"$dest\" \"$@\"",
		"ssh_no_stdin \"$dest\" \"mkdir -p $(remote_quote \"$dest_path\")\"",
		"ssh_no_stdin \"$dest\" \"test -d $(remote_quote \"$src\")\"",
		"rx_worker_experimental_tcp=1",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_ALLOW_EXPERIMENTAL_TCP=%s",
		"TRUSTIX_EXPERIMENTAL_TCP_ALLOW_MIXED_TCP_FAST_PATH=1",
		"full-kmod with experimental_tcp endpoint is diagnostic only",
		"TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER_EXPERIMENTS=1",
		"TRUSTIX_KERNEL_DATAPATH_ALLOW_UNSAFE_RX_WORKER_EXPERIMENTS=1",
		"TRUSTIX_CROSS_HOST_OPENWRT_RX_SINGLE_COALESCE",
		"TRUSTIX_KERNEL_DATAPATH_OPENWRT_RX_SINGLE_COALESCE=%s",
		"daemon_env_exports",
		"env ${env_exports} $(remote_quote \"$trustixd\") -config",
		"yaml_single_quote",
		"encryption: ${encryption}",
		"crypto_placement: ${crypto_placement}",
		"TRUSTIX_KERNEL_UDP_TC_SECURE_DIRECT_ONLY=1",
		"TRUSTIX_KERNEL_CRYPTO_ALLOW_SIMD_KFUNC_FASTPATH=1",
		"TRUSTIX_KERNEL_CRYPTO_ALLOW_SIMD_IRQ_FPU_KFUNC_FASTPATH=1",
		"TRUSTIX_KERNEL_CRYPTO_KFUNC_FASTPATH_STATS=1",
		"TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_KFUNC_SEAL=1",
		"TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_KFUNC_OPEN=1",
		"TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_TRUST_INNER_CHECKSUMS=1",
		"TRUSTIX_KERNEL_UDP_TC_TX_SECURE_ROUTE_GSO_KFUNC=1",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC=1",
		"TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO=0",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC=0",
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY=1",
		"unload_on_exit: true",
		"-cleanup-dataplane",
		"rmmod trustix_datapath",
		"rmmod trustix_datapath_helpers",
		"printf 'pass\\n' >\"$workdir/${case_name}.result\"",
		"collect_binary_identity a",
		"version_output=\\$(",
		"collect_kernel_logs a",
		"collect_all",
		"collect_module_parameters a",
		"${dir}/module-parameters.txt",
		"stop_daemon a",
		"collect_one status status",
		"collect_one datapath datapath",
		"collect_one transports transports",
		"collect_transport_snapshot",
		"run_iperf_client_with_snapshot",
		"run_connectivity_checks",
		"run_tcp_health_checks",
		"run_tcp_health_direction",
		"collect_one bpf bpf maps",
		"${dir}/binary-identity.json",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("linux-cross-host-soak-runner.sh missing %q", want)
		}
	}
	for _, unwanted := range []string{
		"xargs -r",
		"${prefix}-status.json",
		"${prefix}-datapath.json",
		"${prefix}-binary-identity.json",
		"find \"$workdir/a\" \"$workdir/b\" -type f -name 'iperf3-*.json' -exec cp",
		"trustixd\") -version 2>/dev/null | awk -F= '/^version=/{print $2; exit}'",
	} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("linux-cross-host-soak-runner.sh contains non-portable %q", unwanted)
		}
	}
}
