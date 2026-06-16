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
				"experimental_tcp:plaintext:performance:kernel_module:userspace",
				"experimental_tcp:secure:stable:userspace:userspace",
			} {
				if !strings.Contains(text, wantCase) {
					t.Fatalf("%s production defaults missing %q", name, wantCase)
				}
			}
			for _, unwanted := range []string{
				"kernel_udp:secure:stable:tc_xdp:userspace",
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
		"rx_worker_single_coalesce=0",
		"tx_plaintext_skip_inner_tcp_checksum=0",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("linux-production-transport-matrix.sh production defaults missing %q", want)
		}
	}
	for _, unwanted := range []string{
		"rx_worker_single_coalesce=1",
		"rx_worker_single_coalesce_max_frames=16",
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
		"route_tcp_gso_async_worker_min_queue_depth=1",
		"route_tcp_gso_async_worker_schedule_delay_usecs=0",
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
		"TRUSTIX_CROSS_HOST_GATE_MIN_GBPS:-4",
		"TRUSTIX_CROSS_HOST_GATE_MIN_SECONDS:-120",
		"TRUSTIX_CROSS_HOST_GATE_REQUIRE_BINARY_IDENTITY:-1",
		"TRUSTIX_CROSS_HOST_DD_FULL_KMOD",
		"TRUSTIX_CROSS_HOST_OWDEB_FULL_KMOD",
		"TRUSTIX_CROSS_HOST_DD_ROUTE_GSO",
		"--require-binary-identity",
		"--require-datapath-stat kernel_udp.provider_stats.kernel_datapath_full_plaintext_provider=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_experimental_tcp_tx_direct_route_tcp_gso_async_kfunc=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_experimental_tcp_tx_direct_route_tcp_gso_async_kfunc_requested=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_tx_direct_experimental_tcp_only=1",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("linux-cross-host-production-gate.sh missing %q", want)
		}
	}
}
