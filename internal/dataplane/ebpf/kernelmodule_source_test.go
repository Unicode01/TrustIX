package ebpf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKernelModuleRouteTCPHRTimerSetupIsVersionCompatible(t *testing.T) {
	sourceBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "kernel", "trustix_datapath_helpers", "trustix_datapath_helpers_kfuncs.c"))
	if err != nil {
		t.Fatalf("read datapath module C source: %v", err)
	}
	source := string(sourceBytes)
	if !strings.Contains(source, "static void trustix_hrtimer_setup(struct hrtimer *timer,") {
		t.Fatal("route TCP timers must use the local hrtimer compatibility wrapper")
	}
	for _, want := range []string{
		"#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)",
		"hrtimer_setup(timer, function, clock_id, mode);",
		"hrtimer_init(timer, clock_id, mode);",
		"timer->function = function;",
		"trustix_hrtimer_setup(&trustix_route_tcp_gso_async_schedule_timer,",
		"trustix_hrtimer_setup(&trustix_route_tcp_gso_async_shards[i].schedule_timer,",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("route TCP hrtimer setup missing %q", want)
		}
	}
	if got := strings.Count(source, "hrtimer_init("); got != 1 {
		t.Fatalf("direct hrtimer_init uses = %d, want exactly wrapper fallback", got)
	}
	if got := strings.Count(source, "timer->function = function;"); got != 1 {
		t.Fatalf("direct timer function assignments = %d, want exactly wrapper fallback", got)
	}
}

func TestKernelDatapathSecureRXFailuresExposeStageDiagnostics(t *testing.T) {
	datapathBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "kernel", "trustix_datapath", "trustix_datapath.c"))
	if err != nil {
		t.Fatalf("read full datapath module C source: %v", err)
	}
	datapathSource := string(datapathBytes)
	managerBytes, err := os.ReadFile("manager_linux.go")
	if err != nil {
		t.Fatalf("read datapath manager source: %v", err)
	}
	managerSource := string(managerBytes)

	for _, name := range []string{
		"secure_rx_writable_errors",
		"secure_rx_frame_limit_errors",
		"secure_rx_frame_parse_errors",
		"secure_rx_frame_validate_errors",
		"secure_rx_plan_errors",
		"secure_rx_header_errors",
		"secure_rx_crypto_errors",
		"secure_rx_checksum_errors",
		"secure_rx_layout_errors",
		"secure_rx_copy_errors",
		"secure_rx_delivery_errors",
		"secure_rx_other_errors",
		"secure_rx_gso_packets",
		"secure_rx_nonlinear_packets",
		"secure_rx_cloned_packets",
		"secure_rx_max_frames",
		"secure_rx_last_error_stage",
	} {
		if !strings.Contains(datapathSource, "module_param_named("+name+",") {
			t.Fatalf("secure RX diagnostic %s is not exported by the kernel module", name)
		}
		if !strings.Contains(managerSource, `"`+name+`",`) {
			t.Fatalf("secure RX diagnostic %s is not exported through datapath stats", name)
		}
	}

	// WRITABLE is a legacy diagnostic retained for deployed sysfs consumers.
	// Every active stage must appear in the enum, counter switch, and an error path.
	for _, stage := range []string{
		"TRUSTIX_DATAPATH_SECURE_RX_ERROR_FRAME_LIMIT",
		"TRUSTIX_DATAPATH_SECURE_RX_ERROR_FRAME_PARSE",
		"TRUSTIX_DATAPATH_SECURE_RX_ERROR_FRAME_VALIDATE",
		"TRUSTIX_DATAPATH_SECURE_RX_ERROR_PLAN",
		"TRUSTIX_DATAPATH_SECURE_RX_ERROR_HEADER",
		"TRUSTIX_DATAPATH_SECURE_RX_ERROR_CRYPTO",
		"TRUSTIX_DATAPATH_SECURE_RX_ERROR_CHECKSUM",
		"TRUSTIX_DATAPATH_SECURE_RX_ERROR_LAYOUT",
		"TRUSTIX_DATAPATH_SECURE_RX_ERROR_COPY",
		"TRUSTIX_DATAPATH_SECURE_RX_ERROR_DELIVERY",
	} {
		if strings.Count(datapathSource, stage) < 3 {
			t.Fatalf("secure RX error stage %s is declared but never assigned", stage)
		}
	}
	if !strings.Contains(datapathSource, "trustix_datapath_secure_rx_record_error(error_stage, ret);") {
		t.Fatal("secure RX claimed-packet failures are not recorded by stage")
	}
	if strings.Contains(datapathSource, "skb_ensure_writable(skb, (__u32)network_offset + total_len)") {
		t.Fatal("secure RX must not linearize an entire GRO skb in atomic context")
	}
	for _, want := range []string{
		"scratch->packet = kvzalloc(TRUSTIX_DATAPATH_PACKET_MAX_LEN,",
		"skb_copy_bits(skb, (__u32)network_offset, scratch->packet,",
		"trustix_datapath_rx_worker_push_stream_batch_source(",
		"local_bh_disable();\n\tscratch = get_cpu_ptr(trustix_datapath_secure_rx_scratch);",
		"put_cpu_ptr(scratch);\n\tscratch = NULL;\n\tlocal_bh_enable();",
		"memzero_explicit(scratch->packet,",
	} {
		if !strings.Contains(datapathSource, want) {
			t.Fatalf("secure RX scratch delivery path missing %q", want)
		}
	}
}
