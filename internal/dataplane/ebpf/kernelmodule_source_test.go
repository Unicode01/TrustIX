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
