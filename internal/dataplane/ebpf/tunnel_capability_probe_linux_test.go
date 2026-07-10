package ebpf

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTunnelCapabilityProbeCacheValidity(t *testing.T) {
	now := time.Now()
	if !tunnelCapabilityProbeCacheValid(now, tunnelCapabilityProbeResult{
		ready:     true,
		expiresAt: now.Add(-time.Hour),
	}) {
		t.Fatal("successful tunnel capability probe expired within one daemon process")
	}
	if !tunnelCapabilityProbeCacheValid(now, tunnelCapabilityProbeResult{
		ready:     false,
		expiresAt: now.Add(time.Minute),
	}) {
		t.Fatal("failed tunnel capability probe was not cached until its retry deadline")
	}
	if tunnelCapabilityProbeCacheValid(now, tunnelCapabilityProbeResult{
		ready:     false,
		expiresAt: now.Add(-time.Second),
	}) {
		t.Fatal("failed tunnel capability probe remained cached after its retry deadline")
	}
}

func TestTunnelCapabilityProbeCacheSerializesConcurrentMisses(t *testing.T) {
	tunnelCapabilityProbeCache.Clear()
	t.Cleanup(tunnelCapabilityProbeCache.Clear)

	const callers = 32
	now := time.Now()
	start := make(chan struct{})
	errs := make(chan string, callers)
	var probes atomic.Int32
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ready, reason := probeTunnelCapabilityCached("gre", func() time.Time { return now }, func(string) (bool, string) {
				probes.Add(1)
				time.Sleep(10 * time.Millisecond)
				return true, "ready"
			})
			if !ready || reason != "ready" {
				errs <- "concurrent caller did not receive the cached successful result"
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if got := probes.Load(); got != 1 {
		t.Fatalf("concurrent capability probes = %d, want 1", got)
	}
}

func TestDatapathHelpersIgnoreTunnelCapabilityProbeUnregisters(t *testing.T) {
	path := filepath.Join("..", "..", "..", "kernel", "trustix_datapath_helpers", "trustix_datapath_helpers_kfuncs.c")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read datapath helper source: %v", err)
	}
	source := strings.ReplaceAll(string(raw), "\r\n", "\n")
	for _, want := range []string{
		`"tixcapgre"`,
		`"tixcapipip"`,
		`"tixcapvxlan"`,
		"trustix_netdev_unregister_probe_ignored++",
		"trustix_netdev_unregister_flushes++",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("datapath helper capability-probe guard is missing %q", want)
		}
	}
	body := sourceFunctionBody(t, source, "trustix_datapath_helpers_netdev_event")
	ignore := strings.Index(body, "trustix_datapath_helpers_is_capability_probe_dev(dev)")
	flush := strings.Index(body, "trustix_datapath_helpers_release_netdev_refs(dev)")
	if ignore < 0 || flush <= ignore {
		t.Fatalf("capability-probe guard must run before netdev queue quiesce: guard=%d flush=%d", ignore, flush)
	}
}
