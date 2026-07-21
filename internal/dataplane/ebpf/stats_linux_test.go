//go:build linux

package ebpf

import (
	"slices"
	"testing"
	"time"

	cebpf "github.com/cilium/ebpf"
)

func TestSumPerCPUCounterBatch(t *testing.T) {
	totals := make([]uint64, 6)
	sumPerCPUCounterBatch(
		[]uint32{4, 1, 7},
		[]uint64{1, 2, 3, 10, 20, 30, 100, 200, 300},
		3,
		3,
		totals,
	)

	want := []uint64{0, 60, 0, 0, 6, 0}
	if !slices.Equal(totals, want) {
		t.Fatalf("counter totals = %v, want %v", totals, want)
	}
}

func TestSumPerCPUCounterBatchBoundsTruncatedInput(t *testing.T) {
	totals := make([]uint64, 3)
	sumPerCPUCounterBatch(
		[]uint32{0, 1, 2},
		[]uint64{1, 2, 10, 20, 100},
		10,
		2,
		totals,
	)

	want := []uint64{3, 30, 0}
	if !slices.Equal(totals, want) {
		t.Fatalf("counter totals = %v, want %v", totals, want)
	}
}

func TestResizeCounterSlicesReuseCapacity(t *testing.T) {
	uint32s := make([]uint32, 1, 4)
	uint32s[0] = 9
	uint32s = resizeUint32Slice(uint32s, 4)
	if len(uint32s) != 4 || cap(uint32s) != 4 || uint32s[0] != 9 {
		t.Fatalf("resized uint32 slice = %#v len=%d cap=%d", uint32s, len(uint32s), cap(uint32s))
	}

	uint64s := make([]uint64, 1, 4)
	uint64s[0] = 11
	uint64s = resizeUint64Slice(uint64s, 4)
	if len(uint64s) != 4 || cap(uint64s) != 4 || uint64s[0] != 11 {
		t.Fatalf("resized uint64 slice = %#v len=%d cap=%d", uint64s, len(uint64s), cap(uint64s))
	}
}

func TestStatsCounterBatchValuesReadsAndCachesPerCPUArray(t *testing.T) {
	statsMap := newTestBPFMap(t, &cebpf.MapSpec{
		Name:       "ix_stats_batch_test",
		Type:       cebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 4,
	})
	defer statsMap.Close()

	possibleCPUs, err := cebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("possible CPUs: %v", err)
	}
	perCPU := make([]uint64, possibleCPUs)
	for index := range perCPU {
		perCPU[index] = uint64(index + 1)
	}
	key := uint32(2)
	if err := statsMap.Update(key, perCPU, cebpf.UpdateAny); err != nil {
		t.Fatalf("seed per-CPU counter: %v", err)
	}

	manager := NewManager()
	manager.statsMap = statsMap
	now := time.Unix(100, 0)
	values, ok := manager.statsCounterBatchValuesLocked(now)
	if !ok {
		t.Skip("kernel does not support batched per-CPU array lookup")
	}
	var want uint64
	for _, value := range perCPU {
		want += value
	}
	if got := values[key]; got != want {
		t.Fatalf("batched counter = %d, want %d", got, want)
	}

	clear(perCPU)
	perCPU[0] = 99
	if err := statsMap.Update(key, perCPU, cebpf.UpdateAny); err != nil {
		t.Fatalf("update per-CPU counter: %v", err)
	}
	values, ok = manager.statsCounterBatchValuesLocked(now.Add(statsCounterBatchCacheTTL / 2))
	if !ok || values[key] != want {
		t.Fatalf("cached counter = %d, want %d", values[key], want)
	}
	values, ok = manager.statsCounterBatchValuesLocked(now.Add(statsCounterBatchCacheTTL))
	if !ok || values[key] != 99 {
		t.Fatalf("refreshed counter = %d, want 99", values[key])
	}
}
