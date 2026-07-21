//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"time"

	cebpf "github.com/cilium/ebpf"
)

const statsCounterBatchCacheTTL = 500 * time.Millisecond

func (manager *Manager) resetStatsCounterCacheLocked() {
	manager.statsBatchUnsupported = false
	manager.statsBatchMap = nil
	manager.statsBatchAt = time.Time{}
	manager.statsBatchKeys = nil
	manager.statsBatchValues = nil
	manager.statsBatchTotals = nil
	manager.statsLookupValues = nil
}

func (manager *Manager) statsCounterBatchValuesLocked(now time.Time) ([]uint64, bool) {
	statsMap := manager.statsMap
	if statsMap == nil || manager.statsBatchUnsupported {
		return nil, false
	}
	if now.IsZero() {
		now = time.Now()
	}
	if manager.statsBatchMap == statsMap && !manager.statsBatchAt.IsZero() && now.Sub(manager.statsBatchAt) < statsCounterBatchCacheTTL {
		return manager.statsBatchTotals, true
	}
	possibleCPUs, err := cebpf.PossibleCPU()
	if err != nil || possibleCPUs <= 0 {
		manager.statsBatchUnsupported = true
		return nil, false
	}
	entryCount := int(statsMap.MaxEntries())
	if entryCount <= 0 {
		manager.statsBatchUnsupported = true
		return nil, false
	}
	manager.statsBatchPossibleCPUs = possibleCPUs
	manager.statsBatchKeys = resizeUint32Slice(manager.statsBatchKeys, entryCount)
	manager.statsBatchValues = resizeUint64Slice(manager.statsBatchValues, entryCount*possibleCPUs)
	manager.statsBatchTotals = resizeUint64Slice(manager.statsBatchTotals, entryCount)
	clear(manager.statsBatchTotals)

	var cursor cebpf.MapBatchCursor
	offset := 0
	for offset < entryCount {
		keys := manager.statsBatchKeys[offset:entryCount]
		values := manager.statsBatchValues[offset*possibleCPUs : entryCount*possibleCPUs]
		count, lookupErr := statsMap.BatchLookup(&cursor, keys, values, nil)
		if lookupErr != nil && !errors.Is(lookupErr, cebpf.ErrKeyNotExist) {
			manager.statsBatchUnsupported = true
			manager.statsBatchAt = time.Time{}
			manager.statsBatchMap = nil
			return nil, false
		}
		sumPerCPUCounterBatch(keys, values, count, possibleCPUs, manager.statsBatchTotals)
		offset += count
		if errors.Is(lookupErr, cebpf.ErrKeyNotExist) || count == 0 {
			break
		}
	}
	manager.statsBatchMap = statsMap
	manager.statsBatchAt = now
	return manager.statsBatchTotals, true
}

func (manager *Manager) statsCounterValueFallbackLocked(key uint32) (uint64, error) {
	if manager.statsMap == nil {
		return 0, fmt.Errorf("BPF counter map is nil")
	}
	if manager.statsMap.Type() != cebpf.PerCPUArray && manager.statsMap.Type() != cebpf.PerCPUHash && manager.statsMap.Type() != cebpf.LRUCPUHash {
		return bpfCounterValue(manager.statsMap, key)
	}
	possibleCPUs := manager.statsBatchPossibleCPUs
	if possibleCPUs <= 0 {
		var err error
		possibleCPUs, err = cebpf.PossibleCPU()
		if err != nil {
			return 0, err
		}
		manager.statsBatchPossibleCPUs = possibleCPUs
	}
	manager.statsLookupValues = resizeUint64Slice(manager.statsLookupValues, possibleCPUs)
	clear(manager.statsLookupValues)
	if err := manager.statsMap.Lookup(key, manager.statsLookupValues); err != nil {
		return 0, err
	}
	var total uint64
	for _, value := range manager.statsLookupValues {
		total += value
	}
	return total, nil
}

func sumPerCPUCounterBatch(keys []uint32, values []uint64, count int, possibleCPUs int, totals []uint64) {
	if count > len(keys) {
		count = len(keys)
	}
	if possibleCPUs <= 0 || count <= 0 {
		return
	}
	if maxCount := len(values) / possibleCPUs; count > maxCount {
		count = maxCount
	}
	for index := 0; index < count; index++ {
		key := int(keys[index])
		if key < 0 || key >= len(totals) {
			continue
		}
		start := index * possibleCPUs
		end := start + possibleCPUs
		var total uint64
		for _, value := range values[start:end] {
			total += value
		}
		totals[key] = total
	}
}

func resizeUint32Slice(values []uint32, size int) []uint32 {
	if cap(values) < size {
		return make([]uint32, size)
	}
	return values[:size]
}

func resizeUint64Slice(values []uint64, size int) []uint64 {
	if cap(values) < size {
		return make([]uint64, size)
	}
	return values[:size]
}

func bpfCounterValue(m *cebpf.Map, key uint32) (uint64, error) {
	if m == nil {
		return 0, fmt.Errorf("BPF counter map is nil")
	}
	if m.Type() == cebpf.PerCPUArray || m.Type() == cebpf.PerCPUHash || m.Type() == cebpf.LRUCPUHash {
		var values []uint64
		if err := m.Lookup(key, &values); err != nil {
			return 0, err
		}
		var total uint64
		for _, value := range values {
			total += value
		}
		return total, nil
	}
	var value uint64
	if err := m.Lookup(key, &value); err != nil {
		return 0, err
	}
	return value, nil
}
