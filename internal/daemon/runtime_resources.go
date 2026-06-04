package daemon

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

const (
	runtimeWarnRSSBytes   uint64 = 256 * 1024 * 1024
	runtimeWarnGoSysBytes uint64 = 256 * 1024 * 1024
	runtimeWarnFDs               = 4096
	runtimeWarnGoroutines        = 2048
)

type runtimeResourceStatus struct {
	PID                 int    `json:"pid"`
	GoOS                string `json:"goos"`
	GoArch              string `json:"goarch"`
	DataDirLockHeld     bool   `json:"data_dir_lock_held"`
	DataDirLockPath     string `json:"data_dir_lock_path,omitempty"`
	Goroutines          int    `json:"goroutines"`
	GoHeapAllocBytes    uint64 `json:"go_heap_alloc_bytes"`
	GoHeapSysBytes      uint64 `json:"go_heap_sys_bytes"`
	GoHeapIdleBytes     uint64 `json:"go_heap_idle_bytes"`
	GoHeapReleasedBytes uint64 `json:"go_heap_released_bytes"`
	GoStackInuseBytes   uint64 `json:"go_stack_inuse_bytes"`
	GoSysBytes          uint64 `json:"go_sys_bytes"`
	GoNumGC             uint32 `json:"go_num_gc"`
	RSSBytes            uint64 `json:"rss_bytes,omitempty"`
	OpenFDs             int    `json:"open_fds,omitempty"`
}

func runtimeResourceSnapshot() runtimeResourceStatus {
	return runtimeResourceSnapshotWithDataDirLock("", false)
}

func runtimeResourceSnapshotWithDataDirLock(lockPath string, lockHeld bool) runtimeResourceStatus {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	status := runtimeResourceStatus{
		PID:                 os.Getpid(),
		GoOS:                runtime.GOOS,
		GoArch:              runtime.GOARCH,
		DataDirLockHeld:     lockHeld,
		DataDirLockPath:     lockPath,
		Goroutines:          runtime.NumGoroutine(),
		GoHeapAllocBytes:    mem.HeapAlloc,
		GoHeapSysBytes:      mem.HeapSys,
		GoHeapIdleBytes:     mem.HeapIdle,
		GoHeapReleasedBytes: mem.HeapReleased,
		GoStackInuseBytes:   mem.StackInuse,
		GoSysBytes:          mem.Sys,
		GoNumGC:             mem.NumGC,
	}
	if rss, err := readProcStatusRSSBytes("/proc/self/status"); err == nil {
		status.RSSBytes = rss
	}
	if fds, err := countOpenFDs("/proc/self/fd"); err == nil {
		status.OpenFDs = fds
	}
	return status
}

func (daemon *Daemon) runtimeResourceSnapshot() runtimeResourceStatus {
	lockPath := ""
	lockHeld := false
	if daemon.dataDirLock != nil {
		lockPath = daemon.dataDirLock.Path()
		lockHeld = lockPath != ""
	}
	return runtimeResourceSnapshotWithDataDirLock(lockPath, lockHeld)
}

func runtimeResourceDoctorCheck(status runtimeResourceStatus) doctorCheck {
	return doctorCheck{
		Name:   "runtime_resources",
		Status: runtimeResourceDoctorStatus(status),
		Detail: runtimeResourceDoctorDetail(status),
	}
}

func runtimeResourceDoctorStatus(status runtimeResourceStatus) string {
	switch {
	case status.RSSBytes >= runtimeWarnRSSBytes && status.RSSBytes > 0:
		return "warn"
	case status.GoSysBytes >= runtimeWarnGoSysBytes:
		return "warn"
	case status.OpenFDs >= runtimeWarnFDs && status.OpenFDs > 0:
		return "warn"
	case status.Goroutines >= runtimeWarnGoroutines:
		return "warn"
	default:
		return "ok"
	}
}

func runtimeResourceDoctorDetail(status runtimeResourceStatus) string {
	return fmt.Sprintf("pid=%d data_dir_lock_held=%t data_dir_lock_path=%s goroutines=%d go_heap_alloc_bytes=%d go_sys_bytes=%d rss_bytes=%d open_fds=%d",
		status.PID,
		status.DataDirLockHeld,
		status.DataDirLockPath,
		status.Goroutines,
		status.GoHeapAllocBytes,
		status.GoSysBytes,
		status.RSSBytes,
		status.OpenFDs,
	)
}

func readProcStatusRSSBytes(path string) (uint64, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return parseProcStatusRSSBytes(string(payload))
}

func parseProcStatusRSSBytes(payload string) (uint64, error) {
	for _, rawLine := range strings.Split(payload, "\n") {
		key, value, ok := strings.Cut(rawLine, ":")
		if !ok || strings.TrimSpace(key) != "VmRSS" {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			return 0, fmt.Errorf("VmRSS value is empty")
		}
		amount, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse VmRSS %q: %w", fields[0], err)
		}
		unit := "B"
		if len(fields) > 1 {
			unit = strings.ToLower(fields[1])
		}
		switch unit {
		case "b":
			return amount, nil
		case "kb", "kib":
			return amount * 1024, nil
		case "mb", "mib":
			return amount * 1024 * 1024, nil
		default:
			return 0, fmt.Errorf("unsupported VmRSS unit %q", unit)
		}
	}
	return 0, fmt.Errorf("VmRSS not found")
}

func countOpenFDs(path string) (int, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}
