package daemon

import (
	"strings"
	"testing"
)

func TestParseProcStatusRSSBytes(t *testing.T) {
	payload := "Name:\ttrustixd\nVmRSS:\t  12345 kB\nThreads:\t7\n"
	rss, err := parseProcStatusRSSBytes(payload)
	if err != nil {
		t.Fatalf("parse VmRSS: %v", err)
	}
	if want := uint64(12345 * 1024); rss != want {
		t.Fatalf("rss = %d, want %d", rss, want)
	}
}

func TestParseProcStatusRSSBytesRejectsMissingRSS(t *testing.T) {
	if _, err := parseProcStatusRSSBytes("Name:\ttrustixd\n"); err == nil {
		t.Fatal("expected missing VmRSS error")
	}
}

func TestRuntimeResourceDoctorStatusWarnsOnLargeRSS(t *testing.T) {
	status := runtimeResourceStatus{
		PID:      10,
		RSSBytes: runtimeWarnRSSBytes,
	}
	if got := runtimeResourceDoctorStatus(status); got != "warn" {
		t.Fatalf("doctor status = %q, want warn", got)
	}
	detail := runtimeResourceDoctorDetail(status)
	for _, want := range []string{"pid=10", "rss_bytes="} {
		if !strings.Contains(detail, want) {
			t.Fatalf("detail %q does not contain %q", detail, want)
		}
	}
}

func TestRuntimeResourceSnapshotIncludesDataDirLock(t *testing.T) {
	status := runtimeResourceSnapshotWithDataDirLock("/tmp/trustixd.lock", true)
	if !status.DataDirLockHeld {
		t.Fatal("expected data dir lock to be marked held")
	}
	if status.DataDirLockPath != "/tmp/trustixd.lock" {
		t.Fatalf("data dir lock path = %q, want /tmp/trustixd.lock", status.DataDirLockPath)
	}
	detail := runtimeResourceDoctorDetail(status)
	for _, want := range []string{"data_dir_lock_held=true", "data_dir_lock_path=/tmp/trustixd.lock"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("detail %q does not contain %q", detail, want)
		}
	}
}

func TestRuntimeResourceDoctorStatusOK(t *testing.T) {
	status := runtimeResourceStatus{
		PID:              10,
		Goroutines:       8,
		GoSysBytes:       32 * 1024 * 1024,
		RSSBytes:         64 * 1024 * 1024,
		OpenFDs:          32,
		GoHeapAllocBytes: 16 * 1024 * 1024,
	}
	if got := runtimeResourceDoctorStatus(status); got != "ok" {
		t.Fatalf("doctor status = %q, want ok", got)
	}
}
