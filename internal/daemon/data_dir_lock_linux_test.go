//go:build linux

package daemon

import (
	"strings"
	"testing"
)

func TestDataDirLockRejectsSecondOwner(t *testing.T) {
	dataDir := t.TempDir()
	first, err := acquireDataDirLock(dataDir)
	if err != nil {
		t.Fatalf("acquire first lock: %v", err)
	}
	defer first.Close()

	second, err := acquireDataDirLock(dataDir)
	if err == nil {
		_ = second.Close()
		t.Fatal("expected second data dir lock to fail")
	}
	if !strings.Contains(err.Error(), "already locked") {
		t.Fatalf("second lock error = %v, want already locked", err)
	}
}

func TestDataDirLockCanBeReacquiredAfterClose(t *testing.T) {
	dataDir := t.TempDir()
	first, err := acquireDataDirLock(dataDir)
	if err != nil {
		t.Fatalf("acquire first lock: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first lock: %v", err)
	}

	second, err := acquireDataDirLock(dataDir)
	if err != nil {
		t.Fatalf("reacquire lock: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("close second lock: %v", err)
	}
}
