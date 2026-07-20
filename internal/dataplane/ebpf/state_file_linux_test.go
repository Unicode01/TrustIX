//go:build linux

package ebpf

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteDataplaneStateAtomicReplacesCompleteFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeDataplaneStateAtomic(path, []byte("new-state"), 0o600); err != nil {
		t.Fatalf("write atomic state: %v", err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "new-state" {
		t.Fatalf("state payload = %q, want new-state", payload)
	}
	assertNoDataplaneStateTempFiles(t, path)
}

func TestWriteDataplaneStateAtomicRenameFailurePreservesOldFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("old-state"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("injected rename failure")
	originalRename := renameDataplaneStateFileFunc
	renameDataplaneStateFileFunc = func(string, string) error { return wantErr }
	t.Cleanup(func() { renameDataplaneStateFileFunc = originalRename })

	err := writeDataplaneStateAtomic(path, []byte("new-state"), 0o600)
	if !errors.Is(err, wantErr) || dataplaneStateCommitSucceeded(err) {
		t.Fatalf("write error = %v, want uncommitted rename failure", err)
	}
	payload, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(payload) != "old-state" {
		t.Fatalf("state payload = %q, want preserved old-state", payload)
	}
	assertNoDataplaneStateTempFiles(t, path)
}

func TestWriteDataplaneStateAtomicReportsCommittedDirectorySyncFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	wantErr := errors.New("injected directory sync failure")
	originalSync := syncDataplaneStateDirectoryFunc
	syncDataplaneStateDirectoryFunc = func(string) error { return wantErr }
	t.Cleanup(func() { syncDataplaneStateDirectoryFunc = originalSync })

	err := writeDataplaneStateAtomic(path, []byte("committed-state"), 0o600)
	if !errors.Is(err, wantErr) || !dataplaneStateCommitSucceeded(err) {
		t.Fatalf("write error = %v, want committed durability failure", err)
	}
	payload, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(payload) != "committed-state" {
		t.Fatalf("state payload = %q, want committed-state", payload)
	}
	assertNoDataplaneStateTempFiles(t, path)
}

func assertNoDataplaneStateTempFiles(t *testing.T, path string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary dataplane state files remain: %v", matches)
	}
}
