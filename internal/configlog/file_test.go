package configlog

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"trustix.local/trustix/internal/core"
)

func TestFileStorePersistsAndReloadsHashChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.log")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("new file store: %v", err)
	}
	first := Event{
		DomainID:  core.DomainID("lab.local"),
		EventID:   core.EventID("evt-1"),
		Seq:       1,
		Resource:  core.ResourcePath("/desired"),
		Action:    ActionUpsert,
		Payload:   []byte(`{"ok":true}`),
		SignerID:  core.SignerID("admin-1"),
		Signature: []byte("signature"),
		CreatedAt: time.Unix(1, 0).UTC(),
	}
	if err := store.Append(first); err != nil {
		t.Fatalf("append first event: %v", err)
	}

	reloaded, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("reload file store: %v", err)
	}
	head, err := reloaded.Head()
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	if head.Seq != 1 || head.Hash == "" {
		t.Fatalf("head = %+v, want seq 1 with hash", head)
	}
}

func TestFileStoreReplaceAllRewritesLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.log")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("new file store: %v", err)
	}
	first := Event{
		DomainID:  core.DomainID("lab.local"),
		EventID:   core.EventID("evt-1"),
		Seq:       1,
		Resource:  core.ResourcePath("/domain/genesis"),
		Action:    ActionCreate,
		Payload:   []byte(`{"version":1}`),
		SignerID:  core.SignerID("genesis:lab.local"),
		Signature: []byte("signature"),
		CreatedAt: time.Unix(1, 0).UTC(),
	}
	if err := store.Append(first); err != nil {
		t.Fatalf("append first event: %v", err)
	}

	replacement := first
	replacement.EventID = core.EventID("evt-replacement")
	replacement.Payload = []byte(`{"version":2}`)
	if err := store.ReplaceAll([]Event{replacement}); err != nil {
		t.Fatalf("replace log: %v", err)
	}

	reloaded, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("reload file store: %v", err)
	}
	events, err := reloaded.Range(1, 1)
	if err != nil {
		t.Fatalf("range reloaded: %v", err)
	}
	if events[0].EventID != "evt-replacement" {
		t.Fatalf("event id = %q, want replacement", events[0].EventID)
	}
	backups, err := filepath.Glob(path + ".backup.*")
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 1 {
		t.Fatalf("backups = %d, want 1", len(backups))
	}
	payload, err := os.ReadFile(backups[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) == 0 {
		t.Fatal("backup is empty")
	}
}

func TestBackupFilePrunesOldBackups(t *testing.T) {
	t.Setenv(BackupKeepEnv, "2")
	path := filepath.Join(t.TempDir(), "config.log")
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(path, []byte(`{"seq":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := BackupFile(path); err != nil {
			t.Fatalf("backup %d: %v", i, err)
		}
	}

	backups, err := BackupFiles(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 2 {
		t.Fatalf("backups = %d, want 2: %v", len(backups), backups)
	}
}
