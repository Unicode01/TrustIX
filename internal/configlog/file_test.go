package configlog

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
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

func TestFileStoreAppendBatchPersistsAllEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.log")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("new file store: %v", err)
	}
	first := configLogTestEvent(t, 1, "evt-1", "")
	firstHash, err := first.Hash()
	if err != nil {
		t.Fatal(err)
	}
	second := configLogTestEvent(t, 2, "evt-2", firstHash)
	if err := store.AppendBatch([]Event{first, second}); err != nil {
		t.Fatalf("append batch: %v", err)
	}

	reloaded, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("reload file store: %v", err)
	}
	head, err := reloaded.Head()
	if err != nil {
		t.Fatal(err)
	}
	if head.Seq != 2 {
		t.Fatalf("reloaded head seq = %d, want 2", head.Seq)
	}
}

func TestFileStoreAppendFailureDoesNotAdvanceMemory(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "log")
	path := filepath.Join(parent, "config.log")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("new file store: %v", err)
	}
	first := configLogTestEvent(t, 1, "evt-1", "")
	if err := store.Append(first); err != nil {
		t.Fatalf("append first event: %v", err)
	}
	firstHash, err := first.Hash()
	if err != nil {
		t.Fatal(err)
	}
	second := configLogTestEvent(t, 2, "evt-2", firstHash)

	savedParent := filepath.Join(root, "saved-log")
	if err := os.Rename(parent, savedParent); err != nil {
		t.Fatalf("move log directory: %v", err)
	}
	if err := os.WriteFile(parent, []byte("blocks directory creation"), 0o600); err != nil {
		t.Fatalf("create blocking file: %v", err)
	}
	if err := store.Append(second); err == nil {
		t.Fatal("append succeeded with an invalid log parent")
	}
	head, err := store.Head()
	if err != nil {
		t.Fatal(err)
	}
	if head.Seq != 1 {
		t.Fatalf("head advanced after failed persistence: %+v", head)
	}

	if err := os.Remove(parent); err != nil {
		t.Fatalf("remove blocking file: %v", err)
	}
	if err := os.Rename(savedParent, parent); err != nil {
		t.Fatalf("restore log directory: %v", err)
	}
	if err := store.Append(second); err != nil {
		t.Fatalf("retry append after restoring storage: %v", err)
	}
	reloaded, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("reload file store: %v", err)
	}
	head, err = reloaded.Head()
	if err != nil {
		t.Fatal(err)
	}
	if head.Seq != 2 {
		t.Fatalf("reloaded head after retry = %+v, want seq 2", head)
	}
}

func TestFileStoreConcurrentAppendHeadAndRange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.log")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("new file store: %v", err)
	}
	stop := make(chan struct{})
	errCh := make(chan error, 1)
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				head, err := store.Head()
				if err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
				if head.Seq == 0 {
					continue
				}
				events, err := store.Range(1, head.Seq)
				if err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
				if uint64(len(events)) != head.Seq {
					select {
					case errCh <- fmt.Errorf("range length = %d, want %d", len(events), head.Seq):
					default:
					}
					return
				}
			}
		}()
	}
	previousHash := ""
	for seq := uint64(1); seq <= 32; seq++ {
		event := configLogTestEvent(t, seq, core.EventID(fmt.Sprintf("evt-%d", seq)), previousHash)
		if err := store.Append(event); err != nil {
			close(stop)
			readers.Wait()
			t.Fatalf("append event %d: %v", seq, err)
		}
		previousHash, err = event.Hash()
		if err != nil {
			close(stop)
			readers.Wait()
			t.Fatalf("hash event %d: %v", seq, err)
		}
	}
	close(stop)
	readers.Wait()
	select {
	case err := <-errCh:
		t.Fatal(err)
	default:
	}
}

func TestMemoryStoreAppendBatchIsAtomic(t *testing.T) {
	store := NewMemoryStore()
	first := configLogTestEvent(t, 1, "evt-1", "")
	firstHash, err := first.Hash()
	if err != nil {
		t.Fatal(err)
	}
	invalid := configLogTestEvent(t, 3, "evt-3", firstHash)
	if err := store.AppendBatch([]Event{first, invalid}); err == nil {
		t.Fatal("invalid batch succeeded")
	}
	head, err := store.Head()
	if err != nil {
		t.Fatal(err)
	}
	if head.Seq != 0 || head.Hash != "" {
		t.Fatalf("head advanced after invalid batch: %+v", head)
	}
}

func configLogTestEvent(t *testing.T, seq uint64, id core.EventID, previousHash string) Event {
	t.Helper()
	return Event{
		DomainID:  core.DomainID("lab.local"),
		EventID:   id,
		Seq:       seq,
		PrevHash:  previousHash,
		Resource:  core.ResourcePath("/desired"),
		Action:    ActionUpsert,
		Payload:   []byte(`{"ok":true}`),
		SignerID:  core.SignerID("admin-1"),
		Signature: []byte("signature"),
		CreatedAt: time.Unix(int64(seq), 0).UTC(),
	}
}
