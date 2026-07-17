package configlog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultBackupKeep = 16
	BackupKeepEnv     = "TRUSTIX_CONFIG_LOG_BACKUP_KEEP"
)

type FileStore struct {
	mu     sync.Mutex
	path   string
	memory *MemoryStore
}

func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		return nil, fmt.Errorf("config log path is required")
	}
	store := &FileStore{
		path:   path,
		memory: NewMemoryStore(),
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (store *FileStore) Append(event Event) error {
	return store.AppendBatch([]Event{event})
}

func (store *FileStore) AppendBatch(events []Event) error {
	if len(events) == 0 {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()

	next := &MemoryStore{events: store.memory.snapshot()}
	if err := next.AppendBatch(events); err != nil {
		return err
	}
	payload, err := encodeEvents(next.snapshot())
	if err != nil {
		return err
	}
	committed, err := writeFileAtomic(store.path, payload, 0o600)
	if committed {
		store.memory = next
	}
	if err != nil {
		return fmt.Errorf("commit config log %q: %w", store.path, err)
	}
	return nil
}

func (store *FileStore) ReplaceAll(events []Event) error {
	next := NewMemoryStore()
	if err := next.AppendBatch(events); err != nil {
		return err
	}

	payload, err := encodeEvents(events)
	if err != nil {
		return err
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(store.path), 0o755); err != nil {
		return fmt.Errorf("create config log directory: %w", err)
	}
	if _, err := BackupFile(store.path); err != nil {
		return err
	}
	committed, err := writeFileAtomic(store.path, payload, 0o600)
	if committed {
		store.memory = next
	}
	if err != nil {
		return fmt.Errorf("replace config log %q: %w", store.path, err)
	}
	return nil
}

func encodeEvents(events []Event) ([]byte, error) {
	var payload bytes.Buffer
	encoder := json.NewEncoder(&payload)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			return nil, fmt.Errorf("encode config event: %w", err)
		}
	}
	return payload.Bytes(), nil
}

func writeFileAtomic(path string, payload []byte, mode os.FileMode) (committed bool, resultErr error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, fmt.Errorf("create directory %q: %w", dir, err)
	}
	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return false, fmt.Errorf("create temporary file for %q: %w", path, err)
	}
	tmp := file.Name()
	closed := false
	defer func() {
		if !closed {
			if err := file.Close(); err != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("close temporary file %q: %w", tmp, err))
			}
		}
		if tmp != "" {
			if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
				resultErr = errors.Join(resultErr, fmt.Errorf("remove temporary file %q: %w", tmp, err))
			}
		}
	}()
	if _, err := file.Write(payload); err != nil {
		return false, fmt.Errorf("write temporary file %q: %w", tmp, err)
	}
	if err := file.Chmod(mode); err != nil {
		return false, fmt.Errorf("chmod temporary file %q: %w", tmp, err)
	}
	if err := file.Sync(); err != nil {
		return false, fmt.Errorf("sync temporary file %q: %w", tmp, err)
	}
	if err := file.Close(); err != nil {
		closed = true
		return false, fmt.Errorf("close temporary file %q: %w", tmp, err)
	}
	closed = true
	if err := os.Rename(tmp, path); err != nil {
		return false, fmt.Errorf("rename temporary file %q to %q: %w", tmp, path, err)
	}
	tmp = ""
	committed = true
	if err := syncDirectory(dir); err != nil {
		return true, &CommitError{Err: fmt.Errorf("sync directory %q: %w", dir, err)}
	}
	return true, nil
}

func (store *FileStore) Head() (Head, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.memory.Head()
}

func (store *FileStore) Range(fromSeq, toSeq uint64) ([]Event, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.memory.Range(fromSeq, toSeq)
}

func (store *FileStore) Path() string {
	return store.path
}

func BackupFile(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("stat config log for backup %q: %w", path, err)
	}
	if info.IsDir() || info.Size() == 0 {
		return "", nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("create config log backup directory: %w", err)
	}
	base := path + ".backup." + time.Now().UTC().Format("20060102T150405.000000000Z")
	backup := base
	for i := 1; ; i++ {
		if _, err := os.Stat(backup); errors.Is(err, os.ErrNotExist) {
			break
		} else if err != nil {
			return "", fmt.Errorf("stat config log backup %q: %w", backup, err)
		}
		backup = fmt.Sprintf("%s.%d", base, i)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read config log for backup %q: %w", path, err)
	}
	committed, err := writeFileAtomic(backup, payload, 0o600)
	if err != nil {
		if committed {
			return backup, fmt.Errorf("commit config log backup %q: %v", backup, err)
		}
		return "", fmt.Errorf("write config log backup %q: %w", backup, err)
	}
	if err := pruneBackups(path, BackupKeepFromEnv(), backup); err != nil {
		return backup, err
	}
	return backup, nil
}

func BackupKeepFromEnv() int {
	raw := strings.TrimSpace(os.Getenv(BackupKeepEnv))
	if raw == "" {
		return DefaultBackupKeep
	}
	switch strings.ToLower(raw) {
	case "0", "off", "false", "no", "disabled":
		return 0
	}
	keep, err := strconv.Atoi(raw)
	if err != nil || keep < 0 {
		return DefaultBackupKeep
	}
	return keep
}

func PruneBackups(path string, keep int) error {
	return pruneBackups(path, keep, "")
}

func pruneBackups(path string, keep int, protected string) error {
	if path == "" || keep <= 0 {
		return nil
	}
	backups, err := BackupFiles(path)
	if err != nil {
		return err
	}
	if len(backups) <= keep {
		return nil
	}
	removeCount := len(backups) - keep
	for _, backup := range backups {
		if removeCount == 0 {
			break
		}
		if protected != "" && backup == protected {
			continue
		}
		if err := os.Remove(backup); err != nil {
			return fmt.Errorf("prune config log backup %q: %w", backup, err)
		}
		removeCount--
	}
	return nil
}

func BackupFiles(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	matches, err := filepath.Glob(path + ".backup.*")
	if err != nil {
		return nil, err
	}
	sort.SliceStable(matches, func(i, j int) bool {
		leftInfo, leftErr := os.Stat(matches[i])
		rightInfo, rightErr := os.Stat(matches[j])
		if leftErr == nil && rightErr == nil && !leftInfo.ModTime().Equal(rightInfo.ModTime()) {
			return leftInfo.ModTime().Before(rightInfo.ModTime())
		}
		return matches[i] < matches[j]
	})
	return matches, nil
}

func (store *FileStore) load() (resultErr error) {
	file, err := os.Open(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open config log %q: %w", store.path, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close config log %q: %w", store.path, err))
		}
	}()

	decoder := json.NewDecoder(file)
	for {
		var event Event
		if err := decoder.Decode(&event); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("decode config log %q: %w", store.path, err)
		}
		if err := store.memory.Append(event); err != nil {
			return fmt.Errorf("validate config log %q: %w", store.path, err)
		}
	}
	return nil
}
