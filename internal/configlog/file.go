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
	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.memory.Append(event); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(store.path), 0o755); err != nil {
		return fmt.Errorf("create config log directory: %w", err)
	}
	file, err := os.OpenFile(store.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open config log %q: %w", store.path, err)
	}
	defer file.Close()

	encoded, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode config event: %w", err)
	}
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("append config event: %w", err)
	}
	return nil
}

func (store *FileStore) ReplaceAll(events []Event) error {
	next := NewMemoryStore()
	for _, event := range events {
		if err := next.Append(event); err != nil {
			return err
		}
	}

	var payload bytes.Buffer
	encoder := json.NewEncoder(&payload)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			return fmt.Errorf("encode config event: %w", err)
		}
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(store.path), 0o755); err != nil {
		return fmt.Errorf("create config log directory: %w", err)
	}
	if _, err := BackupFile(store.path); err != nil {
		return err
	}
	tmp := store.path + ".tmp"
	if err := os.WriteFile(tmp, payload.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write replacement config log %q: %w", tmp, err)
	}
	if err := os.Rename(tmp, store.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace config log %q: %w", store.path, err)
	}
	store.memory = next
	return nil
}

func (store *FileStore) Head() (Head, error) {
	return store.memory.Head()
}

func (store *FileStore) Range(fromSeq, toSeq uint64) ([]Event, error) {
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
	if err := os.WriteFile(backup, payload, 0o600); err != nil {
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

func (store *FileStore) load() error {
	file, err := os.Open(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open config log %q: %w", store.path, err)
	}
	defer file.Close()

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
