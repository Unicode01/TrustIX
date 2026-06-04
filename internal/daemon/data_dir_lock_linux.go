//go:build linux

package daemon

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type flockDataDirLock struct {
	file *os.File
	path string
}

func acquireDataDirLock(dataDir string) (heldDataDirLock, error) {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir %q: %w", dataDir, err)
	}
	path := dataDirLockPath(dataDir)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open data dir lock %q: %w", path, err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if err == unix.EWOULDBLOCK || err == unix.EAGAIN {
			owner := readLockOwnerPID(path)
			if owner != "" {
				return nil, fmt.Errorf("data dir %q is already locked by trustixd pid %s", dataDir, owner)
			}
			return nil, fmt.Errorf("data dir %q is already locked by another trustixd process", dataDir)
		}
		return nil, fmt.Errorf("lock data dir %q: %w", dataDir, err)
	}
	if err := file.Truncate(0); err != nil {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
		return nil, fmt.Errorf("truncate data dir lock %q: %w", path, err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
		return nil, fmt.Errorf("seek data dir lock %q: %w", path, err)
	}
	if _, err := fmt.Fprintf(file, "%d\n", os.Getpid()); err != nil {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
		return nil, fmt.Errorf("write data dir lock %q: %w", path, err)
	}
	return &flockDataDirLock{file: file, path: path}, nil
}

func (lock *flockDataDirLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	var errs []error
	if err := unix.Flock(int(lock.file.Fd()), unix.LOCK_UN); err != nil {
		errs = append(errs, err)
	}
	if err := lock.file.Close(); err != nil {
		errs = append(errs, err)
	}
	lock.file = nil
	if len(errs) > 0 {
		return fmt.Errorf("release data dir lock %q: %w", lock.path, errs[0])
	}
	return nil
}

func (lock *flockDataDirLock) Path() string {
	if lock == nil {
		return ""
	}
	return lock.path
}

func readLockOwnerPID(path string) string {
	payload, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	raw := strings.TrimSpace(string(payload))
	if raw == "" {
		return ""
	}
	if _, err := strconv.Atoi(raw); err != nil {
		return ""
	}
	return raw
}
