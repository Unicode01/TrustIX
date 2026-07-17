//go:build linux

package daemon

import (
	"errors"
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
		closeErr := file.Close()
		if err == unix.EWOULDBLOCK || err == unix.EAGAIN {
			owner := readLockOwnerPID(path)
			if owner != "" {
				return nil, errors.Join(
					fmt.Errorf("data dir %q is already locked by trustixd pid %s", dataDir, owner),
					wrapOperationError("close data dir lock after contention", closeErr),
				)
			}
			return nil, errors.Join(
				fmt.Errorf("data dir %q is already locked by another trustixd process", dataDir),
				wrapOperationError("close data dir lock after contention", closeErr),
			)
		}
		return nil, errors.Join(
			fmt.Errorf("lock data dir %q: %w", dataDir, err),
			wrapOperationError("close data dir lock after lock failure", closeErr),
		)
	}
	if err := file.Truncate(0); err != nil {
		return nil, errors.Join(fmt.Errorf("truncate data dir lock %q: %w", path, err), releaseFailedDataDirLock(file))
	}
	if _, err := file.Seek(0, 0); err != nil {
		return nil, errors.Join(fmt.Errorf("seek data dir lock %q: %w", path, err), releaseFailedDataDirLock(file))
	}
	if _, err := fmt.Fprintf(file, "%d\n", os.Getpid()); err != nil {
		return nil, errors.Join(fmt.Errorf("write data dir lock %q: %w", path, err), releaseFailedDataDirLock(file))
	}
	return &flockDataDirLock{file: file, path: path}, nil
}

func (lock *flockDataDirLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	err := releaseFailedDataDirLock(lock.file)
	lock.file = nil
	if err != nil {
		return fmt.Errorf("release data dir lock %q: %w", lock.path, err)
	}
	return nil
}

func releaseFailedDataDirLock(file *os.File) error {
	if file == nil {
		return nil
	}
	return errors.Join(
		wrapOperationError("unlock data dir lock", unix.Flock(int(file.Fd()), unix.LOCK_UN)),
		wrapOperationError("close data dir lock", file.Close()),
	)
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
