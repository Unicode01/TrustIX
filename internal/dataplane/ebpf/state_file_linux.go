//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type dataplaneStateCommitError struct {
	err error
}

var (
	renameDataplaneStateFileFunc    = os.Rename
	syncDataplaneStateDirectoryFunc = syncDataplaneStateDirectory
)

func (err *dataplaneStateCommitError) Error() string {
	if err == nil || err.err == nil {
		return "dataplane state committed with an unknown durability error"
	}
	return err.err.Error()
}

func (err *dataplaneStateCommitError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.err
}

func dataplaneStateCommitSucceeded(err error) bool {
	var committed *dataplaneStateCommitError
	return errors.As(err, &committed)
}

func writeDataplaneStateAtomic(path string, payload []byte, mode os.FileMode) (resultErr error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create dataplane state directory %q: %w", dir, err)
	}
	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary dataplane state file for %q: %w", path, err)
	}
	tmp := file.Name()
	closed := false
	defer func() {
		if !closed {
			if err := file.Close(); err != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("close temporary dataplane state file %q: %w", tmp, err))
			}
		}
		if tmp != "" {
			if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
				resultErr = errors.Join(resultErr, fmt.Errorf("remove temporary dataplane state file %q: %w", tmp, err))
			}
		}
	}()
	if _, err := file.Write(payload); err != nil {
		return fmt.Errorf("write temporary dataplane state file %q: %w", tmp, err)
	}
	if err := file.Chmod(mode); err != nil {
		return fmt.Errorf("chmod temporary dataplane state file %q: %w", tmp, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync temporary dataplane state file %q: %w", tmp, err)
	}
	if err := file.Close(); err != nil {
		closed = true
		return fmt.Errorf("close temporary dataplane state file %q: %w", tmp, err)
	}
	closed = true
	if err := renameDataplaneStateFileFunc(tmp, path); err != nil {
		return fmt.Errorf("replace dataplane state file %q: %w", path, err)
	}
	tmp = ""
	if err := syncDataplaneStateDirectoryFunc(dir); err != nil {
		return &dataplaneStateCommitError{err: fmt.Errorf("sync dataplane state directory %q: %w", dir, err)}
	}
	return nil
}

func syncDataplaneStateDirectory(path string) (resultErr error) {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		if err := dir.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close directory: %w", err))
		}
	}()
	return dir.Sync()
}
