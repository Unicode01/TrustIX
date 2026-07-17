package iptunnel

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type tunnelStateCommitError struct {
	err error
}

var syncTunnelStateDirectoryFunc = syncTunnelStateDirectory

func (commitErr *tunnelStateCommitError) Error() string {
	if commitErr == nil || commitErr.err == nil {
		return "iptunnel state committed with an unknown durability error"
	}
	return commitErr.err.Error()
}

func (commitErr *tunnelStateCommitError) Unwrap() error {
	if commitErr == nil {
		return nil
	}
	return commitErr.err
}

func tunnelStateCommitSucceeded(err error) bool {
	var committed *tunnelStateCommitError
	return errors.As(err, &committed)
}

func writeTunnelStateAtomic(path string, payload []byte, mode os.FileMode) (resultErr error) {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := file.Name()
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, wrapTunnelStateError("close temporary state file", file.Close()))
		}
		if tmp != "" {
			if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
				resultErr = errors.Join(resultErr, fmt.Errorf("remove temporary state file %q: %w", tmp, err))
			}
		}
	}()
	if _, err := file.Write(payload); err != nil {
		return err
	}
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		closed = true
		return err
	}
	closed = true
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	tmp = ""
	if err := syncTunnelStateDirectoryFunc(dir); err != nil {
		return &tunnelStateCommitError{err: fmt.Errorf("sync iptunnel state directory %q: %w", dir, err)}
	}
	return nil
}

func wrapTunnelStateError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}
