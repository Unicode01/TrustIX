//go:build !windows

package daemon

import (
	"errors"
	"fmt"
	"os"
)

func syncStateDirectory(path string) (resultErr error) {
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
