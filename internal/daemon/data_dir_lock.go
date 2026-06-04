package daemon

import "path/filepath"

type heldDataDirLock interface {
	Close() error
	Path() string
}

func dataDirLockPath(dataDir string) string {
	return filepath.Join(dataDir, "trustixd.lock")
}
