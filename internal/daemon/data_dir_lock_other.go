//go:build !linux

package daemon

func acquireDataDirLock(dataDir string) (heldDataDirLock, error) {
	return nil, nil
}
