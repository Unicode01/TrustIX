//go:build windows

package daemon

import "os"

func restoreFileModeEqual(os.FileMode, os.FileMode) bool {
	return true
}
