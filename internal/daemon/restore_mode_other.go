//go:build !windows

package daemon

import "os"

func restoreFileModeEqual(actual, expected os.FileMode) bool {
	return actual.Perm() == expected.Perm()
}
