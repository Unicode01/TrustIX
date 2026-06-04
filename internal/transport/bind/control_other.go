//go:build !linux

package bind

import (
	"fmt"
	"runtime"
	"syscall"
)

func bindToDeviceControl(iface string) (func(string, string, syscall.RawConn) error, error) {
	return nil, fmt.Errorf("binding to interface %q is not supported on %s", iface, runtime.GOOS)
}
