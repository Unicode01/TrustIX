package bind

import (
	"syscall"
)

func bindToDeviceControl(iface string) (func(string, string, syscall.RawConn) error, error) {
	return func(_ string, _ string, conn syscall.RawConn) error {
		var sockErr error
		if err := conn.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
		}); err != nil {
			return err
		}
		return sockErr
	}, nil
}
