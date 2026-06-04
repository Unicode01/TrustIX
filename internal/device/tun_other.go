//go:build !linux

package device

import "fmt"

func OpenInterface(cfg InterfaceConfig) (Interface, error) {
	return nil, fmt.Errorf("trustix-device TUN interface is only implemented on Linux")
}
