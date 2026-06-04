//go:build !linux

package iptunnel

import (
	"fmt"

	"trustix.local/trustix/internal/transport"
)

func createKernelTunnel(protocol transport.Protocol, name string, cfg tunnelConfig) (string, error) {
	return "", fmt.Errorf("%s kernel tunnel carrier requires Linux netlink", protocol)
}

func CreateKernelTunnel(protocol transport.Protocol, name string, cfg TunnelConfig) (string, error) {
	return createKernelTunnel(protocol, name, cfg)
}

func deleteKernelTunnel(name string) error {
	return nil
}

func kernelTunnelExists(name string) bool {
	return name != ""
}
