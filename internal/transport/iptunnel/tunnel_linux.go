//go:build linux

package iptunnel

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"

	"trustix.local/trustix/internal/transport"
)

func createKernelTunnel(protocol transport.Protocol, name string, cfg tunnelConfig) (string, error) {
	if name == "" {
		generated, err := randomAvailableTunnelName(protocol)
		if err != nil {
			return "", err
		}
		name = generated
	}
	if existing, err := netlink.LinkByName(name); err == nil {
		return "", fmt.Errorf("kernel tunnel %q already exists", existing.Attrs().Name)
	}
	attrs := netlink.LinkAttrs{Name: name, MTU: cfg.MTU}
	if cfg.Queues > 0 {
		attrs.NumTxQueues = cfg.Queues
		attrs.NumRxQueues = cfg.Queues
	}
	local := net.IP(cfg.LocalUnderlay.AsSlice())
	remote := net.IP(cfg.RemoteUnderlay.AsSlice())
	switch protocol {
	case transport.ProtocolGRE:
		if err := netlink.LinkAdd(&netlink.Gretun{
			LinkAttrs: attrs,
			Local:     local,
			Remote:    remote,
			PMtuDisc:  1,
		}); err != nil {
			return "", fmt.Errorf("create GRE tunnel %q: %w", name, err)
		}
	case transport.ProtocolIPIP:
		if err := netlink.LinkAdd(&netlink.Iptun{
			LinkAttrs: attrs,
			Local:     local,
			Remote:    remote,
			PMtuDisc:  1,
		}); err != nil {
			return "", fmt.Errorf("create IPIP tunnel %q: %w", name, err)
		}
	case transport.ProtocolVXLAN:
		vxlan := &netlink.Vxlan{
			LinkAttrs: attrs,
			VxlanId:   effectiveVXLANVNI(cfg.VNI),
			SrcAddr:   local,
			Group:     remote,
			Port:      int(effectiveVXLANPort(cfg.VXLANPort)),
			PortLow:   int(cfg.VXLANPortLow),
			PortHigh:  int(cfg.VXLANPortHigh),
			Learning:  false,
			UDPCSum:   cfg.VXLANUDPCSum,
		}
		if cfg.UnderlayIf != "" {
			link, err := netlink.LinkByName(cfg.UnderlayIf)
			if err != nil {
				return "", fmt.Errorf("resolve VXLAN underlay interface %q: %w", cfg.UnderlayIf, err)
			}
			vxlan.VtepDevIndex = link.Attrs().Index
		}
		if err := netlink.LinkAdd(vxlan); err != nil {
			return "", fmt.Errorf("create VXLAN tunnel %q: %w", name, err)
		}
	default:
		return "", fmt.Errorf("unsupported kernel tunnel protocol %q", protocol)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return "", fmt.Errorf("inspect kernel tunnel %q: %w", name, err)
	}
	addr := &netlink.Addr{IPNet: netipPrefixToIPNet(cfg.LocalCarrier)}
	if err := netlink.AddrReplace(link, addr); err != nil {
		_ = netlink.LinkDel(link)
		return "", fmt.Errorf("configure carrier address %s on %q: %w", cfg.LocalCarrier, name, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		_ = netlink.LinkDel(link)
		return "", fmt.Errorf("set tunnel %q up: %w", name, err)
	}
	return name, nil
}

func CreateKernelTunnel(protocol transport.Protocol, name string, cfg TunnelConfig) (string, error) {
	return createKernelTunnel(protocol, name, cfg)
}

func randomAvailableTunnelName(protocol transport.Protocol) (string, error) {
	prefix := tunnelNamePrefix(string(protocol))
	var lastErr error
	for i := 0; i < 16; i++ {
		name, err := randomTunnelName(prefix)
		if err != nil {
			return "", fmt.Errorf("generate %s tunnel name: %w", protocol, err)
		}
		if _, err := netlink.LinkByName(name); err != nil {
			return name, nil
		}
		lastErr = fmt.Errorf("kernel tunnel %q already exists", name)
	}
	return "", fmt.Errorf("generate %s tunnel name: exhausted collision retries: %w", protocol, lastErr)
}

func deleteKernelTunnel(name string) error {
	if name == "" {
		return nil
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil
	}
	return netlink.LinkDel(link)
}

func kernelTunnelExists(name string) bool {
	if name == "" {
		return false
	}
	_, err := netlink.LinkByName(name)
	return err == nil
}

func netipPrefixToIPNet(prefix netip.Prefix) *net.IPNet {
	addr := net.IP(prefix.Addr().AsSlice())
	bits := prefix.Bits()
	if bits < 0 {
		bits = 32
	}
	return &net.IPNet{IP: addr, Mask: net.CIDRMask(bits, 32)}
}
