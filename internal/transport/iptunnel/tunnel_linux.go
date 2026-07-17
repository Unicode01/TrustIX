//go:build linux

package iptunnel

import (
	"errors"
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
	} else if !kernelTunnelLinkNotFound(err) {
		return "", fmt.Errorf("inspect requested kernel tunnel name %q: %w", name, err)
	}
	attrs := netlink.LinkAttrs{Name: name, MTU: cfg.MTU}
	if cfg.Queues > 0 {
		attrs.NumTxQueues = cfg.Queues
		attrs.NumRxQueues = cfg.Queues
	}
	local := net.IP(cfg.LocalUnderlay.AsSlice())
	remote := net.IP(cfg.RemoteUnderlay.AsSlice())
	var created netlink.Link
	switch protocol {
	case transport.ProtocolGRE:
		created = &netlink.Gretun{
			LinkAttrs: attrs,
			Local:     local,
			Remote:    remote,
			PMtuDisc:  1,
		}
	case transport.ProtocolIPIP:
		created = &netlink.Iptun{
			LinkAttrs: attrs,
			Local:     local,
			Remote:    remote,
			PMtuDisc:  1,
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
		created = vxlan
	default:
		return "", fmt.Errorf("unsupported kernel tunnel protocol %q", protocol)
	}
	if err := netlink.LinkAdd(created); err != nil {
		return "", fmt.Errorf("create %s tunnel %q: %w", protocol, name, err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return "", errors.Join(
			fmt.Errorf("inspect kernel tunnel %q: %w", name, err),
			deleteKernelTunnelLink(created),
		)
	}
	addr := &netlink.Addr{IPNet: netipPrefixToIPNet(cfg.LocalCarrier)}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return "", errors.Join(
			fmt.Errorf("configure carrier address %s on %q: %w", cfg.LocalCarrier, name, err),
			deleteKernelTunnelLink(link),
		)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return "", errors.Join(
			fmt.Errorf("set tunnel %q up: %w", name, err),
			deleteKernelTunnelLink(link),
		)
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
		if _, err := netlink.LinkByName(name); kernelTunnelLinkNotFound(err) {
			return name, nil
		} else if err != nil {
			return "", fmt.Errorf("inspect generated %s tunnel name %q: %w", protocol, name, err)
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
		if kernelTunnelLinkNotFound(err) {
			return nil
		}
		return fmt.Errorf("inspect kernel tunnel %q for delete: %w", name, err)
	}
	return deleteKernelTunnelLink(link)
}

func deleteKernelTunnelLink(link netlink.Link) error {
	if link == nil {
		return nil
	}
	if err := netlink.LinkDel(link); err != nil && !kernelTunnelLinkNotFound(err) {
		return fmt.Errorf("delete kernel tunnel %q: %w", link.Attrs().Name, err)
	}
	return nil
}

func kernelTunnelLinkNotFound(err error) bool {
	if err == nil {
		return false
	}
	var notFound netlink.LinkNotFoundError
	return errors.As(err, &notFound)
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
