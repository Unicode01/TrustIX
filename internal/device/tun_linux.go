//go:build linux

package device

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	tunDevice    = "/dev/net/tun"
	tunIFReqSize = unix.IFNAMSIZ + 64
)

type tunInterface struct {
	file *os.File
	name string
	mtu  int
}

func OpenInterface(cfg InterfaceConfig) (Interface, error) {
	if cfg.Name == "" {
		cfg.Name = "trustix0"
	}
	if cfg.MTU <= 0 {
		cfg.MTU = defaultMTU
	}
	fd, err := unix.Open(tunDevice, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", tunDevice, err)
	}
	var ifr [tunIFReqSize]byte
	copy(ifr[:unix.IFNAMSIZ], []byte(cfg.Name))
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = unix.IFF_TUN | unix.IFF_NO_PI
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("create tun %q: %w", cfg.Name, errno)
	}
	file := os.NewFile(uintptr(fd), cfg.Name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("create tun file for %q", cfg.Name)
	}
	iface := &tunInterface{file: file, name: cfg.Name, mtu: cfg.MTU}
	if err := iface.configureLink(cfg.MTU); err != nil {
		_ = file.Close()
		return nil, err
	}
	return iface, nil
}

func (iface *tunInterface) Name() string {
	return iface.name
}

func (iface *tunInterface) MTU() int {
	return iface.mtu
}

func (iface *tunInterface) ReadPacket(packet []byte) (int, error) {
	return iface.file.Read(packet)
}

func (iface *tunInterface) WritePacket(packet []byte) (int, error) {
	return iface.file.Write(packet)
}

func (iface *tunInterface) Configure(lease Lease, routes []netip.Prefix) error {
	link, err := netlink.LinkByName(iface.name)
	if err != nil {
		return fmt.Errorf("lookup link %q: %w", iface.name, err)
	}
	if lease.Prefix.IsValid() && lease.Prefix.Addr().Is4() {
		addr, err := netlink.ParseAddr(lease.Prefix.String())
		if err != nil {
			return fmt.Errorf("parse lease address %q: %w", lease.Prefix, err)
		}
		if err := netlink.AddrReplace(link, addr); err != nil {
			return fmt.Errorf("set %s address %s: %w", iface.name, lease.Prefix, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("set %s up: %w", iface.name, err)
	}
	for _, prefix := range routes {
		if !prefix.IsValid() || !prefix.Addr().Is4() {
			continue
		}
		dst := ipNetFromPrefix(prefix)
		if dst == nil {
			continue
		}
		route := netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       dst,
		}
		if err := netlink.RouteReplace(&route); err != nil {
			return fmt.Errorf("replace route %s dev %s: %w", prefix, iface.name, err)
		}
	}
	return nil
}

func (iface *tunInterface) Close() error {
	if iface.file == nil {
		return nil
	}
	return iface.file.Close()
}

func (iface *tunInterface) configureLink(mtu int) error {
	link, err := netlink.LinkByName(iface.name)
	if err != nil {
		return fmt.Errorf("lookup link %q: %w", iface.name, err)
	}
	if mtu > 0 {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			return fmt.Errorf("set %s mtu %d: %w", iface.name, mtu, err)
		}
		iface.mtu = mtu
	}
	return netlink.LinkSetUp(link)
}

func ipNetFromPrefix(prefix netip.Prefix) *net.IPNet {
	if !prefix.IsValid() {
		return nil
	}
	var ip net.IP
	bits := 128
	if prefix.Addr().Is4() {
		raw := prefix.Addr().As4()
		ip = net.IPv4(raw[0], raw[1], raw[2], raw[3]).To4()
		bits = 32
	} else {
		raw := prefix.Addr().As16()
		ip = append(net.IP(nil), raw[:]...)
	}
	return &net.IPNet{
		IP:   ip.Mask(net.CIDRMask(prefix.Bits(), bits)),
		Mask: net.CIDRMask(prefix.Bits(), bits),
	}
}
