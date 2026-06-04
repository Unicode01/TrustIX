//go:build linux

package udp

import (
	"encoding/binary"
	"net"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestUDPGROSegmentSizeFromControl(t *testing.T) {
	control := make([]byte, unix.CmsgSpace(2))
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
	hdr.Level = unix.SOL_UDP
	hdr.Type = unix.UDP_GRO
	hdr.SetLen(unix.CmsgLen(2))
	data := control[unix.CmsgLen(0):unix.CmsgLen(2)]
	binary.NativeEndian.PutUint16(data, 1400)

	msg := unix.Msghdr{}
	msg.SetControllen(len(control))
	segmentSize, cmsgErr, truncated := udpGROSegmentSizeFromControl(msg, control)
	if cmsgErr || truncated {
		t.Fatalf("unexpected parse flags: err=%t truncated=%t", cmsgErr, truncated)
	}
	if segmentSize != 1400 {
		t.Fatalf("segment size = %d, want 1400", segmentSize)
	}
}

func TestUDPGROSegmentSizeFromControlTruncated(t *testing.T) {
	msg := unix.Msghdr{Flags: unix.MSG_CTRUNC}
	segmentSize, cmsgErr, truncated := udpGROSegmentSizeFromControl(msg, nil)
	if segmentSize != 0 || cmsgErr || !truncated {
		t.Fatalf("segment=%d err=%t truncated=%t, want 0/false/true", segmentSize, cmsgErr, truncated)
	}
}

func TestUDPAddrFromRawSockaddrAny(t *testing.T) {
	ipv4 := unix.RawSockaddrInet4{
		Family: unix.AF_INET,
		Port:   udpHTONS(7001),
		Addr:   [4]byte{203, 0, 113, 9},
	}
	got := udpAddrFromRawSockaddrAny((*unix.RawSockaddrAny)(unsafe.Pointer(&ipv4)))
	if got == nil || got.Port != 7001 || !got.IP.Equal(net.IPv4(203, 0, 113, 9)) {
		t.Fatalf("ipv4 addr = %#v", got)
	}

	ipv6 := unix.RawSockaddrInet6{
		Family: unix.AF_INET6,
		Port:   udpHTONS(7002),
		Addr:   [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
	}
	got = udpAddrFromRawSockaddrAny((*unix.RawSockaddrAny)(unsafe.Pointer(&ipv6)))
	if got == nil || got.Port != 7002 || !got.IP.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("ipv6 addr = %#v", got)
	}

	mapped := unix.RawSockaddrInet6{
		Family: unix.AF_INET6,
		Port:   udpHTONS(7003),
		Addr:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 198, 51, 100, 7},
	}
	got = udpAddrFromRawSockaddrAny((*unix.RawSockaddrAny)(unsafe.Pointer(&mapped)))
	if got == nil || got.Port != 7003 || !got.IP.Equal(net.IPv4(198, 51, 100, 7)) {
		t.Fatalf("mapped ipv6 addr = %#v", got)
	}
}
