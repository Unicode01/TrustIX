//go:build linux

package ebpf

import (
	"net"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

type mmsghdr struct {
	hdr unix.Msghdr
	len uint32
}

type lanSendMMSGScratch struct {
	addrs []unix.RawSockaddrLinklayer
	iovs  []unix.Iovec
	msgs  []mmsghdr
}

type lanGSOSendMMSGScratch struct {
	addrs     []unix.RawSockaddrLinklayer
	headers   []byte
	ethernets []byte
	ipHeaders []byte
	iovs      []unix.Iovec
	msgs      []mmsghdr
}

type rawIPv4SendMMSGScratch struct {
	addrs []unix.RawSockaddrInet4
	iovs  []unix.Iovec
	msgs  []mmsghdr
}

type rawIPv4PacketBatchScratch struct {
	packets [][]byte
	arena   []byte
}

type lanSegmentBatchScratch struct {
	segments [][]byte
}

var lanSendMMSGPool = sync.Pool{
	New: func() any {
		return &lanSendMMSGScratch{
			addrs: make([]unix.RawSockaddrLinklayer, 0, 256),
			iovs:  make([]unix.Iovec, 0, 256),
			msgs:  make([]mmsghdr, 0, 256),
		}
	},
}

var lanGSOSendMMSGPool = sync.Pool{
	New: func() any {
		return &lanGSOSendMMSGScratch{
			addrs:     make([]unix.RawSockaddrLinklayer, 0, 256),
			headers:   make([]byte, 0, 256*virtioNetHdrLen),
			ethernets: make([]byte, 0, 256*ethernetHeaderLen),
			ipHeaders: make([]byte, 0, 256*(rejectIPv4HeaderLen+rejectTCPHeaderLen)),
			iovs:      make([]unix.Iovec, 0, 256*3),
			msgs:      make([]mmsghdr, 0, 256),
		}
	},
}

var rawIPv4SendMMSGPool = sync.Pool{
	New: func() any {
		return &rawIPv4SendMMSGScratch{
			addrs: make([]unix.RawSockaddrInet4, 0, 256),
			iovs:  make([]unix.Iovec, 0, 256),
			msgs:  make([]mmsghdr, 0, 256),
		}
	},
}

var rawIPv4PacketBatchPool = sync.Pool{
	New: func() any {
		return &rawIPv4PacketBatchScratch{
			packets: make([][]byte, 0, 256),
			arena:   make([]byte, 0, 256*1500),
		}
	},
}

var lanSegmentBatchPool = sync.Pool{
	New: func() any {
		return &lanSegmentBatchScratch{
			segments: make([][]byte, 0, 512),
		}
	},
}

func takeLANSendMMSGScratch(size int) *lanSendMMSGScratch {
	scratch := lanSendMMSGPool.Get().(*lanSendMMSGScratch)
	if cap(scratch.addrs) < size {
		scratch.addrs = make([]unix.RawSockaddrLinklayer, size)
	} else {
		scratch.addrs = scratch.addrs[:size]
	}
	if cap(scratch.iovs) < size {
		scratch.iovs = make([]unix.Iovec, size)
	} else {
		scratch.iovs = scratch.iovs[:size]
	}
	if cap(scratch.msgs) < size {
		scratch.msgs = make([]mmsghdr, size)
	} else {
		scratch.msgs = scratch.msgs[:size]
	}
	return scratch
}

func putLANSendMMSGScratch(scratch *lanSendMMSGScratch) {
	if scratch == nil {
		return
	}
	if cap(scratch.msgs) > 4096 {
		return
	}
	scratch.addrs = scratch.addrs[:0]
	scratch.iovs = scratch.iovs[:0]
	scratch.msgs = scratch.msgs[:0]
	lanSendMMSGPool.Put(scratch)
}

func takeLANGSOSendMMSGScratch(size int) *lanGSOSendMMSGScratch {
	scratch := lanGSOSendMMSGPool.Get().(*lanGSOSendMMSGScratch)
	if cap(scratch.addrs) < size {
		scratch.addrs = make([]unix.RawSockaddrLinklayer, size)
	} else {
		scratch.addrs = scratch.addrs[:size]
	}
	headerBytes := size * virtioNetHdrLen
	if cap(scratch.headers) < headerBytes {
		scratch.headers = make([]byte, headerBytes)
	} else {
		scratch.headers = scratch.headers[:headerBytes]
	}
	ethernetBytes := size * ethernetHeaderLen
	if cap(scratch.ethernets) < ethernetBytes {
		scratch.ethernets = make([]byte, ethernetBytes)
	} else {
		scratch.ethernets = scratch.ethernets[:ethernetBytes]
	}
	ipHeaderBytes := size * (rejectIPv4HeaderLen + rejectTCPHeaderLen)
	if cap(scratch.ipHeaders) < ipHeaderBytes {
		scratch.ipHeaders = make([]byte, ipHeaderBytes)
	} else {
		scratch.ipHeaders = scratch.ipHeaders[:ipHeaderBytes]
	}
	iovCount := size * 3
	if cap(scratch.iovs) < iovCount {
		scratch.iovs = make([]unix.Iovec, iovCount)
	} else {
		scratch.iovs = scratch.iovs[:iovCount]
	}
	if cap(scratch.msgs) < size {
		scratch.msgs = make([]mmsghdr, size)
	} else {
		scratch.msgs = scratch.msgs[:size]
	}
	return scratch
}

func putLANGSOSendMMSGScratch(scratch *lanGSOSendMMSGScratch) {
	if scratch == nil {
		return
	}
	if cap(scratch.msgs) > 4096 || cap(scratch.iovs) > 4096*3 {
		return
	}
	scratch.addrs = scratch.addrs[:0]
	scratch.headers = scratch.headers[:0]
	scratch.ethernets = scratch.ethernets[:0]
	scratch.ipHeaders = scratch.ipHeaders[:0]
	scratch.iovs = scratch.iovs[:0]
	scratch.msgs = scratch.msgs[:0]
	lanGSOSendMMSGPool.Put(scratch)
}

func (scratch *lanGSOSendMMSGScratch) virtioHeader(index int) []byte {
	base := index * virtioNetHdrLen
	return scratch.headers[base : base+virtioNetHdrLen]
}

func (scratch *lanGSOSendMMSGScratch) ethernetHeader(index int) []byte {
	base := index * ethernetHeaderLen
	return scratch.ethernets[base : base+ethernetHeaderLen]
}

func (scratch *lanGSOSendMMSGScratch) ipHeader(index int, size int) []byte {
	base := index * (rejectIPv4HeaderLen + rejectTCPHeaderLen)
	return scratch.ipHeaders[base : base+size]
}

func takeRawIPv4SendMMSGScratch(size int) *rawIPv4SendMMSGScratch {
	scratch := rawIPv4SendMMSGPool.Get().(*rawIPv4SendMMSGScratch)
	if cap(scratch.addrs) < size {
		scratch.addrs = make([]unix.RawSockaddrInet4, size)
	} else {
		scratch.addrs = scratch.addrs[:size]
	}
	if cap(scratch.iovs) < size {
		scratch.iovs = make([]unix.Iovec, size)
	} else {
		scratch.iovs = scratch.iovs[:size]
	}
	if cap(scratch.msgs) < size {
		scratch.msgs = make([]mmsghdr, size)
	} else {
		scratch.msgs = scratch.msgs[:size]
	}
	return scratch
}

func putRawIPv4SendMMSGScratch(scratch *rawIPv4SendMMSGScratch) {
	if scratch == nil {
		return
	}
	if cap(scratch.msgs) > 4096 {
		return
	}
	scratch.addrs = scratch.addrs[:0]
	scratch.iovs = scratch.iovs[:0]
	scratch.msgs = scratch.msgs[:0]
	rawIPv4SendMMSGPool.Put(scratch)
}

func takeRawIPv4PacketBatchScratch(packets int, bytes int) *rawIPv4PacketBatchScratch {
	scratch := rawIPv4PacketBatchPool.Get().(*rawIPv4PacketBatchScratch)
	if cap(scratch.packets) < packets {
		scratch.packets = make([][]byte, packets)
	} else {
		scratch.packets = scratch.packets[:packets]
	}
	if cap(scratch.arena) < bytes {
		scratch.arena = make([]byte, bytes)
	} else {
		scratch.arena = scratch.arena[:bytes]
	}
	return scratch
}

func putRawIPv4PacketBatchScratch(scratch *rawIPv4PacketBatchScratch) {
	if scratch == nil {
		return
	}
	if cap(scratch.packets) > 4096 || cap(scratch.arena) > 8*1024*1024 {
		return
	}
	clear(scratch.packets)
	scratch.packets = scratch.packets[:0]
	scratch.arena = scratch.arena[:0]
	rawIPv4PacketBatchPool.Put(scratch)
}

func takeLANSegmentBatchScratch(size int) *lanSegmentBatchScratch {
	scratch := lanSegmentBatchPool.Get().(*lanSegmentBatchScratch)
	if cap(scratch.segments) < size {
		scratch.segments = make([][]byte, 0, size)
	} else {
		scratch.segments = scratch.segments[:0]
	}
	return scratch
}

func putLANSegmentBatchScratch(scratch *lanSegmentBatchScratch) {
	if scratch == nil {
		return
	}
	if cap(scratch.segments) > 4096 {
		return
	}
	clear(scratch.segments)
	scratch.segments = scratch.segments[:0]
	lanSegmentBatchPool.Put(scratch)
}

func sendLANIPv4PacketBatch(fd int, ifindex int, packets [][]byte, dstMAC net.HardwareAddr) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	scratch := takeLANSendMMSGScratch(len(packets))
	defer putLANSendMMSGScratch(scratch)
	addrs := scratch.addrs
	iovs := scratch.iovs
	msgs := scratch.msgs
	for i, packet := range packets {
		resetSendMMSGNoControl(&msgs[i])
		addrs[i] = rawSockaddrLinklayer(ifindex, dstMAC)
		iovs[i].Base = &packet[0]
		iovs[i].SetLen(len(packet))
		msgs[i].hdr.Name = (*byte)(unsafe.Pointer(&addrs[i]))
		msgs[i].hdr.Namelen = unix.SizeofSockaddrLinklayer
		msgs[i].hdr.Iov = &iovs[i]
		msgs[i].hdr.Iovlen = 1
	}
	var sent int
	for sent < len(msgs) {
		n, err := sendmmsg(fd, msgs[sent:])
		if n > 0 {
			sent += n
		}
		if err != nil {
			if n > 0 {
				continue
			}
			return sent, err
		}
		if n <= 0 {
			return sent, unix.EIO
		}
	}
	return sent, nil
}

func rawSockaddrLinklayer(ifindex int, dstMAC net.HardwareAddr) unix.RawSockaddrLinklayer {
	var addr unix.RawSockaddrLinklayer
	addr.Family = unix.AF_PACKET
	addr.Protocol = htons(etherTypeIPv4)
	addr.Ifindex = int32(ifindex)
	addr.Halen = uint8(len(dstMAC))
	copy(addr.Addr[:], dstMAC)
	return addr
}

func resetSendMMSGNoControl(msg *mmsghdr) {
	msg.len = 0
	msg.hdr.Control = nil
	msg.hdr.SetControllen(0)
	msg.hdr.Flags = 0
}

func sendmmsg(fd int, msgs []mmsghdr) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	n, _, errno := unix.Syscall6(
		unix.SYS_SENDMMSG,
		uintptr(fd),
		uintptr(unsafe.Pointer(&msgs[0])),
		uintptr(len(msgs)),
		0,
		0,
		0,
	)
	if errno != 0 {
		return int(n), errno
	}
	return int(n), nil
}

func sendmsgRaw(fd int, addr *unix.RawSockaddrLinklayer, iovs []unix.Iovec) (int, error) {
	if addr == nil || len(iovs) == 0 {
		return 0, unix.EINVAL
	}
	msg := unix.Msghdr{
		Name:    (*byte)(unsafe.Pointer(addr)),
		Namelen: unix.SizeofSockaddrLinklayer,
		Iov:     &iovs[0],
	}
	msg.SetIovlen(len(iovs))
	n, _, errno := unix.Syscall6(
		unix.SYS_SENDMSG,
		uintptr(fd),
		uintptr(unsafe.Pointer(&msg)),
		0,
		0,
		0,
		0,
	)
	if errno != 0 {
		return int(n), errno
	}
	return int(n), nil
}

func recvmmsg(fd int, msgs []mmsghdr, flags int) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	n, _, errno := unix.Syscall6(
		unix.SYS_RECVMMSG,
		uintptr(fd),
		uintptr(unsafe.Pointer(&msgs[0])),
		uintptr(len(msgs)),
		uintptr(flags),
		0,
		0,
	)
	if errno != 0 {
		return int(n), errno
	}
	return int(n), nil
}
