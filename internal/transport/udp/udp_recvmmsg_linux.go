//go:build linux

package udp

import (
	"encoding/binary"
	"errors"
	"net"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const udpRecvMmsgMaxBatch = 128
const udpRecvMmsgControlSize = 64

type udpRecvMMsgHdr struct {
	hdr unix.Msghdr
	len uint32
}

type udpRecvMmsgScratch struct {
	addrs   []unix.RawSockaddrAny
	iovs    []unix.Iovec
	msgs    []udpRecvMMsgHdr
	arena   []byte
	control []byte
	packet  [][]byte
	from    []udpReceivedPacket
}

var udpRecvMmsgPool = sync.Pool{
	New: func() any {
		return &udpRecvMmsgScratch{
			addrs:  make([]unix.RawSockaddrAny, 0, udpRecvMmsgMaxBatch),
			iovs:   make([]unix.Iovec, 0, udpRecvMmsgMaxBatch),
			msgs:   make([]udpRecvMMsgHdr, 0, udpRecvMmsgMaxBatch),
			packet: make([][]byte, 0, udpRecvMmsgMaxBatch),
			from:   make([]udpReceivedPacket, 0, udpRecvMmsgMaxBatch),
		}
	},
}

func recvUDPBatch(conn *net.UDPConn, max int, packetSize int) ([][]byte, udpBatchReceiveResult, func(), error) {
	if max <= 0 {
		max = 1
	}
	if max > udpRecvMmsgMaxBatch {
		max = udpRecvMmsgMaxBatch
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		packets, result, release, loopErr := readUDPBatchLoop(conn, max, packetSize)
		result.fallbacks++
		return packets, result, release, loopErr
	}
	scratch := takeUDPRecvMmsgScratch(max, packetSize)
	packets, result, err := recvUDPBatchMmsg(raw, scratch, max, packetSize, false)
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			putUDPRecvMmsgScratch(scratch)
			result.fallbacks++
			packets, loopResult, release, loopErr := readUDPBatchLoop(conn, max, packetSize)
			loopResult.fallbacks += result.fallbacks
			return packets, loopResult, release, loopErr
		}
		putUDPRecvMmsgScratch(scratch)
		return nil, result, nil, err
	}
	return packets, result, func() { putUDPRecvMmsgScratch(scratch) }, nil
}

func recvUDPBatchFrom(conn *net.UDPConn, max int, packetSize int) ([]udpReceivedPacket, udpBatchReceiveResult, func(), error) {
	if max <= 0 {
		max = 1
	}
	if max > udpRecvMmsgMaxBatch {
		max = udpRecvMmsgMaxBatch
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		packets, result, release, loopErr := readUDPBatchFromLoop(conn, max, packetSize)
		result.fallbacks++
		return packets, result, release, loopErr
	}
	scratch := takeUDPRecvMmsgScratch(max, packetSize)
	packets, result, err := recvUDPBatchFromMmsg(raw, scratch, max, packetSize)
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			putUDPRecvMmsgScratch(scratch)
			result.fallbacks++
			packets, loopResult, release, loopErr := readUDPBatchFromLoop(conn, max, packetSize)
			loopResult.fallbacks += result.fallbacks
			return packets, loopResult, release, loopErr
		}
		putUDPRecvMmsgScratch(scratch)
		return nil, result, nil, err
	}
	return packets, result, func() { putUDPRecvMmsgScratch(scratch) }, nil
}

func recvUDPBatchMmsg(raw syscall.RawConn, scratch *udpRecvMmsgScratch, max int, packetSize int, from bool) ([][]byte, udpBatchReceiveResult, error) {
	n, result, err := recvUDPMmsgChunk(raw, scratch, max, packetSize, from)
	if err != nil {
		return nil, result, err
	}
	packets := scratch.packet[:0]
	for i := 0; i < n; i++ {
		size := int(scratch.msgs[i].len)
		base := i * packetSize
		payload := scratch.arena[base : base+size]
		segmentSize, cmsgErr, cmsgTruncated := udpGROSegmentSizeFromControl(scratch.msgs[i].hdr, scratch.controlForMessage(i))
		if cmsgErr {
			result.groCmsgErrors++
		}
		if cmsgTruncated {
			result.groCmsgTruncations++
		}
		var segments int
		packets, segments = appendUDPGROPayloadSegments(packets, payload, segmentSize)
		if segments > 1 {
			result.groPackets++
			result.groSegments += uint64(segments)
			result.groBytes += uint64(size)
		}
		result.bytesReceived += uint64(size)
	}
	scratch.packet = packets
	return packets, result, nil
}

func recvUDPBatchFromMmsg(raw syscall.RawConn, scratch *udpRecvMmsgScratch, max int, packetSize int) ([]udpReceivedPacket, udpBatchReceiveResult, error) {
	n, result, err := recvUDPMmsgChunk(raw, scratch, max, packetSize, true)
	if err != nil {
		return nil, result, err
	}
	packets := scratch.from[:0]
	for i := 0; i < n; i++ {
		size := int(scratch.msgs[i].len)
		base := i * packetSize
		addr := udpAddrFromRawSockaddrAny(&scratch.addrs[i])
		payload := scratch.arena[base : base+size]
		segmentSize, cmsgErr, cmsgTruncated := udpGROSegmentSizeFromControl(scratch.msgs[i].hdr, scratch.controlForMessage(i))
		if cmsgErr {
			result.groCmsgErrors++
		}
		if cmsgTruncated {
			result.groCmsgTruncations++
		}
		var segments int
		packets, segments = appendUDPReceivedGROPayloadSegments(packets, payload, segmentSize, addr)
		if segments > 1 {
			result.groPackets++
			result.groSegments += uint64(segments)
			result.groBytes += uint64(size)
		}
		result.bytesReceived += uint64(size)
	}
	scratch.from = packets
	return packets, result, nil
}

func recvUDPMmsgChunk(raw syscall.RawConn, scratch *udpRecvMmsgScratch, max int, packetSize int, from bool) (int, udpBatchReceiveResult, error) {
	if packetSize <= 0 {
		packetSize = userspaceUDPDatagramBatchMax
	}
	addrs := scratch.addrs[:max]
	iovs := scratch.iovs[:max]
	msgs := scratch.msgs[:max]
	for i := 0; i < max; i++ {
		base := i * packetSize
		buf := scratch.arena[base : base+packetSize]
		msgs[i] = udpRecvMMsgHdr{}
		iovs[i].Base = &buf[0]
		iovs[i].SetLen(len(buf))
		msgs[i].hdr.Iov = &iovs[i]
		msgs[i].hdr.Iovlen = 1
		control := scratch.controlForMessage(i)
		msgs[i].hdr.Control = &control[0]
		msgs[i].hdr.SetControllen(len(control))
		if from {
			msgs[i].hdr.Name = (*byte)(unsafe.Pointer(&addrs[i]))
			msgs[i].hdr.Namelen = uint32(unsafe.Sizeof(addrs[i]))
		}
	}
	n, err := recvUDPMmsgRaw(raw, msgs)
	runtime.KeepAlive(scratch.arena)
	runtime.KeepAlive(scratch.control)
	result := udpBatchReceiveResult{mmsgSyscalls: 1}
	if err != nil {
		return n, result, err
	}
	if n <= 0 {
		return n, result, unix.EIO
	}
	return n, result, nil
}

func takeUDPRecvMmsgScratch(size int, packetSize int) *udpRecvMmsgScratch {
	if size <= 0 {
		size = 1
	}
	if packetSize <= 0 {
		packetSize = userspaceUDPDatagramBatchMax
	}
	scratch := udpRecvMmsgPool.Get().(*udpRecvMmsgScratch)
	neededBytes := size * packetSize
	if cap(scratch.arena) < neededBytes {
		scratch.arena = make([]byte, neededBytes)
	} else {
		scratch.arena = scratch.arena[:neededBytes]
	}
	neededControlBytes := size * udpRecvMmsgControlSize
	if cap(scratch.control) < neededControlBytes {
		scratch.control = make([]byte, neededControlBytes)
	} else {
		scratch.control = scratch.control[:neededControlBytes]
	}
	if cap(scratch.addrs) < size {
		scratch.addrs = make([]unix.RawSockaddrAny, size)
	} else {
		scratch.addrs = scratch.addrs[:size]
	}
	if cap(scratch.iovs) < size {
		scratch.iovs = make([]unix.Iovec, size)
	} else {
		scratch.iovs = scratch.iovs[:size]
	}
	if cap(scratch.msgs) < size {
		scratch.msgs = make([]udpRecvMMsgHdr, size)
	} else {
		scratch.msgs = scratch.msgs[:size]
	}
	if cap(scratch.packet) < size {
		scratch.packet = make([][]byte, 0, size)
	} else {
		scratch.packet = scratch.packet[:0]
	}
	if cap(scratch.from) < size {
		scratch.from = make([]udpReceivedPacket, 0, size)
	} else {
		scratch.from = scratch.from[:0]
	}
	return scratch
}

func putUDPRecvMmsgScratch(scratch *udpRecvMmsgScratch) {
	if scratch == nil {
		return
	}
	clear(scratch.packet)
	clear(scratch.from)
	if cap(scratch.arena) > userspaceUDPSessionMaxPacket*udpRecvMmsgMaxBatch {
		return
	}
	scratch.addrs = scratch.addrs[:0]
	scratch.iovs = scratch.iovs[:0]
	scratch.msgs = scratch.msgs[:0]
	scratch.control = scratch.control[:0]
	scratch.packet = scratch.packet[:0]
	scratch.from = scratch.from[:0]
	udpRecvMmsgPool.Put(scratch)
}

func (scratch *udpRecvMmsgScratch) controlForMessage(index int) []byte {
	base := index * udpRecvMmsgControlSize
	return scratch.control[base : base+udpRecvMmsgControlSize]
}

func udpGROSegmentSizeFromControl(msg unix.Msghdr, control []byte) (int, bool, bool) {
	if msg.Flags&unix.MSG_CTRUNC != 0 {
		return 0, false, true
	}
	n := int(msg.Controllen)
	if n <= 0 {
		return 0, false, false
	}
	if n > len(control) {
		n = len(control)
	}
	cmsgs, err := unix.ParseSocketControlMessage(control[:n])
	if err != nil {
		return 0, true, false
	}
	for _, cmsg := range cmsgs {
		if cmsg.Header.Level != unix.SOL_UDP || cmsg.Header.Type != unix.UDP_GRO {
			continue
		}
		if len(cmsg.Data) < 2 {
			return 0, true, false
		}
		segmentSize := int(binary.NativeEndian.Uint16(cmsg.Data[:2]))
		if segmentSize > 0 {
			return segmentSize, false, false
		}
	}
	return 0, false, false
}

func appendUDPReceivedGROPayloadSegments(dst []udpReceivedPacket, payload []byte, segmentSize int, addr *net.UDPAddr) ([]udpReceivedPacket, int) {
	segments := udpGROSegmentCount(len(payload), segmentSize)
	if segments <= 1 {
		return append(dst, udpReceivedPacket{payload: payload, addr: addr}), 1
	}
	for offset := 0; offset < len(payload); offset += segmentSize {
		end := offset + segmentSize
		if end > len(payload) {
			end = len(payload)
		}
		dst = append(dst, udpReceivedPacket{payload: payload[offset:end], addr: addr})
	}
	return dst, segments
}

func recvUDPMmsgRaw(raw syscall.RawConn, msgs []udpRecvMMsgHdr) (int, error) {
	var received int
	var opErr error
	err := raw.Read(func(fd uintptr) bool {
		received, opErr = udpRecvmmsg(int(fd), msgs)
		return !errors.Is(opErr, unix.EAGAIN) && !errors.Is(opErr, unix.EWOULDBLOCK)
	})
	if err != nil {
		return received, err
	}
	return received, opErr
}

func udpRecvmmsg(fd int, msgs []udpRecvMMsgHdr) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	n, _, errno := unix.Syscall6(
		unix.SYS_RECVMMSG,
		uintptr(fd),
		uintptr(unsafe.Pointer(&msgs[0])),
		uintptr(len(msgs)),
		unix.MSG_DONTWAIT,
		0,
		0,
	)
	if errno != 0 {
		return int(n), errno
	}
	return int(n), nil
}

func udpAddrFromRawSockaddrAny(raw *unix.RawSockaddrAny) *net.UDPAddr {
	if raw == nil {
		return nil
	}
	switch raw.Addr.Family {
	case unix.AF_INET:
		return udpAddrFromRawSockaddrInet4((*unix.RawSockaddrInet4)(unsafe.Pointer(raw)))
	case unix.AF_INET6:
		return udpAddrFromRawSockaddrInet6((*unix.RawSockaddrInet6)(unsafe.Pointer(raw)))
	default:
		return nil
	}
}

func udpAddrFromRawSockaddrInet4(raw *unix.RawSockaddrInet4) *net.UDPAddr {
	if raw == nil || raw.Family != unix.AF_INET {
		return nil
	}
	ip := net.IPv4(raw.Addr[0], raw.Addr[1], raw.Addr[2], raw.Addr[3])
	return &net.UDPAddr{IP: ip, Port: int(udpNTOHS(raw.Port))}
}

func udpAddrFromRawSockaddrInet6(raw *unix.RawSockaddrInet6) *net.UDPAddr {
	if raw == nil || raw.Family != unix.AF_INET6 {
		return nil
	}
	ip := net.IP(raw.Addr[:]).To16()
	if ip == nil {
		return nil
	}
	if mapped := ip.To4(); mapped != nil {
		ip = net.IPv4(mapped[0], mapped[1], mapped[2], mapped[3])
	} else {
		ip = append(net.IP(nil), ip...)
	}
	return &net.UDPAddr{IP: ip, Port: int(udpNTOHS(raw.Port)), Zone: udpIPv6Zone(raw.Scope_id)}
}

func udpIPv6Zone(scopeID uint32) string {
	if scopeID == 0 {
		return ""
	}
	if iface, err := net.InterfaceByIndex(int(scopeID)); err == nil {
		return iface.Name
	}
	return strconv.FormatUint(uint64(scopeID), 10)
}

func udpNTOHS(value uint16) uint16 {
	return (value << 8) | (value >> 8)
}
