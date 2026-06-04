//go:build linux

package iptunnel

import (
	"errors"
	"net"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const carrierRecvMmsgMaxBatch = 128

type carrierRecvMMsgHdr struct {
	hdr unix.Msghdr
	len uint32
}

type carrierRecvMmsgScratch struct {
	addrs   []unix.RawSockaddrInet4
	iovs    []unix.Iovec
	msgs    []carrierRecvMMsgHdr
	buffers [][]byte
	packet  [][]byte
	from    []carrierReceivedPacket
}

var carrierRecvMmsgPool = sync.Pool{
	New: func() any {
		return &carrierRecvMmsgScratch{
			addrs:   make([]unix.RawSockaddrInet4, 0, carrierRecvMmsgMaxBatch),
			iovs:    make([]unix.Iovec, 0, carrierRecvMmsgMaxBatch),
			msgs:    make([]carrierRecvMMsgHdr, 0, carrierRecvMmsgMaxBatch),
			buffers: make([][]byte, 0, carrierRecvMmsgMaxBatch),
			packet:  make([][]byte, 0, carrierRecvMmsgMaxBatch),
			from:    make([]carrierReceivedPacket, 0, carrierRecvMmsgMaxBatch),
		}
	},
}

func recvCarrierBatch(conn *net.UDPConn, max int, packetSize int) ([][]byte, carrierBatchReceiveResult, func(), error) {
	if max <= 0 {
		max = 1
	}
	if max > carrierRecvMmsgMaxBatch {
		max = carrierRecvMmsgMaxBatch
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		packets, result, release, loopErr := readCarrierBatchLoop(conn, max, packetSize)
		result.fallbacks++
		return packets, result, release, loopErr
	}
	scratch := takeCarrierRecvMmsgScratch(max, packetSize)
	packets, result, err := recvCarrierBatchMmsg(raw, scratch, max, false)
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			putCarrierRecvMmsgScratch(scratch, true)
			result.fallbacks++
			packets, loopResult, release, loopErr := readCarrierBatchLoop(conn, max, packetSize)
			loopResult.fallbacks += result.fallbacks
			return packets, loopResult, release, loopErr
		}
		putCarrierRecvMmsgScratch(scratch, true)
		return nil, result, nil, err
	}
	return packets, result, func() { putCarrierRecvMmsgScratch(scratch, true) }, nil
}

func recvCarrierBatchFrom(conn *net.UDPConn, max int, packetSize int) ([]carrierReceivedPacket, carrierBatchReceiveResult, func(), error) {
	if max <= 0 {
		max = 1
	}
	if max > carrierRecvMmsgMaxBatch {
		max = carrierRecvMmsgMaxBatch
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		packets, result, release, loopErr := readCarrierBatchFromLoop(conn, max, packetSize)
		result.fallbacks++
		return packets, result, release, loopErr
	}
	scratch := takeCarrierRecvMmsgScratch(max, packetSize)
	packets, result, err := recvCarrierBatchFromMmsg(raw, scratch, max)
	if err != nil {
		putCarrierRecvMmsgScratch(scratch, true)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			result.fallbacks++
			packets, loopResult, release, loopErr := readCarrierBatchFromLoop(conn, max, packetSize)
			loopResult.fallbacks += result.fallbacks
			return packets, loopResult, release, loopErr
		}
		return nil, result, nil, err
	}
	return packets, result, func() { putCarrierRecvMmsgScratch(scratch, false) }, nil
}

func recvCarrierBatchMmsg(raw syscall.RawConn, scratch *carrierRecvMmsgScratch, max int, from bool) ([][]byte, carrierBatchReceiveResult, error) {
	n, result, err := recvCarrierMmsgChunk(raw, scratch, max, from)
	if err != nil {
		return nil, result, err
	}
	releaseUnusedCarrierRecvBuffers(scratch, n)
	packets := scratch.packet[:0]
	for i := 0; i < n; i++ {
		size := int(scratch.msgs[i].len)
		buffer := scratch.buffers[i]
		payload, _, err := decodeCarrierView(buffer[:size])
		if err != nil {
			putCarrierReadBuffer(buffer)
			scratch.buffers[i] = nil
			continue
		}
		packets = append(packets, payload)
		result.bytesReceived += uint64(size)
	}
	scratch.packet = packets
	if len(packets) == 0 {
		return nil, result, unix.EAGAIN
	}
	return packets, result, nil
}

func recvCarrierBatchFromMmsg(raw syscall.RawConn, scratch *carrierRecvMmsgScratch, max int) ([]carrierReceivedPacket, carrierBatchReceiveResult, error) {
	n, result, err := recvCarrierMmsgChunk(raw, scratch, max, true)
	if err != nil {
		return nil, result, err
	}
	releaseUnusedCarrierRecvBuffers(scratch, n)
	packets := scratch.from[:0]
	for i := 0; i < n; i++ {
		size := int(scratch.msgs[i].len)
		buffer := scratch.buffers[i]
		payload, _, err := decodeCarrierView(buffer[:size])
		if err != nil {
			putCarrierReadBuffer(buffer)
			scratch.buffers[i] = nil
			continue
		}
		addr := carrierAddrFromRawSockaddrInet4(&scratch.addrs[i])
		packets = append(packets, carrierReceivedPacket{payload: payload, wireLen: size, buffer: buffer, addr: addr})
		scratch.buffers[i] = nil
		result.bytesReceived += uint64(size)
	}
	scratch.from = packets
	return packets, result, nil
}

func releaseUnusedCarrierRecvBuffers(scratch *carrierRecvMmsgScratch, received int) {
	if scratch == nil {
		return
	}
	for i := received; i < len(scratch.buffers); i++ {
		if scratch.buffers[i] != nil {
			putCarrierReadBuffer(scratch.buffers[i])
			scratch.buffers[i] = nil
		}
	}
}

func recvCarrierMmsgChunk(raw syscall.RawConn, scratch *carrierRecvMmsgScratch, max int, from bool) (int, carrierBatchReceiveResult, error) {
	addrs := scratch.addrs[:max]
	iovs := scratch.iovs[:max]
	msgs := scratch.msgs[:max]
	for i := 0; i < max; i++ {
		buffer := scratch.buffers[i]
		msgs[i] = carrierRecvMMsgHdr{}
		iovs[i].Base = &buffer[0]
		iovs[i].SetLen(len(buffer))
		msgs[i].hdr.Iov = &iovs[i]
		msgs[i].hdr.Iovlen = 1
		if from {
			msgs[i].hdr.Name = (*byte)(unsafe.Pointer(&addrs[i]))
			msgs[i].hdr.Namelen = unix.SizeofSockaddrInet4
		}
	}
	n, err := recvCarrierMmsgRaw(raw, msgs)
	runtime.KeepAlive(scratch.buffers)
	result := carrierBatchReceiveResult{mmsgSyscalls: 1}
	if err != nil {
		return n, result, err
	}
	if n <= 0 {
		return n, result, unix.EIO
	}
	return n, result, nil
}

func takeCarrierRecvMmsgScratch(size int, packetSize int) *carrierRecvMmsgScratch {
	if size <= 0 {
		size = 1
	}
	if size > carrierRecvMmsgMaxBatch {
		size = carrierRecvMmsgMaxBatch
	}
	packetSize = carrierReadBufferSize(packetSize)
	scratch := carrierRecvMmsgPool.Get().(*carrierRecvMmsgScratch)
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
		scratch.msgs = make([]carrierRecvMMsgHdr, size)
	} else {
		scratch.msgs = scratch.msgs[:size]
	}
	if cap(scratch.buffers) < size {
		scratch.buffers = make([][]byte, size)
	} else {
		scratch.buffers = scratch.buffers[:size]
	}
	for i := 0; i < size; i++ {
		scratch.buffers[i] = takeCarrierReadBuffer(packetSize)
	}
	if cap(scratch.packet) < size {
		scratch.packet = make([][]byte, 0, size)
	} else {
		scratch.packet = scratch.packet[:0]
	}
	if cap(scratch.from) < size {
		scratch.from = make([]carrierReceivedPacket, 0, size)
	} else {
		scratch.from = scratch.from[:0]
	}
	return scratch
}

func putCarrierRecvMmsgScratch(scratch *carrierRecvMmsgScratch, releaseBuffers bool) {
	if scratch == nil {
		return
	}
	if releaseBuffers {
		for i, buffer := range scratch.buffers {
			if buffer != nil {
				putCarrierReadBuffer(buffer)
				scratch.buffers[i] = nil
			}
		}
	}
	clear(scratch.packet)
	clear(scratch.from)
	scratch.addrs = scratch.addrs[:0]
	scratch.iovs = scratch.iovs[:0]
	scratch.msgs = scratch.msgs[:0]
	scratch.buffers = scratch.buffers[:0]
	scratch.packet = scratch.packet[:0]
	scratch.from = scratch.from[:0]
	carrierRecvMmsgPool.Put(scratch)
}

func recvCarrierMmsgRaw(raw syscall.RawConn, msgs []carrierRecvMMsgHdr) (int, error) {
	var received int
	var opErr error
	err := raw.Read(func(fd uintptr) bool {
		received, opErr = carrierRecvmmsg(int(fd), msgs)
		return !errors.Is(opErr, unix.EAGAIN) && !errors.Is(opErr, unix.EWOULDBLOCK)
	})
	if err != nil {
		return received, err
	}
	return received, opErr
}

func carrierRecvmmsg(fd int, msgs []carrierRecvMMsgHdr) (int, error) {
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

func carrierAddrFromRawSockaddrInet4(raw *unix.RawSockaddrInet4) *net.UDPAddr {
	if raw == nil || raw.Family != unix.AF_INET {
		return nil
	}
	ip := net.IPv4(raw.Addr[0], raw.Addr[1], raw.Addr[2], raw.Addr[3])
	return &net.UDPAddr{IP: ip, Port: int(carrierNTOHS(raw.Port))}
}

func carrierNTOHS(value uint16) uint16 {
	return (value << 8) | (value >> 8)
}
