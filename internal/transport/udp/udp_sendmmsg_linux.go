//go:build linux

package udp

import (
	"errors"
	"net"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const udpSendMmsgMaxBatch = 128

type udpMMsgHdr struct {
	hdr unix.Msghdr
	len uint32
}

type udpSendMmsgScratch struct {
	addrs []unix.RawSockaddrInet4
	iovs  []unix.Iovec
	msgs  []udpMMsgHdr
}

var udpSendMmsgPool = sync.Pool{
	New: func() any {
		return &udpSendMmsgScratch{
			addrs: make([]unix.RawSockaddrInet4, 0, udpSendMmsgMaxBatch),
			iovs:  make([]unix.Iovec, 0, udpSendMmsgMaxBatch),
			msgs:  make([]udpMMsgHdr, 0, udpSendMmsgMaxBatch),
		}
	},
}

func sendUDPBatch(conn *net.UDPConn, packets [][]byte) (udpBatchSendResult, error) {
	if len(packets) == 0 {
		return udpBatchSendResult{}, nil
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		result, loopErr := writeUDPBatchLoop(conn, packets)
		result.fallbacks++
		return result, loopErr
	}
	return sendUDPBatchMmsg(raw, packets, nil)
}

func sendUDPBatchTo(conn *net.UDPConn, remote *net.UDPAddr, packets [][]byte) (udpBatchSendResult, error) {
	if len(packets) == 0 {
		return udpBatchSendResult{}, nil
	}
	addr, ok := udpRawSockaddrInet4(remote)
	if !ok {
		result, err := writeUDPBatchToLoop(conn, remote, packets)
		result.fallbacks++
		return result, err
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		result, loopErr := writeUDPBatchToLoop(conn, remote, packets)
		result.fallbacks++
		return result, loopErr
	}
	return sendUDPBatchMmsg(raw, packets, &addr)
}

func sendUDPBatchMmsg(raw syscall.RawConn, packets [][]byte, remote *unix.RawSockaddrInet4) (udpBatchSendResult, error) {
	var result udpBatchSendResult
	for offset := 0; offset < len(packets); {
		end := offset + udpSendMmsgMaxBatch
		if end > len(packets) {
			end = len(packets)
		}
		chunk := packets[offset:end]
		n, err := sendUDPMmsgChunk(raw, chunk, remote)
		result.mmsgSyscalls++
		for i := 0; i < n; i++ {
			result.bytesSent += uint64(len(chunk[i]))
		}
		offset += n
		if err != nil {
			if n > 0 {
				continue
			}
			return result, err
		}
		if n <= 0 {
			return result, unix.EIO
		}
	}
	return result, nil
}

func sendUDPMmsgChunk(raw syscall.RawConn, packets [][]byte, remote *unix.RawSockaddrInet4) (int, error) {
	scratch := takeUDPSendMmsgScratch(len(packets))
	defer putUDPSendMmsgScratch(scratch)
	addrs := scratch.addrs[:len(packets)]
	iovs := scratch.iovs[:len(packets)]
	msgs := scratch.msgs[:len(packets)]
	for i, packet := range packets {
		msgs[i] = udpMMsgHdr{}
		if len(packet) == 0 {
			continue
		}
		iovs[i].Base = &packet[0]
		iovs[i].SetLen(len(packet))
		msgs[i].hdr.Iov = &iovs[i]
		msgs[i].hdr.Iovlen = 1
		if remote != nil {
			addrs[i] = *remote
			msgs[i].hdr.Name = (*byte)(unsafe.Pointer(&addrs[i]))
			msgs[i].hdr.Namelen = unix.SizeofSockaddrInet4
		}
	}
	n, err := sendUDPMmsgRaw(raw, msgs)
	runtime.KeepAlive(packets)
	return n, err
}

func takeUDPSendMmsgScratch(size int) *udpSendMmsgScratch {
	scratch := udpSendMmsgPool.Get().(*udpSendMmsgScratch)
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
		scratch.msgs = make([]udpMMsgHdr, size)
	} else {
		scratch.msgs = scratch.msgs[:size]
	}
	return scratch
}

func putUDPSendMmsgScratch(scratch *udpSendMmsgScratch) {
	if scratch == nil {
		return
	}
	if cap(scratch.msgs) > 4096 {
		return
	}
	scratch.addrs = scratch.addrs[:0]
	scratch.iovs = scratch.iovs[:0]
	scratch.msgs = scratch.msgs[:0]
	udpSendMmsgPool.Put(scratch)
}

func sendUDPMmsgRaw(raw syscall.RawConn, msgs []udpMMsgHdr) (int, error) {
	var sent int
	var opErr error
	err := raw.Write(func(fd uintptr) bool {
		sent, opErr = udpSendmmsg(int(fd), msgs)
		return !errors.Is(opErr, unix.EAGAIN) && !errors.Is(opErr, unix.EWOULDBLOCK)
	})
	if err != nil {
		return sent, err
	}
	return sent, opErr
}

func udpSendmmsg(fd int, msgs []udpMMsgHdr) (int, error) {
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

func udpRawSockaddrInet4(remote *net.UDPAddr) (unix.RawSockaddrInet4, bool) {
	if remote == nil || remote.Port <= 0 || remote.Port > 0xffff {
		return unix.RawSockaddrInet4{}, false
	}
	ip := remote.IP.To4()
	if ip == nil {
		return unix.RawSockaddrInet4{}, false
	}
	var addr unix.RawSockaddrInet4
	addr.Family = unix.AF_INET
	addr.Port = udpHTONS(uint16(remote.Port))
	copy(addr.Addr[:], ip)
	return addr, true
}

func udpHTONS(value uint16) uint16 {
	return (value << 8) | (value >> 8)
}
