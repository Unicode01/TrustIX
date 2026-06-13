//go:build linux

package iptunnel

import (
	"errors"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const carrierSendMmsgMaxBatch = 128
const carrierUDPSegmentMaxBatch = 64

type carrierMMsgHdr struct {
	hdr unix.Msghdr
	len uint32
}

var carrierUDPSegmentDisabled atomic.Bool

type carrierSendMmsgScratch struct {
	addrs []unix.RawSockaddrInet4
	iovs  []unix.Iovec
	msgs  []carrierMMsgHdr
	oob   []byte
}

var carrierSendMmsgPool = sync.Pool{
	New: func() any {
		return &carrierSendMmsgScratch{
			addrs: make([]unix.RawSockaddrInet4, 0, carrierSendMmsgMaxBatch),
			iovs:  make([]unix.Iovec, 0, carrierSendMmsgMaxBatch),
			msgs:  make([]carrierMMsgHdr, 0, carrierSendMmsgMaxBatch),
		}
	},
}

func sendCarrierBatch(conn *net.UDPConn, wires [][]byte) (carrierBatchSendResult, error) {
	if len(wires) == 0 {
		return carrierBatchSendResult{}, nil
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		result, loopErr := writeCarrierBatchLoop(conn, wires)
		result.fallbacks++
		return result, loopErr
	}
	return sendCarrierBatchMmsg(raw, wires, nil)
}

func sendCarrierBatchTo(conn *net.UDPConn, remote *net.UDPAddr, wires [][]byte) (carrierBatchSendResult, error) {
	if len(wires) == 0 {
		return carrierBatchSendResult{}, nil
	}
	addr, ok := carrierRawSockaddrInet4(remote)
	if !ok {
		result, err := writeCarrierBatchToLoop(conn, remote, wires)
		result.fallbacks++
		return result, err
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		result, loopErr := writeCarrierBatchToLoop(conn, remote, wires)
		result.fallbacks++
		return result, loopErr
	}
	return sendCarrierBatchMmsg(raw, wires, &addr)
}

func sendCarrierPacketBatch(conn *net.UDPConn, packets []carrierBatchPacket) (carrierBatchSendResult, error) {
	if len(packets) == 0 {
		return carrierBatchSendResult{}, nil
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		result, loopErr := writeCarrierPacketBatchLoop(conn, packets)
		result.fallbacks++
		return result, loopErr
	}
	return sendCarrierPacketBatchMmsg(raw, packets, nil)
}

func sendCarrierPacketBatchTo(conn *net.UDPConn, remote *net.UDPAddr, packets []carrierBatchPacket) (carrierBatchSendResult, error) {
	if len(packets) == 0 {
		return carrierBatchSendResult{}, nil
	}
	addr, ok := carrierRawSockaddrInet4(remote)
	if !ok {
		result, err := writeCarrierPacketBatchToLoop(conn, remote, packets)
		result.fallbacks++
		return result, err
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		result, loopErr := writeCarrierPacketBatchToLoop(conn, remote, packets)
		result.fallbacks++
		return result, loopErr
	}
	return sendCarrierPacketBatchMmsg(raw, packets, &addr)
}

func sendCarrierBatchMmsg(raw syscall.RawConn, wires [][]byte, remote *unix.RawSockaddrInet4) (carrierBatchSendResult, error) {
	if carrierUDPSegmentEnabled() && !carrierUDPSegmentDisabled.Load() {
		result, ok, err := sendCarrierBatchUDPSegment(raw, wires, remote)
		if ok || err != nil {
			return result, err
		}
	}
	return sendCarrierBatchMmsgNoGSO(raw, wires, remote)
}

func sendCarrierBatchMmsgNoGSO(raw syscall.RawConn, wires [][]byte, remote *unix.RawSockaddrInet4) (carrierBatchSendResult, error) {
	var result carrierBatchSendResult
	for offset := 0; offset < len(wires); {
		end := offset + carrierSendMmsgMaxBatch
		if end > len(wires) {
			end = len(wires)
		}
		chunk := wires[offset:end]
		n, err := sendCarrierMmsgChunk(raw, chunk, remote)
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

func sendCarrierMmsgChunk(raw syscall.RawConn, wires [][]byte, remote *unix.RawSockaddrInet4) (int, error) {
	scratch := takeCarrierSendMmsgScratch(len(wires))
	defer putCarrierSendMmsgScratch(scratch)
	addrs := scratch.addrs[:len(wires)]
	iovs := scratch.iovs[:len(wires)]
	msgs := scratch.msgs[:len(wires)]
	for i, wire := range wires {
		msgs[i] = carrierMMsgHdr{}
		if len(wire) == 0 {
			continue
		}
		iovs[i].Base = &wire[0]
		iovs[i].SetLen(len(wire))
		msgs[i].hdr.Iov = &iovs[i]
		msgs[i].hdr.Iovlen = 1
		if remote != nil {
			addrs[i] = *remote
			msgs[i].hdr.Name = (*byte)(unsafe.Pointer(&addrs[i]))
			msgs[i].hdr.Namelen = unix.SizeofSockaddrInet4
		}
	}
	n, err := sendCarrierMmsgRaw(raw, msgs)
	runtime.KeepAlive(wires)
	return n, err
}

func sendCarrierPacketBatchMmsg(raw syscall.RawConn, packets []carrierBatchPacket, remote *unix.RawSockaddrInet4) (carrierBatchSendResult, error) {
	if carrierUDPSegmentEnabled() && !carrierUDPSegmentDisabled.Load() {
		result, ok, err := sendCarrierPacketBatchUDPSegment(raw, packets, remote)
		if ok || err != nil {
			return result, err
		}
	}
	return sendCarrierPacketBatchMmsgNoGSO(raw, packets, remote)
}

func sendCarrierPacketBatchMmsgNoGSO(raw syscall.RawConn, packets []carrierBatchPacket, remote *unix.RawSockaddrInet4) (carrierBatchSendResult, error) {
	var result carrierBatchSendResult
	for offset := 0; offset < len(packets); {
		end := offset + carrierSendMmsgMaxBatch
		if end > len(packets) {
			end = len(packets)
		}
		chunk := packets[offset:end]
		n, err := sendCarrierPacketMmsgChunk(raw, chunk, remote)
		result.mmsgSyscalls++
		for i := 0; i < n; i++ {
			result.bytesSent += uint64(len(chunk[i].header) + len(chunk[i].payload))
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

func sendCarrierPacketMmsgChunk(raw syscall.RawConn, packets []carrierBatchPacket, remote *unix.RawSockaddrInet4) (int, error) {
	scratch := takeCarrierSendMmsgScratchIov(len(packets), len(packets)*2)
	defer putCarrierSendMmsgScratch(scratch)
	addrs := scratch.addrs[:len(packets)]
	iovs := scratch.iovs[:len(packets)*2]
	msgs := scratch.msgs[:len(packets)]
	for i, packet := range packets {
		msgs[i] = carrierMMsgHdr{}
		headerIov := &iovs[i*2]
		payloadIov := &iovs[i*2+1]
		if len(packet.header) > 0 {
			headerIov.Base = &packet.header[0]
			headerIov.SetLen(len(packet.header))
		}
		if len(packet.payload) > 0 {
			payloadIov.Base = &packet.payload[0]
			payloadIov.SetLen(len(packet.payload))
		}
		msgs[i].hdr.Iov = headerIov
		msgs[i].hdr.Iovlen = 2
		if remote != nil {
			addrs[i] = *remote
			msgs[i].hdr.Name = (*byte)(unsafe.Pointer(&addrs[i]))
			msgs[i].hdr.Namelen = unix.SizeofSockaddrInet4
		}
	}
	n, err := sendCarrierMmsgRaw(raw, msgs)
	runtime.KeepAlive(packets)
	return n, err
}

func takeCarrierSendMmsgScratch(size int) *carrierSendMmsgScratch {
	scratch := carrierSendMmsgPool.Get().(*carrierSendMmsgScratch)
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
		scratch.msgs = make([]carrierMMsgHdr, size)
	} else {
		scratch.msgs = scratch.msgs[:size]
	}
	return scratch
}

func takeCarrierSendMmsgScratchIov(size int, iovs int) *carrierSendMmsgScratch {
	scratch := takeCarrierSendMmsgScratch(size)
	if cap(scratch.iovs) < iovs {
		scratch.iovs = make([]unix.Iovec, iovs)
	} else {
		scratch.iovs = scratch.iovs[:iovs]
	}
	return scratch
}

func carrierSendMmsgScratchOOB(scratch *carrierSendMmsgScratch, size int) []byte {
	if scratch == nil {
		return make([]byte, size)
	}
	if cap(scratch.oob) < size {
		scratch.oob = make([]byte, size)
	} else {
		scratch.oob = scratch.oob[:size]
		clear(scratch.oob)
	}
	return scratch.oob
}

func putCarrierSendMmsgScratch(scratch *carrierSendMmsgScratch) {
	if scratch == nil {
		return
	}
	clear(scratch.addrs)
	clear(scratch.iovs)
	clear(scratch.msgs)
	if cap(scratch.msgs) > 4096 {
		return
	}
	scratch.addrs = scratch.addrs[:0]
	scratch.iovs = scratch.iovs[:0]
	scratch.msgs = scratch.msgs[:0]
	scratch.oob = scratch.oob[:0]
	carrierSendMmsgPool.Put(scratch)
}

func sendCarrierBatchUDPSegment(raw syscall.RawConn, wires [][]byte, remote *unix.RawSockaddrInet4) (carrierBatchSendResult, bool, error) {
	var result carrierBatchSendResult
	for offset := 0; offset < len(wires); {
		segLen := len(wires[offset])
		if segLen <= 0 {
			result.fallbacks++
			loopResult, err := sendCarrierBatchMmsgNoGSO(raw, wires[offset:offset+1], remote)
			result.add(loopResult)
			if err != nil {
				return result, true, err
			}
			offset++
			continue
		}
		end := offset + 1
		total := segLen
		for end < len(wires) && end-offset < carrierUDPSegmentMaxBatch && len(wires[end]) == segLen {
			if total+len(wires[end]) > 65535 {
				break
			}
			total += len(wires[end])
			end++
		}
		if end-offset < 2 {
			result.fallbacks++
			loopResult, err := sendCarrierBatchMmsgNoGSO(raw, wires[offset:end], remote)
			result.add(loopResult)
			if err != nil {
				return result, true, err
			}
			offset = end
			continue
		}
		n, err := sendCarrierUDPSegmentChunk(raw, wires[offset:end], segLen, total, remote)
		result.gsoSyscalls++
		if err != nil {
			if carrierUDPSegmentPermanentError(err) {
				carrierUDPSegmentDisabled.Store(true)
				result.fallbacks++
				loopResult, loopErr := sendCarrierBatchMmsgNoGSO(raw, wires[offset:], remote)
				result.add(loopResult)
				return result, true, loopErr
			}
			return result, true, err
		}
		result.bytesSent += uint64(n)
		offset = end
	}
	return result, true, nil
}

func sendCarrierPacketBatchUDPSegment(raw syscall.RawConn, packets []carrierBatchPacket, remote *unix.RawSockaddrInet4) (carrierBatchSendResult, bool, error) {
	var result carrierBatchSendResult
	for offset := 0; offset < len(packets); {
		segLen := len(packets[offset].header) + len(packets[offset].payload)
		if segLen <= 0 {
			result.fallbacks++
			loopResult, err := sendCarrierPacketBatchMmsgNoGSO(raw, packets[offset:offset+1], remote)
			result.add(loopResult)
			if err != nil {
				return result, true, err
			}
			offset++
			continue
		}
		end := offset + 1
		total := segLen
		for end < len(packets) && end-offset < carrierUDPSegmentMaxBatch {
			nextLen := len(packets[end].header) + len(packets[end].payload)
			if nextLen != segLen || total+nextLen > 65535 {
				break
			}
			total += nextLen
			end++
		}
		if end-offset < 2 {
			result.fallbacks++
			loopResult, err := sendCarrierPacketBatchMmsgNoGSO(raw, packets[offset:end], remote)
			result.add(loopResult)
			if err != nil {
				return result, true, err
			}
			offset = end
			continue
		}
		n, err := sendCarrierUDPSegmentPacketChunk(raw, packets[offset:end], segLen, total, remote)
		result.gsoSyscalls++
		if err != nil {
			if carrierUDPSegmentPermanentError(err) {
				carrierUDPSegmentDisabled.Store(true)
				result.fallbacks++
				loopResult, loopErr := sendCarrierPacketBatchMmsgNoGSO(raw, packets[offset:], remote)
				result.add(loopResult)
				return result, true, loopErr
			}
			return result, true, err
		}
		result.bytesSent += uint64(n)
		offset = end
	}
	return result, true, nil
}

func (result *carrierBatchSendResult) add(other carrierBatchSendResult) {
	result.bytesSent += other.bytesSent
	result.mmsgSyscalls += other.mmsgSyscalls
	result.gsoSyscalls += other.gsoSyscalls
	result.loopSyscalls += other.loopSyscalls
	result.fallbacks += other.fallbacks
}

func sendCarrierUDPSegmentChunk(raw syscall.RawConn, wires [][]byte, segLen int, total int, remote *unix.RawSockaddrInet4) (int, error) {
	if len(wires) == 0 {
		return 0, nil
	}
	scratch := takeCarrierSendMmsgScratchIov(1, len(wires))
	defer putCarrierSendMmsgScratch(scratch)
	iovs := scratch.iovs[:len(wires)]
	for i, wire := range wires {
		iovs[i] = unix.Iovec{}
		if len(wire) > 0 {
			iovs[i].Base = &wire[0]
			iovs[i].SetLen(len(wire))
		}
	}
	oob := carrierUDPSegmentOOB(carrierSendMmsgScratchOOB(scratch, unix.CmsgSpace(2)), uint16(segLen))
	var sent int
	var opErr error
	err := raw.Write(func(fd uintptr) bool {
		sent, opErr = sendCarrierUDPSegmentRaw(int(fd), iovs, oob, remote)
		return !errors.Is(opErr, unix.EAGAIN) && !errors.Is(opErr, unix.EWOULDBLOCK)
	})
	runtime.KeepAlive(wires)
	runtime.KeepAlive(iovs)
	runtime.KeepAlive(oob)
	if err != nil {
		return sent, err
	}
	if opErr == nil && sent != total {
		return sent, unix.EIO
	}
	return sent, opErr
}

func sendCarrierUDPSegmentPacketChunk(raw syscall.RawConn, packets []carrierBatchPacket, segLen int, total int, remote *unix.RawSockaddrInet4) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	scratch := takeCarrierSendMmsgScratchIov(1, len(packets)*2)
	defer putCarrierSendMmsgScratch(scratch)
	iovs := scratch.iovs[:len(packets)*2]
	for i, packet := range packets {
		headerIov := &iovs[i*2]
		payloadIov := &iovs[i*2+1]
		*headerIov = unix.Iovec{}
		*payloadIov = unix.Iovec{}
		if len(packet.header) > 0 {
			headerIov.Base = &packet.header[0]
			headerIov.SetLen(len(packet.header))
		}
		if len(packet.payload) > 0 {
			payloadIov.Base = &packet.payload[0]
			payloadIov.SetLen(len(packet.payload))
		}
	}
	oob := carrierUDPSegmentOOB(carrierSendMmsgScratchOOB(scratch, unix.CmsgSpace(2)), uint16(segLen))
	var sent int
	var opErr error
	err := raw.Write(func(fd uintptr) bool {
		sent, opErr = sendCarrierUDPSegmentRaw(int(fd), iovs, oob, remote)
		return !errors.Is(opErr, unix.EAGAIN) && !errors.Is(opErr, unix.EWOULDBLOCK)
	})
	runtime.KeepAlive(packets)
	runtime.KeepAlive(iovs)
	runtime.KeepAlive(oob)
	if err != nil {
		return sent, err
	}
	if opErr == nil && sent != total {
		return sent, unix.EIO
	}
	return sent, opErr
}

func carrierUDPSegmentOOB(oob []byte, segLen uint16) []byte {
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	hdr.Level = unix.SOL_UDP
	hdr.Type = unix.UDP_SEGMENT
	hdr.SetLen(unix.CmsgLen(2))
	*(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(hdr)) + uintptr(unix.CmsgLen(0)))) = segLen
	return oob
}

func sendCarrierUDPSegmentRaw(fd int, iovs []unix.Iovec, oob []byte, remote *unix.RawSockaddrInet4) (int, error) {
	if len(iovs) == 0 {
		return 0, nil
	}
	msg := unix.Msghdr{
		Iov:     &iovs[0],
		Control: &oob[0],
	}
	msg.SetIovlen(len(iovs))
	msg.SetControllen(len(oob))
	if remote != nil {
		msg.Name = (*byte)(unsafe.Pointer(remote))
		msg.Namelen = unix.SizeofSockaddrInet4
	}
	n, _, errno := unix.Syscall(unix.SYS_SENDMSG, uintptr(fd), uintptr(unsafe.Pointer(&msg)), 0)
	if errno != 0 {
		return int(n), errno
	}
	return int(n), nil
}

func carrierUDPSegmentPermanentError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.ENOPROTOOPT) ||
		errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.ENOTSUP) ||
		errors.Is(err, unix.EMSGSIZE) ||
		errors.Is(err, unix.ENOSYS) ||
		errors.Is(err, os.ErrInvalid)
}

func sendCarrierMmsgRaw(raw syscall.RawConn, msgs []carrierMMsgHdr) (int, error) {
	var sent int
	var opErr error
	err := raw.Write(func(fd uintptr) bool {
		sent, opErr = carrierSendmmsg(int(fd), msgs)
		return !errors.Is(opErr, unix.EAGAIN) && !errors.Is(opErr, unix.EWOULDBLOCK)
	})
	if err != nil {
		return sent, err
	}
	return sent, opErr
}

func carrierSendmmsg(fd int, msgs []carrierMMsgHdr) (int, error) {
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

func carrierRawSockaddrInet4(remote *net.UDPAddr) (unix.RawSockaddrInet4, bool) {
	if remote == nil || remote.Port <= 0 || remote.Port > 0xffff {
		return unix.RawSockaddrInet4{}, false
	}
	ip := remote.IP.To4()
	if ip == nil {
		return unix.RawSockaddrInet4{}, false
	}
	var addr unix.RawSockaddrInet4
	addr.Family = unix.AF_INET
	addr.Port = carrierHTONS(uint16(remote.Port))
	copy(addr.Addr[:], ip)
	return addr, true
}

func carrierHTONS(value uint16) uint16 {
	return (value << 8) | (value >> 8)
}
