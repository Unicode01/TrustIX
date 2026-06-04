//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"

	"trustix.local/trustix/internal/transport/kerneludp"
)

const (
	kernelUDPUDPFallbackRecvBufferSize = 64 * 1024
	kernelUDPUDPFallbackControlSize    = 64
	kernelUDPUDPFallbackGSOMaxPayload  = 0xffff - 20 - 8
)

type kernelUDPUDPFallbackSocket struct {
	port uint16
	fd   int
}

type kernelUDPUDPFallbackRecvScratch struct {
	addrs       []unix.RawSockaddrAny
	iovs        []unix.Iovec
	msgs        []mmsghdr
	arena       []byte
	control     []byte
	initialized int
	active      int
}

type kernelUDPUDPFallbackSendScratch struct {
	addrs   []unix.RawSockaddrInet4
	control []byte
	headers []byte
	iovs    []unix.Iovec
	msgs    []mmsghdr
}

var kernelUDPUDPFallbackRecvPool = sync.Pool{
	New: func() any {
		return &kernelUDPUDPFallbackRecvScratch{
			addrs: make([]unix.RawSockaddrAny, 0, 256),
			iovs:  make([]unix.Iovec, 0, 256),
			msgs:  make([]mmsghdr, 0, 256),
		}
	},
}

var kernelUDPUDPFallbackSendPool = sync.Pool{
	New: func() any {
		return &kernelUDPUDPFallbackSendScratch{
			addrs:   make([]unix.RawSockaddrInet4, 0, 256),
			control: make([]byte, 0, 256*unix.CmsgSpace(2)),
			headers: make([]byte, 0, 256*kerneludp.HeaderLen),
			iovs:    make([]unix.Iovec, 0, 256),
			msgs:    make([]mmsghdr, 0, 256),
		}
	},
}

func (manager *Manager) syncKernelUDPUDPFallbackSocketsLocked(ports map[uint16]struct{}) error {
	if !kernelUDPUDPFallbackEnabled() {
		return nil
	}
	if manager.kernelUDPUDPFallbackSockets == nil {
		manager.kernelUDPUDPFallbackSockets = make(map[uint16]*kernelUDPUDPFallbackSocket)
	}
	var closeList []*kernelUDPUDPFallbackSocket
	manager.kernelUDPUDPFallbackMu.Lock()
	for port, socket := range manager.kernelUDPUDPFallbackSockets {
		if _, ok := ports[port]; ok {
			continue
		}
		delete(manager.kernelUDPUDPFallbackSockets, port)
		closeList = append(closeList, socket)
	}
	var opened []*kernelUDPUDPFallbackSocket
	for port := range ports {
		if port == 0 {
			continue
		}
		if manager.kernelUDPUDPFallbackSockets[port] != nil {
			continue
		}
		socket, err := openKernelUDPUDPFallbackSocket(port)
		if err != nil {
			for _, item := range opened {
				delete(manager.kernelUDPUDPFallbackSockets, item.port)
			}
			manager.kernelUDPUDPFallbackMu.Unlock()
			for _, item := range opened {
				_ = unix.Close(item.fd)
			}
			for _, item := range closeList {
				_ = unix.Close(item.fd)
			}
			return err
		}
		manager.kernelUDPUDPFallbackSockets[port] = socket
		opened = append(opened, socket)
	}
	manager.kernelUDPUDPFallbackMu.Unlock()
	for _, item := range closeList {
		_ = unix.Close(item.fd)
	}
	if len(opened) > 0 && manager.kernelUDPRawFD >= 0 {
		if err := unix.Close(manager.kernelUDPRawFD); err != nil {
			manager.warnings = append(manager.warnings, "close kernel_udp raw UDP socket after UDP socket fallback attach: "+err.Error())
		}
		manager.kernelUDPRawFD = -1
	}
	for _, socket := range opened {
		go manager.readKernelUDPUDPFallbackFrames(socket)
	}
	return nil
}

func (manager *Manager) closeKernelUDPUDPFallbackSocketsLocked() error {
	manager.kernelUDPUDPFallbackMu.Lock()
	sockets := manager.kernelUDPUDPFallbackSockets
	manager.kernelUDPUDPFallbackSockets = make(map[uint16]*kernelUDPUDPFallbackSocket)
	manager.kernelUDPUDPFallbackMu.Unlock()
	var errs []string
	for _, socket := range sockets {
		if socket == nil || socket.fd < 0 {
			continue
		}
		if err := unix.Close(socket.fd); err != nil {
			errs = append(errs, fmt.Sprintf("close kernel_udp UDP socket %d: %v", socket.port, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func openKernelUDPUDPFallbackSocket(port uint16) (*kernelUDPUDPFallbackSocket, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		return nil, fmt.Errorf("open UDP socket for port %d: %w", port, err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = unix.Close(fd)
		}
	}()
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	if err := unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_PKTINFO, 1); err != nil {
		return nil, fmt.Errorf("enable IP_PKTINFO for port %d: %w", port, err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_UDP, unix.UDP_GRO, 1); err != nil {
		// UDP_GRO is an optimization; kernels without it should still use the socket fallback.
	}
	bufferSize := kernelUDPUDPFallbackSocketBufferSize()
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, bufferSize)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, bufferSize)
	if err := unix.Bind(fd, &unix.SockaddrInet4{Port: int(port)}); err != nil {
		return nil, fmt.Errorf("bind UDP socket port %d: %w", port, err)
	}
	closeOnError = false
	return &kernelUDPUDPFallbackSocket{port: port, fd: fd}, nil
}

func (manager *Manager) readKernelUDPUDPFallbackFrames(socket *kernelUDPUDPFallbackSocket) {
	if socket == nil || socket.fd < 0 {
		return
	}
	batchSize := kernelUDPRawFallbackRecvBatchSize()
	if batchSize < 1 {
		batchSize = 1
	}
	if batchSize > 4096 {
		batchSize = 4096
	}
	scratch := takeKernelUDPUDPFallbackRecvScratch(batchSize)
	defer putKernelUDPUDPFallbackRecvScratch(scratch)
	batchHolder, batch := takeReceivedKernelUDPFrameBatch(batchSize)
	defer putReceivedKernelUDPFrameBatch(batchHolder, batch)
	for {
		n, err := recvKernelUDPUDPFallbackBatch(socket.fd, scratch, batchSize)
		if err != nil {
			if n <= 0 {
				return
			}
		}
		batch = resetReceivedKernelUDPFrameBatch(batch)
		for i := 0; i < n; i++ {
			length := int(scratch.msgs[i].len)
			if length <= 0 || length > kernelUDPUDPFallbackRecvBufferSize {
				continue
			}
			base := i * kernelUDPUDPFallbackRecvBufferSize
			remote, ok := kernelUDPUDPFallbackRemoteAddr(&scratch.addrs[i])
			if !ok {
				continue
			}
			local, segmentSize := kernelUDPUDPFallbackControlInfo(scratch.msgs[i].hdr, scratch.controlForMessage(i))
			if !local.IsValid() || !local.Is4() {
				local = netip.IPv4Unspecified()
			}
			for offset := 0; offset < length; {
				end := length
				if segmentSize > 0 {
					end = offset + segmentSize
					if end > length {
						end = length
					}
				}
				payload := scratch.arena[base+offset : base+end]
				packet := kerneludp.UDPPacket{
					SourceIP:        remote.addr,
					DestinationIP:   local,
					SourcePort:      remote.port,
					DestinationPort: socket.port,
					Payload:         payload,
				}
				if item, ok := manager.decodeKernelUDPPayloadBorrowEncrypted(packet, payload); ok {
					batch = append(batch, item)
				}
				if segmentSize <= 0 {
					break
				}
				offset = end
			}
		}
		if len(batch) > 0 {
			manager.mu.Lock()
			manager.kernelUDPUDPFallbackRXBatches++
			manager.kernelUDPUDPFallbackRXFrames += uint64(len(batch))
			manager.mu.Unlock()
			manager.deliverKernelUDPFrames(batch)
		}
	}
}

func recvKernelUDPUDPFallbackBatch(fd int, scratch *kernelUDPUDPFallbackRecvScratch, batchSize int) (int, error) {
	resetCount := scratch.active
	if resetCount > batchSize {
		resetCount = batchSize
	}
	for i := 0; i < resetCount; i++ {
		scratch.msgs[i].len = 0
		scratch.msgs[i].hdr.Namelen = uint32(unsafe.Sizeof(scratch.addrs[i]))
		scratch.msgs[i].hdr.SetControllen(kernelUDPUDPFallbackControlSize)
		scratch.msgs[i].hdr.Flags = 0
	}
	n, err := recvmmsg(fd, scratch.msgs, unix.MSG_WAITFORONE)
	if n >= 0 {
		scratch.active = n
	}
	runtime.KeepAlive(scratch.arena)
	runtime.KeepAlive(scratch.control)
	return n, err
}

type kernelUDPUDPFallbackRemote struct {
	addr netip.Addr
	port uint16
}

func kernelUDPUDPFallbackRemoteAddr(raw *unix.RawSockaddrAny) (kernelUDPUDPFallbackRemote, bool) {
	if raw == nil || raw.Addr.Family != unix.AF_INET {
		return kernelUDPUDPFallbackRemote{}, false
	}
	addr := (*unix.RawSockaddrInet4)(unsafe.Pointer(raw))
	return kernelUDPUDPFallbackRemote{
		addr: netip.AddrFrom4(addr.Addr),
		port: ntohs(addr.Port),
	}, true
}

func kernelUDPUDPFallbackControlInfo(msg unix.Msghdr, control []byte) (netip.Addr, int) {
	if msg.Flags&unix.MSG_CTRUNC != 0 {
		return netip.Addr{}, 0
	}
	n := int(msg.Controllen)
	if n <= 0 {
		return netip.Addr{}, 0
	}
	if n > len(control) {
		n = len(control)
	}
	var local netip.Addr
	var segmentSize int
	for control = control[:n]; len(control) >= unix.CmsgLen(0); {
		header := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
		cmsgLen := int(header.Len)
		if cmsgLen < unix.CmsgLen(0) || cmsgLen > len(control) {
			break
		}
		data := control[unix.CmsgLen(0):cmsgLen]
		switch {
		case header.Level == unix.SOL_IP && header.Type == unix.IP_PKTINFO && len(data) >= unix.SizeofInet4Pktinfo:
			info := (*unix.Inet4Pktinfo)(unsafe.Pointer(&data[0]))
			local = netip.AddrFrom4(info.Addr)
		case header.Level == unix.SOL_UDP && header.Type == unix.UDP_GRO && len(data) >= 2:
			segmentSize = int(binary.NativeEndian.Uint16(data[:2]))
		}
		next := unix.CmsgSpace(cmsgLen - unix.CmsgLen(0))
		if next <= 0 || next > len(control) {
			break
		}
		control = control[next:]
	}
	return local, segmentSize
}

func (manager *Manager) sendKernelUDPUDPPreparedFrames(frames []preparedKernelUDPTXFrame) (int, error) {
	if len(frames) == 0 {
		return 0, nil
	}
	sent := 0
	for sent < len(frames) {
		port := frames[sent].sourcePort
		if port == 0 {
			return sent, fmt.Errorf("send kernel_udp UDP fallback: frame %d has no source port", sent)
		}
		socket := manager.kernelUDPUDPFallbackSocketForPort(port)
		if socket == nil {
			return sent, fmt.Errorf("send kernel_udp UDP fallback: no socket for source port %d", port)
		}
		end := sent + 1
		for end < len(frames) && frames[end].sourcePort == port {
			end++
		}
		n, err := manager.sendKernelUDPUDPFallbackSocketBatch(socket.fd, frames[sent:end])
		if n > 0 {
			manager.mu.Lock()
			manager.kernelUDPUDPFallbackTXFrames += uint64(n)
			manager.kernelUDPUDPFallbackTXBatches++
			manager.mu.Unlock()
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

func (manager *Manager) kernelUDPUDPFallbackSocketForPort(port uint16) *kernelUDPUDPFallbackSocket {
	manager.kernelUDPUDPFallbackMu.RLock()
	socket := manager.kernelUDPUDPFallbackSockets[port]
	manager.kernelUDPUDPFallbackMu.RUnlock()
	return socket
}

func sendKernelUDPUDPFallbackSocketBatch(fd int, frames []preparedKernelUDPTXFrame) (int, error) {
	return sendKernelUDPUDPFallbackSocketBatchWithGSO(fd, frames, nil)
}

func (manager *Manager) sendKernelUDPUDPFallbackSocketBatch(fd int, frames []preparedKernelUDPTXFrame) (int, error) {
	return sendKernelUDPUDPFallbackSocketBatchWithGSO(fd, frames, manager)
}

func sendKernelUDPUDPFallbackSocketBatchWithGSO(fd int, frames []preparedKernelUDPTXFrame, manager *Manager) (int, error) {
	if len(frames) == 0 {
		return 0, nil
	}
	if manager != nil && kernelUDPUDPFallbackGSOEnabled() && !manager.kernelUDPUDPFallbackGSODisabled.Load() {
		sent, ok, err := manager.sendKernelUDPUDPFallbackGSOFramesMixed(fd, frames)
		if ok || err != nil && sent > 0 {
			return sent, err
		}
	}
	return sendKernelUDPUDPFallbackSocketBatchNoGSO(fd, frames)
}

func sendKernelUDPUDPFallbackSocketBatchNoGSO(fd int, frames []preparedKernelUDPTXFrame) (int, error) {
	totalBytes := 0
	for i, frame := range frames {
		frameLen := frame.frameWireLen
		if frameLen <= 0 {
			var err error
			frameLen, err = kerneludp.FrameWireLen(len(frame.wireFrame.Payload))
			if err != nil {
				return i, err
			}
		}
		totalBytes += frameLen
	}
	scratch := takeRawIPv4PacketBatchScratch(len(frames), totalBytes)
	defer putRawIPv4PacketBatchScratch(scratch)
	offset := 0
	for i, frame := range frames {
		frameLen := frame.frameWireLen
		if frameLen <= 0 {
			var err error
			frameLen, err = kerneludp.FrameWireLen(len(frame.wireFrame.Payload))
			if err != nil {
				return i, err
			}
		}
		payload := scratch.arena[offset : offset+frameLen]
		offset += frameLen
		if _, err := frame.wireFrame.MarshalBinaryInto(payload); err != nil {
			return i, err
		}
		scratch.packets[i] = payload
	}
	return sendKernelUDPUDPFallbackPayloadBatch(fd, scratch.packets, frames)
}

func (manager *Manager) sendKernelUDPUDPFallbackGSOFramesMixed(fd int, frames []preparedKernelUDPTXFrame) (int, bool, error) {
	if len(frames) < 2 {
		return 0, false, nil
	}
	maxSegments := kernelUDPUDPFallbackGSOMaxSegments()
	if maxSegments < 2 {
		return 0, false, nil
	}
	if !kernelUDPUDPFallbackGSORunBatchEnabled() {
		return manager.sendKernelUDPUDPFallbackGSOFramesMixedCompat(fd, frames, maxSegments)
	}
	sent := 0
	usedGSO := false
	for sent < len(frames) {
		start := sent
		end, _, _, ok, err := kernelUDPUDPFallbackFrameGSOGroupRunEnd(frames, start, maxSegments)
		if err != nil {
			return sent, true, err
		}
		if ok {
			n, gsoOK, err := manager.sendKernelUDPUDPFallbackGSOFrames(fd, frames[start:end])
			usedGSO = true
			if n > 0 {
				sent += n
			}
			if err != nil {
				return sent, true, err
			}
			if gsoOK && n == end-start {
				continue
			}
			if !gsoOK && n == 0 {
				n, err := sendKernelUDPUDPFallbackSocketBatchNoGSO(fd, frames[start:end])
				if n > 0 {
					sent += n
				}
				if err != nil {
					return sent, true, err
				}
			}
			if sent < end {
				return sent, true, unix.EIO
			}
			continue
		}
		next := sent + 1
		for next < len(frames) {
			_, _, _, groupOK, err := kernelUDPUDPFallbackFrameGSOGroupRunEnd(frames, next, maxSegments)
			if err != nil {
				return sent, true, err
			}
			if groupOK {
				break
			}
			next++
		}
		if !usedGSO && next == len(frames) {
			return 0, false, nil
		}
		n, err := sendKernelUDPUDPFallbackSocketBatchNoGSO(fd, frames[sent:next])
		if n > 0 {
			sent += n
		}
		if err != nil {
			return sent, true, err
		}
		if sent < next {
			return sent, true, unix.EIO
		}
	}
	return sent, usedGSO, nil
}

func (manager *Manager) sendKernelUDPUDPFallbackGSOFramesMixedCompat(fd int, frames []preparedKernelUDPTXFrame, maxSegments int) (int, bool, error) {
	hasGroup, err := kernelUDPUDPFallbackHasFrameGSOGroup(frames, maxSegments)
	if err != nil || !hasGroup {
		return 0, false, err
	}
	sent := 0
	for sent < len(frames) {
		start := sent
		end, _, ok, err := kernelUDPUDPFallbackFrameGSOGroupEnd(frames, start, maxSegments)
		if err != nil {
			return sent, true, err
		}
		if ok && end-start >= 2 {
			n, gsoOK, err := manager.sendKernelUDPUDPFallbackGSOFrames(fd, frames[start:end])
			if n > 0 {
				sent += n
			}
			if err != nil {
				return sent, true, err
			}
			if gsoOK && n == end-start {
				continue
			}
			if !gsoOK && n == 0 {
				n, err := sendKernelUDPUDPFallbackSocketBatchNoGSO(fd, frames[start:end])
				if n > 0 {
					sent += n
				}
				if err != nil {
					return sent, true, err
				}
			}
			if sent < end {
				return sent, true, unix.EIO
			}
			continue
		}
		next := sent + 1
		for next < len(frames) {
			groupEnd, _, groupOK, err := kernelUDPUDPFallbackFrameGSOGroupEnd(frames, next, maxSegments)
			if err != nil {
				return sent, true, err
			}
			if groupOK && groupEnd-next >= 2 {
				break
			}
			next++
		}
		n, err := sendKernelUDPUDPFallbackSocketBatchNoGSO(fd, frames[sent:next])
		if n > 0 {
			sent += n
		}
		if err != nil {
			return sent, true, err
		}
		if sent < next {
			return sent, true, unix.EIO
		}
	}
	return sent, true, nil
}

func sendKernelUDPUDPFallbackPayloadBatch(fd int, packets [][]byte, frames []preparedKernelUDPTXFrame) (int, error) {
	if len(packets) != len(frames) {
		return 0, fmt.Errorf("send kernel_udp UDP fallback: packet count %d does not match frame count %d", len(packets), len(frames))
	}
	scratch := takeKernelUDPUDPFallbackSendScratch(len(packets))
	defer putKernelUDPUDPFallbackSendScratch(scratch)
	for i, packet := range packets {
		if len(packet) == 0 {
			return i, fmt.Errorf("send kernel_udp UDP fallback: packet %d is empty", i)
		}
		resetSendMMSGNoControl(&scratch.msgs[i])
		scratch.addrs[i] = unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Port:   htons(frames[i].destinationPort),
			Addr:   frames[i].destinationIP4,
		}
		scratch.iovs[i].Base = &packet[0]
		scratch.iovs[i].SetLen(len(packet))
		scratch.msgs[i].hdr.Name = (*byte)(unsafe.Pointer(&scratch.addrs[i]))
		scratch.msgs[i].hdr.Namelen = unix.SizeofSockaddrInet4
		scratch.msgs[i].hdr.Iov = &scratch.iovs[i]
		scratch.msgs[i].hdr.Iovlen = 1
	}
	var sent int
	for sent < len(packets) {
		n, err := sendmmsg(fd, scratch.msgs[sent:])
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

func (manager *Manager) sendKernelUDPUDPFallbackGSOFrames(fd int, frames []preparedKernelUDPTXFrame) (int, bool, error) {
	if len(frames) < 2 {
		return 0, false, nil
	}
	maxSegments := kernelUDPUDPFallbackGSOMaxSegments()
	if maxSegments < 2 {
		return 0, false, nil
	}
	groups, totalBytes, ok, err := kernelUDPUDPFallbackFrameGSOGroups(frames, maxSegments)
	if err != nil || !ok {
		return 0, false, err
	}
	manager.mu.Lock()
	manager.kernelUDPUDPFallbackGSOAttempts++
	manager.mu.Unlock()
	if kernelUDPUDPFallbackGSOScatterEnabled() && !manager.kernelUDPUDPFallbackGSOScatterDisabled.Load() {
		if sent, sentOK, err := manager.sendKernelUDPUDPFallbackGSOFramesScatter(fd, frames, groups, maxSegments); sentOK || sent > 0 || err != nil {
			return sent, sentOK, err
		}
	}
	return manager.sendKernelUDPUDPFallbackGSOFramesCopy(fd, frames, groups, totalBytes, maxSegments)
}

func (manager *Manager) sendKernelUDPUDPFallbackGSOFramesScatter(fd int, frames []preparedKernelUDPTXFrame, groups int, maxSegments int) (int, bool, error) {
	manager.mu.Lock()
	manager.kernelUDPUDPFallbackGSOScatterAttempts++
	manager.mu.Unlock()
	sendScratch := takeKernelUDPUDPFallbackGSOSendScratch(groups, len(frames))
	defer putKernelUDPUDPFallbackSendScratch(sendScratch)
	group := 0
	iovIndex := 0
	headerIndex := 0
	for offset := 0; offset < len(frames); {
		end, frameLen, _, err := kernelUDPUDPFallbackFrameGSOGroupEnd(frames, offset, maxSegments)
		if err != nil {
			return 0, false, err
		}
		iovStart := iovIndex
		for i := offset; i < end; i++ {
			header := sendScratch.headerForFrame(headerIndex)
			headerIndex++
			if _, err := frames[i].wireFrame.MarshalHeaderInto(header); err != nil {
				return i, false, err
			}
			sendScratch.iovs[iovIndex].Base = &header[0]
			sendScratch.iovs[iovIndex].SetLen(kerneludp.HeaderLen)
			iovIndex++
			if payload := frames[i].wireFrame.Payload; len(payload) > 0 {
				sendScratch.iovs[iovIndex].Base = &payload[0]
				sendScratch.iovs[iovIndex].SetLen(len(payload))
				iovIndex++
			}
		}
		control := udpSegmentControlInto(sendScratch.controlForMessage(group), uint16(frameLen))
		sendScratch.msgs[group] = mmsghdr{}
		sendScratch.addrs[group] = unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Port:   htons(frames[offset].destinationPort),
			Addr:   frames[offset].destinationIP4,
		}
		sendScratch.msgs[group].hdr.Name = (*byte)(unsafe.Pointer(&sendScratch.addrs[group]))
		sendScratch.msgs[group].hdr.Namelen = unix.SizeofSockaddrInet4
		sendScratch.msgs[group].hdr.Iov = &sendScratch.iovs[iovStart]
		sendScratch.msgs[group].hdr.SetIovlen(iovIndex - iovStart)
		sendScratch.msgs[group].hdr.Control = &control[0]
		sendScratch.msgs[group].hdr.SetControllen(len(control))
		group++
		offset = end
	}
	sentGroups := 0
	for sentGroups < groups {
		n, err := sendmmsg(fd, sendScratch.msgs[sentGroups:groups])
		if n > 0 {
			sentGroups += n
		}
		if err != nil {
			if n > 0 {
				continue
			}
			if sentGroups > 0 {
				manager.recordKernelUDPUDPFallbackGSOScatterFallback(err)
				return kernelUDPUDPFallbackFramesForGroups(frames, maxSegments, sentGroups), true, err
			}
			manager.recordKernelUDPUDPFallbackGSOScatterFallback(err)
			return 0, false, nil
		}
		if n <= 0 {
			if sentGroups > 0 {
				manager.recordKernelUDPUDPFallbackGSOScatterFallback(unix.EIO)
				return kernelUDPUDPFallbackFramesForGroups(frames, maxSegments, sentGroups), true, unix.EIO
			}
			manager.recordKernelUDPUDPFallbackGSOScatterFallback(unix.EIO)
			return 0, false, nil
		}
	}
	runtime.KeepAlive(sendScratch.headers)
	runtime.KeepAlive(frames)
	manager.mu.Lock()
	manager.kernelUDPUDPFallbackGSOSuccesses++
	manager.kernelUDPUDPFallbackGSOFrames += uint64(len(frames))
	manager.kernelUDPUDPFallbackGSOBatches += uint64(groups)
	manager.kernelUDPUDPFallbackGSOScatterSuccesses++
	manager.mu.Unlock()
	return len(frames), true, nil
}

func (manager *Manager) sendKernelUDPUDPFallbackGSOFramesCopy(fd int, frames []preparedKernelUDPTXFrame, groups int, totalBytes int, maxSegments int) (int, bool, error) {
	packetScratch := takeRawIPv4PacketBatchScratch(groups, totalBytes)
	defer putRawIPv4PacketBatchScratch(packetScratch)
	sendScratch := takeKernelUDPUDPFallbackSendScratch(groups)
	defer putKernelUDPUDPFallbackSendScratch(sendScratch)
	arenaOffset := 0
	group := 0
	for offset := 0; offset < len(frames); {
		end, frameLen, _, err := kernelUDPUDPFallbackFrameGSOGroupEnd(frames, offset, maxSegments)
		if err != nil {
			return 0, false, err
		}
		combined := packetScratch.arena[arenaOffset : arenaOffset+frameLen*(end-offset)]
		arenaOffset += len(combined)
		writeOffset := 0
		for i := offset; i < end; i++ {
			if _, err := frames[i].wireFrame.MarshalBinaryInto(combined[writeOffset : writeOffset+frameLen]); err != nil {
				return i, false, err
			}
			writeOffset += frameLen
		}
		packetScratch.packets[group] = combined
		control := udpSegmentControlInto(sendScratch.controlForMessage(group), uint16(frameLen))
		sendScratch.msgs[group] = mmsghdr{}
		sendScratch.addrs[group] = unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Port:   htons(frames[offset].destinationPort),
			Addr:   frames[offset].destinationIP4,
		}
		sendScratch.iovs[group].Base = &combined[0]
		sendScratch.iovs[group].SetLen(len(combined))
		sendScratch.msgs[group].hdr.Name = (*byte)(unsafe.Pointer(&sendScratch.addrs[group]))
		sendScratch.msgs[group].hdr.Namelen = unix.SizeofSockaddrInet4
		sendScratch.msgs[group].hdr.Iov = &sendScratch.iovs[group]
		sendScratch.msgs[group].hdr.Iovlen = 1
		sendScratch.msgs[group].hdr.Control = &control[0]
		sendScratch.msgs[group].hdr.SetControllen(len(control))
		group++
		offset = end
	}
	sentGroups := 0
	for sentGroups < groups {
		n, err := sendmmsg(fd, sendScratch.msgs[sentGroups:groups])
		if n > 0 {
			sentGroups += n
		}
		if err != nil {
			if n > 0 {
				continue
			}
			manager.recordKernelUDPUDPFallbackGSOFallback(err)
			if sentGroups > 0 {
				return kernelUDPUDPFallbackFramesForGroups(frames, maxSegments, sentGroups), true, err
			}
			return 0, false, nil
		}
		if n <= 0 {
			manager.recordKernelUDPUDPFallbackGSOFallback(unix.EIO)
			if sentGroups > 0 {
				return kernelUDPUDPFallbackFramesForGroups(frames, maxSegments, sentGroups), true, unix.EIO
			}
			return 0, false, nil
		}
	}
	manager.mu.Lock()
	manager.kernelUDPUDPFallbackGSOSuccesses++
	manager.kernelUDPUDPFallbackGSOFrames += uint64(len(frames))
	manager.kernelUDPUDPFallbackGSOBatches += uint64(groups)
	manager.mu.Unlock()
	return len(frames), true, nil
}

func kernelUDPUDPFallbackFrameGSOGroups(frames []preparedKernelUDPTXFrame, maxSegments int) (int, int, bool, error) {
	end, groups, totalBytes, ok, err := kernelUDPUDPFallbackFrameGSOGroupRunEnd(frames, 0, maxSegments)
	if err != nil || !ok {
		return 0, 0, false, err
	}
	if end != len(frames) {
		return 0, 0, false, nil
	}
	return groups, totalBytes, true, nil
}

func kernelUDPUDPFallbackHasFrameGSOGroup(frames []preparedKernelUDPTXFrame, maxSegments int) (bool, error) {
	for offset := 0; offset < len(frames); {
		end, _, ok, err := kernelUDPUDPFallbackFrameGSOGroupEnd(frames, offset, maxSegments)
		if err != nil {
			return false, err
		}
		if ok && end-offset >= 2 {
			return true, nil
		}
		if end <= offset {
			offset++
		} else {
			offset = end
		}
	}
	return false, nil
}

func kernelUDPUDPFallbackFramesForGroups(frames []preparedKernelUDPTXFrame, maxSegments int, groups int) int {
	if groups <= 0 {
		return 0
	}
	sentFrames := 0
	for offset := 0; offset < len(frames) && groups > 0; {
		end, _, ok, err := kernelUDPUDPFallbackFrameGSOGroupEnd(frames, offset, maxSegments)
		if err != nil || !ok || end <= offset {
			return sentFrames
		}
		sentFrames += end - offset
		offset = end
		groups--
	}
	return sentFrames
}

func kernelUDPUDPFallbackFrameGSOGroupRunEnd(frames []preparedKernelUDPTXFrame, start int, maxSegments int) (int, int, int, bool, error) {
	if start < 0 || start >= len(frames) {
		return start, 0, 0, false, nil
	}
	offset := start
	groups := 0
	totalBytes := 0
	for offset < len(frames) {
		end, frameLen, ok, err := kernelUDPUDPFallbackFrameGSOGroupEnd(frames, offset, maxSegments)
		if err != nil {
			return start, 0, 0, false, err
		}
		if !ok || end-offset < 2 {
			break
		}
		groups++
		totalBytes += frameLen * (end - offset)
		offset = end
	}
	return offset, groups, totalBytes, groups > 0, nil
}

func kernelUDPUDPFallbackFrameGSOGroupEnd(frames []preparedKernelUDPTXFrame, start int, maxSegments int) (int, int, bool, error) {
	if start < 0 || start >= len(frames) {
		return start, 0, false, nil
	}
	first := frames[start]
	frameLen := first.frameWireLen
	if frameLen <= 0 {
		var err error
		frameLen, err = kerneludp.FrameWireLen(len(first.wireFrame.Payload))
		if err != nil {
			return start, 0, false, err
		}
	}
	if frameLen <= 0 {
		return start, 0, false, nil
	}
	if frameLen > kernelUDPUDPFallbackGSOMaxPayload {
		return start, 0, false, nil
	}
	totalLen := frameLen
	end := start + 1
	for end < len(frames) && end-start < maxSegments {
		frame := frames[end]
		nextLen := frame.frameWireLen
		if nextLen <= 0 {
			var err error
			nextLen, err = kerneludp.FrameWireLen(len(frame.wireFrame.Payload))
			if err != nil {
				return start, 0, false, err
			}
		}
		if nextLen != frameLen {
			break
		}
		if totalLen+nextLen > kernelUDPUDPFallbackGSOMaxPayload {
			break
		}
		if frame.destinationPort != first.destinationPort || frame.destinationIP4 != first.destinationIP4 || frame.sourcePort != first.sourcePort {
			break
		}
		totalLen += nextLen
		end++
	}
	return end, frameLen, end-start >= 2, nil
}

func (manager *Manager) sendKernelUDPUDPFallbackGSOBatch(fd int, packets [][]byte, frames []preparedKernelUDPTXFrame) (int, bool, error) {
	if len(packets) < 2 || len(packets) != len(frames) {
		return 0, false, nil
	}
	maxSegments := kernelUDPUDPFallbackGSOMaxSegments()
	if maxSegments < 2 {
		return 0, false, nil
	}
	groups := 0
	for offset := 0; offset < len(frames); {
		end := kernelUDPUDPFallbackGSOGroupEnd(packets, frames, offset, maxSegments)
		if end-offset < 2 {
			return 0, false, nil
		}
		groups++
		offset = end
	}
	manager.mu.Lock()
	manager.kernelUDPUDPFallbackGSOAttempts++
	manager.mu.Unlock()
	arenaBytes := 0
	for offset := 0; offset < len(frames); {
		end := kernelUDPUDPFallbackGSOGroupEnd(packets, frames, offset, maxSegments)
		for _, packet := range packets[offset:end] {
			arenaBytes += len(packet)
		}
		offset = end
	}
	scratch := takeRawIPv4PacketBatchScratch(groups, arenaBytes)
	defer putRawIPv4PacketBatchScratch(scratch)
	sendScratch := takeKernelUDPUDPFallbackSendScratch(groups)
	defer putKernelUDPUDPFallbackSendScratch(sendScratch)
	arenaOffset := 0
	group := 0
	for offset := 0; offset < len(frames); {
		end := kernelUDPUDPFallbackGSOGroupEnd(packets, frames, offset, maxSegments)
		groupLen := 0
		for _, packet := range packets[offset:end] {
			groupLen += len(packet)
		}
		combined := scratch.arena[arenaOffset : arenaOffset+groupLen]
		arenaOffset += groupLen
		writeOffset := 0
		for _, packet := range packets[offset:end] {
			copy(combined[writeOffset:], packet)
			writeOffset += len(packet)
		}
		scratch.packets[group] = combined
		control := udpSegmentControlInto(sendScratch.controlForMessage(group), uint16(len(packets[offset])))
		sendScratch.msgs[group] = mmsghdr{}
		sendScratch.addrs[group] = unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Port:   htons(frames[offset].destinationPort),
			Addr:   frames[offset].destinationIP4,
		}
		sendScratch.iovs[group].Base = &combined[0]
		sendScratch.iovs[group].SetLen(len(combined))
		sendScratch.msgs[group].hdr.Name = (*byte)(unsafe.Pointer(&sendScratch.addrs[group]))
		sendScratch.msgs[group].hdr.Namelen = unix.SizeofSockaddrInet4
		sendScratch.msgs[group].hdr.Iov = &sendScratch.iovs[group]
		sendScratch.msgs[group].hdr.Iovlen = 1
		sendScratch.msgs[group].hdr.Control = &control[0]
		sendScratch.msgs[group].hdr.SetControllen(len(control))
		group++
		offset = end
	}
	sentGroups := 0
	for sentGroups < groups {
		n, err := sendmmsg(fd, sendScratch.msgs[sentGroups:groups])
		if n > 0 {
			sentGroups += n
		}
		if err != nil {
			if n > 0 {
				continue
			}
			manager.recordKernelUDPUDPFallbackGSOFallback(err)
			return 0, false, nil
		}
		if n <= 0 {
			manager.recordKernelUDPUDPFallbackGSOFallback(unix.EIO)
			return 0, false, nil
		}
	}
	manager.mu.Lock()
	manager.kernelUDPUDPFallbackGSOSuccesses++
	manager.kernelUDPUDPFallbackGSOFrames += uint64(len(frames))
	manager.kernelUDPUDPFallbackGSOBatches += uint64(groups)
	manager.mu.Unlock()
	return len(frames), true, nil
}

func (manager *Manager) recordKernelUDPUDPFallbackGSOFallback(err error) {
	manager.mu.Lock()
	manager.kernelUDPUDPFallbackGSOFallbacks++
	if kernelUDPUDPFallbackGSOUnsupported(err) {
		manager.kernelUDPUDPFallbackGSODisabled.Store(true)
	}
	manager.mu.Unlock()
}

func (manager *Manager) recordKernelUDPUDPFallbackGSOScatterFallback(err error) {
	manager.mu.Lock()
	manager.kernelUDPUDPFallbackGSOScatterFallbacks++
	if kernelUDPUDPFallbackGSOUnsupported(err) {
		manager.kernelUDPUDPFallbackGSOScatterDisabled.Store(true)
	}
	manager.mu.Unlock()
}

func kernelUDPUDPFallbackGSOGroupEnd(packets [][]byte, frames []preparedKernelUDPTXFrame, start int, maxSegments int) int {
	if start < 0 || start >= len(frames) || start >= len(packets) {
		return start
	}
	packetLen := len(packets[start])
	if packetLen <= 0 {
		return start
	}
	if packetLen > kernelUDPUDPFallbackGSOMaxPayload {
		return start
	}
	first := frames[start]
	totalLen := packetLen
	end := start + 1
	for end < len(frames) && end < len(packets) && end-start < maxSegments {
		if len(packets[end]) != packetLen {
			break
		}
		if totalLen+packetLen > kernelUDPUDPFallbackGSOMaxPayload {
			break
		}
		frame := frames[end]
		if frame.destinationPort != first.destinationPort || frame.destinationIP4 != first.destinationIP4 || frame.sourcePort != first.sourcePort {
			break
		}
		totalLen += packetLen
		end++
	}
	return end
}

func udpSegmentControlInto(control []byte, segmentSize uint16) []byte {
	control = control[:unix.CmsgSpace(2)]
	clear(control)
	header := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
	header.Level = unix.SOL_UDP
	header.Type = unix.UDP_SEGMENT
	header.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(control[unix.CmsgLen(0):unix.CmsgLen(0)+2], segmentSize)
	return control
}

func kernelUDPUDPFallbackGSOUnsupported(err error) bool {
	switch {
	case errors.Is(err, unix.EINVAL),
		errors.Is(err, unix.ENOPROTOOPT),
		errors.Is(err, unix.EOPNOTSUPP),
		errors.Is(err, unix.ENOTSUP),
		errors.Is(err, unix.EMSGSIZE):
		return true
	default:
		return false
	}
}

func takeKernelUDPUDPFallbackRecvScratch(size int) *kernelUDPUDPFallbackRecvScratch {
	scratch := kernelUDPUDPFallbackRecvPool.Get().(*kernelUDPUDPFallbackRecvScratch)
	changed := false
	if cap(scratch.addrs) < size {
		scratch.addrs = make([]unix.RawSockaddrAny, size)
		changed = true
	} else {
		scratch.addrs = scratch.addrs[:size]
	}
	if cap(scratch.iovs) < size {
		scratch.iovs = make([]unix.Iovec, size)
		changed = true
	} else {
		scratch.iovs = scratch.iovs[:size]
	}
	if cap(scratch.msgs) < size {
		scratch.msgs = make([]mmsghdr, size)
		changed = true
	} else {
		scratch.msgs = scratch.msgs[:size]
	}
	arenaBytes := size * kernelUDPUDPFallbackRecvBufferSize
	if cap(scratch.arena) < arenaBytes {
		scratch.arena = make([]byte, arenaBytes)
		changed = true
	} else {
		scratch.arena = scratch.arena[:arenaBytes]
	}
	controlBytes := size * kernelUDPUDPFallbackControlSize
	if cap(scratch.control) < controlBytes {
		scratch.control = make([]byte, controlBytes)
		changed = true
	} else {
		scratch.control = scratch.control[:controlBytes]
	}
	if changed {
		scratch.initialized = 0
		scratch.active = 0
	}
	if scratch.initialized < size {
		initializeKernelUDPUDPFallbackRecvScratch(scratch, scratch.initialized, size)
		scratch.initialized = size
	}
	return scratch
}

func initializeKernelUDPUDPFallbackRecvScratch(scratch *kernelUDPUDPFallbackRecvScratch, start int, end int) {
	if scratch == nil {
		return
	}
	if start < 0 {
		start = 0
	}
	if end > len(scratch.msgs) {
		end = len(scratch.msgs)
	}
	for i := start; i < end; i++ {
		base := i * kernelUDPUDPFallbackRecvBufferSize
		buf := scratch.arena[base : base+kernelUDPUDPFallbackRecvBufferSize]
		control := scratch.controlForMessage(i)
		scratch.iovs[i].Base = &buf[0]
		scratch.iovs[i].SetLen(len(buf))
		scratch.msgs[i].hdr.Name = (*byte)(unsafe.Pointer(&scratch.addrs[i]))
		scratch.msgs[i].hdr.Namelen = uint32(unsafe.Sizeof(scratch.addrs[i]))
		scratch.msgs[i].hdr.Iov = &scratch.iovs[i]
		scratch.msgs[i].hdr.Iovlen = 1
		scratch.msgs[i].hdr.Control = &control[0]
		scratch.msgs[i].hdr.SetControllen(len(control))
	}
}

func putKernelUDPUDPFallbackRecvScratch(scratch *kernelUDPUDPFallbackRecvScratch) {
	if scratch == nil {
		return
	}
	if cap(scratch.msgs) > 4096 || cap(scratch.arena) > 256*kernelUDPUDPFallbackRecvBufferSize {
		return
	}
	scratch.addrs = scratch.addrs[:0]
	scratch.iovs = scratch.iovs[:0]
	scratch.msgs = scratch.msgs[:0]
	scratch.arena = scratch.arena[:0]
	scratch.control = scratch.control[:0]
	scratch.active = 0
	kernelUDPUDPFallbackRecvPool.Put(scratch)
}

func (scratch *kernelUDPUDPFallbackRecvScratch) controlForMessage(index int) []byte {
	base := index * kernelUDPUDPFallbackControlSize
	return scratch.control[base : base+kernelUDPUDPFallbackControlSize]
}

func takeKernelUDPUDPFallbackSendScratch(size int) *kernelUDPUDPFallbackSendScratch {
	scratch := kernelUDPUDPFallbackSendPool.Get().(*kernelUDPUDPFallbackSendScratch)
	if cap(scratch.addrs) < size {
		scratch.addrs = make([]unix.RawSockaddrInet4, size)
	} else {
		scratch.addrs = scratch.addrs[:size]
	}
	controlBytes := size * unix.CmsgSpace(2)
	if cap(scratch.control) < controlBytes {
		scratch.control = make([]byte, controlBytes)
	} else {
		scratch.control = scratch.control[:controlBytes]
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

func takeKernelUDPUDPFallbackGSOSendScratch(groups int, frames int) *kernelUDPUDPFallbackSendScratch {
	scratch := takeKernelUDPUDPFallbackSendScratch(groups)
	iovCount := frames * 2
	if cap(scratch.iovs) < iovCount {
		scratch.iovs = make([]unix.Iovec, iovCount)
	} else {
		scratch.iovs = scratch.iovs[:iovCount]
	}
	headerBytes := frames * kerneludp.HeaderLen
	if cap(scratch.headers) < headerBytes {
		scratch.headers = make([]byte, headerBytes)
	} else {
		scratch.headers = scratch.headers[:headerBytes]
	}
	return scratch
}

func putKernelUDPUDPFallbackSendScratch(scratch *kernelUDPUDPFallbackSendScratch) {
	if scratch == nil {
		return
	}
	if cap(scratch.msgs) > 4096 || cap(scratch.iovs) > 8192 || cap(scratch.headers) > 4096*kerneludp.HeaderLen {
		return
	}
	scratch.addrs = scratch.addrs[:0]
	scratch.control = scratch.control[:0]
	scratch.headers = scratch.headers[:0]
	scratch.iovs = scratch.iovs[:0]
	scratch.msgs = scratch.msgs[:0]
	kernelUDPUDPFallbackSendPool.Put(scratch)
}

func (scratch *kernelUDPUDPFallbackSendScratch) controlForMessage(index int) []byte {
	size := unix.CmsgSpace(2)
	base := index * size
	return scratch.control[base : base+size]
}

func (scratch *kernelUDPUDPFallbackSendScratch) headerForFrame(index int) []byte {
	base := index * kerneludp.HeaderLen
	return scratch.headers[base : base+kerneludp.HeaderLen]
}

func ntohs(value uint16) uint16 {
	return (value << 8) | (value >> 8)
}
