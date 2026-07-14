//go:build linux

package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"

	"trustix.local/trustix/internal/transport/tixtcp"
)

const (
	tixTCPSocketGSODefaultMTU          = 1500
	tixTCPSocketGSODefaultMaxSegments  = 44
	tixTCPSocketGSODefaultMaxIPv4Len   = 0xffff
	tixTCPSocketGSODefaultMessageBatch = 64
)

type preparedTIXTCPSocketGSOMessage struct {
	start     int
	count     int
	frameLen  int
	packetLen int
	gso       bool
}

type preparedTIXTCPSocketGSOGroupResult struct {
	groupLen  int
	packetLen int
	frameLen  int
	reject    preparedTIXTCPSocketGSORejectReason
}

type preparedTIXTCPSocketGSORejectReason uint8

const (
	preparedTIXTCPSocketGSORejectNone preparedTIXTCPSocketGSORejectReason = iota
	preparedTIXTCPSocketGSORejectIneligible
	preparedTIXTCPSocketGSORejectKernelTX
	preparedTIXTCPSocketGSORejectKernelOpened
	preparedTIXTCPSocketGSORejectNotSecure
	preparedTIXTCPSocketGSORejectFlags
	preparedTIXTCPSocketGSORejectFragment
	preparedTIXTCPSocketGSORejectTuple
	preparedTIXTCPSocketGSORejectSequence
	preparedTIXTCPSocketGSORejectFrameLen
	preparedTIXTCPSocketGSORejectPacketLen
	preparedTIXTCPSocketGSORejectMaxSegments
	preparedTIXTCPSocketGSORejectMaxIPv4Len
)

type preparedTIXTCPSocketGSOItemMeta struct {
	src             [4]byte
	dst             [4]byte
	sourcePort      uint16
	destinationPort uint16
	ack             uint32
	sequence        uint32
	flowID          uint64
	frameLen        int
	packetLen       int
}

func tixTCPTXSocketGSOEnabled() bool {
	return envTruthy("TRUSTIX_TIX_TCP_TX_SOCKET_GSO", "TRUSTIX_TIXT_TX_SOCKET_GSO")
}

func tixTCPTXSocketGSOMaxSegments() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_TIX_TCP_TX_SOCKET_GSO_MAX_SEGMENTS"))
	if value == "" {
		value = strings.TrimSpace(os.Getenv("TRUSTIX_TIXT_TX_SOCKET_GSO_MAX_SEGMENTS"))
	}
	if value == "" {
		return tixTCPSocketGSODefaultMaxSegments
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 2 {
		return tixTCPSocketGSODefaultMaxSegments
	}
	if parsed > 64 {
		return 64
	}
	return parsed
}

func tixTCPTXSocketGSOMaxIPv4Len() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_TIX_TCP_TX_SOCKET_GSO_MAX_IPV4_LEN"))
	if value == "" {
		value = strings.TrimSpace(os.Getenv("TRUSTIX_TIXT_TX_SOCKET_GSO_MAX_IPV4_LEN"))
	}
	if value == "" {
		return tixTCPSocketGSODefaultMaxIPv4Len
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 20+20+tixtcp.HeaderLen*2 {
		return tixTCPSocketGSODefaultMaxIPv4Len
	}
	if parsed > 0xffff {
		return 0xffff
	}
	return parsed
}

func tixTCPTXSocketGSOMessageBatchLimit() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_TIX_TCP_TX_SOCKET_GSO_SENDMMSG"))
	if value == "" {
		value = strings.TrimSpace(os.Getenv("TRUSTIX_TIXT_TX_SOCKET_GSO_SENDMMSG"))
	}
	if value == "" {
		return tixTCPSocketGSODefaultMessageBatch
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return tixTCPSocketGSODefaultMessageBatch
	}
	if parsed > 256 {
		return 256
	}
	return parsed
}

func (socket *afXDPSocket) sendPreparedTIXTCPSocketGSOBatchLocked(items []preparedTIXTCPTXFrame, dstMAC net.HardwareAddr) (bool, error) {
	if len(items) < 2 {
		return false, nil
	}
	socket.stats.txSocketGSOAttempts.Add(1)
	if len(socket.linkMAC) < 6 || len(dstMAC) < 6 {
		socket.recordPreparedTIXTCPSocketGSOReject(preparedTIXTCPSocketGSORejectIneligible)
		return false, nil
	}
	mtu := socket.linkMTU
	if mtu <= 0 {
		mtu = tixTCPSocketGSODefaultMTU
	}
	maxSegmentPayload := mtu - 20 - 20
	if maxSegmentPayload < tixtcp.HeaderLen {
		socket.recordPreparedTIXTCPSocketGSOReject(preparedTIXTCPSocketGSORejectFrameLen)
		return false, nil
	}
	maxSegments := tixTCPTXSocketGSOMaxSegments()
	maxIPv4Len := tixTCPTXSocketGSOMaxIPv4Len()
	messages := make([]preparedTIXTCPSocketGSOMessage, 0, len(items))
	gsoMessages := 0
	gsoSegments := 0
	singles := 0
	for i := 0; i < len(items); {
		meta, reject, err := preparedTIXTCPSocketGSOItemMetaFor(items[i], maxSegmentPayload)
		if err != nil {
			return false, err
		}
		if reject != preparedTIXTCPSocketGSORejectNone {
			socket.recordPreparedTIXTCPSocketGSOReject(reject)
			return false, nil
		}
		group, err := preparedTIXTCPSocketGSOGroupWithReason(items[i:], maxSegmentPayload, maxSegments, maxIPv4Len)
		if err != nil {
			return false, err
		}
		if group.groupLen >= 2 {
			messages = append(messages, preparedTIXTCPSocketGSOMessage{
				start:     i,
				count:     group.groupLen,
				frameLen:  group.frameLen,
				packetLen: group.packetLen,
				gso:       true,
			})
			gsoMessages++
			gsoSegments += group.groupLen
			i += group.groupLen
			continue
		}
		messages = append(messages, preparedTIXTCPSocketGSOMessage{
			start:     i,
			count:     1,
			frameLen:  meta.frameLen,
			packetLen: meta.packetLen,
		})
		if group.reject != preparedTIXTCPSocketGSORejectNone {
			socket.recordPreparedTIXTCPSocketGSOReject(group.reject)
		}
		singles++
		i++
	}
	if gsoMessages == 0 {
		socket.stats.txSocketGSORejectNoBenefit.Add(1)
		return false, nil
	}
	fd, err := socket.preparedTIXTCPSocketGSORawSocketLocked()
	if err != nil {
		socket.stats.txSocketGSOUnsupported.Add(1)
		socket.stats.txSocketGSOFallbacks.Add(1)
		return false, nil
	}
	limit := tixTCPTXSocketGSOMessageBatchLimit()
	sentAny := false
	for start := 0; start < len(messages); {
		end := min(start+limit, len(messages))
		handled, err := socket.sendPreparedTIXTCPSocketGSOMessageBatchLocked(fd, items, messages[start:end], dstMAC)
		if err != nil {
			if !sentAny && !handled {
				socket.stats.txSocketGSOFallbacks.Add(1)
				return false, nil
			}
			socket.stats.txSocketGSOErrors.Add(1)
			return true, err
		}
		sentAny = true
		start = end
	}
	socket.stats.txSocketGSOSuccesses.Add(1)
	socket.stats.txSocketGSOMessages.Add(uint64(len(messages)))
	socket.stats.txSocketGSOInputFrames.Add(uint64(len(items)))
	socket.stats.txSocketGSOSegments.Add(uint64(gsoSegments))
	socket.stats.txSocketGSOSingles.Add(uint64(singles))
	return true, nil
}

func (socket *afXDPSocket) sendPreparedTIXTCPSocketGSOMessageBatchLocked(fd int, items []preparedTIXTCPTXFrame, messages []preparedTIXTCPSocketGSOMessage, dstMAC net.HardwareAddr) (bool, error) {
	if len(messages) == 0 {
		return false, nil
	}
	totalBytes := 0
	for _, message := range messages {
		totalBytes += message.packetLen
	}
	packetScratch := takeRawIPv4PacketBatchScratch(len(messages), totalBytes)
	defer putRawIPv4PacketBatchScratch(packetScratch)
	sendScratch := takeLANGSOSendMMSGScratch(len(messages))
	defer putLANGSOSendMMSGScratch(sendScratch)
	offset := 0
	for i, message := range messages {
		packet := packetScratch.arena[offset : offset+message.packetLen]
		offset += message.packetLen
		header := sendScratch.virtioHeader(i)
		clear(header)
		if message.gso {
			if err := marshalPreparedTIXTCPSocketGSOIPv4Into(items[message.start:message.start+message.count], packet); err != nil {
				return false, err
			}
			if err := preparePreparedTIXTCPSocketGSOVirtioHeader(header, message.frameLen); err != nil {
				return false, err
			}
		} else if err := marshalPreparedTIXTCPIPv4FrameInto(items[message.start], packet, false); err != nil {
			return false, err
		}
		ethernet := sendScratch.ethernetHeader(i)
		copy(ethernet[0:6], dstMAC)
		copy(ethernet[6:12], socket.linkMAC)
		binary.BigEndian.PutUint16(ethernet[12:14], etherTypeIPv4)
		resetSendMMSGNoControl(&sendScratch.msgs[i])
		sendScratch.addrs[i] = rawSockaddrLinklayer(socket.linkIndex, dstMAC)
		iovBase := i * 3
		sendScratch.iovs[iovBase].Base = &header[0]
		sendScratch.iovs[iovBase].SetLen(len(header))
		sendScratch.iovs[iovBase+1].Base = &ethernet[0]
		sendScratch.iovs[iovBase+1].SetLen(len(ethernet))
		sendScratch.iovs[iovBase+2].Base = &packet[0]
		sendScratch.iovs[iovBase+2].SetLen(len(packet))
		sendScratch.msgs[i].hdr.Name = (*byte)(unsafe.Pointer(&sendScratch.addrs[i]))
		sendScratch.msgs[i].hdr.Namelen = unix.SizeofSockaddrLinklayer
		sendScratch.msgs[i].hdr.Iov = &sendScratch.iovs[iovBase]
		sendScratch.msgs[i].hdr.SetIovlen(3)
		packetScratch.packets[i] = packet
	}
	sent := 0
	for sent < len(messages) {
		n, err := sendmmsg(fd, sendScratch.msgs[sent:])
		if n > 0 {
			sent += n
		}
		if err != nil {
			runtime.KeepAlive(sendScratch.iovs)
			runtime.KeepAlive(sendScratch.headers)
			runtime.KeepAlive(sendScratch.ethernets)
			runtime.KeepAlive(packetScratch.arena)
			if sent == 0 && isPacketSocketGSOUnsupported(err) {
				socket.disablePreparedTIXTCPSocketGSOLocked()
				socket.stats.txSocketGSOUnsupported.Add(1)
				return false, fmt.Errorf("%w: send tix_tcp raw VNET GSO batch on ifindex=%d: %v", errGSOUnsupported, socket.linkIndex, err)
			}
			return sent > 0, fmt.Errorf("send tix_tcp raw VNET GSO batch on ifindex=%d: %w", socket.linkIndex, err)
		}
		if n <= 0 {
			runtime.KeepAlive(sendScratch.iovs)
			runtime.KeepAlive(sendScratch.headers)
			runtime.KeepAlive(sendScratch.ethernets)
			runtime.KeepAlive(packetScratch.arena)
			return sent > 0, fmt.Errorf("send tix_tcp raw VNET GSO batch on ifindex=%d: %w", socket.linkIndex, unix.EIO)
		}
	}
	runtime.KeepAlive(sendScratch.iovs)
	runtime.KeepAlive(sendScratch.headers)
	runtime.KeepAlive(sendScratch.ethernets)
	runtime.KeepAlive(packetScratch.arena)
	return true, nil
}

func (socket *afXDPSocket) preparedTIXTCPSocketGSORawSocketLocked() (int, error) {
	if socket.txSocketGSODisabled {
		return -1, fmt.Errorf("%w for tix_tcp raw packet socket", errGSOUnsupported)
	}
	if socket.txSocketGSOFDValid && socket.txSocketGSOFD >= 0 {
		return socket.txSocketGSOFD, nil
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(etherTypeIPv4)))
	if err != nil {
		socket.txSocketGSODisabled = true
		return -1, fmt.Errorf("%w: open tix_tcp raw packet socket: %v", errGSOUnsupported, err)
	}
	if err := configureGSOPacketSocket(fd); err != nil {
		_ = unix.Close(fd)
		socket.txSocketGSODisabled = true
		return -1, fmt.Errorf("%w: configure tix_tcp raw packet GSO socket: %v", errGSOUnsupported, err)
	}
	socket.txSocketGSOFD = fd
	socket.txSocketGSOFDValid = true
	return fd, nil
}

func (socket *afXDPSocket) disablePreparedTIXTCPSocketGSOLocked() {
	socket.txSocketGSODisabled = true
	if socket.txSocketGSOFDValid && socket.txSocketGSOFD >= 0 {
		_ = unix.Close(socket.txSocketGSOFD)
	}
	socket.txSocketGSOFD = -1
	socket.txSocketGSOFDValid = false
}

func (socket *afXDPSocket) recordPreparedTIXTCPSocketGSOReject(reason preparedTIXTCPSocketGSORejectReason) {
	if reason == preparedTIXTCPSocketGSORejectNone {
		return
	}
	socket.stats.txSocketGSORejectIneligible.Add(1)
	switch reason {
	case preparedTIXTCPSocketGSORejectKernelTX:
		socket.stats.txSocketGSORejectKernelTX.Add(1)
	case preparedTIXTCPSocketGSORejectKernelOpened:
		socket.stats.txSocketGSORejectKernelOpened.Add(1)
	case preparedTIXTCPSocketGSORejectNotSecure:
		socket.stats.txSocketGSORejectNotSecure.Add(1)
	case preparedTIXTCPSocketGSORejectFlags:
		socket.stats.txSocketGSORejectFlags.Add(1)
	case preparedTIXTCPSocketGSORejectFragment:
		socket.stats.txSocketGSORejectFragment.Add(1)
	case preparedTIXTCPSocketGSORejectTuple:
		socket.stats.txSocketGSORejectTuple.Add(1)
	case preparedTIXTCPSocketGSORejectSequence:
		socket.stats.txSocketGSORejectSequence.Add(1)
	case preparedTIXTCPSocketGSORejectFrameLen:
		socket.stats.txSocketGSORejectFrameLen.Add(1)
	case preparedTIXTCPSocketGSORejectPacketLen:
		socket.stats.txSocketGSORejectPacketLen.Add(1)
	case preparedTIXTCPSocketGSORejectMaxSegments:
		socket.stats.txSocketGSORejectMaxSegments.Add(1)
	case preparedTIXTCPSocketGSORejectMaxIPv4Len:
		socket.stats.txSocketGSORejectMaxIPv4Len.Add(1)
	}
}

func preparedTIXTCPSocketGSOItemMetaFor(item preparedTIXTCPTXFrame, maxSegmentPayload int) (preparedTIXTCPSocketGSOItemMeta, preparedTIXTCPSocketGSORejectReason, error) {
	if item.kernelTX {
		return preparedTIXTCPSocketGSOItemMeta{}, preparedTIXTCPSocketGSORejectKernelTX, nil
	}
	frame := item.wireFrame
	if frame.Flags&tixtcp.FlagKernelOpened != 0 {
		return preparedTIXTCPSocketGSOItemMeta{}, preparedTIXTCPSocketGSORejectKernelOpened, nil
	}
	encryptedFrame := frame.Flags&tixtcp.FlagEncrypted != 0
	userspaceSecurePayload := tixTCPUserspaceSecurePayload(frame.Payload)
	fragmentedPayload := frame.FragmentCount > 1
	if !encryptedFrame && !userspaceSecurePayload && !fragmentedPayload {
		return preparedTIXTCPSocketGSOItemMeta{}, preparedTIXTCPSocketGSORejectNotSecure, nil
	}
	if frame.Flags&^(tixtcp.FlagEncrypted|tixtcp.FlagCryptoFragment|tixtcp.FlagInnerIPv4) != 0 {
		return preparedTIXTCPSocketGSOItemMeta{}, preparedTIXTCPSocketGSORejectFlags, nil
	}
	if frame.FragmentCount == 0 {
		if frame.FragmentIndex != 0 || frame.Flags&tixtcp.FlagCryptoFragment != 0 {
			return preparedTIXTCPSocketGSOItemMeta{}, preparedTIXTCPSocketGSORejectFragment, nil
		}
	} else if frame.FragmentCount == 1 {
		if frame.FragmentIndex != 0 {
			return preparedTIXTCPSocketGSOItemMeta{}, preparedTIXTCPSocketGSORejectFragment, nil
		}
	} else if frame.FragmentIndex >= frame.FragmentCount {
		return preparedTIXTCPSocketGSOItemMeta{}, preparedTIXTCPSocketGSORejectFragment, nil
	}
	frameLen, err := preparedTIXTCPFrameWireLen(item)
	if err != nil {
		return preparedTIXTCPSocketGSOItemMeta{}, preparedTIXTCPSocketGSORejectFrameLen, err
	}
	if frameLen <= 0 || frameLen > maxSegmentPayload {
		return preparedTIXTCPSocketGSOItemMeta{}, preparedTIXTCPSocketGSORejectFrameLen, nil
	}
	src, dst, sourcePort, destinationPort, err := preparedTIXTCPIPv4Tuple(item)
	if err != nil {
		return preparedTIXTCPSocketGSOItemMeta{}, preparedTIXTCPSocketGSORejectTuple, err
	}
	packetLen := item.packetLen
	if packetLen <= 0 {
		packetLen = 20 + 20 + frameLen
	}
	if packetLen != 20+20+frameLen || packetLen > 0xffff {
		return preparedTIXTCPSocketGSOItemMeta{}, preparedTIXTCPSocketGSORejectPacketLen, nil
	}
	return preparedTIXTCPSocketGSOItemMeta{
		src:             src,
		dst:             dst,
		sourcePort:      sourcePort,
		destinationPort: destinationPort,
		ack:             item.packet.Acknowledgment,
		sequence:        item.packet.Sequence,
		flowID:          frame.FlowID,
		frameLen:        frameLen,
		packetLen:       packetLen,
	}, preparedTIXTCPSocketGSORejectNone, nil
}

func preparedTIXTCPSocketGSOGroupWithReason(items []preparedTIXTCPTXFrame, maxSegmentPayload int, maxSegments int, maxIPv4Len int) (preparedTIXTCPSocketGSOGroupResult, error) {
	if len(items) == 0 {
		return preparedTIXTCPSocketGSOGroupResult{}, nil
	}
	if maxSegments < 2 || maxIPv4Len < 20+20+tixtcp.HeaderLen*2 {
		return preparedTIXTCPSocketGSOGroupResult{groupLen: 1, reject: preparedTIXTCPSocketGSORejectMaxSegments}, nil
	}
	first, firstReject, err := preparedTIXTCPSocketGSOItemMetaFor(items[0], maxSegmentPayload)
	if err != nil || firstReject != preparedTIXTCPSocketGSORejectNone {
		if firstReject == preparedTIXTCPSocketGSORejectNone {
			firstReject = preparedTIXTCPSocketGSORejectIneligible
		}
		return preparedTIXTCPSocketGSOGroupResult{groupLen: 1, reject: firstReject}, err
	}
	payloadLen := 0
	groupLen := 0
	expectedSeq := first.sequence
	reject := preparedTIXTCPSocketGSORejectNone
	for i := 0; i < len(items) && i < maxSegments; i++ {
		meta, itemReject, err := preparedTIXTCPSocketGSOItemMetaFor(items[i], maxSegmentPayload)
		if err != nil {
			return preparedTIXTCPSocketGSOGroupResult{}, err
		}
		if itemReject != preparedTIXTCPSocketGSORejectNone {
			reject = itemReject
			break
		}
		if meta.src != first.src ||
			meta.dst != first.dst ||
			meta.sourcePort != first.sourcePort ||
			meta.destinationPort != first.destinationPort ||
			meta.ack != first.ack ||
			meta.flowID != first.flowID {
			reject = preparedTIXTCPSocketGSORejectTuple
			break
		}
		if meta.frameLen != first.frameLen {
			reject = preparedTIXTCPSocketGSORejectFrameLen
			break
		}
		if meta.sequence != expectedSeq {
			reject = preparedTIXTCPSocketGSORejectSequence
			break
		}
		nextPayloadLen := payloadLen + meta.frameLen
		if 20+20+nextPayloadLen > maxIPv4Len {
			reject = preparedTIXTCPSocketGSORejectMaxIPv4Len
			break
		}
		payloadLen = nextPayloadLen
		groupLen++
		expectedSeq += uint32(meta.frameLen)
	}
	if reject == preparedTIXTCPSocketGSORejectNone && groupLen == maxSegments && len(items) > maxSegments {
		reject = preparedTIXTCPSocketGSORejectMaxSegments
	}
	if groupLen < 2 {
		if reject == preparedTIXTCPSocketGSORejectNone {
			reject = preparedTIXTCPSocketGSORejectMaxIPv4Len
		}
		return preparedTIXTCPSocketGSOGroupResult{
			groupLen:  1,
			frameLen:  first.frameLen,
			packetLen: first.packetLen,
			reject:    reject,
		}, nil
	}
	return preparedTIXTCPSocketGSOGroupResult{
		groupLen:  groupLen,
		frameLen:  first.frameLen,
		packetLen: 20 + 20 + payloadLen,
		reject:    reject,
	}, nil
}

func marshalPreparedTIXTCPSocketGSOIPv4Into(items []preparedTIXTCPTXFrame, wire []byte) error {
	if len(items) < 2 {
		return fmt.Errorf("tix_tcp socket GSO requires at least two frames")
	}
	group, err := preparedTIXTCPSocketGSOGroupWithReason(items, 0xffff, len(items), 0xffff)
	if err != nil {
		return err
	}
	if group.groupLen != len(items) {
		return fmt.Errorf("tix_tcp socket GSO group is not contiguous: got %d want %d reject=%d", group.groupLen, len(items), group.reject)
	}
	src, dst, sourcePort, destinationPort, err := preparedTIXTCPIPv4Tuple(items[0])
	if err != nil {
		return err
	}
	totalLen := group.packetLen
	if totalLen <= 0 || totalLen > 0xffff {
		return fmt.Errorf("tix_tcp socket GSO packet size %d exceeds IPv4 limit", totalLen)
	}
	if len(wire) < totalLen {
		return fmt.Errorf("tix_tcp socket GSO packet buffer size %d is smaller than wire length %d", len(wire), totalLen)
	}
	wire = wire[:totalLen]
	wire[0] = 0x45
	wire[1] = 0
	binary.BigEndian.PutUint16(wire[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(wire[4:6], 0)
	binary.BigEndian.PutUint16(wire[6:8], 0x4000)
	wire[8] = 64
	wire[9] = unix.IPPROTO_TCP
	binary.BigEndian.PutUint16(wire[10:12], 0)
	copy(wire[12:16], src[:])
	copy(wire[16:20], dst[:])
	binary.BigEndian.PutUint16(wire[10:12], ipv4Checksum20(wire[:20]))

	tcp := wire[20:]
	binary.BigEndian.PutUint16(tcp[0:2], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], destinationPort)
	binary.BigEndian.PutUint32(tcp[4:8], items[0].packet.Sequence)
	binary.BigEndian.PutUint32(tcp[8:12], items[0].packet.Acknowledgment)
	tcp[12] = 0x50
	tcp[13] = 0x18
	binary.BigEndian.PutUint16(tcp[14:16], 0xffff)
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	binary.BigEndian.PutUint16(tcp[18:20], 0)
	cursor := tcp[20:]
	for _, item := range items {
		frameLen, err := preparedTIXTCPFrameWireLen(item)
		if err != nil {
			return err
		}
		if err := marshalPreparedTIXTCPTIXTFrameInto(item, cursor[:frameLen]); err != nil {
			return err
		}
		cursor = cursor[frameLen:]
	}
	binary.BigEndian.PutUint16(tcp[16:18], tcpPseudoHeaderPartialChecksum(wire, len(tcp)))
	return nil
}

func preparePreparedTIXTCPSocketGSOVirtioHeader(header []byte, frameLen int) error {
	if len(header) < virtioNetHdrLen {
		return fmt.Errorf("%w: short tix_tcp socket GSO virtio header", errGSOUnsupported)
	}
	headerLen := ethernetHeaderLen + 20 + 20
	csumStart := ethernetHeaderLen + 20
	if frameLen <= 0 || frameLen > 0xffff || headerLen > 0xffff || csumStart > 0xffff {
		return fmt.Errorf("%w: invalid tix_tcp socket GSO header_len=%d csum_start=%d gso_size=%d", errMTUExceeded, headerLen, csumStart, frameLen)
	}
	clear(header[:virtioNetHdrLen])
	header[0] = unix.VIRTIO_NET_HDR_F_NEEDS_CSUM
	header[1] = unix.VIRTIO_NET_HDR_GSO_TCPV4
	binary.LittleEndian.PutUint16(header[2:4], uint16(headerLen))
	binary.LittleEndian.PutUint16(header[4:6], uint16(frameLen))
	binary.LittleEndian.PutUint16(header[6:8], uint16(csumStart))
	binary.LittleEndian.PutUint16(header[8:10], 16)
	return nil
}
