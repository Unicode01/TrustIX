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

	"trustix.local/trustix/internal/transport/experimentaltcp"
)

const (
	expTCPSocketGSODefaultMTU          = 1500
	expTCPSocketGSODefaultMaxSegments  = 44
	expTCPSocketGSODefaultMaxIPv4Len   = 0xffff
	expTCPSocketGSODefaultMessageBatch = 64
)

type preparedExperimentalTCPSocketGSOMessage struct {
	start     int
	count     int
	frameLen  int
	packetLen int
	gso       bool
}

type preparedExperimentalTCPSocketGSOGroupResult struct {
	groupLen  int
	packetLen int
	frameLen  int
	reject    preparedExperimentalTCPSocketGSORejectReason
}

type preparedExperimentalTCPSocketGSORejectReason uint8

const (
	preparedExperimentalTCPSocketGSORejectNone preparedExperimentalTCPSocketGSORejectReason = iota
	preparedExperimentalTCPSocketGSORejectIneligible
	preparedExperimentalTCPSocketGSORejectKernelTX
	preparedExperimentalTCPSocketGSORejectKernelOpened
	preparedExperimentalTCPSocketGSORejectNotSecure
	preparedExperimentalTCPSocketGSORejectFlags
	preparedExperimentalTCPSocketGSORejectFragment
	preparedExperimentalTCPSocketGSORejectTuple
	preparedExperimentalTCPSocketGSORejectSequence
	preparedExperimentalTCPSocketGSORejectFrameLen
	preparedExperimentalTCPSocketGSORejectPacketLen
	preparedExperimentalTCPSocketGSORejectMaxSegments
	preparedExperimentalTCPSocketGSORejectMaxIPv4Len
)

type preparedExperimentalTCPSocketGSOItemMeta struct {
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

func experimentalTCPTXSocketGSOEnabled() bool {
	return envTruthy("TRUSTIX_EXPERIMENTAL_TCP_TX_SOCKET_GSO", "TRUSTIX_TIXT_TX_SOCKET_GSO")
}

func experimentalTCPTXSocketGSOMaxSegments() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_EXPERIMENTAL_TCP_TX_SOCKET_GSO_MAX_SEGMENTS"))
	if value == "" {
		value = strings.TrimSpace(os.Getenv("TRUSTIX_TIXT_TX_SOCKET_GSO_MAX_SEGMENTS"))
	}
	if value == "" {
		return expTCPSocketGSODefaultMaxSegments
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 2 {
		return expTCPSocketGSODefaultMaxSegments
	}
	if parsed > 64 {
		return 64
	}
	return parsed
}

func experimentalTCPTXSocketGSOMaxIPv4Len() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_EXPERIMENTAL_TCP_TX_SOCKET_GSO_MAX_IPV4_LEN"))
	if value == "" {
		value = strings.TrimSpace(os.Getenv("TRUSTIX_TIXT_TX_SOCKET_GSO_MAX_IPV4_LEN"))
	}
	if value == "" {
		return expTCPSocketGSODefaultMaxIPv4Len
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 20+20+experimentaltcp.HeaderLen*2 {
		return expTCPSocketGSODefaultMaxIPv4Len
	}
	if parsed > 0xffff {
		return 0xffff
	}
	return parsed
}

func experimentalTCPTXSocketGSOMessageBatchLimit() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_EXPERIMENTAL_TCP_TX_SOCKET_GSO_SENDMMSG"))
	if value == "" {
		value = strings.TrimSpace(os.Getenv("TRUSTIX_TIXT_TX_SOCKET_GSO_SENDMMSG"))
	}
	if value == "" {
		return expTCPSocketGSODefaultMessageBatch
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return expTCPSocketGSODefaultMessageBatch
	}
	if parsed > 256 {
		return 256
	}
	return parsed
}

func (socket *afXDPSocket) sendPreparedExperimentalTCPSocketGSOBatchLocked(items []preparedExperimentalTCPTXFrame, dstMAC net.HardwareAddr) (bool, error) {
	if len(items) < 2 {
		return false, nil
	}
	socket.stats.txSocketGSOAttempts.Add(1)
	if len(socket.linkMAC) < 6 || len(dstMAC) < 6 {
		socket.recordPreparedExperimentalTCPSocketGSOReject(preparedExperimentalTCPSocketGSORejectIneligible)
		return false, nil
	}
	mtu := socket.linkMTU
	if mtu <= 0 {
		mtu = expTCPSocketGSODefaultMTU
	}
	maxSegmentPayload := mtu - 20 - 20
	if maxSegmentPayload < experimentaltcp.HeaderLen {
		socket.recordPreparedExperimentalTCPSocketGSOReject(preparedExperimentalTCPSocketGSORejectFrameLen)
		return false, nil
	}
	maxSegments := experimentalTCPTXSocketGSOMaxSegments()
	maxIPv4Len := experimentalTCPTXSocketGSOMaxIPv4Len()
	messages := make([]preparedExperimentalTCPSocketGSOMessage, 0, len(items))
	gsoMessages := 0
	gsoSegments := 0
	singles := 0
	for i := 0; i < len(items); {
		meta, reject, err := preparedExperimentalTCPSocketGSOItemMetaFor(items[i], maxSegmentPayload)
		if err != nil {
			return false, err
		}
		if reject != preparedExperimentalTCPSocketGSORejectNone {
			socket.recordPreparedExperimentalTCPSocketGSOReject(reject)
			return false, nil
		}
		group, err := preparedExperimentalTCPSocketGSOGroupWithReason(items[i:], maxSegmentPayload, maxSegments, maxIPv4Len)
		if err != nil {
			return false, err
		}
		if group.groupLen >= 2 {
			messages = append(messages, preparedExperimentalTCPSocketGSOMessage{
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
		messages = append(messages, preparedExperimentalTCPSocketGSOMessage{
			start:     i,
			count:     1,
			frameLen:  meta.frameLen,
			packetLen: meta.packetLen,
		})
		if group.reject != preparedExperimentalTCPSocketGSORejectNone {
			socket.recordPreparedExperimentalTCPSocketGSOReject(group.reject)
		}
		singles++
		i++
	}
	if gsoMessages == 0 {
		socket.stats.txSocketGSORejectNoBenefit.Add(1)
		return false, nil
	}
	fd, err := socket.preparedExperimentalTCPSocketGSORawSocketLocked()
	if err != nil {
		socket.stats.txSocketGSOUnsupported.Add(1)
		socket.stats.txSocketGSOFallbacks.Add(1)
		return false, nil
	}
	limit := experimentalTCPTXSocketGSOMessageBatchLimit()
	sentAny := false
	for start := 0; start < len(messages); {
		end := min(start+limit, len(messages))
		handled, err := socket.sendPreparedExperimentalTCPSocketGSOMessageBatchLocked(fd, items, messages[start:end], dstMAC)
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

func (socket *afXDPSocket) sendPreparedExperimentalTCPSocketGSOMessageBatchLocked(fd int, items []preparedExperimentalTCPTXFrame, messages []preparedExperimentalTCPSocketGSOMessage, dstMAC net.HardwareAddr) (bool, error) {
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
			if err := marshalPreparedExperimentalTCPSocketGSOIPv4Into(items[message.start:message.start+message.count], packet); err != nil {
				return false, err
			}
			if err := preparePreparedExperimentalTCPSocketGSOVirtioHeader(header, message.frameLen); err != nil {
				return false, err
			}
		} else if err := marshalPreparedExperimentalTCPIPv4FrameInto(items[message.start], packet, false); err != nil {
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
				socket.disablePreparedExperimentalTCPSocketGSOLocked()
				socket.stats.txSocketGSOUnsupported.Add(1)
				return false, fmt.Errorf("%w: send experimental_tcp raw VNET GSO batch on ifindex=%d: %v", errGSOUnsupported, socket.linkIndex, err)
			}
			return sent > 0, fmt.Errorf("send experimental_tcp raw VNET GSO batch on ifindex=%d: %w", socket.linkIndex, err)
		}
		if n <= 0 {
			runtime.KeepAlive(sendScratch.iovs)
			runtime.KeepAlive(sendScratch.headers)
			runtime.KeepAlive(sendScratch.ethernets)
			runtime.KeepAlive(packetScratch.arena)
			return sent > 0, fmt.Errorf("send experimental_tcp raw VNET GSO batch on ifindex=%d: %w", socket.linkIndex, unix.EIO)
		}
	}
	runtime.KeepAlive(sendScratch.iovs)
	runtime.KeepAlive(sendScratch.headers)
	runtime.KeepAlive(sendScratch.ethernets)
	runtime.KeepAlive(packetScratch.arena)
	return true, nil
}

func (socket *afXDPSocket) preparedExperimentalTCPSocketGSORawSocketLocked() (int, error) {
	if socket.txSocketGSODisabled {
		return -1, fmt.Errorf("%w for experimental_tcp raw packet socket", errGSOUnsupported)
	}
	if socket.txSocketGSOFDValid && socket.txSocketGSOFD >= 0 {
		return socket.txSocketGSOFD, nil
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(etherTypeIPv4)))
	if err != nil {
		socket.txSocketGSODisabled = true
		return -1, fmt.Errorf("%w: open experimental_tcp raw packet socket: %v", errGSOUnsupported, err)
	}
	if err := configureGSOPacketSocket(fd); err != nil {
		_ = unix.Close(fd)
		socket.txSocketGSODisabled = true
		return -1, fmt.Errorf("%w: configure experimental_tcp raw packet GSO socket: %v", errGSOUnsupported, err)
	}
	socket.txSocketGSOFD = fd
	socket.txSocketGSOFDValid = true
	return fd, nil
}

func (socket *afXDPSocket) disablePreparedExperimentalTCPSocketGSOLocked() {
	socket.txSocketGSODisabled = true
	if socket.txSocketGSOFDValid && socket.txSocketGSOFD >= 0 {
		_ = unix.Close(socket.txSocketGSOFD)
	}
	socket.txSocketGSOFD = -1
	socket.txSocketGSOFDValid = false
}

func (socket *afXDPSocket) recordPreparedExperimentalTCPSocketGSOReject(reason preparedExperimentalTCPSocketGSORejectReason) {
	if reason == preparedExperimentalTCPSocketGSORejectNone {
		return
	}
	socket.stats.txSocketGSORejectIneligible.Add(1)
	switch reason {
	case preparedExperimentalTCPSocketGSORejectKernelTX:
		socket.stats.txSocketGSORejectKernelTX.Add(1)
	case preparedExperimentalTCPSocketGSORejectKernelOpened:
		socket.stats.txSocketGSORejectKernelOpened.Add(1)
	case preparedExperimentalTCPSocketGSORejectNotSecure:
		socket.stats.txSocketGSORejectNotSecure.Add(1)
	case preparedExperimentalTCPSocketGSORejectFlags:
		socket.stats.txSocketGSORejectFlags.Add(1)
	case preparedExperimentalTCPSocketGSORejectFragment:
		socket.stats.txSocketGSORejectFragment.Add(1)
	case preparedExperimentalTCPSocketGSORejectTuple:
		socket.stats.txSocketGSORejectTuple.Add(1)
	case preparedExperimentalTCPSocketGSORejectSequence:
		socket.stats.txSocketGSORejectSequence.Add(1)
	case preparedExperimentalTCPSocketGSORejectFrameLen:
		socket.stats.txSocketGSORejectFrameLen.Add(1)
	case preparedExperimentalTCPSocketGSORejectPacketLen:
		socket.stats.txSocketGSORejectPacketLen.Add(1)
	case preparedExperimentalTCPSocketGSORejectMaxSegments:
		socket.stats.txSocketGSORejectMaxSegments.Add(1)
	case preparedExperimentalTCPSocketGSORejectMaxIPv4Len:
		socket.stats.txSocketGSORejectMaxIPv4Len.Add(1)
	}
}

func preparedExperimentalTCPSocketGSOItemMetaFor(item preparedExperimentalTCPTXFrame, maxSegmentPayload int) (preparedExperimentalTCPSocketGSOItemMeta, preparedExperimentalTCPSocketGSORejectReason, error) {
	if item.kernelTX {
		return preparedExperimentalTCPSocketGSOItemMeta{}, preparedExperimentalTCPSocketGSORejectKernelTX, nil
	}
	frame := item.wireFrame
	if frame.Flags&experimentaltcp.FlagKernelOpened != 0 {
		return preparedExperimentalTCPSocketGSOItemMeta{}, preparedExperimentalTCPSocketGSORejectKernelOpened, nil
	}
	encryptedFrame := frame.Flags&experimentaltcp.FlagEncrypted != 0
	userspaceSecurePayload := experimentalTCPUserspaceSecurePayload(frame.Payload)
	fragmentedPayload := frame.FragmentCount > 1
	if !encryptedFrame && !userspaceSecurePayload && !fragmentedPayload {
		return preparedExperimentalTCPSocketGSOItemMeta{}, preparedExperimentalTCPSocketGSORejectNotSecure, nil
	}
	if frame.Flags&^(experimentaltcp.FlagEncrypted|experimentaltcp.FlagCryptoFragment|experimentaltcp.FlagInnerIPv4) != 0 {
		return preparedExperimentalTCPSocketGSOItemMeta{}, preparedExperimentalTCPSocketGSORejectFlags, nil
	}
	if frame.FragmentCount == 0 {
		if frame.FragmentIndex != 0 || frame.Flags&experimentaltcp.FlagCryptoFragment != 0 {
			return preparedExperimentalTCPSocketGSOItemMeta{}, preparedExperimentalTCPSocketGSORejectFragment, nil
		}
	} else if frame.FragmentCount == 1 {
		if frame.FragmentIndex != 0 {
			return preparedExperimentalTCPSocketGSOItemMeta{}, preparedExperimentalTCPSocketGSORejectFragment, nil
		}
	} else if frame.FragmentIndex >= frame.FragmentCount {
		return preparedExperimentalTCPSocketGSOItemMeta{}, preparedExperimentalTCPSocketGSORejectFragment, nil
	}
	frameLen, err := preparedExperimentalTCPFrameWireLen(item)
	if err != nil {
		return preparedExperimentalTCPSocketGSOItemMeta{}, preparedExperimentalTCPSocketGSORejectFrameLen, err
	}
	if frameLen <= 0 || frameLen > maxSegmentPayload {
		return preparedExperimentalTCPSocketGSOItemMeta{}, preparedExperimentalTCPSocketGSORejectFrameLen, nil
	}
	src, dst, sourcePort, destinationPort, err := preparedExperimentalTCPIPv4Tuple(item)
	if err != nil {
		return preparedExperimentalTCPSocketGSOItemMeta{}, preparedExperimentalTCPSocketGSORejectTuple, err
	}
	packetLen := item.packetLen
	if packetLen <= 0 {
		packetLen = 20 + 20 + frameLen
	}
	if packetLen != 20+20+frameLen || packetLen > 0xffff {
		return preparedExperimentalTCPSocketGSOItemMeta{}, preparedExperimentalTCPSocketGSORejectPacketLen, nil
	}
	return preparedExperimentalTCPSocketGSOItemMeta{
		src:             src,
		dst:             dst,
		sourcePort:      sourcePort,
		destinationPort: destinationPort,
		ack:             item.packet.Acknowledgment,
		sequence:        item.packet.Sequence,
		flowID:          frame.FlowID,
		frameLen:        frameLen,
		packetLen:       packetLen,
	}, preparedExperimentalTCPSocketGSORejectNone, nil
}

func preparedExperimentalTCPSocketGSOGroupWithReason(items []preparedExperimentalTCPTXFrame, maxSegmentPayload int, maxSegments int, maxIPv4Len int) (preparedExperimentalTCPSocketGSOGroupResult, error) {
	if len(items) == 0 {
		return preparedExperimentalTCPSocketGSOGroupResult{}, nil
	}
	if maxSegments < 2 || maxIPv4Len < 20+20+experimentaltcp.HeaderLen*2 {
		return preparedExperimentalTCPSocketGSOGroupResult{groupLen: 1, reject: preparedExperimentalTCPSocketGSORejectMaxSegments}, nil
	}
	first, firstReject, err := preparedExperimentalTCPSocketGSOItemMetaFor(items[0], maxSegmentPayload)
	if err != nil || firstReject != preparedExperimentalTCPSocketGSORejectNone {
		if firstReject == preparedExperimentalTCPSocketGSORejectNone {
			firstReject = preparedExperimentalTCPSocketGSORejectIneligible
		}
		return preparedExperimentalTCPSocketGSOGroupResult{groupLen: 1, reject: firstReject}, err
	}
	payloadLen := 0
	groupLen := 0
	expectedSeq := first.sequence
	reject := preparedExperimentalTCPSocketGSORejectNone
	for i := 0; i < len(items) && i < maxSegments; i++ {
		meta, itemReject, err := preparedExperimentalTCPSocketGSOItemMetaFor(items[i], maxSegmentPayload)
		if err != nil {
			return preparedExperimentalTCPSocketGSOGroupResult{}, err
		}
		if itemReject != preparedExperimentalTCPSocketGSORejectNone {
			reject = itemReject
			break
		}
		if meta.src != first.src ||
			meta.dst != first.dst ||
			meta.sourcePort != first.sourcePort ||
			meta.destinationPort != first.destinationPort ||
			meta.ack != first.ack ||
			meta.flowID != first.flowID {
			reject = preparedExperimentalTCPSocketGSORejectTuple
			break
		}
		if meta.frameLen != first.frameLen {
			reject = preparedExperimentalTCPSocketGSORejectFrameLen
			break
		}
		if meta.sequence != expectedSeq {
			reject = preparedExperimentalTCPSocketGSORejectSequence
			break
		}
		nextPayloadLen := payloadLen + meta.frameLen
		if 20+20+nextPayloadLen > maxIPv4Len {
			reject = preparedExperimentalTCPSocketGSORejectMaxIPv4Len
			break
		}
		payloadLen = nextPayloadLen
		groupLen++
		expectedSeq += uint32(meta.frameLen)
	}
	if reject == preparedExperimentalTCPSocketGSORejectNone && groupLen == maxSegments && len(items) > maxSegments {
		reject = preparedExperimentalTCPSocketGSORejectMaxSegments
	}
	if groupLen < 2 {
		if reject == preparedExperimentalTCPSocketGSORejectNone {
			reject = preparedExperimentalTCPSocketGSORejectMaxIPv4Len
		}
		return preparedExperimentalTCPSocketGSOGroupResult{
			groupLen:  1,
			frameLen:  first.frameLen,
			packetLen: first.packetLen,
			reject:    reject,
		}, nil
	}
	return preparedExperimentalTCPSocketGSOGroupResult{
		groupLen:  groupLen,
		frameLen:  first.frameLen,
		packetLen: 20 + 20 + payloadLen,
		reject:    reject,
	}, nil
}

func marshalPreparedExperimentalTCPSocketGSOIPv4Into(items []preparedExperimentalTCPTXFrame, wire []byte) error {
	if len(items) < 2 {
		return fmt.Errorf("experimental_tcp socket GSO requires at least two frames")
	}
	group, err := preparedExperimentalTCPSocketGSOGroupWithReason(items, 0xffff, len(items), 0xffff)
	if err != nil {
		return err
	}
	if group.groupLen != len(items) {
		return fmt.Errorf("experimental_tcp socket GSO group is not contiguous: got %d want %d reject=%d", group.groupLen, len(items), group.reject)
	}
	src, dst, sourcePort, destinationPort, err := preparedExperimentalTCPIPv4Tuple(items[0])
	if err != nil {
		return err
	}
	totalLen := group.packetLen
	if totalLen <= 0 || totalLen > 0xffff {
		return fmt.Errorf("experimental_tcp socket GSO packet size %d exceeds IPv4 limit", totalLen)
	}
	if len(wire) < totalLen {
		return fmt.Errorf("experimental_tcp socket GSO packet buffer size %d is smaller than wire length %d", len(wire), totalLen)
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
		frameLen, err := preparedExperimentalTCPFrameWireLen(item)
		if err != nil {
			return err
		}
		if err := marshalPreparedExperimentalTCPTIXTFrameInto(item, cursor[:frameLen]); err != nil {
			return err
		}
		cursor = cursor[frameLen:]
	}
	binary.BigEndian.PutUint16(tcp[16:18], tcpPseudoHeaderPartialChecksum(wire, len(tcp)))
	return nil
}

func preparePreparedExperimentalTCPSocketGSOVirtioHeader(header []byte, frameLen int) error {
	if len(header) < virtioNetHdrLen {
		return fmt.Errorf("%w: short experimental_tcp socket GSO virtio header", errGSOUnsupported)
	}
	headerLen := ethernetHeaderLen + 20 + 20
	csumStart := ethernetHeaderLen + 20
	if frameLen <= 0 || frameLen > 0xffff || headerLen > 0xffff || csumStart > 0xffff {
		return fmt.Errorf("%w: invalid experimental_tcp socket GSO header_len=%d csum_start=%d gso_size=%d", errMTUExceeded, headerLen, csumStart, frameLen)
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
