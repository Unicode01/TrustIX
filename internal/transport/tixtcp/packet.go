package tixtcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const (
	ipv4HeaderLen = 20
	tcpHeaderLen  = 20
	tcpFlagPSHACK = 0x18
)

var ErrChecksum = errors.New("tix_tcp checksum error")

type TCPPacket struct {
	SourceIP        netip.Addr
	DestinationIP   netip.Addr
	SourcePort      uint16
	DestinationPort uint16
	Sequence        uint32
	Acknowledgment  uint32
	Payload         []byte
}

func MarshalTCPShapedIPv4(packet TCPPacket) ([]byte, error) {
	totalLen, err := TCPShapedIPv4WireLen(len(packet.Payload))
	if err != nil {
		return nil, err
	}
	wire := make([]byte, totalLen)
	if _, err := MarshalTCPShapedIPv4Into(packet, wire); err != nil {
		return nil, err
	}
	return wire, nil
}

func TCPShapedIPv4WireLen(payloadLen int) (int, error) {
	if payloadLen < 0 {
		return 0, fmt.Errorf("tix_tcp payload size %d is invalid", payloadLen)
	}
	totalLen := ipv4HeaderLen + tcpHeaderLen + payloadLen
	if totalLen > 0xffff {
		return 0, fmt.Errorf("tix_tcp packet size %d exceeds IPv4 limit", totalLen)
	}
	return totalLen, nil
}

func MarshalTCPShapedIPv4Into(packet TCPPacket, wire []byte) (int, error) {
	tcp, src, dst, totalLen, err := prepareTCPShapedIPv4(packet, len(packet.Payload), wire)
	if err != nil {
		return 0, err
	}
	copy(tcp[tcpHeaderLen:], packet.Payload)
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(src, dst, tcp))
	return totalLen, nil
}

func MarshalTCPShapedIPv4FrameInto(packet TCPPacket, frame Frame, wire []byte) (int, error) {
	return marshalTCPShapedIPv4FrameInto(packet, frame, wire, false)
}

func MarshalTCPShapedIPv4FrameIntoSkipTCPChecksum(packet TCPPacket, frame Frame, wire []byte) (int, error) {
	return marshalTCPShapedIPv4FrameInto(packet, frame, wire, true)
}

func marshalTCPShapedIPv4FrameInto(packet TCPPacket, frame Frame, wire []byte, skipTCPChecksum bool) (int, error) {
	frameLen, err := FrameWireLen(len(frame.Payload))
	if err != nil {
		return 0, err
	}
	tcp, src, dst, totalLen, err := prepareTCPShapedIPv4(packet, frameLen, wire)
	if err != nil {
		return 0, err
	}
	if _, err := frame.MarshalBinaryInto(tcp[tcpHeaderLen:]); err != nil {
		return 0, err
	}
	if !skipTCPChecksum {
		binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(src, dst, tcp))
	}
	return totalLen, nil
}

func prepareTCPShapedIPv4(packet TCPPacket, payloadLen int, wire []byte) ([]byte, [4]byte, [4]byte, int, error) {
	if !packet.SourceIP.Is4() || !packet.DestinationIP.Is4() {
		return nil, [4]byte{}, [4]byte{}, 0, fmt.Errorf("tix_tcp only supports IPv4 underlay packets")
	}
	if packet.SourcePort == 0 || packet.DestinationPort == 0 {
		return nil, [4]byte{}, [4]byte{}, 0, fmt.Errorf("tix_tcp source and destination ports are required")
	}
	totalLen, err := TCPShapedIPv4WireLen(payloadLen)
	if err != nil {
		return nil, [4]byte{}, [4]byte{}, 0, err
	}
	if len(wire) < totalLen {
		return nil, [4]byte{}, [4]byte{}, 0, fmt.Errorf("tix_tcp packet buffer size %d is smaller than wire length %d", len(wire), totalLen)
	}
	wire = wire[:totalLen]
	wire[0] = 0x45
	wire[1] = 0
	binary.BigEndian.PutUint16(wire[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(wire[4:6], 0)
	binary.BigEndian.PutUint16(wire[6:8], 0x4000)
	wire[8] = 64
	wire[9] = 6
	binary.BigEndian.PutUint16(wire[10:12], 0)
	src := packet.SourceIP.As4()
	dst := packet.DestinationIP.As4()
	copy(wire[12:16], src[:])
	copy(wire[16:20], dst[:])
	binary.BigEndian.PutUint16(wire[10:12], checksum(wire[:ipv4HeaderLen]))

	tcp := wire[ipv4HeaderLen:]
	binary.BigEndian.PutUint16(tcp[0:2], packet.SourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], packet.DestinationPort)
	binary.BigEndian.PutUint32(tcp[4:8], packet.Sequence)
	binary.BigEndian.PutUint32(tcp[8:12], packet.Acknowledgment)
	tcp[12] = byte((tcpHeaderLen / 4) << 4)
	tcp[13] = tcpFlagPSHACK
	binary.BigEndian.PutUint16(tcp[14:16], 0xffff)
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	binary.BigEndian.PutUint16(tcp[18:20], 0)
	return tcp, src, dst, totalLen, nil
}

func ParseTCPShapedIPv4(wire []byte) (TCPPacket, error) {
	return parseTCPShapedIPv4(wire, true, false)
}

func ParseTCPShapedIPv4NoCopy(wire []byte) (TCPPacket, error) {
	return parseTCPShapedIPv4(wire, false, false)
}

func ParseTCPShapedIPv4NoCopySkipTCPChecksum(wire []byte) (TCPPacket, error) {
	return parseTCPShapedIPv4(wire, false, true)
}

func parseTCPShapedIPv4(wire []byte, copyPayload bool, skipTCPChecksum bool) (TCPPacket, error) {
	if len(wire) < ipv4HeaderLen+tcpHeaderLen {
		return TCPPacket{}, fmt.Errorf("tix_tcp packet too short: %d", len(wire))
	}
	if wire[0]>>4 != 4 {
		return TCPPacket{}, fmt.Errorf("tix_tcp packet is not IPv4")
	}
	ihl := int(wire[0]&0x0f) * 4
	if ihl < ipv4HeaderLen || len(wire) < ihl+tcpHeaderLen {
		return TCPPacket{}, fmt.Errorf("tix_tcp invalid IPv4 header length %d", ihl)
	}
	if wire[9] != 6 {
		return TCPPacket{}, fmt.Errorf("tix_tcp IPv4 protocol %d is not TCP", wire[9])
	}
	totalLen := int(binary.BigEndian.Uint16(wire[2:4]))
	if totalLen < ihl+tcpHeaderLen || totalLen > len(wire) {
		return TCPPacket{}, fmt.Errorf("tix_tcp invalid IPv4 total length %d", totalLen)
	}
	if checksum(wire[:ihl]) != 0 {
		return TCPPacket{}, fmt.Errorf("%w: invalid IPv4 header checksum", ErrChecksum)
	}
	tcp := wire[ihl:totalLen]
	dataOffset := int(tcp[12]>>4) * 4
	if dataOffset < tcpHeaderLen || len(tcp) < dataOffset {
		return TCPPacket{}, fmt.Errorf("tix_tcp invalid TCP data offset %d", dataOffset)
	}
	src := netip.AddrFrom4([4]byte{wire[12], wire[13], wire[14], wire[15]})
	dst := netip.AddrFrom4([4]byte{wire[16], wire[17], wire[18], wire[19]})
	if !skipTCPChecksum {
		got, want := binary.BigEndian.Uint16(tcp[16:18]), tcpChecksum(src.As4(), dst.As4(), tcp)
		if got != want {
			return TCPPacket{}, fmt.Errorf("%w: invalid TCP checksum", ErrChecksum)
		}
	}
	payload := tcp[dataOffset:]
	if copyPayload {
		payload = append([]byte(nil), payload...)
	}
	return TCPPacket{
		SourceIP:        src,
		DestinationIP:   dst,
		SourcePort:      binary.BigEndian.Uint16(tcp[0:2]),
		DestinationPort: binary.BigEndian.Uint16(tcp[2:4]),
		Sequence:        binary.BigEndian.Uint32(tcp[4:8]),
		Acknowledgment:  binary.BigEndian.Uint32(tcp[8:12]),
		Payload:         payload,
	}, nil
}

func checksum(payload []byte) uint16 {
	return checksumFold(checksumAddBytes(0, payload))
}

func checksumAddBytes(sum uint32, payload []byte) uint32 {
	for len(payload) >= 32 {
		sum += uint32(binary.BigEndian.Uint16(payload[0:2]))
		sum += uint32(binary.BigEndian.Uint16(payload[2:4]))
		sum += uint32(binary.BigEndian.Uint16(payload[4:6]))
		sum += uint32(binary.BigEndian.Uint16(payload[6:8]))
		sum += uint32(binary.BigEndian.Uint16(payload[8:10]))
		sum += uint32(binary.BigEndian.Uint16(payload[10:12]))
		sum += uint32(binary.BigEndian.Uint16(payload[12:14]))
		sum += uint32(binary.BigEndian.Uint16(payload[14:16]))
		sum += uint32(binary.BigEndian.Uint16(payload[16:18]))
		sum += uint32(binary.BigEndian.Uint16(payload[18:20]))
		sum += uint32(binary.BigEndian.Uint16(payload[20:22]))
		sum += uint32(binary.BigEndian.Uint16(payload[22:24]))
		sum += uint32(binary.BigEndian.Uint16(payload[24:26]))
		sum += uint32(binary.BigEndian.Uint16(payload[26:28]))
		sum += uint32(binary.BigEndian.Uint16(payload[28:30]))
		sum += uint32(binary.BigEndian.Uint16(payload[30:32]))
		payload = payload[32:]
	}
	for len(payload) >= 8 {
		value := binary.BigEndian.Uint64(payload[:8])
		sum += uint32(value >> 48)
		sum += uint32((value >> 32) & 0xffff)
		sum += uint32((value >> 16) & 0xffff)
		sum += uint32(value & 0xffff)
		payload = payload[8:]
	}
	for len(payload) > 1 {
		sum += uint32(binary.BigEndian.Uint16(payload[:2]))
		payload = payload[2:]
	}
	if len(payload) == 1 {
		sum += uint32(payload[0]) << 8
	}
	return sum
}

func checksumFold(sum uint32) uint16 {
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tcpChecksum(src, dst [4]byte, tcp []byte) uint16 {
	sum := uint32(0)
	sum = checksumAddBytes(sum, src[:])
	sum = checksumAddBytes(sum, dst[:])
	sum += 6
	sum += uint32(len(tcp))
	if len(tcp) <= 16 {
		sum = checksumAddBytes(sum, tcp)
		return checksumFold(sum)
	}
	sum = checksumAddBytes(sum, tcp[:16])
	if len(tcp) > 18 {
		sum = checksumAddBytes(sum, tcp[18:])
	}
	return checksumFold(sum)
}
