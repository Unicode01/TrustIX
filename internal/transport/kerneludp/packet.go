package kerneludp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const (
	ipv4HeaderLen = 20
	udpHeaderLen  = 8
)

var ErrChecksum = errors.New("kernel_udp checksum error")

type UDPPacket struct {
	SourceIP        netip.Addr
	DestinationIP   netip.Addr
	SourcePort      uint16
	DestinationPort uint16
	Payload         []byte
}

func MarshalUDPIPv4(packet UDPPacket) ([]byte, error) {
	totalLen, err := UDPIPv4WireLen(len(packet.Payload))
	if err != nil {
		return nil, err
	}
	wire := make([]byte, totalLen)
	if _, err := MarshalUDPIPv4Into(packet, wire); err != nil {
		return nil, err
	}
	return wire, nil
}

func UDPIPv4WireLen(payloadLen int) (int, error) {
	if payloadLen < 0 {
		return 0, fmt.Errorf("kernel_udp payload size %d is invalid", payloadLen)
	}
	udpLen := udpHeaderLen + payloadLen
	totalLen := ipv4HeaderLen + udpLen
	if totalLen > 0xffff || udpLen > 0xffff {
		return 0, fmt.Errorf("kernel_udp packet size %d exceeds IPv4/UDP limit", totalLen)
	}
	return totalLen, nil
}

func MarshalUDPIPv4Into(packet UDPPacket, wire []byte) (int, error) {
	udp, src, dst, totalLen, err := prepareUDPIPv4(packet, len(packet.Payload), wire)
	if err != nil {
		return 0, err
	}
	copy(udp[udpHeaderLen:], packet.Payload)
	checksum := udpChecksum(src, dst, udp)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], checksum)
	return totalLen, nil
}

func MarshalUDPIPv4FrameInto(packet UDPPacket, frame Frame, wire []byte) (int, error) {
	return marshalUDPIPv4FrameInto(packet, frame, wire, false)
}

func MarshalUDPIPv4FrameIntoNoChecksum(packet UDPPacket, frame Frame, wire []byte) (int, error) {
	return marshalUDPIPv4FrameInto(packet, frame, wire, true)
}

func marshalUDPIPv4FrameInto(packet UDPPacket, frame Frame, wire []byte, noChecksum bool) (int, error) {
	frameLen, err := FrameWireLen(len(frame.Payload))
	if err != nil {
		return 0, err
	}
	udp, src, dst, totalLen, err := prepareUDPIPv4(packet, frameLen, wire)
	if err != nil {
		return 0, err
	}
	if _, err := frame.MarshalBinaryInto(udp[udpHeaderLen:]); err != nil {
		return 0, err
	}
	if !noChecksum {
		checksum := udpChecksum(src, dst, udp)
		if checksum == 0 {
			checksum = 0xffff
		}
		binary.BigEndian.PutUint16(udp[6:8], checksum)
	}
	return totalLen, nil
}

func prepareUDPIPv4(packet UDPPacket, payloadLen int, wire []byte) ([]byte, [4]byte, [4]byte, int, error) {
	if !packet.SourceIP.Is4() || !packet.DestinationIP.Is4() {
		return nil, [4]byte{}, [4]byte{}, 0, fmt.Errorf("kernel_udp only supports IPv4 underlay packets")
	}
	if packet.SourcePort == 0 || packet.DestinationPort == 0 {
		return nil, [4]byte{}, [4]byte{}, 0, fmt.Errorf("kernel_udp source and destination ports are required")
	}
	totalLen, err := UDPIPv4WireLen(payloadLen)
	if err != nil {
		return nil, [4]byte{}, [4]byte{}, 0, err
	}
	if len(wire) < totalLen {
		return nil, [4]byte{}, [4]byte{}, 0, fmt.Errorf("kernel_udp packet buffer size %d is smaller than wire length %d", len(wire), totalLen)
	}
	wire = wire[:totalLen]
	wire[0] = 0x45
	wire[1] = 0
	binary.BigEndian.PutUint16(wire[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(wire[4:6], 0)
	binary.BigEndian.PutUint16(wire[6:8], 0x4000)
	wire[8] = 64
	wire[9] = 17
	binary.BigEndian.PutUint16(wire[10:12], 0)
	src := packet.SourceIP.As4()
	dst := packet.DestinationIP.As4()
	copy(wire[12:16], src[:])
	copy(wire[16:20], dst[:])
	binary.BigEndian.PutUint16(wire[10:12], checksum(wire[:ipv4HeaderLen]))

	udp := wire[ipv4HeaderLen:]
	udpLen := udpHeaderLen + payloadLen
	binary.BigEndian.PutUint16(udp[0:2], packet.SourcePort)
	binary.BigEndian.PutUint16(udp[2:4], packet.DestinationPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	binary.BigEndian.PutUint16(udp[6:8], 0)
	return udp, src, dst, totalLen, nil
}

func ParseUDPIPv4(wire []byte) (UDPPacket, error) {
	return parseUDPIPv4(wire, true, false)
}

func ParseUDPIPv4NoCopy(wire []byte) (UDPPacket, error) {
	return parseUDPIPv4(wire, false, false)
}

func ParseUDPIPv4NoCopySkipChecksum(wire []byte) (UDPPacket, error) {
	return parseUDPIPv4(wire, false, true)
}

func parseUDPIPv4(wire []byte, copyPayload bool, skipChecksum bool) (UDPPacket, error) {
	if len(wire) < ipv4HeaderLen+udpHeaderLen {
		return UDPPacket{}, fmt.Errorf("kernel_udp packet too short: %d", len(wire))
	}
	if wire[0]>>4 != 4 {
		return UDPPacket{}, fmt.Errorf("kernel_udp packet is not IPv4")
	}
	ihl := int(wire[0]&0x0f) * 4
	if ihl < ipv4HeaderLen || len(wire) < ihl+udpHeaderLen {
		return UDPPacket{}, fmt.Errorf("kernel_udp invalid IPv4 header length %d", ihl)
	}
	if wire[9] != 17 {
		return UDPPacket{}, fmt.Errorf("kernel_udp IPv4 protocol %d is not UDP", wire[9])
	}
	totalLen := int(binary.BigEndian.Uint16(wire[2:4]))
	if totalLen < ihl+udpHeaderLen || totalLen > len(wire) {
		return UDPPacket{}, fmt.Errorf("kernel_udp invalid IPv4 total length %d", totalLen)
	}
	if !skipChecksum && checksum(wire[:ihl]) != 0 {
		return UDPPacket{}, fmt.Errorf("%w: invalid IPv4 header checksum", ErrChecksum)
	}
	udp := wire[ihl:totalLen]
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < udpHeaderLen || udpLen > len(udp) {
		return UDPPacket{}, fmt.Errorf("kernel_udp invalid UDP length %d", udpLen)
	}
	udp = udp[:udpLen]
	src := netip.AddrFrom4([4]byte{wire[12], wire[13], wire[14], wire[15]})
	dst := netip.AddrFrom4([4]byte{wire[16], wire[17], wire[18], wire[19]})
	got := binary.BigEndian.Uint16(udp[6:8])
	if !skipChecksum && got != 0 && udpChecksum(src.As4(), dst.As4(), udp) != 0 {
		return UDPPacket{}, fmt.Errorf("%w: invalid UDP checksum", ErrChecksum)
	}
	payload := udp[udpHeaderLen:]
	if copyPayload {
		payload = append([]byte(nil), payload...)
	}
	return UDPPacket{
		SourceIP:        src,
		DestinationIP:   dst,
		SourcePort:      binary.BigEndian.Uint16(udp[0:2]),
		DestinationPort: binary.BigEndian.Uint16(udp[2:4]),
		Payload:         payload,
	}, nil
}

func checksum(payload []byte) uint16 {
	return checksumFold(checksumAddBytes(0, payload))
}

func checksumAddBytes(sum uint32, payload []byte) uint32 {
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
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func udpChecksum(src, dst [4]byte, udp []byte) uint16 {
	sum := uint32(0)
	sum = checksumAddBytes(sum, src[:])
	sum = checksumAddBytes(sum, dst[:])
	sum += 17
	sum += uint32(len(udp))
	sum = checksumAddBytes(sum, udp)
	return checksumFold(sum)
}
