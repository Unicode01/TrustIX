package kerneludp

import (
	"encoding/binary"
	"fmt"
)

const (
	Magic      uint32 = 0x54495855 // TIXU
	Version    uint8  = 1
	HeaderLen         = 32
	MaxPayload        = 64 * 1024

	FlagEncrypted    uint8 = 1 << 0
	FlagKernelOpened uint8 = 1 << 1
	// FlagCryptoFragment marks UDP fragments that together form one encrypted
	// TrustIX secure frame. The receiver reassembles these before AEAD open.
	FlagCryptoFragment uint8 = 1 << 2
	// FlagInnerIPv4 marks payloads that are known dataplane IPv4 packets and
	// are eligible for kernel RX direct decapsulation after crypto open.
	FlagInnerIPv4 uint8 = 1 << 3
)

type Frame struct {
	Flags         uint8
	FlowID        uint64
	Sequence      uint64
	FragmentIndex uint16
	FragmentCount uint16
	Payload       []byte
}

func (frame Frame) MarshalBinary() ([]byte, error) {
	wireLen, err := FrameWireLen(len(frame.Payload))
	if err != nil {
		return nil, err
	}
	wire := make([]byte, wireLen)
	if _, err := frame.MarshalBinaryInto(wire); err != nil {
		return nil, err
	}
	return wire, nil
}

func FrameWireLen(payloadLen int) (int, error) {
	if payloadLen < 0 {
		return 0, fmt.Errorf("kernel_udp payload size %d is invalid", payloadLen)
	}
	if payloadLen > MaxPayload {
		return 0, fmt.Errorf("kernel_udp payload size %d exceeds max %d", payloadLen, MaxPayload)
	}
	return HeaderLen + payloadLen, nil
}

func (frame Frame) MarshalBinaryInto(wire []byte) (int, error) {
	if len(frame.Payload) > MaxPayload {
		return 0, fmt.Errorf("kernel_udp payload size %d exceeds max %d", len(frame.Payload), MaxPayload)
	}
	wireLen := HeaderLen + len(frame.Payload)
	if len(wire) < wireLen {
		return 0, fmt.Errorf("kernel_udp frame buffer size %d is smaller than wire length %d", len(wire), wireLen)
	}
	wire = wire[:wireLen]
	if _, err := frame.MarshalHeaderInto(wire[:HeaderLen]); err != nil {
		return 0, err
	}
	copy(wire[HeaderLen:], frame.Payload)
	return wireLen, nil
}

func (frame Frame) MarshalHeaderInto(wire []byte) (int, error) {
	if len(frame.Payload) > MaxPayload {
		return 0, fmt.Errorf("kernel_udp payload size %d exceeds max %d", len(frame.Payload), MaxPayload)
	}
	if len(wire) < HeaderLen {
		return 0, fmt.Errorf("kernel_udp frame header buffer size %d is smaller than header length %d", len(wire), HeaderLen)
	}
	wire = wire[:HeaderLen]
	binary.BigEndian.PutUint32(wire[0:4], Magic)
	wire[4] = Version
	wire[5] = frame.Flags
	binary.BigEndian.PutUint16(wire[6:8], HeaderLen)
	binary.BigEndian.PutUint64(wire[8:16], frame.FlowID)
	binary.BigEndian.PutUint64(wire[16:24], frame.Sequence)
	binary.BigEndian.PutUint32(wire[24:28], uint32(len(frame.Payload)))
	binary.BigEndian.PutUint16(wire[28:30], frame.FragmentIndex)
	binary.BigEndian.PutUint16(wire[30:32], frame.FragmentCount)
	return HeaderLen, nil
}

func ParseFrame(wire []byte) (Frame, error) {
	return parseFrame(wire, true)
}

func ParseFrameNoCopy(wire []byte) (Frame, error) {
	return parseFrame(wire, false)
}

func parseFrame(wire []byte, copyPayload bool) (Frame, error) {
	if len(wire) < HeaderLen {
		return Frame{}, fmt.Errorf("kernel_udp frame too short: %d", len(wire))
	}
	if binary.BigEndian.Uint32(wire[0:4]) != Magic {
		return Frame{}, fmt.Errorf("kernel_udp bad magic")
	}
	if wire[4] != Version {
		return Frame{}, fmt.Errorf("kernel_udp version %d is unsupported", wire[4])
	}
	headerLen := int(binary.BigEndian.Uint16(wire[6:8]))
	if headerLen != HeaderLen {
		return Frame{}, fmt.Errorf("kernel_udp header length %d is unsupported", headerLen)
	}
	payloadLen := int(binary.BigEndian.Uint32(wire[24:28]))
	if payloadLen > MaxPayload {
		return Frame{}, fmt.Errorf("kernel_udp payload size %d exceeds max %d", payloadLen, MaxPayload)
	}
	if len(wire) != HeaderLen+payloadLen {
		return Frame{}, fmt.Errorf("kernel_udp length mismatch: header payload=%d wire=%d", payloadLen, len(wire))
	}
	payload := wire[HeaderLen:]
	if copyPayload {
		payload = append([]byte(nil), payload...)
	}
	return Frame{
		Flags:         wire[5],
		FlowID:        binary.BigEndian.Uint64(wire[8:16]),
		Sequence:      binary.BigEndian.Uint64(wire[16:24]),
		FragmentIndex: binary.BigEndian.Uint16(wire[28:30]),
		FragmentCount: binary.BigEndian.Uint16(wire[30:32]),
		Payload:       payload,
	}, nil
}
