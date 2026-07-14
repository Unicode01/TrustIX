// Package tixtcp defines the shared wire frame used by TrustIX's
// TCP-shaped TIX-TCP datapath. The outer packet can be emitted by TC/XDP or a
// userspace reinjector; this frame is the stable payload contract between
// userspace crypto and a future kernel crypto implementation.
package tixtcp

import (
	"encoding/binary"
	"fmt"
)

const (
	Magic      uint32 = 0x54495854 // TIXT
	Version    uint8  = 1
	HeaderLen         = 40
	MaxPayload        = 64 * 1024

	FlagEncrypted    uint8 = 1 << 0
	FlagKernelOpened uint8 = 1 << 1
	// FlagCryptoFragment marks encrypted payload fragments that must be
	// reassembled before kernel/userspace crypto open.
	FlagCryptoFragment uint8 = 1 << 2
	// FlagInnerIPv4 marks payloads that are known dataplane IPv4 packets and
	// are eligible for kernel RX direct decapsulation after crypto open.
	FlagInnerIPv4 uint8 = 1 << 3
)

type Frame struct {
	Flags         uint8
	FlowID        uint64
	Epoch         uint64
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
	if payloadLen > MaxPayload {
		return 0, fmt.Errorf("tix_tcp payload size %d exceeds max %d", payloadLen, MaxPayload)
	}
	if payloadLen < 0 {
		return 0, fmt.Errorf("tix_tcp payload size %d is invalid", payloadLen)
	}
	return HeaderLen + payloadLen, nil
}

func (frame Frame) MarshalBinaryInto(wire []byte) (int, error) {
	if len(frame.Payload) > MaxPayload {
		return 0, fmt.Errorf("tix_tcp payload size %d exceeds max %d", len(frame.Payload), MaxPayload)
	}
	wireLen := HeaderLen + len(frame.Payload)
	if len(wire) < wireLen {
		return 0, fmt.Errorf("tix_tcp frame buffer size %d is smaller than wire length %d", len(wire), wireLen)
	}
	wire = wire[:wireLen]
	binary.BigEndian.PutUint32(wire[0:4], Magic)
	wire[4] = Version
	wire[5] = frame.Flags
	binary.BigEndian.PutUint16(wire[6:8], HeaderLen)
	binary.BigEndian.PutUint64(wire[8:16], frame.FlowID)
	binary.BigEndian.PutUint64(wire[16:24], frame.Epoch)
	binary.BigEndian.PutUint64(wire[24:32], frame.Sequence)
	binary.BigEndian.PutUint32(wire[32:36], uint32(len(frame.Payload)))
	binary.BigEndian.PutUint16(wire[36:38], frame.FragmentIndex)
	binary.BigEndian.PutUint16(wire[38:40], frame.FragmentCount)
	copy(wire[HeaderLen:], frame.Payload)
	return wireLen, nil
}

func ParseFrame(wire []byte) (Frame, error) {
	return parseFrame(wire, true)
}

func ParseFrameNoCopy(wire []byte) (Frame, error) {
	return parseFrame(wire, false)
}

func ParseFrameStreamNoCopy(wire []byte) ([]Frame, error) {
	return ParseFrameStreamNoCopyInto(wire, make([]Frame, 0, 1))
}

func ParseFrameStreamNoCopyInto(wire []byte, frames []Frame) ([]Frame, error) {
	frames = frames[:0]
	for cursor := 0; cursor < len(wire); {
		frame, next, err := parseFramePrefix(wire[cursor:], false)
		if err != nil {
			return nil, err
		}
		frames = append(frames, frame)
		cursor += next
	}
	return frames, nil
}

func parseFrame(wire []byte, copyPayload bool) (Frame, error) {
	frame, next, err := parseFramePrefix(wire, copyPayload)
	if err != nil {
		return Frame{}, err
	}
	if next != len(wire) {
		return Frame{}, fmt.Errorf("tix_tcp length mismatch: frame=%d wire=%d", next, len(wire))
	}
	return frame, nil
}

func parseFramePrefix(wire []byte, copyPayload bool) (Frame, int, error) {
	if len(wire) < HeaderLen {
		return Frame{}, 0, fmt.Errorf("tix_tcp frame too short: %d", len(wire))
	}
	if binary.BigEndian.Uint32(wire[0:4]) != Magic {
		return Frame{}, 0, fmt.Errorf("tix_tcp bad magic")
	}
	if wire[4] != Version {
		return Frame{}, 0, fmt.Errorf("tix_tcp version %d is unsupported", wire[4])
	}
	headerLen := int(binary.BigEndian.Uint16(wire[6:8]))
	if headerLen != HeaderLen {
		return Frame{}, 0, fmt.Errorf("tix_tcp header length %d is unsupported", headerLen)
	}
	payloadLen := int(binary.BigEndian.Uint32(wire[32:36]))
	if payloadLen > MaxPayload {
		return Frame{}, 0, fmt.Errorf("tix_tcp payload size %d exceeds max %d", payloadLen, MaxPayload)
	}
	wireLen := HeaderLen + payloadLen
	if len(wire) < wireLen {
		return Frame{}, 0, fmt.Errorf("tix_tcp length mismatch: header payload=%d wire=%d", payloadLen, len(wire))
	}
	payload := wire[HeaderLen:wireLen]
	if copyPayload {
		payload = append([]byte(nil), payload...)
	}
	return Frame{
		Flags:         wire[5],
		FlowID:        binary.BigEndian.Uint64(wire[8:16]),
		Epoch:         binary.BigEndian.Uint64(wire[16:24]),
		Sequence:      binary.BigEndian.Uint64(wire[24:32]),
		FragmentIndex: binary.BigEndian.Uint16(wire[36:38]),
		FragmentCount: binary.BigEndian.Uint16(wire[38:40]),
		Payload:       payload,
	}, wireLen, nil
}
