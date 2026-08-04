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
	// FlagInnerL4ChecksumValid is the legacy full-kmod plaintext meaning of
	// bit 1. Receivers disambiguate it from FlagKernelOpened with the flow's
	// crypto placement; the alias preserves the version 1 wire contract.
	FlagInnerL4ChecksumValid uint8 = FlagKernelOpened
	// FlagCryptoFragment marks encrypted payload fragments that must be
	// reassembled before kernel/userspace crypto open.
	FlagCryptoFragment uint8 = 1 << 2
	// FlagInnerIPv4 marks payloads that are known dataplane IPv4 packets and
	// are eligible for kernel RX direct decapsulation after crypto open.
	FlagInnerIPv4 uint8 = 1 << 3
	// FlagInnerTCPChecksumPartial marks a plaintext inner IPv4/TCP packet whose
	// TCP checksum field contains the CHECKSUM_PARTIAL pseudo-header seed.
	FlagInnerTCPChecksumPartial uint8 = 1 << 4
	// FlagInnerGSO marks one plaintext inner IPv4/TCP GSO packet. For this flag,
	// FragmentIndex carries gso_size and FragmentCount carries gso_segs.
	FlagInnerGSO uint8 = 1 << 5
	KnownFlags         = FlagEncrypted | FlagKernelOpened |
		FlagCryptoFragment | FlagInnerIPv4 | FlagInnerTCPChecksumPartial |
		FlagInnerGSO
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
	if err := validateFrameFlags(frame.Flags, frame.FragmentIndex, frame.FragmentCount); err != nil {
		return 0, err
	}
	if frame.Flags&FlagInnerGSO != 0 {
		if err := ValidateInnerTCPGSO(frame.Payload, frame.FragmentIndex, frame.FragmentCount); err != nil {
			return 0, err
		}
	} else if frame.Flags&FlagInnerTCPChecksumPartial != 0 {
		if err := ValidateInnerTCPChecksumPartial(frame.Payload); err != nil {
			return 0, err
		}
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
	flags := wire[5]
	fragmentIndex := binary.BigEndian.Uint16(wire[36:38])
	fragmentCount := binary.BigEndian.Uint16(wire[38:40])
	if err := validateFrameFlags(flags, fragmentIndex, fragmentCount); err != nil {
		return Frame{}, 0, err
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
	if flags&FlagInnerGSO != 0 {
		if err := ValidateInnerTCPGSO(payload, fragmentIndex, fragmentCount); err != nil {
			return Frame{}, 0, err
		}
	} else if flags&FlagInnerTCPChecksumPartial != 0 {
		if err := ValidateInnerTCPChecksumPartial(payload); err != nil {
			return Frame{}, 0, err
		}
	}
	if copyPayload {
		payload = append([]byte(nil), payload...)
	}
	return Frame{
		Flags:         flags,
		FlowID:        binary.BigEndian.Uint64(wire[8:16]),
		Epoch:         binary.BigEndian.Uint64(wire[16:24]),
		Sequence:      binary.BigEndian.Uint64(wire[24:32]),
		FragmentIndex: fragmentIndex,
		FragmentCount: fragmentCount,
		Payload:       payload,
	}, wireLen, nil
}

func validateFrameFlags(flags uint8, fragmentIndex, fragmentCount uint16) error {
	if unknown := flags &^ KnownFlags; unknown != 0 {
		return fmt.Errorf("tix_tcp flags %#x contain unsupported bits %#x", flags, unknown)
	}
	if flags&FlagInnerGSO != 0 {
		if flags&(FlagInnerIPv4|FlagInnerTCPChecksumPartial) != FlagInnerIPv4|FlagInnerTCPChecksumPartial ||
			flags&(FlagEncrypted|FlagKernelOpened|FlagCryptoFragment) != 0 {
			return fmt.Errorf("tix_tcp inner GSO flag has incompatible frame flags %#x", flags)
		}
		if fragmentIndex == 0 || fragmentCount < 2 {
			return fmt.Errorf("tix_tcp inner GSO metadata size=%d segments=%d is invalid", fragmentIndex, fragmentCount)
		}
		return nil
	}
	if fragmentCount == 0 {
		if fragmentIndex != 0 {
			return fmt.Errorf("tix_tcp fragment index %d requires a fragment count", fragmentIndex)
		}
		if flags&FlagCryptoFragment != 0 {
			return fmt.Errorf("tix_tcp crypto fragment flag requires a fragment count")
		}
	} else if fragmentIndex >= fragmentCount {
		return fmt.Errorf("tix_tcp fragment index %d is outside count %d", fragmentIndex, fragmentCount)
	}
	if flags&FlagInnerTCPChecksumPartial == 0 {
		return nil
	}
	if flags&FlagInnerIPv4 == 0 ||
		flags&(FlagEncrypted|FlagKernelOpened|FlagCryptoFragment) != 0 ||
		fragmentIndex != 0 || fragmentCount != 0 {
		return fmt.Errorf("tix_tcp inner TCP checksum-partial flag has incompatible frame metadata")
	}
	return nil
}

// ValidateInnerTCPGSO validates a plaintext IPv4/TCP GSO payload and the
// gso_size/gso_segs values carried in the TIXT fragment fields.
func ValidateInnerTCPGSO(packet []byte, gsoSize, gsoSegs uint16) error {
	_, _, ipHeaderLen, totalLen, err := innerTCPChecksumPartialMeta(packet)
	if err != nil {
		return err
	}
	if gsoSize == 0 || gsoSegs < 2 {
		return fmt.Errorf("tix_tcp inner GSO metadata size=%d segments=%d is invalid", gsoSize, gsoSegs)
	}
	tcp := packet[ipHeaderLen:totalLen]
	tcpHeaderLen := int(tcp[12]>>4) * 4
	payloadLen := len(tcp) - tcpHeaderLen
	if payloadLen <= 0 {
		return fmt.Errorf("tix_tcp inner GSO packet has no TCP payload")
	}
	wantSegs := (payloadLen + int(gsoSize) - 1) / int(gsoSize)
	if wantSegs < 2 || wantSegs != int(gsoSegs) {
		return fmt.Errorf("tix_tcp inner GSO metadata size=%d segments=%d does not cover payload %d (want %d segments)", gsoSize, gsoSegs, payloadLen, wantSegs)
	}
	return nil
}

// ValidateInnerTCPChecksumPartial validates a plaintext IPv4/TCP payload and
// its CHECKSUM_PARTIAL pseudo-header seed without scanning the TCP payload.
func ValidateInnerTCPChecksumPartial(packet []byte) error {
	_, _, _, _, err := innerTCPChecksumPartialMeta(packet)
	return err
}

// CompleteInnerTCPChecksumPartial replaces a validated pseudo-header seed with
// the complete TCP checksum for userspace fallback delivery.
func CompleteInnerTCPChecksumPartial(packet []byte) error {
	src, dst, ipHeaderLen, totalLen, err := innerTCPChecksumPartialMeta(packet)
	if err != nil {
		return err
	}
	tcp := packet[ipHeaderLen:totalLen]
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(src, dst, tcp))
	return nil
}

func innerTCPChecksumPartialMeta(packet []byte) ([4]byte, [4]byte, int, int, error) {
	var src [4]byte
	var dst [4]byte
	if len(packet) < ipv4HeaderLen+tcpHeaderLen {
		return src, dst, 0, 0, fmt.Errorf("tix_tcp inner checksum-partial packet is too short: %d", len(packet))
	}
	if packet[0]>>4 != 4 {
		return src, dst, 0, 0, fmt.Errorf("tix_tcp inner checksum-partial packet is not IPv4")
	}
	ipHeaderLen := int(packet[0]&0x0f) * 4
	if ipHeaderLen < ipv4HeaderLen || len(packet) < ipHeaderLen+tcpHeaderLen {
		return src, dst, 0, 0, fmt.Errorf("tix_tcp inner checksum-partial IPv4 header length %d is invalid", ipHeaderLen)
	}
	if packet[9] != 6 || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return src, dst, 0, 0, fmt.Errorf("tix_tcp inner checksum-partial payload is not unfragmented TCP")
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen != len(packet) || totalLen < ipHeaderLen+tcpHeaderLen {
		return src, dst, 0, 0, fmt.Errorf("tix_tcp inner checksum-partial total length %d does not match payload %d", totalLen, len(packet))
	}
	tcp := packet[ipHeaderLen:totalLen]
	tcpHeaderSize := int(tcp[12]>>4) * 4
	if tcpHeaderSize < tcpHeaderLen || len(tcp) < tcpHeaderSize {
		return src, dst, 0, 0, fmt.Errorf("tix_tcp inner checksum-partial TCP header length %d is invalid", tcpHeaderSize)
	}
	copy(src[:], packet[12:16])
	copy(dst[:], packet[16:20])
	seed := tcpPseudoHeaderSeed(src, dst, len(tcp))
	if got := binary.BigEndian.Uint16(tcp[16:18]); got != seed {
		return src, dst, 0, 0, fmt.Errorf("%w: tix_tcp inner TCP checksum-partial seed %#x does not match %#x", ErrChecksum, got, seed)
	}
	return src, dst, ipHeaderLen, totalLen, nil
}

func tcpPseudoHeaderSeed(src, dst [4]byte, tcpLen int) uint16 {
	sum := checksumAddBytes(0, src[:])
	sum = checksumAddBytes(sum, dst[:])
	sum += 6
	sum += uint32(tcpLen)
	return ^checksumFold(sum)
}
