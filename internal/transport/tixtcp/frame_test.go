package tixtcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

var frameSink Frame

func TestFrameRoundTrip(t *testing.T) {
	want := Frame{
		Flags:         FlagEncrypted,
		FlowID:        42,
		Epoch:         7,
		Sequence:      99,
		FragmentIndex: 2,
		FragmentCount: 4,
		Payload:       []byte("ciphertext"),
	}
	wire, err := want.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal frame: %v", err)
	}
	got, err := ParseFrame(wire)
	if err != nil {
		t.Fatalf("parse frame: %v", err)
	}
	if got.Flags != want.Flags || got.FlowID != want.FlowID || got.Epoch != want.Epoch || got.Sequence != want.Sequence || got.FragmentIndex != want.FragmentIndex || got.FragmentCount != want.FragmentCount {
		t.Fatalf("parsed header = %#v, want %#v", got, want)
	}
	if !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("payload = %q, want %q", got.Payload, want.Payload)
	}

	into := make([]byte, len(wire))
	n, err := want.MarshalBinaryInto(into)
	if err != nil {
		t.Fatalf("marshal frame into: %v", err)
	}
	if n != len(wire) || !bytes.Equal(into, wire) {
		t.Fatalf("marshal into produced len=%d wire=%x, want len=%d wire=%x", n, into, len(wire), wire)
	}
}

func TestParseFrameNoCopySharesPayload(t *testing.T) {
	wire, err := Frame{Payload: []byte("payload")}.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal frame: %v", err)
	}
	got, err := ParseFrameNoCopy(wire)
	if err != nil {
		t.Fatalf("parse frame no-copy: %v", err)
	}
	wire[len(wire)-1] = 'X'
	if got.Payload[len(got.Payload)-1] != 'X' {
		t.Fatalf("no-copy payload did not reflect wire mutation: %q", got.Payload)
	}

	wireCopy, err := Frame{Payload: []byte("payload")}.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal frame copy: %v", err)
	}
	copied, err := ParseFrame(wireCopy)
	if err != nil {
		t.Fatalf("parse frame copy: %v", err)
	}
	wireCopy[len(wireCopy)-1] = 'Y'
	if copied.Payload[len(copied.Payload)-1] == 'Y' {
		t.Fatalf("copying parser returned payload alias")
	}
}

func TestParseFrameStreamNoCopy(t *testing.T) {
	first, err := (Frame{FlowID: 1, Sequence: 10, Payload: []byte("one")}).MarshalBinary()
	if err != nil {
		t.Fatalf("marshal first frame: %v", err)
	}
	second, err := (Frame{FlowID: 1, Sequence: 11, Payload: []byte("two")}).MarshalBinary()
	if err != nil {
		t.Fatalf("marshal second frame: %v", err)
	}
	wire := append(first, second...)
	frames, err := ParseFrameStreamNoCopy(wire)
	if err != nil {
		t.Fatalf("parse frame stream: %v", err)
	}
	if len(frames) != 2 {
		t.Fatalf("frame count = %d, want 2", len(frames))
	}
	if string(frames[0].Payload) != "one" || string(frames[1].Payload) != "two" {
		t.Fatalf("payloads = %q/%q, want one/two", frames[0].Payload, frames[1].Payload)
	}
	wire[len(first)+HeaderLen] = 'T'
	if string(frames[1].Payload) != "Two" {
		t.Fatalf("stream parser copied payload: %q", frames[1].Payload)
	}
	if _, err := ParseFrameNoCopy(wire); err == nil {
		t.Fatal("single-frame parser accepted a multi-frame stream")
	}
}

func TestParseFrameNoCopyDoesNotAllocate(t *testing.T) {
	wire, err := Frame{Payload: []byte("payload")}.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal frame: %v", err)
	}
	allocs := testing.AllocsPerRun(1000, func() {
		got, err := ParseFrameNoCopy(wire)
		if err != nil {
			panic(err)
		}
		frameSink = got
	})
	if allocs != 0 {
		t.Fatalf("allocs per no-copy frame parse = %v, want 0", allocs)
	}
}

func TestMarshalFrameIntoDoesNotAllocate(t *testing.T) {
	frame := Frame{FlowID: 1, Epoch: 2, Sequence: 3, Payload: []byte("payload")}
	wire := make([]byte, HeaderLen+len(frame.Payload))
	allocs := testing.AllocsPerRun(1000, func() {
		n, err := frame.MarshalBinaryInto(wire)
		if err != nil {
			panic(err)
		}
		if n != len(wire) {
			panic("short frame marshal")
		}
	})
	if allocs != 0 {
		t.Fatalf("allocs per frame marshal into = %v, want 0", allocs)
	}
}

func TestParseFrameRejectsBadMagic(t *testing.T) {
	wire, err := Frame{Payload: []byte("x")}.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal frame: %v", err)
	}
	wire[0] = 0
	if _, err := ParseFrame(wire); err == nil {
		t.Fatal("expected bad magic error")
	}
}

func TestInnerTCPChecksumPartialRoundTripAndComplete(t *testing.T) {
	inner := testInnerTCPChecksumPartialPacket([]byte("checksum-partial"))
	wire, err := (Frame{
		Flags:    FlagInnerIPv4 | FlagInnerTCPChecksumPartial,
		FlowID:   7,
		Sequence: 11,
		Payload:  inner,
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("marshal checksum-partial frame: %v", err)
	}
	frame, err := ParseFrame(wire)
	if err != nil {
		t.Fatalf("parse checksum-partial frame: %v", err)
	}
	if err := CompleteInnerTCPChecksumPartial(frame.Payload); err != nil {
		t.Fatalf("complete checksum-partial payload: %v", err)
	}
	tcp := frame.Payload[ipv4HeaderLen:]
	src := [4]byte{192, 0, 2, 1}
	dst := [4]byte{198, 51, 100, 2}
	got := binary.BigEndian.Uint16(tcp[16:18])
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	want := tcpChecksum(src, dst, tcp)
	if got != want {
		t.Fatalf("completed TCP checksum = %#x, want %#x", got, want)
	}
}

func TestInnerTCPGSORoundTrip(t *testing.T) {
	inner := testInnerTCPChecksumPartialPacket(bytes.Repeat([]byte{0x5a}, 2500))
	want := Frame{
		Flags:         FlagInnerIPv4 | FlagInnerTCPChecksumPartial | FlagInnerGSO,
		FlowID:        11,
		Epoch:         12,
		Sequence:      13,
		FragmentIndex: 1000,
		FragmentCount: 3,
		Payload:       inner,
	}
	wire, err := want.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal inner GSO frame: %v", err)
	}
	got, err := ParseFrame(wire)
	if err != nil {
		t.Fatalf("parse inner GSO frame: %v", err)
	}
	if got.Flags != want.Flags || got.FragmentIndex != want.FragmentIndex || got.FragmentCount != want.FragmentCount || !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("inner GSO round trip = %+v", got)
	}
}

func TestFrameRejectsInvalidInnerGSOMetadata(t *testing.T) {
	inner := testInnerTCPChecksumPartialPacket(bytes.Repeat([]byte{0x31}, 2500))
	tests := []Frame{
		{Flags: FlagInnerGSO | FlagInnerIPv4 | FlagInnerTCPChecksumPartial, FragmentIndex: 0, FragmentCount: 3, Payload: inner},
		{Flags: FlagInnerGSO | FlagInnerIPv4 | FlagInnerTCPChecksumPartial, FragmentIndex: 1000, FragmentCount: 1, Payload: inner},
		{Flags: FlagInnerGSO | FlagInnerIPv4, FragmentIndex: 1000, FragmentCount: 3, Payload: inner},
		{Flags: FlagInnerGSO | FlagInnerIPv4 | FlagInnerTCPChecksumPartial | FlagEncrypted, FragmentIndex: 1000, FragmentCount: 3, Payload: inner},
		{Flags: FlagInnerGSO | FlagInnerIPv4 | FlagInnerTCPChecksumPartial, FragmentIndex: 1300, FragmentCount: 3, Payload: inner},
	}
	for i, frame := range tests {
		if _, err := frame.MarshalBinary(); err == nil {
			t.Fatalf("case %d accepted invalid inner GSO frame", i)
		}
	}
}

func TestFrameRejectsInvalidInnerTCPChecksumPartialMetadata(t *testing.T) {
	inner := testInnerTCPChecksumPartialPacket([]byte("metadata"))
	tests := []Frame{
		{Flags: FlagInnerTCPChecksumPartial, Payload: inner},
		{Flags: FlagInnerIPv4 | FlagInnerTCPChecksumPartial | FlagEncrypted | FlagKernelOpened, Payload: inner},
		{Flags: FlagInnerIPv4 | FlagInnerTCPChecksumPartial | FlagCryptoFragment, FragmentCount: 2, Payload: inner},
		{Flags: FlagInnerIPv4 | FlagInnerTCPChecksumPartial, FragmentCount: 2, Payload: inner},
		{Flags: 1 << 7, Payload: inner},
	}
	for _, frame := range tests {
		if _, err := frame.MarshalBinary(); err == nil {
			t.Fatalf("MarshalBinary accepted invalid frame %#v", frame)
		}
	}
}

func TestEncryptedInnerTCPChecksumPartialDefersPayloadValidation(t *testing.T) {
	want := []byte("opaque-ciphertext")
	wire, err := (Frame{
		Flags:   FlagEncrypted | FlagInnerIPv4 | FlagInnerTCPChecksumPartial,
		Payload: want,
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("marshal encrypted checksum-partial frame: %v", err)
	}
	got, err := ParseFrame(wire)
	if err != nil {
		t.Fatalf("parse encrypted checksum-partial frame: %v", err)
	}
	if !bytes.Equal(got.Payload, want) {
		t.Fatalf("encrypted payload = %x, want %x", got.Payload, want)
	}
}

func TestKernelOpenedInnerTCPChecksumPartialValidatesSeed(t *testing.T) {
	inner := testInnerTCPChecksumPartialPacket([]byte("kernel-opened"))
	wire, err := (Frame{
		Flags:   FlagKernelOpened | FlagInnerIPv4 | FlagInnerTCPChecksumPartial,
		Payload: inner,
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("marshal kernel-opened checksum-partial frame: %v", err)
	}
	if _, err := ParseFrameNoCopy(wire); err != nil {
		t.Fatalf("parse kernel-opened checksum-partial frame: %v", err)
	}
	wire[HeaderLen+ipv4HeaderLen+16] ^= 1
	if _, err := ParseFrameNoCopy(wire); !errors.Is(err, ErrChecksum) {
		t.Fatalf("ParseFrameNoCopy error = %v, want ErrChecksum", err)
	}
}

func TestValidateInnerTCPChecksumRejectsPartialSeedAndCorruption(t *testing.T) {
	partial := testInnerTCPChecksumPartialPacket([]byte("full-checksum"))
	if err := ValidateInnerTCPChecksum(partial); !errors.Is(err, ErrChecksum) {
		t.Fatalf("partial seed full-checksum validation error = %v, want ErrChecksum", err)
	}
	full := append([]byte(nil), partial...)
	if err := CompleteInnerTCPChecksumPartial(full); err != nil {
		t.Fatalf("complete checksum partial: %v", err)
	}
	if err := ValidateInnerTCPChecksum(full); err != nil {
		t.Fatalf("validate complete checksum: %v", err)
	}
	if err := ValidateInnerTCPChecksumPartial(full); !errors.Is(err, ErrChecksum) {
		t.Fatalf("complete checksum partial validation error = %v, want ErrChecksum", err)
	}
	full[len(full)-1] ^= 1
	if err := ValidateInnerTCPChecksum(full); !errors.Is(err, ErrChecksum) {
		t.Fatalf("corrupt full-checksum validation error = %v, want ErrChecksum", err)
	}
}

func TestParseFrameRejectsInvalidInnerTCPChecksumPartialSeed(t *testing.T) {
	inner := testInnerTCPChecksumPartialPacket([]byte("bad-seed"))
	wire, err := (Frame{
		Flags:   FlagInnerIPv4 | FlagInnerTCPChecksumPartial,
		Payload: inner,
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("marshal checksum-partial frame: %v", err)
	}
	wire[HeaderLen+ipv4HeaderLen+16] ^= 1
	if _, err := ParseFrameNoCopy(wire); !errors.Is(err, ErrChecksum) {
		t.Fatalf("ParseFrameNoCopy error = %v, want ErrChecksum", err)
	}
}

func testInnerTCPChecksumPartialPacket(payload []byte) []byte {
	packet := make([]byte, ipv4HeaderLen+tcpHeaderLen+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 6
	copy(packet[12:16], []byte{192, 0, 2, 1})
	copy(packet[16:20], []byte{198, 51, 100, 2})
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:ipv4HeaderLen]))
	tcp := packet[ipv4HeaderLen:]
	binary.BigEndian.PutUint16(tcp[0:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	binary.BigEndian.PutUint32(tcp[4:8], 0x10203040)
	tcp[12] = 5 << 4
	tcp[13] = tcpFlagPSHACK
	binary.BigEndian.PutUint16(tcp[14:16], 0xffff)
	copy(tcp[tcpHeaderLen:], payload)
	binary.BigEndian.PutUint16(tcp[16:18], tcpPseudoHeaderSeed(
		[4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 2}, len(tcp)))
	return packet
}
