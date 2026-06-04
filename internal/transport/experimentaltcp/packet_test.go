package experimentaltcp

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
)

var tcpPacketSink TCPPacket

func TestTCPShapedIPv4RoundTrip(t *testing.T) {
	want := TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.10"),
		DestinationIP:   netip.MustParseAddr("198.51.100.20"),
		SourcePort:      43000,
		DestinationPort: 443,
		Sequence:        1234,
		Acknowledgment:  1,
		Payload:         []byte("tix-frame"),
	}
	wire, err := MarshalTCPShapedIPv4(want)
	if err != nil {
		t.Fatalf("marshal tcp-shaped packet: %v", err)
	}
	got, err := ParseTCPShapedIPv4(wire)
	if err != nil {
		t.Fatalf("parse tcp-shaped packet: %v", err)
	}
	if got.SourceIP != want.SourceIP || got.DestinationIP != want.DestinationIP || got.SourcePort != want.SourcePort || got.DestinationPort != want.DestinationPort || got.Sequence != want.Sequence || got.Acknowledgment != want.Acknowledgment {
		t.Fatalf("parsed header = %#v, want %#v", got, want)
	}
	if !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("payload = %q, want %q", got.Payload, want.Payload)
	}

	into := make([]byte, len(wire))
	n, err := MarshalTCPShapedIPv4Into(want, into)
	if err != nil {
		t.Fatalf("marshal tcp-shaped packet into: %v", err)
	}
	if n != len(wire) || !bytes.Equal(into, wire) {
		t.Fatalf("marshal into produced len=%d wire=%x, want len=%d wire=%x", n, into, len(wire), wire)
	}
}

func TestParseTCPShapedIPv4NoCopySharesPayload(t *testing.T) {
	wire := mustTCPShapedIPv4(t)
	got, err := ParseTCPShapedIPv4NoCopy(wire)
	if err != nil {
		t.Fatalf("parse tcp-shaped packet no-copy: %v", err)
	}
	if len(got.Payload) == 0 {
		t.Fatal("payload is empty")
	}
	wire[len(wire)-1] = 'X'
	if got.Payload[len(got.Payload)-1] != 'X' {
		t.Fatalf("no-copy payload did not reflect wire mutation: %q", got.Payload)
	}

	wireCopy := mustTCPShapedIPv4(t)
	copied, err := ParseTCPShapedIPv4(wireCopy)
	if err != nil {
		t.Fatalf("parse tcp-shaped packet copy: %v", err)
	}
	wireCopy[len(wireCopy)-1] = 'Y'
	if copied.Payload[len(copied.Payload)-1] == 'Y' {
		t.Fatalf("copying parser returned payload alias")
	}
}

func TestParseTCPShapedIPv4NoCopyDoesNotAllocate(t *testing.T) {
	wire := mustTCPShapedIPv4(t)
	allocs := testing.AllocsPerRun(1000, func() {
		got, err := ParseTCPShapedIPv4NoCopy(wire)
		if err != nil {
			panic(err)
		}
		tcpPacketSink = got
	})
	if allocs != 0 {
		t.Fatalf("allocs per no-copy parse = %v, want 0", allocs)
	}
}

func TestMarshalTCPShapedIPv4FrameInto(t *testing.T) {
	frame := Frame{
		Flags:    FlagEncrypted,
		FlowID:   44,
		Epoch:    2,
		Sequence: 9,
		Payload:  []byte("ciphertext"),
	}
	frameWire, err := frame.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal frame: %v", err)
	}
	packet := TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.10"),
		DestinationIP:   netip.MustParseAddr("198.51.100.20"),
		SourcePort:      43000,
		DestinationPort: 443,
		Sequence:        1234,
		Acknowledgment:  1,
		Payload:         frameWire,
	}
	want, err := MarshalTCPShapedIPv4(packet)
	if err != nil {
		t.Fatalf("marshal tcp-shaped packet: %v", err)
	}
	got := make([]byte, len(want))
	n, err := MarshalTCPShapedIPv4FrameInto(TCPPacket{
		SourceIP:        packet.SourceIP,
		DestinationIP:   packet.DestinationIP,
		SourcePort:      packet.SourcePort,
		DestinationPort: packet.DestinationPort,
		Sequence:        packet.Sequence,
		Acknowledgment:  packet.Acknowledgment,
	}, frame, got)
	if err != nil {
		t.Fatalf("marshal tcp-shaped frame into: %v", err)
	}
	if n != len(want) || !bytes.Equal(got, want) {
		t.Fatalf("marshal frame into produced len=%d wire=%x, want len=%d wire=%x", n, got, len(want), want)
	}
	parsedPacket, err := ParseTCPShapedIPv4NoCopy(got)
	if err != nil {
		t.Fatalf("parse tcp-shaped frame packet: %v", err)
	}
	parsedFrame, err := ParseFrameNoCopy(parsedPacket.Payload)
	if err != nil {
		t.Fatalf("parse TIXT frame: %v", err)
	}
	if parsedFrame.FlowID != frame.FlowID || parsedFrame.Sequence != frame.Sequence || !bytes.Equal(parsedFrame.Payload, frame.Payload) {
		t.Fatalf("parsed frame = %#v, want %#v", parsedFrame, frame)
	}
}

func TestMarshalTCPShapedIPv4FrameIntoDoesNotAllocate(t *testing.T) {
	frame := Frame{
		FlowID:   44,
		Epoch:    2,
		Sequence: 9,
		Payload:  []byte("ciphertext"),
	}
	packet := TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.10"),
		DestinationIP:   netip.MustParseAddr("198.51.100.20"),
		SourcePort:      43000,
		DestinationPort: 443,
		Sequence:        1234,
		Acknowledgment:  1,
	}
	frameLen, err := FrameWireLen(len(frame.Payload))
	if err != nil {
		t.Fatalf("frame wire len: %v", err)
	}
	packetLen, err := TCPShapedIPv4WireLen(frameLen)
	if err != nil {
		t.Fatalf("packet wire len: %v", err)
	}
	wire := make([]byte, packetLen)
	allocs := testing.AllocsPerRun(1000, func() {
		n, err := MarshalTCPShapedIPv4FrameInto(packet, frame, wire)
		if err != nil {
			panic(err)
		}
		if n != len(wire) {
			panic("short packet marshal")
		}
	})
	if allocs != 0 {
		t.Fatalf("allocs per tcp-shaped frame marshal into = %v, want 0", allocs)
	}
}

func TestParseTCPShapedIPv4RejectsBadIPv4Checksum(t *testing.T) {
	wire := mustTCPShapedIPv4(t)
	wire[12] ^= 0xff
	if _, err := ParseTCPShapedIPv4(wire); !errors.Is(err, ErrChecksum) {
		t.Fatalf("parse error = %v, want checksum error", err)
	}
}

func TestParseTCPShapedIPv4RejectsBadTCPChecksum(t *testing.T) {
	wire := mustTCPShapedIPv4(t)
	wire[len(wire)-1] ^= 0xff
	if _, err := ParseTCPShapedIPv4(wire); !errors.Is(err, ErrChecksum) {
		t.Fatalf("parse error = %v, want checksum error", err)
	}
}

func TestParseTCPShapedIPv4SkipTCPChecksumAcceptsBadTCPChecksum(t *testing.T) {
	wire := mustTCPShapedIPv4(t)
	wire[len(wire)-1] ^= 0xff
	if _, err := ParseTCPShapedIPv4NoCopySkipTCPChecksum(wire); err != nil {
		t.Fatalf("parse tcp-shaped packet with skipped TCP checksum: %v", err)
	}
}

func mustTCPShapedIPv4(t *testing.T) []byte {
	t.Helper()
	wire, err := MarshalTCPShapedIPv4(TCPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.10"),
		DestinationIP:   netip.MustParseAddr("198.51.100.20"),
		SourcePort:      43000,
		DestinationPort: 443,
		Sequence:        1234,
		Acknowledgment:  1,
		Payload:         []byte("tix-frame"),
	})
	if err != nil {
		t.Fatalf("marshal tcp-shaped packet: %v", err)
	}
	return wire
}
