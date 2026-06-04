package kerneludp

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
)

var udpPacketSink UDPPacket

func TestUDPIPv4RoundTrip(t *testing.T) {
	want := UDPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.10"),
		DestinationIP:   netip.MustParseAddr("198.51.100.20"),
		SourcePort:      43000,
		DestinationPort: 443,
		Payload:         []byte("tix-frame"),
	}
	wire, err := MarshalUDPIPv4(want)
	if err != nil {
		t.Fatalf("marshal udp packet: %v", err)
	}
	got, err := ParseUDPIPv4(wire)
	if err != nil {
		t.Fatalf("parse udp packet: %v", err)
	}
	if got.SourceIP != want.SourceIP || got.DestinationIP != want.DestinationIP || got.SourcePort != want.SourcePort || got.DestinationPort != want.DestinationPort {
		t.Fatalf("parsed header = %#v, want %#v", got, want)
	}
	if !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("payload = %q, want %q", got.Payload, want.Payload)
	}

	into := make([]byte, len(wire))
	n, err := MarshalUDPIPv4Into(want, into)
	if err != nil {
		t.Fatalf("marshal udp packet into: %v", err)
	}
	if n != len(wire) || !bytes.Equal(into, wire) {
		t.Fatalf("marshal into produced len=%d wire=%x, want len=%d wire=%x", n, into, len(wire), wire)
	}
}

func TestParseUDPIPv4NoCopySharesPayload(t *testing.T) {
	wire := mustUDPIPv4(t)
	got, err := ParseUDPIPv4NoCopy(wire)
	if err != nil {
		t.Fatalf("parse udp packet no-copy: %v", err)
	}
	if len(got.Payload) == 0 {
		t.Fatal("payload is empty")
	}
	wire[len(wire)-1] = 'X'
	if got.Payload[len(got.Payload)-1] != 'X' {
		t.Fatalf("no-copy payload did not reflect wire mutation: %q", got.Payload)
	}

	wireCopy := mustUDPIPv4(t)
	copied, err := ParseUDPIPv4(wireCopy)
	if err != nil {
		t.Fatalf("parse udp packet copy: %v", err)
	}
	wireCopy[len(wireCopy)-1] = 'Y'
	if copied.Payload[len(copied.Payload)-1] == 'Y' {
		t.Fatalf("copying parser returned payload alias")
	}
}

func TestParseUDPIPv4NoCopyDoesNotAllocate(t *testing.T) {
	wire := mustUDPIPv4(t)
	allocs := testing.AllocsPerRun(1000, func() {
		got, err := ParseUDPIPv4NoCopy(wire)
		if err != nil {
			panic(err)
		}
		udpPacketSink = got
	})
	if allocs != 0 {
		t.Fatalf("allocs per no-copy parse = %v, want 0", allocs)
	}
}

func TestMarshalUDPIPv4FrameInto(t *testing.T) {
	frame := Frame{
		FlowID:   44,
		Sequence: 9,
		Payload:  []byte("payload"),
	}
	frameWire, err := frame.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal frame: %v", err)
	}
	packet := UDPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.10"),
		DestinationIP:   netip.MustParseAddr("198.51.100.20"),
		SourcePort:      43000,
		DestinationPort: 443,
		Payload:         frameWire,
	}
	want, err := MarshalUDPIPv4(packet)
	if err != nil {
		t.Fatalf("marshal udp packet: %v", err)
	}
	got := make([]byte, len(want))
	n, err := MarshalUDPIPv4FrameInto(UDPPacket{
		SourceIP:        packet.SourceIP,
		DestinationIP:   packet.DestinationIP,
		SourcePort:      packet.SourcePort,
		DestinationPort: packet.DestinationPort,
	}, frame, got)
	if err != nil {
		t.Fatalf("marshal udp frame into: %v", err)
	}
	if n != len(want) || !bytes.Equal(got, want) {
		t.Fatalf("marshal frame into produced len=%d wire=%x, want len=%d wire=%x", n, got, len(want), want)
	}
	parsedPacket, err := ParseUDPIPv4NoCopy(got)
	if err != nil {
		t.Fatalf("parse udp frame packet: %v", err)
	}
	parsedFrame, err := ParseFrameNoCopy(parsedPacket.Payload)
	if err != nil {
		t.Fatalf("parse TIXU frame: %v", err)
	}
	if parsedFrame.FlowID != frame.FlowID || parsedFrame.Sequence != frame.Sequence || !bytes.Equal(parsedFrame.Payload, frame.Payload) {
		t.Fatalf("parsed frame = %#v, want %#v", parsedFrame, frame)
	}
}

func TestMarshalUDPIPv4FrameIntoDoesNotAllocate(t *testing.T) {
	frame := Frame{
		FlowID:   44,
		Sequence: 9,
		Payload:  []byte("payload"),
	}
	packet := UDPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.10"),
		DestinationIP:   netip.MustParseAddr("198.51.100.20"),
		SourcePort:      43000,
		DestinationPort: 443,
	}
	frameLen, err := FrameWireLen(len(frame.Payload))
	if err != nil {
		t.Fatalf("frame wire len: %v", err)
	}
	packetLen, err := UDPIPv4WireLen(frameLen)
	if err != nil {
		t.Fatalf("packet wire len: %v", err)
	}
	wire := make([]byte, packetLen)
	allocs := testing.AllocsPerRun(1000, func() {
		n, err := MarshalUDPIPv4FrameInto(packet, frame, wire)
		if err != nil {
			panic(err)
		}
		if n != len(wire) {
			panic("short packet marshal")
		}
	})
	if allocs != 0 {
		t.Fatalf("allocs per udp frame marshal into = %v, want 0", allocs)
	}
}

func TestParseUDPIPv4RejectsBadIPv4Checksum(t *testing.T) {
	wire := mustUDPIPv4(t)
	wire[12] ^= 0xff
	if _, err := ParseUDPIPv4(wire); !errors.Is(err, ErrChecksum) {
		t.Fatalf("parse error = %v, want checksum error", err)
	}
}

func TestParseUDPIPv4RejectsBadUDPChecksum(t *testing.T) {
	wire := mustUDPIPv4(t)
	wire[len(wire)-1] ^= 0xff
	if _, err := ParseUDPIPv4(wire); !errors.Is(err, ErrChecksum) {
		t.Fatalf("parse error = %v, want checksum error", err)
	}
}

func TestParseUDPIPv4NoCopySkipChecksumAcceptsBadChecksum(t *testing.T) {
	wire := mustUDPIPv4(t)
	wire[12] ^= 0xff
	wire[len(wire)-1] ^= 0xff
	got, err := ParseUDPIPv4NoCopySkipChecksum(wire)
	if err != nil {
		t.Fatalf("parse udp packet with skipped checksums: %v", err)
	}
	if got.SourcePort != 43000 || got.DestinationPort != 443 || len(got.Payload) == 0 {
		t.Fatalf("parsed packet = %#v", got)
	}
}

func mustUDPIPv4(t *testing.T) []byte {
	t.Helper()
	wire, err := MarshalUDPIPv4(UDPPacket{
		SourceIP:        netip.MustParseAddr("192.0.2.10"),
		DestinationIP:   netip.MustParseAddr("198.51.100.20"),
		SourcePort:      43000,
		DestinationPort: 443,
		Payload:         []byte("tix-frame"),
	})
	if err != nil {
		t.Fatalf("marshal udp packet: %v", err)
	}
	return wire
}
