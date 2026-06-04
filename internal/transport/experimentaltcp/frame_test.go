package experimentaltcp

import (
	"bytes"
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
