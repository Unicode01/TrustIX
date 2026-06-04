package kerneludp

import "testing"

func TestFrameRoundTrip(t *testing.T) {
	wire, err := (Frame{FlowID: 42, Sequence: 7, FragmentIndex: 2, FragmentCount: 4, Payload: []byte("payload")}).MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	frame, err := ParseFrame(wire)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if frame.FlowID != 42 || frame.Sequence != 7 || frame.FragmentIndex != 2 || frame.FragmentCount != 4 || string(frame.Payload) != "payload" {
		t.Fatalf("frame = %+v, want flow 42 sequence 7 fragment 2/4 payload", frame)
	}
}

func TestFrameRejectsBadMagic(t *testing.T) {
	wire, err := (Frame{Payload: []byte("payload")}).MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	wire[0] = 0
	if _, err := ParseFrame(wire); err == nil {
		t.Fatal("expected bad magic error")
	}
}

func TestFrameMarshalHeaderInto(t *testing.T) {
	frame := Frame{Flags: FlagEncrypted, FlowID: 42, Sequence: 7, FragmentIndex: 2, FragmentCount: 4, Payload: []byte("payload")}
	wire := make([]byte, HeaderLen+len(frame.Payload))
	n, err := frame.MarshalHeaderInto(wire[:HeaderLen])
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	if n != HeaderLen {
		t.Fatalf("header len = %d, want %d", n, HeaderLen)
	}
	copy(wire[HeaderLen:], frame.Payload)
	parsed, err := ParseFrameNoCopy(wire)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Flags != frame.Flags || parsed.FlowID != frame.FlowID || parsed.Sequence != frame.Sequence ||
		parsed.FragmentIndex != frame.FragmentIndex || parsed.FragmentCount != frame.FragmentCount ||
		string(parsed.Payload) != string(frame.Payload) {
		t.Fatalf("frame = %+v, want %+v", parsed, frame)
	}
}
