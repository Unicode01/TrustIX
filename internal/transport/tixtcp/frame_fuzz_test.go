package tixtcp

import (
	"bytes"
	"testing"
)

func FuzzParseFrameStreamRoundTrip(f *testing.F) {
	first, err := (Frame{Flags: FlagInnerIPv4, FlowID: 7, Epoch: 8, Sequence: 9, Payload: []byte("first")}).MarshalBinary()
	if err != nil {
		f.Fatalf("marshal first seed: %v", err)
	}
	second, err := (Frame{FlowID: 10, Epoch: 11, Sequence: 12, Payload: []byte("second")}).MarshalBinary()
	if err != nil {
		f.Fatalf("marshal second seed: %v", err)
	}
	f.Add(append(first, second...))
	f.Add([]byte{})
	f.Add([]byte("TIXT"))

	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 2*(HeaderLen+MaxPayload) {
			t.Skip()
		}
		frames, err := ParseFrameStreamNoCopy(wire)
		if err != nil {
			return
		}
		roundTrip := make([]byte, 0, len(wire))
		for _, frame := range frames {
			encoded, err := frame.MarshalBinary()
			if err != nil {
				t.Fatalf("marshal parsed frame: %v", err)
			}
			roundTrip = append(roundTrip, encoded...)
		}
		if !bytes.Equal(roundTrip, wire) {
			t.Fatal("parsed frame stream did not round trip")
		}
	})
}
