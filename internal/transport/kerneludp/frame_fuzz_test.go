package kerneludp

import (
	"bytes"
	"testing"
)

func FuzzParseFrameRoundTrip(f *testing.F) {
	seed, err := (Frame{Flags: FlagInnerIPv4, FlowID: 7, Sequence: 9, Payload: []byte("payload")}).MarshalBinary()
	if err != nil {
		f.Fatalf("marshal seed: %v", err)
	}
	f.Add(seed)
	f.Add([]byte{})
	f.Add([]byte("TIXU"))

	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > HeaderLen+MaxPayload {
			t.Skip()
		}
		frame, err := ParseFrameNoCopy(wire)
		if err != nil {
			return
		}
		roundTrip, err := frame.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal parsed frame: %v", err)
		}
		if !bytes.Equal(roundTrip, wire) {
			t.Fatal("parsed frame did not round trip")
		}
	})
}
