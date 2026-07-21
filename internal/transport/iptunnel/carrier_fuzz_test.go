package iptunnel

import (
	"bytes"
	"testing"
)

func FuzzParseTunnelConfigRoundTrip(f *testing.F) {
	for _, seed := range []string{
		"local=198.18.0.1,remote=198.18.0.2,local_carrier=100.64.0.1/30,remote_carrier=100.64.0.2",
		"vxlan://local=198.18.0.1,remote=198.18.0.2,local_carrier=100.64.0.1/30,remote_carrier=100.64.0.2,vni=5527625,queues=4",
		"",
		"local=invalid",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			t.Skip()
		}
		cfg, err := parseTunnelConfig(raw)
		if err != nil {
			return
		}
		normalized := normalizeTunnelConfigFields(cfg)
		roundTrip, err := parseTunnelConfig(normalized)
		if err != nil {
			t.Fatalf("parse normalized config %q: %v", normalized, err)
		}
		if got := normalizeTunnelConfigFields(roundTrip); got != normalized {
			t.Fatalf("normalized round trip = %q, want %q", got, normalized)
		}
	})
}

func FuzzDecodeCarrierFrame(f *testing.F) {
	data, err := encodeCarrier([]byte("carrier-fuzz-seed"), 7)
	if err != nil {
		f.Fatalf("encode data seed: %v", err)
	}
	fragment := make([]byte, carrierHeaderLen+carrierFragmentHeaderLen+4)
	if err := encodeCarrierFragmentHeaderInto(fragment, 4, 11, 8, 4); err != nil {
		f.Fatalf("encode fragment seed: %v", err)
	}
	copy(fragment[carrierHeaderLen+carrierFragmentHeaderLen:], []byte("tail"))
	for _, seed := range [][]byte{data, fragment, nil, []byte("TIXG")} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > carrierMaxWire {
			t.Skip()
		}
		frame, err := decodeCarrierFrameView(wire)
		if err != nil {
			return
		}
		if frame.wireLen != len(wire) {
			t.Fatalf("decoded wire length = %d, want %d", frame.wireLen, len(wire))
		}

		roundTrip := make([]byte, len(wire))
		switch frame.frameType {
		case carrierTypeData:
			if err := encodeCarrierInto(roundTrip, frame.payload, frame.sequence); err != nil {
				t.Fatalf("encode decoded data frame: %v", err)
			}
		case carrierTypeFragment:
			if err := encodeCarrierFragmentHeaderInto(roundTrip, len(frame.payload), frame.sequence, frame.totalLen, frame.offset); err != nil {
				t.Fatalf("encode decoded fragment frame: %v", err)
			}
			copy(roundTrip[carrierHeaderLen+carrierFragmentHeaderLen:], frame.payload)
		default:
			t.Fatalf("decoded unsupported frame type %d", frame.frameType)
		}
		if !bytes.Equal(roundTrip, wire) {
			t.Fatalf("carrier frame round trip changed valid wire data")
		}
	})
}
