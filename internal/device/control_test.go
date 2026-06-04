package device

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func TestDecodeLease(t *testing.T) {
	frame := make([]byte, dataSessionControlDeviceLeaseLen)
	copy(frame[0:4], dataSessionControlMagic[:])
	frame[4] = dataSessionControlVersion
	frame[5] = DataSessionControlDeviceLease
	copy(frame[8:12], []byte{10, 0, 0, 240})
	binary.BigEndian.PutUint32(frame[12:16], 32)
	binary.BigEndian.PutUint64(frame[16:24], uint64(time.Unix(1700000000, 0).Unix()))

	lease, ok := DecodeLease(frame)
	if !ok {
		t.Fatal("expected lease frame")
	}
	if lease.Address != netip.MustParseAddr("10.0.0.240") || lease.Prefix.String() != "10.0.0.240/32" {
		t.Fatalf("lease = %s %s", lease.Address, lease.Prefix)
	}
	if lease.ExpiresAt.Unix() != 1700000000 {
		t.Fatalf("lease expires = %s", lease.ExpiresAt)
	}
}

func TestDecodeLeaseWithRoutes(t *testing.T) {
	frame := make([]byte, dataSessionControlDeviceLeaseLen+2*dataSessionControlDeviceLeaseRouteLen)
	copy(frame[0:4], dataSessionControlMagic[:])
	frame[4] = dataSessionControlVersion
	frame[5] = DataSessionControlDeviceLease
	copy(frame[8:12], []byte{10, 0, 0, 240})
	binary.BigEndian.PutUint32(frame[12:16], 32)
	binary.BigEndian.PutUint16(frame[24:26], 2)
	copy(frame[28:32], []byte{10, 0, 1, 0})
	frame[32] = 24
	copy(frame[36:40], []byte{10, 0, 2, 0})
	frame[40] = 24

	lease, ok := DecodeLease(frame)
	if !ok {
		t.Fatal("expected lease frame")
	}
	if len(lease.Routes) != 2 || lease.Routes[0] != netip.MustParsePrefix("10.0.1.0/24") || lease.Routes[1] != netip.MustParsePrefix("10.0.2.0/24") {
		t.Fatalf("lease routes = %#v", lease.Routes)
	}
}

func TestDecodeBatchInto(t *testing.T) {
	frame := []byte{'T', 'I', 'X', 'B', dataSessionBatchVersion, 0, 0, 2}
	frame = binary.BigEndian.AppendUint16(frame, 3)
	frame = append(frame, []byte("one")...)
	frame = binary.BigEndian.AppendUint16(frame, 3)
	frame = append(frame, []byte("two")...)

	packets, ok := DecodeBatchInto(frame, nil)
	if !ok {
		t.Fatal("expected batch frame")
	}
	if len(packets) != 2 || string(packets[0]) != "one" || string(packets[1]) != "two" {
		t.Fatalf("packets = %#v", packets)
	}
}

func TestControlPingPong(t *testing.T) {
	frame := EncodeControl(DataSessionControlPing, 42)
	kind, nonce, ok := DecodeControl(frame)
	if !ok || kind != DataSessionControlPing || nonce != 42 {
		t.Fatalf("control = kind:%d nonce:%d ok:%t", kind, nonce, ok)
	}
}
