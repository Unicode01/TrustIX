// Package device contains helpers for TrustIX roaming device access clients.
package device

import (
	"encoding/binary"
	"net/netip"
	"time"
)

const (
	DataSessionControlPing        byte = 1
	DataSessionControlPong        byte = 2
	DataSessionControlDeviceLease byte = 3

	dataSessionControlVersion             byte = 1
	dataSessionControlLen                      = 16
	dataSessionControlDeviceLeaseLen           = 28
	dataSessionControlDeviceLeaseRouteLen      = 8
	dataSessionBatchVersion               byte = 1
	dataSessionBatchHeaderLen                  = 8
	dataSessionBatchItemHeaderLen              = 2
	dataSessionBatchMaxPackets                 = 256
)

var (
	dataSessionControlMagic = [4]byte{'T', 'I', 'X', 'C'}
	dataSessionBatchMagic   = [4]byte{'T', 'I', 'X', 'B'}
)

type Lease struct {
	Address   netip.Addr
	Prefix    netip.Prefix
	ExpiresAt time.Time
	Routes    []netip.Prefix
}

func EncodeControl(kind byte, nonce uint64) []byte {
	frame := make([]byte, dataSessionControlLen)
	copy(frame[0:4], dataSessionControlMagic[:])
	frame[4] = dataSessionControlVersion
	frame[5] = kind
	binary.BigEndian.PutUint64(frame[8:16], nonce)
	return frame
}

func IsControlPacket(packet []byte) bool {
	if len(packet) == dataSessionControlLen {
		return string(packet[0:4]) == string(dataSessionControlMagic[:]) && packet[4] == dataSessionControlVersion
	}
	if len(packet) < dataSessionControlDeviceLeaseLen || string(packet[0:4]) != string(dataSessionControlMagic[:]) || packet[4] != dataSessionControlVersion {
		return false
	}
	if packet[5] != DataSessionControlDeviceLease {
		return false
	}
	count := int(binary.BigEndian.Uint16(packet[24:26]))
	return len(packet) == dataSessionControlDeviceLeaseLen+count*dataSessionControlDeviceLeaseRouteLen
}

func DecodeControl(packet []byte) (kind byte, nonce uint64, ok bool) {
	if !IsControlPacket(packet) {
		return 0, 0, false
	}
	switch packet[5] {
	case DataSessionControlPing, DataSessionControlPong, DataSessionControlDeviceLease:
		return packet[5], binary.BigEndian.Uint64(packet[8:16]), true
	default:
		return 0, 0, false
	}
}

func DecodeLease(packet []byte) (Lease, bool) {
	kind, _, ok := DecodeControl(packet)
	if !ok || kind != DataSessionControlDeviceLease || len(packet) < dataSessionControlDeviceLeaseLen {
		return Lease{}, false
	}
	addr := netip.AddrFrom4([4]byte{packet[8], packet[9], packet[10], packet[11]})
	bits := int(binary.BigEndian.Uint32(packet[12:16]))
	if bits < 0 || bits > 32 {
		return Lease{}, false
	}
	expiresUnix := int64(binary.BigEndian.Uint64(packet[16:24]))
	var expires time.Time
	if expiresUnix > 0 {
		expires = time.Unix(expiresUnix, 0).UTC()
	}
	var routes []netip.Prefix
	if len(packet) > dataSessionControlDeviceLeaseLen {
		if len(packet) < dataSessionControlDeviceLeaseLen+2 {
			return Lease{}, false
		}
		count := int(binary.BigEndian.Uint16(packet[24:26]))
		wantLen := dataSessionControlDeviceLeaseLen + count*dataSessionControlDeviceLeaseRouteLen
		if count < 0 || len(packet) != wantLen {
			return Lease{}, false
		}
		routes = make([]netip.Prefix, 0, count)
		offset := dataSessionControlDeviceLeaseLen
		for i := 0; i < count; i++ {
			addr := netip.AddrFrom4([4]byte{packet[offset], packet[offset+1], packet[offset+2], packet[offset+3]})
			routeBits := int(packet[offset+4])
			if routeBits < 0 || routeBits > 32 {
				return Lease{}, false
			}
			routes = append(routes, netip.PrefixFrom(addr, routeBits).Masked())
			offset += dataSessionControlDeviceLeaseRouteLen
		}
	}
	return Lease{
		Address:   addr,
		Prefix:    netip.PrefixFrom(addr, bits),
		ExpiresAt: expires,
		Routes:    routes,
	}, true
}

func DecodeBatchInto(packet []byte, dst [][]byte) ([][]byte, bool) {
	if len(packet) < dataSessionBatchHeaderLen {
		return nil, false
	}
	if string(packet[0:4]) != string(dataSessionBatchMagic[:]) || packet[4] != dataSessionBatchVersion {
		return nil, false
	}
	count := int(binary.BigEndian.Uint16(packet[6:8]))
	if count <= 0 || count > dataSessionBatchMaxPackets {
		return nil, false
	}
	offset := dataSessionBatchHeaderLen
	var items [][]byte
	if cap(dst) < count {
		items = make([][]byte, 0, count)
	} else {
		items = dst[:0]
	}
	for i := 0; i < count; i++ {
		if len(packet)-offset < dataSessionBatchItemHeaderLen {
			return nil, false
		}
		size := int(binary.BigEndian.Uint16(packet[offset : offset+dataSessionBatchItemHeaderLen]))
		offset += dataSessionBatchItemHeaderLen
		if size <= 0 || len(packet)-offset < size {
			return nil, false
		}
		items = append(items, packet[offset:offset+size])
		offset += size
	}
	if offset != len(packet) {
		return nil, false
	}
	return items, true
}
