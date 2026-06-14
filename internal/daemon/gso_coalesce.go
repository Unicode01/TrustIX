package daemon

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"trustix.local/trustix/internal/transport"
)

const (
	dataSessionRXGSOCoalesceDefaultMaxBytes   = 65535
	dataSessionRXGSOCoalesceDefaultMaxPackets = 128
	dataSessionTXGSOCoalesceDefaultMaxBytes   = 65535
	dataSessionTXGSOCoalesceDefaultMaxPackets = 128
	dataSessionTXGSOCoalesceLargeDatagramMin  = 32 * 1024
	dataSessionGSOCoalesceMaxActiveFlows      = 64
)

type dataSessionGSOCoalesceStats struct {
	Batches       uint64
	InputPackets  uint64
	OutputPackets uint64
	OutputBytes   uint64
}

type tcpGSOCoalesceKey struct {
	SourceIP        netip.Addr
	DestinationIP   netip.Addr
	SourcePort      uint16
	DestinationPort uint16
}

type tcpGSOCoalesceMeta struct {
	key           tcpGSOCoalesceKey
	ihl           int
	tcpHeaderLen  int
	payloadOffset int
	payloadLen    int
	seq           uint32
	ack           uint32
	flags         byte
	window        uint16
	urgent        uint16
	totalLen      int
	headerLen     int
}

type tcpGSOCoalescer struct {
	active bool
	meta   tcpGSOCoalesceMeta
	packet []byte
	count  int
	cloned bool
}

type tcpGSOCoalesceOptions struct {
	skipTCPChecksumAbove int
	multiFlow            bool
}

func dataSessionRXGSOCoalesceEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_DATA_SESSION_RX_GSO_COALESCE"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}

func dataSessionRXGSOCoalesceMaxBytes() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_DATA_SESSION_RX_GSO_COALESCE_BYTES"))
	if value == "" {
		return dataSessionRXGSOCoalesceDefaultMaxBytes
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1500 {
		return dataSessionRXGSOCoalesceDefaultMaxBytes
	}
	if parsed > 0xffff {
		return 0xffff
	}
	return parsed
}

func dataSessionRXGSOCoalesceMaxPackets() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_DATA_SESSION_RX_GSO_COALESCE_PACKETS"))
	if value == "" {
		return dataSessionRXGSOCoalesceDefaultMaxPackets
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return dataSessionRXGSOCoalesceDefaultMaxPackets
	}
	if parsed > 512 {
		return 512
	}
	return parsed
}

func dataSessionTXGSOCoalesceEnabled() bool {
	enabled, _ := dataSessionTXGSOCoalescePreference()
	return enabled
}

func dataSessionTXGSOCoalesceDefaultForStats(stats transport.TransportStats) bool {
	if stats.Encrypted && stats.CryptoPlacement == "kernel" {
		return true
	}
	return stats.Datagram &&
		stats.NativeBatching &&
		!stats.FragmentingDatagram &&
		stats.MaxPacketSize >= dataSessionTXGSOCoalesceLargeDatagramMin
}

func dataSessionTXGSOCoalescePreference() (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_DATA_SESSION_TX_GSO_COALESCE"))) {
	case "1", "true", "yes", "on", "enabled":
		return true, true
	case "0", "false", "no", "off", "disabled":
		return false, true
	default:
		return false, false
	}
}

func dataSessionTXGSOCoalesceMaxBytes() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_DATA_SESSION_TX_GSO_COALESCE_BYTES"))
	if value == "" {
		return dataSessionTXGSOCoalesceDefaultMaxBytes
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1500 {
		return dataSessionTXGSOCoalesceDefaultMaxBytes
	}
	if parsed > 0xffff {
		return 0xffff
	}
	return parsed
}

func dataSessionTXGSOCoalesceMaxPackets() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_DATA_SESSION_TX_GSO_COALESCE_PACKETS"))
	if value == "" {
		return dataSessionTXGSOCoalesceDefaultMaxPackets
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return dataSessionTXGSOCoalesceDefaultMaxPackets
	}
	if parsed > 512 {
		return 512
	}
	return parsed
}

func dataSessionRXGSOCoalesceDisabledForSession(runtime *dataSessionRuntime, session transport.Session) bool {
	stats := dataSessionTransportStats(runtime, session)
	if stats.Encrypted && stats.CryptoPlacement == "userspace" && stats.ReceiveEncrypted {
		return !dataSessionRXGSOCoalesceUserspaceEncryptedEnabledForRuntime(runtime)
	}
	if !stats.Encrypted {
		return !dataSessionRXGSOCoalescePlaintextEnabled()
	}
	return false
}

func dataSessionRXGSOCoalesceUserspaceEncryptedEnabled() bool {
	enabled, _ := dataSessionRXGSOCoalesceUserspaceEncryptedPreference()
	return enabled
}

func dataSessionRXGSOCoalesceUserspaceEncryptedEnabledForRuntime(runtime *dataSessionRuntime) bool {
	if enabled, explicit := dataSessionRXGSOCoalesceUserspaceEncryptedPreference(); explicit {
		return enabled
	}
	switch dataSessionRuntimeTransport(runtime) {
	case transport.ProtocolGRE, transport.ProtocolIPIP, transport.ProtocolVXLAN:
		return true
	default:
		return false
	}
}

func dataSessionRXGSOCoalesceUserspaceEncryptedPreference() (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_DATA_SESSION_RX_GSO_COALESCE_USERSPACE_ENCRYPTED"))) {
	case "1", "true", "yes", "on", "enabled":
		return true, true
	case "0", "false", "no", "off", "disabled":
		return false, true
	default:
		return false, false
	}
}

func dataSessionRXGSOCoalescePlaintextEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_DATA_SESSION_RX_GSO_COALESCE_PLAINTEXT"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}

func dataSessionRXGSOScatterEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_DATA_SESSION_RX_GSO_SCATTER"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func dataSessionRXGSOCoalesceMultiFlowEnabled() bool {
	return envTruthyAny(
		"TRUSTIX_DATA_SESSION_RX_GSO_COALESCE_MULTI_FLOW",
		"TRUSTIX_DATA_SESSION_RX_GSO_MULTI_FLOW",
	)
}

func coalesceDataSessionRXTCPLocalPackets(packets [][]byte, allowed ...bool) ([][]byte, dataSessionGSOCoalesceStats) {
	if len(allowed) > 0 && !allowed[0] {
		return packets, dataSessionGSOCoalesceStats{}
	}
	return coalesceDataSessionRXTCPLocalPacketsConfigured(
		packets,
		dataSessionRXGSOCoalesceEnabled(),
		dataSessionRXGSOCoalesceMaxBytes(),
		dataSessionRXGSOCoalesceMaxPackets(),
	)
}

func coalesceDataSessionRXTCPLocalPacketsConfigured(packets [][]byte, enabled bool, maxBytes int, maxPackets int) ([][]byte, dataSessionGSOCoalesceStats) {
	return coalesceDataSessionTCPLocalPacketsConfigured(packets, enabled, maxBytes, maxPackets)
}

func coalesceDataSessionTXTCPLocalPacketsConfigured(packets [][]byte, enabled bool, maxBytes int, maxPackets int) ([][]byte, dataSessionGSOCoalesceStats) {
	return coalesceDataSessionTCPLocalPacketsConfigured(packets, enabled, maxBytes, maxPackets)
}

func coalesceDataSessionTCPLocalPacketsConfigured(packets [][]byte, enabled bool, maxBytes int, maxPackets int) ([][]byte, dataSessionGSOCoalesceStats) {
	return coalesceDataSessionTCPLocalPacketsConfiguredScratch(packets, enabled, maxBytes, maxPackets, nil, nil)
}

func coalesceDataSessionTCPLocalPacketsConfiguredScratch(packets [][]byte, enabled bool, maxBytes int, maxPackets int, outScratch *[][]byte, arenaScratch *[]byte) ([][]byte, dataSessionGSOCoalesceStats) {
	return coalesceDataSessionTCPLocalPacketsConfiguredScratchOptions(packets, enabled, maxBytes, maxPackets, outScratch, arenaScratch, tcpGSOCoalesceOptions{})
}

func coalesceDataSessionTCPLocalPacketsConfiguredScratchOptions(packets [][]byte, enabled bool, maxBytes int, maxPackets int, outScratch *[][]byte, arenaScratch *[]byte, options tcpGSOCoalesceOptions) ([][]byte, dataSessionGSOCoalesceStats) {
	if len(packets) < 2 || !enabled {
		return packets, dataSessionGSOCoalesceStats{}
	}
	if maxBytes <= 0 || maxPackets <= 1 {
		return packets, dataSessionGSOCoalesceStats{}
	}
	if options.multiFlow {
		return coalesceDataSessionTCPLocalPacketsMultiFlowScratchOptions(packets, maxBytes, maxPackets, outScratch, arenaScratch, options)
	}
	out := tcpGSOCoalescePacketSlice(outScratch, len(packets))
	var current tcpGSOCoalescer
	var stats dataSessionGSOCoalesceStats
	flush := func() {
		if !current.active {
			return
		}
		if current.count <= 1 {
			out = append(out, current.packet[:current.meta.totalLen])
			current = tcpGSOCoalescer{}
			return
		}
		packet := finishTCPGSOCoalescedPacket(current.packet, current.meta, tcpGSOCoalesceSkipTCPChecksum(current.meta.totalLen, options))
		out = append(out, packet)
		stats.Batches++
		stats.InputPackets += uint64(current.count)
		stats.OutputPackets++
		stats.OutputBytes += uint64(len(packet))
		current = tcpGSOCoalescer{}
	}
	for i, packet := range packets {
		meta, ok := tcpGSOCoalescePacketMeta(packet)
		if !ok {
			flush()
			out = append(out, packet)
			continue
		}
		if !current.active {
			current = tcpGSOCoalescer{
				active: true,
				meta:   meta,
				packet: packet[:meta.totalLen],
				count:  1,
			}
			continue
		}
		if !tcpGSOCoalescerCanAppend(current, packet, meta, maxBytes, maxPackets) {
			flush()
			current = tcpGSOCoalescer{
				active: true,
				meta:   meta,
				packet: packet[:meta.totalLen],
				count:  1,
			}
			continue
		}
		if !current.cloned {
			current.packet = cloneTCPGSOCoalescePacket(packets, i, current, maxBytes, maxPackets, arenaScratch)
			current.cloned = true
		}
		current.packet = append(current.packet, packet[meta.payloadOffset:meta.totalLen]...)
		current.meta.payloadLen += meta.payloadLen
		current.meta.totalLen += meta.payloadLen
		current.count++
		current.meta.flags = tcpGSOCoalescedFlags(current.meta.flags, meta.flags)
	}
	flush()
	if stats.Batches == 0 {
		if outScratch != nil {
			clear(out)
			*outScratch = out[:0]
		}
		return packets, stats
	}
	if outScratch != nil {
		*outScratch = out
	}
	return out, stats
}

func coalesceDataSessionTCPLocalPacketsMultiFlowScratchOptions(packets [][]byte, maxBytes int, maxPackets int, outScratch *[][]byte, arenaScratch *[]byte, options tcpGSOCoalesceOptions) ([][]byte, dataSessionGSOCoalesceStats) {
	out := tcpGSOCoalescePacketSlice(outScratch, len(packets))
	active := make(map[tcpGSOCoalesceKey]int, min(len(packets), dataSessionGSOCoalesceMaxActiveFlows))
	flows := make([]tcpGSOCoalescer, 0, min(len(packets), dataSessionGSOCoalesceMaxActiveFlows))
	var stats dataSessionGSOCoalesceStats
	flushIndex := func(index int) {
		if index < 0 || index >= len(flows) {
			return
		}
		current := flows[index]
		if !current.active {
			return
		}
		if current.count <= 1 {
			out = append(out, current.packet[:current.meta.totalLen])
		} else {
			packet := finishTCPGSOCoalescedPacket(current.packet, current.meta, tcpGSOCoalesceSkipTCPChecksum(current.meta.totalLen, options))
			out = append(out, packet)
			stats.Batches++
			stats.InputPackets += uint64(current.count)
			stats.OutputPackets++
			stats.OutputBytes += uint64(len(packet))
		}
		delete(active, current.meta.key)
		flows[index] = tcpGSOCoalescer{}
	}
	flushAll := func() {
		for i := range flows {
			flushIndex(i)
		}
		clear(active)
		flows = flows[:0]
	}
	startFlow := func(meta tcpGSOCoalesceMeta, packet []byte) {
		if len(active) >= dataSessionGSOCoalesceMaxActiveFlows {
			flushAll()
		}
		active[meta.key] = len(flows)
		flows = append(flows, tcpGSOCoalescer{
			active: true,
			meta:   meta,
			packet: packet[:meta.totalLen],
			count:  1,
		})
	}
	for i, packet := range packets {
		meta, ok := tcpGSOCoalescePacketMeta(packet)
		if !ok {
			flushAll()
			out = append(out, packet)
			continue
		}
		index, ok := active[meta.key]
		if !ok {
			startFlow(meta, packet)
			continue
		}
		current := flows[index]
		if !tcpGSOCoalescerCanAppend(current, packet, meta, maxBytes, maxPackets) {
			flushIndex(index)
			startFlow(meta, packet)
			continue
		}
		if !current.cloned {
			current.packet = cloneTCPGSOCoalescePacket(packets, i, current, maxBytes, maxPackets, arenaScratch)
			current.cloned = true
		}
		current.packet = append(current.packet, packet[meta.payloadOffset:meta.totalLen]...)
		current.meta.payloadLen += meta.payloadLen
		current.meta.totalLen += meta.payloadLen
		current.count++
		current.meta.flags = tcpGSOCoalescedFlags(current.meta.flags, meta.flags)
		flows[index] = current
	}
	flushAll()
	if stats.Batches == 0 {
		if outScratch != nil {
			clear(out)
			*outScratch = out[:0]
		}
		return packets, stats
	}
	if outScratch != nil {
		*outScratch = out
	}
	return out, stats
}

func tcpGSOCoalesceSkipTCPChecksum(totalLen int, options tcpGSOCoalesceOptions) bool {
	return options.skipTCPChecksumAbove > 0 && totalLen > options.skipTCPChecksumAbove
}

func tcpGSOCoalescePacketSlice(outScratch *[][]byte, size int) [][]byte {
	if outScratch == nil {
		return make([][]byte, 0, size)
	}
	out := *outScratch
	clear(out)
	if cap(out) < size {
		out = make([][]byte, 0, size)
	} else {
		out = out[:0]
	}
	*outScratch = out
	return out
}

func cloneTCPGSOCoalescePacket(packets [][]byte, next int, current tcpGSOCoalescer, maxBytes int, maxPackets int, arenaScratch *[]byte) []byte {
	initialLen := current.meta.totalLen
	capacity := initialLen
	for i := next; i < len(packets) && current.count < maxPackets; i++ {
		packet := packets[i]
		meta, ok := tcpGSOCoalescePacketMeta(packet)
		if !ok || !tcpGSOCoalescerCanAppend(current, packet, meta, maxBytes, maxPackets) {
			break
		}
		if capacity+meta.payloadLen > maxBytes {
			break
		}
		capacity += meta.payloadLen
		current.meta.payloadLen += meta.payloadLen
		current.meta.totalLen += meta.payloadLen
		current.count++
	}
	if arenaScratch != nil {
		arena := *arenaScratch
		start := len(arena)
		if cap(arena)-start < capacity {
			newCap := capacity
			if doubled := cap(arena) * 2; doubled > newCap {
				newCap = doubled
			}
			arena = make([]byte, 0, newCap)
			start = 0
		}
		arena = arena[:start+capacity]
		out := arena[start : start+initialLen : start+capacity]
		copy(out, current.packet[:initialLen])
		*arenaScratch = arena
		return out
	}
	out := make([]byte, initialLen, capacity)
	copy(out, current.packet[:initialLen])
	return out
}

func tcpGSOCoalescerCanAppend(current tcpGSOCoalescer, packet []byte, meta tcpGSOCoalesceMeta, maxBytes int, maxPackets int) bool {
	if maxBytes > 0xffff {
		maxBytes = 0xffff
	}
	if !current.active || current.count >= maxPackets {
		return false
	}
	if current.meta.key != meta.key ||
		current.meta.ihl != meta.ihl ||
		current.meta.tcpHeaderLen != meta.tcpHeaderLen ||
		current.meta.headerLen != meta.headerLen ||
		current.meta.ack != meta.ack ||
		current.meta.window != meta.window ||
		current.meta.urgent != meta.urgent ||
		current.meta.seq+uint32(current.meta.payloadLen) != meta.seq {
		return false
	}
	if len(packet) < meta.totalLen || len(current.packet)+meta.payloadLen > maxBytes {
		return false
	}
	if !bytes.Equal(
		current.packet[current.meta.ihl+20:current.meta.ihl+current.meta.tcpHeaderLen],
		packet[meta.ihl+20:meta.ihl+meta.tcpHeaderLen],
	) {
		return false
	}
	return tcpGSOCoalescibleFlags(current.meta.flags) &&
		tcpGSOCoalescibleFlags(meta.flags) &&
		meta.payloadLen > 0
}

func tcpGSOCoalescedFlags(current byte, next byte) byte {
	flags := current
	if next&tcpFlagPSH != 0 {
		flags |= tcpFlagPSH
	}
	return flags
}

func finishTCPGSOCoalescedPacket(packet []byte, meta tcpGSOCoalesceMeta, skipTCPChecksum bool) []byte {
	if len(packet) < meta.totalLen {
		return packet
	}
	packet = packet[:meta.totalLen]
	binary.BigEndian.PutUint16(packet[2:4], uint16(meta.totalLen))
	packet[6] &^= 0x20
	binary.BigEndian.PutUint16(packet[10:12], 0)
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:meta.ihl]))
	tcp := packet[meta.ihl:meta.headerLen]
	tcp[13] = meta.flags
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	if skipTCPChecksum {
		return packet
	}
	binary.BigEndian.PutUint16(tcp[16:18], transportChecksum(packet[12:16], packet[16:20], ipProtocolTCP, packet[meta.ihl:]))
	return packet
}

func tcpGSOCoalescePacketMeta(packet []byte) (tcpGSOCoalesceMeta, bool) {
	ipOffset, ihl, totalLen, err := ipv4HeaderBounds(packet)
	if err != nil || ipOffset != 0 || totalLen != len(packet) || totalLen > 0xffff {
		return tcpGSOCoalesceMeta{}, false
	}
	if packet[9] != ipProtocolTCP {
		return tcpGSOCoalesceMeta{}, false
	}
	flagsAndFragment := binary.BigEndian.Uint16(packet[6:8])
	if flagsAndFragment&(ipv4MoreFragments|ipv4FragmentOffsetMask) != 0 {
		return tcpGSOCoalesceMeta{}, false
	}
	tcp := packet[ihl:totalLen]
	if len(tcp) < 20 {
		return tcpGSOCoalesceMeta{}, false
	}
	tcpHeaderLen := int(tcp[12]>>4) * 4
	if tcpHeaderLen < 20 || tcpHeaderLen > len(tcp) {
		return tcpGSOCoalesceMeta{}, false
	}
	flags := tcp[13]
	payloadOffset := ihl + tcpHeaderLen
	payloadLen := totalLen - payloadOffset
	if payloadLen <= 0 || !tcpGSOCoalescibleFlags(flags) {
		return tcpGSOCoalesceMeta{}, false
	}
	return tcpGSOCoalesceMeta{
		key: tcpGSOCoalesceKey{
			SourceIP:        netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]}),
			DestinationIP:   netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]}),
			SourcePort:      binary.BigEndian.Uint16(tcp[0:2]),
			DestinationPort: binary.BigEndian.Uint16(tcp[2:4]),
		},
		ihl:           ihl,
		tcpHeaderLen:  tcpHeaderLen,
		payloadOffset: payloadOffset,
		payloadLen:    payloadLen,
		seq:           binary.BigEndian.Uint32(tcp[4:8]),
		ack:           binary.BigEndian.Uint32(tcp[8:12]),
		flags:         flags,
		window:        binary.BigEndian.Uint16(tcp[14:16]),
		urgent:        binary.BigEndian.Uint16(tcp[18:20]),
		totalLen:      totalLen,
		headerLen:     payloadOffset,
	}, true
}

func tcpGSOCoalescibleFlags(flags byte) bool {
	return flags == tcpFlagACK || flags == tcpFlagACK|tcpFlagPSH
}
