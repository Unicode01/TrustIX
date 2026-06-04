package daemon

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"

	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/observability"
	"trustix.local/trustix/internal/routing"
)

const (
	icmpTypeDestinationUnreachable = 3
	icmpTypeEchoReply              = 0
	icmpTypeEchoRequest            = 8
	icmpTypeTimeExceeded           = 11
	icmpCodeHostUnreachable        = 1
	icmpCodeTTLExceeded            = 0
	tcpFlagFIN                     = 0x01
	tcpFlagSYN                     = 0x02
	tcpFlagRST                     = 0x04
	tcpFlagPSH                     = 0x08
	tcpFlagACK                     = 0x10
	ipProtocolICMP                 = 1
)

func (daemon *Daemon) replyToRejectedPacket(ctx context.Context, packet []byte) error {
	reply, dst, kind, err := rejectReplyPacket(packet)
	if err != nil {
		daemon.dataStats.recordDrop(observability.DropInvalidPacket)
		return err
	}
	if len(reply) == 0 {
		return nil
	}
	switch kind {
	case rejectReplyRST:
		daemon.dataStats.rejectRSTGenerated.Add(1)
	case rejectReplyICMP:
		daemon.dataStats.rejectICMPGenerated.Add(1)
	}
	if err := daemon.injectRejectReply(ctx, reply, dst); err != nil {
		daemon.dataStats.recordDrop(observability.DropEndpointDown)
		return err
	}
	daemon.dataStats.packetsInjected.Add(1)
	return nil
}

func (daemon *Daemon) replyToTTLExpiredPacket(ctx context.Context, packet []byte) error {
	reply, dst, err := ttlExpiredReplyPacket(packet)
	if err != nil {
		daemon.dataStats.recordDrop(observability.DropInvalidPacket)
		return err
	}
	if len(reply) == 0 {
		return nil
	}
	daemon.dataStats.ttlICMPGenerated.Add(1)
	return daemon.deliverTTLExpiredReply(ctx, reply, dst)
}

func (daemon *Daemon) deliverTTLExpiredReply(ctx context.Context, packet []byte, destination netip.Addr) error {
	if daemon.destinationInLocalLAN(destination) {
		if err := daemon.injectRejectReply(ctx, packet, destination); err != nil {
			daemon.dataStats.recordDrop(observability.DropEndpointDown)
			return err
		}
		daemon.dataStats.packetsInjected.Add(1)
		return nil
	}
	if daemon.routes == nil {
		daemon.dataStats.routeMisses.Add(1)
		daemon.dataStats.recordDrop(observability.DropNoRoute)
		return fmt.Errorf("no route for TTL exceeded reply destination %s", destination)
	}
	decision, ok := daemon.lookupRouteForPacket(destination, packet)
	if !ok {
		daemon.dataStats.routeMisses.Add(1)
		daemon.dataStats.recordDrop(observability.DropNoRoute)
		return fmt.Errorf("no route for TTL exceeded reply destination %s", destination)
	}
	if dropReason, drop := routeDropReason(decision.Route); drop {
		daemon.recordRouteHit(decision)
		daemon.dataStats.recordDrop(dropReason)
		return fmt.Errorf("TTL exceeded reply route %q is %s", decision.Route.Prefix, decision.Route.Kind)
	}
	if decision.Route.Kind == routing.RouteLocal || decision.Route.NextHop == daemon.desired.IX.ID {
		if err := daemon.injectRejectReply(ctx, packet, destination); err != nil {
			daemon.dataStats.recordDrop(observability.DropEndpointDown)
			return err
		}
		daemon.dataStats.packetsInjected.Add(1)
		return nil
	}
	daemon.recordRouteHit(decision)
	if err := daemon.sendPacketByDecisionWithOptions(ctx, decision, packet, routing.FlowKey{}, false, diagnosticDataPacketSendOptions); err != nil {
		daemon.dataStats.sendErrors.Add(1)
		return err
	}
	return nil
}

func (daemon *Daemon) injectRejectReply(ctx context.Context, packet []byte, destination netip.Addr) error {
	if injector, ok := daemon.dataplane.(dataplane.LANPacketInjector); ok {
		return injector.InjectLANPacket(ctx, packet, destination)
	}
	if injector, ok := daemon.dataplane.(dataplane.PacketInjector); ok {
		return injector.InjectPacket(ctx, packet)
	}
	return nil
}

type rejectReplyKind int

const (
	rejectReplyNone rejectReplyKind = iota
	rejectReplyICMP
	rejectReplyRST
)

func rejectReplyPacket(packet []byte) ([]byte, netip.Addr, rejectReplyKind, error) {
	ipOffset, ihl, totalLen, err := ipv4HeaderBounds(packet)
	if err != nil {
		return nil, netip.Addr{}, rejectReplyNone, err
	}
	ip := packet[ipOffset : ipOffset+totalLen]
	source := netip.AddrFrom4([4]byte{ip[12], ip[13], ip[14], ip[15]})
	destination := netip.AddrFrom4([4]byte{ip[16], ip[17], ip[18], ip[19]})
	if !source.Is4() || !destination.Is4() {
		return nil, netip.Addr{}, rejectReplyNone, fmt.Errorf("reject reply supports only IPv4")
	}
	flagsAndFragment := binary.BigEndian.Uint16(ip[6:8])
	if flagsAndFragment&(ipv4MoreFragments|ipv4FragmentOffsetMask) != 0 {
		return buildICMPDestinationUnreachable(ip, source, destination), source, rejectReplyICMP, nil
	}
	if ip[9] == ipProtocolICMP && len(ip[ihl:]) >= 1 && !icmpErrorMayReceiveError(ip[ihl]) {
		return nil, netip.Addr{}, rejectReplyNone, nil
	}
	if ip[9] == ipProtocolTCP {
		reply, ok, err := buildTCPReset(ip, ihl, source, destination)
		if err != nil || ok {
			return reply, source, rejectReplyRST, err
		}
		return nil, netip.Addr{}, rejectReplyNone, nil
	}
	return buildICMPDestinationUnreachable(ip, source, destination), source, rejectReplyICMP, nil
}

func ttlExpiredReplyPacket(packet []byte) ([]byte, netip.Addr, error) {
	ipOffset, ihl, totalLen, err := ipv4HeaderBounds(packet)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	ip := packet[ipOffset : ipOffset+totalLen]
	source := netip.AddrFrom4([4]byte{ip[12], ip[13], ip[14], ip[15]})
	destination := netip.AddrFrom4([4]byte{ip[16], ip[17], ip[18], ip[19]})
	if !source.Is4() || !destination.Is4() {
		return nil, netip.Addr{}, fmt.Errorf("TTL exceeded reply supports only IPv4")
	}
	if ip[9] == ipProtocolICMP && len(ip[ihl:]) >= 1 && !icmpErrorMayReceiveError(ip[ihl]) {
		return nil, netip.Addr{}, nil
	}
	return buildICMPError(ip, source, destination, icmpTypeTimeExceeded, icmpCodeTTLExceeded), source, nil
}

func localICMPEchoReplyPacket(packet []byte) ([]byte, netip.Addr, bool, error) {
	ipOffset, ihl, totalLen, err := ipv4HeaderBounds(packet)
	if err != nil {
		return nil, netip.Addr{}, false, err
	}
	ip := packet[ipOffset : ipOffset+totalLen]
	source := netip.AddrFrom4([4]byte{ip[12], ip[13], ip[14], ip[15]})
	destination := netip.AddrFrom4([4]byte{ip[16], ip[17], ip[18], ip[19]})
	if !source.Is4() || !destination.Is4() {
		return nil, netip.Addr{}, false, fmt.Errorf("ICMP echo reply supports only IPv4")
	}
	flagsAndFragment := binary.BigEndian.Uint16(ip[6:8])
	if flagsAndFragment&(ipv4MoreFragments|ipv4FragmentOffsetMask) != 0 {
		return nil, netip.Addr{}, false, nil
	}
	if ip[9] != ipProtocolICMP {
		return nil, netip.Addr{}, false, nil
	}
	icmp := ip[ihl:]
	if len(icmp) < 8 {
		return nil, netip.Addr{}, false, fmt.Errorf("ICMP echo packet is too short")
	}
	if icmp[0] != icmpTypeEchoRequest {
		return nil, netip.Addr{}, false, nil
	}
	reply := append([]byte(nil), ip...)
	copy(reply[12:16], destination.AsSlice())
	copy(reply[16:20], source.AsSlice())
	reply[8] = 64
	binary.BigEndian.PutUint16(reply[10:12], 0)
	replyICMP := reply[ihl:]
	replyICMP[0] = icmpTypeEchoReply
	replyICMP[1] = 0
	binary.BigEndian.PutUint16(replyICMP[2:4], 0)
	binary.BigEndian.PutUint16(replyICMP[2:4], ipv4Checksum(replyICMP))
	binary.BigEndian.PutUint16(reply[10:12], ipv4Checksum(reply[:ihl]))
	return reply, source, true, nil
}

func buildICMPDestinationUnreachable(original []byte, originalSource netip.Addr, originalDestination netip.Addr) []byte {
	return buildICMPError(original, originalSource, originalDestination, icmpTypeDestinationUnreachable, icmpCodeHostUnreachable)
}

func buildICMPError(original []byte, originalSource netip.Addr, originalDestination netip.Addr, icmpType byte, icmpCode byte) []byte {
	quotedLen := len(original)
	if quotedLen > 28 {
		quotedLen = 28
	}
	totalLen := 20 + 8 + quotedLen
	reply := make([]byte, totalLen)
	reply[0] = 0x45
	reply[8] = 64
	reply[9] = byte(ipProtocolICMP)
	binary.BigEndian.PutUint16(reply[2:4], uint16(totalLen))
	copy(reply[12:16], originalDestination.AsSlice())
	copy(reply[16:20], originalSource.AsSlice())
	reply[20] = icmpType
	reply[21] = icmpCode
	copy(reply[28:], original[:quotedLen])
	binary.BigEndian.PutUint16(reply[22:24], ipv4Checksum(reply[20:]))
	binary.BigEndian.PutUint16(reply[10:12], ipv4Checksum(reply[:20]))
	return reply
}

func buildTCPReset(original []byte, ihl int, originalSource netip.Addr, originalDestination netip.Addr) ([]byte, bool, error) {
	tcp := original[ihl:]
	if len(tcp) < 20 {
		return nil, false, fmt.Errorf("rejected TCP packet is too short")
	}
	tcpHeaderLen := int(tcp[12]>>4) * 4
	if tcpHeaderLen < 20 || len(tcp) < tcpHeaderLen {
		return nil, false, fmt.Errorf("invalid rejected TCP header length %d", tcpHeaderLen)
	}
	if tcp[13]&tcpFlagRST != 0 {
		return nil, false, nil
	}
	segmentLen := len(tcp)
	seq := binary.BigEndian.Uint32(tcp[4:8])
	ack := binary.BigEndian.Uint32(tcp[8:12])
	flags := tcp[13]
	payloadLen := uint32(segmentLen - tcpHeaderLen)
	if flags&tcpFlagSYN != 0 {
		payloadLen++
	}
	if flags&tcpFlagFIN != 0 {
		payloadLen++
	}

	reply := make([]byte, 40)
	reply[0] = 0x45
	reply[8] = 64
	reply[9] = byte(ipProtocolTCP)
	binary.BigEndian.PutUint16(reply[2:4], uint16(len(reply)))
	copy(reply[12:16], originalDestination.AsSlice())
	copy(reply[16:20], originalSource.AsSlice())
	tcpReply := reply[20:]
	copy(tcpReply[0:2], tcp[2:4])
	copy(tcpReply[2:4], tcp[0:2])
	tcpReply[12] = 5 << 4
	tcpReply[13] = tcpFlagRST
	if flags&tcpFlagACK != 0 {
		binary.BigEndian.PutUint32(tcpReply[4:8], ack)
	} else {
		tcpReply[13] |= tcpFlagACK
		binary.BigEndian.PutUint32(tcpReply[8:12], seq+payloadLen)
	}
	binary.BigEndian.PutUint16(tcpReply[14:16], 0)
	binary.BigEndian.PutUint16(tcpReply[16:18], transportChecksum(reply[12:16], reply[16:20], byte(ipProtocolTCP), tcpReply))
	binary.BigEndian.PutUint16(reply[10:12], ipv4Checksum(reply[:20]))
	return reply, true, nil
}

func icmpErrorMayReceiveError(icmpType byte) bool {
	switch icmpType {
	case 0, 8, 13, 14, 15, 16, 17, 18:
		return true
	default:
		return false
	}
}
