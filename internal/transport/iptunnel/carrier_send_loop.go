package iptunnel

import "net"

type carrierBatchSendResult struct {
	bytesSent    uint64
	mmsgSyscalls uint64
	gsoSyscalls  uint64
	loopSyscalls uint64
	fallbacks    uint64
}

func writeCarrierBatchLoop(conn *net.UDPConn, wires [][]byte) (carrierBatchSendResult, error) {
	var result carrierBatchSendResult
	for _, wire := range wires {
		n, err := conn.Write(wire)
		if err != nil {
			return result, err
		}
		result.bytesSent += uint64(n)
		result.loopSyscalls++
	}
	return result, nil
}

func writeCarrierBatchToLoop(conn *net.UDPConn, remote *net.UDPAddr, wires [][]byte) (carrierBatchSendResult, error) {
	var result carrierBatchSendResult
	for _, wire := range wires {
		n, err := conn.WriteToUDP(wire, remote)
		if err != nil {
			return result, err
		}
		result.bytesSent += uint64(n)
		result.loopSyscalls++
	}
	return result, nil
}

func writeCarrierPacketBatchLoop(conn *net.UDPConn, packets []carrierBatchPacket) (carrierBatchSendResult, error) {
	var result carrierBatchSendResult
	for _, packet := range packets {
		wire, err := carrierBatchPacketWire(packet)
		if err != nil {
			return result, err
		}
		n, err := conn.Write(wire)
		if err != nil {
			return result, err
		}
		result.bytesSent += uint64(n)
		result.loopSyscalls++
	}
	return result, nil
}

func writeCarrierPacketBatchToLoop(conn *net.UDPConn, remote *net.UDPAddr, packets []carrierBatchPacket) (carrierBatchSendResult, error) {
	var result carrierBatchSendResult
	for _, packet := range packets {
		wire, err := carrierBatchPacketWire(packet)
		if err != nil {
			return result, err
		}
		n, err := conn.WriteToUDP(wire, remote)
		if err != nil {
			return result, err
		}
		result.bytesSent += uint64(n)
		result.loopSyscalls++
	}
	return result, nil
}

func carrierBatchPacketWire(packet carrierBatchPacket) ([]byte, error) {
	wire := make([]byte, 0, len(packet.header)+len(packet.payload))
	wire = append(wire, packet.header...)
	wire = append(wire, packet.payload...)
	return wire, nil
}
