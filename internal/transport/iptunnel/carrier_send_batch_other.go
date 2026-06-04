//go:build !linux

package iptunnel

import "net"

func sendCarrierBatch(conn *net.UDPConn, wires [][]byte) (carrierBatchSendResult, error) {
	return writeCarrierBatchLoop(conn, wires)
}

func sendCarrierBatchTo(conn *net.UDPConn, remote *net.UDPAddr, wires [][]byte) (carrierBatchSendResult, error) {
	return writeCarrierBatchToLoop(conn, remote, wires)
}

func sendCarrierPacketBatch(conn *net.UDPConn, packets []carrierBatchPacket) (carrierBatchSendResult, error) {
	return writeCarrierPacketBatchLoop(conn, packets)
}

func sendCarrierPacketBatchTo(conn *net.UDPConn, remote *net.UDPAddr, packets []carrierBatchPacket) (carrierBatchSendResult, error) {
	return writeCarrierPacketBatchToLoop(conn, remote, packets)
}
