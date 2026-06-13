//go:build !linux

package iptunnel

import "net"

func recvCarrierBatch(conn *net.UDPConn, max int, packetSize int) ([]carrierReceivedPacket, carrierBatchReceiveResult, func(), error) {
	return readCarrierBatchLoop(conn, max, packetSize)
}

func recvCarrierBatchFrom(conn *net.UDPConn, max int, packetSize int) ([]carrierReceivedPacket, carrierBatchReceiveResult, func(), error) {
	return readCarrierBatchFromLoop(conn, max, packetSize)
}
