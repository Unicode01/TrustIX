//go:build !linux

package udp

import "net"

func recvUDPBatch(conn *net.UDPConn, max int, packetSize int) ([][]byte, udpBatchReceiveResult, func(), error) {
	return readUDPBatchLoop(conn, max, packetSize)
}

func recvUDPBatchFrom(conn *net.UDPConn, max int, packetSize int) ([]udpReceivedPacket, udpBatchReceiveResult, func(), error) {
	return readUDPBatchFromLoop(conn, max, packetSize)
}
