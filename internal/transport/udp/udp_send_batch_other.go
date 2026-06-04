//go:build !linux

package udp

import "net"

func sendUDPBatch(conn *net.UDPConn, packets [][]byte) (udpBatchSendResult, error) {
	return writeUDPBatchLoop(conn, packets)
}

func sendUDPBatchTo(conn *net.UDPConn, remote *net.UDPAddr, packets [][]byte) (udpBatchSendResult, error) {
	return writeUDPBatchToLoop(conn, remote, packets)
}
