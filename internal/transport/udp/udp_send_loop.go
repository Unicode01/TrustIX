package udp

import "net"

type udpBatchSendResult struct {
	bytesSent    uint64
	mmsgSyscalls uint64
	loopSyscalls uint64
	fallbacks    uint64
}

func writeUDPBatchLoop(conn *net.UDPConn, packets [][]byte) (udpBatchSendResult, error) {
	var result udpBatchSendResult
	for _, packet := range packets {
		n, err := conn.Write(packet)
		if err != nil {
			return result, err
		}
		result.bytesSent += uint64(n)
		result.loopSyscalls++
	}
	return result, nil
}

func writeUDPBatchToLoop(conn *net.UDPConn, remote *net.UDPAddr, packets [][]byte) (udpBatchSendResult, error) {
	var result udpBatchSendResult
	for _, packet := range packets {
		n, err := conn.WriteToUDP(packet, remote)
		if err != nil {
			return result, err
		}
		result.bytesSent += uint64(n)
		result.loopSyscalls++
	}
	return result, nil
}
