package udp

import "net"

type udpReceivedPacket struct {
	payload []byte
	addr    *net.UDPAddr
}

type udpBatchReceiveResult struct {
	bytesReceived      uint64
	mmsgSyscalls       uint64
	loopSyscalls       uint64
	fallbacks          uint64
	groPackets         uint64
	groSegments        uint64
	groBytes           uint64
	groCmsgErrors      uint64
	groCmsgTruncations uint64
}

func udpGROSegmentCount(payloadLen int, segmentSize int) int {
	if payloadLen <= 0 || segmentSize <= 0 || segmentSize >= payloadLen {
		return 1
	}
	return (payloadLen + segmentSize - 1) / segmentSize
}

func appendUDPGROPayloadSegments(dst [][]byte, payload []byte, segmentSize int) ([][]byte, int) {
	segments := udpGROSegmentCount(len(payload), segmentSize)
	if segments <= 1 {
		return append(dst, payload), 1
	}
	for offset := 0; offset < len(payload); offset += segmentSize {
		end := offset + segmentSize
		if end > len(payload) {
			end = len(payload)
		}
		dst = append(dst, payload[offset:end])
	}
	return dst, segments
}

func readUDPBatchLoop(conn *net.UDPConn, max int, packetSize int) ([][]byte, udpBatchReceiveResult, func(), error) {
	if max <= 0 {
		max = 1
	}
	if packetSize <= 0 {
		packetSize = userspaceUDPDatagramBatchMax
	}
	buf := make([]byte, packetSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, udpBatchReceiveResult{}, nil, err
	}
	packets := make([][]byte, 0, max)
	packets = append(packets, buf[:n])
	result := udpBatchReceiveResult{bytesReceived: uint64(n), loopSyscalls: 1}
	if max > 1 {
		if err := conn.SetReadDeadline(nowForUDPReadBatch()); err == nil {
			for len(packets) < max {
				buf = make([]byte, packetSize)
				n, err = conn.Read(buf)
				if err != nil {
					if udpReadErrorTimeout(err) {
						break
					}
					_ = conn.SetReadDeadline(zeroUDPReadDeadline())
					return packets, result, nil, nil
				}
				packets = append(packets, buf[:n])
				result.bytesReceived += uint64(n)
				result.loopSyscalls++
			}
			_ = conn.SetReadDeadline(zeroUDPReadDeadline())
		}
	}
	return packets, result, nil, nil
}

func readUDPBatchFromLoop(conn *net.UDPConn, max int, packetSize int) ([]udpReceivedPacket, udpBatchReceiveResult, func(), error) {
	if max <= 0 {
		max = 1
	}
	if packetSize <= 0 {
		packetSize = userspaceUDPDatagramBatchMax
	}
	buf := make([]byte, packetSize)
	n, addr, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, udpBatchReceiveResult{}, nil, err
	}
	packets := make([]udpReceivedPacket, 0, max)
	packets = append(packets, udpReceivedPacket{payload: buf[:n], addr: addr})
	result := udpBatchReceiveResult{bytesReceived: uint64(n), loopSyscalls: 1}
	if max > 1 {
		if err := conn.SetReadDeadline(nowForUDPReadBatch()); err == nil {
			for len(packets) < max {
				buf = make([]byte, packetSize)
				n, addr, err = conn.ReadFromUDP(buf)
				if err != nil {
					if udpReadErrorTimeout(err) {
						break
					}
					_ = conn.SetReadDeadline(zeroUDPReadDeadline())
					return packets, result, nil, nil
				}
				packets = append(packets, udpReceivedPacket{payload: buf[:n], addr: addr})
				result.bytesReceived += uint64(n)
				result.loopSyscalls++
			}
			_ = conn.SetReadDeadline(zeroUDPReadDeadline())
		}
	}
	return packets, result, nil, nil
}
