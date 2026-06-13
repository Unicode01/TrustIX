package iptunnel

import (
	"net"
	"time"
)

func readCarrierBatchLoop(conn *net.UDPConn, max int, packetSize int) ([]carrierReceivedPacket, carrierBatchReceiveResult, func(), error) {
	if max <= 0 {
		max = 1
	}
	packetSize = carrierReadBufferSize(packetSize)
	packets := make([]carrierReceivedPacket, 0, max)
	buffers := make([][]byte, 0, max)
	release := func() {
		for _, buffer := range buffers {
			putCarrierReadBuffer(buffer)
		}
	}
	result := carrierBatchReceiveResult{}
	for len(packets) == 0 {
		buf := takeCarrierReadBuffer(packetSize)
		n, err := conn.Read(buf)
		if err != nil {
			putCarrierReadBuffer(buf)
			return nil, result, nil, err
		}
		packet, err := decodeCarrierFrameView(buf[:n])
		if err != nil {
			putCarrierReadBuffer(buf)
			continue
		}
		packet.buffer = buf
		packet.wireLen = n
		packets = append(packets, packet)
		buffers = append(buffers, buf)
		result.bytesReceived += uint64(n)
		result.loopSyscalls++
	}
	if max > 1 {
		if err := conn.SetReadDeadline(time.Now()); err == nil {
			for len(packets) < max {
				buf := takeCarrierReadBuffer(packetSize)
				n, err := conn.Read(buf)
				if err != nil {
					putCarrierReadBuffer(buf)
					if udpReadErrorTimeout(err) {
						break
					}
					_ = conn.SetReadDeadline(time.Time{})
					return packets, result, release, nil
				}
				packet, err := decodeCarrierFrameView(buf[:n])
				if err != nil {
					putCarrierReadBuffer(buf)
					_ = conn.SetReadDeadline(time.Time{})
					return packets, result, release, nil
				}
				packet.buffer = buf
				packet.wireLen = n
				packets = append(packets, packet)
				buffers = append(buffers, buf)
				result.bytesReceived += uint64(n)
				result.loopSyscalls++
			}
			_ = conn.SetReadDeadline(time.Time{})
		}
	}
	return packets, result, release, nil
}

func readCarrierBatchFromLoop(conn *net.UDPConn, max int, packetSize int) ([]carrierReceivedPacket, carrierBatchReceiveResult, func(), error) {
	if max <= 0 {
		max = 1
	}
	packetSize = carrierReadBufferSize(packetSize)
	packets := make([]carrierReceivedPacket, 0, max)
	result := carrierBatchReceiveResult{}
	for len(packets) == 0 {
		buf := takeCarrierReadBuffer(packetSize)
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			putCarrierReadBuffer(buf)
			return nil, result, nil, err
		}
		packet, err := decodeCarrierFrameView(buf[:n])
		if err != nil {
			putCarrierReadBuffer(buf)
			continue
		}
		packet.wireLen = n
		packet.buffer = buf
		packet.addr = addr
		packets = append(packets, packet)
		result.bytesReceived += uint64(n)
		result.loopSyscalls++
	}
	if max > 1 {
		if err := conn.SetReadDeadline(time.Now()); err == nil {
			for len(packets) < max {
				buf := takeCarrierReadBuffer(packetSize)
				n, addr, err := conn.ReadFromUDP(buf)
				if err != nil {
					putCarrierReadBuffer(buf)
					if udpReadErrorTimeout(err) {
						break
					}
					_ = conn.SetReadDeadline(time.Time{})
					return packets, result, nil, nil
				}
				packet, err := decodeCarrierFrameView(buf[:n])
				if err != nil {
					putCarrierReadBuffer(buf)
					continue
				}
				packet.wireLen = n
				packet.buffer = buf
				packet.addr = addr
				packets = append(packets, packet)
				result.bytesReceived += uint64(n)
				result.loopSyscalls++
			}
			_ = conn.SetReadDeadline(time.Time{})
		}
	}
	return packets, result, nil, nil
}
