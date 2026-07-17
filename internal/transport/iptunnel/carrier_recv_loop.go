package iptunnel

import (
	"errors"
	"fmt"
	"net"
	"time"
)

type carrierBatchReadConn interface {
	Read([]byte) (int, error)
	ReadFromUDP([]byte) (int, *net.UDPAddr, error)
	SetReadDeadline(time.Time) error
}

func readCarrierBatchLoop(conn carrierBatchReadConn, max int, packetSize int) ([]carrierReceivedPacket, carrierBatchReceiveResult, func(), error) {
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
		if err := conn.SetReadDeadline(time.Now()); err != nil {
			return packets, result, release, fmt.Errorf("set tunnel carrier batch drain read deadline: %w", err)
		}
		var trailingErr error
		for len(packets) < max {
			buf := takeCarrierReadBuffer(packetSize)
			n, err := conn.Read(buf)
			if err != nil {
				putCarrierReadBuffer(buf)
				if !udpReadErrorTimeout(err) {
					trailingErr = fmt.Errorf("drain tunnel carrier receive batch: %w", err)
				}
				break
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
		resetErr := conn.SetReadDeadline(time.Time{})
		return packets, result, release, errors.Join(trailingErr, wrapCarrierDeadlineResetError(resetErr))
	}
	return packets, result, release, nil
}

func readCarrierBatchFromLoop(conn carrierBatchReadConn, max int, packetSize int) ([]carrierReceivedPacket, carrierBatchReceiveResult, func(), error) {
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
		if err := conn.SetReadDeadline(time.Now()); err != nil {
			return packets, result, nil, fmt.Errorf("set tunnel carrier batch drain read deadline: %w", err)
		}
		var trailingErr error
		for len(packets) < max {
			buf := takeCarrierReadBuffer(packetSize)
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				putCarrierReadBuffer(buf)
				if !udpReadErrorTimeout(err) {
					trailingErr = fmt.Errorf("drain tunnel carrier receive batch: %w", err)
				}
				break
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
		resetErr := conn.SetReadDeadline(time.Time{})
		return packets, result, nil, errors.Join(trailingErr, wrapCarrierDeadlineResetError(resetErr))
	}
	return packets, result, nil, nil
}

func wrapCarrierDeadlineResetError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("restore tunnel carrier receive deadline: %w", err)
}
