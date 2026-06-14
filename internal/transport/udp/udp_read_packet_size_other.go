//go:build !linux

package udp

func defaultUserspaceUDPReadPacketSize() int {
	return userspaceUDPDatagramBatchMax
}

func defaultUserspaceUDPDatagramMaxPacketSize() int {
	return userspaceUDPDatagramBatchMax
}
