//go:build linux

package udp

func defaultUserspaceUDPReadPacketSize() int {
	return userspaceUDPSessionMaxPacket
}

func defaultUserspaceUDPDatagramMaxPacketSize() int {
	return userspaceUDPDatagramDefaultMax
}
