//go:build linux

package udp

func defaultUserspaceUDPReadPacketSize() int {
	return userspaceUDPSessionMaxPacket
}

func defaultUserspaceUDPDatagramMaxPacketSize() int {
	// Keep the advertised send-side limit below a normal 1500-byte underlay MTU.
	// The receive side still accepts larger datagrams for explicit deployments,
	// but the default data path should not induce IP fragmentation under load.
	return userspaceUDPDatagramBatchMax
}
