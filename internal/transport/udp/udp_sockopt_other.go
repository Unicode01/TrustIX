//go:build !linux

package udp

import "net"

func configureUDPConn(conn *net.UDPConn) {
}
