//go:build linux

package udp

import (
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func configureUDPConn(conn *net.UDPConn) {
	if conn == nil {
		return
	}
	if raw, err := conn.SyscallConn(); err == nil {
		_ = raw.Control(func(fd uintptr) {
			_ = unix.SetsockoptInt(int(fd), unix.SOL_UDP, unix.UDP_GRO, 1)
		})
	}
	_ = conn.SetReadBuffer(userspaceUDPSocketBufferSize())
	_ = conn.SetWriteBuffer(userspaceUDPSocketBufferSize())
}

func userspaceUDPSocketBufferSize() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_UDP_SOCKET_BUFFER"))
	if value == "" {
		return 8 * 1024 * 1024
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 8 * 1024 * 1024
	}
	if parsed > 64*1024*1024 {
		return 64 * 1024 * 1024
	}
	return parsed
}
