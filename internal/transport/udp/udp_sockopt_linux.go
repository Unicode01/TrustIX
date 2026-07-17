//go:build linux

package udp

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func configureUDPConn(conn *net.UDPConn) error {
	if conn == nil {
		return nil
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("access UDP socket: %w", err)
	}
	var groErr error
	if err := raw.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_UDP, unix.UDP_GRO, 1); err != nil && !optionalUDPGROError(err) {
			groErr = err
		}
	}); err != nil {
		return fmt.Errorf("configure UDP socket: %w", err)
	}
	if groErr != nil {
		return fmt.Errorf("enable UDP_GRO: %w", groErr)
	}
	bufferSize := userspaceUDPSocketBufferSize()
	if err := conn.SetReadBuffer(bufferSize); err != nil {
		return fmt.Errorf("set UDP read buffer to %d: %w", bufferSize, err)
	}
	if err := conn.SetWriteBuffer(bufferSize); err != nil {
		return fmt.Errorf("set UDP write buffer to %d: %w", bufferSize, err)
	}
	return nil
}

func optionalUDPGROError(err error) bool {
	return errors.Is(err, unix.ENOPROTOOPT) ||
		errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.ENOTSUP) ||
		errors.Is(err, unix.EINVAL)
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
