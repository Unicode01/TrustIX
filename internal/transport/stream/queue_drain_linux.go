//go:build linux

package stream

import (
	"errors"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

type streamConnQueue struct {
	raw syscall.RawConn
}

func streamKernelQueueDrainDefault() bool {
	return true
}

func newStreamConnQueue(conn net.Conn) (streamConnQueue, bool) {
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		return streamConnQueue{}, false
	}
	raw, err := syscallConn.SyscallConn()
	return streamConnQueue{raw: raw}, err == nil && raw != nil
}

func (queue streamConnQueue) queuedBytes() (int, bool) {
	var queued int
	var ioctlErr error
	if err := queue.raw.Control(func(fd uintptr) {
		queued, ioctlErr = unix.IoctlGetInt(int(fd), unix.TIOCINQ)
	}); err != nil || ioctlErr != nil || queued < 0 {
		return 0, false
	}
	return queued, true
}

func (queue streamConnQueue) peek(dst []byte) (int, bool) {
	if len(dst) == 0 {
		return 0, true
	}
	var n int
	var peekErr error
	if err := queue.raw.Control(func(fd uintptr) {
		n, _, peekErr = unix.Recvfrom(int(fd), dst, unix.MSG_DONTWAIT|unix.MSG_PEEK)
	}); err != nil {
		return 0, false
	}
	if errors.Is(peekErr, unix.EAGAIN) || errors.Is(peekErr, unix.EWOULDBLOCK) {
		return 0, true
	}
	return n, peekErr == nil
}
