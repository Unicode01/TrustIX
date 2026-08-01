//go:build !linux

package stream

import "net"

type streamConnQueue struct{}

func streamKernelQueueDrainDefault() bool {
	return false
}

func newStreamConnQueue(net.Conn) (streamConnQueue, bool) {
	return streamConnQueue{}, false
}

func (streamConnQueue) queuedBytes() (int, bool) {
	return 0, false
}

func (streamConnQueue) peek([]byte) (int, bool) {
	return 0, false
}
