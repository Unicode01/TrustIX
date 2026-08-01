//go:build linux

package stream

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

type syscallCountingTCPConn struct {
	*net.TCPConn
	calls int
}

func (conn *syscallCountingTCPConn) SyscallConn() (syscall.RawConn, error) {
	conn.calls++
	return conn.TCPConn.SyscallConn()
}

func TestSessionKernelQueueDrainReadsCompleteQueuedRecord(t *testing.T) {
	t.Setenv("TRUSTIX_STREAM_KERNEL_QUEUE_DRAIN", "1")
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen TCP: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("dial TCP: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	var server *net.TCPConn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		t.Fatalf("accept TCP: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("accept TCP timed out")
	}
	t.Cleanup(func() { _ = server.Close() })

	first := bytes.Repeat([]byte{0x5a}, 128*1024)
	second := []byte("queued-record")
	wire := make([]byte, 4+len(first)+4+len(second))
	binary.BigEndian.PutUint32(wire[0:4], uint32(len(first)))
	copy(wire[4:4+len(first)], first)
	offset := 4 + len(first)
	binary.BigEndian.PutUint32(wire[offset:offset+4], uint32(len(second)))
	copy(wire[offset+4:], second)
	if _, err := io.Copy(client, bytes.NewReader(wire)); err != nil {
		t.Fatalf("write framed records: %v", err)
	}

	countingServer := &syscallCountingTCPConn{TCPConn: server}
	session := NewSession(countingServer)
	packets, release, err := session.RecvPacketsWithRelease(128)
	if err != nil {
		t.Fatalf("receive queued records: %v", err)
	}
	if release != nil {
		defer release()
	}
	if len(packets) != 2 {
		t.Fatalf("received packets = %d, want 2", len(packets))
	}
	if !bytes.Equal(packets[0], first) || !bytes.Equal(packets[1], second) {
		t.Fatal("received queued record payload mismatch")
	}
	stats := session.Stats()
	if stats.Extra["stream_kernel_queue_drain_reads"] != 1 || stats.Extra["stream_kernel_queue_drain_bytes"] != uint64(len(second)) {
		t.Fatalf("kernel queue drain stats = %#v", stats.Extra)
	}
	if countingServer.calls != 1 {
		t.Fatalf("SyscallConn calls = %d, want 1", countingServer.calls)
	}
}
