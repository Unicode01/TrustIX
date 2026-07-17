package udp

import (
	"errors"
	"net"
	"testing"
	"time"
)

type scriptedUDPRead struct {
	payload []byte
	addr    *net.UDPAddr
	err     error
}

type scriptedUDPBatchConn struct {
	reads        []scriptedUDPRead
	readIndex    int
	deadlineErrs []error
	deadlineCall int
}

func (conn *scriptedUDPBatchConn) Read(dst []byte) (int, error) {
	item := conn.nextRead()
	return copy(dst, item.payload), item.err
}

func (conn *scriptedUDPBatchConn) ReadFromUDP(dst []byte) (int, *net.UDPAddr, error) {
	item := conn.nextRead()
	return copy(dst, item.payload), item.addr, item.err
}

func (conn *scriptedUDPBatchConn) SetReadDeadline(time.Time) error {
	index := conn.deadlineCall
	conn.deadlineCall++
	if index < len(conn.deadlineErrs) {
		return conn.deadlineErrs[index]
	}
	return nil
}

func (conn *scriptedUDPBatchConn) nextRead() scriptedUDPRead {
	if conn.readIndex >= len(conn.reads) {
		return scriptedUDPRead{err: udpBatchTimeoutError{}}
	}
	item := conn.reads[conn.readIndex]
	conn.readIndex++
	return item
}

type udpBatchTimeoutError struct{}

func (udpBatchTimeoutError) Error() string   { return "injected timeout" }
func (udpBatchTimeoutError) Timeout() bool   { return true }
func (udpBatchTimeoutError) Temporary() bool { return true }

func TestReadUDPBatchLoopPreservesPacketAndDeadlineResetError(t *testing.T) {
	wantErr := errors.New("injected deadline reset failure")
	conn := &scriptedUDPBatchConn{
		reads: []scriptedUDPRead{
			{payload: []byte("first")},
			{err: udpBatchTimeoutError{}},
		},
		deadlineErrs: []error{nil, wantErr},
	}

	packets, _, release, err := readUDPBatchLoop(conn, 4, 64)
	if len(packets) != 1 || string(packets[0]) != "first" {
		t.Fatalf("packets = %q, want first packet", packets)
	}
	if release != nil {
		t.Fatal("loop receive unexpectedly returned a release callback")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want deadline reset failure", err)
	}
}

func TestReadUDPBatchFromLoopPreservesPacketAndTrailingReadError(t *testing.T) {
	wantErr := errors.New("injected trailing read failure")
	wantAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 7000}
	conn := &scriptedUDPBatchConn{reads: []scriptedUDPRead{
		{payload: []byte("first"), addr: wantAddr},
		{err: wantErr},
	}}

	packets, _, release, err := readUDPBatchFromLoop(conn, 4, 64)
	if len(packets) != 1 || string(packets[0].payload) != "first" || packets[0].addr.String() != wantAddr.String() {
		t.Fatalf("packets = %#v, want first packet from %s", packets, wantAddr)
	}
	if release != nil {
		t.Fatal("loop receive unexpectedly returned a release callback")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want trailing read failure", err)
	}
}

func TestReadUDPBatchLoopPreservesPacketWhenDrainDeadlineCannotBeSet(t *testing.T) {
	wantErr := errors.New("injected deadline setup failure")
	conn := &scriptedUDPBatchConn{
		reads:        []scriptedUDPRead{{payload: []byte("first")}},
		deadlineErrs: []error{wantErr},
	}

	packets, _, _, err := readUDPBatchLoop(conn, 4, 64)
	if len(packets) != 1 || string(packets[0]) != "first" {
		t.Fatalf("packets = %q, want first packet", packets)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want deadline setup failure", err)
	}
}
