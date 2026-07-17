package iptunnel

import (
	"errors"
	"net"
	"testing"
	"time"
)

type scriptedCarrierRead struct {
	payload []byte
	addr    *net.UDPAddr
	err     error
}

type scriptedCarrierBatchConn struct {
	reads        []scriptedCarrierRead
	readIndex    int
	deadlineErrs []error
	deadlineCall int
}

func (conn *scriptedCarrierBatchConn) Read(dst []byte) (int, error) {
	item := conn.nextRead()
	return copy(dst, item.payload), item.err
}

func (conn *scriptedCarrierBatchConn) ReadFromUDP(dst []byte) (int, *net.UDPAddr, error) {
	item := conn.nextRead()
	return copy(dst, item.payload), item.addr, item.err
}

func (conn *scriptedCarrierBatchConn) SetReadDeadline(time.Time) error {
	index := conn.deadlineCall
	conn.deadlineCall++
	if index < len(conn.deadlineErrs) {
		return conn.deadlineErrs[index]
	}
	return nil
}

func (conn *scriptedCarrierBatchConn) nextRead() scriptedCarrierRead {
	if conn.readIndex >= len(conn.reads) {
		return scriptedCarrierRead{err: carrierBatchTimeoutError{}}
	}
	item := conn.reads[conn.readIndex]
	conn.readIndex++
	return item
}

type carrierBatchTimeoutError struct{}

func (carrierBatchTimeoutError) Error() string   { return "injected timeout" }
func (carrierBatchTimeoutError) Timeout() bool   { return true }
func (carrierBatchTimeoutError) Temporary() bool { return true }

func TestReadCarrierBatchLoopPreservesPacketAndTrailingErrors(t *testing.T) {
	wantReadErr := errors.New("injected trailing read failure")
	wantResetErr := errors.New("injected deadline reset failure")
	wire, err := encodeCarrier([]byte("first"), 1)
	if err != nil {
		t.Fatalf("encode carrier frame: %v", err)
	}
	conn := &scriptedCarrierBatchConn{
		reads: []scriptedCarrierRead{
			{payload: wire},
			{err: wantReadErr},
		},
		deadlineErrs: []error{nil, wantResetErr},
	}

	packets, _, release, err := readCarrierBatchLoop(conn, 4, len(wire)+16)
	if len(packets) != 1 || string(packets[0].payload) != "first" {
		t.Fatalf("packets = %#v, want first carrier packet", packets)
	}
	if release == nil {
		t.Fatal("connected carrier batch did not return buffer release callback")
	}
	release()
	if !errors.Is(err, wantReadErr) || !errors.Is(err, wantResetErr) {
		t.Fatalf("error = %v, want read and deadline reset failures", err)
	}
}

func TestReadCarrierBatchFromLoopPreservesOwnedPacketOnDeadlineFailure(t *testing.T) {
	wantErr := errors.New("injected deadline setup failure")
	wantAddr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 2), Port: 7001}
	wire, err := encodeCarrier([]byte("first"), 1)
	if err != nil {
		t.Fatalf("encode carrier frame: %v", err)
	}
	conn := &scriptedCarrierBatchConn{
		reads:        []scriptedCarrierRead{{payload: wire, addr: wantAddr}},
		deadlineErrs: []error{wantErr},
	}

	packets, _, release, err := readCarrierBatchFromLoop(conn, 4, len(wire)+16)
	if len(packets) != 1 || string(packets[0].payload) != "first" || packets[0].addr.String() != wantAddr.String() {
		t.Fatalf("packets = %#v, want owned first carrier packet", packets)
	}
	if release != nil {
		t.Fatal("listener carrier batch unexpectedly owns packet buffers")
	}
	releaseCarrierReceivedPacket(packets[0])
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want deadline setup failure", err)
	}
}
