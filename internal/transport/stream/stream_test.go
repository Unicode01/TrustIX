package stream

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
)

type countingCloseConn struct {
	net.Conn
	err   error
	calls atomic.Int32
}

type countingWriteConn struct {
	net.Conn
	calls atomic.Int32
}

func (conn *countingWriteConn) Write(payload []byte) (int, error) {
	conn.calls.Add(1)
	return conn.Conn.Write(payload)
}

func (conn *countingCloseConn) Close() error {
	conn.calls.Add(1)
	return errors.Join(conn.err, conn.Conn.Close())
}

func TestSessionCloseIsConcurrentAndErrorPreserving(t *testing.T) {
	local, peer := net.Pipe()
	t.Cleanup(func() {
		if err := peer.Close(); err != nil {
			t.Errorf("close peer: %v", err)
		}
	})
	wantErr := errors.New("injected stream close failure")
	conn := &countingCloseConn{Conn: local, err: wantErr}
	session := NewSession(conn)

	const callers = 16
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- session.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if !errors.Is(err, wantErr) {
			t.Fatalf("close error = %v, want %v", err, wantErr)
		}
	}
	if calls := conn.calls.Load(); calls != 1 {
		t.Fatalf("underlying close calls = %d, want 1", calls)
	}
}

func TestSessionSendBuiltPacketsFramesWithoutIntermediatePacketCopies(t *testing.T) {
	local, peer := net.Pipe()
	t.Cleanup(func() {
		_ = local.Close()
		_ = peer.Close()
	})
	session := NewSession(local)
	packets := [][]byte{[]byte("one"), []byte("second")}
	wantWire := make([]byte, 0, 4+len(packets[0])+4+len(packets[1]))
	for _, packet := range packets {
		wantWire = binary.BigEndian.AppendUint32(wantWire, uint32(len(packet)))
		wantWire = append(wantWire, packet...)
	}
	readResult := make(chan []byte, 1)
	readErr := make(chan error, 1)
	go func() {
		wire := make([]byte, len(wantWire))
		if _, err := io.ReadFull(peer, wire); err != nil {
			readErr <- err
			return
		}
		readResult <- wire
	}()
	sizes := []int{len(packets[0]), len(packets[1])}
	if err := session.SendBuiltPackets(sizes, func(index int, dst []byte) error {
		if len(dst) != sizes[index] {
			t.Fatalf("builder packet %d len = %d, want %d", index, len(dst), sizes[index])
		}
		copy(dst, packets[index])
		return nil
	}); err != nil {
		t.Fatalf("send built packets: %v", err)
	}
	select {
	case err := <-readErr:
		t.Fatalf("read built packet wire: %v", err)
	case wire := <-readResult:
		if !bytes.Equal(wire, wantWire) {
			t.Fatalf("built packet wire = %x, want %x", wire, wantWire)
		}
	}
	stats := session.Stats()
	if stats.PacketsSent != 2 || stats.BytesSent != uint64(len(packets[0])+len(packets[1])) {
		t.Fatalf("built packet stats = packets:%d bytes:%d", stats.PacketsSent, stats.BytesSent)
	}
}

func TestSessionSendBuiltPacketsBuildErrorDoesNotWrite(t *testing.T) {
	local, peer := net.Pipe()
	t.Cleanup(func() {
		_ = local.Close()
		_ = peer.Close()
	})
	conn := &countingWriteConn{Conn: local}
	session := NewSession(conn)
	wantErr := errors.New("injected packet build failure")
	err := session.SendBuiltPackets([]int{4, 8}, func(index int, dst []byte) error {
		if index == 1 {
			return wantErr
		}
		copy(dst, "good")
		return nil
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("send built packets error = %v, want %v", err, wantErr)
	}
	if calls := conn.calls.Load(); calls != 0 {
		t.Fatalf("underlying writes = %d, want 0", calls)
	}
	stats := session.Stats()
	if stats.PacketsSent != 0 || stats.BytesSent != 0 {
		t.Fatalf("failed built packet stats = packets:%d bytes:%d", stats.PacketsSent, stats.BytesSent)
	}
}
