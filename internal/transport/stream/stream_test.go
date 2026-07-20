package stream

import (
	"errors"
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
