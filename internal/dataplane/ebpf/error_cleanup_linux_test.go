//go:build linux

package ebpf

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestErrorCleanupStackRunsInReverseAndJoinsErrors(t *testing.T) {
	firstErr := errors.New("first cleanup failed")
	secondErr := errors.New("second cleanup failed")
	var order []string
	var stack errorCleanupStack
	stack.Add("first", func() error {
		order = append(order, "first")
		return firstErr
	})
	stack.Add("second", func() error {
		order = append(order, "second")
		return secondErr
	})

	err := stack.Run()
	if !reflect.DeepEqual(order, []string{"second", "first"}) {
		t.Fatalf("cleanup order = %v, want reverse registration order", order)
	}
	if !errors.Is(err, firstErr) || !errors.Is(err, secondErr) {
		t.Fatalf("cleanup error = %v, want both failures", err)
	}
	if err := stack.Run(); err != nil {
		t.Fatalf("second cleanup run = %v, want nil", err)
	}
}

func TestErrorCleanupStackDisarmTransfersOwnership(t *testing.T) {
	called := false
	var stack errorCleanupStack
	stack.Add("unexpected cleanup", func() error {
		called = true
		return nil
	})
	stack.Disarm()

	if err := stack.Run(); err != nil || called {
		t.Fatalf("disarmed cleanup err=%v called=%t", err, called)
	}
}

func TestBackgroundTaskTrackerWaitReturnsTaskError(t *testing.T) {
	wantErr := errors.New("background failure")
	var tracker backgroundTaskTracker
	tracker.Go("test task", func() error { return wantErr })

	if err := tracker.Wait(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("wait error = %v, want %v", err, wantErr)
	}
	if err := tracker.Wait(context.Background()); err != nil {
		t.Fatalf("second wait error = %v, want nil after error was consumed", err)
	}
}

func TestAFXDPSocketClosePreservesCleanupError(t *testing.T) {
	socket := &afXDPSocket{fd: 1 << 30, txSocketGSOFD: -1}

	firstErr := socket.Close()
	secondErr := socket.Close()
	if !errors.Is(firstErr, unix.EBADF) {
		t.Fatalf("first close error = %v, want EBADF", firstErr)
	}
	if !errors.Is(secondErr, unix.EBADF) {
		t.Fatalf("second close error = %v, want preserved EBADF", secondErr)
	}
}

func TestKernelUDPUDPFallbackSocketSetCloseUnblocksIdleReadersTogether(t *testing.T) {
	const socketCount = 3
	sockets := make([]*kernelUDPUDPFallbackSocket, 0, socketCount)
	manager := NewManager()
	done := make(chan error, socketCount)
	for range socketCount {
		socket, err := openKernelUDPUDPFallbackSocket(0)
		if err != nil {
			if cleanupErr := closeKernelUDPUDPFallbackSocketSet(sockets); cleanupErr != nil {
				t.Logf("cleanup sockets after open failure: %v", cleanupErr)
			}
			t.Fatalf("open fallback socket: %v", err)
		}
		sockets = append(sockets, socket)
		go func() {
			done <- manager.readKernelUDPUDPFallbackFrames(socket)
		}()
	}
	time.Sleep(50 * time.Millisecond)

	started := time.Now()
	if err := closeKernelUDPUDPFallbackSocketSet(sockets); err != nil {
		t.Fatalf("close fallback sockets: %v", err)
	}
	if elapsed := time.Since(started); elapsed >= 2500*time.Millisecond {
		t.Fatalf("closing %d idle fallback sockets took %s; closes were serialized", socketCount, elapsed)
	}
	for range socketCount {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("idle fallback reader exit error: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("idle fallback reader did not stop after socket close")
		}
	}
}
