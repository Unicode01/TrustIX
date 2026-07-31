package daemon

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"trustix.local/trustix/internal/dataplane"
)

func TestCaptureBatchWorkZeroDelayDrainsQueuedWork(t *testing.T) {
	workCh := make(chan captureBatchWork, 3)
	var released atomic.Int32
	for i := byte(1); i <= 3; i++ {
		workCh <- captureBatchWork{
			events:  []dataplane.CaptureEvent{{Payload: []byte{i}}},
			release: func() { released.Add(1) },
		}
	}
	close(workCh)

	var batches [][]byte
	forwardCapturedPacketBatchWorkCoalescedLoop(
		context.Background(),
		workCh,
		3,
		0,
		func(_ context.Context, events []dataplane.CaptureEvent, _ *captureForwardScratch) bool {
			payloads := make([]byte, len(events))
			for i := range events {
				payloads[i] = events[i].Payload[0]
			}
			batches = append(batches, payloads)
			return true
		},
	)

	if len(batches) != 1 || string(batches[0]) != "\x01\x02\x03" {
		t.Fatalf("forwarded batches = %v, want one drained three-event batch", batches)
	}
	if got := released.Load(); got != 3 {
		t.Fatalf("release count = %d, want 3", got)
	}
}

func TestCaptureBatchWorkZeroDelayFlushesWithoutWaiting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	workCh := make(chan captureBatchWork)
	forwarded := make(chan int, 1)
	done := make(chan struct{})
	var released atomic.Int32
	go func() {
		defer close(done)
		forwardCapturedPacketBatchWorkCoalescedLoop(
			ctx,
			workCh,
			1024,
			0,
			func(_ context.Context, events []dataplane.CaptureEvent, _ *captureForwardScratch) bool {
				forwarded <- len(events)
				return true
			},
		)
	}()

	workCh <- captureBatchWork{
		events:  []dataplane.CaptureEvent{{Payload: []byte{1}}},
		release: func() { released.Add(1) },
	}
	select {
	case got := <-forwarded:
		if got != 1 {
			t.Fatalf("forwarded event count = %d, want 1", got)
		}
	case <-time.After(time.Second):
		t.Fatal("zero-delay capture work did not flush promptly")
	}
	close(workCh)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("capture work loop did not stop after channel close")
	}
	if got := released.Load(); got != 1 {
		t.Fatalf("release count = %d, want 1", got)
	}
}

func TestCaptureBatchWorkZeroDelayReleasesPendingWorkWhenForwardStops(t *testing.T) {
	workCh := make(chan captureBatchWork, 2)
	var released atomic.Int32
	for i := 0; i < 2; i++ {
		workCh <- captureBatchWork{
			events:  []dataplane.CaptureEvent{{Payload: []byte{byte(i)}}},
			release: func() { released.Add(1) },
		}
	}

	var calls atomic.Int32
	forwardCapturedPacketBatchWorkCoalescedLoop(
		context.Background(),
		workCh,
		2,
		0,
		func(_ context.Context, events []dataplane.CaptureEvent, _ *captureForwardScratch) bool {
			calls.Add(1)
			return false
		},
	)

	if got := calls.Load(); got != 1 {
		t.Fatalf("forward call count = %d, want 1", got)
	}
	if got := released.Load(); got != 2 {
		t.Fatalf("release count = %d, want 2", got)
	}
}
