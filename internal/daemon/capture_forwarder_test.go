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

func TestCaptureBatchDispatchCompletionWaitsAndClearsBeforeRelease(t *testing.T) {
	var pool captureBatchDispatchGroupPool
	groups := pool.take(2)
	groups.groups[0] = append(groups.groups[0], dataplane.CaptureEvent{
		Hook:    "old-a",
		Payload: []byte{1},
	})
	groups.groups[1] = append(groups.groups[1], dataplane.CaptureEvent{
		Hook:    "old-b",
		Payload: []byte{2},
	})
	groupA := groups.groups[0]
	groupB := groups.groups[1]
	batch := []dataplane.CaptureEvent{{Payload: []byte{9}}}
	var released atomic.Int32
	completion := newCaptureBatchDispatchCompletion(
		&pool,
		groups,
		func(got []dataplane.CaptureEvent) {
			if len(got) != len(batch) || &got[0] != &batch[0] {
				t.Errorf("released batch does not reference the original lease")
			}
			if groupA[0].Payload != nil || groupA[0].Hook != "" || groupB[0].Payload != nil || groupB[0].Hook != "" {
				t.Errorf("pooled group references were not cleared before releasing the source batch")
			}
			released.Add(1)
		},
		batch,
		2,
	)

	done := completion.done
	done()
	if got := released.Load(); got != 0 {
		t.Fatalf("release count after first worker = %d, want 0", got)
	}
	if groupA[0].Payload == nil || groupB[0].Payload == nil {
		t.Fatal("group storage was cleared before all recipients completed")
	}
	completion.done()
	if got := released.Load(); got != 0 {
		t.Fatalf("release count while one worker remains = %d, want 0", got)
	}
	done()
	if got := released.Load(); got != 1 {
		t.Fatalf("release count after completion = %d, want 1", got)
	}
	done()
	if got := released.Load(); got != 1 {
		t.Fatalf("release count after duplicate completion = %d, want 1", got)
	}

	reused := pool.take(2)
	for index := range reused.groups {
		if len(reused.groups[index]) != 0 {
			t.Fatalf("reused group %d length = %d, want 0", index, len(reused.groups[index]))
		}
	}
	pool.put(reused)
}

func TestDispatchCapturedPacketBatchGroupsPooledCancellationRetainsQueuedWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	batches := make(chan []dataplane.CaptureEvent, 1)
	batch := []dataplane.CaptureEvent{
		{Payload: []byte{1}},
		{Payload: []byte{2}},
	}
	batches <- batch
	close(batches)
	queues := []chan captureBatchWork{
		make(chan captureBatchWork, 1),
		make(chan captureBatchWork),
	}
	var pool captureBatchDispatchGroupPool
	var released atomic.Int32
	dispatchDone := make(chan struct{})
	go func() {
		defer close(dispatchDone)
		new(Daemon).dispatchCapturedPacketBatchGroupsWithPool(
			ctx,
			batches,
			queues,
			func(got []dataplane.CaptureEvent) {
				if len(got) != len(batch) || &got[0] != &batch[0] {
					t.Errorf("released batch does not reference the original lease")
				}
				released.Add(1)
			},
			&pool,
		)
	}()

	var queued captureBatchWork
	select {
	case queued = <-queues[0]:
	case <-time.After(time.Second):
		t.Fatal("first worker group was not queued")
	}
	cancel()
	select {
	case <-dispatchDone:
	case <-time.After(time.Second):
		t.Fatal("dispatcher did not stop after cancellation")
	}
	if got := released.Load(); got != 0 {
		t.Fatalf("release count while queued work remains = %d, want 0", got)
	}
	if len(queued.events) != 1 || len(queued.events[0].Payload) != 1 || queued.events[0].Payload[0] != 1 {
		t.Fatalf("queued work was recycled before completion: %+v", queued.events)
	}
	queuedEvents := queued.events
	queued.finish()
	if got := released.Load(); got != 1 {
		t.Fatalf("release count after queued work completion = %d, want 1", got)
	}
	if queuedEvents[0].Payload != nil || queuedEvents[0].Hook != "" {
		t.Fatal("queued group references were not cleared on final completion")
	}
}

func TestDispatchCapturedPacketBatchGroupsPreservesWorkerOrderAndFinalRelease(t *testing.T) {
	batches := make(chan []dataplane.CaptureEvent, 1)
	batch := []dataplane.CaptureEvent{
		{Payload: []byte{1}},
		{Payload: []byte{2}},
		{Payload: []byte{3}},
		{Payload: []byte{4}},
	}
	batches <- batch
	close(batches)
	queues := []chan captureBatchWork{
		make(chan captureBatchWork, 1),
		make(chan captureBatchWork, 1),
		make(chan captureBatchWork, 1),
	}
	var pool captureBatchDispatchGroupPool
	var released atomic.Int32
	new(Daemon).dispatchCapturedPacketBatchGroupsWithPool(
		context.Background(),
		batches,
		queues,
		func(got []dataplane.CaptureEvent) {
			if len(got) != len(batch) || &got[0] != &batch[0] {
				t.Errorf("released batch does not reference the original lease")
			}
			released.Add(1)
		},
		&pool,
	)
	if got := released.Load(); got != 0 {
		t.Fatalf("release count before workers finish = %d, want 0", got)
	}

	works := []captureBatchWork{<-queues[0], <-queues[1], <-queues[2]}
	want := [][]byte{{1, 4}, {2}, {3}}
	aliases := make([][]dataplane.CaptureEvent, len(works))
	for worker := range works {
		aliases[worker] = works[worker].events
		got := make([]byte, len(works[worker].events))
		for index := range works[worker].events {
			got[index] = works[worker].events[index].Payload[0]
		}
		if string(got) != string(want[worker]) {
			t.Fatalf("worker %d payload order = %v, want %v", worker, got, want[worker])
		}
		works[worker].finish()
		if worker < len(works)-1 && released.Load() != 0 {
			t.Fatalf("source batch released after worker %d while recipients remain", worker)
		}
	}
	if got := released.Load(); got != 1 {
		t.Fatalf("release count after all workers finish = %d, want 1", got)
	}
	for worker := range aliases {
		for index := range aliases[worker] {
			if aliases[worker][index].Payload != nil {
				t.Fatalf("worker %d event %d retained payload after recycle", worker, index)
			}
		}
	}
}

func TestCaptureBatchDispatchGroupPoolDoesNotAliasInFlightBundles(t *testing.T) {
	var pool captureBatchDispatchGroupPool
	first := pool.take(2)
	second := pool.take(2)
	if first == second {
		t.Fatal("pool reused a bundle that was still in flight")
	}
	first.groups[0] = append(first.groups[0], dataplane.CaptureEvent{Hook: "first"})
	second.groups[0] = append(second.groups[0], dataplane.CaptureEvent{Hook: "second"})
	second.groups[0][0].Hook = "changed"
	if got := first.groups[0][0].Hook; got != "first" {
		t.Fatalf("in-flight bundle was aliased: hook = %q, want first", got)
	}
	pool.put(first)
	pool.put(second)
}
