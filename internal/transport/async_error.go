package transport

import (
	"fmt"
	"log"
	"sync"
)

// ObserveAsyncError records a failure from work that has no synchronous caller.
// Callers with an error return must propagate the error instead of using this helper.
func ObserveAsyncError(operation string, err error) {
	if err != nil {
		log.Printf("trustix transport: %s: %v", operation, err)
	}
}

// AsyncErrorTracker preserves the first asynchronous failure for Close while
// still reporting every occurrence when it happens.
type AsyncErrorTracker struct {
	mu  sync.Mutex
	err error
}

func (tracker *AsyncErrorTracker) Record(operation string, err error) {
	if err == nil {
		return
	}
	ObserveAsyncError(operation, err)
	tracker.mu.Lock()
	if tracker.err == nil {
		tracker.err = fmt.Errorf("%s: %w", operation, err)
	}
	tracker.mu.Unlock()
}

func (tracker *AsyncErrorTracker) Err() error {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return tracker.err
}
