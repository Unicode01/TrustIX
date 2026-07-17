//go:build linux

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"

	cebpf "github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

type backgroundErrorTracker struct {
	mu  sync.Mutex
	err error
}

func (tracker *backgroundErrorTracker) Record(operation string, err error) {
	if err == nil {
		return
	}
	log.Printf("trustix ebpf: %s: %v", operation, err)
	tracker.mu.Lock()
	if tracker.err == nil {
		tracker.err = fmt.Errorf("%s: %w", operation, err)
	}
	tracker.mu.Unlock()
}

func (tracker *backgroundErrorTracker) Err() error {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return tracker.err
}

func (tracker *backgroundErrorTracker) Take() error {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	err := tracker.err
	tracker.err = nil
	return err
}

type backgroundTaskTracker struct {
	mu     sync.Mutex
	active int
	idle   chan struct{}
	errors backgroundErrorTracker
}

func (tracker *backgroundTaskTracker) Go(operation string, action func() error) {
	if action == nil {
		return
	}
	tracker.mu.Lock()
	if tracker.active == 0 {
		tracker.idle = make(chan struct{})
	}
	tracker.active++
	tracker.mu.Unlock()
	go func() {
		err := action()
		tracker.errors.Record(operation, err)
		tracker.mu.Lock()
		tracker.active--
		if tracker.active == 0 {
			close(tracker.idle)
		}
		tracker.mu.Unlock()
	}()
}

func (tracker *backgroundTaskTracker) Record(operation string, err error) {
	tracker.errors.Record(operation, err)
}

func (tracker *backgroundTaskTracker) Wait(ctx context.Context) error {
	tracker.mu.Lock()
	if tracker.active == 0 {
		tracker.mu.Unlock()
		return tracker.errors.Take()
	}
	idle := tracker.idle
	tracker.mu.Unlock()
	select {
	case <-idle:
		return tracker.errors.Take()
	case <-ctx.Done():
		return errors.Join(tracker.errors.Take(), ctx.Err())
	}
}

type errorCleanupAction struct {
	operation string
	run       func() error
}

type errorCleanupStack struct {
	actions  []errorCleanupAction
	disarmed bool
}

func (stack *errorCleanupStack) Add(operation string, action func() error) {
	if action == nil {
		return
	}
	stack.actions = append(stack.actions, errorCleanupAction{operation: operation, run: action})
}

func (stack *errorCleanupStack) Run() error {
	if stack.disarmed {
		return nil
	}
	stack.disarmed = true
	var errs []error
	for i := len(stack.actions) - 1; i >= 0; i-- {
		action := stack.actions[i]
		if err := action.run(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", action.operation, err))
		}
	}
	stack.actions = nil
	return errors.Join(errs...)
}

func (stack *errorCleanupStack) Disarm() {
	stack.disarmed = true
	stack.actions = nil
}

func deleteTCFilterCleanup(filter netlink.Filter) error {
	if filter == nil {
		return nil
	}
	if err := netlink.FilterDel(filter); err != nil && !isNotFound(err) {
		return err
	}
	return nil
}

func wrapEBPFOperation(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func closeKernelUDPRXDirectMaps(configMap, devMap, neighMap *cebpf.Map) error {
	var cleanup errorCleanupStack
	if neighMap != nil {
		cleanup.Add("close kernel_udp RX direct neighbor map", neighMap.Close)
	}
	if devMap != nil {
		cleanup.Add("close kernel_udp RX direct devmap", devMap.Close)
	}
	if configMap != nil {
		cleanup.Add("close kernel_udp RX direct config map", configMap.Close)
	}
	return cleanup.Run()
}
