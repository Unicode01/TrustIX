package daemon

import (
	"context"
	"sync/atomic"
	"testing"

	"trustix.local/trustix/internal/dataplane"
)

func TestShutdownRuntimeDetachesDataplane(t *testing.T) {
	manager := &detachCountingManager{}
	daemon := &Daemon{dataplane: manager}

	if err := daemon.shutdownRuntime(nil, true); err != nil {
		t.Fatalf("shutdown runtime: %v", err)
	}
	if got := manager.detaches.Load(); got != 1 {
		t.Fatalf("detach calls = %d, want 1", got)
	}
}

func TestShutdownRuntimeCanSkipDetach(t *testing.T) {
	manager := &detachCountingManager{}
	daemon := &Daemon{dataplane: manager}

	if err := daemon.shutdownRuntime(nil, false); err != nil {
		t.Fatalf("shutdown runtime: %v", err)
	}
	if got := manager.detaches.Load(); got != 0 {
		t.Fatalf("detach calls = %d, want 0", got)
	}
}

type detachCountingManager struct {
	detaches atomic.Uint64
}

func (manager *detachCountingManager) Load(ctx context.Context) error {
	return ctx.Err()
}

func (manager *detachCountingManager) Attach(ctx context.Context, spec dataplane.AttachSpec) error {
	return ctx.Err()
}

func (manager *detachCountingManager) ApplySnapshot(ctx context.Context, snapshot dataplane.Snapshot) error {
	return ctx.Err()
}

func (manager *detachCountingManager) Stats(ctx context.Context) (dataplane.Stats, error) {
	if err := ctx.Err(); err != nil {
		return dataplane.Stats{}, err
	}
	return dataplane.Stats{}, nil
}

func (manager *detachCountingManager) Detach(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	manager.detaches.Add(1)
	return nil
}
