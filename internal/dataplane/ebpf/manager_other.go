//go:build !linux

package ebpf

import (
	"context"

	"trustix.local/trustix/internal/dataplane"
)

type Manager struct{}

func NewManager() *Manager {
	return &Manager{}
}

func (manager *Manager) Load(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return dataplane.ErrUnsupported
}

func (manager *Manager) Attach(ctx context.Context, spec dataplane.AttachSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return dataplane.ErrUnsupported
}

func (manager *Manager) ApplySnapshot(ctx context.Context, snapshot dataplane.Snapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return dataplane.ErrUnsupported
}

func (manager *Manager) Stats(ctx context.Context) (dataplane.Stats, error) {
	if err := ctx.Err(); err != nil {
		return dataplane.Stats{}, err
	}
	return dataplane.Stats{}, dataplane.ErrUnsupported
}

func (manager *Manager) Detach(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return dataplane.ErrUnsupported
}
