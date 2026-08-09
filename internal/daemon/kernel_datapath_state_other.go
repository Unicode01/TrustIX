//go:build !linux

package daemon

import (
	"context"

	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/routing"
	"trustix.local/trustix/internal/transport"
)

func (daemon *Daemon) syncKernelDatapathState(ctx context.Context, snapshot dataplane.Snapshot) error {
	daemon.kernelDatapathStateMu.Lock()
	defer daemon.kernelDatapathStateMu.Unlock()
	return ctx.Err()
}

func (daemon *Daemon) syncCurrentKernelDatapathState(ctx context.Context) error {
	daemon.kernelDatapathStateMu.Lock()
	defer daemon.kernelDatapathStateMu.Unlock()
	return ctx.Err()
}

func (daemon *Daemon) runKernelDatapathStateSync(ctx context.Context) {
}

func (daemon *Daemon) syncKernelDatapathSessionUpsert(key dataSessionKey, runtime *dataSessionRuntime, session transport.Session) {
}

func (daemon *Daemon) syncKernelDatapathSessionDelete(key dataSessionKey, session transport.Session) {
}

func (daemon *Daemon) syncKernelDatapathSessionDeleteRetainingFlow(key dataSessionKey, session transport.Session) {
}

func (daemon *Daemon) syncKernelDatapathFlowUpsert(binding routing.FlowBinding) {
}

func (daemon *Daemon) syncKernelDatapathFlowDelete(key routing.FlowKey) {
}

func (daemon *Daemon) kernelDatapathAvailable() bool {
	return daemon != nil && daemon.kernelDatapath != nil && daemon.kernelDatapath.Snapshot().Loaded
}
