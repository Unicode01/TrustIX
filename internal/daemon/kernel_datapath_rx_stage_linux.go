//go:build linux

package daemon

import (
	"errors"
	"syscall"

	"trustix.local/trustix/internal/kernelmodule"
)

const kernelDatapathRXStagePacketBufferLen = kernelmodule.TrustIXDatapathPacketMaxLen

var errKernelDatapathRXStageEmpty = syscall.ENOENT

type kernelDatapathRXStageModuleDriver struct {
	device *kernelmodule.DatapathDevice
}

func openKernelDatapathRXStageDriver() (kernelDatapathRXStageDriver, error) {
	device, err := kernelmodule.OpenDatapathDevice(kernelmodule.TrustIXDatapathDevicePath)
	if err != nil {
		return nil, err
	}
	return &kernelDatapathRXStageModuleDriver{device: device}, nil
}

func kernelDatapathRXStageHookFlags() uint32 {
	return kernelmodule.TrustIXDatapathHookFlagRXPreview | kernelmodule.TrustIXDatapathHookFlagRXStage
}

func kernelDatapathRXWorkerHookFlags() uint32 {
	return kernelmodule.TrustIXDatapathHookFlagRXPreview | kernelmodule.TrustIXDatapathHookFlagRXWorker
}

func kernelDatapathTXPlaintextHookFlags() uint32 {
	return kernelmodule.TrustIXDatapathHookFlagTXPlaintext
}

func (driver *kernelDatapathRXStageModuleDriver) Attach(ifname, targetIfname string, flags uint32) (kernelDatapathRXStageHookStatus, error) {
	status, err := driver.device.Hook(kernelmodule.DatapathHookRequest{
		Op:           kernelmodule.TrustIXDatapathHookOpAttach,
		Flags:        flags,
		IfName:       ifname,
		TargetIfName: targetIfname,
	})
	return kernelDatapathRXStageHookStatusFromKernel(status), err
}

func kernelDatapathRXStageHookStatusFromKernel(status kernelmodule.DatapathHookStatus) kernelDatapathRXStageHookStatus {
	return kernelDatapathRXStageHookStatus{
		Attached:         status.Attached,
		Flags:            status.Flags,
		IfName:           status.IfName,
		IfIndex:          status.IfIndex,
		TargetIfName:     status.TargetIfName,
		TargetIfIndex:    status.TargetIfIndex,
		RXWorker:         status.RXWorker,
		RXWorkerErrors:   status.RXWorkerErrors,
		RXWorkerInjected: status.RXWorkerInjected,
		RXWorkerDropped:  status.RXWorkerDropped,
	}
}

func (driver *kernelDatapathRXStageModuleDriver) Detach() error {
	for {
		_, err := driver.device.HookDetach()
		if errors.Is(err, syscall.ENOENT) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (driver *kernelDatapathRXStageModuleDriver) DetachFor(ifname string) error {
	_, err := driver.device.Hook(kernelmodule.DatapathHookRequest{
		Op:     kernelmodule.TrustIXDatapathHookOpDetach,
		IfName: ifname,
	})
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	return err
}

func (driver *kernelDatapathRXStageModuleDriver) Clear() (kernelDatapathRXStageResult, error) {
	result, err := driver.device.RXStageClear()
	return kernelDatapathRXStageResultFromKernel(result), err
}

func (driver *kernelDatapathRXStageModuleDriver) HookQuery() (kernelDatapathRXStageHookStatus, error) {
	status, err := driver.device.HookQuery()
	return kernelDatapathRXStageHookStatusFromKernel(status), err
}

func (driver *kernelDatapathRXStageModuleDriver) HookQueryFor(ifname string) (kernelDatapathRXStageHookStatus, error) {
	status, err := driver.device.Hook(kernelmodule.DatapathHookRequest{
		Op:     kernelmodule.TrustIXDatapathHookOpQuery,
		IfName: ifname,
	})
	return kernelDatapathRXStageHookStatusFromKernel(status), err
}

func (driver *kernelDatapathRXStageModuleDriver) PopInto(out []byte) (kernelDatapathRXStageResult, error) {
	result, err := driver.device.RXStagePopInto(out)
	return kernelDatapathRXStageResultFromKernel(result), err
}

func (driver *kernelDatapathRXStageModuleDriver) Query() (kernelDatapathRXStageResult, error) {
	result, err := driver.device.RXStageQuery()
	return kernelDatapathRXStageResultFromKernel(result), err
}

func (driver *kernelDatapathRXStageModuleDriver) Close() error {
	return driver.device.Close()
}

func kernelDatapathRXStageResultFromKernel(result kernelmodule.DatapathRXStageResult) kernelDatapathRXStageResult {
	return kernelDatapathRXStageResult{
		Inner:       result.Inner,
		WrittenLen:  result.WrittenLen,
		QueueLen:    result.QueueLen,
		Capacity:    result.Capacity,
		Staged:      result.Staged,
		Popped:      result.Popped,
		Dropped:     result.Dropped,
		Overwritten: result.Overwritten,
	}
}
