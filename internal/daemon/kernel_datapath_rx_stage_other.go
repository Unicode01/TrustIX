//go:build !linux

package daemon

import (
	"errors"
	"fmt"
)

const kernelDatapathRXStagePacketBufferLen = 65535

var errKernelDatapathRXStageEmpty = errors.New("kernel RX_STAGE queue is empty")

func openKernelDatapathRXStageDriver() (kernelDatapathRXStageDriver, error) {
	return nil, fmt.Errorf("kernel RX_STAGE is only available on Linux")
}

func kernelDatapathRXStageHookFlags() uint32 {
	return 1<<0 | 1<<1
}

func kernelDatapathRXWorkerHookFlags() uint32 {
	return 1<<0 | 1<<2
}

func kernelDatapathRXSecureTIXTCPHookFlags() uint32 {
	return kernelDatapathRXWorkerHookFlags() | 1<<5
}

func kernelDatapathTXPlaintextHookFlags() uint32 {
	return 1 << 3
}

func kernelDatapathTXSecureTIXTCPHookFlags() uint32 {
	return 1 << 4
}
