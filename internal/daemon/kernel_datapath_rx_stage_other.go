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
	return 0
}

func kernelDatapathRXWorkerHookFlags() uint32 {
	return 0
}

func kernelDatapathTXPlaintextHookFlags() uint32 {
	return 0
}
