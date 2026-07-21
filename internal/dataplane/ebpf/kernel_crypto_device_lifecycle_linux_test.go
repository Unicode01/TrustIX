//go:build linux

package ebpf

import (
	"testing"
	"time"
)

func TestDeleteKernelCryptoDeviceLockedDoesNotBlockManagerLockOnBorrowedDevice(t *testing.T) {
	manager := NewManager()
	device := &kernelCryptoDevice{}
	manager.kernelCryptoDevices = map[uint64]*kernelCryptoDevice{7: device}

	device.sealMu.Lock()
	unlockedSeal := false
	defer func() {
		if !unlockedSeal {
			device.sealMu.Unlock()
		}
	}()

	deleted := make(chan struct{})
	go func() {
		manager.mu.Lock()
		manager.deleteKernelCryptoDeviceLocked(kernelCryptoNamespaceKernelUDP, 7)
		manager.mu.Unlock()
		close(deleted)
	}()

	select {
	case <-deleted:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("deleteKernelCryptoDeviceLocked blocked while closing a borrowed kernel crypto device")
	}
	locked := make(chan bool, 1)
	go func() {
		manager.mu.Lock()
		_, stillPresent := manager.kernelCryptoDevices[7]
		manager.mu.Unlock()
		locked <- stillPresent
	}()
	select {
	case stillPresent := <-locked:
		if stillPresent {
			t.Fatal("kernel crypto device was not detached from manager map")
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("manager lock remained blocked after detaching kernel crypto device")
	}

	device.sealMu.Unlock()
	unlockedSeal = true
}
