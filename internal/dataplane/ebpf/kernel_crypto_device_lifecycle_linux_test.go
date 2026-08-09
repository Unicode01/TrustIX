//go:build linux

package ebpf

import (
	"bytes"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestKernelCryptoDeviceCloseWipesMappedAliasesBeforeDeviceClose(t *testing.T) {
	source, err := os.ReadFile("kernel_crypto_device_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	wipe := strings.Index(text, "clear(device.sealPool)")
	closeDevice := strings.Index(text, "device.seal.Close()")
	if wipe < 0 || closeDevice < 0 || wipe >= closeDevice {
		t.Fatal("kernel crypto device must wipe mmap-backed pool aliases before the AEAD device unmaps them")
	}
}

func TestKernelCryptoDeviceConcurrentCloseWipesState(t *testing.T) {
	sealPool := []byte{1, 2, 3, 4}
	openPool := []byte{5, 6, 7, 8}
	device := &kernelCryptoDevice{
		sealPool:     sealPool,
		openPool:     openPool,
		sealBorrowed: [][]byte{sealPool[:2]},
		openIn:       [][]byte{openPool[:2]},
		openOut:      []kernelCryptoDeviceOpenResult{{Plain: openPool[2:]}},
		recvScratch:  []uint64{1, 2},
		recvSeen:     []uint64{3, 4},
	}
	device.flow.SendKey[0] = 0xff
	device.flow.RecvKey[0] = 0xee

	const closers = 32
	start := make(chan struct{})
	errs := make(chan error, closers)
	var wait sync.WaitGroup
	wait.Add(closers)
	for range closers {
		go func() {
			defer wait.Done()
			<-start
			errs <- device.Close()
		}()
	}
	close(start)
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent close: %v", err)
		}
	}
	if !bytes.Equal(sealPool, make([]byte, len(sealPool))) ||
		!bytes.Equal(openPool, make([]byte, len(openPool))) {
		t.Fatalf("close did not wipe pool aliases: seal=%v open=%v", sealPool, openPool)
	}
	if device.flow != (kernelCryptoDeviceFlow{}) {
		t.Fatal("close did not wipe flow key material")
	}
	if device.sealPool != nil || device.openPool != nil ||
		device.sealBorrowed != nil || device.openIn != nil ||
		device.openOut != nil || device.recvScratch != nil || device.recvSeen != nil {
		t.Fatal("close retained crypto scratch state")
	}
}

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
