//go:build linux

package ebpf

import (
	"context"
	"os"
	"testing"

	cebpf "github.com/cilium/ebpf"
)

func TestKernelUDPTCSecureDirectObjectsLoadWithKernelDirectKfunc(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("kernel_udp secure TC direct object load requires root")
	}
	manager := NewManager()
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("load manager: %v", err)
	}
	defer manager.closeKernelCryptoProviderMapLocked()
	if !manager.kernelCryptoTCDirectReadyLocked() {
		t.Skipf("kernel crypto TC direct provider is not ready: %s", manager.kernelCryptoUnavailableReasonLocked())
	}

	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tc_secure_load_stats", Type: cebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	defer statsMap.Close()
	routeMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tc_secure_load_tx_route", Type: cebpf.LPMTrie, KeySize: 8, ValueSize: kernelUDPTXRouteValueSize, MaxEntries: 4096, Flags: 1})
	defer routeMap.Close()
	flowMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tc_secure_load_tx_flow", Type: cebpf.Hash, KeySize: 8, ValueSize: kernelUDPTXFlowValueSize, MaxEntries: 4096})
	defer flowMap.Close()

	tx, err := loadKernelUDPTXSecureDirectObject(manager.kernelCryptoProvider, statsMap, routeMap, flowMap, kernelUDPTXSecureDirectProgramOptions{})
	if err != nil {
		t.Fatalf("load kernel_udp secure TC TX direct object: %-v", err)
	}
	defer tx.Close()

	portMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tc_secure_load_ports", Type: cebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: 4096})
	defer portMap.Close()
	neighMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tc_secure_load_neigh", Type: cebpf.Hash, KeySize: 4, ValueSize: 20, MaxEntries: 4096})
	defer neighMap.Close()
	rx, err := loadKernelUDPRXSecureDirectObject(manager.kernelCryptoProvider, statsMap, portMap, neighMap, 1, 0, [6]byte{2, 0, 0, 0, 0, 1}, kernelUDPRXDirectProgramOptions{})
	if err != nil {
		t.Fatalf("load kernel_udp secure TC RX direct object: %-v", err)
	}
	defer rx.Close()
}
