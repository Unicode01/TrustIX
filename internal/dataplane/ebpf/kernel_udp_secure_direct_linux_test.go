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
	stats := manager.kernelCryptoProviderStatsLocked()
	if stats["kernel_crypto_direct_slot_provider_ready"] != 1 {
		t.Fatal("kernel crypto direct-slot provider is not ready")
	}
	if got := stats["kernel_crypto_ctx_provider_loaded"]; got != 0 {
		t.Fatalf("BPF context provider loaded = %d while direct-slot fast path is ready, want 0", got)
	}
	if attempts, failures := stats["kernel_crypto_aead_gcm_ctx_create_attempts"], stats["kernel_crypto_aead_gcm_ctx_create_errors"]; attempts != 0 || failures != 0 {
		t.Fatalf("unused BPF AEAD context probe = attempts:%d errors:%d, want zero", attempts, failures)
	}

	statsMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tc_secure_load_stats", Type: cebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: tcStatsMapMaxEntries})
	defer statsMap.Close()
	routeMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tc_secure_load_tx_route", Type: cebpf.LPMTrie, KeySize: 8, ValueSize: kernelUDPTXRouteValueSize, MaxEntries: 4096, Flags: 1})
	defer routeMap.Close()
	flowMap := newTestBPFMap(t, &cebpf.MapSpec{Name: "ix_tc_secure_load_tx_flow", Type: cebpf.Hash, KeySize: 8, ValueSize: kernelUDPTXFlowValueSize, MaxEntries: 4096})
	defer flowMap.Close()

	tx, err := loadKernelUDPTXSecureDirectObject(manager.kernelCryptoProvider, statsMap, routeMap, flowMap, kernelUDPTXSecureDirectProgramOptions{
		StrongFlowHash: true,
		FlowAffinity:   true,
	})
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
