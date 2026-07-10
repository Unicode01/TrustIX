package ebpf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKernelCryptoReplayCommitsUseMapSpinLocks(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		functions []string
		lockCount int
	}{
		{
			name: "kernel_udp_tc_rx",
			path: filepath.Join("..", "..", "..", "kernel", "bpf", "dataplane", "kernel_udp_rx_kernel_crypto_tc.c"),
			functions: []string{
				"trustix_replay_commit",
				"trustix_direct_replay_commit",
			},
			lockCount: 2,
		},
		{
			name: "experimental_tcp_xdp_rx",
			path: filepath.Join("..", "..", "..", "kernel", "bpf", "dataplane", "experimental_tcp_kernel_crypto_xdp.c"),
			functions: []string{
				"trustix_replay_commit",
				"trustix_direct_replay_commit",
			},
			lockCount: 2,
		},
		{
			name: "kernel_crypto_provider",
			path: filepath.Join("..", "..", "..", "kernel", "bpf", "dataplane", "kernel_crypto_provider.c"),
			functions: []string{
				"trustix_kernel_crypto_replay_commit",
			},
			lockCount: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := os.ReadFile(test.path)
			if err != nil {
				t.Fatalf("read %s: %v", test.path, err)
			}
			source := strings.ReplaceAll(string(raw), "\r\n", "\n")
			if got := strings.Count(source, "struct bpf_spin_lock replay_lock;"); got != test.lockCount {
				t.Fatalf("replay lock fields = %d, want %d", got, test.lockCount)
			}
			if strings.Contains(source, "replay_check(") {
				t.Fatal("receive path still performs an unlocked replay precheck")
			}
			for _, function := range test.functions {
				body := sourceFunctionBody(t, source, function)
				lock := strings.Index(body, "bpf_spin_lock(")
				unlock := strings.Index(body, "bpf_spin_unlock(")
				if lock < 0 || unlock <= lock {
					t.Fatalf("%s does not lock and unlock replay state", function)
				}
				critical := body[lock:unlock]
				if strings.Contains(critical, "_count(") {
					t.Fatalf("%s calls a stats map helper while holding the replay lock", function)
				}
			}
		})
	}
}

func TestKernelCryptoDirectSlotMapPreservesSpinLockBTF(t *testing.T) {
	raw, err := os.ReadFile("kernel_crypto_provider_linux.go")
	if err != nil {
		t.Fatalf("read kernel crypto provider loader: %v", err)
	}
	source := string(raw)
	for _, want := range []string{
		`spec.Maps["trustix_kernel_crypto_direct_slots"]`,
		"cebpf.NewMap(directSlotSpec)",
		"cebpf.UpdateLock",
		"cebpf.LookupLock",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("kernel crypto direct slot loader is missing %q", want)
		}
	}
}
