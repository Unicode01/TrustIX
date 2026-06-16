//go:build linux

package ebpf

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	cebpf "github.com/cilium/ebpf"

	"trustix.local/trustix/internal/dataplane"
)

func TestKernelCryptoProviderObjectSyntheticContextLifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("kernel crypto provider object load requires root")
	}
	probe := probeKernelCryptoCapability()
	if probe.SelfTest == nil || !probe.SelfTest.Passed {
		t.Skipf("kernel crypto verifier selftest is not available: %s", probe.Reason)
	}

	provider, err := loadKernelCryptoProviderObject()
	if err != nil {
		t.Fatalf("load kernel crypto provider object: %v", err)
	}
	defer provider.Close()

	entries, err := encodeKernelCryptoSpec(validKernelCryptoSpec(9001))
	if err != nil {
		t.Fatalf("encode kernel crypto spec: %v", err)
	}
	defer zeroKernelCryptoEntries(entries)

	if err := provider.Install(entries); err != nil {
		if !strings.Contains(err.Error(), "returned -2") {
			t.Fatalf("install synthetic kernel crypto contexts: %v", err)
		}
		assertKernelCryptoCommandSlotCleared(t, provider)
		if keys := kernelCryptoProviderContextKeys(t, provider); len(keys) != 0 {
			t.Fatalf("kernel crypto ctx map retained keys after failed AEAD create: %+v", keys)
		}
		t.Skipf("kernel BPF crypto does not expose AEAD-GCM ctx create on this kernel: %v", err)
	}
	keys := kernelCryptoProviderContextKeys(t, provider)
	for _, entry := range entries {
		if !keys[entry.Key] {
			t.Fatalf("kernel crypto ctx map is missing key %+v", entry.Key)
		}
	}
	if err := provider.RoundTrip(entries[0].Key); err != nil {
		t.Fatalf("kernel crypto AEAD-GCM roundtrip: %v", err)
	}
	assertKernelCryptoCommandSlotCleared(t, provider)

	if err := provider.DeleteFlow(9001); err != nil {
		t.Fatalf("delete synthetic kernel crypto contexts: %v", err)
	}
	keys = kernelCryptoProviderContextKeys(t, provider)
	for _, entry := range entries {
		if keys[entry.Key] {
			t.Fatalf("kernel crypto ctx map retained key %+v", entry.Key)
		}
	}
	assertKernelCryptoCommandSlotCleared(t, provider)
}

func TestKernelCryptoTCDirectProviderReadyRequiresBPFContextProvider(t *testing.T) {
	if kernelCryptoTCDirectProviderReady(false, true, false) {
		t.Fatal("direct-slot-only provider must not be TC direct ready without BPF crypto context provider")
	}
	if kernelCryptoTCDirectProviderReady(false, true, true) {
		t.Fatal("direct-slot provider must not be TC direct ready even when direct kfunc fastpath is available")
	}
	if !kernelCryptoTCDirectProviderReady(true, false, false) {
		t.Fatal("BPF context provider should be TC direct ready without direct-slot kfunc fastpath")
	}
}

func TestKernelCryptoManagerInstallsRealContextWhenProviderAvailable(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("kernel crypto provider object load requires root")
	}
	manager := NewManager()
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("load manager: %v", err)
	}
	defer manager.closeKernelCryptoProviderMapLocked()
	if !manager.kernelCryptoContextProviderReadyLocked() {
		t.Skipf("kernel crypto provider is not ready: %s", manager.kernelCryptoUnavailableReasonLocked())
	}

	const flowID = 9102
	spec := validKernelCryptoSpec(flowID)
	if err := manager.InstallExperimentalTCPCrypto(context.Background(), []dataplane.ExperimentalTCPCryptoSpec{spec}); err != nil {
		t.Fatalf("install real kernel crypto contexts: %v", err)
	}
	stats := manager.kernelCryptoProviderStatsLocked()
	if got := stats["kernel_crypto_flow_map_entries"]; got != 2 {
		t.Fatalf("kernel crypto flow map entries = %d, want 2", got)
	}
	if got := stats["kernel_crypto_flow_map_updates"]; got != 2 {
		t.Fatalf("kernel crypto flow map updates = %d, want 2", got)
	}
	keys := kernelCryptoProviderContextKeys(t, manager.kernelCryptoProvider)
	for _, direction := range []uint8{kernelCryptoDirectionSend, kernelCryptoDirectionRecv} {
		key := kernelCryptoFlowKey{FlowID: flowID, Direction: direction}
		if !keys[key] {
			t.Fatalf("kernel crypto ctx map is missing key %+v", key)
		}
	}

	if err := manager.DeleteExperimentalTCPFlows(context.Background(), []uint64{flowID}); err != nil {
		t.Fatalf("delete kernel crypto flow: %v", err)
	}
	stats = manager.kernelCryptoProviderStatsLocked()
	if got := stats["kernel_crypto_flow_map_entries"]; got != 0 {
		t.Fatalf("kernel crypto flow map entries after delete = %d, want 0", got)
	}
	keys = kernelCryptoProviderContextKeys(t, manager.kernelCryptoProvider)
	for _, direction := range []uint8{kernelCryptoDirectionSend, kernelCryptoDirectionRecv} {
		key := kernelCryptoFlowKey{FlowID: flowID, Direction: direction}
		if keys[key] {
			t.Fatalf("kernel crypto ctx map retained key %+v", key)
		}
	}
}

func TestKernelCryptoProviderFrameSealOpenAndReplay(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("kernel crypto provider object load requires root")
	}
	manager := NewManager()
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("load manager: %v", err)
	}
	defer manager.closeKernelCryptoProviderMapLocked()
	if !manager.kernelCryptoProductionReadyLocked() {
		t.Skipf("kernel crypto provider is not ready: %s", manager.kernelCryptoUnavailableReasonLocked())
	}

	const flowID = 9103
	spec := validKernelCryptoSpec(flowID)
	spec.RecvKey = append([]byte(nil), spec.SendKey...)
	spec.RecvIV = append([]byte(nil), spec.SendIV...)
	if err := manager.InstallExperimentalTCPCrypto(context.Background(), []dataplane.ExperimentalTCPCryptoSpec{spec}); err != nil {
		t.Fatalf("install frame crypto contexts: %v", err)
	}
	plaintext := []byte("trustix kernel frame crypto")
	sealed, err := manager.kernelCryptoProvider.SealFrame(kernelCryptoFlowKeyFor(kernelCryptoNamespaceExperimentalTCP, flowID, kernelCryptoDirectionSend), kernelCryptoSuiteIDTrustIXAES256GCMX25519, spec.Epoch, 1, plaintext)
	if err != nil {
		t.Fatalf("seal frame: %v", err)
	}
	if string(sealed) == string(plaintext) {
		t.Fatalf("sealed frame did not change plaintext")
	}
	opened, err := manager.kernelCryptoProvider.OpenFrame(kernelCryptoFlowKeyFor(kernelCryptoNamespaceExperimentalTCP, flowID, kernelCryptoDirectionRecv), kernelCryptoSuiteIDTrustIXAES256GCMX25519, spec.Epoch, 1, sealed)
	if err != nil {
		t.Fatalf("open frame: %v", err)
	}
	if string(opened) != string(plaintext) {
		t.Fatalf("opened plaintext = %q, want %q", opened, plaintext)
	}
	if _, err := manager.kernelCryptoProvider.OpenFrame(kernelCryptoFlowKeyFor(kernelCryptoNamespaceExperimentalTCP, flowID, kernelCryptoDirectionRecv), kernelCryptoSuiteIDTrustIXAES256GCMX25519, spec.Epoch, 1, sealed); err == nil || !isKernelCryptoReplayError(err) {
		t.Fatalf("replay open error = %v, want replay", err)
	}
	if _, err := manager.kernelCryptoProvider.SealFrame(kernelCryptoFlowKeyFor(kernelCryptoNamespaceExperimentalTCP, flowID, kernelCryptoDirectionSend), kernelCryptoSuiteIDTrustIXAES256GCMX25519, spec.Epoch, 1, plaintext); err == nil || !isKernelCryptoReplayError(err) {
		t.Fatalf("duplicate seal error = %v, want replay/sequence reuse", err)
	}

	seal := func(sequence uint64, plaintext []byte) []byte {
		t.Helper()
		sealed, err := manager.kernelCryptoProvider.SealFrame(kernelCryptoFlowKeyFor(kernelCryptoNamespaceExperimentalTCP, flowID, kernelCryptoDirectionSend), kernelCryptoSuiteIDTrustIXAES256GCMX25519, spec.Epoch, sequence, plaintext)
		if err != nil {
			t.Fatalf("seal frame sequence %d: %v", sequence, err)
		}
		return sealed
	}
	open := func(sequence uint64, sealed []byte, want []byte) {
		t.Helper()
		opened, err := manager.kernelCryptoProvider.OpenFrame(kernelCryptoFlowKeyFor(kernelCryptoNamespaceExperimentalTCP, flowID, kernelCryptoDirectionRecv), kernelCryptoSuiteIDTrustIXAES256GCMX25519, spec.Epoch, sequence, sealed)
		if err != nil {
			t.Fatalf("open frame sequence %d: %v", sequence, err)
		}
		if string(opened) != string(want) {
			t.Fatalf("opened sequence %d plaintext = %q, want %q", sequence, opened, want)
		}
	}

	plain10 := []byte("sequence 10")
	plain11 := []byte("sequence 11")
	plain12 := []byte("sequence 12")
	sealed10 := seal(10, plain10)
	sealed11 := seal(11, plain11)
	sealed12 := seal(12, plain12)
	open(10, sealed10, plain10)
	open(12, sealed12, plain12)
	open(11, sealed11, plain11)
	if _, err := manager.kernelCryptoProvider.OpenFrame(kernelCryptoFlowKeyFor(kernelCryptoNamespaceExperimentalTCP, flowID, kernelCryptoDirectionRecv), kernelCryptoSuiteIDTrustIXAES256GCMX25519, spec.Epoch, 11, sealed11); err == nil || !isKernelCryptoReplayError(err) {
		t.Fatalf("out-of-order replay open error = %v, want replay", err)
	}

	plain13 := []byte("sequence 13")
	sealed13 := seal(13, plain13)
	tampered13 := append([]byte(nil), sealed13...)
	tampered13[len(tampered13)-1] ^= 0x01
	if _, err := manager.kernelCryptoProvider.OpenFrame(kernelCryptoFlowKeyFor(kernelCryptoNamespaceExperimentalTCP, flowID, kernelCryptoDirectionRecv), kernelCryptoSuiteIDTrustIXAES256GCMX25519, spec.Epoch, 13, tampered13); err == nil || isKernelCryptoReplayError(err) {
		t.Fatalf("tampered open error = %v, want non-replay decrypt failure", err)
	}
	open(13, sealed13, plain13)

	plain90 := []byte("sequence 90")
	plain25 := []byte("sequence 25")
	sealed25 := seal(25, plain25)
	sealed90 := seal(90, plain90)
	open(90, sealed90, plain90)
	if _, err := manager.kernelCryptoProvider.OpenFrame(kernelCryptoFlowKeyFor(kernelCryptoNamespaceExperimentalTCP, flowID, kernelCryptoDirectionRecv), kernelCryptoSuiteIDTrustIXAES256GCMX25519, spec.Epoch, 25, sealed25); err == nil || !isKernelCryptoReplayError(err) {
		t.Fatalf("too-old replay open error = %v, want replay", err)
	}
}

func TestKernelCryptoProviderFrameSealOpenAES128(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("kernel crypto provider object load requires root")
	}
	manager := NewManager()
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("load manager: %v", err)
	}
	defer manager.closeKernelCryptoProviderMapLocked()
	if !manager.kernelCryptoProductionReadyLocked() {
		t.Skipf("kernel crypto provider is not ready: %s", manager.kernelCryptoUnavailableReasonLocked())
	}

	const flowID = 9104
	spec := validKernelCryptoSpec(flowID)
	spec.Suite = kernelCryptoSuiteAES128GCMX25519
	spec.SendKey = bytesOf(0x51, kernelCryptoAES128KeyLen)
	spec.RecvKey = append([]byte(nil), spec.SendKey...)
	spec.RecvIV = append([]byte(nil), spec.SendIV...)
	if err := manager.InstallExperimentalTCPCrypto(context.Background(), []dataplane.ExperimentalTCPCryptoSpec{spec}); err != nil {
		t.Fatalf("install AES-128 kernel crypto contexts: %v", err)
	}

	plaintext := []byte("aes128 provider frame")
	sealed, err := manager.kernelCryptoProvider.SealFrame(kernelCryptoFlowKeyFor(kernelCryptoNamespaceExperimentalTCP, flowID, kernelCryptoDirectionSend), kernelCryptoSuiteIDTrustIXAES128GCMX25519, spec.Epoch, 1, plaintext)
	if err != nil {
		t.Fatalf("seal AES-128 frame: %v", err)
	}
	if len(sealed) < kernelCryptoSecureHeaderLen || sealed[5] != byte(kernelCryptoSuiteIDTrustIXAES128GCMX25519) {
		t.Fatalf("sealed AES-128 header = %x", sealed[:min(len(sealed), kernelCryptoSecureHeaderLen)])
	}
	opened, err := manager.kernelCryptoProvider.OpenFrame(kernelCryptoFlowKeyFor(kernelCryptoNamespaceExperimentalTCP, flowID, kernelCryptoDirectionRecv), kernelCryptoSuiteIDTrustIXAES128GCMX25519, spec.Epoch, 1, sealed)
	if err != nil {
		t.Fatalf("open AES-128 frame: %v", err)
	}
	if string(opened) != string(plaintext) {
		t.Fatalf("opened AES-128 plaintext = %q", opened)
	}
}

func TestKernelCryptoProviderFrameSealOpenVariableSizes(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("kernel crypto provider object load requires root")
	}
	manager := NewManager()
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("load manager: %v", err)
	}
	defer manager.closeKernelCryptoProviderMapLocked()
	if !manager.kernelCryptoProductionReadyLocked() {
		t.Skipf("kernel crypto provider is not ready: %s", manager.kernelCryptoUnavailableReasonLocked())
	}

	const flowID = 9105
	spec := validKernelCryptoSpec(flowID)
	spec.RecvKey = append([]byte(nil), spec.SendKey...)
	spec.RecvIV = append([]byte(nil), spec.SendIV...)
	if err := manager.InstallExperimentalTCPCrypto(context.Background(), []dataplane.ExperimentalTCPCryptoSpec{spec}); err != nil {
		t.Fatalf("install variable-size frame crypto contexts: %v", err)
	}
	lengths := []int{1, 15, 16, 17, 31, 32, 33, 127, 128, 129, 1200, 1340, 1360, kernelCryptoFrameMaxPlain}
	for i, length := range lengths {
		plaintext := bytesOf(byte(0x30+i), length)
		sequence := uint64(i + 1)
		sealed, err := manager.kernelCryptoProvider.SealFrame(kernelCryptoFlowKeyFor(kernelCryptoNamespaceExperimentalTCP, flowID, kernelCryptoDirectionSend), kernelCryptoSuiteIDTrustIXAES256GCMX25519, spec.Epoch, sequence, plaintext)
		if err != nil {
			t.Fatalf("seal %d-byte frame: %v", length, err)
		}
		opened, err := manager.kernelCryptoProvider.OpenFrame(kernelCryptoFlowKeyFor(kernelCryptoNamespaceExperimentalTCP, flowID, kernelCryptoDirectionRecv), kernelCryptoSuiteIDTrustIXAES256GCMX25519, spec.Epoch, sequence, sealed)
		if err != nil {
			t.Fatalf("open %d-byte frame: %v", length, err)
		}
		if !bytes.Equal(opened, plaintext) {
			t.Fatalf("opened %d-byte frame mismatch", length)
		}
	}
}

func kernelCryptoProviderContextKeys(t *testing.T, provider *kernelCryptoProviderObject) map[kernelCryptoFlowKey]bool {
	t.Helper()
	keys := make(map[kernelCryptoFlowKey]bool)
	var previous any
	for {
		var next kernelCryptoFlowKey
		err := provider.flowIndexMap.NextKey(previous, &next)
		if errors.Is(err, cebpf.ErrKeyNotExist) {
			return keys
		}
		if err != nil {
			t.Fatalf("iterate kernel crypto ctx map keys: %v", err)
		}
		keys[next] = true
		previous = next
	}
}

func assertKernelCryptoCommandSlotCleared(t *testing.T, provider *kernelCryptoProviderObject) {
	t.Helper()
	var cmd kernelCryptoCommand
	if err := provider.commandMap.Lookup(uint32(0), &cmd); err != nil {
		t.Fatalf("lookup kernel crypto command slot: %v", err)
	}
	if cmd != (kernelCryptoCommand{}) {
		t.Fatalf("kernel crypto command slot retained data: %+v", cmd)
	}
}
