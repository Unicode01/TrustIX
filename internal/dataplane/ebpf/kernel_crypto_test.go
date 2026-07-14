package ebpf

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"trustix.local/trustix/internal/dataplane"
)

func TestParseProcCryptoDetectsAESGCMAndAESNI(t *testing.T) {
	payload := []byte(`
name         : gcm(aes)
driver       : generic-gcm-aesni
module       : aesni_intel
priority     : 800

name         : cbc(aes)
driver       : cbc-aes-aesni
module       : aesni_intel
priority     : 400
`)
	cpuInfo := []byte("flags\t\t: fpu sse2 aes avx\n")

	aesGCM, aesNI, softwareFallback, algorithms := summarizeKernelCryptoAlgorithms(parseProcCrypto(payload), cpuInfo)
	if !aesGCM {
		t.Fatalf("expected AES-GCM to be detected")
	}
	if !aesNI {
		t.Fatalf("expected AES-NI to be detected")
	}
	if softwareFallback {
		t.Fatalf("did not expect software fallback from AES-NI-only payload")
	}
	if len(algorithms) == 0 {
		t.Fatalf("expected interesting crypto algorithms")
	}
	if got := strings.Join(algorithms, "\n"); !strings.Contains(got, "gcm(aes)") {
		t.Fatalf("expected gcm(aes) in algorithm summary, got %q", got)
	}
}

func TestParseProcCryptoDetectsAESGCMSoftwareFallback(t *testing.T) {
	payload := []byte(`
name         : gcm(aes)
driver       : generic-gcm-aes
module       : kernel
priority     : 100

name         : __gcm(aes)
driver       : __generic-gcm-aes
module       : kernel
priority     : 100
`)
	cpuInfo := []byte("flags\t\t: fpu sse2 avx\n")

	aesGCM, aesNI, softwareFallback, algorithms := summarizeKernelCryptoAlgorithms(parseProcCrypto(payload), cpuInfo)
	if !aesGCM {
		t.Fatalf("expected AES-GCM to be detected")
	}
	if aesNI {
		t.Fatalf("did not expect AES-NI to be detected")
	}
	if !softwareFallback {
		t.Fatalf("expected AES-GCM software fallback to be detected")
	}
	if got := strings.Join(algorithms, "\n"); !strings.Contains(got, "__gcm(aes)") {
		t.Fatalf("expected internal generic GCM in algorithm summary, got %q", got)
	}
}

func TestCPUInfoHasAESRequiresExactFlag(t *testing.T) {
	if !cpuInfoHasAES([]byte("flags : fpu aes avx\n")) {
		t.Fatalf("expected exact aes flag to be detected")
	}
	if cpuInfoHasAES([]byte("flags : fpu vaes avx\n")) {
		t.Fatalf("did not expect vaes substring to count as aes")
	}
}

func TestKernelCryptoProbeReason(t *testing.T) {
	probe := baseKernelCryptoProbe()
	probe.KernelBTF = true
	probe.MissingKfuncs = []string{"bpf_crypto_encrypt"}
	probe.CryptoKfuncs = false
	reason := kernelCryptoProbeReason(probe, "", "")
	if !strings.Contains(reason, "bpf_crypto_encrypt") {
		t.Fatalf("expected missing kfunc in reason, got %q", reason)
	}

	probe = dataplane.KernelCryptoProbe{
		KernelBTF:       true,
		CryptoKfuncs:    true,
		AESGCM:          true,
		CapabilityReady: true,
		ProviderReady:   false,
	}
	reason = kernelCryptoProbeReason(probe, "", "")
	if reason != kernelCryptoProviderPendingReason {
		t.Fatalf("expected provider pending reason, got %q", reason)
	}

	probe.SelfTest = &dataplane.KernelCryptoSelfTest{Attempted: true, Passed: false, Reason: "verifier denied kfunc"}
	reason = kernelCryptoProbeReason(probe, "", "")
	if !strings.Contains(reason, "verifier denied kfunc") {
		t.Fatalf("expected selftest failure reason, got %q", reason)
	}
}

func TestMissingKernelCryptoKfuncsFromBTF(t *testing.T) {
	payload := testBTFWithFunctions("bpf_crypto_ctx_create", "bpf_crypto_encrypt")
	missing, err := missingKernelCryptoKfuncsFromBTF(payload, []string{
		"bpf_crypto_ctx_create",
		"bpf_crypto_ctx_release",
		"bpf_crypto_encrypt",
	})
	if err != nil {
		t.Fatalf("parse BTF: %v", err)
	}
	if got, want := strings.Join(missing, ","), "bpf_crypto_ctx_release"; got != want {
		t.Fatalf("missing kfuncs = %q, want %q", got, want)
	}
}

func TestEncodeKernelCryptoSpec(t *testing.T) {
	sendKey := bytesOf(0x11, kernelCryptoAES256KeyLen)
	recvKey := bytesOf(0x22, kernelCryptoAES256KeyLen)
	sendIV := bytesOf(0x33, kernelCryptoAESGCMIVLen)
	recvIV := bytesOf(0x44, kernelCryptoAESGCMIVLen)
	installed := time.Unix(10, 20).UTC()

	entries, err := encodeKernelCryptoSpec(dataplane.TIXTCPCryptoSpec{
		FlowID:       42,
		Suite:        kernelCryptoSuiteAES256GCMX25519,
		WireFormat:   kernelCryptoWireFormatTrustIXSecureDataV1,
		Epoch:        7,
		SendKey:      sendKey,
		SendIV:       sendIV,
		RecvKey:      recvKey,
		RecvIV:       recvIV,
		ReplayWindow: 64,
		InstalledAt:  installed,
	})
	if err != nil {
		t.Fatalf("encode kernel crypto spec: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	if entries[0].Key.FlowID != 42 || entries[0].Key.Direction != kernelCryptoDirectionSend {
		t.Fatalf("send key = %#v", entries[0].Key)
	}
	if entries[1].Key.FlowID != 42 || entries[1].Key.Direction != kernelCryptoDirectionRecv {
		t.Fatalf("recv key = %#v", entries[1].Key)
	}
	if entries[0].Value.Epoch != 7 || entries[0].Value.ReplayWindow != 64 || entries[0].Value.InstalledUnix != installed.UnixNano() {
		t.Fatalf("send value metadata = %#v", entries[0].Value)
	}
	if entries[0].Value.Suite != kernelCryptoSuiteIDTrustIXAES256GCMX25519 || entries[0].Value.KeyLen != kernelCryptoAES256KeyLen {
		t.Fatalf("send suite/key length = %d/%d", entries[0].Value.Suite, entries[0].Value.KeyLen)
	}
	if entries[0].Value.Key != kernelCryptoFixedKey(sendKey) || entries[0].Value.IV != kernelCryptoFixedIV(sendIV) {
		t.Fatalf("send key material was not encoded")
	}
	if entries[1].Value.Key != kernelCryptoFixedKey(recvKey) || entries[1].Value.IV != kernelCryptoFixedIV(recvIV) {
		t.Fatalf("recv key material was not encoded")
	}
}

func TestEncodeKernelCryptoSpecSupportsAES128(t *testing.T) {
	sendKey := bytesOf(0x11, kernelCryptoAES128KeyLen)
	recvKey := bytesOf(0x22, kernelCryptoAES128KeyLen)
	entries, err := encodeKernelCryptoSpec(dataplane.TIXTCPCryptoSpec{
		FlowID:     43,
		Suite:      kernelCryptoSuiteAES128GCMX25519,
		WireFormat: kernelCryptoWireFormatTrustIXSecureDataV1,
		Epoch:      8,
		SendKey:    sendKey,
		SendIV:     bytesOf(0x33, kernelCryptoAESGCMIVLen),
		RecvKey:    recvKey,
		RecvIV:     bytesOf(0x44, kernelCryptoAESGCMIVLen),
	})
	if err != nil {
		t.Fatalf("encode AES-128 kernel crypto spec: %v", err)
	}
	if entries[0].Value.Suite != kernelCryptoSuiteIDTrustIXAES128GCMX25519 || entries[0].Value.KeyLen != kernelCryptoAES128KeyLen {
		t.Fatalf("send suite/key length = %d/%d", entries[0].Value.Suite, entries[0].Value.KeyLen)
	}
	if entries[0].Value.Key != kernelCryptoFixedKey(sendKey) || entries[1].Value.Key != kernelCryptoFixedKey(recvKey) {
		t.Fatalf("AES-128 key material was not encoded")
	}
}

func TestEncodeKernelUDPCryptoSpecUsesSeparateNamespace(t *testing.T) {
	entries, err := encodeKernelUDPCryptoSpec(dataplane.KernelUDPCryptoSpec{
		FlowID:     42,
		Suite:      kernelCryptoSuiteAES256GCMX25519,
		WireFormat: kernelCryptoWireFormatTrustIXSecureDataV1,
		SendKey:    bytesOf(0x11, kernelCryptoAES256KeyLen),
		SendIV:     bytesOf(0x33, kernelCryptoAESGCMIVLen),
		RecvKey:    bytesOf(0x22, kernelCryptoAES256KeyLen),
		RecvIV:     bytesOf(0x44, kernelCryptoAESGCMIVLen),
	})
	if err != nil {
		t.Fatalf("encode kernel_udp crypto spec: %v", err)
	}
	if entries[0].Key.Reserved[0] != kernelCryptoNamespaceKernelUDP || entries[1].Key.Reserved[0] != kernelCryptoNamespaceKernelUDP {
		t.Fatalf("kernel_udp namespace was not encoded: %+v %+v", entries[0].Key, entries[1].Key)
	}
}

func TestEncodeKernelCryptoSpecRejectsChaChaKernelOffload(t *testing.T) {
	_, err := encodeKernelCryptoSpec(dataplane.TIXTCPCryptoSpec{
		FlowID:     42,
		Suite:      kernelCryptoSuiteChaCha20Poly1305X25519,
		WireFormat: kernelCryptoWireFormatTrustIXSecureDataV1,
		SendKey:    bytesOf(0x11, 32),
		SendIV:     bytesOf(0x33, kernelCryptoAESGCMIVLen),
		RecvKey:    bytesOf(0x22, 32),
		RecvIV:     bytesOf(0x44, kernelCryptoAESGCMIVLen),
	})
	if err == nil || !strings.Contains(err.Error(), "ChaCha20-Poly1305 remains userspace") {
		t.Fatalf("error = %v, want ChaCha userspace reason", err)
	}
}

func TestZeroKernelCryptoEntriesClearsKeyMaterial(t *testing.T) {
	sendKey := bytesOf(0x11, kernelCryptoAES256KeyLen)
	recvKey := bytesOf(0x22, kernelCryptoAES256KeyLen)
	sendIV := bytesOf(0x33, kernelCryptoAESGCMIVLen)
	recvIV := bytesOf(0x44, kernelCryptoAESGCMIVLen)

	entries, err := encodeKernelCryptoSpec(dataplane.TIXTCPCryptoSpec{
		FlowID:     42,
		Suite:      kernelCryptoSuiteAES256GCMX25519,
		WireFormat: kernelCryptoWireFormatTrustIXSecureDataV1,
		SendKey:    sendKey,
		SendIV:     sendIV,
		RecvKey:    recvKey,
		RecvIV:     recvIV,
	})
	if err != nil {
		t.Fatalf("encode kernel crypto spec: %v", err)
	}

	zeroKernelCryptoEntries(entries)
	for _, entry := range entries {
		if entry != (kernelCryptoFlowEntry{}) {
			t.Fatalf("kernel crypto entry was not zeroed: %#v", entry)
		}
	}
}

func TestEncodeKernelCryptoSpecRejectsInvalidKeyLength(t *testing.T) {
	_, err := encodeKernelCryptoSpec(dataplane.TIXTCPCryptoSpec{
		FlowID:     42,
		Suite:      kernelCryptoSuiteAES256GCMX25519,
		WireFormat: kernelCryptoWireFormatTrustIXSecureDataV1,
		SendKey:    bytesOf(0x11, kernelCryptoAES256KeyLen-1),
		SendIV:     bytesOf(0x33, kernelCryptoAESGCMIVLen),
		RecvKey:    bytesOf(0x22, kernelCryptoAES256KeyLen),
		RecvIV:     bytesOf(0x44, kernelCryptoAESGCMIVLen),
	})
	if err == nil || !strings.Contains(err.Error(), "send key length") {
		t.Fatalf("error = %v, want send key length", err)
	}
}

func TestEncodeKernelCryptoSpecsRejectsMapOverflow(t *testing.T) {
	specs := make([]dataplane.TIXTCPCryptoSpec, int(kernelCryptoMaxEntries)/2+1)
	_, err := encodeKernelCryptoSpecs(specs)
	if err == nil || !strings.Contains(err.Error(), "exceeds map capacity") {
		t.Fatalf("error = %v, want map capacity", err)
	}
}

func TestKernelCryptoMapSchemaMatchesEncodedTypes(t *testing.T) {
	schema := kernelCryptoMapSchema()
	if schema.FlowKeySize != binary.Size(kernelCryptoFlowKey{}) {
		t.Fatalf("key size = %d", schema.FlowKeySize)
	}
	if schema.FlowValueSize != binary.Size(kernelCryptoFlowValue{}) {
		t.Fatalf("value size = %d", schema.FlowValueSize)
	}
	if schema.MaxEntries != kernelCryptoMaxEntries {
		t.Fatalf("max entries = %d", schema.MaxEntries)
	}
	if got := strings.Join(schema.SupportedSuites, ","); !strings.Contains(got, kernelCryptoSuiteAES128GCMX25519) {
		t.Fatalf("supported suites = %q, want AES-128", got)
	}
	if got := strings.Join(schema.UnsupportedSuites, ","); !strings.Contains(got, kernelCryptoSuiteChaCha20Poly1305X25519) {
		t.Fatalf("unsupported suites = %q, want ChaCha", got)
	}
}

func testBTFWithFunctions(names ...string) []byte {
	stringsSection := []byte{0}
	nameOffsets := make([]uint32, 0, len(names))
	for _, name := range names {
		nameOffsets = append(nameOffsets, uint32(len(stringsSection)))
		stringsSection = append(stringsSection, name...)
		stringsSection = append(stringsSection, 0)
	}
	var types []byte
	for _, nameOff := range nameOffsets {
		types = appendBTFType(types, nameOff, btfKindFunc, 0, 1, nil)
	}
	header := make([]byte, 24)
	binary.LittleEndian.PutUint16(header[0:2], btfMagic)
	header[2] = 1
	binary.LittleEndian.PutUint32(header[4:8], uint32(len(header)))
	binary.LittleEndian.PutUint32(header[8:12], 0)
	binary.LittleEndian.PutUint32(header[12:16], uint32(len(types)))
	binary.LittleEndian.PutUint32(header[16:20], uint32(len(types)))
	binary.LittleEndian.PutUint32(header[20:24], uint32(len(stringsSection)))
	payload := append(header, types...)
	return append(payload, stringsSection...)
}

func appendBTFType(out []byte, nameOff uint32, kind int, vlen int, sizeOrType uint32, extra []byte) []byte {
	header := make([]byte, 12)
	binary.LittleEndian.PutUint32(header[0:4], nameOff)
	binary.LittleEndian.PutUint32(header[4:8], uint32(kind<<24)|uint32(vlen))
	binary.LittleEndian.PutUint32(header[8:12], sizeOrType)
	out = append(out, header...)
	return append(out, extra...)
}

func bytesOf(value byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = value
	}
	return out
}
