package ebpf

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"trustix.local/trustix/internal/dataplane"
)

const kernelCryptoProviderPendingReason = "kernel BPF crypto kfuncs and AES-GCM are present, but the TrustIX eBPF crypto provider is not loaded"
const kernelCryptoSelfTestPendingReason = "kfunc verifier selftest has not been attempted"

const (
	kernelCryptoSuiteAES256GCMX25519                     = "AES-256-GCM-X25519"
	kernelCryptoSuiteAES128GCMX25519                     = "AES-128-GCM-X25519"
	kernelCryptoSuiteChaCha20Poly1305X25519              = "CHACHA20-POLY1305-X25519"
	kernelCryptoWireFormatTrustIXSecureDataV1            = "trustix-secure-data-v1"
	kernelCryptoAES128KeyLen                             = 16
	kernelCryptoAES256KeyLen                             = 32
	kernelCryptoMaxKeyLen                                = 32
	kernelCryptoAESGCMIVLen                              = 12
	kernelCryptoMaxEntries                               = 4096
	kernelCryptoNamespaceTIXTCP                   uint8  = 0
	kernelCryptoNamespaceKernelUDP                uint8  = 1
	kernelCryptoDirectionSend                     uint8  = 1
	kernelCryptoDirectionRecv                     uint8  = 2
	kernelCryptoSuiteIDTrustIXAES256GCMX25519     uint16 = 1
	kernelCryptoSuiteIDTrustIXAES128GCMX25519     uint16 = 2
	kernelCryptoSuiteIDTrustIXChaCha20Poly1305    uint16 = 3
	kernelCryptoWireFormatIDSecureV1              uint16 = 1
	kernelCryptoFlowFlagHotStats                  uint32 = 1
	kernelCryptoFlowFlagNoReplay                  uint32 = 2
	kernelCryptoChacha20Poly1305UnsupportedReason        = "kernel crypto kfunc provider only exposes AEAD gcm(aes); ChaCha20-Poly1305 remains userspace until a synchronous kernel chacha20-poly1305 AEAD provider is available"
)

var kernelCryptoRequiredKfuncs = []string{
	"bpf_crypto_ctx_create",
	"bpf_crypto_ctx_release",
	"bpf_crypto_encrypt",
	"bpf_crypto_decrypt",
	"bpf_rcu_read_lock",
	"bpf_rcu_read_unlock",
}

const (
	btfMagic    = 0xeb9f
	btfKindFunc = 12
)

type procCryptoAlgorithm struct {
	Name   string
	Driver string
	Module string
}

type kernelCryptoFlowKey struct {
	FlowID    uint64
	Direction uint8
	Reserved  [7]byte
}

type kernelCryptoFlowValue struct {
	Suite         uint16
	WireFormat    uint16
	Flags         uint32
	KeyLen        uint32
	_             uint32
	Epoch         uint64
	Key           [kernelCryptoMaxKeyLen]byte
	IV            [kernelCryptoAESGCMIVLen]byte
	ReplayWindow  uint32
	InstalledUnix int64
	Reserved      [4]uint64
}

type kernelCryptoFlowEntry struct {
	Key   kernelCryptoFlowKey
	Value kernelCryptoFlowValue
}

func baseKernelCryptoProbe() dataplane.KernelCryptoProbe {
	return dataplane.KernelCryptoProbe{
		RequiredKfuncs: append([]string(nil), kernelCryptoRequiredKfuncs...),
		ProviderReady:  false,
		SelfTest:       kernelCryptoSelfTest(dataplane.KernelCryptoProbe{}),
		MapSchema:      kernelCryptoMapSchema(),
	}
}

func unprobedKernelCryptoProbe() dataplane.KernelCryptoProbe {
	probe := baseKernelCryptoProbe()
	probe.Reason = "kernel crypto capability has not been probed"
	return probe
}

func cloneKernelCryptoProbe(probe dataplane.KernelCryptoProbe) dataplane.KernelCryptoProbe {
	probe.RequiredKfuncs = append([]string(nil), probe.RequiredKfuncs...)
	probe.MissingKfuncs = append([]string(nil), probe.MissingKfuncs...)
	probe.CryptoAlgorithms = append([]string(nil), probe.CryptoAlgorithms...)
	if probe.SelfTest != nil {
		selfTest := *probe.SelfTest
		selfTest.ProgramTypes = append([]string(nil), probe.SelfTest.ProgramTypes...)
		probe.SelfTest = &selfTest
	}
	if probe.MapSchema != nil {
		schema := *probe.MapSchema
		schema.Directions = append([]string(nil), probe.MapSchema.Directions...)
		schema.KeyNamespaces = append([]string(nil), probe.MapSchema.KeyNamespaces...)
		schema.SupportedSuites = append([]string(nil), probe.MapSchema.SupportedSuites...)
		schema.SoftwareFallback = append([]string(nil), probe.MapSchema.SoftwareFallback...)
		schema.UnsupportedSuites = append([]string(nil), probe.MapSchema.UnsupportedSuites...)
		if probe.MapSchema.UnsupportedReasons != nil {
			schema.UnsupportedReasons = make(map[string]string, len(probe.MapSchema.UnsupportedReasons))
			for suite, reason := range probe.MapSchema.UnsupportedReasons {
				schema.UnsupportedReasons[suite] = reason
			}
		}
		schema.SupportedFormats = append([]string(nil), probe.MapSchema.SupportedFormats...)
		probe.MapSchema = &schema
	}
	return probe
}

func kernelCryptoUnavailableReason(probe dataplane.KernelCryptoProbe) string {
	if probe.Reason != "" {
		return probe.Reason
	}
	return "kernel AEAD crypto offload requires the TrustIX BPF crypto provider"
}

func kernelCryptoProbeReason(probe dataplane.KernelCryptoProbe, btfErr string, procCryptoErr string) string {
	switch {
	case !probe.KernelBTF:
		if btfErr != "" {
			return "kernel BTF is unavailable: " + btfErr
		}
		return "kernel BTF is unavailable"
	case !probe.CryptoKfuncs:
		if len(probe.MissingKfuncs) > 0 {
			return "kernel BTF is missing BPF crypto/RCU kfuncs: " + strings.Join(probe.MissingKfuncs, ", ")
		}
		return "kernel BTF is missing BPF crypto/RCU kfuncs"
	case procCryptoErr != "":
		return "kernel crypto API algorithms could not be read: " + procCryptoErr
	case !probe.AESGCM:
		return "kernel crypto API does not expose AES-GCM (gcm(aes))"
	case probe.SelfTest != nil && probe.SelfTest.Attempted && !probe.SelfTest.Passed:
		if probe.SelfTest.Reason != "" {
			return "kernel BPF crypto verifier selftest failed: " + probe.SelfTest.Reason
		}
		return "kernel BPF crypto verifier selftest failed"
	case probe.CapabilityReady && !probe.ProviderReady:
		return kernelCryptoProviderPendingReason
	default:
		return ""
	}
}

func kernelCryptoSelfTest(probe dataplane.KernelCryptoProbe) *dataplane.KernelCryptoSelfTest {
	selfTest := &dataplane.KernelCryptoSelfTest{
		ProgramTypes: []string{"syscall", "xdp", "sched_cls"},
	}
	if !probe.CapabilityReady {
		selfTest.Reason = "skipped: kernel crypto kfunc capability is incomplete"
		return selfTest
	}
	selfTest.Reason = kernelCryptoSelfTestPendingReason
	return selfTest
}

func kernelCryptoMapSchema() *dataplane.KernelCryptoMapSchema {
	return &dataplane.KernelCryptoMapSchema{
		MaxEntries:       kernelCryptoMaxEntries,
		FlowKeySize:      binary.Size(kernelCryptoFlowKey{}),
		FlowValueSize:    binary.Size(kernelCryptoFlowValue{}),
		Directions:       []string{"send", "recv"},
		KeyNamespaces:    []string{"tix_tcp", "kernel_udp"},
		SupportedSuites:  []string{kernelCryptoSuiteAES256GCMX25519, kernelCryptoSuiteAES128GCMX25519},
		SoftwareFallback: []string{kernelCryptoSuiteAES256GCMX25519, kernelCryptoSuiteAES128GCMX25519},
		UnsupportedSuites: []string{
			kernelCryptoSuiteChaCha20Poly1305X25519,
		},
		UnsupportedReasons: map[string]string{
			kernelCryptoSuiteChaCha20Poly1305X25519: kernelCryptoChacha20Poly1305UnsupportedReason,
		},
		SupportedFormats: []string{kernelCryptoWireFormatTrustIXSecureDataV1},
	}
}

func encodeKernelCryptoSpec(spec dataplane.TIXTCPCryptoSpec) ([]kernelCryptoFlowEntry, error) {
	return encodeKernelCryptoInstallSpec(kernelCryptoInstallSpec{
		component:    "tix_tcp",
		namespace:    kernelCryptoNamespaceTIXTCP,
		flowID:       spec.FlowID,
		suite:        spec.Suite,
		wireFormat:   spec.WireFormat,
		epoch:        spec.Epoch,
		sendKey:      spec.SendKey,
		sendIV:       spec.SendIV,
		recvKey:      spec.RecvKey,
		recvIV:       spec.RecvIV,
		replayWindow: spec.ReplayWindow,
		installedAt:  spec.InstalledAt,
	})
}

func encodeKernelUDPCryptoSpec(spec dataplane.KernelUDPCryptoSpec) ([]kernelCryptoFlowEntry, error) {
	return encodeKernelCryptoInstallSpec(kernelCryptoInstallSpec{
		component:    "kernel_udp",
		namespace:    kernelCryptoNamespaceKernelUDP,
		flowID:       spec.FlowID,
		suite:        spec.Suite,
		wireFormat:   spec.WireFormat,
		epoch:        spec.Epoch,
		sendKey:      spec.SendKey,
		sendIV:       spec.SendIV,
		recvKey:      spec.RecvKey,
		recvIV:       spec.RecvIV,
		replayWindow: spec.ReplayWindow,
		installedAt:  spec.InstalledAt,
	})
}

type kernelCryptoInstallSpec struct {
	component    string
	namespace    uint8
	flowID       uint64
	suite        string
	wireFormat   string
	epoch        uint64
	sendKey      []byte
	sendIV       []byte
	recvKey      []byte
	recvIV       []byte
	replayWindow uint
	installedAt  time.Time
}

func encodeKernelCryptoInstallSpec(spec kernelCryptoInstallSpec) ([]kernelCryptoFlowEntry, error) {
	suiteID, keyLen, err := validateKernelCryptoInstallSpec(spec)
	if err != nil {
		return nil, err
	}
	flags := kernelCryptoFlowFlags()
	installed := spec.installedAt
	if installed.IsZero() {
		installed = time.Now().UTC()
	}
	return []kernelCryptoFlowEntry{
		{
			Key: kernelCryptoFlowKeyFor(spec.namespace, spec.flowID, kernelCryptoDirectionSend),
			Value: kernelCryptoFlowValue{
				Suite:         suiteID,
				WireFormat:    kernelCryptoWireFormatIDSecureV1,
				Flags:         flags,
				KeyLen:        uint32(keyLen),
				Epoch:         spec.epoch,
				Key:           kernelCryptoFixedKey(spec.sendKey),
				IV:            kernelCryptoFixedIV(spec.sendIV),
				ReplayWindow:  uint32(spec.replayWindow),
				InstalledUnix: installed.UnixNano(),
			},
		},
		{
			Key: kernelCryptoFlowKeyFor(spec.namespace, spec.flowID, kernelCryptoDirectionRecv),
			Value: kernelCryptoFlowValue{
				Suite:         suiteID,
				WireFormat:    kernelCryptoWireFormatIDSecureV1,
				Flags:         flags,
				KeyLen:        uint32(keyLen),
				Epoch:         spec.epoch,
				Key:           kernelCryptoFixedKey(spec.recvKey),
				IV:            kernelCryptoFixedIV(spec.recvIV),
				ReplayWindow:  uint32(spec.replayWindow),
				InstalledUnix: installed.UnixNano(),
			},
		},
	}, nil
}

func kernelCryptoFlowFlags() uint32 {
	var flags uint32
	if kernelCryptoHotPathStatsRequested() {
		flags |= kernelCryptoFlowFlagHotStats
	}
	if kernelCryptoNoReplayRequested() {
		flags |= kernelCryptoFlowFlagNoReplay
	}
	return flags
}

func kernelCryptoHotPathStatsRequested() bool {
	for _, name := range []string{
		"TRUSTIX_TIX_TCP_HOT_STATS",
		"TRUSTIX_XDP_HOT_STATS",
		"TRUSTIX_KERNEL_UDP_XDP_HOT_STATS",
		"TRUSTIX_KERNEL_UDP_TC_HOT_STATS",
		"TRUSTIX_KERNEL_UDP_HOT_STATS",
		"TRUSTIX_TC_HOT_STATS",
	} {
		switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
		case "1", "true", "yes", "on", "enabled":
			return true
		}
	}
	return false
}

func kernelCryptoNoReplayRequested() bool {
	for _, name := range []string{
		"TRUSTIX_KERNEL_CRYPTO_NO_REPLAY",
		"TRUSTIX_TIX_TCP_KERNEL_CRYPTO_NO_REPLAY",
		"TRUSTIX_KERNEL_UDP_KERNEL_CRYPTO_NO_REPLAY",
	} {
		switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
		case "1", "true", "yes", "on", "enabled":
			return true
		}
	}
	return false
}

func validateKernelCryptoSpec(spec dataplane.TIXTCPCryptoSpec) error {
	_, _, err := validateKernelCryptoInstallSpec(kernelCryptoInstallSpec{
		component:    "tix_tcp",
		namespace:    kernelCryptoNamespaceTIXTCP,
		flowID:       spec.FlowID,
		suite:        spec.Suite,
		wireFormat:   spec.WireFormat,
		epoch:        spec.Epoch,
		sendKey:      spec.SendKey,
		sendIV:       spec.SendIV,
		recvKey:      spec.RecvKey,
		recvIV:       spec.RecvIV,
		replayWindow: spec.ReplayWindow,
		installedAt:  spec.InstalledAt,
	})
	return err
}

func validateKernelCryptoInstallSpec(spec kernelCryptoInstallSpec) (uint16, int, error) {
	if spec.flowID == 0 {
		return 0, 0, fmt.Errorf("%s kernel crypto flow id is required", spec.component)
	}
	suiteID, keyLen, err := kernelCryptoSuiteIDAndKeyLen(spec.suite)
	if err != nil {
		return 0, 0, fmt.Errorf("%s kernel crypto suite %q is unsupported: %w", spec.component, spec.suite, err)
	}
	if spec.wireFormat != kernelCryptoWireFormatTrustIXSecureDataV1 {
		return 0, 0, fmt.Errorf("%s kernel crypto wire format %q is unsupported", spec.component, spec.wireFormat)
	}
	if len(spec.sendKey) != keyLen {
		return 0, 0, fmt.Errorf("%s kernel crypto send key length %d, want %d", spec.component, len(spec.sendKey), keyLen)
	}
	if len(spec.recvKey) != keyLen {
		return 0, 0, fmt.Errorf("%s kernel crypto recv key length %d, want %d", spec.component, len(spec.recvKey), keyLen)
	}
	if len(spec.sendIV) != kernelCryptoAESGCMIVLen {
		return 0, 0, fmt.Errorf("%s kernel crypto send iv length %d, want %d", spec.component, len(spec.sendIV), kernelCryptoAESGCMIVLen)
	}
	if len(spec.recvIV) != kernelCryptoAESGCMIVLen {
		return 0, 0, fmt.Errorf("%s kernel crypto recv iv length %d, want %d", spec.component, len(spec.recvIV), kernelCryptoAESGCMIVLen)
	}
	if spec.replayWindow > uint(^uint32(0)) {
		return 0, 0, fmt.Errorf("%s kernel crypto replay window %d exceeds uint32", spec.component, spec.replayWindow)
	}
	return suiteID, keyLen, nil
}

func kernelCryptoSuiteIDAndKeyLen(suite string) (uint16, int, error) {
	switch suite {
	case kernelCryptoSuiteAES256GCMX25519:
		return kernelCryptoSuiteIDTrustIXAES256GCMX25519, kernelCryptoAES256KeyLen, nil
	case kernelCryptoSuiteAES128GCMX25519:
		return kernelCryptoSuiteIDTrustIXAES128GCMX25519, kernelCryptoAES128KeyLen, nil
	case kernelCryptoSuiteChaCha20Poly1305X25519:
		return 0, 0, fmt.Errorf(kernelCryptoChacha20Poly1305UnsupportedReason)
	default:
		return 0, 0, fmt.Errorf("suite is not in the kernel provider schema")
	}
}

func kernelCryptoSuiteID(suite string) (uint16, error) {
	suiteID, _, err := kernelCryptoSuiteIDAndKeyLen(suite)
	return suiteID, err
}

func encodeKernelCryptoSpecs(specs []dataplane.TIXTCPCryptoSpec) ([]kernelCryptoFlowEntry, error) {
	if len(specs) > int(kernelCryptoMaxEntries)/2 {
		return nil, fmt.Errorf("tix_tcp kernel crypto spec count %d exceeds map capacity %d", len(specs), kernelCryptoMaxEntries/2)
	}
	entries := make([]kernelCryptoFlowEntry, 0, len(specs)*2)
	for _, spec := range specs {
		specEntries, err := encodeKernelCryptoSpec(spec)
		if err != nil {
			zeroKernelCryptoEntries(entries)
			return nil, err
		}
		entries = append(entries, specEntries...)
	}
	return entries, nil
}

func encodeKernelUDPCryptoSpecs(specs []dataplane.KernelUDPCryptoSpec) ([]kernelCryptoFlowEntry, error) {
	if len(specs) > int(kernelCryptoMaxEntries)/2 {
		return nil, fmt.Errorf("kernel_udp kernel crypto spec count %d exceeds map capacity %d", len(specs), kernelCryptoMaxEntries/2)
	}
	entries := make([]kernelCryptoFlowEntry, 0, len(specs)*2)
	for _, spec := range specs {
		specEntries, err := encodeKernelUDPCryptoSpec(spec)
		if err != nil {
			zeroKernelCryptoEntries(entries)
			return nil, err
		}
		entries = append(entries, specEntries...)
	}
	return entries, nil
}

func zeroKernelCryptoEntries(entries []kernelCryptoFlowEntry) {
	for i := range entries {
		entries[i] = kernelCryptoFlowEntry{}
	}
}

func uniqueKernelCryptoFlowIDs(entries []kernelCryptoFlowEntry) []uint64 {
	seen := make(map[uint64]struct{}, len(entries)/2)
	flowIDs := make([]uint64, 0, len(entries)/2)
	for _, entry := range entries {
		if entry.Key.FlowID == 0 {
			continue
		}
		if _, ok := seen[entry.Key.FlowID]; ok {
			continue
		}
		seen[entry.Key.FlowID] = struct{}{}
		flowIDs = append(flowIDs, entry.Key.FlowID)
	}
	return flowIDs
}

func uniqueKernelCryptoFlowKeys(entries []kernelCryptoFlowEntry) []kernelCryptoFlowKey {
	seen := make(map[kernelCryptoFlowKey]struct{}, len(entries))
	keys := make([]kernelCryptoFlowKey, 0, len(entries))
	for _, entry := range entries {
		key := entry.Key
		if key.FlowID == 0 {
			continue
		}
		key.Direction = 0
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	return keys
}

func kernelCryptoFlowKeyFor(namespace uint8, flowID uint64, direction uint8) kernelCryptoFlowKey {
	key := kernelCryptoFlowKey{FlowID: flowID, Direction: direction}
	key.Reserved[0] = namespace
	return key
}

func kernelCryptoFixedKey(key []byte) [kernelCryptoMaxKeyLen]byte {
	var out [kernelCryptoMaxKeyLen]byte
	copy(out[:], key)
	return out
}

func kernelCryptoFixedIV(iv []byte) [kernelCryptoAESGCMIVLen]byte {
	var out [kernelCryptoAESGCMIVLen]byte
	copy(out[:], iv)
	return out
}

func parseProcCrypto(payload []byte) []procCryptoAlgorithm {
	var algorithms []procCryptoAlgorithm
	var current procCryptoAlgorithm
	flush := func() {
		if current.Name == "" && current.Driver == "" && current.Module == "" {
			return
		}
		algorithms = append(algorithms, current)
		current = procCryptoAlgorithm{}
	}
	for _, rawLine := range strings.Split(string(payload), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			flush()
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "name":
			current.Name = value
		case "driver":
			current.Driver = value
		case "module":
			current.Module = value
		}
	}
	flush()
	return algorithms
}

func summarizeKernelCryptoAlgorithms(algorithms []procCryptoAlgorithm, cpuInfo []byte) (bool, bool, bool, []string) {
	var aesGCM bool
	var aesNI bool
	var aesGCMSoftware bool
	interesting := make(map[string]struct{})
	for _, algorithm := range algorithms {
		name := strings.ToLower(algorithm.Name)
		driver := strings.ToLower(algorithm.Driver)
		module := strings.ToLower(algorithm.Module)
		isGCM := strings.Contains(name, "gcm(aes)") ||
			strings.Contains(driver, "gcm-aes") ||
			strings.Contains(driver, "gcm_aes")
		isAESNI := strings.Contains(driver, "aesni") ||
			strings.Contains(driver, "aes-ni") ||
			strings.Contains(module, "aesni") ||
			strings.Contains(module, "aes-ni")
		if isGCM {
			aesGCM = true
		}
		if isAESNI {
			aesNI = true
		}
		if isGCM && !isAESNI {
			aesGCMSoftware = true
		}
		if isGCM || isAESNI {
			if label := formatProcCryptoAlgorithm(algorithm); label != "" {
				interesting[label] = struct{}{}
			}
		}
	}
	if cpuInfoHasAES(cpuInfo) {
		aesNI = true
	}
	if aesGCM && !aesNI {
		aesGCMSoftware = true
	}
	labels := make([]string, 0, len(interesting))
	for label := range interesting {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	if len(labels) > 16 {
		labels = labels[:16]
	}
	return aesGCM, aesNI, aesGCMSoftware, labels
}

func formatProcCryptoAlgorithm(algorithm procCryptoAlgorithm) string {
	var parts []string
	if algorithm.Name != "" {
		parts = append(parts, algorithm.Name)
	}
	if algorithm.Driver != "" && algorithm.Driver != algorithm.Name {
		parts = append(parts, "driver="+algorithm.Driver)
	}
	if algorithm.Module != "" {
		parts = append(parts, "module="+algorithm.Module)
	}
	return strings.Join(parts, " ")
}

func cpuInfoHasAES(payload []byte) bool {
	for _, rawLine := range strings.Split(string(payload), "\n") {
		key, value, ok := strings.Cut(rawLine, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if key != "flags" && key != "features" {
			continue
		}
		for _, field := range strings.Fields(strings.ToLower(value)) {
			if field == "aes" || field == "aes_ni" || field == "aes-ni" {
				return true
			}
		}
	}
	return false
}

func missingKernelCryptoKfuncsFromBTF(payload []byte, names []string) ([]string, error) {
	functions, err := btfFunctionNames(payload)
	if err != nil {
		return nil, err
	}
	missing := make([]string, 0, len(names))
	for _, name := range names {
		if !functions[name] {
			missing = append(missing, name)
		}
	}
	return missing, nil
}

func btfFunctionNames(payload []byte) (map[string]bool, error) {
	const headerLen = 24
	if len(payload) < headerLen {
		return nil, fmt.Errorf("BTF payload is too short: %d bytes", len(payload))
	}
	order, err := btfByteOrder(payload)
	if err != nil {
		return nil, err
	}
	hdrLen := int(order.Uint32(payload[4:8]))
	typeOff := int(order.Uint32(payload[8:12]))
	typeLen := int(order.Uint32(payload[12:16]))
	strOff := int(order.Uint32(payload[16:20]))
	strLen := int(order.Uint32(payload[20:24]))
	if hdrLen < headerLen || hdrLen > len(payload) {
		return nil, fmt.Errorf("invalid BTF header length %d", hdrLen)
	}
	body := payload[hdrLen:]
	if typeOff < 0 || typeLen < 0 || typeOff+typeLen > len(body) {
		return nil, fmt.Errorf("invalid BTF type section offset=%d len=%d", typeOff, typeLen)
	}
	if strOff < 0 || strLen < 0 || strOff+strLen > len(body) {
		return nil, fmt.Errorf("invalid BTF string section offset=%d len=%d", strOff, strLen)
	}
	types := body[typeOff : typeOff+typeLen]
	stringsSection := body[strOff : strOff+strLen]
	functions := make(map[string]bool)
	for offset := 0; offset < len(types); {
		if len(types)-offset < 12 {
			return nil, fmt.Errorf("truncated BTF type header at offset %d", offset)
		}
		nameOff := int(order.Uint32(types[offset : offset+4]))
		info := order.Uint32(types[offset+4 : offset+8])
		kind := int((info >> 24) & 0x1f)
		vlen := int(info & 0xffff)
		if kind == btfKindFunc {
			name, ok := btfString(stringsSection, nameOff)
			if ok && name != "" {
				functions[name] = true
			}
		}
		extra, err := btfTypeExtraLen(kind, vlen)
		if err != nil {
			return nil, err
		}
		offset += 12 + extra
		if offset > len(types) {
			return nil, fmt.Errorf("truncated BTF type kind=%d vlen=%d", kind, vlen)
		}
	}
	return functions, nil
}

func btfByteOrder(payload []byte) (binary.ByteOrder, error) {
	switch {
	case binary.LittleEndian.Uint16(payload[0:2]) == btfMagic:
		return binary.LittleEndian, nil
	case binary.BigEndian.Uint16(payload[0:2]) == btfMagic:
		return binary.BigEndian, nil
	default:
		return nil, fmt.Errorf("invalid BTF magic 0x%02x%02x", payload[0], payload[1])
	}
}

func btfString(stringsSection []byte, offset int) (string, bool) {
	if offset < 0 || offset >= len(stringsSection) {
		return "", false
	}
	end := offset
	for end < len(stringsSection) && stringsSection[end] != 0 {
		end++
	}
	if end >= len(stringsSection) {
		return "", false
	}
	return string(stringsSection[offset:end]), true
}

func btfTypeExtraLen(kind int, vlen int) (int, error) {
	switch kind {
	case 0:
		return 0, fmt.Errorf("unsupported BTF kind 0")
	case 1:
		return 4, nil
	case 2, 7, 8, 9, 10, 11, 12, 16, 18:
		return 0, nil
	case 3:
		return 12, nil
	case 4, 5:
		return vlen * 12, nil
	case 6:
		return vlen * 8, nil
	case 13:
		return vlen * 8, nil
	case 14:
		return 4, nil
	case 15:
		return vlen * 12, nil
	case 17:
		return 4, nil
	case 19:
		return vlen * 12, nil
	default:
		return 0, fmt.Errorf("unsupported BTF kind %d", kind)
	}
}
