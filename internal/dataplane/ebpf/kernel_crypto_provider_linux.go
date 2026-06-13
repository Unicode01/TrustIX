//go:build linux

package ebpf

import (
	"bytes"
	"embed"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime/debug"
	"strings"

	cebpf "github.com/cilium/ebpf"

	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/kernelmodule"
)

const kernelCryptoFlowMapName = "ix_exp_tcp_kernel_crypto_flows"
const kernelCryptoProviderMaxReason = 768

const (
	kernelCryptoCommandInstall    uint32 = 1
	kernelCryptoCommandDelete     uint32 = 2
	kernelCryptoRoundTripPlainLen        = 16
	kernelCryptoRoundTripTagLen          = 16
	kernelCryptoRoundTripWireLen         = kernelCryptoRoundTripPlainLen + kernelCryptoRoundTripTagLen
	kernelCryptoFrameMaxWire             = 4095
	kernelCryptoFrameTagLen              = 16
	kernelCryptoFrameMaxPlain            = kernelCryptoFrameMaxWire - kernelCryptoFrameTagLen
	kernelCryptoSecureHeaderLen          = 24
	kernelCryptoSecureVersion            = 1
)

//go:embed bpf/kernel_crypto_provider_bpfel.o
var kernelCryptoProviderFS embed.FS

type kernelCryptoCommand struct {
	Op     uint32
	Result int32
	Slot   uint32
	_      uint32
	Key    kernelCryptoFlowKey
	Value  kernelCryptoFlowValue
}

type kernelCryptoRoundTripScratch struct {
	Key      kernelCryptoFlowKey
	Result   int32
	_        uint32
	Plain    [kernelCryptoRoundTripWireLen]byte
	Cipher   [kernelCryptoRoundTripWireLen]byte
	Out      [kernelCryptoRoundTripWireLen]byte
	Nonce    [kernelCryptoAESGCMIVLen]byte
	Reserved [4]byte
}

type kernelCryptoFrameScratch struct {
	Key      kernelCryptoFlowKey
	Result   int32
	_        uint32
	Epoch    uint64
	Sequence uint64
	InLen    uint32
	OutLen   uint32
	In       [kernelCryptoFrameMaxWire]byte
	Out      [kernelCryptoFrameMaxWire]byte
	Nonce    [kernelCryptoAESGCMIVLen]byte
	Reserved [6]byte
}

type kernelCryptoCtxSlotValue struct {
	Context       uint64
	Suite         uint16
	WireFormat    uint16
	Flags         uint32
	Epoch         uint64
	IV            [kernelCryptoAESGCMIVLen]byte
	ReplayWindow  uint32
	InstalledUnix int64
	Packets       uint64
	Bytes         uint64
	LastSequence  uint64
	ReplaySeen    [64]uint64
	ReplayBlocks  [64]uint64
}

type kernelCryptoProviderObject struct {
	collection     *cebpf.Collection
	commandMap     *cebpf.Map
	flowIndexMap   *cebpf.Map
	contextSlots   *cebpf.Map
	directSlotMap  *cebpf.Map
	roundTripMap   *cebpf.Map
	frameMap       *cebpf.Map
	installProgram *cebpf.Program
	deleteProgram  *cebpf.Program
	roundTripProg  *cebpf.Program
	frameSealProg  *cebpf.Program
	frameOpenProg  *cebpf.Program
}

const (
	kernelCryptoCtxSlotValueSize = 1096
)

type kernelCryptoDirectSlotValue struct {
	SlotID        uint32
	Enabled       uint32
	Suite         uint16
	WireFormat    uint16
	Flags         uint32
	Epoch         uint64
	IV            [kernelCryptoAESGCMIVLen]byte
	ReplayWindow  uint32
	InstalledUnix int64
	Packets       uint64
	Bytes         uint64
	LastSequence  uint64
	ReplaySeen    [64]uint64
	ReplayBlocks  [64]uint64
}

type kernelCryptoProviderInstallEntry struct {
	Slot  uint32
	Entry kernelCryptoFlowEntry
}

func (manager *Manager) initKernelCryptoProviderMapLocked() {
	if manager.kernelCryptoFlowMap != nil {
		manager.addCapabilityLocked("experimental-tcp-kernel-crypto-flow-map")
		if manager.kernelCryptoProvider != nil {
			if manager.kernelCryptoProvider.installProgram != nil {
				manager.addCapabilityLocked("experimental-tcp-kernel-crypto-ctx-provider")
			}
			if manager.kernelCryptoProvider.directSlotMap != nil {
				manager.addCapabilityLocked("experimental-tcp-kernel-crypto-direct-slot-provider")
			}
		}
		return
	}
	probe := manager.kernelCryptoProbeSnapshotLocked()
	bpfCryptoProviderReady := probe.SelfTest != nil && probe.SelfTest.Passed
	directSlotProviderReady := kernelCryptoDirectSlotModuleReady()
	if !bpfCryptoProviderReady && !directSlotProviderReady {
		return
	}
	schema := kernelCryptoMapSchema()
	flowMap, err := cebpf.NewMap(&cebpf.MapSpec{
		Name:       kernelCryptoFlowMapName,
		Type:       cebpf.Hash,
		KeySize:    uint32(schema.FlowKeySize),
		ValueSize:  uint32(schema.FlowValueSize),
		MaxEntries: schema.MaxEntries,
	})
	if err != nil {
		manager.kernelCryptoFlowMapCreateErrors++
		manager.warnings = append(manager.warnings, "experimental_tcp kernel crypto flow map unavailable: "+err.Error())
		return
	}
	manager.kernelCryptoFlowMap = flowMap
	manager.kernelCryptoFlowMapEntries = make(map[kernelCryptoFlowKey]struct{})
	manager.addCapabilityLocked("experimental-tcp-kernel-crypto-flow-map")
	var provider *kernelCryptoProviderObject
	if bpfCryptoProviderReady {
		provider, err = loadKernelCryptoProviderObject()
		if err != nil {
			manager.kernelCryptoProviderLoadErrors++
			manager.warnings = append(manager.warnings, "experimental_tcp kernel crypto ctx provider unavailable: "+summarizeKernelCryptoProviderError(err))
		} else {
			manager.kernelCryptoProvider = provider
			manager.addCapabilityLocked("experimental-tcp-kernel-crypto-ctx-provider")
			manager.addCapabilityLocked("experimental-tcp-kernel-crypto-direct-slot-provider")
			manager.probeKernelCryptoAEADCreateLocked()
			return
		}
	}
	if !directSlotProviderReady {
		return
	}
	provider, err = loadKernelCryptoDirectSlotProviderMaps()
	if err != nil {
		manager.kernelCryptoProviderLoadErrors++
		manager.warnings = append(manager.warnings, "experimental_tcp kernel crypto direct-slot provider unavailable: "+err.Error())
		return
	}
	manager.kernelCryptoProvider = provider
	manager.addCapabilityLocked("experimental-tcp-kernel-crypto-direct-slot-provider")
}

func (manager *Manager) closeKernelCryptoProviderMapLocked() error {
	for flowID := range manager.expTCPKernelCryptoDevices {
		manager.deleteKernelCryptoDeviceLocked(kernelCryptoNamespaceExperimentalTCP, flowID)
	}
	for flowID := range manager.kernelCryptoDevices {
		manager.deleteKernelCryptoDeviceLocked(kernelCryptoNamespaceKernelUDP, flowID)
	}
	var closeErr error
	if manager.kernelCryptoProvider != nil {
		for _, slot := range manager.kernelCryptoCtxSlots {
			closeErr = errors.Join(closeErr, manager.kernelCryptoProvider.clearDirectSlot(slot))
		}
		closeErr = errors.Join(closeErr, manager.kernelCryptoProvider.Close())
		manager.kernelCryptoProvider = nil
	}
	manager.kernelCryptoCtxSlots = nil
	manager.kernelCryptoNextSlot = 0
	if manager.kernelCryptoFlowMap == nil {
		manager.kernelCryptoFlowMapEntries = nil
		return closeErr
	}
	err := manager.kernelCryptoFlowMap.Close()
	manager.kernelCryptoFlowMap = nil
	manager.kernelCryptoFlowMapEntries = nil
	if err != nil {
		err = fmt.Errorf("close experimental_tcp kernel crypto flow map: %w", err)
	}
	return errors.Join(closeErr, err)
}

func (manager *Manager) stageKernelCryptoEntriesLocked(entries []kernelCryptoFlowEntry) error {
	if len(entries) == 0 {
		return nil
	}
	if manager.kernelCryptoFlowMap == nil {
		return fmt.Errorf("experimental_tcp kernel crypto flow map is not loaded")
	}
	for _, entry := range entries {
		if err := manager.kernelCryptoFlowMap.Update(entry.Key, entry.Value, cebpf.UpdateAny); err != nil {
			return fmt.Errorf("update experimental_tcp kernel crypto flow %d direction %d: %w", entry.Key.FlowID, entry.Key.Direction, err)
		}
		manager.kernelCryptoFlowMapEntries[entry.Key] = struct{}{}
		manager.kernelCryptoFlowMapUpdates++
	}
	return nil
}

func (manager *Manager) deleteKernelCryptoFlowLocked(flowID uint64) {
	manager.deleteKernelCryptoFlowNamespaceLocked(kernelCryptoNamespaceExperimentalTCP, flowID)
}

func (manager *Manager) deleteKernelUDPCryptoFlowLocked(flowID uint64) {
	manager.deleteKernelCryptoFlowNamespaceLocked(kernelCryptoNamespaceKernelUDP, flowID)
}

func (manager *Manager) deleteKernelCryptoFlowNamespaceLocked(namespace uint8, flowID uint64) {
	if flowID == 0 {
		return
	}
	keys := []kernelCryptoFlowKey{
		kernelCryptoFlowKeyFor(namespace, flowID, kernelCryptoDirectionSend),
		kernelCryptoFlowKeyFor(namespace, flowID, kernelCryptoDirectionRecv),
	}
	if manager.kernelCryptoProvider != nil {
		if err := manager.kernelCryptoProvider.DeleteKeys(keys); err != nil {
			manager.warnings = append(manager.warnings, "delete experimental_tcp kernel crypto ctx flow: "+summarizeKernelCryptoProviderError(err))
		}
	}
	for _, key := range keys {
		if slot, ok := manager.kernelCryptoCtxSlots[key]; ok {
			if manager.kernelCryptoProvider != nil {
				_ = manager.kernelCryptoProvider.clearDirectSlot(slot)
			}
		}
		if manager.kernelCryptoFlowMap != nil {
			if err := manager.kernelCryptoFlowMap.Delete(key); err == nil {
				manager.kernelCryptoFlowMapDeletes++
			}
		}
		delete(manager.kernelCryptoFlowMapEntries, key)
		delete(manager.kernelCryptoCtxSlots, key)
	}
}

func (manager *Manager) syncKernelCryptoDirectSlotsLocked(entries []kernelCryptoProviderInstallEntry) {
	if manager.kernelCryptoProvider == nil || manager.kernelCryptoProvider.directSlotMap == nil {
		return
	}
	for _, install := range entries {
		enabled, directSlot, err := installKernelCryptoDirectSlot(install)
		if err != nil {
			manager.warnings = append(manager.warnings, err.Error())
			continue
		}
		if !enabled {
			if err := manager.kernelCryptoProvider.clearDirectSlot(install.Slot); err != nil {
				manager.warnings = append(manager.warnings, "clear TrustIX AEAD direct slot: "+err.Error())
			}
			continue
		}
		if err := manager.kernelCryptoProvider.publishDirectSlot(install, directSlot); err != nil {
			_ = kernelmodule.AEADDirectClearKey("", directSlot)
			manager.warnings = append(manager.warnings, "publish TrustIX AEAD direct slot: "+err.Error())
		}
	}
}

func (manager *Manager) installKernelCryptoDirectOnlyLocked(entries []kernelCryptoFlowEntry) (bool, error) {
	if len(entries) == 0 {
		return false, nil
	}
	if manager.kernelCryptoProvider == nil ||
		manager.kernelCryptoProvider.flowIndexMap == nil ||
		manager.kernelCryptoProvider.directSlotMap == nil {
		return false, nil
	}
	installEntries, err := manager.prepareKernelCryptoProviderInstallEntriesLocked(entries)
	if err != nil {
		return false, err
	}
	installed := false
	for _, install := range installEntries {
		if err := manager.kernelCryptoProvider.clearDirectSlot(install.Slot); err != nil {
			manager.rollbackKernelCryptoProviderInstallLocked(entries)
			return false, err
		}
		enabled, directSlot, err := installKernelCryptoDirectSlot(install)
		if err != nil {
			manager.rollbackKernelCryptoProviderInstallLocked(entries)
			return false, err
		}
		if !enabled {
			continue
		}
		if err := manager.kernelCryptoProvider.publishDirectSlot(install, directSlot); err != nil {
			_ = kernelmodule.AEADDirectClearKey("", directSlot)
			manager.rollbackKernelCryptoProviderInstallLocked(entries)
			return false, err
		}
		if err := manager.kernelCryptoProvider.flowIndexMap.Update(install.Entry.Key, install.Slot, cebpf.UpdateAny); err != nil {
			_ = kernelmodule.AEADDirectClearKey("", directSlot)
			manager.rollbackKernelCryptoProviderInstallLocked(entries)
			return false, fmt.Errorf("update direct-only kernel crypto flow %d direction %d: %w", install.Entry.Key.FlowID, install.Entry.Key.Direction, err)
		}
		installed = true
	}
	if installed && manager.kernelCryptoFlowMap != nil {
		if err := manager.stageKernelCryptoEntriesLocked(entries); err != nil {
			manager.rollbackKernelCryptoProviderInstallLocked(entries)
			return false, err
		}
	}
	return installed, nil
}

func (manager *Manager) kernelCryptoFlowMapReadyLocked() bool {
	return manager.kernelCryptoFlowMap != nil
}

func (manager *Manager) kernelCryptoFlowMapEntriesLocked() uint64 {
	return uint64(len(manager.kernelCryptoFlowMapEntries))
}

func (manager *Manager) kernelCryptoContextProviderReadyLocked() bool {
	return manager.kernelCryptoProvider != nil &&
		manager.kernelCryptoAEADCreateSuccesses > 0 &&
		manager.kernelCryptoAEADRoundTripSuccesses > 0
}

func (manager *Manager) kernelCryptoDirectSlotProviderReadyLocked() bool {
	return manager.kernelCryptoProvider != nil &&
		manager.kernelCryptoProvider.flowIndexMap != nil &&
		manager.kernelCryptoProvider.directSlotMap != nil &&
		kernelmodule.AEADDeviceAvailable("")
}

func (manager *Manager) kernelCryptoProductionReadyLocked() bool {
	return manager.kernelCryptoContextProviderReadyLocked() &&
		manager.kernelCryptoProvider.frameMap != nil &&
		manager.kernelCryptoProvider.frameSealProg != nil &&
		manager.kernelCryptoProvider.frameOpenProg != nil
}

func (manager *Manager) kernelCryptoTCDirectReadyLocked() bool {
	return kernelCryptoTCDirectProviderReady(manager.kernelCryptoContextProviderReadyLocked(), manager.kernelCryptoDirectSlotProviderReadyLocked(), kernelCryptoDirectKfuncFastpathReady()) &&
		manager.kernelCryptoProvider.flowIndexMap != nil &&
		manager.kernelCryptoProvider.contextSlots != nil &&
		manager.kernelCryptoProvider.directSlotMap != nil &&
		manager.kernelCryptoFlowMap != nil
}

func kernelCryptoTCDirectProviderReady(contextProviderReady bool, directSlotProviderReady bool, directKfuncFastpathReady bool) bool {
	return contextProviderReady || (directSlotProviderReady && directKfuncFastpathReady)
}

func kernelCryptoDirectKfuncFastpathReady() bool {
	value, ok := readTrustIXAEADModuleParamUint64("kfunc_simd_fastpath")
	return ok && value != 0
}

func kernelCryptoDirectKfuncFastpathUnavailableReason() string {
	value, ok := readTrustIXAEADModuleParamUint64("kfunc_simd_fastpath")
	if !ok {
		return "TrustIX AEAD direct kfunc fastpath parameter kfunc_simd_fastpath is unavailable"
	}
	if value == 0 {
		return "TrustIX AEAD direct kfunc fastpath kfunc_simd_fastpath is disabled"
	}
	return ""
}

func (manager *Manager) kernelCryptoTCDirectUnavailableReasonLocked() string {
	reason := manager.kernelCryptoUnavailableReasonLocked()
	if manager.kernelCryptoDirectSlotProviderReadyLocked() {
		if directReason := kernelCryptoDirectKfuncFastpathUnavailableReason(); directReason != "" {
			if reason == "" {
				return directReason
			}
			return reason + "; " + directReason
		}
	}
	return reason
}

func kernelCryptoDirectSlotModuleReady() bool {
	status := kernelmodule.ProbeTrustIXCryptoStatus()
	return status.Loaded &&
		status.HasFeature(kernelmodule.FeatureKfuncTC) &&
		kernelmodule.AEADDeviceAvailable("")
}

func (manager *Manager) kernelCryptoDeviceAvailableLocked(namespace uint8) bool {
	if manager.hasKernelCryptoDeviceLocked(namespace) {
		return true
	}
	return kernelmodule.AEADDeviceAvailable("")
}

func (manager *Manager) kernelUDPDeviceCryptoReasonLocked() string {
	if manager.kernelCryptoDeviceAvailableLocked(kernelCryptoNamespaceKernelUDP) {
		return ""
	}
	return "TrustIX AEAD kernel module device " + kernelmodule.TrustIXAEADDevicePath + " is unavailable"
}

func (manager *Manager) experimentalTCPDeviceCryptoReasonLocked() string {
	if manager.kernelCryptoDeviceAvailableLocked(kernelCryptoNamespaceExperimentalTCP) {
		return ""
	}
	return "TrustIX AEAD kernel module device " + kernelmodule.TrustIXAEADDevicePath + " is unavailable"
}

func (manager *Manager) kernelUDPKernelCryptoReadyLocked() bool {
	return manager.kernelCryptoTCDirectReadyLocked() || manager.kernelCryptoDeviceAvailableLocked(kernelCryptoNamespaceKernelUDP)
}

func (manager *Manager) kernelUDPKernelCryptoUnavailableReasonLocked() string {
	reasons := make([]string, 0, 2)
	if !manager.kernelCryptoTCDirectReadyLocked() {
		reasons = append(reasons, "TC direct BPF crypto provider: "+manager.kernelCryptoTCDirectUnavailableReasonLocked())
	}
	if reason := manager.kernelUDPDeviceCryptoReasonLocked(); reason != "" {
		reasons = append(reasons, "AEAD device: "+reason)
	}
	if len(reasons) == 0 {
		return ""
	}
	return strings.Join(reasons, "; ")
}

func (manager *Manager) kernelUDPCryptoFallbackStatusLocked() dataplane.CryptoFallbackStatus {
	fullModuleStatus := kernelmodule.ProbeTrustIXDatapathStatus()
	helpersModuleStatus := kernelmodule.ProbeTrustIXDatapathHelpersStatus()
	fullDatapathReady := fullModuleStatus.FullDatapathReady() && trustIXFullDatapathDriverReady()
	gsoReady := helpersModuleStatus.GSOSKBReady() && trustIXGSOSKBDriverReady()
	tcReady := manager.kernelCryptoTCDirectReadyLocked()
	deviceReady := manager.kernelCryptoDeviceAvailableLocked(kernelCryptoNamespaceKernelUDP)
	steps := []dataplane.CryptoFallbackStep{
		{
			Name:      dataplane.CryptoFallbackFullKernelModuleDatapath,
			Ready:     fullDatapathReady,
			Placement: "kernel",
			Layer:     dataplane.CryptoFallbackLayerKernelModule,
			Reason:    readinessReason(fullDatapathReady, moduleDatapathFallbackReason(fullModuleStatus, kernelmodule.FeatureFullDatapath, kernelmodule.TrustIXDatapathDevicePath)),
		},
		{
			Name:      dataplane.CryptoFallbackGSOSKBModuleHelpers,
			Ready:     gsoReady,
			Placement: "kernel",
			Layer:     dataplane.CryptoFallbackLayerKernelModule,
			Reason:    readinessReason(gsoReady, moduleDatapathFallbackReason(helpersModuleStatus, kernelmodule.FeatureGSOSKB, kernelmodule.TrustIXDatapathHelpersDevicePath)),
		},
		{
			Name:      dataplane.CryptoFallbackTCBPFDirect,
			Ready:     tcReady,
			Placement: "kernel",
			Layer:     dataplane.CryptoFallbackLayerTC,
			Reason:    readinessReason(tcReady, manager.kernelCryptoTCDirectUnavailableReasonLocked()),
		},
		{
			Name:      dataplane.CryptoFallbackKOAEADDevice,
			Ready:     deviceReady,
			Placement: "kernel",
			Layer:     dataplane.CryptoFallbackLayerDevice,
			Reason:    readinessReason(deviceReady, manager.kernelUDPDeviceCryptoReasonLocked()),
		},
		{
			Name:      dataplane.CryptoFallbackUserspaceAEAD,
			Ready:     true,
			Placement: "userspace",
			Layer:     dataplane.CryptoFallbackLayerUserspace,
			Reason:    "daemon AEAD fallback is available when the UDP kernel transport is active",
		},
	}
	return dataplane.CryptoFallbackStatus{Selected: dataplane.FirstReadyCryptoFallbackStep(steps), Chain: steps}
}

func (manager *Manager) experimentalTCPKernelCryptoReadyLocked() bool {
	return manager.kernelCryptoProductionReadyLocked() || manager.kernelCryptoDeviceAvailableLocked(kernelCryptoNamespaceExperimentalTCP)
}

func (manager *Manager) experimentalTCPKernelCryptoUnavailableReasonLocked() string {
	reasons := make([]string, 0, 2)
	if !manager.kernelCryptoProductionReadyLocked() {
		reasons = append(reasons, "BPF crypto provider: "+manager.kernelCryptoUnavailableReasonLocked())
	}
	if reason := manager.experimentalTCPDeviceCryptoReasonLocked(); reason != "" {
		reasons = append(reasons, "AEAD device: "+reason)
	}
	if len(reasons) == 0 {
		return ""
	}
	return strings.Join(reasons, "; ")
}

func (manager *Manager) experimentalTCPCryptoFallbackStatusLocked() dataplane.CryptoFallbackStatus {
	fullModuleStatus := kernelmodule.ProbeTrustIXDatapathStatus()
	helpersModuleStatus := kernelmodule.ProbeTrustIXDatapathHelpersStatus()
	fullDatapathReady := fullModuleStatus.FullDatapathReady() && trustIXFullDatapathDriverReady()
	gsoReady := helpersModuleStatus.GSOSKBReady() && trustIXGSOSKBDriverReady()
	bpfReady := manager.kernelCryptoProductionReadyLocked()
	deviceReady := manager.kernelCryptoDeviceAvailableLocked(kernelCryptoNamespaceExperimentalTCP)
	steps := []dataplane.CryptoFallbackStep{
		{
			Name:      dataplane.CryptoFallbackFullKernelModuleDatapath,
			Ready:     fullDatapathReady,
			Placement: "kernel",
			Layer:     dataplane.CryptoFallbackLayerKernelModule,
			Reason:    readinessReason(fullDatapathReady, moduleDatapathFallbackReason(fullModuleStatus, kernelmodule.FeatureFullDatapath, kernelmodule.TrustIXDatapathDevicePath)),
		},
		{
			Name:      dataplane.CryptoFallbackGSOSKBModuleHelpers,
			Ready:     gsoReady,
			Placement: "kernel",
			Layer:     dataplane.CryptoFallbackLayerKernelModule,
			Reason:    readinessReason(gsoReady, moduleDatapathFallbackReason(helpersModuleStatus, kernelmodule.FeatureGSOSKB, kernelmodule.TrustIXDatapathHelpersDevicePath)),
		},
		{
			Name:      dataplane.CryptoFallbackBPFProgRunFrame,
			Ready:     bpfReady,
			Placement: "kernel",
			Layer:     dataplane.CryptoFallbackLayerBPFProgRun,
			Reason:    readinessReason(bpfReady, manager.kernelCryptoUnavailableReasonLocked()),
		},
		{
			Name:      dataplane.CryptoFallbackKOAEADDevice,
			Ready:     deviceReady,
			Placement: "kernel",
			Layer:     dataplane.CryptoFallbackLayerDevice,
			Reason:    readinessReason(deviceReady, manager.experimentalTCPDeviceCryptoReasonLocked()),
		},
		{
			Name:      dataplane.CryptoFallbackUserspaceAEAD,
			Ready:     true,
			Placement: "userspace",
			Layer:     dataplane.CryptoFallbackLayerUserspace,
			Reason:    "daemon AEAD fallback is available when the AF_XDP/TCP-shaped transport is active",
		},
	}
	return dataplane.CryptoFallbackStatus{Selected: dataplane.FirstReadyCryptoFallbackStep(steps), Chain: steps}
}

func readinessReason(ready bool, reason string) string {
	if ready {
		return ""
	}
	return reason
}

func moduleDatapathFallbackReason(status kernelmodule.Status, feature string, devicePath string) string {
	if !status.Loaded {
		if status.Reason != "" {
			return status.Reason
		}
		return status.Name + " is not loaded"
	}
	if status.ABIVersion == 0 {
		return status.Name + " does not expose the first-release ABI version"
	}
	if status.HasFeature(feature) {
		query, err := kernelmodule.ProbeDatapath(devicePath)
		if err != nil {
			return status.Name + " ioctl is unavailable: " + err.Error()
		}
		if query.DatapathABIVersion == 0 {
			return status.Name + " ioctl returned no datapath ABI version"
		}
		if !featureListContains(query.Features, feature) {
			return status.Name + " ioctl does not report " + feature
		}
		if !featureListContains(query.SafeFeatures, feature) {
			return status.Name + " ioctl reports " + feature + " only as unsafe"
		}
		if !query.TIXTSelftestOK() {
			return status.Name + " TIXT selftest is not clean"
		}
		if !query.FeaturesActive() {
			return status.Name + " feature gate is inactive"
		}
		return status.Name + " driver is not active"
	}
	if status.CapabilityReason != "" {
		return status.CapabilityReason
	}
	return status.Name + " is loaded but does not report " + feature
}

func trustIXFullDatapathDriverReady() bool {
	query, err := kernelmodule.ProbeDatapath(kernelmodule.TrustIXDatapathDevicePath)
	return err == nil && query.SafeActiveFeature(kernelmodule.FeatureFullDatapath)
}

func trustIXGSOSKBDriverReady() bool {
	query, err := kernelmodule.ProbeDatapath(kernelmodule.TrustIXDatapathHelpersDevicePath)
	return err == nil && query.SafeActiveFeature(kernelmodule.FeatureGSOSKB)
}

func featureListContains(features []string, feature string) bool {
	for _, candidate := range features {
		if candidate == feature {
			return true
		}
	}
	return false
}

func (manager *Manager) installKernelCryptoDevicesLocked(namespace uint8, entries []kernelCryptoFlowEntry) {
	devices := manager.kernelCryptoDeviceMapForNamespaceLocked(namespace, true)
	if devices == nil {
		return
	}
	for _, flowID := range uniqueKernelCryptoFlowIDs(entries) {
		flow, ok := newKernelCryptoDeviceFlow(entries, namespace, flowID)
		if !ok {
			continue
		}
		device, err := newKernelCryptoDevice(flow)
		if err != nil {
			manager.warnings = append(manager.warnings, kernelCryptoNamespaceName(namespace)+" AEAD batch device unavailable: "+err.Error())
			continue
		}
		if old := devices[flowID]; old != nil {
			_ = old.Close()
		}
		devices[flowID] = device
	}
}

func (manager *Manager) hasKernelCryptoDeviceForEntriesLocked(namespace uint8, entries []kernelCryptoFlowEntry) bool {
	devices := manager.kernelCryptoDeviceMapForNamespaceLocked(namespace, false)
	if devices == nil {
		return false
	}
	for _, flowID := range uniqueKernelCryptoFlowIDs(entries) {
		if devices[flowID] != nil {
			return true
		}
	}
	return false
}

func (manager *Manager) deleteKernelCryptoDeviceLocked(namespace uint8, flowID uint64) {
	devices := manager.kernelCryptoDeviceMapForNamespaceLocked(namespace, false)
	if devices == nil {
		return
	}
	if device := devices[flowID]; device != nil {
		_ = device.Close()
	}
	delete(devices, flowID)
}

func (manager *Manager) kernelCryptoDeviceMapForNamespaceLocked(namespace uint8, create bool) map[uint64]*kernelCryptoDevice {
	switch namespace {
	case kernelCryptoNamespaceKernelUDP:
		if manager.kernelCryptoDevices == nil && create {
			manager.kernelCryptoDevices = make(map[uint64]*kernelCryptoDevice)
		}
		return manager.kernelCryptoDevices
	case kernelCryptoNamespaceExperimentalTCP:
		if manager.expTCPKernelCryptoDevices == nil && create {
			manager.expTCPKernelCryptoDevices = make(map[uint64]*kernelCryptoDevice)
		}
		return manager.expTCPKernelCryptoDevices
	default:
		return nil
	}
}

func (manager *Manager) hasKernelCryptoDeviceLocked(namespace uint8) bool {
	for _, device := range manager.kernelCryptoDeviceMapForNamespaceLocked(namespace, false) {
		if device != nil {
			return true
		}
	}
	return false
}

func (manager *Manager) kernelCryptoDeviceForFlowLocked(namespace uint8, flowID uint64) *kernelCryptoDevice {
	devices := manager.kernelCryptoDeviceMapForNamespaceLocked(namespace, false)
	if devices == nil {
		return nil
	}
	return devices[flowID]
}

func (manager *Manager) kernelCryptoProviderHasFlowLocked(namespace uint8, flowID uint64, direction uint8) bool {
	if flowID == 0 || manager.kernelCryptoProvider == nil || manager.kernelCryptoProvider.flowIndexMap == nil {
		return false
	}
	if manager.kernelCryptoCtxSlots == nil {
		return false
	}
	_, ok := manager.kernelCryptoCtxSlots[kernelCryptoFlowKeyFor(namespace, flowID, direction)]
	return ok
}

func kernelCryptoNamespaceName(namespace uint8) string {
	switch namespace {
	case kernelCryptoNamespaceExperimentalTCP:
		return "experimental_tcp"
	case kernelCryptoNamespaceKernelUDP:
		return "kernel_udp"
	default:
		return fmt.Sprintf("namespace_%d", namespace)
	}
}

func (manager *Manager) prepareKernelCryptoProviderInstallEntriesLocked(entries []kernelCryptoFlowEntry) ([]kernelCryptoProviderInstallEntry, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	if len(entries) > int(kernelCryptoMaxEntries) {
		return nil, fmt.Errorf("experimental_tcp kernel crypto ctx entries %d exceeds capacity %d", len(entries), kernelCryptoMaxEntries)
	}
	if manager.kernelCryptoCtxSlots == nil {
		manager.kernelCryptoCtxSlots = make(map[kernelCryptoFlowKey]uint32, len(entries))
	}
	used := make(map[uint32]struct{}, len(manager.kernelCryptoCtxSlots)+len(entries))
	for _, slot := range manager.kernelCryptoCtxSlots {
		used[slot] = struct{}{}
	}
	prepared := make([]kernelCryptoProviderInstallEntry, 0, len(entries))
	allocated := make([]kernelCryptoFlowKey, 0, len(entries))
	for _, entry := range entries {
		slot, ok := manager.kernelCryptoCtxSlots[entry.Key]
		if !ok {
			var err error
			slot, err = manager.nextKernelCryptoProviderSlotLocked(used)
			if err != nil {
				for _, key := range allocated {
					delete(manager.kernelCryptoCtxSlots, key)
				}
				return nil, err
			}
			manager.kernelCryptoCtxSlots[entry.Key] = slot
			allocated = append(allocated, entry.Key)
		}
		used[slot] = struct{}{}
		prepared = append(prepared, kernelCryptoProviderInstallEntry{Slot: slot, Entry: entry})
	}
	return prepared, nil
}

func (manager *Manager) nextKernelCryptoProviderSlotLocked(used map[uint32]struct{}) (uint32, error) {
	for attempts := uint32(0); attempts < kernelCryptoMaxEntries; attempts++ {
		slot := manager.kernelCryptoNextSlot % kernelCryptoMaxEntries
		manager.kernelCryptoNextSlot = (slot + 1) % kernelCryptoMaxEntries
		if _, ok := used[slot]; !ok {
			return slot, nil
		}
	}
	return 0, fmt.Errorf("experimental_tcp kernel crypto ctx slots are exhausted")
}

func (manager *Manager) rollbackKernelCryptoProviderInstallLocked(entries []kernelCryptoFlowEntry) {
	keys := uniqueKernelCryptoFlowKeys(entries)
	for _, key := range keys {
		manager.deleteKernelCryptoFlowNamespaceLocked(key.Reserved[0], key.FlowID)
	}
}

func kernelCryptoFlowMapKeySize() uint32 {
	return uint32(binary.Size(kernelCryptoFlowKey{}))
}

func kernelCryptoFlowMapValueSize() uint32 {
	return uint32(binary.Size(kernelCryptoFlowValue{}))
}

func kernelCryptoCommandSize() uint32 {
	return uint32(binary.Size(kernelCryptoCommand{}))
}

func loadKernelCryptoProviderObject() (provider *kernelCryptoProviderObject, err error) {
	object, err := kernelCryptoProviderFS.ReadFile("bpf/kernel_crypto_provider_bpfel.o")
	if err != nil {
		return nil, fmt.Errorf("read embedded provider object: %w", err)
	}
	if len(object) == 0 {
		return nil, fmt.Errorf("embedded provider object is empty")
	}
	defer debug.FreeOSMemory()

	spec, err := cebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, fmt.Errorf("parse embedded provider ELF: %w", err)
	}
	for _, name := range []string{"trustix_kernel_crypto_cmd_map", "trustix_kernel_crypto_flow_index_map", "trustix_kernel_crypto_ctx_slots", "trustix_kernel_crypto_direct_slots", "trustix_kernel_crypto_roundtrip_map", "trustix_kernel_crypto_frame_map"} {
		if spec.Maps[name] == nil {
			return nil, fmt.Errorf("embedded provider ELF is missing map %q", name)
		}
	}
	if spec.Maps["trustix_kernel_crypto_ctx_slots"].ValueSize != kernelCryptoCtxSlotValueSize {
		return nil, fmt.Errorf("embedded provider ctx slot size %d != expected %d", spec.Maps["trustix_kernel_crypto_ctx_slots"].ValueSize, kernelCryptoCtxSlotValueSize)
	}
	if spec.Maps["trustix_kernel_crypto_direct_slots"].ValueSize != uint32(binary.Size(kernelCryptoDirectSlotValue{})) {
		return nil, fmt.Errorf("embedded provider direct slot size %d != Go size %d", spec.Maps["trustix_kernel_crypto_direct_slots"].ValueSize, binary.Size(kernelCryptoDirectSlotValue{}))
	}
	for _, name := range []string{"trustix_kernel_crypto_install", "trustix_kernel_crypto_delete", "trustix_kernel_crypto_roundtrip_xdp", "trustix_kernel_crypto_frame_seal_xdp", "trustix_kernel_crypto_frame_open_xdp"} {
		if spec.Programs[name] == nil {
			return nil, fmt.Errorf("embedded provider ELF is missing program %q", name)
		}
	}
	coll, err := newBPFCollectionWithOptions(spec, cebpf.CollectionOptions{})
	if err != nil {
		return nil, fmt.Errorf("load embedded provider programs: %w", err)
	}
	defer func() {
		if err != nil {
			coll.Close()
		}
	}()
	provider = &kernelCryptoProviderObject{
		collection:     coll,
		commandMap:     coll.Maps["trustix_kernel_crypto_cmd_map"],
		flowIndexMap:   coll.Maps["trustix_kernel_crypto_flow_index_map"],
		contextSlots:   coll.Maps["trustix_kernel_crypto_ctx_slots"],
		directSlotMap:  coll.Maps["trustix_kernel_crypto_direct_slots"],
		roundTripMap:   coll.Maps["trustix_kernel_crypto_roundtrip_map"],
		frameMap:       coll.Maps["trustix_kernel_crypto_frame_map"],
		installProgram: coll.Programs["trustix_kernel_crypto_install"],
		deleteProgram:  coll.Programs["trustix_kernel_crypto_delete"],
		roundTripProg:  coll.Programs["trustix_kernel_crypto_roundtrip_xdp"],
		frameSealProg:  coll.Programs["trustix_kernel_crypto_frame_seal_xdp"],
		frameOpenProg:  coll.Programs["trustix_kernel_crypto_frame_open_xdp"],
	}
	if provider.commandMap == nil || provider.flowIndexMap == nil || provider.contextSlots == nil || provider.directSlotMap == nil || provider.roundTripMap == nil || provider.frameMap == nil || provider.installProgram == nil || provider.deleteProgram == nil || provider.roundTripProg == nil || provider.frameSealProg == nil || provider.frameOpenProg == nil {
		err = fmt.Errorf("embedded provider collection is incomplete")
		return nil, err
	}
	return provider, nil
}

func loadKernelCryptoDirectSlotProviderMaps() (*kernelCryptoProviderObject, error) {
	flowIndexMap, err := cebpf.NewMap(&cebpf.MapSpec{
		Name:       "trustix_kernel_crypto_flow_index_map",
		Type:       cebpf.Hash,
		KeySize:    uint32(binary.Size(kernelCryptoFlowKey{})),
		ValueSize:  uint32(binary.Size(uint32(0))),
		MaxEntries: kernelCryptoMaxEntries,
	})
	if err != nil {
		return nil, fmt.Errorf("create kernel crypto direct flow index map: %w", err)
	}
	contextSlots, err := cebpf.NewMap(&cebpf.MapSpec{
		Name:       "trustix_kernel_crypto_ctx_slots",
		Type:       cebpf.Array,
		KeySize:    uint32(binary.Size(uint32(0))),
		ValueSize:  kernelCryptoCtxSlotValueSize,
		MaxEntries: kernelCryptoMaxEntries,
	})
	if err != nil {
		_ = flowIndexMap.Close()
		return nil, fmt.Errorf("create kernel crypto placeholder ctx slot map: %w", err)
	}
	directSlotMap, err := cebpf.NewMap(&cebpf.MapSpec{
		Name:       "trustix_kernel_crypto_direct_slots",
		Type:       cebpf.Array,
		KeySize:    uint32(binary.Size(uint32(0))),
		ValueSize:  uint32(binary.Size(kernelCryptoDirectSlotValue{})),
		MaxEntries: kernelCryptoMaxEntries,
	})
	if err != nil {
		_ = contextSlots.Close()
		_ = flowIndexMap.Close()
		return nil, fmt.Errorf("create kernel crypto direct slot map: %w", err)
	}
	return &kernelCryptoProviderObject{
		flowIndexMap:  flowIndexMap,
		contextSlots:  contextSlots,
		directSlotMap: directSlotMap,
	}, nil
}

func (provider *kernelCryptoProviderObject) Install(entries []kernelCryptoFlowEntry) error {
	if provider == nil {
		return fmt.Errorf("experimental_tcp kernel crypto ctx provider is not loaded")
	}
	prepared := make([]kernelCryptoProviderInstallEntry, 0, len(entries))
	for i, entry := range entries {
		prepared = append(prepared, kernelCryptoProviderInstallEntry{Slot: uint32(i), Entry: entry})
	}
	return provider.InstallAt(prepared)
}

func (provider *kernelCryptoProviderObject) InstallAt(entries []kernelCryptoProviderInstallEntry) error {
	if provider == nil {
		return fmt.Errorf("experimental_tcp kernel crypto ctx provider is not loaded")
	}
	if len(entries) > int(kernelCryptoMaxEntries) {
		return fmt.Errorf("experimental_tcp kernel crypto ctx slot count %d exceeds capacity %d", len(entries), kernelCryptoMaxEntries)
	}
	for _, install := range entries {
		if install.Slot >= kernelCryptoMaxEntries {
			return fmt.Errorf("experimental_tcp kernel crypto ctx slot %d exceeds capacity %d", install.Slot, kernelCryptoMaxEntries)
		}
		if err := provider.clearDirectSlot(install.Slot); err != nil {
			return err
		}
		cmd := kernelCryptoCommand{Op: kernelCryptoCommandInstall, Slot: install.Slot, Key: install.Entry.Key, Value: install.Entry.Value}
		if err := provider.runCommand(provider.installProgram, &cmd); err != nil {
			zeroKernelCryptoCommand(&cmd)
			return err
		}
		zeroKernelCryptoCommand(&cmd)
	}
	return nil
}

func (provider *kernelCryptoProviderObject) RoundTrip(key kernelCryptoFlowKey) error {
	if provider == nil || provider.roundTripMap == nil || provider.roundTripProg == nil {
		return fmt.Errorf("experimental_tcp kernel crypto ctx provider roundtrip program is not loaded")
	}
	var scratch kernelCryptoRoundTripScratch
	scratch.Key = key
	for i := 0; i < kernelCryptoRoundTripPlainLen; i++ {
		scratch.Plain[i] = byte(0x40 + i)
	}
	for i := 0; i < kernelCryptoAESGCMIVLen; i++ {
		scratch.Nonce[i] = byte(0xa0 + i)
	}
	slot := uint32(0)
	if err := provider.roundTripMap.Update(slot, scratch, cebpf.UpdateAny); err != nil {
		return fmt.Errorf("stage experimental_tcp kernel crypto roundtrip scratch: %w", err)
	}
	ret, err := provider.roundTripProg.Run(&cebpf.RunOptions{Data: make([]byte, 64)})
	if err != nil {
		return fmt.Errorf("run experimental_tcp kernel crypto roundtrip: %w", err)
	}
	if ret == 0 {
		return fmt.Errorf("experimental_tcp kernel crypto roundtrip returned XDP_ABORTED")
	}
	if err := provider.roundTripMap.Lookup(slot, &scratch); err != nil {
		return fmt.Errorf("read experimental_tcp kernel crypto roundtrip scratch: %w", err)
	}
	if scratch.Result != 0 {
		return fmt.Errorf("experimental_tcp kernel crypto roundtrip result %d", scratch.Result)
	}
	for i := 0; i < kernelCryptoRoundTripPlainLen; i++ {
		if scratch.Out[i] != scratch.Plain[i] {
			return fmt.Errorf("experimental_tcp kernel crypto roundtrip plaintext mismatch at byte %d", i)
		}
	}
	if bytes.Equal(scratch.Cipher[:kernelCryptoRoundTripPlainLen], scratch.Plain[:kernelCryptoRoundTripPlainLen]) {
		return fmt.Errorf("experimental_tcp kernel crypto roundtrip ciphertext did not change")
	}
	_ = provider.roundTripMap.Update(slot, kernelCryptoRoundTripScratch{}, cebpf.UpdateAny)
	return nil
}

func (provider *kernelCryptoProviderObject) SealFrame(key kernelCryptoFlowKey, suiteID uint16, epoch uint64, sequence uint64, plaintext []byte) ([]byte, error) {
	if provider == nil || provider.frameMap == nil || provider.frameSealProg == nil {
		return nil, fmt.Errorf("experimental_tcp kernel crypto frame seal program is not loaded")
	}
	if suiteID == 0 || suiteID > 255 {
		return nil, fmt.Errorf("experimental_tcp kernel crypto frame suite id %d is invalid", suiteID)
	}
	if len(plaintext) > kernelCryptoFrameMaxPlain {
		return nil, fmt.Errorf("experimental_tcp kernel crypto frame plaintext size %d exceeds max %d", len(plaintext), kernelCryptoFrameMaxPlain)
	}
	if sequence == 0 {
		return nil, fmt.Errorf("experimental_tcp kernel crypto frame sequence is required")
	}
	var scratch kernelCryptoFrameScratch
	scratch.Key = key
	scratch.Epoch = epoch
	scratch.Sequence = sequence
	scratch.InLen = uint32(len(plaintext))
	copy(scratch.In[:], plaintext)
	if err := provider.frameMap.Update(uint32(0), scratch, cebpf.UpdateAny); err != nil {
		return nil, fmt.Errorf("stage experimental_tcp kernel crypto frame seal: %w", err)
	}
	if err := provider.runFrameProgram(provider.frameSealProg); err != nil {
		provider.clearFrameSlot()
		return nil, err
	}
	if err := provider.frameMap.Lookup(uint32(0), &scratch); err != nil {
		provider.clearFrameSlot()
		return nil, fmt.Errorf("read experimental_tcp kernel crypto frame seal: %w", err)
	}
	if scratch.Result != 0 {
		provider.clearFrameSlot()
		return nil, fmt.Errorf("experimental_tcp kernel crypto frame seal returned %d", scratch.Result)
	}
	if scratch.OutLen == 0 || scratch.OutLen > kernelCryptoFrameMaxWire {
		provider.clearFrameSlot()
		return nil, fmt.Errorf("experimental_tcp kernel crypto frame seal output length %d is invalid", scratch.OutLen)
	}
	payload := make([]byte, kernelCryptoSecureHeaderLen+int(scratch.OutLen))
	kernelCryptoPutSecureHeader(payload[:kernelCryptoSecureHeaderLen], byte(suiteID), epoch, sequence)
	copy(payload[kernelCryptoSecureHeaderLen:], scratch.Out[:scratch.OutLen])
	provider.clearFrameSlot()
	return payload, nil
}

func (provider *kernelCryptoProviderObject) OpenFrame(key kernelCryptoFlowKey, suiteID uint16, epoch uint64, sequence uint64, payload []byte) ([]byte, error) {
	if provider == nil || provider.frameMap == nil || provider.frameOpenProg == nil {
		return nil, fmt.Errorf("experimental_tcp kernel crypto frame open program is not loaded")
	}
	if suiteID == 0 || suiteID > 255 {
		return nil, fmt.Errorf("experimental_tcp kernel crypto frame suite id %d is invalid", suiteID)
	}
	ciphertext, err := kernelCryptoParseSecureFrame(payload, byte(suiteID), epoch, sequence)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) > kernelCryptoFrameMaxWire {
		return nil, fmt.Errorf("experimental_tcp kernel crypto frame ciphertext size %d exceeds max %d", len(ciphertext), kernelCryptoFrameMaxWire)
	}
	var scratch kernelCryptoFrameScratch
	scratch.Key = key
	scratch.Epoch = epoch
	scratch.Sequence = sequence
	scratch.InLen = uint32(len(ciphertext))
	copy(scratch.In[:], ciphertext)
	if err := provider.frameMap.Update(uint32(0), scratch, cebpf.UpdateAny); err != nil {
		return nil, fmt.Errorf("stage experimental_tcp kernel crypto frame open: %w", err)
	}
	if err := provider.runFrameProgram(provider.frameOpenProg); err != nil {
		provider.clearFrameSlot()
		return nil, err
	}
	if err := provider.frameMap.Lookup(uint32(0), &scratch); err != nil {
		provider.clearFrameSlot()
		return nil, fmt.Errorf("read experimental_tcp kernel crypto frame open: %w", err)
	}
	if scratch.Result != 0 {
		provider.clearFrameSlot()
		return nil, fmt.Errorf("experimental_tcp kernel crypto frame open returned %d", scratch.Result)
	}
	if scratch.OutLen > kernelCryptoFrameMaxPlain {
		provider.clearFrameSlot()
		return nil, fmt.Errorf("experimental_tcp kernel crypto frame open output length %d is invalid", scratch.OutLen)
	}
	plaintext := make([]byte, int(scratch.OutLen))
	copy(plaintext, scratch.Out[:scratch.OutLen])
	provider.clearFrameSlot()
	return plaintext, nil
}

func (provider *kernelCryptoProviderObject) DeleteFlow(flowID uint64) error {
	if provider == nil || flowID == 0 {
		return nil
	}
	return provider.DeleteKeys([]kernelCryptoFlowKey{
		kernelCryptoFlowKeyFor(kernelCryptoNamespaceExperimentalTCP, flowID, kernelCryptoDirectionSend),
		kernelCryptoFlowKeyFor(kernelCryptoNamespaceExperimentalTCP, flowID, kernelCryptoDirectionRecv),
	})
}

func (provider *kernelCryptoProviderObject) DeleteKeys(keys []kernelCryptoFlowKey) error {
	if provider == nil || len(keys) == 0 {
		return nil
	}
	var err error
	for _, key := range keys {
		if key.FlowID == 0 {
			continue
		}
		var slot uint32
		if provider.flowIndexMap != nil {
			if lookupErr := provider.flowIndexMap.Lookup(key, &slot); lookupErr == nil {
				if clearErr := provider.clearDirectSlot(slot); clearErr != nil {
					err = errors.Join(err, clearErr)
				}
			}
		}
		if provider.deleteProgram != nil && provider.commandMap != nil {
			cmd := kernelCryptoCommand{
				Op:  kernelCryptoCommandDelete,
				Key: key,
			}
			if commandErr := provider.runCommand(provider.deleteProgram, &cmd); commandErr != nil {
				err = errors.Join(err, commandErr)
			}
			zeroKernelCryptoCommand(&cmd)
		} else if provider.flowIndexMap != nil {
			if deleteErr := provider.flowIndexMap.Delete(key); deleteErr != nil && !errors.Is(deleteErr, cebpf.ErrKeyNotExist) {
				err = errors.Join(err, deleteErr)
			}
		}
	}
	return err
}

func (provider *kernelCryptoProviderObject) lookupCtxSlot(slot uint32) (kernelCryptoCtxSlotValue, error) {
	if provider == nil || provider.contextSlots == nil {
		return kernelCryptoCtxSlotValue{}, fmt.Errorf("kernel crypto ctx slot map is not loaded")
	}
	var value kernelCryptoCtxSlotValue
	if err := provider.contextSlots.Lookup(slot, &value); err != nil {
		return kernelCryptoCtxSlotValue{}, err
	}
	return value, nil
}

func installKernelCryptoDirectSlot(install kernelCryptoProviderInstallEntry) (bool, uint32, error) {
	entry := install.Entry
	if entry.Value.Suite != kernelCryptoSuiteIDTrustIXAES256GCMX25519 &&
		entry.Value.Suite != kernelCryptoSuiteIDTrustIXAES128GCMX25519 {
		return false, 0, nil
	}
	if entry.Value.KeyLen != kernelCryptoAES128KeyLen && entry.Value.KeyLen != kernelCryptoAES256KeyLen {
		return false, 0, nil
	}
	key := entry.Value.Key[:entry.Value.KeyLen]
	open := entry.Key.Direction == kernelCryptoDirectionRecv
	directSlot, err := kernelmodule.AEADDirectSetKeyAlloc("", kernelmodule.TrustIXAEADDirectAnySlot, key, open)
	if err != nil {
		return false, 0, fmt.Errorf("install TrustIX AEAD direct slot for ctx slot %d: %w", install.Slot, err)
	}
	return true, directSlot, nil
}

func (provider *kernelCryptoProviderObject) publishDirectSlot(install kernelCryptoProviderInstallEntry, directSlot uint32) error {
	if provider == nil || provider.directSlotMap == nil {
		return fmt.Errorf("kernel crypto direct slot map is not loaded")
	}
	if directSlot >= kernelmodule.TrustIXAEADDirectMaxSlots {
		return fmt.Errorf("TrustIX AEAD direct slot %d exceeds max %d", directSlot, kernelmodule.TrustIXAEADDirectMaxSlots)
	}
	value := kernelCryptoDirectSlotValue{
		SlotID:        directSlot,
		Enabled:       1,
		Suite:         install.Entry.Value.Suite,
		WireFormat:    install.Entry.Value.WireFormat,
		Flags:         install.Entry.Value.Flags,
		Epoch:         install.Entry.Value.Epoch,
		IV:            install.Entry.Value.IV,
		ReplayWindow:  install.Entry.Value.ReplayWindow,
		InstalledUnix: install.Entry.Value.InstalledUnix,
	}
	if err := provider.directSlotMap.Update(install.Slot, value, cebpf.UpdateAny); err != nil {
		return fmt.Errorf("update direct slot %d: %w", install.Slot, err)
	}
	return nil
}

func (provider *kernelCryptoProviderObject) clearDirectSlot(slot uint32) error {
	if provider == nil || provider.directSlotMap == nil {
		return nil
	}
	var existing kernelCryptoDirectSlotValue
	if err := provider.directSlotMap.Lookup(slot, &existing); err == nil && existing.Enabled != 0 &&
		existing.SlotID < kernelmodule.TrustIXAEADDirectMaxSlots {
		_ = kernelmodule.AEADDirectClearKey("", existing.SlotID)
	}
	if err := provider.directSlotMap.Update(slot, kernelCryptoDirectSlotValue{}, cebpf.UpdateAny); err != nil {
		return fmt.Errorf("clear direct slot %d: %w", slot, err)
	}
	return nil
}

func (provider *kernelCryptoProviderObject) Close() error {
	if provider == nil {
		return nil
	}
	var err error
	if provider.collection != nil {
		provider.collection.Close()
	} else {
		if provider.commandMap != nil {
			err = errors.Join(err, provider.commandMap.Close())
		}
		if provider.flowIndexMap != nil {
			err = errors.Join(err, provider.flowIndexMap.Close())
		}
		if provider.contextSlots != nil {
			err = errors.Join(err, provider.contextSlots.Close())
		}
		if provider.directSlotMap != nil {
			err = errors.Join(err, provider.directSlotMap.Close())
		}
		if provider.roundTripMap != nil {
			err = errors.Join(err, provider.roundTripMap.Close())
		}
		if provider.frameMap != nil {
			err = errors.Join(err, provider.frameMap.Close())
		}
	}
	provider.collection = nil
	provider.commandMap = nil
	provider.flowIndexMap = nil
	provider.contextSlots = nil
	provider.directSlotMap = nil
	provider.roundTripMap = nil
	provider.frameMap = nil
	provider.installProgram = nil
	provider.deleteProgram = nil
	provider.roundTripProg = nil
	provider.frameSealProg = nil
	provider.frameOpenProg = nil
	return err
}

func (provider *kernelCryptoProviderObject) runCommand(program *cebpf.Program, cmd *kernelCryptoCommand) error {
	if provider.commandMap == nil || program == nil {
		return fmt.Errorf("experimental_tcp kernel crypto ctx provider is incomplete")
	}
	slot := uint32(0)
	if err := provider.commandMap.Update(slot, *cmd, cebpf.UpdateAny); err != nil {
		return fmt.Errorf("stage experimental_tcp kernel crypto command: %w", err)
	}
	defer provider.clearCommandSlot(slot)
	ret, err := program.Run(&cebpf.RunOptions{Context: uint64(0)})
	if err != nil {
		return fmt.Errorf("run experimental_tcp kernel crypto command: %w", err)
	}
	var out kernelCryptoCommand
	if lookupErr := provider.commandMap.Lookup(slot, &out); lookupErr == nil && out.Result != 0 {
		return fmt.Errorf("experimental_tcp kernel crypto command returned %d", out.Result)
	}
	if ret != 0 {
		return fmt.Errorf("experimental_tcp kernel crypto command returned %d", int32(ret))
	}
	return nil
}

func (provider *kernelCryptoProviderObject) clearCommandSlot(slot uint32) {
	if provider == nil || provider.commandMap == nil {
		return
	}
	_ = provider.commandMap.Update(slot, kernelCryptoCommand{}, cebpf.UpdateAny)
}

func (provider *kernelCryptoProviderObject) runFrameProgram(program *cebpf.Program) error {
	if program == nil {
		return fmt.Errorf("experimental_tcp kernel crypto frame program is incomplete")
	}
	ret, err := program.Run(&cebpf.RunOptions{Data: make([]byte, 64)})
	if err != nil {
		return fmt.Errorf("run experimental_tcp kernel crypto frame program: %w", err)
	}
	if ret == 0 {
		return fmt.Errorf("experimental_tcp kernel crypto frame program returned XDP_ABORTED")
	}
	return nil
}

func (provider *kernelCryptoProviderObject) clearFrameSlot() {
	if provider == nil || provider.frameMap == nil {
		return
	}
	_ = provider.frameMap.Update(uint32(0), kernelCryptoFrameScratch{}, cebpf.UpdateAny)
}

func zeroKernelCryptoCommand(cmd *kernelCryptoCommand) {
	if cmd != nil {
		*cmd = kernelCryptoCommand{}
	}
}

var kernelCryptoSecureMagic = [4]byte{'T', 'I', 'X', 'D'}

func kernelCryptoPutSecureHeader(header []byte, suite byte, epoch uint64, sequence uint64) {
	copy(header[0:4], kernelCryptoSecureMagic[:])
	header[4] = kernelCryptoSecureVersion
	header[5] = suite
	binary.BigEndian.PutUint64(header[8:16], epoch)
	binary.BigEndian.PutUint64(header[16:24], sequence)
}

func kernelCryptoParseSecureFrame(payload []byte, suite byte, epoch uint64, sequence uint64) ([]byte, error) {
	if len(payload) < kernelCryptoSecureHeaderLen+kernelCryptoFrameTagLen {
		return nil, fmt.Errorf("experimental_tcp kernel crypto frame too short: %d", len(payload))
	}
	header := payload[:kernelCryptoSecureHeaderLen]
	if !bytes.Equal(header[0:4], kernelCryptoSecureMagic[:]) || header[4] != kernelCryptoSecureVersion || header[5] != suite {
		return nil, fmt.Errorf("experimental_tcp kernel crypto frame secure header is invalid")
	}
	headerEpoch := binary.BigEndian.Uint64(header[8:16])
	if headerEpoch != epoch {
		return nil, fmt.Errorf("experimental_tcp kernel crypto frame epoch %d != outer epoch %d", headerEpoch, epoch)
	}
	headerSequence := binary.BigEndian.Uint64(header[16:24])
	if headerSequence != sequence {
		return nil, fmt.Errorf("experimental_tcp kernel crypto frame sequence %d != outer sequence %d", headerSequence, sequence)
	}
	return payload[kernelCryptoSecureHeaderLen:], nil
}

func kernelCryptoSecureFrameMetadata(payload []byte, sequence uint64) (uint16, string, uint64, error) {
	if len(payload) < kernelCryptoSecureHeaderLen+kernelCryptoFrameTagLen {
		return 0, "", 0, fmt.Errorf("kernel crypto frame too short: %d", len(payload))
	}
	header := payload[:kernelCryptoSecureHeaderLen]
	if !bytes.Equal(header[0:4], kernelCryptoSecureMagic[:]) || header[4] != kernelCryptoSecureVersion {
		return 0, "", 0, fmt.Errorf("kernel crypto frame secure header is invalid")
	}
	headerSequence := binary.BigEndian.Uint64(header[16:24])
	if headerSequence != sequence {
		return 0, "", 0, fmt.Errorf("kernel crypto frame sequence %d != outer sequence %d", headerSequence, sequence)
	}
	suiteID := uint16(header[5])
	switch suiteID {
	case kernelCryptoSuiteIDTrustIXAES256GCMX25519:
		return suiteID, kernelCryptoSuiteAES256GCMX25519, binary.BigEndian.Uint64(header[8:16]), nil
	case kernelCryptoSuiteIDTrustIXAES128GCMX25519:
		return suiteID, kernelCryptoSuiteAES128GCMX25519, binary.BigEndian.Uint64(header[8:16]), nil
	case kernelCryptoSuiteIDTrustIXChaCha20Poly1305:
		return 0, "", 0, fmt.Errorf(kernelCryptoChacha20Poly1305UnsupportedReason)
	default:
		return 0, "", 0, fmt.Errorf("kernel crypto frame suite id %d is not in the kernel provider schema", suiteID)
	}
}

func (manager *Manager) probeKernelCryptoAEADCreateLocked() {
	if manager.kernelCryptoProvider == nil {
		return
	}
	manager.kernelCryptoAEADCreateAttempts++
	entries, err := encodeKernelCryptoSpec(kernelCryptoSyntheticProbeSpec())
	var probeKey kernelCryptoFlowKey
	if len(entries) > 0 {
		probeKey = entries[0].Key
	}
	if err == nil {
		err = manager.kernelCryptoProvider.Install(entries)
	}
	zeroKernelCryptoEntries(entries)
	if err != nil {
		manager.kernelCryptoAEADCreateErrors++
		manager.warnings = append(manager.warnings, "experimental_tcp kernel AEAD-GCM ctx create unavailable: "+summarizeKernelCryptoProviderError(err))
		return
	}
	manager.kernelCryptoAEADCreateSuccesses++
	defer manager.kernelCryptoProvider.DeleteFlow(kernelCryptoSyntheticProbeFlowID)
	manager.kernelCryptoAEADRoundTripAttempts++
	if err := manager.kernelCryptoProvider.RoundTrip(probeKey); err != nil {
		manager.kernelCryptoAEADRoundTripErrors++
		manager.warnings = append(manager.warnings, "experimental_tcp kernel AEAD-GCM roundtrip unavailable: "+summarizeKernelCryptoProviderError(err))
		return
	}
	manager.kernelCryptoAEADRoundTripSuccesses++
}

const kernelCryptoSyntheticProbeFlowID uint64 = ^uint64(0) - 0x7158

func kernelCryptoSyntheticProbeSpec() dataplane.ExperimentalTCPCryptoSpec {
	return dataplane.ExperimentalTCPCryptoSpec{
		FlowID:       kernelCryptoSyntheticProbeFlowID,
		Suite:        kernelCryptoSuiteAES256GCMX25519,
		WireFormat:   kernelCryptoWireFormatTrustIXSecureDataV1,
		Epoch:        1,
		SendKey:      bytesOfValue(0xa5, kernelCryptoAES256KeyLen),
		SendIV:       bytesOfValue(0x5a, kernelCryptoAESGCMIVLen),
		RecvKey:      bytesOfValue(0x3c, kernelCryptoAES256KeyLen),
		RecvIV:       bytesOfValue(0xc3, kernelCryptoAESGCMIVLen),
		ReplayWindow: 64,
	}
}

func bytesOfValue(value byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = value
	}
	return out
}

func summarizeKernelCryptoProviderError(err error) string {
	if err == nil {
		return ""
	}
	var verifier *cebpf.VerifierError
	var reason string
	if errors.As(err, &verifier) {
		reason = fmt.Sprintf("%+v", verifier)
	} else {
		reason = err.Error()
	}
	reason = strings.Join(strings.Fields(reason), " ")
	if len(reason) > kernelCryptoProviderMaxReason {
		reason = reason[:kernelCryptoProviderMaxReason] + "..."
	}
	return reason
}

func (manager *Manager) addCapabilityLocked(capability string) {
	for _, existing := range manager.capabilities {
		if existing == capability {
			return
		}
	}
	manager.capabilities = append(manager.capabilities, capability)
}
