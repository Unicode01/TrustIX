//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"os"

	"trustix.local/trustix/internal/dataplane"
)

func (manager *Manager) refreshKernelCryptoProbeLocked() {
	probe := probeKernelCryptoCapability()
	manager.kernelCryptoProbe = probe
	manager.kernelCryptoProbeValid = true
	manager.capabilities = append(manager.capabilities, "tix-tcp-kernel-crypto-probe")
	if probe.CapabilityReady {
		manager.capabilities = append(manager.capabilities, "tix-tcp-kernel-crypto-capable")
	}
	if probe.SelfTest != nil && probe.SelfTest.Passed {
		manager.capabilities = append(manager.capabilities, "tix-tcp-kernel-crypto-verifier-ok")
	}
	if probe.AESNI {
		manager.capabilities = append(manager.capabilities, "aes-ni")
	}
	if probe.AESGCMSoftware {
		manager.capabilities = append(manager.capabilities, "aes-gcm-software-fallback")
	}
	if !probe.CapabilityReady && probe.Reason != "" {
		manager.warnings = append(manager.warnings, "tix_tcp kernel crypto capability unavailable: "+probe.Reason)
	}
	if probe.SelfTest != nil && probe.SelfTest.Attempted && !probe.SelfTest.Passed && probe.SelfTest.Reason != "" {
		manager.warnings = append(manager.warnings, "tix_tcp kernel crypto verifier selftest failed: "+probe.SelfTest.Reason)
	}
}

func (manager *Manager) kernelCryptoProbeSnapshotLocked() dataplane.KernelCryptoProbe {
	if !manager.kernelCryptoProbeValid {
		return unprobedKernelCryptoProbe()
	}
	probe := cloneKernelCryptoProbe(manager.kernelCryptoProbe)
	if manager.kernelCryptoProductionReadyLocked() {
		probe.ProviderReady = true
		probe.Reason = kernelCryptoProbeReason(probe, "", "")
	}
	return probe
}

func (manager *Manager) kernelCryptoUnavailableReasonLocked() string {
	return kernelCryptoUnavailableReason(manager.kernelCryptoProbeSnapshotLocked())
}

func probeKernelCryptoCapability() dataplane.KernelCryptoProbe {
	probe := baseKernelCryptoProbe()
	var btfErr string
	btfPayload, _, err := readKernelCryptoProbeBTF()
	if err != nil {
		btfErr = err.Error()
	} else {
		probe.KernelBTF = true
		missing, err := missingKernelCryptoKfuncsFromBTF(btfPayload, kernelCryptoRequiredKfuncs)
		if err != nil {
			btfErr = err.Error()
			probe.KernelBTF = false
		} else {
			probe.MissingKfuncs = missing
			probe.CryptoKfuncs = len(probe.MissingKfuncs) == 0
		}
		btfPayload = nil
	}

	var procCryptoErr string
	cryptoPayload, err := os.ReadFile("/proc/crypto")
	if err != nil {
		procCryptoErr = err.Error()
	} else {
		cpuPayload, _ := os.ReadFile("/proc/cpuinfo")
		probe.AESGCM, probe.AESNI, probe.AESGCMSoftware, probe.CryptoAlgorithms = summarizeKernelCryptoAlgorithms(parseProcCrypto(cryptoPayload), cpuPayload)
		cryptoPayload = nil
		cpuPayload = nil
	}

	probe.CapabilityReady = probe.KernelBTF && probe.CryptoKfuncs && probe.AESGCM
	probe.ProviderReady = false
	probe.SelfTest = probeKernelCryptoVerifierSelfTest(probe)
	probe.MapSchema = kernelCryptoMapSchema()
	if reason := kernelCryptoProbeReason(probe, btfErr, procCryptoErr); reason != "" {
		probe.Reason = reason
	}
	return cloneKernelCryptoProbe(probe)
}

func readKernelCryptoProbeBTF() ([]byte, string, error) {
	var firstErr error
	for _, path := range configuredBTFPaths(os.Getenv(bpfKernelBTFEnv)) {
		payload, err := os.ReadFile(path)
		if err == nil {
			return payload, path, nil
		}
		if firstErr == nil || configuredBTFStrict(bpfBTFStrictKernelEnv) || !errors.Is(err, os.ErrNotExist) {
			firstErr = fmt.Errorf("read %s entry %q: %w", bpfKernelBTFEnv, path, err)
		}
		if configuredBTFStrict(bpfBTFStrictKernelEnv) || !errors.Is(err, os.ErrNotExist) {
			return nil, "", firstErr
		}
	}
	payload, err := os.ReadFile("/sys/kernel/btf/vmlinux")
	if err == nil {
		return payload, "/sys/kernel/btf/vmlinux", nil
	}
	if firstErr != nil {
		return nil, "", fmt.Errorf("%v; fallback /sys/kernel/btf/vmlinux: %w", firstErr, err)
	}
	return nil, "", err
}
