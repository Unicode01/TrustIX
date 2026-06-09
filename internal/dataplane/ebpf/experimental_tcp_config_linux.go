//go:build linux

package ebpf

import (
	"fmt"
	"os"
	"strings"

	cebpf "github.com/cilium/ebpf"
)

const experimentalTCPConfigSkipTCPChecksum uint32 = 1 << 0
const experimentalTCPConfigKernelUDPTCRXDirect uint32 = 1 << 1
const experimentalTCPConfigKernelUDPXDPOpen uint32 = 1 << 2
const experimentalTCPConfigKernelUDPXDPPassOpened uint32 = 1 << 3
const experimentalTCPConfigHotPathStats uint32 = 1 << 4
const experimentalTCPConfigKernelUDPXDPRXDirect uint32 = 1 << 5
const experimentalTCPConfigKernelUDPXDPRXDirectIfindex uint32 = 1 << 6
const experimentalTCPConfigKernelUDPTCRXSecureDirect uint32 = 1 << 7
const experimentalTCPConfigKernelUDPXDPRXSecureDirect uint32 = 1 << 8
const experimentalTCPConfigKernelUDPXDPRXDirectFixedL2 uint32 = 1 << 9
const experimentalTCPConfigXDPFallbackPass uint32 = 1 << 10
const experimentalTCPConfigKernelUDPXDPRXDirectTrustInnerChecksum uint32 = 1 << 11
const experimentalTCPConfigQueueCountShift = 16

func experimentalTCPBPFConfigValue(queueCount int, kernelUDPTCRXDirect bool) uint32 {
	return experimentalTCPBPFConfigValueFor(queueCount, kernelUDPTCRXDirect, false, false)
}

func experimentalTCPBPFConfigValueFor(queueCount int, kernelUDPTCRXDirect bool, kernelUDPXDPRXDirect bool, kernelUDPTCRXSecureDirect bool) uint32 {
	return experimentalTCPBPFConfigValueForOptions(queueCount, kernelUDPTCRXDirect, kernelUDPXDPRXDirect, kernelUDPTCRXSecureDirect, experimentalTCPBPFConfigOptions{})
}

type experimentalTCPBPFConfigOptions struct {
	ForcePassOpened         bool
	XDPRXSecureDirect       bool
	XDPFallbackPass         bool
	XDPRXTrustInnerChecksum bool
}

func experimentalTCPBPFConfigValueForOptions(queueCount int, kernelUDPTCRXDirect bool, kernelUDPXDPRXDirect bool, kernelUDPTCRXSecureDirect bool, options experimentalTCPBPFConfigOptions) uint32 {
	var config uint32
	if experimentalTCPSkipTCPChecksum() {
		config |= experimentalTCPConfigSkipTCPChecksum
	}
	if experimentalTCPHotPathStats() {
		config |= experimentalTCPConfigHotPathStats
	}
	if kernelUDPTCRXDirect {
		config |= experimentalTCPConfigKernelUDPTCRXDirect
	}
	if kernelUDPTCRXSecureDirect {
		config |= experimentalTCPConfigKernelUDPTCRXSecureDirect
	}
	if kernelUDPXDPRXDirect {
		config |= experimentalTCPConfigKernelUDPXDPRXDirect
		if kernelUDPXDPRXDirectIfindexEnabled() {
			config |= experimentalTCPConfigKernelUDPXDPRXDirectIfindex
		}
		if kernelUDPXDPRXDirectFixedL2Enabled() {
			config |= experimentalTCPConfigKernelUDPXDPRXDirectFixedL2
		}
		if kernelUDPTCRXSecureDirect && options.XDPRXSecureDirect {
			config |= experimentalTCPConfigKernelUDPXDPRXSecureDirect
		}
		if kernelUDPXDPRXDirectTrustInnerChecksumEnabled() || options.XDPRXTrustInnerChecksum {
			config |= experimentalTCPConfigKernelUDPXDPRXDirectTrustInnerChecksum
		}
	}
	if kernelUDPXDPOpen() {
		config |= experimentalTCPConfigKernelUDPXDPOpen
		if kernelUDPTCRXDirect && (options.ForcePassOpened || kernelUDPXDPPassOpened()) {
			config |= experimentalTCPConfigKernelUDPXDPPassOpened
		}
	}
	if options.XDPFallbackPass {
		config |= experimentalTCPConfigXDPFallbackPass
	}
	if queueCount > 0 {
		if queueCount > 0xffff {
			queueCount = 0xffff
		}
		config |= uint32(queueCount) << experimentalTCPConfigQueueCountShift
	}
	return config
}

func kernelUDPXDPOpen() bool {
	return envTruthy(
		"TRUSTIX_KERNEL_UDP_XDP_OPEN",
		"TRUSTIX_KERNEL_UDP_XDP_CRYPTO",
	)
}

func experimentalTCPXDPDirectOpenKfuncEnabled() bool {
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_XDP_DIRECT_OPEN_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_XDP_KFUNC_OPEN",
	)
}

func kernelUDPXDPPassOpened() bool {
	return envTruthy("TRUSTIX_KERNEL_UDP_XDP_PASS_OPENED")
}

func kernelUDPXDPRXDirectEnabled() bool {
	return envTruthy(
		"TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT",
		"TRUSTIX_KERNEL_UDP_XDP_DEVMAP_DIRECT",
	)
}

func kernelUDPXDPRXSecureDirectEnabled() bool {
	return envTruthy(
		"TRUSTIX_KERNEL_UDP_XDP_RX_SECURE_DIRECT",
		"TRUSTIX_KERNEL_UDP_XDP_SECURE_DIRECT",
	)
}

func kernelUDPXDPRXDirectIfindexEnabled() bool {
	if envTruthy("TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_IFINDEX") {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_MODE"))) {
	case "ifindex", "redirect", "direct":
		return true
	default:
		return false
	}
}

func kernelUDPXDPRXDirectFixedL2Enabled() bool {
	if envTruthy("TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_FIXED_L2") {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_MODE"))) {
	case "fixed_l2", "fixed-l2", "fixed", "broadcast":
		return true
	default:
		return false
	}
}

func kernelUDPXDPRXDirectTrustInnerChecksumEnabled() bool {
	return envTruthy(
		"TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_TRUST_INNER_CHECKSUM",
		"TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_TRUST_INNER_CHECKSUMS",
		"TRUSTIX_KERNEL_UDP_XDP_RX_TRUST_INNER_CHECKSUM",
		"TRUSTIX_KERNEL_UDP_XDP_RX_TRUST_INNER_CHECKSUMS",
	)
}

func kernelDatapathRXXDPPassEnabled() bool {
	if envFalsey(
		"TRUSTIX_KERNEL_DATAPATH_RX_XDP_PASS",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XDP_PASS",
	) {
		return false
	}
	if !kernelDatapathRXWorkerCrashRiskAllowed() {
		return false
	}
	return envTruthy(
		"TRUSTIX_KERNEL_DATAPATH_RX_XDP_PASS",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XDP_PASS",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER",
	)
}

func kernelDatapathRXWorkerOwnsStackRX() bool {
	return kernelDatapathRXXDPPassEnabled()
}

func kernelDatapathRXWorkerCrashRiskAllowed() bool {
	return envTruthy(
		"TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER",
		"TRUSTIX_KERNEL_DATAPATH_ALLOW_UNSAFE_RX_WORKER",
		"TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT",
		"TRUSTIX_KERNEL_DATAPATH_ALLOW_UNSAFE_FULL_PLAINTEXT",
	)
}

func configureExperimentalTCPBPFConfig(m *cebpf.Map, queueCount int) (uint32, error) {
	return configureExperimentalTCPBPFConfigValue(m, queueCount, false)
}

func configureExperimentalTCPBPFConfigValue(m *cebpf.Map, queueCount int, kernelUDPTCRXDirect bool) (uint32, error) {
	return configureExperimentalTCPBPFConfigValueFor(m, queueCount, kernelUDPTCRXDirect, false, false)
}

func configureExperimentalTCPBPFConfigValueFor(m *cebpf.Map, queueCount int, kernelUDPTCRXDirect bool, kernelUDPXDPRXDirect bool, kernelUDPTCRXSecureDirect bool) (uint32, error) {
	return configureExperimentalTCPBPFConfigValueForOptions(m, queueCount, kernelUDPTCRXDirect, kernelUDPXDPRXDirect, kernelUDPTCRXSecureDirect, experimentalTCPBPFConfigOptions{})
}

func configureExperimentalTCPBPFConfigValueForOptions(m *cebpf.Map, queueCount int, kernelUDPTCRXDirect bool, kernelUDPXDPRXDirect bool, kernelUDPTCRXSecureDirect bool, options experimentalTCPBPFConfigOptions) (uint32, error) {
	config := experimentalTCPBPFConfigValueForOptions(queueCount, kernelUDPTCRXDirect, kernelUDPXDPRXDirect, kernelUDPTCRXSecureDirect, options)
	if m == nil {
		return config, nil
	}
	key := uint32(0)
	if err := m.Update(key, config, cebpf.UpdateAny); err != nil {
		return 0, fmt.Errorf("configure experimental_tcp BPF config: %w", err)
	}
	return config, nil
}

func experimentalTCPSkipTCPChecksum() bool {
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_SKIP_TCP_CHECKSUM",
		"TRUSTIX_EXPERIMENTAL_TCP_SKIP_OUTER_TCP_CHECKSUM",
		"TRUSTIX_EXPERIMENTAL_TCP_SKIP_CHECKSUM",
	)
}

func kernelUDPSkipUDPChecksum() bool {
	return envTruthy(
		"TRUSTIX_KERNEL_UDP_SKIP_UDP_CHECKSUM",
		"TRUSTIX_KERNEL_UDP_NO_CHECKSUM",
	)
}

func experimentalTCPHotPathStats() bool {
	return envTruthy(
		"TRUSTIX_EXPERIMENTAL_TCP_HOT_STATS",
		"TRUSTIX_XDP_HOT_STATS",
		"TRUSTIX_KERNEL_UDP_XDP_HOT_STATS",
		"TRUSTIX_KERNEL_UDP_TC_HOT_STATS",
		"TRUSTIX_KERNEL_UDP_HOT_STATS",
		"TRUSTIX_TC_HOT_STATS",
	)
}

func envTruthy(names ...string) bool {
	for _, name := range names {
		switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
		case "1", "true", "yes", "on", "enabled":
			return true
		}
	}
	return false
}

func envFalsey(names ...string) bool {
	for _, name := range names {
		switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
		case "0", "false", "no", "off", "disabled":
			return true
		}
	}
	return false
}
