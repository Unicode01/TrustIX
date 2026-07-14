//go:build linux

package ebpf

import (
	"fmt"
	"os"
	"strings"

	cebpf "github.com/cilium/ebpf"
)

const tixTCPConfigSkipTCPChecksum uint32 = 1 << 0
const tixTCPConfigKernelUDPTCRXDirect uint32 = 1 << 1
const tixTCPConfigKernelUDPXDPOpen uint32 = 1 << 2
const tixTCPConfigKernelUDPXDPPassOpened uint32 = 1 << 3
const tixTCPConfigHotPathStats uint32 = 1 << 4
const tixTCPConfigKernelUDPXDPRXDirect uint32 = 1 << 5
const tixTCPConfigKernelUDPXDPRXDirectIfindex uint32 = 1 << 6
const tixTCPConfigKernelUDPTCRXSecureDirect uint32 = 1 << 7
const tixTCPConfigKernelUDPXDPRXSecureDirect uint32 = 1 << 8
const tixTCPConfigKernelUDPXDPRXDirectFixedL2 uint32 = 1 << 9
const tixTCPConfigXDPFallbackPass uint32 = 1 << 10
const tixTCPConfigKernelUDPXDPRXDirectTrustInnerChecksum uint32 = 1 << 11
const tixTCPConfigQueueCountShift = 16

func tixTCPBPFConfigValue(queueCount int, kernelUDPTCRXDirect bool) uint32 {
	return tixTCPBPFConfigValueFor(queueCount, kernelUDPTCRXDirect, false, false)
}

func tixTCPBPFConfigValueFor(queueCount int, kernelUDPTCRXDirect bool, kernelUDPXDPRXDirect bool, kernelUDPTCRXSecureDirect bool) uint32 {
	return tixTCPBPFConfigValueForOptions(queueCount, kernelUDPTCRXDirect, kernelUDPXDPRXDirect, kernelUDPTCRXSecureDirect, tixTCPBPFConfigOptions{})
}

type tixTCPBPFConfigOptions struct {
	ForcePassOpened         bool
	XDPRXSecureDirect       bool
	XDPFallbackPass         bool
	XDPRXTrustInnerChecksum bool
}

func tixTCPBPFConfigValueForOptions(queueCount int, kernelUDPTCRXDirect bool, kernelUDPXDPRXDirect bool, kernelUDPTCRXSecureDirect bool, options tixTCPBPFConfigOptions) uint32 {
	var config uint32
	if tixTCPSkipTCPChecksum() {
		config |= tixTCPConfigSkipTCPChecksum
	}
	if tixTCPHotPathStats() {
		config |= tixTCPConfigHotPathStats
	}
	if kernelUDPTCRXDirect {
		config |= tixTCPConfigKernelUDPTCRXDirect
	}
	if kernelUDPTCRXSecureDirect {
		config |= tixTCPConfigKernelUDPTCRXSecureDirect
	}
	if kernelUDPXDPRXDirect {
		config |= tixTCPConfigKernelUDPXDPRXDirect
		if kernelUDPXDPRXDirectIfindexEnabled() {
			config |= tixTCPConfigKernelUDPXDPRXDirectIfindex
		}
		if kernelUDPXDPRXDirectFixedL2Enabled() {
			config |= tixTCPConfigKernelUDPXDPRXDirectFixedL2
		}
		if kernelUDPTCRXSecureDirect && options.XDPRXSecureDirect {
			config |= tixTCPConfigKernelUDPXDPRXSecureDirect
		}
		if kernelUDPXDPRXDirectTrustInnerChecksumEnabled() || options.XDPRXTrustInnerChecksum {
			config |= tixTCPConfigKernelUDPXDPRXDirectTrustInnerChecksum
		}
	}
	if kernelUDPXDPOpen() {
		config |= tixTCPConfigKernelUDPXDPOpen
		if kernelUDPTCRXDirect && (options.ForcePassOpened || kernelUDPXDPPassOpened()) {
			config |= tixTCPConfigKernelUDPXDPPassOpened
		}
	}
	if options.XDPFallbackPass {
		config |= tixTCPConfigXDPFallbackPass
	}
	if queueCount > 0 {
		if queueCount > 0xffff {
			queueCount = 0xffff
		}
		config |= uint32(queueCount) << tixTCPConfigQueueCountShift
	}
	return config
}

func kernelUDPXDPOpen() bool {
	return envTruthy(
		"TRUSTIX_KERNEL_UDP_XDP_OPEN",
		"TRUSTIX_KERNEL_UDP_XDP_CRYPTO",
	)
}

func tixTCPXDPDirectOpenKfuncEnabled() bool {
	return envTruthy(
		"TRUSTIX_TIX_TCP_XDP_DIRECT_OPEN_KFUNC",
		"TRUSTIX_TIX_TCP_XDP_KFUNC_OPEN",
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

func configureTIXTCPBPFConfig(m *cebpf.Map, queueCount int) (uint32, error) {
	return configureTIXTCPBPFConfigValue(m, queueCount, false)
}

func configureTIXTCPBPFConfigValue(m *cebpf.Map, queueCount int, kernelUDPTCRXDirect bool) (uint32, error) {
	return configureTIXTCPBPFConfigValueFor(m, queueCount, kernelUDPTCRXDirect, false, false)
}

func configureTIXTCPBPFConfigValueFor(m *cebpf.Map, queueCount int, kernelUDPTCRXDirect bool, kernelUDPXDPRXDirect bool, kernelUDPTCRXSecureDirect bool) (uint32, error) {
	return configureTIXTCPBPFConfigValueForOptions(m, queueCount, kernelUDPTCRXDirect, kernelUDPXDPRXDirect, kernelUDPTCRXSecureDirect, tixTCPBPFConfigOptions{})
}

func configureTIXTCPBPFConfigValueForOptions(m *cebpf.Map, queueCount int, kernelUDPTCRXDirect bool, kernelUDPXDPRXDirect bool, kernelUDPTCRXSecureDirect bool, options tixTCPBPFConfigOptions) (uint32, error) {
	config := tixTCPBPFConfigValueForOptions(queueCount, kernelUDPTCRXDirect, kernelUDPXDPRXDirect, kernelUDPTCRXSecureDirect, options)
	if m == nil {
		return config, nil
	}
	key := uint32(0)
	if err := m.Update(key, config, cebpf.UpdateAny); err != nil {
		return 0, fmt.Errorf("configure tix_tcp BPF config: %w", err)
	}
	return config, nil
}

func tixTCPSkipTCPChecksum() bool {
	return envTruthy(
		"TRUSTIX_TIX_TCP_SKIP_TCP_CHECKSUM",
		"TRUSTIX_TIX_TCP_SKIP_OUTER_TCP_CHECKSUM",
		"TRUSTIX_TIX_TCP_SKIP_CHECKSUM",
	)
}

func kernelUDPSkipUDPChecksum() bool {
	return envTruthy(
		"TRUSTIX_KERNEL_UDP_SKIP_UDP_CHECKSUM",
		"TRUSTIX_KERNEL_UDP_NO_CHECKSUM",
	)
}

func tixTCPHotPathStats() bool {
	return envTruthy(
		"TRUSTIX_TIX_TCP_HOT_STATS",
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
