//go:build linux

package ebpf

import "testing"

func TestExperimentalTCPBPFConfigPassOpenedRequiresExplicitEnv(t *testing.T) {
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_SKIP_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_SKIP_OUTER_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_SKIP_CHECKSUM", "")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_HOT_STATS", "")
	t.Setenv("TRUSTIX_XDP_HOT_STATS", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_HOT_STATS", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_DEVMAP_DIRECT", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_FIXED_L2", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_MODE", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_TRUST_INNER_CHECKSUM", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_TRUST_INNER_CHECKSUMS", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_RX_TRUST_INNER_CHECKSUM", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_RX_TRUST_INNER_CHECKSUMS", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_RX_SECURE_DIRECT", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_SECURE_DIRECT", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_CRYPTO", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_OPEN", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_PASS_OPENED", "")

	config := experimentalTCPBPFConfigValue(4, true)
	if config&experimentalTCPConfigKernelUDPXDPOpen == 0 {
		t.Fatalf("kernel_udp XDP open bit was not set: %#x", config)
	}
	if config&experimentalTCPConfigKernelUDPTCRXDirect == 0 {
		t.Fatalf("kernel_udp TC RX direct bit was not set: %#x", config)
	}
	if config&experimentalTCPConfigKernelUDPXDPRXDirect != 0 {
		t.Fatalf("kernel_udp XDP RX direct bit set by TC-only config: %#x", config)
	}
	if config&experimentalTCPConfigKernelUDPXDPPassOpened != 0 {
		t.Fatalf("kernel_udp XDP pass-opened bit set without explicit opt-in: %#x", config)
	}
	if config&experimentalTCPConfigHotPathStats != 0 {
		t.Fatalf("hot-path stats bit set without explicit opt-in: %#x", config)
	}
	config = experimentalTCPBPFConfigValueForOptions(4, true, false, false, experimentalTCPBPFConfigOptions{ForcePassOpened: true})
	if config&experimentalTCPConfigKernelUDPXDPPassOpened == 0 {
		t.Fatalf("kernel_udp XDP pass-opened bit was not forced for TC fallback: %#x", config)
	}

	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_PASS_OPENED", "1")
	config = experimentalTCPBPFConfigValue(4, true)
	if config&experimentalTCPConfigKernelUDPXDPPassOpened == 0 {
		t.Fatalf("kernel_udp XDP pass-opened bit was not set after opt-in: %#x", config)
	}

	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_HOT_STATS", "1")
	config = experimentalTCPBPFConfigValue(4, true)
	if config&experimentalTCPConfigHotPathStats == 0 {
		t.Fatalf("hot-path stats bit was not set after opt-in: %#x", config)
	}

	config = experimentalTCPBPFConfigValueFor(4, true, true, false)
	if config&experimentalTCPConfigKernelUDPXDPRXDirect == 0 {
		t.Fatalf("kernel_udp XDP RX direct bit was not set by explicit XDP config: %#x", config)
	}
	if config&experimentalTCPConfigKernelUDPXDPRXDirectFixedL2 != 0 {
		t.Fatalf("kernel_udp XDP RX fixed L2 bit set without explicit opt-in: %#x", config)
	}
	if config&experimentalTCPConfigKernelUDPXDPRXSecureDirect != 0 {
		t.Fatalf("kernel_udp XDP secure RX direct bit set without explicit secure-XDP opt-in: %#x", config)
	}
	if config&experimentalTCPConfigKernelUDPXDPRXDirectTrustInnerChecksum != 0 {
		t.Fatalf("kernel_udp XDP RX trust-inner-checksum bit set without explicit opt-in: %#x", config)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_MODE", "fixed_l2")
	config = experimentalTCPBPFConfigValueFor(4, true, true, false)
	if config&experimentalTCPConfigKernelUDPXDPRXDirectFixedL2 == 0 {
		t.Fatalf("kernel_udp XDP RX fixed L2 bit was not set by mode: %#x", config)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_MODE", "")
	config = experimentalTCPBPFConfigValueForOptions(4, true, true, false, experimentalTCPBPFConfigOptions{XDPRXTrustInnerChecksum: true})
	if config&experimentalTCPConfigKernelUDPXDPRXDirectTrustInnerChecksum == 0 {
		t.Fatalf("kernel_udp XDP RX trust-inner-checksum bit was not set by explicit option: %#x", config)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_TRUST_INNER_CHECKSUM", "1")
	if !kernelUDPXDPRXDirectTrustInnerChecksumEnabled() {
		t.Fatalf("kernel_udp XDP RX trust-inner-checksum env gate did not enable")
	}
	config = experimentalTCPBPFConfigValueFor(4, true, true, false)
	if config&experimentalTCPConfigKernelUDPXDPRXDirectTrustInnerChecksum == 0 {
		t.Fatalf("kernel_udp XDP RX trust-inner-checksum bit was not set by env: %#x", config)
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_TRUST_INNER_CHECKSUM", "")
	if config&experimentalTCPConfigKernelUDPTCRXSecureDirect != 0 {
		t.Fatalf("kernel_udp TC secure RX direct bit set without explicit secure opt-in: %#x", config)
	}
	config = experimentalTCPBPFConfigValueFor(4, true, false, true)
	if config&experimentalTCPConfigKernelUDPTCRXSecureDirect == 0 {
		t.Fatalf("kernel_udp TC secure RX direct bit was not set by explicit secure config: %#x", config)
	}
	config = experimentalTCPBPFConfigValueForOptions(4, true, true, true, experimentalTCPBPFConfigOptions{XDPRXSecureDirect: true})
	if config&experimentalTCPConfigKernelUDPXDPRXSecureDirect == 0 {
		t.Fatalf("kernel_udp XDP secure RX direct bit was not set by explicit secure-XDP config: %#x", config)
	}
	if config&experimentalTCPConfigXDPFallbackPass != 0 {
		t.Fatalf("XDP fallback-pass bit set without explicit option: %#x", config)
	}
	config = experimentalTCPBPFConfigValueForOptions(4, true, true, false, experimentalTCPBPFConfigOptions{XDPFallbackPass: true})
	if config&experimentalTCPConfigXDPFallbackPass == 0 {
		t.Fatalf("XDP fallback-pass bit was not set by explicit option: %#x", config)
	}
	if kernelUDPXDPRXSecureDirectEnabled() {
		t.Fatalf("kernel_udp XDP secure RX direct env gate enabled unexpectedly")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_RX_SECURE_DIRECT", "1")
	if !kernelUDPXDPRXSecureDirectEnabled() {
		t.Fatalf("kernel_udp XDP secure RX direct env gate did not enable")
	}
	if kernelUDPXDPRXDirectEnabled() {
		t.Fatalf("kernel_udp XDP RX direct env gate enabled unexpectedly")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT", "1")
	if !kernelUDPXDPRXDirectEnabled() {
		t.Fatalf("kernel_udp XDP RX direct env gate did not enable")
	}
}

func TestExperimentalTCPSkipOuterChecksumSetsBPFSkipChecksum(t *testing.T) {
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_SKIP_TCP_CHECKSUM", "")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_SKIP_CHECKSUM", "")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_SKIP_OUTER_TCP_CHECKSUM", "1")
	if !experimentalTCPSkipTCPChecksum() {
		t.Fatal("experimental_tcp outer-checksum skip did not enable TCP checksum skip")
	}
	config := experimentalTCPBPFConfigValue(1, false)
	if config&experimentalTCPConfigSkipTCPChecksum == 0 {
		t.Fatalf("experimental_tcp BPF config %#x missing skip TCP checksum bit", config)
	}
}

func TestKernelUDPTCRXDirectRequiresExplicitEnv(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT", "")
	if kernelUDPRXDirectDisabled() {
		t.Fatalf("kernel_udp TC RX direct disabled by default")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT", "0")
	if kernelUDPRXDirectDisabled() {
		return
	}
	t.Fatalf("kernel_udp TC RX direct did not disable after explicit opt-out")
}

func TestKernelUDPTCRXDirectStillDependsOnTXDirect(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT", "")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_RX_DIRECT", "1")
	if kernelUDPRXDirectDisabled() {
		t.Fatalf("kernel_udp TC RX direct disabled with TX direct default-enabled")
	}
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT", "0")
	if !kernelUDPRXDirectDisabled() {
		t.Fatalf("kernel_udp TC RX direct stayed enabled while TX direct was disabled")
	}
}
