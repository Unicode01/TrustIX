package daemon

import (
	"os"
	"strings"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/transport"
	securetransport "trustix.local/trustix/internal/transport/secure"
)

func kernelUDPTXDirectOnlyForDesired(desired config.Desired) bool {
	if normalizeKernelTransportMode(desired.TransportPolicy.KernelTransport.Mode) != dataplane.KernelTransportModeRequireKernel ||
		!desiredTransportPolicyUsesOnlyDirectKernelTransports(desired) {
		return false
	}
	switch parseSecureTransportEncryption(desired.TransportPolicy.Encryption) {
	case securetransport.EncryptionPlaintext:
		return true
	case securetransport.EncryptionSecure:
		return desiredTransportPolicyAllowsKernelCryptoDirectOnly(desired) &&
			desiredTransportPolicyAllowsSecureDirectOnly(desired)
	default:
		return false
	}
}

func kernelUDPSecureFullDirectForDesired(desired config.Desired) bool {
	if !desiredTransportPolicyUsesAnyProtocol(desired, transport.ProtocolUDP) {
		return false
	}
	if normalizeKernelTransportMode(desired.TransportPolicy.KernelTransport.Mode) == dataplane.KernelTransportModeDisabled {
		return false
	}
	profile := config.EffectiveTransportProfile(desired.TransportPolicy, string(transport.ProtocolUDP))
	if profile.Profile != config.TransportProfilePerformance {
		return false
	}
	if profile.Datapath == config.TransportDatapathUserspace {
		return false
	}
	if parseSecureTransportEncryption(profile.Encryption) != securetransport.EncryptionSecure {
		return false
	}
	placement := normalizeTransportCryptoPlacementConfig(profile.CryptoPlacement)
	if placement == "" {
		placement = effectiveTransportCryptoPlacementConfig(desired.TransportPolicy)
	}
	return placement != string(dataplane.CryptoPlacementUserspace)
}

func experimentalTCPSecureKernelCryptoDirectForDesired(desired config.Desired) bool {
	if normalizeKernelTransportMode(desired.TransportPolicy.KernelTransport.Mode) == dataplane.KernelTransportModeDisabled {
		return false
	}
	if experimentalTCPFastPathDisabledForDesired(desired) {
		return false
	}
	if !desiredTransportPolicyUsesAnyProtocol(desired, transport.ProtocolExperimentalTCP) {
		return false
	}
	profile := config.EffectiveTransportProfile(desired.TransportPolicy, string(transport.ProtocolExperimentalTCP))
	if profile.Profile != config.TransportProfilePerformance {
		return false
	}
	if profile.Datapath == config.TransportDatapathUserspace {
		return false
	}
	if parseSecureTransportEncryption(profile.Encryption) != securetransport.EncryptionSecure {
		return false
	}
	placement := normalizeTransportCryptoPlacementConfig(profile.CryptoPlacement)
	if placement == "" {
		placement = effectiveTransportCryptoPlacementConfig(desired.TransportPolicy)
	}
	return placement != string(dataplane.CryptoPlacementUserspace)
}

func kernelUDPTXDirectOnlyReasonForDesired(desired config.Desired) string {
	if !kernelUDPTXDirectOnlyForDesired(desired) {
		return ""
	}
	encryption := parseSecureTransportEncryption(desired.TransportPolicy.Encryption)
	raw := strings.TrimSpace(desired.TransportPolicy.Encryption)
	if raw == "" {
		raw = encryption
	}
	reason := "transport_policy.encryption=" + raw
	if encryption == securetransport.EncryptionSecure {
		placement := effectiveTransportCryptoPlacementConfig(desired.TransportPolicy)
		if placement == "" {
			placement = string(dataplane.CryptoPlacementAuto)
		}
		reason += " transport_policy.crypto_placement=" + placement
	}
	return reason
}

func kernelUDPTXDirectOnlyFailClosedForDesired(desired config.Desired) bool {
	return kernelUDPTXDirectOnlyForDesired(desired) &&
		!desiredTransportPolicyUsesAnyProtocol(desired, transport.ProtocolExperimentalTCP) &&
		envTruthyAny(
			"TRUSTIX_KERNEL_UDP_TC_ONLY",
			"TRUSTIX_KERNEL_UDP_TC_DIRECT_ONLY_PROVIDER",
		)
}

func kernelUDPTXDirectOnlyFailClosedReasonForDesired(desired config.Desired) string {
	if !kernelUDPTXDirectOnlyFailClosedForDesired(desired) {
		return ""
	}
	reason := kernelUDPTXDirectOnlyReasonForDesired(desired)
	if reason == "" {
		return "kernel_udp_tc_only_provider=enabled"
	}
	return reason + " kernel_udp_tc_only_provider=enabled"
}

func kernelUDPTXDirectOnlyAttachForDesired(desired config.Desired) bool {
	if experimentalTCPPerformanceRouteGSOAsyncForDesired(desired) {
		return true
	}
	if kernelUDPPlaintextPerformanceDirectOnlyForDesired(desired) {
		return true
	}
	if kernelUDPTXDirectOnlyFailClosedForDesired(desired) {
		return true
	}
	if !kernelUDPTXDirectOnlyEnvForcedForDesired() {
		return false
	}
	return kernelUDPTXDirectOnlyForDesired(desired)
}

func kernelUDPTXDirectOnlyAttachReasonForDesired(desired config.Desired) string {
	if experimentalTCPPerformanceRouteGSOAsyncForDesired(desired) {
		return "transport_policy.experimental_tcp=performance route_gso_async_outer_gso=enabled encryption=plaintext"
	}
	if kernelUDPPlaintextPerformanceDirectOnlyForDesired(desired) {
		return "transport_policy.udp=performance tc_direct=enabled encryption=plaintext"
	}
	if reason := kernelUDPTXDirectOnlyFailClosedReasonForDesired(desired); reason != "" {
		return reason
	}
	if !kernelUDPTXDirectOnlyEnvForcedForDesired() {
		return ""
	}
	return kernelUDPTXDirectOnlyReasonForDesired(desired)
}

func kernelUDPTCOnlyProviderForDesired(desired config.Desired) bool {
	return kernelUDPPlaintextPerformanceDirectOnlyForDesired(desired) ||
		kernelUDPTXDirectOnlyFailClosedForDesired(desired)
}

func kernelUDPTCOnlyProviderReasonForDesired(desired config.Desired) string {
	if !kernelUDPTCOnlyProviderForDesired(desired) {
		return ""
	}
	if kernelUDPPlaintextPerformanceDirectOnlyForDesired(desired) {
		return kernelUDPTXDirectOnlyAttachReasonForDesired(desired)
	}
	return kernelUDPTXDirectOnlyFailClosedReasonForDesired(desired)
}

func kernelUDPTXDirectOnlyEnvForcedForDesired() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY"))) {
	case "1", "true", "yes", "on", "enabled", "force":
		return true
	default:
		return false
	}
}

func kernelUDPPlaintextPerformanceDirectOnlyForDesired(desired config.Desired) bool {
	if normalizeKernelTransportMode(desired.TransportPolicy.KernelTransport.Mode) == dataplane.KernelTransportModeDisabled {
		return false
	}
	if !desiredTransportPolicyUsesAnyProtocol(desired, transport.ProtocolUDP) {
		return false
	}
	profile := config.EffectiveTransportProfile(desired.TransportPolicy, string(transport.ProtocolUDP))
	if profile.Datapath == config.TransportDatapathUserspace {
		return false
	}
	if parseSecureTransportEncryption(profile.Encryption) != securetransport.EncryptionPlaintext {
		return false
	}
	fullPlaintextRequested := kernelUDPFullPlaintextDatapathRequestedForDesired(desired)
	if kernelUDPPlaintextPerformanceDirectOnlyExplicitlyEnabledByEnv() && (profile.Profile == config.TransportProfilePerformance || fullPlaintextRequested) {
		return true
	}
	if kernelDatapathFullPlaintextPolicySelectedForDesired(desired) {
		return false
	}
	if kernelUDPPlaintextPerformanceDirectOnlyExplicitlyDisabledByEnv() && !fullPlaintextRequested {
		return false
	}
	if profile.Profile == config.TransportProfilePerformance {
		return true
	}
	return false
}

func kernelUDPFullPlaintextDatapathRequestedForDesired(desired config.Desired) bool {
	if kernelDatapathFullPlaintextPolicySelectedForDesired(desired) {
		return true
	}
	runtime := config.EffectiveKernelDatapathRuntime(desired.KernelModules)
	if runtime.FullPlaintext || runtime.TXPlaintext {
		return true
	}
	switch config.NormalizeKernelCapabilityProfile(desired.KernelModules.CapabilityProfile) {
	case config.KernelCapabilityProfileFullPlaintext:
		return true
	default:
		return false
	}
}

func kernelUDPPlaintextPerformanceDirectOnlyExplicitlyEnabledByEnv() bool {
	return envTruthyAny(
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT",
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY",
		"TRUSTIX_KERNEL_UDP_TC_ONLY",
	)
}

func kernelUDPPlaintextPerformanceDirectOnlyExplicitlyDisabledByEnv() bool {
	for _, name := range []string{
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT",
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY",
		"TRUSTIX_KERNEL_UDP_TC_ONLY",
	} {
		if envFalsey(name) {
			return true
		}
	}
	return false
}

func desiredTransportPolicyAllowsKernelCryptoDirectOnly(desired config.Desired) bool {
	switch effectiveTransportCryptoPlacementConfig(desired.TransportPolicy) {
	case string(dataplane.CryptoPlacementUserspace):
		return false
	default:
		return true
	}
}

func desiredTransportPolicyAllowsSecureDirectOnly(desired config.Desired) bool {
	if !desiredTransportPolicyUsesAnyProtocol(desired, transport.ProtocolUDP) &&
		desiredTransportPolicyUsesAnyProtocol(desired, transport.ProtocolExperimentalTCP) {
		return true
	}
	return kernelUDPSecureDirectOnlyEnvEnabled()
}

func kernelUDPSecureDirectOnlyEnvEnabled() bool {
	return envTruthyAny(
		"TRUSTIX_KERNEL_UDP_TC_SECURE_DIRECT_ONLY",
		"TRUSTIX_KERNEL_UDP_SECURE_DIRECT_ONLY",
	)
}

func desiredTransportPolicyUsesOnlyDirectKernelTransports(desired config.Desired) bool {
	endpointByName := make(map[core.EndpointID]config.EndpointConfig, len(desired.Endpoints))
	for _, endpoint := range desired.Endpoints {
		endpointByName[endpoint.Name] = endpoint
	}
	seen := false
	consider := func(endpoint config.EndpointConfig) bool {
		if !endpoint.Enabled {
			return true
		}
		seen = true
		switch transport.Protocol(strings.ToLower(strings.TrimSpace(endpoint.Transport))) {
		case transport.ProtocolUDP, transport.ProtocolExperimentalTCP:
			return true
		default:
			return false
		}
	}
	if len(desired.TransportPolicy.Candidates) > 0 {
		for _, candidate := range desired.TransportPolicy.Candidates {
			endpoint, ok := endpointByName[candidate]
			if !ok {
				continue
			}
			if !consider(endpoint) {
				return false
			}
		}
		return seen
	}
	if len(desired.Endpoints) == 0 {
		return true
	}
	for _, endpoint := range desired.Endpoints {
		if !consider(endpoint) {
			return false
		}
	}
	return seen
}

func experimentalTCPTXDirectForDesired(desired config.Desired) bool {
	if experimentalTCPFastPathDisabledForDesired(desired) {
		return false
	}
	if experimentalTCPPerformanceRouteGSOAsyncForDesired(desired) {
		return true
	}
	if !envTruthyAny("TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT", "TRUSTIX_REMOTE_EXPERIMENTAL_TCP_TC_TX_DIRECT", "TRUSTIX_E2E_EXPERIMENTAL_TCP_TC_TX_DIRECT", "TRUSTIX_IPERF3_CRYPTO_BENCH_EXPERIMENTAL_TCP_TC_TX_DIRECT", "TRUSTIX_EXPERIMENTAL_TCP_TC_TX_DIRECT_ONLY", "TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_EXPERIMENTAL_TCP_ONLY") {
		return false
	}
	return desiredTransportPolicyUsesAnyProtocol(desired, transport.ProtocolExperimentalTCP)
}

func experimentalTCPPerformanceRouteGSOAsyncForDesired(desired config.Desired) bool {
	if normalizeKernelTransportMode(desired.TransportPolicy.KernelTransport.Mode) == dataplane.KernelTransportModeDisabled {
		return false
	}
	if experimentalTCPFastPathDisabledForDesired(desired) {
		return false
	}
	if experimentalTCPRouteGSOExplicitlyDisabledByEnv() {
		return false
	}
	if !desiredTransportPolicyUsesAnyProtocol(desired, transport.ProtocolExperimentalTCP) {
		return false
	}
	profile := config.EffectiveTransportProfile(desired.TransportPolicy, string(transport.ProtocolExperimentalTCP))
	if profile.Datapath == config.TransportDatapathUserspace {
		return false
	}
	if parseSecureTransportEncryption(profile.Encryption) != securetransport.EncryptionPlaintext {
		return false
	}
	if experimentalTCPRouteGSOExplicitlyEnabledByEnv() {
		return true
	}
	if profile.Datapath != config.TransportDatapathKernelModule {
		return false
	}
	if kernelUDPFullPlaintextDatapathRequestedForDesired(desired) {
		return false
	}
	return profile.Profile == config.TransportProfilePerformance
}

func experimentalTCPRouteGSOAsyncForDesired(desired config.Desired) bool {
	return experimentalTCPPerformanceRouteGSOAsyncForDesired(desired) ||
		experimentalTCPSecureRouteGSOAsyncForDesired(desired)
}

func experimentalTCPSecureRouteGSOAsyncForDesired(desired config.Desired) bool {
	if experimentalTCPRouteGSOExplicitlyDisabledByEnv() {
		return false
	}
	return experimentalTCPSecureKernelCryptoDirectForDesired(desired)
}

func kernelUDPSecureRouteGSOForDesired(desired config.Desired) bool {
	if kernelUDPSecureRouteGSOExplicitlyDisabledByEnv() {
		return false
	}
	return kernelUDPSecureFullDirectForDesired(desired)
}

func secureKernelRouteGSOForDesired(desired config.Desired) bool {
	return experimentalTCPSecureRouteGSOAsyncForDesired(desired) ||
		kernelUDPSecureRouteGSOForDesired(desired)
}

func routeGSOHelpersForDesired(desired config.Desired) bool {
	return experimentalTCPRouteGSOAsyncForDesired(desired) ||
		kernelUDPSecureRouteGSOForDesired(desired)
}

func kernelDatapathFullPlaintextPolicySelectedForDesired(desired config.Desired) bool {
	runtime := config.EffectiveKernelDatapathRuntime(desired.KernelModules)
	if runtime.FullPlaintext || runtime.TXPlaintext {
		return true
	}
	switch config.NormalizeKernelCapabilityProfile(desired.KernelModules.CapabilityProfile) {
	case config.KernelCapabilityProfileFullPlaintext:
		return true
	}
	if normalizeKernelTransportMode(desired.TransportPolicy.KernelTransport.Mode) == dataplane.KernelTransportModeDisabled {
		return false
	}
	if !desiredTransportPolicyUsesOnlyDirectKernelTransports(desired) {
		return false
	}
	endpointByName := make(map[core.EndpointID]config.EndpointConfig, len(desired.Endpoints))
	for _, endpoint := range desired.Endpoints {
		endpointByName[endpoint.Name] = endpoint
	}
	seen := false
	consider := func(endpoint config.EndpointConfig) bool {
		if !endpoint.Enabled {
			return true
		}
		switch transport.Protocol(strings.ToLower(strings.TrimSpace(endpoint.Transport))) {
		case transport.ProtocolUDP:
		default:
			return false
		}
		profile := config.EffectiveEndpointProfile(endpoint, desired.TransportPolicy)
		if profile.Profile != config.TransportProfilePerformance {
			return false
		}
		if profile.Datapath != config.TransportDatapathKernelModule {
			return false
		}
		if parseSecureTransportEncryption(profile.Encryption) != securetransport.EncryptionPlaintext {
			return false
		}
		seen = true
		return true
	}
	if len(desired.TransportPolicy.Candidates) > 0 {
		for _, candidate := range desired.TransportPolicy.Candidates {
			endpoint, ok := endpointByName[candidate]
			if !ok {
				continue
			}
			if !consider(endpoint) {
				return false
			}
		}
		return seen
	}
	if len(desired.Endpoints) == 0 {
		return false
	}
	for _, endpoint := range desired.Endpoints {
		if !consider(endpoint) {
			return false
		}
	}
	return seen
}

func experimentalTCPRouteGSOExplicitlyEnabledByEnv() bool {
	return envTruthyAny(
		"TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO",
		"TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC",
	)
}

func experimentalTCPRouteGSOExplicitlyDisabledByEnv() bool {
	for _, name := range []string{
		"TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO",
		"TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO_ASYNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_KFUNC",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC",
	} {
		if envFalsey(name) {
			return true
		}
	}
	return false
}

func kernelUDPSecureRouteGSOExplicitlyDisabledByEnv() bool {
	for _, name := range []string{
		"TRUSTIX_KERNEL_UDP_TC_TX_SECURE_ROUTE_GSO",
		"TRUSTIX_KERNEL_UDP_TC_TX_SECURE_ROUTE_GSO_KFUNC",
		"TRUSTIX_KERNEL_UDP_TC_TX_SECURE_ROUTE_TCP_GSO_KFUNC",
	} {
		if envFalsey(name) {
			return true
		}
	}
	return false
}

func experimentalTCPFastPathDisabledForDesired(desired config.Desired) bool {
	return experimentalTCPFastPathDisabledReasonForDesired(desired) != ""
}

func experimentalTCPFastPathDisabledReasonForDesired(desired config.Desired) string {
	mode := normalizeKernelTransportMode(desired.TransportPolicy.KernelTransport.Mode)
	if mode == dataplane.KernelTransportModeDisabled {
		return ""
	}
	if mode == dataplane.KernelTransportModeAuto && desiredTransportPolicyUsesSecureUserspaceExperimentalTCP(desired) {
		return "experimental_tcp secure userspace-crypto AF_XDP fast path is disabled by auto policy; use kernel crypto/full-kernel plaintext or enable an explicit fallback after validation"
	}
	if experimentalTCPMixedTCPFastPathAllowedForPolicy() {
		return ""
	}
	if !desiredTransportPolicyUsesAnyProtocol(desired, transport.ProtocolExperimentalTCP) {
		return ""
	}
	if !desiredTransportPolicyUsesAnyProtocol(desired, transport.ProtocolTCP) {
		return ""
	}
	return "tcp+experimental_tcp concurrent kernel transport is disabled by default after PVE mixed-load reboot reproduction; set TRUSTIX_EXPERIMENTAL_TCP_ALLOW_MIXED_TCP_FAST_PATH=1 only for isolated validation"
}

func experimentalTCPMixedTCPFastPathAllowedForPolicy() bool {
	return envTruthyAny(
		"TRUSTIX_EXPERIMENTAL_TCP_ALLOW_MIXED_TCP_FAST_PATH",
		"TRUSTIX_EXPERIMENTAL_TCP_ALLOW_MIXED_TCP",
	)
}
