package daemon

import (
	"sort"
	"strings"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/transport"
)

const transportProfileMetadataVersion = 1

func endpointTransportProfileMetadataForPolicy(endpoint config.EndpointConfig, policy config.TransportPolicyConfig) dataplane.TransportProfileMetadata {
	profile := config.EffectiveEndpointProfile(endpoint, policy)
	metadata := dataplane.TransportProfileMetadata{
		Version:         transportProfileMetadataVersion,
		Profile:         profile.Profile,
		Datapath:        profile.Datapath,
		Encryption:      parseSecureTransportEncryption(profile.Encryption),
		CryptoPlacement: normalizeEndpointCryptoPlacement(profile.CryptoPlacement),
		Features:        transportProfileFeatures(endpoint.Transport, profile),
	}
	if metadata.Encryption == "" {
		metadata.Encryption = parseSecureTransportEncryption(policy.Encryption)
	}
	if metadata.CryptoPlacement == "" {
		metadata.CryptoPlacement = effectiveTransportCryptoPlacementConfig(policy)
	}
	return metadata
}

func endpointTransportProfileConfigFromMetadata(profile dataplane.TransportProfileMetadata) config.EndpointProfileConfig {
	return config.EndpointProfileConfig{
		Version:         profile.Version,
		Profile:         normalizeEndpointTransportProfile(profile.Profile),
		Datapath:        normalizeEndpointTransportDatapath(profile.Datapath),
		Encryption:      parseSecureTransportEncryption(profile.Encryption),
		CryptoPlacement: normalizeEndpointCryptoPlacement(profile.CryptoPlacement),
		Features:        normalizeEndpointProfileFeatures(profile.Features),
	}
}

func endpointTransportProfileMetadataFromConfig(profile config.EndpointProfileConfig) dataplane.TransportProfileMetadata {
	return dataplane.TransportProfileMetadata{
		Version:         profile.Version,
		Profile:         normalizeEndpointTransportProfile(profile.Profile),
		Datapath:        normalizeEndpointTransportDatapath(profile.Datapath),
		Encryption:      parseSecureTransportEncryption(profile.Encryption),
		CryptoPlacement: normalizeEndpointCryptoPlacement(profile.CryptoPlacement),
		Features:        normalizeEndpointProfileFeatures(profile.Features),
	}
}

func endpointTransportProfileConfigured(profile config.EndpointProfileConfig) bool {
	return profile.Version > 0 ||
		strings.TrimSpace(profile.Profile) != "" ||
		strings.TrimSpace(profile.Datapath) != "" ||
		strings.TrimSpace(profile.Encryption) != "" ||
		strings.TrimSpace(profile.CryptoPlacement) != "" ||
		len(profile.Features) > 0
}

func normalizeEndpointTransportProfile(raw string) string {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(raw), "-", "_")) {
	case "performance", "perf", "throughput", "fast":
		return config.TransportProfilePerformance
	case "latency", "low_latency", "lowlatency", "interactive":
		return config.TransportProfileLatency
	case "stable", "safe", "compat", "compatibility":
		return config.TransportProfileStable
	default:
		return ""
	}
}

func normalizeEndpointTransportDatapath(raw string) string {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(raw), "-", "_")) {
	case "userspace", "user", "raw_socket", "rawsocket":
		return config.TransportDatapathUserspace
	case "tc_xdp", "tcxdp", "tc", "xdp", "ebpf":
		return config.TransportDatapathTCXDP
	case "kernel_module", "kernel", "module", "ko", "full_kernel":
		return config.TransportDatapathKernelModule
	case "auto":
		return config.TransportDatapathAuto
	default:
		return ""
	}
}

func normalizeEndpointProfileFeatures(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		normalized := normalizeEndpointProfileFeature(value)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out
}

func normalizeEndpointProfileFeature(value string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "-", "_"))
}

func transportProfileFeatures(rawTransport string, profile config.EndpointProfileConfig) []string {
	protocol := transport.Protocol(strings.ToLower(strings.TrimSpace(rawTransport)))
	features := make([]string, 0, 8)
	add := func(values ...string) {
		features = append(features, values...)
	}
	switch protocol {
	case transport.ProtocolExperimentalTCP:
		add("tixt_v1", "ackless_tcp")
		if profile.Profile == config.TransportProfilePerformance {
			add("tixb_batching")
			if profile.Datapath != config.TransportDatapathUserspace {
				add("tc_xdp", "af_xdp", "tc_tx_direct", "route_gso_async", "route_gso_async_outer_gso", "route_xmit_worker")
			}
			if parseSecureTransportEncryption(profile.Encryption) == "plaintext" {
				add("plaintext_ack_only")
			}
		}
	case transport.ProtocolUDP:
		add("tixt_v1")
		if profile.Profile == config.TransportProfilePerformance && profile.Datapath != config.TransportDatapathUserspace {
			add("kernel_udp", "large_frame_rx", "gso_rx", "gro_rx")
			if parseSecureTransportEncryption(profile.Encryption) == "secure" &&
				normalizeEndpointCryptoPlacement(profile.CryptoPlacement) != string(dataplane.CryptoPlacementUserspace) {
				add("secure_tx_direct", "secure_rx_direct", "secure_trust_inner_checksum")
			}
		}
	case transport.ProtocolGRE, transport.ProtocolIPIP, transport.ProtocolVXLAN:
		add("native_tunnel")
	}
	add(profile.Features...)
	return normalizeEndpointProfileFeatures(features)
}

func (daemon *Daemon) endpointTransportProfileCompatible(endpoint config.EndpointConfig) bool {
	remote := endpoint.Profile
	if remote.Version == 0 && remote.Profile == "" && remote.Datapath == "" && len(remote.Features) == 0 {
		return true
	}
	local := config.EffectiveTransportProfile(daemon.desired.TransportPolicy, endpoint.Transport)
	localEndpointProfile := config.EndpointProfileConfig{
		Profile:         local.Profile,
		Datapath:        local.Datapath,
		Encryption:      local.Encryption,
		CryptoPlacement: local.CryptoPlacement,
	}
	required := requiredTransportProfileFeatures(endpoint.Transport, localEndpointProfile)
	if len(required) == 0 {
		return true
	}
	remoteFeatures := endpointTransportProfileFeaturesForCompatibility(endpoint.Transport, remote)
	for _, feature := range required {
		if !stringListContains(remoteFeatures, feature) {
			return false
		}
	}
	return true
}

func endpointTransportProfileFeaturesForCompatibility(rawTransport string, profile config.EndpointProfileConfig) []string {
	if len(profile.Features) > 0 {
		return normalizeEndpointProfileFeatures(profile.Features)
	}
	normalized := config.EndpointProfileConfig{
		Profile:         normalizeEndpointTransportProfile(profile.Profile),
		Datapath:        normalizeEndpointTransportDatapath(profile.Datapath),
		Encryption:      parseSecureTransportEncryption(profile.Encryption),
		CryptoPlacement: normalizeEndpointCryptoPlacement(profile.CryptoPlacement),
	}
	if normalized.Profile == "" {
		return nil
	}
	return transportProfileFeatures(rawTransport, normalized)
}

func requiredTransportProfileFeatures(rawTransport string, profile config.EndpointProfileConfig) []string {
	if profile.Profile != config.TransportProfilePerformance {
		return nil
	}
	features := transportProfileFeatures(rawTransport, profile)
	required := make([]string, 0, len(features))
	for _, feature := range features {
		switch feature {
		case "tixb_batching", "tc_xdp", "af_xdp", "tc_tx_direct", "route_gso_async", "route_gso_async_outer_gso", "route_xmit_worker", "large_frame_rx", "gso_rx", "gro_rx",
			"secure_tx_direct", "secure_rx_direct", "secure_kfunc_seal", "secure_trust_inner_checksum":
			required = append(required, feature)
		}
	}
	return required
}

func stringListContains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func transportProfileMetadataEmpty(profile dataplane.TransportProfileMetadata) bool {
	return profile.Version == 0 &&
		strings.TrimSpace(profile.Profile) == "" &&
		strings.TrimSpace(profile.Datapath) == "" &&
		strings.TrimSpace(profile.Encryption) == "" &&
		strings.TrimSpace(profile.CryptoPlacement) == "" &&
		len(profile.Features) == 0 &&
		strings.TrimSpace(profile.FallbackReason) == ""
}

func transportProfileSurfacesCompatible(left, right dataplane.TransportProfileMetadata) bool {
	if transportProfileMetadataEmpty(left) || transportProfileMetadataEmpty(right) {
		return true
	}
	left.Features = normalizeEndpointProfileFeatures(left.Features)
	right.Features = normalizeEndpointProfileFeatures(right.Features)
	left.Profile = normalizeEndpointTransportProfile(left.Profile)
	right.Profile = normalizeEndpointTransportProfile(right.Profile)
	left.Datapath = normalizeEndpointTransportDatapath(left.Datapath)
	right.Datapath = normalizeEndpointTransportDatapath(right.Datapath)
	left.Encryption = parseSecureTransportEncryption(left.Encryption)
	right.Encryption = parseSecureTransportEncryption(right.Encryption)
	left.CryptoPlacement = normalizeEndpointCryptoPlacement(left.CryptoPlacement)
	right.CryptoPlacement = normalizeEndpointCryptoPlacement(right.CryptoPlacement)
	return left.Version == right.Version &&
		left.Profile == right.Profile &&
		left.Datapath == right.Datapath &&
		left.Encryption == right.Encryption &&
		left.CryptoPlacement == right.CryptoPlacement &&
		left.FallbackReason == right.FallbackReason &&
		equalStringSlices(left.Features, right.Features)
}

func equalStringSlices(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
