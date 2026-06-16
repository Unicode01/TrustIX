package daemon

import (
	"strings"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/transport"
	securetransport "trustix.local/trustix/internal/transport/secure"
)

const (
	endpointLinkTLSOptional    = "optional"
	endpointLinkTLSRequired    = "required"
	endpointLinkTLSUnsupported = "unsupported"

	endpointTLSIdentityIXCert     = transportTLSIdentityIXCert
	endpointTLSIdentityCustomCert = transportTLSIdentityCustomCert

	endpointWireFormatTrustIXSecureDataV1 = transport.CryptoWireFormatTrustIXSecureDataV1
)

func (daemon *Daemon) endpointSecurityMetadata(endpoint config.EndpointConfig) dataplane.EndpointSecurityMetadata {
	return endpointSecurityMetadataForPolicy(endpoint, daemon.desired.TransportPolicy)
}

func endpointSecurityMetadataForPolicy(endpoint config.EndpointConfig, policy config.TransportPolicyConfig) dataplane.EndpointSecurityMetadata {
	metadata := endpointSecurityMetadataFromConfig(endpoint.Security, endpoint.TLSServerName)
	profile := config.EffectiveEndpointProfile(endpoint, policy)
	if metadata.LinkTLS == "" {
		if transportSupportsTLSExporter(transport.Protocol(endpoint.Transport)) {
			metadata.LinkTLS = endpointLinkTLSOptional
		} else {
			metadata.LinkTLS = endpointLinkTLSUnsupported
		}
	}
	if metadata.TLSIdentity == "" && metadata.LinkTLS != endpointLinkTLSUnsupported {
		metadata.TLSIdentity = normalizedTransportTLSIdentityMode(policy.TLSIdentity.Mode)
	}
	if metadata.Encryption == "" {
		metadata.Encryption = parseSecureTransportEncryption(firstNonEmpty(profile.Encryption, policy.Encryption))
	}
	if len(metadata.KeySources) == 0 && endpointEncryptionUsesCrypto(metadata.Encryption) {
		metadata.KeySources = advertisedEndpointKeySources(policy.CryptoKeySource, endpoint.Transport)
	}
	if metadata.WireFormat == "" && endpointEncryptionUsesSecureEnvelope(metadata.Encryption) {
		metadata.WireFormat = endpointWireFormatTrustIXSecureDataV1
	}
	if len(metadata.CryptoSuites) == 0 && endpointEncryptionUsesCrypto(metadata.Encryption) {
		metadata.CryptoSuites = effectiveSecureTransportCryptoSuitesForEndpointPolicy(endpoint, policy)
	}
	if len(metadata.CryptoPlacements) == 0 && transportSupportsCryptoPlacement(endpoint.Transport) && endpointEncryptionFullySecure(metadata.Encryption) {
		metadata.CryptoPlacements = advertisedTransportCryptoPlacements(effectiveTransportCryptoPlacementConfig(policy))
	}
	return metadata
}

func endpointSecurityMetadataFromConfig(security config.EndpointSecurityConfig, tlsServerName string) dataplane.EndpointSecurityMetadata {
	return dataplane.EndpointSecurityMetadata{
		LinkTLS:          normalizeEndpointLinkTLS(security.LinkTLS),
		TLSIdentity:      normalizeEndpointTLSIdentity(security.TLSIdentity),
		TLSServerName:    strings.TrimSpace(tlsServerName),
		Encryption:       normalizeEndpointEncryption(security.Encryption),
		KeySources:       normalizeEndpointList(security.KeySources, normalizeEndpointKeySource),
		WireFormat:       normalizeEndpointWireFormat(security.WireFormat),
		CryptoSuites:     normalizeEndpointList(security.CryptoSuites, normalizeEndpointCryptoSuite),
		CryptoPlacements: normalizeEndpointList(security.CryptoPlacements, normalizeEndpointCryptoPlacement),
	}
}

func endpointSecurityConfigFromMetadata(security dataplane.EndpointSecurityMetadata) config.EndpointSecurityConfig {
	return config.EndpointSecurityConfig{
		LinkTLS:          normalizeEndpointLinkTLS(security.LinkTLS),
		TLSIdentity:      normalizeEndpointTLSIdentity(security.TLSIdentity),
		Encryption:       normalizeEndpointEncryption(security.Encryption),
		KeySources:       normalizeEndpointList(security.KeySources, normalizeEndpointKeySource),
		WireFormat:       normalizeEndpointWireFormat(security.WireFormat),
		CryptoSuites:     normalizeEndpointList(security.CryptoSuites, normalizeEndpointCryptoSuite),
		CryptoPlacements: normalizeEndpointList(security.CryptoPlacements, normalizeEndpointCryptoPlacement),
	}
}

func advertisedEndpointKeySources(rawKeySource string, rawTransport string) []string {
	keySource := parseSecureTransportKeySource(strings.ToLower(strings.TrimSpace(rawKeySource)))
	switch keySource {
	case securetransport.KeySourceTLSExporter:
		return []string{securetransport.KeySourceTLSExporter}
	case securetransport.KeySourceTrustIXX25519:
		return []string{securetransport.KeySourceTrustIXX25519}
	default:
		if transportSupportsTLSExporter(transport.Protocol(rawTransport)) {
			return []string{securetransport.KeySourceTLSExporter}
		}
		return []string{securetransport.KeySourceTrustIXX25519}
	}
}

func endpointTransportAllowsTLS(rawTransport string, security dataplane.EndpointSecurityMetadata) bool {
	return transportSupportsTLSExporter(transport.Protocol(rawTransport)) &&
		normalizeEndpointLinkTLS(security.LinkTLS) != endpointLinkTLSUnsupported
}

func advertisedTransportCryptoPlacements(rawPlacement string) []string {
	switch normalizeEndpointCryptoPlacement(rawPlacement) {
	case "kernel":
		return []string{"kernel"}
	case "userspace":
		return []string{"userspace"}
	default:
		return []string{"kernel", "userspace"}
	}
}

func (daemon *Daemon) endpointSecurityCompatible(endpoint config.EndpointConfig) bool {
	security := endpointSecurityMetadataFromConfig(endpoint.Security, endpoint.TLSServerName)
	if security.Encryption == "" && strings.TrimSpace(endpoint.Profile.Encryption) != "" {
		security.Encryption = parseSecureTransportEncryption(endpoint.Profile.Encryption)
	}
	localEncryption := daemon.endpointLocalEncryptionForSecurity(security)
	remoteSecurity := security
	if remoteSecurity.Encryption == "" {
		remoteSecurity.Encryption = parseSecureTransportEncryption(daemon.desired.TransportPolicy.Encryption)
	}
	if endpointRequiresLinkTLSForEncryption(endpoint.Transport, localEncryption, remoteSecurity) && !endpointTransportAllowsTLS(endpoint.Transport, remoteSecurity) {
		return false
	}
	if !endpointEncryptionCompatible(localEncryption, remoteSecurity) {
		return false
	}
	if endpointEncryptionUsesCrypto(localEncryption) && !endpointKeySourceCompatible(daemon.desired.TransportPolicy.CryptoKeySource, endpoint.Transport, remoteSecurity) {
		return false
	}
	if !endpointTLSCompatible(daemon.desired.TransportPolicy.TLSIdentity.Mode, endpoint.Transport, remoteSecurity) {
		return false
	}
	if endpointEncryptionUsesSecureEnvelope(remoteSecurity.Encryption) && !endpointWireFormatCompatible(remoteSecurity) {
		return false
	}
	if endpointEncryptionUsesCrypto(remoteSecurity.Encryption) && !daemon.endpointCryptoSuiteCompatible(remoteSecurity) {
		return false
	}
	if transportSupportsCryptoPlacement(endpoint.Transport) && endpointEncryptionFullySecure(localEncryption) &&
		!endpointCryptoPlacementCompatible(effectiveTransportCryptoPlacementConfig(daemon.desired.TransportPolicy), remoteSecurity) {
		return false
	}
	return true
}

func transportSupportsCryptoPlacement(rawTransport string) bool {
	switch transport.Protocol(strings.ToLower(strings.TrimSpace(rawTransport))) {
	case transport.ProtocolExperimentalTCP, transport.ProtocolUDP:
		return true
	default:
		return false
	}
}

func (daemon *Daemon) endpointLocalEncryptionForSecurity(security dataplane.EndpointSecurityMetadata) string {
	if strings.TrimSpace(security.Encryption) != "" {
		return complementEndpointEncryption(security.Encryption)
	}
	return parseSecureTransportEncryption(daemon.desired.TransportPolicy.Encryption)
}

func endpointKeySourceCompatible(localKeySource string, rawTransport string, security dataplane.EndpointSecurityMetadata) bool {
	required := parseSecureTransportKeySource(strings.ToLower(strings.TrimSpace(localKeySource)))
	if required == securetransport.KeySourceAuto {
		if len(security.KeySources) == 0 {
			return true
		}
		required = securetransport.KeySourceTrustIXX25519
		if endpointTransportAllowsTLS(rawTransport, security) {
			required = securetransport.KeySourceTLSExporter
		}
	}
	if required == securetransport.KeySourceTLSExporter && !endpointTransportAllowsTLS(rawTransport, security) {
		return false
	}
	if len(security.KeySources) == 0 {
		return true
	}
	return endpointListContains(security.KeySources, required, normalizeEndpointKeySource)
}

func endpointTLSCompatible(localIdentityMode string, rawTransport string, security dataplane.EndpointSecurityMetadata) bool {
	if security.LinkTLS == "" {
		return true
	}
	localSupportsTLS := endpointTransportAllowsTLS(rawTransport, security)
	switch normalizeEndpointLinkTLS(security.LinkTLS) {
	case endpointLinkTLSRequired:
		if !localSupportsTLS {
			return false
		}
	case endpointLinkTLSUnsupported:
		if endpointListContains(security.KeySources, securetransport.KeySourceTLSExporter, normalizeEndpointKeySource) {
			return false
		}
	}
	if security.TLSIdentity == "" {
		return true
	}
	return normalizeEndpointTLSIdentity(security.TLSIdentity) == normalizedTransportTLSIdentityMode(localIdentityMode)
}

func endpointWireFormatCompatible(security dataplane.EndpointSecurityMetadata) bool {
	return security.WireFormat == "" || normalizeEndpointWireFormat(security.WireFormat) == endpointWireFormatTrustIXSecureDataV1
}

func (daemon *Daemon) endpointCryptoSuiteCompatible(security dataplane.EndpointSecurityMetadata) bool {
	if len(security.CryptoSuites) == 0 {
		return true
	}
	for _, local := range effectiveSecureTransportCryptoSuitesForDesired(daemon.desired) {
		if endpointListContains(security.CryptoSuites, local, normalizeEndpointCryptoSuite) {
			return true
		}
	}
	return false
}

func endpointCryptoPlacementCompatible(localPlacement string, security dataplane.EndpointSecurityMetadata) bool {
	if len(security.CryptoPlacements) == 0 {
		return true
	}
	local := normalizeEndpointCryptoPlacement(localPlacement)
	if local == "" || local == "auto" {
		return endpointListContains(security.CryptoPlacements, "kernel", normalizeEndpointCryptoPlacement) ||
			endpointListContains(security.CryptoPlacements, "userspace", normalizeEndpointCryptoPlacement)
	}
	return endpointListContains(security.CryptoPlacements, local, normalizeEndpointCryptoPlacement)
}

func endpointEncryptionCompatible(localEncryption string, security dataplane.EndpointSecurityMetadata) bool {
	local := securetransport.EncryptionPolicyForMode(endpointEncryptionOrDefault(localEncryption))
	remote := securetransport.EncryptionPolicyForMode(endpointEncryptionOrDefault(security.Encryption))
	return local.SendEncrypted == remote.ReceiveEncrypted && local.ReceiveEncrypted == remote.SendEncrypted
}

func (daemon *Daemon) endpointDialEncryption(endpoint config.EndpointConfig) string {
	if strings.TrimSpace(endpoint.Security.Encryption) == "" {
		profile := config.EffectiveEndpointProfile(endpoint, daemon.desired.TransportPolicy)
		return parseSecureTransportEncryption(firstNonEmpty(profile.Encryption, daemon.desired.TransportPolicy.Encryption))
	}
	return complementEndpointEncryption(endpoint.Security.Encryption)
}

func complementEndpointEncryption(encryption string) string {
	policy := securetransport.EncryptionPolicyForMode(endpointEncryptionOrDefault(encryption))
	switch {
	case policy.SendEncrypted && policy.ReceiveEncrypted:
		return securetransport.EncryptionSecure
	case policy.SendEncrypted:
		return securetransport.EncryptionReceiveEncrypted
	case policy.ReceiveEncrypted:
		return securetransport.EncryptionSendEncrypted
	default:
		return securetransport.EncryptionPlaintext
	}
}

func endpointEncryptionUsesSecureEnvelope(encryption string) bool {
	return securetransport.EncryptionPolicyForMode(endpointEncryptionOrDefault(encryption)).AnyEncrypted()
}

func endpointEncryptionUsesCrypto(encryption string) bool {
	return securetransport.EncryptionPolicyForMode(endpointEncryptionOrDefault(encryption)).AnyEncrypted()
}

func endpointEncryptionFullySecure(encryption string) bool {
	return securetransport.EncryptionPolicyForMode(endpointEncryptionOrDefault(encryption)).FullyEncrypted()
}

func endpointRequiresLinkTLSForEncryption(rawTransport string, encryption string, security dataplane.EndpointSecurityMetadata) bool {
	return endpointEncryptionOrDefault(encryption) == securetransport.EncryptionPlaintext &&
		normalizeEndpointLinkTLS(security.LinkTLS) == endpointLinkTLSRequired
}

func endpointEncryptionOrDefault(encryption string) string {
	normalized := normalizeEndpointEncryption(encryption)
	if normalized == "" {
		return securetransport.EncryptionSecure
	}
	return normalized
}

func normalizeEndpointLinkTLS(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case endpointLinkTLSRequired:
		return endpointLinkTLSRequired
	case endpointLinkTLSUnsupported:
		return endpointLinkTLSUnsupported
	case endpointLinkTLSOptional:
		return endpointLinkTLSOptional
	default:
		return ""
	}
}

func normalizeEndpointTLSIdentity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case endpointTLSIdentityCustomCert:
		return endpointTLSIdentityCustomCert
	case endpointTLSIdentityIXCert:
		return endpointTLSIdentityIXCert
	default:
		return ""
	}
}

func normalizeEndpointKeySource(value string) string {
	switch parseSecureTransportKeySource(strings.ToLower(strings.TrimSpace(value))) {
	case securetransport.KeySourceTLSExporter:
		return securetransport.KeySourceTLSExporter
	case securetransport.KeySourceTrustIXX25519:
		return securetransport.KeySourceTrustIXX25519
	default:
		return ""
	}
}

func normalizeEndpointEncryption(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	switch parseSecureTransportEncryption(value) {
	case securetransport.EncryptionPlaintext:
		return securetransport.EncryptionPlaintext
	case securetransport.EncryptionSendEncrypted:
		return securetransport.EncryptionSendEncrypted
	case securetransport.EncryptionReceiveEncrypted:
		return securetransport.EncryptionReceiveEncrypted
	default:
		return securetransport.EncryptionSecure
	}
}

func normalizeEndpointWireFormat(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case endpointWireFormatTrustIXSecureDataV1:
		return endpointWireFormatTrustIXSecureDataV1
	default:
		return ""
	}
}

func normalizeEndpointCryptoSuite(value string) string {
	return securetransport.NormalizeCryptoSuite(value)
}

func normalizeEndpointCryptoPlacement(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "kernel":
		return "kernel"
	case "userspace":
		return "userspace"
	case "auto":
		return "auto"
	default:
		return ""
	}
}

func normalizeEndpointList(values []string, normalize func(string) string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		normalized := normalize(value)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func endpointListContains(values []string, want string, normalize func(string) string) bool {
	want = normalize(want)
	if want == "" {
		return false
	}
	for _, value := range values {
		if normalize(value) == want {
			return true
		}
	}
	return false
}
