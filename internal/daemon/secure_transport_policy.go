package daemon

import (
	"strings"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/transport"
	securetransport "trustix.local/trustix/internal/transport/secure"
)

const (
	secureKeySourceAutoCode uint32 = iota
	secureKeySourceTrustIXX25519Code
	secureKeySourceTLSExporterCode
)

const (
	secureEncryptionSecureCode uint32 = iota
	secureEncryptionPlaintextCode
	secureEncryptionSendEncryptedCode
	secureEncryptionReceiveEncryptedCode
)

func (daemon *Daemon) setSecureTransportKeySource(raw string) {
	daemon.secureKeySource.Store(secureKeySourceCode(parseSecureTransportKeySource(raw)))
}

func (daemon *Daemon) setSecureTransportEncryption(raw string) {
	daemon.secureEncryption.Store(secureEncryptionCode(parseSecureTransportEncryption(raw)))
}

func (daemon *Daemon) setSecureTransportCryptoSuites(desired config.Desired) {
	daemon.secureSuites.Store(effectiveSecureTransportCryptoSuitesForDesired(desired))
}

func (daemon *Daemon) secureTransportKeySource() string {
	switch daemon.secureKeySource.Load() {
	case secureKeySourceTrustIXX25519Code:
		return securetransport.KeySourceTrustIXX25519
	case secureKeySourceTLSExporterCode:
		return securetransport.KeySourceTLSExporter
	default:
		return securetransport.KeySourceAuto
	}
}

func (daemon *Daemon) secureTransportEncryption() string {
	switch daemon.secureEncryption.Load() {
	case secureEncryptionPlaintextCode:
		return securetransport.EncryptionPlaintext
	case secureEncryptionSendEncryptedCode:
		return securetransport.EncryptionSendEncrypted
	case secureEncryptionReceiveEncryptedCode:
		return securetransport.EncryptionReceiveEncrypted
	default:
		return securetransport.EncryptionSecure
	}
}

func (daemon *Daemon) secureTransportCryptoSuites() []string {
	value := daemon.secureSuites.Load()
	if value == nil {
		return securetransport.CryptoSuitesOrDefault(nil)
	}
	suites, ok := value.([]string)
	if !ok {
		return securetransport.CryptoSuitesOrDefault(nil)
	}
	return append([]string(nil), suites...)
}

func parseSecureTransportKeySource(raw string) string {
	switch raw {
	case securetransport.KeySourceTrustIXX25519:
		return securetransport.KeySourceTrustIXX25519
	case securetransport.KeySourceTLSExporter:
		return securetransport.KeySourceTLSExporter
	default:
		return securetransport.KeySourceAuto
	}
}

func parseSecureTransportEncryption(raw string) string {
	switch securetransport.NormalizeEncryptionMode(raw) {
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

func effectiveSecureTransportCryptoSuitesForDesired(desired config.Desired) []string {
	if len(desired.TransportPolicy.CryptoSuites) > 0 {
		return securetransport.CryptoSuitesOrDefault(desired.TransportPolicy.CryptoSuites)
	}
	if performanceKernelSecureCryptoForDesired(desired) {
		return performanceKernelSecureCryptoSuites()
	}
	return securetransport.CryptoSuitesOrDefault(nil)
}

func effectiveSecureTransportCryptoSuitesForEndpointPolicy(endpoint config.EndpointConfig, policy config.TransportPolicyConfig) []string {
	if len(policy.CryptoSuites) > 0 {
		return securetransport.CryptoSuitesOrDefault(policy.CryptoSuites)
	}
	if performanceKernelSecureCryptoForEndpointPolicy(endpoint, policy) {
		return performanceKernelSecureCryptoSuites()
	}
	return securetransport.CryptoSuitesOrDefault(nil)
}

func performanceKernelSecureCryptoSuites() []string {
	return []string{
		securetransport.SuiteAES128GCMX25519,
		securetransport.SuiteAES256GCMX25519,
	}
}

func performanceKernelSecureCryptoForDesired(desired config.Desired) bool {
	return experimentalTCPSecureKernelCryptoDirectForDesired(desired) ||
		kernelUDPSecureFullDirectForDesired(desired)
}

func performanceKernelSecureCryptoForEndpointPolicy(endpoint config.EndpointConfig, policy config.TransportPolicyConfig) bool {
	if normalizeKernelTransportMode(policy.KernelTransport.Mode) == dataplane.KernelTransportModeDisabled {
		return false
	}
	switch transport.Protocol(strings.ToLower(strings.TrimSpace(endpoint.Transport))) {
	case transport.ProtocolExperimentalTCP, transport.ProtocolUDP:
	default:
		return false
	}
	profile := config.EffectiveEndpointProfile(endpoint, policy)
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
		placement = effectiveTransportCryptoPlacementConfig(policy)
	}
	return placement != string(dataplane.CryptoPlacementUserspace)
}

func secureKeySourceCode(source string) uint32 {
	switch source {
	case securetransport.KeySourceTrustIXX25519:
		return secureKeySourceTrustIXX25519Code
	case securetransport.KeySourceTLSExporter:
		return secureKeySourceTLSExporterCode
	default:
		return secureKeySourceAutoCode
	}
}

func secureEncryptionCode(encryption string) uint32 {
	switch encryption {
	case securetransport.EncryptionPlaintext:
		return secureEncryptionPlaintextCode
	case securetransport.EncryptionSendEncrypted:
		return secureEncryptionSendEncryptedCode
	case securetransport.EncryptionReceiveEncrypted:
		return secureEncryptionReceiveEncryptedCode
	default:
		return secureEncryptionSecureCode
	}
}
