package daemon

import (
	"fmt"
	"strings"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/transport"
	securetransport "trustix.local/trustix/internal/transport/secure"
)

type transportTLSStatus struct {
	Encryption                    string   `json:"encryption"`
	CryptoKeySource               string   `json:"crypto_key_source"`
	CryptoSuites                  []string `json:"crypto_suites"`
	TLSIdentityMode               string   `json:"tls_identity_mode"`
	WireFormat                    string   `json:"wire_format"`
	CustomCertificate             bool     `json:"custom_certificate,omitempty"`
	SystemRoots                   bool     `json:"system_roots,omitempty"`
	TrustRoots                    int      `json:"trust_roots,omitempty"`
	ConfiguredEndpoints           int      `json:"configured_endpoints"`
	ExporterCapableEndpoints      int      `json:"exporter_capable_endpoints"`
	NonExporterEndpoints          int      `json:"non_exporter_endpoints"`
	PassiveListeners              int      `json:"passive_listeners"`
	ActiveSessions                int      `json:"active_sessions"`
	LinkTLSSessions               int      `json:"link_tls_sessions"`
	TLSExporterKeySessions        int      `json:"tls_exporter_key_sessions"`
	TLSExporterWithoutLinkTLS     int      `json:"tls_exporter_without_link_tls"`
	RequiredLinkTLSEndpoints      int      `json:"required_link_tls_endpoints"`
	RequiredLinkTLSSessions       int      `json:"required_link_tls_sessions"`
	RequiredLinkTLSMissing        int      `json:"required_link_tls_missing"`
	TLSOnlyEndpoints              int      `json:"tls_only_endpoints"`
	TLSOnlySessions               int      `json:"tls_only_sessions"`
	TLSOnlyMissingLinkTLS         int      `json:"tls_only_missing_link_tls"`
	LinkTLSSessionsSeen           uint64   `json:"link_tls_sessions_seen"`
	TLSExporterKeySessionsSeen    uint64   `json:"tls_exporter_key_sessions_seen"`
	TLSExporterWithoutLinkTLSSeen uint64   `json:"tls_exporter_without_link_tls_seen"`
	LastLinkTLSVersion            string   `json:"last_link_tls_version,omitempty"`
	LastLinkTLSCipherSuite        string   `json:"last_link_tls_cipher_suite,omitempty"`
	Warnings                      []string `json:"warnings,omitempty"`
}

func (daemon *Daemon) transportTLSStatus(dataPath dataPathStatus) transportTLSStatus {
	status := transportTLSStatus{
		Encryption:                    parseSecureTransportEncryption(daemon.desired.TransportPolicy.Encryption),
		CryptoKeySource:               parseSecureTransportKeySource(daemon.desired.TransportPolicy.CryptoKeySource),
		CryptoSuites:                  securetransport.CryptoSuitesOrDefault(daemon.desired.TransportPolicy.CryptoSuites),
		TLSIdentityMode:               normalizedTransportTLSIdentityMode(daemon.desired.TransportPolicy.TLSIdentity.Mode),
		WireFormat:                    transport.CryptoWireFormatTrustIXSecureDataV1,
		SystemRoots:                   daemon.desired.TransportPolicy.TLSIdentity.SystemRoots,
		TrustRoots:                    len(daemon.desired.TransportPolicy.TLSIdentity.TrustRoots),
		ActiveSessions:                len(dataPath.Sessions),
		PassiveListeners:              enabledPassiveEndpointCount(daemon.desired.Endpoints),
		LinkTLSSessionsSeen:           dataPath.TLS.LinkTLSSessionsSeen,
		TLSExporterKeySessionsSeen:    dataPath.TLS.TLSExporterSessionsSeen,
		TLSExporterWithoutLinkTLSSeen: dataPath.TLS.TLSExporterNoLinkSeen,
		LastLinkTLSVersion:            dataPath.TLS.LastLinkTLSVersion,
		LastLinkTLSCipherSuite:        dataPath.TLS.LastLinkTLSCipherSuite,
	}
	identity := daemon.desired.TransportPolicy.TLSIdentity
	status.CustomCertificate = identity.CertPath != "" && identity.KeyPath != ""

	for _, endpoint := range daemon.desired.Endpoints {
		if !endpoint.Enabled {
			continue
		}
		status.recordEndpoint(endpoint, status.Encryption)
	}
	for _, peer := range daemon.desired.Peers {
		for _, endpoint := range peer.Endpoints {
			status.recordEndpoint(endpoint, status.Encryption)
		}
	}
	for _, session := range dataPath.Sessions {
		if session.Stats.LinkTLS {
			status.LinkTLSSessions++
		}
		if endpoint, ok := daemon.statusEndpointConfig(session); ok {
			if endpointRequiresLinkTLS(endpoint) {
				status.RequiredLinkTLSSessions++
				if !session.Stats.LinkTLS {
					status.RequiredLinkTLSMissing++
				}
			}
			if statusEndpointIsTLSOnly(endpoint, status.Encryption) {
				status.TLSOnlySessions++
				if !session.Stats.LinkTLS {
					status.TLSOnlyMissingLinkTLS++
				}
			}
		}
		if session.Stats.CryptoKeySource == securetransport.KeySourceTLSExporter {
			status.TLSExporterKeySessions++
			if !session.Stats.LinkTLS {
				status.TLSExporterWithoutLinkTLS++
			}
		}
	}
	status.Warnings = transportTLSWarnings(status)
	return status
}

func (status *transportTLSStatus) recordEndpoint(endpoint config.EndpointConfig, globalEncryption string) {
	status.ConfiguredEndpoints++
	if endpointUsesLinkTLS(endpoint) {
		status.ExporterCapableEndpoints++
	} else {
		status.NonExporterEndpoints++
	}
	if endpointRequiresLinkTLS(endpoint) {
		status.RequiredLinkTLSEndpoints++
	}
	if statusEndpointIsTLSOnly(endpoint, globalEncryption) {
		status.TLSOnlyEndpoints++
	}
}

func transportSupportsTLSExporter(protocol transport.Protocol) bool {
	switch protocol {
	case transport.ProtocolTCP, transport.ProtocolWebSocket, transport.ProtocolHTTPConnect, transport.ProtocolQUIC:
		return true
	default:
		return false
	}
}

func enabledPassiveEndpointCount(endpoints []config.EndpointConfig) int {
	count := 0
	for _, endpoint := range endpoints {
		if endpoint.Enabled && endpoint.Mode == config.EndpointModePassive && endpointUsesLinkTLS(endpoint) {
			count++
		}
	}
	return count
}

func transportTLSWarnings(status transportTLSStatus) []string {
	var warnings []string
	if status.TLSIdentityMode == transportTLSIdentityCustomCert {
		if status.PassiveListeners > 0 && !status.CustomCertificate {
			warnings = append(warnings, "custom_cert mode has enabled passive listeners but transport cert/key are not configured")
		}
		if !status.SystemRoots && status.TrustRoots == 0 {
			warnings = append(warnings, "custom_cert mode has no transport trust roots")
		}
	}
	if status.Encryption != securetransport.EncryptionPlaintext && status.CryptoKeySource == securetransport.KeySourceTLSExporter {
		switch {
		case status.ConfiguredEndpoints > 0 && status.ExporterCapableEndpoints == 0:
			warnings = append(warnings, "crypto_key_source=tls_exporter requires tcp, websocket, http_connect, or quic endpoints")
		case status.NonExporterEndpoints > 0:
			warnings = append(warnings, fmt.Sprintf("%d configured endpoint(s) cannot export TLS keying material and will fail if selected with crypto_key_source=tls_exporter", status.NonExporterEndpoints))
		}
		if status.ActiveSessions > 0 && status.TLSExporterKeySessions != status.ActiveSessions {
			warnings = append(warnings, fmt.Sprintf("crypto_key_source=tls_exporter is configured but only %d/%d active session(s) use TLS exporter keys", status.TLSExporterKeySessions, status.ActiveSessions))
		}
	}
	if status.TLSExporterWithoutLinkTLS > 0 {
		warnings = append(warnings, fmt.Sprintf("%d active session(s) report TLS exporter keys without link TLS", status.TLSExporterWithoutLinkTLS))
	}
	if status.TLSExporterWithoutLinkTLSSeen > 0 {
		warnings = append(warnings, fmt.Sprintf("%d observed session(s) reported TLS exporter keys without link TLS", status.TLSExporterWithoutLinkTLSSeen))
	}
	if status.RequiredLinkTLSMissing > 0 {
		warnings = append(warnings, fmt.Sprintf("%d active session(s) require link TLS but are not using link TLS", status.RequiredLinkTLSMissing))
	}
	if status.TLSOnlyMissingLinkTLS > 0 {
		warnings = append(warnings, fmt.Sprintf("%d active TLS-only session(s) are missing link TLS", status.TLSOnlyMissingLinkTLS))
	}
	return warnings
}

func transportTLSDoctorCheck(status transportTLSStatus) doctorCheck {
	return doctorCheck{
		Name:   "transport_tls",
		Status: transportTLSDoctorStatus(status),
		Detail: transportTLSDoctorDetail(status),
	}
}

func transportTLSDoctorStatus(status transportTLSStatus) string {
	if status.TLSIdentityMode == transportTLSIdentityCustomCert && status.PassiveListeners > 0 && !status.CustomCertificate {
		return "degraded"
	}
	if status.Encryption != securetransport.EncryptionPlaintext && status.CryptoKeySource == securetransport.KeySourceTLSExporter {
		if status.ConfiguredEndpoints > 0 && status.ExporterCapableEndpoints == 0 {
			return "degraded"
		}
		if status.ActiveSessions > 0 && status.TLSExporterKeySessions != status.ActiveSessions {
			return "degraded"
		}
	}
	if status.TLSExporterWithoutLinkTLS > 0 {
		return "degraded"
	}
	if status.TLSExporterWithoutLinkTLSSeen > 0 {
		return "degraded"
	}
	if status.RequiredLinkTLSMissing > 0 {
		return "degraded"
	}
	if status.TLSOnlyMissingLinkTLS > 0 {
		return "degraded"
	}
	if len(status.Warnings) > 0 {
		return "warn"
	}
	return "ok"
}

func transportTLSDoctorDetail(status transportTLSStatus) string {
	detail := fmt.Sprintf("encryption=%s crypto_key_source=%s crypto_suites=%s tls_identity=%s wire_format=%s endpoints=%d exporter_capable=%d non_exporter=%d required_link_tls_endpoints=%d tls_only_endpoints=%d passive_listeners=%d active_sessions=%d link_tls_sessions=%d required_link_tls_sessions=%d required_link_tls_missing=%d tls_only_sessions=%d tls_only_missing_link_tls=%d tls_exporter_key_sessions=%d link_tls_seen=%d tls_exporter_seen=%d",
		status.Encryption,
		status.CryptoKeySource,
		strings.Join(status.CryptoSuites, ","),
		status.TLSIdentityMode,
		status.WireFormat,
		status.ConfiguredEndpoints,
		status.ExporterCapableEndpoints,
		status.NonExporterEndpoints,
		status.RequiredLinkTLSEndpoints,
		status.TLSOnlyEndpoints,
		status.PassiveListeners,
		status.ActiveSessions,
		status.LinkTLSSessions,
		status.RequiredLinkTLSSessions,
		status.RequiredLinkTLSMissing,
		status.TLSOnlySessions,
		status.TLSOnlyMissingLinkTLS,
		status.TLSExporterKeySessions,
		status.LinkTLSSessionsSeen,
		status.TLSExporterKeySessionsSeen,
	)
	if len(status.Warnings) > 0 {
		detail += " warnings=" + strings.Join(status.Warnings, "; ")
	}
	return detail
}

func (daemon *Daemon) statusEndpointConfig(session dataPathSessionStatus) (config.EndpointConfig, bool) {
	return daemon.statusPeerEndpointConfig(session.Peer, session.Endpoint, session.Transport)
}

func (daemon *Daemon) statusPeerEndpointConfig(peerID string, name string, rawTransport string) (config.EndpointConfig, bool) {
	for _, peer := range daemon.desired.Peers {
		if string(peer.ID) != peerID {
			continue
		}
		for _, endpoint := range peer.Endpoints {
			if string(endpoint.Name) == name && strings.EqualFold(strings.TrimSpace(endpoint.Transport), strings.TrimSpace(rawTransport)) {
				return endpoint, true
			}
		}
		return config.EndpointConfig{}, false
	}
	return config.EndpointConfig{}, false
}

func statusEndpointIsTLSOnly(endpoint config.EndpointConfig, globalEncryption string) bool {
	encryption := parseSecureTransportEncryption(globalEncryption)
	if strings.TrimSpace(endpoint.Security.Encryption) != "" {
		encryption = parseSecureTransportEncryption(endpoint.Security.Encryption)
	}
	return encryption == securetransport.EncryptionPlaintext &&
		endpointRequiresLinkTLS(endpoint)
}
