package daemon

import (
	"strings"
	"testing"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/transport"
	securetransport "trustix.local/trustix/internal/transport/secure"
)

func TestTransportTLSDoctorDegradesForcedExporterOnNonExporterEndpoints(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				CryptoKeySource: securetransport.KeySourceTLSExporter,
			},
			Peers: []config.PeerConfig{
				{
					ID:     core.IXID("ix-b"),
					Domain: core.DomainID("lab.local"),
					Endpoints: []config.EndpointConfig{
						{Name: core.EndpointID("b-udp"), Address: "203.0.113.20:7000", Transport: string(transport.ProtocolUDP)},
					},
				},
			},
		},
	}

	status := daemon.transportTLSStatus(dataPathStatus{})
	if got := transportTLSDoctorStatus(status); got != "degraded" {
		t.Fatalf("doctor status = %q, want degraded", got)
	}
	detail := transportTLSDoctorDetail(status)
	for _, want := range []string{"crypto_key_source=tls_exporter", "exporter_capable=0", "non_exporter=1"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("doctor detail %q does not contain %q", detail, want)
		}
	}
}

func TestTransportTLSDoctorAcceptsExporterBackedTLSSession(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{
				CryptoKeySource: securetransport.KeySourceTLSExporter,
			},
			Peers: []config.PeerConfig{
				{
					ID:     core.IXID("ix-b"),
					Domain: core.DomainID("lab.local"),
					Endpoints: []config.EndpointConfig{
						{Name: core.EndpointID("b-tcp"), Address: "203.0.113.20:7000", Transport: string(transport.ProtocolTCP)},
					},
				},
			},
		},
	}
	dataPath := dataPathStatus{
		Sessions: []dataPathSessionStatus{
			{
				Peer:      "ix-b",
				Endpoint:  "b-tcp",
				Transport: string(transport.ProtocolTCP),
				Stats: transport.TransportStats{
					CryptoKeySource: securetransport.KeySourceTLSExporter,
					LinkTLS:         true,
					TLSVersion:      "TLS 1.3",
					TLSCipherSuite:  "TLS_AES_128_GCM_SHA256",
				},
			},
		},
	}

	status := daemon.transportTLSStatus(dataPath)
	if got := transportTLSDoctorStatus(status); got != "ok" {
		t.Fatalf("doctor status = %q, want ok; detail=%s", got, transportTLSDoctorDetail(status))
	}
	if status.LinkTLSSessions != 1 || status.TLSExporterKeySessions != 1 {
		t.Fatalf("TLS session counts = link_tls:%d exporter:%d, want 1/1", status.LinkTLSSessions, status.TLSExporterKeySessions)
	}
}

func TestTransportTLSDoctorDegradesCustomCertPassiveListenerWithoutCertificate(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			Endpoints: []config.EndpointConfig{
				{Name: core.EndpointID("a-tcp"), Mode: config.EndpointModePassive, Listen: "127.0.0.1:7000", Transport: string(transport.ProtocolTCP), Enabled: true},
			},
			TransportPolicy: config.TransportPolicyConfig{
				TLSIdentity: config.TransportTLSIdentityConfig{
					Mode:        "custom_cert",
					SystemRoots: true,
				},
			},
		},
	}

	status := daemon.transportTLSStatus(dataPathStatus{})
	if got := transportTLSDoctorStatus(status); got != "degraded" {
		t.Fatalf("doctor status = %q, want degraded", got)
	}
	if len(status.Warnings) == 0 || !strings.Contains(status.Warnings[0], "cert/key") {
		t.Fatalf("warnings = %#v, want missing cert/key warning", status.Warnings)
	}
}

func TestTransportTLSDoctorDegradesTLSOnlySessionWithoutLinkTLS(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{Encryption: securetransport.EncryptionPlaintext},
			Peers: []config.PeerConfig{
				{
					ID:     core.IXID("ix-b"),
					Domain: core.DomainID("lab.local"),
					Endpoints: []config.EndpointConfig{
						{
							Name:      core.EndpointID("b-tcp"),
							Address:   "203.0.113.20:7000",
							Transport: string(transport.ProtocolTCP),
							Security: config.EndpointSecurityConfig{
								LinkTLS: "required",
							},
						},
					},
				},
			},
		},
	}
	dataPath := dataPathStatus{
		Sessions: []dataPathSessionStatus{
			{
				Peer:      "ix-b",
				Endpoint:  "b-tcp",
				Transport: string(transport.ProtocolTCP),
				Stats: transport.TransportStats{
					Encryption: securetransport.EncryptionPlaintext,
				},
			},
		},
	}

	status := daemon.transportTLSStatus(dataPath)
	if got := transportTLSDoctorStatus(status); got != "degraded" {
		t.Fatalf("doctor status = %q, want degraded; detail=%s", got, transportTLSDoctorDetail(status))
	}
	if status.TLSOnlyEndpoints != 1 || status.TLSOnlySessions != 1 || status.TLSOnlyMissingLinkTLS != 1 {
		t.Fatalf("TLS-only counts = endpoints:%d sessions:%d missing:%d, want 1/1/1", status.TLSOnlyEndpoints, status.TLSOnlySessions, status.TLSOnlyMissingLinkTLS)
	}
}

func TestTransportTLSDoctorAcceptsTLSOnlySessionWithLinkTLS(t *testing.T) {
	daemon := &Daemon{
		desired: config.Desired{
			TransportPolicy: config.TransportPolicyConfig{Encryption: securetransport.EncryptionPlaintext},
			Peers: []config.PeerConfig{
				{
					ID:     core.IXID("ix-b"),
					Domain: core.DomainID("lab.local"),
					Endpoints: []config.EndpointConfig{
						{
							Name:      core.EndpointID("b-tcp"),
							Address:   "203.0.113.20:7000",
							Transport: string(transport.ProtocolTCP),
							Security: config.EndpointSecurityConfig{
								LinkTLS: "required",
							},
						},
					},
				},
			},
		},
	}
	dataPath := dataPathStatus{
		Sessions: []dataPathSessionStatus{
			{
				Peer:      "ix-b",
				Endpoint:  "b-tcp",
				Transport: string(transport.ProtocolTCP),
				Stats: transport.TransportStats{
					Encryption: securetransport.EncryptionPlaintext,
					LinkTLS:    true,
				},
			},
		},
	}

	status := daemon.transportTLSStatus(dataPath)
	if got := transportTLSDoctorStatus(status); got != "ok" {
		t.Fatalf("doctor status = %q, want ok; detail=%s", got, transportTLSDoctorDetail(status))
	}
	if status.TLSOnlyEndpoints != 1 || status.TLSOnlySessions != 1 || status.TLSOnlyMissingLinkTLS != 0 {
		t.Fatalf("TLS-only counts = endpoints:%d sessions:%d missing:%d, want 1/1/0", status.TLSOnlyEndpoints, status.TLSOnlySessions, status.TLSOnlyMissingLinkTLS)
	}
}
