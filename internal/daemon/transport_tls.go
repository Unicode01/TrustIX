package daemon

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/pki"
	"trustix.local/trustix/internal/transport"
)

const (
	transportTLSIdentityIXCert     = "ix_cert"
	transportTLSIdentityCustomCert = "custom_cert"
)

func (daemon *Daemon) dataTransportServerTLSConfig(endpoint config.EndpointConfig) (*tls.Config, error) {
	if !endpointUsesLinkTLS(endpoint) {
		return nil, nil
	}
	identity := daemon.desired.TransportPolicy.TLSIdentity
	switch normalizedTransportTLSIdentityMode(identity.Mode) {
	case transportTLSIdentityCustomCert:
		if identity.CertPath == "" || identity.KeyPath == "" {
			return nil, fmt.Errorf("custom transport TLS listener requires transport_policy tls_identity cert and key")
		}
		cert, err := tls.LoadX509KeyPair(identity.CertPath, identity.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("load custom transport TLS certificate: %w", err)
		}
		if len(cert.Certificate) > 0 {
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				return nil, fmt.Errorf("parse custom transport TLS certificate: %w", err)
			}
			if err := daemon.verifyCertificateNotRevoked(leaf, "custom transport TLS certificate"); err != nil {
				return nil, err
			}
		}
		return &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
		}, nil
	default:
		conf, err := daemon.dataTransportPeerServerTLSConfig()
		if err != nil {
			return nil, err
		}
		conf = conf.Clone()
		conf.MinVersion = tls.VersionTLS13
		return conf, nil
	}
}

func (daemon *Daemon) dataTransportClientTLSConfig(peer config.PeerConfig, endpoint config.EndpointConfig) (*tls.Config, error) {
	if !endpointUsesLinkTLS(endpoint) {
		return nil, nil
	}
	identity := daemon.desired.TransportPolicy.TLSIdentity
	switch normalizedTransportTLSIdentityMode(identity.Mode) {
	case transportTLSIdentityCustomCert:
		roots, err := transportTLSRootPool(identity)
		if err != nil {
			return nil, err
		}
		var certs []tls.Certificate
		if identity.CertPath != "" || identity.KeyPath != "" {
			cert, err := tls.LoadX509KeyPair(identity.CertPath, identity.KeyPath)
			if err != nil {
				return nil, fmt.Errorf("load custom transport TLS client certificate: %w", err)
			}
			certs = []tls.Certificate{cert}
		}
		return &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: certs,
			RootCAs:      roots,
			ServerName:   transportTLSServerName(peer, endpoint),
		}, nil
	default:
		conf, err := daemon.peerClientTLSConfig(peer)
		if err != nil {
			return nil, err
		}
		conf = conf.Clone()
		conf.MinVersion = tls.VersionTLS13
		return conf, nil
	}
}

func (daemon *Daemon) secureClientAuthTLSConfig(peer transport.Peer) (*tls.Config, error) {
	return daemon.peerClientTLSConfig(config.PeerConfig{
		ID:     peer.ID,
		Domain: peer.DomainID,
	})
}

func (daemon *Daemon) secureServerAuthTLSConfig() (*tls.Config, error) {
	return daemon.dataTransportPeerServerTLSConfig()
}

func normalizedTransportTLSIdentityMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case transportTLSIdentityCustomCert:
		return transportTLSIdentityCustomCert
	default:
		return transportTLSIdentityIXCert
	}
}

func transportTLSRootPool(identity config.TransportTLSIdentityConfig) (*x509.CertPool, error) {
	var roots *x509.CertPool
	if identity.SystemRoots {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system transport TLS roots: %w", err)
		}
		roots = pool
	}
	if roots == nil {
		roots = x509.NewCertPool()
	}
	for _, path := range identity.TrustRoots {
		cert, _, err := pki.LoadCertificate(path)
		if err != nil {
			return nil, err
		}
		roots.AddCert(cert)
	}
	return roots, nil
}

func transportTLSServerName(peer config.PeerConfig, endpoint config.EndpointConfig) string {
	if endpoint.TLSServerName != "" {
		return endpoint.TLSServerName
	}
	if peer.TLSServerName != "" {
		return peer.TLSServerName
	}
	host, _, err := net.SplitHostPort(endpoint.Address)
	if err == nil && host != "" {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(endpoint.Address, "[]")
}

func endpointUsesLinkTLS(endpoint config.EndpointConfig) bool {
	if !transportSupportsTLSExporter(transport.Protocol(strings.ToLower(strings.TrimSpace(endpoint.Transport)))) {
		return false
	}
	return normalizeEndpointLinkTLS(endpoint.Security.LinkTLS) != endpointLinkTLSUnsupported
}

func endpointRequiresLinkTLS(endpoint config.EndpointConfig) bool {
	return normalizeEndpointLinkTLS(endpoint.Security.LinkTLS) == endpointLinkTLSRequired
}

func requireEndpointLinkTLS(peer core.IXID, endpoint config.EndpointConfig, session transport.Session) error {
	if !endpointRequiresLinkTLS(endpoint) {
		return nil
	}
	if session != nil && session.Stats().LinkTLS {
		return nil
	}
	return fmt.Errorf("peer %q endpoint %q requires link TLS but session is not using link TLS", peer, endpoint.Name)
}
