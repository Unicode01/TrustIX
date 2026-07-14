package daemon

import (
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/pki"
)

// ConfigCheckResult identifies the configuration that passed an offline check.
type ConfigCheckResult struct {
	ConfigPath    string
	DomainID      string
	IXID          string
	DataplaneMode string
	APIAddr       string
	PeerAPIAddr   string
}

// CheckConfig validates a daemon configuration without acquiring the data-dir
// lock, loading kernel modules, attaching a dataplane, or opening listeners.
func CheckConfig(cfg Config) (ConfigCheckResult, error) {
	if err := validateConfigCheckRuntime(cfg); err != nil {
		return ConfigCheckResult{}, err
	}
	desired, err := config.LoadFile(cfg.ConfigPath)
	if err != nil {
		return ConfigCheckResult{}, err
	}
	if err := verifyLocalRouteAuthorizations(desired); err != nil {
		return ConfigCheckResult{}, err
	}
	if err := validateConfigCheckCredentials(cfg, desired); err != nil {
		return ConfigCheckResult{}, err
	}
	if err := validateOpenWrtKernelModuleSources(effectiveKernelModulesForDesired(desired)); err != nil {
		return ConfigCheckResult{}, err
	}
	return ConfigCheckResult{
		ConfigPath:    cfg.ConfigPath,
		DomainID:      string(desired.Domain.ID),
		IXID:          string(desired.IX.ID),
		DataplaneMode: cfg.DataplaneMode,
		APIAddr:       cfg.APIAddr,
		PeerAPIAddr:   cfg.PeerAPIAddr,
	}, nil
}

func validateConfigCheckRuntime(cfg Config) error {
	switch cfg.DataplaneMode {
	case "", "noop", "linux", "auto":
	default:
		return fmt.Errorf("unsupported dataplane mode %q", cfg.DataplaneMode)
	}
	if err := validateConfigCheckListenAddress("management api", cfg.APIAddr, true); err != nil {
		return err
	}
	return validateConfigCheckListenAddress("peer api", cfg.PeerAPIAddr, false)
}

func validateConfigCheckListenAddress(label, value string, required bool) error {
	trimmed := strings.TrimSpace(value)
	if value != trimmed {
		return fmt.Errorf("%s listen address %q must not contain surrounding whitespace", label, value)
	}
	value = trimmed
	if value == "" {
		if required {
			return fmt.Errorf("%s listen address is required", label)
		}
		return nil
	}
	_, port, err := net.SplitHostPort(value)
	if err != nil || strings.TrimSpace(port) == "" {
		if err == nil {
			err = fmt.Errorf("port is required")
		}
		return fmt.Errorf("%s listen address %q is invalid: %w", label, value, err)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("%s listen address %q must use a numeric port between 1 and 65535", label, value)
	}
	return nil
}

func validateConfigCheckCredentials(cfg Config, desired config.Desired) error {
	if strings.TrimSpace(desired.IX.CertPath) == "" || strings.TrimSpace(desired.IX.KeyPath) == "" {
		return fmt.Errorf("ix cert and key are required")
	}
	certificate, err := loadTLSCertificateChecked(desired, desired.IX.CertPath, desired.IX.KeyPath, "local IX certificate")
	if err != nil {
		return fmt.Errorf("load local IX certificate: %w", err)
	}
	if len(certificate.Certificate) == 0 {
		return fmt.Errorf("local IX certificate has no leaf certificate")
	}
	leaf := certificate.Leaf
	if leaf == nil {
		leaf, err = x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return fmt.Errorf("parse local IX certificate: %w", err)
		}
	}
	metadata := pki.ParseMetadata(leaf)
	if metadata.Role != pki.RoleIX {
		return fmt.Errorf("local IX certificate role is %q, want %q", metadata.Role, pki.RoleIX)
	}
	if metadata.Domain != string(desired.Domain.ID) {
		return fmt.Errorf("local IX certificate domain is %q, want %q", metadata.Domain, desired.Domain.ID)
	}
	if metadata.IX != string(desired.IX.ID) {
		return fmt.Errorf("local IX certificate ix is %q, want %q", metadata.IX, desired.IX.ID)
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return fmt.Errorf("local IX certificate is not valid at current time")
	}

	checker := &Daemon{cfg: cfg, desired: desired}
	if _, err := checker.trustRootCertificates(); err != nil {
		return fmt.Errorf("load trust roots: %w", err)
	}
	if _, err := managementHostAPIListenAddressForDesired(desired, cfg.APIAddr); err != nil {
		return err
	}
	if configCheckManagementTLSRequired(checker) {
		if _, err := checker.managementServerTLSConfig(); err != nil {
			return fmt.Errorf("configure management api TLS: %w", err)
		}
	}
	identity := desired.TransportPolicy.TLSIdentity
	if normalizedTransportTLSIdentityMode(identity.Mode) == transportTLSIdentityCustomCert {
		if identity.CertPath != "" || identity.KeyPath != "" {
			if _, err := loadTLSCertificateChecked(desired, identity.CertPath, identity.KeyPath, "custom transport TLS certificate"); err != nil {
				return fmt.Errorf("load custom transport TLS certificate: %w", err)
			}
		}
		if _, err := transportTLSRootPool(identity); err != nil {
			return err
		}
	}
	return nil
}

func configCheckManagementTLSRequired(checker *Daemon) bool {
	if checker.managementTLSEnabledForListen(checker.cfg.APIAddr) {
		return true
	}
	listen, err := checker.managementHostAPIListenAddress()
	return err == nil && listen != "" && checker.managementTLSEnabledForListen(listen)
}
