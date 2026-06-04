package daemon

import (
	"crypto/tls"
	"fmt"
	"reflect"
	"strings"

	"trustix.local/trustix/internal/config"
)

const (
	managementTLSModeAuto     = "auto"
	managementTLSModeDisabled = "disabled"
	managementTLSModeRequired = "required"

	managementTLSIdentityIXCert     = "ix_cert"
	managementTLSIdentityCustomCert = "custom_cert"
)

type managementTLSStatus struct {
	Mode       string `json:"mode"`
	Identity   string `json:"identity"`
	Primary    bool   `json:"primary"`
	Host       bool   `json:"host,omitempty"`
	CustomCert string `json:"custom_cert,omitempty"`
}

func normalizedManagementTLSMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", managementTLSModeAuto:
		return managementTLSModeAuto
	case managementTLSModeDisabled, "off", "http":
		return managementTLSModeDisabled
	case managementTLSModeRequired, "require", "https":
		return managementTLSModeRequired
	default:
		return strings.ToLower(strings.TrimSpace(mode))
	}
}

func normalizedManagementTLSIdentity(identity string) string {
	switch strings.ToLower(strings.TrimSpace(identity)) {
	case "", managementTLSIdentityIXCert:
		return managementTLSIdentityIXCert
	case managementTLSIdentityCustomCert:
		return managementTLSIdentityCustomCert
	default:
		return strings.ToLower(strings.TrimSpace(identity))
	}
}

func (daemon *Daemon) managementTLSEnabledForListen(listen string) bool {
	return managementTLSEnabledForConfig(daemon.desired.Management.TLS, listen)
}

func managementTLSEnabledForConfig(tlsConfig config.ManagementTLSConfig, listen string) bool {
	switch normalizedManagementTLSMode(tlsConfig.Mode) {
	case managementTLSModeDisabled:
		return false
	case managementTLSModeRequired:
		return true
	default:
		return !apiAddrIsLoopback(listen)
	}
}

func (daemon *Daemon) managementAPIScheme(listen string) string {
	if daemon.managementTLSEnabledForListen(listen) {
		return "https"
	}
	return "http"
}

func (daemon *Daemon) managementServerTLSConfig() (*tls.Config, error) {
	tlsConfig := daemon.desired.Management.TLS
	var cert tls.Certificate
	var err error
	switch normalizedManagementTLSIdentity(tlsConfig.Identity) {
	case managementTLSIdentityCustomCert:
		if strings.TrimSpace(tlsConfig.CertPath) == "" || strings.TrimSpace(tlsConfig.KeyPath) == "" {
			return nil, fmt.Errorf("custom management TLS certificate and key are required")
		}
		cert, err = loadTLSCertificateChecked(daemon.desired, tlsConfig.CertPath, tlsConfig.KeyPath, "custom management TLS certificate")
	default:
		cert, err = loadTLSCertificateChecked(daemon.desired, daemon.desired.IX.CertPath, daemon.desired.IX.KeyPath, "management TLS IX certificate")
	}
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}, nil
}

func (daemon *Daemon) managementTLSStatus() managementTLSStatus {
	status := managementTLSStatus{
		Mode:     normalizedManagementTLSMode(daemon.desired.Management.TLS.Mode),
		Identity: normalizedManagementTLSIdentity(daemon.desired.Management.TLS.Identity),
		Primary:  daemon.managementTLSEnabledForListen(daemon.cfg.APIAddr),
	}
	if daemon.managementHostAPIEnabled() {
		if listen, err := daemon.managementHostAPIListenAddress(); err == nil {
			status.Host = daemon.managementTLSEnabledForListen(listen)
		}
	}
	if status.Identity == managementTLSIdentityCustomCert {
		status.CustomCert = strings.TrimSpace(daemon.desired.Management.TLS.CertPath)
	}
	return status
}

func (daemon *Daemon) managementTLSDoctorCheck() doctorCheck {
	mode := normalizedManagementTLSMode(daemon.desired.Management.TLS.Mode)
	identity := normalizedManagementTLSIdentity(daemon.desired.Management.TLS.Identity)
	status := "ok"
	details := []string{fmt.Sprintf("mode=%s identity=%s", mode, identity)}
	appendListener := func(name, listen string) {
		tlsEnabled := daemon.managementTLSEnabledForListen(listen)
		details = append(details, fmt.Sprintf("%s=%s://%s", name, daemon.managementAPIScheme(listen), listen))
		if !tlsEnabled && !apiAddrIsLoopback(listen) {
			status = worstDoctorStatus(status, "degraded")
			details = append(details, fmt.Sprintf("%s non-loopback listener is not using HTTPS", name))
		}
	}
	appendListener("primary", daemon.cfg.APIAddr)
	if daemon.managementHostAPIEnabled() {
		listen, err := daemon.managementHostAPIListenAddress()
		if err != nil {
			status = worstDoctorStatus(status, "degraded")
			details = append(details, err.Error())
		} else {
			appendListener("host", listen)
		}
	}
	for _, target := range daemon.managementVIPTargets() {
		appendListener("management_vip", target.listenAddress())
	}
	if identity == managementTLSIdentityIXCert {
		details = append(details, "ix_cert may require installing the TrustIX CA or using a matching server name in browser/CLI clients")
	}
	return doctorCheck{Name: "management_tls", Status: status, Detail: strings.Join(details, "; ")}
}

func managementTLSServerConfigChanged(oldDesired, newDesired config.Desired) bool {
	return oldDesired.IX.CertPath != newDesired.IX.CertPath ||
		oldDesired.IX.KeyPath != newDesired.IX.KeyPath ||
		oldDesired.Management.TLS != newDesired.Management.TLS ||
		!reflect.DeepEqual(effectiveLANGateways(oldDesired), effectiveLANGateways(newDesired))
}

func managementPrimaryAPINeedsRestart(oldDesired, newDesired config.Desired, listen string) bool {
	if !managementTLSServerConfigChanged(oldDesired, newDesired) {
		return false
	}
	return managementTLSEnabledForConfig(oldDesired.Management.TLS, listen) ||
		managementTLSEnabledForConfig(newDesired.Management.TLS, listen)
}
