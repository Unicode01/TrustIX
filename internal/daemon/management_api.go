package daemon

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"trustix.local/trustix/internal/config"
)

func (daemon *Daemon) managementHostAPIEnabled() bool {
	return daemon.desired.Management.HostAPI.Enabled
}

func (daemon *Daemon) managementHostAPIWriteAuthRequired() bool {
	return daemon.managementHostAPIWriteAuthRequiredForDesired(daemon.desired)
}

func (daemon *Daemon) managementHostAPIWriteAuthRequiredForDesired(desired config.Desired) bool {
	hostAPI := desired.Management.HostAPI
	if daemon.cfg.APIAdminAuth {
		return true
	}
	return hostAPI.Enabled && !hostAPI.AllowUnauthenticatedWrites
}

func (daemon *Daemon) managementHostAPIReadAuthRequired() bool {
	return managementHostAPIReadAuthRequiredForDesired(daemon.desired)
}

func managementHostAPIReadAuthRequiredForDesired(desired config.Desired) bool {
	hostAPI := desired.Management.HostAPI
	return hostAPI.Enabled && !hostAPI.AllowUnauthenticatedReads
}

func (daemon *Daemon) managementPrimaryAPIReadAuthRequired() bool {
	return daemon.cfg.APIAdminAuth && !apiAddrIsLoopback(daemon.cfg.APIAddr)
}

func (daemon *Daemon) managementHostAPIListenAddress() (string, error) {
	return managementHostAPIListenAddressForDesired(daemon.desired, daemon.cfg.APIAddr)
}

func managementHostAPIListenAddressForDesired(desired config.Desired, apiAddr string) (string, error) {
	hostAPI := desired.Management.HostAPI
	if !hostAPI.Enabled {
		return "", nil
	}
	if strings.TrimSpace(hostAPI.Listen) != "" {
		return strings.TrimSpace(hostAPI.Listen), nil
	}
	lan, ok := config.FirstLANGatewayLAN(desired)
	if !ok {
		return "", fmt.Errorf("management host_api listen is not configured and lan gateway is empty")
	}
	prefix, err := netip.ParsePrefix(lan.Gateway)
	if err != nil {
		return "", fmt.Errorf("parse lan gateway for management host_api: %w", err)
	}
	port, err := apiListenPort(apiAddr)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(prefix.Addr().String(), port), nil
}

func apiListenPort(addr string) (string, error) {
	_, port, err := net.SplitHostPort(addr)
	if err == nil && port != "" {
		return port, nil
	}
	return "", fmt.Errorf("parse management api listen address %q: %w", addr, err)
}

func (daemon *Daemon) managementAPIStatus() managementAPIStatus {
	status := managementAPIStatus{
		Primary: managementAPIListenerStatus{
			Enabled:   true,
			Listen:    daemon.cfg.APIAddr,
			Scheme:    daemon.managementAPIScheme(daemon.cfg.APIAddr),
			TLS:       daemon.managementTLSEnabledForListen(daemon.cfg.APIAddr),
			Scope:     managementAPIScope(daemon.cfg.APIAddr),
			WriteAuth: daemon.cfg.APIAdminAuth,
			ReadAuth:  daemon.managementPrimaryAPIReadAuthRequired(),
		},
		TLS:   daemon.managementTLSStatus(),
		WebUI: daemon.managementWebUIStatus(),
	}
	hostAPI := daemon.desired.Management.HostAPI
	if !hostAPI.Enabled {
		return status
	}
	host := managementAPIListenerStatus{
		Enabled:   true,
		Scope:     "host",
		WriteAuth: daemon.managementHostAPIWriteAuthRequired(),
		ReadAuth:  daemon.managementHostAPIReadAuthRequired(),
	}
	listen, err := daemon.managementHostAPIListenAddress()
	if err != nil {
		host.Error = err.Error()
	} else {
		host.Listen = listen
		host.Scheme = daemon.managementAPIScheme(listen)
		host.TLS = daemon.managementTLSEnabledForListen(listen)
	}
	status.Host = &host
	return status
}

func managementAPIScope(addr string) string {
	if apiAddrIsLoopback(addr) {
		return "loopback"
	}
	return "network"
}
