package daemon

import (
	"strings"
	"testing"

	"trustix.local/trustix/internal/config"
)

func TestManagementTLSEnabledForListen(t *testing.T) {
	daemon := &Daemon{cfg: Config{APIAddr: "127.0.0.1:8787"}}
	if daemon.managementTLSEnabledForListen("127.0.0.1:8787") {
		t.Fatal("auto management TLS should keep loopback HTTP")
	}
	if !daemon.managementTLSEnabledForListen("10.0.0.1:8787") {
		t.Fatal("auto management TLS should enable HTTPS on non-loopback listeners")
	}
	daemon.desired.Management.TLS.Mode = "required"
	if !daemon.managementTLSEnabledForListen("127.0.0.1:8787") {
		t.Fatal("required management TLS should enable HTTPS on loopback")
	}
	daemon.desired.Management.TLS.Mode = "disabled"
	if daemon.managementTLSEnabledForListen("10.0.0.1:8787") {
		t.Fatal("disabled management TLS should keep non-loopback HTTP")
	}
}

func TestManagementTLSDoctorDegradesNonLoopbackHTTP(t *testing.T) {
	daemon := &Daemon{
		cfg: Config{APIAddr: "0.0.0.0:8787"},
		desired: config.Desired{
			Management: config.ManagementConfig{
				TLS: config.ManagementTLSConfig{Mode: "disabled"},
			},
		},
	}

	check := daemon.managementTLSDoctorCheck()

	if check.Status != "degraded" || !strings.Contains(check.Detail, "not using HTTPS") {
		t.Fatalf("management tls doctor = %#v, want degraded HTTPS warning", check)
	}
}

func TestManagementTLSDoctorAcceptsAutoNetworkHTTPS(t *testing.T) {
	daemon := &Daemon{
		cfg: Config{APIAddr: "0.0.0.0:8787"},
	}

	check := daemon.managementTLSDoctorCheck()

	if check.Status != "ok" || !strings.Contains(check.Detail, "primary=https://0.0.0.0:8787") {
		t.Fatalf("management tls doctor = %#v, want auto HTTPS ok", check)
	}
}
