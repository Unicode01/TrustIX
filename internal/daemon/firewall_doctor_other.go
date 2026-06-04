//go:build !linux

package daemon

func firewallDoctorCheck() doctorCheck {
	return doctorCheck{Name: "firewall_compat", Status: "ok", Detail: "firewall compatibility check is Linux-only"}
}
