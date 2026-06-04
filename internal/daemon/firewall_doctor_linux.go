//go:build linux

package daemon

import (
	"fmt"
	"os"
	"strings"
)

func firewallDoctorCheck() doctorCheck {
	details := []string{
		procFileState("/proc/net/ip_tables_names", "iptables_ipv4_tables"),
		procFileState("/proc/net/ip6_tables_names", "iptables_ipv6_tables"),
		procFileState("/proc/net/nf_tables", "nftables"),
	}
	status := "ok"
	for _, detail := range details {
		if strings.Contains(detail, "unavailable") {
			status = "warn"
			break
		}
	}
	details = append(details, "trustix_managed_firewall_rules=false")
	return doctorCheck{Name: "firewall_compat", Status: status, Detail: strings.Join(details, " ")}
}

func procFileState(path, label string) string {
	payload, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("%s=unavailable(%s)", label, err)
	}
	lines := nonEmptyLineCount(string(payload))
	return fmt.Sprintf("%s=present(lines=%d)", label, lines)
}

func nonEmptyLineCount(payload string) int {
	count := 0
	for _, line := range strings.Split(payload, "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}
