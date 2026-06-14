package daemon

import (
	"fmt"
	"os"
	"strings"
)

func trustixManagedFirewallRulesEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_OPENWRT_FIREWALL_RULES"))) {
	case "1", "true", "yes", "on", "enabled", "auto":
		return true
	default:
		return false
	}
}

func firewallDoctorStatus(details []string, managedRules bool) string {
	if !managedRules {
		return "ok"
	}
	for _, detail := range details {
		if strings.Contains(detail, "unavailable") {
			return "warn"
		}
	}
	return "ok"
}

func firewallDoctorManagedRulesDetail(managedRules bool) string {
	return fmt.Sprintf("trustix_managed_firewall_rules=%t firewall_backends_required=%t", managedRules, managedRules)
}
