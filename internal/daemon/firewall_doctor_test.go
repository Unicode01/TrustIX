package daemon

import (
	"strings"
	"testing"
)

func TestFirewallDoctorStatusIgnoresUnavailableBackendsWhenUnmanaged(t *testing.T) {
	details := []string{
		"iptables_ipv4_tables=present(lines=0)",
		"iptables_ipv6_tables=unavailable(open /proc/net/ip6_tables_names: no such file or directory)",
		"nftables=unavailable(open /proc/net/nf_tables: no such file or directory)",
	}

	if got := firewallDoctorStatus(details, false); got != "ok" {
		t.Fatalf("status = %q, want ok", got)
	}
}

func TestFirewallDoctorStatusWarnsUnavailableBackendsWhenManaged(t *testing.T) {
	details := []string{
		"iptables_ipv4_tables=present(lines=0)",
		"nftables=unavailable(open /proc/net/nf_tables: no such file or directory)",
	}

	if got := firewallDoctorStatus(details, true); got != "warn" {
		t.Fatalf("status = %q, want warn", got)
	}
}

func TestFirewallDoctorStatusAcceptsPresentBackendsWhenManaged(t *testing.T) {
	details := []string{
		"iptables_ipv4_tables=present(lines=0)",
		"nftables=present(lines=2)",
	}

	if got := firewallDoctorStatus(details, true); got != "ok" {
		t.Fatalf("status = %q, want ok", got)
	}
}

func TestFirewallDoctorManagedRulesDetailShowsBackendRequirement(t *testing.T) {
	detail := firewallDoctorManagedRulesDetail(false)
	if !strings.Contains(detail, "trustix_managed_firewall_rules=false") {
		t.Fatalf("detail %q missing managed firewall flag", detail)
	}
	if !strings.Contains(detail, "firewall_backends_required=false") {
		t.Fatalf("detail %q missing backend requirement flag", detail)
	}
}
