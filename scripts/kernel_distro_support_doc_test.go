package scripts

import (
	"os"
	"strings"
	"testing"
)

func TestKernelDistroSupportUsesCurrentProductionEvidenceBoundary(t *testing.T) {
	payload, err := os.ReadFile("../docs/kernel-distro-support.md")
	if err != nil {
		t.Fatalf("read kernel distro support doc: %v", err)
	}
	source := string(payload)
	for _, want := range []string{
		"later 3600s manifest-backed rechecks now provide the",
		"Plaintext experimental TCP route-GSO",
		"2.829761 Gbps",
		"3600s per direction on Debian `6.12.94+deb13-cloud-amd64`, 2026-06-22",
		"Secure experimental TCP kernel crypto",
		"`experimental_tcp` / `secure` / `performance` / `kernel_module` / `kernel`",
		"1.599325 Gbps",
		"3600s per direction on Debian `6.12.90+deb13.1-cloud-amd64`, 2026-06-25",
		"Minimum received throughput was 1.634107 Gbps against the 1.5 Gbps gate",
		"requires zero `replay_old` drops and bounds `replay_seen/open`",
		"Minimum received throughput was 2.829761 Gbps against the 2.5 Gbps gate",
		"Minimum received throughput was 1.599325 Gbps against the 1.5 Gbps gate",
		"dedicated `secure_exp_tcp_kernel` production default and must not reuse",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("kernel distro support doc missing current production evidence fragment %q", want)
		}
	}
	if strings.Contains(source, "Route-GSO fallback | `experimental_tcp`") {
		t.Fatal("kernel distro support doc still describes selected plaintext route-GSO as fallback-only")
	}
}
