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
		"Plaintext kernel UDP TC-direct",
		"3.765459 Gbps",
		"Plaintext experimental TCP route-GSO",
		"2.975477 Gbps",
		"3600s per direction on Debian `6.12.94+deb13-cloud-amd64`, 2026-06-26",
		"Secure experimental TCP kernel crypto",
		"`experimental_tcp` / `secure` / `performance` / `kernel_module` / `kernel`",
		"1.662160 Gbps",
		"used commit `fa207ea`; minimum received throughput was 3.765459 Gbps",
		"minimum received throughput was 1.709080 Gbps",
		"against the 1.5 Gbps gate",
		"requires zero",
		"`replay_old` drops and bounds `replay_seen/open`",
		"minimum received throughput was 2.975477 Gbps",
		"received throughput was 1.662160 Gbps",
		"dedicated `secure_exp_tcp_kernel`",
		"production default and must not reuse secure-kUDP evidence",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("kernel distro support doc missing current production evidence fragment %q", want)
		}
	}
	if strings.Contains(source, "Route-GSO fallback | `experimental_tcp`") {
		t.Fatal("kernel distro support doc still describes selected plaintext route-GSO as fallback-only")
	}
}
