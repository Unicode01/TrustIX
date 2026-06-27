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

func TestKernelDistroSupportOpenWrtSDKSpotCheckTracksCurrentMatrixTargets(t *testing.T) {
	payload, err := os.ReadFile("../docs/kernel-distro-support.md")
	if err != nil {
		t.Fatalf("read kernel distro support doc: %v", err)
	}
	source := string(payload)
	for _, want := range []string{
		"default `scripts/openwrt-full-datapath-kmod-matrix.sh` target list",
		"| `21.02.7 x86/64` | SDK `kernel-version.mk` | long-tail compile target; historical pass |",
		"| `21.02.7 armvirt/64` | SDK `kernel-version.mk` | long-tail compile target; historical pass |",
		"| `22.03.7 x86/64` | SDK `kernel-version.mk` | long-tail compile target; historical pass |",
		"| `22.03.7 armvirt/64` | SDK `kernel-version.mk` | long-tail compile target; historical pass |",
		"| `23.05.6 x86/64` | SDK `kernel-version.mk` | compile-matrix target; runtime not promoted |",
		"| `23.05.6 armsr/armv8` | SDK `kernel-version.mk` | compile-matrix target; runtime not promoted |",
		"| `24.10.7 x86/64` | `6.6.141` | SDK build plus full-kmod runtime gate promoted |",
		"| `24.10.7 armsr/armv8` | SDK `kernel-version.mk` | compile-matrix target; runtime not promoted |",
		"| `25.12.4 x86/64` | `6.12.87` | SDK build passed; route-GSO runtime failed closed |",
		"| `25.12.4 armsr/armv8` | SDK `kernel-version.mk` | compile-matrix target; runtime not promoted |",
		"table above is the current-source default matrix",
		"Runtime full-kmod coverage now",
		"includes OpenWrt 23.05.5, 24.10.2, and 24.10.7 x86_64",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("kernel distro support doc missing OpenWrt current SDK/runtime boundary fragment %q", want)
		}
	}
	for _, staleTableRow := range []string{
		"| `23.05.5 x86/64` |",
		"| `23.05.5 armsr/armv8` |",
		"| `24.10.2 x86/64` |",
		"| `24.10.2 armsr/armv8` |",
		"| `25.12.1 x86/64` |",
		"| `25.12.1 armsr/armv8` |",
	} {
		if strings.Contains(source, staleTableRow) {
			t.Fatalf("kernel distro support current SDK spot-check table still includes stale target row %q", staleTableRow)
		}
	}
}
