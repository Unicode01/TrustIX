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
		"2026-06-27, 2026-07-02, 2026-07-03, and 2026-07-04",
		"most recently on 2026-07-03",
		"`9235159503ed1746a41af9a86cbe9baebd67ed8f`",
		"`trustix_datapath.rx_worker_single_coalesce=N`",
		"OpenWrt-Debian full-kmod plaintext",
		"4.130908 Gbps",
		"OpenWrt-Debian experimental TCP full-kmod plaintext",
		"7.818210 Gbps",
		"Plaintext kernel UDP TC-direct",
		"3.196574 Gbps",
		"Experimental TCP full-kmod plaintext",
		"8.978477 Gbps",
		"Plaintext experimental TCP route-GSO",
		"7.515116 Gbps",
		"3600s per direction on Debian `6.12.94+deb13-cloud-amd64`, 2026-07-04, stopped-TXQ backoff enabled",
		"`add2971946b4948fbdd49d973aa94581b2e87a50`",
		"route-GSO async xmit",
		"stopped-TXQ drop error counters were zero",
		"Secure experimental TCP kernel crypto",
		"`experimental_tcp` / `secure` / `performance` / `kernel_module` / `kernel`",
		"4.543153 Gbps",
		"used commit `fa207ea`; minimum received throughput was 3.765459 Gbps",
		"minimum received throughput was 1.709080 Gbps",
		"against the 1.5 Gbps gate",
		"requires zero",
		"`replay_old` drops and bounds `replay_seen/open`",
		"minimum received throughput was 2.975477 Gbps",
		"minimum received throughput was\n7.515116 Gbps",
		"received throughput was 1.662160 Gbps",
		"dedicated `secure_exp_tcp_kernel`",
		"production default and must not reuse secure-kUDP evidence",
		"Route-TCP GSO/XMIT families are enabled only by selected policies",
		"production route-GSO uses separate cross-host gates",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("kernel distro support doc missing current production evidence fragment %q", want)
		}
	}
	if strings.Contains(source, "Route-GSO fallback | `experimental_tcp`") {
		t.Fatal("kernel distro support doc still describes selected plaintext route-GSO as fallback-only")
	}
}

func TestFirstRunDocsDoNotDescribeProductionRouteGSOAsHardDisabled(t *testing.T) {
	tests := []struct {
		path string
		want []string
	}{
		{
			path: "../docs/first-run.md",
			want: []string{
				"route_gso",
				"secure_kudp",
				"secure_exp_tcp_kernel",
				"route-TCP GSO/XMIT",
			},
		},
		{
			path: "../docs/implementation-boundaries.md",
			want: []string{
				"route-GSO/XMIT helper",
				"runtime 参数",
				"cross-host gate",
			},
		},
	}
	for _, tt := range tests {
		payload, err := os.ReadFile(tt.path)
		if err != nil {
			t.Fatalf("read %s: %v", tt.path, err)
		}
		source := string(payload)
		for _, want := range tt.want {
			if !strings.Contains(source, want) {
				t.Fatalf("%s missing current route-GSO helper boundary fragment %q", tt.path, want)
			}
		}
		for _, stale := range []string{
			"当前第一版只允许它报告安全 `gso_skb` helper 能力",
			"route-TCP GSO async、outer-GSO batch 和 TIXT RX stream/coalesce 第一版由模块 init 与 daemon 参数过滤共同 hard-disable",
			"route-TCP GSO async、route-TCP XMIT worker、outer-GSO batch、TIXT RX stream/coalesce 等曾触发 panic 或未完成验证的路径第一版 hard-disabled",
		} {
			if strings.Contains(source, stale) {
				t.Fatalf("%s still contains stale route-GSO hard-disabled wording %q", tt.path, stale)
			}
		}
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
