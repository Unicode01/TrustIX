package scripts

import (
	"os"
	"strings"
	"testing"
)

func TestTrustIXPrereqsOpenWrtRuntimeIncludesVeth(t *testing.T) {
	payload, err := os.ReadFile("trustix-prereqs.sh")
	if err != nil {
		t.Fatalf("read trustix-prereqs.sh: %v", err)
	}
	text := string(payload)
	for _, want := range []string{
		"trustix_prereqs_ensure_openwrt_dataplane_runtime_deps()",
		"kmod-sched-core kmod-sched kmod-sched-bpf kmod-veth",
		"ip-full tc-bpf",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("trustix-prereqs.sh missing OpenWrt runtime dependency fragment %q", want)
		}
	}
}

func TestTrustIXPrereqsDownloadsHaveTotalAndStallTimeouts(t *testing.T) {
	payload, err := os.ReadFile("trustix-prereqs.sh")
	if err != nil {
		t.Fatalf("read trustix-prereqs.sh: %v", err)
	}
	text := string(payload)
	for _, want := range []string{
		`TRUSTIX_BOOTSTRAP_CONNECT_TIMEOUT:-8`,
		`TRUSTIX_BOOTSTRAP_DOWNLOAD_TIMEOUT:-600`,
		`TRUSTIX_BOOTSTRAP_STALL_TIMEOUT:-20`,
		`TRUSTIX_BOOTSTRAP_MIN_DOWNLOAD_SPEED:-1024`,
		`--max-time "$download_timeout"`,
		`--speed-time "$stall_timeout"`,
		`--speed-limit "$min_speed"`,
		`wget -T "$stall_timeout"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("trustix-prereqs.sh missing bounded download fragment %q", want)
		}
	}
}
