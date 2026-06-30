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
