package scripts

import (
	"os"
	"os/exec"
	"runtime"
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

func TestTrustIXPrereqsPinsPatchedGoToolchain(t *testing.T) {
	const version = "1.25.12"

	goMod, err := os.ReadFile("../go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	if !strings.Contains(string(goMod), "\ngo "+version+"\n") {
		t.Fatalf("go.mod must pin Go %s", version)
	}

	prereqs, err := os.ReadFile("trustix-prereqs.sh")
	if err != nil {
		t.Fatalf("read trustix-prereqs.sh: %v", err)
	}
	if !strings.Contains(string(prereqs), `version="`+version+`"`) {
		t.Fatalf("trustix-prereqs.sh fallback must pin Go %s", version)
	}
}

func TestTrustIXPrereqsEnforcesGoPatchFloor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a native GNU bash")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("GNU bash is unavailable")
	}

	const probe = `
set -euo pipefail
source ./trustix-prereqs.sh
while read -r actual required want; do
  if trustix_prereqs_go_version_at_least "$actual" "$required"; then
    got=yes
  else
    got=no
  fi
  if [[ "$got" != "$want" ]]; then
    printf 'actual=%s required=%s got=%s want=%s\n' "$actual" "$required" "$got" "$want" >&2
    exit 1
  fi
done <<'EOF'
go1.25.11 1.25.12 no
go1.25.12 1.25.12 yes
go1.25.13 1.25.12 yes
go1.26.0 1.25.12 yes
go2.0.0 1.25.12 yes
go1.24.99 1.25.12 no
devel 1.25.12 no
EOF
`
	cmd := exec.Command(bash, "-c", probe)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Go patch floor probe failed: %v\n%s", err, output)
	}
}
