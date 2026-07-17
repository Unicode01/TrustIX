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

func TestTrustIXPrereqsSelectsReachableGoProxy(t *testing.T) {
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
expected='https://goproxy.cn|https://mirrors.aliyun.com/goproxy/|https://goproxy.io|direct'

unset GOPROXY TRUSTIX_BOOTSTRAP_GOPROXY
TRUSTIX_BOOTSTRAP_MIRRORS=auto
trustix_prereqs_prepare_go_module_network
[[ "$GOPROXY" == "$expected" ]]

GOPROXY=https://proxy.example.test
trustix_prereqs_prepare_go_module_network
[[ "$GOPROXY" == https://proxy.example.test ]]

TRUSTIX_BOOTSTRAP_GOPROXY=https://override.example.test
trustix_prereqs_prepare_go_module_network
[[ "$GOPROXY" == https://override.example.test ]]

unset GOPROXY TRUSTIX_BOOTSTRAP_GOPROXY
TRUSTIX_BOOTSTRAP_MIRRORS=off
trustix_prereqs_prepare_go_module_network
[[ -z "${GOPROXY:-}" ]]
`
	cmd := exec.Command(bash, "-c", probe)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Go proxy selection probe failed: %v\n%s", err, output)
	}
}

func TestTrustIXPrereqsOfficialGoInstallPropagatesLinkFailureWithoutErrexit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a native GNU bash")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("GNU bash is unavailable")
	}

	const probe = `
set -u
source ./trustix-prereqs.sh
root="$(command mktemp -d /tmp/trustix-prereqs-test.XXXXXX)"
trap 'command rm -rf "$root"' EXIT
export TRUSTIX_BOOTSTRAP_GO_VERSION=1.25.12
export TRUSTIX_BOOTSTRAP_GO_ROOT="$root/install"
export TRUSTIX_BOOTSTRAP_GO_BIN_DIR="$root/bin"

mktemp() {
  if [[ "${1:-}" == "-d" ]]; then
    command mkdir -p "$root/stage"
    printf '%s\n' "$root/stage"
  else
    : >"$root/archive"
    printf '%s\n' "$root/archive"
  fi
}
trustix_prereqs_go_arch() { printf 'amd64\n'; }
trustix_prereqs_download_file() { : >"$1"; }
tar() {
  local stage="" previous=""
  for arg in "$@"; do
    if [[ "$previous" == "-C" ]]; then stage="$arg"; fi
    previous="$arg"
  done
  command mkdir -p "$stage/go/bin"
  printf '#!/bin/sh\nexit 0\n' >"$stage/go/bin/go"
  printf '#!/bin/sh\nexit 0\n' >"$stage/go/bin/gofmt"
  command chmod 0755 "$stage/go/bin/go" "$stage/go/bin/gofmt"
}
trustix_prereqs_run_root() {
  if [[ "${1:-}" == "ln" && "${3:-}" == */bin/gofmt ]]; then
    return 42
  fi
  command "$@"
}

if trustix_prereqs_install_official_go; then
  echo 'install unexpectedly succeeded' >&2
  exit 1
fi
[[ ! -e "$root/archive" ]]
[[ ! -e "$root/stage" ]]
[[ ! -e "$root/install/go1.25.12" ]]
[[ ! -e "$root/bin/go" ]]
[[ ! -e "$root/bin/gofmt" ]]

command mkdir -p "$root/install/go1.25.12/bin" "$root/bin"
printf '#!/bin/sh\necho old-go\n' >"$root/install/go1.25.12/bin/go"
printf '#!/bin/sh\necho old-gofmt\n' >"$root/install/go1.25.12/bin/gofmt"
command chmod 0755 "$root/install/go1.25.12/bin/go" "$root/install/go1.25.12/bin/gofmt"
command ln -s "$root/install/go1.25.12/bin/go" "$root/bin/go"
command ln -s "$root/install/go1.25.12/bin/gofmt" "$root/bin/gofmt"

if trustix_prereqs_install_official_go; then
  echo 'replacement install unexpectedly succeeded' >&2
  exit 1
fi
[[ "$("$root/bin/go")" == "old-go" ]]
[[ "$("$root/bin/gofmt")" == "old-gofmt" ]]
[[ "$(readlink "$root/bin/go")" == "$root/install/go1.25.12/bin/go" ]]
[[ "$(readlink "$root/bin/gofmt")" == "$root/install/go1.25.12/bin/gofmt" ]]
if find "$root/install" -maxdepth 1 -name '.trustix-go-rollback.*' -print | grep -q .; then
  echo 'replacement rollback directory was not removed' >&2
  exit 1
fi
`
	cmd := exec.Command(bash, "-c", probe)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("official Go install failure probe failed: %v\n%s", err, output)
	}
}

func TestReleaseBuildPreparesGoModuleNetwork(t *testing.T) {
	payload, err := os.ReadFile("build-release-linux.sh")
	if err != nil {
		t.Fatalf("read build-release-linux.sh: %v", err)
	}
	if !strings.Contains(string(payload), "trustix_prereqs_prepare_go_module_network") {
		t.Fatal("build-release-linux.sh must prepare the Go module network before building")
	}
}
