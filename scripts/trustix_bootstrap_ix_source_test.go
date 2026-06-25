package scripts

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

func TestTrustIXBootstrapIXScriptSyntax(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	version, err := exec.Command(bash, "-c", "printf '%s' \"${BASH_VERSINFO[0]:-0}\"").Output()
	major, parseErr := strconv.Atoi(strings.TrimSpace(string(version)))
	if err != nil || parseErr != nil || major < 4 {
		t.Skip("GNU bash 4+ not available")
	}
	cmd := exec.Command(bash, "-n", "trustix-bootstrap-ix.sh")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n trustix-bootstrap-ix.sh: %v\n%s", err, out)
	}
}

func TestTrustIXBootstrapIXDirectDefaultsMatchProductionProfile(t *testing.T) {
	payload, err := os.ReadFile("trustix-bootstrap-ix.sh")
	if err != nil {
		t.Fatalf("read trustix-bootstrap-ix.sh: %v", err)
	}
	script := string(payload)
	mustContain := []string{
		`profile="plaintext_performance"`,
		`--profile PROFILE`,
		`profile_transport_profile="performance"`,
		`profile_datapath="kernel_module"`,
		`profile_encryption="plaintext"`,
		`profile_crypto_placement="userspace"`,
		`profile_kernel_transport="require_kernel"`,
		`profile_kernel_capability="full_plaintext"`,
		`OpenWrt secure performance route-GSO is not a production default yet`,
		`crypto_module_mode="disabled"`,
		`datapath_module_mode="required"`,
		`helpers_module_mode="disabled"`,
		`go run ./cmd/trustix-ca "$@") >&2`,
		`"$trustix_ca_cmd" "$@" >&2`,
		`"capability_profile":"%s"`,
		`"datapath":{"rx_stage":"worker","rx_worker":true,"tx_plaintext":true,"full_plaintext":true,"rx_worker_allow_experimental_tcp":true}`,
		`"session_pool":{"warmup":true}`,
		`"profile":"%s","datapath":"%s","encryption":"%s","crypto_key_source":"auto","crypto_placement":"%s","kernel_transport":{"mode":"%s"}`,
		`trustix_bootstrap_mktemp_dir()`,
		`trustix_bootstrap_mktemp_file()`,
		`payload="$(trustix_bootstrap_mktemp_file trustix-provision-payload)"`,
		`TRUSTIX_BOOTSTRAP_KEEP_WORKDIR`,
		`rm -rf "$repo_root" || true`,
	}
	for _, want := range mustContain {
		if !strings.Contains(script, want) {
			t.Fatalf("trustix-bootstrap-ix.sh missing production default fragment %q", want)
		}
	}
	forbidden := []string{
		`"profile":"stable","datapath":"auto","encryption":"secure","crypto_key_source":"auto","crypto_placement":"auto","kernel_transport":{"mode":"auto"}`,
		`mktemp -d /tmp/trustix-bootstrap-archive.XXXXXX`,
		`mktemp -d /tmp/trustix-bootstrap-src.XXXXXX`,
		`mktemp /tmp/trustix-bootstrap-src.XXXXXX`,
		`mktemp /tmp/trustix-provision-payload.XXXXXX`,
	}
	for _, bad := range forbidden {
		if strings.Contains(script, bad) {
			t.Fatalf("trustix-bootstrap-ix.sh still contains old direct bootstrap default %q", bad)
		}
	}
}
