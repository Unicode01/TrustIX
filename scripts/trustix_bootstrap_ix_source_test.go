package scripts

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func requireGNUBash4(t *testing.T) string {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	version, err := exec.Command(bash, "-c", `case "${BASH_VERSION:-}" in "") exit 9;; esac; printf '%s' "${BASH_VERSINFO[0]:-0}"`).Output()
	major, parseErr := strconv.Atoi(strings.TrimSpace(string(version)))
	if err != nil || parseErr != nil || major < 4 {
		t.Skip("GNU bash 4+ not available")
	}
	return bash
}

func TestTrustIXBootstrapIXScriptSyntax(t *testing.T) {
	bash := requireGNUBash4(t)
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
		`stable)
      profile_transport_profile="stable"
      profile_datapath="userspace"
      profile_encryption="secure"
      profile_crypto_placement="userspace"
      profile_kernel_transport="disabled"
      profile_kernel_capability="disabled"`,
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
		`printf '"encryption":"%s",' "$(json_escape "$encryption")"`,
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
		`stable)
      profile_transport_profile="stable"
      profile_datapath="auto"`,
		`"profile":"stable","datapath":"auto","encryption":"secure","crypto_key_source":"auto","crypto_placement":"auto","kernel_transport":{"mode":"auto"}`,
		`mktemp -d /tmp/trustix-bootstrap-archive.XXXXXX`,
		`mktemp -d /tmp/trustix-bootstrap-src.XXXXXX`,
		`mktemp /tmp/trustix-bootstrap-src.XXXXXX`,
		`mktemp /tmp/trustix-provision-payload.XXXXXX`,
		`"load_balance":"least_conn"`,
	}
	for _, bad := range forbidden {
		if strings.Contains(script, bad) {
			t.Fatalf("trustix-bootstrap-ix.sh still contains old direct bootstrap default %q", bad)
		}
	}
}

func TestTrustIXBootstrapIXGeneratesProductionPlaintextDefaults(t *testing.T) {
	bash := requireGNUBash4(t)
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not available")
	}

	workDir, err := os.MkdirTemp(".", ".trustix-bootstrap-test-")
	if err != nil {
		t.Fatalf("create temp work dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(workDir)
	})
	bashWorkDir := strings.ReplaceAll(workDir, "\\", "/")
	certDir := filepath.Join(workDir, "certs")
	if out, err := exec.Command("go", "run", "../cmd/trustix-ca", "quickstart", "-out", certDir, "-domain", "trust.local", "-ix", "ix-bootstrap-ca-seed").CombinedOutput(); err != nil {
		t.Fatalf("generate bootstrap test certs: %v\n%s", err, out)
	}
	bashCertDir := strings.ReplaceAll(certDir, "\\", "/")

	cmd := exec.Command(
		bash,
		"trustix-bootstrap-ix.sh",
		"--ix", "ix-script-test",
		"--domain", "trust.local",
		"--control-api", "https://ix-script-test.example:9443",
		"--advertise", "10.90.0.0/24",
		"--listen", "0.0.0.0:7000",
		"--address", "ix-script-test.example:7000",
		"--source-certs", bashCertDir,
		"--work-dir", bashWorkDir,
		"--target-cert-dir", "/etc/trustix/certs",
		"--no-build",
		"--no-deploy",
		"--json",
	)
	cmd.Env = append(os.Environ(), "TRUSTIX_BOOTSTRAP_INSTALL_DEPS=0")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	if err != nil {
		t.Fatalf("trustix-bootstrap-ix.sh failed: %v\nstderr:\n%s\nstdout:\n%s", err, stderr.String(), string(stdout))
	}

	var summary struct {
		Config string `json:"config"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(stdout), &summary); err != nil {
		t.Fatalf("parse bootstrap summary: %v\nstdout:\n%s\nstderr:\n%s", err, string(stdout), stderr.String())
	}
	if summary.Config == "" {
		t.Fatalf("bootstrap summary did not include config path: %s", stdout)
	}
	configJSON, err := os.ReadFile(summary.Config)
	if err != nil {
		t.Fatalf("read generated config %q: %v\nstderr:\n%s", summary.Config, err, stderr.String())
	}

	var cfg struct {
		KernelModules struct {
			CapabilityProfile string `json:"capability_profile"`
			Datapath          struct {
				RXStage                   string `json:"rx_stage"`
				RXWorker                  bool   `json:"rx_worker"`
				TXPlaintext               bool   `json:"tx_plaintext"`
				FullPlaintext             bool   `json:"full_plaintext"`
				RXWorkerAllowExperimental bool   `json:"rx_worker_allow_experimental_tcp"`
			} `json:"datapath"`
		} `json:"kernel_modules"`
		Endpoints []struct {
			Name      string `json:"name"`
			Transport string `json:"transport"`
			Security  struct {
				Encryption string `json:"encryption"`
			} `json:"security"`
			TransportProfile struct {
				Profile         string `json:"profile"`
				Datapath        string `json:"datapath"`
				Encryption      string `json:"encryption"`
				CryptoPlacement string `json:"crypto_placement"`
			} `json:"transport_profile"`
		} `json:"endpoints"`
		Policies []struct {
			Name           string `json:"name"`
			RouteSelect    string `json:"route_selection"`
			LoadBalance    string `json:"load_balance"`
			FlowStickiness bool   `json:"flow_stickiness"`
			Rewrite        string `json:"rewrite"`
		} `json:"policies"`
		TransportPolicy struct {
			Profile         string `json:"profile"`
			Datapath        string `json:"datapath"`
			Encryption      string `json:"encryption"`
			CryptoPlacement string `json:"crypto_placement"`
			KernelTransport struct {
				Mode string `json:"mode"`
			} `json:"kernel_transport"`
			SessionPool struct {
				Warmup bool `json:"warmup"`
			} `json:"session_pool"`
		} `json:"transport_policy"`
	}
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		t.Fatalf("parse generated config: %v\n%s", err, string(configJSON))
	}

	if cfg.TransportPolicy.Profile != "performance" ||
		cfg.TransportPolicy.Datapath != "kernel_module" ||
		cfg.TransportPolicy.Encryption != "plaintext" ||
		cfg.TransportPolicy.CryptoPlacement != "userspace" ||
		cfg.TransportPolicy.KernelTransport.Mode != "require_kernel" ||
		!cfg.TransportPolicy.SessionPool.Warmup {
		t.Fatalf("transport policy = %#v", cfg.TransportPolicy)
	}
	if cfg.KernelModules.CapabilityProfile != "full_plaintext" ||
		cfg.KernelModules.Datapath.RXStage != "worker" ||
		!cfg.KernelModules.Datapath.RXWorker ||
		!cfg.KernelModules.Datapath.TXPlaintext ||
		!cfg.KernelModules.Datapath.FullPlaintext ||
		!cfg.KernelModules.Datapath.RXWorkerAllowExperimental {
		t.Fatalf("kernel module defaults = %#v", cfg.KernelModules)
	}
	if len(cfg.Endpoints) != 1 ||
		cfg.Endpoints[0].Name != "ix-script-test-udp" ||
		cfg.Endpoints[0].Transport != "udp" ||
		cfg.Endpoints[0].Security.Encryption != "plaintext" ||
		cfg.Endpoints[0].TransportProfile.Profile != "performance" ||
		cfg.Endpoints[0].TransportProfile.Datapath != "kernel_module" ||
		cfg.Endpoints[0].TransportProfile.Encryption != "plaintext" ||
		cfg.Endpoints[0].TransportProfile.CryptoPlacement != "userspace" {
		t.Fatalf("endpoint defaults = %#v", cfg.Endpoints)
	}
	if len(cfg.Policies) != 1 ||
		cfg.Policies[0].Name != "default-routed" ||
		cfg.Policies[0].RouteSelect != "longest_prefix" ||
		cfg.Policies[0].LoadBalance != "" ||
		!cfg.Policies[0].FlowStickiness ||
		cfg.Policies[0].Rewrite != "preserve_source" {
		t.Fatalf("policy defaults = %#v", cfg.Policies)
	}
}
