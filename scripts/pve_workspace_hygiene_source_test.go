package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPVEWorkspaceHygieneScriptSyntax(t *testing.T) {
	bash := requireGNUBash4(t)
	cmd := exec.Command(bash, "-n", "pve-workspace-hygiene.sh")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n pve-workspace-hygiene.sh: %v\n%s", err, out)
	}
}

func TestPVECurrentUserspaceRefreshScriptSyntax(t *testing.T) {
	bash := requireGNUBash4(t)
	cmd := exec.Command(bash, "-n", "pve-current-userspace-refresh.sh")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n pve-current-userspace-refresh.sh: %v\n%s", err, out)
	}
}

func TestPVECurrentRunStatusScriptSyntax(t *testing.T) {
	bash := requireGNUBash4(t)
	cmd := exec.Command(bash, "-n", "pve-current-run-status.sh")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n pve-current-run-status.sh: %v\n%s", err, out)
	}
}

func TestPVECurrentUserspaceRefreshScriptKeepsPVEWorkspaceScoped(t *testing.T) {
	payload, err := os.ReadFile("pve-current-userspace-refresh.sh")
	if err != nil {
		t.Fatalf("read pve-current-userspace-refresh.sh: %v", err)
	}
	script := string(payload)
	mustContain := []string{
		`workspace="${TRUSTIX_PVE_WORKSPACE:-/root/trustix-pve-work}"`,
		`--refresh-gaps`,
		`detect_refresh_gap_transports()`,
		`production-transport-audit.py`,
		`pve-workspace-hygiene.sh" --workspace "$workspace" --check`,
		`"${workspace}/results/current-${commit_short}-userspace-${label}-production-${stamp}"`,
		`"${scratch}/scripts/start-current-${commit_short}-userspace-${label}-production-${stamp}.sh"`,
		`"${scratch}/pids/current-${commit_short}-userspace-${label}-production-${stamp}.pid"`,
		`TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_KEEP_REMOTE=0`,
		`TRUSTIX_CROSS_HOST_KEEP_REMOTE=0`,
	}
	for _, want := range mustContain {
		if !strings.Contains(script, want) {
			t.Fatalf("pve-current-userspace-refresh.sh missing %q", want)
		}
	}
	forbidden := []string{
		`/root/current-`,
		`mktemp -d /root`,
	}
	for _, bad := range forbidden {
		if strings.Contains(script, bad) {
			t.Fatalf("pve-current-userspace-refresh.sh contains unsafe root fragment %q", bad)
		}
	}
}

func TestPVECurrentRunStatusScriptIsReadOnlyAndScoped(t *testing.T) {
	payload, err := os.ReadFile("pve-current-run-status.sh")
	if err != nil {
		t.Fatalf("read pve-current-run-status.sh: %v", err)
	}
	script := string(payload)
	for _, want := range []string{
		`workspace="${TRUSTIX_PVE_WORKSPACE:-/root/trustix-pve-work}"`,
		`pve-workspace-hygiene.sh" --workspace "$workspace" --check`,
		`"${workspace}/results/"*`,
		`root top trustix-like entries`,
		`status=ready_to_review_or_promote`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("pve-current-run-status.sh missing %q", want)
		}
	}
	for _, bad := range []string{
		`rm -`,
		`mv `,
		`mkdir `,
		`mktemp`,
		`> /root`,
		`/root/current-`,
	} {
		if strings.Contains(script, bad) {
			t.Fatalf("pve-current-run-status.sh contains mutating or unsafe fragment %q", bad)
		}
	}
}

func TestPVECurrentUserspaceRefreshDetectsRefreshGapTransports(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pve-current-userspace-refresh.sh dry-run expects Linux-style paths")
	}
	bash := requireGNUBash4(t)
	requirePython3(t)
	root := t.TempDir()
	workspace := filepath.Join(root, "trustix-pve-work")
	runRoot := filepath.Join(workspace, "results", "refresh-gaps-dry-run")

	cmd := exec.Command(
		bash,
		"pve-current-userspace-refresh.sh",
		"--workspace", workspace,
		"--run-root", runRoot,
		"--refresh-gaps",
		"--dry-run",
		"--skip-hygiene-check",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("refresh-gap dry-run failed: %v\n%s", err, out)
	}
	text := string(out)
	for _, want := range []string{
		"RUN_ROOT=" + runRoot,
		"DEFAULTS=" + filepath.Join(runRoot, "userspace-defaults.tsv"),
		"DRY_RUN=1",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("dry-run output missing %q:\n%s", want, text)
		}
	}

	payload, err := os.ReadFile(filepath.Join(runRoot, "userspace-defaults.tsv"))
	if err != nil {
		t.Fatalf("read generated defaults: %v", err)
	}
	defaults := string(payload)
	for _, want := range []string{
		"udp\tsecure\tstable\tuserspace\tuserspace\tcross_host\tuserspace",
		"udp\tplaintext\tstable\tuserspace\tuserspace\tcross_host\tuserspace",
		"tcp\tsecure\tstable\tuserspace\tuserspace\tcross_host\tuserspace",
		"tcp\tplaintext\tstable\tuserspace\tuserspace\tcross_host\tuserspace",
		"quic\tsecure\tstable\tuserspace\tuserspace\tcross_host\tuserspace",
		"quic\tplaintext\tstable\tuserspace\tuserspace\tcross_host\tuserspace",
		"websocket\tsecure\tstable\tuserspace\tuserspace\tcross_host\tuserspace",
		"websocket\tplaintext\tstable\tuserspace\tuserspace\tcross_host\tuserspace",
		"http_connect\tsecure\tstable\tuserspace\tuserspace\tcross_host\tuserspace",
		"http_connect\tplaintext\tstable\tuserspace\tuserspace\tcross_host\tuserspace",
		"experimental_tcp\tsecure\tstable\tuserspace\tuserspace\tcross_host\tuserspace",
	} {
		if !strings.Contains(defaults, want) {
			t.Fatalf("refresh-gap defaults missing %q:\n%s", want, defaults)
		}
	}
	for _, bad := range []string{
		"kernel_module",
		"experimental_tcp\tplaintext",
	} {
		if strings.Contains(defaults, bad) {
			t.Fatalf("refresh-gap defaults unexpectedly contain %q:\n%s", bad, defaults)
		}
	}
}

func TestPVEWorkspaceHygieneQuarantinesOnlyLooseArtifacts(t *testing.T) {
	bash := requireGNUBash4(t)
	root := t.TempDir()
	workspace := filepath.Join(root, "trustix-pve-work")
	for _, dir := range []string{
		workspace,
		filepath.Join(root, "trustix-run-leftover"),
		filepath.Join(root, "current-604d67d-src"),
		filepath.Join(root, "go"),
		filepath.Join(root, ".ssh"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "current-aee1046.tar"), []byte("tar"), 0o644); err != nil {
		t.Fatalf("write loose tar: %v", err)
	}

	check := exec.Command(bash, "pve-workspace-hygiene.sh", "--root", root, "--workspace", workspace, "--check")
	out, err := check.CombinedOutput()
	if err == nil {
		t.Fatalf("check unexpectedly passed with loose artifacts:\n%s", out)
	}
	for _, want := range []string{"trustix-run-leftover", "current-604d67d-src", "current-aee1046.tar"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("check output missing %s:\n%s", want, out)
		}
	}

	cmd := exec.Command(bash, "pve-workspace-hygiene.sh", "--root", root, "--workspace", workspace, "--quarantine")
	cmd.Env = append(os.Environ(), "TRUSTIX_PVE_WORKSPACE_HYGIENE_STAMP=teststamp")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("quarantine failed: %v\n%s", err, out)
	}

	archive := filepath.Join(workspace, "_scratch", "root-loose-teststamp")
	for _, want := range []string{"trustix-run-leftover", "current-604d67d-src", "current-aee1046.tar"} {
		if _, err := os.Stat(filepath.Join(archive, want)); err != nil {
			t.Fatalf("expected quarantined %s: %v", want, err)
		}
	}
	for _, keep := range []string{"trustix-pve-work", "go", ".ssh"} {
		if _, err := os.Stat(filepath.Join(root, keep)); err != nil {
			t.Fatalf("expected retained %s: %v", keep, err)
		}
	}
}
