package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
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

func TestPVECurrentUserspaceRefreshScriptKeepsPVEWorkspaceScoped(t *testing.T) {
	payload, err := os.ReadFile("pve-current-userspace-refresh.sh")
	if err != nil {
		t.Fatalf("read pve-current-userspace-refresh.sh: %v", err)
	}
	script := string(payload)
	mustContain := []string{
		`workspace="${TRUSTIX_PVE_WORKSPACE:-/root/trustix-pve-work}"`,
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
