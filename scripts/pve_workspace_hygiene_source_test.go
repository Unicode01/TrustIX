package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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

func TestPVEPromoteRunEvidenceScriptSyntax(t *testing.T) {
	bash := requireGNUBash4(t)
	cmd := exec.Command(bash, "-n", "pve-promote-run-evidence.sh")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n pve-promote-run-evidence.sh: %v\n%s", err, out)
	}
}

func TestCrossHostConcurrentSoakScriptSyntax(t *testing.T) {
	bash := requireGNUBash4(t)
	cmd := exec.Command(bash, "-n", "linux-cross-host-concurrent-soak.sh")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n linux-cross-host-concurrent-soak.sh: %v\n%s", err, out)
	}
}

func TestCrossHostConcurrentSoakScriptKeepsCasesIsolated(t *testing.T) {
	payload, err := os.ReadFile("linux-cross-host-concurrent-soak.sh")
	if err != nil {
		t.Fatalf("read linux-cross-host-concurrent-soak.sh: %v", err)
	}
	script := string(payload)
	for _, want := range []string{
		`workdir="${TRUSTIX_CROSS_HOST_CONCURRENT_WORKDIR:-$(mktemp -d /tmp/trustix-cross-host-concurrent.XXXXXX)}"`,
		`remote_base="${TRUSTIX_CROSS_HOST_CONCURRENT_REMOTE_BASE:-${remote_parent}/trustix-cross-host-concurrent-$(date +%Y%m%d-%H%M%S)-$$}"`,
		`unload_modules="${TRUSTIX_CROSS_HOST_CONCURRENT_UNLOAD_MODULES:-0}"`,
		`TRUSTIX_CROSS_HOST_UNLOAD_MODULES=${unload_modules}`,
		`TRUSTIX_CROSS_HOST_REMOTE_A=${remote_base}/${label}/a`,
		`TRUSTIX_CROSS_HOST_REMOTE_B=${remote_base}/${label}/b`,
		`TRUSTIX_CROSS_HOST_API_A_PORT=${api_a}`,
		`TRUSTIX_CROSS_HOST_PEER_A_PORT=${peer_a}`,
		`TRUSTIX_CROSS_HOST_DATA_A_PORT=${data_a}`,
		`TRUSTIX_CROSS_HOST_IPERF_PORT=${iperf}`,
		`TRUSTIX_CROSS_HOST_LAN_IF_A=tix-lan-c${index}a`,
		`TRUSTIX_CROSS_HOST_HOST_NS_A=tix-host-c${index}a`,
		`TRUSTIX_CROSS_HOST_LAN_A_CIDR=10.74.${lan_a_octet}.0/24`,
		`case "$dir" in "$workdir"/*)`,
		`run_one "$name" "$dir" "$env_file" >"${dir}.out" 2>"${dir}.err" &`,
		`"--require-stable-boot-id"`,
		`"--require-kernel-log-artifacts"`,
		`"--forbid-lsmod-prefix" "trustix_"`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("linux-cross-host-concurrent-soak.sh missing %q", want)
		}
	}
	for _, bad := range []string{
		`/root/current-`,
		`mktemp -d /root`,
		`TRUSTIX_CROSS_HOST_CONCURRENT_UNLOAD_MODULES:-1`,
	} {
		if strings.Contains(script, bad) {
			t.Fatalf("linux-cross-host-concurrent-soak.sh contains unsafe fragment %q", bad)
		}
	}
}

func TestCrossHostConcurrentSoakDryRunGeneratesIsolatedCases(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("concurrent soak dry-run expects GNU bash and Linux-style paths")
	}
	bash := requireGNUBash4(t)
	root := t.TempDir()
	runner := filepath.Join(root, "runner.sh")
	verifier := filepath.Join(root, "verifier.py")
	workdir := filepath.Join(root, "concurrent")
	if err := os.WriteFile(runner, []byte("#!/usr/bin/env bash\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write runner: %v", err)
	}
	if err := os.WriteFile(verifier, []byte("#!/usr/bin/env python3\n"), 0o755); err != nil {
		t.Fatalf("write verifier: %v", err)
	}
	cmd := exec.Command(bash, "linux-cross-host-concurrent-soak.sh")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(),
		"TRUSTIX_CROSS_HOST_CONCURRENT_DRY_RUN=1",
		"TRUSTIX_CROSS_HOST_CONCURRENT_WORKDIR="+workdir,
		"TRUSTIX_CROSS_HOST_CONCURRENT_RUNNER="+runner,
		"TRUSTIX_CROSS_HOST_CONCURRENT_VERIFIER="+verifier,
		"TRUSTIX_CROSS_HOST_CONCURRENT_CASES=userspace-udp-secure userspace-tcp-plaintext userspace-experimental-tcp-secure",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("concurrent dry-run failed: %v\n%s", err, out)
	}
	summary, err := os.ReadFile(filepath.Join(workdir, "summary.jsonl"))
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	for _, want := range []string{
		`"case":"userspace-udp-secure"`,
		`"case":"userspace-tcp-plaintext"`,
		`"case":"userspace-experimental-tcp-secure"`,
		`"status":"dry_run"`,
	} {
		if !strings.Contains(string(summary), want) {
			t.Fatalf("summary missing %q:\n%s", want, summary)
		}
	}
	env0, err := os.ReadFile(filepath.Join(workdir, "userspace-udp-secure", "case.env"))
	if err != nil {
		t.Fatalf("read case 0 env: %v", err)
	}
	env1, err := os.ReadFile(filepath.Join(workdir, "userspace-tcp-plaintext", "case.env"))
	if err != nil {
		t.Fatalf("read case 1 env: %v", err)
	}
	for _, want := range []string{
		"TRUSTIX_CROSS_HOST_UNLOAD_MODULES=0",
		"TRUSTIX_CROSS_HOST_API_A_PORT=28787",
		"TRUSTIX_CROSS_HOST_PEER_A_PORT=29443",
		"TRUSTIX_CROSS_HOST_DATA_A_PORT=29700",
		"TRUSTIX_CROSS_HOST_IPERF_PORT=35201",
		"TRUSTIX_CROSS_HOST_LAN_A_CIDR=10.74.80.0/24",
	} {
		if !strings.Contains(string(env0), want) {
			t.Fatalf("case 0 env missing %q:\n%s", want, env0)
		}
	}
	for _, want := range []string{
		"TRUSTIX_CROSS_HOST_UNLOAD_MODULES=0",
		"TRUSTIX_CROSS_HOST_API_A_PORT=28797",
		"TRUSTIX_CROSS_HOST_PEER_A_PORT=29453",
		"TRUSTIX_CROSS_HOST_DATA_A_PORT=29710",
		"TRUSTIX_CROSS_HOST_IPERF_PORT=35211",
		"TRUSTIX_CROSS_HOST_LAN_A_CIDR=10.74.82.0/24",
	} {
		if !strings.Contains(string(env1), want) {
			t.Fatalf("case 1 env missing %q:\n%s", want, env1)
		}
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
		`--next-refresh-gap`,
		`--quarantine-loose-root-artifacts`,
		`host_health_interval="${TRUSTIX_PVE_HOST_HEALTH_INTERVAL:-0}"`,
		`TRUSTIX_PVE_HOST_HEALTH_INTERVAL`,
		`detect_refresh_gap_transports()`,
		`production-transport-audit.py`,
		`hygiene_mode="--check"`,
		`hygiene_mode="--quarantine"`,
		`pve-workspace-hygiene.sh" --workspace "$workspace" "$hygiene_mode"`,
		`host-health.log`,
		`sample_host_health()`,
		`[[ "\$host_health_interval" == "0" ]] && return 0`,
		`if [[ "\$host_health_interval" != "0" ]]; then`,
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
		`--latest-production`,
		`latest_pattern()`,
		`pve-workspace-hygiene.sh" --workspace "$workspace" --check`,
		`"${workspace}/results/"*`,
		`root top trustix-like entries`,
		`== progress ==`,
		`cases_total=`,
		`summary_rows=`,
		`active_case=`,
		`== host health ==`,
		`latest_sample=`,
		`latest_kernel_warnings_tail`,
		`status=ready_to_review_or_promote`,
		`status=interrupted_or_stale`,
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

func TestPVECurrentRunStatusSelectsLatestProductionRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pve-current-run-status.sh functional test expects Linux-style paths")
	}
	bash := requireGNUBash4(t)
	root := t.TempDir()
	workspace := filepath.Join(root, "trustix-pve-work")
	oldUserspace := filepath.Join(workspace, "results", "current-old-userspace-udp-production-20260708-000000")
	newProduction := filepath.Join(workspace, "results", "owdeb-new-production-20260708-010000")
	createStatusRun := func(path string, ts time.Time) {
		t.Helper()
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("mkdir run root: %v", err)
		}
		if err := os.WriteFile(filepath.Join(path, "run.meta"), []byte("exit_code=0\n"), 0o644); err != nil {
			t.Fatalf("write run meta: %v", err)
		}
		if err := os.WriteFile(filepath.Join(path, "evidence.tsv"), []byte("# evidence\nrow\n"), 0o644); err != nil {
			t.Fatalf("write evidence: %v", err)
		}
		if err := os.Chtimes(path, ts, ts); err != nil {
			t.Fatalf("chtimes run root: %v", err)
		}
	}
	base := time.Unix(1_800_000_000, 0)
	createStatusRun(oldUserspace, base)
	createStatusRun(newProduction, base.Add(time.Hour))

	productionCmd := exec.Command(bash, "pve-current-run-status.sh", "--workspace", workspace, "--latest-production", "--tail", "0")
	productionOut, err := productionCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("latest production status failed: %v\n%s", err, productionOut)
	}
	if !strings.Contains(string(productionOut), "run_root="+newProduction) {
		t.Fatalf("latest production did not select newest production run:\n%s", productionOut)
	}

	userspaceCmd := exec.Command(bash, "pve-current-run-status.sh", "--workspace", workspace, "--latest-userspace", "--tail", "0")
	userspaceOut, err := userspaceCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("latest userspace status failed: %v\n%s", err, userspaceOut)
	}
	if !strings.Contains(string(userspaceOut), "run_root="+oldUserspace) {
		t.Fatalf("latest userspace did not stay scoped to userspace runs:\n%s", userspaceOut)
	}
}

func TestPVECurrentRunStatusDetectsStalePID(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pve-current-run-status.sh functional test expects Linux-style paths")
	}
	bash := requireGNUBash4(t)
	root := t.TempDir()
	workspace := filepath.Join(root, "trustix-pve-work")
	runName := "current-test-userspace-udp-production-20260708-000000"
	runRoot := filepath.Join(workspace, "results", runName)
	pidDir := filepath.Join(workspace, "_scratch", "pids")
	if err := os.MkdirAll(runRoot, 0o755); err != nil {
		t.Fatalf("mkdir run root: %v", err)
	}
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatalf("mkdir pid dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runRoot, "run.meta"), []byte("started_at=2026-07-08T00:00:00+08:00\n"), 0o644); err != nil {
		t.Fatalf("write run meta: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, runName+".pid"), []byte("999999999\n"), 0o644); err != nil {
		t.Fatalf("write pid file: %v", err)
	}

	cmd := exec.Command(bash, "pve-current-run-status.sh", "--workspace", workspace, "--run-root", runRoot, "--tail", "0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run status failed: %v\n%s", err, out)
	}
	for _, want := range []string{
		"pid_status=stale",
		"status=interrupted_or_stale",
	} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("stale pid status output missing %q:\n%s", want, out)
		}
	}
}

func TestPVEPromoteRunEvidenceScriptIsScopedAndDryRunByDefault(t *testing.T) {
	payload, err := os.ReadFile("pve-promote-run-evidence.sh")
	if err != nil {
		t.Fatalf("read pve-promote-run-evidence.sh: %v", err)
	}
	script := string(payload)
	for _, want := range []string{
		`workspace="${TRUSTIX_PVE_WORKSPACE:-/root/trustix-pve-work}"`,
		`promote-production-evidence.py`,
		`--latest-production`,
		`latest_pattern()`,
		`args+=(--dry-run)`,
		`"${workspace}/results/"*`,
		`refusing --write with dirty production evidence TSVs`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("pve-promote-run-evidence.sh missing %q", want)
		}
	}
	for _, bad := range []string{
		`/root/current-`,
		`mktemp -d /root`,
		`rm -`,
		`mv `,
	} {
		if strings.Contains(script, bad) {
			t.Fatalf("pve-promote-run-evidence.sh contains unsafe fragment %q", bad)
		}
	}
}

func TestPVECurrentUserspaceRefreshSelectsNextRefreshGap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pve-current-userspace-refresh.sh dry-run expects Linux-style paths")
	}
	bash := requireGNUBash4(t)
	requirePython3(t)
	root := t.TempDir()
	workspace := filepath.Join(root, "trustix-pve-work")
	runRoot := filepath.Join(workspace, "results", "next-refresh-gap-dry-run")

	cmd := exec.Command(
		bash,
		"pve-current-userspace-refresh.sh",
		"--workspace", workspace,
		"--run-root", runRoot,
		"--next-refresh-gap",
		"--dry-run",
		"--skip-hygiene-check",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("next-refresh-gap dry-run failed: %v\n%s", err, out)
	}
	payload, err := os.ReadFile(filepath.Join(runRoot, "userspace-defaults.tsv"))
	if err != nil {
		t.Fatalf("read generated defaults: %v", err)
	}
	defaults := string(payload)
	for _, want := range []string{
		"tcp\tsecure\tstable\tuserspace\tuserspace\tcross_host\tuserspace",
		"tcp\tplaintext\tstable\tuserspace\tuserspace\tcross_host\tuserspace",
	} {
		if !strings.Contains(defaults, want) {
			t.Fatalf("next refresh defaults missing %q:\n%s", want, defaults)
		}
	}
	for _, bad := range []string{
		"udp\t",
		"quic\t",
		"websocket\t",
		"http_connect\t",
		"experimental_tcp\t",
		"kernel_module",
	} {
		if strings.Contains(defaults, bad) {
			t.Fatalf("next refresh defaults unexpectedly contain %q:\n%s", bad, defaults)
		}
	}
}

func TestPVEPromoteRunEvidenceRejectsFailedRunBeforePromotion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pve-promote-run-evidence.sh functional test expects Linux-style paths")
	}
	bash := requireGNUBash4(t)
	root := t.TempDir()
	workspace := filepath.Join(root, "trustix-pve-work")
	runRoot := filepath.Join(workspace, "results", "current-test-userspace-udp-production-20260708-000000")
	if err := os.MkdirAll(runRoot, 0o755); err != nil {
		t.Fatalf("mkdir run root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runRoot, "run.meta"), []byte("exit_code=1\n"), 0o644); err != nil {
		t.Fatalf("write run meta: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runRoot, "evidence.tsv"), []byte("# evidence\nuserspace\tudp\n"), 0o644); err != nil {
		t.Fatalf("write evidence: %v", err)
	}

	cmd := exec.Command(bash, "pve-promote-run-evidence.sh", "--workspace", workspace, "--run-root", runRoot)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("promote unexpectedly accepted failed run:\n%s", out)
	}
	if !strings.Contains(string(out), "run exit_code must be 0 before promotion") {
		t.Fatalf("promote failure did not mention run exit code:\n%s", out)
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
		"udp\t",
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
