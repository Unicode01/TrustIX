package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPromoteProductionEvidenceUpdatesHistoryAndCurrentRows(t *testing.T) {
	python := requirePython3(t)
	dir := t.TempDir()
	defaults := filepath.Join(dir, "defaults.tsv")
	evidence := filepath.Join(dir, "evidence.tsv")
	current := filepath.Join(dir, "current.tsv")
	generated := filepath.Join(dir, "generated.tsv")

	sha := func(ch string) string { return strings.Repeat(ch, 64) }
	defaultHeader := "# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tmin_gbps\tmin_seconds\tnote\n"
	evidenceHeader := "# gate_family\ttransport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tos_matrix\tkernel_matrix\tresult\tmin_gbps\tmin_seconds\tgate_manifest_schema\tproduction_gate_sha256\tverifier_sha256\tartifact\tevidence_note\tbinary_sha256\tbuild_version\tbuild_commit\tbuild_built_at\tbuild_go_version\trunner_sha256\ttransport_matrix_sha256\tevidence_generator_sha256\n"
	currentHeader := "# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tos_matrix\tkernel_matrix\tgate_manifest_schema\tproduction_gate_sha256\tverifier_sha256\tartifact\tnote\tbinary_sha256\tbuild_version\tbuild_commit\tbuild_built_at\tbuild_go_version\trunner_sha256\ttransport_matrix_sha256\tevidence_generator_sha256\n"
	defaultRow := "udp\tsecure\tstable\tuserspace\tuserspace\tcross_host\tuserspace\t1.5\t3600\tselected encrypted UDP userspace compatibility path\n"
	generatedRow := strings.Join([]string{
		"userspace", "udp", "secure", "stable", "userspace", "userspace", "cross_host",
		"debian13-debian13", "6.12.94_to_6.12.94", "pass", "1.9", "3600",
		"trustix-cross-host-production-gate-manifest-v1", sha("a"), sha("b"),
		"docs/trustix-performance-log.md#synthetic", "current synthetic udp secure userspace evidence",
		sha("c"), "trustix-linux-amd64", "abc123", "2026-07-08T00:00:00Z", "go1.25.0",
		sha("d"), sha("e"), sha("f"),
	}, "\t") + "\n"
	oldCurrentRow := strings.Join([]string{
		"udp", "secure", "stable", "userspace", "userspace", "cross_host", "userspace",
		"debian13-debian13", "6.12.90_to_6.12.90", "trustix-cross-host-production-gate-manifest-v1",
		sha("1"), sha("2"), "docs/trustix-performance-log.md#old", "old current evidence",
		sha("3"), "trustix-linux-amd64", "oldcommit", "2026-06-01T00:00:00Z", "go1.25.0",
		sha("4"), sha("5"), sha("6"),
	}, "\t") + "\n"

	writeText(t, defaults, defaultHeader+defaultRow)
	writeText(t, evidence, evidenceHeader)
	writeText(t, current, currentHeader+oldCurrentRow)
	writeText(t, generated, evidenceHeader+generatedRow)

	beforeEvidence := readText(t, evidence)
	beforeCurrent := readText(t, current)
	dryRun := exec.Command(python, "promote-production-evidence.py",
		"--generated", generated,
		"--defaults", defaults,
		"--evidence", evidence,
		"--current", current,
		"--skip-post-audit",
		"--dry-run",
	)
	dryRun.Dir = "."
	if out, err := dryRun.CombinedOutput(); err != nil {
		t.Fatalf("dry-run promotion failed: %v\n%s", err, out)
	}
	if got := readText(t, evidence); got != beforeEvidence {
		t.Fatalf("dry-run changed evidence file")
	}
	if got := readText(t, current); got != beforeCurrent {
		t.Fatalf("dry-run changed current file")
	}

	cmd := exec.Command(python, "promote-production-evidence.py",
		"--generated", generated,
		"--defaults", defaults,
		"--evidence", evidence,
		"--current", current,
		"--skip-post-audit",
	)
	cmd.Dir = "."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("promotion failed: %v\n%s", err, out)
	}
	evidenceText := readText(t, evidence)
	if !strings.Contains(evidenceText, generatedRow) {
		t.Fatalf("history evidence missing generated row:\n%s", evidenceText)
	}
	currentText := readText(t, current)
	if strings.Contains(currentText, "old current evidence") {
		t.Fatalf("current evidence still contains old row:\n%s", currentText)
	}
	for _, want := range []string{
		"current synthetic udp secure userspace evidence",
		"6.12.94_to_6.12.94",
		sha("d"),
		sha("e"),
		sha("f"),
	} {
		if !strings.Contains(currentText, want) {
			t.Fatalf("current evidence missing %q:\n%s", want, currentText)
		}
	}
}

func TestPromoteProductionEvidenceResolvesRepositoryRelativePaths(t *testing.T) {
	python := requirePython3(t)
	script, err := filepath.Abs("promote-production-evidence.py")
	if err != nil {
		t.Fatalf("resolve promotion script: %v", err)
	}
	code := strings.Join([]string{
		"import importlib.util, sys",
		"spec = importlib.util.spec_from_file_location('promote_production_evidence', sys.argv[1])",
		"module = importlib.util.module_from_spec(spec)",
		"spec.loader.exec_module(module)",
		"print(module.resolve_path(sys.argv[2]))",
	}, "; ")
	cmd := exec.Command(python, "-c", code, script, "scripts/production-transport-defaults.tsv")
	cmd.Dir = ".."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("resolve repository-relative promotion path: %v\n%s", err, out)
	}
	got := strings.TrimSpace(string(out))
	if !filepath.IsAbs(got) {
		t.Fatalf("resolved promotion path = %q, want absolute", got)
	}
	want, err := filepath.Abs("production-transport-defaults.tsv")
	if err != nil {
		t.Fatalf("resolve expected defaults path: %v", err)
	}
	gotInfo, err := os.Stat(got)
	if err != nil {
		t.Fatalf("stat resolved promotion path: %v", err)
	}
	wantInfo, err := os.Stat(want)
	if err != nil {
		t.Fatalf("stat expected defaults path: %v", err)
	}
	if !os.SameFile(gotInfo, wantInfo) {
		t.Fatalf("resolved promotion path = %q, want %q", got, want)
	}
}

func TestPromoteProductionEvidencePostAuditRejectsMissingArtifact(t *testing.T) {
	python := requirePython3(t)
	headBytes, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		t.Skipf("git rev-parse HEAD unavailable: %v", err)
	}
	head := strings.TrimSpace(string(headBytes))
	dir := t.TempDir()
	defaults := filepath.Join(dir, "defaults.tsv")
	evidence := filepath.Join(dir, "evidence.tsv")
	current := filepath.Join(dir, "current.tsv")
	generated := filepath.Join(dir, "generated.tsv")

	sha := func(ch string) string { return strings.Repeat(ch, 64) }
	defaultHeader := "# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tmin_gbps\tmin_seconds\tnote\n"
	evidenceHeader := "# gate_family\ttransport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tos_matrix\tkernel_matrix\tresult\tmin_gbps\tmin_seconds\tgate_manifest_schema\tproduction_gate_sha256\tverifier_sha256\tartifact\tevidence_note\tbinary_sha256\tbuild_version\tbuild_commit\tbuild_built_at\tbuild_go_version\trunner_sha256\ttransport_matrix_sha256\tevidence_generator_sha256\n"
	currentHeader := "# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tos_matrix\tkernel_matrix\tgate_manifest_schema\tproduction_gate_sha256\tverifier_sha256\tartifact\tnote\tbinary_sha256\tbuild_version\tbuild_commit\tbuild_built_at\tbuild_go_version\trunner_sha256\ttransport_matrix_sha256\tevidence_generator_sha256\n"
	writeText(t, defaults, defaultHeader+"udp\tsecure\tstable\tuserspace\tuserspace\tcross_host\tuserspace\t1.5\t3600\tselected\n")
	writeText(t, evidence, evidenceHeader)
	writeText(t, current, currentHeader+"udp\tsecure\tstable\tuserspace\tuserspace\tcross_host\tuserspace\tdebian13-debian13\t6.12.94\ttrustix-cross-host-production-gate-manifest-v1\t"+sha("1")+"\t"+sha("2")+"\tdocs/trustix-performance-log.md#old\told\t"+sha("3")+"\ttrustix-linux-amd64\t"+head+"\t2026-07-08T00:00:00Z\tgo1.25.0\t"+sha("4")+"\t"+sha("5")+"\t"+sha("6")+"\n")
	writeText(t, generated, evidenceHeader+strings.Join([]string{
		"userspace", "udp", "secure", "stable", "userspace", "userspace", "cross_host",
		"debian13-debian13", "6.12.94", "pass", "1.9", "3600",
		"trustix-cross-host-production-gate-manifest-v1",
		sha256File(t, "linux-cross-host-production-gate.sh"),
		sha256File(t, "linux-cross-host-soak-verify.py"),
		"docs/trustix-performance-log.md#missing-promote-test-anchor",
		"current synthetic udp secure userspace evidence",
		sha("a"), "trustix-linux-amd64", head, "2026-07-08T00:00:00Z", "go1.25.0",
		sha256File(t, "linux-cross-host-soak-runner.sh"),
		sha256File(t, "linux-cross-host-transport-matrix.sh"),
		sha256File(t, "production-evidence-from-gate-summary.py"),
	}, "\t")+"\n")

	cmd := exec.Command(python, "promote-production-evidence.py",
		"--generated", generated,
		"--defaults", defaults,
		"--evidence", evidence,
		"--current", current,
		"--dry-run",
	)
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("promotion unexpectedly accepted missing artifact:\n%s", out)
	}
	if !strings.Contains(string(out), "post-promotion strict audit failed") ||
		!strings.Contains(string(out), "missing-promote-test-anchor") {
		t.Fatalf("promotion failure did not mention strict audit artifact failure:\n%s", out)
	}
	if got := readText(t, evidence); strings.Contains(got, "missing-promote-test-anchor") {
		t.Fatalf("dry-run post-audit failure changed evidence file:\n%s", got)
	}
	if got := readText(t, current); strings.Contains(got, "missing-promote-test-anchor") {
		t.Fatalf("dry-run post-audit failure changed current file:\n%s", got)
	}
}

func TestPromoteProductionEvidenceRejectsRowsBelowDefaultGate(t *testing.T) {
	python := requirePython3(t)
	dir := t.TempDir()
	defaults := filepath.Join(dir, "defaults.tsv")
	evidence := filepath.Join(dir, "evidence.tsv")
	current := filepath.Join(dir, "current.tsv")
	generated := filepath.Join(dir, "generated.tsv")
	sha := strings.Repeat("a", 64)
	defaultHeader := "# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tmin_gbps\tmin_seconds\tnote\n"
	evidenceHeader := "# gate_family\ttransport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tos_matrix\tkernel_matrix\tresult\tmin_gbps\tmin_seconds\tgate_manifest_schema\tproduction_gate_sha256\tverifier_sha256\tartifact\tevidence_note\tbinary_sha256\tbuild_version\tbuild_commit\tbuild_built_at\tbuild_go_version\trunner_sha256\ttransport_matrix_sha256\tevidence_generator_sha256\n"
	currentHeader := "# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tos_matrix\tkernel_matrix\tgate_manifest_schema\tproduction_gate_sha256\tverifier_sha256\tartifact\tnote\tbinary_sha256\tbuild_version\tbuild_commit\tbuild_built_at\tbuild_go_version\trunner_sha256\ttransport_matrix_sha256\tevidence_generator_sha256\n"
	writeText(t, defaults, defaultHeader+"udp\tsecure\tstable\tuserspace\tuserspace\tcross_host\tuserspace\t1.5\t3600\tselected\n")
	writeText(t, evidence, evidenceHeader)
	writeText(t, current, currentHeader+"udp\tsecure\tstable\tuserspace\tuserspace\tcross_host\tuserspace\tdebian13-debian13\t6.12.90\ttrustix-cross-host-production-gate-manifest-v1\t"+sha+"\t"+sha+"\tdocs/trustix-performance-log.md#old\told\t"+sha+"\ttrustix-linux-amd64\told\t2026-06-01T00:00:00Z\tgo1.25.0\t"+sha+"\t"+sha+"\t"+sha+"\n")
	writeText(t, generated, evidenceHeader+strings.Join([]string{
		"userspace", "udp", "secure", "stable", "userspace", "userspace", "cross_host",
		"debian13-debian13", "6.12.94", "pass", "1.0", "3600",
		"trustix-cross-host-production-gate-manifest-v1", sha, sha,
		"docs/trustix-performance-log.md#synthetic", "too slow", sha, "trustix-linux-amd64",
		"abc123", "2026-07-08T00:00:00Z", "go1.25.0", sha, sha, sha,
	}, "\t")+"\n")

	cmd := exec.Command(python, "promote-production-evidence.py",
		"--generated", generated,
		"--defaults", defaults,
		"--evidence", evidence,
		"--current", current,
		"--dry-run",
	)
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("promotion unexpectedly accepted below-threshold evidence:\n%s", out)
	}
	if !strings.Contains(string(out), "evidence min_gbps 1.0 < default 1.5") {
		t.Fatalf("promotion failure did not mention min_gbps threshold:\n%s", out)
	}
}

func writeText(t *testing.T, path string, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readText(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
