package scripts

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCrossHostSoakVerifyAcceptsPassingArtifacts(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 4.8e9, 4.7e9, 120.1)
	if err := os.WriteFile(filepath.Join(dir, "case.result"), []byte("pass\n"), 0o644); err != nil {
		t.Fatalf("write result marker: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run.log"), []byte("case PASS\n"), 0o644); err != nil {
		t.Fatalf("write run log: %v", err)
	}

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify passing artifacts failed: %v\n%s", err, output)
	}
}

func TestCrossHostSoakVerifyReportsIperfIntervalDiagnostics(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 4.8e9, 4.7e9, 120.1)
	writeResultMarker(t, dir)
	summary := filepath.Join(dir, "summary.jsonl")

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--summary", summary, "--min-gbps", "4", "--min-seconds", "120", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify passing artifacts failed: %v\n%s", err, output)
	}
	lines, err := os.ReadFile(summary)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	var row struct {
		Iperf []struct {
			Intervals              int     `json:"intervals"`
			IntervalMinGbps        float64 `json:"interval_min_gbps"`
			IntervalFirst10AvgGbps float64 `json:"interval_first_10_avg_gbps"`
			IntervalLast10AvgGbps  float64 `json:"interval_last_10_avg_gbps"`
			Retransmits            int     `json:"retransmits"`
			IntervalRetransmits    int     `json:"interval_retransmits"`
		} `json:"iperf"`
	}
	if err := json.Unmarshal(lines, &row); err != nil {
		t.Fatalf("unmarshal summary: %v\n%s", err, lines)
	}
	if len(row.Iperf) == 0 {
		t.Fatalf("summary did not include iperf diagnostics:\n%s", lines)
	}
	for _, item := range row.Iperf {
		if item.Intervals != 3 {
			t.Fatalf("interval count = %d, want 3", item.Intervals)
		}
		if item.IntervalMinGbps <= 0 || item.IntervalFirst10AvgGbps <= 0 || item.IntervalLast10AvgGbps <= 0 {
			t.Fatalf("missing interval throughput diagnostics: %+v", item)
		}
		if item.Retransmits != 6 || item.IntervalRetransmits != 6 {
			t.Fatalf("retransmits = %d/%d, want 6/6", item.Retransmits, item.IntervalRetransmits)
		}
	}
}

func TestCrossHostSoakVerifyAcceptsReceiverOnlyServerArtifact(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b-client.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfReceiverJSON(t, filepath.Join(dir, "case-iperf-b-to-a-server.json"), 4.7e9, 120.1)
	if err := os.WriteFile(filepath.Join(dir, "case.result"), []byte("pass\n"), 0o644); err != nil {
		t.Fatalf("write result marker: %v", err)
	}

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify receiver-only artifacts failed: %v\n%s", err, output)
	}
}

func TestCrossHostSoakVerifySkipsClientMissingServerResults(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfMissingServerResultsJSON(t, filepath.Join(dir, "a", "iperf3-a-to-b-forward.json"), 5.0e9)
	writeIperfReceiverJSON(t, filepath.Join(dir, "b", "iperf3-server.json"), 4.7e9, 120.1)
	writeResultMarker(t, dir)
	summary := filepath.Join(dir, "summary.jsonl")

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--summary", summary, "--min-gbps", "4", "--min-seconds", "120", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify missing-server-results artifacts failed: %v\n%s", err, output)
	}
	lines, err := os.ReadFile(summary)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	var row struct {
		Skipped []string `json:"iperf_skipped_missing_server_results"`
		Status  string   `json:"status"`
	}
	if err := json.Unmarshal(lines, &row); err != nil {
		t.Fatalf("unmarshal summary: %v\n%s", err, lines)
	}
	if row.Status != "pass" {
		t.Fatalf("status = %q, want pass: %s", row.Status, lines)
	}
	if len(row.Skipped) != 1 || filepath.ToSlash(row.Skipped[0]) != "a/iperf3-a-to-b-forward.json" {
		t.Fatalf("skipped missing-server-results files = %#v, want client artifact", row.Skipped)
	}
}

func TestCrossHostSoakVerifyRejectsServerSummaryWithIperfError(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfMissingServerResultsJSON(t, filepath.Join(dir, "a", "iperf3-a-to-b-forward.json"), 5.0e9)
	writeIperfReceiverJSONWithError(t, filepath.Join(dir, "b", "iperf3-server.json"), 4.7e9, 120.1, "error - unable to receive control message: Bad file descriptor")
	writeResultMarker(t, dir)

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted server summary with iperf error:\n%s", output)
	}
	if !strings.Contains(string(output), "iperf3-server.json: iperf JSON contains error") {
		t.Fatalf("verify output did not report server iperf error:\n%s", output)
	}
}

func TestCrossHostSoakVerifyAcceptsSingleDirectionClientAndServerArtifacts(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "a"), 0o755); err != nil {
		t.Fatalf("make a dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "b"), 0o755); err != nil {
		t.Fatalf("make b dir: %v", err)
	}
	writeIperfJSON(t, filepath.Join(dir, "a", "iperf3-a-to-b-forward.json"), 4.8e9, 4.7e9, 900.1)
	writeIperfReceiverJSON(t, filepath.Join(dir, "b", "iperf3-server.json"), 4.7e9, 900.1)
	writeResultMarker(t, dir)

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "900", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify single-direction artifacts failed: %v\n%s", err, output)
	}
}

func TestCrossHostSoakVerifyRequiresIperfPairDirections(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b-forward.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a2b-retry.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-iperf-pair-directions", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted one-way iperf artifacts:\n%s", output)
	}
	if !strings.Contains(string(output), "missing iperf traffic pair directions: b-to-a") {
		t.Fatalf("verify output did not report missing b-to-a pair direction:\n%s", output)
	}
}

func TestCrossHostSoakVerifyAcceptsIperfPairDirectionsFromServerArtifacts(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfReceiverJSON(t, filepath.Join(dir, "a", "iperf3-server.json"), 4.8e9, 120.2)
	writeIperfReceiverJSON(t, filepath.Join(dir, "b", "iperf3-server.json"), 4.8e9, 120.2)
	writeResultMarker(t, dir)

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-iperf-pair-directions", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify rejected server-side pair direction artifacts: %v\n%s", err, output)
	}
}

func TestCrossHostSoakVerifyRejectsSlowArtifacts(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 0.5e9, 120.2)
	if err := os.WriteFile(filepath.Join(dir, "case.result"), []byte("pass\n"), 0o644); err != nil {
		t.Fatalf("write result marker: %v", err)
	}

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted slow artifacts:\n%s", output)
	}
}

func TestCrossHostSoakVerifyAcceptsRawBidirClientArtifact(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfBidirJSON(t, filepath.Join(dir, "case-iperf-bidir.json"), 13.6e9, 13.5e9, 5.8e9, 5.7e9, 900.1)
	writeResultMarker(t, dir)

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "900", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify raw bidir artifact failed: %v\n%s", err, output)
	}
}

func TestCrossHostSoakVerifyRejectsSlowRawBidirReverse(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfBidirJSON(t, filepath.Join(dir, "case-iperf-bidir.json"), 13.6e9, 13.5e9, 0.5e9, 0.4e9, 900.1)
	writeResultMarker(t, dir)

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "900", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted slow reverse bidir artifact:\n%s", output)
	}
	if !strings.Contains(string(output), "case-iperf-bidir.json:reverse") {
		t.Fatalf("verify did not identify reverse direction failure:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRejectsKernelCrashLogs(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	if err := os.WriteFile(filepath.Join(dir, "case.result"), []byte("pass\n"), 0o644); err != nil {
		t.Fatalf("write result marker: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "kernel.log"), []byte("kernel: BUG: unable to handle test fault\n"), 0o644); err != nil {
		t.Fatalf("write kernel log: %v", err)
	}

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted crash log artifacts:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRequiresKernelLogArtifacts(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-kernel-log-artifacts", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted missing kernel log artifacts:\n%s", output)
	}
	if !strings.Contains(string(output), "kernel/dmesg log artifacts") {
		t.Fatalf("verify output did not report missing kernel log artifacts:\n%s", output)
	}
}

func TestCrossHostSoakVerifyAcceptsKernelLogArtifacts(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeTextFile(t, filepath.Join(dir, "collect", "a", "ix-a-kernel.log"), "kernel: Linux version test\n")
	writeTextFile(t, filepath.Join(dir, "collect", "b", "ix-b-dmesg.log"), "[    0.000000] Linux version test\n")

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-kernel-log-artifacts", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify rejected kernel log artifacts: %v\n%s", err, output)
	}
}

func TestCrossHostSoakVerifyRequiresKernelLogNodes(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeTextFile(t, filepath.Join(dir, "collect", "a", "ix-a-kernel.log"), "kernel: Linux version test\n")
	writeTextFile(t, filepath.Join(dir, "collect", "a", "ix-a-dmesg.log"), "[    0.000000] Linux version test\n")

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-kernel-log-artifacts", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted single-node kernel log artifacts:\n%s", output)
	}
	if !strings.Contains(string(output), "kernel/dmesg log artifacts for 1 nodes") {
		t.Fatalf("verify output did not report missing kernel log node coverage:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRejectsKernelLogCollectionErrors(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeTextFile(t, filepath.Join(dir, "collect", "a", "ix-a-kernel.log"), "kernel: Linux version test\n")
	writeTextFile(t, filepath.Join(dir, "collect", "b", "ix-b-dmesg.log"), "dmesg: read kernel buffer failed: Operation not permitted\n")

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-kernel-log-artifacts", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted unusable kernel log artifact:\n%s", output)
	}
	if !strings.Contains(string(output), "kernel/dmesg log artifact unusable") ||
		!strings.Contains(string(output), "read kernel buffer failed") {
		t.Fatalf("verify output did not report unusable kernel log artifact:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRejectsTxQueueLenMisconfigLogs(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "kernel.log"), []byte("tix-lan: Caught tx_queue_len zero misconfig\n"), 0o644); err != nil {
		t.Fatalf("write tx_queue_len log: %v", err)
	}

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted tx_queue_len log:\n%s", output)
	}
	if !strings.Contains(string(output), "tx_queue_len zero misconfig") {
		t.Fatalf("verify output did not report tx_queue_len signature:\n%s", output)
	}
}

func TestCrossHostSoakVerifyIgnoresBenignKernelBugWords(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	benign := strings.Join([]string{
		`PCI: Using host bridge windows from ACPI; if necessary, use "pci=nocrs" and report a bug`,
		`systemd[1]: Mounting sys-kernel-debug.mount - Kernel Debug File System...`,
		`systemd[1]: Mounted sys-kernel-debug.mount - Kernel Debug File System.`,
	}, "\n")
	if err := os.WriteFile(filepath.Join(dir, "kernel.log"), []byte(benign+"\n"), 0o644); err != nil {
		t.Fatalf("write kernel log: %v", err)
	}

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify rejected benign kernel log artifacts: %v\n%s", err, output)
	}
}

func TestCrossHostSoakVerifyRejectsMismatchedBuildIdentity(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeStatusJSON(t, filepath.Join(dir, "collect", "a", "status.json"), "trustix-linux-amd64", "commit-a", "2026-06-15T00:00:00Z")
	writeStatusJSON(t, filepath.Join(dir, "collect", "b", "status.json"), "trustix-linux-amd64", "commit-b", "2026-06-15T00:00:00Z")

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted mismatched build identities:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRequiresStrongBuildIdentity(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeStatusJSON(t, filepath.Join(dir, "collect", "a", "status.json"), "dev", "unknown", "unknown")
	writeStatusJSON(t, filepath.Join(dir, "collect", "b", "status.json"), "dev", "unknown", "unknown")

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-strong-build-identity", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted weak build identities:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRejectsMismatchedBinaryIdentity(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeBinaryIdentityJSON(t, filepath.Join(dir, "collect", "a", "binary-identity.json"), "aaaaaaaa")
	writeBinaryIdentityJSON(t, filepath.Join(dir, "collect", "b", "binary-identity.json"), "bbbbbbbb")

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted mismatched binary identities:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRequiresStableBootIDs(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeStableBootIDs(t, dir)

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-stable-boot-id", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify rejected stable boot IDs:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRejectsChangedBootID(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeStableBootIDs(t, dir)
	writeBootID(t, filepath.Join(dir, "a", "boot-id-after.txt"), "boot-a-rebooted")

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-stable-boot-id", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted changed boot ID:\n%s", output)
	}
	if !strings.Contains(string(output), "boot-id changed") {
		t.Fatalf("verify did not report changed boot ID:\n%s", output)
	}
}

func TestCrossHostSoakVerifyChecksRequiredDatapathStats(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeDatapathJSON(t, filepath.Join(dir, "collect", "a", "datapath.json"), 1)
	writeDatapathJSON(t, filepath.Join(dir, "collect", "b", "datapath.json"), 0)

	cmd := exec.Command(
		python,
		"linux-cross-host-soak-verify.py",
		"--min-gbps",
		"4",
		"--min-seconds",
		"120",
		"--require-datapath-stat",
		"kernel_udp.provider_stats.kernel_datapath_full_plaintext_provider=1",
		dir,
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted missing datapath fast-path stat:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRequiresTwoDatapathStatsByDefault(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeDatapathJSON(t, filepath.Join(dir, "collect", "a", "datapath.json"), 1)

	cmd := exec.Command(
		python,
		"linux-cross-host-soak-verify.py",
		"--min-gbps",
		"4",
		"--min-seconds",
		"120",
		"--require-datapath-stat",
		"kernel_udp.provider_stats.kernel_datapath_full_plaintext_provider=1",
		dir,
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted one-sided datapath artifacts:\n%s", output)
	}
}

func TestCrossHostSoakVerifyChecksDatapathAndModuleCounterMinima(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	for _, node := range []string{"a", "b"} {
		writeDatapathJSONWithRX(t, filepath.Join(dir, "collect", node, "datapath.json"), 1, 42)
		writeModuleParameters(t, filepath.Join(dir, "collect", node, "module-parameters.txt"), map[string]map[string]string{
			"trustix_datapath": {
				"tx_plaintext_outer_gso_segments": "128",
				"rx_worker_gso_xmit_segments":     "256",
			},
		})
	}

	cmd := exec.Command(
		python,
		"linux-cross-host-soak-verify.py",
		"--min-gbps",
		"4",
		"--min-seconds",
		"120",
		"--require-datapath-min",
		"kernel_rx_stage.rx_worker_injected=1",
		"--require-datapath-min",
		"counters.session_dials=8",
		"--require-datapath-max",
		"counters.session_dial_errors=0",
		"--require-module-param-min",
		"trustix_datapath.tx_plaintext_outer_gso_segments=1",
		"--require-module-param-min",
		"trustix_datapath.rx_worker_gso_xmit_segments=1",
		dir,
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify rejected positive fast-path counters:\n%s", output)
	}
}

func TestCrossHostSoakVerifyChecksTransportPolicyAndSessions(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	for _, node := range []string{"a", "b"} {
		writeTransportsJSON(t, filepath.Join(dir, "collect", node, "transports.json"), 8, "flow", true, 8)
	}

	cmd := exec.Command(
		python,
		"linux-cross-host-soak-verify.py",
		"--min-gbps",
		"4",
		"--min-seconds",
		"120",
		"--require-transport-policy-min",
		"session_pool_size=8",
		"--require-transport-policy-stat",
		"session_pool_strategy=flow",
		"--require-transport-policy-stat",
		"session_pool_warmup=true",
		"--require-transport-sessions-min",
		"8",
		dir,
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify rejected valid transport session pool artifacts:\n%s", output)
	}
}

func TestCrossHostSoakVerifyChecksAnyDatapathCounterMinima(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeDatapathJSONWithSecureCounters(t, filepath.Join(dir, "collect", "a", "datapath.json"), 16, 0)
	writeDatapathJSONWithSecureCounters(t, filepath.Join(dir, "collect", "b", "datapath.json"), 0, 16)

	cmd := exec.Command(
		python,
		"linux-cross-host-soak-verify.py",
		"--min-gbps",
		"4",
		"--min-seconds",
		"120",
		"--require-datapath-any-min",
		"kernel_udp.provider_stats.tc_kernel_udp_tx_secure_direct_packets=1",
		"--require-datapath-any-min",
		"kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_packets=1",
		dir,
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify rejected any-min datapath counters:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRejectsMissingAnyDatapathCounterMinima(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	for _, node := range []string{"a", "b"} {
		writeDatapathJSONWithSecureCounters(t, filepath.Join(dir, "collect", node, "datapath.json"), 0, 16)
	}

	cmd := exec.Command(
		python,
		"linux-cross-host-soak-verify.py",
		"--min-gbps",
		"4",
		"--min-seconds",
		"120",
		"--require-datapath-any-min",
		"kernel_udp.provider_stats.tc_kernel_udp_tx_secure_direct_packets=1",
		dir,
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted missing any-min datapath counter:\n%s", output)
	}
	if !strings.Contains(string(output), "no collected datapath stat 'kernel_udp.provider_stats.tc_kernel_udp_tx_secure_direct_packets' reached >= 1") {
		t.Fatalf("verify did not report missing any-min counter:\n%s", output)
	}
}

func TestCrossHostSoakVerifyChecksStatusHealthCounters(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeStatusHealthJSON(t, filepath.Join(dir, "collect", "a", "status.json"), 8, 0, 0)
	writeStatusHealthJSON(t, filepath.Join(dir, "collect", "b", "status.json"), 8, 0, 0)

	cmd := exec.Command(
		python,
		"linux-cross-host-soak-verify.py",
		"--min-gbps",
		"4",
		"--min-seconds",
		"120",
		"--require-status-min",
		"data_path.active_sessions=8",
		"--require-status-max",
		"data_path.counters.session_dial_errors=0",
		"--require-status-max",
		"data_path.counters.session_heartbeat_timeouts=0",
		dir,
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify rejected healthy status counters:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRejectsUnhealthyStatusCounters(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeStatusHealthJSON(t, filepath.Join(dir, "collect", "a", "status.json"), 8, 1, 0)
	writeStatusHealthJSON(t, filepath.Join(dir, "collect", "b", "status.json"), 8, 0, 3)

	cmd := exec.Command(
		python,
		"linux-cross-host-soak-verify.py",
		"--min-gbps",
		"4",
		"--min-seconds",
		"120",
		"--require-status-min",
		"data_path.active_sessions=8",
		"--require-status-max",
		"data_path.counters.session_dial_errors=0",
		"--require-status-max",
		"data_path.counters.session_heartbeat_timeouts=0",
		dir,
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted unhealthy status counters:\n%s", output)
	}
	text := string(output)
	if !strings.Contains(text, "status stat data_path.counters.session_dial_errors=1, want <= 0") ||
		!strings.Contains(text, "status stat data_path.counters.session_heartbeat_timeouts=3, want <= 0") {
		t.Fatalf("verify did not report unhealthy status counters:\n%s", output)
	}
}

func TestCrossHostSoakVerifyAcceptsActiveTransportSessionSnapshot(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	for _, node := range []string{"a", "b"} {
		writeTransportsJSON(t, filepath.Join(dir, "collect", node, "transports-during-a-to-b-forward.json"), 8, "flow", true, 8)
		writeTransportsJSON(t, filepath.Join(dir, "collect", node, "transports.json"), 8, "flow", true, 0)
	}

	cmd := exec.Command(
		python,
		"linux-cross-host-soak-verify.py",
		"--min-gbps",
		"4",
		"--min-seconds",
		"120",
		"--require-transport-policy-min",
		"session_pool_size=8",
		"--require-transport-policy-stat",
		"session_pool_strategy=flow",
		"--require-transport-policy-stat",
		"session_pool_warmup=true",
		"--require-transport-sessions-min",
		"8",
		dir,
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify rejected active transport session snapshot:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRejectsInsufficientTransportSessions(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeTransportsJSON(t, filepath.Join(dir, "collect", "a", "transports.json"), 8, "flow", true, 8)
	writeTransportsJSON(t, filepath.Join(dir, "collect", "b", "transports.json"), 1, "flow", true, 1)

	cmd := exec.Command(
		python,
		"linux-cross-host-soak-verify.py",
		"--min-gbps",
		"4",
		"--min-seconds",
		"120",
		"--require-transport-policy-min",
		"session_pool_size=8",
		"--require-transport-policy-stat",
		"session_pool_strategy=flow",
		"--require-transport-policy-stat",
		"session_pool_warmup=true",
		"--require-transport-sessions-min",
		"8",
		dir,
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted insufficient transport sessions:\n%s", output)
	}
	if !strings.Contains(string(output), "transport sessions=1, want >= 8") {
		t.Fatalf("verify did not report insufficient sessions:\n%s", output)
	}
}

func TestCrossHostSoakVerifyChecksAnyModuleCounterMinima(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeModuleParameters(t, filepath.Join(dir, "collect", "a", "module-parameters.txt"), map[string]map[string]string{
		"trustix_datapath": {
			"tx_plaintext_outer_gso_segments": "128",
		},
	})
	writeModuleParameters(t, filepath.Join(dir, "collect", "b", "module-parameters.txt"), map[string]map[string]string{
		"trustix_datapath": {
			"tx_plaintext_outer_gso_segments": "0",
		},
	})

	cmd := exec.Command(
		python,
		"linux-cross-host-soak-verify.py",
		"--min-gbps",
		"4",
		"--min-seconds",
		"120",
		"--require-module-param-any-min",
		"trustix_datapath.tx_plaintext_outer_gso_segments=1",
		dir,
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify rejected one-sided fast-path counter:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRejectsMissingAnyModuleCounterMinima(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	for _, node := range []string{"a", "b"} {
		writeModuleParameters(t, filepath.Join(dir, "collect", node, "module-parameters.txt"), map[string]map[string]string{
			"trustix_datapath": {
				"tx_plaintext_outer_gso_segments": "0",
			},
		})
	}

	cmd := exec.Command(
		python,
		"linux-cross-host-soak-verify.py",
		"--min-gbps",
		"4",
		"--min-seconds",
		"120",
		"--require-module-param-any-min",
		"trustix_datapath.tx_plaintext_outer_gso_segments=1",
		dir,
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted missing any-min counter:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRejectsMissingModuleCounterMinima(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeModuleParameters(t, filepath.Join(dir, "collect", "a", "module-parameters.txt"), map[string]map[string]string{
		"trustix_datapath": {
			"tx_plaintext_outer_gso_segments": "128",
		},
	})

	cmd := exec.Command(
		python,
		"linux-cross-host-soak-verify.py",
		"--min-gbps",
		"4",
		"--min-seconds",
		"120",
		"--require-module-param-min",
		"trustix_datapath.tx_plaintext_outer_gso_segments=1",
		dir,
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted one-sided module counters:\n%s", output)
	}
}

func TestCrossHostSoakVerifyChecksDatapathAndModuleCounterMaxima(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	for _, node := range []string{"a", "b"} {
		writeDatapathJSONWithRX(t, filepath.Join(dir, "collect", node, "datapath.json"), 1, 0)
		writeModuleParameters(t, filepath.Join(dir, "collect", node, "module-parameters.txt"), map[string]map[string]string{
			"trustix_datapath": {
				"rx_worker_gso_xmit_errors": "0",
				"tx_plaintext_xmit_errors":  "0",
			},
		})
	}

	cmd := exec.Command(
		python,
		"linux-cross-host-soak-verify.py",
		"--min-gbps",
		"4",
		"--min-seconds",
		"120",
		"--require-datapath-max",
		"kernel_rx_stage.rx_worker_injected=0",
		"--require-module-param-max",
		"trustix_datapath.rx_worker_gso_xmit_errors=0",
		"--require-module-param-max",
		"trustix_datapath.tx_plaintext_xmit_errors=0",
		dir,
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify rejected zero error counters:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRejectsModuleCounterAboveMaximum(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	for _, node := range []string{"a", "b"} {
		value := "0"
		if node == "b" {
			value = "1"
		}
		writeModuleParameters(t, filepath.Join(dir, "collect", node, "module-parameters.txt"), map[string]map[string]string{
			"trustix_datapath_helpers": {
				"route_tcp_gso_async_xmit_errors": value,
			},
		})
	}

	cmd := exec.Command(
		python,
		"linux-cross-host-soak-verify.py",
		"--min-gbps",
		"4",
		"--min-seconds",
		"120",
		"--require-module-param-max",
		"trustix_datapath_helpers.route_tcp_gso_async_xmit_errors=0",
		dir,
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted non-zero error counter:\n%s", output)
	}
}

func TestCrossHostProductionGateAcceptsFullKmodArtifacts(t *testing.T) {
	requireProductionGateTools(t)
	dir := t.TempDir()
	writeFullKmodProductionGateArtifacts(t, dir, true)

	cmd := productionGateCommand(t, "TRUSTIX_CROSS_HOST_FULL_KMOD_CASES=full-kmod="+filepath.ToSlash(dir))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("production gate rejected full-kmod artifacts:\n%s", output)
	}
}

func TestCrossHostProductionGateRejectsFullKmodWithoutPlaintextXmit(t *testing.T) {
	requireProductionGateTools(t)
	dir := t.TempDir()
	writeFullKmodProductionGateArtifacts(t, dir, false)

	cmd := productionGateCommand(t, "TRUSTIX_CROSS_HOST_FULL_KMOD_CASES=full-kmod="+filepath.ToSlash(dir))
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("production gate unexpectedly accepted full-kmod artifacts without plaintext xmit:\n%s", output)
	}
	if !strings.Contains(string(output), "tx_plaintext_outer_gso_segments") {
		t.Fatalf("production gate did not report missing full-kmod plaintext xmit counter:\n%s", output)
	}
}

func TestCrossHostProductionGateRejectsFullKmodUnsafeModuleState(t *testing.T) {
	requireProductionGateTools(t)
	dir := t.TempDir()
	writeFullKmodProductionGateArtifacts(t, dir, true)
	writeFullKmodModuleParametersWithOverrides(t, filepath.Join(dir, "collect", "b", "module-parameters.txt"), true, map[string]string{
		"unsafe_features": "1",
	})

	cmd := productionGateCommand(t, "TRUSTIX_CROSS_HOST_FULL_KMOD_CASES=full-kmod="+filepath.ToSlash(dir))
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("production gate unexpectedly accepted full-kmod artifacts with unsafe module features:\n%s", output)
	}
	if !strings.Contains(string(output), "unsafe_features") {
		t.Fatalf("production gate did not report unsafe full-kmod module state:\n%s", output)
	}
}

func TestCrossHostProductionGateAcceptsSecureKUDPRouteGSOArtifacts(t *testing.T) {
	requireProductionGateTools(t)
	dir := t.TempDir()
	writeSecureKUDPProductionGateArtifacts(t, dir, true, true)

	cmd := productionGateCommand(t, "TRUSTIX_CROSS_HOST_SECURE_KUDP_CASES=secure-kudp="+filepath.ToSlash(dir))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("production gate rejected secure-kUDP route-GSO artifacts:\n%s", output)
	}
}

func TestCrossHostProductionGateRejectsSecureKUDPWithoutRouteGSO(t *testing.T) {
	requireProductionGateTools(t)
	dir := t.TempDir()
	writeSecureKUDPProductionGateArtifacts(t, dir, false, true)

	cmd := productionGateCommand(t, "TRUSTIX_CROSS_HOST_SECURE_KUDP_CASES=secure-kudp="+filepath.ToSlash(dir))
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("production gate unexpectedly accepted secure-kUDP artifacts without route-GSO:\n%s", output)
	}
	if !strings.Contains(string(output), "tc_kernel_udp_tx_secure_direct_route_tcp_gso_kfunc") {
		t.Fatalf("production gate did not report missing secure route-GSO datapath stat:\n%s", output)
	}
}

func TestCrossHostProductionGateRejectsSecureKUDPWithoutRouteHelperXmit(t *testing.T) {
	requireProductionGateTools(t)
	dir := t.TempDir()
	writeSecureKUDPProductionGateArtifacts(t, dir, true, false)

	cmd := productionGateCommand(t, "TRUSTIX_CROSS_HOST_SECURE_KUDP_CASES=secure-kudp="+filepath.ToSlash(dir))
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("production gate unexpectedly accepted secure-kUDP artifacts without route helper xmit:\n%s", output)
	}
	if !strings.Contains(string(output), "route_tcp_gso_async_xmit_packets") {
		t.Fatalf("production gate did not report missing secure route helper xmit counter:\n%s", output)
	}
}

func TestCrossHostProductionGateAcceptsRouteGSOArtifacts(t *testing.T) {
	requireProductionGateTools(t)
	dir := t.TempDir()
	writeRouteGSOProductionGateArtifacts(t, dir, true)

	cmd := productionGateCommand(t, "TRUSTIX_CROSS_HOST_ROUTE_GSO_CASES=route-gso="+filepath.ToSlash(dir))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("production gate rejected route-GSO artifacts:\n%s", output)
	}
}

func TestCrossHostProductionGateRejectsRouteGSOWithoutTCFlag(t *testing.T) {
	requireProductionGateTools(t)
	dir := t.TempDir()
	writeRouteGSOProductionGateArtifacts(t, dir, false)

	cmd := productionGateCommand(t, "TRUSTIX_CROSS_HOST_ROUTE_GSO_CASES=route-gso="+filepath.ToSlash(dir))
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("production gate unexpectedly accepted route-GSO artifacts without TC route-GSO flag:\n%s", output)
	}
	if !strings.Contains(string(output), "tc_experimental_tcp_tx_direct_route_tcp_gso_async_kfunc") {
		t.Fatalf("production gate did not report missing route-GSO datapath stat:\n%s", output)
	}
}

func requireProductionGateTools(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	output, err := exec.Command("bash", "--version").CombinedOutput()
	if err != nil || !strings.Contains(string(output), "GNU bash") {
		t.Skip("GNU bash not available")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
}

func productionGateCommand(t *testing.T, extraEnv ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("bash", "linux-cross-host-production-gate.sh")
	cmd.Dir = "."
	verifier, err := filepath.Abs("linux-cross-host-soak-verify.py")
	if err != nil {
		t.Fatalf("resolve verifier path: %v", err)
	}
	cmd.Env = append(os.Environ(), "TRUSTIX_CROSS_HOST_GATE_VERIFIER="+filepath.ToSlash(verifier))
	cmd.Env = append(cmd.Env, extraEnv...)
	return cmd
}

func writeIperfJSON(t *testing.T, path string, sentBPS, receivedBPS, seconds float64) {
	t.Helper()
	payload := map[string]any{
		"end": map[string]any{
			"sum_sent": map[string]any{
				"bits_per_second": sentBPS,
				"seconds":         seconds,
				"retransmits":     6,
			},
			"sum_received": map[string]any{
				"bits_per_second": receivedBPS,
				"seconds":         seconds,
			},
		},
		"intervals": []map[string]any{
			{"sum": map[string]any{"bits_per_second": sentBPS * 0.8, "retransmits": 1}},
			{"sum": map[string]any{"bits_per_second": sentBPS, "retransmits": 2}},
			{"sum": map[string]any{"bits_per_second": sentBPS * 1.1, "retransmits": 3}},
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal iperf json: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write iperf json: %v", err)
	}
}

func writeIperfReceiverJSON(t *testing.T, path string, receivedBPS, seconds float64) {
	t.Helper()
	writeIperfReceiverJSONWithError(t, path, receivedBPS, seconds, "")
}

func writeIperfReceiverJSONWithError(t *testing.T, path string, receivedBPS, seconds float64, iperfError string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("make iperf receiver artifact dir: %v", err)
	}
	payload := map[string]any{
		"end": map[string]any{
			"sum_sent": map[string]any{
				"bits_per_second": 0,
				"seconds":         seconds,
				"sender":          false,
			},
			"sum_received": map[string]any{
				"bits_per_second": receivedBPS,
				"seconds":         seconds,
				"sender":          false,
			},
		},
	}
	if iperfError != "" {
		payload["error"] = iperfError
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal iperf receiver json: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write iperf receiver json: %v", err)
	}
}

func writeIperfMissingServerResultsJSON(t *testing.T, path string, intervalBPS float64) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("make iperf artifact dir: %v", err)
	}
	payload := map[string]any{
		"error": "unable to receive results from server: Connection reset by peer",
		"intervals": []map[string]any{
			{"sum": map[string]any{"bits_per_second": intervalBPS}},
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal missing-server-results iperf json: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write missing-server-results iperf json: %v", err)
	}
}

func writeIperfBidirJSON(t *testing.T, path string, sentBPS, receivedBPS, reverseSentBPS, reverseReceivedBPS, seconds float64) {
	t.Helper()
	payload := map[string]any{
		"end": map[string]any{
			"sum_sent": map[string]any{
				"bits_per_second": sentBPS,
				"seconds":         seconds,
				"sender":          true,
			},
			"sum_received": map[string]any{
				"bits_per_second": receivedBPS,
				"seconds":         seconds,
				"sender":          true,
			},
			"sum_sent_bidir_reverse": map[string]any{
				"bits_per_second": reverseSentBPS,
				"seconds":         seconds,
				"sender":          false,
			},
			"sum_received_bidir_reverse": map[string]any{
				"bits_per_second": reverseReceivedBPS,
				"seconds":         seconds,
				"sender":          false,
			},
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal iperf bidir json: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write iperf bidir json: %v", err)
	}
}

func writeResultMarker(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "case.result"), []byte("pass\n"), 0o644); err != nil {
		t.Fatalf("write result marker: %v", err)
	}
}

func writeTextFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create parent for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeKernelLogArtifacts(t *testing.T, dir string) {
	t.Helper()
	writeTextFile(t, filepath.Join(dir, "collect", "a", "ix-a-kernel.log"), "kernel: TrustIX soak fixture clean\n")
	writeTextFile(t, filepath.Join(dir, "collect", "b", "ix-b-dmesg.log"), "[    0.000000] TrustIX soak fixture clean\n")
}

func writeStatusJSON(t *testing.T, path, version, commit, builtAt string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("make status dir: %v", err)
	}
	payload := map[string]any{
		"build": map[string]any{
			"version":    version,
			"commit":     commit,
			"built_at":   builtAt,
			"go_version": "go1.25.0",
			"goos":       "linux",
			"goarch":     "amd64",
			"assets": map[string]any{
				"ebpf": map[string]any{
					"kernel_udp_xdp_bpfel.o": map[string]any{
						"sha256": "asset-sha",
					},
				},
			},
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal status json: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write status json: %v", err)
	}
}

func writeStatusHealthJSON(t *testing.T, path string, activeSessions, dialErrors, heartbeatTimeouts int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("make status health dir: %v", err)
	}
	payload := map[string]any{
		"data_path": map[string]any{
			"active_sessions": activeSessions,
			"counters": map[string]any{
				"session_dial_errors":        dialErrors,
				"session_heartbeat_timeouts": heartbeatTimeouts,
			},
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal status health json: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write status health json: %v", err)
	}
}

func writeBinaryIdentityJSON(t *testing.T, path, sha256 string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("make binary identity dir: %v", err)
	}
	payload := map[string]any{
		"path":   "/tmp/trustix-e2e/bin/trustixd",
		"sha256": sha256,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal binary identity json: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write binary identity json: %v", err)
	}
}

func writeBootID(t *testing.T, path, value string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("make boot ID dir: %v", err)
	}
	if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
		t.Fatalf("write boot ID: %v", err)
	}
}

func writeStableBootIDs(t *testing.T, dir string) {
	t.Helper()
	for _, node := range []string{"a", "b"} {
		value := "boot-" + node
		writeBootID(t, filepath.Join(dir, node, "boot-id-before.txt"), value)
		writeBootID(t, filepath.Join(dir, node, "boot-id-after.txt"), value)
	}
}

func writeDatapathJSON(t *testing.T, path string, fullPlaintextProvider int) {
	t.Helper()
	writeDatapathJSONWithRX(t, path, fullPlaintextProvider, 0)
}

func writeDatapathJSONWithRX(t *testing.T, path string, fullPlaintextProvider int, rxWorkerInjected int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("make datapath dir: %v", err)
	}
	payload := map[string]any{
		"counters": map[string]any{
			"session_dials":       8,
			"session_dial_errors": 0,
		},
		"kernel_rx_stage": map[string]any{
			"rx_worker_injected": rxWorkerInjected,
		},
		"kernel_udp": map[string]any{
			"provider_stats": map[string]any{
				"kernel_datapath_full_plaintext_provider": fullPlaintextProvider,
			},
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal datapath json: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write datapath json: %v", err)
	}
}

func writeDatapathJSONWithSecureCounters(t *testing.T, path string, txPackets, rxPackets int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("make datapath dir: %v", err)
	}
	payload := map[string]any{
		"kernel_udp": map[string]any{
			"provider_stats": map[string]any{
				"tc_kernel_udp_tx_secure_direct_packets": txPackets,
				"tc_kernel_udp_rx_secure_direct_packets": rxPackets,
			},
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal datapath json: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write datapath json: %v", err)
	}
}

func writeTransportsJSON(t *testing.T, path string, poolSize int, strategy string, warmup bool, sessions int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("make transports dir: %v", err)
	}
	sessionRows := make([]any, 0, sessions)
	for i := 0; i < sessions; i++ {
		sessionRows = append(sessionRows, map[string]any{
			"peer":       "ix-b",
			"endpoint":   "b-experimental-tcp",
			"pool_index": i,
		})
	}
	payload := map[string]any{
		"policy": map[string]any{
			"encryption":            "plaintext",
			"profile":               "performance",
			"datapath":              "kernel_module",
			"crypto_placement":      "userspace",
			"session_pool_size":     poolSize,
			"session_pool_strategy": strategy,
			"session_pool_warmup":   warmup,
		},
		"sessions": sessionRows,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal transports json: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write transports json: %v", err)
	}
}

func writeModuleParameters(t *testing.T, path string, modules map[string]map[string]string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("make module parameters dir: %v", err)
	}
	var builder strings.Builder
	for module, params := range modules {
		builder.WriteString("===== " + module + " =====\n")
		for name, value := range params {
			builder.WriteString(name + "=" + value + "\n")
		}
	}
	if err := os.WriteFile(path, []byte(builder.String()), 0o644); err != nil {
		t.Fatalf("write module parameters: %v", err)
	}
}

func writeFullKmodProductionGateArtifacts(t *testing.T, dir string, plaintextXmit bool) {
	t.Helper()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 3.3e9, 3.2e9, 900.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 3.3e9, 3.2e9, 900.2)
	writeResultMarker(t, dir)
	writeStableBootIDs(t, dir)
	writeKernelLogArtifacts(t, dir)
	for _, node := range []string{"a", "b"} {
		base := filepath.Join(dir, "collect", node)
		writeStatusHealthJSON(t, filepath.Join(base, "status.json"), 8, 0, 0)
		writeBinaryIdentityJSON(t, filepath.Join(base, "binary-identity.json"), "full-kmod-sha")
		writeDatapathJSONWithRX(t, filepath.Join(base, "datapath.json"), 1, 42)
		writeTransportsJSON(t, filepath.Join(base, "transports.json"), 8, "flow", true, 8)
		writeFullKmodModuleParameters(t, filepath.Join(base, "module-parameters.txt"), plaintextXmit)
	}
}

func writeFullKmodModuleParameters(t *testing.T, path string, plaintextXmit bool) {
	t.Helper()
	writeFullKmodModuleParametersWithOverrides(t, path, plaintextXmit, nil)
}

func writeFullKmodModuleParametersWithOverrides(t *testing.T, path string, plaintextXmit bool, overrides map[string]string) {
	t.Helper()
	plaintextSegments := "0"
	if plaintextXmit {
		plaintextSegments = "128"
	}
	params := map[string]string{
		"enable_features":                             "128",
		"features":                                    "128",
		"safe_features":                               "128",
		"unsafe_features":                             "0",
		"selftest_failures":                           "0",
		"rx_worker_inject":                            "Y",
		"tx_plaintext":                                "Y",
		"rx_worker_hot_stats":                         "N",
		"tx_plaintext_skip_inner_tcp_checksum":        "N",
		"session_records":                             "8",
		"session_wire_records":                        "8",
		"rx_worker_single_coalesce_max_frames":        "32",
		"tx_plaintext_outer_gso_segments":             plaintextSegments,
		"tx_plaintext_direct_xmit_dst_mac_cache_hits": "8",
		"rx_worker_gso_xmit_segments":                 "8",
		"rx_worker_alloc_errors":                      "0",
		"rx_worker_deliver_errors":                    "0",
		"rx_worker_gso_xmit_errors":                   "0",
		"rx_worker_xmit_ret_errors":                   "0",
		"rx_worker_xmit_other_ret_errors":             "0",
		"rx_worker_xmit_dev_forward_errors":           "0",
		"rx_worker_xmit_peer_forward_errors":          "0",
		"tx_plaintext_build_errors":                   "0",
		"tx_plaintext_no_sessions":                    "0",
		"tx_plaintext_no_wires":                       "0",
		"tx_plaintext_stale_wires":                    "0",
		"tx_plaintext_xmit_errors":                    "0",
		"tx_plaintext_outer_gso_errors":               "0",
		"tx_plaintext_queue_drops":                    "0",
	}
	for name, value := range overrides {
		params[name] = value
	}
	writeModuleParameters(t, path, map[string]map[string]string{"trustix_datapath": params})
}

func writeSecureKUDPProductionGateArtifacts(t *testing.T, dir string, routeGSO bool, routeHelperXmit bool) {
	t.Helper()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 1.9e9, 1.8e9, 900.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 1.9e9, 1.8e9, 900.2)
	writeResultMarker(t, dir)
	writeStableBootIDs(t, dir)
	writeKernelLogArtifacts(t, dir)
	for _, node := range []string{"a", "b"} {
		base := filepath.Join(dir, "collect", node)
		writeStatusHealthJSON(t, filepath.Join(base, "status.json"), 8, 0, 0)
		writeBinaryIdentityJSON(t, filepath.Join(base, "binary-identity.json"), "secure-kudp-sha")
		writeSecureKUDPDatapathJSON(t, filepath.Join(base, "datapath.json"), routeGSO)
		writeSecureKUDPTransportsJSON(t, filepath.Join(base, "transports.json"))
		writeSecureKUDPModuleParameters(t, filepath.Join(base, "module-parameters.txt"), routeHelperXmit)
	}
}

func writeSecureKUDPDatapathJSON(t *testing.T, path string, routeGSO bool) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("make secure-kudp datapath dir: %v", err)
	}
	routeGSOValue := 0
	if routeGSO {
		routeGSOValue = 1
	}
	payload := map[string]any{
		"kernel_udp": map[string]any{
			"kernel_crypto":    true,
			"requested_crypto": "kernel",
			"effective_crypto": "kernel",
			"provider_stats": map[string]any{
				"kernel_crypto_flow_map_ready":                         1,
				"kernel_crypto_flow_map_entries":                       1,
				"kernel_crypto_flow_map_updates":                       1,
				"kernel_crypto_direct_slot_provider_ready":             1,
				"kernel_crypto_direct_kfunc_fastpath_ready":            1,
				"kernel_crypto_tc_direct_ready":                        1,
				"tc_kernel_udp_tx_direct_only_enabled":                 1,
				"tc_kernel_udp_tx_secure_direct_attached":              1,
				"tc_kernel_udp_rx_secure_direct_attached":              1,
				"tc_kernel_udp_tx_secure_direct_trust_inner_checksums": 1,
				"tc_kernel_udp_tx_secure_direct_kfunc_seal_enabled":    1,
				"tc_kernel_udp_tx_secure_direct_route_tcp_gso_kfunc":   routeGSOValue,
				"tc_kernel_udp_rx_secure_direct_kfunc_open_enabled":    1,
				"tc_kernel_udp_rx_secure_direct_skb_open_kfunc":        0,
				"kernel_crypto_provider_unavailable_errors":            0,
				"kernel_crypto_flow_rejects":                           0,
				"kernel_crypto_frame_rejects":                          0,
				"kernel_crypto_frame_seal_errors":                      0,
				"kernel_crypto_frame_open_errors":                      0,
				"kernel_crypto_frame_replay_drops":                     0,
				"tc_kernel_udp_tx_secure_direct_encrypt_errors":        0,
				"tc_kernel_udp_tx_secure_direct_sequence_errors":       0,
				"tc_kernel_udp_tx_secure_direct_drops":                 0,
				"tc_kernel_udp_rx_secure_direct_header_errors":         0,
				"tc_kernel_udp_rx_secure_direct_decrypt_errors":        0,
				"tc_kernel_udp_rx_secure_direct_replay_drops":          0,
				"tc_kernel_udp_rx_secure_direct_drops":                 0,
			},
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal secure-kudp datapath json: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write secure-kudp datapath json: %v", err)
	}
}

func writeSecureKUDPTransportsJSON(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("make secure-kudp transports dir: %v", err)
	}
	payload := map[string]any{
		"policy": map[string]any{
			"encryption":            "secure",
			"crypto_placement":      "kernel",
			"datapath":              "tc_xdp",
			"session_pool_size":     8,
			"session_pool_strategy": "flow",
			"session_pool_warmup":   true,
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal secure-kudp transports json: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write secure-kudp transports json: %v", err)
	}
}

func writeSecureKUDPModuleParameters(t *testing.T, path string, routeHelperXmit bool) {
	t.Helper()
	xmitPackets := "0"
	if routeHelperXmit {
		xmitPackets = "8"
	}
	writeModuleParameters(t, path, map[string]map[string]string{
		"trustix_crypto": {
			"kfunc_simd_fastpath":         "1",
			"kfunc_simd_irq_fpu_fastpath": "1",
			"direct_kfunc_seal_calls":     "16",
			"direct_kfunc_open_calls":     "16",
			"direct_kfunc_errors":         "0",
		},
		"trustix_datapath_helpers": {
			"route_tcp_gso_async_secure_seal_batch":                    "1",
			"route_tcp_gso_async_stream_outer_gso_frames":              "0",
			"route_tcp_gso_async_xmit_packets":                         xmitPackets,
			"route_tcp_gso_async_flow_errors":                          "0",
			"route_tcp_gso_async_plan_errors":                          "0",
			"route_tcp_gso_async_mtu_errors":                           "0",
			"route_tcp_gso_async_queue_full":                           "0",
			"route_tcp_gso_async_queue_bytes_full":                     "0",
			"route_tcp_gso_async_alloc_errors":                         "0",
			"route_tcp_gso_async_clone_errors":                         "0",
			"route_tcp_gso_async_segment_errors":                       "0",
			"route_tcp_gso_async_prepare_errors":                       "0",
			"route_tcp_gso_async_txq_stopped_drops":                    "0",
			"route_tcp_gso_async_xmit_errors":                          "0",
			"route_tcp_gso_async_stream_errors":                        "0",
			"route_tcp_gso_async_stream_xmit_errors":                   "0",
			"route_tcp_gso_async_stream_direct_errors":                 "0",
			"route_tcp_gso_async_stream_outer_gso_errors":              "0",
			"route_tcp_gso_async_stream_outer_gso_blocked":             "0",
			"route_tcp_gso_async_stream_outer_gso_verify_errors":       "0",
			"route_tcp_gso_async_stream_cross_item_errors":             "0",
			"route_tcp_gso_async_stream_cross_item_tail_stitch_errors": "0",
		},
	})
}

func writeRouteGSOProductionGateArtifacts(t *testing.T, dir string, routeGSO bool) {
	t.Helper()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 2.8e9, 2.7e9, 900.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 2.8e9, 2.7e9, 900.2)
	writeResultMarker(t, dir)
	writeStableBootIDs(t, dir)
	writeKernelLogArtifacts(t, dir)
	for _, node := range []string{"a", "b"} {
		base := filepath.Join(dir, "collect", node)
		writeStatusHealthJSON(t, filepath.Join(base, "status.json"), 8, 0, 0)
		writeBinaryIdentityJSON(t, filepath.Join(base, "binary-identity.json"), "route-gso-sha")
		writeRouteGSODatapathJSON(t, filepath.Join(base, "datapath.json"), routeGSO)
		writeTransportsJSON(t, filepath.Join(base, "transports.json"), 8, "flow", true, 8)
		writeRouteGSOModuleParameters(t, filepath.Join(base, "module-parameters.txt"))
	}
}

func writeRouteGSODatapathJSON(t *testing.T, path string, routeGSO bool) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("make route-GSO datapath dir: %v", err)
	}
	routeGSOValue := 0
	if routeGSO {
		routeGSOValue = 1
	}
	payload := map[string]any{
		"kernel_udp": map[string]any{
			"provider_stats": map[string]any{
				"tc_experimental_tcp_tx_direct_route_tcp_gso_async_kfunc":           routeGSOValue,
				"tc_experimental_tcp_tx_direct_route_tcp_gso_async_kfunc_requested": 1,
				"tc_kernel_udp_tx_direct_experimental_tcp_only":                     1,
			},
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal route-GSO datapath json: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write route-GSO datapath json: %v", err)
	}
}

func writeRouteGSOModuleParameters(t *testing.T, path string) {
	t.Helper()
	writeModuleParameters(t, path, map[string]map[string]string{
		"trustix_datapath_helpers": routeGSOHelperParameters(),
	})
}

func routeGSOHelperParameters() map[string]string {
	return map[string]string{
		"route_tcp_gso_async_hash_tx_queue":                        "1",
		"route_tcp_gso_async_stream_outer_gso_frames":              "8",
		"route_tcp_gso_async_xmit_packets":                         "8",
		"route_tcp_gso_async_flow_errors":                          "0",
		"route_tcp_gso_async_plan_errors":                          "0",
		"route_tcp_gso_async_mtu_errors":                           "0",
		"route_tcp_gso_async_queue_full":                           "0",
		"route_tcp_gso_async_queue_bytes_full":                     "0",
		"route_tcp_gso_async_alloc_errors":                         "0",
		"route_tcp_gso_async_clone_errors":                         "0",
		"route_tcp_gso_async_segment_errors":                       "0",
		"route_tcp_gso_async_prepare_errors":                       "0",
		"route_tcp_gso_async_txq_stopped_drops":                    "0",
		"route_tcp_gso_async_xmit_errors":                          "0",
		"route_tcp_gso_async_stream_errors":                        "0",
		"route_tcp_gso_async_stream_xmit_errors":                   "0",
		"route_tcp_gso_async_stream_direct_errors":                 "0",
		"route_tcp_gso_async_stream_outer_gso_errors":              "0",
		"route_tcp_gso_async_stream_outer_gso_blocked":             "0",
		"route_tcp_gso_async_stream_outer_gso_verify_errors":       "0",
		"route_tcp_gso_async_stream_cross_item_errors":             "0",
		"route_tcp_gso_async_stream_cross_item_tail_stitch_errors": "0",
	}
}
