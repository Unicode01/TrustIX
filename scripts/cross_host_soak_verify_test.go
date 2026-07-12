package scripts

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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

func TestCrossHostSoakVerifyRejectsTooFewIperfIntervals(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--min-iperf-intervals", "4", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted too few interval samples:\n%s", output)
	}
	if !strings.Contains(string(output), "interval count 3, want >= 4") {
		t.Fatalf("verify output did not report too few interval samples:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRejectsLowIperfIntervalFloor(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSONWithIntervals(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2, 8, 0.1)
	writeIperfJSONWithIntervals(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2, 8, 0.8)
	writeResultMarker(t, dir)

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--min-iperf-interval-gbps-ratio", "0.5", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted low interval floor:\n%s", output)
	}
	if !strings.Contains(string(output), "interval min 0.510Gbps < 2.000Gbps") {
		t.Fatalf("verify output did not report low interval floor:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRequiresRunTiming(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-run-timing", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted missing run timing:\n%s", output)
	}
	if !strings.Contains(string(output), "run-timing.json") {
		t.Fatalf("verify output did not report missing run timing:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRejectsShortRunTiming(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeRunTiming(t, dir, 1000, 1060, 120)

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-run-timing", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted short run timing:\n%s", output)
	}
	if !strings.Contains(string(output), "elapsed_seconds") {
		t.Fatalf("verify output did not report short run timing:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRejectsShortRequestedRunTiming(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeRunTiming(t, dir, 1000, 1121, 60)

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-run-timing", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted short requested timing:\n%s", output)
	}
	if !strings.Contains(string(output), "iperf_seconds_requested") {
		t.Fatalf("verify output did not report short requested timing:\n%s", output)
	}
}

func TestCrossHostSoakVerifyChecksRequiredRunTimingStats(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeRunTimingWithStats(t, dir, 1000, 1121, 120, map[string]any{
		"iperf_mode":       "bidir",
		"iperf_directions": "a2b",
	})

	cmd := exec.Command(
		python,
		"linux-cross-host-soak-verify.py",
		"--min-gbps", "4",
		"--min-seconds", "120",
		"--require-run-timing-stat", "iperf_mode=forward",
		"--require-run-timing-stat", "iperf_directions=both",
		dir,
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted wrong run timing stats:\n%s", output)
	}
	if !strings.Contains(string(output), "run timing iperf_mode='bidir', want 'forward'") ||
		!strings.Contains(string(output), "run timing iperf_directions='a2b', want 'both'") {
		t.Fatalf("verify output did not report run timing stat mismatch:\n%s", output)
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

func TestCrossHostSoakVerifyAcceptsEmptyJournalWindow(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeTextFile(t, filepath.Join(dir, "collect", "a", "ix-a-kernel.log"), "-- No entries --\n")
	writeTextFile(t, filepath.Join(dir, "collect", "b", "ix-b-dmesg.log"), "[    0.000000] Linux version test\n")

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-kernel-log-artifacts", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify rejected empty journal window: %v\n%s", err, output)
	}
}

func TestCrossHostSoakVerifyRequiresPstoreArtifacts(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-pstore-artifacts", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted missing pstore artifacts:\n%s", output)
	}
	if !strings.Contains(string(output), "pstore artifacts") {
		t.Fatalf("verify output did not report missing pstore artifacts:\n%s", output)
	}
}

func TestCrossHostSoakVerifyAcceptsPstoreArtifacts(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writePstoreArtifacts(t, dir)

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-pstore-artifacts", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify rejected pstore artifacts: %v\n%s", err, output)
	}
}

func TestCrossHostSoakVerifyRejectsPstoreCrashArtifact(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writePstoreArtifacts(t, dir)
	writeTextFile(t, filepath.Join(dir, "collect", "a", "ix-a-pstore.txt"), "===== /sys/fs/pstore/dmesg-ramoops-0 =====\nKernel panic - not syncing: test\n")

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-pstore-artifacts", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted pstore crash artifact:\n%s", output)
	}
	if !strings.Contains(string(output), "log crash signature") ||
		!strings.Contains(string(output), "pstore") {
		t.Fatalf("verify output did not report pstore crash artifact:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRequiresLANStateArtifacts(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-lan-state-artifacts", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted missing LAN state artifacts:\n%s", output)
	}
	if !strings.Contains(string(output), "LAN state artifacts") {
		t.Fatalf("verify output did not report missing LAN state artifacts:\n%s", output)
	}
}

func TestCrossHostSoakVerifyAcceptsLANStateArtifacts(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeLANStateArtifacts(t, dir, 1000, 1000)

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-lan-state-artifacts", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify rejected LAN state artifacts: %v\n%s", err, output)
	}
}

func TestCrossHostSoakVerifyRejectsZeroLANTxQueueLen(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeLANStateArtifacts(t, dir, 1000, 0)

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-lan-state-artifacts", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted zero LAN tx_queue_len:\n%s", output)
	}
	if !strings.Contains(string(output), "LAN tx_queue_len=0") {
		t.Fatalf("verify output did not report zero LAN tx_queue_len:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRequiresHostStateArtifacts(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-host-state-artifacts", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted missing host state artifacts:\n%s", output)
	}
	if !strings.Contains(string(output), "host state artifacts") {
		t.Fatalf("verify output did not report missing host state artifacts:\n%s", output)
	}
}

func TestCrossHostSoakVerifyAcceptsHostStateArtifacts(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeHostStateArtifacts(t, dir, 4, 4, "virtio_net", "virtio_net")

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-host-state-artifacts", "--min-host-cpus", "4", "--forbid-host-net-driver", "e1000", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify rejected host state artifacts: %v\n%s", err, output)
	}
}

func TestCrossHostSoakVerifyRejectsLowHostCPUCount(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeHostStateArtifacts(t, dir, 4, 2, "virtio_net", "virtio_net")

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-host-state-artifacts", "--min-host-cpus", "4", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted low host CPU count:\n%s", output)
	}
	if !strings.Contains(string(output), "host cpu_count=2") {
		t.Fatalf("verify output did not report low host CPU count:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRejectsForbiddenHostNetDriver(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeHostStateArtifacts(t, dir, 4, 4, "virtio_net", "e1000")

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-host-state-artifacts", "--forbid-host-net-driver", "e1000", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted forbidden host net driver:\n%s", output)
	}
	if !strings.Contains(string(output), "forbidden host net driver") ||
		!strings.Contains(string(output), "e1000") {
		t.Fatalf("verify output did not report forbidden host net driver:\n%s", output)
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

func TestCrossHostSoakVerifyRejectsNetdevUnregisterWaitLogs(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "kernel.log"), []byte("unregister_netdevice: waiting for tix-lan to become free. Usage count = 2\n"), 0o644); err != nil {
		t.Fatalf("write unregister_netdevice log: %v", err)
	}

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted unregister_netdevice log:\n%s", output)
	}
	if !strings.Contains(string(output), "unregister_netdevice") {
		t.Fatalf("verify output did not report unregister_netdevice signature:\n%s", output)
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

func TestCrossHostSoakVerifyRequiresUnameArtifacts(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-uname-artifacts", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted missing uname artifacts:\n%s", output)
	}
	if !strings.Contains(string(output), "uname artifacts") {
		t.Fatalf("verify output did not report missing uname coverage:\n%s", output)
	}
}

func TestCrossHostSoakVerifyAcceptsStableUnameArtifacts(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeStableUnames(t, dir)

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-uname-artifacts", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify rejected stable uname artifacts:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRejectsChangedKernelRelease(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeStableUnames(t, dir)
	writeTextFile(t, filepath.Join(dir, "a", "uname-after.txt"), "Linux ix-a 6.6.141 #1 SMP x86_64 GNU/Linux\n")

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-uname-artifacts", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted changed kernel release:\n%s", output)
	}
	if !strings.Contains(string(output), "kernel release changed") {
		t.Fatalf("verify output did not report changed kernel release:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRequiresOSReleaseArtifacts(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-os-release-artifacts", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted missing os-release artifacts:\n%s", output)
	}
	if !strings.Contains(string(output), "os-release artifacts") {
		t.Fatalf("verify output did not report missing os-release coverage:\n%s", output)
	}
}

func TestCrossHostSoakVerifyAcceptsStableOSReleaseArtifacts(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeStableOSReleases(t, dir)

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-os-release-artifacts", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify rejected stable os-release artifacts:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRejectsChangedOSRelease(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeStableOSReleases(t, dir)
	writeTextFile(t, filepath.Join(dir, "a", "os-release-after.txt"), "NAME=\"OpenWrt\"\nID=openwrt\nVERSION_ID=\"24.10.2\"\n")

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-os-release-artifacts", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted changed os-release:\n%s", output)
	}
	if !strings.Contains(string(output), "os-release changed") {
		t.Fatalf("verify output did not report changed os-release:\n%s", output)
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

func TestCrossHostSoakVerifyRequiresLsmodArtifacts(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-lsmod-artifacts", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted missing lsmod artifacts:\n%s", output)
	}
	if !strings.Contains(string(output), "lsmod artifacts") {
		t.Fatalf("verify output did not report missing lsmod artifacts:\n%s", output)
	}
}

func TestCrossHostSoakVerifyChecksRequiredLsmodModules(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeLsmodArtifacts(t, dir, map[string][]string{
		"a": {"trustix_datapath"},
		"b": {"trustix_datapath"},
	})

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-lsmod-artifacts", "--require-lsmod-module", "trustix_datapath", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify rejected required lsmod modules:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRejectsMissingRequiredLsmodModule(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeLsmodArtifacts(t, dir, map[string][]string{
		"a": {"trustix_datapath"},
		"b": {},
	})

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-lsmod-artifacts", "--require-lsmod-module", "trustix_datapath", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted missing required lsmod module:\n%s", output)
	}
	if !strings.Contains(string(output), "missing loaded module") {
		t.Fatalf("verify output did not report missing lsmod module:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRejectsForbiddenLsmodPrefix(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeLsmodArtifacts(t, dir, map[string][]string{
		"a": {"trustix_datapath"},
		"b": {},
	})

	cmd := exec.Command(python, "linux-cross-host-soak-verify.py", "--min-gbps", "4", "--min-seconds", "120", "--require-lsmod-artifacts", "--forbid-lsmod-prefix", "trustix_", dir)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted forbidden lsmod module prefix:\n%s", output)
	}
	if !strings.Contains(string(output), "forbidden loaded modules") {
		t.Fatalf("verify output did not report forbidden lsmod module prefix:\n%s", output)
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
		"--require-transport-local-endpoint-stat",
		"transport=experimental_tcp",
		"--require-transport-local-endpoint-stat",
		"usable=true",
		"--require-transport-peer-endpoint-stat",
		"transport=experimental_tcp",
		"--require-transport-peer-endpoint-stat",
		"usable=true",
		"--require-transport-sessions-min",
		"8",
		"--require-transport-session-stat",
		"transport=experimental_tcp",
		"--require-transport-session-stat",
		"stats.encryption=plaintext",
		"--require-transport-session-any-min",
		"stats.bytes_sent=1",
		"--require-transport-session-any-min",
		"stats.bytes_received=1",
		"--require-transport-session-endpoint-suffix=-experimental-tcp",
		dir,
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify rejected valid transport session pool artifacts:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRejectsWrongTransportEndpoint(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	for _, node := range []string{"a", "b"} {
		writeTransportsJSONWithSession(t, filepath.Join(dir, "collect", node, "transports.json"), 8, "flow", true, 8, "tcp", peerEndpointForNode(node, "-tcp"))
	}

	cmd := exec.Command(
		python,
		"linux-cross-host-soak-verify.py",
		"--min-gbps",
		"4",
		"--min-seconds",
		"120",
		"--require-transport-local-endpoint-stat",
		"transport=experimental_tcp",
		dir,
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted wrong transport endpoint:\n%s", output)
	}
	if !strings.Contains(string(output), "matching transport local_endpoints=0") {
		t.Fatalf("verify did not report wrong transport local endpoint:\n%s", output)
	}
}

func TestCrossHostSoakVerifyMatchesTransportEndpointListStats(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	for _, node := range []string{"a", "b"} {
		writeTransportsJSONWithSessionStats(t, filepath.Join(dir, "collect", node, "transports.json"), 8, "flow", true, 8, "udp", peerEndpointForNode(node, "-udp"), map[string]any{
			"encryption":       "secure",
			"bytes_sent":       4096,
			"bytes_received":   4096,
			"packets_sent":     4,
			"packets_received": 4,
		})
	}

	cmd := exec.Command(
		python,
		"linux-cross-host-soak-verify.py",
		"--min-gbps",
		"4",
		"--min-seconds",
		"120",
		"--require-transport-local-endpoint-stat",
		"encryption=secure",
		"--require-transport-local-endpoint-stat",
		"crypto_placements=userspace",
		"--require-transport-peer-endpoint-stat",
		"crypto_placements=userspace",
		dir,
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify rejected endpoint list stat match:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRejectsWrongTransportSessionEndpoint(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	for _, node := range []string{"a", "b"} {
		writeTransportsJSONWithSession(t, filepath.Join(dir, "collect", node, "transports.json"), 8, "flow", true, 8, "tcp", peerEndpointForNode(node, "-tcp"))
	}

	cmd := exec.Command(
		python,
		"linux-cross-host-soak-verify.py",
		"--min-gbps",
		"4",
		"--min-seconds",
		"120",
		"--require-transport-sessions-min",
		"8",
		"--require-transport-session-stat",
		"transport=experimental_tcp",
		"--require-transport-session-endpoint-suffix=-experimental-tcp",
		dir,
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted wrong transport session endpoint:\n%s", output)
	}
	if !strings.Contains(string(output), "matching transport sessions=0, want >= 8") {
		t.Fatalf("verify did not report wrong transport session endpoint:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRejectsWrongTransportSessionStats(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	for _, node := range []string{"a", "b"} {
		writeTransportsJSONWithSession(t, filepath.Join(dir, "collect", node, "transports.json"), 8, "flow", true, 8, "experimental_tcp", peerEndpointForNode(node, "-experimental-tcp"))
	}

	cmd := exec.Command(
		python,
		"linux-cross-host-soak-verify.py",
		"--min-gbps",
		"4",
		"--min-seconds",
		"120",
		"--require-transport-sessions-min",
		"8",
		"--require-transport-session-stat",
		"transport=experimental_tcp",
		"--require-transport-session-stat",
		"stats.encryption=secure",
		"--require-transport-session-endpoint-suffix=-experimental-tcp",
		dir,
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted wrong transport session stats:\n%s", output)
	}
	if !strings.Contains(string(output), "stats.encryption=secure") {
		t.Fatalf("verify did not report wrong transport session stats:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRejectsIdleMatchingTransportSessions(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	for _, node := range []string{"a", "b"} {
		writeTransportsJSONWithSessionStats(t, filepath.Join(dir, "collect", node, "transports.json"), 8, "flow", true, 8, "experimental_tcp", peerEndpointForNode(node, "-experimental-tcp"), map[string]any{
			"encryption":       "plaintext",
			"bytes_sent":       0,
			"bytes_received":   0,
			"packets_sent":     0,
			"packets_received": 0,
		})
	}

	cmd := exec.Command(
		python,
		"linux-cross-host-soak-verify.py",
		"--min-gbps",
		"4",
		"--min-seconds",
		"120",
		"--require-transport-sessions-min",
		"8",
		"--require-transport-session-stat",
		"transport=experimental_tcp",
		"--require-transport-session-stat",
		"stats.encryption=plaintext",
		"--require-transport-session-any-min",
		"stats.bytes_sent=1",
		"--require-transport-session-endpoint-suffix=-experimental-tcp",
		dir,
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted idle matching transport sessions:\n%s", output)
	}
	if !strings.Contains(string(output), "stats.bytes_sent=0, want >= 1") {
		t.Fatalf("verify did not report idle matching transport sessions:\n%s", output)
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

func TestCrossHostSoakVerifyChecksDatapathRatioMaxima(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeDatapathJSONWithReplayStats(t, filepath.Join(dir, "collect", "a", "datapath.json"), 20, 0, 1000000, 20)
	writeDatapathJSONWithReplayStats(t, filepath.Join(dir, "collect", "b", "datapath.json"), 0, 0, 500000, 0)

	cmd := exec.Command(
		python,
		"linux-cross-host-soak-verify.py",
		"--min-gbps",
		"4",
		"--min-seconds",
		"120",
		"--require-datapath-max",
		"kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_replay_old_drops=0",
		"--require-datapath-ratio-max",
		"kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_replay_seen_drops/kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_kfunc_open_attempts=0.00002",
		"--require-datapath-ratio-max",
		"kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_drops/kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_kfunc_open_attempts=0.00002",
		dir,
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify rejected bounded datapath ratios:\n%s", output)
	}
}

func TestCrossHostSoakVerifyRejectsHighDatapathRatio(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 5.1e9, 5.0e9, 120.2)
	writeIperfJSON(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 5.1e9, 5.0e9, 120.2)
	writeResultMarker(t, dir)
	writeDatapathJSONWithReplayStats(t, filepath.Join(dir, "collect", "a", "datapath.json"), 100, 0, 1000, 100)
	writeDatapathJSONWithReplayStats(t, filepath.Join(dir, "collect", "b", "datapath.json"), 0, 0, 500000, 0)

	cmd := exec.Command(
		python,
		"linux-cross-host-soak-verify.py",
		"--min-gbps",
		"4",
		"--min-seconds",
		"120",
		"--require-datapath-ratio-max",
		"kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_replay_seen_drops/kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_kfunc_open_attempts=0.00002",
		dir,
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify unexpectedly accepted high datapath ratio:\n%s", output)
	}
	if !strings.Contains(string(output), "datapath ratio kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_replay_seen_drops/kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_kfunc_open_attempts") {
		t.Fatalf("verify did not report high datapath ratio:\n%s", output)
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
		"--require-status-max",
		"data_path.drop_reasons.FLOW_NOT_INSTALLED=0",
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
		"--require-transport-session-stat",
		"transport=experimental_tcp",
		"--require-transport-session-stat",
		"stats.encryption=plaintext",
		"--require-transport-session-any-min",
		"stats.bytes_sent=1",
		"--require-transport-session-any-min",
		"stats.bytes_received=1",
		"--require-transport-session-endpoint-suffix=-experimental-tcp",
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

func TestCrossHostProductionGateAcceptsOpenWrtDebianFullKmodWithSingleCoalesceDisabled(t *testing.T) {
	requireProductionGateTools(t)
	dir := t.TempDir()
	writeFullKmodProductionGateArtifacts(t, dir, true)
	writeFullKmodModuleParametersWithOverrides(t, filepath.Join(dir, "collect", "a", "module-parameters.txt"), true, map[string]string{
		"rx_worker_single_coalesce": "N",
	})
	writeFullKmodModuleParametersWithOverrides(t, filepath.Join(dir, "collect", "b", "module-parameters.txt"), true, map[string]string{
		"rx_worker_single_coalesce": "Y",
	})

	cmd := productionGateCommand(t, "TRUSTIX_CROSS_HOST_FULL_KMOD_CASES=owdeb-fullkmod="+filepath.ToSlash(dir))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("production gate rejected OpenWrt-Debian full-kmod artifacts with single-coalesce disabled:\n%s", output)
	}
}

func TestCrossHostProductionGateRejectsOpenWrtDebianFullKmodWithSingleCoalesceEnabled(t *testing.T) {
	requireProductionGateTools(t)
	dir := t.TempDir()
	writeFullKmodProductionGateArtifacts(t, dir, true)
	writeFullKmodModuleParametersWithOverrides(t, filepath.Join(dir, "collect", "a", "module-parameters.txt"), true, map[string]string{
		"rx_worker_single_coalesce": "Y",
	})
	writeFullKmodModuleParametersWithOverrides(t, filepath.Join(dir, "collect", "b", "module-parameters.txt"), true, map[string]string{
		"rx_worker_single_coalesce": "N",
	})

	cmd := productionGateCommand(t, "TRUSTIX_CROSS_HOST_FULL_KMOD_CASES=owdeb-fullkmod="+filepath.ToSlash(dir))
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("production gate unexpectedly accepted OpenWrt-Debian full-kmod artifacts with single-coalesce enabled:\n%s", output)
	}
	if !strings.Contains(string(output), "rx_worker_single_coalesce") {
		t.Fatalf("production gate did not report enabled OpenWrt single-coalesce:\n%s", output)
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

func TestCrossHostProductionGateAcceptsExpTCPFullKmodArtifacts(t *testing.T) {
	requireProductionGateTools(t)
	dir := t.TempDir()
	writeExpTCPFullKmodProductionGateArtifacts(t, dir, true, true)

	cmd := productionGateCommand(t, "TRUSTIX_CROSS_HOST_EXP_TCP_FULL_KMOD_CASES=exp-tcp-full-kmod="+filepath.ToSlash(dir))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("production gate rejected experimental TCP full-kmod artifacts:\n%s", output)
	}
}

func TestCrossHostProductionGateRejectsExpTCPFullKmodWithoutProvider(t *testing.T) {
	requireProductionGateTools(t)
	dir := t.TempDir()
	writeExpTCPFullKmodProductionGateArtifacts(t, dir, false, true)

	cmd := productionGateCommand(t, "TRUSTIX_CROSS_HOST_EXP_TCP_FULL_KMOD_CASES=exp-tcp-full-kmod="+filepath.ToSlash(dir))
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("production gate unexpectedly accepted experimental TCP full-kmod artifacts without provider:\n%s", output)
	}
	if !strings.Contains(string(output), "kernel_datapath_full_plaintext") {
		t.Fatalf("production gate did not report missing full plaintext provider:\n%s", output)
	}
}

func TestCrossHostProductionGateRejectsExpTCPFullKmodWithoutPlaintextTraffic(t *testing.T) {
	requireProductionGateTools(t)
	dir := t.TempDir()
	writeExpTCPFullKmodProductionGateArtifacts(t, dir, true, false)

	cmd := productionGateCommand(t, "TRUSTIX_CROSS_HOST_EXP_TCP_FULL_KMOD_CASES=exp-tcp-full-kmod="+filepath.ToSlash(dir))
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("production gate unexpectedly accepted experimental TCP full-kmod artifacts without plaintext module traffic:\n%s", output)
	}
	if !strings.Contains(string(output), "tx_plaintext_packets") {
		t.Fatalf("production gate did not report missing plaintext module traffic:\n%s", output)
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

func TestCrossHostProductionGateAcceptsSecureExpTCPKernelArtifacts(t *testing.T) {
	requireProductionGateTools(t)
	dir := t.TempDir()
	writeSecureExpTCPKernelProductionGateArtifacts(t, dir, true, true)

	cmd := productionGateCommand(t, "TRUSTIX_CROSS_HOST_SECURE_EXP_TCP_KERNEL_CASES=secure-exp-tcp-kernel="+filepath.ToSlash(dir))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("production gate rejected secure experimental TCP kernel artifacts:\n%s", output)
	}
}

func TestCrossHostProductionGateRejectsSecureExpTCPKernelWithoutRouteGSO(t *testing.T) {
	requireProductionGateTools(t)
	dir := t.TempDir()
	writeSecureExpTCPKernelProductionGateArtifacts(t, dir, false, true)

	cmd := productionGateCommand(t, "TRUSTIX_CROSS_HOST_SECURE_EXP_TCP_KERNEL_CASES=secure-exp-tcp-kernel="+filepath.ToSlash(dir))
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("production gate unexpectedly accepted secure experimental TCP kernel artifacts without route-GSO:\n%s", output)
	}
	if !strings.Contains(string(output), "tc_experimental_tcp_tx_direct_route_tcp_gso_async_kfunc") {
		t.Fatalf("production gate did not report missing secure experimental TCP route-GSO stat:\n%s", output)
	}
}

func TestCrossHostProductionGateRejectsSecureExpTCPKernelWithoutDirectKfuncCrypto(t *testing.T) {
	requireProductionGateTools(t)
	dir := t.TempDir()
	writeSecureExpTCPKernelProductionGateArtifacts(t, dir, true, false)

	cmd := productionGateCommand(t, "TRUSTIX_CROSS_HOST_SECURE_EXP_TCP_KERNEL_CASES=secure-exp-tcp-kernel="+filepath.ToSlash(dir))
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("production gate unexpectedly accepted secure experimental TCP kernel artifacts without direct kfunc crypto:\n%s", output)
	}
	if !strings.Contains(string(output), "kernel_crypto_module_direct_kfunc_seal_calls") {
		t.Fatalf("production gate did not report missing secure experimental TCP direct kfunc counter:\n%s", output)
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
	writeIperfJSONWithIntervals(t, path, sentBPS, receivedBPS, seconds, 3, 0.8)
}

func writeIperfJSONWithIntervals(t *testing.T, path string, sentBPS, receivedBPS, seconds float64, intervalCount int, minFactor float64) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("make iperf artifact dir: %v", err)
	}
	if intervalCount < 1 {
		intervalCount = 1
	}
	if minFactor <= 0 {
		minFactor = 0.8
	}
	intervals := make([]map[string]any, 0, intervalCount)
	for i := 0; i < intervalCount; i++ {
		factor := 1.0
		retransmits := 0
		switch i {
		case 0:
			factor = minFactor
			retransmits = 1
		case 1:
			factor = 1.0
			retransmits = 2
		case 2:
			factor = 1.1
			retransmits = 3
		}
		intervals = append(intervals, map[string]any{
			"sum": map[string]any{
				"bits_per_second": sentBPS * factor,
				"retransmits":     retransmits,
			},
		})
	}
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
		"intervals": intervals,
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

func writeRunTiming(t *testing.T, dir string, startEpoch, endEpoch, requestedSeconds int) {
	t.Helper()
	writeRunTimingWithStats(t, dir, startEpoch, endEpoch, requestedSeconds, nil)
}

func writeRunTimingWithStats(t *testing.T, dir string, startEpoch, endEpoch, requestedSeconds int, extra map[string]any) {
	t.Helper()
	payload := map[string]any{
		"case":                    "case",
		"iperf_seconds_requested": requestedSeconds,
		"start_epoch":             startEpoch,
		"end_epoch":               endEpoch,
		"elapsed_seconds":         endEpoch - startEpoch,
		"start_time":              "2026-06-21T00:00:00Z",
		"end_time":                "2026-06-21T00:15:00Z",
	}
	for key, value := range extra {
		payload[key] = value
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal run timing: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run-timing.json"), data, 0o644); err != nil {
		t.Fatalf("write run timing: %v", err)
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

func writePstoreArtifacts(t *testing.T, dir string) {
	t.Helper()
	writeTextFile(t, filepath.Join(dir, "collect", "a", "ix-a-pstore.txt"), "status=mounted\nstatus=empty\n")
	writeTextFile(t, filepath.Join(dir, "collect", "b", "ix-b-pstore.txt"), "status=unavailable\n")
}

func writeLANStateArtifacts(t *testing.T, dir string, txQueueLenA, txQueueLenB int) {
	t.Helper()
	for node, txQueueLen := range map[string]int{"a": txQueueLenA, "b": txQueueLenB} {
		value := "interface=tix-lan\n" +
			"tx_queue_len=" + strconv.Itoa(txQueueLen) + "\n" +
			"===== ip-link =====\n" +
			"11: tix-lan: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen " + strconv.Itoa(txQueueLen) + "\n"
		writeTextFile(t, filepath.Join(dir, "collect", node, "ix-"+node+"-lan-state.txt"), value)
	}
}

func writeHostStateArtifacts(t *testing.T, dir string, cpuCountA, cpuCountB int, driverA, driverB string) {
	t.Helper()
	for node, item := range map[string]struct {
		cpuCount int
		driver   string
	}{
		"a": {cpuCount: cpuCountA, driver: driverA},
		"b": {cpuCount: cpuCountB, driver: driverB},
	} {
		value := "cpu_count=" + strconv.Itoa(item.cpuCount) + "\n" +
			"machine=x86_64\n" +
			"kernel_release=6.12.94+deb13-cloud-amd64\n" +
			"underlay_interface=eth0\n" +
			"underlay_driver=" + item.driver + "\n" +
			"===== net-drivers =====\n" +
			"net_driver[eth0]=" + item.driver + "\n" +
			"net_driver[lo]=none\n"
		writeTextFile(t, filepath.Join(dir, "collect", node, "ix-"+node+"-host-state.txt"), value)
	}
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
		"build": map[string]any{
			"version":    "trustix-test",
			"commit":     "0123456789ab",
			"built_at":   "2026-06-25T00:00:00Z",
			"go_version": "go1.25.0",
			"goos":       "linux",
			"goarch":     "amd64",
			"assets": map[string]any{
				"kernel": map[string]any{
					"trustix_crypto.ko": map[string]any{
						"sha256": "status-health-asset-sha",
					},
				},
			},
		},
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

func writeStableUnames(t *testing.T, dir string) {
	t.Helper()
	for _, node := range []string{"a", "b"} {
		value := "Linux ix-" + node + " 6.12.90+deb13.1-amd64 #1 SMP PREEMPT_DYNAMIC x86_64 GNU/Linux\n"
		writeTextFile(t, filepath.Join(dir, node, "uname-before.txt"), value)
		writeTextFile(t, filepath.Join(dir, node, "uname-after.txt"), value)
	}
}

func writeStableOSReleases(t *testing.T, dir string) {
	t.Helper()
	for _, node := range []string{"a", "b"} {
		value := "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nNAME=\"Debian GNU/Linux\"\nID=debian\nVERSION_ID=\"13\"\n"
		writeTextFile(t, filepath.Join(dir, node, "os-release-before.txt"), value)
		writeTextFile(t, filepath.Join(dir, node, "os-release-after.txt"), value)
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
		"capture_forwarder_suppressed": true,
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

func writeDatapathJSONWithReplayStats(t *testing.T, path string, replaySeen, replayOld, openAttempts, drops int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("make datapath dir: %v", err)
	}
	payload := map[string]any{
		"kernel_udp": map[string]any{
			"provider_stats": map[string]any{
				"tc_kernel_udp_rx_secure_direct_replay_seen_drops":   replaySeen,
				"tc_kernel_udp_rx_secure_direct_replay_old_drops":    replayOld,
				"tc_kernel_udp_rx_secure_direct_replay_drops":        replaySeen + replayOld,
				"tc_kernel_udp_rx_secure_direct_drops":               drops,
				"tc_kernel_udp_rx_secure_direct_kfunc_open_attempts": openAttempts,
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
	writeTransportsJSONWithSession(t, path, poolSize, strategy, warmup, sessions, "experimental_tcp", "b-experimental-tcp")
}

func writeTransportsJSONWithSession(t *testing.T, path string, poolSize int, strategy string, warmup bool, sessions int, sessionTransport string, endpoint string) {
	t.Helper()
	writeTransportsJSONWithSessionStats(t, path, poolSize, strategy, warmup, sessions, sessionTransport, endpoint, map[string]any{
		"encryption":       "plaintext",
		"bytes_sent":       4096,
		"bytes_received":   4096,
		"packets_sent":     4,
		"packets_received": 4,
	})
}

func writeTransportsJSONWithSessionStats(t *testing.T, path string, poolSize int, strategy string, warmup bool, sessions int, sessionTransport string, endpoint string, stats map[string]any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("make transports dir: %v", err)
	}
	encryption, _ := stats["encryption"].(string)
	if encryption == "" {
		encryption = "plaintext"
	}
	sessionRows := make([]any, 0, sessions)
	for i := 0; i < sessions; i++ {
		sessionRows = append(sessionRows, map[string]any{
			"peer":       "ix-b",
			"endpoint":   endpoint,
			"transport":  sessionTransport,
			"pool_index": i,
			"stats":      stats,
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
		"local_endpoints": []any{
			map[string]any{
				"name":                localEndpointForTransportPath(path, sessionTransport),
				"transport":           sessionTransport,
				"enabled":             true,
				"usable":              true,
				"profile":             "performance",
				"datapath":            "kernel_module",
				"encryption":          encryption,
				"kernel_compatible":   true,
				"security_compatible": true,
				"profile_compatible":  true,
				"crypto_placements":   []string{"userspace"},
			},
		},
		"peer_endpoints": []any{
			map[string]any{
				"name":                endpoint,
				"transport":           sessionTransport,
				"usable":              true,
				"profile":             "performance",
				"datapath":            "kernel_module",
				"encryption":          encryption,
				"kernel_compatible":   true,
				"security_compatible": true,
				"profile_compatible":  true,
				"crypto_placements":   []string{"userspace"},
			},
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

func peerEndpointForNode(node string, endpointSuffix string) string {
	if node == "a" {
		return "b" + endpointSuffix
	}
	return "a" + endpointSuffix
}

func localEndpointForTransportPath(path string, transport string) string {
	clean := filepath.Clean(path)
	node := "a"
	for _, part := range strings.Split(clean, string(os.PathSeparator)) {
		if part == "b" {
			node = "b"
			break
		}
	}
	return node + "-" + strings.ReplaceAll(transport, "_", "-")
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

func writeLsmodArtifacts(t *testing.T, dir string, modulesByNode map[string][]string) {
	t.Helper()
	for _, node := range []string{"a", "b"} {
		var builder strings.Builder
		for _, module := range modulesByNode[node] {
			builder.WriteString(module + " 16384 0\n")
		}
		writeTextFile(t, filepath.Join(dir, "collect", node, "ix-"+node+"-lsmod.txt"), builder.String())
	}
}

func writeFullKmodProductionGateArtifacts(t *testing.T, dir string, plaintextXmit bool) {
	t.Helper()
	writeIperfJSONWithIntervals(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 3.3e9, 3.2e9, 3600.2, 3600, 0.8)
	writeIperfJSONWithIntervals(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 3.3e9, 3.2e9, 3600.2, 3600, 0.8)
	writeResultMarker(t, dir)
	writeRunTimingWithStats(t, dir, 1000, 4601, 3600, map[string]any{
		"iperf_mode":       "forward",
		"iperf_directions": "both",
	})
	writeStableBootIDs(t, dir)
	writeStableUnames(t, dir)
	writeStableOSReleases(t, dir)
	writeKernelLogArtifacts(t, dir)
	writePstoreArtifacts(t, dir)
	writeLANStateArtifacts(t, dir, 1000, 1000)
	writeHostStateArtifacts(t, dir, 4, 4, "virtio_net", "virtio_net")
	writeLsmodArtifacts(t, dir, map[string][]string{
		"a": {"trustix_datapath"},
		"b": {"trustix_datapath"},
	})
	for _, node := range []string{"a", "b"} {
		base := filepath.Join(dir, "collect", node)
		writeStatusHealthJSON(t, filepath.Join(base, "status.json"), 8, 0, 0)
		writeBinaryIdentityJSON(t, filepath.Join(base, "binary-identity.json"), "full-kmod-sha")
		writeDatapathJSONWithRX(t, filepath.Join(base, "datapath.json"), 1, 42)
		writeTransportsJSONWithSession(t, filepath.Join(base, "transports.json"), 8, "flow", true, 8, "udp", peerEndpointForNode(node, "-udp"))
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
		"tx_plaintext_hash_tx_queue":                  "Y",
		"tx_plaintext_stream_coalesce":                "N",
		"tx_plaintext_packets":                        plaintextSegments,
		"tx_plaintext_gso_segments":                   plaintextSegments,
		"tx_plaintext_outer_gso_segments":             plaintextSegments,
		"tx_plaintext_hash_tx_queue_sets":             plaintextSegments,
		"tx_plaintext_hash_tx_queue_fallbacks":        "0",
		"rx_worker_injected":                          "8",
		"rx_worker_dst_mac_cache_hits":                "8",
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
		"tx_plaintext_gso_errors":                     "0",
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

func writeExpTCPFullKmodProductionGateArtifacts(t *testing.T, dir string, provider bool, plaintextTraffic bool) {
	t.Helper()
	writeIperfJSONWithIntervals(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 7.2e9, 7.1e9, 3600.2, 3600, 0.8)
	writeIperfJSONWithIntervals(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 7.2e9, 7.1e9, 3600.2, 3600, 0.8)
	writeResultMarker(t, dir)
	writeRunTimingWithStats(t, dir, 1000, 4601, 3600, map[string]any{
		"iperf_mode":       "forward",
		"iperf_directions": "both",
	})
	writeStableBootIDs(t, dir)
	writeStableUnames(t, dir)
	writeStableOSReleases(t, dir)
	writeKernelLogArtifacts(t, dir)
	writePstoreArtifacts(t, dir)
	writeLANStateArtifacts(t, dir, 1000, 1000)
	writeHostStateArtifacts(t, dir, 4, 4, "virtio_net", "virtio_net")
	writeLsmodArtifacts(t, dir, map[string][]string{
		"a": {"trustix_datapath"},
		"b": {"trustix_datapath"},
	})
	for _, node := range []string{"a", "b"} {
		base := filepath.Join(dir, "collect", node)
		writeExpTCPFullKmodStatusJSON(t, filepath.Join(base, "status.json"))
		writeBinaryIdentityJSON(t, filepath.Join(base, "binary-identity.json"), "exp-tcp-full-kmod-sha")
		writeExpTCPFullKmodDatapathJSON(t, filepath.Join(base, "datapath.json"), provider)
		writeExpTCPFullKmodTransportsJSON(t, filepath.Join(base, "transports.json"), node)
		writeFullKmodModuleParametersWithOverrides(t, filepath.Join(base, "module-parameters.txt"), true, expTCPFullKmodModuleOverrides(plaintextTraffic))
	}
}

func expTCPFullKmodModuleOverrides(plaintextTraffic bool) map[string]string {
	traffic := "0"
	if plaintextTraffic {
		traffic = "128"
	}
	return map[string]string{
		"session_records":           "16",
		"session_wire_records":      "16",
		"tx_plaintext_packets":      traffic,
		"tx_plaintext_gso_segments": traffic,
		"rx_worker_injected":        traffic,
	}
}

func writeExpTCPFullKmodStatusJSON(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("make experimental TCP full-kmod status dir: %v", err)
	}
	payload := map[string]any{
		"build": map[string]any{
			"version":    "trustix-test",
			"commit":     "0123456789ab",
			"built_at":   "2026-06-25T00:00:00Z",
			"go_version": "go1.25.0",
			"goos":       "linux",
			"goarch":     "amd64",
		},
		"data_path": map[string]any{
			"active_sessions": 16,
			"counters": map[string]any{
				"session_dial_errors":        0,
				"session_heartbeat_timeouts": 0,
				"session_resets_sent":        0,
				"session_resets_received":    0,
				"stale_sessions_dropped":     0,
			},
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal experimental TCP full-kmod status json: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write experimental TCP full-kmod status json: %v", err)
	}
}

func writeExpTCPFullKmodDatapathJSON(t *testing.T, path string, fullPlaintextProvider bool) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("make experimental TCP full-kmod datapath dir: %v", err)
	}
	provider := "af_xdp"
	if fullPlaintextProvider {
		provider = "kernel_datapath_full_plaintext"
	}
	payload := map[string]any{
		"capture_forwarder_suppressed": true,
		"counters": map[string]any{
			"session_dials":       16,
			"session_dial_errors": 0,
		},
		"kernel_rx_stage": map[string]any{
			"rx_worker_injected": 128,
		},
		"experimental_tcp": map[string]any{
			"provider":                     provider,
			"fast_path":                    true,
			"capture_forwarder_suppressed": true,
			"active_flows":                 16,
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal experimental TCP full-kmod datapath json: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write experimental TCP full-kmod datapath json: %v", err)
	}
}

func writeExpTCPFullKmodTransportsJSON(t *testing.T, path string, node string) {
	t.Helper()
	writeTransportsJSONWithSessionStats(t, path, 16, "flow", true, 16, "experimental_tcp", peerEndpointForNode(node, "-experimental-tcp"), map[string]any{
		"encryption":       "plaintext",
		"bytes_sent":       0,
		"bytes_received":   0,
		"packets_sent":     8,
		"packets_received": 0,
		"extra": map[string]any{
			"experimental_tcp_full_plaintext_kernel_datapath": 1,
		},
	})
}

func writeSecureKUDPProductionGateArtifacts(t *testing.T, dir string, routeGSO bool, routeHelperXmit bool) {
	t.Helper()
	writeIperfJSONWithIntervals(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 1.9e9, 1.8e9, 3600.2, 3600, 0.8)
	writeIperfJSONWithIntervals(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 1.9e9, 1.8e9, 3600.2, 3600, 0.8)
	writeResultMarker(t, dir)
	writeRunTimingWithStats(t, dir, 1000, 4601, 3600, map[string]any{
		"iperf_mode":       "forward",
		"iperf_directions": "both",
	})
	writeStableBootIDs(t, dir)
	writeStableUnames(t, dir)
	writeStableOSReleases(t, dir)
	writeKernelLogArtifacts(t, dir)
	writePstoreArtifacts(t, dir)
	writeLANStateArtifacts(t, dir, 1000, 1000)
	writeHostStateArtifacts(t, dir, 4, 4, "virtio_net", "virtio_net")
	writeLsmodArtifacts(t, dir, map[string][]string{
		"a": {"trustix_crypto", "trustix_datapath_helpers"},
		"b": {"trustix_crypto", "trustix_datapath_helpers"},
	})
	for _, node := range []string{"a", "b"} {
		base := filepath.Join(dir, "collect", node)
		writeStatusHealthJSON(t, filepath.Join(base, "status.json"), 8, 0, 0)
		writeBinaryIdentityJSON(t, filepath.Join(base, "binary-identity.json"), "secure-kudp-sha")
		writeSecureKUDPDatapathJSON(t, filepath.Join(base, "datapath.json"), routeGSO)
		writeSecureKUDPTransportsJSON(t, filepath.Join(base, "transports.json"), node)
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
				"tc_kernel_udp_rx_secure_direct_kfunc_open_attempts":   1024,
				"tc_kernel_udp_rx_secure_direct_replay_old_drops":      0,
				"tc_kernel_udp_rx_secure_direct_replay_seen_drops":     0,
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

func writeSecureKUDPTransportsJSON(t *testing.T, path string, node string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("make secure-kudp transports dir: %v", err)
	}
	sessionRows := make([]any, 0, 8)
	for i := 0; i < 8; i++ {
		sessionRows = append(sessionRows, map[string]any{
			"peer":       "ix-b",
			"endpoint":   peerEndpointForNode(node, "-udp"),
			"transport":  "udp",
			"pool_index": i,
			"stats": map[string]any{
				"encryption":        "secure",
				"encrypted":         true,
				"send_encrypted":    true,
				"receive_encrypted": true,
				"crypto_placement":  "kernel",
				"bytes_sent":        4096,
				"bytes_received":    4096,
				"packets_sent":      4,
				"packets_received":  4,
			},
		})
	}
	payload := map[string]any{
		"policy": map[string]any{
			"encryption":            "secure",
			"profile":               "performance",
			"crypto_placement":      "kernel",
			"datapath":              "tc_xdp",
			"session_pool_size":     8,
			"session_pool_strategy": "flow",
			"session_pool_warmup":   true,
		},
		"local_endpoints": []any{
			map[string]any{
				"name":                localEndpointForTransportPath(path, "udp"),
				"transport":           "udp",
				"enabled":             true,
				"usable":              true,
				"profile":             "performance",
				"datapath":            "tc_xdp",
				"encryption":          "secure",
				"kernel_compatible":   true,
				"security_compatible": true,
				"profile_compatible":  true,
				"crypto_placements":   []string{"kernel"},
			},
		},
		"peer_endpoints": []any{
			map[string]any{
				"name":                peerEndpointForNode(node, "-udp"),
				"transport":           "udp",
				"usable":              true,
				"profile":             "performance",
				"datapath":            "tc_xdp",
				"encryption":          "secure",
				"kernel_compatible":   true,
				"security_compatible": true,
				"profile_compatible":  true,
				"crypto_placements":   []string{"kernel"},
			},
		},
		"sessions": sessionRows,
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
	helperParams := routeGSOHelperParameters()
	helperParams["route_tcp_gso_async_secure_seal_batch"] = "1"
	helperParams["route_tcp_gso_async_stream_outer_gso_frames"] = "0"
	helperParams["route_tcp_gso_async_xmit_packets"] = xmitPackets
	writeModuleParameters(t, path, map[string]map[string]string{
		"trustix_crypto": {
			"kfunc_simd_fastpath":         "1",
			"kfunc_simd_irq_fpu_fastpath": "1",
			"direct_kfunc_seal_calls":     "16",
			"direct_kfunc_open_calls":     "16",
			"direct_kfunc_errors":         "0",
		},
		"trustix_datapath_helpers": helperParams,
	})
}

func writeSecureExpTCPKernelProductionGateArtifacts(t *testing.T, dir string, routeGSO bool, directKfuncCrypto bool) {
	t.Helper()
	writeIperfJSONWithIntervals(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 1.9e9, 1.8e9, 3600.2, 3600, 0.8)
	writeIperfJSONWithIntervals(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 1.9e9, 1.8e9, 3600.2, 3600, 0.8)
	writeResultMarker(t, dir)
	writeRunTimingWithStats(t, dir, 1000, 4601, 3600, map[string]any{
		"iperf_mode":       "forward",
		"iperf_directions": "both",
	})
	writeStableBootIDs(t, dir)
	writeStableUnames(t, dir)
	writeStableOSReleases(t, dir)
	writeKernelLogArtifacts(t, dir)
	writePstoreArtifacts(t, dir)
	writeLANStateArtifacts(t, dir, 1000, 1000)
	writeHostStateArtifacts(t, dir, 4, 4, "virtio_net", "virtio_net")
	writeLsmodArtifacts(t, dir, map[string][]string{
		"a": {"trustix_crypto", "trustix_datapath_helpers"},
		"b": {"trustix_crypto", "trustix_datapath_helpers"},
	})
	for _, node := range []string{"a", "b"} {
		base := filepath.Join(dir, "collect", node)
		writeStatusHealthJSON(t, filepath.Join(base, "status.json"), 8, 0, 0)
		writeBinaryIdentityJSON(t, filepath.Join(base, "binary-identity.json"), "secure-exp-tcp-kernel-sha")
		writeSecureExpTCPKernelDatapathJSON(t, filepath.Join(base, "datapath.json"), routeGSO, directKfuncCrypto)
		writeSecureExpTCPKernelTransportsJSON(t, filepath.Join(base, "transports.json"), node)
		writeSecureExpTCPKernelModuleParameters(t, filepath.Join(base, "module-parameters.txt"), routeGSO, directKfuncCrypto)
	}
}

func writeSecureExpTCPKernelDatapathJSON(t *testing.T, path string, routeGSO bool, directKfuncCrypto bool) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("make secure experimental TCP datapath dir: %v", err)
	}
	routeGSOValue := 0
	if routeGSO {
		routeGSOValue = 1
	}
	directSealCalls := 0
	directOpenCalls := 0
	if directKfuncCrypto {
		directSealCalls = 16
		directOpenCalls = 16
	}
	payload := map[string]any{
		"experimental_tcp": map[string]any{
			"fast_path":        true,
			"reinject":         true,
			"kernel_crypto":    true,
			"requested_crypto": "kernel",
			"effective_crypto": "kernel",
			"active_flows":     1,
			"provider_stats": map[string]any{
				"kernel_crypto_flow_map_ready":                                      1,
				"kernel_crypto_flow_map_entries":                                    1,
				"kernel_crypto_flow_map_updates":                                    1,
				"kernel_crypto_direct_slot_provider_ready":                          1,
				"kernel_crypto_direct_kfunc_fastpath_ready":                         1,
				"kernel_crypto_tc_direct_ready":                                     1,
				"kernel_crypto_rx_attached":                                         0,
				"kernel_crypto_tx_packet":                                           0,
				"kernel_crypto_module_direct_kfunc_seal_calls":                      directSealCalls,
				"kernel_crypto_module_direct_kfunc_open_calls":                      directOpenCalls,
				"kernel_crypto_module_direct_kfunc_errors":                          0,
				"tc_experimental_tcp_tx_direct_route_tcp_gso_async_kfunc":           routeGSOValue,
				"tc_experimental_tcp_tx_direct_route_tcp_gso_async_kfunc_requested": 1,
				"tc_kernel_udp_tx_secure_direct_attached":                           1,
				"tc_kernel_udp_tx_secure_direct_trust_inner_checksums":              1,
				"tc_kernel_udp_tx_secure_direct_kfunc_seal_enabled":                 1,
				"tc_kernel_udp_tx_secure_direct_route_tcp_gso_kfunc":                routeGSOValue,
				"kernel_crypto_frame_seal_successes":                                0,
				"kernel_crypto_frame_open_successes":                                0,
				"xdp_kernel_crypto_open_attempts":                                   0,
				"xdp_kernel_crypto_open_successes":                                  0,
				"tx_kernel_crypto_packet_seal_successes":                            0,
				"kernel_crypto_provider_unavailable_errors":                         0,
				"kernel_crypto_flow_rejects":                                        0,
				"kernel_crypto_frame_rejects":                                       0,
				"kernel_crypto_frame_seal_errors":                                   0,
				"kernel_crypto_frame_open_errors":                                   0,
				"kernel_crypto_frame_replay_drops":                                  0,
				"xdp_kernel_crypto_open_errors":                                     0,
				"xdp_kernel_crypto_replay_drops":                                    0,
				"xdp_kernel_crypto_no_context_drops":                                0,
				"xdp_kernel_crypto_header_errors":                                   0,
				"xdp_kernel_crypto_payload_len_errors":                              0,
				"xdp_kernel_crypto_secure_header_errors":                            0,
				"xdp_kernel_crypto_frame_header_errors":                             0,
				"xdp_kernel_crypto_epoch_sequence_mismatches":                       0,
				"xdp_kernel_crypto_cipher_len_errors":                               0,
				"xdp_kernel_crypto_cipher_load_errors":                              0,
				"xdp_kernel_crypto_context_misses":                                  0,
				"xdp_kernel_crypto_state_misses":                                    0,
				"xdp_kernel_crypto_zero_plain_errors":                               0,
				"xdp_kernel_crypto_context_unavailable":                             0,
				"xdp_kernel_crypto_epoch_mismatches":                                0,
				"xdp_kernel_crypto_suite_mismatches":                                0,
				"xdp_kernel_crypto_dynptr_errors":                                   0,
				"xdp_kernel_crypto_decrypt_errors":                                  0,
				"xdp_kernel_crypto_replay_commit_errors":                            0,
				"xdp_kernel_crypto_store_errors":                                    0,
			},
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal secure experimental TCP datapath json: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write secure experimental TCP datapath json: %v", err)
	}
}

func writeSecureExpTCPKernelModuleParameters(t *testing.T, path string, routeHelperXmit bool, directKfuncCrypto bool) {
	t.Helper()
	xmitPackets := "0"
	if routeHelperXmit {
		xmitPackets = "8"
	}
	directSealCalls := "0"
	directOpenCalls := "0"
	if directKfuncCrypto {
		directSealCalls = "16"
		directOpenCalls = "16"
	}
	helperParams := routeGSOHelperParameters()
	helperParams["route_tcp_gso_async_secure_seal_batch"] = "1"
	helperParams["route_tcp_gso_async_stream_outer_gso_frames"] = "0"
	helperParams["route_tcp_gso_async_xmit_packets"] = xmitPackets
	writeModuleParameters(t, path, map[string]map[string]string{
		"trustix_crypto": {
			"kfunc_simd_fastpath":         "1",
			"kfunc_simd_irq_fpu_fastpath": "1",
			"direct_kfunc_seal_calls":     directSealCalls,
			"direct_kfunc_open_calls":     directOpenCalls,
			"direct_kfunc_errors":         "0",
		},
		"trustix_datapath_helpers": helperParams,
	})
}

func writeSecureExpTCPKernelTransportsJSON(t *testing.T, path string, node string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("make secure experimental TCP transports dir: %v", err)
	}
	sessionRows := make([]any, 0, 8)
	for i := 0; i < 8; i++ {
		sessionRows = append(sessionRows, map[string]any{
			"peer":       "ix-b",
			"endpoint":   peerEndpointForNode(node, "-experimental-tcp"),
			"transport":  "experimental_tcp",
			"pool_index": i,
			"stats": map[string]any{
				"encryption":        "secure",
				"encrypted":         true,
				"send_encrypted":    true,
				"receive_encrypted": true,
				"crypto_placement":  "kernel",
				"bytes_sent":        112,
				"bytes_received":    0,
				"packets_sent":      7,
				"packets_received":  0,
			},
		})
	}
	payload := map[string]any{
		"policy": map[string]any{
			"encryption":            "secure",
			"profile":               "performance",
			"crypto_placement":      "kernel",
			"datapath":              "kernel_module",
			"session_pool_size":     8,
			"session_pool_strategy": "flow",
			"session_pool_warmup":   true,
		},
		"local_endpoints": []any{
			map[string]any{
				"name":                localEndpointForTransportPath(path, "experimental_tcp"),
				"transport":           "experimental_tcp",
				"enabled":             true,
				"usable":              true,
				"profile":             "performance",
				"datapath":            "kernel_module",
				"encryption":          "secure",
				"kernel_compatible":   true,
				"security_compatible": true,
				"profile_compatible":  true,
				"crypto_placements":   []string{"kernel"},
			},
		},
		"peer_endpoints": []any{
			map[string]any{
				"name":                peerEndpointForNode(node, "-experimental-tcp"),
				"transport":           "experimental_tcp",
				"usable":              true,
				"profile":             "performance",
				"datapath":            "kernel_module",
				"encryption":          "secure",
				"kernel_compatible":   true,
				"security_compatible": true,
				"profile_compatible":  true,
				"crypto_placements":   []string{"kernel"},
			},
		},
		"sessions": sessionRows,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal secure experimental TCP transports json: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write secure experimental TCP transports json: %v", err)
	}
}

func writeRouteGSOProductionGateArtifacts(t *testing.T, dir string, routeGSO bool) {
	t.Helper()
	writeIperfJSONWithIntervals(t, filepath.Join(dir, "case-iperf-a-to-b.json"), 2.8e9, 2.7e9, 3600.2, 3600, 0.8)
	writeIperfJSONWithIntervals(t, filepath.Join(dir, "case-iperf-b-to-a.json"), 2.8e9, 2.7e9, 3600.2, 3600, 0.8)
	writeResultMarker(t, dir)
	writeRunTimingWithStats(t, dir, 1000, 4601, 3600, map[string]any{
		"iperf_mode":       "forward",
		"iperf_directions": "both",
	})
	writeStableBootIDs(t, dir)
	writeStableUnames(t, dir)
	writeStableOSReleases(t, dir)
	writeKernelLogArtifacts(t, dir)
	writePstoreArtifacts(t, dir)
	writeLANStateArtifacts(t, dir, 1000, 1000)
	writeHostStateArtifacts(t, dir, 4, 4, "virtio_net", "virtio_net")
	writeLsmodArtifacts(t, dir, map[string][]string{
		"a": {"trustix_datapath_helpers"},
		"b": {"trustix_datapath_helpers"},
	})
	for _, node := range []string{"a", "b"} {
		base := filepath.Join(dir, "collect", node)
		writeStatusHealthJSON(t, filepath.Join(base, "status.json"), 8, 0, 0)
		writeBinaryIdentityJSON(t, filepath.Join(base, "binary-identity.json"), "route-gso-sha")
		writeRouteGSODatapathJSON(t, filepath.Join(base, "datapath.json"), routeGSO)
		writeTransportsJSONWithSession(t, filepath.Join(base, "transports.json"), 8, "flow", true, 8, "experimental_tcp", peerEndpointForNode(node, "-experimental-tcp"))
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
		"enable_features":                   "768",
		"features":                          "768",
		"safe_features":                     "768",
		"selftests":                         "3",
		"unsafe_features":                   "0",
		"selftest_failures":                 "0",
		"route_tcp_gso_async_hash_tx_queue": "0",
		"route_tcp_gso_async_txq_stopped_backoff_retries":          "1",
		"route_tcp_gso_async_txq_stopped_backoff_sleep_usecs":      "50",
		"route_tcp_gso_async_stream_direct_builds":                 "8",
		"route_tcp_gso_async_stream_direct_frames":                 "8",
		"route_tcp_gso_async_stream_outer_gso_frames":              "0",
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
		"route_tcp_gso_async_stream_outer_gso_virtio_blocked":      "0",
		"route_tcp_gso_async_stream_outer_gso_verify_errors":       "0",
		"route_tcp_gso_async_stream_cross_item_errors":             "0",
		"route_tcp_gso_async_stream_cross_item_tail_stitch_errors": "0",
	}
}
