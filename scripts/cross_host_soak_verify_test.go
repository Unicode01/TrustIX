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
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal iperf receiver json: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write iperf receiver json: %v", err)
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
