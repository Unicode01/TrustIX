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

func writeIperfJSON(t *testing.T, path string, sentBPS, receivedBPS, seconds float64) {
	t.Helper()
	payload := map[string]any{
		"end": map[string]any{
			"sum_sent": map[string]any{
				"bits_per_second": sentBPS,
				"seconds":         seconds,
			},
			"sum_received": map[string]any{
				"bits_per_second": receivedBPS,
				"seconds":         seconds,
			},
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
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("make datapath dir: %v", err)
	}
	payload := map[string]any{
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
