package scripts

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
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
