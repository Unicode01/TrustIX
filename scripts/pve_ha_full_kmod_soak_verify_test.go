package scripts

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPVEHAFullKmodSoakVerifierAcceptsCompleteEvidence(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writePVEHAFullKmodEvidence(t, dir, false)
	cmd := exec.Command(python,
		"pve-ha-full-kmod-soak-verify.py",
		"--evidence", dir,
		"--min-duration", "20",
		"--min-transitions", "2",
		"--max-ready-seconds", "3",
		"--max-ping-outage-seconds", "3",
		"--transition-failure-grace-seconds", "1",
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify passing HA evidence: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), `"ok": true`) {
		t.Fatalf("passing HA evidence was not accepted:\n%s", output)
	}
}

func TestPVEHAFullKmodSoakVerifierRejectsStaleMACBlackhole(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writePVEHAFullKmodEvidence(t, dir, true)
	cmd := exec.Command(python,
		"pve-ha-full-kmod-soak-verify.py",
		"--evidence", dir,
		"--min-duration", "20",
		"--min-transitions", "2",
		"--max-ready-seconds", "3",
		"--max-ping-outage-seconds", "3",
		"--transition-failure-grace-seconds", "1",
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verifier accepted stale-MAC blackhole evidence:\n%s", output)
	}
	if !strings.Contains(string(output), "ping outage") {
		t.Fatalf("stale-MAC rejection did not report ping outage:\n%s", output)
	}
}

func TestPVEHAFullKmodSoakVerifierRejectsTruncatedModuleCoverage(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writePVEHAFullKmodEvidence(t, dir, false)
	truncated := strings.Join([]string{
		"1000.0\t1\t1\t0\t0\t0\t0\t1\t10.203.3.210_old",
		"1006.0\t2\t1\t1\t1\t0\t0\t2\t10.203.3.210_new",
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "remote-module.tsv"), []byte(truncated), 0o644); err != nil {
		t.Fatalf("write truncated module evidence: %v", err)
	}
	cmd := exec.Command(python,
		"pve-ha-full-kmod-soak-verify.py",
		"--evidence", dir,
		"--min-duration", "20",
		"--min-transitions", "2",
		"--max-ready-seconds", "3",
		"--max-ping-outage-seconds", "3",
		"--transition-failure-grace-seconds", "1",
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verifier accepted truncated module coverage:\n%s", output)
	}
	if !strings.Contains(string(output), "module monitor coverage ends more than 5s before soak end") {
		t.Fatalf("truncated module rejection did not report coverage gap:\n%s", output)
	}
}

func TestPVEHAFullKmodSoakVerifierRejectsTruncatedTrafficCoverage(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writePVEHAFullKmodEvidence(t, dir, false)
	truncated := "1001.0\t1003.0\t0\t2000000000\t1900000000\t\n"
	if err := os.WriteFile(filepath.Join(dir, "tcp-forward.tsv"), []byte(truncated), 0o644); err != nil {
		t.Fatalf("write truncated traffic evidence: %v", err)
	}
	cmd := exec.Command(python,
		"pve-ha-full-kmod-soak-verify.py",
		"--evidence", dir,
		"--min-duration", "20",
		"--min-transitions", "2",
		"--max-ready-seconds", "3",
		"--max-ping-outage-seconds", "3",
		"--transition-failure-grace-seconds", "1",
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verifier accepted truncated traffic coverage:\n%s", output)
	}
	if !strings.Contains(string(output), "tcp-forward.tsv: coverage ends more than 15.000s before soak end") {
		t.Fatalf("truncated traffic rejection did not report coverage gap:\n%s", output)
	}
}

func TestPVEHAFullKmodSoakVerifierRejectsWrongTransitionOrder(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writePVEHAFullKmodEvidence(t, dir, false)
	transitions := strings.Join([]string{
		"index\ttype\told_master\tnew_master\ttrigger_epoch\tready_epoch\trecovery_seconds\trejoin_epoch",
		"1\thost_stop\t200\t201\t1005.0\t1007.0\t2.000000\t1009.0",
		"2\thost_stop\t201\t200\t1012.0\t1014.0\t2.000000\t1016.0",
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "transitions.tsv"), []byte(transitions), 0o644); err != nil {
		t.Fatalf("write invalid transition evidence: %v", err)
	}
	cmd := exec.Command(python,
		"pve-ha-full-kmod-soak-verify.py",
		"--evidence", dir,
		"--min-duration", "20",
		"--min-transitions", "2",
		"--max-ready-seconds", "3",
		"--max-ping-outage-seconds", "3",
		"--transition-failure-grace-seconds", "1",
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verifier accepted wrong transition order:\n%s", output)
	}
	if !strings.Contains(string(output), "transition 2: type='host_stop', want 'vrrp_partition'") {
		t.Fatalf("wrong transition rejection did not report expected type:\n%s", output)
	}
}

func TestPVEHAFullKmodSoakVerifierRejectsBothHAStopped(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writePVEHAFullKmodEvidence(t, dir, false)
	states := strings.Join([]string{
		"1000.0\trunning\trunning",
		"1002.0\tstopped\tstopped",
		"1019.0\trunning\trunning",
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "pve-state.tsv"), []byte(states), 0o644); err != nil {
		t.Fatalf("write invalid PVE state evidence: %v", err)
	}
	cmd := exec.Command(python,
		"pve-ha-full-kmod-soak-verify.py",
		"--evidence", dir,
		"--min-duration", "20",
		"--min-transitions", "2",
		"--max-ready-seconds", "3",
		"--max-ping-outage-seconds", "3",
		"--transition-failure-grace-seconds", "1",
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verifier accepted simultaneous HA outage:\n%s", output)
	}
	if !strings.Contains(string(output), "both HA VMs stopped") {
		t.Fatalf("simultaneous HA outage rejection missing:\n%s", output)
	}
}

func TestPVEHAFullKmodSoakVerifierRejectsUnexpectedWorkerStderr(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writePVEHAFullKmodEvidence(t, dir, false)
	if err := os.WriteFile(filepath.Join(dir, "remote-module.stderr.log"), []byte("ssh: connection reset\n"), 0o644); err != nil {
		t.Fatalf("write worker stderr evidence: %v", err)
	}
	cmd := exec.Command(python,
		"pve-ha-full-kmod-soak-verify.py",
		"--evidence", dir,
		"--min-duration", "20",
		"--min-transitions", "2",
		"--max-ready-seconds", "3",
		"--max-ping-outage-seconds", "3",
		"--transition-failure-grace-seconds", "1",
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verifier accepted unexpected worker stderr:\n%s", output)
	}
	if !strings.Contains(string(output), "unexpected worker stderr") {
		t.Fatalf("worker stderr rejection missing:\n%s", output)
	}
}

func TestPVEHAFullKmodSoakVerifierRejectsWrongModuleIdentity(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writePVEHAFullKmodEvidence(t, dir, false)
	snapshot := pveHAFullKmodModuleSnapshot(strings.Repeat("b", 64))
	if err := os.WriteFile(filepath.Join(dir, "module-master-after.txt"), []byte(snapshot), 0o644); err != nil {
		t.Fatalf("write wrong module snapshot: %v", err)
	}
	cmd := exec.Command(python,
		"pve-ha-full-kmod-soak-verify.py",
		"--evidence", dir,
		"--min-duration", "20",
		"--min-transitions", "2",
		"--max-ready-seconds", "3",
		"--max-ping-outage-seconds", "3",
		"--transition-failure-grace-seconds", "1",
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verifier accepted wrong module identity:\n%s", output)
	}
	if !strings.Contains(string(output), "module-master-after.txt: build_sha256") {
		t.Fatalf("wrong module identity rejection missing:\n%s", output)
	}
}

func TestPVEHAFullKmodSoakVerifierRejectsInactiveModuleCounters(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("python not available")
	}
	dir := t.TempDir()
	writePVEHAFullKmodEvidence(t, dir, false)
	inactive := strings.Join([]string{
		"1000.0\t1\t1\t0\t0\t0\t0\t1\t10.203.3.210_old",
		"1006.0\t1\t1\t0\t1\t0\t0\t1\t10.203.3.210_new",
		"1009.0\t1\t1\t0\t1\t0\t0\t1\t10.203.3.210_new",
		"1013.0\t1\t1\t0\t2\t0\t0\t1\t10.203.3.210_old",
		"1019.0\t1\t1\t0\t2\t0\t0\t1\t10.203.3.210_old",
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "remote-module.tsv"), []byte(inactive), 0o644); err != nil {
		t.Fatalf("write inactive module evidence: %v", err)
	}
	cmd := exec.Command(python,
		"pve-ha-full-kmod-soak-verify.py",
		"--evidence", dir,
		"--min-duration", "20",
		"--min-transitions", "2",
		"--max-ready-seconds", "3",
		"--max-ping-outage-seconds", "3",
		"--transition-failure-grace-seconds", "1",
	)
	cmd.Dir = "."
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verifier accepted inactive full-kmod counters:\n%s", output)
	}
	for _, want := range []string{
		"full-kmod plaintext packet counter did not increase",
		"full-kmod destination-MAC cache hit counter did not increase",
		"full-kmod RX worker injected counter did not increase",
	} {
		if !strings.Contains(string(output), want) {
			t.Fatalf("inactive module rejection missing %q:\n%s", want, output)
		}
	}
}

func writePVEHAFullKmodEvidence(t *testing.T, dir string, staleMACBlackhole bool) {
	t.Helper()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("result", "runner_pass\n")
	write("start.epoch", "1000.0\n")
	write("end.epoch", "1020.0\n")
	write("manifest.tsv", strings.Join([]string{
		"schema\ttrustix-pve-ha-full-kmod-soak-v1",
		"duration\t20",
		"run_id\ttrustix-ha-soak-fixture",
		"module_sha256\t" + strings.Repeat("a", 64),
		"module_srcversion\tABCDEF0123",
		"vm_a\t200",
		"vm_b\t201",
		"initial_master\t200",
		"remote_boot_before\tboot-remote",
		"client_boot_before\tboot-client",
		"remote_boot_after\tboot-remote",
		"client_boot_after\tboot-client",
		"final_master\t200",
		"final_backup\t201",
	}, "\n")+"\n")
	write("transitions.tsv", strings.Join([]string{
		"index\ttype\told_master\tnew_master\ttrigger_epoch\tready_epoch\trecovery_seconds\trejoin_epoch",
		"1\thost_stop\t200\t201\t1005.0\t1007.0\t2.000000\t1009.0",
		"2\tvrrp_partition\t201\t200\t1012.0\t1014.0\t2.000000\t1016.0",
	}, "\n")+"\n")

	var ping strings.Builder
	sequence := 1
	for tick := 0; tick < 100; tick++ {
		epoch := 1000.0 + float64(tick)*0.2
		drop := epoch > 1005.2 && epoch < 1006.2 || epoch > 1012.2 && epoch < 1013.2
		if staleMACBlackhole {
			drop = epoch > 1005.0 && epoch < 1017.0
		}
		if !drop {
			fmt.Fprintf(&ping, "[%.1f] 64 bytes from 10.220.0.2: icmp_seq=%d ttl=64 time=1 ms\n", epoch, sequence)
		}
		sequence++
	}
	write("ping.log", ping.String())

	traffic := strings.Join([]string{
		"1001.0\t1003.0\t0\t2000000000\t1900000000\t",
		"1005.5\t1006.5\t1\t0\t0\tconnection reset",
		"1017.0\t1019.0\t0\t2100000000\t2000000000\t",
	}, "\n") + "\n"
	udpTraffic := strings.ReplaceAll(traffic, "2000000000", "180000000")
	udpTraffic = strings.ReplaceAll(udpTraffic, "1900000000", "175000000")
	udpTraffic = strings.ReplaceAll(udpTraffic, "2100000000", "185000000")
	for _, name := range []string{"tcp-forward.tsv", "tcp-reverse.tsv"} {
		write(name, traffic)
	}
	for _, name := range []string{"udp-forward.tsv", "udp-reverse.tsv"} {
		write(name, udpTraffic)
	}
	write("pve-state.tsv", strings.Join([]string{
		"1000.0\trunning\trunning",
		"1004.0\trunning\trunning",
		"1005.5\tstopped\trunning",
		"1009.5\trunning\trunning",
		"1011.0\trunning\trunning",
		"1012.5\trunning\tstopped",
		"1016.5\trunning\trunning",
		"1019.0\trunning\trunning",
	}, "\n")+"\n")
	write("remote-module.tsv", strings.Join([]string{
		"1000.0\t1\t1\t0\t0\t0\t0\t1\t10.203.3.210_old",
		"1006.0\t2\t1\t1\t1\t0\t0\t2\t10.203.3.210_new",
		"1009.0\t3\t2\t1\t1\t0\t0\t3\t10.203.3.210_new",
		"1013.0\t4\t2\t2\t2\t0\t0\t4\t10.203.3.210_old",
		"1019.0\t5\t3\t2\t2\t0\t0\t5\t10.203.3.210_old",
	}, "\n")+"\n")
	for index := 0; index < 6; index++ {
		write(fmt.Sprintf("kernel-%02d.log", index), "")
		write(fmt.Sprintf("pstore-%02d.log", index), "")
	}
	for _, name := range []string{
		"tcp-forward.stderr.log",
		"tcp-reverse.stderr.log",
		"udp-forward.stderr.log",
		"udp-reverse.stderr.log",
		"ping.stderr.log",
		"remote-module.stderr.log",
		"pve-state.stderr.log",
	} {
		write(name, "")
	}
	write("remote-module.stderr.log", "Terminated\n")
	snapshot := pveHAFullKmodModuleSnapshot(strings.Repeat("a", 64))
	write("module-master-after.txt", snapshot)
	write("module-remote-after.txt", snapshot)
	ready := "{\"status\":\"ready\",\"ready\":true}\n"
	write("master-ready-after.json", ready)
	write("remote-ready-after.json", ready)
}

func pveHAFullKmodModuleSnapshot(moduleSHA256 string) string {
	parameters := map[string]string{
		"build_sha256":      moduleSHA256,
		"enable_features":   "128",
		"features":          "128",
		"rx_worker_inject":  "Y",
		"selftest_failures": "0",
		"selftests":         "1023",
		"tx_plaintext":      "Y",
	}
	names := []string{
		"build_sha256",
		"enable_features",
		"features",
		"rx_worker_inject",
		"selftest_failures",
		"selftests",
		"tx_plaintext",
	}
	var snapshot strings.Builder
	for _, name := range names {
		fmt.Fprintf(&snapshot, "/sys/module/trustix_datapath/parameters/%s:%s\n", name, parameters[name])
	}
	return snapshot.String()
}
