package scripts

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestCrossHostSystemProfileScriptSyntax(t *testing.T) {
	bash := requireGNUBash4(t)
	cmd := exec.Command(bash, "-n", "linux-cross-host-system-profile.sh")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n linux-cross-host-system-profile.sh: %v\n%s", err, out)
	}
}

func TestCrossHostSystemProfileScriptPreservesEvidenceAndCleansRemoteState(t *testing.T) {
	payload, err := os.ReadFile("linux-cross-host-system-profile.sh")
	if err != nil {
		t.Fatalf("read linux-cross-host-system-profile.sh: %v", err)
	}
	script := string(payload)
	for _, want := range []string{
		`[[ "$node_a" == "local" ]]`,
		`TRUSTIX_CROSS_HOST_SYSTEM_PROFILE_DIR is required`,
		`[[ "$profile_dir" == /* ]]`,
		`[[ "$remote_parent" == /* ]]`,
		`[[ ! -e "$profile_dir" ]]`,
		`export TRUSTIX_CROSS_HOST_WORKDIR="$workdir"`,
		`export TRUSTIX_CROSS_HOST_IPERF_DIRECTIONS="a2b"`,
		`trap cleanup EXIT`,
		`*/trustix-system-profile-*)`,
		`ssh "${ssh_opts[@]}" "$node_b" "rm -rf -- '${remote_profile_dir}'"`,
		`missing required remote command`,
		`remote underlay interface is missing`,
		`perf stat -a -x, -e cycles,instructions,task-clock`,
		`perf record -a -F "$profile_frequency"`,
		`cat /proc/kallsyms`,
		`[[ -r "/proc/${pid}/cmdline" ]] || continue`,
		`tr '\0' ' ' 2>/dev/null <"/proc/${pid}/cmdline"`,
		`snapshot_link "$underlay_if_a" before`,
		`snapshot_link "$underlay_if_a" after`,
		`throughput-bps.txt`,
		`need_cmd jq`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("linux-cross-host-system-profile.sh missing %q", want)
		}
	}
	for _, bad := range []string{
		`/root/trustix`,
		`PVEAPIToken=`,
		`root@pam!`,
		`password=`,
		`StrictHostKeyChecking=no`,
	} {
		if strings.Contains(script, bad) {
			t.Fatalf("linux-cross-host-system-profile.sh contains unsafe fragment %q", bad)
		}
	}
}
