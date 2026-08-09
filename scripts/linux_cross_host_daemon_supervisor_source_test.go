package scripts

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestCrossHostSoakRunnerSystemdSupervisorSyntax(t *testing.T) {
	bash := requireGNUBash4(t)
	cmd := exec.Command(bash, "-n", "linux-cross-host-soak-runner.sh")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n linux-cross-host-soak-runner.sh: %v\n%s", err, out)
	}
}

func TestCrossHostSoakRunnerSystemdSupervisorLifecycle(t *testing.T) {
	payload, err := os.ReadFile("linux-cross-host-soak-runner.sh")
	if err != nil {
		t.Fatalf("read linux-cross-host-soak-runner.sh: %v", err)
	}
	script := string(payload)
	for _, want := range []string{
		"daemon_supervisor=\"${TRUSTIX_CROSS_HOST_DAEMON_SUPERVISOR:-process}\"",
		"daemon_restart_sec=\"${TRUSTIX_CROSS_HOST_DAEMON_RESTART_SEC:-1}\"",
		"TRUSTIX_CROSS_HOST_DAEMON_SUPERVISOR must be process or systemd",
		"required_commands=\\\"\\${required_commands} systemctl systemd-run\\\"",
		"systemd-run --quiet --collect",
		"--property=Restart=always",
		"--property=RestartSec=${daemon_restart_sec}s",
		"StandardOutput=append:",
		"systemctl show --property=MainPID --value",
		"printf '%s\\n' \\\"\\$pid\\\" >trustixd.pid",
		"systemctl stop",
		"systemctl kill --kill-who=all --signal=KILL",
		"cleanup_step systemd-stop systemctl stop",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("linux-cross-host-soak-runner.sh missing %q", want)
		}
	}
}
