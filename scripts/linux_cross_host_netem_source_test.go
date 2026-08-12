package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func crossHostNetemDryRunEnv(workdir string) []string {
	return append(os.Environ(),
		"TRUSTIX_CROSS_HOST_DRY_RUN_CONFIG=1",
		"TRUSTIX_CROSS_HOST_CASE=dd-fullkmod",
		"TRUSTIX_CROSS_HOST_A_UNDERLAY_IP=192.0.2.10",
		"TRUSTIX_CROSS_HOST_B_UNDERLAY_IP=192.0.2.11",
		"TRUSTIX_CROSS_HOST_A_UNDERLAY_IF=eth0",
		"TRUSTIX_CROSS_HOST_B_UNDERLAY_IF=eth0",
		"TRUSTIX_CROSS_HOST_IPERF_TCP_BUFFER_BYTES=0",
		"TRUSTIX_CROSS_HOST_WORKDIR="+workdir,
	)
}

func TestCrossHostSoakRunnerIperfTCPBufferDryRunContract(t *testing.T) {
	bash := requireGNUBash4(t)
	workdir := filepath.Join(t.TempDir(), "iperf-tcp-buffer")
	cmd := exec.Command(bash, "linux-cross-host-soak-runner.sh")
	cmd.Dir = "."
	cmd.Env = append(crossHostNetemDryRunEnv(workdir),
		"TRUSTIX_CROSS_HOST_IPERF_TCP_BUFFER_BYTES=268435456",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("iperf TCP buffer dry-run failed: %v\n%s", err, out)
	}
	payload, err := os.ReadFile(filepath.Join(workdir, "iperf-tcp-buffer-config.txt"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, want := range []string{
		"format=trustix-cross-host-iperf-tcp-buffer-v1\n",
		"requested_bytes=268435456\n",
		"enabled=1\n",
		"scope=temporary-host-network-namespace\n",
		"host_namespace_a=tix-host-a\n",
		"host_namespace_b=tix-host-b\n",
		"socket_window=autotune\n",
		"settings=net.ipv4.tcp_rmem[2],net.ipv4.tcp_wmem[2]\n",
		"read_only_settings=net.core.rmem_max,net.core.wmem_max\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("iperf TCP buffer contract missing %q:\n%s", want, text)
		}
	}
}

func TestCrossHostSoakRunnerNetemDryRunContract(t *testing.T) {
	bash := requireGNUBash4(t)
	workdir := filepath.Join(t.TempDir(), "netem")
	cmd := exec.Command(bash, "linux-cross-host-soak-runner.sh")
	cmd.Dir = "."
	cmd.Env = append(crossHostNetemDryRunEnv(workdir),
		"TRUSTIX_CROSS_HOST_NETEM_TARGETS=a",
		"TRUSTIX_CROSS_HOST_NETEM_LOSS_PCT=0.1",
		"TRUSTIX_CROSS_HOST_NETEM_DELAY_MS=20",
		"TRUSTIX_CROSS_HOST_NETEM_JITTER_MS=5",
		"TRUSTIX_CROSS_HOST_NETEM_REORDER_PCT=1",
		"TRUSTIX_CROSS_HOST_NETEM_DUPLICATE_PCT=.2",
		"TRUSTIX_CROSS_HOST_NETEM_CORRUPT_PCT=0.03",
		"TRUSTIX_CROSS_HOST_NETEM_RATE_MBIT=2500",
		"TRUSTIX_CROSS_HOST_NETEM_LIMIT_PACKETS=8192",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("netem dry-run failed: %v\n%s", err, out)
	}
	payload, err := os.ReadFile(filepath.Join(workdir, "netem-config.txt"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, want := range []string{
		"format=trustix-cross-host-netem-v1\n",
		"enabled=1\n",
		"targets=a\n",
		"placement=egress\n",
		"loss_pct=0.1\n",
		"delay_ms=20\n",
		"jitter_ms=5\n",
		"reorder_pct=1\n",
		"duplicate_pct=.2\n",
		"corrupt_pct=0.03\n",
		"rate_mbit=2500\n",
		"limit_packets=8192\n",
		"disable_gro=1\n",
		"handle=7e10:\n",
		"underlay_a_if=eth0\n",
		"qdisc_args=limit 8192 delay 20ms 5ms loss 0.1% duplicate .2% corrupt 0.03% reorder 1% rate 2500mbit\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("netem contract missing %q:\n%s", want, text)
		}
	}
}

func TestCrossHostSoakRunnerNetemRateAloneEnablesQdisc(t *testing.T) {
	bash := requireGNUBash4(t)
	workdir := filepath.Join(t.TempDir(), "netem-rate")
	cmd := exec.Command(bash, "linux-cross-host-soak-runner.sh")
	cmd.Dir = "."
	cmd.Env = append(crossHostNetemDryRunEnv(workdir),
		"TRUSTIX_CROSS_HOST_NETEM_RATE_MBIT=100",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("netem rate-only dry-run failed: %v\n%s", err, out)
	}
	payload, err := os.ReadFile(filepath.Join(workdir, "netem-config.txt"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, want := range []string{
		"enabled=1\n",
		"rate_mbit=100\n",
		"limit_packets=1024\n",
		"limit_packets_explicit=0\n",
		"qdisc_args=limit 1024 rate 100mbit\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("netem rate-only contract missing %q:\n%s", want, text)
		}
	}
}

func TestCrossHostSoakRunnerNetemRateAutoLimitIsBounded(t *testing.T) {
	bash := requireGNUBash4(t)
	tests := []struct {
		name string
		rate string
		want string
	}{
		{"minimum", "1", "limit_packets=1024\n"},
		{"hundred-ms", "2500", "limit_packets=20834\n"},
		{"maximum", "1000000", "limit_packets=262144\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			workdir := filepath.Join(t.TempDir(), tc.name)
			cmd := exec.Command(bash, "linux-cross-host-soak-runner.sh")
			cmd.Dir = "."
			cmd.Env = append(crossHostNetemDryRunEnv(workdir),
				"TRUSTIX_CROSS_HOST_NETEM_RATE_MBIT="+tc.rate,
			)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("netem auto-limit dry-run failed: %v\n%s", err, out)
			}
			payload, err := os.ReadFile(filepath.Join(workdir, "netem-config.txt"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(payload), tc.want) {
				t.Fatalf("netem contract missing %q:\n%s", tc.want, payload)
			}
		})
	}
}

func TestCrossHostSoakRunnerRejectsInvalidNetemConfig(t *testing.T) {
	bash := requireGNUBash4(t)
	tests := []struct {
		name string
		env  string
		want string
	}{
		{"target", "TRUSTIX_CROSS_HOST_NETEM_TARGETS=sideways", "must be both, a, or b"},
		{"placement", "TRUSTIX_CROSS_HOST_NETEM_PLACEMENT=middle", "must be egress or ingress"},
		{"negative-loss", "TRUSTIX_CROSS_HOST_NETEM_LOSS_PCT=-1", "must be a decimal percentage in 0..100"},
		{"excess-loss", "TRUSTIX_CROSS_HOST_NETEM_LOSS_PCT=100.01", "must be a decimal percentage in 0..100"},
		{"fractional-delay", "TRUSTIX_CROSS_HOST_NETEM_DELAY_MS=1.5", "must be a non-negative integer"},
		{"negative-rate", "TRUSTIX_CROSS_HOST_NETEM_RATE_MBIT=-1", "must be a non-negative integer"},
		{"fractional-rate", "TRUSTIX_CROSS_HOST_NETEM_RATE_MBIT=1.5", "must be a non-negative integer"},
		{"excess-rate", "TRUSTIX_CROSS_HOST_NETEM_RATE_MBIT=1000001", "must be in 0..1000000"},
		{"jitter-without-delay", "TRUSTIX_CROSS_HOST_NETEM_JITTER_MS=1", "requires TRUSTIX_CROSS_HOST_NETEM_DELAY_MS > 0"},
		{"reorder-without-delay", "TRUSTIX_CROSS_HOST_NETEM_REORDER_PCT=1", "requires TRUSTIX_CROSS_HOST_NETEM_DELAY_MS > 0"},
		{"zero-limit", "TRUSTIX_CROSS_HOST_NETEM_LIMIT_PACKETS=0", "must be a positive integer"},
		{"invalid-disable-gro", "TRUSTIX_CROSS_HOST_NETEM_DISABLE_GRO=yes", "must be 0 or 1"},
		{"invalid-iperf-seconds", "TRUSTIX_CROSS_HOST_IPERF_SECONDS=long", "must be an integer"},
		{"invalid-iperf-timeout", "TRUSTIX_CROSS_HOST_IPERF_TIMEOUT=long", "must be an integer"},
		{"zero-iperf-timeout", "TRUSTIX_CROSS_HOST_IPERF_TIMEOUT=0", "must be positive"},
		{"invalid-active-seconds", "TRUSTIX_CROSS_HOST_NETEM_ACTIVE_SECONDS=soon", "must be a non-negative integer"},
		{"active-without-netem", "TRUSTIX_CROSS_HOST_NETEM_ACTIVE_SECONDS=1", "requires an enabled netem impairment"},
		{"invalid-latched-fallback-required", "TRUSTIX_CROSS_HOST_REQUIRE_INNER_GSO_LATCHED_FALLBACK=yes", "must be 0 or 1"},
		{"latched-fallback-observe-without-gate", "TRUSTIX_CROSS_HOST_INNER_GSO_LATCHED_FALLBACK_OBSERVE_SECONDS=1", "requires TRUSTIX_CROSS_HOST_REQUIRE_INNER_GSO_LATCHED_FALLBACK=1"},
		{"invalid-inner-gso", "TRUSTIX_CROSS_HOST_TIX_TCP_INNER_GSO=maybe", "must be boolean"},
		{"invalid-mtu", "TRUSTIX_CROSS_HOST_MTU=jumbo", "must be an integer"},
		{"small-mtu", "TRUSTIX_CROSS_HOST_MTU=575", "must be in 576..65535"},
		{"large-mtu", "TRUSTIX_CROSS_HOST_MTU=65536", "must be in 576..65535"},
		{"negative-iperf-tcp-buffer", "TRUSTIX_CROSS_HOST_IPERF_TCP_BUFFER_BYTES=-1", "must be a non-negative integer"},
		{"fractional-iperf-tcp-buffer", "TRUSTIX_CROSS_HOST_IPERF_TCP_BUFFER_BYTES=1.5", "must be a non-negative integer"},
		{"large-iperf-tcp-buffer", "TRUSTIX_CROSS_HOST_IPERF_TCP_BUFFER_BYTES=2147483648", "must be in 0..2147483647"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(bash, "linux-cross-host-soak-runner.sh")
			cmd.Dir = "."
			cmd.Env = append(crossHostNetemDryRunEnv(filepath.Join(t.TempDir(), tt.name)), tt.env)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("invalid netem config unexpectedly passed:\n%s", out)
			}
			if !strings.Contains(string(out), tt.want) {
				t.Fatalf("invalid netem error missing %q:\n%s", tt.want, out)
			}
		})
	}
}

func TestCrossHostSoakRunnerScopesIperfTCPBufferToHostNetNS(t *testing.T) {
	bash := requireGNUBash4(t)
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeIP := `#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$TRUSTIX_FAKE_IP_LOG"
[ "${1:-}" = netns ] && [ "${2:-}" = exec ] && [ "${3:-}" = tix-host-a ]
namespace=$3
shift 3
TRUSTIX_FAKE_SYSCTL_NETNS="$namespace" "$@"
`
	fakeSysctl := `#!/bin/sh
set -eu
[ "${TRUSTIX_FAKE_SYSCTL_NETNS:-}" = tix-host-a ] || {
  echo 'sysctl escaped the temporary host namespace' >&2
  exit 97
}
printf '%s\n' "$*" >>"$TRUSTIX_FAKE_SYSCTL_LOG"
state=$TRUSTIX_FAKE_SYSCTL_STATE
if [ "${1:-}" = -n ]; then
  applied=0
  [ -f "$state" ] && applied=1
  case "${2:-}" in
    net.core.rmem_max|net.core.wmem_max)
      echo 212992
      ;;
    net.ipv4.tcp_rmem)
      [ "$applied" -eq 1 ] && echo '4096 131072 268435456' || echo '4096 131072 6291456'
      ;;
    net.ipv4.tcp_wmem)
      [ "$applied" -eq 1 ] && echo '4096 16384 268435456' || echo '4096 16384 4194304'
      ;;
    *) exit 2 ;;
  esac
  exit 0
fi
if [ "${1:-}" = -q ] && [ "${2:-}" = -w ]; then
  case "${3:-}" in
    net.ipv4.tcp_rmem='4096 131072 268435456'|net.ipv4.tcp_wmem='4096 16384 268435456')
      : >"$state"
      exit 0
      ;;
  esac
fi
exit 2
`
	for name, source := range map[string]string{"ip": fakeIP, "sysctl": fakeSysctl} {
		path := filepath.Join(binDir, name)
		if err := os.WriteFile(path, []byte(source), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	runner, err := filepath.Abs("linux-cross-host-soak-runner.sh")
	if err != nil {
		t.Fatal(err)
	}
	remote := filepath.Join(root, "remote")
	code := `
set -Eeuo pipefail
source "$RUNNER"
node_a=local
remote_a="$REMOTE"
host_ns_a=tix-host-a
iperf_tcp_buffer_bytes=268435456
mkdir -p "$remote_a"
configure_iperf_tcp_buffer_node a
grep -Fqx 'requested_bytes=268435456' "$remote_a/iperf-tcp-buffer-state.txt"
grep -Fqx 'scope=temporary-host-network-namespace' "$remote_a/iperf-tcp-buffer-state.txt"
grep -Fqx 'actual_net_core_rmem_max=212992' "$remote_a/iperf-tcp-buffer-state.txt"
grep -Fqx 'actual_net_ipv4_tcp_rmem=4096 131072 268435456' "$remote_a/iperf-tcp-buffer-state.txt"
grep -Fqx 'actual_net_ipv4_tcp_wmem=4096 16384 268435456' "$remote_a/iperf-tcp-buffer-state.txt"
grep -Fqx 'status=applied' "$remote_a/iperf-tcp-buffer-state.txt"
test "$(wc -l <"$TRUSTIX_FAKE_IP_LOG")" = 10
test "$(sed -n '/^netns exec tix-host-a /!p' "$TRUSTIX_FAKE_IP_LOG" | wc -l)" = 0
`
	cmd := exec.Command(bash, "-c", code)
	cmd.Dir = "."
	cmd.Env = append(crossHostNetemDryRunEnv(filepath.Join(root, "dry-run")),
		"RUNNER="+runner,
		"REMOTE="+remote,
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"TRUSTIX_FAKE_IP_LOG="+filepath.Join(root, "ip.log"),
		"TRUSTIX_FAKE_SYSCTL_LOG="+filepath.Join(root, "sysctl.log"),
		"TRUSTIX_FAKE_SYSCTL_STATE="+filepath.Join(root, "sysctl.state"),
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("iperf TCP buffer namespace scope contract failed: %v\n%s", err, out)
	}
}

func TestCrossHostSoakRunnerLeavesIperfTCPBufferUntouchedAtZero(t *testing.T) {
	bash := requireGNUBash4(t)
	runner, err := filepath.Abs("linux-cross-host-soak-runner.sh")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ip", "sysctl"} {
		path := filepath.Join(binDir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\necho 'unexpected "+name+" call' >&2\nexit 97\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	remote := filepath.Join(root, "remote")
	code := `
set -Eeuo pipefail
source "$RUNNER"
node_a=local
remote_a="$REMOTE"
host_ns_a=tix-host-a
iperf_tcp_buffer_bytes=0
mkdir -p "$remote_a"
configure_iperf_tcp_buffer_node a
grep -Fqx 'requested_bytes=0' "$remote_a/iperf-tcp-buffer-state.txt"
grep -Fqx 'enabled=0' "$remote_a/iperf-tcp-buffer-state.txt"
grep -Fqx 'status=unchanged' "$remote_a/iperf-tcp-buffer-state.txt"
`
	cmd := exec.Command(bash, "-c", code)
	cmd.Dir = "."
	cmd.Env = append(crossHostNetemDryRunEnv(filepath.Join(root, "dry-run")),
		"RUNNER="+runner,
		"REMOTE="+remote,
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("zero iperf TCP buffer unexpectedly required sysctl or ip: %v\n%s", err, out)
	}
}

func TestCrossHostSoakRunnerUsesAllScheduledDirectionsForNetemTiming(t *testing.T) {
	bash := requireGNUBash4(t)
	tests := []struct {
		name       string
		directions string
		active     string
		observe    string
		wantPass   bool
		want       string
	}{
		{
			name:       "both-directions-active-window",
			directions: "both",
			active:     "15",
			wantPass:   true,
		},
		{
			name:       "single-direction-active-window",
			directions: "a2b",
			active:     "10",
			want:       "must be less than scheduled iperf traffic seconds (10)",
		},
		{
			name:       "both-directions-latched-window",
			directions: "both",
			active:     "12",
			observe:    "5",
			wantPass:   true,
		},
		{
			name:       "both-directions-latched-window-overrun",
			directions: "both",
			active:     "12",
			observe:    "8",
			want:       "must finish before scheduled iperf traffic seconds (20)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(bash, "linux-cross-host-soak-runner.sh")
			cmd.Dir = "."
			cmd.Env = append(crossHostNetemDryRunEnv(filepath.Join(t.TempDir(), tt.name)),
				"TRUSTIX_CROSS_HOST_IPERF_SECONDS=10",
				"TRUSTIX_CROSS_HOST_IPERF_DIRECTIONS="+tt.directions,
				"TRUSTIX_CROSS_HOST_NETEM_DELAY_MS=1",
				"TRUSTIX_CROSS_HOST_NETEM_ACTIVE_SECONDS="+tt.active,
			)
			if tt.observe != "" {
				cmd.Env = append(cmd.Env,
					"TRUSTIX_CROSS_HOST_REQUIRE_INNER_GSO_LATCHED_FALLBACK=1",
					"TRUSTIX_CROSS_HOST_INNER_GSO_LATCHED_FALLBACK_OBSERVE_SECONDS="+tt.observe,
				)
			}
			out, err := cmd.CombinedOutput()
			if tt.wantPass {
				if err != nil {
					t.Fatalf("scheduled netem timing rejected: %v\n%s", err, out)
				}
				return
			}
			if err == nil {
				t.Fatalf("invalid scheduled netem timing unexpectedly passed:\n%s", out)
			}
			if !strings.Contains(string(out), tt.want) {
				t.Fatalf("scheduled netem timing error missing %q:\n%s", tt.want, out)
			}
		})
	}
}

func TestCrossHostSoakRunnerLatchedFallbackRejectsExplicitInnerGSODisable(t *testing.T) {
	bash := requireGNUBash4(t)
	workdir := filepath.Join(t.TempDir(), "latched-default")
	baseEnv := append(crossHostNetemDryRunEnv(workdir),
		"TRUSTIX_CROSS_HOST_CASE=tix-tcp-full-kmod",
		"TRUSTIX_CROSS_HOST_IPERF_SECONDS=10",
		"TRUSTIX_CROSS_HOST_IPERF_DIRECTIONS=both",
		"TRUSTIX_CROSS_HOST_NETEM_DELAY_MS=1",
		"TRUSTIX_CROSS_HOST_NETEM_ACTIVE_SECONDS=2",
		"TRUSTIX_CROSS_HOST_REQUIRE_INNER_GSO_LATCHED_FALLBACK=1",
		"TRUSTIX_CROSS_HOST_INNER_GSO_LATCHED_FALLBACK_OBSERVE_SECONDS=2",
	)

	cmd := exec.Command(bash, "linux-cross-host-soak-runner.sh")
	cmd.Dir = "."
	cmd.Env = baseEnv
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("default inner-GSO latched-fallback dry-run failed: %v\n%s", err, out)
	}
	payload, err := os.ReadFile(filepath.Join(workdir, "daemon-env.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "TRUSTIX_TIX_TCP_INNER_GSO=") {
		t.Fatalf("default inner-GSO latched-fallback injected an enable override:\n%s", payload)
	}

	cmd = exec.Command(bash, "linux-cross-host-soak-runner.sh")
	cmd.Dir = "."
	cmd.Env = append(baseEnv, "TRUSTIX_CROSS_HOST_TIX_TCP_INNER_GSO=0")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("explicitly disabled inner GSO unexpectedly passed latched-fallback validation:\n%s", out)
	}
	if !strings.Contains(string(out), "cannot run when TRUSTIX_CROSS_HOST_TIX_TCP_INNER_GSO is explicitly disabled") {
		t.Fatalf("explicit inner-GSO disable error is unclear:\n%s", out)
	}
}

func TestCrossHostSoakRunnerScheduledNetemProvesInnerGSOLatchedFallback(t *testing.T) {
	bash := requireGNUBash4(t)
	runner, err := filepath.Abs("linux-cross-host-soak-runner.sh")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	code := `
set -Eeuo pipefail
source "$RUNNER"
sleep() { SECONDS=$((SECONDS + ${1:-0})); }
collect_transport_snapshot() {
  printf 'transport-%s\n' "$1" >>"$EVENTS"
  case "$1" in
    netem-after-clear) : >"$AFTER_CLEAR" ;;
    netem-after-latched-fallback) : >"$AFTER_OBSERVE" ;;
  esac
}
collect_module_parameters() { printf 'module-%s-%s\n' "$1" "$2" >>"$EVENTS"; }
collect_netem_state_node() { printf 'netem-%s\n' "$1" >>"$EVENTS"; }
record_netem_evidence() {
  printf 'format=trustix-cross-host-netem-evidence-v1\nlabel=%s\na_targeted=1\na_packets=100\na_drops=1\nb_targeted=1\nb_packets=100\nb_drops=1\nstatus=pass\n' "$1" >"$RESULTS/netem-evidence-$1.txt"
}
clear_netem_node() { printf 'clear-%s\n' "$1" >>"$EVENTS"; : >"$CLEARED"; }
transport_snapshot_counter() {
  case "$2:$3" in
    netem-before-apply:session_dials|netem-before-clear:session_dials|netem-after-clear:session_dials|netem-after-latched-fallback:session_dials) echo 1 ;;
    *) return 1 ;;
  esac
}
transport_snapshot_extra_sum() {
  case "$3" in
    tix_tcp_capability_withdrawals|tix_tcp_capability_withdrawal_acks) echo 1 ;;
    tix_tcp_capability_withdrawal_ack_timeouts) echo 0 ;;
    *) return 1 ;;
  esac
}
inner_gso_module_param_sum() {
  case "$1" in
    tx_plaintext_inner_gso_packets) echo 10 ;;
    tx_plaintext_outer_gso_packets) [ -f "$AFTER_OBSERVE" ] && echo 25 || echo 20 ;;
    tx_plaintext_packets) [ -f "$AFTER_OBSERVE" ] && echo 40 || echo 30 ;;
    inner_gso_circuit_trips) echo 2 ;;
    inner_gso_circuit_recoveries) echo 0 ;;
    *) return 1 ;;
  esac
}
inner_gso_module_param_uint() {
  case "$2" in
    inner_gso_circuit_trips) echo 1 ;;
    inner_gso_circuit_recoveries) echo 0 ;;
    *) return 1 ;;
  esac
}
inner_gso_module_param() {
  case "$2" in
    inner_gso_runtime_ready|inner_gso_auto_recover) echo N ;;
    *) return 1 ;;
  esac
}
workdir="$RESULTS"
mkdir -p "$workdir"
netem_active_seconds=1
inner_gso_latched_fallback_observe_seconds=2
require_inner_gso_latched_fallback=1
schedule_netem_transition
wait_netem_transition
grep -Fqx 'status=pass' "$RESULTS/inner-gso-latched-fallback-contract.txt"
grep -Fqx 'inner_gso_packets_before_clear=10' "$RESULTS/inner-gso-latched-fallback-contract.txt"
grep -Fqx 'inner_gso_packets_after_clear=10' "$RESULTS/inner-gso-latched-fallback-contract.txt"
grep -Fqx 'inner_gso_packets_after_observe=10' "$RESULTS/inner-gso-latched-fallback-contract.txt"
grep -Fqx 'outer_gso_packets_after_observe=25' "$RESULTS/inner-gso-latched-fallback-contract.txt"
grep -Fqx 'plaintext_packets_after_observe=40' "$RESULTS/inner-gso-latched-fallback-contract.txt"
grep -Fqx 'circuit_trips_before_clear=2' "$RESULTS/inner-gso-latched-fallback-contract.txt"
grep -Fqx 'circuit_recoveries_after_observe=0' "$RESULTS/inner-gso-latched-fallback-contract.txt"
grep -Fqx 'a_runtime_ready_after_observe=N' "$RESULTS/inner-gso-latched-fallback-contract.txt"
grep -Fqx 'b_auto_recover_after_observe=N' "$RESULTS/inner-gso-latched-fallback-contract.txt"
grep -Fqx 'a_capability_withdrawals_before_clear=1' "$RESULTS/inner-gso-latched-fallback-contract.txt"
grep -Fqx 'b_capability_withdrawal_acks_before_clear=1' "$RESULTS/inner-gso-latched-fallback-contract.txt"
grep -Fqx 'a_session_dials_before_apply=1' "$RESULTS/inner-gso-latched-fallback-contract.txt"
grep -Fqx 'a_session_dials_after_observe=1' "$RESULTS/inner-gso-latched-fallback-contract.txt"
test "$(grep -c '^clear-' "$EVENTS")" = 2
`
	cmd := exec.Command(bash, "-c", code)
	cmd.Dir = "."
	cmd.Env = append(crossHostNetemDryRunEnv(filepath.Join(root, "dry-run")),
		"RUNNER="+runner,
		"RESULTS="+filepath.Join(root, "results"),
		"EVENTS="+filepath.Join(root, "events.txt"),
		"CLEARED="+filepath.Join(root, "cleared"),
		"AFTER_CLEAR="+filepath.Join(root, "after-clear"),
		"AFTER_OBSERVE="+filepath.Join(root, "after-observe"),
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("scheduled inner-GSO latched-fallback contract failed: %v\n%s", err, out)
	}
}

func TestCrossHostSoakRunnerCanPreserveGROForIngressNetem(t *testing.T) {
	bash := requireGNUBash4(t)
	workdir := filepath.Join(t.TempDir(), "netem-preserve-gro")
	cmd := exec.Command(bash, "linux-cross-host-soak-runner.sh")
	cmd.Dir = "."
	cmd.Env = append(crossHostNetemDryRunEnv(workdir),
		"TRUSTIX_CROSS_HOST_NETEM_PLACEMENT=ingress",
		"TRUSTIX_CROSS_HOST_NETEM_DELAY_MS=10",
		"TRUSTIX_CROSS_HOST_NETEM_DISABLE_GRO=0",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ingress netem dry-run failed: %v\n%s", err, out)
	}
	payload, err := os.ReadFile(filepath.Join(workdir, "netem-config.txt"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, want := range []string{"placement=ingress\n", "disable_gro=0\n"} {
		if !strings.Contains(text, want) {
			t.Fatalf("ingress netem contract missing %q:\n%s", want, text)
		}
	}

	runner, err := os.ReadFile("linux-cross-host-soak-runner.sh")
	if err != nil {
		t.Fatal(err)
	}
	source := string(runner)
	for _, want := range []string{
		`if [ $(remote_quote "$netem_disable_gro") = 1 ]; then`,
		`if [ \"\$disable_gro\" = 1 ] && [ -n \"\$ethtool_cmd\" ]; then`,
		`grep -q '^ifb ' /proc/modules 2>/dev/null && ifb_loaded=1`,
		`0) rmmod ifb >/dev/null 2>&1 || rc=1 ;;`,
		`daemon_env >"$workdir/daemon-env.txt"`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("ingress netem GRO gate missing %q", want)
		}
	}
}

func TestCrossHostSoakRunnerRejectsUnsafeIngressCorruption(t *testing.T) {
	runner, err := os.ReadFile("linux-cross-host-soak-runner.sh")
	if err != nil {
		t.Fatal(err)
	}
	source := string(runner)
	for _, want := range []string{
		`rx_checksum=\$(awk '\$1 == \"rx-checksumming:\"`,
		`rx_checksum_fixed=\$(awk '\$1 == \"rx-checksumming:\"`,
		`ingress netem corruption cannot disable fixed RX checksum offload`,
		`if ! \"\$ethtool_cmd\" -K \"\$underlay_if\" rx off; then`,
		`rx_checksum_changed=%s`,
		`rx_checksum_changed=\$(sed -n 's/^rx_checksum_changed=//p'`,
		`\"\$ethtool_cmd\" -K \"\$underlay_if\" rx on || rc=1`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("ingress corruption checksum guard missing %q", want)
		}
	}
	fixedGuard := strings.Index(source, "ingress netem corruption cannot disable fixed RX checksum offload")
	marker := strings.Index(source, "printf 'placement=ingress")
	qdisc := strings.Index(source, `\"\$tc_cmd\" qdisc add dev \"\$underlay_if\" handle ffff: ingress`)
	if fixedGuard < 0 || marker < 0 || qdisc < 0 || fixedGuard > marker || fixedGuard > qdisc {
		t.Fatal("fixed RX checksum rejection must happen before ingress netem ownership or qdisc changes")
	}
}

func TestCrossHostSoakRunnerPassesInnerGSOToBothDaemons(t *testing.T) {
	bash := requireGNUBash4(t)
	workdir := filepath.Join(t.TempDir(), "inner-gso-env")
	cmd := exec.Command(bash, "linux-cross-host-soak-runner.sh")
	cmd.Dir = "."
	cmd.Env = append(crossHostNetemDryRunEnv(workdir),
		"TRUSTIX_CROSS_HOST_TIX_TCP_INNER_GSO=1",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("inner-GSO daemon env dry-run failed: %v\n%s", err, out)
	}
	payload, err := os.ReadFile(filepath.Join(workdir, "daemon-env.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), "TRUSTIX_TIX_TCP_INNER_GSO=1\n") {
		t.Fatalf("daemon env does not enable inner GSO:\n%s", payload)
	}
}

func TestCrossHostSoakRunnerSetsTransportMTUOnBothNodes(t *testing.T) {
	bash := requireGNUBash4(t)
	workdir := filepath.Join(t.TempDir(), "mtu")
	cmd := exec.Command(bash, "linux-cross-host-soak-runner.sh")
	cmd.Dir = "."
	cmd.Env = append(crossHostNetemDryRunEnv(workdir),
		"TRUSTIX_CROSS_HOST_MTU=1280",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("transport MTU dry-run failed: %v\n%s", err, out)
	}
	for _, name := range []string{"config-a.yaml", "config-b.yaml"} {
		payload, err := os.ReadFile(filepath.Join(workdir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(payload), "  mtu: 1280\n") {
			t.Fatalf("%s does not use requested MTU:\n%s", name, payload)
		}
	}
}

func TestCrossHostSoakRunnerAppliesAndClearsOwnedNetemQdisc(t *testing.T) {
	bash := requireGNUBash4(t)
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeTC := `#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$TRUSTIX_FAKE_TC_LOG"
if [ "${1:-}" = "-s" ]; then shift; fi
[ "${1:-}" = qdisc ] || exit 2
case "${2:-}" in
  show)
    if [ -f "$TRUSTIX_FAKE_TC_STATE" ]; then
      printf '%s\n' 'qdisc netem 7e10: root refcnt 2 limit 8192 delay 10ms'
      printf '%s\n' ' Sent 100000 bytes 100 pkt (dropped 1, overlimits 0 requeues 0)'
    else
      printf '%s\n' 'qdisc fq_codel 0: root refcnt 2 limit 10240p'
      printf '%s\n' ' Sent 200000 bytes 200 pkt (dropped 0, overlimits 0 requeues 0)'
    fi
    ;;
  replace) : >"$TRUSTIX_FAKE_TC_STATE" ;;
  del) rm -f "$TRUSTIX_FAKE_TC_STATE" ;;
  *) exit 2 ;;
esac
`
	tcPath := filepath.Join(binDir, "tc")
	if err := os.WriteFile(tcPath, []byte(fakeTC), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tcPath, 0o755); err != nil {
		t.Fatal(err)
	}
	runner, err := filepath.Abs("linux-cross-host-soak-runner.sh")
	if err != nil {
		t.Fatal(err)
	}
	remote := filepath.Join(root, "remote")
	code := `
set -Eeuo pipefail
source "$RUNNER"
node_a=local
remote_a="$REMOTE"
underlay_a_if=eth-test
apply_netem_node a
test -f "$TRUSTIX_FAKE_TC_STATE"
test -f "$REMOTE/netem-owned.txt"
collect_netem_state_node a
collect_netem_state_node a before-clear
clear_netem_node a
collect_netem_state_node a
test ! -e "$TRUSTIX_FAKE_TC_STATE"
test ! -e "$REMOTE/netem-owned.txt"
test -s "$REMOTE/netem-qdisc-after-clear.txt"
grep -Fq 'qdisc netem 7e10:' "$REMOTE/netem-qdisc-before-clear.txt"
grep -Fq '100 pkt (dropped 1,' "$REMOTE/netem-qdisc-before-clear.txt"
grep -Fq 'qdisc fq_codel 0:' "$REMOTE/netem-qdisc-current.txt"
clear_netem_node a
test "$(grep -c 'qdisc del dev eth-test root' "$TRUSTIX_FAKE_TC_LOG")" = 1
grep -Fq 'qdisc replace dev eth-test root handle 7e10: netem limit 8192 delay 10ms 2ms loss 0.1% duplicate 0.2% corrupt 0.3% reorder 1%' "$TRUSTIX_FAKE_TC_LOG"
`
	cmd := exec.Command(bash, "-c", code)
	cmd.Dir = "."
	cmd.Env = append(crossHostNetemDryRunEnv(filepath.Join(root, "dry-run")),
		"RUNNER="+runner,
		"REMOTE="+remote,
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"TRUSTIX_FAKE_TC_LOG="+filepath.Join(root, "tc.log"),
		"TRUSTIX_FAKE_TC_STATE="+filepath.Join(root, "tc.state"),
		"TRUSTIX_CROSS_HOST_NETEM_TARGETS=a",
		"TRUSTIX_CROSS_HOST_NETEM_LOSS_PCT=0.1",
		"TRUSTIX_CROSS_HOST_NETEM_DELAY_MS=10",
		"TRUSTIX_CROSS_HOST_NETEM_JITTER_MS=2",
		"TRUSTIX_CROSS_HOST_NETEM_REORDER_PCT=1",
		"TRUSTIX_CROSS_HOST_NETEM_DUPLICATE_PCT=0.2",
		"TRUSTIX_CROSS_HOST_NETEM_CORRUPT_PCT=0.3",
		"TRUSTIX_CROSS_HOST_NETEM_LIMIT_PACKETS=8192",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("netem apply/clear contract failed: %v\n%s", err, out)
	}
}

func TestCrossHostSoakRunnerRequiresNetemTrafficAndLossEvidence(t *testing.T) {
	bash := requireGNUBash4(t)
	runner, err := filepath.Abs("linux-cross-host-soak-runner.sh")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	code := `
set -Eeuo pipefail
source "$RUNNER"
netem_qdisc_counters() {
  case "$1" in
    a) echo '1000 10' ;;
    b) echo '2000 20' ;;
    *) return 1 ;;
  esac
}
workdir="$RESULTS"
mkdir -p "$workdir"
netem_targets=both
netem_loss_pct=1
record_netem_evidence before-clear
grep -Fqx 'a_packets=1000' "$RESULTS/netem-evidence-before-clear.txt"
grep -Fqx 'a_drops=10' "$RESULTS/netem-evidence-before-clear.txt"
grep -Fqx 'b_packets=2000' "$RESULTS/netem-evidence-before-clear.txt"
grep -Fqx 'b_drops=20' "$RESULTS/netem-evidence-before-clear.txt"
grep -Fqx 'status=pass' "$RESULTS/netem-evidence-before-clear.txt"
`
	cmd := exec.Command(bash, "-c", code)
	cmd.Dir = "."
	cmd.Env = append(crossHostNetemDryRunEnv(filepath.Join(root, "dry-run")),
		"RUNNER="+runner,
		"RESULTS="+filepath.Join(root, "results"),
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("netem traffic evidence contract failed: %v\n%s", err, out)
	}
}

func TestCrossHostSoakRunnerRejectsNetemWithoutObservedLoss(t *testing.T) {
	bash := requireGNUBash4(t)
	runner, err := filepath.Abs("linux-cross-host-soak-runner.sh")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	code := `
set -Eeuo pipefail
source "$RUNNER"
netem_qdisc_counters() { echo '1000 0'; }
workdir="$RESULTS"
mkdir -p "$workdir"
netem_targets=both
netem_loss_pct=1
if record_netem_evidence before-clear; then
  echo 'zero-drop netem evidence unexpectedly passed' >&2
  exit 1
fi
grep -Fqx 'status=fail' "$RESULTS/netem-evidence-before-clear.txt"
`
	cmd := exec.Command(bash, "-c", code)
	cmd.Dir = "."
	cmd.Env = append(crossHostNetemDryRunEnv(filepath.Join(root, "dry-run")),
		"RUNNER="+runner,
		"RESULTS="+filepath.Join(root, "results"),
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("zero-drop netem evidence rejection failed: %v\n%s", err, out)
	}
}

func TestCrossHostSoakRunnerClearsNetemWhenPreservingFailure(t *testing.T) {
	bash := requireGNUBash4(t)
	runner, err := filepath.Abs("linux-cross-host-soak-runner.sh")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	code := `
set -Eeuo pipefail
source "$RUNNER"
events=""
collect_all() { events="${events} collect"; }
stop_daemon() { events="${events} stop-$1"; }
clear_netem_node() { events="${events} clear-$1"; }
fetch_all() { events="${events} fetch"; }
cleanup_node() { events="${events} cleanup-$1"; }
release_pair_lock() { events="${events} unlock"; }
workdir="$RESULTS"
mkdir -p "$workdir"
preserve_on_failure=1
set +e
false
cleanup_all
cleanup_rc=$?
set -e
test "$cleanup_rc" = 1
test "$events" = " collect stop-a stop-b clear-a clear-b fetch unlock"
`
	cmd := exec.Command(bash, "-c", code)
	cmd.Dir = "."
	cmd.Env = append(crossHostNetemDryRunEnv(filepath.Join(root, "dry-run")),
		"RUNNER="+runner,
		"RESULTS="+filepath.Join(root, "results"),
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("preserved-failure netem cleanup contract failed: %v\n%s", err, out)
	}
}
