package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPVEWorkspaceHygieneScriptSyntax(t *testing.T) {
	bash := requireGNUBash4(t)
	cmd := exec.Command(bash, "-n", "pve-workspace-hygiene.sh")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n pve-workspace-hygiene.sh: %v\n%s", err, out)
	}
}

func TestPVECurrentUserspaceRefreshScriptSyntax(t *testing.T) {
	bash := requireGNUBash4(t)
	cmd := exec.Command(bash, "-n", "pve-current-userspace-refresh.sh")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n pve-current-userspace-refresh.sh: %v\n%s", err, out)
	}
}

func TestPVECurrentRunStatusScriptSyntax(t *testing.T) {
	bash := requireGNUBash4(t)
	cmd := exec.Command(bash, "-n", "pve-current-run-status.sh")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n pve-current-run-status.sh: %v\n%s", err, out)
	}
}

func TestPVEPromoteRunEvidenceScriptSyntax(t *testing.T) {
	bash := requireGNUBash4(t)
	cmd := exec.Command(bash, "-n", "pve-promote-run-evidence.sh")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n pve-promote-run-evidence.sh: %v\n%s", err, out)
	}
}

func TestPVEHAFullKmodSoakScriptSyntax(t *testing.T) {
	bash := requireGNUBash4(t)
	cmd := exec.Command(bash, "-n", "pve-ha-full-kmod-soak.sh")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n pve-ha-full-kmod-soak.sh: %v\n%s", err, out)
	}
}

func TestPVEHAFullKmodSoakScriptKeepsProductionVMsAndHostStateOutOfScope(t *testing.T) {
	payload, err := os.ReadFile("pve-ha-full-kmod-soak.sh")
	if err != nil {
		t.Fatalf("read pve-ha-full-kmod-soak.sh: %v", err)
	}
	script := string(payload)
	for _, want := range []string{
		`(( value >= 200 ))`,
		`TRUSTIX_HA_SOAK_ALLOWED_ROOT:-/root/trustix-pve-work`,
		`case "$output" in`,
		`"$allowed_root"/*)`,
		`StrictHostKeyChecking=yes`,
		`TRUSTIX_HA_SOAK_MODULE_SHA256`,
		`TRUSTIX_HA_SOAK_MODULE_SRCVERSION`,
		`TRUSTIX_HA_SOAK_RUN_ID`,
		`TRUSTIX_HA_SOAK_TRAFFIC_PAUSE`,
		`TRUSTIX_HA_SOAK_SERVER_SETTLE_SECONDS`,
		`flock -n -o -E 75`,
		`TRUSTIX_HA_SOAK_LOCKED_INTERNAL`,
		`collect_tagged_pids`,
		`cleanup_stale_remote_load`,
		`cleanup_remote_load || die "failed to clean remote load processes"`,
		`TRUSTIX_HA_SOAK_ROLE='server-${port}'`,
		`rmdir "$root" 2>/dev/null || true`,
		`rcu.*stall`,
		`NETDEV WATCHDOG`,
		`workqueue lockup`,
		`2>"$stderr_file"`,
		`remote-module.stderr.log`,
		`qm stop "$active" --timeout 10`,
		`iptables -I OUTPUT 1 -p 112`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("pve-ha-full-kmod-soak.sh missing safety boundary %q", want)
		}
	}
	for _, bad := range []string{
		`120.220.44.72`,
		`5c15d166-661c-4a9d-8244-bfe45a36d136`,
		`ZakoUnRikaLou1145`,
		`qm stop 1`,
		`qm destroy 1`,
		`/etc/network/interfaces`,
		`exec 9>`,
	} {
		if strings.Contains(script, bad) {
			t.Fatalf("pve-ha-full-kmod-soak.sh contains forbidden host-specific fragment %q", bad)
		}
	}
}

func TestPVEHAFullKmodSoakScriptInitializesDependentLocalsSeparately(t *testing.T) {
	payload, err := os.ReadFile("pve-ha-full-kmod-soak.sh")
	if err != nil {
		t.Fatalf("read pve-ha-full-kmod-soak.sh: %v", err)
	}
	script := string(payload)
	if strings.Contains(script, `timeout="$2" deadline=$((SECONDS + timeout))`) {
		t.Fatal("pve-ha-full-kmod-soak.sh references timeout in the same local declaration under set -u")
	}
	if got := strings.Count(script, `local deadline=$((SECONDS + timeout))`); got != 3 {
		t.Fatalf("dependent timeout deadline declarations = %d, want 3", got)
	}
}

func TestCrossHostConcurrentSoakScriptSyntax(t *testing.T) {
	bash := requireGNUBash4(t)
	cmd := exec.Command(bash, "-n", "linux-cross-host-concurrent-soak.sh")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n linux-cross-host-concurrent-soak.sh: %v\n%s", err, out)
	}
}

func TestCrossHostConcurrentSoakScriptKeepsCasesIsolated(t *testing.T) {
	payload, err := os.ReadFile("linux-cross-host-concurrent-soak.sh")
	if err != nil {
		t.Fatalf("read linux-cross-host-concurrent-soak.sh: %v", err)
	}
	script := string(payload)
	for _, want := range []string{
		`workdir="${TRUSTIX_CROSS_HOST_CONCURRENT_WORKDIR:-$(mktemp -d /tmp/trustix-cross-host-concurrent.XXXXXX)}"`,
		`remote_base="${TRUSTIX_CROSS_HOST_CONCURRENT_REMOTE_BASE:-${remote_parent}/trustix-cross-host-concurrent-$(date +%Y%m%d-%H%M%S)-$$}"`,
		`unload_modules="${TRUSTIX_CROSS_HOST_CONCURRENT_UNLOAD_MODULES:-0}"`,
		`TRUSTIX_CROSS_HOST_UNLOAD_MODULES=${unload_modules}`,
		`TRUSTIX_CROSS_HOST_PROFILE=${profile}`,
		`TRUSTIX_CROSS_HOST_TRANSPORT_DATAPATH=${datapath}`,
		`TRUSTIX_CROSS_HOST_CRYPTO_PLACEMENT=userspace`,
		`TRUSTIX_CROSS_HOST_REMOTE_A=${remote_base}/${label}/a`,
		`TRUSTIX_CROSS_HOST_REMOTE_B=${remote_base}/${label}/b`,
		`TRUSTIX_CROSS_HOST_API_A_PORT=${api_a}`,
		`TRUSTIX_CROSS_HOST_PEER_A_PORT=${peer_a}`,
		`TRUSTIX_CROSS_HOST_DATA_A_PORT=${data_a}`,
		`TRUSTIX_CROSS_HOST_IPERF_PORT=${iperf}`,
		`TRUSTIX_CROSS_HOST_IPERF_PARALLEL=${iperf_parallel}`,
		`TRUSTIX_CROSS_HOST_SESSION_POOL_SIZE=${session_pool_size}`,
		`write_optional_env "$env_file" TRUSTIX_CROSS_HOST_A "$node_a"`,
		`write_optional_env "$env_file" TRUSTIX_CROSS_HOST_BIN_DIR_A "$bin_dir_a"`,
		`write_optional_env "$env_file" TRUSTIX_CROSS_HOST_A_UNDERLAY_IP "$underlay_a_ip"`,
		`write_optional_env "$env_file" TRUSTIX_CROSS_HOST_ENDPOINT_TRANSPORTS "$endpoint_transports_raw"`,
		`unset TRUSTIX_CROSS_HOST_ENDPOINT_TRANSPORTS`,
		`TRUSTIX_CROSS_HOST_LAN_IF_A=tix-lan-c${index}a`,
		`TRUSTIX_CROSS_HOST_HOST_NS_A=tix-host-c${index}a`,
		`TRUSTIX_CROSS_HOST_LAN_A_CIDR=10.74.${lan_a_octet}.0/24`,
		`TRUSTIX_CROSS_HOST_IPTUNNEL_A_CARRIER=10.75.${carrier_octet}.1/30`,
		`TRUSTIX_CROSS_HOST_IPTUNNEL_PORT=${iptunnel_port}`,
		`TRUSTIX_CROSS_HOST_VXLAN_VNI=${vxlan_vni}`,
		`TRUSTIX_CROSS_HOST_VXLAN_PORT=${vxlan_port}`,
		`case "$dir" in "$workdir"/*)`,
		`run_one "$name" "$dir" "$env_file" >"${dir}.out" 2>"${dir}.err" &`,
		`"--require-stable-boot-id"`,
		`"--require-kernel-log-artifacts"`,
		`"--require-status-max" "data_path.counters.send_errors=0"`,
		`"--require-status-max" "data_path.counters.receive_errors=0"`,
		`"--require-status-max" "data_path.counters.listener_accept_errors=0"`,
		`"--require-status-max" "data_path.counters.stale_sessions_dropped=0"`,
		`"--require-status-max" "data_path.drop_reasons.FLOW_NOT_INSTALLED=0"`,
		`"--require-transport-policy-stat" "profile=${profile}"`,
		`"--require-transport-policy-stat" "datapath=${datapath}"`,
		`--require-transport-session-any-min "stats.bytes_sent=1"`,
		`--require-transport-session-any-min "stats.bytes_received=1"`,
		`"--forbid-lsmod-prefix" "trustix_"`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("linux-cross-host-concurrent-soak.sh missing %q", want)
		}
	}
	for _, bad := range []string{
		`/root/current-`,
		`mktemp -d /root`,
		`TRUSTIX_CROSS_HOST_CONCURRENT_UNLOAD_MODULES:-1`,
	} {
		if strings.Contains(script, bad) {
			t.Fatalf("linux-cross-host-concurrent-soak.sh contains unsafe fragment %q", bad)
		}
	}
}

func TestCrossHostConcurrentSoakDryRunGeneratesIsolatedCases(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("concurrent soak dry-run expects GNU bash and Linux-style paths")
	}
	bash := requireGNUBash4(t)
	root := t.TempDir()
	runner := filepath.Join(root, "runner.sh")
	verifier := filepath.Join(root, "verifier.py")
	workdir := filepath.Join(root, "concurrent")
	if err := os.WriteFile(runner, []byte("#!/usr/bin/env bash\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write runner: %v", err)
	}
	if err := os.WriteFile(verifier, []byte("#!/usr/bin/env python3\n"), 0o755); err != nil {
		t.Fatalf("write verifier: %v", err)
	}
	cmd := exec.Command(bash, "linux-cross-host-concurrent-soak.sh")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(),
		"TRUSTIX_CROSS_HOST_CONCURRENT_DRY_RUN=1",
		"TRUSTIX_CROSS_HOST_CONCURRENT_WORKDIR="+workdir,
		"TRUSTIX_CROSS_HOST_CONCURRENT_RUNNER="+runner,
		"TRUSTIX_CROSS_HOST_CONCURRENT_VERIFIER="+verifier,
		"TRUSTIX_CROSS_HOST_CONCURRENT_CASES=userspace-udp-secure tc-gre-plaintext userspace-tix-tcp-secure userspace-mixed-secure",
		"TRUSTIX_CROSS_HOST_CONCURRENT_ENDPOINT_TRANSPORTS=udp,tcp,quic,websocket,http_connect,tix_tcp",
		"TRUSTIX_CROSS_HOST_CONCURRENT_A=root@192.0.2.10",
		"TRUSTIX_CROSS_HOST_CONCURRENT_B=root@192.0.2.11",
		"TRUSTIX_CROSS_HOST_CONCURRENT_SSH_OPTS=-i /tmp/test-key -o BatchMode=yes",
		"TRUSTIX_CROSS_HOST_CONCURRENT_BIN_DIR_A=/opt/trustix-a/bin",
		"TRUSTIX_CROSS_HOST_CONCURRENT_BIN_DIR_B=/opt/trustix-b/bin",
		"TRUSTIX_CROSS_HOST_CONCURRENT_TRUSTIX_CA=/opt/trustix-a/bin/trustix-ca",
		"TRUSTIX_CROSS_HOST_CONCURRENT_A_UNDERLAY_IP=198.51.100.10",
		"TRUSTIX_CROSS_HOST_CONCURRENT_B_UNDERLAY_IP=198.51.100.11",
		"TRUSTIX_CROSS_HOST_CONCURRENT_A_UNDERLAY_IF=eth1",
		"TRUSTIX_CROSS_HOST_CONCURRENT_B_UNDERLAY_IF=eth2",
		"TRUSTIX_CROSS_HOST_CONCURRENT_CARRIER_OCTET_BASE=120",
		"TRUSTIX_CROSS_HOST_CONCURRENT_IPTUNNEL_PORT_BASE=48000",
		"TRUSTIX_CROSS_HOST_CONCURRENT_VXLAN_VNI_BASE=900",
		"TRUSTIX_CROSS_HOST_CONCURRENT_VXLAN_PORT_BASE=4900",
		"TRUSTIX_CROSS_HOST_CONCURRENT_IPERF_PARALLEL=3",
		"TRUSTIX_CROSS_HOST_CONCURRENT_SESSION_POOL_SIZE=5",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("concurrent dry-run failed: %v\n%s", err, out)
	}
	summary, err := os.ReadFile(filepath.Join(workdir, "summary.jsonl"))
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	for _, want := range []string{
		`"case":"userspace-udp-secure"`,
		`"case":"tc-gre-plaintext"`,
		`"case":"userspace-tix-tcp-secure"`,
		`"case":"userspace-mixed-secure"`,
		`"status":"dry_run"`,
	} {
		if !strings.Contains(string(summary), want) {
			t.Fatalf("summary missing %q:\n%s", want, summary)
		}
	}
	env0, err := os.ReadFile(filepath.Join(workdir, "userspace-udp-secure", "case.env"))
	if err != nil {
		t.Fatalf("read case 0 env: %v", err)
	}
	env1, err := os.ReadFile(filepath.Join(workdir, "tc-gre-plaintext", "case.env"))
	if err != nil {
		t.Fatalf("read case 1 env: %v", err)
	}
	for _, want := range []string{
		"TRUSTIX_CROSS_HOST_UNLOAD_MODULES=0",
		"TRUSTIX_CROSS_HOST_PROFILE=stable",
		"TRUSTIX_CROSS_HOST_TRANSPORT_DATAPATH=userspace",
		"TRUSTIX_CROSS_HOST_CRYPTO_PLACEMENT=userspace",
		"TRUSTIX_CROSS_HOST_API_A_PORT=28787",
		"TRUSTIX_CROSS_HOST_PEER_A_PORT=29443",
		"TRUSTIX_CROSS_HOST_DATA_A_PORT=29700",
		"TRUSTIX_CROSS_HOST_IPERF_PORT=35201",
		"TRUSTIX_CROSS_HOST_IPERF_PARALLEL=3",
		"TRUSTIX_CROSS_HOST_SESSION_POOL_SIZE=5",
		"TRUSTIX_CROSS_HOST_A=root@192.0.2.10",
		"TRUSTIX_CROSS_HOST_B=root@192.0.2.11",
		"TRUSTIX_CROSS_HOST_SSH_OPTS=-i\\ /tmp/test-key\\ -o\\ BatchMode=yes",
		"TRUSTIX_CROSS_HOST_BIN_DIR_A=/opt/trustix-a/bin",
		"TRUSTIX_CROSS_HOST_BIN_DIR_B=/opt/trustix-b/bin",
		"TRUSTIX_CROSS_HOST_TRUSTIX_CA=/opt/trustix-a/bin/trustix-ca",
		"TRUSTIX_CROSS_HOST_A_UNDERLAY_IP=198.51.100.10",
		"TRUSTIX_CROSS_HOST_B_UNDERLAY_IP=198.51.100.11",
		"TRUSTIX_CROSS_HOST_A_UNDERLAY_IF=eth1",
		"TRUSTIX_CROSS_HOST_B_UNDERLAY_IF=eth2",
		"TRUSTIX_CROSS_HOST_LAN_A_CIDR=10.74.80.0/24",
		"TRUSTIX_CROSS_HOST_IPTUNNEL_A_CARRIER=10.75.120.1/30",
		"TRUSTIX_CROSS_HOST_IPTUNNEL_B_CARRIER=10.75.120.2/30",
		"TRUSTIX_CROSS_HOST_IPTUNNEL_PORT=48000",
		"TRUSTIX_CROSS_HOST_VXLAN_VNI=900",
		"TRUSTIX_CROSS_HOST_VXLAN_PORT=4900",
	} {
		if !strings.Contains(string(env0), want) {
			t.Fatalf("case 0 env missing %q:\n%s", want, env0)
		}
	}
	for _, want := range []string{
		"TRUSTIX_CROSS_HOST_UNLOAD_MODULES=0",
		"TRUSTIX_CROSS_HOST_TRANSPORT=gre",
		"TRUSTIX_CROSS_HOST_ENCRYPTION=plaintext",
		"TRUSTIX_CROSS_HOST_PROFILE=performance",
		"TRUSTIX_CROSS_HOST_TRANSPORT_DATAPATH=tc_xdp",
		"TRUSTIX_CROSS_HOST_CRYPTO_PLACEMENT=userspace",
		"TRUSTIX_CROSS_HOST_API_A_PORT=28797",
		"TRUSTIX_CROSS_HOST_PEER_A_PORT=29453",
		"TRUSTIX_CROSS_HOST_DATA_A_PORT=29710",
		"TRUSTIX_CROSS_HOST_IPERF_PORT=35211",
		"TRUSTIX_CROSS_HOST_LAN_A_CIDR=10.74.82.0/24",
		"TRUSTIX_CROSS_HOST_IPTUNNEL_A_CARRIER=10.75.121.1/30",
		"TRUSTIX_CROSS_HOST_IPTUNNEL_B_CARRIER=10.75.121.2/30",
		"TRUSTIX_CROSS_HOST_IPTUNNEL_PORT=48001",
		"TRUSTIX_CROSS_HOST_VXLAN_VNI=901",
		"TRUSTIX_CROSS_HOST_VXLAN_PORT=4901",
	} {
		if !strings.Contains(string(env1), want) {
			t.Fatalf("case 1 env missing %q:\n%s", want, env1)
		}
	}
	envMixed, err := os.ReadFile(filepath.Join(workdir, "userspace-mixed-secure", "case.env"))
	if err != nil {
		t.Fatalf("read mixed case env: %v", err)
	}
	for _, want := range []string{
		"TRUSTIX_CROSS_HOST_TRANSPORT=mixed",
		"TRUSTIX_CROSS_HOST_PROFILE=stable",
		"TRUSTIX_CROSS_HOST_TRANSPORT_DATAPATH=userspace",
		"TRUSTIX_CROSS_HOST_ENDPOINT_TRANSPORTS=udp\\,tcp\\,quic\\,websocket\\,http_connect\\,tix_tcp",
	} {
		if !strings.Contains(string(envMixed), want) {
			t.Fatalf("mixed case env missing %q:\n%s", want, envMixed)
		}
	}
}

func TestCrossHostRunnerMultiEndpointDryRunConfig(t *testing.T) {
	bash := requireGNUBash4(t)
	workdir := filepath.Join(t.TempDir(), "mixed")
	cmd := exec.Command(bash, "linux-cross-host-soak-runner.sh")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(),
		"TRUSTIX_CROSS_HOST_DRY_RUN_CONFIG=1",
		"TRUSTIX_CROSS_HOST_CASE=userspace-mixed-secure",
		"TRUSTIX_CROSS_HOST_ENDPOINT_TRANSPORTS=udp,tcp,quic,websocket,http_connect,tix_tcp",
		"TRUSTIX_CROSS_HOST_A_UNDERLAY_IP=192.0.2.10",
		"TRUSTIX_CROSS_HOST_B_UNDERLAY_IP=192.0.2.11",
		"TRUSTIX_CROSS_HOST_A_UNDERLAY_IF=eth0",
		"TRUSTIX_CROSS_HOST_B_UNDERLAY_IF=eth0",
		"TRUSTIX_CROSS_HOST_WORKDIR="+workdir,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("multi-endpoint dry-run config failed: %v\n%s", err, out)
	}
	for _, name := range []string{"config-a.yaml", "config-b.yaml"} {
		payload, err := os.ReadFile(filepath.Join(workdir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		config := string(payload)
		for _, transport := range []string{"udp", "tcp", "quic", "websocket", "http_connect", "tix_tcp"} {
			if got := strings.Count(config, "transport: "+transport+"\n"); got != 2 {
				t.Fatalf("%s transport %s count = %d, want local+peer; config:\n%s", name, transport, got, config)
			}
		}
		if got := strings.Count(config, "  candidates:\n"); got != 1 {
			t.Fatalf("%s candidates block count = %d; config:\n%s", name, got, config)
		}
		if strings.Contains(config, "    endpoint:") {
			t.Fatalf("%s route unexpectedly pins one endpoint:\n%s", name, config)
		}
		for _, want := range []string{
			"  crypto_key_source: auto",
			"  tls_identity:",
			"    mode: custom_cert",
		} {
			if !strings.Contains(config, want) {
				t.Fatalf("%s missing %q:\n%s", name, want, config)
			}
		}
	}
}

func TestCrossHostRunnerKernelMixedEndpointDryRunConfig(t *testing.T) {
	bash := requireGNUBash4(t)
	for _, tc := range []struct {
		name       string
		datapath   string
		crypto     string
		configWant []string
		envWant    []string
	}{
		{
			name:     "mixed-plaintext-full-kmod",
			datapath: "kernel_module",
			crypto:   "userspace",
			configWant: []string{
				"capability_profile: full_plaintext",
				"trustix_datapath:\n    mode: required",
			},
			envWant: []string{
				"TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT=1",
				"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_ALLOW_TIX_TCP=1",
				"TRUSTIX_TIX_TCP_ALLOW_MIXED_TCP_FAST_PATH=1",
			},
		},
		{
			name:     "mixed-secure-kernel",
			datapath: "kernel_module",
			crypto:   "kernel",
			configWant: []string{
				"capability_profile: performance",
				"trustix_crypto:\n    mode: required",
				"trustix_datapath_helpers:\n    mode: required",
			},
			envWant: []string{
				"TRUSTIX_TIX_TCP_ROUTE_GSO=1",
				"TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT=1",
				"TRUSTIX_KERNEL_UDP_TC_TX_SECURE_ROUTE_GSO=1",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			workdir := filepath.Join(t.TempDir(), tc.name)
			cmd := exec.Command(bash, "linux-cross-host-soak-runner.sh")
			cmd.Dir = "."
			cmd.Env = append(os.Environ(),
				"TRUSTIX_CROSS_HOST_DRY_RUN_CONFIG=1",
				"TRUSTIX_CROSS_HOST_CASE="+tc.name,
				"TRUSTIX_CROSS_HOST_ENDPOINT_TRANSPORTS=udp,tix_tcp",
				"TRUSTIX_CROSS_HOST_A_UNDERLAY_IP=192.0.2.10",
				"TRUSTIX_CROSS_HOST_B_UNDERLAY_IP=192.0.2.11",
				"TRUSTIX_CROSS_HOST_A_UNDERLAY_IF=eth0",
				"TRUSTIX_CROSS_HOST_B_UNDERLAY_IF=eth0",
				"TRUSTIX_CROSS_HOST_WORKDIR="+workdir,
			)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("kernel mixed-endpoint dry-run config failed: %v\n%s", err, out)
			}
			configRaw, err := os.ReadFile(filepath.Join(workdir, "config-a.yaml"))
			if err != nil {
				t.Fatalf("read config-a.yaml: %v", err)
			}
			config := string(configRaw)
			for _, transport := range []string{"udp", "tix_tcp"} {
				if got := strings.Count(config, "transport: "+transport+"\n"); got != 2 {
					t.Fatalf("transport %s count = %d, want local+peer; config:\n%s", transport, got, config)
				}
			}
			for _, want := range append([]string{
				"datapath: " + tc.datapath,
				"crypto_placement: " + tc.crypto,
				"kernel_transport:\n    mode: require_kernel",
				"  - prefix: 10.64.1.0/25\n    next_hop: ix-b\n    endpoint: b-udp",
				"  - prefix: 10.64.1.128/25\n    next_hop: ix-b\n    endpoint: b-tix-tcp",
			}, tc.configWant...) {
				if !strings.Contains(config, want) {
					t.Fatalf("config missing %q:\n%s", want, config)
				}
			}
			envRaw, err := os.ReadFile(filepath.Join(workdir, "daemon-env.txt"))
			if err != nil {
				t.Fatalf("read daemon-env.txt: %v", err)
			}
			for _, want := range tc.envWant {
				if !strings.Contains(string(envRaw), want) {
					t.Fatalf("daemon environment missing %q:\n%s", want, envRaw)
				}
			}
			contractRaw, err := os.ReadFile(filepath.Join(workdir, "pinned-mixed-routes.txt"))
			if err != nil {
				t.Fatalf("read pinned mixed route contract: %v", err)
			}
			for _, want := range []string{
				"udp.a_prefix=10.64.0.0/25",
				"udp.b_prefix=10.64.1.0/25",
				"udp.a_host=10.64.0.2",
				"udp.b_host=10.64.1.2",
				"udp.iperf_port=25201",
				"tix_tcp.a_prefix=10.64.0.128/25",
				"tix_tcp.b_prefix=10.64.1.128/25",
				"tix_tcp.a_host=10.64.0.130",
				"tix_tcp.b_host=10.64.1.130",
				"tix_tcp.iperf_port=25203",
			} {
				if !strings.Contains(string(contractRaw), want+"\n") {
					t.Fatalf("pinned mixed route contract missing %q:\n%s", want, contractRaw)
				}
			}
		})
	}
}

func TestCrossHostRunnerPinnedMixedThroughputGate(t *testing.T) {
	bash := requireGNUBash4(t)
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	root := t.TempDir()
	fast := `{"end":{"sum_sent":{"bits_per_second":2500000000},"sum_received":{"bits_per_second":2400000000}}}`
	slow := `{"end":{"sum_sent":{"bits_per_second":2500000000},"sum_received":{"bits_per_second":140000}}}`
	if err := os.WriteFile(filepath.Join(root, "fast.json"), []byte(fast), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "slow.json"), []byte(slow), 0o644); err != nil {
		t.Fatal(err)
	}
	runner, err := filepath.Abs("linux-cross-host-soak-runner.sh")
	if err != nil {
		t.Fatal(err)
	}
	code := `
set -Eeuo pipefail
source "$RUNNER"
node_a=local
remote_a="$FIXTURES"
workdir="$RESULTS"
mkdir -p "$workdir"
assert_iperf_min_gbps a fast.json fast-carrier 1
if assert_iperf_min_gbps a slow.json slow-carrier 1; then
  echo 'slow carrier unexpectedly passed' >&2
  exit 1
fi
grep -Fq '"status": "pass"' "$workdir/mixed-throughput-gates.jsonl"
grep -Fq '"status": "fail"' "$workdir/mixed-throughput-gates.jsonl"
`
	cmd := exec.Command(bash, "-c", code)
	cmd.Dir = "."
	cmd.Env = append(os.Environ(),
		"TRUSTIX_CROSS_HOST_DRY_RUN_CONFIG=1",
		"RUNNER="+runner,
		"FIXTURES="+root,
		"RESULTS="+filepath.Join(root, "results"),
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("pinned mixed throughput gate failed: %v\n%s", err, output)
	}
}

func TestCrossHostConcurrentSoakScopesInheritedEndpointTransports(t *testing.T) {
	bash := requireGNUBash4(t)
	root := t.TempDir()
	runner := filepath.Join(root, "runner.sh")
	verifier := filepath.Join(root, "verifier.py")
	workdir := filepath.Join(root, "concurrent")
	if err := os.WriteFile(runner, []byte(`#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "${TRUSTIX_CROSS_HOST_ENDPOINT_TRANSPORTS-unset}" >"${TRUSTIX_CROSS_HOST_WORKDIR}/observed-endpoint-transports.txt"
`), 0o755); err != nil {
		t.Fatalf("write runner: %v", err)
	}
	if err := os.WriteFile(verifier, []byte("#!/usr/bin/env python3\n"), 0o755); err != nil {
		t.Fatalf("write verifier: %v", err)
	}
	cmd := exec.Command(bash, "linux-cross-host-concurrent-soak.sh")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(),
		"TRUSTIX_CROSS_HOST_CONCURRENT_WORKDIR="+workdir,
		"TRUSTIX_CROSS_HOST_CONCURRENT_RUNNER="+runner,
		"TRUSTIX_CROSS_HOST_CONCURRENT_VERIFIER="+verifier,
		"TRUSTIX_CROSS_HOST_CONCURRENT_VERIFY=0",
		"TRUSTIX_CROSS_HOST_CONCURRENT_CASES=userspace-udp-secure userspace-mixed-secure",
		"TRUSTIX_CROSS_HOST_ENDPOINT_TRANSPORTS=udp,tcp",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("concurrent inherited endpoint scope run failed: %v\n%s", err, out)
	}
	regular, err := os.ReadFile(filepath.Join(workdir, "userspace-udp-secure", "observed-endpoint-transports.txt"))
	if err != nil {
		t.Fatalf("read regular observed endpoint transports: %v", err)
	}
	if got := strings.TrimSpace(string(regular)); got != "unset" {
		t.Fatalf("regular case inherited endpoint transports = %q, want unset", got)
	}
	mixed, err := os.ReadFile(filepath.Join(workdir, "userspace-mixed-secure", "observed-endpoint-transports.txt"))
	if err != nil {
		t.Fatalf("read mixed observed endpoint transports: %v", err)
	}
	if got := strings.TrimSpace(string(mixed)); got != "udp,tcp" {
		t.Fatalf("mixed case endpoint transports = %q, want udp,tcp", got)
	}
}

func TestPVECurrentUserspaceRefreshScriptKeepsPVEWorkspaceScoped(t *testing.T) {
	payload, err := os.ReadFile("pve-current-userspace-refresh.sh")
	if err != nil {
		t.Fatalf("read pve-current-userspace-refresh.sh: %v", err)
	}
	script := string(payload)
	mustContain := []string{
		`workspace="${TRUSTIX_PVE_WORKSPACE:-/root/trustix-pve-work}"`,
		`--refresh-gaps`,
		`--next-refresh-gap`,
		`--quarantine-loose-root-artifacts`,
		`host_health_interval="${TRUSTIX_PVE_HOST_HEALTH_INTERVAL:-0}"`,
		`TRUSTIX_PVE_HOST_HEALTH_INTERVAL`,
		`detect_refresh_gap_transports()`,
		`production-transport-audit.py`,
		`hygiene_mode="--check"`,
		`hygiene_mode="--quarantine"`,
		`pve-workspace-hygiene.sh" --workspace "$workspace" "$hygiene_mode"`,
		`host-health.log`,
		`sample_host_health()`,
		`[[ "\$host_health_interval" == "0" ]] && return 0`,
		`if [[ "\$host_health_interval" != "0" ]]; then`,
		`"${workspace}/results/current-${commit_short}-userspace-${label}-production-${stamp}"`,
		`"${scratch}/scripts/start-current-${commit_short}-userspace-${label}-production-${stamp}.sh"`,
		`"${scratch}/pids/current-${commit_short}-userspace-${label}-production-${stamp}.pid"`,
		`TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_KEEP_REMOTE=0`,
		`TRUSTIX_CROSS_HOST_KEEP_REMOTE=0`,
	}
	for _, want := range mustContain {
		if !strings.Contains(script, want) {
			t.Fatalf("pve-current-userspace-refresh.sh missing %q", want)
		}
	}
	forbidden := []string{
		`/root/current-`,
		`mktemp -d /root`,
	}
	for _, bad := range forbidden {
		if strings.Contains(script, bad) {
			t.Fatalf("pve-current-userspace-refresh.sh contains unsafe root fragment %q", bad)
		}
	}
}

func TestPVECurrentRunStatusScriptIsReadOnlyAndScoped(t *testing.T) {
	payload, err := os.ReadFile("pve-current-run-status.sh")
	if err != nil {
		t.Fatalf("read pve-current-run-status.sh: %v", err)
	}
	script := string(payload)
	for _, want := range []string{
		`workspace="${TRUSTIX_PVE_WORKSPACE:-/root/trustix-pve-work}"`,
		`--latest-production`,
		`latest_pattern()`,
		`pve-workspace-hygiene.sh" --workspace "$workspace" --check`,
		`"${workspace}/results/"*`,
		`root top trustix-like entries`,
		`== progress ==`,
		`cases_total=`,
		`summary_rows=`,
		`active_case=`,
		`== host health ==`,
		`latest_sample=`,
		`latest_kernel_warnings_tail`,
		`TRUSTIX_PVE_STATUS_CHECK_NODES`,
		`--check-nodes`,
		`print_node_status()`,
		`ssh -n "${node_ssh_opts[@]}"`,
		`status=ready_to_review_or_promote`,
		`status=interrupted_or_stale`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("pve-current-run-status.sh missing %q", want)
		}
	}
	for _, bad := range []string{
		`rm -`,
		`mv `,
		`mkdir `,
		`mktemp`,
		`> /root`,
		`/root/current-`,
	} {
		if strings.Contains(script, bad) {
			t.Fatalf("pve-current-run-status.sh contains mutating or unsafe fragment %q", bad)
		}
	}
}

func TestPVECurrentRunStatusSelectsLatestProductionRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pve-current-run-status.sh functional test expects Linux-style paths")
	}
	bash := requireGNUBash4(t)
	root := t.TempDir()
	workspace := filepath.Join(root, "trustix-pve-work")
	oldUserspace := filepath.Join(workspace, "results", "current-old-userspace-udp-production-20260708-000000")
	newProduction := filepath.Join(workspace, "results", "owdeb-new-production-20260708-010000")
	createStatusRun := func(path string, ts time.Time) {
		t.Helper()
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("mkdir run root: %v", err)
		}
		if err := os.WriteFile(filepath.Join(path, "run.meta"), []byte("exit_code=0\n"), 0o644); err != nil {
			t.Fatalf("write run meta: %v", err)
		}
		if err := os.WriteFile(filepath.Join(path, "evidence.tsv"), []byte("# evidence\nrow\n"), 0o644); err != nil {
			t.Fatalf("write evidence: %v", err)
		}
		if err := os.Chtimes(path, ts, ts); err != nil {
			t.Fatalf("chtimes run root: %v", err)
		}
	}
	base := time.Unix(1_800_000_000, 0)
	createStatusRun(oldUserspace, base)
	createStatusRun(newProduction, base.Add(time.Hour))

	productionCmd := exec.Command(bash, "pve-current-run-status.sh", "--workspace", workspace, "--latest-production", "--tail", "0")
	productionOut, err := productionCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("latest production status failed: %v\n%s", err, productionOut)
	}
	if !strings.Contains(string(productionOut), "run_root="+newProduction) {
		t.Fatalf("latest production did not select newest production run:\n%s", productionOut)
	}

	userspaceCmd := exec.Command(bash, "pve-current-run-status.sh", "--workspace", workspace, "--latest-userspace", "--tail", "0")
	userspaceOut, err := userspaceCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("latest userspace status failed: %v\n%s", err, userspaceOut)
	}
	if !strings.Contains(string(userspaceOut), "run_root="+oldUserspace) {
		t.Fatalf("latest userspace did not stay scoped to userspace runs:\n%s", userspaceOut)
	}
}

func TestPVECurrentRunStatusDetectsStalePID(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pve-current-run-status.sh functional test expects Linux-style paths")
	}
	bash := requireGNUBash4(t)
	root := t.TempDir()
	workspace := filepath.Join(root, "trustix-pve-work")
	runName := "current-test-userspace-udp-production-20260708-000000"
	runRoot := filepath.Join(workspace, "results", runName)
	pidDir := filepath.Join(workspace, "_scratch", "pids")
	if err := os.MkdirAll(runRoot, 0o755); err != nil {
		t.Fatalf("mkdir run root: %v", err)
	}
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatalf("mkdir pid dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runRoot, "run.meta"), []byte("started_at=2026-07-08T00:00:00+08:00\n"), 0o644); err != nil {
		t.Fatalf("write run meta: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, runName+".pid"), []byte("999999999\n"), 0o644); err != nil {
		t.Fatalf("write pid file: %v", err)
	}

	cmd := exec.Command(bash, "pve-current-run-status.sh", "--workspace", workspace, "--run-root", runRoot, "--tail", "0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run status failed: %v\n%s", err, out)
	}
	for _, want := range []string{
		"pid_status=stale",
		"status=interrupted_or_stale",
	} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("stale pid status output missing %q:\n%s", want, out)
		}
	}
}

func TestPVEPromoteRunEvidenceScriptIsScopedAndDryRunByDefault(t *testing.T) {
	payload, err := os.ReadFile("pve-promote-run-evidence.sh")
	if err != nil {
		t.Fatalf("read pve-promote-run-evidence.sh: %v", err)
	}
	script := string(payload)
	for _, want := range []string{
		`workspace="${TRUSTIX_PVE_WORKSPACE:-/root/trustix-pve-work}"`,
		`promote-production-evidence.py`,
		`--latest-production`,
		`latest_pattern()`,
		`args+=(--dry-run)`,
		`"${workspace}/results/"*`,
		`refusing --write with dirty production evidence TSVs`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("pve-promote-run-evidence.sh missing %q", want)
		}
	}
	for _, bad := range []string{
		`/root/current-`,
		`mktemp -d /root`,
		`rm -`,
		`mv `,
	} {
		if strings.Contains(script, bad) {
			t.Fatalf("pve-promote-run-evidence.sh contains unsafe fragment %q", bad)
		}
	}
}

func TestPVECurrentUserspaceRefreshRejectsNextRefreshGapWhenCurrent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pve-current-userspace-refresh.sh dry-run expects Linux-style paths")
	}
	bash := requireGNUBash4(t)
	requirePython3(t)
	root := t.TempDir()
	workspace := filepath.Join(root, "trustix-pve-work")
	runRoot := filepath.Join(workspace, "results", "next-refresh-gap-dry-run")

	cmd := exec.Command(
		bash,
		"pve-current-userspace-refresh.sh",
		"--workspace", workspace,
		"--run-root", runRoot,
		"--next-refresh-gap",
		"--dry-run",
		"--skip-hygiene-check",
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("next-refresh-gap unexpectedly succeeded with no gaps:\n%s", out)
	}
	if !strings.Contains(string(out), "no cross-host userspace current refresh gaps detected") {
		t.Fatalf("next-refresh-gap failure did not explain that evidence is current:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(runRoot, "userspace-defaults.tsv")); !os.IsNotExist(err) {
		t.Fatalf("next-refresh-gap wrote defaults despite having no gaps: %v", err)
	}
}

func TestPVEPromoteRunEvidenceRejectsFailedRunBeforePromotion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pve-promote-run-evidence.sh functional test expects Linux-style paths")
	}
	bash := requireGNUBash4(t)
	root := t.TempDir()
	workspace := filepath.Join(root, "trustix-pve-work")
	runRoot := filepath.Join(workspace, "results", "current-test-userspace-udp-production-20260708-000000")
	if err := os.MkdirAll(runRoot, 0o755); err != nil {
		t.Fatalf("mkdir run root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runRoot, "run.meta"), []byte("exit_code=1\n"), 0o644); err != nil {
		t.Fatalf("write run meta: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runRoot, "evidence.tsv"), []byte("# evidence\nuserspace\tudp\n"), 0o644); err != nil {
		t.Fatalf("write evidence: %v", err)
	}

	cmd := exec.Command(bash, "pve-promote-run-evidence.sh", "--workspace", workspace, "--run-root", runRoot)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("promote unexpectedly accepted failed run:\n%s", out)
	}
	if !strings.Contains(string(out), "run exit_code must be 0 before promotion") {
		t.Fatalf("promote failure did not mention run exit code:\n%s", out)
	}
}

func TestPVECurrentUserspaceRefreshRejectsRefreshGapsWhenCurrent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pve-current-userspace-refresh.sh dry-run expects Linux-style paths")
	}
	bash := requireGNUBash4(t)
	requirePython3(t)
	root := t.TempDir()
	workspace := filepath.Join(root, "trustix-pve-work")
	runRoot := filepath.Join(workspace, "results", "refresh-gaps-dry-run")

	cmd := exec.Command(
		bash,
		"pve-current-userspace-refresh.sh",
		"--workspace", workspace,
		"--run-root", runRoot,
		"--refresh-gaps",
		"--dry-run",
		"--skip-hygiene-check",
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("refresh-gap unexpectedly succeeded with no gaps:\n%s", out)
	}
	if !strings.Contains(string(out), "no cross-host userspace current refresh gaps detected") {
		t.Fatalf("refresh-gap failure did not explain that evidence is current:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(runRoot, "userspace-defaults.tsv")); !os.IsNotExist(err) {
		t.Fatalf("refresh-gap wrote defaults despite having no gaps: %v", err)
	}
}

func TestPVEWorkspaceHygieneQuarantinesOnlyLooseArtifacts(t *testing.T) {
	bash := requireGNUBash4(t)
	root := t.TempDir()
	workspace := filepath.Join(root, "trustix-pve-work")
	for _, dir := range []string{
		workspace,
		filepath.Join(root, "trustix-run-leftover"),
		filepath.Join(root, "current-604d67d-src"),
		filepath.Join(root, "go"),
		filepath.Join(root, ".ssh"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "current-aee1046.tar"), []byte("tar"), 0o644); err != nil {
		t.Fatalf("write loose tar: %v", err)
	}

	check := exec.Command(bash, "pve-workspace-hygiene.sh", "--root", root, "--workspace", workspace, "--check")
	out, err := check.CombinedOutput()
	if err == nil {
		t.Fatalf("check unexpectedly passed with loose artifacts:\n%s", out)
	}
	for _, want := range []string{"trustix-run-leftover", "current-604d67d-src", "current-aee1046.tar"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("check output missing %s:\n%s", want, out)
		}
	}

	cmd := exec.Command(bash, "pve-workspace-hygiene.sh", "--root", root, "--workspace", workspace, "--quarantine")
	cmd.Env = append(os.Environ(), "TRUSTIX_PVE_WORKSPACE_HYGIENE_STAMP=teststamp")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("quarantine failed: %v\n%s", err, out)
	}

	archive := filepath.Join(workspace, "_scratch", "root-loose-teststamp")
	for _, want := range []string{"trustix-run-leftover", "current-604d67d-src", "current-aee1046.tar"} {
		if _, err := os.Stat(filepath.Join(archive, want)); err != nil {
			t.Fatalf("expected quarantined %s: %v", want, err)
		}
	}
	for _, keep := range []string{"trustix-pve-work", "go", ".ssh"} {
		if _, err := os.Stat(filepath.Join(root, keep)); err != nil {
			t.Fatalf("expected retained %s: %v", keep, err)
		}
	}
}
