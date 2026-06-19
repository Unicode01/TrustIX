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

func readProductionTransportDefaults(t *testing.T) string {
	t.Helper()
	rows := loadProductionTransportDefaults(t)
	var packed []string
	for _, row := range rows {
		packed = append(packed, strings.Join([]string{
			row.Transport,
			row.Encryption,
			row.Profile,
			row.Datapath,
			row.CryptoPlacement,
			row.ValidationScope,
			row.GateFamily,
			row.MinGbps,
			row.MinSeconds,
		}, ":"))
	}
	return strings.Join(packed, "\n")
}

type productionTransportDefault struct {
	Transport       string
	Encryption      string
	Profile         string
	Datapath        string
	CryptoPlacement string
	ValidationScope string
	GateFamily      string
	MinGbps         string
	MinSeconds      string
}

type productionTransportEvidence struct {
	GateFamily      string
	Transport       string
	Encryption      string
	Profile         string
	Datapath        string
	CryptoPlacement string
	ValidationScope string
	OSMatrix        string
	KernelMatrix    string
	Result          string
	MinGbps         string
	MinSeconds      string
	Artifact        string
	Note            string
}

func loadProductionTransportDefaults(t *testing.T) []productionTransportDefault {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join(".", "production-transport-defaults.tsv"))
	if err != nil {
		t.Fatalf("read production-transport-defaults.tsv: %v", err)
	}
	var rows []productionTransportDefault
	for _, line := range strings.Split(string(payload), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 9 {
			t.Fatalf("invalid production default row %q", line)
		}
		rows = append(rows, productionTransportDefault{
			Transport:       fields[0],
			Encryption:      fields[1],
			Profile:         fields[2],
			Datapath:        fields[3],
			CryptoPlacement: fields[4],
			ValidationScope: fields[5],
			GateFamily:      fields[6],
			MinGbps:         fields[7],
			MinSeconds:      fields[8],
		})
	}
	return rows
}

func loadProductionTransportEvidence(t *testing.T) []productionTransportEvidence {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join(".", "production-transport-evidence.tsv"))
	if err != nil {
		t.Fatalf("read production-transport-evidence.tsv: %v", err)
	}
	var rows []productionTransportEvidence
	for _, line := range strings.Split(string(payload), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 14 {
			t.Fatalf("invalid production evidence row %q", line)
		}
		rows = append(rows, productionTransportEvidence{
			GateFamily:      fields[0],
			Transport:       fields[1],
			Encryption:      fields[2],
			Profile:         fields[3],
			Datapath:        fields[4],
			CryptoPlacement: fields[5],
			ValidationScope: fields[6],
			OSMatrix:        fields[7],
			KernelMatrix:    fields[8],
			Result:          fields[9],
			MinGbps:         fields[10],
			MinSeconds:      fields[11],
			Artifact:        fields[12],
			Note:            strings.Join(fields[13:], "\t"),
		})
	}
	return rows
}

func productionDefaultEvidenceKey(row productionTransportDefault) string {
	return strings.Join([]string{
		row.Transport,
		row.Encryption,
		row.Profile,
		row.Datapath,
		row.CryptoPlacement,
		row.ValidationScope,
		row.GateFamily,
	}, ":")
}

func productionEvidenceKey(row productionTransportEvidence) string {
	return strings.Join([]string{
		row.Transport,
		row.Encryption,
		row.Profile,
		row.Datapath,
		row.CryptoPlacement,
		row.ValidationScope,
		row.GateFamily,
	}, ":")
}

func TestProductionMatrixDefaultsAvoidUnsafeExperimentalTCPSecureFastPath(t *testing.T) {
	for _, name := range []string{"linux-production-transport-matrix.sh"} {
		t.Run(name, func(t *testing.T) {
			payload, err := os.ReadFile(filepath.Join(".", name))
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			text := string(payload)
			if strings.Contains(text, "experimental_tcp:secure:stable:kernel_module:userspace") {
				t.Fatalf("%s production defaults still select unsafe secure userspace-crypto experimental_tcp kernel fast path", name)
			}
			defaults := readProductionTransportDefaults(t)
			for _, wantCase := range []string{
				"udp:secure:stable:userspace:userspace:cross_host:userspace:1.5:900",
				"udp:plaintext:performance:kernel_module:userspace:cross_host:full_kmod:3:900",
				"udp:plaintext:performance:kernel_module:userspace:cross_host:owdeb_full_kmod:3:900",
				"tcp:plaintext:stable:userspace:userspace:cross_host:userspace:1:900",
				"kernel_udp:plaintext:performance:tc_xdp:userspace:cross_host:tc_direct:3:900",
				"kernel_udp:secure:performance:tc_xdp:kernel:cross_host:secure_kudp:1.5:900",
				"experimental_tcp:plaintext:performance:kernel_module:userspace:cross_host:route_gso:2.5:900",
				"experimental_tcp:secure:stable:userspace:userspace:single_host:userspace:0:30",
				"experimental_tcp:plaintext:stable:userspace:userspace:single_host:userspace:0:30",
			} {
				if !strings.Contains(defaults, wantCase) {
					t.Fatalf("production defaults missing %q", wantCase)
				}
			}
			for _, unwanted := range []string{
				"kernel_udp:secure:stable:tc_xdp:userspace",
			} {
				if strings.Contains(defaults, unwanted) {
					t.Fatalf("production defaults still include slow/unselected combo %q", unwanted)
				}
			}
		})
	}
}

func TestProductionTransportMatrixDefaults(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join(".", "linux-production-transport-matrix.sh"))
	if err != nil {
		t.Fatalf("read linux-production-transport-matrix.sh: %v", err)
	}
	text := string(payload)
	for _, want := range []string{
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_PERF_FAST:-1",
		"defaults_file=\"${TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_DEFAULTS:-${repo_root}/scripts/production-transport-defaults.tsv}\"",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_CASE_TIMEOUT",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_FULL_DATAPATH_IOCTL_SELFTEST:-0",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_FULL_DATAPATH_VERIFY_SAFE_DEFAULTS:-0",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_SINGLE_HOST_FULL_DATAPATH:-0",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_SINGLE_HOST_ROUTE_GSO:-0",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_FULL_DATAPATH_MIN_GBPS:-3",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_ROUTE_GSO_MIN_GBPS:-2.5",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_AF_XDP_TX_BACKPRESSURE_WAIT:-50ms",
		"TRUSTIX_E2E_AF_XDP_TX_BACKPRESSURE_WAIT",
		"key = $1 SUBSEP $2 SUBSEP $3 SUBSEP $4 SUBSEP $5",
		"if (seen[key]++) next",
		"print $1, $2, $3, $4, $5, $8, $9",
		"case_iperf3_seconds=\"${default_seconds:-$iperf3_seconds}\"",
		"export TRUSTIX_E2E_IPERF3_SECONDS=\"$case_iperf3_seconds\"",
		"rx_worker_xmit=1",
		"rx_worker_single_coalesce=1",
		"rx_worker_single_coalesce_max_frames=32",
		"tx_plaintext_skip_inner_tcp_checksum=0",
		"production defaults file not found",
		"invalid production defaults row",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("linux-production-transport-matrix.sh production defaults missing %q", want)
		}
	}
	for _, unwanted := range []string{
		"rx_worker_single_coalesce=0",
	} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("linux-production-transport-matrix.sh production defaults still include %q", unwanted)
		}
	}
}

func TestCrossHostProductionDefaultsHavePassingEvidence(t *testing.T) {
	defaults := loadProductionTransportDefaults(t)
	evidenceRows := loadProductionTransportEvidence(t)
	evidenceByKey := map[string][]productionTransportEvidence{}
	seenEvidence := map[string]bool{}
	for _, evidence := range evidenceRows {
		key := productionEvidenceKey(evidence)
		identity := strings.Join([]string{key, evidence.OSMatrix, evidence.KernelMatrix, evidence.Result, evidence.Artifact}, ":")
		if seenEvidence[identity] {
			t.Fatalf("duplicate production evidence row %q", identity)
		}
		seenEvidence[identity] = true
		if evidence.Artifact == "" {
			t.Fatalf("production evidence row lacks artifact: %+v", evidence)
		}
		switch evidence.Result {
		case "pass", "fail", "fail_closed":
		default:
			t.Fatalf("unknown production evidence result %q in %+v", evidence.Result, evidence)
		}
		evidenceMinGbps, err := strconv.ParseFloat(evidence.MinGbps, 64)
		if err != nil || evidenceMinGbps < 0 {
			t.Fatalf("invalid production evidence min_gbps %q in %+v", evidence.MinGbps, evidence)
		}
		evidenceMinSeconds, err := strconv.Atoi(evidence.MinSeconds)
		if err != nil || evidenceMinSeconds <= 0 {
			t.Fatalf("invalid production evidence min_seconds %q in %+v", evidence.MinSeconds, evidence)
		}
		evidenceByKey[key] = append(evidenceByKey[key], evidence)
	}
	for _, row := range defaults {
		if row.ValidationScope != "cross_host" {
			continue
		}
		minGbps, err := strconv.ParseFloat(row.MinGbps, 64)
		if err != nil {
			t.Fatalf("invalid production default min_gbps %q in %+v", row.MinGbps, row)
		}
		minSeconds, err := strconv.Atoi(row.MinSeconds)
		if err != nil {
			t.Fatalf("invalid production default min_seconds %q in %+v", row.MinSeconds, row)
		}
		key := productionDefaultEvidenceKey(row)
		var candidates []string
		found := false
		for _, evidence := range evidenceByKey[key] {
			evidenceGbps, err := strconv.ParseFloat(evidence.MinGbps, 64)
			if err != nil {
				t.Fatalf("invalid production evidence min_gbps %q in %+v", evidence.MinGbps, evidence)
			}
			evidenceSeconds, err := strconv.Atoi(evidence.MinSeconds)
			if err != nil {
				t.Fatalf("invalid production evidence min_seconds %q in %+v", evidence.MinSeconds, evidence)
			}
			candidates = append(candidates, strings.Join([]string{
				evidence.Result,
				evidence.MinGbps,
				evidence.MinSeconds,
				evidence.Artifact,
			}, " "))
			if evidence.Result == "pass" && evidenceGbps >= minGbps && evidenceSeconds >= minSeconds {
				found = true
				break
			}
		}
		if found {
			continue
		}
		t.Fatalf("cross-host production default lacks passing evidence at or above gate %s: %+v; candidates=%v", key, row, candidates)
	}
}

func TestProductionTransportDefaultsCoverProtocolsAndValidationScopes(t *testing.T) {
	defaults := readProductionTransportDefaults(t)
	for _, wantCase := range []string{
		"udp:secure:stable:userspace:userspace:single_host:userspace:0:30",
		"udp:secure:stable:userspace:userspace:cross_host:userspace:1.5:900",
		"udp:plaintext:stable:userspace:userspace:single_host:userspace:0:30",
		"udp:plaintext:performance:kernel_module:userspace:cross_host:owdeb_full_kmod:3:900",
		"tcp:secure:stable:userspace:userspace:single_host:userspace:0:30",
		"tcp:plaintext:stable:userspace:userspace:single_host:userspace:0:30",
		"tcp:plaintext:stable:userspace:userspace:cross_host:userspace:1:900",
		"quic:secure:stable:userspace:userspace:single_host:userspace:0:30",
		"quic:plaintext:stable:userspace:userspace:single_host:userspace:0:30",
		"websocket:secure:stable:userspace:userspace:single_host:userspace:0:30",
		"websocket:plaintext:stable:userspace:userspace:single_host:userspace:0:30",
		"http_connect:secure:stable:userspace:userspace:single_host:userspace:0:30",
		"http_connect:plaintext:stable:userspace:userspace:single_host:userspace:0:30",
		"gre:secure:stable:tc_xdp:userspace:single_host:userspace_tc:0:30",
		"gre:plaintext:performance:tc_xdp:userspace:single_host:userspace_tc:0:30",
		"ipip:secure:stable:tc_xdp:userspace:single_host:userspace_tc:0:30",
		"ipip:plaintext:performance:tc_xdp:userspace:single_host:userspace_tc:0:30",
		"vxlan:secure:stable:tc_xdp:userspace:single_host:userspace_tc:0:30",
		"vxlan:plaintext:performance:tc_xdp:userspace:single_host:userspace_tc:0:30",
		"kernel_udp:plaintext:performance:tc_xdp:userspace:single_host:tc_direct:0:30",
		"kernel_udp:plaintext:performance:tc_xdp:userspace:cross_host:tc_direct:3:900",
		"kernel_udp:secure:performance:tc_xdp:kernel:cross_host:secure_kudp:1.5:900",
		"experimental_tcp:secure:stable:userspace:userspace:single_host:userspace:0:30",
		"experimental_tcp:plaintext:stable:userspace:userspace:single_host:userspace:0:30",
		"experimental_tcp:plaintext:performance:kernel_module:userspace:cross_host:route_gso:2.5:900",
	} {
		if !strings.Contains(defaults, wantCase) {
			t.Fatalf("production defaults missing %q", wantCase)
		}
	}
}

func TestProductionTransportDefaultsAreStructuredAndGateScoped(t *testing.T) {
	rows := loadProductionTransportDefaults(t)
	knownTransport := map[string]bool{
		"udp": true, "tcp": true, "quic": true, "websocket": true,
		"http_connect": true, "gre": true, "ipip": true, "vxlan": true,
		"kernel_udp": true, "experimental_tcp": true,
	}
	knownGate := map[string]bool{
		"userspace": true, "userspace_tc": true, "tc_direct": true,
		"full_kmod": true, "owdeb_full_kmod": true,
		"secure_kudp": true, "route_gso": true,
	}
	crossHostGate := map[string]bool{
		"userspace": true, "userspace_tc": true, "tc_direct": true,
		"full_kmod": true, "owdeb_full_kmod": true,
		"secure_kudp": true, "route_gso": true,
	}
	crossHostOnlyGate := map[string]bool{
		"full_kmod": true, "owdeb_full_kmod": true,
		"secure_kudp": true, "route_gso": true,
	}
	seen := map[string]bool{}
	baseline := map[string]bool{}
	for _, row := range rows {
		key := strings.Join([]string{
			row.Transport, row.Encryption, row.Profile, row.Datapath,
			row.CryptoPlacement, row.ValidationScope, row.GateFamily,
		}, ":")
		if seen[key] {
			t.Fatalf("duplicate production default row key %q", key)
		}
		seen[key] = true
		if !knownTransport[row.Transport] {
			t.Fatalf("unknown production transport %q in %+v", row.Transport, row)
		}
		switch row.Encryption {
		case "secure", "plaintext":
		default:
			t.Fatalf("unknown encryption %q in %+v", row.Encryption, row)
		}
		switch row.Profile {
		case "stable", "performance", "latency":
		default:
			t.Fatalf("unknown profile %q in %+v", row.Profile, row)
		}
		switch row.Datapath {
		case "userspace", "tc_xdp", "kernel_module", "auto":
		default:
			t.Fatalf("unknown datapath %q in %+v", row.Datapath, row)
		}
		switch row.CryptoPlacement {
		case "userspace", "kernel", "auto":
		default:
			t.Fatalf("unknown crypto placement %q in %+v", row.CryptoPlacement, row)
		}
		switch row.ValidationScope {
		case "single_host", "cross_host":
		default:
			t.Fatalf("unknown validation scope %q in %+v", row.ValidationScope, row)
		}
		if !knownGate[row.GateFamily] {
			t.Fatalf("unknown gate family %q in %+v", row.GateFamily, row)
		}
		minGbps, err := strconv.ParseFloat(row.MinGbps, 64)
		if err != nil || minGbps < 0 {
			t.Fatalf("invalid min_gbps %q in %+v", row.MinGbps, row)
		}
		minSeconds, err := strconv.Atoi(row.MinSeconds)
		if err != nil || minSeconds <= 0 {
			t.Fatalf("invalid min_seconds %q in %+v", row.MinSeconds, row)
		}
		if row.ValidationScope == "cross_host" {
			if !crossHostGate[row.GateFamily] {
				t.Fatalf("cross-host production row uses non-production gate %q: %+v", row.GateFamily, row)
			}
			if minGbps <= 0 || minSeconds < 900 {
				t.Fatalf("cross-host production row lacks throughput/soak gate: %+v", row)
			}
		}
		if crossHostOnlyGate[row.GateFamily] && row.ValidationScope != "cross_host" {
			t.Fatalf("production gate %q must be cross_host, got %+v", row.GateFamily, row)
		}
		if row.GateFamily == "userspace" &&
			row.Profile == "stable" &&
			row.Datapath == "userspace" &&
			row.CryptoPlacement == "userspace" {
			baseline[row.Transport+":"+row.Encryption] = true
		}
	}
	for _, transport := range []string{"udp", "tcp", "quic", "websocket", "http_connect", "experimental_tcp"} {
		for _, encryption := range []string{"secure", "plaintext"} {
			key := transport + ":" + encryption
			if !baseline[key] {
				t.Fatalf("missing stable userspace baseline for %s", key)
			}
		}
	}
}

func TestE2ESmokeDefaultsAvoidUnsafeDirectKfuncCrypto(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join(".", "linux-e2e-smoke.sh"))
	if err != nil {
		t.Fatalf("read linux-e2e-smoke.sh: %v", err)
	}
	text := string(payload)
	for _, want := range []string{
		"TRUSTIX_E2E_AF_XDP_TX_BACKPRESSURE_WAIT:-50ms",
		"TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_KFUNC_SEAL:-0",
		"TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_KFUNC_OPEN:-0",
		"TRUSTIX_E2E_AF_XDP_TX_BACKPRESSURE_WAIT must be a Go duration or 0",
		"route_tcp_gso_async_worker_emit_budget=0",
		"route_tcp_gso_async_worker_dequeue_batch=4",
		"route_tcp_gso_async_hash_tx_queue=1",
		"route_tcp_gso_async_worker_min_queue_depth=1",
		"route_tcp_gso_async_worker_schedule_delay_usecs=0",
		"experimental_tcp_route_gso_async_worker_item_budget=64",
		"experimental_tcp_route_gso_async_worker_segment_budget=2048",
		"route_tcp_gso_async_worker_item_budget=${experimental_tcp_route_gso_async_worker_item_budget}",
		"route_tcp_gso_async_worker_segment_budget=${experimental_tcp_route_gso_async_worker_segment_budget}",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("linux-e2e-smoke.sh default missing %q", want)
		}
	}
}

func TestProductionSoakWrapsProductionMatrix(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join(".", "linux-production-soak.sh"))
	if err != nil {
		t.Fatalf("read linux-production-soak.sh: %v", err)
	}
	text := string(payload)
	for _, want := range []string{
		"TRUSTIX_PRODUCTION_SOAK_DURATION_SECONDS:-3600",
		"TRUSTIX_PRODUCTION_SOAK_IPERF3_SECONDS:-120",
		"TRUSTIX_PRODUCTION_SOAK_PERF_FAST:-1",
		"TRUSTIX_PRODUCTION_SOAK_CASE_TIMEOUT:-15m",
		"TRUSTIX_PRODUCTION_TRANSPORT_MATRIX_CASES",
		"linux-production-transport-matrix.sh",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("linux-production-soak.sh missing %q", want)
		}
	}
}

func TestCrossHostProductionGateRequiresFastPathArtifacts(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join(".", "linux-cross-host-production-gate.sh"))
	if err != nil {
		t.Fatalf("read linux-cross-host-production-gate.sh: %v", err)
	}
	text := string(payload)
	for _, want := range []string{
		"gate_min_gbps=\"${TRUSTIX_CROSS_HOST_GATE_MIN_GBPS:-}\"",
		"TRUSTIX_CROSS_HOST_USERSPACE_MIN_GBPS:-${gate_min_gbps:-0}",
		"TRUSTIX_CROSS_HOST_USERSPACE_TC_MIN_GBPS:-${gate_min_gbps:-0}",
		"TRUSTIX_CROSS_HOST_TC_DIRECT_MIN_GBPS:-${gate_min_gbps:-0}",
		"TRUSTIX_CROSS_HOST_FULL_KMOD_MIN_GBPS:-${gate_min_gbps:-3}",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_GBPS:-${gate_min_gbps:-1.5}",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_MIN_GBPS:-${gate_min_gbps:-2.5}",
		"TRUSTIX_CROSS_HOST_GATE_MIN_SECONDS:-900",
		"TRUSTIX_CROSS_HOST_GATE_REQUIRE_BINARY_IDENTITY:-1",
		"TRUSTIX_CROSS_HOST_FULL_KMOD_MIN_SESSIONS:-8",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_SESSIONS:-8",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_CRYPTO_FLOWS:-1",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_DIRECT_ERROR_BUDGET:-64",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_REPLAY_BUDGET:-4096",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_MIN_SESSIONS:-8",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_SESSION_ERROR_BUDGET:-2",
		"TRUSTIX_CROSS_HOST_COMPAT_MIN_SESSIONS:-1",
		"TRUSTIX_CROSS_HOST_USERSPACE_CASES",
		"TRUSTIX_CROSS_HOST_USERSPACE_TC_CASES",
		"TRUSTIX_CROSS_HOST_TC_DIRECT_CASES",
		"TRUSTIX_CROSS_HOST_DD_FULL_KMOD",
		"TRUSTIX_CROSS_HOST_OWDEB_FULL_KMOD",
		"TRUSTIX_CROSS_HOST_DD_SECURE_KUDP",
		"TRUSTIX_CROSS_HOST_OWDEB_SECURE_KUDP",
		"TRUSTIX_CROSS_HOST_DD_ROUTE_GSO",
		"TRUSTIX_CROSS_HOST_OWDEB_ROUTE_GSO",
		"validate_number TRUSTIX_CROSS_HOST_USERSPACE_MIN_GBPS \"$userspace_min_gbps\"",
		"validate_number TRUSTIX_CROSS_HOST_USERSPACE_TC_MIN_GBPS \"$userspace_tc_min_gbps\"",
		"validate_number TRUSTIX_CROSS_HOST_TC_DIRECT_MIN_GBPS \"$tc_direct_min_gbps\"",
		"validate_number TRUSTIX_CROSS_HOST_FULL_KMOD_MIN_GBPS \"$full_kmod_min_gbps\"",
		"validate_number TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_GBPS \"$secure_kudp_min_gbps\"",
		"validate_number TRUSTIX_CROSS_HOST_ROUTE_GSO_MIN_GBPS \"$route_gso_min_gbps\"",
		"validate_number TRUSTIX_CROSS_HOST_SECURE_KUDP_MIN_CRYPTO_FLOWS \"$secure_kudp_min_crypto_flows\"",
		"validate_number TRUSTIX_CROSS_HOST_SECURE_KUDP_DIRECT_ERROR_BUDGET \"$secure_kudp_direct_error_budget\"",
		"validate_number TRUSTIX_CROSS_HOST_SECURE_KUDP_REPLAY_BUDGET \"$secure_kudp_replay_budget\"",
		"validate_number TRUSTIX_CROSS_HOST_ROUTE_GSO_SESSION_ERROR_BUDGET \"$route_gso_session_error_budget\"",
		"validate_number TRUSTIX_CROSS_HOST_COMPAT_MIN_SESSIONS \"$compat_min_sessions\"",
		"--require-binary-identity",
		"run_gate userspace \"$userspace_min_gbps\"",
		"run_gate userspace-tc \"$userspace_tc_min_gbps\"",
		"run_gate tc-direct \"$tc_direct_min_gbps\"",
		"--require-transport-sessions-min \"${compat_min_sessions}\"",
		"--require-datapath-stat kernel_udp.provider=tc_direct",
		"--require-datapath-stat kernel_udp.fast_path=true",
		"--require-datapath-stat kernel_udp.direct_only=true",
		"--require-datapath-any-min kernel_udp.active_flows=1",
		"--require-transport-policy-stat encryption=secure",
		"--require-transport-policy-stat crypto_placement=kernel",
		"--require-transport-policy-stat datapath=tc_xdp",
		"--require-transport-policy-min session_pool_size=\"${full_kmod_min_sessions}\"",
		"--require-transport-policy-min session_pool_size=\"${secure_kudp_min_sessions}\"",
		"--require-transport-policy-min session_pool_size=\"${route_gso_min_sessions}\"",
		"--require-transport-policy-stat session_pool_strategy=flow",
		"--require-transport-policy-stat session_pool_warmup=true",
		"--require-status-min data_path.active_sessions=\"${route_gso_min_sessions}\"",
		"--require-status-max data_path.counters.session_dial_errors=\"${route_gso_session_error_budget}\"",
		"--require-status-max data_path.counters.session_heartbeat_timeouts=0",
		"--require-datapath-stat kernel_udp.provider_stats.kernel_datapath_full_plaintext_provider=1",
		"--require-datapath-stat kernel_udp.kernel_crypto=true",
		"--require-datapath-stat kernel_udp.requested_crypto=kernel",
		"--require-datapath-stat kernel_udp.effective_crypto=kernel",
		"--require-datapath-stat kernel_udp.provider_stats.kernel_crypto_flow_map_ready=1",
		"--require-datapath-min kernel_udp.provider_stats.kernel_crypto_flow_map_entries=\"${secure_kudp_min_crypto_flows}\"",
		"--require-datapath-min kernel_udp.provider_stats.kernel_crypto_flow_map_updates=\"${secure_kudp_min_crypto_flows}\"",
		"--require-datapath-stat kernel_udp.provider_stats.kernel_crypto_direct_slot_provider_ready=1",
		"--require-datapath-stat kernel_udp.provider_stats.kernel_crypto_direct_kfunc_fastpath_ready=1",
		"--require-datapath-stat kernel_udp.provider_stats.kernel_crypto_tc_direct_ready=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_tx_direct_only_enabled=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_tx_secure_direct_attached=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_attached=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_tx_secure_direct_kfunc_seal_enabled=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_tx_secure_direct_route_tcp_gso_kfunc=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_kfunc_open_enabled=1",
		"--require-datapath-max kernel_udp.provider_stats.kernel_crypto_frame_seal_errors=0",
		"--require-datapath-max kernel_udp.provider_stats.kernel_crypto_frame_open_errors=0",
		"--require-datapath-max kernel_udp.provider_stats.tc_kernel_udp_tx_secure_direct_encrypt_errors=0",
		"--require-datapath-max kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_decrypt_errors=\"${secure_kudp_direct_error_budget}\"",
		"--require-datapath-max kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_replay_drops=\"${secure_kudp_replay_budget}\"",
		"--require-datapath-max kernel_udp.provider_stats.tc_kernel_udp_rx_secure_direct_drops=\"${secure_kudp_replay_budget}\"",
		"--require-module-param-min trustix_crypto.kfunc_simd_fastpath=1",
		"--require-module-param-min trustix_crypto.kfunc_simd_irq_fpu_fastpath=1",
		"--require-module-param-any-min trustix_crypto.direct_kfunc_seal_calls=1",
		"--require-module-param-any-min trustix_crypto.direct_kfunc_open_calls=1",
		"--require-module-param-max trustix_crypto.direct_kfunc_errors=\"${secure_kudp_direct_error_budget}\"",
		"--require-module-param-min trustix_datapath_helpers.route_tcp_gso_async_secure_seal_batch=1",
		"--require-module-param-any-min trustix_datapath_helpers.route_tcp_gso_async_xmit_packets=1",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_flow_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_plan_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_mtu_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_queue_bytes_full=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_alloc_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_clone_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_segment_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_prepare_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_txq_stopped_drops=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_xmit_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_direct_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_cross_item_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_cross_item_tail_stitch_errors=0",
		"--require-datapath-min kernel_rx_stage.rx_worker_injected=1",
		"--require-datapath-min counters.session_dials=\"${full_kmod_min_sessions}\"",
		"--require-datapath-max counters.session_dial_errors=0",
		"--require-module-param-min trustix_datapath.session_records=\"${full_kmod_min_sessions}\"",
		"--require-module-param-min trustix_datapath.session_wire_records=\"${full_kmod_min_sessions}\"",
		"--require-module-param-min trustix_datapath.rx_worker_single_coalesce_max_frames=32",
		"--require-module-param-any-min trustix_datapath.tx_plaintext_outer_gso_segments=1",
		"--require-module-param-any-min trustix_datapath.tx_plaintext_direct_xmit_dst_mac_cache_hits=1",
		"--require-module-param-any-min trustix_datapath.rx_worker_gso_xmit_segments=1",
		"--require-module-param-max trustix_datapath.rx_worker_alloc_errors=0",
		"--require-module-param-max trustix_datapath.rx_worker_deliver_errors=0",
		"--require-module-param-max trustix_datapath.rx_worker_gso_xmit_errors=0",
		"--require-module-param-max trustix_datapath.rx_worker_xmit_ret_errors=0",
		"--require-module-param-max trustix_datapath.rx_worker_xmit_peer_forward_errors=0",
		"--require-module-param-max trustix_datapath.tx_plaintext_no_sessions=0",
		"--require-module-param-max trustix_datapath.tx_plaintext_no_wires=0",
		"--require-module-param-max trustix_datapath.tx_plaintext_stale_wires=0",
		"--require-module-param-max trustix_datapath.tx_plaintext_xmit_errors=0",
		"--require-module-param-max trustix_datapath.tx_plaintext_queue_drops=0",
		"--require-datapath-stat kernel_udp.provider_stats.tc_experimental_tcp_tx_direct_route_tcp_gso_async_kfunc=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_experimental_tcp_tx_direct_route_tcp_gso_async_kfunc_requested=1",
		"--require-datapath-stat kernel_udp.provider_stats.tc_kernel_udp_tx_direct_experimental_tcp_only=1",
		"--require-module-param-min trustix_datapath_helpers.route_tcp_gso_async_hash_tx_queue=1",
		"--require-module-param-any-min trustix_datapath_helpers.route_tcp_gso_async_stream_outer_gso_frames=1",
		"--require-module-param-any-min trustix_datapath_helpers.route_tcp_gso_async_xmit_packets=1",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_queue_full=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_xmit_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_outer_gso_errors=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_outer_gso_blocked=0",
		"--require-module-param-max trustix_datapath_helpers.route_tcp_gso_async_stream_outer_gso_verify_errors=0",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("linux-cross-host-production-gate.sh missing %q", want)
		}
	}
	if got := strings.Count(text, "--require-module-param-any-min trustix_datapath_helpers.route_tcp_gso_async_stream_outer_gso_frames=1"); got != 1 {
		t.Fatalf("linux-cross-host-production-gate.sh should require outer-GSO frames only for route-GSO, got %d occurrences", got)
	}
	for _, unwanted := range []string{
		"TRUSTIX_CROSS_HOST_DD_FULL_KMOD_EXPERIMENTAL_TCP",
		"dd-fullkmod-experimental-tcp",
	} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("linux-cross-host-production-gate.sh still promotes diagnostic full-kmod experimental_tcp case %q", unwanted)
		}
	}
}

func TestCrossHostTransportMatrixWrapsProductionDefaults(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join(".", "linux-cross-host-transport-matrix.sh"))
	if err != nil {
		t.Fatalf("read linux-cross-host-transport-matrix.sh: %v", err)
	}
	text := string(payload)
	for _, want := range []string{
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DEFAULTS:-${repo_root}/scripts/production-transport-defaults.tsv",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_RUNNER:-${repo_root}/scripts/linux-cross-host-soak-runner.sh",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFIER:-${repo_root}/scripts/linux-cross-host-soak-verify.py",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_PRODUCTION_GATE:-${repo_root}/scripts/linux-cross-host-production-gate.sh",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SCOPE:-all",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_KEEP_REMOTE:-0",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SELECTED_GATE:-1",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DRY_RUN:-0",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SECONDS",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_MIN_GBPS",
		"validation_scope",
		"gate_family",
		"\"runner_case\":\"%s\"",
		"runner_case_name",
		"gate_family_class",
		"matrix_case_name",
		"full_kmod|dd_full_kmod) printf 'dd-fullkmod\\n'",
		"owdeb_full_kmod) printf 'owdeb-fullkmod\\n'",
		"secure_kudp|dd_secure_kudp) printf 'secure-kudp\\n'",
		"owdeb_secure_kudp) printf 'owdeb-secure-kudp\\n'",
		"route_gso|dd_route_gso) printf 'dd-routegso\\n'",
		"owdeb_route_gso) printf 'owdeb-routegso\\n'",
		"owdeb_*) printf '%s-owdeb\\n' \"$base\"",
		"userspace) append_case_token userspace_cases",
		"userspace_tc) append_case_token userspace_tc_cases",
		"tc_direct) append_case_token tc_direct_cases",
		"full_kmod|dd_full_kmod|owdeb_full_kmod) printf 'full_kmod\\n'",
		"secure_kudp|dd_secure_kudp|owdeb_secure_kudp) printf 'secure_kudp\\n'",
		"route_gso|dd_route_gso|owdeb_route_gso) printf 'route_gso\\n'",
		"TRUSTIX_CROSS_HOST_CASE=\"$runner_case\"",
		"TRUSTIX_CROSS_HOST_TRANSPORT=\"$token\"",
		"TRUSTIX_CROSS_HOST_PROFILE=\"$profile\"",
		"TRUSTIX_CROSS_HOST_TRANSPORT_DATAPATH=\"$datapath\"",
		"TRUSTIX_CROSS_HOST_CRYPTO_PLACEMENT=\"$placement\"",
		"TRUSTIX_CROSS_HOST_KEEP_REMOTE=\"$keep_remote\"",
		"record_result \"dry_run\"",
		"--require-transport-policy-stat\" \"encryption=${encryption}",
		"--require-transport-policy-stat\" \"profile=${profile}",
		"--require-transport-policy-stat\" \"datapath=${datapath}",
		"--require-transport-policy-stat\" \"crypto_placement=${placement}",
		"if [[ \"$validation_scope\" == \"cross_host\" ]]; then",
		"TRUSTIX_CROSS_HOST_USERSPACE_CASES=${userspace_cases}",
		"TRUSTIX_CROSS_HOST_USERSPACE_TC_CASES=${userspace_tc_cases}",
		"TRUSTIX_CROSS_HOST_TC_DIRECT_CASES=${tc_direct_cases}",
		"TRUSTIX_CROSS_HOST_FULL_KMOD_CASES=${full_kmod_cases}",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_CASES=${secure_kudp_cases}",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_CASES=${route_gso_cases}",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("linux-cross-host-transport-matrix.sh missing %q", want)
		}
	}
}

func TestCrossHostTransportMatrixCanRepresentCompatibilityCrossHostGates(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	if err := exec.Command(bash, "-c", "x=(); x+=(a); [[ ${x[0]} == a ]]").Run(); err != nil {
		t.Skipf("bash array syntax not available from %s", bash)
	}
	workdir := t.TempDir()
	defaults := filepath.Join(workdir, "defaults.tsv")
	summary := filepath.Join(workdir, "summary.jsonl")
	if err := os.WriteFile(defaults, []byte(strings.Join([]string{
		"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tmin_gbps\tmin_seconds\tnote",
		"udp\tsecure\tstable\tuserspace\tuserspace\tcross_host\tuserspace\t0\t900\texplicit UDP userspace cross-host validation input",
		"gre\tplaintext\tperformance\ttc_xdp\tuserspace\tcross_host\tuserspace_tc\t0\t900\texplicit GRE userspace-TC cross-host validation input",
		"kernel_udp\tplaintext\tperformance\ttc_xdp\tuserspace\tcross_host\ttc_direct\t0\t900\texplicit kernel UDP TC-direct cross-host validation input",
		"",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("write defaults: %v", err)
	}
	cmd := exec.Command(bash, "linux-cross-host-transport-matrix.sh")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DEFAULTS="+defaults,
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_WORKDIR="+workdir,
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SCOPE=cross_host",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DRY_RUN=1",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFY=0",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SELECTED_GATE=0",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SUMMARY="+summary,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dry-run explicit compatibility matrix failed: %v\n%s", err, output)
	}
	payload, err := os.ReadFile(summary)
	if err != nil {
		t.Fatalf("read dry-run summary: %v", err)
	}
	type row struct {
		RunnerCase string `json:"runner_case"`
		GateFamily string `json:"gate_family"`
	}
	got := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(payload)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var decoded row
		if err := json.Unmarshal([]byte(line), &decoded); err != nil {
			t.Fatalf("decode dry-run summary row %q: %v", line, err)
		}
		got[decoded.RunnerCase+":"+decoded.GateFamily] = true
	}
	for _, want := range []string{
		"userspace-udp-secure:userspace",
		"tc-gre-plaintext:userspace_tc",
		"tc-udp-plaintext:tc_direct",
	} {
		if !got[want] {
			t.Fatalf("dry-run summary missing %s:\n%s", want, payload)
		}
	}
}

func TestCrossHostTransportMatrixDryRunIncludesOpenWrtDebianFullKmod(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	if err := exec.Command(bash, "-c", "x=(); x+=(a); [[ ${x[0]} == a ]]").Run(); err != nil {
		t.Skipf("bash array syntax not available from %s", bash)
	}
	workdir := t.TempDir()
	summary := filepath.Join(workdir, "summary.jsonl")
	cmd := exec.Command(bash, "linux-cross-host-transport-matrix.sh")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_WORKDIR="+workdir,
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SCOPE=cross_host",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DRY_RUN=1",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFY=0",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SELECTED_GATE=0",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SUMMARY="+summary,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dry-run cross-host transport matrix failed: %v\n%s", err, output)
	}
	payload, err := os.ReadFile(summary)
	if err != nil {
		t.Fatalf("read dry-run summary: %v", err)
	}
	var sawDebianFullKmod, sawOpenWrtDebianFullKmod bool
	for _, line := range strings.Split(strings.TrimSpace(string(payload)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var row struct {
			Case       string `json:"case"`
			RunnerCase string `json:"runner_case"`
			GateFamily string `json:"gate_family"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("decode dry-run summary row %q: %v", line, err)
		}
		if row.RunnerCase == "dd-fullkmod" && row.GateFamily == "full_kmod" {
			sawDebianFullKmod = true
		}
		if row.RunnerCase == "owdeb-fullkmod" &&
			row.GateFamily == "owdeb_full_kmod" &&
			strings.HasSuffix(row.Case, "-owdeb") {
			sawOpenWrtDebianFullKmod = true
		}
		if row.RunnerCase == "owdeb-secure-kudp" || row.GateFamily == "owdeb_secure_kudp" {
			t.Fatalf("OpenWrt-Debian secure-kudp was promoted without a passing OpenWrt route-GSO/kfunc gate:\n%s", payload)
		}
		if strings.Contains(row.Case, "route-gso") && strings.HasSuffix(row.Case, "-owdeb") {
			t.Fatalf("OpenWrt-Debian route-GSO was promoted without a passing OpenWrt route-GSO/kfunc gate:\n%s", payload)
		}
	}
	if !sawDebianFullKmod || !sawOpenWrtDebianFullKmod {
		t.Fatalf("dry-run summary missing full-kmod target cases: debian=%t owdeb=%t\n%s", sawDebianFullKmod, sawOpenWrtDebianFullKmod, payload)
	}
}

func TestCrossHostTransportMatrixCanRepresentOpenWrtRouteGSOWhenExplicitlyValidated(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	if err := exec.Command(bash, "-c", "x=(); x+=(a); [[ ${x[0]} == a ]]").Run(); err != nil {
		t.Skipf("bash array syntax not available from %s", bash)
	}
	workdir := t.TempDir()
	defaults := filepath.Join(workdir, "defaults.tsv")
	summary := filepath.Join(workdir, "summary.jsonl")
	if err := os.WriteFile(defaults, []byte(strings.Join([]string{
		"# transport\tencryption\tprofile\tdatapath\tcrypto_placement\tvalidation_scope\tgate_family\tmin_gbps\tmin_seconds\tnote",
		"experimental_tcp\tplaintext\tperformance\tkernel_module\tuserspace\tcross_host\towdeb_route_gso\t2.5\t900\texplicit OpenWrt-Debian route-GSO validation input",
		"",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("write defaults: %v", err)
	}
	cmd := exec.Command(bash, "linux-cross-host-transport-matrix.sh")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(),
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DEFAULTS="+defaults,
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_WORKDIR="+workdir,
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SCOPE=cross_host",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_DRY_RUN=1",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_VERIFY=0",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SELECTED_GATE=0",
		"TRUSTIX_CROSS_HOST_TRANSPORT_MATRIX_SUMMARY="+summary,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dry-run explicit owdeb route-GSO matrix failed: %v\n%s", err, output)
	}
	payload, err := os.ReadFile(summary)
	if err != nil {
		t.Fatalf("read dry-run summary: %v", err)
	}
	var row struct {
		Case       string `json:"case"`
		RunnerCase string `json:"runner_case"`
		GateFamily string `json:"gate_family"`
	}
	lines := strings.Fields(strings.TrimSpace(string(payload)))
	if len(lines) != 1 {
		t.Fatalf("expected one summary row, got %d:\n%s", len(lines), payload)
	}
	if err := json.Unmarshal([]byte(lines[0]), &row); err != nil {
		t.Fatalf("decode summary row: %v\n%s", err, payload)
	}
	if row.RunnerCase != "owdeb-routegso" ||
		row.GateFamily != "owdeb_route_gso" ||
		!strings.HasSuffix(row.Case, "-owdeb") {
		t.Fatalf("unexpected owdeb route-GSO dry-run row: %+v\n%s", row, payload)
	}
}

func TestProductionDefaultsDoNotPromoteOpenWrtRouteGSOWithoutRuntimeEvidence(t *testing.T) {
	rows := loadProductionTransportDefaults(t)
	for _, row := range rows {
		switch row.GateFamily {
		case "owdeb_secure_kudp", "owdeb_route_gso":
			t.Fatalf("production defaults include %s before OpenWrt route-GSO/kfunc runtime validation: %+v", row.GateFamily, row)
		}
	}
}

func TestCrossHostSoakRunnerCoversKernelFastPathsAndCleanup(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join(".", "linux-cross-host-soak-runner.sh"))
	if err != nil {
		t.Fatalf("read linux-cross-host-soak-runner.sh: %v", err)
	}
	text := string(payload)
	for _, want := range []string{
		"TRUSTIX_CROSS_HOST_CASE:-dd-fullkmod",
		"case_transport_override=\"${TRUSTIX_CROSS_HOST_TRANSPORT:-}\"",
		"case_encryption_override=\"${TRUSTIX_CROSS_HOST_ENCRYPTION:-}\"",
		"case_profile_override=\"${TRUSTIX_CROSS_HOST_PROFILE:-}\"",
		"case_datapath_override=\"${TRUSTIX_CROSS_HOST_TRANSPORT_DATAPATH:-}\"",
		"case_crypto_placement_override=\"${TRUSTIX_CROSS_HOST_CRYPTO_PLACEMENT:-}\"",
		"data_a_port=\"${TRUSTIX_CROSS_HOST_DATA_A_PORT:-}\"",
		"data_b_port=\"${TRUSTIX_CROSS_HOST_DATA_B_PORT:-}\"",
		"default_data_port",
		"node_value \"$node\" 13000 13001",
		"TRUSTIX_CROSS_HOST_IPERF_SECONDS:-900",
		"health_port=\"${TRUSTIX_CROSS_HOST_HEALTH_PORT:-}\"",
		"TRUSTIX_CROSS_HOST_IPERF_MODE:-forward",
		"TRUSTIX_CROSS_HOST_IPERF_DIRECTIONS:-both",
		"daemon_ready_sleep=\"${TRUSTIX_CROSS_HOST_READY_SLEEP:-1}\"",
		"iperf_parallel=\"${TRUSTIX_CROSS_HOST_IPERF_PARALLEL:-8}\"",
		"transport_snapshot_delay=\"${TRUSTIX_CROSS_HOST_TRANSPORT_SNAPSHOT_DELAY:-5}\"",
		"session_pool_size=\"${TRUSTIX_CROSS_HOST_SESSION_POOL_SIZE:-$iperf_parallel}\"",
		"session_pool:",
		"size: ${session_pool_size}",
		"strategy: ${session_pool_strategy}",
		"warmup: ${session_pool_warmup}",
		"heartbeat:",
		"mode: ${session_pool_heartbeat_mode}",
		"TRUSTIX_CROSS_HOST_IPERF_DIRECTIONS must be both, a2b, or b2a",
		"TRUSTIX_CROSS_HOST_HEALTH_PORT must differ from TRUSTIX_CROSS_HOST_IPERF_PORT",
		"case \"$iperf_mode\" in bidir|forward|reverse)",
		"TRUSTIX_CROSS_HOST_SESSION_POOL_SIZE must be >= 1",
		"TRUSTIX_CROSS_HOST_TRANSPORT_SNAPSHOT_DELAY must be >= 0",
		"TRUSTIX_CROSS_HOST_SESSION_POOL_STRATEGY must be flow, five_tuple, 5tuple, packet, or round_robin",
		"ssh -n \"${ssh_opts[@]}\" \"$dest\" \"bash -c $(remote_quote \"$script\")\"",
		"iperf_artifact_suffix",
		"dd-fullkmod|owdeb-fullkmod|full-kmod|udp-plaintext-full-kmod|udp_plaintext_full_kmod",
		"dd-secure-kudp|owdeb-secure-kudp|secure-kudp|kernel-udp-secure-kernel|kernel_udp_secure_kernel|udp-secure-kernel|udp_secure_kernel",
		"dd-routegso|owdeb-routegso|route-gso|experimental-tcp-route-gso|experimental_tcp_route_gso",
		"ow-tc-direct|tc-direct|experimental-tcp-tc-direct|experimental_tcp_tc_direct",
		"userspace-*-secure|userspace-*-plaintext|crosshost-userspace-*-secure|crosshost-userspace-*-plaintext",
		"tc-*-secure|tc-*-plaintext|crosshost-tc-*-secure|crosshost-tc-*-plaintext",
		"supported_case_transport",
		"case_transport_profile",
		"case_fast_path",
		"case_encryption",
		"case_crypto_placement",
		"case_transport_datapath",
		"case_uses_tc_direct_fast_path",
		"case_tc_requested_but_falls_back_to_userspace",
		"has no safe TC direct fast path with this configuration; using userspace datapath",
		"secure_kudp|tc_direct) printf 'tc_xdp\\n'",
		"tc_direct) printf 'tc_xdp\\n'",
		"capability_profile: full_plaintext",
		"capability_profile: performance",
		"capability_profile: disabled",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_CRYPTO_PATH:-embedded",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_CRYPTO_PATH_A:-$secure_kudp_crypto_path",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_CRYPTO_PATH_B:-$secure_kudp_crypto_path",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_HELPERS_PATH",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_HELPERS_PATH_A:-$secure_kudp_helpers_path",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_HELPERS_PATH_B:-$secure_kudp_helpers_path",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_CRYPTO_PARAMETERS",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_HELPER_PARAMETERS",
		"infer_helpers_path_from_module_path",
		"embedded://trustix_crypto.ko|embedded://trustix_datapath.ko",
		"route authorize -out \"$workdir/certs\" -domain \"$domain_id\" -ix \"$ix_a\" -prefix \"$lan_a_cidr\"",
		"route authorize -out \"$workdir/certs\" -domain \"$domain_id\" -ix \"$ix_b\" -prefix \"$lan_b_cidr\"",
		"copy_to_node a \"$workdir/certs/.\"",
		"copy_to_node b \"$workdir/certs/.\"",
		"TRUSTIX_CROSS_HOST_FULL_KMOD_DATAPATH_PARAMETERS",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_HELPER_PARAMETERS",
		"TRUSTIX_CROSS_HOST_FULL_KMOD_DATAPATH_PATH:-embedded",
		"TRUSTIX_CROSS_HOST_ROUTE_GSO_HELPERS_PATH:-embedded",
		"TRUSTIX_CROSS_HOST_ENDPOINT_TRANSPORT",
		"case_endpoint_transport",
		"TRUSTIX_CROSS_HOST_ENDPOINT_TRANSPORT is unsupported",
		"TRUSTIX_CROSS_HOST_TRANSPORT is unsupported",
		"TRUSTIX_CROSS_HOST_ENCRYPTION/case encryption must be secure or plaintext",
		"TRUSTIX_CROSS_HOST_TRANSPORT_DATAPATH/case datapath must be userspace, tc_xdp, kernel_module, or auto",
		"endpoint_security_yaml",
		"link_tls: required",
		"crypto_key_source: tls_exporter",
		"tls_identity:",
		"${local_ix}-transport.crt",
		"ssh_no_stdin()",
		"ssh -n \"${ssh_opts[@]}\" \"$dest\" \"$@\"",
		"ssh_no_stdin \"$dest\" \"mkdir -p $(remote_quote \"$dest_path\")\"",
		"ssh_no_stdin \"$dest\" \"test -d $(remote_quote \"$src\")\"",
		"rx_worker_experimental_tcp=1",
		"TRUSTIX_KERNEL_DATAPATH_RX_WORKER_ALLOW_EXPERIMENTAL_TCP=%s",
		"TRUSTIX_EXPERIMENTAL_TCP_ALLOW_MIXED_TCP_FAST_PATH=1",
		"full-kmod with experimental_tcp endpoint is diagnostic only",
		"TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER_EXPERIMENTS=1",
		"TRUSTIX_KERNEL_DATAPATH_ALLOW_UNSAFE_RX_WORKER_EXPERIMENTS=1",
		"TRUSTIX_CROSS_HOST_OPENWRT_RX_SINGLE_COALESCE",
		"TRUSTIX_KERNEL_DATAPATH_OPENWRT_RX_SINGLE_COALESCE=%s",
		"daemon_env_exports",
		"env ${env_exports} $(remote_quote \"$trustixd\") -config",
		"yaml_single_quote",
		"endpoint_security_yaml \"    \" \"$encryption\"",
		"crypto_placement: ${crypto_placement}",
		"TRUSTIX_KERNEL_UDP_TC_SECURE_DIRECT_ONLY=1",
		"TRUSTIX_KERNEL_CRYPTO_ALLOW_SIMD_KFUNC_FASTPATH=1",
		"TRUSTIX_KERNEL_CRYPTO_ALLOW_SIMD_IRQ_FPU_KFUNC_FASTPATH=1",
		"TRUSTIX_KERNEL_CRYPTO_KFUNC_FASTPATH_STATS=1",
		"TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_KFUNC_SEAL=1",
		"TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_KFUNC_OPEN=1",
		"TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_TRUST_INNER_CHECKSUMS=1",
		"TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT=1",
		"TRUSTIX_KERNEL_UDP_XDP_RX_SECURE_DIRECT=1",
		"TRUSTIX_KERNEL_UDP_XDP_RX_DIRECT_TRUST_INNER_CHECKSUMS=1",
		"TRUSTIX_CROSS_HOST_SECURE_KUDP_ROUTE_GSO:-0",
		"printf 'TRUSTIX_KERNEL_UDP_TC_TX_SECURE_ROUTE_GSO_KFUNC=%s\\n' \"$route_gso\"",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_GSO_ASYNC_KFUNC=1",
		"TRUSTIX_EXPERIMENTAL_TCP_ROUTE_GSO=0",
		"TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC=0",
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY=1",
		"unload_on_exit: true",
		"-cleanup-dataplane",
		"rmmod trustix_datapath",
		"rmmod trustix_datapath_helpers",
		"printf 'pass\\n' >\"$workdir/${case_name}.result\"",
		"collect_binary_identity a",
		"version_output=\\$(",
		"collect_kernel_logs a",
		"collect_all",
		"collect_module_parameters a",
		"${dir}/module-parameters.txt",
		"stop_daemon a",
		"collect_one status status",
		"collect_one datapath datapath",
		"collect_one transports transports",
		"collect_transport_snapshot",
		"run_iperf_client_with_snapshot",
		"run_connectivity_checks",
		"run_tcp_health_checks",
		"run_tcp_health_direction",
		"collect_one bpf bpf maps",
		"${dir}/binary-identity.json",
		"ip_cmd=\\$(command -v ip)",
		"nohup \\\"\\$ip_cmd\\\" netns exec",
		"setsid \\\"\\$ip_cmd\\\" netns exec",
		"timeout ${iperf_timeout}s \\\"\\$ip_cmd\\\" netns exec",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("linux-cross-host-soak-runner.sh missing %q", want)
		}
	}
	for _, unwanted := range []string{
		"xargs -r",
		"${prefix}-status.json",
		"${prefix}-datapath.json",
		"${prefix}-binary-identity.json",
		"find \"$workdir/a\" \"$workdir/b\" -type f -name 'iperf3-*.json' -exec cp",
		"trustixd\") -version 2>/dev/null | awk -F= '/^version=/{print $2; exit}'",
		"ip netns exec",
		"ip netns del",
		"ip netns pids",
		"nohup ip netns exec",
		"setsid ip netns exec",
		"\"$dest\" bash -s <<<\"$script\"",
		"sh -c \"$iperf_cmd\"",
	} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("linux-cross-host-soak-runner.sh contains non-portable %q", unwanted)
		}
	}
}
