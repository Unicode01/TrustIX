package scripts

import (
	"os"
	"strings"
	"testing"
)

func TestCrossHostSoakRunnerWaitsForTIXTCPFullKmodReadiness(t *testing.T) {
	payload, err := os.ReadFile("linux-cross-host-soak-runner.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, want := range []string{
		"case_requires_tix_tcp_full_kmod_readiness()",
		"case_has_endpoint_transport tix_tcp",
		"wait_for_tix_tcp_full_kmod_readiness()",
		"case_endpoint_name_for_transport b tix_tcp",
		"case_endpoint_name_for_transport a tix_tcp",
		`status.get("provider") != "kernel_datapath_full_plaintext"`,
		`for key in ("available", "fast_path", "inner_gso", "port_sharding")`,
		`if len(outbound) < pool_size or len(inbound) < pool_size`,
		`"tix_tcp_kernel_datapath_ready_negotiated"`,
		`"tix_tcp_inner_gso_negotiated"`,
		`"tix_tcp_port_sharding_negotiated"`,
		`tx_plaintext_inner_flow_hash_sets`,
		`tx_plaintext_tix_tcp_shard_sequence_fallbacks`,
		`stable_polls=$((stable_polls + 1))`,
		`[[ "$stable_polls" -ge 2 ]]`,
		`collect_transport_snapshot startup-ready`,
		`TIX-TCP full-kmod sessions did not become stably ready before connectivity traffic`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("linux-cross-host-soak-runner.sh missing readiness contract %q", want)
		}
	}

	wait := strings.LastIndex(text, "  wait_for_tix_tcp_full_kmod_readiness ||")
	connectivity := strings.LastIndex(text, "  run_connectivity_checks")
	if wait < 0 || connectivity < 0 || wait > connectivity {
		t.Fatalf("TIX-TCP readiness gate must run before connectivity traffic: wait=%d connectivity=%d", wait, connectivity)
	}
}
