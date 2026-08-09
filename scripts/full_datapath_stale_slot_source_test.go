package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFullDatapathRetiredCryptoSlotsAreStale(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "kernel", "trustix_datapath", "trustix_datapath.c"))
	if err != nil {
		t.Fatalf("read trustix_datapath.c: %v", err)
	}
	source := string(payload)
	if got := strings.Count(source, "if (ret == -ENOENT)\n\t\tret = -ESTALE;"); got < 3 {
		t.Fatalf("retired-slot normalization count = %d, want at least 3", got)
	}
	if got := strings.Count(source, "if (plan->secure && ret != -ESTALE)\n\t\ttrustix_datapath_secure_tx_errors++;"); got != 3 {
		t.Fatalf("secure TX stale exclusion count = %d, want 3", got)
	}
	for _, want := range []string{
		"wire = trustix_datapath_session_wire_for_tuple_locked(\n\t\tframe->flow_id, outer->src_ipv4, outer->dst_ipv4,\n\t\touter->src_port, outer->dst_port, outer->protocol, &reverse);\n\tif (!wire)\n\t\treturn -ESTALE;",
		"session = trustix_datapath_session_for_flow_id_locked(wire->value[0]);\n\tif (!session)\n\t\treturn -ESTALE;",
		"if (!crypto ||\n\t    (crypto->flags & TRUSTIX_DATAPATH_SESSION_CRYPTO_FLAGS_READY) !=\n\t\t    TRUSTIX_DATAPATH_SESSION_CRYPTO_FLAGS_READY)\n\t\treturn -ESTALE;",
		"if (ret == -ESTALE) {\n\t\ttrustix_datapath_tx_plaintext_stale_wires++;\n\t\treturn;\n\t}",
		"if (ret == -ESTALE)\n\t\ttrustix_datapath_secure_rx_stale++;\n\telse\n\t\ttrustix_datapath_secure_rx_errors++;",
		"if (ret == -ESTALE)\n\t\t\treturn ret;\n\t}\n\tif (plan && plan->outer_protocol == IPPROTO_UDP)",
		"if (!ret)\n\t\treturn 0;\n\tif (ret == -ESTALE)\n\t\treturn ret;\n\ttrustix_datapath_tx_plaintext_outer_gso_fallbacks++;",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("trustix_datapath.c missing stale-slot contract %q", want)
		}
	}
}
