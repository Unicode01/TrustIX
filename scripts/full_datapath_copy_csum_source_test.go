package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFullDatapathTXPayloadCopyChecksumHasFallbackAndCounters(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "kernel", "trustix_datapath", "trustix_datapath.c"))
	if err != nil {
		t.Fatalf("read trustix_datapath.c: %v", err)
	}
	source := strings.ReplaceAll(string(payload), "\r\n", "\n")
	for _, want := range []string{
		"static bool trustix_datapath_tx_plaintext_payload_copy_csum = true;",
		"csum_partial_copy_nocheck(",
		"skb_copy_and_csum_bits(src, src_offset, dst, len)",
		"csum_block_add(header_sum, payload_sum, tcp_header_len)",
		"chunked_sum = csum_block_add(",
		"memcmp(copied_payload, payload, payload_len)",
		"trustix_datapath_tx_plaintext_payload_copy_csum_attempts",
		"trustix_datapath_tx_plaintext_payload_copy_csum_hits",
		"trustix_datapath_tx_plaintext_payload_copy_csum_fallbacks",
		"trustix_datapath_tx_plaintext_payload_copy_csum_errors",
		"if (!payload_sum_ready)\n\t\treturn trustix_datapath_rx_worker_l4_checksum(",
		"trustix_datapath_selftest_tx_plaintext_payload_copy_csum()",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("trustix_datapath.c missing TX copy-checksum guard %q", want)
		}
	}
	if got := strings.Count(source, "trustix_datapath_tx_plaintext_tcp_checksum("); got < 5 {
		t.Fatalf("TX copy-checksum helper has %d declarations/calls, want at least 5", got)
	}
	if got := strings.Count(source, "trustix_datapath_tx_plaintext_copy_payload("); got < 5 {
		t.Fatalf("TX payload-copy helper has %d declarations/calls, want at least 5", got)
	}
}
