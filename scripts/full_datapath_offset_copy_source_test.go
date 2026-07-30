package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFullDatapathRXStreamOffsetCopyGuardsAndFallback(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "kernel", "trustix_datapath", "trustix_datapath.c"))
	if err != nil {
		t.Fatalf("read trustix_datapath.c: %v", err)
	}
	source := strings.ReplaceAll(string(payload), "\r\n", "\n")
	for _, want := range []string{
		"trustix_datapath_rx_worker_stream_offset_copy = true",
		"trustix_datapath_parse_tixt_skb_header(",
		"trustix_datapath_selftest_tixt_stream_skb(",
		"return skb_copy_bits(pending->source_skb,",
		"pending[frames].source_skb = skb",
		"pending[frames].source_offset = inner_offset",
		"offset_copy = consumer_validates_frames && skb_is_nonlinear(skb)",
		"if (!offset_copy &&\n\t    !pskb_may_pull(skb, (__u32)network_offset + total_len))",
		"trustix_datapath_rx_worker_stream_offset_copy_errors",
		"trustix_datapath_reset_percpu_ullong(\n\t\t&trustix_datapath_rx_worker_stream_offset_copy_attempts)",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("trustix_datapath.c missing RX stream offset-copy guard %q", want)
		}
	}

	pushStart := strings.Index(source, "trustix_datapath_rx_worker_push_stream(\n")
	if pushStart < 0 {
		t.Fatal("trustix_datapath.c missing RX stream push function")
	}
	pushEnd := strings.Index(source[pushStart:], "static int\ntrustix_datapath_rx_worker_inject_stolen_skb")
	if pushEnd < 0 {
		t.Fatal("trustix_datapath.c missing RX stream push function boundary")
	}
	pushSource := source[pushStart : pushStart+pushEnd]
	offsetDecision := strings.Index(pushSource, "offset_copy = consumer_validates_frames")
	fullPull := strings.Index(pushSource, "pskb_may_pull(skb, (__u32)network_offset + total_len)")
	if offsetDecision < 0 || fullPull < 0 || offsetDecision >= fullPull {
		t.Fatal("RX stream offset-copy decision must precede the guarded full-skb pull")
	}
}
