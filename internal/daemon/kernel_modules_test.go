package daemon

import "testing"

func TestTrustIXDatapathModuleParametersAutoEnableRXWorker(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersFullPlaintextEnablesTX(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 tx_plaintext=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersInlineStolenEnablesDependencies(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_ALLOW_EXPERIMENTAL_TCP", "1")

	got := TrustIXDatapathModuleParameters("rx_worker_slots=64")
	want := "rx_worker_slots=64 enable_features=128 rx_worker_inject=1 rx_worker_steal_skb=1 rx_worker_inline_stolen=1 rx_worker_tcp=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersInlineReceiveEnablesDependencies(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE_RECEIVE", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 rx_worker_steal_skb=1 rx_worker_inline_stolen=1 rx_worker_inline_receive=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersXmitRequiresUnsafeOptIn(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersXmitEnablesLANTransmitWithUnsafeOptIn(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_ALLOW_UNSAFE_XMIT", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 rx_worker_xmit=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersDirectXmitRequiresUnsafeOptIn(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_DIRECT_XMIT", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersDirectXmitEnabledWithUnsafeOptIn(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_DIRECT_XMIT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_ALLOW_UNSAFE_XMIT", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 rx_worker_xmit=1 rx_worker_direct_xmit=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersInlineXmitRequiresUnsafeOptIn(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE_XMIT", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersInlineXmitEnablesLANTransmitWithUnsafeOptIn(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE_XMIT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_ALLOW_UNSAFE_XMIT", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 rx_worker_xmit=1 rx_worker_inline_xmit=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersInlineXmitCanDisableCopyChecksum(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE_XMIT_NO_COPY_CSUM", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 rx_worker_inline_xmit_copy_csum=0"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersCanDisableRXWorkerHotStats(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_HOT_STATS", "0")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 rx_worker_hot_stats=0"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersInlinePairCoalesce(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE_PAIR_COALESCE", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE_PAIR_FLUSH_JIFFIES", "2")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE_COALESCE_MAX_FRAMES", "4")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 rx_worker_inline_pair_coalesce=1 rx_worker_inline_pair_flush_jiffies=2 rx_worker_inline_coalesce_max_frames=4"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersInlinePairHoldSKB(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE_PAIR_COALESCE", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE_PAIR_HOLD_SKB", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 rx_worker_inline_pair_coalesce=1 rx_worker_inline_pair_hold_skb=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersStealXmitIsExplicit(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_ALLOW_UNSAFE_XMIT", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_ALLOW_STEAL_XMIT", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 rx_worker_xmit=1 rx_worker_steal_xmit=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersStealTCPIsExplicit(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_STEAL_TCP", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 rx_worker_steal_tcp=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersStreamTCPEnablesDependencies(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_STREAM_TCP", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 rx_worker_tcp=1 rx_worker_stream_tcp=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersStreamBatchQueueIsExplicit(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_STREAM_TCP", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_STREAM_BATCH_QUEUE", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 rx_worker_tcp=1 rx_worker_stream_tcp=1 rx_worker_stream_batch_queue=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersRXWorkerTrustTCPChecksumThreshold(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT_TRUST_TCP_CHECKSUM_MIN_LEN", "1024")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 rx_worker_xmit_trust_tcp_checksum_min_len=1024"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersRXWorkerTrustTCPChecksumAckOnly(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT_TRUST_TCP_CHECKSUM_ACK_ONLY", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 rx_worker_xmit_trust_tcp_checksum_ack_only=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersRXWorkerTCPPartialChecksum(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT_TCP_PARTIAL_CSUM", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 rx_worker_xmit_tcp_partial_csum=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersRXWorkerHashTXQueue(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT_HASH_TX_QUEUE", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 rx_worker_xmit_hash_tx_queue=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersRXWorkerXmitMore(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT_MORE", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 rx_worker_xmit_more=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersRXWorkerDstMACCache(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT_DST_MAC_CACHE", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 rx_worker_xmit_dst_mac_cache=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersRXWorkerDstMACPerCPUCache(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT_DST_MAC_PCPU_CACHE", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 rx_worker_xmit_dst_mac_pcpu_cache=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersRXWorkerDstMACSeqCache(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_XMIT_DST_MAC_SEQ_CACHE", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 rx_worker_xmit_dst_mac_seq_cache=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersRXWorkerQueueSKB(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_QUEUE_SKB", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 rx_worker_queue_skb=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersRXWorkerStreamCoalesceGSO(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_STREAM_COALESCE_GSO", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 rx_worker_stream_coalesce_gso=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersRXWorkerStreamCoalesceSoftwareSegment(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_STREAM_COALESCE_SOFTWARE_SEGMENT", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 rx_worker_stream_coalesce_software_segment=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersRXWorkerStreamCoalesceFullChecksum(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_STREAM_COALESCE_FULL_CSUM", "1")

	got := TrustIXDatapathModuleParameters("")
	want := "enable_features=128 rx_worker_inject=1 rx_worker_stream_coalesce_partial_csum=0"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathModuleParametersKeepExplicitValues(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_INLINE", "1")
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_RX_WORKER_TCP", "1")

	got := TrustIXDatapathModuleParameters("enable_features=0 rx_worker_inject=0 rx_worker_steal_skb=0 rx_worker_inline_stolen=0 rx_worker_tcp=0")
	want := "enable_features=0 rx_worker_inject=0 rx_worker_steal_skb=0 rx_worker_inline_stolen=0 rx_worker_tcp=0"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathHelpersModuleParametersAutoEnableRouteTCPXmitWorker(t *testing.T) {
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC", "1")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_XMIT", "1")

	got := TrustIXDatapathHelpersModuleParameters("tixt_tx_plain_skip_sequence=1")
	want := "tixt_tx_plain_skip_sequence=1 route_tcp_xmit_worker=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathHelpersModuleParametersRequireRouteTCPXmitAck(t *testing.T) {
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC", "1")

	got := TrustIXDatapathHelpersModuleParameters("")
	if got != "" {
		t.Fatalf("parameters = %q, want empty without crash-risk ack", got)
	}
}

func TestTrustIXDatapathHelpersModuleParametersAutoEnableTIXTSingleCoalesce(t *testing.T) {
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_TC_RX_SINGLE_COALESCE_GSO", "1")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_TC_RX_SINGLE_COALESCE_SKIP_TCP_CSUM", "1")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_TC_RX_SINGLE_COALESCE_NETIF_RX", "1")

	got := TrustIXDatapathHelpersModuleParameters("route_tcp_xmit_worker=0")
	want := "route_tcp_xmit_worker=0 tixt_rx_single_coalesce_gso=1 tixt_rx_single_coalesce_skip_tcp_csum=1 tixt_rx_single_coalesce_netif_rx=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathHelpersModuleParametersAutoEnableTIXTStreamOrderedList(t *testing.T) {
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_TC_RX_STREAM_ORDERED_LIST", "1")

	got := TrustIXDatapathHelpersModuleParameters("tixt_rx_stream_parse=1")
	want := "tixt_rx_stream_parse=1 tixt_rx_stream_ordered_list=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathHelpersModuleParametersStealIsSeparateOptIn(t *testing.T) {
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC", "1")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_XMIT", "1")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_STEAL", "1")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_XMIT_STEAL", "1")

	got := TrustIXDatapathHelpersModuleParameters("")
	want := "route_tcp_xmit_worker=1 route_tcp_xmit_worker_steal=1"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}

func TestTrustIXDatapathHelpersModuleParametersKeepExplicitValues(t *testing.T) {
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_KFUNC", "1")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_XMIT", "1")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_TC_TX_ROUTE_TCP_XMIT_STEAL", "1")
	t.Setenv("TRUSTIX_EXPERIMENTAL_TCP_ALLOW_CRASH_RISK_ROUTE_TCP_XMIT_STEAL", "1")

	got := TrustIXDatapathHelpersModuleParameters("route_tcp_xmit_worker=0 route_tcp_xmit_worker_steal=0")
	want := "route_tcp_xmit_worker=0 route_tcp_xmit_worker_steal=0"
	if got != want {
		t.Fatalf("parameters = %q, want %q", got, want)
	}
}
