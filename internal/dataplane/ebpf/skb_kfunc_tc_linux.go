//go:build linux

package ebpf

import (
	"bytes"
	"embed"
	"fmt"
	"runtime/debug"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

//go:embed bpf/skb_kfunc_tc_bpfel.o
var skbKfuncTCFS embed.FS

func loadSKBClearTXOffloadKfuncCall() (asm.Instruction, error) {
	return loadSKBKfuncCall("trustix_skb_clear_tx_offload_tc")
}

func loadSKBFixInnerTCPCsumKfuncCall() (asm.Instruction, error) {
	return loadSKBKfuncCall("trustix_skb_fix_inner_tcp_csum_tc")
}

func loadSKBKernelUDPRXDecapL2KfuncCall() (asm.Instruction, error) {
	return loadSKBKfuncCall("trustix_skb_kudp_rx_decap_l2_tc")
}

func loadSKBKernelUDPRXDecapL2DevKfuncCall() (asm.Instruction, error) {
	return loadSKBKfuncCall("trustix_skb_kudp_rx_decap_l2_dev_tc")
}

func loadSKBKernelUDPRXParseDecapL2KfuncCall() (asm.Instruction, error) {
	return loadSKBKfuncCall("trustix_skb_kudp_rx_parse_decap_l2_tc")
}

func loadSKBTIXTFixOuterTCPCsumKfuncCall() (asm.Instruction, error) {
	return loadSKBKfuncCall("trustix_skb_tixt_fix_outer_tcp_csum_tc")
}

func loadSKBTIXTTXFinalizeTCPHeaderKfuncCall() (asm.Instruction, error) {
	return loadSKBKfuncCall("trustix_skb_tixt_tx_finalize_tcp_header_tc")
}

func loadSKBTIXTTXSetTCPPartialCSUMKfuncCall() (asm.Instruction, error) {
	return loadSKBKfuncCall("trustix_skb_tixt_tx_set_tcp_partial_csum_tc")
}

func loadSKBTIXTTXPushTCPHeaderKfuncCall() (asm.Instruction, error) {
	return loadSKBKfuncCall("trustix_skb_tixt_tx_push_tcp_header_tc")
}

func loadSKBTIXTTXPushFlowTCPHeaderKfuncCall() (asm.Instruction, error) {
	return loadSKBKfuncCall("trustix_skb_tixt_tx_push_flow_tcp_header_tc")
}

func loadSKBTIXTTXFinalizeFlowTCPHeaderKfuncCall() (asm.Instruction, error) {
	return loadSKBKfuncCall("trustix_skb_tixt_tx_finalize_flow_tcp_header_tc")
}

func loadSKBTIXTTXPushRouteTCPHeaderKfuncCall() (asm.Instruction, error) {
	return loadSKBKfuncCall("trustix_skb_tixt_tx_push_route_tcp_header_tc")
}

func loadSKBTIXTTXSegmentRouteTCPGSOKfuncCall() (asm.Instruction, error) {
	return loadSKBKfuncCall("trustix_skb_tixt_tx_segment_route_tcp_gso_tc")
}

func loadSKBTIXTTXSegmentSecureRouteTCPGSOKfuncCall() (asm.Instruction, error) {
	return loadSKBKfuncCall("trustix_skb_tixt_tx_segment_secure_route_tcp_gso_tc")
}

func loadSKBTIXTTXRouteTCPKfuncCall() (asm.Instruction, error) {
	return loadSKBKfuncCall("trustix_skb_tixt_tx_route_tcp_tc")
}

func loadSKBTIXTTXRouteTCPXmitKfuncCall() (asm.Instruction, error) {
	return loadSKBKfuncCall("trustix_skb_tixt_tx_route_tcp_xmit_tc")
}

func loadSKBKernelUDPTXStoreL2L3L4KfuncCall() (asm.Instruction, error) {
	return loadSKBKfuncCall("trustix_skb_kudp_tx_store_l2_l3_l4_tc")
}

func loadSKBKernelUDPTXBuildUDPHeaderKfuncCall() (asm.Instruction, error) {
	return loadSKBKfuncCall("trustix_skb_kudp_tx_build_udp_header_tc")
}

func loadSKBKernelUDPTXFinalizeUDPHeaderKfuncCall() (asm.Instruction, error) {
	return loadSKBKfuncCall("trustix_skb_kudp_tx_finalize_udp_header_tc")
}

func loadSKBKernelUDPTXPushUDPHeaderKfuncCall() (asm.Instruction, error) {
	return loadSKBKfuncCall("trustix_skb_kudp_tx_push_udp_header_tc")
}

func loadSKBKfuncCall(programName string) (asm.Instruction, error) {
	object, err := skbKfuncTCFS.ReadFile("bpf/skb_kfunc_tc_bpfel.o")
	if err != nil {
		return asm.Instruction{}, fmt.Errorf("read embedded skb TC kfunc object: %w", err)
	}
	if len(object) == 0 {
		return asm.Instruction{}, fmt.Errorf("embedded skb TC kfunc object is empty")
	}
	defer debug.FreeOSMemory()

	spec, err := cebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return asm.Instruction{}, fmt.Errorf("parse embedded skb TC kfunc ELF: %w", err)
	}
	prog := spec.Programs[programName]
	if prog == nil {
		return asm.Instruction{}, fmt.Errorf("embedded skb TC kfunc ELF is missing program %q", programName)
	}
	for _, ins := range prog.Instructions {
		if ins.IsKfuncCall() {
			return ins, nil
		}
	}
	return asm.Instruction{}, fmt.Errorf("embedded skb TC kfunc program %q has no kfunc call", programName)
}
