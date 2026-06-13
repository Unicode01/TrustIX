//go:build linux

package ebpf

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	cebpf "github.com/cilium/ebpf"
)

//go:embed bpf/kernel_udp_tx_kernel_crypto_tc_bpfel.o
var kernelUDPTXSecureDirectFS embed.FS

type kernelUDPTXSecureDirectObject struct {
	collection *cebpf.Collection
	program    *cebpf.Program
}

type kernelUDPTXSecureDirectProgramOptions struct {
	KfuncSeal                bool
	SKBSealKfunc             bool
	FixInnerChecksums        bool
	InnerTCPChecksumKfunc    bool
	OuterTCPChecksumKfunc    bool
	OuterTCPPartialCSUMKfunc bool
}

const (
	kernelUDPTXSecureDirectSKBSealKfuncCompiled          = false
	kernelUDPTXSecureDirectOuterTCPChecksumKfuncCompiled = false
)

func loadKernelUDPTXSecureDirectObject(provider *kernelCryptoProviderObject, statsMap *cebpf.Map, routeMap *cebpf.Map, flowMap *cebpf.Map, options kernelUDPTXSecureDirectProgramOptions) (*kernelUDPTXSecureDirectObject, error) {
	if provider == nil || provider.flowIndexMap == nil || provider.contextSlots == nil || provider.directSlotMap == nil {
		return nil, fmt.Errorf("kernel_udp secure TC TX direct requires loaded kernel crypto provider maps")
	}
	if statsMap == nil || routeMap == nil || flowMap == nil {
		return nil, fmt.Errorf("kernel_udp secure TC TX direct requires stats, route, and flow maps")
	}
	object, err := kernelUDPTXSecureDirectFS.ReadFile("bpf/kernel_udp_tx_kernel_crypto_tc_bpfel.o")
	if err != nil {
		return nil, fmt.Errorf("read embedded kernel_udp secure TC TX direct object: %w", err)
	}
	if len(object) == 0 {
		return nil, fmt.Errorf("embedded kernel_udp secure TC TX direct object is empty")
	}
	defer debug.FreeOSMemory()

	spec, err := cebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, fmt.Errorf("parse embedded kernel_udp secure TC TX direct ELF: %w", err)
	}
	if variable := spec.Variables["trustix_kudp_tx_adjust_room_flags"]; variable != nil {
		if err := variable.Set(kernelUDPTXSecureDirectAdjustRoomFlags()); err != nil {
			return nil, fmt.Errorf("configure kernel_udp secure TC TX direct adjust_room flags: %w", err)
		}
	}
	if variable := spec.Variables["trustix_kudp_tx_direct_seal_kfunc"]; variable != nil {
		if err := variable.Set(boolAsUint32(options.KfuncSeal)); err != nil {
			return nil, fmt.Errorf("configure kernel_udp secure TC TX direct kfunc seal: %w", err)
		}
	}
	if variable := spec.Variables["trustix_kudp_tx_secure_skb_seal_kfunc"]; variable != nil {
		if err := variable.Set(boolAsUint32(options.SKBSealKfunc)); err != nil {
			return nil, fmt.Errorf("configure kernel_udp secure TC TX direct skb seal: %w", err)
		}
	}
	if variable := spec.Variables["trustix_kudp_tx_fix_inner_checksums"]; variable != nil {
		if err := variable.Set(boolAsUint32(options.FixInnerChecksums)); err != nil {
			return nil, fmt.Errorf("configure kernel_udp secure TC TX direct inner checksum normalization: %w", err)
		}
	}
	if variable := spec.Variables["trustix_kudp_tx_secure_inner_tcp_csum_kfunc"]; variable != nil {
		if err := variable.Set(boolAsUint32(options.InnerTCPChecksumKfunc)); err != nil {
			return nil, fmt.Errorf("configure kernel_udp secure TC TX direct inner TCP checksum kfunc: %w", err)
		}
	}
	if variable := spec.Variables["trustix_kudp_tx_secure_outer_tcp_csum_kfunc"]; variable != nil {
		if err := variable.Set(boolAsUint32(options.OuterTCPChecksumKfunc)); err != nil {
			return nil, fmt.Errorf("configure kernel_udp secure TC TX direct outer TCP checksum kfunc: %w", err)
		}
	}
	if variable := spec.Variables["trustix_kudp_tx_secure_outer_tcp_partial_csum_kfunc"]; variable != nil {
		if err := variable.Set(boolAsUint32(options.OuterTCPPartialCSUMKfunc)); err != nil {
			return nil, fmt.Errorf("configure kernel_udp secure TC TX direct outer TCP partial checksum kfunc: %w", err)
		}
	}
	for _, name := range []string{
		"ix_stats_map",
		"ix_kudp_tx_route",
		"ix_kudp_tx_flow",
		"trustix_kernel_crypto_flow_index_map",
		"trustix_kernel_crypto_ctx_slots",
		"trustix_kernel_crypto_direct_slots",
		"ix_kudp_tx_secure_scratch",
	} {
		if spec.Maps[name] == nil {
			return nil, fmt.Errorf("embedded kernel_udp secure TC TX direct ELF is missing map %q", name)
		}
	}
	spec.Maps["ix_stats_map"].MaxEntries = tcStatsMapMaxEntries
	if spec.Programs["trustix_kudp_tx_secure"] == nil {
		return nil, fmt.Errorf("embedded kernel_udp secure TC TX direct ELF is missing program %q", "trustix_kudp_tx_secure")
	}
	coll, err := newBPFCollectionWithOptions(spec, cebpf.CollectionOptions{
		MapReplacements: map[string]*cebpf.Map{
			"ix_stats_map":                         statsMap,
			"ix_kudp_tx_route":                     routeMap,
			"ix_kudp_tx_flow":                      flowMap,
			"trustix_kernel_crypto_flow_index_map": provider.flowIndexMap,
			"trustix_kernel_crypto_ctx_slots":      provider.contextSlots,
			"trustix_kernel_crypto_direct_slots":   provider.directSlotMap,
		},
		Programs: cebpf.ProgramOptions{LogSizeStart: 8 * 1024 * 1024},
	})
	if err != nil {
		var verifier *cebpf.VerifierError
		if errors.As(err, &verifier) {
			return nil, fmt.Errorf("load embedded kernel_udp secure TC TX direct object: verifier log:\n%+v", verifier)
		}
		return nil, fmt.Errorf("load embedded kernel_udp secure TC TX direct object: %w", err)
	}
	objectHandle := &kernelUDPTXSecureDirectObject{
		collection: coll,
		program:    coll.Programs["trustix_kudp_tx_secure"],
	}
	if objectHandle.program == nil {
		objectHandle.Close()
		return nil, fmt.Errorf("embedded kernel_udp secure TC TX direct object is incomplete")
	}
	return objectHandle, nil
}

func (object *kernelUDPTXSecureDirectObject) Close() error {
	if object == nil || object.collection == nil {
		return nil
	}
	object.collection.Close()
	object.collection = nil
	object.program = nil
	return nil
}

func kernelUDPTXSecureDirectAdjustRoomFlags() uint32 {
	flags := uint32(bpfAdjRoomNoCSUMReset)
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_TUNNEL_GSO"))) {
	case "1", "true", "yes", "on", "enabled":
		flags |= uint32(bpfAdjRoomFixedGSO | bpfAdjRoomEncapL3IPv4 | bpfAdjRoomEncapL4UDP)
	case "", "0", "false", "no", "off", "disabled":
	default:
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_NO_CSUM_RESET"))) {
	case "1", "true", "yes", "on", "enabled":
		return flags
	case "0", "false", "no", "off", "disabled":
		return flags &^ bpfAdjRoomNoCSUMReset
	case "":
		return flags
	default:
		return flags
	}
}

func kernelUDPTXSecureDirectKfuncSealEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_KFUNC_SEAL"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func kernelUDPTXSecureDirectSKBSealKfuncEnabled() bool {
	return kernelUDPTXSecureDirectSKBSealKfuncCompiled &&
		envTruthy("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_SKB_SEAL_KFUNC")
}

func kernelUDPTXSecureDirectFixInnerChecksumsEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_FIX_INNER_CHECKSUMS"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func kernelUDPTXSecureDirectInnerTCPChecksumKfuncEnabled() bool {
	return envTruthy("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_INNER_TCP_CHECKSUM_KFUNC")
}

func kernelUDPTXSecureDirectOuterTCPChecksumKfuncEnabled() bool {
	return envTruthy("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_OUTER_TCP_CHECKSUM_KFUNC")
}

func kernelUDPTXSecureDirectOuterTCPPartialChecksumKfuncEnabled() bool {
	return envTruthy("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_OUTER_TCP_PARTIAL_CHECKSUM_KFUNC")
}

func kernelUDPTXSecureDirectIngressEnabled() bool {
	return !envFalsey("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_INGRESS")
}

func kernelUDPTXSecureDirectEgressEnabled() bool {
	return !envFalsey("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT_EGRESS")
}

func kernelUDPTXSecureDirectRequested() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}
