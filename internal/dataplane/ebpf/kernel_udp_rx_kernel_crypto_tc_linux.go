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

//go:embed bpf/kernel_udp_rx_kernel_crypto_tc_bpfel.o
var kernelUDPRXSecureDirectFS embed.FS

type kernelUDPRXSecureDirectObject struct {
	collection *cebpf.Collection
	program    *cebpf.Program
}

const (
	kernelUDPRXSecureDirectSKBOpenKfuncCompiled = false
	kernelUDPRXSecureDirectDecapL2KfuncCompiled = false
)

func loadKernelUDPRXSecureDirectObject(provider *kernelCryptoProviderObject, statsMap *cebpf.Map, portMap *cebpf.Map, neighMap *cebpf.Map, lanIfindex int, localIPv4 uint32, sourceMAC [6]byte, options kernelUDPRXDirectProgramOptions) (*kernelUDPRXSecureDirectObject, error) {
	if provider == nil || provider.flowIndexMap == nil || provider.contextSlots == nil || provider.directSlotMap == nil {
		return nil, fmt.Errorf("kernel_udp secure TC RX direct requires loaded kernel crypto provider maps")
	}
	if statsMap == nil || portMap == nil || neighMap == nil {
		return nil, fmt.Errorf("kernel_udp secure TC RX direct requires stats, port, and neighbor maps")
	}
	if lanIfindex <= 0 {
		return nil, fmt.Errorf("invalid LAN ifindex %d", lanIfindex)
	}
	object, err := kernelUDPRXSecureDirectFS.ReadFile("bpf/kernel_udp_rx_kernel_crypto_tc_bpfel.o")
	if err != nil {
		return nil, fmt.Errorf("read embedded kernel_udp secure TC RX direct object: %w", err)
	}
	if len(object) == 0 {
		return nil, fmt.Errorf("embedded kernel_udp secure TC RX direct object is empty")
	}
	defer debug.FreeOSMemory()

	spec, err := cebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, fmt.Errorf("parse embedded kernel_udp secure TC RX direct ELF: %w", err)
	}
	destinationMAC := options.BroadcastDestination
	if destinationMAC == ([6]byte{}) {
		destinationMAC = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	}
	variables := map[string]any{
		"trustix_kudp_rx_secure_adjust_room_flags":    uint32(kernelUDPTCRXAdjustRoomFlags()),
		"trustix_kudp_rx_secure_lan_ifindex":          uint32(lanIfindex),
		"trustix_kudp_rx_secure_local_ipv4":           localIPv4,
		"trustix_kudp_rx_secure_source_mac0":          uint32FromMACPrefix(sourceMAC),
		"trustix_kudp_rx_secure_source_mac1":          uint16FromMACSuffix(sourceMAC),
		"trustix_kudp_rx_secure_destination_mac0":     uint32FromMACPrefix(destinationMAC),
		"trustix_kudp_rx_secure_destination_mac1":     uint16FromMACSuffix(destinationMAC),
		"trustix_kudp_rx_secure_redirect_peer":        boolAsUint32(options.RedirectPeer),
		"trustix_kudp_rx_secure_broadcast":            boolAsUint32(options.Broadcast),
		"trustix_kudp_rx_secure_hot_stats":            boolAsUint32(experimentalTCPHotPathStats()),
		"trustix_kudp_rx_secure_direct_open_kfunc":    boolAsUint32(kernelUDPRXSecureDirectKfuncOpenEnabled()),
		"trustix_kudp_rx_secure_skb_open_kfunc":       boolAsUint32(kernelUDPRXSecureDirectSKBOpenKfuncEnabled()),
		"trustix_kudp_rx_secure_decap_l2_kfunc":       boolAsUint32(kernelUDPRXSecureDirectDecapL2KfuncEnabled()),
		"trustix_kudp_rx_secure_recompute_inner_csum": boolAsUint32(kernelUDPRXSecureDirectRecomputeInnerChecksumEnabled()),
	}
	for name, value := range variables {
		variable := spec.Variables[name]
		if variable == nil {
			return nil, fmt.Errorf("embedded kernel_udp secure TC RX direct ELF is missing variable %q", name)
		}
		if err := variable.Set(value); err != nil {
			return nil, fmt.Errorf("configure kernel_udp secure TC RX direct variable %q: %w", name, err)
		}
	}
	for _, name := range []string{
		"ix_stats_map",
		"ix_exp_tcp_port",
		"ix_kudp_rx_neigh",
		"trustix_kernel_crypto_flow_index_map",
		"trustix_kernel_crypto_ctx_slots",
		"trustix_kernel_crypto_direct_slots",
		"ix_kudp_rx_secure_scratch",
	} {
		if spec.Maps[name] == nil {
			return nil, fmt.Errorf("embedded kernel_udp secure TC RX direct ELF is missing map %q", name)
		}
	}
	spec.Maps["ix_stats_map"].MaxEntries = tcStatsMapMaxEntries
	if spec.Programs["trustix_kudp_rx_secure"] == nil {
		return nil, fmt.Errorf("embedded kernel_udp secure TC RX direct ELF is missing program %q", "trustix_kudp_rx_secure")
	}
	coll, err := newBPFCollectionWithOptions(spec, cebpf.CollectionOptions{
		MapReplacements: map[string]*cebpf.Map{
			"ix_stats_map":                         statsMap,
			"ix_exp_tcp_port":                      portMap,
			"ix_kudp_rx_neigh":                     neighMap,
			"trustix_kernel_crypto_flow_index_map": provider.flowIndexMap,
			"trustix_kernel_crypto_ctx_slots":      provider.contextSlots,
			"trustix_kernel_crypto_direct_slots":   provider.directSlotMap,
		},
		Programs: cebpf.ProgramOptions{LogSizeStart: 8 * 1024 * 1024},
	})
	if err != nil {
		var verifier *cebpf.VerifierError
		if errors.As(err, &verifier) {
			return nil, fmt.Errorf("load embedded kernel_udp secure TC RX direct object: verifier log:\n%+v", verifier)
		}
		return nil, fmt.Errorf("load embedded kernel_udp secure TC RX direct object: %w", err)
	}
	objectHandle := &kernelUDPRXSecureDirectObject{
		collection: coll,
		program:    coll.Programs["trustix_kudp_rx_secure"],
	}
	if objectHandle.program == nil {
		objectHandle.Close()
		return nil, fmt.Errorf("embedded kernel_udp secure TC RX direct object is incomplete")
	}
	return objectHandle, nil
}

func (object *kernelUDPRXSecureDirectObject) Close() error {
	if object == nil || object.collection == nil {
		return nil
	}
	object.collection.Close()
	object.collection = nil
	object.program = nil
	return nil
}

func boolAsUint32(value bool) uint32 {
	if value {
		return 1
	}
	return 0
}

func uint32FromMACPrefix(mac [6]byte) uint32 {
	return uint32(mac[0]) | uint32(mac[1])<<8 | uint32(mac[2])<<16 | uint32(mac[3])<<24
}

func uint16FromMACSuffix(mac [6]byte) uint16 {
	return uint16(mac[4]) | uint16(mac[5])<<8
}

func kernelUDPRXSecureDirectKfuncOpenEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_KFUNC_OPEN"))) {
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return true
	}
}

func kernelUDPRXSecureDirectDecapL2KfuncEnabled() bool {
	return kernelUDPRXSecureDirectDecapL2KfuncCompiled &&
		envTruthy("TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_DECAP_L2_KFUNC")
}

func kernelUDPRXSecureDirectSKBOpenKfuncEnabled() bool {
	return kernelUDPRXSecureDirectSKBOpenKfuncCompiled &&
		envTruthy("TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_SKB_OPEN_KFUNC")
}

func kernelUDPRXSecureDirectRecomputeInnerChecksumEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_RX_SECURE_DIRECT_RECOMPUTE_INNER_CHECKSUMS"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}
