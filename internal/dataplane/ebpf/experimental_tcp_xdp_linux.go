//go:build linux

package ebpf

import (
	"bytes"
	"embed"
	"fmt"
	"runtime/debug"

	cebpf "github.com/cilium/ebpf"
)

//go:embed bpf/experimental_tcp_xdp_bpfel.o bpf/experimental_tcp_kernel_crypto_xdp_bpfel.o bpf/experimental_tcp_kernel_crypto_xdp_direct_bpfel.o bpf/kernel_udp_xdp_bpfel.o
var experimentalTCPXDPFS embed.FS

type experimentalTCPXDPObject struct {
	collection      *cebpf.Collection
	xskMap          *cebpf.Map
	portMap         *cebpf.Map
	xdpStatsMap     *cebpf.Map
	configMap       *cebpf.Map
	rxNeighMap      *cebpf.Map
	rxDevMap        *cebpf.Map
	rxConfigMap     *cebpf.Map
	program         *cebpf.Program
	kernelCryptoRX  bool
	skipTCPChecksum bool
	fallbackReason  string
}

type experimentalTCPXDPReplacements struct {
	kernelCryptoProvider *kernelCryptoProviderObject
	xskMap               *cebpf.Map
	kernelUDPRXNeighMap  *cebpf.Map
	kernelUDPRXDevMap    *cebpf.Map
	kernelUDPRXConfigMap *cebpf.Map
}

func loadExperimentalTCPXDPObject(queueCount int, replacements experimentalTCPXDPReplacements) (*experimentalTCPXDPObject, error) {
	if queueCount <= 0 {
		queueCount = 1
	}
	provider := replacements.kernelCryptoProvider
	if provider != nil && provider.flowIndexMap != nil && provider.contextSlots != nil {
		xdpObject, err := loadExperimentalTCPXDPObjectFile(queueCount, "bpf/experimental_tcp_kernel_crypto_xdp_direct_bpfel.o", replacements)
		if err == nil {
			xdpObject.kernelCryptoRX = true
			return xdpObject, nil
		}
		fallback, fallbackErr := loadExperimentalTCPXDPObjectFile(queueCount, "bpf/experimental_tcp_kernel_crypto_xdp_bpfel.o", replacements)
		if fallbackErr == nil {
			fallback.kernelCryptoRX = true
			fallback.fallbackReason = fmt.Sprintf("experimental_tcp attached RX direct kfunc decrypt unavailable; using BPF crypto RX open fallback: %v", err)
			return fallback, nil
		}
		replacements.kernelCryptoProvider = nil
		base, baseErr := loadExperimentalTCPXDPObjectFile(queueCount, "bpf/experimental_tcp_xdp_bpfel.o", replacements)
		if baseErr != nil {
			return nil, fmt.Errorf("load direct-open kernel-crypto experimental_tcp XDP object: %v; load BPF crypto fallback: %v; load base fallback: %w", err, fallbackErr, baseErr)
		}
		base.fallbackReason = fmt.Sprintf("experimental_tcp attached RX kernel decrypt unavailable; using userspace RX open fallback: direct-open=%v; bpf-crypto=%v", err, fallbackErr)
		return base, nil
	}
	return loadExperimentalTCPXDPObjectFile(queueCount, "bpf/experimental_tcp_xdp_bpfel.o", replacements)
}

func loadKernelUDPStandaloneXDPObject(replacements experimentalTCPXDPReplacements) (*experimentalTCPXDPObject, error) {
	return loadExperimentalTCPXDPObjectFile(1, "bpf/kernel_udp_xdp_bpfel.o", replacements)
}

func loadExperimentalTCPXDPObjectFile(queueCount int, objectPath string, replacements experimentalTCPXDPReplacements) (*experimentalTCPXDPObject, error) {
	object, err := experimentalTCPXDPFS.ReadFile(objectPath)
	if err != nil {
		return nil, fmt.Errorf("read embedded experimental_tcp XDP object %q: %w", objectPath, err)
	}
	if len(object) == 0 {
		return nil, fmt.Errorf("embedded experimental_tcp XDP object %q is empty", objectPath)
	}
	defer debug.FreeOSMemory()

	spec, err := cebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, fmt.Errorf("parse embedded experimental_tcp XDP ELF %q: %w", objectPath, err)
	}
	xskSpec := spec.Maps["ix_exp_tcp_xsk"]
	if xskSpec == nil {
		return nil, fmt.Errorf("embedded experimental_tcp XDP ELF is missing XSK map")
	}
	xskSpec.MaxEntries = uint32(queueCount)
	for _, name := range []string{"ix_exp_tcp_port", "ix_exp_tcp_stat", "ix_exp_tcp_config", "ix_kudp_rx_neigh", "ix_kudp_rx_devmap", "ix_kudp_rx_config"} {
		if spec.Maps[name] == nil {
			return nil, fmt.Errorf("embedded experimental_tcp XDP ELF is missing map %q", name)
		}
	}
	if spec.Programs["trustix_exp_tcp"] == nil {
		return nil, fmt.Errorf("embedded experimental_tcp XDP ELF is missing program %q", "trustix_exp_tcp")
	}
	options := cebpf.CollectionOptions{
		Programs: cebpf.ProgramOptions{LogSizeStart: 4 * 1024 * 1024},
	}
	mapReplacements := make(map[string]*cebpf.Map)
	if replacements.xskMap != nil {
		mapReplacements["ix_exp_tcp_xsk"] = replacements.xskMap
	}
	if replacements.kernelUDPRXNeighMap != nil {
		mapReplacements["ix_kudp_rx_neigh"] = replacements.kernelUDPRXNeighMap
	}
	if replacements.kernelUDPRXDevMap != nil {
		mapReplacements["ix_kudp_rx_devmap"] = replacements.kernelUDPRXDevMap
	}
	if replacements.kernelUDPRXConfigMap != nil {
		mapReplacements["ix_kudp_rx_config"] = replacements.kernelUDPRXConfigMap
	}
	provider := replacements.kernelCryptoProvider
	if provider != nil {
		for _, name := range []string{"trustix_kernel_crypto_flow_index_map", "trustix_kernel_crypto_ctx_slots", "ix_exp_tcp_config"} {
			if spec.Maps[name] == nil {
				return nil, fmt.Errorf("embedded experimental_tcp XDP ELF is missing kernel crypto replacement map %q", name)
			}
		}
		mapReplacements["trustix_kernel_crypto_flow_index_map"] = provider.flowIndexMap
		mapReplacements["trustix_kernel_crypto_ctx_slots"] = provider.contextSlots
		if spec.Maps["trustix_kernel_crypto_direct_slots"] != nil {
			if provider.directSlotMap == nil {
				return nil, fmt.Errorf("embedded experimental_tcp XDP ELF requires kernel crypto direct slot map")
			}
			mapReplacements["trustix_kernel_crypto_direct_slots"] = provider.directSlotMap
		}
	}
	if len(mapReplacements) > 0 {
		options.MapReplacements = mapReplacements
	}

	coll, err := newBPFCollectionWithOptions(spec, options)
	if err != nil {
		return nil, fmt.Errorf("load embedded experimental_tcp XDP object %q: %w", objectPath, err)
	}
	xdpObject := &experimentalTCPXDPObject{
		collection:  coll,
		xskMap:      coll.Maps["ix_exp_tcp_xsk"],
		portMap:     coll.Maps["ix_exp_tcp_port"],
		xdpStatsMap: coll.Maps["ix_exp_tcp_stat"],
		configMap:   coll.Maps["ix_exp_tcp_config"],
		rxNeighMap:  coll.Maps["ix_kudp_rx_neigh"],
		rxDevMap:    coll.Maps["ix_kudp_rx_devmap"],
		rxConfigMap: coll.Maps["ix_kudp_rx_config"],
		program:     coll.Programs["trustix_exp_tcp"],
	}
	config, err := configureExperimentalTCPBPFConfig(xdpObject.configMap, queueCount)
	if err != nil {
		xdpObject.Close()
		return nil, err
	}
	xdpObject.skipTCPChecksum = config&experimentalTCPConfigSkipTCPChecksum != 0
	if xdpObject.xskMap == nil || xdpObject.portMap == nil || xdpObject.xdpStatsMap == nil || xdpObject.program == nil {
		xdpObject.Close()
		return nil, fmt.Errorf("embedded experimental_tcp XDP object is incomplete")
	}
	if xdpObject.configMap == nil {
		xdpObject.Close()
		return nil, fmt.Errorf("embedded experimental_tcp XDP object is missing config map")
	}
	return xdpObject, nil
}

func (object *experimentalTCPXDPObject) Close() error {
	if object == nil || object.collection == nil {
		return nil
	}
	object.collection.Close()
	object.collection = nil
	object.xskMap = nil
	object.portMap = nil
	object.xdpStatsMap = nil
	object.configMap = nil
	object.rxNeighMap = nil
	object.rxDevMap = nil
	object.rxConfigMap = nil
	object.program = nil
	return nil
}
