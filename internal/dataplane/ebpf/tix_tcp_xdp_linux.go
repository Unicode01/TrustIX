//go:build linux

package ebpf

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"runtime/debug"

	cebpf "github.com/cilium/ebpf"
)

//go:embed bpf/tix_tcp_xdp_bpfel.o bpf/tix_tcp_kernel_crypto_xdp_bpfel.o bpf/tix_tcp_kernel_crypto_xdp_direct_bpfel.o bpf/kernel_udp_xdp_bpfel.o
var tixTCPXDPFS embed.FS

type tixTCPXDPObject struct {
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

type tixTCPXDPReplacements struct {
	kernelCryptoProvider *kernelCryptoProviderObject
	xskMap               *cebpf.Map
	kernelUDPRXNeighMap  *cebpf.Map
	kernelUDPRXDevMap    *cebpf.Map
	kernelUDPRXConfigMap *cebpf.Map
}

func loadTIXTCPXDPObject(queueCount int, replacements tixTCPXDPReplacements) (*tixTCPXDPObject, error) {
	if queueCount <= 0 {
		queueCount = 1
	}
	provider := replacements.kernelCryptoProvider
	if provider != nil && provider.flowIndexMap != nil && provider.contextSlots != nil {
		xdpObject, err := loadTIXTCPXDPObjectFile(queueCount, "bpf/tix_tcp_kernel_crypto_xdp_direct_bpfel.o", replacements)
		if err == nil {
			xdpObject.kernelCryptoRX = true
			return xdpObject, nil
		}
		fallback, fallbackErr := loadTIXTCPXDPObjectFile(queueCount, "bpf/tix_tcp_kernel_crypto_xdp_bpfel.o", replacements)
		if fallbackErr == nil {
			fallback.kernelCryptoRX = true
			fallback.fallbackReason = fmt.Sprintf("tix_tcp attached RX direct kfunc decrypt unavailable; using BPF crypto RX open fallback: %v", err)
			return fallback, nil
		}
		replacements.kernelCryptoProvider = nil
		base, baseErr := loadTIXTCPXDPObjectFile(queueCount, "bpf/tix_tcp_xdp_bpfel.o", replacements)
		if baseErr != nil {
			return nil, fmt.Errorf("load direct-open kernel-crypto tix_tcp XDP object: %v; load BPF crypto fallback: %v; load base fallback: %w", err, fallbackErr, baseErr)
		}
		base.fallbackReason = fmt.Sprintf("tix_tcp attached RX kernel decrypt unavailable; using userspace RX open fallback: direct-open=%v; bpf-crypto=%v", err, fallbackErr)
		return base, nil
	}
	return loadTIXTCPXDPObjectFile(queueCount, "bpf/tix_tcp_xdp_bpfel.o", replacements)
}

func loadKernelUDPStandaloneXDPObject(replacements tixTCPXDPReplacements) (*tixTCPXDPObject, error) {
	return loadTIXTCPXDPObjectFile(1, "bpf/kernel_udp_xdp_bpfel.o", replacements)
}

func loadTIXTCPXDPObjectFile(queueCount int, objectPath string, replacements tixTCPXDPReplacements) (*tixTCPXDPObject, error) {
	object, err := tixTCPXDPFS.ReadFile(objectPath)
	if err != nil {
		return nil, fmt.Errorf("read embedded tix_tcp XDP object %q: %w", objectPath, err)
	}
	if len(object) == 0 {
		return nil, fmt.Errorf("embedded tix_tcp XDP object %q is empty", objectPath)
	}
	defer debug.FreeOSMemory()

	spec, err := cebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, fmt.Errorf("parse embedded tix_tcp XDP ELF %q: %w", objectPath, err)
	}
	xskSpec := spec.Maps["ix_tix_tcp_xsk"]
	if xskSpec == nil {
		return nil, fmt.Errorf("embedded tix_tcp XDP ELF is missing XSK map")
	}
	xskSpec.MaxEntries = uint32(queueCount)
	for _, name := range []string{"ix_tix_tcp_port", "ix_tix_tcp_stat", "ix_tix_tcp_config", "ix_kudp_rx_neigh", "ix_kudp_rx_devmap", "ix_kudp_rx_config"} {
		if spec.Maps[name] == nil {
			return nil, fmt.Errorf("embedded tix_tcp XDP ELF is missing map %q", name)
		}
	}
	if spec.Programs["trustix_tix_tcp"] == nil {
		return nil, fmt.Errorf("embedded tix_tcp XDP ELF is missing program %q", "trustix_tix_tcp")
	}
	options := cebpf.CollectionOptions{
		Programs: cebpf.ProgramOptions{LogSizeStart: 4 * 1024 * 1024},
	}
	mapReplacements := make(map[string]*cebpf.Map)
	if replacements.xskMap != nil {
		mapReplacements["ix_tix_tcp_xsk"] = replacements.xskMap
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
		for _, name := range []string{"trustix_kernel_crypto_flow_index_map", "trustix_kernel_crypto_ctx_slots", "ix_tix_tcp_config"} {
			if spec.Maps[name] == nil {
				return nil, fmt.Errorf("embedded tix_tcp XDP ELF is missing kernel crypto replacement map %q", name)
			}
		}
		mapReplacements["trustix_kernel_crypto_flow_index_map"] = provider.flowIndexMap
		mapReplacements["trustix_kernel_crypto_ctx_slots"] = provider.contextSlots
		if spec.Maps["trustix_kernel_crypto_direct_slots"] != nil {
			if provider.directSlotMap == nil {
				return nil, fmt.Errorf("embedded tix_tcp XDP ELF requires kernel crypto direct slot map")
			}
			mapReplacements["trustix_kernel_crypto_direct_slots"] = provider.directSlotMap
		}
	}
	if len(mapReplacements) > 0 {
		options.MapReplacements = mapReplacements
	}

	coll, err := newBPFCollectionWithOptions(spec, options)
	if err != nil {
		return nil, fmt.Errorf("load embedded tix_tcp XDP object %q: %w", objectPath, err)
	}
	xdpObject := &tixTCPXDPObject{
		collection:  coll,
		xskMap:      coll.Maps["ix_tix_tcp_xsk"],
		portMap:     coll.Maps["ix_tix_tcp_port"],
		xdpStatsMap: coll.Maps["ix_tix_tcp_stat"],
		configMap:   coll.Maps["ix_tix_tcp_config"],
		rxNeighMap:  coll.Maps["ix_kudp_rx_neigh"],
		rxDevMap:    coll.Maps["ix_kudp_rx_devmap"],
		rxConfigMap: coll.Maps["ix_kudp_rx_config"],
		program:     coll.Programs["trustix_tix_tcp"],
	}
	config, err := configureTIXTCPBPFConfig(xdpObject.configMap, queueCount)
	if err != nil {
		return nil, errors.Join(err, xdpObject.Close())
	}
	xdpObject.skipTCPChecksum = config&tixTCPConfigSkipTCPChecksum != 0
	if xdpObject.xskMap == nil || xdpObject.portMap == nil || xdpObject.xdpStatsMap == nil || xdpObject.program == nil {
		return nil, errors.Join(fmt.Errorf("embedded tix_tcp XDP object is incomplete"), xdpObject.Close())
	}
	if xdpObject.configMap == nil {
		return nil, errors.Join(fmt.Errorf("embedded tix_tcp XDP object is missing config map"), xdpObject.Close())
	}
	return xdpObject, nil
}

func (object *tixTCPXDPObject) Close() error {
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
