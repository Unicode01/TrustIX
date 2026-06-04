//go:build linux

package ebpf

import (
	"bytes"
	"embed"
	"encoding/binary"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"sync"

	cebpf "github.com/cilium/ebpf"

	"trustix.local/trustix/internal/transport/experimentaltcp"
)

const experimentalTCPKernelCryptoOverhead = kernelCryptoSecureHeaderLen + kernelCryptoFrameTagLen
const experimentalTCPXDPKernelCryptoPlainMax = kernelCryptoFrameMaxPlain

//go:embed bpf/experimental_tcp_kernel_crypto_tx_xdp_bpfel.o
var experimentalTCPTXSealFS embed.FS

type experimentalTCPTXSealObject struct {
	collection      *cebpf.Collection
	statsMap        *cebpf.Map
	configMap       *cebpf.Map
	program         *cebpf.Program
	runOptionsPool  sync.Pool
	validateOutput  bool
	skipTCPChecksum bool
}

func loadExperimentalTCPTXSealObject(provider *kernelCryptoProviderObject) (*experimentalTCPTXSealObject, error) {
	if provider == nil || provider.flowIndexMap == nil || provider.contextSlots == nil {
		return nil, fmt.Errorf("experimental_tcp TX seal requires loaded kernel crypto provider maps")
	}
	object, err := experimentalTCPTXSealFS.ReadFile("bpf/experimental_tcp_kernel_crypto_tx_xdp_bpfel.o")
	if err != nil {
		return nil, fmt.Errorf("read embedded experimental_tcp TX seal XDP object: %w", err)
	}
	if len(object) == 0 {
		return nil, fmt.Errorf("embedded experimental_tcp TX seal XDP object is empty")
	}
	defer debug.FreeOSMemory()

	spec, err := cebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, fmt.Errorf("parse embedded experimental_tcp TX seal XDP ELF: %w", err)
	}
	for _, name := range []string{"trustix_kernel_crypto_flow_index_map", "trustix_kernel_crypto_ctx_slots", "ix_exp_tcp_tx_scratch", "ix_exp_tcp_tx_stat", "ix_exp_tcp_tx_config"} {
		if spec.Maps[name] == nil {
			return nil, fmt.Errorf("embedded experimental_tcp TX seal XDP ELF is missing map %q", name)
		}
	}
	if spec.Programs["trustix_exp_tcp_tx_seal"] == nil {
		return nil, fmt.Errorf("embedded experimental_tcp TX seal XDP ELF is missing program %q", "trustix_exp_tcp_tx_seal")
	}
	coll, err := newBPFCollectionWithOptions(spec, cebpf.CollectionOptions{
		MapReplacements: map[string]*cebpf.Map{
			"trustix_kernel_crypto_flow_index_map": provider.flowIndexMap,
			"trustix_kernel_crypto_ctx_slots":      provider.contextSlots,
		},
		Programs: cebpf.ProgramOptions{LogSizeStart: 4 * 1024 * 1024},
	})
	if err != nil {
		return nil, fmt.Errorf("load embedded experimental_tcp TX seal XDP object: %w", err)
	}
	sealer := &experimentalTCPTXSealObject{
		collection:     coll,
		statsMap:       coll.Maps["ix_exp_tcp_tx_stat"],
		configMap:      coll.Maps["ix_exp_tcp_tx_config"],
		program:        coll.Programs["trustix_exp_tcp_tx_seal"],
		validateOutput: experimentalTCPTXSealValidateOutput(),
	}
	config, err := configureExperimentalTCPBPFConfig(sealer.configMap, 0)
	if err != nil {
		sealer.Close()
		return nil, err
	}
	sealer.skipTCPChecksum = config&experimentalTCPConfigSkipTCPChecksum != 0
	sealer.runOptionsPool = sync.Pool{
		New: func() any {
			return new(cebpf.RunOptions)
		},
	}
	if sealer.statsMap == nil || sealer.configMap == nil || sealer.program == nil {
		sealer.Close()
		return nil, fmt.Errorf("embedded experimental_tcp TX seal XDP object is incomplete")
	}
	return sealer, nil
}

func (object *experimentalTCPTXSealObject) Close() error {
	if object == nil || object.collection == nil {
		return nil
	}
	object.collection.Close()
	object.collection = nil
	object.statsMap = nil
	object.configMap = nil
	object.program = nil
	return nil
}

func (object *experimentalTCPTXSealObject) SealIPv4(packet []byte) ([]byte, error) {
	if object == nil || object.program == nil {
		return nil, fmt.Errorf("experimental_tcp TX seal XDP object is not loaded")
	}
	if len(packet) == 0 {
		return nil, fmt.Errorf("experimental_tcp TX seal packet is empty")
	}
	ethernet := make([]byte, ethernetHeaderLen+len(packet))
	ethernet[12] = 0x08
	ethernet[13] = 0x00
	copy(ethernet[ethernetHeaderLen:], packet)
	out, err := object.runSealEthernet(ethernet, make([]byte, len(ethernet)+experimentalTCPKernelCryptoOverhead))
	if err != nil {
		return nil, err
	}
	sealed := append([]byte(nil), out[ethernetHeaderLen:]...)
	if err := validateExperimentalTCPTXSealedIPv4(sealed, object.skipTCPChecksum); err != nil {
		return nil, err
	}
	return sealed, nil
}

func (object *experimentalTCPTXSealObject) SealEthernetInPlace(frame []byte, length int) (int, error) {
	if object == nil || object.program == nil {
		return 0, fmt.Errorf("experimental_tcp TX seal XDP object is not loaded")
	}
	if length <= ethernetHeaderLen {
		return 0, fmt.Errorf("experimental_tcp TX seal ethernet frame is too short: %d", length)
	}
	if length > len(frame) {
		return 0, fmt.Errorf("experimental_tcp TX seal ethernet frame length %d exceeds buffer %d", length, len(frame))
	}
	outputLen := length + experimentalTCPKernelCryptoOverhead
	if outputLen > len(frame) {
		return 0, fmt.Errorf("experimental_tcp TX seal ethernet output length %d exceeds buffer %d", outputLen, len(frame))
	}
	out, err := object.runSealEthernet(frame[:length], frame[:outputLen])
	if err != nil {
		return 0, err
	}
	if len(out) < ethernetHeaderLen {
		return 0, fmt.Errorf("experimental_tcp TX seal XDP output too short: %d", len(out))
	}
	if object.validateOutput {
		if err := validateExperimentalTCPTXSealedIPv4(out[ethernetHeaderLen:], object.skipTCPChecksum); err != nil {
			return 0, err
		}
	}
	return len(out), nil
}

func (object *experimentalTCPTXSealObject) runSealEthernet(input []byte, output []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("experimental_tcp TX seal packet is empty")
	}
	options := object.getRunOptions(input, output)
	ret, err := object.program.Run(options)
	out := options.DataOut
	object.putRunOptions(options)
	if err != nil {
		return nil, fmt.Errorf("run experimental_tcp TX seal XDP program: %w", err)
	}
	if ret != 2 {
		return nil, fmt.Errorf("experimental_tcp TX seal XDP program returned %d", ret)
	}
	if len(out) < ethernetHeaderLen {
		return nil, fmt.Errorf("experimental_tcp TX seal XDP output too short: %d", len(out))
	}
	return out, nil
}

func (object *experimentalTCPTXSealObject) getRunOptions(input []byte, output []byte) *cebpf.RunOptions {
	if object == nil {
		return &cebpf.RunOptions{Data: input, DataOut: output}
	}
	options, _ := object.runOptionsPool.Get().(*cebpf.RunOptions)
	if options == nil {
		options = new(cebpf.RunOptions)
	}
	*options = cebpf.RunOptions{
		Data:    input,
		DataOut: output,
	}
	return options
}

func (object *experimentalTCPTXSealObject) putRunOptions(options *cebpf.RunOptions) {
	if object == nil || options == nil {
		return
	}
	*options = cebpf.RunOptions{}
	object.runOptionsPool.Put(options)
}

func experimentalTCPTXSealValidateOutput() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_EXPERIMENTAL_TCP_VALIDATE_TX_SEAL"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func validateExperimentalTCPTXSealedIPv4(sealed []byte, skipTCPChecksum bool) error {
	parseTCP := experimentaltcp.ParseTCPShapedIPv4NoCopy
	if skipTCPChecksum {
		parseTCP = experimentaltcp.ParseTCPShapedIPv4NoCopySkipTCPChecksum
	}
	tcpPacket, err := parseTCP(sealed)
	if err != nil {
		got, want := experimentalTCPTCPChecksumPair(sealed)
		return fmt.Errorf("parse experimental_tcp TX sealed packet: %w (tcp checksum got=%#04x want=%#04x)", err, got, want)
	}
	frame, err := experimentaltcp.ParseFrameNoCopy(tcpPacket.Payload)
	if err != nil {
		return fmt.Errorf("parse experimental_tcp TX sealed frame: %w", err)
	}
	if frame.Flags&experimentaltcp.FlagEncrypted == 0 || frame.Flags&experimentaltcp.FlagKernelOpened != 0 {
		return fmt.Errorf("experimental_tcp TX sealed frame flags %#x are invalid", frame.Flags)
	}
	return nil
}

func experimentalTCPTCPChecksumPair(wire []byte) (uint16, uint16) {
	if len(wire) < 40 {
		return 0, 0
	}
	ihl := int(wire[0]&0x0f) * 4
	totalLen := int(binary.BigEndian.Uint16(wire[2:4]))
	if ihl < 20 || totalLen < ihl+20 || totalLen > len(wire) {
		return 0, 0
	}
	tcp := wire[ihl:totalLen]
	src := [4]byte{wire[12], wire[13], wire[14], wire[15]}
	dst := [4]byte{wire[16], wire[17], wire[18], wire[19]}
	return binary.BigEndian.Uint16(tcp[16:18]), experimentalTCPTCPChecksum(src, dst, tcp)
}

func experimentalTCPTCPChecksum(src, dst [4]byte, tcp []byte) uint16 {
	pseudo := make([]byte, 12+len(tcp))
	copy(pseudo[0:4], src[:])
	copy(pseudo[4:8], dst[:])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	copy(pseudo[12:], tcp)
	pseudo[28] = 0
	pseudo[29] = 0
	return experimentalTCPChecksum(pseudo)
}

func experimentalTCPChecksum(payload []byte) uint16 {
	var sum uint32
	for len(payload) > 1 {
		sum += uint32(binary.BigEndian.Uint16(payload[:2]))
		payload = payload[2:]
	}
	if len(payload) == 1 {
		sum += uint32(payload[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (object *experimentalTCPTXSealObject) Stats() map[string]uint64 {
	keys := []struct {
		key  uint32
		name string
	}{
		{key: 0, name: "tx_kernel_crypto_packet_seal_attempts"},
		{key: 1, name: "tx_kernel_crypto_packet_seal_successes"},
		{key: 2, name: "tx_kernel_crypto_packet_seal_errors"},
		{key: 3, name: "tx_kernel_crypto_packet_seal_no_context_errors"},
		{key: 4, name: "tx_kernel_crypto_packet_seal_header_errors"},
		{key: 5, name: "tx_kernel_crypto_packet_seal_encrypt_errors"},
		{key: 6, name: "tx_kernel_crypto_packet_seal_sequence_errors"},
		{key: 7, name: "tx_kernel_crypto_packet_seal_tcp_checksum_skipped"},
	}
	stats := make(map[string]uint64, len(keys)+1)
	stats["tx_kernel_crypto_packet_seal_skip_tcp_checksum_enabled"] = boolCounter(object != nil && object.skipTCPChecksum)
	if object == nil || object.statsMap == nil {
		for _, item := range keys {
			stats[item.name] = 0
		}
		return stats
	}
	for _, item := range keys {
		stats[item.name] = 0
		if value, err := bpfCounterValue(object.statsMap, item.key); err == nil {
			stats[item.name] = value
		}
	}
	return stats
}
