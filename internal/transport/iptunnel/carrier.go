package iptunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"trustix.local/trustix/internal/transport"
)

const (
	carrierHeaderLen                    = 16
	carrierFragmentHeaderLen            = 8
	carrierIPv4UDPHeaderLen             = 20 + 8
	carrierVersion                 byte = 1
	carrierTypeData                byte = 1
	carrierTypeFragment            byte = 2
	carrierMaxPacket                    = 512 * 1024
	carrierMaxUDPPayload                = 65507
	carrierMaxUnfragmentedPacket        = carrierMaxUDPPayload - carrierHeaderLen
	carrierMaxWire                      = carrierMaxUDPPayload
	defaultCarrierPort                  = 47819
	defaultTunnelMTU                    = 1400
	defaultVXLANVNI                     = 0x545849
	defaultVXLANPort                    = 4789
	carrierReadBatchDefault             = 64
	carrierReadBatchMax                 = 256
	carrierListenWorkersDefault         = 4
	carrierListenWorkersMax             = 16
	carrierReassemblyMaxPackets         = 64
	carrierSendBatchArenaRetainMax      = 4 * 1024 * 1024
)

var carrierMagic = [4]byte{'T', 'I', 'X', 'G'}

type carrierReadBufferPoolBucket struct {
	size int
	pool sync.Pool
}

var carrierReadBufferPools = []carrierReadBufferPoolBucket{
	{size: 2048, pool: sync.Pool{New: func() any { return make([]byte, 2048) }}},
	{size: 4096, pool: sync.Pool{New: func() any { return make([]byte, 4096) }}},
	{size: 16 * 1024, pool: sync.Pool{New: func() any { return make([]byte, 16*1024) }}},
	{size: carrierMaxWire, pool: sync.Pool{New: func() any { return make([]byte, carrierMaxWire) }}},
}

var carrierReassemblyBufferPools = []carrierReadBufferPoolBucket{
	{size: 64 * 1024, pool: sync.Pool{New: func() any { return make([]byte, 64*1024) }}},
	{size: 128 * 1024, pool: sync.Pool{New: func() any { return make([]byte, 128*1024) }}},
	{size: 256 * 1024, pool: sync.Pool{New: func() any { return make([]byte, 256*1024) }}},
	{size: carrierMaxPacket, pool: sync.Pool{New: func() any { return make([]byte, carrierMaxPacket) }}},
}

func takeCarrierReadBuffer(sizes ...int) []byte {
	size := carrierMaxWire
	if len(sizes) > 0 && sizes[0] > 0 {
		size = carrierReadBufferSize(sizes[0])
	}
	for i := range carrierReadBufferPools {
		bucket := &carrierReadBufferPools[i]
		if bucket.size < size {
			continue
		}
		buf := bucket.pool.Get().([]byte)
		if cap(buf) < bucket.size {
			return make([]byte, bucket.size)
		}
		return buf[:bucket.size]
	}
	return make([]byte, carrierMaxWire)
}

func putCarrierReadBuffer(buf []byte) {
	if cap(buf) <= 0 {
		return
	}
	for i := range carrierReadBufferPools {
		bucket := &carrierReadBufferPools[i]
		if cap(buf) == bucket.size {
			bucket.pool.Put(buf[:bucket.size])
			return
		}
	}
	if cap(buf) >= carrierMaxWire {
		carrierReadBufferPools[len(carrierReadBufferPools)-1].pool.Put(buf[:carrierMaxWire])
	}
}

func takeCarrierReassemblyBuffer(size int) []byte {
	if size <= 0 {
		size = 1
	}
	if size > carrierMaxPacket {
		size = carrierMaxPacket
	}
	for i := range carrierReassemblyBufferPools {
		bucket := &carrierReassemblyBufferPools[i]
		if bucket.size < size {
			continue
		}
		buf := bucket.pool.Get().([]byte)
		if cap(buf) < bucket.size {
			return make([]byte, size, bucket.size)
		}
		return buf[:size]
	}
	return make([]byte, size)
}

func putCarrierReassemblyBuffer(buf []byte) {
	if cap(buf) <= 0 {
		return
	}
	for i := range carrierReassemblyBufferPools {
		bucket := &carrierReassemblyBufferPools[i]
		if cap(buf) != bucket.size {
			continue
		}
		bucket.pool.Put(buf[:bucket.size])
		return
	}
}

func carrierReadBufferSize(size int) int {
	if size <= carrierHeaderLen {
		return carrierHeaderLen + 1
	}
	if size > carrierMaxWire {
		return carrierMaxWire
	}
	return size
}

type tunnelConfig struct {
	Protocol       transport.Protocol
	LocalUnderlay  netip.Addr
	RemoteUnderlay netip.Addr
	UnderlayIf     string
	LocalCarrier   netip.Prefix
	RemoteCarrier  netip.Addr
	CarrierPort    uint16
	MTU            int
	VNI            int
	VXLANPort      uint16
	VXLANPortLow   uint16
	VXLANPortHigh  uint16
	Queues         int
	VXLANUDPCSum   bool
}

type TunnelConfig = tunnelConfig

type carrier struct {
	cfg                    tunnelConfig
	closeFunc              func() error
	conn                   *net.UDPConn
	closeOnce              sync.Once
	closeErr               error
	recvMu                 sync.Mutex
	sendSeq                atomic.Uint64
	bytesSent              atomic.Uint64
	bytesReceived          atomic.Uint64
	packetsSent            atomic.Uint64
	packetsReceived        atomic.Uint64
	decodeErrors           atomic.Uint64
	mtuDrops               atomic.Uint64
	sendBatchCalls         atomic.Uint64
	sendBatchPackets       atomic.Uint64
	sendBatchBytes         atomic.Uint64
	sendBatchMMSGSyscalls  atomic.Uint64
	sendBatchGSOSyscalls   atomic.Uint64
	sendBatchLoopSyscalls  atomic.Uint64
	sendBatchFallbacks     atomic.Uint64
	recvBatchCalls         atomic.Uint64
	recvBatchPackets       atomic.Uint64
	recvBatchBytes         atomic.Uint64
	recvBatchMMSGSyscalls  atomic.Uint64
	recvBatchLoopSyscalls  atomic.Uint64
	recvBatchFallbacks     atomic.Uint64
	fragmentsSent          atomic.Uint64
	fragmentedPacketsSent  atomic.Uint64
	fragmentsReceived      atomic.Uint64
	reassembledPackets     atomic.Uint64
	fragmentDrops          atomic.Uint64
	sendWire               []byte
	sendBatchWire          [][]byte
	sendBatchPacketScratch []carrierBatchPacket
	sendBatchArena         []byte
	reassembler            carrierReassembler
}

type packetListener struct {
	conn      *net.UDPConn
	conns     []*net.UDPConn
	cfg       tunnelConfig
	acceptCh  chan transport.Session
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
	mu        sync.Mutex
	sessions  map[string]*carrierServerSession
}

type carrierServerSession struct {
	conn                   *net.UDPConn
	remote                 *net.UDPAddr
	in                     chan carrierReceivedPacket
	listener               *packetListener
	key                    string
	closeOnce              sync.Once
	mu                     sync.Mutex
	closed                 bool
	sendSeq                atomic.Uint64
	bytesSent              atomic.Uint64
	bytesReceived          atomic.Uint64
	packetsSent            atomic.Uint64
	packetsReceived        atomic.Uint64
	packetsDropped         atomic.Uint64
	mtuDrops               atomic.Uint64
	sendBatchCalls         atomic.Uint64
	sendBatchPackets       atomic.Uint64
	sendBatchBytes         atomic.Uint64
	sendBatchMMSGSyscalls  atomic.Uint64
	sendBatchGSOSyscalls   atomic.Uint64
	sendBatchLoopSyscalls  atomic.Uint64
	sendBatchFallbacks     atomic.Uint64
	recvBatchCalls         atomic.Uint64
	recvBatchPackets       atomic.Uint64
	recvBatchBytes         atomic.Uint64
	fragmentsSent          atomic.Uint64
	fragmentedPacketsSent  atomic.Uint64
	fragmentsReceived      atomic.Uint64
	reassembledPackets     atomic.Uint64
	fragmentDrops          atomic.Uint64
	sendWire               []byte
	sendBatchWire          [][]byte
	sendBatchPacketScratch []carrierBatchPacket
	sendBatchArena         []byte
	reassembler            carrierReassembler
}

type carrierBatchPacket struct {
	header  []byte
	payload []byte
}

type carrierReceivedPacket struct {
	payload    []byte
	wireLen    int
	buffer     []byte
	reassembly []byte
	addr       *net.UDPAddr
	sequence   uint64
	frameType  byte
	totalLen   int
	offset     int
}

type carrierBatchReceiveResult struct {
	bytesReceived uint64
	mmsgSyscalls  uint64
	loopSyscalls  uint64
	fallbacks     uint64
}

type carrierFragmentRange struct {
	start int
	end   int
}

type carrierFragmentAssembly struct {
	totalLen int
	received int
	wireLen  int
	data     []byte
	ranges   []carrierFragmentRange
}

type carrierReassembler struct {
	assemblies map[uint64]*carrierFragmentAssembly
	order      []uint64
}

func parseTunnelConfig(raw string) (tunnelConfig, error) {
	values, err := parseTunnelValues(raw)
	if err != nil {
		return tunnelConfig{}, err
	}
	cfg := tunnelConfig{CarrierPort: defaultCarrierPort, MTU: defaultTunnelMTU, VXLANPort: defaultVXLANPort, VXLANUDPCSum: true}
	if value := values["vni"]; value != "" {
		vni, err := strconv.ParseUint(value, 10, 24)
		if err != nil || vni == 0 {
			return tunnelConfig{}, fmt.Errorf("parse VXLAN VNI %q", value)
		}
		cfg.VNI = int(vni)
	}
	if value := firstTunnelValue(values, "queues", "num_queues", "vxlan_queues"); value != "" {
		queues, err := strconv.ParseUint(value, 10, 16)
		if err != nil || queues == 0 {
			return tunnelConfig{}, fmt.Errorf("parse VXLAN queue count %q", value)
		}
		cfg.Queues = int(queues)
	}
	if value := firstTunnelValue(values, "vxlan_port", "outer_port"); value != "" {
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil || port == 0 {
			return tunnelConfig{}, fmt.Errorf("parse VXLAN outer port %q", value)
		}
		cfg.VXLANPort = uint16(port)
	}
	if low, high, ok, err := parseVXLANPortRange(values); err != nil {
		return tunnelConfig{}, err
	} else if ok {
		cfg.VXLANPortLow = low
		cfg.VXLANPortHigh = high
	}
	if value := firstTunnelValue(values, "udp_checksum", "udpcsum", "vxlan_udp_checksum"); value != "" {
		enabled, err := parseTunnelBool(value)
		if err != nil {
			return tunnelConfig{}, fmt.Errorf("parse VXLAN UDP checksum %q: %w", value, err)
		}
		cfg.VXLANUDPCSum = enabled
	}
	if value := firstTunnelValue(values, "underlay_if", "underlay_iface", "dev", "link"); value != "" {
		if strings.ContainsAny(value, "/\x00") {
			return tunnelConfig{}, fmt.Errorf("parse tunnel underlay interface %q", value)
		}
		cfg.UnderlayIf = value
	}
	if value := values["port"]; value != "" {
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil || port == 0 {
			return tunnelConfig{}, fmt.Errorf("parse tunnel carrier port %q", value)
		}
		cfg.CarrierPort = uint16(port)
	}
	if value := values["mtu"]; value != "" {
		mtu, err := strconv.ParseUint(value, 10, 16)
		if err != nil || mtu < carrierHeaderLen+1 {
			return tunnelConfig{}, fmt.Errorf("parse tunnel carrier mtu %q", value)
		}
		cfg.MTU = int(mtu)
	}
	localUnderlay, err := requiredTunnelAddr(values, "local")
	if err != nil {
		return tunnelConfig{}, err
	}
	remoteUnderlay, err := requiredTunnelAddr(values, "remote")
	if err != nil {
		return tunnelConfig{}, err
	}
	localCarrier, err := requiredTunnelPrefix(values, "local_carrier")
	if err != nil {
		return tunnelConfig{}, err
	}
	remoteCarrier, err := requiredTunnelAddr(values, "remote_carrier")
	if err != nil {
		return tunnelConfig{}, err
	}
	cfg.LocalUnderlay = localUnderlay
	cfg.RemoteUnderlay = remoteUnderlay
	cfg.LocalCarrier = localCarrier
	cfg.RemoteCarrier = remoteCarrier
	return cfg, nil
}

func ParseTunnelConfig(raw string) (TunnelConfig, error) {
	return parseTunnelConfig(raw)
}

func normalizeTunnelConfig(raw string) string {
	cfg, err := parseTunnelConfig(raw)
	if err != nil {
		return strings.TrimSpace(raw)
	}
	return normalizeTunnelConfigFields(cfg)
}

func normalizeTunnelConfigFields(cfg tunnelConfig) string {
	fields := []string{
		fmt.Sprintf("local=%s", cfg.LocalUnderlay),
		fmt.Sprintf("remote=%s", cfg.RemoteUnderlay),
	}
	if cfg.UnderlayIf != "" {
		fields = append(fields, fmt.Sprintf("underlay_if=%s", cfg.UnderlayIf))
	}
	fields = append(fields,
		fmt.Sprintf("local_carrier=%s", cfg.LocalCarrier),
		fmt.Sprintf("remote_carrier=%s", cfg.RemoteCarrier),
		fmt.Sprintf("port=%d", cfg.CarrierPort),
		fmt.Sprintf("mtu=%d", effectiveTunnelMTU(cfg.MTU)),
	)
	if cfg.Queues > 0 {
		fields = append(fields, fmt.Sprintf("queues=%d", cfg.Queues))
	}
	return strings.Join(fields, ",")
}

func normalizeVXLANConfig(raw string) string {
	cfg, err := parseTunnelConfig(raw)
	if err != nil {
		return strings.TrimSpace(raw)
	}
	return normalizeVXLANConfigFields(cfg)
}

func normalizeVXLANConfigFields(cfg tunnelConfig) string {
	fields := []string{
		fmt.Sprintf("local=%s", cfg.LocalUnderlay),
		fmt.Sprintf("remote=%s", cfg.RemoteUnderlay),
	}
	if cfg.UnderlayIf != "" {
		fields = append(fields, fmt.Sprintf("underlay_if=%s", cfg.UnderlayIf))
	}
	fields = append(fields,
		fmt.Sprintf("local_carrier=%s", cfg.LocalCarrier),
		fmt.Sprintf("remote_carrier=%s", cfg.RemoteCarrier),
		fmt.Sprintf("port=%d", cfg.CarrierPort),
		fmt.Sprintf("mtu=%d", effectiveTunnelMTU(cfg.MTU)),
		fmt.Sprintf("vni=%d", effectiveVXLANVNI(cfg.VNI)),
		fmt.Sprintf("vxlan_port=%d", effectiveVXLANPort(cfg.VXLANPort)),
	)
	if cfg.VXLANPortLow > 0 || cfg.VXLANPortHigh > 0 {
		fields = append(fields, fmt.Sprintf("src_port_low=%d", cfg.VXLANPortLow), fmt.Sprintf("src_port_high=%d", cfg.VXLANPortHigh))
	}
	if cfg.Queues > 0 {
		fields = append(fields, fmt.Sprintf("queues=%d", cfg.Queues))
	}
	if !cfg.VXLANUDPCSum {
		fields = append(fields, "udp_checksum=false")
	}
	return strings.Join(fields, ",")
}

func legacyNormalizeVXLANConfig(raw string) string {
	cfg, err := parseTunnelConfig(raw)
	if err != nil {
		return strings.TrimSpace(raw)
	}
	return fmt.Sprintf("local=%s,remote=%s,local_carrier=%s,remote_carrier=%s,port=%d,mtu=%d,vni=%d,vxlan_port=%d",
		cfg.LocalUnderlay,
		cfg.RemoteUnderlay,
		cfg.LocalCarrier,
		cfg.RemoteCarrier,
		cfg.CarrierPort,
		effectiveTunnelMTU(cfg.MTU),
		effectiveVXLANVNI(cfg.VNI),
		effectiveVXLANPort(cfg.VXLANPort),
	)
}

func NormalizeTunnelConfig(raw string) string {
	return normalizeTunnelConfig(raw)
}

func NormalizeKernelTunnelConfig(protocol transport.Protocol, raw string) string {
	if protocol == transport.ProtocolVXLAN {
		return normalizeVXLANConfig(raw)
	}
	return normalizeTunnelConfig(raw)
}

func NormalizeParsedKernelTunnelConfig(protocol transport.Protocol, cfg TunnelConfig) string {
	if protocol == transport.ProtocolVXLAN {
		return normalizeVXLANConfigFields(cfg)
	}
	return normalizeTunnelConfigFields(cfg)
}

func ReverseKernelTunnelConfig(protocol transport.Protocol, raw string, underlayIf ...string) (string, error) {
	cfg, err := parseTunnelConfig(raw)
	if err != nil {
		return "", err
	}
	reversed := cfg
	reversed.LocalUnderlay, reversed.RemoteUnderlay = cfg.RemoteUnderlay, cfg.LocalUnderlay
	reversed.LocalCarrier = netip.PrefixFrom(cfg.RemoteCarrier, cfg.LocalCarrier.Bits())
	reversed.RemoteCarrier = cfg.LocalCarrier.Addr()
	if len(underlayIf) > 0 {
		reversed.UnderlayIf = strings.TrimSpace(underlayIf[0])
	}
	return NormalizeKernelTunnelConfig(protocol, formatTunnelConfig(reversed, protocol == transport.ProtocolVXLAN)), nil
}

func formatTunnelConfig(cfg tunnelConfig, vxlan bool) string {
	fields := []string{
		fmt.Sprintf("local=%s", cfg.LocalUnderlay),
		fmt.Sprintf("remote=%s", cfg.RemoteUnderlay),
	}
	if cfg.UnderlayIf != "" {
		fields = append(fields, fmt.Sprintf("underlay_if=%s", cfg.UnderlayIf))
	}
	fields = append(fields,
		fmt.Sprintf("local_carrier=%s", cfg.LocalCarrier),
		fmt.Sprintf("remote_carrier=%s", cfg.RemoteCarrier),
		fmt.Sprintf("port=%d", cfg.CarrierPort),
		fmt.Sprintf("mtu=%d", cfg.MTU),
	)
	if cfg.Queues > 0 {
		fields = append(fields, fmt.Sprintf("queues=%d", cfg.Queues))
	}
	if vxlan {
		if cfg.VNI > 0 {
			fields = append(fields, fmt.Sprintf("vni=%d", cfg.VNI))
		}
		fields = append(fields, fmt.Sprintf("vxlan_port=%d", cfg.VXLANPort))
		if cfg.VXLANPortLow > 0 || cfg.VXLANPortHigh > 0 {
			fields = append(fields, fmt.Sprintf("src_port_low=%d", cfg.VXLANPortLow), fmt.Sprintf("src_port_high=%d", cfg.VXLANPortHigh))
		}
		if !cfg.VXLANUDPCSum {
			fields = append(fields, "udp_checksum=false")
		}
	}
	return strings.Join(fields, ",")
}

func parseTunnelValues(raw string) (map[string]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("tunnel endpoint config is required")
	}
	if strings.Contains(raw, "://") {
		parts := strings.SplitN(raw, "://", 2)
		raw = parts[1]
	}
	values := make(map[string]string)
	for _, field := range strings.Split(raw, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			return nil, fmt.Errorf("tunnel endpoint field %q must use key=value", field)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			return nil, fmt.Errorf("tunnel endpoint field %q is incomplete", field)
		}
		values[key] = value
	}
	return values, nil
}

func firstTunnelValue(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(values[key]); value != "" {
			return value
		}
	}
	return ""
}

func parseVXLANPortRange(values map[string]string) (uint16, uint16, bool, error) {
	if value := firstTunnelValue(values, "src_port", "srcport", "source_port_range", "vxlan_src_port"); value != "" {
		lowRaw, highRaw, ok := strings.Cut(value, "-")
		if !ok {
			lowRaw, highRaw, ok = strings.Cut(value, ":")
		}
		if !ok {
			return 0, 0, false, fmt.Errorf("parse VXLAN source port range %q: expected low-high", value)
		}
		low, err := parsePort16(strings.TrimSpace(lowRaw))
		if err != nil {
			return 0, 0, false, fmt.Errorf("parse VXLAN source port low %q: %w", lowRaw, err)
		}
		high, err := parsePort16(strings.TrimSpace(highRaw))
		if err != nil {
			return 0, 0, false, fmt.Errorf("parse VXLAN source port high %q: %w", highRaw, err)
		}
		if low > high {
			return 0, 0, false, fmt.Errorf("parse VXLAN source port range %q: low exceeds high", value)
		}
		return low, high, true, nil
	}
	lowRaw := firstTunnelValue(values, "src_port_low", "srcport_low", "source_port_low", "vxlan_src_port_low")
	highRaw := firstTunnelValue(values, "src_port_high", "srcport_high", "source_port_high", "vxlan_src_port_high")
	if lowRaw == "" && highRaw == "" {
		return 0, 0, false, nil
	}
	if lowRaw == "" || highRaw == "" {
		return 0, 0, false, fmt.Errorf("VXLAN source port range requires both low and high")
	}
	low, err := parsePort16(lowRaw)
	if err != nil {
		return 0, 0, false, fmt.Errorf("parse VXLAN source port low %q: %w", lowRaw, err)
	}
	high, err := parsePort16(highRaw)
	if err != nil {
		return 0, 0, false, fmt.Errorf("parse VXLAN source port high %q: %w", highRaw, err)
	}
	if low > high {
		return 0, 0, false, fmt.Errorf("VXLAN source port range low %d exceeds high %d", low, high)
	}
	return low, high, true, nil
}

func parsePort16(value string) (uint16, error) {
	port, err := strconv.ParseUint(strings.TrimSpace(value), 10, 16)
	if err != nil || port == 0 {
		if err == nil {
			err = fmt.Errorf("port must be non-zero")
		}
		return 0, err
	}
	return uint16(port), nil
}

func parseTunnelBool(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "enabled":
		return true, nil
	case "0", "false", "no", "off", "disabled":
		return false, nil
	default:
		return false, fmt.Errorf("expected boolean")
	}
}

func requiredTunnelAddr(values map[string]string, key string) (netip.Addr, error) {
	value := strings.TrimSpace(values[key])
	if value == "" {
		return netip.Addr{}, fmt.Errorf("tunnel endpoint requires %s", key)
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse tunnel %s IPv4 address %q: %w", key, value, err)
	}
	if !addr.Is4() {
		return netip.Addr{}, fmt.Errorf("parse tunnel %s IPv4 address %q: not IPv4", key, value)
	}
	return addr, nil
}

func requiredTunnelPrefix(values map[string]string, key string) (netip.Prefix, error) {
	value := strings.TrimSpace(values[key])
	if value == "" {
		return netip.Prefix{}, fmt.Errorf("tunnel endpoint requires %s", key)
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse tunnel %s IPv4 prefix %q: %w", key, value, err)
	}
	if !prefix.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("parse tunnel %s IPv4 prefix %q: not IPv4", key, value)
	}
	return prefix, nil
}

func encodeCarrier(payload []byte, sequence uint64) ([]byte, error) {
	if len(payload) > carrierMaxPacket {
		return nil, fmt.Errorf("tunnel carrier packet size %d exceeds max %d", len(payload), carrierMaxPacket)
	}
	if len(payload) > carrierMaxUnfragmentedPacket {
		return nil, fmt.Errorf("tunnel carrier packet size %d exceeds header capacity", len(payload))
	}
	out := make([]byte, carrierHeaderLen+len(payload))
	if err := encodeCarrierInto(out, payload, sequence); err != nil {
		return nil, err
	}
	return out, nil
}

func encodeCarrierInto(out []byte, payload []byte, sequence uint64) error {
	if len(payload) > carrierMaxPacket {
		return fmt.Errorf("tunnel carrier packet size %d exceeds max %d", len(payload), carrierMaxPacket)
	}
	if len(payload) > carrierMaxUnfragmentedPacket {
		return fmt.Errorf("tunnel carrier packet size %d exceeds header capacity", len(payload))
	}
	if len(out) < carrierHeaderLen+len(payload) {
		return fmt.Errorf("tunnel carrier output buffer size %d is smaller than frame %d", len(out), carrierHeaderLen+len(payload))
	}
	if err := encodeCarrierHeaderInto(out[:carrierHeaderLen], len(payload), sequence); err != nil {
		return err
	}
	copy(out[carrierHeaderLen:], payload)
	return nil
}

func encodeCarrierHeaderInto(out []byte, payloadLen int, sequence uint64) error {
	return encodeCarrierTypedHeaderInto(out, carrierTypeData, payloadLen, sequence)
}

func encodeCarrierTypedHeaderInto(out []byte, frameType byte, payloadLen int, sequence uint64) error {
	if payloadLen > carrierMaxPacket {
		return fmt.Errorf("tunnel carrier packet size %d exceeds max %d", payloadLen, carrierMaxPacket)
	}
	if payloadLen > carrierMaxUnfragmentedPacket {
		return fmt.Errorf("tunnel carrier packet size %d exceeds header capacity", payloadLen)
	}
	if len(out) < carrierHeaderLen {
		return fmt.Errorf("tunnel carrier header output buffer size %d is smaller than header %d", len(out), carrierHeaderLen)
	}
	copy(out[0:4], carrierMagic[:])
	out[4] = carrierVersion
	out[5] = frameType
	binary.BigEndian.PutUint16(out[6:8], uint16(payloadLen))
	binary.BigEndian.PutUint64(out[8:16], sequence)
	return nil
}

func encodeCarrierFragmentHeaderInto(out []byte, fragmentLen int, sequence uint64, totalLen int, offset int) error {
	if totalLen <= 0 || totalLen > carrierMaxPacket {
		return fmt.Errorf("tunnel carrier fragment total size %d exceeds max %d", totalLen, carrierMaxPacket)
	}
	if offset < 0 || fragmentLen <= 0 || offset+fragmentLen > totalLen {
		return fmt.Errorf("invalid tunnel carrier fragment offset=%d len=%d total=%d", offset, fragmentLen, totalLen)
	}
	payloadLen := carrierFragmentHeaderLen + fragmentLen
	if len(out) < carrierHeaderLen+carrierFragmentHeaderLen {
		return fmt.Errorf("tunnel carrier fragment header output buffer size %d is smaller than header %d", len(out), carrierHeaderLen+carrierFragmentHeaderLen)
	}
	if err := encodeCarrierTypedHeaderInto(out[:carrierHeaderLen], carrierTypeFragment, payloadLen, sequence); err != nil {
		return err
	}
	binary.BigEndian.PutUint32(out[carrierHeaderLen:carrierHeaderLen+4], uint32(totalLen))
	binary.BigEndian.PutUint32(out[carrierHeaderLen+4:carrierHeaderLen+8], uint32(offset))
	return nil
}

func decodeCarrier(wire []byte) ([]byte, uint64, error) {
	payload, sequence, err := decodeCarrierView(wire)
	if err != nil {
		return nil, 0, err
	}
	return append([]byte(nil), payload...), sequence, nil
}

func decodeCarrierView(wire []byte) ([]byte, uint64, error) {
	frame, err := decodeCarrierFrameView(wire)
	if err != nil {
		return nil, 0, err
	}
	if frame.frameType != carrierTypeData {
		return nil, 0, fmt.Errorf("tunnel carrier frame is not data")
	}
	return frame.payload, frame.sequence, nil
}

func decodeCarrierFrameView(wire []byte) (carrierReceivedPacket, error) {
	if len(wire) < carrierHeaderLen {
		return carrierReceivedPacket{}, fmt.Errorf("tunnel carrier frame too short: %d", len(wire))
	}
	if wire[0] != carrierMagic[0] || wire[1] != carrierMagic[1] || wire[2] != carrierMagic[2] || wire[3] != carrierMagic[3] || wire[4] != carrierVersion {
		return carrierReceivedPacket{}, fmt.Errorf("invalid tunnel carrier header")
	}
	frameType := wire[5]
	payloadLen := int(binary.BigEndian.Uint16(wire[6:8]))
	if payloadLen != len(wire)-carrierHeaderLen {
		return carrierReceivedPacket{}, fmt.Errorf("tunnel carrier payload length %d != wire payload %d", payloadLen, len(wire)-carrierHeaderLen)
	}
	sequence := binary.BigEndian.Uint64(wire[8:16])
	payload := wire[carrierHeaderLen:]
	switch frameType {
	case carrierTypeData:
		return carrierReceivedPacket{
			payload:   payload,
			wireLen:   len(wire),
			sequence:  sequence,
			frameType: frameType,
		}, nil
	case carrierTypeFragment:
		if payloadLen < carrierFragmentHeaderLen {
			return carrierReceivedPacket{}, fmt.Errorf("tunnel carrier fragment payload too short: %d", payloadLen)
		}
		totalLen := int(binary.BigEndian.Uint32(payload[0:4]))
		offset := int(binary.BigEndian.Uint32(payload[4:8]))
		fragment := payload[carrierFragmentHeaderLen:]
		if totalLen <= 0 || totalLen > carrierMaxPacket {
			return carrierReceivedPacket{}, fmt.Errorf("tunnel carrier fragment total size %d exceeds max %d", totalLen, carrierMaxPacket)
		}
		if len(fragment) == 0 || offset < 0 || offset+len(fragment) > totalLen {
			return carrierReceivedPacket{}, fmt.Errorf("invalid tunnel carrier fragment offset=%d len=%d total=%d", offset, len(fragment), totalLen)
		}
		return carrierReceivedPacket{
			payload:   fragment,
			wireLen:   len(wire),
			sequence:  sequence,
			frameType: frameType,
			totalLen:  totalLen,
			offset:    offset,
		}, nil
	default:
		return carrierReceivedPacket{}, fmt.Errorf("unsupported tunnel carrier frame type %d", frameType)
	}
}

func carrierUDPPayloadSizeForMTU(mtu int) int {
	if mtu <= carrierIPv4UDPHeaderLen {
		return 0
	}
	return min(mtu-carrierIPv4UDPHeaderLen, carrierMaxUDPPayload)
}

func carrierMaxFragmentPayloadForMTUWithMode(mtu int, kernelFragment bool) int {
	if kernelFragment {
		return carrierMaxUDPPayload - carrierHeaderLen - carrierFragmentHeaderLen
	}
	maxPayload := carrierUDPPayloadSizeForMTU(mtu) - carrierHeaderLen - carrierFragmentHeaderLen
	if wireMax := carrierMaxUnfragmentedPacket - carrierFragmentHeaderLen; maxPayload > wireMax {
		maxPayload = wireMax
	}
	return maxPayload
}

func carrierMaxFragmentPayloadForMTU(mtu int) int {
	return carrierMaxFragmentPayloadForMTUWithMode(mtu, carrierKernelFragmentEnabled())
}

func carrierPacketFitsUnfragmentedWithMode(packetLen int, mtu int, kernelFragment bool) bool {
	if kernelFragment {
		return packetLen <= carrierMaxUnfragmentedPacket
	}
	return packetLen <= carrierMaxUnfragmentedPacket &&
		packetLen+carrierHeaderLen <= carrierUDPPayloadSizeForMTU(mtu)
}

func carrierPacketFitsUnfragmented(packetLen int, mtu int) bool {
	return carrierPacketFitsUnfragmentedWithMode(packetLen, mtu, carrierKernelFragmentEnabled())
}

func carrierReadWireSizeForMTUWithMode(mtu int, kernelFragment bool) int {
	if kernelFragment {
		return carrierMaxUDPPayload
	}
	return carrierUDPPayloadSizeForMTU(mtu)
}

func carrierReadWireSizeForMTU(mtu int) int {
	return carrierReadWireSizeForMTUWithMode(mtu, carrierKernelFragmentEnabled())
}

func carrierReceiveWireSize() int {
	// Always accept legacy/kernel-fragmented carrier datagrams during rolling
	// upgrades, even when this side uses MTU-bounded application fragments.
	return carrierMaxUDPPayload
}

func carrierMaxUnfragmentedPayloadForMTUWithMode(mtu int, kernelFragment bool) int {
	if kernelFragment {
		return carrierMaxUnfragmentedPacket
	}
	return max(0, carrierUDPPayloadSizeForMTU(mtu)-carrierHeaderLen)
}

func carrierMaxUnfragmentedPayloadForMTU(mtu int) int {
	return carrierMaxUnfragmentedPayloadForMTUWithMode(mtu, carrierKernelFragmentEnabled())
}

func boolUint64(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}

func carrierPacketFragmentCountWithMode(packetLen int, mtu int, kernelFragment bool) (int, error) {
	if packetLen <= 0 {
		return 0, nil
	}
	if packetLen > carrierMaxPacket {
		return 0, fmt.Errorf("tunnel carrier packet size %d exceeds max %d", packetLen, carrierMaxPacket)
	}
	maxPayload := carrierMaxFragmentPayloadForMTUWithMode(mtu, kernelFragment)
	if maxPayload <= 0 {
		return 0, fmt.Errorf("tunnel carrier mtu %d cannot carry fragment header", mtu)
	}
	return (packetLen + maxPayload - 1) / maxPayload, nil
}

func carrierPacketFragmentCount(packetLen int, mtu int) (int, error) {
	return carrierPacketFragmentCountWithMode(packetLen, mtu, carrierKernelFragmentEnabled())
}

func buildCarrierFragmentPacketsWithMode(packetScratch []carrierBatchPacket, headerArena []byte, pkt []byte, sequence uint64, mtu int, kernelFragment bool) ([]carrierBatchPacket, []byte, error) {
	fragments, err := carrierPacketFragmentCountWithMode(len(pkt), mtu, kernelFragment)
	if err != nil {
		return nil, headerArena, err
	}
	if fragments == 0 {
		return packetScratch[:0], headerArena[:0], nil
	}
	if cap(packetScratch) < fragments {
		packetScratch = make([]carrierBatchPacket, fragments)
	} else {
		packetScratch = packetScratch[:fragments]
		clear(packetScratch)
	}
	headerBytes := fragments * (carrierHeaderLen + carrierFragmentHeaderLen)
	if cap(headerArena) < headerBytes {
		headerArena = make([]byte, headerBytes)
	} else {
		headerArena = headerArena[:headerBytes]
		clear(headerArena)
	}
	maxPayload := carrierMaxFragmentPayloadForMTUWithMode(mtu, kernelFragment)
	for i, offset := 0, 0; offset < len(pkt); i, offset = i+1, offset+maxPayload {
		end := offset + maxPayload
		if end > len(pkt) {
			end = len(pkt)
		}
		header := headerArena[i*(carrierHeaderLen+carrierFragmentHeaderLen) : (i+1)*(carrierHeaderLen+carrierFragmentHeaderLen)]
		if err := encodeCarrierFragmentHeaderInto(header, end-offset, sequence, len(pkt), offset); err != nil {
			clear(packetScratch)
			return nil, headerArena, err
		}
		packetScratch[i] = carrierBatchPacket{header: header, payload: pkt[offset:end]}
	}
	return packetScratch, headerArena, nil
}

func buildCarrierFragmentPackets(packetScratch []carrierBatchPacket, headerArena []byte, pkt []byte, sequence uint64, mtu int) ([]carrierBatchPacket, []byte, error) {
	return buildCarrierFragmentPacketsWithMode(packetScratch, headerArena, pkt, sequence, mtu, carrierKernelFragmentEnabled())
}

func (reassembler *carrierReassembler) accept(packet carrierReceivedPacket) (carrierReceivedPacket, bool, bool) {
	if packet.frameType != carrierTypeFragment {
		return packet, true, false
	}
	if packet.totalLen <= 0 || packet.totalLen > carrierMaxPacket || packet.offset < 0 || len(packet.payload) == 0 || packet.offset+len(packet.payload) > packet.totalLen {
		return carrierReceivedPacket{}, false, true
	}
	if reassembler.assemblies == nil {
		reassembler.assemblies = make(map[uint64]*carrierFragmentAssembly)
	}
	assembly := reassembler.assemblies[packet.sequence]
	if assembly != nil && assembly.totalLen != packet.totalLen {
		delete(reassembler.assemblies, packet.sequence)
		reassembler.removeOrder(packet.sequence)
		putCarrierReassemblyBuffer(assembly.data)
		assembly = nil
	}
	if assembly == nil {
		if len(reassembler.assemblies) >= carrierReassemblyMaxPackets {
			reassembler.dropOldest()
		}
		assembly = &carrierFragmentAssembly{
			totalLen: packet.totalLen,
			data:     takeCarrierReassemblyBuffer(packet.totalLen),
		}
		reassembler.assemblies[packet.sequence] = assembly
		reassembler.order = append(reassembler.order, packet.sequence)
	}
	added, ok := assembly.add(packet.offset, packet.payload)
	if !ok {
		delete(reassembler.assemblies, packet.sequence)
		reassembler.removeOrder(packet.sequence)
		putCarrierReassemblyBuffer(assembly.data)
		return carrierReceivedPacket{}, false, true
	}
	assembly.received += added
	assembly.wireLen += packet.wireLen
	if assembly.received < assembly.totalLen {
		return carrierReceivedPacket{}, false, false
	}
	delete(reassembler.assemblies, packet.sequence)
	reassembler.removeOrder(packet.sequence)
	return carrierReceivedPacket{
		payload:    assembly.data[:assembly.totalLen],
		wireLen:    assembly.wireLen,
		reassembly: assembly.data,
		sequence:   packet.sequence,
		frameType:  carrierTypeData,
	}, true, false
}

func (assembly *carrierFragmentAssembly) add(start int, payload []byte) (int, bool) {
	end := start + len(payload)
	if start < 0 || len(payload) == 0 || end > assembly.totalLen {
		return 0, false
	}
	for _, existing := range assembly.ranges {
		if end <= existing.start || start >= existing.end {
			continue
		}
		if start >= existing.start && end <= existing.end {
			return 0, true
		}
		return 0, false
	}
	copy(assembly.data[start:end], payload)
	assembly.ranges = append(assembly.ranges, carrierFragmentRange{start: start, end: end})
	sort.Slice(assembly.ranges, func(i, j int) bool {
		return assembly.ranges[i].start < assembly.ranges[j].start
	})
	merged := assembly.ranges[:0]
	for _, next := range assembly.ranges {
		if len(merged) == 0 || next.start > merged[len(merged)-1].end {
			merged = append(merged, next)
			continue
		}
		if next.end > merged[len(merged)-1].end {
			merged[len(merged)-1].end = next.end
		}
	}
	assembly.ranges = merged
	return len(payload), true
}

func (reassembler *carrierReassembler) dropOldest() {
	for len(reassembler.order) > 0 {
		sequence := reassembler.order[0]
		copy(reassembler.order, reassembler.order[1:])
		reassembler.order = reassembler.order[:len(reassembler.order)-1]
		if assembly, ok := reassembler.assemblies[sequence]; ok {
			delete(reassembler.assemblies, sequence)
			if assembly != nil {
				putCarrierReassemblyBuffer(assembly.data)
			}
			return
		}
	}
}

func (reassembler *carrierReassembler) releaseAll() {
	for sequence, assembly := range reassembler.assemblies {
		delete(reassembler.assemblies, sequence)
		if assembly != nil {
			putCarrierReassemblyBuffer(assembly.data)
		}
	}
	clear(reassembler.order)
	reassembler.order = reassembler.order[:0]
}

func (reassembler *carrierReassembler) removeOrder(sequence uint64) {
	for i, value := range reassembler.order {
		if value != sequence {
			continue
		}
		copy(reassembler.order[i:], reassembler.order[i+1:])
		reassembler.order = reassembler.order[:len(reassembler.order)-1]
		return
	}
}

func randomTunnelName(prefix string) (string, error) {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("tix%s%x", prefix, raw[:]), nil
}

func tunnelNamePrefix(protocol string) string {
	switch transport.Protocol(strings.ToLower(strings.TrimSpace(protocol))) {
	case transport.ProtocolIPIP:
		return "ip"
	case transport.ProtocolVXLAN:
		return "vx"
	default:
		return "gr"
	}
}

func listenUDPOnCarrier(ctx context.Context, addr netip.Addr, port uint16) (*net.UDPConn, error) {
	udpAddr := net.UDPAddr{IP: net.IP(addr.AsSlice()), Port: int(port)}
	conn, err := net.ListenUDP("udp4", &udpAddr)
	if err != nil {
		return nil, err
	}
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	return conn, nil
}

func dialUDPOnCarrier(ctx context.Context, local netip.Addr, remote netip.Addr, port uint16) (*net.UDPConn, error) {
	dialer := net.Dialer{LocalAddr: &net.UDPAddr{IP: net.IP(local.AsSlice()), Port: 0}}
	conn, err := dialer.DialContext(ctx, "udp4", net.JoinHostPort(remote.String(), strconv.Itoa(int(port))))
	if err != nil {
		return nil, err
	}
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		return nil, errors.Join(
			fmt.Errorf("dial tunnel carrier returned %T", conn),
			wrapManagerError("close unexpected tunnel carrier connection", conn.Close()),
		)
	}
	return udpConn, nil
}

func (session *carrier) SendPacket(pkt []byte) error {
	mtu := effectiveTunnelMTU(session.cfg.MTU)
	kernelFragment := carrierKernelFragmentEnabledForConfig(session.cfg)
	if len(pkt) > carrierMaxPacket {
		session.mtuDrops.Add(1)
		return fmt.Errorf("tunnel carrier packet size %d exceeds max %d", len(pkt), carrierMaxPacket)
	}
	seq := session.sendSeq.Add(1)
	if !carrierPacketFitsUnfragmentedWithMode(len(pkt), mtu, kernelFragment) {
		return session.sendFragmentedPacket(pkt, seq, mtu)
	}
	needed := carrierHeaderLen + len(pkt)
	if cap(session.sendWire) < needed {
		session.sendWire = make([]byte, needed)
	} else {
		session.sendWire = session.sendWire[:needed]
	}
	if err := encodeCarrierInto(session.sendWire, pkt, seq); err != nil {
		return err
	}
	n, err := session.conn.Write(session.sendWire)
	if err != nil {
		return err
	}
	session.bytesSent.Add(uint64(n))
	session.packetsSent.Add(1)
	return nil
}

func (session *carrier) sendFragmentedPacket(pkt []byte, sequence uint64, mtu int) error {
	kernelFragment := carrierKernelFragmentEnabledForConfig(session.cfg)
	fragments, err := carrierPacketFragmentCountWithMode(len(pkt), mtu, kernelFragment)
	if err != nil {
		session.mtuDrops.Add(1)
		return err
	}
	batch, headers, err := buildCarrierFragmentPacketsWithMode(session.sendBatchPacketScratch, session.sendBatchArena, pkt, sequence, mtu, kernelFragment)
	session.sendBatchPacketScratch = batch
	session.sendBatchArena = headers
	if err != nil {
		session.mtuDrops.Add(1)
		return err
	}
	result, err := sendCarrierPacketBatch(session.conn, batch)
	clear(batch)
	session.sendBatchPacketScratch = batch[:0]
	session.sendBatchArena = retainCarrierSendBatchArena(headers, len(headers))
	if err != nil {
		return err
	}
	session.bytesSent.Add(result.bytesSent)
	session.packetsSent.Add(1)
	session.fragmentedPacketsSent.Add(1)
	session.fragmentsSent.Add(uint64(fragments))
	session.recordBatchSend(1, result)
	return nil
}

func (session *carrier) SendPackets(pkts [][]byte) error {
	if len(pkts) == 0 {
		return nil
	}
	if len(pkts) == 1 {
		return session.SendPacket(pkts[0])
	}
	mtu := effectiveTunnelMTU(session.cfg.MTU)
	kernelFragment := carrierKernelFragmentEnabledForConfig(session.cfg)
	for _, pkt := range pkts {
		if len(pkt) > carrierMaxPacket {
			session.mtuDrops.Add(1)
			return fmt.Errorf("tunnel carrier packet size %d exceeds max %d", len(pkt), carrierMaxPacket)
		}
	}
	if carrierPacketBatchNeedsFragmentationWithMode(pkts, mtu, kernelFragment) {
		for _, pkt := range pkts {
			if err := session.SendPacket(pkt); err != nil {
				return err
			}
		}
		return nil
	}
	if !carrierSendScatterGatherEnabled() {
		return session.sendPacketsContiguous(pkts)
	}
	if cap(session.sendBatchPacketScratch) < len(pkts) {
		session.sendBatchPacketScratch = make([]carrierBatchPacket, len(pkts))
	} else {
		session.sendBatchPacketScratch = session.sendBatchPacketScratch[:len(pkts)]
	}
	headerBytes := carrierHeaderLen * len(pkts)
	if cap(session.sendBatchArena) < headerBytes {
		session.sendBatchArena = make([]byte, headerBytes)
	}
	headers := session.sendBatchArena[:headerBytes]
	baseSeq := session.sendSeq.Add(uint64(len(pkts))) - uint64(len(pkts)) + 1
	for i, pkt := range pkts {
		header := headers[i*carrierHeaderLen : (i+1)*carrierHeaderLen]
		if err := encodeCarrierHeaderInto(header, len(pkt), baseSeq+uint64(i)); err != nil {
			session.sendBatchArena = headers
			clear(session.sendBatchPacketScratch)
			return err
		}
		session.sendBatchPacketScratch[i] = carrierBatchPacket{header: header, payload: pkt}
	}
	session.sendBatchArena = retainCarrierSendBatchArena(headers, headerBytes)
	batch := session.sendBatchPacketScratch
	result, err := sendCarrierPacketBatch(session.conn, batch)
	clear(batch)
	session.sendBatchPacketScratch = batch[:0]
	if err != nil {
		return err
	}
	session.bytesSent.Add(result.bytesSent)
	session.packetsSent.Add(uint64(len(pkts)))
	session.recordBatchSend(uint64(len(pkts)), result)
	return nil
}

func carrierPacketBatchNeedsFragmentationWithMode(pkts [][]byte, mtu int, kernelFragment bool) bool {
	for _, pkt := range pkts {
		if !carrierPacketFitsUnfragmentedWithMode(len(pkt), mtu, kernelFragment) {
			return true
		}
	}
	return false
}

func carrierPacketBatchNeedsFragmentation(pkts [][]byte, mtu int) bool {
	return carrierPacketBatchNeedsFragmentationWithMode(pkts, mtu, carrierKernelFragmentEnabled())
}

func (session *carrier) sendPacketsContiguous(pkts [][]byte) error {
	totalWire := 0
	for _, pkt := range pkts {
		totalWire += carrierHeaderLen + len(pkt)
	}
	if cap(session.sendBatchWire) < len(pkts) {
		session.sendBatchWire = make([][]byte, len(pkts))
	} else {
		session.sendBatchWire = session.sendBatchWire[:len(pkts)]
	}
	if cap(session.sendBatchArena) < totalWire {
		session.sendBatchArena = make([]byte, 0, totalWire)
	}
	arena := session.sendBatchArena[:0]
	baseSeq := session.sendSeq.Add(uint64(len(pkts))) - uint64(len(pkts)) + 1
	for i, pkt := range pkts {
		base := len(arena)
		needed := carrierHeaderLen + len(pkt)
		arena = arena[:base+needed]
		if err := encodeCarrierInto(arena[base:base+needed], pkt, baseSeq+uint64(i)); err != nil {
			session.sendBatchArena = retainCarrierSendBatchArena(arena, totalWire)
			clear(session.sendBatchWire)
			return err
		}
		session.sendBatchWire[i] = arena[base : base+needed]
	}
	session.sendBatchArena = retainCarrierSendBatchArena(arena, totalWire)
	batch := session.sendBatchWire
	result, err := sendCarrierBatch(session.conn, batch)
	clear(batch)
	session.sendBatchWire = batch[:0]
	if err != nil {
		return err
	}
	session.bytesSent.Add(result.bytesSent)
	session.packetsSent.Add(uint64(len(pkts)))
	session.recordBatchSend(uint64(len(pkts)), result)
	return nil
}

func retainCarrierSendBatchArena(arena []byte, used int) []byte {
	if cap(arena) > carrierSendBatchArenaRetainMax && used < carrierSendBatchArenaRetainMax/2 {
		return nil
	}
	return arena
}

func (session *carrier) RecvPacket() ([]byte, error) {
	packets, err := session.RecvPackets(1)
	if err != nil {
		return nil, err
	}
	if len(packets) == 0 {
		return session.RecvPacket()
	}
	return packets[0], nil
}

func (session *carrier) RecvPackets(max int) ([][]byte, error) {
	packets, release, err := session.RecvPacketsWithRelease(max)
	if err != nil || release == nil {
		return packets, err
	}
	copied := make([][]byte, len(packets))
	for i, packet := range packets {
		copied[i] = append([]byte(nil), packet...)
	}
	release()
	return copied, nil
}

func (session *carrier) RecvPacketsWithRelease(max int) ([][]byte, func(), error) {
	if max <= 0 {
		max = 1
	}
	session.recvMu.Lock()
	defer session.recvMu.Unlock()
	for {
		received, result, release, err := recvCarrierBatch(session.conn, max, carrierReceiveWireSize())
		if err != nil {
			return nil, nil, err
		}
		completed := session.completeReceivedPackets(received)
		session.recordReceivedPackets(uint64(len(completed)), completedWireLen(completed))
		session.recordBatchReceive(uint64(len(received)), result)
		if len(completed) == 0 {
			if release != nil {
				release()
			}
			continue
		}
		packets := make([][]byte, 0, len(completed))
		reassemblies := make([][]byte, 0, len(completed))
		for _, packet := range completed {
			packets = append(packets, packet.payload)
			if packet.reassembly != nil {
				reassemblies = append(reassemblies, packet.reassembly)
			}
		}
		return packets, releaseCarrierReceivedBatch(release, reassemblies), nil
	}
}

func releaseCarrierReceivedBatch(release func(), reassemblies [][]byte) func() {
	if release == nil && len(reassemblies) == 0 {
		return nil
	}
	return func() {
		if release != nil {
			release()
		}
		for _, buf := range reassemblies {
			putCarrierReassemblyBuffer(buf)
		}
	}
}

func (session *carrier) completeReceivedPackets(received []carrierReceivedPacket) []carrierReceivedPacket {
	if len(received) == 0 {
		return nil
	}
	completed := make([]carrierReceivedPacket, 0, len(received))
	for _, packet := range received {
		if packet.frameType == carrierTypeFragment {
			session.fragmentsReceived.Add(1)
		}
		complete, ok, dropped := session.reassembler.accept(packet)
		if dropped {
			session.fragmentDrops.Add(1)
		}
		if !ok {
			continue
		}
		if packet.frameType == carrierTypeFragment {
			session.reassembledPackets.Add(1)
		}
		completed = append(completed, complete)
	}
	return completed
}

func completedWireLen(packets []carrierReceivedPacket) uint64 {
	var total uint64
	for _, packet := range packets {
		total += uint64(packet.wireLen)
	}
	return total
}

func (session *carrier) readCarrierPacket() ([]byte, int, []byte, error) {
	buf := takeCarrierReadBuffer(carrierReceiveWireSize())
	n, err := session.conn.Read(buf)
	if err != nil {
		putCarrierReadBuffer(buf)
		return nil, 0, nil, err
	}
	payload, _, err := decodeCarrierView(buf[:n])
	if err != nil {
		session.decodeErrors.Add(1)
		putCarrierReadBuffer(buf)
		return nil, 0, nil, err
	}
	return payload, n, buf, nil
}

func (session *carrier) recordReceivedPackets(packets uint64, bytes uint64) {
	session.bytesReceived.Add(bytes)
	session.packetsReceived.Add(packets)
}

func (session *carrier) Close() error {
	session.closeOnce.Do(func() {
		var errs []error
		if session.conn != nil {
			if err := session.conn.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close tunnel carrier connection: %w", err))
			}
		}
		if session.closeFunc != nil {
			if err := session.closeFunc(); err != nil {
				errs = append(errs, fmt.Errorf("release kernel tunnel: %w", err))
			}
		}
		session.recvMu.Lock()
		session.reassembler.releaseAll()
		session.recvMu.Unlock()
		session.closeErr = errors.Join(errs...)
	})
	return session.closeErr
}

func (session *carrier) Stats() transport.TransportStats {
	mtu := effectiveTunnelMTU(session.cfg.MTU)
	kernelFragment := carrierKernelFragmentEnabledForConfig(session.cfg)
	return transport.TransportStats{
		BytesSent:           session.bytesSent.Load(),
		BytesReceived:       session.bytesReceived.Load(),
		PacketsSent:         session.packetsSent.Load(),
		PacketsReceived:     session.packetsReceived.Load(),
		NativeBatching:      true,
		Datagram:            true,
		FragmentingDatagram: true,
		MaxPacketSize:       uint64(carrierMaxPacket),
		Extra: map[string]uint64{
			"iptunnel_carrier_port":             uint64(session.cfg.CarrierPort),
			"iptunnel_mtu":                      uint64(mtu),
			"iptunnel_kernel_fragment":          boolUint64(kernelFragment),
			"iptunnel_udp_payload_size":         uint64(carrierReadWireSizeForMTUWithMode(mtu, kernelFragment)),
			"iptunnel_wire_max_packet_size":     uint64(carrierMaxUnfragmentedPayloadForMTUWithMode(mtu, kernelFragment)),
			"iptunnel_fragment_payload_size":    uint64(max(0, carrierMaxFragmentPayloadForMTUWithMode(mtu, kernelFragment))),
			"iptunnel_decode_errors":            session.decodeErrors.Load(),
			"iptunnel_mtu_drops":                session.mtuDrops.Load(),
			"iptunnel_send_batch_calls":         session.sendBatchCalls.Load(),
			"iptunnel_send_batch_packets":       session.sendBatchPackets.Load(),
			"iptunnel_send_batch_bytes":         session.sendBatchBytes.Load(),
			"iptunnel_send_batch_mmsg_syscalls": session.sendBatchMMSGSyscalls.Load(),
			"iptunnel_send_batch_gso_syscalls":  session.sendBatchGSOSyscalls.Load(),
			"iptunnel_send_batch_loop_syscalls": session.sendBatchLoopSyscalls.Load(),
			"iptunnel_send_batch_fallbacks":     session.sendBatchFallbacks.Load(),
			"iptunnel_recv_batch_calls":         session.recvBatchCalls.Load(),
			"iptunnel_recv_batch_packets":       session.recvBatchPackets.Load(),
			"iptunnel_recv_batch_bytes":         session.recvBatchBytes.Load(),
			"iptunnel_recv_batch_mmsg_syscalls": session.recvBatchMMSGSyscalls.Load(),
			"iptunnel_recv_batch_loop_syscalls": session.recvBatchLoopSyscalls.Load(),
			"iptunnel_recv_batch_fallbacks":     session.recvBatchFallbacks.Load(),
			"iptunnel_fragmented_packets_sent":  session.fragmentedPacketsSent.Load(),
			"iptunnel_fragments_sent":           session.fragmentsSent.Load(),
			"iptunnel_fragments_received":       session.fragmentsReceived.Load(),
			"iptunnel_reassembled_packets":      session.reassembledPackets.Load(),
			"iptunnel_fragment_drops":           session.fragmentDrops.Load(),
		},
	}
}

func (session *carrier) recordBatchSend(packets uint64, result carrierBatchSendResult) {
	session.sendBatchCalls.Add(1)
	session.sendBatchPackets.Add(packets)
	session.sendBatchBytes.Add(result.bytesSent)
	session.sendBatchMMSGSyscalls.Add(result.mmsgSyscalls)
	session.sendBatchGSOSyscalls.Add(result.gsoSyscalls)
	session.sendBatchLoopSyscalls.Add(result.loopSyscalls)
	session.sendBatchFallbacks.Add(result.fallbacks)
}

func (session *carrier) recordBatchReceive(packets uint64, result carrierBatchReceiveResult) {
	session.recvBatchCalls.Add(1)
	session.recvBatchPackets.Add(packets)
	session.recvBatchBytes.Add(result.bytesReceived)
	session.recvBatchMMSGSyscalls.Add(result.mmsgSyscalls)
	session.recvBatchLoopSyscalls.Add(result.loopSyscalls)
	session.recvBatchFallbacks.Add(result.fallbacks)
}

func newPacketListener(ctx context.Context, cfg tunnelConfig, conns []*net.UDPConn) *packetListener {
	if len(conns) == 0 {
		conns = []*net.UDPConn{nil}
	}
	listener := &packetListener{
		conn:     conns[0],
		conns:    conns,
		cfg:      cfg,
		acceptCh: make(chan transport.Session, 64),
		done:     make(chan struct{}),
		sessions: make(map[string]*carrierServerSession),
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for _, conn := range conns {
		if conn == nil {
			continue
		}
		go listener.readLoop(conn)
	}
	return listener
}

func (listener *packetListener) Accept(ctx context.Context) (transport.Session, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-listener.done:
		return nil, net.ErrClosed
	case session := <-listener.acceptCh:
		if session == nil {
			return nil, net.ErrClosed
		}
		return session, nil
	}
}

func (listener *packetListener) Close() error {
	listener.closeOnce.Do(func() {
		close(listener.done)
		var errs []error
		for _, conn := range listener.conns {
			if conn == nil {
				continue
			}
			if err := conn.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close tunnel listener connection: %w", err))
			}
		}
		listener.mu.Lock()
		for key, session := range listener.sessions {
			session.closeInput()
			delete(listener.sessions, key)
		}
		listener.mu.Unlock()
		listener.closeErr = errors.Join(errs...)
	})
	return listener.closeErr
}

func (listener *packetListener) readLoop(conn *net.UDPConn) {
	for {
		packets, _, release, err := recvCarrierBatchFrom(conn, carrierReadBatch(), carrierReceiveWireSize())
		if err != nil {
			if release != nil {
				release()
			}
			if udpReadErrorClosed(err) {
				_ = listener.Close()
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		listener.dispatchPackets(conn, packets)
		if release != nil {
			release()
		}
	}
}

func (listener *packetListener) dispatchPackets(conn *net.UDPConn, packets []carrierReceivedPacket) {
	for _, packet := range packets {
		if packet.addr == nil {
			putCarrierReadBuffer(packet.buffer)
			continue
		}
		key := packet.addr.String()
		listener.mu.Lock()
		session := listener.sessions[key]
		if session == nil {
			session = &carrierServerSession{
				conn:     conn,
				remote:   packet.addr,
				in:       make(chan carrierReceivedPacket, 256),
				listener: listener,
				key:      key,
			}
			listener.sessions[key] = session
			select {
			case listener.acceptCh <- session:
			default:
				delete(listener.sessions, key)
				close(session.in)
				listener.mu.Unlock()
				putCarrierReadBuffer(packet.buffer)
				continue
			}
		}
		listener.mu.Unlock()
		session.enqueue(packet)
	}
}

func carrierListenWorkers() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_IPTUNNEL_LISTEN_WORKERS"))
	if value == "" {
		workers := runtime.GOMAXPROCS(0)
		if workers > carrierListenWorkersDefault {
			workers = carrierListenWorkersDefault
		}
		if workers < 1 {
			workers = 1
		}
		return workers
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 1
	}
	if parsed > carrierListenWorkersMax {
		return carrierListenWorkersMax
	}
	return parsed
}

func carrierReadBatch() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_IPTUNNEL_READ_BATCH"))
	if value == "" {
		return carrierReadBatchDefault
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return carrierReadBatchDefault
	}
	if parsed > carrierReadBatchMax {
		return carrierReadBatchMax
	}
	return parsed
}

func carrierSendScatterGatherEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_IPTUNNEL_SEND_SG"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func carrierUDPSegmentEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_IPTUNNEL_UDP_SEGMENT"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return false
	}
}

func carrierKernelFragmentEnabledForConfig(cfg tunnelConfig) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_IPTUNNEL_KERNEL_FRAGMENT"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return cfg.Protocol != transport.ProtocolVXLAN
	}
}

func carrierKernelFragmentEnabled() bool {
	return carrierKernelFragmentEnabledForConfig(tunnelConfig{})
}

func udpReadErrorClosed(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "use of closed network connection") || strings.Contains(text, "closed network connection")
}

func udpReadErrorTimeout(err error) bool {
	if err == nil {
		return false
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "i/o timeout") || strings.Contains(text, "resource temporarily unavailable")
}

func (session *carrierServerSession) SendPacket(pkt []byte) error {
	mtu := defaultTunnelMTU
	if session.listener != nil {
		mtu = effectiveTunnelMTU(session.listener.cfg.MTU)
	}
	kernelFragment := session.kernelFragmentEnabled()
	if len(pkt) > carrierMaxPacket {
		session.mtuDrops.Add(1)
		return fmt.Errorf("tunnel carrier packet size %d exceeds max %d", len(pkt), carrierMaxPacket)
	}
	seq := session.sendSeq.Add(1)
	if !carrierPacketFitsUnfragmentedWithMode(len(pkt), mtu, kernelFragment) {
		return session.sendFragmentedPacket(pkt, seq, mtu)
	}
	needed := carrierHeaderLen + len(pkt)
	if cap(session.sendWire) < needed {
		session.sendWire = make([]byte, needed)
	} else {
		session.sendWire = session.sendWire[:needed]
	}
	if err := encodeCarrierInto(session.sendWire, pkt, seq); err != nil {
		return err
	}
	n, err := session.conn.WriteToUDP(session.sendWire, session.remote)
	if err != nil {
		return err
	}
	session.bytesSent.Add(uint64(n))
	session.packetsSent.Add(1)
	return nil
}

func (session *carrierServerSession) sendFragmentedPacket(pkt []byte, sequence uint64, mtu int) error {
	kernelFragment := session.kernelFragmentEnabled()
	fragments, err := carrierPacketFragmentCountWithMode(len(pkt), mtu, kernelFragment)
	if err != nil {
		session.mtuDrops.Add(1)
		return err
	}
	batch, headers, err := buildCarrierFragmentPacketsWithMode(session.sendBatchPacketScratch, session.sendBatchArena, pkt, sequence, mtu, kernelFragment)
	session.sendBatchPacketScratch = batch
	session.sendBatchArena = headers
	if err != nil {
		session.mtuDrops.Add(1)
		return err
	}
	result, err := sendCarrierPacketBatchTo(session.conn, session.remote, batch)
	clear(batch)
	session.sendBatchPacketScratch = batch[:0]
	session.sendBatchArena = retainCarrierSendBatchArena(headers, len(headers))
	if err != nil {
		return err
	}
	session.bytesSent.Add(result.bytesSent)
	session.packetsSent.Add(1)
	session.fragmentedPacketsSent.Add(1)
	session.fragmentsSent.Add(uint64(fragments))
	session.recordBatchSend(1, result)
	return nil
}

func (session *carrierServerSession) SendPackets(pkts [][]byte) error {
	if len(pkts) == 0 {
		return nil
	}
	if len(pkts) == 1 {
		return session.SendPacket(pkts[0])
	}
	mtu := defaultTunnelMTU
	if session.listener != nil {
		mtu = effectiveTunnelMTU(session.listener.cfg.MTU)
	}
	kernelFragment := session.kernelFragmentEnabled()
	for _, pkt := range pkts {
		if len(pkt) > carrierMaxPacket {
			session.mtuDrops.Add(1)
			return fmt.Errorf("tunnel carrier packet size %d exceeds max %d", len(pkt), carrierMaxPacket)
		}
	}
	if carrierPacketBatchNeedsFragmentationWithMode(pkts, mtu, kernelFragment) {
		for _, pkt := range pkts {
			if err := session.SendPacket(pkt); err != nil {
				return err
			}
		}
		return nil
	}
	if !carrierSendScatterGatherEnabled() {
		return session.sendPacketsContiguous(pkts)
	}
	if cap(session.sendBatchPacketScratch) < len(pkts) {
		session.sendBatchPacketScratch = make([]carrierBatchPacket, len(pkts))
	} else {
		session.sendBatchPacketScratch = session.sendBatchPacketScratch[:len(pkts)]
	}
	headerBytes := carrierHeaderLen * len(pkts)
	if cap(session.sendBatchArena) < headerBytes {
		session.sendBatchArena = make([]byte, headerBytes)
	}
	headers := session.sendBatchArena[:headerBytes]
	baseSeq := session.sendSeq.Add(uint64(len(pkts))) - uint64(len(pkts)) + 1
	for i, pkt := range pkts {
		header := headers[i*carrierHeaderLen : (i+1)*carrierHeaderLen]
		if err := encodeCarrierHeaderInto(header, len(pkt), baseSeq+uint64(i)); err != nil {
			session.sendBatchArena = headers
			clear(session.sendBatchPacketScratch)
			return err
		}
		session.sendBatchPacketScratch[i] = carrierBatchPacket{header: header, payload: pkt}
	}
	session.sendBatchArena = retainCarrierSendBatchArena(headers, headerBytes)
	batch := session.sendBatchPacketScratch
	result, err := sendCarrierPacketBatchTo(session.conn, session.remote, batch)
	clear(batch)
	session.sendBatchPacketScratch = batch[:0]
	if err != nil {
		return err
	}
	session.bytesSent.Add(result.bytesSent)
	session.packetsSent.Add(uint64(len(pkts)))
	session.recordBatchSend(uint64(len(pkts)), result)
	return nil
}

func (session *carrierServerSession) sendPacketsContiguous(pkts [][]byte) error {
	totalWire := 0
	for _, pkt := range pkts {
		totalWire += carrierHeaderLen + len(pkt)
	}
	if cap(session.sendBatchWire) < len(pkts) {
		session.sendBatchWire = make([][]byte, len(pkts))
	} else {
		session.sendBatchWire = session.sendBatchWire[:len(pkts)]
	}
	if cap(session.sendBatchArena) < totalWire {
		session.sendBatchArena = make([]byte, 0, totalWire)
	}
	arena := session.sendBatchArena[:0]
	baseSeq := session.sendSeq.Add(uint64(len(pkts))) - uint64(len(pkts)) + 1
	for i, pkt := range pkts {
		base := len(arena)
		needed := carrierHeaderLen + len(pkt)
		arena = arena[:base+needed]
		if err := encodeCarrierInto(arena[base:base+needed], pkt, baseSeq+uint64(i)); err != nil {
			session.sendBatchArena = retainCarrierSendBatchArena(arena, totalWire)
			clear(session.sendBatchWire)
			return err
		}
		session.sendBatchWire[i] = arena[base : base+needed]
	}
	session.sendBatchArena = retainCarrierSendBatchArena(arena, totalWire)
	batch := session.sendBatchWire
	result, err := sendCarrierBatchTo(session.conn, session.remote, batch)
	clear(batch)
	session.sendBatchWire = batch[:0]
	if err != nil {
		return err
	}
	session.bytesSent.Add(result.bytesSent)
	session.packetsSent.Add(uint64(len(pkts)))
	session.recordBatchSend(uint64(len(pkts)), result)
	return nil
}

func (session *carrierServerSession) RecvPacket() ([]byte, error) {
	packets, err := session.RecvPackets(1)
	if err != nil {
		return nil, err
	}
	if len(packets) == 0 {
		return session.RecvPacket()
	}
	return packets[0], nil
}

func (session *carrierServerSession) RecvPackets(max int) ([][]byte, error) {
	packets, release, err := session.RecvPacketsWithRelease(max)
	if err != nil || release == nil {
		return packets, err
	}
	copied := make([][]byte, len(packets))
	for i, packet := range packets {
		copied[i] = append([]byte(nil), packet...)
	}
	release()
	return copied, nil
}

func (session *carrierServerSession) RecvPacketsWithRelease(max int) ([][]byte, func(), error) {
	if max <= 1 {
		item, ok := <-session.in
		if !ok {
			return nil, nil, net.ErrClosed
		}
		session.bytesReceived.Add(uint64(item.wireLen))
		session.packetsReceived.Add(1)
		return [][]byte{item.payload}, func() { releaseCarrierReceivedPacket(item) }, nil
	}
	first, ok := <-session.in
	if !ok {
		return nil, nil, net.ErrClosed
	}
	packets := make([][]byte, 0, max)
	received := make([]carrierReceivedPacket, 0, max)
	packets = append(packets, first.payload)
	received = append(received, first)
	var bytes uint64
	bytes += uint64(first.wireLen)
	release := func() {
		for _, item := range received {
			releaseCarrierReceivedPacket(item)
		}
	}
	for len(packets) < max {
		select {
		case item, ok := <-session.in:
			if !ok {
				session.packetsReceived.Add(uint64(len(packets)))
				return packets, release, nil
			}
			packets = append(packets, item.payload)
			received = append(received, item)
			bytes += uint64(item.wireLen)
		default:
			session.bytesReceived.Add(bytes)
			session.packetsReceived.Add(uint64(len(packets)))
			session.recordBatchReceive(uint64(len(packets)), bytes)
			return packets, release, nil
		}
	}
	session.bytesReceived.Add(bytes)
	session.packetsReceived.Add(uint64(len(packets)))
	session.recordBatchReceive(uint64(len(packets)), bytes)
	return packets, release, nil
}

func (session *carrierServerSession) Close() error {
	session.closeOnce.Do(func() {
		if session.listener != nil {
			session.listener.mu.Lock()
			if session.listener.sessions[session.key] == session {
				delete(session.listener.sessions, session.key)
				session.closeInput()
			}
			session.listener.mu.Unlock()
		}
	})
	return nil
}

func (session *carrierServerSession) enqueue(pkt carrierReceivedPacket) {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		releaseCarrierReceivedPacket(pkt)
		return
	}
	if pkt.frameType == carrierTypeFragment {
		session.fragmentsReceived.Add(1)
	}
	complete, ok, dropped := session.reassembler.accept(pkt)
	if dropped {
		session.fragmentDrops.Add(1)
	}
	if pkt.frameType == carrierTypeFragment {
		putCarrierReadBuffer(pkt.buffer)
		if ok {
			session.reassembledPackets.Add(1)
		}
	} else {
		complete = pkt
	}
	if !ok {
		return
	}
	select {
	case session.in <- complete:
	default:
		releaseCarrierReceivedPacket(complete)
		session.packetsDropped.Add(1)
	}
}

func (session *carrierServerSession) closeInput() {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return
	}
	session.closed = true
	session.reassembler.releaseAll()
	close(session.in)
	for item := range session.in {
		releaseCarrierReceivedPacket(item)
	}
}

func releaseCarrierReceivedPacket(packet carrierReceivedPacket) {
	putCarrierReadBuffer(packet.buffer)
	if packet.reassembly != nil {
		putCarrierReassemblyBuffer(packet.reassembly)
	}
}

func (session *carrierServerSession) Stats() transport.TransportStats {
	mtu := session.listenerMTU()
	kernelFragment := session.kernelFragmentEnabled()
	return transport.TransportStats{
		BytesSent:           session.bytesSent.Load(),
		BytesReceived:       session.bytesReceived.Load(),
		PacketsSent:         session.packetsSent.Load(),
		PacketsReceived:     session.packetsReceived.Load(),
		NativeBatching:      true,
		Datagram:            true,
		FragmentingDatagram: true,
		MaxPacketSize:       uint64(carrierMaxPacket),
		Extra: map[string]uint64{
			"iptunnel_carrier_port":             uint64(session.listenerCarrierPort()),
			"iptunnel_mtu":                      uint64(mtu),
			"iptunnel_kernel_fragment":          boolUint64(kernelFragment),
			"iptunnel_udp_payload_size":         uint64(carrierReadWireSizeForMTUWithMode(mtu, kernelFragment)),
			"iptunnel_wire_max_packet_size":     uint64(carrierMaxUnfragmentedPayloadForMTUWithMode(mtu, kernelFragment)),
			"iptunnel_fragment_payload_size":    uint64(max(0, carrierMaxFragmentPayloadForMTUWithMode(mtu, kernelFragment))),
			"iptunnel_packets_dropped":          session.packetsDropped.Load(),
			"iptunnel_mtu_drops":                session.mtuDrops.Load(),
			"iptunnel_send_batch_calls":         session.sendBatchCalls.Load(),
			"iptunnel_send_batch_packets":       session.sendBatchPackets.Load(),
			"iptunnel_send_batch_bytes":         session.sendBatchBytes.Load(),
			"iptunnel_send_batch_mmsg_syscalls": session.sendBatchMMSGSyscalls.Load(),
			"iptunnel_send_batch_gso_syscalls":  session.sendBatchGSOSyscalls.Load(),
			"iptunnel_send_batch_loop_syscalls": session.sendBatchLoopSyscalls.Load(),
			"iptunnel_send_batch_fallbacks":     session.sendBatchFallbacks.Load(),
			"iptunnel_recv_batch_calls":         session.recvBatchCalls.Load(),
			"iptunnel_recv_batch_packets":       session.recvBatchPackets.Load(),
			"iptunnel_recv_batch_bytes":         session.recvBatchBytes.Load(),
			"iptunnel_fragmented_packets_sent":  session.fragmentedPacketsSent.Load(),
			"iptunnel_fragments_sent":           session.fragmentsSent.Load(),
			"iptunnel_fragments_received":       session.fragmentsReceived.Load(),
			"iptunnel_reassembled_packets":      session.reassembledPackets.Load(),
			"iptunnel_fragment_drops":           session.fragmentDrops.Load(),
		},
	}
}

func (session *carrierServerSession) recordBatchSend(packets uint64, result carrierBatchSendResult) {
	session.sendBatchCalls.Add(1)
	session.sendBatchPackets.Add(packets)
	session.sendBatchBytes.Add(result.bytesSent)
	session.sendBatchMMSGSyscalls.Add(result.mmsgSyscalls)
	session.sendBatchGSOSyscalls.Add(result.gsoSyscalls)
	session.sendBatchLoopSyscalls.Add(result.loopSyscalls)
	session.sendBatchFallbacks.Add(result.fallbacks)
}

func (session *carrierServerSession) recordBatchReceive(packets uint64, bytes uint64) {
	session.recvBatchCalls.Add(1)
	session.recvBatchPackets.Add(packets)
	session.recvBatchBytes.Add(bytes)
}

func (session *carrierServerSession) listenerCarrierPort() uint16 {
	if session == nil || session.listener == nil || session.listener.conn == nil {
		return 0
	}
	if addr, ok := session.listener.conn.LocalAddr().(*net.UDPAddr); ok {
		return uint16(addr.Port)
	}
	return 0
}

func (session *carrierServerSession) listenerMTU() int {
	if session == nil || session.listener == nil {
		return defaultTunnelMTU
	}
	return effectiveTunnelMTU(session.listener.cfg.MTU)
}

func (session *carrierServerSession) kernelFragmentEnabled() bool {
	if session == nil || session.listener == nil {
		return carrierKernelFragmentEnabled()
	}
	return carrierKernelFragmentEnabledForConfig(session.listener.cfg)
}

func effectiveTunnelMTU(mtu int) int {
	if mtu <= 0 {
		return defaultTunnelMTU
	}
	return mtu
}

func effectiveVXLANVNI(vni int) int {
	if vni <= 0 {
		return defaultVXLANVNI
	}
	return vni
}

func effectiveVXLANPort(port uint16) uint16 {
	if port == 0 {
		return defaultVXLANPort
	}
	return port
}
