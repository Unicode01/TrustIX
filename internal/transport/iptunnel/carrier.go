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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"trustix.local/trustix/internal/transport"
)

const (
	carrierHeaderLen                    = 16
	carrierVersion                 byte = 1
	carrierTypeData                byte = 1
	carrierMaxPacket                    = 64 * 1024
	carrierMaxWire                      = carrierHeaderLen + carrierMaxPacket
	defaultCarrierPort                  = 47819
	defaultTunnelMTU                    = 1400
	defaultVXLANVNI                     = 0x545849
	defaultVXLANPort                    = 4789
	carrierReadBatchDefault             = 64
	carrierReadBatchMax                 = 256
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
	sendWire               []byte
	sendBatchWire          [][]byte
	sendBatchPacketScratch []carrierBatchPacket
	sendBatchArena         []byte
}

type packetListener struct {
	conn      *net.UDPConn
	cfg       tunnelConfig
	acceptCh  chan transport.Session
	done      chan struct{}
	closeOnce sync.Once
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
	sendWire               []byte
	sendBatchWire          [][]byte
	sendBatchPacketScratch []carrierBatchPacket
	sendBatchArena         []byte
}

type carrierBatchPacket struct {
	header  []byte
	payload []byte
}

type carrierReceivedPacket struct {
	payload []byte
	wireLen int
	buffer  []byte
	addr    *net.UDPAddr
}

type carrierBatchReceiveResult struct {
	bytesReceived uint64
	mmsgSyscalls  uint64
	loopSyscalls  uint64
	fallbacks     uint64
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
	if len(payload) > 0xffff {
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
	if len(payload) > 0xffff {
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
	if payloadLen > carrierMaxPacket {
		return fmt.Errorf("tunnel carrier packet size %d exceeds max %d", payloadLen, carrierMaxPacket)
	}
	if payloadLen > 0xffff {
		return fmt.Errorf("tunnel carrier packet size %d exceeds header capacity", payloadLen)
	}
	if len(out) < carrierHeaderLen {
		return fmt.Errorf("tunnel carrier header output buffer size %d is smaller than header %d", len(out), carrierHeaderLen)
	}
	copy(out[0:4], carrierMagic[:])
	out[4] = carrierVersion
	out[5] = carrierTypeData
	binary.BigEndian.PutUint16(out[6:8], uint16(payloadLen))
	binary.BigEndian.PutUint64(out[8:16], sequence)
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
	if len(wire) < carrierHeaderLen {
		return nil, 0, fmt.Errorf("tunnel carrier frame too short: %d", len(wire))
	}
	if wire[0] != carrierMagic[0] || wire[1] != carrierMagic[1] || wire[2] != carrierMagic[2] || wire[3] != carrierMagic[3] || wire[4] != carrierVersion || wire[5] != carrierTypeData {
		return nil, 0, fmt.Errorf("invalid tunnel carrier header")
	}
	payloadLen := int(binary.BigEndian.Uint16(wire[6:8]))
	if payloadLen != len(wire)-carrierHeaderLen {
		return nil, 0, fmt.Errorf("tunnel carrier payload length %d != wire payload %d", payloadLen, len(wire)-carrierHeaderLen)
	}
	sequence := binary.BigEndian.Uint64(wire[8:16])
	return wire[carrierHeaderLen:], sequence, nil
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
		_ = conn.Close()
		return nil, fmt.Errorf("dial tunnel carrier returned %T", conn)
	}
	return udpConn, nil
}

func (session *carrier) SendPacket(pkt []byte) error {
	mtu := effectiveTunnelMTU(session.cfg.MTU)
	if len(pkt)+carrierHeaderLen > mtu {
		session.mtuDrops.Add(1)
		return fmt.Errorf("tunnel carrier packet size %d plus header %d exceeds mtu %d", len(pkt), carrierHeaderLen, mtu)
	}
	seq := session.sendSeq.Add(1)
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

func (session *carrier) SendPackets(pkts [][]byte) error {
	if len(pkts) == 0 {
		return nil
	}
	if len(pkts) == 1 {
		return session.SendPacket(pkts[0])
	}
	mtu := effectiveTunnelMTU(session.cfg.MTU)
	for _, pkt := range pkts {
		if len(pkt)+carrierHeaderLen > mtu {
			session.mtuDrops.Add(1)
			return fmt.Errorf("tunnel carrier packet size %d plus header %d exceeds mtu %d", len(pkt), carrierHeaderLen, mtu)
		}
		if len(pkt) > carrierMaxPacket {
			return fmt.Errorf("tunnel carrier packet size %d exceeds max %d", len(pkt), carrierMaxPacket)
		}
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
	packets, result, release, err := recvCarrierBatch(session.conn, max, effectiveTunnelMTU(session.cfg.MTU))
	if err != nil {
		return nil, nil, err
	}
	session.recordReceivedPackets(uint64(len(packets)), result.bytesReceived)
	session.recordBatchReceive(uint64(len(packets)), result)
	return packets, release, nil
}

func (session *carrier) readCarrierPacket() ([]byte, int, []byte, error) {
	buf := takeCarrierReadBuffer(effectiveTunnelMTU(session.cfg.MTU))
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
	var err error
	session.closeOnce.Do(func() {
		if session.conn != nil {
			err = session.conn.Close()
		}
		if session.closeFunc != nil {
			if closeErr := session.closeFunc(); err == nil {
				err = closeErr
			}
		}
	})
	return err
}

func (session *carrier) Stats() transport.TransportStats {
	mtu := effectiveTunnelMTU(session.cfg.MTU)
	maxPacket := 0
	if mtu > carrierHeaderLen {
		maxPacket = mtu - carrierHeaderLen
	}
	return transport.TransportStats{
		BytesSent:       session.bytesSent.Load(),
		BytesReceived:   session.bytesReceived.Load(),
		PacketsSent:     session.packetsSent.Load(),
		PacketsReceived: session.packetsReceived.Load(),
		NativeBatching:  true,
		Datagram:        true,
		MaxPacketSize:   uint64(maxPacket),
		Extra: map[string]uint64{
			"iptunnel_carrier_port":             uint64(session.cfg.CarrierPort),
			"iptunnel_mtu":                      uint64(mtu),
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

func newPacketListener(ctx context.Context, cfg tunnelConfig, conn *net.UDPConn) *packetListener {
	listener := &packetListener{
		conn:     conn,
		cfg:      cfg,
		acceptCh: make(chan transport.Session, 64),
		done:     make(chan struct{}),
		sessions: make(map[string]*carrierServerSession),
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	go listener.readLoop()
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
	var err error
	listener.closeOnce.Do(func() {
		close(listener.done)
		if listener.conn != nil {
			err = listener.conn.Close()
		}
		listener.mu.Lock()
		for key, session := range listener.sessions {
			session.closeInput()
			delete(listener.sessions, key)
		}
		listener.mu.Unlock()
	})
	return err
}

func (listener *packetListener) readLoop() {
	for {
		packets, _, release, err := recvCarrierBatchFrom(listener.conn, carrierReadBatch(), effectiveTunnelMTU(listener.cfg.MTU))
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
		listener.dispatchPackets(packets)
		if release != nil {
			release()
		}
	}
}

func (listener *packetListener) dispatchPackets(packets []carrierReceivedPacket) {
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
				conn:     listener.conn,
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
	default:
		return false
	}
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
	if len(pkt)+carrierHeaderLen > mtu {
		session.mtuDrops.Add(1)
		return fmt.Errorf("tunnel carrier packet size %d plus header %d exceeds mtu %d", len(pkt), carrierHeaderLen, mtu)
	}
	seq := session.sendSeq.Add(1)
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
	for _, pkt := range pkts {
		if len(pkt)+carrierHeaderLen > mtu {
			session.mtuDrops.Add(1)
			return fmt.Errorf("tunnel carrier packet size %d plus header %d exceeds mtu %d", len(pkt), carrierHeaderLen, mtu)
		}
		if len(pkt) > carrierMaxPacket {
			return fmt.Errorf("tunnel carrier packet size %d exceeds max %d", len(pkt), carrierMaxPacket)
		}
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
		return [][]byte{item.payload}, func() { putCarrierReadBuffer(item.buffer) }, nil
	}
	first, ok := <-session.in
	if !ok {
		return nil, nil, net.ErrClosed
	}
	packets := make([][]byte, 0, max)
	buffers := make([][]byte, 0, max)
	packets = append(packets, first.payload)
	buffers = append(buffers, first.buffer)
	var bytes uint64
	bytes += uint64(first.wireLen)
	release := func() {
		for _, buffer := range buffers {
			putCarrierReadBuffer(buffer)
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
			buffers = append(buffers, item.buffer)
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
		putCarrierReadBuffer(pkt.buffer)
		return
	}
	select {
	case session.in <- pkt:
	default:
		putCarrierReadBuffer(pkt.buffer)
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
	close(session.in)
	for item := range session.in {
		putCarrierReadBuffer(item.buffer)
	}
}

func (session *carrierServerSession) Stats() transport.TransportStats {
	mtu := session.listenerMTU()
	maxPacket := 0
	if mtu > carrierHeaderLen {
		maxPacket = mtu - carrierHeaderLen
	}
	return transport.TransportStats{
		BytesSent:       session.bytesSent.Load(),
		BytesReceived:   session.bytesReceived.Load(),
		PacketsSent:     session.packetsSent.Load(),
		PacketsReceived: session.packetsReceived.Load(),
		NativeBatching:  true,
		Datagram:        true,
		MaxPacketSize:   uint64(maxPacket),
		Extra: map[string]uint64{
			"iptunnel_carrier_port":             uint64(session.listenerCarrierPort()),
			"iptunnel_mtu":                      uint64(mtu),
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
