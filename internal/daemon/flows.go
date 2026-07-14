package daemon

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/routing"
	"trustix.local/trustix/internal/transport"
	iptunneltransport "trustix.local/trustix/internal/transport/iptunnel"
	securetransport "trustix.local/trustix/internal/transport/secure"
)

const flowBindingTTL = 5 * time.Minute
const flowBindingRefreshInterval = time.Second
const ethPIPv4 = 0x0800
const ipv4MoreFragments = 0x2000
const ipv4FragmentOffsetMask = 0x1fff
const ipProtocolTCP = 6
const ipProtocolUDP = 17
const tcpOptionMSS = 2
const ipv4HeaderLen = 20
const tcpHeaderLen = 20
const kernelUDPSecureDirectDefaultUnderlayMTU = 1500
const userspaceUDPOuterOverhead = 20 + 8
const dataSessionBatchSinglePacketOverhead = dataSessionBatchHeaderLen + dataSessionBatchItemHeaderLen
const kernelUDPOuterOverhead = 20 + 8 + 32
const tixTCPOuterOverhead = 20 + 20 + 40
const kernelTunnelCarrierOverhead = 16
const trustIXSecureDataOverhead = 24 + 16
const kernelUDPSecureDirectOuterOverhead = kernelUDPOuterOverhead + trustIXSecureDataOverhead
const kernelUDPSecureDirectTCPOptionBudget = 40
const kernelTunnelSecureTCPMSSHeadroom = 80
const tcpMSSMinimumIPv4 = 536
const kernelUDPPlaintextSafeMSSClamp = 1090

var errIPv4TTLExpired = errors.New("IPv4 TTL expired")

type tcpMSSClampMode int

const (
	tcpMSSClampUnset tcpMSSClampMode = iota
	tcpMSSClampDisabled
	tcpMSSClampExplicit
	tcpMSSClampAuto
)

func flowKeyFromIPv4Packet(packet []byte) (routing.FlowKey, bool) {
	if len(packet) >= 14 && binary.BigEndian.Uint16(packet[12:14]) == ethPIPv4 {
		packet = packet[14:]
	}
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return routing.FlowKey{}, false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		return routing.FlowKey{}, false
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < ihl || totalLen > len(packet) {
		return routing.FlowKey{}, false
	}
	flagsAndFragment := binary.BigEndian.Uint16(packet[6:8])
	if flagsAndFragment&ipv4FragmentOffsetMask != 0 {
		return routing.FlowKey{}, false
	}
	source := netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]})
	destination := netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]})
	key := routing.FlowKey{
		SourceIP:      source,
		DestinationIP: destination,
		Protocol:      packet[9],
	}
	switch key.Protocol {
	case 6, 17:
		if totalLen < ihl+4 {
			return routing.FlowKey{}, false
		}
		key.SourcePort = binary.BigEndian.Uint16(packet[ihl : ihl+2])
		key.DestinationPort = binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
	}
	return key, true
}

func ipv4PacketFragmented(packet []byte) bool {
	if len(packet) >= 14 && binary.BigEndian.Uint16(packet[12:14]) == ethPIPv4 {
		packet = packet[14:]
	}
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		return false
	}
	flagsAndFragment := binary.BigEndian.Uint16(packet[6:8])
	return flagsAndFragment&(ipv4MoreFragments|ipv4FragmentOffsetMask) != 0
}

func ipv4Destination(packet []byte) (netip.Addr, error) {
	ipOffset, _, _, err := ipv4HeaderBounds(packet)
	if err != nil {
		return netip.Addr{}, err
	}
	ip := packet[ipOffset:]
	return netip.AddrFrom4([4]byte{ip[16], ip[17], ip[18], ip[19]}), nil
}

func decrementIPv4TTL(packet []byte) ([]byte, error) {
	ipOffset, ihl, totalLen, err := ipv4HeaderBounds(packet)
	if err != nil {
		return nil, err
	}
	ip := packet[ipOffset : ipOffset+totalLen]
	if ip[8] <= 1 {
		return nil, errIPv4TTLExpired
	}
	out := append([]byte(nil), packet...)
	ip = out[ipOffset : ipOffset+totalLen]
	decrementIPv4TTLAndChecksumInPlace(ip, ihl)
	return out, nil
}

func decrementIPv4TTLInPlace(packet []byte) error {
	ipOffset, ihl, totalLen, err := ipv4HeaderBounds(packet)
	if err != nil {
		return err
	}
	ip := packet[ipOffset : ipOffset+totalLen]
	if ip[8] <= 1 {
		return errIPv4TTLExpired
	}
	decrementIPv4TTLAndChecksumInPlace(ip, ihl)
	return nil
}

func decrementIPv4TTLBeforeChecksumInPlace(packet []byte) error {
	ipOffset, _, totalLen, err := ipv4HeaderBounds(packet)
	if err != nil {
		return err
	}
	ip := packet[ipOffset : ipOffset+totalLen]
	if ip[8] <= 1 {
		return errIPv4TTLExpired
	}
	ip[8]--
	return nil
}

func decrementIPv4TTLAndChecksumInPlace(ip []byte, ihl int) {
	if len(ip) < ihl || ihl < 20 {
		return
	}
	oldWord := binary.BigEndian.Uint16(ip[8:10])
	newWord := oldWord - 0x0100
	oldChecksum := binary.BigEndian.Uint16(ip[10:12])
	ip[8]--
	sum := uint32(^oldChecksum&0xffff) + uint32(^oldWord&0xffff) + uint32(newWord)
	binary.BigEndian.PutUint16(ip[10:12], checksumFold(sum))
}

func ipv4HeaderBounds(packet []byte) (ipOffset int, ihl int, totalLen int, err error) {
	if len(packet) >= 14 && binary.BigEndian.Uint16(packet[12:14]) == ethPIPv4 {
		ipOffset = 14
	}
	if len(packet) < ipOffset+20 {
		return 0, 0, 0, fmt.Errorf("packet is too short for IPv4: %d bytes", len(packet)-ipOffset)
	}
	ip := packet[ipOffset:]
	if ip[0]>>4 != 4 {
		return 0, 0, 0, fmt.Errorf("packet is not IPv4")
	}
	ihl = int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl {
		return 0, 0, 0, fmt.Errorf("invalid IPv4 header length %d", ihl)
	}
	totalLen = int(binary.BigEndian.Uint16(ip[2:4]))
	if totalLen < ihl || totalLen > len(ip) {
		return 0, 0, 0, fmt.Errorf("invalid IPv4 total length %d for %d-byte packet", totalLen, len(ip))
	}
	return ipOffset, ihl, totalLen, nil
}

func normalizeCapturedIPv4Checksums(packet []byte) []byte {
	return normalizeCapturedIPv4ChecksumsWithMSS(packet, capturedTCPMSSClamp())
}

func normalizeCapturedIPv4ChecksumsWithMSS(packet []byte, mss int) []byte {
	normalized := append([]byte(nil), packet...)
	clampCapturedTCPMSSInPlaceWithMSS(normalized, mss)
	normalizeCapturedIPv4ChecksumsInPlace(normalized)
	return normalized
}

func clampCapturedTCPMSSInPlace(packet []byte) {
	clampCapturedTCPMSSInPlaceWithMSS(packet, capturedTCPMSSClamp())
}

func clampCapturedTCPMSSInPlaceWithMSS(packet []byte, mss int) {
	if mss <= 0 || mss > 0xffff {
		return
	}
	ipOffset := 0
	if len(packet) >= 14 && binary.BigEndian.Uint16(packet[12:14]) == ethPIPv4 {
		ipOffset = 14
	}
	if len(packet) < ipOffset+20 {
		return
	}
	ip := packet[ipOffset:]
	if ip[0]>>4 != 4 || ip[9] != ipProtocolTCP {
		return
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl+20 {
		return
	}
	totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
	if totalLen < ihl+20 || totalLen > len(ip) {
		return
	}
	flagsAndFragment := binary.BigEndian.Uint16(ip[6:8])
	if flagsAndFragment&(ipv4MoreFragments|ipv4FragmentOffsetMask) != 0 {
		return
	}
	tcp := ip[ihl:totalLen]
	tcpHeaderLen := int(tcp[12]>>4) * 4
	if tcpHeaderLen < 20 || tcpHeaderLen > len(tcp) || tcp[13]&tcpFlagSYN == 0 {
		return
	}
	options := tcp[20:tcpHeaderLen]
	for i := 0; i < len(options); {
		kind := options[i]
		switch kind {
		case 0:
			return
		case 1:
			i++
			continue
		}
		if i+1 >= len(options) {
			return
		}
		length := int(options[i+1])
		if length < 2 || i+length > len(options) {
			return
		}
		if kind == tcpOptionMSS && length == 4 {
			current := binary.BigEndian.Uint16(options[i+2 : i+4])
			if current > uint16(mss) {
				binary.BigEndian.PutUint16(options[i+2:i+4], uint16(mss))
			}
			return
		}
		i += length
	}
}

func capturedPacketNeedsTCPMSSClamp(packet []byte, mss int) bool {
	if mss <= 0 || mss > 0xffff {
		return false
	}
	ipOffset := 0
	if len(packet) >= 14 && binary.BigEndian.Uint16(packet[12:14]) == ethPIPv4 {
		ipOffset = 14
	}
	if len(packet) < ipOffset+20 {
		return false
	}
	ip := packet[ipOffset:]
	if ip[0]>>4 != 4 || ip[9] != ipProtocolTCP {
		return false
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl+20 {
		return false
	}
	totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
	if totalLen < ihl+20 || totalLen > len(ip) {
		return false
	}
	flagsAndFragment := binary.BigEndian.Uint16(ip[6:8])
	if flagsAndFragment&(ipv4MoreFragments|ipv4FragmentOffsetMask) != 0 {
		return false
	}
	tcp := ip[ihl:totalLen]
	tcpHeaderLen := int(tcp[12]>>4) * 4
	if tcpHeaderLen < 20 || tcpHeaderLen > len(tcp) || tcp[13]&tcpFlagSYN == 0 {
		return false
	}
	options := tcp[20:tcpHeaderLen]
	for i := 0; i < len(options); {
		kind := options[i]
		switch kind {
		case 0:
			return false
		case 1:
			i++
			continue
		}
		if i+1 >= len(options) {
			return false
		}
		length := int(options[i+1])
		if length < 2 || i+length > len(options) {
			return false
		}
		if kind == tcpOptionMSS && length == 4 {
			return binary.BigEndian.Uint16(options[i+2:i+4]) > uint16(mss)
		}
		i += length
	}
	return false
}

func capturedTCPMSSClamp() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_TCP_MSS_CLAMP"))
	if value == "" {
		return 0
	}
	switch strings.ToLower(value) {
	case "0", "false", "off", "disabled", "none":
		return 0
	case "auto":
		return 0
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return 0
	}
	if parsed > 0xffff {
		return 0xffff
	}
	return parsed
}

func configuredTCPMSSClamp() (int, tcpMSSClampMode) {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_TCP_MSS_CLAMP"))
	if value == "" {
		return 0, tcpMSSClampUnset
	}
	switch strings.ToLower(value) {
	case "0", "false", "off", "disabled", "none":
		return 0, tcpMSSClampDisabled
	case "auto":
		return 0, tcpMSSClampAuto
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return 0, tcpMSSClampDisabled
	}
	if parsed > 0xffff {
		parsed = 0xffff
	}
	return parsed, tcpMSSClampExplicit
}

func (daemon *Daemon) effectiveTCPMSSClamp() int {
	if daemon == nil {
		return capturedTCPMSSClamp()
	}
	if mss, mode := configuredTCPMSSClamp(); mode != tcpMSSClampUnset {
		switch mode {
		case tcpMSSClampExplicit:
			return mss
		case tcpMSSClampAuto:
			return daemon.autoTransportTCPMSSClamp(true)
		default:
			return 0
		}
	}
	return daemon.autoTransportTCPMSSClamp(false)
}

func (daemon *Daemon) autoTransportTCPMSSClamp(explicitAuto bool) int {
	if daemon == nil {
		return 0
	}
	if mss := daemon.autoTIXTCPTCPMSSClamp(explicitAuto); mss > 0 {
		return mss
	}
	if mss := daemon.autoKernelTunnelTCPMSSClamp(explicitAuto); mss > 0 {
		return mss
	}
	if mss := daemon.autoUserspaceUDPTCPMSSClamp(explicitAuto); mss > 0 {
		return mss
	}
	return daemon.autoKernelUDPSecureDirectTCPMSSClamp(explicitAuto)
}

func (daemon *Daemon) autoTIXTCPTCPMSSClamp(explicitAuto bool) int {
	if daemon == nil {
		return 0
	}
	if !explicitAuto &&
		!tixTCPAutoTCPMSSClampRequestedForPolicy() &&
		!kernelUDPTXSecureDirectRequestedForPolicy() &&
		!daemon.transportPolicySendsPlainTIXTCPData() &&
		!daemon.transportPolicySendsSecureTIXTCPData() {
		return 0
	}
	if !daemon.transportPolicyUsesTIXTCP() {
		return 0
	}
	mtu := daemon.desired.TransportPolicy.MTU
	if mtu <= 0 {
		mtu = kernelUDPSecureDirectDefaultUnderlayMTU
	}
	return autoTIXTCPTCPMSSClampForMTU(mtu, daemon.transportPolicySendsSecureData())
}

func (daemon *Daemon) transportPolicySendsPlainTIXTCPData() bool {
	if daemon == nil || !daemon.transportPolicyUsesTIXTCP() || daemon.transportPolicySendsSecureData() {
		return false
	}
	if daemon.kernelTransportMode() == dataplane.KernelTransportModeDisabled {
		return false
	}
	return true
}

func (daemon *Daemon) transportPolicySendsSecureTIXTCPData() bool {
	if daemon == nil || !daemon.transportPolicyUsesTIXTCP() || !daemon.transportPolicySendsSecureData() {
		return false
	}
	if daemon.kernelTransportMode() == dataplane.KernelTransportModeDisabled {
		return false
	}
	return true
}

func (daemon *Daemon) autoKernelUDPSecureDirectTCPMSSClamp(explicitAuto bool) int {
	if daemon == nil {
		return 0
	}
	if !explicitAuto &&
		!kernelUDPAutoTCPMSSClampRequestedForPolicy() &&
		!daemon.transportPolicySendsPlainKernelUDPData() &&
		!daemon.transportPolicySendsSecureKernelUDPData() {
		return 0
	}
	if !daemon.transportPolicyUsesKernelUDP() {
		return 0
	}
	mtu := daemon.desired.TransportPolicy.MTU
	if mtu <= 0 {
		mtu = kernelUDPSecureDirectDefaultUnderlayMTU
	}
	return daemon.autoKernelUDPTCPMSSClampForMTU(mtu, daemon.transportPolicySendsSecureData())
}

func (daemon *Daemon) transportPolicySendsPlainKernelUDPData() bool {
	if daemon == nil || !daemon.transportPolicyUsesKernelUDP() || daemon.transportPolicySendsSecureData() {
		return false
	}
	if daemon.kernelTransportMode() == dataplane.KernelTransportModeDisabled {
		return false
	}
	return true
}

func (daemon *Daemon) transportPolicySendsSecureKernelUDPData() bool {
	if daemon == nil || !daemon.transportPolicyUsesKernelUDP() || !daemon.transportPolicySendsSecureData() {
		return false
	}
	if daemon.kernelTransportMode() == dataplane.KernelTransportModeDisabled {
		return false
	}
	return true
}

func (daemon *Daemon) autoUserspaceUDPTCPMSSClamp(explicitAuto bool) int {
	if daemon == nil {
		return 0
	}
	if !daemon.transportPolicyUsesUserspaceUDP() {
		return 0
	}
	if !explicitAuto && !userspaceUDPAutoTCPMSSClampRequestedForPolicy() {
		return 0
	}
	mtu := daemon.desired.TransportPolicy.MTU
	if mtu <= 0 {
		mtu = kernelUDPSecureDirectDefaultUnderlayMTU
	}
	return autoUserspaceUDPTCPMSSClampForMTU(mtu, daemon.transportPolicySendsSecureData())
}

func (daemon *Daemon) autoKernelTunnelTCPMSSClamp(explicitAuto bool) int {
	if daemon == nil {
		return 0
	}
	if !explicitAuto && !nativeTunnelAutoTCPMSSClampRequestedForPolicy() {
		return 0
	}
	if !daemon.transportPolicyUsesKernelTunnel() {
		return 0
	}
	mtu, fromTunnelEndpoint := daemon.kernelTunnelPolicyMTU()
	if mtu <= 0 {
		mtu = kernelUDPSecureDirectDefaultUnderlayMTU
	}
	if fromTunnelEndpoint && daemon.transportPolicyUsesNativePlaintextKernelTunnelRouteOffload() {
		return autoNativeKernelTunnelRouteTCPMSSClampForMTU(mtu)
	}
	return autoKernelTunnelTCPMSSClampForMTU(mtu, daemon.transportPolicySendsSecureData())
}

func (daemon *Daemon) kernelTunnelPolicyMTU() (int, bool) {
	if daemon == nil {
		return 0, false
	}
	selected := make(map[core.EndpointID]struct{}, len(daemon.desired.TransportPolicy.Candidates)+len(daemon.desired.Routes))
	for _, candidate := range daemon.desired.TransportPolicy.Candidates {
		if candidate != "" {
			selected[candidate] = struct{}{}
		}
	}
	for _, route := range daemon.desired.Routes {
		if route.Endpoint != "" {
			selected[route.Endpoint] = struct{}{}
		}
	}
	requireSelected := len(selected) > 0
	mtu := 0
	consider := func(name core.EndpointID, transportName string, address string, listen string, enabled bool) {
		if !enabled || !transportProtocolIsKernelTunnel(transportName) {
			return
		}
		if requireSelected {
			if _, ok := selected[name]; !ok {
				return
			}
		}
		raw := strings.TrimSpace(address)
		if raw == "" {
			raw = strings.TrimSpace(listen)
		}
		if raw == "" {
			return
		}
		cfg, err := iptunneltransport.ParseTunnelConfig(raw)
		if err != nil || cfg.MTU <= 0 {
			return
		}
		if mtu == 0 || cfg.MTU < mtu {
			mtu = cfg.MTU
		}
	}
	for _, endpoint := range daemon.desired.Endpoints {
		consider(endpoint.Name, endpoint.Transport, endpoint.Address, endpoint.Listen, endpoint.Enabled)
	}
	for _, peer := range daemon.desired.Peers {
		for _, endpoint := range peer.Endpoints {
			consider(endpoint.Name, endpoint.Transport, endpoint.Address, endpoint.Listen, true)
		}
	}
	if mtu > 0 {
		return mtu, true
	}
	return daemon.desired.TransportPolicy.MTU, false
}

func transportProtocolIsKernelTunnel(raw string) bool {
	switch transport.Protocol(strings.ToLower(strings.TrimSpace(raw))) {
	case transport.ProtocolGRE, transport.ProtocolIPIP, transport.ProtocolVXLAN:
		return true
	default:
		return false
	}
}

func (daemon *Daemon) transportPolicyUsesNativePlaintextKernelTunnelRouteOffload() bool {
	if daemon == nil || nativeTunnelRouteOffloadDisabledForPolicy() || daemon.transportPolicySendsSecureData() {
		return false
	}
	return daemon.transportPolicyUsesKernelTunnel()
}

func nativePlaintextKernelTunnelRouteOffloadForDesired(desired config.Desired) bool {
	if nativeTunnelRouteOffloadDisabledForPolicy() {
		return false
	}
	if desiredTransportPolicySendsSecureData(desired) {
		return false
	}
	return desiredTransportPolicyUsesKernelTunnel(desired)
}

func nativePlaintextKernelTunnelMTUForDesired(desired config.Desired) int {
	if !nativePlaintextKernelTunnelRouteOffloadForDesired(desired) {
		return 0
	}
	selected := make(map[core.EndpointID]struct{}, len(desired.TransportPolicy.Candidates)+len(desired.Routes))
	for _, candidate := range desired.TransportPolicy.Candidates {
		if candidate != "" {
			selected[candidate] = struct{}{}
		}
	}
	for _, route := range desired.Routes {
		if route.Endpoint != "" {
			selected[route.Endpoint] = struct{}{}
		}
	}
	requireSelected := len(selected) > 0
	mtu := 0
	consider := func(name core.EndpointID, transportName string, address string, listen string, enabled bool) {
		if !enabled || !transportProtocolIsKernelTunnel(transportName) {
			return
		}
		if requireSelected {
			if _, ok := selected[name]; !ok {
				return
			}
		}
		raw := strings.TrimSpace(address)
		if raw == "" {
			raw = strings.TrimSpace(listen)
		}
		if raw == "" {
			return
		}
		cfg, err := iptunneltransport.ParseTunnelConfig(raw)
		if err != nil || cfg.MTU <= 0 {
			return
		}
		if mtu == 0 || cfg.MTU < mtu {
			mtu = cfg.MTU
		}
	}
	for _, endpoint := range desired.Endpoints {
		consider(endpoint.Name, endpoint.Transport, endpoint.Address, endpoint.Listen, endpoint.Enabled)
	}
	for _, peer := range desired.Peers {
		for _, endpoint := range peer.Endpoints {
			consider(endpoint.Name, endpoint.Transport, endpoint.Address, endpoint.Listen, true)
		}
	}
	return mtu
}

func nativeTunnelManagedLANMTUEnabled() bool {
	for _, name := range []string{"TRUSTIX_NATIVE_TUNNEL_MANAGED_LAN_MTU", "TRUSTIX_IPTUNNEL_MANAGED_LAN_MTU"} {
		switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
		case "0", "false", "no", "off", "disabled":
			return false
		}
	}
	return true
}

func nativeTunnelRouteOffloadDisabledForPolicy() bool {
	for _, name := range []string{"TRUSTIX_NATIVE_TUNNEL_ROUTE_OFFLOAD", "TRUSTIX_IPTUNNEL_ROUTE_OFFLOAD"} {
		switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
		case "0", "false", "no", "off", "disabled":
			return true
		}
	}
	return false
}

func autoNativeKernelTunnelRouteTCPMSSClampForMTU(mtu int) int {
	mss := mtu - ipv4HeaderLen - tcpHeaderLen
	if mss < tcpMSSMinimumIPv4 {
		return tcpMSSMinimumIPv4
	}
	if mss > 0xffff {
		return 0xffff
	}
	return mss
}

func autoKernelTunnelTCPMSSClampForMTU(mtu int, secureData bool) int {
	overhead := kernelTunnelCarrierOverhead
	if secureData {
		overhead += trustIXSecureDataOverhead + kernelTunnelSecureTCPMSSHeadroom
	}
	mss := mtu - overhead - ipv4HeaderLen - tcpHeaderLen - kernelUDPSecureDirectTCPOptionBudget
	if mss < tcpMSSMinimumIPv4 {
		return tcpMSSMinimumIPv4
	}
	if mss > 0xffff {
		return 0xffff
	}
	return mss
}

func autoTIXTCPTCPMSSClampForMTU(mtu int, secureData bool) int {
	overhead := tixTCPOuterOverhead
	if secureData {
		overhead += trustIXSecureDataOverhead
	}
	mss := mtu - overhead - ipv4HeaderLen - tcpHeaderLen - kernelUDPSecureDirectTCPOptionBudget
	if mss < tcpMSSMinimumIPv4 {
		return tcpMSSMinimumIPv4
	}
	if mss > 0xffff {
		return 0xffff
	}
	return mss
}

func autoKernelUDPSecureDirectTCPMSSClampForMTU(mtu int) int {
	return autoKernelUDPTCPMSSClampForMTU(mtu, true)
}

func autoKernelUDPTCPMSSClampForMTU(mtu int, secureData bool) int {
	mss := autoKernelUDPTCPMSSClampBaseForMTU(mtu, secureData)
	if !secureData {
		mss = capKernelUDPPlaintextMSSClamp(mss)
	}
	return mss
}

func (daemon *Daemon) autoKernelUDPTCPMSSClampForMTU(mtu int, secureData bool) int {
	mss := autoKernelUDPTCPMSSClampBaseForMTU(mtu, secureData)
	if !secureData {
		mss = daemon.capKernelUDPPlaintextMSSClamp(mss)
	}
	return mss
}

func autoKernelUDPTCPMSSClampBaseForMTU(mtu int, secureData bool) int {
	overhead := kernelUDPOuterOverhead
	if secureData {
		overhead += trustIXSecureDataOverhead
	}
	mss := mtu - overhead - ipv4HeaderLen - tcpHeaderLen - kernelUDPSecureDirectTCPOptionBudget
	if mss < tcpMSSMinimumIPv4 {
		return tcpMSSMinimumIPv4
	}
	if mss > 0xffff {
		return 0xffff
	}
	return mss
}

func autoUserspaceUDPTCPMSSClampForMTU(mtu int, secureData bool) int {
	overhead := userspaceUDPOuterOverhead + dataSessionBatchSinglePacketOverhead
	if secureData {
		overhead += trustIXSecureDataOverhead
	}
	mss := mtu - overhead - ipv4HeaderLen - tcpHeaderLen - kernelUDPSecureDirectTCPOptionBudget
	if mss < tcpMSSMinimumIPv4 {
		return tcpMSSMinimumIPv4
	}
	if mss > 0xffff {
		return 0xffff
	}
	return mss
}

func capKernelUDPPlaintextMSSClamp(mss int) int {
	if kernelUDPPlaintextMSSCapDisabled() {
		return mss
	}
	capValue := kernelUDPPlaintextMSSCap()
	if capValue > 0 && mss > capValue {
		return capValue
	}
	return mss
}

func (daemon *Daemon) capKernelUDPPlaintextMSSClamp(mss int) int {
	if kernelUDPPlaintextMSSCapDisabled() {
		return mss
	}
	return capKernelUDPPlaintextMSSClampValue(mss)
}

func capKernelUDPPlaintextMSSClampValue(mss int) int {
	capValue := kernelUDPPlaintextMSSCap()
	if capValue > 0 && mss > capValue {
		return capValue
	}
	return mss
}

func kernelUDPPlaintextMSSCap() int {
	value := strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_PLAINTEXT_SAFE_MSS_CAP"))
	if value == "" || strings.EqualFold(value, "auto") || strings.EqualFold(value, "default") {
		return kernelUDPPlaintextSafeMSSClamp
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < tcpMSSMinimumIPv4 {
		return kernelUDPPlaintextSafeMSSClamp
	}
	if parsed > 0xffff {
		return 0xffff
	}
	return parsed
}

func kernelUDPPlaintextMSSCapDisabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_PLAINTEXT_SAFE_MSS_CAP"))) {
	case "0", "false", "no", "off", "disabled", "none":
		return true
	default:
		return false
	}
}

func kernelUDPActiveGSORequestedForPolicy() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func (daemon *Daemon) kernelUDPActiveGSOEnabledForPolicy() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_DIRECT_ACTIVE_GSO"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	}
	return daemon.kernelUDPTunnelGSOEnabledForPolicy() &&
		daemon.kernelUDPDirectOnlyProgramEnabledForPolicy() &&
		!kernelUDPTXDirectTIXTCPOnlyRequestedForPolicy()
}

func (daemon *Daemon) kernelUDPTunnelGSOEnabledForPolicy() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_ADJ_ROOM_TUNNEL_GSO"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	}
	return daemon.kernelUDPDirectOnlyProgramEnabledForPolicy() &&
		!kernelUDPTXDirectTIXTCPOnlyRequestedForPolicy()
}

func (daemon *Daemon) kernelUDPDirectOnlyProgramEnabledForPolicy() bool {
	if daemon == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY"))) {
	case "1", "true", "yes", "on", "enabled", "force":
		return daemon.transportPolicyUsesKernelDirect()
	default:
		return kernelUDPTXDirectOnlyAttachForDesired(daemon.desired)
	}
}

func kernelUDPTXDirectTIXTCPOnlyRequestedForPolicy() bool {
	return envTruthyAny(
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_TIX_TCP_ONLY",
		"TRUSTIX_TIX_TCP_TC_TX_DIRECT_ONLY",
	)
}

func tixTCPCompatStreamEnabledForPolicy() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_TIX_TCP_COMPAT_STREAM"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func tixTCPTXDirectRequestedForPolicy() bool {
	return envTruthyAny(
		"TRUSTIX_TIX_TCP_TC_TX_DIRECT",
		"TRUSTIX_REMOTE_TIX_TCP_TC_TX_DIRECT",
		"TRUSTIX_E2E_TIX_TCP_TC_TX_DIRECT",
		"TRUSTIX_IPERF3_CRYPTO_BENCH_TIX_TCP_TC_TX_DIRECT",
		"TRUSTIX_TIX_TCP_TC_TX_DIRECT_ONLY",
		"TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_TIX_TCP_ONLY",
	)
}

func (daemon *Daemon) transportPolicyUsesKernelUDP() bool {
	if daemon.kernelTransportMode() == dataplane.KernelTransportModeDisabled {
		return false
	}
	return daemon.transportPolicyUsesAnyProtocol(transport.ProtocolUDP)
}

func (daemon *Daemon) transportPolicyUsesUserspaceUDP() bool {
	if daemon.kernelTransportMode() != dataplane.KernelTransportModeDisabled {
		return false
	}
	return daemon.transportPolicyUsesAnyProtocol(transport.ProtocolUDP)
}

func (daemon *Daemon) transportPolicyUsesTIXTCP() bool {
	if daemon.kernelTransportMode() == dataplane.KernelTransportModeDisabled {
		return false
	}
	return daemon.transportPolicyUsesAnyProtocol(transport.ProtocolTIXTCP)
}

func (daemon *Daemon) transportPolicyUsesKernelDirect() bool {
	if daemon.kernelTransportMode() == dataplane.KernelTransportModeDisabled {
		return false
	}
	return daemon.transportPolicyUsesAnyProtocol(transport.ProtocolUDP, transport.ProtocolTIXTCP)
}

func (daemon *Daemon) transportPolicyUsesKernelPlaintextDirect() bool {
	return daemon.transportPolicyUsesKernelDirect()
}

func (daemon *Daemon) transportPolicyUsesKernelTunnel() bool {
	return daemon.transportPolicyUsesAnyProtocol(transport.ProtocolGRE, transport.ProtocolIPIP, transport.ProtocolVXLAN)
}

func desiredTransportPolicyUsesKernelTunnel(desired config.Desired) bool {
	return desiredTransportPolicyUsesAnyProtocol(desired, transport.ProtocolGRE, transport.ProtocolIPIP, transport.ProtocolVXLAN)
}

func (daemon *Daemon) transportPolicyUsesAnyProtocol(protocols ...transport.Protocol) bool {
	return desiredTransportPolicyUsesAnyProtocol(daemon.desired, protocols...)
}

func desiredTransportPolicyUsesAnyProtocol(desired config.Desired, protocols ...transport.Protocol) bool {
	if len(desired.TransportPolicy.Candidates) > 0 {
		for _, candidate := range desired.TransportPolicy.Candidates {
			if endpoint, ok := desiredEndpointByName(desired.Endpoints, candidate); ok && endpoint.Enabled && transportProtocolMatchesAny(endpoint.Transport, protocols) {
				return true
			}
		}
		return false
	}
	for _, endpoint := range desired.Endpoints {
		if endpoint.Enabled && transportProtocolMatchesAny(endpoint.Transport, protocols) {
			return true
		}
	}
	for _, peer := range desired.Peers {
		for _, endpoint := range peer.Endpoints {
			if endpoint.Enabled && transportProtocolMatchesAny(endpoint.Transport, protocols) {
				return true
			}
		}
	}
	return false
}

func desiredEndpointByName(endpoints []config.EndpointConfig, name core.EndpointID) (config.EndpointConfig, bool) {
	for _, endpoint := range endpoints {
		if endpoint.Name == name {
			return endpoint, true
		}
	}
	return config.EndpointConfig{}, false
}

func transportProtocolMatchesAny(protocol string, allowed []transport.Protocol) bool {
	normalized := strings.ToLower(strings.TrimSpace(protocol))
	for _, candidate := range allowed {
		if normalized == string(candidate) {
			return true
		}
	}
	return false
}

func (daemon *Daemon) transportPolicySendsSecureData() bool {
	return desiredTransportPolicySendsSecureData(daemon.desired)
}

func desiredTransportPolicySendsSecureData(desired config.Desired) bool {
	switch parseSecureTransportEncryption(desired.TransportPolicy.Encryption) {
	case securetransport.EncryptionPlaintext, securetransport.EncryptionReceiveEncrypted:
		return false
	default:
		return true
	}
}

func kernelUDPAutoTCPMSSClampRequestedForPolicy() bool {
	if kernelUDPTXSecureDirectRequestedForPolicy() {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_AUTO_TCP_MSS_CLAMP"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func userspaceUDPAutoTCPMSSClampRequestedForPolicy() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_UDP_AUTO_TCP_MSS_CLAMP"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func nativeTunnelAutoTCPMSSClampRequestedForPolicy() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_NATIVE_TUNNEL_AUTO_TCP_MSS_CLAMP"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func tixTCPAutoTCPMSSClampRequestedForPolicy() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_TIX_TCP_AUTO_TCP_MSS_CLAMP"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func kernelUDPTXSecureDirectRequestedForPolicy() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT"))) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func normalizeCapturedIPv4ChecksumsInPlace(packet []byte) {
	ipOffset := 0
	if len(packet) >= 14 && binary.BigEndian.Uint16(packet[12:14]) == ethPIPv4 {
		ipOffset = 14
	}
	if len(packet) < ipOffset+20 {
		return
	}
	ip := packet[ipOffset:]
	if ip[0]>>4 != 4 {
		return
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl {
		return
	}
	totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
	if totalLen < ihl || totalLen > len(ip) {
		return
	}

	ip = packet[ipOffset : ipOffset+totalLen]
	binary.BigEndian.PutUint16(ip[10:12], 0)
	binary.BigEndian.PutUint16(ip[10:12], ipv4Checksum(ip[:ihl]))

	flagsAndFragment := binary.BigEndian.Uint16(ip[6:8])
	if flagsAndFragment&(ipv4MoreFragments|ipv4FragmentOffsetMask) != 0 {
		return
	}
	segment := ip[ihl:totalLen]
	switch ip[9] {
	case ipProtocolTCP:
		if len(segment) < 20 {
			return
		}
		tcpHeaderLen := int(segment[12]>>4) * 4
		if tcpHeaderLen < 20 || len(segment) < tcpHeaderLen {
			return
		}
		binary.BigEndian.PutUint16(segment[16:18], 0)
		binary.BigEndian.PutUint16(segment[16:18], transportChecksum(ip[12:16], ip[16:20], ip[9], segment))
	case ipProtocolUDP:
		if len(segment) < 8 {
			return
		}
		udpLen := int(binary.BigEndian.Uint16(segment[4:6]))
		if udpLen < 8 || udpLen > len(segment) {
			return
		}
		udp := segment[:udpLen]
		binary.BigEndian.PutUint16(udp[6:8], 0)
		binary.BigEndian.PutUint16(udp[6:8], transportChecksum(ip[12:16], ip[16:20], ip[9], udp))
	case ipProtocolICMP:
		if len(segment) < 8 {
			return
		}
		binary.BigEndian.PutUint16(segment[2:4], 0)
		binary.BigEndian.PutUint16(segment[2:4], ipv4Checksum(segment))
	}
}

func ipv4Checksum(payload []byte) uint16 {
	return checksumFold(checksumAddBytes(0, payload))
}

func transportChecksum(src []byte, dst []byte, protocol byte, segment []byte) uint16 {
	sum := checksumAddBytes(0, src)
	sum = checksumAddBytes(sum, dst)
	sum += uint32(protocol)
	sum += uint32(len(segment))
	sum = checksumAddBytes(sum, segment)
	checksum := checksumFold(sum)
	if checksum == 0 {
		return 0xffff
	}
	return checksum
}

func checksumAddBytes(sum uint32, payload []byte) uint32 {
	for len(payload) >= 32 {
		sum += uint32(binary.BigEndian.Uint16(payload[0:2]))
		sum += uint32(binary.BigEndian.Uint16(payload[2:4]))
		sum += uint32(binary.BigEndian.Uint16(payload[4:6]))
		sum += uint32(binary.BigEndian.Uint16(payload[6:8]))
		sum += uint32(binary.BigEndian.Uint16(payload[8:10]))
		sum += uint32(binary.BigEndian.Uint16(payload[10:12]))
		sum += uint32(binary.BigEndian.Uint16(payload[12:14]))
		sum += uint32(binary.BigEndian.Uint16(payload[14:16]))
		sum += uint32(binary.BigEndian.Uint16(payload[16:18]))
		sum += uint32(binary.BigEndian.Uint16(payload[18:20]))
		sum += uint32(binary.BigEndian.Uint16(payload[20:22]))
		sum += uint32(binary.BigEndian.Uint16(payload[22:24]))
		sum += uint32(binary.BigEndian.Uint16(payload[24:26]))
		sum += uint32(binary.BigEndian.Uint16(payload[26:28]))
		sum += uint32(binary.BigEndian.Uint16(payload[28:30]))
		sum += uint32(binary.BigEndian.Uint16(payload[30:32]))
		payload = payload[32:]
	}
	for len(payload) >= 8 {
		value := binary.BigEndian.Uint64(payload[:8])
		sum += uint32(value >> 48)
		sum += uint32((value >> 32) & 0xffff)
		sum += uint32((value >> 16) & 0xffff)
		sum += uint32(value & 0xffff)
		payload = payload[8:]
	}
	for len(payload) > 1 {
		sum += uint32(binary.BigEndian.Uint16(payload[:2]))
		payload = payload[2:]
	}
	if len(payload) == 1 {
		sum += uint32(payload[0]) << 8
	}
	return sum
}

func checksumFold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (daemon *Daemon) policyForRoute(route routing.Route) config.PolicyConfig {
	for _, policy := range daemon.desired.Policies {
		if policy.Name == route.Policy {
			return policy
		}
	}
	return config.PolicyConfig{Name: route.Policy}
}

func (daemon *Daemon) bindFlow(key routing.FlowKey, nextHop core.IXID, endpoint core.EndpointID, poolIndex ...int) {
	now := time.Now().UTC()
	selectedPool := 0
	if len(poolIndex) > 0 && poolIndex[0] > 0 {
		selectedPool = poolIndex[0]
	}
	daemon.flowMu.Lock()
	if daemon.flows == nil {
		daemon.flows = make(map[routing.FlowKey]routing.FlowBinding)
	}
	if binding, ok := daemon.flows[key]; ok && binding.NextHop == nextHop && binding.Endpoint == endpoint && binding.PoolIndex == selectedPool && now.Sub(binding.LastSeen) < flowBindingRefreshInterval {
		daemon.flowMu.Unlock()
		return
	}
	daemon.pruneFlowsLocked(now)
	binding := routing.FlowBinding{
		Key:       key,
		NextHop:   nextHop,
		Endpoint:  endpoint,
		PoolIndex: selectedPool,
		LastSeen:  now,
		ExpiresAt: now.Add(flowBindingTTL),
	}
	daemon.flows[key] = binding
	daemon.flowMu.Unlock()
	daemon.syncKernelDatapathFlowUpsert(binding)
}

func (daemon *Daemon) lookupFlow(key routing.FlowKey, nextHop core.IXID) (routing.FlowBinding, bool) {
	now := time.Now().UTC()
	daemon.flowMu.RLock()
	binding, ok := daemon.flows[key]
	if !ok || binding.NextHop != nextHop {
		daemon.flowMu.RUnlock()
		return routing.FlowBinding{}, false
	}
	if binding.ExpiresAt.Before(now) {
		daemon.flowMu.RUnlock()
		daemon.flowMu.Lock()
		if current, exists := daemon.flows[key]; exists && current.ExpiresAt.Before(now) {
			delete(daemon.flows, key)
		}
		daemon.flowMu.Unlock()
		return routing.FlowBinding{}, false
	}
	daemon.flowMu.RUnlock()
	return binding, true
}

func (daemon *Daemon) releaseFlow(key routing.FlowKey) {
	daemon.flowMu.Lock()
	_, existed := daemon.flows[key]
	delete(daemon.flows, key)
	daemon.flowMu.Unlock()
	daemon.deleteForwardCache(key)
	if existed {
		daemon.syncKernelDatapathFlowDelete(key)
	}
}

func (daemon *Daemon) clearFlowsForPeers(peers map[core.IXID]struct{}) {
	if len(peers) == 0 {
		return
	}
	daemon.flowMu.Lock()
	defer daemon.flowMu.Unlock()
	for key, binding := range daemon.flows {
		if _, ok := peers[binding.NextHop]; ok {
			delete(daemon.flows, key)
		}
	}
	daemon.clearForwardCacheForPeers(peers)
}

func (daemon *Daemon) flowSnapshot() []routing.FlowBinding {
	now := time.Now().UTC()
	daemon.flowMu.Lock()
	defer daemon.flowMu.Unlock()
	daemon.pruneFlowsLocked(now)
	flows := make([]routing.FlowBinding, 0, len(daemon.flows))
	for _, binding := range daemon.flows {
		flows = append(flows, binding)
	}
	sort.Slice(flows, func(i, j int) bool {
		if flows[i].NextHop != flows[j].NextHop {
			return flows[i].NextHop < flows[j].NextHop
		}
		if flows[i].Endpoint != flows[j].Endpoint {
			return flows[i].Endpoint < flows[j].Endpoint
		}
		return flows[i].LastSeen.Before(flows[j].LastSeen)
	})
	return flows
}

func (daemon *Daemon) pruneFlowsLocked(now time.Time) {
	for key, binding := range daemon.flows {
		if !binding.ExpiresAt.IsZero() && !now.Before(binding.ExpiresAt) {
			delete(daemon.flows, key)
		}
	}
}

func (daemon *Daemon) sortEndpointsByFlowCount(nextHop core.IXID, endpoints []config.EndpointConfig) {
	now := time.Now().UTC()
	daemon.flowMu.Lock()
	defer daemon.flowMu.Unlock()
	daemon.pruneFlowsLocked(now)
	counts := make(map[core.EndpointID]int, len(endpoints))
	for _, binding := range daemon.flows {
		if binding.NextHop == nextHop {
			counts[binding.Endpoint]++
		}
	}
	originalIndex := make(map[core.EndpointID]int, len(endpoints))
	for i, endpoint := range endpoints {
		originalIndex[endpoint.Name] = i
	}
	sort.SliceStable(endpoints, func(i, j int) bool {
		left := counts[endpoints[i].Name]
		right := counts[endpoints[j].Name]
		if left != right {
			return left < right
		}
		leftPriority := daemon.endpointPriorityScore(nextHop, endpoints[i])
		rightPriority := daemon.endpointPriorityScore(nextHop, endpoints[j])
		if leftPriority != rightPriority {
			return leftPriority > rightPriority
		}
		return originalIndex[endpoints[i].Name] < originalIndex[endpoints[j].Name]
	})
}

func preferEndpoint(endpoints []config.EndpointConfig, preferred core.EndpointID) []config.EndpointConfig {
	index := -1
	for i, endpoint := range endpoints {
		if endpoint.Name == preferred {
			index = i
			break
		}
	}
	if index <= 0 {
		return endpoints
	}
	preferredEndpoint := endpoints[index]
	copy(endpoints[1:index+1], endpoints[0:index])
	endpoints[0] = preferredEndpoint
	return endpoints
}

func endpointByName(endpoints []config.EndpointConfig, name core.EndpointID) (config.EndpointConfig, bool) {
	for _, endpoint := range endpoints {
		if endpoint.Name == name {
			return endpoint, true
		}
	}
	return config.EndpointConfig{}, false
}
