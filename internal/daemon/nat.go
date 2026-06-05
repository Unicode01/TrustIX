package daemon

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/routing"
)

const (
	natBindingTTL             = 5 * time.Minute
	natBindingRefreshInterval = natBindingTTL / 2
	natDefaultMaxBindings     = 16 * 1024
)

type natTable struct {
	mu          sync.Mutex
	bindings    map[natKey]natBinding
	maxBindings int
	ttl         time.Duration
	evictions   uint64
	expired     uint64
}

type natKey struct {
	TranslatedIP netip.Addr `json:"translated_ip"`
	RemoteIP     netip.Addr `json:"remote_ip"`
	Protocol     uint8      `json:"protocol"`
	LocalPort    uint16     `json:"local_port,omitempty"`
	RemotePort   uint16     `json:"remote_port,omitempty"`
}

type natBinding struct {
	Key        natKey     `json:"key"`
	OriginalIP netip.Addr `json:"original_ip"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeen   time.Time  `json:"last_seen"`
	ExpiresAt  time.Time  `json:"expires_at"`
}

type natStatus struct {
	Enabled        bool         `json:"enabled"`
	Gateway        string       `json:"gateway,omitempty"`
	MaxBindings    int          `json:"max_bindings"`
	BindingTTL     string       `json:"binding_ttl"`
	ActiveBindings int          `json:"active_bindings"`
	Evictions      uint64       `json:"evictions"`
	Expired        uint64       `json:"expired"`
	Bindings       []natBinding `json:"bindings,omitempty"`
}

type natTableSnapshot struct {
	Bindings       []natBinding
	MaxBindings    int
	BindingTTL     time.Duration
	ActiveBindings int
	Evictions      uint64
	Expired        uint64
}

type ipv4NATTuple struct {
	source      netip.Addr
	destination netip.Addr
	protocol    uint8
	sourcePort  uint16
	destPort    uint16
}

func newNATTable() *natTable {
	return newNATTableWithLimitAndTTL(natDefaultMaxBindings, natBindingTTL)
}

func newNATTableWithLimit(maxBindings int) *natTable {
	return newNATTableWithLimitAndTTL(maxBindings, natBindingTTL)
}

func newNATTableWithLimitAndTTL(maxBindings int, ttl time.Duration) *natTable {
	if maxBindings <= 0 {
		maxBindings = natDefaultMaxBindings
	}
	if ttl <= 0 {
		ttl = natBindingTTL
	}
	return &natTable{
		bindings:    make(map[natKey]natBinding),
		maxBindings: maxBindings,
		ttl:         ttl,
	}
}

func (daemon *Daemon) natEnabledForRoute(route routing.Route, policy config.PolicyConfig) bool {
	if route.Kind != "" && route.Kind != routing.RouteUnicast {
		return false
	}
	for _, lan := range config.EffectiveLANs(daemon.desired) {
		if lan.Mode == config.LANModeNAT {
			return true
		}
	}
	return rewritePolicyEnablesNAT(policy.Rewrite)
}

func rewritePolicyEnablesNAT(rewrite string) bool {
	switch strings.ToLower(strings.TrimSpace(rewrite)) {
	case "snat_gateway", "nat", "snat":
		return true
	default:
		return false
	}
}

func (daemon *Daemon) applyOutboundNAT(packet []byte, route routing.Route, policy config.PolicyConfig) ([]byte, bool, error) {
	if !daemon.natEnabledForRoute(route, policy) {
		return packet, false, nil
	}
	gateway, ok := daemon.lanGatewayAddr()
	if !ok {
		return nil, false, fmt.Errorf("NAT route %q requires lan gateway", route.Prefix)
	}
	tuple, ok, err := ipv4NATTupleFromPacket(packet)
	if err != nil || !ok {
		return packet, false, err
	}
	if !daemon.sourceInLocalLAN(tuple.source) || tuple.source == gateway {
		return packet, false, nil
	}
	if daemon.isRemoteManagementVIP(tuple.destination) {
		return packet, false, nil
	}
	key := natKey{
		TranslatedIP: gateway,
		RemoteIP:     tuple.destination,
		Protocol:     tuple.protocol,
		LocalPort:    tuple.sourcePort,
		RemotePort:   tuple.destPort,
	}
	daemon.ensureNATTable()
	if daemon.nat.upsert(key, tuple.source) {
		daemon.syncNATBindingsToDataplane(context.Background())
	}
	translated, err := rewriteIPv4Source(packet, gateway)
	if err != nil {
		return nil, false, err
	}
	return translated, true, nil
}

func (daemon *Daemon) mirrorOutboundNATFromCapture(event dataplane.CaptureEvent, route routing.Route, policy config.PolicyConfig) (bool, error) {
	if !event.NATTranslated {
		return false, nil
	}
	if !daemon.natEnabledForRoute(route, policy) {
		return false, nil
	}
	originalSource := event.OriginalSourceAddr
	if !originalSource.IsValid() {
		var err error
		originalSource, err = netip.ParseAddr(event.OriginalSourceIP)
		if err != nil || !originalSource.Is4() {
			return false, fmt.Errorf("parse original NAT source %q: %w", event.OriginalSourceIP, err)
		}
	}
	if !originalSource.Is4() {
		return false, fmt.Errorf("parse original NAT source %q: invalid IPv4 address", event.OriginalSourceIP)
	}
	gateway, ok := daemon.lanGatewayAddr()
	if !ok {
		return false, fmt.Errorf("NAT route %q requires lan gateway", route.Prefix)
	}
	if !daemon.sourceInLocalLAN(originalSource) || originalSource == gateway {
		return false, nil
	}
	tuple, ok, err := ipv4NATTupleFromPacket(event.Payload)
	if err != nil || !ok {
		return false, err
	}
	if tuple.source != gateway {
		return false, nil
	}
	key := natKey{
		TranslatedIP: gateway,
		RemoteIP:     tuple.destination,
		Protocol:     tuple.protocol,
		LocalPort:    tuple.sourcePort,
		RemotePort:   tuple.destPort,
	}
	daemon.ensureNATTable()
	if daemon.nat.upsert(key, originalSource) {
		daemon.syncNATBindingsToDataplane(context.Background())
	}
	return true, nil
}

func (daemon *Daemon) isRemoteManagementVIP(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	daemon.membershipMu.RLock()
	defer daemon.membershipMu.RUnlock()
	for ixID, record := range daemon.members {
		if ixID == daemon.desired.IX.ID {
			continue
		}
		if managementVIPFromAdvertisement(record.Advertisement) == addr {
			return true
		}
	}
	return false
}

func (daemon *Daemon) applyInboundNAT(packet []byte) ([]byte, bool, error) {
	binding, found, eligible, err := daemon.inboundNATBinding(packet)
	if err != nil || !eligible {
		return packet, false, err
	}
	if !found {
		daemon.dataStats.natMisses.Add(1)
		return packet, false, nil
	}
	translated, err := rewriteIPv4Destination(packet, binding.OriginalIP)
	if err != nil {
		return nil, false, err
	}
	return translated, true, nil
}

func (daemon *Daemon) inboundNATBinding(packet []byte) (natBinding, bool, bool, error) {
	if !daemon.hasNATModeLAN() && !daemon.hasNATRewritePolicy() {
		return natBinding{}, false, false, nil
	}
	gateway, ok := daemon.lanGatewayAddr()
	if !ok {
		return natBinding{}, false, false, nil
	}
	tuple, ok, err := ipv4NATTupleFromPacket(packet)
	if err != nil || !ok {
		return natBinding{}, false, false, err
	}
	if tuple.destination != gateway {
		return natBinding{}, false, false, nil
	}
	key := natKey{
		TranslatedIP: gateway,
		RemoteIP:     tuple.source,
		Protocol:     tuple.protocol,
		LocalPort:    tuple.destPort,
		RemotePort:   tuple.sourcePort,
	}
	daemon.ensureNATTable()
	binding, found, changed := daemon.nat.lookup(key)
	if changed {
		daemon.syncNATBindingsToDataplane(context.Background())
	}
	return binding, found, true, nil
}

func (daemon *Daemon) ensureNATTable() {
	if daemon.nat == nil {
		daemon.nat = newNATTableWithLimitAndTTL(daemon.natMaxBindings(), daemon.natBindingTTL())
		return
	}
	daemon.nat.configure(daemon.natMaxBindings(), daemon.natBindingTTL())
}

func (daemon *Daemon) configureNATTable() {
	daemon.ensureNATTable()
}

func (daemon *Daemon) natMaxBindings() int {
	if lan, ok := daemon.primaryNATConfigLAN(); ok && lan.NAT.MaxBindings > 0 {
		return lan.NAT.MaxBindings
	}
	return natDefaultMaxBindings
}

func (daemon *Daemon) natBindingTTL() time.Duration {
	lan, ok := daemon.primaryNATConfigLAN()
	if !ok || lan.NAT.BindingTTL == "" {
		return natBindingTTL
	}
	ttl, err := time.ParseDuration(lan.NAT.BindingTTL)
	if err != nil || ttl <= 0 {
		return natBindingTTL
	}
	return ttl
}

func (daemon *Daemon) lanGatewayAddr() (netip.Addr, bool) {
	lan, ok := daemon.primaryNATLAN()
	if !ok {
		return netip.Addr{}, false
	}
	prefix, err := netip.ParsePrefix(lan.Gateway)
	if err != nil || !prefix.Addr().Is4() {
		return netip.Addr{}, false
	}
	return prefix.Addr(), true
}

func (daemon *Daemon) sourceInLocalLAN(source netip.Addr) bool {
	lan, ok := daemon.primaryNATLAN()
	if !ok {
		return false
	}
	for _, rawPrefix := range lan.Advertise {
		prefix, err := rawPrefix.Parse()
		if err == nil && prefix.Contains(source) {
			return true
		}
	}
	return false
}

func (daemon *Daemon) natStatus() *natStatus {
	if !daemon.hasNATModeLAN() && !daemon.hasNATRewritePolicy() {
		return nil
	}
	gateway, _ := daemon.lanGatewayAddr()
	status := &natStatus{Enabled: gateway.IsValid(), Gateway: gateway.String()}
	if daemon.nat != nil {
		snapshot := daemon.nat.snapshot()
		status.Bindings = snapshot.Bindings
		status.MaxBindings = snapshot.MaxBindings
		status.BindingTTL = snapshot.BindingTTL.String()
		status.ActiveBindings = snapshot.ActiveBindings
		status.Evictions = snapshot.Evictions
		status.Expired = snapshot.Expired
	}
	return status
}

func (daemon *Daemon) syncNATBindingsToDataplane(ctx context.Context) {
	applier, ok := daemon.dataplane.(dataplane.NATSnapshotApplier)
	if !ok {
		return
	}
	snapshot := daemon.runtimeDataplaneSnapshot().NAT
	if err := applier.ApplyNATSnapshot(ctx, snapshot); err != nil {
		daemon.dataStats.natDataplaneSyncErrors.Add(1)
	}
}

func (daemon *Daemon) natSnapshotForRoutes(routes []routing.Route) *dataplane.NATSnapshot {
	gateway, ok := daemon.lanGatewayAddr()
	if !ok {
		return nil
	}
	lan, ok := daemon.primaryNATLAN()
	if !ok {
		return nil
	}
	sourcePrefixes := make([]netip.Prefix, 0, len(lan.Advertise))
	for _, rawPrefix := range lan.Advertise {
		prefix, err := rawPrefix.Parse()
		if err == nil && prefix.Addr().Is4() {
			sourcePrefixes = append(sourcePrefixes, prefix.Masked())
		}
	}
	if len(sourcePrefixes) == 0 {
		return nil
	}
	routePrefixes := make([]core.Prefix, 0, len(routes))
	for _, route := range routes {
		if route.Kind != "" && route.Kind != routing.RouteUnicast {
			continue
		}
		if daemon.natEnabledForRoute(route, daemon.policyForRoute(route)) {
			if prefix, err := route.Prefix.Parse(); err == nil && prefix.Addr().Is4() {
				routePrefixes = append(routePrefixes, core.Prefix(prefix.Masked().String()))
			}
		}
	}
	if len(routePrefixes) == 0 {
		return nil
	}
	return &dataplane.NATSnapshot{
		Enabled:              true,
		Gateway:              gateway,
		SourcePrefixes:       sourcePrefixes,
		RoutePrefixes:        routePrefixes,
		ExcludedDestinations: daemon.remoteManagementVIPsLocked(),
		Bindings:             daemon.dataplaneNATBindings(),
	}
}

func (daemon *Daemon) dataplaneNATBindings() []dataplane.NATBinding {
	if daemon.nat == nil {
		return nil
	}
	return dataplaneNATBindingsFromTable(daemon.nat.snapshot().Bindings)
}

func dataplaneNATBindingsFromTable(bindings []natBinding) []dataplane.NATBinding {
	if len(bindings) == 0 {
		return nil
	}
	out := make([]dataplane.NATBinding, 0, len(bindings))
	for _, binding := range bindings {
		if !binding.Key.TranslatedIP.Is4() || !binding.Key.RemoteIP.Is4() || !binding.OriginalIP.Is4() {
			continue
		}
		out = append(out, dataplane.NATBinding{
			TranslatedIP: binding.Key.TranslatedIP,
			RemoteIP:     binding.Key.RemoteIP,
			Protocol:     binding.Key.Protocol,
			LocalPort:    binding.Key.LocalPort,
			RemotePort:   binding.Key.RemotePort,
			OriginalIP:   binding.OriginalIP,
			ExpiresAt:    binding.ExpiresAt,
		})
	}
	return out
}

func (daemon *Daemon) remoteManagementVIPsLocked() []netip.Addr {
	out := make([]netip.Addr, 0)
	for ixID, record := range daemon.members {
		if ixID == daemon.desired.IX.ID {
			continue
		}
		if vip := managementVIPFromAdvertisement(record.Advertisement); vip.IsValid() && vip.Is4() {
			out = append(out, vip)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

func (daemon *Daemon) hasNATRewritePolicy() bool {
	for _, policy := range daemon.desired.Policies {
		if rewritePolicyEnablesNAT(policy.Rewrite) {
			return true
		}
	}
	return false
}

func (daemon *Daemon) hasNATModeLAN() bool {
	for _, lan := range config.EffectiveLANs(daemon.desired) {
		if lan.Mode == config.LANModeNAT {
			return true
		}
	}
	return false
}

func (daemon *Daemon) primaryNATLAN() (config.LANConfig, bool) {
	for _, lan := range config.EffectiveLANs(daemon.desired) {
		if lan.Mode == config.LANModeNAT && strings.TrimSpace(lan.Gateway) != "" {
			return lan, true
		}
	}
	for _, lan := range config.EffectiveLANs(daemon.desired) {
		if strings.TrimSpace(lan.Gateway) != "" {
			return lan, true
		}
	}
	return config.LANConfig{}, false
}

func (daemon *Daemon) primaryNATConfigLAN() (config.LANConfig, bool) {
	for _, lan := range config.EffectiveLANs(daemon.desired) {
		if lan.Mode == config.LANModeNAT {
			return lan, true
		}
	}
	return config.LANConfig{}, false
}

func (table *natTable) upsert(key natKey, original netip.Addr) bool {
	now := time.Now().UTC()
	table.mu.Lock()
	defer table.mu.Unlock()
	if table.ttl <= 0 {
		table.ttl = natBindingTTL
	}
	changed := table.pruneLocked(now)
	if _, exists := table.bindings[key]; !exists && len(table.bindings) >= table.maxBindings {
		table.evictOldestLocked()
		changed = true
	}
	binding := table.bindings[key]
	oldOriginal := binding.OriginalIP
	if binding.CreatedAt.IsZero() {
		binding.CreatedAt = now
		changed = true
	}
	if !binding.ExpiresAt.IsZero() && binding.ExpiresAt.Sub(now) <= table.refreshIntervalLocked() {
		changed = true
	}
	binding.Key = key
	binding.OriginalIP = original
	binding.LastSeen = now
	binding.ExpiresAt = now.Add(table.ttl)
	table.bindings[key] = binding
	return changed || oldOriginal.IsValid() && oldOriginal != original
}

func (table *natTable) lookup(key natKey) (natBinding, bool, bool) {
	now := time.Now().UTC()
	table.mu.Lock()
	defer table.mu.Unlock()
	changed := table.pruneLocked(now)
	binding, ok := table.bindings[key]
	if !ok {
		return natBinding{}, false, changed
	}
	if table.ttl <= 0 {
		table.ttl = natBindingTTL
	}
	if !binding.ExpiresAt.IsZero() && binding.ExpiresAt.Sub(now) <= table.refreshIntervalLocked() {
		changed = true
	}
	binding.LastSeen = now
	binding.ExpiresAt = now.Add(table.ttl)
	table.bindings[key] = binding
	return binding, true, changed
}

func (table *natTable) snapshot() natTableSnapshot {
	now := time.Now().UTC()
	table.mu.Lock()
	defer table.mu.Unlock()
	table.pruneLocked(now)
	out := make([]natBinding, 0, len(table.bindings))
	for _, binding := range table.bindings {
		out = append(out, binding)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Key.TranslatedIP != out[j].Key.TranslatedIP {
			return out[i].Key.TranslatedIP.Less(out[j].Key.TranslatedIP)
		}
		if out[i].Key.RemoteIP != out[j].Key.RemoteIP {
			return out[i].Key.RemoteIP.Less(out[j].Key.RemoteIP)
		}
		if out[i].Key.Protocol != out[j].Key.Protocol {
			return out[i].Key.Protocol < out[j].Key.Protocol
		}
		if out[i].Key.LocalPort != out[j].Key.LocalPort {
			return out[i].Key.LocalPort < out[j].Key.LocalPort
		}
		return out[i].Key.RemotePort < out[j].Key.RemotePort
	})
	return natTableSnapshot{
		Bindings:       out,
		MaxBindings:    table.maxBindings,
		BindingTTL:     table.ttl,
		ActiveBindings: len(out),
		Evictions:      table.evictions,
		Expired:        table.expired,
	}
}

func (table *natTable) configure(maxBindings int, ttl time.Duration) {
	if maxBindings <= 0 {
		maxBindings = natDefaultMaxBindings
	}
	if ttl <= 0 {
		ttl = natBindingTTL
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	table.maxBindings = maxBindings
	table.ttl = ttl
	now := time.Now().UTC()
	for key, binding := range table.bindings {
		if binding.LastSeen.IsZero() {
			binding.LastSeen = now
		}
		binding.ExpiresAt = binding.LastSeen.Add(table.ttl)
		if !now.Before(binding.ExpiresAt) {
			delete(table.bindings, key)
			table.expired++
			continue
		}
		table.bindings[key] = binding
	}
	for len(table.bindings) > table.maxBindings {
		table.evictOldestLocked()
	}
}

func (table *natTable) refreshIntervalLocked() time.Duration {
	if table.ttl <= 0 {
		return natBindingRefreshInterval
	}
	return table.ttl / 2
}

func (table *natTable) pruneLocked(now time.Time) bool {
	changed := false
	for key, binding := range table.bindings {
		if !binding.ExpiresAt.IsZero() && !now.Before(binding.ExpiresAt) {
			delete(table.bindings, key)
			table.expired++
			changed = true
		}
	}
	return changed
}

func (table *natTable) evictOldestLocked() {
	var oldestKey natKey
	var oldest natBinding
	found := false
	for key, binding := range table.bindings {
		if !found || binding.LastSeen.Before(oldest.LastSeen) || binding.LastSeen.Equal(oldest.LastSeen) && binding.CreatedAt.Before(oldest.CreatedAt) {
			oldestKey = key
			oldest = binding
			found = true
		}
	}
	if found {
		delete(table.bindings, oldestKey)
		table.evictions++
	}
}

func ipv4NATTupleFromPacket(packet []byte) (ipv4NATTuple, bool, error) {
	ipOffset, ihl, totalLen, err := ipv4HeaderBounds(packet)
	if err != nil {
		return ipv4NATTuple{}, false, err
	}
	ip := packet[ipOffset : ipOffset+totalLen]
	flagsAndFragment := binary.BigEndian.Uint16(ip[6:8])
	if flagsAndFragment&(ipv4MoreFragments|ipv4FragmentOffsetMask) != 0 {
		return ipv4NATTuple{}, false, nil
	}
	tuple := ipv4NATTuple{
		source:      netip.AddrFrom4([4]byte{ip[12], ip[13], ip[14], ip[15]}),
		destination: netip.AddrFrom4([4]byte{ip[16], ip[17], ip[18], ip[19]}),
		protocol:    ip[9],
	}
	segment := ip[ihl:totalLen]
	switch tuple.protocol {
	case ipProtocolTCP:
		if len(segment) < 20 {
			return ipv4NATTuple{}, false, fmt.Errorf("TCP packet is too short for NAT")
		}
		tuple.sourcePort = binary.BigEndian.Uint16(segment[0:2])
		tuple.destPort = binary.BigEndian.Uint16(segment[2:4])
	case ipProtocolUDP:
		if len(segment) < 8 {
			return ipv4NATTuple{}, false, fmt.Errorf("UDP packet is too short for NAT")
		}
		udpLen := int(binary.BigEndian.Uint16(segment[4:6]))
		if udpLen < 8 || udpLen > len(segment) {
			return ipv4NATTuple{}, false, fmt.Errorf("invalid UDP length %d for NAT", udpLen)
		}
		tuple.sourcePort = binary.BigEndian.Uint16(segment[0:2])
		tuple.destPort = binary.BigEndian.Uint16(segment[2:4])
	case ipProtocolICMP:
		if len(segment) < 8 {
			return ipv4NATTuple{}, false, fmt.Errorf("ICMP packet is too short for NAT")
		}
		icmpType := segment[0]
		if icmpType != 0 && icmpType != 8 {
			return ipv4NATTuple{}, false, nil
		}
		identifier := binary.BigEndian.Uint16(segment[4:6])
		tuple.sourcePort = identifier
		tuple.destPort = identifier
	default:
		return ipv4NATTuple{}, false, nil
	}
	return tuple, true, nil
}

func rewriteIPv4Source(packet []byte, source netip.Addr) ([]byte, error) {
	return rewriteIPv4Address(packet, source, true)
}

func rewriteIPv4Destination(packet []byte, destination netip.Addr) ([]byte, error) {
	return rewriteIPv4Address(packet, destination, false)
}

func rewriteIPv4Address(packet []byte, addr netip.Addr, source bool) ([]byte, error) {
	if !addr.Is4() {
		return nil, fmt.Errorf("NAT address %s is not IPv4", addr)
	}
	ipOffset, ihl, totalLen, err := ipv4HeaderBounds(packet)
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), packet...)
	ip := out[ipOffset : ipOffset+totalLen]
	addr4 := addr.As4()
	if source {
		copy(ip[12:16], addr4[:])
	} else {
		copy(ip[16:20], addr4[:])
	}
	binary.BigEndian.PutUint16(ip[10:12], 0)
	binary.BigEndian.PutUint16(ip[10:12], ipv4Checksum(ip[:ihl]))
	flagsAndFragment := binary.BigEndian.Uint16(ip[6:8])
	if flagsAndFragment&(ipv4MoreFragments|ipv4FragmentOffsetMask) != 0 {
		return out, nil
	}
	segment := ip[ihl:totalLen]
	switch ip[9] {
	case ipProtocolTCP:
		if len(segment) < 20 {
			return nil, fmt.Errorf("TCP packet is too short for NAT checksum")
		}
		tcpHeaderLen := int(segment[12]>>4) * 4
		if tcpHeaderLen < 20 || len(segment) < tcpHeaderLen {
			return nil, fmt.Errorf("invalid TCP header length %d for NAT checksum", tcpHeaderLen)
		}
		binary.BigEndian.PutUint16(segment[16:18], 0)
		binary.BigEndian.PutUint16(segment[16:18], transportChecksum(ip[12:16], ip[16:20], ip[9], segment))
	case ipProtocolUDP:
		if len(segment) < 8 {
			return nil, fmt.Errorf("UDP packet is too short for NAT checksum")
		}
		udpLen := int(binary.BigEndian.Uint16(segment[4:6]))
		if udpLen < 8 || udpLen > len(segment) {
			return nil, fmt.Errorf("invalid UDP length %d for NAT checksum", udpLen)
		}
		udp := segment[:udpLen]
		binary.BigEndian.PutUint16(udp[6:8], 0)
		binary.BigEndian.PutUint16(udp[6:8], transportChecksum(ip[12:16], ip[16:20], ip[9], udp))
	case ipProtocolICMP:
		if len(segment) < 8 {
			return nil, fmt.Errorf("ICMP packet is too short for NAT checksum")
		}
		binary.BigEndian.PutUint16(segment[2:4], 0)
		binary.BigEndian.PutUint16(segment[2:4], ipv4Checksum(segment))
	}
	return out, nil
}
