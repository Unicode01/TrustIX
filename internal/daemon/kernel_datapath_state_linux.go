//go:build linux

package daemon

import (
	"context"
	"encoding/binary"
	"hash/fnv"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/kernelmodule"
	"trustix.local/trustix/internal/routing"
	"trustix.local/trustix/internal/transport"
)

const (
	kernelDatapathSessionFlagReverse             = uint32(1 << 0)
	kernelDatapathSessionFlagControlOnly         = uint32(1 << 1)
	kernelDatapathSessionFlagKernelFlow          = uint32(1 << 2)
	kernelDatapathSessionFlagEncrypted           = uint32(1 << 3)
	kernelDatapathSessionFlagSendEncrypted       = uint32(1 << 4)
	kernelDatapathSessionFlagReceiveEncrypted    = uint32(1 << 5)
	kernelDatapathSessionFlagCryptoKernel        = uint32(1 << 6)
	kernelDatapathSessionFlagCryptoUserspace     = uint32(1 << 7)
	kernelDatapathSessionFlagNativeBatching      = uint32(1 << 8)
	kernelDatapathSessionFlagDatagram            = uint32(1 << 9)
	kernelDatapathSessionFlagFragmentingDatagram = uint32(1 << 10)

	kernelDatapathFlowFlagIPv4 = uint32(1 << 0)

	kernelDatapathSessionWireFlagIPv4        = uint32(1 << 0)
	kernelDatapathSessionWireFlagLocalKnown  = uint32(1 << 1)
	kernelDatapathSessionWireFlagRemoteKnown = uint32(1 << 2)
)

const (
	kernelDatapathKernelUDPFlowAddressPrefix = "kernel_udp_flow:"
	kernelDatapathStateSyncInterval          = 2 * time.Second
)

type kernelDatapathSessionSnapshot struct {
	key     dataSessionKey
	runtime *dataSessionRuntime
	session transport.Session
}

func (daemon *Daemon) syncKernelDatapathState(ctx context.Context, snapshot dataplane.Snapshot) {
	if ctx.Err() != nil {
		return
	}
	if !daemon.kernelDatapathAvailable() {
		return
	}
	stats, err := kernelmodule.DatapathStateStatsQuery(kernelmodule.TrustIXDatapathDevicePath)
	if err != nil || stats.MaxRoutes == 0 || stats.MaxSessions == 0 || stats.MaxFlows == 0 {
		return
	}
	records := make([]kernelmodule.DatapathStateRecord, 0, len(snapshot.Routes))
	for _, kind := range []uint32{
		kernelmodule.TrustIXDatapathStateKindRoute,
		kernelmodule.TrustIXDatapathStateKindSession,
		kernelmodule.TrustIXDatapathStateKindSessionWire,
		kernelmodule.TrustIXDatapathStateKindFlow,
	} {
		records = append(records, kernelmodule.DatapathStateRecord{Kind: kind, Op: kernelmodule.TrustIXDatapathStateOpClear})
	}
	for _, route := range snapshot.Routes {
		if record, ok := kernelDatapathRouteRecord(route); ok {
			records = append(records, record)
		}
	}
	for _, item := range daemon.kernelDatapathSessionSnapshot() {
		if ctx.Err() != nil {
			return
		}
		if record, ok := kernelDatapathSessionRecord(item.key, item.runtime, item.session); ok {
			records = append(records, record)
		}
		if record, ok := daemon.kernelDatapathSessionWireRecord(item.key, item.session); ok {
			records = append(records, record)
		}
	}
	records = append(records, daemon.kernelDatapathKernelUDPFlowRecords(ctx)...)
	for _, flow := range daemon.flowSnapshot() {
		if ctx.Err() != nil {
			return
		}
		if record, ok := kernelDatapathFlowRecord(flow); ok {
			records = append(records, record)
		}
	}
	daemon.applyKernelDatapathStateRecords(ctx, records)
}

func (daemon *Daemon) runKernelDatapathStateSync(ctx context.Context) {
	ticker := time.NewTicker(kernelDatapathStateSyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			daemon.syncKernelDatapathState(ctx, daemon.runtimeDataplaneSnapshot())
		}
	}
}

func (daemon *Daemon) syncKernelDatapathSessionUpsert(key dataSessionKey, runtime *dataSessionRuntime, session transport.Session) {
	if !daemon.kernelDatapathAvailable() {
		return
	}
	record, ok := kernelDatapathSessionRecord(key, runtime, session)
	if !ok {
		return
	}
	records := []kernelmodule.DatapathStateRecord{record}
	if wireRecord, ok := daemon.kernelDatapathSessionWireRecord(key, session); ok {
		records = append(records, wireRecord)
	}
	records = append(records, daemon.kernelDatapathKernelUDPFlowRecords(context.Background())...)
	daemon.applyKernelDatapathStateRecords(context.Background(), records)
}

func (daemon *Daemon) syncKernelDatapathSessionDelete(key dataSessionKey) {
	if !daemon.kernelDatapathAvailable() {
		return
	}
	record := kernelmodule.DatapathStateRecord{
		Kind: kernelmodule.TrustIXDatapathStateKindSession,
		Op:   kernelmodule.TrustIXDatapathStateOpDelete,
		Key:  kernelDatapathSessionStateKey(key),
	}
	wireRecord := kernelmodule.DatapathStateRecord{
		Kind: kernelmodule.TrustIXDatapathStateKindSessionWire,
		Op:   kernelmodule.TrustIXDatapathStateOpDelete,
		Key:  kernelDatapathSessionStateKey(key),
	}
	records := []kernelmodule.DatapathStateRecord{record, wireRecord}
	records = append(records, daemon.kernelDatapathKernelUDPFlowRecords(context.Background())...)
	daemon.applyKernelDatapathStateRecords(context.Background(), records)
}

func (daemon *Daemon) syncKernelDatapathFlowUpsert(binding routing.FlowBinding) {
	if !daemon.kernelDatapathAvailable() {
		return
	}
	record, ok := kernelDatapathFlowRecord(binding)
	if !ok {
		return
	}
	daemon.applyKernelDatapathStateRecords(context.Background(), []kernelmodule.DatapathStateRecord{record})
}

func (daemon *Daemon) syncKernelDatapathFlowDelete(key routing.FlowKey) {
	if !daemon.kernelDatapathAvailable() {
		return
	}
	record, ok := kernelDatapathFlowDeleteRecord(key)
	if !ok {
		return
	}
	daemon.applyKernelDatapathStateRecords(context.Background(), []kernelmodule.DatapathStateRecord{record})
}

func (daemon *Daemon) kernelDatapathAvailable() bool {
	return daemon != nil && daemon.kernelDatapath != nil && daemon.kernelDatapath.Snapshot().Loaded
}

func (daemon *Daemon) applyKernelDatapathStateRecords(ctx context.Context, records []kernelmodule.DatapathStateRecord) {
	for len(records) > 0 {
		if ctx.Err() != nil {
			return
		}
		limit := len(records)
		if limit > kernelmodule.TrustIXDatapathStateBatchMax {
			limit = kernelmodule.TrustIXDatapathStateBatchMax
		}
		applied, _, err := kernelmodule.DatapathApplyStateBatch(kernelmodule.TrustIXDatapathDevicePath, records[:limit])
		if err != nil {
			if applied == 0 {
				return
			}
			records = records[int(applied):]
			continue
		}
		records = records[limit:]
	}
}

func (daemon *Daemon) kernelDatapathSessionSnapshot() []kernelDatapathSessionSnapshot {
	if daemon == nil {
		return nil
	}
	daemon.dataMu.Lock()
	defer daemon.dataMu.Unlock()
	sessions := make([]kernelDatapathSessionSnapshot, 0, len(daemon.dataSessions))
	for key, session := range daemon.dataSessions {
		if session == nil {
			continue
		}
		sessions = append(sessions, kernelDatapathSessionSnapshot{
			key:     key,
			runtime: daemon.dataSessionState[key],
			session: session,
		})
	}
	sort.Slice(sessions, func(i, j int) bool {
		left := sessions[i].key
		right := sessions[j].key
		if left.Peer != right.Peer {
			return left.Peer < right.Peer
		}
		if left.Endpoint != right.Endpoint {
			return left.Endpoint < right.Endpoint
		}
		if left.Transport != right.Transport {
			return left.Transport < right.Transport
		}
		if left.Address != right.Address {
			return left.Address < right.Address
		}
		if left.Encryption != right.Encryption {
			return left.Encryption < right.Encryption
		}
		return left.PoolIndex < right.PoolIndex
	})
	return sessions
}

func (daemon *Daemon) kernelDatapathKernelUDPFlowRecords(ctx context.Context) []kernelmodule.DatapathStateRecord {
	if daemon == nil || daemon.dataplane == nil {
		return nil
	}
	snapshotter, ok := daemon.dataplane.(dataplane.KernelUDPFlowSnapshotter)
	if !ok {
		return nil
	}
	flows, err := snapshotter.KernelUDPFlows(ctx)
	if err != nil || len(flows) == 0 {
		return nil
	}
	sessionFlowIDs := daemon.kernelDatapathSessionFlowIDs()
	records := make([]kernelmodule.DatapathStateRecord, 0, len(flows)*2)
	for _, flow := range flows {
		if ctx.Err() != nil {
			return records
		}
		if flow.ID == 0 || sessionFlowIDs[flow.ID] {
			continue
		}
		if record, ok := kernelDatapathKernelUDPFlowSessionRecord(flow); ok {
			records = append(records, record)
		}
		if record, ok := kernelDatapathKernelUDPFlowSessionWireRecord(flow); ok {
			records = append(records, record)
		}
	}
	return records
}

func (daemon *Daemon) kernelDatapathSessionFlowIDs() map[uint64]bool {
	ids := make(map[uint64]bool)
	for _, item := range daemon.kernelDatapathSessionSnapshot() {
		info, ok := kernelDatapathSessionInfo(item.session)
		if ok && info.FlowID != 0 {
			ids[info.FlowID] = true
		}
	}
	return ids
}

func kernelDatapathRouteRecord(route routing.Route) (kernelmodule.DatapathStateRecord, bool) {
	prefix, err := route.Prefix.Parse()
	if err != nil || !prefix.Addr().Is4() {
		return kernelmodule.DatapathStateRecord{}, false
	}
	prefix = prefix.Masked()
	addr := prefix.Addr().As4()
	record := kernelmodule.DatapathStateRecord{
		Kind:  kernelmodule.TrustIXDatapathStateKindRoute,
		Op:    kernelmodule.TrustIXDatapathStateOpUpsert,
		Flags: kernelDatapathRouteKindFlag(route.Kind),
		Key: [4]uint64{
			uint64(binary.BigEndian.Uint32(addr[:])),
			uint64(prefix.Bits()),
			hashString64(string(route.NextHop)),
			hashString64(string(route.Endpoint)),
		},
		Value: [8]uint64{
			uint64(route.Metric),
			hashString64(string(route.Owner)),
			hashString64(string(route.Policy)),
			hashString64(route.Source),
		},
	}
	if route.LocalProtocol != 0 || route.LocalPort != 0 {
		record.Value[4] = uint64(route.LocalProtocol)
		record.Value[5] = uint64(route.LocalPort)
	}
	return record, true
}

func kernelDatapathSessionRecord(key dataSessionKey, runtime *dataSessionRuntime, session transport.Session) (kernelmodule.DatapathStateRecord, bool) {
	info, ok := kernelDatapathSessionInfo(session)
	if !ok || info.FlowID == 0 {
		return kernelmodule.DatapathStateRecord{}, false
	}
	if info.Protocol == "" {
		info.Protocol = key.Transport
	}
	record := kernelmodule.DatapathStateRecord{
		Kind:  kernelmodule.TrustIXDatapathStateKindSession,
		Op:    kernelmodule.TrustIXDatapathStateOpUpsert,
		Flags: kernelDatapathSessionFlags(key, runtime, info),
		Key:   kernelDatapathSessionStateKey(key),
		Value: [8]uint64{
			info.FlowID,
			uint64(kernelDatapathTransportCode(info.Protocol)),
			info.Epoch,
			hashString64(info.CryptoSuite),
			uint64(kernelDatapathCryptoPlacementCode(info.CryptoPlacement)),
			kernelDatapathRuntimeLastRX(runtime),
			kernelDatapathRuntimeLastTX(runtime),
			uint64(uint32(key.PoolIndex)),
		},
	}
	return record, true
}

func kernelDatapathKernelUDPFlowSessionRecord(flow dataplane.KernelUDPFlow) (kernelmodule.DatapathStateRecord, bool) {
	key, ok := kernelDatapathKernelUDPFlowSessionKey(flow)
	if !ok {
		return kernelmodule.DatapathStateRecord{}, false
	}
	record := kernelmodule.DatapathStateRecord{
		Kind: kernelmodule.TrustIXDatapathStateKindSession,
		Op:   kernelmodule.TrustIXDatapathStateOpUpsert,
		Flags: kernelDatapathSessionFlagKernelFlow |
			kernelDatapathSessionFlagDatagram |
			kernelDatapathSessionFlagNativeBatching,
		Key: key,
		Value: [8]uint64{
			flow.ID,
			uint64(kernelDatapathTransportCode(transport.ProtocolUDP)),
			flow.Epoch,
			hashString64(flow.CryptoSuite),
			uint64(kernelDatapathCryptoPlacementCode(string(flow.CryptoPlacement))),
			kernelDatapathUnixNano(flow.LastSeen.UnixNano()),
			kernelDatapathUnixNano(flow.LastSeen.UnixNano()),
			0,
		},
	}
	switch flow.CryptoPlacement {
	case dataplane.CryptoPlacementKernel:
		record.Flags |= kernelDatapathSessionFlagCryptoKernel
	case dataplane.CryptoPlacementUserspace:
		record.Flags |= kernelDatapathSessionFlagCryptoUserspace
	}
	if flow.CryptoSuite != "" {
		record.Flags |= kernelDatapathSessionFlagEncrypted
	}
	return record, true
}

func (daemon *Daemon) kernelDatapathSessionWireRecord(key dataSessionKey, session transport.Session) (kernelmodule.DatapathStateRecord, bool) {
	info, ok := kernelDatapathSessionInfo(session)
	if !ok || info.FlowID == 0 {
		return kernelmodule.DatapathStateRecord{}, false
	}
	if info.Protocol == "" {
		info.Protocol = key.Transport
	}
	info = daemon.kernelDatapathResolveSessionWireInfo(info)
	local, localPort, ok := kernelDatapathParseIPv4AddrPort(info.LocalAddress)
	if !ok {
		return kernelmodule.DatapathStateRecord{}, false
	}
	remote, remotePort, ok := kernelDatapathParseIPv4AddrPort(info.RemoteAddress)
	if !ok {
		return kernelmodule.DatapathStateRecord{}, false
	}
	if info.SourcePort != 0 {
		localPort = info.SourcePort
	}
	if info.DestinationPort != 0 {
		remotePort = info.DestinationPort
	}
	if localPort == 0 || remotePort == 0 {
		return kernelmodule.DatapathStateRecord{}, false
	}
	return kernelmodule.DatapathStateRecord{
		Kind:  kernelmodule.TrustIXDatapathStateKindSessionWire,
		Op:    kernelmodule.TrustIXDatapathStateOpUpsert,
		Flags: kernelDatapathSessionWireFlagIPv4 | kernelDatapathSessionWireFlagLocalKnown | kernelDatapathSessionWireFlagRemoteKnown,
		Key:   kernelDatapathSessionStateKey(key),
		Value: [8]uint64{
			info.FlowID,
			uint64(local),
			uint64(remote),
			uint64(localPort)<<16 | uint64(remotePort),
			uint64(kernelDatapathTransportCode(info.Protocol)),
			info.MaxPacketSize,
			kernelDatapathSessionWireEpoch(info),
			uint64(uint32(key.PoolIndex)),
		},
	}, true
}

func kernelDatapathKernelUDPFlowSessionWireRecord(flow dataplane.KernelUDPFlow) (kernelmodule.DatapathStateRecord, bool) {
	key, ok := kernelDatapathKernelUDPFlowSessionKey(flow)
	if !ok {
		return kernelmodule.DatapathStateRecord{}, false
	}
	local, localPort, ok := kernelDatapathParseIPv4AddrPort(flow.LocalAddress)
	if !ok {
		return kernelmodule.DatapathStateRecord{}, false
	}
	remote, remotePort, ok := kernelDatapathParseIPv4AddrPort(flow.RemoteAddress)
	if !ok {
		return kernelmodule.DatapathStateRecord{}, false
	}
	if flow.SourcePort != 0 {
		localPort = flow.SourcePort
	}
	if flow.DestinationPort != 0 {
		remotePort = flow.DestinationPort
	}
	if localPort == 0 || remotePort == 0 {
		return kernelmodule.DatapathStateRecord{}, false
	}
	return kernelmodule.DatapathStateRecord{
		Kind:  kernelmodule.TrustIXDatapathStateKindSessionWire,
		Op:    kernelmodule.TrustIXDatapathStateOpUpsert,
		Flags: kernelDatapathSessionWireFlagIPv4 | kernelDatapathSessionWireFlagLocalKnown | kernelDatapathSessionWireFlagRemoteKnown,
		Key:   key,
		Value: [8]uint64{
			flow.ID,
			uint64(local),
			uint64(remote),
			uint64(localPort)<<16 | uint64(remotePort),
			uint64(kernelDatapathTransportCode(transport.ProtocolUDP)),
			0,
			0,
			0,
		},
	}, true
}

func kernelDatapathSessionWireEpoch(info transport.KernelDatapathSessionInfo) uint64 {
	if info.Protocol == transport.ProtocolUDP {
		return 0
	}
	return info.Epoch
}

func (daemon *Daemon) kernelDatapathResolveSessionWireInfo(info transport.KernelDatapathSessionInfo) transport.KernelDatapathSessionInfo {
	if daemon == nil || daemon.dataplane == nil || info.FlowID == 0 {
		return info
	}
	switch info.Protocol {
	case transport.ProtocolUDP:
		lookup, ok := daemon.dataplane.(dataplane.KernelUDPFlowLookup)
		if !ok {
			return info
		}
		flow, found, err := lookup.KernelUDPFlow(context.Background(), info.FlowID)
		if err != nil || !found {
			return info
		}
		if flow.LocalAddress != "" {
			info.LocalAddress = flow.LocalAddress
		}
		if flow.RemoteAddress != "" {
			info.RemoteAddress = flow.RemoteAddress
		}
		if flow.SourcePort != 0 {
			info.SourcePort = flow.SourcePort
		}
		if flow.DestinationPort != 0 {
			info.DestinationPort = flow.DestinationPort
		}
	case transport.ProtocolExperimentalTCP:
		lookup, ok := daemon.dataplane.(dataplane.ExperimentalTCPFlowLookup)
		if !ok {
			return info
		}
		flow, found, err := lookup.ExperimentalTCPFlow(context.Background(), info.FlowID)
		if err != nil || !found {
			return info
		}
		if flow.LocalAddress != "" {
			info.LocalAddress = flow.LocalAddress
		}
		if flow.RemoteAddress != "" {
			info.RemoteAddress = flow.RemoteAddress
		}
		if flow.SourcePort != 0 {
			info.SourcePort = flow.SourcePort
		}
		if flow.DestinationPort != 0 {
			info.DestinationPort = flow.DestinationPort
		}
	}
	return info
}

func kernelDatapathSessionInfo(session transport.Session) (transport.KernelDatapathSessionInfo, bool) {
	if session == nil {
		return transport.KernelDatapathSessionInfo{}, false
	}
	introspector, ok := session.(transport.KernelDatapathSession)
	if !ok {
		return transport.KernelDatapathSessionInfo{}, false
	}
	return introspector.KernelDatapathSessionInfo()
}

func kernelDatapathSessionStateKey(key dataSessionKey) [4]uint64 {
	return [4]uint64{
		hashString64(string(key.Peer)),
		hashString64(string(key.Endpoint)),
		hashString64(string(key.Transport)),
		hashString64(key.Encryption + "\x00" + strconv.Itoa(key.PoolIndex)),
	}
}

func kernelDatapathKernelUDPFlowSessionKey(flow dataplane.KernelUDPFlow) ([4]uint64, bool) {
	if flow.ID == 0 || flow.Peer == "" || flow.Endpoint == "" {
		return [4]uint64{}, false
	}
	return [4]uint64{
		hashString64(string(flow.Peer)),
		hashString64(string(flow.Endpoint)),
		hashString64(string(transport.ProtocolUDP)),
		hashString64(kernelDatapathKernelUDPFlowAddressPrefix + strconv.FormatUint(flow.ID, 16)),
	}, true
}

func kernelDatapathSessionFlags(key dataSessionKey, runtime *dataSessionRuntime, info transport.KernelDatapathSessionInfo) uint32 {
	flags := kernelDatapathSessionFlagKernelFlow
	if key.Address == reverseSessionAddress {
		flags |= kernelDatapathSessionFlagReverse
	}
	if runtime != nil && runtime.controlOnly {
		flags |= kernelDatapathSessionFlagControlOnly
	}
	if info.Encrypted {
		flags |= kernelDatapathSessionFlagEncrypted
	}
	if info.SendEncrypted {
		flags |= kernelDatapathSessionFlagSendEncrypted
	}
	if info.ReceiveEncrypted {
		flags |= kernelDatapathSessionFlagReceiveEncrypted
	}
	switch info.CryptoPlacement {
	case "kernel":
		flags |= kernelDatapathSessionFlagCryptoKernel
	case "userspace":
		flags |= kernelDatapathSessionFlagCryptoUserspace
	}
	if info.NativeBatching {
		flags |= kernelDatapathSessionFlagNativeBatching
	}
	if info.Datagram {
		flags |= kernelDatapathSessionFlagDatagram
	}
	if info.FragmentingDatagram {
		flags |= kernelDatapathSessionFlagFragmentingDatagram
	}
	return flags
}

func kernelDatapathFlowRecord(binding routing.FlowBinding) (kernelmodule.DatapathStateRecord, bool) {
	key, ok := kernelDatapathFlowStateKey(binding.Key)
	if !ok {
		return kernelmodule.DatapathStateRecord{}, false
	}
	return kernelmodule.DatapathStateRecord{
		Kind:  kernelmodule.TrustIXDatapathStateKindFlow,
		Op:    kernelmodule.TrustIXDatapathStateOpUpsert,
		Flags: kernelDatapathFlowFlagIPv4,
		Key:   key,
		Value: [8]uint64{
			hashString64(string(binding.NextHop)),
			hashString64(string(binding.Endpoint)),
			uint64(uint32(binding.PoolIndex)),
			kernelDatapathUnixNano(binding.LastSeen.UnixNano()),
			kernelDatapathUnixNano(binding.ExpiresAt.UnixNano()),
		},
	}, true
}

func kernelDatapathFlowDeleteRecord(key routing.FlowKey) (kernelmodule.DatapathStateRecord, bool) {
	stateKey, ok := kernelDatapathFlowStateKey(key)
	if !ok {
		return kernelmodule.DatapathStateRecord{}, false
	}
	return kernelmodule.DatapathStateRecord{
		Kind: kernelmodule.TrustIXDatapathStateKindFlow,
		Op:   kernelmodule.TrustIXDatapathStateOpDelete,
		Key:  stateKey,
	}, true
}

func kernelDatapathFlowStateKey(key routing.FlowKey) ([4]uint64, bool) {
	source, ok := kernelDatapathIPv4Uint32(key.SourceIP)
	if !ok {
		return [4]uint64{}, false
	}
	destination, ok := kernelDatapathIPv4Uint32(key.DestinationIP)
	if !ok {
		return [4]uint64{}, false
	}
	return [4]uint64{
		uint64(source),
		uint64(destination),
		uint64(key.SourcePort)<<16 | uint64(key.DestinationPort),
		uint64(key.Protocol),
	}, true
}

func kernelDatapathRouteKindFlag(kind routing.RouteKind) uint32 {
	switch kind {
	case "", routing.RouteUnicast:
		return 1
	case routing.RouteLocal:
		return 2
	case routing.RouteBlackhole:
		return 3
	case routing.RouteReject:
		return 4
	default:
		return 0
	}
}

func kernelDatapathTransportCode(protocol transport.Protocol) uint32 {
	switch protocol {
	case transport.ProtocolUDP:
		return 1
	case transport.ProtocolExperimentalTCP:
		return 2
	case transport.ProtocolGRE:
		return 3
	case transport.ProtocolIPIP:
		return 4
	case transport.ProtocolVXLAN:
		return 5
	case transport.ProtocolTCP:
		return 6
	default:
		return 0
	}
}

func kernelDatapathCryptoPlacementCode(placement string) uint32 {
	switch placement {
	case "kernel":
		return 1
	case "userspace":
		return 2
	case "auto":
		return 3
	default:
		return 0
	}
}

func kernelDatapathRuntimeLastRX(runtime *dataSessionRuntime) uint64 {
	if runtime == nil {
		return 0
	}
	return kernelDatapathUnixNano(runtime.lastRX.Load())
}

func kernelDatapathRuntimeLastTX(runtime *dataSessionRuntime) uint64 {
	if runtime == nil {
		return 0
	}
	return kernelDatapathUnixNano(runtime.lastTX.Load())
}

func kernelDatapathUnixNano(value int64) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value)
}

func kernelDatapathIPv4Uint32(addr netip.Addr) (uint32, bool) {
	addr = addr.Unmap()
	if !addr.Is4() {
		return 0, false
	}
	raw := addr.As4()
	return binary.BigEndian.Uint32(raw[:]), true
}

func kernelDatapathParseIPv4AddrPort(address string) (uint32, uint16, bool) {
	address = strings.TrimSpace(address)
	if address == "" {
		return 0, 0, false
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return 0, 0, false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return 0, 0, false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return 0, 0, false
	}
	ipv4, ok := kernelDatapathIPv4Uint32(addr)
	if !ok {
		return 0, 0, false
	}
	return ipv4, uint16(port), true
}

func hashString64(value string) uint64 {
	if value == "" {
		return 0
	}
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(value))
	return hash.Sum64()
}
