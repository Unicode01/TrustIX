//go:build linux

package daemon

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/kernelmodule"
	"trustix.local/trustix/internal/routing"
	"trustix.local/trustix/internal/transport"
)

func TestKernelDatapathRouteRecordEncodesIPv4Prefix(t *testing.T) {
	route := routing.Route{
		Prefix:   core.Prefix("10.82.0.0/24"),
		Owner:    "ix-b",
		NextHop:  "ix-c",
		Endpoint: "wan-tcp",
		Metric:   100,
		Policy:   "fast",
		Kind:     routing.RouteUnicast,
		Source:   "dynamic",
	}
	record, ok := kernelDatapathRouteRecord(route)
	if !ok {
		t.Fatal("route record was not encoded")
	}
	addr := netip.MustParseAddr("10.82.0.0").As4()
	if record.Kind != kernelmodule.TrustIXDatapathStateKindRoute ||
		record.Op != kernelmodule.TrustIXDatapathStateOpUpsert ||
		record.Flags != 1 ||
		record.Key[0] != uint64(binary.BigEndian.Uint32(addr[:])) ||
		record.Key[1] != 24 ||
		record.Key[2] == 0 ||
		record.Key[3] == 0 ||
		record.Value[0] != 100 ||
		record.Value[1] == 0 ||
		record.Value[2] == 0 ||
		record.Value[3] == 0 {
		t.Fatalf("unexpected route record: %#v", record)
	}
}

func TestKernelDatapathRouteRecordSkipsIPv6ForNow(t *testing.T) {
	_, ok := kernelDatapathRouteRecord(routing.Route{Prefix: core.Prefix("fd00::/64"), NextHop: "ix-b"})
	if ok {
		t.Fatal("IPv6 route should be skipped until the first full datapath ABI defines IPv6 keys")
	}
}

func TestKernelDatapathSessionRecordEncodesKernelFlow(t *testing.T) {
	key := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "wan-udp",
		Transport:  transport.ProtocolUDP,
		Address:    "198.51.100.2:9000",
		Encryption: "secure",
		PoolIndex:  2,
	}
	runtime := &dataSessionRuntime{
		key:         key,
		peer:        config.PeerConfig{ID: "ix-b"},
		endpoint:    config.EndpointConfig{Name: "wan-udp"},
		controlOnly: true,
	}
	runtime.lastRX.Store(100)
	runtime.lastTX.Store(200)
	session := kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
		FlowID:              0x1020304050607080,
		Protocol:            transport.ProtocolUDP,
		Peer:                "ix-b",
		Endpoint:            "wan-udp",
		LocalAddress:        "192.0.2.1:51820",
		RemoteAddress:       "198.51.100.2:17041",
		Epoch:               7,
		CryptoSuite:         "AES-128-GCM-X25519",
		CryptoPlacement:     "kernel",
		Encrypted:           true,
		SendEncrypted:       true,
		ReceiveEncrypted:    true,
		NativeBatching:      true,
		Datagram:            true,
		FragmentingDatagram: true,
		MaxPacketSize:       64000,
	}}
	record, ok := kernelDatapathSessionRecord(key, runtime, session)
	if !ok {
		t.Fatal("session record was not encoded")
	}
	if record.Kind != kernelmodule.TrustIXDatapathStateKindSession ||
		record.Op != kernelmodule.TrustIXDatapathStateOpUpsert ||
		record.Key != kernelDatapathSessionStateKey(key) ||
		record.Value[0] != 0x1020304050607080 ||
		record.Value[1] != 1 ||
		record.Value[2] != 7 ||
		record.Value[3] == 0 ||
		record.Value[4] != 1 ||
		record.Value[5] != 100 ||
		record.Value[6] != 200 ||
		record.Value[7] != 2 {
		t.Fatalf("unexpected session record: %#v", record)
	}
	for _, flag := range []uint32{
		kernelDatapathSessionFlagControlOnly,
		kernelDatapathSessionFlagKernelFlow,
		kernelDatapathSessionFlagEncrypted,
		kernelDatapathSessionFlagSendEncrypted,
		kernelDatapathSessionFlagReceiveEncrypted,
		kernelDatapathSessionFlagCryptoKernel,
		kernelDatapathSessionFlagNativeBatching,
		kernelDatapathSessionFlagDatagram,
		kernelDatapathSessionFlagFragmentingDatagram,
	} {
		if record.Flags&flag == 0 {
			t.Fatalf("session record missing flag %#x: %#v", flag, record)
		}
	}
}

func TestKernelDatapathSessionWireRecordEncodesIPv4Underlay(t *testing.T) {
	key := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "wan-udp",
		Transport:  transport.ProtocolUDP,
		Address:    "198.51.100.2:17041",
		Encryption: "none",
		PoolIndex:  5,
	}
	session := kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
		FlowID:        0x1020304050607080,
		Protocol:      transport.ProtocolUDP,
		Peer:          "ix-b",
		Endpoint:      "wan-udp",
		LocalAddress:  "192.0.2.1:51820",
		RemoteAddress: "198.51.100.2:17041",
		MaxPacketSize: 64000,
		Epoch:         11,
	}}
	record, ok := (*Daemon)(nil).kernelDatapathSessionWireRecord(key, session)
	if !ok {
		t.Fatal("session wire record was not encoded")
	}
	local := netip.MustParseAddr("192.0.2.1").As4()
	remote := netip.MustParseAddr("198.51.100.2").As4()
	if record.Kind != kernelmodule.TrustIXDatapathStateKindSessionWire ||
		record.Op != kernelmodule.TrustIXDatapathStateOpUpsert ||
		record.Flags != kernelDatapathSessionWireFlagIPv4|kernelDatapathSessionWireFlagLocalKnown|kernelDatapathSessionWireFlagRemoteKnown ||
		record.Key != kernelDatapathSessionStateKey(key) ||
		record.Value[0] != 0x1020304050607080 ||
		record.Value[1] != uint64(binary.BigEndian.Uint32(local[:])) ||
		record.Value[2] != uint64(binary.BigEndian.Uint32(remote[:])) ||
		record.Value[3] != uint64(51820)<<16|uint64(17041) ||
		record.Value[4] != 1 ||
		record.Value[5] != 64000 ||
		record.Value[6] != 0 ||
		record.Value[7] != 5 {
		t.Fatalf("unexpected session wire record: %#v", record)
	}
}

func TestKernelDatapathSessionWireRecordKeepsExperimentalTCPEpoch(t *testing.T) {
	key := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "wan-exp-tcp",
		Transport:  transport.ProtocolExperimentalTCP,
		Address:    "198.51.100.2:17041",
		Encryption: "secure",
	}
	session := kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
		FlowID:        0x1020304050607080,
		Protocol:      transport.ProtocolExperimentalTCP,
		LocalAddress:  "192.0.2.1:51820",
		RemoteAddress: "198.51.100.2:17041",
		Epoch:         11,
	}}
	record, ok := (*Daemon)(nil).kernelDatapathSessionWireRecord(key, session)
	if !ok {
		t.Fatal("session wire record was not encoded")
	}
	if record.Value[4] != 2 || record.Value[6] != 11 {
		t.Fatalf("unexpected experimental_tcp wire record: %#v", record)
	}
}

func TestKernelDatapathSessionWireRecordSkipsUnresolvedUnderlay(t *testing.T) {
	key := dataSessionKey{Peer: "ix-b", Endpoint: "wan-udp", Transport: transport.ProtocolUDP}
	session := kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
		FlowID:        7,
		Protocol:      transport.ProtocolUDP,
		LocalAddress:  "192.0.2.1:51820",
		RemoteAddress: "peer.example.net:17041",
	}}
	if _, ok := (*Daemon)(nil).kernelDatapathSessionWireRecord(key, session); ok {
		t.Fatal("session wire record should skip unresolved domain names until provider resolves them")
	}
}

func TestKernelDatapathSessionRecordSkipsUserspaceSession(t *testing.T) {
	key := dataSessionKey{Peer: "ix-b", Endpoint: "wan-tcp", Transport: transport.ProtocolTCP}
	if _, ok := kernelDatapathSessionRecord(key, nil, kernelDatapathUserspaceTestSession{}); ok {
		t.Fatal("userspace session without kernel datapath info should be skipped")
	}
}

func TestKernelDatapathKernelUDPFlowRecordsEncodeSessionAndWire(t *testing.T) {
	flow := dataplane.KernelUDPFlow{
		ID:              0x1122334455667788,
		Peer:            "ix-b",
		Endpoint:        "wan-udp",
		LocalAddress:    "192.0.2.1:17001",
		RemoteAddress:   "198.51.100.2:52000",
		SourcePort:      17001,
		DestinationPort: 52000,
		Epoch:           42,
		CryptoSuite:     "AES-128-GCM-X25519",
		CryptoPlacement: dataplane.CryptoPlacementKernel,
		LastSeen:        time.Unix(0, 1000).UTC(),
	}
	session, ok := kernelDatapathKernelUDPFlowSessionRecord(flow)
	if !ok {
		t.Fatal("kernel_udp flow session record was not encoded")
	}
	wire, ok := kernelDatapathKernelUDPFlowSessionWireRecord(flow)
	if !ok {
		t.Fatal("kernel_udp flow wire record was not encoded")
	}
	local := netip.MustParseAddr("192.0.2.1").As4()
	remote := netip.MustParseAddr("198.51.100.2").As4()
	if session.Kind != kernelmodule.TrustIXDatapathStateKindSession ||
		session.Op != kernelmodule.TrustIXDatapathStateOpUpsert ||
		session.Value[0] != flow.ID ||
		session.Value[1] != 1 ||
		session.Value[2] != 42 ||
		session.Value[3] == 0 ||
		session.Value[4] != 1 ||
		session.Value[5] != 1000 ||
		session.Value[6] != 1000 ||
		session.Flags&kernelDatapathSessionFlagKernelFlow == 0 ||
		session.Flags&kernelDatapathSessionFlagDatagram == 0 ||
		session.Flags&kernelDatapathSessionFlagCryptoKernel == 0 {
		t.Fatalf("unexpected kernel_udp flow session record: %#v", session)
	}
	if wire.Kind != kernelmodule.TrustIXDatapathStateKindSessionWire ||
		wire.Op != kernelmodule.TrustIXDatapathStateOpUpsert ||
		wire.Key != session.Key ||
		wire.Value[0] != flow.ID ||
		wire.Value[1] != uint64(binary.BigEndian.Uint32(local[:])) ||
		wire.Value[2] != uint64(binary.BigEndian.Uint32(remote[:])) ||
		wire.Value[3] != uint64(17001)<<16|uint64(52000) ||
		wire.Value[4] != 1 ||
		wire.Value[6] != 0 {
		t.Fatalf("unexpected kernel_udp flow wire record: %#v", wire)
	}
}

func TestKernelDatapathKernelUDPFlowRecordsSkipExistingSessionFlowID(t *testing.T) {
	daemon := &Daemon{
		dataplane: &kernelDatapathFlowSnapshotManager{flows: []dataplane.KernelUDPFlow{{
			ID:              7,
			Peer:            "ix-b",
			Endpoint:        "wan-udp",
			LocalAddress:    "192.0.2.1:17001",
			RemoteAddress:   "198.51.100.2:52000",
			SourcePort:      17001,
			DestinationPort: 52000,
		}}},
		dataSessions: map[dataSessionKey]transport.Session{
			{Peer: "ix-b", Endpoint: "wan-udp", Transport: transport.ProtocolUDP, Encryption: "none"}: kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
				FlowID:        7,
				Protocol:      transport.ProtocolUDP,
				Peer:          "ix-b",
				Endpoint:      "wan-udp",
				LocalAddress:  "192.0.2.1:17001",
				RemoteAddress: "198.51.100.2:52000",
			}},
		},
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
	}
	if records := daemon.kernelDatapathKernelUDPFlowRecords(context.Background()); len(records) != 0 {
		t.Fatalf("records for existing session flow = %#v, want none", records)
	}
}

func TestKernelDatapathFullPlaintextRouteSessionRecordsIgnoreExistingSessionKey(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_FORCE_FULL_PLAINTEXT_TX", "1")
	daemon := &Daemon{
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-a"},
			KernelModules: config.KernelModulesConfig{
				CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
			},
			TransportPolicy: config.TransportPolicyConfig{
				Encryption: "plaintext",
			},
			Endpoints: []config.EndpointConfig{{
				Name:      "wan-udp",
				Mode:      config.EndpointModePassive,
				Listen:    "192.0.2.1:17041",
				Address:   "192.0.2.1:17041",
				Transport: string(transport.ProtocolUDP),
				Security: config.EndpointSecurityConfig{
					Encryption: "plaintext",
				},
				Enabled: true,
			}},
			Peers: []config.PeerConfig{{
				ID: "ix-b",
				Endpoints: []config.EndpointConfig{{
					Name:      "wan-udp",
					Mode:      config.EndpointModePassive,
					Address:   "198.51.100.2:17042",
					Transport: string(transport.ProtocolUDP),
					Security: config.EndpointSecurityConfig{
						Encryption: "plaintext",
					},
					Enabled: true,
				}},
			}},
		},
		dataSessions:     map[dataSessionKey]transport.Session{},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{},
	}
	existingKey := dataSessionKey{
		Peer:       "ix-b",
		Endpoint:   "wan-udp",
		Transport:  transport.ProtocolUDP,
		Address:    "198.51.100.2:17042",
		Encryption: "plaintext",
	}
	daemon.dataSessions[existingKey] = kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
		FlowID:   7,
		Peer:     "ix-b",
		Endpoint: "wan-udp",
	}}
	daemon.dataSessionState[existingKey] = &dataSessionRuntime{key: existingKey}

	records := daemon.kernelDatapathFullPlaintextRouteSessionRecords(context.Background(), []routing.Route{{
		Prefix:   core.Prefix("10.202.12.0/24"),
		NextHop:  "ix-b",
		Endpoint: "wan-udp",
		Kind:     routing.RouteUnicast,
	}})
	if len(records) != 2 {
		t.Fatalf("full plaintext records = %#v, want session+wire", records)
	}
	if records[0].Kind != kernelmodule.TrustIXDatapathStateKindSession ||
		records[1].Kind != kernelmodule.TrustIXDatapathStateKindSessionWire ||
		records[0].Key != kernelDatapathSessionStateKey(existingKey) ||
		records[1].Key != records[0].Key {
		t.Fatalf("unexpected full plaintext records: %#v", records)
	}
	if records[1].Value[0] != records[0].Value[0] || records[1].Value[0] == 0 {
		t.Fatalf("wire record does not match synthetic flow id: session=%#v wire=%#v", records[0], records[1])
	}
}

func TestKernelDatapathFullPlaintextRouteSessionRecordsCoverActivePoolIndexes(t *testing.T) {
	t.Setenv("TRUSTIX_KERNEL_DATAPATH_FORCE_FULL_PLAINTEXT_TX", "1")
	daemon := &Daemon{
		desired: config.Desired{
			IX: config.IXConfig{ID: "ix-a"},
			KernelModules: config.KernelModulesConfig{
				CapabilityProfile: config.KernelCapabilityProfileFullPlaintext,
			},
			TransportPolicy: config.TransportPolicyConfig{
				Encryption: "plaintext",
			},
			Endpoints: []config.EndpointConfig{{
				Name:      "wan-udp",
				Mode:      config.EndpointModePassive,
				Listen:    "192.0.2.1:17041",
				Address:   "192.0.2.1:17041",
				Transport: string(transport.ProtocolUDP),
				Security: config.EndpointSecurityConfig{
					Encryption: "plaintext",
				},
				Enabled: true,
			}},
			Peers: []config.PeerConfig{{
				ID: "ix-b",
				Endpoints: []config.EndpointConfig{{
					Name:      "wan-udp",
					Mode:      config.EndpointModePassive,
					Address:   "198.51.100.2:17042",
					Transport: string(transport.ProtocolUDP),
					Security: config.EndpointSecurityConfig{
						Encryption: "plaintext",
					},
					Enabled: true,
				}},
			}},
		},
		dataSessions:     map[dataSessionKey]transport.Session{},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{},
	}
	for _, poolIndex := range []int{0, 7, 1} {
		key := dataSessionKey{
			Peer:       "ix-b",
			Endpoint:   "wan-udp",
			Transport:  transport.ProtocolUDP,
			Address:    "198.51.100.2:17042",
			Encryption: "plaintext",
			PoolIndex:  poolIndex,
		}
		daemon.dataSessions[key] = kernelDatapathTestSession{info: transport.KernelDatapathSessionInfo{
			FlowID:   uint64(100 + poolIndex),
			Peer:     "ix-b",
			Endpoint: "wan-udp",
		}}
		daemon.dataSessionState[key] = &dataSessionRuntime{key: key}
	}

	records := daemon.kernelDatapathFullPlaintextRouteSessionRecords(context.Background(), []routing.Route{{
		Prefix:   core.Prefix("10.202.12.0/24"),
		NextHop:  "ix-b",
		Endpoint: "wan-udp",
		Kind:     routing.RouteUnicast,
	}})
	if len(records) != 6 {
		t.Fatalf("full plaintext records = %#v, want three session/wire pairs", records)
	}
	for i, poolIndex := range []int{0, 1, 7} {
		session := records[i*2]
		wire := records[i*2+1]
		key := dataSessionKey{
			Peer:       "ix-b",
			Endpoint:   "wan-udp",
			Transport:  transport.ProtocolUDP,
			Address:    "198.51.100.2:17042",
			Encryption: "plaintext",
			PoolIndex:  poolIndex,
		}
		if session.Kind != kernelmodule.TrustIXDatapathStateKindSession ||
			wire.Kind != kernelmodule.TrustIXDatapathStateKindSessionWire ||
			session.Key != kernelDatapathSessionStateKey(key) ||
			wire.Key != session.Key ||
			session.Value[7] != uint64(poolIndex) ||
			wire.Value[7] != uint64(poolIndex) ||
			wire.Value[0] != session.Value[0] ||
			wire.Value[0] == 0 {
			t.Fatalf("unexpected pool %d records: session=%#v wire=%#v", poolIndex, session, wire)
		}
	}
}

func TestKernelDatapathFullPlaintextFlowIDIsSharedAcrossDirections(t *testing.T) {
	daemon := &Daemon{}
	endpointA := config.EndpointConfig{
		Name:      "ix-a-full",
		Mode:      config.EndpointModePassive,
		Listen:    "192.0.2.1:17041",
		Address:   "192.0.2.1:17041",
		Transport: string(transport.ProtocolUDP),
		Enabled:   true,
	}
	endpointB := config.EndpointConfig{
		Name:      "ix-b-full",
		Mode:      config.EndpointModePassive,
		Listen:    "198.51.100.2:17042",
		Address:   "198.51.100.2:17042",
		Transport: string(transport.ProtocolUDP),
		Enabled:   true,
	}
	sessionAB, wireAB, ok := daemon.kernelDatapathFullPlaintextEndpointRecords(
		context.Background(),
		config.PeerConfig{ID: "ix-b"},
		endpointB,
		endpointA,
		0,
	)
	if !ok {
		t.Fatal("ix-a to ix-b full plaintext records were not encoded")
	}
	sessionBA, wireBA, ok := daemon.kernelDatapathFullPlaintextEndpointRecords(
		context.Background(),
		config.PeerConfig{ID: "ix-a"},
		endpointA,
		endpointB,
		0,
	)
	if !ok {
		t.Fatal("ix-b to ix-a full plaintext records were not encoded")
	}
	if sessionAB.Value[0] == 0 ||
		sessionAB.Value[0] != wireAB.Value[0] ||
		sessionAB.Value[0] != sessionBA.Value[0] ||
		sessionBA.Value[0] != wireBA.Value[0] {
		t.Fatalf("full plaintext flow ids should match both directions: ab session=%#v wire=%#v ba session=%#v wire=%#v", sessionAB, wireAB, sessionBA, wireBA)
	}
	if wireAB.Value[1] != wireBA.Value[2] ||
		wireAB.Value[2] != wireBA.Value[1] ||
		uint16(wireAB.Value[3]>>16) != uint16(wireBA.Value[3]) ||
		uint16(wireAB.Value[3]) != uint16(wireBA.Value[3]>>16) {
		t.Fatalf("full plaintext wire tuples should remain local-perspective encoded: ab=%#v ba=%#v", wireAB, wireBA)
	}
}

func TestKernelDatapathKernelUDPFlowSessionKeyIncludesFlowID(t *testing.T) {
	first, ok := kernelDatapathKernelUDPFlowSessionKey(dataplane.KernelUDPFlow{
		ID:       1,
		Peer:     "ix-b",
		Endpoint: "wan-udp",
	})
	if !ok {
		t.Fatal("first flow key was not encoded")
	}
	second, ok := kernelDatapathKernelUDPFlowSessionKey(dataplane.KernelUDPFlow{
		ID:       2,
		Peer:     "ix-b",
		Endpoint: "wan-udp",
	})
	if !ok {
		t.Fatal("second flow key was not encoded")
	}
	if first == second {
		t.Fatalf("different kernel_udp flow ids produced same session key: %#v", first)
	}
}

func TestKernelDatapathFlowRecordEncodesIPv4Tuple(t *testing.T) {
	binding := routing.FlowBinding{
		Key: routing.FlowKey{
			SourceIP:        netip.MustParseAddr("10.82.0.2"),
			DestinationIP:   netip.MustParseAddr("10.216.0.9"),
			SourcePort:      12345,
			DestinationPort: 5201,
			Protocol:        6,
		},
		NextHop:   "ix-b",
		Endpoint:  "wan-exp-tcp",
		PoolIndex: 3,
		LastSeen:  time.Unix(0, 1000).UTC(),
		ExpiresAt: time.Unix(0, 2000).UTC(),
	}
	record, ok := kernelDatapathFlowRecord(binding)
	if !ok {
		t.Fatal("flow record was not encoded")
	}
	source := netip.MustParseAddr("10.82.0.2").As4()
	destination := netip.MustParseAddr("10.216.0.9").As4()
	if record.Kind != kernelmodule.TrustIXDatapathStateKindFlow ||
		record.Op != kernelmodule.TrustIXDatapathStateOpUpsert ||
		record.Flags != kernelDatapathFlowFlagIPv4 ||
		record.Key[0] != uint64(binary.BigEndian.Uint32(source[:])) ||
		record.Key[1] != uint64(binary.BigEndian.Uint32(destination[:])) ||
		record.Key[2] != uint64(12345)<<16|uint64(5201) ||
		record.Key[3] != 6 ||
		record.Value[0] == 0 ||
		record.Value[1] == 0 ||
		record.Value[2] != 3 ||
		record.Value[3] != 1000 ||
		record.Value[4] != 2000 {
		t.Fatalf("unexpected flow record: %#v", record)
	}
}

func TestKernelDatapathFlowRecordSkipsIPv6ForNow(t *testing.T) {
	_, ok := kernelDatapathFlowRecord(routing.FlowBinding{Key: routing.FlowKey{
		SourceIP:      netip.MustParseAddr("fd00::1"),
		DestinationIP: netip.MustParseAddr("10.216.0.9"),
		Protocol:      17,
	}})
	if ok {
		t.Fatal("IPv6 flow should be skipped until the first full datapath ABI defines IPv6 keys")
	}
}

type kernelDatapathTestSession struct {
	info transport.KernelDatapathSessionInfo
}

func (session kernelDatapathTestSession) KernelDatapathSessionInfo() (transport.KernelDatapathSessionInfo, bool) {
	return session.info, true
}

func (session kernelDatapathTestSession) SendPacket(pkt []byte) error { return nil }
func (session kernelDatapathTestSession) RecvPacket() ([]byte, error) {
	return nil, errors.New("not implemented")
}
func (session kernelDatapathTestSession) Close() error { return nil }
func (session kernelDatapathTestSession) Stats() transport.TransportStats {
	return transport.TransportStats{}
}

type kernelDatapathUserspaceTestSession struct{}

func (session kernelDatapathUserspaceTestSession) SendPacket(pkt []byte) error { return nil }
func (session kernelDatapathUserspaceTestSession) RecvPacket() ([]byte, error) {
	return nil, errors.New("not implemented")
}
func (session kernelDatapathUserspaceTestSession) Close() error { return nil }
func (session kernelDatapathUserspaceTestSession) Stats() transport.TransportStats {
	return transport.TransportStats{}
}

type kernelDatapathFlowSnapshotManager struct {
	dataplane.NoopManager
	flows []dataplane.KernelUDPFlow
}

func (manager kernelDatapathFlowSnapshotManager) KernelUDPFlows(ctx context.Context) ([]dataplane.KernelUDPFlow, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]dataplane.KernelUDPFlow(nil), manager.flows...), nil
}
