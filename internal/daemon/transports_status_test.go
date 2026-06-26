package daemon

import (
	"testing"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/transport"
	securetransport "trustix.local/trustix/internal/transport/secure"
)

func TestTransportMatrixStatusSurfacesVXLANSessionStats(t *testing.T) {
	localEndpoint := config.EndpointConfig{
		Name:      core.EndpointID("a-vxlan"),
		Mode:      config.EndpointModePassive,
		Listen:    "local=10.203.3.202,remote=10.203.3.203,underlay_if=eth1,local_carrier=10.255.10.1/30,remote_carrier=10.255.10.2,port=47829,mtu=1400,vni=7,vxlan_port=4789",
		Address:   "local=10.203.3.202,remote=10.203.3.203,underlay_if=eth1,local_carrier=10.255.10.1/30,remote_carrier=10.255.10.2,port=47829,mtu=1400,vni=7,vxlan_port=4789",
		Transport: string(transport.ProtocolVXLAN),
		Enabled:   true,
	}
	peerEndpoint := config.EndpointConfig{
		Name:      core.EndpointID("b-vxlan"),
		Address:   localEndpoint.Address,
		Transport: string(transport.ProtocolVXLAN),
		Enabled:   true,
	}
	key := dataSessionKey{
		Peer:       core.IXID("ix-b"),
		Endpoint:   peerEndpoint.Name,
		Transport:  transport.ProtocolVXLAN,
		Address:    peerEndpoint.Address,
		Encryption: securetransport.EncryptionPlaintext,
		PoolIndex:  2,
	}
	now := time.Now().UTC()
	runtime := &dataSessionRuntime{
		key:         key,
		peer:        config.PeerConfig{ID: core.IXID("ix-b"), Domain: core.DomainID("lab.local")},
		endpoint:    peerEndpoint,
		receiveLoop: true,
	}
	runtime.lastRX.Store(now.UnixNano())
	runtime.lastTX.Store(now.UnixNano())
	runtime.lastUp.Store(now.UnixNano())
	runtime.lastPong.Store(now.UnixNano())

	daemon := &Daemon{
		dataplane: dataplane.NewNoopManager(),
		desired: config.Desired{
			Domain: config.DomainConfig{ID: core.DomainID("lab.local")},
			IX:     config.IXConfig{ID: core.IXID("ix-a"), Domain: core.DomainID("lab.local")},
			Endpoints: []config.EndpointConfig{
				localEndpoint,
			},
			Peers: []config.PeerConfig{{
				ID:        core.IXID("ix-b"),
				Domain:    core.DomainID("lab.local"),
				Endpoints: []config.EndpointConfig{peerEndpoint},
			}},
			TransportPolicy: config.TransportPolicyConfig{
				Mode:            "user_defined",
				Profile:         config.TransportProfilePerformance,
				Datapath:        config.TransportDatapathTCXDP,
				Encryption:      securetransport.EncryptionPlaintext,
				CryptoPlacement: string(dataplane.CryptoPlacementUserspace),
				SessionPool: config.SessionPoolPolicyConfig{
					Size:     4,
					Strategy: "flow",
					Warmup:   true,
				},
			},
		},
		transports: transport.NewRegistry(),
		dataSessions: map[dataSessionKey]transport.Session{
			key: &recordingSession{stats: transport.TransportStats{
				BytesSent:           4096,
				BytesReceived:       8192,
				PacketsSent:         4,
				PacketsReceived:     8,
				Encryption:          securetransport.EncryptionPlaintext,
				CryptoPlacement:     string(dataplane.CryptoPlacementUserspace),
				NativeBatching:      true,
				Datagram:            true,
				FragmentingDatagram: true,
				MaxPacketSize:       524288,
			}},
		},
		dataSessionState: map[dataSessionKey]*dataSessionRuntime{
			key: runtime,
		},
	}

	status := daemon.transportMatrixStatus()
	if status.Policy.Encryption != securetransport.EncryptionPlaintext || status.Policy.Datapath != config.TransportDatapathTCXDP || status.Policy.CryptoPlacement != string(dataplane.CryptoPlacementUserspace) {
		t.Fatalf("policy = %#v, want plaintext tc_xdp userspace", status.Policy)
	}
	if len(status.LocalEndpoints) != 1 || status.LocalEndpoints[0].Transport != string(transport.ProtocolVXLAN) || !status.LocalEndpoints[0].Usable {
		t.Fatalf("local endpoints = %#v, want usable vxlan endpoint", status.LocalEndpoints)
	}
	if len(status.PeerEndpoints) != 1 || status.PeerEndpoints[0].Transport != string(transport.ProtocolVXLAN) || !status.PeerEndpoints[0].Usable {
		t.Fatalf("peer endpoints = %#v, want usable vxlan endpoint", status.PeerEndpoints)
	}
	if got := status.PeerEndpoints[0].ActiveReverse; got != 0 {
		t.Fatalf("active reverse sessions = %d, want 0 for outbound session", got)
	}
	if len(status.Sessions) != 1 {
		t.Fatalf("sessions = %#v, want one", status.Sessions)
	}
	session := status.Sessions[0]
	if session.Transport != string(transport.ProtocolVXLAN) || session.Endpoint != string(peerEndpoint.Name) || session.PoolIndex != 2 || !session.ReceiveLoop {
		t.Fatalf("session surface = %#v, want vxlan endpoint pool member", session)
	}
	if session.Stats.Encryption != securetransport.EncryptionPlaintext || session.Stats.CryptoPlacement != string(dataplane.CryptoPlacementUserspace) {
		t.Fatalf("session stats = %#v, want plaintext userspace", session.Stats)
	}
	if session.Stats.BytesSent == 0 || session.Stats.BytesReceived == 0 || session.Stats.PacketsSent == 0 || session.Stats.PacketsReceived == 0 {
		t.Fatalf("session traffic stats = %#v, want non-zero traffic", session.Stats)
	}
}
