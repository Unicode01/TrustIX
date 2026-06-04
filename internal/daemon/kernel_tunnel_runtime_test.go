package daemon

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"sync"
	"testing"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/transport"
)

func TestValidateDesiredKernelTunnelConflictsRejectsCarrierReuse(t *testing.T) {
	desired := config.Desired{
		Endpoints: []config.EndpointConfig{
			{
				Name:      "a-gre-1",
				Mode:      config.EndpointModePassive,
				Listen:    "local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.0.1/30,remote_carrier=10.255.0.2,port=47819,mtu=1400",
				Transport: "gre",
				Enabled:   true,
			},
			{
				Name:      "a-gre-2",
				Mode:      config.EndpointModePassive,
				Listen:    "local=198.18.0.1,remote=198.18.0.3,local_carrier=10.255.0.1/30,remote_carrier=10.255.0.2,port=47819,mtu=1400",
				Transport: "gre",
				Enabled:   true,
			},
		},
	}
	err := validateDesiredKernelTunnelConflicts(desired)
	if err == nil || !strings.Contains(err.Error(), "local carrier prefix conflict") {
		t.Fatalf("conflict error = %v, want local carrier prefix conflict", err)
	}
}

func TestNegotiatedKernelTunnelCarrierUsesExpandedCGNATPool(t *testing.T) {
	local, remote := negotiatedTunnelCarrier("ix-a", "ix-b", transport.ProtocolGRE)
	if !local.Addr().Is4() || !remote.Is4() {
		t.Fatalf("carrier is not IPv4: %s %s", local, remote)
	}
	for _, addr := range []string{local.Addr().String(), remote.String()} {
		if !strings.HasPrefix(addr, "100.") {
			t.Fatalf("carrier address %s is outside expanded CGNAT pool", addr)
		}
	}
}

func TestSyncKernelTunnelListenersStartsAndStopsDynamicPeerListeners(t *testing.T) {
	registry := transport.NewRegistry()
	recorder := &recordingListenTransport{name: transport.ProtocolGRE}
	if err := registry.Register(recorder); err != nil {
		t.Fatalf("register gre transport: %v", err)
	}
	daemon := &Daemon{
		desired: config.Desired{
			Domain: config.DomainConfig{ID: "lab.local"},
			IX:     config.IXConfig{ID: "ix-a"},
			Endpoints: []config.EndpointConfig{{
				Name:      "ix-a-gre",
				Mode:      config.EndpointModePassive,
				Listen:    "local=198.18.0.1",
				Address:   "local=198.18.0.1",
				Transport: "gre",
				Enabled:   true,
			}},
		},
		transports:       registry,
		dataplane:        dataplane.NewNoopManager(),
		members:          make(map[core.IXID]memberRecord),
		pendingMembers:   make(map[core.IXID]pendingMemberRecord),
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		sessionPoolRR:    make(map[dataSessionPoolKey]uint64),
		sessionPoolFlow:  make(map[dataSessionFlowPoolKey]int),
		dataPathStarted:  true,
	}
	daemon.members["ix-b"] = memberRecord{
		Advertisement: advertisementResponse{
			DomainID:    "lab.local",
			IXID:        "ix-b",
			LANPrefixes: []string{"10.0.1.0/24"},
			Endpoints: []dataplane.EndpointMetadata{{
				ID:        "ix-b-gre",
				Peer:      "ix-b",
				Transport: "gre",
				Address:   "local=198.18.0.2",
				Enabled:   true,
			}},
		},
	}

	if err := daemon.syncKernelTunnelListeners(context.Background()); err != nil {
		t.Fatalf("sync listeners: %v", err)
	}
	if got := recorder.listenCount(); got != 1 {
		t.Fatalf("listen count = %d, want 1", got)
	}
	if len(daemon.dataListeners) != 1 {
		t.Fatalf("data listeners = %d, want 1", len(daemon.dataListeners))
	}
	if !strings.Contains(recorder.lastListen(), "local=198.18.0.1") || !strings.Contains(recorder.lastListen(), "remote=198.18.0.2") {
		t.Fatalf("listener address = %q, want negotiated local/remote", recorder.lastListen())
	}

	delete(daemon.members, "ix-b")
	if err := daemon.syncKernelTunnelListeners(context.Background()); err != nil {
		t.Fatalf("sync after delete: %v", err)
	}
	if len(daemon.dataListeners) != 0 {
		t.Fatalf("data listeners after delete = %d, want 0", len(daemon.dataListeners))
	}
	if got := recorder.closeCount(); got != 1 {
		t.Fatalf("closed listeners = %d, want 1", got)
	}
}

func BenchmarkRuntimeDataplaneSnapshotScale(b *testing.B) {
	for _, peers := range []int{10, 100, 1000, 5000} {
		b.Run(fmt.Sprintf("udp_peers_%d", peers), func(b *testing.B) {
			daemon := benchmarkMembershipDaemon(b, peers)
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				snapshot := daemon.runtimeDataplaneSnapshot()
				if got := len(snapshot.Routes); got != peers {
					b.Fatalf("routes = %d, want %d", got, peers)
				}
			}
		})
	}
}

func BenchmarkRuntimeKernelTunnelConflictValidationScale(b *testing.B) {
	for _, peers := range []int{10, 100, 1000, 5000} {
		b.Run(fmt.Sprintf("gre_endpoints_%d", peers), func(b *testing.B) {
			snapshot := benchmarkKernelTunnelSnapshot(peers)
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if err := validateRuntimeKernelTunnelConflicts(snapshot); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func benchmarkMembershipDaemon(tb testing.TB, peers int) *Daemon {
	tb.Helper()
	registry := transport.NewRegistry()
	if err := registry.Register(&recordingListenTransport{name: transport.ProtocolUDP}); err != nil {
		tb.Fatalf("register udp transport: %v", err)
	}
	daemon := &Daemon{
		desired: config.Desired{
			Domain: config.DomainConfig{ID: "lab.local"},
			IX:     config.IXConfig{ID: "ix-a"},
		},
		transports:       registry,
		dataplane:        dataplane.NewNoopManager(),
		members:          make(map[core.IXID]memberRecord, peers),
		pendingMembers:   make(map[core.IXID]pendingMemberRecord),
		dataSessions:     make(map[dataSessionKey]transport.Session),
		dataSessionState: make(map[dataSessionKey]*dataSessionRuntime),
		sessionPoolRR:    make(map[dataSessionPoolKey]uint64),
		sessionPoolFlow:  make(map[dataSessionFlowPoolKey]int),
	}
	for i := 0; i < peers; i++ {
		ixID := core.IXID(fmt.Sprintf("ix-%05d", i))
		daemon.members[ixID] = memberRecord{
			Advertisement: advertisementResponse{
				DomainID:    "lab.local",
				IXID:        string(ixID),
				LANPrefixes: []string{fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)},
				Endpoints: []dataplane.EndpointMetadata{{
					ID:        core.EndpointID(fmt.Sprintf("%s-udp", ixID)),
					Peer:      ixID,
					Transport: "udp",
					Address:   fmt.Sprintf("192.0.2.%d:17041", 1+(i%250)),
					Enabled:   true,
				}},
			},
			Direct: true,
		}
	}
	return daemon
}

func benchmarkKernelTunnelSnapshot(peers int) dataplane.Snapshot {
	endpoints := make([]dataplane.EndpointMetadata, 0, peers)
	for i := 0; i < peers; i++ {
		base := 4 * (i + 1)
		endpoints = append(endpoints, dataplane.EndpointMetadata{
			ID:        core.EndpointID(fmt.Sprintf("ix-%05d-gre", i)),
			Peer:      core.IXID(fmt.Sprintf("ix-%05d", i)),
			Transport: "gre",
			Address: fmt.Sprintf(
				"local=198.18.0.1,remote=198.18.%d.%d,local_carrier=100.64.%d.%d/30,remote_carrier=100.64.%d.%d,port=47819,mtu=1400",
				i/250,
				1+(i%250),
				base/256,
				base%256+1,
				base/256,
				base%256+2,
			),
			Enabled: true,
		})
	}
	return dataplane.Snapshot{Endpoints: endpoints}
}

type recordingListenTransport struct {
	name      transport.Protocol
	mu        sync.Mutex
	listens   []transport.Endpoint
	listeners []*recordingListener
}

func (transportImpl *recordingListenTransport) Name() transport.Protocol {
	return transportImpl.name
}

func (transportImpl *recordingListenTransport) Probe(ctx context.Context, peer transport.Peer) transport.ProbeResult {
	return transport.ProbeResult{}
}

func (transportImpl *recordingListenTransport) Dial(ctx context.Context, peer transport.Peer, tlsConf *tls.Config) (transport.Session, error) {
	return nil, fmt.Errorf("unexpected dial")
}

func (transportImpl *recordingListenTransport) Listen(ctx context.Context, endpoint transport.Endpoint, tlsConf *tls.Config) (transport.Listener, error) {
	listener := &recordingListener{done: make(chan struct{})}
	transportImpl.mu.Lock()
	transportImpl.listens = append(transportImpl.listens, endpoint)
	transportImpl.listeners = append(transportImpl.listeners, listener)
	transportImpl.mu.Unlock()
	return listener, nil
}

func (transportImpl *recordingListenTransport) listenCount() int {
	transportImpl.mu.Lock()
	defer transportImpl.mu.Unlock()
	return len(transportImpl.listens)
}

func (transportImpl *recordingListenTransport) lastListen() string {
	transportImpl.mu.Lock()
	defer transportImpl.mu.Unlock()
	if len(transportImpl.listens) == 0 {
		return ""
	}
	return transportImpl.listens[len(transportImpl.listens)-1].Listen
}

func (transportImpl *recordingListenTransport) closeCount() int {
	transportImpl.mu.Lock()
	defer transportImpl.mu.Unlock()
	count := 0
	for _, listener := range transportImpl.listeners {
		if listener.closed {
			count++
		}
	}
	return count
}

type recordingListener struct {
	mu     sync.Mutex
	done   chan struct{}
	closed bool
}

func (listener *recordingListener) Accept(ctx context.Context) (transport.Session, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-listener.done:
		return nil, context.Canceled
	}
}

func (listener *recordingListener) Close() error {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	if !listener.closed {
		listener.closed = true
		close(listener.done)
	}
	return nil
}
