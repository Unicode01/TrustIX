package tixtcp

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/pki"
	"trustix.local/trustix/internal/transport"
	securetransport "trustix.local/trustix/internal/transport/secure"
	"trustix.local/trustix/internal/transport/stream"
)

func TestListenerClosePersistsSubscriptionError(t *testing.T) {
	wantErr := errors.New("injected subscription close failure")
	listener := &listener{
		subscription: &closeErrorTIXTCPSubscription{events: make(chan dataplane.TIXTCPFrame), err: wantErr},
		done:         make(chan struct{}),
		sessions:     make(map[uint64]*session),
	}

	if err := listener.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("first close error = %v, want %v", err, wantErr)
	}
	if err := listener.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("second close error = %v, want persisted %v", err, wantErr)
	}
}

type closeErrorTIXTCPSubscription struct {
	events chan dataplane.TIXTCPFrame
	err    error
}

func (subscription *closeErrorTIXTCPSubscription) Events() <-chan dataplane.TIXTCPFrame {
	return subscription.events
}

func (subscription *closeErrorTIXTCPSubscription) Close() error {
	return subscription.err
}

func TestSecureTransportOverTIXTCPProvider(t *testing.T) {
	providerA, providerB := newProviderPair("ix-a", "ix-b")
	clientTransport := securetransport.New(New(providerA), securetransport.Options{})
	serverTransport := securetransport.New(New(providerB), securetransport.Options{})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := serverTransport.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolTIXTCP,
		Listen:    "ix-b-underlay:443",
		Enabled:   true,
	}, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan transport.Session, 1)
	acceptErr := make(chan error, 1)
	go func() {
		session, err := listener.Accept(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- session
	}()

	client, err := clientTransport.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{
			{
				Name:      core.EndpointID("server"),
				Transport: transport.ProtocolTIXTCP,
				Address:   "ix-b-underlay:443",
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	var server transport.Session
	select {
	case err := <-acceptErr:
		t.Fatalf("accept: %v", err)
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()

	if err := client.SendPacket([]byte("hello-over-tix-tcp")); err != nil {
		t.Fatalf("client send: %v", err)
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if string(got) != "hello-over-tix-tcp" {
		t.Fatalf("server received %q", got)
	}

	if err := server.SendPacket([]byte("reply-over-tix-tcp")); err != nil {
		t.Fatalf("server send: %v", err)
	}
	reply, err := client.RecvPacket()
	if err != nil {
		t.Fatalf("client recv: %v", err)
	}
	if string(reply) != "reply-over-tix-tcp" {
		t.Fatalf("client received %q", reply)
	}
	if !client.Stats().Encrypted || !server.Stats().Encrypted {
		t.Fatal("secure wrapper did not report encrypted tix_tcp sessions")
	}
	if providerA.submitted.Load() == 0 || providerB.submitted.Load() == 0 {
		t.Fatalf("providers did not submit frames: a=%d b=%d", providerA.submitted.Load(), providerB.submitted.Load())
	}
}

func TestTIXTCPDialContextCancelDoesNotCloseSession(t *testing.T) {
	providerA, providerB := newProviderPair("ix-a", "ix-b")
	clientTransport := New(providerA)
	serverTransport := New(providerB)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := serverTransport.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolTIXTCP,
		Listen:    "ix-b-underlay:443",
		Enabled:   true,
	}, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan transport.Session, 1)
	go func() {
		session, err := listener.Accept(ctx)
		if err == nil {
			accepted <- session
		}
	}()

	dialCtx, dialCancel := context.WithCancel(ctx)
	client, err := clientTransport.Dial(dialCtx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolTIXTCP,
			Address:   "ix-b-underlay:443",
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	dialCancel()

	if err := client.SendPacket([]byte("exp-after-cancel")); err != nil {
		t.Fatalf("client send after cancel: %v", err)
	}
	var server transport.Session
	select {
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()
	if got, err := server.RecvPacket(); err != nil || string(got) != "exp-after-cancel" {
		t.Fatalf("server recv after cancel = %q, %v", got, err)
	}
	if err := server.SendPacket([]byte("exp-still-open")); err != nil {
		t.Fatalf("server send after cancel: %v", err)
	}
	reply, err := client.RecvPacket()
	if err != nil {
		t.Fatalf("client recv after cancel: %v", err)
	}
	if string(reply) != "exp-still-open" {
		t.Fatalf("client received %q", reply)
	}
}

func TestTIXTCPCompatPrimerDoesNotPolluteTIXTCPFlowTuple(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_TCP_PRIMER", "1")
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_STREAM", "0")
	provider := &fakeProvider{
		local:   "ix-a",
		subs:    make(map[chan dataplane.TIXTCPFrame]struct{}),
		flows:   make(map[uint64]dataplane.TIXTCPFlow),
		cryptos: make(map[uint64]fakeCrypto),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen primer peer: %v", err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := New(provider).Dial(ctx, transport.Peer{
		ID: core.IXID("ix-b"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolTIXTCP,
			Address:   ln.Addr().String(),
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	var serverConn net.Conn
	select {
	case serverConn = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer serverConn.Close()

	provider.mu.Lock()
	if len(provider.flows) != 1 {
		provider.mu.Unlock()
		t.Fatalf("installed flows = %d, want 1", len(provider.flows))
	}
	var flow dataplane.TIXTCPFlow
	for _, item := range provider.flows {
		flow = item
	}
	provider.mu.Unlock()
	if flow.LocalAddress != "" {
		t.Fatalf("flow local address = %q, want empty so TIX-TCP data path derives its own source tuple", flow.LocalAddress)
	}
	if flow.RemoteAddress != ln.Addr().String() {
		t.Fatalf("flow remote address = %q, want endpoint address %q", flow.RemoteAddress, ln.Addr().String())
	}
	if flow.LocalAddress == serverConn.RemoteAddr().String() {
		t.Fatalf("flow local address inherited primer tuple %q", serverConn.RemoteAddr().String())
	}
}

func TestTIXTCPCompatPrimerListenerInstallsControlFlow(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_TCP_PRIMER", "1")
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_STREAM", "0")
	provider := &fakeProvider{
		local:   "ix-b",
		subs:    make(map[chan dataplane.TIXTCPFrame]struct{}),
		flows:   make(map[uint64]dataplane.TIXTCPFlow),
		cryptos: make(map[uint64]fakeCrypto),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ln, err := New(provider).Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolTIXTCP,
		Listen:    "127.0.0.1:0",
		Enabled:   true,
	}, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	expListener := ln.(*listener)
	if expListener.compatListener == nil {
		t.Fatal("compat primer listener is nil")
	}
	conn, err := net.Dial("tcp", expListener.compatListener.Addr().String())
	if err != nil {
		t.Fatalf("dial compat primer: %v", err)
	}
	control := stream.NewSession(conn)
	defer control.Close()
	const flowID = 0x1020304050607080
	if err := control.SendPacket(encodeTIXTCPCompatControlInit(flowID)); err != nil {
		t.Fatalf("send compat control init: %v", err)
	}
	var accepted transport.Session
	select {
	case accepted = <-expListener.acceptCh:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer accepted.Close()
	provider.mu.Lock()
	flow, ok := provider.flows[flowID]
	provider.mu.Unlock()
	if !ok {
		t.Fatal("compat control flow was not installed")
	}
	clientAddr := conn.LocalAddr().(*net.TCPAddr)
	serverAddr := conn.RemoteAddr().(*net.TCPAddr)
	wantSourcePort := uint16(serverAddr.Port)
	wantDestinationPort := tixTCPCompatDerivedSourcePort(flowID)
	wantLocal := net.JoinHostPort(serverAddr.IP.String(), strconv.Itoa(serverAddr.Port))
	wantRemote := net.JoinHostPort(clientAddr.IP.String(), strconv.Itoa(int(wantDestinationPort)))
	if flow.LocalAddress != wantLocal || flow.RemoteAddress != wantRemote {
		t.Fatalf("flow addresses local=%q remote=%q, want %q %q", flow.LocalAddress, flow.RemoteAddress, wantLocal, wantRemote)
	}
	if flow.SourcePort != wantSourcePort || flow.DestinationPort != wantDestinationPort {
		t.Fatalf("flow ports source=%d destination=%d, want %d %d", flow.SourcePort, flow.DestinationPort, wantSourcePort, wantDestinationPort)
	}
}

func TestTIXTCPCompatControlDecodesOldInitWithoutSourcePort(t *testing.T) {
	const flowID = 0x1020304050607082
	payload := make([]byte, tixTCPCompatControlInitOldLen)
	copy(payload[0:4], tixTCPCompatControlMagic[:])
	payload[4] = tixTCPCompatControlVersion
	payload[5] = tixTCPCompatControlInitType
	binary.BigEndian.PutUint64(payload[6:14], flowID)
	init, ok := decodeTIXTCPCompatControlInit(payload)
	if !ok {
		t.Fatal("old compat control init did not decode")
	}
	if init.flowID != flowID || init.sourcePort != 0 {
		t.Fatalf("decoded init flow=%x source=%d, want flow=%x source=0", init.flowID, init.sourcePort, flowID)
	}
}

func TestTIXTCPCompatControlCloseClosesAcceptedSession(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_TCP_PRIMER", "1")
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_STREAM", "0")
	provider := &fakeProvider{
		local:   "ix-b",
		subs:    make(map[chan dataplane.TIXTCPFrame]struct{}),
		flows:   make(map[uint64]dataplane.TIXTCPFlow),
		cryptos: make(map[uint64]fakeCrypto),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ln, err := New(provider).Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolTIXTCP,
		Listen:    "127.0.0.1:0",
		Enabled:   true,
	}, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	expListener := ln.(*listener)
	conn, err := net.Dial("tcp", expListener.compatListener.Addr().String())
	if err != nil {
		t.Fatalf("dial compat primer: %v", err)
	}
	control := stream.NewSession(conn)
	const flowID = 0x1020304050607081
	if err := control.SendPacket(encodeTIXTCPCompatControlInit(flowID)); err != nil {
		t.Fatalf("send compat control init: %v", err)
	}
	var accepted transport.Session
	select {
	case accepted = <-expListener.acceptCh:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	acceptedSession := accepted.(*session)
	if err := control.Close(); err != nil {
		t.Fatalf("close compat control: %v", err)
	}
	select {
	case <-acceptedSession.closed:
	case <-ctx.Done():
		t.Fatal("accepted session did not close after compat control closed")
	}
	eventually(t, ctx, func() bool {
		expListener.mu.Lock()
		defer expListener.mu.Unlock()
		_, ok := expListener.sessions[flowID]
		return !ok
	})
	provider.mu.Lock()
	_, stillInstalled := provider.flows[flowID]
	provider.mu.Unlock()
	if stillInstalled {
		t.Fatal("compat control flow remained installed after accepted session closed")
	}
}

func TestTIXTCPCompatPrimerRegistersSessionBeforeAcceptDelivery(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_TCP_PRIMER", "1")
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_STREAM", "0")
	provider := &fakeProvider{
		local:   "ix-b",
		subs:    make(map[chan dataplane.TIXTCPFrame]struct{}),
		flows:   make(map[uint64]dataplane.TIXTCPFlow),
		cryptos: make(map[uint64]fakeCrypto),
	}
	ln, err := New(provider).Listen(context.Background(), transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolTIXTCP,
		Listen:    "127.0.0.1:0",
		Enabled:   true,
	}, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	expListener := ln.(*listener)
	conn, err := net.Dial("tcp", expListener.compatListener.Addr().String())
	if err != nil {
		t.Fatalf("dial compat primer: %v", err)
	}
	defer conn.Close()
	control := stream.NewSession(conn)
	defer control.Close()
	const flowID = 0x1234567812345678
	if err := control.SendPacket(encodeTIXTCPCompatControlInit(flowID)); err != nil {
		t.Fatalf("send compat control init: %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		expListener.mu.Lock()
		sess := expListener.sessions[flowID]
		queued := len(expListener.acceptCh)
		expListener.mu.Unlock()
		if sess != nil && queued == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	expListener.mu.Lock()
	sess := expListener.sessions[flowID]
	queuedBefore := len(expListener.acceptCh)
	expListener.mu.Unlock()
	if sess == nil || queuedBefore != 1 {
		t.Fatalf("compat session registered=%t queued=%d, want registered and one accept", sess != nil, queuedBefore)
	}

	expListener.dispatch(dataplane.TIXTCPFrame{
		FlowID:    flowID,
		Direction: dataplane.TIXTCPInbound,
		Endpoint:  core.EndpointID("server"),
		Payload:   []byte("data-after-primer"),
	})
	if queuedAfter := len(expListener.acceptCh); queuedAfter != 1 {
		t.Fatalf("accept queue length after same-flow data = %d, want 1", queuedAfter)
	}
	got, err := sess.RecvPacket()
	if err != nil {
		t.Fatalf("recv same-flow data: %v", err)
	}
	if string(got) != "data-after-primer" {
		t.Fatalf("same-flow data = %q", got)
	}
}

func TestTIXTCPCompatPrimerDropsUnknownFlowFrames(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_TCP_PRIMER", "1")
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_STREAM", "0")
	provider := &fakeProvider{
		local:   "ix-b",
		subs:    make(map[chan dataplane.TIXTCPFrame]struct{}),
		flows:   make(map[uint64]dataplane.TIXTCPFlow),
		cryptos: make(map[uint64]fakeCrypto),
	}
	ln, err := New(provider).Listen(context.Background(), transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolTIXTCP,
		Listen:    "127.0.0.1:0",
		Enabled:   true,
	}, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	expListener := ln.(*listener)
	if !expListener.primerFlowRequired {
		t.Fatal("compat primer listener did not require primer-established flows")
	}

	expListener.dispatch(dataplane.TIXTCPFrame{
		FlowID:    0xfeedface,
		Direction: dataplane.TIXTCPInbound,
		Endpoint:  core.EndpointID("server"),
		Payload:   []byte("stale-data-before-primer"),
	})
	if queued := len(expListener.acceptCh); queued != 0 {
		t.Fatalf("accept queue length = %d, want 0", queued)
	}
	expListener.mu.Lock()
	_, installed := expListener.sessions[0xfeedface]
	expListener.mu.Unlock()
	if installed {
		t.Fatal("unknown flow created a listener session despite compat primer requirement")
	}
}

func TestTIXTCPCompatPrimerDropsUnknownFlowBatchFrames(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_TCP_PRIMER", "1")
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_STREAM", "0")
	provider := &fakeProvider{
		local:   "ix-b",
		subs:    make(map[chan dataplane.TIXTCPFrame]struct{}),
		flows:   make(map[uint64]dataplane.TIXTCPFlow),
		cryptos: make(map[uint64]fakeCrypto),
	}
	ln, err := New(provider).Listen(context.Background(), transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolTIXTCP,
		Listen:    "127.0.0.1:0",
		Enabled:   true,
	}, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	expListener := ln.(*listener)

	expListener.dispatchBatch([]dataplane.TIXTCPFrame{
		{
			FlowID:    0x1111,
			Direction: dataplane.TIXTCPInbound,
			Endpoint:  core.EndpointID("server"),
			Payload:   []byte("stale-batch-1"),
		},
		{
			FlowID:    0x2222,
			Direction: dataplane.TIXTCPInbound,
			Endpoint:  core.EndpointID("server"),
			Payload:   []byte("stale-batch-2"),
		},
	})
	if queued := len(expListener.acceptCh); queued != 0 {
		t.Fatalf("accept queue length = %d, want 0", queued)
	}
	expListener.mu.Lock()
	sessionCount := len(expListener.sessions)
	expListener.mu.Unlock()
	if sessionCount != 0 {
		t.Fatalf("listener sessions = %d, want 0", sessionCount)
	}
}

func TestTIXTCPCompatStreamFallbackRoundTrips(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_TCP_PRIMER", "1")
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_STREAM", "1")
	providerA, providerB := newProviderPair("ix-a", "ix-b")
	clientTransport := New(providerA)
	serverTransport := New(providerB)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ln, err := serverTransport.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolTIXTCP,
		Listen:    "127.0.0.1:0",
		Enabled:   true,
	}, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	expListener := ln.(*listener)
	accepted := make(chan transport.Session, 1)
	go func() {
		session, err := ln.Accept(ctx)
		if err == nil {
			accepted <- session
		}
	}()

	client, err := clientTransport.Dial(ctx, transport.Peer{
		ID: core.IXID("ix-b"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolTIXTCP,
			Address:   expListener.compatListener.Addr().String(),
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	var server transport.Session
	select {
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()
	if _, ok := client.(*compatStreamSession); !ok {
		t.Fatalf("client session type = %T, want compat stream", client)
	}
	if _, ok := server.(*compatStreamSession); !ok {
		t.Fatalf("server session type = %T, want compat stream", server)
	}
	if err := client.SendPacket([]byte("compat-stream")); err != nil {
		t.Fatalf("client send: %v", err)
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if string(got) != "compat-stream" {
		t.Fatalf("server got %q", got)
	}
	if err := server.SendPacket([]byte("compat-reply")); err != nil {
		t.Fatalf("server send: %v", err)
	}
	reply, err := client.RecvPacket()
	if err != nil {
		t.Fatalf("client recv: %v", err)
	}
	if string(reply) != "compat-reply" {
		t.Fatalf("client got %q", reply)
	}
	if providerA.submitted.Load() != 0 || providerB.submitted.Load() != 0 {
		t.Fatalf("compat stream should not submit AF_XDP frames: a=%d b=%d", providerA.submitted.Load(), providerB.submitted.Load())
	}
	if client.Stats().Extra["tix_tcp_compat_stream"] != 1 {
		t.Fatalf("client stats missing compat stream marker: %#v", client.Stats())
	}
}

func TestTIXTCPCompatStreamFallbackRoundTripsWithoutProvider(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_TCP_PRIMER", "1")
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_STREAM", "1")
	clientTransport := New(nil)
	serverTransport := New(nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ln, err := serverTransport.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolTIXTCP,
		Listen:    "127.0.0.1:0",
		Enabled:   true,
	}, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	expListener := ln.(*listener)
	accepted := make(chan transport.Session, 1)
	go func() {
		session, err := ln.Accept(ctx)
		if err == nil {
			accepted <- session
		}
	}()

	probe := clientTransport.Probe(ctx, transport.Peer{
		ID: core.IXID("ix-b"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolTIXTCP,
			Address:   expListener.compatListener.Addr().String(),
		}},
	})
	if !probe.Healthy {
		t.Fatalf("probe failed: %s", probe.Error)
	}

	client, err := clientTransport.Dial(ctx, transport.Peer{
		ID: core.IXID("ix-b"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolTIXTCP,
			Address:   expListener.compatListener.Addr().String(),
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	var server transport.Session
	select {
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()
	if _, ok := client.(*compatStreamSession); !ok {
		t.Fatalf("client session type = %T, want compat stream", client)
	}
	if _, ok := server.(*compatStreamSession); !ok {
		t.Fatalf("server session type = %T, want compat stream", server)
	}
	if err := client.SendPacket([]byte("compat-stream-no-provider")); err != nil {
		t.Fatalf("client send: %v", err)
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if string(got) != "compat-stream-no-provider" {
		t.Fatalf("server got %q", got)
	}
}

func TestTIXTCPCompatStreamKeptForKernelUDPDirectOnly(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_TCP_PRIMER", "1")
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_STREAM", "1")
	t.Setenv("TRUSTIX_KERNEL_UDP_TC_TX_DIRECT_ONLY", "1")
	client, server, providerA, providerB, cleanup := dialTIXTCPCompatStreamTestPair(t)
	defer cleanup()
	defer client.Close()
	defer server.Close()
	if _, ok := client.(*compatStreamSession); !ok {
		t.Fatalf("client session type = %T, want compat stream", client)
	}
	if _, ok := server.(*compatStreamSession); !ok {
		t.Fatalf("server session type = %T, want compat stream", server)
	}
	if err := client.SendPacket([]byte("kernel-udp-direct-only")); err != nil {
		t.Fatalf("client send: %v", err)
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if string(got) != "kernel-udp-direct-only" {
		t.Fatalf("server got %q", got)
	}
	if providerA.submitted.Load() != 0 || providerB.submitted.Load() != 0 {
		t.Fatalf("kernel_udp direct-only must not suppress tix_tcp compat stream: a=%d b=%d", providerA.submitted.Load(), providerB.submitted.Load())
	}
	if client.Stats().Extra["tix_tcp_compat_stream"] != 1 {
		t.Fatalf("client stats missing compat stream marker: %#v", client.Stats())
	}
}

func TestTIXTCPCompatStreamDisabledForTIXTCPDirectOnly(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_TCP_PRIMER", "1")
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_STREAM", "1")
	t.Setenv("TRUSTIX_TIX_TCP_TC_TX_DIRECT_ONLY", "1")
	client, server, providerA, _, cleanup := dialTIXTCPCompatStreamTestPair(t)
	defer cleanup()
	defer client.Close()
	defer server.Close()
	if _, ok := client.(*compatStreamSession); ok {
		t.Fatalf("client session type = %T, want TIX-TCP direct session", client)
	}
	if _, ok := server.(*compatStreamSession); ok {
		t.Fatalf("server session type = %T, want TIX-TCP direct session", server)
	}
	if err := client.SendPacket([]byte("direct-only")); err != nil {
		t.Fatalf("client send: %v", err)
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if string(got) != "direct-only" {
		t.Fatalf("server got %q", got)
	}
	if providerA.submitted.Load() == 0 {
		t.Fatal("tix_tcp direct-only compat stream suppression did not submit provider frames")
	}
	if client.Stats().Extra["tix_tcp_compat_stream"] != 0 {
		t.Fatalf("client stats unexpectedly marked compat stream: %#v", client.Stats())
	}
}

func dialTIXTCPCompatStreamTestPair(t *testing.T) (transport.Session, transport.Session, *fakeProvider, *fakeProvider, func()) {
	t.Helper()
	providerA, providerB := newProviderPair("ix-a", "ix-b")
	clientTransport := New(providerA)
	serverTransport := New(providerB)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	ln, err := serverTransport.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolTIXTCP,
		Listen:    "127.0.0.1:0",
		Enabled:   true,
	}, nil)
	if err != nil {
		cancel()
		t.Fatalf("listen: %v", err)
	}
	expListener := ln.(*listener)
	accepted := make(chan transport.Session, 1)
	go func() {
		session, err := ln.Accept(ctx)
		if err == nil {
			accepted <- session
		}
	}()

	client, err := clientTransport.Dial(ctx, transport.Peer{
		ID: core.IXID("ix-b"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolTIXTCP,
			Address:   expListener.compatListener.Addr().String(),
		}},
	}, nil)
	if err != nil {
		_ = ln.Close()
		cancel()
		t.Fatalf("dial: %v", err)
	}
	var server transport.Session
	select {
	case server = <-accepted:
	case <-ctx.Done():
		_ = client.Close()
		_ = ln.Close()
		cancel()
		t.Fatal(ctx.Err())
	}
	cleanup := func() {
		_ = ln.Close()
		cancel()
	}
	return client, server, providerA, providerB, cleanup
}

func TestTIXTCPCompatControlCarriesSecureHandshakeOnly(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_TCP_PRIMER", "1")
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_STREAM", "0")
	providerA := &fakeProvider{local: "ix-a", subs: make(map[chan dataplane.TIXTCPFrame]struct{}), flows: make(map[uint64]dataplane.TIXTCPFlow), cryptos: make(map[uint64]fakeCrypto)}
	providerB := &fakeProvider{local: "ix-b", subs: make(map[chan dataplane.TIXTCPFrame]struct{}), flows: make(map[uint64]dataplane.TIXTCPFlow), cryptos: make(map[uint64]fakeCrypto)}
	providerA.remote = providerB
	providerB.remote = providerA
	clientTransport := securetransport.New(New(providerA), securetransport.Options{})
	serverTransport := securetransport.New(New(providerB), securetransport.Options{})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listenAddr := tixTCPLocalTCPAddr(t)
	listener, err := serverTransport.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolTIXTCP,
		Listen:    listenAddr,
		Enabled:   true,
	}, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	accepted := make(chan transport.Session, 1)
	acceptErr := make(chan error, 1)
	go func() {
		session, err := listener.Accept(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- session
	}()

	client, err := clientTransport.Dial(ctx, transport.Peer{
		ID: core.IXID("ix-b"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolTIXTCP,
			Address:   listenAddr,
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	var server transport.Session
	select {
	case err := <-acceptErr:
		t.Fatalf("accept: %v", err)
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()

	if got := providerA.submitted.Load(); got != 0 {
		t.Fatalf("secure handshake submitted TIX-TCP frames = %d, want 0", got)
	}
	payload := []byte("after-handshake-uses-tix-tcp")
	if err := client.SendPacket(payload); err != nil {
		t.Fatalf("client send: %v", err)
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("server got %q", got)
	}
	if providerA.submitted.Load() == 0 {
		t.Fatal("data packets did not use tix_tcp provider")
	}
	frames := providerA.submittedFrames()
	if len(frames) == 0 {
		t.Fatal("no submitted data frame captured")
	}
	providerB.mu.Lock()
	_, reverseInstalled := providerB.flows[frames[0].FlowID]
	providerB.mu.Unlock()
	if !reverseInstalled {
		t.Fatal("server did not install reverse tix_tcp flow from compat control")
	}
}

func TestTIXTCPCompatControlHandshakeHasReceivePriority(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_HANDSHAKE_PRIORITY_DELAY", "100ms")
	session := newSession(nil, nil, 1, core.IXID("ix-a"), core.EndpointID("server"), dataplane.CryptoPlacementUserspace)
	session.enableCompatPriority()
	defer session.Close()

	session.enqueue([]byte("dataplane-before-handshake"))
	hello := []byte{'T', 'I', 'X', 'H', 1, 1, 'h'}
	go func() {
		time.Sleep(10 * time.Millisecond)
		session.enqueueCompatPriority(hello)
	}()

	got, err := session.RecvPacket()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if !bytes.Equal(got, hello) {
		t.Fatalf("first packet = %q, want compat handshake", got)
	}
	next, err := session.RecvPacket()
	if err != nil {
		t.Fatalf("recv queued dataplane: %v", err)
	}
	if string(next) != "dataplane-before-handshake" {
		t.Fatalf("next packet = %q, want queued dataplane", next)
	}
}

func TestTIXTCPPlaintextStillUsesCompatControlHandshake(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_TCP_PRIMER", "1")
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_STREAM", "0")
	providerA := &fakeProvider{local: "ix-a", subs: make(map[chan dataplane.TIXTCPFrame]struct{}), flows: make(map[uint64]dataplane.TIXTCPFlow), cryptos: make(map[uint64]fakeCrypto)}
	providerB := &fakeProvider{local: "ix-b", subs: make(map[chan dataplane.TIXTCPFrame]struct{}), flows: make(map[uint64]dataplane.TIXTCPFlow), cryptos: make(map[uint64]fakeCrypto)}
	providerA.remote = providerB
	providerB.remote = providerA
	options := securetransport.Options{
		Encryption: func() string {
			return securetransport.EncryptionPlaintext
		},
	}
	clientTransport := securetransport.New(New(providerA), options)
	serverTransport := securetransport.New(New(providerB), options)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listenAddr := tixTCPLocalTCPAddr(t)
	listener, err := serverTransport.Listen(ctx, transport.Endpoint{
		Name:       core.EndpointID("server"),
		Transport:  transport.ProtocolTIXTCP,
		Listen:     listenAddr,
		Encryption: securetransport.EncryptionPlaintext,
		Enabled:    true,
	}, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	accepted := make(chan transport.Session, 1)
	acceptErr := make(chan error, 1)
	go func() {
		session, err := listener.Accept(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- session
	}()

	client, err := clientTransport.Dial(ctx, transport.Peer{
		ID: core.IXID("ix-b"),
		Endpoints: []transport.Endpoint{{
			Name:       core.EndpointID("server"),
			Transport:  transport.ProtocolTIXTCP,
			Address:    listenAddr,
			Encryption: securetransport.EncryptionPlaintext,
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	var server transport.Session
	select {
	case err := <-acceptErr:
		t.Fatalf("accept: %v", err)
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()

	if providerA.submitted.Load() != 0 || providerB.submitted.Load() != 0 {
		t.Fatalf("plaintext handshake used TIX-TCP frames: a=%d b=%d", providerA.submitted.Load(), providerB.submitted.Load())
	}
	if stats := client.Stats(); stats.Encrypted || stats.Encryption != securetransport.EncryptionPlaintext {
		t.Fatalf("client stats = %+v, want plaintext without data encryption", stats)
	}
	payload := []byte("plaintext-over-tix-tcp")
	if err := client.SendPacket(payload); err != nil {
		t.Fatalf("client send: %v", err)
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("server got %q", got)
	}
	if providerA.submitted.Load() == 0 {
		t.Fatal("plaintext data packets did not use tix_tcp provider")
	}
}

func TestTIXTCPFullPlaintextKernelDatapathRequiresCompatPrimer(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_TCP_PRIMER", "0")
	provider := &fakeProvider{
		local:          "ix-a",
		subs:           make(map[chan dataplane.TIXTCPFrame]struct{}),
		flows:          make(map[uint64]dataplane.TIXTCPFlow),
		cryptos:        make(map[uint64]fakeCrypto),
		statusProvider: tixTCPProviderFullPlaintextKernel,
	}
	clientTransport := New(provider)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := clientTransport.Dial(ctx, transport.Peer{
		ID: core.IXID("ix-b"),
		Endpoints: []transport.Endpoint{{
			Name:       core.EndpointID("server"),
			Transport:  transport.ProtocolTIXTCP,
			Address:    "127.0.0.1:9",
			Encryption: securetransport.EncryptionPlaintext,
		}},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "requires compat TCP control primer") {
		t.Fatalf("dial error = %v, want compat control primer requirement", err)
	}
}

func TestTIXTCPFullPlaintextKernelDatapathHandshakeUsesCompatControl(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_TCP_PRIMER", "1")
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_STREAM", "0")
	providerA, providerB := newProviderPair("ix-a", "ix-b")
	providerA.statusProvider = tixTCPProviderFullPlaintextKernel
	providerB.statusProvider = tixTCPProviderFullPlaintextKernel
	options := securetransport.Options{
		Encryption: func() string {
			return securetransport.EncryptionPlaintext
		},
	}
	clientTransport := securetransport.New(New(providerA), options)
	serverTransport := securetransport.New(New(providerB), options)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listenAddr := tixTCPLocalTCPAddr(t)
	listener, err := serverTransport.Listen(ctx, transport.Endpoint{
		Name:       core.EndpointID("server"),
		Transport:  transport.ProtocolTIXTCP,
		Listen:     listenAddr,
		Encryption: securetransport.EncryptionPlaintext,
		Enabled:    true,
	}, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	accepted := make(chan transport.Session, 1)
	acceptErr := make(chan error, 1)
	go func() {
		session, err := listener.Accept(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- session
	}()

	client, err := clientTransport.Dial(ctx, transport.Peer{
		ID: core.IXID("ix-b"),
		Endpoints: []transport.Endpoint{{
			Name:       core.EndpointID("server"),
			Transport:  transport.ProtocolTIXTCP,
			Address:    listenAddr,
			Encryption: securetransport.EncryptionPlaintext,
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	var server transport.Session
	select {
	case err := <-acceptErr:
		t.Fatalf("accept: %v", err)
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()

	if providerA.submitted.Load() != 0 || providerB.submitted.Load() != 0 {
		t.Fatalf("full plaintext handshake used userspace provider frames: a=%d b=%d", providerA.submitted.Load(), providerB.submitted.Load())
	}
	if err := client.SendPacket([]byte{0x45, 0, 0, 20}); err == nil || !strings.Contains(err.Error(), "full plaintext kernel datapath owns data frames") {
		t.Fatalf("data send error = %v, want full plaintext kernel datapath ownership", err)
	}
}

func TestTIXTCPFullPlaintextKernelDatapathCompatControlCarriesControlFrames(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_TCP_PRIMER", "1")
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_STREAM", "0")
	providerA, providerB := newProviderPair("ix-a", "ix-b")
	providerA.statusProvider = tixTCPProviderFullPlaintextKernel
	providerB.statusProvider = tixTCPProviderFullPlaintextKernel
	clientTransport := New(providerA)
	serverTransport := New(providerB)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listenAddr := tixTCPLocalTCPAddr(t)
	listener, err := serverTransport.Listen(ctx, transport.Endpoint{
		Name:       core.EndpointID("server"),
		Transport:  transport.ProtocolTIXTCP,
		Listen:     listenAddr,
		Encryption: securetransport.EncryptionPlaintext,
		Enabled:    true,
	}, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	accepted := make(chan transport.Session, 1)
	acceptErr := make(chan error, 1)
	go func() {
		session, err := listener.Accept(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- session
	}()

	client, err := clientTransport.Dial(ctx, transport.Peer{
		ID: core.IXID("ix-b"),
		Endpoints: []transport.Endpoint{{
			Name:       core.EndpointID("server"),
			Transport:  transport.ProtocolTIXTCP,
			Address:    listenAddr,
			Encryption: securetransport.EncryptionPlaintext,
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	var server transport.Session
	select {
	case err := <-acceptErr:
		t.Fatalf("accept: %v", err)
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()

	control := make([]byte, 16)
	copy(control[0:4], tixTCPCompatControlMagic[:])
	control[4] = tixTCPCompatControlVersion
	control[5] = 2
	binary.BigEndian.PutUint64(control[8:16], 0x1020304050607080)
	if err := client.SendPacket(control); err != nil {
		t.Fatalf("send control: %v", err)
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("server recv control: %v", err)
	}
	if !bytes.Equal(got, control) {
		t.Fatalf("server control = %x, want %x", got, control)
	}
	if providerA.submitted.Load() != 0 || providerB.submitted.Load() != 0 {
		t.Fatalf("compat control used userspace provider frames: a=%d b=%d", providerA.submitted.Load(), providerB.submitted.Load())
	}
	if err := client.SendPacket([]byte{0x45, 0, 0, 20}); err == nil || !strings.Contains(err.Error(), "full plaintext kernel datapath owns data frames") {
		t.Fatalf("data send error = %v, want full plaintext kernel datapath ownership", err)
	}
}

func TestTIXTCPFullPlaintextKernelDatapathCompatControlWakesBlockedReceive(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_TCP_PRIMER", "1")
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_STREAM", "0")
	providerA, providerB := newProviderPair("ix-a", "ix-b")
	providerA.statusProvider = tixTCPProviderFullPlaintextKernel
	providerB.statusProvider = tixTCPProviderFullPlaintextKernel
	clientTransport := New(providerA)
	serverTransport := New(providerB)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listenAddr := tixTCPLocalTCPAddr(t)
	listener, err := serverTransport.Listen(ctx, transport.Endpoint{
		Name:       core.EndpointID("server"),
		Transport:  transport.ProtocolTIXTCP,
		Listen:     listenAddr,
		Encryption: securetransport.EncryptionPlaintext,
		Enabled:    true,
	}, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	accepted := make(chan transport.Session, 1)
	acceptErr := make(chan error, 1)
	go func() {
		session, err := listener.Accept(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- session
	}()

	client, err := clientTransport.Dial(ctx, transport.Peer{
		ID: core.IXID("ix-b"),
		Endpoints: []transport.Endpoint{{
			Name:       core.EndpointID("server"),
			Transport:  transport.ProtocolTIXTCP,
			Address:    listenAddr,
			Encryption: securetransport.EncryptionPlaintext,
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	var server transport.Session
	select {
	case err := <-acceptErr:
		t.Fatalf("accept: %v", err)
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()

	received := make(chan []byte, 1)
	recvErr := make(chan error, 1)
	go func() {
		packet, err := server.RecvPacket()
		if err != nil {
			recvErr <- err
			return
		}
		received <- packet
	}()
	time.Sleep(100 * time.Millisecond)

	control := make([]byte, 16)
	copy(control[0:4], tixTCPCompatControlMagic[:])
	control[4] = tixTCPCompatControlVersion
	control[5] = 2
	binary.BigEndian.PutUint64(control[8:16], 0x1020304050607080)
	if err := client.SendPacket(control); err != nil {
		t.Fatalf("send control: %v", err)
	}
	select {
	case err := <-recvErr:
		t.Fatalf("server recv control: %v", err)
	case got := <-received:
		if !bytes.Equal(got, control) {
			t.Fatalf("server control = %x, want %x", got, control)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked receive was not woken by compat control frame")
	}
}

func TestTIXTCPCompatStreamPlaintextUsesSecureHandshake(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_TCP_PRIMER", "1")
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_STREAM", "1")
	root, err := pki.NewRoot("compat-stream-plaintext-root", 1)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	ixA, err := pki.Issue(root, pki.IssueRequest{CommonName: "ix-a", Role: pki.RoleIX, Domain: "lab.local", IX: "ix-a"})
	if err != nil {
		t.Fatalf("issue ix-a: %v", err)
	}
	ixB, err := pki.Issue(root, pki.IssueRequest{CommonName: "ix-b", Role: pki.RoleIX, Domain: "lab.local", IX: "ix-b"})
	if err != nil {
		t.Fatalf("issue ix-b: %v", err)
	}
	providerA, providerB := newProviderPair("ix-a", "ix-b")
	options := securetransport.Options{
		Encryption: func() string {
			return securetransport.EncryptionPlaintext
		},
	}
	tlsA := &tls.Config{Certificates: []tls.Certificate{tlsCertificateForTIXTCPTest(ixA)}}
	tlsB := &tls.Config{Certificates: []tls.Certificate{tlsCertificateForTIXTCPTest(ixB)}}
	clientTransport := securetransport.New(New(providerA), options)
	serverTransport := securetransport.New(New(providerB), options)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listenAddr := tixTCPLocalTCPAddr(t)
	listener, err := serverTransport.Listen(ctx, transport.Endpoint{
		Name:       core.EndpointID("server"),
		Transport:  transport.ProtocolTIXTCP,
		Listen:     listenAddr,
		Encryption: securetransport.EncryptionPlaintext,
		Enabled:    true,
	}, tlsB)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	accepted := make(chan transport.Session, 1)
	acceptErr := make(chan error, 1)
	go func() {
		session, err := listener.Accept(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- session
	}()

	client, err := clientTransport.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{{
			Name:       core.EndpointID("server"),
			Transport:  transport.ProtocolTIXTCP,
			Address:    listenAddr,
			Encryption: securetransport.EncryptionPlaintext,
		}},
	}, tlsA)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	var server transport.Session
	select {
	case err := <-acceptErr:
		t.Fatalf("accept: %v", err)
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()
	if providerA.submitted.Load() != 0 || providerB.submitted.Load() != 0 {
		t.Fatalf("compat stream plaintext handshake used TIX-TCP frames: a=%d b=%d", providerA.submitted.Load(), providerB.submitted.Load())
	}
	if peer, domain, ok := server.(transport.PeerIdentitySession).PeerIdentity(); !ok || peer != "ix-a" || domain != "lab.local" {
		t.Fatalf("server peer identity = %q/%q ok=%t, want ix-a/lab.local", peer, domain, ok)
	}
	if stats := client.Stats(); stats.Encrypted || stats.Encryption != securetransport.EncryptionPlaintext || stats.Extra["tix_tcp_compat_stream"] != 1 {
		t.Fatalf("client stats = %+v, want plaintext compat stream", stats)
	}
	payload := []byte("plaintext-over-compat-stream")
	if err := client.SendPacket(payload); err != nil {
		t.Fatalf("client send: %v", err)
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("server got %q", got)
	}
	if providerA.submitted.Load() != 0 || providerB.submitted.Load() != 0 {
		t.Fatalf("compat stream plaintext data used TIX-TCP frames: a=%d b=%d", providerA.submitted.Load(), providerB.submitted.Load())
	}
}

func TestTIXTCPCompatStreamPlaintextWorksWithoutProvider(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_TCP_PRIMER", "1")
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_STREAM", "1")
	root, err := pki.NewRoot("compat-stream-no-provider-root", 1)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	ixA, err := pki.Issue(root, pki.IssueRequest{CommonName: "ix-a", Role: pki.RoleIX, Domain: "lab.local", IX: "ix-a"})
	if err != nil {
		t.Fatalf("issue ix-a: %v", err)
	}
	ixB, err := pki.Issue(root, pki.IssueRequest{CommonName: "ix-b", Role: pki.RoleIX, Domain: "lab.local", IX: "ix-b"})
	if err != nil {
		t.Fatalf("issue ix-b: %v", err)
	}
	options := securetransport.Options{
		Encryption: func() string {
			return securetransport.EncryptionPlaintext
		},
	}
	tlsA := &tls.Config{Certificates: []tls.Certificate{tlsCertificateForTIXTCPTest(ixA)}}
	tlsB := &tls.Config{Certificates: []tls.Certificate{tlsCertificateForTIXTCPTest(ixB)}}
	clientTransport := securetransport.New(New(nil), options)
	serverTransport := securetransport.New(New(nil), options)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listenAddr := tixTCPLocalTCPAddr(t)
	listener, err := serverTransport.Listen(ctx, transport.Endpoint{
		Name:       core.EndpointID("server"),
		Transport:  transport.ProtocolTIXTCP,
		Listen:     listenAddr,
		Encryption: securetransport.EncryptionPlaintext,
		Enabled:    true,
	}, tlsB)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	accepted := make(chan transport.Session, 1)
	acceptErr := make(chan error, 1)
	go func() {
		session, err := listener.Accept(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- session
	}()

	client, err := clientTransport.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{{
			Name:       core.EndpointID("server"),
			Transport:  transport.ProtocolTIXTCP,
			Address:    listenAddr,
			Encryption: securetransport.EncryptionPlaintext,
		}},
	}, tlsA)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	var server transport.Session
	select {
	case err := <-acceptErr:
		t.Fatalf("accept: %v", err)
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()
	if stats := client.Stats(); stats.Encrypted || stats.Encryption != securetransport.EncryptionPlaintext || stats.Extra["tix_tcp_compat_stream"] != 1 {
		t.Fatalf("client stats = %+v, want plaintext compat stream", stats)
	}
	payload := []byte("plaintext-over-compat-stream-no-provider")
	if err := client.SendPacket(payload); err != nil {
		t.Fatalf("client send: %v", err)
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("server got %q", got)
	}
}

func TestSecureTransportLargeHandshakeOverTIXTCPCompatControl(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_TCP_PRIMER", "1")
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_STREAM", "0")
	root, err := pki.NewRoot("large-handshake-root", 1)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	ixA, err := pki.Issue(root, pki.IssueRequest{CommonName: "ix-a", Role: pki.RoleIX, Domain: "lab.local", IX: "ix-a"})
	if err != nil {
		t.Fatalf("issue ix-a: %v", err)
	}
	ixB, err := pki.Issue(root, pki.IssueRequest{CommonName: "ix-b", Role: pki.RoleIX, Domain: "lab.local", IX: "ix-b"})
	if err != nil {
		t.Fatalf("issue ix-b: %v", err)
	}
	providerA, providerB := newProviderPair("ix-a", "ix-b")
	providerA.payloadMax = 576
	providerB.payloadMax = 576
	tlsA := &tls.Config{Certificates: []tls.Certificate{tlsCertificateForTIXTCPTest(ixA)}}
	tlsB := &tls.Config{Certificates: []tls.Certificate{tlsCertificateForTIXTCPTest(ixB)}}
	clientTransport := securetransport.New(New(providerA), securetransport.Options{})
	serverTransport := securetransport.New(New(providerB), securetransport.Options{})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listenAddr := tixTCPLocalTCPAddr(t)
	listener, err := serverTransport.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolTIXTCP,
		Listen:    listenAddr,
		Enabled:   true,
	}, tlsB)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	accepted := make(chan transport.Session, 1)
	acceptErr := make(chan error, 1)
	go func() {
		session, err := listener.Accept(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- session
	}()

	client, err := clientTransport.Dial(ctx, transport.Peer{
		ID: core.IXID("ix-b"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolTIXTCP,
			Address:   listenAddr,
		}},
	}, tlsA)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	var server transport.Session
	select {
	case err := <-acceptErr:
		t.Fatalf("accept: %v", err)
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()
	if providerA.submitted.Load() != 0 || providerB.submitted.Load() != 0 {
		t.Fatalf("large secure handshake used TIX-TCP frames: a=%d b=%d", providerA.submitted.Load(), providerB.submitted.Load())
	}
	if err := client.SendPacket([]byte("large-handshake-data")); err != nil {
		t.Fatalf("client send: %v", err)
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if string(got) != "large-handshake-data" {
		t.Fatalf("server got %q", got)
	}
}

func TestTIXTCPFragmentsLargePacket(t *testing.T) {
	providerA, providerB := newProviderPair("ix-a", "ix-b")
	clientTransport := New(providerA)
	serverTransport := New(providerB)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := serverTransport.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolTIXTCP,
		Listen:    "ix-b-underlay:443",
		Enabled:   true,
	}, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan transport.Session, 1)
	go func() {
		session, err := listener.Accept(ctx)
		if err == nil {
			accepted <- session
		}
	}()

	client, err := clientTransport.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolTIXTCP,
			Address:   "ix-b-underlay:443",
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	payload := bytes.Repeat([]byte("x"), tixTCPFragmentPayloadSize*2+321)
	if err := client.SendPacket(payload); err != nil {
		t.Fatalf("client send large payload: %v", err)
	}

	var server transport.Session
	select {
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("server recv large payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("large payload mismatch len=%d want=%d", len(got), len(payload))
	}
	wantFragments := uint64(fragmentCount(len(payload)))
	if got := providerA.submitted.Load(); got != wantFragments {
		t.Fatalf("submitted frames = %d, want %d", got, wantFragments)
	}
	if stats := client.Stats(); stats.PacketsSent != 1 || stats.BytesSent != uint64(len(payload)) {
		t.Fatalf("client stats = %+v", stats)
	}
	if stats := client.Stats(); stats.Extra[tixTCPStatFragmentedPacketsSent] != 1 || stats.Extra[tixTCPStatFragmentsSent] != wantFragments {
		t.Fatalf("client fragment stats = %+v, want 1 packet/%d fragments", stats.Extra, wantFragments)
	}
	if stats := server.Stats(); stats.Extra[tixTCPStatFragmentedPacketsReceived] != 1 || stats.Extra[tixTCPStatFragmentsReassembled] != wantFragments {
		t.Fatalf("server fragment stats = %+v, want 1 packet/%d fragments", stats.Extra, wantFragments)
	}
}

func TestTIXTCPSessionBufferFromEnv(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_SESSION_BUFFER", "")
	if got := tixTCPSessionBuffer(); got != tixTCPSessionBufferDefault {
		t.Fatalf("session buffer default = %d, want %d", got, tixTCPSessionBufferDefault)
	}
	t.Setenv("TRUSTIX_TIX_TCP_SESSION_BUFFER", "2048")
	if got := tixTCPSessionBuffer(); got != 2048 {
		t.Fatalf("session buffer = %d, want 2048", got)
	}
	t.Setenv("TRUSTIX_TIX_TCP_SESSION_BUFFER", "999999")
	if got := tixTCPSessionBuffer(); got != tixTCPSessionBufferMax {
		t.Fatalf("session buffer clamp = %d, want %d", got, tixTCPSessionBufferMax)
	}
	t.Setenv("TRUSTIX_TIX_TCP_SESSION_BUFFER", "bad")
	if got := tixTCPSessionBuffer(); got != tixTCPSessionBufferDefault {
		t.Fatalf("invalid session buffer = %d, want %d", got, tixTCPSessionBufferDefault)
	}
}

func TestTIXTCPReassemblyPrunesOldestWhenFull(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_REASSEMBLY_MAX_ASSEMBLIES", "2")
	session := newSession(nil, nil, 1001, "ix-b", "server", dataplane.CryptoPlacementUserspace)
	defer session.closeInput()

	for _, seq := range []uint64{10, 20, 30} {
		if _, _, ok := session.handleFrameOne(dataplane.TIXTCPFrame{
			FlowID:        1001,
			Direction:     dataplane.TIXTCPInbound,
			Sequence:      seq,
			FragmentIndex: 0,
			FragmentCount: 2,
			Payload:       []byte{byte(seq)},
		}); ok {
			t.Fatalf("incomplete fragment sequence %d unexpectedly reassembled", seq)
		}
	}

	stats := session.Stats()
	if got := stats.Extra[tixTCPStatFragmentAssembliesCurrent]; got != 2 {
		t.Fatalf("current assemblies = %d, want 2", got)
	}
	if got := stats.Extra[tixTCPStatFragmentExpiredAssemblies]; got != 1 {
		t.Fatalf("expired assemblies = %d, want 1", got)
	}
	if got := stats.Extra[tixTCPStatFragmentExpiredFragments]; got != 1 {
		t.Fatalf("expired fragments = %d, want 1", got)
	}
}

func TestTIXTCPConfiguredFragmentPayloadAllowsJumboUserspace(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_FRAGMENT_PAYLOAD_SIZE", "8000")
	if got := tixTCPFragmentPayloadSizeForPlacement(dataplane.CryptoPlacementUserspace, false); got != 8000 {
		t.Fatalf("userspace fragment payload = %d, want 8000", got)
	}
	if got := tixTCPFragmentPayloadSizeForPlacement(dataplane.CryptoPlacementKernel, true); got != tixTCPKernelFragmentPayloadMax {
		t.Fatalf("kernel fragment payload = %d, want %d", got, tixTCPKernelFragmentPayloadMax)
	}
}

func TestTIXTCPAutoFragmentPayloadUsesPlacementMax(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_FRAGMENT_PAYLOAD_SIZE", "auto")
	if got := tixTCPFragmentPayloadSizeForPlacement(dataplane.CryptoPlacementUserspace, false); got != tixTCPFragmentPayloadMax {
		t.Fatalf("userspace auto fragment payload = %d, want %d", got, tixTCPFragmentPayloadMax)
	}
	if got := tixTCPFragmentPayloadSizeForPlacement(dataplane.CryptoPlacementKernel, true); got != tixTCPKernelFragmentPayloadMax {
		t.Fatalf("kernel auto fragment payload = %d, want %d", got, tixTCPKernelFragmentPayloadMax)
	}
}

func TestTIXTCPFragmentPayloadClampsToProviderMax(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_FRAGMENT_PAYLOAD_SIZE", "8000")
	provider := &fakeProvider{payloadMax: 3900}
	session := newSession(provider, nil, 1, "ix-a", "ep", dataplane.CryptoPlacementUserspace)

	if got := session.fragmentPayloadSize(); got != 3900 {
		t.Fatalf("fragment payload = %d, want provider max 3900", got)
	}
}

func TestTIXTCPAutoFragmentPayloadRaisesDefaultToProviderMax(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_AUTO_FRAGMENT_PAYLOAD", "1")
	provider := &fakeProvider{payloadMax: 3900}
	session := newSession(provider, nil, 1, "ix-a", "ep", dataplane.CryptoPlacementUserspace)

	if got := session.fragmentPayloadSize(); got != 3900 {
		t.Fatalf("fragment payload = %d, want provider max 3900", got)
	}
}

func TestTIXTCPAutoFragmentPayloadPreservesExplicitSetting(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_AUTO_FRAGMENT_PAYLOAD", "1")
	t.Setenv("TRUSTIX_TIX_TCP_FRAGMENT_PAYLOAD_SIZE", "legacy")
	provider := &fakeProvider{payloadMax: 3900}
	session := newSession(provider, nil, 1, "ix-a", "ep", dataplane.CryptoPlacementUserspace)

	if got := session.fragmentPayloadSize(); got != tixTCPUserspaceCryptoPayloadHint {
		t.Fatalf("fragment payload = %d, want explicit legacy %d", got, tixTCPUserspaceCryptoPayloadHint)
	}
}

func TestTIXTCPStatsAdvertisesDatagramMaxPacketSize(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_FRAGMENT_PAYLOAD_SIZE", "8000")
	provider := &fakeProvider{payloadMax: 3900}
	session := newSession(provider, nil, 1, "ix-a", "ep", dataplane.CryptoPlacementUserspace)

	stats := session.Stats()
	if !stats.Datagram {
		t.Fatal("Datagram = false, want true")
	}
	if !stats.NativeBatching {
		t.Fatal("NativeBatching = false, want true")
	}
	if got, want := stats.MaxPacketSize, uint64(MaxPayload); got != want {
		t.Fatalf("MaxPacketSize = %d, want %d", got, want)
	}
}

func TestTIXTCPStatsHonorsConfiguredMaxPacketSize(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_FRAGMENT_PAYLOAD_SIZE", "8000")
	t.Setenv("TRUSTIX_TIX_TCP_MAX_PACKET_SIZE", "1200")
	provider := &fakeProvider{payloadMax: 3900}
	session := newSession(provider, nil, 1, "ix-a", "ep", dataplane.CryptoPlacementUserspace)

	stats := session.Stats()
	if got, want := stats.MaxPacketSize, uint64(1200); got != want {
		t.Fatalf("MaxPacketSize = %d, want %d", got, want)
	}
}

func TestTIXTCPSendPacketsMarksOnlyValidInnerIPv4(t *testing.T) {
	provider := &fakeProvider{}
	session := newSession(provider, nil, 1, "ix-a", "ep", dataplane.CryptoPlacementUserspace)
	valid := ipv4PacketForTIXTCPTest(96)
	badTotalLen := append([]byte(nil), valid...)
	binary.BigEndian.PutUint16(badTotalLen[2:4], uint16(len(badTotalLen)-1))
	nonIPv4 := append([]byte(nil), valid...)
	nonIPv4[0] = 0x60

	if err := session.SendPackets([][]byte{valid, badTotalLen, nonIPv4}); err != nil {
		t.Fatalf("send packets: %v", err)
	}
	frames := provider.submittedFrames()
	if len(frames) != 3 {
		t.Fatalf("submitted frames = %d, want 3", len(frames))
	}
	if !frames[0].InnerIPv4 {
		t.Fatalf("valid IPv4 packet was not marked inner_ipv4")
	}
	if frames[1].InnerIPv4 {
		t.Fatalf("bad IPv4 total length was marked inner_ipv4")
	}
	if frames[2].InnerIPv4 {
		t.Fatalf("non-IPv4 packet was marked inner_ipv4")
	}
}

func TestTIXTCPSendPacketsDoesNotMarkFragmentsInnerIPv4(t *testing.T) {
	provider := &fakeProvider{payloadMax: 64}
	session := newSession(provider, nil, 1, "ix-a", "ep", dataplane.CryptoPlacementUserspace)
	packet := ipv4PacketForTIXTCPTest(256)

	if err := session.SendPackets([][]byte{packet}); err != nil {
		t.Fatalf("send fragmented packet: %v", err)
	}
	frames := provider.submittedFrames()
	if len(frames) < 2 {
		t.Fatalf("submitted frames = %d, want fragmented packet", len(frames))
	}
	for i, frame := range frames {
		if frame.InnerIPv4 {
			t.Fatalf("fragment %d was marked inner_ipv4", i)
		}
	}
}

func TestTIXTCPSendPacketsLeavesTIXBWrappedWhenExpansionDisabled(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_EXPAND_TIXB", "0")
	provider := &fakeProvider{}
	session := newSession(provider, nil, 1, "ix-a", "ep", dataplane.CryptoPlacementUserspace)
	packetA := ipv4PacketForTIXTCPTest(96)
	packetB := ipv4PacketForTIXTCPTest(128)
	batch := tixTCPTestTIXB(packetA, packetB)

	if err := session.SendPackets([][]byte{batch}); err != nil {
		t.Fatalf("send TIXB packet: %v", err)
	}
	frames := provider.submittedFrames()
	if len(frames) != 1 {
		t.Fatalf("submitted frames = %d, want wrapped TIXB frame", len(frames))
	}
	if !bytes.Equal(frames[0].Payload, batch) {
		t.Fatalf("wrapped frame payload changed")
	}
	if frames[0].InnerIPv4 {
		t.Fatalf("wrapped TIXB frame was marked inner_ipv4")
	}
	if stats := session.Stats(); stats.Extra[tixTCPStatTIXBExpandedPackets] != 0 || stats.Extra[tixTCPStatTIXBExpandedItems] != 0 {
		t.Fatalf("TIXB expansion stats = %+v, want zero", stats.Extra)
	}
}

func TestTIXTCPSendPacketsExpandsTIXBWhenEnabled(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_EXPAND_TIXB", "1")
	provider := &fakeProvider{}
	session := newSession(provider, nil, 1, "ix-a", "ep", dataplane.CryptoPlacementUserspace)
	packetA := ipv4PacketForTIXTCPTest(96)
	packetB := ipv4PacketForTIXTCPTest(128)
	batch := tixTCPTestTIXB(packetA, packetB)

	if err := session.SendPackets([][]byte{batch}); err != nil {
		t.Fatalf("send TIXB packet: %v", err)
	}
	frames := provider.submittedFrames()
	if len(frames) != 2 {
		t.Fatalf("submitted frames = %d, want expanded TIXB items", len(frames))
	}
	if !bytes.Equal(frames[0].Payload, packetA) || !bytes.Equal(frames[1].Payload, packetB) {
		t.Fatalf("expanded frame payloads changed")
	}
	if !frames[0].InnerIPv4 || !frames[1].InnerIPv4 {
		t.Fatalf("expanded IPv4 frames were not marked inner_ipv4: %+v", frames)
	}
	if frames[0].FragmentCount != 0 || frames[1].FragmentCount != 0 {
		t.Fatalf("expanded frames were fragmented: %+v", frames)
	}
	if frames[0].Sequence != 1 || frames[1].Sequence != 2 {
		t.Fatalf("expanded frame sequences = %d/%d, want 1/2", frames[0].Sequence, frames[1].Sequence)
	}
	stats := session.Stats()
	if stats.PacketsSent != 2 || stats.BytesSent != uint64(len(packetA)+len(packetB)) {
		t.Fatalf("stats = %+v, want expanded packet accounting", stats)
	}
	if stats.Extra[tixTCPStatTIXBExpandedPackets] != 1 || stats.Extra[tixTCPStatTIXBExpandedItems] != 2 {
		t.Fatalf("TIXB expansion stats = %+v, want one packet/two items", stats.Extra)
	}
}

func TestTIXTCPKernelCryptoSealBeforeFragmentEmitsLogicalFrame(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_FRAGMENT_PAYLOAD_SIZE", "1000")
	provider := &fakeProvider{
		kernelCrypto:  true,
		payloadMax:    1000,
		sealBeforeMax: 4096,
		cryptos:       make(map[uint64]fakeCrypto),
	}
	session := newSession(provider, nil, 7, "ix-a", "ep", dataplane.CryptoPlacementKernel)
	if err := session.EnableCryptoOffload(tixTCPTestCryptoOffloadSpec()); err != nil {
		t.Fatalf("enable crypto offload: %v", err)
	}
	packet := ipv4PacketForTIXTCPTest(2500)

	if err := session.SendPackets([][]byte{packet}); err != nil {
		t.Fatalf("send packets: %v", err)
	}
	frames := provider.submittedFrames()
	if len(frames) != 1 {
		t.Fatalf("submitted frames = %d, want 1 logical frame", len(frames))
	}
	frame := frames[0]
	if frame.FragmentPayloadSize != 1000 {
		t.Fatalf("fragment payload hint = %d, want 1000", frame.FragmentPayloadSize)
	}
	if frame.FragmentCount != 0 || frame.FragmentIndex != 0 {
		t.Fatalf("logical frame fragment header = index %d count %d, want zero", frame.FragmentIndex, frame.FragmentCount)
	}
	if frame.CryptoPlacement != dataplane.CryptoPlacementKernel {
		t.Fatalf("crypto placement = %q, want kernel", frame.CryptoPlacement)
	}
	wantFragments := uint64(fragmentCountForSize(len(packet)+tixTCPSecureFrameOverhead, 1000))
	stats := session.Stats()
	if stats.Extra[tixTCPStatFragmentedPacketsSent] != 1 || stats.Extra[tixTCPStatFragmentsSent] != wantFragments {
		t.Fatalf("fragment stats = %+v, want one logical packet and %d wire fragments", stats.Extra, wantFragments)
	}
}

func TestTIXTCPKernelCryptoSealBeforeFragmentUsesConfiguredPayloadByDefault(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_FRAGMENT_PAYLOAD_SIZE", "1380")
	provider := &fakeProvider{
		kernelCrypto:  true,
		payloadMax:    1420,
		sealBeforeMax: 4096,
		cryptos:       make(map[uint64]fakeCrypto),
	}
	session := newSession(provider, nil, 7, "ix-a", "ep", dataplane.CryptoPlacementKernel)
	if err := session.EnableCryptoOffload(tixTCPTestCryptoOffloadSpec()); err != nil {
		t.Fatalf("enable crypto offload: %v", err)
	}
	packet := ipv4PacketForTIXTCPTest(2500)

	if err := session.SendPackets([][]byte{packet}); err != nil {
		t.Fatalf("send packets: %v", err)
	}
	frames := provider.submittedFrames()
	if len(frames) != 1 {
		t.Fatalf("submitted frames = %d, want 1 logical frame", len(frames))
	}
	if frames[0].FragmentPayloadSize != 1380 {
		t.Fatalf("fragment payload hint = %d, want configured payload 1380", frames[0].FragmentPayloadSize)
	}
}

func TestTIXTCPKernelCryptoSealBeforeFragmentWirePayloadMaxCanBeEnabled(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_FRAGMENT_PAYLOAD_SIZE", "1380")
	t.Setenv("TRUSTIX_TIX_TCP_KERNEL_SEAL_BEFORE_FRAGMENT_WIRE_MAX", "1")
	provider := &fakeProvider{
		kernelCrypto:  true,
		payloadMax:    1420,
		sealBeforeMax: 4096,
		cryptos:       make(map[uint64]fakeCrypto),
	}
	session := newSession(provider, nil, 7, "ix-a", "ep", dataplane.CryptoPlacementKernel)
	if err := session.EnableCryptoOffload(tixTCPTestCryptoOffloadSpec()); err != nil {
		t.Fatalf("enable crypto offload: %v", err)
	}
	packet := ipv4PacketForTIXTCPTest(2500)

	if err := session.SendPackets([][]byte{packet}); err != nil {
		t.Fatalf("send packets: %v", err)
	}
	frames := provider.submittedFrames()
	if len(frames) != 1 {
		t.Fatalf("submitted frames = %d, want 1 logical frame", len(frames))
	}
	if frames[0].FragmentPayloadSize != 1420 {
		t.Fatalf("fragment payload hint = %d, want wire payload max 1420", frames[0].FragmentPayloadSize)
	}
}

func TestTIXTCPKernelCryptoSealBeforeFragmentAllowsDeviceSizedLogicalFrame(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_FRAGMENT_PAYLOAD_SIZE", "auto")
	provider := &fakeProvider{
		kernelCrypto:  true,
		payloadMax:    1460,
		sealBeforeMax: 256 * 1024,
		cryptos:       make(map[uint64]fakeCrypto),
	}
	session := newSession(provider, nil, 7, "ix-a", "ep", dataplane.CryptoPlacementKernel)
	if err := session.EnableCryptoOffload(tixTCPTestCryptoOffloadSpec()); err != nil {
		t.Fatalf("enable crypto offload: %v", err)
	}
	packet := bytes.Repeat([]byte{0x7a}, 128*1024)

	if err := session.SendPackets([][]byte{packet}); err != nil {
		t.Fatalf("send packets: %v", err)
	}
	frames := provider.submittedFrames()
	if len(frames) != 1 {
		t.Fatalf("submitted frames = %d, want 1 logical frame", len(frames))
	}
	if frames[0].FragmentPayloadSize != 1460 {
		t.Fatalf("fragment payload hint = %d, want 1460", frames[0].FragmentPayloadSize)
	}
	if frames[0].FragmentCount != 0 || frames[0].FragmentIndex != 0 {
		t.Fatalf("logical frame fragment header = index %d count %d, want zero", frames[0].FragmentIndex, frames[0].FragmentCount)
	}
	wantFragments := uint64(fragmentCountForSize(len(packet)+tixTCPSecureFrameOverhead, 1460))
	stats := session.Stats()
	if stats.Extra[tixTCPStatFragmentedPacketsSent] != 1 || stats.Extra[tixTCPStatFragmentsSent] != wantFragments {
		t.Fatalf("fragment stats = %+v, want one logical packet and %d wire fragments", stats.Extra, wantFragments)
	}
}

func TestTIXTCPKernelCryptoSealBeforeFragmentCanBeDisabled(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_FRAGMENT_PAYLOAD_SIZE", "1000")
	t.Setenv("TRUSTIX_TIX_TCP_KERNEL_SEAL_BEFORE_FRAGMENT", "0")
	provider := &fakeProvider{
		kernelCrypto:  true,
		payloadMax:    1000,
		sealBeforeMax: 4096,
		cryptos:       make(map[uint64]fakeCrypto),
	}
	session := newSession(provider, nil, 7, "ix-a", "ep", dataplane.CryptoPlacementKernel)
	if err := session.EnableCryptoOffload(tixTCPTestCryptoOffloadSpec()); err != nil {
		t.Fatalf("enable crypto offload: %v", err)
	}
	packet := ipv4PacketForTIXTCPTest(2500)

	if err := session.SendPackets([][]byte{packet}); err != nil {
		t.Fatalf("send packets: %v", err)
	}
	frames := provider.submittedFrames()
	if len(frames) != 3 {
		t.Fatalf("submitted frames = %d, want 3 pre-seal fragments", len(frames))
	}
	for i, frame := range frames {
		if frame.FragmentPayloadSize != 0 {
			t.Fatalf("frame %d fragment payload hint = %d, want 0", i, frame.FragmentPayloadSize)
		}
		if frame.FragmentIndex != uint16(i) || frame.FragmentCount != 3 {
			t.Fatalf("frame %d fragment header = index %d count %d", i, frame.FragmentIndex, frame.FragmentCount)
		}
	}
}

func TestTIXTCPReassemblesOutOfOrderFragments(t *testing.T) {
	session := newSession(nil, nil, 42, "ix-b", "server", dataplane.CryptoPlacementUserspace)
	payload := bytes.Repeat([]byte("a"), tixTCPFragmentPayloadSize*2+17)
	parts := [][]byte{
		payload[:tixTCPFragmentPayloadSize],
		payload[tixTCPFragmentPayloadSize : tixTCPFragmentPayloadSize*2],
		payload[tixTCPFragmentPayloadSize*2:],
	}
	for _, index := range []int{2, 0, 1} {
		session.handleFrame(dataplane.TIXTCPFrame{
			FlowID:        42,
			Direction:     dataplane.TIXTCPInbound,
			Sequence:      100 + uint64(index),
			FragmentIndex: uint16(index),
			FragmentCount: 3,
			Payload:       parts[index],
		})
	}
	got, err := session.RecvPacket()
	if err != nil {
		t.Fatalf("recv reassembled packet: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("reassembled payload mismatch len=%d want=%d", len(got), len(payload))
	}
	stats := session.Stats()
	if stats.Extra[tixTCPStatFragmentsReceived] != 3 || stats.Extra[tixTCPStatFragmentsReassembled] != 3 || stats.Extra[tixTCPStatFragmentedPacketsReceived] != 1 {
		t.Fatalf("fragment stats = %+v, want received/reassembled packet counters", stats.Extra)
	}
	if stats.Extra[tixTCPStatFragmentAssembliesCurrent] != 0 {
		t.Fatalf("current assemblies = %d, want 0", stats.Extra[tixTCPStatFragmentAssembliesCurrent])
	}
}

func TestTIXTCPRecvPacketsDrainsNativeBatch(t *testing.T) {
	session := newSession(nil, nil, 42, "ix-b", "server", dataplane.CryptoPlacementUserspace)
	session.handleFrames([]dataplane.TIXTCPFrame{
		{FlowID: 42, Direction: dataplane.TIXTCPInbound, Sequence: 1, Payload: []byte("one")},
		{FlowID: 42, Direction: dataplane.TIXTCPInbound, Sequence: 2, Payload: []byte("two")},
		{FlowID: 42, Direction: dataplane.TIXTCPInbound, Sequence: 3, Payload: []byte("three")},
	})

	packets, err := session.RecvPackets(2)
	if err != nil {
		t.Fatalf("RecvPackets first batch: %v", err)
	}
	if got, want := len(packets), 2; got != want {
		t.Fatalf("first batch size = %d, want %d", got, want)
	}
	if !bytes.Equal(packets[0], []byte("one")) || !bytes.Equal(packets[1], []byte("two")) {
		t.Fatalf("first batch = %q", packets)
	}
	packets, err = session.RecvPackets(8)
	if err != nil {
		t.Fatalf("RecvPackets pending batch: %v", err)
	}
	if got, want := len(packets), 1; got != want {
		t.Fatalf("pending batch size = %d, want %d", got, want)
	}
	if !bytes.Equal(packets[0], []byte("three")) {
		t.Fatalf("pending packet = %q", packets[0])
	}
	stats := session.Stats()
	if stats.PacketsReceived != 3 {
		t.Fatalf("packets received = %d, want 3", stats.PacketsReceived)
	}
}

func TestTIXTCPRecvCoalesceDelayEnv(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_RECV_COALESCE_DELAY", "")
	t.Setenv("TRUSTIX_TIX_TCP_RECV_BATCH_DELAY", "")
	if got := tixTCPRecvCoalesceDelay(); got != 0 {
		t.Fatalf("default recv coalesce delay = %s, want 0", got)
	}
	t.Setenv("TRUSTIX_TIX_TCP_RECV_COALESCE_DELAY", "25us")
	if got := tixTCPRecvCoalesceDelay(); got != 25*time.Microsecond {
		t.Fatalf("duration recv coalesce delay = %s, want 25us", got)
	}
	t.Setenv("TRUSTIX_TIX_TCP_RECV_COALESCE_DELAY", "50")
	if got := tixTCPRecvCoalesceDelay(); got != 50*time.Microsecond {
		t.Fatalf("numeric recv coalesce delay = %s, want 50us", got)
	}
	t.Setenv("TRUSTIX_TIX_TCP_RECV_COALESCE_DELAY", "10ms")
	if got := tixTCPRecvCoalesceDelay(); got != tixTCPRecvCoalesceDelayMax {
		t.Fatalf("capped recv coalesce delay = %s, want %s", got, tixTCPRecvCoalesceDelayMax)
	}
}

func TestTIXTCPRecvDrainBatchLimitEnv(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_RECV_DRAIN_BATCHES", "")
	if got := tixTCPRecvDrainBatchLimit(); got != tixTCPRecvDrainDefault {
		t.Fatalf("default recv drain batches = %d, want %d", got, tixTCPRecvDrainDefault)
	}
	t.Setenv("TRUSTIX_TIX_TCP_RECV_DRAIN_BATCHES", "0")
	if got := tixTCPRecvDrainBatchLimit(); got != 0 {
		t.Fatalf("disabled recv drain batches = %d, want 0", got)
	}
	t.Setenv("TRUSTIX_TIX_TCP_RECV_DRAIN_BATCHES", "512")
	if got := tixTCPRecvDrainBatchLimit(); got != tixTCPRecvDrainMax {
		t.Fatalf("capped recv drain batches = %d, want %d", got, tixTCPRecvDrainMax)
	}
}

func TestTIXTCPRecvPacketsDrainsQueuedBatchesWithoutDelay(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_RECV_DRAIN_BATCHES", "4")
	session := newSession(nil, nil, 42, "ix-b", "server", dataplane.CryptoPlacementUserspace)
	session.handleFrame(dataplane.TIXTCPFrame{FlowID: 42, Direction: dataplane.TIXTCPInbound, Sequence: 1, Payload: []byte("one")})
	session.handleFrame(dataplane.TIXTCPFrame{FlowID: 42, Direction: dataplane.TIXTCPInbound, Sequence: 2, Payload: []byte("two")})

	packets, err := session.RecvPackets(8)
	if err != nil {
		t.Fatalf("RecvPackets: %v", err)
	}
	if got, want := len(packets), 2; got != want {
		t.Fatalf("drained packet count = %d, want %d (%q)", got, want, packets)
	}
	if !bytes.Equal(packets[0], []byte("one")) || !bytes.Equal(packets[1], []byte("two")) {
		t.Fatalf("drained packets = %q", packets)
	}
}

func TestTIXTCPRecvPacketsCoalesceDelayWaitsForNextBatch(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_RECV_COALESCE_DELAY", "10ms")
	coalesceReady := make(chan struct{}, 1)
	tixTCPRecvCoalesceWaitHook = func() {
		select {
		case coalesceReady <- struct{}{}:
		default:
		}
	}
	t.Cleanup(func() {
		tixTCPRecvCoalesceWaitHook = nil
	})

	session := newSession(nil, nil, 42, "ix-b", "server", dataplane.CryptoPlacementUserspace)
	session.handleFrame(dataplane.TIXTCPFrame{FlowID: 42, Direction: dataplane.TIXTCPInbound, Sequence: 1, Payload: []byte("one")})

	result := make(chan [][]byte, 1)
	errCh := make(chan error, 1)
	go func() {
		packets, err := session.RecvPackets(8)
		if err != nil {
			errCh <- err
			return
		}
		result <- packets
	}()

	select {
	case <-coalesceReady:
	case err := <-errCh:
		t.Fatalf("RecvPackets error before coalesce wait = %v", err)
	case packets := <-result:
		t.Fatalf("RecvPackets returned before coalesce wait: %q", packets)
	case <-time.After(time.Second):
		t.Fatal("RecvPackets did not enter coalesce wait")
	}

	session.handleFrame(dataplane.TIXTCPFrame{FlowID: 42, Direction: dataplane.TIXTCPInbound, Sequence: 2, Payload: []byte("two")})

	select {
	case err := <-errCh:
		t.Fatalf("RecvPackets error = %v", err)
	case packets := <-result:
		if got, want := len(packets), 2; got != want {
			t.Fatalf("coalesced packet count = %d, want %d (%q)", got, want, packets)
		}
		if !bytes.Equal(packets[0], []byte("one")) || !bytes.Equal(packets[1], []byte("two")) {
			t.Fatalf("coalesced packets = %q", packets)
		}
	case <-time.After(time.Second):
		t.Fatal("RecvPackets did not return")
	}
}

func TestTIXTCPRecvPacketsWithRelease(t *testing.T) {
	session := newSession(nil, nil, 42, "ix-b", "server", dataplane.CryptoPlacementUserspace)
	var releases atomic.Uint64
	session.handleFrames([]dataplane.TIXTCPFrame{
		{FlowID: 42, Direction: dataplane.TIXTCPInbound, Sequence: 1, Payload: []byte("one"), Release: func() { releases.Add(1) }},
		{FlowID: 42, Direction: dataplane.TIXTCPInbound, Sequence: 2, Payload: []byte("two"), Release: func() { releases.Add(1) }},
	})

	packets, release, err := session.RecvPacketsWithRelease(8)
	if err != nil {
		t.Fatalf("RecvPacketsWithRelease: %v", err)
	}
	if got, want := len(packets), 2; got != want {
		t.Fatalf("batch size = %d, want %d", got, want)
	}
	if release == nil {
		t.Fatal("release is nil, want borrowed release")
	}
	if got := releases.Load(); got != 0 {
		t.Fatalf("releases before release() = %d, want 0", got)
	}
	release()
	if got := releases.Load(); got != 2 {
		t.Fatalf("releases after release() = %d, want 2", got)
	}
}

func TestTIXTCPListenerDispatchBatchReleasesSkippedFrames(t *testing.T) {
	listener := &listener{
		provider: &fakeProvider{},
		endpoint: transport.Endpoint{
			Name: "server",
		},
		acceptCh:  make(chan transport.Session),
		done:      make(chan struct{}),
		sessions:  make(map[uint64]*session),
		placement: dataplane.CryptoPlacementUserspace,
	}
	var releases atomic.Uint64
	listener.dispatchBatch([]dataplane.TIXTCPFrame{
		{
			FlowID:    1,
			Direction: dataplane.TIXTCPOutbound,
			Payload:   []byte("wrong-direction"),
			Release:   func() { releases.Add(1) },
		},
		{
			FlowID:    2,
			Direction: dataplane.TIXTCPInbound,
			Endpoint:  "other",
			Payload:   []byte("wrong-endpoint"),
			Release:   func() { releases.Add(1) },
		},
		{
			FlowID:    3,
			Direction: dataplane.TIXTCPInbound,
			Payload:   []byte("accept-full"),
			Release:   func() { releases.Add(1) },
		},
	})

	if got := releases.Load(); got != 3 {
		t.Fatalf("released skipped frames = %d, want 3", got)
	}
}

func TestTIXTCPListenerDispatchAllowsAnnotatedExistingFlow(t *testing.T) {
	listener := &listener{
		provider: &fakeProvider{},
		endpoint: transport.Endpoint{
			Name: "server",
		},
		acceptCh:  make(chan transport.Session, 1),
		done:      make(chan struct{}),
		sessions:  make(map[uint64]*session),
		placement: dataplane.CryptoPlacementUserspace,
	}
	listener.dispatch(dataplane.TIXTCPFrame{
		FlowID:    9,
		Direction: dataplane.TIXTCPInbound,
		Endpoint:  "server",
		Payload:   []byte("first"),
	})
	accepted := (<-listener.acceptCh).(*session)

	var released atomic.Uint64
	listener.dispatch(dataplane.TIXTCPFrame{
		FlowID:    9,
		Direction: dataplane.TIXTCPInbound,
		Endpoint:  "peer-endpoint",
		Payload:   []byte("annotated"),
		Release:   func() { released.Add(1) },
	})

	packets, release, err := accepted.RecvPacketsWithRelease(2)
	if err != nil {
		t.Fatalf("RecvPacketsWithRelease: %v", err)
	}
	if len(packets) != 2 || string(packets[0]) != "first" || string(packets[1]) != "annotated" {
		t.Fatalf("packets = %q, want first and annotated", packets)
	}
	if got := released.Load(); got != 0 {
		t.Fatalf("released before receiver release = %d, want 0", got)
	}
	release()
	if got := released.Load(); got != 1 {
		t.Fatalf("released after receiver release = %d, want 1", got)
	}
}

func TestTIXTCPListenerDispatchBatchAllowsAnnotatedExistingFlow(t *testing.T) {
	listener := &listener{
		provider: &fakeProvider{},
		endpoint: transport.Endpoint{
			Name: "server",
		},
		acceptCh:  make(chan transport.Session, 1),
		done:      make(chan struct{}),
		sessions:  make(map[uint64]*session),
		placement: dataplane.CryptoPlacementUserspace,
	}
	existing := newSession(listener.provider, nil, 10, "ix-b", "server", dataplane.CryptoPlacementUserspace)
	listener.sessions[10] = existing

	var released atomic.Uint64
	listener.dispatchBatch([]dataplane.TIXTCPFrame{
		{
			FlowID:    10,
			Direction: dataplane.TIXTCPInbound,
			Endpoint:  "peer-endpoint",
			Payload:   []byte("existing"),
			Release:   func() { released.Add(1) },
		},
		{
			FlowID:    11,
			Direction: dataplane.TIXTCPInbound,
			Endpoint:  "peer-endpoint",
			Payload:   []byte("new-wrong-endpoint"),
			Release:   func() { released.Add(1) },
		},
	})

	packets, release, err := existing.RecvPacketsWithRelease(1)
	if err != nil {
		t.Fatalf("RecvPacketsWithRelease: %v", err)
	}
	if len(packets) != 1 || string(packets[0]) != "existing" {
		t.Fatalf("packets = %q, want existing", packets)
	}
	if got := released.Load(); got != 1 {
		t.Fatalf("released before receiver release = %d, want only rejected frame", got)
	}
	release()
	if got := released.Load(); got != 2 {
		t.Fatalf("released after receiver release = %d, want 2", got)
	}
	if _, ok := listener.sessions[11]; ok {
		t.Fatal("created session for mismatched endpoint")
	}
}

func TestTIXTCPSessionCloseReleasesQueuedBorrowedPackets(t *testing.T) {
	session := newSession(nil, nil, 42, "ix-b", "server", dataplane.CryptoPlacementUserspace)
	var releases atomic.Uint64
	session.handleFrames([]dataplane.TIXTCPFrame{
		{
			FlowID:    42,
			Direction: dataplane.TIXTCPInbound,
			Sequence:  1,
			Payload:   []byte("queued"),
			Release:   func() { releases.Add(1) },
		},
	})

	session.closeInput()

	if got := releases.Load(); got != 1 {
		t.Fatalf("released queued packets on close = %d, want 1", got)
	}
}

func TestTIXTCPFragmentStatsTrackRejectsDuplicatesAndExpiry(t *testing.T) {
	session := newSession(nil, nil, 42, "ix-b", "server", dataplane.CryptoPlacementUserspace)
	session.handleFrame(dataplane.TIXTCPFrame{
		FlowID:        42,
		Direction:     dataplane.TIXTCPInbound,
		Sequence:      0,
		FragmentIndex: 1,
		FragmentCount: 3,
		Payload:       []byte("bad-sequence"),
	})
	if got := session.Stats().Extra[tixTCPStatFragmentRejects]; got != 1 {
		t.Fatalf("fragment rejects = %d, want 1", got)
	}

	session.handleFrame(dataplane.TIXTCPFrame{
		FlowID:        42,
		Direction:     dataplane.TIXTCPInbound,
		Sequence:      100,
		FragmentIndex: 0,
		FragmentCount: 2,
		Payload:       []byte("first-"),
	})
	session.handleFrame(dataplane.TIXTCPFrame{
		FlowID:        42,
		Direction:     dataplane.TIXTCPInbound,
		Sequence:      100,
		FragmentIndex: 0,
		FragmentCount: 2,
		Payload:       []byte("first-again"),
	})
	stats := session.Stats()
	if stats.Extra[tixTCPStatFragmentDuplicates] != 1 {
		t.Fatalf("fragment duplicates = %d, want 1", stats.Extra[tixTCPStatFragmentDuplicates])
	}
	if stats.Extra[tixTCPStatFragmentAssembliesCurrent] != 1 {
		t.Fatalf("current assemblies = %d, want 1", stats.Extra[tixTCPStatFragmentAssembliesCurrent])
	}

	session.handleFrame(dataplane.TIXTCPFrame{
		FlowID:        42,
		Direction:     dataplane.TIXTCPInbound,
		Sequence:      101,
		FragmentIndex: 1,
		FragmentCount: 4,
		Payload:       []byte("mismatch"),
	})
	stats = session.Stats()
	if stats.Extra[tixTCPStatFragmentMismatches] != 1 || stats.Extra[tixTCPStatFragmentRejects] != 2 {
		t.Fatalf("mismatch/reject stats = %+v, want mismatch=1 rejects=2", stats.Extra)
	}
	if stats.Extra[tixTCPStatFragmentAssembliesCurrent] != 0 {
		t.Fatalf("current assemblies after mismatch = %d, want 0", stats.Extra[tixTCPStatFragmentAssembliesCurrent])
	}

	session.handleFrame(dataplane.TIXTCPFrame{
		FlowID:        42,
		Direction:     dataplane.TIXTCPInbound,
		Sequence:      300,
		FragmentIndex: 0,
		FragmentCount: 2,
		Payload:       []byte("stale"),
	})
	session.recvMu.Lock()
	session.reassembly[300].createdAt = time.Now().Add(-tixTCPReassemblyTTL - time.Second)
	session.recvMu.Unlock()
	session.handleFrame(dataplane.TIXTCPFrame{
		FlowID:        42,
		Direction:     dataplane.TIXTCPInbound,
		Sequence:      400,
		FragmentIndex: 0,
		FragmentCount: 2,
		Payload:       []byte("fresh"),
	})
	stats = session.Stats()
	if stats.Extra[tixTCPStatFragmentExpiredAssemblies] != 1 || stats.Extra[tixTCPStatFragmentExpiredFragments] != 1 {
		t.Fatalf("expiry stats = %+v, want one stale assembly/fragment", stats.Extra)
	}
}

func TestTIXTCPUsesConfiguredCryptoPlacement(t *testing.T) {
	providerA, _ := newProviderPair("ix-a", "ix-b")
	transportImpl := New(providerA, Options{
		CryptoPlacement: func() dataplane.CryptoPlacement {
			return dataplane.CryptoPlacementUserspace
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session, err := transportImpl.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{
			{
				Name:      core.EndpointID("server"),
				Transport: transport.ProtocolTIXTCP,
				Address:   "ix-b-underlay:443",
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer session.Close()

	providerA.mu.Lock()
	defer providerA.mu.Unlock()
	if len(providerA.flows) != 1 {
		t.Fatalf("installed flows = %d, want 1", len(providerA.flows))
	}
	for _, flow := range providerA.flows {
		if flow.CryptoPlacement != dataplane.CryptoPlacementUserspace {
			t.Fatalf("flow crypto placement = %q, want userspace", flow.CryptoPlacement)
		}
	}
	if session.Stats().CryptoPlacement != string(dataplane.CryptoPlacementUserspace) {
		t.Fatalf("session crypto placement = %q, want userspace", session.Stats().CryptoPlacement)
	}
}

func TestTIXTCPDefaultAutoUsesKernelCryptoWhenAvailable(t *testing.T) {
	providerA, _ := newProviderPair("ix-a", "ix-b")
	providerA.kernelCrypto = true
	transportImpl := New(providerA)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session, err := transportImpl.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolTIXTCP,
			Address:   "ix-b-underlay:443",
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer session.Close()

	providerA.mu.Lock()
	defer providerA.mu.Unlock()
	if len(providerA.flows) != 1 {
		t.Fatalf("installed flows = %d, want 1", len(providerA.flows))
	}
	for _, flow := range providerA.flows {
		if flow.CryptoPlacement != dataplane.CryptoPlacementKernel {
			t.Fatalf("flow crypto placement = %q, want kernel", flow.CryptoPlacement)
		}
	}
}

func TestTIXTCPAutoPrefersKernelCryptoWhenBothPlacementsAvailable(t *testing.T) {
	placement, err := selectCryptoPlacement(dataplane.CryptoPlacementAuto, dataplane.TIXTCPStatus{
		UserspaceCrypto: true,
		KernelCrypto:    true,
		PreferredCrypto: dataplane.CryptoPlacementUserspace,
	})
	if err != nil {
		t.Fatalf("select crypto placement: %v", err)
	}
	if placement != dataplane.CryptoPlacementKernel {
		t.Fatalf("auto crypto placement = %q, want kernel", placement)
	}
}

func TestTIXTCPPlaintextAutoKeepsKernelTransportWithoutCryptoPlacement(t *testing.T) {
	providerA, _ := newProviderPair("ix-a", "ix-b")
	providerA.kernelCrypto = true
	transportImpl := New(providerA, Options{
		CryptoPlacement: func() dataplane.CryptoPlacement {
			return dataplane.CryptoPlacementAuto
		},
		Encryption: func() string {
			return "plaintext"
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session, err := transportImpl.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolTIXTCP,
			Address:   "ix-b-underlay:443",
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer session.Close()

	providerA.mu.Lock()
	defer providerA.mu.Unlock()
	if len(providerA.flows) != 1 {
		t.Fatalf("installed flows = %d, want 1", len(providerA.flows))
	}
	for _, flow := range providerA.flows {
		if flow.CryptoPlacement != dataplane.CryptoPlacementUserspace {
			t.Fatalf("plaintext flow crypto placement = %q, want userspace/no crypto", flow.CryptoPlacement)
		}
	}
}

func TestTIXTCPCloseDeletesInstalledFlow(t *testing.T) {
	providerA, _ := newProviderPair("ix-a", "ix-b")
	transportImpl := New(providerA)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session, err := transportImpl.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{
			{
				Name:      core.EndpointID("server"),
				Transport: transport.ProtocolTIXTCP,
				Address:   "ix-b-underlay:443",
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	providerA.mu.Lock()
	installed := len(providerA.flows)
	providerA.mu.Unlock()
	if installed != 1 {
		t.Fatalf("installed flows = %d, want 1", installed)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	providerA.mu.Lock()
	defer providerA.mu.Unlock()
	if len(providerA.flows) != 0 {
		t.Fatalf("installed flows after close = %d, want 0", len(providerA.flows))
	}
}

func TestTIXTCPDialCarriesLocalBindSourceIP(t *testing.T) {
	t.Setenv("TRUSTIX_TIX_TCP_COMPAT_TCP_PRIMER", "0")
	providerA, _ := newProviderPair("ix-a", "ix-b")
	transportImpl := New(providerA)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session, err := transportImpl.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolTIXTCP,
			Address:   "198.51.100.2:7142",
			LocalBind: transport.LocalBind{SourceIP: "192.0.2.10"},
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer session.Close()
	providerA.mu.Lock()
	defer providerA.mu.Unlock()
	if len(providerA.flows) != 1 {
		t.Fatalf("installed flows = %d, want 1", len(providerA.flows))
	}
	for _, flow := range providerA.flows {
		if flow.LocalAddress != "192.0.2.10" {
			t.Fatalf("flow local address = %q, want 192.0.2.10", flow.LocalAddress)
		}
	}
}

func TestTIXTCPCloseCanRetainInstalledFlow(t *testing.T) {
	providerA, _ := newProviderPair("ix-a", "ix-b")
	session := newSession(providerA, nil, 123, "ix-b", "server", dataplane.CryptoPlacementUserspace)
	providerA.flows[123] = dataplane.TIXTCPFlow{
		ID:            123,
		Peer:          "ix-b",
		Endpoint:      "server",
		RemoteAddress: "198.51.100.2:7142",
	}

	retainer, ok := any(session).(transport.KernelFlowRetentionSession)
	if !ok {
		t.Fatal("tix_tcp session does not implement KernelFlowRetentionSession")
	}
	retainer.RetainKernelFlowOnClose()
	if err := session.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	providerA.mu.Lock()
	defer providerA.mu.Unlock()
	if _, ok := providerA.flows[123]; !ok {
		t.Fatal("retained tix_tcp flow was deleted on close")
	}
}

func TestTIXTCPSessionEnqueueAfterCloseDoesNotPanic(t *testing.T) {
	providerA, _ := newProviderPair("ix-a", "ix-b")
	session := newSession(providerA, nil, 123, "ix-b", "server", dataplane.CryptoPlacementUserspace)
	session.closeInput()
	session.enqueue([]byte("late-frame"))
}

func TestTIXTCPRejectsUnavailableKernelCrypto(t *testing.T) {
	providerA, _ := newProviderPair("ix-a", "ix-b")
	transportImpl := New(providerA, Options{
		CryptoPlacement: func() dataplane.CryptoPlacement {
			return dataplane.CryptoPlacementKernel
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := transportImpl.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{
			{
				Name:      core.EndpointID("server"),
				Transport: transport.ProtocolTIXTCP,
				Address:   "ix-b-underlay:443",
			},
		},
	}, nil)
	if err == nil {
		t.Fatal("expected unavailable kernel crypto to be rejected")
	}
}

func TestSecureTransportKernelCryptoOffloadOverTIXTCPProvider(t *testing.T) {
	providerA, providerB := newProviderPair("ix-a", "ix-b")
	providerA.kernelCrypto = true
	providerB.kernelCrypto = true
	kernelOptions := Options{
		CryptoPlacement: func() dataplane.CryptoPlacement {
			return dataplane.CryptoPlacementKernel
		},
	}
	clientTransport := securetransport.New(New(providerA, kernelOptions), securetransport.Options{})
	serverTransport := securetransport.New(New(providerB, kernelOptions), securetransport.Options{})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := serverTransport.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolTIXTCP,
		Listen:    "ix-b-underlay:443",
		Enabled:   true,
	}, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan transport.Session, 1)
	acceptErr := make(chan error, 1)
	go func() {
		session, err := listener.Accept(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- session
	}()

	client, err := clientTransport.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{
			{
				Name:      core.EndpointID("server"),
				Transport: transport.ProtocolTIXTCP,
				Address:   "ix-b-underlay:443",
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	var server transport.Session
	select {
	case err := <-acceptErr:
		t.Fatalf("accept: %v", err)
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()

	payload := []byte("kernel-offloaded-secret")
	if err := client.SendPacket(payload); err != nil {
		t.Fatalf("client send: %v", err)
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("server received %q", got)
	}
	if bytes.Contains(providerA.lastWirePayload(), payload) {
		t.Fatalf("kernel offload wire payload contains plaintext: %x", providerA.lastWirePayload())
	}
	if stats := client.Stats(); !stats.Encrypted || stats.CryptoPlacement != string(dataplane.CryptoPlacementKernel) {
		t.Fatalf("client stats encrypted=%t placement=%q", stats.Encrypted, stats.CryptoPlacement)
	}
	if stats := server.Stats(); !stats.Encrypted || stats.CryptoPlacement != string(dataplane.CryptoPlacementKernel) {
		t.Fatalf("server stats encrypted=%t placement=%q", stats.Encrypted, stats.CryptoPlacement)
	}
}

func TestSecureTransportKernelCryptoOffloadAES128OverTIXTCPProvider(t *testing.T) {
	providerA, providerB := newProviderPair("ix-a", "ix-b")
	providerA.kernelCrypto = true
	providerB.kernelCrypto = true
	kernelOptions := Options{
		CryptoPlacement: func() dataplane.CryptoPlacement {
			return dataplane.CryptoPlacementKernel
		},
	}
	secureOptions := securetransport.Options{
		CryptoSuites: func() []string {
			return []string{securetransport.SuiteAES128GCMX25519}
		},
	}
	clientTransport := securetransport.New(New(providerA, kernelOptions), secureOptions)
	serverTransport := securetransport.New(New(providerB, kernelOptions), secureOptions)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	listener, err := serverTransport.Listen(ctx, transport.Endpoint{
		Name:      core.EndpointID("server"),
		Transport: transport.ProtocolTIXTCP,
		Listen:    "ix-b-underlay:443",
		Enabled:   true,
	}, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan transport.Session, 1)
	go func() {
		session, err := listener.Accept(ctx)
		if err == nil {
			accepted <- session
		}
	}()

	client, err := clientTransport.Dial(ctx, transport.Peer{
		ID:       core.IXID("ix-b"),
		DomainID: core.DomainID("lab.local"),
		Endpoints: []transport.Endpoint{{
			Name:      core.EndpointID("server"),
			Transport: transport.ProtocolTIXTCP,
			Address:   "ix-b-underlay:443",
		}},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	var server transport.Session
	select {
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()

	payload := []byte("aes128-kernel-offload")
	if err := client.SendPacket(payload); err != nil {
		t.Fatalf("client send: %v", err)
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("server recv: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("server received %q", got)
	}
	wire := providerA.lastWirePayload()
	if len(wire) < 6 {
		t.Fatalf("wire payload too short: %d", len(wire))
	}
	if wire[5] != 2 {
		t.Fatalf("wire suite id = %d, want AES-128 id 2", wire[5])
	}
}

func TestTIXTCPOffloadClearsDataplaneSpec(t *testing.T) {
	provider := &capturingCryptoInstallerProvider{}
	session := newSession(provider, nil, 42, core.IXID("ix-b"), core.EndpointID("server"), dataplane.CryptoPlacementKernel)
	spec := transport.CryptoOffloadSpec{
		Suite:        securetransport.SuiteAES256GCMX25519,
		WireFormat:   transport.CryptoWireFormatTrustIXSecureDataV1,
		Epoch:        7,
		SendKey:      bytes.Repeat([]byte{0x11}, 32),
		SendIV:       bytes.Repeat([]byte{0x22}, 12),
		RecvKey:      bytes.Repeat([]byte{0x33}, 32),
		RecvIV:       bytes.Repeat([]byte{0x44}, 12),
		ReplayWindow: 64,
	}

	if err := session.EnableCryptoOffload(spec); err != nil {
		t.Fatalf("enable crypto offload: %v", err)
	}
	if !session.cryptoOffloaded {
		t.Fatalf("session did not mark crypto as offloaded")
	}
	if len(provider.specs) != 1 {
		t.Fatalf("captured specs = %d, want 1", len(provider.specs))
	}
	captured := provider.specs[0]
	if captured.ReplayWindow != tixTCPKernelCryptoReplayWindow {
		t.Fatalf("replay window = %d, want %d", captured.ReplayWindow, tixTCPKernelCryptoReplayWindow)
	}
	requireZeroedBytes(t, "send key", captured.SendKey)
	requireZeroedBytes(t, "send iv", captured.SendIV)
	requireZeroedBytes(t, "recv key", captured.RecvKey)
	requireZeroedBytes(t, "recv iv", captured.RecvIV)
	if !bytes.Equal(spec.SendKey, bytes.Repeat([]byte{0x11}, 32)) {
		t.Fatalf("input send key was mutated")
	}
}

func TestTIXTCPSessionSetPeerEndpointAnnotatesFlow(t *testing.T) {
	providerA, _ := newProviderPair("ix-a", "ix-b")
	flowID := uint64(99)
	providerA.flows[flowID] = dataplane.TIXTCPFlow{
		ID:       flowID,
		Peer:     core.IXID("ix-a"),
		Endpoint: core.EndpointID("ix-b-tix_tcp"),
	}
	session := newSession(providerA, nil, flowID, core.IXID("ix-a"), core.EndpointID("ix-b-tix_tcp"), dataplane.CryptoPlacementUserspace)

	session.SetPeerEndpoint(core.IXID("ix-a"), core.EndpointID("ix-a-tix_tcp"))

	providerA.mu.Lock()
	flow := providerA.flows[flowID]
	providerA.mu.Unlock()
	if flow.Peer != "ix-a" || flow.Endpoint != "ix-a-tix_tcp" {
		t.Fatalf("annotated flow identity = peer:%q endpoint:%q, want ix-a/ix-a-tix_tcp", flow.Peer, flow.Endpoint)
	}
}

func TestTIXTCPSessionCloseReturnsFlowAnnotationFailure(t *testing.T) {
	wantErr := errors.New("injected tix_tcp flow annotation failure")
	provider, _ := newProviderPair("ix-a", "ix-b")
	provider.annotateErr = wantErr
	session := newSession(provider, nil, 100, core.IXID("ix-a"), core.EndpointID("ix-b-tix_tcp"), dataplane.CryptoPlacementUserspace)

	session.SetPeerEndpoint(core.IXID("ix-a"), core.EndpointID("ix-a-tix_tcp"))

	if err := session.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("close error = %v, want annotation failure", err)
	}
}

func TestTuneTIXTCPCompatConnReturnsSocketErrors(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen TCP: %v", err)
	}
	defer listener.Close()
	type dialResult struct {
		conn net.Conn
		err  error
	}
	dialCh := make(chan dialResult, 1)
	go func() {
		conn, err := net.Dial("tcp", listener.Addr().String())
		dialCh <- dialResult{conn: conn, err: err}
	}()
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept TCP: %v", err)
	}
	dialed := <-dialCh
	if dialed.err != nil {
		t.Fatalf("dial TCP: %v", dialed.err)
	}
	defer dialed.conn.Close()
	if err := serverConn.Close(); err != nil {
		t.Fatalf("close accepted TCP connection: %v", err)
	}

	if err := tuneTIXTCPCompatConn(serverConn); err == nil {
		t.Fatal("tuning a closed TCP connection unexpectedly succeeded")
	}
}

func TestTIXTCPUnavailableErrorsIncludeFastPathFallback(t *testing.T) {
	provider := &fakeProvider{
		subs:             make(map[chan dataplane.TIXTCPFrame]struct{}),
		flows:            make(map[uint64]dataplane.TIXTCPFlow),
		cryptos:          make(map[uint64]fakeCrypto),
		availableSet:     true,
		available:        false,
		reinjectSet:      true,
		reinject:         false,
		fastPathFallback: "missing requested kfuncs: route_tcp_gso; fixing up kfuncs: no BTF found",
	}
	transportImpl := New(provider)
	peer := transport.Peer{
		ID: "ix-b",
		Endpoints: []transport.Endpoint{{
			Name:      "exp",
			Address:   "198.18.0.2:13000",
			Transport: transport.ProtocolTIXTCP,
		}},
	}
	endpoint := transport.Endpoint{
		Name:      "exp",
		Listen:    "127.0.0.1:0",
		Transport: transport.ProtocolTIXTCP,
	}

	probe := transportImpl.Probe(context.Background(), peer)
	if probe.Healthy || !strings.Contains(probe.Error, "no BTF found") {
		t.Fatalf("probe = %+v, want unavailable error with fallback detail", probe)
	}
	if _, err := transportImpl.Dial(context.Background(), peer, nil); err == nil || !strings.Contains(err.Error(), "no BTF found") {
		t.Fatalf("dial error = %v, want fallback detail", err)
	}
	if _, err := transportImpl.Listen(context.Background(), endpoint, nil); err == nil || !strings.Contains(err.Error(), "no BTF found") {
		t.Fatalf("listen error = %v, want fallback detail", err)
	}
}

type fakeProvider struct {
	local            core.IXID
	remote           *fakeProvider
	mu               sync.Mutex
	subs             map[chan dataplane.TIXTCPFrame]struct{}
	flows            map[uint64]dataplane.TIXTCPFlow
	cryptos          map[uint64]fakeCrypto
	kernelCrypto     bool
	statusProvider   string
	availableSet     bool
	available        bool
	reinjectSet      bool
	reinject         bool
	fastPathFallback string
	payloadMax       int
	sealBeforeMax    int
	lastWire         []byte
	frames           []dataplane.TIXTCPFrame
	submitted        atomic.Uint64
	received         atomic.Uint64
	annotateErr      error
}

type capturingCryptoInstallerProvider struct {
	specs []dataplane.TIXTCPCryptoSpec
}

func (provider *capturingCryptoInstallerProvider) TIXTCPStatus(ctx context.Context) (dataplane.TIXTCPStatus, error) {
	if err := ctx.Err(); err != nil {
		return dataplane.TIXTCPStatus{}, err
	}
	return dataplane.TIXTCPStatus{
		Available:       true,
		UserspaceCrypto: true,
		KernelCrypto:    true,
		Reinject:        true,
		PreferredCrypto: dataplane.CryptoPlacementKernel,
	}, nil
}

func (provider *capturingCryptoInstallerProvider) InstallTIXTCPFlows(ctx context.Context, flows []dataplane.TIXTCPFlow) error {
	return ctx.Err()
}

func (provider *capturingCryptoInstallerProvider) SubmitTIXTCPFrame(ctx context.Context, frame dataplane.TIXTCPFrame) error {
	return ctx.Err()
}

func (provider *capturingCryptoInstallerProvider) SubscribeTIXTCP(ctx context.Context, buffer int) (dataplane.TIXTCPSubscription, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("capturing provider does not support subscriptions")
}

func (provider *capturingCryptoInstallerProvider) InstallTIXTCPCrypto(ctx context.Context, specs []dataplane.TIXTCPCryptoSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	provider.specs = append(provider.specs, specs...)
	return nil
}

func requireZeroedBytes(t *testing.T, name string, payload []byte) {
	t.Helper()
	for i, value := range payload {
		if value != 0 {
			t.Fatalf("%s byte %d = 0x%02x, want zero", name, i, value)
		}
	}
}

func tixTCPTestCryptoOffloadSpec() transport.CryptoOffloadSpec {
	return transport.CryptoOffloadSpec{
		Suite:      securetransport.SuiteAES256GCMX25519,
		WireFormat: transport.CryptoWireFormatTrustIXSecureDataV1,
		Epoch:      1,
		SendKey:    bytes.Repeat([]byte{0x11}, 32),
		SendIV:     bytes.Repeat([]byte{0x22}, 12),
		RecvKey:    bytes.Repeat([]byte{0x11}, 32),
		RecvIV:     bytes.Repeat([]byte{0x22}, 12),
	}
}

func eventually(t *testing.T, ctx context.Context, check func() bool) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if check() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
		}
	}
}

func newProviderPair(a, b core.IXID) (*fakeProvider, *fakeProvider) {
	providerA := &fakeProvider{local: a, subs: make(map[chan dataplane.TIXTCPFrame]struct{}), flows: make(map[uint64]dataplane.TIXTCPFlow), cryptos: make(map[uint64]fakeCrypto)}
	providerB := &fakeProvider{local: b, subs: make(map[chan dataplane.TIXTCPFrame]struct{}), flows: make(map[uint64]dataplane.TIXTCPFlow), cryptos: make(map[uint64]fakeCrypto)}
	providerA.remote = providerB
	providerB.remote = providerA
	return providerA, providerB
}

func (provider *fakeProvider) TIXTCPStatus(ctx context.Context) (dataplane.TIXTCPStatus, error) {
	if err := ctx.Err(); err != nil {
		return dataplane.TIXTCPStatus{}, err
	}
	provider.mu.Lock()
	activeFlows := len(provider.flows)
	provider.mu.Unlock()
	available := true
	if provider.availableSet {
		available = provider.available
	}
	reinject := true
	if provider.reinjectSet {
		reinject = provider.reinject
	}
	return dataplane.TIXTCPStatus{
		Available:        available,
		Provider:         provider.statusProvider,
		UserspaceCrypto:  true,
		KernelCrypto:     provider.kernelCrypto,
		Reinject:         reinject,
		FastPathFallback: provider.fastPathFallback,
		PreferredCrypto:  provider.preferredCrypto(),
		SupportedCrypto:  provider.supportedCrypto(),
		ActiveFlows:      activeFlows,
		SubmittedFrames:  provider.submitted.Load(),
		ReceivedFrames:   provider.received.Load(),
	}, nil
}

func (provider *fakeProvider) preferredCrypto() dataplane.CryptoPlacement {
	if provider.kernelCrypto {
		return dataplane.CryptoPlacementKernel
	}
	return dataplane.CryptoPlacementUserspace
}

func (provider *fakeProvider) supportedCrypto() []dataplane.CryptoPlacement {
	if provider.kernelCrypto {
		return []dataplane.CryptoPlacement{dataplane.CryptoPlacementUserspace, dataplane.CryptoPlacementKernel}
	}
	return []dataplane.CryptoPlacement{dataplane.CryptoPlacementUserspace}
}

func (provider *fakeProvider) TIXTCPPayloadMax(ctx context.Context, placement dataplane.CryptoPlacement, encrypted bool) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return provider.payloadMax, nil
}

func (provider *fakeProvider) TIXTCPSealBeforeFragmentMax(ctx context.Context, placement dataplane.CryptoPlacement) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if provider.sealBeforeMax > 0 {
		return provider.sealBeforeMax, nil
	}
	return tixTCPKernelSealBeforeMax, nil
}

func (provider *fakeProvider) InstallTIXTCPFlows(ctx context.Context, flows []dataplane.TIXTCPFlow) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	for _, flow := range flows {
		if flow.CryptoPlacement == dataplane.CryptoPlacementKernel && !provider.kernelCrypto {
			return fmt.Errorf("kernel crypto unavailable")
		}
		provider.flows[flow.ID] = flow
	}
	return nil
}

func (provider *fakeProvider) DeleteTIXTCPFlows(ctx context.Context, flowIDs []uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	for _, flowID := range flowIDs {
		delete(provider.flows, flowID)
		delete(provider.cryptos, flowID)
	}
	return nil
}

func (provider *fakeProvider) SetTIXTCPFlowPeer(ctx context.Context, flowID uint64, peer core.IXID, endpoint core.EndpointID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if provider.annotateErr != nil {
		return provider.annotateErr
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	flow := provider.flows[flowID]
	if peer != "" {
		flow.Peer = peer
	}
	if endpoint != "" {
		flow.Endpoint = endpoint
	}
	provider.flows[flowID] = flow
	return nil
}

func (provider *fakeProvider) InstallTIXTCPCrypto(ctx context.Context, specs []dataplane.TIXTCPCryptoSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !provider.kernelCrypto {
		return fmt.Errorf("kernel crypto unavailable")
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	for _, spec := range specs {
		cryptoState, err := newFakeCrypto(spec)
		if err != nil {
			return err
		}
		provider.cryptos[spec.FlowID] = cryptoState
	}
	return nil
}

func (provider *fakeProvider) SubmitTIXTCPFrame(ctx context.Context, frame dataplane.TIXTCPFrame) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	provider.submitted.Add(1)
	provider.mu.Lock()
	provider.frames = append(provider.frames, frame)
	provider.mu.Unlock()
	outbound := frame
	if frame.CryptoPlacement == dataplane.CryptoPlacementKernel {
		provider.mu.Lock()
		cryptoState, ok := provider.cryptos[frame.FlowID]
		provider.mu.Unlock()
		if !ok {
			return fmt.Errorf("kernel crypto for flow %d is not installed", frame.FlowID)
		}
		wire, err := cryptoState.seal(frame.Sequence, frame.Payload)
		if err != nil {
			return err
		}
		outbound.Payload = wire
		outbound.Encrypted = true
		outbound.CryptoSuite = frame.CryptoSuite
		provider.mu.Lock()
		provider.lastWire = append(provider.lastWire[:0], wire...)
		provider.mu.Unlock()
	}
	if provider.remote == nil {
		return nil
	}
	inbound := outbound
	inbound.Direction = dataplane.TIXTCPInbound
	inbound.Peer = provider.local
	provider.remote.deliver(inbound)
	return nil
}

func (provider *fakeProvider) SubmitTIXTCPFrames(ctx context.Context, frames []dataplane.TIXTCPFrame) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, frame := range frames {
		if err := provider.SubmitTIXTCPFrame(ctx, frame); err != nil {
			return err
		}
	}
	return nil
}

func (provider *fakeProvider) SubscribeTIXTCP(ctx context.Context, buffer int) (dataplane.TIXTCPSubscription, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if buffer <= 0 {
		buffer = 16
	}
	events := make(chan dataplane.TIXTCPFrame, buffer)
	provider.mu.Lock()
	provider.subs[events] = struct{}{}
	provider.mu.Unlock()
	return &fakeSubscription{provider: provider, events: events}, nil
}

func (provider *fakeProvider) deliver(frame dataplane.TIXTCPFrame) {
	provider.received.Add(1)
	provider.mu.Lock()
	if frame.Encrypted && frame.CryptoPlacement == dataplane.CryptoPlacementKernel {
		cryptoState, ok := provider.cryptos[frame.FlowID]
		if !ok {
			provider.mu.Unlock()
			return
		}
		plaintext, err := cryptoState.open(frame.Payload)
		if err != nil {
			provider.mu.Unlock()
			return
		}
		frame.Payload = plaintext
		frame.Encrypted = false
	}
	defer provider.mu.Unlock()
	for sub := range provider.subs {
		select {
		case sub <- frame:
		default:
		}
	}
}

func (provider *fakeProvider) lastWirePayload() []byte {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return append([]byte(nil), provider.lastWire...)
}

func (provider *fakeProvider) submittedFrames() []dataplane.TIXTCPFrame {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return append([]dataplane.TIXTCPFrame(nil), provider.frames...)
}

type fakeCrypto struct {
	epoch    uint64
	suiteID  byte
	sendIV   []byte
	recvIV   []byte
	sendAEAD cipher.AEAD
	recvAEAD cipher.AEAD
}

func newFakeCrypto(spec dataplane.TIXTCPCryptoSpec) (fakeCrypto, error) {
	sendAEAD, err := fakeAEAD(spec.SendKey)
	if err != nil {
		return fakeCrypto{}, err
	}
	recvAEAD, err := fakeAEAD(spec.RecvKey)
	if err != nil {
		return fakeCrypto{}, err
	}
	if len(spec.SendIV) != 12 || len(spec.RecvIV) != 12 {
		return fakeCrypto{}, fmt.Errorf("invalid IV length")
	}
	suiteID, err := fakeSuiteID(spec.Suite)
	if err != nil {
		return fakeCrypto{}, err
	}
	return fakeCrypto{
		epoch:    spec.Epoch,
		suiteID:  suiteID,
		sendIV:   append([]byte(nil), spec.SendIV...),
		recvIV:   append([]byte(nil), spec.RecvIV...),
		sendAEAD: sendAEAD,
		recvAEAD: recvAEAD,
	}, nil
}

func fakeAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (cryptoState fakeCrypto) seal(seq uint64, plaintext []byte) ([]byte, error) {
	header := fakeSecureHeader(cryptoState.suiteID, cryptoState.epoch, seq)
	nonce := fakeNonce(cryptoState.sendIV, seq)
	return cryptoState.sendAEAD.Seal(header, nonce, plaintext, header), nil
}

func (cryptoState fakeCrypto) open(wire []byte) ([]byte, error) {
	if len(wire) < 24 {
		return nil, fmt.Errorf("wire packet too short")
	}
	header := wire[:24]
	seq := binary.BigEndian.Uint64(header[16:24])
	nonce := fakeNonce(cryptoState.recvIV, seq)
	return cryptoState.recvAEAD.Open(nil, nonce, wire[24:], header)
}

func fakeSuiteID(suite string) (byte, error) {
	switch suite {
	case securetransport.SuiteAES256GCMX25519:
		return 1, nil
	case securetransport.SuiteAES128GCMX25519:
		return 2, nil
	default:
		return 0, fmt.Errorf("fake kernel crypto suite %q is unsupported", suite)
	}
}

func fakeSecureHeader(suiteID byte, epoch, seq uint64) []byte {
	header := make([]byte, 24)
	copy(header[0:4], []byte{'T', 'I', 'X', 'D'})
	header[4] = 1
	header[5] = suiteID
	binary.BigEndian.PutUint64(header[8:16], epoch)
	binary.BigEndian.PutUint64(header[16:24], seq)
	return header
}

func fakeNonce(prefix []byte, seq uint64) []byte {
	nonce := make([]byte, 12)
	copy(nonce, prefix)
	binary.BigEndian.PutUint64(nonce[4:], seq)
	return nonce
}

func tlsCertificateForTIXTCPTest(bundle pki.Bundle) tls.Certificate {
	return tls.Certificate{
		Certificate: [][]byte{bundle.Cert.Raw},
		PrivateKey:  bundle.Key,
		Leaf:        bundle.Cert,
	}
}

func tixTCPLocalTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve tcp addr: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close reserved tcp addr: %v", err)
	}
	return addr
}

func ipv4PacketForTIXTCPTest(length int) []byte {
	if length < 20 {
		length = 20
	}
	packet := make([]byte, length)
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 6
	binary.BigEndian.PutUint16(packet[2:4], uint16(length))
	copy(packet[12:16], []byte{10, 0, 0, 1})
	copy(packet[16:20], []byte{10, 0, 0, 2})
	return packet
}

func tixTCPTestTIXB(packets ...[]byte) []byte {
	batch := []byte{'T', 'I', 'X', 'B', tixTCPTIXBVersion, 0, byte(len(packets) >> 8), byte(len(packets))}
	for _, packet := range packets {
		batch = binary.BigEndian.AppendUint16(batch, uint16(len(packet)))
		batch = append(batch, packet...)
	}
	return batch
}

type fakeSubscription struct {
	provider *fakeProvider
	events   chan dataplane.TIXTCPFrame
	once     sync.Once
}

func (subscription *fakeSubscription) Events() <-chan dataplane.TIXTCPFrame {
	return subscription.events
}

func (subscription *fakeSubscription) Close() error {
	subscription.once.Do(func() {
		subscription.provider.mu.Lock()
		delete(subscription.provider.subs, subscription.events)
		close(subscription.events)
		subscription.provider.mu.Unlock()
	})
	return nil
}
