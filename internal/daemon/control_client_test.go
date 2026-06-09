package daemon

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/transport"
)

func TestControlClientReusesCachedTransport(t *testing.T) {
	t.Setenv("TRUSTIX_CONTROL_CLIENT_CACHE_TTL", "5m")
	daemon := &Daemon{controlClients: make(map[string]*cachedControlClient)}
	target := controlTarget{
		ID:         core.IXID("ix-b"),
		Domain:     core.DomainID("lab.local"),
		ControlAPI: "http://127.0.0.1:19443",
	}

	first, err := daemon.controlClient(target)
	if err != nil {
		t.Fatalf("first control client: %v", err)
	}
	second, err := daemon.controlClient(target)
	if err != nil {
		t.Fatalf("second control client: %v", err)
	}
	if first != second {
		t.Fatal("control client was not reused for the same target")
	}
	if got := len(daemon.controlClients); got != 1 {
		t.Fatalf("cached control clients = %d, want 1", got)
	}
}

func TestControlClientCacheCanBeDisabled(t *testing.T) {
	t.Setenv("TRUSTIX_CONTROL_CLIENT_CACHE_TTL", "0")
	daemon := &Daemon{controlClients: make(map[string]*cachedControlClient)}
	target := controlTarget{
		ID:         core.IXID("ix-b"),
		Domain:     core.DomainID("lab.local"),
		ControlAPI: "http://127.0.0.1:19443",
	}

	first, err := daemon.controlClient(target)
	if err != nil {
		t.Fatalf("first control client: %v", err)
	}
	second, err := daemon.controlClient(target)
	if err != nil {
		t.Fatalf("second control client: %v", err)
	}
	if first == second {
		t.Fatal("control client cache was not disabled")
	}
	if got := len(daemon.controlClients); got != 0 {
		t.Fatalf("cached control clients = %d, want 0", got)
	}
}

func TestControlClientTCPKeepAliveDefaultAndEnv(t *testing.T) {
	t.Setenv("TRUSTIX_CONTROL_CLIENT_TCP_KEEPALIVE", "")
	if got := controlClientTCPKeepAlive(); got != defaultControlClientTCPKeepAlive {
		t.Fatalf("default control client tcp keepalive = %s, want %s", got, defaultControlClientTCPKeepAlive)
	}
	t.Setenv("TRUSTIX_CONTROL_CLIENT_TCP_KEEPALIVE", "45s")
	if got := controlClientTCPKeepAlive(); got != 45*time.Second {
		t.Fatalf("duration control client tcp keepalive = %s, want 45s", got)
	}
	t.Setenv("TRUSTIX_CONTROL_CLIENT_TCP_KEEPALIVE", "2.5")
	if got := controlClientTCPKeepAlive(); got != 2500*time.Millisecond {
		t.Fatalf("numeric control client tcp keepalive = %s, want 2.5s", got)
	}
	t.Setenv("TRUSTIX_CONTROL_CLIENT_TCP_KEEPALIVE", "off")
	if got := controlClientTCPKeepAlive(); got >= 0 {
		t.Fatalf("off control client tcp keepalive = %s, want negative duration", got)
	}
}

func TestServerTCPKeepAliveDefaultAndEnv(t *testing.T) {
	t.Setenv("TRUSTIX_SERVER_TCP_KEEPALIVE", "")
	if got := serverTCPKeepAlive(); got != defaultServerTCPKeepAlive {
		t.Fatalf("default server tcp keepalive = %s, want %s", got, defaultServerTCPKeepAlive)
	}
	t.Setenv("TRUSTIX_SERVER_TCP_KEEPALIVE", "90s")
	if got := serverTCPKeepAlive(); got != 90*time.Second {
		t.Fatalf("duration server tcp keepalive = %s, want 90s", got)
	}
	t.Setenv("TRUSTIX_SERVER_TCP_KEEPALIVE", "off")
	if got := serverTCPKeepAlive(); got >= 0 {
		t.Fatalf("off server tcp keepalive = %s, want negative duration", got)
	}
}

func TestHTTPServersSetResourceTimeouts(t *testing.T) {
	handler := http.NewServeMux()
	management := newManagementHTTPServer(handler)
	if management.ReadHeaderTimeout != managementHTTPReadHeaderTimeout ||
		management.WriteTimeout != managementHTTPWriteTimeout ||
		management.IdleTimeout != managementHTTPIdleTimeout ||
		management.MaxHeaderBytes != httpMaxHeaderBytes {
		t.Fatalf("management server timeouts = read_header:%s write:%s idle:%s max_header:%d",
			management.ReadHeaderTimeout, management.WriteTimeout, management.IdleTimeout, management.MaxHeaderBytes)
	}

	peer := newPeerHTTPServer(handler)
	if peer.ReadHeaderTimeout != peerHTTPReadHeaderTimeout ||
		peer.WriteTimeout != peerHTTPWriteTimeout ||
		peer.IdleTimeout != peerHTTPIdleTimeout ||
		peer.MaxHeaderBytes != httpMaxHeaderBytes {
		t.Fatalf("peer server timeouts = read_header:%s write:%s idle:%s max_header:%d",
			peer.ReadHeaderTimeout, peer.WriteTimeout, peer.IdleTimeout, peer.MaxHeaderBytes)
	}
}

func TestResetControlClientsClearsCache(t *testing.T) {
	t.Setenv("TRUSTIX_CONTROL_CLIENT_CACHE_TTL", "5m")
	daemon := &Daemon{controlClients: make(map[string]*cachedControlClient)}
	target := controlTarget{
		ID:         core.IXID("ix-b"),
		Domain:     core.DomainID("lab.local"),
		ControlAPI: "http://127.0.0.1:19443",
	}

	if _, err := daemon.controlClient(target); err != nil {
		t.Fatalf("control client: %v", err)
	}
	daemon.resetControlClients()
	if got := len(daemon.controlClients); got != 0 {
		t.Fatalf("cached control clients after reset = %d, want 0", got)
	}
}

func TestControlMembersResponseSkipsDuplicateLocalAndUsesETag(t *testing.T) {
	daemon := &Daemon{
		localAd: advertisementResponse{IXID: "ix-a", DomainID: "lab.local"},
		members: map[core.IXID]memberRecord{
			"ix-a": {Advertisement: advertisementResponse{IXID: "ix-a", DomainID: "lab.local"}, LastSeen: time.Now().UTC(), Direct: true},
			"ix-b": {Advertisement: advertisementResponse{IXID: "ix-b", DomainID: "lab.local"}, LastSeen: time.Now().UTC(), Direct: true},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/control/members", nil)
	rec := httptest.NewRecorder()
	daemon.handleControlMembers(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200", rec.Code)
	}
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("members response did not include ETag")
	}
	var response membersResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode members response: %v", err)
	}
	if got := len(response.Members); got != 2 {
		t.Fatalf("members = %d, want local once plus peer", got)
	}
	if response.Members[0].IXID != "ix-a" || response.Members[1].IXID != "ix-b" {
		t.Fatalf("members order = %#v, want ix-a then ix-b", response.Members)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/control/members", nil)
	req.Header.Set("If-None-Match", etag)
	rec = httptest.NewRecorder()
	daemon.handleControlMembers(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Fatalf("second status = %d, want 304", rec.Code)
	}
}

func TestControlMembersResponsePaginatesDirectMembers(t *testing.T) {
	now := time.Now().UTC()
	daemon := &Daemon{
		localAd: advertisementResponse{IXID: "ix-a", DomainID: "lab.local"},
		members: map[core.IXID]memberRecord{
			"ix-b": {Advertisement: advertisementResponse{IXID: "ix-b", DomainID: "lab.local"}, LastSeen: now, Direct: true},
			"ix-c": {Advertisement: advertisementResponse{IXID: "ix-c", DomainID: "lab.local"}, LastSeen: now, Direct: true},
			"ix-d": {Advertisement: advertisementResponse{IXID: "ix-d", DomainID: "lab.local"}, LastSeen: now, Direct: true},
			"ix-e": {Advertisement: advertisementResponse{IXID: "ix-e", DomainID: "lab.local"}, LastSeen: now, Direct: false},
		},
	}

	first := daemon.controlMembersResponse(controlTarget{}, controlMembersPageOptions{Limit: 2})
	if ids := advertisementIDs(first.Members); strings.Join(ids, ",") != "ix-a,ix-b,ix-c" {
		t.Fatalf("first page members = %#v, want local plus ix-b,ix-c", ids)
	}
	if first.NextCursor != "ix-c" || !first.Truncated || first.Total != 4 {
		t.Fatalf("first page metadata = %#v, want next ix-c truncated total 4", first)
	}

	second := daemon.controlMembersResponse(controlTarget{}, controlMembersPageOptions{Cursor: first.NextCursor, Limit: 2})
	if ids := advertisementIDs(second.Members); strings.Join(ids, ",") != "ix-a,ix-d" {
		t.Fatalf("second page members = %#v, want local plus ix-d", ids)
	}
	if second.NextCursor != "" || second.Truncated {
		t.Fatalf("second page metadata = %#v, want final page", second)
	}

	targeted := daemon.controlMembersResponse(controlTarget{ID: "ix-d"}, controlMembersPageOptions{Limit: 1})
	if ids := advertisementIDs(targeted.Members); strings.Join(ids, ",") != "ix-a,ix-d,ix-b" {
		t.Fatalf("targeted page members = %#v, want local plus targeted member plus first page", ids)
	}
	if targeted.NextCursor != "ix-b" || !targeted.Truncated || targeted.Total != 4 {
		t.Fatalf("targeted page metadata = %#v, want next ix-b truncated total 4", targeted)
	}
}

func TestFetchMembersUsesNotModifiedCache(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/v1/control/members" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		if requests == 2 {
			if got := r.Header.Get("If-None-Match"); got != `"members-v1"` {
				t.Fatalf("If-None-Match = %q, want cached ETag", got)
			}
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"members-v1"`)
		_ = json.NewEncoder(w).Encode(membersResponse{
			Members: []advertisementResponse{{IXID: "ix-b", DomainID: "lab.local"}},
		})
	}))
	defer server.Close()

	daemon := &Daemon{}
	target := controlTarget{ID: "ix-b", Domain: "lab.local", ControlAPI: server.URL}
	first, err := daemon.fetchMembers(context.Background(), target)
	if err != nil {
		t.Fatalf("first fetch members: %v", err)
	}
	second, err := daemon.fetchMembers(context.Background(), target)
	if err != nil {
		t.Fatalf("second fetch members: %v", err)
	}
	if len(first) != 1 || len(second) != 1 || second[0].IXID != "ix-b" {
		t.Fatalf("cached members mismatch: first=%#v second=%#v", first, second)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
}

func TestFetchMembersPaginatesAndStoresCursorByImportLimit(t *testing.T) {
	pageSize := 2
	importLimit := 3
	remoteIDs := []string{"ix-b", "ix-c", "ix-d", "ix-e"}
	requests := make([]string, 0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/control/members" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		cursor := r.URL.Query().Get("cursor")
		limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
		if err != nil {
			t.Fatalf("parse limit: %v", err)
		}
		requests = append(requests, cursor+":"+strconv.Itoa(limit))
		start := sort.Search(len(remoteIDs), func(index int) bool {
			return remoteIDs[index] > cursor
		})
		response := membersResponse{
			Members: []advertisementResponse{{IXID: "ix-reflector", DomainID: "lab.local"}},
			Limit:   limit,
			Total:   len(remoteIDs) + 1,
		}
		added := 0
		last := ""
		for _, ixID := range remoteIDs[start:] {
			if limit > 0 && added >= limit {
				break
			}
			response.Members = append(response.Members, advertisementResponse{IXID: ixID, DomainID: "lab.local"})
			added++
			last = ixID
		}
		if limit > 0 && start+added < len(remoteIDs) && last != "" {
			response.NextCursor = last
			response.Truncated = true
		}
		w.Header().Set("ETag", `"`+cursor+":"+strconv.Itoa(limit)+`"`)
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	daemon := &Daemon{
		desired: config.Desired{ControlFabric: config.ControlFabricConfig{
			MemberPageSize:    &pageSize,
			MemberImportLimit: &importLimit,
		}},
	}
	target := controlTarget{ID: "ix-reflector", Domain: "lab.local", ControlAPI: server.URL}
	first, err := daemon.fetchMembers(context.Background(), target)
	if err != nil {
		t.Fatalf("first fetch members: %v", err)
	}
	if ids := advertisementIDs(first); strings.Join(ids, ",") != "ix-reflector,ix-b,ix-c,ix-d" {
		t.Fatalf("first fetch members = %#v, want reflector plus first 3 remote members", ids)
	}
	if cursor := daemon.controlMemberCursor(controlClientCacheKey(target)); cursor != "ix-d" {
		t.Fatalf("stored cursor after first fetch = %q, want ix-d", cursor)
	}

	second, err := daemon.fetchMembers(context.Background(), target)
	if err != nil {
		t.Fatalf("second fetch members: %v", err)
	}
	if ids := advertisementIDs(second); strings.Join(ids, ",") != "ix-reflector,ix-e" {
		t.Fatalf("second fetch members = %#v, want reflector plus ix-e", ids)
	}
	if cursor := daemon.controlMemberCursor(controlClientCacheKey(target)); cursor != "" {
		t.Fatalf("stored cursor after second fetch = %q, want empty", cursor)
	}
	if got := strings.Join(requests, ","); got != ":2,ix-c:1,ix-d:2" {
		t.Fatalf("requests = %q, want :2,ix-c:1,ix-d:2", got)
	}
}

func advertisementIDs(advertisements []advertisementResponse) []string {
	ids := make([]string, 0, len(advertisements))
	for _, advertisement := range advertisements {
		ids = append(ids, advertisement.IXID)
	}
	return ids
}

func TestAdvertisementPushSkipsUnchangedUntilInterval(t *testing.T) {
	t.Setenv("TRUSTIX_ADVERTISEMENT_PUSH_INTERVAL", "1h")
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	daemon := &Daemon{
		localAd: advertisementResponse{IXID: "ix-a", DomainID: "lab.local", IssuedAt: time.Unix(1, 0).UTC()},
	}
	target := controlTarget{ID: "ix-b", Domain: "lab.local", ControlAPI: server.URL}
	if err := daemon.pushLocalAdvertisement(context.Background(), target); err != nil {
		t.Fatalf("first push: %v", err)
	}
	if err := daemon.pushLocalAdvertisement(context.Background(), target); err != nil {
		t.Fatalf("second push: %v", err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want unchanged advertisement pushed once", requests)
	}
}

func TestControlAdvertisementPostSchedulesRouteWarmup(t *testing.T) {
	pkiSet := buildMembershipPKI(t)
	desiredA := desiredForMembershipTest(pkiSet, "ix-a", "127.0.0.1:7001", "https://127.0.0.1:9443", "10.0.0.0/24")
	desiredA.TransportPolicy = config.TransportPolicyConfig{
		Encryption:  "plaintext",
		SessionPool: config.SessionPoolPolicyConfig{Warmup: true},
	}
	daemonA := newMembershipTestDaemon(t, desiredA, 1)
	authorizeMembershipTestIX(t, daemonA, pkiSet, "ix-c", "10.0.2.0/24")
	fake := newWarmupSignalTransport(transport.ProtocolUDP)
	registry := transport.NewRegistry()
	if err := registry.Register(fake); err != nil {
		t.Fatalf("register warmup transport: %v", err)
	}
	daemonA.transports = registry
	daemonA.dataMu.Lock()
	daemonA.dataPathStarted = true
	daemonA.dataMu.Unlock()

	daemonC := newMembershipTestDaemon(t, desiredForMembershipTest(pkiSet, "ix-c", "127.0.0.1:7003", "https://127.0.0.1:9445", "10.0.2.0/24"), 2)
	advertisement, err := daemonC.buildLocalAdvertisement()
	if err != nil {
		t.Fatalf("build ix-c advertisement: %v", err)
	}
	payload, err := json.Marshal(advertisement)
	if err != nil {
		t.Fatalf("marshal advertisement: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/control/advertisements", bytes.NewReader(payload))
	recorder := httptest.NewRecorder()
	daemonA.handleControlAdvertisementPost(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("advertisement post status = %d body=%s", recorder.Code, recorder.Body.String())
	}

	select {
	case <-fake.dialed:
	case <-time.After(time.Second):
		t.Fatal("control advertisement post did not schedule route warmup")
	}
	if got := fake.dialCount(); got == 0 {
		t.Fatal("warmup transport was not dialed")
	}
	daemonA.dataMu.Lock()
	defer daemonA.dataMu.Unlock()
	for key := range daemonA.dataSessions {
		if key.Peer == "ix-c" && key.Endpoint == "ix-c-udp" {
			return
		}
	}
	t.Fatalf("warmup session for ix-c was not registered: %#v", daemonA.dataSessions)
}

type warmupSignalTransport struct {
	name   transport.Protocol
	mu     sync.Mutex
	dials  int
	dialed chan struct{}
}

func newWarmupSignalTransport(name transport.Protocol) *warmupSignalTransport {
	return &warmupSignalTransport{name: name, dialed: make(chan struct{}, 1)}
}

func (fake *warmupSignalTransport) Name() transport.Protocol {
	return fake.name
}

func (fake *warmupSignalTransport) Probe(ctx context.Context, peer transport.Peer) transport.ProbeResult {
	return transport.ProbeResult{}
}

func (fake *warmupSignalTransport) Dial(ctx context.Context, peer transport.Peer, tlsConf *tls.Config) (transport.Session, error) {
	fake.mu.Lock()
	fake.dials++
	fake.mu.Unlock()
	select {
	case fake.dialed <- struct{}{}:
	default:
	}
	encryption := ""
	if len(peer.Endpoints) > 0 {
		encryption = peer.Endpoints[0].Encryption
	}
	return &statsSession{stats: transport.TransportStats{
		Datagram:        true,
		Encryption:      encryption,
		CryptoPlacement: "userspace",
		MaxPacketSize:   65536,
		NativeBatching:  true,
	}}, nil
}

func (fake *warmupSignalTransport) Listen(ctx context.Context, ep transport.Endpoint, tlsConf *tls.Config) (transport.Listener, error) {
	return nil, errors.New("unexpected warmup signal transport listen")
}

func (fake *warmupSignalTransport) dialCount() int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.dials
}
