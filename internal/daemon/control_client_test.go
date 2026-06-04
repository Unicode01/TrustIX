package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trustix.local/trustix/internal/core"
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
