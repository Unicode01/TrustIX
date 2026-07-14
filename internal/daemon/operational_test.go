package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/observability"
)

func TestOperationalReadinessBypassesManagementAuthWhenReady(t *testing.T) {
	daemon := newOperationalTestDaemon(t)
	handler := daemon.managementHandler(managementAuthOptions{
		RequireReadAuth:  true,
		RequireWriteAuth: true,
	})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("ready status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var response readinessResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode readiness: %v", err)
	}
	if !response.Ready || response.Status != "ready" {
		t.Fatalf("readiness = %#v", response)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache control = %q", got)
	}
}

func TestOperationalReadinessRejectsIncompleteRuntime(t *testing.T) {
	daemon := newOperationalTestDaemon(t)
	daemon.dataMu.Lock()
	daemon.dataPathStarted = false
	daemon.dataMu.Unlock()
	daemon.cfg.DataDir = t.TempDir()

	recorder := httptest.NewRecorder()
	daemon.managementHandler(managementAuthOptions{}).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("not-ready status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var response readinessResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode readiness: %v", err)
	}
	if response.Ready || response.Status != "not_ready" {
		t.Fatalf("readiness = %#v", response)
	}
	wantFailed := map[string]bool{"data_dir_lock": true, "data_path": true}
	for _, check := range response.Checks {
		if !check.Ready {
			delete(wantFailed, check.Name)
		}
	}
	if len(wantFailed) != 0 {
		t.Fatalf("missing failed readiness checks: %#v; response=%#v", wantFailed, response)
	}
}

func TestOperationalMetricsExposeStableCoreCounters(t *testing.T) {
	daemon := newOperationalTestDaemon(t)
	daemon.dataStats.packetsSent.Store(7)
	daemon.dataStats.packetsReceived.Store(9)
	daemon.dataStats.sendErrors.Store(2)
	daemon.dataStats.dropMu.Lock()
	daemon.dataStats.dropReasons = map[observability.DropReason]uint64{
		observability.DropNoRoute: 3,
	}
	daemon.dataStats.dropMu.Unlock()

	recorder := httptest.NewRecorder()
	daemon.managementHandler(managementAuthOptions{RequireReadAuth: true}).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Type"); got != prometheusContentType {
		t.Fatalf("metrics content type = %q", got)
	}
	body := recorder.Body.String()
	for _, want := range []string{
		"trustix_ready 1",
		"trustix_dataplane_attached 1",
		"trustix_data_packets_sent_total 7",
		"trustix_data_packets_received_total 9",
		"trustix_data_send_errors_total 2",
		"trustix_data_path_drops_total{reason=\"NO_ROUTE\"} 3",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics missing %q:\n%s", want, body)
		}
	}
}

func TestOperationalEndpointsRejectMutationMethods(t *testing.T) {
	daemon := newOperationalTestDaemon(t)
	for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
		recorder := httptest.NewRecorder()
		daemon.managementHandler(managementAuthOptions{}).ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, nil))
		if recorder.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST %s status = %d", path, recorder.Code)
		}
		if got := recorder.Header().Get("Allow"); got != "GET, HEAD" {
			t.Fatalf("POST %s Allow = %q", path, got)
		}
	}
}

func TestPrometheusEscapeLabel(t *testing.T) {
	if got, want := prometheusEscapeLabel("a\\b\n\"c"), "a\\\\b\\n\\\"c"; got != want {
		t.Fatalf("escaped label = %q, want %q", got, want)
	}
}

func newOperationalTestDaemon(t *testing.T) *Daemon {
	t.Helper()
	manager := dataplane.NewNoopManager()
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("load noop dataplane: %v", err)
	}
	if err := manager.Attach(context.Background(), dataplane.AttachSpec{}); err != nil {
		t.Fatalf("attach noop dataplane: %v", err)
	}
	daemon, err := New(Config{DataplaneMode: "noop"}, WithDataplane(manager))
	if err != nil {
		t.Fatalf("new daemon: %v", err)
	}
	daemon.configMu.Lock()
	daemon.desired = config.Desired{
		Domain: config.DomainConfig{ID: core.DomainID("lab.local")},
		IX:     config.IXConfig{ID: core.IXID("ix-a")},
	}
	daemon.logPath = "/tmp/config.log"
	daemon.head.Seq = 4
	daemon.startedAt = time.Now().Add(-time.Minute)
	daemon.configMu.Unlock()
	daemon.dataMu.Lock()
	daemon.dataPathStarted = true
	daemon.dataMu.Unlock()
	return daemon
}
