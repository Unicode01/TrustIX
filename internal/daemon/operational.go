package daemon

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"trustix.local/trustix/internal/observability"
)

const prometheusContentType = "text/plain; version=0.0.4; charset=utf-8"

type readinessCheck struct {
	Name   string `json:"name"`
	Ready  bool   `json:"ready"`
	Detail string `json:"detail,omitempty"`
}

type readinessResponse struct {
	Status string           `json:"status"`
	Ready  bool             `json:"ready"`
	Checks []readinessCheck `json:"checks"`
}

func (daemon *Daemon) serveOperationalEndpoint(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/healthz":
		if !operationalMethodAllowed(w, r) {
			return true
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, struct {
			Status string `json:"status"`
		}{Status: "ok"})
		return true
	case "/readyz":
		if !operationalMethodAllowed(w, r) {
			return true
		}
		response, _ := daemon.readinessSnapshot()
		status := http.StatusOK
		if !response.Ready {
			status = http.StatusServiceUnavailable
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, status, response)
		return true
	case "/metrics":
		if !operationalMethodAllowed(w, r) {
			return true
		}
		daemon.handlePrometheusMetrics(w)
		return true
	default:
		return false
	}
}

func operationalMethodAllowed(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	w.Header().Set("Allow", "GET, HEAD")
	writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method %s is not allowed", r.Method))
	return false
}

func (daemon *Daemon) readinessSnapshot() (readinessResponse, controlViewSnapshot) {
	view := daemon.controlViewSnapshot()

	daemon.configMu.RLock()
	configLoaded := daemon.desired.Domain.ID != "" && daemon.desired.IX.ID != "" && daemon.logPath != ""
	dataDirRequired := strings.TrimSpace(daemon.cfg.DataDir) != ""
	daemon.configMu.RUnlock()

	runContextReady := true
	if done := daemon.runCtxDone(); done != nil {
		select {
		case <-done:
			runContextReady = false
		default:
		}
	}

	checks := []readinessCheck{
		{Name: "config", Ready: configLoaded},
		{Name: "data_dir_lock", Ready: !dataDirRequired || view.Runtime.DataDirLockHeld},
		{Name: "dataplane", Ready: view.DataplaneStatsErr == nil},
		{Name: "data_path", Ready: daemon.dataPathIsStarted()},
		{Name: "run_context", Ready: runContextReady},
	}
	if view.DataplaneStatsErr != nil {
		checks[2].Detail = view.DataplaneStatsErr.Error()
	}
	ready := true
	for _, check := range checks {
		if !check.Ready {
			ready = false
			break
		}
	}
	status := "ready"
	if !ready {
		status = "not_ready"
	}
	return readinessResponse{Status: status, Ready: ready, Checks: checks}, view
}

func (daemon *Daemon) handlePrometheusMetrics(w http.ResponseWriter) {
	readiness, view := daemon.readinessSnapshot()

	daemon.configMu.RLock()
	configuredPeers := len(daemon.desired.Peers)
	configHeadSeq := daemon.head.Seq
	startedAt := daemon.startedAt
	daemon.configMu.RUnlock()

	healthyPeers := 0
	for _, peer := range view.Peers {
		if peer.Runtime.Healthy {
			healthyPeers++
		}
	}
	uptime := 0.0
	if !startedAt.IsZero() {
		uptime = time.Since(startedAt).Seconds()
		if uptime < 0 {
			uptime = 0
		}
	}

	var output strings.Builder
	writePrometheusMetric(&output, "trustix_ready", "Whether the daemon is ready to serve configured traffic.", "gauge", boolMetric(readiness.Ready))
	writePrometheusMetric(&output, "trustix_uptime_seconds", "Daemon uptime in seconds.", "gauge", uptime)
	writePrometheusMetric(&output, "trustix_config_head_sequence", "Current signed configuration log sequence.", "gauge", float64(configHeadSeq))
	writePrometheusMetric(&output, "trustix_routes", "Current runtime route count.", "gauge", float64(len(view.Routes)))
	writePrometheusMetric(&output, "trustix_peers_configured", "Configured peer count.", "gauge", float64(configuredPeers))
	writePrometheusMetric(&output, "trustix_peers_healthy", "Healthy peer count.", "gauge", float64(healthyPeers))
	writePrometheusMetric(&output, "trustix_data_sessions_active", "Active data session count.", "gauge", float64(view.DataPath.ActiveSessions))
	writePrometheusMetric(&output, "trustix_dataplane_epoch", "Current dataplane snapshot epoch.", "gauge", float64(view.DataplaneStats.Epoch))
	writePrometheusMetric(&output, "trustix_dataplane_attached", "Whether the selected dataplane is attached.", "gauge", boolMetric(view.DataplaneStats.Attached))
	writePrometheusMetric(&output, "trustix_dataplane_collection_error", "Whether dataplane statistics collection failed.", "gauge", boolMetric(view.DataplaneStatsErr != nil))
	writePrometheusMetric(&output, "trustix_runtime_goroutines", "Current Go goroutine count.", "gauge", float64(view.Runtime.Goroutines))
	writePrometheusMetric(&output, "trustix_runtime_heap_alloc_bytes", "Current allocated Go heap bytes.", "gauge", float64(view.Runtime.GoHeapAllocBytes))
	writePrometheusMetric(&output, "trustix_runtime_sys_bytes", "Current Go runtime system bytes.", "gauge", float64(view.Runtime.GoSysBytes))
	writePrometheusMetric(&output, "trustix_runtime_rss_bytes", "Current resident set size in bytes.", "gauge", float64(view.Runtime.RSSBytes))
	writePrometheusMetric(&output, "trustix_runtime_open_fds", "Current open file descriptor count.", "gauge", float64(view.Runtime.OpenFDs))

	writePrometheusMetric(&output, "trustix_data_packets_sent_total", "Data packets sent by the daemon.", "counter", float64(view.DataPath.Counters.PacketsSent))
	writePrometheusMetric(&output, "trustix_data_packets_received_total", "Data packets received by the daemon.", "counter", float64(view.DataPath.Counters.PacketsReceived))
	writePrometheusMetric(&output, "trustix_data_send_errors_total", "Data packet send errors.", "counter", float64(view.DataPath.Counters.SendErrors))
	writePrometheusMetric(&output, "trustix_data_receive_errors_total", "Data packet receive errors.", "counter", float64(view.DataPath.Counters.ReceiveErrors))
	writePrometheusMetric(&output, "trustix_data_inject_errors_total", "LAN packet injection errors.", "counter", float64(view.DataPath.Counters.InjectErrors))

	output.WriteString("# HELP trustix_http_rate_limited_total HTTP requests rejected by the per-client rate limiter.\n")
	output.WriteString("# TYPE trustix_http_rate_limited_total counter\n")
	for _, scope := range apiRateLimitScopes {
		fmt.Fprintf(&output, "trustix_http_rate_limited_total{scope=\"%s\"} %d\n", scope, daemon.apiRateLimits.deniedCount(scope))
	}

	counters := append([]observability.Counter(nil), view.DataplaneStats.Counters...)
	sort.Slice(counters, func(i, j int) bool { return counters[i].Name < counters[j].Name })
	if len(counters) > 0 {
		output.WriteString("# HELP trustix_dataplane_counter_total Low-level dataplane counters by counter name.\n")
		output.WriteString("# TYPE trustix_dataplane_counter_total counter\n")
		for _, counter := range counters {
			fmt.Fprintf(&output, "trustix_dataplane_counter_total{counter=\"%s\"} %d\n", prometheusEscapeLabel(counter.Name), counter.Value)
		}
	}
	writePrometheusDropMetrics(&output, "trustix_dataplane_drops_total", "Low-level dataplane drops by reason.", view.DataplaneStats.DropReasons)
	writePrometheusDropMetrics(&output, "trustix_data_path_drops_total", "Daemon data-path drops by reason.", view.DataPath.DropReasons)

	setHTTPResponseSecurityHeaders(w)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", prometheusContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(output.String()))
}

func writePrometheusMetric(output *strings.Builder, name, help, metricType string, value float64) {
	fmt.Fprintf(output, "# HELP %s %s\n", name, help)
	fmt.Fprintf(output, "# TYPE %s %s\n", name, metricType)
	fmt.Fprintf(output, "%s %g\n", name, value)
}

func writePrometheusDropMetrics(output *strings.Builder, name, help string, values map[observability.DropReason]uint64) {
	if len(values) == 0 {
		return
	}
	reasons := make([]string, 0, len(values))
	for reason := range values {
		reasons = append(reasons, string(reason))
	}
	sort.Strings(reasons)
	fmt.Fprintf(output, "# HELP %s %s\n", name, help)
	fmt.Fprintf(output, "# TYPE %s counter\n", name)
	for _, reason := range reasons {
		fmt.Fprintf(output, "%s{reason=\"%s\"} %d\n", name, prometheusEscapeLabel(reason), values[observability.DropReason(reason)])
	}
}

func boolMetric(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func prometheusEscapeLabel(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	return strings.ReplaceAll(value, "\"", "\\\"")
}
