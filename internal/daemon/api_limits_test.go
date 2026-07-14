package daemon

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAPIProtectionRateLimitsBeforeManagementAuth(t *testing.T) {
	daemon := newOperationalTestDaemon(t)
	daemon.apiRateLimits = testAPIRateLimiters(1)
	handler := daemon.managementHandler(managementAuthOptions{RequireReadAuth: true})

	first := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	first.RemoteAddr = "198.51.100.9:40001"
	firstRecorder := httptest.NewRecorder()
	handler.ServeHTTP(firstRecorder, first)
	if firstRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("first status = %d, want authentication rejection", firstRecorder.Code)
	}

	second := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	second.RemoteAddr = "198.51.100.9:40002"
	secondRecorder := httptest.NewRecorder()
	handler.ServeHTTP(secondRecorder, second)
	if secondRecorder.Code != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want %d; body=%s", secondRecorder.Code, http.StatusTooManyRequests, secondRecorder.Body.String())
	}
	if got := secondRecorder.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q", got)
	}
	if got := daemon.apiRateLimits.deniedCount(apiRateLimitManagementRead); got != 1 {
		t.Fatalf("denied count = %d, want 1", got)
	}
}

func TestAPIProtectionDoesNotTrustForwardedFor(t *testing.T) {
	daemon := newOperationalTestDaemon(t)
	daemon.apiRateLimits = testAPIRateLimiters(1)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := daemon.apiProtectionMiddleware(apiSurfaceManagement, next)

	request := func(remote, forwarded string) int {
		req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
		req.RemoteAddr = remote
		req.Header.Set("X-Forwarded-For", forwarded)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		return recorder.Code
	}
	if got := request("192.0.2.10:41000", "203.0.113.1"); got != http.StatusNoContent {
		t.Fatalf("first status = %d", got)
	}
	if got := request("192.0.2.10:41001", "203.0.113.2"); got != http.StatusTooManyRequests {
		t.Fatalf("same TCP source with different forwarded-for status = %d", got)
	}
	if got := request("192.0.2.11:41000", "203.0.113.1"); got != http.StatusNoContent {
		t.Fatalf("different TCP source status = %d", got)
	}
}

func TestAPIProtectionHealthBypassesOperationalRateLimit(t *testing.T) {
	daemon := newOperationalTestDaemon(t)
	daemon.apiRateLimits = testAPIRateLimiters(1)
	handler := daemon.managementHandler(managementAuthOptions{})
	for i := 0; i < 4; i++ {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.RemoteAddr = "192.0.2.10:42000"
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("health request %d status = %d", i, recorder.Code)
		}
	}

	for i, want := range []int{http.StatusOK, http.StatusTooManyRequests} {
		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		req.RemoteAddr = "192.0.2.10:42000"
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		if recorder.Code != want {
			t.Fatalf("ready request %d status = %d, want %d", i, recorder.Code, want)
		}
	}
}

func TestAPIProtectionUsesSeparateReadWriteBuckets(t *testing.T) {
	daemon := newOperationalTestDaemon(t)
	daemon.apiRateLimits = testAPIRateLimiters(1)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := daemon.apiProtectionMiddleware(apiSurfaceManagement, next)

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req := httptest.NewRequest(method, "/v1/example", nil)
		req.RemoteAddr = "192.0.2.20:43000"
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("%s status = %d", method, recorder.Code)
		}
	}
}

func TestAPIProtectionRejectsDeclaredOversizeBody(t *testing.T) {
	daemon := newOperationalTestDaemon(t)
	nextCalled := false
	handler := daemon.apiProtectionMiddleware(apiSurfaceManagement, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		nextCalled = true
	}))
	req := httptest.NewRequest(http.MethodPost, "/v1/config/validate", strings.NewReader("{}"))
	req.RemoteAddr = "192.0.2.30:44000"
	req.ContentLength = apiDefaultRequestBodyLimit + 1
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusRequestEntityTooLarge, recorder.Body.String())
	}
	if nextCalled {
		t.Fatal("oversize request reached downstream handler")
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
}

func TestAPIProtectionCapsChunkedBody(t *testing.T) {
	daemon := newOperationalTestDaemon(t)
	readErr := make(chan error, 1)
	handler := daemon.apiProtectionMiddleware(apiSurfacePeer, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.Copy(io.Discard, r.Body)
		readErr <- err
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/v1/control/advertisements", io.LimitReader(zeroReader{}, apiDefaultRequestBodyLimit+1))
	req.RemoteAddr = "192.0.2.40:45000"
	req.ContentLength = -1
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if err := <-readErr; err == nil || !strings.Contains(err.Error(), "request body too large") {
		t.Fatalf("chunked oversize read error = %v", err)
	}
}

func TestAPITokenBucketLimiterBoundsClientState(t *testing.T) {
	now := time.Unix(1000, 0)
	limiter := newAPITokenBucketLimiter(apiRateLimitConfig{rate: 1, burst: 1})
	limiter.maxClients = 2
	limiter.now = func() time.Time { return now }
	if !limiter.allow("a") {
		t.Fatal("first client did not receive an initial token")
	}
	now = now.Add(time.Second)
	if !limiter.allow("b") {
		t.Fatal("second client did not receive an initial token")
	}
	now = now.Add(time.Second)
	if !limiter.allow("c") {
		t.Fatal("new clients should receive an initial token")
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if len(limiter.clients) != 2 {
		t.Fatalf("client state size = %d, want 2", len(limiter.clients))
	}
	if _, ok := limiter.clients["a"]; ok {
		t.Fatal("oldest client was not evicted")
	}
}

func TestOperationalMetricsExposeRateLimitRejections(t *testing.T) {
	daemon := newOperationalTestDaemon(t)
	daemon.apiRateLimits = testAPIRateLimiters(1)
	handler := daemon.managementHandler(managementAuthOptions{})

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/v1/not-found", nil)
		req.RemoteAddr = "192.0.2.50:46000"
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "192.0.2.51:46000"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("metrics status = %d; body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `trustix_http_rate_limited_total{scope="management_read"} 1`) {
		t.Fatalf("metrics missing management rejection:\n%s", recorder.Body.String())
	}
}

func TestAPIRateLimitEnvironmentCanDisableScope(t *testing.T) {
	t.Setenv("TRUSTIX_API_READ_RATE", "off")
	limits := newAPIRateLimitersFromEnv()
	for i := 0; i < 100; i++ {
		if !limits.managementRead.allow("192.0.2.60") {
			t.Fatalf("disabled limiter rejected request %d", i)
		}
	}
}

type zeroReader struct{}

func (zeroReader) Read(payload []byte) (int, error) {
	for i := range payload {
		payload[i] = 0
	}
	return len(payload), nil
}

func testAPIRateLimiters(burst int) *apiRateLimiters {
	newLimiter := func() *apiTokenBucketLimiter {
		return newAPITokenBucketLimiter(apiRateLimitConfig{rate: 0.000001, burst: burst})
	}
	return &apiRateLimiters{
		managementRead:  newLimiter(),
		managementWrite: newLimiter(),
		peer:            newLimiter(),
		operational:     newLimiter(),
	}
}
