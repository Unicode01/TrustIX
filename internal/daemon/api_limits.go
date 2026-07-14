package daemon

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	apiDefaultRequestBodyLimit = int64(maxConfigEventsBytes)
	apiRateLimitMaxClients     = 4096
	apiRateLimitClientIdleTTL  = 10 * time.Minute
)

type apiSurface uint8

const (
	apiSurfaceManagement apiSurface = iota
	apiSurfacePeer
)

type apiRateLimitScope string

const (
	apiRateLimitManagementRead  apiRateLimitScope = "management_read"
	apiRateLimitManagementWrite apiRateLimitScope = "management_write"
	apiRateLimitPeer            apiRateLimitScope = "peer"
	apiRateLimitOperational     apiRateLimitScope = "operational"
)

var apiRateLimitScopes = []apiRateLimitScope{
	apiRateLimitManagementRead,
	apiRateLimitManagementWrite,
	apiRateLimitPeer,
	apiRateLimitOperational,
}

type apiRateLimiters struct {
	managementRead  *apiTokenBucketLimiter
	managementWrite *apiTokenBucketLimiter
	peer            *apiTokenBucketLimiter
	operational     *apiTokenBucketLimiter
}

type apiTokenBucketLimiter struct {
	mu         sync.Mutex
	rate       float64
	burst      float64
	maxClients int
	idleTTL    time.Duration
	now        func() time.Time
	clients    map[string]*apiTokenBucketClient
	lastSweep  time.Time
	denied     atomic.Uint64
}

type apiTokenBucketClient struct {
	tokens float64
	last   time.Time
}

func newAPIRateLimitersFromEnv() *apiRateLimiters {
	return &apiRateLimiters{
		managementRead: newAPITokenBucketLimiter(apiRateLimitConfigFromEnv(
			"TRUSTIX_API_READ_RATE", "TRUSTIX_API_READ_BURST", 120, 240,
		)),
		managementWrite: newAPITokenBucketLimiter(apiRateLimitConfigFromEnv(
			"TRUSTIX_API_WRITE_RATE", "TRUSTIX_API_WRITE_BURST", 20, 40,
		)),
		peer: newAPITokenBucketLimiter(apiRateLimitConfigFromEnv(
			"TRUSTIX_PEER_API_RATE", "TRUSTIX_PEER_API_BURST", 240, 480,
		)),
		operational: newAPITokenBucketLimiter(apiRateLimitConfigFromEnv(
			"TRUSTIX_OPERATIONAL_API_RATE", "TRUSTIX_OPERATIONAL_API_BURST", 20, 40,
		)),
	}
}

type apiRateLimitConfig struct {
	rate  float64
	burst int
}

func apiRateLimitConfigFromEnv(rateName, burstName string, defaultRate float64, defaultBurst int) apiRateLimitConfig {
	rate := apiPositiveFloatEnv(rateName, defaultRate)
	burst := apiPositiveIntEnv(burstName, defaultBurst)
	if rate == 0 || burst == 0 {
		return apiRateLimitConfig{}
	}
	return apiRateLimitConfig{rate: rate, burst: burst}
}

func apiPositiveFloatEnv(name string, fallback float64) float64 {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	if raw == "" {
		return fallback
	}
	if raw == "0" || raw == "off" || raw == "disabled" {
		return 0
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || value <= 0 || math.IsInf(value, 0) || math.IsNaN(value) {
		return fallback
	}
	return value
}

func apiPositiveIntEnv(name string, fallback int) int {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	if raw == "" {
		return fallback
	}
	if raw == "0" || raw == "off" || raw == "disabled" {
		return 0
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func newAPITokenBucketLimiter(config apiRateLimitConfig) *apiTokenBucketLimiter {
	return &apiTokenBucketLimiter{
		rate:       config.rate,
		burst:      float64(config.burst),
		maxClients: apiRateLimitMaxClients,
		idleTTL:    apiRateLimitClientIdleTTL,
		now:        time.Now,
		clients:    make(map[string]*apiTokenBucketClient),
	}
}

func (limiter *apiTokenBucketLimiter) allow(client string) bool {
	if limiter == nil || limiter.rate <= 0 || limiter.burst <= 0 {
		return true
	}
	now := limiter.now()
	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	limiter.sweepLocked(now)
	bucket := limiter.clients[client]
	if bucket == nil {
		if len(limiter.clients) >= limiter.maxClients {
			limiter.evictOldestLocked()
		}
		bucket = &apiTokenBucketClient{tokens: limiter.burst, last: now}
		limiter.clients[client] = bucket
	} else if elapsed := now.Sub(bucket.last).Seconds(); elapsed > 0 {
		bucket.tokens = math.Min(limiter.burst, bucket.tokens+elapsed*limiter.rate)
		bucket.last = now
	}
	if bucket.tokens >= 1 {
		bucket.tokens--
		return true
	}
	limiter.denied.Add(1)
	return false
}

func (limiter *apiTokenBucketLimiter) sweepLocked(now time.Time) {
	if limiter.idleTTL <= 0 || !limiter.lastSweep.IsZero() && now.Sub(limiter.lastSweep) < time.Minute {
		return
	}
	cutoff := now.Add(-limiter.idleTTL)
	for client, bucket := range limiter.clients {
		if bucket.last.Before(cutoff) {
			delete(limiter.clients, client)
		}
	}
	limiter.lastSweep = now
}

func (limiter *apiTokenBucketLimiter) evictOldestLocked() {
	var oldestClient string
	var oldest time.Time
	for client, bucket := range limiter.clients {
		if oldestClient == "" || bucket.last.Before(oldest) {
			oldestClient = client
			oldest = bucket.last
		}
	}
	if oldestClient != "" {
		delete(limiter.clients, oldestClient)
	}
}

func (limits *apiRateLimiters) limiter(scope apiRateLimitScope) *apiTokenBucketLimiter {
	if limits == nil {
		return nil
	}
	switch scope {
	case apiRateLimitManagementRead:
		return limits.managementRead
	case apiRateLimitManagementWrite:
		return limits.managementWrite
	case apiRateLimitPeer:
		return limits.peer
	case apiRateLimitOperational:
		return limits.operational
	default:
		return nil
	}
}

func (limits *apiRateLimiters) deniedCount(scope apiRateLimitScope) uint64 {
	limiter := limits.limiter(scope)
	if limiter == nil {
		return 0
	}
	return limiter.denied.Load()
}

func (daemon *Daemon) apiProtectionMiddleware(surface apiSurface, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scope, limited := apiRequestRateLimitScope(surface, r)
		if limited {
			limiter := daemon.apiRateLimits.limiter(scope)
			if limiter != nil && !limiter.allow(apiRemoteClientKey(r.RemoteAddr)) {
				setHTTPResponseSecurityHeaders(w)
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("Retry-After", "1")
				writeError(w, http.StatusTooManyRequests, fmt.Errorf("request rate limit exceeded"))
				return
			}
		}

		limit := apiRequestBodyLimit(surface, r)
		if r.ContentLength > limit {
			setHTTPResponseSecurityHeaders(w)
			w.Header().Set("Cache-Control", "no-store")
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Errorf("request body exceeds %d bytes", limit))
			return
		}
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}

func apiRequestRateLimitScope(surface apiSurface, r *http.Request) (apiRateLimitScope, bool) {
	if surface == apiSurfacePeer {
		return apiRateLimitPeer, true
	}
	switch r.URL.Path {
	case "/healthz":
		return "", false
	case "/readyz", "/metrics":
		return apiRateLimitOperational, true
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return apiRateLimitManagementRead, true
	default:
		return apiRateLimitManagementWrite, true
	}
}

func apiRequestBodyLimit(surface apiSurface, r *http.Request) int64 {
	if surface == apiSurfaceManagement && r.Method == http.MethodPost && (r.URL.Path == "/v1/config/restore-archive" || r.URL.Path == "/v1/config/validate-archive") {
		return maxConfigRestoreArchiveBytes
	}
	return apiDefaultRequestBodyLimit
}

func apiRemoteClientKey(remoteAddr string) string {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return normalizeAPIClientHost(host)
	}
	return normalizeAPIClientHost(remoteAddr)
}

func normalizeAPIClientHost(host string) string {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Unmap().String()
	}
	if host == "" {
		return "unknown"
	}
	return strings.ToLower(host)
}
