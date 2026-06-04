package daemon

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/routing"
)

const defaultControlViewCacheTTL = 250 * time.Millisecond

type controlViewSnapshot struct {
	DataplaneStats    dataplane.Stats
	DataplaneStatsErr error
	DataPath          dataPathStatus
	Routes            []routing.Route
	Peers             []peerStatusResponse
	Runtime           runtimeResourceStatus
	Epoch             uint64
	ExpiresAt         time.Time
}

func (daemon *Daemon) controlViewSnapshot() controlViewSnapshot {
	ttl := controlViewCacheTTL()
	now := time.Now().UTC()
	epoch := daemon.runtimeSnapshotEpoch()
	daemon.controlViewMu.Lock()
	defer daemon.controlViewMu.Unlock()

	cached := daemon.controlView
	if ttl > 0 && cached.Epoch == epoch && !cached.ExpiresAt.IsZero() && now.Before(cached.ExpiresAt) {
		return cached
	}

	stats, statsErr := daemon.dataplane.Stats(context.Background())
	snapshot := controlViewSnapshot{
		DataplaneStats:    stats,
		DataplaneStatsErr: statsErr,
		DataPath:          daemon.dataPathStatusWithStats(stats, statsErr == nil),
		Routes:            daemon.runtimeRoutes(),
		Peers:             daemon.peerStatuses(),
		Runtime:           daemon.runtimeResourceSnapshot(),
		Epoch:             epoch,
	}
	if statsErr == nil && ttl > 0 {
		snapshot.ExpiresAt = now.Add(ttl)
		daemon.controlView = snapshot
	}
	return snapshot
}

func controlViewCacheTTL() time.Duration {
	raw := strings.TrimSpace(os.Getenv("TRUSTIX_CONTROL_VIEW_CACHE_TTL"))
	if raw == "" {
		return defaultControlViewCacheTTL
	}
	if value, err := time.ParseDuration(raw); err == nil {
		if value <= 0 {
			return 0
		}
		return value
	}
	if value, err := strconv.Atoi(raw); err == nil {
		if value <= 0 {
			return 0
		}
		return time.Duration(value) * time.Millisecond
	}
	return defaultControlViewCacheTTL
}
