package daemon

import (
	"context"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/configlog"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
)

const defaultPeerPollInterval = 30 * time.Second

type advertisementResponse struct {
	DomainID            string                       `json:"domain_id"`
	IXID                string                       `json:"ix_id"`
	ConfigHead          headResponse                 `json:"config_head"`
	ControlAPI          string                       `json:"control_api,omitempty"`
	Management          *managementAdvertisement     `json:"management,omitempty"`
	LANPrefixes         []string                     `json:"lan_prefixes"`
	AnnouncedPrefixes   []announcedPrefix            `json:"announced_prefixes,omitempty"`
	Endpoints           []dataplane.EndpointMetadata `json:"endpoints"`
	IXCertificate       []byte                       `json:"ix_certificate,omitempty"`
	RouteAuthorizations [][]byte                     `json:"route_authorizations,omitempty"`
	IssuedAt            time.Time                    `json:"issued_at,omitempty"`
	Signature           []byte                       `json:"signature,omitempty"`
}

type announcedPrefix struct {
	Prefix    core.Prefix `json:"prefix"`
	OriginIX  core.IXID   `json:"origin_ix,omitempty"`
	NextHopIX core.IXID   `json:"next_hop_ix,omitempty"`
	Source    string      `json:"source,omitempty"`
	Metric    int         `json:"metric,omitempty"`
	Path      []core.IXID `json:"path,omitempty"`
}

type managementAdvertisement struct {
	HostAPI *hostAPIAdvertisement `json:"host_api,omitempty"`
}

type hostAPIAdvertisement struct {
	IP        string `json:"ip,omitempty"`
	Port      string `json:"port,omitempty"`
	ReadAuth  bool   `json:"read_auth"`
	WriteAuth bool   `json:"write_auth"`
}

type peerRuntime struct {
	Healthy       bool                  `json:"healthy"`
	LastSeen      time.Time             `json:"last_seen,omitempty"`
	LastError     string                `json:"last_error,omitempty"`
	Advertisement advertisementResponse `json:"advertisement,omitempty"`
}

type peerStatusResponse struct {
	Config  config.PeerConfig `json:"config"`
	Runtime peerRuntime       `json:"runtime"`
}

func (daemon *Daemon) peerPoller(ctx context.Context) {
	daemon.pollPeers(ctx)
	ticker := time.NewTicker(peerPollInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			daemon.pollPeers(ctx)
		}
	}
}

func peerPollInterval() time.Duration {
	raw := strings.TrimSpace(os.Getenv("TRUSTIX_PEER_POLL_INTERVAL"))
	if raw == "" {
		return defaultPeerPollInterval
	}
	if seconds, err := strconv.ParseFloat(raw, 64); err == nil && seconds > 0 {
		return time.Duration(seconds * float64(time.Second))
	}
	if interval, err := time.ParseDuration(raw); err == nil && interval > 0 {
		return interval
	}
	return defaultPeerPollInterval
}

func (daemon *Daemon) pollPeers(ctx context.Context) {
	changed := false
	for _, target := range daemon.controlTargets() {
		if err := daemon.pushLocalAdvertisement(ctx, target); err != nil && target.Static {
			daemon.recordPeerError(target.ID, err.Error())
		} else if err != nil {
			daemon.recordConfigSync(target, "error", configlog.Head{}, 0, 0, err)
		}
		advertisements, err := daemon.fetchMembers(ctx, target)
		if err != nil {
			if target.Static {
				daemon.recordPeerError(target.ID, err.Error())
			} else {
				daemon.recordConfigSync(target, "error", configlog.Head{}, 0, 0, err)
			}
			continue
		}
		var targetAdvertisement *advertisementResponse
		for _, advertisement := range advertisements {
			if advertisementMatchesControlTarget(advertisement, target) {
				copyAdvertisement := advertisement
				targetAdvertisement = &copyAdvertisement
			}
			direct := advertisementMatchesControlTarget(advertisement, target)
			merged, err := daemon.mergeAdvertisementFromControlTarget(advertisement, target)
			if err != nil {
				if target.Static {
					daemon.recordPeerError(target.ID, err.Error())
				}
				continue
			}
			if merged {
				changed = true
			}
			if direct {
				ixID := core.IXID(advertisement.IXID)
				daemon.peerMu.Lock()
				daemon.peerState[ixID] = peerRuntime{
					Healthy:       true,
					LastSeen:      time.Now().UTC(),
					Advertisement: advertisement,
				}
				daemon.peerMu.Unlock()
			}
		}
		var syncErr error
		if targetAdvertisement != nil {
			syncErr = daemon.syncConfigLogWithAdvertisement(ctx, target, *targetAdvertisement)
		} else {
			syncErr = daemon.syncConfigLogWithTarget(ctx, target)
		}
		if syncErr != nil {
			continue
		}
	}
	if daemon.pruneExpiredMembers() {
		changed = true
	}
	if changed {
		if err := daemon.applyRuntimeDataplaneSnapshot(ctx); err != nil {
			for _, target := range daemon.controlTargets() {
				if target.Static {
					daemon.recordPeerError(target.ID, err.Error())
				}
			}
		} else {
			daemon.scheduleRuntimeRouteWarmup(ctx)
		}
	}
}

func advertisementMatchesControlTarget(advertisement advertisementResponse, target controlTarget) bool {
	if target.ID != "" && core.IXID(advertisement.IXID) == target.ID {
		return true
	}
	return strings.TrimSpace(advertisement.ControlAPI) != "" &&
		strings.TrimSpace(advertisement.ControlAPI) == strings.TrimSpace(target.ControlAPI)
}

func (daemon *Daemon) recordPeerError(peer core.IXID, message string) {
	daemon.peerMu.Lock()
	defer daemon.peerMu.Unlock()
	current := daemon.peerState[peer]
	current.Healthy = false
	current.LastError = message
	daemon.peerState[peer] = current
}

func (daemon *Daemon) peerStatuses() []peerStatusResponse {
	daemon.peerMu.RLock()
	defer daemon.peerMu.RUnlock()

	statuses := make([]peerStatusResponse, 0, len(daemon.desired.Peers))
	seen := make(map[core.IXID]struct{}, len(daemon.desired.Peers))
	for _, peer := range daemon.desired.Peers {
		seen[peer.ID] = struct{}{}
		daemon.membershipMu.RLock()
		record, dynamic := daemon.members[peer.ID]
		daemon.membershipMu.RUnlock()
		if dynamic {
			peer = daemon.mergeStaticPeerWithAdvertisement(peer, record.Advertisement)
		}
		statuses = append(statuses, peerStatusResponse{
			Config:  peer,
			Runtime: daemon.peerState[peer.ID],
		})
	}
	daemon.membershipMu.RLock()
	dynamicIDs := make([]string, 0, len(daemon.members))
	for ixID := range daemon.members {
		if ixID == daemon.desired.IX.ID {
			continue
		}
		if _, exists := seen[ixID]; exists {
			continue
		}
		dynamicIDs = append(dynamicIDs, string(ixID))
	}
	sort.Strings(dynamicIDs)
	for _, rawID := range dynamicIDs {
		ixID := core.IXID(rawID)
		statuses = append(statuses, peerStatusResponse{
			Config:  daemon.peerConfigFromAdvertisement(daemon.members[ixID].Advertisement),
			Runtime: daemon.peerState[ixID],
		})
	}
	daemon.membershipMu.RUnlock()
	return statuses
}
