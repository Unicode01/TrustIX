package daemon

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"trustix.local/trustix/internal/buildassets"
	"trustix.local/trustix/internal/buildinfo"
	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/kernelmodule"
	"trustix.local/trustix/internal/pki"
	"trustix.local/trustix/internal/routing"
	"trustix.local/trustix/internal/transport"
)

type statusResponse struct {
	DomainID       string                `json:"domain_id"`
	IXID           string                `json:"ix_id"`
	ConfigPath     string                `json:"config_path"`
	ConfigLogPath  string                `json:"config_log_path"`
	DataDir        string                `json:"data_dir"`
	APIAddr        string                `json:"api_addr"`
	APIAdminAuth   bool                  `json:"api_admin_auth"`
	PeerAPIAddr    string                `json:"peer_api_addr"`
	StartedAt      time.Time             `json:"started_at"`
	Build          buildinfo.Info        `json:"build"`
	Management     managementAPIStatus   `json:"management"`
	LAN            lanStatus             `json:"lan"`
	LANs           []lanStatus           `json:"lans,omitempty"`
	ConfigHead     headResponse          `json:"config_head"`
	Counts         statusCounts          `json:"counts"`
	DomainIX       domainIXStatus        `json:"domain_ix"`
	DomainPrefixes domainPrefixStatus    `json:"domain_prefixes"`
	Transports     []string              `json:"transports"`
	Dataplane      string                `json:"dataplane"`
	DataplaneEpoch uint64                `json:"dataplane_epoch"`
	KernelModules  []kernelmodule.Status `json:"kernel_modules,omitempty"`
	Runtime        runtimeResourceStatus `json:"runtime"`
	StateFiles     stateFilesStatus      `json:"state_files"`
	TransportTLS   transportTLSStatus    `json:"transport_tls"`
	DataPath       dataPathStatus        `json:"data_path"`
	ConfigSync     []configSyncPeerState `json:"config_sync,omitempty"`
}

type statusCounts struct {
	LocalEndpoints int `json:"local_endpoints"`
	Peers          int `json:"peers"`
	PeerEndpoints  int `json:"peer_endpoints"`
	Routes         int `json:"routes"`
	Policies       int `json:"policies"`
}

type domainPrefixStatus struct {
	Total    int `json:"total"`
	Accepted int `json:"accepted"`
	Local    int `json:"local"`
	Device   int `json:"device"`
	Direct   int `json:"direct"`
	Transit  int `json:"transit"`
	Static   int `json:"static"`
	Rejected int `json:"rejected"`
}

type domainIXStatus struct {
	Active     int `json:"active"`
	T1         int `json:"t1"`
	Local      int `json:"local"`
	Direct     int `json:"direct"`
	Downstream int `json:"downstream"`
	Stale      int `json:"stale"`
}

type headResponse struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
}

type doctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type kernelCapabilitiesResponse struct {
	Modules         []kernelmodule.Status            `json:"modules,omitempty"`
	Offload         dataPathKernelOffloadStatus      `json:"offload"`
	RXStage         kernelDatapathRXStageStatus      `json:"rx_stage,omitempty"`
	KernelTransport *dataplane.KernelTransportStatus `json:"kernel_transport,omitempty"`
	KernelUDP       *dataplane.KernelUDPStatus       `json:"kernel_udp,omitempty"`
	ExperimentalTCP *dataplane.ExperimentalTCPStatus `json:"experimental_tcp,omitempty"`
	DataPathMode    string                           `json:"datapath_mode,omitempty"`
	Capabilities    []string                         `json:"capabilities,omitempty"`
}

type managementAPIStatus struct {
	Primary managementAPIListenerStatus  `json:"primary"`
	Host    *managementAPIListenerStatus `json:"host,omitempty"`
	TLS     managementTLSStatus          `json:"tls"`
	WebUI   webUIStatus                  `json:"web_ui"`
}

type managementAPIListenerStatus struct {
	Enabled   bool   `json:"enabled"`
	Listen    string `json:"listen,omitempty"`
	Scheme    string `json:"scheme,omitempty"`
	TLS       bool   `json:"tls"`
	Scope     string `json:"scope,omitempty"`
	WriteAuth bool   `json:"write_auth"`
	ReadAuth  bool   `json:"read_auth"`
	Error     string `json:"error,omitempty"`
}

type lanStatus struct {
	ID               string        `json:"id,omitempty"`
	Type             string        `json:"type,omitempty"`
	Primary          bool          `json:"primary,omitempty"`
	Iface            string        `json:"iface,omitempty"`
	UnderlayIface    string        `json:"underlay_iface,omitempty"`
	Gateway          string        `json:"gateway,omitempty"`
	Advertise        []core.Prefix `json:"advertise,omitempty"`
	Mode             string        `json:"mode,omitempty"`
	AttachMode       string        `json:"attach_mode,omitempty"`
	ManageAddress    bool          `json:"manage_address"`
	ManageForwarding bool          `json:"manage_forwarding"`
	ManageRPFilter   bool          `json:"manage_rp_filter"`
}

func (daemon *Daemon) handler() http.Handler {
	return daemon.managementHandler(managementAuthOptions{
		RequireWriteAuth: daemon.cfg.APIAdminAuth,
		RequireReadAuth:  daemon.managementPrimaryAPIReadAuthRequired(),
	})
}

func (daemon *Daemon) hostAPIHandler() http.Handler {
	return daemon.managementHandler(managementAuthOptions{
		RequireWriteAuth: daemon.managementHostAPIWriteAuthRequired(),
		RequireReadAuth:  daemon.managementHostAPIReadAuthRequired(),
	})
}

func (daemon *Daemon) managementHandler(auth managementAuthOptions) http.Handler {
	api := daemon.managementAuthMiddleware(daemon.managementMux(), auth)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if daemon.serveIXProvisionIfRequest(w, r) {
			return
		}
		if daemon.managementWebUIEnabled() && daemon.serveWebUIIfRequest(w, r) {
			return
		}
		api.ServeHTTP(w, r)
	})
}

func (daemon *Daemon) managementMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", daemon.handleStatus)
	mux.HandleFunc("GET /v1/peers", daemon.handlePeers)
	mux.HandleFunc("GET /v1/routes", daemon.handleRoutes)
	mux.HandleFunc("GET /v1/route/probe", daemon.handleRouteProbe)
	mux.HandleFunc("GET /v1/route/trace", daemon.handleRouteTrace)
	mux.HandleFunc("GET /v1/route-policy", daemon.handleRoutePolicy)
	mux.HandleFunc("GET /v1/flows", daemon.handleFlows)
	mux.HandleFunc("GET /v1/endpoints", daemon.handleEndpoints)
	mux.HandleFunc("GET /v1/endpoint/probe", daemon.handleEndpointProbe)
	mux.HandleFunc("GET /v1/links", daemon.handleLinks)
	mux.HandleFunc("GET /v1/device-access", daemon.handleDeviceAccessList)
	mux.HandleFunc("GET /v1/device-access/{device_id}", daemon.handleDeviceAccessShow)
	mux.HandleFunc("POST /v1/device-access/issue", daemon.handleDeviceAccessIssue)
	mux.HandleFunc("POST /v1/device-access/revoke", daemon.handleDeviceAccessRevoke)
	mux.HandleFunc("GET /v1/endpoint-grants", daemon.handleEndpointGrantsList)
	mux.HandleFunc("POST /v1/endpoint-grants/issue", daemon.handleEndpointGrantIssue)
	mux.HandleFunc("POST /v1/endpoint-grants/revoke", daemon.handleEndpointGrantRevoke)
	mux.HandleFunc("POST /v1/provision/ix", daemon.handleIXProvisionIssue)
	mux.HandleFunc("GET /v1/config/desired", daemon.handleConfigDesired)
	mux.HandleFunc("GET /v1/config/peers", daemon.handleConfigPeers)
	mux.HandleFunc("POST /v1/config/validate", daemon.handleConfigValidate)
	mux.HandleFunc("POST /v1/config/apply", daemon.handleConfigApply)
	mux.HandleFunc("POST /v1/config/rollback", daemon.handleConfigRollback)
	mux.HandleFunc("GET /v1/config/head", daemon.handleConfigHead)
	mux.HandleFunc("GET /v1/config/log", daemon.handleConfigLog)
	mux.HandleFunc("GET /v1/config/verify", daemon.handleConfigVerify)
	mux.HandleFunc("GET /v1/config/snapshot", daemon.handleConfigSnapshot)
	mux.HandleFunc("POST /v1/config/rejoin", daemon.handleConfigRejoin)
	mux.HandleFunc("POST /v1/config/restore-backup", daemon.handleConfigRestoreBackup)
	mux.HandleFunc("GET /v1/trust", daemon.handleTrustShow)
	mux.HandleFunc("POST /v1/trust", daemon.handleTrustApply)
	mux.HandleFunc("GET /v1/trust/policy", daemon.handleTrustPolicyShow)
	mux.HandleFunc("POST /v1/trust/policy", daemon.handleTrustPolicyApply)
	mux.HandleFunc("GET /v1/trust/admins", daemon.handleTrustPolicyShow)
	mux.HandleFunc("GET /v1/trust/roots", daemon.handleTrustRootsShow)
	mux.HandleFunc("POST /v1/trust/roots/add", daemon.handleTrustRootAdd)
	mux.HandleFunc("POST /v1/trust/roots/remove", daemon.handleTrustRootRemove)
	mux.HandleFunc("POST /v1/trust/revoke", daemon.handleTrustRevoke)
	mux.HandleFunc("POST /v1/trust/unrevoke", daemon.handleTrustUnrevoke)
	mux.HandleFunc("GET /v1/admissions", daemon.handleAdmissionsList)
	mux.HandleFunc("GET /v1/admissions/pending", daemon.handleAdmissionsPendingList)
	mux.HandleFunc("GET /v1/admissions/pending/{ix_id}", daemon.handleAdmissionPendingShow)
	mux.HandleFunc("GET /v1/admissions/{ix_id}", daemon.handleAdmissionShow)
	mux.HandleFunc("POST /v1/admissions/approve", daemon.handleAdmissionApprove)
	mux.HandleFunc("POST /v1/admissions/approve-pending", daemon.handleAdmissionApprovePending)
	mux.HandleFunc("POST /v1/admissions/revoke", daemon.handleAdmissionRevoke)
	mux.HandleFunc("GET /v1/capture", daemon.handleCapture)
	mux.HandleFunc("GET /v1/datapath", daemon.handleDataPath)
	mux.HandleFunc("GET /v1/transports", daemon.handleTransports)
	mux.HandleFunc("GET /v1/kernel/capabilities", daemon.handleKernelCapabilities)
	mux.HandleFunc("GET /v1/bpf/maps", daemon.handleBPFMaps)
	mux.HandleFunc("GET /v1/doctor", daemon.handleDoctor)
	mux.HandleFunc("/v1/management/ix/{ix_id}/{path...}", daemon.handleManagementIXProxy)
	mux.HandleFunc("GET /v1/control/advertisements", daemon.handleControlAdvertisements)
	mux.HandleFunc("POST /v1/control/advertisements", daemon.handleControlAdvertisementPost)
	mux.HandleFunc("GET /v1/control/members", daemon.handleControlMembers)
	mux.HandleFunc("DELETE /v1/control/members/{ix_id}", daemon.handleControlMemberDelete)
	mux.HandleFunc("GET /v1/control/config/head", daemon.handleControlConfigHead)
	mux.HandleFunc("GET /v1/control/config/log", daemon.handleControlConfigLog)
	mux.HandleFunc("GET /v1/control/config/snapshot", daemon.handleControlConfigSnapshot)
	mux.HandleFunc("POST /v1/control/config/events", daemon.handleControlConfigEventsPost)
	return mux
}

func (daemon *Daemon) peerHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/control/advertisements", daemon.handleControlAdvertisements)
	mux.HandleFunc("POST /v1/control/advertisements", daemon.handleControlAdvertisementPost)
	mux.HandleFunc("GET /v1/control/members", daemon.handleControlMembers)
	mux.HandleFunc("GET /v1/control/config/head", daemon.handleControlConfigHead)
	mux.HandleFunc("GET /v1/control/config/log", daemon.handleControlConfigLog)
	mux.HandleFunc("GET /v1/control/config/snapshot", daemon.handleControlConfigSnapshot)
	mux.HandleFunc("GET /v1/control/route/trace", daemon.handleControlRouteTrace)
	mux.HandleFunc("POST /v1/control/config/events", daemon.handleControlConfigEventsPost)
	mux.HandleFunc("/v1/control/management", daemon.handleControlManagementProxy)
	return mux
}

func (daemon *Daemon) handleStatus(w http.ResponseWriter, r *http.Request) {
	view := daemon.controlViewSnapshot()
	if view.DataplaneStatsErr != nil {
		writeError(w, http.StatusInternalServerError, view.DataplaneStatsErr)
		return
	}
	peerEndpoints := 0
	for _, peer := range daemon.peerConfigsSnapshot() {
		peerEndpoints += len(peer.Endpoints)
	}
	writeJSON(w, http.StatusOK, statusResponse{
		DomainID:      string(daemon.desired.Domain.ID),
		IXID:          string(daemon.desired.IX.ID),
		ConfigPath:    daemon.cfg.ConfigPath,
		ConfigLogPath: daemon.logPath,
		DataDir:       daemon.cfg.DataDir,
		APIAddr:       daemon.cfg.APIAddr,
		APIAdminAuth:  daemon.cfg.APIAdminAuth,
		PeerAPIAddr:   daemon.cfg.PeerAPIAddr,
		StartedAt:     daemon.startedAt,
		Build:         buildassets.BuildInfo(),
		Management:    daemon.managementAPIStatus(),
		LAN:           daemon.lanStatus(),
		LANs:          daemon.lanStatuses(),
		ConfigHead: headResponse{
			Seq:  daemon.head.Seq,
			Hash: daemon.head.Hash,
		},
		Counts: statusCounts{
			LocalEndpoints: len(daemon.desired.Endpoints),
			Peers:          len(view.Peers),
			PeerEndpoints:  peerEndpoints,
			Routes:         len(view.Routes),
			Policies:       len(daemon.desired.Policies),
		},
		DomainIX:       daemon.domainIXStatus(time.Now().UTC(), view.DataPath),
		DomainPrefixes: domainPrefixStatusForRoutes(daemon.desired.IX.ID, view.Routes, daemon.runtimeRoutePolicyStatus().Decisions),
		Transports:     transportNames(daemon.transports.Names()),
		Dataplane:      fmt.Sprintf("%T", daemon.dataplane),
		DataplaneEpoch: view.DataplaneStats.Epoch,
		KernelModules:  daemon.kernelModuleStatuses(),
		Runtime:        view.Runtime,
		StateFiles:     daemon.stateFilesStatus(),
		TransportTLS:   daemon.transportTLSStatus(view.DataPath),
		DataPath:       view.DataPath,
		ConfigSync:     daemon.configSyncSnapshot(),
	})
}

func (daemon *Daemon) handlePeers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, daemon.controlViewSnapshot().Peers)
}

func (daemon *Daemon) domainIXStatus(now time.Time, dataPath dataPathStatus) domainIXStatus {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	status := domainIXStatus{}
	localIX := daemon.desired.IX.ID
	counted := make(map[core.IXID]struct{}, 1+len(daemon.desired.Peers))
	localCounted := false
	if localIX != "" {
		status.Local = 1
		status.T1 = 1
		status.Active = 1
		localCounted = true
		counted[localIX] = struct{}{}
	}

	daemon.membershipMu.RLock()
	defer daemon.membershipMu.RUnlock()
	for ixID, record := range daemon.members {
		if ixID == "" {
			continue
		}
		if ixID == localIX {
			if !localCounted {
				if !record.LastSeen.IsZero() && now.Sub(record.LastSeen) > memberRecordTTL {
					status.Stale++
					continue
				}
				status.Local = 1
				status.T1++
				status.Active++
				localCounted = true
				counted[ixID] = struct{}{}
			}
			continue
		}
		if !record.LastSeen.IsZero() && now.Sub(record.LastSeen) > memberRecordTTL {
			status.Stale++
			continue
		}
		status.Active++
		if record.Direct {
			status.Direct++
			status.T1++
		} else {
			status.Downstream++
		}
		counted[ixID] = struct{}{}
	}
	activeStaticPeers := activeDomainIXPeers(dataPath)
	for _, peer := range daemon.desired.Peers {
		ixID := peer.ID
		if ixID == "" || ixID == localIX {
			continue
		}
		if _, ok := counted[ixID]; ok {
			continue
		}
		counted[ixID] = struct{}{}
		status.Direct++
		status.T1++
		if _, active := activeStaticPeers[ixID]; active {
			status.Active++
		}
	}
	for ixID := range activeStaticPeers {
		if ixID == "" || ixID == localIX {
			continue
		}
		if _, ok := counted[ixID]; ok {
			continue
		}
		counted[ixID] = struct{}{}
		status.Direct++
		status.T1++
		status.Active++
	}
	return status
}

func activeDomainIXPeers(dataPath dataPathStatus) map[core.IXID]struct{} {
	out := make(map[core.IXID]struct{}, len(dataPath.Sessions))
	for _, session := range dataPath.Sessions {
		peer := core.IXID(strings.TrimSpace(session.Peer))
		if peer == "" {
			continue
		}
		out[peer] = struct{}{}
	}
	return out
}

func domainPrefixStatusForRoutes(localIX core.IXID, routes []routing.Route, decisions []routePolicyDecision) domainPrefixStatus {
	type prefixClass struct {
		local   bool
		device  bool
		direct  bool
		transit bool
		static  bool
	}
	classes := make(map[string]prefixClass, len(routes))
	for _, route := range routes {
		key := strings.TrimSpace(string(route.Prefix))
		if parsed, err := route.Prefix.Parse(); err == nil {
			key = parsed.Masked().String()
		}
		if key == "" {
			continue
		}
		class := classes[key]
		switch route.Source {
		case "device_access":
			class.device = true
		case "static":
			class.static = true
		case "dynamic_transit":
			class.transit = true
		case "dynamic":
			class.direct = true
		}
		if route.Kind == routing.RouteLocal || route.Owner == localIX || route.NextHop == localIX && route.Source != "device_access" {
			class.local = true
		}
		if route.Owner != "" && route.NextHop != "" && route.Owner != route.NextHop {
			class.transit = true
		}
		classes[key] = class
	}
	rejected := make(map[string]struct{})
	for _, decision := range decisions {
		if decision.Action != "reject" || decision.Direction != "import" {
			continue
		}
		key := strings.TrimSpace(string(decision.Prefix))
		if parsed, err := decision.Prefix.Parse(); err == nil {
			key = parsed.Masked().String()
		}
		if key != "" {
			rejected[key] = struct{}{}
		}
	}
	status := domainPrefixStatus{
		Total:    len(classes),
		Accepted: len(classes),
		Rejected: len(rejected),
	}
	for _, class := range classes {
		switch {
		case class.device:
			status.Device++
		case class.local:
			status.Local++
		case class.static:
			status.Static++
		case class.transit:
			status.Transit++
		case class.direct:
			status.Direct++
		default:
			status.Static++
		}
	}
	return status
}

func (daemon *Daemon) handleRoutes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, daemon.controlViewSnapshot().Routes)
}

type routeProbeResponse struct {
	OK                 bool                    `json:"ok"`
	Destination        string                  `json:"destination"`
	Source             string                  `json:"source,omitempty"`
	Protocol           uint8                   `json:"protocol,omitempty"`
	SourcePort         uint16                  `json:"source_port,omitempty"`
	DestinationPort    uint16                  `json:"destination_port,omitempty"`
	Matched            bool                    `json:"matched"`
	Prefix             string                  `json:"prefix,omitempty"`
	Route              *routing.Route          `json:"route,omitempty"`
	Policy             *config.PolicyConfig    `json:"policy,omitempty"`
	NextHopConfigured  bool                    `json:"next_hop_configured,omitempty"`
	CandidateEndpoints []routeProbeEndpoint    `json:"candidate_endpoints,omitempty"`
	CandidateError     string                  `json:"candidate_error,omitempty"`
	Datapath           routeProbeDatapathHints `json:"datapath"`
	Reason             string                  `json:"reason,omitempty"`
}

type routeProbeEndpoint struct {
	Name          string `json:"name"`
	Transport     string `json:"transport,omitempty"`
	Priority      int    `json:"priority,omitempty"`
	PriorityScore int    `json:"priority_score,omitempty"`
	Preference    int    `json:"preference,omitempty"`
	Address       string `json:"address,omitempty"`
	Mode          string `json:"mode,omitempty"`
	Enabled       bool   `json:"enabled"`
	LinkTLS       string `json:"link_tls,omitempty"`
	Encryption    string `json:"encryption,omitempty"`
	TLSServerName string `json:"tls_server_name,omitempty"`
}

type endpointProbeResponse struct {
	OK          bool          `json:"ok"`
	Peer        string        `json:"peer"`
	Endpoint    string        `json:"endpoint"`
	Transport   string        `json:"transport"`
	Address     string        `json:"address,omitempty"`
	Healthy     bool          `json:"healthy"`
	RTT         time.Duration `json:"rtt,omitempty"`
	Error       string        `json:"error,omitempty"`
	CheckedAt   time.Time     `json:"checked_at"`
	Updated     bool          `json:"updated"`
	Unsupported bool          `json:"unsupported,omitempty"`
}

type routeProbeDatapathHints struct {
	CaptureForwarderActive     bool   `json:"capture_forwarder_active"`
	CaptureForwarderSuppressed bool   `json:"capture_forwarder_suppressed,omitempty"`
	KernelTransportMode        string `json:"kernel_transport_mode,omitempty"`
	KernelTransportReady       bool   `json:"kernel_transport_ready,omitempty"`
	ExperimentalTCPReady       bool   `json:"experimental_tcp_ready,omitempty"`
	ActiveSessions             int    `json:"active_sessions"`
}

type routeTraceResponse struct {
	OK          bool            `json:"ok"`
	Destination string          `json:"destination"`
	Complete    bool            `json:"complete"`
	Hops        []routeTraceHop `json:"hops"`
	Reason      string          `json:"reason,omitempty"`
}

type routeTraceOptions struct {
	MaxHops int
	Visited map[core.IXID]bool
}

type routeTraceHop struct {
	Index              int                     `json:"index"`
	IXID               string                  `json:"ix_id"`
	Prefix             string                  `json:"prefix,omitempty"`
	Kind               string                  `json:"kind,omitempty"`
	Owner              string                  `json:"owner,omitempty"`
	NextHop            string                  `json:"next_hop,omitempty"`
	Endpoint           string                  `json:"endpoint,omitempty"`
	Policy             string                  `json:"policy,omitempty"`
	Terminal           bool                    `json:"terminal,omitempty"`
	NextHopConfigured  bool                    `json:"next_hop_configured,omitempty"`
	CandidateEndpoints []routeProbeEndpoint    `json:"candidate_endpoints,omitempty"`
	CandidateError     string                  `json:"candidate_error,omitempty"`
	Datapath           routeProbeDatapathHints `json:"datapath,omitempty"`
	Reason             string                  `json:"reason,omitempty"`
}

func (daemon *Daemon) handleRouteProbe(w http.ResponseWriter, r *http.Request) {
	probe, err := daemon.routeProbe(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, probe)
}

func (daemon *Daemon) handleRouteTrace(w http.ResponseWriter, r *http.Request) {
	response, err := daemon.routeTraceFromRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (daemon *Daemon) handleControlRouteTrace(w http.ResponseWriter, r *http.Request) {
	response, err := daemon.routeTraceFromRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (daemon *Daemon) routeTraceFromRequest(r *http.Request) (routeTraceResponse, error) {
	dst, err := parseRouteDiagnosticDestination(r)
	if err != nil {
		return routeTraceResponse{}, err
	}
	maxHops, err := parseUintParam(r, "max_hops", 16)
	if err != nil {
		return routeTraceResponse{}, err
	}
	if maxHops == 0 {
		return routeTraceResponse{}, fmt.Errorf("max_hops must be greater than zero")
	}
	options := routeTraceOptions{
		MaxHops: int(maxHops),
		Visited: parseRouteTraceVisited(r.URL.Query()),
	}
	return daemon.routeTrace(r.Context(), dst, r.URL.Query(), options)
}

func (daemon *Daemon) routeTrace(ctx context.Context, dst netip.Addr, query url.Values, options routeTraceOptions) (routeTraceResponse, error) {
	if options.MaxHops <= 0 {
		return routeTraceResponse{}, fmt.Errorf("max_hops must be greater than zero")
	}
	if options.Visited == nil {
		options.Visited = make(map[core.IXID]bool)
	}
	localIX := daemon.desired.IX.ID
	probe, err := daemon.routeProbeForDestination(dst, query)
	if err != nil {
		return routeTraceResponse{}, err
	}
	response := routeTraceResponse{
		OK:          probe.OK,
		Destination: dst.String(),
		Complete:    false,
		Hops:        []routeTraceHop{routeTraceHopFromProbe(1, localIX, probe)},
	}
	hop := &response.Hops[0]
	if options.Visited[localIX] {
		hop.Terminal = true
		hop.Reason = "loop detected"
		response.OK = false
		response.Complete = true
		response.Reason = fmt.Sprintf("loop detected at IX %q", localIX)
		return response, nil
	}
	options.Visited[localIX] = true
	switch {
	case !probe.Matched:
		hop.Terminal = true
		hop.Reason = "no route"
		response.Complete = true
		response.Reason = hop.Reason
	case probe.Route == nil:
		hop.Terminal = true
		hop.Reason = "route decision missing"
		response.Complete = true
		response.Reason = hop.Reason
	case probe.Route.Kind == routing.RouteLocal:
		hop.Terminal = true
		hop.Reason = "local route"
		response.Complete = true
		response.Reason = hop.Reason
	case probe.Route.Kind == routing.RouteBlackhole || probe.Route.Kind == routing.RouteReject:
		hop.Terminal = true
		hop.Reason = fmt.Sprintf("%s route", probe.Route.Kind)
		response.Complete = true
		response.Reason = hop.Reason
	case probe.Route.NextHop == "" || probe.Route.NextHop == daemon.desired.IX.ID:
		hop.Terminal = true
		hop.Reason = "local next hop"
		response.Complete = true
		response.Reason = hop.Reason
	case options.Visited[probe.Route.NextHop]:
		response.OK = false
		response.Complete = true
		response.Hops = append(response.Hops, routeTraceHop{
			Index:    2,
			IXID:     string(probe.Route.NextHop),
			Terminal: true,
			Reason:   "loop detected",
		})
		response.Reason = fmt.Sprintf("loop detected to IX %q", probe.Route.NextHop)
	case options.MaxHops <= 1:
		response.Reason = "max_hops reached before remote recursive trace"
	default:
		remote, err := daemon.fetchRemoteRouteTrace(ctx, probe.Route.NextHop, dst, query, routeTraceOptions{
			MaxHops: options.MaxHops - 1,
			Visited: options.Visited,
		})
		if err != nil {
			response.Hops = append(response.Hops, routeTraceHop{
				Index:             2,
				IXID:              string(probe.Route.NextHop),
				Terminal:          false,
				NextHopConfigured: probe.NextHopConfigured,
				Reason:            err.Error(),
			})
			response.Reason = "remote recursive trace failed"
			break
		}
		response.OK = response.OK && remote.OK
		response.Complete = remote.Complete
		response.Reason = remote.Reason
		for _, remoteHop := range remote.Hops {
			remoteHop.Index = len(response.Hops) + 1
			response.Hops = append(response.Hops, remoteHop)
		}
	}
	return response, nil
}

func routeTraceHopFromProbe(index int, ixID core.IXID, probe routeProbeResponse) routeTraceHop {
	hop := routeTraceHop{
		Index:              index,
		IXID:               string(ixID),
		Datapath:           probe.Datapath,
		NextHopConfigured:  probe.NextHopConfigured,
		CandidateEndpoints: probe.CandidateEndpoints,
		CandidateError:     probe.CandidateError,
	}
	if probe.Route != nil {
		hop.Prefix = probe.Prefix
		hop.Kind = string(probe.Route.Kind)
		hop.Owner = string(probe.Route.Owner)
		hop.NextHop = string(probe.Route.NextHop)
		hop.Endpoint = string(probe.Route.Endpoint)
		hop.Policy = string(probe.Route.Policy)
	}
	return hop
}

func (daemon *Daemon) fetchRemoteRouteTrace(ctx context.Context, nextHop core.IXID, dst netip.Addr, query url.Values, options routeTraceOptions) (routeTraceResponse, error) {
	target, err := daemon.managementControlTarget(nextHop)
	if err != nil {
		return routeTraceResponse{}, err
	}
	client, err := daemon.controlClient(target)
	if err != nil {
		return routeTraceResponse{}, err
	}
	parsed, err := url.Parse(target.ControlAPI)
	if err != nil {
		return routeTraceResponse{}, fmt.Errorf("parse control_api for %q: %w", nextHop, err)
	}
	traceQuery := cloneRouteTraceQuery(query)
	traceQuery.Set("dst", dst.String())
	traceQuery.Set("max_hops", strconv.Itoa(options.MaxHops))
	traceQuery.Set("visited", routeTraceVisitedValue(options.Visited))
	requestURL := parsed.ResolveReference(&url.URL{Path: "/v1/control/route/trace", RawQuery: traceQuery.Encode()})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return routeTraceResponse{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return routeTraceResponse{}, fmt.Errorf("trace next hop %q: %w", nextHop, err)
	}
	defer drainAndCloseResponse(resp)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return routeTraceResponse{}, fmt.Errorf("read trace response from %q: %w", nextHop, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return routeTraceResponse{}, fmt.Errorf("trace next hop %q returned HTTP %d: %s", nextHop, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var response routeTraceResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return routeTraceResponse{}, fmt.Errorf("decode trace response from %q: %w", nextHop, err)
	}
	return response, nil
}

func cloneRouteTraceQuery(query url.Values) url.Values {
	out := url.Values{}
	for _, name := range []string{"src", "source_ip", "proto", "protocol", "sport", "source_port", "dport", "destination_port"} {
		for _, value := range query[name] {
			if strings.TrimSpace(value) != "" {
				out.Add(name, value)
			}
		}
	}
	return out
}

func parseRouteTraceVisited(query url.Values) map[core.IXID]bool {
	visited := make(map[core.IXID]bool)
	for _, raw := range query["visited"] {
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			visited[core.IXID(part)] = true
		}
	}
	return visited
}

func routeTraceVisitedValue(visited map[core.IXID]bool) string {
	if len(visited) == 0 {
		return ""
	}
	values := make([]string, 0, len(visited))
	for ixID := range visited {
		values = append(values, string(ixID))
	}
	sort.Strings(values)
	return strings.Join(values, ",")
}

func (daemon *Daemon) routeProbe(r *http.Request) (routeProbeResponse, error) {
	dst, err := parseRouteDiagnosticDestination(r)
	if err != nil {
		return routeProbeResponse{}, err
	}
	return daemon.routeProbeForDestination(dst, r.URL.Query())
}

func (daemon *Daemon) routeProbeForDestination(dst netip.Addr, query map[string][]string) (routeProbeResponse, error) {
	packet, flowKey, hasFlow, err := routeDiagnosticPacket(dst, query)
	if err != nil {
		return routeProbeResponse{}, err
	}
	response := routeProbeResponse{
		OK:          true,
		Destination: dst.String(),
		Datapath:    daemon.routeProbeDatapathHints(),
	}
	if flowKey.SourceIP.IsValid() {
		response.Source = flowKey.SourceIP.String()
	}
	if flowKey.Protocol != 0 {
		response.Protocol = flowKey.Protocol
	}
	if flowKey.SourcePort != 0 {
		response.SourcePort = flowKey.SourcePort
	}
	if flowKey.DestinationPort != 0 {
		response.DestinationPort = flowKey.DestinationPort
	}
	var decision routing.Decision
	var ok bool
	if len(packet) > 0 {
		decision, ok = daemon.lookupRouteForPacket(dst, packet)
	} else if daemon.routes != nil {
		decision, ok = daemon.routes.Lookup(dst)
	}
	if !ok {
		response.OK = false
		response.Reason = "no route"
		return response, nil
	}
	response.Matched = true
	response.Prefix = decision.Prefix.String()
	route := decision.Route
	response.Route = &route
	policy := daemon.policyForRoute(decision.Route)
	response.Policy = &policy
	if decision.Route.Kind != "" && decision.Route.Kind != routing.RouteUnicast {
		response.Reason = fmt.Sprintf("%s route", decision.Route.Kind)
		return response, nil
	}
	if decision.Route.NextHop == "" {
		response.Reason = "route has no next hop"
		return response, nil
	}
	peer, ok := daemon.peerConfig(decision.Route.NextHop)
	response.NextHopConfigured = ok
	if !ok {
		response.CandidateError = fmt.Sprintf("route next hop %q is not configured", decision.Route.NextHop)
		return response, nil
	}
	candidates, policy, err := daemon.candidatePeerEndpoints(peer, decision.Route, flowKey, hasFlow)
	response.Policy = &policy
	if err != nil {
		response.CandidateError = err.Error()
		return response, nil
	}
	response.CandidateEndpoints = daemon.routeProbeEndpoints(candidates)
	return response, nil
}

func routeDiagnosticPacket(dst netip.Addr, query map[string][]string) ([]byte, routing.FlowKey, bool, error) {
	src, hasSource, err := parseOptionalAddrParam(query, "src", "source_ip")
	if err != nil {
		return nil, routing.FlowKey{}, false, err
	}
	proto, hasProtocol, err := parseOptionalUint8Param(query, "proto", "protocol")
	if err != nil {
		return nil, routing.FlowKey{}, false, err
	}
	sport, hasSourcePort, err := parseOptionalUint16Param(query, "sport", "source_port")
	if err != nil {
		return nil, routing.FlowKey{}, false, err
	}
	dport, hasDestinationPort, err := parseOptionalUint16Param(query, "dport", "destination_port")
	if err != nil {
		return nil, routing.FlowKey{}, false, err
	}
	if !hasSource && !hasProtocol && !hasSourcePort && !hasDestinationPort {
		return nil, routing.FlowKey{}, false, nil
	}
	if !hasSource {
		src = netip.MustParseAddr("192.0.2.1")
	}
	if !src.Is4() || !dst.Is4() {
		return nil, routing.FlowKey{}, false, fmt.Errorf("route probe packet filters support only IPv4")
	}
	if !hasProtocol {
		if hasSourcePort || hasDestinationPort {
			proto = ipProtocolTCP
		} else {
			proto = ipProtocolICMP
		}
	}
	packet, err := syntheticIPv4ProbePacket(src, dst, proto, sport, dport)
	if err != nil {
		return nil, routing.FlowKey{}, false, err
	}
	flowKey, hasFlow := flowKeyFromIPv4Packet(packet)
	return packet, flowKey, hasFlow, nil
}

func syntheticIPv4ProbePacket(src netip.Addr, dst netip.Addr, proto uint8, sport uint16, dport uint16) ([]byte, error) {
	var payloadLen int
	switch proto {
	case ipProtocolTCP:
		payloadLen = 20
	case ipProtocolUDP:
		payloadLen = 8
	case ipProtocolICMP:
		payloadLen = 8
	default:
		payloadLen = 4
	}
	totalLen := ipv4HeaderLen + payloadLen
	packet := make([]byte, totalLen)
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = proto
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	copy(packet[12:16], src.AsSlice())
	copy(packet[16:20], dst.AsSlice())
	segment := packet[ipv4HeaderLen:]
	switch proto {
	case ipProtocolTCP:
		binary.BigEndian.PutUint16(segment[0:2], sport)
		binary.BigEndian.PutUint16(segment[2:4], dport)
		segment[12] = 5 << 4
		binary.BigEndian.PutUint16(segment[16:18], transportChecksum(packet[12:16], packet[16:20], proto, segment))
	case ipProtocolUDP:
		binary.BigEndian.PutUint16(segment[0:2], sport)
		binary.BigEndian.PutUint16(segment[2:4], dport)
		binary.BigEndian.PutUint16(segment[4:6], uint16(len(segment)))
		binary.BigEndian.PutUint16(segment[6:8], transportChecksum(packet[12:16], packet[16:20], proto, segment))
	case ipProtocolICMP:
		segment[0] = 8
		binary.BigEndian.PutUint16(segment[2:4], ipv4Checksum(segment))
	}
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:ipv4HeaderLen]))
	return packet, nil
}

func parseRouteDiagnosticDestination(r *http.Request) (netip.Addr, error) {
	raw := strings.TrimSpace(firstNonEmpty(r.URL.Query().Get("dst"), r.URL.Query().Get("destination"), r.URL.Query().Get("destination_ip")))
	if raw == "" {
		return netip.Addr{}, fmt.Errorf("dst is required")
	}
	dst, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid dst %q: %w", raw, err)
	}
	return dst, nil
}

func parseOptionalAddrParam(query map[string][]string, names ...string) (netip.Addr, bool, error) {
	raw := strings.TrimSpace(firstQueryValue(query, names...))
	if raw == "" {
		return netip.Addr{}, false, nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, false, fmt.Errorf("invalid %s %q: %w", names[0], raw, err)
	}
	return addr, true, nil
}

func parseOptionalUint8Param(query map[string][]string, names ...string) (uint8, bool, error) {
	value, ok, err := parseOptionalUintParam(query, 8, names...)
	return uint8(value), ok, err
}

func parseOptionalUint16Param(query map[string][]string, names ...string) (uint16, bool, error) {
	value, ok, err := parseOptionalUintParam(query, 16, names...)
	return uint16(value), ok, err
}

func parseOptionalUintParam(query map[string][]string, bitSize int, names ...string) (uint64, bool, error) {
	raw := strings.TrimSpace(firstQueryValue(query, names...))
	if raw == "" {
		return 0, false, nil
	}
	value, err := strconv.ParseUint(raw, 10, bitSize)
	if err != nil {
		return 0, false, fmt.Errorf("invalid %s %q", names[0], raw)
	}
	return value, true, nil
}

func firstQueryValue(query map[string][]string, names ...string) string {
	for _, name := range names {
		values := query[name]
		for _, value := range values {
			if strings.TrimSpace(value) != "" {
				return value
			}
		}
	}
	return ""
}

func (daemon *Daemon) routeProbeDatapathHints() routeProbeDatapathHints {
	status := daemon.dataPathStatus()
	hints := routeProbeDatapathHints{
		CaptureForwarderActive:     status.CaptureForwarderActive,
		CaptureForwarderSuppressed: status.CaptureForwarderSuppressed,
		ActiveSessions:             status.ActiveSessions,
	}
	if status.KernelTransport != nil {
		hints.KernelTransportReady = status.KernelTransport.Available
		hints.KernelTransportMode = string(status.KernelTransport.Mode)
	}
	if status.ExperimentalTCP != nil {
		hints.ExperimentalTCPReady = status.ExperimentalTCP.Available && status.ExperimentalTCP.FastPath
	}
	return hints
}

func (daemon *Daemon) routeProbeEndpoints(endpoints []config.EndpointConfig) []routeProbeEndpoint {
	out := make([]routeProbeEndpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		out = append(out, routeProbeEndpoint{
			Name:          string(endpoint.Name),
			Transport:     endpoint.Transport,
			Priority:      endpoint.Priority,
			PriorityScore: daemon.endpointPriorityScore("", endpoint),
			Preference:    daemon.endpointTransportPreferenceRank(endpoint),
			Address:       endpoint.Address,
			Mode:          string(endpoint.Mode),
			Enabled:       endpoint.Enabled,
			LinkTLS:       endpoint.Security.LinkTLS,
			Encryption:    endpoint.Security.Encryption,
			TLSServerName: endpoint.TLSServerName,
		})
	}
	return out
}

func (daemon *Daemon) handleRoutePolicy(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, daemon.runtimeRoutePolicyStatus())
}

func (daemon *Daemon) handleFlows(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, daemon.flowSnapshot())
}

func (daemon *Daemon) handleEndpoints(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, endpointsFromConfig(daemon.desired))
}

func (daemon *Daemon) handleEndpointProbe(w http.ResponseWriter, r *http.Request) {
	response, err := daemon.endpointProbeFromRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (daemon *Daemon) endpointProbeFromRequest(r *http.Request) (endpointProbeResponse, error) {
	query := r.URL.Query()
	peerID := core.IXID(strings.TrimSpace(firstQueryValue(query, "peer", "ix", "ix_id")))
	endpointName := core.EndpointID(strings.TrimSpace(firstQueryValue(query, "endpoint", "name")))
	if peerID == "" {
		return endpointProbeResponse{}, fmt.Errorf("peer is required")
	}
	if endpointName == "" {
		return endpointProbeResponse{}, fmt.Errorf("endpoint is required")
	}
	peer, ok := daemon.peerConfig(peerID)
	if !ok {
		return endpointProbeResponse{}, fmt.Errorf("peer %q is not configured", peerID)
	}
	var endpoint config.EndpointConfig
	foundEndpoint := false
	for _, candidate := range peer.Endpoints {
		if candidate.Name == endpointName {
			endpoint = candidate
			foundEndpoint = true
			break
		}
	}
	if !foundEndpoint {
		return endpointProbeResponse{}, fmt.Errorf("peer %q endpoint %q is not configured", peerID, endpointName)
	}
	response := endpointProbeResponse{
		Peer:      string(peer.ID),
		Endpoint:  string(endpoint.Name),
		Transport: endpoint.Transport,
		Address:   endpoint.Address,
		CheckedAt: time.Now().UTC(),
	}
	if endpoint.Address == "" {
		response.Error = "endpoint has no address; reverse/inbound-only endpoints are verified by active reverse sessions"
		return response, nil
	}
	protocol := transport.Protocol(endpoint.Transport)
	if !endpointSupportsPassiveProbe(protocol) {
		response.Unsupported = true
		response.Error = fmt.Sprintf("transport %q does not support passive probe", endpoint.Transport)
		return response, nil
	}
	tr, ok := daemon.transports.Get(protocol)
	if !ok {
		response.Error = fmt.Sprintf("transport %q is not registered", endpoint.Transport)
		return response, nil
	}
	timeout := endpointProbeTimeout()
	if value, ok, err := parseOptionalUintParam(query, 32, "timeout_ms"); err != nil {
		return endpointProbeResponse{}, err
	} else if ok && value > 0 {
		timeout = time.Duration(value) * time.Millisecond
	}
	probeCtx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	result := tr.Probe(probeCtx, transport.Peer{
		ID:       peer.ID,
		DomainID: peer.Domain,
		Endpoints: []transport.Endpoint{
			transportEndpointFromConfig(endpoint),
		},
	})
	if result.CheckedAt.IsZero() {
		result.CheckedAt = time.Now().UTC()
	}
	response.CheckedAt = result.CheckedAt
	response.Healthy = result.Healthy
	response.RTT = result.RTT
	if result.Healthy {
		response.OK = true
		response.Updated = daemon.recordEndpointUp(peer.ID, endpoint, result.RTT)
		return response, nil
	}
	response.Error = result.Error
	if response.Error == "" && probeCtx.Err() != nil {
		response.Error = probeCtx.Err().Error()
	}
	response.Updated = daemon.recordEndpointDown(peer.ID, endpoint, fmt.Errorf("%s", response.Error))
	return response, nil
}

func (daemon *Daemon) handleConfigHead(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, struct {
		Head headResponse `json:"head"`
		Path string       `json:"path"`
	}{
		Head: headResponse{Seq: daemon.head.Seq, Hash: daemon.head.Hash},
		Path: daemon.logPath,
	})
}

func (daemon *Daemon) handleConfigLog(w http.ResponseWriter, r *http.Request) {
	if daemon.head.Seq == 0 {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	from, err := parseUintParam(r, "from", 1)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	to, err := parseUintParam(r, "to", daemon.head.Seq)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	events, err := daemon.store.Range(from, to)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func (daemon *Daemon) handleCapture(w http.ResponseWriter, r *http.Request) {
	limit, err := parseUintParam(r, "limit", 20)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	filter, err := parseCaptureFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	reader, ok := daemon.dataplane.(dataplane.CaptureReader)
	if !ok {
		writeJSON(w, http.StatusOK, struct {
			Packets []any  `json:"packets"`
			Status  string `json:"status"`
		}{
			Packets: []any{},
			Status:  "dataplane capture is not available",
		})
		return
	}
	readLimit := int(limit)
	if filter.Enabled() && readLimit < 128 {
		readLimit = 128
	}
	events, err := reader.Capture(r.Context(), readLimit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	events = filterCaptureEvents(events, filter, daemon.routes)
	events = trimCaptureEvents(events, int(limit))
	writeJSON(w, http.StatusOK, struct {
		Packets any    `json:"packets"`
		Status  string `json:"status"`
	}{
		Packets: events,
		Status:  "TC/eBPF route-hit capture active",
	})
}

type captureFilter struct {
	Hook           string
	Peer           core.IXID
	SourceIP       netip.Addr
	DestinationIP  netip.Addr
	HasSourceIP    bool
	HasDestination bool
}

func parseCaptureFilter(r *http.Request) (captureFilter, error) {
	query := r.URL.Query()
	filter := captureFilter{
		Hook: strings.TrimSpace(query.Get("hook")),
	}
	if rawPeer := strings.TrimSpace(query.Get("peer")); rawPeer != "" {
		peer := core.IXID(rawPeer)
		if err := peer.Validate(); err != nil {
			return captureFilter{}, err
		}
		filter.Peer = peer
	}
	if rawSource := strings.TrimSpace(firstNonEmpty(query.Get("src"), query.Get("source_ip"))); rawSource != "" {
		addr, err := netip.ParseAddr(rawSource)
		if err != nil {
			return captureFilter{}, fmt.Errorf("invalid source ip %q: %w", rawSource, err)
		}
		filter.SourceIP = addr
		filter.HasSourceIP = true
	}
	if rawDestination := strings.TrimSpace(firstNonEmpty(query.Get("dst"), query.Get("destination_ip"))); rawDestination != "" {
		addr, err := netip.ParseAddr(rawDestination)
		if err != nil {
			return captureFilter{}, fmt.Errorf("invalid destination ip %q: %w", rawDestination, err)
		}
		filter.DestinationIP = addr
		filter.HasDestination = true
	}
	return filter, nil
}

func (filter captureFilter) Enabled() bool {
	return filter.Hook != "" || filter.Peer != "" || filter.HasSourceIP || filter.HasDestination
}

func filterCaptureEvents(events []dataplane.CaptureEvent, filter captureFilter, routes routing.Engine) []dataplane.CaptureEvent {
	if !filter.Enabled() {
		return events
	}
	out := make([]dataplane.CaptureEvent, 0, len(events))
	for _, event := range events {
		if filter.Hook != "" && event.Hook != filter.Hook {
			continue
		}
		if filter.HasSourceIP && !captureEventIPMatches(event.SourceAddr, event.SourceIP, filter.SourceIP) {
			continue
		}
		if filter.HasDestination && !captureEventIPMatches(event.DestinationAddr, event.DestinationIP, filter.DestinationIP) {
			continue
		}
		if filter.Peer != "" && !captureEventPeerMatches(event, filter.Peer, routes) {
			continue
		}
		out = append(out, event)
	}
	return out
}

func captureEventIPMatches(addr netip.Addr, raw string, want netip.Addr) bool {
	if addr.IsValid() {
		return addr == want
	}
	addr, err := netip.ParseAddr(raw)
	return err == nil && addr == want
}

func captureEventPeerMatches(event dataplane.CaptureEvent, peer core.IXID, routes routing.Engine) bool {
	dst := event.DestinationAddr
	if !dst.IsValid() {
		var err error
		dst, err = netip.ParseAddr(event.DestinationIP)
		if err != nil {
			return false
		}
	}
	decision, ok := routes.Lookup(dst)
	return ok && decision.Route.NextHop == peer
}

func trimCaptureEvents(events []dataplane.CaptureEvent, limit int) []dataplane.CaptureEvent {
	if limit <= 0 || len(events) <= limit {
		return events
	}
	return events[len(events)-limit:]
}

func (daemon *Daemon) handleBPFMaps(w http.ResponseWriter, r *http.Request) {
	view := daemon.controlViewSnapshot()
	if view.DataplaneStatsErr != nil {
		writeError(w, http.StatusInternalServerError, view.DataplaneStatsErr)
		return
	}
	var maps any
	if snapshotter, ok := daemon.dataplane.(dataplane.BPFMapSnapshotter); ok {
		snapshot, err := snapshotter.BPFMapSnapshot(r.Context())
		if err != nil && !errors.Is(err, dataplane.ErrUnsupported) {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if err == nil {
			maps = snapshot
		}
	}
	writeJSON(w, http.StatusOK, struct {
		Stats  any    `json:"stats"`
		Maps   any    `json:"maps,omitempty"`
		Status string `json:"status"`
	}{
		Stats:  view.DataplaneStats,
		Maps:   maps,
		Status: "dataplane manager boundary active",
	})
}

func (daemon *Daemon) handleDataPath(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, daemon.controlViewSnapshot().DataPath)
}

func (daemon *Daemon) handleKernelCapabilities(w http.ResponseWriter, r *http.Request) {
	view := daemon.controlViewSnapshot()
	if view.DataplaneStatsErr != nil {
		writeError(w, http.StatusInternalServerError, view.DataplaneStatsErr)
		return
	}
	writeJSON(w, http.StatusOK, kernelCapabilitiesResponse{
		Modules:         daemon.kernelModuleStatuses(),
		Offload:         view.DataPath.KernelOffload,
		RXStage:         view.DataPath.KernelRXStage,
		KernelTransport: view.DataPath.KernelTransport,
		KernelUDP:       view.DataPath.KernelUDP,
		ExperimentalTCP: view.DataPath.ExperimentalTCP,
		DataPathMode:    view.DataPath.KernelOffload.DataplaneMode,
		Capabilities:    append([]string(nil), view.DataPath.KernelOffload.Capabilities...),
	})
}

func (daemon *Daemon) handleTransports(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, daemon.transportMatrixStatus())
}

func (daemon *Daemon) handleDoctor(w http.ResponseWriter, r *http.Request) {
	view := daemon.controlViewSnapshot()
	if view.DataplaneStatsErr != nil {
		writeError(w, http.StatusInternalServerError, view.DataplaneStatsErr)
		return
	}
	healthyPeers := 0
	for _, peer := range view.Peers {
		if peer.Runtime.Healthy {
			healthyPeers++
		}
	}
	configSyncStates := daemon.configSyncSnapshot()
	kernelModules := daemon.kernelModuleStatuses()
	checks := []doctorCheck{
		{Name: "config", Status: "ok", Detail: "desired config loaded and validated"},
		{Name: "config_log", Status: "ok", Detail: fmt.Sprintf("head seq=%d path=%s", daemon.head.Seq, daemon.logPath)},
		{Name: "config_sync", Status: configSyncDoctorStatus(configSyncStates), Detail: configSyncDoctorDetail(configSyncStates)},
		daemon.apiSecurityDoctorCheck(),
		daemon.managementHostAPIDoctorCheck(),
		daemon.managementTLSDoctorCheck(),
		daemon.managementWebUIDoctorCheck(),
		daemon.trustRevocationDoctorCheck(),
		runtimeResourceDoctorCheck(view.Runtime),
		daemon.stateFilesDoctorCheck(),
		kernelModuleDoctorCheck(kernelModules),
		firewallDoctorCheck(),
		transportTLSDoctorCheck(daemon.transportTLSStatus(view.DataPath)),
		daemon.lanDoctorCheck(),
		{Name: "routing", Status: "ok", Detail: fmt.Sprintf("%d routes loaded", len(daemon.desired.Routes))},
		{Name: "peer_control", Status: peerControlStatus(healthyPeers, len(daemon.desired.Peers)), Detail: fmt.Sprintf("%d/%d peers healthy", healthyPeers, len(daemon.desired.Peers))},
		{Name: "dataplane", Status: dataplaneStatus(view.DataplaneStats), Detail: dataplaneDetail(view.DataplaneStats)},
		{Name: "data_path", Status: dataPathDoctorStatus(view.DataPath), Detail: dataPathDoctorDetail(view.DataPath)},
		{Name: "kernel_transport", Status: kernelTransportDoctorStatus(view.DataPath), Detail: kernelTransportDoctorDetail(view.DataPath)},
	}
	if daemon.experimentalTCPDoctorEnabled(view.DataPath) {
		checks = append(checks, doctorCheck{
			Name:   "experimental_tcp",
			Status: experimentalTCPDoctorStatus(view.DataPath),
			Detail: experimentalTCPDoctorDetail(view.DataPath),
		})
	}
	if daemon.kernelUDPDoctorEnabled(view.DataPath) {
		checks = append(checks, doctorCheck{
			Name:   "kernel_udp",
			Status: kernelUDPDoctorStatus(view.DataPath),
			Detail: kernelUDPDoctorDetail(view.DataPath),
		})
	}
	writeJSON(w, http.StatusOK, checks)
}

func (daemon *Daemon) handleControlAdvertisements(w http.ResponseWriter, r *http.Request) {
	if target, ok := daemon.controlRequestTarget(r); ok {
		advertisement, err := daemon.localAdvertisementForTarget(target)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, advertisement)
		return
	}
	daemon.membershipMu.RLock()
	advertisement := daemon.localAd
	daemon.membershipMu.RUnlock()
	writeJSON(w, http.StatusOK, advertisement)
}

func (daemon *Daemon) handleControlMembers(w http.ResponseWriter, r *http.Request) {
	target, _ := daemon.controlRequestTarget(r)
	response := daemon.controlMembersResponse(target)
	payload, err := json.Marshal(response)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	etag := `"` + controlPayloadHash(payload) + `"`
	w.Header().Set("ETag", etag)
	if httpETagMatches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func (daemon *Daemon) controlMembersResponse(target controlTarget) membersResponse {
	now := time.Now().UTC()
	var targetedLocal *advertisementResponse
	if target.ID != "" {
		if ad, err := daemon.localAdvertisementForTarget(target); err == nil {
			targetedLocal = &ad
		}
	}
	daemon.membershipMu.RLock()
	defer daemon.membershipMu.RUnlock()
	members := make([]advertisementResponse, 0, len(daemon.members)+1)
	localID := core.IXID(daemon.localAd.IXID)
	if daemon.localAd.IXID != "" {
		local := daemon.localAd
		if targetedLocal != nil {
			local = *targetedLocal
		}
		members = append(members, local)
	}
	ids := make([]string, 0, len(daemon.members))
	for ixID := range daemon.members {
		if localID != "" && ixID == localID {
			continue
		}
		ids = append(ids, string(ixID))
	}
	sort.Strings(ids)
	for _, rawID := range ids {
		record := daemon.members[core.IXID(rawID)]
		if !record.Direct || now.Sub(record.LastSeen) > memberRecordTTL {
			continue
		}
		members = append(members, record.Advertisement)
	}
	return membersResponse{Members: members}
}

func (daemon *Daemon) controlRequestTarget(r *http.Request) (controlTarget, bool) {
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return controlTarget{}, false
	}
	meta := pki.ParseMetadata(r.TLS.PeerCertificates[0])
	if meta.Role != pki.RoleIX || meta.IX == "" {
		return controlTarget{}, false
	}
	domain := core.DomainID(meta.Domain)
	if domain == "" {
		domain = daemon.desired.Domain.ID
	}
	return controlTarget{ID: core.IXID(meta.IX), Domain: domain}, true
}

func httpETagMatches(header, etag string) bool {
	for _, item := range strings.Split(header, ",") {
		item = strings.TrimSpace(item)
		if item == "*" || item == etag {
			return true
		}
	}
	return false
}

func (daemon *Daemon) handleControlAdvertisementPost(w http.ResponseWriter, r *http.Request) {
	var advertisement advertisementResponse
	if err := json.NewDecoder(r.Body).Decode(&advertisement); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	changed, err := daemon.mergeAdvertisement(advertisement, r.RemoteAddr)
	if err != nil {
		if isPendingAdmissionError(err) {
			writeJSON(w, http.StatusAccepted, struct {
				Accepted bool   `json:"accepted"`
				Pending  bool   `json:"pending"`
				Changed  bool   `json:"changed"`
				Error    string `json:"error,omitempty"`
			}{Accepted: false, Pending: true, Changed: false, Error: err.Error()})
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if changed {
		if err := daemon.applyRuntimeDataplaneSnapshot(r.Context()); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		daemon.scheduleRuntimeRouteWarmup(r.Context())
	}
	writeJSON(w, http.StatusOK, struct {
		Accepted bool `json:"accepted"`
		Changed  bool `json:"changed"`
	}{Accepted: true, Changed: changed})
}

func (daemon *Daemon) handleControlMemberDelete(w http.ResponseWriter, r *http.Request) {
	ixID := core.IXID(r.PathValue("ix_id"))
	if err := ixID.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if ixID == daemon.desired.IX.ID {
		writeError(w, http.StatusBadRequest, fmt.Errorf("cannot delete local IX member"))
		return
	}
	daemon.membershipMu.Lock()
	_, existed := daemon.members[ixID]
	delete(daemon.members, ixID)
	daemon.membershipMu.Unlock()
	if existed {
		daemon.closeDataSessionsForPeers(map[core.IXID]struct{}{ixID: {}})
		daemon.clearFlowsForPeers(map[core.IXID]struct{}{ixID: {}})
		if err := daemon.persistMembers(); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if err := daemon.applyRuntimeDataplaneSnapshot(r.Context()); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, struct {
		Deleted bool `json:"deleted"`
	}{Deleted: existed})
}

func (daemon *Daemon) lanStatus() lanStatus {
	lan := config.PrimaryLAN(daemon.desired)
	return lanStatusFromConfig(lan, true)
}

func (daemon *Daemon) lanStatuses() []lanStatus {
	lans := config.EffectiveLANs(daemon.desired)
	if len(lans) == 0 {
		return nil
	}
	primaryID := config.PrimaryLAN(daemon.desired).ID
	out := make([]lanStatus, 0, len(lans))
	for index, lan := range lans {
		out = append(out, lanStatusFromConfig(lan, lan.ID == primaryID || primaryID == "" && index == 0))
	}
	return out
}

func lanStatusFromConfig(lan config.LANConfig, primary bool) lanStatus {
	attachMode := lan.AttachMode
	if attachMode == "" {
		attachMode = config.LANAttachModeManaged
	}
	return lanStatus{
		ID:               lan.ID,
		Type:             string(lan.Type),
		Primary:          primary,
		Iface:            lan.Iface,
		UnderlayIface:    lan.UnderlayIface,
		Gateway:          lan.Gateway,
		Advertise:        append([]core.Prefix(nil), lan.Advertise...),
		Mode:             string(lan.Mode),
		AttachMode:       string(attachMode),
		ManageAddress:    lan.ManageAddress,
		ManageForwarding: lan.ManageForwarding,
		ManageRPFilter:   lan.ManageRPFilter,
	}
}

func (daemon *Daemon) lanDoctorCheck() doctorCheck {
	statuses := daemon.lanStatuses()
	if len(statuses) == 0 {
		return doctorCheck{Name: "lan", Status: "ok", Detail: "LAN not configured"}
	}
	status := statuses[0]
	for _, item := range statuses {
		if item.Iface == "" && len(item.Advertise) > 0 {
			return doctorCheck{Name: "lan", Status: "degraded", Detail: fmt.Sprintf("LAN %q prefixes are configured without an iface", item.ID)}
		}
	}
	attachMode := status.AttachMode
	if attachMode == "" {
		attachMode = string(config.LANAttachModeManaged)
	}
	detail := fmt.Sprintf("count=%d primary=%s iface=%s attach_mode=%s gateway=%s advertise=%d manage_address=%t forwarding=%t rp_filter=%t",
		len(statuses),
		status.ID,
		status.Iface,
		attachMode,
		status.Gateway,
		len(status.Advertise),
		status.ManageAddress,
		status.ManageForwarding,
		status.ManageRPFilter,
	)
	if attachMode == string(config.LANAttachModeExisting) && status.ManageAddress {
		return doctorCheck{Name: "lan", Status: "degraded", Detail: detail + " invalid existing interface address management"}
	}
	if len(statuses) > 1 {
		detail += "; dataplane receives multi-LAN attach metadata"
	}
	return doctorCheck{Name: "lan", Status: "ok", Detail: detail}
}

func peerControlStatus(healthy, total int) string {
	switch {
	case total == 0:
		return "ok"
	case healthy == total:
		return "ok"
	case healthy == 0:
		return "warn"
	default:
		return "degraded"
	}
}

func transportNames(protocols []transport.Protocol) []string {
	names := make([]string, 0, len(protocols))
	for _, protocol := range protocols {
		names = append(names, string(protocol))
	}
	return names
}

func dataplaneStatus(stats dataplane.Stats) string {
	if stats.Mode == "noop" {
		return "warn"
	}
	if !stats.Attached {
		return "warn"
	}
	return "ok"
}

func dataplaneDetail(stats dataplane.Stats) string {
	if stats.Mode == "noop" {
		return "using no-op dataplane"
	}
	detail := fmt.Sprintf("mode=%s attached=%t epoch=%d iface=%s lan_attach_mode=%s", stats.Mode, stats.Attached, stats.Epoch, stats.LANIface, stats.LANAttachMode)
	if len(stats.Warnings) > 0 {
		detail += " warnings=" + fmt.Sprint(stats.Warnings)
	}
	return detail
}

func dataPathDoctorStatus(status dataPathStatus) string {
	if status.Counters.CaptureUnavailable > 0 {
		return "warn"
	}
	if !status.CaptureForwarderActive && !status.CaptureForwarderSuppressed {
		return "warn"
	}
	if len(status.Listeners) == 0 {
		return "warn"
	}
	if status.Counters.SendErrors > 0 || status.Counters.InjectErrors > 0 {
		return "degraded"
	}
	return "ok"
}

func dataPathDoctorDetail(status dataPathStatus) string {
	reverseSessions := 0
	for _, session := range status.Sessions {
		if session.Reverse {
			reverseSessions++
		}
	}
	return fmt.Sprintf("listeners=%d sessions=%d reverse_sessions=%d capture_forwarder_active=%t capture_forwarder_suppressed=%t sent=%d received=%d injected=%d resets_sent=%d resets_received=%d stale_sessions_dropped=%d",
		len(status.Listeners),
		status.ActiveSessions,
		reverseSessions,
		status.CaptureForwarderActive,
		status.CaptureForwarderSuppressed,
		status.Counters.PacketsSent,
		status.Counters.PacketsReceived,
		status.Counters.PacketsInjected,
		status.Counters.SessionResetsSent,
		status.Counters.SessionResetsReceived,
		status.Counters.StaleSessionsDropped,
	)
}

func kernelTransportDoctorStatus(status dataPathStatus) string {
	kernelTransport := status.KernelTransport
	if kernelTransport == nil {
		return "warn"
	}
	if kernelTransport.Mode == dataplane.KernelTransportModeDisabled {
		return "ok"
	}
	if kernelTransport.Mode == dataplane.KernelTransportModeRequireKernel && !kernelTransport.Available {
		return "degraded"
	}
	if !kernelTransport.Available {
		return "warn"
	}
	return "ok"
}

func kernelTransportDoctorDetail(status dataPathStatus) string {
	kernelTransport := status.KernelTransport
	if kernelTransport == nil {
		return "kernel transport provider status is unavailable"
	}
	detail := fmt.Sprintf("mode=%s available=%t provider=%s", kernelTransport.Mode, kernelTransport.Available, kernelTransport.Provider)
	for _, protocol := range kernelTransport.Protocols {
		detail += fmt.Sprintf(" %s=%s/%t capability=%t fallback=%t", protocol.Protocol, protocol.Placement, protocol.Available, protocol.CapabilityReady, protocol.UserspaceFallback)
		if protocol.Carrier != "" {
			detail += " carrier=" + protocol.Carrier
		}
		if protocol.Contract != "" {
			detail += " contract=" + protocol.Contract
		}
		if protocol.Reason != "" {
			detail += " reason=" + protocol.Reason
		}
	}
	return detail
}

func (daemon *Daemon) kernelUDPDoctorEnabled(status dataPathStatus) bool {
	if status.KernelUDP != nil && status.KernelUDP.Available {
		return true
	}
	if daemon.kernelTransportMode() == dataplane.KernelTransportModeDisabled {
		return false
	}
	for _, endpoint := range daemon.desired.Endpoints {
		if endpoint.Transport == string(transport.ProtocolUDP) && endpoint.Enabled {
			return true
		}
	}
	for _, peer := range daemon.desired.Peers {
		for _, endpoint := range peer.Endpoints {
			if endpoint.Transport == string(transport.ProtocolUDP) {
				return true
			}
		}
	}
	return false
}

func kernelUDPDoctorStatus(status dataPathStatus) string {
	udp := status.KernelUDP
	if udp == nil {
		if kernelTransportRequiresKernel(status) {
			return "degraded"
		}
		return "warn"
	}
	if !udp.Available || !udp.Reinject || !udp.FastPath {
		if kernelTransportRequiresKernel(status) {
			return "degraded"
		}
		return "warn"
	}
	return "ok"
}

func kernelUDPDoctorDetail(status dataPathStatus) string {
	udp := status.KernelUDP
	if udp == nil {
		return "kernel UDP provider status is unavailable"
	}
	detail := fmt.Sprintf("provider=%s available=%t fast_path=%t reinject=%t userspace_crypto=%t kernel_crypto=%t active_flows=%d submitted=%d received=%d",
		udp.Provider,
		udp.Available,
		udp.FastPath,
		udp.Reinject,
		udp.UserspaceCrypto,
		udp.KernelCrypto,
		udp.ActiveFlows,
		udp.SubmittedFrames,
		udp.ReceivedFrames,
	)
	if udp.KernelCryptoReason != "" {
		detail += " kernel_crypto_reason=" + udp.KernelCryptoReason
	}
	if udp.XDPAttachMode != "" {
		detail += " xdp_attach_mode=" + udp.XDPAttachMode
	}
	if udp.AFXDPBindMode != "" {
		detail += " af_xdp_bind_mode=" + udp.AFXDPBindMode
	}
	detail += fmt.Sprintf(" zerocopy_enabled=%t", udp.ZeroCopyEnabled)
	if len(udp.ProviderStats) > 0 {
		detail += " provider_stats=" + fmt.Sprint(udp.ProviderStats)
	}
	return detail
}

func kernelTransportRequiresKernel(status dataPathStatus) bool {
	return status.KernelTransport != nil && status.KernelTransport.Mode == dataplane.KernelTransportModeRequireKernel
}

func (daemon *Daemon) experimentalTCPDoctorEnabled(status dataPathStatus) bool {
	if status.ExperimentalTCP != nil && status.ExperimentalTCP.Available {
		return true
	}
	for _, endpoint := range daemon.desired.Endpoints {
		if endpoint.Transport == string(transport.ProtocolExperimentalTCP) && endpoint.Enabled {
			return true
		}
	}
	for _, peer := range daemon.desired.Peers {
		for _, endpoint := range peer.Endpoints {
			if endpoint.Transport == string(transport.ProtocolExperimentalTCP) {
				return true
			}
		}
	}
	return false
}

func experimentalTCPDoctorStatus(status dataPathStatus) string {
	exp := status.ExperimentalTCP
	if exp == nil {
		return "warn"
	}
	if exp.RequestedCrypto == dataplane.CryptoPlacementKernel && !exp.KernelCrypto {
		return "degraded"
	}
	if !exp.Available || !exp.Reinject {
		return "warn"
	}
	if exp.RawSocketFallback || !exp.FastPath {
		return "warn"
	}
	if exp.EffectiveCrypto == "" {
		return "warn"
	}
	return "ok"
}

func experimentalTCPDoctorDetail(status dataPathStatus) string {
	exp := status.ExperimentalTCP
	if exp == nil {
		return "experimental_tcp status is unavailable"
	}
	detail := fmt.Sprintf("provider=%s available=%t fast_path=%t reinject=%t requested_crypto=%s effective_crypto=%s kernel_crypto=%t",
		exp.Provider,
		exp.Available,
		exp.FastPath,
		exp.Reinject,
		exp.RequestedCrypto,
		exp.EffectiveCrypto,
		exp.KernelCrypto,
	)
	if probe := exp.KernelCryptoProbe; probe != nil {
		detail += fmt.Sprintf(" kernel_btf=%t crypto_kfuncs=%t aes_gcm=%t aes_ni=%t provider_ready=%t",
			probe.KernelBTF,
			probe.CryptoKfuncs,
			probe.AESGCM,
			probe.AESNI,
			probe.ProviderReady,
		)
		if probe.SelfTest != nil {
			detail += fmt.Sprintf(" selftest_attempted=%t selftest_passed=%t",
				probe.SelfTest.Attempted,
				probe.SelfTest.Passed,
			)
			if probe.SelfTest.Reason != "" {
				detail += " selftest_reason=" + probe.SelfTest.Reason
			}
		}
		if probe.MapSchema != nil {
			detail += fmt.Sprintf(" crypto_map_key_size=%d crypto_map_value_size=%d crypto_map_max_entries=%d",
				probe.MapSchema.FlowKeySize,
				probe.MapSchema.FlowValueSize,
				probe.MapSchema.MaxEntries,
			)
		}
	}
	if exp.KernelCryptoReason != "" {
		detail += " kernel_crypto_reason=" + exp.KernelCryptoReason
	}
	return detail
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(value)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, struct {
		Error string `json:"error"`
	}{
		Error: err.Error(),
	})
}
