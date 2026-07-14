package daemon

import (
	"context"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
)

type transportMatrixStatus struct {
	Policy          transportMatrixPolicy            `json:"policy"`
	Registered      []string                         `json:"registered"`
	LocalEndpoints  []transportMatrixEndpoint        `json:"local_endpoints"`
	PeerEndpoints   []transportMatrixPeerEndpoint    `json:"peer_endpoints"`
	KernelTransport *dataplane.KernelTransportStatus `json:"kernel_transport,omitempty"`
	TIXTCP          *dataplane.ExperimentalTCPStatus `json:"tix_tcp,omitempty"`
	ExperimentalTCP *dataplane.ExperimentalTCPStatus `json:"experimental_tcp,omitempty"`
	KernelUDP       *dataplane.KernelUDPStatus       `json:"kernel_udp,omitempty"`
	TransportTLS    transportTLSStatus               `json:"transport_tls"`
	Sessions        []dataPathSessionStatus          `json:"sessions"`
	Counters        dataPathCounters                 `json:"counters"`
}

type transportMatrixPolicy struct {
	Mode                string   `json:"mode,omitempty"`
	KernelTransport     string   `json:"kernel_transport"`
	Profile             string   `json:"profile,omitempty"`
	Datapath            string   `json:"datapath,omitempty"`
	CryptoPlacement     string   `json:"crypto_placement"`
	Encryption          string   `json:"encryption,omitempty"`
	CryptoKeySource     string   `json:"crypto_key_source,omitempty"`
	CryptoSuites        []string `json:"crypto_suites,omitempty"`
	MTU                 int      `json:"mtu,omitempty"`
	FragmentPolicy      string   `json:"fragment_policy,omitempty"`
	SessionPoolSize     int      `json:"session_pool_size,omitempty"`
	SessionPoolStrategy string   `json:"session_pool_strategy,omitempty"`
	SessionPoolWarmup   bool     `json:"session_pool_warmup,omitempty"`
}

type transportMatrixEndpoint struct {
	Name               string                         `json:"name"`
	Transport          string                         `json:"transport"`
	Priority           int                            `json:"priority,omitempty"`
	Preference         int                            `json:"preference,omitempty"`
	Listen             string                         `json:"listen,omitempty"`
	Address            string                         `json:"address,omitempty"`
	LocalBind          config.EndpointLocalBindConfig `json:"local_bind,omitempty"`
	Enabled            bool                           `json:"enabled"`
	Usable             bool                           `json:"usable"`
	Profile            string                         `json:"profile,omitempty"`
	Datapath           string                         `json:"datapath,omitempty"`
	Features           []string                       `json:"features,omitempty"`
	Encryption         string                         `json:"encryption,omitempty"`
	CryptoPlacements   []string                       `json:"crypto_placements,omitempty"`
	KernelCompatible   bool                           `json:"kernel_compatible"`
	SecurityCompatible bool                           `json:"security_compatible"`
	ProfileCompatible  bool                           `json:"profile_compatible"`
}

type transportMatrixPeerEndpoint struct {
	Peer               string                         `json:"peer"`
	Name               string                         `json:"name"`
	Transport          string                         `json:"transport"`
	Priority           int                            `json:"priority,omitempty"`
	Preference         int                            `json:"preference,omitempty"`
	Address            string                         `json:"address,omitempty"`
	LocalBind          config.EndpointLocalBindConfig `json:"local_bind,omitempty"`
	ReverseOnly        bool                           `json:"reverse_only,omitempty"`
	ActiveReverse      int                            `json:"active_reverse_sessions,omitempty"`
	Usable             bool                           `json:"usable"`
	Profile            string                         `json:"profile,omitempty"`
	Datapath           string                         `json:"datapath,omitempty"`
	Features           []string                       `json:"features,omitempty"`
	Encryption         string                         `json:"encryption,omitempty"`
	CryptoPlacements   []string                       `json:"crypto_placements,omitempty"`
	KernelCompatible   bool                           `json:"kernel_compatible"`
	SecurityCompatible bool                           `json:"security_compatible"`
	ProfileCompatible  bool                           `json:"profile_compatible"`
}

func (daemon *Daemon) transportMatrixStatus() transportMatrixStatus {
	view := daemon.controlViewSnapshot()
	dataPath := publicDataPathStatus(view.DataPath)
	var kernelTransport *dataplane.KernelTransportStatus
	if dataPath.KernelTransport != nil {
		status := *dataPath.KernelTransport
		kernelTransport = &status
	} else if provider, ok := daemon.dataplane.(dataplane.KernelTransportProvider); ok {
		if status, err := provider.KernelTransportStatus(context.Background()); err == nil {
			daemon.annotateKernelTransportStatus(&status)
			kernelTransport = publicKernelTransportStatus(&status)
		}
	}
	var experimentalTCP *dataplane.ExperimentalTCPStatus
	if dataPath.ExperimentalTCP != nil {
		status := *dataPath.ExperimentalTCP
		experimentalTCP = &status
	}
	var kernelUDP *dataplane.KernelUDPStatus
	if dataPath.KernelUDP != nil {
		status := *dataPath.KernelUDP
		kernelUDP = &status
	}
	return transportMatrixStatus{
		Policy:          daemon.transportMatrixPolicy(),
		Registered:      transportNames(daemon.transports.Names()),
		LocalEndpoints:  daemon.transportMatrixLocalEndpoints(),
		PeerEndpoints:   daemon.transportMatrixPeerEndpoints(),
		KernelTransport: kernelTransport,
		TIXTCP:          experimentalTCP,
		ExperimentalTCP: experimentalTCP,
		KernelUDP:       kernelUDP,
		TransportTLS:    daemon.transportTLSStatus(dataPath),
		Sessions:        dataPath.Sessions,
		Counters:        dataPath.Counters,
	}
}

func (daemon *Daemon) transportMatrixPolicy() transportMatrixPolicy {
	policy := daemon.desired.TransportPolicy
	return transportMatrixPolicy{
		Mode:                policy.Mode,
		KernelTransport:     string(daemon.kernelTransportMode()),
		Profile:             policy.Profile,
		Datapath:            policy.Datapath,
		CryptoPlacement:     effectiveTransportCryptoPlacementConfig(policy),
		Encryption:          policy.Encryption,
		CryptoKeySource:     policy.CryptoKeySource,
		CryptoSuites:        effectiveSecureTransportCryptoSuitesForDesired(daemon.desired),
		MTU:                 policy.MTU,
		FragmentPolicy:      policy.FragmentPolicy,
		SessionPoolSize:     policy.SessionPool.Size,
		SessionPoolStrategy: policy.SessionPool.Strategy,
		SessionPoolWarmup:   policy.SessionPool.Warmup,
	}
}

func (daemon *Daemon) transportMatrixLocalEndpoints() []transportMatrixEndpoint {
	out := make([]transportMatrixEndpoint, 0, len(daemon.desired.Endpoints))
	for _, endpoint := range daemon.desired.Endpoints {
		security := daemon.endpointSecurityMetadata(endpoint)
		profile := endpointTransportProfileMetadataForDesired(endpoint, daemon.desired)
		kernelCompatible := daemon.endpointKernelTransportCompatible(endpoint.Transport)
		securityCompatible := daemon.endpointSecurityCompatible(endpoint)
		profileCompatible := daemon.endpointTransportProfileCompatible(endpoint)
		out = append(out, transportMatrixEndpoint{
			Name:               string(endpoint.Name),
			Transport:          config.PublicTransportName(endpoint.Transport),
			Priority:           endpoint.Priority,
			Preference:         daemon.endpointTransportPreferenceRank(endpoint),
			Listen:             endpoint.Listen,
			Address:            endpoint.Address,
			LocalBind:          endpointLocalBindSurface(endpoint.LocalBind),
			Enabled:            endpoint.Enabled,
			Usable:             endpoint.Enabled && kernelCompatible && securityCompatible && profileCompatible,
			Profile:            profile.Profile,
			Datapath:           profile.Datapath,
			Features:           append([]string(nil), profile.Features...),
			Encryption:         security.Encryption,
			CryptoPlacements:   append([]string(nil), security.CryptoPlacements...),
			KernelCompatible:   kernelCompatible,
			SecurityCompatible: securityCompatible,
			ProfileCompatible:  profileCompatible,
		})
	}
	return out
}

func (daemon *Daemon) transportMatrixPeerEndpoints() []transportMatrixPeerEndpoint {
	total := 0
	peers := daemon.peerConfigsSnapshot()
	for _, peer := range peers {
		total += len(peer.Endpoints)
	}
	out := make([]transportMatrixPeerEndpoint, 0, total)
	for _, peer := range peers {
		for _, endpoint := range peer.Endpoints {
			security := endpointSecurityMetadataFromConfig(endpoint.Security, endpoint.TLSServerName)
			profile := endpointTransportProfileMetadataFromConfig(endpoint.Profile)
			kernelCompatible := daemon.endpointKernelTransportCompatible(endpoint.Transport)
			securityCompatible := daemon.endpointSecurityCompatible(endpoint)
			profileCompatible := daemon.endpointTransportProfileCompatible(endpoint)
			activeReverse := daemon.activeReverseSessionsForEndpoint(peer.ID, endpoint)
			reverseOnly := endpoint.Address == ""
			out = append(out, transportMatrixPeerEndpoint{
				Peer:               string(peer.ID),
				Name:               string(endpoint.Name),
				Transport:          config.PublicTransportName(endpoint.Transport),
				Priority:           endpoint.Priority,
				Preference:         daemon.endpointTransportPreferenceRank(endpoint),
				Address:            endpoint.Address,
				LocalBind:          endpointLocalBindSurface(endpoint.LocalBind),
				ReverseOnly:        reverseOnly,
				ActiveReverse:      activeReverse,
				Usable:             kernelCompatible && securityCompatible && profileCompatible && (!reverseOnly || activeReverse > 0),
				Profile:            profile.Profile,
				Datapath:           profile.Datapath,
				Features:           append([]string(nil), profile.Features...),
				Encryption:         security.Encryption,
				CryptoPlacements:   append([]string(nil), security.CryptoPlacements...),
				KernelCompatible:   kernelCompatible,
				SecurityCompatible: securityCompatible,
				ProfileCompatible:  profileCompatible,
			})
		}
	}
	return out
}

func (daemon *Daemon) activeReverseSessionsForEndpoint(peerID core.IXID, endpoint config.EndpointConfig) int {
	encryption := daemon.endpointDialEncryption(endpoint)
	daemon.dataMu.Lock()
	defer daemon.dataMu.Unlock()
	var active int
	for key, session := range daemon.dataSessions {
		if reverseDataSessionKeyMatches(key, peerID, endpoint, encryption) && session != nil {
			active++
		}
	}
	return active
}
