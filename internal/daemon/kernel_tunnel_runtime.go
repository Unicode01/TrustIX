package daemon

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/transport"
	iptunneltransport "trustix.local/trustix/internal/transport/iptunnel"
)

type kernelTunnelConfigUse struct {
	protocol       transport.Protocol
	raw            string
	normalized     string
	linkName       string
	label          string
	localUnderlay  netip.Addr
	remoteUnderlay netip.Addr
	underlayIf     string
	localCarrier   netip.Prefix
	remoteCarrier  netip.Addr
	carrierPort    uint16
	vni            int
	vxlanPort      uint16
}

func normalizedKernelTunnelConfigKey(protocol transport.Protocol, raw string) (string, bool) {
	use, ok, err := newKernelTunnelConfigUse(protocol, raw, "")
	if err != nil || !ok {
		return "", false
	}
	return string(protocol) + "\x00" + use.normalized, true
}

func newKernelTunnelConfigUse(protocol transport.Protocol, raw string, label string) (kernelTunnelConfigUse, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || !transportProtocolIsKernelTunnel(string(protocol)) || !kernelTunnelConfigComplete(raw) {
		return kernelTunnelConfigUse{}, false, nil
	}
	cfg, err := iptunneltransport.ParseTunnelConfig(raw)
	if err != nil {
		return kernelTunnelConfigUse{}, false, fmt.Errorf("%s tunnel config %s: %w", protocol, label, err)
	}
	normalized := iptunneltransport.NormalizeParsedKernelTunnelConfig(protocol, cfg)
	return kernelTunnelConfigUse{
		protocol:       protocol,
		raw:            raw,
		normalized:     normalized,
		linkName:       iptunneltransport.DeterministicTunnelName(string(protocol), normalized),
		label:          label,
		localUnderlay:  cfg.LocalUnderlay,
		remoteUnderlay: cfg.RemoteUnderlay,
		underlayIf:     cfg.UnderlayIf,
		localCarrier:   cfg.LocalCarrier.Masked(),
		remoteCarrier:  cfg.RemoteCarrier,
		carrierPort:    cfg.CarrierPort,
		vni:            cfg.VNI,
		vxlanPort:      cfg.VXLANPort,
	}, true, nil
}

func validateKernelTunnelConfigConflicts(uses []kernelTunnelConfigUse) error {
	if len(uses) < 2 {
		return nil
	}
	byName := make(map[string]kernelTunnelConfigUse, len(uses))
	byUnderlay := make(map[string]kernelTunnelConfigUse, len(uses))
	byCarrierPrefix := make(map[string]kernelTunnelConfigUse, len(uses))
	byCarrierBind := make(map[string]kernelTunnelConfigUse, len(uses))
	for _, use := range uses {
		if use.normalized == "" {
			continue
		}
		if existing, ok := byName[use.linkName]; ok && existing.normalized != use.normalized {
			return kernelTunnelConflictError("interface name", use.linkName, existing, use)
		}
		byName[use.linkName] = use

		underlayKey := kernelTunnelUnderlayKey(use)
		if existing, ok := byUnderlay[underlayKey]; ok && existing.normalized != use.normalized {
			return kernelTunnelConflictError("underlay tuple", underlayKey, existing, use)
		}
		byUnderlay[underlayKey] = use

		prefixKey := use.localCarrier.String()
		if existing, ok := byCarrierPrefix[prefixKey]; ok && existing.normalized != use.normalized {
			return kernelTunnelConflictError("local carrier prefix", prefixKey, existing, use)
		}
		byCarrierPrefix[prefixKey] = use

		bindKey := fmt.Sprintf("%s/%d", use.localCarrier.Addr(), use.carrierPort)
		if existing, ok := byCarrierBind[bindKey]; ok && existing.normalized != use.normalized {
			return kernelTunnelConflictError("carrier bind", bindKey, existing, use)
		}
		byCarrierBind[bindKey] = use
	}
	return nil
}

func kernelTunnelUnderlayKey(use kernelTunnelConfigUse) string {
	fields := []string{
		string(use.protocol),
		use.localUnderlay.String(),
		use.remoteUnderlay.String(),
	}
	if use.protocol == transport.ProtocolVXLAN {
		fields = append(fields, use.underlayIf, fmt.Sprintf("vni=%d", use.vni), fmt.Sprintf("vxlan_port=%d", use.vxlanPort))
	}
	return strings.Join(fields, "|")
}

func kernelTunnelConflictError(kind string, key string, left kernelTunnelConfigUse, right kernelTunnelConfigUse) error {
	return fmt.Errorf(
		"kernel tunnel %s conflict %q between %s and %s: %s != %s",
		kind,
		key,
		kernelTunnelUseLabel(left),
		kernelTunnelUseLabel(right),
		left.normalized,
		right.normalized,
	)
}

func kernelTunnelUseLabel(use kernelTunnelConfigUse) string {
	if strings.TrimSpace(use.label) != "" {
		return use.label
	}
	return string(use.protocol)
}

func validateDesiredKernelTunnelConflicts(desired config.Desired) error {
	uses := make([]kernelTunnelConfigUse, 0, len(desired.Endpoints))
	for _, endpoint := range desired.Endpoints {
		if !endpoint.Enabled || !transportProtocolIsKernelTunnel(endpoint.Transport) {
			continue
		}
		raw := firstNonEmpty(endpoint.Listen, endpoint.Address)
		use, ok, err := newKernelTunnelConfigUse(
			transport.Protocol(strings.ToLower(strings.TrimSpace(endpoint.Transport))),
			raw,
			fmt.Sprintf("local endpoint %q", endpoint.Name),
		)
		if err != nil {
			return err
		}
		if ok {
			uses = append(uses, use)
		}
	}
	for _, peer := range desired.Peers {
		for _, endpoint := range peer.Endpoints {
			if !endpointDataSessionEnabled(endpoint) || !transportProtocolIsKernelTunnel(endpoint.Transport) {
				continue
			}
			use, ok, err := newKernelTunnelConfigUse(
				transport.Protocol(strings.ToLower(strings.TrimSpace(endpoint.Transport))),
				endpoint.Address,
				fmt.Sprintf("peer %q endpoint %q", peer.ID, endpoint.Name),
			)
			if err != nil {
				return err
			}
			if ok {
				uses = append(uses, use)
			}
		}
	}
	return validateKernelTunnelConfigConflicts(uses)
}

func validateRuntimeKernelTunnelConflicts(snapshot dataplane.Snapshot) error {
	uses := make([]kernelTunnelConfigUse, 0, len(snapshot.Endpoints))
	for _, endpoint := range snapshot.Endpoints {
		if !endpoint.Enabled || !transportProtocolIsKernelTunnel(endpoint.Transport) {
			continue
		}
		raw := firstNonEmpty(endpoint.Listen, endpoint.Address)
		use, ok, err := newKernelTunnelConfigUse(
			transport.Protocol(strings.ToLower(strings.TrimSpace(endpoint.Transport))),
			raw,
			fmt.Sprintf("runtime endpoint %q/%q", endpoint.Peer, endpoint.ID),
		)
		if err != nil {
			return err
		}
		if ok {
			uses = append(uses, use)
		}
	}
	return validateKernelTunnelConfigConflicts(uses)
}

func (daemon *Daemon) desiredKernelTunnelListenerEndpoints() (map[string]config.EndpointConfig, error) {
	out := make(map[string]config.EndpointConfig)
	for _, endpoint := range daemon.desired.Endpoints {
		if !endpoint.Enabled || endpoint.Mode != config.EndpointModePassive || !transportProtocolIsKernelTunnel(endpoint.Transport) {
			continue
		}
		raw := strings.TrimSpace(firstNonEmpty(endpoint.Listen, endpoint.Address))
		use, ok, err := newKernelTunnelConfigUse(
			transport.Protocol(strings.ToLower(strings.TrimSpace(endpoint.Transport))),
			raw,
			fmt.Sprintf("local listener endpoint %q", endpoint.Name),
		)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		key := string(use.protocol) + "\x00" + use.normalized
		out[key] = endpoint
	}
	for _, peer := range daemon.peerConfigsForTunnelListeners() {
		for _, endpoint := range peer.Endpoints {
			if !endpointDataSessionEnabled(endpoint) || !transportProtocolIsKernelTunnel(endpoint.Transport) {
				continue
			}
			use, ok, err := newKernelTunnelConfigUse(
				transport.Protocol(strings.ToLower(strings.TrimSpace(endpoint.Transport))),
				endpoint.Address,
				fmt.Sprintf("peer listener %q endpoint %q", peer.ID, endpoint.Name),
			)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			key := string(use.protocol) + "\x00" + use.normalized
			if _, exists := out[key]; exists {
				continue
			}
			listenerEndpoint := endpoint
			listenerEndpoint.Mode = config.EndpointModePassive
			listenerEndpoint.Listen = use.raw
			listenerEndpoint.Address = ""
			out[key] = listenerEndpoint
		}
	}
	if len(out) < 2 {
		return out, nil
	}
	uses := make([]kernelTunnelConfigUse, 0, len(out))
	keys := make([]string, 0, len(out))
	for key := range out {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		endpoint := out[key]
		use, ok, err := newKernelTunnelConfigUse(
			transport.Protocol(strings.ToLower(strings.TrimSpace(endpoint.Transport))),
			firstNonEmpty(endpoint.Listen, endpoint.Address),
			fmt.Sprintf("listener endpoint %q", endpoint.Name),
		)
		if err != nil {
			return nil, err
		}
		if ok {
			uses = append(uses, use)
		}
	}
	return out, validateKernelTunnelConfigConflicts(uses)
}

func listenerKernelTunnelConfigKey(endpoint transport.Endpoint) (string, bool) {
	if !transportProtocolIsKernelTunnel(string(endpoint.Transport)) {
		return "", false
	}
	return normalizedKernelTunnelConfigKey(endpoint.Transport, firstNonEmpty(endpoint.Listen, endpoint.Address))
}

func (daemon *Daemon) dataPathIsStarted() bool {
	daemon.dataMu.Lock()
	defer daemon.dataMu.Unlock()
	return daemon.dataPathStarted
}

func (daemon *Daemon) syncKernelTunnelListeners(ctx context.Context) error {
	if !daemon.dataPathIsStarted() {
		return nil
	}
	desired, err := daemon.desiredKernelTunnelListenerEndpoints()
	if err != nil {
		return err
	}
	existing := make(map[string]struct{}, len(desired))
	var closing []dataListenerRuntime
	daemon.dataMu.Lock()
	kept := daemon.dataListeners[:0]
	for _, runtime := range daemon.dataListeners {
		key, ok := listenerKernelTunnelConfigKey(runtime.Endpoint)
		if !ok {
			kept = append(kept, runtime)
			continue
		}
		if _, want := desired[key]; !want {
			closing = append(closing, runtime)
			continue
		}
		if _, duplicate := existing[key]; duplicate {
			closing = append(closing, runtime)
			continue
		}
		existing[key] = struct{}{}
		kept = append(kept, runtime)
	}
	daemon.dataListeners = kept
	daemon.dataMu.Unlock()

	for _, runtime := range closing {
		if runtime.Cancel != nil {
			runtime.Cancel()
		}
		_ = runtime.Listener.Close()
	}

	keys := make([]string, 0, len(desired))
	for key := range desired {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, ok := existing[key]; ok {
			continue
		}
		if err := daemon.startTransportListenerEndpoint(ctx, desired[key]); err != nil {
			return err
		}
	}
	return nil
}

func kernelTunnelEndpointID(peer core.IXID, endpoint core.EndpointID) string {
	if peer == "" {
		return string(endpoint)
	}
	return string(peer) + "/" + string(endpoint)
}
