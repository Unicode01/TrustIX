package daemon

import (
	"fmt"
	"strings"

	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/kernelmodule"
)

const (
	kernelLayerTC      = "tc"
	kernelLayerXDP     = "xdp"
	kernelLayerAFXDP   = "af_xdp"
	kernelLayerModule  = "kernel_module"
	kernelLayerControl = "control"

	placementKernel    = "kernel"
	placementUserspace = "userspace"
	placementHybrid    = "hybrid"
	placementFallback  = "fallback"
)

func (daemon *Daemon) dataPathKernelOffloadStatus(stats dataplane.Stats, statsOK bool, experimentalTCP *dataplane.ExperimentalTCPStatus, kernelTransport *dataplane.KernelTransportStatus, kernelUDP *dataplane.KernelUDPStatus) dataPathKernelOffloadStatus {
	packetPolicy := daemon.dataplanePacketPolicy()
	modulePlacements := kernelModulePlacements(daemon.kernelModuleStatuses())
	status := dataPathKernelOffloadStatus{
		PacketPolicy: packetPolicy,
		Placements: []dataPathKernelPlacement{
			{Name: "route_lpm", Layer: kernelLayerTC, Placement: placementKernel, Detail: "IPv4 route LPM, local/blackhole/reject/capture action selection"},
			{Name: "packet_policy", Layer: kernelLayerTC, Placement: packetPolicyPlacement(packetPolicy), Detail: packetPolicyDetail(packetPolicy)},
			{Name: "nat_snat", Layer: kernelLayerTC, Placement: placementHybrid, Detail: "TC rewrites eligible outbound IPv4 source addresses; daemon mirrors binding state from capture metadata"},
			{Name: "nat_dnat", Layer: kernelLayerTC, Placement: placementHybrid, Detail: "LAN egress TC applies reverse binding when available; daemon falls back to userspace DNAT"},
			{Name: "reject_reply", Layer: kernelLayerTC, Placement: placementHybrid, Detail: "TC drops and counts reject routes, suppresses no-reply TCP RST / ICMP error cases, and generates fixed IPv4 TCP RST plus ICMP unreachable replies; daemon remains fallback for fragments, IPv4 options, short packets, and TC errors"},
			{Name: "transport_plane", Layer: kernelLayerAFXDP, Placement: kernelTransportPlacement(kernelTransport), Detail: kernelTransportDetail(kernelTransport)},
			{Name: "flow_selection", Layer: kernelLayerControl, Placement: placementUserspace, Detail: "endpoint selection, flow stickiness, health, and least_conn need daemon runtime state"},
			{Name: "secure_handshake", Layer: kernelLayerControl, Placement: placementUserspace, Detail: "IX certificate authentication and key derivation stay in userspace"},
			{Name: "standard_transports", Layer: kernelLayerControl, Placement: placementUserspace, Detail: "tcp/quic/websocket/http_connect remain userspace socket transports; UDP uses userspace socket fallback unless the fixed TIXU kernel provider is active"},
			{Name: "transit_routing_after_decrypt", Layer: kernelLayerControl, Placement: placementUserspace, Detail: "post-decrypt route lookup and next-hop session selection stay in daemon"},
		},
		KernelCandidates: []dataPathKernelCandidate{
			{Name: "experimental_tcp_plaintext_forward", Layer: kernelLayerXDP, Complexity: "medium", Detail: "eligible plaintext experimental_tcp frames can avoid secure crypto workers; routing still needs explicit flow/session context"},
			{Name: "endpoint_flow_map", Layer: kernelLayerTC, Complexity: "high", Detail: "requires kernel-visible endpoint/flow/session maps and health state ownership"},
		},
		UserspaceRemaining: []dataPathUserspaceResponsibility{
			{Name: "control_plane", Reason: "config log, trust/admission validation, membership gossip, and management API are not packet fast-path work"},
			{Name: "secure_handshake", Reason: "certificate parsing, TLS exporter, and key agreement are handshake-time state machines"},
			{Name: "standard_quic", Reason: "QUIC TLS, ACK, recovery, congestion control, and connection migration remain userspace; kernel plane should carry a TrustIX fixed frame instead"},
			{Name: "userspace_crypto_fallback", Reason: "kernel transport can own RX/TX while AEAD seal/open falls back to daemon when kernel crypto is unavailable"},
		},
	}
	status.Placements = append(status.Placements[:6], append(modulePlacements, status.Placements[6:]...)...)
	if statsOK {
		status.DataplaneMode = stats.Mode
		status.Capabilities = append([]string(nil), stats.Capabilities...)
	}
	if experimentalTCP != nil {
		status.Placements = append(status.Placements, experimentalTCPPlacement(*experimentalTCP))
	}
	if kernelUDP != nil {
		status.Placements = append(status.Placements, kernelUDPPlacement(*kernelUDP))
	}
	return status
}

func kernelModulePlacements(statuses []kernelmodule.Status) []dataPathKernelPlacement {
	if len(statuses) == 0 {
		return []dataPathKernelPlacement{{
			Name:      "trustix_crypto",
			Layer:     kernelLayerModule,
			Placement: placementUserspace,
			Detail:    "no kernel module status is available; crypto stays in userspace or built-in dataplane fallback",
		}}
	}
	placements := make([]dataPathKernelPlacement, 0, len(statuses))
	for _, status := range statuses {
		placements = append(placements, kernelModulePlacement(status))
	}
	return placements
}

func kernelModulePlacement(status kernelmodule.Status) dataPathKernelPlacement {
	placement := placementUserspace
	switch status.CapabilityTier {
	case kernelmodule.CapabilityTierFullDatapath:
		placement = placementKernel
	case kernelmodule.CapabilityTierGSOSKB, kernelmodule.CapabilityTierCryptoOnly:
		placement = placementHybrid
	default:
		if status.Mode == kernelmodule.ModeRequired && !status.Loaded {
			placement = placementFallback
		}
	}
	return dataPathKernelPlacement{
		Name:      status.Name,
		Layer:     kernelLayerModule,
		Placement: placement,
		Detail:    kernelModulePlacementDetail(status),
	}
}

func kernelModulePlacementDetail(status kernelmodule.Status) string {
	detail := fmt.Sprintf("mode=%s loaded=%t state=%s tier=%s", status.Mode, status.Loaded, status.State, status.CapabilityTier)
	if status.ABIVersion > 0 {
		detail += fmt.Sprintf(" abi=%d", status.ABIVersion)
	}
	if len(status.Features) > 0 {
		detail += " features=" + strings.Join(status.Features, ",")
	}
	if len(status.MissingFeatures) > 0 {
		detail += " missing=" + strings.Join(status.MissingFeatures, ",")
	}
	if status.CapabilityReason != "" {
		detail += " reason=" + status.CapabilityReason
	}
	return detail
}

func kernelTransportPlacement(status *dataplane.KernelTransportStatus) string {
	if status == nil || status.Mode == dataplane.KernelTransportModeDisabled {
		return placementUserspace
	}
	if !status.Available {
		if status.Mode == dataplane.KernelTransportModeRequireKernel {
			return placementFallback
		}
		return placementUserspace
	}
	for _, protocol := range status.Protocols {
		if protocol.Available && protocol.UserspaceFallback {
			return placementHybrid
		}
	}
	return placementKernel
}

func kernelTransportDetail(status *dataplane.KernelTransportStatus) string {
	if status == nil {
		return "no kernel transport provider is registered; socket transports remain userspace"
	}
	detail := fmt.Sprintf("mode=%s available=%t provider=%s", status.Mode, status.Available, status.Provider)
	for _, protocol := range status.Protocols {
		if protocol.Available {
			detail += fmt.Sprintf("; %s=%s", protocol.Protocol, protocol.Placement)
		}
	}
	if status.Mode == dataplane.KernelTransportModeRequireKernel && !status.Available {
		detail += "; require_kernel will reject endpoints without a kernel transport provider"
	}
	return detail
}

func packetPolicyPlacement(policy dataplane.PacketPolicy) string {
	if policy.MTU > 0 || policy.DropFragments || policy.TCPMSSClamp > 0 {
		return placementKernel
	}
	return placementUserspace
}

func packetPolicyDetail(policy dataplane.PacketPolicy) string {
	switch {
	case policy.MTU > 0 && policy.DropFragments && policy.TCPMSSClamp > 0:
		return fmt.Sprintf("TC drops captured-path packets above MTU %d and IPv4 fragments, and clamps TCP SYN MSS to %d before perf capture/direct TX", policy.MTU, policy.TCPMSSClamp)
	case policy.MTU > 0 && policy.DropFragments:
		return fmt.Sprintf("TC drops captured-path packets above MTU %d and IPv4 fragments before perf capture", policy.MTU)
	case policy.MTU > 0 && policy.TCPMSSClamp > 0:
		return fmt.Sprintf("TC drops captured-path packets above MTU %d and clamps TCP SYN MSS to %d before perf capture/direct TX", policy.MTU, policy.TCPMSSClamp)
	case policy.DropFragments && policy.TCPMSSClamp > 0:
		return fmt.Sprintf("TC drops IPv4 fragments and clamps TCP SYN MSS to %d before perf capture/direct TX", policy.TCPMSSClamp)
	case policy.MTU > 0:
		return fmt.Sprintf("TC drops captured-path packets above MTU %d before perf capture", policy.MTU)
	case policy.DropFragments:
		return "TC drops IPv4 fragments before perf capture"
	case policy.TCPMSSClamp > 0:
		return fmt.Sprintf("TC clamps TCP SYN MSS to %d before perf capture/direct TX", policy.TCPMSSClamp)
	default:
		return "no kernel packet policy is configured; daemon still validates captured packets defensively"
	}
}

func experimentalTCPPlacement(status dataplane.ExperimentalTCPStatus) dataPathKernelPlacement {
	placement := placementUserspace
	detail := "experimental_tcp provider is unavailable"
	switch {
	case status.FastPath && status.KernelCrypto:
		placement = placementKernel
		detail = "AF_XDP/XDP fast path with kernel secure AEAD seal/open when selected by crypto placement"
	case status.FastPath:
		placement = placementHybrid
		detail = "AF_XDP/XDP handles TCP-shaped frame RX/TX; secure AEAD remains userspace unless kernel crypto is selected and ready"
	case status.RawSocketFallback:
		placement = placementFallback
		detail = "raw socket fallback is active and is not a kernel fast path"
	case status.Available:
		placement = placementFallback
		detail = "experimental_tcp contract is available but no TC/XDP fast path is attached"
	}
	if status.Provider != "" {
		detail += "; provider=" + status.Provider
	}
	if status.EffectiveCrypto != "" {
		detail += "; effective_crypto=" + string(status.EffectiveCrypto)
	}
	if status.CryptoFallback.Selected != "" {
		detail += "; crypto_backend=" + status.CryptoFallback.Selected
	}
	return dataPathKernelPlacement{
		Name:      "experimental_tcp",
		Layer:     kernelLayerAFXDP,
		Placement: placement,
		Detail:    detail,
	}
}

func kernelUDPPlacement(status dataplane.KernelUDPStatus) dataPathKernelPlacement {
	placement := placementUserspace
	detail := "UDP/TIXU kernel transport provider is unavailable"
	switch {
	case status.FastPath && status.Reinject && status.KernelCrypto:
		placement = placementKernel
		detail = "XDP/AF_XDP handles fixed IPv4/UDP TIXU frame RX/TX; AES-GCM secure AEAD can run in kernel crypto provider"
	case status.FastPath && status.Reinject:
		placement = placementHybrid
		detail = "XDP/AF_XDP handles fixed IPv4/UDP TIXU frame RX/TX; secure AEAD remains userspace fallback"
	case status.Available:
		placement = placementFallback
		detail = "UDP/TIXU kernel transport contract is available but fast_path or reinject is not ready"
	}
	if status.Provider != "" {
		detail += "; provider=" + status.Provider
	}
	if status.XDPAttachMode != "" {
		detail += "; xdp_attach_mode=" + status.XDPAttachMode
	}
	if status.AFXDPBindMode != "" {
		detail += "; af_xdp_bind_mode=" + status.AFXDPBindMode
	}
	detail += fmt.Sprintf("; zerocopy_enabled=%t active_flows=%d submitted=%d received=%d",
		status.ZeroCopyEnabled,
		status.ActiveFlows,
		status.SubmittedFrames,
		status.ReceivedFrames,
	)
	detail += fmt.Sprintf("; kernel_crypto=%t", status.KernelCrypto)
	if status.CryptoFallback.Selected != "" {
		detail += "; crypto_backend=" + status.CryptoFallback.Selected
	}
	if status.KernelCryptoReason != "" {
		detail += "; kernel_crypto_reason=" + status.KernelCryptoReason
	}
	return dataPathKernelPlacement{
		Name:      "kernel_udp",
		Layer:     kernelLayerAFXDP,
		Placement: placement,
		Detail:    detail,
	}
}
