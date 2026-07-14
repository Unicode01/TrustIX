package daemon

import (
	"context"
	"fmt"
	"strings"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/dataplane"
	"trustix.local/trustix/internal/transport"
	securetransport "trustix.local/trustix/internal/transport/secure"
)

func normalizeKernelTransportMode(raw string) dataplane.KernelTransportMode {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "prefer_kernel", "prefer-kernel", "prefer":
		return dataplane.KernelTransportModePreferKernel
	case "require_kernel", "require-kernel", "required":
		return dataplane.KernelTransportModeRequireKernel
	case "disabled", "off":
		return dataplane.KernelTransportModeDisabled
	default:
		return dataplane.KernelTransportModeAuto
	}
}

func (daemon *Daemon) kernelTransportMode() dataplane.KernelTransportMode {
	return effectiveKernelTransportModeForDesired(daemon.desired)
}

func effectiveKernelTransportModeForDesired(desired config.Desired) dataplane.KernelTransportMode {
	mode, explicit := effectiveKernelTransportModeConfig(desired.TransportPolicy.KernelTransport.Mode)
	if mode == dataplane.KernelTransportModeDisabled {
		return mode
	}
	if tixTCPRouteGSOAsyncForDesired(desired) {
		return dataplane.KernelTransportModeRequireKernel
	}
	if !explicit && mode == dataplane.KernelTransportModeAuto && desiredTransportPolicyUsesOnlyUserspaceUDP(desired) {
		return dataplane.KernelTransportModeDisabled
	}
	if !explicit && mode == dataplane.KernelTransportModeAuto && desiredTransportPolicyUsesOnlyUserspaceTIXTCP(desired) {
		return dataplane.KernelTransportModeDisabled
	}
	if !explicit && mode == dataplane.KernelTransportModeAuto && desiredTransportPolicyUsesSecureUserspaceKernelUDP(desired) {
		return dataplane.KernelTransportModeDisabled
	}
	if !explicit && mode == dataplane.KernelTransportModeAuto && desiredTransportPolicyUsesOnlySecureUserspaceTIXTCP(desired) {
		return dataplane.KernelTransportModeDisabled
	}
	return mode
}

func effectiveKernelTransportModeConfig(raw string) (dataplane.KernelTransportMode, bool) {
	if strings.TrimSpace(raw) == "" {
		return dataplane.KernelTransportModeAuto, false
	}
	return normalizeKernelTransportMode(raw), true
}

func desiredTransportPolicyUsesOnlyUserspaceUDP(desired config.Desired) bool {
	if !desiredTransportPolicyUsesAnyProtocol(desired, transport.ProtocolUDP) {
		return false
	}
	if desiredTransportPolicyUsesAnyProtocol(desired, transport.ProtocolTIXTCP) {
		return false
	}
	profile := config.EffectiveTransportProfile(desired.TransportPolicy, string(transport.ProtocolUDP))
	return profile.Datapath == config.TransportDatapathUserspace
}

func desiredTransportPolicyUsesOnlyUserspaceTIXTCP(desired config.Desired) bool {
	if !desiredTransportPolicyUsesAnyProtocol(desired, transport.ProtocolTIXTCP) {
		return false
	}
	if desiredTransportPolicyUsesAnyProtocol(desired,
		transport.ProtocolUDP,
		transport.ProtocolGRE,
		transport.ProtocolIPIP,
		transport.ProtocolVXLAN,
	) {
		return false
	}
	profile := config.EffectiveTransportProfile(desired.TransportPolicy, string(transport.ProtocolTIXTCP))
	return profile.Datapath == config.TransportDatapathUserspace
}

func desiredTransportPolicyUsesSecureUserspaceKernelUDP(desired config.Desired) bool {
	if !desiredTransportPolicyUsesAnyProtocol(desired, transport.ProtocolUDP) {
		return false
	}
	if desiredTransportPolicyUsesAnyProtocol(desired, transport.ProtocolTIXTCP) {
		return false
	}
	profile := config.EffectiveTransportProfile(desired.TransportPolicy, string(transport.ProtocolUDP))
	if profile.Datapath == config.TransportDatapathUserspace {
		return false
	}
	if parseSecureTransportEncryption(profile.Encryption) != securetransport.EncryptionSecure {
		return false
	}
	placement := normalizeTransportCryptoPlacementConfig(profile.CryptoPlacement)
	if placement == "" {
		placement = effectiveTransportCryptoPlacementConfig(desired.TransportPolicy)
	}
	return placement == string(dataplane.CryptoPlacementUserspace)
}

func desiredTransportPolicyUsesSecureUserspaceTIXTCP(desired config.Desired) bool {
	if !desiredTransportPolicyUsesAnyProtocol(desired, transport.ProtocolTIXTCP) {
		return false
	}
	profile := config.EffectiveTransportProfile(desired.TransportPolicy, string(transport.ProtocolTIXTCP))
	if profile.Datapath == config.TransportDatapathUserspace {
		return false
	}
	if parseSecureTransportEncryption(profile.Encryption) != securetransport.EncryptionSecure {
		return false
	}
	placement := normalizeTransportCryptoPlacementConfig(profile.CryptoPlacement)
	if placement == "" {
		placement = effectiveTransportCryptoPlacementConfig(desired.TransportPolicy)
	}
	return placement == string(dataplane.CryptoPlacementUserspace)
}

func desiredTransportPolicyUsesOnlySecureUserspaceTIXTCP(desired config.Desired) bool {
	if !desiredTransportPolicyUsesSecureUserspaceTIXTCP(desired) {
		return false
	}
	return !desiredTransportPolicyUsesAnyProtocol(desired,
		transport.ProtocolUDP,
		transport.ProtocolGRE,
		transport.ProtocolIPIP,
		transport.ProtocolVXLAN,
	)
}

func (daemon *Daemon) annotateKernelTransportStatus(status *dataplane.KernelTransportStatus) {
	if status == nil {
		return
	}
	status.Mode = daemon.kernelTransportMode()
}

func (daemon *Daemon) kernelTransportProtocolStatus(protocol transport.Protocol) (dataplane.KernelTransportProtocol, bool) {
	provider, ok := daemon.dataplane.(dataplane.KernelTransportProvider)
	if !ok {
		return dataplane.KernelTransportProtocol{}, false
	}
	status, err := provider.KernelTransportStatus(context.Background())
	if err != nil {
		return dataplane.KernelTransportProtocol{}, false
	}
	for _, item := range status.Protocols {
		if item.Protocol == string(protocol) {
			return item, true
		}
	}
	return dataplane.KernelTransportProtocol{}, false
}

func (daemon *Daemon) endpointKernelTransportCompatible(endpointTransport string) bool {
	mode := daemon.kernelTransportMode()
	if mode != dataplane.KernelTransportModeRequireKernel {
		return true
	}
	if daemon.endpointKernelTransportPendingCompatible(endpointTransport) {
		return true
	}
	item, ok := daemon.kernelTransportProtocolStatus(transport.Protocol(endpointTransport))
	return ok && item.Available
}

func (daemon *Daemon) endpointKernelTransportPendingCompatible(endpointTransport string) bool {
	if transport.Protocol(strings.ToLower(strings.TrimSpace(endpointTransport))) != transport.ProtocolUDP {
		return false
	}
	return daemon.kernelUDPTCOnlyProviderRequested() && !daemon.transportPolicySendsSecureData()
}

func (daemon *Daemon) kernelTransportRequirementError(endpointTransport string) error {
	if daemon.endpointKernelTransportPendingCompatible(endpointTransport) {
		return fmt.Errorf("transport_policy kernel_transport mode requires kernel transport for %q: kernel_udp TC-only provider is pending route/flow warmup", endpointTransport)
	}
	item, ok := daemon.kernelTransportProtocolStatus(transport.Protocol(endpointTransport))
	if ok && item.Reason != "" {
		return fmt.Errorf("transport_policy kernel_transport mode requires kernel transport for %q: %s", endpointTransport, item.Reason)
	}
	return fmt.Errorf("transport_policy kernel_transport mode requires kernel transport for %q", endpointTransport)
}
