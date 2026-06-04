package daemon

import (
	"fmt"
	"strings"

	"trustix.local/trustix/internal/config"
	"trustix.local/trustix/internal/dataplane"
)

const (
	transportPlacementUserspace uint32 = iota
	transportPlacementKernel
	transportPlacementAuto
)

func effectiveTransportCryptoPlacementConfig(policy config.TransportPolicyConfig) string {
	if normalized := normalizeTransportCryptoPlacementConfig(policy.CryptoPlacement); normalized != "" {
		return normalized
	}
	return string(dataplane.CryptoPlacementAuto)
}

func normalizeTransportCryptoPlacementConfig(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "auto":
		return string(dataplane.CryptoPlacementAuto)
	case "kernel":
		return string(dataplane.CryptoPlacementKernel)
	case "userspace":
		return string(dataplane.CryptoPlacementUserspace)
	default:
		return ""
	}
}

func (daemon *Daemon) setTransportCryptoPlacement(policy config.TransportPolicyConfig) {
	daemon.cryptoPlacement.Store(transportPlacementCode(parseTransportCryptoPlacement(effectiveTransportCryptoPlacementConfig(policy))))
}

func (daemon *Daemon) transportCryptoPlacement() dataplane.CryptoPlacement {
	switch daemon.cryptoPlacement.Load() {
	case transportPlacementKernel:
		return dataplane.CryptoPlacementKernel
	case transportPlacementAuto:
		return dataplane.CryptoPlacementAuto
	default:
		return dataplane.CryptoPlacementUserspace
	}
}

func parseTransportCryptoPlacement(raw string) dataplane.CryptoPlacement {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "auto":
		return dataplane.CryptoPlacementAuto
	case "kernel":
		return dataplane.CryptoPlacementKernel
	default:
		return dataplane.CryptoPlacementUserspace
	}
}

func transportPlacementCode(placement dataplane.CryptoPlacement) uint32 {
	switch placement {
	case dataplane.CryptoPlacementKernel:
		return transportPlacementKernel
	case dataplane.CryptoPlacementAuto:
		return transportPlacementAuto
	default:
		return transportPlacementUserspace
	}
}

func (daemon *Daemon) annotateExperimentalTCPStatus(status *dataplane.ExperimentalTCPStatus) {
	if status == nil {
		return
	}
	requested := daemon.transportCryptoPlacement()
	status.RequestedCrypto = requested
	effective, err := effectiveCryptoPlacement("experimental_tcp", requested, cryptoPlacementStatus{
		UserspaceCrypto:    status.UserspaceCrypto,
		KernelCrypto:       status.KernelCrypto,
		KernelCryptoReason: status.KernelCryptoReason,
		PreferredCrypto:    status.PreferredCrypto,
	})
	if err == nil {
		status.EffectiveCrypto = effective
	}
}

func (daemon *Daemon) annotateKernelUDPStatus(status *dataplane.KernelUDPStatus) {
	if status == nil {
		return
	}
	requested := daemon.transportCryptoPlacement()
	status.RequestedCrypto = requested
	effective, err := effectiveCryptoPlacement("kernel_udp", requested, cryptoPlacementStatus{
		UserspaceCrypto:    status.UserspaceCrypto,
		KernelCrypto:       status.KernelCrypto,
		KernelCryptoReason: status.KernelCryptoReason,
		PreferredCrypto:    status.PreferredCrypto,
	})
	if err == nil {
		status.EffectiveCrypto = effective
	}
}

func (daemon *Daemon) experimentalTCPCryptoPlacementAvailable(status dataplane.ExperimentalTCPStatus) error {
	requested := daemon.transportCryptoPlacement()
	_, err := effectiveCryptoPlacement("experimental_tcp", requested, cryptoPlacementStatus{
		UserspaceCrypto:    status.UserspaceCrypto,
		KernelCrypto:       status.KernelCrypto,
		KernelCryptoReason: status.KernelCryptoReason,
		PreferredCrypto:    status.PreferredCrypto,
	})
	return err
}

func (daemon *Daemon) kernelUDPCryptoPlacementAvailable(status dataplane.KernelUDPStatus) error {
	requested := daemon.transportCryptoPlacement()
	_, err := effectiveCryptoPlacement("kernel_udp", requested, cryptoPlacementStatus{
		UserspaceCrypto:    status.UserspaceCrypto,
		KernelCrypto:       status.KernelCrypto,
		KernelCryptoReason: status.KernelCryptoReason,
		PreferredCrypto:    status.PreferredCrypto,
	})
	return err
}

type cryptoPlacementStatus struct {
	UserspaceCrypto    bool
	KernelCrypto       bool
	KernelCryptoReason string
	PreferredCrypto    dataplane.CryptoPlacement
}

func effectiveCryptoPlacement(component string, requested dataplane.CryptoPlacement, status cryptoPlacementStatus) (dataplane.CryptoPlacement, error) {
	switch requested {
	case "", dataplane.CryptoPlacementUserspace:
		if status.UserspaceCrypto {
			return dataplane.CryptoPlacementUserspace, nil
		}
		return "", fmt.Errorf("%s userspace crypto is not available", component)
	case dataplane.CryptoPlacementKernel:
		if status.KernelCrypto {
			return dataplane.CryptoPlacementKernel, nil
		}
		reason := status.KernelCryptoReason
		if reason == "" {
			reason = "kernel crypto provider is not available"
		}
		return "", fmt.Errorf("%s kernel crypto requested but unavailable: %s", component, reason)
	case dataplane.CryptoPlacementAuto:
		if status.PreferredCrypto == dataplane.CryptoPlacementKernel && status.KernelCrypto {
			return dataplane.CryptoPlacementKernel, nil
		}
		if status.UserspaceCrypto {
			return dataplane.CryptoPlacementUserspace, nil
		}
		if status.KernelCrypto {
			return dataplane.CryptoPlacementKernel, nil
		}
		return "", fmt.Errorf("%s has no available crypto placement", component)
	default:
		return "", fmt.Errorf("%s crypto placement %q is unsupported", component, requested)
	}
}

func (daemon *Daemon) experimentalTCPCryptoPlacement() dataplane.CryptoPlacement {
	return daemon.transportCryptoPlacement()
}

func effectiveExperimentalTCPCryptoPlacement(requested dataplane.CryptoPlacement, status dataplane.ExperimentalTCPStatus) (dataplane.CryptoPlacement, error) {
	return effectiveCryptoPlacement("experimental_tcp", requested, cryptoPlacementStatus{
		UserspaceCrypto:    status.UserspaceCrypto,
		KernelCrypto:       status.KernelCrypto,
		KernelCryptoReason: status.KernelCryptoReason,
		PreferredCrypto:    status.PreferredCrypto,
	})
}
