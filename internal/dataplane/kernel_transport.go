package dataplane

import "context"

type KernelTransportMode string

const (
	KernelTransportModeAuto          KernelTransportMode = "auto"
	KernelTransportModePreferKernel  KernelTransportMode = "prefer_kernel"
	KernelTransportModeRequireKernel KernelTransportMode = "require_kernel"
	KernelTransportModeDisabled      KernelTransportMode = "disabled"
)

type KernelTransportStatus struct {
	Mode       KernelTransportMode       `json:"mode"`
	Available  bool                      `json:"available"`
	Provider   string                    `json:"provider,omitempty"`
	Protocols  []KernelTransportProtocol `json:"protocols"`
	Notes      []string                  `json:"notes,omitempty"`
	Statistics map[string]uint64         `json:"statistics,omitempty"`
}

type KernelTransportProtocol struct {
	Protocol          string   `json:"protocol"`
	Available         bool     `json:"available"`
	CapabilityReady   bool     `json:"capability_ready,omitempty"`
	Placement         string   `json:"placement"`
	Provider          string   `json:"provider,omitempty"`
	Carrier           string   `json:"carrier,omitempty"`
	Contract          string   `json:"contract,omitempty"`
	UserspaceFallback bool     `json:"userspace_fallback"`
	RequiredConfig    []string `json:"required_config,omitempty"`
	Reason            string   `json:"reason,omitempty"`
}

type KernelTransportProvider interface {
	KernelTransportStatus(ctx context.Context) (KernelTransportStatus, error)
}
