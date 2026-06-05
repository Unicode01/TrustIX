package config

import (
	"strings"

	"trustix.local/trustix/internal/core"
)

func LANConfigured(lan LANConfig) bool {
	return strings.TrimSpace(lan.Iface) != "" ||
		strings.TrimSpace(lan.ID) != "" ||
		lan.Type != "" && lan.Type != LANTypeLocal ||
		strings.TrimSpace(lan.UnderlayIface) != "" ||
		strings.TrimSpace(lan.Gateway) != "" ||
		len(lan.Advertise) > 0 ||
		lan.Mode == LANModeNAT ||
		lan.Mode != "" && lan.Mode != LANModeRouted ||
		lan.NAT.MaxBindings > 0 ||
		strings.TrimSpace(lan.NAT.BindingTTL) != "" ||
		lan.DeviceAccess.Enabled ||
		strings.TrimSpace(lan.DeviceAccess.AddressPool) != "" ||
		strings.TrimSpace(lan.DeviceAccess.LeaseTTL) != "" ||
		lan.ManageAddress ||
		lan.ManageForwarding ||
		lan.ManageRPFilter
}

func EffectiveLANs(desired Desired) []LANConfig {
	out := make([]LANConfig, 0, 1+len(desired.LANs))
	if LANConfigured(desired.LAN) {
		out = append(out, withLANDefaults(desired.LAN, DefaultLANID))
	}
	for _, lan := range desired.LANs {
		out = append(out, withLANDefaults(lan, ""))
	}
	return out
}

func PrimaryLAN(desired Desired) LANConfig {
	if id := strings.TrimSpace(desired.PrimaryLANID); id != "" {
		for _, lan := range EffectiveLANs(desired) {
			if lan.ID == id {
				return lan
			}
		}
	}
	if LANConfigured(desired.LAN) {
		return withLANDefaults(desired.LAN, DefaultLANID)
	}
	if len(desired.LANs) > 0 {
		return withLANDefaults(desired.LANs[0], "")
	}
	return withLANDefaults(desired.LAN, DefaultLANID)
}

func FirstLANGatewayLAN(desired Desired) (LANConfig, bool) {
	for _, lan := range EffectiveLANs(desired) {
		if strings.TrimSpace(lan.Gateway) != "" {
			return lan, true
		}
	}
	return LANConfig{}, false
}

func DeviceAccessLAN(desired Desired) (LANConfig, bool) {
	lans := DeviceAccessLANs(desired)
	if len(lans) == 0 {
		return LANConfig{}, false
	}
	return lans[0], true
}

func DeviceAccessLANs(desired Desired) []LANConfig {
	out := make([]LANConfig, 0)
	for _, lan := range EffectiveLANs(desired) {
		if lan.DeviceAccess.Enabled {
			out = append(out, lan)
		}
	}
	return out
}

func DeviceAccessLANByID(desired Desired, id string) (LANConfig, bool) {
	id = strings.TrimSpace(id)
	if id == "" {
		return DeviceAccessLAN(desired)
	}
	for _, lan := range DeviceAccessLANs(desired) {
		if lan.ID == id {
			return lan, true
		}
	}
	return LANConfig{}, false
}

func EffectiveLANAdvertise(desired Desired) []core.Prefix {
	lans := EffectiveLANs(desired)
	out := make([]core.Prefix, 0)
	seen := make(map[string]struct{})
	for _, lan := range lans {
		for _, prefix := range lan.Advertise {
			key := strings.TrimSpace(string(prefix))
			if key == "" {
				continue
			}
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, prefix)
		}
	}
	return out
}

func withLANDefaults(lan LANConfig, defaultID string) LANConfig {
	if strings.TrimSpace(lan.ID) == "" && defaultID != "" {
		lan.ID = defaultID
	}
	if lan.Type == "" {
		lan.Type = LANTypeLocal
	}
	if lan.Mode == "" {
		lan.Mode = LANModeRouted
	}
	if lan.AttachMode == "" {
		lan.AttachMode = LANAttachModeManaged
	}
	return lan
}
