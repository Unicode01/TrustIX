package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/routing"
)

func LoadFile(path string) (Desired, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return Desired{}, fmt.Errorf("read config %q: %w", path, err)
	}
	return LoadBytes(payload, filepath.Ext(path))
}

func LoadBytes(payload []byte, ext string) (Desired, error) {
	cfg, err := DecodeBytes(payload, ext)
	if err != nil {
		return Desired{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Desired{}, err
	}
	return cfg, nil
}

func DecodeBytes(payload []byte, ext string) (Desired, error) {
	var cfg Desired
	switch strings.ToLower(ext) {
	case ".json":
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&cfg); err != nil {
			return Desired{}, fmt.Errorf("decode json config: %w", err)
		}
	default:
		decoder := yaml.NewDecoder(bytes.NewReader(payload))
		decoder.KnownFields(true)
		if err := decoder.Decode(&cfg); err != nil {
			return Desired{}, fmt.Errorf("decode yaml config: %w", err)
		}
	}

	return Normalize(cfg), nil
}

func Normalize(cfg Desired) Desired {
	if cfg.IX.Domain == "" {
		cfg.IX.Domain = cfg.Domain.ID
	}
	cfg.PrimaryLANID = strings.TrimSpace(cfg.PrimaryLANID)
	normalizeTrustConfig(&cfg.Trust)
	normalizeLAN(&cfg.LAN)
	if cfg.LAN.Mode == "" {
		cfg.LAN.Mode = LANModeRouted
	}
	if cfg.LAN.AttachMode == "" {
		cfg.LAN.AttachMode = LANAttachModeManaged
	}
	for i := range cfg.LANs {
		normalizeLAN(&cfg.LANs[i])
		if cfg.LANs[i].Mode == "" {
			cfg.LANs[i].Mode = LANModeRouted
		}
		if cfg.LANs[i].AttachMode == "" {
			cfg.LANs[i].AttachMode = LANAttachModeManaged
		}
		if cfg.LANs[i].Type == "" {
			cfg.LANs[i].Type = LANTypeLocal
		}
	}
	normalizeManagement(&cfg.Management)
	normalizeKernelModules(&cfg.KernelModules)
	for i := range cfg.Endpoints {
		normalizeEndpoint(&cfg.Endpoints[i])
	}
	for i := range cfg.Peers {
		cfg.Peers[i].TLSServerName = strings.TrimSpace(cfg.Peers[i].TLSServerName)
		for j := range cfg.Peers[i].Endpoints {
			normalizeEndpoint(&cfg.Peers[i].Endpoints[j])
		}
		cfg.Peers[i].AllowedPrefixes = normalizePrefixList(cfg.Peers[i].AllowedPrefixes)
	}
	normalizeRoutes(cfg.Routes)
	normalizeRoutePolicy(&cfg.RoutePolicy)
	normalizeTransportPolicy(&cfg.TransportPolicy)
	return cfg
}

func normalizeLAN(lan *LANConfig) {
	if lan == nil {
		return
	}
	lan.ID = strings.TrimSpace(lan.ID)
	lan.Type = normalizeLANType(lan.Type)
	lan.Iface = strings.TrimSpace(lan.Iface)
	lan.UnderlayIface = strings.TrimSpace(lan.UnderlayIface)
	lan.Gateway = strings.TrimSpace(lan.Gateway)
	lan.Advertise = normalizePrefixList(lan.Advertise)
	lan.Mode = LANMode(strings.ToLower(strings.TrimSpace(string(lan.Mode))))
	lan.AttachMode = LANAttachMode(strings.ToLower(strings.ReplaceAll(strings.TrimSpace(string(lan.AttachMode)), "_", "-")))
	lan.NAT.BindingTTL = strings.TrimSpace(lan.NAT.BindingTTL)
	lan.DeviceAccess.AddressPool = strings.TrimSpace(lan.DeviceAccess.AddressPool)
	lan.DeviceAccess.LeaseTTL = strings.TrimSpace(lan.DeviceAccess.LeaseTTL)
}

func normalizeLANType(value LANType) LANType {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(string(value)), "-", "_")) {
	case "", string(LANTypeLocal):
		return LANTypeLocal
	case string(LANTypeTrustedPublic):
		return LANTypeTrustedPublic
	default:
		return LANType(strings.ToLower(strings.ReplaceAll(strings.TrimSpace(string(value)), "-", "_")))
	}
}

func normalizeManagement(management *ManagementConfig) {
	if management == nil {
		return
	}
	management.HostAPI.Listen = strings.TrimSpace(management.HostAPI.Listen)
	management.TLS.Mode = normalizeManagementTLSMode(management.TLS.Mode)
	management.TLS.Identity = normalizeManagementTLSIdentity(management.TLS.Identity)
	management.TLS.CertPath = strings.TrimSpace(management.TLS.CertPath)
	management.TLS.KeyPath = strings.TrimSpace(management.TLS.KeyPath)
	management.WebUI.CustomDir = strings.TrimSpace(management.WebUI.CustomDir)
}

func normalizeKernelModules(modules *KernelModulesConfig) {
	if modules == nil {
		return
	}
	normalizeKernelModule(&modules.TrustIXCrypto)
	normalizeKernelModule(&modules.TrustIXDatapath)
	normalizeKernelModule(&modules.TrustIXDatapathHelpers)
}

func normalizeKernelModule(module *KernelModuleConfig) {
	if module == nil {
		return
	}
	module.Mode = strings.ToLower(strings.TrimSpace(module.Mode))
	module.Path = strings.TrimSpace(module.Path)
	module.Parameters = strings.TrimSpace(module.Parameters)
}

func normalizeEndpoint(ep *EndpointConfig) {
	ep.TLSServerName = strings.TrimSpace(ep.TLSServerName)
	ep.Transport = strings.ToLower(strings.TrimSpace(ep.Transport))
	normalizeEndpointAccess(&ep.Access)
	ep.Security.CryptoSuites = normalizeCryptoSuiteList(ep.Security.CryptoSuites)
	normalizeEndpointProfile(&ep.Profile)
	if ep.Mode != "" {
		return
	}
	switch {
	case strings.TrimSpace(ep.Address) != "" && strings.TrimSpace(ep.Listen) == "":
		ep.Mode = EndpointModeActive
	default:
		ep.Mode = EndpointModePassive
	}
}

func normalizeEndpointAccess(access *EndpointAccessConfig) {
	if access == nil {
		return
	}
	access.Mode = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(access.Mode), "-", "_"))
	access.DefaultTTL = strings.TrimSpace(access.DefaultTTL)
	if len(access.AllowedPeers) > 0 {
		seen := make(map[core.IXID]struct{}, len(access.AllowedPeers))
		out := access.AllowedPeers[:0]
		for _, peer := range access.AllowedPeers {
			peer = core.IXID(strings.TrimSpace(string(peer)))
			if peer == "" {
				continue
			}
			if _, ok := seen[peer]; ok {
				continue
			}
			seen[peer] = struct{}{}
			out = append(out, peer)
		}
		access.AllowedPeers = out
	}
}

func normalizeTransportPolicy(policy *TransportPolicyConfig) {
	if policy == nil {
		return
	}
	policy.Profile = normalizeTransportProfile(policy.Profile)
	policy.Datapath = normalizeTransportDatapath(policy.Datapath)
	policy.FragmentPolicy = strings.ToLower(strings.TrimSpace(policy.FragmentPolicy))
	policy.Encryption = strings.ToLower(strings.TrimSpace(policy.Encryption))
	policy.CryptoKeySource = strings.ToLower(strings.TrimSpace(policy.CryptoKeySource))
	policy.CryptoPlacement = strings.ToLower(strings.TrimSpace(policy.CryptoPlacement))
	policy.CryptoSuites = normalizeCryptoSuiteList(policy.CryptoSuites)
	normalizeTransportAdvanced(&policy.Advanced)
	for i := range policy.Profiles {
		normalizeTransportProfileConfig(&policy.Profiles[i])
	}
	policy.SessionPool.Strategy = strings.ToLower(strings.TrimSpace(policy.SessionPool.Strategy))
	policy.SessionPool.Heartbeat.Mode = strings.ToLower(strings.TrimSpace(policy.SessionPool.Heartbeat.Mode))
	policy.SessionPool.Heartbeat.Interval = strings.TrimSpace(policy.SessionPool.Heartbeat.Interval)
	policy.SessionPool.Heartbeat.Timeout = strings.TrimSpace(policy.SessionPool.Heartbeat.Timeout)
	normalizeTransportTLSIdentity(&policy.TLSIdentity)
	policy.KernelTransport.Mode = strings.ToLower(strings.TrimSpace(policy.KernelTransport.Mode))
	switch policy.KernelTransport.Mode {
	case "prefer-kernel", "prefer":
		policy.KernelTransport.Mode = "prefer_kernel"
	case "require-kernel", "required":
		policy.KernelTransport.Mode = "require_kernel"
	case "off":
		policy.KernelTransport.Mode = "disabled"
	}
}

func normalizeEndpointProfile(profile *EndpointProfileConfig) {
	if profile == nil {
		return
	}
	profile.Profile = normalizeTransportProfile(profile.Profile)
	profile.Datapath = normalizeTransportDatapath(profile.Datapath)
	profile.Encryption = strings.ToLower(strings.TrimSpace(profile.Encryption))
	profile.CryptoPlacement = strings.ToLower(strings.TrimSpace(profile.CryptoPlacement))
	profile.Features = normalizeTransportFeatureList(profile.Features)
}

func normalizeTransportProfileConfig(profile *TransportProfileConfig) {
	if profile == nil {
		return
	}
	profile.Transport = normalizeTransportProfileTransport(profile.Transport)
	profile.Profile = normalizeTransportProfile(profile.Profile)
	profile.Datapath = normalizeTransportDatapath(profile.Datapath)
	profile.Encryption = strings.ToLower(strings.TrimSpace(profile.Encryption))
	profile.CryptoPlacement = strings.ToLower(strings.TrimSpace(profile.CryptoPlacement))
	normalizeTransportAdvanced(&profile.Advanced)
}

func normalizeTransportProfile(value string) string {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "-", "_")) {
	case "", "auto":
		return ""
	case "stable", "safe", "compat", "compatibility":
		return "stable"
	case "performance", "perf", "throughput", "fast":
		return "performance"
	case "latency", "low_latency", "lowlatency", "interactive":
		return "latency"
	default:
		return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "-", "_"))
	}
}

func normalizeTransportDatapath(value string) string {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "-", "_")) {
	case "", "auto":
		return ""
	case "userspace", "user", "raw_socket", "rawsocket":
		return "userspace"
	case "tc_xdp", "tcxdp", "tc", "xdp", "ebpf":
		return "tc_xdp"
	case "kernel_module", "kernel", "module", "ko", "full_kernel":
		return "kernel_module"
	default:
		return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "-", "_"))
	}
}

func normalizeTransportProfileTransport(value string) string {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "-", "_")) {
	case "ackless_tcp", "ackless", "experimental-tcp":
		return "experimental_tcp"
	case "kernel_udp", "kudp":
		return "udp"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func normalizeTransportAdvanced(advanced *TransportAdvancedConfig) {
	if advanced == nil {
		return
	}
	advanced.LargeFrames = normalizeTransportToggle(advanced.LargeFrames)
	advanced.GSO = normalizeTransportToggle(advanced.GSO)
	advanced.GRO = normalizeTransportToggle(advanced.GRO)
	advanced.FlushDelay = strings.TrimSpace(advanced.FlushDelay)
	if len(advanced.Parameters) > 0 {
		normalized := make(map[string]string, len(advanced.Parameters))
		for key, value := range advanced.Parameters {
			key = strings.ToLower(strings.TrimSpace(key))
			value = strings.TrimSpace(value)
			if key == "" {
				continue
			}
			normalized[key] = value
		}
		advanced.Parameters = normalized
	}
}

func normalizeTransportToggle(value string) string {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "-", "_")) {
	case "", "auto":
		return ""
	case "on", "true", "enabled", "enable", "yes":
		return "enabled"
	case "off", "false", "disabled", "disable", "no":
		return "disabled"
	default:
		return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "-", "_"))
	}
}

func normalizeTransportFeatureList(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "-", "_"))
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func normalizeCryptoSuiteList(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		normalized := normalizeCryptoSuiteName(value)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func normalizeCryptoSuiteName(value string) string {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "AES-256-GCM-X25519":
		return "AES-256-GCM-X25519"
	case "AES-128-GCM-X25519":
		return "AES-128-GCM-X25519"
	case "CHACHA20-POLY1305-X25519", "CHACHA20POLY1305-X25519":
		return "CHACHA20-POLY1305-X25519"
	default:
		return strings.TrimSpace(value)
	}
}

func normalizeTransportTLSIdentity(identity *TransportTLSIdentityConfig) {
	if identity == nil {
		return
	}
	identity.Mode = strings.ToLower(strings.TrimSpace(identity.Mode))
	identity.CertPath = strings.TrimSpace(identity.CertPath)
	identity.KeyPath = strings.TrimSpace(identity.KeyPath)
	identity.TrustRoots = trimStringList(identity.TrustRoots)
}

func normalizeRoutePolicy(policy *RoutePolicyConfig) {
	if policy == nil {
		return
	}
	policy.ImportPrefixes = normalizePrefixList(policy.ImportPrefixes)
	policy.ExportPrefixes = normalizePrefixList(policy.ExportPrefixes)
}

func normalizeRoutes(routes []RouteConfig) {
	for i := range routes {
		routes[i].Kind = routing.RouteKind(strings.ToLower(strings.TrimSpace(string(routes[i].Kind))))
		if parsed, err := routes[i].Prefix.Parse(); err == nil {
			routes[i].Prefix = core.Prefix(parsed.Masked().String())
		}
		if routes[i].Kind == "" {
			routes[i].Kind = routing.RouteUnicast
		}
		if routes[i].Owner == "" && routes[i].Kind == routing.RouteUnicast {
			routes[i].Owner = routes[i].NextHop
		}
	}
}

func normalizePrefixList(prefixes []core.Prefix) []core.Prefix {
	if len(prefixes) == 0 {
		return prefixes
	}
	out := make([]core.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		parsed, err := prefix.Parse()
		if err != nil {
			out = append(out, prefix)
			continue
		}
		out = append(out, core.Prefix(parsed.Masked().String()))
	}
	return out
}

func trimStringList(values []string) []string {
	out := values[:0]
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}
