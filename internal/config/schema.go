// Package config defines the desired configuration schema consumed by the
// control plane. Loading formats such as YAML are intentionally kept outside
// this package so signed events remain the source of truth.
package config

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/pki"
	"trustix.local/trustix/internal/routing"
)

type Desired struct {
	Domain          DomainConfig          `json:"domain" yaml:"domain"`
	IX              IXConfig              `json:"ix" yaml:"ix"`
	PrimaryLANID    string                `json:"primary_lan_id,omitempty" yaml:"primary_lan_id,omitempty"`
	LAN             LANConfig             `json:"lan" yaml:"lan"`
	LANs            []LANConfig           `json:"lans,omitempty" yaml:"lans,omitempty"`
	Management      ManagementConfig      `json:"management,omitempty" yaml:"management,omitempty"`
	KernelModules   KernelModulesConfig   `json:"kernel_modules,omitempty" yaml:"kernel_modules,omitempty"`
	Trust           TrustConfig           `json:"trust,omitempty" yaml:"trust,omitempty"`
	Endpoints       []EndpointConfig      `json:"endpoints" yaml:"endpoints"`
	Bootstrap       BootstrapConfig       `json:"bootstrap,omitempty" yaml:"bootstrap,omitempty"`
	Peers           []PeerConfig          `json:"peers" yaml:"peers"`
	Routes          []RouteConfig         `json:"routes" yaml:"routes"`
	RoutePolicy     RoutePolicyConfig     `json:"route_policy,omitempty" yaml:"route_policy,omitempty"`
	Policies        []PolicyConfig        `json:"policies" yaml:"policies"`
	TransportPolicy TransportPolicyConfig `json:"transport_policy" yaml:"transport_policy"`
}

type DomainConfig struct {
	ID         core.DomainID `json:"id" yaml:"id"`
	TrustRoots []string      `json:"trust_roots" yaml:"trust_roots"`
}

type IXConfig struct {
	ID                  core.IXID     `json:"id" yaml:"id"`
	Domain              core.DomainID `json:"domain" yaml:"domain"`
	CertPath            string        `json:"cert" yaml:"cert"`
	KeyPath             string        `json:"key" yaml:"key"`
	ControlAPI          string        `json:"control_api,omitempty" yaml:"control_api,omitempty"`
	ConfigLog           string        `json:"config_log" yaml:"config_log"`
	RouteAuthorizations []string      `json:"route_authorizations" yaml:"route_authorizations"`
}

type TrustConfig struct {
	RevokedCertFingerprints []string          `json:"revoked_cert_fingerprints,omitempty" yaml:"revoked_cert_fingerprints,omitempty"`
	TrustRootsPEM           []string          `json:"trust_roots_pem,omitempty" yaml:"trust_roots_pem,omitempty"`
	AdminPolicy             AdminPolicyConfig `json:"admin_policy,omitempty" yaml:"admin_policy,omitempty"`
}

type AdminPolicyConfig struct {
	Threshold           int      `json:"threshold,omitempty" yaml:"threshold,omitempty"`
	AllowedFingerprints []string `json:"allowed_fingerprints,omitempty" yaml:"allowed_fingerprints,omitempty"`
}

type LANConfig struct {
	ID               string             `json:"id,omitempty" yaml:"id,omitempty"`
	Type             LANType            `json:"type,omitempty" yaml:"type,omitempty"`
	Iface            string             `json:"iface" yaml:"iface"`
	UnderlayIface    string             `json:"underlay_iface,omitempty" yaml:"underlay_iface,omitempty"`
	Gateway          string             `json:"gateway" yaml:"gateway"`
	Advertise        []core.Prefix      `json:"advertise" yaml:"advertise"`
	Mode             LANMode            `json:"mode" yaml:"mode"`
	AttachMode       LANAttachMode      `json:"attach_mode,omitempty" yaml:"attach_mode,omitempty"`
	NAT              NATConfig          `json:"nat,omitempty" yaml:"nat,omitempty"`
	DeviceAccess     DeviceAccessConfig `json:"device_access,omitempty" yaml:"device_access,omitempty"`
	ManageAddress    bool               `json:"manage_address" yaml:"manage_address"`
	ManageForwarding bool               `json:"manage_forwarding" yaml:"manage_forwarding"`
	ManageRPFilter   bool               `json:"manage_rp_filter" yaml:"manage_rp_filter"`
}

type NATConfig struct {
	MaxBindings int    `json:"max_bindings,omitempty" yaml:"max_bindings,omitempty"`
	BindingTTL  string `json:"binding_ttl,omitempty" yaml:"binding_ttl,omitempty"`
}

type DeviceAccessConfig struct {
	Enabled     bool   `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	AddressPool string `json:"address_pool,omitempty" yaml:"address_pool,omitempty"`
	LeaseTTL    string `json:"lease_ttl,omitempty" yaml:"lease_ttl,omitempty"`
}

type ManagementConfig struct {
	HostAPI HostManagementAPIConfig `json:"host_api,omitempty" yaml:"host_api,omitempty"`
	TLS     ManagementTLSConfig     `json:"tls,omitempty" yaml:"tls,omitempty"`
	WebUI   WebUIConfig             `json:"web_ui,omitempty" yaml:"web_ui,omitempty"`
}

type ManagementTLSConfig struct {
	Mode     string `json:"mode,omitempty" yaml:"mode,omitempty"`
	Identity string `json:"identity,omitempty" yaml:"identity,omitempty"`
	CertPath string `json:"cert,omitempty" yaml:"cert,omitempty"`
	KeyPath  string `json:"key,omitempty" yaml:"key,omitempty"`
}

type HostManagementAPIConfig struct {
	Enabled                    bool   `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Listen                     string `json:"listen,omitempty" yaml:"listen,omitempty"`
	RequireReadAuth            bool   `json:"require_read_auth,omitempty" yaml:"require_read_auth,omitempty"`
	AllowUnauthenticatedReads  bool   `json:"allow_unauthenticated_reads,omitempty" yaml:"allow_unauthenticated_reads,omitempty"`
	AllowUnauthenticatedWrites bool   `json:"allow_unauthenticated_writes,omitempty" yaml:"allow_unauthenticated_writes,omitempty"`
}

type WebUIConfig struct {
	Enabled   bool   `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	CustomDir string `json:"custom_dir,omitempty" yaml:"custom_dir,omitempty"`
}

type LANMode string

const (
	LANModeRouted LANMode = "routed"
	LANModeNAT    LANMode = "nat"
)

type LANType string

const (
	DefaultLANID         = "lan"
	LANTypeLocal         = LANType("local")
	LANTypeTrustedPublic = LANType("trusted_public")
)

type LANAttachMode string

const (
	LANAttachModeManaged  LANAttachMode = "managed"
	LANAttachModeExisting LANAttachMode = "existing"
)

type KernelModulesConfig struct {
	TrustIXCrypto          KernelModuleConfig `json:"trustix_crypto,omitempty" yaml:"trustix_crypto,omitempty"`
	TrustIXDatapath        KernelModuleConfig `json:"trustix_datapath,omitempty" yaml:"trustix_datapath,omitempty"`
	TrustIXDatapathHelpers KernelModuleConfig `json:"trustix_datapath_helpers,omitempty" yaml:"trustix_datapath_helpers,omitempty"`
}

type KernelModuleConfig struct {
	Mode         string `json:"mode,omitempty" yaml:"mode,omitempty"`
	Path         string `json:"path,omitempty" yaml:"path,omitempty"`
	Parameters   string `json:"parameters,omitempty" yaml:"parameters,omitempty"`
	UnloadOnExit bool   `json:"unload_on_exit,omitempty" yaml:"unload_on_exit,omitempty"`
}

type EndpointConfig struct {
	Name          core.EndpointID         `json:"name" yaml:"name"`
	Mode          EndpointMode            `json:"mode" yaml:"mode"`
	Listen        string                  `json:"listen,omitempty" yaml:"listen,omitempty"`
	Address       string                  `json:"address,omitempty" yaml:"address,omitempty"`
	LocalBind     EndpointLocalBindConfig `json:"local_bind,omitempty" yaml:"local_bind,omitempty"`
	Transport     string                  `json:"transport" yaml:"transport"`
	Priority      int                     `json:"priority,omitempty" yaml:"priority,omitempty"`
	TLSServerName string                  `json:"tls_server_name,omitempty" yaml:"tls_server_name,omitempty"`
	Publish       EndpointPublishConfig   `json:"publish,omitempty" yaml:"publish,omitempty"`
	Access        EndpointAccessConfig    `json:"access,omitempty" yaml:"access,omitempty"`
	Security      EndpointSecurityConfig  `json:"security,omitempty" yaml:"security,omitempty"`
	Profile       EndpointProfileConfig   `json:"transport_profile,omitempty" yaml:"transport_profile,omitempty"`
	Enabled       bool                    `json:"enabled" yaml:"enabled"`
	EnabledSet    bool                    `json:"-" yaml:"-"`
}

func (endpoint *EndpointConfig) UnmarshalJSON(payload []byte) error {
	type endpointConfig EndpointConfig
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return err
	}
	var decoded endpointConfig
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return err
	}
	*endpoint = EndpointConfig(decoded)
	_, endpoint.EnabledSet = raw["enabled"]
	return nil
}

func (endpoint *EndpointConfig) UnmarshalYAML(value *yaml.Node) error {
	type endpointConfig EndpointConfig
	var decoded endpointConfig
	if err := value.Decode(&decoded); err != nil {
		return err
	}
	*endpoint = EndpointConfig(decoded)
	endpoint.EnabledSet = false
	if value.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(value.Content); index += 2 {
		if value.Content[index].Value == "enabled" {
			endpoint.EnabledSet = true
			break
		}
	}
	return nil
}

type EndpointMode string

const (
	EndpointModeActive  EndpointMode = "active"
	EndpointModePassive EndpointMode = "passive"
)

type EndpointLocalBindConfig struct {
	SourceIP string `json:"source_ip,omitempty" yaml:"source_ip,omitempty"`
	Iface    string `json:"iface,omitempty" yaml:"iface,omitempty"`
}

type EndpointSecurityConfig struct {
	LinkTLS          string   `json:"link_tls,omitempty" yaml:"link_tls,omitempty"`
	TLSIdentity      string   `json:"tls_identity,omitempty" yaml:"tls_identity,omitempty"`
	Encryption       string   `json:"encryption,omitempty" yaml:"encryption,omitempty"`
	KeySources       []string `json:"key_sources,omitempty" yaml:"key_sources,omitempty"`
	WireFormat       string   `json:"wire_format,omitempty" yaml:"wire_format,omitempty"`
	CryptoSuites     []string `json:"crypto_suites,omitempty" yaml:"crypto_suites,omitempty"`
	CryptoPlacements []string `json:"crypto_placements,omitempty" yaml:"crypto_placements,omitempty"`
}

type EndpointPublishConfig struct {
	Mode        string          `json:"mode,omitempty" yaml:"mode,omitempty"`
	OnlyPeers   []core.IXID     `json:"only_peers,omitempty" yaml:"only_peers,omitempty"`
	ExceptPeers []core.IXID     `json:"except_peers,omitempty" yaml:"except_peers,omitempty"`
	Domains     []core.DomainID `json:"domains,omitempty" yaml:"domains,omitempty"`
}

type EndpointAccessConfig struct {
	Mode         string      `json:"mode,omitempty" yaml:"mode,omitempty"`
	AllowedPeers []core.IXID `json:"allowed_peers,omitempty" yaml:"allowed_peers,omitempty"`
	DefaultTTL   string      `json:"default_ttl,omitempty" yaml:"default_ttl,omitempty"`
}

type EndpointProfileConfig struct {
	Version         int      `json:"version,omitempty" yaml:"version,omitempty"`
	Profile         string   `json:"profile,omitempty" yaml:"profile,omitempty"`
	Datapath        string   `json:"datapath,omitempty" yaml:"datapath,omitempty"`
	Encryption      string   `json:"encryption,omitempty" yaml:"encryption,omitempty"`
	CryptoPlacement string   `json:"crypto_placement,omitempty" yaml:"crypto_placement,omitempty"`
	Features        []string `json:"features,omitempty" yaml:"features,omitempty"`
}

type BootstrapConfig struct {
	Peers []BootstrapPeerConfig `json:"peers,omitempty" yaml:"peers,omitempty"`
}

type BootstrapPeerConfig struct {
	ID         core.IXID     `json:"id,omitempty" yaml:"id,omitempty"`
	Domain     core.DomainID `json:"domain,omitempty" yaml:"domain,omitempty"`
	ControlAPI string        `json:"control_api" yaml:"control_api"`
}

type PeerConfig struct {
	ID              core.IXID        `json:"id" yaml:"id"`
	Domain          core.DomainID    `json:"domain" yaml:"domain"`
	ControlAPI      string           `json:"control_api,omitempty" yaml:"control_api,omitempty"`
	TLSServerName   string           `json:"tls_server_name,omitempty" yaml:"tls_server_name,omitempty"`
	Endpoints       []EndpointConfig `json:"endpoints" yaml:"endpoints"`
	AllowedPrefixes []core.Prefix    `json:"allowed_prefixes" yaml:"allowed_prefixes"`
}

type RouteConfig struct {
	Prefix   core.Prefix       `json:"prefix" yaml:"prefix"`
	Kind     routing.RouteKind `json:"kind,omitempty" yaml:"kind,omitempty"`
	Owner    core.IXID         `json:"owner,omitempty" yaml:"owner,omitempty"`
	NextHop  core.IXID         `json:"next_hop,omitempty" yaml:"next_hop,omitempty"`
	Endpoint core.EndpointID   `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`
	Policy   core.PolicyID     `json:"policy" yaml:"policy"`
	Metric   int               `json:"metric" yaml:"metric"`
}

type PolicyConfig struct {
	Name           core.PolicyID `json:"name" yaml:"name"`
	RouteSelection string        `json:"route_selection,omitempty" yaml:"route_selection,omitempty"`
	LoadBalance    string        `json:"load_balance,omitempty" yaml:"load_balance,omitempty"`
	FlowStickiness bool          `json:"flow_stickiness,omitempty" yaml:"flow_stickiness,omitempty"`
	Rewrite        string        `json:"rewrite,omitempty" yaml:"rewrite,omitempty"`
}

type RoutePolicyConfig struct {
	ImportPrefixes []core.Prefix `json:"import_prefixes,omitempty" yaml:"import_prefixes,omitempty"`
	ExportPrefixes []core.Prefix `json:"export_prefixes,omitempty" yaml:"export_prefixes,omitempty"`
	DynamicMetric  int           `json:"dynamic_metric,omitempty" yaml:"dynamic_metric,omitempty"`
}

type TransportPolicyConfig struct {
	Mode            string                      `json:"mode" yaml:"mode"`
	Candidates      []core.EndpointID           `json:"candidates" yaml:"candidates"`
	Failover        string                      `json:"failover" yaml:"failover"`
	LoadBalance     string                      `json:"load_balance" yaml:"load_balance"`
	Profile         string                      `json:"profile,omitempty" yaml:"profile,omitempty"`
	Datapath        string                      `json:"datapath,omitempty" yaml:"datapath,omitempty"`
	MTU             int                         `json:"mtu,omitempty" yaml:"mtu,omitempty"`
	FragmentPolicy  string                      `json:"fragment_policy,omitempty" yaml:"fragment_policy,omitempty"`
	Encryption      string                      `json:"encryption,omitempty" yaml:"encryption,omitempty"`
	CryptoKeySource string                      `json:"crypto_key_source,omitempty" yaml:"crypto_key_source,omitempty"`
	CryptoSuites    []string                    `json:"crypto_suites,omitempty" yaml:"crypto_suites,omitempty"`
	CryptoPlacement string                      `json:"crypto_placement,omitempty" yaml:"crypto_placement,omitempty"`
	Profiles        []TransportProfileConfig    `json:"profiles,omitempty" yaml:"profiles,omitempty"`
	Advanced        TransportAdvancedConfig     `json:"advanced,omitempty" yaml:"advanced,omitempty"`
	SessionPool     SessionPoolPolicyConfig     `json:"session_pool,omitempty" yaml:"session_pool,omitempty"`
	TLSIdentity     TransportTLSIdentityConfig  `json:"tls_identity,omitempty" yaml:"tls_identity,omitempty"`
	KernelTransport KernelTransportPolicyConfig `json:"kernel_transport,omitempty" yaml:"kernel_transport,omitempty"`
}

type TransportProfileConfig struct {
	Transport       string                  `json:"transport" yaml:"transport"`
	Profile         string                  `json:"profile,omitempty" yaml:"profile,omitempty"`
	Datapath        string                  `json:"datapath,omitempty" yaml:"datapath,omitempty"`
	Encryption      string                  `json:"encryption,omitempty" yaml:"encryption,omitempty"`
	CryptoPlacement string                  `json:"crypto_placement,omitempty" yaml:"crypto_placement,omitempty"`
	Advanced        TransportAdvancedConfig `json:"advanced,omitempty" yaml:"advanced,omitempty"`
}

type TransportAdvancedConfig struct {
	AllowUnsafe         bool              `json:"allow_unsafe,omitempty" yaml:"allow_unsafe,omitempty"`
	AllowOuterGSOUnsafe bool              `json:"allow_outer_gso_unsafe,omitempty" yaml:"allow_outer_gso_unsafe,omitempty"`
	AllowChecksumSkip   bool              `json:"allow_checksum_skip,omitempty" yaml:"allow_checksum_skip,omitempty"`
	LargeFrames         string            `json:"large_frames,omitempty" yaml:"large_frames,omitempty"`
	GSO                 string            `json:"gso,omitempty" yaml:"gso,omitempty"`
	GRO                 string            `json:"gro,omitempty" yaml:"gro,omitempty"`
	Shards              int               `json:"shards,omitempty" yaml:"shards,omitempty"`
	MaxFrames           int               `json:"max_frames,omitempty" yaml:"max_frames,omitempty"`
	BatchBytes          int               `json:"batch_bytes,omitempty" yaml:"batch_bytes,omitempty"`
	FlushDelay          string            `json:"flush_delay,omitempty" yaml:"flush_delay,omitempty"`
	Parameters          map[string]string `json:"parameters,omitempty" yaml:"parameters,omitempty"`
}

type SessionPoolPolicyConfig struct {
	Size      int                        `json:"size,omitempty" yaml:"size,omitempty"`
	Strategy  string                     `json:"strategy,omitempty" yaml:"strategy,omitempty"`
	Warmup    bool                       `json:"warmup,omitempty" yaml:"warmup,omitempty"`
	Heartbeat SessionPoolHeartbeatConfig `json:"heartbeat,omitempty" yaml:"heartbeat,omitempty"`
}

type SessionPoolHeartbeatConfig struct {
	Mode     string `json:"mode,omitempty" yaml:"mode,omitempty"`
	Interval string `json:"interval,omitempty" yaml:"interval,omitempty"`
	Timeout  string `json:"timeout,omitempty" yaml:"timeout,omitempty"`
}

type KernelTransportPolicyConfig struct {
	Mode string `json:"mode,omitempty" yaml:"mode,omitempty"`
}

type TransportTLSIdentityConfig struct {
	Mode        string   `json:"mode,omitempty" yaml:"mode,omitempty"`
	CertPath    string   `json:"cert,omitempty" yaml:"cert,omitempty"`
	KeyPath     string   `json:"key,omitempty" yaml:"key,omitempty"`
	TrustRoots  []string `json:"trust_roots,omitempty" yaml:"trust_roots,omitempty"`
	SystemRoots bool     `json:"system_roots,omitempty" yaml:"system_roots,omitempty"`
}

const (
	TransportProfileStable      = "stable"
	TransportProfilePerformance = "performance"
	TransportProfileLatency     = "latency"

	TransportDatapathAuto         = "auto"
	TransportDatapathUserspace    = "userspace"
	TransportDatapathTCXDP        = "tc_xdp"
	TransportDatapathKernelModule = "kernel_module"
)

func EffectiveTransportProfile(policy TransportPolicyConfig, rawTransport string) TransportProfileConfig {
	transportName := normalizeTransportProfileTransport(rawTransport)
	effective := TransportProfileConfig{
		Transport:       transportName,
		Profile:         effectiveTransportProfileName(policy.Profile),
		Datapath:        effectiveTransportDatapath(policy.Datapath),
		Encryption:      strings.ToLower(strings.TrimSpace(policy.Encryption)),
		CryptoPlacement: strings.ToLower(strings.TrimSpace(policy.CryptoPlacement)),
		Advanced:        policy.Advanced,
	}
	for _, candidate := range policy.Profiles {
		if normalizeTransportProfileTransport(candidate.Transport) != transportName {
			continue
		}
		if candidate.Profile != "" {
			effective.Profile = effectiveTransportProfileName(candidate.Profile)
		}
		if candidate.Datapath != "" {
			effective.Datapath = effectiveTransportDatapath(candidate.Datapath)
		}
		if strings.TrimSpace(candidate.Encryption) != "" {
			effective.Encryption = strings.ToLower(strings.TrimSpace(candidate.Encryption))
		}
		if strings.TrimSpace(candidate.CryptoPlacement) != "" {
			effective.CryptoPlacement = strings.ToLower(strings.TrimSpace(candidate.CryptoPlacement))
		}
		effective.Advanced = mergeTransportAdvanced(effective.Advanced, candidate.Advanced)
	}
	return effective
}

func EffectiveEndpointProfile(endpoint EndpointConfig, policy TransportPolicyConfig) EndpointProfileConfig {
	base := EffectiveTransportProfile(policy, endpoint.Transport)
	effective := EndpointProfileConfig{
		Profile:         base.Profile,
		Datapath:        base.Datapath,
		Encryption:      base.Encryption,
		CryptoPlacement: base.CryptoPlacement,
	}
	if endpoint.Profile.Version > 0 {
		effective.Version = endpoint.Profile.Version
	}
	if endpoint.Profile.Profile != "" {
		effective.Profile = effectiveTransportProfileName(endpoint.Profile.Profile)
	}
	if endpoint.Profile.Datapath != "" {
		effective.Datapath = effectiveTransportDatapath(endpoint.Profile.Datapath)
	}
	if strings.TrimSpace(endpoint.Profile.Encryption) != "" {
		effective.Encryption = strings.ToLower(strings.TrimSpace(endpoint.Profile.Encryption))
	}
	if strings.TrimSpace(endpoint.Profile.CryptoPlacement) != "" {
		effective.CryptoPlacement = strings.ToLower(strings.TrimSpace(endpoint.Profile.CryptoPlacement))
	}
	if len(endpoint.Profile.Features) > 0 {
		effective.Features = append([]string(nil), endpoint.Profile.Features...)
	}
	return effective
}

func effectiveTransportProfileName(value string) string {
	if normalized := normalizeTransportProfile(value); normalized != "" {
		return normalized
	}
	return TransportProfileStable
}

func effectiveTransportDatapath(value string) string {
	if normalized := normalizeTransportDatapath(value); normalized != "" {
		return normalized
	}
	return TransportDatapathAuto
}

func mergeTransportAdvanced(base, override TransportAdvancedConfig) TransportAdvancedConfig {
	merged := base
	merged.AllowUnsafe = merged.AllowUnsafe || override.AllowUnsafe
	merged.AllowOuterGSOUnsafe = merged.AllowOuterGSOUnsafe || override.AllowOuterGSOUnsafe
	merged.AllowChecksumSkip = merged.AllowChecksumSkip || override.AllowChecksumSkip
	if override.LargeFrames != "" {
		merged.LargeFrames = override.LargeFrames
	}
	if override.GSO != "" {
		merged.GSO = override.GSO
	}
	if override.GRO != "" {
		merged.GRO = override.GRO
	}
	if override.Shards > 0 {
		merged.Shards = override.Shards
	}
	if override.MaxFrames > 0 {
		merged.MaxFrames = override.MaxFrames
	}
	if override.BatchBytes > 0 {
		merged.BatchBytes = override.BatchBytes
	}
	if strings.TrimSpace(override.FlushDelay) != "" {
		merged.FlushDelay = override.FlushDelay
	}
	if len(override.Parameters) > 0 {
		if len(merged.Parameters) == 0 {
			merged.Parameters = make(map[string]string, len(override.Parameters))
		} else {
			copied := make(map[string]string, len(merged.Parameters)+len(override.Parameters))
			for key, value := range merged.Parameters {
				copied[key] = value
			}
			merged.Parameters = copied
		}
		for key, value := range override.Parameters {
			merged.Parameters[key] = value
		}
	}
	return merged
}

func (cfg Desired) Validate() error {
	return cfg.validateWithRoutePeers(cfg.Peers)
}

func (cfg Desired) ValidateWithRoutePeers(routePeers []PeerConfig) error {
	return cfg.validateWithRoutePeers(routePeers)
}

func (cfg Desired) validateWithRoutePeers(routePeers []PeerConfig) error {
	if err := cfg.Domain.ID.Validate(); err != nil {
		return err
	}
	if err := cfg.IX.ID.Validate(); err != nil {
		return err
	}
	if cfg.IX.Domain != "" && cfg.IX.Domain != cfg.Domain.ID {
		return fmt.Errorf("ix domain %q does not match domain %q", cfg.IX.Domain, cfg.Domain.ID)
	}
	if cfg.IX.ControlAPI != "" {
		if err := validateControlAPI("ix control_api", cfg.IX.ControlAPI); err != nil {
			return err
		}
	}
	if err := validateLAN(cfg.LAN); err != nil {
		return err
	}
	if err := validateLANs(cfg); err != nil {
		return err
	}
	if err := validateManagement(cfg.Management, EffectiveLANs(cfg)); err != nil {
		return err
	}
	if err := validateKernelModules(cfg.KernelModules); err != nil {
		return err
	}
	if err := cfg.Trust.Validate(); err != nil {
		return err
	}
	if err := validateEndpoints(cfg.Endpoints); err != nil {
		return err
	}
	if err := validateBootstrap(cfg.Bootstrap, cfg.Domain.ID); err != nil {
		return err
	}
	if err := validatePeers(cfg.Peers); err != nil {
		return err
	}
	if err := validatePrefixConflicts(cfg); err != nil {
		return err
	}
	if err := validateRoutes(cfg.Routes, routePeers, cfg.IX.ID); err != nil {
		return err
	}
	if err := validateRoutePolicy(cfg.RoutePolicy); err != nil {
		return err
	}
	if err := validatePolicies(cfg.Policies, EffectiveLANs(cfg)); err != nil {
		return err
	}
	return validateTransportPolicy(cfg.TransportPolicy, cfg.Endpoints)
}

func validateLAN(lan LANConfig) error {
	if !LANConfigured(lan) {
		return nil
	}
	if lan.Type != "" && lan.Type != LANTypeLocal && lan.Type != LANTypeTrustedPublic {
		return fmt.Errorf("unsupported lan type %q", lan.Type)
	}
	if strings.TrimSpace(lan.Iface) == "" && len(lan.Advertise) > 0 {
		return fmt.Errorf("lan iface is required when prefixes are advertised")
	}
	var gatewayPrefix netip.Prefix
	if lan.Gateway != "" {
		parsed, err := netip.ParsePrefix(lan.Gateway)
		if err != nil {
			return fmt.Errorf("parse lan gateway %q: %w", lan.Gateway, err)
		}
		gatewayPrefix = parsed.Masked()
	}
	if lan.Mode != "" && lan.Mode != LANModeRouted && lan.Mode != LANModeNAT {
		return fmt.Errorf("unsupported lan mode %q", lan.Mode)
	}
	if lan.AttachMode != "" && lan.AttachMode != LANAttachModeManaged && lan.AttachMode != LANAttachModeExisting {
		return fmt.Errorf("unsupported lan attach_mode %q", lan.AttachMode)
	}
	if lan.AttachMode == LANAttachModeExisting {
		if strings.TrimSpace(lan.Iface) == "" {
			return fmt.Errorf("lan iface is required when attach_mode is existing")
		}
		if gatewayPrefix == (netip.Prefix{}) {
			return fmt.Errorf("lan gateway is required when attach_mode is existing")
		}
		if lan.ManageAddress {
			return fmt.Errorf("lan manage_address must be false when attach_mode is existing")
		}
	}
	gatewayAdvertised := gatewayPrefix == netip.Prefix{}
	for _, prefix := range lan.Advertise {
		parsed, err := prefix.Parse()
		if err != nil {
			return err
		}
		if gatewayPrefix != (netip.Prefix{}) && parsed == gatewayPrefix {
			gatewayAdvertised = true
		}
	}
	if !gatewayAdvertised {
		return fmt.Errorf("lan gateway prefix %q is not listed in advertise", gatewayPrefix)
	}
	if lan.Mode == LANModeNAT && len(lan.Advertise) == 0 {
		return fmt.Errorf("nat mode still requires an explicit advertised prefix")
	}
	if lan.Mode == LANModeNAT && gatewayPrefix == (netip.Prefix{}) {
		return fmt.Errorf("nat mode requires lan gateway")
	}
	if lan.NAT.MaxBindings < 0 {
		return fmt.Errorf("lan nat max_bindings must be non-negative")
	}
	if strings.TrimSpace(lan.NAT.BindingTTL) != "" {
		ttl, err := time.ParseDuration(strings.TrimSpace(lan.NAT.BindingTTL))
		if err != nil {
			return fmt.Errorf("parse lan nat binding_ttl %q: %w", lan.NAT.BindingTTL, err)
		}
		if ttl <= 0 {
			return fmt.Errorf("lan nat binding_ttl must be positive")
		}
	}
	if lan.DeviceAccess.Enabled {
		if strings.TrimSpace(lan.DeviceAccess.AddressPool) == "" {
			return fmt.Errorf("lan device_access address_pool is required when device access is enabled")
		}
		pool, err := netip.ParsePrefix(strings.TrimSpace(lan.DeviceAccess.AddressPool))
		if err != nil {
			return fmt.Errorf("parse lan device_access address_pool %q: %w", lan.DeviceAccess.AddressPool, err)
		}
		if !pool.Addr().Is4() {
			return fmt.Errorf("lan device_access address_pool must be an IPv4 prefix")
		}
		if strings.TrimSpace(lan.Gateway) != "" {
			if gatewayPrefix.Addr().IsValid() && !prefixContainsPrefix(gatewayPrefix, pool.Masked()) {
				return fmt.Errorf("lan device_access address_pool %q must be inside lan gateway prefix %q", pool.Masked(), gatewayPrefix)
			}
		}
	}
	if strings.TrimSpace(lan.DeviceAccess.LeaseTTL) != "" {
		ttl, err := time.ParseDuration(strings.TrimSpace(lan.DeviceAccess.LeaseTTL))
		if err != nil {
			return fmt.Errorf("parse lan device_access lease_ttl %q: %w", lan.DeviceAccess.LeaseTTL, err)
		}
		if ttl <= 0 {
			return fmt.Errorf("lan device_access lease_ttl must be positive")
		}
	}
	return nil
}

func validateLANs(cfg Desired) error {
	seen := make(map[string]struct{}, 1+len(cfg.LANs))
	effectiveIDs := make(map[string]struct{}, 1+len(cfg.LANs))
	deviceAccessLANs := make([]string, 0)
	if LANConfigured(cfg.LAN) {
		id := strings.TrimSpace(cfg.LAN.ID)
		if id == "" {
			id = DefaultLANID
		}
		if err := validateLANID(id); err != nil {
			return err
		}
		seen[id] = struct{}{}
	}
	prefixOwners := make([]struct {
		id     string
		prefix netip.Prefix
	}, 0)
	for _, lan := range EffectiveLANs(cfg) {
		if !LANConfigured(lan) {
			continue
		}
		effectiveIDs[lan.ID] = struct{}{}
		if lan.DeviceAccess.Enabled {
			deviceAccessLANs = append(deviceAccessLANs, lan.ID)
		}
		for _, rawPrefix := range lan.Advertise {
			prefix, err := rawPrefix.Parse()
			if err != nil {
				return err
			}
			for _, existing := range prefixOwners {
				if existing.id != lan.ID && existing.prefix.Overlaps(prefix) {
					return fmt.Errorf("lan prefix conflict: %q on %q overlaps %q on %q", existing.prefix, existing.id, prefix, lan.ID)
				}
			}
			prefixOwners = append(prefixOwners, struct {
				id     string
				prefix netip.Prefix
			}{id: lan.ID, prefix: prefix})
		}
	}
	for index, lan := range cfg.LANs {
		if strings.TrimSpace(lan.ID) == "" {
			return fmt.Errorf("lans[%d] id is required", index)
		}
		if err := validateLANID(lan.ID); err != nil {
			return fmt.Errorf("lans[%d]: %w", index, err)
		}
		if _, exists := seen[lan.ID]; exists {
			return fmt.Errorf("duplicate lan id %q", lan.ID)
		}
		seen[lan.ID] = struct{}{}
		if err := validateLAN(lan); err != nil {
			return fmt.Errorf("lans[%d]: %w", index, err)
		}
	}
	if cfg.PrimaryLANID != "" {
		if err := validateLANID(cfg.PrimaryLANID); err != nil {
			return fmt.Errorf("primary_lan_id: %w", err)
		}
		if _, ok := effectiveIDs[cfg.PrimaryLANID]; !ok {
			return fmt.Errorf("primary_lan_id %q does not match a configured LAN", cfg.PrimaryLANID)
		}
	}
	if len(deviceAccessLANs) > 1 {
		return fmt.Errorf("multiple device_access LANs are configured (%s); only one device access pool is currently supported", strings.Join(deviceAccessLANs, ", "))
	}
	return nil
}

func validateLANID(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("lan id is required")
	}
	if strings.ContainsAny(id, "/\x00") {
		return fmt.Errorf("lan id %q is invalid", id)
	}
	return nil
}

func prefixContainsPrefix(parent, child netip.Prefix) bool {
	parent = parent.Masked()
	child = child.Masked()
	if !parent.Addr().IsValid() || !child.Addr().IsValid() {
		return false
	}
	if parent.Addr().Is4() != child.Addr().Is4() {
		return false
	}
	return parent.Bits() <= child.Bits() && parent.Contains(child.Addr())
}

func validateManagement(management ManagementConfig, lans []LANConfig) error {
	hostAPI := management.HostAPI
	if err := validateManagementTLS(management.TLS); err != nil {
		return err
	}
	if err := validateWebUI(management.WebUI); err != nil {
		return err
	}
	if !hostAPI.Enabled {
		return nil
	}
	if strings.TrimSpace(hostAPI.Listen) != "" {
		if err := validateTCPListenAddress("management host_api listen", hostAPI.Listen); err != nil {
			return err
		}
	}
	if strings.TrimSpace(hostAPI.Listen) == "" && !anyLANGatewayConfigured(lans) {
		return fmt.Errorf("management host_api listen is required when lan gateway is not configured")
	}
	return nil
}

func anyLANGatewayConfigured(lans []LANConfig) bool {
	for _, lan := range lans {
		if strings.TrimSpace(lan.Gateway) != "" {
			return true
		}
	}
	return false
}

func validateManagementTLS(tls ManagementTLSConfig) error {
	switch normalizeManagementTLSMode(tls.Mode) {
	case "auto", "disabled", "required":
	default:
		return fmt.Errorf("management tls mode %q is unsupported", tls.Mode)
	}
	switch normalizeManagementTLSIdentity(tls.Identity) {
	case "ix_cert":
		return nil
	case "custom_cert":
		hasCert := strings.TrimSpace(tls.CertPath) != ""
		hasKey := strings.TrimSpace(tls.KeyPath) != ""
		if hasCert != hasKey || !hasCert {
			return fmt.Errorf("management tls custom_cert cert and key must be configured together")
		}
		return nil
	default:
		return fmt.Errorf("management tls identity %q is unsupported", tls.Identity)
	}
}

func normalizeManagementTLSMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "auto":
		return "auto"
	case "disabled", "off", "http":
		return "disabled"
	case "required", "require", "https":
		return "required"
	default:
		return strings.ToLower(strings.TrimSpace(mode))
	}
}

func normalizeManagementTLSIdentity(identity string) string {
	switch strings.ToLower(strings.TrimSpace(identity)) {
	case "", "ix_cert":
		return "ix_cert"
	case "custom_cert":
		return "custom_cert"
	default:
		return strings.ToLower(strings.TrimSpace(identity))
	}
}

func validateWebUI(webUI WebUIConfig) error {
	return nil
}

func validateTCPListenAddress(label string, value string) error {
	if _, _, err := net.SplitHostPort(value); err != nil {
		return fmt.Errorf("%s %q is invalid: %w", label, value, err)
	}
	return nil
}

func validateKernelModules(modules KernelModulesConfig) error {
	if err := validateKernelModule("kernel_modules trustix_crypto", modules.TrustIXCrypto); err != nil {
		return err
	}
	if err := validateKernelModule("kernel_modules trustix_datapath", modules.TrustIXDatapath); err != nil {
		return err
	}
	return validateKernelModule("kernel_modules trustix_datapath_helpers", modules.TrustIXDatapathHelpers)
}

func validateKernelModule(label string, module KernelModuleConfig) error {
	switch strings.ToLower(strings.TrimSpace(module.Mode)) {
	case "", "disabled", "auto", "required":
		return nil
	default:
		return fmt.Errorf("%s mode %q is unsupported", label, module.Mode)
	}
}

func NormalizeTrust(trust TrustConfig) TrustConfig {
	normalized := make([]string, 0, len(trust.RevokedCertFingerprints))
	for _, raw := range trust.RevokedCertFingerprints {
		fingerprint, err := pki.NormalizeCertificateFingerprintSHA256(raw)
		if err != nil {
			fingerprint = strings.TrimSpace(raw)
		}
		normalized = append(normalized, fingerprint)
	}
	sort.Strings(normalized)
	trust.RevokedCertFingerprints = normalized

	allowed := make([]string, 0, len(trust.AdminPolicy.AllowedFingerprints))
	for _, raw := range trust.AdminPolicy.AllowedFingerprints {
		fingerprint, err := pki.NormalizeCertificateFingerprintSHA256(raw)
		if err != nil {
			fingerprint = strings.TrimSpace(raw)
		}
		allowed = append(allowed, fingerprint)
	}
	sort.Strings(allowed)
	trust.AdminPolicy.AllowedFingerprints = allowed

	type rootPEM struct {
		fingerprint string
		pem         string
	}
	roots := make([]rootPEM, 0, len(trust.TrustRootsPEM))
	for _, raw := range trust.TrustRootsPEM {
		cert, err := pki.ParseCertificatePEM([]byte(raw))
		if err != nil {
			roots = append(roots, rootPEM{fingerprint: strings.TrimSpace(raw), pem: strings.TrimSpace(raw)})
			continue
		}
		roots = append(roots, rootPEM{
			fingerprint: pki.CertificateFingerprintSHA256(cert),
			pem:         string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
		})
	}
	sort.Slice(roots, func(i, j int) bool {
		return roots[i].fingerprint < roots[j].fingerprint
	})
	trust.TrustRootsPEM = trust.TrustRootsPEM[:0]
	for _, root := range roots {
		trust.TrustRootsPEM = append(trust.TrustRootsPEM, root.pem)
	}
	return trust
}

func normalizeTrustConfig(trust *TrustConfig) {
	if trust == nil {
		return
	}
	*trust = NormalizeTrust(*trust)
}

func (trust TrustConfig) Validate() error {
	seen := make(map[string]struct{}, len(trust.RevokedCertFingerprints))
	for _, raw := range trust.RevokedCertFingerprints {
		fingerprint, err := pki.NormalizeCertificateFingerprintSHA256(raw)
		if err != nil {
			return fmt.Errorf("trust revoked_cert_fingerprints entry %q: %w", raw, err)
		}
		if _, exists := seen[fingerprint]; exists {
			return fmt.Errorf("duplicate revoked certificate fingerprint %q", fingerprint)
		}
		seen[fingerprint] = struct{}{}
	}
	if trust.AdminPolicy.Threshold < 0 {
		return fmt.Errorf("trust admin_policy threshold must be non-negative")
	}
	adminSeen := make(map[string]struct{}, len(trust.AdminPolicy.AllowedFingerprints))
	for _, raw := range trust.AdminPolicy.AllowedFingerprints {
		fingerprint, err := pki.NormalizeCertificateFingerprintSHA256(raw)
		if err != nil {
			return fmt.Errorf("trust admin_policy allowed_fingerprints entry %q: %w", raw, err)
		}
		if _, exists := adminSeen[fingerprint]; exists {
			return fmt.Errorf("duplicate admin policy fingerprint %q", fingerprint)
		}
		adminSeen[fingerprint] = struct{}{}
	}
	threshold := EffectiveAdminThreshold(trust)
	if len(adminSeen) > 0 && threshold > len(adminSeen) {
		return fmt.Errorf("trust admin_policy threshold %d exceeds %d allowed admin fingerprints", threshold, len(adminSeen))
	}
	rootSeen := make(map[string]struct{}, len(trust.TrustRootsPEM))
	for i, root := range trust.TrustRootsPEM {
		cert, err := pki.ParseCertificatePEM([]byte(root))
		if err != nil {
			return fmt.Errorf("trust trust_roots_pem entry %d: %w", i, err)
		}
		if !cert.IsCA {
			return fmt.Errorf("trust trust_roots_pem entry %d is not a CA certificate", i)
		}
		fingerprint := pki.CertificateFingerprintSHA256(cert)
		if _, exists := rootSeen[fingerprint]; exists {
			return fmt.Errorf("duplicate trust root fingerprint %q", fingerprint)
		}
		rootSeen[fingerprint] = struct{}{}
	}
	return nil
}

func EffectiveAdminThreshold(trust TrustConfig) int {
	if trust.AdminPolicy.Threshold > 0 {
		return trust.AdminPolicy.Threshold
	}
	return 1
}

func validateEndpoints(endpoints []EndpointConfig) error {
	seen := make(map[core.EndpointID]struct{}, len(endpoints))
	for _, ep := range endpoints {
		if err := ep.Name.Validate(); err != nil {
			return err
		}
		if _, exists := seen[ep.Name]; exists {
			return fmt.Errorf("duplicate endpoint %q", ep.Name)
		}
		seen[ep.Name] = struct{}{}
		if ep.Mode != EndpointModeActive && ep.Mode != EndpointModePassive {
			return fmt.Errorf("endpoint %q has unsupported mode %q", ep.Name, ep.Mode)
		}
		if ep.Mode == EndpointModePassive && strings.TrimSpace(ep.Listen) == "" {
			return fmt.Errorf("passive endpoint %q listen address is required", ep.Name)
		}
		if ep.Mode == EndpointModeActive && strings.TrimSpace(ep.Address) == "" {
			return fmt.Errorf("active endpoint %q remote address is required", ep.Name)
		}
		if strings.TrimSpace(ep.Transport) == "" {
			return fmt.Errorf("endpoint %q transport is required", ep.Name)
		}
		ep.Transport = strings.ToLower(strings.TrimSpace(ep.Transport))
		if !supportedTransport(ep.Transport) {
			return fmt.Errorf("endpoint %q has unsupported transport %q", ep.Name, ep.Transport)
		}
		if err := validateEndpointLocalBind("endpoint "+string(ep.Name), ep.LocalBind); err != nil {
			return err
		}
		if err := validateEndpointPublish("endpoint "+string(ep.Name), ep.Publish); err != nil {
			return err
		}
		if err := validateEndpointAccess("endpoint "+string(ep.Name), ep.Access); err != nil {
			return err
		}
		if ep.Transport == "gre" || ep.Transport == "ipip" || ep.Transport == "vxlan" {
			raw := firstNonEmpty(strings.TrimSpace(ep.Address), strings.TrimSpace(ep.Listen))
			if err := validateKernelTunnelEndpoint(fmt.Sprintf("endpoint %q", ep.Name), raw, true); err != nil {
				return err
			}
		}
		if err := validateEndpointSecurity("endpoint "+string(ep.Name), ep.Transport, ep.Security); err != nil {
			return err
		}
		if err := validateEndpointProfile("endpoint "+string(ep.Name), ep.Profile); err != nil {
			return err
		}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func validateBootstrap(bootstrap BootstrapConfig, domain core.DomainID) error {
	seen := make(map[string]struct{}, len(bootstrap.Peers))
	for _, peer := range bootstrap.Peers {
		if strings.TrimSpace(peer.ControlAPI) == "" {
			return fmt.Errorf("bootstrap peer control_api is required")
		}
		if _, exists := seen[peer.ControlAPI]; exists {
			return fmt.Errorf("duplicate bootstrap peer control_api %q", peer.ControlAPI)
		}
		seen[peer.ControlAPI] = struct{}{}
		if peer.ID != "" {
			if err := peer.ID.Validate(); err != nil {
				return err
			}
		}
		if peer.Domain != "" {
			if err := peer.Domain.Validate(); err != nil {
				return err
			}
			if peer.Domain != domain {
				return fmt.Errorf("bootstrap peer domain %q does not match domain %q", peer.Domain, domain)
			}
		}
		if err := validateControlAPI("bootstrap peer control_api", peer.ControlAPI); err != nil {
			return err
		}
	}
	return nil
}

func validatePeers(peers []PeerConfig) error {
	seen := make(map[core.IXID]struct{}, len(peers))
	for _, peer := range peers {
		if err := peer.ID.Validate(); err != nil {
			return err
		}
		if _, exists := seen[peer.ID]; exists {
			return fmt.Errorf("duplicate peer %q", peer.ID)
		}
		seen[peer.ID] = struct{}{}
		if err := peer.Domain.Validate(); err != nil {
			return err
		}
		if peer.ControlAPI != "" {
			if err := validateControlAPI(fmt.Sprintf("peer %q control_api", peer.ID), peer.ControlAPI); err != nil {
				return err
			}
		}
		peerEndpoints := make(map[core.EndpointID]struct{}, len(peer.Endpoints))
		for _, ep := range peer.Endpoints {
			if err := ep.Name.Validate(); err != nil {
				return fmt.Errorf("peer %q endpoint: %w", peer.ID, err)
			}
			if _, exists := peerEndpoints[ep.Name]; exists {
				return fmt.Errorf("peer %q has duplicate endpoint %q", peer.ID, ep.Name)
			}
			peerEndpoints[ep.Name] = struct{}{}
			if ep.Mode != EndpointModeActive && ep.Mode != EndpointModePassive {
				return fmt.Errorf("peer %q endpoint %q has unsupported mode %q", peer.ID, ep.Name, ep.Mode)
			}
			if ep.Mode == EndpointModeActive && strings.TrimSpace(ep.Address) == "" {
				return fmt.Errorf("peer %q active endpoint %q address is required", peer.ID, ep.Name)
			}
			if strings.TrimSpace(ep.Transport) == "" {
				return fmt.Errorf("peer %q endpoint %q transport is required", peer.ID, ep.Name)
			}
			ep.Transport = strings.ToLower(strings.TrimSpace(ep.Transport))
			if !supportedTransport(ep.Transport) {
				return fmt.Errorf("peer %q endpoint %q has unsupported transport %q", peer.ID, ep.Name, ep.Transport)
			}
			if err := validateEndpointLocalBind(fmt.Sprintf("peer %q endpoint %q", peer.ID, ep.Name), ep.LocalBind); err != nil {
				return err
			}
			if ep.Transport == "gre" || ep.Transport == "ipip" || ep.Transport == "vxlan" {
				if strings.TrimSpace(ep.Address) != "" {
					if err := validateKernelTunnelEndpoint(fmt.Sprintf("peer %q endpoint %q", peer.ID, ep.Name), ep.Address, false); err != nil {
						return err
					}
				}
			}
			if err := validateEndpointSecurity(fmt.Sprintf("peer %q endpoint %q", peer.ID, ep.Name), ep.Transport, ep.Security); err != nil {
				return err
			}
			if err := validateEndpointAccess(fmt.Sprintf("peer %q endpoint %q", peer.ID, ep.Name), ep.Access); err != nil {
				return err
			}
			if err := validateEndpointProfile(fmt.Sprintf("peer %q endpoint %q", peer.ID, ep.Name), ep.Profile); err != nil {
				return err
			}
		}
		for _, prefix := range peer.AllowedPrefixes {
			if _, err := prefix.Parse(); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateControlAPI(label string, value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("%s %q is invalid", label, value)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%s scheme %q is unsupported", label, parsed.Scheme)
	}
	return nil
}

func validateRoutes(routes []RouteConfig, peers []PeerConfig, localIX core.IXID) error {
	peerPrefixes := make(map[core.IXID][]netip.Prefix, len(peers))
	peerEndpoints := make(map[core.IXID]map[core.EndpointID]struct{}, len(peers))
	for _, peer := range peers {
		for _, prefix := range peer.AllowedPrefixes {
			parsed, err := prefix.Parse()
			if err != nil {
				return err
			}
			peerPrefixes[peer.ID] = append(peerPrefixes[peer.ID], parsed)
		}
		peerEndpoints[peer.ID] = make(map[core.EndpointID]struct{}, len(peer.Endpoints))
		for _, ep := range peer.Endpoints {
			peerEndpoints[peer.ID][ep.Name] = struct{}{}
		}
	}
	for _, route := range routes {
		parsedRoute, err := route.Prefix.Parse()
		if err != nil {
			return err
		}
		kind := route.Kind
		if kind == "" {
			kind = routing.RouteUnicast
		}
		switch kind {
		case routing.RouteUnicast:
		case routing.RouteLocal:
			if route.Endpoint != "" {
				return fmt.Errorf("route %q local kind cannot set endpoint", route.Prefix)
			}
			if route.NextHop != "" && route.NextHop != localIX {
				return fmt.Errorf("route %q local kind next_hop must be local IX %q", route.Prefix, localIX)
			}
			if route.Owner != "" {
				if err := route.Owner.Validate(); err != nil {
					return err
				}
			}
			if route.Metric < 0 {
				return fmt.Errorf("route %q has negative metric", route.Prefix)
			}
			continue
		case routing.RouteBlackhole, routing.RouteReject:
			if route.Endpoint != "" {
				return fmt.Errorf("route %q %s kind cannot set endpoint", route.Prefix, kind)
			}
			if route.Owner != "" {
				if err := route.Owner.Validate(); err != nil {
					return err
				}
			}
			if route.NextHop != "" {
				if err := route.NextHop.Validate(); err != nil {
					return err
				}
			}
			if route.Metric < 0 {
				return fmt.Errorf("route %q has negative metric", route.Prefix)
			}
			continue
		default:
			return fmt.Errorf("route %q has unsupported kind %q", route.Prefix, route.Kind)
		}
		owner := route.Owner
		if owner == "" {
			owner = route.NextHop
		}
		if err := owner.Validate(); err != nil {
			return err
		}
		if err := route.NextHop.Validate(); err != nil {
			return err
		}
		if _, ok := peerPrefixes[route.NextHop]; !ok {
			return fmt.Errorf("route %q next_hop %q is not a configured peer", route.Prefix, route.NextHop)
		}
		allowedPrefixes, ok := peerPrefixes[owner]
		if !ok {
			return fmt.Errorf("route %q owner %q is not a configured peer", route.Prefix, owner)
		}
		authorized := false
		for _, allowedPrefix := range allowedPrefixes {
			if allowedPrefix.Contains(parsedRoute.Addr()) && allowedPrefix.Bits() <= parsedRoute.Bits() {
				authorized = true
				break
			}
		}
		if !authorized {
			return fmt.Errorf("route %q is not authorized by owner %q allowed_prefixes", route.Prefix, owner)
		}
		if route.Endpoint != "" {
			endpoints := peerEndpoints[route.NextHop]
			if _, ok := endpoints[route.Endpoint]; !ok && !endpointMayBeDynamicallyNegotiated(route.Endpoint) {
				return fmt.Errorf("route %q endpoint %q is not configured on peer %q", route.Prefix, route.Endpoint, route.NextHop)
			}
		}
		if route.Metric < 0 {
			return fmt.Errorf("route %q has negative metric", route.Prefix)
		}
	}
	return nil
}

func validatePolicies(policies []PolicyConfig, lans []LANConfig) error {
	for _, policy := range policies {
		switch strings.ToLower(strings.TrimSpace(policy.Rewrite)) {
		case "", "none", "preserve_source", "snat_gateway", "nat", "snat":
		default:
			return fmt.Errorf("policy %q rewrite %q is unsupported", policy.Name, policy.Rewrite)
		}
		if rewritePolicyEnablesNAT(policy.Rewrite) && !anyLANGatewayConfigured(lans) {
			return fmt.Errorf("policy %q rewrite %q requires lan gateway", policy.Name, policy.Rewrite)
		}
	}
	return nil
}

func endpointMayBeDynamicallyNegotiated(endpoint core.EndpointID) bool {
	name := strings.ToLower(strings.TrimSpace(string(endpoint)))
	return strings.HasSuffix(name, "-gre") ||
		strings.HasSuffix(name, "-ipip") ||
		strings.HasSuffix(name, "-vxlan")
}

func rewritePolicyEnablesNAT(rewrite string) bool {
	switch strings.ToLower(strings.TrimSpace(rewrite)) {
	case "snat_gateway", "nat", "snat":
		return true
	default:
		return false
	}
}

func validateRoutePolicy(policy RoutePolicyConfig) error {
	for _, prefix := range policy.ImportPrefixes {
		if _, err := prefix.Parse(); err != nil {
			return fmt.Errorf("route_policy import_prefixes: %w", err)
		}
	}
	for _, prefix := range policy.ExportPrefixes {
		if _, err := prefix.Parse(); err != nil {
			return fmt.Errorf("route_policy export_prefixes: %w", err)
		}
	}
	if policy.DynamicMetric < 0 {
		return fmt.Errorf("route_policy dynamic_metric must be non-negative")
	}
	return nil
}

func validateTransportPolicy(policy TransportPolicyConfig, endpoints []EndpointConfig) error {
	if err := validateTransportProfileName("transport_policy profile", policy.Profile); err != nil {
		return err
	}
	if err := validateTransportDatapath("transport_policy datapath", policy.Datapath); err != nil {
		return err
	}
	if err := validateTransportCryptoPlacement("transport_policy", policy.CryptoPlacement); err != nil {
		return err
	}
	if err := validateTransportAdvanced("transport_policy advanced", policy.Advanced); err != nil {
		return err
	}
	for index, profile := range policy.Profiles {
		if strings.TrimSpace(profile.Transport) == "" {
			return fmt.Errorf("transport_policy profiles[%d] transport is required", index)
		}
		if !supportedTransport(normalizeTransportProfileTransport(profile.Transport)) {
			return fmt.Errorf("transport_policy profiles[%d] has unsupported transport %q", index, profile.Transport)
		}
		if err := validateTransportProfileName(fmt.Sprintf("transport_policy profiles[%d] profile", index), profile.Profile); err != nil {
			return err
		}
		if err := validateTransportDatapath(fmt.Sprintf("transport_policy profiles[%d] datapath", index), profile.Datapath); err != nil {
			return err
		}
		if err := validateTransportEncryption(profile.Encryption); err != nil {
			return fmt.Errorf("transport_policy profiles[%d]: %w", index, err)
		}
		if err := validateTransportCryptoPlacement(fmt.Sprintf("transport_policy profiles[%d]", index), profile.CryptoPlacement); err != nil {
			return err
		}
		if err := validateTransportAdvanced(fmt.Sprintf("transport_policy profiles[%d] advanced", index), profile.Advanced); err != nil {
			return err
		}
	}
	if err := validateKernelTransportPolicy(policy.KernelTransport); err != nil {
		return err
	}
	if err := validateSessionPoolPolicy(policy.SessionPool); err != nil {
		return err
	}
	if err := validateCryptoKeySource(policy.CryptoKeySource); err != nil {
		return err
	}
	if err := validateTransportEncryption(policy.Encryption); err != nil {
		return err
	}
	for _, suite := range policy.CryptoSuites {
		if err := validateCryptoSuite("transport_policy", suite); err != nil {
			return err
		}
	}
	if err := validateTransportTLSIdentity(policy.TLSIdentity); err != nil {
		return err
	}
	if err := validateTransportTLSListenerIdentity(policy.TLSIdentity, endpoints); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(policy.FragmentPolicy)) {
	case "", "allow", "drop":
	default:
		return fmt.Errorf("transport_policy fragment_policy %q is unsupported", policy.FragmentPolicy)
	}
	if policy.MTU < 0 {
		return fmt.Errorf("transport_policy mtu must be non-negative")
	}
	if len(policy.Candidates) == 0 {
		return nil
	}
	localEndpoints := make(map[core.EndpointID]struct{}, len(endpoints))
	for _, ep := range endpoints {
		localEndpoints[ep.Name] = struct{}{}
	}
	for _, candidate := range policy.Candidates {
		if _, ok := localEndpoints[candidate]; !ok {
			return fmt.Errorf("transport policy candidate %q is not a local endpoint", candidate)
		}
	}
	return nil
}

func validateTransportProfileName(label string, profile string) error {
	switch normalizeTransportProfile(profile) {
	case "", "stable", "performance", "latency":
		return nil
	default:
		return fmt.Errorf("%s %q is unsupported", label, profile)
	}
}

func validateTransportDatapath(label string, datapath string) error {
	switch normalizeTransportDatapath(datapath) {
	case "", "userspace", "tc_xdp", "kernel_module":
		return nil
	default:
		return fmt.Errorf("%s %q is unsupported", label, datapath)
	}
}

func validateTransportAdvanced(label string, advanced TransportAdvancedConfig) error {
	for name, value := range map[string]string{
		"large_frames": advanced.LargeFrames,
		"gso":          advanced.GSO,
		"gro":          advanced.GRO,
	} {
		switch normalizeTransportToggle(value) {
		case "", "enabled", "disabled":
		default:
			return fmt.Errorf("%s %s %q is unsupported", label, name, value)
		}
	}
	if advanced.Shards < 0 {
		return fmt.Errorf("%s shards must be non-negative", label)
	}
	if advanced.MaxFrames < 0 {
		return fmt.Errorf("%s max_frames must be non-negative", label)
	}
	if advanced.BatchBytes < 0 {
		return fmt.Errorf("%s batch_bytes must be non-negative", label)
	}
	if strings.TrimSpace(advanced.FlushDelay) != "" {
		delay, err := time.ParseDuration(strings.TrimSpace(advanced.FlushDelay))
		if err != nil {
			return fmt.Errorf("parse %s flush_delay %q: %w", label, advanced.FlushDelay, err)
		}
		if delay < 0 {
			return fmt.Errorf("%s flush_delay must be non-negative", label)
		}
	}
	for key := range advanced.Parameters {
		if strings.TrimSpace(key) == "" {
			return fmt.Errorf("%s parameters contains an empty key", label)
		}
	}
	return nil
}

func validateKernelTransportPolicy(policy KernelTransportPolicyConfig) error {
	switch strings.ToLower(strings.TrimSpace(policy.Mode)) {
	case "", "auto", "prefer_kernel", "prefer-kernel", "prefer", "require_kernel", "require-kernel", "required", "disabled", "off":
		return nil
	default:
		return fmt.Errorf("transport_policy kernel_transport mode %q is unsupported", policy.Mode)
	}
}

func validateEndpointPublish(label string, publish EndpointPublishConfig) error {
	switch strings.ToLower(strings.TrimSpace(publish.Mode)) {
	case "", "public", "all", "private", "disabled", "none", "allowlist", "only", "denylist", "except":
	default:
		return fmt.Errorf("%s publish mode %q is unsupported", label, publish.Mode)
	}
	for _, peer := range publish.OnlyPeers {
		if err := peer.Validate(); err != nil {
			return fmt.Errorf("%s publish only_peers: %w", label, err)
		}
	}
	for _, peer := range publish.ExceptPeers {
		if err := peer.Validate(); err != nil {
			return fmt.Errorf("%s publish except_peers: %w", label, err)
		}
	}
	for _, domain := range publish.Domains {
		if err := domain.Validate(); err != nil {
			return fmt.Errorf("%s publish domains: %w", label, err)
		}
	}
	if len(publish.OnlyPeers) > 0 && len(publish.ExceptPeers) > 0 {
		return fmt.Errorf("%s publish only_peers and except_peers cannot both be set", label)
	}
	return nil
}

func validateEndpointAccess(label string, access EndpointAccessConfig) error {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(access.Mode), "-", "_")) {
	case "", "open", "public", "allow", "allowlist", "only", "require_grant", "grant", "grants", "authenticated":
	default:
		return fmt.Errorf("%s access mode %q is unsupported", label, access.Mode)
	}
	for _, peer := range access.AllowedPeers {
		if err := peer.Validate(); err != nil {
			return fmt.Errorf("%s access allowed_peers: %w", label, err)
		}
	}
	if strings.TrimSpace(access.DefaultTTL) != "" {
		ttl, err := time.ParseDuration(strings.TrimSpace(access.DefaultTTL))
		if err != nil {
			return fmt.Errorf("parse %s access default_ttl %q: %w", label, access.DefaultTTL, err)
		}
		if ttl <= 0 {
			return fmt.Errorf("%s access default_ttl must be positive", label)
		}
	}
	return nil
}

func validateEndpointLocalBind(label string, bind EndpointLocalBindConfig) error {
	sourceIP := strings.TrimSpace(bind.SourceIP)
	if sourceIP != "" {
		if parsed := net.ParseIP(sourceIP); parsed == nil {
			return fmt.Errorf("%s local_bind source_ip %q is not an IP address", label, bind.SourceIP)
		}
	}
	if iface := strings.TrimSpace(bind.Iface); iface != "" {
		if strings.ContainsAny(iface, "/\x00") {
			return fmt.Errorf("%s local_bind iface must be an interface name", label)
		}
	}
	return nil
}

func validateKernelTunnelEndpoint(label string, raw string, allowNegotiated bool) error {
	values, err := parseKernelTunnelEndpointFields(raw)
	if err != nil {
		return fmt.Errorf("%s tunnel config: %w", label, err)
	}
	required := []string{"local"}
	if !allowNegotiated || strings.TrimSpace(values["remote"]) != "" || strings.TrimSpace(values["local_carrier"]) != "" || strings.TrimSpace(values["remote_carrier"]) != "" {
		required = []string{"local", "remote", "local_carrier", "remote_carrier"}
	}
	for _, key := range required {
		if strings.TrimSpace(values[key]) == "" {
			return fmt.Errorf("%s tunnel config requires %s", label, key)
		}
	}
	for _, key := range []string{"local", "remote", "remote_carrier"} {
		if strings.TrimSpace(values[key]) == "" {
			continue
		}
		addr, err := netip.ParseAddr(values[key])
		if err != nil {
			return fmt.Errorf("%s tunnel config %s must be an IPv4 address", label, key)
		}
		if !addr.Is4() {
			return fmt.Errorf("%s tunnel config %s must be an IPv4 address", label, key)
		}
	}
	if strings.TrimSpace(values["local_carrier"]) != "" {
		prefix, err := netip.ParsePrefix(values["local_carrier"])
		if err != nil {
			return fmt.Errorf("%s tunnel config local_carrier must be an IPv4 prefix", label)
		}
		if !prefix.Addr().Is4() {
			return fmt.Errorf("%s tunnel config local_carrier must be an IPv4 prefix", label)
		}
	}
	if port := strings.TrimSpace(values["port"]); port != "" {
		parsed, err := strconv.ParseUint(port, 10, 16)
		if err != nil || parsed == 0 {
			return fmt.Errorf("%s tunnel config port must be in 1..65535", label)
		}
	}
	for _, key := range []string{"underlay_if", "underlay_iface", "dev", "link"} {
		if iface := strings.TrimSpace(values[key]); iface != "" && strings.ContainsAny(iface, "/\x00") {
			return fmt.Errorf("%s tunnel config %s must be an interface name", label, key)
		}
	}
	for _, key := range []string{"vxlan_port", "outer_port"} {
		if port := strings.TrimSpace(values[key]); port != "" {
			parsed, err := strconv.ParseUint(port, 10, 16)
			if err != nil || parsed == 0 {
				return fmt.Errorf("%s tunnel config %s must be in 1..65535", label, key)
			}
		}
	}
	if vni := strings.TrimSpace(values["vni"]); vni != "" {
		parsed, err := strconv.ParseUint(vni, 10, 24)
		if err != nil || parsed == 0 {
			return fmt.Errorf("%s tunnel config vni must be in 1..16777215", label)
		}
	}
	if mtu := strings.TrimSpace(values["mtu"]); mtu != "" {
		parsed, err := strconv.ParseUint(mtu, 10, 16)
		if err != nil || parsed <= 16 {
			return fmt.Errorf("%s tunnel config mtu must be in 17..65535", label)
		}
	}
	return nil
}

func parseKernelTunnelEndpointFields(raw string) (map[string]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("endpoint string is required")
	}
	if strings.Contains(raw, "://") {
		parts := strings.SplitN(raw, "://", 2)
		raw = parts[1]
	}
	values := make(map[string]string)
	for _, field := range strings.Split(raw, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			return nil, fmt.Errorf("field %q must use key=value", field)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			return nil, fmt.Errorf("field %q is incomplete", field)
		}
		values[key] = value
	}
	return values, nil
}

func validateSessionPoolPolicy(policy SessionPoolPolicyConfig) error {
	if policy.Size < 0 {
		return fmt.Errorf("transport_policy session_pool size must be non-negative")
	}
	switch strings.ToLower(strings.TrimSpace(policy.Strategy)) {
	case "", "flow", "five_tuple", "5tuple", "packet", "round_robin":
	default:
		return fmt.Errorf("transport_policy session_pool strategy %q is unsupported", policy.Strategy)
	}
	switch strings.ToLower(strings.TrimSpace(policy.Heartbeat.Mode)) {
	case "", "auto", "enabled", "on", "disabled", "off":
	default:
		return fmt.Errorf("transport_policy session_pool heartbeat mode %q is unsupported", policy.Heartbeat.Mode)
	}
	if strings.TrimSpace(policy.Heartbeat.Interval) != "" {
		interval, err := time.ParseDuration(strings.TrimSpace(policy.Heartbeat.Interval))
		if err != nil {
			return fmt.Errorf("parse transport_policy session_pool heartbeat interval %q: %w", policy.Heartbeat.Interval, err)
		}
		if interval <= 0 {
			return fmt.Errorf("transport_policy session_pool heartbeat interval must be positive")
		}
	}
	if strings.TrimSpace(policy.Heartbeat.Timeout) != "" {
		timeout, err := time.ParseDuration(strings.TrimSpace(policy.Heartbeat.Timeout))
		if err != nil {
			return fmt.Errorf("parse transport_policy session_pool heartbeat timeout %q: %w", policy.Heartbeat.Timeout, err)
		}
		if timeout <= 0 {
			return fmt.Errorf("transport_policy session_pool heartbeat timeout must be positive")
		}
	}
	return nil
}

func validateTransportTLSIdentity(identity TransportTLSIdentityConfig) error {
	mode := strings.ToLower(strings.TrimSpace(identity.Mode))
	switch mode {
	case "", "ix_cert":
		return nil
	case "custom_cert":
		hasCert := strings.TrimSpace(identity.CertPath) != ""
		hasKey := strings.TrimSpace(identity.KeyPath) != ""
		if hasCert != hasKey {
			return fmt.Errorf("transport_policy tls_identity custom_cert cert and key must be configured together")
		}
		if !identity.SystemRoots && len(identity.TrustRoots) == 0 {
			return fmt.Errorf("transport_policy tls_identity custom_cert requires trust_roots or system_roots")
		}
		return nil
	default:
		return fmt.Errorf("transport_policy tls_identity mode %q is unsupported", identity.Mode)
	}
}

func validateEndpointSecurity(label string, transport string, security EndpointSecurityConfig) error {
	linkTLS := strings.ToLower(strings.TrimSpace(security.LinkTLS))
	switch linkTLS {
	case "", "optional", "required", "unsupported":
	default:
		return fmt.Errorf("%s security link_tls %q is unsupported", label, security.LinkTLS)
	}
	if linkTLS == "unsupported" && strings.EqualFold(strings.TrimSpace(transport), "quic") {
		return fmt.Errorf("%s security link_tls unsupported is invalid for quic transport", label)
	}
	if linkTLS == "required" && !transportSupportsLinkTLS(transport) {
		return fmt.Errorf("%s security link_tls required requires tcp, websocket, http_connect, or quic transport", label)
	}
	switch strings.ToLower(strings.TrimSpace(security.TLSIdentity)) {
	case "", "ix_cert", "custom_cert":
	default:
		return fmt.Errorf("%s security tls_identity %q is unsupported", label, security.TLSIdentity)
	}
	for _, source := range security.KeySources {
		if err := validateCryptoKeySource(source); err != nil {
			return fmt.Errorf("%s security key_source: %w", label, err)
		}
		if linkTLS == "unsupported" && strings.EqualFold(strings.TrimSpace(source), "tls_exporter") {
			return fmt.Errorf("%s security key_source tls_exporter requires link_tls", label)
		}
	}
	if err := validateEndpointEncryption(label, security.Encryption); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(security.WireFormat)) {
	case "", "trustix-secure-data-v1":
	default:
		return fmt.Errorf("%s security wire_format %q is unsupported", label, security.WireFormat)
	}
	for _, suite := range security.CryptoSuites {
		if err := validateCryptoSuite(label+" security", suite); err != nil {
			return err
		}
	}
	for _, placement := range security.CryptoPlacements {
		if err := validateTransportCryptoPlacement("endpoint security", placement); err != nil {
			return fmt.Errorf("%s security crypto_placement: %w", label, err)
		}
	}
	return nil
}

func validateEndpointProfile(label string, profile EndpointProfileConfig) error {
	if profile.Version < 0 {
		return fmt.Errorf("%s transport_profile version must be non-negative", label)
	}
	if err := validateTransportProfileName(label+" transport_profile profile", profile.Profile); err != nil {
		return err
	}
	if err := validateTransportDatapath(label+" transport_profile datapath", profile.Datapath); err != nil {
		return err
	}
	if err := validateTransportEncryption(profile.Encryption); err != nil {
		return fmt.Errorf("%s transport_profile: %w", label, err)
	}
	if err := validateTransportCryptoPlacement(label+" transport_profile", profile.CryptoPlacement); err != nil {
		return err
	}
	for _, feature := range profile.Features {
		if strings.TrimSpace(feature) == "" {
			return fmt.Errorf("%s transport_profile features contains an empty value", label)
		}
	}
	return nil
}

func validateTransportTLSListenerIdentity(identity TransportTLSIdentityConfig, endpoints []EndpointConfig) error {
	mode := strings.ToLower(strings.TrimSpace(identity.Mode))
	if mode != "custom_cert" {
		return nil
	}
	if strings.TrimSpace(identity.CertPath) != "" && strings.TrimSpace(identity.KeyPath) != "" {
		return nil
	}
	for _, endpoint := range endpoints {
		if endpoint.Enabled && endpoint.Mode == EndpointModePassive && endpointCanUseLinkTLS(endpoint) {
			return fmt.Errorf("transport_policy tls_identity custom_cert cert and key are required when enabled passive endpoints are configured")
		}
	}
	return nil
}

func endpointCanUseLinkTLS(endpoint EndpointConfig) bool {
	if strings.ToLower(strings.TrimSpace(endpoint.Security.LinkTLS)) == "unsupported" {
		return false
	}
	return transportSupportsLinkTLS(endpoint.Transport)
}

func transportSupportsLinkTLS(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "tcp", "websocket", "http_connect", "quic":
		return true
	default:
		return false
	}
}

func validateCryptoKeySource(source string) error {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "", "auto", "trustix_x25519", "tls_exporter":
		return nil
	default:
		return fmt.Errorf("transport_policy crypto_key_source %q is unsupported", source)
	}
}

func validateTransportEncryption(encryption string) error {
	switch strings.ToLower(strings.TrimSpace(encryption)) {
	case "", "secure", "encrypted", "trustix_secure", "trustix-secure", "plaintext", "none", "disabled", "off", "send_encrypted", "outbound_encrypted", "encrypt_outbound", "send_only", "receive_encrypted", "inbound_encrypted", "encrypt_inbound", "receive_only":
		return nil
	default:
		return fmt.Errorf("transport_policy encryption %q is unsupported", encryption)
	}
}

func validateEndpointEncryption(label string, encryption string) error {
	switch strings.ToLower(strings.TrimSpace(encryption)) {
	case "", "secure", "encrypted", "trustix_secure", "trustix-secure", "plaintext", "none", "disabled", "off", "send_encrypted", "outbound_encrypted", "encrypt_outbound", "send_only", "receive_encrypted", "inbound_encrypted", "encrypt_inbound", "receive_only":
		return nil
	default:
		return fmt.Errorf("%s security encryption %q is unsupported", label, encryption)
	}
}

func validateCryptoSuite(label string, suite string) error {
	switch strings.ToUpper(strings.TrimSpace(suite)) {
	case "", "AES-256-GCM-X25519", "AES-128-GCM-X25519", "CHACHA20-POLY1305-X25519", "CHACHA20POLY1305-X25519":
		return nil
	default:
		return fmt.Errorf("%s crypto_suite %q is unsupported", label, suite)
	}
}

func validateTransportCryptoPlacement(label string, placement string) error {
	switch strings.ToLower(strings.TrimSpace(placement)) {
	case "", "auto", "userspace", "kernel":
		return nil
	default:
		return fmt.Errorf("%s crypto_placement %q is unsupported", label, placement)
	}
}

func normalizeTransportCryptoPlacement(placement string) string {
	switch strings.ToLower(strings.TrimSpace(placement)) {
	case "auto":
		return "auto"
	case "kernel":
		return "kernel"
	case "userspace":
		return "userspace"
	default:
		return ""
	}
}

func validatePrefixConflicts(cfg Desired) error {
	type ownerPrefix struct {
		owner  core.IXID
		prefix netip.Prefix
	}
	lanPrefixes := EffectiveLANAdvertise(cfg)
	seen := make([]ownerPrefix, 0, len(lanPrefixes)+len(cfg.Peers))
	for _, prefix := range lanPrefixes {
		parsed, err := prefix.Parse()
		if err != nil {
			return err
		}
		seen = append(seen, ownerPrefix{owner: cfg.IX.ID, prefix: parsed})
	}
	for _, peer := range cfg.Peers {
		for _, prefix := range peer.AllowedPrefixes {
			parsed, err := prefix.Parse()
			if err != nil {
				return err
			}
			for _, existing := range seen {
				if existing.owner != peer.ID && existing.prefix.Overlaps(parsed) {
					return fmt.Errorf("prefix conflict: %q owned by %q overlaps %q owned by %q", existing.prefix, existing.owner, parsed, peer.ID)
				}
			}
			seen = append(seen, ownerPrefix{owner: peer.ID, prefix: parsed})
		}
	}
	return nil
}

func supportedTransport(name string) bool {
	switch name {
	case "udp", "quic", "tcp", "websocket", "http_connect", "experimental_tcp", "gre", "ipip", "vxlan":
		return true
	default:
		return false
	}
}
