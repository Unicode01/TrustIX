package device

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"trustix.local/trustix/internal/core"
	"trustix.local/trustix/internal/transport"
	securetransport "trustix.local/trustix/internal/transport/secure"
)

const defaultStatsEvery = 30 * time.Second

type FileConfig struct {
	Domain          core.DomainID       `json:"domain" yaml:"domain"`
	IX              core.IXID           `json:"ix" yaml:"ix"`
	Endpoint        FileEndpointConfig  `json:"endpoint" yaml:"endpoint"`
	CertPath        string              `json:"cert" yaml:"cert"`
	KeyPath         string              `json:"key" yaml:"key"`
	TrustRoots      []string            `json:"trust_roots" yaml:"trust_roots"`
	ServerName      string              `json:"server_name,omitempty" yaml:"server_name,omitempty"`
	Encryption      string              `json:"encryption,omitempty" yaml:"encryption,omitempty"`
	CryptoKeySource string              `json:"crypto_key_source,omitempty" yaml:"crypto_key_source,omitempty"`
	CryptoSuites    []string            `json:"crypto_suites,omitempty" yaml:"crypto_suites,omitempty"`
	Interface       FileInterfaceConfig `json:"interface,omitempty" yaml:"interface,omitempty"`
	BatchSize       int                 `json:"batch_size,omitempty" yaml:"batch_size,omitempty"`
	StatsEvery      string              `json:"stats_every,omitempty" yaml:"stats_every,omitempty"`
}

type FileEndpointConfig struct {
	Name       core.EndpointID    `json:"name,omitempty" yaml:"name,omitempty"`
	Address    string             `json:"address" yaml:"address"`
	Transport  transport.Protocol `json:"transport,omitempty" yaml:"transport,omitempty"`
	Encryption string             `json:"encryption,omitempty" yaml:"encryption,omitempty"`
}

type FileInterfaceConfig struct {
	Name            string   `json:"name,omitempty" yaml:"name,omitempty"`
	MTU             int      `json:"mtu,omitempty" yaml:"mtu,omitempty"`
	BootstrapRoutes []string `json:"bootstrap_routes,omitempty" yaml:"bootstrap_routes,omitempty"`
	Routes          []string `json:"routes,omitempty" yaml:"routes,omitempty"`
}

func LoadFileConfig(path string) (FileConfig, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return FileConfig{}, fmt.Errorf("read device config %q: %w", path, err)
	}
	return DecodeFileConfig(payload, filepath.Ext(path))
}

func DecodeFileConfig(payload []byte, ext string) (FileConfig, error) {
	var cfg FileConfig
	switch strings.ToLower(ext) {
	case ".json":
		if err := json.Unmarshal(payload, &cfg); err != nil {
			return FileConfig{}, fmt.Errorf("decode device json config: %w", err)
		}
	default:
		if err := yaml.Unmarshal(payload, &cfg); err != nil {
			return FileConfig{}, fmt.Errorf("decode device yaml config: %w", err)
		}
	}
	return NormalizeFileConfig(cfg), nil
}

func NormalizeFileConfig(cfg FileConfig) FileConfig {
	cfg.CertPath = strings.TrimSpace(cfg.CertPath)
	cfg.KeyPath = strings.TrimSpace(cfg.KeyPath)
	cfg.TrustRoots = trimStrings(cfg.TrustRoots)
	cfg.ServerName = strings.TrimSpace(cfg.ServerName)
	cfg.Encryption = securetransport.NormalizeEncryptionMode(cfg.Encryption)
	if cfg.Encryption == "" {
		cfg.Encryption = securetransport.EncryptionSecure
	}
	cfg.CryptoKeySource = normalizeKeySource(cfg.CryptoKeySource)
	cfg.CryptoSuites = securetransport.CryptoSuitesOrDefault(cfg.CryptoSuites)
	cfg.Endpoint.Name = core.EndpointID(strings.TrimSpace(string(cfg.Endpoint.Name)))
	if cfg.Endpoint.Name == "" {
		cfg.Endpoint.Name = "device-access"
	}
	cfg.Endpoint.Address = strings.TrimSpace(cfg.Endpoint.Address)
	cfg.Endpoint.Transport = transport.Protocol(strings.ToLower(strings.TrimSpace(string(cfg.Endpoint.Transport))))
	if cfg.Endpoint.Transport == "" {
		cfg.Endpoint.Transport = transport.ProtocolUDP
	}
	endpointEncryption := strings.TrimSpace(cfg.Endpoint.Encryption)
	if endpointEncryption == "" {
		cfg.Endpoint.Encryption = cfg.Encryption
	} else {
		cfg.Endpoint.Encryption = securetransport.NormalizeEncryptionMode(endpointEncryption)
	}
	cfg.Interface.Name = strings.TrimSpace(cfg.Interface.Name)
	cfg.Interface.BootstrapRoutes = trimStrings(cfg.Interface.BootstrapRoutes)
	cfg.Interface.Routes = trimStrings(cfg.Interface.Routes)
	if len(cfg.Interface.BootstrapRoutes) == 0 && len(cfg.Interface.Routes) > 0 {
		cfg.Interface.BootstrapRoutes = append([]string(nil), cfg.Interface.Routes...)
	}
	cfg.StatsEvery = strings.TrimSpace(cfg.StatsEvery)
	return cfg
}

func (cfg FileConfig) ClientConfig() (Config, error) {
	cfg = NormalizeFileConfig(cfg)
	routes, err := ParsePrefixes(cfg.Interface.BootstrapRoutes)
	if err != nil {
		return Config{}, err
	}
	statsEvery, err := parseStatsEvery(cfg.StatsEvery)
	if err != nil {
		return Config{}, err
	}
	return Config{
		Domain:       cfg.Domain,
		IX:           cfg.IX,
		Endpoint:     transport.Endpoint{Name: cfg.Endpoint.Name, Address: cfg.Endpoint.Address, Transport: cfg.Endpoint.Transport, Encryption: cfg.Endpoint.Encryption},
		CertPath:     cfg.CertPath,
		KeyPath:      cfg.KeyPath,
		TrustRoots:   cfg.TrustRoots,
		ServerName:   cfg.ServerName,
		Encryption:   cfg.Encryption,
		KeySource:    cfg.CryptoKeySource,
		CryptoSuites: cfg.CryptoSuites,
		Interface: InterfaceConfig{
			Name:   cfg.Interface.Name,
			MTU:    cfg.Interface.MTU,
			Routes: routes,
		},
		BatchSize:  cfg.BatchSize,
		StatsEvery: statsEvery,
	}, nil
}

func ParsePrefixes(values []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("parse route %q: %w", value, err)
		}
		prefix = prefix.Masked()
		if !prefix.Addr().Is4() {
			return nil, fmt.Errorf("route %q must be IPv4", value)
		}
		if _, ok := seen[prefix.String()]; ok {
			continue
		}
		seen[prefix.String()] = struct{}{}
		out = append(out, prefix)
	}
	return out, nil
}

func parseStatsEvery(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultStatsEvery, nil
	}
	duration, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("parse stats_every %q: %w", raw, err)
	}
	if duration < 0 {
		return 0, fmt.Errorf("stats_every must be non-negative")
	}
	return duration, nil
}

func normalizeKeySource(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "", securetransport.KeySourceAuto:
		return securetransport.KeySourceAuto
	case securetransport.KeySourceTrustIXX25519:
		return securetransport.KeySourceTrustIXX25519
	case securetransport.KeySourceTLSExporter:
		return securetransport.KeySourceTLSExporter
	default:
		return strings.TrimSpace(source)
	}
}

func trimStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := values[:0]
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}
