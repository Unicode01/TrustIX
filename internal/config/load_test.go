package config

import "testing"

func TestLoadBytesNormalizesTrustRevocations(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
trust:
  revoked_cert_fingerprints:
    - "SHA256:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA"
`), ".yaml")
	if err != nil {
		t.Fatalf("load yaml: %v", err)
	}
	want := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if len(cfg.Trust.RevokedCertFingerprints) != 1 || cfg.Trust.RevokedCertFingerprints[0] != want {
		t.Fatalf("revoked fingerprints = %#v, want %q", cfg.Trust.RevokedCertFingerprints, want)
	}
}

func TestLoadBytesRejectsInvalidTrustRevocation(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
trust:
  revoked_cert_fingerprints:
    - not-a-fingerprint
`), ".yaml")
	if err == nil {
		t.Fatal("expected invalid revoked certificate fingerprint error")
	}
}

func TestLoadBytesYAMLNormalizesAndValidates(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
lan:
  iface: br-lan
  gateway: 10.0.0.1/24
  advertise:
    - 10.0.0.0/24
management:
  tls:
    mode: HTTPS
    identity: CUSTOM_CERT
    cert: " ./certs/management.crt "
    key: " ./certs/management.key "
  host_api:
    enabled: true
    listen: " 10.0.0.1:8787 "
    require_read_auth: true
  web_ui:
    enabled: true
    custom_dir: " ./webui "
endpoints:
  - name: sh-udp
    listen: 0.0.0.0:7000
    transport: udp
    security:
      key_sources:
        - trustix_x25519
      wire_format: trustix-secure-data-v1
      crypto_suites:
        - chacha20poly1305-x25519
    enabled: true
peers:
  - id: ix-b
    domain: lab.local
    endpoints:
      - name: hk-udp
        address: 203.0.113.10:7000
        transport: udp
        security:
          link_tls: unsupported
          key_sources:
            - trustix_x25519
    allowed_prefixes:
      - 10.0.1.0/24
routes:
  - prefix: 10.0.1.0/24
    kind: UNICAST
    next_hop: ix-b
    endpoint: hk-udp
    metric: 100
transport_policy:
  mtu: 1400
  fragment_policy: DROP
  encryption: SEND_ENCRYPTED
  crypto_key_source: TLS_EXPORTER
  crypto_placement: AUTO
  crypto_suites:
    - AES-128-GCM-X25519
    - CHACHA20POLY1305-X25519
  session_pool:
    size: 4
    strategy: FIVE_TUPLE
    warmup: true
    heartbeat:
      mode: ENABLED
      interval: " 5s "
      timeout: " 1s "
  tls_identity:
    mode: CUSTOM_CERT
    cert: " ./certs/transport.crt "
    key: " ./certs/transport.key "
    trust_roots:
      - " ./certs/public-root.pem "
  candidates:
    - sh-udp
  kernel_transport:
    mode: REQUIRE-KERNEL
kernel_modules:
  trustix_crypto:
    mode: REQUIRED
    path: " kernel/trustix_crypto/trustix_crypto.ko "
    parameters: " "
    unload_on_exit: true
  trustix_datapath:
    mode: AUTO
    path: " kernel/trustix_datapath/trustix_datapath.ko "
  trustix_datapath_helpers:
    mode: AUTO
    path: " kernel/trustix_datapath_helpers/trustix_datapath_helpers.ko "
    parameters: " tixt_tx_plain_skip_sequence=1 "
`), ".yaml")
	if err != nil {
		t.Fatalf("load yaml: %v", err)
	}
	if cfg.IX.Domain != "lab.local" {
		t.Fatalf("ix domain = %q, want lab.local", cfg.IX.Domain)
	}
	if cfg.LAN.Mode != LANModeRouted {
		t.Fatalf("lan mode = %q, want routed", cfg.LAN.Mode)
	}
	if cfg.Endpoints[0].Mode != EndpointModePassive {
		t.Fatalf("endpoint mode = %q, want passive", cfg.Endpoints[0].Mode)
	}
	if got := cfg.Endpoints[0].Security.KeySources; len(got) != 1 || got[0] != "trustix_x25519" {
		t.Fatalf("endpoint security key_sources = %#v, want trustix_x25519", got)
	}
	if cfg.Endpoints[0].Security.WireFormat != "trustix-secure-data-v1" {
		t.Fatalf("endpoint security wire_format = %q", cfg.Endpoints[0].Security.WireFormat)
	}
	if got := cfg.Endpoints[0].Security.CryptoSuites; len(got) != 1 || got[0] != "CHACHA20-POLY1305-X25519" {
		t.Fatalf("endpoint security crypto_suites = %#v, want normalized chacha", got)
	}
	if got := cfg.Peers[0].Endpoints[0].Security.LinkTLS; got != "unsupported" {
		t.Fatalf("peer endpoint link_tls = %q, want unsupported", got)
	}
	if cfg.TransportPolicy.CryptoPlacement != "auto" {
		t.Fatalf("transport crypto placement = %q, want auto", cfg.TransportPolicy.CryptoPlacement)
	}
	if cfg.TransportPolicy.KernelTransport.Mode != "require_kernel" {
		t.Fatalf("kernel transport mode = %q, want require_kernel", cfg.TransportPolicy.KernelTransport.Mode)
	}
	if cfg.TransportPolicy.FragmentPolicy != "drop" {
		t.Fatalf("fragment policy = %q, want drop", cfg.TransportPolicy.FragmentPolicy)
	}
	if cfg.TransportPolicy.Encryption != "send_encrypted" {
		t.Fatalf("encryption = %q, want send_encrypted", cfg.TransportPolicy.Encryption)
	}
	if cfg.TransportPolicy.CryptoKeySource != "tls_exporter" {
		t.Fatalf("crypto key source = %q, want tls_exporter", cfg.TransportPolicy.CryptoKeySource)
	}
	if got := cfg.TransportPolicy.CryptoSuites; len(got) != 2 || got[0] != "AES-128-GCM-X25519" || got[1] != "CHACHA20-POLY1305-X25519" {
		t.Fatalf("transport crypto suites = %#v", got)
	}
	if pool := cfg.TransportPolicy.SessionPool; pool.Size != 4 || pool.Strategy != "five_tuple" || !pool.Warmup || pool.Heartbeat.Mode != "enabled" || pool.Heartbeat.Interval != "5s" || pool.Heartbeat.Timeout != "1s" {
		t.Fatalf("session pool = %#v", pool)
	}
	identity := cfg.TransportPolicy.TLSIdentity
	if identity.Mode != "custom_cert" || identity.CertPath != "./certs/transport.crt" || identity.KeyPath != "./certs/transport.key" || len(identity.TrustRoots) != 1 || identity.TrustRoots[0] != "./certs/public-root.pem" {
		t.Fatalf("tls identity = %#v", identity)
	}
	if cfg.TransportPolicy.MTU != 1400 {
		t.Fatalf("mtu = %d, want 1400", cfg.TransportPolicy.MTU)
	}
	if cfg.Routes[0].Owner != "ix-b" {
		t.Fatalf("route owner = %q, want ix-b", cfg.Routes[0].Owner)
	}
	if cfg.Routes[0].Kind != "unicast" {
		t.Fatalf("route kind = %q, want unicast", cfg.Routes[0].Kind)
	}
	if module := cfg.KernelModules.TrustIXCrypto; module.Mode != "required" || module.Path != "kernel/trustix_crypto/trustix_crypto.ko" || module.Parameters != "" || !module.UnloadOnExit {
		t.Fatalf("trustix_crypto module config = %#v", module)
	}
	if module := cfg.KernelModules.TrustIXDatapath; module.Mode != "auto" || module.Path != "kernel/trustix_datapath/trustix_datapath.ko" || module.Parameters != "" || module.UnloadOnExit {
		t.Fatalf("trustix_datapath module config = %#v", module)
	}
	if module := cfg.KernelModules.TrustIXDatapathHelpers; module.Mode != "auto" || module.Path != "kernel/trustix_datapath_helpers/trustix_datapath_helpers.ko" || module.Parameters != "tixt_tx_plain_skip_sequence=1" || module.UnloadOnExit {
		t.Fatalf("trustix_datapath_helpers module config = %#v", module)
	}
	if hostAPI := cfg.Management.HostAPI; !hostAPI.Enabled || hostAPI.Listen != "10.0.0.1:8787" || !hostAPI.RequireReadAuth {
		t.Fatalf("management host api = %#v", hostAPI)
	}
	if tls := cfg.Management.TLS; tls.Mode != "required" || tls.Identity != "custom_cert" || tls.CertPath != "./certs/management.crt" || tls.KeyPath != "./certs/management.key" {
		t.Fatalf("management tls = %#v", tls)
	}
	if webUI := cfg.Management.WebUI; !webUI.Enabled || webUI.CustomDir != "./webui" {
		t.Fatalf("management web ui = %#v", webUI)
	}
}

func TestLoadJSONNormalizesTransportProfiles(t *testing.T) {
	cfg, err := LoadBytes([]byte(`{
  "domain": {"id": "lab.local"},
  "ix": {"id": "ix-a"},
  "transport_policy": {
    "profile": "PERFORMANCE",
    "datapath": "TC-XDP",
    "profiles": [
      {
        "transport": "ackless_tcp",
        "profile": "throughput",
        "datapath": "full-kernel",
        "encryption": "PLAINTEXT",
        "crypto_placement": "USERSPACE",
        "advanced": {
          "allow_outer_gso_unsafe": true,
          "large_frames": "ON",
          "gso": "ENABLED",
          "shards": 8,
          "max_frames": 64
        }
      }
    ]
  }
}`), ".json")
	if err != nil {
		t.Fatalf("load json transport profiles: %v", err)
	}
	if cfg.TransportPolicy.Profile != "performance" {
		t.Fatalf("transport profile = %q, want performance", cfg.TransportPolicy.Profile)
	}
	if cfg.TransportPolicy.Datapath != "tc_xdp" {
		t.Fatalf("transport datapath = %q, want tc_xdp", cfg.TransportPolicy.Datapath)
	}
	if len(cfg.TransportPolicy.Profiles) != 1 {
		t.Fatalf("transport profiles = %#v, want one profile", cfg.TransportPolicy.Profiles)
	}
	profile := cfg.TransportPolicy.Profiles[0]
	if profile.Transport != "experimental_tcp" || profile.Profile != "performance" || profile.Datapath != "kernel_module" || profile.Encryption != "plaintext" || profile.CryptoPlacement != "userspace" {
		t.Fatalf("transport profile override = %#v, want normalized ackless tcp performance kernel module plaintext", profile)
	}
	if !profile.Advanced.AllowOuterGSOUnsafe || profile.Advanced.LargeFrames != "enabled" || profile.Advanced.GSO != "enabled" || profile.Advanced.Shards != 8 || profile.Advanced.MaxFrames != 64 {
		t.Fatalf("transport profile advanced = %#v", profile.Advanced)
	}
}

func TestLoadBytesAcceptsReverseOnlyPeerEndpoint(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
lan:
  iface: br-lan
  gateway: 10.0.0.1/24
  advertise:
    - 10.0.0.0/24
peers:
  - id: ix-b
    domain: lab.local
    endpoints:
      - name: ix-b-udp
        mode: passive
        transport: udp
    allowed_prefixes:
      - 10.0.1.0/24
routes:
  - prefix: 10.0.1.0/24
    next_hop: ix-b
    endpoint: ix-b-udp
`), ".yaml")
	if err != nil {
		t.Fatalf("load reverse-only peer endpoint: %v", err)
	}
	endpoint := cfg.Peers[0].Endpoints[0]
	if endpoint.Mode != EndpointModePassive || endpoint.Address != "" {
		t.Fatalf("peer endpoint = %#v, want passive without address", endpoint)
	}
}

func TestLoadBytesRejectsUnsupportedTransportCryptoPlacement(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
transport_policy:
  crypto_placement: plaintext
`), ".yaml")
	if err == nil {
		t.Fatal("expected unsupported transport crypto placement error")
	}
}

func TestLoadBytesRejectsUnsupportedTransportProfile(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
transport_policy:
  profile: impossible
`), ".yaml")
	if err == nil {
		t.Fatal("expected unsupported transport profile error")
	}
}

func TestLoadBytesRejectsUnsupportedTransportDatapath(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
transport_policy:
  datapath: impossible
`), ".yaml")
	if err == nil {
		t.Fatal("expected unsupported transport datapath error")
	}
}

func TestLoadBytesRejectsUnknownTransportPolicyField(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
transport_policy:
  experimental_tcp:
    crypto_placement: userspace
`), ".yaml")
	if err == nil {
		t.Fatal("expected unknown transport policy field error")
	}
}

func TestLoadJSONRejectsUnknownKernelModuleField(t *testing.T) {
	_, err := LoadBytes([]byte(`{
  "domain": {"id": "lab.local"},
  "ix": {"id": "ix-a"},
  "kernel_modules": {
    "trustix_kernel": {"mode": "disabled"}
  }
}`), ".json")
	if err == nil {
		t.Fatal("expected unknown kernel module field error")
	}
}

func TestLoadBytesRejectsUnsupportedKernelTransportMode(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
transport_policy:
  kernel_transport:
    mode: magic
`), ".yaml")
	if err == nil {
		t.Fatal("expected unsupported kernel_transport mode error")
	}
}

func TestLoadBytesRejectsUnsupportedCryptoKeySource(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
transport_policy:
  crypto_key_source: magic
`), ".yaml")
	if err == nil {
		t.Fatal("expected unsupported crypto key source error")
	}
}

func TestLoadBytesRejectsUnsupportedCryptoSuite(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
transport_policy:
  crypto_suites:
    - RC4-X25519
`), ".yaml")
	if err == nil {
		t.Fatal("expected unsupported crypto suite error")
	}
}

func TestLoadBytesRejectsUnsupportedTransportEncryption(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
transport_policy:
  encryption: maybe
`), ".yaml")
	if err == nil {
		t.Fatal("expected unsupported transport encryption error")
	}
}

func TestLoadBytesRejectsIncompleteKernelTunnelEndpoint(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
endpoints:
  - name: sh-gre
    listen: local=198.18.0.1,remote=198.18.0.2
    transport: gre
    enabled: true
`), ".yaml")
	if err == nil {
		t.Fatal("expected incomplete GRE tunnel endpoint config to fail")
	}
}

func TestLoadBytesAcceptsKernelTunnelEndpointContract(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
endpoints:
  - name: sh-gre
    listen: local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.0.1/30,remote_carrier=10.255.0.2,mtu=1300
    transport: gre
    enabled: true
`), ".yaml")
	if err != nil {
		t.Fatalf("load GRE tunnel endpoint config: %v", err)
	}
	if cfg.Endpoints[0].Transport != "gre" {
		t.Fatalf("transport = %q, want gre", cfg.Endpoints[0].Transport)
	}
}

func TestLoadBytesAcceptsVXLANEndpointContract(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
endpoints:
  - name: sh-vxlan
    listen: local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.0.1/30,remote_carrier=10.255.0.2,port=4789,mtu=1450,vni=7
    transport: vxlan
    enabled: true
`), ".yaml")
	if err != nil {
		t.Fatalf("load VXLAN tunnel endpoint config: %v", err)
	}
	if cfg.Endpoints[0].Transport != "vxlan" {
		t.Fatalf("transport = %q, want vxlan", cfg.Endpoints[0].Transport)
	}
}

func TestLoadBytesAcceptsVXLANUnderlayInterface(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
endpoints:
  - name: sh-vxlan
    listen: local=198.18.0.1,remote=198.18.0.2,underlay_if=tix216ula,local_carrier=10.255.0.1/30,remote_carrier=10.255.0.2,port=4789,mtu=1450,vni=7
    transport: vxlan
    enabled: true
`), ".yaml")
	if err != nil {
		t.Fatalf("load VXLAN tunnel endpoint config: %v", err)
	}
	if cfg.Endpoints[0].Transport != "vxlan" {
		t.Fatalf("transport = %q, want vxlan", cfg.Endpoints[0].Transport)
	}
}

func TestLoadBytesRejectsInvalidKernelTunnelMTU(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
endpoints:
  - name: sh-gre
    listen: local=198.18.0.1,remote=198.18.0.2,local_carrier=10.255.0.1/30,remote_carrier=10.255.0.2,mtu=4
    transport: gre
    enabled: true
`), ".yaml")
	if err == nil {
		t.Fatal("expected invalid GRE tunnel mtu to fail")
	}
}

func TestLoadBytesRejectsUnsupportedEndpointSecurityEncryption(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
endpoints:
  - name: sh-udp
    listen: 0.0.0.0:7000
    transport: udp
    security:
      encryption: maybe
    enabled: true
`), ".yaml")
	if err == nil {
		t.Fatal("expected unsupported endpoint security encryption error")
	}
}

func TestLoadBytesRejectsIncompleteCustomTransportTLSIdentity(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
transport_policy:
  tls_identity:
    mode: custom_cert
    cert: ./certs/transport.crt
    system_roots: true
`), ".yaml")
	if err == nil {
		t.Fatal("expected incomplete custom transport TLS identity error")
	}
}

func TestLoadBytesRejectsCustomTransportTLSListenerWithoutCertificate(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
endpoints:
  - name: tcp-in
    listen: 127.0.0.1:7000
    transport: tcp
    enabled: true
transport_policy:
  tls_identity:
    mode: custom_cert
    system_roots: true
`), ".yaml")
	if err == nil {
		t.Fatal("expected custom transport TLS listener cert/key error")
	}
}

func TestLoadBytesAllowsDialOnlyCustomTransportTLSWithoutCertificate(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
peers:
  - id: ix-b
    domain: lab.local
    endpoints:
      - name: tcp-out
        address: 203.0.113.20:7000
        transport: tcp
transport_policy:
  tls_identity:
    mode: custom_cert
    system_roots: true
`), ".yaml")
	if err != nil {
		t.Fatalf("load dial-only custom transport TLS config: %v", err)
	}
	if cfg.TransportPolicy.TLSIdentity.Mode != "custom_cert" {
		t.Fatalf("tls identity mode = %q, want custom_cert", cfg.TransportPolicy.TLSIdentity.Mode)
	}
}

func TestLoadBytesAllowsCustomTransportTLSWithoutCertificateForNonTLSPassiveListener(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
endpoints:
  - name: udp-in
    listen: 127.0.0.1:7000
    transport: udp
    enabled: true
transport_policy:
  tls_identity:
    mode: custom_cert
    system_roots: true
`), ".yaml")
	if err != nil {
		t.Fatalf("load non-TLS custom transport listener: %v", err)
	}
	if cfg.TransportPolicy.TLSIdentity.Mode != "custom_cert" {
		t.Fatalf("tls identity mode = %q, want custom_cert", cfg.TransportPolicy.TLSIdentity.Mode)
	}
}

func TestLoadBytesRejectsTLSExporterWithUnsupportedLinkTLS(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
peers:
  - id: ix-b
    domain: lab.local
    endpoints:
      - name: tcp-out
        address: 203.0.113.20:7000
        transport: tcp
        security:
          link_tls: unsupported
          key_sources:
            - tls_exporter
`), ".yaml")
	if err == nil {
		t.Fatal("expected tls_exporter with link_tls unsupported to fail")
	}
}

func TestLoadBytesRejectsUnsupportedLinkTLSForQUIC(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
peers:
  - id: ix-b
    domain: lab.local
    endpoints:
      - name: quic-out
        address: 203.0.113.20:7000
        transport: quic
        security:
          link_tls: unsupported
`), ".yaml")
	if err == nil {
		t.Fatal("expected quic link_tls unsupported to fail")
	}
}

func TestLoadBytesRejectsRequiredLinkTLSForUDP(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
peers:
  - id: ix-b
    domain: lab.local
    endpoints:
      - name: udp-out
        address: 203.0.113.20:7000
        transport: udp
        security:
          link_tls: required
`), ".yaml")
	if err == nil {
		t.Fatal("expected required link_tls on udp to fail")
	}
}

func TestLoadBytesRejectsUnsupportedKernelModuleMode(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
kernel_modules:
  trustix_crypto:
    mode: force
`), ".yaml")
	if err == nil {
		t.Fatal("expected unsupported kernel module mode error")
	}
}

func TestLoadBytesRejectsHostManagementAPIWithoutListenOrGateway(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
management:
  host_api:
    enabled: true
`), ".yaml")
	if err == nil {
		t.Fatal("expected host management API listen/gateway error")
	}
}

func TestLoadBytesRejectsInvalidHostManagementAPIListen(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
management:
  host_api:
    enabled: true
    listen: 10.0.0.1
`), ".yaml")
	if err == nil {
		t.Fatal("expected invalid host management API listen error")
	}
}

func TestLoadBytesAcceptsWebUIWithoutHostManagementAPI(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
management:
  web_ui:
    enabled: true
    custom_dir: " ./custom-webui "
`), ".yaml")
	if err != nil {
		t.Fatalf("load web ui: %v", err)
	}
	if webUI := cfg.Management.WebUI; !webUI.Enabled || webUI.CustomDir != "./custom-webui" {
		t.Fatalf("web ui = %#v, want enabled with custom dir", webUI)
	}
}

func TestLoadBytesRejectsUnsupportedManagementTLSMode(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
management:
  tls:
    mode: magic
`), ".yaml")
	if err == nil {
		t.Fatal("expected unsupported management tls mode error")
	}
}

func TestLoadBytesRejectsIncompleteCustomManagementTLSIdentity(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
management:
  tls:
    identity: custom_cert
    cert: ./certs/management.crt
`), ".yaml")
	if err == nil {
		t.Fatal("expected incomplete custom management tls identity error")
	}
}

func TestLoadBytesNormalizesRoutePolicyPrefixes(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
route_policy:
  import_prefixes:
    - 10.0.1.42/24
  export_prefixes:
    - 10.0.0.42/24
  dynamic_metric: 250
`), ".yaml")
	if err != nil {
		t.Fatalf("load route policy yaml: %v", err)
	}
	if cfg.RoutePolicy.ImportPrefixes[0] != "10.0.1.0/24" {
		t.Fatalf("import prefixes = %#v", cfg.RoutePolicy.ImportPrefixes)
	}
	if cfg.RoutePolicy.ExportPrefixes[0] != "10.0.0.0/24" {
		t.Fatalf("export prefixes = %#v", cfg.RoutePolicy.ExportPrefixes)
	}
	if cfg.RoutePolicy.DynamicMetric != 250 {
		t.Fatalf("dynamic metric = %d, want 250", cfg.RoutePolicy.DynamicMetric)
	}
}

func TestLoadBytesRejectsUnsupportedFragmentPolicy(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
transport_policy:
  fragment_policy: rewrite
`), ".yaml")
	if err == nil {
		t.Fatal("expected unsupported fragment policy error")
	}
}

func TestLoadBytesRejectsUnsupportedSessionPoolPolicy(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
lan:
  iface: br-lan
  gateway: 10.0.0.1/24
  advertise:
    - 10.0.0.0/24
endpoints:
  - name: sh-udp
    listen: 0.0.0.0:7000
    transport: udp
    enabled: true
peers: []
routes: []
transport_policy:
  session_pool:
    size: 2
    strategy: random
`), ".yaml")
	if err == nil {
		t.Fatal("expected unsupported session pool strategy error")
	}

	_, err = LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
lan:
  iface: br-lan
  gateway: 10.0.0.1/24
  advertise:
    - 10.0.0.0/24
endpoints:
  - name: sh-udp
    listen: 0.0.0.0:7000
    transport: udp
    enabled: true
peers: []
routes: []
transport_policy:
  session_pool:
    size: -1
`), ".yaml")
	if err == nil {
		t.Fatal("expected negative session pool size error")
	}
}

func TestLoadBytesAcceptsBlackholeAndRejectRoutes(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
routes:
  - prefix: 10.66.0.0/16
    kind: blackhole
    metric: 10
  - prefix: 10.77.0.0/16
    kind: reject
    next_hop: ix-a
    metric: 20
`), ".yaml")
	if err != nil {
		t.Fatalf("load route kind yaml: %v", err)
	}
	if cfg.Routes[0].Kind != "blackhole" || cfg.Routes[0].Owner != "" || cfg.Routes[0].NextHop != "" {
		t.Fatalf("blackhole route = %#v", cfg.Routes[0])
	}
	if cfg.Routes[1].Kind != "reject" || cfg.Routes[1].NextHop != "ix-a" {
		t.Fatalf("reject route = %#v", cfg.Routes[1])
	}
}

func TestLoadBytesRejectsUnsupportedRouteKind(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
routes:
  - prefix: 10.66.0.0/16
    kind: throw
`), ".yaml")
	if err == nil {
		t.Fatal("expected unsupported route kind error")
	}
}

func TestLoadBytesAcceptsNATRewritePolicy(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
lan:
  iface: br-lan
  gateway: 10.0.0.1/24
  advertise:
    - 10.0.0.0/24
policies:
  - name: default-nat
    rewrite: SNAT_GATEWAY
`), ".yaml")
	if err != nil {
		t.Fatalf("load NAT rewrite policy: %v", err)
	}
	if cfg.Policies[0].Rewrite != "SNAT_GATEWAY" {
		t.Fatalf("policy rewrite = %q", cfg.Policies[0].Rewrite)
	}
}

func TestLoadBytesAcceptsNATRuntimeConfig(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
lan:
  iface: br-lan
  gateway: 10.0.0.1/24
  advertise:
    - 10.0.0.0/24
  mode: nat
  nat:
    max_bindings: 2048
    binding_ttl: "90s"
`), ".yaml")
	if err != nil {
		t.Fatalf("load NAT runtime config: %v", err)
	}
	if cfg.LAN.NAT.MaxBindings != 2048 || cfg.LAN.NAT.BindingTTL != "90s" {
		t.Fatalf("NAT config = %#v", cfg.LAN.NAT)
	}
}

func TestLoadBytesAcceptsExistingLANAttachMode(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
lan:
  iface: " br-lan "
  attach_mode: EXISTING
  gateway: " 10.0.0.1/24 "
  advertise:
    - 10.0.0.0/24
  manage_address: false
`), ".yaml")
	if err != nil {
		t.Fatalf("load existing LAN attach mode: %v", err)
	}
	if cfg.LAN.Iface != "br-lan" {
		t.Fatalf("lan iface = %q, want br-lan", cfg.LAN.Iface)
	}
	if cfg.LAN.Gateway != "10.0.0.1/24" {
		t.Fatalf("lan gateway = %q, want trimmed prefix", cfg.LAN.Gateway)
	}
	if cfg.LAN.AttachMode != LANAttachModeExisting {
		t.Fatalf("lan attach_mode = %q, want existing", cfg.LAN.AttachMode)
	}
}

func TestLoadBytesAcceptsMultiLANConfig(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
primary_lan_id: public
lans:
  - id: home
    type: local
    iface: " br-lan "
    attach_mode: existing
    gateway: " 10.0.0.1/24 "
    advertise:
      - 10.0.0.0/24
    device_access:
      enabled: true
      address_pool: 10.0.0.240/28
    manage_address: false
  - id: public
    type: trusted-public
    iface: br-pub
    gateway: 203.0.113.1/29
    advertise:
      - 203.0.113.0/29
    device_access:
      enabled: true
      address_pool: 203.0.113.4/30
management:
  host_api:
    enabled: true
`), ".yaml")
	if err != nil {
		t.Fatalf("load multi LAN config: %v", err)
	}
	if len(cfg.LANs) != 2 {
		t.Fatalf("lans = %d, want 2", len(cfg.LANs))
	}
	if cfg.LANs[0].ID != "home" || cfg.LANs[0].Type != LANTypeLocal || cfg.LANs[0].Iface != "br-lan" || cfg.LANs[0].AttachMode != LANAttachModeExisting {
		t.Fatalf("first LAN = %#v", cfg.LANs[0])
	}
	if cfg.LANs[1].Type != LANTypeTrustedPublic {
		t.Fatalf("second LAN type = %q, want trusted_public", cfg.LANs[1].Type)
	}
	effective := EffectiveLANs(cfg)
	if len(effective) != 2 || effective[0].ID != "home" || effective[1].ID != "public" {
		t.Fatalf("effective LANs = %#v", effective)
	}
	if got := EffectiveLANAdvertise(cfg); len(got) != 2 || got[0] != "10.0.0.0/24" || got[1] != "203.0.113.0/29" {
		t.Fatalf("effective advertise = %#v", got)
	}
	if primary := PrimaryLAN(cfg); primary.ID != "public" || primary.Iface != "br-pub" {
		t.Fatalf("primary LAN = %#v, want public", primary)
	}
	if accessLANs := DeviceAccessLANs(cfg); len(accessLANs) != 2 || accessLANs[0].ID != "home" || accessLANs[1].ID != "public" {
		t.Fatalf("device access LANs = %#v, want home and public", accessLANs)
	}
}

func TestLoadBytesRejectsInvalidMultiLANConfig(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "missing id",
			body: `
lans:
  - iface: br-lan
    gateway: 10.0.0.1/24
    advertise:
      - 10.0.0.0/24
`,
		},
		{
			name: "duplicate id",
			body: `
lans:
  - id: home
    iface: br-lan
    gateway: 10.0.0.1/24
    advertise:
      - 10.0.0.0/24
  - id: home
    iface: br-lan2
    gateway: 10.0.1.1/24
    advertise:
      - 10.0.1.0/24
`,
		},
		{
			name: "unsupported type",
			body: `
lans:
  - id: home
    type: dmz
    iface: br-lan
    gateway: 10.0.0.1/24
    advertise:
      - 10.0.0.0/24
`,
		},
		{
			name: "overlap",
			body: `
lans:
  - id: home
    iface: br-lan
    gateway: 10.0.0.1/24
    advertise:
      - 10.0.0.0/24
  - id: lab
    iface: br-lab
    gateway: 10.0.0.129/25
    advertise:
      - 10.0.0.128/25
`,
		},
		{
			name: "unknown primary",
			body: `
primary_lan_id: missing
lans:
  - id: home
    iface: br-lan
    gateway: 10.0.0.1/24
    advertise:
      - 10.0.0.0/24
`,
		},
		{
			name: "overlapping device access pools",
			body: `
lans:
  - id: home
    device_access:
      enabled: true
      address_pool: 10.0.0.128/25
  - id: lab
    device_access:
      enabled: true
      address_pool: 10.0.0.192/26
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := `
domain:
  id: lab.local
ix:
  id: ix-a
` + tt.body
			_, err := LoadBytes([]byte(payload), ".yaml")
			if err == nil {
				t.Fatal("expected multi LAN config to be rejected")
			}
		})
	}
}

func TestLoadBytesRejectsInvalidExistingLANAttachMode(t *testing.T) {
	tests := []struct {
		name string
		lan  string
	}{
		{
			name: "unsupported",
			lan: `
  iface: br-lan
  attach_mode: floating
  gateway: 10.0.0.1/24
  advertise:
    - 10.0.0.0/24
  manage_address: false
`,
		},
		{
			name: "missing gateway",
			lan: `
  iface: br-lan
  attach_mode: existing
  advertise:
    - 10.0.0.0/24
  manage_address: false
`,
		},
		{
			name: "manage address",
			lan: `
  iface: br-lan
  attach_mode: existing
  gateway: 10.0.0.1/24
  advertise:
    - 10.0.0.0/24
  manage_address: true
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
lan:
`+tt.lan), ".yaml")
			if err == nil {
				t.Fatal("expected existing LAN attach config to be rejected")
			}
		})
	}
}

func TestLoadBytesRejectsInvalidNATRuntimeConfig(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
lan:
  iface: br-lan
  gateway: 10.0.0.1/24
  advertise:
    - 10.0.0.0/24
  mode: routed
  nat:
    max_bindings: 2048
`), ".yaml")
	if err == nil {
		t.Fatal("expected routed lan nat config to be rejected")
	}

	_, err = LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
lan:
  iface: br-lan
  gateway: 10.0.0.1/24
  advertise:
    - 10.0.0.0/24
  mode: nat
  nat:
    max_bindings: -1
    binding_ttl: "90s"
`), ".yaml")
	if err == nil {
		t.Fatal("expected negative NAT max_bindings to be rejected")
	}

	_, err = LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
lan:
  iface: br-lan
  gateway: 10.0.0.1/24
  advertise:
    - 10.0.0.0/24
  mode: nat
  nat:
    binding_ttl: "0s"
`), ".yaml")
	if err == nil {
		t.Fatal("expected non-positive NAT binding_ttl to be rejected")
	}
}

func TestLoadBytesRejectsNATRewritePolicyWithoutGateway(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
policies:
  - name: default-nat
    rewrite: snat_gateway
`), ".yaml")
	if err == nil {
		t.Fatal("expected NAT rewrite without gateway to be rejected")
	}
}

func TestLoadBytesRejectsUnauthorizedRoute(t *testing.T) {
	_, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
lan:
  iface: br-lan
  gateway: 10.0.0.1/24
  advertise:
    - 10.0.0.0/24
endpoints:
  - name: sh-udp
    listen: 0.0.0.0:7000
    transport: udp
    enabled: true
peers:
  - id: ix-b
    domain: lab.local
    endpoints:
      - name: hk-udp
        address: 203.0.113.10:7000
        transport: udp
    allowed_prefixes:
      - 10.0.1.0/24
routes:
  - prefix: 10.0.2.0/24
    next_hop: ix-b
    endpoint: hk-udp
    metric: 100
`), ".yaml")
	if err == nil {
		t.Fatal("expected unauthorized route error")
	}
}

func TestLoadBytesAcceptsTransitRouteOwnerViaNextHop(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-a
lan:
  iface: br-lan
  gateway: 10.0.0.1/24
  advertise:
    - 10.0.0.0/24
peers:
  - id: ix-b
    domain: lab.local
    endpoints:
      - name: b-udp
        address: 203.0.113.10:7000
        transport: udp
    allowed_prefixes:
      - 10.0.1.0/24
  - id: ix-c
    domain: lab.local
    endpoints: []
    allowed_prefixes:
      - 10.0.2.0/24
routes:
  - prefix: 10.0.2.42/24
    owner: ix-c
    next_hop: ix-b
    endpoint: b-udp
    policy: default-routed
    metric: 50
`), ".yaml")
	if err != nil {
		t.Fatalf("load transit route yaml: %v", err)
	}
	route := cfg.Routes[0]
	if route.Prefix != "10.0.2.0/24" || route.Owner != "ix-c" || route.NextHop != "ix-b" || route.Endpoint != "b-udp" {
		t.Fatalf("transit route = %#v", route)
	}
}

func TestLoadBytesAcceptsBootstrapOnlyPeerDiscovery(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
domain:
  id: lab.local
ix:
  id: ix-c
  control_api: https://c.example.com:9443
lan:
  iface: br-lan
  gateway: 10.0.2.1/24
  advertise:
    - 10.0.2.0/24
endpoints:
  - name: c-udp
    listen: 0.0.0.0:7003
    address: c.example.com:7003
    transport: udp
    enabled: true
bootstrap:
  peers:
    - control_api: https://a.example.com:9443
routes: []
`), ".yaml")
	if err != nil {
		t.Fatalf("load bootstrap yaml: %v", err)
	}
	if len(cfg.Bootstrap.Peers) != 1 {
		t.Fatalf("bootstrap peers = %d, want 1", len(cfg.Bootstrap.Peers))
	}
	if cfg.Bootstrap.Peers[0].Domain != "" {
		t.Fatalf("bootstrap domain = %q, want empty/defaulted at runtime", cfg.Bootstrap.Peers[0].Domain)
	}
}
