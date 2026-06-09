export type Bootstrap = {
  api_base?: string;
  asset_base?: string;
  require_admin_proof?: boolean;
  admin_read_auth_enabled?: boolean;
};

export type StatusPayload = {
  domain_id?: string;
  ix_id?: string;
  config_head?: {
    seq?: number;
    hash?: string;
  };
  build?: {
    version?: string;
    commit?: string;
    built_at?: string;
  };
  counts?: {
    local_endpoints?: number;
    peers?: number;
    peer_endpoints?: number;
    routes?: number;
  };
  domain_ix?: {
    active?: number;
    t1?: number;
    local?: number;
    direct?: number;
    downstream?: number;
    stale?: number;
  };
  domain_prefixes?: {
    total?: number;
    accepted?: number;
    local?: number;
    device?: number;
    direct?: number;
    transit?: number;
    static?: number;
    rejected?: number;
  };
  transports?: string[];
  management?: {
    primary?: ListenerStatus;
    host?: ListenerStatus;
    web_ui?: {
      enabled?: boolean;
      active?: boolean;
      mode?: string;
      exposed_on?: string[];
      custom_dir?: string;
      error?: string;
    };
  };
  dns?: DNSStatus;
  kernel_modules?: KernelModuleStatus[];
  data_path?: {
    active_sessions?: number;
    counters?: Record<string, number>;
    kernel_offload?: KernelOffloadStatus;
    kernel_rx_stage?: KernelRXStageStatus;
    kernel_transport?: KernelTransportStatus;
    kernel_udp?: KernelUDPStatus;
    experimental_tcp?: ExperimentalTCPStatus;
    sessions?: DataPathSession[];
  };
};

export type KernelCapabilitiesPayload = {
  modules?: KernelModuleStatus[];
  offload?: KernelOffloadStatus;
  rx_stage?: KernelRXStageStatus;
  kernel_transport?: KernelTransportStatus;
  kernel_udp?: KernelUDPStatus;
  experimental_tcp?: ExperimentalTCPStatus;
  datapath_mode?: string;
  capabilities?: string[];
};

export type ListenerStatus = {
  listen?: string;
  scope?: string;
  enabled?: boolean;
  error?: string;
  read_auth?: boolean;
  write_auth?: boolean;
};

export type DoctorCheck = {
  name?: string;
  status?: string;
  detail?: string;
};

export type DesiredConfig = {
  domain?: {
    id?: string;
    trust_roots?: string[];
  };
  ix?: {
    id?: string;
    domain?: string;
    cert?: string;
    key?: string;
    control_api?: string;
    control_api_publish?: string;
    config_log?: string;
    route_authorizations?: string[];
  };
  primary_lan_id?: string;
  lan?: LANConfig;
  lans?: LANConfig[];
  management?: ManagementConfig;
  dns?: DNSConfig;
  kernel_modules?: KernelModulesConfig;
  trust?: TrustConfig;
  endpoints?: EndpointConfig[];
  bootstrap?: BootstrapConfig;
  control_fabric?: ControlFabricConfig;
  peers?: PeerConfig[];
  routes?: RouteConfig[];
  route_policy?: {
    import_prefixes?: string[];
    export_prefixes?: string[];
    dynamic_metric?: number;
    transit_forwarding?: boolean;
    import_transit_routes?: boolean;
    [key: string]: unknown;
  };
  policies?: Record<string, unknown>[];
  transport_policy?: TransportPolicyConfig;
};

export type ManagementConfig = {
  host_api?: {
    enabled?: boolean;
    listen?: string;
    require_read_auth?: boolean;
    allow_unauthenticated_reads?: boolean;
    allow_unauthenticated_writes?: boolean;
  };
  tls?: {
    mode?: string;
    identity?: string;
    cert?: string;
    key?: string;
  };
  web_ui?: {
    enabled?: boolean;
    custom_dir?: string;
  };
};

export type DNSConfig = {
  enabled?: boolean;
  listen?: string;
  domain?: string;
  ttl?: string;
  upstreams?: string[];
  capture?: string;
  dnsmasq?: {
    enabled?: boolean;
  };
};

export type DNSStatus = DNSConfig & {
  running?: boolean;
  error?: string;
  dnsmasq?: {
    enabled?: boolean;
    mode?: string;
    server?: string;
    section?: string;
    applied?: boolean;
    error?: string;
  };
};

export type KernelModuleConfig = {
  mode?: string;
  path?: string;
  parameters?: string;
  reload_on_upgrade?: string;
  unload_on_exit?: boolean;
};

export type KernelDatapathRuntimeConfig = {
  rx_stage?: string;
  rx_worker?: boolean;
  tx_plaintext?: boolean;
  full_plaintext?: boolean;
  rx_worker_allow_experimental_tcp?: boolean;
  rx_worker_hot_stats?: boolean;
};

export type KernelModulesConfig = {
  capability_profile?: string;
  datapath?: KernelDatapathRuntimeConfig;
  trustix_crypto?: KernelModuleConfig;
  trustix_datapath?: KernelModuleConfig;
  trustix_datapath_helpers?: KernelModuleConfig;
};

export type TrustConfig = {
  revoked_cert_fingerprints?: string[];
  trust_roots_pem?: string[];
  admin_policy?: {
    threshold?: number;
    allowed_fingerprints?: string[];
  };
};

export type BootstrapConfig = {
  peers?: BootstrapPeerConfig[];
};

export type BootstrapPeerConfig = {
  id?: string;
  domain?: string;
  control_api?: string;
};

export type ControlFabricConfig = {
  profile?: string;
  dynamic_control_fanout?: number;
  member_page_size?: number;
  member_import_limit?: number;
};

export type LANConfig = {
  id?: string;
  type?: string;
  iface?: string;
  underlay_iface?: string;
  gateway?: string;
  advertise?: string[];
  mode?: string;
  attach_mode?: string;
  nat?: {
    max_bindings?: number;
    binding_ttl?: string;
  };
  device_access?: {
    enabled?: boolean;
    address_pool?: string;
    lease_ttl?: string;
  };
  manage_address?: boolean;
  manage_forwarding?: boolean;
  manage_rp_filter?: boolean;
};

export type EndpointSecurityConfig = {
  link_tls?: string;
  tls_identity?: string;
  encryption?: string;
  key_sources?: string[];
  wire_format?: string;
  crypto_suites?: string[];
  crypto_placements?: string[];
};

export type EndpointProfileConfig = {
  version?: number;
  profile?: string;
  datapath?: string;
  encryption?: string;
  crypto_placement?: string;
  features?: string[];
};

export type EndpointLocalBindConfig = {
  source_ip?: string;
  iface?: string;
};

export type EndpointConfig = {
  name?: string;
  mode?: string;
  listen?: string;
  address?: string;
  local_bind?: EndpointLocalBindConfig;
  transport?: string;
  priority?: number;
  tls_server_name?: string;
  publish?: {
    mode?: string;
    only_peers?: string[];
    except_peers?: string[];
    domains?: string[];
  };
  access?: {
    mode?: string;
    allowed_peers?: string[];
    default_ttl?: string;
  };
  security?: EndpointSecurityConfig;
  transport_profile?: EndpointProfileConfig;
  enabled?: boolean;
};

export type PeerConfig = {
  id?: string;
  domain?: string;
  control_api?: string;
  tls_server_name?: string;
  endpoints?: EndpointConfig[];
  allowed_prefixes?: string[];
};

export type RouteConfig = {
  prefix?: string;
  kind?: string;
  owner?: string;
  next_hop?: string;
  endpoint?: string;
  policy?: string;
  metric?: number;
};

export type TransportPolicyConfig = {
  mode?: string;
  candidates?: string[];
  failover?: string;
  load_balance?: string;
  profile?: string;
  datapath?: string;
  mtu?: number;
  fragment_policy?: string;
  encryption?: string;
  crypto_key_source?: string;
  crypto_suites?: string[];
  crypto_placement?: string;
  profiles?: TransportProfileConfig[];
  advanced?: TransportAdvancedConfig;
  session_pool?: {
    size?: number;
    strategy?: string;
    warmup?: boolean;
    heartbeat?: {
      mode?: string;
      interval?: string;
      timeout?: string;
    };
  };
  tls_identity?: TransportTLSIdentityConfig;
  kernel_transport?: {
    mode?: string;
  };
};

export type TransportTLSIdentityConfig = {
  mode?: string;
  cert?: string;
  key?: string;
  trust_roots?: string[];
  system_roots?: boolean;
};

export type TransportProfileConfig = {
  transport?: string;
  profile?: string;
  datapath?: string;
  encryption?: string;
  crypto_placement?: string;
  advanced?: TransportAdvancedConfig;
};

export type TransportAdvancedConfig = {
  allow_unsafe?: boolean;
  allow_outer_gso_unsafe?: boolean;
  allow_checksum_skip?: boolean;
  large_frames?: string;
  gso?: string;
  gro?: string;
  shards?: number;
  max_frames?: number;
  batch_bytes?: number;
  flush_delay?: string;
  parameters?: Record<string, string>;
};

export type PeerRuntime = {
  healthy?: boolean;
  last_seen?: string;
  last_error?: string;
  advertisement?: {
    ix_id?: string;
  };
};

export type PeerView = {
  config?: PeerConfig;
  runtime?: PeerRuntime;
};

export type RouteView = RouteConfig & {
  source?: string;
};

export type RouteCandidate = {
  prefix?: string;
  owner?: string;
  origin_ix?: string;
  next_hop?: string;
  learned_from?: string;
  endpoint?: string;
  kind?: string;
  metric?: number;
  source?: string;
  source_priority?: number;
  action?: string;
  reason?: string;
  health?: string;
  selected?: boolean;
  direct?: boolean;
  static?: boolean;
  last_seen?: string;
  path?: string[];
};

export type RoutePolicyStatus = {
  config?: {
    import_prefixes?: string[];
    export_prefixes?: string[];
    dynamic_metric?: number;
    transit_forwarding?: boolean;
    import_transit_routes?: boolean;
    [key: string]: unknown;
  };
  decisions?: Array<{
    direction?: string;
    ix_id?: string;
    origin_ix?: string;
    next_hop_ix?: string;
    prefix?: string;
    action?: string;
    reason?: string;
    source?: string;
  }>;
  candidates?: RouteCandidate[];
  decision_total?: number;
  decision_offset?: number;
  decision_limit?: number;
  decision_truncated?: boolean;
  candidate_total?: number;
  candidate_offset?: number;
  candidate_limit?: number;
  candidate_truncated?: boolean;
};

export type RouteProbeResponse = {
  ok?: boolean;
  destination?: string;
  matched?: boolean;
  prefix?: string;
  route?: RouteView;
  next_hop_configured?: boolean;
  candidate_endpoints?: Array<{
    name?: string;
    transport?: string;
    priority?: number;
    priority_score?: number;
    preference?: number;
    address?: string;
    mode?: string;
    enabled?: boolean;
    link_tls?: string;
    encryption?: string;
    tls_server_name?: string;
  }>;
  candidate_error?: string;
  reason?: string;
};

export type RouteTraceResponse = {
  ok?: boolean;
  destination?: string;
  complete?: boolean;
  reason?: string;
  hops?: Array<{
    index?: number;
    ix_id?: string;
    prefix?: string;
    next_hop?: string;
    endpoint?: string;
    kind?: string;
    terminal?: boolean;
    reason?: string;
  }>;
};

export type EndpointProbeResponse = {
  ok?: boolean;
  peer?: string;
  endpoint?: string;
  transport?: string;
  address?: string;
  healthy?: boolean;
  rtt?: number;
  error?: string;
  checked_at?: string;
  updated?: boolean;
  unsupported?: boolean;
};

export type EndpointView = EndpointConfig & {
  id?: string;
};

export type TransportMatrix = {
  policy?: TransportMatrixPolicy;
  registered?: string[];
  local_endpoints?: Array<EndpointView & TransportMatrixEndpointRuntime>;
  peer_endpoints?: Array<EndpointView & TransportMatrixEndpointRuntime & { peer?: string; reverse_only?: boolean; active_reverse_sessions?: number }>;
  kernel_transport?: KernelTransportStatus;
  experimental_tcp?: Record<string, unknown>;
  kernel_udp?: Record<string, unknown>;
  transport_tls?: Record<string, unknown>;
  sessions?: DataPathSession[];
  counters?: Record<string, number>;
};

export type TransportMatrixPolicy = {
  mode?: string;
  kernel_transport?: string;
  profile?: string;
  datapath?: string;
  crypto_placement?: string;
  encryption?: string;
  crypto_key_source?: string;
  crypto_suites?: string[];
  mtu?: number;
  fragment_policy?: string;
  session_pool_size?: number;
  session_pool_strategy?: string;
  session_pool_warmup?: boolean;
};

export type TransportMatrixEndpointRuntime = {
  preference?: number;
  usable?: boolean;
  profile?: string;
  datapath?: string;
  features?: string[];
  encryption?: string;
  crypto_placements?: string[];
  kernel_compatible?: boolean;
  security_compatible?: boolean;
  profile_compatible?: boolean;
  rtt?: number;
};

export type KernelTransportStatus = {
  mode?: string;
  available?: boolean;
  provider?: string;
  protocols?: Array<{
    protocol?: string;
    available?: boolean;
    placement?: string;
    provider?: string;
    carrier?: string;
    contract?: string;
    capability_ready?: boolean;
    userspace_fallback?: boolean;
    required_config?: string[];
    reason?: string;
  }>;
  notes?: string[];
  statistics?: Record<string, number>;
};

export type KernelModuleStatus = {
  name?: string;
  mode?: string;
  loaded?: boolean;
  managed?: boolean;
  path?: string;
  sha256?: string;
  loaded_sha256?: string;
  parameters?: string;
  reload_on_upgrade?: string;
  upgrade_state?: string;
  ref_count?: number;
  used_by?: string[];
  init_state?: string;
  version?: string;
  abi_version?: number;
  features?: string[];
  missing_features?: string[];
  capability_tier?: string;
  capability_reason?: string;
  state?: string;
  reason?: string;
  loaded_at?: string;
  unload_on_exit?: boolean;
};

export type KernelOffloadStatus = {
  dataplane_mode?: string;
  capabilities?: string[];
  packet_policy?: {
    mtu?: number;
    drop_fragments?: boolean;
    tcp_mss_clamp?: number;
  };
  placements?: KernelPlacementStatus[];
  kernel_candidates?: Array<{
    name?: string;
    layer?: string;
    complexity?: string;
    detail?: string;
  }>;
  userspace_remaining?: Array<{
    name?: string;
    reason?: string;
  }>;
};

export type KernelPlacementStatus = {
  name?: string;
  layer?: string;
  placement?: string;
  detail?: string;
};

export type KernelRXStageStatus = {
  enabled?: boolean;
  active?: boolean;
  mode?: string;
  attached?: boolean;
  ifname?: string;
  ifindex?: number;
  target_ifname?: string;
  target_ifindex?: number;
  flags?: number;
  queue_len?: number;
  capacity?: number;
  staged?: number;
  popped?: number;
  dropped?: number;
  overwritten?: number;
  polls?: number;
  empty_polls?: number;
  packets?: number;
  batches?: number;
  errors?: number;
  rx_worker?: number;
  rx_worker_errors?: number;
  rx_worker_injected?: number;
  rx_worker_dropped?: number;
  last_error?: string;
  last_stopped?: string;
  started_at?: string;
  disabled_reason?: string;
  inactive_reason?: string;
  batch_size?: number;
  idle_delay_ms?: number;
};

export type CryptoFallbackStatus = {
  selected?: string;
  chain?: Array<{
    name?: string;
    ready?: boolean;
    placement?: string;
    layer?: string;
    reason?: string;
  }>;
};

export type KernelUDPStatus = {
  available?: boolean;
  provider?: string;
  fast_path?: boolean;
  direct_only?: boolean;
  tc_only?: boolean;
  userspace_crypto?: boolean;
  kernel_crypto?: boolean;
  kernel_crypto_reason?: string;
  crypto_fallback?: CryptoFallbackStatus;
  requested_crypto?: string;
  effective_crypto?: string;
  preferred_crypto?: string;
  supported_crypto?: string[];
  reinject?: boolean;
  xdp_attach_mode?: string;
  af_xdp_bind_mode?: string;
  zerocopy_enabled?: boolean;
  active_flows?: number;
  submitted_frames?: number;
  received_frames?: number;
  provider_stats?: Record<string, number>;
  notes?: string[];
};

export type ExperimentalTCPStatus = KernelUDPStatus & {
  raw_socket_fallback?: boolean;
  fast_path_fallback_reason?: string;
  fast_path_queues?: number;
  flows?: Array<Record<string, unknown>>;
  kernel_crypto_probe?: {
    kernel_btf?: boolean;
    crypto_kfuncs?: boolean;
    required_kfuncs?: string[];
    missing_kfuncs?: string[];
    aes_gcm?: boolean;
    aes_ni?: boolean;
    aes_gcm_software_fallback?: boolean;
    crypto_algorithms?: string[];
    capability_ready?: boolean;
    provider_ready?: boolean;
    reason?: string;
    self_test?: {
      attempted?: boolean;
      passed?: boolean;
      program_types?: string[];
      reason?: string;
    };
    map_schema?: {
      max_entries?: number;
      flow_key_size?: number;
      flow_value_size?: number;
      directions?: string[];
      key_namespaces?: string[];
      supported_suites?: string[];
      software_fallback_suites?: string[];
      unsupported_suites?: string[];
      unsupported_reasons?: Record<string, string>;
      supported_formats?: string[];
    };
  };
};

export type LinksPayload = {
  local_ix?: string;
  links?: LinkStatus[];
  total?: number;
  offset?: number;
  limit?: number;
  truncated?: boolean;
};

export type LinkStatus = {
  peer?: string;
  domain?: string;
  source?: string;
  control_api?: string;
  static?: boolean;
  dynamic?: boolean;
  trusted?: boolean;
  state?: string;
  warnings?: string[];
  active_sessions?: number;
  current_flows?: number;
  packets_sent?: number;
  packets_received?: number;
  bytes_sent?: number;
  bytes_received?: number;
  send_errors?: number;
  last_tx?: string;
  last_rx?: string;
  last_up?: string;
  routes?: RouteView[];
  endpoints?: LinkEndpoint[];
  sessions?: DataPathSession[];
};

export type LinkEndpoint = {
  name?: string;
  transport?: string;
  mode?: string;
  address?: string;
  enabled?: boolean;
  reverse_only?: boolean;
  usable?: boolean;
  kernel_compatible?: boolean;
  security_compatible?: boolean;
  profile_compatible?: boolean;
  profile?: string;
  datapath?: string;
  features?: string[];
  link_tls?: string;
  encryption?: string;
  crypto_placements?: string[];
  active_sessions?: number;
  current_flows?: number;
  health?: string;
  rtt?: number;
  last_error?: string;
  observed_at?: string;
  last_sent?: string;
  last_received?: string;
  send_errors?: number;
  packets_sent?: number;
  packets_received?: number;
  bytes_sent?: number;
  bytes_received?: number;
};

export type DeviceAccessLease = {
  domain?: string;
  ix?: string;
  device?: string;
  peer?: string;
  address?: string;
  prefix?: string;
  advertise_prefixes?: string[];
  endpoint?: string;
  transport?: string;
  encryption?: string;
  online?: boolean;
  revoked?: boolean;
  cert_fingerprint?: string;
  expires_at?: string;
};

export type DeviceAccessPayload = {
  enabled?: boolean;
  address_pool?: string;
  lease_ttl?: string;
  leases?: DeviceAccessLease[];
  counts?: {
    online?: number;
    leased?: number;
    revoked?: number;
  };
};

export type DeviceAccessIssueRequest = {
  device: string;
  endpoint?: string;
  endpoint_address?: string;
  transport?: string;
  ttl?: string;
  dns_names?: string[];
  ip_addresses?: string[];
  interface_name?: string;
  interface_mtu?: number;
  bootstrap_routes?: string[];
  advertise_prefixes?: string[];
  routes?: string[];
  server_name?: string;
  encryption?: string;
  crypto_key_source?: string;
  crypto_suites?: string[];
};

export type DeviceAccessIssueResponse = {
  domain?: string;
  ix?: string;
  device?: string;
  certificate_pem?: string;
  private_key_pem?: string;
  issuer_cert_pem?: string;
  trust_roots_pem?: string[];
  fingerprint?: string;
  not_after?: string;
  client_config?: Record<string, unknown>;
  client_config_json?: string;
};

export type IXProvisionIssueRequest = {
  ix_id: string;
  domain?: string;
  role?: string;
  profile?: string;
  control_api?: string;
  advertise?: string[];
  endpoint_name?: string;
  endpoint_mode?: string;
  endpoint_transport?: string;
  endpoint_listen?: string;
  endpoint_address?: string;
  lan_iface?: string;
  lan_gateway?: string;
  underlay_iface?: string;
  attach_mode?: string;
  api_addr?: string;
  peer_api_addr?: string;
  dataplane?: string;
  service_manager?: string;
  dns_enabled?: string;
  dns_domain?: string;
  openwrt_dnsmasq?: string;
  kernel_modules?: string;
  goarch?: string;
  build_bpf?: string;
  build_ko?: string;
  build_webui?: string;
  source_certs?: string;
  domain_ca_cert?: string;
  domain_ca_key?: string;
  config_ca_cert?: string;
  config_ca_key?: string;
  trust_roots?: string[];
  target_cert_dir?: string;
  bootstrap_ix?: string;
  bootstrap_control_api?: string;
  provision_url?: string;
  ttl?: string;
};

export type IXProvisionIssueResponse = {
  token?: string;
  provision_url?: string;
  expires_at?: string;
  command?: string;
  ix_cert_fingerprint?: string;
  route_auth_fingerprints?: string[];
  admission?: Record<string, unknown>;
};

export type EndpointGrant = {
  version?: number;
  domain_id?: string;
  grant_id?: string;
  issuer_ix?: string;
  subject_ix?: string;
  endpoint?: string;
  transport?: string;
  state?: string;
  permissions?: string[];
  issued_at?: string;
  expires_at?: string;
  effective_seq?: number;
  effective_at?: string;
  reason?: string;
};

export type EndpointGrantsPayload = {
  domain_id?: string;
  head?: {
    seq?: number;
    hash?: string;
  };
  grants?: EndpointGrant[];
};

export type EndpointGrantIssueRequest = {
  subject_ix: string;
  endpoint: string;
  transport?: string;
  ttl?: string;
  expires_at?: string;
  permissions?: string[];
  reason?: string;
};

export type EndpointGrantMutationResponse = {
  applied?: boolean;
  changed?: boolean;
  grant?: EndpointGrant;
  head?: {
    seq?: number;
    hash?: string;
  };
};

export type DataPathSession = {
  peer?: string;
  endpoint?: string;
  transport?: string;
  address?: string;
  direction?: string;
  reverse?: boolean;
  pool_index?: number;
  control_only?: boolean;
  last_rx?: string;
  last_tx?: string;
  last_up?: string;
  last_pong?: string;
  stats?: {
    packets_sent?: number;
    packets_received?: number;
    bytes_sent?: number;
    bytes_received?: number;
    encrypted?: boolean;
    send_encrypted?: boolean;
    receive_encrypted?: boolean;
    crypto_placement?: string;
  };
};

export type CapturePayload = {
  packets?: CaptureEvent[];
};

export type CaptureEvent = {
  hook?: string;
  cpu?: number;
  source_ip?: string;
  destination_ip?: string;
  original_source_ip?: string;
  nat_translated?: boolean;
  checksum_normalized?: boolean;
  gso_segment_length?: number;
  packet_length?: number;
  sample_length?: number;
};

export type TopologyState = "up" | "idle" | "degraded" | "down";

export type TopologyNode = {
  id: string;
  label: string;
  domain?: string;
  local?: boolean;
  dynamic?: boolean;
  state: TopologyState;
  x: number;
  y: number;
  prefixes: string[];
  link?: LinkStatus;
  peer?: PeerConfig;
};

export type TopologyEdge = {
  id: string;
  source: string;
  target: string;
  label: string;
  state: TopologyState;
  transports: string[];
  transportCount: number;
  usableTransportCount: number;
  activeTransportSessions: number;
  routes: RouteView[];
  endpoints: LinkEndpoint[];
  link?: LinkStatus;
};

export type SelectedTopology =
  | { type: "node"; nodeId: string }
  | { type: "edge"; edgeId: string }
  | { type: "route"; index: number }
  | { type: "endpoint"; peerId: string; index: number }
  | null;
