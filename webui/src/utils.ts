import type { DesiredConfig, EndpointConfig, PeerConfig, RouteConfig, TopologyState } from "./types";

export function normalizeBase(raw: string | undefined): string {
  const value = String(raw || "").trim().replace(/\/+$/, "");
  return value || "/v1";
}

export function cloneJSON<T>(value: T): T {
  return JSON.parse(JSON.stringify(value ?? null));
}

export function arrayValue<T>(value: T[] | undefined | null): T[] {
  return Array.isArray(value) ? value : [];
}

export function normalizeDesiredConfig(raw: DesiredConfig | null | undefined): DesiredConfig {
  const cfg = cloneJSON(raw || {}) as DesiredConfig;
  cfg.domain = isObject(cfg.domain) ? cfg.domain : {};
  cfg.domain.trust_roots = arrayValue(cfg.domain.trust_roots);
  cfg.ix = isObject(cfg.ix) ? cfg.ix : {};
  cfg.ix.route_authorizations = arrayValue(cfg.ix.route_authorizations);
  cfg.lan = isObject(cfg.lan) ? cfg.lan : {};
  cfg.lan.advertise = arrayValue(cfg.lan.advertise);
  cfg.lan.nat = isObject(cfg.lan.nat) ? cfg.lan.nat : {};
  cfg.management = isObject(cfg.management) ? cfg.management : {};
  cfg.dns = isObject(cfg.dns) ? cfg.dns : {};
  cfg.dns.upstreams = arrayValue(cfg.dns.upstreams);
  cfg.dns.dnsmasq = isObject(cfg.dns.dnsmasq) ? cfg.dns.dnsmasq : {};
  cfg.kernel_modules = isObject(cfg.kernel_modules) ? cfg.kernel_modules : {};
  cfg.trust = isObject(cfg.trust) ? cfg.trust : {};
  cfg.bootstrap = isObject(cfg.bootstrap) ? cfg.bootstrap : {};
  cfg.control_fabric = isObject(cfg.control_fabric) ? cfg.control_fabric : {};
  cfg.route_policy = isObject(cfg.route_policy) ? cfg.route_policy : {};
  cfg.route_policy.import_prefixes = arrayValue(cfg.route_policy.import_prefixes);
  cfg.route_policy.export_prefixes = arrayValue(cfg.route_policy.export_prefixes);
  cfg.policies = arrayValue(cfg.policies);
  cfg.endpoints = arrayValue(cfg.endpoints).map(normalizeEndpointConfig);
  cfg.peers = arrayValue(cfg.peers).map(normalizePeerConfig);
  cfg.routes = arrayValue(cfg.routes).map(normalizeRouteConfig);
  cfg.transport_policy = isObject(cfg.transport_policy) ? cfg.transport_policy : {};
  cfg.transport_policy.candidates = arrayValue(cfg.transport_policy.candidates);
  cfg.transport_policy.crypto_suites = arrayValue(cfg.transport_policy.crypto_suites);
  cfg.transport_policy.profiles = arrayValue(cfg.transport_policy.profiles).map((profile) => ({
    ...(isObject(profile) ? profile : {}),
    advanced: isObject(profile?.advanced) ? profile.advanced : {},
  }));
  cfg.transport_policy.advanced = isObject(cfg.transport_policy.advanced)
    ? cfg.transport_policy.advanced
    : {};
  cfg.transport_policy.kernel_transport = isObject(cfg.transport_policy.kernel_transport)
    ? cfg.transport_policy.kernel_transport
    : {};
  cfg.transport_policy.session_pool = isObject(cfg.transport_policy.session_pool)
    ? cfg.transport_policy.session_pool
    : {};
  return cfg;
}

export function normalizeEndpointConfig(raw: EndpointConfig | null | undefined): EndpointConfig {
  const endpoint = isObject(raw) ? raw : {};
  endpoint.security = isObject(endpoint.security) ? endpoint.security : {};
  endpoint.security.crypto_placements = arrayValue(endpoint.security.crypto_placements);
  endpoint.security.crypto_suites = arrayValue(endpoint.security.crypto_suites);
  endpoint.security.key_sources = arrayValue(endpoint.security.key_sources);
  endpoint.transport_profile = isObject(endpoint.transport_profile) ? endpoint.transport_profile : {};
  endpoint.transport_profile.features = arrayValue(endpoint.transport_profile.features);
  endpoint.local_bind = isObject(endpoint.local_bind) ? endpoint.local_bind : {};
  endpoint.publish = isObject(endpoint.publish) ? endpoint.publish : {};
  endpoint.publish.only_peers = arrayValue(endpoint.publish.only_peers);
  endpoint.publish.except_peers = arrayValue(endpoint.publish.except_peers);
  endpoint.publish.domains = arrayValue(endpoint.publish.domains);
  endpoint.access = isObject(endpoint.access) ? endpoint.access : {};
  endpoint.access.allowed_peers = arrayValue(endpoint.access.allowed_peers);
  if (!endpoint.mode) {
    endpoint.mode = endpoint.address && !endpoint.listen ? "active" : "passive";
  }
  if (endpoint.priority == null || Number.isNaN(Number(endpoint.priority))) {
    endpoint.priority = 0;
  } else {
    endpoint.priority = Math.trunc(Number(endpoint.priority));
  }
  if (endpoint.enabled == null) {
    endpoint.enabled = true;
  }
  return endpoint;
}

export function normalizePeerConfig(raw: PeerConfig | null | undefined): PeerConfig {
  const peer = isObject(raw) ? raw : {};
  peer.allowed_prefixes = arrayValue(peer.allowed_prefixes);
  peer.endpoints = arrayValue(peer.endpoints).map(normalizeEndpointConfig);
  return peer;
}

export function normalizeRouteConfig(raw: RouteConfig | null | undefined): RouteConfig {
  const route = isObject(raw) ? raw : {};
  if (!route.kind) {
    route.kind = "unicast";
  }
  if (route.metric == null || Number.isNaN(Number(route.metric))) {
    route.metric = 100;
  }
  if (route.policy == null) {
    route.policy = "";
  }
  return route;
}

export function isObject(value: unknown): value is Record<string, any> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

export function splitLines(value: string): string[] {
  return String(value || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

export function joinLines(values: string[] | undefined): string {
  return arrayValue(values).join("\n");
}

export function splitCSV(value: string): string[] {
  return String(value || "")
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
}

export function formatNumber(value: unknown, lang: string): string {
  const n = Number(value);
  if (!Number.isFinite(n)) {
    return "-";
  }
  return new Intl.NumberFormat(lang).format(n);
}

export function formatBytes(value: unknown, lang: string): string {
  const bytes = Number(value || 0);
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return "0 B";
  }
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let size = bytes;
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  const maximumFractionDigits = size >= 100 || index === 0 ? 0 : size >= 10 ? 1 : 2;
  return `${new Intl.NumberFormat(lang, { maximumFractionDigits }).format(size)} ${units[index]}`;
}

export function formatDurationNanos(value: unknown, lang: string): string {
  const nanos = Number(value);
  if (!Number.isFinite(nanos) || nanos <= 0) {
    return "-";
  }
  if (nanos < 1_000) {
    return `${new Intl.NumberFormat(lang, { maximumFractionDigits: 0 }).format(nanos)} ns`;
  }
  if (nanos < 1_000_000) {
    return `${new Intl.NumberFormat(lang, { maximumFractionDigits: nanos >= 100_000 ? 0 : 1 }).format(nanos / 1_000)} us`;
  }
  if (nanos < 1_000_000_000) {
    return `${new Intl.NumberFormat(lang, { maximumFractionDigits: nanos >= 100_000_000 ? 0 : 2 }).format(nanos / 1_000_000)} ms`;
  }
  return `${new Intl.NumberFormat(lang, { maximumFractionDigits: 2 }).format(nanos / 1_000_000_000)} s`;
}

export function formatTime(value: string | Date | undefined, lang: string): string {
  if (!value) {
    return "-";
  }
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "-";
  }
  return new Intl.DateTimeFormat(lang, { dateStyle: "medium", timeStyle: "medium" }).format(date);
}

export function shortHash(value: string | undefined): string {
  if (!value) {
    return "-";
  }
  return value.length > 12 ? `${value.slice(0, 12)}...` : value;
}

export function statusBucket(value: string | undefined): TopologyState {
  switch (String(value || "").toLowerCase()) {
    case "up":
    case "ok":
    case "healthy":
      return "up";
    case "idle":
    case "inactive":
      return "idle";
    case "down":
    case "bad":
    case "error":
      return "down";
    default:
      return "degraded";
  }
}

export function compactList(values: Array<string | undefined>, fallback = "-"): string {
  const text = values.map((value) => String(value || "").trim()).filter(Boolean).join(" · ");
  return text || fallback;
}

export function transportOptions(): string[] {
  return ["udp", "kernel_udp", "experimental_tcp", "tcp", "quic", "websocket", "http_connect", "gre", "ipip", "vxlan"];
}

export function encryptionOptions(): string[] {
  return ["", "secure", "plaintext", "send_encrypted", "receive_encrypted"];
}

export function cryptoSuiteOptions(): string[] {
  return ["AES-256-GCM-X25519", "AES-128-GCM-X25519", "CHACHA20-POLY1305-X25519"];
}

export function transportProfileOptions(): string[] {
  return ["", "stable", "performance", "latency"];
}

export function transportDatapathOptions(): string[] {
  return ["", "auto", "userspace", "tc_xdp", "kernel_module"];
}

export function transportToggleOptions(): string[] {
  return ["", "enabled", "disabled"];
}
