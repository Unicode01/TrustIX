import { useEffect, useMemo, useRef, useState, type MouseEvent, type PointerEvent, type ReactNode, type WheelEvent } from "react";
import { Archive, ArrowLeft, Check, Circle, Copy, Download, KeyRound, Languages, Move, Network, Plus, RefreshCw, Route, Save, ShieldCheck, Trash2, Upload, ZoomIn, ZoomOut } from "lucide-react";
import type {
  BootstrapPeerConfig,
  DeviceAccessIssueResponse,
  DeviceAccessPayload,
  DesiredConfig,
  DoctorCheck,
  EndpointGrant,
  EndpointGrantIssueRequest,
  ExperimentalTCPStatus,
  EndpointConfig,
  KernelModuleStatus,
  KernelModuleConfig,
  KernelCapabilitiesPayload,
  KernelPlacementStatus,
  KernelRXStageStatus,
  KernelTransportStatus,
  KernelUDPStatus,
  IXProvisionIssueRequest,
  IXProvisionIssueResponse,
  LANConfig,
  ListenerStatus,
  LinkStatus,
  PeerConfig,
  RouteCandidate,
  RouteConfig,
  RoutePolicyStatus,
  RouteView,
  SelectedTopology,
  StatusPayload,
  TransportAdvancedConfig,
  TransportMatrix,
  TransportProfileConfig,
  TopologyEdge,
  TopologyNode,
} from "./types";
import { edgeMidpoint, edgePath } from "./topology";
import { arrayValue, compactList, cryptoSuiteOptions, encryptionOptions, formatBytes, formatDurationNanos, formatNumber, formatTime, joinLines, kernelCapabilityProfileOptions, kernelRXStageOptions, shortHash, splitLines, transportDatapathOptions, transportOptions, transportProfileOptions, transportToggleOptions } from "./utils";

export type Translate = (key: string, fallback?: string) => string;

export function IconButton(props: {
  title: string;
  onClick?: () => void;
  disabled?: boolean;
  children: ReactNode;
  className?: string;
}) {
  return (
    <button type="button" className={`icon-button ${props.className || ""}`} title={props.title} aria-label={props.title} disabled={props.disabled} onClick={props.onClick}>
      {props.children}
    </button>
  );
}

export function Button(props: {
  children: ReactNode;
  onClick?: () => void;
  variant?: "primary" | "ghost" | "danger";
  type?: "button" | "submit";
  disabled?: boolean;
  title?: string;
}) {
  return (
    <button type={props.type || "button"} className={`button ${props.variant || "primary"}`} disabled={props.disabled} title={props.title} onClick={props.onClick}>
      {props.children}
    </button>
  );
}

export function Pill(props: { state: string; children: React.ReactNode }) {
  return <span className={`pill ${props.state}`}>{props.children}</span>;
}

export function routePeerOptions(desired: DesiredConfig | null | undefined, nodes?: TopologyNode[], links?: LinkStatus[]): string[] {
  const peers = new Set<string>();
  for (const peer of arrayValue(desired?.peers)) {
    if (peer.id) {
      peers.add(peer.id);
    }
  }
  for (const node of arrayValue(nodes)) {
    if (node.id && !node.local) {
      peers.add(node.id);
    }
  }
  for (const link of arrayValue(links)) {
    if (link.peer) {
      peers.add(link.peer);
    }
  }
  return Array.from(peers).sort((a, b) => a.localeCompare(b));
}

export function routePeerPrefix(peerId: string | undefined, desired: DesiredConfig | null | undefined, nodes?: TopologyNode[], links?: LinkStatus[]): string {
  if (!peerId) {
    return "";
  }
  const staticPeer = arrayValue(desired?.peers).find((peer) => peer.id === peerId);
  const staticPrefix = arrayValue(staticPeer?.allowed_prefixes).find(Boolean);
  if (staticPrefix) {
    return staticPrefix;
  }
  const nodePrefix = arrayValue(nodes).find((node) => node.id === peerId)?.prefixes.find(Boolean);
  if (nodePrefix) {
    return nodePrefix;
  }
  const linkPrefix = arrayValue(links).find((link) => link.peer === peerId)?.routes?.find((route) => route.prefix && (!route.owner || route.owner === peerId))?.prefix;
  return linkPrefix || "";
}

export function routePeerEndpoint(peerId: string | undefined, desired: DesiredConfig | null | undefined, links?: LinkStatus[]): string {
  if (!peerId) {
    return "";
  }
  const staticPeer = arrayValue(desired?.peers).find((peer) => peer.id === peerId);
  const staticEndpoint = arrayValue(staticPeer?.endpoints).find((endpoint) => endpoint.name)?.name;
  if (staticEndpoint) {
    return staticEndpoint;
  }
  const linkEndpoint = arrayValue(links).find((link) => link.peer === peerId)?.endpoints?.find((endpoint) => endpoint.name && endpoint.usable !== false)?.name;
  return linkEndpoint || "";
}

export function Shell(props: {
  t: Translate;
  lang: string;
  activeTab: string;
  locked: boolean;
  loading: boolean;
  adminProofReady: boolean;
  adminProofStatus: string;
  adminProofSelected: string;
  onRefresh: () => void;
  onTheme: () => void;
  onLanguage: () => void;
  onTab: (tab: string) => void;
  onImportAdmin: (cert: File | null, key: File | null) => void;
  onClearAdmin: () => void;
  children: ReactNode;
}) {
  const tabs = ["overview", "network", "access", "config", "doctor", "capture"];
  return (
    <div className={`shell ${props.locked ? "is-locked" : "is-unlocked"}`}>
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">T</div>
          <div className="brand-copy">
            <div className="brand-title">TrustIX</div>
            <div className="brand-subtitle">{props.t("app_tagline", "Control plane and datapath console")}</div>
          </div>
        </div>
        <div className="toolbar">
          <AdminProofToolbar
            t={props.t}
            ready={props.adminProofReady}
            status={props.adminProofStatus}
            selected={props.adminProofSelected}
            onImport={props.onImportAdmin}
            onClear={props.onClearAdmin}
          />
          <IconButton title={props.t("refresh", "Refresh")} onClick={props.onRefresh} disabled={props.loading || props.locked} className={props.loading ? "is-loading" : ""}>
            <RefreshCw size={16} />
          </IconButton>
          <IconButton title={props.t("theme", "Theme")} onClick={props.onTheme}>
            <Circle size={16} />
          </IconButton>
          <IconButton title={props.t("language", "Language")} onClick={props.onLanguage} className="lang-button">
            <Languages size={16} />
            <span className="lang-code">{props.lang === "zh" ? "EN" : "中"}</span>
          </IconButton>
        </div>
      </header>
      {!props.locked && (
        <nav className="tabs" role="tablist" aria-label={props.t("trustix_sections", "TrustIX sections")}>
          {tabs.map((tab) => (
            <button key={tab} type="button" className={`tab ${props.activeTab === tab ? "is-active" : ""}`} onClick={() => props.onTab(tab)}>
              {props.t(tab, tab)}
            </button>
          ))}
        </nav>
      )}
      {props.children}
    </div>
  );
}

function AdminProofToolbar(props: {
  t: Translate;
  ready: boolean;
  status: string;
  selected: string;
  onImport: (cert: File | null, key: File | null) => void;
  onClear: () => void;
}) {
  const [cert, setCert] = useState<File | null>(null);
  const [key, setKey] = useState<File | null>(null);
  const notify = (nextCert: File | null, nextKey: File | null) => props.onImport(nextCert, nextKey);
  return (
    <div className="admin-toolbar" title={props.status || props.selected || ""}>
      <Pill state={props.ready ? "ok" : "warn"}>
        <KeyRound size={13} />{props.ready ? props.t("admin_ready", "Admin ready") : props.t("admin_proof", "Admin proof")}
      </Pill>
      <label className="mini-file-button">
        <Upload size={14} />
        <span>{props.t("admin_cert", "Admin certificate")}</span>
        <input type="file" accept=".crt,.pem" onChange={(event) => { const file = event.currentTarget.files?.[0] || null; setCert(file); notify(file, key); }} />
      </label>
      <label className="mini-file-button">
        <Upload size={14} />
        <span>{props.t("admin_key", "Admin key")}</span>
        <input type="file" accept=".key,.pem" onChange={(event) => { const file = event.currentTarget.files?.[0] || null; setKey(file); notify(cert, file); }} />
      </label>
      {props.ready && <button type="button" className="mini-clear-button" onClick={props.onClear}>{props.t("clear", "Clear")}</button>}
    </div>
  );
}

export function UnlockPanel(props: {
  t: Translate;
  status: string;
  selected: string;
  restoring?: boolean;
  onImport: (cert: File | null, key: File | null) => void;
  onClear: () => void;
}) {
  const [cert, setCert] = useState<File | null>(null);
  const [key, setKey] = useState<File | null>(null);
  const notify = (nextCert: File | null, nextKey: File | null) => props.onImport(nextCert, nextKey);
  return (
    <section className="unlock-panel">
      <div className="panel unlock-card">
        <div className="panel-head">
          <div>
            <h2>{props.t("unlock_title", "Unlock management console")}</h2>
            <p className="panel-note">{props.t("unlock_body", "Select an Admin certificate and private key before the WebUI can read or change the API.")}</p>
          </div>
          <span className="muted">{props.status || "-"}</span>
        </div>
        <div className="admin-grid">
          <label className="file-button">
            <span>{props.t("admin_cert", "Admin certificate")}</span>
            <input type="file" accept=".crt,.pem" disabled={props.restoring} onChange={(event) => { const file = event.currentTarget.files?.[0] || null; setCert(file); notify(file, key); }} />
          </label>
          <label className="file-button">
            <span>{props.t("admin_key", "Admin key")}</span>
            <input type="file" accept=".key,.pem" disabled={props.restoring} onChange={(event) => { const file = event.currentTarget.files?.[0] || null; setKey(file); notify(cert, file); }} />
          </label>
          <Button variant="ghost" disabled={props.restoring} onClick={props.onClear}>{props.t("clear", "Clear")}</Button>
        </div>
        <div className="admin-selected">{props.selected || props.t("admin_proof_files_hint", "Expected: certs/admin-1.crt + certs/admin-1.key")}</div>
        <p className="panel-note">{props.t("admin_proof_note", "The private key stays in this browser session and is used only to sign API requests.")}</p>
      </div>
    </section>
  );
}

export function Metrics(props: { t: Translate; lang: string; status: StatusPayload | null }) {
  const status = props.status || {};
  const management = status.management || {};
  const webUI = management.web_ui || {};
  const counts = status.counts || {};
  const datapath = status.data_path || {};
  const cards = [
    [props.t("domain", "Domain"), status.domain_id || "-", compactBuild(status.build)],
    [props.t("ix", "IX"), status.ix_id || "-", `#${formatNumber(status.config_head?.seq, props.lang)} ${status.config_head?.hash?.slice(0, 12) || "-"}`],
    [props.t("management", "Management"), compactListener(management.primary), webUI.enabled ? compactList(webUI.exposed_on || []) : props.t("disabled", "Disabled")],
    [props.t("dataplane", "Dataplane"), `${formatNumber(datapath.active_sessions || 0, props.lang)} ${props.t("sessions", "sessions")}`, `${formatNumber(counts.peers || 0, props.lang)} ${props.t("peers", "Peers")} · ${formatNumber(counts.routes || 0, props.lang)} ${props.t("routes", "Routes")}`],
  ];
  return (
    <section className="status-grid" aria-label={props.t("status", "Status")}>
      {cards.map(([label, value, foot]) => (
        <article className="metric" key={label}>
          <div className="metric-label">{label}</div>
          <div className="metric-value">{value}</div>
          <div className="metric-foot">{foot}</div>
        </article>
      ))}
    </section>
  );
}

export function OverviewView(props: { t: Translate; lang: string; status: StatusPayload | null; doctor: DoctorCheck[]; links: LinkStatus[]; onTab: (tab: string) => void }) {
  const status = props.status || {};
  const counts = status.counts || {};
  const warnings = props.doctor.filter((check) => !["ok", ""].includes(String(check.status || "").toLowerCase()));
  return (
    <main className="views">
      <section className="view">
        <div className="overview-layout">
          <div className="panel">
            <div className="panel-head">
              <h2>{props.t("summary", "Summary")}</h2>
              <Pill state={warnings.length ? "warn" : "ok"}>{warnings.length ? props.t("warn", "Warn") : props.t("ok", "OK")}</Pill>
            </div>
            <div className="summary-grid">
              <SummaryItem label={props.t("peers", "Peers")} value={formatNumber(counts.peers || 0, props.lang)} />
              <SummaryItem label={props.t("routes", "Routes")} value={formatNumber(counts.routes || 0, props.lang)} />
              <SummaryItem label={props.t("endpoints", "Endpoints")} value={formatNumber(counts.local_endpoints || 0, props.lang)} />
              <SummaryItem label={props.t("links", "Links")} value={formatNumber(props.links.length, props.lang)} />
            </div>
          </div>
          <div className="panel">
            <div className="panel-head">
              <h2>{props.t("status", "Status")}</h2>
            </div>
            <div className="status-stack">
              <StatusRow label={props.t("management", "Management")} value={compactListener(status.management?.primary)} />
              <StatusRow label={props.t("web_ui", "WebUI")} value={status.management?.web_ui?.enabled ? props.t("enabled", "Enabled") : props.t("disabled", "Disabled")} />
              <StatusRow label={props.t("dns", "DNS")} value={compactDNSStatus(status.dns, props.t)} />
              <StatusRow label={props.t("transport", "Transport")} value={(status.transports || []).join(", ") || "-"} />
              <StatusRow label={props.t("warnings", "Warnings")} value={warnings.map((warning) => `${warning.name}: ${warning.detail}`).join(" · ") || "-"} />
            </div>
          </div>
        </div>
        <FirstRunPanel t={props.t} lang={props.lang} status={props.status} doctor={props.doctor} links={props.links} onTab={props.onTab} />
      </section>
    </main>
  );
}

type FirstRunItem = {
  label: string;
  state: "ok" | "warn" | "bad";
  value: string;
};

function FirstRunPanel(props: { t: Translate; lang: string; status: StatusPayload | null; doctor: DoctorCheck[]; links: LinkStatus[]; onTab: (tab: string) => void }) {
  const status = props.status || {};
  const counts = status.counts || {};
  const warningCount = props.doctor.filter((check) => !["ok", ""].includes(String(check.status || "").toLowerCase())).length;
  const activeLinks = props.links.filter((link) => Number(link.active_sessions || 0) > 0 || String(link.state || "").toLowerCase() === "up");
  const enabledEndpoints = Number(counts.local_endpoints || 0);
  const datapathSummary = firstRunDatapathSummary(props.t, props.lang, status);
  const items: FirstRunItem[] = [
    {
      label: props.t("first_run_identity", "Identity"),
      state: status.ix_id && status.domain_id ? "ok" : "bad",
      value: compactList([status.ix_id, status.domain_id], " / ") || "-",
    },
    {
      label: props.t("first_run_endpoints", "Endpoints"),
      state: enabledEndpoints > 0 ? "ok" : "bad",
      value: `${formatNumber(enabledEndpoints, props.lang)} ${props.t("enabled", "Enabled")}`,
    },
    {
      label: props.t("first_run_links", "Links"),
      state: activeLinks.length > 0 ? "ok" : props.links.length > 0 ? "warn" : "bad",
      value: `${formatNumber(activeLinks.length, props.lang)} / ${formatNumber(props.links.length, props.lang)}`,
    },
    {
      label: props.t("first_run_datapath", "Datapath"),
      state: datapathSummary.state,
      value: datapathSummary.value,
    },
    {
      label: props.t("first_run_doctor", "Doctor"),
      state: warningCount === 0 ? "ok" : "warn",
      value: warningCount === 0 ? props.t("ok", "OK") : `${formatNumber(warningCount, props.lang)} ${props.t("warnings", "Warnings")}`,
    },
  ];
  const next = items.find((item) => item.state !== "ok");
  return (
    <div className="panel first-run-panel">
      <div className="panel-head">
        <div>
          <h2>{props.t("first_run", "First run")}</h2>
        </div>
        <Pill state={next ? next.state : "ok"}>{next ? next.label : props.t("ready", "Ready")}</Pill>
      </div>
      <div className="first-run-grid">
        {items.map((item) => (
          <div className="first-run-row" key={item.label}>
            <Pill state={item.state}>{item.state === "ok" ? props.t("ok", "OK") : item.state === "warn" ? props.t("warn", "Warn") : props.t("missing", "Missing")}</Pill>
            <span className="first-run-label">{item.label}</span>
            <strong>{item.value}</strong>
          </div>
        ))}
      </div>
      <div className="first-run-actions">
        <Button variant="ghost" onClick={() => props.onTab("network")}><Network size={15} />{props.t("network", "Network")}</Button>
        <Button variant="ghost" onClick={() => props.onTab("access")}><ShieldCheck size={15} />{props.t("access", "Access")}</Button>
        <Button variant="ghost" onClick={() => props.onTab("config")}><Save size={15} />{props.t("config", "Config")}</Button>
        <Button variant="ghost" onClick={() => props.onTab("doctor")}><Check size={15} />{props.t("doctor", "Doctor")}</Button>
      </div>
    </div>
  );
}

function firstRunDatapathSummary(t: Translate, lang: string, status: StatusPayload): FirstRunItem {
  const dataPath = status.data_path;
  if (!dataPath) {
    return { label: t("first_run_datapath", "Datapath"), state: "bad", value: t("missing", "Missing") };
  }

  const runtimeRows = [
    dataPath.kernel_transport ? kernelTransportStatusRow(t, dataPath.kernel_transport) : null,
    kernelUDPStatusRow(t, lang, dataPath.kernel_udp),
    experimentalTCPStatusRow(t, lang, dataPath.experimental_tcp),
    kernelRXStageStatusRow(t, lang, dataPath.kernel_rx_stage),
  ].filter((row): row is KernelCapabilityRow => Boolean(row));
  const loadedModuleRows = arrayValue(status.kernel_modules)
    .filter((module) => module.loaded)
    .map((module) => kernelModuleCapabilityRow(t, module));
  const okRows = [...runtimeRows, ...loadedModuleRows].filter((row) => row.state === "ok");
  if (okRows.length) {
    return {
      label: t("first_run_datapath", "Datapath"),
      state: "ok",
      value: compactList(okRows.slice(0, 3).map((row) => row.name), ", "),
    };
  }

  const warnRows = runtimeRows.filter((row) => row.state === "warn");
  if (warnRows.length) {
    return {
      label: t("first_run_datapath", "Datapath"),
      state: "warn",
      value: compactList(warnRows.slice(0, 3).map((row) => compactList([row.name, row.badge], " ")), ", "),
    };
  }

  return {
    label: t("first_run_datapath", "Datapath"),
    state: "warn",
    value: t("userspace_fallback", "Userspace fallback"),
  };
}

function SummaryItem(props: { label: string; value: string }) {
  return (
    <div className="summary-item">
      <div className="summary-label">{props.label}</div>
      <div className="summary-value" title={props.value}>{props.value}</div>
    </div>
  );
}

function StatusRow(props: { label: string; value: string }) {
  return (
    <div className="status-row">
      <div className="label">{props.label}</div>
      <div className="value">{props.value}</div>
    </div>
  );
}

function KernelCapabilitiesPanel(props: { t: Translate; lang: string; status?: StatusPayload | null; capabilities?: KernelCapabilitiesPayload | null }) {
  const dataPath = props.status?.data_path || {};
  const capabilities = props.capabilities || {};
  const modules = arrayValue(capabilities.modules?.length ? capabilities.modules : props.status?.kernel_modules);
  const offload = capabilities.offload || dataPath.kernel_offload;
  const placements = arrayValue(offload?.placements);
  const rxStage = capabilities.rx_stage || dataPath.kernel_rx_stage;
  const kernelTransport = capabilities.kernel_transport || dataPath.kernel_transport;
  const kernelUDP = capabilities.kernel_udp || dataPath.kernel_udp;
  const experimentalTCP = capabilities.experimental_tcp || dataPath.experimental_tcp;
  const kernelRows = [
    ...modules.map((module) => kernelModuleCapabilityRow(props.t, module)),
    ...kernelTransportCapabilityRows(props.t, kernelTransport),
    kernelTransportStatusRow(props.t, kernelTransport),
    kernelUDPStatusRow(props.t, props.lang, kernelUDP),
    experimentalTCPStatusRow(props.t, props.lang, experimentalTCP),
    kernelRXStageStatusRow(props.t, props.lang, rxStage),
  ].filter((row): row is KernelCapabilityRow => Boolean(row));
  const offloadRows = placements.slice(0, 12);
  const kernelReady = kernelRows.some((row) => row.state === "ok" || row.state === "warn");
  const summary = compactList([
    capabilities.datapath_mode || offload?.dataplane_mode,
    compactList(arrayValue(capabilities.capabilities?.length ? capabilities.capabilities : offload?.capabilities).slice(0, 4), ""),
  ], "-");
  return (
    <div className="panel kernel-panel">
      <div className="panel-head">
        <div>
          <h2>{props.t("kernel_capabilities", "Kernel capabilities")}</h2>
          <p className="panel-note inline-note">{props.t("kernel_capabilities_note", "Runtime module, TC/XDP/AF_XDP, crypto, and full-kernel datapath readiness.")}</p>
        </div>
        <Pill state={kernelReady ? "ok" : "warn"}>{kernelReady ? props.t("available", "Available") : props.t("limited", "Limited")}</Pill>
      </div>
      <div className="kernel-summary-strip">
        <SummaryItem label={props.t("dataplane", "Dataplane")} value={summary} />
        <SummaryItem label={props.t("kernel_modules", "Kernel modules")} value={formatNumber(modules.length, props.lang)} />
        <SummaryItem label={props.t("offload_paths", "Offload paths")} value={formatNumber(placements.length, props.lang)} />
        <SummaryItem label={props.t("active_flows", "Active flows")} value={formatNumber((kernelUDP?.active_flows || 0) + (experimentalTCP?.active_flows || 0), props.lang)} />
      </div>
      <div className="kernel-capability-grid">
        <div className="kernel-capability-list">
          {kernelRows.length ? kernelRows.map((row) => (
            <div className="kernel-capability-row" key={row.name}>
              <div className="kernel-capability-main">
                <span className="kernel-capability-name">{row.name}</span>
                <Pill state={row.state}>{row.badge}</Pill>
              </div>
              <div className="kernel-capability-meta">{row.meta || "-"}</div>
              {row.detail ? <div className="kernel-capability-detail">{row.detail}</div> : null}
            </div>
          )) : <div className="muted">{props.t("no_data", "No data")}</div>}
        </div>
        <div className="kernel-placement-list">
          <div className="kernel-placement-head">{props.t("offload_placements", "Offload placements")}</div>
          {offloadRows.length ? offloadRows.map((placement, index) => (
            <div className="kernel-placement-row" key={`${placement.name || "placement"}-${index}`}>
              <span className="kernel-placement-name">{placement.name || "-"}</span>
              <span>{placement.layer || "-"}</span>
              <Pill state={kernelPlacementState(placement)}>{placement.placement || "-"}</Pill>
            </div>
          )) : <div className="muted">{props.t("no_data", "No data")}</div>}
        </div>
      </div>
    </div>
  );
}

type KernelCapabilityRow = {
  name: string;
  state: string;
  badge: string;
  meta: string;
  detail?: string;
};

function kernelModuleCapabilityRow(t: Translate, module: KernelModuleStatus): KernelCapabilityRow {
  const loaded = Boolean(module.loaded);
  const state = loaded ? kernelTierState(module.capability_tier) : "bad";
  const featureText = compactList([
    compactList(arrayValue(module.features).slice(0, 5), ", "),
    arrayValue(module.missing_features).length ? `${t("missing", "Missing")} ${arrayValue(module.missing_features).join(", ")}` : "",
  ], " · ");
  const fingerprintText = module.sha256 || module.loaded_sha256
    ? `target ${shortHash(module.sha256)} / loaded ${shortHash(module.loaded_sha256)}`
    : "";
  return {
    name: module.name || t("kernel_module", "Kernel module"),
    state,
    badge: loaded ? module.capability_tier || module.state || t("loaded", "Loaded") : module.state || t("not_loaded", "Not loaded"),
    meta: compactList([
      module.mode,
      module.loaded ? t("loaded", "Loaded") : t("not_loaded", "Not loaded"),
      module.upgrade_state,
      module.abi_version ? `ABI ${module.abi_version}` : "",
      featureText,
    ], " · "),
    detail: compactList([module.capability_reason, module.reason, module.reload_on_upgrade ? `reload_on_upgrade=${module.reload_on_upgrade}` : "", fingerprintText, module.parameters], " · "),
  };
}

function kernelTransportCapabilityRows(t: Translate, status: KernelTransportStatus | undefined): KernelCapabilityRow[] {
  return arrayValue(status?.protocols).map((protocol) => ({
    name: `${t("kernel_transport", "Kernel transport")} / ${protocol.protocol || "-"}`,
    state: protocol.available ? (protocol.userspace_fallback ? "warn" : "ok") : "bad",
    badge: protocol.available ? protocol.placement || t("available", "Available") : t("not_usable", "Not usable"),
    meta: compactList([
      protocol.provider,
      protocol.carrier,
      protocol.contract,
      protocol.capability_ready === false ? t("capability_not_ready", "Capability not ready") : "",
      protocol.userspace_fallback ? t("userspace_fallback", "Userspace fallback") : "",
    ], " · "),
    detail: compactList([protocol.reason, compactList(arrayValue(protocol.required_config), ", ")], " · "),
  }));
}

function kernelTransportStatusRow(t: Translate, status: KernelTransportStatus | undefined): KernelCapabilityRow | null {
  if (!status) {
    return {
      name: t("kernel_transport", "Kernel transport"),
      state: "bad",
      badge: t("not_usable", "Not usable"),
      meta: t("no_kernel_transport_status", "No kernel transport provider status"),
    };
  }
  return {
    name: t("kernel_transport", "Kernel transport"),
    state: status.available ? "ok" : status.mode === "require_kernel" ? "bad" : "warn",
    badge: status.available ? t("available", "Available") : t("not_usable", "Not usable"),
    meta: compactList([status.mode, status.provider, `${arrayValue(status.protocols).filter((protocol) => protocol.available).length}/${arrayValue(status.protocols).length} ${t("protocols", "Protocols")}`], " · "),
    detail: compactList(arrayValue(status.notes), " · "),
  };
}

function kernelUDPStatusRow(t: Translate, lang: string, status: KernelUDPStatus | undefined): KernelCapabilityRow | null {
  if (!status) {
    return null;
  }
  return {
    name: "kernel_udp",
    state: status.fast_path && status.reinject ? "ok" : status.available ? "warn" : "bad",
    badge: status.fast_path ? t("fast_path", "Fast path") : status.available ? t("available", "Available") : t("not_usable", "Not usable"),
    meta: compactList([
      status.provider,
      status.xdp_attach_mode ? `XDP ${status.xdp_attach_mode}` : "",
      status.af_xdp_bind_mode ? `AF_XDP ${status.af_xdp_bind_mode}` : "",
      status.zerocopy_enabled ? t("zero_copy", "Zero-copy") : "",
      status.reinject ? t("reinject", "Reinject") : "",
      status.kernel_crypto ? t("kernel_crypto", "Kernel crypto") : status.effective_crypto,
    ], " · "),
    detail: compactList([
      `${t("active_flows", "Active flows")} ${formatNumber(status.active_flows || 0, lang)}`,
      `${t("submitted", "Submitted")} ${formatNumber(status.submitted_frames || 0, lang)}`,
      `${t("received", "Received")} ${formatNumber(status.received_frames || 0, lang)}`,
      status.kernel_crypto_reason,
      compactList(arrayValue(status.notes), " · "),
    ], " · "),
  };
}

function experimentalTCPStatusRow(t: Translate, lang: string, status: ExperimentalTCPStatus | undefined): KernelCapabilityRow | null {
  if (!status) {
    return null;
  }
  const probe = status.kernel_crypto_probe;
  return {
    name: "ackless_tcp",
    state: status.fast_path ? "ok" : status.raw_socket_fallback ? "warn" : status.available ? "warn" : "bad",
    badge: status.fast_path ? t("fast_path", "Fast path") : status.raw_socket_fallback ? t("raw_socket_fallback", "Raw socket fallback") : status.available ? t("available", "Available") : t("not_usable", "Not usable"),
    meta: compactList([
      status.provider,
      status.xdp_attach_mode ? `XDP ${status.xdp_attach_mode}` : "",
      status.af_xdp_bind_mode ? `AF_XDP ${status.af_xdp_bind_mode}` : "",
      status.zerocopy_enabled ? t("zero_copy", "Zero-copy") : "",
      status.reinject ? t("reinject", "Reinject") : "",
      status.kernel_crypto ? t("kernel_crypto", "Kernel crypto") : status.effective_crypto,
      status.fast_path_queues ? `${status.fast_path_queues} ${t("queues", "Queues")}` : "",
    ], " · "),
    detail: compactList([
      `${t("active_flows", "Active flows")} ${formatNumber(status.active_flows || 0, lang)}`,
      `${t("submitted", "Submitted")} ${formatNumber(status.submitted_frames || 0, lang)}`,
      `${t("received", "Received")} ${formatNumber(status.received_frames || 0, lang)}`,
      probe ? `BTF ${yesNo(probe.kernel_btf, t)} / kfunc ${yesNo(probe.crypto_kfuncs, t)} / AES-GCM ${yesNo(probe.aes_gcm, t)} / AES-NI ${yesNo(probe.aes_ni, t)}` : "",
      status.fast_path_fallback_reason,
      status.kernel_crypto_reason,
      compactList(arrayValue(status.notes), " · "),
    ], " · "),
  };
}

function kernelRXStageStatusRow(t: Translate, lang: string, status: KernelRXStageStatus | undefined): KernelCapabilityRow | null {
  if (!status || !status.enabled) {
    return null;
  }
  return {
    name: t("kernel_rx_stage", "Kernel RX stage"),
    state: status.active && status.attached ? "ok" : "warn",
    badge: status.active ? status.mode || t("active", "Active") : t("inactive", "Inactive"),
    meta: compactList([
      status.ifname,
      status.target_ifname ? `${status.ifname || "-"} -> ${status.target_ifname}` : "",
      status.attached ? t("attached", "Attached") : "",
    ], " · "),
    detail: compactList([
      `${t("packets", "Packets")} ${formatNumber(status.packets || 0, lang)}`,
      `${t("batches", "Batches")} ${formatNumber(status.batches || 0, lang)}`,
      `${t("rx_worker_injected", "RX worker injected")} ${formatNumber(status.rx_worker_injected || 0, lang)}`,
      status.inactive_reason,
      status.last_error,
    ], " · "),
  };
}

function kernelTierState(tier: string | undefined): string {
  switch (tier) {
    case "full_datapath":
    case "gso_skb":
    case "crypto_only":
      return "ok";
    case "unavailable":
      return "bad";
    default:
      return "warn";
  }
}

function kernelPlacementState(placement: KernelPlacementStatus): string {
  switch (placement.placement) {
    case "kernel":
      return "ok";
    case "hybrid":
    case "fallback":
      return "warn";
    case "userspace":
      return "idle";
    default:
      return "warn";
  }
}

function yesNo(value: boolean | undefined, t: Translate): string {
  return value ? t("yes", "Yes") : t("no", "No");
}

type IPv4Prefix = {
  raw: string;
  network: number;
  bits: number;
};

function endpointPublicAddress(endpoint: EndpointConfig | undefined): string {
  if (!endpoint) {
    return "";
  }
  return String(endpoint.address || endpoint.listen || "").trim();
}

function endpointLabel(endpoint: EndpointConfig): string {
  return compactList([endpoint.name, endpoint.transport], " · ");
}

function localPassiveEndpoint(endpoint: EndpointConfig): boolean {
  return Boolean(endpoint.name) && endpoint.enabled !== false && (endpoint.mode || "passive") === "passive";
}

function endpointAccessMode(endpoint: EndpointConfig | undefined): string {
  return String(endpoint?.access?.mode || "open").trim() || "open";
}

function endpointRequiresGrant(endpoint: EndpointConfig | undefined): boolean {
  const mode = endpointAccessMode(endpoint).toLowerCase().replaceAll("-", "_");
  return ["require_grant", "grant", "grants", "authenticated"].includes(mode);
}

function endpointGrantExpired(grant: EndpointGrant, now = Date.now()): boolean {
  if (!grant.expires_at) {
    return false;
  }
  const expires = new Date(grant.expires_at).getTime();
  return Number.isFinite(expires) && expires <= now;
}

function endpointGrantLive(grant: EndpointGrant, now = Date.now()): boolean {
  return grant.state === "active" && !endpointGrantExpired(grant, now);
}

function endpointGrantPillState(grant: EndpointGrant, now = Date.now()): string {
  if (grant.state === "revoked") {
    return "idle";
  }
  if (endpointGrantExpired(grant, now)) {
    return "warn";
  }
  return grant.state === "active" ? "ok" : "idle";
}

function endpointGrantStateLabel(grant: EndpointGrant, t: Translate, now = Date.now()): string {
  if (grant.state === "revoked") {
    return t("revoked", "Revoked");
  }
  if (endpointGrantExpired(grant, now)) {
    return t("expired", "Expired");
  }
  if (grant.state === "active") {
    return t("active", "Active");
  }
  return grant.state || "-";
}

function shortGrantID(grantID: string | undefined): string {
  const raw = String(grantID || "").trim();
  return raw ? raw.slice(0, 12) : "-";
}

function validateDeviceAdvertisePrefixes(t: Translate, raw: string, reservedRaw: string[], delegatedParentRaw: string[], exportRaw: string[]): string[] {
  const warnings: string[] = [];
  const seen = new Set<string>();
  const reserved = reservedRaw.map(parseIPv4Prefix).filter((prefix): prefix is IPv4Prefix => Boolean(prefix));
  const delegatedParents = delegatedParentRaw.map(parseIPv4Prefix).filter((prefix): prefix is IPv4Prefix => Boolean(prefix));
  const exportPrefixes = exportRaw.map(parseIPv4Prefix).filter((prefix): prefix is IPv4Prefix => Boolean(prefix));
  for (const line of splitLines(raw)) {
    const parsed = parseIPv4Prefix(line);
    if (!parsed) {
      warnings.push(`${t("invalid_cidr", "Invalid CIDR")}: ${line}`);
      continue;
    }
    const normalized = ipv4PrefixString(parsed);
    if (seen.has(normalized)) {
      warnings.push(`${t("duplicate_cidr", "Duplicate CIDR")}: ${normalized}`);
      continue;
    }
    seen.add(normalized);
    const overlap = reserved.find((prefix) => ipv4PrefixOverlaps(prefix, parsed));
    if (overlap) {
      warnings.push(`${t("overlaps_reserved_prefix", "Overlaps reserved prefix")}: ${normalized}`);
    }
    const delegatedParentOverlap = delegatedParents.find((prefix) => ipv4PrefixOverlaps(prefix, parsed) && !ipv4PrefixDelegatedSubprefix(parsed, prefix));
    if (delegatedParentOverlap) {
      warnings.push(`${t("overlaps_local_prefix", "Overlaps local LAN/address pool")}: ${normalized}`);
    }
    if (exportPrefixes.length > 0 && !exportPrefixes.some((prefix) => ipv4PrefixCovered(parsed, prefix))) {
      warnings.push(`${t("outside_export_policy", "Outside export policy")}: ${normalized}`);
    }
  }
  return warnings;
}

function parseIPv4Prefix(raw: string): IPv4Prefix | null {
  const value = String(raw || "").trim();
  const parts = value.split("/");
  if (parts.length !== 2) {
    return null;
  }
  const addr = parseIPv4Address(parts[0]);
  const bits = Number(parts[1]);
  if (addr == null || !Number.isInteger(bits) || bits < 0 || bits > 32) {
    return null;
  }
  const mask = ipv4Mask(bits);
  return { raw: value, network: (addr & mask) >>> 0, bits };
}

function parseIPv4Address(raw: string): number | null {
  const parts = String(raw || "").trim().split(".");
  if (parts.length !== 4) {
    return null;
  }
  let out = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) {
      return null;
    }
    const value = Number(part);
    if (!Number.isInteger(value) || value < 0 || value > 255) {
      return null;
    }
    out = ((out * 256) + value) >>> 0;
  }
  return out >>> 0;
}

function ipv4Mask(bits: number): number {
  if (bits === 0) {
    return 0;
  }
  return (0xffffffff << (32 - bits)) >>> 0;
}

function ipv4PrefixOverlaps(a: IPv4Prefix, b: IPv4Prefix): boolean {
  const bits = Math.min(a.bits, b.bits);
  const mask = ipv4Mask(bits);
  return ((a.network & mask) >>> 0) === ((b.network & mask) >>> 0);
}

function ipv4PrefixCovered(child: IPv4Prefix, parent: IPv4Prefix): boolean {
  if (parent.bits > child.bits) {
    return false;
  }
  const mask = ipv4Mask(parent.bits);
  return ((child.network & mask) >>> 0) === ((parent.network & mask) >>> 0);
}

function ipv4PrefixDelegatedSubprefix(child: IPv4Prefix, parent: IPv4Prefix): boolean {
  return child.bits > parent.bits && ipv4PrefixCovered(child, parent);
}

function ipv4PrefixString(prefix: IPv4Prefix): string {
  return `${ipv4AddressString(prefix.network)}/${prefix.bits}`;
}

function ipv4AddressString(value: number): string {
  return [
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ].join(".");
}

type IXProvisionEffectiveDefaults = {
  controlAPI: string;
  endpointAddress: string;
  endpointListen: string;
  endpointName: string;
  acklessEndpointName: string;
  endpointMode: string;
  lanIface: string;
  lanGateway: string;
  lanGatewaySource: string;
  bootstrapControlAPI: string;
  transportProfile: string;
  datapath: string;
  encryption: string;
  cryptoPlacement: string;
  kernelTransport: string;
  kernelModules: string;
};

function ixProvisionProfileDefaults(profile: string): Pick<IXProvisionEffectiveDefaults, "transportProfile" | "datapath" | "encryption" | "cryptoPlacement" | "kernelTransport"> {
  switch (normalizeIXProvisionProfileName(profile)) {
    case "performance":
      return { transportProfile: "performance", datapath: "auto", encryption: "secure", cryptoPlacement: "auto", kernelTransport: "auto" };
    case "latency":
      return { transportProfile: "latency", datapath: "auto", encryption: "secure", cryptoPlacement: "auto", kernelTransport: "auto" };
    case "compatibility":
    case "compat":
    case "compatible":
      return { transportProfile: "stable", datapath: "userspace", encryption: "secure", cryptoPlacement: "userspace", kernelTransport: "disabled" };
    case "plaintext_performance":
    case "plaintext-performance":
    case "plaintext":
    case "plain":
      return { transportProfile: "performance", datapath: "kernel_module", encryption: "plaintext", cryptoPlacement: "auto", kernelTransport: "auto" };
    default:
      return { transportProfile: "stable", datapath: "auto", encryption: "secure", cryptoPlacement: "auto", kernelTransport: "auto" };
  }
}

function normalizeIXProvisionProfileName(profile: string): string {
  const normalized = String(profile || "plaintext_performance").trim().toLowerCase().replaceAll("-", "_");
  switch (normalized) {
    case "compat":
    case "compatible":
      return "compatibility";
    case "plain":
    case "plaintext":
    case "plaintext_perf":
    case "performance_plaintext":
      return "plaintext_performance";
    default:
      return normalized || "plaintext_performance";
  }
}

function ixProvisionDefaultEndpointTransport(profile: string, endpointMode = "passive", endpointAddress = ""): string {
  if (normalizeIXProvisionProfileName(profile) !== "plaintext_performance") {
    return "udp";
  }
  if (String(endpointMode || "passive").trim().toLowerCase().replaceAll("-", "_") !== "active" && provisionEndpointAddressHasIPv4(endpointAddress)) {
    return "ipip";
  }
  return "experimental_tcp";
}

function ixProvisionAcklessEndpointName(endpointName: string, ixID: string): string {
  const name = String(endpointName || "").trim();
  if (name.endsWith("-udp")) {
    return `${name.slice(0, -4)}-experimental_tcp`;
  }
  if (name) {
    return `${name}-experimental_tcp`;
  }
  return `${safeShellName(ixID, "ix-new")}-experimental_tcp`;
}

function plaintextPerformanceEndpoint(name: string, options: Partial<EndpointConfig>): EndpointConfig {
  const { security, transport_profile: transportProfile, ...rest } = options;
  return {
    name,
    transport: "experimental_tcp",
    enabled: true,
    security: { encryption: "plaintext", ...(security || {}) },
    transport_profile: {
      profile: "performance",
      datapath: "kernel_module",
      encryption: "plaintext",
      crypto_placement: "auto",
      ...(transportProfile || {}),
    },
    ...rest,
  };
}

function ixProvisionEffectiveDefaults(input: {
  ixID: string;
  role: string;
  profile: string;
  endpointMode: string;
  endpointTransport: string;
  endpointAddress: string;
  endpointListen: string;
  endpointName: string;
  controlAPI: string;
  advertisePrefixes: string[];
  lanIface: string;
  lanGateway: string;
  attachMode: string;
  bootstrapControlAPI: string;
  desiredControlAPI: string;
  kernelModules: string;
  serviceManager: string;
}): IXProvisionEffectiveDefaults {
  const endpointMode = String(input.endpointMode || "passive").trim().toLowerCase().replaceAll("-", "_") === "active" ? "active" : "passive";
  const bootstrapControlAPI = String(input.bootstrapControlAPI || "").trim() || String(input.desiredControlAPI || "").trim();
  const endpointAddress = normalizeProvisionEndpointAddress(input.endpointAddress, "7000") || (endpointMode === "active" ? provisionEndpointAddressFromControlAPI(bootstrapControlAPI, "7000") : "");
  const endpointPort = provisionEndpointPort(endpointAddress, "7000");
  const role = String(input.role || "public_ix").trim().toLowerCase().replaceAll("-", "_");
  const attachMode = String(input.attachMode || "managed").trim().toLowerCase().replaceAll("_", "-");
  const derivedGateway = role === "transit_ix" ? "" : defaultLANGatewayForPrefix(input.advertisePrefixes[0] || "");
  const profile = ixProvisionProfileDefaults(input.profile);
  const endpointTransport = String(input.endpointTransport || "").trim() || ixProvisionDefaultEndpointTransport(input.profile, endpointMode, endpointAddress);
  const endpointName = String(input.endpointName || "").trim() || `${safeShellName(input.ixID, "ix-new")}-${endpointTransport}`;
  const endpointAddressForConfig = transportIsKernelTunnel(endpointTransport) ? (normalizeProvisionTunnelEndpointAddress(endpointAddress) || endpointAddress) : endpointAddress;
  return {
    controlAPI: String(input.controlAPI || "").trim() || (endpointMode === "passive" ? provisionControlAPIFromEndpointAddress(endpointAddress, "9443") : ""),
    endpointAddress: endpointAddressForConfig,
    endpointListen: endpointMode === "passive" ? (String(input.endpointListen || "").trim() || (transportIsKernelTunnel(endpointTransport) ? endpointAddressForConfig : (endpointPort ? `0.0.0.0:${endpointPort}` : ""))) : "",
    endpointName,
    acklessEndpointName: endpointTransport === "udp" ? ixProvisionAcklessEndpointName(endpointName, input.ixID) : "",
    endpointMode,
    lanIface: String(input.lanIface || "").trim() || (attachMode === "existing" ? "" : `trustix-${safeShellName(input.ixID, "ix")}`),
    lanGateway: String(input.lanGateway || "").trim() || derivedGateway,
    lanGatewaySource: String(input.lanGateway || "").trim() ? "manual" : role === "transit_ix" ? "transit" : derivedGateway ? "derived" : "empty",
    bootstrapControlAPI,
    kernelModules: String(input.kernelModules || "").trim() || "auto",
    ...profile,
  };
}

function transportIsKernelTunnel(transport: string): boolean {
  return ["gre", "ipip", "vxlan"].includes(String(transport || "").trim().toLowerCase());
}

function normalizeProvisionEndpointAddress(raw: string, fallbackPort: string): string {
  let value = String(raw || "").trim();
  if (!value) {
    return "";
  }
  try {
    const parsed = new URL(value);
    if (parsed.host) {
      value = parsed.host;
    }
  } catch {
    // Plain host:port is expected here.
  }
  if (value.includes(",") || value.includes("=")) {
    return value;
  }
  if (/^\[[^\]]+\]:\d+$/.test(value) || /^[^:\[\]]+:\d+$/.test(value)) {
    return value;
  }
  if (value.startsWith("[") && value.endsWith("]")) {
    return `${value}:${fallbackPort}`;
  }
  if ((value.match(/:/g) || []).length > 1) {
    return `[${value.replace(/^\[|\]$/g, "")}]:${fallbackPort}`;
  }
  return `${value}:${fallbackPort}`;
}

function provisionEndpointAddressHasIPv4(raw: string): boolean {
  if (String(raw || "").includes("=")) {
    const local = parseTunnelEndpointField(raw, "local");
    if (local) {
      raw = local;
    }
  }
  const host = provisionEndpointHost(raw) || String(raw || "").trim();
  return isIPv4Address(host.replace(/^\[|\]$/g, ""));
}

function parseTunnelEndpointField(raw: string, fieldName: string): string {
  const prefix = `${fieldName.toLowerCase()}=`;
  for (const field of String(raw || "").split(",")) {
    const value = field.trim();
    if (value.toLowerCase().startsWith(prefix)) {
      return value.slice(prefix.length).trim();
    }
  }
  return "";
}

function normalizeProvisionTunnelEndpointAddress(raw: string): string {
  const value = String(raw || "").trim();
  if (!value || value.includes("=") || value.includes(",")) {
    return value;
  }
  const host = provisionEndpointHost(value) || value;
  const addr = host.replace(/^\[|\]$/g, "");
  return isIPv4Address(addr) ? `local=${addr}` : value;
}

function isIPv4Address(value: string): boolean {
  const parts = String(value || "").trim().split(".");
  return parts.length === 4 && parts.every((part) => /^\d+$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function provisionEndpointPort(endpointAddress: string, fallback: string): string {
  const value = String(endpointAddress || "").trim();
  const bracket = value.match(/^\[[^\]]+\]:(\d+)$/);
  if (bracket) {
    return bracket[1];
  }
  const simple = value.match(/^[^:\[\]]+:(\d+)$/);
  return simple ? simple[1] : fallback;
}

function provisionEndpointHost(endpointAddress: string): string {
  const value = String(endpointAddress || "").trim();
  const bracket = value.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (bracket) {
    return bracket[1];
  }
  const simple = value.match(/^([^:\[\]]+)(?::\d+)?$/);
  return simple ? simple[1] : "";
}

function provisionControlAPIFromEndpointAddress(endpointAddress: string, fallbackPort: string): string {
  const host = provisionEndpointHost(endpointAddress);
  if (!host) {
    return "";
  }
  return (host.includes(":") ? `https://[${host}]:${fallbackPort}` : `https://${host}:${fallbackPort}`);
}

function provisionEndpointAddressFromControlAPI(controlAPI: string, fallbackPort: string): string {
  const value = String(controlAPI || "").trim();
  if (!value) {
    return "";
  }
  try {
    const parsed = new URL(value.includes("://") ? value : `https://${value}`);
    const host = parsed.hostname.replace(/^\[|\]$/g, "");
    if (!host) {
      return "";
    }
    return host.includes(":") ? `[${host}]:${fallbackPort}` : `${host}:${fallbackPort}`;
  } catch {
    return "";
  }
}

function defaultLANGatewayForPrefix(rawPrefix: string): string {
  const prefix = parseIPv4Prefix(rawPrefix);
  if (!prefix) {
    return "";
  }
  const host = prefix.bits < 32 ? (prefix.network + 1) >>> 0 : prefix.network;
  return `${ipv4AddressString(host)}/${prefix.bits}`;
}

function deviceAccessQuickJoinCommand(response: DeviceAccessIssueResponse): string {
  const device = safeShellName(response.device || "device", "device");
  const base = `/etc/trustix/device/${device}`;
  const service = `trustix-device-${device}.service`;
  const certFile = "device.crt";
  const keyFile = "device.key";
  const trustRoots = deviceAccessTrustRootPEMs(response);
  const trustRootFiles = trustRoots.map((_, index) => `trust-root-${index + 1}.pem`);
  const clientConfigJSON = deviceAccessTargetClientConfigJSON(response, certFile, keyFile, trustRootFiles);
  const bodyLines = [
    "set -eu",
    `BASE=${shellSingleQuote(base)}`,
    `SERVICE=${shellSingleQuote(service)}`,
    'UNIT="/etc/systemd/system/$SERVICE"',
    'BIN="${TRUSTIX_DEVICE_BIN:-}"',
    'if [ -z "$BIN" ]; then',
    '  if command -v trustix-device >/dev/null 2>&1; then',
    '    BIN="$(command -v trustix-device)"',
    '  elif [ -x /usr/local/bin/trustix-device ]; then',
    '    BIN=/usr/local/bin/trustix-device',
    '  elif [ -x /opt/trustix/trustix-device ]; then',
    '    BIN=/opt/trustix/trustix-device',
    "  else",
    '    echo "trustix-device not found; deploy TrustIX first or set TRUSTIX_DEVICE_BIN" >&2',
    "    exit 127",
    "  fi",
    "fi",
    'install -d -m 0755 "$BASE"',
    shellWriteFile(`${base}/client.json`, clientConfigJSON, "CLIENT_JSON"),
    shellWriteFile(`${base}/${certFile}`, response.certificate_pem || "", "DEVICE_CERT"),
    shellWriteFile(`${base}/${keyFile}`, response.private_key_pem || "", "DEVICE_KEY"),
    ...trustRoots.map((root, index) => shellWriteFile(`${base}/${trustRootFiles[index]}`, root, `TRUST_ROOT_${index + 1}`)),
    `chmod 0644 ${shellSingleQuote(`${base}/client.json`)} ${shellSingleQuote(`${base}/${certFile}`)}${trustRootFiles.map((file) => ` ${shellSingleQuote(`${base}/${file}`)}`).join("")}`,
    `chmod 0600 ${shellSingleQuote(`${base}/${keyFile}`)}`,
    'if command -v systemctl >/dev/null 2>&1; then',
    '  cat > "$UNIT" <<EOF_SERVICE',
    "[Unit]",
    `Description=TrustIX device client ${device}`,
    "After=network-online.target",
    "Wants=network-online.target",
    "",
    "[Service]",
    "Type=simple",
    `WorkingDirectory=${base}`,
    `ExecStart=$BIN -config ${base}/client.json`,
    "Restart=always",
    "RestartSec=2s",
    "",
    "[Install]",
    "WantedBy=multi-user.target",
    "EOF_SERVICE",
    '  systemctl daemon-reload',
    '  systemctl enable --now "$SERVICE"',
    '  systemctl --no-pager --full status "$SERVICE" || true',
    "else",
    `  echo "systemd not found; run: $BIN -config ${base}/client.json" >&2`,
    "fi",
  ];
  const body = bodyLines.join("\n");
  const delimiter = uniqueHereDocDelimiter("QUICK_JOIN", body);
  return [
    `cat <<'${delimiter}' | sh -c 'if [ "$(id -u)" = 0 ]; then exec sh; elif command -v sudo >/dev/null 2>&1; then exec sudo sh; else echo "run as root or install sudo" >&2; exit 1; fi'`,
    body,
    delimiter,
  ].join("\n");
}

function deviceAccessTargetClientConfig(response: DeviceAccessIssueResponse, certFile: string, keyFile: string, trustRootFiles: string[]): Record<string, unknown> {
  const parsed = parseClientConfigJSON(response.client_config_json);
  const source = objectValue(response.client_config) || parsed || {};
  return {
    ...source,
    cert: certFile,
    key: keyFile,
    trust_roots: trustRootFiles,
  };
}

function deviceAccessDisplayClientConfigJSON(response: DeviceAccessIssueResponse): string {
  const trustRootFiles = deviceAccessTrustRootPEMs(response).map((_, index) => `trust-root-${index + 1}.pem`);
  return deviceAccessTargetClientConfigJSON(response, "device.crt", "device.key", trustRootFiles);
}

function deviceAccessTargetClientConfigJSON(response: DeviceAccessIssueResponse, certFile: string, keyFile: string, trustRootFiles: string[]): string {
  return JSON.stringify(deviceAccessTargetClientConfig(response, certFile, keyFile, trustRootFiles), null, 2);
}

function parseClientConfigJSON(value: string | undefined): Record<string, unknown> | null {
  if (!value) {
    return null;
  }
  try {
    return objectValue(JSON.parse(value));
  } catch {
    return null;
  }
}

function deviceAccessTrustRootPEMs(response: DeviceAccessIssueResponse): string[] {
  const roots = arrayValue(response.trust_roots_pem).map((value) => String(value || "").trim()).filter(Boolean);
  if (roots.length) {
    return roots;
  }
  const issuer = String(response.issuer_cert_pem || "").trim();
  return issuer ? [issuer] : [];
}

function objectValue(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function safeShellName(value: string, fallback: string): string {
  const safe = String(value || "").trim().replace(/[^A-Za-z0-9_.-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 64);
  return safe || fallback;
}

function shellSingleQuote(value: string): string {
  return `'${String(value).replace(/'/g, `'"'"'`)}'`;
}

function shellWriteFile(path: string, content: string, marker: string): string {
  const normalized = String(content || "").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const delimiter = uniqueHereDocDelimiter(marker, normalized);
  return [`cat > ${shellSingleQuote(path)} <<'${delimiter}'`, normalized.replace(/\n*$/, ""), delimiter].join("\n");
}

function uniqueHereDocDelimiter(marker: string, content: string): string {
  const base = `TRUSTIX_${marker.replace(/[^A-Za-z0-9_]+/g, "_")}_EOF`;
  let delimiter = base;
  while (content.includes(delimiter)) {
    delimiter = `${delimiter}_X`;
  }
  return delimiter;
}

function validateCIDRList(t: Translate, raw: string): string[] {
  const warnings: string[] = [];
  const seen = new Set<string>();
  for (const line of splitLines(raw)) {
    const parsed = parseIPv4Prefix(line);
    if (!parsed) {
      warnings.push(`${line}: ${t("invalid_cidr", "Invalid CIDR")}`);
      continue;
    }
    const normalized = ipv4PrefixString(parsed);
    if (seen.has(normalized)) {
      warnings.push(`${line}: ${t("duplicate_cidr", "Duplicate CIDR")}`);
    }
    seen.add(normalized);
  }
  return warnings;
}

export function AccessView(props: {
  t: Translate;
  lang: string;
  desired: DesiredConfig | null;
  deviceAccess: DeviceAccessPayload | null;
  endpointGrants: EndpointGrant[];
  issuedDevice: DeviceAccessIssueResponse | null;
  issuedIXProvision: IXProvisionIssueResponse | null;
  dirty: boolean;
  message: string;
  onIssueDevice: (request: {
    device: string;
    endpoint?: string;
    endpoint_address?: string;
    transport?: string;
    ttl?: string;
    bootstrap_routes?: string[];
    advertise_prefixes?: string[];
    server_name?: string;
    encryption?: string;
  }) => void;
  onIssueIXProvision: (request: IXProvisionIssueRequest) => void;
  onIssueEndpointGrant: (request: EndpointGrantIssueRequest) => void;
  onRevokeEndpointGrant: (grant: EndpointGrant) => void;
  onCopy: (text: string, label: string) => void;
  onDesired: (desired: DesiredConfig) => void;
  onValidate: () => void;
  onApply: () => void;
}) {
  const endpoints = arrayValue(props.desired?.endpoints);
  const deviceEndpointCandidates = useMemo(
    () => endpoints.filter(localPassiveEndpoint),
    [endpoints],
  );
  const grantRequiredEndpointCandidates = useMemo(
    () => endpoints.filter((endpoint) => localPassiveEndpoint(endpoint) && endpointRequiresGrant(endpoint)),
    [endpoints],
  );
  const grantEndpointCandidates = grantRequiredEndpointCandidates.length > 0 ? grantRequiredEndpointCandidates : deviceEndpointCandidates;
  const peers = routePeerOptions(props.desired);
  const [deviceID, setDeviceID] = useState("");
  const [deviceEndpoint, setDeviceEndpoint] = useState(deviceEndpointCandidates[0]?.name || "");
  const [deviceAddress, setDeviceAddress] = useState("");
  const [deviceTTL, setDeviceTTL] = useState("720h");
  const [deviceAdvertisePrefixes, setDeviceAdvertisePrefixes] = useState("");
  const [deviceBootstrapRoutes, setDeviceBootstrapRoutes] = useState("");
  const [deviceServerName, setDeviceServerName] = useState("");
  const [deviceEncryption, setDeviceEncryption] = useState("");
  const [grantPeer, setGrantPeer] = useState(peers[0] || "");
  const [grantEndpoint, setGrantEndpoint] = useState(grantEndpointCandidates[0]?.name || "");
  const [grantTTL, setGrantTTL] = useState("24h");
  const [grantReason, setGrantReason] = useState("");
  const [newIXID, setNewIXID] = useState("ix-new");
  const [newIXDomain, setNewIXDomain] = useState("");
  const [newIXRole, setNewIXRole] = useState("public_ix");
  const [newIXProfile, setNewIXProfile] = useState("plaintext_performance");
  const [newIXAdvertise, setNewIXAdvertise] = useState("");
  const [newIXControlAPI, setNewIXControlAPI] = useState("");
  const [newIXEndpointAddress, setNewIXEndpointAddress] = useState("");
  const [newIXEndpointMode, setNewIXEndpointMode] = useState("passive");
  const [newIXEndpointListen, setNewIXEndpointListen] = useState("");
  const [newIXEndpointTransport, setNewIXEndpointTransport] = useState("");
  const [newIXEndpointName, setNewIXEndpointName] = useState("");
  const [newIXBootstrapIX, setNewIXBootstrapIX] = useState("");
  const [newIXBootstrapControlAPI, setNewIXBootstrapControlAPI] = useState("");
  const [newIXLANIface, setNewIXLANIface] = useState("");
  const [newIXLANGateway, setNewIXLANGateway] = useState("");
  const [newIXUnderlayIface, setNewIXUnderlayIface] = useState("");
  const [newIXAttachMode, setNewIXAttachMode] = useState("managed");
  const [newIXSourceCerts, setNewIXSourceCerts] = useState("certs");
  const [newIXDomainCACert, setNewIXDomainCACert] = useState("certs/domain-ca.pem");
  const [newIXDomainCAKey, setNewIXDomainCAKey] = useState("certs/domain-ca.key");
  const [newIXConfigCACert, setNewIXConfigCACert] = useState("certs/config-ca.pem");
  const [newIXConfigCAKey, setNewIXConfigCAKey] = useState("certs/config-ca.key");
  const [newIXTrustRoots, setNewIXTrustRoots] = useState("");
  const [newIXProvisionURL, setNewIXProvisionURL] = useState("");
  const [newIXProvisionTTL, setNewIXProvisionTTL] = useState("30m");
  const [newIXTargetCertDir, setNewIXTargetCertDir] = useState("/etc/trustix/certs");
  const [newIXAPIAddr, setNewIXAPIAddr] = useState("127.0.0.1:8787");
  const [newIXPeerAPIAddr, setNewIXPeerAPIAddr] = useState("0.0.0.0:9443");
  const [newIXDataplane, setNewIXDataplane] = useState("auto");
  const [newIXServiceManager, setNewIXServiceManager] = useState("auto");
  const [newIXDNSEnabled, setNewIXDNSEnabled] = useState(false);
  const [newIXDNSDomain, setNewIXDNSDomain] = useState("");
  const [newIXOpenWRTDNSMasq, setNewIXOpenWRTDNSMasq] = useState(false);
  const [newIXKernelModules, setNewIXKernelModules] = useState("auto");
  const [newIXGoArch, setNewIXGoArch] = useState("");
  const [newIXBuildBPF, setNewIXBuildBPF] = useState("0");
  const [newIXBuildKO, setNewIXBuildKO] = useState("auto");
  const desiredDomainID = props.desired?.domain?.id || props.desired?.ix?.domain || "";
  const desiredIXID = props.desired?.ix?.id || "";
  const desiredControlAPI = props.desired?.ix?.control_api || "";
  const defaultUpstreamEndpointAddress = endpointPublicAddress(deviceEndpointCandidates[0]);
  const handleNewIXRoleChange = (value: string) => {
    setNewIXRole(value);
    if (value === "edge_ix") {
      setNewIXEndpointMode("active");
      setNewIXControlAPI((current) => current.trim() ? current : "");
      setNewIXEndpointAddress((current) => current.trim() || defaultUpstreamEndpointAddress);
    } else if (newIXEndpointMode === "active") {
      setNewIXEndpointMode("passive");
    }
  };
  const handleNewIXEndpointModeChange = (value: string) => {
    setNewIXEndpointMode(value);
    if (value === "active") {
      setNewIXControlAPI((current) => current.trim() ? current : "");
      setNewIXEndpointAddress((current) => current.trim() || defaultUpstreamEndpointAddress);
    }
  };
  const updateNewIXEndpointTransportDefault = (nextProfile: string, nextServiceManager = newIXServiceManager) => {
    void nextServiceManager;
    const previousDefault = ixProvisionDefaultEndpointTransport(newIXProfile, newIXEndpointMode, newIXEndpointAddress);
    const nextDefault = ixProvisionDefaultEndpointTransport(nextProfile, newIXEndpointMode, newIXEndpointAddress);
    if (newIXEndpointTransport === previousDefault) {
      setNewIXEndpointTransport(nextDefault);
    }
  };
  const handleNewIXProfileChange = (value: string) => {
    updateNewIXEndpointTransportDefault(value);
    setNewIXProfile(value);
  };
  const handleNewIXServiceManagerChange = (value: string) => {
    updateNewIXEndpointTransportDefault(newIXProfile, value);
    setNewIXServiceManager(value);
  };
  useEffect(() => {
    if (!deviceEndpoint && deviceEndpointCandidates[0]?.name) {
      setDeviceEndpoint(deviceEndpointCandidates[0].name);
    }
    if ((!grantEndpoint || !grantEndpointCandidates.some((endpoint) => endpoint.name === grantEndpoint)) && grantEndpointCandidates[0]?.name) {
      setGrantEndpoint(grantEndpointCandidates[0].name);
    }
    if (!grantPeer && peers[0]) {
      setGrantPeer(peers[0]);
    }
    if (!newIXDomain && desiredDomainID) {
      setNewIXDomain(desiredDomainID);
    }
    if (!newIXBootstrapIX && desiredIXID) {
      setNewIXBootstrapIX(desiredIXID);
    }
    if (!newIXBootstrapControlAPI && desiredControlAPI) {
      setNewIXBootstrapControlAPI(desiredControlAPI);
    }
    if (newIXEndpointMode === "active" && !newIXEndpointAddress.trim() && defaultUpstreamEndpointAddress) {
      setNewIXEndpointAddress(defaultUpstreamEndpointAddress);
    }
  }, [defaultUpstreamEndpointAddress, deviceEndpoint, deviceEndpointCandidates, desiredControlAPI, desiredDomainID, desiredIXID, grantEndpoint, grantEndpointCandidates, grantPeer, newIXBootstrapControlAPI, newIXBootstrapIX, newIXDomain, newIXEndpointAddress, newIXEndpointMode, peers]);
  const selectedDeviceEndpoint = deviceEndpointCandidates.find((endpoint) => endpoint.name === deviceEndpoint) || endpoints.find((endpoint) => endpoint.name === deviceEndpoint);
  const selectedGrantEndpoint = grantEndpointCandidates.find((endpoint) => endpoint.name === grantEndpoint) || endpoints.find((endpoint) => endpoint.name === grantEndpoint);
  const resolvedDeviceEndpointAddress = deviceAddress.trim() || endpointPublicAddress(selectedDeviceEndpoint);
  const deviceEndpointOptions = ["", ...deviceEndpointCandidates.map((endpoint) => endpoint.name || "").filter(Boolean)];
  const endpointLabels = Object.fromEntries(deviceEndpointCandidates.map((endpoint) => [endpoint.name || "", endpointLabel(endpoint)]));
  const grantEndpointOptions = ["", ...grantEndpointCandidates.map((endpoint) => endpoint.name || "").filter(Boolean)];
  const grantEndpointLabels = Object.fromEntries(grantEndpointCandidates.map((endpoint) => [
    endpoint.name || "",
    compactList([endpoint.name, endpoint.transport, endpointAccessMode(endpoint)], " · "),
  ]));
  const peerOptions = ["", ...peers];
  const now = Date.now();
  const activeGrants = props.endpointGrants.filter((grant) => endpointGrantLive(grant, now));
  const sortedEndpointGrants = [...props.endpointGrants].sort((left, right) => {
    const leftLive = endpointGrantLive(left, now) ? 0 : 1;
    const rightLive = endpointGrantLive(right, now) ? 0 : 1;
    if (leftLive !== rightLive) {
      return leftLive - rightLive;
    }
    const leftIssued = left.issued_at ? new Date(left.issued_at).getTime() : 0;
    const rightIssued = right.issued_at ? new Date(right.issued_at).getTime() : 0;
    return rightIssued - leftIssued;
  });
  const grantEndpointRequiresGrant = endpointRequiresGrant(selectedGrantEndpoint);
  const grantEndpointMode = endpointAccessMode(selectedGrantEndpoint);
  const grantEndpointTransport = selectedGrantEndpoint?.transport || props.t("missing", "Missing");
  const grantModePendingApply = grantEndpointRequiresGrant && props.dirty;
  const grantIssueDisabled = !grantPeer || !grantEndpoint;
  const newIXAdvertisePrefixes = splitLines(newIXAdvertise);
  const newIXAdvertiseWarnings = validateCIDRList(props.t, newIXAdvertise);
  const effectiveNewIXDomain = newIXDomain.trim() || desiredDomainID.trim();
  const newIXActiveOnly = newIXEndpointMode === "active";
  const newIXAdvertiseRequired = newIXRole !== "transit_ix";
  const newIXBootstrapControlAPIEffective = newIXBootstrapControlAPI.trim() || desiredControlAPI.trim();
  const newIXCommandDisabled = !newIXID.trim() || !effectiveNewIXDomain || (!newIXActiveOnly && !newIXEndpointAddress.trim()) || (newIXActiveOnly && !newIXBootstrapControlAPIEffective) || (newIXAdvertiseRequired && newIXAdvertisePrefixes.length === 0) || newIXAdvertiseWarnings.length > 0;
  const newIXEffectiveEndpointTransport = newIXEndpointTransport || ixProvisionDefaultEndpointTransport(newIXProfile, newIXEndpointMode, newIXEndpointAddress);
  const newIXResolvedEndpointName = newIXEndpointName.trim() || `${safeShellName(newIXID, "ix-new")}-${newIXEffectiveEndpointTransport}`;
  const newIXQuickJoinCommand = props.issuedIXProvision?.command || "";
  const newIXEffective = ixProvisionEffectiveDefaults({
    ixID: newIXID,
    role: newIXRole,
    profile: newIXProfile,
    endpointMode: newIXEndpointMode,
    endpointTransport: newIXEffectiveEndpointTransport,
    endpointAddress: newIXEndpointAddress,
    endpointListen: newIXEndpointListen,
    endpointName: newIXEndpointName,
    controlAPI: newIXControlAPI,
    advertisePrefixes: newIXAdvertisePrefixes,
    lanIface: newIXLANIface,
    lanGateway: newIXLANGateway,
    attachMode: newIXAttachMode,
    bootstrapControlAPI: newIXBootstrapControlAPI,
    desiredControlAPI,
    kernelModules: newIXKernelModules,
    serviceManager: newIXServiceManager,
  });
  const newIXRoleOptions = ["public_ix", "edge_ix", "transit_ix", "lab_ix"];
  const newIXRoleLabels = {
    public_ix: props.t("new_ix_role_public", "Public IX"),
    edge_ix: props.t("new_ix_role_edge", "Edge IX"),
    transit_ix: props.t("new_ix_role_transit", "Transit IX"),
    lab_ix: props.t("new_ix_role_lab", "Lab IX"),
  };
  const newIXEndpointModeLabels = {
    active: props.t("new_ix_endpoint_mode_active", "Active outbound"),
    passive: props.t("new_ix_endpoint_mode_passive", "Passive inbound"),
  };
  const newIXEndpointAddressLabel = newIXActiveOnly ? props.t("new_ix_upstream_endpoint", "Upstream data endpoint") : props.t("new_ix_endpoint_address", "New IX public endpoint");
  const newIXEndpointAddressHelp = newIXActiveOnly
    ? props.t("help_new_ix_upstream_endpoint", "Data endpoint on the upstream IX that this no-public-IP edge IX dials. Empty derives host:7000 from the bootstrap control API. It is not advertised as the new IX public address.")
    : props.t("help_new_ix_endpoint_address", "Public data endpoint address written into the new IX config. Domain:port and IP:port are both valid.");
  const newIXEndpointAddressPlaceholder = newIXActiveOnly ? (defaultUpstreamEndpointAddress || "ix-a.example.com:7000") : "ix-c.example.com:7000";
  const newIXProfileOptions = ["stable", "performance", "latency", "compatibility", "plaintext_performance"];
  const newIXProfileLabels = {
    stable: props.t("new_ix_profile_stable", "Stable"),
    performance: props.t("new_ix_profile_performance", "Performance"),
    latency: props.t("new_ix_profile_latency", "Low latency"),
    compatibility: props.t("new_ix_profile_compatibility", "Compatibility"),
    plaintext_performance: props.t("new_ix_profile_plaintext_performance", "Plaintext performance"),
  };
  const newIXServiceManagerLabels = {
    auto: props.t("service_manager_auto", "Auto"),
    systemd: "systemd",
    openwrt: "OpenWrt procd",
  };
  const handleNewIXOpenWRTDNSMasqChange = (value: boolean) => {
    setNewIXOpenWRTDNSMasq(value);
    if (value) {
      setNewIXDNSEnabled(true);
      if (newIXServiceManager === "auto") {
        updateNewIXEndpointTransportDefault(newIXProfile, "openwrt");
        setNewIXServiceManager("openwrt");
      }
    }
  };
  const newIXRequiredItems = [
    { label: props.t("new_ix_id", "New IX ID"), ok: Boolean(newIXID.trim()) },
    { label: newIXActiveOnly ? props.t("new_ix_bootstrap_control_api", "Bootstrap control API") : newIXEndpointAddressLabel, ok: newIXActiveOnly ? Boolean(newIXBootstrapControlAPIEffective) : Boolean(newIXEndpointAddress.trim()) },
    {
      label: newIXAdvertiseRequired ? props.t("new_ix_lan_prefixes", "New IX route prefixes") : props.t("new_ix_lan_prefixes_optional", "Optional route prefixes"),
      ok: newIXAdvertiseRequired ? newIXAdvertisePrefixes.length > 0 && newIXAdvertiseWarnings.length === 0 : newIXAdvertiseWarnings.length === 0,
    },
  ];
  const newIXAdvertiseLabel = newIXAdvertiseRequired ? props.t("new_ix_lan_prefixes", "New IX route prefixes") : props.t("new_ix_lan_prefixes_optional", "Optional route prefixes");
  const newIXAdvertiseHelp = newIXAdvertiseRequired
    ? props.t("help_new_ix_lan_prefixes", "CIDR prefixes this new IX will advertise or may transit in the domain, one per line. This creates route authorization, not a target-host interface address; the LAN gateway is derived from the role or overridden in advanced options.")
    : props.t("help_new_ix_lan_prefixes_transit", "Transit IX nodes can join without a local LAN prefix. Add CIDRs only when this node should originate or authorize downstream routes now; otherwise configure LANs later from the config page.");
  const newIXAdvertisePlaceholder = newIXAdvertiseRequired ? "10.83.0.0/24" : props.t("new_ix_lan_prefixes_optional_placeholder", "optional: 10.83.0.0/24");
  const deviceDelegatedParentPrefixes = arrayValue(props.desired?.lan?.advertise);
  const deviceReservedPrefixes = [
    props.deviceAccess?.address_pool || "",
    ...arrayValue(props.desired?.routes).map((route) => route.prefix || ""),
  ];
  const deviceAdvertiseWarnings = validateDeviceAdvertisePrefixes(props.t, deviceAdvertisePrefixes, [
    ...deviceReservedPrefixes,
  ], deviceDelegatedParentPrefixes, arrayValue(props.desired?.route_policy?.export_prefixes));
  const deviceIssueDisabled = !deviceID.trim() || !deviceEndpoint || !resolvedDeviceEndpointAddress || deviceAdvertiseWarnings.length > 0;
  const issuedDeviceQuickJoinCommand = props.issuedDevice ? deviceAccessQuickJoinCommand(props.issuedDevice) : "";
  const issuedDeviceClientConfigJSON = props.issuedDevice ? deviceAccessDisplayClientConfigJSON(props.issuedDevice) : "";
  const updateEndpointAccess = (index: number, endpoint: EndpointConfig) => {
    if (!props.desired) {
      return;
    }
    const nextEndpoints = [...arrayValue(props.desired.endpoints)];
    nextEndpoints[index] = endpoint;
    props.onDesired({ ...props.desired, endpoints: nextEndpoints });
  };
  const enableGrantModeForEndpoint = (endpointName: string) => {
    if (!props.desired || !endpointName) {
      return;
    }
    const nextEndpoints = [...arrayValue(props.desired.endpoints)];
    const index = nextEndpoints.findIndex((endpoint) => endpoint.name === endpointName);
    if (index < 0) {
      return;
    }
    const endpoint = nextEndpoints[index];
    nextEndpoints[index] = { ...endpoint, access: { ...(endpoint.access || {}), mode: "require_grant" } };
    props.onDesired({ ...props.desired, endpoints: nextEndpoints });
  };
  return (
    <main className="views">
      <section className="view access-layout">
        <div className="panel">
          <div className="panel-head">
            <div>
              <h2>{props.t("access", "Access")}</h2>
              <p className="panel-note inline-note">{props.t("access_note", "Issue device certificates and endpoint grants from the WebUI.")}</p>
            </div>
            <div className="inline-controls">
              <Pill state={props.dirty ? "warn" : "ok"}>{props.dirty ? props.t("unsaved_changes", "Unsaved changes") : props.t("saved", "Saved")}</Pill>
              <Button variant="ghost" onClick={props.onValidate}><Check size={15} />{props.t("validate", "Validate")}</Button>
              <Button onClick={props.onApply}><Save size={15} />{props.t("apply", "Apply")}</Button>
            </div>
          </div>
          <div className="summary-grid">
            <SummaryItem label={props.t("device_access", "Device access")} value={props.deviceAccess?.enabled ? props.t("enabled", "Enabled") : props.t("disabled", "Disabled")} />
            <SummaryItem label={props.t("address_pool", "Address pool")} value={props.deviceAccess?.address_pool || "-"} />
            <SummaryItem label={props.t("leases", "Leases")} value={formatNumber(props.deviceAccess?.counts?.leased || props.deviceAccess?.leases?.length || 0, props.lang)} />
            <SummaryItem label={props.t("active_grants", "Active grants")} value={formatNumber(activeGrants.length, props.lang)} />
          </div>
        </div>

        <section className="panel ix-bootstrap-panel">
          <div className="panel-head">
            <div>
              <h2>{props.t("join_new_ix", "Join new IX")}</h2>
              <p className="panel-note inline-note">{props.t("help_join_new_ix", "Issue a one-time provision token, then paste the generated command on the target Linux host. CA private keys stay on this IX/provisioner.")}</p>
            </div>
            <Network size={18} />
          </div>
          <div className="access-form ix-bootstrap-form">
            <div className="ix-bootstrap-primary config-wide">
              <SelectField label={props.t("new_ix_role", "IX role")} help={props.t("help_new_ix_role", "Role selects the generated LAN defaults and route-exchange intent.")} value={newIXRole} options={newIXRoleOptions} optionLabels={newIXRoleLabels} onChange={handleNewIXRoleChange} />
              <SelectField label={props.t("new_ix_profile", "Deployment profile")} help={props.t("help_new_ix_profile", "Profile chooses stable, performance, latency, compatibility, or plaintext performance defaults.")} value={newIXProfile} options={newIXProfileOptions} optionLabels={newIXProfileLabels} onChange={handleNewIXProfileChange} />
              <SelectField label={props.t("new_ix_endpoint_mode", "Endpoint mode")} help={props.t("help_new_ix_endpoint_mode", "Passive inbound publishes a reachable endpoint for peers to dial. Active outbound is for edge IX nodes without public inbound access.")} value={newIXEndpointMode} options={["passive", "active"]} optionLabels={newIXEndpointModeLabels} onChange={handleNewIXEndpointModeChange} />
              <Field label={props.t("new_ix_id", "New IX ID")} help={props.t("help_new_ix_id", "Unique IX identity to issue. It must differ from the current IX and becomes the certificate IX name.")} placeholder="ix-c" value={newIXID} onChange={setNewIXID} />
              <Field label={newIXEndpointAddressLabel} help={newIXEndpointAddressHelp} placeholder={newIXEndpointAddressPlaceholder} value={newIXEndpointAddress} onChange={setNewIXEndpointAddress} />
            </div>
            <Field label={newIXAdvertiseLabel} help={newIXAdvertiseHelp} textarea placeholder={newIXAdvertisePlaceholder} value={newIXAdvertise} onChange={setNewIXAdvertise} />
            {newIXAdvertiseWarnings.length > 0 && <div className="field-hint warn config-wide">{newIXAdvertiseWarnings.join(" · ")}</div>}
            {!newIXAdvertiseRequired && newIXAdvertisePrefixes.length === 0 && <div className="field-hint config-wide">{props.t("new_ix_transit_no_prefix_note", "Transit-only join: no local LAN route authorization will be issued. The IX can still join the control fabric and learn domain routes.")}</div>}
            <div className="requirement-strip config-wide" aria-label={props.t("new_ix_required_fields", "Required fields")}>
              <span className="requirement-label">{props.t("new_ix_required_fields", "Required fields")}</span>
              {newIXRequiredItems.map((item) => (
                <span key={item.label} className={`requirement-item ${item.ok ? "ok" : "warn"}`}>
                  {item.ok ? <Check size={14} /> : <Circle size={12} />}
                  <span>{item.label}</span>
                  <strong>{item.ok ? props.t("ready", "Ready") : props.t("missing", "Missing")}</strong>
                </span>
              ))}
            </div>
            <details className="endpoint-advanced-fields config-wide">
              <summary>{props.t("new_ix_advanced", "Advanced IX bootstrap")}</summary>
              <div className="endpoint-advanced-grid ix-bootstrap-advanced-grid">
                <Field label={props.t("domain", "Domain")} help={props.t("help_new_ix_domain_locked", "Provisioned IX nodes always join the current TrustIX domain; the server rejects any different domain.")} value={newIXDomain || desiredDomainID || "-"} onChange={() => undefined} readOnly />
                <Field label={props.t("new_ix_control_api", "New IX public control API")} help={newIXActiveOnly ? props.t("help_new_ix_control_api_active", "Optional published control API for this edge IX. Leave empty when it has no public inbound control-plane address.") : props.t("help_new_ix_control_api", "Optional public URL for the new IX control API. Empty derives https://host:9443 from the public endpoint.")} placeholder={newIXActiveOnly ? props.t("no_control_api", "No control API published") : (newIXEffective.controlAPI || "https://ix-c.example.com:9443")} value={newIXControlAPI} onChange={setNewIXControlAPI} />
                <Field label={props.t("new_ix_bootstrap_peer", "Bootstrap peer IX")} help={props.t("help_new_ix_bootstrap_peer", "Existing IX used as the first control-plane peer for the generated config.")} value={newIXBootstrapIX} onChange={setNewIXBootstrapIX} />
                <Field label={props.t("new_ix_bootstrap_control_api", "Bootstrap control API")} help={props.t("help_new_ix_bootstrap_control_api", "Control API URL of the bootstrap peer. Empty uses the current IX control API from this config.")} placeholder={newIXEffective.bootstrapControlAPI || "https://ix-a.example.com:9443"} value={newIXBootstrapControlAPI} onChange={setNewIXBootstrapControlAPI} />
                <SelectField label={props.t("transport", "Transport")} help={newIXActiveOnly ? props.t("help_new_ix_transport_active", "Data transport used to dial the upstream endpoint. It should match the selected upstream endpoint transport.") : props.t("help_new_ix_transport", "Initial passive data transport for the new IX endpoint. Plaintext performance uses IPIP when the public endpoint is an IPv4 address; DNS or active endpoints fall back to experimental_tcp.")} value={newIXEffectiveEndpointTransport} options={transportOptions()} onChange={setNewIXEndpointTransport} />
                {!newIXActiveOnly && <Field label={props.t("new_ix_endpoint_listen", "Endpoint listen")} help={props.t("help_new_ix_endpoint_listen", "Optional listen address. Empty listens on 0.0.0.0 with the public endpoint port.")} placeholder={newIXEffective.endpointListen || "0.0.0.0:7000"} value={newIXEndpointListen} onChange={setNewIXEndpointListen} />}
                <Field label={props.t("new_ix_endpoint_name", "Endpoint name")} help={props.t("help_new_ix_endpoint_name", "Optional local endpoint name written into the generated config. Empty derives <ix_id>-<transport>.")} placeholder={newIXResolvedEndpointName} value={newIXEndpointName} onChange={setNewIXEndpointName} />
                <Field label={props.t("new_ix_lan_iface", "LAN interface")} help={props.t("help_new_ix_lan_iface", "Optional LAN interface. Managed mode creates trustix-<ix_id> when empty; existing mode requires a host interface.")} placeholder={newIXEffective.lanIface || "br-lan / eth1"} value={newIXLANIface} onChange={setNewIXLANIface} />
                <Field label={props.t("new_ix_lan_gateway", "LAN gateway")} help={props.t("help_new_ix_lan_gateway", "Optional local gateway CIDR. Public/edge/lab roles derive the first address of the first advertised prefix; transit leaves it empty.")} placeholder={newIXEffective.lanGateway || "10.83.0.1/24"} value={newIXLANGateway} onChange={setNewIXLANGateway} />
                <Field label={props.t("new_ix_underlay_iface", "Underlay interface")} help={props.t("help_new_ix_underlay_iface", "Optional physical or WAN interface hint used by kernel fast paths and tunnel transports.")} value={newIXUnderlayIface} onChange={setNewIXUnderlayIface} />
                <SelectField label={props.t("new_ix_attach_mode", "Attach mode")} help={props.t("help_new_ix_attach_mode", "Managed lets TrustIX create/manage the LAN interface; existing attaches to an interface already present on the target host.")} value={newIXAttachMode} options={["managed", "existing"]} onChange={setNewIXAttachMode} />
                <Field label={props.t("new_ix_provision_url", "Provision URL")} help={props.t("help_new_ix_provision_url", "Public management URL of this IX/provisioner. Empty uses the current WebUI origin seen by the server.")} placeholder="https://ix-a.example.com:18787" value={newIXProvisionURL} onChange={setNewIXProvisionURL} />
                <Field label={props.t("new_ix_provision_ttl", "Token TTL")} help={props.t("help_new_ix_provision_ttl", "Lifetime of the one-time bootstrap token. Short TTLs reduce risk if the command is leaked.")} value={newIXProvisionTTL} onChange={setNewIXProvisionTTL} />
                <Field label={props.t("new_ix_target_cert_dir", "Target cert dir")} help={props.t("help_new_ix_target_cert_dir", "Directory path written into the generated target config for IX certificates and trust roots.")} value={newIXTargetCertDir} onChange={setNewIXTargetCertDir} />
                <SelectField label={props.t("new_ix_goarch", "GOARCH")} help={props.t("help_new_ix_goarch", "Optional target CPU architecture for cross-builds. Empty uses the target host architecture when possible.")} value={newIXGoArch} options={["", "amd64", "arm64", "arm", "386", "mips", "mipsle", "mips64", "mips64le", "riscv64"]} onChange={setNewIXGoArch} />
                <SelectField label={props.t("dataplane", "Dataplane")} help={props.t("help_new_ix_dataplane", "Runtime dataplane mode for the target IX. Auto chooses the best supported path; noop is only for diagnostics.")} value={newIXDataplane} options={["auto", "linux", "noop"]} onChange={setNewIXDataplane} />
                <SelectField label={props.t("service_manager", "Service manager")} help={props.t("help_new_ix_service_manager", "Target service manager for installation. Auto detects systemd on normal Linux and OpenWrt procd on OpenWrt.")} value={newIXServiceManager} options={["auto", "systemd", "openwrt"]} optionLabels={newIXServiceManagerLabels} onChange={handleNewIXServiceManagerChange} />
                <SelectField label={props.t("new_ix_kernel_modules", "Kernel modules")} help={props.t("help_new_ix_kernel_modules", "Controls whether target install may load TrustIX kernel modules. Required fails installation if modules cannot load.")} value={newIXKernelModules} options={["auto", "disabled", "required"]} onChange={setNewIXKernelModules} />
                <CheckField label={props.t("dns_enabled", "DNS enabled")} help={props.t("help_new_ix_dns_enabled", "Enable the built-in TrustIX DNS resolver on the new IX. It answers names inside the TrustIX DNS domain only unless upstreams are configured later.")} checked={newIXDNSEnabled} onChange={setNewIXDNSEnabled} />
                <CheckField label={props.t("openwrt_dnsmasq", "OpenWrt dnsmasq")} help={props.t("help_new_ix_openwrt_dnsmasq", "For OpenWrt targets, add a dnsmasq conditional forward for only the TrustIX DNS domain and keep normal LAN DNS unchanged.")} checked={newIXOpenWRTDNSMasq} onChange={handleNewIXOpenWRTDNSMasqChange} />
                <Field label={props.t("dns_domain", "DNS domain")} help={props.t("help_new_ix_dns_domain", "Optional DNS suffix for TrustIX IX names. Empty uses the TrustIX domain ID.")} placeholder={desiredDomainID || "trust.ix"} value={newIXDNSDomain} onChange={setNewIXDNSDomain} />
                <Field label={props.t("new_ix_api_listen", "Admin API listen")} help={props.t("help_new_ix_api_listen", "Management API listen address on the target IX. Keep loopback unless you intend to expose the WebUI/API.")} value={newIXAPIAddr} onChange={setNewIXAPIAddr} />
                <Field label={props.t("new_ix_peer_api_listen", "Peer API listen")} help={props.t("help_new_ix_peer_api_listen", "Peer control API listen address on the target IX, used by other IX nodes for control-plane sync.")} value={newIXPeerAPIAddr} onChange={setNewIXPeerAPIAddr} />
                <Field label={props.t("source_certs", "Source certs")} help={props.t("help_new_ix_source_certs", "Local directory on the provisioner that contains domain/config CA material used to issue the new IX.")} value={newIXSourceCerts} onChange={setNewIXSourceCerts} />
                <Field label={props.t("domain_ca_cert", "Domain CA cert")} help={props.t("help_new_ix_domain_ca_cert", "Domain CA certificate path on the provisioner. It identifies the TrustIX domain issuing the new IX certificate.")} value={newIXDomainCACert} onChange={setNewIXDomainCACert} />
                <Field label={props.t("domain_ca_key", "Domain CA key")} help={props.t("help_new_ix_domain_ca_key", "Domain CA private key path on the provisioner. It is used only to sign the new IX certificate and is not sent to the target.")} value={newIXDomainCAKey} onChange={setNewIXDomainCAKey} />
                <Field label={props.t("config_ca_cert", "Config CA cert")} help={props.t("help_new_ix_config_ca_cert", "Config CA certificate path on the provisioner, used to verify route authorization issuing authority.")} value={newIXConfigCACert} onChange={setNewIXConfigCACert} />
                <Field label={props.t("config_ca_key", "Config CA key")} help={props.t("help_new_ix_config_ca_key", "Config CA private key path on the provisioner. It signs route authorizations and is not sent to the target.")} value={newIXConfigCAKey} onChange={setNewIXConfigCAKey} />
                <SelectField label={props.t("new_ix_build_bpf", "Rebuild BPF")} help={props.t("help_new_ix_build_bpf", "Recompile embedded eBPF objects on the target. Leave off for normal installs; embedded BPF fast-path objects are still used.")} value={newIXBuildBPF} options={["1", "0"]} onChange={setNewIXBuildBPF} />
                <SelectField label={props.t("new_ix_build_ko", "Build .ko")} help={props.t("help_new_ix_build_ko", "Whether the bootstrap build should build TrustIX kernel modules. Auto builds them when kernel headers are available.")} value={newIXBuildKO} options={["auto", "1", "0"]} onChange={setNewIXBuildKO} />
                <Field label={props.t("trust_roots", "Trust roots")} help={props.t("help_new_ix_trust_roots", "Optional trust root paths, one per line. Empty uses certs/root-ca.pem, certs/domain-ca.pem, and certs/config-ca.pem if present.")} textarea value={newIXTrustRoots} onChange={setNewIXTrustRoots} />
                <div className="ix-bootstrap-effective config-wide">
                  <div className="subhead">
                    <strong>{props.t("new_ix_effective_config", "Effective generated config")}</strong>
                    <span className="readonly-note">{compactList([newIXRoleLabels[newIXRole as keyof typeof newIXRoleLabels], newIXProfileLabels[newIXProfile as keyof typeof newIXProfileLabels]], " / ")}</span>
                  </div>
                  <div className="ix-bootstrap-effective-grid">
                    <StatusRow label={props.t("new_ix_control_api", "New IX public control API")} value={newIXEffective.controlAPI || props.t("no_control_api", "No control API published")} />
                    <StatusRow label={props.t("endpoint", "Endpoint")} value={compactList([compactList([newIXEffective.endpointName, newIXEffective.acklessEndpointName], " + "), newIXEndpointModeLabels[newIXEffective.endpointMode as keyof typeof newIXEndpointModeLabels] || newIXEffective.endpointMode, newIXEffectiveEndpointTransport, newIXEffective.endpointListen, newIXEffective.endpointAddress], " / ")} />
                    <StatusRow label={props.t("lan", "LAN")} value={compactList([newIXEffective.lanIface, newIXEffective.lanGateway || props.t("no_gateway", "No gateway"), newIXAttachMode], " / ")} />
                    <StatusRow label={props.t("transport_policy", "Transport policy")} value={compactList([newIXEffective.transportProfile, newIXEffective.datapath, newIXEffective.encryption, newIXEffective.cryptoPlacement, `kernel=${newIXEffective.kernelTransport}`], " / ")} />
                    <StatusRow label={props.t("service_manager", "Service manager")} value={newIXServiceManagerLabels[newIXServiceManager as keyof typeof newIXServiceManagerLabels] || newIXServiceManager} />
                    <StatusRow label={props.t("dns", "DNS")} value={newIXDNSEnabled ? compactList([newIXDNSDomain.trim() || effectiveNewIXDomain, newIXOpenWRTDNSMasq ? props.t("openwrt_dnsmasq", "OpenWrt dnsmasq") : props.t("dns_split_only", "Split-only")], " / ") : props.t("disabled", "Disabled")} />
                    <StatusRow label={props.t("kernel_modules", "Kernel modules")} value={newIXEffective.kernelModules || "auto"} />
                    <StatusRow label={props.t("bootstrap", "Bootstrap")} value={compactList([newIXBootstrapIX || desiredIXID, newIXEffective.bootstrapControlAPI], " / ")} />
                  </div>
                </div>
              </div>
            </details>
          </div>
          <div className="access-output ix-bootstrap-output">
            {props.issuedIXProvision && (
              <div className="issue-result-meta">
                <Pill state="ok">{props.t("provision_token_ready", "Token ready")}</Pill>
                <span>{props.t("expires_at", "Expires at")}: {formatTime(props.issuedIXProvision.expires_at, props.lang)}</span>
                <span title={props.issuedIXProvision.ix_cert_fingerprint}>{compactList([props.t("fingerprint", "Fingerprint"), props.issuedIXProvision.ix_cert_fingerprint?.slice(0, 16)], " ")}</span>
              </div>
            )}
            <Field label={props.t("new_ix_bootstrap_command", "Target one-command join")} help={props.t("help_new_ix_bootstrap_command", "One-time command to run on the target Linux host. It fetches the provision token payload without exposing CA private keys.")} textarea value={newIXQuickJoinCommand} placeholder={props.t("new_ix_command_pending", "Issue a one-time token to generate the target command.")} onChange={() => undefined} />
            <div className="form-actions">
              <Button disabled={newIXCommandDisabled} onClick={() => props.onIssueIXProvision({
                ix_id: newIXID.trim(),
                domain: undefined,
                role: newIXRole || undefined,
                profile: newIXProfile || undefined,
                control_api: newIXControlAPI.trim() || undefined,
                advertise: newIXAdvertisePrefixes,
                endpoint_name: newIXResolvedEndpointName,
                endpoint_mode: newIXEndpointMode || undefined,
                endpoint_transport: newIXEffectiveEndpointTransport || undefined,
                endpoint_listen: newIXActiveOnly ? undefined : (newIXEndpointListen.trim() || undefined),
                endpoint_address: newIXEndpointAddress.trim() || undefined,
                lan_iface: newIXLANIface.trim() || undefined,
                lan_gateway: newIXLANGateway.trim() || undefined,
                underlay_iface: newIXUnderlayIface.trim() || undefined,
                attach_mode: newIXAttachMode || undefined,
                api_addr: newIXAPIAddr.trim() || undefined,
                peer_api_addr: newIXPeerAPIAddr.trim() || undefined,
                dataplane: newIXDataplane || undefined,
                service_manager: newIXServiceManager || undefined,
                dns_enabled: newIXDNSEnabled ? "1" : "0",
                dns_domain: newIXDNSDomain.trim() || undefined,
                openwrt_dnsmasq: newIXOpenWRTDNSMasq ? "1" : "0",
                kernel_modules: newIXKernelModules || undefined,
                goarch: newIXGoArch || undefined,
                build_bpf: newIXBuildBPF || undefined,
                build_ko: newIXBuildKO || undefined,
                source_certs: newIXSourceCerts.trim() || undefined,
                domain_ca_cert: newIXDomainCACert.trim() || undefined,
                domain_ca_key: newIXDomainCAKey.trim() || undefined,
                config_ca_cert: newIXConfigCACert.trim() || undefined,
                config_ca_key: newIXConfigCAKey.trim() || undefined,
                trust_roots: splitLines(newIXTrustRoots),
                target_cert_dir: newIXTargetCertDir.trim() || undefined,
                bootstrap_ix: newIXBootstrapIX.trim() || undefined,
                bootstrap_control_api: newIXBootstrapControlAPI.trim() || undefined,
                provision_url: newIXProvisionURL.trim() || undefined,
                ttl: newIXProvisionTTL.trim() || undefined,
              })}><KeyRound size={15} />{props.t("issue_provision_token", "Issue provision token")}</Button>
              <Button variant="ghost" disabled={!newIXQuickJoinCommand} onClick={() => props.onCopy(newIXQuickJoinCommand, props.t("new_ix_bootstrap_command", "Target one-command join"))}><Copy size={15} />{props.t("copy_join_new_ix", "Copy target join command")}</Button>
            </div>
          </div>
        </section>

        <div className="access-grid">
          <section className="panel">
            <div className="panel-head">
              <h2>{props.t("issue_device_certificate", "Issue device certificate")}</h2>
              <ShieldCheck size={18} />
            </div>
            <div className="access-form device-issue-form">
              <div className="device-issue-primary config-wide">
                <Field label={props.t("device_id", "Device ID")} help={props.t("help_device_id", "Stable device identity written into the issued certificate and device access lease.")} placeholder="laptop-01" value={deviceID} onChange={setDeviceID} />
                <EndpointSelectField
                  label={props.t("endpoint", "Endpoint")}
                  help={props.t("help_device_issue_endpoint", "Select an enabled passive local endpoint. Its configured public address is used unless an override is set below.")}
                  addressLabel={props.t("public_endpoint_address", "Public endpoint address")}
                  address={resolvedDeviceEndpointAddress || props.t("missing", "Missing")}
                  value={deviceEndpoint}
                  options={deviceEndpointOptions}
                  optionLabels={endpointLabels}
                  onChange={setDeviceEndpoint}
                />
                <Field label={props.t("ttl", "TTL")} help={props.t("help_device_ttl", "Certificate and lease lifetime for the issued device config.")} placeholder="720h" value={deviceTTL} onChange={setDeviceTTL} />
                <Field label={props.t("server_name", "Server name")} help={props.t("help_device_server_name", "Optional TLS server name override used by the generated device client config.")} value={deviceServerName} onChange={setDeviceServerName} />
                <SelectField label={props.t("encryption", "Encryption")} help={props.t("help_device_encryption", "Optional device transport encryption override. Empty follows the selected endpoint and transport policy.")} value={deviceEncryption} options={encryptionOptions()} onChange={setDeviceEncryption} />
              </div>
              <Field label={props.t("device_advertise_prefixes", "Downstream advertised prefixes")} help={props.t("help_device_advertise_prefixes", "Route advertisement authorization issued to this downstream device or IX, one CIDR per line. Ordinary devices usually leave this empty and only receive one leased address; fill it only when the downstream side hosts its own LAN or acts as a child IX transit node. The upstream still accepts prefixes through certificate authorization and domain policy.")} textarea placeholder="10.99.0.0/24" value={deviceAdvertisePrefixes} onChange={setDeviceAdvertisePrefixes} />
              {deviceAdvertiseWarnings.length > 0 && <div className="field-hint warn config-wide">{deviceAdvertiseWarnings.join(" · ")}</div>}
              <details className="endpoint-advanced-fields config-wide">
                <summary>{props.t("device_issue_advanced", "Advanced device config")}</summary>
                <div className="endpoint-advanced-grid">
                  <Field label={props.t("public_endpoint_override", "Public endpoint override")} help={props.t("help_public_endpoint_override", "Optional address written into the generated client config instead of the selected endpoint address. Use domain:port or IP:port.")} placeholder={props.t("placeholder_endpoint_address", "203.0.113.10:7000")} value={deviceAddress} onChange={setDeviceAddress} />
                  <Field label={props.t("bootstrap_routes", "Initial static routes")} help={props.t("help_bootstrap_routes", "Optional initial static routes written into the generated client config. Normal domain routes are synchronized by the IX after the device connects, so ordinary devices usually leave this empty.")} textarea value={deviceBootstrapRoutes} onChange={setDeviceBootstrapRoutes} />
                </div>
              </details>
              <div className="form-actions">
                <Button disabled={deviceIssueDisabled} onClick={() => props.onIssueDevice({
                  device: deviceID.trim(),
                  endpoint: deviceEndpoint || undefined,
                  endpoint_address: deviceAddress.trim() || undefined,
                  ttl: deviceTTL.trim() || undefined,
                  advertise_prefixes: splitLines(deviceAdvertisePrefixes),
                  bootstrap_routes: splitLines(deviceBootstrapRoutes),
                  server_name: deviceServerName.trim() || undefined,
                  encryption: deviceEncryption || undefined,
                })}><ShieldCheck size={15} />{props.t("issue", "Issue")}</Button>
              </div>
            </div>
            {props.issuedDevice && (
              <div className="access-output">
                <StatusRow label={props.t("fingerprint", "Fingerprint")} value={props.issuedDevice.fingerprint || "-"} />
                <StatusRow label={props.t("not_after", "Not after")} value={formatTime(props.issuedDevice.not_after, props.lang)} />
                <Field label={props.t("quick_join_command", "Quick join command")} help={props.t("help_device_quick_join_command", "Root shell command that installs the issued device certificate, key, trust roots, and systemd unit.")} textarea value={issuedDeviceQuickJoinCommand} onChange={() => undefined} />
                <Field label={props.t("client_config_json", "Client config JSON")} help={props.t("help_device_client_config_json", "Raw client configuration produced for the issued device certificate.")} textarea value={issuedDeviceClientConfigJSON} onChange={() => undefined} />
                <div className="form-actions">
                  <Button onClick={() => props.onCopy(issuedDeviceQuickJoinCommand, props.t("quick_join_command", "Quick join command"))}><Copy size={15} />{props.t("copy_quick_join", "Copy quick join")}</Button>
                  <Button variant="ghost" onClick={() => props.onCopy(issuedDeviceClientConfigJSON, props.t("client_config_json", "Client config JSON"))}><Copy size={15} />{props.t("copy_config", "Copy config")}</Button>
                  <Button variant="ghost" onClick={() => props.onCopy(props.issuedDevice?.certificate_pem || "", props.t("certificate", "Certificate"))}><Copy size={15} />{props.t("copy_certificate", "Copy certificate")}</Button>
                  <Button variant="ghost" onClick={() => props.onCopy(props.issuedDevice?.private_key_pem || "", props.t("private_key", "Private key"))}><Copy size={15} />{props.t("copy_key", "Copy key")}</Button>
                </div>
              </div>
            )}
          </section>

          <section className="panel">
            <div className="panel-head">
              <h2>{props.t("issue_endpoint_grant", "Issue endpoint grant")}</h2>
            </div>
            <div className="access-form endpoint-grant-form">
              <SelectField label={props.t("grant_subject_ix", "Authorized IX")} help={props.t("help_grant_subject_ix", "Remote IX allowed to open inbound data sessions on the selected local endpoint.")} value={grantPeer} options={peerOptions} onChange={setGrantPeer} />
              <SelectField label={props.t("grant_endpoint", "Protected endpoint")} help={props.t("help_grant_endpoint", "Local passive endpoint this authorization applies to. Endpoints using require_grant are listed first.")} value={grantEndpoint} options={grantEndpointOptions} optionLabels={grantEndpointLabels} onChange={setGrantEndpoint} />
              <Field label={props.t("ttl", "TTL")} help={props.t("help_endpoint_grant_ttl", "Lifetime of the endpoint authorization issued for the selected remote IX.")} placeholder="24h" value={grantTTL} onChange={setGrantTTL} />
              <Field label={props.t("reason", "Reason")} help={props.t("help_endpoint_grant_reason", "Optional operator note stored with the grant for audit and troubleshooting.")} value={grantReason} onChange={setGrantReason} />
              <div className={`grant-mode-panel config-wide ${grantEndpointRequiresGrant && !grantModePendingApply ? "ok" : "warn"}`}>
                <div className="grant-mode-copy">
                  <strong>{grantEndpointRequiresGrant ? (grantModePendingApply ? props.t("grant_mode_pending_apply", "require_grant pending apply") : props.t("grant_enforced", "Grant enforced")) : props.t("grant_not_enforced_short", "Grant not enforced")}</strong>
                  <span>{compactList([
                    `${props.t("access_mode", "Access mode")}: ${grantEndpointMode}`,
                    `${props.t("transport", "Transport")}: ${grantEndpointTransport}`,
                    grantEndpointRequiresGrant ? (grantModePendingApply ? props.t("grant_apply_required", "Click Apply before runtime enforcement changes") : props.t("grant_enforced_detail", "Inbound data sessions require an active endpoint grant")) : props.t("grant_not_enforced", "Grant is not enforced until this endpoint uses require_grant"),
                  ], " · ")}</span>
                </div>
                {!grantEndpointRequiresGrant && selectedGrantEndpoint && (
                  <Button variant="ghost" onClick={() => enableGrantModeForEndpoint(grantEndpoint)}><ShieldCheck size={15} />{props.t("enable_grant_mode", "Enable require_grant")}</Button>
                )}
              </div>
              <div className="form-actions">
                <Button disabled={grantIssueDisabled} onClick={() => props.onIssueEndpointGrant({
                  subject_ix: grantPeer,
                  endpoint: grantEndpoint,
                  ttl: grantTTL.trim() || undefined,
                  reason: grantReason.trim() || undefined,
                })}><Plus size={15} />{props.t("issue_grant", "Issue grant")}</Button>
              </div>
            </div>
            <div className="grant-list">
              {sortedEndpointGrants.length ? sortedEndpointGrants.map((grant) => (
                <div className="grant-row" key={grant.grant_id || `${grant.subject_ix}-${grant.endpoint}`}>
                  <div className="grant-main">
                    <strong>{compactList([grant.issuer_ix || props.desired?.ix?.id || "-", "->", grant.subject_ix || "-"], " ")}</strong>
                    <span>{compactList([
                      `${props.t("grant_id", "Grant ID")}: ${shortGrantID(grant.grant_id)}`,
                      grant.endpoint,
                      grant.transport || props.t("transport_auto", "Transport auto"),
                      grant.expires_at ? `${props.t("expires", "Expires")} ${formatTime(grant.expires_at, props.lang)}` : props.t("no_expiry", "No expiry"),
                      grant.reason ? `${props.t("reason", "Reason")}: ${grant.reason}` : "",
                    ], " · ")}</span>
                  </div>
                  <Pill state={endpointGrantPillState(grant, now)}>{endpointGrantStateLabel(grant, props.t, now)}</Pill>
                  <Button variant="danger" disabled={grant.state === "revoked"} onClick={() => props.onRevokeEndpointGrant(grant)}><Trash2 size={15} />{props.t("revoke", "Revoke")}</Button>
                </div>
              )) : <div className="empty-row">{props.t("no_endpoint_grant", "No endpoint grant")}</div>}
            </div>
          </section>
        </div>

        <section className="panel">
          <div className="panel-head">
            <h2>{props.t("endpoint_access_policy", "Endpoint access policy")}</h2>
            <span className="muted">{endpoints.length}</span>
          </div>
          <div className="endpoint-access-list">
            {endpoints.length ? endpoints.map((endpoint, index) => (
              <div className="endpoint-access-row" key={`${endpoint.name}-${index}`}>
                <div>
                  <strong>{endpoint.name || props.t("endpoint", "Endpoint")}</strong>
                  <span>{compactList([endpoint.transport, endpointAddressSummary(endpoint, props.t)], " · ")}</span>
                </div>
                <EndpointAccessFields t={props.t} endpoint={endpoint} onUpdate={(next) => updateEndpointAccess(index, next)} />
              </div>
            )) : <div className="empty-row">{props.t("no_endpoint", "No endpoint")}</div>}
          </div>
        </section>

        <section className="panel">
          <div className="panel-head">
            <h2>{props.t("device_access_leases", "Device access leases")}</h2>
          </div>
          <div className="grant-list">
            {arrayValue(props.deviceAccess?.leases).length ? arrayValue(props.deviceAccess?.leases).map((lease) => (
              <div className="grant-row" key={`${lease.ix}-${lease.device}-${lease.address}`}>
                <div className="grant-main">
                  <strong>{compactList([lease.device, lease.address], " / ")}</strong>
                  <span>{compactList([lease.ix, lease.endpoint, lease.transport, lease.encryption, arrayValue(lease.advertise_prefixes).join(", "), lease.expires_at ? formatTime(lease.expires_at, props.lang) : ""], " · ")}</span>
                </div>
                <Pill state={lease.online ? "ok" : "idle"}>{lease.online ? props.t("online", "Online") : props.t("offline", "Offline")}</Pill>
              </div>
            )) : <div className="empty-row">{props.t("no_device_lease", "No device lease")}</div>}
          </div>
        </section>
      </section>
    </main>
  );
}

export function NetworkView(props: {
  t: Translate;
  lang: string;
  status: StatusPayload | null;
  desired: DesiredConfig | null;
  transports: TransportMatrix | null;
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  selected: SelectedTopology;
  dirty: boolean;
  message: string;
  onSelect: (selection: SelectedTopology) => void;
  onDesired: (desired: DesiredConfig) => void;
  onValidate: () => void;
  onApply: () => void;
  onAddPeer: () => void;
  onAddRoute: (peerId?: string) => void;
  onTopologyRoute: (ownerId: string, nextHop: string) => void;
  onProbeEndpoint: (peerId: string, endpointName: string) => void;
  onProbeRoute: (destination: string, trace?: boolean) => void;
}) {
  const selectedNodeID = props.selected?.type === "node" ? props.selected.nodeId : "";
  const selectedEdgeID = props.selected?.type === "edge" ? props.selected.edgeId : "";
  const selectedNode = selectedNodeID ? props.nodes.find((node) => node.id === selectedNodeID) : null;
  const selectedEdge = selectedEdgeID ? props.edges.find((edge) => edge.id === selectedEdgeID) : null;
  return (
    <main className="views network-workspace">
      <section className="topology-layout">
        <div className="panel topology-panel">
          <div className="panel-head">
            <div>
              <h2>{props.t("network", "Network")}</h2>
              <p className="panel-note inline-note">{props.t("links_note", "Per-IX transport sessions, routes, and datapath health.")}</p>
            </div>
            <div className="inline-controls">
              <Pill state={props.dirty ? "warn" : "ok"}>{props.dirty ? props.t("unsaved_changes", "Unsaved changes") : props.t("saved", "Saved")}</Pill>
              <Button variant="ghost" onClick={props.onValidate}><Check size={15} />{props.t("validate", "Validate")}</Button>
              <Button onClick={props.onApply}><Save size={15} />{props.t("apply", "Apply")}</Button>
            </div>
          </div>
          <TransportPolicyStrip t={props.t} transports={props.transports} status={props.status} />
          <TopologyCanvas nodes={props.nodes} edges={props.edges} selected={props.selected} onSelect={props.onSelect} onAddRoute={props.onAddRoute} onTopologyRoute={props.onTopologyRoute} t={props.t} />
        </div>
        <TopologyInspector
          t={props.t}
          lang={props.lang}
          desired={props.desired}
          transports={props.transports}
          nodes={props.nodes}
          edges={props.edges}
          node={selectedNode}
          edge={selectedEdge}
          selected={props.selected}
          onSelect={props.onSelect}
          onDesired={props.onDesired}
          onAddPeer={props.onAddPeer}
          onAddRoute={props.onAddRoute}
          onProbeEndpoint={props.onProbeEndpoint}
          onProbeRoute={props.onProbeRoute}
        />
      </section>
      <section className="panel">
        <div className="panel-head">
          <h2>{props.t("links", "Links")}</h2>
          <span className="muted">{props.edges.length}</span>
        </div>
        <div className="link-list">
          {props.edges.map((edge) => (
            <button key={edge.id} type="button" className="link-row" onClick={() => props.onSelect({ type: "edge", edgeId: edge.id })}>
              <span><Pill state={edge.state}>{props.t(edge.state, edge.state)}</Pill></span>
              <strong>{edge.target}</strong>
              <span title={edge.transports.join(", ")}>{compactTransportList(edge.transports)}</span>
              <span>{edge.routes.map((route) => routeSummary(route)).filter(Boolean).join(", ") || "-"}</span>
              <span>{formatBytes(edge.link?.bytes_sent || 0, props.lang)} / {formatBytes(edge.link?.bytes_received || 0, props.lang)}</span>
            </button>
          ))}
        </div>
      </section>
    </main>
  );
}

function TransportPolicyStrip(props: { t: Translate; transports: TransportMatrix | null; status: StatusPayload | null }) {
  const policy = props.transports?.policy || {};
  const kernel = props.transports?.kernel_transport || props.status?.data_path?.kernel_transport;
  const active = props.transports?.sessions?.length ?? props.status?.data_path?.active_sessions ?? 0;
  return (
    <div className="transport-strip">
      <SummaryItem label={props.t("transport_policy", "Transport policy")} value={compactList([policy.mode, policy.profile, policy.datapath, policy.kernel_transport, policy.crypto_placement], "-")} />
      <SummaryItem label={props.t("session_pool", "Session pool")} value={compactList([policy.session_pool_size ? String(policy.session_pool_size) : "", policy.session_pool_strategy, policy.session_pool_warmup ? props.t("warmup", "Warmup") : ""], "-")} />
      <SummaryItem label={props.t("kernel_transport", "Kernel transport")} value={compactList([kernel?.mode, kernel?.provider, kernel?.available ? props.t("available", "Available") : ""], "-")} />
      <SummaryItem label={props.t("active_sessions", "Active sessions")} value={String(active || 0)} />
    </div>
  );
}

function TopologyCanvas(props: {
  t: Translate;
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  selected: SelectedTopology;
  onSelect: (selection: SelectedTopology) => void;
  onAddRoute: (peerId?: string) => void;
  onTopologyRoute: (ownerId: string, nextHop: string) => void;
}) {
  const selectedNode = props.selected?.type === "node" ? props.selected.nodeId : "";
  const selectedEdge = props.selected?.type === "edge" ? props.selected.edgeId : "";
  const [view, setView] = useState({ x: 0, y: 0, scale: 1 });
  const [interaction, setInteraction] = useState<
    | { kind: "node"; id: string; startClientX: number; startClientY: number; originX: number; originY: number }
    | { kind: "pan"; startClientX: number; startClientY: number; originX: number; originY: number }
    | null
  >(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const suppressContextMenuRef = useRef(false);
  const [nodePositions, setNodePositions] = useState<Record<string, { x: number; y: number }>>({});
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; nodeId?: string; edgeId?: string } | null>(null);
  const [routeDrag, setRouteDrag] = useState<{ sourceId: string; x: number; y: number } | null>(null);
  const positionedNodes = useMemo(() => props.nodes.map((node) => ({ ...node, ...(nodePositions[node.id] || {}) })), [props.nodes, nodePositions]);
  useEffect(() => {
    if (!contextMenu) {
      return;
    }
    const close = () => setContextMenu(null);
    window.addEventListener("pointerdown", close);
    window.addEventListener("keydown", close);
    window.addEventListener("resize", close);
    return () => {
      window.removeEventListener("pointerdown", close);
      window.removeEventListener("keydown", close);
      window.removeEventListener("resize", close);
    };
  }, [contextMenu]);
  const toCanvas = (event: { currentTarget: EventTarget & Element; clientX: number; clientY: number }) => {
    const element = event.currentTarget;
    const svg = element instanceof SVGSVGElement
      ? element
      : element instanceof SVGElement
        ? element.ownerSVGElement
        : null;
    if (svg) {
      const matrix = svg.getScreenCTM()?.inverse();
      if (matrix) {
        const point = svg.createSVGPoint();
        point.x = event.clientX;
        point.y = event.clientY;
        const transformed = point.matrixTransform(matrix);
        return { x: transformed.x, y: transformed.y };
      }
    }
    const rect = (svg || element).getBoundingClientRect();
    return {
      x: ((event.clientX - rect.left) / rect.width) * 840,
      y: ((event.clientY - rect.top) / rect.height) * 520,
    };
  };
  const toWorld = (event: { currentTarget: EventTarget & Element; clientX: number; clientY: number }) => {
    const point = toCanvas(event);
    return {
      x: (point.x - view.x) / view.scale,
      y: (point.y - view.y) / view.scale,
    };
  };
  const screenDeltaToWorld = (startClientX: number, startClientY: number, clientX: number, clientY: number) => {
    const svg = svgRef.current;
    if (!svg) {
      return { dx: clientX - startClientX, dy: clientY - startClientY };
    }
    const start = toCanvas({ currentTarget: svg, clientX: startClientX, clientY: startClientY });
    const current = toCanvas({ currentTarget: svg, clientX, clientY });
    return { dx: current.x - start.x, dy: current.y - start.y };
  };
  const zoomAt = (point: { x: number; y: number }, factor: number) => {
    setView((current) => {
      const nextScale = Math.max(0.35, Math.min(4, current.scale * factor));
      const worldX = (point.x - current.x) / current.scale;
      const worldY = (point.y - current.y) / current.scale;
      return {
        x: point.x - worldX * nextScale,
        y: point.y - worldY * nextScale,
        scale: nextScale,
      };
    });
  };
  const beginPan = (event: PointerEvent<SVGSVGElement>) => {
    setContextMenu(null);
    if (event.button !== 0) {
      return;
    }
    const target = event.target;
    if (target instanceof Element && target.closest(".topology-node, .topology-edge")) {
      return;
    }
    event.currentTarget.setPointerCapture(event.pointerId);
    setInteraction({ kind: "pan", startClientX: event.clientX, startClientY: event.clientY, originX: view.x, originY: view.y });
  };
  const beginNodeDrag = (event: PointerEvent<SVGGElement>, node: TopologyNode) => {
    event.stopPropagation();
    setContextMenu(null);
    if (event.button !== 0) {
      return;
    }
    event.currentTarget.setPointerCapture(event.pointerId);
    setInteraction({ kind: "node", id: node.id, startClientX: event.clientX, startClientY: event.clientY, originX: node.x, originY: node.y });
    props.onSelect({ type: "node", nodeId: node.id });
  };
  const handleWheel = (event: WheelEvent<SVGSVGElement>) => {
    const svg = svgRef.current;
    if (!svg || event.currentTarget !== svg) {
      return;
    }
    setContextMenu(null);
    event.preventDefault();
    event.stopPropagation();
    zoomAt(toCanvas({ currentTarget: svg, clientX: event.clientX, clientY: event.clientY }), Math.exp(-event.deltaY * 0.001));
  };
  const moveDrag = (event: PointerEvent<SVGSVGElement>) => {
    if (routeDrag) {
      event.preventDefault();
      const point = toWorld({ currentTarget: event.currentTarget, clientX: event.clientX, clientY: event.clientY });
      setRouteDrag((current) => current ? { ...current, x: point.x, y: point.y } : null);
      return;
    }
    if (!interaction) {
      return;
    }
    const delta = screenDeltaToWorld(interaction.startClientX, interaction.startClientY, event.clientX, event.clientY);
    if (interaction.kind === "pan") {
      setView((current) => ({ ...current, x: interaction.originX + delta.dx, y: interaction.originY + delta.dy }));
      return;
    }
    setNodePositions((current) => ({
      ...current,
      [interaction.id]: {
        x: interaction.originX + delta.dx / view.scale,
        y: interaction.originY + delta.dy / view.scale,
      },
    }));
  };
  const endPointer = (event: PointerEvent<SVGSVGElement>) => {
    if (routeDrag) {
      event.preventDefault();
      const target = document.elementFromPoint(event.clientX, event.clientY);
      const targetNode = target instanceof Element ? target.closest<SVGGElement>(".topology-node") : null;
      const targetId = targetNode?.dataset.nodeId || "";
      if (targetId && targetId !== routeDrag.sourceId) {
        props.onTopologyRoute(routeDrag.sourceId, targetId);
        props.onSelect({ type: "node", nodeId: routeDrag.sourceId });
      }
      suppressContextMenuRef.current = true;
      setRouteDrag(null);
    }
    setInteraction(null);
  };
  const handleContextMenu = (event: MouseEvent<SVGSVGElement>) => {
    event.preventDefault();
    if (suppressContextMenuRef.current) {
      suppressContextMenuRef.current = false;
      return;
    }
    const target = event.target;
    const node = target instanceof Element ? target.closest<SVGGElement>(".topology-node") : null;
    const edge = target instanceof Element ? target.closest<SVGGElement>(".topology-edge") : null;
    const rect = event.currentTarget.getBoundingClientRect();
    const nodeId = node?.dataset.nodeId || "";
    const edgeId = edge?.dataset.edgeId || "";
    if (nodeId) {
      props.onSelect({ type: "node", nodeId });
    } else if (edgeId) {
      props.onSelect({ type: "edge", edgeId });
    }
    const menuWidth = 168;
    const menuHeight = nodeId || edgeId ? 76 : 44;
    setContextMenu({
      x: Math.max(8, Math.min(event.clientX - rect.left, rect.width - menuWidth - 8)),
      y: Math.max(8, Math.min(event.clientY - rect.top, rect.height - menuHeight - 8)),
      nodeId,
      edgeId,
    });
  };
  const zoomCanvasCenter = (factor: number) => zoomAt({ x: 420, y: 260 }, factor);
  const routeDragSource = routeDrag ? positionedNodes.find((node) => node.id === routeDrag.sourceId) : null;
  return (
    <div className="topology-canvas">
      <div className="canvas-tools">
        <IconButton title={props.t("zoom_in", "Zoom in")} onClick={() => zoomCanvasCenter(1.18)}><ZoomIn size={15} /></IconButton>
        <IconButton title={props.t("zoom_out", "Zoom out")} onClick={() => zoomCanvasCenter(0.84)}><ZoomOut size={15} /></IconButton>
        <IconButton title={props.t("reset", "Reset")} onClick={() => { setView({ x: 0, y: 0, scale: 1 }); setNodePositions({}); }}><Move size={15} /></IconButton>
      </div>
      <svg ref={svgRef} className={`topology-svg ${interaction?.kind === "pan" ? "is-panning" : ""}`} viewBox="0 0 840 520" role="img" aria-label={props.t("network", "Network")} onWheel={handleWheel} onContextMenu={handleContextMenu} onPointerDown={beginPan} onPointerMove={moveDrag} onPointerUp={endPointer} onPointerCancel={endPointer}>
        <defs>
          <marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
            <path d="M 0 0 L 8 4 L 0 8 z" />
          </marker>
        </defs>
        <g transform={`translate(${view.x} ${view.y}) scale(${view.scale})`}>
        {props.edges.map((edge) => {
          const mid = edgeMidpoint(positionedNodes, edge);
          return (
            <g key={edge.id} data-edge-id={edge.id} className={`topology-edge ${edge.state} ${selectedEdge === edge.id ? "is-selected" : ""}`} onClick={() => props.onSelect({ type: "edge", edgeId: edge.id })}>
              <path d={edgePath(positionedNodes, edge)} markerEnd="url(#arrow)" />
              <rect x={mid.x - 76} y={mid.y - 15} width="152" height="30" rx="6" />
              <text x={mid.x} y={mid.y + 4}>{edgeTransportLabel(edge, props.t)}</text>
            </g>
          );
        })}
        {positionedNodes.map((node) => (
          <g key={node.id} data-node-id={node.id} className={`topology-node ${node.state} ${node.local ? "is-local" : ""} ${selectedNode === node.id ? "is-selected" : ""}`} transform={`translate(${node.x} ${node.y})`} onPointerDown={(event) => beginNodeDrag(event, node)} onClick={() => props.onSelect({ type: "node", nodeId: node.id })}>
            <circle r={node.local ? 54 : 42} />
            <text className="node-title" y="-4">{node.label}</text>
            <text className="node-subtitle" y="17">{node.local ? "local" : props.t(node.state, node.state)}</text>
          </g>
        ))}
        {routeDrag && routeDragSource && (
          <path className="topology-route-draft" d={`M ${routeDragSource.x} ${routeDragSource.y} L ${routeDrag.x} ${routeDrag.y}`} />
        )}
        </g>
      </svg>
      {contextMenu && (
        <div className="topology-context-menu" style={{ left: contextMenu.x, top: contextMenu.y }} onPointerDown={(event) => event.stopPropagation()} onContextMenu={(event) => event.preventDefault()}>
          {contextMenu.nodeId ? (
            <>
              <button type="button" onClick={() => { props.onSelect({ type: "node", nodeId: contextMenu.nodeId || "" }); setContextMenu(null); }}>{props.t("open_details", "Open details")}</button>
              <button type="button" onClick={() => { props.onAddRoute(contextMenu.nodeId || undefined); setContextMenu(null); }}>{props.t("add_route", "Add route")}</button>
            </>
          ) : contextMenu.edgeId ? (
            <>
              <button type="button" onClick={() => { props.onSelect({ type: "edge", edgeId: contextMenu.edgeId || "" }); setContextMenu(null); }}>{props.t("open_details", "Open details")}</button>
              <button type="button" onClick={() => { const edge = props.edges.find((item) => item.id === contextMenu.edgeId); props.onAddRoute(edge?.target); setContextMenu(null); }}>{props.t("add_route", "Add route")}</button>
            </>
          ) : (
            <button type="button" onClick={() => setContextMenu(null)}>{props.t("close", "Close")}</button>
          )}
        </div>
      )}
    </div>
  );
}

function TopologyInspector(props: {
  t: Translate;
  lang: string;
  desired: DesiredConfig | null;
  transports: TransportMatrix | null;
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  node: TopologyNode | null | undefined;
  edge: TopologyEdge | null | undefined;
  selected: SelectedTopology;
  onSelect: (selection: SelectedTopology) => void;
  onDesired: (desired: DesiredConfig) => void;
  onAddPeer: () => void;
  onAddRoute: (peerId?: string) => void;
  onProbeEndpoint: (peerId: string, endpointName: string) => void;
  onProbeRoute: (destination: string, trace?: boolean) => void;
}) {
  const cfg = props.desired;
  const selectedRouteIndex = props.selected?.type === "route" ? props.selected.index : -1;
  const backToPeer = (peerId: string) => {
    const edge = props.edges.find((item) => item.target === peerId);
    props.onSelect(edge ? { type: "edge", edgeId: edge.id } : { type: "node", nodeId: peerId });
  };
  const backFromRoute = (routeIndex: number) => {
    const route = arrayValue(cfg?.routes)[routeIndex];
    if (route?.next_hop) {
      backToPeer(route.next_hop);
      return;
    }
    props.onSelect(null);
  };
  return (
    <aside className="panel inspector">
      <div className="panel-head">
        <h2>{props.t("details", "Details")}</h2>
        <div className="inline-controls">
          <Button variant="ghost" onClick={props.onAddPeer} title={props.t("add_static_peer_note", "Create a static peer entry in desired config; dynamic IX members still come from membership admission.")}>
            <Plus size={15} />{props.t("add_peer", "Add static peer")}
          </Button>
        </div>
      </div>
      {!cfg && <div className="muted">{props.t("loading", "Loading")}</div>}
      {cfg && props.node && <NodeEditor t={props.t} node={props.node} desired={cfg} onDesired={props.onDesired} onAddRoute={props.onAddRoute} />}
      {cfg && props.edge && <EdgeEditor t={props.t} lang={props.lang} edge={props.edge} desired={cfg} transports={props.transports} onSelect={props.onSelect} onDesired={props.onDesired} onAddRoute={props.onAddRoute} onProbeEndpoint={props.onProbeEndpoint} />}
      {cfg && selectedRouteIndex >= 0 && <RouteEditor t={props.t} desired={cfg} nodes={props.nodes} links={props.edges.map((edge) => edge.link).filter((link): link is LinkStatus => Boolean(link))} index={selectedRouteIndex} onBack={() => backFromRoute(selectedRouteIndex)} onDesired={props.onDesired} onProbeRoute={props.onProbeRoute} />}
      {cfg && !props.node && !props.edge && selectedRouteIndex < 0 && (
        <div className="empty-inspector">
          <Network size={24} />
          <p>{props.t("network", "Network")}</p>
          <span className="muted">{props.t("select_node_or_link", "Select a node or link")}</span>
        </div>
      )}
    </aside>
  );
}

function NodeEditor(props: { t: Translate; node: TopologyNode; desired: DesiredConfig; onDesired: (desired: DesiredConfig) => void; onAddRoute: (peerId?: string) => void }) {
  const cfg = props.desired;
  const peerIndex = arrayValue(cfg.peers).findIndex((peer) => peer.id === props.node.id);
  const peer = peerIndex >= 0 ? cfg.peers![peerIndex] : null;
  if (props.node.local) {
    return (
      <div className="inspector-stack">
        <h3>{props.node.label}</h3>
        <Field label={props.t("domain_id", "Domain ID")} help={props.t("help_domain_id", "Domain identifier shared by IX nodes that belong to the same TrustIX domain.")} value={cfg.domain?.id || ""} onChange={(value) => props.onDesired({ ...cfg, domain: { ...(cfg.domain || {}), id: value } })} />
        <Field label={props.t("ix_id", "IX ID")} help={props.t("help_ix_id", "Unique name of this IX node inside the domain. Peers and routes use this value as the next hop.")} value={cfg.ix?.id || ""} onChange={(value) => props.onDesired({ ...cfg, ix: { ...(cfg.ix || {}), id: value } })} />
        <Field label={props.t("control_api", "Control API")} help={props.t("help_ix_control_api", "URL other IX nodes use to call this node's control API, usually https://host:port.")} value={cfg.ix?.control_api || ""} onChange={(value) => props.onDesired({ ...cfg, ix: { ...(cfg.ix || {}), control_api: value } })} />
        <SelectField label={props.t("control_api_publish", "Control API publish")} help={props.t("help_ix_control_api_publish", "auto publishes ix.control_api or falls back to the peer API listen address. disabled is for edge IX nodes without public inbound control-plane access.")} value={cfg.ix?.control_api_publish || ""} options={["", "disabled"]} optionLabels={{ "": props.t("auto", "Auto"), disabled: props.t("disabled", "Disabled") }} onChange={(value) => props.onDesired({ ...cfg, ix: { ...(cfg.ix || {}), control_api_publish: value || undefined } })} />
        <Field label={props.t("advertise_prefixes", "Advertise prefixes")} help={props.t("help_lan_advertise", "CIDR prefixes this IX announces to other IX nodes, one prefix per line.")} textarea value={joinLines(localAdvertisePrefixes(cfg))} onChange={(value) => props.onDesired({ ...cfg, lan: { ...(cfg.lan || {}), advertise: splitLines(value) } })} />
        <div className="detail-grid">
          <span>{props.t("transport_policy", "Transport policy")}</span><strong>{compactList([cfg.transport_policy?.mode, cfg.transport_policy?.profile, cfg.transport_policy?.datapath, cfg.transport_policy?.kernel_transport?.mode, cfg.transport_policy?.crypto_placement], "-")}</strong>
          <span>{props.t("session_pool", "Session pool")}</span><strong>{compactList([cfg.transport_policy?.session_pool?.size ? String(cfg.transport_policy.session_pool.size) : "", cfg.transport_policy?.session_pool?.strategy], "-")}</strong>
        </div>
      </div>
    );
  }
  if (!peer) {
    return (
      <div className="inspector-stack">
        <h3>{props.node.label}</h3>
        <Pill state={props.node.state}>{props.t(props.node.state, props.node.state)}</Pill>
        <p className="muted">{props.t("dynamic", "Dynamic")} / session-only peer</p>
      </div>
    );
  }
  return <PeerEditor t={props.t} desired={cfg} peer={peer} peerIndex={peerIndex} onDesired={props.onDesired} onAddRoute={props.onAddRoute} />;
}

function PeerEditor(props: { t: Translate; desired: DesiredConfig; peer: PeerConfig; peerIndex: number; onDesired: (desired: DesiredConfig) => void; onAddRoute: (peerId?: string) => void }) {
  const updatePeer = (next: PeerConfig) => {
    const peers = [...arrayValue(props.desired.peers)];
    peers[props.peerIndex] = next;
    props.onDesired({ ...props.desired, peers });
  };
  const removePeer = () => {
    const peers = arrayValue(props.desired.peers).filter((_, index) => index !== props.peerIndex);
    const routes = arrayValue(props.desired.routes).filter((route) => route.next_hop !== props.peer.id && route.owner !== props.peer.id);
    props.onDesired({ ...props.desired, peers, routes });
  };
  return (
    <div className="inspector-stack">
      <h3>{props.peer.id || props.t("peer", "Peer")}</h3>
      <Field label={props.t("ix", "IX")} help={props.t("help_peer_ix", "Static peer IX ID. Dynamic admitted IX members do not need to be duplicated here.")} value={props.peer.id || ""} onChange={(value) => updatePeer({ ...props.peer, id: value })} />
      <Field label={props.t("domain", "Domain")} help={props.t("help_peer_domain", "Peer domain ID. Leave aligned with the local domain for same-domain IX peers.")} value={props.peer.domain || ""} onChange={(value) => updatePeer({ ...props.peer, domain: value })} />
      <Field label={props.t("control_api", "Control API")} help={props.t("help_peer_control_api", "Peer control API URL used for config sync and membership exchange.")} value={props.peer.control_api || ""} onChange={(value) => updatePeer({ ...props.peer, control_api: value })} />
      <Field label={props.t("allowed_prefixes", "Allowed prefixes")} help={props.t("help_peer_allowed_prefixes", "Static prefixes this peer is allowed to advertise. Admission route authorizations are preferred for dynamic IX members.")} textarea value={joinLines(props.peer.allowed_prefixes)} onChange={(value) => updatePeer({ ...props.peer, allowed_prefixes: splitLines(value) })} />
      <div className="inline-controls">
        <Button variant="ghost" onClick={() => props.onAddRoute(props.peer.id)}><Route size={15} />{props.t("add_route", "Add route")}</Button>
        <Button variant="danger" onClick={removePeer}><Trash2 size={15} />{props.t("remove", "Remove")}</Button>
      </div>
    </div>
  );
}

function EdgeEditor(props: { t: Translate; lang: string; edge: TopologyEdge; desired: DesiredConfig; transports: TransportMatrix | null; onSelect: (selection: SelectedTopology) => void; onDesired: (desired: DesiredConfig) => void; onAddRoute: (peerId?: string) => void; onProbeEndpoint: (peerId: string, endpointName: string) => void }) {
  const peer = arrayValue(props.desired.peers).find((item) => item.id === props.edge.target);
  const staticEndpointList = arrayValue(peer?.endpoints);
  const localEndpoints = arrayValue(props.desired.endpoints);
  const peers = arrayValue(props.desired.peers);
  const routePeers = routePeerOptions(props.desired, undefined, props.edge.link ? [props.edge.link] : []);
  const policy = props.transports?.policy || {};
  const sessions = arrayValue(props.edge.link?.sessions).length ? arrayValue(props.edge.link?.sessions) : arrayValue(props.transports?.sessions).filter((session) => session.peer === props.edge.target);
  const runtimePeerEndpoints = arrayValue(props.transports?.peer_endpoints).filter((endpoint) => endpoint.peer === props.edge.target);
  const endpointList = mergedPeerEndpointList(staticEndpointList, runtimePeerEndpoints, props.edge.endpoints);
  const selectableEndpoints = endpointList.length ? endpointList : props.edge.endpoints;
  const routeIndexes = arrayValue(props.desired.routes)
    .map((route, index) => ({ route, index }))
    .filter(({ route }) => route.next_hop === props.edge.target || route.owner === props.edge.target);
  const runtimeEdgeRoutes = props.edge.routes
    .map((route) => routeWithEdgeNextHop(route, props.edge.target))
    .filter((route) => !routeIndexes.some((item) => routesMatch(item.route, route)));
  const updateLocalEndpoints = (nextEndpoints: EndpointConfig[]) => {
    props.onDesired({ ...props.desired, endpoints: nextEndpoints });
  };
  const setRouteEndpoint = (routeIndex: number, endpointName: string) => {
    const routes = [...arrayValue(props.desired.routes)];
    routes[routeIndex] = { ...routes[routeIndex], endpoint: endpointName };
    props.onDesired({ ...props.desired, routes });
  };
  const setRouteNextHop = (routeIndex: number, nextHop: string) => {
    const routes = [...arrayValue(props.desired.routes)];
    const route = routes[routeIndex] || {};
    const targetPeer = peers.find((item) => item.id === nextHop);
    const targetLink = props.edge.link?.peer === nextHop ? props.edge.link : undefined;
    const targetEndpoints = targetPeer
      ? peerEndpointCandidates(targetPeer, props.transports, props.edge.link ? [props.edge.link] : [])
      : arrayValue(targetLink?.endpoints);
    routes[routeIndex] = {
      ...route,
      owner: route.owner || props.edge.target || nextHop,
      next_hop: nextHop,
      endpoint: nextHop === route.next_hop ? route.endpoint : "",
    };
    if (!nextHop) {
      routes[routeIndex].endpoint = "";
    } else if (route.endpoint && !targetEndpoints.some((endpoint) => endpoint.name === route.endpoint)) {
      routes[routeIndex].endpoint = "";
    }
    props.onDesired({ ...props.desired, routes });
  };
  const promoteRoute = (route: RouteView) => {
    const promoted = promoteRuntimeRouteInDesired(props.desired, route);
    props.onDesired(promoted.desired);
    props.onSelect({ type: "route", index: promoted.index });
  };
  return (
    <div className="inspector-stack">
      <h3>{props.edge.source} {"->"} {props.edge.target}</h3>
      <div className="detail-grid">
        <span>{props.t("status", "Status")}</span><Pill state={props.edge.state}>{props.t(props.edge.state, props.edge.state)}</Pill>
        <span>{props.t("sessions", "Sessions")}</span><strong>{formatNumber(props.edge.link?.active_sessions || 0, props.lang)}</strong>
        <span>{props.t("traffic", "Traffic")}</span><strong>{formatBytes(props.edge.link?.bytes_sent || 0, props.lang)} / {formatBytes(props.edge.link?.bytes_received || 0, props.lang)}</strong>
        <span>{props.t("transports", "Transports")}</span><strong title={props.edge.transports.join(", ") || "-"}>{compactTransportList(props.edge.transports)}</strong>
        <span>{props.t("policy", "Policy")}</span><strong>{compactList([policy.mode, policy.profile, policy.datapath, policy.kernel_transport, policy.session_pool_size ? `${policy.session_pool_size} pool` : "", policy.session_pool_strategy, policy.session_pool_warmup ? props.t("warmup", "Warmup") : ""], "-")}</strong>
      </div>
      <div className="active-transport-strip">
        <SummaryItem label={props.t("current_transport", "Current transport")} value={compactList([sessions[0]?.transport, sessions[0]?.endpoint, sessions[0]?.stats?.crypto_placement], "-")} />
        <SummaryItem label={props.t("profile", "Profile")} value={compactList([policy.profile, policy.datapath], "-")} />
        <SummaryItem label={props.t("session_pool", "Session pool")} value={compactList([policy.session_pool_size ? String(policy.session_pool_size) : "", policy.session_pool_strategy, policy.session_pool_warmup ? props.t("warmup", "Warmup") : ""], "-")} />
      </div>
      <div className="runtime-cards">
        {sessions.length ? sessions.map((session, index) => (
          <div className="runtime-card" key={`${session.endpoint}-${session.pool_index}-${index}`}>
            <strong>{session.transport || "-"} · {session.endpoint || "-"}</strong>
            <span>{compactList([session.direction, session.address, session.pool_index != null ? `pool ${session.pool_index}` : ""], "-")}</span>
            <span>{formatBytes(session.stats?.bytes_sent || 0, props.lang)} / {formatBytes(session.stats?.bytes_received || 0, props.lang)} · {session.stats?.crypto_placement || "-"}</span>
          </div>
        )) : (
          <div className="runtime-card">
            <strong>{props.t("runtime", "Runtime")}</strong>
            <span>{props.t("idle", "Idle")} · {props.t("no_active_sessions", "No active transport sessions")}</span>
            <span>{runtimePeerEndpoints.filter((endpoint) => endpoint.usable).length}/{runtimePeerEndpoints.length || endpointList.length} {props.t("usable", "Usable")}</span>
          </div>
        )}
      </div>
      <div className="subhead">
        <strong>{props.t("peer_endpoints", "Peer endpoints")}</strong>
        <span className="readonly-note">{props.t("learned_readonly", "Learned from peer advertisements")}</span>
      </div>
      <div className="item-list">
        {endpointList.map((endpoint, index) => {
          const runtime = runtimePeerEndpoints.find((item) => item.name === endpoint.name) || {};
          const linkRuntime = props.edge.endpoints.find((item) => item.name === endpoint.name) || {};
          const staticIndex = staticEndpointList.findIndex((item) => item.name === endpoint.name);
          const dynamicEndpoint = staticIndex < 0;
          const activeSessions = linkRuntime.active_sessions ?? runtime.active_reverse_sessions;
          const currentFlows = linkRuntime.current_flows;
          const rtt = linkRuntime.rtt ?? runtime.rtt;
          const profile = compactList([runtime.profile || linkRuntime.profile || endpoint.transport_profile?.profile, runtime.datapath || linkRuntime.datapath || endpoint.transport_profile?.datapath, (arrayValue(runtime.features).length ? arrayValue(runtime.features) : arrayValue(linkRuntime.features)).join("/")], "");
          const capability = compactList([(runtime.usable ?? linkRuntime.usable) ? props.t("usable", "Usable") : props.t("not_usable", "Not usable"), (runtime.kernel_compatible ?? linkRuntime.kernel_compatible) === false ? "no-kernel" : "kernel", (runtime.profile_compatible ?? linkRuntime.profile_compatible) === false ? "profile-mismatch" : (runtime.profile_compatible ?? linkRuntime.profile_compatible) === true ? "profile-ok" : "", runtime.encryption || linkRuntime.encryption || endpoint.security?.encryption, profile, arrayValue(runtime.crypto_placements).length ? arrayValue(runtime.crypto_placements).join("/") : arrayValue(linkRuntime.crypto_placements).join("/")], "-");
          const traffic = compactList([activeSessions != null ? `${activeSessions} ${props.t("sessions", "Sessions")}` : "", currentFlows != null ? `${currentFlows} ${props.t("flows", "Flows")}` : "", linkRuntime.health, rtt ? `rtt ${formatDurationNanos(rtt, props.lang)}` : ""], "-");
          const meta = compactList([endpoint.transport, endpoint.priority ? `prio ${endpoint.priority}` : "", capability, traffic], "-");
          const source = dynamicEndpoint ? props.t("negotiated", "Negotiated") : props.t("static", "Static");
          return (
            <div key={`${endpoint.name}-${index}`} className={`endpoint-row ${dynamicEndpoint ? "is-runtime" : ""}`}>
              <div className="endpoint-main">
                <strong>{endpoint.name || "-"}</strong>
                <span title={meta}>{meta}</span>
              </div>
              <div className="endpoint-controls">
                <div className="endpoint-badges">
                  <span className="readonly-chip">{source}</span>
                  <span className={`readonly-chip ${endpoint.enabled === false ? "is-muted" : ""}`}>{endpoint.enabled === false ? props.t("disabled", "Disabled") : props.t("enabled", "Enabled")}</span>
                </div>
                <button
                  type="button"
                  className={`endpoint-actions ${endpoint.name ? "" : "is-disabled"}`}
                  disabled={!endpoint.name}
                  onClick={() => {
                    if (endpoint.name) {
                      props.onProbeEndpoint(props.edge.target, endpoint.name);
                    }
                  }}
                >
                  <Check size={15} />{props.t("test", "Test")}
                </button>
              </div>
            </div>
          );
        })}
      </div>
      <div className="subhead">
        <strong>{props.t("endpoint_publish_to_peer", "Publish local endpoints")}</strong>
      </div>
      <LocalEndpointPublishList
        t={props.t}
        peerId={props.edge.target}
        endpoints={localEndpoints}
        onUpdate={updateLocalEndpoints}
      />
      <div className="subhead">
        <strong>{props.t("routes", "Routes")}</strong>
        <Button variant="ghost" onClick={() => props.onAddRoute(props.edge.target)}><Plus size={15} />{props.t("add_route", "Add route")}</Button>
      </div>
      <div className="item-list">
        {routeIndexes.map(({ route, index }) => {
          const nextHopPeer = peers.find((item) => item.id === route.next_hop);
          const routeEndpointOptions = route.next_hop === props.edge.target
            ? selectableEndpoints
            : peerEndpointCandidates(nextHopPeer, props.transports, props.edge.link ? [props.edge.link] : []);
          return (
            <div key={`${route.prefix}-${index}`} className="route-inline-row">
              <button type="button" className="route-inline-main" onClick={() => props.onSelect({ type: "route", index })}>
                <strong>{route.prefix || "-"}</strong>
                <span>{compactList([route.owner ? `${props.t("owner", "Owner")} ${route.owner}` : "", route.next_hop ? `${props.t("via", "Via")} ${route.next_hop}` : "", route.kind || "unicast", route.metric != null ? `metric ${route.metric}` : ""], "-")}</span>
              </button>
              <select className="inline-select" title={props.t("help_route_next_hop", "IX ID that should receive traffic for this prefix.")} aria-label={props.t("next_hop", "Next hop")} value={route.next_hop || ""} onChange={(event) => setRouteNextHop(index, event.currentTarget.value)}>
                <option value="">{props.t("none", "None")}</option>
                {routePeers.map((id) => <option key={id} value={id}>{id}</option>)}
              </select>
              <select className="inline-select" title={props.t("help_route_endpoint", "Preferred endpoint for this route. Empty lets transport policy choose among usable endpoints.")} aria-label={props.t("endpoint", "Endpoint")} value={route.endpoint || ""} onChange={(event) => setRouteEndpoint(index, event.currentTarget.value)}>
                <option value="">{props.t("auto", "Auto")}</option>
                {routeEndpointOptions.map((endpoint) => <option key={endpoint.name || ""} value={endpoint.name || ""}>{compactList([endpoint.name, endpoint.transport], "-")}</option>)}
              </select>
            </div>
          );
        })}
        {runtimeEdgeRoutes.map((route, index) => {
          const targetIndex = staticRouteTargetIndex(arrayValue(props.desired.routes), route);
          const promotable = runtimeRoutePromotable(route);
          const canOpenRoute = promotable || targetIndex >= 0;
          const openRoute = () => {
            if (promotable) {
              promoteRoute(route);
              return;
            }
            if (targetIndex >= 0) {
              props.onSelect({ type: "route", index: targetIndex });
            }
          };
          return (
            <div key={`runtime-${route.prefix}-${route.owner}-${route.next_hop}-${index}`} className="route-inline-row route-inline-runtime-row">
              <button
                type="button"
                className="route-inline-main"
                title={canOpenRoute ? props.t("help_promote_runtime_route", "Copy this learned runtime route into desired static routes, then edit and apply it.") : routeSummary(route)}
                disabled={!canOpenRoute}
                onClick={openRoute}
              >
                <strong>{route.prefix || "-"}</strong>
                <span>{routeSummary(route)}</span>
              </button>
              {promotable ? (
                <Button variant="ghost" title={props.t("help_promote_runtime_route", "Copy this learned runtime route into desired static routes, then edit and apply it.")} onClick={openRoute}>
                  <Plus size={15} />{targetIndex >= 0 ? props.t("update_static_route", "Update static") : props.t("promote_to_static", "Make static")}
                </Button>
              ) : (
                <span className="readonly-chip">{props.t("runtime", "Runtime")}</span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function LocalEndpointPublishList(props: { t: Translate; peerId: string; endpoints: EndpointConfig[]; onUpdate: (endpoints: EndpointConfig[]) => void }) {
  const updateEndpoint = (index: number, next: EndpointConfig) => {
    const endpoints = [...props.endpoints];
    endpoints[index] = next;
    props.onUpdate(endpoints);
  };
  if (!props.endpoints.length) {
    return <div className="muted">{props.t("no_endpoint", "No endpoint")}</div>;
  }
  return (
    <div className="publish-list">
      {props.endpoints.map((endpoint, index) => {
        const state = endpointPublishStateForPeer(endpoint, props.peerId);
        return (
          <div className="publish-row" key={`${endpoint.name}-${index}`}>
            <div className="publish-main">
              <strong>{endpoint.name || "-"}</strong>
              <span>{compactList([endpoint.transport, endpoint.security?.encryption, state.label], "-")}</span>
            </div>
            <div className="publish-controls">
              <label className="mini-toggle" title={props.t("help_endpoint_publish_to_peer", "Controls whether this local endpoint is advertised to the selected IX peer.")}>
                <input type="checkbox" checked={state.published} onChange={(event) => updateEndpoint(index, setEndpointPublishedForPeer(endpoint, props.peerId, event.currentTarget.checked))} />
                <span>{state.published ? props.t("published", "Published") : props.t("hidden", "Hidden")}</span>
                <small aria-label={props.t("help_endpoint_publish_to_peer", "Controls whether this local endpoint is advertised to the selected IX peer.")}>?</small>
              </label>
              <select className="inline-select" title={props.t("help_endpoint_publish_mode", "Choose whether the publish setting inherits the global policy, applies only to this IX, hides from this IX, or disables publishing.")} aria-label={props.t("endpoint_publish_to_peer", "Publish local endpoints")} value={state.mode} onChange={(event) => updateEndpoint(index, setEndpointPublishModeForPeer(endpoint, props.peerId, event.currentTarget.value))}>
                <option value="inherit">{props.t("publish_inherit", "Inherit")}</option>
                <option value="only">{props.t("publish_only_this_peer", "Only this IX")}</option>
                <option value="except">{props.t("publish_hide_this_peer", "Hide from this IX")}</option>
                <option value="disabled">{props.t("disabled", "Disabled")}</option>
              </select>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function routeSummary(route: RouteConfig & { source?: string }): string {
  return compactList([
    route.prefix || "",
    route.owner ? `owner ${route.owner}` : "",
    route.next_hop ? `via ${route.next_hop}` : "",
    route.source || route.kind || "",
  ], " ");
}

function routesMatch(a: RouteConfig, b: RouteConfig): boolean {
  return (a.prefix || "") === (b.prefix || "") &&
    (a.owner || "") === (b.owner || "") &&
    (a.next_hop || "") === (b.next_hop || "") &&
    (a.endpoint || "") === (b.endpoint || "");
}

function routeWithEdgeNextHop(route: RouteView, edgeTarget: string): RouteView {
  if (route.next_hop || !edgeTarget) {
    return route;
  }
  return {
    ...route,
    owner: route.owner || edgeTarget,
    next_hop: edgeTarget,
  };
}

function runtimeRoutePromotable(route: RouteView): boolean {
  const source = String(route.source || "").trim();
  if (!route.prefix || !route.next_hop || route.kind === "local") {
    return false;
  }
  if (["static", "local_lan", "management_vip", "device_access"].includes(source)) {
    return false;
  }
  return source === "dynamic" || source === "dynamic_transit" || source === "" || Boolean(route.owner && route.next_hop && route.owner !== route.next_hop);
}

function staticRouteFromRuntimeRoute(route: RouteView): RouteConfig {
  const owner = route.owner || route.next_hop || "";
  return {
    prefix: route.prefix || "",
    kind: route.kind && route.kind !== "local" ? route.kind : "unicast",
    owner,
    next_hop: route.next_hop || owner,
    endpoint: route.endpoint || "",
    policy: route.policy || "",
    metric: route.metric ?? 100,
  };
}

function staticRouteTargetIndex(routes: RouteConfig[], route: RouteView): number {
  const target = staticRouteFromRuntimeRoute(route);
  const targetOwner = target.owner || target.next_hop || "";
  return routes.findIndex((item) => {
    const itemOwner = item.owner || item.next_hop || "";
    return (item.prefix || "") === (target.prefix || "") && itemOwner === targetOwner;
  });
}

function staticRouteExactIndex(routes: RouteConfig[], route: RouteView): number {
  const target = staticRouteFromRuntimeRoute(route);
  return routes.findIndex((item) => routesMatch(item, target));
}

function promoteRuntimeRouteInDesired(desired: DesiredConfig, route: RouteView): { desired: DesiredConfig; index: number } {
  const routes = [...arrayValue(desired.routes)];
  const nextRoute = staticRouteFromRuntimeRoute(route);
  const existing = staticRouteTargetIndex(routes, route);
  if (existing >= 0) {
    routes[existing] = {
      ...routes[existing],
      ...nextRoute,
      policy: nextRoute.policy || routes[existing].policy || "",
    };
    return { desired: { ...desired, routes }, index: existing };
  }
  routes.push(nextRoute);
  return { desired: { ...desired, routes }, index: routes.length - 1 };
}

function endpointPublishStateForPeer(endpoint: EndpointConfig, peerId: string): { published: boolean; mode: string; label: string } {
  const publish = endpoint.publish || {};
  const mode = String(publish.mode || "").trim().toLowerCase();
  const onlyPeers = arrayValue(publish.only_peers);
  const exceptPeers = arrayValue(publish.except_peers);
  if (["private", "disabled", "none"].includes(mode)) {
    return { published: false, mode: "disabled", label: "disabled" };
  }
  if (onlyPeers.length || ["allowlist", "only"].includes(mode)) {
    return { published: onlyPeers.includes(peerId), mode: onlyPeers.includes(peerId) ? "only" : "inherit", label: "allowlist" };
  }
  if (exceptPeers.includes(peerId) || ["denylist", "except"].includes(mode)) {
    return { published: !exceptPeers.includes(peerId), mode: exceptPeers.includes(peerId) ? "except" : "inherit", label: "denylist" };
  }
  return { published: true, mode: "inherit", label: mode || "public" };
}

function setEndpointPublishedForPeer(endpoint: EndpointConfig, peerId: string, published: boolean): EndpointConfig {
  const state = endpointPublishStateForPeer(endpoint, peerId);
  if (published === state.published) {
    return endpoint;
  }
  if (!published) {
    return setEndpointPublishModeForPeer(endpoint, peerId, "except");
  }
  if (state.label === "allowlist") {
    return setEndpointPublishModeForPeer(endpoint, peerId, "only");
  }
  return setEndpointPublishModeForPeer(endpoint, peerId, "inherit");
}

function setEndpointPublishModeForPeer(endpoint: EndpointConfig, peerId: string, mode: string): EndpointConfig {
  const publish = { ...(endpoint.publish || {}) };
  const onlyPeers = new Set(arrayValue(publish.only_peers));
  const exceptPeers = new Set(arrayValue(publish.except_peers));
  const previousMode = String(publish.mode || "").trim().toLowerCase();
  if (mode === "disabled") {
    return { ...endpoint, publish: { ...publish, mode: "disabled", only_peers: [], except_peers: [] } };
  }
  if (mode === "only") {
    exceptPeers.delete(peerId);
    onlyPeers.add(peerId);
    return { ...endpoint, publish: cleanPublishConfig({ ...publish, mode: "allowlist", only_peers: Array.from(onlyPeers), except_peers: Array.from(exceptPeers) }) };
  }
  if (mode === "except") {
    onlyPeers.delete(peerId);
    exceptPeers.add(peerId);
    return { ...endpoint, publish: cleanPublishConfig({ ...publish, mode: "denylist", only_peers: Array.from(onlyPeers), except_peers: Array.from(exceptPeers) }) };
  }
  onlyPeers.delete(peerId);
  exceptPeers.delete(peerId);
  publish.mode = ["allowlist", "only"].includes(previousMode) && onlyPeers.size > 0
    ? "allowlist"
    : ["denylist", "except"].includes(previousMode) && exceptPeers.size > 0
      ? "denylist"
      : "";
  publish.only_peers = Array.from(onlyPeers);
  publish.except_peers = Array.from(exceptPeers);
  return { ...endpoint, publish: cleanPublishConfig(publish) };
}

function cleanPublishConfig(publish: NonNullable<EndpointConfig["publish"]>): EndpointConfig["publish"] {
  const onlyPeers = Array.from(new Set(arrayValue(publish.only_peers).map((peer) => String(peer || "").trim()).filter(Boolean)));
  const exceptPeers = Array.from(new Set(arrayValue(publish.except_peers).map((peer) => String(peer || "").trim()).filter(Boolean)));
  const domains = Array.from(new Set(arrayValue(publish.domains).map((domain) => String(domain || "").trim()).filter(Boolean)));
  const mode = String(publish.mode || "").trim();
  return {
    ...(mode ? { mode } : {}),
    ...(onlyPeers.length ? { only_peers: onlyPeers } : {}),
    ...(exceptPeers.length ? { except_peers: exceptPeers } : {}),
    ...(domains.length ? { domains } : {}),
  };
}

type RuntimeEndpointFields = EndpointConfig & {
  encryption?: string;
  crypto_placements?: string[];
  profile?: string;
  datapath?: string;
  features?: string[];
};

function mergedPeerEndpointList(staticEndpoints: EndpointConfig[], runtimeEndpoints: RuntimeEndpointFields[], linkEndpoints: RuntimeEndpointFields[]): EndpointConfig[] {
  const merged: EndpointConfig[] = [];
  const seen = new Set<string>();
  for (const endpoint of staticEndpoints) {
    merged.push(endpoint);
    if (endpoint.name) {
      seen.add(endpoint.name);
    }
  }
  for (const endpoint of [...runtimeEndpoints, ...linkEndpoints]) {
    if (!endpoint.name || seen.has(endpoint.name)) {
      continue;
    }
    seen.add(endpoint.name);
    merged.push({
      name: endpoint.name,
      transport: endpoint.transport,
      mode: endpoint.mode || "active",
      address: endpoint.address,
      enabled: endpoint.enabled,
      security: {
        encryption: endpoint.encryption,
        crypto_placements: arrayValue(endpoint.crypto_placements),
      },
      transport_profile: {
        profile: endpoint.profile || "",
        datapath: endpoint.datapath || "",
        features: arrayValue(endpoint.features),
      },
    });
  }
  return merged;
}

function RouteEditor(props: { t: Translate; desired: DesiredConfig; nodes: TopologyNode[]; links: LinkStatus[]; index: number; onBack: () => void; onDesired: (desired: DesiredConfig) => void; onProbeRoute: (destination: string, trace?: boolean) => void }) {
  const route = props.desired.routes?.[props.index];
  const [probeDestination, setProbeDestination] = useState("");
  if (!route) {
    return null;
  }
  const updateRoute = (next: RouteConfig) => {
    const routes = [...arrayValue(props.desired.routes)];
    routes[props.index] = next;
    props.onDesired({ ...props.desired, routes });
  };
  const removeRoute = () => {
    const routes = arrayValue(props.desired.routes).filter((_, index) => index !== props.index);
    props.onDesired({ ...props.desired, routes });
  };
  const peer = arrayValue(props.desired.peers).find((item) => item.id === route.next_hop);
  const link = props.links.find((item) => item.peer === route.next_hop);
  const endpointOptions = ["", ...Array.from(new Set([
    ...peerEndpointCandidates(peer, null, props.links).map((endpoint) => endpoint.name || "").filter(Boolean),
    ...arrayValue(link?.endpoints).map((endpoint) => endpoint.name || "").filter(Boolean),
    route.endpoint || "",
  ].filter(Boolean)))];
  const peerOptions = routePeerOptions(props.desired, props.nodes, props.links);
  const target = probeDestination || routeProbeDefaultDestination(route.prefix || "");
  return (
    <div className="inspector-stack">
      <div className="detail-title">
        <IconButton title={props.t("back", "Back")} onClick={props.onBack}><ArrowLeft size={15} /></IconButton>
        <h3>{props.t("route", "Route")}</h3>
      </div>
      <Field label={props.t("prefix", "Prefix")} help={props.t("help_route_prefix", "Destination CIDR prefix for this route.")} value={route.prefix || ""} onChange={(value) => updateRoute({ ...route, prefix: value })} />
      <SelectField label={props.t("kind", "Kind")} help={props.t("help_route_kind", "unicast forwards traffic; local terminates it here; blackhole/reject intentionally drop matching traffic.")} value={route.kind || "unicast"} options={["unicast", "local", "blackhole", "reject"]} onChange={(value) => updateRoute({ ...route, kind: value })} />
      <SelectField label={props.t("owner", "Owner")} help={props.t("help_route_owner", "IX that owns the destination prefix. For transit routes, owner is the downstream/destination IX and next hop is the immediate IX to send packets to.")} value={route.owner || ""} options={["", ...peerOptions]} onChange={(value) => updateRoute({ ...route, owner: value })} />
      <SelectField label={props.t("next_hop", "Next hop")} help={props.t("help_route_next_hop", "IX ID that should receive traffic for this prefix.")} value={route.next_hop || ""} options={["", ...peerOptions]} onChange={(value) => updateRoute({ ...route, next_hop: value, owner: route.owner || value })} />
      <SelectField label={props.t("endpoint", "Endpoint")} help={props.t("help_route_endpoint", "Preferred endpoint for this route. Empty lets transport policy choose among usable endpoints.")} value={route.endpoint || ""} options={endpointOptions} onChange={(value) => updateRoute({ ...route, endpoint: value })} />
      <Field label={props.t("policy", "Policy")} help={props.t("help_route_policy", "Optional route policy name. Empty uses the default policy selection.")} value={route.policy || ""} onChange={(value) => updateRoute({ ...route, policy: value })} />
      <Field label={props.t("metric", "Metric")} help={props.t("help_route_metric", "Lower metric wins among otherwise comparable routes.")} type="number" value={String(route.metric ?? 100)} onChange={(value) => updateRoute({ ...route, metric: Number(value || 0) })} />
      {route.owner && route.next_hop && route.owner !== route.next_hop ? (
        <div className="field-hint">{props.t("transit_route_hint", "Transit route: this prefix belongs to the owner IX, and packets are sent to the next-hop IX first.")}</div>
      ) : null}
      <div className="diagnostic-box">
        <Field label={props.t("probe_destination", "Probe destination")} help={props.t("help_probe_destination", "Destination address used for route probe and trace checks.")} value={target} onChange={setProbeDestination} />
        <div className="inline-controls">
          <Button variant="ghost" disabled={!target} onClick={() => props.onProbeRoute(target, false)}><Check size={15} />{props.t("probe", "Probe")}</Button>
          <Button variant="ghost" disabled={!target} onClick={() => props.onProbeRoute(target, true)}><Route size={15} />{props.t("trace", "Trace")}</Button>
        </div>
      </div>
      <div className="form-actions">
        <Button variant="danger" onClick={removeRoute}><Trash2 size={15} />{props.t("remove", "Remove")}</Button>
      </div>
    </div>
  );
}

export function ConfigView(props: {
  t: Translate;
  lang: string;
  desired: DesiredConfig | null;
  transports: TransportMatrix | null;
  kernelCapabilities: KernelCapabilitiesPayload | null;
  links: LinkStatus[];
  routes: RouteView[];
  text: string;
  dirty: boolean;
  message: string;
  onDesired: (desired: DesiredConfig) => void;
  onText: (text: string) => void;
  onReload: () => void;
  onValidate: () => void;
  onApply: () => void;
  onCopy: () => void;
  onExport: () => void;
  onBackup: () => void;
  onRestore: (file: File | null) => void;
}) {
  const restoreInputRef = useRef<HTMLInputElement>(null);
  return (
    <main className="views">
      <section className="panel">
        <div className="panel-head">
          <h2>{props.t("config", "Config")}</h2>
          <div className="inline-controls">
            <Pill state={props.dirty ? "warn" : "ok"}>{props.dirty ? props.t("unsaved_changes", "Unsaved changes") : props.t("saved", "Saved")}</Pill>
            <Button variant="ghost" onClick={props.onReload}><RefreshCw size={15} />{props.t("reload", "Reload")}</Button>
            <Button variant="ghost" onClick={props.onValidate}><Check size={15} />{props.t("validate", "Validate")}</Button>
            <Button onClick={props.onApply}><Save size={15} />{props.t("apply", "Apply")}</Button>
            <Button variant="ghost" onClick={props.onCopy}><Copy size={15} />{props.t("copy", "Copy")}</Button>
            <Button variant="ghost" onClick={props.onExport} title={props.t("help_config_export", "Download desired config, config log, and public certificate material without private keys.")}><Download size={15} />{props.t("export", "Export")}</Button>
            <Button variant="ghost" onClick={props.onBackup} title={props.t("help_config_backup", "Download a full backup archive including configured private keys.")}><Archive size={15} />{props.t("full_backup", "Full backup")}</Button>
            <Button variant="ghost" onClick={() => restoreInputRef.current?.click()} title={props.t("help_config_restore", "Restore config log and configured certificate/key files from a TrustIX backup archive.")}><Upload size={15} />{props.t("restore_backup", "Restore")}</Button>
            <input
              ref={restoreInputRef}
              type="file"
              accept=".tar.gz,.tgz,application/gzip,application/x-gzip"
              style={{ display: "none" }}
              onChange={(event) => {
                const file = event.currentTarget.files?.[0] || null;
                props.onRestore(file);
                event.currentTarget.value = "";
              }}
            />
          </div>
        </div>
        {props.desired ? (
          <VisualConfig t={props.t} lang={props.lang} desired={props.desired} transports={props.transports} kernelCapabilities={props.kernelCapabilities} links={props.links} runtimeRoutes={props.routes} onDesired={props.onDesired} />
        ) : (
          <div className="muted">{props.t("loading", "Loading")}</div>
        )}
        <details className="advanced-config">
          <summary>{props.t("advanced_json", "Advanced JSON")}</summary>
          <textarea className="editor" value={props.text} spellCheck={false} onChange={(event) => props.onText(event.currentTarget.value)} />
        </details>
      </section>
    </main>
  );
}

type ConfigSectionID = "basic" | "connectivity" | "routing" | "performance" | "advanced";

function VisualConfig(props: { t: Translate; lang: string; desired: DesiredConfig; transports: TransportMatrix | null; kernelCapabilities: KernelCapabilitiesPayload | null; links: LinkStatus[]; runtimeRoutes: RouteView[]; onDesired: (desired: DesiredConfig) => void }) {
  const cfg = props.desired;
  const [activeSection, setActiveSection] = useState<ConfigSectionID>("basic");
  const updateEndpoint = (index: number, next: EndpointConfig) => {
    const endpoints = [...arrayValue(cfg.endpoints)];
    endpoints[index] = next;
    props.onDesired({ ...cfg, endpoints });
  };
  const addEndpoint = () => {
    const endpoints = [...arrayValue(cfg.endpoints), plaintextPerformanceEndpoint("local-experimental_tcp", {
      mode: "passive",
      listen: "0.0.0.0:7000",
    })];
    props.onDesired({ ...cfg, endpoints });
  };
  const removeEndpoint = (index: number) => {
    props.onDesired({ ...cfg, endpoints: arrayValue(cfg.endpoints).filter((_, itemIndex) => itemIndex !== index) });
  };
  const updatePeer = (index: number, next: PeerConfig) => {
    const peers = [...arrayValue(cfg.peers)];
    peers[index] = next;
    props.onDesired({ ...cfg, peers });
  };
  const addPeer = () => {
    const id = `ix-static-${arrayValue(cfg.peers).length + 1}`;
    props.onDesired({
      ...cfg,
      peers: [...arrayValue(cfg.peers), {
        id,
        domain: cfg.domain?.id || cfg.ix?.domain || "",
        control_api: "",
        allowed_prefixes: [],
        endpoints: [plaintextPerformanceEndpoint(`${id}-experimental_tcp`, { mode: "active", address: "" })],
      }],
    });
  };
  const removePeer = (index: number) => {
    const peerID = cfg.peers?.[index]?.id;
    props.onDesired({
      ...cfg,
      peers: arrayValue(cfg.peers).filter((_, itemIndex) => itemIndex !== index),
      routes: arrayValue(cfg.routes).filter((route) => route.next_hop !== peerID && route.owner !== peerID),
    });
  };
  const updateRoute = (index: number, next: RouteConfig) => {
    const routes = [...arrayValue(cfg.routes)];
    routes[index] = next;
    props.onDesired({ ...cfg, routes });
  };
  const addRoute = () => {
    const peerID = routePeerOptions(cfg, undefined, props.links)[0] || "";
    const peer = arrayValue(cfg.peers).find((item) => item.id === peerID);
    const endpoint = routePeerEndpoint(peerID, cfg, props.links) || peerEndpointCandidates(peer, props.transports, props.links)[0]?.name || "";
    props.onDesired({
      ...cfg,
      routes: [...arrayValue(cfg.routes), {
        prefix: routePeerPrefix(peerID, cfg, undefined, props.links),
        kind: "unicast",
        owner: peerID,
        next_hop: peerID,
        endpoint,
        policy: "",
        metric: 100,
      }],
    });
  };
  const removeRoute = (index: number) => {
    props.onDesired({ ...cfg, routes: arrayValue(cfg.routes).filter((_, itemIndex) => itemIndex !== index) });
  };
  const promoteRuntimeRoute = (route: RouteView): number => {
    const promoted = promoteRuntimeRouteInDesired(cfg, route);
    props.onDesired(promoted.desired);
    return promoted.index;
  };
  const updateRoutePolicy = (next: DesiredConfig["route_policy"]) => {
    props.onDesired({ ...cfg, route_policy: { ...(cfg.route_policy || {}), ...(next || {}) } });
  };
  const sections: ConfigSectionID[] = ["basic", "connectivity", "routing", "performance", "advanced"];
  const endpoints = arrayValue(cfg.endpoints);
  const peers = arrayValue(cfg.peers);
  const routes = arrayValue(cfg.routes);
  const runtimeRoutes = domainRouteRows(props.runtimeRoutes);
  return (
    <div className="config-visual">
      <ConfigSummaryStrip t={props.t} lang={props.lang} desired={cfg} transports={props.transports} links={props.links} runtimeRoutes={runtimeRoutes} />
      <ConfigConceptStrip t={props.t} />
      <nav className="config-task-nav" aria-label={props.t("config_sections", "Config sections")}>
        {sections.map((section) => (
          <button key={section} type="button" className={`config-task-tab ${activeSection === section ? "is-active" : ""}`} onClick={() => setActiveSection(section)}>
            <span>{configSectionLabel(props.t, section)}</span>
            <strong>{configSectionValue(props.t, cfg, props.transports, props.links, runtimeRoutes, section)}</strong>
          </button>
        ))}
      </nav>

      {activeSection === "basic" && (
        <>
          <section className="config-section">
            <div className="config-section-head"><h3>{props.t("identity", "Identity")}</h3></div>
            <div className="form-grid">
              <Field label={props.t("domain_id", "Domain ID")} help={props.t("help_domain_id", "Domain identifier shared by IX nodes that belong to the same TrustIX domain.")} value={cfg.domain?.id || ""} onChange={(value) => props.onDesired({ ...cfg, domain: { ...(cfg.domain || {}), id: value } })} />
              <Field label={props.t("ix_id", "IX ID")} help={props.t("help_ix_id", "Unique name of this IX node inside the domain. Peers and routes use this value as the next hop.")} value={cfg.ix?.id || ""} onChange={(value) => props.onDesired({ ...cfg, ix: { ...(cfg.ix || {}), id: value } })} />
              <Field label={props.t("control_api", "Control API")} help={props.t("help_ix_control_api", "URL other IX nodes use to call this node's control API, usually https://host:port.")} value={cfg.ix?.control_api || ""} onChange={(value) => props.onDesired({ ...cfg, ix: { ...(cfg.ix || {}), control_api: value } })} />
              <SelectField label={props.t("control_api_publish", "Control API publish")} help={props.t("help_ix_control_api_publish", "auto publishes ix.control_api or falls back to the peer API listen address. disabled is for edge IX nodes without public inbound control-plane access.")} value={cfg.ix?.control_api_publish || ""} options={["", "disabled"]} optionLabels={{ "": props.t("auto", "Auto"), disabled: props.t("disabled", "Disabled") }} onChange={(value) => props.onDesired({ ...cfg, ix: { ...(cfg.ix || {}), control_api_publish: value || undefined } })} />
              <Field label={props.t("ix_cert", "IX certificate")} help={props.t("help_ix_cert", "Path to the IX certificate used for node identity, trust propagation, and optional management TLS.")} value={cfg.ix?.cert || ""} onChange={(value) => props.onDesired({ ...cfg, ix: { ...(cfg.ix || {}), cert: value } })} />
              <Field label={props.t("ix_key", "IX key")} help={props.t("help_ix_key", "Path to the private key matching the IX certificate.")} value={cfg.ix?.key || ""} onChange={(value) => props.onDesired({ ...cfg, ix: { ...(cfg.ix || {}), key: value } })} />
            </div>
          </section>

          <ConfigLANTable t={props.t} lang={props.lang} desired={cfg} onDesired={props.onDesired} />
          <ConfigDNSEditor t={props.t} desired={cfg} onDesired={props.onDesired} />
        </>
      )}

      {activeSection === "connectivity" && (
        <>
          <ConfigEndpointTable t={props.t} endpoints={endpoints} onAdd={addEndpoint} onUpdate={updateEndpoint} onRemove={removeEndpoint} />
          <ConfigPeerTable t={props.t} lang={props.lang} peers={peers} transports={props.transports} links={props.links} onAdd={addPeer} onUpdate={updatePeer} onRemove={removePeer} />
        </>
      )}

      {activeSection === "routing" && (
        <>
          <ConfigRoutePolicy t={props.t} routePolicy={cfg.route_policy || {}} onUpdate={updateRoutePolicy} />
          <ConfigRouteTable t={props.t} lang={props.lang} desired={cfg} transports={props.transports} links={props.links} routes={routes} runtimeRoutes={runtimeRoutes} onAdd={addRoute} onUpdate={updateRoute} onRemove={removeRoute} onPromote={promoteRuntimeRoute} />
        </>
      )}

      {activeSection === "performance" && (
        <section className="config-section">
          <div className="config-section-head"><h3>{props.t("transport_policy", "Transport policy")}</h3></div>
          <div className="form-grid">
            <Field label={props.t("transport_mode", "Transport mode")} help={props.t("help_transport_policy_mode", "Overall transport preference, such as auto or a specific policy mode.")} value={cfg.transport_policy?.mode || ""} onChange={(value) => props.onDesired({ ...cfg, transport_policy: { ...(cfg.transport_policy || {}), mode: value } })} />
            <SelectField label={props.t("profile", "Profile")} help={props.t("help_transport_profile", "Default transport intent: stable favors reliability, performance favors throughput, and latency favors low delay. The concrete protocol and datapath are still negotiated from both sides' capabilities.")} value={cfg.transport_policy?.profile || ""} options={transportProfileOptions()} onChange={(value) => props.onDesired({ ...cfg, transport_policy: { ...(cfg.transport_policy || {}), profile: value } })} />
            <SelectField label={props.t("datapath", "Datapath")} help={props.t("help_transport_datapath", "Preferred datapath implementation, such as auto, kernel_module, tc_xdp, or userspace.")} value={cfg.transport_policy?.datapath || ""} options={transportDatapathOptions()} onChange={(value) => props.onDesired({ ...cfg, transport_policy: { ...(cfg.transport_policy || {}), datapath: value } })} />
            <SelectField label={props.t("encryption", "Encryption")} help={props.t("help_transport_policy_encryption", "Default encryption direction. secure encrypts both directions; plaintext disables transport encryption.")} value={cfg.transport_policy?.encryption || ""} options={encryptionOptions()} onChange={(value) => props.onDesired({ ...cfg, transport_policy: { ...(cfg.transport_policy || {}), encryption: value } })} />
            <SelectField label={props.t("kernel_transport", "Kernel transport")} help={props.t("help_transport_policy_kernel_transport_mode", "Controls whether UDP/TCP/GRE/IPIP datapath should prefer or require the kernel fast path.")} value={cfg.transport_policy?.kernel_transport?.mode || ""} options={["", "auto", "prefer_kernel", "require_kernel", "disabled"]} onChange={(value) => props.onDesired({ ...cfg, transport_policy: { ...(cfg.transport_policy || {}), kernel_transport: { ...(cfg.transport_policy?.kernel_transport || {}), mode: value } } })} />
            <SelectField label={props.t("crypto_placement", "Crypto placement")} help={props.t("help_transport_policy_crypto_placement", "Where payload encryption runs: auto, userspace fallback, or kernel when supported.")} value={cfg.transport_policy?.crypto_placement || ""} options={["", "auto", "userspace", "kernel"]} onChange={(value) => props.onDesired({ ...cfg, transport_policy: { ...(cfg.transport_policy || {}), crypto_placement: value } })} />
            <Field label={props.t("mtu", "MTU")} help={props.t("help_transport_policy_mtu", "Datapath MTU. Leave 0 to let TrustIX choose from the interface and transport.")} type="number" value={String(cfg.transport_policy?.mtu || "")} onChange={(value) => props.onDesired({ ...cfg, transport_policy: { ...(cfg.transport_policy || {}), mtu: Number(value || 0) } })} />
            <MultiSelectField label={props.t("crypto_suites", "Crypto suites")} help={props.t("help_transport_policy_crypto_suites", "Allowed crypto suites in preference order.")} clearLabel={props.t("clear", "Clear")} values={cfg.transport_policy?.crypto_suites} options={cryptoSuiteOptions()} onChange={(values) => props.onDesired({ ...cfg, transport_policy: { ...(cfg.transport_policy || {}), crypto_suites: values } })} />
          </div>
          <ConfigKernelCapabilityEditor t={props.t} lang={props.lang} desired={cfg} capabilities={props.kernelCapabilities} onDesired={props.onDesired} />
          <TransportPolicyOptionalFields
            t={props.t}
            policy={cfg.transport_policy || {}}
            onChange={(transportPolicy) => props.onDesired({ ...cfg, transport_policy: transportPolicy })}
          />
          <CandidateEndpointPicker
            t={props.t}
            endpoints={endpoints}
            selected={arrayValue(cfg.transport_policy?.candidates)}
            onChange={(candidates) => props.onDesired({ ...cfg, transport_policy: { ...(cfg.transport_policy || {}), candidates } })}
          />
          <TransportAdvancedFields
            t={props.t}
            framed
            value={cfg.transport_policy?.advanced || {}}
            onChange={(advanced) => props.onDesired({ ...cfg, transport_policy: { ...(cfg.transport_policy || {}), advanced } })}
          />
          <TransportProfileOverrides
            t={props.t}
            profiles={arrayValue(cfg.transport_policy?.profiles)}
            onChange={(profiles) => props.onDesired({ ...cfg, transport_policy: { ...(cfg.transport_policy || {}), profiles } })}
          />
        </section>
      )}

      {activeSection === "advanced" && (
        <AdvancedConfigEditor t={props.t} desired={cfg} onDesired={props.onDesired} />
      )}
    </div>
  );
}

type LANEntry = {
  source: "legacy" | "lans";
  index: number;
  id: string;
  lan: LANConfig;
};

function ConfigLANTable(props: { t: Translate; lang: string; desired: DesiredConfig; onDesired: (desired: DesiredConfig) => void }) {
  const [selectedIndex, setSelectedIndex] = useState(0);
  const entries = effectiveLANEntries(props.desired);
  useEffect(() => {
    if (selectedIndex >= entries.length) {
      setSelectedIndex(Math.max(0, entries.length - 1));
    }
  }, [entries.length, selectedIndex]);
  const selected = entries[selectedIndex];
  const primaryID = props.desired.primary_lan_id || entries[0]?.id || "";
  const addLAN = () => {
    const ids = new Set(entries.map((entry) => entry.id));
    let nextID = `lan-${entries.length + 1}`;
    for (let i = entries.length + 1; ids.has(nextID); i++) {
      nextID = `lan-${i + 1}`;
    }
    const nextLAN: LANConfig = { id: nextID, type: "local", mode: "routed", attach_mode: "managed", advertise: [] };
    props.onDesired({
      ...props.desired,
      primary_lan_id: props.desired.primary_lan_id || nextID,
      lans: [...arrayValue(props.desired.lans), nextLAN],
    });
    setSelectedIndex(entries.length);
  };
  const updateLAN = (entry: LANEntry, nextLAN: LANConfig) => {
    const oldID = entry.id;
    const nextID = lanEntryID(nextLAN, entry.source);
    const nextDesired = updateLANEntry(props.desired, entry, nextLAN);
    if ((nextDesired.primary_lan_id || "") === oldID && nextID !== oldID) {
      nextDesired.primary_lan_id = nextID;
    }
    props.onDesired(nextDesired);
  };
  const removeLAN = (entry: LANEntry) => {
    const nextDesired = removeLANEntry(props.desired, entry);
    const remaining = effectiveLANEntries(nextDesired);
    if ((nextDesired.primary_lan_id || "") === entry.id || !remaining.some((item) => item.id === nextDesired.primary_lan_id)) {
      nextDesired.primary_lan_id = remaining[0]?.id || "";
    }
    props.onDesired(nextDesired);
  };
  const setPrimary = (id: string) => props.onDesired({ ...props.desired, primary_lan_id: id });
  const selectedLANHelp = props.t("help_selected_lan", "Select which LAN entry to edit. The list can include the legacy LAN block and multi-LAN entries.");
  return (
    <section className="config-section">
      <div className="config-section-head">
        <div className="section-title-row">
          <h3>{props.t("lans", "LANs")}</h3>
          <span className="muted">{formatNumber(entries.length, props.lang)}</span>
        </div>
        <Button variant="ghost" onClick={addLAN}><Plus size={15} />{props.t("add_lan", "Add LAN")}</Button>
      </div>
      {entries.length ? (
        <div className="config-split">
          <div className="config-list compact-config-list">
            <label className="field compact-selector">
              <span title={selectedLANHelp}>{props.t("selected_lan", "Selected LAN")}<small aria-label={selectedLANHelp}>?</small></span>
              <select className="input" value={selectedIndex} onChange={(event) => setSelectedIndex(Number(event.currentTarget.value))}>
                {entries.map((entry, index) => <option key={`${entry.source}-${entry.index}-${entry.id}`} value={index}>{entry.id}</option>)}
              </select>
            </label>
            {entries.map((entry, index) => (
              <button key={`${entry.source}-${entry.index}-${entry.id}`} type="button" className={`config-list-row ${index === selectedIndex ? "is-selected" : ""}`} onClick={() => setSelectedIndex(index)}>
                <strong>{entry.id}</strong>
                <span>{compactList([entry.lan.type || "local", entry.lan.iface, entry.lan.gateway, entry.id === primaryID ? props.t("primary", "Primary") : ""], "-")}</span>
                <span>{arrayValue(entry.lan.advertise).length} {props.t("prefixes", "Prefixes")} · {entry.lan.device_access?.enabled ? props.t("device_access", "Device access") : entry.lan.mode || "routed"}</span>
              </button>
            ))}
          </div>
          {selected && (
            <div className="config-card lan-config-card">
              <LANConfigFields t={props.t} lan={selected.lan} source={selected.source} onUpdate={(nextLAN) => updateLAN(selected, nextLAN)} />
              <div className="form-actions">
                <Button variant="ghost" disabled={selected.id === primaryID} onClick={() => setPrimary(selected.id)}><Check size={15} />{props.t("set_primary", "Set primary")}</Button>
                <Button variant="danger" onClick={() => removeLAN(selected)}><Trash2 size={15} />{props.t("remove", "Remove")}</Button>
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className="empty-row">
          <span>{props.t("no_lan", "No LAN")}</span>
          <Button variant="ghost" onClick={addLAN}><Plus size={15} />{props.t("add_lan", "Add LAN")}</Button>
        </div>
      )}
    </section>
  );
}

function ConfigDNSEditor(props: { t: Translate; desired: DesiredConfig; onDesired: (desired: DesiredConfig) => void }) {
  const dns = props.desired.dns || {};
  const upstreams = arrayValue(dns.upstreams);
  const splitOnly = upstreams.length === 0;
  const dnsmasqEnabled = Boolean(dns.dnsmasq?.enabled);
  const update = (patch: NonNullable<DesiredConfig["dns"]>) => {
    props.onDesired({ ...props.desired, dns: { ...dns, ...patch } });
  };
  const updateDNSMasq = (enabled: boolean) => {
    props.onDesired({
      ...props.desired,
      dns: {
        ...dns,
        enabled: enabled ? true : dns.enabled,
        dnsmasq: { ...(dns.dnsmasq || {}), enabled },
      },
    });
  };
  return (
    <section className="config-section">
      <div className="config-section-head">
        <div className="section-title-row">
          <h3>{props.t("dns_resolver", "DNS resolver")}</h3>
          <span className="muted">{dns.enabled ? compactList([dnsmasqEnabled ? props.t("openwrt_dnsmasq", "OpenWrt dnsmasq") : "", splitOnly ? props.t("dns_split_only", "Split-only") : props.t("dns_forwarding", "Forwarding")], " / ") : props.t("disabled", "Disabled")}</span>
        </div>
      </div>
      <div className="form-grid">
        <CheckField label={props.t("dns_enabled", "DNS enabled")} help={props.t("help_dns_enabled", "Run the built-in DNS server for TrustIX domain names. It answers IX IDs such as ix-a.domain to their domain management address.")} checked={Boolean(dns.enabled)} onChange={(value) => update({ enabled: value, dnsmasq: value ? dns.dnsmasq : { ...(dns.dnsmasq || {}), enabled: false } })} />
        <CheckField label={props.t("openwrt_dnsmasq", "OpenWrt dnsmasq")} help={props.t("help_openwrt_dnsmasq", "On OpenWrt, keep dnsmasq on LAN port 53, add a conditional forward rule for only the TrustIX DNS domain, and allow that domain to return LAN/RFC1918 addresses. Empty listen defaults to 127.0.0.1:1053 in this mode.")} checked={dnsmasqEnabled} onChange={updateDNSMasq} />
        <Field label={props.t("dns_domain", "DNS domain")} help={props.t("help_dns_domain", "DNS suffix served by TrustIX. Empty uses the TrustIX domain ID.")} placeholder={props.desired.domain?.id || "trust.ix"} value={dns.domain || ""} onChange={(value) => update({ domain: value })} />
        <Field label={props.t("listen", "Listen")} help={dnsmasqEnabled ? props.t("help_dns_listen_dnsmasq", "DNS listen address. Empty uses 127.0.0.1:1053 so OpenWrt dnsmasq can forward only the TrustIX domain without losing normal LAN DNS.") : props.t("help_dns_listen", "DNS listen address. Empty uses the first LAN gateway on port 53, for example 10.0.0.1:53.")} placeholder={dnsmasqEnabled ? "127.0.0.1:1053" : "10.0.0.1:53"} value={dns.listen || ""} onChange={(value) => update({ listen: value })} />
        <Field label={props.t("dns_ttl", "DNS TTL")} help={props.t("help_dns_ttl", "TTL for TrustIX DNS answers. Empty uses 30s.")} placeholder="30s" value={dns.ttl || ""} onChange={(value) => update({ ttl: value })} />
        <Field label={props.t("dns_upstreams", "DNS upstreams")} help={props.t("help_dns_upstreams", "Optional upstream DNS servers, one host:port per line. Leave empty to answer only TrustIX domain names and refuse unrelated domains.")} textarea placeholder={"1.1.1.1:53\n8.8.8.8:53"} value={joinLines(upstreams)} onChange={(value) => update({ upstreams: splitLines(value) })} />
      </div>
      <p className="panel-note inline-note">
        {dnsmasqEnabled ? `${props.t("openwrt_dnsmasq_note", "OpenWrt mode writes a dnsmasq conditional server rule plus a rebind whitelist, then reloads dnsmasq; it does not redirect arbitrary LAN DNS packets.")} ` : ""}
        {splitOnly
          ? props.t("dns_split_only_note", "No upstreams are configured: this IX only answers names inside the TrustIX DNS domain and does not capture or forward other DNS traffic.")
          : props.t("dns_forwarding_note", "Upstreams are configured: non-TrustIX names are forwarded to those DNS servers. Transparent LAN capture is still disabled.")}
        {" "}
        {props.t("dns_capture_disabled_note", "LAN transparent capture and hosts-file rewriting are intentionally not enabled in this first stage.")}
      </p>
    </section>
  );
}

function LANConfigFields(props: { t: Translate; lan: LANConfig; source: "legacy" | "lans"; onUpdate: (lan: LANConfig) => void }) {
  const lan = props.lan;
  const deviceAccess = lan.device_access || {};
  const showDeviceAccessDetails = Boolean(deviceAccess.enabled || deviceAccess.address_pool || deviceAccess.lease_ttl);
  const update = (patch: Partial<LANConfig>) => props.onUpdate({ ...lan, ...patch });
  const updateNAT = (patch: NonNullable<LANConfig["nat"]>) => update({ nat: { ...(lan.nat || {}), ...patch } });
  const updateDeviceAccess = (patch: NonNullable<LANConfig["device_access"]>) => update({ device_access: { ...(lan.device_access || {}), ...patch } });
  const lanMode = lan.mode || "routed";
  const updateMode = (mode: string) => {
    if (mode === "nat") {
      update({ mode });
      return;
    }
    props.onUpdate({ ...lan, mode, nat: undefined });
  };
  return (
    <>
      <div className="lan-field-group lan-field-group-main">
        <Field label={props.t("lan_id", "LAN ID")} help={props.t("help_lan_id", "Stable LAN identifier used by primary_lan_id and diagnostics.")} value={lan.id || (props.source === "legacy" ? "lan" : "")} onChange={(value) => update({ id: value })} />
        <SelectField label={props.t("lan_type", "LAN type")} help={props.t("help_lan_type", "local is a private LAN behind this IX; trusted_public is a directly reachable trusted network segment.")} value={lan.type || "local"} options={["local", "trusted_public"]} onChange={(value) => update({ type: value })} />
        <SelectField label={props.t("lan_mode", "LAN mode")} help={props.t("help_lan_mode", "routed advertises LAN prefixes directly; nat rewrites LAN traffic behind this IX.")} value={lanMode} options={["routed", "nat"]} onChange={updateMode} />
        <SelectField label={props.t("attach_mode", "Attach mode")} help={props.t("help_lan_attach_mode", "managed lets TrustIX create/manage the interface; existing attaches to an interface already present on the host.")} value={lan.attach_mode || "managed"} options={["managed", "existing"]} onChange={(value) => update({ attach_mode: value })} />
      </div>
      <div className="lan-field-group lan-field-group-network">
        <Field label={props.t("iface", "Interface")} help={props.t("help_lan_iface", "LAN interface handled by TrustIX. Use an existing LAN NIC or the virtual interface name.")} value={lan.iface || ""} onChange={(value) => update({ iface: value })} />
        <Field label={props.t("underlay_iface", "Underlay")} help={props.t("help_lan_underlay_iface", "Physical or underlay interface used for transport traffic and kernel datapath attachment.")} value={lan.underlay_iface || ""} onChange={(value) => update({ underlay_iface: value })} />
        <Field label={props.t("gateway", "Gateway")} help={props.t("help_lan_gateway", "Gateway address exposed to local LAN hosts when TrustIX manages LAN addressing.")} value={lan.gateway || ""} onChange={(value) => update({ gateway: value })} />
      </div>
      <div className="lan-field-group lan-field-group-prefixes">
        <Field label={props.t("advertise_prefixes", "Advertise prefixes")} help={props.t("help_lan_advertise", "CIDR prefixes this IX announces to other IX nodes, one prefix per line.")} textarea value={joinLines(lan.advertise)} onChange={(value) => update({ advertise: splitLines(value) })} />
      </div>
      {lanMode === "nat" && (
        <div className="lan-field-group lan-field-group-nat">
          <Field label={props.t("nat_max_bindings", "NAT max bindings")} help={props.t("help_lan_nat_max_bindings", "Maximum number of NAT flow bindings kept for this LAN. Empty uses the daemon default.")} type="number" value={numberFieldValue(lan.nat?.max_bindings)} onChange={(value) => updateNAT({ max_bindings: numberOrUndefined(value) })} />
          <Field label={props.t("nat_binding_ttl", "NAT binding TTL")} help={props.t("help_lan_nat_binding_ttl", "Idle timeout for NAT bindings on this LAN, for example 5m or 1h.")} placeholder="5m" value={lan.nat?.binding_ttl || ""} onChange={(value) => updateNAT({ binding_ttl: value })} />
        </div>
      )}
      <div className="lan-field-group lan-field-group-access">
        <CheckField label={props.t("device_access", "Device access")} help={props.t("help_lan_device_access", "Enable certificate-based device clients on this LAN.")} checked={Boolean(deviceAccess.enabled)} onChange={(value) => updateDeviceAccess({ enabled: value })} />
        {showDeviceAccessDetails && <Field label={props.t("device_address_pool", "Device address pool")} help={props.t("help_lan_device_address_pool", "IPv4 pool used to lease addresses to device clients. It should be inside the LAN gateway prefix when a gateway is configured.")} placeholder="10.82.0.128/25" value={deviceAccess.address_pool || ""} onChange={(value) => updateDeviceAccess({ address_pool: value })} />}
        {showDeviceAccessDetails && <Field label={props.t("device_lease_ttl", "Device lease TTL")} help={props.t("help_lan_device_lease_ttl", "Default device address lease lifetime for this LAN.")} placeholder="24h" value={deviceAccess.lease_ttl || ""} onChange={(value) => updateDeviceAccess({ lease_ttl: value })} />}
      </div>
      <div className="lan-field-group lan-field-group-system">
        <CheckField label={props.t("manage_address", "Manage address")} help={props.t("help_lan_manage_address", "Let TrustIX add or remove the LAN gateway address on the interface.")} checked={Boolean(lan.manage_address)} onChange={(value) => update({ manage_address: value })} />
        <CheckField label={props.t("manage_forwarding", "Manage forwarding")} help={props.t("help_lan_manage_forwarding", "Let TrustIX enable Linux forwarding needed for routed or NAT LAN traffic.")} checked={Boolean(lan.manage_forwarding)} onChange={(value) => update({ manage_forwarding: value })} />
        <CheckField label={props.t("manage_rp_filter", "Manage rp_filter")} help={props.t("help_lan_manage_rp_filter", "Let TrustIX relax reverse-path filtering when it would drop overlay-routed packets.")} checked={Boolean(lan.manage_rp_filter)} onChange={(value) => update({ manage_rp_filter: value })} />
      </div>
    </>
  );
}

function effectiveLANEntries(desired: DesiredConfig): LANEntry[] {
  const entries: LANEntry[] = [];
  if (lanConfiguredUI(desired.lan)) {
    const lan = withLANUIDefaults(desired.lan || {}, "lan");
    entries.push({ source: "legacy", index: -1, id: lanEntryID(lan, "legacy"), lan });
  }
  for (const [index, rawLAN] of arrayValue(desired.lans).entries()) {
    const lan = withLANUIDefaults(rawLAN, "");
    entries.push({ source: "lans", index, id: lanEntryID(lan, "lans", index), lan });
  }
  return entries;
}

function withLANUIDefaults(lan: LANConfig, defaultID: string): LANConfig {
  return {
    ...lan,
    id: lan.id || defaultID,
    type: lan.type || "local",
    mode: lan.mode || "routed",
    attach_mode: lan.attach_mode || "managed",
  };
}

function lanEntryID(lan: LANConfig, source: "legacy" | "lans", index = 0): string {
  return String(lan.id || (source === "legacy" ? "lan" : `lan-${index + 1}`)).trim();
}

function lanConfiguredUI(lan: LANConfig | undefined): boolean {
  if (!lan) {
    return false;
  }
  return Boolean(
    lan.id ||
    lan.type && lan.type !== "local" ||
    lan.iface ||
    lan.underlay_iface ||
    lan.gateway ||
    arrayValue(lan.advertise).length ||
    lan.mode && lan.mode !== "routed" ||
    lan.attach_mode && lan.attach_mode !== "managed" ||
    lan.nat?.max_bindings ||
    lan.nat?.binding_ttl ||
    lan.device_access?.enabled ||
    lan.device_access?.address_pool ||
    lan.device_access?.lease_ttl ||
    lan.manage_address ||
    lan.manage_forwarding ||
    lan.manage_rp_filter
  );
}

function updateLANEntry(desired: DesiredConfig, entry: LANEntry, nextLAN: LANConfig): DesiredConfig {
  if (entry.source === "legacy") {
    return { ...desired, lan: nextLAN };
  }
  const lans = [...arrayValue(desired.lans)];
  lans[entry.index] = nextLAN;
  return { ...desired, lans };
}

function removeLANEntry(desired: DesiredConfig, entry: LANEntry): DesiredConfig {
  if (entry.source === "legacy") {
    const next: DesiredConfig = { ...desired };
    delete next.lan;
    return next;
  }
  return { ...desired, lans: arrayValue(desired.lans).filter((_, index) => index !== entry.index) };
}

function localAdvertisePrefixes(desired: DesiredConfig): string[] {
  const prefixes = new Set<string>();
  for (const entry of effectiveLANEntries(desired)) {
    for (const prefix of arrayValue(entry.lan.advertise)) {
      if (prefix) {
        prefixes.add(prefix);
      }
    }
  }
  return Array.from(prefixes);
}

function ConfigSummaryStrip(props: { t: Translate; lang: string; desired: DesiredConfig; transports: TransportMatrix | null; links: LinkStatus[]; runtimeRoutes: RouteView[] }) {
  const cfg = props.desired;
  const endpointCount = arrayValue(cfg.endpoints).length;
  const peerCount = arrayValue(cfg.peers).length;
  const staticRouteCount = arrayValue(cfg.routes).length;
  const runtimeRouteCount = props.runtimeRoutes.length;
  const activeSessions = arrayValue(props.transports?.sessions).length || props.links.reduce((sum, link) => sum + arrayValue(link.sessions).length, 0);
  const lanEntries = effectiveLANEntries(cfg);
  const primaryID = cfg.primary_lan_id || lanEntries[0]?.id || "";
  return (
    <div className="config-summary-strip">
      <SummaryItem label={props.t("identity", "Identity")} value={compactList([cfg.domain?.id, cfg.ix?.id], "-")} />
      <SummaryItem label={props.t("lans", "LANs")} value={`${formatNumber(lanEntries.length, props.lang)} · ${primaryID || "-"}`} />
      <SummaryItem label={props.t("dns", "DNS")} value={cfg.dns?.enabled ? compactList([cfg.dns.domain || cfg.domain?.id, arrayValue(cfg.dns.upstreams).length ? props.t("dns_forwarding", "Forwarding") : props.t("dns_split_only", "Split-only")], " · ") : props.t("disabled", "Disabled")} />
      <SummaryItem label={props.t("connectivity", "Connectivity")} value={`${formatNumber(endpointCount, props.lang)} ${props.t("endpoints", "Endpoints")} · ${formatNumber(peerCount, props.lang)} ${props.t("peers", "Peers")}`} />
      <SummaryItem label={props.t("routing", "Routing")} value={`${formatNumber(staticRouteCount, props.lang)} ${props.t("static", "Static")} · ${formatNumber(runtimeRouteCount, props.lang)} ${props.t("runtime", "Runtime")} · ${formatNumber(activeSessions, props.lang)} ${props.t("sessions", "sessions")}`} />
    </div>
  );
}

function ConfigConceptStrip(props: { t: Translate }) {
  const concepts = [
    {
      key: "endpoint",
      label: props.t("concept_endpoint", "Endpoint"),
      detail: props.t("concept_endpoint_help", "Reachable data-session address and transport, such as udp or experimental_tcp."),
    },
    {
      key: "lan-prefix",
      label: props.t("concept_lan_prefix", "LAN prefix"),
      detail: props.t("concept_lan_prefix_help", "CIDR network owned or hosted by this IX and advertised into the domain."),
    },
    {
      key: "route",
      label: props.t("concept_route", "Route"),
      detail: props.t("concept_route_help", "Normally learned from advertisements; static routes are for pinning or override."),
    },
    {
      key: "transport-profile",
      label: props.t("concept_transport_profile", "Transport profile"),
      detail: props.t("concept_transport_profile_help", "Intent such as stable, performance, or latency; datapath is the implementation."),
    },
  ];
  return (
    <div className="concept-strip" aria-label={props.t("config_concepts", "Config concepts")}>
      {concepts.map((concept) => (
        <button
          type="button"
          className="concept-item"
          key={concept.key}
          aria-describedby={`config-concept-${concept.key}`}
          title={concept.detail}
        >
          <span className="concept-label">{concept.label}</span>
          <span className="concept-mark" aria-hidden="true">?</span>
          <span className="concept-bubble" id={`config-concept-${concept.key}`} role="tooltip">{concept.detail}</span>
        </button>
      ))}
    </div>
  );
}

function configSectionLabel(t: Translate, section: ConfigSectionID): string {
  switch (section) {
    case "basic":
      return t("basic", "Basic");
    case "connectivity":
      return t("connectivity", "Connectivity");
    case "routing":
      return t("routing", "Routing");
    case "performance":
      return t("performance", "Performance");
    case "advanced":
      return t("advanced", "Advanced");
  }
}

function configSectionValue(t: Translate, cfg: DesiredConfig, transports: TransportMatrix | null, links: LinkStatus[], runtimeRoutes: RouteView[], section: ConfigSectionID): string {
  switch (section) {
    case "basic":
      return compactList([cfg.ix?.id, `${effectiveLANEntries(cfg).length} ${t("lans", "LANs")}`, cfg.dns?.enabled ? t("dns", "DNS") : ""], "-");
    case "connectivity":
      return `${arrayValue(cfg.endpoints).length} / ${arrayValue(cfg.peers).length}`;
    case "routing":
      return `${arrayValue(cfg.routes).length} ${t("static", "Static")} · ${runtimeRoutes.length} ${t("runtime", "Runtime")}`;
    case "performance":
      return compactList([cfg.transport_policy?.profile, cfg.transport_policy?.datapath, cfg.transport_policy?.encryption], "-");
    case "advanced": {
      const fabric = cfg.control_fabric || {};
      return compactList([
        fabric.profile ? t("control_fabric", "Control fabric") : "",
        fabric.dynamic_control_fanout != null ? `${t("dynamic_control_fanout", "Dynamic fanout")} ${fabric.dynamic_control_fanout}` : "",
        fabric.member_page_size != null ? `${t("member_page_size", "Member page")} ${fabric.member_page_size}` : "",
        fabric.member_import_limit != null ? `${t("member_import_limit", "Import limit")} ${fabric.member_import_limit}` : "",
        cfg.management ? t("management", "Management") : "",
        cfg.kernel_modules ? t("kernel", "Kernel") : "",
        arrayValue(transports?.sessions).length || links.some((link) => arrayValue(link.sessions).length) ? t("runtime", "Runtime") : "",
      ], "-");
    }
  }
}

function ConfigKernelCapabilityEditor(props: { t: Translate; lang: string; desired: DesiredConfig; capabilities: KernelCapabilitiesPayload | null; onDesired: (desired: DesiredConfig) => void }) {
  const modules = props.desired.kernel_modules || {};
  const datapath = modules.datapath || {};
  const actualModules = arrayValue(props.capabilities?.modules);
  const datapathModule = actualModules.find((module) => module.name === "trustix_datapath");
  const helpersModule = actualModules.find((module) => module.name === "trustix_datapath_helpers");
  const cryptoModule = actualModules.find((module) => module.name === "trustix_crypto");
  const rxStage = props.capabilities?.rx_stage;
  const updateModules = (patch: NonNullable<DesiredConfig["kernel_modules"]>) => props.onDesired({ ...props.desired, kernel_modules: { ...modules, ...patch } });
  const updateDatapath = (patch: NonNullable<NonNullable<DesiredConfig["kernel_modules"]>["datapath"]>) => updateModules({ datapath: { ...datapath, ...patch } });
  const setProfile = (value: string) => {
    const nextModules = { ...modules, capability_profile: value || undefined };
    if (value === "disabled") {
      nextModules.trustix_crypto = { ...(modules.trustix_crypto || {}), mode: "disabled" };
      nextModules.trustix_datapath = { ...(modules.trustix_datapath || {}), mode: "disabled" };
      nextModules.trustix_datapath_helpers = { ...(modules.trustix_datapath_helpers || {}), mode: "disabled" };
    } else if (["stable", "performance", "full_plaintext", "custom"].includes(value)) {
      nextModules.trustix_crypto = { ...(modules.trustix_crypto || {}), mode: kernelProfileModuleMode(modules.trustix_crypto?.mode) };
      nextModules.trustix_datapath = { ...(modules.trustix_datapath || {}), mode: kernelProfileModuleMode(modules.trustix_datapath?.mode) };
      nextModules.trustix_datapath_helpers = { ...(modules.trustix_datapath_helpers || {}), mode: kernelProfileModuleMode(modules.trustix_datapath_helpers?.mode) };
    }
    props.onDesired({ ...props.desired, kernel_modules: nextModules });
  };
  const actualSummary = compactList([
    datapathModule?.capability_tier,
    helpersModule?.capability_tier,
    cryptoModule?.capability_tier,
    rxStage?.enabled ? `RX ${rxStage.mode || props.t("active", "Active")}` : "",
  ], "-");
  return (
    <div className="config-card config-wide kernel-config-card">
      <div className="config-section-head config-wide">
        <div>
          <h3>{props.t("kernel_capability_profile", "Kernel capability profile")}</h3>
          <span className="readonly-note">{props.t("kernel_capability_apply_note", "Applying these settings briefly restarts the dataplane and reloads managed TrustIX modules when needed.")}</span>
        </div>
        <Pill state={datapathModule?.loaded || helpersModule?.loaded || cryptoModule?.loaded ? "ok" : "warn"}>{datapathModule?.loaded || helpersModule?.loaded || cryptoModule?.loaded ? props.t("loaded", "Loaded") : props.t("limited", "Limited")}</Pill>
      </div>
      <div className="kernel-summary-strip config-wide">
        <SummaryItem label={props.t("desired", "Desired")} value={compactList([modules.capability_profile || props.t("default", "Default"), datapath.rx_stage, datapath.full_plaintext ? "full_plaintext" : ""], "-")} />
        <SummaryItem label={props.t("actual", "Actual")} value={actualSummary} />
        <SummaryItem label={props.t("kernel_modules", "Kernel modules")} value={`${formatNumber(actualModules.filter((module) => module.loaded).length, props.lang)} / ${formatNumber(actualModules.length, props.lang)}`} />
        <SummaryItem label={props.t("rx_worker", "RX worker")} value={rxStage?.rx_worker || rxStage?.mode === "worker" ? props.t("enabled", "Enabled") : props.t("disabled", "Disabled")} />
      </div>
      <div className="form-grid config-wide kernel-config-grid">
        <SelectField label={props.t("kernel_capability_profile", "Kernel capability profile")} help={props.t("help_kernel_capability_profile", "disabled unloads managed modules; stable keeps conservative kernel support; performance keeps production-safe helper acceleration available; full_plaintext enables experimental kernel plaintext TX/RX ownership. custom lets advanced datapath switches decide.")} value={modules.capability_profile || ""} options={kernelCapabilityProfileOptions()} optionLabels={{ "": props.t("default", "Default"), disabled: props.t("disabled", "Disabled"), stable: props.t("stable", "Stable"), performance: props.t("performance", "Performance"), full_plaintext: props.t("full_plaintext", "Full plaintext"), custom: props.t("custom", "Custom") }} onChange={setProfile} />
        <SelectField label={props.t("kernel_rx_stage", "Kernel RX stage")} help={props.t("help_kernel_rx_stage", "auto follows the selected profile; stage polls packets back into userspace; worker injects packets from the kernel worker; disabled turns the hook off.")} value={datapath.rx_stage || ""} options={kernelRXStageOptions()} optionLabels={{ "": props.t("default", "Default"), auto: props.t("auto", "Auto"), disabled: props.t("disabled", "Disabled"), stage: props.t("stage", "Stage"), worker: props.t("worker", "Worker") }} onChange={(value) => updateDatapath({ rx_stage: value || undefined })} />
        <CheckField label={props.t("rx_worker", "RX worker")} help={props.t("help_kernel_rx_worker", "Enable the experimental trustix_datapath RX worker path. Use only after validating the target kernel under real traffic.")} checked={Boolean(datapath.rx_worker)} onChange={(value) => updateDatapath({ rx_worker: value })} />
        <CheckField label={props.t("full_plaintext", "Full plaintext")} help={props.t("help_kernel_full_plaintext", "Experimental: for plaintext transports, let trustix_datapath own both RX and TX hooks when the module supports full_datapath.")} checked={Boolean(datapath.full_plaintext)} onChange={(value) => updateDatapath({ full_plaintext: value, tx_plaintext: value || datapath.tx_plaintext })} />
        <CheckField label={props.t("tx_plaintext", "TX plaintext")} help={props.t("help_kernel_tx_plaintext", "Experimental kernel plaintext TX hook without secure userspace reinjection. Use only with plaintext transport policy after target-kernel validation.")} checked={Boolean(datapath.tx_plaintext)} onChange={(value) => updateDatapath({ tx_plaintext: value })} />
        <CheckField label={props.t("allow_ackless_tcp_rx_worker", "Allow ackless TCP RX worker")} help={props.t("help_kernel_rx_worker_allow_experimental_tcp", "Allow RX worker with experimental_tcp TC direct. This is needed for full-kernel ackless TCP testing and should be validated on the target kernel.")} checked={Boolean(datapath.rx_worker_allow_experimental_tcp)} onChange={(value) => updateDatapath({ rx_worker_allow_experimental_tcp: value })} />
        <CheckField label={props.t("rx_worker_hot_stats", "RX worker hot stats")} help={props.t("help_kernel_rx_worker_hot_stats", "Keep per-packet hot-path counters enabled. Disable for lower CPU overhead during throughput tests.")} checked={datapath.rx_worker_hot_stats !== false} onChange={(value) => updateDatapath({ rx_worker_hot_stats: value })} />
      </div>
    </div>
  );
}

function kernelProfileModuleMode(mode: string | undefined): string {
  const normalized = String(mode || "").trim().toLowerCase();
  return normalized === "required" ? "required" : "auto";
}

function TransportPolicyOptionalFields(props: { t: Translate; policy: NonNullable<DesiredConfig["transport_policy"]>; onChange: (policy: NonNullable<DesiredConfig["transport_policy"]>) => void }) {
  const policy = props.policy || {};
  const sessionPool = policy.session_pool || {};
  const heartbeat = sessionPool.heartbeat || {};
  const tlsIdentity = policy.tls_identity || {};
  const update = (patch: Partial<NonNullable<DesiredConfig["transport_policy"]>>) => props.onChange({ ...policy, ...patch });
  const updateSessionPool = (patch: NonNullable<NonNullable<DesiredConfig["transport_policy"]>["session_pool"]>) => update({ session_pool: { ...sessionPool, ...patch } });
  const updateHeartbeat = (patch: NonNullable<NonNullable<NonNullable<DesiredConfig["transport_policy"]>["session_pool"]>["heartbeat"]>) => updateSessionPool({ heartbeat: { ...heartbeat, ...patch } });
  const updateTLSIdentity = (patch: NonNullable<NonNullable<DesiredConfig["transport_policy"]>["tls_identity"]>) => update({ tls_identity: { ...tlsIdentity, ...patch } });
  return (
    <div className="config-card-list config-wide">
      <div className="config-card">
        <div className="config-section-head config-wide">
          <h3>{props.t("transport_selection", "Transport selection")}</h3>
        </div>
        <SelectField label={props.t("failover", "Failover")} help={props.t("help_transport_failover", "health_based skips endpoints recently marked down by probes or send failures.")} value={policy.failover || ""} options={["", "health_based"]} onChange={(value) => update({ failover: value })} />
        <SelectField label={props.t("load_balance", "Load balance")} help={props.t("help_transport_load_balance", "least_conn prefers endpoints with fewer active sessions when routes do not pin an endpoint.")} value={policy.load_balance || ""} options={["", "least_conn"]} onChange={(value) => update({ load_balance: value })} />
        <SelectField label={props.t("fragment_policy", "Fragments")} help={props.t("help_transport_policy_fragment_policy", "Whether fragmented packets are accepted or dropped before forwarding.")} value={policy.fragment_policy || ""} options={["", "allow", "drop"]} onChange={(value) => update({ fragment_policy: value })} />
        <SelectField label={props.t("crypto_key_source", "Key source")} help={props.t("help_transport_policy_crypto_key_source", "Key derivation source for transport encryption, such as TrustIX X25519 or TLS exporter.")} value={policy.crypto_key_source || ""} options={["", "auto", "trustix_x25519", "tls_exporter"]} onChange={(value) => update({ crypto_key_source: value })} />
      </div>
      <div className="config-card">
        <div className="config-section-head config-wide">
          <h3>{props.t("session_pool", "Session pool")}</h3>
        </div>
        <Field label={props.t("session_pool_size", "Pool size")} help={props.t("help_session_pool_size", "Number of parallel transport sessions per endpoint. 0 or 1 keeps a single session.")} type="number" value={numberFieldValue(sessionPool.size)} onChange={(value) => updateSessionPool({ size: numberOrUndefined(value) })} />
        <SelectField label={props.t("strategy", "Strategy")} help={props.t("help_session_pool_strategy", "flow/five_tuple pins flows to a session; packet/round_robin spreads packets across sessions.")} value={sessionPool.strategy || ""} options={["", "flow", "five_tuple", "packet", "round_robin"]} onChange={(value) => updateSessionPool({ strategy: value })} />
        <CheckField label={props.t("session_warmup", "Session warmup")} help={props.t("help_session_warmup", "Pre-open transport sessions for configured peers so the first data flow avoids dial latency.")} checked={Boolean(sessionPool.warmup)} onChange={(value) => updateSessionPool({ warmup: value })} />
        <SelectField label={props.t("heartbeat_mode", "Heartbeat mode")} help={props.t("help_session_pool_heartbeat_mode", "auto enables session heartbeats when the pool uses more than one session.")} value={heartbeat.mode || ""} options={["", "auto", "enabled", "disabled"]} onChange={(value) => updateHeartbeat({ mode: value })} />
        <Field label={props.t("heartbeat_interval", "Heartbeat interval")} help={props.t("help_session_pool_heartbeat_interval", "Interval between session heartbeat probes, for example 10s.")} placeholder="10s" value={heartbeat.interval || ""} onChange={(value) => updateHeartbeat({ interval: value })} />
        <Field label={props.t("heartbeat_timeout", "Heartbeat timeout")} help={props.t("help_session_pool_heartbeat_timeout", "Heartbeat response timeout before a pooled session is considered unhealthy.")} placeholder="3s" value={heartbeat.timeout || ""} onChange={(value) => updateHeartbeat({ timeout: value })} />
      </div>
      <div className="config-card">
        <div className="config-section-head config-wide">
          <h3>{props.t("transport_tls_identity", "Transport TLS identity")}</h3>
        </div>
        <SelectField label={props.t("mode", "Mode")} help={props.t("help_transport_tls_identity_mode", "ix_cert reuses the IX certificate for link TLS; custom_cert uses the certificate and trust roots below.")} value={tlsIdentity.mode || ""} options={["", "ix_cert", "custom_cert"]} onChange={(value) => updateTLSIdentity({ mode: value })} />
        <Field label={props.t("certificate", "Certificate")} help={props.t("help_transport_tls_identity_cert", "Custom certificate path used by TCP/WebSocket/HTTP CONNECT/QUIC link TLS.")} value={tlsIdentity.cert || ""} onChange={(value) => updateTLSIdentity({ cert: value })} />
        <Field label={props.t("private_key", "Private key")} help={props.t("help_transport_tls_identity_key", "Private key path matching the custom transport TLS certificate.")} value={tlsIdentity.key || ""} onChange={(value) => updateTLSIdentity({ key: value })} />
        <Field label={props.t("trust_root_paths", "Trust root paths")} help={props.t("help_transport_tls_identity_trust_roots", "CA paths trusted for custom transport TLS verification, one path per line.")} textarea value={joinLines(tlsIdentity.trust_roots)} onChange={(value) => updateTLSIdentity({ trust_roots: splitLines(value) })} />
        <CheckField label={props.t("system_roots", "System roots")} help={props.t("help_transport_tls_identity_system_roots", "Also trust the system certificate pool for custom transport TLS.")} checked={Boolean(tlsIdentity.system_roots)} onChange={(value) => updateTLSIdentity({ system_roots: value })} />
      </div>
    </div>
  );
}

function CandidateEndpointPicker(props: { t: Translate; endpoints: EndpointConfig[]; selected: string[]; onChange: (selected: string[]) => void }) {
  const selected = new Set(props.selected);
  const knownNames = new Set(props.endpoints.map((endpoint) => endpoint.name || "").filter(Boolean));
  const unknownSelected = props.selected.filter((name) => name && !knownNames.has(name));
  const toggle = (name: string, checked: boolean) => {
    const next = props.selected.filter((item) => item !== name);
    if (checked) {
      next.push(name);
    }
    props.onChange(Array.from(new Set(next)));
  };
  const selectAll = () => props.onChange(props.endpoints.map((endpoint) => endpoint.name || "").filter(Boolean));
  const clear = () => props.onChange([]);
  return (
    <div className="candidate-picker config-wide">
      <div className="subhead">
        <strong>{props.t("candidate_endpoints", "Candidate endpoints")}</strong>
        <div className="inline-controls">
          <Button variant="ghost" onClick={selectAll}><Check size={15} />{props.t("select_all", "Select all")}</Button>
          <Button variant="ghost" onClick={clear}>{props.t("clear", "Clear")}</Button>
        </div>
      </div>
      <div className="candidate-grid">
        {props.endpoints.length ? props.endpoints.map((endpoint, index) => {
          const name = endpoint.name || "";
          const disabled = !name;
          return (
            <label className={`candidate-row ${endpoint.enabled === false ? "is-muted" : ""}`} key={`${name || "endpoint"}-${index}`}>
              <input type="checkbox" disabled={disabled} checked={Boolean(name && selected.has(name))} onChange={(event) => toggle(name, event.currentTarget.checked)} />
              <span>
                <strong>{name || props.t("endpoint", "Endpoint")}</strong>
                <em>{compactList([endpoint.transport, endpoint.mode || "passive", endpoint.security?.encryption || endpoint.transport_profile?.encryption, endpoint.enabled === false ? props.t("disabled", "Disabled") : props.t("enabled", "Enabled")], "-")}</em>
              </span>
              <small title={endpointAddressSummary(endpoint, props.t)}>{endpointAddressSummary(endpoint, props.t)}</small>
            </label>
          );
        }) : <div className="empty-row">{props.t("no_endpoint", "No endpoint")}</div>}
        {unknownSelected.map((name) => (
          <label className="candidate-row is-muted" key={name}>
            <input type="checkbox" checked onChange={(event) => toggle(name, event.currentTarget.checked)} />
            <span>
              <strong>{name}</strong>
              <em>{props.t("unknown_endpoint", "Unknown endpoint")}</em>
            </span>
            <small>-</small>
          </label>
        ))}
      </div>
    </div>
  );
}

function AdvancedConfigEditor(props: { t: Translate; desired: DesiredConfig; onDesired: (desired: DesiredConfig) => void }) {
  return (
    <>
      <ConfigManagementEditor t={props.t} desired={props.desired} onDesired={props.onDesired} />
      <ConfigKernelModulesEditor t={props.t} desired={props.desired} onDesired={props.onDesired} />
      <ConfigTrustEditor t={props.t} desired={props.desired} onDesired={props.onDesired} />
      <ConfigBootstrapEditor t={props.t} desired={props.desired} onDesired={props.onDesired} />
      <ConfigControlFabricEditor t={props.t} desired={props.desired} onDesired={props.onDesired} />
      <section className="config-section">
        <div className="config-section-head"><h3>{props.t("advanced_config", "Advanced config")}</h3></div>
        <AdvancedConfigSummary t={props.t} desired={props.desired} />
      </section>
    </>
  );
}

function ConfigManagementEditor(props: { t: Translate; desired: DesiredConfig; onDesired: (desired: DesiredConfig) => void }) {
  const management = props.desired.management || {};
  const hostAPI = management.host_api || {};
  const tls = management.tls || {};
  const webUI = management.web_ui || {};
  const updateManagement = (patch: NonNullable<DesiredConfig["management"]>) => props.onDesired({ ...props.desired, management: { ...management, ...patch } });
  const updateHostAPI = (patch: NonNullable<NonNullable<DesiredConfig["management"]>["host_api"]>) => updateManagement({ host_api: { ...hostAPI, ...patch } });
  const updateTLS = (patch: NonNullable<NonNullable<DesiredConfig["management"]>["tls"]>) => updateManagement({ tls: { ...tls, ...patch } });
  const updateWebUI = (patch: NonNullable<NonNullable<DesiredConfig["management"]>["web_ui"]>) => updateManagement({ web_ui: { ...webUI, ...patch } });
  return (
    <section className="config-section">
      <div className="config-section-head"><h3>{props.t("management", "Management")}</h3></div>
      <div className="form-grid">
        <CheckField label={props.t("web_ui_enabled", "WebUI enabled")} help={props.t("help_management_web_ui_enabled", "Expose the embedded WebUI on the same listener as the API.")} checked={Boolean(webUI.enabled)} onChange={(value) => updateWebUI({ enabled: value })} />
        <Field label={props.t("custom_dir", "Custom dir")} help={props.t("help_management_web_ui_custom_dir", "Optional directory served instead of the embedded WebUI assets.")} value={webUI.custom_dir || ""} onChange={(value) => updateWebUI({ custom_dir: value })} />
        <SelectField label={props.t("management_tls_mode", "TLS mode")} help={props.t("help_management_tls_mode", "Controls HTTPS for the API and WebUI: auto uses TLS when credentials are available, required refuses plaintext, disabled allows HTTP.")} value={tls.mode || ""} options={["", "auto", "required", "disabled"]} onChange={(value) => updateTLS({ mode: value })} />
        <SelectField label={props.t("management_tls_identity", "TLS identity")} help={props.t("help_management_tls_identity", "Choose whether management TLS uses the IX certificate or a custom certificate/key pair.")} value={tls.identity || ""} options={["", "ix_cert", "custom_cert"]} onChange={(value) => updateTLS({ identity: value })} />
        <Field label={props.t("management_cert", "Management cert")} help={props.t("help_management_tls_cert", "Custom management TLS certificate path when TLS identity is custom_cert.")} value={tls.cert || ""} onChange={(value) => updateTLS({ cert: value })} />
        <Field label={props.t("management_key", "Management key")} help={props.t("help_management_tls_key", "Private key path for the custom management TLS certificate.")} value={tls.key || ""} onChange={(value) => updateTLS({ key: value })} />
      </div>
      <div className="config-card config-wide">
        <div className="config-section-head config-wide">
          <h3>{props.t("host_api", "Host API")}</h3>
          <span className="readonly-note">{props.t("host_api_note", "Optional API listener for LAN or localhost clients.")}</span>
        </div>
        <CheckField label={props.t("host_api_enabled", "Host API enabled")} help={props.t("help_management_host_api_enabled", "Enable the local host API used by LAN/localhost clients.")} checked={Boolean(hostAPI.enabled)} onChange={(value) => updateHostAPI({ enabled: value })} />
        <Field label={props.t("host_api_listen", "Host API listen")} help={props.t("help_management_host_api_listen", "Listen address for the host API, for example 127.0.0.1:8787 or 0.0.0.0:8787.")} placeholder="127.0.0.1:8787" value={hostAPI.listen || ""} onChange={(value) => updateHostAPI({ listen: value })} />
        <CheckField label={props.t("require_read_auth", "Require read auth")} help={props.t("help_management_host_api_require_read_auth", "Require Admin proof even for read-only API calls.")} checked={Boolean(hostAPI.require_read_auth)} onChange={(value) => updateHostAPI({ require_read_auth: value })} />
        <CheckField label={props.t("allow_unauthenticated_reads", "Allow unauthenticated reads")} help={props.t("help_management_host_api_allow_unauthenticated_reads", "Allow read-only host API calls without Admin proof. Use only on trusted local networks.")} checked={Boolean(hostAPI.allow_unauthenticated_reads)} onChange={(value) => updateHostAPI({ allow_unauthenticated_reads: value })} />
        <CheckField label={props.t("allow_unauthenticated_writes", "Allow unauthenticated writes")} help={props.t("help_management_host_api_allow_unauthenticated_writes", "Dangerous: allow config-changing host API calls without Admin proof. Keep disabled unless the listener is fully isolated.")} checked={Boolean(hostAPI.allow_unauthenticated_writes)} onChange={(value) => updateHostAPI({ allow_unauthenticated_writes: value })} />
      </div>
    </section>
  );
}

type KernelModuleKey = "trustix_crypto" | "trustix_datapath" | "trustix_datapath_helpers";

const kernelModuleEditors: Array<{ key: KernelModuleKey; labelKey: string; fallback: string }> = [
  { key: "trustix_crypto", labelKey: "trustix_crypto", fallback: "trustix_crypto" },
  { key: "trustix_datapath", labelKey: "trustix_datapath", fallback: "trustix_datapath" },
  { key: "trustix_datapath_helpers", labelKey: "trustix_datapath_helpers", fallback: "trustix_datapath_helpers" },
];

function ConfigKernelModulesEditor(props: { t: Translate; desired: DesiredConfig; onDesired: (desired: DesiredConfig) => void }) {
  const modules = props.desired.kernel_modules || {};
  const updateModule = (key: KernelModuleKey, module: KernelModuleConfig) => {
    props.onDesired({ ...props.desired, kernel_modules: { ...modules, [key]: module } });
  };
  return (
    <section className="config-section">
      <div className="config-section-head"><h3>{props.t("kernel_modules", "Kernel modules")}</h3></div>
      <div className="config-card-list config-wide">
        {kernelModuleEditors.map((item) => {
          const module = modules[item.key] || {};
          const update = (patch: KernelModuleConfig) => updateModule(item.key, { ...module, ...patch });
          return (
            <div className="config-card" key={item.key}>
              <div className="config-section-head config-wide">
                <h3>{props.t(item.labelKey, item.fallback)}</h3>
              </div>
              <SelectField label={props.t("mode", "Mode")} help={props.t("help_kernel_module_mode", "disabled never loads the module; auto loads when useful; required fails startup if loading is unavailable.")} value={module.mode || ""} options={["", "disabled", "auto", "required"]} onChange={(value) => update({ mode: value })} />
              <Field label={props.t("path", "Path")} help={props.t("help_kernel_module_path", "Module path, or embedded for release binaries that carry the module payload.")} placeholder="embedded" value={module.path || ""} onChange={(value) => update({ path: value })} />
              <Field label={props.t("parameters", "Parameters")} help={props.t("help_kernel_module_parameters", "Optional module parameters passed when loading, for example enable_features=128.")} value={module.parameters || ""} onChange={(value) => update({ parameters: value })} />
              <SelectField label={props.t("reload_on_upgrade", "Reload on upgrade")} help={props.t("help_kernel_module_reload_on_upgrade", "Controls whether a loaded TrustIX module may be reloaded when the desired module payload changes.")} value={module.reload_on_upgrade || ""} options={["", "auto", "never", "always"]} onChange={(value) => update({ reload_on_upgrade: value })} />
              <CheckField label={props.t("unload_on_exit", "Unload on exit")} help={props.t("help_kernel_module_unload_on_exit", "Unload this module when the daemon exits if this process loaded it and the module is not busy.")} checked={Boolean(module.unload_on_exit)} onChange={(value) => update({ unload_on_exit: value })} />
            </div>
          );
        })}
      </div>
    </section>
  );
}

function ConfigTrustEditor(props: { t: Translate; desired: DesiredConfig; onDesired: (desired: DesiredConfig) => void }) {
  const domain = props.desired.domain || {};
  const ix = props.desired.ix || {};
  const trust = props.desired.trust || {};
  const adminPolicy = trust.admin_policy || {};
  const updateDomain = (patch: NonNullable<DesiredConfig["domain"]>) => props.onDesired({ ...props.desired, domain: { ...domain, ...patch } });
  const updateIX = (patch: NonNullable<DesiredConfig["ix"]>) => props.onDesired({ ...props.desired, ix: { ...ix, ...patch } });
  const updateTrust = (patch: NonNullable<DesiredConfig["trust"]>) => props.onDesired({ ...props.desired, trust: { ...trust, ...patch } });
  const updateAdminPolicy = (patch: NonNullable<NonNullable<DesiredConfig["trust"]>["admin_policy"]>) => updateTrust({ admin_policy: { ...adminPolicy, ...patch } });
  return (
    <section className="config-section">
      <div className="config-section-head"><h3>{props.t("trust_and_authorization", "Trust and authorization")}</h3></div>
      <div className="form-grid">
        <Field label={props.t("config_log", "Config log")} help={props.t("help_ix_config_log", "Path to the local signed config log. Empty uses the daemon default under data-dir.")} value={ix.config_log || ""} onChange={(value) => updateIX({ config_log: value })} />
        <Field label={props.t("trust_roots", "Trust roots")} help={props.t("help_domain_trust_roots", "Trust root file paths used by this IX, one path per line.")} textarea value={joinLines(domain.trust_roots)} onChange={(value) => updateDomain({ trust_roots: splitLines(value) })} />
        <Field label={props.t("route_authorizations", "Route authorizations")} help={props.t("help_ix_route_authorizations", "Route authorization certificate paths held by this IX, one path per line.")} textarea value={joinLines(ix.route_authorizations)} onChange={(value) => updateIX({ route_authorizations: splitLines(value) })} />
        <Field label={props.t("revoked_cert_fingerprints", "Revoked cert fingerprints")} help={props.t("help_trust_revoked_cert_fingerprints", "Certificate SHA256 fingerprints revoked by this domain, one fingerprint per line.")} textarea value={joinLines(trust.revoked_cert_fingerprints)} onChange={(value) => updateTrust({ revoked_cert_fingerprints: splitLines(value) })} />
        <Field label={props.t("trust_roots_pem", "Trust roots PEM")} help={props.t("help_trust_roots_pem", "Optional CA certificate PEM blocks stored directly in desired config. Prefer file paths when possible.")} textarea value={arrayValue(trust.trust_roots_pem).join("\n\n")} onChange={(value) => updateTrust({ trust_roots_pem: splitPEMBlocks(value) })} />
        <Field label={props.t("admin_threshold", "Admin threshold")} help={props.t("help_admin_threshold", "Number of allowed Admin proofs required for protected config changes. Empty or 0 uses the default policy.")} type="number" value={numberFieldValue(adminPolicy.threshold)} onChange={(value) => updateAdminPolicy({ threshold: numberOrUndefined(value) })} />
        <Field label={props.t("allowed_admin_fingerprints", "Allowed Admin fingerprints")} help={props.t("help_allowed_admin_fingerprints", "Admin certificate SHA256 fingerprints allowed to approve protected changes, one fingerprint per line.")} textarea value={joinLines(adminPolicy.allowed_fingerprints)} onChange={(value) => updateAdminPolicy({ allowed_fingerprints: splitLines(value) })} />
      </div>
    </section>
  );
}

function ConfigBootstrapEditor(props: { t: Translate; desired: DesiredConfig; onDesired: (desired: DesiredConfig) => void }) {
  const bootstrap = props.desired.bootstrap || {};
  const peers = arrayValue(bootstrap.peers);
  const updatePeers = (nextPeers: BootstrapPeerConfig[]) => props.onDesired({ ...props.desired, bootstrap: { ...bootstrap, peers: nextPeers } });
  const addPeer = () => updatePeers([...peers, { domain: props.desired.domain?.id || "", control_api: "" }]);
  const updatePeer = (index: number, peer: BootstrapPeerConfig) => {
    const next = [...peers];
    next[index] = peer;
    updatePeers(next);
  };
  const removePeer = (index: number) => updatePeers(peers.filter((_, itemIndex) => itemIndex !== index));
  return (
    <section className="config-section">
      <div className="config-section-head">
        <div className="section-title-row">
          <h3>{props.t("bootstrap", "Bootstrap")}</h3>
          <span className="muted">{peers.length}</span>
        </div>
        <Button variant="ghost" onClick={addPeer}><Plus size={15} />{props.t("add_bootstrap_peer", "Add bootstrap peer")}</Button>
      </div>
      <div className="config-card-list config-wide">
        {peers.length ? peers.map((peer, index) => (
          <div className="config-card" key={`${peer.control_api || "bootstrap"}-${index}`}>
            <Field label={props.t("ix_id", "IX ID")} help={props.t("help_bootstrap_peer_id", "Optional IX ID expected from this bootstrap control API.")} value={peer.id || ""} onChange={(value) => updatePeer(index, { ...peer, id: value })} />
            <Field label={props.t("domain_id", "Domain ID")} help={props.t("help_bootstrap_peer_domain", "Optional domain ID expected from this bootstrap peer. Leave aligned with this IX domain.")} value={peer.domain || ""} onChange={(value) => updatePeer(index, { ...peer, domain: value })} />
            <Field label={props.t("control_api", "Control API")} help={props.t("help_bootstrap_peer_control_api", "Control API URL used during startup to push this IX advertisement and fetch members.")} placeholder="https://ix-a.example:9443" value={peer.control_api || ""} onChange={(value) => updatePeer(index, { ...peer, control_api: value })} />
            <div className="form-actions">
              <Button variant="danger" onClick={() => removePeer(index)}><Trash2 size={15} />{props.t("remove", "Remove")}</Button>
            </div>
          </div>
        )) : <div className="empty-row">{props.t("no_bootstrap_peer", "No bootstrap peer")}</div>}
      </div>
    </section>
  );
}

function ConfigControlFabricEditor(props: { t: Translate; desired: DesiredConfig; onDesired: (desired: DesiredConfig) => void }) {
  const fabric = props.desired.control_fabric || {};
  const update = (patch: NonNullable<DesiredConfig["control_fabric"]>) => props.onDesired({ ...props.desired, control_fabric: { ...fabric, ...patch } });
  const profileLabels: Record<string, string> = {
    "": props.t("default", "Default"),
    small: props.t("control_fabric_profile_small", "Small"),
    edge: props.t("control_fabric_profile_edge", "Edge"),
    reflector: props.t("control_fabric_profile_reflector", "Reflector"),
    route_reflector: props.t("control_fabric_profile_route_reflector", "Route reflector"),
    core: props.t("control_fabric_profile_core", "Core"),
    authority: props.t("control_fabric_profile_authority", "Authority"),
  };
  return (
    <section className="config-section">
      <div className="config-section-head">
        <div className="section-title-row">
          <h3>{props.t("control_fabric", "Control fabric")}</h3>
          <span className="muted">{compactList([
            profileLabels[fabric.profile || ""],
            fabric.dynamic_control_fanout != null ? `${props.t("dynamic_control_fanout", "Dynamic fanout")} ${fabric.dynamic_control_fanout}` : "",
            fabric.member_page_size != null ? `${props.t("member_page_size", "Member page")} ${fabric.member_page_size}` : "",
            fabric.member_import_limit != null ? `${props.t("member_import_limit", "Import limit")} ${fabric.member_import_limit}` : "",
          ], "-")}</span>
        </div>
      </div>
      <div className="form-grid">
        <SelectField
          label={props.t("control_fabric_profile", "Fabric profile")}
          help={props.t("help_control_fabric_profile", "Selects the control-plane discovery role. Edge nodes poll a bounded reflector set; reflector/core nodes can carry more member exchange. This does not change cryptographic authority by itself.")}
          value={fabric.profile || ""}
          options={["", "small", "edge", "reflector", "route_reflector", "core", "authority"]}
          optionLabels={profileLabels}
          onChange={(value) => update({ profile: value || undefined })}
        />
        <Field
          label={props.t("dynamic_control_fanout", "Dynamic control fanout")}
          help={props.t("help_dynamic_control_fanout", "Maximum learned control endpoints polled per peer cycle. Static peers and bootstrap peers are always polled. 0 disables the limit.")}
          type="number"
          value={numberFieldValue(fabric.dynamic_control_fanout)}
          onChange={(value) => update({ dynamic_control_fanout: nonNegativeNumberOrUndefined(value) })}
        />
        <Field
          label={props.t("member_page_size", "Member page size")}
          help={props.t("help_member_page_size", "Maximum remote IX advertisements returned by one control members response. The local advertisement is always included. 0 disables pagination.")}
          type="number"
          value={numberFieldValue(fabric.member_page_size)}
          onChange={(value) => update({ member_page_size: nonNegativeNumberOrUndefined(value) })}
        />
        <Field
          label={props.t("member_import_limit", "Member import limit")}
          help={props.t("help_member_import_limit", "Maximum remote IX advertisements imported from one control target per poll. Cursor state resumes on the next poll. 0 imports all pages.")}
          type="number"
          value={numberFieldValue(fabric.member_import_limit)}
          onChange={(value) => update({ member_import_limit: nonNegativeNumberOrUndefined(value) })}
        />
      </div>
    </section>
  );
}

function splitPEMBlocks(value: string): string[] {
  const raw = String(value || "").trim();
  if (!raw) {
    return [];
  }
  const matches = raw.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  if (matches?.length) {
    return matches.map((item) => item.trim()).filter(Boolean);
  }
  return splitLines(value);
}

function AdvancedConfigSummary(props: { t: Translate; desired: DesiredConfig }) {
  const cfg = props.desired;
  const management = cfg.management || {};
  const dns = cfg.dns || {};
  const kernelModules = cfg.kernel_modules || {};
  const fabric = cfg.control_fabric || {};
  const trustRoots = arrayValue(cfg.domain?.trust_roots);
  const routeAuth = arrayValue(cfg.ix?.route_authorizations);
  return (
    <div className="advanced-config-summary">
      <StatusRow label={props.t("management", "Management")} value={compactAdvancedObject(management)} />
      <StatusRow label={props.t("dns", "DNS")} value={compactAdvancedObject(dns)} />
      <StatusRow label={props.t("kernel_modules", "Kernel modules")} value={compactAdvancedObject(kernelModules)} />
      <StatusRow label={props.t("control_fabric", "Control fabric")} value={compactList([
        fabric.profile,
        fabric.dynamic_control_fanout != null ? `${props.t("dynamic_control_fanout", "Dynamic fanout")} ${fabric.dynamic_control_fanout}` : "",
        fabric.member_page_size != null ? `${props.t("member_page_size", "Member page")} ${fabric.member_page_size}` : "",
        fabric.member_import_limit != null ? `${props.t("member_import_limit", "Import limit")} ${fabric.member_import_limit}` : "",
      ], "-")} />
      <StatusRow label={props.t("trust_roots", "Trust roots")} value={trustRoots.join(" · ") || "-"} />
      <StatusRow label={props.t("route_authorizations", "Route authorizations")} value={routeAuth.join(" · ") || "-"} />
      <StatusRow label={props.t("advanced_json", "Advanced JSON")} value={props.t("advanced_json_available", "Raw JSON editor is below the visual config.")} />
    </div>
  );
}

function TransportAdvancedFields(props: { t: Translate; value: TransportAdvancedConfig; onChange: (value: TransportAdvancedConfig) => void; framed?: boolean }) {
  const advanced = props.value || {};
  const update = (patch: Partial<TransportAdvancedConfig>) => props.onChange({ ...advanced, ...patch });
  return (
    <div className={`${props.framed ? "config-card " : "transport-advanced-fields "}config-wide`}>
      <div className="config-section-head config-wide">
        <h3>{props.t("transport_advanced", "Transport advanced")}</h3>
        <span className="readonly-note">{props.t("transport_advanced_note", "Optional performance gates for batching, GSO/GRO, and large frames.")}</span>
      </div>
      <SelectField label={props.t("large_frames", "Large frames")} help={props.t("help_transport_large_frames", "Allow larger internal frames when both endpoints and the selected datapath support them.")} value={advanced.large_frames || ""} options={transportToggleOptions()} onChange={(value) => update({ large_frames: value })} />
      <SelectField label={props.t("gso", "GSO")} help={props.t("help_transport_gso", "Enable transmit segmentation offload in supported kernel datapaths.")} value={advanced.gso || ""} options={transportToggleOptions()} onChange={(value) => update({ gso: value })} />
      <SelectField label={props.t("gro", "GRO")} help={props.t("help_transport_gro", "Enable receive coalescing in supported kernel datapaths.")} value={advanced.gro || ""} options={transportToggleOptions()} onChange={(value) => update({ gro: value })} />
      <Field label={props.t("shards", "Shards")} help={props.t("help_transport_shards", "Number of worker shards for transports that support parallel session processing.")} type="number" value={numberFieldValue(advanced.shards)} onChange={(value) => update({ shards: numberOrUndefined(value) })} />
      <Field label={props.t("max_frames", "Max frames")} help={props.t("help_transport_max_frames", "Maximum frames included in one batch before an immediate flush.")} type="number" value={numberFieldValue(advanced.max_frames)} onChange={(value) => update({ max_frames: numberOrUndefined(value) })} />
      <Field label={props.t("batch_bytes", "Batch bytes")} help={props.t("help_transport_batch_bytes", "Maximum bytes included in one transport batch before an immediate flush.")} type="number" value={numberFieldValue(advanced.batch_bytes)} onChange={(value) => update({ batch_bytes: numberOrUndefined(value) })} />
      <Field label={props.t("flush_delay", "Flush delay")} help={props.t("help_transport_flush_delay", "Maximum time to hold a partial batch before sending it.")} placeholder="100us" value={advanced.flush_delay || ""} onChange={(value) => update({ flush_delay: value })} />
      <CheckField label={props.t("allow_unsafe", "Allow unsafe")} help={props.t("help_transport_allow_unsafe", "Allow experimental fast paths marked unsafe for production until explicitly validated.")} checked={Boolean(advanced.allow_unsafe)} onChange={(value) => update({ allow_unsafe: value })} />
      <CheckField label={props.t("allow_outer_gso_unsafe", "Allow outer GSO")} help={props.t("help_transport_allow_outer_gso_unsafe", "Allow outer-packet GSO paths that may depend on NIC/kernel behavior.")} checked={Boolean(advanced.allow_outer_gso_unsafe)} onChange={(value) => update({ allow_outer_gso_unsafe: value })} />
      <CheckField label={props.t("allow_checksum_skip", "Allow checksum skip")} help={props.t("help_transport_allow_checksum_skip", "Allow checksum shortcuts only after validating the path preserves packet correctness.")} checked={Boolean(advanced.allow_checksum_skip)} onChange={(value) => update({ allow_checksum_skip: value })} />
    </div>
  );
}

function TransportProfileOverrides(props: { t: Translate; profiles: TransportProfileConfig[]; onChange: (profiles: TransportProfileConfig[]) => void }) {
  const addProfile = () => props.onChange([...props.profiles, { transport: "experimental_tcp", profile: "performance", datapath: "auto", advanced: {} }]);
  const updateProfile = (index: number, profile: TransportProfileConfig) => {
    const profiles = [...props.profiles];
    profiles[index] = profile;
    props.onChange(profiles);
  };
  const removeProfile = (index: number) => props.onChange(props.profiles.filter((_, itemIndex) => itemIndex !== index));
  return (
    <div className="config-card-list config-wide">
      <div className="config-section-head">
        <h3>{props.t("transport_profiles", "Transport profiles")}</h3>
        <Button variant="ghost" onClick={addProfile}><Plus size={15} />{props.t("add_profile", "Add profile")}</Button>
      </div>
      {props.profiles.length ? props.profiles.map((profile, index) => (
        <div className="config-card" key={`${profile.transport}-${index}`}>
          <SelectField label={props.t("transport", "Transport")} help={props.t("help_transport_override_transport", "Transport this override applies to, for example experimental_tcp or udp.")} value={profile.transport || ""} options={transportOptions()} onChange={(value) => updateProfile(index, { ...profile, transport: value })} />
          <SelectField label={props.t("profile", "Profile")} help={props.t("help_transport_override_profile", "Profile advertised and preferred for this transport override.")} value={profile.profile || ""} options={transportProfileOptions()} onChange={(value) => updateProfile(index, { ...profile, profile: value })} />
          <SelectField label={props.t("datapath", "Datapath")} help={props.t("help_transport_override_datapath", "Datapath preferred for this transport override.")} value={profile.datapath || ""} options={transportDatapathOptions()} onChange={(value) => updateProfile(index, { ...profile, datapath: value })} />
          <SelectField label={props.t("encryption", "Encryption")} help={props.t("help_transport_override_encryption", "Encryption behavior for this transport override. Empty inherits the global transport policy.")} value={profile.encryption || ""} options={encryptionOptions()} onChange={(value) => updateProfile(index, { ...profile, encryption: value })} />
          <SelectField label={props.t("crypto_placement", "Crypto placement")} help={props.t("help_transport_override_crypto_placement", "Where crypto should run for this transport override.")} value={profile.crypto_placement || ""} options={["", "auto", "userspace", "kernel"]} onChange={(value) => updateProfile(index, { ...profile, crypto_placement: value })} />
          <TransportAdvancedFields t={props.t} value={profile.advanced || {}} onChange={(advanced) => updateProfile(index, { ...profile, advanced })} />
          <div className="form-actions">
            <Button variant="danger" onClick={() => removeProfile(index)}><Trash2 size={15} />{props.t("remove", "Remove")}</Button>
          </div>
        </div>
      )) : <div className="empty-row">{props.t("no_transport_profile", "No transport profile override")}</div>}
    </div>
  );
}

function ConfigEndpointTable(props: { t: Translate; endpoints: EndpointConfig[]; onAdd: () => void; onUpdate: (index: number, endpoint: EndpointConfig) => void; onRemove: (index: number) => void }) {
  const [selectedIndex, setSelectedIndex] = useState(0);
  useEffect(() => {
    if (selectedIndex >= props.endpoints.length) {
      setSelectedIndex(Math.max(0, props.endpoints.length - 1));
    }
  }, [props.endpoints.length, selectedIndex]);
  const selectedEndpoint = props.endpoints[selectedIndex];
  return (
    <section className="config-section">
      <div className="config-section-head">
        <div className="section-title-row">
          <h3>{props.t("endpoints", "Endpoints")}</h3>
          <span className="muted">{props.endpoints.length}</span>
        </div>
        <Button variant="ghost" onClick={() => { props.onAdd(); setSelectedIndex(props.endpoints.length); }}><Plus size={15} />{props.t("add_endpoint", "Add endpoint")}</Button>
      </div>
      {props.endpoints.length ? (
        <div className="config-split">
          <div className="config-list compact-config-list">
            {props.endpoints.map((endpoint, index) => (
              <button key={index} type="button" className={`config-list-row ${index === selectedIndex ? "is-selected" : ""}`} onClick={() => setSelectedIndex(index)}>
                <strong>{endpoint.name || props.t("endpoint", "Endpoint")}</strong>
                <span>{compactList([endpoint.transport, endpoint.mode || "passive", endpoint.security?.encryption, endpoint.enabled === false ? props.t("disabled", "Disabled") : props.t("enabled", "Enabled")], "-")}</span>
                <span>{endpointAddressSummary(endpoint, props.t)}</span>
              </button>
            ))}
          </div>
          {selectedEndpoint && (
            <ConfigEndpointCard
              t={props.t}
              scope="local"
              endpoint={selectedEndpoint}
              onUpdate={(next) => props.onUpdate(selectedIndex, next)}
              onRemove={() => props.onRemove(selectedIndex)}
            />
          )}
        </div>
      ) : (
        <div className="empty-row">{props.t("no_endpoint", "No endpoint")}</div>
      )}
    </section>
  );
}

type EndpointScope = "local" | "peer";

function ConfigEndpointCard(props: { t: Translate; scope?: EndpointScope; endpoint: EndpointConfig; onUpdate: (endpoint: EndpointConfig) => void; onRemove: () => void }) {
  return (
    <div className="config-card endpoint-config-card">
      <EndpointConfigFields t={props.t} scope={props.scope || "local"} endpoint={props.endpoint} onUpdate={props.onUpdate} />
      <div className="form-actions">
        <Button variant="danger" onClick={props.onRemove}><Trash2 size={15} />{props.t("remove", "Remove")}</Button>
      </div>
    </div>
  );
}

function EndpointConfigFields(props: { t: Translate; scope: EndpointScope; endpoint: EndpointConfig; onUpdate: (endpoint: EndpointConfig) => void }) {
  const endpoint = props.endpoint;
  const tunnel = isTunnelTransport(endpoint.transport);
  const publishMode = String(endpoint.publish?.mode || "").trim().toLowerCase();
  const showOnlyPeers = ["allowlist", "only"].includes(publishMode) || arrayValue(endpoint.publish?.only_peers).length > 0;
  const showExceptPeers = ["denylist", "except"].includes(publishMode) || arrayValue(endpoint.publish?.except_peers).length > 0;
  const updateTunnel = (value: string) => {
    if (props.scope === "peer") {
      props.onUpdate({ ...endpoint, listen: "", address: value });
      return;
    }
    props.onUpdate({ ...endpoint, listen: value, address: value });
  };
  return (
    <>
      <Field label={props.t("name", "Name")} help={props.t("help_endpoint_name", "Endpoint name referenced by peers, routes, and transport policies.")} value={endpoint.name || ""} onChange={(value) => props.onUpdate({ ...endpoint, name: value })} />
      <SelectField label={props.t("transport", "Transport")} help={props.t("help_endpoint_transport", "Underlying transport used by this endpoint, such as udp, experimental_tcp, gre, or ipip.")} value={endpoint.transport || "udp"} options={transportOptions()} onChange={(value) => props.onUpdate({ ...endpoint, transport: value })} />
      <SelectField label={props.t("mode", "Mode")} help={props.t("help_endpoint_mode", "passive listens for inbound sessions; active dials the peer address.")} value={endpoint.mode || (props.scope === "peer" ? "active" : "passive")} options={["active", "passive"]} onChange={(value) => props.onUpdate({ ...endpoint, mode: value })} />
      {tunnel && props.scope === "local" ? (
        <TunnelEndpointFields
          t={props.t}
          transport={endpoint.transport}
          value={endpoint.address || endpoint.listen || ""}
          onChange={updateTunnel}
        />
      ) : tunnel ? (
        <Field label={props.t("advertised_address", "Advertised address")} help={props.t("help_peer_tunnel_address", "Static tunnel address. Dynamic GRE/IPIP/VXLAN endpoints come from IX member advertisements and are negotiated locally.")} placeholder={props.t("placeholder_tunnel_endpoint", "local=198.18.0.1")} value={endpoint.address || ""} onChange={(value) => props.onUpdate({ ...endpoint, listen: "", address: value })} />
      ) : (
        <>
          <Field label={props.t("listen", "Listen")} help={props.t("help_endpoint_listen", "Local listen address for passive endpoints, for example 0.0.0.0:4433.")} placeholder={props.t("placeholder_endpoint_listen", "0.0.0.0:7000")} value={endpoint.listen || ""} onChange={(value) => props.onUpdate({ ...endpoint, listen: value })} />
          <Field label={props.t("address", "Address")} help={props.t("help_endpoint_address", "Remote address dialed by active endpoints.")} placeholder={props.t("placeholder_endpoint_address", "203.0.113.10:7000")} value={endpoint.address || ""} onChange={(value) => props.onUpdate({ ...endpoint, address: value })} />
        </>
      )}
      <SelectField label={props.t("encryption", "Encryption")} help={props.t("help_endpoint_security_encryption", "Endpoint-level encryption override for this transport.")} value={endpoint.security?.encryption || ""} options={encryptionOptions()} onChange={(value) => props.onUpdate({ ...endpoint, security: { ...(endpoint.security || {}), encryption: value } })} />
      {props.scope === "local" ? (
        <>
          <SelectField label={props.t("publish_mode", "Publish")} help={props.t("help_publish_mode", "Controls which IX peers can see this local endpoint in control-plane advertisements.")} value={endpoint.publish?.mode || ""} options={["", "public", "private", "allowlist", "denylist"]} onChange={(value) => props.onUpdate({ ...endpoint, publish: { ...(endpoint.publish || {}), mode: value } })} />
          {showOnlyPeers && <Field label={props.t("publish_only_peers", "Only peers")} help={props.t("help_publish_only_peers", "IX IDs allowed to see this endpoint, one per line. Used when publish is allowlist.")} textarea value={joinLines(endpoint.publish?.only_peers)} onChange={(value) => props.onUpdate({ ...endpoint, publish: { ...(endpoint.publish || {}), only_peers: splitLines(value) } })} />}
          {showExceptPeers && <Field label={props.t("publish_except_peers", "Except peers")} help={props.t("help_publish_except_peers", "IX IDs that must not see this endpoint, one per line. Used when publish is denylist.")} textarea value={joinLines(endpoint.publish?.except_peers)} onChange={(value) => props.onUpdate({ ...endpoint, publish: { ...(endpoint.publish || {}), except_peers: splitLines(value) } })} />}
        </>
      ) : null}
      <CheckField label={props.t("enabled", "Enabled")} help={props.t("help_endpoint_enabled", "Disabled endpoints remain in config but are not used for listening, dialing, or negotiation.")} checked={endpoint.enabled !== false} onChange={(value) => props.onUpdate({ ...endpoint, enabled: value })} />
      <details className="endpoint-advanced-fields config-wide">
        <summary>{props.t("endpoint_advanced", "Endpoint advanced")}</summary>
        <div className="endpoint-advanced-grid">
          <Field label={props.t("priority", "Priority")} help={props.t("help_endpoint_priority", "Integer exchanged during endpoint negotiation. Transport profile/datapath pick the endpoint class first; higher combined priority breaks ties within comparable endpoints.")} type="number" value={String(endpoint.priority ?? 0)} onChange={(value) => props.onUpdate({ ...endpoint, priority: Math.trunc(Number(value || 0)) })} />
          <MultiSelectField label={props.t("crypto_suites", "Crypto suites")} help={props.t("help_endpoint_crypto_suites", "Endpoint-level crypto suite allowlist. Empty inherits the transport policy list.")} clearLabel={props.t("clear", "Clear")} values={endpoint.security?.crypto_suites} options={cryptoSuiteOptions()} onChange={(values) => props.onUpdate({ ...endpoint, security: { ...(endpoint.security || {}), crypto_suites: values } })} />
          <Field label={props.t("local_bind_source_ip", "Source IP")} help={props.t("help_local_bind_source_ip", "Local underlay source IP used when dialing this endpoint. Leave empty to let the OS route choose.")} placeholder="192.0.2.10" value={endpoint.local_bind?.source_ip || ""} onChange={(value) => props.onUpdate({ ...endpoint, local_bind: { ...(endpoint.local_bind || {}), source_ip: value } })} />
          <Field label={props.t("local_bind_iface", "Source iface")} help={props.t("help_local_bind_iface", "Linux interface name used with SO_BINDTODEVICE for outbound dials. Requires privileges.")} placeholder="eth0" value={endpoint.local_bind?.iface || ""} onChange={(value) => props.onUpdate({ ...endpoint, local_bind: { ...(endpoint.local_bind || {}), iface: value } })} />
          <SelectField label={props.t("transport_profile", "Transport profile")} help={props.t("help_endpoint_transport_profile", "Endpoint-level profile override advertised to peers.")} value={endpoint.transport_profile?.profile || ""} options={transportProfileOptions()} onChange={(value) => props.onUpdate({ ...endpoint, transport_profile: { ...(endpoint.transport_profile || {}), profile: value } })} />
          <SelectField label={props.t("datapath", "Datapath")} help={props.t("help_endpoint_transport_datapath", "Endpoint-level datapath override advertised to peers.")} value={endpoint.transport_profile?.datapath || ""} options={transportDatapathOptions()} onChange={(value) => props.onUpdate({ ...endpoint, transport_profile: { ...(endpoint.transport_profile || {}), datapath: value } })} />
          <SelectField label={props.t("profile_encryption", "Profile encryption")} help={props.t("help_endpoint_profile_encryption", "Endpoint-level encryption advertised with the transport profile.")} value={endpoint.transport_profile?.encryption || ""} options={encryptionOptions()} onChange={(value) => props.onUpdate({ ...endpoint, transport_profile: { ...(endpoint.transport_profile || {}), encryption: value } })} />
          <SelectField label={props.t("profile_crypto_placement", "Profile crypto")} help={props.t("help_endpoint_profile_crypto_placement", "Endpoint-level crypto placement advertised with the transport profile.")} value={endpoint.transport_profile?.crypto_placement || ""} options={["", "auto", "userspace", "kernel"]} onChange={(value) => props.onUpdate({ ...endpoint, transport_profile: { ...(endpoint.transport_profile || {}), crypto_placement: value } })} />
          <Field label={props.t("profile_features", "Profile capabilities")} help={props.t("help_profile_features", "Low-level transport capability flags advertised to peers. Leave empty unless a specific transport implementation requires them.")} textarea value={joinLines(endpoint.transport_profile?.features)} onChange={(value) => props.onUpdate({ ...endpoint, transport_profile: { ...(endpoint.transport_profile || {}), features: splitLines(value) } })} />
          {props.scope === "local" && <EndpointAccessFields t={props.t} endpoint={endpoint} onUpdate={props.onUpdate} />}
        </div>
      </details>
    </>
  );
}

function EndpointAccessFields(props: { t: Translate; endpoint: EndpointConfig; onUpdate: (endpoint: EndpointConfig) => void }) {
  const access = props.endpoint.access || {};
  const mode = access.mode || "";
  const showAllowed = mode === "allow" || mode === "require_grant" || arrayValue(access.allowed_peers).length > 0;
  const updateAccess = (patch: NonNullable<EndpointConfig["access"]>) => props.onUpdate({ ...props.endpoint, access: { ...access, ...patch } });
  return (
    <>
      <SelectField label={props.t("access_mode", "Access mode")} help={props.t("help_access_mode", "open accepts configured IX peers; require_grant also requires an active endpoint grant unless the peer is allowlisted.")} value={mode} options={["", "open", "allow", "require_grant"]} onChange={(value) => updateAccess({ mode: value })} />
      {showAllowed && <Field label={props.t("access_allowed_peers", "Allowed peers")} help={props.t("help_access_allowed_peers", "IX IDs allowed without an endpoint grant, one per line.")} textarea value={joinLines(access.allowed_peers)} onChange={(value) => updateAccess({ allowed_peers: splitLines(value) })} />}
      <Field label={props.t("grant_default_ttl", "Grant default TTL")} help={props.t("help_grant_default_ttl", "Default TTL used when issuing grants for this endpoint.")} placeholder="24h" value={access.default_ttl || ""} onChange={(value) => updateAccess({ default_ttl: value })} />
    </>
  );
}

type TunnelConfigUI = {
  local: string;
  mtu: string;
  port: string;
  vni: string;
  underlay_if: string;
};

const tunnelFieldOrder: Array<keyof TunnelConfigUI> = ["local", "mtu", "port", "vni", "underlay_if"];

function TunnelEndpointFields(props: { t: Translate; transport?: string; value: string; onChange: (value: string) => void }) {
  const config = parseTunnelConfigUI(props.value);
  const update = (key: keyof TunnelConfigUI, value: string) => {
    props.onChange(formatTunnelConfigUI({ ...config, [key]: value }, props.transport));
  };
  return (
    <div className="tunnel-fields config-wide">
      <Field label={props.t("tunnel_local_underlay", "Local underlay")} help={props.t("help_tunnel_local_underlay", "This host's public or underlay IPv4 address advertised for negotiated GRE/IPIP/VXLAN links.")} placeholder="198.18.0.1" value={config.local} onChange={(value) => update("local", value)} />
      <Field label={props.t("mtu", "MTU")} help={props.t("help_tunnel_mtu", "Optional tunnel interface MTU. Empty lets TrustIX derive it from the underlay and transport.")} type="number" placeholder="1450" value={config.mtu} onChange={(value) => update("mtu", value)} />
      <Field label={props.t("port", "Port")} help={props.t("help_tunnel_port", "Optional UDP port for VXLAN or tunnel transports that use an outer port.")} type="number" placeholder={props.transport === "vxlan" ? "4789" : ""} value={config.port} onChange={(value) => update("port", value)} />
      {props.transport === "vxlan" && <Field label={props.t("vni", "VNI")} help={props.t("help_tunnel_vni", "VXLAN Network Identifier used when creating the VXLAN interface.")} type="number" placeholder="7" value={config.vni} onChange={(value) => update("vni", value)} />}
      <Field label={props.t("underlay_iface", "Underlay")} help={props.t("help_tunnel_underlay_if", "Optional Linux underlay interface name for VXLAN or tunnel creation.")} placeholder="ens18" value={config.underlay_if} onChange={(value) => update("underlay_if", value)} />
    </div>
  );
}

function parseTunnelConfigUI(raw: string): TunnelConfigUI {
  const values: TunnelConfigUI = {
    local: "",
    mtu: "",
    port: "",
    vni: "",
    underlay_if: "",
  };
  const source = String(raw || "").includes("://") ? String(raw || "").split("://", 2)[1] : String(raw || "");
  if (source && !source.includes("=")) {
    values.local = source.trim();
    return values;
  }
  for (const field of source.split(",")) {
    const [rawKey, ...rest] = field.split("=");
    const key = rawKey?.trim().toLowerCase();
    const value = rest.join("=").trim();
    if (!key || !value) {
      continue;
    }
    if (key === "underlay_iface" || key === "dev" || key === "link") {
      values.underlay_if = value;
      continue;
    }
    if (tunnelFieldOrder.includes(key as keyof TunnelConfigUI)) {
      values[key as keyof TunnelConfigUI] = value;
    }
  }
  return values;
}

function formatTunnelConfigUI(config: TunnelConfigUI, transport?: string): string {
  const fields: string[] = [];
  const add = (key: keyof TunnelConfigUI, wireKey = key) => {
    const value = String(config[key] || "").trim();
    if (value) {
      fields.push(`${wireKey}=${value}`);
    }
  };
  add("local");
  add("mtu");
  add("port");
  if (transport === "vxlan") {
    add("vni");
  }
  add("underlay_if");
  return fields.join(",");
}

function ConfigPeerTable(props: { t: Translate; lang: string; peers: PeerConfig[]; transports: TransportMatrix | null; links: LinkStatus[]; onAdd: () => void; onUpdate: (index: number, peer: PeerConfig) => void; onRemove: (index: number) => void }) {
  const [selectedIndex, setSelectedIndex] = useState(0);
  useEffect(() => {
    if (selectedIndex >= props.peers.length) {
      setSelectedIndex(Math.max(0, props.peers.length - 1));
    }
  }, [props.peers.length, selectedIndex]);
  const selectedPeer = props.peers[selectedIndex];
  const runtimePeerEndpoints = peerRuntimeEndpointCandidates(selectedPeer, props.transports, props.links);
  const addPeerEndpoint = () => {
    if (!selectedPeer) {
      return;
    }
    const endpoints = arrayValue(selectedPeer.endpoints);
    props.onUpdate(selectedIndex, {
      ...selectedPeer,
      endpoints: [...endpoints, plaintextPerformanceEndpoint(`${selectedPeer.id || "peer"}-experimental_tcp-${endpoints.length + 1}`, { mode: "active", address: "" })],
    });
  };
  const updatePeerEndpoint = (endpointIndex: number, endpoint: EndpointConfig) => {
    if (!selectedPeer) {
      return;
    }
    const endpoints = [...arrayValue(selectedPeer.endpoints)];
    endpoints[endpointIndex] = endpoint;
    props.onUpdate(selectedIndex, { ...selectedPeer, endpoints });
  };
  const removePeerEndpoint = (endpointIndex: number) => {
    if (!selectedPeer) {
      return;
    }
    props.onUpdate(selectedIndex, { ...selectedPeer, endpoints: arrayValue(selectedPeer.endpoints).filter((_, index) => index !== endpointIndex) });
  };
  const selectedPeerHelp = props.t("help_selected_peer", "Select which static peer entry to edit. Runtime peers learned from the domain are shown separately.");
  return (
    <section className="config-section">
      <div className="config-section-head">
        <div className="section-title-row">
          <h3>{props.t("peers", "Peers")}</h3>
          <span className="muted">{props.peers.length}</span>
        </div>
        <Button variant="ghost" onClick={() => { props.onAdd(); setSelectedIndex(props.peers.length); }} title={props.t("add_static_peer_note", "Creates a static peer in desired config. Dynamic IX members still come from membership admission.")}><Plus size={15} />{props.t("add_peer", "Add static peer")}</Button>
      </div>
      {props.peers.length ? (
        <div className="config-split">
          <div className="config-list compact-config-list">
            <label className="field compact-selector">
              <span title={selectedPeerHelp}>{props.t("selected_peer", "Selected peer")}<small aria-label={selectedPeerHelp}>?</small></span>
              <select className="input" value={selectedIndex} onChange={(event) => setSelectedIndex(Number(event.currentTarget.value))}>
                {props.peers.map((peer, index) => <option key={`${peer.id}-${index}`} value={index}>{peer.id || `${props.t("peer", "Peer")} ${index + 1}`}</option>)}
              </select>
            </label>
            {props.peers.map((peer, index) => (
              <button key={`${peer.id}-${index}`} type="button" className={`config-list-row ${index === selectedIndex ? "is-selected" : ""}`} onClick={() => setSelectedIndex(index)}>
                <strong>{peer.id || props.t("peer", "Peer")}</strong>
                <span>{compactList([peer.domain, peer.control_api], "-")}</span>
                <span>{peerEndpointCandidates(peer, props.transports, props.links).length} {props.t("endpoints", "Endpoints")} · {arrayValue(peer.allowed_prefixes).length} {props.t("routes", "Routes")}</span>
              </button>
            ))}
          </div>
          {selectedPeer && (
            <div className="config-card peer-config-card">
              <Field label={props.t("ix", "IX")} help={props.t("help_peer_ix", "Static peer IX ID. Dynamic admitted IX members do not need to be duplicated here.")} value={selectedPeer.id || ""} onChange={(value) => props.onUpdate(selectedIndex, { ...selectedPeer, id: value })} />
              <Field label={props.t("domain", "Domain")} help={props.t("help_peer_domain", "Peer domain ID. Leave aligned with the local domain for same-domain IX peers.")} value={selectedPeer.domain || ""} onChange={(value) => props.onUpdate(selectedIndex, { ...selectedPeer, domain: value })} />
              <Field label={props.t("control_api", "Control API")} help={props.t("help_peer_control_api", "Peer control API URL used for config sync and membership exchange.")} value={selectedPeer.control_api || ""} onChange={(value) => props.onUpdate(selectedIndex, { ...selectedPeer, control_api: value })} />
              <Field label={props.t("allowed_prefixes", "Allowed prefixes")} help={props.t("help_peer_allowed_prefixes", "Static prefixes this peer is allowed to advertise. Admission route authorizations are preferred for dynamic IX members.")} textarea value={joinLines(selectedPeer.allowed_prefixes)} onChange={(value) => props.onUpdate(selectedIndex, { ...selectedPeer, allowed_prefixes: splitLines(value) })} />
              <div className="peer-endpoint-editor config-wide">
                <div className="subhead">
                  <strong>{props.t("static_peer_endpoints", "Static peer endpoints")}</strong>
                  <Button variant="ghost" onClick={addPeerEndpoint}><Plus size={15} />{props.t("add_endpoint", "Add endpoint")}</Button>
                </div>
                <PeerEndpointEditorList t={props.t} endpoints={arrayValue(selectedPeer.endpoints)} onUpdate={updatePeerEndpoint} onRemove={removePeerEndpoint} />
              </div>
              {runtimePeerEndpoints.length ? (
                <div className="peer-endpoint-list config-wide">
                  <div className="subhead">
                    <strong>{props.t("runtime_peer_endpoints", "Runtime peer endpoints")}</strong>
                    <span className="readonly-note">{props.t("peer_endpoints_runtime_note", "Learned from peer advertisements and live negotiation.")}</span>
                  </div>
                  <PeerEndpointReadonlyList t={props.t} lang={props.lang} endpoints={runtimePeerEndpoints} />
                </div>
              ) : null}
              <div className="form-actions">
                <Button variant="danger" onClick={() => props.onRemove(selectedIndex)}><Trash2 size={15} />{props.t("remove", "Remove")}</Button>
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className="empty-row">{props.t("no_peer", "No peer")}</div>
      )}
    </section>
  );
}

function PeerEndpointEditorList(props: { t: Translate; endpoints: EndpointConfig[]; onUpdate: (index: number, endpoint: EndpointConfig) => void; onRemove: (index: number) => void }) {
  const [selectedIndex, setSelectedIndex] = useState(0);
  useEffect(() => {
    if (selectedIndex >= props.endpoints.length) {
      setSelectedIndex(Math.max(0, props.endpoints.length - 1));
    }
  }, [props.endpoints.length, selectedIndex]);
  const selectedEndpoint = props.endpoints[selectedIndex];
  return props.endpoints.length ? (
    <div className="peer-endpoint-split">
      <div className="config-list compact-config-list peer-endpoint-nav">
        {props.endpoints.map((endpoint, index) => (
          <button key={index} type="button" className={`config-list-row ${index === selectedIndex ? "is-selected" : ""}`} onClick={() => setSelectedIndex(index)}>
            <strong>{endpoint.name || props.t("endpoint", "Endpoint")}</strong>
            <span>{compactList([endpoint.transport, endpoint.mode || "active", endpoint.security?.encryption, endpoint.enabled === false ? props.t("disabled", "Disabled") : props.t("enabled", "Enabled")], "-")}</span>
            <span>{endpointAddressSummary(endpoint, props.t)}</span>
          </button>
        ))}
      </div>
      {selectedEndpoint && (
        <div className="peer-endpoint-card">
          <EndpointConfigFields t={props.t} scope="peer" endpoint={selectedEndpoint} onUpdate={(endpoint) => props.onUpdate(selectedIndex, endpoint)} />
          <div className="form-actions">
            <Button variant="danger" onClick={() => props.onRemove(selectedIndex)}><Trash2 size={15} />{props.t("remove", "Remove")}</Button>
          </div>
        </div>
      )}
    </div>
  ) : <div className="empty-row">{props.t("no_endpoint", "No endpoint")}</div>;
}

type PeerEndpointCandidate = EndpointConfig & {
  usable?: boolean;
  kernel_compatible?: boolean;
  security_compatible?: boolean;
  profile_compatible?: boolean;
  profile?: string;
  datapath?: string;
  features?: string[];
  encryption?: string;
  crypto_placements?: string[];
  active_sessions?: number;
  current_flows?: number;
  health?: string;
  rtt?: number;
  source?: string;
};

function peerEndpointCandidates(peer: PeerConfig | undefined | null, transports: TransportMatrix | null, links: LinkStatus[]): PeerEndpointCandidate[] {
  if (!peer?.id) {
    return [];
  }
  const staticEndpoints = arrayValue(peer.endpoints) as PeerEndpointCandidate[];
  const runtimeEndpoints = arrayValue(transports?.peer_endpoints).filter((endpoint) => endpoint.peer === peer.id) as PeerEndpointCandidate[];
  const linkEndpoints = arrayValue(links.find((link) => link.peer === peer.id)?.endpoints) as PeerEndpointCandidate[];
  return mergedPeerEndpointList(staticEndpoints, runtimeEndpoints, linkEndpoints).map((endpoint) => {
    const runtime = runtimeEndpoints.find((item) => item.name === endpoint.name);
    const linkRuntime = linkEndpoints.find((item) => item.name === endpoint.name);
    return {
      ...endpoint,
      ...runtime,
      ...linkRuntime,
      security: {
        ...(endpoint.security || {}),
        encryption: runtime?.encryption || linkRuntime?.encryption || endpoint.security?.encryption,
        crypto_placements: arrayValue(runtime?.crypto_placements).length ? arrayValue(runtime?.crypto_placements) : arrayValue(linkRuntime?.crypto_placements),
      },
      profile: runtime?.profile || linkRuntime?.profile || endpoint.transport_profile?.profile,
      datapath: runtime?.datapath || linkRuntime?.datapath || endpoint.transport_profile?.datapath,
      features: arrayValue(runtime?.features).length ? arrayValue(runtime?.features) : arrayValue(linkRuntime?.features).length ? arrayValue(linkRuntime?.features) : arrayValue(endpoint.transport_profile?.features),
      source: staticEndpoints.some((item) => item.name === endpoint.name) ? "static" : "negotiated",
    };
  });
}

function peerRuntimeEndpointCandidates(peer: PeerConfig | undefined | null, transports: TransportMatrix | null, links: LinkStatus[]): PeerEndpointCandidate[] {
  if (!peer?.id) {
    return [];
  }
  const runtimeEndpoints = arrayValue(transports?.peer_endpoints).filter((endpoint) => endpoint.peer === peer.id) as PeerEndpointCandidate[];
  const linkEndpoints = arrayValue(links.find((link) => link.peer === peer.id)?.endpoints) as PeerEndpointCandidate[];
  return mergedPeerEndpointList([], runtimeEndpoints, linkEndpoints).map((endpoint) => {
    const runtime = runtimeEndpoints.find((item) => item.name === endpoint.name);
    const linkRuntime = linkEndpoints.find((item) => item.name === endpoint.name);
    return {
      ...endpoint,
      ...runtime,
      ...linkRuntime,
      security: {
        ...(endpoint.security || {}),
        encryption: runtime?.encryption || linkRuntime?.encryption || endpoint.security?.encryption,
        crypto_placements: arrayValue(runtime?.crypto_placements).length ? arrayValue(runtime?.crypto_placements) : arrayValue(linkRuntime?.crypto_placements),
      },
      profile: runtime?.profile || linkRuntime?.profile || endpoint.transport_profile?.profile,
      datapath: runtime?.datapath || linkRuntime?.datapath || endpoint.transport_profile?.datapath,
      features: arrayValue(runtime?.features).length ? arrayValue(runtime?.features) : arrayValue(linkRuntime?.features).length ? arrayValue(linkRuntime?.features) : arrayValue(endpoint.transport_profile?.features),
      source: "negotiated",
    };
  });
}

function peerEndpointCandidatesByID(peerID: string | undefined, desired: DesiredConfig, transports: TransportMatrix | null, links: LinkStatus[]): PeerEndpointCandidate[] {
  if (!peerID) {
    return [];
  }
  const peer = arrayValue(desired.peers).find((item) => item.id === peerID);
  const link = links.find((item) => item.peer === peerID);
  const dynamicPeer = peer || link
    ? peer || {
      id: peerID,
      domain: link?.domain,
      control_api: link?.control_api,
      endpoints: [],
      allowed_prefixes: arrayValue(link?.routes).map((route) => route.prefix || "").filter(Boolean),
    }
    : null;
  return peerEndpointCandidates(dynamicPeer, transports, links);
}

function PeerEndpointReadonlyList(props: { t: Translate; lang: string; endpoints: PeerEndpointCandidate[] }) {
  return (
    <div className="readonly-endpoint-list">
      {props.endpoints.map((endpoint, index) => {
        const suites = compactList([arrayValue(endpoint.security?.crypto_suites).join("/"), arrayValue(endpoint.security?.crypto_placements).join("/")], "");
        const runtime = compactList([
          endpoint.usable != null ? (endpoint.usable ? props.t("usable", "Usable") : props.t("not_usable", "Not usable")) : "",
          endpoint.kernel_compatible === false ? "no-kernel" : endpoint.kernel_compatible === true ? "kernel" : "",
          endpoint.profile_compatible === false ? "profile-mismatch" : endpoint.profile_compatible === true ? "profile-ok" : "",
          endpoint.active_sessions != null ? `${endpoint.active_sessions} ${props.t("sessions", "Sessions")}` : "",
          endpoint.rtt ? `rtt ${formatDurationNanos(endpoint.rtt, props.lang)}` : "",
        ], "");
        const profile = compactList([endpoint.profile, endpoint.datapath, arrayValue(endpoint.features).join("/")], "");
        const meta = compactList([
          endpoint.transport,
          endpoint.mode,
          endpoint.priority ? `prio ${endpoint.priority}` : "",
          endpoint.encryption || endpoint.security?.encryption,
          profile,
          suites,
          runtime,
          endpoint.enabled === false ? props.t("disabled", "Disabled") : props.t("enabled", "Enabled"),
        ], "-");
        return (
          <div className="readonly-endpoint-card" key={`${endpoint.name}-${index}`}>
            <div className="readonly-endpoint-main">
              <strong>{endpoint.name || props.t("endpoint", "Endpoint")}</strong>
              <span title={meta}>{meta}</span>
              <span title={endpointAddressSummary(endpoint, props.t)}>{endpointAddressSummary(endpoint, props.t)}</span>
            </div>
            <span className="readonly-chip">{endpoint.source === "static" ? props.t("static", "Static") : props.t("negotiated", "Negotiated")}</span>
          </div>
        );
      })}
    </div>
  );
}

function ConfigRoutePolicy(props: { t: Translate; routePolicy: NonNullable<DesiredConfig["route_policy"]>; onUpdate: (routePolicy: DesiredConfig["route_policy"]) => void }) {
  const policy = props.routePolicy || {};
  const update = (next: DesiredConfig["route_policy"]) => props.onUpdate({ ...policy, ...(next || {}) });
  return (
    <section className="config-section">
      <div className="config-section-head">
        <div className="section-title-row">
          <h3>{props.t("route_policy", "Route policy")}</h3>
        </div>
      </div>
      <div className="form-grid">
        <CheckField
          label={props.t("transit_forwarding", "Transit forwarding")}
          help={props.t("help_transit_forwarding", "Allow packets received from another IX to be forwarded to a third IX by this node. Disable on edge nodes that must not carry transit traffic.")}
          checked={policy.transit_forwarding !== false}
          onChange={(value) => update({ transit_forwarding: value })}
        />
        <CheckField
          label={props.t("import_transit_routes", "Import transit routes")}
          help={props.t("help_import_transit_routes", "Install dynamic routes learned indirectly through another IX. Direct peer and local LAN routes are still allowed.")}
          checked={policy.import_transit_routes !== false}
          onChange={(value) => update({ import_transit_routes: value })}
        />
        <Field
          label={props.t("import_prefixes", "Import prefixes")}
          help={props.t("help_import_prefixes", "Optional CIDR allowlist for dynamic route imports. Empty allows non-default advertised prefixes.")}
          textarea
          value={joinLines(policy.import_prefixes)}
          onChange={(value) => update({ import_prefixes: splitLines(value) })}
        />
        <Field
          label={props.t("export_prefixes", "Export prefixes")}
          help={props.t("help_export_prefixes", "Optional CIDR allowlist for prefixes this IX advertises to peers. Empty allows local advertised prefixes except default routes.")}
          textarea
          value={joinLines(policy.export_prefixes)}
          onChange={(value) => update({ export_prefixes: splitLines(value) })}
        />
        <Field
          label={props.t("dynamic_metric", "Dynamic metric")}
          help={props.t("help_dynamic_metric", "Metric added to imported dynamic routes. Lower metrics win when multiple routes match.")}
          type="number"
          value={String(policy.dynamic_metric || "")}
          onChange={(value) => update({ dynamic_metric: Number(value || 0) })}
        />
      </div>
    </section>
  );
}

function ConfigRouteTable(props: { t: Translate; lang: string; desired: DesiredConfig; transports: TransportMatrix | null; links: LinkStatus[]; routes: RouteConfig[]; runtimeRoutes: RouteView[]; onAdd: () => void; onUpdate: (index: number, route: RouteConfig) => void; onRemove: (index: number) => void; onPromote: (route: RouteView) => number }) {
  const peers = routePeerOptions(props.desired, undefined, props.links);
  const [selectedIndex, setSelectedIndex] = useState(0);
  useEffect(() => {
    if (selectedIndex >= props.routes.length) {
      setSelectedIndex(Math.max(0, props.routes.length - 1));
    }
  }, [props.routes.length, selectedIndex]);
  const selectedRoute = props.routes[selectedIndex];
  return (
    <section className="config-section">
      <div className="config-section-head">
        <div className="section-title-row">
          <h3>{props.t("static_routes", "Static routes")}</h3>
          <span className="muted">{props.routes.length}</span>
        </div>
        <Button variant="ghost" onClick={() => { props.onAdd(); setSelectedIndex(props.routes.length); }}><Plus size={15} />{props.t("add_route", "Add route")}</Button>
      </div>
      {props.routes.length ? (
        <div className="config-split">
          <div className="config-list compact-config-list">
            {props.routes.map((route, index) => (
              <button key={`${route.prefix}-${index}`} type="button" className={`config-list-row ${index === selectedIndex ? "is-selected" : ""}`} onClick={() => setSelectedIndex(index)}>
                <strong>{route.prefix || props.t("route", "Route")}</strong>
                <span>{compactList([route.kind || "unicast", route.next_hop, route.endpoint || props.t("auto", "Auto")], "-")}</span>
                <span>{compactList([route.owner, route.metric != null ? `metric ${route.metric}` : ""], "-")}</span>
              </button>
            ))}
          </div>
          {selectedRoute && (() => {
            const endpointOptions = ["", ...Array.from(new Set([
              ...peerEndpointCandidatesByID(selectedRoute.next_hop, props.desired, props.transports, props.links).map((endpoint) => endpoint.name || "").filter(Boolean),
              selectedRoute.endpoint || "",
            ].filter(Boolean)))];
            return (
              <div className="config-card route-config-card">
                <Field label={props.t("prefix", "Prefix")} help={props.t("help_route_prefix", "Destination CIDR prefix for this route.")} value={selectedRoute.prefix || ""} onChange={(value) => props.onUpdate(selectedIndex, { ...selectedRoute, prefix: value })} />
                <SelectField label={props.t("kind", "Kind")} help={props.t("help_route_kind", "unicast forwards traffic; local terminates it here; blackhole/reject intentionally drop matching traffic.")} value={selectedRoute.kind || "unicast"} options={["unicast", "local", "blackhole", "reject"]} onChange={(value) => props.onUpdate(selectedIndex, { ...selectedRoute, kind: value })} />
                <SelectField label={props.t("owner", "Owner")} help={props.t("help_route_owner", "IX that owns the destination prefix. For transit routes, owner is the downstream/destination IX and next hop is the immediate IX to send packets to.")} value={selectedRoute.owner || ""} options={["", ...peers]} onChange={(value) => props.onUpdate(selectedIndex, { ...selectedRoute, owner: value })} />
                <SelectField label={props.t("next_hop", "Next hop")} help={props.t("help_route_next_hop", "IX ID that should receive traffic for this prefix.")} value={selectedRoute.next_hop || ""} options={["", ...peers]} onChange={(value) => props.onUpdate(selectedIndex, { ...selectedRoute, next_hop: value, owner: selectedRoute.owner || value })} />
                <SelectField label={props.t("endpoint", "Endpoint")} help={props.t("help_route_endpoint", "Preferred endpoint for this route. Empty lets transport policy choose among usable endpoints.")} value={selectedRoute.endpoint || ""} options={endpointOptions} onChange={(value) => props.onUpdate(selectedIndex, { ...selectedRoute, endpoint: value })} />
                <Field label={props.t("policy", "Policy")} help={props.t("help_route_policy", "Optional route policy name. Empty uses the default policy selection.")} value={selectedRoute.policy || ""} onChange={(value) => props.onUpdate(selectedIndex, { ...selectedRoute, policy: value })} />
                <Field label={props.t("metric", "Metric")} help={props.t("help_route_metric", "Lower metric wins among otherwise comparable routes.")} type="number" value={String(selectedRoute.metric ?? 100)} onChange={(value) => props.onUpdate(selectedIndex, { ...selectedRoute, metric: Number(value || 0) })} />
                {selectedRoute.owner && selectedRoute.next_hop && selectedRoute.owner !== selectedRoute.next_hop ? (
                  <div className="field-hint config-wide">{props.t("transit_route_hint", "Transit route: this prefix belongs to the owner IX, and packets are sent to the next-hop IX first.")}</div>
                ) : null}
                <div className="form-actions">
                  <Button variant="danger" onClick={() => props.onRemove(selectedIndex)}><Trash2 size={15} />{props.t("remove", "Remove")}</Button>
                </div>
              </div>
            );
          })()}
        </div>
      ) : (
        <div className="empty-row">{props.t("no_static_route", "No static route")}</div>
      )}
      <RuntimeRouteList t={props.t} lang={props.lang} routes={props.runtimeRoutes} staticRoutes={props.routes} onPromote={(route) => setSelectedIndex(props.onPromote(route))} />
    </section>
  );
}

function RuntimeRouteList(props: { t: Translate; lang: string; routes: RouteView[]; staticRoutes: RouteConfig[]; onPromote: (route: RouteView) => void }) {
  return (
    <div className="runtime-route-panel">
      <div className="config-section-head">
        <div className="section-title-row">
          <h3>{props.t("runtime_routes", "Runtime routes")}</h3>
          <span className="muted">{formatNumber(props.routes.length, props.lang)}</span>
        </div>
        <span className="readonly-note">{props.t("learned_readonly", "Learned from peer advertisements")}</span>
      </div>
      <p className="panel-note inline-note">{props.t("runtime_routes_note", "Read-only routes currently selected by the control plane. They can come from local LAN advertisements, devices, static routes, or peer advertisements.")}</p>
      {props.routes.length ? (
        <div className="readonly-route-list">
          {props.routes.map((route, index) => {
            const owner = route.owner || route.next_hop || "";
            const via = route.next_hop && route.next_hop !== owner ? route.next_hop : "";
            const targetIndex = staticRouteTargetIndex(props.staticRoutes, route);
            const exactIndex = staticRouteExactIndex(props.staticRoutes, route);
            const promotable = runtimeRoutePromotable(route);
            const meta = compactList([
              route.kind || "unicast",
              routeSourceLabel(props.t, route),
              owner ? `${props.t("owner", "Owner")} ${owner}` : "",
              via ? `${props.t("via", "Via")} ${via}` : "",
              route.endpoint || props.t("auto", "Auto"),
              route.metric != null ? `metric ${route.metric}` : "",
            ], "-");
            return (
              <div className="readonly-route-row" key={`${route.prefix || "route"}-${route.next_hop || ""}-${index}`}>
                <strong title={route.prefix || ""}>{route.prefix || props.t("route", "Route")}</strong>
                <span title={meta}>{meta}</span>
                <div className="readonly-route-actions">
                  {exactIndex >= 0 || route.source === "static" ? (
                    <span className="readonly-chip">{props.t("already_static", "Already static")}</span>
                  ) : promotable ? (
                    <Button variant="ghost" title={props.t("help_promote_runtime_route", "Copy this learned runtime route into desired static routes, then edit and apply it.")} onClick={() => props.onPromote(route)}>
                      <Plus size={15} />{targetIndex >= 0 ? props.t("update_static_route", "Update static") : props.t("promote_to_static", "Make static")}
                    </Button>
                  ) : (
                    <span className="readonly-chip is-muted">{props.t("runtime", "Runtime")}</span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="empty-row">{props.t("no_runtime_route", "No runtime route")}</div>
      )}
    </div>
  );
}

export function DoctorView(props: { t: Translate; lang: string; doctor: DoctorCheck[]; status: StatusPayload | null; routes: RouteView[]; routePolicy: RoutePolicyStatus | null; kernelCapabilities: KernelCapabilitiesPayload | null }) {
  const domainIX = props.status?.domain_ix || {};
  const prefixes = props.status?.domain_prefixes || {};
  const routeRows = domainRouteRows(props.routes);
  const candidateRows = routeCandidateRows(props.routePolicy);
  const candidateTotal = props.routePolicy?.candidate_total ?? candidateRows.length;
  return (
    <main className="views">
      <section className="panel">
        <div className="panel-head">
          <div>
            <h2>{props.t("domain_ix", "Domain IX")}</h2>
            <p className="panel-note inline-note">{props.t("domain_ix_note", "Live T1 IX counts include this IX and directly observed IX members; downstream IX are shown separately.")}</p>
          </div>
          <Pill state={Number(domainIX.stale || 0) > 0 ? "warn" : "ok"}>{formatNumber(domainIX.t1 || 0, props.lang)}</Pill>
        </div>
        <div className="summary-grid">
          <SummaryItem label={props.t("t1_ix", "T1 IX")} value={formatNumber(domainIX.t1 || 0, props.lang)} />
          <SummaryItem label={props.t("active", "Active")} value={formatNumber(domainIX.active || 0, props.lang)} />
          <SummaryItem label={props.t("local", "Local")} value={formatNumber(domainIX.local || 0, props.lang)} />
          <SummaryItem label={props.t("direct", "Direct")} value={formatNumber(domainIX.direct || 0, props.lang)} />
          <SummaryItem label={props.t("downstream", "Downstream")} value={formatNumber(domainIX.downstream || 0, props.lang)} />
          <SummaryItem label={props.t("stale", "Stale")} value={formatNumber(domainIX.stale || 0, props.lang)} />
        </div>
      </section>
      <section className="panel">
        <div className="panel-head">
          <div>
            <h2>{props.t("domain_prefixes", "Domain prefixes")}</h2>
            <p className="panel-note inline-note">{props.t("domain_prefixes_note", "Accepted unique runtime prefixes visible to this IX, grouped by route source.")}</p>
          </div>
          <Pill state={Number(prefixes.rejected || 0) > 0 ? "warn" : "ok"}>{formatNumber(prefixes.total || 0, props.lang)}</Pill>
        </div>
        <div className="summary-grid">
          <SummaryItem label={props.t("accepted", "Accepted")} value={formatNumber(prefixes.accepted || prefixes.total || 0, props.lang)} />
          <SummaryItem label={props.t("local", "Local")} value={formatNumber(prefixes.local || 0, props.lang)} />
          <SummaryItem label={props.t("direct", "Direct")} value={formatNumber(prefixes.direct || 0, props.lang)} />
          <SummaryItem label={props.t("transit", "Transit")} value={formatNumber(prefixes.transit || 0, props.lang)} />
          <SummaryItem label={props.t("device", "Device")} value={formatNumber(prefixes.device || 0, props.lang)} />
          <SummaryItem label={props.t("rejected", "Rejected")} value={formatNumber(prefixes.rejected || 0, props.lang)} />
        </div>
      </section>
      <section className="panel">
        <div className="panel-head">
          <div>
            <h2>{props.t("domain_route_prefixes", "Domain route prefixes")}</h2>
            <p className="panel-note inline-note">{props.t("domain_route_prefixes_note", "Runtime prefixes known to this IX, including direct peers and downstream transit LANs.")}</p>
          </div>
          <span className="muted">{formatNumber(routeRows.length, props.lang)}</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th title={props.t("prefix", "Prefix")}>{props.t("prefix", "Prefix")}</th>
                <th title={props.t("owner", "Owner")}>{props.t("owner", "Owner")}</th>
                <th title={props.t("via", "Via")}>{props.t("via", "Via")}</th>
                <th title={props.t("endpoint", "Endpoint")}>{props.t("endpoint", "Endpoint")}</th>
                <th title={props.t("source", "Source")}>{props.t("source", "Source")}</th>
                <th title={props.t("metric", "Metric")}>{props.t("metric", "Metric")}</th>
              </tr>
            </thead>
            <tbody>
              {routeRows.length ? routeRows.map((route, index) => (
                <tr key={`${route.prefix}-${route.owner}-${route.next_hop}-${route.endpoint}-${route.source}-${index}`}>
                  <td>{route.prefix || "-"}</td>
                  <td>{route.owner || "-"}</td>
                  <td>{route.next_hop || "-"}</td>
                  <td>{route.endpoint || props.t("auto", "Auto")}</td>
                  <td>{routeSourceLabel(props.t, route)}</td>
                  <td>{route.metric ?? "-"}</td>
                </tr>
              )) : <tr><td colSpan={6} className="muted">{props.t("no_route", "No route")}</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
      <section className="panel">
        <div className="panel-head">
          <div>
            <h2>{props.t("route_candidates", "Route candidates")}</h2>
            <p className="panel-note inline-note">{props.t("route_candidates_note", "Candidate paths before the runtime table picks the best route for each prefix, including accepted, shadowed, and rejected paths.")}</p>
          </div>
          <span className="muted">{formatNumber(candidateRows.length, props.lang)} / {formatNumber(candidateTotal, props.lang)}</span>
        </div>
        {props.routePolicy?.candidate_truncated && <p className="panel-note inline-note">{props.t("route_candidates_truncated", "Showing a bounded route-candidate page to keep the control UI responsive.")}</p>}
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th title={props.t("selected", "Selected")}>{props.t("selected", "Selected")}</th>
                <th title={props.t("prefix", "Prefix")}>{props.t("prefix", "Prefix")}</th>
                <th title={props.t("owner", "Owner")}>{props.t("owner", "Owner")}</th>
                <th title={props.t("via", "Via")}>{props.t("via", "Via")}</th>
                <th title={props.t("learned_from", "Learned from")}>{props.t("learned_from", "Learned from")}</th>
                <th title={props.t("source", "Source")}>{props.t("source", "Source")}</th>
                <th title={props.t("health", "Health")}>{props.t("health", "Health")}</th>
                <th title={props.t("reason", "Reason")}>{props.t("reason", "Reason")}</th>
              </tr>
            </thead>
            <tbody>
              {candidateRows.length ? candidateRows.map((candidate, index) => (
                <tr key={`${candidate.prefix}-${candidate.owner}-${candidate.next_hop}-${candidate.source}-${candidate.action}-${index}`}>
                  <td>{candidate.selected ? <Pill state="ok">{props.t("selected", "Selected")}</Pill> : <span className="muted">-</span>}</td>
                  <td>{candidate.prefix || "-"}</td>
                  <td>{candidate.owner || candidate.origin_ix || "-"}</td>
                  <td>{candidate.next_hop || "-"}</td>
                  <td>{candidate.learned_from || (candidate.direct ? props.t("direct", "Direct") : "-")}</td>
                  <td>{routeCandidateSourceLabel(props.t, candidate)}</td>
                  <td><Pill state={routeCandidateHealthState(candidate)}>{routeCandidateHealthLabel(props.t, candidate)}</Pill></td>
                  <td>{routeCandidateDetail(props.t, candidate)}</td>
                </tr>
              )) : <tr><td colSpan={8} className="muted">{props.t("no_route_candidate", "No route candidate")}</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
      <section className="panel">
        <div className="panel-head">
          <h2>{props.t("doctor", "Doctor")}</h2>
          <span className="muted">{props.doctor.length}</span>
        </div>
        <div className="table-wrap doctor-table-wrap">
          <table className="doctor-table">
            <thead>
              <tr><th title={props.t("name", "Name")}>{props.t("name", "Name")}</th><th title={props.t("health", "Health")}>{props.t("health", "Health")}</th><th title={props.t("details", "Details")}>{props.t("details", "Details")}</th></tr>
            </thead>
            <tbody>
              {props.doctor.length ? props.doctor.map((check, index) => (
                <tr key={`${check.name}-${index}`}>
                  <td>{check.name || "-"}</td>
                  <td><Pill state={doctorState(check.status)}>{check.status || "-"}</Pill></td>
                  <td>{check.detail || "-"}</td>
                </tr>
              )) : <tr><td colSpan={3} className="muted">{props.t("no_data", "No data")}</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
      <KernelCapabilitiesPanel t={props.t} lang={props.lang} status={props.status} capabilities={props.kernelCapabilities} />
    </main>
  );
}

function domainRouteRows(routes: RouteView[]): RouteView[] {
  return [...arrayValue(routes)].sort((a, b) => {
    const aKey = [routeSourceSortKey(a), a.owner || "", a.next_hop || "", a.prefix || ""].join("\0");
    const bKey = [routeSourceSortKey(b), b.owner || "", b.next_hop || "", b.prefix || ""].join("\0");
    return aKey.localeCompare(bKey);
  });
}

function routeCandidateRows(policy: RoutePolicyStatus | null | undefined): RouteCandidate[] {
  return [...arrayValue(policy?.candidates)].sort((a, b) => {
    const aKey = [
      a.prefix || "",
      a.selected ? "0" : "1",
      a.action === "accept" ? "0" : "1",
      String(a.source_priority ?? 99).padStart(3, "0"),
      String(a.metric ?? 0).padStart(8, "0"),
      a.owner || a.origin_ix || "",
      a.next_hop || "",
      a.source || "",
    ].join("\0");
    const bKey = [
      b.prefix || "",
      b.selected ? "0" : "1",
      b.action === "accept" ? "0" : "1",
      String(b.source_priority ?? 99).padStart(3, "0"),
      String(b.metric ?? 0).padStart(8, "0"),
      b.owner || b.origin_ix || "",
      b.next_hop || "",
      b.source || "",
    ].join("\0");
    return aKey.localeCompare(bKey);
  });
}

function routeSourceSortKey(route: RouteView): string {
  if (route.kind === "local" || !route.next_hop) {
    return "0-local";
  }
  if (route.source === "device_access") {
    return "1-device";
  }
  if (route.source === "static") {
    return "2-static";
  }
  if (route.source === "dynamic") {
    return "3-direct";
  }
  if (route.source === "dynamic_transit" || route.owner && route.next_hop && route.owner !== route.next_hop) {
    return "4-transit";
  }
  return "9-other";
}

function routeSourceLabel(t: Translate, route: RouteView): string {
  const rawSource = String(route.source || "").trim();
  const label = (() => {
    if (route.kind === "local" || !route.next_hop) {
      return t("local", "Local");
    }
    switch (rawSource) {
      case "device_access":
        return t("device", "Device");
      case "dynamic":
        return t("direct", "Direct");
      case "dynamic_transit":
        return t("transit", "Transit");
      case "static":
        return t("static", "Static");
      default:
        if (route.owner && route.next_hop && route.owner !== route.next_hop) {
          return t("transit", "Transit");
        }
        return rawSource || String(route.kind || "") || "-";
    }
  })();
  return rawSource && rawSource !== label ? compactList([label, rawSource], " / ") : label;
}

function routeCandidateSourceLabel(t: Translate, candidate: RouteCandidate): string {
  const route: RouteView = {
    prefix: candidate.prefix,
    owner: candidate.owner || candidate.origin_ix,
    next_hop: candidate.next_hop,
    endpoint: candidate.endpoint,
    kind: candidate.kind,
    metric: candidate.metric,
    source: candidate.source,
  };
  return routeSourceLabel(t, route);
}

function routeCandidateHealthState(candidate: RouteCandidate): string {
  switch (String(candidate.health || candidate.action || "").toLowerCase()) {
    case "ok":
    case "accept":
      return "ok";
    case "shadowed":
    case "shadow":
      return "idle";
    case "blocked":
      return "warn";
    case "down":
    case "reject":
      return "bad";
    default:
      return candidate.selected ? "ok" : "idle";
  }
}

function routeCandidateHealthLabel(t: Translate, candidate: RouteCandidate): string {
  const raw = String(candidate.health || candidate.action || "").toLowerCase();
  switch (raw) {
    case "ok":
      return t("ok", "OK");
    case "accept":
      return t("accepted", "Accepted");
    case "shadow":
    case "shadowed":
      return t("shadowed", "Shadowed");
    case "blocked":
      return t("blocked", "Blocked");
    case "down":
      return t("down", "Down");
    case "reject":
      return t("rejected", "Rejected");
    default:
      return candidate.health || candidate.action || "-";
  }
}

function routeCandidateDetail(t: Translate, candidate: RouteCandidate): string {
  const metric = candidate.metric != null ? `${t("metric", "Metric")} ${candidate.metric}` : "";
  const reason = routeCandidateReasonLabel(t, candidate.reason);
  if (candidate.reason === "configured" || candidate.reason === "shadowed_by_static") {
    return compactList([reason, metric], " · ") || "-";
  }
  return compactList([routeCandidateActionLabel(t, candidate.action), reason, metric], " · ") || "-";
}

function routeCandidateActionLabel(t: Translate, action: string | undefined): string {
  switch (String(action || "").toLowerCase()) {
    case "accept":
      return t("accepted", "Accepted");
    case "reject":
      return t("rejected", "Rejected");
    case "shadow":
      return t("shadowed", "Shadowed");
    default:
      return action || "";
  }
}

function routeCandidateReasonLabel(t: Translate, reason: string | undefined): string {
  const raw = String(reason || "").trim();
  switch (raw) {
    case "configured":
      return t("configured", "Configured");
    case "import_default":
      return t("import_default", "Import default");
    case "duplicate_prefix":
      return t("duplicate_prefix", "Duplicate prefix");
    case "shadowed_by_static":
      return t("shadowed_by_static", "Shadowed by static route");
    case "prefix_conflict":
      return t("prefix_conflict", "Prefix conflict");
    case "invalid_prefix":
      return t("invalid_prefix", "Invalid prefix");
    case "path_loop":
      return t("path_loop", "Path loop");
    case "no_usable_endpoint":
      return t("no_usable_endpoint", "No usable endpoint");
    case "no_transit_next_hop":
      return t("no_transit_next_hop", "No transit next hop");
    case "transit_import_disabled":
      return t("transit_import_disabled", "Transit import disabled");
    case "import_prefix_denied":
      return t("import_prefix_denied", "Import prefix denied");
    case "export_prefix_denied":
      return t("export_prefix_denied", "Export prefix denied");
    case "management_host_api_disabled":
      return t("management_host_api_disabled", "Host API disabled");
    case "no_control_api":
      return t("no_control_api", "No control API");
    default:
      return raw;
  }
}

export function CaptureView(props: { t: Translate; capture: Array<Record<string, unknown>>; onReload: () => void }) {
  return (
    <main className="views">
      <section className="panel">
        <div className="panel-head">
          <h2>{props.t("capture", "Capture")}</h2>
          <Button variant="ghost" onClick={props.onReload}><RefreshCw size={15} />{props.t("reload", "Reload")}</Button>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th title={props.t("hook", "Hook")}>{props.t("hook", "Hook")}</th><th title={props.t("cpu", "CPU")}>{props.t("cpu", "CPU")}</th><th title={props.t("source", "Source")}>{props.t("source", "Source")}</th><th title={props.t("destination", "Destination")}>{props.t("destination", "Destination")}</th><th title={props.t("flags", "Flags")}>{props.t("flags", "Flags")}</th></tr>
            </thead>
            <tbody>
              {props.capture.length ? props.capture.map((event, index) => (
                <tr key={index}>
                  <td>{String(event.hook || "-")}</td>
                  <td>{String(event.cpu ?? "-")}</td>
                  <td>{String(event.source_ip || event.original_source_ip || "-")}</td>
                  <td>{String(event.destination_ip || "-")}</td>
                  <td>{captureFlags(event).join(" · ") || "-"}</td>
                </tr>
              )) : <tr><td colSpan={5} className="muted">{props.t("no_data", "No data")}</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
    </main>
  );
}

function Field(props: { label: string; value: string; onChange: (value: string) => void; textarea?: boolean; type?: string; help?: string; placeholder?: string; readOnly?: boolean }) {
  return (
    <label className="field">
      <span title={props.help || undefined}>{props.label}{props.help ? <small aria-label={props.help}>?</small> : null}</span>
      {props.textarea
        ? <textarea className="input field-lines" value={props.value} placeholder={props.placeholder} readOnly={props.readOnly} onChange={(event) => { if (!props.readOnly) props.onChange(event.currentTarget.value); }} />
        : <input className="input" type={props.type || "text"} value={props.value} placeholder={props.placeholder} readOnly={props.readOnly} onChange={(event) => { if (!props.readOnly) props.onChange(event.currentTarget.value); }} />}
    </label>
  );
}

function EndpointSelectField(props: { label: string; value: string; options: string[]; onChange: (value: string) => void; addressLabel: string; address: string; help?: string; optionLabels?: Record<string, string> }) {
  return (
    <label className="field endpoint-select-field">
      <span title={props.help || undefined}>{props.label}{props.help ? <small aria-label={props.help}>?</small> : null}</span>
      <select className="input" value={props.value} onChange={(event) => props.onChange(event.currentTarget.value)}>
        {props.options.map((option) => <option key={option || "__empty"} value={option}>{props.optionLabels?.[option] || option || "-"}</option>)}
      </select>
      <em className="endpoint-address-line" title={props.address}>
        <span>{props.addressLabel}</span>
        <strong>{props.address}</strong>
      </em>
    </label>
  );
}

function SelectField(props: { label: string; value: string; options: string[]; onChange: (value: string) => void; help?: string; optionLabels?: Record<string, string> }) {
  return (
    <label className="field">
      <span title={props.help || undefined}>{props.label}{props.help ? <small aria-label={props.help}>?</small> : null}</span>
      <select className="input" value={props.value} onChange={(event) => props.onChange(event.currentTarget.value)}>
        {props.options.map((option) => <option key={option || "__empty"} value={option}>{props.optionLabels?.[option] || option || "-"}</option>)}
      </select>
    </label>
  );
}

function MultiSelectField(props: { label: string; values: string[] | undefined; options: string[]; onChange: (values: string[]) => void; help?: string; clearLabel?: string }) {
  const [open, setOpen] = useState(false);
  const values = arrayValue(props.values);
  const selected = new Set(values);
  const toggle = (option: string) => {
    const next = new Set(values);
    if (next.has(option)) {
      next.delete(option);
    } else {
      next.add(option);
    }
    props.onChange(Array.from(next));
  };
  return (
    <div className="field multi-select-field">
      <span title={props.help || undefined}>{props.label}{props.help ? <small aria-label={props.help}>?</small> : null}</span>
      <button type="button" className="input multi-select-trigger" onClick={() => setOpen((current) => !current)}>
        <span>{values.length ? values.join(", ") : "-"}</span>
      </button>
      {open && (
        <div className="multi-select-menu">
          {props.options.map((option) => (
            <label key={option} className="multi-select-option">
              <input type="checkbox" checked={selected.has(option)} onChange={() => toggle(option)} />
              <span>{option}</span>
            </label>
          ))}
          <div className="multi-select-actions">
            <button type="button" onClick={() => props.onChange([])}>{props.clearLabel || "Clear"}</button>
          </div>
        </div>
      )}
    </div>
  );
}

function CheckField(props: { label: string; checked: boolean; onChange: (checked: boolean) => void; help?: string }) {
  return (
    <label className="check-field">
      <input type="checkbox" checked={props.checked} onChange={(event) => props.onChange(event.currentTarget.checked)} />
      <span title={props.help || undefined}>{props.label}{props.help ? <small aria-label={props.help}>?</small> : null}</span>
    </label>
  );
}

function endpointAddressSummary(endpoint: EndpointConfig, t: Translate): string {
  if (isTunnelTransport(endpoint.transport)) {
    const parsed = parseTunnelConfigUI(endpoint.address || endpoint.listen || "");
    return compactList([parsed.local ? `local ${parsed.local}` : "", parsed.mtu ? `mtu ${parsed.mtu}` : "", parsed.port ? `port ${parsed.port}` : "", parsed.vni ? `vni ${parsed.vni}` : ""], t("negotiated", "Negotiated"));
  }
  const bind = compactList([endpoint.local_bind?.source_ip, endpoint.local_bind?.iface], "/");
  return compactList([endpoint.listen || endpoint.address || "-", bind ? `${t("bind", "Bind")} ${bind}` : ""], " · ");
}

function compactBuild(build: StatusPayload["build"]): string {
  return [build?.version, build?.commit?.slice(0, 12), build?.built_at].filter(Boolean).join(" · ") || "-";
}

function compactListener(listener: ListenerStatus | undefined): string {
  return [listener?.listen, listener?.scope, listener?.error].filter(Boolean).join(" · ") || "-";
}

function compactDNSStatus(status: StatusPayload["dns"], t: Translate): string {
  if (!status?.enabled) {
    return t("disabled", "Disabled");
  }
  const runtime = status.running ? t("dns_running", "Running") : t("dns_not_running", "Not running");
  const mode = arrayValue(status.upstreams).length ? t("dns_forwarding", "Forwarding") : t("dns_split_only", "Split-only");
  const dnsmasq = status.dnsmasq?.enabled ? compactList([t("openwrt_dnsmasq", "OpenWrt dnsmasq"), status.dnsmasq.applied ? t("applied", "Applied") : t("pending", "Pending"), status.dnsmasq.error], " ") : "";
  return compactList([runtime, status.listen, status.domain, mode, dnsmasq, status.error], " · ");
}

function compactAdvancedObject(value: Record<string, unknown> | undefined): string {
  const entries = Object.entries(value || {}).filter(([, item]) => item != null && item !== "");
  if (!entries.length) {
    return "-";
  }
  return entries.slice(0, 6).map(([key, item]) => {
    if (Array.isArray(item)) {
      return `${key}(${item.length})`;
    }
    if (typeof item === "object") {
      return key;
    }
    return `${key}: ${String(item)}`;
  }).join(" · ");
}

function compactTransportList(transports: string[]): string {
  if (!transports.length) {
    return "-";
  }
  const shown = transports.slice(0, 4);
  const hidden = transports.length - shown.length;
  return hidden > 0 ? `${shown.join(", ")} +${hidden}` : shown.join(", ");
}

function routeProbeDefaultDestination(prefix: string): string {
  return String(prefix || "").trim().split("/", 1)[0] || "";
}

function isTunnelTransport(transport: string | undefined): boolean {
  return transport === "gre" || transport === "ipip" || transport === "vxlan";
}

function edgeTransportLabel(edge: TopologyEdge, t: Translate): string {
  if (!edge.transportCount) {
    return t("no_endpoint", "No endpoint");
  }
  if (edge.activeTransportSessions > 0) {
    return `${edge.activeTransportSessions}/${edge.transportCount} ${t("active", "Active")}`;
  }
  if (edge.usableTransportCount > 0) {
    return `${edge.usableTransportCount}/${edge.transportCount} ${t("usable", "Usable")}`;
  }
  return `${edge.transportCount} ${t("transports", "Transports")}`;
}

function doctorState(status: string | undefined): string {
  switch (String(status || "").toLowerCase()) {
    case "ok":
      return "ok";
    case "degraded":
    case "bad":
    case "error":
      return "bad";
    default:
      return "warn";
  }
}

function captureFlags(event: Record<string, unknown>): string[] {
  return [
    event.nat_translated ? "NAT" : "",
    event.checksum_normalized ? "CSUM" : "",
    event.gso_segment_length ? `GSO ${event.gso_segment_length}` : "",
    event.packet_length ? `len ${event.packet_length}` : "",
    event.sample_length ? `sample ${event.sample_length}` : "",
  ].filter(Boolean) as string[];
}

function numberFieldValue(value: number | undefined): string {
  return value == null || Number.isNaN(Number(value)) ? "" : String(value);
}

function numberOrUndefined(value: string): number | undefined {
  const trimmed = String(value || "").trim();
  if (!trimmed) {
    return undefined;
  }
  const parsed = Number(trimmed);
  return Number.isFinite(parsed) ? Math.trunc(parsed) : undefined;
}

function nonNegativeNumberOrUndefined(value: string): number | undefined {
  const parsed = numberOrUndefined(value);
  return parsed == null ? undefined : Math.max(0, parsed);
}
