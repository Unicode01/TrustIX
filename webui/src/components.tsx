import { useEffect, useMemo, useRef, useState, type MouseEvent, type PointerEvent, type ReactNode, type WheelEvent } from "react";
import { ArrowLeft, Check, Circle, Copy, KeyRound, Languages, Move, Network, Plus, RefreshCw, Route, Save, ShieldCheck, Trash2, Upload, ZoomIn, ZoomOut } from "lucide-react";
import type {
  DeviceAccessIssueResponse,
  DeviceAccessPayload,
  DesiredConfig,
  DoctorCheck,
  EndpointGrant,
  EndpointGrantIssueRequest,
  ExperimentalTCPStatus,
  EndpointConfig,
  KernelModuleStatus,
  KernelCapabilitiesPayload,
  KernelPlacementStatus,
  KernelRXStageStatus,
  KernelTransportStatus,
  KernelUDPStatus,
  LANConfig,
  ListenerStatus,
  LinkStatus,
  PeerConfig,
  RouteConfig,
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
import { arrayValue, compactList, cryptoSuiteOptions, encryptionOptions, formatBytes, formatDurationNanos, formatNumber, formatTime, joinLines, splitLines, transportDatapathOptions, transportOptions, transportProfileOptions, transportToggleOptions } from "./utils";

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
      <div className="summary-value">{props.value}</div>
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
  return {
    name: module.name || t("kernel_module", "Kernel module"),
    state,
    badge: loaded ? module.capability_tier || module.state || t("loaded", "Loaded") : module.state || t("not_loaded", "Not loaded"),
    meta: compactList([
      module.mode,
      module.loaded ? t("loaded", "Loaded") : t("not_loaded", "Not loaded"),
      module.abi_version ? `ABI ${module.abi_version}` : "",
      featureText,
    ], " · "),
    detail: module.capability_reason || module.reason || module.parameters || "",
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

export function AccessView(props: {
  t: Translate;
  lang: string;
  desired: DesiredConfig | null;
  deviceAccess: DeviceAccessPayload | null;
  endpointGrants: EndpointGrant[];
  issuedDevice: DeviceAccessIssueResponse | null;
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
  }, [deviceEndpoint, deviceEndpointCandidates, grantEndpoint, grantEndpointCandidates, grantPeer, peers]);
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
  const deviceDelegatedParentPrefixes = arrayValue(props.desired?.lan?.advertise);
  const deviceReservedPrefixes = [
    props.deviceAccess?.address_pool || "",
    ...arrayValue(props.desired?.routes).map((route) => route.prefix || ""),
  ];
  const deviceAdvertiseWarnings = validateDeviceAdvertisePrefixes(props.t, deviceAdvertisePrefixes, [
    ...deviceReservedPrefixes,
  ], deviceDelegatedParentPrefixes, arrayValue(props.desired?.route_policy?.export_prefixes));
  const deviceIssueDisabled = !deviceID.trim() || !deviceEndpoint || !resolvedDeviceEndpointAddress || deviceAdvertiseWarnings.length > 0;
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
          <div className="result">{props.message}</div>
        </div>

        <div className="access-grid">
          <section className="panel">
            <div className="panel-head">
              <h2>{props.t("issue_device_certificate", "Issue device certificate")}</h2>
              <ShieldCheck size={18} />
            </div>
            <div className="access-form device-issue-form">
              <div className="device-issue-primary config-wide">
                <Field label={props.t("device_id", "Device ID")} placeholder="laptop-01" value={deviceID} onChange={setDeviceID} />
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
                <Field label={props.t("ttl", "TTL")} placeholder="720h" value={deviceTTL} onChange={setDeviceTTL} />
                <Field label={props.t("server_name", "Server name")} value={deviceServerName} onChange={setDeviceServerName} />
                <SelectField label={props.t("encryption", "Encryption")} value={deviceEncryption} options={encryptionOptions()} onChange={setDeviceEncryption} />
              </div>
              <Field label={props.t("device_advertise_prefixes", "Device announced prefixes")} help={props.t("help_device_advertise_prefixes", "CIDR prefixes this device or downstream IX is allowed to announce into the TrustIX domain. Use independent downstream LANs by default; use a more-specific subprefix of this IX LAN only when intentionally delegating that subnet to the device. The upstream IX forwards by authorization and does not let the device decide global routes. Leave empty for a single leased /32 only.")} textarea placeholder="10.99.0.0/24" value={deviceAdvertisePrefixes} onChange={setDeviceAdvertisePrefixes} />
              {deviceAdvertiseWarnings.length > 0 && <div className="field-hint warn config-wide">{deviceAdvertiseWarnings.join(" · ")}</div>}
              <details className="endpoint-advanced-fields config-wide">
                <summary>{props.t("device_issue_advanced", "Advanced device config")}</summary>
                <div className="endpoint-advanced-grid">
                  <Field label={props.t("public_endpoint_override", "Public endpoint override")} help={props.t("help_public_endpoint_override", "Optional address written into the generated client config instead of the selected endpoint address. Use domain:port or IP:port.")} placeholder={props.t("placeholder_endpoint_address", "203.0.113.10:7000")} value={deviceAddress} onChange={setDeviceAddress} />
                  <Field label={props.t("bootstrap_routes", "Bootstrap routes")} help={props.t("help_bootstrap_routes", "Optional static client routes written into the generated config. Normal route updates are sent by the IX after the device connects.")} textarea value={deviceBootstrapRoutes} onChange={setDeviceBootstrapRoutes} />
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
                <Field label={props.t("client_config_json", "Client config JSON")} textarea value={props.issuedDevice.client_config_json || ""} onChange={() => undefined} />
                <div className="form-actions">
                  <Button variant="ghost" onClick={() => props.onCopy(props.issuedDevice?.client_config_json || "", props.t("client_config_json", "Client config JSON"))}><Copy size={15} />{props.t("copy_config", "Copy config")}</Button>
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
              <Field label={props.t("ttl", "TTL")} placeholder="24h" value={grantTTL} onChange={setGrantTTL} />
              <Field label={props.t("reason", "Reason")} value={grantReason} onChange={setGrantReason} />
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
          <div className="result">{props.message}</div>
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
        <Field label={props.t("domain_id", "Domain ID")} value={cfg.domain?.id || ""} onChange={(value) => props.onDesired({ ...cfg, domain: { ...(cfg.domain || {}), id: value } })} />
        <Field label={props.t("ix_id", "IX ID")} value={cfg.ix?.id || ""} onChange={(value) => props.onDesired({ ...cfg, ix: { ...(cfg.ix || {}), id: value } })} />
        <Field label={props.t("control_api", "Control API")} value={cfg.ix?.control_api || ""} onChange={(value) => props.onDesired({ ...cfg, ix: { ...(cfg.ix || {}), control_api: value } })} />
        <Field label={props.t("advertise_prefixes", "Advertise prefixes")} textarea value={joinLines(localAdvertisePrefixes(cfg))} onChange={(value) => props.onDesired({ ...cfg, lan: { ...(cfg.lan || {}), advertise: splitLines(value) } })} />
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
      <Field label={props.t("ix", "IX")} value={props.peer.id || ""} onChange={(value) => updatePeer({ ...props.peer, id: value })} />
      <Field label={props.t("domain", "Domain")} value={props.peer.domain || ""} onChange={(value) => updatePeer({ ...props.peer, domain: value })} />
      <Field label={props.t("control_api", "Control API")} value={props.peer.control_api || ""} onChange={(value) => updatePeer({ ...props.peer, control_api: value })} />
      <Field label={props.t("allowed_prefixes", "Allowed prefixes")} textarea value={joinLines(props.peer.allowed_prefixes)} onChange={(value) => updatePeer({ ...props.peer, allowed_prefixes: splitLines(value) })} />
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
              <select className="inline-select" value={route.next_hop || ""} onChange={(event) => setRouteNextHop(index, event.currentTarget.value)}>
                <option value="">{props.t("none", "None")}</option>
                {routePeers.map((id) => <option key={id} value={id}>{id}</option>)}
              </select>
              <select className="inline-select" value={route.endpoint || ""} onChange={(event) => setRouteEndpoint(index, event.currentTarget.value)}>
                <option value="">{props.t("auto", "Auto")}</option>
                {routeEndpointOptions.map((endpoint) => <option key={endpoint.name || ""} value={endpoint.name || ""}>{compactList([endpoint.name, endpoint.transport], "-")}</option>)}
              </select>
            </div>
          );
        })}
        {props.edge.routes.filter((route) => !routeIndexes.some((item) => routesMatch(item.route, route))).map((route, index) => (
          <div key={`runtime-${route.prefix}-${route.owner}-${route.next_hop}-${index}`} className="route-inline-row">
            <button type="button" className="route-inline-main" disabled>
              <strong>{route.prefix || "-"}</strong>
              <span>{routeSummary(route)}</span>
            </button>
            <span className="readonly-chip">{props.t("runtime", "Runtime")}</span>
          </div>
        ))}
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
              <label className="mini-toggle">
                <input type="checkbox" checked={state.published} onChange={(event) => updateEndpoint(index, setEndpointPublishedForPeer(endpoint, props.peerId, event.currentTarget.checked))} />
                <span>{state.published ? props.t("published", "Published") : props.t("hidden", "Hidden")}</span>
              </label>
              <select className="inline-select" value={state.mode} onChange={(event) => updateEndpoint(index, setEndpointPublishModeForPeer(endpoint, props.peerId, event.currentTarget.value))}>
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
      <Field label={props.t("prefix", "Prefix")} value={route.prefix || ""} onChange={(value) => updateRoute({ ...route, prefix: value })} />
      <SelectField label={props.t("kind", "Kind")} value={route.kind || "unicast"} options={["unicast", "local", "blackhole", "reject"]} onChange={(value) => updateRoute({ ...route, kind: value })} />
      <SelectField label={props.t("next_hop", "Next hop")} value={route.next_hop || ""} options={["", ...peerOptions]} onChange={(value) => updateRoute({ ...route, next_hop: value, owner: route.owner || value })} />
      <Field label={props.t("owner", "Owner")} value={route.owner || ""} onChange={(value) => updateRoute({ ...route, owner: value })} />
      <SelectField label={props.t("endpoint", "Endpoint")} value={route.endpoint || ""} options={endpointOptions} onChange={(value) => updateRoute({ ...route, endpoint: value })} />
      <Field label={props.t("policy", "Policy")} value={route.policy || ""} onChange={(value) => updateRoute({ ...route, policy: value })} />
      <Field label={props.t("metric", "Metric")} type="number" value={String(route.metric ?? 100)} onChange={(value) => updateRoute({ ...route, metric: Number(value || 0) })} />
      <div className="diagnostic-box">
        <Field label={props.t("probe_destination", "Probe destination")} value={target} onChange={setProbeDestination} />
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
  links: LinkStatus[];
  text: string;
  dirty: boolean;
  message: string;
  onDesired: (desired: DesiredConfig) => void;
  onText: (text: string) => void;
  onReload: () => void;
  onValidate: () => void;
  onApply: () => void;
  onCopy: () => void;
}) {
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
          </div>
        </div>
        {props.desired ? (
          <VisualConfig t={props.t} lang={props.lang} desired={props.desired} transports={props.transports} links={props.links} onDesired={props.onDesired} />
        ) : (
          <div className="muted">{props.t("loading", "Loading")}</div>
        )}
        <details className="advanced-config">
          <summary>{props.t("advanced_json", "Advanced JSON")}</summary>
          <textarea className="editor" value={props.text} spellCheck={false} onChange={(event) => props.onText(event.currentTarget.value)} />
        </details>
        <div className="result">{props.message}</div>
      </section>
    </main>
  );
}

type ConfigSectionID = "basic" | "connectivity" | "routing" | "performance" | "advanced";

function VisualConfig(props: { t: Translate; lang: string; desired: DesiredConfig; transports: TransportMatrix | null; links: LinkStatus[]; onDesired: (desired: DesiredConfig) => void }) {
  const cfg = props.desired;
  const [activeSection, setActiveSection] = useState<ConfigSectionID>("basic");
  const updateEndpoint = (index: number, next: EndpointConfig) => {
    const endpoints = [...arrayValue(cfg.endpoints)];
    endpoints[index] = next;
    props.onDesired({ ...cfg, endpoints });
  };
  const addEndpoint = () => {
    const endpoints = [...arrayValue(cfg.endpoints), {
      name: "local-udp",
      transport: "udp",
      mode: "passive",
      listen: "0.0.0.0:7000",
      enabled: true,
      security: {},
    }];
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
        endpoints: [{ name: `${id}-udp`, transport: "udp", mode: "active", address: "", enabled: true, security: {} }],
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
  const sections: ConfigSectionID[] = ["basic", "connectivity", "routing", "performance", "advanced"];
  const endpoints = arrayValue(cfg.endpoints);
  const peers = arrayValue(cfg.peers);
  const routes = arrayValue(cfg.routes);
  return (
    <div className="config-visual">
      <ConfigSummaryStrip t={props.t} lang={props.lang} desired={cfg} transports={props.transports} links={props.links} />
      <nav className="config-task-nav" aria-label={props.t("config_sections", "Config sections")}>
        {sections.map((section) => (
          <button key={section} type="button" className={`config-task-tab ${activeSection === section ? "is-active" : ""}`} onClick={() => setActiveSection(section)}>
            <span>{configSectionLabel(props.t, section)}</span>
            <strong>{configSectionValue(props.t, cfg, props.transports, props.links, section)}</strong>
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
              <Field label={props.t("ix_cert", "IX certificate")} help={props.t("help_ix_cert", "Path to the IX certificate used for node identity, trust propagation, and optional management TLS.")} value={cfg.ix?.cert || ""} onChange={(value) => props.onDesired({ ...cfg, ix: { ...(cfg.ix || {}), cert: value } })} />
              <Field label={props.t("ix_key", "IX key")} help={props.t("help_ix_key", "Path to the private key matching the IX certificate.")} value={cfg.ix?.key || ""} onChange={(value) => props.onDesired({ ...cfg, ix: { ...(cfg.ix || {}), key: value } })} />
            </div>
          </section>

          <ConfigLANTable t={props.t} lang={props.lang} desired={cfg} onDesired={props.onDesired} />
        </>
      )}

      {activeSection === "connectivity" && (
        <>
          <ConfigEndpointTable t={props.t} endpoints={endpoints} onAdd={addEndpoint} onUpdate={updateEndpoint} onRemove={removeEndpoint} />
          <ConfigPeerTable t={props.t} lang={props.lang} peers={peers} transports={props.transports} links={props.links} onAdd={addPeer} onUpdate={updatePeer} onRemove={removePeer} />
        </>
      )}

      {activeSection === "routing" && (
        <ConfigRouteTable t={props.t} desired={cfg} transports={props.transports} links={props.links} routes={routes} onAdd={addRoute} onUpdate={updateRoute} onRemove={removeRoute} />
      )}

      {activeSection === "performance" && (
        <section className="config-section">
          <div className="config-section-head"><h3>{props.t("transport_policy", "Transport policy")}</h3></div>
          <div className="form-grid">
            <Field label={props.t("transport_mode", "Transport mode")} help={props.t("help_transport_policy_mode", "Overall transport preference, such as auto or a specific policy mode.")} value={cfg.transport_policy?.mode || ""} onChange={(value) => props.onDesired({ ...cfg, transport_policy: { ...(cfg.transport_policy || {}), mode: value } })} />
            <SelectField label={props.t("profile", "Profile")} help={props.t("help_transport_profile", "Default transport behavior profile. Use performance only after both IX endpoints support the advertised features.")} value={cfg.transport_policy?.profile || ""} options={transportProfileOptions()} onChange={(value) => props.onDesired({ ...cfg, transport_policy: { ...(cfg.transport_policy || {}), profile: value } })} />
            <SelectField label={props.t("datapath", "Datapath")} help={props.t("help_transport_datapath", "Preferred datapath for transports that support multiple implementations.")} value={cfg.transport_policy?.datapath || ""} options={transportDatapathOptions()} onChange={(value) => props.onDesired({ ...cfg, transport_policy: { ...(cfg.transport_policy || {}), datapath: value } })} />
            <SelectField label={props.t("encryption", "Encryption")} help={props.t("help_transport_policy_encryption", "Default encryption direction. secure encrypts both directions; plaintext disables transport encryption.")} value={cfg.transport_policy?.encryption || ""} options={encryptionOptions()} onChange={(value) => props.onDesired({ ...cfg, transport_policy: { ...(cfg.transport_policy || {}), encryption: value } })} />
            <SelectField label={props.t("kernel_transport", "Kernel transport")} help={props.t("help_transport_policy_kernel_transport_mode", "Controls whether UDP/TCP/GRE/IPIP datapath should prefer or require the kernel fast path.")} value={cfg.transport_policy?.kernel_transport?.mode || ""} options={["", "auto", "prefer_kernel", "require_kernel", "disabled"]} onChange={(value) => props.onDesired({ ...cfg, transport_policy: { ...(cfg.transport_policy || {}), kernel_transport: { ...(cfg.transport_policy?.kernel_transport || {}), mode: value } } })} />
            <SelectField label={props.t("crypto_placement", "Crypto placement")} help={props.t("help_transport_policy_crypto_placement", "Where payload encryption runs: auto, userspace fallback, or kernel when supported.")} value={cfg.transport_policy?.crypto_placement || ""} options={["", "auto", "userspace", "kernel"]} onChange={(value) => props.onDesired({ ...cfg, transport_policy: { ...(cfg.transport_policy || {}), crypto_placement: value } })} />
            <Field label={props.t("mtu", "MTU")} help={props.t("help_transport_policy_mtu", "Datapath MTU. Leave 0 to let TrustIX choose from the interface and transport.")} type="number" value={String(cfg.transport_policy?.mtu || "")} onChange={(value) => props.onDesired({ ...cfg, transport_policy: { ...(cfg.transport_policy || {}), mtu: Number(value || 0) } })} />
            <MultiSelectField label={props.t("crypto_suites", "Crypto suites")} help={props.t("help_transport_policy_crypto_suites", "Allowed crypto suites in preference order.")} clearLabel={props.t("clear", "Clear")} values={cfg.transport_policy?.crypto_suites} options={cryptoSuiteOptions()} onChange={(values) => props.onDesired({ ...cfg, transport_policy: { ...(cfg.transport_policy || {}), crypto_suites: values } })} />
            <CheckField label={props.t("session_warmup", "Session warmup")} checked={Boolean(cfg.transport_policy?.session_pool?.warmup)} onChange={(value) => props.onDesired({ ...cfg, transport_policy: { ...(cfg.transport_policy || {}), session_pool: { ...(cfg.transport_policy?.session_pool || {}), warmup: value } } })} />
          </div>
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
        <section className="config-section">
          <div className="config-section-head"><h3>{props.t("advanced_config", "Advanced config")}</h3></div>
          <AdvancedConfigSummary t={props.t} desired={cfg} />
        </section>
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
              <span>{props.t("selected_lan", "Selected LAN")}</span>
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

function LANConfigFields(props: { t: Translate; lan: LANConfig; source: "legacy" | "lans"; onUpdate: (lan: LANConfig) => void }) {
  const lan = props.lan;
  const update = (patch: Partial<LANConfig>) => props.onUpdate({ ...lan, ...patch });
  const updateNAT = (patch: NonNullable<LANConfig["nat"]>) => update({ nat: { ...(lan.nat || {}), ...patch } });
  const updateDeviceAccess = (patch: NonNullable<LANConfig["device_access"]>) => update({ device_access: { ...(lan.device_access || {}), ...patch } });
  return (
    <>
      <div className="lan-field-group lan-field-group-main">
        <Field label={props.t("lan_id", "LAN ID")} help={props.t("help_lan_id", "Stable LAN identifier used by primary_lan_id and diagnostics.")} value={lan.id || (props.source === "legacy" ? "lan" : "")} onChange={(value) => update({ id: value })} />
        <SelectField label={props.t("lan_type", "LAN type")} help={props.t("help_lan_type", "local is a private LAN behind this IX; trusted_public is a directly reachable trusted network segment.")} value={lan.type || "local"} options={["local", "trusted_public"]} onChange={(value) => update({ type: value })} />
        <SelectField label={props.t("lan_mode", "LAN mode")} help={props.t("help_lan_mode", "routed advertises LAN prefixes directly; nat rewrites LAN traffic behind this IX.")} value={lan.mode || "routed"} options={["routed", "nat"]} onChange={(value) => update({ mode: value })} />
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
      <div className="lan-field-group lan-field-group-nat">
        <Field label={props.t("nat_max_bindings", "NAT max bindings")} type="number" value={numberFieldValue(lan.nat?.max_bindings)} onChange={(value) => updateNAT({ max_bindings: numberOrUndefined(value) })} />
        <Field label={props.t("nat_binding_ttl", "NAT binding TTL")} placeholder="5m" value={lan.nat?.binding_ttl || ""} onChange={(value) => updateNAT({ binding_ttl: value })} />
      </div>
      <div className="lan-field-group lan-field-group-access">
        <CheckField label={props.t("device_access", "Device access")} checked={Boolean(lan.device_access?.enabled)} onChange={(value) => updateDeviceAccess({ enabled: value })} />
        <Field label={props.t("device_address_pool", "Device address pool")} placeholder="10.82.0.128/25" value={lan.device_access?.address_pool || ""} onChange={(value) => updateDeviceAccess({ address_pool: value })} />
        <Field label={props.t("device_lease_ttl", "Device lease TTL")} placeholder="24h" value={lan.device_access?.lease_ttl || ""} onChange={(value) => updateDeviceAccess({ lease_ttl: value })} />
      </div>
      <div className="lan-field-group lan-field-group-system">
        <CheckField label={props.t("manage_address", "Manage address")} checked={Boolean(lan.manage_address)} onChange={(value) => update({ manage_address: value })} />
        <CheckField label={props.t("manage_forwarding", "Manage forwarding")} checked={Boolean(lan.manage_forwarding)} onChange={(value) => update({ manage_forwarding: value })} />
        <CheckField label={props.t("manage_rp_filter", "Manage rp_filter")} checked={Boolean(lan.manage_rp_filter)} onChange={(value) => update({ manage_rp_filter: value })} />
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

function ConfigSummaryStrip(props: { t: Translate; lang: string; desired: DesiredConfig; transports: TransportMatrix | null; links: LinkStatus[] }) {
  const cfg = props.desired;
  const endpointCount = arrayValue(cfg.endpoints).length;
  const peerCount = arrayValue(cfg.peers).length;
  const routeCount = arrayValue(cfg.routes).length;
  const activeSessions = arrayValue(props.transports?.sessions).length || props.links.reduce((sum, link) => sum + arrayValue(link.sessions).length, 0);
  const lanEntries = effectiveLANEntries(cfg);
  const primaryID = cfg.primary_lan_id || lanEntries[0]?.id || "";
  return (
    <div className="config-summary-strip">
      <SummaryItem label={props.t("identity", "Identity")} value={compactList([cfg.domain?.id, cfg.ix?.id], "-")} />
      <SummaryItem label={props.t("lans", "LANs")} value={`${formatNumber(lanEntries.length, props.lang)} · ${primaryID || "-"}`} />
      <SummaryItem label={props.t("connectivity", "Connectivity")} value={`${formatNumber(endpointCount, props.lang)} ${props.t("endpoints", "Endpoints")} · ${formatNumber(peerCount, props.lang)} ${props.t("peers", "Peers")}`} />
      <SummaryItem label={props.t("routing", "Routing")} value={`${formatNumber(routeCount, props.lang)} ${props.t("routes", "Routes")} · ${formatNumber(activeSessions, props.lang)} ${props.t("sessions", "sessions")}`} />
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

function configSectionValue(t: Translate, cfg: DesiredConfig, transports: TransportMatrix | null, links: LinkStatus[], section: ConfigSectionID): string {
  switch (section) {
    case "basic":
      return compactList([cfg.ix?.id, `${effectiveLANEntries(cfg).length} ${t("lans", "LANs")}`], "-");
    case "connectivity":
      return `${arrayValue(cfg.endpoints).length} / ${arrayValue(cfg.peers).length}`;
    case "routing":
      return `${arrayValue(cfg.routes).length} ${t("routes", "Routes")}`;
    case "performance":
      return compactList([cfg.transport_policy?.profile, cfg.transport_policy?.datapath, cfg.transport_policy?.encryption], "-");
    case "advanced":
      return compactList([
        cfg.management ? t("management", "Management") : "",
        cfg.kernel_modules ? t("kernel", "Kernel") : "",
        arrayValue(transports?.sessions).length || links.some((link) => arrayValue(link.sessions).length) ? t("runtime", "Runtime") : "",
      ], "-");
  }
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

function AdvancedConfigSummary(props: { t: Translate; desired: DesiredConfig }) {
  const cfg = props.desired;
  const management = cfg.management || {};
  const kernelModules = cfg.kernel_modules || {};
  const trustRoots = arrayValue(cfg.domain?.trust_roots);
  const routeAuth = arrayValue(cfg.ix?.route_authorizations);
  return (
    <div className="advanced-config-summary">
      <StatusRow label={props.t("management", "Management")} value={compactAdvancedObject(management)} />
      <StatusRow label={props.t("kernel_modules", "Kernel modules")} value={compactAdvancedObject(kernelModules)} />
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
      <SelectField label={props.t("large_frames", "Large frames")} value={advanced.large_frames || ""} options={transportToggleOptions()} onChange={(value) => update({ large_frames: value })} />
      <SelectField label={props.t("gso", "GSO")} value={advanced.gso || ""} options={transportToggleOptions()} onChange={(value) => update({ gso: value })} />
      <SelectField label={props.t("gro", "GRO")} value={advanced.gro || ""} options={transportToggleOptions()} onChange={(value) => update({ gro: value })} />
      <Field label={props.t("shards", "Shards")} type="number" value={numberFieldValue(advanced.shards)} onChange={(value) => update({ shards: numberOrUndefined(value) })} />
      <Field label={props.t("max_frames", "Max frames")} type="number" value={numberFieldValue(advanced.max_frames)} onChange={(value) => update({ max_frames: numberOrUndefined(value) })} />
      <Field label={props.t("batch_bytes", "Batch bytes")} type="number" value={numberFieldValue(advanced.batch_bytes)} onChange={(value) => update({ batch_bytes: numberOrUndefined(value) })} />
      <Field label={props.t("flush_delay", "Flush delay")} placeholder="100us" value={advanced.flush_delay || ""} onChange={(value) => update({ flush_delay: value })} />
      <CheckField label={props.t("allow_unsafe", "Allow unsafe")} checked={Boolean(advanced.allow_unsafe)} onChange={(value) => update({ allow_unsafe: value })} />
      <CheckField label={props.t("allow_outer_gso_unsafe", "Allow outer GSO")} checked={Boolean(advanced.allow_outer_gso_unsafe)} onChange={(value) => update({ allow_outer_gso_unsafe: value })} />
      <CheckField label={props.t("allow_checksum_skip", "Allow checksum skip")} checked={Boolean(advanced.allow_checksum_skip)} onChange={(value) => update({ allow_checksum_skip: value })} />
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
          <SelectField label={props.t("transport", "Transport")} value={profile.transport || ""} options={transportOptions()} onChange={(value) => updateProfile(index, { ...profile, transport: value })} />
          <SelectField label={props.t("profile", "Profile")} value={profile.profile || ""} options={transportProfileOptions()} onChange={(value) => updateProfile(index, { ...profile, profile: value })} />
          <SelectField label={props.t("datapath", "Datapath")} value={profile.datapath || ""} options={transportDatapathOptions()} onChange={(value) => updateProfile(index, { ...profile, datapath: value })} />
          <SelectField label={props.t("encryption", "Encryption")} value={profile.encryption || ""} options={encryptionOptions()} onChange={(value) => updateProfile(index, { ...profile, encryption: value })} />
          <SelectField label={props.t("crypto_placement", "Crypto placement")} value={profile.crypto_placement || ""} options={["", "auto", "userspace", "kernel"]} onChange={(value) => updateProfile(index, { ...profile, crypto_placement: value })} />
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
              <button key={`${endpoint.name}-${index}`} type="button" className={`config-list-row ${index === selectedIndex ? "is-selected" : ""}`} onClick={() => setSelectedIndex(index)}>
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
    <div className="config-card endpoint-config-card" key={props.endpoint.name || "endpoint"}>
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
      <Field label={props.t("priority", "Priority")} help={props.t("help_endpoint_priority", "Integer exchanged during endpoint negotiation. Higher local plus remote priority is tried first.")} type="number" value={String(endpoint.priority ?? 0)} onChange={(value) => props.onUpdate({ ...endpoint, priority: Math.trunc(Number(value || 0)) })} />
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
      <CheckField label={props.t("enabled", "Enabled")} checked={endpoint.enabled !== false} onChange={(value) => props.onUpdate({ ...endpoint, enabled: value })} />
      <details className="endpoint-advanced-fields config-wide">
        <summary>{props.t("endpoint_advanced", "Endpoint advanced")}</summary>
        <div className="endpoint-advanced-grid">
          <MultiSelectField label={props.t("crypto_suites", "Crypto suites")} clearLabel={props.t("clear", "Clear")} values={endpoint.security?.crypto_suites} options={cryptoSuiteOptions()} onChange={(values) => props.onUpdate({ ...endpoint, security: { ...(endpoint.security || {}), crypto_suites: values } })} />
          <Field label={props.t("local_bind_source_ip", "Source IP")} help={props.t("help_local_bind_source_ip", "Local underlay source IP used when dialing this endpoint. Leave empty to let the OS route choose.")} placeholder="192.0.2.10" value={endpoint.local_bind?.source_ip || ""} onChange={(value) => props.onUpdate({ ...endpoint, local_bind: { ...(endpoint.local_bind || {}), source_ip: value } })} />
          <Field label={props.t("local_bind_iface", "Source iface")} help={props.t("help_local_bind_iface", "Linux interface name used with SO_BINDTODEVICE for outbound dials. Requires privileges.")} placeholder="eth0" value={endpoint.local_bind?.iface || ""} onChange={(value) => props.onUpdate({ ...endpoint, local_bind: { ...(endpoint.local_bind || {}), iface: value } })} />
          <SelectField label={props.t("transport_profile", "Transport profile")} help={props.t("help_endpoint_transport_profile", "Endpoint-level profile override advertised to peers.")} value={endpoint.transport_profile?.profile || ""} options={transportProfileOptions()} onChange={(value) => props.onUpdate({ ...endpoint, transport_profile: { ...(endpoint.transport_profile || {}), profile: value } })} />
          <SelectField label={props.t("datapath", "Datapath")} value={endpoint.transport_profile?.datapath || ""} options={transportDatapathOptions()} onChange={(value) => props.onUpdate({ ...endpoint, transport_profile: { ...(endpoint.transport_profile || {}), datapath: value } })} />
          <SelectField label={props.t("profile_encryption", "Profile encryption")} value={endpoint.transport_profile?.encryption || ""} options={encryptionOptions()} onChange={(value) => props.onUpdate({ ...endpoint, transport_profile: { ...(endpoint.transport_profile || {}), encryption: value } })} />
          <SelectField label={props.t("profile_crypto_placement", "Profile crypto")} value={endpoint.transport_profile?.crypto_placement || ""} options={["", "auto", "userspace", "kernel"]} onChange={(value) => props.onUpdate({ ...endpoint, transport_profile: { ...(endpoint.transport_profile || {}), crypto_placement: value } })} />
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
      <Field label={props.t("mtu", "MTU")} type="number" placeholder="1450" value={config.mtu} onChange={(value) => update("mtu", value)} />
      <Field label={props.t("port", "Port")} type="number" placeholder={props.transport === "vxlan" ? "4789" : ""} value={config.port} onChange={(value) => update("port", value)} />
      {props.transport === "vxlan" && <Field label={props.t("vni", "VNI")} type="number" placeholder="7" value={config.vni} onChange={(value) => update("vni", value)} />}
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
      endpoints: [...endpoints, { name: `${selectedPeer.id || "peer"}-udp-${endpoints.length + 1}`, transport: "udp", mode: "active", address: "", enabled: true, security: {} }],
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
              <span>{props.t("selected_peer", "Selected peer")}</span>
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
              <Field label={props.t("ix", "IX")} value={selectedPeer.id || ""} onChange={(value) => props.onUpdate(selectedIndex, { ...selectedPeer, id: value })} />
              <Field label={props.t("domain", "Domain")} value={selectedPeer.domain || ""} onChange={(value) => props.onUpdate(selectedIndex, { ...selectedPeer, domain: value })} />
              <Field label={props.t("control_api", "Control API")} value={selectedPeer.control_api || ""} onChange={(value) => props.onUpdate(selectedIndex, { ...selectedPeer, control_api: value })} />
              <Field label={props.t("allowed_prefixes", "Allowed prefixes")} textarea value={joinLines(selectedPeer.allowed_prefixes)} onChange={(value) => props.onUpdate(selectedIndex, { ...selectedPeer, allowed_prefixes: splitLines(value) })} />
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
          <button key={`${endpoint.name}-${index}`} type="button" className={`config-list-row ${index === selectedIndex ? "is-selected" : ""}`} onClick={() => setSelectedIndex(index)}>
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

function ConfigRouteTable(props: { t: Translate; desired: DesiredConfig; transports: TransportMatrix | null; links: LinkStatus[]; routes: RouteConfig[]; onAdd: () => void; onUpdate: (index: number, route: RouteConfig) => void; onRemove: (index: number) => void }) {
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
          <h3>{props.t("routes", "Routes")}</h3>
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
                <Field label={props.t("prefix", "Prefix")} value={selectedRoute.prefix || ""} onChange={(value) => props.onUpdate(selectedIndex, { ...selectedRoute, prefix: value })} />
                <SelectField label={props.t("kind", "Kind")} value={selectedRoute.kind || "unicast"} options={["unicast", "local", "blackhole", "reject"]} onChange={(value) => props.onUpdate(selectedIndex, { ...selectedRoute, kind: value })} />
                <SelectField label={props.t("next_hop", "Next hop")} value={selectedRoute.next_hop || ""} options={["", ...peers]} onChange={(value) => props.onUpdate(selectedIndex, { ...selectedRoute, next_hop: value, owner: selectedRoute.owner || value })} />
                <SelectField label={props.t("endpoint", "Endpoint")} value={selectedRoute.endpoint || ""} options={endpointOptions} onChange={(value) => props.onUpdate(selectedIndex, { ...selectedRoute, endpoint: value })} />
                <Field label={props.t("policy", "Policy")} value={selectedRoute.policy || ""} onChange={(value) => props.onUpdate(selectedIndex, { ...selectedRoute, policy: value })} />
                <Field label={props.t("metric", "Metric")} type="number" value={String(selectedRoute.metric ?? 100)} onChange={(value) => props.onUpdate(selectedIndex, { ...selectedRoute, metric: Number(value || 0) })} />
                <div className="form-actions">
                  <Button variant="danger" onClick={() => props.onRemove(selectedIndex)}><Trash2 size={15} />{props.t("remove", "Remove")}</Button>
                </div>
              </div>
            );
          })()}
        </div>
      ) : (
        <div className="empty-row">{props.t("no_route", "No route")}</div>
      )}
    </section>
  );
}

export function DoctorView(props: { t: Translate; lang: string; doctor: DoctorCheck[]; status: StatusPayload | null; routes: RouteView[]; kernelCapabilities: KernelCapabilitiesPayload | null }) {
  const domainIX = props.status?.domain_ix || {};
  const prefixes = props.status?.domain_prefixes || {};
  const routeRows = domainRouteRows(props.routes);
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

function routeSourceSortKey(route: RouteView): string {
  if (route.kind === "local" || !route.next_hop) {
    return "0-local";
  }
  if (route.source === "device_access") {
    return "1-device";
  }
  if (route.source === "dynamic") {
    return "2-direct";
  }
  if (route.source === "dynamic_transit" || route.owner && route.next_hop && route.owner !== route.next_hop) {
    return "3-transit";
  }
  if (route.source === "static") {
    return "4-static";
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

function Field(props: { label: string; value: string; onChange: (value: string) => void; textarea?: boolean; type?: string; help?: string; placeholder?: string }) {
  return (
    <label className="field">
      <span title={props.help || undefined}>{props.label}{props.help ? <small aria-label={props.help}>?</small> : null}</span>
      {props.textarea
        ? <textarea className="input field-lines" value={props.value} placeholder={props.placeholder} onChange={(event) => props.onChange(event.currentTarget.value)} />
        : <input className="input" type={props.type || "text"} value={props.value} placeholder={props.placeholder} onChange={(event) => props.onChange(event.currentTarget.value)} />}
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

function CheckField(props: { label: string; checked: boolean; onChange: (checked: boolean) => void }) {
  return (
    <label className="check-field">
      <input type="checkbox" checked={props.checked} onChange={(event) => props.onChange(event.currentTarget.checked)} />
      <span>{props.label}</span>
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
