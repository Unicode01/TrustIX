import { StrictMode, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { X } from "lucide-react";
import {
  AccessView,
  CaptureView,
  ConfigView,
  DoctorView,
  Metrics,
  NetworkView,
  OverviewView,
  routePeerEndpoint,
  routePeerOptions,
  routePeerPrefix,
  Shell,
  UnlockPanel,
  type Translate,
} from "./components";
import { APIClient } from "./api";
import {
  emptyAdminProof,
  forgetStoredAdminProof,
  hasStoredAdminProof,
  loadAdminProofMaterial,
  readStoredAdminProof,
  rememberAdminProof,
  requiresAdminProof,
  type AdminProofState,
} from "./auth";
import { loadDictionary, normalizeLang, preferredLang, type Dictionary, type Lang } from "./i18n";
import { buildTopology } from "./topology";
import type {
  Bootstrap,
  CapturePayload,
  DeviceAccessIssueRequest,
  DeviceAccessIssueResponse,
  DeviceAccessPayload,
  DesiredConfig,
  DoctorCheck,
  EndpointConfig,
  EndpointGrant,
  EndpointGrantIssueRequest,
  EndpointGrantMutationResponse,
  EndpointGrantsPayload,
  EndpointProbeResponse,
  KernelCapabilitiesPayload,
  LinksPayload,
  LinkStatus,
  PeerConfig,
  RouteProbeResponse,
  RouteTraceResponse,
  PeerView,
  RouteView,
  SelectedTopology,
  StatusPayload,
  TransportMatrix,
} from "./types";
import { cloneJSON, normalizeBase, normalizeDesiredConfig } from "./utils";
import "./styles.css";

declare global {
  interface Window {
    TRUSTIX_WEBUI?: Bootstrap;
  }
}

type Tab = "overview" | "network" | "access" | "config" | "doctor" | "capture";
type ThemeSetting = "light" | "dark" | "system";
type ToastKind = "success" | "error" | "info";
type ToastNotice = {
  id: number;
  kind: ToastKind;
  title: string;
  detail?: string;
};
type RefreshOptions = {
  silent?: boolean;
};

const bootstrap = window.TRUSTIX_WEBUI || {};

function App() {
  const [themeSetting, setThemeSetting] = useState<ThemeSetting>(() => normalizeTheme(localStorage.getItem("trustix.ui.theme")));
  const [lang, setLang] = useState<Lang>(() => normalizeLang(localStorage.getItem("trustix.ui.lang") || preferredLang()));
  const [dict, setDict] = useState<Dictionary>({});
  const [english, setEnglish] = useState<Dictionary>({});
  const [activeTab, setActiveTab] = useState<Tab>("overview");
  const [loading, setLoading] = useState(false);
  const [unlocked, setUnlocked] = useState(!requiresAdminProof(bootstrap));
  const [adminRestorePending, setAdminRestorePending] = useState(() => requiresAdminProof(bootstrap) && hasStoredAdminProof());
  const [adminProof, setAdminProof] = useState<AdminProofState>(() => emptyAdminProof());
  const [status, setStatus] = useState<StatusPayload | null>(null);
  const [doctor, setDoctor] = useState<DoctorCheck[]>([]);
  const [kernelCapabilities, setKernelCapabilities] = useState<KernelCapabilitiesPayload | null>(null);
  const [links, setLinks] = useState<LinkStatus[]>([]);
  const [peers, setPeers] = useState<PeerView[]>([]);
  const [routes, setRoutes] = useState<RouteView[]>([]);
  const [endpoints, setEndpoints] = useState<EndpointConfig[]>([]);
  const [deviceAccess, setDeviceAccess] = useState<DeviceAccessPayload | null>(null);
  const [endpointGrants, setEndpointGrants] = useState<EndpointGrant[]>([]);
  const [issuedDevice, setIssuedDevice] = useState<DeviceAccessIssueResponse | null>(null);
  const [transports, setTransports] = useState<TransportMatrix | null>(null);
  const [desired, setDesired] = useState<DesiredConfig | null>(null);
  const [configText, setConfigText] = useState("");
  const [baselineText, setBaselineText] = useState("");
  const [configMessage, setConfigMessage] = useState("");
  const [capture, setCapture] = useState<Array<Record<string, unknown>>>([]);
  const [selected, setSelected] = useState<SelectedTopology>(null);
  const [toasts, setToasts] = useState<ToastNotice[]>([]);
  const toastID = useRef(1);
  const toastTimers = useRef<number[]>([]);
  const proofRef = useRef(adminProof);
  proofRef.current = adminProof;

  const api = useMemo(() => new APIClient(normalizeBase(bootstrap.api_base), () => proofRef.current), []);
  const t: Translate = useCallback((key, fallback) => dict[key] || english[key] || fallback || key, [dict, english]);
  const locked = requiresAdminProof(bootstrap) && (!unlocked || adminRestorePending);
  const dirty = Boolean(configText && baselineText && configText !== baselineText);
  const topology = useMemo(() => buildTopology(desired, links), [desired, links]);
  const dismissToast = useCallback((id: number) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);
  const pushToast = useCallback((kind: ToastKind, title: string, detail?: string) => {
    const id = toastID.current;
    toastID.current += 1;
    setToasts((current) => [...current.slice(-3), { id, kind, title, detail }]);
    const timeout = window.setTimeout(() => dismissToast(id), kind === "error" ? 7000 : 4200);
    toastTimers.current.push(timeout);
  }, [dismissToast]);

  useEffect(() => {
    return () => {
      for (const timer of toastTimers.current) {
        window.clearTimeout(timer);
      }
    };
  }, []);

  useEffect(() => {
    void Promise.all([
      loadDictionary("en").then(setEnglish).catch(() => setEnglish({})),
      loadDictionary(lang).then(setDict).catch(() => setDict({})),
    ]);
  }, [lang]);

  useEffect(() => {
    applyTheme(themeSetting);
  }, [themeSetting]);

  useEffect(() => {
    let cancelled = false;
    async function restore() {
      const saved = readStoredAdminProof();
      if (!saved?.certPEM || !saved?.keyPEM) {
        setAdminRestorePending(false);
        return;
      }
      try {
        const proof = await loadAdminProofMaterial(saved.certPEM, saved.keyPEM, saved.certName || "Restored", saved.keyName || "Restored");
        if (cancelled) {
          return;
        }
        proof.message = t("admin_proof_restored", "Admin proof restored for this browser tab");
        setAdminProof(proof);
        setUnlocked(true);
      } catch (error) {
        forgetStoredAdminProof();
        if (!cancelled) {
          setAdminProof({ ...emptyAdminProof(), message: errorMessage(error) });
        }
      } finally {
        if (!cancelled) {
          setAdminRestorePending(false);
        }
      }
    }
    void restore();
    return () => {
      cancelled = true;
    };
  }, [t]);

  useEffect(() => {
    if (!locked) {
      void refreshAll({ silent: true });
    }
  }, [locked]);

  const refreshAll = useCallback(async (options: RefreshOptions = {}) => {
    if (requiresAdminProof(bootstrap) && !proofRef.current.ready && !unlocked) {
      return;
    }
    setLoading(true);
    try {
      const [nextStatus, nextDoctor, nextKernelCapabilities, nextLinks, nextPeers, nextRoutes, nextEndpoints, nextDeviceAccess, nextEndpointGrants, nextTransports, nextConfig] = await Promise.all([
        api.getJSON<StatusPayload>("/status"),
        api.getJSON<DoctorCheck[]>("/doctor"),
        api.getJSON<KernelCapabilitiesPayload>("/kernel/capabilities").catch(() => null),
        api.getJSON<LinksPayload>("/links"),
        api.getJSON<PeerView[] | { members?: PeerView[] }>("/peers"),
        api.getJSON<RouteView[]>("/routes"),
        api.getJSON<EndpointConfig[]>("/endpoints"),
        api.getJSON<DeviceAccessPayload>("/device-access").catch(() => null),
        api.getJSON<EndpointGrantsPayload>("/endpoint-grants").catch(() => null),
        api.getJSON<TransportMatrix>("/transports"),
        api.getJSON<DesiredConfig>("/config/desired"),
      ]);
      const normalized = normalizeDesiredConfig(nextConfig);
      const text = JSON.stringify(normalized, null, 2);
      setStatus(nextStatus || null);
      setDoctor(Array.isArray(nextDoctor) ? nextDoctor : []);
      setKernelCapabilities(nextKernelCapabilities || null);
      setLinks(Array.isArray(nextLinks?.links) ? nextLinks.links : []);
      setPeers(Array.isArray(nextPeers) ? nextPeers : Array.isArray(nextPeers?.members) ? nextPeers.members : []);
      setRoutes(Array.isArray(nextRoutes) ? nextRoutes : []);
      setEndpoints(Array.isArray(nextEndpoints) ? nextEndpoints : []);
      setDeviceAccess(nextDeviceAccess || null);
      setEndpointGrants(Array.isArray(nextEndpointGrants?.grants) ? nextEndpointGrants.grants : []);
      setTransports(nextTransports || null);
      setDesired(normalized);
      setConfigText(text);
      setBaselineText(text);
      setConfigMessage(t("ready", "Ready"));
      setUnlocked(true);
      if (!options.silent) {
        pushToast("success", t("refreshed", "Refreshed"), t("runtime_state_updated", "Runtime state updated"));
      }
    } catch (error) {
      const message = errorMessage(error);
      setConfigMessage(message);
      if (!options.silent) {
        pushToast("error", t("refresh_failed", "Refresh failed"), message);
      }
      if (requiresAdminProof(bootstrap)) {
        setAdminProof((proof) => ({ ...proof, message }));
        setUnlocked(false);
      }
    } finally {
      setLoading(false);
    }
  }, [api, pushToast, t, unlocked]);

  const refreshRuntime = useCallback(async (options: RefreshOptions = {}) => {
    setLoading(true);
    try {
      const [nextStatus, nextDoctor, nextKernelCapabilities, nextLinks, nextPeers, nextRoutes, nextEndpoints, nextDeviceAccess, nextEndpointGrants, nextTransports] = await Promise.all([
        api.getJSON<StatusPayload>("/status"),
        api.getJSON<DoctorCheck[]>("/doctor"),
        api.getJSON<KernelCapabilitiesPayload>("/kernel/capabilities").catch(() => null),
        api.getJSON<LinksPayload>("/links"),
        api.getJSON<PeerView[] | { members?: PeerView[] }>("/peers"),
        api.getJSON<RouteView[]>("/routes"),
        api.getJSON<EndpointConfig[]>("/endpoints"),
        api.getJSON<DeviceAccessPayload>("/device-access").catch(() => null),
        api.getJSON<EndpointGrantsPayload>("/endpoint-grants").catch(() => null),
        api.getJSON<TransportMatrix>("/transports"),
      ]);
      setStatus(nextStatus || null);
      setDoctor(Array.isArray(nextDoctor) ? nextDoctor : []);
      setKernelCapabilities(nextKernelCapabilities || null);
      setLinks(Array.isArray(nextLinks?.links) ? nextLinks.links : []);
      setPeers(Array.isArray(nextPeers) ? nextPeers : Array.isArray(nextPeers?.members) ? nextPeers.members : []);
      setRoutes(Array.isArray(nextRoutes) ? nextRoutes : []);
      setEndpoints(Array.isArray(nextEndpoints) ? nextEndpoints : []);
      setDeviceAccess(nextDeviceAccess || null);
      setEndpointGrants(Array.isArray(nextEndpointGrants?.grants) ? nextEndpointGrants.grants : []);
      setTransports(nextTransports || null);
      setUnlocked(true);
      if (!options.silent) {
        pushToast("success", t("refreshed", "Refreshed"), t("runtime_state_updated", "Runtime state updated"));
      }
    } catch (error) {
      const message = errorMessage(error);
      setConfigMessage(message);
      if (!options.silent) {
        pushToast("error", t("refresh_failed", "Refresh failed"), message);
      }
      if (requiresAdminProof(bootstrap)) {
        setAdminProof((proof) => ({ ...proof, message }));
        setUnlocked(false);
      }
    } finally {
      setLoading(false);
    }
  }, [api, pushToast, t]);

  const loadCapture = useCallback(async () => {
    setLoading(true);
    try {
      const payload = await api.getJSON<CapturePayload>("/capture?limit=50");
      const packets = Array.isArray(payload?.packets) ? payload.packets as unknown as Array<Record<string, unknown>> : [];
      setCapture(packets);
      pushToast("success", t("capture_loaded", "Capture loaded"), `${packets.length} ${t("packets", "packets")}`);
    } catch (error) {
      const message = errorMessage(error);
      setConfigMessage(message);
      pushToast("error", t("capture_failed", "Capture failed"), message);
    } finally {
      setLoading(false);
    }
  }, [api, pushToast, t]);

  const importAdmin = useCallback(async (certFile: File | null, keyFile: File | null) => {
    if (!certFile || !keyFile) {
      const message = t("admin_proof_select_pair", "Select Admin certificate and key");
      setAdminProof((proof) => ({ ...proof, message }));
      pushToast("info", t("admin_proof_required", "Admin proof required"), message);
      return;
    }
    try {
      const [certPEM, keyPEM] = await Promise.all([certFile.text(), keyFile.text()]);
      const proof = await loadAdminProofMaterial(certPEM, keyPEM, certFile.name, keyFile.name);
      proof.message = t("verifying_admin_proof", "Verifying Admin proof");
      setAdminProof(proof);
      rememberAdminProof(certPEM, keyPEM, certFile.name, keyFile.name);
      setUnlocked(true);
      pushToast("success", t("admin_proof_ready", "Admin proof ready"), `${certFile.name} / ${keyFile.name}`);
    } catch (error) {
      const message = errorMessage(error);
      forgetStoredAdminProof();
      setUnlocked(false);
      setAdminProof({ ...emptyAdminProof(), message });
      pushToast("error", t("admin_proof_failed", "Admin proof failed"), message);
    }
  }, [pushToast, t]);

  const clearAdmin = useCallback(() => {
    forgetStoredAdminProof();
    setAdminProof(emptyAdminProof());
    setUnlocked(!requiresAdminProof(bootstrap));
    setStatus(null);
    setDoctor([]);
    setLinks([]);
    setDesired(null);
    setConfigText("");
    setBaselineText("");
    pushToast("info", t("admin_proof_cleared", "Admin proof cleared"));
  }, [pushToast, t]);

  const updateDesired = useCallback((next: DesiredConfig) => {
    const normalized = normalizeDesiredConfig(next);
    setDesired(normalized);
    setConfigText(JSON.stringify(normalized, null, 2));
    setConfigMessage(t("edited", "Edited"));
  }, [t]);

  const updateConfigText = useCallback((text: string) => {
    setConfigText(text);
    try {
      setDesired(normalizeDesiredConfig(JSON.parse(text)));
      setConfigMessage(t("edited", "Edited"));
    } catch (error) {
      setConfigMessage(errorMessage(error));
    }
  }, [t]);

  const validateConfig = useCallback(async () => {
    setLoading(true);
    try {
      const payload = await api.postJSON<Record<string, unknown>>("/config/validate?format=json", configText);
      setConfigMessage(JSON.stringify(payload, null, 2));
      pushToast("success", t("config_valid", "Config validated"));
    } catch (error) {
      const message = errorMessage(error);
      setConfigMessage(message);
      pushToast("error", t("config_invalid", "Config validation failed"), message);
    } finally {
      setLoading(false);
    }
  }, [api, configText, pushToast, t]);

  const applyConfig = useCallback(async () => {
    setLoading(true);
    try {
      const payload = await api.postJSON<Record<string, unknown>>("/config/apply?format=json", configText);
      setConfigMessage(JSON.stringify(payload, null, 2));
      pushToast("success", t("config_applied", "Config applied"));
      await refreshAll({ silent: true });
    } catch (error) {
      const message = errorMessage(error);
      setConfigMessage(message);
      pushToast("error", t("config_apply_failed", "Config apply failed"), message);
    } finally {
      setLoading(false);
    }
  }, [api, configText, pushToast, refreshAll, t]);

  const copyConfig = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(configText);
      setConfigMessage(t("copied", "Copied"));
      pushToast("success", t("copied", "Copied"), t("config_copied", "Config copied to clipboard"));
    } catch (error) {
      const message = errorMessage(error);
      setConfigMessage(message);
      pushToast("error", t("copy_failed", "Copy failed"), message);
    }
  }, [configText, pushToast, t]);

  const copyText = useCallback(async (text: string, label: string) => {
    if (!text) {
      pushToast("info", t("nothing_to_copy", "Nothing to copy"), label);
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      pushToast("success", t("copied", "Copied"), label);
    } catch (error) {
      const message = errorMessage(error);
      setConfigMessage(message);
      pushToast("error", t("copy_failed", "Copy failed"), message);
    }
  }, [pushToast, t]);

  const issueDeviceAccess = useCallback(async (request: DeviceAccessIssueRequest) => {
    if (!request.device?.trim()) {
      const message = t("device_id_required", "Device ID is required");
      setConfigMessage(message);
      pushToast("info", t("issue_device_certificate", "Issue device certificate"), message);
      return;
    }
    setLoading(true);
    try {
      const response = await api.postJSON<DeviceAccessIssueResponse>("/device-access/issue", JSON.stringify(request));
      setIssuedDevice(response || null);
      setConfigMessage(`${t("device_certificate_issued", "Device certificate issued")}: ${response.device || request.device}`);
      pushToast("success", t("device_certificate_issued", "Device certificate issued"), response.fingerprint || response.device || request.device);
      await refreshRuntime({ silent: true });
    } catch (error) {
      const message = errorMessage(error);
      setConfigMessage(message);
      pushToast("error", t("device_certificate_issue_failed", "Device certificate issue failed"), message);
    } finally {
      setLoading(false);
    }
  }, [api, pushToast, refreshRuntime, t]);

  const issueEndpointGrant = useCallback(async (request: EndpointGrantIssueRequest) => {
    if (!request.subject_ix?.trim() || !request.endpoint?.trim()) {
      const message = t("grant_peer_endpoint_required", "Peer and endpoint are required");
      setConfigMessage(message);
      pushToast("info", t("issue_endpoint_grant", "Issue endpoint grant"), message);
      return;
    }
    setLoading(true);
    try {
      const response = await api.postJSON<EndpointGrantMutationResponse>("/endpoint-grants/issue", JSON.stringify(request));
      setConfigMessage(`${t("endpoint_grant_issued", "Endpoint grant issued")}: ${response.grant?.grant_id || request.subject_ix}`);
      pushToast("success", t("endpoint_grant_issued", "Endpoint grant issued"), compactListForMessage([request.subject_ix, request.endpoint], " / "));
      await refreshAll({ silent: true });
    } catch (error) {
      const message = errorMessage(error);
      setConfigMessage(message);
      pushToast("error", t("endpoint_grant_issue_failed", "Endpoint grant issue failed"), message);
    } finally {
      setLoading(false);
    }
  }, [api, pushToast, refreshAll, t]);

  const revokeEndpointGrant = useCallback(async (grant: EndpointGrant) => {
    if (!grant.grant_id) {
      return;
    }
    setLoading(true);
    try {
      await api.postJSON<EndpointGrantMutationResponse>("/endpoint-grants/revoke", JSON.stringify({ grant_id: grant.grant_id }));
      setConfigMessage(`${t("endpoint_grant_revoked", "Endpoint grant revoked")}: ${grant.grant_id}`);
      pushToast("success", t("endpoint_grant_revoked", "Endpoint grant revoked"), grant.grant_id);
      await refreshAll({ silent: true });
    } catch (error) {
      const message = errorMessage(error);
      setConfigMessage(message);
      pushToast("error", t("endpoint_grant_revoke_failed", "Endpoint grant revoke failed"), message);
    } finally {
      setLoading(false);
    }
  }, [api, pushToast, refreshAll, t]);

  const addPeer = useCallback(() => {
    const cfg = normalizeDesiredConfig(desired || {});
    const domain = cfg.domain?.id || cfg.ix?.domain || "";
    const peers = [...(cfg.peers || [])];
    const nextID = uniqueID("ix-new", peers.map((peer) => peer.id || ""));
    peers.push({
      id: nextID,
      domain,
      control_api: "",
      allowed_prefixes: [],
      endpoints: [{
        name: `${nextID}-udp`,
        transport: "udp",
        mode: "active",
        address: "",
        enabled: true,
        security: {},
      }],
    });
    updateDesired({ ...cfg, peers });
    setSelected({ type: "node", nodeId: nextID });
    pushToast("info", t("peer_added", "Peer added"), nextID);
  }, [desired, pushToast, t, updateDesired]);

  const addRoute = useCallback((peerId?: string) => {
    const cfg = normalizeDesiredConfig(desired || {});
    const routes = [...(cfg.routes || [])];
    const targetPeer = peerId || routePeerOptions(cfg, topology.nodes, links)[0] || "";
    routes.push({
      prefix: routePeerPrefix(targetPeer, cfg, topology.nodes, links),
      kind: "unicast",
      owner: targetPeer,
      next_hop: targetPeer,
      endpoint: routePeerEndpoint(targetPeer, cfg, links),
      policy: "",
      metric: 100,
    });
    updateDesired({ ...cfg, routes });
    setSelected({ type: "route", index: routes.length - 1 });
    pushToast("info", t("route_added", "Route added"), targetPeer || t("no_peer_selected", "No peer selected"));
  }, [desired, links, pushToast, t, topology.nodes, updateDesired]);

  const updateTopologyRoute = useCallback((ownerId: string, nextHop: string) => {
    const cfg = normalizeDesiredConfig(desired || {});
    if (!ownerId || !nextHop || ownerId === nextHop) {
      return;
    }
    const prefix = routePeerPrefix(ownerId, cfg, topology.nodes, links);
    const routes = [...(cfg.routes || [])];
    const existing = routes.findIndex((route) => (route.owner || "") === ownerId || (prefix && route.prefix === prefix));
    const nextRoute = {
      ...(existing >= 0 ? routes[existing] : {}),
      prefix: existing >= 0 ? routes[existing].prefix || prefix : prefix,
      kind: "unicast",
      owner: ownerId,
      next_hop: nextHop,
      endpoint: "",
      policy: existing >= 0 ? routes[existing].policy || "" : "",
      metric: existing >= 0 ? routes[existing].metric ?? 100 : 100,
    };
    if (existing >= 0) {
      routes[existing] = nextRoute;
      setSelected({ type: "route", index: existing });
    } else {
      routes.push(nextRoute);
      setSelected({ type: "route", index: routes.length - 1 });
    }
    updateDesired({ ...cfg, routes });
    pushToast("info", t("route_updated", "Route updated"), `${ownerId} -> ${nextHop}`);
  }, [desired, links, pushToast, t, topology.nodes, updateDesired]);

  const probeEndpoint = useCallback(async (peerId: string, endpointName: string) => {
    if (!peerId || !endpointName) {
      const message = t("endpoint_probe_missing", "Select a peer endpoint to test");
      setConfigMessage(message);
      pushToast("info", t("endpoint_probe", "Endpoint probe"), message);
      return;
    }
    setLoading(true);
    try {
      const query = new URLSearchParams({ peer: peerId, endpoint: endpointName, timeout_ms: "2000" });
      const response = await api.getJSON<EndpointProbeResponse>(`/endpoint/probe?${query.toString()}`);
      const state = response.ok ? t("reachable", "Reachable") : t("unreachable", "Unreachable");
      const rtt = response.rtt ? ` · rtt ${formatDurationForMessage(response.rtt, lang)}` : "";
      const detail = response.error ? ` · ${response.error}` : "";
      setConfigMessage(`${state}: ${response.peer || peerId}/${response.endpoint || endpointName} ${response.transport || ""}${rtt}${detail}`);
      pushToast(response.ok ? "success" : "error", state, `${response.peer || peerId}/${response.endpoint || endpointName}${rtt}${detail}`);
      await refreshRuntime({ silent: true });
    } catch (error) {
      const message = errorMessage(error);
      setConfigMessage(message);
      pushToast("error", t("endpoint_probe_failed", "Endpoint probe failed"), message);
    } finally {
      setLoading(false);
    }
  }, [api, lang, pushToast, refreshRuntime, t]);

  const probeRoute = useCallback(async (destination: string, trace = false) => {
    const dst = destination.trim();
    if (!dst) {
      const message = t("route_probe_missing", "Enter a route probe destination");
      setConfigMessage(message);
      pushToast("info", t("route_probe", "Route probe"), message);
      return;
    }
    setLoading(true);
    try {
      const query = new URLSearchParams({ dst });
      if (trace) {
        query.set("max_hops", "16");
        const response = await api.getJSON<RouteTraceResponse>(`/route/trace?${query.toString()}`);
        const hops = (response.hops || []).map((hop) => compactListForMessage([hop.index ? `${hop.index}` : "", hop.ix_id, hop.prefix, hop.next_hop ? `next ${hop.next_hop}` : "", hop.endpoint, hop.reason], " "));
        setConfigMessage(`${response.ok ? t("trace_complete", "Trace complete") : t("trace_failed", "Trace failed")}: ${response.destination || dst}${response.reason ? ` · ${response.reason}` : ""}\n${hops.join("\n") || "-"}`);
        pushToast(response.ok ? "success" : "error", response.ok ? t("trace_complete", "Trace complete") : t("trace_failed", "Trace failed"), response.destination || dst);
        return;
      }
      const response = await api.getJSON<RouteProbeResponse>(`/route/probe?${query.toString()}`);
      const candidates = (response.candidate_endpoints || []).map((endpoint) => compactListForMessage([endpoint.name, endpoint.transport, endpoint.encryption], "/")).join(", ");
      const detail = compactListForMessage([response.prefix, response.route?.next_hop ? `next ${response.route.next_hop}` : "", response.route?.endpoint ? `endpoint ${response.route.endpoint}` : "", candidates ? `candidates ${candidates}` : "", response.candidate_error, response.reason], " · ");
      setConfigMessage(`${response.ok ? t("route_probe_ok", "Route probe OK") : t("route_probe_failed", "Route probe failed")}: ${response.destination || dst}\n${detail || "-"}`);
      pushToast(response.ok ? "success" : "error", response.ok ? t("route_probe_ok", "Route probe OK") : t("route_probe_failed", "Route probe failed"), response.destination || dst);
    } catch (error) {
      const message = errorMessage(error);
      setConfigMessage(message);
      pushToast("error", t("route_probe_failed", "Route probe failed"), message);
    } finally {
      setLoading(false);
    }
  }, [api, pushToast, t]);

  const selectedFiles = adminProof.certName || adminProof.keyName
    ? `${t("selected", "Selected")}: ${adminProof.certName || "-"} / ${adminProof.keyName || "-"}`
    : "";
  const unlockStatus = adminRestorePending
    ? t("admin_proof_restoring", "Restoring Admin proof")
    : adminProof.message || t("admin_proof_missing", "No Admin proof loaded");

  const content = locked ? (
    <UnlockPanel t={t} status={unlockStatus} selected={selectedFiles} restoring={adminRestorePending} onImport={importAdmin} onClear={clearAdmin} />
  ) : (
    <>
      <Metrics t={t} lang={lang} status={status} />
      {activeTab === "overview" && <OverviewView t={t} lang={lang} status={status} doctor={doctor} links={links} onTab={(tab) => setActiveTab(tab as Tab)} />}
      {activeTab === "network" && (
        <NetworkView
          t={t}
          lang={lang}
          status={status}
          desired={desired}
          transports={transports}
          nodes={topology.nodes}
          edges={topology.edges}
          selected={selected}
          dirty={dirty}
          message={configMessage}
          onSelect={setSelected}
          onDesired={updateDesired}
          onValidate={validateConfig}
          onApply={applyConfig}
          onAddPeer={addPeer}
          onAddRoute={addRoute}
          onTopologyRoute={updateTopologyRoute}
          onProbeEndpoint={probeEndpoint}
          onProbeRoute={probeRoute}
        />
      )}
      {activeTab === "access" && (
        <AccessView
          t={t}
          lang={lang}
          desired={desired}
          deviceAccess={deviceAccess}
          endpointGrants={endpointGrants}
          issuedDevice={issuedDevice}
          dirty={dirty}
          message={configMessage}
          onIssueDevice={issueDeviceAccess}
          onIssueEndpointGrant={issueEndpointGrant}
          onRevokeEndpointGrant={revokeEndpointGrant}
          onCopy={copyText}
          onDesired={updateDesired}
          onValidate={validateConfig}
          onApply={applyConfig}
        />
      )}
      {activeTab === "config" && (
        <ConfigView
          t={t}
          lang={lang}
          desired={desired}
          transports={transports}
          links={links}
          text={configText}
          dirty={dirty}
          message={configMessage}
          onDesired={updateDesired}
          onText={updateConfigText}
          onReload={refreshAll}
          onValidate={validateConfig}
          onApply={applyConfig}
          onCopy={copyConfig}
        />
      )}
      {activeTab === "doctor" && <DoctorView t={t} lang={lang} doctor={doctor} status={status} routes={routes} kernelCapabilities={kernelCapabilities} />}
      {activeTab === "capture" && <CaptureView t={t} capture={capture} onReload={loadCapture} />}
    </>
  );

  return (
    <>
      <Shell
        t={t}
        lang={lang}
        activeTab={activeTab}
        locked={locked}
        loading={loading}
        adminProofReady={adminProof.ready}
        adminProofStatus={adminProof.message}
        adminProofSelected={selectedFiles}
        onRefresh={() => void refreshAll()}
        onTheme={() => {
          const next = themeSetting === "dark" ? "light" : "dark";
          setThemeSetting(next);
          pushToast("info", t("theme_updated", "Theme updated"), next === "dark" ? t("dark", "Dark") : t("light", "Light"));
        }}
        onLanguage={() => {
          const next = lang === "zh" ? "en" : "zh";
          localStorage.setItem("trustix.ui.lang", next);
          setLang(next);
          pushToast("info", t("language_updated", "Language updated"), next === "zh" ? "中文" : "English");
        }}
        onTab={(tab) => {
          setActiveTab(tab as Tab);
          if (tab === "capture") {
            void loadCapture();
          } else if (tab === "access") {
            void refreshRuntime({ silent: true });
          }
        }}
        onImportAdmin={importAdmin}
        onClearAdmin={clearAdmin}
      >
        {content}
      </Shell>
      <ToastViewport t={t} toasts={toasts} onDismiss={dismissToast} />
    </>
  );
}

function ToastViewport(props: { t: Translate; toasts: ToastNotice[]; onDismiss: (id: number) => void }) {
  if (props.toasts.length === 0) {
    return null;
  }
  return (
    <div className="toast-viewport" aria-live="polite" aria-relevant="additions text">
      {props.toasts.map((toast) => (
        <div key={toast.id} className={`toast ${toast.kind}`} role={toast.kind === "error" ? "alert" : "status"}>
          <div className="toast-marker" aria-hidden="true" />
          <div className="toast-copy">
            <div className="toast-title">{toast.title}</div>
            {toast.detail && <div className="toast-detail">{toast.detail}</div>}
          </div>
          <button type="button" className="toast-close" aria-label={props.t("dismiss", "Dismiss")} onClick={() => props.onDismiss(toast.id)}>
            <X size={14} />
          </button>
        </div>
      ))}
    </div>
  );
}

function normalizeTheme(raw: string | null): ThemeSetting {
  return raw === "light" || raw === "dark" || raw === "system" ? raw : "system";
}

function applyTheme(setting: ThemeSetting): void {
  localStorage.setItem("trustix.ui.theme", setting);
  const dark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  const theme = setting === "dark" || (setting === "system" && dark) ? "dark" : "light";
  document.documentElement.dataset.theme = theme;
  document.documentElement.style.colorScheme = theme;
  document.body.dataset.theme = theme;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function compactListForMessage(values: Array<string | number | undefined>, separator: string): string {
  return values.map((value) => String(value || "").trim()).filter(Boolean).join(separator);
}

function formatDurationForMessage(value: unknown, lang: string): string {
  const nanos = Number(value);
  if (!Number.isFinite(nanos) || nanos <= 0) {
    return "-";
  }
  if (nanos < 1_000_000) {
    return `${new Intl.NumberFormat(lang, { maximumFractionDigits: 1 }).format(nanos / 1_000)} us`;
  }
  if (nanos < 1_000_000_000) {
    return `${new Intl.NumberFormat(lang, { maximumFractionDigits: 2 }).format(nanos / 1_000_000)} ms`;
  }
  return `${new Intl.NumberFormat(lang, { maximumFractionDigits: 2 }).format(nanos / 1_000_000_000)} s`;
}

function uniqueID(base: string, existing: string[]): string {
  const used = new Set(existing);
  if (!used.has(base)) {
    return base;
  }
  for (let i = 2; ; i += 1) {
    const candidate = `${base}-${i}`;
    if (!used.has(candidate)) {
      return candidate;
    }
  }
}

const root = document.getElementById("root");
if (root) {
  createRoot(root).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}
