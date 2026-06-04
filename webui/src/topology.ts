import type {
  DesiredConfig,
  LinkStatus,
  PeerConfig,
  RouteView,
  TopologyEdge,
  TopologyNode,
} from "./types";
import { arrayValue, statusBucket } from "./utils";

export function buildTopology(desired: DesiredConfig | null, links: LinkStatus[]): { nodes: TopologyNode[]; edges: TopologyEdge[] } {
  const localID = desired?.ix?.id || "local";
  const domain = desired?.domain?.id || desired?.ix?.domain || "";
  const routes = uniqueRoutes([
    ...(arrayValue(desired?.routes) as RouteView[]),
    ...links.flatMap((link) => arrayValue(link.routes)),
  ]);
  const peers = new Map<string, PeerConfig>();
  for (const peer of arrayValue(desired?.peers)) {
    if (peer.id) {
      peers.set(peer.id, peer);
    }
  }
  const linkMap = new Map<string, LinkStatus>();
  for (const link of links) {
    if (link.peer) {
      linkMap.set(link.peer, link);
    }
  }
  const peerIDs = new Set<string>();
  for (const peer of peers.keys()) {
    peerIDs.add(peer);
  }
  for (const peer of linkMap.keys()) {
    peerIDs.add(peer);
  }
  for (const route of routes) {
    if (route.next_hop) {
      peerIDs.add(route.next_hop);
    }
    if (route.owner && route.owner !== localID) {
      peerIDs.add(route.owner);
    }
  }

  const nodes: TopologyNode[] = [];
  nodes.push({
    id: localID,
    label: localID,
    domain,
    local: true,
    state: "up",
    x: 420,
    y: 260,
    prefixes: localLANPrefixes(desired),
  });

  const ids = Array.from(peerIDs).filter((id) => id && id !== localID).sort((a, b) => a.localeCompare(b));
  const radiusX = Math.max(260, Math.min(520, 190 + ids.length * 42));
  const radiusY = Math.max(170, Math.min(320, 130 + ids.length * 18));
  ids.forEach((id, index) => {
    const angle = (2 * Math.PI * index) / Math.max(1, ids.length) - Math.PI / 2;
    const peer = peers.get(id);
    const link = linkMap.get(id);
    nodes.push({
      id,
      label: id,
      domain: peer?.domain || link?.domain || domain,
      dynamic: Boolean(link?.dynamic && !peer),
      state: link ? statusBucket(link.state) : "degraded",
      x: 420 + Math.cos(angle) * radiusX,
      y: 260 + Math.sin(angle) * radiusY,
      prefixes: nodePrefixes(id, peer, link, routes),
      link,
      peer,
    });
  });

  const edges: TopologyEdge[] = ids.map((id) => {
    const peer = peers.get(id);
    const link = linkMap.get(id);
    const edgeRoutes = routes.filter((route) => route.next_hop === id || route.owner === id);
    const endpoints = arrayValue(link?.endpoints);
    const transports = Array.from(new Set([
      ...endpoints.map((endpoint) => endpoint.transport || ""),
      ...arrayValue(peer?.endpoints).map((endpoint) => endpoint.transport || ""),
      ...arrayValue(link?.sessions).map((session) => session.transport || ""),
    ].filter(Boolean))).sort((a, b) => a.localeCompare(b));
    const usableTransportCount = endpoints.filter((endpoint) => endpoint.usable).length;
    const activeTransportSessions = endpoints.reduce((sum, endpoint) => sum + Number(endpoint.active_sessions || 0), 0);
    return {
      id: `${localID}->${id}`,
      source: localID,
      target: id,
      label: edgeTransportSummary(transports.length, usableTransportCount, activeTransportSessions),
      state: link ? statusBucket(link.state) : "degraded",
      transports,
      transportCount: transports.length,
      usableTransportCount,
      activeTransportSessions,
      routes: edgeRoutes,
      endpoints,
      link,
    };
  });

  return { nodes, edges };
}

function localLANPrefixes(desired: DesiredConfig | null): string[] {
  const prefixes = new Set<string>();
  for (const prefix of arrayValue(desired?.lan?.advertise)) {
    if (prefix) {
      prefixes.add(prefix);
    }
  }
  for (const lan of arrayValue(desired?.lans)) {
    for (const prefix of arrayValue(lan.advertise)) {
      if (prefix) {
        prefixes.add(prefix);
      }
    }
  }
  return Array.from(prefixes);
}

function nodePrefixes(nodeID: string, peer: PeerConfig | undefined, link: LinkStatus | undefined, routes: RouteView[]): string[] {
  const prefixes = new Set<string>();
  for (const prefix of arrayValue(peer?.allowed_prefixes)) {
    if (prefix) {
      prefixes.add(prefix);
    }
  }
  for (const route of arrayValue(link?.routes)) {
    if (route.prefix && (!route.owner || route.owner === nodeID)) {
      prefixes.add(route.prefix);
    }
  }
  for (const route of routes) {
    if (route.prefix && route.owner === nodeID) {
      prefixes.add(route.prefix);
    }
  }
  return Array.from(prefixes);
}

function uniqueRoutes(routes: RouteView[]): RouteView[] {
  const out: RouteView[] = [];
  const seen = new Set<string>();
  for (const route of routes) {
    const key = [route.prefix || "", route.owner || "", route.next_hop || "", route.endpoint || "", route.source || ""].join("\0");
    if (!route.prefix || seen.has(key)) {
      continue;
    }
    seen.add(key);
    out.push(route);
  }
  return out;
}

function edgeTransportSummary(total: number, usable: number, active: number): string {
  if (total === 0) {
    return "no endpoint";
  }
  if (active > 0) {
    return `${active} active / ${total} total`;
  }
  if (usable > 0) {
    return `${usable} usable / ${total} total`;
  }
  return `${total} transport${total === 1 ? "" : "s"}`;
}

export function edgeMidpoint(nodes: TopologyNode[], edge: TopologyEdge): { x: number; y: number } {
  const source = nodes.find((node) => node.id === edge.source);
  const target = nodes.find((node) => node.id === edge.target);
  if (!source || !target) {
    return { x: 0, y: 0 };
  }
  return { x: (source.x + target.x) / 2, y: (source.y + target.y) / 2 };
}

export function edgePath(nodes: TopologyNode[], edge: TopologyEdge): string {
  const source = nodes.find((node) => node.id === edge.source);
  const target = nodes.find((node) => node.id === edge.target);
  if (!source || !target) {
    return "";
  }
  const dx = target.x - source.x;
  const dy = target.y - source.y;
  const length = Math.max(1, Math.sqrt(dx * dx + dy * dy));
  const sourceRadius = source.local ? 58 : 45;
  const targetRadius = target.local ? 58 : 45;
  const sx = source.x + (dx / length) * sourceRadius;
  const sy = source.y + (dy / length) * sourceRadius;
  const tx = target.x - (dx / length) * targetRadius;
  const ty = target.y - (dy / length) * targetRadius;
  return `M ${sx} ${sy} L ${tx} ${ty}`;
}
