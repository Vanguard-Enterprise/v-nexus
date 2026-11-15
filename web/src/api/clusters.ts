import { apiGet } from "./client";
import {
  asObject,
  isOneOf,
  isOptionalString,
  isString,
  parseArray,
  readBoolean,
  readNumber,
  readString,
  readStrings,
} from "./parse";

/** Inventory collections of the first release, in the order the server lists them. */
export const COLLECTIONS = [
  "v1/nodes",
  "v1/namespaces",
  "apps/v1/deployments",
  "apps/v1/statefulsets",
  "apps/v1/daemonsets",
] as const;

export type Collection = (typeof COLLECTIONS)[number];

export function isCollection(value: unknown): value is Collection {
  return isOneOf(value, COLLECTIONS);
}

/** Collections whose resources live in a namespace. */
export function isNamespaced(collection: Collection): boolean {
  return collection !== "v1/nodes" && collection !== "v1/namespaces";
}

export type ConnectionState = "connected" | "disconnected" | "never_connected";
export type CollectionState = "synced" | "syncing" | "error" | "never_synced";
export type AgentStatus = "active" | "revoked";
export type ResourceState = "present" | "deleted";

const CONNECTION_STATES: readonly ConnectionState[] = ["connected", "disconnected", "never_connected"];
const COLLECTION_STATES: readonly CollectionState[] = ["synced", "syncing", "error", "never_synced"];
const AGENT_STATUSES: readonly AgentStatus[] = ["active", "revoked"];
const RESOURCE_STATES: readonly ResourceState[] = ["present", "deleted"];

export interface ClusterAgent {
  id: string;
  status: AgentStatus;
  agent_version: string;
}

export interface ClusterConnection {
  state: ConnectionState;
  connected_since: string | null;
  last_seen_at: string | null;
  kubernetes_version: string | null;
}

export interface ClusterInventory {
  /** True whenever the cluster is not connected. */
  stale: boolean;
  last_observed_at: string | null;
  /** Resource counts keyed by collection. Collections without data may be missing. */
  counts: Partial<Record<string, number>>;
}

export interface CollectionError {
  reason: string;
  message: string;
  observed_at: string;
}

export interface CollectionStatus {
  collection: string;
  state: CollectionState;
  last_snapshot_completed_at: string | null;
  resource_count: number;
  error: CollectionError | null;
}

/** A registered cluster, as `GET /api/v1/projects/{slug}/clusters/{id}` returns it. */
export interface Cluster {
  id: string;
  project_id: string;
  display_name: string;
  created_at: string;
  source_id: string;
  agent: ClusterAgent | null;
  connection: ClusterConnection;
  inventory: ClusterInventory;
  collections: CollectionStatus[];
}

function parseAgent(value: unknown): ClusterAgent | null | undefined {
  if (value === null) return null;
  const body = asObject(value);
  if (!body) return undefined;
  const { id, status, agent_version } = body;
  if (!isString(id) || !isOneOf(status, AGENT_STATUSES) || !isString(agent_version)) return undefined;
  return { id, status, agent_version };
}

function parseConnection(value: unknown): ClusterConnection | undefined {
  const body = asObject(value);
  if (!body) return undefined;
  const { state, connected_since, last_seen_at, kubernetes_version } = body;
  if (
    !isOneOf(state, CONNECTION_STATES) ||
    !isOptionalString(connected_since) ||
    !isOptionalString(last_seen_at) ||
    !isOptionalString(kubernetes_version)
  ) {
    return undefined;
  }
  return { state, connected_since, last_seen_at, kubernetes_version };
}

function parseInventory(value: unknown): ClusterInventory | undefined {
  const body = asObject(value);
  if (!body) return undefined;
  const { stale, last_observed_at } = body;
  const counts = asObject(body.counts);
  if (typeof stale !== "boolean" || !isOptionalString(last_observed_at) || !counts) return undefined;
  const parsedCounts: Partial<Record<string, number>> = {};
  for (const [key, count] of Object.entries(counts)) {
    if (typeof count !== "number") return undefined;
    parsedCounts[key] = count;
  }
  return { stale, last_observed_at, counts: parsedCounts };
}

function parseCollectionError(value: unknown): CollectionError | null | undefined {
  if (value === null) return null;
  const body = asObject(value);
  if (!body) return undefined;
  const { reason, message, observed_at } = body;
  if (!isString(reason) || !isString(message) || !isString(observed_at)) return undefined;
  return { reason, message, observed_at };
}

function parseCollectionStatus(value: unknown): CollectionStatus | undefined {
  const body = asObject(value);
  if (!body) return undefined;
  const { collection, state, last_snapshot_completed_at, resource_count } = body;
  const error = parseCollectionError(body.error);
  if (
    !isString(collection) ||
    !isOneOf(state, COLLECTION_STATES) ||
    !isOptionalString(last_snapshot_completed_at) ||
    typeof resource_count !== "number" ||
    error === undefined
  ) {
    return undefined;
  }
  return { collection, state, last_snapshot_completed_at, resource_count, error };
}

export function parseCluster(value: unknown): Cluster | undefined {
  const body = asObject(value);
  if (!body) return undefined;
  const { id, project_id, display_name, created_at, source_id } = body;
  const agent = parseAgent(body.agent);
  const connection = parseConnection(body.connection);
  const inventory = parseInventory(body.inventory);
  const collections = parseArray(body.collections, parseCollectionStatus);
  if (
    !isString(id) ||
    !isString(project_id) ||
    !isString(display_name) ||
    !isString(created_at) ||
    !isString(source_id) ||
    agent === undefined ||
    !connection ||
    !inventory ||
    !collections
  ) {
    return undefined;
  }
  return { id, project_id, display_name, created_at, source_id, agent, connection, inventory, collections };
}

export function parseClusterList(value: unknown): Cluster[] | undefined {
  return parseArray(asObject(value)?.clusters, parseCluster);
}

/* Resources */

export interface NodeSummary {
  ready: boolean | null;
  roles: string[] | null;
  kubelet_version: string | null;
  os_image: string | null;
  internal_ip: string | null;
  cpu: string | null;
  memory: string | null;
}

export interface NamespaceSummary {
  phase: string | null;
}

export interface ReplicatedSummary {
  replicas: number | null;
  ready_replicas: number | null;
  images: string[] | null;
}

export interface DaemonSetSummary {
  desired: number | null;
  ready: number | null;
  images: string[] | null;
}

/** Kind-specific summary columns, tagged by collection. `other` covers collections this UI does not know. */
export type ResourceSummary =
  | { collection: "v1/nodes"; value: NodeSummary }
  | { collection: "v1/namespaces"; value: NamespaceSummary }
  | { collection: "apps/v1/deployments" | "apps/v1/statefulsets"; value: ReplicatedSummary }
  | { collection: "apps/v1/daemonsets"; value: DaemonSetSummary }
  | { collection: "other"; value: Record<string, unknown> };

/**
 * Reads a summary leniently: the server computes it from the stored object, so any
 * field may be null or absent. A field of the wrong type reads as null.
 */
export function parseSummary(collection: string, value: unknown): ResourceSummary {
  const s = asObject(value) ?? {};
  switch (collection) {
    case "v1/nodes":
      return {
        collection,
        value: {
          ready: readBoolean(s.ready),
          roles: readStrings(s.roles),
          kubelet_version: readString(s.kubelet_version),
          os_image: readString(s.os_image),
          internal_ip: readString(s.internal_ip),
          cpu: readString(s.cpu),
          memory: readString(s.memory),
        },
      };
    case "v1/namespaces":
      return { collection, value: { phase: readString(s.phase) } };
    case "apps/v1/deployments":
    case "apps/v1/statefulsets":
      return {
        collection,
        value: {
          replicas: readNumber(s.replicas),
          ready_replicas: readNumber(s.ready_replicas),
          images: readStrings(s.images),
        },
      };
    case "apps/v1/daemonsets":
      return {
        collection,
        value: { desired: readNumber(s.desired), ready: readNumber(s.ready), images: readStrings(s.images) },
      };
    default:
      return { collection: "other", value: s };
  }
}

export interface Resource {
  id: string;
  collection: string;
  kind: string;
  uid: string;
  namespace: string | null;
  name: string;
  resource_version: string;
  state: ResourceState;
  first_observed_at: string;
  last_observed_at: string;
  deleted_at: string | null;
  /** The object was over the agent's message size limit, so only its identity is stored. */
  truncated: boolean;
  summary: ResourceSummary;
}

export interface ResourceDetail extends Resource {
  /** The sanitized Kubernetes object. */
  object: Record<string, unknown>;
}

export interface ResourcePage {
  resources: Resource[];
  next_cursor: string | null;
}

export function parseResource(value: unknown): Resource | undefined {
  const body = asObject(value);
  if (!body) return undefined;
  const {
    id,
    collection,
    kind,
    uid,
    namespace,
    name,
    resource_version,
    state,
    first_observed_at,
    last_observed_at,
    deleted_at,
    truncated = false,
  } = body;
  if (
    !isString(id) ||
    !isString(collection) ||
    !isString(kind) ||
    !isString(uid) ||
    !isOptionalString(namespace) ||
    !isString(name) ||
    !isString(resource_version) ||
    !isOneOf(state, RESOURCE_STATES) ||
    !isString(first_observed_at) ||
    !isString(last_observed_at) ||
    !isOptionalString(deleted_at) ||
    typeof truncated !== "boolean"
  ) {
    return undefined;
  }
  return {
    id,
    collection,
    kind,
    uid,
    namespace,
    name,
    resource_version,
    state,
    first_observed_at,
    last_observed_at,
    deleted_at,
    truncated,
    summary: parseSummary(collection, body.summary),
  };
}

export function parseResourceDetail(value: unknown): ResourceDetail | undefined {
  const resource = parseResource(value);
  const object = asObject(asObject(value)?.object);
  return resource && object ? { ...resource, object } : undefined;
}

export function parseResourcePage(value: unknown): ResourcePage | undefined {
  const body = asObject(value);
  if (!body) return undefined;
  const resources = parseArray(body.resources, parseResource);
  const { next_cursor } = body;
  if (!resources || !isOptionalString(next_cursor)) return undefined;
  return { resources, next_cursor };
}

/* Requests */

/** Largest page the resources endpoint returns. */
export const MAX_RESOURCE_PAGE = 500;

export interface ResourceQuery {
  collection?: Collection | undefined;
  namespace?: string | undefined;
  search?: string | undefined;
  includeDeleted?: boolean | undefined;
  limit?: number | undefined;
  cursor?: string | undefined;
}

function projectPath(slug: string): string {
  return `/projects/${encodeURIComponent(slug)}`;
}

function clusterPath(slug: string, clusterId: string): string {
  return `${projectPath(slug)}/clusters/${encodeURIComponent(clusterId)}`;
}

/** Query string for the resources endpoint. Empty filters are left out. */
export function resourceQueryString(query: ResourceQuery): string {
  const params = new URLSearchParams();
  if (query.collection) params.set("collection", query.collection);
  if (query.namespace) params.set("namespace", query.namespace);
  if (query.search) params.set("search", query.search);
  if (query.includeDeleted) params.set("include_deleted", "true");
  if (query.limit !== undefined) params.set("limit", String(query.limit));
  if (query.cursor) params.set("cursor", query.cursor);
  const text = params.toString();
  return text === "" ? "" : `?${text}`;
}

function withSignal(signal?: AbortSignal) {
  return signal ? { signal } : {};
}

export function fetchClusters(slug: string, signal?: AbortSignal): Promise<Cluster[]> {
  return apiGet(`${projectPath(slug)}/clusters`, { parse: parseClusterList, ...withSignal(signal) });
}

export function fetchCluster(slug: string, clusterId: string, signal?: AbortSignal): Promise<Cluster> {
  return apiGet(clusterPath(slug, clusterId), { parse: parseCluster, ...withSignal(signal) });
}

export function fetchResources(
  slug: string,
  clusterId: string,
  query: ResourceQuery,
  signal?: AbortSignal,
): Promise<ResourcePage> {
  return apiGet(`${clusterPath(slug, clusterId)}/resources${resourceQueryString(query)}`, {
    parse: parseResourcePage,
    ...withSignal(signal),
  });
}

/** Upper bound on namespace pages followed for the namespace filter (10,000 namespaces). */
export const MAX_NAMESPACE_PAGES = 20;

/** Names of the cluster's present namespaces, following `next_cursor` across pages. */
export async function fetchNamespaceNames(slug: string, clusterId: string, signal?: AbortSignal): Promise<string[]> {
  const names: string[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < MAX_NAMESPACE_PAGES; page += 1) {
    const result = await fetchResources(
      slug,
      clusterId,
      { collection: "v1/namespaces", limit: MAX_RESOURCE_PAGE, cursor },
      signal,
    );
    names.push(...result.resources.map((resource) => resource.name));
    if (result.next_cursor === null || result.next_cursor === cursor) break;
    cursor = result.next_cursor;
  }
  return names;
}

export function fetchResource(
  slug: string,
  clusterId: string,
  resourceId: string,
  signal?: AbortSignal,
): Promise<ResourceDetail> {
  return apiGet(`${clusterPath(slug, clusterId)}/resources/${encodeURIComponent(resourceId)}`, {
    parse: parseResourceDetail,
    ...withSignal(signal),
  });
}
