import type { Cluster, CollectionState, ConnectionState, EnrollmentTokenStatus, Project } from "../api";
import type { Tone } from "../components/StatusBadge";

/** Display names of collections: as a heading, and inside a sentence. */
const COLLECTION_LABELS: Partial<Record<string, { title: string; inline: string }>> = {
  "v1/nodes": { title: "Nodes", inline: "nodes" },
  "v1/namespaces": { title: "Namespaces", inline: "namespaces" },
  "apps/v1/deployments": { title: "Deployments", inline: "deployments" },
  "apps/v1/statefulsets": { title: "StatefulSets", inline: "StatefulSets" },
  "apps/v1/daemonsets": { title: "DaemonSets", inline: "DaemonSets" },
};

export function collectionLabel(collection: string): string {
  return COLLECTION_LABELS[collection]?.title ?? collection;
}

/** A collection's name for use mid-sentence, such as "No StatefulSets match". */
export function collectionNoun(collection: string): string {
  return COLLECTION_LABELS[collection]?.inline ?? collection;
}

export const CONNECTION: Record<ConnectionState, { label: string; tone: Tone }> = {
  connected: { label: "Connected", tone: "ok" },
  disconnected: { label: "Disconnected", tone: "down" },
  never_connected: { label: "Never connected", tone: "pending" },
};

export const COLLECTION_STATE: Record<CollectionState, { label: string; tone: Tone }> = {
  synced: { label: "Synced", tone: "ok" },
  syncing: { label: "Syncing", tone: "degraded" },
  error: { label: "Error", tone: "down" },
  never_synced: { label: "Not synced yet", tone: "pending" },
};

export const TOKEN_STATUS: Record<EnrollmentTokenStatus, { label: string; tone: Tone }> = {
  active: { label: "Active", tone: "ok" },
  used: { label: "Used", tone: "pending" },
  expired: { label: "Expired", tone: "pending" },
  revoked: { label: "Revoked", tone: "down" },
};

export function accessLabel(project: Project): string {
  if (project.role === "operator") return "Operator";
  if (project.role === "viewer") return "Viewer";
  return "Admin";
}

const WORKLOADS = ["apps/v1/deployments", "apps/v1/statefulsets", "apps/v1/daemonsets"];

/** Resource counts for the cluster list: nodes, namespaces, and all workloads together. */
export function clusterCounts(cluster: Cluster): { nodes: number | null; namespaces: number | null; workloads: number | null } {
  const { counts } = cluster.inventory;
  const workloadCounts = WORKLOADS.map((key) => counts[key]).filter((n): n is number => n !== undefined);
  return {
    nodes: counts["v1/nodes"] ?? null,
    namespaces: counts["v1/namespaces"] ?? null,
    workloads: workloadCounts.length === 0 ? null : workloadCounts.reduce((a, b) => a + b, 0),
  };
}

export function clusterPath(slug: string, clusterId: string): string {
  return `/projects/${encodeURIComponent(slug)}/clusters/${encodeURIComponent(clusterId)}`;
}

export function projectPath(slug: string): string {
  return `/projects/${encodeURIComponent(slug)}`;
}

export function resourcePath(slug: string, clusterId: string, resourceId: string): string {
  return `${clusterPath(slug, clusterId)}/resources/${encodeURIComponent(resourceId)}`;
}
