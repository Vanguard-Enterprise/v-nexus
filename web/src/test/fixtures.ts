import type { Cluster } from "../api";

/** JSON fixtures shaped exactly like the inventory API contract. */

export const PROJECT = {
  id: "p1",
  slug: "prod",
  name: "Production",
  created_at: "2026-11-12T10:00:00Z",
  role: null,
  permissions: { view: true, operate: true, manage_members: true },
};

const COLLECTIONS = [
  "v1/nodes",
  "v1/namespaces",
  "apps/v1/deployments",
  "apps/v1/statefulsets",
  "apps/v1/daemonsets",
];

export function cluster(overrides: Partial<Cluster> = {}): Cluster {
  return {
    id: "c1",
    project_id: "p1",
    display_name: "prod-east",
    created_at: "2026-11-14T09:00:00Z",
    source_id: "s1",
    agent: { id: "a1", status: "active", agent_version: "0.1.0" },
    connection: {
      state: "connected",
      connected_since: "2026-11-15T08:00:00Z",
      last_seen_at: "2026-11-15T10:00:00Z",
      kubernetes_version: "v1.34.2",
    },
    inventory: {
      stale: false,
      last_observed_at: "2026-11-15T10:00:00Z",
      counts: { "v1/nodes": 3, "v1/namespaces": 7, "apps/v1/deployments": 12, "apps/v1/statefulsets": 2, "apps/v1/daemonsets": 4 },
    },
    collections: COLLECTIONS.map((collection) => ({
      collection,
      state: "synced",
      last_snapshot_completed_at: "2026-11-15T09:59:00Z",
      resource_count: 3,
      error: null,
    })),
    ...overrides,
  };
}

export const DISCONNECTED = cluster({
  id: "c2",
  display_name: "lab",
  connection: {
    state: "disconnected",
    connected_since: null,
    last_seen_at: "2026-11-15T07:30:00Z",
    kubernetes_version: "v1.33.0",
  },
  inventory: { stale: true, last_observed_at: "2026-11-15T07:29:00Z", counts: { "v1/nodes": 1 } },
});

export const NEVER_CONNECTED = cluster({
  id: "c3",
  display_name: "edge",
  agent: null,
  connection: { state: "never_connected", connected_since: null, last_seen_at: null, kubernetes_version: null },
  inventory: { stale: true, last_observed_at: null, counts: {} },
  collections: COLLECTIONS.map((collection) => ({
    collection,
    state: "never_synced",
    last_snapshot_completed_at: null,
    resource_count: 0,
    error: null,
  })),
});

export function deployment(name: string, overrides: Record<string, unknown> = {}) {
  return {
    id: `r-${name}`,
    collection: "apps/v1/deployments",
    kind: "Deployment",
    uid: `uid-${name}`,
    namespace: "default",
    name,
    resource_version: "100",
    state: "present",
    first_observed_at: "2026-11-15T08:00:00Z",
    last_observed_at: "2026-11-15T10:00:00Z",
    deleted_at: null,
    summary: { replicas: 3, ready_replicas: 3, images: [`ghcr.io/example/${name}:1.0`] },
    ...overrides,
  };
}

export function namespaceResource(name: string) {
  return {
    id: `ns-${name}`,
    collection: "v1/namespaces",
    kind: "Namespace",
    uid: `uid-ns-${name}`,
    namespace: null,
    name,
    resource_version: "1",
    state: "present",
    first_observed_at: "2026-11-15T08:00:00Z",
    last_observed_at: "2026-11-15T10:00:00Z",
    deleted_at: null,
    summary: { phase: "Active" },
  };
}

export function node(name: string, overrides: Record<string, unknown> = {}) {
  return {
    id: `n-${name}`,
    collection: "v1/nodes",
    kind: "Node",
    uid: `uid-n-${name}`,
    namespace: null,
    name,
    resource_version: "55",
    state: "present",
    first_observed_at: "2026-11-15T08:00:00Z",
    last_observed_at: "2026-11-15T10:00:00Z",
    deleted_at: null,
    summary: {
      ready: true,
      roles: ["control-plane"],
      kubelet_version: "v1.34.2",
      os_image: "Talos (v1.11.0)",
      internal_ip: "10.0.0.11",
      cpu: "4",
      memory: "16Gi",
    },
    ...overrides,
  };
}

export const TOKEN = {
  id: "t1",
  project_id: "p1",
  kind: "kubernetes",
  target: { type: "new_cluster", display_name: "prod-east" },
  status: "active",
  created_by: "u1",
  created_at: "2026-11-15T10:00:00Z",
  expires_at: "2026-11-15T11:00:00Z",
  used_at: null,
  revoked_at: null,
  revoked_by: null,
};
