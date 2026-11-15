import { describe, expect, it } from "vitest";
import {
  fetchCluster,
  fetchClusters,
  fetchResource,
  fetchResources,
  parseCluster,
  parseResourcePage,
  parseSummary,
  resourceQueryString,
} from "./clusters";
import { cluster, deployment, node } from "../test/fixtures";
import { jsonResponse, mockFetch } from "../test/utils";

describe("fetchClusters", () => {
  it("requests the project's clusters and parses the contract shape", async () => {
    const fetchMock = mockFetch(() => Promise.resolve(jsonResponse({ clusters: [cluster()] })));
    await expect(fetchClusters("prod")).resolves.toEqual([cluster()]);
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/projects/prod/clusters", expect.objectContaining({ method: "GET" }));
  });

  it("rejects a list with a malformed cluster", async () => {
    mockFetch(() =>
      Promise.resolve(jsonResponse({ clusters: [{ ...cluster(), connection: { state: "maybe" } }] })),
    );
    await expect(fetchClusters("prod")).rejects.toMatchObject({ kind: "parse" });
  });

  it("encodes path segments", async () => {
    const fetchMock = mockFetch(() => Promise.resolve(jsonResponse(cluster())));
    await fetchCluster("prod", "a/b");
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/projects/prod/clusters/a%2Fb", expect.anything());
  });

  it("surfaces a cluster from another project as a 404", async () => {
    mockFetch(() => Promise.resolve(jsonResponse({ error: "not_found", message: "no cluster" }, 404)));
    await expect(fetchCluster("prod", "c9")).rejects.toMatchObject({ kind: "http", status: 404 });
  });
});

describe("parseCluster", () => {
  it("accepts a cluster without an agent or inventory", () => {
    const parsed = parseCluster({
      ...cluster(),
      agent: null,
      connection: { state: "never_connected", connected_since: null, last_seen_at: null, kubernetes_version: null },
      inventory: { stale: true, last_observed_at: null, counts: {} },
    });
    expect(parsed?.agent).toBeNull();
    expect(parsed?.inventory.counts).toEqual({});
  });

  it("keeps collection errors", () => {
    const error = { reason: "forbidden", message: "nodes is forbidden", observed_at: "2026-11-15T10:00:00Z" };
    const parsed = parseCluster({
      ...cluster(),
      collections: [
        { collection: "v1/nodes", state: "error", last_snapshot_completed_at: null, resource_count: 0, error },
      ],
    });
    expect(parsed?.collections[0]?.error).toEqual(error);
  });

  it("rejects unknown states and non-numeric counts", () => {
    expect(parseCluster({ ...cluster(), agent: { id: "a", status: "lost", agent_version: "1" } })).toBeUndefined();
    expect(
      parseCluster({ ...cluster(), inventory: { stale: false, last_observed_at: null, counts: { "v1/nodes": "3" } } }),
    ).toBeUndefined();
  });
});

describe("fetchResources", () => {
  it("sends filters, the cursor, and the page size", async () => {
    const fetchMock = mockFetch(() => Promise.resolve(jsonResponse({ resources: [], next_cursor: null })));
    await fetchResources("prod", "c1", {
      collection: "apps/v1/deployments",
      namespace: "kube-system",
      search: "core dns",
      includeDeleted: true,
      limit: 100,
      cursor: "abc=",
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/projects/prod/clusters/c1/resources?collection=apps%2Fv1%2Fdeployments&namespace=kube-system&search=core+dns&include_deleted=true&limit=100&cursor=abc%3D",
      expect.anything(),
    );
  });

  it("leaves out empty filters", () => {
    expect(resourceQueryString({})).toBe("");
    expect(resourceQueryString({ namespace: "", search: "", includeDeleted: false })).toBe("");
  });

  it("parses resources with their kind-specific summaries", async () => {
    mockFetch(() => Promise.resolve(jsonResponse({ resources: [deployment("api"), node("n1")], next_cursor: "next" })));
    const page = await fetchResources("prod", "c1", {});
    expect(page.next_cursor).toBe("next");
    expect(page.resources.map((r) => r.summary)).toEqual([
      { collection: "apps/v1/deployments", value: { replicas: 3, ready_replicas: 3, images: ["ghcr.io/example/api:1.0"] } },
      {
        collection: "v1/nodes",
        value: {
          ready: true,
          roles: ["control-plane"],
          kubelet_version: "v1.34.2",
          os_image: "Talos (v1.11.0)",
          internal_ip: "10.0.0.11",
          cpu: "4",
          memory: "16Gi",
        },
      },
    ]);
  });

  it("rejects a page with a malformed resource", () => {
    expect(parseResourcePage({ resources: [{ ...deployment("x"), state: "gone" }], next_cursor: null })).toBeUndefined();
    expect(parseResourcePage({ resources: [] })).toBeUndefined();
    expect(parseResourcePage({ resources: [{ ...deployment("x"), truncated: "yes" }], next_cursor: null })).toBeUndefined();
  });

  it("keeps the truncation flag, reading it as false when absent", () => {
    const page = parseResourcePage({ resources: [{ ...deployment("big"), truncated: true }, deployment("small")], next_cursor: null });
    expect(page?.resources.map((r) => r.truncated)).toEqual([true, false]);
  });
});

describe("parseSummary", () => {
  it("reads missing, null, and mistyped fields as null", () => {
    expect(parseSummary("apps/v1/daemonsets", { desired: 3, ready: null, images: "nginx" })).toEqual({
      collection: "apps/v1/daemonsets",
      value: { desired: 3, ready: null, images: null },
    });
    expect(parseSummary("v1/namespaces", null)).toEqual({ collection: "v1/namespaces", value: { phase: null } });
  });

  it("keeps summaries of unknown collections as they are", () => {
    expect(parseSummary("batch/v1/jobs", { active: 1 })).toEqual({ collection: "other", value: { active: 1 } });
  });
});

describe("fetchResource", () => {
  it("returns the resource with its sanitized object", async () => {
    const object = { apiVersion: "apps/v1", kind: "Deployment", metadata: { name: "api" } };
    const fetchMock = mockFetch(() => Promise.resolve(jsonResponse({ ...deployment("api"), object })));
    const resource = await fetchResource("prod", "c1", "r-api");
    expect(resource.object).toEqual(object);
    expect(resource.name).toBe("api");
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/projects/prod/clusters/c1/resources/r-api", expect.anything());
  });

  it("rejects a detail answer without an object", async () => {
    mockFetch(() => Promise.resolve(jsonResponse(deployment("api"))));
    await expect(fetchResource("prod", "c1", "r-api")).rejects.toMatchObject({ kind: "parse" });
  });
});
