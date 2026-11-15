import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ClusterPage } from "./ClusterPage";
import { formatDateTime } from "../lib/format";
import { DISCONNECTED, NEVER_CONNECTED, PROJECT, cluster, node } from "../test/fixtures";
import type { Cluster } from "../api";
import { VIEWER, jsonResponse, notFound, renderPage, serveApi } from "../test/utils";
import type { ApiHandler } from "../test/utils";

const AGENT = {
  id: "a1",
  kind: "kubernetes",
  status: "active",
  project_id: "p1",
  cluster_id: "c1",
  cluster_name: "prod-east",
  source_id: "s1",
  key_id: "key-abc",
  cluster_fingerprint: "fp",
  agent_version: "0.1.0",
  protocol_versions: [1],
  enrollment_token_id: "t1",
  enrolled_by: "u1",
  enrolled_at: "2026-11-15T07:00:00Z",
  source_address: null,
  revoked_at: null,
  revoked_by: null,
  revocation_reason: null,
};

function serve(data: Cluster, extra: Record<string, ApiHandler> = {}) {
  return serveApi({
    "GET /api/v1/projects/prod": () => jsonResponse(PROJECT),
    [`GET /api/v1/projects/prod/clusters/${data.id}`]: () => jsonResponse(data),
    [`GET /api/v1/projects/prod/clusters/${data.id}/resources`]: () =>
      jsonResponse({ resources: [node("node-1")], next_cursor: null }),
    "GET /api/v1/projects/prod/agents": () => jsonResponse({ agents: [AGENT] }),
    ...extra,
  });
}

function open(id: string, me = undefined as Parameters<typeof renderPage>[1]["me"]) {
  return renderPage(<ClusterPage />, {
    path: "/projects/:slug/clusters/:clusterId",
    url: `/projects/prod/clusters/${id}`,
    ...(me ? { me } : {}),
  });
}

describe("ClusterPage", () => {
  it("shows a connected cluster without a stale banner", async () => {
    serve(cluster());
    open("c1");

    expect(await screen.findByRole("heading", { level: 1, name: "prod-east" })).toBeInTheDocument();
    expect(screen.queryByText(/Showing the last inventory/)).not.toBeInTheDocument();
    expect(await screen.findByRole("link", { name: "node-1" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Nodes/, current: "page" })).toBeInTheDocument();
  });

  it("shows the stale banner with the last inventory time when disconnected", async () => {
    serve(DISCONNECTED);
    open("c2");

    const banner = await screen.findByText(/Showing the last inventory received at/);
    expect(banner).toHaveTextContent(
      `Showing the last inventory received at ${formatDateTime("2026-11-15T07:29:00Z")}.`,
    );
    expect(screen.getByText(/resources may have changed since then/)).toBeInTheDocument();
    // The inventory itself stays visible.
    expect(await screen.findByRole("link", { name: "node-1" })).toBeInTheDocument();
  });

  it("says a revoked agent will not reconnect", async () => {
    serve({ ...DISCONNECTED, agent: { id: "a1", status: "revoked", agent_version: "0.1.0" } });
    open("c2");
    expect(await screen.findByText(/agent was revoked, so it will not reconnect/)).toBeInTheDocument();
  });

  it("explains a cluster that never connected", async () => {
    serveApi({
      "GET /api/v1/projects/prod": () => jsonResponse(PROJECT),
      "GET /api/v1/projects/prod/clusters/c3": () => jsonResponse(NEVER_CONNECTED),
      "GET /api/v1/projects/prod/clusters/c3/resources": () => jsonResponse({ resources: [], next_cursor: null }),
    });
    open("c3");

    expect(await screen.findByText("Waiting for the agent")).toBeInTheDocument();
    expect(await screen.findByText("No nodes in the inventory.")).toBeInTheDocument();
    expect(screen.getByText("No agent is enrolled for this cluster.")).toBeInTheDocument();
  });

  it("shows collection errors", async () => {
    const data = cluster();
    data.collections[0] = {
      collection: "v1/nodes",
      state: "error",
      last_snapshot_completed_at: null,
      resource_count: 0,
      error: { reason: "forbidden", message: "nodes is forbidden: cannot list", observed_at: "2026-11-15T10:00:00Z" },
    };
    serve(data);
    open("c1");

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("The agent could not read this collection: forbidden");
    expect(alert).toHaveTextContent("nodes is forbidden: cannot list");
    expect(screen.getByRole("link", { name: /Nodes.*collection error/ })).toBeInTheDocument();
  });

  it("shows not found for an unknown cluster or one in another project", async () => {
    serveApi({
      "GET /api/v1/projects/prod": () => jsonResponse(PROJECT),
      "GET /api/v1/projects/prod/clusters/nope": notFound,
      "GET /api/v1/projects/prod/clusters/nope/resources": notFound,
    });
    open("nope");

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Not found");
    expect(alert).toHaveTextContent("This cluster does not exist, or you do not have access to it.");
    expect(within(alert).queryByRole("button")).not.toBeInTheDocument();
  });

  it("revokes the agent after confirmation", async () => {
    let revoked = false;
    const fetchMock = serve(cluster(), {
      "GET /api/v1/projects/prod/clusters/c1": () =>
        jsonResponse(revoked ? { ...cluster(), agent: { id: "a1", status: "revoked", agent_version: "0.1.0" } } : cluster()),
      "POST /api/v1/projects/prod/agents/a1/revoke": () => {
        revoked = true;
        return jsonResponse({ ...AGENT, status: "revoked", revoked_at: "2026-11-15T10:10:00Z", revocation_reason: "revoked" });
      },
    });
    open("c1");

    const panel = await screen.findByRole("region", { name: "Agent" });
    fireEvent.click(within(panel).getByRole("button", { name: "Revoke agent" }));
    const confirm = within(panel).getByRole("group", { name: "Confirm: Revoke agent" });
    expect(confirm).toHaveTextContent("cannot reconnect");

    // Cancelling does nothing.
    fireEvent.click(within(confirm).getByRole("button", { name: "Cancel" }));
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === "POST")).toBe(false);

    fireEvent.click(within(panel).getByRole("button", { name: "Revoke agent" }));
    fireEvent.click(within(panel).getByRole("button", { name: "Revoke agent" }));

    await waitFor(() => {
      expect(within(panel).getByText("Revoked")).toBeInTheDocument();
    });
    expect(within(panel).queryByRole("button", { name: "Revoke agent" })).not.toBeInTheDocument();
  });

  it("does not offer revoke to users who may not manage agents", async () => {
    serve(cluster());
    open("c1", VIEWER);

    const panel = await screen.findByRole("region", { name: "Agent" });
    expect(within(panel).getByText("Active")).toBeInTheDocument();
    expect(within(panel).queryByRole("button", { name: "Revoke agent" })).not.toBeInTheDocument();
  });
});
