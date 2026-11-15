import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ClusterPage } from "../pages/ClusterPage";
import { PROJECT, cluster, deployment, namespaceResource } from "../test/fixtures";
import { jsonResponse, renderPage, requestsTo, serveApi } from "../test/utils";

const RESOURCES = "/api/v1/projects/prod/clusters/c1/resources";

function rows(): string[] {
  const table = screen.getByRole("table", { name: /Deployments/ });
  return within(table)
    .getAllByRole("row")
    .slice(1)
    .map((row) => within(row).getAllByRole("link")[0]?.textContent ?? "");
}

/** A fake resources endpoint: filters and pages a fixed list of deployments like the server. */
function serve() {
  const all = [
    deployment("api"),
    deployment("web", { namespace: "frontend" }),
    deployment("worker"),
    deployment("old-api", { state: "deleted", deleted_at: "2026-11-15T09:00:00Z" }),
  ];
  return serveApi({
    "GET /api/v1/projects/prod": () => jsonResponse(PROJECT),
    "GET /api/v1/projects/prod/clusters/c1": () => jsonResponse(cluster()),
    "GET /api/v1/projects/prod/agents": () => jsonResponse({ agents: [] }),
    [`GET ${RESOURCES}`]: (url) => {
      const q = url.searchParams;
      if (q.get("collection") === "v1/namespaces") {
        return jsonResponse({ resources: ["default", "frontend"].map(namespaceResource), next_cursor: null });
      }
      const search = q.get("search")?.toLowerCase() ?? "";
      const matches = all.filter(
        (r) =>
          (q.get("include_deleted") === "true" || r.state === "present") &&
          (!q.has("namespace") || r.namespace === q.get("namespace")) &&
          r.name.toLowerCase().includes(search),
      );
      // Two per page here, to exercise the cursor.
      const start = Number(q.get("cursor") ?? "0");
      const page = matches.slice(start, start + 2);
      const next = start + 2 < matches.length ? String(start + 2) : null;
      return jsonResponse({ resources: page, next_cursor: next });
    },
  });
}

function open(search = "?collection=apps/v1/deployments") {
  return renderPage(<ClusterPage />, {
    path: "/projects/:slug/clusters/:clusterId",
    url: `/projects/prod/clusters/c1${search}`,
  });
}

function deploymentRequests(fetchMock: ReturnType<typeof serve>) {
  return requestsTo(fetchMock, "GET", RESOURCES).filter((url) => url.searchParams.get("collection") !== "v1/namespaces");
}

describe("Resource browser", () => {
  it("shows kind-specific columns for deployments", async () => {
    serve();
    open();

    const table = await screen.findByRole("table", { name: /Deployments/ });
    const headers = within(table).getAllByRole("columnheader").map((h) => h.textContent);
    expect(headers).toEqual(["Name", "Namespace", "Ready", "Images", "Last observed"]);
    expect(within(table).getAllByText("3/3")).toHaveLength(2);
    expect(within(table).getByText("ghcr.io/example/api:1.0")).toBeInTheDocument();
  });

  it("pages forward and back with the server's cursor", async () => {
    const fetchMock = serve();
    open();

    await screen.findByRole("table", { name: "Deployments, page 1" });
    expect(rows()).toEqual(["api", "web"]);
    const pager = screen.getByRole("navigation", { name: "Deployments pages" });
    expect(within(pager).getByRole("button", { name: "Previous" })).toBeDisabled();

    fireEvent.click(within(pager).getByRole("button", { name: "Next" }));
    await screen.findByRole("table", { name: "Deployments, page 2" });
    expect(rows()).toEqual(["worker"]);
    expect(within(pager).getByRole("button", { name: "Next" })).toBeDisabled();
    expect(deploymentRequests(fetchMock).at(-1)?.searchParams.get("cursor")).toBe("2");
    expect(deploymentRequests(fetchMock).at(-1)?.searchParams.get("limit")).toBe("100");

    fireEvent.click(within(pager).getByRole("button", { name: "Previous" }));
    await screen.findByRole("table", { name: "Deployments, page 1" });
    expect(rows()).toEqual(["api", "web"]);
  });

  it("searches by name after a pause and starts again from the first page", async () => {
    const fetchMock = serve();
    open();
    await screen.findByRole("table", { name: "Deployments, page 1" });
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    await screen.findByRole("table", { name: "Deployments, page 2" });

    fireEvent.change(screen.getByLabelText("Name"), { target: { value: " API " } });
    await waitFor(() => {
      expect(rows()).toEqual(["api"]);
    });
    const last = deploymentRequests(fetchMock).at(-1);
    expect(last?.searchParams.get("search")).toBe("API");
    expect(last?.searchParams.has("cursor")).toBe(false);
    expect(screen.getByRole("table", { name: "Deployments, page 1" })).toBeInTheDocument();
  });

  it("filters by namespace from the cluster's namespaces", async () => {
    const fetchMock = serve();
    open();
    await screen.findByRole("table", { name: "Deployments, page 1" });

    const select = screen.getByLabelText("Namespace");
    await within(select).findByRole("option", { name: "frontend" });
    fireEvent.change(select, { target: { value: "frontend" } });

    await waitFor(() => {
      expect(rows()).toEqual(["web"]);
    });
    expect(deploymentRequests(fetchMock).at(-1)?.searchParams.get("namespace")).toBe("frontend");
  });

  it("includes deleted resources when asked and marks them", async () => {
    serve();
    open("?collection=apps/v1/deployments&search=api");
    await waitFor(() => {
      expect(rows()).toEqual(["api"]);
    });

    fireEvent.click(screen.getByLabelText("Include deleted"));
    await waitFor(() => {
      expect(rows()).toEqual(["api", "old-api"]);
    });
    const deleted = screen.getByRole("link", { name: "old-api" }).closest("tr");
    expect(deleted).toHaveAttribute("data-deleted", "true");
    expect(deleted).toHaveTextContent("Deleted");
  });

  it("says when nothing matches", async () => {
    serve();
    open("?collection=apps/v1/deployments&search=nothing");
    expect(await screen.findByText("No deployments match these filters.")).toBeInTheDocument();
  });

  it("follows namespace pages to fill the namespace filter", async () => {
    const fetchMock = serve();
    const pages: Record<string, { names: string[]; next: string | null }> = {
      "": { names: ["default", "frontend"], next: "p2" },
      p2: { names: ["zz-late"], next: null },
    };
    const base = fetchMock.getMockImplementation();
    fetchMock.mockImplementation((input, init) => {
      const url = new URL(input instanceof Request ? input.url : input.toString(), "http://vn.test");
      if (url.pathname === RESOURCES && url.searchParams.get("collection") === "v1/namespaces") {
        const page = pages[url.searchParams.get("cursor") ?? ""];
        return Promise.resolve(
          jsonResponse({ resources: page?.names.map(namespaceResource) ?? [], next_cursor: page?.next ?? null }),
        );
      }
      return base ? base(input, init) : Promise.reject(new Error("no handler"));
    });
    open();
    await screen.findByRole("table", { name: "Deployments, page 1" });

    const select = screen.getByLabelText("Namespace");
    expect(await within(select).findByRole("option", { name: "zz-late" })).toBeInTheDocument();
    expect(within(select).getByRole("option", { name: "frontend" })).toBeInTheDocument();
  });

  it("hides the namespace filter for cluster-scoped collections", async () => {
    serve();
    open("?collection=v1/nodes");
    await screen.findByLabelText("Name");
    expect(screen.queryByLabelText("Namespace")).not.toBeInTheDocument();
  });
});
