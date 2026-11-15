import { act, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ClustersPanel } from "./ClustersPanel";
import { DISCONNECTED, NEVER_CONNECTED, cluster } from "../test/fixtures";
import { forbidden, jsonResponse, mockFetch, renderPage, serveApi } from "../test/utils";

const noop = () => undefined;
const page = { path: "/projects/:slug", url: "/projects/prod" };

function renderPanel(canRegister = true) {
  return renderPage(<ClustersPanel slug="prod" canRegister={canRegister} registering={false} onRegister={noop} />, page);
}

function row(name: string): HTMLElement {
  const link = screen.getByRole("link", { name });
  const tr = link.closest("tr");
  if (!tr) throw new Error(`No row for ${name}`);
  return tr;
}

describe("ClustersPanel", () => {
  it("shows a loading state", () => {
    mockFetch(() => new Promise<Response>(() => undefined));
    renderPanel();
    expect(screen.getByRole("region", { name: "Clusters" })).toHaveAttribute("aria-busy", "true");
    expect(screen.getByText("Loading clusters…")).toBeInTheDocument();
  });

  it("invites admins to register the first cluster", async () => {
    serveApi({ "GET /api/v1/projects/prod/clusters": () => jsonResponse({ clusters: [] }) });
    renderPanel();
    expect(await screen.findByText("No clusters yet")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Register cluster" })).toBeInTheDocument();
  });

  it("tells other users who can register clusters", async () => {
    serveApi({ "GET /api/v1/projects/prod/clusters": () => jsonResponse({ clusters: [] }) });
    renderPanel(false);
    expect(await screen.findByText("An installation admin can register a cluster in this project.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Register cluster" })).not.toBeInTheDocument();
  });

  it("explains a 403", async () => {
    serveApi({ "GET /api/v1/projects/prod/clusters": () => forbidden() });
    renderPanel();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("No access");
    expect(alert).toHaveTextContent("does not allow this");
  });

  it("offers a retry for server errors", async () => {
    serveApi({
      "GET /api/v1/projects/prod/clusters": () => jsonResponse({ error: "internal", message: "Database down." }, 500),
    });
    renderPanel();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Clusters could not be loaded");
    expect(within(alert).getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });

  it("lists clusters with connection state, freshness, version, and counts", async () => {
    serveApi({
      "GET /api/v1/projects/prod/clusters": () =>
        jsonResponse({ clusters: [NEVER_CONNECTED, DISCONNECTED, cluster()] }),
    });
    renderPanel();

    await screen.findByRole("link", { name: "prod-east" });
    const live = row("prod-east");
    expect(live).toHaveTextContent("Connected");
    expect(live).toHaveTextContent("Live");
    expect(live).toHaveTextContent("v1.34.2");
    const cells = within(live).getAllByRole("cell").map((cell) => cell.textContent);
    // Nodes, namespaces, and the three workload kinds together.
    expect(cells.slice(-3)).toEqual(["3", "7", "18"]);
    expect(within(live).getByRole("link", { name: "prod-east" })).toHaveAttribute("href", "/projects/prod/clusters/c1");

    const stale = row("lab");
    expect(stale).toHaveTextContent("Disconnected");
    expect(stale).toHaveTextContent(/Stale, from/);

    const fresh = row("edge");
    expect(fresh).toHaveTextContent("Never connected");
    expect(fresh).toHaveTextContent("None yet");
    expect(fresh).toHaveTextContent("Never");
  });

  it("keeps the list on screen and says when a refresh fails", async () => {
    let failing = false;
    serveApi({
      "GET /api/v1/projects/prod/clusters": () =>
        failing
          ? jsonResponse({ error: "internal", message: "database unavailable" }, 500)
          : jsonResponse({ clusters: [cluster()] }),
    });
    const { client } = renderPanel();
    await screen.findByRole("link", { name: "prod-east" });
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();

    failing = true;
    await act(() => client.refetchQueries());

    expect(await screen.findByRole("alert")).toHaveTextContent(/The cluster list could not be refreshed/);
    expect(row("prod-east")).toHaveTextContent("Connected");
  });
});
