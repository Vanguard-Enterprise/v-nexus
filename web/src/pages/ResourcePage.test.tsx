import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ResourcePage } from "./ResourcePage";
import { DISCONNECTED, PROJECT, cluster, deployment } from "../test/fixtures";
import { jsonResponse, notFound, renderPage, serveApi } from "../test/utils";

const OBJECT = { apiVersion: "apps/v1", kind: "Deployment", metadata: { name: "api", namespace: "default" } };
const page = {
  path: "/projects/:slug/clusters/:clusterId/resources/:resourceId",
  url: "/projects/prod/clusters/c1/resources/r-api",
};

describe("ResourcePage", () => {
  it("shows metadata, the summary, and the object as formatted JSON", async () => {
    serveApi({
      "GET /api/v1/projects/prod": () => jsonResponse(PROJECT),
      "GET /api/v1/projects/prod/clusters/c1": () => jsonResponse(cluster()),
      "GET /api/v1/projects/prod/clusters/c1/resources/r-api": () =>
        jsonResponse({ ...deployment("api"), object: OBJECT }),
    });
    renderPage(<ResourcePage />, page);

    expect(await screen.findByRole("heading", { level: 1, name: "api" })).toBeInTheDocument();
    expect(screen.getByText("uid-api")).toBeInTheDocument();
    expect(screen.getByText("ghcr.io/example/api:1.0")).toBeInTheDocument();
    const json = screen.getByLabelText("Deployment api as JSON", { selector: "pre" });
    expect(json.textContent).toBe(JSON.stringify(OBJECT, null, 2));
    const crumbs = screen.getByRole("navigation", { name: "Breadcrumb" });
    expect(within(crumbs).getByRole("link", { name: "prod-east" })).toHaveAttribute(
      "href",
      "/projects/prod/clusters/c1?collection=apps%2Fv1%2Fdeployments",
    );
  });

  it("marks deleted resources and stale clusters", async () => {
    serveApi({
      "GET /api/v1/projects/prod": () => jsonResponse(PROJECT),
      "GET /api/v1/projects/prod/clusters/c1": () => jsonResponse({ ...DISCONNECTED, id: "c1" }),
      "GET /api/v1/projects/prod/clusters/c1/resources/r-api": () =>
        jsonResponse({ ...deployment("api", { state: "deleted", deleted_at: "2026-11-15T09:00:00Z" }), object: OBJECT }),
    });
    renderPage(<ResourcePage />, page);

    expect(await screen.findByText(/was deleted from the cluster/)).toBeInTheDocument();
    expect(await screen.findByText(/The cluster is disconnected/)).toBeInTheDocument();
  });

  it("shows not found", async () => {
    serveApi({
      "GET /api/v1/projects/prod": () => jsonResponse(PROJECT),
      "GET /api/v1/projects/prod/clusters/c1": () => jsonResponse(cluster()),
      "GET /api/v1/projects/prod/clusters/c1/resources/r-api": notFound,
    });
    renderPage(<ResourcePage />, page);
    expect(await screen.findByRole("alert")).toHaveTextContent("This resource does not exist");
  });
});
