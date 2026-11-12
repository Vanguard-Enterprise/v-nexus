import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { navigation } from "./auth/session";
import { jsonResponse, mockFetch, renderWithQuery } from "./test/utils";

const ME = {
  user: {
    id: "u1",
    issuer: "https://id.example.com",
    subject: "alice",
    email: "alice@example.com",
    display_name: "Alice Admin",
  },
  installation_roles: ["admin"],
  session_expires_at: "2026-11-12T20:00:00Z",
};

const PROJECTS = {
  projects: [
    {
      id: "p1",
      slug: "prod",
      name: "Production",
      created_at: "2026-11-12T10:00:00Z",
      role: "viewer",
      permissions: { view: true, operate: false, manage_members: false },
    },
  ],
};

const HEALTH = { status: "ok", version: "0.1.0", database: "ok" };

type Routes = Record<string, () => Response>;

function serve(routes: Routes) {
  return mockFetch((input, init) => {
    const url = input instanceof Request ? input.url : input.toString();
    const key = `${init?.method ?? "GET"} ${url}`;
    const route = routes[key];
    return route ? Promise.resolve(route()) : Promise.reject(new Error(`unexpected ${key}`));
  });
}

const unauthorized = () =>
  jsonResponse({ error: "unauthorized", message: "Sign in to continue." }, 401);

describe("App", () => {
  it("shows the signed-in user, their role, and their projects", async () => {
    serve({
      "GET /api/v1/auth/me": () => jsonResponse(ME),
      "GET /api/v1/projects": () => jsonResponse(PROJECTS),
      "GET /api/v1/health": () => jsonResponse(HEALTH),
    });
    renderWithQuery(<App />);

    expect(await screen.findByText("Alice Admin")).toBeInTheDocument();
    expect(screen.getByText("Admin")).toBeInTheDocument();
    expect(await screen.findByText("Production")).toBeInTheDocument();
    expect(screen.getByText("Viewer")).toBeInTheDocument();
  });

  it("signs out through the API and lands on the signed-out page", async () => {
    const assign = vi.spyOn(navigation, "assign").mockImplementation(() => undefined);
    const fetchMock = serve({
      "GET /api/v1/auth/me": () => jsonResponse(ME),
      "GET /api/v1/projects": () => jsonResponse(PROJECTS),
      "GET /api/v1/health": () => jsonResponse(HEALTH),
      "POST /api/v1/auth/logout": () => new Response(null, { status: 204 }),
    });
    renderWithQuery(<App />);

    fireEvent.click(await screen.findByRole("button", { name: "Sign out" }));
    await waitFor(() => {
      expect(assign).toHaveBeenCalledWith("/?signed_out=1");
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/auth/logout",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("offers sign-in when there is no session", async () => {
    serve({
      "GET /api/v1/auth/me": unauthorized,
      "GET /api/v1/health": () => jsonResponse(HEALTH),
    });
    renderWithQuery(<App />);

    const link = await screen.findByRole("link", { name: "Sign in" });
    expect(link).toHaveAttribute("href", "/api/v1/auth/login?return_to=%2F");
    expect(screen.queryByText("Sign out")).not.toBeInTheDocument();
  });

  it("explains a failed sign-in", async () => {
    window.history.replaceState(null, "", "/?login_error=expired");
    serve({
      "GET /api/v1/auth/me": unauthorized,
      "GET /api/v1/health": () => jsonResponse(HEALTH),
    });
    renderWithQuery(<App />);

    expect(await screen.findByRole("alert")).toHaveTextContent("started in another browser");
    window.history.replaceState(null, "", "/");
  });
});
