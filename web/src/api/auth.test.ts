import { describe, expect, it } from "vitest";
import { ApiError, apiSend, isUnauthorized } from "./client";
import { fetchMe, loginUrl, logout, parseMe, userLabel } from "./auth";
import { parseProjectList } from "./projects";
import { jsonResponse, mockFetch } from "../test/utils";

const ME = {
  user: {
    id: "8f9c2b8e-1b6e-4c1e-9d55-6c3a4f1b2a10",
    issuer: "https://id.example.com",
    subject: "alice",
    email: "alice@example.com",
    display_name: "Alice",
  },
  installation_roles: ["admin"],
  session_expires_at: "2026-11-12T20:00:00Z",
};

describe("fetchMe", () => {
  it("parses the signed-in user", async () => {
    const fetchMock = mockFetch(() => Promise.resolve(jsonResponse(ME)));
    await expect(fetchMe()).resolves.toEqual(ME);
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/auth/me",
      expect.objectContaining({ method: "GET", credentials: "same-origin" }),
    );
  });

  it("reports a missing session as unauthorized with the server's code", async () => {
    mockFetch(() =>
      Promise.resolve(jsonResponse({ error: "unauthorized", message: "Sign in to continue." }, 401)),
    );
    const error: unknown = await fetchMe().catch((e: unknown) => e);
    expect(isUnauthorized(error)).toBe(true);
    expect(error).toMatchObject({ code: "unauthorized", message: "Sign in to continue." });
  });

  it("does not treat other failures as unauthorized", () => {
    expect(isUnauthorized(new ApiError("http", "nope", { status: 403 }))).toBe(false);
    expect(isUnauthorized(new ApiError("network", "down"))).toBe(false);
    expect(isUnauthorized(new Error("x"))).toBe(false);
  });
});

describe("parseMe", () => {
  it("rejects malformed users and ignores unknown roles", () => {
    expect(parseMe({ ...ME, user: { ...ME.user, id: 1 } })).toBeUndefined();
    expect(parseMe({ ...ME, installation_roles: "admin" })).toBeUndefined();
    expect(parseMe({ ...ME, installation_roles: ["admin", "owner"] })?.installation_roles).toEqual([
      "admin",
    ]);
  });

  it("labels users by name, then email, then subject", () => {
    expect(userLabel(ME.user)).toBe("Alice");
    expect(userLabel({ ...ME.user, display_name: null })).toBe("alice@example.com");
    expect(userLabel({ ...ME.user, display_name: null, email: null })).toBe("alice");
  });
});

describe("logout", () => {
  it("posts to the logout endpoint and accepts 204", async () => {
    const fetchMock = mockFetch(() => Promise.resolve(new Response(null, { status: 204 })));
    await expect(logout()).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/auth/logout",
      expect.objectContaining({ method: "POST", credentials: "same-origin" }),
    );
  });
});

describe("apiSend", () => {
  it("sends a JSON body and parses the answer", async () => {
    const fetchMock = mockFetch(() => Promise.resolve(jsonResponse({ ok: true }, 201)));
    await expect(
      apiSend("POST", "/projects", {
        body: { slug: "prod", name: "Production" },
        parse: (b) => b as { ok: boolean },
      }),
    ).resolves.toEqual({ ok: true });
    const init = fetchMock.mock.calls[0]?.[1];
    expect(init?.body).toBe('{"slug":"prod","name":"Production"}');
    expect(init?.headers).toMatchObject({ "Content-Type": "application/json" });
  });

  it("surfaces a forbidden answer with its code", async () => {
    mockFetch(() =>
      Promise.resolve(jsonResponse({ error: "forbidden", message: "Admins only." }, 403)),
    );
    await expect(apiSend("POST", "/projects", { body: {} })).rejects.toMatchObject({
      kind: "http",
      status: 403,
      code: "forbidden",
    });
  });
});

describe("loginUrl", () => {
  it("encodes the return path", () => {
    expect(loginUrl("/projects?tab=all")).toBe(
      "/api/v1/auth/login?return_to=%2Fprojects%3Ftab%3Dall",
    );
  });
});

describe("parseProjectList", () => {
  const project = {
    id: "p1",
    slug: "prod",
    name: "Production",
    created_at: "2026-11-12T10:00:00Z",
    role: "viewer",
    permissions: { view: true, operate: false, manage_members: false },
  };

  it("accepts projects with or without a role", () => {
    expect(parseProjectList({ projects: [project, { ...project, role: null }] })).toHaveLength(2);
  });

  it("rejects the list when any project is malformed", () => {
    expect(parseProjectList({ projects: [project, { ...project, role: "admin" }] })).toBeUndefined();
    expect(parseProjectList({ projects: [{ ...project, permissions: {} }] })).toBeUndefined();
    expect(parseProjectList([])).toBeUndefined();
  });
});
