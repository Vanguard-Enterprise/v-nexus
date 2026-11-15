import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { MemoryRouter, Route, Routes } from "react-router";
import { vi } from "vitest";
import type { Me } from "../api";
import { MeContext } from "../auth/me";

export function testQueryClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
  });
}

export function renderWithQuery(ui: ReactElement) {
  const client = testQueryClient();
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

export const ADMIN: Me = {
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

export const VIEWER: Me = {
  ...ADMIN,
  user: { ...ADMIN.user, id: "u2", subject: "bob", display_name: "Bob Viewer" },
  installation_roles: [],
};

interface PageOptions {
  /** Route pattern, such as `/projects/:slug`. */
  path: string;
  /** Location to open, such as `/projects/prod`. */
  url: string;
  me?: Me;
}

/** Renders `ui` at a route with a signed-in user, a router, and a fresh query client. */
export function renderPage(ui: ReactElement, { path, url, me = ADMIN }: PageOptions) {
  const client = testQueryClient();
  const result = render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[url]}>
        <MeContext value={me}>
          <Routes>
            <Route path={path} element={ui} />
          </Routes>
        </MeContext>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { ...result, client };
}

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/** Replaces global fetch with a mock and returns it. Vitest unstubs globals after each test. */
export function mockFetch(
  implementation: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>,
) {
  const fetchMock = vi.fn<typeof fetch>(implementation);
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

export type ApiHandler = (url: URL, init?: RequestInit) => Response | Promise<Response>;

/**
 * Serves API routes keyed by method and path without the query string, such as
 * `GET /api/v1/projects/prod`. Unknown routes reject so tests notice them.
 */
export function serveApi(routes: Record<string, ApiHandler>) {
  return mockFetch((input, init) => {
    const raw = input instanceof Request ? input.url : input.toString();
    const url = new URL(raw, "http://vn.test");
    const key = `${init?.method ?? "GET"} ${url.pathname}`;
    const handler = routes[key];
    return handler ? Promise.resolve(handler(url, init)) : Promise.reject(new Error(`unexpected ${key}`));
  });
}

/** Requests the mock received for a method and path, as URLs. */
export function requestsTo(fetchMock: ReturnType<typeof mockFetch>, method: string, path: string): URL[] {
  return fetchMock.mock.calls
    .filter(([input, init]) => {
      const url = new URL(input instanceof Request ? input.url : input.toString(), "http://vn.test");
      return (init?.method ?? "GET") === method && url.pathname === path;
    })
    .map(([input]) => new URL(input instanceof Request ? input.url : input.toString(), "http://vn.test"));
}

export const notFound = () => jsonResponse({ error: "not_found", message: "not found" }, 404);
export const forbidden = (message = "Your role in project `prod` does not allow this.") =>
  jsonResponse({ error: "forbidden", message }, 403);

/** The JSON body a mocked request sent, decoded. */
export function sentJson(init: RequestInit | undefined): unknown {
  return typeof init?.body === "string" ? (JSON.parse(init.body) as unknown) : undefined;
}

/** The URL of a mocked request. */
export function urlOf(input: RequestInfo | URL): string {
  return input instanceof Request ? input.url : input.toString();
}
