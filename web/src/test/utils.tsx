import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { vi } from "vitest";

export function renderWithQuery(ui: ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity } },
  });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
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
