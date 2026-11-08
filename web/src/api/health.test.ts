import { describe, expect, it } from "vitest";
import { ApiError, apiGet } from "./client";
import { fetchHealth, parseHealthResponse } from "./health";
import { jsonResponse, mockFetch } from "../test/utils";

async function captureError(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof ApiError) return error;
    throw error;
  }
  throw new Error("Expected the promise to reject");
}

describe("fetchHealth", () => {
  it("requests the versioned health endpoint", async () => {
    const fetchMock = mockFetch(() =>
      Promise.resolve(jsonResponse({ status: "ok", version: "1.2.3", database: "ok" })),
    );

    await expect(fetchHealth()).resolves.toEqual({ status: "ok", version: "1.2.3", database: "ok" });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/health",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("resolves a 503 that carries a degraded health body", async () => {
    mockFetch(() =>
      Promise.resolve(
        jsonResponse({ status: "degraded", version: "1.2.3", database: "unavailable" }, 503),
      ),
    );

    await expect(fetchHealth()).resolves.toEqual({
      status: "degraded",
      version: "1.2.3",
      database: "unavailable",
    });
  });

  it("rejects a 503 without JSON as an outage, not a degraded state", async () => {
    mockFetch(() =>
      Promise.resolve(new Response("Service Unavailable", { status: 503, headers: { "Content-Type": "text/plain" } })),
    );

    const error = await captureError(fetchHealth());
    expect(error.kind).toBe("unavailable");
    expect(error.status).toBe(503);
  });

  it("rejects a 503 with JSON that is not a health body as a parse error", async () => {
    mockFetch(() => Promise.resolve(jsonResponse({ unexpected: true }, 503)));

    const error = await captureError(fetchHealth());
    expect(error.kind).toBe("parse");
    expect(error.status).toBe(503);
  });

  it("rejects other HTTP errors with the server message when present", async () => {
    mockFetch(() =>
      Promise.resolve(
        jsonResponse({ error: "internal", message: "The server hit an unexpected error." }, 500),
      ),
    );

    const error = await captureError(fetchHealth());
    expect(error.kind).toBe("http");
    expect(error.status).toBe(500);
    expect(error.message).toBe("The server hit an unexpected error.");
  });

  it("falls back to the error code when an error body has no message", async () => {
    mockFetch(() => Promise.resolve(jsonResponse({ error: "internal" }, 500)));

    const error = await captureError(fetchHealth());
    expect(error.message).toBe("internal");
  });

  it("reports a bare 502 from the dev proxy as an outage", async () => {
    mockFetch(() =>
      Promise.resolve(new Response("", { status: 502, headers: { "Content-Type": "text/plain" } })),
    );

    const error = await captureError(fetchHealth());
    expect(error.kind).toBe("unavailable");
    expect(error.status).toBe(502);
  });

  it("wraps network failures", async () => {
    mockFetch(() => Promise.reject(new TypeError("Failed to fetch")));

    const error = await captureError(fetchHealth());
    expect(error.kind).toBe("network");
    expect(error.status).toBeUndefined();
  });
});

describe("apiGet timeouts", () => {
  /** A fetch that never answers until its signal aborts, like a stalled server. */
  function hangingFetch() {
    return mockFetch(
      (_input, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            reject(init.signal?.reason as Error);
          });
        }),
    );
  }

  it("reports a stalled request as a timeout", async () => {
    hangingFetch();

    const error = await captureError(apiGet("/health", { parse: (b) => b, timeoutMs: 20 }));
    expect(error.kind).toBe("timeout");
  });

  it("recovers on the next request after a timeout", async () => {
    hangingFetch();
    await captureError(apiGet("/health", { parse: (b) => b, timeoutMs: 20 }));

    mockFetch(() =>
      Promise.resolve(jsonResponse({ status: "ok", version: "1.2.3", database: "ok" })),
    );
    await expect(fetchHealth()).resolves.toMatchObject({ status: "ok" });
  });

  it("passes a caller abort through instead of reporting a timeout", async () => {
    hangingFetch();
    const controller = new AbortController();
    const pending = apiGet("/health", {
      parse: (b) => b,
      signal: controller.signal,
      timeoutMs: 5_000,
    });
    controller.abort();

    await expect(pending).rejects.not.toBeInstanceOf(ApiError);
  });
});

describe("parseHealthResponse", () => {
  it("rejects unknown status values and missing fields", () => {
    expect(parseHealthResponse({ status: "maybe", version: "1", database: "ok" })).toBeUndefined();
    expect(parseHealthResponse({ status: "ok", database: "ok" })).toBeUndefined();
    expect(parseHealthResponse(null)).toBeUndefined();
  });
});
