/** Base path for every versioned API route served by vn-server. */
export const API_BASE = "/api/v1";

export type ApiErrorKind = "network" | "timeout" | "unavailable" | "http" | "parse";

/** Default time limit for an API request, including reading the body. */
export const DEFAULT_TIMEOUT_MS = 10_000;

/** Statuses a reverse proxy (or the Vite dev proxy) returns when vn-server is down. */
const GATEWAY_STATUSES: readonly number[] = [502, 503, 504];

/**
 * A failed API call. `kind` lets the UI explain each failure:
 * - `network`: the request never got a response.
 * - `timeout`: the server did not finish responding in time.
 * - `unavailable`: a proxy answered with a gateway error and no JSON body.
 * - `http`: the API answered with an error status.
 * - `parse`: the API answered with a body we do not understand.
 */
export class ApiError extends Error {
  override readonly name = "ApiError";
  readonly kind: ApiErrorKind;
  readonly status: number | undefined;

  constructor(kind: ApiErrorKind, message: string, options?: { status?: number; cause?: unknown }) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.kind = kind;
    this.status = options?.status;
  }
}

export interface ApiGetOptions<T> {
  /** Validates and narrows the decoded JSON body. Return `undefined` to reject it. */
  parse: (body: unknown) => T | undefined;
  /**
   * Non-2xx statuses whose JSON body is still a meaningful answer.
   * The health endpoint, for example, reports a degraded state with 503.
   */
  acceptStatuses?: readonly number[];
  signal?: AbortSignal;
  /** Abort and report a `timeout` error after this many milliseconds. */
  timeoutMs?: number;
}

function apiUrl(path: string): string {
  return `${API_BASE}${path.startsWith("/") ? path : `/${path}`}`;
}

async function readJson(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("json")) {
    return undefined;
  }
  try {
    return (await response.json()) as unknown;
  } catch {
    return undefined;
  }
}

/** Picks a readable message from an API error body: `{"error":"<code>","message":"..."}`. */
function errorMessageFrom(body: unknown): string | undefined {
  if (typeof body !== "object" || body === null) return undefined;
  if ("message" in body && typeof body.message === "string" && body.message !== "") {
    return body.message;
  }
  if ("error" in body && typeof body.error === "string" && body.error !== "") {
    return body.error;
  }
  return undefined;
}

/** GET a JSON resource under {@link API_BASE}. Throws {@link ApiError} on failure. */
export async function apiGet<T>(path: string, options: ApiGetOptions<T>): Promise<T> {
  const url = apiUrl(path);
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const timeoutSignal = AbortSignal.timeout(timeoutMs);
  const signal = options.signal ? AbortSignal.any([options.signal, timeoutSignal]) : timeoutSignal;

  // A caller abort (for example TanStack Query cancelling) propagates as-is.
  // Our own timeout becomes an ApiError the UI can explain.
  const throwIfAborted = (cause?: unknown) => {
    options.signal?.throwIfAborted();
    if (timeoutSignal.aborted) {
      throw new ApiError(
        "timeout",
        `The server did not respond within ${String(Math.round(timeoutMs / 1000))} seconds.`,
        { cause },
      );
    }
  };

  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal,
    });
  } catch (cause) {
    throwIfAborted(cause);
    throw new ApiError("network", "The server could not be reached.", { cause });
  }

  const body = await readJson(response);
  // readJson swallows body errors, so check whether reading was cut short.
  throwIfAborted();
  const accepted =
    response.ok ||
    // An accepted error status only counts when it carries a JSON body. A bare
    // 503 from a proxy or load balancer is an outage, not an API answer.
    (body !== undefined && (options.acceptStatuses ?? []).includes(response.status));

  if (!accepted && body === undefined && GATEWAY_STATUSES.includes(response.status)) {
    throw new ApiError("unavailable", `A proxy answered with HTTP ${String(response.status)}.`, {
      status: response.status,
    });
  }

  if (!accepted) {
    const detail = errorMessageFrom(body);
    throw new ApiError(
      "http",
      detail ?? `The server responded with HTTP ${String(response.status)}.`,
      { status: response.status },
    );
  }

  const parsed = body === undefined ? undefined : options.parse(body);
  if (parsed === undefined) {
    throw new ApiError(
      "parse",
      `The server sent an unexpected response (HTTP ${String(response.status)}).`,
      { status: response.status },
    );
  }
  return parsed;
}
