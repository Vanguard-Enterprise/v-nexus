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
  /** Machine-readable `error` code from the API body, such as `unauthorized`. */
  readonly code: string | undefined;

  constructor(
    kind: ApiErrorKind,
    message: string,
    options?: { status?: number; code?: string; cause?: unknown },
  ) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.kind = kind;
    this.status = options?.status;
    this.code = options?.code;
  }
}

/** Whether `error` is the API saying the caller is not signed in. */
export function isUnauthorized(error: unknown): error is ApiError {
  return error instanceof ApiError && error.kind === "http" && error.status === 401;
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

export interface ApiSendOptions<T> {
  /** JSON request body. */
  body?: unknown;
  /** Validates the JSON answer. Omit it for endpoints that answer 204. */
  parse?: (body: unknown) => T | undefined;
  signal?: AbortSignal;
  timeoutMs?: number;
}

interface RequestOptions {
  body?: unknown;
  acceptStatuses?: readonly number[] | undefined;
  signal?: AbortSignal | undefined;
  timeoutMs?: number | undefined;
}

interface RawResponse {
  status: number;
  /** Decoded JSON, or `undefined` when the answer had no JSON body. */
  body: unknown;
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

function errorCodeFrom(body: unknown): string | undefined {
  if (typeof body !== "object" || body === null) return undefined;
  return "error" in body && typeof body.error === "string" ? body.error : undefined;
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

function parseOrThrow<T>(raw: RawResponse, parse: (body: unknown) => T | undefined): T {
  const parsed = raw.body === undefined ? undefined : parse(raw.body);
  if (parsed === undefined) {
    throw new ApiError(
      "parse",
      `The server sent an unexpected response (HTTP ${String(raw.status)}).`,
      { status: raw.status },
    );
  }
  return parsed;
}

/** Sends a request and throws {@link ApiError} unless the answer is accepted. */
async function request(method: string, path: string, options: RequestOptions): Promise<RawResponse> {
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

  const headers: Record<string, string> = { Accept: "application/json" };
  const init: RequestInit = { method, headers, credentials: "same-origin", signal };
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(options.body);
  }

  let response: Response;
  try {
    response = await fetch(url, init);
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
    const code = errorCodeFrom(body);
    throw new ApiError(
      "http",
      detail ?? `The server responded with HTTP ${String(response.status)}.`,
      code === undefined ? { status: response.status } : { status: response.status, code },
    );
  }

  return { status: response.status, body };
}

/** GET a JSON resource under {@link API_BASE}. Throws {@link ApiError} on failure. */
export async function apiGet<T>(path: string, options: ApiGetOptions<T>): Promise<T> {
  const raw = await request("GET", path, options);
  return parseOrThrow(raw, options.parse);
}

/**
 * Sends a state-changing request under {@link API_BASE}. The browser attaches the session
 * cookie and the `Origin` header the server checks. Resolves the parsed JSON answer, or
 * `undefined` when no `parse` is given (for 204 answers).
 */
export async function apiSend<T>(
  method: "POST" | "PUT" | "DELETE",
  path: string,
  options: ApiSendOptions<T> = {},
): Promise<T | undefined> {
  const raw = await request(method, path, options);
  return options.parse ? parseOrThrow(raw, options.parse) : undefined;
}
