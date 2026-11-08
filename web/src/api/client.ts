/** Base path for every versioned API route served by vn-server. */
export const API_BASE = "/api/v1";

export type ApiErrorKind = "network" | "unavailable" | "http" | "parse";

/** Statuses a reverse proxy (or the Vite dev proxy) returns when vn-server is down. */
const GATEWAY_STATUSES: readonly number[] = [502, 503, 504];

/**
 * A failed API call. `kind` lets the UI explain each failure:
 * - `network`: the request never got a response.
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

function errorMessageFrom(body: unknown): string | undefined {
  if (typeof body === "object" && body !== null && "error" in body) {
    const { error } = body;
    if (typeof error === "string") return error;
    if (typeof error === "object" && error !== null && "message" in error) {
      const { message } = error;
      if (typeof message === "string") return message;
    }
  }
  if (typeof body === "object" && body !== null && "message" in body) {
    const { message } = body;
    if (typeof message === "string") return message;
  }
  return undefined;
}

/** GET a JSON resource under {@link API_BASE}. Throws {@link ApiError} on failure. */
export async function apiGet<T>(path: string, options: ApiGetOptions<T>): Promise<T> {
  const url = apiUrl(path);
  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
      headers: { Accept: "application/json" },
      ...(options.signal ? { signal: options.signal } : {}),
    });
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === "AbortError") {
      throw cause;
    }
    throw new ApiError("network", "The server could not be reached.", { cause });
  }

  const body = await readJson(response);
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
