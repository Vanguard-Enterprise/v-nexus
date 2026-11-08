import { apiGet } from "./client";

export type HealthStatus = "ok" | "degraded";
export type DatabaseStatus = "ok" | "unavailable";

/** Body of `GET /api/v1/health`, mirroring `HealthResponse` in the vn-core crate. */
export interface HealthResponse {
  status: HealthStatus;
  /** vn-server crate version. */
  version: string;
  database: DatabaseStatus;
}

const HEALTH_STATUSES: readonly string[] = ["ok", "degraded"] satisfies HealthStatus[];
const DATABASE_STATUSES: readonly string[] = ["ok", "unavailable"] satisfies DatabaseStatus[];

export function parseHealthResponse(body: unknown): HealthResponse | undefined {
  if (typeof body !== "object" || body === null) return undefined;
  const { status, version, database } = body as Record<string, unknown>;
  if (
    typeof status !== "string" ||
    !HEALTH_STATUSES.includes(status) ||
    typeof version !== "string" ||
    typeof database !== "string" ||
    !DATABASE_STATUSES.includes(database)
  ) {
    return undefined;
  }
  return {
    status: status as HealthStatus,
    version,
    database: database as DatabaseStatus,
  };
}

/**
 * Fetches server health. A 503 with a valid JSON body is a normal answer
 * (the server is up but degraded), so it resolves instead of throwing.
 */
export function fetchHealth(signal?: AbortSignal): Promise<HealthResponse> {
  return apiGet("/health", {
    parse: parseHealthResponse,
    acceptStatuses: [503],
    ...(signal ? { signal } : {}),
  });
}
