import { ApiError } from "../api";

/** Whether an error is a 404 or 403, where showing the rest of a page makes no sense. */
export function isMissing(error: Error | null): boolean {
  return error instanceof ApiError && error.kind === "http" && (error.status === 404 || error.status === 403);
}

/** Whether retrying a failed request could help. Client errors (4xx) will not change. */
export function isRetryable(error: unknown): boolean {
  return !(error instanceof ApiError && error.kind === "http" && error.status !== undefined && error.status < 500);
}
