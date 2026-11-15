/**
 * Small helpers for validating decoded JSON. Each returns `undefined` when the value
 * does not have the expected shape, so parsers can reject a whole answer.
 */

export type JsonObject = Record<string, unknown>;

export function asObject(value: unknown): JsonObject | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;
}

export function isString(value: unknown): value is string {
  return typeof value === "string";
}

export function isOptionalString(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

export function isOneOf<T extends string>(value: unknown, options: readonly T[]): value is T {
  return typeof value === "string" && (options as readonly string[]).includes(value);
}

/** Parses every item of an array, or rejects the array when any item fails. */
export function parseArray<T>(value: unknown, parse: (item: unknown) => T | undefined): T[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const parsed = value.map(parse);
  return parsed.every((item) => item !== undefined) ? parsed : undefined;
}

/* Lenient readers for server-computed summaries, where any field may be null or absent. */

export function readString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

export function readNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

export function readBoolean(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

export function readStrings(value: unknown): string[] | null {
  return Array.isArray(value) ? value.filter(isString) : null;
}
