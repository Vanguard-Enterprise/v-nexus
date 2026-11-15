import { apiGet, apiSend } from "./client";
import { asObject, isOneOf, isOptionalString, isString, parseArray } from "./parse";

/** Default and longest lifetime of an enrollment token, matching vn-core. */
export const DEFAULT_ENROLLMENT_TOKEN_MINUTES = 60;
export const MAX_ENROLLMENT_TOKEN_MINUTES = 24 * 60;

export type EnrollmentTokenStatus = "active" | "used" | "expired" | "revoked";
const TOKEN_STATUSES: readonly EnrollmentTokenStatus[] = ["active", "used", "expired", "revoked"];

/** What an enrollment token enrolls, mirroring `EnrollmentTarget` in vn-core. */
export type EnrollmentTarget =
  | { type: "new_cluster"; display_name: string }
  | { type: "replace_source"; source_id: string };

/** An enrollment token's metadata. The secret is only ever in {@link CreatedEnrollmentToken}. */
export interface EnrollmentToken {
  id: string;
  project_id: string;
  kind: "kubernetes";
  target: EnrollmentTarget;
  status: EnrollmentTokenStatus;
  created_by: string | null;
  created_at: string;
  expires_at: string;
  used_at: string | null;
  revoked_at: string | null;
  revoked_by: string | null;
}

export interface CreatedEnrollmentToken {
  token: EnrollmentToken;
  /** The token string for the agent. The server returns it only once. */
  secret: string;
  installation_id: string;
}

function parseTarget(value: unknown): EnrollmentTarget | undefined {
  const body = asObject(value);
  if (!body) return undefined;
  if (body.type === "new_cluster" && isString(body.display_name)) {
    return { type: "new_cluster", display_name: body.display_name };
  }
  if (body.type === "replace_source" && isString(body.source_id)) {
    return { type: "replace_source", source_id: body.source_id };
  }
  return undefined;
}

export function parseEnrollmentToken(value: unknown): EnrollmentToken | undefined {
  const body = asObject(value);
  if (!body) return undefined;
  const { id, project_id, kind, status, created_by, created_at, expires_at, used_at, revoked_at, revoked_by } =
    body;
  const target = parseTarget(body.target);
  if (
    !isString(id) ||
    !isString(project_id) ||
    kind !== "kubernetes" ||
    !target ||
    !isOneOf(status, TOKEN_STATUSES) ||
    !isOptionalString(created_by) ||
    !isString(created_at) ||
    !isString(expires_at) ||
    !isOptionalString(used_at) ||
    !isOptionalString(revoked_at) ||
    !isOptionalString(revoked_by)
  ) {
    return undefined;
  }
  return { id, project_id, kind, target, status, created_by, created_at, expires_at, used_at, revoked_at, revoked_by };
}

export function parseCreatedEnrollmentToken(value: unknown): CreatedEnrollmentToken | undefined {
  const body = asObject(value);
  if (!body) return undefined;
  const token = parseEnrollmentToken(body.token);
  const { secret, installation_id } = body;
  if (!token || !isString(secret) || !isString(installation_id)) return undefined;
  return { token, secret, installation_id };
}

export function parseEnrollmentTokenList(value: unknown): EnrollmentToken[] | undefined {
  return parseArray(asObject(value)?.tokens, parseEnrollmentToken);
}

function tokensPath(slug: string): string {
  return `/projects/${encodeURIComponent(slug)}/enrollment-tokens`;
}

export function fetchEnrollmentTokens(slug: string, signal?: AbortSignal): Promise<EnrollmentToken[]> {
  return apiGet(tokensPath(slug), { parse: parseEnrollmentTokenList, ...(signal ? { signal } : {}) });
}

export interface CreateEnrollmentTokenInput {
  target: EnrollmentTarget;
  expiresInMinutes: number;
}

export async function createEnrollmentToken(
  slug: string,
  input: CreateEnrollmentTokenInput,
): Promise<CreatedEnrollmentToken> {
  const created = await apiSend("POST", tokensPath(slug), {
    body: { kind: "kubernetes", target: input.target, expires_in_minutes: input.expiresInMinutes },
    parse: parseCreatedEnrollmentToken,
  });
  // apiSend only resolves undefined without a parser.
  if (!created) throw new Error("Missing enrollment token in the answer.");
  return created;
}

export async function revokeEnrollmentToken(slug: string, tokenId: string): Promise<EnrollmentToken> {
  const token = await apiSend("POST", `${tokensPath(slug)}/${encodeURIComponent(tokenId)}/revoke`, {
    parse: parseEnrollmentToken,
  });
  if (!token) throw new Error("Missing enrollment token in the answer.");
  return token;
}

/**
 * Commands that install the agent with a new enrollment token. `serverUrl` is the URL
 * agents use to reach this server; the UI passes its own origin.
 *
 * The namespace and Secret commands create or update, so they also work when an earlier
 * attempt left them behind (for example when its token expired before the agent enrolled).
 * The Secret is applied server-side, which does not copy the token into an annotation.
 */
export function installCommands(serverUrl: string, secret: string): string[] {
  const base = serverUrl.replace(/\/+$/, "");
  return [
    "kubectl create namespace vn-agent --dry-run=client -o yaml | kubectl apply -f -",
    [
      "kubectl -n vn-agent create secret generic vn-agent-enrollment \\",
      `  --from-literal=server-url=${base} --from-literal=token=${secret} \\`,
      "  --dry-run=client -o yaml | kubectl apply --server-side --force-conflicts -f -",
    ].join("\n"),
    `kubectl apply -f ${base}/api/v1/agent/manifests/kubernetes.yaml`,
  ];
}
