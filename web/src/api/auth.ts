import { API_BASE, apiGet, apiSend } from "./client";

export type InstallationRole = "admin";

/** A person known to VN, mirroring `User` in the vn-core crate. */
export interface User {
  id: string;
  issuer: string;
  subject: string;
  email: string | null;
  display_name: string | null;
}

/** Body of `GET /api/v1/auth/me`, mirroring `MeResponse` in the vn-core crate. */
export interface Me {
  user: User;
  installation_roles: InstallationRole[];
  session_expires_at: string;
}

function optionalString(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

export function parseUser(body: unknown): User | undefined {
  if (typeof body !== "object" || body === null) return undefined;
  const { id, issuer, subject, email, display_name } = body as Record<string, unknown>;
  if (
    typeof id !== "string" ||
    typeof issuer !== "string" ||
    typeof subject !== "string" ||
    !optionalString(email) ||
    !optionalString(display_name)
  ) {
    return undefined;
  }
  return { id, issuer, subject, email, display_name };
}

export function parseMe(body: unknown): Me | undefined {
  if (typeof body !== "object" || body === null) return undefined;
  const { user, installation_roles, session_expires_at } = body as Record<string, unknown>;
  const parsedUser = parseUser(user);
  if (
    parsedUser === undefined ||
    !Array.isArray(installation_roles) ||
    typeof session_expires_at !== "string"
  ) {
    return undefined;
  }
  // Ignore roles this UI does not know yet instead of rejecting the whole answer.
  const roles = installation_roles.filter((role): role is InstallationRole => role === "admin");
  return { user: parsedUser, installation_roles: roles, session_expires_at };
}

export function fetchMe(signal?: AbortSignal): Promise<Me> {
  return apiGet("/auth/me", { parse: parseMe, ...(signal ? { signal } : {}) });
}

/** Ends the session on the server. The server also clears the session cookie. */
export async function logout(): Promise<void> {
  await apiSend("POST", "/auth/logout");
}

/** URL that starts browser sign-in and returns to `returnTo` (a same-origin path) after. */
export function loginUrl(returnTo: string): string {
  return `${API_BASE}/auth/login?return_to=${encodeURIComponent(returnTo)}`;
}

/** The name to show for a user: display name, then email, then subject. */
export function userLabel(user: User): string {
  return user.display_name ?? user.email ?? user.subject;
}
