import { apiGet } from "./client";

export type ProjectRole = "viewer" | "operator";

export interface ProjectPermissions {
  view: boolean;
  operate: boolean;
  manage_members: boolean;
}

/** A project as seen by the caller, mirroring `Project` in the vn-core crate. */
export interface Project {
  id: string;
  slug: string;
  name: string;
  created_at: string;
  /** The caller's role. Installation admins may have none and still have full access. */
  role: ProjectRole | null;
  permissions: ProjectPermissions;
}

function parsePermissions(value: unknown): ProjectPermissions | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  const { view, operate, manage_members } = value as Record<string, unknown>;
  if (typeof view !== "boolean" || typeof operate !== "boolean" || typeof manage_members !== "boolean") {
    return undefined;
  }
  return { view, operate, manage_members };
}

export function parseProject(value: unknown): Project | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  const { id, slug, name, created_at, role, permissions } = value as Record<string, unknown>;
  const parsedPermissions = parsePermissions(permissions);
  if (
    typeof id !== "string" ||
    typeof slug !== "string" ||
    typeof name !== "string" ||
    typeof created_at !== "string" ||
    !(role === null || role === "viewer" || role === "operator") ||
    parsedPermissions === undefined
  ) {
    return undefined;
  }
  return { id, slug, name, created_at, role, permissions: parsedPermissions };
}

export function parseProjectList(body: unknown): Project[] | undefined {
  if (typeof body !== "object" || body === null) return undefined;
  const { projects } = body as Record<string, unknown>;
  if (!Array.isArray(projects)) return undefined;
  const parsed = projects.map(parseProject);
  return parsed.every((project) => project !== undefined) ? parsed : undefined;
}

export function fetchProjects(signal?: AbortSignal): Promise<Project[]> {
  return apiGet("/projects", { parse: parseProjectList, ...(signal ? { signal } : {}) });
}
