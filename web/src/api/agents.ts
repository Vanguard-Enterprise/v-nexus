import { apiGet, apiSend } from "./client";
import type { AgentStatus } from "./clusters";
import { asObject, isOneOf, isOptionalString, isString, parseArray } from "./parse";

export type AgentRevocationReason = "revoked" | "replaced";

/** The fields of vn-core's `Agent` this UI shows. */
export interface Agent {
  id: string;
  status: AgentStatus;
  cluster_id: string;
  source_id: string;
  key_id: string;
  agent_version: string;
  enrolled_at: string;
  revoked_at: string | null;
  revocation_reason: AgentRevocationReason | null;
}

export function parseAgent(value: unknown): Agent | undefined {
  const body = asObject(value);
  if (!body) return undefined;
  const { id, status, cluster_id, source_id, key_id, agent_version, enrolled_at, revoked_at, revocation_reason } =
    body;
  if (
    !isString(id) ||
    !isOneOf(status, ["active", "revoked"] as const) ||
    !isString(cluster_id) ||
    !isString(source_id) ||
    !isString(key_id) ||
    !isString(agent_version) ||
    !isString(enrolled_at) ||
    !isOptionalString(revoked_at) ||
    !(revocation_reason === null || isOneOf(revocation_reason, ["revoked", "replaced"] as const))
  ) {
    return undefined;
  }
  return { id, status, cluster_id, source_id, key_id, agent_version, enrolled_at, revoked_at, revocation_reason };
}

export function parseAgentList(value: unknown): Agent[] | undefined {
  return parseArray(asObject(value)?.agents, parseAgent);
}

function agentsPath(slug: string): string {
  return `/projects/${encodeURIComponent(slug)}/agents`;
}

export function fetchAgents(slug: string, signal?: AbortSignal): Promise<Agent[]> {
  return apiGet(agentsPath(slug), { parse: parseAgentList, ...(signal ? { signal } : {}) });
}

/** Revokes an agent. It loses access at once; the cluster and its inventory stay. */
export async function revokeAgent(slug: string, agentId: string): Promise<Agent> {
  const agent = await apiSend("POST", `${agentsPath(slug)}/${encodeURIComponent(agentId)}/revoke`, {
    parse: parseAgent,
  });
  if (!agent) throw new Error("Missing agent in the answer.");
  return agent;
}
