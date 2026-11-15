import { describe, expect, it } from "vitest";
import { fetchAgents, revokeAgent } from "./agents";
import {
  createEnrollmentToken,
  fetchEnrollmentTokens,
  installCommands,
  parseEnrollmentToken,
  revokeEnrollmentToken,
} from "./enrollment";
import { fetchMembers, fetchProject } from "./projects";
import { PROJECT, TOKEN } from "../test/fixtures";
import { jsonResponse, mockFetch, sentJson, urlOf } from "../test/utils";


const AGENT = {
  id: "a1",
  kind: "kubernetes",
  status: "active",
  project_id: "p1",
  cluster_id: "c1",
  cluster_name: "prod-east",
  source_id: "s1",
  key_id: "key",
  cluster_fingerprint: "fp",
  agent_version: "0.1.0",
  protocol_versions: [1],
  enrollment_token_id: "t1",
  enrolled_by: "u1",
  enrolled_at: "2026-11-15T10:05:00Z",
  source_address: null,
  revoked_at: null,
  revoked_by: null,
  revocation_reason: null,
};

describe("createEnrollmentToken", () => {
  it("posts a new-cluster target with the expiry and returns the one-time secret", async () => {
    const fetchMock = mockFetch(() =>
      Promise.resolve(jsonResponse({ token: TOKEN, secret: "vn_enroll_abc", installation_id: "i1" }, 201)),
    );
    const created = await createEnrollmentToken("prod", {
      target: { type: "new_cluster", display_name: "prod-east" },
      expiresInMinutes: 240,
    });
    expect(created.secret).toBe("vn_enroll_abc");
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/projects/prod/enrollment-tokens",
      expect.objectContaining({ method: "POST" }),
    );
    expect(sentJson(fetchMock.mock.calls[0]?.[1])).toEqual({
      kind: "kubernetes",
      target: { type: "new_cluster", display_name: "prod-east" },
      expires_in_minutes: 240,
    });
  });

  it("surfaces a 403 for users who may not register clusters", async () => {
    mockFetch(() => Promise.resolve(jsonResponse({ error: "forbidden", message: "Not allowed." }, 403)));
    await expect(
      createEnrollmentToken("prod", { target: { type: "new_cluster", display_name: "x" }, expiresInMinutes: 60 }),
    ).rejects.toMatchObject({ status: 403, code: "forbidden" });
  });
});

describe("enrollment token list and revoke", () => {
  it("lists tokens with either target type", async () => {
    const replacement = { ...TOKEN, id: "t2", target: { type: "replace_source", source_id: "s1" } };
    mockFetch(() => Promise.resolve(jsonResponse({ tokens: [TOKEN, replacement] })));
    const tokens = await fetchEnrollmentTokens("prod");
    expect(tokens.map((t) => t.target.type)).toEqual(["new_cluster", "replace_source"]);
  });

  it("revokes by token ID", async () => {
    const fetchMock = mockFetch(() => Promise.resolve(jsonResponse({ ...TOKEN, status: "revoked" })));
    await expect(revokeEnrollmentToken("prod", "t1")).resolves.toMatchObject({ status: "revoked" });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/projects/prod/enrollment-tokens/t1/revoke",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("rejects unknown statuses and targets", () => {
    expect(parseEnrollmentToken({ ...TOKEN, status: "pending" })).toBeUndefined();
    expect(parseEnrollmentToken({ ...TOKEN, target: { type: "new_cluster" } })).toBeUndefined();
  });
});

describe("agents", () => {
  it("lists and revokes agents", async () => {
    const fetchMock = mockFetch((input) =>
      Promise.resolve(
        urlOf(input).endsWith("/revoke")
          ? jsonResponse({ ...AGENT, status: "revoked", revoked_at: "2026-11-15T11:00:00Z", revocation_reason: "revoked" })
          : jsonResponse({ agents: [AGENT] }),
      ),
    );
    await expect(fetchAgents("prod")).resolves.toMatchObject([{ id: "a1", status: "active" }]);
    await expect(revokeAgent("prod", "a1")).resolves.toMatchObject({ status: "revoked", revocation_reason: "revoked" });
    expect(fetchMock).toHaveBeenLastCalledWith(
      "/api/v1/projects/prod/agents/a1/revoke",
      expect.objectContaining({ method: "POST" }),
    );
  });
});

describe("projects", () => {
  it("shows one project and its members", async () => {
    const member = { user: { id: "u2", issuer: "i", subject: "bob", email: null, display_name: "Bob" }, role: "viewer", granted_at: "2026-11-12T10:00:00Z" };
    mockFetch((input) =>
      Promise.resolve(urlOf(input).endsWith("/members") ? jsonResponse({ members: [member] }) : jsonResponse(PROJECT)),
    );
    await expect(fetchProject("prod")).resolves.toMatchObject({ slug: "prod" });
    await expect(fetchMembers("prod")).resolves.toEqual([member]);
  });
});

describe("installCommands", () => {
  it("builds the three install commands with the server URL and token", () => {
    expect(installCommands("https://vn.example.com/", "vn_enroll_abc")).toEqual([
      "kubectl create namespace vn-agent",
      "kubectl -n vn-agent create secret generic vn-agent-enrollment \\\n  --from-literal=server-url=https://vn.example.com --from-literal=token=vn_enroll_abc",
      "kubectl apply -f https://vn.example.com/api/v1/agent/manifests/kubernetes.yaml",
    ]);
  });
});
