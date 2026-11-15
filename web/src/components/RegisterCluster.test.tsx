import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ProjectPage } from "../pages/ProjectPage";
import { PROJECT, TOKEN } from "../test/fixtures";
import { VIEWER, jsonResponse, renderPage, requestsTo, sentJson, serveApi } from "../test/utils";

const SECRET = "vn_enroll_t1_0123456789abcdef";

function serve(overrides: Parameters<typeof serveApi>[0] = {}) {
  let tokens: unknown[] = [];
  return serveApi({
    "GET /api/v1/projects/prod": () => jsonResponse(PROJECT),
    "GET /api/v1/projects/prod/clusters": () => jsonResponse({ clusters: [] }),
    "GET /api/v1/projects/prod/members": () => jsonResponse({ members: [] }),
    "GET /api/v1/projects/prod/enrollment-tokens": () => jsonResponse({ tokens }),
    "POST /api/v1/projects/prod/enrollment-tokens": (_url, init) => {
      const body = sentJson(init) as { target: { display_name: string } };
      const token = { ...TOKEN, target: { type: "new_cluster", display_name: body.target.display_name } };
      tokens = [token];
      return jsonResponse({ token, secret: SECRET, installation_id: "i1" }, 201);
    },
    "POST /api/v1/projects/prod/enrollment-tokens/t1/revoke": () => {
      tokens = [{ ...TOKEN, status: "revoked", revoked_at: "2026-11-15T10:30:00Z" }];
      return jsonResponse(tokens[0]);
    },
    ...overrides,
  });
}

const page = { path: "/projects/:slug", url: "/projects/prod" };

describe("Register cluster", () => {
  it("creates a token, shows it once with the install commands, and forgets it when done", async () => {
    const fetchMock = serve();
    const { client } = renderPage(<ProjectPage />, page);

    fireEvent.click(await screen.findByRole("button", { name: "Register cluster" }));
    fireEvent.change(screen.getByLabelText("Cluster name"), { target: { value: "  prod-east  " } });
    fireEvent.change(screen.getByLabelText("Token expires after"), { target: { value: "240" } });
    fireEvent.click(screen.getByRole("button", { name: "Create enrollment token" }));

    const panel = await screen.findByRole("region", { name: "Install the agent on prod-east" });
    const post = fetchMock.mock.calls.find(([, init]) => init?.method === "POST");
    expect(sentJson(post?.[1])).toEqual({
      kind: "kubernetes",
      target: { type: "new_cluster", display_name: "prod-east" },
      expires_in_minutes: 240,
    });

    // The one-time nature is spelled out next to the secret.
    expect(within(panel).getByRole("note")).toHaveTextContent("It is shown only once");
    expect(within(panel).getByText(SECRET)).toBeInTheDocument();
    expect(within(panel).getByRole("button", { name: "Copy enrollment token" })).toBeInTheDocument();

    const origin = window.location.origin;
    const commands = within(panel)
      .getAllByRole("listitem")
      .map((item) => item.querySelector("code")?.textContent);
    expect(commands).toEqual([
      "kubectl create namespace vn-agent",
      `kubectl -n vn-agent create secret generic vn-agent-enrollment \\\n  --from-literal=server-url=${origin} --from-literal=token=${SECRET}`,
      `kubectl apply -f ${origin}/api/v1/agent/manifests/kubernetes.yaml`,
    ]);

    // The new token shows up in the token list without its secret.
    const tokens = await screen.findByRole("region", { name: "Enrollment tokens" });
    expect(await within(tokens).findByText("prod-east")).toBeInTheDocument();
    expect(within(tokens).queryByText(SECRET)).not.toBeInTheDocument();

    // The secret is not kept in the query or mutation caches.
    expect(JSON.stringify(client.getQueryCache().getAll().map((q) => q.state.data))).not.toContain(SECRET);
    expect(JSON.stringify(client.getMutationCache().getAll().map((m) => m.state.data))).not.toContain(SECRET);

    fireEvent.click(within(panel).getByRole("button", { name: "Done, I have copied the token" }));
    expect(screen.queryByText(SECRET)).not.toBeInTheDocument();
    expect(screen.queryByRole("region", { name: /Install the agent/ })).not.toBeInTheDocument();
  });

  it("copies the token, falling back when the Clipboard API is unavailable", async () => {
    serve();
    const execCommand = vi.fn(() => true);
    // jsdom has no Clipboard API and no secure context, so the legacy path runs.
    Object.defineProperty(document, "execCommand", { value: execCommand, configurable: true });
    renderPage(<ProjectPage />, page);

    fireEvent.click(await screen.findByRole("button", { name: "Register cluster" }));
    fireEvent.change(screen.getByLabelText("Cluster name"), { target: { value: "prod-east" } });
    fireEvent.click(screen.getByRole("button", { name: "Create enrollment token" }));
    fireEvent.click(await screen.findByRole("button", { name: "Copy enrollment token" }));

    expect(await screen.findByText("Copied enrollment token.")).toBeInTheDocument();
    expect(execCommand).toHaveBeenCalledWith("copy");
  });

  it("explains a failed token creation and keeps the form", async () => {
    serve({
      "POST /api/v1/projects/prod/enrollment-tokens": () =>
        jsonResponse({ error: "invalid_request", message: "`target.display_name` must be 1 to 200 characters." }, 400),
    });
    renderPage(<ProjectPage />, page);

    fireEvent.click(await screen.findByRole("button", { name: "Register cluster" }));
    fireEvent.change(screen.getByLabelText("Cluster name"), { target: { value: "x" } });
    fireEvent.click(screen.getByRole("button", { name: "Create enrollment token" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("must be 1 to 200 characters");
    expect(screen.getByLabelText("Cluster name")).toHaveValue("x");
  });

  it("does not submit an empty name", async () => {
    const fetchMock = serve();
    renderPage(<ProjectPage />, page);

    fireEvent.click(await screen.findByRole("button", { name: "Register cluster" }));
    fireEvent.change(screen.getByLabelText("Cluster name"), { target: { value: "   " } });
    expect(screen.getByRole("button", { name: "Create enrollment token" })).toBeDisabled();
    expect(requestsTo(fetchMock, "POST", "/api/v1/projects/prod/enrollment-tokens")).toHaveLength(0);
  });

  it("revokes an unused token after confirmation", async () => {
    serve();
    renderPage(<ProjectPage />, page);

    fireEvent.click(await screen.findByRole("button", { name: "Register cluster" }));
    fireEvent.change(screen.getByLabelText("Cluster name"), { target: { value: "prod-east" } });
    fireEvent.click(screen.getByRole("button", { name: "Create enrollment token" }));
    fireEvent.click(await screen.findByRole("button", { name: "Done, I have copied the token" }));

    const tokens = screen.getByRole("region", { name: "Enrollment tokens" });
    fireEvent.click(await within(tokens).findByRole("button", { name: "Revoke token" }));
    const confirm = within(tokens).getByRole("group", { name: "Confirm: Revoke token" });
    expect(confirm).toHaveTextContent("Revoke the token for prod-east?");
    fireEvent.click(within(confirm).getByRole("button", { name: "Revoke token" }));

    await waitFor(() => {
      expect(within(tokens).getByText("Revoked")).toBeInTheDocument();
    });
    expect(within(tokens).queryByRole("button", { name: "Revoke token" })).not.toBeInTheDocument();
  });

  it("is not offered to users who may not manage agents", async () => {
    const fetchMock = serve();
    renderPage(<ProjectPage />, { ...page, me: VIEWER });

    expect(await screen.findByText("An installation admin can register a cluster in this project.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Register cluster" })).not.toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Enrollment tokens" })).not.toBeInTheDocument();
    expect(requestsTo(fetchMock, "GET", "/api/v1/projects/prod/enrollment-tokens")).toHaveLength(0);
  });
});
