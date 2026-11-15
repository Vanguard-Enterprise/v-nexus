# Vanguard Nexus

A self-hosted infrastructure management platform for applications, Kubernetes clusters, Docker hosts, Linux servers, and multi-site networks.

## Project direction

- Rust server, CLI, and agents.
- Configuration-file setup and platform settings.
- Kubernetes and Docker deployment targets, with Talos Linux integration planned.
- Integrations for identity, storage, certificates, DNS, VPNs, alerts, and AI tooling.
- Self-hosted first, with hosted management a possible future option.

## Planning

The agreed [initial architecture](docs/architecture.md) covers the application stack, data ownership, agent synchronization, and the first cluster inventory milestone. The [agent protocol sketch](docs/agent-protocol.md) describes the agent connection and message framing.

Open [project-priorities.html](project-priorities.html) in a browser for the current feature ideas and examples. Priorities are provisional, and entries describe planned capabilities.

## Status

Early development. The repository contains the application skeleton from the first milestone step: a Rust workspace (server, agent stub, and `vn` CLI), configuration-file validation, PostgreSQL migrations, and a React web UI that reports server health.

The user-access half of the second milestone step is also in place: browser sign-in through an OIDC provider (such as Pocket ID), server-side sessions, an installation admin role mapped from a provider claim, and projects with per-project `viewer` and `operator` roles. Every API route except health and sign-in requires a session.

Agents can enroll with single-use tokens and hold an authenticated WebSocket connection to the server: they sign a stateless server challenge with their Ed25519 key for a short-lived session token, then connect with the `vn-agent.v1` subprotocol. The server records connections, supersedes an older connection of the same agent, and closes a revoked agent's connection. `vn-agent` enrolls itself, stores its identity in a Kubernetes Secret (or a file on a development host), and reconnects with backoff.

The agent can be packaged and installed: `docker build --target agent` builds the `vn-agent` image, `deploy/kubernetes/vn-agent.yaml` installs it (the server also serves it at `/api/v1/agent/manifests/kubernetes.yaml`), and `scripts/dev-cluster.sh` runs it in a local kind cluster.

Cluster inventory works end to end: the agent watches nodes, namespaces, deployments, statefulsets, and daemonsets in all namespaces, sanitizes the objects, and sends a snapshot of each collection on every connection, followed by watch events, within the server's acknowledgement window. The server persists them with per-resource ordering, an epoch fence against superseded connections, and deletion inference only from complete snapshots, and serves clusters (with connection, staleness, and per-collection status) and their resources (with filters, pagination, and kind-specific summaries) to project members. CLI sign-in, the agent `status` message, and jobs are not implemented yet.

## Quick start

```sh
docker compose up -d postgres
cp config/vn.example.yaml vn.yaml   # then point the auth section at your OIDC provider (Pocket ID)
export VN_DATABASE_URL=postgres://vn:vn@localhost:5432/vn
export VN_OIDC_CLIENT_SECRET=...      # client secret from your OIDC provider
cargo run -p vn-server

# In a second terminal:
pnpm --dir web install && pnpm --dir web dev
```

See [docs/development.md](docs/development.md) for prerequisites, setting up Pocket ID for sign-in, running the agent in a local cluster, tests, and container builds.
