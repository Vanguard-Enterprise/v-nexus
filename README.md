# Vanguard Nexus

A self-hosted infrastructure management platform for applications, Kubernetes clusters, Docker hosts, Linux servers, and multi-site networks.

## Project direction

- Rust server, CLI, and agents.
- Configuration-file setup and platform settings.
- Kubernetes and Docker deployment targets, with Talos Linux integration planned.
- Integrations for identity, storage, certificates, DNS, VPNs, alerts, and AI tooling.
- Self-hosted first, with hosted management a possible future option.

## Planning

The agreed [initial architecture](docs/architecture.md) covers the application stack, data ownership, agent synchronization, and the first cluster inventory milestone.

Open [project-priorities.html](project-priorities.html) in a browser for the current feature ideas and examples. Priorities are provisional, and entries describe planned capabilities.

## Status

Early development. The repository contains the application skeleton from the first milestone step: a Rust workspace (server, agent stub, and `vn` CLI), configuration-file validation, PostgreSQL migrations, and a React web UI that reports server health.

The user-access half of the second milestone step is also in place: browser sign-in through an OIDC provider (such as Zitadel), server-side sessions, an installation admin role mapped from a provider claim, and projects with per-project `viewer` and `operator` roles. Every API route except health and sign-in requires a session. CLI sign-in, agent enrollment, and cluster inventory are not implemented yet.

## Quick start

```sh
docker compose up -d postgres
cp config/vn.example.yaml vn.yaml   # then point the auth section at your OIDC provider
export VN_DATABASE_URL=postgres://vn:vn@localhost:5432/vn
export VN_OIDC_CLIENT_SECRET=...      # client secret from your OIDC provider
cargo run -p vn-server

# In a second terminal:
pnpm --dir web install && pnpm --dir web dev
```

See [docs/development.md](docs/development.md) for prerequisites, setting up a local OIDC provider, tests, and container builds.
