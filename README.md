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

Early development. The repository contains the application skeleton from the first milestone step: a Rust workspace (server, agent stub, and `vn` CLI), configuration-file validation, PostgreSQL migrations, and a React web UI that reports server health. Authentication, agent enrollment, and cluster inventory are not implemented yet.

## Quick start

```sh
docker compose up -d postgres
cp config/vn.example.yaml vn.yaml
export VN_DATABASE_URL=postgres://vn:vn@localhost:5432/vn
cargo run -p vn-server

# In a second terminal:
pnpm --dir web install && pnpm --dir web dev
```

See [docs/development.md](docs/development.md) for prerequisites, tests, and container builds.
