# Development

This guide covers running Vanguard Nexus from a source checkout.

## Prerequisites

- [rustup](https://rustup.rs). The toolchain version is pinned in `rust-toolchain.toml`, and rustup installs it on first use (or run `rustup toolchain install` in the repository root).
- Node.js 24 with Corepack. Run `corepack enable` once so the pnpm version pinned in `web/package.json` is used.
- Docker with the Compose plugin, for PostgreSQL and container builds.

## Start PostgreSQL

```sh
docker compose up -d postgres
docker compose ps
```

This starts `postgres:17` with database, user, and password all set to `vn`, published on port 5432. Data is kept in the `postgres-data` named volume. Remove it with `docker compose down -v` to start from an empty database.

## Configure the server

The server reads a YAML config file from `--config <path>`, the `VN_CONFIG` environment variable, or `./vn.yaml`, in that order. Copy the example and adjust it if needed:

```sh
cp config/vn.example.yaml vn.yaml
```

`vn.yaml` in the repository root is ignored by Git. The database URL is never stored in the file. The `database.url_env` setting names the environment variable that holds it:

```sh
export VN_DATABASE_URL=postgres://vn:vn@localhost:5432/vn
```

Check a config file without starting the server:

```sh
cargo run -p vn-cli -- config validate vn.yaml
```

## Run the server

```sh
cargo run -p vn-server
```

The server applies database migrations at startup, then listens on the `server.listen` address (`0.0.0.0:8080` in the example). Set `RUST_LOG` to change log verbosity, for example `RUST_LOG=debug`.

Check that it is healthy:

```sh
cargo run -p vn-cli -- health --server http://127.0.0.1:8080
```

## Run the web UI

In a second terminal:

```sh
pnpm --dir web install
pnpm --dir web dev
```

The Vite dev server listens on port 5173 and proxies `/api` requests to the server on port 8080.

Both development servers bind to `0.0.0.0`, so they are reachable from other machines on the network at `http://<host>:5173` and `http://<host>:8080`. Use the host's private or VPN address, and do not expose these ports to untrusted networks.

To have the Rust server serve the UI itself, build it once with `pnpm --dir web build`. The example config points `server.static_dir` at `web/dist`.

## Run tests and checks

These match the CI workflow in `.github/workflows/ci.yml`.

Rust:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

The Rust build and tests do not need a running database.

Web:

```sh
pnpm --dir web install --frozen-lockfile
pnpm --dir web lint
pnpm --dir web typecheck
pnpm --dir web test
pnpm --dir web build
```

## Build and run the container

The `Dockerfile` builds the web UI and the `vn-server` and `vn` binaries, then packages them in a slim image that runs as a non-root user.

```sh
docker build -t vanguard-nexus .
```

The image includes a default config at `/etc/vn/vn.yaml` (`VN_CONFIG`) that listens on `0.0.0.0:8080`, serves the UI from `/usr/share/vn/web`, and reads the database URL from `VN_DATABASE_URL`. Mount your own file at `/etc/vn/vn.yaml` to override it.

To run the server container next to the Compose database:

```sh
docker compose --profile app up -d --build
```

The `server` service waits for PostgreSQL to report healthy, connects to it over the Compose network, and publishes port 8080. Stop everything with `docker compose --profile app down`.
