# syntax=docker/dockerfile:1

# Vanguard Nexus server and agent images.
#
# Stages:
#   web          builds the browser UI into web/dist with pnpm.
#   rust-base    Rust toolchain and workspace sources, shared by both binary builds.
#   rust         builds the vn-server and vn release binaries.
#   agent-rust   builds the vn-agent release binary.
#   agent        minimal, non-root image with only vn-agent (build with --target agent).
#   runtime      slim, non-root server image with the binaries, UI assets, and a default
#                config. It is the last stage, so a build without --target produces it.
#
# Server: docker build -t vanguard-nexus .
#         docker run -p 8080:8080 -e VN_DATABASE_URL=postgres://... vanguard-nexus
#         (add -e VN_OIDC_CLIENT_SECRET=... and a config with an `auth` section for sign-in)
# Agent:  docker build --target agent -t ghcr.io/vanguard-enterprise/vn-agent:latest .
#         Install it in a cluster with deploy/kubernetes/vn-agent.yaml.

ARG NODE_VERSION=24
ARG RUST_VERSION=1.96.0
ARG DEBIAN_RELEASE=bookworm
# Distroless base for the agent: glibc, libgcc, CA certificates, and a nonroot user, but
# no shell or package manager. Debian 12 matches DEBIAN_RELEASE above.
ARG AGENT_BASE=gcr.io/distroless/cc-debian12:nonroot

# ---------------------------------------------------------------------------
# Web UI
# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION}-${DEBIAN_RELEASE}-slim AS web

ENV PNPM_HOME=/pnpm \
    PATH=/pnpm:$PATH \
    COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
    CI=true
RUN corepack enable

WORKDIR /src/web

# Install dependencies first so they are cached until the manifest or lockfile changes.
# The optional files are matched with wildcards so their absence does not fail the build.
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml* web/.npmrc* ./
RUN --mount=type=cache,id=vn-pnpm-store,target=/pnpm/store \
    pnpm install --frozen-lockfile --store-dir /pnpm/store

COPY web/ ./
RUN pnpm build

# ---------------------------------------------------------------------------
# Rust binaries
# ---------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-${DEBIAN_RELEASE} AS rust-base

WORKDIR /src

# Install the toolchain and components pinned in rust-toolchain.toml in their own layer,
# so they are not downloaded again on every source change.
COPY rust-toolchain.toml ./
RUN rustup set auto-self-update disable \
 && rustup toolchain install \
 && rustc --version

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# vn-server embeds the agent install manifest with include_str!.
COPY deploy ./deploy

FROM rust-base AS rust

# The registry, git checkouts, and target directory live in BuildKit cache mounts,
# so binaries are copied out of target/ within the same step.
RUN --mount=type=cache,id=vn-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=vn-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=vn-cargo-target,target=/src/target,sharing=locked \
    cargo build --locked --release -p vn-server -p vn-cli \
 && install -D -m 0755 target/release/vn-server /out/vn-server \
 && install -D -m 0755 target/release/vn /out/vn

FROM rust-base AS agent-rust

RUN --mount=type=cache,id=vn-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=vn-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=vn-cargo-target,target=/src/target,sharing=locked \
    cargo build --locked --release -p vn-agent \
 && install -D -m 0755 target/release/vn-agent /out/vn-agent

# ---------------------------------------------------------------------------
# Agent runtime
# ---------------------------------------------------------------------------
FROM ${AGENT_BASE} AS agent

COPY --from=agent-rust /out/vn-agent /usr/local/bin/vn-agent

ENV RUST_LOG=info

# The distroless nonroot user. deploy/kubernetes/vn-agent.yaml runs the pod as this UID.
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/vn-agent"]

# ---------------------------------------------------------------------------
# Server runtime
# ---------------------------------------------------------------------------
FROM debian:${DEBIAN_RELEASE}-slim AS runtime

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 10001 vn \
 && useradd --uid 10001 --gid vn --no-create-home \
      --home-dir /nonexistent --shell /usr/sbin/nologin vn \
 && install -d -m 0755 /etc/vn

COPY --from=rust /out/ /usr/local/bin/
COPY --from=web /src/web/dist/ /usr/share/vn/web/

# Default container config. Mount a different file at /etc/vn/vn.yaml to override it.
# The database URL is read from the VN_DATABASE_URL environment variable at runtime.
# Sign-in stays disabled until a mounted config adds an `auth` section like the
# commented one below (see config/vn.example.yaml); the client secret then comes from
# VN_OIDC_CLIENT_SECRET.
COPY --chmod=0644 <<'EOF' /etc/vn/vn.yaml
version: 1
server:
  listen: 0.0.0.0:8080
  static_dir: /usr/share/vn/web
database:
  url_env: VN_DATABASE_URL
  max_connections: 10
# auth:
#   issuer_url: https://id.example.com
#   client_id: "<client ID from Pocket ID>"
#   client_secret_env: VN_OIDC_CLIENT_SECRET
#   public_url: https://vn.example.com
#   scopes: [openid, profile, email, groups]
#   admin:
#     claim: groups
#     values: [vn-admins]
EOF

ENV VN_CONFIG=/etc/vn/vn.yaml \
    RUST_LOG=info

USER 10001:10001
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/vn-server"]
