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

Check a config file without starting the server. `--check-env` also requires the named environment variables to be set: with the example's `auth` section that includes `VN_OIDC_CLIENT_SECRET`, so export it first (see [Configure sign-in](#configure-sign-in)), or remove the `auth` section to validate a config without sign-in.

```sh
cargo run -p vn-cli -- config validate vn.yaml --check-env
```

## Configure sign-in

VN signs users in with an OpenID Connect provider using the authorization code flow with PKCE. Without an `auth` section in the config file the server still starts, but nobody can sign in and every API route except `/api/v1/health` answers 401.

The `auth` section in `config/vn.example.yaml` documents every setting. The values that matter for a local setup:

- `issuer_url`: the provider's issuer, exactly as its discovery document reports it.
- `client_id`, and `client_secret_env`: the name of the environment variable holding the client secret (`VN_OIDC_CLIENT_SECRET` in the example). The secret never goes in the file and is never logged.
- `public_url`: the origin your browser uses to reach VN. With the Vite dev server that is `http://<host>:5173`; when the Rust server serves the UI it is `http://<host>:8080` (both need `allow_insecure_http`, below). VN uses `<public_url>/api/v1/auth/callback` as the redirect URI, marks cookies `Secure` when `public_url` uses https, and rejects state-changing requests whose `Origin` header differs from it. Open the UI at exactly this origin, or sign-in and every change will fail.
- `allow_insecure_http`: `issuer_url` and `public_url` must use https unless this is `true`. Over http, provider metadata and signing keys can be tampered with in transit, and session cookies are sent without the `Secure` flag. Set it only for development over a trusted network, such as loopback or a VPN like NetBird; the server logs a warning at startup while it is in effect. The example config sets it because its `public_url` uses http.
- `admin.claim` and `admin.values`: users whose claim contains one of the values get the installation `admin` role. The first admin therefore needs no database setup. `admin.claim` is either a role or groups claim (any custom claim, read from the ID token or the userinfo response) or `sub`, which matches the user's subject at the provider against `admin.values`. The other registered and standard profile claims (`email`, `preferred_username`, `name`, `iss`, `aud`, and so on) are rejected at startup: users can often change the profile claims, and the rest do not describe authorization.

```sh
export VN_OIDC_CLIENT_SECRET=<client secret>
```

The provider must sign ID tokens with an asymmetric algorithm (RS*, PS*, ES*, or EdDSA). VN rejects ID tokens signed with a shared-secret algorithm (HS256, HS384, or HS512), because their integrity would rest on the client secret; configure the provider to use RS256 if it offers a choice. When an ID token names a signing key VN has not seen, VN fetches the provider's keys again once, so key rotation needs no restart.

### Zitadel

1. In a Zitadel project, create a role with key `vn-admin` and grant it to your user.
2. In the project settings, enable **Assert Roles on Authentication**. Zitadel then reports the user's roles in the `urn:zitadel:iam:org:project:roles` claim, which the example config maps to `admin`.
3. Add an application of type **Web** with authentication method **Code**. Register the redirect URI `<public_url>/api/v1/auth/callback`. For an `http://` development URL, turn on **Development Mode** in the application settings.
4. Optionally enable **User roles inside ID Token** in the application's token settings. Otherwise VN reads the roles claim from the userinfo endpoint at sign-in.
5. Copy the client ID into `auth.client_id` and the client secret into `VN_OIDC_CLIENT_SECRET`, and set `auth.issuer_url` to your Zitadel instance URL.

Other providers work the same way. For providers that put group names in a `groups` claim (Keycloak, Authentik, and others), set `admin.claim: groups`, list the admin group in `admin.values`, and add any scope the provider needs to release the claim to `auth.scopes`.

### Sessions and roles

Sessions are stored in PostgreSQL and end after `auth.session.idle_timeout_minutes` without a request (default 60) or `auth.session.absolute_timeout_minutes` after sign-in (default 720), whichever comes first. Signing out revokes the session. The admin role is evaluated at sign-in, so a change at the provider applies at the user's next sign-in. Removing the role at the provider does not end existing sessions: each keeps the admin role it was issued with until it is signed out or reaches its idle or absolute timeout. Keep `absolute_timeout_minutes` short where that matters.

Installation admins create projects and assign project roles through the API. Users appear after their first sign-in. From the browser's developer console while signed in as an admin:

```js
const send = (method, path, body) =>
  fetch(`/api/v1${path}`, {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }).then((r) => r.json());

await send("POST", "/projects", { slug: "prod", name: "Production" });
const { users } = await (await fetch("/api/v1/users")).json();
const user = users.find((u) => u.subject === "<subject>");
if (!user) throw new Error("No user with that subject. They must sign in once first.");
await send("PUT", `/projects/prod/members/${user.id}`, { role: "viewer" });
```

Replace `<subject>` with the user's subject (`sub` claim) at the provider. `viewer` may view a project; `operator` may also operate it. Users only see projects they hold a role in, and admins see all of them.

## Enroll an agent

Agents register with single-use enrollment tokens. For the first release only installation admins create and revoke tokens and agents; project members with a role can list a project's agents.

### Create an enrollment token

A token targets either a new cluster, by display name, or an existing source whose agent is being replaced (`{"type": "replace_source", "source_id": "<source ID>"}`, using the `source_id` from the agent list). It expires after `expires_in_minutes` (default 60, at most 1440) and enrolls one agent. From the browser's developer console while signed in as an admin, with `send` from [Sessions and roles](#sessions-and-roles):

```js
const created = await send("POST", "/projects/prod/enrollment-tokens", {
  kind: "kubernetes",
  target: { type: "new_cluster", display_name: "east" },
  expires_in_minutes: 60,
});
created.secret; // vn_enroll_<token ID>_<secret>, shown only in this response
```

The token string has the form `vn_enroll_<token ID>_<secret>`: the token ID is the public ID as 32 hex digits, and the secret is 256 random bits. VN stores only the SHA-256 of the secret, so a lost token cannot be shown again. Create a new one instead.

List a project's tokens with `GET /api/v1/projects/prod/enrollment-tokens`, and revoke one that has not been used with `POST /api/v1/projects/prod/enrollment-tokens/<token ID>/revoke`.

### Enroll

The agent sends the token, its Ed25519 public key, and a signature proving it holds the private key, to `POST /api/v1/agent/enroll`. The endpoint needs no session and no `Origin` header. The signed message is the ASCII string `vn-agent-enroll-v1`, a zero byte, the 16 raw bytes of the installation ID, the 16 raw bytes of the token ID, and the 32 raw bytes of the public key. Keys and signatures are URL-safe base64 without padding. The agent reads the installation ID from `GET /api/v1/agent/info`.

Until `vn-agent` exists, `curl` and `openssl` can play the agent:

```sh
SERVER=http://127.0.0.1:8080
TOKEN='<the vn_enroll_ token string>'
b64url() { base64 -w0 | tr '+/' '-_' | tr -d '='; }

openssl genpkey -algorithm ed25519 -out agent.pem
openssl pkey -in agent.pem -pubout -outform DER | tail -c 32 > agent.pub
INSTALLATION_ID=$(curl -fsS "$SERVER/api/v1/agent/info" | jq -r .installation_id)
TOKEN_ID=$(printf %s "$TOKEN" | cut -c11-42)
{
  printf 'vn-agent-enroll-v1\0'
  printf %s "$INSTALLATION_ID" | tr -d - | xxd -r -p
  printf %s "$TOKEN_ID" | xxd -r -p
  cat agent.pub
} > enroll.msg
openssl pkeyutl -sign -rawin -inkey agent.pem -in enroll.msg -out enroll.sig

jq -n --arg token "$TOKEN" --arg installation "$INSTALLATION_ID" \
  --arg key "$(b64url < agent.pub)" --arg sig "$(b64url < enroll.sig)" \
  '{token: $token, installation_id: $installation, kind: "kubernetes",
    public_key: $key, signature: $sig, agent_version: "0.1.0-dev",
    protocol_versions: [1], cluster_fingerprint: "dev-cluster-uid"}' |
  curl -fsS "$SERVER/api/v1/agent/enroll" -H 'Content-Type: application/json' -d @-
```

A real cluster agent reports the UID of its `kube-system` namespace as `cluster_fingerprint` (`kubectl get namespace kube-system -o jsonpath='{.metadata.uid}'`). A replacement agent for an existing source must report the same fingerprint.

The response holds the agent ID, installation ID, cluster ID, source ID, and key ID. Enrollment creates the cluster and its one whole-cluster source. A replacement enrollment revokes the source's previous agent in the same transaction.

Every refused attempt before the token is proven answers with the same `401 enrollment_failed`, whether the token ID is unknown, the secret is wrong, the token is expired, revoked, or used, or the signature does not verify. The reason is recorded in the audit log as `agent.enroll_failed`. Attempts are rate-limited per client address: a burst of 10, then one more every 6 seconds. Successful enrollments do not count, and IPv6 clients are grouped by /64. The limiter lives in the server process. Behind a reverse proxy, list the proxy in `server.trusted_proxies` so VN reads the client address from `X-Forwarded-For`; otherwise every request appears to come from the proxy and shares one limit.

### Revoke an agent

```js
const { agents } = await (await fetch("/api/v1/projects/prod/agents")).json();
await send("POST", `/projects/prod/agents/${agents[0].id}/revoke`);
```

Revocation marks the agent revoked, records an audit event, and sends a PostgreSQL notification on the `vn_agent_revoked` channel in one transaction. The cluster, its source, and its inventory stay. To bring the cluster back, create a `replace_source` token for its source and enroll a new agent.

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

The Rust build and unit tests do not need a running database. The sign-in and access-control integration tests in `crates/vn-server/tests/auth_flow.rs` run against a mock OIDC provider and a real PostgreSQL, and the enrollment tests in `crates/vn-server/tests/agent_enrollment.rs` against a real PostgreSQL. Both are skipped (with a printed note) unless `DATABASE_URL` is set. Each test creates and drops its own database, so the user needs permission to create databases. With the Compose database:

```sh
DATABASE_URL=postgres://vn:vn@localhost:5432/vn cargo test --workspace --locked
```

CI sets `DATABASE_URL` and runs them against a PostgreSQL service container.

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

The image includes a default config at `/etc/vn/vn.yaml` (`VN_CONFIG`) that listens on `0.0.0.0:8080`, serves the UI from `/usr/share/vn/web`, and reads the database URL from `VN_DATABASE_URL`. It has no `auth` section, so sign-in is disabled. Mount your own file at `/etc/vn/vn.yaml` with an `auth` section, and pass `VN_OIDC_CLIENT_SECRET`, to enable it.

To run the server container next to the Compose database:

```sh
docker compose --profile app up -d --build
```

To enable sign-in there, uncomment and fill in the `auth` block in the `vn-config` config in `compose.yaml` and export `VN_OIDC_CLIENT_SECRET` first. The `server` service waits for PostgreSQL to report healthy, connects to it over the Compose network, and publishes port 8080. Stop everything with `docker compose --profile app down`.
