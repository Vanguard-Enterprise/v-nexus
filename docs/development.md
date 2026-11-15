# Development

This guide covers running Vanguard Nexus from a source checkout.

## Prerequisites

- [rustup](https://rustup.rs). The toolchain version is pinned in `rust-toolchain.toml`, and rustup installs it on first use (or run `rustup toolchain install` in the repository root).
- Node.js 24 with Corepack. Run `corepack enable` once so the pnpm version pinned in `web/package.json` is used.
- Docker with the Compose plugin, for PostgreSQL and container builds.
- To run the agent in a local cluster: [kind](https://kind.sigs.k8s.io) (`go install sigs.k8s.io/kind@latest`, which puts it in `$(go env GOPATH)/bin`) and `kubectl`.

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
- `client_id`, and `client_secret_env`: the name of the environment variable holding the client secret (`VN_OIDC_CLIENT_SECRET` in the example). The secret never goes in the file and is never logged. Omit `client_secret_env` for a public client (such as a Pocket ID client marked public): VN then authenticates the code exchange with PKCE alone and sends no secret.
- `public_url`: the origin your browser uses to reach VN. With the Vite dev server that is `http://<host>:5173`; when the Rust server serves the UI it is `http://<host>:8080` (both need `allow_insecure_http`, below). VN uses `<public_url>/api/v1/auth/callback` as the redirect URI, marks cookies `Secure` when `public_url` uses https, and rejects state-changing requests whose `Origin` header differs from it. Open the UI at exactly this origin, or sign-in and every change will fail.
- `allow_insecure_http`: `issuer_url` and `public_url` must use https unless this is `true`. Over http, provider metadata and signing keys can be tampered with in transit, and session cookies are sent without the `Secure` flag. Set it only for development over a trusted network, such as loopback or a VPN like NetBird; the server logs a warning at startup while it is in effect. The example config sets it because its `public_url` uses http.
- `admin.claim` and `admin.values`: users whose claim contains one of the values get the installation `admin` role. The first admin therefore needs no database setup. `admin.claim` is either a role or groups claim (any custom claim, read from the ID token or the userinfo response) or `sub`, which matches the user's subject at the provider against `admin.values`. The other registered and standard profile claims (`email`, `preferred_username`, `name`, `iss`, `aud`, and so on) are rejected at startup: users can often change the profile claims, and the rest do not describe authorization.

```sh
export VN_OIDC_CLIENT_SECRET=<client secret>
```

The provider must sign ID tokens with an asymmetric algorithm (RS*, PS*, ES*, or EdDSA). VN rejects ID tokens signed with a shared-secret algorithm (HS256, HS384, or HS512), because their integrity would rest on the client secret; configure the provider to use RS256 if it offers a choice. When an ID token names a signing key VN has not seen, VN fetches the provider's keys again once, so key rotation needs no restart.

### Pocket ID

[Pocket ID](https://pocket-id.org) is the provider this project develops and deploys against. These steps assume an instance at `https://id.example.com`; use your own URL.

1. Sign in to Pocket ID as an admin. Under **Administration**, open **User Groups** and add a group with the name `vn-admins`, then add your user to it. Pocket ID reports each group's name (not its friendly name) in the `groups` claim, which the example config maps to the installation `admin` role.
2. Open **OIDC Clients** and add a client, for example named `Vanguard Nexus`. Set the callback URL to `<public_url>/api/v1/auth/callback`, for example `http://<host>:5173/api/v1/auth/callback` with the Vite dev server. Turn **PKCE** on. Turn **Public Client** on as well unless you want a client secret: VN then signs in with PKCE alone.
3. Save the client and copy the client ID into `auth.client_id`. For a public client, delete the `client_secret_env` line from `auth` and skip `VN_OIDC_CLIENT_SECRET`. For a confidential client, copy the client secret, which is shown only once, into `VN_OIDC_CLIENT_SECRET`.
4. Set `auth.issuer_url` to the Pocket ID URL (`https://id.example.com`, without a trailing slash). The example config already sets `admin.claim: groups` and `admin.values: [vn-admins]`, and requests the `groups` scope in `auth.scopes`. Pocket ID leaves the `groups` claim out unless that scope is requested, so keep it there.
5. Optionally restrict the client to selected user groups in its settings, so only members of those groups can sign in to VN at all.

Other OpenID Connect providers work the same way. Point `issuer_url` at the provider, set `admin.claim` to the claim that carries its groups or roles, and add any scope it needs to release that claim to `auth.scopes`.

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

`vn-agent` does this itself (see [Run the agent](#run-the-agent)). To enroll by hand, `curl` and `openssl` can play the agent:

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

Revocation marks the agent revoked, deletes its sessions, records an audit event, and sends a PostgreSQL notification on the `vn_agent_revoked` channel in one transaction. The server closes the agent's open connection with code 4003 when the notification arrives, and each connection also rechecks its agent every 30 seconds in case a notification is missed. The cluster, its source, and its inventory stay. To bring the cluster back, create a `replace_source` token for its source and enroll a new agent.

## Connect an agent

Agents authenticate by signing a server challenge and then hold one WebSocket connection (see [Agent protocol](agent-protocol.md)). The server needs a challenge key for this. Add an `agents` section to the config file, as in `config/vn.example.yaml`:

```yaml
agents:
  challenge_key_env: VN_AGENT_CHALLENGE_KEY
```

and export a key: base64 of 32 to 64 random bytes. The server refuses to start with a missing or malformed key, and never logs it. Without the `agents` section agents can still enroll, but the challenge, session, and connect endpoints answer `503 agents_disabled`.

```sh
export VN_AGENT_CHALLENGE_KEY=$(openssl rand -base64 32)
```

Keep the key stable across restarts: changing it only invalidates challenges issued in the last minute, but every server replica needs the same key.

### Run the agent

`vn-agent` reads `VN_SERVER_URL` and, the first time, `VN_ENROLLMENT_TOKEN`. In a cluster it runs with `POD_NAMESPACE` set (downward API) and stores its identity in the Secret `vn-agent-identity` in that namespace. On a development host it uses the Kubernetes client from your kubeconfig (`KUBECONFIG` or `~/.kube/config`) and an identity file instead:

```sh
export VN_SERVER_URL=http://127.0.0.1:8080
export VN_ENROLLMENT_TOKEN='<the vn_enroll_ token string>'
cargo run -p vn-agent -- --identity-file vn-agent-identity.json
```

The agent reads the `kube-system` namespace UID as its cluster fingerprint and the API server version from `/version`, so the kubeconfig user needs `get` on namespaces. It enrolls when no identity is stored and writes the identity file with mode 0600 (it never overwrites an existing one), then connects and reconnects with backoff from 1 to 60 seconds. Later starts reuse the stored identity and ignore `VN_ENROLLMENT_TOKEN`. The identity file holds the agent's private key: keep it out of the repository.

Open connections are recorded in the `agent_connections` table:

```sh
psql "$VN_DATABASE_URL" -c 'SELECT agent_id, sync_epoch, opened_at, last_seen_at, closed_at, close_code, kubernetes_version FROM agent_connections ORDER BY opened_at DESC LIMIT 5'
```

When the agent is revoked (close code 4003) or reports a different cluster fingerprint (4010), it logs that it needs to be enrolled again and exits with status 2. Delete the identity file (or Secret) and start it with a new enrollment token. A second agent process with the same identity supersedes the first (4009), and the two keep replacing each other's connection, so run one per identity.

## Collect inventory

Once connected, the agent watches five collections in all namespaces: `v1/nodes`, `v1/namespaces`, `apps/v1/deployments`, `apps/v1/statefulsets`, and `apps/v1/daemonsets`. The kubeconfig user (or the in-cluster service account) needs `get`, `list`, and `watch` on them. Every connection starts with a fresh snapshot of each collection, followed by watch events. The agent removes managed fields, the `kubectl.kubernetes.io/last-applied-configuration` annotation, and environment variable values in pod templates before sending (the server removes them again), and never collects Secrets or ConfigMaps.

A collection the agent may not read is reported as an error with reason `forbidden` and retried with backoff from 1 to 60 seconds. Earlier inventory of that collection stays.

The inventory is in the `inventory_resources` table (one row per cluster and resource UID, with a tombstone in `deleted_at` once the resource is deleted) and the `inventory_collections` table (per-collection snapshot and error state):

```sh
psql "$VN_DATABASE_URL" -c "SELECT collection, namespace, name, resource_version, deleted_at FROM inventory_resources ORDER BY collection, namespace, name"
```

Browse it in the web UI, or through the API with a session cookie (`vn_session` when `auth.public_url` uses http, `__Host-vn_session` with https):

```sh
curl -s -H "cookie: vn_session=$SESSION" http://127.0.0.1:8080/api/v1/projects/<slug>/clusters
curl -s -H "cookie: vn_session=$SESSION" \
  "http://127.0.0.1:8080/api/v1/projects/<slug>/clusters/<cluster_id>/resources?collection=apps/v1/deployments&search=web"
```

The resources endpoint takes `collection`, `namespace`, `search` (a case-insensitive substring of the name), `include_deleted=true`, `limit` (1 to 500, default 100), and the `cursor` from the previous page's `next_cursor`. A cluster is `stale` whenever its agent is not connected; its inventory stays visible.

To try it against a local [kind](https://kind.sigs.k8s.io/) cluster, export a kubeconfig for that cluster only, so the agent cannot reach any other context:

```sh
kind get kubeconfig --name <cluster> > /tmp/vn-kind.kubeconfig
KUBECONFIG=/tmp/vn-kind.kubeconfig cargo run -p vn-agent -- --identity-file vn-agent-identity.json
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

## Run the agent

The agent runs inside a Kubernetes cluster, enrolls with a token, and keeps its identity in a Secret. Its connection code (`vn-agent` enrolling, connecting, and streaming inventory) lands in a separate pull request. Until then the image starts, logs its settings, and exits, so the pod restarts repeatedly; the image build, the install manifest, and the local cluster below work already.

### Local cluster

`scripts/dev-cluster.sh` manages a [kind](https://kind.sigs.k8s.io) cluster named `vn-dev` for agent development. Every `kubectl` call it makes uses the `kind-vn-dev` context, and it switches the current context back after creating the cluster, so other clusters in your kubeconfig are not affected.

```sh
scripts/dev-cluster.sh up     # create the cluster if missing, build the agent image, load it
scripts/dev-cluster.sh load   # rebuild and reload the image, restart the agent if installed
scripts/dev-cluster.sh down   # delete the cluster
```

The image is tagged `ghcr.io/vanguard-enterprise/vn-agent:latest`, the tag the install manifest uses, and loaded straight into the cluster's node. The manifest's `imagePullPolicy: IfNotPresent` then uses the loaded image instead of pulling it.

The agent pod cannot reach the server at `127.0.0.1`, which is the pod itself. Give it an address of the host that the kind node container can reach: the host's LAN address or its VPN address, such as its NetBird IP (`netbird status` prints it). The server must listen on that address, so keep `server.listen: 0.0.0.0:8080` (the example config already does), and allow port 8080 through the host firewall if one is active. Over plain http, use only a trusted network such as a LAN or NetBird.

### Install the agent

1. Start the server and sign in as an installation admin.
2. Create an enrollment token for a new cluster (see [Create an enrollment token](#create-an-enrollment-token)) and copy its `secret`.
3. Create the namespace and the enrollment Secret, then apply the manifest. `<VN public URL>` is the URL the agent uses to reach the server, for example `http://<NetBird IP>:8080` with the local cluster:

   ```sh
   kubectl create namespace vn-agent --dry-run=client -o yaml | kubectl apply -f -
   kubectl -n vn-agent create secret generic vn-agent-enrollment \
     --from-literal=server-url=<VN public URL> --from-literal=token=<token> \
     --dry-run=client -o yaml | kubectl apply --server-side --force-conflicts -f -
   kubectl apply -f <VN public URL>/api/v1/agent/manifests/kubernetes.yaml
   ```

   The first two commands create or update, so they can be run again with a new token when an earlier token expired before the agent enrolled. Applying the Secret server-side keeps the token out of the `last-applied-configuration` annotation.

   With the local cluster, add `--context kind-vn-dev` to each command. `kubectl apply -f deploy/kubernetes/vn-agent.yaml` applies the same manifest from the checkout.

The server serves the manifest at `GET /api/v1/agent/manifests/kubernetes.yaml` without a session. It is `deploy/kubernetes/vn-agent.yaml`, embedded in the server binary at build time. It creates:

- the `vn-agent` namespace, enforcing the `restricted` Pod Security Standard;
- the `vn-agent` ServiceAccount;
- a ClusterRole that can only get, list, and watch nodes, namespaces, deployments, statefulsets, and daemonsets (reading the `kube-system` namespace gives the cluster fingerprint);
- a Role in `vn-agent` that can get and update the `vn-agent-identity` Secret, create Secrets in that namespace (Kubernetes cannot limit `create` to one name), and get the `vn-agent-enrollment` Secret;
- a single-replica Deployment that runs as a non-root user with a read-only root filesystem, no privilege escalation, and all capabilities dropped. It reads `VN_SERVER_URL` from the `server-url` key and `VN_ENROLLMENT_TOKEN` from the optional `token` key of `vn-agent-enrollment`, and sets `POD_NAMESPACE`, which tells the agent to keep its identity in the `vn-agent-identity` Secret.

After the first enrollment the token is used up and the agent works from its stored identity; the `token` key may then be removed. Check on the agent with:

```sh
kubectl --context kind-vn-dev -n vn-agent logs deployment/vn-agent
kubectl --context kind-vn-dev -n vn-agent get secret vn-agent-identity
```

To enroll the cluster again, for example after revoking its agent, create a `replace_source` token, put it in `vn-agent-enrollment`, delete the `vn-agent-identity` Secret, and restart the Deployment. Remove the agent with `kubectl delete -f deploy/kubernetes/vn-agent.yaml`, which also deletes the namespace and both Secrets.

The image is not published to a registry yet. For a cluster other than the local one, build it (see [Build and run the container](#build-and-run-the-container)), push it to a registry the cluster can pull from, and change the Deployment's image to match.

## Run tests and checks

These match the CI workflow in `.github/workflows/ci.yml`.

Rust:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

The Rust build and unit tests do not need a running database. The sign-in and access-control integration tests in `crates/vn-server/tests/auth_flow.rs` run against a mock OIDC provider and a real PostgreSQL, the enrollment, connection, and inventory tests in `crates/vn-server/tests/agent_enrollment.rs`, `agent_connection.rs`, and `inventory.rs`, and the agent's end-to-end tests in `crates/vn-agent/tests/agent_server.rs`, against a real PostgreSQL. They are skipped (with a printed note) unless `DATABASE_URL` is set. Each test creates and drops its own database, so the user needs permission to create databases. With the Compose database:

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

The `Dockerfile` builds the web UI and the `vn-server` and `vn` binaries, then packages them in a slim image that runs as a non-root user. Its `agent` target builds the agent image instead: only the `vn-agent` binary on a distroless base, running as a non-root user.

```sh
docker build -t vanguard-nexus .
docker build --target agent -t ghcr.io/vanguard-enterprise/vn-agent:latest .
```

The image includes a default config at `/etc/vn/vn.yaml` (`VN_CONFIG`) that listens on `0.0.0.0:8080`, serves the UI from `/usr/share/vn/web`, and reads the database URL from `VN_DATABASE_URL`. It has no `auth` section, so sign-in is disabled. Mount your own file at `/etc/vn/vn.yaml` with an `auth` section, and pass `VN_OIDC_CLIENT_SECRET`, to enable it.

To run the server container next to the Compose database:

```sh
docker compose --profile app up -d --build
```

To enable sign-in there, uncomment and fill in the `auth` block in the `vn-config` config in `compose.yaml` and export `VN_OIDC_CLIENT_SECRET` first. To let agents connect, uncomment the `agents` block and export `VN_AGENT_CHALLENGE_KEY` (see [Connect an agent](#connect-an-agent)). The `server` service waits for PostgreSQL to report healthy, connects to it over the Compose network, and publishes port 8080. Stop everything with `docker compose --profile app down`.
