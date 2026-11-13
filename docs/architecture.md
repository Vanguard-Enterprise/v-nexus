# Architecture

Status: agreed initial direction.

## Application stack

- Rust server, CLI, and agents.
- Axum and Tokio for the HTTP API, agent connections, and background work.
- PostgreSQL for persistent server state, accessed through SQLx with versioned migrations.
- React and TypeScript for the browser UI, built with Vite and using TanStack Query for API data.
- Static UI assets served by the Rust server. Node is a build dependency; production starts with the VN server and PostgreSQL.

Start with one server application containing the API, inventory processing, and background jobs. The browser and CLI use the same versioned API. Agents connect outbound to the server.

## Data ownership

### VN records

PostgreSQL owns projects, environments, resource ownership, permission assignments, saved views, agent registrations, deployment requests, jobs, and audit history. Store relationships and commonly queried fields in typed tables with constraints.

Platform setup comes from a validated, versioned configuration file. This includes database connectivity and identity-provider settings. The dashboard identifies file-managed settings and where to edit them. Database records must not silently override those settings.

### Observed infrastructure

Agents report permitted Kubernetes resources, Docker containers, Linux host information, and health. PostgreSQL stores the latest inventory for browsing and filtering while a site is disconnected.

Each observation identifies its source, external resource identity, source version where available, and observation time. Kubernetes resources use the cluster identity and resource UID so a replacement with the same name remains distinguishable. Use selected JSONB fields for sanitized provider-specific attributes, alongside typed inventory fields.

The source system owns observed state. VN's inventory is a persisted view of that state. Connection status and data freshness are separate concepts, and the UI displays both. A disconnected agent does not imply its resources were deleted.

### Desired configuration

Every managed resource declares its configuration owner: Git, a configuration file, or VN. Changes go through that owner. Discovery initially grants observation only; management requires explicit adoption.

Keep desired configuration separate from observed state. A successful command is not proof that the requested state has been reached. Subsequent observations confirm the result.

### Logs, metrics, artifacts, and secrets

Stream logs on demand and integrate with existing telemetry systems for retained logs and metrics. Define retention before collecting history continuously.

When artifact and backup features arrive, store their files in object storage and their metadata and references in PostgreSQL.

Prefer secret references to OpenBao or another configured provider. Exclude secret values from inventory, logs, and audit payloads. Credentials that VN must retain need a separate protected storage design before implementation.

## Agent synchronization and jobs

Use Kubernetes list/watch through kube-rs for the cluster agent. The agent-to-server protocol must also handle reconnects, duplicate observations, and interrupted synchronization.

A reconnect starts a complete inventory reconciliation. Only a successfully completed snapshot of a known collection scope may establish that previously observed resources are missing. A resource listed in that snapshot counts as present even when its content is unchanged. An incomplete snapshot or collection permission failure must not mark those resources deleted. Version observations so delayed updates cannot replace newer state. The sync epoch that orders observations belongs to the source record (see [Agent enrollment](#agent-enrollment)), not the agent, so ordering survives agent replacement. Each ingest transaction confirms, atomically with persistence, that its connection's epoch is still the source's current epoch, so a superseded connection cannot persist observations.

Persist management requests as jobs before dispatch. Design retries and agent result reporting to tolerate duplicate delivery, with explicit handling for operations whose outcome is unknown after a disconnect.

Enrollment uses expiring tokens, authenticated agent identities, and revocation. User access uses OIDC and scoped permissions. Neither browsers nor agents connect directly to PostgreSQL.

The [agent protocol sketch](agent-protocol.md) describes connection setup, message framing, snapshots, acknowledgements, heartbeats, and job messages.

### Agent identity

Decision: each agent generates an Ed25519 keypair locally and registers the public key at enrollment. To connect, the agent signs a stateless, single-use server challenge and receives a short-lived session token (15 minutes), which it presents when opening the agent channel. The token only authorizes opening connections. An open connection stays authorized while the agent remains active. The private key never leaves the agent. The server stores only public keys, hashes of session tokens, and the IDs of consumed challenges until they expire. Challenges carry a server-keyed MAC instead of being stored, so the unauthenticated challenge endpoint writes nothing. The challenge, session, and enrollment endpoints are rate-limited.

Rationale:

- Authentication happens in the application, so it works unchanged when a reverse proxy or Kubernetes ingress terminates TLS. Most self-hosted installations will run behind one.
- A captured session token stops working within its lifetime. A database leak exposes no reusable agent secret.
- The agent can rotate its key without the server delivering a secret.
- Maintained libraries exist. Use `ed25519-dalek` (3.x, dalek-cryptography) with strict verification. `aws-lc-rs`, already a dependency through rustls, also implements Ed25519 if one crypto backend is preferred.

Rejected alternatives:

- mTLS with server-issued client certificates. The client certificate does not reach VN when a proxy terminates TLS. TLS passthrough or a proxy-set certificate header are proxy-specific, and a misconfigured header is spoofable. It also needs a VN certificate authority with CRLs or short certificate lifetimes, and open connections still need revocation in the application. It can return later as optional hardening for direct deployments.
- A server-issued long-lived bearer credential. It is the simplest option and proxy-friendly. The same reusable secret crosses the network on every connection, so a copy from a TLS-inspecting proxy, a log, or a backup grants access until someone rotates it, and rotation still needs a protocol. The signed-challenge design costs one extra request per connection and a small amount of signing code. A bearer credential remains a fallback for a future agent type that cannot sign.

### Agent enrollment

- A user with permission to register clusters in a project creates an enrollment token for that project. Installation admins hold this permission in every project. Role names and grants come from the user access design.
- A token is a random 256-bit secret with a recognizable prefix and a public token ID. It is shown once. The server stores the token ID, a SHA-256 hash of the secret, the scope, the creator, and the creation, expiry, use, and revocation times. Expiry defaults to 1 hour, with a maximum of 24 hours.
- A token is single-use and scoped to a project, an agent kind, and a target: a new cluster with a given display name, or an existing source when replacing a lost or revoked agent. An unused token can be revoked.
- Agents write inventory through sources. A source is its own record, separate from the cluster record. It belongs to one cluster, declares the collection scope it reports, holds the sync epoch counter, and has one active agent at a time, so every resource has exactly one writer. The first release creates one source per cluster, covering the whole cluster.
- Later agent kinds can add more sources to a cluster, such as namespace-scoped agents in shared clusters where a team cannot grant cluster-wide read access, or per-node collectors for host data. The server rejects a source whose scope overlaps another source of the same cluster, because a completed snapshot from one writer would otherwise mark the other writer's resources missing.
- A replacement enrollment for a source revokes its previous agent, if it is still active, in the same transaction. The sync epoch counter stays on the source record and keeps increasing, so the replacement's observations order after the previous agent's.
- For availability, a cluster agent can run as several replicas that share one agent identity (the Kubernetes Secret) and elect a leader with a `coordination.k8s.io` Lease. Only the leader connects. A replica that takes over the Lease connects with the same identity and supersedes the previous connection. Replicas share no job state: the server never offers a job attempt on a second connection, and marks an unfinished attempt of a closed connection `outcome_unknown` unless the next `hello` reports it (see Jobs in the agent protocol). The first release defaults to one replica.
- At enrollment the agent proves it holds the token and the private key: it sends the token, its public key, and a signature over the token ID, public key, and installation ID. It also reports its agent version, supported protocol versions, and a cluster fingerprint (the `kube-system` namespace UID). The fingerprint is a claim, not proof. The server records it and rejects later connections, and replacement enrollments for an existing source, that report a different fingerprint.
- The token is consumed in the same transaction that creates the agent record, by a conditional update on an unused, unexpired, unrevoked token. Failed attempts are rate-limited and audited.
- The server records the agent ID, kind, project, cluster, public key with a key ID, cluster fingerprint, agent version, enrolling token and its creator, enrollment time, and source address (resolved through configured trusted proxies). The response returns the agent ID, installation ID, and cluster ID. The cluster agent stores these with its private key in a Kubernetes Secret in its own namespace, readable only by its service account.

### Agent revocation

- A user with the same project permission, or an installation admin, revokes an agent. One transaction marks the agent revoked, deletes its sessions, records an audit event, and sends a PostgreSQL notification.
- Session and connection requests fail as soon as the revocation commits. The session endpoint tells an agent with a valid signature that it is revoked.
- Every ingest transaction locks and checks the agent row. No observation or job result from a revoked agent is persisted after the revocation commits.
- The server process holding an open connection closes it when it receives the notification. Each connection also rechecks its agent every 30 seconds, in case a notification is missed. Open connections close within 30 seconds of the revocation, normally within one second.
- Revocation does not delete inventory. The cluster's inventory stays visible and is marked as coming from a revoked agent. A replacement agent needs a new enrollment token for the existing source.
- Key rotation is agent-initiated over an authenticated connection. The agent submits a new public key signed by both the old and new keys. The old key is retired after the first session authenticated with the new key.

### Agent transport

Decision: one WebSocket connection over HTTPS per agent, on the server's existing listener. The server uses Axum's `ws` feature. The agent uses `tokio-tungstenite` with rustls.

Rationale:

- WebSocket passes through common reverse proxies and ingress controllers. They need to forward the Upgrade headers and allow idle times above the heartbeat interval, and most do both by default.
- It runs over HTTP/1.1 and needs no end-to-end HTTP/2.
- It shares the router, middleware, TLS setup, and port with the API.
- The channel is bidirectional, so the server can dispatch jobs without polling.
- WebSocket has no per-message flow control. The protocol adds acknowledgement-based windows.

Rejected alternatives:

- gRPC bidirectional streaming with `tonic`. It brings typed schemas and HTTP/2 flow control, and `tonic` routes can be mounted in an Axum router. It requires HTTP/2 and trailers end to end, and many proxies, ingress controllers, and tunnels need explicit gRPC configuration or do not support it. Protobuf may still be adopted later as a message encoding.
- HTTP long-polling. It tolerates the most proxies, but adds latency and per-request overhead, makes server-initiated messages awkward, and spreads ordering and acknowledgement across separate requests. The message envelope does not depend on WebSocket, so a long-polling fallback can be added if a deployment needs one.

### Open questions

Proposed defaults below are the owner's provisional answers. The questions stay open until confirmed.

1. Should the enrollment bundle (server URL and token) also carry a server CA fingerprint for installations with a private or self-signed CA, or should the agent rely only on a configured CA bundle?

   Proposed default: an optional CA fingerprint in the enrollment bundle.

2. For the first milestone, should project operators be able to create enrollment tokens, or only installation admins?

   Proposed default: only installation admins for the first milestone.

3. Are the proposed token expiry (1 hour default, 24 hours maximum) and session lifetime (15 minutes) acceptable? Multi-use tokens for fleet installs are left out until Docker and Linux agents need them.

   Proposed default: accept a 1-hour default and 24-hour maximum token expiry, and 15-minute sessions.

4. What is the default key rotation period (proposed: 90 days), and should admins be able to force a rotation?

   Proposed default: 90 days, and admins can force a rotation.

5. Is a 30-second worst-case bound for closing revoked connections acceptable? A shorter bound costs more database checks per connection.

   Proposed default: accept 30 seconds.

6. Should the first protocol version use JSON text frames (proposed, for debuggability) or a binary encoding from the start?

   Proposed default: JSON for version 1.

7. Is running more than one server replica in scope for the first release? The design coordinates through PostgreSQL and works with one replica either way.

   Proposed default: a single replica for the first release. The design stays compatible with multiple replicas.

8. What is the minimum supported Kubernetes version? Resource version ordering is guaranteed only on 1.35 and later, so the server applies the resource version rule only to clusters that report 1.35 or later. Older clusters rely on VN sequence numbers alone.

   Still open for the owner.

9. When a collection's scope shrinks, should resources outside the new scope be marked as no longer collected (proposed) or removed from inventory?

   Proposed default: mark them as no longer collected.

## First implementation milestone

Deliver a read-only cluster inventory path before deployment controls.

1. Create the Rust server and agent workspace, frontend application, configuration validation, and PostgreSQL migrations.
2. Implement user authentication and scoped access, plus agent enrollment, authenticated outbound connections, and revocation.
3. Register a cluster and collect a bounded initial inventory of nodes, namespaces, and workloads using read-only Kubernetes permissions.
4. Persist sanitized observations with source identity, version, and timestamps. Handle snapshots, updates, deletions, and reconnect reconciliation.
5. Display cluster inventory, connection status, last observation times, and collection errors through the Rust API and browser UI.

The milestone is complete when an authorized user can register a cluster and browse its inventory, unauthorized users cannot access it, disconnection leaves inventory visible with stale status, and reconnection reconciles changes without false deletions or duplicate resources. Inventory must survive a server restart. Revoked agents must lose access.

Validate synchronization with disconnects, partial snapshots, duplicate delivery, resource replacement, and permission failures. Build both the production frontend and Rust binaries before packaging the first release.

Deployment jobs, external provider integrations, retained telemetry, and object storage follow this milestone. Database backups and a tested restore procedure are required before relying on VN for production management.
