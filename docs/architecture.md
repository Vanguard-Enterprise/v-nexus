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

A reconnect starts a complete inventory reconciliation. Only a successfully completed snapshot of a known collection scope may establish that previously observed resources are missing. An incomplete snapshot or collection permission failure must not mark those resources deleted. Version observations so delayed updates cannot replace newer state.

Persist management requests as jobs before dispatch. Design retries and agent result reporting to tolerate duplicate delivery, with explicit handling for operations whose outcome is unknown after a disconnect.

Enrollment uses expiring tokens, authenticated agent identities, and revocation. User access uses OIDC and scoped permissions. Neither browsers nor agents connect directly to PostgreSQL.

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
