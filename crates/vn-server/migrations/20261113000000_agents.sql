-- Agent enrollment: enrollment tokens, clusters, sources, and agent identities.

-- Kubernetes clusters registered in a project. A cluster is created by the first
-- enrollment for it. `fingerprint` is the identity the enrolling agent reported (the
-- `kube-system` namespace UID): a claim, not proof. Replacement enrollments and later
-- connections that report a different fingerprint are rejected.
CREATE TABLE clusters (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid NOT NULL REFERENCES projects (id) ON DELETE RESTRICT,
    display_name text NOT NULL CHECK (length(btrim(display_name)) BETWEEN 1 AND 200),
    fingerprint text NOT NULL CHECK (length(fingerprint) BETWEEN 1 AND 255),
    created_at timestamptz NOT NULL DEFAULT now(),
    -- Lets agents reference (project_id, cluster_id) so the pair stays consistent.
    UNIQUE (project_id, id)
);

CREATE INDEX clusters_project_id_idx ON clusters (project_id);

-- Writers of inventory. A source belongs to one cluster, declares the scope it collects,
-- and has at most one active agent. `sync_epoch` orders observations across connections
-- and across agent replacements, so it lives here and not on the agent.
CREATE TABLE sources (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id uuid NOT NULL REFERENCES clusters (id) ON DELETE CASCADE,
    -- The first release only has whole-cluster sources. Narrower scopes add values and
    -- columns describing them.
    scope text NOT NULL DEFAULT 'cluster' CHECK (scope IN ('cluster')),
    sync_epoch bigint NOT NULL DEFAULT 0 CHECK (sync_epoch >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (cluster_id, id)
);

-- A cluster has at most one whole-cluster source, because two would overlap.
CREATE UNIQUE INDEX sources_one_cluster_scope_idx ON sources (cluster_id) WHERE scope = 'cluster';

-- Single-use enrollment tokens. The token string is shown once at creation; only the
-- SHA-256 of its secret part is stored. A token targets either a new cluster (by display
-- name) or an existing source whose agent is being replaced.
CREATE TABLE enrollment_tokens (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_hash bytea NOT NULL CHECK (octet_length(secret_hash) = 32),
    project_id uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    agent_kind text NOT NULL CHECK (agent_kind IN ('kubernetes')),
    target_cluster_name text CHECK (length(btrim(target_cluster_name)) BETWEEN 1 AND 200),
    target_source_id uuid REFERENCES sources (id) ON DELETE CASCADE,
    created_by uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    revoked_at timestamptz,
    revoked_by uuid REFERENCES users (id) ON DELETE SET NULL,
    CHECK ((target_cluster_name IS NULL) <> (target_source_id IS NULL)),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '24 hours'),
    -- A used token cannot be revoked, and a revoked token cannot be used.
    CHECK (used_at IS NULL OR revoked_at IS NULL)
);

CREATE INDEX enrollment_tokens_project_id_idx ON enrollment_tokens (project_id, created_at);

-- Enrolled agents. Revoked agents are kept for history; nothing here is deleted by
-- revocation, and neither is the cluster or its inventory.
CREATE TABLE agents (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind text NOT NULL CHECK (kind IN ('kubernetes')),
    project_id uuid NOT NULL,
    cluster_id uuid NOT NULL,
    source_id uuid NOT NULL,
    -- Raw 32-byte Ed25519 public key. Never reused, so a revoked key cannot come back.
    public_key bytea NOT NULL UNIQUE CHECK (octet_length(public_key) = 32),
    -- URL-safe base64 of the SHA-256 of `public_key`.
    key_id text NOT NULL UNIQUE CHECK (length(key_id) = 43),
    cluster_fingerprint text NOT NULL CHECK (length(cluster_fingerprint) BETWEEN 1 AND 255),
    agent_version text NOT NULL CHECK (length(agent_version) BETWEEN 1 AND 64),
    protocol_versions integer[] NOT NULL CHECK (cardinality(protocol_versions) >= 1),
    enrollment_token_id uuid NOT NULL UNIQUE REFERENCES enrollment_tokens (id),
    -- Creator of the enrolling token.
    enrolled_by uuid REFERENCES users (id) ON DELETE SET NULL,
    enrolled_at timestamptz NOT NULL DEFAULT now(),
    -- Client address of the enrollment request, resolved through trusted proxies.
    source_address inet,
    revoked_at timestamptz,
    revoked_by uuid REFERENCES users (id) ON DELETE SET NULL,
    revocation_reason text CHECK (revocation_reason IN ('revoked', 'replaced')),
    CHECK ((revoked_at IS NULL) = (revocation_reason IS NULL)),
    FOREIGN KEY (project_id, cluster_id) REFERENCES clusters (project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (cluster_id, source_id) REFERENCES sources (cluster_id, id) ON DELETE CASCADE
);

-- One writer per source: at most one agent that is not revoked.
CREATE UNIQUE INDEX agents_one_active_per_source_idx ON agents (source_id) WHERE revoked_at IS NULL;
CREATE INDEX agents_project_id_idx ON agents (project_id, enrolled_at);

-- Audit events about an agent, as actor (enrollment) or target (revocation).
ALTER TABLE audit_events ADD COLUMN agent_id uuid REFERENCES agents (id) ON DELETE SET NULL;
