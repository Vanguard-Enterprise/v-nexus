-- Agent authentication and connections: session tokens, consumed challenges, and the
-- connection history that connection status is derived from.

-- Agent session tokens. Only the SHA-256 of the token is stored. A session only
-- authorizes opening connections; revoking the agent deletes its sessions.
CREATE TABLE agent_sessions (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    agent_id uuid NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    -- Client address of the session request, resolved through trusted proxies.
    source_address inet,
    CHECK (expires_at > created_at)
);

CREATE INDEX agent_sessions_agent_id_idx ON agent_sessions (agent_id);
CREATE INDEX agent_sessions_expires_at_idx ON agent_sessions (expires_at);

-- Challenges answered with a session. Challenges themselves are stateless; a row here
-- makes one single-use until it expires, after which it is deleted.
CREATE TABLE consumed_agent_challenges (
    challenge_id uuid PRIMARY KEY,
    expires_at timestamptz NOT NULL
);

CREATE INDEX consumed_agent_challenges_expires_at_idx ON consumed_agent_challenges (expires_at);

-- One row per accepted agent WebSocket connection. A connection is open while
-- `closed_at` is null. `sync_epoch` is the source epoch allocated when it opened.
-- `close_code` is the WebSocket close code, or null when the server stopped without
-- recording one (rows left open are closed at the next startup).
CREATE TABLE agent_connections (
    id uuid PRIMARY KEY,
    agent_id uuid NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    source_id uuid NOT NULL REFERENCES sources (id) ON DELETE CASCADE,
    sync_epoch bigint NOT NULL CHECK (sync_epoch >= 1),
    opened_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    closed_at timestamptz,
    close_code integer CHECK (close_code BETWEEN 1000 AND 4999),
    -- From the agent record when the connection opens, then from the agent's `hello`.
    agent_version text NOT NULL CHECK (length(agent_version) BETWEEN 1 AND 64),
    kubernetes_version text CHECK (length(kubernetes_version) BETWEEN 1 AND 64),
    CHECK (closed_at IS NOT NULL OR close_code IS NULL),
    UNIQUE (source_id, sync_epoch)
);

-- A newer connection supersedes the older one in the transaction that opens it.
CREATE UNIQUE INDEX agent_connections_one_open_per_agent_idx
    ON agent_connections (agent_id) WHERE closed_at IS NULL;
CREATE INDEX agent_connections_source_id_idx ON agent_connections (source_id, opened_at DESC);
