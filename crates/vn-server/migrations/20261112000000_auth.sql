-- User authentication, browser sessions, projects, and project-scoped roles.

-- People who have signed in through the configured OIDC provider. The (issuer, subject)
-- pair is the stable identity; email and display name are refreshed at each sign-in and
-- are informational only.
CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer text NOT NULL CHECK (issuer <> ''),
    subject text NOT NULL CHECK (subject <> '' AND length(subject) <= 255),
    email text CHECK (length(email) <= 320),
    display_name text CHECK (length(display_name) <= 200),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (issuer, subject)
);

-- In-flight sign-ins: written when the browser is sent to the provider, consumed once by
-- the callback. Keyed by the SHA-256 of the OAuth `state` value.
CREATE TABLE oidc_login_attempts (
    state_hash bytea PRIMARY KEY CHECK (octet_length(state_hash) = 32),
    nonce text NOT NULL CHECK (nonce <> ''),
    pkce_verifier text NOT NULL CHECK (pkce_verifier <> ''),
    return_to text NOT NULL CHECK (return_to LIKE '/%'),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    CHECK (expires_at > created_at)
);

CREATE INDEX oidc_login_attempts_expires_at_idx ON oidc_login_attempts (expires_at);

-- Browser sessions. Only the SHA-256 of the session token is stored; the token itself
-- lives in the session cookie. `installation_admin` is derived from the provider's claims
-- at sign-in, so the configured admin mapping stays the only source of that role.
CREATE TABLE sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    installation_admin boolean NOT NULL,
    created_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CHECK (expires_at > created_at),
    CHECK (last_seen_at >= created_at)
);

CREATE INDEX sessions_user_id_idx ON sessions (user_id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

CREATE TABLE projects (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    name text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 200),
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid REFERENCES users (id) ON DELETE SET NULL
);

-- One role per user per project. `operator` includes everything `viewer` allows.
CREATE TABLE project_role_assignments (
    project_id uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('viewer', 'operator')),
    granted_at timestamptz NOT NULL DEFAULT now(),
    granted_by uuid REFERENCES users (id) ON DELETE SET NULL,
    PRIMARY KEY (project_id, user_id)
);

CREATE INDEX project_role_assignments_user_id_idx ON project_role_assignments (user_id);

-- Security-relevant events. `details` never holds tokens, secrets, or raw claims.
CREATE TABLE audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    action text NOT NULL CHECK (action ~ '^[a-z_]+(\.[a-z_]+)+$'),
    actor_user_id uuid REFERENCES users (id) ON DELETE SET NULL,
    project_id uuid REFERENCES projects (id) ON DELETE SET NULL,
    target_user_id uuid REFERENCES users (id) ON DELETE SET NULL,
    details jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(details) = 'object')
);

CREATE INDEX audit_events_occurred_at_idx ON audit_events (occurred_at);
