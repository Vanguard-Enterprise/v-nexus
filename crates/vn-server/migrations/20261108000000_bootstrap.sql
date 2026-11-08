-- Bootstrap: one row identifying this Vanguard Nexus installation.
-- Feature tables arrive in later migrations.
CREATE TABLE installation (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    installation_id uuid NOT NULL DEFAULT gen_random_uuid(),
    created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO installation DEFAULT VALUES;
